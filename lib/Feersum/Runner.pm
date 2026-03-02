package Feersum::Runner;
use warnings;
use strict;

use EV;
use Feersum;
use Socket qw/SOMAXCONN SOL_SOCKET SO_REUSEADDR AF_INET SOCK_STREAM
              inet_aton pack_sockaddr_in/;
BEGIN {
    # IPv6 support (Socket 1.95+, Perl 5.14+)
    eval { Socket->import(qw/AF_INET6 inet_pton pack_sockaddr_in6/); 1 }
        or do {
            *AF_INET6 = sub () { undef };
            *inet_pton = sub { undef };
            *pack_sockaddr_in6 = sub { undef };
        };
}
BEGIN {
    # SO_REUSEPORT may not be available on all systems
    eval { Socket->import('SO_REUSEPORT'); 1 }
        or *SO_REUSEPORT = sub () { undef };
}
use POSIX ();
use Scalar::Util qw/weaken/;
use Guard ();
use Carp qw/carp croak/;
use File::Spec::Functions 'rel2abs';

use constant DEATH_TIMER => 5.0; # seconds
use constant DEATH_TIMER_INCR => 2.0; # seconds
use constant DEFAULT_HOST => 'localhost';
use constant DEFAULT_PORT => 5000;
use constant MAX_PRE_FORK => $ENV{FEERSUM_MAX_PRE_FORK} || 1000;

our $INSTANCE;
sub new { ## no critic (RequireArgUnpacking)
    my $c = shift;
    if ($INSTANCE) {
        croak "Only one Feersum::Runner instance can be active at a time"
            if $INSTANCE->{running};
        # Clean up old instance state before creating new one
        $INSTANCE->_cleanup();
        undef $INSTANCE;
    }
    $INSTANCE = bless {quiet=>1, @_, running=>0}, $c;
    return $INSTANCE;
}

sub _cleanup {
    my $self = shift;
    return if $self->{_cleaned_up};
    $self->{_cleaned_up} = 1;
    if (my $f = $self->{endjinn}) {
        $f->request_handler(sub{});
        $f->unlisten();
    }
    $self->{_quit} = undef;
    $self->{running} = 0;
    if (my $file = $self->{pid_file}) {
        unlink $file if -f $file;
    }
    return;
}

sub DESTROY {
    local $@;
    $_[0]->_cleanup();
}

sub _create_socket {
    my ($self, $listen, $use_reuseport) = @_;
    my $backlog = $self->{backlog} || SOMAXCONN;

    my $sock;
    if ($listen =~ m#^[/\.]+\w#) {
        require IO::Socket::UNIX;
        if (-S $listen) {
            unlink $listen or carp "unlink stale socket '$listen': $!";
        }
        my $saved = umask(0);
        $sock = eval {
            IO::Socket::UNIX->new(
               Local => rel2abs($listen),
               Listen => $backlog,
            );
        };
        my $err = $@;
        umask($saved);  # Restore umask even if socket creation failed
        die $err if $err;
        croak "couldn't bind to socket" unless $sock;
        $sock->blocking(0) || do { close($sock); croak "couldn't unblock socket: $!"; };
    }
    else {
        require IO::Socket::INET;
        # SO_REUSEPORT must be set BEFORE bind for multiple sockets per port
        if ($use_reuseport && defined SO_REUSEPORT) {
            # Parse listen address - handle IPv6 bracketed notation [host]:port
            my ($host, $port, $is_ipv6);
            if ($listen =~ /^\[([^\]]+)\]:(\d*)$/) {
                # IPv6 with port: [::1]:8080
                ($host, $port, $is_ipv6) = ($1, $2 || 0, 1);
            } elsif ($listen =~ /^\[([^\]]+)\]$/) {
                # IPv6 without port: [::1]
                ($host, $port, $is_ipv6) = ($1, 0, 1);
            } elsif ($listen =~ /:.*:/) {
                # Bare IPv6 - reject ambiguous cases that look like host:port
                if ($listen =~ /:(\d{1,5})$/) {
                    my $maybe_port = $1;
                    # 5 digits = definitely a port; >=1024 = likely a port
                    if ($maybe_port <= 65535 && (length($maybe_port) == 5 || $maybe_port >= 1024)) {
                        croak "ambiguous IPv6 address '$listen': use bracket notation [host]:port " .
                              "(e.g., [::1]:$maybe_port or [2001:db8::1]:$maybe_port)";
                    }
                }
                ($host, $port, $is_ipv6) = ($listen, 0, 1);
            } else {
                # IPv4: host:port
                ($host, $port) = split /:/, $listen, 2;
                $host ||= '0.0.0.0';
                $port ||= 0;
                $is_ipv6 = 0;
            }

            # Validate port range (0-65535)
            if ($port !~ /^\d+$/ || $port > 65535) {
                croak "invalid port '$port': must be 0-65535";
            }

            my ($domain, $sockaddr);
            if ($is_ipv6) {
                defined AF_INET6()
                    or croak "IPv6 not supported on this system";
                my $addr = inet_pton(AF_INET6(), $host)
                    or croak "couldn't resolve IPv6 address '$host'";
                $domain = AF_INET6();
                $sockaddr = pack_sockaddr_in6($port, $addr);
            } else {
                my $addr = inet_aton($host)
                    or croak "couldn't resolve address '$host'";
                $domain = AF_INET();
                $sockaddr = pack_sockaddr_in($port, $addr);
            }

            # Create socket with correct address family
            socket($sock, $domain, SOCK_STREAM(), 0)
                or croak "couldn't create socket: $!";
            setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, pack("i", 1))
                or do { close($sock); croak "setsockopt SO_REUSEADDR failed: $!"; };
            setsockopt($sock, SOL_SOCKET, SO_REUSEPORT, pack("i", 1))
                or do { close($sock); croak "setsockopt SO_REUSEPORT failed: $!"; };
            bind($sock, $sockaddr)
                or do { close($sock); croak "couldn't bind to socket: $!"; };
            listen($sock, $backlog)
                or do { close($sock); croak "couldn't listen: $!"; };

            # Wrap in IO::Handle for ->blocking() method
            require IO::Handle;
            bless $sock, 'IO::Handle';
            $sock->blocking(0)
                || do { close($sock); croak "couldn't unblock socket: $!"; };
        }
        else {
            # Validate port in listen address for better error messages
            if ($listen =~ /:(\d+)$/) {
                my $port = $1;
                croak "invalid port '$port': must be 0-65535" if $port > 65535;
            } elsif ($listen =~ /:(\S+)$/) {
                my $port = $1;
                croak "invalid port '$port': must be numeric" unless $port =~ /^\d+$/;
            }
            $sock = IO::Socket::INET->new(
                LocalAddr => $listen,
                ReuseAddr => 1,
                Proto => 'tcp',
                Listen => $backlog,
                Blocking => 0,
            );
            croak "couldn't bind to socket: $!" unless $sock;
        }
    }
    return $sock;
}

sub _extract_options {
    my $self = shift;
    if (my $opts = $self->{options}) {
        $self->{$_} = delete $opts->{$_} for grep defined($opts->{$_}),
            qw/pre_fork preload_app keepalive backlog hot_restart graceful_timeout startup_timeout
               after_fork pid_file daemonize user group max_requests_per_worker access_log
               read_timeout header_timeout write_timeout max_connection_reqs reuseport epoll_exclusive
               read_priority write_priority accept_priority max_accept_per_loop max_connections
               max_read_buf max_body_len max_uri_len wbuf_low_water max_h2_concurrent_streams
               reverse_proxy proxy_protocol psgix_io h2 tls tls_cert_file tls_key_file sni/;
        for my $unknown (keys %$opts) {
            carp "Unknown option '$unknown' ignored";
        }
    }
}

sub _apply_tls_to_listeners {
    my ($self, $f, $n_listeners, $tls, $sni) = @_;
    for my $i (0 .. $n_listeners - 1) {
        $f->set_tls(listener => $i, %$tls);
    }
    if ($sni) {
        croak "sni must be an array reference" unless ref $sni eq 'ARRAY';
        for my $entry (@$sni) {
            for my $i (0 .. $n_listeners - 1) {
                $f->set_tls(listener => $i, %$entry);
            }
        }
    }
}

sub _normalize_listen {
    my $self = shift;
    if (defined $self->{listen} && !ref $self->{listen}) {
        $self->{listen} = [ $self->{listen} ];
    }
    $self->{listen} ||=
        [ ($self->{host}||DEFAULT_HOST).':'.($self->{port}||DEFAULT_PORT) ];
    croak "listen must be an array reference"
        if ref $self->{listen} ne 'ARRAY';
    croak "listen array cannot be empty"
        if @{$self->{listen}} == 0;
    $self->{_listen_addrs} = [ @{$self->{listen}} ];
}

sub _prepare {
    my $self = shift;

    $self->_normalize_listen();

    # Validate pre_fork early (before socket creation) to fail fast
    if ($self->{pre_fork}) {
        my $n = $self->{pre_fork};
        if ($n !~ /^\d+$/ || $n < 1) {
            croak "pre_fork must be a positive integer";
        }
        if ($n > MAX_PRE_FORK) {
            croak "pre_fork=$n exceeds maximum of " . MAX_PRE_FORK;
        }
    }

    # Enable reuseport automatically in prefork mode if SO_REUSEPORT available
    my $use_reuseport = $self->{reuseport} && $self->{pre_fork} && defined SO_REUSEPORT;
    $self->{_use_reuseport} = $use_reuseport;

    my $f = Feersum->endjinn;

    # EPOLLEXCLUSIVE must be set BEFORE use_socket() so the separate accept epoll
    # is created with EPOLLEXCLUSIVE flag (Linux 4.5+)
    if ($self->{epoll_exclusive} && $self->{pre_fork} && $^O eq 'linux') {
        $f->set_epoll_exclusive(1);
    }

    my @socks;
    for my $listen (@{$self->{_listen_addrs}}) {
        my $sock = $self->_create_socket($listen, $use_reuseport);
        push @socks, $sock;
        $f->use_socket($sock);
    }
    $self->{sock} = $socks[0];   # backward compat: primary socket
    $self->{_socks} = \@socks;   # all sockets

    $f->set_keepalive($_) for grep defined, delete $self->{keepalive};
    $f->set_reverse_proxy($_) for grep defined, delete $self->{reverse_proxy};
    $f->set_proxy_protocol($_) for grep defined, delete $self->{proxy_protocol};
    $f->set_psgix_io($_) for grep defined, delete $self->{psgix_io};
    $f->read_timeout($_) for grep defined, delete $self->{read_timeout};
    $f->header_timeout($_) for grep defined, delete $self->{header_timeout};
    $f->write_timeout($_) for grep defined, delete $self->{write_timeout};
    $f->max_connection_reqs($_) for grep defined, delete $self->{max_connection_reqs};
    # Validate priority values (-2 to +2 per libev)
    for my $prio_name (qw/read_priority write_priority accept_priority/) {
        my $val = $self->{$prio_name};
        if (defined $val) {
            # Must be an integer (not float, not string)
            croak "$prio_name must be an integer" unless $val =~ /^-?\d+$/;
            croak "$prio_name must be between -2 and 2" if $val < -2 || $val > 2;
        }
    }
    $f->read_priority($_) for grep defined, delete $self->{read_priority};
    $f->write_priority($_) for grep defined, delete $self->{write_priority};
    $f->accept_priority($_) for grep defined, delete $self->{accept_priority};
    # Validate max_accept_per_loop (must be positive integer)
    if (defined(my $val = $self->{max_accept_per_loop})) {
        croak "max_accept_per_loop must be a positive integer"
            unless $val =~ /^\d+$/ && $val > 0;
    }
    $f->max_accept_per_loop($_) for grep defined, delete $self->{max_accept_per_loop};
    # Validate max_connections (must be non-negative integer, 0 = unlimited)
    if (defined(my $val = $self->{max_connections})) {
        croak "max_connections must be a non-negative integer"
            unless $val =~ /^\d+$/;
    }
    $f->max_connections($_) for grep defined, delete $self->{max_connections};
    $f->max_read_buf($_) for grep defined, delete $self->{max_read_buf};
    $f->max_body_len($_) for grep defined, delete $self->{max_body_len};
    $f->max_uri_len($_) for grep defined, delete $self->{max_uri_len};
    $f->wbuf_low_water($_) for grep defined, delete $self->{wbuf_low_water};
    if ($f->can('max_h2_concurrent_streams')) {
        $f->max_h2_concurrent_streams($_) for grep defined, delete $self->{max_h2_concurrent_streams};
    }

    # Build tls hash from flat options (for Plack -o tls_cert_file=... -o tls_key_file=...)
    if (!$self->{tls}) {
        if (my $cert = delete $self->{tls_cert_file}) {
            my $key = delete $self->{tls_key_file}
                or croak "tls_cert_file requires tls_key_file";
            $self->{tls} = { cert_file => $cert, key_file => $key };
        } elsif (delete $self->{tls_key_file}) {
            croak "tls_key_file requires tls_cert_file";
        }
    } else {
        # tls hash takes precedence; discard flat options
        delete $self->{tls_cert_file};
        delete $self->{tls_key_file};
    }

    # TLS configuration: apply to all listeners
    if (my $tls = delete $self->{tls}) {
        croak "tls must be a hash reference" unless ref $tls eq 'HASH';
        croak "tls requires cert_file" unless $tls->{cert_file};
        croak "tls requires key_file" unless $tls->{key_file};
        -f $tls->{cert_file} && -r _
            or croak "tls cert_file '$tls->{cert_file}': not found or not readable";
        -f $tls->{key_file} && -r _
            or croak "tls key_file '$tls->{key_file}': not found or not readable";

        # H2 is off by default; only enable if h2 => 1 was passed
        if (delete $self->{h2}) {
            $tls->{h2} = 1;
        }

        if ($f->has_tls()) {
            $self->_apply_tls_to_listeners($f, scalar(@socks), $tls, $self->{sni});
            $self->{_tls_config} = $tls;  # for reuseport workers
            $self->{quiet} or warn "Feersum [$$]: TLS enabled on "
                . scalar(@socks) . " listener(s)\n";
        } else {
            croak "tls option requires Feersum compiled with TLS support (need picotls submodule + OpenSSL; see Alien::OpenSSL)";
        }
    } else {
        if (delete $self->{h2}) {
            croak "h2 requires TLS (provide tls_cert_file and tls_key_file, or a tls hash)";
        }
    }

    $self->{endjinn} = $f;
    return;
}

# for overriding:
sub assign_request_handler { ## no critic (RequireArgUnpacking)
    my ($self, $app) = @_;
    if (my $log_cb = $self->{access_log}) {
        my $orig = $app;
        $app = sub {
            my $r = shift;
            my $t0 = EV::now();
            my $method = $r->method;
            my $uri = $r->uri;
            $r->response_guard(Guard::guard(sub {
                $log_cb->($method, $uri, EV::now() - $t0);
            }));
            $orig->($r);
        };
    }
    return $self->{endjinn}->request_handler($app);
}

sub run {
    my $self = shift;
    weaken $self;

    $self->{running} = 1;
    my $app = shift || $self->{app};
    $self->{quiet} or warn "Feersum [$$]: starting...\n";

    $self->_extract_options();

    # Hot restart mode: entry process creates sockets, then manages
    # generation children that each load a fresh app with clean modules.
    if ($self->{hot_restart}) {
        croak "hot_restart requires app_file" unless $self->{app_file};
        $self->_daemonize_and_write_pid();
        $self->_run_hot_restart_master();  # creates sockets, then drops privs
        return;
    }

    $self->_prepare();       # bind() on listen sockets
    $self->_daemonize_and_write_pid();
    $self->_drop_privs();    # after bind, before app load

    # preload_app => 0: fork workers first, each loads the app independently.
    # Default (preload_app unset or true): load app once, fork inherits via COW.
    if ($self->{pre_fork} && defined $self->{preload_app} && !$self->{preload_app}) {
        $self->{_app_loader} = sub {
            my $a = $app || $self->{app};
            if (!$a && $self->{app_file}) {
                local ($@, $!);
                $a = do(rel2abs($self->{app_file}));
                warn "couldn't load $self->{app_file}: " . ($@ || $!) if $@ || !$a;
            }
            croak "app not defined or failed to compile" unless $a;
            $self->assign_request_handler($a);
        };
        # Set a no-op handler on parent so it doesn't crash if it briefly
        # re-accepts during non-reuseport worker respawn
        $self->{endjinn}->request_handler(sub {
            $_[0]->send_response(503, ['Content-Type'=>'text/plain'], \"Service Unavailable\n");
        });
        $self->{_quit} = EV::signal 'QUIT', sub { $self && $self->quit };
        $self->_start_pre_fork;
    } else {
        $app ||= delete $self->{app};
        if (!$app && $self->{app_file}) {
            local ($@, $!);
            $app = do(rel2abs($self->{app_file}));
            warn "couldn't parse $self->{app_file}: $@" if $@;
            warn "couldn't do $self->{app_file}: $!" if ($! && !defined $app);
            warn "couldn't run $self->{app_file}: didn't return anything"
                unless $app;
        }
        croak "app not defined or failed to compile" unless $app;

        $self->assign_request_handler($app);

        $self->{_quit} = EV::signal 'QUIT', sub { $self && $self->quit };

        $self->_start_pre_fork if $self->{pre_fork};
    }
    EV::run;
    $self->{quiet} or warn "Feersum [$$]: done\n";
    $self->_cleanup();
    return;
}

# Hot restart master: creates sockets once, then manages generations.
# Each generation is a forked child that runs _prepare + app load + serve.
# SIGHUP → fork new gen → if ready → SIGQUIT old gen.
sub _run_hot_restart_master {
    my ($self) = @_;
    my $quiet = $self->{quiet};

    $quiet or warn "Feersum [$$]: hot restart master starting\n";

    $self->_normalize_listen();

    # Create listen sockets in the master (shared across generations via fork).
    # Use SO_REUSEPORT if configured — reuseport workers need all sockets
    # on the same addr:port to have the flag set.
    $self->{_listen_addrs} ||= [ @{$self->{listen}} ];
    my $use_reuseport = $self->{reuseport} && $self->{pre_fork} && defined SO_REUSEPORT;
    my @socks;
    for my $listen (@{$self->{_listen_addrs}}) {
        my $sock = $self->_create_socket($listen, $use_reuseport);
        push @socks, $sock;
    }
    $self->{_master_socks} = \@socks;

    # Drop privileges after sockets are bound (privileged ports are now open)
    $self->_drop_privs();

    my $gen = 0;
    my $current_pid;
    my $pending_pid;   # generation being started (not yet $current_pid)
    my $shutting_down = 0;
    my $startup_timeout = $self->{startup_timeout} // 10;

    # Fork a generation child.  The child inherits listen sockets via fork,
    # runs _prepare (which calls use_socket + applies all settings),
    # loads the app file fresh, then serves.
    my $fork_generation = sub {
        $gen++;
        my $pid = fork;
        croak "fork generation: $!" unless defined $pid;

        if ($pid == 0) {
            # === Generation child ===
            EV::default_loop()->loop_fork;
            $quiet or warn "Feersum [$$]: gen $gen loading app\n";

            # Sockets were created in the master and inherited via fork —
            # register them with this generation's Feersum instance.
            my $f = Feersum->endjinn;
            for my $sock (@socks) {
                $f->use_socket($sock);
            }
            $self->{_socks} = \@socks;
            $self->{sock} = $socks[0];

            # Apply server settings (consumed from $self by _apply_settings)
            $self->_apply_settings($f);

            # Load app fresh (fork gave us clean copy-on-write memory)
            my $app_file = rel2abs($self->{app_file});
            local ($@, $!);
            my $app = do $app_file;
            if ($@ || !$app || ref $app ne 'CODE') {
                warn "Feersum [$$]: gen $gen: failed to load $app_file: "
                    . ($@ || $! || "not a coderef") . "\n";
                POSIX::_exit(1);
            }

            $self->{endjinn} = $f;
            $self->assign_request_handler($app);

            my ($quit_w, $death_w);
            $quit_w = EV::signal 'QUIT', sub {
                if ($self->{pre_fork}) {
                    kill POSIX::SIGQUIT, -$$;
                }
                $f->graceful_shutdown(sub { POSIX::_exit(0) });
                my $gt = $self->{graceful_timeout}
                      // $ENV{FEERSUM_GRACEFUL_TIMEOUT}
                      // DEATH_TIMER;
                $death_w = EV::timer($gt + DEATH_TIMER_INCR, 0, sub {
                    POSIX::_exit(1);
                });
            };

            if ($self->{pre_fork}) {
                $f->set_multiprocess(1);
                # Set reuseport flag for _fork_another workers
                $self->{_use_reuseport} = $self->{reuseport}
                    && $self->{pre_fork} && defined SO_REUSEPORT;
                if ($self->{_use_reuseport} && $^O eq 'linux') {
                    $f->set_epoll_exclusive(1)
                        if $self->{epoll_exclusive} && $f->can('set_epoll_exclusive');
                }
                POSIX::setsid();
                $self->{_kids} = [];
                $self->{_n_kids} = 0;
                $self->_fork_another($_) for (1 .. $self->{pre_fork});
                $f->unlisten();  # parent of workers doesn't accept
            }

            if (!$self->{pre_fork}) {
                $self->{after_fork}->() if $self->{after_fork};

                # Auto-recycle generation after N requests
                if (my $max = $self->{max_requests_per_worker}) {
                    my $mrw; $mrw = EV::timer(1, 1, sub {
                        if ($f->total_requests >= $max) {
                            $f->graceful_shutdown(sub { POSIX::_exit(0) });
                            undef $mrw;
                        }
                    });
                }
            }

            # Signal master: ready to serve (after workers are forked)
            kill 'USR2', getppid();

            $quiet or warn "Feersum [$$]: gen $gen ready"
                . ($self->{pre_fork} ? " ($self->{pre_fork} workers)" : "") . "\n";
            EV::run;
            POSIX::_exit(0);
        }

        return $pid;
    };

    # Fork first generation
    $pending_pid = $fork_generation->();
    unless (_wait_for_ready($pending_pid, $quiet, $gen, \$shutting_down, $startup_timeout)) {
        kill 'KILL', $pending_pid if kill(0, $pending_pid);
        waitpid($pending_pid, 0);
        croak "first generation failed to start";
    }
    $current_pid = $pending_pid;
    $pending_pid = undef;

    $quiet or warn "Feersum [$$]: master ready (gen $gen, pid $current_pid)\n";

    my $hup = EV::signal 'HUP', sub {
        return if $shutting_down || $pending_pid;  # debounce rapid HUPs
        $quiet or warn "Feersum [$$]: HUP — spawning gen " . ($gen + 1) . "\n";

        my $old_pid = $current_pid;
        $pending_pid = $fork_generation->();

        if (_wait_for_ready($pending_pid, $quiet, $gen, \$shutting_down, $startup_timeout)) {
            $quiet or warn "Feersum [$$]: gen $gen ready (pid $pending_pid), retiring old (pid $old_pid)\n";
            $current_pid = $pending_pid;
            $pending_pid = undef;
            kill 'QUIT', $old_pid if $old_pid;
        } else {
            warn "Feersum [$$]: gen $gen failed, keeping old (pid $old_pid)\n";
            kill 'KILL', $pending_pid if kill(0, $pending_pid);
            waitpid($pending_pid, 0);
            $pending_pid = undef;
        }
    };

    my $quit = EV::signal 'QUIT', sub {
        return if $shutting_down;
        $shutting_down = 1;
        $quiet or warn "Feersum [$$]: master shutting down\n";
        kill 'QUIT', $current_pid if $current_pid;
        # Also kill $pending_pid in case QUIT raced with a HUP reload:
        # the pending gen may be about to be promoted to $current_pid.
        kill 'QUIT', $pending_pid if $pending_pid;
    };

    my $int = EV::signal 'INT', sub {
        return if $shutting_down;
        $shutting_down = 1;
        $quiet or warn "Feersum [$$]: master interrupted\n";
        kill 'QUIT', $current_pid if $current_pid;
        kill 'QUIT', $pending_pid if $pending_pid;
    };

    # Reap children; restart if active generation dies unexpectedly
    my $reap = EV::child 0, 0, sub {
        my $kid = $_[0]->rpid;
        my $status = $_[0]->rstatus >> 8;
        $quiet or warn "Feersum [$$]: child $kid exited ($status)\n";
        # Ignore pending generation deaths — handled by _wait_for_ready
        return if $pending_pid && $kid == $pending_pid;
        if ($current_pid && $kid == $current_pid) {
            $current_pid = undef;
            EV::break if $shutting_down;
            unless ($shutting_down || $pending_pid) {
                warn "Feersum [$$]: active generation died, restarting\n";
                $pending_pid = $fork_generation->();
                if (_wait_for_ready($pending_pid, $quiet, $gen, \$shutting_down, $startup_timeout)) {
                    $current_pid = $pending_pid;
                } else {
                    # Replacement also failed — kill it and shut down
                    warn "Feersum [$$]: replacement generation also failed, giving up\n";
                    kill 'KILL', $pending_pid if kill(0, $pending_pid);
                    waitpid($pending_pid, 0);
                    EV::break;
                }
                $pending_pid = undef;
            }
        }
    };

    EV::run;
    # Cleanup
    for my $sock (@socks) { close($sock) }
    waitpid(-1, POSIX::WNOHANG()) for 1..100;
    $quiet or warn "Feersum [$$]: master done\n";
}

# Wait for a generation child to signal readiness (USR2) or fail.
# Uses RUN_ONCE loop to avoid EV::break propagating to the outer EV::run.
sub _wait_for_ready {
    my ($pid, $quiet, $gen, $shutdown_ref, $timeout) = @_;
    $timeout //= 10;
    my $ready = 0;
    my $done = 0;
    my $usr2 = EV::signal 'USR2', sub { $ready = 1; $done = 1 };
    my $fail = EV::child $pid, 0, sub {
        warn "Feersum [$$]: gen $gen (pid $pid) died during startup\n";
        $done = 1;
    };
    my $to = EV::timer($timeout, 0, sub {
        warn "Feersum [$$]: gen $gen startup timeout\n";
        $done = 1;
    });
    EV::run(EV::RUN_ONCE) until $done || ($shutdown_ref && $$shutdown_ref);
    return $ready;
}

# Apply server settings to a Feersum instance (without consuming from $self).
# Used by hot_restart generations to re-apply settings from the master's config.
sub _apply_settings {
    my ($self, $f) = @_;
    $f->set_keepalive($self->{keepalive}) if defined $self->{keepalive};
    $f->set_reverse_proxy($self->{reverse_proxy}) if defined $self->{reverse_proxy};
    $f->set_proxy_protocol($self->{proxy_protocol}) if defined $self->{proxy_protocol};
    $f->set_psgix_io($self->{psgix_io}) if defined $self->{psgix_io};
    $f->read_timeout($self->{read_timeout}) if defined $self->{read_timeout};
    $f->header_timeout($self->{header_timeout}) if defined $self->{header_timeout};
    $f->write_timeout($self->{write_timeout}) if defined $self->{write_timeout};
    $f->max_connection_reqs($self->{max_connection_reqs}) if defined $self->{max_connection_reqs};
    $f->read_priority($self->{read_priority}) if defined $self->{read_priority};
    $f->write_priority($self->{write_priority}) if defined $self->{write_priority};
    $f->accept_priority($self->{accept_priority}) if defined $self->{accept_priority};
    $f->max_accept_per_loop($self->{max_accept_per_loop}) if defined $self->{max_accept_per_loop};
    $f->max_connections($self->{max_connections}) if defined $self->{max_connections};
    $f->max_read_buf($self->{max_read_buf}) if defined $self->{max_read_buf};
    $f->max_body_len($self->{max_body_len}) if defined $self->{max_body_len};
    $f->max_uri_len($self->{max_uri_len}) if defined $self->{max_uri_len};
    $f->wbuf_low_water($self->{wbuf_low_water}) if defined $self->{wbuf_low_water};
    $f->max_h2_concurrent_streams($self->{max_h2_concurrent_streams})
        if defined $self->{max_h2_concurrent_streams};
    $f->set_epoll_exclusive($self->{epoll_exclusive} ? 1 : 0)
        if defined $self->{epoll_exclusive} && $f->can('set_epoll_exclusive');

    # TLS
    if (my $tls = $self->{tls}) {
        if ($f->has_tls()) {
            my $n = scalar @{$self->{_master_socks} || $self->{_socks}};
            $self->_apply_tls_to_listeners($f, $n, $tls, $self->{sni});
            $self->{_tls_config} = $tls;  # for reuseport workers
        }
    }
}

sub _fork_another {
    my ($self, $slot) = @_;

    my $pid = fork;
    croak "failed to fork: $!" unless defined $pid;
    unless ($pid) {
        EV::default_loop()->loop_fork;
        $self->{quiet} or warn "Feersum [$$]: starting\n";
        delete $self->{_kids};
        delete $self->{pre_fork};
        $self->{_n_kids} = 0;

        # With SO_REUSEPORT, each child creates its own sockets
        # This eliminates accept() contention for better scaling
        if ($self->{_use_reuseport}) {
            $self->{endjinn}->unlisten();
            for my $old_sock (@{$self->{_socks} || []}) {
                close($old_sock)
                    or do { warn "close parent socket in child: $!"; POSIX::_exit(1); };
            }
            my @new_socks;
            eval {
                for my $listen (@{$self->{_listen_addrs}}) {
                    my $sock = $self->_create_socket($listen, 1);
                    push @new_socks, $sock;
                    $self->{endjinn}->use_socket($sock);
                }
                1;
            } or do {
                warn "Feersum [$$]: child socket creation failed: $@";
                POSIX::_exit(1);
            };
            $self->{sock} = $new_socks[0];
            $self->{_socks} = \@new_socks;

            # Re-apply TLS config + SNI on new listeners
            if (my $tls = $self->{_tls_config}) {
                $self->_apply_tls_to_listeners(
                    $self->{endjinn}, scalar(@new_socks), $tls, $self->{sni});
            }
        }

        # Per-worker app loading (preload_app => 0)
        if (my $loader = $self->{_app_loader}) {
            eval { $loader->() };
            if ($@) {
                warn "Feersum [$$]: worker app load failed: $@";
                POSIX::_exit(1);
            }
        }

        if (my $cb = $self->{after_fork}) { $cb->() }

        # Auto-recycle worker after N total requests
        my $max_reqs_w;
        if (my $max = $self->{max_requests_per_worker}) {
            my $f = $self->{endjinn};
            $max_reqs_w = EV::timer(1, 1, sub {
                if ($f->total_requests >= $max) {
                    $f->graceful_shutdown(sub { POSIX::_exit(0) });
                    undef $max_reqs_w;
                }
            });
        }

        eval { EV::run; }; ## no critic (RequireCheckingReturnValueOfEval)
        carp $@ if $@;
        POSIX::_exit($@ ? 1 : 0);  # _exit avoids running parent's END blocks
    }

    weaken $self;  # prevent circular ref with watcher callback
    $self->{_n_kids}++;
    $self->{_kids}[$slot] = EV::child $pid, 0, sub {
        my $w = shift;
        return unless $self;  # guard against destruction during shutdown
        $self->{quiet} or warn "Feersum [$$]: child $pid exited ".
            "with rstatus ".$w->rstatus."\n";
        $self->{_n_kids}--;
        if ($self->{_shutdown}) {
            unless ($self->{_n_kids}) {
                $self->{_death} = undef;
                EV::break(EV::BREAK_ALL());
            }
            return;
        }
        # Without SO_REUSEPORT, parent needs to accept during respawn
        unless ($self->{_use_reuseport}) {
            my $feersum = $self->{endjinn};
            my @socks = @{$self->{_socks} || [$self->{sock}]};
            my $all_valid = 1;
            for my $sock (@socks) {
                unless (defined fileno $sock) {
                    $all_valid = 0;
                    last;
                }
            }
            if ($all_valid) {
                for my $sock (@socks) {
                    $feersum->accept_on_fd(fileno $sock);
                }
                $self->_fork_another($slot);
                $feersum->unlisten;
            } else {
                carp "fileno returned undef during respawn, cannot respawn worker";
            }
        }
        else {
            # With SO_REUSEPORT, just spawn new child (it creates its own socket)
            $self->_fork_another($slot);
        }
    };
    return;
}

sub _start_pre_fork {
    my $self = shift;

    # pre_fork value already validated in _prepare()
    $self->{endjinn}->set_multiprocess(1);

    POSIX::setsid() or croak "setsid() failed: $!";

    $self->{_kids} = [];
    $self->{_n_kids} = 0;
    $self->_fork_another($_) for (1 .. $self->{pre_fork});

    # Parent stops accepting - children handle connections
    $self->{endjinn}->unlisten();

    # With SO_REUSEPORT, parent can close its sockets entirely
    # Children have their own sockets
    if ($self->{_use_reuseport}) {
        for my $sock (@{$self->{_socks} || []}) {
            close($sock)
                or warn "close parent socket after fork: $!";
        }
        $self->{sock} = undef;
        $self->{_socks} = [];
    }
    return;
}

sub _daemonize_and_write_pid {
    my $self = shift;

    if ($self->{daemonize}) {
        my $pid = fork;
        croak "daemonize fork: $!" unless defined $pid;
        if ($pid) {
            if (my $file = $self->{pid_file}) {
                open my $fh, '>', $file or croak "Cannot write pid_file '$file': $!";
                print $fh "$pid\n";
                close $fh;
            }
            POSIX::_exit(0);
        }
        POSIX::setsid();
        open STDIN,  '<', '/dev/null' or croak "redirect stdin: $!";
        open STDOUT, '>', '/dev/null' or croak "redirect stdout: $!";
        open STDERR, '>', '/dev/null' or croak "redirect stderr: $!"
            unless $ENV{FEERSUM_DEBUG};
    } elsif (my $file = $self->{pid_file}) {
        open my $fh, '>', $file or croak "Cannot write pid_file '$file': $!";
        print $fh "$$\n";
        close $fh;
    }
}

sub _drop_privs {
    my $self = shift;
    if (my $group = $self->{group}) {
        my $gid = getgrnam($group);
        croak "Unknown group '$group'" unless defined $gid;
        # Setting $) clears supplemental groups AND sets effective GID (via
        # setgroups + setgid). Without this, supplemental groups like wheel,
        # sudo, docker, shadow inherited from root are retained after setuid.
        $) = "$gid $gid";
        croak "setgroups/setegid($gid): $!" if $!;
        POSIX::setgid($gid) or croak "setgid($gid): $!";
        # Verify drop took effect AND supplemental groups were cleared
        # (some LSMs/seccomp policies silently no-op setgroups).
        my @rg = split ' ', $(;
        croak "setgid($gid) verification failed: real GID list is @rg"
            unless @rg == 1 && $rg[0] == $gid;
    }
    if (my $user = $self->{user}) {
        my $uid = getpwnam($user);
        croak "Unknown user '$user'" unless defined $uid;
        POSIX::setuid($uid) or croak "setuid($uid): $!";
        # Verify the privilege drop actually happened.
        croak "setuid($uid) verification failed: \$<=$<, \$>=$>"
            unless $< == $uid && $> == $uid;
    }
}

sub quit {
    my $self = shift;
    return if $self->{_shutdown};

    $self->{_shutdown} = 1;
    $self->{quiet} or warn "Feersum [$$]: shutting down...\n";
    my $death = $self->{graceful_timeout}
             // $ENV{FEERSUM_GRACEFUL_TIMEOUT}
             // DEATH_TIMER;

    if ($self->{_n_kids}) {
        # in parent, broadcast SIGQUIT to the process group (including self,
        # but protected by _shutdown flag above)
        kill POSIX::SIGQUIT, -$$;
        $death += DEATH_TIMER_INCR;
    }
    else {
        # in child or solo process
        $self->{endjinn}->graceful_shutdown(sub { POSIX::_exit(0) });
    }

    $self->{_death} = EV::timer $death, 0, sub { POSIX::_exit(1) };
    return;
}

1;
__END__

=head1 NAME

Feersum::Runner - feersum script core

=head1 SYNOPSIS

    use Feersum::Runner;
    my $runner = Feersum::Runner->new(
        listen => 'localhost:5000',
        pre_fork => 0,
        quiet => 1,
        app_file => 'app.feersum',
    );
    $runner->run($feersum_app);

=head1 DESCRIPTION

Process manager for Feersum.  Handles listen sockets, pre-forking,
hot restart, TLS, daemonization, and graceful shutdown.

=head1 METHODS

=over 4

=item C<< Feersum::Runner->new(%params) >>

Returns a Feersum::Runner singleton.  If called again while not running, the
previous instance is replaced with a new one using the provided params.

=over 8

=item listen

Listen address as an arrayref containing one or more address strings, e.g.,
C<< listen => ['localhost:5000'] >>. Formats: C<host:port> for IPv4,
C<[host]:port> for IPv6 (e.g., C<['[::1]:8080']>).

B<Important:> IPv6 addresses require C<reuseport> AND C<pre_fork> to be
enabled, plus Perl 5.14+ with Socket IPv6 support. Without these, only IPv4
addresses are supported.

Alternatively, use C<host> and C<port> parameters.

=item pre_fork

Fork this many worker processes.

By default the app is loaded once in the parent and workers inherit it via
fork (copy-on-write friendly).  Set C<< preload_app => 0 >> to load the app
independently in each worker instead.

=item preload_app

Controls whether the app is loaded before or after forking workers (default:
true / load before fork).

When true (default), the app and all its modules are loaded once in the parent
process.  Workers inherit the loaded code via fork, benefiting from OS
copy-on-write memory sharing.  Use C<after_fork> to reconnect per-process
resources (database handles, etc.).

When false, workers fork first and each loads the app independently.
This is useful when the app has per-process initialization that cannot be
deferred to C<after_fork>, or when you want to test that module loading
works in the worker environment.  Requires C<app_file>.

    Feersum::Runner->new(
        pre_fork    => 4,
        preload_app => 0,
        app_file    => 'app.psgi',
        after_fork  => sub { ... },
    )->run;

=item hot_restart

Enable generation-based hot restart.  Requires C<app_file>.

The entry process becomes a supervisor that manages "generations".  Each
generation is a forked child that loads the app and all modules from scratch.
On C<SIGHUP>, a new generation is forked; if it starts successfully, the old
generation is gracefully shut down via C<SIGQUIT>.  Failed restarts are
rolled back (old generation continues serving).

Works with C<pre_fork>: each generation forks its own workers.  All modules
are reloaded cleanly (fresh C<%INC> via fork, not in-process C<do>).

    plackup -s Feersum --app-file app.psgi -o hot_restart=1 -o pre_fork=4
    kill -HUP <master-pid>   # zero-downtime restart with fresh modules

=item backlog

Listen socket backlog size (default: C<SOMAXCONN>).  Set to a higher value
(e.g. 65535) if the kernel's C<somaxconn> is tuned above the compile-time
C<SOMAXCONN> constant.  The kernel silently clamps to its own maximum.

=item keepalive

Enable/disable http keepalive requests.

=item reverse_proxy

Enable reverse proxy mode. When enabled, Feersum trusts X-Forwarded-For and
X-Forwarded-Proto headers from upstream proxies:

=over

=item * REMOTE_ADDR is set to the first IP in X-Forwarded-For (the original client)

=item * psgi.url_scheme is set from X-Forwarded-Proto (http or https)

=back

For the native interface, use C<< $req->client_address >> and C<< $req->url_scheme >>
to get the forwarded values (these respect reverse_proxy mode automatically).

Only enable this when Feersum is behind a trusted proxy that sets these headers.

=item proxy_protocol

Enable PROXY protocol support (HAProxy protocol). When enabled, Feersum expects
each new connection to begin with a PROXY protocol header before any HTTP data.
Both v1 (text) and v2 (binary) formats are auto-detected and supported.

The PROXY protocol header provides the real client IP address when Feersum is
behind a load balancer like HAProxy, AWS ELB/NLB, or nginx (with proxy_protocol).

When a valid PROXY header is received:

=over

=item * REMOTE_ADDR/REMOTE_PORT are updated to the source address from the header

=item * For v1 UNKNOWN or v2 LOCAL commands, the original address is preserved

=back

This option works independently of C<reverse_proxy>. When both are enabled,
the PROXY protocol sets the base address, which can then be overridden by
X-Forwarded-For headers if reverse_proxy is also enabled.

B<Important:> Only enable this when ALL connections come through a proxy that
sends PROXY headers. Connections without valid PROXY headers will be rejected
with HTTP 400.

Example HAProxy configuration:

    backend feersum_backend
        mode http
        server feersum 127.0.0.1:5000 send-proxy-v2

=item psgix_io

Enable or disable the C<psgix.io> PSGI extension (default: enabled).  When
disabled, Feersum skips creating C<psgix.io> in the PSGI env hash, which avoids
per-request overhead if your app never uses WebSocket upgrades or raw I/O.

=item read_timeout

Set read/keepalive timeout in seconds.

=item header_timeout

Set maximum time (in seconds) to receive complete HTTP headers (Slowloris
protection). Default is 10 seconds. Pass 0 to disable. Connections that don't
complete headers within the timeout are closed.

=item write_timeout

Set maximum time (in seconds) to complete writing a response. Default is 0
(disabled). When enabled, connections that stall during response writing are
closed.

=item max_connection_reqs

Set max requests per connection in case of keepalive - 0(default) for unlimited.

=item max_accept_per_loop

Set max connections to accept per event loop cycle (default: 64). Lower values
give more fair distribution across workers when using C<epoll_exclusive>.
Higher values improve throughput under heavy load by reducing syscall overhead.

=item max_connections

Set maximum concurrent connections (default: 10000). When the limit is
reached, new connections are immediately closed. Provides protection against
Slowloris-style DoS attacks.

=item max_read_buf

Set max read buffer size per connection (default: 64 MB).  This limits how
large the read buffer can grow during header parsing and chunked body
reception.

=item max_body_len

Set max request body size (default: 64 MB).  This limits Content-Length
values and cumulative chunked body sizes.

=item max_uri_len

Set max request URI length (default: 8192).

=item wbuf_low_water

Set write buffer low-water mark in bytes (default: 0).  Used with C<poll_cb()>
on streaming responses: the callback fires when the buffer drains to or below
this threshold.

=item read_priority

=item write_priority

=item accept_priority

Set libev I/O watcher priorities for read, write, and accept operations.
Valid range is -2 (lowest) to +2 (highest), default is 0.

=item tls

Enable TLS 1.3 on all listeners. Pass a hash reference with C<cert_file>
and C<key_file> paths:

    Feersum::Runner->new(
        listen => ['0.0.0.0:8443'],
        tls    => { cert_file => 'server.crt', key_file => 'server.key' },
        app    => $app,
    )->run;

Requires Feersum to be compiled with TLS support (picotls submodule + L<Alien::OpenSSL>).
HTTP/2 is not enabled by default; pass C<< h2 => 1 >> separately to enable it.

=item tls_cert_file

=item tls_key_file

Flat alternatives to the C<tls> hash, useful with Plack's C<-o> flag:

    plackup -s Feersum -o tls_cert_file=server.crt -o tls_key_file=server.key

Both must be specified together. If a C<tls> hash is also provided, it takes
precedence and these are ignored.

=item h2

Enable HTTP/2 negotiation via ALPN on TLS listeners (default: off). Requires
TLS to be enabled. When L<Alien::nghttp2> was available at build time and this
option is set, HTTP/2 is negotiated alongside HTTP/1.1 during the TLS handshake.

    Feersum::Runner->new(
        listen => ['0.0.0.0:8443'],
        tls    => { cert_file => 'server.crt', key_file => 'server.key' },
        h2     => 1,
        app    => $app,
    )->run;

If set without TLS enabled, a fatal error (croak) is raised.

=item sni

SNI virtual hosting: an arrayref of C<< { sni => $hostname, cert_file => $path,
key_file => $path } >> hashes.  Each entry adds a certificate for the given
hostname.  Requires C<tls> to be set first (provides the default cert).

    Feersum::Runner->new(
        listen => ['0.0.0.0:8443'],
        tls    => { cert_file => 'default.crt', key_file => 'default.key' },
        sni    => [
            { sni => 'example.com', cert_file => 'ex.crt', key_file => 'ex.key' },
            { sni => 'other.com',   cert_file => 'ot.crt', key_file => 'ot.key' },
        ],
        app    => $app,
    )->run;

=item reuseport

Enable SO_REUSEPORT for better prefork scaling (default: off). When enabled in
combination with C<pre_fork>, each worker process creates its own socket bound
to the same address. The kernel then distributes incoming connections across
workers, eliminating accept() contention and improving multi-core scaling.
Requires Linux 3.9+ or similar kernel support.

B<Note:> IPv6 support requires C<reuseport> AND C<pre_fork> to be enabled.
Without these, only IPv4 addresses are supported.

=item epoll_exclusive

Enable EPOLLEXCLUSIVE for better prefork scaling on Linux 4.5+ (default: off).
When enabled in combination with C<pre_fork>, only one worker is woken per
incoming connection, avoiding the "thundering herd" problem. Use with
C<max_accept_per_loop> to tune fairness vs throughput.

=item max_requests_per_worker

Maximum total requests a worker process will handle before gracefully
recycling (default: 0 = unlimited).  Requires C<pre_fork>.  The parent
automatically forks a replacement worker.  Useful for containing memory
leaks in long-running applications.

=item access_log

Code reference called after each response completes (native handler only).
Receives C<($method, $uri, $elapsed_seconds)>.  For PSGI apps, use
L<Plack::Middleware::AccessLog> instead.

    access_log => sub {
        my ($method, $uri, $elapsed) = @_;
        warn sprintf "%s %s %.3fms\n", $method, $uri, $elapsed * 1000;
    },

=item graceful_timeout

Seconds to wait for in-flight requests to complete during graceful shutdown
before force-exiting (default: 5).  Also honors the C<FEERSUM_GRACEFUL_TIMEOUT>
environment variable (option takes precedence).

=item startup_timeout

Seconds to wait for a hot_restart generation to signal readiness before
declaring it failed and rolling back (default: 10).

=item after_fork

Code reference called in each worker child immediately after fork, before
entering the event loop.  Use this to reconnect database handles, reseed
PRNGs, or close inherited file descriptors:

    after_fork => sub { $dbh = DBI->connect(...) },

=item pid_file

Write the server PID to this file.  Removed on clean shutdown.

=item daemonize

Fork into background, redirect STDIN/STDOUT/STDERR to /dev/null,
and call C<setsid()>.  The PID file (if specified) is written with the
daemon's PID.

=item user

=item group

Drop privileges to this user/group after creating listen sockets but before
loading the application.  Allows binding to privileged ports as root.

=item max_h2_concurrent_streams

Maximum concurrent HTTP/2 streams per connection (default: 100).
Requires H2 support compiled in.

=item quiet

Don't be so noisy. (default: on)

=item app_file

Load this filename as a native feersum app.

=back

=item C<< $runner->run($feersum_app) >>

Run Feersum with the specified app code reference.  Note that this is not a
PSGI app, but a native Feersum app.

=item C<< $runner->assign_request_handler($subref) >>

For sub-classes to override, assigns an app handler. (e.g.
L<Plack::Handler::Feersum>).  By default, this assigns a Feersum-native (and
not PSGI) handler.

=item C<< $runner->quit() >>

Initiate a graceful shutdown.  A signal handler for SIGQUIT will call this
method.

=back

=head1 AUTHOR

Jeremy Stashewsky, C<< stash@cpan.org >>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Jeremy Stashewsky & Socialtext Inc.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.7 or,
at your option, any later version of Perl 5 you may have available.

=cut
