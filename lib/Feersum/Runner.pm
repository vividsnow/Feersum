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
use Scalar::Util qw/weaken blessed reftype/;
use List::Util qw/any/;
use Carp qw/carp croak/;
use File::Spec::Functions 'rel2abs';

use constant DEATH_TIMER => 5.0; # seconds
use constant DEATH_TIMER_INCR => 2.0; # seconds
use constant DEFAULT_HOST => 'localhost';
use constant DEFAULT_PORT => 5000;
use constant MAX_PRE_FORK => $ENV{FEERSUM_MAX_PRE_FORK} || 1000;
# Worker respawn backoff. A worker dying faster than RESPAWN_INSTANT_DEATH
# (broken app_file, dying after_fork, reuseport bind failure after privdrop)
# would otherwise be re-forked thousands of times per second.
use constant RESPAWN_INSTANT_DEATH => 1.0;  # seconds
use constant RESPAWN_BACKOFF_BASE  => 0.1;  # seconds, doubled per failure
use constant RESPAWN_BACKOFF_MAX   => 30.0; # seconds
use constant RESPAWN_MAX_FAILS     => 10;   # then retry at BACKOFF_MAX only
use constant MAX_PORT              => 65_535;
use constant MIN_LIKELY_PORT       => 1024; # below this, a bare number is ambiguous
use constant PORT_DIGITS           => 5;    # a 5-digit tail is definitely a port
use constant PRIORITY_MIN          => -2;   # libev EV_MINPRI; max is +2
use constant SYSCALL_ERROR         => -1;   # the usual failure return
use constant DEFAULT_STARTUP_TIMEOUT => 10; # seconds
use constant READY_TOKEN_SIZE       => 8;  # daemonize readiness handshake
use constant WSTATUS_SIGNAL_MASK   => 127;  # low 7 bits of a wait() status
use constant WSTATUS_EXIT_SHIFT    => 8;    # high bits hold the exit code
use constant WAIT_ANY_PID          => -1;   # waitpid(): any child
# Exit status a worker uses when it retires itself on max_requests_per_worker.
# Distinct so the supervisor does not mistake a deliberate, fast retirement for
# a crash and start backing off - with a small limit a worker legitimately lives
# well under RESPAWN_INSTANT_DEATH.
use constant EXIT_RETIRED          => 42;
use constant FINAL_REAP_ATTEMPTS   => 100;

# RequireCarping: warn() here is a daemon logging its own state, not a library
#   complaining about its caller, and carp() appends a stack frame even to
#   newline-terminated messages.  The one die() is a rethrow.
# RequireCheckedClose: the unchecked close() calls are best-effort cleanup
#   before croak() or at exit; the pid-file writes, where failure loses data,
#   are checked.
## no critic (ErrorHandling::RequireCarping, InputOutput::RequireCheckedClose)

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
    $self->{_term} = undef;
    $self->{_int}  = undef;
    $self->{_hup}  = undef;
    # _death force-exits the process; leaving it armed lets a run() that has
    # already returned _exit(1) an embedder seconds later.
    $self->{_death} = undef;
    $self->{_kids}  = undef;
    $self->{_respawn_timers} = undef;  # cancel any pending worker respawn
    $self->{running} = 0;
    # Only if it is still ours: a second instance that fails to start would
    # otherwise delete the running server's pid file on its way out.
    $self->_remove_pid_file;
    return;
}

# Remove the pid file, but only if it still holds OUR pid.
sub _remove_pid_file {
    my $self = shift;
    my $file = $self->{pid_file} or return;
    open my $fh, '<', $file or return;
    my $owner = <$fh>;
    close $fh;
    $owner = '' unless defined $owner;
    $owner =~ s/\s+//g;
    return unless $owner eq $$;
    # Needs write permission on the DIRECTORY, which /run rarely gives the user
    # we dropped to; silently, the stale file outlives us and the next
    # `kill $(cat ...)` goes to whatever recycled our pid.
    unlink($file) or warn "Feersum [$$]: cannot remove pid_file '$file': $!\n";
    return;
}

sub DESTROY {
    my ($self) = @_;
    local $@ = undef;
    $self->_cleanup();
    return;
}

sub _create_socket { ## no critic (ProhibitExcessComplexity)
    my ($self, $listen, $use_reuseport, $no_listen) = @_;
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
        # IO::Socket::INET is IPv4-only and does not understand [host]:port, so
        # an IPv6 address has to take the manual socket() path below - which
        # used to be reachable only with reuseport, making `listen =>
        # ['[::1]:5000']` fail with a confusing "invalid port ':1]'".
        my $is_ipv6_form = ($listen =~ /^\[/ || $listen =~ /:.*:/) ? 1 : 0;
        my $want_reuseport = ($use_reuseport && defined SO_REUSEPORT) ? 1 : 0;
        # SO_REUSEPORT must be set BEFORE bind for multiple sockets per port
        if ($want_reuseport || $is_ipv6_form) {
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
                    if ($maybe_port <= MAX_PORT && (length($maybe_port) == PORT_DIGITS || $maybe_port >= MIN_LIKELY_PORT)) {
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
            if ($port !~ /^\d+$/ || $port > MAX_PORT) {
                croak "invalid port '$port': must be 0-" . MAX_PORT;
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
            if ($want_reuseport) {
                setsockopt($sock, SOL_SOCKET, SO_REUSEPORT, pack("i", 1))
                    or do { close($sock); croak "setsockopt SO_REUSEPORT failed: $!"; };
            }
            bind($sock, $sockaddr)
                or do { close($sock); croak "couldn't bind to socket: $!"; };
            # Probe mode (_verify_reuseport_bind): skip listen(), which would
            # join the reuseport group and let the kernel steer connections at
            # a socket we are about to close.
            return $sock if $no_listen;
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
                croak "invalid port '$port': must be 0-" . MAX_PORT if $port > MAX_PORT;
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


# Option name -> Feersum setter method. Used by both _prepare (cold start,
# consumes from $self) and _apply_settings (hot_restart child, preserves
# $self). Adding a new "set this value if defined" setting in one place but
# not the other would silently break hot_restart workers, so both paths
# iterate the same list.
my @SIMPLE_SETTINGS = (
    [keepalive            => 'set_keepalive'],
    [reverse_proxy        => 'set_reverse_proxy'],
    [proxy_protocol       => 'set_proxy_protocol'],
    [psgix_io             => 'set_psgix_io'],
    [read_timeout         => 'read_timeout'],
    [header_timeout       => 'header_timeout'],
    [write_timeout        => 'write_timeout'],
    [max_connection_reqs  => 'max_connection_reqs'],
    [read_priority        => 'read_priority'],
    [write_priority       => 'write_priority'],
    [accept_priority      => 'accept_priority'],
    [max_accept_per_loop  => 'max_accept_per_loop'],
    [max_connections      => 'max_connections'],
    [max_read_buf         => 'max_read_buf'],
    [max_body_len         => 'max_body_len'],
    [max_uri_len          => 'max_uri_len'],
    [wbuf_low_water       => 'wbuf_low_water'],
    [max_h2_concurrent_streams => 'max_h2_concurrent_streams'],
);

# Walk @SIMPLE_SETTINGS. $consume=1 deletes from $self after applying
# (cold-start path); $consume=0 leaves $self intact (hot_restart child
# re-applying preserved config from master).
sub _apply_simple_settings {
    my ($self, $f, $consume) = @_;
    for my $pair (@SIMPLE_SETTINGS) {
        my ($opt, $meth) = @$pair;
        my $val = $consume ? delete $self->{$opt} : $self->{$opt};
        $f->$meth($val) if defined $val;
    }
    return;
}

# Retire the worker once it has served max_requests_per_worker requests.  The
# limit is enforced in XS next to the request counter, so there is no watcher to
# keep alive.  Used by the hot_restart generation and by pre_fork workers.
sub _set_max_requests_per_worker {
    my ($self, $f) = @_;
    my $max = $self->{max_requests_per_worker} or return;
    # A Perl-side poll overshot a limit of 10 by three orders of magnitude
    # under load, and a per-loop-iteration check costs more than it guards.
    $f->max_requests_per_worker($max, sub { POSIX::_exit(EXIT_RETIRED) });
    return;
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
    return;
}

sub _normalize_listen {
    my $self = shift;
    if (defined $self->{listen} && !ref $self->{listen}) {
        $self->{listen} = [ $self->{listen} ];
    }
    $self->{listen} ||=
        [ ($self->{host}||DEFAULT_HOST) . q{:} . ($self->{port}||DEFAULT_PORT) ];
    croak "listen must be an array reference"
        if ref $self->{listen} ne 'ARRAY';
    croak "listen array cannot be empty"
        if @{$self->{listen}} == 0;
    # An undef/empty/bare-numeric entry used to reach IO::Socket::INET as
    # LocalAddr and bind 0.0.0.0 on a random port, so `--listen=$EMPTY_VAR`
    # from a config template silently produced a world-reachable server on an
    # unknown port instead of an error.
    for my $i (0 .. $#{$self->{listen}}) {
        my $l = $self->{listen}[$i];
        croak "listen[$i] is undefined" unless defined $l;
        croak "listen[$i] is empty"     unless length $l;
        croak "listen[$i] '$l' is not an address: use host:port, [ipv6]:port, "
            . "or a socket path" if $l =~ /\A\d+\z/;
        # Same trap one step further in: a spec with no port at all reaches
        # bind() as port 0, so `--listen localhost` came up on a random port
        # with no diagnostic.  Socket paths and bare IPv6 (which cannot carry
        # a port unbracketed) are exempt.
        next if $l =~ m{\A[/.]}
             || ($l =~ /\A\[/ ? $l =~ /\]:/ : $l =~ /:/);
        croak "listen[$i] '$l' has no port: use $l:PORT "
            . "(a portless address binds an arbitrary port)";
    }
    $self->{_listen_addrs} = [ @{$self->{listen}} ];
    return;
}

# Fold the flat tls_cert_file/tls_key_file shorthand and the top-level h2 flag
# into $self->{tls} (a hashref), in place, and validate. Shared by the
# cold-start _prepare path and the hot_restart master so that generation
# children - which apply TLS via _apply_settings, not _prepare - get identical
# TLS/H2 configuration. Does NOT consume $self->{tls} (hot_restart re-reads it
# for each generation).
sub _normalize_tls_config {
    my $self = shift;
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
    if (my $tls = $self->{tls}) {
        croak "tls must be a hash reference" unless ref $tls eq 'HASH';
        croak "tls requires cert_file" unless $tls->{cert_file};
        croak "tls requires key_file" unless $tls->{key_file};
        # H2 is off by default; only enable if h2 => 1 was passed
        $tls->{h2} = 1 if delete $self->{h2};
    } elsif (delete $self->{h2}) {
        croak "h2 requires TLS (provide tls_cert_file and tls_key_file, or a tls hash)";
    }
    # sni without a base tls config would otherwise be silently ignored,
    # leaving the listeners on plaintext - fail loudly like h2 above
    croak "sni requires TLS (provide tls_cert_file and tls_key_file, or a tls hash)"
        if $self->{sni} && !$self->{tls};
    return;
}

# Validate pre_fork early (before socket creation) to fail fast. Shared by
# the cold-start (_prepare) and hot_restart-master paths, which both fork
# workers off this value; one source prevents the two from drifting.
sub _validate_pre_fork {
    my $self = shift;
    return unless $self->{pre_fork};
    my $n = $self->{pre_fork};
    croak "pre_fork must be a positive integer" if $n !~ /^\d+$/ || $n < 1;
    croak "pre_fork=$n exceeds maximum of " . MAX_PRE_FORK if $n > MAX_PRE_FORK;
    return;
}

# A listen spec that names a filesystem path, i.e. an AF_UNIX socket.  Kept in
# one place: _create_socket, the reuseport worker path and the parent-side
# socket cleanup must all agree, or a worker ends up with an undef listener.
sub _is_unix_listen {
    my ($listen) = @_;
    return defined($listen) && $listen =~ m{^[/.]+\w} ? 1 : 0;
}

# A bare coderef, but also a blessed coderef or an object overloading &{} -
# call_sv() invokes any of them.  Testing ref() eq 'CODE' would reject callable
# objects that used to serve perfectly well.
sub _is_callable {
    my ($app) = @_;
    return 0 unless ref $app;
    return 1 if (reftype($app) || q{}) eq 'CODE';
    return 1 if blessed($app) && do { require overload;
                                      overload::Method($app, '&{}') };
    return 0;
}

# Reuseport is enabled automatically in prefork mode when SO_REUSEPORT is
# available.  One source for the cold-start, hot_restart-master and
# generation-child paths, which must agree.
sub _reuseport_enabled {
    my $self = shift;
    # UNIX listeners are handled per-listener in the worker (they keep the
    # inherited fd instead of rebinding); turning reuseport off wholesale here
    # would drop IPv6 listeners into the AF_INET-only socket path.
    return $self->{reuseport} && $self->{pre_fork} && defined SO_REUSEPORT;
}

sub _prepare { ## no critic (ProhibitExcessComplexity)
    my $self = shift;

    $self->_normalize_listen();
    $self->_validate_pre_fork;

    my $use_reuseport = $self->_reuseport_enabled;
    $self->{_use_reuseport} = $use_reuseport;

    my $f = Feersum->endjinn;

    # EPOLLEXCLUSIVE must be set BEFORE use_socket() so the separate accept epoll
    # is created with EPOLLEXCLUSIVE flag (Linux 4.5+)
    if ($self->{epoll_exclusive} && $self->{pre_fork} && $^O eq 'linux') {
        $f->set_epoll_exclusive(1);
    }

    # accept_priority must also be set BEFORE use_socket(): each accept watcher
    # captures srvr->accept_priority when created (setup_accept_watcher), so a
    # later assignment only affects listeners added afterwards.
    if (defined $self->{accept_priority}) {
        my $val = $self->{accept_priority};
        croak "accept_priority must be an integer" unless $val =~ /^-?\d+$/;
        croak "accept_priority must be between -2 and 2" if $val < PRIORITY_MIN || $val > 2;
        $f->accept_priority($val);
    }

    my @socks;
    for my $listen (@{$self->{_listen_addrs}}) {
        my $sock = $self->_create_socket($listen, $use_reuseport);
        push @socks, $sock;
        $f->use_socket($sock);
    }
    $self->{sock} = $socks[0];   # backward compat: primary socket
    $self->{_socks} = \@socks;   # all sockets

    # Validate priorities (-2..+2 per libev) before applying; accept_priority
    # was already validated (and applied) before use_socket above.
    for my $prio_name (qw/read_priority write_priority/) {
        my $val = $self->{$prio_name};
        next unless defined $val;
        croak "$prio_name must be an integer" unless $val =~ /^-?\d+$/;
        croak "$prio_name must be between -2 and 2" if $val < PRIORITY_MIN || $val > 2;
    }
    if (defined(my $val = $self->{max_accept_per_loop})) {
        croak "max_accept_per_loop must be a positive integer"
            if $val !~ /^\d+$/ || $val < 1;
    }
    if (defined(my $val = $self->{max_connections})) {
        croak "max_connections must be a non-negative integer"
            unless $val =~ /^\d+$/;
    }
    $self->_apply_simple_settings($f, 1);  # consume from $self

    # Fold flat tls_cert_file/tls_key_file shorthand + h2 into $self->{tls}
    # (also used by the hot_restart master via _normalize_tls_config).
    $self->_normalize_tls_config;

    # TLS configuration: apply to all listeners
    if (my $tls = delete $self->{tls}) {
        (-f $tls->{cert_file} && -r _)
            or croak "tls cert_file '$tls->{cert_file}': not found or not readable";
        (-f $tls->{key_file} && -r _)
            or croak "tls key_file '$tls->{key_file}': not found or not readable";

        if ($f->has_tls()) {
            $self->_apply_tls_to_listeners($f, scalar(@socks), $tls, $self->{sni});
            $self->{_tls_config} = $tls;  # for reuseport workers
            $self->{quiet} or warn "Feersum [$$]: TLS enabled on "
                . scalar(@socks) . " listener(s)\n";
        } else {
            croak "tls option requires Feersum compiled with TLS support (need picotls submodule + OpenSSL; see Alien::OpenSSL)";
        }
    }

    $self->{endjinn} = $f;
    return;
}

# for overriding:
sub assign_request_handler {
    my ($self, $app) = @_;
    # Enforced in XS, next to the response-completion point.  The old Perl
    # wrapper cost a closure, two accessor calls and a Guard allocation on
    # every request, and hung the line off response_guard - which fires when
    # the CONNECTION is released, so under keepalive each entry came out one
    # request late timing the gap to the next request instead of its own.
    $self->{endjinn}->access_log($self->{access_log});
    return $self->{endjinn}->request_handler($app);
}

sub run { ## no critic (ProhibitExcessComplexity)
    my $self = shift;
    weaken $self;

    $self->{running} = 1;
    my $app = shift || $self->{app};
    $self->{quiet} or warn "Feersum [$$]: starting...\n";

    # Hot restart mode: entry process creates sockets, then manages
    # generation children that each load a fresh app with clean modules.
    if ($self->{hot_restart}) {
        croak "hot_restart requires app_file" unless $self->{app_file};
        # Bind BEFORE daemonizing so a bind failure reaches the exit status,
        # exactly as the normal path's _prepare() does.
        $self->_hot_restart_bind();
        $self->_daemonize_and_write_pid();
        $self->_run_hot_restart_master();  # creates sockets, then drops privs
        # Pid file is documented as removed on clean shutdown; DESTROY at
        # interpreter exit doesn't cover fork + run() + POSIX::_exit embedders.
        $self->_cleanup();
        return;
    }

    $self->_prepare();       # bind() on listen sockets
    $self->_daemonize_and_write_pid();
    $self->_drop_privs();    # after bind, before app load

    # preload_app => 0: fork workers first, each loads the app independently.
    # Default (preload_app unset or true): load app once, fork inherits via COW.
    if ($self->{pre_fork} && defined $self->{preload_app} && !$self->{preload_app}) {
        # An already-compiled coderef cannot be re-loaded per worker, so the
        # loader below would silently hand every worker the same pre-fork app -
        # the opposite of what preload_app => 0 asks for, with no diagnostic.
        croak "preload_app => 0 requires app_file (an app coderef is compiled "
            . "before the fork and cannot be loaded independently per worker)"
            if ($app || $self->{app}) && !$self->{app_file};
        $self->{_app_loader} = sub {
            # Not $a: declaring it lexically shadows sort's special variable.
            my $handler = $app || $self->{app};
            if (!$handler && $self->{app_file}) {
                local ($@, $!) = (undef, undef);
                $handler = do(rel2abs($self->{app_file}));
                warn "couldn't load $self->{app_file}: " . ($@ || $!)
                    if $@ || !$handler;
            }
            croak "app not defined or failed to compile" unless $handler;
            croak "app must be callable, got " . (ref($handler) || 'a plain scalar')
                unless _is_callable($handler);
            $self->assign_request_handler($handler);
        };
        # No parent request_handler: _start_pre_fork unlistens and nothing
        # re-listens, so the 503 handler that used to sit here never ran.  An
        # empty pool queues in the backlog until a worker returns; 503 instead
        # would fail requests on every pre_fork=1 respawn.
        $self->{_quit} = EV::signal 'QUIT', sub { $self && $self->quit };
        # systemctl stop sends TERM; unhandled it orphans the workers, which
        # keep the port bound against a restart.  INT likewise: _start_pre_fork
        # calls setsid(), so Ctrl-C never reaches us and operators send it by
        # pid - and with reuseport an orphaned pool keeps serving stale code.
        $self->{_term} = EV::signal 'TERM', sub { $self && $self->quit };
        $self->{_int}  = EV::signal 'INT',  sub { $self && $self->quit };
        # HUP means "reload" to operators - that is what hot_restart uses it for -
        # but unhandled it kills this supervisor and orphans the workers, which keep
        # the port bound and serve stale code.  Refuse loudly and keep running.
        $self->{_hup}  = EV::signal 'HUP',  sub {
            warn "Feersum [$$]: SIGHUP ignored (reload requires hot_restart)\n";
        };
        $self->_start_pre_fork;
    } else {
        $app ||= delete $self->{app};
        if (!$app && $self->{app_file}) {
            local ($@, $!) = (undef, undef);
            $app = do(rel2abs($self->{app_file}));
            warn "couldn't parse $self->{app_file}: $@" if $@;
            warn "couldn't do $self->{app_file}: $!" if ($! && !defined $app);
            warn "couldn't run $self->{app_file}: didn't return anything"
                unless $app;
        }
        croak "app not defined or failed to compile" unless $app;
        # A truthy non-callable used to bind the port and 500 every request; the
        # hot-restart child already rejects this.
        croak "app must be callable, got " . (ref($app) || 'a plain scalar')
            unless _is_callable($app);

        $self->assign_request_handler($app);

        $self->{_quit} = EV::signal 'QUIT', sub { $self && $self->quit };
        # systemctl stop sends TERM; unhandled it orphans the workers, which
        # keep the port bound against a restart.  INT likewise: _start_pre_fork
        # calls setsid(), so Ctrl-C never reaches us and operators send it by
        # pid - and with reuseport an orphaned pool keeps serving stale code.
        $self->{_term} = EV::signal 'TERM', sub { $self && $self->quit };
        $self->{_int}  = EV::signal 'INT',  sub { $self && $self->quit };
        # HUP means "reload" to operators - that is what hot_restart uses it for -
        # but unhandled it kills this supervisor and orphans the workers, which keep
        # the port bound and serve stale code.  Refuse loudly and keep running.
        $self->{_hup}  = EV::signal 'HUP',  sub {
            warn "Feersum [$$]: SIGHUP ignored (reload requires hot_restart)\n";
        };

        $self->_start_pre_fork if $self->{pre_fork};
    }
    # Everything that can fail at startup has now succeeded.
    $self->_daemon_ready;
    EV::run;
    $self->{quiet} or warn "Feersum [$$]: done\n";
    $self->_cleanup();
    return;
}

# Hot restart master: creates sockets once, then manages generations.
# Each generation is a forked child that runs _apply_settings + app load + serve.
# SIGHUP -> fork new gen -> if ready -> SIGQUIT old gen.
# Validate the configuration and bind the listen sockets for hot_restart mode.
# Called from run() BEFORE _daemonize_and_write_pid: the daemonizing parent
# exits 0 as soon as it forks, so anything that can fail here - a port already
# in use, a bad listen address, an invalid pre_fork - has to be discovered
# while that exit status can still carry it.  Doing it inside the master (i.e.
# after daemonizing) made "port already in use" exit 0 with nothing listening,
# which a Type=forking supervisor records as a clean start.  Idempotent, so the
# master can call it too for the non-daemonized path.
sub _hot_restart_bind {
    my ($self) = @_;
    return if $self->{_master_socks};

    $self->_normalize_listen();
    # Validate here too: the generation children never run _prepare. An
    # unvalidated non-positive value would fork zero workers yet still
    # unlisten() and report ready - a silent outage.
    $self->_validate_pre_fork;
    # Fold flat TLS keys + h2 into $self->{tls} once, here in the master, so
    # every generation child's _apply_settings sees the complete TLS/H2 config
    # (these children never run _prepare, which is where folding otherwise
    # happens). Without this, hot_restart silently drops flat tls_cert_file/
    # tls_key_file and the h2 flag.
    $self->_normalize_tls_config();

    # Create listen sockets in the master (shared across generations via fork).
    # Use SO_REUSEPORT if configured - reuseport workers need all sockets
    # on the same addr:port to have the flag set.
    my $use_reuseport = $self->_reuseport_enabled;
    $self->{_use_reuseport} = $use_reuseport;
    my @socks;
    for my $listen (@{$self->{_listen_addrs}}) {
        my $sock = $self->_create_socket($listen, $use_reuseport);
        push @socks, $sock;
    }
    $self->{_master_socks} = \@socks;
    return;
}

sub _run_hot_restart_master { ## no critic (ProhibitExcessComplexity)
    my ($self) = @_;
    my $quiet = $self->{quiet};

    $quiet or warn "Feersum [$$]: hot restart master starting\n";

    # No-op when run() already bound before daemonizing; binds here for the
    # non-daemonized path.
    $self->_hot_restart_bind();
    my @socks = @{ $self->{_master_socks} };

    # Drop privileges after sockets are bound (privileged ports are now open)
    $self->_drop_privs();
    # Read after the drop: _drop_privs turns reuseport off when the dropped-to
    # user cannot rebind the address (see _verify_reuseport_bind).
    my $use_reuseport = $self->{_use_reuseport};

    my $gen = 0;
    my $current_pid;
    my $pending_pid;   # generation being started (not yet $current_pid)
    my $shutting_down = 0;
    my $startup_timeout = $self->{startup_timeout} // DEFAULT_STARTUP_TIMEOUT;

    # Declared before $fork_generation so the child can undef its inherited
    # copies: EV watchers survive fork+loop_fork and would otherwise fire in
    # the child with stale fork-time state (e.g. SIGQUIT to a $current_pid from
    # a previous generation, which after pid reuse is an unrelated process).
    my ($hup, $quit, $int, $term, $reap, $usr2, $master_death);
    # Readiness flag fed by a PERSISTENT USR2 watcher.  A generation signals
    # readiness with USR2; if the only watcher were the temporary one inside
    # _wait_for_ready, a USR2 arriving outside that window (a generation that
    # timed out and reported ready just afterwards) would hit the default
    # disposition and kill the master.
    my $gen_ready = 0;

    # Fork a generation child.  The child inherits listen sockets via fork,
    # registers them with use_socket, then calls _apply_settings (which
    # applies TLS and other settings without consuming from $self), loads the
    # app file fresh, then serves.
    my $fork_generation = sub {
        $gen++;
        my $pid = fork;
        croak "fork generation: $!" unless defined $pid;

        if ($pid == 0) {
            # === Generation child ===
            # Everything below runs in a forked child, so an exception must not
            # be allowed to propagate: it would unwind out of run() and the
            # child would go on executing whatever the caller's script has
            # after run(), then exit 0.  Only the app-file load used to be
            # guarded; use_socket, _apply_settings (every XS setter, including
            # set_tls) and assign_request_handler were not.
            eval {
            EV::default_loop()->loop_fork;
            # Drop the master's watchers before any loop iteration here.
            undef $hup; undef $quit; undef $int; undef $term; undef $reap;
            undef $usr2; undef $master_death;
            # The master signals daemonize readiness only after generation 1
            # reports ready, so this child inherits the pipe's write end.
            # Holding it means the daemonize parent never sees EOF if the
            # master dies in that window - the same reason _fork_another
            # closes it in pre_fork workers.
            if (my $rdy = delete $self->{_daemon_ready_fh}) { close $rdy }
            $quiet or warn "Feersum [$$]: gen $gen loading app\n";

            # Sockets were created in the master and inherited via fork -
            # register them with this generation's Feersum instance.
            my $f = Feersum->endjinn;
            # EPOLLEXCLUSIVE must be set BEFORE use_socket() so each accept
            # watcher is created with it (mirrors _prepare); otherwise
            # non-reuseport hot_restart workers inherit plain accept watchers
            # and lose the thundering-herd mitigation.
            if ($self->{epoll_exclusive} && $self->{pre_fork} && $^O eq 'linux') {
                $f->set_epoll_exclusive(1);
            }
            # accept_priority also before use_socket (see _prepare); the XS
            # setter clamps to libev's valid range.
            if (defined $self->{accept_priority}) {
                $f->accept_priority($self->{accept_priority});
            }
            if ($use_reuseport) {
                # Each worker binds its own socket, so this generation never
                # accepts on the inherited copies; holding them open would
                # leave a reuseport group member nobody accepts on, which
                # black-holes a share of connections.  Register nothing -
                # _apply_settings skips listener TLS with no listeners and
                # each worker applies TLS to the socket it binds.
                # ...except UNIX listeners, which workers inherit rather than
                # rebind (see _is_unix_listen); this generation keeps them for
                # the workers it forks now and respawns later.
                my $addrs = $self->{_listen_addrs} || [];
                my @keep;
                for my $i (0 .. $#socks) {
                    if (_is_unix_listen($addrs->[$i])) { $keep[$i] = $socks[$i]; next }
                    close($socks[$i])
                        or warn "Feersum [$$]: close inherited socket: $!\n"
                        if defined $socks[$i];
                }
                @socks = @keep;
                $self->{_master_socks} = [];
                $self->{_socks} = \@keep;
                ($self->{sock}) = grep { defined } @keep;
            }
            else {
                for my $sock (@socks) {
                    $f->use_socket($sock);
                }
                $self->{_socks} = \@socks;
                $self->{sock} = $socks[0];
            }

            # Apply server settings (preserved in $self for later generations)
            $self->_apply_settings($f);

            # Load app fresh (fork gave us clean copy-on-write memory)
            my $app_file = rel2abs($self->{app_file});
            local ($@, $!) = (undef, undef);
            my $app = do $app_file;
            if ($@ || !$app || !_is_callable($app)) {
                warn "Feersum [$$]: gen $gen: failed to load $app_file: "
                    . ($@ || $! || "not a coderef") . "\n";
                POSIX::_exit(1);
            }

            $self->{endjinn} = $f;
            $self->assign_request_handler($app);

            my ($quit_w, $term_w, $int_w, $death_w);
            my $begin_gen_shutdown = sub {
                return if $self->{_shutdown};
                $self->{_shutdown} = 1;
                my $gt = $self->{graceful_timeout}
                      // $ENV{FEERSUM_GRACEFUL_TIMEOUT}
                      // DEATH_TIMER;
                if ($self->{_n_kids}) {
                    # Parent of live workers: broadcast SIGQUIT to the process
                    # group (includes self; guarded by _shutdown above) and
                    # let the _fork_another reaper break the loop once the
                    # last worker exits. Calling graceful_shutdown on the
                    # supervisor's own (connection-less) instance would fire
                    # the callback synchronously and _exit(0) before the
                    # workers have drained. Checked via the live worker count,
                    # not pre_fork: with zero live workers there is no reaper
                    # event to wait for, so fall through to graceful_shutdown.
                    kill POSIX::SIGQUIT, -$$;
                    $gt += DEATH_TIMER_INCR;  # outlast the workers' deadline
                }
                else {
                    # Guarded as quit() is: a generation already draining a
                    # retirement croaks "already shutting down" here, and the
                    # croak skipped $death_w below, so this generation lost its
                    # deadline and the master force-KILLed the group, exit 1.
                    eval { $f->graceful_shutdown(sub { POSIX::_exit(0) }); 1 };
                }
                $death_w = EV::timer($gt, 0, sub {
                    # Take this generation's workers with us, as the cold-start
                    # backstop does: exiting alone reparents them to init still
                    # holding the listen socket, so the next start fails with
                    # EADDRINUSE.  The pid file belongs to the master, so unlike
                    # the cold-start path we must not remove it here.
                    my @alive = grep { defined } @{ $self->{_kid_pids} || [] };
                    kill 'KILL', @alive if @alive;
                    POSIX::_exit(1);
                });
            };
            # TERM and INT as well as QUIT.  The generation only setsid()s when
            # pre_fork is on, so under systemd's default KillMode=control-group
            # a `systemctl stop` delivers TERM to the generation directly; with
            # no handler it died by default disposition, dropping in-flight
            # requests instead of draining them.  The master says the same
            # thing about itself three watchers down.
            $quit_w = EV::signal 'QUIT', $begin_gen_shutdown;
            $term_w = EV::signal 'TERM', $begin_gen_shutdown;
            $int_w  = EV::signal 'INT',  $begin_gen_shutdown;

            if ($self->{pre_fork}) {
                $f->set_multiprocess(1);
                # The master's decision, not _reuseport_enabled(): recomputing
                # from config undid _verify_reuseport_bind's fallback, so every
                # worker still died at birth on a privileged port.
                $self->{_use_reuseport} = $use_reuseport;
                # (epoll_exclusive already set before use_socket above)
                # NB: setsid() returns -1 (true!) on failure, not undef, so an
                # "or warn" idiom here would never fire.  EPERM just means we
                # are already a session leader, which is harmless.
                POSIX::setsid() == SYSCALL_ERROR and $! != POSIX::EPERM()
                    and warn "Feersum [$$]: setsid failed: $!\n";
                $self->{_kids} = [];
                $self->{_kid_pids} = [];   # inherited: another generation's
                $self->{_n_kids} = 0;
                $self->_fork_another($_) for (1 .. $self->{pre_fork});
                $f->unlisten();  # parent of workers doesn't accept
            }

            if (!$self->{pre_fork}) {
                if (my $cb = $self->{after_fork}) {
                    unless (eval { $cb->(); 1 }) {
                        warn "Feersum [$$]: after_fork failed: $@";
                        POSIX::_exit(1);
                    }
                }
                $self->_set_max_requests_per_worker($f);
            }

            # Signal master: ready to serve (after workers are forked)
            kill 'USR2', getppid();

            $quiet or warn "Feersum [$$]: gen $gen ready"
                . ($self->{pre_fork} ? " ($self->{pre_fork} workers)" : "") . "\n";
            EV::run;
            1;
            } or do {
                my $err = $@ || 'unknown error';
                warn "Feersum [$$]: gen $gen failed to start: $err";
                POSIX::_exit(1);
            };
            POSIX::_exit(0);
        }

        return $pid;
    };

    # Shared shutdown path for QUIT/INT/TERM.
    my $begin_shutdown = sub {
        my ($why) = @_;
        return if $shutting_down;
        $shutting_down = 1;
        $quiet or warn "Feersum [$$]: master $why\n";
        kill 'QUIT', $current_pid if $current_pid;
        # Also the pending gen, in case shutdown raced a HUP reload.
        kill 'QUIT', $pending_pid if $pending_pid;
        # Nothing to reap => the reap watcher (the only other place that
        # breaks the loop) can never fire, so break here or hang forever.
        EV::break unless $current_pid || $pending_pid;

        # A generation wedged inside app code never gets back to its own event
        # loop, so neither its QUIT watcher nor its death timer can run, and
        # this master would then wait on a reap that never comes - holding the
        # listen sockets, so the next start gets EADDRINUSE, and debouncing
        # every further signal via $shutting_down.  quit() has exactly this
        # backstop for the cold-start path; the master had none.  Deliberately
        # later than the generation's own deadline (itself extended by
        # DEATH_TIMER_INCR when it has workers) so the graceful path always
        # gets to finish first.
        my $gt = ($self->{graceful_timeout}
               // $ENV{FEERSUM_GRACEFUL_TIMEOUT}
               // DEATH_TIMER) + 2 * DEATH_TIMER_INCR;
        $master_death = EV::timer $gt, 0, sub {
            $quiet or warn "Feersum [$$]: master shutdown timed out, forcing\n";
            for my $p (grep { $_ } $current_pid, $pending_pid) {
                kill 'KILL', $p;
                # Pre-fork generations setsid(), so their workers are only
                # reachable by group.  ESRCH otherwise, which is harmless.
                kill 'KILL', -$p;
            }
            $self->_remove_pid_file;
            POSIX::_exit(1);
        };
    };

    # $fork_generation croaks on fork failure and EV discards exceptions thrown
    # from a watcher callback, so calling it bare from one left the master
    # looping with nothing serving and no retry armed.  Returns undef instead.
    my $try_fork_generation = sub {
        my $pid = eval { $fork_generation->() };
        return $pid if $pid;
        my $why = $@ || $!;
        $why =~ s/\s+\z//;
        warn "Feersum [$$]: could not fork a generation: $why\n";
        return;
    };

    # Installed BEFORE generation 1 is forked: until they exist the master has
    # default dispositions, so a QUIT during startup (up to startup_timeout)
    # would kill it and orphan the loading generation, which keeps the port.
    $hup = EV::signal 'HUP', sub {
        return if $shutting_down || $pending_pid;  # debounce rapid HUPs
        $quiet or warn "Feersum [$$]: HUP - spawning gen " . ($gen + 1) . "\n";

        my $old_pid = $current_pid;
        # The old generation is still serving, so a failed reload is survivable.
        $pending_pid = $try_fork_generation->() or return;

        if (_wait_for_ready($pending_pid, $quiet, $gen, \$gen_ready,
                            \$shutting_down, $startup_timeout)) {
            $quiet or warn "Feersum [$$]: gen $gen ready (pid $pending_pid), retiring old (pid $old_pid)\n";
            # Only retire the old generation if it is still the one we started
            # with: the reap watcher clears $current_pid when it dies during
            # the reload, and by then the OS may have reused that pid.
            my $retire = ($current_pid && $current_pid == $old_pid) ? $old_pid : undef;
            $current_pid = $pending_pid;
            $pending_pid = undef;
            kill 'QUIT', $retire if $retire;
        } else {
            kill 'KILL', $pending_pid if kill(0, $pending_pid);
            waitpid($pending_pid, 0);
            $pending_pid = undef;
            # The reap watcher may have cleared $current_pid while we were
            # blocked in _wait_for_ready (running generation died mid-reload);
            # it declined to restart because a reload was pending.  Blindly
            # "keeping the old generation" would then leave nothing serving,
            # nothing able to recover, and QUIT ignored forever.
            if ($current_pid) {
                warn "Feersum [$$]: gen $gen failed, keeping old (pid $current_pid)\n";
            }
            elsif ($shutting_down) {
                EV::break;
            }
            else {
                warn "Feersum [$$]: gen $gen failed and the running generation "
                    . "died during the reload - starting a replacement\n";
                # Nothing is serving now, so a failed fork is terminal: exit and
                # let the supervisor restart us rather than loop doing nothing.
                $pending_pid = $try_fork_generation->();
                if (!$pending_pid) {
                    EV::break;
                }
                elsif (_wait_for_ready($pending_pid, $quiet, $gen, \$gen_ready,
                                    \$shutting_down, $startup_timeout)) {
                    $current_pid = $pending_pid;
                } else {
                    warn "Feersum [$$]: replacement generation also failed, "
                        . "giving up\n";
                    kill 'KILL', $pending_pid if kill(0, $pending_pid);
                    waitpid($pending_pid, 0);
                    EV::break;
                }
                $pending_pid = undef;
            }
        }
    };

    $quit = EV::signal 'QUIT', sub { $begin_shutdown->('shutting down') };
    $int  = EV::signal 'INT',  sub { $begin_shutdown->('interrupted') };
    # systemctl stop sends TERM; unhandled it orphans the generation.
    $term = EV::signal 'TERM', sub { $begin_shutdown->('terminated') };
    $usr2 = EV::signal 'USR2', sub { $gen_ready = 1 };

    # Reap children; restart if active generation dies unexpectedly
    $reap = EV::child 0, 0, sub {
        my $kid = $_[0]->rpid;
        my $rstatus = $_[0]->rstatus;
        # Report signals too: a killed generation logged as "exited (0)"
        # misleads postmortems of the failure paths below.
        my $how = ($rstatus & WSTATUS_SIGNAL_MASK)
            ? "killed by signal " . ($rstatus & WSTATUS_SIGNAL_MASK)
            : "exited (" . ($rstatus >> WSTATUS_EXIT_SHIFT) . ")";
        $quiet or warn "Feersum [$$]: child $kid $how\n";
        # Ignore pending generation deaths - handled by _wait_for_ready
        return if $pending_pid && $kid == $pending_pid;
        if ($current_pid && $kid == $current_pid) {
            $current_pid = undef;
            EV::break if $shutting_down;
            unless ($shutting_down || $pending_pid) {
                warn "Feersum [$$]: active generation died, restarting\n";
                # Nothing is serving now, so a failed fork is terminal: exit and
                # let the supervisor restart us rather than loop doing nothing.
                $pending_pid = $try_fork_generation->();
                if (!$pending_pid) {
                    EV::break;
                }
                elsif (_wait_for_ready($pending_pid, $quiet, $gen, \$gen_ready,
                                       \$shutting_down, $startup_timeout)) {
                    $current_pid = $pending_pid;
                } else {
                    # Replacement also failed - kill it and shut down
                    warn "Feersum [$$]: replacement generation also failed, giving up\n";
                    kill 'KILL', $pending_pid if kill(0, $pending_pid);
                    waitpid($pending_pid, 0);
                    EV::break;
                }
                $pending_pid = undef;
            }
        }
    };

    # Fork first generation (watchers above are already armed)
    $pending_pid = $fork_generation->();

    # The generation has inherited the fds; drop the master's copies now.  Held
    # longer they sit in the reuseport group with no acceptor (a share of
    # connections hangs in their backlog) and, being root-owned, keep
    # privdropped workers out of the group entirely.  Later generations rebind.
    if ($use_reuseport) {
        # Keep UNIX listeners: workers inherit those fds rather than rebinding,
        # so the master needs them for every generation it forks from here on.
        my $addrs = $self->{_listen_addrs} || [];
        my @keep;
        for my $i (0 .. $#socks) {
            if (_is_unix_listen($addrs->[$i])) { $keep[$i] = $socks[$i]; next }
            close($socks[$i]) or warn "Feersum [$$]: close master socket: $!\n"
                if defined $socks[$i];
        }
        @socks = @keep;
        $self->{_master_socks} = \@keep;
    }

    unless (_wait_for_ready($pending_pid, $quiet, $gen, \$gen_ready,
                            \$shutting_down, $startup_timeout)) {
        kill 'KILL', $pending_pid if kill(0, $pending_pid);
        waitpid($pending_pid, 0);
        $pending_pid = undef;
        # A QUIT/INT/TERM during startup is a shutdown request, not a failure.
        return if $shutting_down;
        croak "first generation failed to start";
    }
    $current_pid = $pending_pid;
    $pending_pid = undef;

    # Generation 1 is serving: only now is a daemonized start a success.
    $self->_daemon_ready;

    $quiet or warn "Feersum [$$]: master ready (gen $gen, pid $current_pid)\n";

    EV::run;
    # Cleanup
    # grep defined: with reuseport + a UNIX listener the kept-sockets list is
    # sparse (closed TCP slots stay empty so the indices still line up with
    # _listen_addrs), and close(undef) is fatal under strict.
    for my $sock (grep { defined } @socks) { close($sock) }
    waitpid(WAIT_ANY_PID, POSIX::WNOHANG()) for 1 .. FINAL_REAP_ATTEMPTS;
    $quiet or warn "Feersum [$$]: master done\n";
    return;
}

# Wait for a generation child to signal readiness (USR2) or fail.
# Uses RUN_ONCE loop to avoid EV::break propagating to the outer EV::run.
sub _wait_for_ready { ## no critic (ProhibitManyArgs)
    my ($pid, $quiet, $gen, $ready_ref, $shutdown_ref, $timeout) = @_;
    $timeout //= DEFAULT_STARTUP_TIMEOUT;
    # $ready_ref is fed by the master's persistent USR2 watcher.  Clear it
    # first so a stale signal - from a generation that timed out and only then
    # reported ready - cannot mark this one ready before it is.
    $$ready_ref = 0;
    my $done = 0;
    my $fail = EV::child $pid, 0, sub {
        warn "Feersum [$$]: gen $gen (pid $pid) died during startup\n";
        $done = 1;
    };
    my $to = EV::timer($timeout, 0, sub {
        warn "Feersum [$$]: gen $gen startup timeout\n";
        $done = 1;
    });
    EV::run(EV::RUN_ONCE)
        until $done || $$ready_ref || ($shutdown_ref && $$shutdown_ref);
    return $$ready_ref ? 1 : 0;
}

# Apply server settings to a Feersum instance (without consuming from $self).
# Used by hot_restart generations to re-apply settings from the master's config.
sub _apply_settings {
    my ($self, $f) = @_;
    $self->_apply_simple_settings($f, 0);  # preserve $self for re-use
    # Gate on pre_fork like _prepare: EPOLLEXCLUSIVE is only meaningful with
    # multiple accepting workers (the generation child already set it before
    # use_socket; this keeps the two settings paths consistent). Linux-only
    # like the other call sites - the XS setter warns on other platforms,
    # which would repeat on every hot_restart reload.
    $f->set_epoll_exclusive($self->{epoll_exclusive} && $self->{pre_fork} ? 1 : 0)
        if defined $self->{epoll_exclusive} && $^O eq 'linux';

    # TLS
    if (my $tls = $self->{tls}) {
        if ($f->has_tls()) {
            # 0 under hot_restart+reuseport: the generation registers no
            # listeners of its own and each worker applies TLS to the socket it
            # binds itself (via _tls_config below).
            my $n = scalar @{$self->{_master_socks} || $self->{_socks} || []};
            $self->_apply_tls_to_listeners($f, $n, $tls, $self->{sni});
            $self->{_tls_config} = $tls;  # for reuseport workers
        } else {
            # Match _prepare's loud failure: never silently serve plaintext on
            # a TLS-configured listener just because this build lacks TLS.
            warn "Feersum [$$]: tls configured but TLS not compiled in"
                . " - aborting generation\n";
            POSIX::_exit(1);
        }
    }
    return;
}

sub _fork_another { ## no critic (ProhibitExcessComplexity)
    my ($self, $slot) = @_;

    my $pid = fork;
    croak "failed to fork: $!" unless defined $pid;
    unless ($pid) {
        EV::default_loop()->loop_fork;
        $self->{quiet} or warn "Feersum [$$]: starting\n";
        delete $self->{_kids};
        delete $self->{_kid_pids};  # the parent's workers, not ours to signal
        delete $self->{pre_fork};
        # Workers are forked before the master signals readiness, so each
        # inherits the write end of the daemonize pipe.  Holding it means the
        # daemonize parent never sees EOF when the master dies during startup.
        if (my $rdy = delete $self->{_daemon_ready_fh}) { close $rdy }
        # EV timers survive fork, so a worker forked while ANOTHER slot had a
        # respawn backoff pending used to fire that timer itself: it would
        # _respawn_worker -> fork a grandchild -> unlisten, leaving itself
        # permanently non-accepting while the grandchild inherited the
        # remaining timers and repeated.  pre_fork=4 with a transient boot
        # failure produced 15 descendants in a 4-deep tree instead of 4.
        delete $self->{_respawn_timers};
        delete $self->{_kid_started};
        delete $self->{_respawn_fails};
        $self->{_n_kids} = 0;

        # With SO_REUSEPORT, each child creates its own sockets
        # This eliminates accept() contention for better scaling
        if ($self->{_use_reuseport}) {
            my @addrs = @{$self->{_listen_addrs}};
            my @old   = @{$self->{_socks} || []};
            $self->{endjinn}->unlisten();
            my @new_socks;
            eval {
                for my $i (0 .. $#addrs) {
                    my $listen = $addrs[$i];
                    # Rebinding a UNIX path unlinks the previous worker's
                    # socket, leaving only the last one forked reachable; keep
                    # the inherited fd and accept from it instead.
                    if (_is_unix_listen($listen)) {
                        push @new_socks, $old[$i];
                        $self->{endjinn}->use_socket($old[$i]);
                        next;
                    }
                    if (defined $old[$i]) {
                        close($old[$i])
                            or die "close parent socket in child: $!\n";
                    }
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
            unless (eval { $loader->(); 1 }) {
                warn "Feersum [$$]: worker app load failed: $@";
                POSIX::_exit(1);
            }
        }

        # Guarded like the loader above.  On a respawn this runs inside the
        # parent's EV::child callback, so EV swallows the exception and the
        # worker would serve on with after_fork half-applied - stale DB
        # handles, unreseeded PRNG.  Fail it and let backoff retry.
        if (my $cb = $self->{after_fork}) {
            unless (eval { $cb->(); 1 }) {
                warn "Feersum [$$]: after_fork failed: $@";
                POSIX::_exit(1);
            }
        }

        $self->_set_max_requests_per_worker($self->{endjinn});

        eval { EV::run; }; ## no critic (RequireCheckingReturnValueOfEval)
        carp $@ if $@;
        POSIX::_exit($@ ? 1 : 0);  # _exit avoids running parent's END blocks
    }

    weaken $self;  # prevent circular ref with watcher callback
    $self->{_n_kids}++;
    $self->{_kid_started}[$slot] = EV::time();  # for respawn backoff
    $self->{_kid_pids}[$slot] = $pid;           # for the force-exit backstop
    $self->{_kids}[$slot] = EV::child $pid, 0, sub {
        my $w = shift;
        return unless $self;  # guard against destruction during shutdown
        $self->{quiet} or warn "Feersum [$$]: child $pid exited ".
            "with rstatus ".$w->rstatus."\n";
        $self->{_n_kids}--;
        undef $self->{_kid_pids}[$slot];  # reaped; never signal a reused pid
        if ($self->{_shutdown}) {
            unless ($self->{_n_kids}) {
                $self->{_death} = undef;
                EV::break(EV::BREAK_ALL());
            }
            return;
        }
        # Respawn backoff: without it an instantly-dying worker is re-forked
        # thousands of times per second, silently under the default quiet=1.
        # A max_requests_per_worker retirement is not a death: it exits
        # EXIT_RETIRED, and with a small limit it does so in well under a
        # second, which would otherwise ratchet the backoff up to 30s.
        my $rstatus  = $w->rstatus;
        my $retired  = ($rstatus & WSTATUS_SIGNAL_MASK) == 0
                    && ($rstatus >> WSTATUS_EXIT_SHIFT) == EXIT_RETIRED;
        my $started  = $self->{_kid_started}[$slot];
        my $lifetime = defined $started ? EV::time() - $started : undef;
        if (!$retired && defined $lifetime && $lifetime < RESPAWN_INSTANT_DEATH) {
            my $n = ++$self->{_respawn_fails}[$slot];
            # Past the threshold keep retrying, but only at the maximum
            # interval: giving up entirely would silently strand the slot (with
            # pre_fork=1, a supervisor that looks healthy but serves nothing)
            # and lose self-healing when the cause is transient - a DB down at
            # boot, fd exhaustion, a briefly contended reuseport bind.
            my $delay = $n > RESPAWN_MAX_FAILS
                ? RESPAWN_BACKOFF_MAX
                : RESPAWN_BACKOFF_BASE * (2 ** ($n - 1));
            $delay = RESPAWN_BACKOFF_MAX if $delay > RESPAWN_BACKOFF_MAX;
            warn "Feersum [$$]: worker slot $slot has died immediately $n "
                . "times, still retrying every ${delay}s "
                . "(check the app and after_fork)\n"
                if $n == RESPAWN_MAX_FAILS + 1;
            warn sprintf "Feersum [%d]: worker slot %d died after %.2fs, "
                . "respawning in %gs (failure %d)\n", $$, $slot, $lifetime,
                $delay, $n;
            $self->{_respawn_timers}[$slot] = EV::timer($delay, 0, sub {
                return unless $self;
                return if $self->{_shutdown};
                $self->{_respawn_timers}[$slot] = undef;
                $self->_respawn_worker($slot);
            });
            return;
        }
        $self->{_respawn_fails}[$slot] = 0;
        $self->_respawn_worker($slot);
    };
    return;
}

# Re-fork the worker occupying $slot.  Without SO_REUSEPORT the parent has to
# accept on the listen sockets across the fork so the new worker inherits them.
sub _respawn_worker {
    my ($self, $slot) = @_;
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
            # unlisten() frees each listener's TLS context and clears its
            # SERVER_NAME/SERVER_PORT, so re-arming with accept_on_fd alone
            # forks a worker that serves PLAINTEXT on a TLS port (and reports
            # SERVER_NAME ""). Rebuild the listeners the way _prepare does.
            # Everything between the re-listen and the unlisten is guarded:
            # set_tls and the fork can both croak, and EV discards exceptions
            # from the callback this runs in, which would leave the supervisor
            # listening and serving requests itself with the slot stranded.
            my $forked = eval {
                for my $sock (@socks) {
                    $feersum->use_socket($sock);
                }
                if (my $tls = $self->{_tls_config}) {
                    $self->_apply_tls_to_listeners(
                        $feersum, scalar(@socks), $tls, $self->{sni});
                }
                $self->_fork_another($slot);
                1;
            };
            my $err = $@;
            $feersum->unlisten;
            $self->_retry_respawn($slot, $err) unless $forked;
        } else {
            carp "fileno returned undef during respawn, cannot respawn worker";
        }
    }
    else {
        # With SO_REUSEPORT, just spawn new child (it creates its own socket)
        my $forked = eval { $self->_fork_another($slot); 1 };
        $self->_retry_respawn($slot, $@) unless $forked;
    }
    return;
}

# A fork() that fails here runs inside an EV watcher callback, and EV catches
# and discards the exception.  Without this the slot is stranded for good: no
# worker, no pending timer, and nothing to retry when the pressure passes.
sub _retry_respawn {
    my ($self, $slot, $err) = @_;
    return if $self->{_shutdown};
    my $n = ++$self->{_respawn_fails}[$slot];
    my $delay = $n > RESPAWN_MAX_FAILS
        ? RESPAWN_BACKOFF_MAX
        : RESPAWN_BACKOFF_BASE * (2 ** ($n - 1));
    $delay = RESPAWN_BACKOFF_MAX if $delay > RESPAWN_BACKOFF_MAX;
    my $msg = defined $err ? $err : 'unknown error';
    $msg =~ s/\s+\z//;
    warn sprintf "Feersum [%d]: could not fork worker slot %d (%s), "
        . "retrying in %gs (failure %d)\n", $$, $slot, $msg, $delay, $n;
    $self->{_respawn_timers}[$slot] = EV::timer($delay, 0, sub {
        return unless $self;
        return if $self->{_shutdown};
        $self->{_respawn_timers}[$slot] = undef;
        $self->_respawn_worker($slot);
    });
    return;
}

sub _start_pre_fork {
    my $self = shift;

    # pre_fork value already validated in _prepare()
    $self->{endjinn}->set_multiprocess(1);

    # NB: setsid() returns -1 (true!) on failure, not undef - test explicitly.
    # EPERM only means we are already a session/process-group leader, which is
    # the state we wanted: it happens under --daemonize (which already called
    # setsid) and whenever a supervisor such as runit/s6/systemd starts us in
    # our own session.  Only a different errno is worth reporting.
    POSIX::setsid() == SYSCALL_ERROR and $! != POSIX::EPERM()
        and croak "setsid() failed: $!";

    $self->{_kids} = [];
    $self->{_kid_pids} = [];   # inherited entries belong to another generation
    $self->{_n_kids} = 0;
    # Reuseport workers rebind for themselves, so drop the parent's sockets
    # BEFORE forking: Linux matches reuseport members by UID, and a root-owned
    # parent socket left open cost 5 of 6 privdropped workers their first bind.
    # Without reuseport they inherit the socket, so it must stay listening.
    if ($self->{_use_reuseport}) {
        $self->{endjinn}->unlisten();
        # ...except the UNIX ones, which workers inherit rather than rebind
        # (see _is_unix_listen).  A worker forked later would otherwise read
        # undef out of _socks and die at birth.
        my $addrs = $self->{_listen_addrs} || [];
        my $socks = $self->{_socks} || [];
        my @keep;
        for my $i (0 .. $#$socks) {
            if (_is_unix_listen($addrs->[$i])) { $keep[$i] = $socks->[$i]; next }
            close($socks->[$i]) or warn "close parent socket before fork: $!";
        }
        $self->{_socks} = \@keep;
        ($self->{sock}) = grep { defined } @keep;
    }

    $self->_fork_another($_) for (1 .. $self->{pre_fork});

    # Parent stops accepting - children handle connections
    $self->{endjinn}->unlisten() unless $self->{_use_reuseport};
    return;
}

# Block until the daemonized child reports readiness, or gives up.  Returns
# false only on a DEFINITE failure (EOF before the token, i.e. the child died
# during startup); a timeout returns true so a slow-but-working start is never
# turned into a spurious error.
sub _await_daemon_ready {
    my ($self, $rdy_r) = @_;
    my $rin = '';
    vec($rin, fileno($rdy_r), 1) = 1;
    my $wait = $self->{startup_timeout} // DEFAULT_STARTUP_TIMEOUT;
    my $deadline = EV::time() + $wait;
    my $nready = 0;
    # SIGCHLD from the master dying - precisely the case this handshake exists
    # to catch - interrupts select(), and an interrupted select is
    # indistinguishable below from a timeout, which is reported as success.
    # Resume for whatever time remains instead.
    while (1) {
        my $remaining = $deadline - EV::time();
        last if $remaining <= 0;
        $nready = select(my $rout = $rin, undef, undef, $remaining);
        last if !defined $nready || $nready >= 0 || $! != POSIX::EINTR();
    }
    return 1 if !$nready || $nready < 1;
    my $n = sysread($rdy_r, my $tok, READY_TOKEN_SIZE);
    return (defined $n && $n == 0) ? 0 : 1;
}

# Tell the daemonize parent that startup got far enough to serve.  Closing the
# pipe without writing (which is what happens if the child dies first) is how
# the parent learns startup failed.  Idempotent and a no-op when not daemonized.
sub _daemon_ready {
    my $self = shift;
    my $fh = delete $self->{_daemon_ready_fh} or return;
    syswrite $fh, 'R';
    close $fh;
    return;
}

sub _daemonize_and_write_pid {
    my $self = shift;

    if ($self->{daemonize}) {
        # Verify writability BEFORE forking: otherwise the daemon is already
        # serving when the parent croaks, leaving an undiscoverable orphan.
        if (my $file = $self->{pid_file}) {
            open my $probe, '>>', $file
                or croak "Cannot write pid_file '$file': $!";
            close $probe
                or croak "Cannot write pid_file '$file': $!";
        }
        # Readiness pipe: the parent used to _exit(0) the instant it forked, so
        # anything that failed AFTER the fork - an app that does not compile
        # being the common one - was reported to the caller (and to any
        # supervisor) as a successful start, with nothing listening.
        pipe(my $rdy_r, my $rdy_w) or croak "daemonize pipe: $!";
        my $pid = fork;
        croak "daemonize fork: $!" unless defined $pid;
        if ($pid) {
            close $rdy_w;
            my $ready = $self->_await_daemon_ready($rdy_r);
            close $rdy_r;
            unless ($ready) {
                waitpid $pid, 0;
                warn "Feersum: startup failed, see the log for the reason\n"
                    unless $self->{quiet};
                POSIX::_exit(1);
            }
            if (my $file = $self->{pid_file}) {
                open my $fh, '>', $file or croak "Cannot write pid_file '$file': $!";
                print {$fh} "$pid\n";
                # a failed close truncates the pid file
                close $fh or croak "Cannot write pid_file '$file': $!";
            }
            POSIX::_exit(0);
        }
        close $rdy_r;
        $self->{_daemon_ready_fh} = $rdy_w;
        POSIX::setsid();
        open STDIN,  '<', '/dev/null' or croak "redirect stdin: $!";
        open STDOUT, '>', '/dev/null' or croak "redirect stdout: $!";
        open STDERR, '>', '/dev/null' or croak "redirect stderr: $!"
            unless $ENV{FEERSUM_DEBUG};
    } elsif (my $file = $self->{pid_file}) {
        open my $fh, '>', $file or croak "Cannot write pid_file '$file': $!";
        print {$fh} "$$\n";
        close $fh or croak "Cannot write pid_file '$file': $!";
    }
    return;
}

sub _drop_privs {
    my $self = shift;

    # Resolve the user first so its PRIMARY GROUP can act as the default when
    # no group was configured.  Previously `user` and `group` were handled by
    # two independent blocks, so `user` alone did setuid with no setgid and no
    # setgroups: the "unprivileged" daemon kept GID 0 and every one of root's
    # supplementary groups (on Debian that is shadow, docker, adm, disk...).
    my ($uid, $gid);
    if (my $user = $self->{user}) {
        (undef, undef, $uid, my $pw_gid) = getpwnam($user);
        croak "Unknown user '$user'" unless defined $uid;
        $gid = $pw_gid;
    }
    if (my $group = $self->{group}) {
        $gid = getgrnam($group);
        croak "Unknown group '$group'" unless defined $gid;
    }

    if (defined $gid) {
        # Setting $) clears supplemental groups AND sets effective GID (via
        # setgroups + setgid). Without this, supplemental groups like wheel,
        # sudo, docker, shadow inherited from root are retained after setuid.
        # $)-assignment magic discards the setgroups/setegid return values,
        # so errno is the only failure signal - clear any stale value first
        # (getgrnam may leave errno set even on success).
        $! = 0;
        $) = "$gid $gid";
        croak "setgroups/setegid($gid): $!" if $!;
        POSIX::setgid($gid) or croak "setgid($gid): $!";
        # Verify drop took effect AND supplemental groups were cleared
        # (some LSMs/seccomp policies silently no-op setgroups). A successful
        # drop reads back as "gid gid": real gid plus the one-entry setgroups
        # list ($) = "g g" sets setgroups([g]), not an empty list), so require
        # every token to equal $gid rather than expecting a single token.
        my @rg = split ' ', $(;
        croak "setgid($gid) verification failed: real GID list is @rg"
            if !@rg || any { $_ != $gid } @rg;
    }
    if (defined $uid) {
        POSIX::setuid($uid) or croak "setuid($uid): $!";
        # Verify the privilege drop actually happened.
        croak "setuid($uid) verification failed: \$<=$<, \$>=$>"
            unless $< == $uid && $> == $uid;
    }
    if (defined $uid || defined $gid) {
        $self->_verify_reuseport_bind;
        # Now, while an operator is watching: at shutdown (see
        # _remove_pid_file) the message would go to a closed stderr.
        if (my $file = $self->{pid_file}) {
            my ($dir) = $file =~ m{^(.*)/[^/]+\z};
            $dir = q{.} unless defined $dir && length $dir;
            warn "Feersum [$$]: pid_file '$file' cannot be removed at shutdown: "
               . "'$dir' is not writable after dropping privileges\n"
                unless -w $dir;
        }
    }
    return;
}

# A reuseport worker rebinds the address as the user we just dropped to.  When
# that user cannot (usually a port under 1024) every worker dies at birth and
# respawns forever while the parent, having closed its sockets, accepts
# nothing.  Probe now, while falling back to the inherited-socket path still
# works.  Probing beats testing the port number, which ignores
# CAP_NET_BIND_SERVICE, ip_unprivileged_port_start and LSM labels.
sub _verify_reuseport_bind {
    my $self = shift;
    return unless $self->{_use_reuseport};

    # We still hold the address, so EADDRINUSE is a pass: the kernel tests
    # CAP_NET_BIND_SERVICE before the address conflict, so reaching "in use"
    # proves the worker's bind succeeds once we close.  Built, not hardcoded,
    # so it matches under any locale.
    my $in_use = do { local $! = POSIX::EADDRINUSE(); qq{$!} };

    for my $listen (@{ $self->{_listen_addrs} || [] }) {
        next if _is_unix_listen($listen);   # inherited, never rebound
        my $probe = eval { $self->_create_socket($listen, 1, 1) };
        if ($probe) { close $probe; next }
        my $why = $@ || "unknown error";
        $why =~ s/\s+at\s+\S+\s+line\s+\d+\.?\s*\z//;
        next if index($why, $in_use) >= 0;
        warn "Feersum [$$]: cannot rebind '$listen' after dropping privileges "
           . "($why); disabling reuseport - workers will share the inherited "
           . "listen socket instead\n";
        $self->{_use_reuseport} = 0;
        last;
    }
    return;
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
        # in child or solo process.  Remove the pid file here: POSIX::_exit
        # skips END blocks and DESTROY, so the documented "removed on clean
        # shutdown" contract would otherwise not hold for a single-process
        # (or daemonized) runner.
        #
        # Guarded: a worker already draining a retirement croaks "already
        # shutting down" here, which used to abort quit() before the force-exit
        # timer below was armed - the worker then ignored SIGQUIT and SIGTERM.
        my $ok = eval {
            $self->{endjinn}->graceful_shutdown(sub {
                $self->_remove_pid_file;
                POSIX::_exit(0);
            });
            1;
        };
        $self->{quiet} or $ok
            or warn "Feersum [$$]: already draining, forcing exit in ${death}s\n";
    }

    # Force-exit backstop.  Take the workers with us: quit() has already asked
    # them politely, and exiting alone would reparent them to init still holding
    # the listen socket, so the restart fails with EADDRINUSE.  Drop the pid
    # file too - POSIX::_exit skips END blocks, so nothing else will.
    my $s = $self;
    weaken $s;   # the watcher is stored on $self; a strong ref here leaks it
    $self->{_death} = EV::timer $death, 0, sub {
        return unless $s;
        $s->_remove_pid_file;
        my @alive = grep { defined } @{ $s->{_kid_pids} || [] };
        kill 'KILL', @alive if @alive;
        POSIX::_exit(1);
    };
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
C<< listen => ['localhost:5000'] >>, or a plain string for a single
address. Formats: C<host:port> for IPv4, C<[host]:port> for IPv6 (e.g.,
C<['[::1]:8080']>).

IPv6 needs Perl 5.14+ with Socket IPv6 support; no other option is required.
A bare (unbracketed) IPv6 address whose tail looks like a port is rejected as
ambiguous - use the bracket form.

An entry beginning with C</> or C<.> is bound as a UNIX-domain socket instead
of TCP.  Such a socket is created world-accessible (mode C<0777>) so that a
reverse proxy running as another user can connect; if that is too permissive,
place it in a directory whose permissions restrict who can reach it, which is
the usual way to control access to a UNIX socket.

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

Not supported together with C<hot_restart>: each generation loads the app
once in its supervisor and forks workers copy-on-write, so
C<< preload_app => 0 >> is ignored in that mode.

    Feersum::Runner->new(
        pre_fork    => 4,
        preload_app => 0,
        app_file    => 'app.psgi',
        after_fork  => sub { ... },
    )->run;

=item hot_restart

Enable generation-based hot restart.  Requires C<app_file>.

The entry process becomes a supervisor that manages "generations".  Each
generation is a forked child that re-runs the app file, loading the app and
the modules it pulls in from scratch.
On C<SIGHUP>, a new generation is forked; if it starts successfully, the old
generation is gracefully shut down via C<SIGQUIT>.  Failed restarts are
rolled back (old generation continues serving).

Works with C<pre_fork>: each generation forks its own workers.  The app and
the modules it loads are picked up fresh in each generation (the app file is
re-run via C<do> in a new fork, not re-C<do>ne in a single long-lived
process).  Modules already loaded by the supervisor before C<run()> are
inherited via fork and B<not> reloaded -- restart the supervisor to refresh
those.  Workers within a generation always inherit the app copy-on-write
(C<< preload_app => 0 >> is ignored in this mode).

TLS (C<tls>, or the flat C<tls_cert_file>/C<tls_key_file>) and HTTP/2
(C<h2>) configuration is propagated to every generation, so hot restart
works with HTTPS and H2.

Note that under C<plackup> the C<.psgi> path must also be given to plackup
itself (positionally or via C<-a>) -- C<app_file> only tells Feersum what to
re-run per generation, and plackup otherwise tries to load its own default
F<app.psgi>.

    plackup -s Feersum --app-file=app.psgi --hot-restart=1 --pre-fork=4 app.psgi
    kill -HUP <master-pid>   # zero-downtime restart, reloads app code

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

=item * For v1 UNKNOWN, v2 LOCAL, or v2 UNSPEC/AF_UNIX families, the original address is preserved

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

Set read/keepalive timeout in seconds (default: 5).  Must be positive
(non-zero).

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

Set maximum concurrent connections (default: 10000; 0 disables the limit).
When the limit is reached, Feersum first closes the oldest idle keep-alive
connection to make room; if none are idle, the new connection is closed and
accepting is paused on that listener until a slot frees.  Provides protection
against Slowloris-style DoS attacks.

=item max_read_buf

Set max read buffer size per connection (default: 64 MiB, 67108864 bytes).  This limits how
large the read buffer can grow during header parsing and chunked body
reception.

=item max_body_len

Set max request body size (default: 64 MiB, 67108864 bytes).  This limits Content-Length
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

Flat alternatives to the C<tls> hash, useful with plackup's pass-through
options:

    plackup -s Feersum --tls-cert-file=server.crt --tls-key-file=server.key

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
hostname.  Requires C<tls> to be set first (provides the default cert);
croaks if it is not.

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

Each worker binds for itself, which C<user>/C<group> on a port below 1024 makes
impossible.  Feersum probes the bind while dropping privileges and falls back
to sharing the inherited listen socket, with a warning.

B<Note:> C<reuseport> is not required for IPv6; see C<listen>.

=item epoll_exclusive

Enable EPOLLEXCLUSIVE for better prefork scaling on Linux 4.5+ (default: off).
When enabled in combination with C<pre_fork>, only one worker is woken per
incoming connection, avoiding the "thundering herd" problem. Use with
C<max_accept_per_loop> to tune fairness vs throughput.

=item max_requests_per_worker

Maximum total requests a worker process will handle before gracefully
recycling (default: 0 = unlimited).  Effective with C<pre_fork> or
C<hot_restart>; the parent (or hot-restart supervisor) automatically forks a
replacement worker.  Useful for containing memory leaks in long-running
applications.

The limit is exact - it is enforced in XS alongside the request counter (see
L<Feersum/"max_requests_per_worker()">), so a worker retires on the request that
reaches it, however fast the traffic.  A retiring worker is not treated as a
crash, so it does not trigger the respawn backoff.

=item access_log

Code reference called after each response completes (native handler only).
Receives C<($method, $uri, $elapsed_seconds)>.  Requests the server rejects
before dispatch (malformed, over a limit, timed out) produce no line; see
C<access_log> in L<Feersum>.  For PSGI apps, use
L<Plack::Middleware::AccessLog> instead.

    access_log => sub {
        my ($method, $uri, $elapsed) = @_;
        warn sprintf "%s %s %.3fms\n", $method, $uri, $elapsed * 1000;
    },

=item graceful_timeout

Seconds to wait for in-flight requests to complete during graceful shutdown
before force-exiting (default: 5; 0 force-exits immediately).  Also honors the C<FEERSUM_GRACEFUL_TIMEOUT>
environment variable (option takes precedence).  In prefork mode the parent
allows an extra 2 seconds beyond this before force-exiting, so its workers
have a chance to drain and exit first.

Force-exiting cuts off whatever is still in flight, mid-body.  A response that
needs longer than this to finish is truncated: the client has already been told
a C<Content-Length> it will never receive, and sees a short read at a clean EOF
(detectable, but a failed download).  Raise it if you serve large bodies with
C<sendfile> or long streaming responses, or a restart will truncate every
transfer still running after the deadline.  Feersum itself imposes no deadline
on the drain; this timeout is the only thing bounding it, so it is also what
stops a stuck connection from blocking shutdown forever.

=item startup_timeout

Seconds to wait for a hot_restart generation to signal readiness before
declaring it failed and rolling back (default: 10; 0 fails the restart
immediately).  Also caps how long a C<daemonize> parent waits for the daemon
to report that it got far enough to serve; there a timeout is treated as
success, so that a slow-but-working start is never reported as a failure.

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

Supplementary groups are always cleared.  If C<group> is omitted, the group is
taken from C<user>'s passwd entry, so C<< user => 'www-data' >> drops to that
user's primary group rather than leaving the process in root's groups.  The
drop is verified and croaks if it did not take effect, so a configuration that
cannot clear its groups fails loudly instead of running with them.

B<Note:> TLS certificate and key files are opened by the worker, which is
already running as C<user>.  A key readable only by root (the usual
C<< /etc/ssl/private >> layout) therefore has to be made readable by C<user>.

=item max_h2_concurrent_streams

Maximum concurrent HTTP/2 streams per connection (default: 100).
Requires H2 support compiled in.

=item quiet

Don't be so noisy. (default: on)

=item app

An already-compiled native Feersum app code reference, as an alternative to
passing it to C<run()>.  Mutually exclusive with a per-worker load: when C<app>
is set, C<app_file> is not re-read in the workers.

=item app_file

Load this filename as a native feersum app.  Required for C<hot_restart>, which
re-reads the file in each new generation.  With C<preload_app> off and no
C<app>, each worker loads it independently after the fork.

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
it under the same terms as Perl itself, either Perl version 5.14 or,
at your option, any later version of Perl 5 you may have available.

=cut
