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
    return;
}

sub DESTROY {
    local $@;
    $_[0]->_cleanup();
}

sub _create_socket {
    my ($self, $listen, $use_reuseport) = @_;

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
               Listen => SOMAXCONN,
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
            listen($sock, SOMAXCONN)
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
                Listen => SOMAXCONN,
                Blocking => 0,
            );
            croak "couldn't bind to socket: $!" unless $sock;
        }
    }
    return $sock;
}

sub _prepare {
    my $self = shift;

    # Normalize listen to arrayref (accept scalar for convenience)
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

    if (my $opts = $self->{options}) {
        $self->{$_} = delete $opts->{$_} for grep defined($opts->{$_}),
            qw/pre_fork keepalive read_timeout header_timeout max_connection_reqs reuseport epoll_exclusive
               read_priority write_priority accept_priority max_accept_per_loop max_connections
               reverse_proxy proxy_protocol h2 tls tls_cert_file tls_key_file/;
        # Warn about unknown options (likely typos)
        for my $unknown (keys %$opts) {
            carp "Unknown option '$unknown' ignored";
        }
    }

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

    # Create sockets and attach to server for each listen address
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
    $f->read_timeout($_) for grep defined, delete $self->{read_timeout};
    $f->header_timeout($_) for grep defined, delete $self->{header_timeout};
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

    # Build tls hash from flat options (for Plack -o tls_cert_file=... -o tls_key_file=...)
    if (!$self->{tls}) {
        if (my $cert = delete $self->{tls_cert_file}) {
            my $key = delete $self->{tls_key_file}
                or croak "tls_cert_file requires tls_key_file";
            $self->{tls} = { cert_file => $cert, key_file => $key };
        } elsif (my $key = delete $self->{tls_key_file}) {
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

        # H2 is off by default; only enable if h2 => 1 was passed
        if (delete $self->{h2}) {
            $tls->{h2} = 1;
        }

        if ($f->has_tls()) {
            for my $i (0 .. $#socks) {
                $f->set_tls(listener => $i, %$tls);
            }
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
    return $_[0]->{endjinn}->request_handler($_[1]);
}

sub run {
    my $self = shift;
    weaken $self;

    $self->{running} = 1;
    $self->{quiet} or warn "Feersum [$$]: starting...\n";
    $self->_prepare();

    my $app = shift || delete $self->{app};

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
    EV::run;
    $self->{quiet} or warn "Feersum [$$]: done\n";
    $self->_cleanup();
    return;
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

        # With SO_REUSEPORT, each child creates its own sockets
        # This eliminates accept() contention for better scaling
        if ($self->{_use_reuseport}) {
            $self->{endjinn}->unlisten();
            for my $old_sock (@{$self->{_socks} || []}) {
                close($old_sock)
                    or do { warn "close parent socket in child: $!"; POSIX::_exit(1); };
            }
            my @new_socks;
            for my $listen (@{$self->{_listen_addrs}}) {
                my $sock = $self->_create_socket($listen, 1);
                push @new_socks, $sock;
                $self->{endjinn}->use_socket($sock);
            }
            $self->{sock} = $new_socks[0];
            $self->{_socks} = \@new_socks;
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
            EV::break(EV::BREAK_ALL()) unless $self->{_n_kids};
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

sub quit {
    my $self = shift;
    return if $self->{_shutdown};

    $self->{_shutdown} = 1;
    $self->{quiet} or warn "Feersum [$$]: shutting down...\n";
    my $death = DEATH_TIMER;

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

Much like L<Plack::Runner>, but with far fewer options.

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

B<Important:> IPv6 addresses require both C<reuseport> mode to be enabled
AND Perl 5.14+ with Socket IPv6 support. Without C<reuseport>, only IPv4
addresses are supported.

Alternatively, use C<host> and C<port> parameters.

=item pre_fork

Fork this many worker processes.

The fork is run immediately at startup and after the app is loaded (i.e. in
the C<run()> method).

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

=item read_timeout

Set read/keepalive timeout in seconds.

=item header_timeout

Set maximum time (in seconds) to receive complete HTTP headers (Slowloris
protection). Default is 0 (disabled). When enabled, connections that don't
complete headers within the timeout are closed.

=item max_connection_reqs

Set max requests per connection in case of keepalive - 0(default) for unlimited.

=item max_accept_per_loop

Set max connections to accept per event loop cycle (default: 64). Lower values
give more fair distribution across workers when using C<epoll_exclusive>.
Higher values improve throughput under heavy load by reducing syscall overhead.

=item max_connections

Set maximum concurrent connections (default: 0, unlimited). When the limit is
reached, new connections are immediately closed. Provides protection against
Slowloris-style DoS attacks.

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

=item reuseport

Enable SO_REUSEPORT for better prefork scaling (default: off). When enabled in
combination with C<pre_fork>, each worker process creates its own socket bound
to the same address. The kernel then distributes incoming connections across
workers, eliminating accept() contention and improving multi-core scaling.
Requires Linux 3.9+ or similar kernel support.

B<Note:> IPv6 support requires C<reuseport> to be enabled. Without reuseport,
only IPv4 addresses are supported.

=item epoll_exclusive

Enable EPOLLEXCLUSIVE for better prefork scaling on Linux 4.5+ (default: off).
When enabled in combination with C<pre_fork>, only one worker is woken per
incoming connection, avoiding the "thundering herd" problem. Use with
C<max_accept_per_loop> to tune fairness vs throughput.

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
