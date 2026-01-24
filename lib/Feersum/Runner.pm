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
use constant MAX_PRE_FORK => 1000; # warn if pre_fork exceeds this

our $INSTANCE;
sub new { ## no critic (RequireArgUnpacking)
    my $c = shift;
    croak "Only one Feersum::Runner instance can be active at a time"
        if $INSTANCE && $INSTANCE->{running};
    # Clean up old instance state before creating new one
    if ($INSTANCE) {
        $INSTANCE->DESTROY();
        undef $INSTANCE;
    }
    $INSTANCE = bless {quiet=>1, @_, running=>0}, $c;
    return $INSTANCE;
}

sub DESTROY {
    local $@;
    my $self = shift;
    return if $self->{_destroyed};  # Guard against double-DESTROY
    $self->{_destroyed} = 1;
    if (my $f = $self->{endjinn}) {
        $f->request_handler(sub{});
        $f->unlisten();
    }
    $self->{_quit} = undef;
    $self->{running} = 0;
    return;
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
        croak "couldn't bind to socket: $!" unless $sock;
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
                # Bare IPv6 (multiple colons): could be ::1 or 2001:db8::1
                # Reject ambiguous cases - require bracket notation for IPv6 with ports
                # e.g., ::1:8080 is ambiguous (address ::1 port 8080? or address ::1:8080?)
                if ($listen =~ /:(\d{1,5})$/ && $1 <= 65535) {
                    # Looks like it ends with a port number - ambiguous!
                    croak "ambiguous IPv6 address '$listen': use bracket notation [host]:port " .
                          "(e.g., [::1]:$1 or [2001:db8::1]:$1)";
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
    croak "Feersum doesn't support multiple 'listen' directives yet"
        if @{$self->{listen}} > 1;
    my $listen = shift @{$self->{listen}};
    $self->{_listen_addr} = $listen;  # Store for children when using reuseport

    if (my $opts = $self->{options}) {
        $self->{$_} = delete $opts->{$_} for grep defined($opts->{$_}),
            qw/pre_fork keepalive read_timeout header_timeout max_connection_reqs reuseport epoll_exclusive
               read_priority write_priority accept_priority max_accept_per_loop max_connections/;
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

    my $sock = $self->_create_socket($listen, $use_reuseport);
    $self->{sock} = $sock;

    my $f = Feersum->endjinn;

    # EPOLLEXCLUSIVE must be set BEFORE use_socket() so the separate accept epoll
    # is created with EPOLLEXCLUSIVE flag (Linux 4.5+)
    if ($self->{epoll_exclusive} && $self->{pre_fork} && $^O eq 'linux') {
        $f->set_epoll_exclusive(1);
    }

    $f->use_socket($sock);

    $f->set_keepalive($_) for grep defined, delete $self->{keepalive};
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
    $self->DESTROY();
    return;
}

sub _fork_another {
    my ($self, $slot) = @_;
    weaken $self;

    my $pid = fork;
    croak "failed to fork: $!" unless defined $pid;
    unless ($pid) {
        EV::default_loop()->loop_fork;
        $self->{quiet} or warn "Feersum [$$]: starting\n";
        delete $self->{_kids};
        delete $self->{pre_fork};

        # With SO_REUSEPORT, each child creates its own socket
        # This eliminates accept() contention for better scaling
        if ($self->{_use_reuseport}) {
            $self->{endjinn}->unlisten();
            if ($self->{sock}) {
                close($self->{sock})
                    or croak "close parent socket in child: $! (fd leak risk)";
            }
            my $sock = $self->_create_socket($self->{_listen_addr}, 1);
            $self->{sock} = $sock;
            $self->{endjinn}->use_socket($sock);
        }

        eval { EV::run; }; ## no critic (RequireCheckingReturnValueOfEval)
        carp $@ if $@;
        POSIX::exit($@ ? -1 : 0); ## no critic (ProhibitMagicNumbers)
    }

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
            my $fd = fileno $self->{sock};
            if (defined $fd) {
                $feersum->accept_on_fd($fd);
                $self->_fork_another($slot);
                $feersum->unlisten;
            } else {
                # Socket invalid but still respawn to maintain pool size
                carp "fileno returned undef during respawn, respawning anyway";
                $self->_fork_another($slot);
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

    # With SO_REUSEPORT, parent can close its socket entirely
    # Children have their own sockets
    if ($self->{_use_reuseport} && $self->{sock}) {
        if (close($self->{sock})) {
            $self->{sock} = undef;
        } else {
            carp "close socket: $!";
            # Keep reference so destructor can retry cleanup
        }
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
        $self->{endjinn}->graceful_shutdown(sub { POSIX::exit(0) });
    }

    $self->{_death} = EV::timer $death, 0, sub { POSIX::exit(1) };
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

Returns a Feersum::Runner singleton.  Params are only applied for the first
invocation.

=over 8

=item listen

Listen address as an arrayref containing a single address string, e.g.,
C<< listen => ['localhost:5000'] >>. Formats: C<host:port> for IPv4,
C<[host]:port> for IPv6 (e.g., C<['[::1]:8080']>). IPv6 requires C<reuseport>
mode and Perl 5.14+. Alternatively, use C<host> and C<port> parameters.

=item pre_fork

Fork this many worker processes.

The fork is run immediately at startup and after the app is loaded (i.e. in
the C<run()> method).

=item keepalive

Enable/disable http keepalive requests.

=item read_timeout

Set read/keepalive timeout in seconds.

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

=item reuseport

Enable SO_REUSEPORT for better prefork scaling (default: off). When enabled in
combination with C<pre_fork>, each worker process creates its own socket bound
to the same address. The kernel then distributes incoming connections across
workers, eliminating accept() contention and improving multi-core scaling.
Requires Linux 3.9+ or similar kernel support. Also enables IPv6 support.

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
