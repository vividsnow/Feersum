package Feersum::Runner;
use warnings;
use strict;

use EV;
use Feersum;
use Socket qw/SOMAXCONN SOL_SOCKET SO_REUSEADDR/;
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

our $INSTANCE;
sub new { ## no critic (RequireArgUnpacking)
    my $c = shift;
    croak "Only one Feersum::Runner instance can be active at a time"
        if $INSTANCE && $INSTANCE->{running};
    $INSTANCE = bless {quiet=>1, @_, running=>0}, $c;
    return $INSTANCE;
}

sub DESTROY {
    local $@;
    my $self = shift;
    if (my $f = $self->{endjinn}) {
        $f->request_handler(sub{});
        $f->unlisten();
    }
    $self->{_quit} = undef;
    return;
}

sub _create_socket {
    my ($self, $listen, $use_reuseport) = @_;

    my $sock;
    if ($listen =~ m#^[/\.]+\w#) {
        require IO::Socket::UNIX;
        unlink $listen if -S $listen;
        my $saved = umask(0);
        $sock = IO::Socket::UNIX->new(
           Local => rel2abs($listen),
           Listen => SOMAXCONN,
        );
        umask($saved);
        croak "couldn't bind to socket: $!" unless $sock;
        $sock->blocking(0) || croak "couldn't unblock socket: $!";
    }
    else {
        require IO::Socket::INET;
        # SO_REUSEPORT must be set BEFORE bind for multiple sockets per port
        if ($use_reuseport && defined SO_REUSEPORT) {
            $sock = IO::Socket::INET->new(Proto => 'tcp');
            croak "couldn't create socket: $!" unless $sock;
            setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, pack("i", 1))
                or croak "setsockopt SO_REUSEADDR failed: $!";
            setsockopt($sock, SOL_SOCKET, SO_REUSEPORT, pack("i", 1))
                or croak "setsockopt SO_REUSEPORT failed: $!";
            my ($host, $port) = split /:/, $listen, 2;
            $host ||= '0.0.0.0';
            $port ||= 0;
            $sock->bind(Socket::pack_sockaddr_in($port, Socket::inet_aton($host)))
                or croak "couldn't bind to socket: $!";
            $sock->listen(SOMAXCONN) or croak "couldn't listen: $!";
            $sock->blocking(0) || croak "couldn't unblock socket: $!";
        }
        else {
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

    $self->{listen} ||=
        [ ($self->{host}||DEFAULT_HOST).':'.($self->{port}||DEFAULT_PORT) ];
    croak "Feersum doesn't support multiple 'listen' directives yet"
        if @{$self->{listen}} > 1;
    my $listen = shift @{$self->{listen}};
    $self->{_listen_addr} = $listen;  # Store for children when using reuseport

    if (my $opts = $self->{options}) {
        $self->{$_} = delete $opts->{$_} for grep defined($opts->{$_}),
            qw/pre_fork keepalive read_timeout max_connection_reqs reuseport epoll_exclusive
               read_priority write_priority accept_priority/;
    }

    # Enable reuseport automatically in prefork mode if SO_REUSEPORT available
    my $use_reuseport = $self->{reuseport} && $self->{pre_fork} && defined SO_REUSEPORT;
    $self->{_use_reuseport} = $use_reuseport;

    my $sock = $self->_create_socket($listen, $use_reuseport);
    $self->{sock} = $sock;

    my $f = Feersum->endjinn;
    $f->use_socket($sock);

    # EPOLLEXCLUSIVE must be set before accept watcher starts (Linux 4.5+)
    # Solves thundering herd in prefork mode without SO_REUSEPORT
    if ($self->{epoll_exclusive} && $self->{pre_fork} && $^O eq 'linux') {
        $f->set_epoll_exclusive(1);
    }

    $f->set_keepalive($_) for grep defined, delete $self->{keepalive};
    $f->read_timeout($_) for grep $_, delete $self->{read_timeout};
    $f->max_connection_reqs($_) for grep $_, delete $self->{max_connection_reqs};
    $f->read_priority($_) for grep defined, delete $self->{read_priority};
    $f->write_priority($_) for grep defined, delete $self->{write_priority};
    $f->accept_priority($_) for grep defined, delete $self->{accept_priority};

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
    die "app not defined or failed to compile" unless $app;

    $self->assign_request_handler($app);
    undef $app;

    $self->{_quit} = EV::signal 'QUIT', sub { $self->quit };

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

        # Re-enable EPOLLEXCLUSIVE after fork (per-loop setting resets after fork)
        if ($self->{epoll_exclusive} && $^O eq 'linux') {
            $self->{endjinn}->set_epoll_exclusive(1);
        }

        # With SO_REUSEPORT, each child creates its own socket
        # This eliminates accept() contention for better scaling
        if ($self->{_use_reuseport}) {
            $self->{endjinn}->unlisten();
            close($self->{sock}) if $self->{sock};
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
            $feersum->accept_on_fd(fileno $self->{sock});
            $self->_fork_another($slot);
            $feersum->unlisten;
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

    POSIX::setsid();

    $self->{_kids} = [];
    $self->{_n_kids} = 0;
    $self->_fork_another($_) for (1 .. $self->{pre_fork});

    # Parent stops accepting - children handle connections
    $self->{endjinn}->unlisten();

    # With SO_REUSEPORT, parent can close its socket entirely
    # Children have their own sockets
    if ($self->{_use_reuseport}) {
        close($self->{sock}) if $self->{sock};
        $self->{sock} = undef;
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
        # in parent, broadcast SIGQUIT to the group (not self)
        kill 3, -$$; ## no critic (ProhibitMagicNumbers)
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

Listen on this TCP socket (C<host:port> format).

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

=item reuseport

Enable SO_REUSEPORT for better prefork scaling (default: off). When enabled in
combination with C<pre_fork>, each worker process creates its own socket bound
to the same address. The kernel then distributes incoming connections across
workers, eliminating accept() contention and improving multi-core scaling.
Requires Linux 3.9+ or similar kernel support.

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
