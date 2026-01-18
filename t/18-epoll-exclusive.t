#!perl
use warnings;
use strict;
use Test::More;
use utf8;
use lib 't'; use Utils;
use File::Spec::Functions 'rel2abs';

BEGIN { use_ok 'Feersum' }
BEGIN { use_ok 'Feersum::Runner' }

my $evh = Feersum->new();

# Test API
SKIP: {
    skip "EPOLLEXCLUSIVE only supported on Linux", 4 unless $^O eq 'linux';

    # Test getter/setter API
    is($evh->get_epoll_exclusive(), 0, 'epoll_exclusive is off by default');
    $evh->set_epoll_exclusive(1);
    is($evh->get_epoll_exclusive(), 1, 'epoll_exclusive can be enabled');
    $evh->set_epoll_exclusive(0);
    is($evh->get_epoll_exclusive(), 0, 'epoll_exclusive can be disabled');

    # Test with true value
    $evh->set_epoll_exclusive("yes");
    is($evh->get_epoll_exclusive(), 1, 'epoll_exclusive accepts truthy value');
    $evh->set_epoll_exclusive(0);
}

# Test that non-Linux warns
SKIP: {
    skip "This test is for non-Linux systems", 1 if $^O eq 'linux';

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    $evh->set_epoll_exclusive(1);
    like($warnings[0], qr/EPOLLEXCLUSIVE.*Linux/i, 'setting epoll_exclusive on non-Linux warns');
}

# Test that server works with EPOLLEXCLUSIVE in prefork mode
SKIP: {
    skip "EPOLLEXCLUSIVE prefork test only on Linux", 6 unless $^O eq 'linux';

    my (undef, $port) = get_listen_socket();
    my $app_path = rel2abs('eg/app.feersum');

    my $pid = fork;
    die "can't fork: $!" unless defined $pid;

    if (!$pid) {
        require POSIX;
        eval {
            my $runner = Feersum::Runner->new(
                listen => ["localhost:$port"],
                server_starter => 1,
                app_file => $app_path,
                pre_fork => 2,
                quiet => 1,
                epoll_exclusive => 1,
            );
            $runner->run();
        };
        POSIX::exit(0);
    }

    # Give server time to start
    select undef, undef, undef, 0.25;

    # Test multiple requests
    my $cv = AE::cv;
    my @results;

    for my $n (1..4) {
        $cv->begin;
        my $cli; $cli = simple_client GET => "/?q=$n",
            name => "client $n",
            sub {
                my ($body, $headers) = @_;
                push @results, { n => $n, status => $headers->{Status}, body => $body };
                $cv->end;
                undef $cli;
            };
    }

    $cv->recv;

    is(scalar(@results), 4, 'all 4 requests completed');

    for my $r (@results) {
        is($r->{status}, 200, "client $r->{n}: got 200") or diag("body: $r->{body}");
    }

    # Cleanup
    kill 3, $pid;  # QUIT
    waitpid $pid, 0;
    pass "server shut down cleanly with EPOLLEXCLUSIVE";
}


done_testing();
