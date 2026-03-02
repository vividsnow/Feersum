#!perl
use warnings;
use strict;
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || 1;
use Test::More;
use utf8;
use lib 't'; use Utils;
use File::Spec::Functions 'rel2abs';

BEGIN { use_ok 'Feersum' }
BEGIN { use_ok 'Feersum::Runner' }

my $evh = Feersum->new();

# Detect if EPOLLEXCLUSIVE is available at runtime
my $has_epoll_exclusive;
if ($^O eq 'linux') {
    local $SIG{__WARN__} = sub {};  # suppress warning on old kernels
    $evh->set_epoll_exclusive(1);
    $has_epoll_exclusive = $evh->get_epoll_exclusive();
    $evh->set_epoll_exclusive(0);
}

# Test API
SKIP: {
    skip "EPOLLEXCLUSIVE not available (requires Linux 4.5+)", 4
        unless $has_epoll_exclusive;

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

# Test that unsupported platform warns
SKIP: {
    skip "This test is for systems without EPOLLEXCLUSIVE", 1
        if $has_epoll_exclusive;

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    $evh->set_epoll_exclusive(1);
    like($warnings[0], qr/EPOLLEXCLUSIVE.*Linux/i,
        'setting epoll_exclusive without support warns');
}

# Test that server works with EPOLLEXCLUSIVE in prefork mode
SKIP: {
    skip "EPOLLEXCLUSIVE not available (requires Linux 4.5+)", 6
        unless $has_epoll_exclusive;

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
    select undef, undef, undef, 0.25 * TIMEOUT_MULT;

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
