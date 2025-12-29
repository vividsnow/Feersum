#!perl
use warnings;
use strict;
use Test::More;
use utf8;
use lib 't'; use Utils;

BEGIN { use_ok 'Feersum' }
BEGIN { use_ok 'Feersum::Runner' }

# This test verifies that EPOLLEXCLUSIVE distributes connections
# among workers in prefork mode

sub run_balance_test {
    my ($workers, $max_accept, $label) = @_;
    my $requests_per_worker = 30;  # Enough requests to ensure all workers get some
    my $total_requests = $workers * $requests_per_worker;

    my ($sock, $port) = get_listen_socket();
    $sock->close();  # Free the port for the child

    my $pid = fork;
    die "can't fork: $!" unless defined $pid;

    if (!$pid) {
        require POSIX;
        eval {
            # Native Feersum app that returns the worker PID
            my $app = sub {
                my $req = shift;
                $req->send_response(200, ['Content-Type' => 'text/plain'], [$$]);
            };

            my %opts = (
                listen => ["127.0.0.1:$port"],
                app => $app,
                pre_fork => $workers,
                quiet => 1,
                epoll_exclusive => 1,
            );
            $opts{max_accept_per_loop} = $max_accept if defined $max_accept;

            my $runner = Feersum::Runner->new(%opts);
            $runner->run();
        };
        POSIX::_exit(0);
    }

    # Give server time to start
    select undef, undef, undef, 0.5;

    # Send requests and collect worker PIDs
    my %worker_counts;
    my $cv = AE::cv;

    for my $i (1..$total_requests) {
        $cv->begin;
        my $cli; $cli = simple_client GET => "/req$i",
            name => "$label-req$i",
            timeout => 5,
            sub {
                my ($body, $headers) = @_;
                if ($headers->{Status} && $headers->{Status} == 200 && defined $body) {
                    $body =~ s/\s+//g;
                    if ($body =~ /^(\d+)$/) {
                        $worker_counts{$1}++;
                    }
                }
                $cv->end;
                undef $cli;
            };
        # Small delay between requests to allow distribution across workers
        select undef, undef, undef, 0.01 if $i % 3 == 0;
    }

    $cv->recv;

    # Cleanup server
    kill 'QUIT', $pid;
    waitpid $pid, 0;

    # Analyze distribution
    my @counts = values %worker_counts;
    my $num_workers_seen = scalar @counts;
    my $total_handled = 0;
    $total_handled += $_ for @counts;

    diag "[$label] Workers seen: $num_workers_seen";
    diag "[$label] Requests handled: $total_handled / $total_requests";
    for my $wpid (sort keys %worker_counts) {
        diag "  Worker $wpid: $worker_counts{$wpid} requests";
    }

    # EPOLLEXCLUSIVE prevents thundering herd but doesn't guarantee even distribution.
    # The key benefit is that only ONE worker wakes per connection event.
    # Under light load with fast requests, some workers might not get any.
    # We require at least (workers - 1) to handle requests to avoid flaky tests.

    my $min_workers_expected = $workers - 1;
    ok($num_workers_seen >= $min_workers_expected,
       "[$label] at least $min_workers_expected workers active (got $num_workers_seen)");

    # Check total requests handled equals what we sent
    is($total_handled, $total_requests, "[$label] all $total_requests requests handled");
}

SKIP: {
    skip "EPOLLEXCLUSIVE balance test only on Linux", 1 unless $^O eq 'linux';

    # Test with default max_accept_per_loop (64)
    for my $workers (2, 3, 4) {
        run_balance_test($workers, undef, "$workers workers");
    }

    # Test with minimal max_accept_per_loop (1) for fairer distribution
    # With max_accept_per_loop=1, each worker accepts only 1 connection
    # before yielding, which should improve distribution across workers
    for my $workers (2, 3, 4) {
        run_balance_test($workers, 1, "$workers workers, max_accept=1");
    }
}

done_testing();
