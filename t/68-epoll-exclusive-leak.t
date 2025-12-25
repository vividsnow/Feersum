#!perl
use warnings;
use strict;
use Test::More;
use lib 't'; use Utils;
use File::Spec::Functions 'rel2abs';

BEGIN {
    plan skip_all => "Linux only" unless $^O eq 'linux';
}

use_ok 'Feersum::Runner';

my (undef, $port) = get_listen_socket();

sub get_tcp_alloc {
    open my $fh, '<', '/proc/net/sockstat' or return 0;
    while (<$fh>) {
        if (/^TCP:.*alloc\s+(\d+)/) {
            return $1;
        }
    }
    return 0;
}

my $NUM_WORKERS = $ENV{LEAK_TEST_WORKERS} || 16;
my $NUM_REQUESTS = $ENV{LEAK_TEST_REQUESTS} || 100;
my $NUM_ROUNDS = $ENV{LEAK_TEST_ROUNDS} || 3;

my $tcp_before = get_tcp_alloc();
note "TCP alloc before: $tcp_before";
note "Testing with $NUM_WORKERS workers, $NUM_REQUESTS requests x $NUM_ROUNDS rounds";

my $app_path = rel2abs('eg/app.feersum');
my $pid = fork;
die "can't fork: $!" unless defined $pid;

if (!$pid) {
    require POSIX;
    eval {
        my $runner = Feersum::Runner->new(
            listen => ["localhost:$port"],
            app_file => $app_path,
            pre_fork => $NUM_WORKERS,
            quiet => 1,
            epoll_exclusive => 1,
        );
        $runner->run();
    };
    POSIX::exit(0);
}

select undef, undef, undef, 1; # wait for workers to start

my $tcp_after_fork = get_tcp_alloc();
note "TCP alloc after fork: $tcp_after_fork (diff: " . ($tcp_after_fork - $tcp_before) . ")";

for my $round (1..$NUM_ROUNDS) {
    my $cv = AE::cv;
    for my $i (1..$NUM_REQUESTS) {
        $cv->begin;
        my $cli; $cli = simple_client GET => "/?n=$i&r=$round",
            name => "r${round}req$i",
            timeout => 5,
            sub {
                $cv->end;
                undef $cli;
            };
    }
    $cv->recv;

    select undef, undef, undef, 0.5;
    my $tcp_now = get_tcp_alloc();
    note "Round $round: TCP alloc = $tcp_now (diff from start: " . ($tcp_now - $tcp_before) . ")";
}

select undef, undef, undef, 2; # let everything settle

my $tcp_final = get_tcp_alloc();
my $leaked = $tcp_final - $tcp_before;
note "Final TCP alloc: $tcp_final (total diff: $leaked)";

# Allow some slack for timing/system activity, but leak should not grow with rounds
ok($leaked < $NUM_WORKERS + 10, "No significant socket leak (leaked=$leaked, workers=$NUM_WORKERS)");

kill 3, $pid; # QUIT
waitpid $pid, 0;

done_testing;
