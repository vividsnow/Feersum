#!perl
use warnings;
use strict;
# TIMEOUT_MULT allows scaling all timing values for slow machines (default: 1)
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 2 : 1);
use Test::More;
use lib 't'; use Utils;
use File::Spec::Functions 'rel2abs';

BEGIN {
    plan skip_all => "Linux only" unless $^O eq 'linux';
}

use_ok 'Feersum::Runner';

my (undef, $port) = get_listen_socket();

# Count sockets held by the server process tree, NOT machine-wide.
# /proc/net/sockstat is system-wide, so any unrelated process on the box moved
# this number: it false-failed on a busy machine with zero leak, and returned 0
# for both samples (silently passing) wherever /proc is masked.
sub count_proc_sockets {
    my ($root) = @_;
    my @pids = ($root);
    # include children (the pre_fork workers)
    if (opendir my $dh, '/proc') {
        for my $p (grep { /^\d+$/ } readdir $dh) {
            if (open my $sf, '<', "/proc/$p/stat") {
                my $line = <$sf>;
                close $sf;
                push @pids, $p if $line && $line =~ /\)\s+\S+\s+(\d+)/ && $1 == $root;
            }
        }
        closedir $dh;
    }
    my $n = 0;
    for my $p (@pids) {
        opendir my $fd, "/proc/$p/fd" or next;
        for my $f (grep { /^\d+$/ } readdir $fd) {
            my $l = readlink("/proc/$p/fd/$f");
            $n++ if defined $l && $l =~ /^socket:/;
        }
        closedir $fd;
    }
    return $n;
}

my $NUM_WORKERS = $ENV{LEAK_TEST_WORKERS} || 16;
my $NUM_REQUESTS = $ENV{LEAK_TEST_REQUESTS} || 100;
my $NUM_ROUNDS = $ENV{LEAK_TEST_ROUNDS} || 3;

plan skip_all => 'needs /proc to count per-process sockets'
    unless -r '/proc/self/fd';
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

select undef, undef, undef, 3 * TIMEOUT_MULT; # wait for workers to start

# Baseline AFTER the workers are up: this is the steady-state socket count of
# the server tree, which is what a leak would grow beyond.
my $sock_before = count_proc_sockets($pid);
note "server-tree sockets after fork: $sock_before";

# Without this the whole file was vacuous: if run() croaked in the child, both
# socket samples read 0, $leaked came out 0 and the leak check passed while not
# a single request had been served.
my $ok_responses = 0;
cmp_ok $sock_before, '>', 0, "the forked server has listening sockets";

for my $round (1..$NUM_ROUNDS) {
    my $cv = AE::cv;
    for my $i (1..$NUM_REQUESTS) {
        $cv->begin;
        my $cli; $cli = simple_client GET => "/?n=$i&r=$round",
            name => "r${round}req$i",
            timeout => 3 * TIMEOUT_MULT,
            sub {
                my ($body, $headers) = @_;
                $ok_responses++ if ($headers->{Status} || 0) == 200;
                $cv->end;
                undef $cli;
            };
    }
    $cv->recv;

    select undef, undef, undef, 1.3 * TIMEOUT_MULT;  # settle between rounds
    my $sock_now = count_proc_sockets($pid);
    note "Round $round: server-tree sockets = $sock_now (diff: "
        . ($sock_now - $sock_before) . ")";
}

select undef, undef, undef, 6 * TIMEOUT_MULT; # let everything settle

my $sock_final = count_proc_sockets($pid);
my $leaked = $sock_final - $sock_before;
note "final server-tree sockets: $sock_final (leaked: $leaked)";

# Counting only the server tree means unrelated load on the machine cannot move
# this number, so the slack can be tight: a real per-request leak would be
# NUM_REQUESTS*NUM_ROUNDS sockets, not a handful.
is $ok_responses, $NUM_REQUESTS * $NUM_ROUNDS,
   "every request got a 200 (the leak count means nothing otherwise)";

ok($leaked <= 4,
   "no socket leak in the server tree (leaked=$leaked over "
   . ($NUM_REQUESTS * $NUM_ROUNDS) . " requests)");

kill 3, $pid; # QUIT
waitpid $pid, 0;

done_testing;
