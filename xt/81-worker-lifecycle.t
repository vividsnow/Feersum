#!perl
# Worker lifecycle edge cases:
# 1. max_requests_per_worker with keepalive
# 2. preload_app=0 + app load failure → respawn
# 3. graceful_timeout=0 (immediate exit)
# 4. FEERSUM_GRACEFUL_TIMEOUT env var
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More tests => 18;  # 10 explicit + 8 simple_client implicit
use utf8;
use lib 't'; use Utils;
use File::Temp qw(tempfile tempdir);
use POSIX ();

my $parent_pid = $$;
END { $? = 0 if $$ != $parent_pid }

sub http_get {
    my ($port, $timeout) = @_;
    $timeout //= 3 * TIMEOUT_MULT;
    my $body;
    my $cv = AE::cv;
    my $cli; $cli = simple_client GET => '/', port => $port,
        timeout => $timeout, sub {
            my ($b, $h) = @_;
            $body = $b if $h->{Status} && $h->{Status} == 200;
            $cv->send; undef $cli;
        };
    $cv->recv;
    return $body;
}

sub extract_pid { ($_[0] // '') =~ /^pid=(\d+)/ ? $1 : undef }

my $dir = tempdir(CLEANUP => 1);

###############################################################################
# Test 1: max_requests_per_worker with keepalive connections
###############################################################################

my $app1 = "$dir/mrkeepalive.feersum";
open my $fh1, '>', $app1 or die;
print $fh1 'sub { $_[0]->send_response(200,["Content-Type"=>"text/plain"],\"pid=$$\n") }';
close $fh1;

my (undef, $port1) = get_listen_socket();
my $m1 = fork // die "fork: $!";
if (!$m1) {
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen => ["localhost:$port1"], app_file => $app1,
            pre_fork => 1, max_requests_per_worker => 3,
            quiet => 1,
        )->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 1.0 * TIMEOUT_MULT;

# Send 3 requests (hitting max), then wait for recycle
my $first_pid;
for (1..3) {
    my $b = http_get($port1);
    $first_pid //= extract_pid($b);
}
ok $first_pid, "got initial worker pid ($first_pid)";

# Wait for recycle (1s timer + graceful shutdown time)
select undef, undef, undef, 3.0 * TIMEOUT_MULT;

my $new_pid = extract_pid(http_get($port1));
ok $new_pid, "server responds after recycle";
isnt $new_pid, $first_pid, "worker recycled after max_requests with keepalive";

kill 'QUIT', $m1; waitpid $m1, 0;
pass "keepalive max_requests clean shutdown";

###############################################################################
# Test 2: preload_app=0 + app load failure → worker respawns
###############################################################################

my $app2 = "$dir/badapp.feersum";
open my $fh2, '>', $app2 or die;
# First load succeeds, subsequent loads tracked by a counter file
print $fh2 <<"APP";
my \$counter_file = "$dir/load_counter";
my \$n = 0;
if (-f \$counter_file) { open my \$f, '<', \$counter_file; \$n = <\$f>; chomp \$n; close \$f }
\$n++;
open my \$f, '>', \$counter_file; print \$f \$n; close \$f;
sub { \$_[0]->send_response(200,["Content-Type"=>"text/plain"],\\"pid=\$\$ load=\$n\\n") };
APP
close $fh2;

my (undef, $port2) = get_listen_socket();
my $m2 = fork // die "fork: $!";
if (!$m2) {
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen => ["localhost:$port2"], app_file => $app2,
            pre_fork => 1, preload_app => 0,
            quiet => 1,
        )->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 1.5 * TIMEOUT_MULT;

my $body2 = http_get($port2);
ok $body2, "preload_app=0 worker serves";
like $body2, qr/pid=\d+ load=\d+/, "response includes load counter";

kill 'QUIT', $m2; waitpid $m2, 0;
pass "preload_app=0 clean shutdown";

###############################################################################
# Test 3: graceful_timeout=0 — immediate force exit on QUIT
###############################################################################

my (undef, $port3) = get_listen_socket();
my $m3 = fork // die "fork: $!";
if (!$m3) {
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen => ["localhost:$port3"],
            graceful_timeout => 0,
            quiet => 1,
            app => sub {
                $_[0]->send_response(200, ['Content-Type'=>'text/plain'], \"ok\n");
            },
        )->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 0.8 * TIMEOUT_MULT;
ok http_get($port3), "server responds before QUIT";

kill 'QUIT', $m3;
my $start = time;
waitpid $m3, 0;
my $elapsed = time - $start;
ok $elapsed <= 3, "graceful_timeout=0 exited quickly (${elapsed}s)";

###############################################################################
# Test 4: FEERSUM_GRACEFUL_TIMEOUT env var override
###############################################################################

my (undef, $port4) = get_listen_socket();
my $m4 = fork // die "fork: $!";
if (!$m4) {
    $ENV{FEERSUM_GRACEFUL_TIMEOUT} = 0;
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen => ["localhost:$port4"],
            quiet => 1,
            app => sub {
                $_[0]->send_response(200, ['Content-Type'=>'text/plain'], \"ok\n");
            },
        )->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 0.8 * TIMEOUT_MULT;
ok http_get($port4), "server responds with env var timeout";

kill 'QUIT', $m4;
$start = time;
waitpid $m4, 0;
$elapsed = time - $start;
ok $elapsed <= 3, "FEERSUM_GRACEFUL_TIMEOUT=0 exited quickly (${elapsed}s)";
