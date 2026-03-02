#!perl
# Tests for Runner features: graceful_timeout, pid_file, after_fork,
# multiprocess psgi env, hot_restart failure rollback.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More tests => 19;  # 14 explicit + 5 simple_client implicit
use utf8;
use lib 't'; use Utils;
use File::Temp qw(tempfile tempdir);
use POSIX ();

my $parent_pid = $$;
END { $? = 0 if $$ != $parent_pid }

###############################################################################
# Test 1: pid_file is created and cleaned up
###############################################################################

my (undef, $port1) = get_listen_socket();
my $pid_file = File::Temp::tmpnam() . '.pid';

my $pid1 = fork;
die "fork: $!" unless defined $pid1;
if (!$pid1) {
    require Feersum::Runner;
    eval {
        my $runner = Feersum::Runner->new(
            listen   => ["localhost:$port1"],
            pid_file => $pid_file,
            quiet    => 1,
            app      => sub {
                my $r = shift;
                $r->send_response(200, ['Content-Type'=>'text/plain'], \"ok\n");
            },
        );
        $runner->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 0.8 * TIMEOUT_MULT;
ok -f $pid_file, "pid_file created";
my $file_pid = do { open my $fh, '<', $pid_file; local $/; <$fh> };
chomp $file_pid;
is $file_pid, $pid1, "pid_file contains correct pid";

# Verify server responds
my $body1;
my $cv1 = AE::cv;
my $c1; $c1 = simple_client GET => '/', port => $port1, sub {
    ($body1) = @_;
    $cv1->send;
    undef $c1;
};
$cv1->recv;
is $body1, "ok\n", "server responds";

kill 'QUIT', $pid1;
waitpid $pid1, 0;
unlink $pid_file;  # child uses _exit, cleanup may not run

###############################################################################
# Test 2: after_fork hook runs in workers
###############################################################################

my ($fh2, $app_file2) = tempfile(SUFFIX => '.feersum', UNLINK => 1);
my $marker_dir = tempdir(CLEANUP => 1);
print $fh2 <<"APP";
sub {
    my \$r = shift;
    # Check if after_fork created our marker
    my \@markers = glob("$marker_dir/after_fork_*");
    my \$body = "markers=" . scalar(\@markers) . "\\n";
    \$r->send_response(200, ['Content-Type'=>'text/plain'], \\\$body);
};
APP
close $fh2;

my (undef, $port2) = get_listen_socket();
my $pid2 = fork;
die "fork: $!" unless defined $pid2;
if (!$pid2) {
    require Feersum::Runner;
    eval {
        my $runner = Feersum::Runner->new(
            listen     => ["localhost:$port2"],
            app_file   => $app_file2,
            pre_fork   => 2,
            quiet      => 1,
            after_fork => sub {
                # Create a marker file per worker
                open my $fh, '>', "$marker_dir/after_fork_$$";
                close $fh;
            },
        );
        $runner->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 1.5 * TIMEOUT_MULT;

my $body2;
my $cv2 = AE::cv;
my $c2; $c2 = simple_client GET => '/', port => $port2, sub {
    ($body2) = @_;
    $cv2->send;
    undef $c2;
};
$cv2->recv;
like $body2, qr/^markers=\d+/, "after_fork callback ran";
my ($n_markers) = ($body2 // '') =~ /markers=(\d+)/;
ok $n_markers && $n_markers >= 1, "at least 1 after_fork marker created";

kill 'QUIT', $pid2;
waitpid $pid2, 0;
pass "pre_fork with after_fork shut down cleanly";

###############################################################################
# Test 3: psgi.multiprocess is true under pre_fork
###############################################################################

my ($fh3, $app_file3) = tempfile(SUFFIX => '.psgi', UNLINK => 1);
print $fh3 <<'APP';
sub {
    my $env = shift;
    my $mp = $env->{'psgi.multiprocess'} ? 'true' : 'false';
    [200, ['Content-Type' => 'text/plain'], ["multiprocess=$mp\n"]];
};
APP
close $fh3;

my (undef, $port3) = get_listen_socket();
my $pid3 = fork;
die "fork: $!" unless defined $pid3;
if (!$pid3) {
    require Feersum::Runner;
    require Plack::Handler::Feersum;
    eval {
        my $runner = Plack::Handler::Feersum->new(
            listen   => ["localhost:$port3"],
            pre_fork => 2,
            quiet    => 1,
        );
        my $app = do $app_file3;
        $runner->run($app);
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 1.5 * TIMEOUT_MULT;

my $body3;
my $cv3 = AE::cv;
my $c3; $c3 = simple_client GET => '/', port => $port3, sub {
    ($body3) = @_;
    $cv3->send;
    undef $c3;
};
$cv3->recv;
is $body3, "multiprocess=true\n", "psgi.multiprocess is true under pre_fork";

kill 'QUIT', $pid3;
waitpid $pid3, 0;
pass "psgi multiprocess test shut down cleanly";

###############################################################################
# Test 4: preload_app => 0 — workers load app independently
###############################################################################

my ($fh4, $app_file4) = tempfile(SUFFIX => '.feersum', UNLINK => 1);
print $fh4 <<'APP';
sub {
    my $r = shift;
    $r->send_response(200, ['Content-Type'=>'text/plain'], \"pid=$$\n");
};
APP
close $fh4;

my (undef, $port4) = get_listen_socket();
my $pid4 = fork;
die "fork: $!" unless defined $pid4;
if (!$pid4) {
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen      => ["localhost:$port4"],
            app_file    => $app_file4,
            pre_fork    => 2,
            preload_app => 0,
            quiet       => 1,
        )->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 1.5 * TIMEOUT_MULT;

my $body4;
my $cv4 = AE::cv;
my $c4; $c4 = simple_client GET => '/', port => $port4, sub {
    ($body4) = @_;
    $cv4->send;
    undef $c4;
};
$cv4->recv;
ok $body4, "preload_app=0 server responds";
like $body4, qr/^pid=\d+/, "preload_app=0 worker has its own pid";

kill 'QUIT', $pid4;
waitpid $pid4, 0;
pass "preload_app=0 shut down cleanly";

###############################################################################
# Test 5: access_log callback fires with correct args
###############################################################################

my $log_dir = tempdir(CLEANUP => 1);
my $log_file = "$log_dir/access.log";

my (undef, $port5) = get_listen_socket();
my $pid5 = fork;
die "fork: $!" unless defined $pid5;
if (!$pid5) {
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen     => ["localhost:$port5"],
            quiet      => 1,
            access_log => sub {
                my ($method, $uri, $elapsed) = @_;
                open my $fh, '>>', $log_file;
                print $fh "$method $uri $elapsed\n";
                close $fh;
            },
            app => sub {
                my $r = shift;
                $r->send_response(200, ['Content-Type'=>'text/plain'], \"ok\n");
            },
        )->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 0.8 * TIMEOUT_MULT;

my $cv5 = AE::cv;
my $c5; $c5 = simple_client GET => '/test-path', port => $port5, sub {
    $cv5->send; undef $c5;
};
$cv5->recv;

# Give guard time to fire (response_guard fires after send completes)
select undef, undef, undef, 0.5 * TIMEOUT_MULT;

ok -f $log_file, "access_log file created";
my $log_content = do { local (@ARGV, $/) = ($log_file); <> } // '';
like $log_content, qr{^GET /test-path \d}, "access_log captured method, uri, elapsed";

kill 'QUIT', $pid5;
waitpid $pid5, 0;
pass "access_log test shut down cleanly";
