#!perl
# pid_file + hot_restart: verify pid_file contains master PID
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More tests => 9;  # 7 explicit + 2 simple_client implicit
use utf8;
use lib 't'; use Utils;
use File::Temp qw(tempdir);
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

my $dir = tempdir(CLEANUP => 1);
my $app = "$dir/pidapp.feersum";
open my $fh, '>', $app or die;
print $fh 'sub { $_[0]->send_response(200,["Content-Type"=>"text/plain"],\"pid=$$\n") }';
close $fh;

my $pid_file = "$dir/feersum.pid";
my (undef, $port) = get_listen_socket();

my $master = fork // die "fork: $!";
if (!$master) {
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen      => ["localhost:$port"],
            app_file    => $app,
            hot_restart => 1,
            pid_file    => $pid_file,
            quiet       => 1,
        )->run();
    };
    POSIX::_exit(0);
}

select undef, undef, undef, 1.5 * TIMEOUT_MULT;

# pid_file should exist and contain the master pid
ok -f $pid_file, "pid_file created";
my $file_pid = do { open my $f, '<', $pid_file; local $/; <$f> };
chomp($file_pid //= '');
is $file_pid, $master, "pid_file contains master pid ($master)";

# Verify the serving generation has a DIFFERENT pid
my $body = http_get($port);
ok $body, "server responds";
my ($gen_pid) = ($body // '') =~ /pid=(\d+)/;
isnt $gen_pid, $master, "generation pid ($gen_pid) differs from master ($master)";

# After HUP, pid_file should still contain master pid (unchanged)
kill 'HUP', $master;
select undef, undef, undef, 2.0 * TIMEOUT_MULT;

my $body2 = http_get($port);
ok $body2, "responds after HUP";

my $file_pid2 = do { open my $f, '<', $pid_file; local $/; <$f> };
chomp($file_pid2 //= '');
# pid_file was written at startup by the master, not updated on HUP — still master pid
is $file_pid2, $master, "pid_file still contains master pid after HUP";

kill 'QUIT', $master;
waitpid $master, 0;
unlink $pid_file;
pass "pid_file+hot_restart clean shutdown";
