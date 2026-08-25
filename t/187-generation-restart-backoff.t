#!perl
# #5(b): the master re-forked a dead generation with no backoff, so a crash-
# after-ready app spun it re-forking generations as fast as it could load the
# app (fable: 78 restarts in 4s).  Generation restarts now use the same
# exponential backoff as worker respawns.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More;
use lib 't'; use Utils;
use File::Temp qw(tempdir);
use POSIX ();

BEGIN {
    plan skip_all => 'not applicable on win32' if $^O eq 'MSWin32';
    plan skip_all => 'needs a POSIX fork' unless $Config::Config{d_fork}
        || eval { require Config; $Config::Config{d_fork} };
}
plan tests => 1;

my $parent_pid = $$;
END { $? = 0 if $$ != $parent_pid }

my $dir = tempdir(CLEANUP => 1);
my $app = "$dir/gen.feersum";
open my $ah, '>', $app or die $!;
# Comes up (signals ready), then _exits almost at once: a crash-after-ready
# loop.  The timer is parked in a global so it outlives the do().
print $ah <<'APP';
$Feersum::Runner::_t187_bomb = EV::timer(0.02, 0, sub { POSIX::_exit(7) });
sub { $_[0]->send_response(200, ["Content-Type"=>"text/plain"], \"gen-ok") }
APP
close $ah;

my (undef, $port) = get_listen_socket();
my $logf = "$dir/master.log";

my $master = fork // die "fork: $!";
if (!$master) {
    open STDOUT, '>', "$dir/master.out";
    open STDERR, '>', $logf;
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen => ["127.0.0.1:$port"], app_file => $app,
            hot_restart => 1, quiet => 0, startup_timeout => 5 * TIMEOUT_MULT,
        )->run;
    };
    POSIX::_exit(0);
}

# Let it crash-loop a while, then stop it.  My own #3 fix drains any live
# generation once the master is gone.
select undef, undef, undef, 3 * TIMEOUT_MULT;
kill 'KILL', $master;
waitpid $master, 0;

my $log = '';
if (open my $lh, '<', $logf) { local $/; $log = <$lh> // ''; close $lh }

# The backoff message ("restarting in Ns (failure N)") with a growing counter
# proves throttling; without the fix the master logs a bare "restarting" as
# fast as it can fork, and never reaches failure 3.
like $log, qr/restarting in \S+ \(failure 3\)/,
    'generation restarts back off exponentially instead of spinning'
    or diag "log tail:\n" . substr($log, -1200);
