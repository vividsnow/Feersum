#!perl
# daemonize had NO test coverage at all (`grep -rn daemoniz t/ xt/` matched
# nothing), even though _daemonize_and_write_pid does fork + setsid + three
# croak-able stdio redirections and writes the pid file from the parent.
# Also covers two things that were broken:
#   * the pid file is documented as "removed on clean shutdown", but quit()
#     exits via POSIX::_exit, which skips END blocks and DESTROY;
#   * an unwritable pid_file was only discovered AFTER the daemon had forked
#     and started serving, leaving an orphan holding the port with no pid file
#     to find it by.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More tests => 12;
use lib 't'; use Utils;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use POSIX ();

my $parent_pid = $$;
END { $? = 0 if $$ != $parent_pid }
my @_daemons;
END { kill 'KILL', @_daemons if $$ == $parent_pid && @_daemons }

my $dir = tempdir(CLEANUP => 1);
my $app = "$dir/d.feersum";
open my $fh, '>', $app or die;
print $fh 'sub { $_[0]->send_response(200,["Content-Type"=>"text/plain"],\"daemon-ok") }';
close $fh;

sub serves {
    my ($port) = @_;
    my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port",
                                  Timeout => 3 * TIMEOUT_MULT) or return 0;
    my $out = '';
    eval {
        local $SIG{ALRM} = sub { die "to\n" };
        alarm 5 * TIMEOUT_MULT;
        print $s "GET / HTTP/1.0\r\n\r\n";
        local $/;
        $out = <$s> // '';
        alarm 0;
        1;
    };
    alarm 0;
    close $s;
    return $out =~ /daemon-ok/ ? 1 : 0;
}

sub read_pid_file {
    my ($f) = @_;
    open my $h, '<', $f or return undef;
    my $p = <$h>;
    close $h;
    return undef unless defined $p;
    $p =~ s/\s+//g;
    return $p =~ /^\d+$/ ? $p : undef;
}

#######################################################################
# 1. daemonize writes the DAEMON's pid, detaches, and serves
#######################################################################
my (undef, $port) = get_listen_socket();
my $pid_file = "$dir/d.pid";

my $starter = fork // die "fork: $!";
if (!$starter) {
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen => ["localhost:$port"], app_file => $app,
            daemonize => 1, pid_file => $pid_file, quiet => 1,
        )->run();
    };
    POSIX::_exit(0);
}
# The starter must return promptly: daemonize _exit(0)s the foreground parent.
my $starter_reaped = 0;
for (1 .. 40) {
    select undef, undef, undef, 0.25 * TIMEOUT_MULT;
    if (waitpid($starter, POSIX::WNOHANG()) > 0) { $starter_reaped = 1; last }
}
ok $starter_reaped, 'daemonize: foreground process exited';

select undef, undef, undef, 1.5 * TIMEOUT_MULT;
my $dpid = read_pid_file($pid_file);
ok $dpid, 'daemonize: pid file written';
push @_daemons, $dpid if $dpid;

isnt $dpid, $starter, 'daemonize: pid file holds the daemon, not the starter';
ok $dpid && kill(0, $dpid), 'daemonize: the recorded pid is alive';
ok serves($port), 'daemonize: the daemon serves requests';

#######################################################################
# 2. SIGQUIT stops it AND removes the pid file (documented contract)
#######################################################################
# Daemonizing reparents the process away from this test, so nothing here can
# reap it.  Where the inherited parent does not reap either (CI containers),
# an exited daemon lingers as a zombie and kill(0) keeps reporting it alive.
# A zombie has stopped; any other state has not.  Read /proc rather than
# shelling out to ps: fork from this file's context is not dependable.
sub daemon_state {
    my ($pid) = @_;
    open my $fh, '<', "/proc/$pid/stat" or return;
    my $line = <$fh>;
    close $fh;
    # "pid (comm) state ..." and comm may itself contain spaces or parens.
    return ($line && $line =~ /\)\s+(\S)/) ? $1 : undef;
}

sub daemon_gone {
    my ($pid) = @_;
    return 1 unless $pid && kill(0, $pid);
    my $st = daemon_state($pid);
    return (defined $st && $st eq 'Z') ? 1 : 0;
}

kill 'QUIT', $dpid if $dpid;
my $gone = 0;
for (1 .. 60) {
    select undef, undef, undef, 0.25 * TIMEOUT_MULT;
    if (daemon_gone($dpid)) { $gone = 1; last }
}
ok $gone, 'daemonize: SIGQUIT stopped the daemon'
    or diag "daemon pid=$dpid still alive, /proc state="
          . (daemon_state($dpid) // 'unavailable');
@_daemons = ();

ok !-e $pid_file, 'daemonize: pid file removed on clean shutdown';

#######################################################################
# 3. An unwritable pid_file must fail BEFORE the daemon starts serving,
#    otherwise it is an orphan holding the port with no pid to kill.
#######################################################################
my (undef, $port2) = get_listen_socket();
my $bad_pid_file = "$dir/nonexistent-subdir/x.pid";

my $starter2 = fork // die "fork: $!";
if (!$starter2) {
    open STDERR, '>', "$dir/err2.txt";
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen => ["localhost:$port2"], app_file => $app,
            daemonize => 1, pid_file => $bad_pid_file, quiet => 1,
        )->run();
    };
    POSIX::_exit($@ ? 1 : 0);
}
waitpid $starter2, 0;
select undef, undef, undef, 1.5 * TIMEOUT_MULT;

ok !serves($port2),
    'unwritable pid_file: no orphaned daemon left serving the port';
ok !-e $bad_pid_file, 'unwritable pid_file: no pid file created';

#######################################################################
# 4. The readiness handshake must report failure when the master dies
#    during startup.  It used to report SUCCESS in exactly that case:
#    pre_fork workers are forked BEFORE the master signals readiness, so
#    they inherit the pipe's write end and the parent never sees EOF; and
#    the SIGCHLD from the dying master interrupted select(), which the
#    parent read as "timed out" and treated as a good start.
#######################################################################
my (undef, $port3) = get_listen_socket();
my $master_pid_file = "$dir/master.pid";

my $starter3 = fork // die "fork: $!";
if (!$starter3) {
    open STDERR, '>', "$dir/err3.txt";
    require Feersum::Runner;
    no warnings 'redefine';
    my $orig = \&Feersum::Runner::_start_pre_fork;
    *Feersum::Runner::_start_pre_fork = sub {
        my $self = shift;
        $self->$orig(@_);
        # setsid() has run, so this pid is the pool's process group.
        if (open my $h, '>', $master_pid_file) { print {$h} "$$\n"; close $h }
        POSIX::_exit(3);        # die after forking, before signalling ready
    };
    eval {
        Feersum::Runner->new(
            listen => ["localhost:$port3"], app_file => $app, pre_fork => 2,
            daemonize => 1, quiet => 1, startup_timeout => 5,
        )->run();
    };
    POSIX::_exit(0);
}
my $st3;
for (1 .. 60) {
    select undef, undef, undef, 0.25 * TIMEOUT_MULT;
    last if waitpid($starter3, POSIX::WNOHANG()) > 0 and defined($st3 = $?);
}
# Reap the orphaned worker pool by its process group before asserting.
my $mpid = read_pid_file($master_pid_file);
kill 'KILL', -$mpid if $mpid;

ok defined $st3, 'startup failure: the daemonize parent exited';
is +(defined $st3 ? $st3 >> 8 : -1), 1,
    'startup failure: parent reports failure, not a false success';
select undef, undef, undef, 1.0 * TIMEOUT_MULT;
ok !serves($port3), 'startup failure: no worker pool left serving the port';
