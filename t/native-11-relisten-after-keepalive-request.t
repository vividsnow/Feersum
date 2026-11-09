#!perl
# After unlisten() a kept-alive conn's next request restarts the idle watcher;
# listening again in that same loop turn must not leave the loop spinning.
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;
use Feersum;
use EV;
use IO::Socket::INET;
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
plan tests => 4;

$SIG{PIPE} = 'IGNORE';

my ($lsn, $port) = get_listen_socket();
ok $lsn, "listen on $port";
my ($lsn2) = get_listen_socket();

my $f = Feersum->new_instance;
$f->use_socket($lsn);
$f->set_keepalive(1);
my $nreq = 0;
my ($block, $swap);
$f->request_handler(sub {
    $_[0]->send_response(200, ['Content-Length' => 2], ['ok']);
    return unless ++$nreq == 1;
    $block = EV::timer(0.1 * TMULT, 0, sub {
        $f->unlisten;
        # the second request lands while the loop is held here
        select undef, undef, undef, 0.4 * TMULT;
        $swap = EV::timer(0, 0, sub { $f->use_socket($lsn2) });
        $swap->priority(-1);    # after the read callback of the same turn
    });
});

my $pid = fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    close $lsn;
    my $ok = 0;
    my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port,
        Proto => 'tcp', Timeout => 5 * TMULT) or POSIX::_exit(2);
    local $SIG{ALRM} = sub { POSIX::_exit(4) };
    alarm 10 * TMULT;
    for my $i (1, 2) {
        select undef, undef, undef, 0.25 * TMULT if $i == 2;
        syswrite $c, "GET / HTTP/1.1\015\012Host: x\015\012\015\012";
        my $got = '';
        while ($got !~ /\015\012\015\012ok\z/) {
            my $n = sysread($c, $got, 65536, length $got);
            last unless $n;
        }
        $ok++ if $got =~ /\015\012\015\012ok\z/;
    }
    POSIX::_exit($ok == 2 ? 0 : 3);
}

my $status;
my $cw = EV::child($pid, 0, sub { $status = $_[0]->rstatus; EV::break });
my $guard = EV::timer(15 * TMULT, 0, sub { EV::break });
EV::run;
undef $cw;
is $status, 0, 'both keepalive requests answered';
is $nreq, 2, 'second request dispatched after the re-listen';

# an idle loop wakes for the 1s date timer at most; a spinning one millions of times
my $iters = 0;
my $chk = EV::check(sub { $iters++ });
my $stop = EV::timer(0.5, 0, sub { EV::break });
EV::run;
cmp_ok $iters, '<', 1000, 'the loop sleeps after listening again';
