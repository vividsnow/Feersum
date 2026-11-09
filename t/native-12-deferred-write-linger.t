#!perl
# A queued flush overtaken by the conn's own write watcher, which already
# started a lingering close, must not cut the linger short.
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;
use Feersum;
use EV;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
plan tests => 3;

$SIG{PIPE} = 'IGNORE';

my $dir = tempdir(CLEANUP => 1);
my ($lsn, $port) = get_listen_socket();
ok $lsn, "listen on $port";

my $f = Feersum->new_instance;
$f->use_socket($lsn);
my (@conns_after, $tail_t, $probe_t);
$f->request_handler(sub {
    my $r = shift;
    my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
    my $n = 0;
    # keeps the write watcher armed, so it can fire in the timer's own turn
    $w->poll_cb(sub { $_[0]->write('.') if $n++ < 100_000 });
    $tail_t = EV::timer(0.2 * TMULT, 0, sub {
        undef $tail_t;
        $w->write('TAIL');
        $w->close;
        undef $w;
        $probe_t = EV::timer(0.3 * TMULT, 0, sub { push @conns_after, $f->active_conns });
    });
    $tail_t->priority(2);   # ahead of the io callbacks of the same turn
});

my $pid = fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    close $lsn;
    my $got = '';
    my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port,
        Proto => 'tcp', Timeout => 5 * TMULT);
    if ($c) {
        local $SIG{ALRM} = sub { POSIX::_exit(4) };
        alarm 10 * TMULT;
        syswrite($c, "GET / HTTP/1.1\015\012Host: x\015\012Connection: close\015\012\015\012");
        while (sysread($c, my $buf, 65536)) { $got .= $buf }
        alarm 0;
        # stay connected past the server's probe: a lingering conn is still counted
        select undef, undef, undef, 0.8 * TMULT;
    }
    open my $out, '>', "$dir/got" or POSIX::_exit(9);
    print {$out} $got;
    close $out;
    POSIX::_exit(0);
}

my $cw = EV::child($pid, 0, sub { EV::break });
my $guard = EV::timer(15 * TMULT, 0, sub { EV::break });
EV::run;
undef $cw;

my $got = do { local $/; open my $in, '<', "$dir/got" or die; <$in> } // '';
like $got, qr/TAIL\015\0120\015\012\015\012\z/, 'the response ends with the tail and terminator';
is "@conns_after", '1', 'the conn is still lingering after the stale flush';
