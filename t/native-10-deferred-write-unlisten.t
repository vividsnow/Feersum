#!perl
# unlisten() in the turn a timer queued a write must not strand it, nor leave
# the loop spinning when listening again.
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
plan tests => 5;

$SIG{PIPE} = 'IGNORE';

my $dir = tempdir(CLEANUP => 1);
my ($lsn, $port) = get_listen_socket();
ok $lsn, "listen on $port";
my ($lsn2) = get_listen_socket();

my $f = Feersum->new_instance;
$f->use_socket($lsn);
$f->request_handler(sub {
    my $r = shift;
    my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
    my $t; $t = EV::timer(0.05, 0, sub {
        undef $t;
        $w->write('HELLO');
        $w->write('WORLD');
        $w->close;
        $f->unlisten;
        $f->use_socket($lsn2);
    });
});

my $pid = fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    close $lsn;
    my $got = '';
    my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port,
        Proto => 'tcp', Timeout => 5 * TMULT);
    if ($c) {
        syswrite($c, "GET / HTTP/1.1\015\012Host: x\015\012Connection: close\015\012\015\012");
        eval {
            local $SIG{ALRM} = sub { die "timeout\n" };
            alarm 3 * TMULT;
            while (sysread($c, my $buf, 65536)) {
                $got .= $buf;
                last if $got =~ /\015\0120\015\012\015\012\z/;
            }
            alarm 0;
        };
    }
    open my $out, '>', "$dir/got" or POSIX::_exit(9);
    print {$out} $got;
    close $out;
    POSIX::_exit(0);
}

my $done = 0;
my $cw = EV::child($pid, 0, sub { $done = 1; EV::break });
my $guard = EV::timer(10 * TMULT, 0, sub { EV::break });
EV::run;
ok $done, 'client finished';
undef $cw;
waitpid $pid, 0 unless $done;

my $got = do { local $/; open my $in, '<', "$dir/got" or die; <$in> } // '';
like $got, qr{\AHTTP/1\.1 200 }, 'response headers arrived';
my ($body) = $got =~ /\015\012\015\012(.*)\z/s;
my $plain = '';
$body //= '';
while ($body =~ s/\A([0-9a-f]+)\015\012//i) {
    my $len = hex $1;
    last unless $len;
    $plain .= substr($body, 0, $len, '');
    $body =~ s/\A\015\012//;
}
is $plain, 'HELLOWORLD', 'writes queued before unlisten were delivered';

# an idle loop wakes for the 1s date timer at most; a spinning one millions of times
my $iters = 0;
my $chk = EV::check(sub { $iters++ });
my $stop = EV::timer(0.5, 0, sub { EV::break });
EV::run;
cmp_ok $iters, '<', 1000, 'the loop sleeps after listening again';
