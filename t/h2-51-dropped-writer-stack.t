#!perl
# Freeing an unclosed H2 writer can run a sibling's poll_cb; growing the Perl
# stack there must not corrupt the heap under the caller.
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;

BEGIN {
    require Feersum;
    plan skip_all => "H2 not compiled in" unless Feersum->endjinn->has_h2();
    plan skip_all => "test certs not found"
        unless -f 't/certs/alpha.crt' && -f 't/certs/alpha.key';
}
my $nghttp = `which nghttp 2>/dev/null`;
chomp $nghttp;
plan skip_all => "nghttp not found in PATH" unless $nghttp && -x $nghttp;
plan tests => 6;

use File::Temp qw(tempdir);
use Time::HiRes qw(time sleep);
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);

my $dir = tempdir(CLEANUP => 1);
my $script = "$dir/server.pl";
open my $sf, '>', $script or die "write $script: $!";
print {$sf} <<'SERVER';
use strict; use warnings;
use EV; use Feersum; use IO::Socket::INET; use POSIX ();
my ($ready, $out, $psgi, $tmult) = @ARGV;
my $l = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
    Listen => 16, ReuseAddr => 1, Blocking => 0) or die "listen: $!";
my $f = Feersum->new_instance;
$f->use_socket($l);
$f->set_tls(cert_file => 't/certs/alpha.crt', key_file => 't/certs/alpha.key', h2 => 1);
$f->wbuf_low_water(1 << 30);    # the sibling's poll_cb runs on every send
our ($armed, $inside, $done, $t, $wb) = (0, 0, 0);
my $sibling = sub {
    my $h = shift;
    if ($armed) {
        $armed = 0;
        $inside++;
        my @grow = (1) x 400_000;    # reallocates the Perl stack
    }
    if ($done) { $h->write("end\n"); $h->close; return }
    $h->write('b');
};
my $arm = sub {
    $t = EV::timer(0.3 * $tmult, 0, sub {
        $done = 1;
        open my $o, '>', $out or return; print {$o} $inside; close $o;
    });
    $armed = 1;
};
if ($psgi) {
    $f->psgi_request_handler(sub {
        my $env = shift;
        return sub { $wb = $_[0]->([200, ['Content-Type' => 'text/plain']]); $wb->poll_cb($sibling) }
            if $env->{PATH_INFO} eq '/sibling';
        return sub {
            my $w = $_[0]->([200, ['Content-Type' => 'text/plain']]);
            $w->write("dropped\n");
            $arm->();
            return;    # $w goes unclosed: freeing it ends the stream
        };
    });
} else {
    $f->request_handler(sub {
        my $r = shift;
        if ($r->path eq '/sibling') {
            $wb = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
            $wb->poll_cb($sibling);
            return;
        }
        my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
        $w->write("dropped\n");
        $arm->();
        return;
    });
}
my $q = EV::signal('QUIT', sub { EV::break });
my $life = EV::timer(30 * $tmult, 0, sub { EV::break });
open my $fh, '>', "$ready.tmp" or die; print {$fh} $l->sockport, "\n"; close $fh;
rename "$ready.tmp", $ready or die;
EV::run;
POSIX::_exit(0);
SERVER
close $sf;

for my $psgi (0, 1) {
    my $mode = $psgi ? 'PSGI' : 'native';
    my ($ready, $out) = ("$dir/ready$psgi", "$dir/inside$psgi");
    # a fresh perl, freed memory poisoned: a read through the stale stack faults
    my $srv = do {
        local $ENV{MALLOC_PERTURB_} = 165;
        my $p = fork();
        die "fork: $!" unless defined $p;
        if (!$p) {
            { exec $^X, (map { "-I$_" } grep { !ref } @INC), $script, $ready, $out, $psgi, TMULT }
            POSIX::_exit(1);
        }
        $p;
    };
    my $deadline = time + 10 * TMULT;
    sleep 0.05 until -s $ready || time > $deadline;
    my $port = do { open my $in, '<', $ready or die "no ready file"; my $p = <$in>; chomp $p; $p };

    my $crc = system("$nghttp --no-verify -n https://127.0.0.1:$port/sibling "
        . "https://127.0.0.1:$port/dropped >/dev/null 2>&1");
    my $inside = -s $out ? do { open my $in, q{<}, $out or die; local $/; <$in> } : 0;
    ok $inside, "$mode: the sibling poll_cb ran while the dropped writer was freed";

    kill 'QUIT', $srv;
    my $status;
    my $until = time + 10 * TMULT;
    while (time < $until) {
        if (waitpid($srv, POSIX::WNOHANG()) > 0) { $status = $?; last }
        sleep 0.05;
    }
    unless (defined $status) { kill 'KILL', $srv; waitpid $srv, 0; $status = $? }
    ok $crc == 0 && $status == 0, "$mode: both streams completed and the server exited cleanly"
        or diag "client rc=$crc, server status=$status";
    is $status & 127, 0, "$mode: no crash"
        or diag 'server ended by signal ' . ($status & 127);
}
