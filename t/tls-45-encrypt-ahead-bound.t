#!perl
# A large TLS response to a slow reader is encrypted a window at a time: the
# server must not hold the whole body as ciphertext.
use warnings;
use strict;
use Test::More;
use lib 't'; use Utils;

BEGIN {
    require Feersum;
    plan skip_all => "TLS not compiled in" unless Feersum->endjinn->has_tls();
    plan skip_all => "needs /proc/<pid>/status" unless -r "/proc/$$/status";
    eval { require IO::Socket::SSL; 1 }
        or plan skip_all => "IO::Socket::SSL not available";
    plan skip_all => "OpenSSL too old for TLS 1.3 client" unless tls_client_ok();
    plan skip_all => "test certs not found"
        unless -f 't/certs/alpha.crt' && -f 't/certs/alpha.key';
    plan tests => 3;
}

use File::Temp qw(tempdir);
use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_RCVBUF);
use Time::HiRes qw(time sleep);
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use constant BODY => 16 << 20;

my $dir = tempdir(CLEANUP => 1);
my $ready = "$dir/ready";
my $script = "$dir/server.pl";
open my $sf, '>', $script or die "write $script: $!";
print {$sf} <<'SERVER';
use strict; use warnings;
use EV; use Feersum; use IO::Socket::INET; use POSIX ();
my ($ready, $life, $size) = @ARGV;
my $l = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
    Listen => 16, ReuseAddr => 1, Blocking => 0) or die "listen: $!";
my $f = Feersum->new_instance;
$f->use_socket($l);
$f->set_tls(cert_file => 't/certs/alpha.crt', key_file => 't/certs/alpha.key', h2 => 0);
# built once: before 5.20 an [$body] per request copies the whole string
my $body = [ 'z' x $size ];
$f->request_handler(sub {
    $_[0]->send_response(200, ['Content-Type' => 'text/plain'], $body);
});
my $q = EV::signal('QUIT', sub { EV::break });
my $t = EV::timer($life, 0, sub { EV::break });
open my $fh, '>', "$ready.tmp" or die; print {$fh} $l->sockport, "\n"; close $fh;
rename "$ready.tmp", $ready or die;
EV::run;
POSIX::_exit(0);
SERVER
close $sf;

# a fresh perl with large allocations mmapped, so peak RSS tracks live data
my $pid = do {
    local $ENV{MALLOC_MMAP_THRESHOLD_} = 65536;
    my $p = fork();
    die "fork: $!" unless defined $p;
    if (!$p) {
        { exec $^X, (map { "-I$_" } grep { !ref } @INC), $script, $ready, 60 * TMULT, BODY }
        POSIX::_exit(1);
    }
    $p;
};
my $cleanup = guard { reap_server($pid) };

my $deadline = time + 10 * TMULT;
sleep 0.05 until -s $ready || time > $deadline;
my $port = do { open my $in, '<', $ready or die "no ready file"; my $p = <$in>; chomp $p; $p };
ok $port, "server listening on $port";

sub mem {
    my ($key) = @_;
    open my $st, '<', "/proc/$pid/status" or return 0;
    while (<$st>) { return $1 if /^$key:\s+(\d+)/ }
    return 0;
}
my $start = mem('VmRSS');

my $tcp = IO::Socket::INET->new(Proto => 'tcp') or die "socket: $!";
setsockopt($tcp, SOL_SOCKET, SO_RCVBUF, pack 'i', 65536);
connect($tcp, Socket::pack_sockaddr_in($port, Socket::inet_aton('127.0.0.1'))) or die "connect: $!";
my $c = IO::Socket::SSL->start_SSL($tcp, SSL_verify_mode => 0, Timeout => 10 * TMULT)
    or die "TLS: $IO::Socket::SSL::SSL_ERROR";
print {$c} "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
my $got = 0;
{
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm 60 * TMULT;
    eval {
        while (my $n = sysread($c, my $buf, 16384)) {
            $got += $n;
            sleep 0.0002;
        }
    };
    alarm 0;
}
close $c;
cmp_ok $got, '>', BODY, 'the whole body arrived';

my $peak = mem('VmHWM') - $start;
diag sprintf 'peak server RSS grew %d KB for a %d MB body', $peak, BODY >> 20;
cmp_ok $peak, '<', 8 * 1024, 'ciphertext stayed bounded, not the size of the body';
