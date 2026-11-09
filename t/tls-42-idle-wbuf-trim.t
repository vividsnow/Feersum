#!perl
# A keepalive TLS conn that sent a large response must not keep its peak-sized
# ciphertext buffer while it sits idle, and must still work once it is freed.
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
    plan tests => 4;
}

use File::Temp qw(tempdir);
use Time::HiRes qw(time sleep);
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use constant { CONNS => 16, BODY => 1 << 20 };

my $dir = tempdir(CLEANUP => 1);
my $ready = "$dir/ready";
my $script = "$dir/server.pl";
open my $sf, '>', $script or die "write $script: $!";
print {$sf} <<'SERVER';
use strict; use warnings;
use EV; use Feersum; use IO::Socket::INET; use POSIX ();
my ($ready, $life) = @ARGV;
my $l = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
    Listen => 128, ReuseAddr => 1, Blocking => 0) or die "listen: $!";
my $f = Feersum->new_instance;
$f->use_socket($l);
$f->set_tls(cert_file => 't/certs/alpha.crt', key_file => 't/certs/alpha.key', h2 => 0);
$f->set_keepalive(1);
$f->read_timeout($life);
my $big = 'y' x (1 << 20);
$f->request_handler(sub {
    $_[0]->send_response(200, ['Content-Type' => 'text/plain'], [$big]);
});
my $q = EV::signal('QUIT', sub { EV::break });
my $t = EV::timer($life, 0, sub { EV::break });
open my $fh, '>', "$ready.tmp" or die; print {$fh} $l->sockport, "\n"; close $fh;
rename "$ready.tmp", $ready or die;
EV::run;
POSIX::_exit(0);
SERVER
close $sf;

# glibc reads this only at startup, hence a fresh perl: large buffers are then
# mmapped and a free leaves RSS at once instead of waiting in the heap
my $pid = do {
    local $ENV{MALLOC_MMAP_THRESHOLD_} = 65536;
    my $p = fork();
    die "fork: $!" unless defined $p;
    if (!$p) {
        { exec $^X, (map { "-I$_" } grep { !ref } @INC), $script, $ready, 60 * TMULT }
        POSIX::_exit(1);
    }
    $p;
};
my $cleanup = guard { reap_server($pid) };

my $deadline = time + 10 * TMULT;
sleep 0.05 until -s $ready || time > $deadline;
my $port = do { open my $in, '<', $ready or die "no ready file"; my $p = <$in>; chomp $p; $p };
ok $port, "server listening on $port";

sub rss {
    open my $st, '<', "/proc/$pid/status" or return 0;
    while (<$st>) { return $1 if /^VmRSS:\s+(\d+)/ }
    return 0;
}

sub get_big {
    my ($s) = @_;
    print {$s} "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    my ($buf, $want) = ('', undef);
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm 10 * TMULT;
    my $ok = eval {
        while (!defined $want || length($buf) < $want) {
            my $n = sysread($s, $buf, 1 << 20, length $buf);
            return 0 unless $n;
            if (!defined $want && (my $at = index($buf, "\r\n\r\n")) >= 0) {
                my ($cl) = substr($buf, 0, $at) =~ /^Content-Length:\s*(\d+)/mi;
                return 0 unless defined $cl;
                $want = $at + 4 + $cl;
            }
        }
        1;
    };
    alarm 0;
    return 0 unless $ok;
    # a 1 MiB quantifier is past the regex limit on perl < 5.38
    my $at = index($buf, "\r\n\r\n");
    return length($buf) - $at - 4 == BODY && substr($buf, $at + 4) !~ /[^y]/ ? 1 : 0;
}

my $rss0 = rss();
my @conns;
my $served = 0;
for (1 .. CONNS) {
    my $s = IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $port,
        SSL_verify_mode => 0, Timeout => 10 * TMULT) or last;
    push @conns, $s;
    $served += get_big($s);
}
is $served, CONNS, 'every conn received its 1 MiB body';

my $peak = rss();
my $growth = $peak - $rss0;
diag sprintf "server RSS %d KB -> %d KB after %d responses", $rss0, $peak, CONNS;
SKIP: {
    skip "buffers never showed in RSS (+$growth KB)", 1 if $growth < 8 * 1024;
    my $target = $rss0 + $growth / 2;
    my $until = time + 5 * TMULT;
    my $now = $peak;
    while (time < $until) {
        $now = rss();
        last if $now <= $target;
        sleep 0.1;
    }
    cmp_ok $now, '<=', $target, "idle conns released their buffers (now $now KB)";
}

ok get_big($conns[0]), 'a conn whose buffer was released still serves a large body';
