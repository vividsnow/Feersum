#!perl
# A keepalive connection idle after a request whose large body the app ignored
# must not keep that body's buffer for the next request.
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;

BEGIN {
    plan skip_all => "needs /proc/<pid>/status" unless -r "/proc/$$/status";
    plan tests => 3;
}

use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(time sleep);
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use constant { CONNS => 30, BODY => 300_000 };

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
$f->set_keepalive(1);
$f->read_timeout($life);
$f->request_handler(sub {
    $_[0]->send_response(200, ['Content-Type' => 'text/plain'], ['ok']);  # body ignored
});
my $q = EV::signal('QUIT', sub { EV::break });
my $t = EV::timer($life, 0, sub { EV::break });
open my $fh, '>', "$ready.tmp" or die; print {$fh} $l->sockport, "\n"; close $fh;
rename "$ready.tmp", $ready or die;
EV::run;
POSIX::_exit(0);
SERVER
close $sf;

# a fresh perl with large buffers mmapped, so RSS tracks what is kept
my $pid = do {
    local $ENV{MALLOC_MMAP_THRESHOLD_} = 131072;
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

my $body = 'x' x BODY;
my $before = rss();
my (@conns, $ok);
for (1 .. CONNS) {
    my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port,
        Timeout => 10 * TMULT) or last;
    print {$s} "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: " . BODY . "\r\n\r\n$body";
    my $resp = '';
    while (sysread($s, $resp, 4096, length $resp)) { last if $resp =~ /\r\n\r\nok\z/ }
    $ok++ if $resp =~ /\r\n\r\nok\z/;
    push @conns, $s;
}
is $ok, CONNS, 'every request answered';

sleep 0.3 * TMULT;
my $kept = rss() - $before;
diag sprintf 'idle server RSS grew %d KB across %d connections', $kept, CONNS;
cmp_ok $kept, '<', 4 * 1024, 'idle connections do not keep the ignored bodies';
