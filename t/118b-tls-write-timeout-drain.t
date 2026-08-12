#!perl
# TLS twin of t/88d-write-timeout-drain.t: write_timeout must not truncate an
# HTTPS client that is still draining the kernel send buffer, even when it
# drains too slowly to ever re-trigger EPOLLOUT (Linux re-signals writability
# only after HALF the send buffer frees, and the tls_wbuf flush - the only
# deadline-refreshing write on the TLS path - runs off that same signal).
# A peer that drains nothing for three consecutive intervals is still reaped.
#
# Buffer sizes are pinned on both ends so the behaviour does not depend on
# the machine's autotuning, and the assertions are byte counts, not timing.
use warnings;
use strict;
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 2 : 1);
use Test::More;
use Test::Fatal;
use lib 't'; use Utils;
use Socket qw(SOL_SOCKET SO_SNDBUF SO_RCVBUF SO_REUSEADDR SOMAXCONN
              AF_INET SOCK_STREAM inet_aton pack_sockaddr_in sockaddr_in);
use IO::Socket::INET ();
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Time::HiRes qw(time sleep);
use Feersum;

my $evh = Feersum->new();
plan skip_all => "Feersum not compiled with TLS support" unless $evh->has_tls();
plan skip_all => 'no kernel send-queue probe (SIOCOUTQ/SO_NWRITE/FIONWRITE) on this platform'
    unless $evh->has_outq_probe;
# Same gate and reason as t/88d: the defect this pins down is the Linux
# EPOLLOUT watermark.  t/118-tls-write-deadline.t covers the flushed-write
# refresh on the other platforms.
plan skip_all => "Linux-specific send-buffer behaviour (this is $^O)"
    unless $^O eq 'linux';
my $cert = 'eg/ssl-proxy/server.crt';
my $key  = 'eg/ssl-proxy/server.key';
plan skip_all => "no test certificates" unless -f $cert && -f $key;
eval { require IO::Socket::SSL; 1 }
    or plan skip_all => "IO::Socket::SSL not installed";
plan skip_all => "OpenSSL too old for TLS 1.3 client" unless tls_client_ok();
plan tests => 11;

use AnyEvent;
use EV;

my $wt    = 1.0 * TIMEOUT_MULT;
my $BODY  = 3 * 1024 * 1024;   # well above what the pinned kernel buffers absorb
my $CHUNK = 'x' x (1024 * 1024);

# Pin SO_SNDBUF before listen: accepted sockets inherit it.  512KB requested
# (1MB effective) means EPOLLOUT needs 512KB drained, which the slow reader
# below (~80KB/s) cannot manage within any sane write_timeout.
socket(my $lsock, AF_INET, SOCK_STREAM, 0) or die "socket: $!";
setsockopt($lsock, SOL_SOCKET, SO_REUSEADDR, pack('l', 1));
setsockopt($lsock, SOL_SOCKET, SO_SNDBUF, pack('l', 512 * 1024)) or die "sndbuf: $!";
bind($lsock, pack_sockaddr_in(0, inet_aton('127.0.0.1'))) or die "bind: $!";
listen($lsock, SOMAXCONN) or die "listen: $!";
my $fl = fcntl($lsock, F_GETFL, 0);
fcntl($lsock, F_SETFL, $fl | O_NONBLOCK) or die "nonblock: $!";
my ($port) = sockaddr_in(getsockname($lsock));
ok $port, "made pinned listen socket on port $port";

is exception {
    $evh->use_socket($lsock);
    $evh->set_tls(cert_file => $cert, key_file => $key);
}, undef, "bound to socket, TLS configured";
$evh->write_timeout($wt);
$evh->read_timeout(120 * TIMEOUT_MULT);

$evh->request_handler(sub {
    my $r = shift;
    if ($r->path eq '/streaming') {
        my $w = $r->start_streaming(200, ['Content-Type' => 'application/octet-stream']);
        $w->write($CHUNK) for 1 .. 3;
        $w->close;
    }
    else {
        $r->send_response(200,
            ['Content-Type' => 'application/octet-stream', 'Content-Length' => $BODY],
            [($CHUNK) x 3]);
    }
});

# Forked TLS client (a blocking handshake in-process would deadlock the loop).
# Reads the header, then paces at 16KB plaintext per 0.2s (~80KB/s: draining,
# but far below the 512KB EPOLLOUT threshold per interval) for stall_for
# seconds of not reading at all first if requested, slow_for seconds spanning
# several deadlines next, then drains at full speed.  Pacing is per BYTES
# received, not per sysread: TLS records need not align with read sizes.
# Reports "<verdict> <body_len> <elapsed> <eof>" on the pipe.
sub run_tls_client {
    my ($path, $slow_for, $stall_for) = @_;
    pipe(my $rpt_r, my $rpt_w) or die "pipe: $!";
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if (!$pid) {
        close $rpt_r;
        my $report = sub { syswrite($rpt_w, "$_[0]\n"); exit 0 };
        select undef, undef, undef, 0.3;
        # A real IO::Socket, not a bare glob: start_SSL on a glob croaked
        # "bad open mode" under IO::Socket::SSL 2.096 on CPAN Testers.
        my $s = IO::Socket::INET->new(Proto => q{tcp}) or $report->("ERR-socket 0 0 0");
        # Pin SO_RCVBUF before connect: fixes the window scale and disables
        # receive autotuning, so the kernels absorb a known ~1.2MB total.
        setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('l', 64 * 1024))
            or $report->("ERR-rcvbuf 0 0 0");
        $s->connect(pack_sockaddr_in($port, inet_aton('127.0.0.1')))
            or $report->("ERR-connect 0 0 0");
        IO::Socket::SSL->start_SSL($s, SSL_verify_mode => 0)
            or $report->("ERR-handshake 0 0 0");
        syswrite($s, "GET $path HTTP/1.0\r\nHost: localhost\r\n\r\n")
            or $report->("ERR-request 0 0 0");

        sleep $stall_for if $stall_for;   # dead-peer phase: read nothing at all

        my ($head, $over) = ('', '');
        while ($head !~ /\r\n\r\n/) {
            my $n = sysread($s, my $b, 512);
            $report->("ERR-no-header 0 0 0") unless $n;
            $head .= $b;
        }
        ($head, $over) = split /\r\n\r\n/, $head, 2;
        $head =~ m{\AHTTP/1\.[01] 200} or $report->("ERR-status 0 0 0");

        my $got  = length($over // '');
        my $t0   = time;
        my $eof  = 0;
        my $tick = 0;
        while (1) {
            my $n = sysread($s, my $b, 16384);
            if (!defined $n) { last }         # reset mid-read: not a clean EOF
            if ($n == 0)     { $eof = 1; last }
            $got  += $n;
            $tick += $n;
            if ($tick >= 16384) {
                $tick = 0;
                sleep 0.2 if time - $t0 < $slow_for;
            }
            last if time - $t0 > 60 * TIMEOUT_MULT;
        }
        $report->(sprintf "OK %d %.2f %d", $got, time - $t0, $eof);
    }
    close $rpt_w;
    my $cv = AE::cv;
    my $line = '';
    my $io_w = AE::io($rpt_r, 0, sub {
        my $n = sysread($rpt_r, my $b, 1024);
        if (!defined($n) || $n == 0) { $cv->send }
        else { $line .= $b; $cv->send if $line =~ /\n/ }
    });
    my $bail = AE::timer 90 * TIMEOUT_MULT, 0, sub { $line ||= "ERR-parent-timeout 0 0 0"; $cv->send };
    $cv->recv;
    chomp $line;
    waitpid $pid, 0;
    my ($verdict, $blen, $elapsed, $eof) = split ' ', $line;
    $_ //= 0 for $blen, $elapsed, $eof;
    return ($verdict || 'ERR-empty', $blen, $elapsed, $eof);
}

# Phase 1: buffered response to a slow-but-draining reader survives several
# deadlines and arrives complete.  Slow phase spans >= 4 deadline intervals.
{
    my ($verdict, $blen, $elapsed, $eof) = run_tls_client('/buffered', 4.5 * $wt);
    is $verdict, 'OK', "buffered: client ran clean" or diag "client said: $verdict";
    ok $eof, "buffered: clean EOF";
    is $blen, $BODY, "buffered: slow-draining reader got the whole body";
    cmp_ok $elapsed, '>', 3 * $wt, "buffered: transfer outlived several deadlines (${elapsed}s)";
}

# Phase 2: same through the streaming (start_streaming + write) path.
{
    my ($verdict, $blen, $elapsed, $eof) = run_tls_client('/streaming', 4.5 * $wt);
    is $verdict, 'OK', "streaming: client ran clean" or diag "client said: $verdict";
    ok $eof, "streaming: clean EOF";
    is $blen, $BODY, "streaming: slow-draining reader got the whole body";
}

# Phase 3: a peer that drains NOTHING must still be reaped (that is what
# write_timeout is for; drain-refresh bounds it at three intervals).  Wait 5
# intervals without reading, then drain: if the reaper fired, the server
# never wrote more than the kernel buffers absorbed (~1.2MB << 3MB).
{
    my ($verdict, $blen, undef, undef) = run_tls_client('/buffered', 0, 5 * $wt);
    isnt $verdict, 'ERR-parent-timeout', "stuck: client came back";
    cmp_ok $blen, '<', $BODY, "stuck: response was cut short ($blen < $BODY)";
}
