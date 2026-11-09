#!perl
# Test write_timeout: connections with stalled writes are closed
use warnings;
use strict;
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 2 : 1);
use Test::More tests => 9;
use Test::Fatal;
use lib 't'; use Utils;
use IO::Socket::INET;

BEGIN { use_ok('Feersum') };

my ($socket,$port) = get_listen_socket();
ok $socket, "made listen socket";
ok $socket->fileno, "has a fileno";

my $evh = Feersum->new();
is exception { $evh->use_socket($socket) }, undef, "bound to socket";

# Default is 0 (disabled)
is $evh->write_timeout, 0, "write_timeout defaults to 0";

# Set a short write timeout for testing
my $wt = 1.0 * TIMEOUT_MULT;
$evh->write_timeout($wt);
is $evh->write_timeout, $wt, "write_timeout set to $wt";
# read_timeout reaps a stalled reader too; keep it out of the window
$evh->read_timeout(60 * TIMEOUT_MULT);

# Streaming response that produces lots of data via poll_cb; a dropped Writer
# closes the response, so hold it
my $writer_keep;
$evh->request_handler(sub {
    my $r = shift;
    my $w = $writer_keep = $r->start_streaming(200, ["Content-Type" => "text/plain"]);
    $w->poll_cb(sub {
        my $writer = shift;
        # Keep producing data to fill kernel send buffer
        $writer->write("x" x 65536);
    });
});

my $cv = AE::cv;
$cv->begin;

# Use raw socket: connect, send request, then NEVER read.  Leave the receive
# buffer alone: a tiny one trickles the reaped residue in slower than any EOF
# deadline, and a peer that never reads stalls the writer regardless.
my $raw = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => $port,
    Proto    => 'tcp',
) or die "connect: $!";
$raw->syswrite("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n");

# The server shares this process, so wait for it to drop the stalled socket
# rather than guess a window: a peer buffer that keeps growing (macOS
# autosizing) reads as draining and rightly defers the reap.  Never read before
# then - reading is progress.  After it, the residue must end in EOF; an
# unreaped connection would stream without end.
my $t0 = AE::now;
my ($got, $end, $done, $poll, $rw, $limit) = (0, '');
my $finish = sub {
    my ($why) = @_;
    return if $done++;
    undef $poll; undef $rw; undef $limit;
    ok $end, "connection was closed (write timeout fired) - $end"
        or diag $why // "read $got bytes without the connection ending";
    close $raw;
    $cv->end;
};
$poll = AE::timer(0.1, 0.1, sub {
    return unless $writer_keep;   # a slow box may not have taken the request yet
    if ((eval { $writer_keep->fileno } // -1) >= 0) {
        return if AE::now - $t0 < 30 * TIMEOUT_MULT;
        return $finish->(sprintf 'server still holds the stalled socket after %.0fs',
                         AE::now - $t0);
    }
    undef $poll;
    $raw->blocking(0);
    $rw = AE::io($raw, 0, sub {
        my $n = $raw->sysread(my $buf, 65536);
        if (defined $n) {
            $n ? ($got += $n) : ($end = 'EOF');
            $finish->() if !$n || $got >= 64 * 1024 * 1024;
        }
        elsif (!$!{EAGAIN} && !$!{EWOULDBLOCK}) {
            $end = "error: $!";
            $finish->();
        }
    });
    $limit = AE::timer(10 * TIMEOUT_MULT, 0, sub { $finish->() });
});

$cv->recv;

# Test that write_timeout(0) disables it
$evh->write_timeout(0);
is $evh->write_timeout, 0, "write_timeout disabled";

# Test negative value croaks
like exception { $evh->write_timeout(-1) }, qr/non-negative/,
    "negative write_timeout croaks";
