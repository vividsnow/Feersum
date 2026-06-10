#!perl
# KNOWN ISSUE, documented rather than fixed - see the TODO block below.
#
# Every close path treats "user-space buffers empty" as "delivered".  An empty
# wbuf_rinq (or tls_wbuf) only means the KERNEL send buffer accepted the
# bytes; megabytes can still be in flight.  close() then orphans the socket,
# and any byte arriving afterwards makes the kernel answer RST, which discards
# the queued response at BOTH ends.  There is no lingering close.
#
# A client only has to say something while reading - which is ordinary: an
# HTTP/1.1 client pipelining its next request, or one speculatively writing on
# what it believes is a reusable connection.  keepalive is off by default, so
# every response is a close-response and every such client is exposed.
#
# Measured on a 4MB response with keepalive off:
#   client silent          -> 4194304 bytes, clean EOF
#   client sends one byte  -> 1785735 bytes, "Connection reset by peer",
#                             three runs, identical truncation point
#
# The fix is a lingering close (shutdown(SHUT_WR), drain the read side to EOF
# under a bound, then close) as nginx and Apache both implement.  It is not
# applied here because it interacts with TLS close_notify, the graceful
# shutdown drain, max_connections accounting and fd pressure, and wants to be
# done deliberately rather than late in a release.
#
# This test is TODO so it does not fail the suite, but it will announce itself
# the moment the behaviour is fixed.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More;
use lib 't'; use Utils;
use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_RCVBUF);
use POSIX ();
use Feersum;

plan skip_all => 'author test' unless $ENV{FEERSUM_AUTHOR_TESTS} || $ENV{AUTHOR_TESTING};
plan tests => 3;

my $SIZE = 4 * 1024 * 1024;

my ($sock, $port) = get_listen_socket();
ok $sock, 'listen socket';

my $server = fork();
die "fork: $!" unless defined $server;
if (!$server) {
    open STDOUT, '>', '/dev/null';
    open STDERR, '>', '/dev/null';
    no warnings 'once';
    $Feersum::DIED = sub { };
    my $f = Feersum->new_instance();
    $f->use_socket($sock);
    # keepalive off is the default, so this is a close-response.
    $f->read_timeout(60 * TIMEOUT_MULT);
    $f->header_timeout(60 * TIMEOUT_MULT);
    $f->psgi_request_handler(sub {
        my $b = 'Z' x $SIZE;
        return [200, ['Content-Type' => 'application/octet-stream',
                      'Content-Length' => $SIZE], [$b]];
    });
    my $life_timer = EV::timer(300 * TIMEOUT_MULT, 0, sub { EV::break() });
    EV::run();
    POSIX::_exit(0);
}
close $sock;
select undef, undef, undef, 1 * TIMEOUT_MULT;

# Read the response slowly; optionally send one stray byte partway through.
sub fetch {
    my ($poke) = @_;
    my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port",
                                  Timeout => 10 * TIMEOUT_MULT) or return -1;
    local $SIG{PIPE} = 'IGNORE';
    # A small receive window keeps the server's send buffer loaded, so the
    # transfer is genuinely still in flight when the stray byte lands.
    setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', 8192));
    syswrite $s, "GET /big HTTP/1.0\r\n\r\n";
    my ($raw, $poked) = ('', 0);
    eval {
        local $SIG{ALRM} = sub { die "to\n" };
        alarm 240 * TIMEOUT_MULT;      # generous: an 8KB window is slow
        while (1) {
            my $n = sysread $s, my $z, 4096;
            last if !defined $n || $n == 0;
            $raw .= $z;
            if ($poke && !$poked && length($raw) > 200_000) {
                $poked = 1;
                syswrite $s, 'x';
            }
        }
        alarm 0;
        1;
    };
    alarm 0;
    close $s;
    my $i = index($raw, "\r\n\r\n");
    return $i >= 0 ? length($raw) - $i - 4 : 0;
}

my $silent = fetch(0);
is $silent, $SIZE,
    "a silent client receives the whole $SIZE-byte response (got $silent)";

my $poked = fetch(1);
TODO: {
    local $TODO = 'no lingering close: a byte arriving after close() makes '
                . 'the kernel RST and discard the response still in its send '
                . 'buffer';
    is $poked, $SIZE,
        "a client that sends one byte mid-download still receives the whole "
      . "response (got $poked)";
}

reap_server($server);
