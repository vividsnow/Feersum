#!perl
# Regressions from the round-5 review:
#  1. A response to HEAD carried the message body (RFC 9110 section 9.3.2
#     forbids content).  On a keepalive connection the body bytes ran straight
#     into the next response's status line, desynchronising any client that
#     correctly reads no body after a HEAD.
#  2. write_timeout never fired for a complete (non-streaming) response: such
#     a response enters RESPOND_SHUTDOWN when it is queued, and
#     conn_write_timeout skipped that state, so a client that stopped reading
#     held the connection (and the whole response buffer) forever.
#  3. An unterminated chunk-size line was re-scanned from its start on every
#     read event and nothing bounded its length, so a dribbled line burned
#     quadratic CPU with no deadline.
use strict;
use warnings;
use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 2 : 1);
use Test::More;
use lib 't'; use Utils;
use Feersum;
use File::Temp ();
use Socket ();
use EV;

plan tests => 19;

my ($socket, $port) = get_listen_socket();
ok $socket, "listen on $port";

my $feer = Feersum->new();
$feer->use_socket($socket);
$feer->set_keepalive(1);
$feer->write_timeout(2 * TMULT);
# Raised so that only write_timeout can plausibly close the stalled connection
# below (read_timeout doubles as the keepalive idle timeout and defaults to 5s).
$feer->read_timeout(30 * TMULT);
# Small cap so an over-long URI triggers a server-generated 414 below.
$feer->max_uri_len(128);

# Swallow the DIED noise from the dying-handler test below.
{ no warnings q{redefine}; *Feersum::DIED = sub { }; }

# Must comfortably exceed the kernel send+receive buffers, otherwise the whole
# response lands in the socket buffer, the drain completes, and there is
# nothing for the write timer to reap.
my $big = 'x' x (16 * 1024 * 1024);
our $SENDFILE_PATH;

$feer->psgi_request_handler(sub {
    my $env = shift;
    my $p = $env->{PATH_INFO} || '/';
    # Streaming response: exercises the chunked write path and its terminator,
    # which HEAD must suppress entirely.
    if ($p eq '/stream') {
        return sub {
            my $respond = shift;
            my $w = $respond->([200, ['Content-Type' => 'text/plain']]);
            $w->write("STREAMED-BODY");
            $w->close;
        };
    }
    if ($p eq q{/sendfile} && $SENDFILE_PATH) {
        return sub {
            my $respond = shift;
            my $w = $respond->([200, [q{Content-Type} => q{application/octet-stream}]]);
            open my $in, q{<}, $SENDFILE_PATH or die "open: $!";
            $w->sendfile($in);
        };
    }
    return [200, ['Content-Type' => 'text/plain'], [$big]] if $p eq '/big';
    die "deliberate handler death\n" if $p eq q{/dies};
    return [205, [q{Content-Type} => q{text/plain}], [q{nobody205}]] if $p eq q{/205};
    return [205, [q{Content-Type} => q{text/plain}, q{Content-Length} => 9], [q{nobody205}]] if $p eq q{/205cl};
    return [404, ['Content-Type' => 'text/plain'], ['nope']] if $p eq '/missing';
    # a >4KB body exercises the separate-iovec branch of the write fast path
    return [200, ['Content-Type' => 'text/plain'], ['B' x 5000]] if $p eq '/large';
    return [200, ['Content-Type' => 'text/plain'], ['BODY-FOR-200']];
});

#####################################################################
# 1. HEAD must send headers (incl. Content-Length) but no body, and must
#    not desynchronise a pipelined keepalive connection.
#####################################################################
{
    run_client("head-no-body", sub {
        my $s = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port", Timeout => 5 * TMULT,
        ) or return 10;
        # HEAD then GET in one write, on one keepalive connection.
        $s->print("HEAD / HTTP/1.1\015\012Host: l\015\012\015\012".
                  "GET /missing HTTP/1.1\015\012Host: l\015\012".
                  "Connection: close\015\012\015\012");
        my $all = '';
        while (my $l = <$s>) { $all .= $l }

        # Pre-fix the wire read "...\r\n\r\nBODY-FOR-200HTTP/1.1 404...".
        return 11 if $all =~ /BODY-FOR-200/;
        # HEAD response still advertises the length a GET would have sent.
        return 12 unless $all =~ m{^HTTP/1\.1 200 OK\b}m;
        return 13 unless $all =~ /Content-Length:\s*12\b/i;
        # The next response must start cleanly on its own line.
        return 14 unless $all =~ m{\015\012\015\012HTTP/1\.1 404 Not Found\b};
        return 15 unless $all =~ /nope/;
        return 0;
    });}

#####################################################################
# 1b. Same for a body over 4KB, which takes the other fast-path branch.
#####################################################################
{
    run_client("head-no-body-large", sub {
        my $s = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port", Timeout => 5 * TMULT,
        ) or return 10;
        $s->print("HEAD /large HTTP/1.1\015\012Host: l\015\012".
                  "Connection: close\015\012\015\012");
        my $all = '';
        while (my $l = <$s>) { $all .= $l }
        return 11 if $all =~ /BBBB/;                      # no body bytes
        return 12 unless $all =~ /Content-Length:\s*5000\b/i;
        return 0;
    });}

#####################################################################
# 1c. Server-generated error responses must obey HEAD too.  These are built
#     by respond_with_server_error(), which bypasses the normal body path.
#####################################################################
{
    run_client("head-no-body-error", sub {
        my $s = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port", Timeout => 5 * TMULT,
        ) or return 10;
        # Over-long URI -> 414 from the server itself, not from the handler.
        $s->print("HEAD /" . ('u' x 300) . " HTTP/1.1\015\012Host: l\015\012\015\012");
        my $all = '';
        while (my $l = <$s>) { $all .= $l }
        return 11 unless $all =~ m{^HTTP/1\.[01] 414\b};
        my ($cl) = $all =~ /Content-Length:\s*(\d+)/i;
        return 12 unless defined $cl && $cl > 0;   # length a GET would send
        my ($body) = $all =~ /\015\012\015\012(.*)/s;
        return 13 if length($body // '');          # ...but no body bytes
        return 0;
    });
}

#####################################################################
# 1d. Streaming responses must obey HEAD too - including the terminating
#     chunk, which a HEAD client would otherwise read as the next response.
#     The headers stay exactly as a GET would get them (RFC 9110 9.3.2).
#####################################################################
{
    run_client("head-no-body-streaming", sub {
        my $s = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port", Timeout => 5 * TMULT,
        ) or return 10;
        $s->print("HEAD /stream HTTP/1.1\015\012Host: l\015\012".
                  "Connection: close\015\012\015\012");
        my $all = '';
        while (my $l = <$s>) { $all .= $l }
        my ($hdr, $body) = split /\015\012\015\012/, $all, 2;
        return 11 unless $hdr =~ m{^HTTP/1\.1 200\b};
        # Same framing header a GET would have received...
        return 12 unless $hdr =~ /Transfer-Encoding:\s*chunked/i;
        # ...but not one byte of body, terminating chunk included.
        return 13 if length($body // '');
        return 0;
    });
    # Control: the same handler over GET still streams its chunked body.
    run_client("streaming-get-unaffected", sub {
        my $s = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port", Timeout => 5 * TMULT,
        ) or return 10;
        $s->print("GET /stream HTTP/1.1\015\012Host: l\015\012".
                  "Connection: close\015\012\015\012");
        my $all = '';
        while (my $l = <$s>) { $all .= $l }
        return 11 unless $all =~ /STREAMED-BODY/;
        return 12 unless $all =~ /\r\n0\r\n\r\n\z/;   # terminating chunk present
        return 0;
    });
}

#####################################################################
# 2. write_timeout must reap a client that stops reading a complete response.
#####################################################################
# Asserted server-side: once the peer stops reading, a client-side EOF is not
# a reliable signal (the FIN sits behind megabytes of unread data), but the
# server dropping the connection is exactly what the fix is about.
{
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        select undef, undef, undef, 0.3 * TMULT;
        my $s = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port", Timeout => 5 * TMULT,
        );
        if ($s) {
            setsockopt($s, Socket::SOL_SOCKET(), Socket::SO_RCVBUF(), pack("I", 4096));
            # Connection: close keeps the keepalive idle timer out of it, and
            # read_timeout is raised above, so only write_timeout can reap.
            $s->print("GET /big HTTP/1.1\015\012Host: l\015\012".
                      "Connection: close\015\012\015\012");
            $s->flush;
            select undef, undef, undef, 14 * TMULT;   # never read a byte
        }
        exit 0;
    }

    my ($saw_conn, $reaped, $elapsed) = (0, 0, 0);
    my $w = EV::timer 0.5, 0.5, sub {
        $elapsed += 0.5;
        my $n = $feer->active_conns;
        $saw_conn = 1 if $n > 0;
        if ($saw_conn && $n == 0) { $reaped = 1; EV::break(EV::BREAK_ALL()); return }
        EV::break(EV::BREAK_ALL()) if $elapsed >= 12 * TMULT;
    };
    EV::run;
    kill 'KILL', $pid;
    waitpid($pid, 0);

    ok $saw_conn, "stalled reader connected";
    ok $reaped, "write_timeout reaped a stalled reader of a complete response";
}

#####################################################################
# 2b. ...but a transfer that is still PROGRESSING must not be reaped.  A
#     sendfile() response stays in RESPOND_SHUTDOWN for its whole duration,
#     and try_sendfile did not reset the write deadline on a successful send
#     the way the writev and TLS paths do, so once write_timeout was made
#     effective it started truncating downloads that were advancing normally.
#####################################################################
SKIP: {
    skip "sendfile is Linux-only", 2 unless $^O eq 'linux';
    my ($tfh, $tpath) = File::Temp::tempfile(UNLINK => 1);
    my $size = 4 * 1024 * 1024;
    print {$tfh} ('S' x $size);
    close $tfh;
    $SENDFILE_PATH = $tpath;

    run_client("sendfile-progress-not-reaped", sub {
        # SO_RCVBUF must be set BEFORE connect.  Setting it afterwards leaves
        # the already-negotiated window in place and the transfer wedges - that
        # is a client artifact (it reproduces against a plain non-Feersum
        # socket server too), not a server bug, but it will silently ruin this
        # test if the socket is built with IO::Socket::INET->new(PeerAddr=>...).
        socket(my $s, Socket::AF_INET(), Socket::SOCK_STREAM(), 0) or return 10;
        setsockopt($s, Socket::SOL_SOCKET(), Socket::SO_RCVBUF(), pack("I", 8192))
            or return 11;
        connect($s, Socket::pack_sockaddr_in($port, Socket::inet_aton('127.0.0.1')))
            or return 12;

        syswrite($s, "GET /sendfile HTTP/1.0\015\012\015\012") or return 13;
        # Small paced reads keep the server genuinely blocked on writability
        # for far longer than the 2s write_timeout set above.
        my $got = 0;
        while (1) {
            my $n = sysread($s, my $buf, 4096);
            last if !defined $n || $n == 0;
            $got += $n;
            select undef, undef, undef, 0.005;
        }
        # Headers + the whole file.  Pre-fix this stopped a few hundred KB short.
        return 14 unless $got > $size;
        return 0;
    });
}

#####################################################################
# 3. An unterminated chunk-size line must be rejected, not accepted forever.
#####################################################################
{
    run_client("chunk-size-line-bounded", sub {
        my $s = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port", Timeout => 5 * TMULT,
        ) or return 10;
        $s->print("POST / HTTP/1.1\015\012Host: l\015\012".
                  "Transfer-Encoding: chunked\015\012\015\012");
        $s->flush;
        # Leading zeros are legal hex and never overflow the size check, so
        # pre-fix this could grow without bound.
        my $sent = 0;
        for (1 .. 4000) {
            my $n = syswrite($s, '0') or last;
            $sent += $n;
        }
        my $resp = '';
        eval {
            local $SIG{ALRM} = sub { die "hang\n" };
            alarm(15 * TMULT);
            while (my $l = <$s>) { $resp .= $l; last if $resp =~ /\015\012\015\012/ }
            alarm(0);
        };
        alarm(0);
        return 11 if $@;
        return 12 unless $resp =~ m{^HTTP/1\.[01] 400\b};
        return 0;
    });}

# run_client() drives the event loop itself via $cv->recv, so there is no
# trailing EV::run here (see t/100 for the same pattern).

#####################################################################
# 4. 205 Reset Content must carry a length delimiter.  205 is NOT in RFC 9112
#    6.3 rule 1 (unlike HEAD, 1xx, 204, 304), so with neither Content-Length
#    nor Transfer-Encoding a keepalive client cannot find the end of the
#    response and reads the next one as this one's body.  RFC 7231 6.3.6
#    requires Content-Length: 0, an empty chunked body, or a close.
#####################################################################
{
    run_client("205-has-length-delimiter", sub {
        my $s = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1:$port", Timeout => 5 * TMULT,
        ) or return 10;
        # /205 declares no length; /205cl declares a bogus 9 with no body.
        for my $path (qw(/205 /205cl)) {
            $s->print("GET $path HTTP/1.1\015\012Host: l\015\012\015\012");
        }
        $s->print("GET /missing HTTP/1.1\015\012Host: l\015\012".
                  "Connection: close\015\012\015\012");
        my $all = '';
        while (my $l = <$s>) { $all .= $l }
        my @cl = $all =~ /Content-Length:\s*(\d+)/gi;
        # both 205s must advertise 0, not nothing and not the app's 9
        return 11 unless ($cl[0] // -1) == 0;
        return 12 unless ($cl[1] // -1) == 0;
        return 13 if $all =~ /nobody205/;          # no body bytes on the wire
        return 14 unless $all =~ /nope/;           # the pipeline stayed in sync
        return 0;
    });
}

