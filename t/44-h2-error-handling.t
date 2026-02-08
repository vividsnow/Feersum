#!perl
# Test H2 error handling: GOAWAY on protocol errors, RST_STREAM,
# and server resilience after bad H2 frames.
use warnings;
use strict;
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || 1;
use Test::More;
use lib 't'; use Utils;

use Feersum;

my $evh = Feersum->new();

plan skip_all => "Feersum not compiled with TLS support"
    unless $evh->has_tls();

plan skip_all => "Feersum not compiled with H2 support"
    unless $evh->has_h2();

my $cert_file = 'eg/ssl-proxy/server.crt';
my $key_file  = 'eg/ssl-proxy/server.key';

plan skip_all => "no test certificates ($cert_file / $key_file)"
    unless -f $cert_file && -f $key_file;

eval { require IO::Socket::SSL };
plan skip_all => "IO::Socket::SSL not available"
    if $@;

my ($socket, $port) = get_listen_socket();
ok $socket, "got listen socket on port $port";

$evh->use_socket($socket);
eval { $evh->set_tls(cert_file => $cert_file, key_file => $key_file, h2 => 1) };
is $@, '', "set_tls with h2 enabled";

my @received;
$evh->request_handler(sub {
    my $r = shift;
    my $env = $r->env();
    push @received, $env->{PATH_INFO} || '/';
    $r->send_response(200, ['Content-Type' => 'text/plain'], 'OK');
});

# ---------------------------------------------------------------------------
# H2 frame helpers (same as t/50-h2-websocket.t)
# ---------------------------------------------------------------------------
use constant {
    H2_DATA          => 0x00,
    H2_HEADERS       => 0x01,
    H2_RST_STREAM    => 0x03,
    H2_SETTINGS      => 0x04,
    H2_GOAWAY        => 0x07,
    H2_WINDOW_UPDATE => 0x08,

    FLAG_END_STREAM  => 0x01,
    FLAG_END_HEADERS => 0x04,
    FLAG_ACK         => 0x01,
};

sub h2_frame {
    my ($type, $flags, $stream_id, $payload) = @_;
    $payload //= '';
    my $len = length $payload;
    return pack('CnCCN', ($len >> 16) & 0xFF, $len & 0xFFFF, $type, $flags, $stream_id & 0x7FFFFFFF) . $payload;
}

sub h2_client_preface {
    return "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
         . h2_frame(H2_SETTINGS, 0, 0, '')
         . h2_frame(H2_SETTINGS, FLAG_ACK, 0, '');
}

sub hpack_encode_string {
    my ($s) = @_;
    my $len = length $s;
    return pack('C', $len) . $s if $len < 127;
    return pack('C', 127) . encode_varint($len - 127) . $s;
}

sub encode_varint {
    my ($i) = @_;
    my $out = '';
    while ($i >= 128) {
        $out .= pack('C', ($i & 0x7F) | 0x80);
        $i >>= 7;
    }
    $out .= pack('C', $i);
    return $out;
}

sub hpack_encode_headers {
    my (@pairs) = @_;
    my $out = '';
    for my $pair (@pairs) {
        my ($name, $value) = @$pair;
        $out .= chr(0x00);
        $out .= hpack_encode_string($name);
        $out .= hpack_encode_string($value);
    }
    return $out;
}

sub h2_read_frame {
    my ($sock, $timeout) = @_;
    $timeout //= 5;
    my $deadline = time + $timeout;
    my $hdr = '';
    while (length($hdr) < 9 && time < $deadline) {
        my $n = $sock->sysread(my $buf, 9 - length($hdr));
        if (defined $n && $n > 0) { $hdr .= $buf; }
        elsif (defined $n && $n == 0) { return undef; }
        else { select(undef, undef, undef, 0.01); }
    }
    return undef if length($hdr) < 9;

    my ($len_hi, $len_lo, $type, $flags, $stream_id) = unpack('CnCCN', $hdr);
    my $len = ($len_hi << 16) | $len_lo;
    $stream_id &= 0x7FFFFFFF;

    my $payload = '';
    while (length($payload) < $len && time < $deadline) {
        my $n = $sock->sysread(my $buf, $len - length($payload));
        if (defined $n && $n > 0) { $payload .= $buf; }
        elsif (defined $n && $n == 0) { last; }
        else { select(undef, undef, undef, 0.01); }
    }
    return { type => $type, flags => $flags, stream_id => $stream_id,
             payload => $payload, length => $len };
}

sub h2_connect {
    my ($port) = @_;
    my $sock = IO::Socket::SSL->new(
        PeerAddr           => '127.0.0.1',
        PeerPort           => $port,
        SSL_verify_mode    => IO::Socket::SSL::SSL_VERIFY_NONE(),
        SSL_alpn_protocols => ['h2'],
        Timeout            => 5 * TIMEOUT_MULT,
    );
    return () unless $sock;

    $sock->syswrite(h2_client_preface());
    $sock->blocking(0);

    # Drain server SETTINGS + SETTINGS_ACK + WINDOW_UPDATE
    my $deadline = time + 3;
    while (time < $deadline) {
        my $f = h2_read_frame($sock, $deadline - time);
        last unless $f;
        last if $f->{type} == H2_SETTINGS && ($f->{flags} & FLAG_ACK);
    }
    return $sock;
}

# ========================================================================
# Test 1: Send garbage after H2 preface → expect GOAWAY
# ========================================================================
{
    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my $sock = h2_connect($port);
        exit(1) unless $sock;

        # Send garbage that isn't a valid H2 frame
        $sock->syswrite("GARBAGE GARBAGE GARBAGE\x00\x00\x00");

        # Read frames until we get GOAWAY or connection closes
        my $got_goaway = 0;
        my $deadline = time + 5;
        while (time < $deadline) {
            my $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            if ($f->{type} == H2_GOAWAY) {
                $got_goaway = 1;
                last;
            }
        }
        $sock->close();
        exit($got_goaway ? 0 : 2);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(10 * TIMEOUT_MULT, 0, sub {
        diag "timeout waiting for GOAWAY test";
        $cv->send('timeout');
    });
    my $cw = AE::child($pid, sub {
        $child_status = $_[1] >> 8;
        $cv->send('child_done');
    });

    my $reason = $cv->recv;
    isnt $reason, 'timeout', "garbage after preface: did not hang";
    is $child_status, 0, "garbage after preface: server sent GOAWAY";
}

# ========================================================================
# Test 2: Invalid H2 frame on stream 0 → expect GOAWAY
# (Send a DATA frame on stream 0, which is a protocol error per RFC 7540)
# ========================================================================
{
    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my $sock = h2_connect($port);
        exit(1) unless $sock;

        # DATA on stream 0 is a protocol error
        $sock->syswrite(h2_frame(H2_DATA, 0, 0, "bogus data on stream 0"));

        my $got_goaway = 0;
        my $deadline = time + 5;
        while (time < $deadline) {
            my $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            if ($f->{type} == H2_GOAWAY) {
                $got_goaway = 1;
                last;
            }
        }
        $sock->close();
        exit($got_goaway ? 0 : 2);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(10 * TIMEOUT_MULT, 0, sub {
        diag "timeout waiting for stream-0 DATA test";
        $cv->send('timeout');
    });
    my $cw = AE::child($pid, sub {
        $child_status = $_[1] >> 8;
        $cv->send('child_done');
    });

    my $reason = $cv->recv;
    isnt $reason, 'timeout', "DATA on stream 0: did not hang";
    is $child_status, 0, "DATA on stream 0: server sent GOAWAY";
}

# ========================================================================
# Test 3: Server survives protocol errors — new connections still work
# ========================================================================
{
    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.5 * TIMEOUT_MULT);

        # Normal H2 request via TLS should work after all the abuse above
        my $sock = h2_connect($port);
        exit(1) unless $sock;

        my $headers_block = hpack_encode_headers(
            [':method',    'GET'],
            [':path',      '/recovery'],
            [':scheme',    'https'],
            [':authority',  "127.0.0.1:$port"],
        );
        $sock->syswrite(h2_frame(H2_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM,
                                  1, $headers_block));

        my $got_response = 0;
        my $deadline = time + 5;
        while (time < $deadline) {
            my $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            if ($f->{type} == H2_HEADERS && $f->{stream_id} == 1) {
                $got_response = 1;
                last;
            }
        }

        $sock->syswrite(h2_frame(H2_GOAWAY, 0, 0, pack('NN', 0, 0)));
        select(undef, undef, undef, 0.1);
        $sock->close();
        exit($got_response ? 0 : 2);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(10 * TIMEOUT_MULT, 0, sub {
        diag "timeout waiting for recovery test";
        $cv->send('timeout');
    });
    my $cw = AE::child($pid, sub {
        $child_status = $_[1] >> 8;
        $cv->send('child_done');
    });

    my $reason = $cv->recv;
    isnt $reason, 'timeout', "recovery: did not timeout";
    is $child_status, 0, "recovery: new H2 connection works after protocol errors";
}

done_testing;
