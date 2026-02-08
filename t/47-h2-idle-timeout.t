#!perl
# Test that an idle H2 connection receives GOAWAY with NO_ERROR after
# read_timeout expires.
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

plan tests => 4;

my ($socket, $port) = get_listen_socket();
ok $socket, "got listen socket on port $port";

$evh->use_socket($socket);
eval { $evh->set_tls(cert_file => $cert_file, key_file => $key_file, h2 => 1) };
is $@, '', "set_tls with h2 enabled";

# Set a short read_timeout so the idle connection triggers GOAWAY quickly.
$evh->read_timeout(1.5 * TIMEOUT_MULT);

$evh->request_handler(sub {
    my $r = shift;
    $r->send_response(200, ['Content-Type' => 'text/plain'], 'OK');
});

# ---------------------------------------------------------------------------
# H2 frame helpers (copied from t/44-h2-error-handling.t)
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

# ---------------------------------------------------------------------------
# Test: idle H2 connection → GOAWAY(NO_ERROR) after read_timeout
# ---------------------------------------------------------------------------
{
    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        # Child: connect via TLS+H2, send preface, then idle.
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my $sock = IO::Socket::SSL->new(
            PeerAddr           => '127.0.0.1',
            PeerPort           => $port,
            SSL_verify_mode    => IO::Socket::SSL::SSL_VERIFY_NONE(),
            SSL_alpn_protocols => ['h2'],
            Timeout            => 5 * TIMEOUT_MULT,
        );
        exit(1) unless $sock;

        $sock->syswrite(h2_client_preface());
        $sock->blocking(0);

        # Drain server SETTINGS + SETTINGS_ACK + WINDOW_UPDATE
        my $deadline = time + 3;
        while (time < $deadline) {
            my $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            last if $f->{type} == H2_SETTINGS && ($f->{flags} & FLAG_ACK);
        }

        # Now idle — do NOT send any requests.
        # Wait for GOAWAY (should arrive after ~1.5s read_timeout).
        my $got_goaway = 0;
        my $error_code;
        my $wait_deadline = time + (5 * TIMEOUT_MULT);
        while (time < $wait_deadline) {
            my $f = h2_read_frame($sock, $wait_deadline - time);
            last unless $f;
            if ($f->{type} == H2_GOAWAY) {
                $got_goaway = 1;
                if (length($f->{payload}) >= 8) {
                    my ($last_stream_raw, $ec) = unpack('NN', $f->{payload});
                    $error_code = $ec;
                }
                last;
            }
        }

        $sock->close();
        # Exit code: 0 = GOAWAY with NO_ERROR, 1 = connect fail,
        # 2 = no GOAWAY, 3 = GOAWAY but wrong error code
        if (!$got_goaway) {
            exit(2);
        } elsif (!defined $error_code || $error_code != 0) {
            exit(3);
        } else {
            exit(0);
        }
    }

    # Parent: run event loop, wait for child.
    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(10 * TIMEOUT_MULT, 0, sub {
        diag "timeout waiting for idle H2 GOAWAY test";
        $cv->send('timeout');
    });
    my $cw = AE::child($pid, sub {
        $child_status = $_[1] >> 8;
        $cv->send('child_done');
    });

    my $reason = $cv->recv;
    isnt $reason, 'timeout', "idle H2 GOAWAY: did not hang";
    is $child_status, 0, "idle H2 connection received GOAWAY with NO_ERROR";
}
