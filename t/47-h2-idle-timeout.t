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

use H2Utils;

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

        h2_handshake($sock, timeout => 3);

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
