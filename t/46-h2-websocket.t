#!perl
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

# ---------------------------------------------------------------------------
# Minimal H2 frame helpers
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

    SETTINGS_ENABLE_CONNECT_PROTOCOL => 0x08,
};

sub h2_frame {
    my ($type, $flags, $stream_id, $payload) = @_;
    $payload //= '';
    my $len = length $payload;
    return pack('CnCCN', ($len >> 16) & 0xFF, $len & 0xFFFF, $type, $flags, $stream_id & 0x7FFFFFFF) . $payload;
}

# Build the initial H2 client handshake (preface + empty SETTINGS + SETTINGS ACK)
sub h2_client_preface {
    return "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
         . h2_frame(H2_SETTINGS, 0, 0, '')
         . h2_frame(H2_SETTINGS, FLAG_ACK, 0, '');
}

# HPACK: encode headers as literals without indexing
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

sub hpack_encode_string {
    my ($s) = @_;
    my $len = length $s;
    if ($len < 127) {
        return pack('C', $len) . $s;
    }
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

# Read one H2 frame from a non-blocking SSL socket (with timeout)
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
    return { type => $type, flags => $flags, stream_id => $stream_id, payload => $payload, length => $len };
}

# Read frames until we find one matching type+stream_id (or timeout)
sub h2_read_until {
    my ($sock, $type, $stream_id, $timeout) = @_;
    $timeout //= 5;
    my $deadline = time + $timeout;
    while (time < $deadline) {
        my $f = h2_read_frame($sock, $deadline - time);
        return undef unless $f;
        return $f if $f->{type} == $type && (!defined $stream_id || $f->{stream_id} == $stream_id);
    }
    return undef;
}

# Extract :status from HPACK-encoded HEADERS payload (simple decoder)
sub hpack_decode_status {
    my ($payload) = @_;
    my $pos = 0;
    while ($pos < length $payload) {
        my $byte = ord(substr($payload, $pos, 1));
        $pos++;
        if ($byte & 0x80) {
            my $idx = $byte & 0x7F;
            return '200' if $idx == 8;
            return '204' if $idx == 9;
            return '206' if $idx == 10;
            return '304' if $idx == 11;
            return '400' if $idx == 12;
            return '404' if $idx == 13;
            return '500' if $idx == 14;
        } elsif (($byte & 0xF0) == 0x00 || ($byte & 0xC0) == 0x40) {
            my $name_idx = ($byte & 0xC0) == 0x40 ? ($byte & 0x3F) : ($byte & 0x0F);
            my ($name, $value);
            if ($name_idx == 0) {
                ($name, $pos) = hpack_decode_string($payload, $pos);
            } else {
                $name = $name_idx == 8 ? ':status' : "idx:$name_idx";
            }
            ($value, $pos) = hpack_decode_string($payload, $pos);
            return $value if defined $name && $name eq ':status';
        } else {
            last;
        }
    }
    return undef;
}

sub hpack_decode_string {
    my ($buf, $pos) = @_;
    my $byte = ord(substr($buf, $pos, 1));
    $pos++;
    my $is_huffman = $byte & 0x80;
    my $len = $byte & 0x7F;
    if ($len == 127) {
        my $m = 0;
        while (1) {
            my $b = ord(substr($buf, $pos, 1));
            $pos++;
            $len += ($b & 0x7F) << $m;
            $m += 7;
            last unless ($b & 0x80);
        }
    }
    my $raw = substr($buf, $pos, $len);
    if ($is_huffman) {
        # Try Huffman decoding for digit-only strings (status codes).
        # HPACK Huffman codes for '0'-'9' are 5-bit codes 0x00-0x09 (RFC 7541 App B).
        my $decoded = _hpack_huffman_decode_digits($raw);
        $raw = $decoded if defined $decoded;
    }
    return ($raw, $pos + $len);
}

# Decode a Huffman-encoded string that contains only digits (0-9).
# Each digit is a 5-bit HPACK Huffman code (codes 0x00-0x09).
# Returns decoded string, or undef if the data contains non-digit codes.
sub _hpack_huffman_decode_digits {
    my ($data) = @_;
    my $bits = unpack('B*', $data);
    my $blen = length $bits;
    my $pos = 0;
    my $result = '';
    while ($pos + 5 <= $blen) {
        my $code = oct('0b' . substr($bits, $pos, 5));
        if ($code <= 9) {
            $result .= $code;
            $pos += 5;
        } else {
            last;
        }
    }
    # Remaining bits must be all-1 EOS padding (RFC 7541 §5.2)
    if ($pos < $blen) {
        my $tail = substr($bits, $pos);
        return undef unless $tail =~ /^1+$/;
    }
    return length($result) > 0 ? $result : undef;
}

# Connect to server with H2 ALPN + send preface. Returns (sock, settings_payload).
sub h2_connect {
    my ($port) = @_;

    my $sock = IO::Socket::SSL->new(
        PeerAddr        => '127.0.0.1',
        PeerPort        => $port,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        SSL_alpn_protocols => ['h2'],
    );
    return () unless $sock;

    # Send H2 preface + settings + settings_ack all at once (so server processes
    # everything in a single read cycle and calls session_send)
    $sock->syswrite(h2_client_preface());

    # Read server SETTINGS
    $sock->blocking(0);
    my $settings_payload;
    my $deadline = time + 5;
    while (time < $deadline) {
        my $f = h2_read_frame($sock, $deadline - time);
        last unless $f;
        if ($f->{type} == H2_SETTINGS && !($f->{flags} & FLAG_ACK)) {
            $settings_payload = $f->{payload};
            last;
        }
    }

    # Drain any remaining frames (SETTINGS ACK, WINDOW_UPDATE, etc.)
    for (1..5) {
        my $f = h2_read_frame($sock, 0.2);
        last unless $f;
    }

    return ($sock, $settings_payload);
}

# Send Extended CONNECT HEADERS + optional initial data, all in one write
sub h2_send_extended_connect {
    my ($sock, $stream_id, $path, $port, $initial_data) = @_;

    my $headers_block = hpack_encode_headers(
        [':method',    'CONNECT'],
        [':protocol',  'websocket'],
        [':path',      $path],
        [':scheme',    'https'],
        [':authority',  "127.0.0.1:$port"],
    );

    my $out = h2_frame(H2_HEADERS, FLAG_END_HEADERS, $stream_id, $headers_block);
    if (defined $initial_data && length($initial_data) > 0) {
        $out .= h2_frame(H2_DATA, 0, $stream_id, $initial_data);
    }

    $sock->syswrite($out);
}

# ---------------------------------------------------------------------------
# Handler setup
# ---------------------------------------------------------------------------
my @tunnel_requests;
$evh->psgi_request_handler(sub {
    my $env = shift;

    if (($env->{REQUEST_METHOD} || '') eq 'CONNECT') {
        push @tunnel_requests, {
            method   => $env->{REQUEST_METHOD},
            upgrade  => $env->{HTTP_UPGRADE} || '',
            ext_conn => $env->{'psgix.h2.extended_connect'} || 0,
            protocol => $env->{'psgix.h2.protocol'} || '',
            path     => $env->{PATH_INFO} || '',
            proto    => $env->{SERVER_PROTOCOL} || '',
        };

        my $path = $env->{PATH_INFO} || '';

        if ($path eq '/reject') {
            return [403, ['Content-Type' => 'text/plain'], ['Forbidden']];
        }

        if ($path eq '/server-close') {
            # Accept tunnel then close from server side after brief delay
            return sub {
                my $responder = shift;
                my $writer = $responder->([200, ['X-Tunnel' => 'accepted']]);
                my $io = $env->{'psgix.io'};
                unless ($io && ref($io)) {
                    $writer->close();
                    return;
                }
                my $t; $t = AE::timer(0.2, 0, sub {
                    undef $t;
                    close($io);
                });
            };
        }

        # Accept the tunnel via delayed response
        return sub {
            my $responder = shift;
            my $writer = $responder->([200, ['X-Tunnel' => 'accepted']]);

            # Get tunnel socket via psgix.io
            my $io = $env->{'psgix.io'};
            unless ($io && ref($io)) {
                $writer->close();
                return;
            }

            # Set up AnyEvent echo handler: prepend "echo:" only once
            my $first = 1;
            my $handle; $handle = AnyEvent::Handle->new(
                fh       => $io,
                on_error => sub { $_[0]->destroy; undef $handle; },
                on_eof   => sub { $handle->destroy if $handle; undef $handle; },
            );
            $handle->on_read(sub {
                my $data = $handle->{rbuf};
                $handle->{rbuf} = '';
                if ($first) {
                    $handle->push_write("echo:$data");
                    $first = 0;
                } else {
                    $handle->push_write($data);
                }
            });
        };
    }

    # Non-tunnel: normal response
    my $body = "hello";
    return [200, ['Content-Type' => 'text/plain', 'Content-Length' => length($body)], [$body]];
});

# ---------------------------------------------------------------------------
# Test 1: SETTINGS includes ENABLE_CONNECT_PROTOCOL=1
# ---------------------------------------------------------------------------
subtest 'SETTINGS includes ENABLE_CONNECT_PROTOCOL' => sub {
    plan tests => 2;

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my ($sock, $settings_payload) = h2_connect($port);
        unless ($sock && $settings_payload) {
            exit(1);
        }

        my $found = 0;
        my $pos = 0;
        while ($pos + 6 <= length($settings_payload)) {
            my ($id, $val) = unpack('nN', substr($settings_payload, $pos, 6));
            $pos += 6;
            if ($id == SETTINGS_ENABLE_CONNECT_PROTOCOL && $val == 1) {
                $found = 1;
                last;
            }
        }

        $sock->close();
        exit($found ? 0 : 2);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(10 * TIMEOUT_MULT, 0, sub { $cv->send('timeout') });
    my $w = AE::child($pid, sub { $child_status = $_[1] >> 8; $cv->send('done') });
    isnt $cv->recv, 'timeout', "did not timeout";
    is $child_status, 0, "ENABLE_CONNECT_PROTOCOL=1 in server SETTINGS";
};

# ---------------------------------------------------------------------------
# Test 2: Extended CONNECT env + accept (200) + bidirectional echo
# ---------------------------------------------------------------------------
subtest 'Extended CONNECT: env + bidirectional echo' => sub {
    plan tests => 8;

    @tunnel_requests = ();

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my ($sock) = h2_connect($port);
        exit(1) unless $sock;

        # Send Extended CONNECT + initial data in one write
        h2_send_extended_connect($sock, 1, '/tunnel', $port, "hello-tunnel");

        # Read response HEADERS
        my $got_200 = 0;
        my $deadline = time + 5;
        while (time < $deadline) {
            my $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            if ($f->{type} == H2_HEADERS && $f->{stream_id} == 1) {
                my $status = hpack_decode_status($f->{payload});
                $got_200 = 1 if defined $status && $status eq '200';
                last;
            }
        }
        exit(2) unless $got_200;

        # Read echoed data
        my $echoed = '';
        $deadline = time + 5;
        while (time < $deadline) {
            my $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            if ($f->{type} == H2_DATA && $f->{stream_id} == 1) {
                $echoed .= $f->{payload};
                last if $echoed =~ /echo:/;
            }
        }

        # Close our side
        $sock->syswrite(h2_frame(H2_DATA, FLAG_END_STREAM, 1, ''));
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);
        $sock->close();

        exit($echoed eq "echo:hello-tunnel" ? 0 : 3);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(15 * TIMEOUT_MULT, 0, sub { $cv->send('timeout') });
    my $w = AE::child($pid, sub { $child_status = $_[1] >> 8; $cv->send('done') });
    isnt $cv->recv, 'timeout', "echo test did not timeout";
    is $child_status, 0, "bidirectional echo through H2 tunnel";

    cmp_ok scalar(@tunnel_requests), '>=', 1, "handler saw tunnel request";
    if (@tunnel_requests) {
        is $tunnel_requests[0]{method},   'CONNECT',   "REQUEST_METHOD is CONNECT";
        is $tunnel_requests[0]{upgrade},  'websocket', "HTTP_UPGRADE is websocket";
        is $tunnel_requests[0]{ext_conn}, 1,           "psgix.h2.extended_connect is 1";
        is $tunnel_requests[0]{protocol}, 'websocket', "psgix.h2.protocol is websocket";
        is $tunnel_requests[0]{path},     '/tunnel',   "PATH_INFO is /tunnel";
    }
};

# ---------------------------------------------------------------------------
# Test 3: Reject (403) — no socketpair created
# ---------------------------------------------------------------------------
subtest 'Extended CONNECT reject (403)' => sub {
    plan tests => 2;

    @tunnel_requests = ();

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my ($sock) = h2_connect($port);
        exit(1) unless $sock;

        h2_send_extended_connect($sock, 1, '/reject', $port);

        my $got_403 = 0;
        my $f = h2_read_until($sock, H2_HEADERS, 1, 5);
        if ($f) {
            my $status = hpack_decode_status($f->{payload});
            $got_403 = 1 if defined $status && $status eq '403';
        }

        $sock->close();
        exit($got_403 ? 0 : 2);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(10 * TIMEOUT_MULT, 0, sub { $cv->send('timeout') });
    my $w = AE::child($pid, sub { $child_status = $_[1] >> 8; $cv->send('done') });
    isnt $cv->recv, 'timeout', "reject test did not timeout";
    is $child_status, 0, "server sent 403 for rejected tunnel";
};

# ---------------------------------------------------------------------------
# Test 4: Client close via RST_STREAM
# ---------------------------------------------------------------------------
subtest 'Client RST_STREAM closes tunnel' => sub {
    plan tests => 2;

    @tunnel_requests = ();

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my ($sock) = h2_connect($port);
        exit(1) unless $sock;

        h2_send_extended_connect($sock, 1, '/tunnel', $port);

        # Wait for 200
        my $f = h2_read_until($sock, H2_HEADERS, 1, 5);
        exit(2) unless $f;
        my $status = hpack_decode_status($f->{payload});
        exit(2) unless defined $status && $status eq '200';

        # RST_STREAM (CANCEL)
        $sock->syswrite(h2_frame(H2_RST_STREAM, 0, 1, pack('N', 0x08)));
        select(undef, undef, undef, 0.5 * TIMEOUT_MULT);
        $sock->close();
        exit(0);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(10 * TIMEOUT_MULT, 0, sub { $cv->send('timeout') });
    my $w = AE::child($pid, sub { $child_status = $_[1] >> 8; $cv->send('done') });
    isnt $cv->recv, 'timeout', "RST_STREAM test did not timeout";
    is $child_status, 0, "RST_STREAM cleanly closed tunnel";
};

# ---------------------------------------------------------------------------
# Test 5: Regular H2 GET still works (regression)
# ---------------------------------------------------------------------------
my $nghttp_bin = `which nghttp 2>/dev/null`;
chomp $nghttp_bin;

# ---------------------------------------------------------------------------
# Test 5: Concurrent tunnels on one connection
# ---------------------------------------------------------------------------
subtest 'Concurrent tunnels on one H2 connection' => sub {
    plan tests => 2;

    @tunnel_requests = ();

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my ($sock) = h2_connect($port);
        exit(1) unless $sock;

        # Open 2 concurrent tunnel streams (stream IDs 1, 3) with initial
        # data bundled in each HEADERS+DATA pair (one syswrite per stream).
        h2_send_extended_connect($sock, 1, '/tunnel', $port, "msg-1");
        h2_send_extended_connect($sock, 3, '/tunnel', $port, "msg-3");

        # Collect 200 HEADERS and echoed DATA for both streams
        my %got_200;
        my %echoed;
        my $deadline = time + 8;
        while ((keys(%got_200) < 2 || keys(%echoed) < 2) && time < $deadline) {
            my $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            if ($f->{type} == H2_HEADERS && ($f->{stream_id} % 2 == 1)) {
                my $status = hpack_decode_status($f->{payload});
                $got_200{$f->{stream_id}} = 1 if defined $status && $status eq '200';
            }
            if ($f->{type} == H2_DATA && ($f->{stream_id} % 2 == 1) && length($f->{payload}) > 0) {
                $echoed{$f->{stream_id}} //= '';
                $echoed{$f->{stream_id}} .= $f->{payload};
            }
            # Send WINDOW_UPDATE for DATA frames
            if ($f->{type} == H2_DATA && $f->{length} > 0) {
                $sock->syswrite(h2_frame(H2_WINDOW_UPDATE, 0, $f->{stream_id}, pack('N', $f->{length})));
                $sock->syswrite(h2_frame(H2_WINDOW_UPDATE, 0, 0, pack('N', $f->{length})));
            }
        }

        # Close both streams
        $sock->syswrite(h2_frame(H2_DATA, FLAG_END_STREAM, 1, ''));
        $sock->syswrite(h2_frame(H2_DATA, FLAG_END_STREAM, 3, ''));
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);
        $sock->close();

        exit(2) unless keys(%got_200) == 2;

        # Verify each stream got its own echo
        my $ok = ($echoed{1} // '') eq 'echo:msg-1'
              && ($echoed{3} // '') eq 'echo:msg-3';
        exit($ok ? 0 : 3);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(15 * TIMEOUT_MULT, 0, sub { $cv->send('timeout') });
    my $w = AE::child($pid, sub { $child_status = $_[1] >> 8; $cv->send('done') });
    isnt $cv->recv, 'timeout', "concurrent tunnels did not timeout";
    is $child_status, 0, "2 concurrent tunnels echoed independently";
};

# ---------------------------------------------------------------------------
# Test 6: Server-initiated tunnel close
# ---------------------------------------------------------------------------
subtest 'Server-initiated tunnel close' => sub {
    plan tests => 2;

    @tunnel_requests = ();

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my ($sock) = h2_connect($port);
        exit(1) unless $sock;

        h2_send_extended_connect($sock, 1, '/server-close', $port);

        # Wait for 200
        my $f = h2_read_until($sock, H2_HEADERS, 1, 5);
        exit(2) unless $f;
        my $status = hpack_decode_status($f->{payload});
        exit(2) unless defined $status && $status eq '200';

        # Server will close its end after ~0.2s.
        # We should see either END_STREAM on DATA or RST_STREAM.
        my $saw_end = 0;
        my $deadline = time + 5;
        while (time < $deadline) {
            $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            if ($f->{stream_id} == 1) {
                if ($f->{type} == H2_DATA && ($f->{flags} & FLAG_END_STREAM)) {
                    $saw_end = 1;
                    last;
                }
                if ($f->{type} == H2_RST_STREAM) {
                    $saw_end = 1;
                    last;
                }
            }
        }

        $sock->close();
        exit($saw_end ? 0 : 3);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(10 * TIMEOUT_MULT, 0, sub { $cv->send('timeout') });
    my $w = AE::child($pid, sub { $child_status = $_[1] >> 8; $cv->send('done') });
    isnt $cv->recv, 'timeout', "server-close test did not timeout";
    is $child_status, 0, "server-initiated close propagates END_STREAM or RST";
};

# ---------------------------------------------------------------------------
# Test 7: Large data through tunnel
# ---------------------------------------------------------------------------
subtest 'Large data through tunnel' => sub {
    plan tests => 2;

    @tunnel_requests = ();

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

        my ($sock) = h2_connect($port);
        exit(1) unless $sock;

        # Send a larger payload through the tunnel.
        # Use 8KB (well within max frame size and flow control window).
        my $payload = 'B' x 8192;
        h2_send_extended_connect($sock, 1, '/tunnel', $port, $payload);

        # Read response HEADERS (200)
        my $got_200 = 0;
        my $echoed = '';
        my $expected = "echo:" . $payload;
        my $deadline = time + 8;
        while (length($echoed) < length($expected) && time < $deadline) {
            my $f = h2_read_frame($sock, $deadline - time);
            last unless $f;
            if ($f->{type} == H2_HEADERS && $f->{stream_id} == 1) {
                my $status = hpack_decode_status($f->{payload});
                $got_200 = 1 if defined $status && $status eq '200';
            }
            if ($f->{type} == H2_DATA && $f->{stream_id} == 1) {
                $echoed .= $f->{payload};
            }
            if ($f->{type} == H2_GOAWAY || $f->{type} == H2_RST_STREAM) {
                last;
            }
            # Send WINDOW_UPDATE for DATA frames
            if ($f->{type} == H2_DATA && length($f->{payload}) > 0) {
                my $wulen = length($f->{payload});
                $sock->syswrite(h2_frame(H2_WINDOW_UPDATE, 0, $f->{stream_id}, pack('N', $wulen)));
                $sock->syswrite(h2_frame(H2_WINDOW_UPDATE, 0, 0, pack('N', $wulen)));
            }
        }

        # Close stream
        $sock->syswrite(h2_frame(H2_DATA, FLAG_END_STREAM, 1, ''));
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);
        $sock->close();

        exit(2) unless $got_200;
        exit($echoed eq $expected ? 0 : 3);
    }

    my $cv = AE::cv;
    my $child_status;
    my $t = AE::timer(15 * TIMEOUT_MULT, 0, sub { $cv->send('timeout') });
    my $w = AE::child($pid, sub { $child_status = $_[1] >> 8; $cv->send('done') });
    isnt $cv->recv, 'timeout', "large data test did not timeout";
    is $child_status, 0, "8KB echoed correctly through H2 tunnel";
};

# ---------------------------------------------------------------------------
# Test 8: Regular H2 GET still works (regression)
# ---------------------------------------------------------------------------
SKIP: {
    skip "nghttp not found in PATH", 1 unless $nghttp_bin && -x $nghttp_bin;

    subtest 'Regular H2 GET still works' => sub {
        plan tests => 2;

        my $pid = fork();
        die "fork: $!" unless defined $pid;

        if ($pid == 0) {
            select(undef, undef, undef, 0.3 * TIMEOUT_MULT);
            my $url = "https://127.0.0.1:$port/hello";
            my $output = `$nghttp_bin --no-verify $url 2>&1`;
            exit($output =~ /hello/ ? 0 : 1);
        }

        my $cv = AE::cv;
        my $child_status;
        my $t = AE::timer(15 * TIMEOUT_MULT, 0, sub { $cv->send('timeout') });
        my $w = AE::child($pid, sub { $child_status = $_[1] >> 8; $cv->send('done') });
        isnt $cv->recv, 'timeout', "regression test did not timeout";
        is $child_status, 0, "regular H2 GET still works after adding tunnel support";
    };
}

done_testing;
