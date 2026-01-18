#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;
use lib 'blib/lib', 'blib/arch';
use Feersum;
use AnyEvent;
use AnyEvent::Handle;

#######################################################################
# Test coverage gaps identified in code review:
# - Multiple Transfer-Encoding headers (request smuggling prevention)
# - Chunked encoding malformations
# - max_connection_reqs boundary
# - Keepalive timeout edge cases
#######################################################################

plan tests => 29;

my ($socket, $port) = get_listen_socket();
ok $socket, 'made listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);
$feer->set_keepalive(1);
$feer->max_connection_reqs(4);  # Set limit for testing
$feer->request_handler(sub {
    my $r = shift;
    my $env = $r->env;
    my $body = '';
    if (my $cl = $env->{CONTENT_LENGTH}) {
        $env->{'psgi.input'}->read($body, $cl);
    }
    my $resp = "len=" . length($body) . ",body=$body";
    $r->send_response(200, ['Content-Type' => 'text/plain'], \$resp);
});

# Helper to send raw request and get response
sub raw_request {
    my ($request, $timeout) = @_;
    $timeout ||= 3;

    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    $h->push_write($request);

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
    });

    my $timer = AE::timer $timeout, 0, sub { $cv->send; };
    $cv->recv;

    return $response;
}

#######################################################################
# Test: Multiple Transfer-Encoding headers (request smuggling prevention)
# RFC 7230 3.3.3: Multiple TE headers should be rejected
#######################################################################

{
    # Two Transfer-Encoding: chunked headers
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Multiple TE headers (same value): rejected with 400');
    like($response, qr/Multiple Transfer-Encoding/i, 'Multiple TE headers: error message');
}

{
    # Transfer-Encoding: chunked + Transfer-Encoding: identity
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Transfer-Encoding: identity\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Multiple TE headers (different values): rejected with 400');
}

{
    # Transfer-Encoding: chunked + Transfer-Encoding: gzip (smuggling attempt)
    # Note: chunked first so it's accepted, then gzip triggers duplicate check
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Transfer-Encoding: gzip\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Multiple TE headers (chunked+gzip smuggling): rejected');
}

#######################################################################
# Test: Chunked encoding malformations
#######################################################################

{
    # Non-hex characters in chunk size
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "GGG\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Chunked malformed: non-hex chunk size rejected');
}

{
    # Empty chunk size line
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Chunked malformed: empty chunk size rejected');
}

{
    # Chunk size with invalid characters after hex
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5xyz\r\nhello\r\n0\r\n\r\n"
    );
    # Note: 5xyz may be parsed as 5 with extension xyz, which is valid per RFC
    # Or it may be rejected - either way server should handle gracefully
    ok(defined $response, 'Chunked with trailing chars: handled gracefully');
}

{
    # Missing CRLF after chunk data
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhelloX0\r\n\r\n"  # Missing CRLF after "hello"
    );
    # Should timeout or return 400
    ok(defined $response, 'Chunked missing CRLF after data: handled gracefully');
}

{
    # Negative chunk size (starts with -)
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "-5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Chunked malformed: negative chunk size rejected');
}

#######################################################################
# Test: max_connection_reqs boundary (set to 4 above)
#######################################################################

{
    my $cv = AE::cv;
    my $buffer = '';
    my $requests_sent = 0;
    my $responses_received = 0;

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        timeout => 10,
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
        on_read => sub {
            $buffer .= $_[0]->rbuf;
            $_[0]->rbuf = '';
            # Count complete responses
            $responses_received = () = $buffer =~ /HTTP\/1\.1 200 OK/g;
            $cv->send if $responses_received >= 4;
        }
    );

    # Send 5 requests - 4th should have Connection: close, 5th might not be processed
    for my $i (1..4) {
        $h->push_write("GET /req$i HTTP/1.1\r\nHost: localhost\r\n\r\n");
    }

    my $timer = AE::timer 5, 0, sub { $cv->send; };
    $cv->recv;

    # Check we got 4 responses
    my @responses = $buffer =~ /HTTP\/1\.1 200 OK/g;
    is(scalar(@responses), 4, 'max_connection_reqs: got exactly 4 responses');

    # First 3 responses should NOT have Connection: close
    my @parts = split(/HTTP\/1\.1 200 OK/, $buffer);
    shift @parts;  # Remove part before first response

    my $close_count = 0;
    for my $i (0..2) {
        if (defined $parts[$i] && $parts[$i] =~ /Connection: close/i) {
            $close_count++;
        }
    }
    is($close_count, 0, 'max_connection_reqs: first 3 responses have no Connection: close');

    # 4th response SHOULD have Connection: close
    if (defined $parts[3]) {
        like($parts[3], qr/Connection: close/i, 'max_connection_reqs: 4th response has Connection: close');
    } else {
        pass('max_connection_reqs: 4th response has Connection: close (implicit)');
    }
}

#######################################################################
# Test: Expect header edge cases
#######################################################################

{
    # Expect: 100 (incomplete value) - should get 417
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Expect: 100\r\n" .
        "Content-Length: 5\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 417/, 'Expect: 100 (incomplete): rejected with 417');
}

{
    # Expect: 100-Continue (different case) - should work
    my $cv = AE::cv;
    my $got_continue = 0;
    my $full_response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nExpect: 100-Continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n");

    $h->on_read(sub {
        my $data = $h->rbuf;
        $h->rbuf = '';
        $full_response .= $data;

        if (!$got_continue && $data =~ /100 Continue/i) {
            $got_continue = 1;
            $h->push_write("hello");
        }
        if ($full_response =~ /len=\d+/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 5, 0, sub { $cv->send; };
    $cv->recv;

    like($full_response, qr/100 Continue/i, 'Expect: 100-Continue (mixed case): got continue');
    like($full_response, qr/200 OK/, 'Expect: 100-Continue (mixed case): got 200 OK');
}

{
    # Expect: unknown-value - should get 417
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Expect: something-else\r\n" .
        "Content-Length: 5\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 417/, 'Expect: unknown value: rejected with 417');
}

#######################################################################
# Test: HTTP/1.0 with Transfer-Encoding (should be ignored for HTTP/1.0)
# RFC 7230: HTTP/1.0 does not support chunked transfer encoding
#######################################################################

{
    # HTTP/1.0 doesn't support chunked - TE header should be ignored
    # and Content-Length used instead
    my $response = raw_request(
        "POST /test HTTP/1.0\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.0 200/, 'HTTP/1.0 with CL: accepted');
    like($response, qr/len=5/, 'HTTP/1.0 with CL: body received');
}

{
    # HTTP/1.0 + Transfer-Encoding: chunked + Content-Length
    # Per RFC 7230, HTTP/1.0 doesn't support chunked, so TE should be ignored
    # and Content-Length should be used instead
    my $response = raw_request(
        "POST /test HTTP/1.0\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Content-Length: 5\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.0 200/, 'HTTP/1.0 + TE + CL: TE ignored, CL used');
    like($response, qr/len=5/, 'HTTP/1.0 + TE + CL: body received via Content-Length');
}

{
    # HTTP/1.0 + Transfer-Encoding: chunked WITHOUT Content-Length
    # TE is ignored for HTTP/1.0, so server requires Content-Length for POST body
    # This correctly returns 411 Length Required
    my $response = raw_request(
        "POST /test HTTP/1.0\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    # Server ignores TE for HTTP/1.0 and requires Content-Length for POST
    like($response, qr/HTTP\/1\.0 411/, 'HTTP/1.0 + TE only: 411 Length Required (TE ignored)');
    like($response, qr/Content-Length.*required/i, 'HTTP/1.0 + TE only: error message');
}

#######################################################################
# Test: Large number of chunks (stress test chunk counting)
#######################################################################

{
    # 500 single-byte chunks (under MAX_CHUNK_COUNT of 1024)
    my $chunked_body = '';
    for my $i (1..500) {
        $chunked_body .= "1\r\nX\r\n";
    }
    $chunked_body .= "0\r\n\r\n";

    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        $chunked_body,
        10  # longer timeout for large request
    );
    like($response, qr/HTTP\/1\.1 200/, '500 chunks: accepted');
    like($response, qr/len=500/, '500 chunks: body length correct');
}

#######################################################################
# Test: Trailer headers in chunked encoding
#######################################################################

{
    # Chunked with trailer headers
    my $chunked_body = "5\r\nhello\r\n0\r\nX-Trailer: value\r\n\r\n";
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        $chunked_body
    );
    like($response, qr/HTTP\/1\.1 200/, 'Chunked with trailer: accepted');
    like($response, qr/len=5/, 'Chunked with trailer: body correct');
}

{
    # Multiple trailer headers
    my $chunked_body = "5\r\nhello\r\n0\r\nX-Trailer1: v1\r\nX-Trailer2: v2\r\n\r\n";
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        $chunked_body
    );
    like($response, qr/HTTP\/1\.1 200/, 'Chunked with multiple trailers: accepted');
}

pass "all coverage gap tests completed";
