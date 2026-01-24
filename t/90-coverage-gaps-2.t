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
# Additional coverage gaps identified in 6th code review:
# - Transfer-Encoding header edge cases (case, whitespace)
# - Max connections boundary conditions
# - URI length boundaries
# - Chunked encoding boundary cases
#######################################################################

BEGIN {
    plan skip_all => 'not applicable on win32'
        if $^O eq 'MSWin32';
}

plan tests => 25;

my ($socket, $port) = get_listen_socket();
ok $socket, 'made listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);
$feer->set_keepalive(1);
$feer->request_handler(sub {
    my $r = shift;
    my $env = $r->env;
    my $body = '';
    if (my $cl = $env->{CONTENT_LENGTH}) {
        $env->{'psgi.input'}->read($body, $cl);
    }
    my $uri = $env->{REQUEST_URI} || '/';
    my $resp = "uri_len=" . length($uri) . ",body_len=" . length($body);
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
# Test: Transfer-Encoding case variations
# RFC 7230: Header field names are case-insensitive
#######################################################################

{
    # Transfer-Encoding with different case - should work
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "transfer-encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'TE lowercase: accepted');
    like($response, qr/body_len=5/, 'TE lowercase: body correct');
}

{
    # TRANSFER-ENCODING uppercase
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "TRANSFER-ENCODING: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'TE uppercase: accepted');
    like($response, qr/body_len=5/, 'TE uppercase: body correct');
}

{
    # Mixed case value: CHUNKED
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: CHUNKED\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'TE value CHUNKED: accepted');
    like($response, qr/body_len=5/, 'TE value CHUNKED: body correct');
}

#######################################################################
# Test: Chunked hex digit case variations
# RFC 7230: Chunk size is case-insensitive hex
#######################################################################

{
    # Lowercase hex in chunk size
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "a\r\n0123456789\r\n0\r\n\r\n"  # a = 10
    );
    like($response, qr/HTTP\/1\.1 200/, 'Chunk size lowercase hex: accepted');
    like($response, qr/body_len=10/, 'Chunk size lowercase hex: correct length');
}

{
    # Uppercase hex in chunk size
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "A\r\n0123456789\r\n0\r\n\r\n"  # A = 10
    );
    like($response, qr/HTTP\/1\.1 200/, 'Chunk size uppercase hex: accepted');
    like($response, qr/body_len=10/, 'Chunk size uppercase hex: correct length');
}

{
    # Mixed case hex: aAbBcC = 11189196
    # Too large, let's use smaller: 1F = 31
    my $body = 'x' x 31;
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "1F\r\n${body}\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Chunk size mixed hex 1F: accepted');
    like($response, qr/body_len=31/, 'Chunk size mixed hex 1F: correct length');
}

#######################################################################
# Test: Chunk extension handling
# RFC 7230: chunk-ext = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
#######################################################################

{
    # Chunk with extension (should be ignored)
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5;ext=value\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Chunk with extension: accepted');
    like($response, qr/body_len=5/, 'Chunk with extension: body correct');
}

{
    # Chunk with multiple extensions
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5;foo=bar;baz\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Chunk with multiple extensions: accepted');
    like($response, qr/body_len=5/, 'Chunk with multiple extensions: body correct');
}

#######################################################################
# Test: URI length boundaries
# MAX_URI_LEN is 8192 bytes
#######################################################################

{
    # URI just under limit (8000 bytes to be safe)
    my $long_path = '/test/' . ('x' x 7990);
    my $response = raw_request(
        "GET $long_path HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Connection: close\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Long URI (8000 bytes): accepted');
}

{
    # URI over limit (8500 bytes)
    my $too_long_path = '/test/' . ('x' x 8500);
    my $response = raw_request(
        "GET $too_long_path HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Connection: close\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 414/, 'Too long URI (8500 bytes): rejected with 414');
}

#######################################################################
# Test: Content-Length boundary (duplicate identical values)
# RFC 7230 allows duplicate CL with same value
#######################################################################

{
    # Duplicate Content-Length with same value - should be accepted
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Content-Length: 5\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Duplicate identical CL: accepted');
    like($response, qr/body_len=5/, 'Duplicate identical CL: body correct');
}

{
    # Duplicate Content-Length with different values - should be rejected
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Content-Length: 10\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Duplicate conflicting CL: rejected with 400');
}

#######################################################################
# Test: Transfer-Encoding: identity (should be ignored per RFC)
#######################################################################

{
    # TE: identity should be ignored, require Content-Length
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: identity\r\n" .
        "Content-Length: 5\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 200/, 'TE: identity with CL: accepted');
    like($response, qr/body_len=5/, 'TE: identity with CL: body correct');
}

pass "all additional coverage gap tests completed";
