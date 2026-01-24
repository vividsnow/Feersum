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
# Test chunked encoding limits:
# - MAX_TRAILER_HEADERS (64) boundary
# - Large number of chunks (approaching MAX_CHUNK_COUNT)
# These are high-confidence coverage gaps from 7th review
#######################################################################

BEGIN {
    plan skip_all => 'not applicable on win32'
        if $^O eq 'MSWin32';
}

plan tests => 11;

my ($socket, $port) = get_listen_socket();
ok $socket, 'made listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);
$feer->request_handler(sub {
    my $r = shift;
    my $env = $r->env;
    my $body = '';
    if (my $cl = $env->{CONTENT_LENGTH}) {
        $env->{'psgi.input'}->read($body, $cl);
    }
    my $resp = "len=" . length($body);
    $r->send_response(200, ['Content-Type' => 'text/plain'], \$resp);
});

# Helper to send raw request and get response
sub raw_request {
    my ($request, $timeout) = @_;
    $timeout ||= 5;

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
# Test: MAX_TRAILER_HEADERS boundary (64)
#######################################################################

{
    # Exactly 64 trailer headers - should be accepted
    my $trailers = '';
    for my $i (1..64) {
        $trailers .= "X-Trailer-$i: value$i\r\n";
    }
    my $chunked_body = "5\r\nhello\r\n0\r\n${trailers}\r\n";

    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        $chunked_body,
        10
    );
    like($response, qr/HTTP\/1\.1 200/, 'Exactly 64 trailer headers: accepted');
    like($response, qr/len=5/, 'Exactly 64 trailer headers: body correct');
}

{
    # 65 trailer headers - should be rejected (exceeds MAX_TRAILER_HEADERS)
    my $trailers = '';
    for my $i (1..65) {
        $trailers .= "X-Trailer-$i: value$i\r\n";
    }
    my $chunked_body = "5\r\nhello\r\n0\r\n${trailers}\r\n";

    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        $chunked_body,
        10
    );
    like($response, qr/HTTP\/1\.1 400/, '65 trailer headers: rejected with 400');
}

#######################################################################
# Test: Large number of small chunks (stress test chunk counting)
# MAX_CHUNK_COUNT is 100000, so we test below that threshold
#######################################################################

{
    # 1000 single-byte chunks - well under MAX_CHUNK_COUNT
    my $chunked_body = '';
    for my $i (1..1000) {
        $chunked_body .= "1\r\nX\r\n";
    }
    $chunked_body .= "0\r\n\r\n";

    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        $chunked_body,
        15
    );
    like($response, qr/HTTP\/1\.1 200/, '1000 chunks: accepted');
    like($response, qr/len=1000/, '1000 chunks: body length correct');
}

#######################################################################
# Test: Chunk with very long extension (should be handled)
#######################################################################

{
    # Chunk size with long extension
    my $ext = 'x' x 200;
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5;ext=$ext\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Chunk with long extension: accepted');
    like($response, qr/len=5/, 'Chunk with long extension: body correct');
}

#######################################################################
# Test: Zero-size chunk followed by trailers
#######################################################################

{
    # Zero-size body with trailers
    my $trailers = "X-Final: done\r\n";
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "0\r\n${trailers}\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Zero-size body with trailer: accepted');
    like($response, qr/len=0/, 'Zero-size body with trailer: empty body');
}

pass "all chunked limits tests completed";
