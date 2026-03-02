#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;
use Feersum;
use AnyEvent;
use AnyEvent::Handle;

# HTTP Request Smuggling Prevention Tests (RFC 7230 Section 3.3.3)

BEGIN {
    plan skip_all => 'not applicable on win32'
        if $^O eq 'MSWin32';
}

plan tests => 28;

my ($socket, $port) = get_listen_socket();
ok $socket, 'made listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);

my @requests_received;
$feer->request_handler(sub {
    my $r = shift;
    my $env = $r->env;
    my $body = '';
    if (my $cl = $env->{CONTENT_LENGTH}) {
        $env->{'psgi.input'}->read($body, $cl);
    }
    push @requests_received, {
        method => $env->{REQUEST_METHOD},
        path   => $env->{PATH_INFO},
        body   => $body,
    };
    $r->send_response(200, ['Content-Type' => 'text/plain'], \"OK: $body");
});

sub raw_request {
    my ($request, $timeout) = @_;
    $timeout ||= 3;
    @requests_received = ();

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

# CL.TE Attack Prevention

{
    note "Testing CL.TE attack prevention";

    my $response = raw_request(
        "POST /legitimate HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'CL.TE: rejected with 400');
    is(scalar(@requests_received), 0, 'CL.TE: no requests processed');
}

{
    my $response = raw_request(
        "POST /api/data HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 4\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5c\r\n" .
        "GPOST /admin/delete HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 10\r\n\r\n" .
        "x]]]]]" .
        "\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'CL.TE smuggled admin request: rejected');
    is(scalar(@requests_received), 0, 'CL.TE smuggled admin: no requests processed');
}

# TE.CL Attack Prevention

{
    note "Testing TE.CL attack prevention";

    my $response = raw_request(
        "POST /legitimate HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Content-Length: 100\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n" .
        "GET /smuggled HTTP/1.1\r\n" .
        "Host: localhost\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'TE.CL: rejected with 400');
    is(scalar(@requests_received), 0, 'TE.CL: no requests processed');
}

{
    my $response = raw_request(
        "POST /api HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Content-Length: 0\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'TE.CL with CL=0: rejected');
}

# Header Obfuscation Attempts

{
    note "Testing header obfuscation attempts";

    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "content-length: 5\r\n" .
        "TRANSFER-ENCODING: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "0\r\n\r\nGET /x HTTP/1.1\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Mixed case CL+TE: rejected');
}

{
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "CoNtEnT-LeNgTh: 5\r\n" .
        "TrAnSfEr-EnCoDiNg: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 400/, 'Weird case CL+TE: rejected');
}

{
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Transfer-Encoding:  chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 400/, 'TE with leading space + CL: rejected');
}

{
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Transfer-Encoding:\tchunked\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 400/, 'TE with tab + CL: rejected');
}

# TE Value Variations

{
    note "Testing Transfer-Encoding value variations";

    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Transfer-Encoding: chunked;ext=val\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 400/, 'TE: chunked;ext + CL: rejected');
}

{
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Transfer-Encoding: gzip, chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 (400|501)/, 'TE: gzip,chunked + CL: rejected (400 or 501)');
}

# Multiple Transfer-Encoding Headers (TE.TE)

{
    note "Testing TE.TE attack prevention";

    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'TE.TE identical: rejected');
    like($response, qr/Multiple Transfer-Encoding/i, 'TE.TE: error message');
}

{
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Transfer-Encoding: identity\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'TE.TE chunked+identity: rejected');
}

{
    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: identity\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 400/, 'TE.TE identity+chunked: rejected');
}

# Verify normal requests still work

{
    note "Verifying normal requests work correctly";

    my $response = raw_request(
        "POST /normal HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        "5\r\nhello\r\n0\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Normal chunked: accepted');
    like($response, qr/OK: hello/, 'Normal chunked: body correct');
    is(scalar(@requests_received), 1, 'Normal chunked: exactly 1 request');
}

{
    my $response = raw_request(
        "POST /normal HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Length: 5\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 200/, 'Normal CL: accepted');
    like($response, qr/OK: hello/, 'Normal CL: body correct');
    is(scalar(@requests_received), 1, 'Normal CL: exactly 1 request');
}

{
    my $response = raw_request(
        "GET /simple HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Connection: close\r\n\r\n"
    );
    like($response, qr/HTTP\/1\.1 200/, 'GET no body: accepted');
    is(scalar(@requests_received), 1, 'GET: exactly 1 request');
}

# Edge case: TE: identity alone

{
    note "Testing TE: identity edge cases";

    my $response = raw_request(
        "POST /test HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: identity\r\n" .
        "Content-Length: 5\r\n" .
        "Connection: close\r\n\r\n" .
        "hello"
    );
    like($response, qr/HTTP\/1\.1 200/, 'TE: identity + CL: accepted (identity deprecated)');
}

pass "All request smuggling prevention tests completed";
