#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use lib 't';
use Utils;
use Feersum;
use AnyEvent;
use AnyEvent::Handle;

# Test MAX_BODY_LEN default and runtime override

my ($socket, $port) = get_listen_socket();
ok $socket, 'got listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);

my $request_handled = 0;
$feer->request_handler(sub {
    my $r = shift;
    $request_handled++;
    $r->send_response(200, ['Content-Type' => 'text/plain'], ['OK']);
});

# Helper to send request and get response status
sub get_status {
    my ($headers, $body) = @_;
    my $cv = AE::cv;
    my $response = '';
    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );
    $h->push_write($headers . ($body || ''));
    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
    });
    my $timer = AE::timer 5, 0, sub { $cv->send; };
    $cv->recv;
    if ($response =~ /HTTP\/1\.[01] (\d+)/) {
        return $1;
    }
    return '000';
}

# 1. Test default limit (64MB)
# We won't actually send 64MB in a unit test, but we can check Content-Length
# header rejection which happens early.
{
    $request_handled = 0;
    # 64MB + 1 byte
    my $too_big = 64 * 1024 * 1024 + 1;
    my $status = get_status("POST / HTTP/1.1
Host: localhost
Content-Length: $too_big
Connection: close

");
    is $status, '413', '64MB + 1 byte rejected with 413 (default limit)';
    is $request_handled, 0, 'request handler not called for oversized request';

    $request_handled = 0;
    # Exactly 64MB (should be accepted, but we won't send the full body to keep test fast)
    # Actually, Feersum waits for the body before calling the handler.
    # If we don't send the body, it will timeout.
    # But 413 should be sent IMMEDIATELY upon seeing the header if it's too large.
}

# 2. Test runtime override
{
    $feer->max_body_len(1024); # 1KB limit
    $request_handled = 0;
    my $status = get_status("POST / HTTP/1.1
Host: localhost
Content-Length: 2048
Connection: close

");
    is $status, '413', '2KB rejected with 413 (override to 1KB)';
    is $request_handled, 0, 'request handler not called';

    # Under the new limit
    $request_handled = 0;
    my $body = "x" x 512;
    $status = get_status("POST / HTTP/1.1
Host: localhost
Content-Length: 512
Connection: close

", $body);
    is $status, '200', '512 bytes accepted (under 1KB limit)';
    is $request_handled, 1, 'request handler called';
}

# 3. Test reset to default (0)
{
    $feer->max_body_len(0);
    $request_handled = 0;
    my $too_big = 64 * 1024 * 1024 + 1;
    my $status = get_status("POST / HTTP/1.1
Host: localhost
Content-Length: $too_big
Connection: close

");
    is $status, '413', '64MB + 1 byte rejected after reset to default';
}

done_testing;
