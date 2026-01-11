#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 14;
use lib 't'; use Utils;
use lib 'blib/lib', 'blib/arch';
use Feersum;
use AnyEvent;
use AnyEvent::Handle;

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
    my $resp = "len=" . length($body) . ",body=$body";
    $r->send_response(200, ['Content-Type' => 'text/plain'], \$resp);
});

# Test 1: Simple chunked request - one chunk
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Chunked body: "hello" = 5 bytes
    my $chunked_body = "5\r\nhello\r\n0\r\n\r\n";
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n$chunked_body");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /body=/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/200 OK/, 'Got 200 OK response');
    like($response, qr/len=5/, 'Content length is 5');
    like($response, qr/body=hello/, 'Body is "hello"');
}

# Test 2: Multiple chunks
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Chunked body: "hello" + " world" = 11 bytes total
    my $chunked_body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n$chunked_body");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /body=/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/len=11/, 'Content length is 11');
    like($response, qr/body=hello world/, 'Body is "hello world"');
}

# Test 3: Hex chunk sizes (uppercase)
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Chunk with hex size A (10 bytes)
    my $chunked_body = "A\r\n0123456789\r\n0\r\n\r\n";
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n$chunked_body");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /body=/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/len=10/, 'Content length is 10 (hex A)');
    like($response, qr/body=0123456789/, 'Body is "0123456789"');
}

# Test 4: Empty chunked body
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Empty chunked body - just the terminator
    my $chunked_body = "0\r\n\r\n";
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n$chunked_body");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /len=/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/len=0/, 'Empty chunked body has length 0');
}

# Test 5: Malformed chunked encoding (invalid hex) should return 400
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Invalid hex in chunk size
    my $chunked_body = "XYZ\r\nhello\r\n0\r\n\r\n";
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n$chunked_body");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /HTTP\/1\.\d \d{3}/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/400 Bad Request/, 'Malformed chunked encoding returns 400');
}

# Test 6: Lowercase hex chunk sizes
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Chunk with lowercase hex size 'a' (10 bytes)
    my $chunked_body = "a\r\n0123456789\r\n0\r\n\r\n";
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n$chunked_body");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /body=/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/len=10/, 'Lowercase hex (a=10) works');
    like($response, qr/body=0123456789/, 'Body with lowercase hex is correct');
}

# Test 7: Chunked with trailer headers (should be skipped)
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Chunked body with trailer headers
    my $chunked_body = "5\r\nhello\r\n0\r\nX-Trailer: value\r\n\r\n";
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n$chunked_body");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /body=/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/len=5/, 'Chunked with trailer works');
    like($response, qr/body=hello/, 'Body with trailer is correct');
}
