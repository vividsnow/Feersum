#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 6;
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
    my $resp = "len=" . length($body);
    $r->send_response(200, ['Content-Type' => 'text/plain'], \$resp);
});

# Test 1: POST with Expect: 100-continue
{
    my $cv = AE::cv;
    my $got_continue = 0;
    my $full_response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Send headers with Expect: 100-continue
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n");

    $h->on_read(sub {
        my $data = $h->rbuf;
        $h->rbuf = '';
        $full_response .= $data;

        if (!$got_continue && $data =~ /100 Continue/) {
            $got_continue = 1;
            # Send body after receiving 100 Continue
            $h->push_write("0123456789");
        }
        if ($full_response =~ /len=\d+/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 5, 0, sub { $cv->send; };
    $cv->recv;

    like($full_response, qr/100 Continue/i, 'Got 100 Continue response');
    like($full_response, qr/200 OK/, 'Got 200 OK final response');
    like($full_response, qr/len=10/, 'Body was received correctly (10 bytes)');
}

# Test 2: Normal POST without Expect header (sanity check)
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /len=\d+/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/len=5/, 'Normal POST without Expect works');
}

# Test 3: Unknown Expect value should get 417
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Send an unknown Expect value
    $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nExpect: something-weird\r\nConnection: close\r\n\r\nhello");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
        if ($response =~ /HTTP\/1\.\d \d{3}/) {
            $cv->send;
        }
    });

    my $timer = AE::timer 3, 0, sub { $cv->send; };
    $cv->recv;

    like($response, qr/417 Expectation Failed/, 'Unknown Expect value gets 417');
}
