#!/usr/bin/env perl
use strict;
# TIMEOUT_MULT allows scaling all timing values for slow machines (default: 1)
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || 1;
use warnings;
use Test::More tests => 11;
use lib 't'; use Utils;
use Feersum;
use AnyEvent;
use AnyEvent::Handle;

#######################################################################
# PART 1: Native Feersum interface tests
#######################################################################

{
    my ($socket, $port) = get_listen_socket();
    ok $socket, 'native: made listen socket';

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

        $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n");

        $h->on_read(sub {
            my $data = $h->rbuf;
            $h->rbuf = '';
            $full_response .= $data;

            if (!$got_continue && $data =~ /100 Continue/) {
                $got_continue = 1;
                $h->push_write("0123456789");
            }
            if ($full_response =~ /len=\d+/) {
                $cv->send;
            }
        });

        my $timer = AE::timer 2 * TIMEOUT_MULT, 0, sub { $cv->send; };
        $cv->recv;

        like($full_response, qr/100 Continue/i, 'native: Got 100 Continue response');
        like($full_response, qr/200 OK/, 'native: Got 200 OK final response');
        like($full_response, qr/len=10/, 'native: Body was received correctly (10 bytes)');
    }

    # Test 2: Unknown Expect value should get 417
    {
        my $cv = AE::cv;
        my $response = '';

        my $h = AnyEvent::Handle->new(
            connect => ['localhost', $port],
            on_error => sub { $cv->send; },
            on_eof => sub { $cv->send; },
        );

        $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nExpect: something-weird\r\nConnection: close\r\n\r\nhello");

        $h->on_read(sub {
            $response .= $h->rbuf;
            $h->rbuf = '';
            if ($response =~ /HTTP\/1\.\d \d{3}/) {
                $cv->send;
            }
        });

        my $timer = AE::timer 2 * TIMEOUT_MULT, 0, sub { $cv->send; };
        $cv->recv;

        like($response, qr/417 Expectation Failed/, 'native: Unknown Expect value gets 417');
    }
}

#######################################################################
# PART 2: PSGI interface tests
#######################################################################

{
    my ($socket, $port) = get_listen_socket();
    ok $socket, 'psgi: made listen socket';

    my $feer = Feersum->new();
    $feer->use_socket($socket);

    my $app = sub {
        my $env = shift;
        my $body = '';
        if (my $cl = $env->{CONTENT_LENGTH}) {
            $env->{'psgi.input'}->read($body, $cl);
        }
        my $resp = "len=" . length($body);
        return [200, ['Content-Type' => 'text/plain'], [$resp]];
    };

    $feer->psgi_request_handler($app);

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

        $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n");

        $h->on_read(sub {
            my $data = $h->rbuf;
            $h->rbuf = '';
            $full_response .= $data;

            if (!$got_continue && $data =~ /100 Continue/) {
                $got_continue = 1;
                $h->push_write("0123456789");
            }
            if ($full_response =~ /len=\d+/) {
                $cv->send;
            }
        });

        my $timer = AE::timer 2 * TIMEOUT_MULT, 0, sub { $cv->send; };
        $cv->recv;

        like($full_response, qr/100 Continue/i, 'psgi: Got 100 Continue response');
        like($full_response, qr/200 OK/, 'psgi: Got 200 OK final response');
        like($full_response, qr/len=10/, 'psgi: Body was received correctly (10 bytes)');
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

        my $timer = AE::timer 2 * TIMEOUT_MULT, 0, sub { $cv->send; };
        $cv->recv;

        like($response, qr/len=5/, 'psgi: Normal POST without Expect works');
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

        $h->push_write("POST /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nExpect: something-weird\r\nConnection: close\r\n\r\nhello");

        $h->on_read(sub {
            $response .= $h->rbuf;
            $h->rbuf = '';
            if ($response =~ /HTTP\/1\.\d \d{3}/) {
                $cv->send;
            }
        });

        my $timer = AE::timer 2 * TIMEOUT_MULT, 0, sub { $cv->send; };
        $cv->recv;

        like($response, qr/417 Expectation Failed/, 'psgi: Unknown Expect value gets 417');
    }
}
