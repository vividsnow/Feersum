#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 12;
use lib 't'; use Utils;

BEGIN { use_ok('Feersum') };

#######################################################################
# Test coverage gaps identified in code review
# Note: Double io() call is already tested in t/78-native-io.t
#######################################################################

my ($socket, $port) = get_listen_socket();
ok $socket, 'got listen socket';

#######################################################################
# Test 1: accept_on_fd() direct test (85% importance)
# This tests the accept_on_fd() method which is used internally
# but was not directly tested.
#######################################################################
{
    my $feer = Feersum->new();

    # Get the file descriptor from the socket
    my $fd = fileno($socket);
    ok defined($fd), "socket has fileno: $fd";

    # Use accept_on_fd instead of use_socket
    eval { $feer->accept_on_fd($fd) };
    ok !$@, 'accept_on_fd() succeeded' or diag $@;

    # Set up handler
    $feer->request_handler(sub {
        my $r = shift;
        $r->send_response(200, ['Content-Type' => 'text/plain'], 'accept_on_fd works');
    });

    # Make a request to verify it works
    my $cv = AE::cv;
    my $response_ok = 0;
    my $body = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send },
        on_connect => sub {
            $_[0]->push_write("GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            $_[0]->push_read(line => "\r\n", sub {
                $response_ok = 1 if $_[1] =~ /200 OK/;
                $_[0]->on_read(sub {
                    $body .= $_[0]->rbuf;
                    $_[0]->rbuf = '';
                });
                $_[0]->on_eof(sub { $cv->send });
            });
        },
    );

    my $timeout = AE::timer 2, 0, sub { $cv->send };
    $cv->recv;

    ok $response_ok, 'accept_on_fd: server responds with 200';
    like $body, qr/accept_on_fd works/, 'accept_on_fd: correct body';

    $feer->unlisten();
}

#######################################################################
# Test 2: Graceful shutdown with pipelined requests (76% importance)
# Tests that graceful_shutdown handles in-flight pipelined requests.
#######################################################################
{
    my ($socket2, $port2) = get_listen_socket();
    ok $socket2, 'got second listen socket';

    my $feer = Feersum->new();
    $feer->use_socket($socket2);

    my $request_count = 0;
    my $shutdown_initiated = 0;

    $feer->request_handler(sub {
        my $r = shift;
        $request_count++;

        # Initiate graceful shutdown after first request
        if ($request_count == 1 && !$shutdown_initiated) {
            $shutdown_initiated = 1;
            # Delay shutdown slightly to allow pipeline to be received
            my $t; $t = AE::timer 0.05, 0, sub {
                $feer->graceful_shutdown(sub { });
                undef $t;
            };
        }

        $r->send_response(200, ['Content-Type' => 'text/plain'], "req $request_count");
    });

    # Send pipelined requests
    my $cv = AE::cv;
    my @responses;

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port2],
        on_error => sub { $cv->send },
        on_eof => sub { $cv->send },
        on_connect => sub {
            # Send 3 pipelined requests
            $_[0]->push_write(
                "GET /1 HTTP/1.1\r\nHost: localhost\r\n\r\n" .
                "GET /2 HTTP/1.1\r\nHost: localhost\r\n\r\n" .
                "GET /3 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            );
            $_[0]->on_read(sub {
                my $data = $_[0]->rbuf;
                $_[0]->rbuf = '';
                push @responses, $1 while $data =~ /(HTTP\/1\.1 \d+)/g;
            });
        },
    );

    my $timeout = AE::timer 3, 0, sub { $cv->send };
    $cv->recv;

    ok $shutdown_initiated, 'graceful shutdown was initiated';
    cmp_ok $request_count, '>=', 1, 'at least one request was processed';
    cmp_ok scalar(@responses), '>=', 1, 'at least one response received';
    # First response should be 200
    like $responses[0] || '', qr/200/, 'first pipelined response OK';
}

pass 'all coverage gap tests completed';
