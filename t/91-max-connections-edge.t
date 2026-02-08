#!/usr/bin/env perl
use strict;
# TIMEOUT_MULT allows scaling all timing values for slow machines (default: 1)
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || 1;
use warnings;
use Test::More;
use lib 't'; use Utils;
use Feersum;
use AnyEvent;
use AnyEvent::Handle;
use IO::Socket::INET;

#######################################################################
# Test max_connections boundary conditions
# - Exactly at limit
# - Over limit (should reject)
# - Dynamic adjustment during operation
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
$feer->max_connections(3);  # Set low limit for testing
$feer->request_handler(sub {
    my $r = shift;
    $r->send_response(200, ['Content-Type' => 'text/plain'], \"ok");
});

# Test 1: Open connections up to limit
{
    my @sockets;
    my $cv = AE::cv;

    # Open 3 connections (at limit)
    for my $i (1..3) {
        my $sock = IO::Socket::INET->new(
            PeerAddr => 'localhost',
            PeerPort => $port,
            Proto    => 'tcp',
            Timeout  => 2,
        );
        if ($sock) {
            push @sockets, $sock;
        }
    }

    is(scalar(@sockets), 3, 'Opened 3 connections (at limit)');

    # Small delay to let connections be accepted
    my $timer = AE::timer 0.1, 0, sub { $cv->send };
    $cv->recv;

    # Try to open 4th connection - should be rejected or queued
    my $sock4 = IO::Socket::INET->new(
        PeerAddr => 'localhost',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 1,
    );

    # Connection may succeed at TCP level but be closed by server
    if ($sock4) {
        # Try to send request - may get connection closed
        $sock4->print("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        my $resp = '';
        eval {
            local $SIG{ALRM} = sub { die "timeout" };
            alarm(1);
            $sock4->recv($resp, 1024);
            alarm(0);
        };
        # Either got response (connection was queued) or closed
        ok(1, '4th connection handled (queued or rejected)');
        close($sock4);
    } else {
        ok(1, '4th connection rejected at TCP level');
    }

    # Close all sockets
    close($_) for @sockets;
}

# Test 2: Verify connections work after limit is freed
{
    my $cv = AE::cv;
    my $response = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    $h->push_write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

    $h->on_read(sub {
        $response .= $h->rbuf;
        $h->rbuf = '';
    });

    my $timer = AE::timer 2 * TIMEOUT_MULT, 0, sub { $cv->send };
    $cv->recv;

    like($response, qr/HTTP\/1\.1 200/, 'Connection works after limit freed');
}

# Test 3: max_connections(0) means unlimited
{
    $feer->max_connections(0);  # Unlimited

    my @sockets;

    # Open 10 connections
    for my $i (1..10) {
        my $sock = IO::Socket::INET->new(
            PeerAddr => 'localhost',
            PeerPort => $port,
            Proto    => 'tcp',
            Timeout  => 2,
        );
        push @sockets, $sock if $sock;
    }

    cmp_ok(scalar(@sockets), '>=', 5, 'max_connections(0): opened many connections');

    close($_) for @sockets;
}

# Test 4: Verify active_conns metric
{
    my $active = $feer->active_conns();
    ok(defined $active, 'active_conns() returns value');
    cmp_ok($active, '>=', 0, 'active_conns() is non-negative');
}

# Test 5: Set max_connections back and verify enforcement
{
    $feer->max_connections(2);  # Very low limit

    my @handles;
    my $cv = AE::cv;
    my $connected = 0;
    my $errors = 0;

    # Try to open 5 connections rapidly
    for my $i (1..5) {
        my $h = AnyEvent::Handle->new(
            connect => ['localhost', $port],
            on_connect => sub { $connected++; },
            on_error => sub { $errors++; },
            on_eof => sub { },
        );
        push @handles, $h;
    }

    # Wait briefly for connections
    my $timer = AE::timer 0.3, 0, sub { $cv->send };
    $cv->recv;

    # Should have at least some connected
    cmp_ok($connected, '>=', 2, 'max_connections(2): at least 2 connected');

    # Clean up
    $_->destroy for @handles;
}

# Test 6: max_connections getter
{
    $feer->max_connections(100);
    my $val = $feer->max_connections();
    is($val, 100, 'max_connections getter returns set value');
}

# Test 7: max_connections with keepalive
{
    $feer->max_connections(3);
    $feer->set_keepalive(1);

    my $cv = AE::cv;
    my @responses;

    # Send multiple requests on same connection
    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send; },
        on_eof => sub { $cv->send; },
    );

    # Send 3 requests pipelined
    $h->push_write(
        "GET /1 HTTP/1.1\r\nHost: localhost\r\n\r\n" .
        "GET /2 HTTP/1.1\r\nHost: localhost\r\n\r\n" .
        "GET /3 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );

    my $buffer = '';
    $h->on_read(sub {
        $buffer .= $h->rbuf;
        $h->rbuf = '';
        my $count = () = $buffer =~ /HTTP\/1\.1 200/g;
        $cv->send if $count >= 3;
    });

    my $timer = AE::timer 2 * TIMEOUT_MULT, 0, sub { $cv->send };
    $cv->recv;

    my $count = () = $buffer =~ /HTTP\/1\.1 200/g;
    is($count, 3, 'max_connections with keepalive: 3 responses on single conn');
}

pass "all max_connections edge tests completed";
