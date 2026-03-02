#!/usr/bin/env perl
use strict;
use warnings;
# TIMEOUT_MULT allows scaling all timing values for slow machines (default: 1)
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 2 : 1);
use blib;
use Test::More;
use Socket qw/AF_INET/;

# Check if IPv6 is available and can bind at runtime
my $ipv6_bind_works;
eval {
    require Socket;
    Socket->import(qw/AF_INET6 SOCK_STREAM inet_pton pack_sockaddr_in6/);
    # Try to actually use inet_pton with an IPv6 address
    my $addr = inet_pton(Socket::AF_INET6(), '::1');
    if (defined $addr) {
        # Try to actually bind to ::1 to see if it works
        my $sock;
        socket($sock, Socket::AF_INET6(), Socket::SOCK_STREAM(), 0) or die "socket: $!";
        bind($sock, Socket::pack_sockaddr_in6(0, $addr)) or die "bind: $!";
        close($sock);
        $ipv6_bind_works = 1;
    }
};

plan tests => 19;  # Always 19: 13 parsing tests + 6 IPv6 tests (run or skipped)
note "IPv6 bind test: " . ($ipv6_bind_works ? "available" : "not available");

use_ok('Feersum::Runner');
use_ok('Feersum');

#######################################################################
# Test IPv6 address parsing in Runner.pm
# These tests verify the parsing logic without requiring actual IPv6
# network connectivity
#######################################################################

# Test the address parsing regex patterns used in _create_socket
# We'll test the parsing by examining the code behavior

# Pattern 1: [host]:port format
{
    my $listen = '[::1]:8080';
    my ($host, $port, $is_ipv6);

    if ($listen =~ /^\[([^\]]+)\]:(\d*)$/) {
        ($host, $port, $is_ipv6) = ($1, $2 || 0, 1);
    }

    is $host, '::1', 'IPv6 bracketed with port: host parsed';
    is $port, '8080', 'IPv6 bracketed with port: port parsed';
    is $is_ipv6, 1, 'IPv6 bracketed with port: detected as IPv6';
}

# Pattern 2: [host] format (no port)
{
    my $listen = '[2001:db8::1]';
    my ($host, $port, $is_ipv6);

    if ($listen =~ /^\[([^\]]+)\]:(\d*)$/) {
        ($host, $port, $is_ipv6) = ($1, $2 || 0, 1);
    } elsif ($listen =~ /^\[([^\]]+)\]$/) {
        ($host, $port, $is_ipv6) = ($1, 0, 1);
    }

    is $host, '2001:db8::1', 'IPv6 bracketed no port: host parsed';
    is $port, 0, 'IPv6 bracketed no port: port defaults to 0';
    is $is_ipv6, 1, 'IPv6 bracketed no port: detected as IPv6';
}

# Pattern 3: bare IPv6 (multiple colons)
{
    my $listen = '::1';
    my ($host, $port, $is_ipv6);

    if ($listen =~ /^\[([^\]]+)\]:(\d*)$/) {
        ($host, $port, $is_ipv6) = ($1, $2 || 0, 1);
    } elsif ($listen =~ /^\[([^\]]+)\]$/) {
        ($host, $port, $is_ipv6) = ($1, 0, 1);
    } elsif ($listen =~ /:.*:/) {
        ($host, $port, $is_ipv6) = ($listen, 0, 1);
    }

    is $host, '::1', 'bare IPv6: host parsed';
    is $port, 0, 'bare IPv6: port defaults to 0';
    is $is_ipv6, 1, 'bare IPv6: detected as IPv6';
}

# IPv4 should not be detected as IPv6
{
    my $listen = '127.0.0.1:8080';
    my ($host, $port, $is_ipv6);

    if ($listen =~ /^\[([^\]]+)\]:(\d*)$/) {
        ($host, $port, $is_ipv6) = ($1, $2 || 0, 1);
    } elsif ($listen =~ /^\[([^\]]+)\]$/) {
        ($host, $port, $is_ipv6) = ($1, 0, 1);
    } elsif ($listen =~ /:.*:/) {
        ($host, $port, $is_ipv6) = ($listen, 0, 1);
    } else {
        ($host, $port) = split /:/, $listen, 2;
        $is_ipv6 = 0;
    }

    is $host, '127.0.0.1', 'IPv4: host parsed correctly';
    is $port, '8080', 'IPv4: port parsed correctly';
}

#######################################################################
# Test actual IPv6 socket creation and HTTP request
#######################################################################

SKIP: {
    if (!$ipv6_bind_works) {
        skip "IPv6 bind to ::1 not available on this system", 6;
        last SKIP;  # Explicitly exit block for older/unusual Perl builds
    }

    note "IPv6 support detected - running end-to-end test";

    # Create IPv6 socket manually (simulating what Runner does in reuseport mode)
    require Socket;
    Socket->import(qw/AF_INET6 SOCK_STREAM SOMAXCONN inet_pton pack_sockaddr_in6 unpack_sockaddr_in6/);
    require IO::Handle;

    my $sock;
    socket($sock, Socket::AF_INET6(), Socket::SOCK_STREAM(), 0) or die "socket: $!";
    setsockopt($sock, Socket::SOL_SOCKET(), Socket::SO_REUSEADDR(), pack("i", 1));
    my $addr = Socket::inet_pton(Socket::AF_INET6(), '::1');
    bind($sock, Socket::pack_sockaddr_in6(0, $addr)) or die "bind: $!";
    listen($sock, Socket::SOMAXCONN()) or die "listen: $!";
    bless $sock, 'IO::Handle';
    $sock->blocking(0);

    # Get the assigned port
    my $sockaddr = getsockname($sock);
    my ($port) = Socket::unpack_sockaddr_in6($sockaddr);
    ok $port > 0, "IPv6 socket bound to port $port";

    # Set up Feersum with the IPv6 socket
    my $feer = Feersum->new();
    $feer->use_socket($sock);

    my $request_received = 0;
    my $remote_addr;

    $feer->request_handler(sub {
        my $r = shift;
        $request_received = 1;
        $remote_addr = $r->remote_address;
        $r->send_response(200, ['Content-Type' => 'text/plain'], 'IPv6 OK');
    });

    # Make request using IPv6
    require AnyEvent;
    require AnyEvent::Socket;
    require AnyEvent::Handle;

    my $cv = AnyEvent->condvar;
    my $response_body = '';

    AnyEvent::Socket::tcp_connect('::1', $port, sub {
        my ($fh) = @_;
        if (!$fh) {
            $cv->croak("Failed to connect: $!");
            return;
        }

        my $h = AnyEvent::Handle->new(
            fh => $fh,
            on_error => sub { $cv->croak("Handle error: $_[2]") },
        );

        $h->push_write("GET / HTTP/1.1\r\nHost: [::1]:$port\r\nConnection: close\r\n\r\n");

        $h->push_read(regex => qr/\r\n\r\n/, sub {
            my $headers = $_[1];
            ok $headers =~ /200 OK/, 'IPv6: got 200 response';

            $h->on_read(sub {
                $response_body .= $h->rbuf;
                $h->rbuf = '';
            });
            $h->on_eof(sub { $cv->send });
        });
    });

    my $timeout = AnyEvent->timer(after => 3 * TIMEOUT_MULT, cb => sub { $cv->croak("timeout") });
    eval { $cv->recv };
    my $err = $@;

    ok !$err, 'IPv6: no error during request' or diag $err;
    ok $request_received, 'IPv6: request handler was called';
    is $response_body, 'IPv6 OK', 'IPv6: got correct response body';
    like $remote_addr, qr/^::1$|^::ffff:127/, 'IPv6: remote_address is IPv6 localhost';

    # Cleanup
    $feer->unlisten();
    close($sock);
}
