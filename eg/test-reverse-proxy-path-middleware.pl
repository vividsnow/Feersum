#!/usr/bin/env perl
# Test that Plack::Middleware::ReverseProxyPath works with Feersum's env hash
#
# This verifies the optimized env hash creation (direct build with shared
# constants) is fully compatible with middleware that modifies SCRIPT_NAME
# and PATH_INFO values.
#
# Run: perl eg/test-reverse-proxy-path-middleware.pl
use strict;
use warnings;
use Test::More;
use lib 't';
use Utils;

BEGIN {
    eval { require Plack::Middleware::ReverseProxyPath };
    if ($@) {
        plan skip_all => 'Plack::Middleware::ReverseProxyPath not installed';
    }
}

use Plack::Middleware::ReverseProxyPath;

BEGIN { use_ok('Feersum') };

my ($socket, $port) = get_listen_socket();
ok $socket, 'got listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);

# Captured env values from inside the app
my %captured_env;

# Base PSGI app that captures env
my $app = sub {
    my $env = shift;
    %captured_env = (
        SCRIPT_NAME     => $env->{SCRIPT_NAME},
        PATH_INFO       => $env->{PATH_INFO},
        REQUEST_URI     => $env->{REQUEST_URI},
    );
    return [200, ['Content-Type' => 'text/plain'], ['OK']];
};

# Wrap with ReverseProxyPath middleware
my $wrapped_app = Plack::Middleware::ReverseProxyPath->wrap($app);

$feer->psgi_request_handler($wrapped_app);

###############################################################################
# Test 1: Request without X-Forwarded-Script-Name (passthrough)
###############################################################################
subtest 'Request without X-Forwarded-Script-Name' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /api/users HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{SCRIPT_NAME}, '', 'SCRIPT_NAME unchanged (empty)';
    is $captured_env{PATH_INFO}, '/api/users', 'PATH_INFO unchanged';
};

###############################################################################
# Test 2: Request with X-Forwarded-Script-Name header
###############################################################################
subtest 'Request with X-Forwarded-Script-Name' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /api/users HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "X-Forwarded-Script-Name: /myapp\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{SCRIPT_NAME}, '/myapp', 'SCRIPT_NAME set from X-Forwarded-Script-Name';
    is $captured_env{PATH_INFO}, '/api/users', 'PATH_INFO unchanged';
};

###############################################################################
# Test 3: Request with X-Traversal-Path header
###############################################################################
subtest 'Request with X-Traversal-Path' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    # X-Traversal-Path strips a prefix from PATH_INFO
    print $client "GET /prefix/api/users HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "X-Traversal-Path: /prefix\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{PATH_INFO}, '/api/users', 'PATH_INFO has prefix stripped';
};

###############################################################################
# Test 4: Combined X-Forwarded-Script-Name and X-Traversal-Path
###############################################################################
subtest 'Combined X-Forwarded-Script-Name and X-Traversal-Path' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /v1/api/users HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "X-Forwarded-Script-Name: /myapp\r\n" .
                  "X-Traversal-Path: /v1\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{SCRIPT_NAME}, '/myapp', 'SCRIPT_NAME set';
    is $captured_env{PATH_INFO}, '/api/users', 'PATH_INFO has prefix stripped';
};

###############################################################################
# Test 5: Deep nested script name
###############################################################################
subtest 'Deep nested script name' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /resource HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "X-Forwarded-Script-Name: /apps/production/myapp\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{SCRIPT_NAME}, '/apps/production/myapp', 'Deep SCRIPT_NAME set correctly';
};

###############################################################################
# Test 6: Verify SCRIPT_NAME constant not corrupted after modification
###############################################################################
subtest 'SCRIPT_NAME constant not corrupted after modification' => sub {
    # After middleware has modified SCRIPT_NAME,
    # verify that a new request still gets empty string as default

    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    # Request WITHOUT X-Forwarded-Script-Name
    print $client "GET /test HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{SCRIPT_NAME}, '',
        'SCRIPT_NAME is empty (constant not corrupted from previous request)';
};

done_testing;
