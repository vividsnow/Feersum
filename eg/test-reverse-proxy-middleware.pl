#!/usr/bin/env perl
# Test that Plack::Middleware::ReverseProxy works with Feersum's env hash
#
# This verifies the optimized env hash creation (direct build with shared
# constants) is fully compatible with middleware that modifies env values.
#
# Run: perl eg/test-reverse-proxy-middleware.pl
use strict;
use warnings;
use Test::More;
use lib 't';
use Utils;

BEGIN {
    eval { require Plack::Middleware::ReverseProxy };
    if ($@) {
        plan skip_all => 'Plack::Middleware::ReverseProxy not installed';
    }
}

use Plack::Middleware::ReverseProxy;

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
        REMOTE_ADDR     => $env->{REMOTE_ADDR},
        REMOTE_HOST     => $env->{REMOTE_HOST},
        HTTP_HOST       => $env->{HTTP_HOST},
        SERVER_PORT     => $env->{SERVER_PORT},
        REQUEST_URI     => $env->{REQUEST_URI},
        'psgi.url_scheme' => $env->{'psgi.url_scheme'},
    );
    return [200, ['Content-Type' => 'text/plain'], ['OK']];
};

# Wrap with ReverseProxy middleware
my $wrapped_app = Plack::Middleware::ReverseProxy->wrap($app);

$feer->psgi_request_handler($wrapped_app);

###############################################################################
# Test 1: Request without X-Forwarded headers (passthrough)
###############################################################################
subtest 'Request without X-Forwarded headers' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET / HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{REMOTE_ADDR}, '127.0.0.1', 'REMOTE_ADDR unchanged';
    is $captured_env{'psgi.url_scheme'}, 'http', 'psgi.url_scheme unchanged';
};

###############################################################################
# Test 2: Request with X-Forwarded-For header
###############################################################################
subtest 'Request with X-Forwarded-For' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /test HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "X-Forwarded-For: 10.0.0.1\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{REMOTE_ADDR}, '10.0.0.1', 'REMOTE_ADDR set from X-Forwarded-For';
};

###############################################################################
# Test 3: Request with X-Forwarded-Proto header (HTTPS)
###############################################################################
subtest 'Request with X-Forwarded-Proto https' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /secure HTTP/1.1\r\n" .
                  "Host: example.com\r\n" .
                  "X-Forwarded-Proto: https\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{'psgi.url_scheme'}, 'https', 'psgi.url_scheme changed to https';
};

###############################################################################
# Test 4: Request with X-Forwarded-Host header
###############################################################################
subtest 'Request with X-Forwarded-Host' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /proxied HTTP/1.1\r\n" .
                  "Host: internal.local\r\n" .
                  "X-Forwarded-Host: public.example.com\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{HTTP_HOST}, 'public.example.com', 'HTTP_HOST set from X-Forwarded-Host';
};

###############################################################################
# Test 5: Request with X-Forwarded-Port header (requires X-Forwarded-Host)
###############################################################################
subtest 'Request with X-Forwarded-Port' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    # X-Forwarded-Port requires X-Forwarded-Host to be processed by middleware
    print $client "GET /port HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "X-Forwarded-Host: example.com\r\n" .
                  "X-Forwarded-Port: 443\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{SERVER_PORT}, '443', 'SERVER_PORT set from X-Forwarded-Port';
};

###############################################################################
# Test 6: Combined X-Forwarded headers
###############################################################################
subtest 'Combined X-Forwarded headers' => sub {
    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /full-proxy HTTP/1.1\r\n" .
                  "Host: internal:8080\r\n" .
                  "X-Forwarded-For: 192.168.1.100, 10.0.0.1\r\n" .
                  "X-Forwarded-Proto: https\r\n" .
                  "X-Forwarded-Host: api.example.com\r\n" .
                  "X-Forwarded-Port: 443\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    # X-Forwarded-For with multiple IPs: middleware takes the last one
    like $captured_env{REMOTE_ADDR}, qr/^(192\.168\.1\.100|10\.0\.0\.1)$/,
        'REMOTE_ADDR set from X-Forwarded-For';
    is $captured_env{'psgi.url_scheme'}, 'https', 'psgi.url_scheme is https';
    # Middleware appends port to host when X-Forwarded-Port is present
    like $captured_env{HTTP_HOST}, qr/^api\.example\.com/, 'HTTP_HOST from X-Forwarded-Host';
    is $captured_env{SERVER_PORT}, '443', 'SERVER_PORT from X-Forwarded-Port';
};

###############################################################################
# Test 7: Verify constants are not corrupted after middleware modification
###############################################################################
subtest 'Constants not corrupted after modification' => sub {
    # After middleware has modified psgi.url_scheme to 'https',
    # verify that a new request still gets 'http' as default

    %captured_env = ();

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    # Request WITHOUT X-Forwarded-Proto
    print $client "GET /no-proxy HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{'psgi.url_scheme'}, 'http',
        'psgi.url_scheme is http (constant not corrupted)';
    is $captured_env{REMOTE_ADDR}, '127.0.0.1',
        'REMOTE_ADDR is 127.0.0.1 (not leftover from previous request)';
};

###############################################################################
# Test 8: Verify middleware can add new keys to env hash
###############################################################################
subtest 'Middleware can add new keys to env hash' => sub {
    my %custom_captured;

    # App that captures custom keys
    my $capturing_app = sub {
        my $env = shift;
        %custom_captured = (
            X_CUSTOM_KEY           => $env->{X_CUSTOM_KEY},
            'psgix.custom.extension' => $env->{'psgix.custom.extension'},
        );
        return [200, ['Content-Type' => 'text/plain'], ['OK']];
    };

    # Middleware that adds new keys before passing to app
    my $adding_middleware = sub {
        my $env = shift;
        # Add completely new keys to env hash
        $env->{X_CUSTOM_KEY} = 'custom_value';
        $env->{'psgix.custom.extension'} = { foo => 'bar' };
        return $capturing_app->($env);
    };
    $feer->psgi_request_handler($adding_middleware);

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /extend HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $custom_captured{X_CUSTOM_KEY}, 'custom_value',
        'middleware can add new scalar key';
    is_deeply $custom_captured{'psgix.custom.extension'}, { foo => 'bar' },
        'middleware can add new hashref key';
};

done_testing;
