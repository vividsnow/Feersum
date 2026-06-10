#!/usr/bin/env perl
# Test that Plack::Middleware::ReviseEnv works with Feersum's env hash
#
# This verifies the optimized env hash creation (direct build with shared
# constants) is fully compatible with middleware that directly modifies
# arbitrary env hash values.
#
# Run: perl eg/test-revise-env-middleware.pl
use strict;
use warnings;
use Test::More;
use lib 't';
use Utils;

BEGIN {
    eval { require Plack::Middleware::ReviseEnv };
    if ($@) {
        plan skip_all => 'Plack::Middleware::ReviseEnv not installed';
    }
}

use Plack::Middleware::ReviseEnv;

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
        SCRIPT_NAME       => $env->{SCRIPT_NAME},
        PATH_INFO         => $env->{PATH_INFO},
        REQUEST_URI       => $env->{REQUEST_URI},
        REMOTE_ADDR       => $env->{REMOTE_ADDR},
        SERVER_NAME       => $env->{SERVER_NAME},
        SERVER_PORT       => $env->{SERVER_PORT},
        'psgi.url_scheme' => $env->{'psgi.url_scheme'},
        'X_CUSTOM_VAR'    => $env->{X_CUSTOM_VAR},
    );
    return [200, ['Content-Type' => 'text/plain'], ['OK']];
};

###############################################################################
# Test 1: ReviseEnv modifying psgi.url_scheme
###############################################################################
subtest 'ReviseEnv modifying psgi.url_scheme' => sub {
    %captured_env = ();

    # Create a wrapped app that forces https (using template string syntax)
    my $wrapped_app = Plack::Middleware::ReviseEnv->wrap($app,
        revisors => [
            'psgi.url_scheme' => 'https',
        ],
    );
    $feer->psgi_request_handler($wrapped_app);

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /test HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{'psgi.url_scheme'}, 'https', 'psgi.url_scheme modified to https';
};

###############################################################################
# Test 2: ReviseEnv modifying SCRIPT_NAME
###############################################################################
subtest 'ReviseEnv modifying SCRIPT_NAME' => sub {
    %captured_env = ();

    my $wrapped_app = Plack::Middleware::ReviseEnv->wrap($app,
        revisors => [
            'SCRIPT_NAME' => '/myapp',
        ],
    );
    $feer->psgi_request_handler($wrapped_app);

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /api HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{SCRIPT_NAME}, '/myapp', 'SCRIPT_NAME modified';
};

###############################################################################
# Test 3: ReviseEnv modifying SERVER_PORT
###############################################################################
subtest 'ReviseEnv modifying SERVER_PORT' => sub {
    %captured_env = ();

    my $wrapped_app = Plack::Middleware::ReviseEnv->wrap($app,
        revisors => [
            'SERVER_PORT' => '443',
        ],
    );
    $feer->psgi_request_handler($wrapped_app);

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /secure HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{SERVER_PORT}, '443', 'SERVER_PORT modified';
};

###############################################################################
# Test 4: ReviseEnv adding new env variable
###############################################################################
subtest 'ReviseEnv adding new env variable' => sub {
    %captured_env = ();

    my $wrapped_app = Plack::Middleware::ReviseEnv->wrap($app,
        revisors => [
            'X_CUSTOM_VAR' => 'custom_value',
        ],
    );
    $feer->psgi_request_handler($wrapped_app);

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /custom HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{X_CUSTOM_VAR}, 'custom_value', 'Custom env variable added';
};

###############################################################################
# Test 5: ReviseEnv with multiple modifications
###############################################################################
subtest 'ReviseEnv with multiple modifications' => sub {
    %captured_env = ();

    my $wrapped_app = Plack::Middleware::ReviseEnv->wrap($app,
        revisors => [
            'psgi.url_scheme' => 'https',
            'SERVER_PORT'     => '443',
            'SERVER_NAME'     => 'api.example.com',
            'SCRIPT_NAME'     => '/v2',
        ],
    );
    $feer->psgi_request_handler($wrapped_app);

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /users HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{'psgi.url_scheme'}, 'https', 'psgi.url_scheme modified';
    is $captured_env{SERVER_PORT}, '443', 'SERVER_PORT modified';
    is $captured_env{SERVER_NAME}, 'api.example.com', 'SERVER_NAME modified';
    is $captured_env{SCRIPT_NAME}, '/v2', 'SCRIPT_NAME modified';
};

###############################################################################
# Test 6: Verify constants not corrupted after ReviseEnv modification
###############################################################################
subtest 'Constants not corrupted after modification' => sub {
    %captured_env = ();

    # Use the base app without any modifications
    $feer->psgi_request_handler($app);

    my $cv = AE::cv;
    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    ) or die "Connect failed: $!";

    print $client "GET /plain HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Connection: close\r\n\r\n";

    my $t = AE::timer 1, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    while (<$client>) { $response .= $_; }
    close $client;

    like $response, qr/200 OK/, 'got 200';
    is $captured_env{'psgi.url_scheme'}, 'http',
        'psgi.url_scheme is http (not corrupted from previous tests)';
    is $captured_env{SCRIPT_NAME}, '',
        'SCRIPT_NAME is empty (not corrupted from previous tests)';
};

done_testing;
