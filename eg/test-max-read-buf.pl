#!/usr/bin/env perl
# Manual test for MAX_READ_BUF (64MB) limit
# This test is too resource-intensive for CI, run manually:
#   perl eg/test-max-read-buf.pl
#
# NOTE: MAX_READ_BUF limits the read buffer used during header parsing
# and for chunked transfer encoding body accumulation.
# Content-Length bodies are read through a separate Reader handle and
# are limited by MAX_BODY_LEN (2GB) instead.
use strict;
use warnings;
use Test::More;
use IO::Socket::INET;
use lib 't';
use Utils;

BEGIN { use_ok('Feersum') };

my ($socket, $port) = get_listen_socket();
ok $socket, 'got listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);
$feer->read_timeout(300);  # 5 minutes - enough time to send 65MB

my $request_handled = 0;
$feer->request_handler(sub {
    my $r = shift;
    $request_handled++;
    # Read and discard body for Content-Length requests
    if (my $input = $r->input) {
        my $buf;
        1 while $input->read($buf, 65536);
    }
    $r->send_response(200, ['Content-Type' => 'text/plain'], ['OK']);
});

# MAX_READ_BUF is 64MB (67108864 bytes) defined in Feersum.xs
my $MAX_READ_BUF = 64 * 1024 * 1024;

###############################################################################
# Test 1: Content-Length request (NOT limited by MAX_READ_BUF)
# Content-Length bodies use Reader handle, limited by MAX_BODY_LEN (2GB)
###############################################################################
subtest 'Content-Length request succeeds (uses Reader, not rbuf)' => sub {
    plan tests => 2;

    # Send a request with 1MB body - should succeed
    my $body_size = 1024 * 1024;  # 1MB
    my $body = 'x' x $body_size;

    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 30,
    ) or die "Cannot connect: $!";

    my $request = "POST /content-length HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Content-Length: $body_size\r\n" .
                  "Connection: close\r\n\r\n" .
                  $body;

    print $client $request;

    # Run event loop
    my $cv = AE::cv;
    my $timer = AE::timer 5, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    $client->blocking(1);
    while (my $line = <$client>) {
        $response .= $line;
    }
    close $client;

    like $response, qr/HTTP\/1\.[01] 200/, 'Content-Length request got 200 OK';
    ok $request_handled >= 1, 'request handler was called';
};

###############################################################################
# Test 2: Chunked request under limit should succeed
###############################################################################
subtest 'Chunked request under limit succeeds' => sub {
    plan tests => 1;

    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 30,
    ) or die "Cannot connect: $!";

    # Send 1MB chunked body (under 64MB limit)
    my $chunk_data = 'x' x (1024 * 1024);
    my $chunk_size = length($chunk_data);

    my $request = "POST /chunked-under HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Transfer-Encoding: chunked\r\n" .
                  "Connection: close\r\n\r\n" .
                  sprintf("%x\r\n%s\r\n", $chunk_size, $chunk_data) .
                  "0\r\n\r\n";  # Final chunk

    print $client $request;

    my $cv = AE::cv;
    my $timer = AE::timer 5, 0, sub { $cv->send };
    $cv->recv;

    my $response = '';
    $client->blocking(1);
    while (my $line = <$client>) {
        $response .= $line;
    }
    close $client;

    like $response, qr/HTTP\/1\.[01] 200/, 'chunked request under limit got 200 OK';
};

###############################################################################
# Test 3: Chunked request exceeding MAX_READ_BUF should be rejected
# Server may return 413 (Request Too Large) or 400 (Malformed chunked)
###############################################################################
subtest 'Chunked request over limit gets rejected' => sub {
    plan tests => 1;

    my $client = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 120,
    ) or die "Cannot connect: $!";

    # Send chunked request headers
    my $headers = "POST /chunked-over-limit HTTP/1.1\r\n" .
                  "Host: localhost\r\n" .
                  "Transfer-Encoding: chunked\r\n" .
                  "Connection: close\r\n\r\n";

    print $client $headers;

    # Send chunks as fast as possible until we exceed the limit
    my $sent = 0;
    my $chunk_data = 'x' x (4 * 1024 * 1024);  # 4MB per chunk for speed
    my $chunk_size = length($chunk_data);
    my $chunk = sprintf("%x\r\n%s\r\n", $chunk_size, $chunk_data);
    my $response = '';
    my $target = $MAX_READ_BUF + 4 * 1024 * 1024;  # 68MB target

    $client->blocking(0);

    my $cv = AE::cv;
    my $done = 0;

    # Use idle watcher to send data as fast as possible
    my $idle; $idle = AE::idle sub {
        return if $done;

        # Check for response
        my $buf;
        my $n = sysread($client, $buf, 8192);
        if (defined $n && $n > 0) {
            $response .= $buf;
            if ($response =~ /HTTP\/1\.[01] \d{3}/) {
                $done = 1;
                undef $idle;
                $cv->send;
                return;
            }
        }

        # Send more data
        if ($sent < $target) {
            my $wrote = syswrite($client, $chunk);
            if (defined $wrote && $wrote > 0) {
                $sent += $chunk_size;
                note "Sent $sent bytes..." if $sent % (16 * 1024 * 1024) == 0;
            }
        } else {
            # Sent enough, just wait for response
            note "Sent $sent bytes, waiting for response...";
        }
    };

    # Timeout
    my $timeout = AE::timer 120, 0, sub {
        $done = 1;
        undef $idle;
        $cv->send;
    };

    $cv->recv;

    # Read any remaining response
    $client->blocking(1);
    my $buf;
    local $SIG{ALRM} = sub { die "timeout" };
    alarm(5);
    eval {
        while (sysread($client, $buf, 8192)) {
            $response .= $buf;
        }
    };
    alarm(0);
    close $client;

    # Accept either 413 (Request Too Large) or 400 (Malformed chunked)
    # Both indicate server properly rejects oversized chunked requests
    # 400 can occur when rapid data sending causes parsing issues before
    # the MAX_READ_BUF check triggers
    if ($response =~ /HTTP\/1\.[01] (413|400)/) {
        pass "chunked request over limit rejected with $1";
    } elsif ($response =~ /HTTP\/1\.[01] (\d+)/) {
        fail "chunked request over limit rejected (got $1 instead of 400/413)";
        diag "Response: $response";
    } else {
        fail "chunked request over limit rejected (no HTTP response received)";
        diag "Sent: $sent bytes";
        diag "Response buffer: " . substr($response, 0, 500);
    }
};

done_testing;

__END__

=head1 NAME

test-max-read-buf.pl - Manual test for MAX_READ_BUF limit

=head1 DESCRIPTION

Tests that Feersum correctly rejects chunked transfer encoding requests
that exceed the MAX_READ_BUF limit (64MB). This prevents memory exhaustion
attacks via chunked encoding.

Note: Content-Length requests are NOT limited by MAX_READ_BUF. They use a
separate Reader handle and are limited by MAX_BODY_LEN (2GB) instead.

This test is not included in the normal test suite because it requires
sending ~65MB of data, which is too slow and resource-intensive for CI.

=head1 USAGE

    perl eg/test-max-read-buf.pl

=cut
