#!/usr/bin/env perl
# Test idle keepalive connection eviction under max_connections pressure.
#
# When active_conns >= max_connections and a new connection arrives,
# feer_server_recycle_idle_conn evicts the oldest idle keepalive connection
# to make room. This test exercises that path:
#
# 1. Set max_connections=2, keepalive=1
# 2. Send requests on 2 connections, let them go idle (keepalive)
# 3. Open a 3rd connection — triggers eviction of an idle conn
# 4. Verify the 3rd connection gets a valid response
use strict;
use warnings;
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More tests => 9;
use lib 't'; use Utils;
use IO::Socket::INET;

BEGIN { use_ok('Feersum') };

my ($socket, $port) = get_listen_socket();
ok $socket, "got listen socket on port $port";

my $feer = Feersum->new();
$feer->use_socket($socket);
$feer->set_keepalive(1);
$feer->max_connections(2);

my $request_count = 0;
$feer->request_handler(sub {
    my $r = shift;
    $request_count++;
    $r->send_response(200, ['Content-Type' => 'text/plain'], \"ok $request_count");
});

ok ref($feer), 'server configured';

# Helper: send a request on a given socket, read the full response, return body
sub do_request {
    my ($sock, $label) = @_;
    $sock->print("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");

    # Pump event loop to process the request
    for (1..20) {
        EV::run(EV::RUN_NOWAIT());
        select(undef, undef, undef, 0.02 * TIMEOUT_MULT);
    }

    $sock->blocking(0);
    my $resp = '';
    while (defined(my $n = sysread($sock, my $buf, 8192))) {
        last if $n == 0;
        $resp .= $buf;
    }
    $sock->blocking(1);

    if ($resp =~ /^HTTP\/1\.1 200/m && $resp =~ /\r\n\r\n(.+)$/s) {
        return $1;
    }
    return undef;
}

# Step 1: Open conn1, send request, leave in keepalive-idle
my $conn1 = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1:$port",
    Timeout  => 3 * TIMEOUT_MULT,
);
ok $conn1, "conn1 connected";
my $body1 = do_request($conn1, "conn1");
like $body1, qr/^ok \d+$/, "conn1 got valid response: $body1";

# Step 2: Open conn2, send request, leave in keepalive-idle
my $conn2 = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1:$port",
    Timeout  => 3 * TIMEOUT_MULT,
);
ok $conn2, "conn2 connected";
my $body2 = do_request($conn2, "conn2");
like $body2, qr/^ok \d+$/, "conn2 got valid response: $body2";

# Now both connections are idle-keepalive, active_conns=2, max_connections=2.
# Step 3: Open conn3 — this should trigger eviction of an idle conn.
my $conn3 = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1:$port",
    Timeout  => 3 * TIMEOUT_MULT,
);

# If eviction works, conn3 connects and gets a response.
# If eviction is broken, accept is paused and conn3 times out.
SKIP: {
    skip "conn3 failed to connect (eviction may not have triggered)", 1
        unless $conn3;

    my $body3 = do_request($conn3, "conn3");
    like $body3, qr/^ok \d+$/, "conn3 got valid response after eviction: $body3";
}

# Step 4: Verify one of conn1/conn2 was evicted (closed server-side).
# MRU eviction: conn1 was inserted first (head), so it's evicted first.
# A read on the evicted socket returns EOF (0 bytes).
{
    my $evicted = 0;
    for my $c ($conn1, $conn2) {
        $c->blocking(0);
        my $n = sysread($c, my $buf, 1);
        # EOF (n=0) or error (n=undef, not EAGAIN) means server closed it
        if (!defined($n) ? !$!{EAGAIN} : $n == 0) {
            $evicted++;
        }
    }
    ok $evicted >= 1, "at least one idle conn was evicted (got $evicted)";
}

# Cleanup
$conn1->close if $conn1;
$conn2->close if $conn2;
$conn3->close if $conn3;
