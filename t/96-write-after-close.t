#!/usr/bin/env perl
use warnings;
use strict;
use Test::More tests => 12;
use Test::Fatal;
use IO::Socket::INET;

use lib 't'; use Utils;

use_ok('Feersum');

my ($socket, $port) = get_listen_socket();
ok $socket, "made listen socket";

my $evh = Feersum->new();

my $test_case = '';
my $caught_error = '';
my $writer_ref;

$evh->request_handler(sub {
    my $r = shift;

    if ($test_case eq 'write_after_close') {
        my $w = $r->start_streaming("200 OK", [
            'Content-Type' => 'text/plain',
        ]);
        $w->write("First write\n");
        $w->close();
        eval { $w->write("After close\n"); };
        $caught_error = $@ if $@;
    }
    elsif ($test_case eq 'write_array_after_close') {
        my $w = $r->start_streaming("200 OK", [
            'Content-Type' => 'text/plain',
        ]);
        $w->write("First write\n");
        $w->close();
        eval { $w->write_array(["After", " close\n"]); };
        $caught_error = $@ if $@;
    }
    elsif ($test_case eq 'close_twice') {
        my $w = $r->start_streaming("200 OK", [
            'Content-Type' => 'text/plain',
        ]);
        $w->write("Content\n");
        $w->close();
        eval { $w->close(); };
        $caught_error = $@ if $@;
    }
    elsif ($test_case eq 'sendfile_after_close') {
        my $w = $r->start_streaming("200 OK", [
            'Content-Type' => 'text/plain',
        ]);
        $w->close();
        eval {
            open my $fh, '<', $0 or die "open: $!";
            $w->sendfile($fh, 0, 10);
            close $fh;
        };
        $caught_error = $@ if $@;
    }
    elsif ($test_case eq 'stash_writer') {
        my $w = $r->start_streaming("200 OK", [
            'Content-Type' => 'text/plain',
        ]);
        $w->write("Immediate\n");
        $writer_ref = $w;  # Stash for later use
    }
    else {
        $r->send_response(200, ['Content-Type' => 'text/plain'], "OK\n");
    }
});

$evh->use_socket($socket);

# Helper to run a test request
sub run_request {
    my $client = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$port",
        Proto    => 'tcp',
        Timeout  => 3,
    );
    return undef unless $client;

    print $client "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    my $iterations = 0;
    while ($iterations++ < 50) {
        EV::run(EV::RUN_NOWAIT());
        select(undef, undef, undef, 0.01);
    }

    my $response = '';
    $client->blocking(0);
    my $buf;
    while (sysread($client, $buf, 8192)) {
        $response .= $buf;
        EV::run(EV::RUN_NOWAIT());
    }
    close $client;

    return $response;
}

#######################################################################
# Test 1: write() after close()
#######################################################################

{
    $test_case = 'write_after_close';
    $caught_error = '';

    my $response = run_request();
    ok length($response) > 0, "write_after_close: got response";
    like $response, qr/First write/, "write_after_close: initial write succeeded";
    like $caught_error, qr/closed|shutdown|finished|invalid/i,
        "write_after_close: write after close caught error: $caught_error";
}

#######################################################################
# Test 2: write_array() after close()
#######################################################################

{
    $test_case = 'write_array_after_close';
    $caught_error = '';

    my $response = run_request();
    ok length($response) > 0, "write_array_after_close: got response";
    like $caught_error, qr/closed|shutdown|finished|invalid/i,
        "write_array_after_close: caught error: $caught_error";
}

#######################################################################
# Test 3: close() twice
#######################################################################

{
    $test_case = 'close_twice';
    $caught_error = '';

    my $response = run_request();
    ok length($response) > 0, "close_twice: got response";
    # Double close should either be no-op or give a sensible error
    ok !$caught_error || $caught_error =~ /closed|already|invalid/i,
        "close_twice: no crash (error: " . ($caught_error || 'none') . ")";
}

#######################################################################
# Test 4: sendfile() after close()
#######################################################################

SKIP: {
    skip "sendfile only on Linux", 2 unless $^O eq 'linux';

    $test_case = 'sendfile_after_close';
    $caught_error = '';

    my $response = run_request();
    ok length($response) > 0, "sendfile_after_close: got response";
    like $caught_error, qr/closed|shutdown|finished|invalid/i,
        "sendfile_after_close: caught error: $caught_error";
}

pass "all write-after-close tests completed";
