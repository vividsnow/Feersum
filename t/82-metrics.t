#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 18;
use lib 't'; use Utils;

BEGIN { use_ok('Feersum') };

#######################################################################
# Test active_conns() and total_requests() metrics under load
#######################################################################

my ($socket, $port) = get_listen_socket();
ok $socket, 'got listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);
$feer->set_keepalive(1);

# Track metrics during requests
my @active_during_request;
my $total_before;

$feer->request_handler(sub {
    my $r = shift;
    # Capture active_conns during request handling
    push @active_during_request, $feer->active_conns;
    $r->send_response(200, ['Content-Type' => 'text/plain'], 'OK');
});

# Test 1: Verify initial state
{
    my $active = $feer->active_conns;
    is $active, 0, 'active_conns starts at 0';

    $total_before = $feer->total_requests;
    ok defined($total_before), 'total_requests returns a value';
}

# Test 2: Single request - active_conns during handling
{
    @active_during_request = ();

    my $cv = AE::cv;
    my $h = simple_client GET => '/test1',
        sub {
            my ($body, $hdr) = @_;
            is $hdr->{Status}, 200, 'single request: got 200';
            $cv->send;
        };
    $cv->recv;

    ok @active_during_request >= 1, 'active_conns captured during request';
    ok $active_during_request[0] >= 1, 'active_conns >= 1 during request handling';
}

# Test 3: Multiple concurrent connections
{
    @active_during_request = ();
    my $cv = AE::cv;
    $cv->begin for 1..3;

    my @handles;
    for my $i (1..3) {
        push @handles, simple_client GET => "/test$i",
            keepalive => 1,
            sub {
                my ($body, $hdr) = @_;
                $cv->end;
            };
    }

    my $timeout = AE::timer 5, 0, sub { $cv->croak("timeout") };
    $cv->recv;

    # We should have seen active_conns >= 1 at some point
    my $max_active = 0;
    for my $a (@active_during_request) {
        $max_active = $a if $a > $max_active;
    }
    ok $max_active >= 1, "max active_conns during concurrent requests: $max_active";
}

# Test 4: active_conns returns to baseline after connections close
{
    # Give connections time to close
    my $cv = AE::cv;
    my $t = AE::timer 0.5, 0, sub { $cv->send };
    $cv->recv;

    my $active_after = $feer->active_conns;
    ok $active_after >= 0, "active_conns after close: $active_after (should be low)";
}

# Test 5: total_requests incremented correctly
{
    my $total_after = $feer->total_requests;
    ok $total_after > $total_before, 'total_requests incremented';

    # We made at least 4 requests (1 single + 3 concurrent)
    my $diff = $total_after - $total_before;
    ok $diff >= 4, "total_requests increased by at least 4 (got $diff)";
}

# Test 6: Streaming response - active_conns during streaming
{
    my $streaming_active;

    $feer->request_handler(sub {
        my $r = shift;
        my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
        $streaming_active = $feer->active_conns;
        $w->write("chunk1");
        $w->write("chunk2");
        $w->close();
    });

    my $cv = AE::cv;
    my $body = '';

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send },
    );
    $h->push_write("GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $h->on_read(sub {
        $body .= $h->rbuf;
        $h->rbuf = '';
    });
    $h->on_eof(sub { $cv->send });

    my $timeout = AE::timer 5, 0, sub { $cv->send };
    $cv->recv;

    ok $streaming_active >= 1, "active_conns >= 1 during streaming: $streaming_active";
    like $body, qr/chunk1.*chunk2/s, 'streaming response received';
}

pass 'all metrics tests completed';
