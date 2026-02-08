#!/usr/bin/env perl
# Test API misuse scenarios - calling methods in wrong order/state
use strict;
use warnings;
use Test::More;
use Test::Fatal;
use lib 't'; use Utils;

BEGIN { use_ok('Feersum') };

my ($socket, $port) = get_listen_socket();
ok $socket, 'got listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);

#######################################################################
# Test 1: start_streaming() called twice
#######################################################################
{
    my $double_stream_error;

    $feer->request_handler(sub {
        my $r = shift;
        my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
        eval { $r->start_streaming(200, ['Content-Type' => 'text/plain']) };
        $double_stream_error = $@;
        $w->write("ok");
        $w->close();
    });

    my $cv = AE::cv;
    my $h = simple_client GET => '/double-stream', sub { $cv->send };
    $cv->recv;

    ok $double_stream_error, 'start_streaming() twice throws error';
    like $double_stream_error, qr/already|respond|start/i, 'error mentions already started';
}

#######################################################################
# Test 2: send_response() after start_streaming()
#######################################################################
{
    my $send_after_stream_error;

    $feer->request_handler(sub {
        my $r = shift;
        my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
        eval { $r->send_response(200, [], 'body') };
        $send_after_stream_error = $@;
        $w->write("ok");
        $w->close();
    });

    my $cv = AE::cv;
    my $h = simple_client GET => '/send-after-stream', sub { $cv->send };
    $cv->recv;

    ok $send_after_stream_error, 'send_response() after start_streaming() throws error';
    like $send_after_stream_error, qr/already|respond|start/i, 'error mentions already started';
}

#######################################################################
# Test 3: send_response() called twice
#######################################################################
{
    my $double_send_error;

    $feer->request_handler(sub {
        my $r = shift;
        $r->send_response(200, ['Content-Type' => 'text/plain'], 'first');
        eval { $r->send_response(200, [], 'second') };
        $double_send_error = $@;
    });

    my $cv = AE::cv;
    my $h = simple_client GET => '/double-send', sub { $cv->send };
    $cv->recv;

    ok $double_send_error, 'send_response() twice throws error';
    like $double_send_error, qr/already|respond|complet/i, 'error mentions already responded';
}

#######################################################################
# Test 4: write() with HASH ref (should error)
#######################################################################
{
    my $write_hash_error;

    $feer->request_handler(sub {
        my $r = shift;
        my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
        # Try to write a HASH ref (invalid)
        eval { $w->write({foo => 'bar'}) };
        $write_hash_error = $@;
        $w->write("ok");
        $w->close();
    });

    my $cv = AE::cv;
    my $h = simple_client GET => '/write-hash', sub { $cv->send };
    $cv->recv;

    ok $write_hash_error, 'write() with HASH ref throws error';
    like $write_hash_error, qr/scalar/i, 'error mentions scalar requirement';
}

#######################################################################
# Test 5: write() outside streaming mode
#######################################################################
{
    my $captured_writer;
    my $write_outside_error;

    $feer->request_handler(sub {
        my $r = shift;
        my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
        $captured_writer = $w;
        $w->write("ok");
        $w->close();
    });

    my $cv = AE::cv;
    my $h = simple_client GET => '/capture-writer', sub { $cv->send };
    $cv->recv;

    # Try to write after close
    eval { $captured_writer->write("late") } if $captured_writer;
    $write_outside_error = $@;

    ok $write_outside_error, 'write() after close throws error';
}

#######################################################################
# Test 6: close() called twice (should not crash)
#######################################################################
{
    my $handler_completed = 0;

    $feer->request_handler(sub {
        my $r = shift;
        my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
        $w->write("data");
        $w->close();
        eval { $w->close() };  # Second close - should not crash
        $handler_completed = 1;
    });

    my $cv = AE::cv;
    my $h = simple_client GET => '/double-close', sub { $cv->send };
    $cv->recv;

    ok $handler_completed, 'double close() handled without crash';
}

done_testing;
