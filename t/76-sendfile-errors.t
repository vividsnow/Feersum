#!/usr/bin/env perl
use warnings;
use strict;
use Test::More;
use Test::Fatal;
use File::Temp qw(tempfile);
use IO::Socket::INET;

use lib 't'; use Utils;

# sendfile is Linux-only
unless ($^O eq 'linux') {
    plan skip_all => 'sendfile() is only supported on Linux';
}

plan tests => 15;

use_ok('Feersum');

my ($socket, $port) = get_listen_socket();
ok $socket, "made listen socket";

# Create test file
my ($fh, $file) = tempfile(UNLINK => 1);
print $fh "Hello, sendfile world!\n";  # 24 bytes
close $fh;
my $file_size = -s $file;
ok $file_size > 0, "test file created ($file_size bytes)";

my $evh = Feersum->new();

my $test_mode = '';
my $sendfile_offset = 0;
my $sendfile_length = undef;
my $caught_error = '';

$evh->request_handler(sub {
    my $r = shift;
    open my $fh, '<', $file or die "open: $!";

    my $w = $r->start_streaming("200 OK", [
        'Content-Type' => 'text/plain',
        'Content-Length' => $file_size,
    ]);

    eval {
        if (defined $sendfile_length) {
            $w->sendfile($fh, $sendfile_offset, $sendfile_length);
        } else {
            $w->sendfile($fh, $sendfile_offset);
        }
    };
    if ($@) {
        $caught_error = $@;
    }
    close $fh;
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
# Test 1: Normal sendfile (baseline)
#######################################################################

{
    $sendfile_offset = 0;
    $sendfile_length = undef;
    $caught_error = '';

    my $response = run_request();
    ok length($response) > 0, "Normal sendfile: got response";
    like $response, qr/Hello, sendfile/, "Normal sendfile: contains file content";
    is $caught_error, '', "Normal sendfile: no error";
}

#######################################################################
# Test 2: sendfile with offset
#######################################################################

{
    $sendfile_offset = 7;  # Skip "Hello, "
    $sendfile_length = undef;
    $caught_error = '';

    my $response = run_request();
    ok length($response) > 0, "Offset sendfile: got response";
    like $response, qr/sendfile world/, "Offset sendfile: contains partial content";
}

#######################################################################
# Test 3: sendfile with negative offset (should error)
#######################################################################

{
    $sendfile_offset = -1;
    $sendfile_length = undef;
    $caught_error = '';

    run_request();
    like $caught_error, qr/offset must be non-negative/i, "Negative offset: caught error";
}

#######################################################################
# Test 4: sendfile with offset past end of file (should error)
#######################################################################

{
    $sendfile_offset = $file_size + 100;
    $sendfile_length = undef;
    $caught_error = '';

    run_request();
    like $caught_error, qr/offset out of range/i, "Offset past EOF: caught error";
}

#######################################################################
# Test 5: sendfile with length exceeding file size (should error)
#######################################################################

{
    $sendfile_offset = 0;
    $sendfile_length = $file_size + 100;
    $caught_error = '';

    run_request();
    like $caught_error, qr/exceeds file size/i, "Length too large: caught error";
}

#######################################################################
# Test 6: sendfile with offset + length exceeding file size (should error)
#######################################################################

{
    $sendfile_offset = 10;
    $sendfile_length = $file_size;  # 10 + file_size > file_size
    $caught_error = '';

    run_request();
    like $caught_error, qr/exceeds file size/i, "Offset+length too large: caught error";
}

#######################################################################
# Test 7: sendfile on directory (non-regular file)
#######################################################################

{
    my $dir_error = '';
    my $saved_handler = $evh->request_handler(sub {
        my $r = shift;
        my $w = $r->start_streaming("200 OK", ['Content-Type' => 'text/plain']);
        eval {
            open my $dirfh, '<', '/tmp' or die "open /tmp: $!";
            $w->sendfile($dirfh, 0);
            close $dirfh;
        };
        $dir_error = $@ if $@;
    });

    run_request();
    like $dir_error, qr/not a regular file|fstat|is a directory/i, "Directory sendfile: caught error";

    # Restore original handler
    $evh->request_handler($saved_handler) if $saved_handler;
}

#######################################################################
# Test 8: sendfile with closed handle (should error)
#######################################################################

{
    my $closed_error = '';
    $evh->request_handler(sub {
        my $r = shift;
        my $w = $r->start_streaming("200 OK", ['Content-Type' => 'text/plain']);
        eval {
            open my $fh, '<', $file or die "open: $!";
            close $fh;  # Close before sendfile
            $w->sendfile($fh, 0);
        };
        $closed_error = $@ if $@;
    });

    run_request();
    like $closed_error, qr/Bad file descriptor|fileno|invalid|closed/i, "Closed handle sendfile: caught error";
}

pass "all sendfile error tests completed";
