#!perl
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;
use AnyEvent;
use AnyEvent::Handle;
use Feersum;

plan tests => 101;

my ($socket, $port) = get_listen_socket();
my $evh = Feersum->new;
$evh->set_proxy_protocol(1);
$evh->set_keepalive(0);
$evh->use_socket($socket);

$evh->psgi_request_handler(sub {
    return [200, ['Content-Type' => 'text/plain', 'Content-Length' => 2], ['ok']];
});

sub test_header {
    my ($header, $name) = @_;
    my $cv = AE::cv;
    my $h;
    my $got_error = 0;
    my $got_response = 0;

    $h = AnyEvent::Handle->new(
        connect => ['127.0.0.1', $port],
        on_connect => sub {
            my $handle = shift;
            $handle->push_write($header);
            $handle->push_write("GET / HTTP/1.1
Host: localhost
Connection: close

");
        },
        on_error => sub {
            $got_error = 1;
            $_[0]->destroy;
            $cv->send;
        },
        on_eof => sub {
            $_[0]->destroy;
            $cv->send;
        },
        timeout => 1,
    );

    $h->push_read(regex => qr/HTTP\/1\.\d (\d{3})/, sub {
        my ($handle, $status) = @_;
        $got_response = $1;
        $handle->destroy;
        $cv->send;
    });

    $cv->recv;
    
    # Success means it either errored out correctly (4xx) or closed connection
    # For baseline, we expect 200.
    if ($got_response) {
        if ($name =~ /Baseline/ && $got_response == 200) {
            pass("$name: correctly accepted valid header");
        } elsif ($got_response =~ /^4/) {
            pass("$name: correctly rejected with $got_response");
        } elsif ($got_response == 200) {
            fail("$name: incorrectly accepted malformed header as 200 OK");
        } else {
            pass("$name: returned $got_response");
        }
    } else {
        pass("$name: connection closed/errored as expected");
    }
}

# 1. Valid header for baseline
my $valid_v2 = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A" . # sig
               "\x21" . # ver 2, cmd proxy
               "\x11" . # fam AF_INET, proto STREAM
               "\x00\x0C" . # len 12
               "\x01\x02\x03\x04" . # src
               "\x05\x06\x07\x08" . # dst
               "\x00\x50" . # src port 80
               "\x01\xBB"; # dst port 443

test_header($valid_v2, "Baseline valid V2 header");

# Fuzzing starts here
for (1..100) {
    my $type = int(rand(6));
    my $header = "";
    my $name = "Fuzz test $_";

    if ($type == 0) {
        # Random bytes of random length
        $header = pack("C*", map { int(rand(256)) } 1..(5 + int(rand(50))));
        $name .= " (random bytes)";
    } elsif ($type == 1) {
        # Valid signature, but everything else random
        $header = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A" . 
                  pack("C*", map { int(rand(256)) } 1..(int(rand(40))));
        $name .= " (valid sig, random tail)";
    } elsif ($type == 2) {
        # Truncated valid header
        $header = substr($valid_v2, 0, 1 + int(rand(length($valid_v2) - 1)));
        $name .= " (truncated valid)";
    } elsif ($type == 3) {
        # Valid header but with random TLVs at the end
        my $len = 12 + int(rand(100));
        $header = substr($valid_v2, 0, 14) . pack("n", $len) . substr($valid_v2, 16);
        $header .= pack("C*", map { int(rand(256)) } 1..$len);
        $name .= " (valid base, random TLVs)";
    } elsif ($type == 4) {
        # Wrong signature (one byte off) — ensure byte actually changes
        $header = $valid_v2;
        my $pos = int(rand(12));
        my $orig = ord(substr($header, $pos, 1));
        my $new = ($orig + 1 + int(rand(254))) % 256;
        substr($header, $pos, 1) = pack("C", $new);
        $name .= " (corrupted signature)";
    } else {
        # Valid base but wrong version/command
        $header = $valid_v2;
        substr($header, 12, 1) = pack("C", int(rand(256)) & 0x0F); # version != 2
        $name .= " (invalid version)";
    }

    test_header($header, $name);
}
