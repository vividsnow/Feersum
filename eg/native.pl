#!/usr/bin/env perl
# Native Feersum server example (maximum performance)
#
# Usage: perl eg/native.pl [/path/to/socket]
#        perl eg/native.pl /tmp/feersum.sock
#
use warnings;
use strict;
use Feersum;
use IO::Socket::UNIX;

my $path = shift || '/tmp/feersum.sock';
unlink $path if -e $path;

my $socket = IO::Socket::UNIX->new(
    Local    => $path,
    Type     => SOCK_STREAM,
    Listen   => 1024,
    Blocking => 0,
) or die "Cannot listen on $path: $!\n";

my $evh = Feersum->new();
$evh->use_socket($socket);
$evh->set_keepalive(1);
$evh->header_timeout(30);

my $counter = 0;
$evh->request_handler(sub {
    my $r = shift;
    my $n = $counter++;
    $r->send_response(200, [
        'Content-Type' => 'text/plain',
    ], \"Hello customer number $n\n");
});

print "Feersum native server listening on unix:$path\n";
EV::run;
END { unlink $path if -e $path }
