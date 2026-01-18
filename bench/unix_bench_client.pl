#!/usr/bin/env perl
# Custom benchmark client for Unix sockets
# wrk doesn't support Unix sockets, so we need our own client
use strict;
use warnings;
use IO::Socket::UNIX;
use Time::HiRes qw(time);
use Getopt::Long;
use POSIX qw(:sys_wait_h);

my $socket_path = '/tmp/feersum_bench.sock';
my $duration = 10;
my $concurrency = 50;
my $keepalive = 1;

GetOptions(
    'socket=s' => \$socket_path,
    'duration=i' => \$duration,
    'concurrency=i' => \$concurrency,
    'keepalive!' => \$keepalive,
) or die "Usage: $0 [--socket PATH] [--duration SECS] [--concurrency N] [--keepalive|--no-keepalive]\n";

my $request = "GET / HTTP/1.1\r\nHost: localhost\r\n";
$request .= $keepalive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n";

# Fork workers
my @pids;
my @pipes;

for my $i (0 .. $concurrency - 1) {
    pipe(my $read, my $write) or die "pipe: $!";
    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
        # Child worker
        close $read;
        my $requests = 0;
        my $bytes = 0;
        my $errors = 0;
        my $end_time = time() + $duration;

        while (time() < $end_time) {
            my $sock = IO::Socket::UNIX->new(
                Peer => $socket_path,
            );
            unless ($sock) {
                $errors++;
                next;
            }

            if ($keepalive) {
                # Reuse connection for multiple requests
                my $reqs_per_conn = 100;
                for (1 .. $reqs_per_conn) {
                    last if time() >= $end_time;

                    print $sock $request;

                    # Read response
                    my $response = '';
                    my $content_length = 0;
                    my $headers_done = 0;

                    while (my $line = <$sock>) {
                        $response .= $line;
                        if (!$headers_done) {
                            if ($line =~ /^Content-Length:\s*(\d+)/i) {
                                $content_length = $1;
                            }
                            if ($line eq "\r\n") {
                                $headers_done = 1;
                                if ($content_length > 0) {
                                    my $body;
                                    read($sock, $body, $content_length);
                                    $response .= $body;
                                }
                                last;
                            }
                        }
                    }

                    if ($response =~ /^HTTP\/1\.[01] 200/) {
                        $requests++;
                        $bytes += length($response);
                    } else {
                        $errors++;
                        last;  # Connection probably closed
                    }
                }
            } else {
                # Single request per connection
                print $sock $request;

                local $/;
                my $response = <$sock>;

                if ($response && $response =~ /^HTTP\/1\.[01] 200/) {
                    $requests++;
                    $bytes += length($response);
                } else {
                    $errors++;
                }
            }

            close $sock;
        }

        print $write "$requests $bytes $errors\n";
        close $write;
        exit 0;
    }

    # Parent
    close $write;
    push @pids, $pid;
    push @pipes, $read;
}

# Wait for all workers
my $total_requests = 0;
my $total_bytes = 0;
my $total_errors = 0;

for my $i (0 .. $#pids) {
    waitpid($pids[$i], 0);
    my $line = readline($pipes[$i]);
    if ($line && $line =~ /^(\d+) (\d+) (\d+)/) {
        $total_requests += $1;
        $total_bytes += $2;
        $total_errors += $3;
    }
    close $pipes[$i];
}

# Print results
my $rps = $total_requests / $duration;
my $throughput = $total_bytes / $duration / 1024 / 1024;

print "\n";
print "Results:\n";
print "  Duration:     ${duration}s\n";
print "  Concurrency:  $concurrency\n";
print "  Keepalive:    " . ($keepalive ? "yes" : "no") . "\n";
print "\n";
printf "  Requests:     %d (%.2f req/s)\n", $total_requests, $rps;
printf "  Throughput:   %.2f MB/s\n", $throughput;
printf "  Errors:       %d\n", $total_errors;
print "\n";
