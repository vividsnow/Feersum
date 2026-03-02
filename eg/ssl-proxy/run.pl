#!/usr/bin/env perl
# Run Feersum backend + stunnel SSL frontend with PROXY Protocol v2
#
# Usage: perl eg/ssl-proxy/run.pl
#
# Test:
#   curl -k https://localhost:8443/        # Home page
#   curl -k https://localhost:8443/info    # Connection info from PROXY protocol
#
# This demonstrates L4 TLS termination with PROXY Protocol:
#   1. Client connects via HTTPS to stunnel (port 8443)
#   2. Stunnel terminates TLS, sends PROXY v2 header with client IP + SSL info
#   3. Feersum receives PROXY header, sets:
#      - REMOTE_ADDR = real client IP
#      - psgi.url_scheme = "https" (from PP2_TYPE_SSL TLV)
#
use strict;
use warnings;
use FindBin;

chdir "$FindBin::Bin/../..";
system 'eg/ssl-proxy/gen-cert.sh' unless -f 'eg/ssl-proxy/server.crt';

my $backend = fork // die; exec 'perl', '-Mblib', 'eg/ssl-proxy/backend.pl' unless $backend;
sleep 1;
my $stunnel = fork // die; exec 'stunnel', 'eg/ssl-proxy/stunnel.conf' unless $stunnel;

$SIG{$_} = sub { kill 9, $backend, $stunnel; exit } for qw(INT TERM);
print "Backend PID: $backend\n";
print "Stunnel PID: $stunnel\n";
print "\nTest endpoints:\n";
print "  curl -k https://localhost:8443/       # Home page\n";
print "  curl -k https://localhost:8443/info   # Connection info (shows PROXY protocol data)\n";
waitpid -1, 0 while wait > 0;
