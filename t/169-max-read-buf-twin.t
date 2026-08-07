#!perl
# max_read_buf bounds the HEADER BLOCK (and chunked reception), not the whole
# read buffer: a declared Content-Length body is bounded by max_body_len
# instead.  Both H1 transports must agree, and they used to disagree in both
# directions under one setting:
#
#   plain rejected on where the next 16K growth step would land, so any
#   max_read_buf under ~20K collapsed to a hard 4K header cap;
#   TLS measured SvCUR before parsing, and one decrypt burst carries the body
#   too, so a 9KB upload became "431 Request Header Fields Too Large".
#
# t/32c covers the body case on TLS but happened to pick a body size whose
# record split landed in a passing window, so the divergence survived it.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 4 : 1);
use Test::More;
use lib 't'; use Utils;
use IO::Socket::INET;
use POSIX ();
use Socket qw(SOMAXCONN);

my $cert = 'eg/ssl-proxy/server.crt';
my $key  = 'eg/ssl-proxy/server.key';

my $tls_ok;
BEGIN {
    require Feersum;
    $tls_ok = Feersum->endjinn->has_tls()
           && (eval { require IO::Socket::SSL; require Net::SSLeay; 1 } || 0)
           && tls_client_ok()
           && -f 'eg/ssl-proxy/server.crt' && -f 'eg/ssl-proxy/server.key';
    plan tests => 8;
}

use constant MRB => 8192;

sub spawn {
    my ($tls) = @_;
    my ($lsn, $port) = get_listen_socket();
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';
        my $f = Feersum->new_instance();
        $f->use_socket($lsn);
        $f->set_tls(cert_file => $cert, key_file => $key) if $tls;
        $f->max_read_buf(MRB);
        $f->read_timeout(10 * TIMEOUT_MULT);
        $f->request_handler(sub {
            $_[0]->send_response("200 OK", ['Content-Length' => 2], "OK");
        });
        EV::run();
        POSIX::_exit(0);
    }
    close $lsn;
    return ($pid, $port);
}

my ($ppid, $pport) = spawn(0);
my ($tpid, $tport) = $tls_ok ? spawn(1) : ();
select undef, undef, undef, 1 * TIMEOUT_MULT;

sub status {
    my ($tls, $req) = @_;
    my $s = $tls
        ? IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $tport,
              SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
              SSL_alpn_protocols => ['http/1.1'], Timeout => 5 * TIMEOUT_MULT)
        : IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $pport,
              Proto => 'tcp', Timeout => 5 * TIMEOUT_MULT);
    return 'CONNFAIL' unless $s;
    print $s $req;
    my $raw = '';
    eval { local $SIG{ALRM} = sub { die "to\n" }; alarm 8 * TIMEOUT_MULT;
           while (sysread($s, my $c, 4096)) {
               $raw .= $c; last if $raw =~ /\r\n\r\n/;
           }
           alarm 0; 1 } or alarm 0;
    close $s;
    my ($code) = $raw =~ m{^HTTP/1\.[01] (\d\d\d)};
    return $code || 'NORESP';
}

sub body_req {
    my ($n) = @_;
    return "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: $n\r\n"
         . "Connection: close\r\n\r\n" . ('x' x $n);
}
sub header_req {
    my ($n) = @_;
    return "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " . ('p' x $n)
         . "\r\nConnection: close\r\n\r\n";
}

# name => [request, expected status]
my @CASES = (
    ['a declared-CL body far above max_read_buf' => body_req(20000),   '200'],
    ['a small header block'                      => header_req(3000),  '200'],
    ['a header block just under max_read_buf'    => header_req(7000),  '200'],
    ['a header block far above max_read_buf'     => header_req(30000), '431'],
);

for my $c (@CASES) {
    my ($name, $req, $want) = @$c;
    is status(0, $req), $want, "plain: $name -> $want";
}

SKIP: {
    skip 'no TLS client available', 4 unless $tls_ok;
    for my $c (@CASES) {
        my ($name, $req, $want) = @$c;
        is status(1, $req), $want, "TLS twin: $name -> $want";
    }
}

kill 'QUIT', grep { defined } $ppid, $tpid;
waitpid($_, 0) for grep { defined } $ppid, $tpid;
