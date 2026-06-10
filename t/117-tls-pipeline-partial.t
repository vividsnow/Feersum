#!perl
# When a keepalive response completes and unread bytes are still buffered,
# handle_keepalive_or_close re-enters the read callback directly and returns,
# skipping the start_read_watcher() the non-pipelined path does.  That is fine
# for plain HTTP - try_conn_read arms the watcher itself on its
# "need more data" exit - but try_tls_conn_read never arms a watcher.  So if
# the pipelined bytes were only PART of the next request, the bytes completing
# it never woke the server and the request hung until read_timeout killed the
# connection.  Plain HTTP answered the same sequence instantly.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 4 : 1);
use Test::More;
use Socket qw(AF_INET SOCK_STREAM);
use Time::HiRes qw(time);
use lib 't'; use Utils;
use Feersum;

my $evh = Feersum->new();
plan skip_all => "Feersum not compiled with TLS support" unless $evh->has_tls();

my $cert = 'eg/ssl-proxy/server.crt';
my $key  = 'eg/ssl-proxy/server.key';
plan skip_all => "no test certificates" unless -f $cert && -f $key;
eval { require IO::Socket::SSL; 1 }
    or plan skip_all => "IO::Socket::SSL not installed";
plan skip_all => "OpenSSL too old for TLS 1.3 client" unless tls_client_ok();

plan tests => 4;

use AnyEvent;
use EV;

my ($socket, $port) = get_listen_socket();
ok $socket, "listen on $port";

# read_timeout is the fallback that used to (eventually) end the stuck
# connection.  Keep it well above the deadline we assert so a pass cannot come
# from the timeout firing.
my $READ_TIMEOUT = 10 * TIMEOUT_MULT;

$evh->use_socket($socket);
$evh->set_tls(cert_file => $cert, key_file => $key);
$evh->set_keepalive(1);
$evh->read_timeout($READ_TIMEOUT);
$evh->psgi_request_handler(sub {
    my $env = shift;
    return [200, ['Content-Type' => 'text/plain'],
            ["got $env->{PATH_INFO}\n"]];
});

pipe(my $rpt_r, my $rpt_w) or die "pipe: $!";

my $pid = fork();
die "fork: $!" unless defined $pid;

if (!$pid) {
    close $rpt_r;
    my $report = sub { syswrite($rpt_w, "$_[0]\n"); exit 0 };
    select undef, undef, undef, 0.3;
    socket(my $s, AF_INET, SOCK_STREAM, 0) or $report->("ERR socket");
    connect($s, Socket::pack_sockaddr_in($port, Socket::inet_aton('127.0.0.1')))
        or $report->("ERR connect");
    IO::Socket::SSL->start_SSL($s, SSL_verify_mode => 0)
        or $report->("ERR handshake");

    # Request A complete, plus the first part of request B - one write, so for
    # TLS one record.  B is deliberately incomplete: no terminating blank line.
    syswrite($s, "GET /A HTTP/1.1\r\nHost: localhost\r\n\r\n"
               . "GET /B HTTP/1.1\r\nHost: localhost\r\n")
        or $report->("ERR write");

    my $buf = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 8 * TIMEOUT_MULT;
        while ($buf !~ m{got /A}) {
            my $n = sysread($s, my $b, 4096);
            last unless $n;
            $buf .= $b;
        }
        alarm 0; 1;
    } or $report->("ERR no-A");
    $buf =~ m{got /A} or $report->("ERR no-A");

    select undef, undef, undef, 0.5;

    # Complete B.  Pre-fix nothing was watching this descriptor, so these two
    # bytes were never noticed.
    my $t0 = time;
    syswrite($s, "\r\n") or $report->("ERR write2");
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 8 * TIMEOUT_MULT;
        while ($buf !~ m{got /B}) {
            my $n = sysread($s, my $b, 4096);
            last unless $n;
            $buf .= $b;
        }
        alarm 0; 1;
    } or $report->(sprintf "STUCK %.2f", time - $t0);
    $buf =~ m{got /B} or $report->(sprintf "STUCK %.2f", time - $t0);
    $report->(sprintf "OK %.2f", time - $t0);
}

close $rpt_w;

my $cv = AE::cv;
my $line = '';
my $io_w = AE::io($rpt_r, 0, sub {
    my $n = sysread($rpt_r, my $b, 1024);
    if (!defined($n) || $n == 0) { $cv->send }
    else { $line .= $b; $cv->send if $line =~ /\n/ }
});
my $bail = AE::timer 40 * TIMEOUT_MULT, 0, sub { $line ||= "ERR parent-timeout"; $cv->send };
$cv->recv;
chomp $line;

my ($verdict, $elapsed) = split ' ', $line, 2;
$elapsed = 'n/a' unless defined $elapsed;

is $verdict, 'OK', "the completing bytes of a pipelined TLS request wake the server"
    or diag "client reported: $line";

# The load-bearing assertion: it must be answered promptly, not eventually.
# A pass here cannot come from read_timeout, which is $READ_TIMEOUT seconds.
cmp_ok $elapsed, '<', 2 * TIMEOUT_MULT,
    "second request answered promptly (${elapsed}s), not via read_timeout";

waitpid $pid, 0;
is $?, 0, "client exited cleanly";
