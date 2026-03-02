#!perl
use warnings;
use strict;
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 2 : 1);
use Test::More;
use File::Temp qw(tempfile);
use lib 't'; use Utils;

use Feersum;

unless ($^O eq 'linux') {
    plan skip_all => 'sendfile() is only supported on Linux';
}

my $evh = Feersum->new();

plan skip_all => "Feersum not compiled with TLS support"
    unless $evh->has_tls();

my $cert_file = 'eg/ssl-proxy/server.crt';
my $key_file  = 'eg/ssl-proxy/server.key';

plan skip_all => "no test certificates ($cert_file / $key_file)"
    unless -f $cert_file && -f $key_file;

eval { require IO::Socket::SSL; 1 }
    or plan skip_all => "IO::Socket::SSL not installed";
plan skip_all => "OpenSSL too old for TLS 1.3 client" unless tls_client_ok();

# Create test file with known content
my ($tmp_fh, $tmp_file) = tempfile(UNLINK => 1);
my $file_content = "Hello from sendfile over TLS!\n" x 100;
print $tmp_fh $file_content;
close $tmp_fh;
my $file_size = -s $tmp_file;
ok $file_size > 0, "test file created ($file_size bytes)";

my ($socket, $port) = get_listen_socket();
ok $socket, "got listen socket on port $port";

$evh->use_socket($socket);

eval { $evh->set_tls(cert_file => $cert_file, key_file => $key_file) };
is $@, '', "set_tls with valid cert/key";

$evh->request_handler(sub {
    my $r = shift;
    open my $fh, '<', $tmp_file or die "open: $!";
    my $w = $r->start_streaming("200 OK", [
        'Content-Type'   => 'text/plain',
        'Content-Length' => $file_size,
        'Connection'     => 'close',
    ]);
    $w->sendfile($fh);
    close $fh;
});

my $pid = fork();
die "fork failed: $!" unless defined $pid;

if ($pid == 0) {
    select(undef, undef, undef, 0.3 * TIMEOUT_MULT);

    my $client = IO::Socket::SSL->new(
        PeerAddr        => '127.0.0.1',
        PeerPort        => $port,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
        Timeout         => 5 * TIMEOUT_MULT,
    );
    unless ($client) {
        warn "TLS connect failed: " . IO::Socket::SSL::errstr() . "\n";
        exit(1);
    }

    $client->print(
        "GET /file HTTP/1.1\r\n" .
        "Host: localhost:$port\r\n" .
        "Connection: close\r\n" .
        "\r\n"
    );

    my $response = '';
    while (1) {
        my $buf;
        my $n = $client->sysread($buf, 8192);
        last if !defined($n) || $n == 0;
        $response .= $buf;
    }
    $client->close(SSL_no_shutdown => 1);

    # Extract body after headers
    my ($headers, $body) = split(/\r\n\r\n/, $response, 2);
    $body //= '';

    unless ($headers =~ /200 OK/) {
        warn "Bad status: $headers\n";
        exit(2);
    }
    unless (length($body) == $file_size) {
        warn "Body size mismatch: got " . length($body) . " expected $file_size\n";
        exit(3);
    }
    unless ($body eq $file_content) {
        warn "Body content mismatch\n";
        exit(4);
    }

    exit(0);
}

my $cv = AE::cv;
my $child_status;
my $timeout = AE::timer(15 * TIMEOUT_MULT, 0, sub {
    diag "timeout waiting for TLS sendfile client";
    $cv->send('timeout');
});
my $child_w = AE::child($pid, sub {
    my ($pid, $status) = @_;
    $child_status = $status >> 8;
    $cv->send('child_done');
});

my $reason = $cv->recv;
isnt $reason, 'timeout', "sendfile test did not timeout";
is $child_status, 0, "TLS sendfile client received correct file content";

done_testing;
