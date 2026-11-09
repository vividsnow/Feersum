#!perl
# Byte-exact transfer across TLS record, read and short-write boundaries, up and
# down.
use warnings;
use strict;
use Test::More;
use lib 't'; use Utils;

BEGIN {
    require Feersum;
    plan skip_all => "TLS not compiled in" unless Feersum->endjinn->has_tls();
    eval { require IO::Socket::SSL; 1 }
        or plan skip_all => "IO::Socket::SSL not available";
    plan skip_all => "OpenSSL too old for TLS 1.3 client" unless tls_client_ok();
    plan skip_all => "test certs not found"
        unless -f 't/certs/alpha.crt' && -f 't/certs/alpha.key';
    plan tests => 5;
}

use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_SNDBUF SO_RCVBUF);
use Digest::MD5 qw(md5_hex);
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use constant SIZE => 4 << 20;

# position-dependent, so a misplaced or repeated block cannot go unnoticed
my $payload = join '', map { sprintf "%07d\n", $_ } 0 .. SIZE / 8 - 1;
my $md5 = md5_hex($payload);

my ($sock, $port) = get_listen_socket();
ok $sock, "listening on $port";
setsockopt($sock, SOL_SOCKET, SO_SNDBUF, pack 'i', 16384);

my $pid = fork();
die "fork: $!" unless defined $pid;
if (!$pid) {
    $SIG{QUIT} = 'DEFAULT';
    my $f = Feersum->new_instance;
    $f->use_socket($sock);
    $f->set_tls(cert_file => 't/certs/alpha.crt', key_file => 't/certs/alpha.key', h2 => 0);
    $f->max_body_len(SIZE * 2);
    $f->request_handler(sub {
        my $r = shift;
        if ($r->method eq 'GET') {
            $r->send_response(200, ['Content-Type' => 'text/plain'], [$payload]);
            return;
        }
        my $env = $r->env;
        my $in  = $env->{'psgi.input'};
        my $cl   = $env->{CONTENT_LENGTH};
        my $body = '';
        while (length($body) < $cl) {   # read() appends
            last unless $in->read($body, $cl - length $body);
        }
        $r->send_response(200, ['Content-Type' => 'text/plain'],
            [length($body) . ' ' . md5_hex($body)]);
    });
    my $life = EV::timer(60 * TMULT, 0, sub { EV::break() });
    EV::run();
    POSIX::_exit(0);
}
my $cleanup = guard { reap_server($pid) };
close $sock;

sub tls_conn {
    my (%opt) = @_;
    my $tcp = IO::Socket::INET->new(Proto => 'tcp') or return;
    setsockopt($tcp, SOL_SOCKET, SO_RCVBUF, pack 'i', $opt{rcvbuf}) if $opt{rcvbuf};
    connect($tcp, Socket::pack_sockaddr_in($port, Socket::inet_aton('127.0.0.1'))) or return;
    return IO::Socket::SSL->start_SSL($tcp, SSL_verify_mode => 0, Timeout => 10 * TMULT);
}

sub read_response {
    my ($c, $pause) = @_;
    my ($resp, $want) = ('', undef);
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm 30 * TMULT;
    eval {
        while (!defined $want || length($resp) < $want) {
            my $n = sysread($c, $resp, 4096, length $resp);
            last unless $n;
            if (!defined $want && (my $at = index($resp, "\r\n\r\n")) >= 0) {
                my ($cl) = substr($resp, 0, $at) =~ /^Content-Length:\s*(\d+)/mi;
                $want = $at + 4 + ($cl // 0);
            }
            select undef, undef, undef, $pause if $pause;
        }
    };
    alarm 0;
    my $at = index($resp, "\r\n\r\n");
    return $at < 0 ? '' : substr($resp, $at + 4);
}

sub upload {
    my ($record) = @_;
    my $c = tls_conn() or return '';
    print {$c} "POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: " . SIZE . "\r\n\r\n";
    for (my $o = 0; $o < SIZE; $o += $record) {
        my $piece = substr($payload, $o, $record);
        for (my $w = 0; $w < length $piece;) {
            my $n = syswrite($c, $piece, length($piece) - $w, $w);
            return '' unless $n;
            $w += $n;
        }
    }
    return read_response($c);
}

is upload(512), SIZE . " $md5", 'upload in 512-byte records arrives intact';
is upload(16384), SIZE . " $md5", 'upload in full-size records arrives intact';
is upload(5000), SIZE . " $md5", 'upload in odd-sized records arrives intact';

my $c = tls_conn(rcvbuf => 8192);
print {$c} "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" if $c;
my $got = $c ? read_response($c, 0.0005) : '';
ok length($got) == SIZE && md5_hex($got) eq $md5,
    'download drained in short writes arrives intact'
    or diag 'got ' . length($got) . ' bytes';
