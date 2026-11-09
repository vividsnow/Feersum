#!perl
# A body element's DESTROY that writes to its own connection must not put its
# bytes on the wire ahead of those queued before it.
use warnings;
use strict;
use Test::More;
use lib 't'; use Utils;

BEGIN {
    require Feersum;
    my $f = Feersum->endjinn;
    plan skip_all => "TLS not compiled in" unless $f->has_tls();
    eval { require IO::Socket::SSL; 1 }
        or plan skip_all => "IO::Socket::SSL not available";
    plan skip_all => "OpenSSL too old for TLS 1.3 client" unless tls_client_ok();
    plan skip_all => "test certs not found"
        unless -f 't/certs/alpha.crt' && -f 't/certs/alpha.key';
    plan tests => 3;
}

use IO::Socket::SSL;
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);

my ($sock, $port) = get_listen_socket();
die "listen: $!" unless $sock;

my $f = Feersum->endjinn;
$f->use_socket($sock);
$f->set_tls(cert_file => 't/certs/alpha.crt', key_file => 't/certs/alpha.key', h2 => 0);

our $W;
{
    package Feersum::Test::LateWriter;
    sub DESTROY { $main::W->write("LATE") if $main::W }
}

$f->request_handler(sub {
    my $r = shift;
    $W = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
    my $o = do { my $s = "AAA"; bless \$s, 'Feersum::Test::LateWriter' };
    $W->write($o);
    undef $o;   # the write queue now holds the referent's last reference
    my $t; $t = EV::timer(0.3 * TMULT, 0, sub {
        undef $t;
        $W->write("ZZZ");
        $W->close;
        undef $W;
    });
});

my $pid = fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    $SIG{QUIT} = 'DEFAULT';
    my $life = EV::timer(30 * TMULT, 0, sub { POSIX::_exit(0) });
    EV::run;
    POSIX::_exit(0);
}
my $cleanup = guard { reap_server($pid) };
close $sock;

my $cl = IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $port,
    SSL_verify_mode => 0, Timeout => 10 * TMULT);
ok $cl, 'TLS client connected';

my $all = '';
if ($cl) {
    print {$cl} "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 10 * TMULT;
        while (my $n = $cl->sysread(my $buf, 65536)) {
            $all .= $buf;
            last if $all =~ /\r\n0\r\n\r\n\z/;
        }
        alarm 0;
    };
    alarm 0;
}

like $all, qr{\AHTTP/1\.1 200 }, 'the status line reaches the wire first';

my ($body) = $all =~ /\r\n\r\n(.*)\z/s;
my @chunks;
$body //= '';
while ($body =~ s/\A([0-9a-fA-F]+)\r\n//) {
    my $len = hex $1;
    last unless $len;
    push @chunks, substr($body, 0, $len);
    substr($body, 0, $len + 2) = '';
}
# LATE is only ever written by DESTROY, so its presence proves DESTROY ran
is join(',', @chunks), 'AAA,LATE,ZZZ',
    'a write from DESTROY lands after the bytes queued before it';
