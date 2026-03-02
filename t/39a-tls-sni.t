#!perl
# TLS SNI: multiple certificates on one listener, dispatched by hostname
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More;
use lib 't'; use Utils;

BEGIN {
    require Feersum;
    my $f = Feersum->endjinn;
    plan skip_all => "TLS not compiled in" unless $f->has_tls();
    eval { require IO::Socket::SSL; 1 }
        or plan skip_all => "IO::Socket::SSL not available";
    plan skip_all => "OpenSSL too old for TLS 1.3 client" unless tls_client_ok();
    plan tests => 5;
}

my $alpha_cert = 't/certs/alpha.crt';
my $alpha_key  = 't/certs/alpha.key';
my $beta_cert  = 't/certs/beta.crt';
my $beta_key   = 't/certs/beta.key';

for ($alpha_cert, $alpha_key, $beta_cert, $beta_key) {
    plan skip_all => "test certs not found ($_)" unless -f $_;
}

use IO::Socket::INET;
use Socket qw(SOMAXCONN);

my $sock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    ReuseAddr => 1,
    Proto     => 'tcp',
    Listen    => SOMAXCONN,
    Blocking  => 0,
) or die "listen: $!";
my $port = $sock->sockport;

my $f = Feersum->endjinn;
$f->use_socket($sock);

# Default cert (alpha), SNI entry for beta
$f->set_tls(cert_file => $alpha_cert, key_file => $alpha_key);
$f->set_tls(sni => 'beta.local', cert_file => $beta_cert, key_file => $beta_key);

$f->request_handler(sub {
    my $r = shift;
    $r->send_response(200, ['Content-Type' => 'text/plain'], \"ok\n");
});

# Helper: connect with SNI hostname, return peer cert CN
sub get_cert_cn {
    my ($port, $hostname) = @_;
    my $cl = IO::Socket::SSL->new(
        PeerAddr        => "127.0.0.1:$port",
        SSL_hostname    => $hostname,
        SSL_verify_mode => 0,
        Timeout         => 3 * TIMEOUT_MULT,
    ) or return undef;
    my $cn = $cl->peer_certificate('cn');
    print $cl "GET / HTTP/1.0\r\nHost: $hostname\r\n\r\n";
    local $/;
    my $resp = <$cl>;
    close $cl;
    return $cn;
}

# Run event loop briefly in background via fork
my $pid = fork;
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    EV::default_loop()->loop_fork;
    my $t = EV::timer(5 * TIMEOUT_MULT, 0, sub { EV::break });
    EV::run;
    POSIX::_exit(0);
}

select undef, undef, undef, 1.0 * TIMEOUT_MULT;

# Test: connect with SNI=alpha.local → gets alpha cert (default)
my $cn1 = get_cert_cn($port, 'alpha.local');
is $cn1, 'alpha.local', "SNI alpha.local gets alpha cert";

# Test: connect with SNI=beta.local → gets beta cert (SNI match)
my $cn2 = get_cert_cn($port, 'beta.local');
is $cn2, 'beta.local', "SNI beta.local gets beta cert";

# Test: connect with unknown SNI → gets default (alpha) cert
my $cn3 = get_cert_cn($port, 'unknown.local');
is $cn3, 'alpha.local', "unknown SNI gets default (alpha) cert";

# Test: connect without SNI → gets default cert
my $cn4 = get_cert_cn($port, '');
# Empty hostname may or may not send SNI depending on IO::Socket::SSL version
ok $cn4, "connection without explicit SNI succeeds";
like $cn4, qr/alpha\.local/, "no-SNI gets default cert";

kill 'QUIT', $pid;
waitpid $pid, 0;
