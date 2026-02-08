use strict;
use warnings;
use Test::More;
use blib;
use Feersum;

# Check TLS support at compile time
my $evh = Feersum->new();

plan skip_all => "Feersum not compiled with TLS support"
    unless $evh->has_tls();

diag "TLS support: " . ($evh->has_tls() ? "yes" : "no");
diag "H2 support: " . ($evh->has_h2() ? "yes" : "no");

# Test has_tls / has_h2 return values
ok $evh->has_tls(), "has_tls returns true";
# has_h2 depends on Alien::nghttp2 being available at build time
ok defined($evh->has_h2()), "has_h2 returns defined value";

# Test set_tls requires listeners
eval { $evh->set_tls(cert_file => '/nonexistent.crt', key_file => '/nonexistent.key') };
like $@, qr/no listeners/, "set_tls requires listeners";

# Test set_tls parameter validation
my ($socket, $port);
{
    require IO::Socket::INET;
    require Socket;
    for my $p (10000..20000) {
        my $s = IO::Socket::INET->new(
            LocalAddr => "localhost:$p",
            ReuseAddr => 1,
            Proto => 'tcp',
            Listen => Socket::SOMAXCONN(),
            Blocking => 0,
        );
        if ($s) {
            ($socket, $port) = ($s, $p);
            last;
        }
    }
}

SKIP: {
    skip "couldn't bind socket", 3 unless $socket;

    # Create a fresh server for socket tests
    my $evh2 = Feersum->new_instance();
    $evh2->use_socket($socket);

    eval { $evh2->set_tls() };
    like $@, qr/key => value/, "set_tls requires key/value pairs";

    eval { $evh2->set_tls(cert_file => 'server.crt') };
    like $@, qr/key_file/, "set_tls requires key_file";

    eval { $evh2->set_tls(key_file => 'server.key') };
    like $@, qr/cert_file/, "set_tls requires cert_file";

    # Test with nonexistent files
    eval { $evh2->set_tls(cert_file => '/nonexistent.crt', key_file => '/nonexistent.key') };
    like $@, qr/failed/, "set_tls fails with nonexistent cert";
}

# Test with real certificate files if available
SKIP: {
    my $cert_file = 'eg/ssl-proxy/server.crt';
    my $key_file  = 'eg/ssl-proxy/server.key';
    skip "no test certificates", 1 unless -f $cert_file && -f $key_file;
    skip "couldn't bind socket", 1 unless $socket;

    my $evh3 = Feersum->new_instance();
    my $socket3 = IO::Socket::INET->new(
        LocalAddr => "localhost:0",
        ReuseAddr => 1,
        Proto => 'tcp',
        Listen => Socket::SOMAXCONN(),
        Blocking => 0,
    );
    skip "couldn't bind second socket", 1 unless $socket3;

    $evh3->use_socket($socket3);
    eval { $evh3->set_tls(cert_file => $cert_file, key_file => $key_file) };
    is $@, '', "set_tls succeeds with valid cert/key";
}

done_testing;
