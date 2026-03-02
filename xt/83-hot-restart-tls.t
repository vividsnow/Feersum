#!perl
# hot_restart + TLS: cert propagation across generations
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More;
use utf8;
use lib 't'; use Utils;
use File::Temp qw(tempdir);
use POSIX ();

BEGIN {
    require Feersum;
    my $f = Feersum->endjinn;
    plan skip_all => "TLS not compiled in" unless $f->has_tls();
    eval { require IO::Socket::SSL; 1 }
        or plan skip_all => "IO::Socket::SSL not available";
    plan tests => 6;
}

my $parent_pid = $$;
END { $? = 0 if $$ != $parent_pid }

my $cert = 'eg/ssl-proxy/server.crt';
my $key  = 'eg/ssl-proxy/server.key';
plan skip_all => "test certs not found" unless -f $cert && -f $key;

sub tls_get {
    my ($port, $timeout) = @_;
    $timeout //= 3 * TIMEOUT_MULT;
    my $sock = IO::Socket::SSL->new(
        PeerAddr        => "localhost:$port",
        SSL_verify_mode => 0,
        Timeout         => $timeout,
    ) or return undef;
    print $sock "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    local $/;
    my $resp = <$sock>;
    close $sock;
    return undef unless $resp && $resp =~ /^HTTP\/[\d.]+ 200/;
    $resp =~ /\r\n\r\n(.*)$/s;
    return $1;
}

my $dir = tempdir(CLEANUP => 1);
my $app_file = "$dir/tlsapp.feersum";
open my $fh, '>', $app_file or die;
print $fh 'sub { $_[0]->send_response(200,["Content-Type"=>"text/plain"],\"pid=$$\n") }';
close $fh;

my ($sock, $port) = get_listen_socket();
close $sock;

my $master = fork // die "fork: $!";
if (!$master) {
    require Feersum::Runner;
    eval {
        Feersum::Runner->new(
            listen      => ["localhost:$port"],
            app_file    => $app_file,
            hot_restart => 1,
            tls         => { cert_file => $cert, key_file => $key },
            quiet       => 1,
        )->run();
    };
    warn "master error: $@" if $@;
    POSIX::_exit(0);
}

select undef, undef, undef, 2.0 * TIMEOUT_MULT;

my $body1 = tls_get($port);
ok $body1, "gen1 responds over TLS";
my ($pid1) = ($body1 // '') =~ /pid=(\d+)/;
ok $pid1, "got gen1 pid ($pid1)";

# HUP — new generation should also have TLS
kill 'HUP', $master;
select undef, undef, undef, 2.5 * TIMEOUT_MULT;

my $body2 = tls_get($port);
ok $body2, "gen2 responds over TLS after HUP";
my ($pid2) = ($body2 // '') =~ /pid=(\d+)/;
ok $pid2, "got gen2 pid ($pid2)";
isnt $pid2, $pid1, "generation changed (TLS config propagated)";

kill 'QUIT', $master;
waitpid $master, 0;
pass "hot_restart+TLS clean shutdown";
