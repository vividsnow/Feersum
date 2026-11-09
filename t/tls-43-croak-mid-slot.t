#!perl
# A croak while a write slot is being filled must leave nothing behind for the
# write path to free: reused slots once held another response's SVs.
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
    plan tests => 6;
}

use File::Temp qw(tempdir);
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);

my $dir = tempdir(CLEANUP => 1);
my ($sock, $port) = get_listen_socket();
ok $sock, "listening on $port";

{
    package Feersum::Test::Boom;
    use overload '""' => sub { my $s = shift; die "boom\n" if ++$$s == 2; 'abc' },
        fallback => 1;
}

my $pid = fork();
die "fork: $!" unless defined $pid;
if (!$pid) {
    $SIG{QUIT} = 'DEFAULT';
    open STDERR, '>', "$dir/err" or POSIX::_exit(9);
    my $f = Feersum->new_instance;
    $f->use_socket($sock);
    $f->set_tls(cert_file => 't/certs/alpha.crt', key_file => 't/certs/alpha.key', h2 => 0);
    my $n = 0;
    $f->request_handler(sub {
        my $r = shift;
        if ($r->path eq '/fill') {
            # many slots, freed back to the freelist with their SV pointers
            $r->send_response(200, ['Content-Type' => 'text/plain'],
                [ map { "element-$_-" . ('x' x 30) } 1 .. 50 ]);
        } else {
            my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
            my $count = 0;
            my $obj = bless \$count, 'Feersum::Test::Boom';
            my $ok = eval { $w->write_array([ \$obj ]); 1 };
            print STDERR "croaked: $@" unless $ok;
            my @churn = map { "junk$_" } 1 .. 200;   # reuse freed SV heads
            $w->write('tail');
            $w->close;
        }
        EV::break() if ++$n >= 4;
    });
    my $life = EV::timer(20 * TMULT, 0, sub { EV::break() });
    EV::run();
    POSIX::_exit(0);
}
close $sock;

sub fetch {
    my ($path) = @_;
    my $c = IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $port,
        SSL_verify_mode => 0, Timeout => 10 * TMULT) or return '';
    print {$c} "GET $path HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    local $/;
    my $resp = <$c> // '';
    close $c;
    return $resp;
}

my @r = map { fetch($_) } qw(/fill /croak /fill /croak);
# it exits by itself after the 4th request; a slow box may still be on its
# way out, and our own SIGQUIT must not read as a crash
my $status;
my $until = time + 10 * TMULT;
while (time < $until) {
    if (waitpid($pid, POSIX::WNOHANG()) > 0) { $status = $?; last }
    select undef, undef, undef, 0.05;
}
unless (defined $status) {
    reap_server($pid);
    $status = 0;
}
my $err = do { local $/; open my $e, '<', "$dir/err" or die; <$e> } // '';

like $r[1], qr/\r\n4\r\ntail\r\n0\r\n\r\n\z/, 'first croaked stream still ends cleanly';
like $r[3], qr/\r\n4\r\ntail\r\n0\r\n\r\n\z/, 'second croaked stream still ends cleanly';
ok $r[0] =~ /element-50-/ && $r[2] =~ /element-50-/, 'full responses around them intact';
is scalar(() = $err =~ /^croaked: boom/mg), 2, 'both writes croaked inside the slot fill';
ok $err !~ /Attempt to free|panic|corrupt/i && $status == 0,
    'no stale slot was freed' or diag $err;
