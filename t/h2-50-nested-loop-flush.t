#!perl
# An H2 response sent while another handler runs a nested event loop must
# leave during that loop, not when the handler returns.
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;

BEGIN {
    require Feersum;
    plan skip_all => "H2 not compiled in" unless Feersum->endjinn->has_h2();
    eval { require IO::Socket::SSL; require AnyEvent; 1 }
        or plan skip_all => "IO::Socket::SSL or AnyEvent not available";
    plan skip_all => "OpenSSL too old for TLS 1.3 client" unless tls_client_ok();
    plan skip_all => "test certs not found"
        unless -f 't/certs/alpha.crt' && -f 't/certs/alpha.key';
    plan tests => 3;
}
use H2Utils;
use POSIX ();
use Time::HiRes qw(time);

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use constant HOLD => 8 * TMULT;

my ($lsn, $port) = get_listen_socket();
ok $lsn, "listening on $port";

my $srv = fork();
die "fork: $!" unless defined $srv;
if (!$srv) {
    $SIG{QUIT} = 'DEFAULT';
    my $f = Feersum->new_instance;
    $f->use_socket($lsn);
    $f->set_tls(cert_file => 't/certs/alpha.crt', key_file => 't/certs/alpha.key', h2 => 1);
    my %keep;
    $f->request_handler(sub {
        my $r = shift;
        if ($r->path eq '/hold') {
            my $cv = AE::cv;
            my $t = AE::timer(HOLD, 0, sub { $cv->send });
            $cv->recv;
            $r->send_response(200, ['Content-Type' => 'text/plain'], ['held']);
        } else {
            $keep{$r} = EV::timer(0.1, 0, sub {
                $r->send_response(200, ['Content-Type' => 'text/plain'], ['quick']);
            });
        }
    });
    my $life = EV::timer(30 * TMULT, 0, sub { EV::break });
    EV::run;
    POSIX::_exit(0);
}
close $lsn;
my $cleanup = guard { reap_server($srv) };

sub get_frame {
    my ($path) = @_;
    h2_frame(H2_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, 1,
        hpack_encode_headers([':method', 'GET'], [':scheme', 'https'],
            [':path', $path], [':authority', 'x']));
}

my $hold = h2_connect($port) or die "h2 connect failed";
$hold->syswrite(get_frame('/hold'));
select undef, undef, undef, 0.3;   # its handler is now inside the nested loop

my $quick = h2_connect($port) or die "h2 connect failed";
my $t0 = time;
$quick->syswrite(get_frame('/quick'));
my $done;
while (my $f = h2_read_frame($quick, HOLD + 5 * TMULT)) {
    if ($f->{stream_id} == 1 && ($f->{flags} & FLAG_END_STREAM)) { $done = 1; last }
    last if $f->{type} == H2_GOAWAY || $f->{type} == H2_RST_STREAM;
}
my $elapsed = time - $t0;
ok $done, 'the response arrived';
cmp_ok $elapsed, '<', HOLD / 2, 'it left during the nested loop'
    or diag sprintf 'took %.2fs', $elapsed;
close $quick;
close $hold;
