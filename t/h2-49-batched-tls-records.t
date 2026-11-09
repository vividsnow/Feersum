#!perl
# On the wire: a dispatched batch leaves in a few TLS records, not two per
# stream, and a full DATA frame fills one record without a 9-byte spill.
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
    plan tests => 5;
}
use H2Utils;
use File::Temp qw(tempdir);
use IO::Select;
use IO::Socket::INET;
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use constant { STREAMS => 100, BIG => 1 << 20 };

my $dir = tempdir(CLEANUP => 1);
my ($lsn, $port) = get_listen_socket();
my ($rlsn, $rport) = get_listen_socket();
ok $lsn && $rlsn, 'listening';

my $srv = fork();
die "fork: $!" unless defined $srv;
if (!$srv) {
    $SIG{QUIT} = 'DEFAULT';
    close $rlsn;
    my $f = Feersum->new_instance;
    $f->use_socket($lsn);
    $f->set_tls(cert_file => 't/certs/alpha.crt', key_file => 't/certs/alpha.key', h2 => 1);
    my $big = 'b' x BIG;
    $f->request_handler(sub {
        my $r = shift;
        $r->send_response(200, ['Content-Type' => 'text/plain'],
            $r->path eq '/big' ? [$big] : ['ok']);
    });
    my $life = EV::timer(30 * TMULT, 0, sub { EV::break });
    EV::run;
    POSIX::_exit(0);
}

# one line per relayed connection: server->client application records by size
my $relay = fork();
die "fork: $!" unless defined $relay;
if (!$relay) {
    close $lsn;
    open my $out, '>', "$dir/relay" or POSIX::_exit(9);
    $rlsn->blocking(1);
    for (1 .. 2) {
        my $c = $rlsn->accept or last;
        my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port) or last;
        my $sel = IO::Select->new($c, $s);
        my ($buf, $app, $tiny) = ('', 0, 0);
        PUMP: while (1) {
            for my $h ($sel->can_read(10 * TMULT)) {
                my $n = sysread($h, my $d, 65536);
                last PUMP unless $n;
                my $to = $h == $c ? $s : $c;
                for (my $o = 0; $o < $n;) {
                    my $w = syswrite($to, $d, $n - $o, $o);
                    last PUMP unless $w;
                    $o += $w;
                }
                next if $h == $c;
                $buf .= $d;
                while (length($buf) >= 5) {
                    my ($type, undef, $len) = unpack 'Cnn', $buf;
                    last if length($buf) < 5 + $len;
                    substr($buf, 0, 5 + $len, '');
                    next unless $type == 23;
                    $app++;
                    $tiny++ if $len - 17 <= 16;    # AES-GCM tag + inner type byte
                }
            }
        }
        print {$out} "app=$app tiny=$tiny\n";
        close $c; close $s;
    }
    close $out;
    POSIX::_exit(0);
}
close $lsn;
close $rlsn;
my $cleanup = guard { kill 'KILL', $relay; waitpid $relay, 0; reap_server($srv) };

sub h2_session {
    my $s = IO::Socket::SSL->new(PeerAddr => '127.0.0.1', PeerPort => $rport,
        SSL_verify_mode => 0, SSL_alpn_protocols => ['h2'], Timeout => 10 * TMULT)
        or return;
    my $win = 0x7fffffff;
    $s->syswrite("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        . h2_frame(H2_SETTINGS, 0, 0, pack('nN', 4, $win))
        . h2_frame(H2_WINDOW_UPDATE, 0, 0, pack('N', $win - 65535)));
    $s->blocking(0);
    while (my $f = h2_read_frame($s, 10 * TMULT)) {
        next unless $f->{type} == H2_SETTINGS && !($f->{flags} & FLAG_ACK);
        $s->syswrite(h2_frame(H2_SETTINGS, FLAG_ACK, 0, ''));
        last;
    }
    return $s;
}

# reads until every listed stream ended; returns DATA bytes received
sub drain {
    my ($s, %open) = @_;
    my $data = 0;
    while (%open) {
        my $f = h2_read_frame($s, 10 * TMULT) or last;
        $data += $f->{length} if $f->{type} == H2_DATA;
        delete $open{ $f->{stream_id} }
            if ($f->{type} == H2_DATA || $f->{type} == H2_HEADERS)
            && ($f->{flags} & FLAG_END_STREAM);
        last if $f->{type} == H2_GOAWAY || $f->{type} == H2_RST_STREAM;
    }
    return (scalar(keys %open), $data);
}

sub get_frame {
    my ($sid, $path) = @_;
    h2_frame(H2_HEADERS, FLAG_END_STREAM | FLAG_END_HEADERS, $sid,
        hpack_encode_headers([':method', 'GET'], [':scheme', 'https'],
            [':path', $path], [':authority', 'x']));
}

{
    my $s = h2_session() or die "h2 connect failed";
    my @sids = map { 2 * $_ - 1 } 1 .. STREAMS;
    $s->syswrite(join '', map { get_frame($_, '/') } @sids);
    my ($left) = drain($s, map { $_ => 1 } @sids);
    is $left, 0, STREAMS . ' streams answered';
    close $s;
}
{
    my $s = h2_session() or die "h2 connect failed";
    $s->syswrite(get_frame(1, '/big'));
    my ($left, $data) = drain($s, 1 => 1);
    is $data, BIG, '1 MiB body received';
    close $s;
}

my $deadline = time + 10 * TMULT;
select undef, undef, undef, 0.1 until -s "$dir/relay" && `wc -l < $dir/relay` >= 2 || time > $deadline;
my @line = do { open my $in, '<', "$dir/relay" or die; <$in> };
my ($small_app) = ($line[0] // '') =~ /app=(\d+)/;
my ($big_tiny)  = ($line[1] // '') =~ /tiny=(\d+)/;
diag "relay: @line";
cmp_ok $small_app // 1e9, '<', 40, 'a dispatched batch leaves in a few records, not two per stream';
cmp_ok $big_tiny // 1e9, '<', 10, 'full DATA frames do not spill a 9-byte record';
