#!perl
# Every chunk-size line is the exact lowercase hex of its chunk, across digit
# boundaries.
use strict;
use warnings;
use Test::More;
use lib 't'; use Utils;
use Feersum;
use EV;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use POSIX ();

use constant TMULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
my @sizes = (1, 9, 10, 15, 16, 17, 255, 256, 4095, 4096, 65535, 65536, 1048575, 1048576);
plan tests => 3;

$SIG{PIPE} = 'IGNORE';
my $dir = tempdir(CLEANUP => 1);
my ($lsn, $port) = get_listen_socket();
ok $lsn, "listen on $port";

my $f = Feersum->new_instance;
$f->use_socket($lsn);
$f->request_handler(sub {
    my $w = $_[0]->start_streaming(200, ['Content-Type' => 'text/plain']);
    $w->write(chr(97 + $_ % 26) x $sizes[$_]) for 0 .. $#sizes;
    $w->close;
});

my $pid = fork();
die "fork: $!" unless defined $pid;
if (!$pid) {
    close $lsn;
    my $got = '';
    my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port,
        Proto => 'tcp', Timeout => 5 * TMULT);
    if ($c) {
        syswrite $c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        local $SIG{ALRM} = sub { POSIX::_exit(4) };
        alarm 20 * TMULT;
        while (sysread($c, my $buf, 65536)) { $got .= $buf }
    }
    open my $out, '>', "$dir/got" or POSIX::_exit(9);
    print {$out} $got;
    close $out;
    POSIX::_exit(0);
}
my $cw = EV::child($pid, 0, sub { EV::break });
my $guard = EV::timer(30 * TMULT, 0, sub { EV::break });
EV::run;

my $got = do { local $/; open my $in, '<', "$dir/got" or die; <$in> } // '';
my ($body) = $got =~ /\r\n\r\n(.*)\z/s;
$body //= '';
my (@lines, $data_ok);
$data_ok = 1;
while ($body =~ s/\A([^\r\n]*)\r\n//) {
    my $line = $1;
    push @lines, $line;
    my $len = hex $line;
    last unless $len;
    my $i = $#lines;
    $data_ok = 0 unless substr($body, 0, $len) eq chr(97 + $i % 26) x $len
                        && substr($body, $len, 2) eq "\r\n";
    substr($body, 0, $len + 2, '');
}
is_deeply \@lines, [ (map { sprintf '%x', $_ } @sizes), '0' ], 'chunk-size lines';
ok $data_ok, 'chunk data matches its size line';
