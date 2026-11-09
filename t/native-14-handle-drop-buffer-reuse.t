#!perl
# Dropped handles still end their response and release their connection, and a
# reused body buffer never shows an earlier request's bytes.
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
plan tests => 6;

$SIG{PIPE} = 'IGNORE';
my $dir = tempdir(CLEANUP => 1);
my ($lsn, $port) = get_listen_socket();
ok $lsn, "listen on $port";

my $f = Feersum->new_instance;
$f->use_socket($lsn);
$f->set_keepalive(1);
$f->request_handler(sub {
    my $r = shift;
    my $path = $r->path;
    if ($path eq '/drop') {
        my $w = $r->start_streaming(200, ['Content-Type' => 'text/plain']);
        $w->write('dropped');
        return;    # $w goes out of scope unclosed
    }
    my $body = '';
    if (my $cl = $r->content_length) {
        my $in = $r->input;
        while (length($body) < $cl) {
            last unless $in->read($body, $cl - length $body);
        }
    }
    $r->send_response(200, ['Content-Type' => 'text/plain'], ["[$body]"]);
});

my $pid = fork();
die "fork: $!" unless defined $pid;
if (!$pid) {
    close $lsn;
    my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port,
        Proto => 'tcp', Timeout => 5 * TMULT) or POSIX::_exit(2);
    local $SIG{ALRM} = sub { POSIX::_exit(4) };
    alarm 20 * TMULT;
    my @out;
    my $get = sub {
        my ($req, $chunked) = @_;
        syswrite $c, $req;
        my $resp = '';
        while (1) {
            my $n = sysread($c, $resp, 65536, length $resp);
            last unless $n;
            last if $chunked ? $resp =~ /\r\n0\r\n\r\n\z/
                : ($resp =~ /Content-Length: (\d+)/i
                   && length($resp) >= index($resp, "\r\n\r\n") + 4 + $1);
        }
        push @out, $resp;
    };
    $get->("POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789");
    $get->("GET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    $get->("POST /c HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nxy");
    $get->("GET /d HTTP/1.1\r\nHost: x\r\n\r\n");
    $get->("GET /drop HTTP/1.1\r\nHost: x\r\n\r\n", 1);
    $get->("GET /e HTTP/1.1\r\nHost: x\r\n\r\n");
    open my $o, '>', "$dir/out" or POSIX::_exit(9);
    print {$o} join "\0", @out;
    close $o;
    POSIX::_exit(0);
}
my $cw = EV::child($pid, 0, sub { EV::break });
my $guard = EV::timer(30 * TMULT, 0, sub { EV::break });
EV::run;
undef $cw;

my @out = split /\0/, do { local $/; open my $in, '<', "$dir/out" or die; <$in> } // '';
my @bodies = map { /\r\n\r\n(.*)\z/s ? $1 : '' } @out;
is_deeply [ @bodies[0 .. 3] ], ['[0123456789]', '[]', '[xy]', '[]'],
    'bodies on one keepalive connection never carry earlier bytes';
like $out[4] // '', qr/\r\n7\r\ndropped\r\n0\r\n\r\n\z/, 'a dropped writer still ends its response';
is $bodies[5], '[]', 'the connection is reused after it';

# all connections closed by the client: only the handles could still pin one
my $settle = EV::timer(0.3 * TMULT, 0, sub { EV::break });
EV::run;
is $f->active_conns, 0, 'no handle kept a connection alive';
ok !Feersum::Connection::Writer->can('DESTROY'), 'handles need no DESTROY dispatch';
