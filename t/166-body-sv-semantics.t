#!perl
# What happens to the application's scalar on the way to the wire.
#
# 1. Magic lvalues.  Perl passes substr($x,...) in an argument list as an
#    lvalue PVLV whose value has not been fetched yet, so it arrives at the
#    XSUB with no OK flags.  write() and send_response() tested SvOK before
#    anything fetched it, read it as undef, and returned 0 - so
#
#        $w->write(substr($buf, 4));      # wrote NOTHING, silently
#
#    while the same value through a lexical worked.  No croak, no warning, no
#    framing error: the bytes just never appeared.  $1 escaped notice because
#    a match usually leaves it already fetched.
#
# 2. Array bodies on H2 were concatenated with sv_catsv, which applies
#    character semantics: one UTF8-flagged element upgraded the accumulator
#    and re-encoded every byte element after it.  The same PSGI response then
#    went out as different bytes depending on the protocol -
#    ["\xE9" (upgraded), "\xFF"] was c3a9 ff on H1 and c3a9 c3bf on H2.
#    H1 queues each element's own buffer, so bytes are what H2 must send too.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More;
use lib 't'; use Utils;
use IO::Socket::INET;
use POSIX ();
use Feersum;

my $probe = Feersum->new();
my $h2_ok = $probe->has_tls() && $probe->has_h2()
         && -f 't/certs/alpha.crt' && -f 't/certs/alpha.key'
         && do { my $p = `which nghttp 2>/dev/null`; chomp $p; -x ($p || '') };

plan tests => 7 + ($h2_ok ? 3 : 0);

my $BUF = 'data-payload';

my ($sock, $port) = get_listen_socket();
ok $sock, "listen socket on port $port";

my $server = fork();
die "fork: $!" unless defined $server;
if (!$server) {
    open STDOUT, '>', '/dev/null';
    open STDERR, '>', '/dev/null';
    no warnings 'once';
    $Feersum::DIED = sub { };
    my $f = Feersum->new_instance();
    $f->use_socket($sock);
    $f->read_timeout(30 * TIMEOUT_MULT);
    if ($h2_ok) {
        $f->set_tls(h2 => 1, cert_file => 't/certs/alpha.crt',
                    key_file => 't/certs/alpha.key');
    }
    $f->psgi_request_handler(sub {
        my $env = shift;
        my ($k) = ($env->{PATH_INFO} // '') =~ m{^/(.+)};
        $k //= '';
        # Array bodies (also the H2 leg).
        if ($k eq 'mixed') {
            my $u = chr(0xE9); utf8::upgrade($u);
            return [200, ['Content-Type' => 'application/octet-stream'],
                    [$u, chr(0xFF)]];
        }
        if ($k eq 'bytes') {
            return [200, ['Content-Type' => 'application/octet-stream'],
                    ["ab", "cd"]];
        }
        # Streaming writer takes magic lvalues directly.
        return sub {
            my $w = $_[0]->([200, ['Content-Type' => 'text/plain']]);
            $w->write(substr($BUF, 4))    if $k eq 'w-substr2';
            $w->write(substr($BUF, 0, 4)) if $k eq 'w-substr3';
            if ($k eq 'w-dollar1') { "match-me" =~ /(match)/; $w->write($1) }
            if ($k eq 'w-lexical') { my $x = substr($BUF, 4); $w->write($x) }
            $w->close;
        };
    });
    my $life_timer = EV::timer(120 * TIMEOUT_MULT, 0, sub { EV::break() });
    EV::run();
    POSIX::_exit(0);
}
close $sock;
select undef, undef, undef, 1 * TIMEOUT_MULT;

# Plain-HTTP fetch.  With TLS enabled the listener speaks TLS, so the magic-SV
# leg goes over TLS too; either way the body is what we assert on.
sub body_of {
    my ($path) = @_;
    my $raw;
    if ($h2_ok) {
        $raw = `printf 'GET /$path HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' | openssl s_client -quiet -alpn http/1.1 -connect 127.0.0.1:$port 2>/dev/null`;
    }
    else {
        my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port",
                                      Timeout => 10 * TIMEOUT_MULT) or return '';
        syswrite $s, "GET /$path HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        $raw = '';
        eval { local $SIG{ALRM} = sub { die "to\n" }; alarm 10 * TIMEOUT_MULT;
               while (sysread($s, my $c, 4096)) { $raw .= $c } alarm 0; 1 };
        alarm 0; close $s;
    }
    my ($b) = ($raw // '') =~ /\r\n\r\n(.*)$/s;
    return $b // '';
}

# Chunked framing: strip the chunk sizes to get the payload.
sub dechunk {
    my ($b) = @_;
    my $out = '';
    while ($b =~ s/^([0-9a-fA-F]+)\r\n//) {
        my $n = hex $1;
        last if $n == 0;
        $out .= substr($b, 0, $n, '');
        $b =~ s/^\r\n//;
    }
    return $out;
}

is dechunk(body_of('w-substr2')), '-payload',
   'write(substr($buf,4)) delivers its bytes';
is dechunk(body_of('w-substr3')), 'data',
   'write(substr($buf,0,4)) delivers its bytes';
is dechunk(body_of('w-dollar1')), 'match',
   'write($1) delivers its bytes';
is dechunk(body_of('w-lexical')), '-payload',
   'the same value via a lexical is unchanged';

# The native interface has its own copy of the same guard.
{
    my ($nsock, $nport) = get_listen_socket();
    my $nsrv = fork();
    die "fork: $!" unless defined $nsrv;
    if (!$nsrv) {
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';
        my $f = Feersum->new_instance();
        $f->use_socket($nsock);
        $f->request_handler(sub {
            $_[0]->send_response(200, ['Content-Type' => 'text/plain'],
                                 substr($BUF, 4));
        });
        my $t = EV::timer(60 * TIMEOUT_MULT, 0, sub { EV::break() });
        EV::run();
        POSIX::_exit(0);
    }
    close $nsock;
    select undef, undef, undef, 1 * TIMEOUT_MULT;
    my $raw = '';
    if (my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$nport",
                                      Timeout => 10 * TIMEOUT_MULT)) {
        syswrite $s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        eval { local $SIG{ALRM} = sub { die "to\n" }; alarm 10 * TIMEOUT_MULT;
               while (sysread($s, my $c, 4096)) { $raw .= $c } alarm 0; 1 };
        alarm 0; close $s;
    }
    my ($b) = $raw =~ /\r\n\r\n(.*)$/s;
    is $b // '', '-payload',
       'send_response(substr(...)) delivers its bytes';
    reap_server($nsrv);
}

# H1 array bodies are byte concatenation, whatever flags the elements carry.
is unpack('H*', body_of('mixed')), 'c3a9ff',
   'H1 array body is the elements\' bytes, not a character concatenation';

SKIP: {
    skip 'no TLS+H2+nghttp', 3 unless $h2_ok;
    for my $case (['mixed', 'c3a9ff'], ['bytes', '61626364']) {
        my $got = `nghttp --no-verify-peer https://127.0.0.1:$port/$case->[0] 2>/dev/null`;
        is unpack('H*', $got // ''), $case->[1],
           "H2 array body '$case->[0]' is the same bytes H1 sends";
    }
    is unpack('H*', body_of('bytes')), '61626364',
       'H1 twin of the plain array body';
}

reap_server($server);
