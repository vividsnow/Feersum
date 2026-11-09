#!perl
# When the app closes its end of a TLS psgix.io takeover, the ciphertext still
# queued in tls_wbuf is drained to the client before the connection shuts down,
# so a paused client that resumes reads the whole stream.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use Test::More;
use lib 't'; use Utils;
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Socket qw(SOL_SOCKET SO_SNDBUF SO_RCVBUF MSG_PEEK MSG_DONTWAIT);
use POSIX ();
use Time::HiRes ();
use Feersum;

my $probe = Feersum->new_instance();
plan skip_all => 'Feersum not compiled with TLS support' unless $probe->has_tls();
my $cert = 'eg/ssl-proxy/server.crt';
my $key  = 'eg/ssl-proxy/server.key';
plan skip_all => 'no test certificates' unless -f $cert && -f $key;
eval { require IO::Socket::SSL; 1 } or plan skip_all => 'IO::Socket::SSL not installed';
plan skip_all => 'OpenSSL too old for TLS 1.3 client' unless tls_client_ok();

plan tests => 8;

# Must exceed FEER_TUNNEL_MAX_WBUF (16 MB) so the pause actually fills the
# window and leaves a large residue queued at close time.
my $MB   = 20;
my $WANT = $MB * 1024 * 1024;
my $dir  = tempdir(CLEANUP => 1);
my $nsrv = 0;

# Deferring the close means a peer that never reads again would hold the
# connection - and its queued ciphertext - open, so the deadline has to come
# back into force once the app has let go of the socket.  Each server gets its
# own write_timeout so the drain cases are not racing it.
sub spawn_server {
    my ($write_timeout, $want, $sndbuf) = @_;
    $want //= $WANT;
    my ($lsock, $lport) = get_listen_socket();
    # A peer that stops reading only strands a write the buffers cannot swallow:
    # OpenBSD's defaults absorb the whole reply, leaving the deadline nothing to
    # reap and the test asserting the opposite of what it meant.
    if ($sndbuf) {
        setsockopt($lsock, SOL_SOCKET, SO_SNDBUF, pack('i', $sndbuf))
            or die "SO_SNDBUF: $!";
    }
    my $tag = 'srv' . ++$nsrv;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if (!$pid) {
        open STDOUT, '>', "$dir/$tag.out";
        open STDERR, '>', "$dir/$tag.log";
        no warnings 'once';
        $Feersum::DIED = sub { };
        my $f = Feersum->new_instance();
        $f->use_socket($lsock);
        $f->read_timeout(120 * TIMEOUT_MULT);
        $f->header_timeout(120 * TIMEOUT_MULT);
        $f->write_timeout($write_timeout);
        eval { $f->set_tls(listener => 0, cert_file => $cert,
                           key_file => $key, h2 => 0) };
        my %keep;
        $f->psgi_request_handler(sub {
            my $env = shift;
            return sub {
                my $io = $env->{'psgix.io'} or return; # reading the VALUE takes it
                my $id = 0 + $io;
                # Count BYTES: a partial syswrite still sent what it wrote.
                my $sent = 0;
                my $chunk = 'Z' x (256 * 1024);
                # paced by writability, not a timer: BSD timers tick at 10 ms and
                # their socketpairs are small, so one write per tick crawls
                my $t;
                $t = EV::io $io, EV::WRITE, sub {
                    while ($sent < $want) {
                        my $n = $want - $sent;
                        $n = length $chunk if $n > length $chunk;
                        my $w = syswrite $io, substr($chunk, 0, $n);
                        if (!$w) {
                            return if $!{EAGAIN} || $!{EWOULDBLOCK};
                            last;
                        }
                        $sent += $w;
                    }
                    undef $t;
                    close $io;          # the close under test
                    delete $keep{$id};
                    open my $m, '>', "$dir/closed-$lport"; close $m;
                };
                $keep{$id} = [$io, \$t];
            };
        });
        my $life_timer = EV::timer(180 * TIMEOUT_MULT, 0, sub { EV::break() });
        EV::run();
        POSIX::_exit(0);
    }
    close $lsock;
    return ($pid, $lport);
}

my ($server, $port) = spawn_server(120 * TIMEOUT_MULT);
ok $server, 'server started';
select undef, undef, undef, 1 * TIMEOUT_MULT;

for my $run (1 .. 2) {
    my $s = IO::Socket::SSL->new(PeerAddr => "127.0.0.1:$port",
        SSL_verify_mode => 0, Timeout => 10 * TIMEOUT_MULT);
    ok $s, "run $run: connected";
    my $got = 0;
    if ($s) {
        print {$s} "GET /tail HTTP/1.1\r\nHost: x\r\n\r\n";
        eval {
            local $SIG{ALRM} = sub { die "to\n" };
            alarm 120 * TIMEOUT_MULT;
            # Read a couple of MB, then stall long enough for the app to fill
            # the backpressure window and reach its close.
            while ($got < 2 * 1024 * 1024) {
                my $n = sysread $s, my $z, 65536;
                last if !$n;
                $got += $n;
            }
            select undef, undef, undef, 4 * TIMEOUT_MULT;
            while (1) { my $n = sysread $s, my $z, 65536; last if !$n; $got += $n }
            alarm 0;
            1;
        };
        alarm 0;
        close $s;
    }
    cmp_ok $got, '>=', $WANT,
        sprintf('run %d: the queued tail survives the app closing its end '
              . '(received %d of %d)', $run, $got, $WANT);
}

reap_server($server);

# --- the deferral must not become a way to pin a connection open

# What the kernel does with a peer that stops reading, buffers pinned as below:
# bytes it absorbs until writes stall, then bytes that still reach the peer's
# queue over $watch seconds (BSD persist probes start at 5 s, and one accepted
# byte reads as draining to the outq check).  Either breaks the premise: a
# swallowed reply leaves nothing to reap, and a trickle is progress.
sub kernel_absorbs {
    my ($pin, $cap, $watch) = @_;
    my $l = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
        Proto => 'tcp', Listen => 1) or return (0, 0);
    setsockopt($l, SOL_SOCKET, SO_SNDBUF, pack('i', $pin)) or return (0, 0);
    my $c = IO::Socket::INET->new(Proto => 'tcp') or return (0, 0);
    setsockopt($c, SOL_SOCKET, SO_RCVBUF, pack('i', $pin)) or return (0, 0);
    $c->connect(Socket::pack_sockaddr_in($l->sockport, Socket::inet_aton('127.0.0.1')))
        or return (0, 0);
    my $acc = $l->accept or return (0, 0);
    $acc->blocking(0);
    my ($n, $chunk) = (0, 'Z' x 65536);
    my $until = Time::HiRes::time() + 1;
    while ($n < $cap && Time::HiRes::time() < $until) {
        my $w = syswrite $acc, $chunk;
        if ($w) { $n += $w; $until = Time::HiRes::time() + 1 }
        else    { select undef, undef, undef, 0.02 }
    }
    my $queued = sub {
        my $buf = '';
        defined recv($c, $buf, $cap, MSG_PEEK | MSG_DONTWAIT) ? length $buf : 0;
    };
    my $q0 = my $max = $queued->();
    $until = Time::HiRes::time() + $watch;
    while (Time::HiRes::time() < $until) {
        syswrite $acc, $chunk;   # keep pushing, as the server does
        select undef, undef, undef, 0.25;
        my $q = $queued->();
        $max = $q if $q > $max;
    }
    return ($n, $max - $q0);
}

{
    my $deadline = 4 * TIMEOUT_MULT;
    # Keep this payload UNDER the 16 MB window: the app must be able to write
    # all of it and reach its close without being paused, so that what the
    # deadline has to reap is a connection whose app end is already gone.
    my $small = 8 * 1024 * 1024;
    my $watch = 8;
    my ($absorbs, $trickle) = kernel_absorbs(32768, $small, $watch);
    diag "a stalled peer: kernel absorbs $absorbs bytes, then $trickle more reach it in ${watch}s";
    SKIP: {
        skip "a stalled peer's kernel buffers take $absorbs bytes here, so no write "
           . 'is left for the deadline to reap', 3 if 2 * $absorbs >= $small;
        skip "a stalled peer still receives $trickle bytes in ${watch}s, which "
           . 'write_timeout rightly treats as a slow reader', 3 if $trickle;
        my ($srv2, $port2) = spawn_server($deadline, $small, 32768);
        ok $srv2, 'second server started (write_timeout enabled)';
        select undef, undef, undef, 1 * TIMEOUT_MULT;

        # The client runs apart so a crash in its TLS library is reported as such.
        pipe my $rd, my $wr or die "pipe: $!";
        my $kid = fork // die "fork: $!";
        if (!$kid) {
            close $rd;
            $wr->autoflush(1);
            # pin the receive buffer before connect: post-connect does not stop
            # autosizing, and an autosized buffer swallows the reply the stall needs
            my $s = IO::Socket::INET->new(Proto => 'tcp', Timeout => 10 * TIMEOUT_MULT);
            if ($s) {
                setsockopt($s, SOL_SOCKET, SO_RCVBUF, pack('i', 32768)) or die "SO_RCVBUF: $!";
                $s = $s->connect(Socket::pack_sockaddr_in($port2, Socket::inet_aton('127.0.0.1')))
                    ? IO::Socket::SSL->start_SSL($s, SSL_verify_mode => 0) : undef;
            }
            print {$wr} 'connected ', ($s ? 1 : 0), "\n";
            POSIX::_exit(0) unless $s;
            my $got = 0;
            print {$s} "GET /stall HTTP/1.1\r\nHost: x\r\n\r\n";
            # Read just enough to get the tunnel going, then stop reading entirely.
            eval {
                local $SIG{ALRM} = sub { die "to\n" };
                alarm 10 * TIMEOUT_MULT;
                my $n = sysread $s, my $z, 4096;
                $got += $n if $n;
                alarm 0;
                1;
            };
            alarm 0;
            # The deadline is armed only once the app has let go, so stall from
            # the app's close, not from the first read.
            my $wait = Time::HiRes::time() + 60 * TIMEOUT_MULT;
            select undef, undef, undef, 0.05
                until -e "$dir/closed-$port2" || Time::HiRes::time() > $wait;
            # Stay silent well past the deadline, then read again: a fired deadline
            # yields the socket buffer's worth and EOF, far short of $small; an
            # unreaped server hands over the whole residue.  Five intervals, not
            # three: the deadline reaps only after three drain-free checks, and
            # reading resets it.
            select undef, undef, undef, $deadline * 5;
            eval {
                local $SIG{ALRM} = sub { die "to\n" };
                alarm 60 * TIMEOUT_MULT;
                while (1) { my $n = sysread $s, my $z, 65536; last if !$n; $got += $n }
                alarm 0;
                1;
            };
            alarm 0;
            print {$wr} "got $got\n";
            close $s;
            POSIX::_exit(0);
        }
        close $wr;
        my %r;
        while (my $line = <$rd>) { $r{$1} = $2 if $line =~ /^(\w+) (\d+)/ }
        waitpid $kid, 0;
        my $crashed = $? & 127;
        diag "stalling client died with signal $crashed" if $crashed;
        ok $r{connected}, 'stalling client connected';
        SKIP: {
            skip "the TLS client crashed (signal $crashed), not the server", 1
                if $crashed && !defined $r{got};
            cmp_ok $r{got} // 0, '<', $small,
                sprintf('a peer that stops reading after the app closes is still reaped '
                      . 'by write_timeout, so the deferred close cannot pin the '
                      . 'connection (got %d of %d before being cut off; a stalled '
                      . 'peer absorbs %d, then receives %d)',
                        $r{got} // 0, $small, $absorbs, $trickle);
        }
        reap_server($srv2);
    }
}
