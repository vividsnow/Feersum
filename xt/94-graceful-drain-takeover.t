#!perl
# graceful_shutdown() completes only when active_conns reaches 0, and there is
# no C-level deadline.  Connections Feersum deliberately stops timing out
# (psgix.io takeovers, CONNECT tunnels) therefore hold the drain open forever.
# That is intended - a websocket may idle for hours - and Feersum::Runner bounds
# it with graceful_timeout.  Both halves are asserted so neither can drift: an
# ordinary connection must still drain promptly, and a taken-over one must not
# be reaped behind the app's back.
#
# graceful_shutdown is terminal, so each scenario needs its own server; the
# script re-executes itself per scenario rather than forking twice from one
# parent, which is not reliable once a scenario has run.
use warnings;
use strict;
use constant TIMEOUT_MULT =>
    $ENV{PERL_TEST_TIME_OUT_FACTOR} || ($ENV{AUTOMATED_TESTING} ? 3 : 1);
use IO::Socket::INET;
use POSIX ();

my $MODE = $ENV{FEERSUM_DRAIN_MODE};

if (!defined $MODE) {
    require Test::More;
    Test::More::plan(skip_all => 'author test')
        unless $ENV{FEERSUM_AUTHOR_TESTS} || $ENV{AUTHOR_TESTING};
    Test::More::plan(tests => 4);

    my %got;
    for my $mode (qw(plain takeover)) {
        local $ENV{FEERSUM_DRAIN_MODE} = $mode;
        my @inc = map { "-I$_" } grep { !ref } @INC;
        open my $fh, '-|', $^X, @inc, $0
            or die "cannot re-exec $0: $!";
        my $line = <$fh>;
        close $fh;
        chomp $line if defined $line;
        my ($ran, $lat) = split q{ }, ($line // '0 NONE');
        $got{$mode} = { ran => $ran || 0,
                        latency => (($lat // 'NONE') eq 'NONE' ? undef : $lat) };
    }

    Test::More::is($got{plain}{ran}, 1,
        'ordinary connection: the request actually reached the handler');
    Test::More::cmp_ok($got{plain}{latency} // 9_999, q{<}, 5 * TIMEOUT_MULT,
        sprintf('ordinary connection: graceful_shutdown drained promptly (%s s)',
                $got{plain}{latency} // 'never'));

    Test::More::is($got{takeover}{ran}, 1,
        'takeover: the request actually reached the handler');
    Test::More::ok(!defined($got{takeover}{latency}),
        'psgix.io takeover: graceful_shutdown does NOT complete (the app owns the socket)')
        or Test::More::diag('drain completed after ' . $got{takeover}{latency}
              . ' s - a taken-over socket must not be reaped behind the app');
    exit 0;
}

# ---- child: run one scenario, print "<handler-runs> <latency|NONE>" ----
# Autoflush matters: this child ends via POSIX::_exit, which discards any
# buffered stdout, so a block-buffered result line would never reach the parent.
$| = 1;
require Feersum;
require EV;
my $budget = 8 * TIMEOUT_MULT;

my $sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                 Proto => 'tcp', Listen => 128,
                                 ReuseAddr => 1, Blocking => 0)
    or do { print "0 NONE\n"; POSIX::_exit(0) };
my $port = $sock->sockport;

my $client = fork();
die "fork: $!" unless defined $client;
if (!$client) {
    close $sock;
    select undef, undef, undef, 0.5;
    my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$port",
                                  Proto => 'tcp', Timeout => 5) or POSIX::_exit(1);
    syswrite $s, "GET /take HTTP/1.1\r\nHost: x\r\n\r\n";
    my $b; sysread $s, $b, 65536;
    select undef, undef, undef, $budget + 6;    # hold it open and silent
    POSIX::_exit(0);
}

our @held;
my $ran = 0;
my $f = Feersum->new();
$f->use_socket($sock);
$f->read_timeout(2);        # an ordinary connection is reaped fast
$f->header_timeout(2);
$f->psgi_request_handler(sub {
    my $env = shift;
    $ran++;
    return [200, ['Content-Type' => 'text/plain'], ['plain']] if $MODE ne 'takeover';
    return sub {
        my $respond = shift;                # deliberately never called
        my $io = $env->{'psgix.io'};        # reading the VALUE takes the socket
        if ($io) {
            push @held, $io;
            syswrite $io, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\n\r\n";
        }
    };
});

my $t0;
my $start = EV::timer(3, 0, sub {
    $t0 = EV::now();
    $f->graceful_shutdown(sub {
        printf "%d %.2f\n", $ran, EV::now() - $t0;
        EV::break();
    });
});
my $giveup = EV::timer(3 + $budget, 0, sub { print "$ran NONE\n"; EV::break() });
EV::run();
kill 'KILL', $client;
waitpid $client, 0;
POSIX::_exit(0);
