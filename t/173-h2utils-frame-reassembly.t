#!perl
# The H2 test helper itself.  h2_read_frame used to hand back whatever _read_n
# had managed to read when the timeout expired, so a frame split across that
# deadline came back with a short payload and no error, and the leftover bytes
# were parsed as the next frame header.  That desynchronises the connection
# silently, which can fake a failure OR a pass in any test using this helper.
use warnings;
use strict;
use Test::More tests => 6;
use lib 't';
use AnyEvent;
use H2Utils;
use Socket;
use POSIX ();
use Time::HiRes qw(sleep);

# Deliver $wire in two pieces separated by a gap longer than the read timeout.
sub split_feed {
    my ($wire, $first_n, $gap) = @_;
    socketpair(my $a, my $b, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    $a->autoflush(1); $b->autoflush(1);
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if (!$pid) {
        close $a;
        syswrite $b, substr($wire, 0, $first_n);
        sleep $gap;
        syswrite $b, substr($wire, $first_n);
        sleep 1;
        POSIX::_exit(0);
    }
    close $b;
    $a->blocking(0);
    return ($a, $pid);
}

my $wire = h2_frame(H2_DATA, 0, 1, 'A' x 20) . h2_frame(H2_PING, 0, 0, 'PINGPING');

# Split in the middle of the payload.
{
    my ($s, $pid) = split_feed($wire, 9 + 5, 0.6);
    my $f1 = eval { h2_read_frame($s, 0.2) };
    ok $f1, 'split mid-payload still yields a frame' or diag $@;
    is length($f1->{payload}), $f1->{length},
        'payload is complete, not truncated to what had arrived';
    my $f2 = eval { h2_read_frame($s, 2) };
    is +($f2 ? $f2->{type} : -1), H2_PING,
        'the following frame still parses (connection not desynchronised)';
    close $s; waitpid $pid, 0;
}

# Split in the middle of the 9-byte header.
{
    my ($s, $pid) = split_feed($wire, 4, 0.6);
    my $f1 = eval { h2_read_frame($s, 0.2) };
    is +($f1 ? $f1->{type} : -1), H2_DATA,
        'split mid-header reassembles instead of discarding the bytes read';
    my $f2 = eval { h2_read_frame($s, 2) };
    is +($f2 ? $f2->{type} : -1), H2_PING, 'and the next frame is still aligned';
    close $s; waitpid $pid, 0;
}

# A clean frame boundary with nothing to read must stay a quiet undef, since
# callers poll with a short timeout and treat undef as "nothing yet".
{
    socketpair(my $a, my $b, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    $a->blocking(0);
    my $f = eval { h2_read_frame($a, 0.2) };
    is $f, undef, 'no data at a frame boundary returns undef, not an error';
    close $a; close $b;
}
