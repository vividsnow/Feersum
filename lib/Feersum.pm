package Feersum;
use 5.014;
use strict;
use warnings;
use EV ();
use Carp ();
use Socket ();

our $VERSION = '1.506_63';

require Feersum::Connection;
require Feersum::Connection::Handle;
require XSLoader;
XSLoader::load('Feersum', $VERSION);

# Keep the dist-style string (e.g. "1.506_49") available: $VERSION itself is
# numified below, which is not what a user wants to see from --version.
our $VERSION_STRING = $VERSION;

# numify as per
# http://www.dagolden.com/index.php/369/version-numbers-should-be-boring/
$VERSION = eval $VERSION; ## no critic (StringyEval, ConstantVersion)

our $INSTANCE;
my %_SOCKETS; # inside-out storage for socket refs (keyed by Scalar::Util::refaddr)

# Fallback advertised port when a socket cannot report its own (raw sockets,
# or a sockport() that fails).  Underscore-prefixed: internal, and Pod::Coverage
# treats leading-underscore subs as private.
use constant _DEFAULT_HTTP_PORT => 80;

use Scalar::Util ();
use Exporter 'import';
our @EXPORT_OK = qw(HEADER_NORM_SKIP HEADER_NORM_UPCASE HEADER_NORM_LOCASE HEADER_NORM_UPCASE_DASH HEADER_NORM_LOCASE_DASH);

sub new {
    unless ($INSTANCE) {
        $INSTANCE = __PACKAGE__->_xs_default_server();
        $SIG{PIPE} = 'IGNORE';
    }
    return $INSTANCE;
}
*endjinn = *new;

sub new_instance {
    my $class = shift;
    $SIG{PIPE} = 'IGNORE';
    return $class->_xs_new_server();
}

sub DESTROY {
    my $self = shift;
    my $addr = Scalar::Util::refaddr($self);
    delete $_SOCKETS{$addr};
    # XS DESTROY is renamed to _xs_destroy and called here
    $self->_xs_destroy();
    return;
}

# Keep a reference to $sock so it is not garbage-collected while we accept on
# its descriptor - but only once per socket.  A pre-forking supervisor without
# SO_REUSEPORT re-registers the same listeners on every worker respawn, which
# would otherwise grow this list without bound.
sub _hold_socket {
    my ($addr, $sock) = @_;
    my $held = $_SOCKETS{$addr} ||= [];
    for my $s (@$held) {
        return if defined $s && "$s" eq "$sock";
    }
    push @$held, $sock;
    return;
}

sub use_socket {
    my ($self, $sock) = @_;
    my $addr = Scalar::Util::refaddr($self);
    my $fd = fileno $sock;
    Carp::croak "Invalid socket: fileno returned undef" unless defined $fd;
    _hold_socket($addr, $sock);
    $self->accept_on_fd($fd);

    # Try socket methods first, fall back to getsockname() for raw sockets
    my ($host, $port) = ('localhost', _DEFAULT_HTTP_PORT);
    if ($sock->can('sockhost')) {
        $host = eval { $sock->sockhost() } || 'localhost';
        $port = eval { $sock->sockport() } || _DEFAULT_HTTP_PORT;
    } else {
        # Raw socket (e.g., from Runner with SO_REUSEPORT) - use getsockname
        my $sockaddr = getsockname($sock);
        if ($sockaddr) {
            my $family = eval { Socket::sockaddr_family($sockaddr) };
            if (defined $family && $family == Socket::AF_INET()) {
                (my $packed_port, my $packed_addr) = Socket::sockaddr_in($sockaddr);
                $host = Socket::inet_ntoa($packed_addr) || 'localhost';
                # Use defined check - port 0 is valid (OS-assigned dynamic port)
                $port = defined($packed_port) ? $packed_port : _DEFAULT_HTTP_PORT;
            } elsif (defined $family && eval { Socket::AF_INET6() } && $family == Socket::AF_INET6()) {
                (my $packed_port, my $packed_addr) = Socket::sockaddr_in6($sockaddr);
                $host = Socket::inet_ntop(Socket::AF_INET6(), $packed_addr) || 'localhost';
                # Use defined check - port 0 is valid (OS-assigned dynamic port)
                $port = defined($packed_port) ? $packed_port : _DEFAULT_HTTP_PORT;
            } elsif (defined $family && eval { Socket::AF_UNIX() } && $family == Socket::AF_UNIX()) {
                # IO::Socket::UNIX has no sockhost/sockport, so without this a
                # UNIX listener reported localhost:80 - indistinguishable from a
                # real TCP listener to any app building absolute URLs.  Matches
                # what the C side already reports for REMOTE_ADDR on AF_UNIX.
                ($host, $port) = ('unix', 0);
            }
        }
    }
    $self->set_server_name_and_port($host,$port);
    return;
}

# Copy a PSGI body array, forcing get-magic (tied elements) to fire here, where
# the XS caller has us inside an eval.  fetch_av_normal would otherwise trigger
# it during the body write, which runs with no eval frame above it, so a FETCH
# that dies killed the worker with no response and no DIED.  Called only when
# the body actually contains magic.
# Materialise a response header list into plain strings.  Called from XS only
# when the list or one of its elements carries magic or an overload, and always
# under G_EVAL - iterating a tied array fires FETCHSIZE/FETCH, and stringifying
# an overloaded object runs its "" handler, either of which may die.  Doing it
# here means the C header builder only ever sees plain PVs, so it cannot be
# surprised by a value that dies, or that reports one length and then another.
sub _flatten_headers {
    my ($headers) = @_;
    my @out;
    for my $i (0 .. $#{$headers}) {
        my $v = $headers->[$i];
        push @out, defined($v) ? "$v" : undef;
    }
    return \@out;
}

sub _flatten_body {
    my ($body) = @_;
    my @out;
    for my $e (@{$body}) {            # copying fires a tied element's FETCH
        if (ref($e) eq 'SCALAR') {    # ...and \$tied needs one level more
            my $copy = ${$e};
            push @out, \$copy;
        }
        else { push @out, $e }
    }
    return \@out;
}

# Overload this to catch Feersum errors and exceptions thrown by request
# callbacks.  The error arrives as $_[0]; $@ is clear, because the XS side
# calls this under G_EVAL.  For the same reason this must not throw: until
# 1.507 the default was Carp::confess, whose exception was swallowed, so
# every application exception was reported precisely nowhere.
sub DIED {
    # Not carp(): the caller is the XS layer, so carp's frame is noise, and it
    # appends "at ... line N" even to a newline-terminated message.
    warn "DIED: $_[0]";  ## no critic (ErrorHandling::RequireCarping)
    return;
}

1;
__END__

=head1 NAME

Feersum - A fast PSGI/HTTP server for Perl based on EV/libev

=head1 SYNOPSIS

    use Feersum;
    use EV;
    use IO::Socket::INET;

    my $io_socket = IO::Socket::INET->new(
        LocalAddr => 'localhost:5000',
        Proto     => 'tcp',
        Listen    => 1024,
        Blocking  => 0,      # optional: use_socket sets O_NONBLOCK anyway
    ) or die $!;

    my $ngn = Feersum->endjinn; # singleton
    $ngn->use_socket($io_socket);

    # register a PSGI handler
    $ngn->psgi_request_handler(sub {
        my $env = shift;
        return [200,
            ['Content-Type'=>'text/plain'],
            ["You win one cryptosphere!\n"]];
    });

    # register a Feersum handler:
    $ngn->request_handler(sub {
        my $req = shift;
        my $t; $t = EV::timer 2, 0, sub {
            $req->send_response(
                200,
                ['Content-Type' => 'text/plain'],
                \"You win one cryptosphere!\n"
            );
            undef $t;
        };
    });

    EV::run;   # nothing is served until the loop runs

See C<eg/hello.pl> for the same thing as a file you can run.

=head1 DESCRIPTION

Feersum is an HTTP server built on L<EV>.  It fully supports the PSGI 1.1
spec including the C<psgi.streaming> interface and is compatible with Plack.
It also has its own "native" interface which is similar in a lot of ways to PSGI,
but is B<not compatible> with PSGI or PSGI middleware.

Feersum uses a single-threaded, event-based programming architecture to scale
and can handle many concurrent connections efficiently in both CPU and RAM.
With built-in TLS 1.3, HTTP/2, SNI, and PROXY protocol support, Feersum
can serve directly or behind a reverse proxy.

=head2 How It Works

All of the request-parsing and I/O marshalling is done using C or XS code.
HTTP parsing is done by picohttpparser, which is the core of
L<HTTP::Parser::XS>.  The network I/O is done via the libev library. This is
made possible by C<EV::MakeMaker>, which allows extension writers to link
against the same libev that C<EV> is using.  This means that one can write an
evented app using C<EV> or L<AnyEvent> from Perl that completely co-operates
with the server's event loop.

Since the Perl "app" (handler) is executed in the same thread as the event
loop, one need to be careful to not block this thread.  Standard techniques
include using L<AnyEvent> or L<EV> idle and timer watchers, using L<Coro> to
multitask, and using sub-processes to do heavy lifting (e.g.
L<AnyEvent::Worker> and L<AnyEvent::DBI>).

Feersum also attempts to do as little copying of data as possible. Feersum
uses the low-level C<writev> system call to avoid having to copy data into a
buffer.  For response data, references to scalars are kept in order to avoid
copying the string values (once the data is written to the socket, the
reference is dropped and the data is garbage collected).

This zero-copy behaviour carries an obligation for the caller: B<a scalar
handed to Feersum as response body data must not be modified until the
response has been transmitted>, which happens after the handler returns.
Feersum holds a reference to the scalar, not a copy of its bytes, so
reassigning it in the meantime corrupts the pending write.  Pass a fresh
scalar (or a literal or expression, which produces a private temporary) each
time.  See L<Feersum::Connection::Handle/"Writer methods."> for details and
examples.

For even faster results, Feersum can support very simple pre-forking (See
L<feersum>, L<Feersum::Runner> or L<Plack::Handler::Feersum> for details).

=head1 INTERFACE

There are two handler interfaces for Feersum: The PSGI handler interface and
the "Feersum-native" handler interface.  The PSGI handler interface is fully
PSGI 1.1 compatible, supporting C<psgi.streaming> and C<psgix.io>.  The
Feersum-native handler interface is "inspired by" PSGI, but does some things
differently for speed.

Feersum will use "Transfer-Encoding: chunked" for HTTP/1.1 clients and
"Connection: close" streaming as a fallback.  Technically "Connection: close"
streaming isn't part of the HTTP/1.0 or 1.1 spec, but many browsers and agents
support it anyway.

Responses with 1xx, 204, 205, or 304 status codes are sent without a body;
any body the handler supplies for those statuses is discarded (RFC 9110).

A response to a C<HEAD> request is also sent without a body, as RFC 9110
section 9.3.2 requires.  The handler may return a body exactly as it would
for C<GET>: Feersum measures it to produce the same C<Content-Length> the
equivalent C<GET> would have carried, then transmits only the headers.
(Before 1.507 the body was transmitted, which desynchronised a keepalive
connection for any client that correctly reads no body after a C<HEAD>.)

POST/PUT request bodies (including chunked transfer-encoding) are fully
buffered before the request callback fires, so C<read()> on C<psgi.input>
will never block.  The C<psgix.input.buffered> env var is deliberately I<not>
set, because the handle cannot rewind; see L</"psgix.input.buffered">.

=head2 PSGI interface

Feersum fully supports the PSGI 1.1 spec including C<psgi.streaming>.

Response strings - body parts, streamed C<write()> chunks, header values and
the status message, for the PSGI and native interfaces alike - are B<byte>
strings.  A UTF8-flagged string whose characters are all C<< <= 255 >> is
sent as those bytes (the flagged C<"caf\xE9"> and the plain C<"caf\xE9">
produce identical responses), exactly as the C<syswrite>-based PSGI servers
behave; C<Content-Length> counts the same bytes.  Characters above 255 are
forbidden by the PSGI spec.  Feersum does not police that: such a string is
transmitted in Perl's internal UTF-8 encoding with self-consistent framing,
and the connection survives - but the bytes differ from other servers'
behaviour (most die or truncate mid-response), so C<encode> such data
yourself before returning it.

See also L<Plack::Handler::Feersum>, which provides a way to use Feersum with
L<plackup> and L<Plack::Runner>.

Call C<< psgi_request_handler($app) >> to register C<$app> as a PSGI handler.

    my $app = do $filename;
    Feersum->endjinn->psgi_request_handler($app);

The env hash passed in will always have the following keys in addition to
dynamic ones:

    psgi.version      => [1,1],
    psgi.nonblocking  => 1,
    psgi.multithread  => '',
    psgi.multiprocess => $bool,    # true when pre_fork or set_multiprocess($true)
    psgi.run_once     => '',
    psgi.streaming    => 1,
    psgi.errors       => \*STDERR,
    SCRIPT_NAME       => "",

Feersum adds these extensions (see below for info)

    psgix.output.buffered  => 1,
    psgix.body.scalar_refs => 1,
    psgix.output.guard     => 1,
    psgix.io               => \$magical_io_socket,

Note that SCRIPT_NAME is always blank (but defined).  PATH_INFO will contain
the path part of the requested URI.

B<PATH_INFO is fully percent-decoded, so sanitise it before using it as a
filename.>  Feersum decodes the escapes and does nothing else to the result:

    /a/%2e%2e%2fsecret   ->  /a/../secret     (a live traversal, not collapsed)
    /a%2Fb               ->  /a/b             (a separator that was not one)
    /a%00b               ->  /a\0b            (an embedded NUL)

The C<..> is the one to guard: nothing here collapses it, so a route that
appends PATH_INFO to a document root escapes that root.  C<%2F> matters for
the opposite reason - a path that arrives as one segment becomes two, so a
rule that counts or splits segments sees a different shape than the client
sent.  The NUL is the mildest: Perl's own C<open> refuses a pathname
containing one (it warns and fails rather than truncating), but the byte still
travels into anything else you hand it to - a log line, a database query, an
C<exec>, a downstream service.

Match against a whitelist rather than pattern-matching the tail, and reject a
decoded path containing a C<..> segment or a NUL.  This leniency is what
L<Starman> and the rest of the ecosystem do too - none of them sanitise
either, though Starman truncates at a NUL where Feersum keeps the whole
string.  The raw, undecoded target is always in C<REQUEST_URI> if you would
rather decode it yourself, and QUERY_STRING is B<not> decoded, as PSGI
requires.

B<Over HTTP/1.x, Feersum only accepts these request methods:> GET, HEAD, POST,
PUT, PATCH, DELETE, OPTIONS.  Anything else, C<CONNECT> included, is
answered with C<405 Method Not Allowed> and an C<Allow> header, without the
handler ever running, so WebDAV verbs (PROPFIND, MKCOL, LOCK, ...), TRACE, and
application-specific methods are not usable on an HTTP/1.x listener.  B<HTTP/2
does not share this restriction> and passes every method through to the
handler, so the same application can see a method over h2 that it can never see
over HTTP/1.1.  Other PSGI servers generally pass unknown methods through; if
you are porting an application that relies on that, this is the difference to
check first.

C<psgi.input> always contains a valid handle.  For a request without a body
(e.g. GET), reads return 0 (end of file) - both C<< read($buf,
$env->{CONTENT_LENGTH}) >> with CONTENT_LENGTH 0 and a read requesting a
positive length.  The C<undef>/C<EAGAIN> result only occurs in streaming-input
mode (after C<< $input->poll_cb(...) >>) when no body data has arrived yet.

    my $r = delete $env->{'psgi.input'};
    $r->read($body, $env->{CONTENT_LENGTH});
    # optional: choose to stop receiving further input, discard buffers:
    $r->close();

The handle also implements C<getline>/C<getlines> and overloads the diamond
operator (honouring C<$/>, including C<< local $/; <$fh> >> slurps), so code
that reads C<psgi.input> the filehandle way works; see
L<Feersum::Connection::Handle/"Reader methods">.

B<C<read()> appends to the buffer, it does not replace it.>  Perl's built-in
C<read>, and every PSGI server whose C<psgi.input> is a real filehandle,
overwrite the scalar on each call; Feersum concatenates onto whatever is
already there.  Reading a 3000 byte body 1024 bytes at a time leaves the buffer
holding 1024, then 2048, then 3000 bytes, not 1024/1024/952.  This is
deliberate and long-standing (it makes the read-it-all-in-one-call form above
free), but it means the common portable idiom silently duplicates data here:

    my $buf;
    while (my $n = $input->read($buf, 8192)) { $body .= $buf }   # WRONG here

Either read the whole body in one call, or use a fresh lexical per iteration,
or clear the buffer yourself:

    $input->read(my $body, $env->{CONTENT_LENGTH});              # simplest
    while (my $n = $input->read(my $chunk, 8192)) { $body .= $chunk }
    while (my $n = do { $buf = q{}; $input->read($buf, 8192) }) { $body .= $buf }

C<Plack::Request> and the usual body parsers declare the buffer inside the
loop, so they are unaffected.

The C<psgi.streaming> interface is fully supported, including the
writer-object C<poll_cb> callback feature.  Feersum calls the
poll_cb callback after all data has been flushed out and the socket is
write-ready.  The data is buffered until the callback returns at which point
it will be immediately flushed to the socket.

    my $app = sub {
        my $env = shift;
        return sub {
            my $respond = shift;
            my $w = $respond->([
                200, ['Content-Type' => 'application/json']
            ]);
            my $n = 0;
            # Keep $w alive - a poll_cb registration does not hold it open:
            $KEEP{0+$w} = $w;
            $w->poll_cb(sub {
                $_[0]->write(get_next_chunk());
                # Key the stash off $w: $_[0] is a fresh handle for this one
                # invocation, so 0+$_[0] never matches what was stored.
                # will also unset the poll_cb:
                if ($n++ >= 100) { delete $KEEP{0+$w}; $_[0]->close }
            });
        };
    };

Note that C<< $w->close() >> will be called when the last reference to the
writer is dropped.  B<Registering a C<poll_cb> does not count as a reference>,
so a writer you do not store anywhere is closed as soon as the handler returns:
the callback never fires and the client receives an empty body.

A client that goes away mid-stream is noticed on the next write to it, not
before, so a long-lived stream (SSE, long-poll) that pushes nothing keeps its
connection and its C<active_conns> slot until the app writes again.  A periodic
heartbeat both detects the departure and releases the slot.

B<Treat that heartbeat as mandatory if you also set C<max_connections>.>  Dead
streams are not idle keepalive connections, so they are not eligible for the
oldest-idle eviction that normally makes room; once enough of them accumulate
to reach the cap, the server stops serving entirely and cannot recover, because
the only thing that would reap them is a write from the application.
C<write_timeout> does not help here: with the response already flushed there is
nothing pending to write, so its timer never arms.

=head2 PSGI extensions

=over 4

=item psgix.body.scalar_refs

Scalar refs in the response body are supported, and is indicated as an via the
B<psgix.body.scalar_refs> env variable. Passing by reference is
B<significantly> faster than copying a value onto the return stack or into an
array.  It's also very useful when broadcasting a message to many connected
clients.  This is a Feersum-native feature exposed to PSGI apps; very few
other PSGI handlers will support this.

=item psgix.output.buffered

Calls to C<< $w->write() >> will never block.  This behaviour is indicated by
B<psgix.output.buffered> in the PSGI env hash.

=item psgix.input.buffered

B<Not set> (since 1.507).  Feersum does buffer the entire request body in
memory before the handler runs, so C<read()> on C<psgi.input> never blocks -
but the handle is forward-only: reads consume the buffer, and C<seek> cannot
rewind.  C<psgix.input.buffered> promises more than non-blocking reads: per
PSGI 1.1 a true value means the handle implements C<seek>, and consumers rely
on that - L<Plack::Request> and L<HTTP::Entity::Parser> rewind with
C<seek(0,0)> around their reads because of the flag.  Advertising it made
C<< Plack::Request->content >> return C<''> once C<< ->body_parameters >> had
consumed the buffer.  With the flag unset they buffer the body into their own
rewindable handle, and every read ordering works.

Feersum also supports a C<poll_cb()> method on the reader handle.  On a normal
HTTP/1.x or HTTP/2 request the handler runs only after the whole body has been
received, so the callback drains an already-complete buffer rather than seeing
data arrive.  It becomes a true incremental reader only once the application
takes over the byte stream with C<io()>/C<psgix.io> (a WebSocket-style
upgrade), where each socket read invokes it.

=item psgix.output.guard

The streaming responder has a C<response_guard()> method that can be used to
attach a guard to the request.  When the request completes (all data has been
written to the socket and the connection has started its close) the guard
will trigger.  This is an alternate means to doing a "write completion"
callback via C<poll_cb()> that should be more efficient.  An analogy is the
"on_drain" handler in L<AnyEvent::Handle>.

A "guard" in this context is some object that will do something interesting in
its DESTROY/DEMOLISH method. For example, L<Guard>.

=item psgix.io

The raw socket extension B<psgix.io> is provided in order to support
L<Web::Hippie> and websockets.  C<psgix.io> is defined as part of PSGI 1.1.
To obtain the L<IO::Socket> corresponding to this connection, read this
environment variable.

B<Reading this key hands the connection to your application.>  The value
carries get-magic: fetching it takes over the socket, after which Feersum will
not send a response of its own, and an app that returns a normal PSGI response
anyway gets it refused (reported through C<Feersum::DIED>) and the client
receives nothing.  That is deliberate - once you own the socket, Feersum must
not write to it behind your back.

The consequence is that anything reading B<every> value in C<%$env> takes the
socket as a side effect: C<< my %copy = %$env >>, C<< values %$env >>, and
C<< Data::Dumper::Dumper($env) >> all trip it, and the request then produces an
empty response.  Inspecting C<keys> or using C<exists> is safe; so is reading
any other key.  If you need to copy or dump the environment - some logging and
debug middleware does - either exclude this key, or turn the extension off with
C<< $server->set_psgix_io(0) >> (C<< psgix_io => 0 >> in L<Feersum::Runner>),
which removes it from C<%$env> entirely.

For plain (non-TLS) connections the returned L<IO::Socket::INET> wraps the raw
socket file descriptor (TCP or Unix domain), which has C<O_NONBLOCK> and
C<FD_CLOEXEC> set and (for TCP) C<TCP_NODELAY> enabled.  For TLS connections,
and for HTTP/2 Extended CONNECT (RFC 8441) streams, C<psgix.io> returns a Unix
socketpair that relays data through the TLS/H2 layer transparently.  On a
regular (non-tunnel) HTTP/2 stream C<psgix.io> is C<undef> (the native
C<io()> method croaks in the same case; see L<Feersum::Connection/"$req-E<gt>io">).

That difference shows in one place worth knowing about.  If you take the
socket while part of the request body is still unread, the bytes Feersum has
already buffered are pushed back into the handle - and on a plain connection
that push-back goes through the PerlIO layer, which C<sysread> bypasses: a
buffered C<read> or C<getline> sees them, C<sysread> returns nothing.  Over
TLS and on an HTTP/2 tunnel the same bytes are written onto the socketpair as
real bytes and every read style sees them.  Nothing is lost either way, but an
app that takes over mid-body and only ever C<sysread>s should drain
C<psgi.input> first, or do one buffered read before switching styles.

PSGI apps B<MUST> use a C<psgi.streaming> response so that Feersum doesn't try
to flush and close the connection.  For HTTP/1 connections, the "respond"
parameter to the streaming callback B<MUST NOT> be called for the same reason.
For HTTP/2 Extended CONNECT, calling the responder with a C<200> response is
the correct way to accept the tunnel.

    my $env = shift;
    return sub {
        my $fh = $env->{'psgix.io'};
        syswrite $fh, "HTTP/1.1 101 Switching Protocols\r\n"
                     . "Upgrade: myproto\r\nConnection: Upgrade\r\n\r\n";
        # ... bidirectional I/O on $fh ...
    };

B<HTTP/2 note:> For H2 Extended CONNECT tunnels, Feersum automatically sends
200 HEADERS to accept the tunnel and silently swallows the HTTP/1.1 101
response written by the app.  This means the same handler code works for both
H1 and H2 without branching.  See L</HTTP/2 Support> for details.

=item psgix.h2.trailers

An array-ref of alternating C<name, value> entries (a flat list, not nested
pairs) containing HTTP/2 trailer headers received with the request.  Only
present for HTTP/2 requests that included trailers.  Absent for HTTP/1.x
requests and H2 requests without trailers.

=item psgix.h2.extended_connect

Set to C<1> on HTTP/2 Extended CONNECT streams (RFC 8441).  Absent for
all other request types including plain HTTP/2 requests.

=item psgix.h2.protocol

Present on HTTP/2 Extended CONNECT streams.  Contains the value of the
H2 C<:protocol> pseudo-header (e.g. C<"websocket">).

=item psgix.proxy_tlvs

Present when the connection arrived via PROXY protocol v2 with TLV
extensions.  A hash ref mapping TLV type numbers to their raw values.
See L<Feersum::Connection/"my $tlvs = $req-E<gt>proxy_tlvs"> for details.

The protocol permits a type to repeat, but a hash cannot: the B<last>
occurrence wins and earlier ones are not visible.  That matters if you validate
one TLV against another, since some senders emit repeated sub-TLVs.

=back

=head2 The Feersum-native interface

The Feersum-native interface is inspired by PSGI, but is inherently
B<incompatible> with it.  Apps written against this API will not work as a
PSGI app.

The native interface has been stable since version 1.0; it will only change
for bug fixes or backwards-compatible additions until at least the next
major release.

The main entry point is a sub-ref passed to C<request_handler>.  This sub is
passed a reference to an object that represents an HTTP connection.  Currently
the request_handler is called during the "check" and "idle" phases of the EV
event loop.  The handler is always called after request headers have been
read.  Currently, the handler will B<only> be called after a full request
entity has been received for POST/PUT/etc.

The simplest way to send a response is to use C<send_response>:

    my $req = shift;
    $req->send_response(200, \@headers, ["body ", \"parts"]);

Or, if the app has everything packed into a single scalar already, just pass
it in by reference.

    my $req = shift;
    $req->send_response(200, \@headers, \"whole body");

Both of the above will generate C<Content-Length> header (replacing any that
were pre-defined in C<@headers>).  Response strings are bytes; see the note
under L</"PSGI interface"> for how UTF8-flagged strings are handled.

An environment hash is easy to obtain, but is a method call instead of a
parameter to the callback. (In PSGI, there is no $req object; the env hash is
the first parameter to the callback).  The hash contains the same items as it
would for a PSGI handler (see above for those), except C<psgix.io>, which is
only added for PSGI handlers; from a native handler use C<< $req->io() >>
instead.

    my $req = shift;
    my $env = $req->env();

To read input from a POST/PUT, use the C<psgi.input> item of the env hash.

    if ($env->{REQUEST_METHOD} eq 'POST') {
        my $body = '';
        my $r = delete $env->{'psgi.input'};
        $r->read($body, $env->{CONTENT_LENGTH});
        # or line-wise: my $line = $r->getline; # also <$r>, honouring $/
        # optional:
        $r->close();
    }

Starting a response in stream mode enables the C<write()> method (which really
acts more like a buffered 'print').  Calls to C<write()> will never block.

    my $req = shift;
    my $w = $req->start_streaming(200, \@headers);
    $w->write(\"this is a reference to some shared chunk\n");
    $w->write("regular scalars are OK too\n");
    $w->close(); # close off the stream

The writer object supports C<poll_cb> as specified in PSGI.  Feersum
will call the callback only when all data has been flushed out at the socket
level.  Use C<close()> or unset the handler (C<< $w->poll_cb(undef) >>) to
stop the callback from getting called.

    my $req = shift;
    my $w = $req->start_streaming(
        "200 OK", ['Content-Type' => 'application/json']);
    my $n = 0;
    # Keep $w alive: registering a poll_cb does NOT hold the writer open, and
    # dropping the last reference closes the response.  See below.
    $KEEP{0+$w} = $w;
    $w->poll_cb(sub {
        # $_[0] is a fresh handle for THIS invocation, not $w itself:
        # key the stash off $w, which the closure already captures.
        $_[0]->write(get_next_chunk());
        if ($n++ >= 100) { delete $KEEP{0+$w}; $_[0]->close }
    });

B<You must keep a reference to the writer alive> for as long as you intend to
stream.  C<< $w->close() >> is called when the last reference is dropped, so a
writer that only the C<poll_cb> registration refers to is closed as soon as the
handler returns - the callback never fires and the client gets an empty body.
Store it somewhere that outlives the handler (as above) and drop it when done.

C<poll_cb> is also the only backpressured way to stream.  It fires when the
socket has drained, so an endless source paces itself against the client (see
C<wbuf_low_water>).  A bare C<< $w->write() >> loop does not: it buffers
whatever you give it, so an app that produces independently of the client - SSE,
a log tail - can grow unboundedly against a peer that stops reading but keeps
the connection alive.  Use C<poll_cb> for any source you do not control.

On Linux the writer also supports zero-copy file responses via
C<< $w->sendfile($fh [, $offset, $length]) >> (not available for HTTP/2
streams); see L<Feersum::Connection::Handle/"$w-E<gt>sendfile($fh [, $offset, $length])">.

=head1 METHODS

These are methods on the Feersum server object.

=over 4

=item C<< new() >>

=item C<< endjinn() >>

Returns the C<Feersum> singleton. Takes no parameters.

=item C<< new_instance() >>

Creates a new independent Feersum server instance. Unlike C<new()>, each
call returns a separate server object with its own listeners, configuration,
and request handler. Use this when you need multiple independent servers in
the same process.

    my $http  = Feersum->new_instance();
    my $https = Feersum->new_instance();

Create instances at startup and keep them.  A server object is retained for
the life of the process even after you drop your reference to it (its ev
watchers and any live connections point into it), so calling this repeatedly
in a loop accumulates memory.

Dropping the reference does not stop the server: it goes on accepting and
serving on its listeners, and you no longer hold a handle with which to stop
it.  Call C<unlisten()> or C<graceful_shutdown()> B<before> letting an
instance go out of scope.

See C<eg/multi-instance.pl> for two instances with separate handlers.

=item C<< use_socket($sock) >>

Use the file-descriptor attached to a listen-socket to accept connections.

B<Note:> Pre-encrypted sockets (e.g. L<IO::Socket::SSL>) are not supported.
Feersum operates on the raw file descriptor and will ignore any userspace
encryption layer.  To enable TLS, use C<set_tls()> after adding the socket;
Feersum handles encryption internally via picotls.

A reference to C<$sock> is kept internally to prevent garbage collection.
Registering the same socket twice does not add a second reference.

The listening descriptor must be non-blocking.  Feersum accepts several
connections per event-loop iteration, so on a blocking listener the C<accept()>
that follows the last pending connection blocks and wedges the entire loop.
Feersum sets C<O_NONBLOCK> on the descriptor for you, but a socket you continue
to use elsewhere is affected by that change.

=item C<< accept_on_fd($fileno) >>

Use the specified fileno to accept connections.  May be used as an alternative
to C<use_socket>.  The same non-blocking requirement applies.

=item C<< unlisten() >>

Stop listening on all sockets previously added via C<use_socket()> or
C<accept_on_fd()>: the accept watchers are stopped and the listener slots
freed.  The underlying socket file descriptors are B<not> closed -- they
stay open until the Perl socket objects are garbage-collected, so they can
be handed to C<accept_on_fd()> again (this is how pre-fork worker respawn
re-arms accept).  To actually close the listen fds, use C<graceful_shutdown()>.

A connection reads C<SERVER_NAME> and C<SERVER_PORT> from its listener slot at
request time, not at accept time.  If a keep-alive connection is still open
when you unlisten and then listen on a B<different> socket, the freed slot is
reused and that connection's later requests report the new listener's name and
port.  The respawn pattern above re-registers the same sockets, so nothing
changes there; if you are swapping in different ones, drain first.

=item C<< pause_accept() >>

Temporarily stop accepting new connections.  Existing connections continue
to be processed.  Returns true if any listener was newly paused, false if
all listeners were already paused or during shutdown.

Useful for load shedding or controlled traffic management.

=item C<< resume_accept() >>

Resume accepting new connections after a pause_accept() call.  Returns true
if any listener was resumed, false if none were user-paused or during
shutdown.

=item C<< accept_is_paused() >>

Returns true if accepting is currently paused on all listeners, false
otherwise.  With multiple listen sockets, all must be paused for this to
return true.

=item C<< request_handler(sub { my $req = shift; ... }) >>

Sets the global request handler.  Any previous handler is replaced.

The handler callback is passed a L<Feersum::Connection> object.

B<Subject to change>: if the request has an entity body then the handler will
be called B<only> after receiving the body in its entirety.  The body may use
Content-Length or chunked Transfer-Encoding.  The maximum size defaults to
67108864 bytes and can be changed via C<max_body_len()>.

=item C<< psgi_request_handler(sub { my $env = shift; ... }) >>

Like request_handler, but assigns a PSGI handler instead.

=item C<< read_timeout() >>

=item C<< read_timeout($duration) >>

Get or set the global read timeout.  Default is 5 seconds.  Must be a
positive non-zero value; passing 0 or a negative value will croak.  Changes
take effect for new connections only; existing connections retain the
timeout they were accepted with.

Feersum will wait about this long to receive all headers of a request (within
the tolerances provided by libev).  If an entity body is part of the request
(e.g. POST or PUT) it will wait this long between successful C<read()> system
calls.  This timeout also serves as the keepalive idle timeout between
requests on persistent connections; there is no separate setting for that.

A response counts as delivered once its bytes are queued, so on a large one the
kernel may still be handing it to the client long after that.  Feersum defers
the idle reap while the socket send queue is still draining, so a client merely
slow to read keeps its connection; a client that stops reading altogether is
still reaped, one interval later.  A client that keeps reading, however slowly,
is bounded by C<write_timeout> rather than by this clock.  The deferral needs a
kernel send-queue count, which Feersum does not use on OpenBSD or NetBSD -
there, size C<read_timeout> above the time your slowest client needs to drain
your largest response.

On HTTP/2 it is the only idle watchdog the connection has, and it counts
silence in B<either> direction.  A dispatched stream normally exempts the
connection from this clock, so that a slow SSE or long-poll response that says
nothing for a while is not reaped; but a stream that still owes the peer
response bytes it will not take is not idle, it is stalled.  A client that
opens streams, advertises a zero flow-control window and then goes silent
would otherwise pin one buffered response body per stream, and the connection
itself, for as long as it stayed quiet.  Such a connection is reaped after a
few consecutive intervals of total silence with bytes still pending.  A client
that keeps reading, however slowly, sends WINDOW_UPDATEs that reset the count
and is bounded by C<write_timeout> instead, so this reaps a stalled peer rather
than a slow one.

=item C<< header_timeout() >>

=item C<< header_timeout($seconds) >>

Get or set the header completion deadline timeout (Slowloris protection).
Default is 10 seconds; pass C<0> to disable it.

When enabled, connections must complete sending all HTTP headers within this
many seconds from connection acceptance or receive a 408 Request Timeout
response. For TLS connections where the handshake has not yet completed, the
connection is silently closed (no HTTP response can be sent before the
handshake finishes). This is a B<hard deadline> that does not reset when data
arrives, unlike C<read_timeout> which resets on each successful read.

This provides protection against Slowloris-style attacks where malicious
clients send headers very slowly to exhaust server connection resources.

B<It bounds the header phase only.>  Once the headers are complete the deadline
is dropped and the B<request body> is governed by C<read_timeout>, which resets
on every successful read - so a client trickling one body byte per
C<read_timeout> holds its connection open indefinitely.  This matches nginx's
C<client_body_timeout>, but note the interaction with C<max_connections>: a
connection stalled mid-body is never eligible for the idle-keepalive eviction
that reclaims capacity, so enough slow-body clients can occupy the whole
budget.  If you accept requests from untrusted clients, put a reverse proxy in
front (which buffers the body) rather than relying on C<max_connections> alone,
and consider setting C<write_timeout>, which is disabled by default and is the
matching deadline for the response phase.

Unlike the other per-connection tunables, this one is read live rather than
snapshotted at accept: the deadline is re-armed at the start of each request,
so lowering it under attack takes effect on connections that are already open,
including for the next request on a keepalive connection.

Recommended value for direct internet exposure: 30-60 seconds. When running
behind a reverse proxy (nginx, HAProxy), this can typically be left disabled
since the proxy handles slow clients.

=item C<< graceful_shutdown(sub { .... }) >>

Causes Feersum to initiate a graceful shutdown of all outstanding connections.
No new connections will be accepted.  All listen socket file descriptors are
closed; the Perl socket objects are not freed but the underlying fds are
invalid after this call.

C<graceful_shutdown> is intended to be terminal: because the retained Perl
socket objects still hold the (now-closed) fds, they will close those fd
numbers again when the server object is eventually destroyed.  The process
should exit once the completion callback fires (as C<Feersum::Runner> does via
C<POSIX::_exit>) rather than continue running and reuse the freed fd numbers.

The sub parameter is a completion callback.  It will be called when all
connections have been flushed and closed.  This allows one to do something
like this:

    my $cv = AE::cv;
    my $death = AE::timer 2.5, 0, sub {
        fail "SHUTDOWN TOOK TOO LONG";
        exit 1;
    };
    Feersum->endjinn->graceful_shutdown(sub {
        pass "all gracefully shut down, supposedly";
        undef $death;
        $cv->send;
    });
    $cv->recv;

The C<$death> timer in that example is not decoration.  "All connections"
includes ones Feersum no longer times out: a socket taken over through
C<psgix.io> on HTTP/1.x or TLS, and an established RFC 8441 HTTP/2 tunnel.  Those are exempt from the read and write timeouts on purpose,
because a websocket may legitimately sit idle for hours, so nothing will ever
reap them and the completion callback will not fire while one is open.  A
caller that shuts down on its own must impose its own deadline, as the example
does.  L<Feersum::Runner> already does this via C<graceful_timeout> (default 5
seconds), after which it force-exits.

=item C<< DIED >>

Not really a method so much as a static function.  Works similar to
EV's/AnyEvent's error handler.

The error is passed as C<$_[0]>.  C<$@> is B<not> set: the handler is invoked
under C<G_EVAL>, which clears it.

The default implementation warns the error to STDERR.  To install a custom
handler:

    no strict 'refs';
    *{'Feersum::DIED'} = sub { warn "Error: $_[0]" };

A handler must not throw - see the note below - so C<Carp::confess> is not
usable here; use C<Carp::cluck> if you want a stack trace.

Will get called for any errors that happen before the request handler callback
is called, when the request handler callback throws an exception and
potentially for other not-in-a-request-context errors.

It will not get called for read timeouts or header deadline timeouts
(Slowloris protection) that occur while waiting for a complete header, nor
for timeouts while waiting for a request entity body.

Note: Any exceptions thrown by the DIED handler itself are caught, discarded
and B<not reported anywhere> (the handler is called with G_EVAL).  A handler
that dies is therefore silent.  The server will still respond with a 500 error
to the client.

The 500 can only be sent while the response has not started.  A handler (or
PSGI streaming callback) that dies B<mid-stream> instead has its response
sealed so the client can detect the truncation: HTTP/1.x closes the
connection without the terminating chunk, HTTP/2 sends C<RST_STREAM>.  A
response explicitly completed with C<< $w->close >> before the die is
delivered intact; merely letting the writer go out of scope does not count
as completion when the same callback then dies, since that drop is exactly
what an exception unwind looks like.

=item C<< set_server_name_and_port($host,$port) >>

Override Feersum's notion of what SERVER_NAME and SERVER_PORT should be.
Applies to the most recently added listener only; call it after each
C<use_socket()>/C<accept_on_fd()> when running multiple listeners.
(C<use_socket()> already calls this implicitly with values derived from
the socket.)

=item C<< get_keepalive() >>

=item C<< set_keepalive($bool) >>

Enable or disable keepalive for new connections.  Default is B<disabled>.
When enabled, HTTP/1.1 connections without an explicit C<Connection: close>
header will be kept alive between requests.  Changes take effect for new
connections only.

Returns the current setting (a boolean) when called as C<get_keepalive()>.

=item C<< get_drain_accept_queue() >>

=item C<< set_drain_accept_queue($bool) >>

When enabled, C<graceful_shutdown()> accepts whatever connections the kernel
has already queued on each TCP listen socket and serves them as part of the
drain, before closing the listener.  Default is B<disabled>.

Enable this when the listen socket is owned by this process alone - a
C<SO_REUSEPORT> socket, most notably - because such a socket's accept queue
dies with it: the queued clients completed their TCP handshake and would be
reset having sent nothing wrong.  L<Feersum::Runner> enables this
automatically for reuseport workers.  Leave it off for a listen socket shared
with other processes (the pre-fork inheritance model), where draining would
steal connections a live sibling is about to serve and lengthen this
process's shutdown for no benefit.

Accepted connections respect C<max_connections> and count toward the drain
that C<graceful_shutdown()> waits out.  UNIX-domain listeners are never
drained (under L<Feersum::Runner> they are shared even in reuseport mode).

Enabling this also turns C<TCP_DEFER_ACCEPT> off on the server's TCP
listeners, current and future: a deferred connection - established, but its
first data not yet arrived - is invisible to C<accept()>, so the shutdown
drain would otherwise close the listener on top of it.

Returns the current setting (a boolean) when called as
C<get_drain_accept_queue()>.

=item C<< set_reverse_proxy($bool) >>

Enable or disable reverse proxy mode.  Changes take effect for new
connections only.  When enabled, Feersum trusts
C<X-Forwarded-For> and C<X-Forwarded-Proto> headers from upstream proxies to
determine the client's real IP address and request scheme.

B<Security note:> Feersum uses the leftmost IP from C<X-Forwarded-For>,
which assumes a single-hop reverse proxy that overwrites (not appends to)
the header.  If your proxy appends to an existing C<X-Forwarded-For>,
clients can spoof their IP by sending a forged header.  Ensure your
reverse proxy strips or replaces C<X-Forwarded-For> rather than appending.

A second, subtler route: the CGI mapping folds dashes and underscores to the
same key, so a client-sent C<X_Forwarded_For> lands in
C<HTTP_X_FORWARDED_FOR> beside the proxy's real C<X-Forwarded-For>, and if it
arrives first it is leftmost.  This mode is not fooled by that - it reads the
exact header name off the wire, so C<REMOTE_ADDR> stays correct - but an
application reading C<HTTP_X_FORWARDED_FOR> itself can be.  The behaviour is
not specific to Feersum (Starman and L<HTTP::Server::PSGI> fold it the same
way); the fix is at the proxy, which should drop headers containing
underscores, as nginx does by default.

When this mode is active, C<env()> sets C<REMOTE_ADDR> and C<psgi.url_scheme>
from the forwarded headers, and the L<Feersum::Connection> methods
C<client_address()> and C<url_scheme()> return the forwarded values.  Note
that C<remote_address()> and C<remote_port()> always report the immediate
peer (they are not affected by this mode); use C<client_address()> for the
forwarded client address.

B<Combined with the PROXY protocol:> if C<proxy_protocol> is also enabled,
the two sources are used for different parts of the same peer.  C<REMOTE_ADDR>
comes from C<X-Forwarded-For> (this mode wins), while C<REMOTE_PORT> keeps the
value the PROXY header supplied, so the pair does not describe one endpoint.
The PROXY header is supplied by the upstream connection itself and cannot be
forged by the client, whereas C<X-Forwarded-For> can if your proxy appends
rather than replaces.  If you have a PROXY-protocol upstream, prefer it alone
and leave C<reverse_proxy> off.

=item C<< get_reverse_proxy() >>

Returns whether reverse proxy mode is currently enabled (1 or 0).

=item C<< max_connection_reqs() >>

Changes take effect for new connections only: the value is cached per connection at accept time.

=item C<< max_connection_reqs($count) >>

Get or set the maximum number of requests allowed per keep-alive connection.
Default is 0 (unlimited). When set to a positive value, the connection will
be closed after serving that many requests, even if keep-alive is enabled.

This is useful for preventing any single connection from monopolizing server
resources and helps with memory management by periodically recycling
connections.

B<HTTP/1.1 only.>  An HTTP/2 connection is not closed after this many streams -
multiplexing many requests over one connection is the point of the protocol.
Use C<max_h2_concurrent_streams()> to bound concurrency there, and
C<max_connections()> to bound connections overall.

=item C<< read_priority() >>

=item C<< read_priority($priority) >>

Get or set the libev watcher priority for read I/O operations.
Priority range is -2 (lowest) to +2 (highest), default is 0; out-of-range
values are silently clamped.
Higher priority watchers are invoked before lower priority ones.
Changes take effect for new connections only.

At -2 read watchers tie with Feersum's own dispatch watcher, so a request
is handled one event-loop iteration later than it was read, costing an
extra syscall per request.  Keep this above -2 unless you need it.

=item C<< write_priority() >>

=item C<< write_priority($priority) >>

Get or set the libev watcher priority for write I/O operations.
Priority range is -2 (lowest) to +2 (highest), default is 0; out-of-range
values are silently clamped.
Changes take effect for new connections only.

=item C<< accept_priority() >>

=item C<< accept_priority($priority) >>

Get or set the libev watcher priority for accept operations.
Priority range is -2 (lowest) to +2 (highest), default is 0; out-of-range
values are silently clamped.
Changes take effect for listeners added afterwards; existing listeners
keep the priority they were set up with.

=item C<< set_psgix_io($bool) >>

Enable or disable the C<psgix.io> PSGI extension (default: enabled).  When
disabled, Feersum skips setting up C<psgix.io> in the PSGI environment hash,
avoiding the overhead of creating a raw I/O handle for each request.

Disable this if your application never uses C<psgix.io> (WebSocket upgrades,
etc.) for a small performance improvement in the PSGI path.

Disabling it is also the fix if some middleware in your stack copies or dumps
the whole environment hash: reading the C<psgix.io> value takes over the
socket, so a full-hash read leaves the request with no response.  See
L</psgix.io>.

=item C<< get_psgix_io() >>

Returns whether C<psgix.io> is currently enabled (1 or 0).

=item C<< set_proxy_protocol($bool) >>

Enable or disable PROXY protocol support. When enabled, Feersum expects all
new connections to begin with a PROXY protocol header (v1 text or v2 binary
format, auto-detected) before any HTTP data.

The PROXY protocol is used by load balancers like HAProxy, AWS ELB/NLB, and
nginx to pass the original client IP address to backend servers. When a valid
PROXY header is received, REMOTE_ADDR and REMOTE_PORT are updated to reflect
the client's real address.

Special cases:
- PROXY v1 UNKNOWN: Keeps original address (used for health checks)
- PROXY v2 LOCAL: Keeps original address (used for health checks)
- PROXY v2 with UNSPEC or AF_UNIX address family: keeps original address

Connections without a valid PROXY header will be rejected with HTTP 400.

B<Only enable this when ALL connections come from a proxy that sends PROXY
headers.>

See C<eg/proxy-protocol.pl> for a runnable example.

=item C<< get_proxy_protocol() >>

Returns true if PROXY protocol support is enabled, false otherwise.

=item C<< max_accept_per_loop() >>

=item C<< max_accept_per_loop($count) >>

Get or set the maximum number of connections to accept per event loop
iteration. Default is 64.

Limiting accepts per loop prevents a flood of new connections from starving
existing connections of CPU time. Lower values provide more fairness between
new and existing connections; higher values improve throughput under heavy
connection load.

=item C<< active_conns() >>

Returns the current count of active connection objects being handled by
Feersum.  For HTTP/2, each concurrent stream counts as a separate unit in
addition to the underlying TCP connection, so a single H2 connection with
N streams contributes N+1 to this count.

=item C<< total_requests() >>

Returns the total number of requests processed since the server started.
Useful for monitoring and statistics. The counter is a native unsigned integer
(64-bit on 64-bit Perl builds, 32-bit on 32-bit builds).

=item C<< access_log() >>

=item C<< access_log($cb) >>

Get or set a callback invoked as each response completes, with
C<($method, $uri, $elapsed_seconds)>.  Pass C<undef> to disable it.  Returns the
current callback (or C<undef>).

Only requests that reached the handler are reported: one the server rejects
itself - malformed, over a limit, timed out - is answered without dispatching
and produces no line.  This is a service-time hook, not a CLF access log.

C<$elapsed> is measured from the moment the request was dispatched to the
handler until its response is fully flushed, so it is the request's own service
time - not, as a C<response_guard>-based logger would report under keepalive,
the interval until the following request.  An exception from the callback is
caught and reported as a warning; it does not affect the response, which has
already been sent by the time the callback runs.

L<Feersum::Runner>'s C<access_log> option is implemented with this.

=item C<< max_requests_per_worker() >>

=item C<< max_requests_per_worker($limit, $cb) >>

=item C<< max_requests_per_worker($limit, $cb, $retiring_cb) >>

Retire this process after it has handled C<$limit> requests: once the count is
reached Feersum stops accepting, closes its listeners, lets in-flight requests
drain, and then calls C<$cb>.  Setting C<$limit> to 0 disables it (no callback
is needed in that case).  Returns the current limit.

C<$retiring_cb>, if given, is called instead at the moment the limit is
reached, just before the drain begins.  The drain has no deadline of its own,
and this is the only notification that one has started, so a caller that needs
to bound it - as L<Feersum::Runner> does with C<graceful_timeout> - has to arm
its timer here.  An exception from it is caught and warned about.

The check happens in C where the request counter lives, so the limit is exact
and costs nothing per request.  L<Feersum::Runner>'s C<max_requests_per_worker>
option is implemented with this; a Perl-side watcher either polled (and
overshot a limit of 10 by several thousand under load) or had to run a callback
on every event-loop iteration.

This is per-process, so under C<pre_fork> it retires one worker, which the
supervisor then replaces.

=item C<< max_connections() >>

=item C<< max_connections($limit) >>

Get or set the maximum number of concurrent connections. Default is 10000.

When the limit is reached, Feersum first tries to close the oldest idle
keep-alive connection to make room.  If no idle connections are available, the
new connection is closed immediately after accept() and accepting is paused on
that listener until a connection slot frees up.  This provides protection
against Slowloris-style DoS attacks that attempt to exhaust server resources by
holding many connections open.

A connection whose client vanished mid-stream is neither idle keep-alive nor
freeing itself, so it can never be evicted to make that room; see
L</"PSGI interface"> for why a streaming application needs a heartbeat before
this limit is safe to rely on.

Setting this to 0 disables the limit. In production, consider also running
Feersum behind a reverse proxy (nginx, HAProxy) which can provide additional
connection limiting and rate limiting.

B<Note:> When HTTP/2 is in use, each H2 stream pseudo-connection counts toward
C<active_conns()> in addition to the TCP connection itself, so open streams
consume the budget for accepting further TCP connections.  Stream creation
itself is B<not> checked against this limit - use
C<max_h2_concurrent_streams()> to bound streams.

=item C<< max_read_buf() >>

Changes take effect for new connections only: the value is cached per connection at accept time.

=item C<< max_read_buf($bytes) >>

Get or set the maximum read buffer size per connection (default 64 MiB, 67108864 bytes).
This limits how large the read buffer can grow during header parsing and
chunked body reception.  A request that exceeds the limit while still in its
header block receives a 431 (the fields are too large, not the payload); a
chunked body that outgrows it receives a 413.  Set to 0 to reset to the
compile-time default.

The limit is B<approximate>, and where it bites depends on the transport.  On
a plain connection the buffer is checked before it grows, so a request is
rejected slightly below the configured value; on TLS the check happens after a
record has been decrypted, so a request may be accepted slightly above it.  The
difference is a few tens of KiB, which is immaterial at the default but worth
knowing if you set a very small value.  It is B<not> applied to HTTP/2, whose
request size is bounded instead by C<max_body_len>, by
C<max_h2_concurrent_streams>, and by the SETTINGS_MAX_HEADER_LIST_SIZE that
Feersum advertises to the peer.

=item C<< max_body_len() >>

Changes take effect for new connections only: the value is cached per connection at accept time.

=item C<< max_body_len($bytes) >>

Get or set the maximum request body size (default 64 MiB, 67108864 bytes).  This limits
C<Content-Length> values and cumulative chunked body sizes.  Requests that
exceed the limit receive a 413 response on both HTTP/1.1 and HTTP/2.  An H2
body of unknown length that outgrows the limit mid-stream is reset with
C<ENHANCE_YOUR_CALM> instead, there being no response to attach it to.
Set to 0 to reset to the compile-time default.

=item C<< max_uri_len() >>

Changes take effect for new connections only: the value is cached per connection at accept time.

=item C<< max_uri_len($bytes) >>

Get or set the maximum request URI length (default 8192 bytes).  URIs that
exceed the limit receive a 414 response on both HTTP/1.1 and HTTP/2.
Set to 0 to reset to the compile-time default.

=item C<< write_timeout() >>

Changes take effect for new connections only: the value is cached per connection at accept time.

=item C<< write_timeout($seconds) >>

Get or set the write/response timeout.  Default is 0 (disabled).

When enabled, connections that make no write progress within this many
seconds are forcibly closed.  The timer resets on each successful write.
This protects against slow consumers that stall the server by not reading
response data.  For HTTP/2, the timeout operates per-stream: a stalled
stream receives RST_STREAM rather than closing the entire connection.  It
covers a response held behind the peer's flow-control window, and separately
the connection itself when its outbound buffer backs up; both are reaped, and
progress on either refreshes the deadline, so a transfer too large to finish
within C<write_timeout> is not interrupted while it is still moving.
HTTP/2 tunnels (RFC 8441 Extended CONNECT) remain exempt, like C<psgix.io> --
but only up to a point: the exemption holds while the connection's queued
ciphertext stays under 16MB.  A tunnel peer that stops reading entirely, so
that its side of the socketpair reaches that, is closed like any other
stalled connection; the exemption spares an idle tunnel, not one being used to
pin unbounded memory.

On plain and TLS connections alike (including the HTTP/2 session), "progress"
includes the peer draining the kernel send buffer, not merely successful
writes: at each deadline Feersum asks the kernel (C<SIOCOUTQ> on Linux,
C<SO_NWRITE> on macOS, C<FIONWRITE> on FreeBSD/NetBSD; see
C<has_outq_probe()>) whether queued bytes have left since the previous check,
and pushes the deadline back if so.  Without that probe a client reading
steadily but slower than half the socket send buffer per interval would be
cut off mid-transfer, because the OS reports writability - and so permits a
deadline-refreshing write - only after half the buffer drains.  TLS buffers
ciphertext in user space on top of that, but flushing it waits on the same
writability signal, so the kernel's drain count is the honest progress
measure there too.  Because ACKs can arrive in MSS-sized clumps (64KB on
loopback), a single drain-free interval is not treated as proof of a stall;
a peer that drains nothing across three consecutive checks is closed, so a
genuinely stuck client still lasts only a small bounded multiple (at most
three intervals) of C<write_timeout>.  Where no probe exists (OpenBSD) a
slow-but-active reader may still be closed once the send buffer stays backed
up for a full interval.

The corollary is that C<write_timeout> bounds a I<stalled> transfer, not a
slow one: a client that keeps draining a trickle holds its connection for as
long as it cares to, exactly as a trickling request body does under
C<read_timeout>.  That is the same bargain nginx strikes, and it costs the
peer a byte for every byte it holds, but it means enough deliberately slow
readers can occupy C<max_connections>.  The advice is the same as for slow
bodies: put a reverse proxy in front of untrusted clients.
Disabled when the application takes over the socket via C<io()> or
C<psgix.io>, since the application owns the socket for as long as it holds it.
Over TLS the deadline does apply again once the application closes its end
while data it wrote is still queued, so a peer that stops reading cannot pin
that connection open forever.

B<On HTTP/2 the deadline is not cleared when the buffer drains, so it also
bounds the gap between an application's own writes.>  Once a streaming
response has called write at all - a zero-length write counts, since the
deadline tracks calls and not bytes - it must write again within this many seconds
or the stream is reset, even though the client is healthy and reading;
HTTP/1.x stops the timer once the data is gone and imposes no such rule.  A
long-lived HTTP/2 stream that has not written at all is unaffected, so
open-and-wait works, but an SSE or long-poll application that pushes an event
and then goes quiet needs C<write_timeout> either left at 0 or set above its
own heartbeat interval.

Independently of this deadline, an HTTP/2 connection's pending ciphertext is
capped at 16MB: past that Feersum stops draining nghttp2's output queue, which
leaves frames queued and lets nghttp2's own flood detection close a peer that
stops reading but keeps the session busy answering itself.  A response larger
than the cap is unaffected - the buffer refills as it drains.

=item C<< linger_timeout() >>

=item C<< linger_timeout($seconds) >>

Get or set the lingering-close deadline.  Default is 5 seconds; set to 0 to
disable lingering entirely.

An empty write buffer means the kernel send buffer accepted the response, not
that the client received it - megabytes can still be in flight.  A plain
C<close()> at that point orphans the socket, and any byte arriving afterwards
(a pipelined next request, a speculative write on a connection the client
believes is reusable) makes the kernel answer RST, which discards the queued
response at both ends.  So, like nginx and Apache, a completed HTTP/1.x
close-response instead performs a lingering close: C<shutdown(SHUT_WR)> queues
FIN behind the buffered response, and the server keeps reading and discarding
until the peer closes, 256 KB have been drained, or this many seconds have
passed - whichever comes first.  Error responses (including 413 replies to a
client still uploading) and idle keepalive reaps linger the same way; TLS
connections, HTTP/2 connections, write-timeout teardowns, and connections
closed during a graceful shutdown or by C<max_connections> eviction close
immediately as before.

A lingering connection holds its file descriptor and its C<max_connections>
slot for at most this long, which is why the default is much shorter than
nginx's 30 seconds: with keepalive disabled every response is a
close-response, so every connection pays it.

=item C<< wbuf_low_water() >>

Changes take effect for new connections only: the value is cached per connection at accept time.

=item C<< wbuf_low_water($bytes) >>

Get or set the write buffer low-water-mark.  Default is 0 (callback fires
only when the buffer is completely empty).

When using streaming responses with C<poll_cb>, this setting controls when
the write callback is invoked.  If set to a positive value, the callback
fires when the buffered data drops to or below this threshold, allowing the
application to keep the write pipe full for better throughput.  Works across
all transports (plain, TLS, and HTTP/2).

=item C<< get_multiprocess() >>

=item C<< set_multiprocess($bool) >>

Mark this server instance as running in a multi-process configuration.
When true, C<psgi.multiprocess> in the PSGI env hash will be set to true
(per the PSGI spec).  L<Feersum::Runner> sets this automatically when
C<pre_fork> is enabled.

Returns the current setting (a boolean) when called as C<get_multiprocess()>.

=item C<< max_h2_concurrent_streams() >>

=item C<< max_h2_concurrent_streams($n) >>

Get or set the maximum number of concurrent HTTP/2 streams per connection
(default: 100).  Sent in the SETTINGS frame during H2 handshake.  Lower
values reduce per-connection memory usage for WebSocket-heavy workloads;
higher values benefit multiplexed API traffic.  Requires H2 compiled in.

Values are clamped to the compile-time ceiling C<FEER_H2_MAX_CONCURRENT_STREAMS>
(default 100); requesting more silently saturates at that ceiling.  Values
below 1 are clamped to 1.

=item C<< max_h2_conn_body() >>

=item C<< max_h2_conn_body($bytes) >>

Get or set an aggregate cap on the request-body bytes buffered across all of a
connection's HTTP/2 streams before they dispatch.  Default C<0> (off), and the
per-request C<max_body_len> still applies either way.  Requires H2 compiled in.

C<max_body_len> bounds one request body, but HTTP/2 multiplexes: a peer can
open up to C<max_h2_concurrent_streams> of them at once, never send END_STREAM,
and dribble each toward the per-request limit, so the connection buffers that
product -- 100 x 64MiB = 6.25GiB at the defaults -- and C<read_timeout> does not
help, since it resets on every byte received.  Setting this bounds the sum: a
stream whose data would push the connection's buffered total over the cap is
reset with C<ENHANCE_YOUR_CALM> instead of appended.

It is off by default because any aggregate cap can bite a legitimate set of
large concurrent uploads on one connection.  If you accept H2 request bodies
from untrusted clients, set it to the most you are willing to buffer per
connection at once -- a few times C<max_body_len>, or as low as one C<max_body_len>
if you do not expect concurrent uploads.  Behind a body-buffering reverse proxy
it can be left off.

=item C<< set_tls(cert_file => $path, key_file => $path, [listener => $idx]) >>

Enable TLS 1.3 on a listener. Requires Feersum to be compiled with TLS
support (picotls submodule + OpenSSL; see L<Alien::OpenSSL>).

The cert_file should be a PEM-encoded certificate chain, and key_file the
corresponding PEM-encoded private key.

The optional C<listener> parameter specifies which listener to configure
(0-based index, in order of C<use_socket()>/C<accept_on_fd()> calls).
Defaults to the last-added listener.

Call this after C<use_socket()> or C<accept_on_fd()> to apply TLS to that
listener.  Croaks if no listeners have been configured yet or if the
C<listener> index is out of range.  Different listeners can have different
TLS configurations, or some can be plain HTTP while others use TLS.

    my $ngn = Feersum->endjinn;
    $ngn->use_socket($tls_socket);
    $ngn->set_tls(cert_file => 'default.crt', key_file => 'default.key');

For virtual hosting with multiple certificates on a single port, add SNI
entries after setting the default certificate:

    $ngn->set_tls(sni => 'example.com', cert_file => 'ex.crt', key_file => 'ex.key');
    $ngn->set_tls(sni => 'other.com',   cert_file => 'ot.crt', key_file => 'ot.key');

Clients requesting a hostname that matches an SNI entry get that certificate;
all others get the default.  Matching is case-insensitive.  Up to 32 SNI
entries per listener.

When TLS is enabled and L<Alien::nghttp2> was available at build time,
HTTP/2 can be enabled by passing C<< h2 => 1 >>.  Without this flag, only
C<http/1.1> is offered during ALPN negotiation:

    $ngn->set_tls(cert_file => 'server.crt', key_file => 'server.key',
                  h2 => 1);

C<< h2 => 1 >> is a listener-wide setting and cannot be combined with
C<< sni => >> in the same call (each SNI vhost shares the listener's ALPN
configuration).  Set C<< h2 => 1 >> on the initial default-certificate call
and then add C<< sni => >> entries without it.

L<Feersum::Runner> also accepts C<< h2 => 1 >> as a top-level option.

=item C<< has_tls() >>

Returns true if Feersum was compiled with TLS support (picotls).

=item C<< has_h2() >>

Returns true if Feersum was compiled with HTTP/2 support (nghttp2).

=item C<< has_outq_probe() >>

Returns true if this build can ask the kernel how much of a socket's send
queue is still undelivered (C<SIOCOUTQ>/C<SO_NWRITE>/C<FIONWRITE>), which
C<write_timeout> uses to spare slow-but-draining clients, plain and TLS alike.

=back

=cut

=head1 GRITTY DETAILS

=head2 Compile Time Options

There are a number of constants defined in feersum_core.h.  If you change
any of these, be sure to note that in any bug reports.

=over 4

=item MAX_HEADERS

Defaults to 64.  Controls how many headers can be present in an HTTP request.

If a request exceeds this limit the app handler does not run: HTTP/1.1 gets a
431 response - the fields are too large, as for an over-long header name -
and HTTP/2 a stream reset.

=item MAX_HEADER_NAME_LEN

Defaults to 128.  Controls how long the name of each header can be.

If a request exceeds this limit the app handler does not run: HTTP/1.1 gets a
431 response, HTTP/2 a stream reset.

=item MAX_TRAILER_HEADERS

Defaults to 64.  Caps how many trailer headers a chunked request (HTTP/1.1)
or an HTTP/2 request may carry.  Exceeding it is rejected: 400 for
HTTP/1.1, stream reset for HTTP/2.

=item MAX_CHUNK_COUNT

Defaults to 100000.  Caps how many chunks a single chunked request body may
consist of; bodies with more chunks are rejected with a 400 response.
Guards against CPU exhaustion from streams of tiny chunks.

=item MAX_PIPELINE_DEPTH

Defaults to 15.  Bounds how many pipelined HTTP/1.1 requests are dispatched
recursively off one read; deeper pipelines are deferred to the next event
loop iteration (they still complete, just without unbounded recursion).

=item FEER_MAX_LISTENERS

Defaults to 16.  Maximum number of listen sockets per server instance;
C<use_socket()>/C<accept_on_fd()> croak beyond this.

=item FEER_MAX_SNI_ENTRIES

Defaults to 32.  Maximum number of SNI certificate entries per listener.

=item MAX_URI_LEN

Defaults to 8192.  Controls the maximum length of the request URI (including
query string).

If a request exceeds this limit the app handler does not run; both HTTP/1.1 and
HTTP/2 get a 414 response.

=item MAX_BODY_LEN

Compile-time default for C<max_body_len()> (64 MiB).  Controls how large the
body of a POST/PUT/etc. can be.  Use C<max_body_len($bytes)> to override at
runtime.

See also L</BUGS>.

=item READ_BUFSZ

=item READ_GROW_FACTOR

READ_BUFSZ defaults to 4096, READ_GROW_FACTOR 4.

Together, these tune how data is read for a request.

Read buffers start out at READ_BUFSZ bytes.
If another read is needed and the remaining free space in the buffer is under
READ_BUFSZ bytes then the buffer grows by READ_GROW_FACTOR * READ_BUFSZ bytes.
The trade-off with the grow factor is memory usage vs. system calls.

=item READ_TIMEOUT

Controls read timeout. Default is 5.0 sec. Also used as the keepalive idle
timeout (there is no separate keepalive timeout setting).

=item FEERSUM_IOMATRIX_SIZE

Controls the size of the main write-buffer structure in Feersum.  Making this
value lower will use slightly less memory per connection at the cost of speed
(and vice-versa for raising the value).  The effect is most noticeable when
your app is making a lot of sparse writes.  The default of 64 generally
keeps usage under 4k per connection on full 64-bit platforms when you take
into account the other connection and request structures.

B<NOTE>: the struct is always C<FEERSUM_IOMATRIX_SIZE> entries; if your OS
defines a smaller C<IOV_MAX>/C<UIO_MAXIOV> (Solaris is 16; Linux and macOS are
1024), Feersum clamps the number of iovecs passed to each C<writev(2)> call at
runtime rather than changing the struct size.

=item FEER_H2_MAX_CONCURRENT_STREAMS

Default for C<max_h2_concurrent_streams()> (100).  Controls how many HTTP/2
streams a single connection can have open at once.  Override at runtime with
C<< $server->max_h2_concurrent_streams($n) >>.

=item FEER_H2_MAX_HEADER_LIST_SIZE

Maximum size of the header list per HTTP/2 request (64 KB).

=item FEERSUM_STEAL

For non-threaded perls, this defaults to enabled.

When enabled, Feersum will "steal" the contents of temporary lexical scalars
used for response bodies.  The scalars become C<undef> as a result, but due to
them being temps they likely aren't used again anyway.  Stealing saves the
time and memory needed to make a copy of that scalar, resulting in a mild to
moderate performance boost.

This egregious hack only extends to non-magical, string, C<PADTMP> scalars.

If it breaks for your new version of perl, please send stash a note (or a pull
request!) on github.

Worth noting is that a similar zero-copy effect can be achieved by using the
C<psgix.body.scalar_refs> feature.

=back

=head2 Environment Variables

=over 4

=item C<FEERSUM_FREELIST_MAX>

Read at module BOOT.  Caps the per-process freelist size for recycled
C<feer_req>/C<iomatrix> structs.  Default is 32.  Set to C<0> to disable
struct caching entirely (every request allocates fresh memory).  Lower
values reduce idle memory at the cost of allocator overhead under load.

=item C<FEERSUM_MAX_PRE_FORK>

Read by L<Feersum::Runner> at C<use>-time.  Caps the C<pre_fork> option;
asking for more workers than this value will croak.  Default is C<1000>.

=item C<FEERSUM_GRACEFUL_TIMEOUT>

Read by L<Feersum::Runner> when initiating a graceful shutdown; see
L<Feersum::Runner/graceful_timeout>.

=item C<FEERSUM_DEBUG>

When set, L<Feersum::Runner> keeps STDERR attached to the terminal during
daemonization (C<< daemonize => 1 >>) instead of redirecting it to
F</dev/null>.  Useful for debugging daemon startup.

=back

=head2 HTTP/2 Support

When Feersum is built with TLS (picotls + L<Alien::OpenSSL>) and HTTP/2
(L<Alien::nghttp2>) support, HTTP/2 can be negotiated via ALPN on TLS
connections.  HTTP/2 is B<disabled by default> and must be explicitly
enabled by passing C<< h2 => 1 >> to C<set_tls()> or to L<Feersum::Runner>.

=over 4

=item *

B<TLS-only> -- cleartext HTTP/2 (h2c) is not supported.  HTTP/2 is
negotiated exclusively through the C<h2> ALPN token during the TLS
handshake.

=item *

B<Request methods> -- all standard methods (GET, POST, PUT, DELETE, etc.)
are supported.  Request bodies are fully buffered before the handler is
called, same as HTTP/1.x.  B<Note:> unlike HTTP/1.1 where Feersum rejects
non-standard methods (TRACE, PROPFIND, etc.) with 405, HTTP/2 passes all
methods through to the request handler.

=item *

B<Streaming responses> -- the C<psgi.streaming> / C<start_streaming()>
interface works over HTTP/2, with each C<write()> producing DATA frames.

=item *

B<Multiple concurrent streams> -- the server processes many streams in
parallel on a single connection, up to C<FEER_H2_MAX_CONCURRENT_STREAMS>
(default 100).

=item *

B<Rapid-reset protection (CVE-2023-44487)> -- a connection that opens and
resets more than C<FEER_H2_RST_FLOOD_THRESHOLD> (200) streams within
C<FEER_H2_RST_FLOOD_WINDOW> (10) seconds is closed.  Server-initiated resets
(timeouts, internal errors) are not counted against the client.

=item *

B<Not supported> -- server push, server-sent trailers, streaming (incremental)
request bodies, and C<sendfile>.  For HTTP/2 responses, use C<write()> instead of
C<sendfile>.

=item *

B<IO::Handle response bodies> -- a PSGI response whose body is a filehandle or
C<getline>-style object is read to completion when the handler returns, with
bytes flushed to the client incrementally as they are read.  Unlike the
HTTP/1.x path this drain is not event-loop-paced: it does not read the socket
while running, so a very large or slow body occupies the worker until it is
fully read (a per-stream C<RST_STREAM> that keeps the connection open is not
noticed until the drain finishes).  For such responses prefer the streaming
writer API (C<start_streaming> + C<write>), which is driven by the event loop.

=item *

B<PSGI environment> -- C<psgi.url_scheme> is C<https> for HTTP/2 streams.
C<SERVER_PROTOCOL> is C<HTTP/2>.

=item *

B<Extended CONNECT / WebSocket tunnels (RFC 8441)> -- Feersum advertises
C<SETTINGS_ENABLE_CONNECT_PROTOCOL=1> so HTTP/2 clients can open WebSocket
tunnels via Extended CONNECT.  Feersum translates the H2 Extended CONNECT
into H1-equivalent PSGI env variables (matching HAProxy/nghttpx behaviour),
so existing PSGI WebSocket middleware works transparently:

    REQUEST_METHOD       => 'GET'             # translated from CONNECT
    HTTP_UPGRADE         => 'websocket'       # synthesised from :protocol
    HTTP_CONNECTION      => 'Upgrade'         # synthesised
    psgix.h2.protocol    => 'websocket'       # raw :protocol value
    psgix.h2.extended_connect => 1

The native C<< $req->method() >> likewise returns C<GET> for these streams.

The handler code is identical to HTTP/1.1 upgrades: write an C<HTTP/1.1 101>
response line followed by C<Upgrade:> / C<Connection:> headers via C<psgix.io>
(or C<< $req->io() >>).  Under H2, Feersum automatically sends 200 HEADERS to
accept the tunnel and silently swallows the HTTP/1.1 101 response written by
the app, relaying only the subsequent data as H2 DATA frames.  This means the
same PSGI handler works for both H1 and H2 without any protocol branching.

C<< psgix.io >> (or C<< $req->io() >>) returns a bidirectional handle backed
by a Unix socketpair; Feersum bridges bytes between that handle and the
HTTP/2 DATA frames in both directions.

=back

See C<eg/h2-server.pl> for a runnable server that serves h2 and HTTP/1.1 on
the same listener via ALPN.

=head1 PERFORMANCE

Benchmark results on a typical Linux server (single process, single thread,
loopback, C<wrk -t4 -c100 -d30>, "Hello World" response):

    Feersum native:  ~210K req/s
    Feersum PSGI:    ~132K req/s
    Gazelle:          ~44K req/s
    Starlet:          ~23K req/s
    Twiggy:           ~14K req/s
    Mojolicious:      ~2.8K req/s

Read the table as orientation, not a controlled comparison: Feersum runs
with keepalive on, Gazelle has no keepalive support at all, and Starlet
serves one request per connection unless raised, so those two pay a TCP
setup per request.

The native C<request_handler> avoids PSGI env hash construction and is
roughly 50% faster.  TLS 1.3 via vendored picotls costs about 18% on the
native interface and under 10% on PSGI, where per-request work dominates;
expect more without AES-NI.  In PSGI mode Feersum is 3-10x faster than
other popular Perl PSGI servers.

Run C<bash bench/compare.sh> to get numbers on your own hardware.
See also C<bench/run.sh> (plain HTTP and prefork), C<bench/run_tls.sh>
(TLS), C<bench/run_unix.sh> (unix sockets), and C<bench/pipeline.pl>
(HTTP/1.1 pipelining).

=head1 DEPLOYMENT

=head2 Systemd

    # /etc/systemd/system/feersum.socket
    [Socket]
    ListenStream=80

    [Install]
    WantedBy=sockets.target

    # /etc/systemd/system/feersum.service
    [Service]
    ExecStart=/usr/bin/perl /path/to/app.pl
    NonBlocking=true
    User=www-data
    Group=www-data

See C<eg/systemd-socket.pl> for socket activation code.

=head2 Docker

    HEALTHCHECK --interval=5s CMD curl -sf http://localhost:5000/health

See C<eg/healthcheck.pl> for a health check endpoint pattern.

=head2 Reverse Proxy

Feersum works behind nginx, HAProxy, Caddy, or Envoy.  See C<eg/nginx.conf>,
C<eg/haproxy.cfg>, C<eg/Caddyfile>, C<eg/envoy.yaml> for example configs.
Enable C<reverse_proxy> or C<proxy_protocol> as appropriate.

=head2 Zero-Downtime Restart

For a B<PSGI> app, use L<Plack::Handler::Feersum> - it is the handler that
installs the app with C<psgi_request_handler>:

    plackup -s Feersum --app-file=app.psgi --hot-restart=1 --pre-fork=4 \
        --listen 0.0.0.0:5000 app.psgi
    kill -HUP <master-pid>   # zero-downtime reload of app code

C<--app-file> is required: hot restart re-reads the app from disk in each new
generation, and plackup's positional argument only supplies an already-compiled
app.  Without it the server croaks with C<hot_restart requires app_file>.

L<Feersum::Runner> installs a B<native> handler, so use it directly only with
a native app file:

    perl -MFeersum::Runner -e '
        Feersum::Runner->new(
            listen      => ["0.0.0.0:5000"],
            app_file    => "app.feersum",
            hot_restart => 1,
            pre_fork    => 4,
        )->run;
    '

See C<eg/hot-reload.pl> for a complete example.

=head1 UPGRADING

Upgrading from 1.505 is a large jump.  Most changes are
additive, but the following can affect a working application without any code
change on your part.  Nothing here needs action if your app is a plain PSGI
handler served over HTTP/1.1 with default settings.

=head2 Requirements

Perl 5.14 or newer is now required (was 5.8.7).

=head2 New and lowered default limits

These are new DoS protections.  Each is configurable; a request exceeding one
is rejected by the server before your handler runs, so the app sees nothing.

    setting            1.505             now
    -----------------  ----------------  ------------------
    max_body_len       2 GiB             64 MiB
    max_uri_len        (no limit)        8192      -> 414
    max_read_buf       (no limit)        64 MiB    -> 431/413
    max_connections    (no limit)        10000
    header_timeout     (none)            10 seconds
    write_timeout      (none)            0 (off)
    max_h2_conn_body   (n/a)             0 (off)   H2 only

Raise any of them with the corresponding method if your application accepts
large uploads or long query strings; see L</METHODS>.  C<max_h2_conn_body> is
off by default; enable it to bound the request-body memory an HTTP/2 peer can
tie up across many concurrent streams.

=head2 Privilege drop clears supplementary groups

C<Feersum::Runner>'s C<user> option previously called only C<setuid>: without a
matching C<group>, the process kept its original GID and every supplementary
group, so a daemon started as root and "dropped" to an unprivileged user
retained root's group memberships (on a typical Linux box that includes
C<shadow> and C<docker>).  C<user> now also derives the group from that user's
passwd entry and clears supplementary groups, and the drop is verified.

A configuration that cannot complete the group drop now croaks instead of
continuing with the groups intact.

=head2 Stricter request parsing

Requests that 1.505 accepted are now rejected:

=over 4

=item * An HTTP/1.1 request with no C<Host:> header is answered with 400 (RFC
9112 requires it).  Hand-written health checks and some load-balancer probes
send one without.  HTTP/1.0 requests without C<Host:> are still accepted.

=item * Both C<Content-Length> and C<Transfer-Encoding> present: 400.

=item * Any C<Transfer-Encoding> on an B<HTTP/1.0> request: 400.  1.505 ignored
the header entirely on 1.0, so C<Content-Length> framed the message.  That is
the dangerous half of a TE.CL desync - a front end honouring
C<Transfer-Encoding> and Feersum honouring C<Content-Length> disagree on where
the request ends (RFC 9112 section 6.1), and nginx's default
C<proxy_http_version> is 1.0.  C<Transfer-Encoding> is not defined for
HTTP/1.0, so it is now rejected rather than silently ignored.

=item * A duplicate C<Host:> header: 400.

=item * Obsolete line folding (a continuation line) in a request header: 400.
1.505 silently dropped the continuation.

=item * C<Transfer-Encoding> on a method that takes no body: 400.  An
unsupported transfer coding: 501.

=item * An C<Expect:> value other than C<100-continue>: 417.  1.505 ignored
C<Expect:> entirely.

=item * A header name longer than 128 bytes: 431.  1.505 documented this limit
but never enforced it.

=item * A C<Content-Length> with a leading sign, such as C<+5>: 400.  RFC 9110
section 8.6 defines it as C<1*DIGIT>, and an intermediary that rejects or
reinterprets the value while Feersum accepts it is a smuggling desync.
Surrounding whitespace is still accepted - it is legal OWS.

=item * A PROXY protocol v2 frame whose TLV block ends in a 1 or 2 byte
remainder: rejected.  Such a tail is too short to be a TLV header, so it is the
same malformation as a TLV whose declared length overruns the block, which was
already rejected; the two now agree.  The protocol pads with C<PP2_TYPE_NOOP>,
never with a bare remainder.

=back

An absolute-form request target (C<GET http://host/path HTTP/1.1>, which RFC
9112 section 3.2.2 requires a server to accept) now yields the B<path> in
C<PATH_INFO>.  1.505 put the whole C<http://host/path> there, so no route or
ACL matched it.  C<REQUEST_URI> still carries the raw target, unchanged.

=head2 TLS

A client that offers ALPN but shares no protocol with the server now gets a
fatal C<no_application_protocol> alert, as RFC 7301 section 3.2 requires.
1.505 silently fell back to HTTP/1.1, so a client offering only an unknown
protocol token used to get a working HTTP/1.1 connection and now gets a
handshake failure.  Clients that send no ALPN extension at all are unaffected.

=head2 Response behaviour

=over 4

=item * A response to C<HEAD> no longer carries a body (RFC 9110 section
9.3.2).  Handlers may keep returning one; Feersum measures it for
C<Content-Length> and transmits only the headers.

=item * 1xx and 204 responses no longer pass through an application-supplied
C<Content-Length>, and 205 is now treated as a no-body status.

=item * A no-body status returned B<with> a body now sends none of it, whatever
form the body takes - an array, a filehandle, or C<sendfile>.  Such a response
carries no framing, so those bytes previously arrived undelimited and the next
response on a keepalive connection was read as their continuation.  A handler
that answers 304 without discarding an already-open filehandle is the usual way
to hit this.

=item * A streaming response now honours an application-supplied
C<Content-Length> instead of discarding it.  If yours is wrong the response
will be truncated or over-long; either correct it or omit it and let Feersum
use chunked framing.

=item * A response header name or value containing CR or LF is rejected with
500 (CWE-113 response splitting).  This breaks the old trick of packing two
C<Set-Cookie> values into one string.

=item * A UTF8-flagged response string (body, header value or status message)
whose characters all fit in a byte is now sent as its downgraded bytes, the
way C<syswrite>-based servers such as L<Starman> and L<Twiggy> send it.  Such
strings used to go out in Perl's internal UTF-8 encoding - consistently
framed, but a byte-level difference from every other PSGI server.  Strings
holding characters above 255 (illegal in a PSGI response) still go out in the
internal encoding with consistent framing.

=item * Duplicate request headers are now joined (with C<", ">, or C<"; "> for
C<Cookie>) rather than only the first being reported.

=back

=head2 PSGI environment

=over 4

=item * C<psgi.input> is always a reader object, even for a request with no
body (PSGI 1.1 requires this).  Code using C<< if ($env->{'psgi.input'}) >> as
a has-a-body test must check C<CONTENT_LENGTH> instead.

=item * C<psgix.input.buffered> is no longer advertised.  The handle was
always forward-only (C<seek> cannot rewind), while the flag tells consumers
like L<Plack::Request> that C<seek(0,0)> restores the whole body - so
C<< ->content >> after C<< ->body_parameters >> silently returned C<''>.
With the flag absent, such consumers buffer the body themselves and every
ordering works.  Reads on C<psgi.input> still never block.  An app that
tested the flag before reading incrementally will now take its own buffered
path; the input handle additionally supports C<getline>/C<getlines> and
C<< <$fh> >> since 1.507.

=item * C<psgi.multiprocess> is true when running under C<pre_fork>.

=item * C<return_from_psgix_io()> (and the native C<return_from_io()>) now
croak unless the handle handed back is the one that wraps this connection's
socket.  Passing a different filehandle used to be accepted, and it spliced
that handle's buffered bytes into this connection's next request while leaving
the real handle able to close a descriptor Feersum had reclaimed.

=item * Handing the socket back now takes a private duplicate of the
descriptor, so the returned handle no longer shares one with Feersum.  Code
written to the old rule (keep a reference alive for the life of the process,
because there was no safe moment to drop it) still works and can now simply
release the handle when it is done.

=back

=head2 Error reporting

The default C<Feersum::DIED> now warns the exception to STDERR.  It previously
called C<Carp::confess>, whose exception was in turn swallowed by the C<G_EVAL>
the handler is invoked under - so an unhandled application exception produced a
500 and B<no output at all>.  Expect to start seeing those errors in your logs.
Install your own handler (see L</DIED>) to change the format or silence them.

=head2 Runner, C<plackup> and the CLI

=over 4

=item * C<plackup -s Feersum -D> now really daemonizes.  1.505 ignored the
flag, so a C<-D> that was harmless for years will now detach the process and
redirect STDERR to F</dev/null>.  Remove it under a supervisor.

=item * C<SIGTERM> is now handled and triggers a graceful shutdown, so the
process exits 0 rather than reporting death by signal, and shutdown may take
up to C<graceful_timeout>.

=item * C<--listen> in native mode accumulates instead of last-one-wins.  A
script that appended C<--listen> to override an earlier value will now bind
both addresses.

=item * C<bin/feersum --native> rejects unknown options instead of ignoring
them.  Leftover flags meant for another server will now be a fatal error.

=item * C<< read_timeout => 0 >> is now rejected; it was silently ignored.

=item * The Feersum object is no longer a hash reference, so the documented
1.505 accessor C<< Feersum->endjinn->{socket} >> no longer works.  Use the
public API.

=item * Per-connection tunables are snapshotted when the connection is
accepted, so changing them at runtime no longer affects live connections.
C<header_timeout> is the exception: it is re-read when each request starts,
so a change does reach connections that are already open.

=back

=head1 BUGS

Please report bugs using L<https://github.com/stash/Feersum/issues>

Request bodies are capped at C<MAX_BODY_LEN> (64 MiB by default).  For
untrusted clients it is still recommended to run Feersum behind a reverse
proxy that enforces tighter entity-size limits.

Although not explicitly a bug, the following may cause undesirable behavior.
Feersum will have set SIGPIPE to be ignored by the time your handler gets
called.  If your handler needs to detect SIGPIPE, be sure to do a
C<local $SIG{PIPE} = ...> (L<perlipc>) to make it active just during the
necessary scope.

Feersum is B<not thread-safe> and must not be used with Perl ithreads.
It uses global/static data structures (free lists, lookup tables) that are
not protected by locks.  Running Feersum in a multi-threaded environment
will cause race conditions and memory corruption.  Use pre-fork instead of
threads for parallelism.

=head1 SEE ALSO

Companion modules in this distribution:
L<Feersum::Runner>, L<Plack::Handler::Feersum>,
L<Feersum::Connection>, L<Feersum::Connection::Handle>.

Inspiration: L<https://en.wikipedia.org/wiki/Feersum_Endjinn>

picohttpparser: L<https://github.com/h2o/picohttpparser>

picotls: L<https://github.com/h2o/picotls>

=head1 AUTHORS

Jeremy Stashewsky, C<< stash@cpan.org >>

vividsnow - multi-instance, TLS 1.3 (picotls), HTTP/2 (nghttp2),
PROXY protocol v1/v2, security hardening

=head1 THANKS

Tatsuhiko Miyagawa for PSGI and Plack.

Marc Lehmann for EV and AnyEvent (not to mention JSON::XS and Coro).

Kazuho Oku for picohttpparser.

Luke Closs (lukec), Scott McWhirter (konobi), socialtexters and van.pm for
initial feedback and ideas.  Audrey Tang and Graham Termarsch for XS advice.

Hans Dieter Pearcey (confound) for docs and packaging guidance.

For bug reports: Chia-liang Kao (clkao), Lee Aylward (leedo)

Audrey Tang (au) for flash socket policy support.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Jeremy Stashewsky

Portions Copyright (C) 2010 Socialtext Inc.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14 or,
at your option, any later version of Perl 5 you may have available.

picohttpparser is Copyright 2009-2014 Kazuho Oku, Tokuhiro Matsuno, Daisuke
Murase, and Shigeo Mitsunari.  It is released under the same terms as Perl
itself (or, at your option, the MIT license).

picotls (bundled for TLS support) is Copyright (C) 2016-2025 DeNA Co., Ltd.,
Kazuho Oku, Fastly, and Christian Huitema, released under the MIT license
(the bundled PEM/base64 component is under the ISC license).  See the
per-file headers under F<picotls-git/> for the authoritative notices.

=cut
