package Feersum;
use 5.008007;
use strict;
use warnings;
use EV ();
use Carp ();
use Socket ();

our $VERSION = '1.507';

require Feersum::Connection;
require Feersum::Connection::Handle;
require XSLoader;
XSLoader::load('Feersum', $VERSION);

# numify as per
# http://www.dagolden.com/index.php/369/version-numbers-should-be-boring/
$VERSION = eval $VERSION; ## no critic (StringyEval, ConstantVersion)

our $INSTANCE;
my %_SOCKETS; # inside-out storage for socket refs (keyed by Scalar::Util::refaddr)

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
}

sub use_socket {
    my ($self, $sock) = @_;
    my $addr = Scalar::Util::refaddr($self);
    push @{$_SOCKETS{$addr}}, $sock; # keep ref to prevent GC
    my $fd = fileno $sock;
    Carp::croak "Invalid socket: fileno returned undef" unless defined $fd;
    $self->accept_on_fd($fd);

    # Try socket methods first, fall back to getsockname() for raw sockets
    my ($host, $port) = ('localhost', 80);
    if ($sock->can('sockhost')) {
        $host = eval { $sock->sockhost() } || 'localhost';
        $port = eval { $sock->sockport() } || 80; ## no critic (MagicNumbers)
    } else {
        # Raw socket (e.g., from Runner with SO_REUSEPORT) - use getsockname
        my $sockaddr = getsockname($sock);
        if ($sockaddr) {
            my $family = eval { Socket::sockaddr_family($sockaddr) };
            if (defined $family && $family == Socket::AF_INET()) {
                (my $packed_port, my $packed_addr) = Socket::sockaddr_in($sockaddr);
                $host = Socket::inet_ntoa($packed_addr) || 'localhost';
                # Use defined check - port 0 is valid (OS-assigned dynamic port)
                $port = defined($packed_port) ? $packed_port : 80;
            } elsif (defined $family && eval { Socket::AF_INET6() } && $family == Socket::AF_INET6()) {
                (my $packed_port, my $packed_addr) = Socket::sockaddr_in6($sockaddr);
                $host = Socket::inet_ntop(Socket::AF_INET6(), $packed_addr) || 'localhost';
                # Use defined check - port 0 is valid (OS-assigned dynamic port)
                $port = defined($packed_port) ? $packed_port : 80;
            }
        }
    }
    $self->set_server_name_and_port($host,$port);
    return;
}

# overload this to catch Feersum errors and exceptions thrown by request
# callbacks.
sub DIED { Carp::confess "DIED: $@"; }

# TLS convenience: set_tls on the just-added listener
# Usage: $server->use_socket($sock); $server->set_tls(cert_file => $path, key_file => $path);
# The XS method set_tls is already available directly.

1;
__END__

=head1 NAME

Feersum - A PSGI engine for Perl based on EV/libev

=head1 SYNOPSIS

    use Feersum;
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

=head1 DESCRIPTION

Feersum is an HTTP server built on L<EV>.  It fully supports the PSGI 1.1
spec including the C<psgi.streaming> interface and is compatible with Plack.
It also has its own "native" interface which is similar in a lot of ways to PSGI,
but is B<not compatible> with PSGI or PSGI middleware.

Feersum uses a single-threaded, event-based programming architecture to scale
and can handle many concurrent connections efficiently in both CPU and RAM.
It skips doing a lot of sanity checking with the assumption that a "front-end"
HTTP/HTTPS server is placed between it and the Internet.

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

A trivial hello-world handler can process in excess of 5000 requests per
second on a 4-core Intel(R) Xeon(R) E5335 @ 2.00GHz using TCPv4 on the
loopback interface, OS Ubuntu 6.06LTS, Perl 5.8.7.  Your mileage will likely
vary.

For even faster results, Feersum can support very simple pre-forking (See
L<feersum>, L<Feersum::Runner> or L<Plack::Handler::Feersum> for details).

=head1 INTERFACE

There are two handler interfaces for Feersum: The PSGI handler interface and
the "Feersum-native" handler interface.  The PSGI handler interface is fully
PSGI 1.1 compatible, supporting C<psgi.streaming>, C<psgix.input.buffered>,
and C<psgix.io>.  The Feersum-native handler interface is "inspired by" PSGI, but
does some things differently for speed.

Feersum will use "Transfer-Encoding: chunked" for HTTP/1.1 clients and
"Connection: close" streaming as a fallback.  Technically "Connection: close"
streaming isn't part of the HTTP/1.0 or 1.1 spec, but many browsers and agents
support it anyway.

Currently POST/PUT does not stream input, but read() can be called on
C<psgi.input> to get the body (which has been buffered up before the request
callback is called and therefore will never block).  Likely C<read()> will
change to raise EAGAIN responses and allow for a callback to be registered on
the arrival of more data. (The C<psgix.input.buffered> env var is set to
reflect this).

=head2 PSGI interface

Feersum fully supports the PSGI 1.1 spec including C<psgi.streaming>.

See also L<Plack::Handler::Feersum>, which provides a way to use Feersum with
L<plackup> and L<Plack::Runner>.

Call C<< psgi_request_handler($app) >> to register C<$app> as a PSGI handler.

    my $app = do $filename;
    Feersum->endjinn->psgi_request_handler($app);

The env hash passed in will always have the following keys in addition to
dynamic ones:

    psgi.version      => [1,1],
    psgi.nonblocking  => 1,
    psgi.multithread  => '', # i.e. false
    psgi.multiprocess => '',
    psgi.streaming    => 1,
    psgi.errors       => \*STDERR,
    SCRIPT_NAME       => "",

Feersum adds these extensions (see below for info)

    psgix.input.buffered   => 1,
    psgix.output.buffered  => 1,
    psgix.body.scalar_refs => 1,
    psgix.output.guard     => 1,
    psgix.io               => \$magical_io_socket,

Note that SCRIPT_NAME is always blank (but defined).  PATH_INFO will contain
the path part of the requested URI.

C<psgi.input> always contains a valid handle.  For requests without a body
(e.g. GET), reading from it returns 0 (empty stream).

    my $r = delete $env->{'psgi.input'};
    $r->read($body, $env->{CONTENT_LENGTH});
    # optional: choose to stop receiving further input, discard buffers:
    $r->close();

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
            $w->poll_cb(sub {
                $_[0]->write(get_next_chunk());
                # will also unset the poll_cb:
                $_[0]->close if ($n++ >= 100);
            });
        };
    };

Note that C<< $w->close() >> will be called when the last reference to the
writer is dropped.

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

C<psgix.input.buffered> is defined as part of PSGI 1.1. It means that calls to
read on the input handle will never block because the complete input has been
buffered in some way.

Feersum currently buffers the entire input in memory calling the callback.

B<Feersum's input behaviour MAY eventually change to not be
psgix.input.buffered!>  Likely, a C<poll_cb()> method similar to how the
writer handle works could be registered to have input "pushed" to the app.

=item psgix.output.guard

The streaming responder has a C<response_guard()> method that can be used to
attach a guard to the request.  When the request completes (all data has been
written to the socket and the socket has been closed) the guard will trigger.
This is an alternate means to doing a "write completion" callback via
C<poll_cb()> that should be more efficient.  An analogy is the "on_drain"
handler in L<AnyEvent::Handle>.

A "guard" in this context is some object that will do something interesting in
its DESTROY/DEMOLISH method. For example, L<Guard>.

=item psgix.io

The raw socket extension B<psgix.io> is provided in order to support
L<Web::Hippie> and websockets.  C<psgix.io> is defined as part of PSGI 1.1.
To obtain the L<IO::Socket> corresponding to this connection, read this
environment variable.

The underlying file descriptor will have C<O_NONBLOCK>, C<TCP_NODELAY>,
C<SO_OOBINLINE> enabled and C<SO_LINGER> disabled.

PSGI apps B<MUST> use a C<psgi.streaming> response so that Feersum doesn't try
to flush and close the connection.  Additionally, the "respond" parameter to
the streaming callback B<MUST NOT> be called for the same reason.

    my $env = shift;
    return sub {
        my $fh = $env->{'psgix.io'};
        syswrite $fh, "HTTP/1.1 200 OK\r\n\r\nHello from raw socket";
        close $fh;
    };

=back

=head2 The Feersum-native interface

The Feersum-native interface is inspired by PSGI, but is inherently
B<incompatible> with it.  Apps written against this API will not work as a
PSGI app.

B<This interface may have removals and is not stable until Feersum reaches
version 1.0>, at which point the interface API will become stable and will
only change for bug fixes or new additions.  The "stable" and will retain
backwards compatibility until at least the next major release.

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
were pre-defined in C<@headers>).

An environment hash is easy to obtain, but is a method call instead of a
parameter to the callback. (In PSGI, there is no $req object; the env hash is
the first parameter to the callback).  The hash contains the same items as it
would for a PSGI handler (see above for those).

    my $req = shift;
    my $env = $req->env();

To read input from a POST/PUT, use the C<psgi.input> item of the env hash.

    if ($env->{REQUEST_METHOD} eq 'POST') {
        my $body = '';
        my $r = delete $env->{'psgi.input'};
        $r->read($body, $env->{CONTENT_LENGTH});
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
    $w->poll_cb(sub {
        # $_[0] is a copy of $w so a closure doesn't need to be made
        $_[0]->write(get_next_chunk());
        $_[0]->close if ($n++ >= 100);
    });

Note that C<< $w->close() >> will be called when the last reference to the
writer is dropped.

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

=item C<< use_socket($sock) >>

Use the file-descriptor attached to a listen-socket to accept connections.

B<Note:> Pre-encrypted sockets (e.g. L<IO::Socket::SSL>) are not supported.
Feersum operates on the raw file descriptor and will ignore any userspace
encryption layer.  To enable TLS, use C<set_tls()> after adding the socket;
Feersum handles encryption internally via picotls.

A reference to C<$sock> is kept internally to prevent garbage collection.

=item C<< accept_on_fd($fileno) >>

Use the specified fileno to accept connections.  May be used as an alternative
to C<use_socket>.

=item C<< unlisten() >>

Stop listening to the socket specified by use_socket or accept_on_fd.

=item C<< pause_accept() >>

Temporarily stop accepting new connections.  Existing connections continue
to be processed.  Returns true if paused successfully, false if already
paused or during shutdown.

Useful for load shedding or controlled traffic management.

=item C<< resume_accept() >>

Resume accepting new connections after a pause_accept() call.  Returns true
if resumed successfully, false if not paused or during shutdown.

=item C<< accept_is_paused() >>

Returns true if accepting is currently paused, false otherwise.

=item C<< request_handler(sub { my $req = shift; ... }) >>

Sets the global request handler.  Any previous handler is replaced.

The handler callback is passed a L<Feersum::Connection> object.

B<Subject to change>: if the request has an entity body then the handler will
be called B<only> after receiving the body in its entirety.  The headers
*must* specify a Content-Length of the body otherwise the request will be
rejected.  The maximum size is hard coded to 2147483647 bytes (this may be
considered a bug).

=item C<< psgi_request_handler(sub { my $env = shift; ... }) >>

Like request_handler, but assigns a PSGI handler instead.

=item C<< read_timeout() >>

=item C<< read_timeout($duration) >>

Get or set the global read timeout.

Feersum will wait about this long to receive all headers of a request (within
the tolerances provided by libev).  If an entity body is part of the request
(e.g. POST or PUT) it will wait this long between successful C<read()> system
calls.

=item C<< header_timeout() >>

=item C<< header_timeout($seconds) >>

Get or set the header completion deadline timeout (Slowloris protection).
Default is 0 (disabled).

When enabled, connections must complete sending all HTTP headers within this
many seconds from connection acceptance or receive a 408 Request Timeout
response. This is a B<hard deadline> that does not reset when data arrives,
unlike C<read_timeout> which resets on each successful read.

This provides protection against Slowloris-style attacks where malicious
clients send headers very slowly to exhaust server connection resources.

Recommended value for direct internet exposure: 30-60 seconds. When running
behind a reverse proxy (nginx, HAProxy), this can typically be left disabled
since the proxy handles slow clients.

=item C<< graceful_shutdown(sub { .... }) >>

Causes Feersum to initiate a graceful shutdown of all outstanding connections.
No new connections will be accepted.  The reference to the socket provided
in use_socket() is kept.

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

=item C<< DIED >>

Not really a method so much as a static function.  Works similar to
EV's/AnyEvent's error handler.

The default implementation calls C<Carp::confess> which prints a full
stack trace to STDERR. To install a custom handler:

    no strict 'refs';
    *{'Feersum::DIED'} = sub { warn "Error: $_[0]" };

Will get called for any errors that happen before the request handler callback
is called, when the request handler callback throws an exception and
potentially for other not-in-a-request-context errors.

It will not get called for read timeouts that occur while waiting for a
complete header (and also, until Feersum supports otherwise, time-outs while
waiting for a request entity body).

Note: Any exceptions thrown by the DIED handler itself are caught and will not
propagate (the handler is called with G_EVAL). The server will still respond
with a 500 error to the client.

=item C<< set_server_name_and_port($host,$port) >>

Override Feersum's notion of what SERVER_NAME and SERVER_PORT should be.

=item C<< set_keepalive($bool) >>

Override Feersum's default keepalive behavior.

=item C<< set_reverse_proxy($bool) >>

Enable or disable reverse proxy mode. When enabled, Feersum trusts
C<X-Forwarded-For> and C<X-Forwarded-Proto> headers from upstream proxies to
determine the client's real IP address and request scheme.

The L<Feersum::Connection> methods C<remote_addr()>, C<remote_port()>, and
C<env()> will automatically use the forwarded values when this mode is active.

=item C<< get_reverse_proxy() >>

Returns whether reverse proxy mode is currently enabled (1 or 0).

=item C<< max_connection_reqs() >>

=item C<< max_connection_reqs($count) >>

Get or set the maximum number of requests allowed per keep-alive connection.
Default is 0 (unlimited). When set to a positive value, the connection will
be closed after serving that many requests, even if keep-alive is enabled.

This is useful for preventing any single connection from monopolizing server
resources and helps with memory management by periodically recycling
connections.

=item C<< read_priority() >>

=item C<< read_priority($priority) >>

Get or set the libev watcher priority for read I/O operations.
Priority range is -2 (lowest) to +2 (highest), default is 0.
Higher priority watchers are invoked before lower priority ones.

=item C<< write_priority() >>

=item C<< write_priority($priority) >>

Get or set the libev watcher priority for write I/O operations.
Priority range is -2 (lowest) to +2 (highest), default is 0.

=item C<< accept_priority() >>

=item C<< accept_priority($priority) >>

Get or set the libev watcher priority for accept operations.
Priority range is -2 (lowest) to +2 (highest), default is 0.

=item C<< set_epoll_exclusive($bool) >>

Enable or disable the use of EPOLLEXCLUSIVE flag when accepting connections.
This is a Linux-specific optimization that prevents the "thundering herd"
problem when multiple worker processes are accepting on the same socket.

When enabled, the kernel will wake only one process when a new connection
arrives, rather than waking all waiting processes.

Only effective on Linux systems; has no effect on other platforms.

=item C<< get_epoll_exclusive() >>

Returns true if EPOLLEXCLUSIVE mode is enabled, false otherwise.

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

Connections without a valid PROXY header will be rejected with HTTP 400.

B<Only enable this when ALL connections come from a proxy that sends PROXY
headers.>

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

Returns the current count of active connections being handled by Feersum.
Useful for monitoring, load shedding decisions, or graceful shutdown logic.

=item C<< total_requests() >>

Returns the total number of requests processed since the server started.
Useful for monitoring and statistics. The counter is a 64-bit unsigned integer.

=item C<< max_connections() >>

=item C<< max_connections($limit) >>

Get or set the maximum number of concurrent connections. Default is 0
(unlimited).

When the limit is reached, new connections are immediately closed after
accept(). This provides protection against Slowloris-style DoS attacks that
attempt to exhaust server resources by holding many connections open.

Setting this to 0 disables the limit. In production, consider also running
Feersum behind a reverse proxy (nginx, HAProxy) which can provide additional
connection limiting and rate limiting.

=item C<< set_tls(cert_file => $path, key_file => $path, [listener => $idx]) >>

Enable TLS 1.3 on a listener. Requires Feersum to be compiled with TLS
support (picotls submodule + OpenSSL; see L<Alien::OpenSSL>).

The cert_file should be a PEM-encoded certificate chain, and key_file the
corresponding PEM-encoded private key.

The optional C<listener> parameter specifies which listener to configure
(0-based index, in order of C<use_socket()>/C<accept_on_fd()> calls).
Defaults to the last-added listener.

Call this after C<use_socket()> or C<accept_on_fd()> to apply TLS to that
listener. Different listeners can have different TLS configurations, or some
can be plain HTTP while others use TLS.

    my $ngn = Feersum->endjinn;
    $ngn->use_socket($tls_socket);
    $ngn->set_tls(cert_file => 'server.crt', key_file => 'server.key');

When TLS is enabled and L<Alien::nghttp2> was available at build time,
HTTP/2 can be enabled by passing C<< h2 => 1 >> (HTTP/2 is off by
default):

    $ngn->set_tls(cert_file => 'server.crt', key_file => 'server.key',
                  h2 => 1);

L<Feersum::Runner> also accepts C<< h2 => 1 >> as a top-level option.

=item C<< has_tls() >>

Returns true if Feersum was compiled with TLS support (picotls).

=item C<< has_h2() >>

Returns true if Feersum was compiled with HTTP/2 support (nghttp2).

=back

=cut

=head1 GRITTY DETAILS

=head2 Compile Time Options

There are a number of constants at the top of Feersum.xs.  If you change any
of these, be sure to note that in any bug reports.

=over 4

=item MAX_HEADERS

Defaults to 64.  Controls how many headers can be present in an HTTP request.

If a request exceeds this limit, a 400 response is given and the app handler does not run.

=item MAX_HEADER_NAME_LEN

Defaults to 128.  Controls how long the name of each header can be.

If a request exceeds this limit, a 400 response is given and the app handler does not run.

=item MAX_URI_LEN

Defaults to 8192.  Controls the maximum length of the request URI (including
query string).

If a request exceeds this limit, a 414 response is given and the app handler
does not run.

=item MAX_BODY_LEN

Defaults to ~2GB.  Controls how large the body of a POST/PUT/etc. can be when
that request has a C<Content-Length> header.

If a request exceeds this limit, a 413 response is given and the app handler does not run.

See also BUGS

=item READ_BUFSZ

=item READ_INIT_FACTOR

=item READ_GROW_FACTOR

READ_BUFSZ defaults to 4096, READ_INIT_FACTOR 1 and READ_GROW_FACTOR 4.

Together, these tune how data is read for a request.

Read buffers start out at READ_INIT_FACTOR * READ_BUFSZ bytes.
If another read is needed and the buffer is under READ_BUFSZ bytes
then the buffer gets an additional READ_GROW_FACTOR * READ_BUFSZ bytes.
The trade-off with the grow factor is memory usage vs. system calls.

=item AUTOCORK_WRITES

Controls how response data is written to sockets.  If enabled, the event loop
is used to wait until the socket is writable; if disabled (the default), a
write is performed immediately.  In either case, non-blocking writes are used.
Using the event loop is "nicer" but perhaps introduces latency, hence this
option.  Set to 1 in Feersum.xs to enable event-loop-based writes.

=item KEEPALIVE_CONNECTION

Vestigial compile-time constant (default 0).  Keepalive is now controlled at
runtime via C<< $server->set_keepalive(1) >>.  When enabled, "Connection:
keep-alive" for HTTP/1.0 and "Connection: close" for HTTP/1.1 are
acknowledged.

=item READ_TIMEOUT

Controls read timeout. Default is 5.0 sec. It is also an keepalive timeout.

=item FEERSUM_IOMATRIX_SIZE

Controls the size of the main write-buffer structure in Feersum.  Making this
value lower will use slightly less memory per connection at the cost of speed
(and vice-versa for raising the value).  The effect is most noticeable when
you're app is making a lot of sparce writes.  The default of 64 generally
keeps usage under 4k per connection on full 64-bit platforms when you take
into account the other connection and request structures.

B<NOTE>: FEERSUM_IOMATRIX_SIZE cannot exceed your OS's defined IOV_MAX or
UIO_MAXIOV constant.  Solaris defines IOV_MAX to be 16, making it the default
on that platform.  Linux and OSX seem to set this at 1024.

=item FEERSUM_STEAL

For non-threaded perls >= 5.12.0, this defaults to enabled.

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
called, same as HTTP/1.x.

=item *

B<Streaming responses> -- the C<psgi.streaming> / C<start_streaming()>
interface works over HTTP/2, with each C<write()> producing DATA frames.

=item *

B<Multiple concurrent streams> -- the server processes many streams in
parallel on a single connection, up to C<FEER_H2_MAX_CONCURRENT_STREAMS>
(default 100).

=item *

B<Not supported> -- server push, trailers, streaming (incremental) request
bodies, and C<sendfile>.  For HTTP/2 responses, use C<write()> instead of
C<sendfile>.

=item *

B<PSGI environment> -- C<psgi.url_scheme> is C<https> for HTTP/2 streams.
C<SERVER_PROTOCOL> is C<HTTP/2>.

=item *

B<Extended CONNECT / WebSocket tunnels (RFC 8441)> -- Feersum advertises
C<SETTINGS_ENABLE_CONNECT_PROTOCOL=1> so HTTP/2 clients can open WebSocket
tunnels via Extended CONNECT.  The PSGI handler sees:

    REQUEST_METHOD       => 'CONNECT'
    HTTP_UPGRADE         => 'websocket'       # synthesised from :protocol
    psgix.h2.protocol    => 'websocket'       # raw :protocol value
    psgix.h2.extended_connect => 1

The handler accepts or rejects the tunnel by calling C<start_streaming>
with a C<200> status (accept) or a C<4xx> status (reject).  Once accepted,
C<< psgix.io >> (or C<< $req->io() >>) returns a bidirectional handle backed
by a Unix socketpair; Feersum bridges bytes between that handle and the
HTTP/2 DATA frames in both directions.

=back

=head1 BUGS

Please report bugs using http://github.com/stash/Feersum/issues/

Currently there's no way to limit the request entity length of a B<streaming>
POST/PUT/etc.  This could lead to a DoS attack on a Feersum server.  Suggested
remedy is to only run Feersum behind some other web server and to use that to
limit the entity size.

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

http://en.wikipedia.org/wiki/Feersum_Endjinn

Feersum Git: C<http://github.com/stash/Feersum>
C<git://github.com/stash/Feersum.git>

picohttpparser Git: C<http://github.com/kazuho/picohttpparser>
C<git://github.com/kazuho/picohttpparser.git>

=head1 AUTHOR

Jeremy Stashewsky, C<< stash@cpan.org >>

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
it under the same terms as Perl itself, either Perl version 5.8.7 or,
at your option, any later version of Perl 5 you may have available.

picohttpparser is Copyright 2009 Kazuho Oku.  It is released under the same
terms as Perl itself.

=cut
