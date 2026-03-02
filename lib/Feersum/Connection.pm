package Feersum::Connection;
use warnings;
use strict;
use Carp qw/croak/;
use IO::Socket::INET;

sub new {
    croak "Cannot instantiate Feersum::Connection directly";
}

sub _initiate_streaming_psgi {
    my ($self, $streamer) = @_;
    return $streamer->(sub { $self->_continue_streaming_psgi(@_) });
}

my $_pkg = "Feersum::";
sub _raw { ## no critic (RequireArgUnpacking)
    # don't shift; want to modify $_[0] directly.
    my $fileno = $_[1];
    my $name = "RAW$fileno";
    # Hack to make gensyms via new_from_fd() show up in the Feersum package.
    # This may or may not save memory (HEKs?) over true gensyms.
    no warnings 'redefine';
    local *IO::Handle::gensym = sub {
        no strict;
        my $gv = \*{$_pkg.$name};
        delete $$_pkg{$name};
        $gv;
    };
    # Replace $_[0] directly:
    $_[0] = IO::Socket::INET->new_from_fd($fileno, '+<');
    # after this, Feersum will use PerlIO_unread to put any remainder data
    # into the socket.
    return;
}
1;
__END__

=head1 NAME

Feersum::Connection - HTTP connection encapsulation

=head1 SYNOPSIS

For a streaming response:

    Feersum->endjinn->request_handler(sub {
        my $req = shift; # this is a Feersum::Connection object
        my $env = $req->env();
        my $w = $req->start_streaming(200, ['Content-Type' => 'text/plain']);
        # then immediately or after some time:
        $w->write("Ergrates ");
        $w->write(\"FTW.");
        $w->close();
    });

For a response with a Content-Length header:

    Feersum->endjinn->request_handler(sub {
        my $req = shift; # this is a Feersum::Connection object
        my $env = $req->env();
        $req->send_response(200, ['Content-Type' => 'text/plain'], \"Ergrates FTW.");
    });

=head1 DESCRIPTION

Encapsulates an HTTP connection to Feersum.  It's roughly analogous to an
C<Apache::Request> or C<Apache2::Connection> object, but differs significantly
in functionality.

With HTTP/1.1 Keep-Alive support, multiple requests can be served over
the same connection.

See L<Feersum> for more examples on usage.

=head1 METHODS

=over 4

=item C<< my $env = $req->env() >>

Obtain an environment hash.  This hash contains the same entries as for a PSGI
handler environment hash.  See L<Feersum> for details on the contents.

This is a method instead of a parameter so that future versions of Feersum can
request a slice of the hash for speed.

=item C<< my $w = $req->start_streaming($code, \@headers) >>

A full HTTP header section is sent with "Transfer-Encoding: chunked" (or
"Connection: close" for HTTP/1.0 clients).  

Returns a C<Feersum::Connection::Writer> handle which should be used to
complete the response.  See L<Feersum::Connection::Handle> for methods.

=item C<< $req->send_response($code, \@headers, $body) >>

=item C<< $req->send_response($code, \@headers, \@body) >>

Respond with a full HTTP header (including C<Content-Length>) and body.

Returns the number of bytes calculated for the body.

=item C<< $req->force_http10 >>

=item C<< $req->force_http11 >>

Force the response to use HTTP/1.0 or HTTP/1.1, respectively.

Normally, if the request was made with 1.1 then Feersum uses HTTP/1.1 for the
response, otherwise HTTP/1.0 is used (this includes requests made with the
HTTP "0.9" non-declaration).

For streaming under HTTP/1.1 C<Transfer-Encoding: chunked> is used, otherwise
a C<Connection: close> stream-style is used (with the usual non-guarantees
about delivery).  You may know about certain user-agents that
support/don't-support T-E:chunked, so this is how you can override that.

Supposedly clients and a lot of proxies support the C<Connection: close>
stream-style, see support in Varnish at
http://www.varnish-cache.org/trac/ticket/400

=item C<< $req->is_http11 >>

Returns true if the request was made using HTTP/1.1, false otherwise.
Useful for determining protocol capabilities before sending a response.

=item C<< $req->is_keepalive >>

Returns true if the connection has keep-alive enabled for this request.
This takes into account the HTTP version, Connection header, and server
configuration.

=item C<< $req->fileno >>

The socket file-descriptor number for this connection.

=item C<< $req->io >>

Returns an L<IO::Handle> for the underlying connection socket (typically an
L<IO::Socket::INET>).
This is the native interface equivalent of C<psgix.io> in the PSGI environment.
Any buffered request data will be pushed back into the socket's read buffer.

For HTTP/2 Extended CONNECT streams (RFC 8441), this returns one end of a Unix
socketpair instead of the raw TCP socket. Feersum shuttles data between the
other end of the pair and H2 DATA frames internally. The handle is
bidirectional and suitable for WebSocket or other tunnel protocols.

B<WARNING>: Once you call this method, Feersum relinquishes control of the
socket. You are responsible for all I/O and must not use other Feersum
response methods on this connection.  B<Do not> call C<io()> on regular
(non-tunnel) HTTP/2 streams -- it would expose the shared TCP socket
underlying all multiplexed streams on that connection.

=item C<< $req->return_from_io($io) >>

Returns control of the socket back to Feersum after C<io()> was called.
This allows keepalive to continue working if you decided not to upgrade
the connection (e.g., WebSocket handshake failed). Any buffered data in
the IO handle will be pulled back into Feersum's read buffer.

Returns the number of bytes pulled back from the IO buffer.

=item C<< $req->response_guard($guard) >>

Register a guard to be triggered when the response is completely sent and the
socket is closed.  A "guard" in this context is some object that will do
something interesting in its DESTROY/DEMOLISH method. For example, L<Guard>.

=item C<< my $method = $req->method >>

req method (GET/POST..) (psgi REQUEST_METHOD)

=item C<< my $uri = $req->uri >>

full request uri (psgi REQUEST_URI)

=item C<< my $protocol = $req->protocol >>

protocol (psgi SERVER_PROTOCOL)

=item C<< my $path = $req->path >>

percent decoded request path (psgi PATH_INFO)

=item C<< my $query = $req->query >>

request query (psgi QUERY_STRING)

=item C<< my $len = $req->content_length >>

body content length (psgi CONTENT_LENGTH)

=item C<< my $input = $req->input >>

Input body handler (psgi.input).  Returns C<undef> for requests without a body
(Content-Length == 0 or absent, e.g. GET, HEAD).  Check with C<defined> before
use.  It is advised to close it after read is done.

=item C<< my $headers = $req->headers([normalization_style]) >>

Returns a hash reference of headers in form of { name => value, ... }.

normalization_style is one of (always use named constants, not numeric values):

HEADER_NORM_SKIP (0) - skip normalization (default)
HEADER_NORM_UPCASE_DASH (1) - "CONTENT_TYPE" (like PSGI, but without "HTTP_" prefix)
HEADER_NORM_LOCASE_DASH (2) - "content_type"
HEADER_NORM_UPCASE (3) - "CONTENT-TYPE"
HEADER_NORM_LOCASE (4) - "content-type"

One can export these constants via C<< use Feersum 'HEADER_NORM_LOCASE' >>

=item C<< my $value = $req->header(name) >>

simple lookup for header value, name should be in lowercase, eg. 'content-type'

=item C<< my $addr = $req->remote_address >>

Remote address of the connection (psgi REMOTE_ADDR).  When PROXY protocol is
active, returns the client address from the PROXY header; otherwise returns
the socket peer address.

=item C<< my $port = $req->remote_port >>

Remote port of the connection (psgi REMOTE_PORT).  When PROXY protocol is
active, returns the client port from the PROXY header.

=item C<< my $addr = $req->client_address >>

Client address, respecting reverse proxy mode. When C<reverse_proxy> is
enabled and X-Forwarded-For header is present, returns the first (leftmost)
IP from that header. Otherwise returns the same as C<remote_address>.

=item C<< my $scheme = $req->url_scheme >>

URL scheme (http or https). Resolution order: (1) "https" if the connection
uses TLS or HTTP/2, (2) "https" if PROXY protocol indicates SSL (PP2_TYPE_SSL
TLV) or original destination port 443, (3) X-Forwarded-Proto header value when
C<reverse_proxy> is enabled, (4) "http" otherwise.

=item C<< my $tlvs = $req->proxy_tlvs >>

Returns a hash reference of PROXY protocol v2 TLV (Type-Length-Value)
extensions, or C<undef> if no TLVs were received. Keys are TLV type
numbers (as integers), values are raw TLV data bytes. Only populated
when C<proxy_protocol> is enabled and the client sends a v2 header
with TLV extensions (e.g. PP2_TYPE_SSL, PP2_TYPE_AUTHORITY).

=item C<< my $trailers = $req->trailers >>

Returns an array reference of request trailers in form of [ name => value, ... ],
or C<undef> if no trailers were received. Only supported for HTTP/2
requests currently.

=back

=begin comment

=head2 Private Methods

=over 4

=item C<< new() >>

No-op. Feersum will create these objects internally.

=back

=end comment

=head1 AUTHOR

Jeremy Stashewsky, C<< stash@cpan.org >>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Jeremy Stashewsky & Socialtext Inc.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.7 or,
at your option, any later version of Perl 5 you may have available.

=cut
