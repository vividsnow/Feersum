#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 45;
use lib 't'; use Utils;

BEGIN { use_ok('Feersum') };

#######################################################################
# Test connection methods: is_http11, is_keepalive, protocol, headers
# normalization styles, and other accessors
#######################################################################

my ($socket, $port) = get_listen_socket();
ok $socket, 'got listen socket';

my $feer = Feersum->new();
$feer->use_socket($socket);
$feer->set_keepalive(1);  # Enable keepalive for testing

# Test HTTP/1.1 request
{
    my $cv = AE::cv;
    my %captured;

    $feer->request_handler(sub {
        my $r = shift;
        $captured{is_http11} = $r->is_http11;
        $captured{is_keepalive} = $r->is_keepalive;
        $captured{protocol} = $r->protocol;
        $captured{method} = $r->method;
        $captured{uri} = $r->uri;
        $captured{path} = $r->path;
        $captured{query} = $r->query;
        $captured{fileno} = $r->fileno;
        $captured{remote_address} = $r->remote_address;
        $captured{remote_port} = $r->remote_port;
        $captured{content_length} = $r->content_length;

        # Test headers with different normalization styles
        $captured{headers_raw} = $r->headers(0);  # no normalization
        $captured{headers_locase} = $r->headers(Feersum::HEADER_NORM_LOCASE);
        $captured{headers_upcase} = $r->headers(Feersum::HEADER_NORM_UPCASE);
        $captured{headers_locase_dash} = $r->headers(Feersum::HEADER_NORM_LOCASE_DASH);
        $captured{headers_upcase_dash} = $r->headers(Feersum::HEADER_NORM_UPCASE_DASH);

        # Test single header lookup
        $captured{host_header} = $r->header('host');
        $captured{ua_header} = $r->header('user-agent');

        $r->send_response(200, ['Content-Type' => 'text/plain'], 'OK');
        $cv->send;
    });

    my $h = simple_client GET => '/test/path?foo=bar&baz=1',
        headers => { 'X-Custom' => 'test-value' },
        keepalive => 1,
        sub { };

    $cv->recv;

    # Verify captured values
    ok $captured{is_http11}, 'is_http11 returns true for HTTP/1.1';
    ok $captured{is_keepalive}, 'is_keepalive returns true for HTTP/1.1 default';
    is $captured{protocol}, 'HTTP/1.1', 'protocol returns HTTP/1.1';
    is $captured{method}, 'GET', 'method returns GET';
    is $captured{uri}, '/test/path?foo=bar&baz=1', 'uri returns full URI';
    is $captured{path}, '/test/path', 'path returns decoded path';
    is $captured{query}, 'foo=bar&baz=1', 'query returns query string';
    ok $captured{fileno} > 0, 'fileno returns positive fd';
    is $captured{remote_address}, '127.0.0.1', 'remote_address returns 127.0.0.1';
    ok $captured{remote_port} =~ /^\d+$/, 'remote_port is numeric';
    is $captured{content_length}, 0, 'content_length is 0 for GET';

    # Check headers hash structure (headers() returns a hash ref, not array)
    ok ref($captured{headers_raw}) eq 'HASH', 'headers returns hash ref';
    ok keys %{$captured{headers_raw}} >= 1, 'headers has at least one header';

    # Check header normalization - find Host header in each style
    my %raw = %{$captured{headers_raw}};
    my %locase = %{$captured{headers_locase}};
    my %upcase = %{$captured{headers_upcase}};
    my %locase_dash = %{$captured{headers_locase_dash}};
    my %upcase_dash = %{$captured{headers_upcase_dash}};

    ok exists $raw{Host} || exists $raw{host}, 'raw headers contain Host';
    ok exists $locase{host}, 'locase normalized to "host"';
    ok exists $upcase{HOST}, 'upcase normalized to "HOST"';
    ok exists $locase_dash{host}, 'locase_dash normalized to "host"';
    ok exists $upcase_dash{HOST}, 'upcase_dash normalized to "HOST"';

    # Check custom header normalization
    ok exists $locase{'x-custom'}, 'custom header locase: x-custom';
    ok exists $upcase{'X-CUSTOM'}, 'custom header upcase: X-CUSTOM';
    ok exists $locase_dash{'x_custom'}, 'custom header locase_dash: x_custom';
    ok exists $upcase_dash{'X_CUSTOM'}, 'custom header upcase_dash: X_CUSTOM';

    # Single header lookup
    like $captured{host_header}, qr/localhost/, 'header("host") returns host value';
    is $captured{ua_header}, 'FeersumSimpleClient/1.0', 'header("user-agent") works';
}

# Test HTTP/1.0 request with Connection: close
{
    my $cv = AE::cv;
    my %captured;

    $feer->request_handler(sub {
        my $r = shift;
        $captured{is_http11} = $r->is_http11;
        $captured{is_keepalive} = $r->is_keepalive;
        $captured{protocol} = $r->protocol;
        $r->send_response(200, ['Content-Type' => 'text/plain'], 'OK');
        $cv->send;
    });

    # Send raw HTTP/1.0 request
    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send },
    );
    $h->push_write("GET /test HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $h->on_read(sub { });

    my $timer = AE::timer 3, 0, sub { $cv->send };
    $cv->recv;

    ok !$captured{is_http11}, 'is_http11 returns false for HTTP/1.0';
    ok !$captured{is_keepalive}, 'is_keepalive returns false for HTTP/1.0 + Connection: close';
    is $captured{protocol}, 'HTTP/1.0', 'protocol returns HTTP/1.0';
}

# Test HTTP/1.1 with Connection: close
{
    my $cv = AE::cv;
    my %captured;

    $feer->request_handler(sub {
        my $r = shift;
        $captured{is_http11} = $r->is_http11;
        $captured{is_keepalive} = $r->is_keepalive;
        $r->send_response(200, ['Content-Type' => 'text/plain'], 'OK');
        $cv->send;
    });

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send },
    );
    $h->push_write("GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $h->on_read(sub { });

    my $timer = AE::timer 3, 0, sub { $cv->send };
    $cv->recv;

    ok $captured{is_http11}, 'is_http11 returns true for HTTP/1.1';
    ok !$captured{is_keepalive}, 'is_keepalive returns false with Connection: close';
}

# Test HTTP/1.0 with Connection: keep-alive
{
    my $cv = AE::cv;
    my %captured;

    $feer->request_handler(sub {
        my $r = shift;
        $captured{is_http11} = $r->is_http11;
        $captured{is_keepalive} = $r->is_keepalive;
        $r->send_response(200, ['Content-Type' => 'text/plain'], 'OK');
        $cv->send;
    });

    my $h = AnyEvent::Handle->new(
        connect => ['localhost', $port],
        on_error => sub { $cv->send },
    );
    $h->push_write("GET /test HTTP/1.0\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
    $h->on_read(sub { });

    my $timer = AE::timer 3, 0, sub { $cv->send };
    $cv->recv;

    ok !$captured{is_http11}, 'is_http11 returns false for HTTP/1.0';
    ok $captured{is_keepalive}, 'is_keepalive returns true for HTTP/1.0 + Connection: keep-alive';
}

# Test POST with body
{
    my $cv = AE::cv;
    my %captured;
    my $body_content = 'test=data&more=stuff';

    $feer->request_handler(sub {
        my $r = shift;
        $captured{method} = $r->method;
        $captured{content_length} = $r->content_length;
        $captured{content_type} = $r->header('content-type');

        my $input = $r->input;
        ok defined $input, 'input handle defined for POST';

        my $body = '';
        $input->read($body, $captured{content_length});
        $captured{body} = $body;
        $input->close;

        $r->send_response(200, ['Content-Type' => 'text/plain'], 'OK');
        $cv->send;
    });

    my $h = simple_client POST => '/submit',
        body => $body_content,
        headers => { 'Content-Type' => 'application/x-www-form-urlencoded' },
        sub { };

    $cv->recv;

    is $captured{method}, 'POST', 'method returns POST';
    is $captured{content_length}, length($body_content), 'content_length matches body';
    is $captured{content_type}, 'application/x-www-form-urlencoded', 'content-type header';
    is $captured{body}, $body_content, 'body content matches';
}

# Test metrics: active_conns and total_requests
{
    my $active = $feer->active_conns;
    ok defined $active, 'active_conns returns a value';
    ok $active >= 0, 'active_conns is non-negative';

    my $total = $feer->total_requests;
    ok defined $total, 'total_requests returns a value';
    ok $total >= 5, 'total_requests counted our requests (at least 5)';
}

pass 'all connection method tests completed';
