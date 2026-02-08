#!perl
use warnings;
use strict;
use constant TIMEOUT_MULT => $ENV{PERL_TEST_TIME_OUT_FACTOR} || 1;
use Test::More;
use File::Temp qw(tempfile);
use lib 't'; use Utils;

use Feersum;

my $evh = Feersum->new();

plan skip_all => "Feersum not compiled with TLS support"
    unless $evh->has_tls();

plan skip_all => "Feersum not compiled with H2 support"
    unless $evh->has_h2();

my $cert_file = 'eg/ssl-proxy/server.crt';
my $key_file  = 'eg/ssl-proxy/server.key';

plan skip_all => "no test certificates ($cert_file / $key_file)"
    unless -f $cert_file && -f $key_file;

my $nghttp_bin = `which nghttp 2>/dev/null`;
chomp $nghttp_bin;
plan skip_all => "nghttp not found in PATH"
    unless $nghttp_bin && -x $nghttp_bin;

diag "using nghttp: $nghttp_bin";

my ($socket, $port) = get_listen_socket();
ok $socket, "got listen socket on port $port";

$evh->use_socket($socket);

eval { $evh->set_tls(cert_file => $cert_file, key_file => $key_file, h2 => 1) };
is $@, '', "set_tls with valid cert/key and h2 enabled";

# Helper: fork nghttp client, wait for result with timeout
sub run_nghttp {
    my ($label, $args, $check_fn) = @_;
    my $pid = fork();
    die "fork failed: $!" unless defined $pid;

    if ($pid == 0) {
        select(undef, undef, undef, 0.3 * TIMEOUT_MULT);
        my $output = `$nghttp_bin --no-verify $args 2>&1`;
        my $rc = $? >> 8;
        if ($rc != 0) {
            warn "nghttp exited with status $rc\noutput: $output\n";
            exit(1);
        }
        exit($check_fn->($output) ? 0 : 2);
    }

    my $cv = AE::cv;
    my $child_status;
    my $timeout = AE::timer(15 * TIMEOUT_MULT, 0, sub {
        diag "timeout: $label";
        $cv->send('timeout');
    });
    my $child_w = AE::child($pid, sub {
        $child_status = $_[1] >> 8;
        $cv->send('child_done');
    });

    my $reason = $cv->recv;
    isnt $reason, 'timeout', "$label did not timeout";
    is $child_status, 0, "$label: nghttp succeeded";
}

# ===========================================================================
# Part 1: Basic H2 GET request
# ===========================================================================

my @received_requests;
$evh->request_handler(sub {
    my $r = shift;
    my $env = $r->env();
    my $path   = $env->{PATH_INFO} || $env->{REQUEST_URI} || '/';
    my $scheme = $env->{'psgi.url_scheme'} || 'http';
    my $proto  = $env->{SERVER_PROTOCOL}   || 'HTTP/1.0';
    my $host   = $env->{HTTP_HOST} || '';
    push @received_requests, { path => $path, scheme => $scheme, proto => $proto, host => $host };

    my $body = "path=$path scheme=$scheme proto=$proto";
    $r->send_response("200 OK", [
        'Content-Type'   => 'text/plain',
        'Content-Length' => length($body),
    ], $body);
});

run_nghttp("basic H2 GET", "https://127.0.0.1:$port/hello", sub {
    my $output = shift;
    if ($output =~ /path=\/hello/) { return 1; }
    warn "Expected body not found in nghttp output\noutput: $output\n";
    return 0;
});

cmp_ok scalar(@received_requests), '>=', 1,
    "server received at least 1 H2 request (got " . scalar(@received_requests) . ")";

if (@received_requests) {
    is $received_requests[0]{path}, '/hello', "request path is /hello";
    is $received_requests[0]{scheme}, 'https', "psgi.url_scheme is https";
    like $received_requests[0]{host}, qr/127\.0\.0\.1/,
        "HTTP_HOST set from :authority pseudo-header";
}

# ===========================================================================
# Part 2: Multiple sequential requests on the same H2 connection
# ===========================================================================

@received_requests = ();

run_nghttp("multi-URL H2",
    "https://127.0.0.1:$port/first https://127.0.0.1:$port/second",
    sub {
        my $output = shift;
        my $found_first  = ($output =~ /path=\/first/)  ? 1 : 0;
        my $found_second = ($output =~ /path=\/second/) ? 1 : 0;
        if ($found_first && $found_second) { return 1; }
        warn "Missing expected bodies (first=$found_first second=$found_second)\noutput: $output\n";
        return 0;
    });

cmp_ok scalar(@received_requests), '>=', 2,
    "server received at least 2 H2 requests (got " . scalar(@received_requests) . ")";

if (@received_requests >= 2) {
    my @paths = sort map { $_->{path} } @received_requests;
    is $paths[0], '/first',  "got request for /first";
    is $paths[1], '/second', "got request for /second";
}

# ===========================================================================
# Part 3: H2 streaming response
# ===========================================================================

$evh->request_handler(sub {
    my $r = shift;
    my $w = $r->start_streaming("200 OK", ['Content-Type' => 'text/plain']);
    my $count = 0;
    my $timer; $timer = AE::timer(0.01, 0.01, sub {
        $count++;
        $w->write("chunk $count\n");
        if ($count >= 3) {
            undef $timer;
            $w->close();
        }
    });
});

run_nghttp("H2 streaming", "https://127.0.0.1:$port/stream", sub {
    my $output = shift;
    my $ok = 1;
    for my $i (1..3) {
        unless ($output =~ /chunk $i/) {
            warn "missing 'chunk $i' in output: $output\n";
            $ok = 0;
        }
    }
    return $ok;
});

# ===========================================================================
# Part 4: H2 POST with small body
# ===========================================================================

@received_requests = ();

$evh->psgi_request_handler(sub {
    my $env = shift;
    my $method = $env->{REQUEST_METHOD} || '';
    my $path   = $env->{PATH_INFO} || '/';
    my $cl     = $env->{CONTENT_LENGTH} || 0;
    my $body   = '';

    if ($env->{'psgi.input'}) {
        $env->{'psgi.input'}->read($body, $cl) if $cl > 0;
    }

    push @received_requests, {
        method => $method,
        path   => $path,
        cl     => $cl,
        body   => $body,
    };

    my $resp_body = "method=$method path=$path cl=$cl body=$body";
    return [200,
        ['Content-Type' => 'text/plain', 'Content-Length' => length($resp_body)],
        [$resp_body]];
});

my $post_data = "hello=world&foo=bar";
my ($tmpfh, $tmpfile) = tempfile(UNLINK => 1);
print $tmpfh $post_data;
close $tmpfh;

run_nghttp("H2 POST", "-d $tmpfile https://127.0.0.1:$port/post-test", sub {
    my $output = shift;
    if ($output =~ /method=POST/ && $output =~ /body=\Q$post_data\E/) { return 1; }
    warn "Expected POST body not found in output\noutput: $output\n";
    return 0;
});

cmp_ok scalar(@received_requests), '>=', 1, "server received at least 1 POST request";

if (@received_requests) {
    is $received_requests[0]{method}, 'POST', "request method is POST";
    is $received_requests[0]{path}, '/post-test', "request path is /post-test";
    is $received_requests[0]{body}, $post_data, "request body matches";
    is $received_requests[0]{cl}, length($post_data),
        "Content-Length matches body size";
}

# ===========================================================================
# Part 5: H2 PUT with larger body
# ===========================================================================

@received_requests = ();

my $put_data = "X" x 4096;  # 4KB body
my ($tmpfh2, $tmpfile2) = tempfile(UNLINK => 1);
print $tmpfh2 $put_data;
close $tmpfh2;

run_nghttp("H2 PUT", "-H ':method: PUT' -d $tmpfile2 https://127.0.0.1:$port/put-test", sub {
    my $output = shift;
    if ($output =~ /method=PUT/ && $output =~ /cl=4096/) { return 1; }
    warn "Expected PUT response not found\noutput: $output\n";
    return 0;
});

cmp_ok scalar(@received_requests), '>=', 1, "server received at least 1 PUT request";

if (@received_requests) {
    is $received_requests[0]{method}, 'PUT', "request method is PUT";
    is $received_requests[0]{path}, '/put-test', "request path is /put-test";
    is $received_requests[0]{cl}, length($put_data),
        "Content-Length matches 4KB body";
    is $received_requests[0]{body}, $put_data, "PUT body content matches";
}

# ===========================================================================
# Part 6: Reader close on H2 stream must not shutdown parent TCP fd
# ===========================================================================

# Drain pending events (cleanup from previous H2 sessions).
# macOS kqueue needs extra time for TLS/H2 session teardown.
{ my $cv = AE::cv; my $t = AE::timer(1.0 * TIMEOUT_MULT, 0, sub { $cv->send }); $cv->recv; }

@received_requests = ();

$evh->psgi_request_handler(sub {
    my $env = shift;
    my $path = $env->{PATH_INFO} || '/';

    # Explicitly close psgi.input reader — must not shutdown(SHUT_RD)
    # on the shared parent TCP fd (would break other H2 streams)
    if ($env->{'psgi.input'}) {
        $env->{'psgi.input'}->close();
    }

    push @received_requests, { path => $path };

    my $resp = "path=$path";
    return [200,
        ['Content-Type' => 'text/plain', 'Content-Length' => length($resp)],
        [$resp]];
});

run_nghttp("H2 reader close",
    "https://127.0.0.1:$port/rc1 https://127.0.0.1:$port/rc2",
    sub {
        my $output = shift;
        my $found1 = ($output =~ /path=\/rc1/) ? 1 : 0;
        my $found2 = ($output =~ /path=\/rc2/) ? 1 : 0;
        if ($found1 && $found2) { return 1; }
        warn "reader close test: rc1=$found1 rc2=$found2\noutput: $output\n";
        return 0;
    });

cmp_ok scalar(@received_requests), '>=', 2,
    "both H2 streams completed after reader close (got " . scalar(@received_requests) . ")";

done_testing;
