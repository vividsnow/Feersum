#!/usr/bin/env perl
# WebSocket example with Feersum
#
# Usage:
#   perl -Mblib eg/websocket-server.pl
#
# Then open http://localhost:5001/ in your browser
#
# This example demonstrates using psgix.io to take over the raw socket
# for WebSocket communication. It uses Protocol::WebSocket for the
# handshake and frame encoding/decoding.
#
use strict;
use warnings;
use EV;
use Feersum;
use IO::Socket::INET;
use Scalar::Util qw(weaken);
use Protocol::WebSocket::Handshake::Server;
use Protocol::WebSocket::Frame;

my $PORT = $ENV{PORT} || 5001;

# Track connected WebSocket clients
my %clients;
my $client_id = 0;

# HTML page with WebSocket client
my $html_page = <<'HTML';
<!DOCTYPE html>
<html>
<head>
    <title>Feersum WebSocket Demo</title>
    <style>
        body { font-family: monospace; padding: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #0f0; }
        #messages {
            background: #16213e;
            padding: 15px;
            border-radius: 5px;
            max-height: 300px;
            overflow-y: auto;
            margin-bottom: 15px;
        }
        .msg { margin: 5px 0; padding: 5px; background: #0f3460; border-radius: 3px; }
        .msg-time { color: #e94560; }
        .msg-sent { color: #ffd700; }
        .msg-recv { color: #0f0; }
        .msg-system { color: #888; font-style: italic; }
        #status { margin: 10px 0; padding: 10px; border-radius: 5px; }
        .connected { background: #155724; }
        .disconnected { background: #721c24; }
        button, input[type="text"] {
            padding: 10px;
            border-radius: 5px;
            border: none;
            margin: 5px;
        }
        button {
            background: #e94560;
            color: white;
            cursor: pointer;
        }
        button:hover { background: #ff6b6b; }
        input[type="text"] {
            width: 300px;
            background: #16213e;
            color: #eee;
        }
        #sendForm { margin-top: 15px; }
    </style>
</head>
<body>
    <h1>Feersum WebSocket Demo</h1>
    <div id="status" class="disconnected">Disconnected</div>
    <button onclick="connect()">Connect</button>
    <button onclick="disconnect()">Disconnect</button>

    <h2>Messages:</h2>
    <div id="messages"></div>

    <div id="sendForm">
        <input type="text" id="msgInput" placeholder="Type a message..." onkeypress="if(event.key==='Enter')sendMsg()">
        <button onclick="sendMsg()">Send</button>
        <button onclick="sendPing()">Ping</button>
        <button onclick="broadcast()">Broadcast</button>
    </div>

    <script>
        let ws = null;

        function connect() {
            if (ws && ws.readyState === WebSocket.OPEN) return;

            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(protocol + '//' + location.host + '/ws');

            ws.onopen = function() {
                document.getElementById('status').className = 'connected';
                document.getElementById('status').textContent = 'Connected';
                addMsg('system', 'Connected to server');
            };

            ws.onclose = function(e) {
                document.getElementById('status').className = 'disconnected';
                document.getElementById('status').textContent = 'Disconnected';
                addMsg('system', 'Disconnected (code: ' + e.code + ')');
                ws = null;
            };

            ws.onerror = function() {
                addMsg('system', 'WebSocket error');
            };

            ws.onmessage = function(e) {
                addMsg('recv', e.data);
            };
        }

        function disconnect() {
            if (ws) {
                ws.close();
                ws = null;
            }
        }

        function sendMsg() {
            const input = document.getElementById('msgInput');
            const msg = input.value.trim();
            if (!msg || !ws || ws.readyState !== WebSocket.OPEN) return;
            ws.send(msg);
            addMsg('sent', msg);
            input.value = '';
        }

        function sendPing() {
            if (!ws || ws.readyState !== WebSocket.OPEN) return;
            ws.send('/ping');
            addMsg('sent', '/ping');
        }

        function broadcast() {
            const input = document.getElementById('msgInput');
            const msg = input.value.trim() || 'Hello everyone!';
            if (!ws || ws.readyState !== WebSocket.OPEN) return;
            ws.send('/broadcast ' + msg);
            addMsg('sent', '/broadcast ' + msg);
            input.value = '';
        }

        function addMsg(type, text) {
            const messages = document.getElementById('messages');
            const div = document.createElement('div');
            div.className = 'msg';
            const time = new Date().toLocaleTimeString();
            let typeClass = 'msg-' + type;
            let prefix = type === 'sent' ? '→' : type === 'recv' ? '←' : '●';
            // Use textContent to escape user data
            const timeSpan = document.createElement('span');
            timeSpan.className = 'msg-time';
            timeSpan.textContent = '[' + time + ']';
            const msgSpan = document.createElement('span');
            msgSpan.className = typeClass;
            msgSpan.textContent = prefix + ' ' + text;
            div.appendChild(timeSpan);
            div.appendChild(document.createTextNode(' '));
            div.appendChild(msgSpan);
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
            // Keep only last 50 messages
            while (messages.children.length > 50) {
                messages.removeChild(messages.firstChild);
            }
        }

        // Auto-connect on load
        connect();
    </script>
</body>
</html>
HTML

# Create listen socket
my $sock = IO::Socket::INET->new(
    LocalAddr => "0.0.0.0:$PORT",
    ReuseAddr => 1,
    Proto     => 'tcp',
    Listen    => 1024,
    Blocking  => 0,
) or die "Cannot create socket: $!";

print "WebSocket server listening on http://localhost:$PORT/\n";

my $feersum = Feersum->endjinn;
$feersum->use_socket($sock);

# Request handler
$feersum->request_handler(sub {
    my $req = shift;
    my $env = $req->env;
    my $path = $env->{PATH_INFO};

    if ($path eq '/' || $path eq '/index.html') {
        # Serve HTML page
        $req->send_response(200, [
            'Content-Type' => 'text/html; charset=utf-8',
            'Cache-Control' => 'no-cache',
        ], \$html_page);
    }
    elsif ($path eq '/ws') {
        # WebSocket upgrade
        handle_websocket($req, $env);
    }
    else {
        $req->send_response(404, ['Content-Type' => 'text/plain'], \"Not Found\n");
    }
});

sub handle_websocket {
    my ($req, $env) = @_;

    # Check for WebSocket upgrade request
    my $upgrade = $env->{HTTP_UPGRADE} || '';
    unless (lc($upgrade) eq 'websocket') {
        $req->send_response(400, ['Content-Type' => 'text/plain'],
            \"Bad Request: Expected WebSocket upgrade\n");
        return;
    }

    # Create WebSocket handshake
    my $hs = Protocol::WebSocket::Handshake::Server->new_from_psgi($env);

    # Parse the handshake (validates the request)
    unless ($hs->is_done) {
        $hs->parse('');  # Trigger header parsing
    }

    unless ($hs->is_done) {
        $req->send_response(400, ['Content-Type' => 'text/plain'],
            \"Bad Request: Invalid WebSocket handshake\n");
        return;
    }

    # Take over the raw socket using $req->io() (native API)
    # This is equivalent to psgix.io in PSGI mode
    my $io = $req->io();
    unless ($io) {
        $req->send_response(500, ['Content-Type' => 'text/plain'],
            \"Internal Server Error: io() not available\n");
        return;
    }

    # Send the handshake response directly on the socket
    my $response = $hs->to_string;
    syswrite($io, $response);

    # Set up the WebSocket connection
    my $id = ++$client_id;
    print "WebSocket client $id connected\n";

    # Create frame parser for this connection
    my $frame = Protocol::WebSocket::Frame->new;

    # Store client info
    my $client = {
        id    => $id,
        io    => $io,
        frame => $frame,
    };
    $clients{$id} = $client;

    # Set up EV watcher for incoming data
    my $watcher;
    $watcher = EV::io $io, EV::READ, sub {
        my $buf;
        my $bytes = sysread($io, $buf, 8192);

        if (!defined $bytes || $bytes == 0) {
            # Connection closed
            print "WebSocket client $id disconnected\n";
            delete $clients{$id};
            $watcher->stop;
            undef $watcher;
            close($io);
            return;
        }

        # Append data to frame parser
        $frame->append($buf);

        # Process all complete frames
        while (defined(my $msg = $frame->next)) {
            if ($frame->is_close) {
                # Send close frame back
                my $close_frame = Protocol::WebSocket::Frame->new(
                    type => 'close'
                )->to_bytes;
                syswrite($io, $close_frame);
                print "WebSocket client $id sent close\n";
                delete $clients{$id};
                $watcher->stop;
                undef $watcher;
                close($io);
                return;
            }
            elsif ($frame->is_ping) {
                # Respond with pong
                my $pong = Protocol::WebSocket::Frame->new(
                    type   => 'pong',
                    buffer => $msg,
                )->to_bytes;
                syswrite($io, $pong);
            }
            elsif ($frame->is_text) {
                handle_message($client, $msg);
            }
        }
    };

    # Send welcome message
    send_ws_message($client, "Welcome! You are client #$id. " .
        "Commands: /ping, /broadcast <msg>");
}

sub send_ws_message {
    my ($client, $msg) = @_;
    return unless $client && $client->{io};

    my $frame = Protocol::WebSocket::Frame->new(
        type   => 'text',
        buffer => $msg,
    );
    eval { syswrite($client->{io}, $frame->to_bytes) };
    if ($@) {
        print "Error sending to client $client->{id}: $@\n";
        delete $clients{$client->{id}};
    }
}

sub handle_message {
    my ($client, $msg) = @_;

    print "Client $client->{id}: $msg\n";

    if ($msg eq '/ping') {
        send_ws_message($client, "pong! (time: " . time() . ")");
    }
    elsif ($msg =~ m{^/broadcast\s+(.+)}) {
        my $text = $1;
        my $broadcast_msg = "Broadcast from #$client->{id}: $text";
        for my $c (values %clients) {
            send_ws_message($c, $broadcast_msg);
        }
    }
    elsif ($msg =~ m{^/users?$}) {
        my @ids = sort { $a <=> $b } keys %clients;
        send_ws_message($client, "Connected users: " . join(", ", map { "#$_" } @ids));
    }
    else {
        # Echo back with transformation
        send_ws_message($client, "Echo: $msg");
    }
}

# Periodic ping to keep connections alive
my $ping_timer = EV::timer 30, 30, sub {
    for my $client (values %clients) {
        my $ping = Protocol::WebSocket::Frame->new(
            type   => 'ping',
            buffer => 'keepalive',
        )->to_bytes;
        eval { syswrite($client->{io}, $ping) };
    }
};

# Run event loop
EV::run;
