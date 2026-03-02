static int
try_parse_http(struct feer_conn *c, size_t last_read)
{
    struct feer_req *req = c->req;
    if (likely(!req)) {
        FEER_REQ_ALLOC(req);
        c->req = req;
    }

    // phr_parse_request resets num_headers on each call; must restore to max
    req->num_headers = MAX_HEADERS;

    return phr_parse_request(SvPVX(c->rbuf), SvCUR(c->rbuf),
        &req->method, &req->method_len,
        &req->uri, &req->uri_len, &req->minor_version,
        req->headers, &req->num_headers,
        (SvCUR(c->rbuf)-last_read));
}

// Finish receiving: transition to RECEIVE_SHUTDOWN and stop read I/O
INLINE_UNLESS_DEBUG static void
finish_receiving(struct feer_conn *c) {
    change_receiving_state(c, RECEIVE_SHUTDOWN);
    stop_read_watcher(c);
    stop_read_timer(c);
    stop_header_timer(c);
}

static void
try_conn_read(EV_P_ ev_io *w, int revents)
{
    dCONN;
    SvREFCNT_inc_void_NN(c->self);
    feer_conn_set_busy(c);
    ssize_t got_n = 0;

    if (unlikely(c->pipelined)) goto pipelined;

    // if it's marked readable EV suggests we simply try read it. Otherwise it
    // is stopped and we should ditch this connection.
    if (unlikely(revents & EV_ERROR && !(revents & EV_READ))) {
        trace("EV error on read, fd=%d revents=0x%08x\n", w->fd, revents);
        goto try_read_error;
    }

    if (unlikely(c->receiving == RECEIVE_SHUTDOWN))
        goto dont_read_again;

    trace("try read %d\n",w->fd);

    if (unlikely(!c->rbuf)) { // unlikely = optimize for keepalive requests
        trace("init rbuf for %d\n",w->fd);
        c->rbuf = newSV(READ_BUFSZ + 1);
        SvPOK_on(c->rbuf);
    }

    ssize_t space_free = SvLEN(c->rbuf) - SvCUR(c->rbuf);
    if (unlikely(space_free < READ_BUFSZ)) { // unlikely = optimize for small
        size_t cur_len = SvLEN(c->rbuf);
        // DoS protection: limit buffer growth (especially for chunked encoding)
        if (unlikely(cur_len + READ_GROW_FACTOR*READ_BUFSZ > c->cached_max_read_buf)) {
            trace("buffer too large %d: %"Sz_uf" > %"Sz_uf"\n",
                w->fd, (Sz)cur_len, (Sz)c->cached_max_read_buf);
            respond_with_server_error(c, "Request too large\n", 413);
            goto try_read_error;
        }
        size_t new_len = cur_len + READ_GROW_FACTOR*READ_BUFSZ;
        trace("moar memory %d: %"Sz_uf" to %"Sz_uf"\n",
            w->fd, (Sz)SvLEN(c->rbuf), (Sz)new_len);
        SvGROW(c->rbuf, new_len);
        space_free += READ_GROW_FACTOR*READ_BUFSZ;
    }

    char *cur = SvPVX(c->rbuf) + SvCUR(c->rbuf);
    got_n = read(w->fd, cur, space_free);

    if (unlikely(got_n <= 0)) {
        if (unlikely(got_n == 0)) {
            trace("EOF before complete request: fd=%d buf=%"Sz_uf"\n", w->fd, (Sz)SvCUR(c->rbuf));
            goto try_read_error;
        }
        if (likely(errno == EAGAIN || errno == EINTR))
            goto try_read_again;
        trouble("try_conn_read fd=%d: %s\n", w->fd, strerror(errno));
        goto try_read_error;
    }

    trace("read %d %"Ssz_df"\n", w->fd, (Ssz)got_n);
    SvCUR(c->rbuf) += got_n;
    if (c->receiving == RECEIVE_WAIT)
        change_receiving_state(c, RECEIVE_HEADERS);
    goto try_parse;

pipelined:
    got_n = c->pipelined;
    c->pipelined = 0;

try_parse:
    // Handle PROXY protocol header state
    if (unlikely(c->receiving == RECEIVE_PROXY_HEADER)) {
        int ret = try_parse_proxy_header(c);
        if (ret == -1) {
            respond_with_server_error(c, "Invalid PROXY protocol header\n", 400);
            goto dont_read_again;
        }
        if (ret == -2) goto try_read_again_reset_timer;

        // Consume parsed bytes from buffer
        STRLEN remaining = SvCUR(c->rbuf) - ret;
        if (remaining > 0)
            memmove(SvPVX(c->rbuf), SvPVX(c->rbuf) + ret, remaining);
        SvCUR_set(c->rbuf, remaining);

        // Clear cached remote addr/port (force regeneration with new address)
        feer_clear_remote_cache(c);

        // Transition to HTTP parsing
        change_receiving_state(c, RECEIVE_HEADERS);
        if (remaining > 0) {
            got_n = remaining;
            goto try_parse;
        }
        goto try_read_again_reset_timer;
    }

    // likely = optimize for small requests
    if (likely(c->receiving <= RECEIVE_HEADERS)) {
        int ret = try_parse_http(c, (size_t)got_n);
        if (ret == -1) goto try_read_bad;
#ifdef TCP_DEFER_ACCEPT
        if (ret == -2) goto try_read_again_reset_timer;
#else
        if (ret == -2) {
            if (c->cached_is_tcp) goto try_read_again;
            else goto try_read_again_reset_timer;
        }
#endif

        if (process_request_headers(c, ret))
            goto try_read_again_reset_timer;
        else
            goto dont_read_again;
    }
    else if (likely(c->receiving == RECEIVE_BODY)) {
        c->received_cl += got_n;
        if (c->received_cl < c->expected_cl)
            goto try_read_again_reset_timer;
        // body is complete
        sched_request_callback(c);
        goto dont_read_again;
    }
    else if (c->receiving == RECEIVE_CHUNKED) {
        // Try to parse chunked data
        int ret = try_parse_chunked(c);
        if (ret == 1)
            goto try_read_again_reset_timer;
        if (ret == -1) {
            respond_with_server_error(c, "Malformed chunked encoding\n", 400);
            goto dont_read_again;
        }
        // chunked body is complete
        sched_request_callback(c);
        goto dont_read_again;
    }
    else if (c->receiving == RECEIVE_STREAMING) {
        // Streaming body read with poll_read_cb
        c->received_cl += got_n;
        if (c->poll_read_cb) {
            call_poll_callback(c, 0);  // 0 = read callback
        }
        // Callback may have closed/errored — check before re-arming
        if (c->receiving >= RECEIVE_SHUTDOWN)
            goto dont_read_again;
        // Check if body is complete (if Content-Length was specified)
        if (c->expected_cl > 0 && c->received_cl >= c->expected_cl) {
            goto dont_read_again;
        }
        goto try_read_again_reset_timer;
    }
    else {
        trouble("unknown read state %d %d", w->fd, c->receiving);
    }

    // fallthrough:
try_read_error:
    trace("READ ERROR %d, refcnt=%d\n", w->fd, SvREFCNT(c->self));
    change_receiving_state(c, RECEIVE_SHUTDOWN);
    change_responding_state(c, RESPOND_SHUTDOWN);
    stop_all_watchers(c);
    goto try_read_cleanup;

try_read_bad:
    trace("bad request %d\n", w->fd);
    respond_with_server_error(c, "Malformed request\n", 400);
    // fallthrough (respond_with_server_error sets is_keepalive=0):
dont_read_again:
    trace("done reading %d\n", w->fd);
    finish_receiving(c);
    goto try_read_cleanup;

try_read_again_reset_timer:
    trace("(reset read timer) %d\n", w->fd);
    restart_read_timer(c);
    // fallthrough:
try_read_again:
    trace("read again %d\n", w->fd);
    start_read_watcher(c);

try_read_cleanup:
    SvREFCNT_dec(c->self);
}

static void
conn_read_timeout (EV_P_ ev_timer *w, int revents)
{
    dCONN;
    SvREFCNT_inc_void_NN(c->self);

    if (unlikely(!(revents & EV_TIMER) || c->receiving == RECEIVE_SHUTDOWN)) {
        // if there's no EV_TIMER then EV has stopped it on an error
        if (revents & EV_ERROR)
            trouble("EV error on read timer, fd=%d revents=0x%08x\n",
                c->fd,revents);
        goto read_timeout_cleanup;
    }

    trace("read timeout %d\n", c->fd);

#ifdef FEERSUM_HAS_H2
    if (c->h2_session) {
        /* H2 parent connection idle timeout: send GOAWAY and close.
         * Cannot use respond_with_server_error() which writes HTTP/1.1. */
        trace("H2 idle timeout fd=%d\n", c->fd);
        if (!c->h2_goaway_sent) {
            nghttp2_submit_goaway(c->h2_session, NGHTTP2_FLAG_NONE,
                                  nghttp2_session_get_last_proc_stream_id(c->h2_session),
                                  NGHTTP2_NO_ERROR, NULL, 0);
            c->h2_goaway_sent = 1;
            feer_h2_session_send(c);
        }
        stop_all_watchers(c);
        safe_close_conn(c, "H2 idle timeout");
        change_responding_state(c, RESPOND_SHUTDOWN);
        goto read_timeout_cleanup;
    }
#endif

    if (likely(c->responding == RESPOND_NOT_STARTED) && c->receiving >= RECEIVE_HEADERS) {
#ifdef FEERSUM_HAS_TLS
        if (c->tls && !c->tls_handshake_done) {
            // TLS handshake never completed — can't send HTTP response
            // (ptls_send asserts enc.aead != NULL). Just close.
            stop_all_watchers(c);
            safe_close_conn(c, "TLS handshake timeout (read)");
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto read_timeout_cleanup;
        }
#endif
        const char *msg;
        if (c->receiving == RECEIVE_PROXY_HEADER) {
            msg = "PROXY protocol header timeout.";
        }
        else if (c->receiving == RECEIVE_HEADERS) {
            msg = "Headers took too long.";
        }
        else {
            msg = "Timeout reading body.";
        }
        respond_with_server_error(c, msg, 408);
    } else {
        trace("read timeout in keepalive conn: %d\n", c->fd);
        stop_all_watchers(c);
        safe_close_conn(c, "close at read timeout");
        change_responding_state(c, RESPOND_SHUTDOWN);
        change_receiving_state(c, RECEIVE_SHUTDOWN);
    }

read_timeout_cleanup:
    SvREFCNT_dec(c->self);
}

// Slowloris protection: non-resetting deadline for header completion
static void
conn_header_timeout (EV_P_ ev_timer *w, int revents)
{
    dCONN;
    SvREFCNT_inc_void_NN(c->self);

    if (unlikely(!(revents & EV_TIMER) || c->receiving == RECEIVE_SHUTDOWN)) {
        if (revents & EV_ERROR)
            trouble("EV error on header timer, fd=%d revents=0x%08x\n",
                c->fd, revents);
        goto header_timeout_cleanup;
    }

    // Only trigger if still receiving headers (including PROXY protocol phase)
    if ((c->receiving == RECEIVE_HEADERS || c->receiving == RECEIVE_PROXY_HEADER)
        && c->responding == RESPOND_NOT_STARTED) {
        trace("header deadline timeout %d (Slowloris protection)\n", c->fd);
#ifdef FEERSUM_HAS_TLS
        if (c->tls && !c->tls_handshake_done) {
            // TLS handshake never completed — can't send HTTP response
            // (ptls_send asserts enc.aead != NULL). Just close.
            stop_all_watchers(c);
            safe_close_conn(c, "TLS handshake timeout");
            change_responding_state(c, RESPOND_SHUTDOWN);
        } else
#endif
        {
            respond_with_server_error(c, "Header timeout (possible Slowloris attack)\n", 408);
        }
    }

header_timeout_cleanup:
    // One-shot timer: libev already stopped it before invoking this callback.
    SvREFCNT_dec(c->self);  // balances timer start (setup_accepted_conn or keepalive)
    SvREFCNT_dec(c->self);  // balances callback protection at top of this function
}

static void
conn_write_timeout (EV_P_ ev_timer *w, int revents)
{
    dCONN;
    SvREFCNT_inc_void_NN(c->self);

    if (unlikely(!(revents & EV_TIMER) || c->responding == RESPOND_SHUTDOWN)) {
        if (revents & EV_ERROR)
            trouble("EV error on write timer, fd=%d revents=0x%08x\n",
                c->fd, revents);
        goto write_timeout_cleanup;
    }

    trace("write timeout %d\n", c->fd);
    stop_all_watchers(c);
    safe_close_conn(c, "write timeout");
    change_responding_state(c, RESPOND_SHUTDOWN);
    change_receiving_state(c, RECEIVE_SHUTDOWN);

write_timeout_cleanup:
    SvREFCNT_dec(c->self);
}

// Helper to set up a newly accepted connection
// Returns 0 on success, -1 on error (fd already closed on error)
static int
setup_accepted_conn(EV_P_ int fd, struct sockaddr *sa, socklen_t sa_len,
                    struct feer_server *srvr, struct feer_listen *lsnr)
{
    if (unlikely(prep_socket(fd, lsnr->is_tcp))) {
        trouble("prep_socket failed for fd=%d: %s\n", fd, strerror(errno));
        if (unlikely(close(fd) < 0))
            trouble("close(prep_socket error) fd=%d: %s\n", fd, strerror(errno));
        return -1;
    }

    struct feer_conn *c = new_feer_conn(EV_A, fd, sa, sa_len, srvr, lsnr);

    // Slowloris protection: start non-resetting header deadline timer
    if (srvr->header_timeout > 0.0) {
        ev_timer_set(&c->header_ev_timer, srvr->header_timeout, 0.0);  // one-shot
        ev_timer_start(feersum_ev_loop, &c->header_ev_timer);
        SvREFCNT_inc_void_NN(c->self);
        trace("started header deadline timer %d (%.1fs)\n", c->fd, srvr->header_timeout);
    }

#ifdef TCP_DEFER_ACCEPT
    // With TCP_DEFER_ACCEPT, data is already available
#ifdef FEERSUM_HAS_TLS
    if (lsnr->tls_ctx_ref) {
        // TLS: don't try immediate read with deferred accept, just start watcher.
        // The TLS handshake needs proper event-driven I/O.
        start_read_watcher(c);
    } else
#endif
    {
        try_conn_read(EV_A, &c->read_ev_io, EV_READ);
    }
    assert(SvREFCNT(c->self) <= (srvr->header_timeout > 0.0 ? 4 : 3));
#else
    if (lsnr->is_tcp) {
        start_read_watcher(c);
        restart_read_timer(c);
        assert(SvREFCNT(c->self) == (srvr->header_timeout > 0.0 ? 4 : 3));
    } else {
#ifdef FEERSUM_HAS_TLS
        if (lsnr->tls_ctx_ref)
            try_tls_conn_read(EV_A, &c->read_ev_io, EV_READ);
        else
#endif
            try_conn_read(EV_A, &c->read_ev_io, EV_READ);
        assert(SvREFCNT(c->self) <= (srvr->header_timeout > 0.0 ? 4 : 3));
    }
#endif
    SvREFCNT_dec(c->self);
    return 0;
}

static void
emfile_retry_cb (EV_P_ ev_timer *w, int revents)
{
    struct feer_listen *lsnr = (struct feer_listen *)w->data;
    if (lsnr->server->shutting_down) return;
    trace("EMFILE retry: resuming accept on fd=%d\n", lsnr->fd);
    lsnr->paused = 0;
    ev_io_start(EV_A, &lsnr->accept_w);
}

/*
 * Accept a single connection from the listen socket.
 * Returns: 1 = continue accepting, 0 = stop (EAGAIN/error/limit)
 */
static int
try_accept_one(EV_P_ struct feer_listen *lsnr, struct feer_server *srvr)
{
    struct sockaddr_storage sa_buf;
    socklen_t sa_len = sizeof(struct sockaddr_storage);
    errno = 0;
#ifdef HAS_ACCEPT4
    int fd = accept4(lsnr->fd, (struct sockaddr *)&sa_buf, &sa_len, SOCK_CLOEXEC|SOCK_NONBLOCK);
#else
    int fd = accept(lsnr->fd, (struct sockaddr *)&sa_buf, &sa_len);
#endif
    trace("accepted fd=%d, errno=%d\n", fd, errno);
    if (fd == -1) {
        if (errno == EINTR) return 1;
        if (errno == EMFILE || errno == ENFILE) {
            trouble("accept: %s — pausing accept for 1s on fd=%d\n",
                    strerror(errno), lsnr->fd);
            ev_io_stop(EV_A, &lsnr->accept_w);
            lsnr->paused = 1;
            ev_timer_set(&lsnr->emfile_w, 1.0, 0.0);
            ev_timer_start(EV_A, &lsnr->emfile_w);
        }
        return 0;
    }

    if (srvr->max_connections > 0 && srvr->active_conns >= srvr->max_connections) {
        if (!feer_server_recycle_idle_conn(srvr)) {
            trace("max_connections limit reached (%d), rejecting fd=%d\n",
                  srvr->max_connections, fd);
            close(fd);
            return 0;
        }
    }

    setup_accepted_conn(EV_A, fd, (struct sockaddr *)&sa_buf, sa_len, srvr, lsnr);
    return 1;
}

#ifdef __linux__
static void
accept_epoll_cb (EV_P_ ev_io *w, int revents)
{
    struct feer_listen *lsnr = (struct feer_listen *)w->data;
    struct feer_server *srvr = lsnr->server;
    struct epoll_event events[1];

    if (unlikely(srvr->shutting_down)) {
        ev_io_stop(EV_A, w);
        return;
    }

    if (unlikely(revents & EV_ERROR)) {
        trouble("EV error in accept_epoll_cb, fd=%d, revents=0x%08x\n", w->fd, revents);
        ev_break(EV_A, EVBREAK_ALL);
        return;
    }

    int accept_count = 0;
    while (accept_count++ < srvr->max_accept_per_loop) {
        if (epoll_wait(lsnr->epoll_fd, events, 1, 0) <= 0) break;
        if (!try_accept_one(EV_A, lsnr, srvr)) break;
    }
}
#endif

static void
accept_cb (EV_P_ ev_io *w, int revents)
{
    struct feer_listen *lsnr = (struct feer_listen *)w->data;
    struct feer_server *srvr = lsnr->server;

    if (unlikely(srvr->shutting_down)) {
        ev_io_stop(EV_A, w);
        return;
    }

    if (unlikely(revents & EV_ERROR)) {
        trouble("EV error in accept_cb, fd=%d, revents=0x%08x\n",w->fd,revents);
        ev_break(EV_A, EVBREAK_ALL);
        return;
    }

    trace2("accept! revents=0x%08x\n", revents);

    int accept_count = 0;
    while (accept_count++ < srvr->max_accept_per_loop) {
        if (!try_accept_one(EV_A, lsnr, srvr)) break;
    }
}

// Helper to set up the accept watcher, with optional EPOLLEXCLUSIVE on Linux
static void
setup_accept_watcher(struct feer_listen *lsnr, int listen_fd)
{
    struct feer_server *srvr = lsnr->server;
#if defined(__linux__) && defined(EPOLLEXCLUSIVE)
    if (srvr->use_epoll_exclusive) {
        // Create a separate epoll fd for the accept socket with EPOLLEXCLUSIVE
        // This avoids thundering herd in prefork without patching libev
        struct epoll_event ev;
        lsnr->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (lsnr->epoll_fd < 0) {
            trouble("epoll_create1 for accept: %s\n", strerror(errno));
            croak("Failed to create accept epoll fd");
        }

        ev.events = EPOLLIN | EPOLLEXCLUSIVE;
        ev.data.fd = listen_fd;
        if (epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
            trouble("epoll_ctl EPOLL_CTL_ADD for accept fd=%d: %s\n", listen_fd, strerror(errno));
            if (unlikely(close(lsnr->epoll_fd) < 0))
                trouble("close(lsnr->epoll_fd) fd=%d: %s\n", lsnr->epoll_fd, strerror(errno));
            lsnr->epoll_fd = -1;
            croak("Failed to add listen socket to accept epoll");
        }

        trace("created lsnr->epoll_fd=%d with EPOLLEXCLUSIVE for listen fd=%d\n",
              lsnr->epoll_fd, listen_fd);

        // Watch the lsnr->epoll_fd instead of the listen socket directly
        // When lsnr->epoll_fd becomes readable, only THIS worker was selected
        ev_io_init(&lsnr->accept_w, accept_epoll_cb, lsnr->epoll_fd, EV_READ);
    } else {
        // Standard mode: watch listen socket directly
        ev_io_init(&lsnr->accept_w, accept_cb, listen_fd, EV_READ);
    }
#else
    // Non-Linux or no EPOLLEXCLUSIVE: standard mode only
    ev_io_init(&lsnr->accept_w, accept_cb, listen_fd, EV_READ);
#endif
    lsnr->accept_w.data = (void *)lsnr;
    ev_set_priority(&lsnr->accept_w, srvr->accept_priority);
    ev_init(&lsnr->emfile_w, emfile_retry_cb);
    lsnr->emfile_w.data = (void *)lsnr;
}

static void
sched_request_callback (struct feer_conn *c)
{
    struct feer_server *server = c->server;
    if (FEERSUM_REQ_BODY_ENABLED()) {
        FEERSUM_REQ_BODY(c->fd, (size_t)(c->received_cl >= 0 ? c->received_cl : 0));
    }
    trace("sched req callback: %d c=%p, head=%p\n", c->fd, c, server->request_ready_rinq);
    rinq_push(&server->request_ready_rinq, c);
    SvREFCNT_inc_void_NN(c->self); // for the rinq
    if (!ev_is_active(&server->ei)) {
        trace("starting idle watcher\n");
        ev_idle_start(feersum_ev_loop, &server->ei);
    }
}

// Parse chunked transfer encoding from rbuf
// Returns: 1 if need more data, 0 if complete, -1 if parse error
// Decodes chunks in-place: moves decoded data to beginning of rbuf
// c->received_cl tracks decoded bytes, c->chunk_remaining tracks state (see CHUNK_STATE_*)
static int
try_parse_chunked (struct feer_conn *c)
{
    if (!c->rbuf) return 1;  // need data

    char *buf = SvPVX(c->rbuf);
    STRLEN buf_len = SvCUR(c->rbuf);
    // received_cl tracks decoded position; should always be non-negative
    STRLEN read_pos = (c->received_cl >= 0) ? (STRLEN)c->received_cl : 0;
    STRLEN write_pos = read_pos;  // decoded data position

    trace("try_parse_chunked fd=%d buf_len=%"Sz_uf" read_pos=%"Sz_uf" chunk_remaining=%"Ssz_df"\n",
        c->fd, (Sz)buf_len, (Sz)read_pos, (Ssz)c->chunk_remaining);

    while (read_pos < buf_len) {
        if (c->chunk_remaining == CHUNK_STATE_NEED_CRLF) {
            // Need CRLF after chunk data
            STRLEN remaining = buf_len - read_pos;
            if (remaining < 2)
                goto need_more;
            if (buf[read_pos] != '\r' || buf[read_pos+1] != '\n') {
                trace("chunked: missing CRLF after chunk data\n");
                return -1;  // parse error
            }
            read_pos += 2;
            c->chunk_remaining = CHUNK_STATE_PARSE_SIZE;  // ready for next chunk size
            continue;
        }
        else if (c->chunk_remaining == CHUNK_STATE_PARSE_SIZE) {
            // Parsing chunk size line: find CRLF
            char *line_start = buf + read_pos;
            char *line_end = NULL;
            STRLEN remaining = buf_len - read_pos;
            STRLEN i;

            // Look for CRLF
            for (i = 0; i + 1 < remaining; i++) {
                if (line_start[i] == '\r' && line_start[i+1] == '\n') {
                    line_end = line_start + i;
                    break;
                }
            }

            if (!line_end) {
                // Need more data for chunk size line
                trace("chunked: need more data for chunk size line\n");
                goto need_more;
            }

            // Parse hex chunk size (stop at ; for extensions)
            // Uses hex_decode_table for fast lookup (0-15 for valid, 0xFF for invalid)
            UV chunk_size = 0;
            int hex_digits = 0;
            char *p = line_start;
            while (p < line_end) {
                unsigned char ch = (unsigned char)*p;
                unsigned char val = hex_decode_table[ch];
                if (val != 0xFF) {
                    hex_digits++;
                    // Check for potential overflow BEFORE shifting
                    if (chunk_size > (UV_MAX >> 4)) {
                        trace("chunked: chunk size overflow\n");
                        return -1;
                    }
                    chunk_size = (chunk_size << 4) | val;
                }
                else if (ch == ';' || ch == ' ' || ch == '\t') {
                    break;  // chunk extension or whitespace, stop parsing
                }
                else {
                    trace("chunked: invalid hex char '%c'\n", ch);
                    return -1;  // parse error
                }
                p++;
            }

            // Reject chunk size lines with no hex digits (e.g., ";ext\r\n")
            if (hex_digits == 0) {
                trace("chunked: no hex digits in chunk size\n");
                return -1;  // parse error
            }

            trace("chunked: parsed size=%"UVuf" at pos=%"Sz_uf"\n",
                chunk_size, (Sz)(line_start - buf));

            // Move past the CRLF
            read_pos = (line_end - buf) + 2;

            if (chunk_size == 0) {
                // Final chunk - transition to trailer parsing state.
                // The c->chunk_remaining == 0 handler below does the actual
                // trailer scan (both for first entry and re-entry after needing
                // more data), so just set state and let the while loop continue.
                c->trailer_count = 0;
                c->chunk_remaining = 0;
                continue;
            }

            // Check cumulative body size (prevent overflow on 32-bit)
            // Split into two checks to avoid unsigned underflow when
            // chunk_size > MAX_BODY_LEN (which would wrap the subtraction)
            if (unlikely(chunk_size > (UV)c->cached_max_body_len)) {
                trace("chunked: chunk too large %"UVuf"\n", chunk_size);
                return -1;  // error
            }
            if (unlikely(write_pos > (STRLEN)(c->cached_max_body_len - chunk_size))) {
                trace("chunked: body too large %"UVuf" + %"Sz_uf"\n",
                    chunk_size, (Sz)write_pos);
                return -1;  // error
            }

            // DoS protection: limit number of chunks
            c->chunk_count++;
            if (unlikely(c->chunk_count > MAX_CHUNK_COUNT)) {
                trace("chunked: too many chunks (%u)\n", c->chunk_count);
                return -1;  // error
            }

            if (chunk_size > (UV)SSIZE_MAX) return -1;
            c->chunk_remaining = (ssize_t)chunk_size;
        }
        else if (c->chunk_remaining == 0) {
            // We've seen the 0 chunk, looking for trailer end
            // (This handles the case where we return to this function)
            // Note: c->trailer_count was initialized when we first saw the 0-chunk
            STRLEN remaining = buf_len - read_pos;
            char *trailer_start = buf + read_pos;
            STRLEN i = 0;
            while (i + 1 < remaining) {
                if (trailer_start[i] == '\r' && trailer_start[i+1] == '\n') {
                    if (i == 0) {
                        // Empty line - done (chunk_remaining already 0)
                        read_pos += 2;  // skip terminating \r\n
                        STRLEN pipelined = (read_pos < buf_len) ? buf_len - read_pos : 0;
                        c->expected_cl = write_pos;
                        c->received_cl = write_pos + pipelined;
                        if (pipelined > 0)
                            memmove(buf + write_pos, buf + read_pos, pipelined);
                        SvCUR_set(c->rbuf, write_pos + pipelined);
                        return 0;  // complete
                    }
                    // Skip trailer header
                    if (unlikely(++c->trailer_count > MAX_TRAILER_HEADERS)) {
                        trace("chunked: too many trailer headers\n");
                        return -1;  // error
                    }
                    read_pos += i + 2;
                    remaining = buf_len - read_pos;
                    trailer_start = buf + read_pos;
                    i = 0;  // restart from beginning
                    continue;
                }
                i++;
            }
            goto need_more;
        }
        else {
            // chunk_remaining > 0: copy chunk data
            STRLEN remaining = buf_len - read_pos;
            STRLEN to_copy = (STRLEN)c->chunk_remaining;
            if (to_copy > remaining)
                to_copy = remaining;

            // Move chunk data to write position (decode in place)
            if (write_pos != read_pos && to_copy > 0) {
                memmove(buf + write_pos, buf + read_pos, to_copy);
            }
            write_pos += to_copy;
            read_pos += to_copy;
            c->chunk_remaining -= to_copy;
            c->received_cl = write_pos;

            if (c->chunk_remaining > 0) {
                // Need more data for this chunk
                goto need_more;
            }

            // Chunk complete, need to consume trailing CRLF
            remaining = buf_len - read_pos;
            if (remaining < 2) {
                // Need CRLF
                c->chunk_remaining = CHUNK_STATE_NEED_CRLF;
                goto need_more;
            }
            if (buf[read_pos] != '\r' || buf[read_pos+1] != '\n') {
                trace("chunked: missing CRLF after chunk data\n");
                return -1;  // parse error
            }
            read_pos += 2;
            c->chunk_remaining = CHUNK_STATE_PARSE_SIZE;  // ready for next chunk size
        }
    }

need_more:
    // Compact buffer: move unparsed data to after decoded data
    if (read_pos > write_pos) {
        if (read_pos < buf_len) {
            STRLEN unparsed = buf_len - read_pos;
            memmove(buf + write_pos, buf + read_pos, unparsed);
            SvCUR_set(c->rbuf, write_pos + unparsed);
        } else {
            SvCUR_set(c->rbuf, write_pos);
        }
    }
    // else: read_pos == write_pos, buffer is already compact, SvCUR unchanged
    c->received_cl = write_pos;
    return 1;  // need more data
}

// the unlikely/likely annotations here are trying to optimize for GET first
// and POST second.  Other entity-body requests are third in line.
static bool
process_request_headers (struct feer_conn *c, int body_offset)
{
    int err_code;
    const char *err;
    struct feer_req *req = c->req;

    if (FEERSUM_REQ_NEW_ENABLED()) {
        char m[16], u[1024];
        STRLEN m_len = (req->method_len < 15) ? req->method_len : 15;
        STRLEN u_len = (req->uri_len < 1023) ? req->uri_len : 1023;
        memcpy(m, req->method, m_len); m[m_len] = '\0';
        memcpy(u, req->uri, u_len); u[u_len] = '\0';
        FEERSUM_REQ_NEW(c->fd, m, u);
    }

    // Slowloris protection: headers complete, stop deadline timer
    stop_header_timer(c);

    trace("processing headers %d minor_version=%d\n",c->fd,req->minor_version);
    bool body_is_required = 0;
    bool next_req_follows = 0;
    bool got_content_length = 0;

    c->is_http11 = (req->minor_version == 1);
    c->is_keepalive = c->cached_keepalive_default && c->is_http11;
    c->expect_continue = 0;  // reset for each request
    c->receive_chunked = 0;  // reset for each request
    c->reqs++;

    change_receiving_state(c, RECEIVE_BODY);
    c->expected_cl = 0;
    c->received_cl = 0;

    // Dispatch by method length first to minimize string comparisons
    switch (req->method_len) {
    case 3:
        if (likely(memcmp(req->method, "GET", 3) == 0)) {
            next_req_follows = 1;
        } else if (memcmp(req->method, "PUT", 3) == 0) {
            body_is_required = 1;
        } else {
            goto unsupported_method;
        }
        break;
    case 4:
        if (likely(memcmp(req->method, "POST", 4) == 0)) {
            body_is_required = 1;
        } else if (memcmp(req->method, "HEAD", 4) == 0) {
            next_req_follows = 1;
        } else {
            goto unsupported_method;
        }
        break;
    case 5:
        if (memcmp(req->method, "PATCH", 5) == 0) {
            body_is_required = 1;
        } else {
            goto unsupported_method;
        }
        break;
    case 6:
        if (memcmp(req->method, "DELETE", 6) == 0) {
            next_req_follows = 1;
        } else {
            goto unsupported_method;
        }
        break;
    case 7:
        if (memcmp(req->method, "OPTIONS", 7) == 0) {
            next_req_follows = 1;
        } else {
            goto unsupported_method;
        }
        break;
    default:
    unsupported_method:
        err = "Feersum doesn't support that method yet\n";
        err_code = 405;
        goto got_bad_request;
    }

    // RFC 7230: URI length check (414 URI Too Long)
    if (unlikely(req->uri_len > c->cached_max_uri_len)) {
        err_code = 414;
        err = "URI Too Long\n";
        goto got_bad_request;
    }

#if DEBUG >= 2
    if (next_req_follows)
        trace2("next req follows fd=%d, boff=%d\n",c->fd,body_offset);
    if (body_is_required)
        trace2("body is required fd=%d, boff=%d\n",c->fd,body_offset);
#endif

    // a body or follow-on data potentially follows the headers. Let feer_req
    // retain its pointers into rbuf and make a new scalar for more body data.
    STRLEN from_len;
    char *from = SvPV(c->rbuf,from_len);
    // Validate body_offset to prevent integer underflow
    // Check for negative first (phr_parse_request returns -1/-2 for errors)
    if (unlikely(body_offset < 0 || (STRLEN)body_offset > from_len)) {
        trouble("invalid body_offset %d > from_len %"Sz_uf" fd=%d\n",
                body_offset, (Sz)from_len, c->fd);
        respond_with_server_error(c, "Internal parser error\n", 500);
        return 0;
    }
    from += body_offset;
    STRLEN need = from_len - body_offset;
    trace("new rbuf for body %d need=%"Sz_uf"\n", c->fd, (Sz)need);
    SV *new_rbuf = newSVpvn(need > 0 ? from : "", need);

    req->buf = c->rbuf;
    c->rbuf = new_rbuf;
    SvCUR_set(req->buf, body_offset);

    // determine how much we need to read
    size_t i;
    UV expected = 0;
    bool got_host = 0;
    bool got_transfer_encoding = 0;
    for (i=0; i < req->num_headers; i++) {
        struct phr_header *hdr = &req->headers[i];
        // RFC 7230: reject obsolete header line folding (obs-fold)
        if (unlikely(!hdr->name)) {
            err_code = 400;
            err = "Obsolete header line folding not allowed\n";
            goto got_bad_request;
        }
        // RFC 7231: reject header names that exceed our processing limit
        // Buffer is 5 + MAX_HEADER_NAME_LEN, so names up to MAX_HEADER_NAME_LEN fit
        if (unlikely(hdr->name_len > MAX_HEADER_NAME_LEN)) {
            err_code = 431;
            err = "Header name too long\n";
            goto got_bad_request;
        }
        if (unlikely(hdr->name_len == 14 &&
             str_case_eq_fixed("content-length", hdr->name, 14)))
        {
            // RFC 7230 3.3.3: reject if Transfer-Encoding was already seen
            if (c->receive_chunked) {
                err_code = 400;
                err = "Content-Length not allowed with Transfer-Encoding\n";
                goto got_bad_request;
            }
            UV new_expected = 0;
            int g = grok_number(hdr->value, hdr->value_len, &new_expected);
            if (likely(g == IS_NUMBER_IN_UV)) {
                if (unlikely(new_expected > (UV)c->cached_max_body_len)) {
                    err_code = 413;
                    err = "Content length exceeds maximum\n";
                    goto got_bad_request;
                }
                // RFC 7230: reject multiple Content-Length with different values
                if (got_content_length && new_expected != expected) {
                    err_code = 400;
                    err = "Multiple conflicting Content-Length headers\n";
                    goto got_bad_request;
                }
                expected = new_expected;
                got_content_length = 1;
            }
            else {
                err_code = 400;
                err = "Invalid Content-Length\n";
                goto got_bad_request;
            }
        }
        else if (unlikely(hdr->name_len == 10 &&
                str_case_eq_fixed("connection", hdr->name, 10)))
        {
            if (c->is_http11 && c->is_keepalive &&
                hdr->value_len == 5 && str_case_eq_fixed("close", hdr->value, 5))
            {
                c->is_keepalive = 0;
                trace("setting conn %d to close after response\n", c->fd);
            }
            else if (!c->is_http11 && c->cached_keepalive_default &&
                hdr->value_len == 10 && str_case_eq_fixed("keep-alive", hdr->value, 10))
            {
                c->is_keepalive = 1;
                trace("setting conn %d to keep after response\n", c->fd);
            }
            if (next_req_follows && c->receive_chunked && (!c->is_http11 || got_host)) break;
        }
        else if (unlikely(c->is_http11 && hdr->name_len == 6 &&
                str_case_eq_fixed("expect", hdr->name, 6)))
        {
            // Check for "100-continue" value (case-insensitive)
            if (hdr->value_len == 12 &&
                str_case_eq_fixed("100-continue", hdr->value, 12))
            {
                c->expect_continue = 1;
                trace("got Expect: 100-continue on fd=%d\n", c->fd);
            }
            else {
                // RFC 7231: unknown expectation, respond with 417
                err_code = 417;
                err = "Expectation Failed\n";
                goto got_bad_request;
            }
        }
        else if (unlikely(c->is_http11 && hdr->name_len == 17 &&
                str_case_eq_fixed("transfer-encoding", hdr->name, 17)))
        {
            // RFC 7230 3.3.3: reject multiple Transfer-Encoding headers
            // to prevent request smuggling attacks
            if (got_transfer_encoding) {
                err_code = 400;
                err = "Multiple Transfer-Encoding headers not allowed\n";
                goto got_bad_request;
            }
            got_transfer_encoding = 1;

            // RFC 7230: Accept "chunked" with optional extensions
            // Valid formats: "chunked", "chunked;ext=val", "chunked ; ext"
            bool is_chunked = (hdr->value_len >= 7 &&
                str_case_eq_fixed("chunked", hdr->value, 7) &&
                (hdr->value_len == 7 ||
                 hdr->value[7] == ';' ||
                 hdr->value[7] == ' ' ||
                 hdr->value[7] == '\t'));

            // Also accept "identity" which means no encoding
            bool is_identity = (hdr->value_len == 8 &&
                str_case_eq_fixed("identity", hdr->value, 8));

            if (is_chunked) {
                // RFC 7230 3.3.3: reject if Content-Length is also present
                // This prevents request smuggling attacks
                if (got_content_length) {
                    err_code = 400;
                    err = "Content-Length not allowed with Transfer-Encoding\n";
                    goto got_bad_request;
                }
                c->receive_chunked = 1;
                trace("got Transfer-Encoding: chunked on fd=%d\n", c->fd);
            }
            else if (is_identity) {
                // identity means no encoding - treat as if no TE header
                trace("got Transfer-Encoding: identity on fd=%d (ignored)\n", c->fd);
            }
            else {
                // Unsupported transfer encoding
                err_code = 501;
                err = "Unsupported Transfer-Encoding\n";
                goto got_bad_request;
            }
        }
        else if (unlikely(hdr->name_len == 4 &&
                str_case_eq_fixed("host", hdr->name, 4)))
        {
            got_host = 1;
        }
    }

    // RFC 7230 Section 5.4: HTTP/1.1 requests MUST include Host header
    if (unlikely(c->is_http11 && !got_host)) {
        err_code = 400;
        err = "Host header required for HTTP/1.1\n";
        goto got_bad_request;
    }

    if (c->cached_max_conn_reqs > 0 && c->reqs >= c->cached_max_conn_reqs) {
        c->is_keepalive = 0;
        trace("reached max requests per connection (%d), will close after response\n", c->cached_max_conn_reqs);
    }

    if (likely(next_req_follows) && !got_content_length && !c->receive_chunked) goto got_it_all;
    else if (likely(got_content_length)) goto got_cl;
    else if (unlikely(c->receive_chunked)) goto got_chunked;

    // body_is_required but no Content-Length or Transfer-Encoding
    err_code = 411;
    err = "Content-Length or Transfer-Encoding required\n";

got_bad_request:
    respond_with_server_error(c, err, err_code);
    return 0;

got_cl:
    c->expected_cl = (ssize_t)expected;
    c->received_cl = SvCUR(c->rbuf);
    trace("expecting body %d size=%"Ssz_df" have=%"Ssz_df"\n",
        c->fd, (Ssz)c->expected_cl, (Ssz)c->received_cl);
    SvGROW(c->rbuf, c->expected_cl + 1);

    // don't have enough bytes to schedule immediately?
    // unlikely = optimize for short requests
    if (unlikely(c->expected_cl && c->received_cl < c->expected_cl)) {
        send_100_continue(c);
        return 1;
    }
    // fallthrough: have enough bytes
    goto got_it_all;

got_chunked:
    // Initialize chunked transfer state
    c->chunk_remaining = CHUNK_STATE_PARSE_SIZE;
    c->chunk_count = 0;       // reset chunk counter
    c->trailer_count = 0;     // reset trailer counter
    c->expected_cl = 0;       // will accumulate as we decode
    c->received_cl = 0;
    change_receiving_state(c, RECEIVE_CHUNKED);
    trace("starting chunked receive on fd=%d, have=%"Sz_uf" bytes\n",
        c->fd, (Sz)SvCUR(c->rbuf));

    send_100_continue(c);

    // Try to parse any chunks we already have
    {
        int ret = try_parse_chunked(c);
        if (ret == 1)
            return 1;  // need more data
        if (ret == -1) {
            err_code = 400;
            err = "Malformed chunked encoding\n";
            goto got_bad_request;
        }
    }
    // fallthrough: chunked body complete

got_it_all:
    sched_request_callback(c);
    return 0;
}

static void
conn_write_ready (struct feer_conn *c)
{
#ifdef FEERSUM_HAS_H2
    if (c->is_h2_stream) {
        h2_try_stream_write(aTHX_ c);
        return;
    }
#endif

    if (c->in_callback) {
        // Inside a callback: defer writes via the event loop write watcher.
        // This ensures data gets flushed after the callback returns.
        start_write_watcher(c);
        return;
    }

#ifdef FEERSUM_HAS_TLS
    if (c->tls) {
        // Call TLS write path directly instead of deferring to write watcher.
        // This mirrors how plain HTTP calls try_conn_write immediately below.
        try_tls_conn_write(feersum_ev_loop, &c->write_ev_io, EV_WRITE);
        return;
    }
#endif

    // attempt a non-blocking write immediately if we're not already
    // waiting for writability
    try_conn_write(feersum_ev_loop, &c->write_ev_io, EV_WRITE);
}

/*
 * H2 stream dispatch helpers.
 * These are static functions (not XS) so #ifdef works correctly.
 * Called from XS CODE/PPCODE blocks that can't use #ifdef directly.
 */
static int
h2_try_write_chunk (pTHX_ struct feer_conn *c, SV *body)
{
#ifdef FEERSUM_HAS_H2
    if (unlikely(c->is_h2_stream)) {
        feersum_h2_write_chunk(aTHX_ c, body);
        return 1;
    }
#endif
    PERL_UNUSED_VAR(c); PERL_UNUSED_VAR(body);
    return 0;
}

static int
h2_is_stream (struct feer_conn *c)
{
#ifdef FEERSUM_HAS_H2
    if (unlikely(c->is_h2_stream))
        return 1;
#endif
    PERL_UNUSED_VAR(c);
    return 0;
}

INLINE_UNLESS_DEBUG static void
send_100_continue (struct feer_conn *c)
{
    if (likely(!c->expect_continue))
        return;

    static const char continue_response[] = "HTTP/1.1 100 Continue" CRLF CRLF;
#ifdef FEERSUM_HAS_TLS
    if (c->tls) {
        feer_tls_send(c, continue_response, sizeof(continue_response) - 1);
        feer_tls_flush_wbuf(c);
        if (c->tls_wbuf.off > 0)
            start_write_watcher(c);
        c->expect_continue = 0;
        return;
    }
#endif
    ssize_t wr = write(c->fd, continue_response, sizeof(continue_response) - 1);
    // If write fails with EAGAIN or is partial, client will timeout and
    // send body anyway (RFC 7231 recommends client wait ~1 second)
    if (likely(wr > 0)) {
        trace("sent 100 Continue to fd=%d\n", c->fd);
    }
    else if (wr < 0 && errno != EAGAIN && errno != EINTR) {
        trace("100 Continue write error fd=%d: %s\n", c->fd, strerror(errno));
    }
    c->expect_continue = 0;  // only send once
}

INLINE_UNLESS_DEBUG static void
free_feer_req (struct feer_req *req)
{
    if (unlikely(!req))
        return;

    if (req->buf)
        SvREFCNT_dec(req->buf);
    if (likely(req->path))
        SvREFCNT_dec(req->path);
    if (likely(req->query))
        SvREFCNT_dec(req->query);
#ifdef FEERSUM_HAS_H2
    if (req->h2_method_sv)
        SvREFCNT_dec(req->h2_method_sv);
    if (req->h2_uri_sv)
        SvREFCNT_dec(req->h2_uri_sv);
#endif
    FEER_REQ_FREE(req);
}

INLINE_UNLESS_DEBUG static void
free_request (struct feer_conn *c)
{
    free_feer_req(c->req);
    c->req = NULL;
}

static void
respond_with_server_error (struct feer_conn *c, const char *msg, int err_code)
{
    SV *tmp;
    STRLEN msg_len;

#ifdef FEERSUM_HAS_H2
    if (unlikely(c->is_h2_stream)) {
        feersum_h2_respond_error(c, err_code);
        return;
    }
#endif

    if (unlikely(c->responding != RESPOND_NOT_STARTED)) {
        trouble("Tried to send server error but already responding!");
        return;
    }

    msg_len = strlen(msg);
    assert(msg_len < INT_MAX);

    tmp = newSVpvf("HTTP/1.%d %d %s" CRLF
                   "Content-Type: text/plain" CRLF
                   "Connection: close" CRLF
                   "Cache-Control: no-cache, no-store" CRLF
                   "Content-Length: %"Ssz_df"" CRLFx2
                   "%.*s",
              c->is_http11 ? 1 : 0,
              err_code, http_code_to_msg(err_code),
              (Ssz)msg_len,
              (int)msg_len, msg);
    add_sv_to_wbuf(c, sv_2mortal(tmp));

    stop_read_watcher(c);
    stop_read_timer(c);
    stop_header_timer(c);  // Slowloris protection
    change_responding_state(c, RESPOND_SHUTDOWN);
    change_receiving_state(c, RECEIVE_SHUTDOWN);
    c->is_keepalive = 0;
    conn_write_ready(c);
}


