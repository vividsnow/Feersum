
INLINE_UNLESS_DEBUG
static SV*
fetch_av_normal (pTHX_ AV *av, I32 i)
{
    SV **elt = av_fetch(av, i, 0);
    if (elt == NULL) return NULL;
    SV *sv = *elt;
    if (unlikely(SvMAGICAL(sv))) sv = sv_2mortal(newSVsv(sv));
    if (unlikely(!SvOK(sv))) return NULL;
    // usually array ref elems aren't RVs (for PSGI anyway)
    if (unlikely(SvROK(sv))) sv = SvRV(sv);
    return sv;
}

INLINE_UNLESS_DEBUG
static struct iomatrix *
next_iomatrix (struct feer_conn *c)
{
    bool add_iomatrix = 0;
    struct iomatrix *m;

    if (!c->wbuf_rinq) {
        trace3("next_iomatrix(%d): head\n", c->fd);
        add_iomatrix = 1;
    }
    else {
        // get the tail-end struct
        m = (struct iomatrix *)c->wbuf_rinq->prev->ref;
        trace3("next_iomatrix(%d): tail, count=%d, offset=%d\n",
            c->fd, m->count, m->offset);
        if (m->count >= FEERSUM_IOMATRIX_SIZE) {
            add_iomatrix = 1;
        }
    }

    if (add_iomatrix) {
        trace3("next_iomatrix(%d): alloc\n", c->fd);
        IOMATRIX_ALLOC(m);
        m->offset = m->count = 0;
        rinq_push(&c->wbuf_rinq, m);
    }

    trace3("next_iomatrix(%d): end, count=%d, offset=%d\n",
        c->fd, m->count, m->offset);
    return m;
}

// PSGI strings are bytes: ship a UTF8-flagged value as its downgraded octets,
// which is what the syswrite-based servers emit.  Wide chars (> 255, an app
// error per spec) fail the downgrade and keep their UTF-8 bytes - framing
// stays consistent, unlike Starman's mid-write truncation.  Mortal copy built
// from the already-fetched PV so magical SVs are not fetched twice.
INLINE_UNLESS_DEBUG
static SV *
feer_bytes_mortal(const char *p, STRLEN len)
{
    SV *sv = sv_2mortal(newSVpvn_utf8(p, len, 1));
    (void)sv_utf8_downgrade(sv, TRUE);
    return sv;
}

INLINE_UNLESS_DEBUG
static STRLEN
add_sv_to_wbuf(struct feer_conn *c, SV *sv)
{
    struct iomatrix *m = next_iomatrix(c);
    unsigned idx = m->count++;
    STRLEN cur;
    // Same reason as add_placeholder_to_wbuf: newSVsv() below can croak on a
    // magical SV, leaving this slot counted but unfilled.
    m->iov[idx].iov_base = NULL;
    m->iov[idx].iov_len = 0;
    if (unlikely(SvMAGICAL(sv) || SvUTF8(sv))) {
        // copy to force it to be normal; a UTF8-flagged copy is downgraded to
        // its bytes (see feer_bytes_mortal) without mutating the app's SV.
        sv = newSVsv(sv);
        if (unlikely(SvUTF8(sv)))
            (void)sv_utf8_downgrade(sv, TRUE);
    }
    else if (unlikely(SvPADTMP(sv))) {
        // PADTMPs have their PVs re-used, so we can't simply keep a
        // reference.  TEMPs maybe behave in a similar way and are potentially
        // stealable.  If not stealing, we must make a copy.
#ifdef FEERSUM_STEAL
        if (SvFLAGS(sv) == (SVs_PADTMP|SVf_POK|SVp_POK)) {
            trace3("STEALING\n");
            SV *thief = newSV(0);
            sv_upgrade(thief, SVt_PV);

            SvPV_set(thief, SvPVX(sv));
            SvLEN_set(thief, SvLEN(sv));
            SvCUR_set(thief, SvCUR(sv));

            // make the temp null
            (void)SvOK_off(sv);
            SvPV_set(sv, NULL);
            SvLEN_set(sv, 0);
            SvCUR_set(sv, 0);

            SvFLAGS(thief) |= SVf_READONLY|SVf_POK|SVp_POK;

            sv = thief;
        }
        else {
            sv = newSVsv(sv);
        }
#else
        sv = newSVsv(sv);
#endif
    }
    else {
        sv = SvREFCNT_inc(sv);
    }

    m->iov[idx].iov_base = SvPV(sv, cur);
    m->iov[idx].iov_len = cur;
    m->sv[idx] = sv;

    c->wbuf_len += cur;
    return cur;
}

INLINE_UNLESS_DEBUG
static STRLEN
add_const_to_wbuf(struct feer_conn *c, const char *str, size_t str_len)
{
    struct iomatrix *m = next_iomatrix(c);
    unsigned idx = m->count++;
    m->iov[idx].iov_base = (void*)str;
    m->iov[idx].iov_len = str_len;
    m->sv[idx] = NULL;
    c->wbuf_len += str_len;
    return str_len;
}

INLINE_UNLESS_DEBUG
static void
add_placeholder_to_wbuf(struct feer_conn *c, SV **sv, struct iovec **iov_ref)
{
    struct iomatrix *m = next_iomatrix(c);
    unsigned idx = m->count++;
    // The slot is counted now but filled by update_wbuf_placeholder later; if
    // anything croaks in between it must be an empty iovec, not stale memory.
    m->iov[idx].iov_base = NULL;
    m->iov[idx].iov_len = 0;
    *sv = newSV(31);
    SvPOK_on(*sv);
    m->sv[idx] = *sv;
    *iov_ref = &m->iov[idx];
}

INLINE_UNLESS_DEBUG
static void
finish_wbuf(struct feer_conn *c)
{
    if (!c->use_chunked) return; // nothing required unless chunked encoding
    // HEAD keeps the Transfer-Encoding a GET would have sent but carries no
    // content - not even the terminating chunk, which a client that correctly
    // reads no body would parse as the start of the next response.
    if (unlikely(c->no_resp_body)) return;
    add_const_to_wbuf(c, "0\r\n\r\n", 5); // terminating chunk
}

INLINE_UNLESS_DEBUG
static void
update_wbuf_placeholder(struct feer_conn *c, SV *sv, struct iovec *iov)
{
    STRLEN cur;
    // can't pass iov_len for cur; incompatible pointer type on some systems:
    iov->iov_base = SvPV(sv,cur);
    iov->iov_len = cur;
    c->wbuf_len += cur;
}

static void
add_chunk_sv_to_wbuf(struct feer_conn *c, SV *sv)
{
    STRLEN len;
    (void)SvPV(sv, len);
    if (unlikely(len == 0)) return;  /* skip: "0\r\n\r\n" is the terminal chunk */

    SV *chunk;
    struct iovec *chunk_iov;
    add_placeholder_to_wbuf(c, &chunk, &chunk_iov);
    STRLEN cur = add_sv_to_wbuf(c, sv);
    add_crlf_to_wbuf(c);
    sv_setpvf(chunk, "%"Sz_xf CRLF, (Sz)cur);
    update_wbuf_placeholder(c, chunk, chunk_iov);
}

static const char *
http_code_to_msg (int code) {
    switch (code) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 102: return "Processing"; // RFC 2518
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 207: return "Multi-Status"; // RFC 4918 (WebDav)
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 307: return "Temporary Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 418: return "I'm a teapot";
        case 421: return "Misdirected Request"; // RFC 9110
        case 422: return "Unprocessable Entity"; // RFC 4918
        case 423: return "Locked"; // RFC 4918
        case 424: return "Failed Dependency"; // RFC 4918
        case 425: return "Too Early"; // RFC 8470
        case 426: return "Upgrade Required"; // RFC 2817
        case 429: return "Too Many Requests"; // RFC 6585
        case 431: return "Request Header Fields Too Large"; // RFC 6585
        case 449: return "Retry With"; // Microsoft
        case 450: return "Blocked by Parental Controls"; // Microsoft
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        case 506: return "Variant Also Negotiates"; // RFC 2295
        case 507: return "Insufficient Storage"; // RFC 4918
        case 509: return "Bandwidth Limit Exceeded"; // Apache mod
        case 510: return "Not Extended"; // RFC 2774
        case 530: return "User access denied"; // ??
        default: break;
    }

    // default to the Nxx group names in RFC 2616
    switch (code / 100) {
        case 1: return "Informational";
        case 2: return "Success";
        case 3: return "Redirection";
        case 4: return "Client Error";
        default: return "Error";
    }
}

static int
prep_socket(int fd, int is_tcp)
{
#ifdef HAS_ACCEPT4
    int flags = 1;
#else
    int flags;

    // make it non-blocking and close-on-exec
    flags = fcntl(fd, F_GETFL);
    if (unlikely(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0))
        return -1;
    if (unlikely(fcntl(fd, F_SETFD, FD_CLOEXEC) < 0))
        return -1;

    flags = 1;
#endif
    if (likely(is_tcp)) {
        if (unlikely(setsockopt(fd, SOL_TCP, TCP_NODELAY, &flags, sizeof(int))))
            return -1;
    }

    return 0;
}

// TCP cork/uncork for batching writes (Linux: TCP_CORK, BSD: TCP_NOPUSH)
#if defined(TCP_CORK)
# define FEERSUM_TCP_CORK TCP_CORK
#elif defined(TCP_NOPUSH)
# define FEERSUM_TCP_CORK TCP_NOPUSH
#endif

#ifdef FEERSUM_TCP_CORK
INLINE_UNLESS_DEBUG static void
set_cork(struct feer_conn *c, int cork)
{
    if (likely(c->cached_is_tcp)) {
        setsockopt(c->fd, SOL_TCP, FEERSUM_TCP_CORK, &cork, sizeof(cork));
    }
}
#else
# define set_cork(c, cork) ((void)0)
#endif

static void
invoke_shutdown_cb(pTHX_ struct feer_server *server)
{
    dSP;
    SV *cb = server->shutdown_cb_cv;
    server->shutdown_cb_cv = NULL;

    /* Release this server's hold on the loop, the way unlisten does.  Without
     * it a shut-down server left its prepare/check/idle watchers registered
     * and its share of the process-wide date timer refcounted, so ev_run
     * could never run dry: with one instance the process only exited because
     * the docs say to exit from the callback, and with several the loop kept
     * ticking for an instance that had already stopped serving. */
    ev_idle_stop(feersum_ev_loop, &server->ei);
    ev_prepare_stop(feersum_ev_loop, &server->ep);
    ev_check_stop(feersum_ev_loop, &server->ec);
    if (server->watchers_initialized) {
        server->watchers_initialized = false;
        if (--date_timer_refs <= 0) {
            ev_timer_stop(feersum_ev_loop, &date_timer);
            date_timer_refs = 0;
        }
    }

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    call_sv(cb, G_EVAL|G_VOID|G_DISCARD|G_NOARGS);
    SPAGAIN;
    trace3("called shutdown handler\n");
    /* Report it, as the access-log and request callbacks do.  Swallowing it
     * left a worker that had already closed its listeners and would never
     * finish shutting down, with nothing logged anywhere to say why. */
    if (SvTRUE(ERRSV)) {
        trouble("shutdown callback died: %-p\n", ERRSV);
        sv_setsv(ERRSV, &PL_sv_undef);
    }
    SvREFCNT_dec(cb);
    FREETMPS;
    LEAVE;
}

/*
 * Stop accepting, close the listeners, drop idle keepalive connections and let
 * the in-flight ones drain; cb fires once the last one is done.  Shared by the
 * graceful_shutdown XSUB and the max_requests retirement path.  Callers must
 * have rejected the already-shutting-down case.
 */
static void
feer_begin_graceful_shutdown(pTHX_ struct feer_server *server, SV *cb)
{
    SvREFCNT_dec(server->shutdown_cb_cv);   /* NULL-safe; normally already is */
    server->shutdown_cb_cv = newSVsv(cb);
    trace("shutting down, active=%d\n", server->active_conns);

    server->shutting_down = 1;
    for (int i = 0; i < server->n_listeners; i++) {
        struct feer_listen *lsnr = &server->listeners[i];
        ev_io_stop(feersum_ev_loop, &lsnr->accept_w);
        /* A reuseport listener's accept queue dies with its fd: those clients
         * completed the handshake and would get RST.  Take them into the
         * drain.  UNIX listeners stay shared even under reuseport (workers
         * inherit the fd), so leave their queue to a live sibling. */
        if (unlikely(server->drain_accept_queue)
            && lsnr->is_tcp && lsnr->fd >= 0) {
            while (try_accept_one(feersum_ev_loop, lsnr, server))
                ;
        }
        ev_timer_stop(feersum_ev_loop, &lsnr->emfile_w);
        if (lsnr->fd >= 0) {
            if (unlikely(close(lsnr->fd) < 0))
                trouble("close(listen fd) fd=%d: %s\n", lsnr->fd, strerror(errno));
            ev_io_set(&lsnr->accept_w, -1, EV_READ);
            lsnr->fd = -1;
        }
#ifdef FEERSUM_HAS_TLS
        feer_tls_cleanup_listener(lsnr);
#endif
        lsnr->pause_flags = 0;  /* slot is free; clear stale pause state */
    }

    /* Close idle keepalive connections - they won't get new requests */
    while (feer_server_recycle_idle_conn(server))
        ;

    if (server->active_conns <= 0 && server->shutdown_cb_cv) {
        trace("shutdown is immediate\n");
        invoke_shutdown_cb(aTHX_ server);
    }
}

static void
safe_close_conn(struct feer_conn *c, const char *where)
{
    if (unlikely(c->fd < 0))
        return;

    /* The app's IO handle shares this descriptor and will close it.  Closing
     * it here too means the second close hits whatever number the kernel has
     * since recycled, silently killing an unrelated connection. */
    if (unlikely(c->fd_given_away)) {
        c->fd = -1;
        return;
    }

#ifdef FEERSUM_HAS_H2
    if (c->is_h2_stream) {
        /* Pseudo-conns share parent's fd - do NOT close or shutdown it.
         * The parent connection owns the fd and will close it. */
        c->fd = -1;
        return;
    }
#endif

    CLOSE_SENDFILE_FD(c);

#ifdef FEERSUM_HAS_TLS
    // Tear down the Extended CONNECT bridge before dropping the client fd.
    if (c->tls_tunnel)
        feer_tls_tunnel_shutdown(c);

    // Best-effort TLS alert before TCP shutdown.  An alert encrypted now
    // carries a later sequence number than anything still queued in tls_wbuf,
    // so writing it straight to the fd would put it AHEAD of those records and
    // the peer could not decrypt it.  Flush first; if the queue will not
    // drain, send nothing - an undecryptable alert is worse than none.
    if (c->tls && c->tls_handshake_done && c->tls_wbuf.off > 0)
        (void)feer_tls_flush_wbuf(c);
    if (c->tls && c->tls_handshake_done && c->tls_wbuf.off == 0
        && !c->tls_alert_sent) {
        ptls_buffer_t closebuf;
        c->tls_alert_sent = 1;
        ptls_buffer_init(&closebuf, "", 0);
        if (unlikely(c->tls_fatal_alert))
            ptls_send_alert(c->tls, &closebuf, PTLS_ALERT_LEVEL_FATAL,
                            c->tls_fatal_alert);
        else
            ptls_send_alert(c->tls, &closebuf, PTLS_ALERT_LEVEL_WARNING,
                            PTLS_ALERT_CLOSE_NOTIFY);
        if (closebuf.off > 0) {
            ssize_t wr PERL_UNUSED_DECL;
            wr = write(c->fd, closebuf.base, closebuf.off);
        }
        ptls_buffer_dispose(&closebuf);
    }
#endif

    // Graceful TCP shutdown: send FIN to peer before close
    // This ensures client sees clean EOF instead of RST
    shutdown(c->fd, SHUT_WR);

    /* The alert and FIN are queued behind the response now, but the response
     * is only in the kernel, not delivered.  Closing here while a routine
     * client frame (a WINDOW_UPDATE for the DATA just sent) is unread makes
     * the kernel answer RST and drop the queued response.  Hold the fd open
     * and drain until the peer EOFs or the deadline fires. */
    if (unlikely(c->want_linger_close) && feer_arm_linger(c, where))
        return;

    if (unlikely(close(c->fd) < 0))
        trouble("close(%s) fd=%d: %s\n", where, c->fd, strerror(errno));

    c->fd = -1;
}

static struct feer_conn *
new_feer_conn (EV_P_ int conn_fd, struct sockaddr *sa, socklen_t sa_len,
               struct feer_server *srvr, struct feer_listen *lsnr)
{
    SV *self = newSV(0);
    SvUPGRADE(self, SVt_PVMG); // ensures sv_bless doesn't reallocate
    SvGROW(self, sizeof(struct feer_conn));
    SvPOK_only(self);
    SvIOK_on(self);
    SvIV_set(self,conn_fd);

    struct feer_conn *c = (struct feer_conn *)SvPVX(self);
    Zero(c, 1, struct feer_conn);

    c->self = self;
    c->server = srvr;
    c->listener = lsnr;
    SvREFCNT_inc_void_NN(srvr->self); // prevent server GC while conn alive

    // Cache hot config fields to avoid c->server->/c->listener-> indirection
    c->cached_read_timeout      = srvr->read_timeout;
    c->cached_write_timeout     = srvr->write_timeout;
    c->cached_max_conn_reqs     = srvr->max_connection_reqs;
    c->cached_is_tcp            = lsnr->is_tcp;
    c->cached_keepalive_default = srvr->is_keepalive;
    c->cached_use_reverse_proxy = srvr->use_reverse_proxy;
    c->cached_max_read_buf      = srvr->max_read_buf;
    c->cached_max_body_len      = srvr->max_body_len;
    c->cached_max_uri_len       = srvr->max_uri_len;
    c->cached_wbuf_low_water    = srvr->wbuf_low_water;
    c->fd = conn_fd;
    memcpy(&c->sa, sa, sa_len); // copy into embedded storage
    c->receiving = srvr->use_proxy_protocol ? RECEIVE_PROXY_HEADER : RECEIVE_HEADERS;
    c->sendfile_fd = -1; // no sendfile pending

#ifdef FEERSUM_HAS_TLS
    if (lsnr->tls_ctx_ref) {
        ev_io_init(&c->read_ev_io, try_tls_conn_read, conn_fd, EV_READ);
        ev_io_init(&c->write_ev_io, try_tls_conn_write, conn_fd, EV_WRITE);
        feer_tls_init_conn(c, lsnr->tls_ctx_ref);
    } else
#endif
    {
        ev_io_init(&c->read_ev_io, try_conn_read, conn_fd, EV_READ);
        ev_io_init(&c->write_ev_io, try_conn_write, conn_fd, EV_WRITE);
    }
    ev_set_priority(&c->read_ev_io, srvr->read_priority);
    c->read_ev_io.data = (void *)c;

    ev_set_priority(&c->write_ev_io, srvr->write_priority);
    c->write_ev_io.data = (void *)c;

    ev_init(&c->read_ev_timer, conn_read_timeout);
    ev_set_priority(&c->read_ev_timer, srvr->read_priority);
    c->read_ev_timer.data = (void *)c;

    // Slowloris protection: header deadline timer (non-resetting)
    ev_init(&c->header_ev_timer, conn_header_timeout);
    ev_set_priority(&c->header_ev_timer, srvr->read_priority);
    c->header_ev_timer.data = (void *)c;

    ev_init(&c->write_ev_timer, conn_write_timeout);
    ev_set_priority(&c->write_ev_timer, srvr->write_priority);
    c->write_ev_timer.data = (void *)c;

    trace3("made conn fd=%d self=%p, c=%p, cur=%"Sz_uf", len=%"Sz_uf"\n",
        c->fd, self, c, (Sz)SvCUR(self), (Sz)SvLEN(self));

    SV *rv = newRV_inc(c->self);
    sv_bless(rv, feer_conn_stash); // so DESTROY can get called on read errors
    SvREFCNT_dec(rv);

    SvREADONLY_on(self);
    srvr->active_conns++;
    return c;
}

INLINE_UNLESS_DEBUG
static struct feer_conn *
sv_2feer_conn (SV *rv)
{
    if (unlikely(!sv_isa(rv,"Feersum::Connection")))
       croak("object is not of type Feersum::Connection");
    return (struct feer_conn *)SvPVX(SvRV(rv));
}

INLINE_UNLESS_DEBUG
static SV*
feer_conn_2sv (struct feer_conn *c)
{
    return newRV_inc(c->self);
}

static feer_conn_handle *
sv_2feer_conn_handle (SV *rv, bool can_croak)
{
    trace3("sv 2 conn_handle\n");
    if (unlikely(!SvROK(rv))) croak("Expected a reference");
    // do not allow subclassing
    SV *sv = SvRV(rv);
    if (likely(
        sv_isobject(rv) &&
        (SvSTASH(sv) == feer_conn_writer_stash ||
         SvSTASH(sv) == feer_conn_reader_stash)
    )) {
        UV uv = SvUV(sv);
        if (uv == 0) {
            if (can_croak) croak("Operation not allowed: Handle is closed.");
            return NULL;
        }
        return INT2PTR(feer_conn_handle*,uv);
    }

    if (can_croak)
        croak("Expected a Feersum::Connection::Writer or ::Reader object");
    return NULL;
}

static SV *
new_feer_conn_handle (pTHX_ struct feer_conn *c, bool is_writer)
{
    SV *sv;
    SvREFCNT_inc_void_NN(c->self);
    sv = newRV_noinc(newSVuv(PTR2UV(c)));
    sv_bless(sv, is_writer ? feer_conn_writer_stash : feer_conn_reader_stash);
    /* Pin the referent (the blessed SV, whose refcount drives DESTROY) while
     * the guarded callback runs; see pinned_writer in feersum_core.h.  The
     * !pinned_writer gate keeps a nested poll_cb's per-invocation handle from
     * stealing the slot - by the time a poll_cb can fire, the real writer has
     * already been created and pinned. */
    if (is_writer && unlikely(c->pin_writer) && !c->pinned_writer)
        c->pinned_writer = SvREFCNT_inc_NN(SvRV(sv));
    return sv;
}

static void
init_feer_server (struct feer_server *s)
{
    Zero(s, 1, struct feer_server);
    s->read_timeout = READ_TIMEOUT;
    s->header_timeout = HEADER_TIMEOUT;
    s->write_timeout = WRITE_TIMEOUT;
    s->linger_timeout = LINGER_TIMEOUT;
    s->max_accept_per_loop = DEFAULT_MAX_ACCEPT_PER_LOOP;
    s->max_connections = 10000;
    s->max_read_buf = MAX_READ_BUF;
    s->max_body_len = MAX_BODY_LEN;
    s->max_uri_len = MAX_URI_LEN;
    s->psgix_io = true;
#ifdef FEERSUM_HAS_H2
    s->max_h2_concurrent_streams = FEER_H2_MAX_CONCURRENT_STREAMS;
    s->max_h2_conn_body = 0;   /* off; per-stream max_body_len still applies */
#endif
    for (int i = 0; i < FEER_MAX_LISTENERS; i++) {
        s->listeners[i].fd = -1;
        s->listeners[i].server = s;
    }
}

static struct feer_server *
new_feer_server (pTHX)
{
    SV *self = newSV(0);
    SvUPGRADE(self, SVt_PVMG);
    SvGROW(self, sizeof(struct feer_server));
    SvPOK_only(self);
    SvIOK_on(self);

    struct feer_server *s = (struct feer_server *)SvPVX(self);
    init_feer_server(s);
    s->self = self;

    SV *rv = newRV_inc(self);
    sv_bless(rv, feer_stash);
    SvREFCNT_dec(rv);

    SvREADONLY_on(self);
    return s;
}

INLINE_UNLESS_DEBUG
static struct feer_server *
sv_2feer_server (SV *rv)
{
    // Accept both instance ($obj->method) and class (Feersum->method) calls
    if (sv_isa(rv, "Feersum")) {
        return (struct feer_server *)SvPVX(SvRV(rv));
    }
    // Class method call: "Feersum"->method() - return default server
    if (SvPOK(rv) && strEQ(SvPV_nolen(rv), "Feersum")) {
        if (unlikely(!default_server))
            croak("Feersum: no server instance (call Feersum->new first)");
        return default_server;
    }
    croak("object is not of type Feersum");
    return NULL; // unreachable
}

INLINE_UNLESS_DEBUG
static SV*
feer_server_2sv (struct feer_server *s)
{
    return newRV_inc(s->self);
}

INLINE_UNLESS_DEBUG static void
start_read_watcher(struct feer_conn *c) {
    ASSERT_EV_LOOP_INITIALIZED();
    if (unlikely(ev_is_active(&c->read_ev_io)))
        return;
    trace("start read watcher %d\n",c->fd);
    ev_io_start(feersum_ev_loop, &c->read_ev_io);
    SvREFCNT_inc_void_NN(c->self);
}

INLINE_UNLESS_DEBUG static void
stop_read_watcher(struct feer_conn *c) {
    if (unlikely(!ev_is_active(&c->read_ev_io)))
        return;
    trace("stop read watcher %d\n",c->fd);
    ev_io_stop(feersum_ev_loop, &c->read_ev_io);
    SvREFCNT_dec(c->self);
}

/* A response counts as done once queued, so an idle-looking connection can
 * still owe the client megabytes.  True only while the queue SHRINKS: a peer
 * that stops reading holds it steady and stays reapable. */
INLINE_UNLESS_DEBUG static int
feer_conn_still_delivering(struct feer_conn *c) {
#ifdef FEERSUM_HAS_OUTQ
    int outq = feer_sock_outq(c->fd);
    if (outq > 0 && (c->prev_read_outq <= 0 || outq < c->prev_read_outq)) {
        c->prev_read_outq = outq;
        return 1;
    }
    c->prev_read_outq = 0;
#else
    PERL_UNUSED_ARG(c);
#endif
    return 0;
}

INLINE_UNLESS_DEBUG static void
restart_read_timer(struct feer_conn *c) {
    /* While lingering this timer is the one-shot linger deadline, and
     * ev_timer_again would stop it rather than restart it. */
    if (unlikely(c->closing_linger))
        return;
    if (likely(!ev_is_active(&c->read_ev_timer))) {
        trace("restart read timer %d\n",c->fd);
        c->read_ev_timer.repeat = c->cached_read_timeout;
        SvREFCNT_inc_void_NN(c->self);
    }
    ev_timer_again(feersum_ev_loop, &c->read_ev_timer);
}

INLINE_UNLESS_DEBUG static void
stop_read_timer(struct feer_conn *c) {
    if (unlikely(!ev_is_active(&c->read_ev_timer)))
        return;
    trace("stop read timer %d\n",c->fd);
    ev_timer_stop(feersum_ev_loop, &c->read_ev_timer);
    SvREFCNT_dec(c->self);
}

/* Has the peer hung up?  A peek that returns 0 is EOF; EAGAIN just means a
 * quiet-but-live client, which is the normal case for a streaming response.
 * Only for paths that would otherwise never learn the connection is dead. */
INLINE_UNLESS_DEBUG static bool
peer_is_gone(struct feer_conn *c)
{
    char probe;
    ssize_t n;
    if (c->fd < 0) return 1;
    do {
        n = recv(c->fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
    } while (n < 0 && errno == EINTR);
    return n == 0;
}

INLINE_UNLESS_DEBUG static void
start_write_watcher(struct feer_conn *c) {
    ASSERT_EV_LOOP_INITIALIZED();
    if (unlikely(ev_is_active(&c->write_ev_io)))
        return;
    trace("start write watcher %d\n",c->fd);
    ev_io_start(feersum_ev_loop, &c->write_ev_io);
    SvREFCNT_inc_void_NN(c->self);
}

INLINE_UNLESS_DEBUG static void
stop_write_watcher(struct feer_conn *c) {
    if (unlikely(!ev_is_active(&c->write_ev_io)))
        return;
    trace("stop write watcher %d\n",c->fd);
    ev_io_stop(feersum_ev_loop, &c->write_ev_io);
    SvREFCNT_dec(c->self);
}

INLINE_UNLESS_DEBUG static void
restart_write_timer(struct feer_conn *c) {
    /* Progress: the poll-retry backoff resets even with no deadline
     * configured.  poll_retry_pending is NOT cleared on the early return -
     * that flag may only change where the timer is stopped or re-armed, or a
     * short retry repeat would fire as an instant deadline. */
    c->poll_retry_backoff = 0;
    /* New write progress invalidates the deadline's drain tracking: fresh
     * bytes were queued, so comparing outq against a pre-write sample would
     * lie in both directions. */
    c->prev_outq = 0;
    c->outq_stalls = 0;
    if (c->cached_write_timeout <= 0.0) return;
    if (likely(!ev_is_active(&c->write_ev_timer))) {
        trace("restart write timer %d\n",c->fd);
        SvREFCNT_inc_void_NN(c->self);
    }
    /* Unconditional: the timer may be armed as a poll retry with a short
     * repeat, which must not survive as the deadline interval. */
    c->poll_retry_pending = 0;
    c->write_ev_timer.repeat = c->cached_write_timeout;
    ev_timer_again(feersum_ev_loop, &c->write_ev_timer);
}

/* Arm the write deadline WITHOUT resetting one that is already running.
 * restart_write_timer() is the "we made progress" call; this one is for "we
 * are blocked on writability", which can be reached many times per second by
 * an app that keeps retrying, and must not keep pushing the deadline back. */
INLINE_UNLESS_DEBUG static void
ensure_write_timer(struct feer_conn *c) {
    if (c->cached_write_timeout <= 0.0) return;
    /* Already armed as the deadline: leave it, that is the point of ensure.
     * Armed as a poll retry: the deadline takes the timer back - data is
     * pending now and the short retry repeat must not linger. */
    if (ev_is_active(&c->write_ev_timer) && likely(!c->poll_retry_pending))
        return;
    trace("arm write timer %d\n",c->fd);
    if (likely(!ev_is_active(&c->write_ev_timer)))
        SvREFCNT_inc_void_NN(c->self);
    c->poll_retry_pending = 0;
    c->poll_retry_backoff = 0;
    c->write_ev_timer.repeat = c->cached_write_timeout;
    ev_timer_again(feersum_ev_loop, &c->write_ev_timer);
}

INLINE_UNLESS_DEBUG static void
stop_write_timer(struct feer_conn *c) {
    /* Structural stop: any pending paced re-invitation dies with the timer. */
    c->poll_retry_pending = 0;
    c->poll_retry_backoff = 0;
    if (unlikely(!ev_is_active(&c->write_ev_timer)))
        return;
    trace("stop write timer %d\n",c->fd);
    ev_timer_stop(feersum_ev_loop, &c->write_ev_timer);
    SvREFCNT_dec(c->self);
}

/* A write poll_cb that declined - wrote nothing.  Re-arming a level-triggered
 * watcher on an always-writable socket re-delivers the invitation every loop
 * iteration, about a core's worth, so park it and pace the retry instead: 1ms
 * doubling to 100ms, reset by write progress.  No write deadline while parked
 * - an app with nothing to say yet is the long-poll shape - but each retry
 * still checks for a vanished peer. */
static void
feersum_poll_retry_park(struct feer_conn *c)
{
    double iv;
    stop_write_watcher(c);   /* no-op for an H2 pseudo-conn (never armed) */
    iv = FEER_POLL_RETRY_MIN * (double)(1u << c->poll_retry_backoff);
    if (iv > FEER_POLL_RETRY_MAX) iv = FEER_POLL_RETRY_MAX;
    if (c->poll_retry_backoff < FEER_POLL_RETRY_BACKOFF_CAP)
        c->poll_retry_backoff++;
    c->poll_retry_pending = 1;
    if (likely(!ev_is_active(&c->write_ev_timer)))
        SvREFCNT_inc_void_NN(c->self);
    c->write_ev_timer.repeat = iv;
    ev_timer_again(feersum_ev_loop, &c->write_ev_timer);
    trace("poll_cb declined, parked fd=%d retry in %.3fs\n", c->fd, iv);
}

INLINE_UNLESS_DEBUG static void
stop_header_timer(struct feer_conn *c) {
    if (unlikely(!ev_is_active(&c->header_ev_timer)))
        return;
    trace("stop header timer %d\n", c->fd);
    ev_timer_stop(feersum_ev_loop, &c->header_ev_timer);
    SvREFCNT_dec(c->self);
}

INLINE_UNLESS_DEBUG static void
restart_header_timer(struct feer_conn *c) {
    double timeout = c->server->header_timeout;
    if (timeout <= 0.0) return;
    stop_header_timer(c);
    ev_timer_set(&c->header_ev_timer, timeout, 0.0);
    ev_timer_start(feersum_ev_loop, &c->header_ev_timer);
    SvREFCNT_inc_void_NN(c->self);
}

INLINE_UNLESS_DEBUG static void
stop_all_watchers(struct feer_conn *c) {
    stop_read_watcher(c);
    stop_read_timer(c);
    stop_header_timer(c);
    stop_write_watcher(c);
    stop_write_timer(c);
}

/* Common shutdown sequence: stop watchers, close fd, mark for cleanup.
 * Used by error/EOF/timeout paths across H1, H2, and TLS code. */
INLINE_UNLESS_DEBUG static void
feer_shutdown_conn(struct feer_conn *c, const char *where) {
    stop_all_watchers(c);
    safe_close_conn(c, where);
    change_responding_state(c, RESPOND_SHUTDOWN);
}

static void
feer_conn_set_busy(struct feer_conn *c)
{
    if (c->idle_rinq_node) {
        rinq_remove(&c->server->idle_keepalive_rinq, c->idle_rinq_node);
        c->idle_rinq_node = NULL;
    }
}

static void
feer_conn_set_idle(struct feer_conn *c)
{
    if (c->idle_rinq_node) return; // already idle

    c->idle_rinq_node = rinq_push(&c->server->idle_keepalive_rinq, c);
    trace("conn fd=%d is now idle (added to MRU)\n", c->fd);
}

static int
feer_server_recycle_idle_conn(struct feer_server *srvr)
{
    if (!srvr->idle_keepalive_rinq) return 0;

    struct feer_conn *c = (struct feer_conn *)rinq_shift(&srvr->idle_keepalive_rinq);
    if (unlikely(!c)) return 0;

    c->idle_rinq_node = NULL; // node was shifted

    trace("recycling idle keepalive conn fd=%d to make room for new accept\n", c->fd);

    // Gracefully shut down the idle connection.
    // Guard: after setup_accepted_conn drops the base refcount, connections
    // are alive only via watcher refcounts. stop_all_watchers can drop
    // refcount to 0 -> DESTROY fires before safe_close_conn.
    SvREFCNT_inc_void_NN(c->self);
#ifdef FEERSUM_HAS_H2
    /* For an idle HTTP/2 connection, tell the peer we are going away before
     * closing so it does not see an abrupt FIN (RFC 9113 6.8); mirrors the
     * H2 idle-timeout path. Covers both graceful_shutdown draining and
     * max_connections eviction. */
    if (c->h2_session && !c->h2_goaway_sent) {
        nghttp2_submit_goaway(c->h2_session, NGHTTP2_FLAG_NONE,
                              nghttp2_session_get_last_proc_stream_id(c->h2_session),
                              NGHTTP2_NO_ERROR, NULL, 0);
        c->h2_goaway_sent = 1;
        feer_h2_session_send(c);
    }
#endif
    feer_shutdown_conn(c, "recycled for new connection");
    SvREFCNT_dec(c->self);

    // active_conns will be decremented in DESTROY when refcount drops.
    return 1;
}


/* ------------------------- lingering close ------------------------- */

/* An empty wbuf_rinq means the kernel accepted the bytes, not that the peer
 * got them.  A bare close() orphans the socket and any byte arriving after -
 * a pipelined request, a speculative write - makes the kernel answer RST,
 * discarding the queued response at both ends.  Draining first does not help:
 * the byte typically arrives after the close.  So: shutdown(SHUT_WR), then
 * read and discard until EOF, a byte cap, or a deadline.  Holding the fd and
 * a max_connections slot is why the bounds are tight. */

static void
linger_read_cb(EV_P_ ev_io *w, int revents)
{
    dCONN;
    char buf[8192];
    ssize_t n;

    SvREFCNT_inc_void_NN(c->self);

    if (unlikely(revents & EV_ERROR && !(revents & EV_READ))) {
        trace("linger read EV error fd=%d revents=0x%08x\n", w->fd, revents);
        feer_shutdown_conn(c, "linger EV error");
        goto linger_out;
    }

    do {
        n = read(w->fd, buf, sizeof(buf));
    } while (n < 0 && errno == EINTR);

    if (likely(n > 0)) {
        c->linger_left = ((size_t)n < c->linger_left)
                       ? c->linger_left - (size_t)n : 0;
        trace("linger drained fd=%d left=%"Sz_uf"\n", w->fd, (Sz)c->linger_left);
        if (likely(c->linger_left > 0))
            goto linger_out;   /* within the byte budget: keep draining */
        /* A peer flooding past the cap forfeits the linger. */
        feer_shutdown_conn(c, "linger byte cap");
    }
    else if (n == 0) {
        feer_shutdown_conn(c, "linger peer EOF");  /* the ordinary end */
    }
    else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        feer_shutdown_conn(c, "linger read error");
    }
linger_out:
    SvREFCNT_dec(c->self);
}

static void
linger_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    dCONN;
    SvREFCNT_inc_void_NN(c->self);

    if (unlikely(revents & EV_ERROR))
        trouble("EV error on linger timer, fd=%d revents=0x%08x\n",
                c->fd, revents);

    trace("linger deadline fd=%d\n", c->fd);
    feer_shutdown_conn(c, "linger deadline");
    /* One-shot timer: libev auto-stopped it before running this callback, so
     * feer_shutdown_conn's stop_read_timer released nothing - balance the
     * ev_timer_start reference here. */
    SvREFCNT_dec(c->self);

    SvREFCNT_dec(c->self);  /* protection */
}

/* Linger only for a plain HTTP/1.x connection whose work is complete and only
 * while the server is not draining.  TLS and H2 keep their own close
 * sequences; shutdown and max_connections eviction run precisely to free the
 * slot a linger would hold; a non-empty wbuf means the response never reached
 * the kernel, and an in-progress response would be truncated by SHUT_WR. */
static void
feer_linger_close(struct feer_conn *c, const char *where)
{
    if (likely(c->fd >= 0)
        && c->server->linger_timeout > 0.0
        && !c->server->shutting_down
        && !c->closing_linger
        && !c->wbuf_rinq
        && (c->responding == RESPOND_SHUTDOWN
            || c->responding == RESPOND_NOT_STARTED)
#ifdef __linux__
        && c->sendfile_fd < 0
#endif
#ifdef FEERSUM_HAS_TLS
        && !c->tls
#endif
#ifdef FEERSUM_HAS_H2
        && !c->h2_session && !c->is_h2_stream
#endif
    ) {
        trace("linger begin fd=%d (%s)\n", c->fd, where);
        /* FIN queues behind the buffered response: the peer sees EOF only
         * after every queued byte.  fd_given_away conns have c->fd < 0, so
         * the check above already excludes them. */
        if (unlikely(shutdown(c->fd, SHUT_WR) < 0 && errno != ENOTCONN))
            trace("linger shutdown fd=%d: %s\n", c->fd, strerror(errno));
        stop_all_watchers(c);
        change_responding_state(c, RESPOND_SHUTDOWN);
        change_receiving_state(c, RECEIVE_SHUTDOWN);
        c->closing_linger = 1;
        c->linger_left = LINGER_MAX_BYTES;
        ev_io_init(&c->read_ev_io, linger_read_cb, c->fd, EV_READ);
        ev_set_priority(&c->read_ev_io, c->server->read_priority);
        c->read_ev_io.data = (void *)c;
        start_read_watcher(c);
        ev_timer_init(&c->read_ev_timer, linger_timeout_cb,
                      c->server->linger_timeout, 0.0);
        ev_set_priority(&c->read_ev_timer, c->server->read_priority);
        c->read_ev_timer.data = (void *)c;
        ev_timer_start(feersum_ev_loop, &c->read_ev_timer);
        SvREFCNT_inc_void_NN(c->self);
        /* The response is complete at the wire (data + FIN queued), so the
         * request is over for the app: fire its response_guard now.
         * response_guard is documented as a cheap write-completion callback;
         * holding it to the end of a courtesy drain would pin app resources
         * for up to linger_timeout on every close-response.  DESTROY's own
         * dec is NULL-safe. */
        /* NULL before dec: the guard's DESTROY can register a replacement,
         * and clearing the field afterwards would drop it on the floor. */
        { SV *g = c->ext_guard; c->ext_guard = NULL; SvREFCNT_dec(g); }
        /* Join the idle list: nothing is in flight that a close can hurt, so
         * capacity pressure (max_connections eviction) and the graceful
         * shutdown sweep may reap the connection early rather than wait out
         * the drain.  Recycle's feer_shutdown_conn is exactly the linger
         * teardown, and DESTROY's feer_conn_set_busy unlinks the node. */
        feer_conn_set_idle(c);
        return;
    }
    feer_shutdown_conn(c, where);
}

/* Lingering for the shutdown-close of a TLS/H2 connection.  feer_linger_close
 * excludes that path on purpose - it must not hold an fd and a max_connections
 * slot for a whole linger_timeout while the server is trying to exit - so this
 * arms the same drain on a socket safe_close_conn has already sent the alert
 * and FIN on, with a short cap of its own.  Returns 1 if the fd is now held. */
static int
feer_arm_linger(struct feer_conn *c, const char *where)
{
    double cap = c->server->linger_timeout;
    if (c->fd < 0 || c->closing_linger)
        return 0;
    if (cap <= 0.0 || cap > FEER_SHUTDOWN_LINGER_MAX)
        cap = FEER_SHUTDOWN_LINGER_MAX;

    trace("shutdown linger begin fd=%d (%s)\n", c->fd, where);
    c->want_linger_close = 0;   /* one attempt: the drain's close is the real one */
    c->closing_linger = 1;
    c->linger_left = LINGER_MAX_BYTES;
    stop_all_watchers(c);
    change_receiving_state(c, RECEIVE_SHUTDOWN);
    ev_io_init(&c->read_ev_io, linger_read_cb, c->fd, EV_READ);
    ev_set_priority(&c->read_ev_io, c->server->read_priority);
    c->read_ev_io.data = (void *)c;
    start_read_watcher(c);
    ev_timer_init(&c->read_ev_timer, linger_timeout_cb, cap, 0.0);
    ev_set_priority(&c->read_ev_timer, c->server->read_priority);
    c->read_ev_timer.data = (void *)c;
    ev_timer_start(feersum_ev_loop, &c->read_ev_timer);
    SvREFCNT_inc_void_NN(c->self);
    return 1;
}

static void
process_request_ready_rinq (struct feer_server *server)
{
    while (server->request_ready_rinq) {
        struct feer_conn *c =
            (struct feer_conn *)rinq_shift(&server->request_ready_rinq);
        if (unlikely(!c)) break;

        call_request_callback(c);

        if (likely(c->wbuf_rinq)) {
            // this was deferred until after the perl callback
            conn_write_ready(c);
        }
#ifdef FEERSUM_HAS_H2
        else if (c->is_h2_stream) {
            // H2 pseudo-conns don't use wbuf_rinq; flush deferred session_send
            dTHX;
            struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
            if (stream && stream->parent)
                h2_session_send_and_poll(aTHX_ stream->parent);
        }
#endif
        SvREFCNT_dec(c->self); // for the rinq
    }
}

static void
prepare_cb (EV_P_ ev_prepare *w, int revents)
{
    struct feer_server *srvr = (struct feer_server *)w->data;

    if (unlikely(revents & EV_ERROR)) {
        trouble("EV error in prepare, revents=0x%08x\n", revents);
        ev_break(EV_A, EVBREAK_ALL);
        return;
    }

    if (!srvr->shutting_down) {
        for (int i = 0; i < srvr->n_listeners; i++) {
            struct feer_listen *lsnr = &srvr->listeners[i];
            if (!ev_is_active(&lsnr->accept_w) && !lsnr->pause_flags) {
                ev_io_start(EV_A, &lsnr->accept_w);
            }
        }
    }
    ev_prepare_stop(EV_A, w);
}

static void
check_cb (EV_P_ ev_check *w, int revents)
{
    struct feer_server *server = (struct feer_server *)w->data;

    if (unlikely(revents & EV_ERROR)) {
        trouble("EV error in check, revents=0x%08x\n", revents);
        ev_break(EV_A, EVBREAK_ALL);
        return;
    }

    trace3("check! head=%p\n", server->request_ready_rinq);
    if (server->request_ready_rinq)
        process_request_ready_rinq(server);

    /* Retirement is flagged during dispatch but acted on here, at a loop
     * boundary: draining mid-dispatch closed listeners and recycled idle
     * connections while sibling requests (H2 streams especially) were still
     * queued, dropping responses for requests the app had already run. */
    if (unlikely(server->retire_pending) && !server->shutting_down) {
        dTHX;
        SV *cb = server->max_requests_cb_cv;
        SV *begin_cb = server->retire_begin_cb_cv;
        server->retire_pending = 0;
        server->max_requests_cb_cv = NULL;
        server->retire_begin_cb_cv = NULL;
        /* Announce first: an empty drain finishes inside
         * feer_begin_graceful_shutdown and exits the process. */
        if (begin_cb) {
            dSP;
            ENTER;
            SAVETMPS;
            PUSHMARK(SP);
            PUTBACK;
            call_sv(begin_cb, G_DISCARD|G_VOID|G_EVAL|G_NOARGS);
            SPAGAIN;
            if (unlikely(SvTRUE(ERRSV))) {
                trouble("retirement callback died: %-p\n", ERRSV);
                sv_setsv(ERRSV, &PL_sv_undef);
            }
            PUTBACK;
            FREETMPS;
            LEAVE;
            SvREFCNT_dec(begin_cb);
        }
        if (cb) {
            feer_begin_graceful_shutdown(aTHX_ server, cb);
            SvREFCNT_dec(cb);
        }
    }
}

static void
idle_cb (EV_P_ ev_idle *w, int revents)
{
    struct feer_server *server = (struct feer_server *)w->data;

    trace("idle_cb called, revents=0x%08x\n", revents);
    if (unlikely(revents & EV_ERROR)) {
        trouble("EV error in idle, revents=0x%08x\n", revents);
        ev_break(EV_A, EVBREAK_ALL);
        return;
    }
    trace3("idle! head=%p\n", server->request_ready_rinq);
    if (server->request_ready_rinq)
        process_request_ready_rinq(server);
    ev_idle_stop(EV_A, w);
}

/*
 * A new request is starting: leave RECEIVE_WAIT and re-arm the slowloris
 * deadline.  The header timer is one-shot and the idle wait consumes it, so
 * without this the 2nd and later keepalive requests have no header deadline
 * (read_timeout cannot substitute, being reset by every byte).
 */
INLINE_UNLESS_DEBUG static void
begin_request_headers(struct feer_conn *c)
{
    if (c->receiving != RECEIVE_WAIT) return;
    change_receiving_state(c, RECEIVE_HEADERS);
    restart_header_timer(c);
}

/*
 * Emit one access-log line, if the server wants them and this connection has a
 * request pending a line.  Idempotent: the captured method/uri are released
 * here, so calling it again before the next dispatch does nothing.
 */
static void
feer_emit_access_log(pTHX_ struct feer_conn *c)
{
    if (likely(!c->log_method)) return;

    SV *method = c->log_method, *uri = c->log_uri;
    c->log_method = NULL;
    c->log_uri = NULL;

    SV *cb = c->server->access_log_cb_cv;
    if (likely(cb != NULL)) {
        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        EXTEND(SP, 3);
        PUSHs(sv_2mortal(method));
        PUSHs(sv_2mortal(uri ? uri : newSVpvs("")));
        PUSHs(sv_2mortal(newSVnv(ev_now(feersum_ev_loop) - c->req_start)));
        PUTBACK;
        call_sv(cb, G_DISCARD|G_VOID|G_EVAL);
        SPAGAIN;
        if (unlikely(SvTRUE(ERRSV))) {
            trouble("access_log callback died: %-p\n", ERRSV);
            sv_setsv(ERRSV, &PL_sv_undef);
        }
        PUTBACK;
        FREETMPS;
        LEAVE;
    }
    else {
        SvREFCNT_dec(method);
        SvREFCNT_dec(uri);
    }
}

/*
 * Shared keepalive-or-close logic for both plain and TLS write paths.
 * read_cb is try_conn_read (plain) or try_tls_conn_read (TLS).
 */
static void
handle_keepalive_or_close(struct feer_conn *c, conn_read_cb_t read_cb)
{
    stop_write_watcher(c);
    stop_write_timer(c);

    /* The response is fully flushed here - the point the access log means by
     * "request completed", and the point response_guard notably does not. */
    {
        dTHX;
        feer_emit_access_log(aTHX_ c);
    }

    /* Strip body bytes the app never read, or they parse as the next request.
     * rbuf holds the body (decoded in place if chunked) then any pipelined
     * data; consumed is what $input->read already sv_chop'd off the front. */
    if (c->is_keepalive && c->rbuf) {
        /* expected_cl is set by both Content-Length and chunked paths
         * (try_parse_chunked sets expected_cl = decoded body size). */
        ssize_t body_total = (c->expected_cl > 0) ? c->expected_cl : 0;
        if (body_total > 0) {
            ssize_t consumed = c->received_cl - (ssize_t)SvCUR(c->rbuf);
            ssize_t remaining = body_total - consumed;
            if (remaining > 0 && remaining <= (ssize_t)SvCUR(c->rbuf)) {
                sv_chop(c->rbuf, SvPVX(c->rbuf) + remaining);
                trace("drained body fd=%d stripped=%"Ssz_df" pipeline=%"Sz_uf"\n",
                    c->fd, (Ssz)remaining, (Sz)SvCUR(c->rbuf));
            }
        }
    }

    /* A connection still busy when the shutdown began missed the one-shot idle
     * sweep, and going back to keepalive-idle here meant nothing swept it
     * again: it held the drain open for a whole read_timeout after the app had
     * finished.  Both default to 5s, and Runner's graceful_timeout is 5s too,
     * so a worker that had genuinely finished got force-exited anyway. */
    if (c->is_keepalive && !c->server->shutting_down) {
        /* Defence in depth: never carry sendfile state into the next request
         * on this connection - leftover file bytes would be written into the
         * following response. */
        CLOSE_SENDFILE_FD(c);
        change_responding_state(c, RESPOND_NOT_STARTED);
        change_receiving_state(c, RECEIVE_WAIT);
        STRLEN pipelined = 0;
        if (c->rbuf) { pipelined = SvCUR(c->rbuf); }
        if (likely(c->req)) {
            if (likely(pipelined == 0) && c->req->buf && c->rbuf) {
                SV *tmp = c->rbuf;
                c->rbuf = c->req->buf;
                c->req->buf = NULL;
                /* A body drain / $input->read leaves SvPVX inside the malloc'd
                 * block via sv_chop; SvPV_renew below reallocs SvPVX directly,
                 * so the OOK offset has to go first.  No-op when clear. */
                SvOOK_off(c->rbuf);
                SvCUR_set(c->rbuf, 0);
                // Shrink oversized buffers from large bodies to avoid
                // holding max_body_len per keepalive connection
                if (SvLEN(c->rbuf) > READ_BUFSZ * 4)
                    SvPV_renew(c->rbuf, READ_BUFSZ + 1);
                SvREFCNT_dec(tmp);
            } else if (c->req->buf) {
                SvREFCNT_dec(c->req->buf);
                c->req->buf = NULL;
            }
            free_request(c);
        }
        // No is_http11 gate: this is already inside is_keepalive, and a 1.0
        // client that asked for keep-alive can pipeline exactly as 1.1 does.
        // Gating it here did not decline to serve the buffered request, it
        // just never parsed it - the bytes sat in rbuf until unrelated later
        // traffic woke the read watcher, or read_timeout killed them.
        if (unlikely(pipelined > 0)) {
            c->pipelined = pipelined;
            if (c->pipeline_depth <= MAX_PIPELINE_DEPTH) {
                c->pipeline_depth++;
                restart_header_timer(c);
                read_cb(feersum_ev_loop, &c->read_ev_io, 0);
                c->pipeline_depth--;
                /* try_tls_conn_read never arms a watcher itself (unlike
                 * try_conn_read, whose try_read_again path does), so when the
                 * pipelined bytes are only PART of the next request the rest
                 * never woke us: the request hung until read_timeout killed the
                 * connection.  Idempotent, so the plain path is unaffected. */
                if (c->fd >= 0 && c->receiving != RECEIVE_SHUTDOWN)
                    start_read_watcher(c);
                return;
            }
            trace("pipeline depth limit reached on %d\n", c->fd);
        } else {
            c->pipelined = 0;
        }
        start_read_watcher(c);
        /* New delivery episode: the drain sample belongs to the response just
         * finished and would lie about this one in both directions. */
        c->prev_read_outq = 0;
        restart_read_timer(c);
        restart_header_timer(c);
        feer_conn_set_idle(c);
    } else {
        /* feer_linger_close, not a bare safe_close_conn: the read watcher can
         * still be armed here (an app that set a reader poll_cb starts it and
         * nothing else stops it).  Closing the fd underneath a live watcher
         * leaves it registered - it keeps its reference on c->self, fires on
         * the torn-down connection, and the conn is never freed or recycled.
         * feer_linger_close stops all watchers before re-arming its own, and
         * falls back to feer_shutdown_conn for ineligible connections. */
        feer_linger_close(c, "close at write shutdown");
    }
}

static void
try_conn_write(EV_P_ struct ev_io *w, int revents)
{
    dCONN;
    unsigned i;
    struct iomatrix *m;

    SvREFCNT_inc_void_NN(c->self);

    // if it's marked writeable EV suggests we simply try write to it.
    // Otherwise it is stopped and we should ditch this connection.
    if (unlikely(revents & EV_ERROR && !(revents & EV_WRITE))) {
        trace("EV error on write, fd=%d revents=0x%08x\n", w->fd, revents);
        change_responding_state(c, RESPOND_SHUTDOWN);
        goto try_write_finished;
    }

    if (unlikely(!c->wbuf_rinq)) {
#ifdef __linux__
        // Check for sendfile pending (headers already sent).  This MUST come
        // before the RESPOND_SHUTDOWN early-out: close()ing the writer (which
        // the documented sendfile pattern does, and which also happens when
        // the writer is garbage collected) sets RESPOND_SHUTDOWN while the
        // transfer is still in progress.  Bailing out here would silently
        // truncate every file larger than the socket send buffer.
        if (c->sendfile_fd >= 0)
            goto try_sendfile;
#endif

        if (unlikely(c->responding >= RESPOND_SHUTDOWN))
            goto try_write_finished;

        if (!c->poll_write_cb) {
            // no callback and no data: wait for app to push to us.
            if (c->responding == RESPOND_STREAMING)
                goto try_write_paused;

            trace("tried to write with an empty buffer %d resp=%d\n",w->fd,c->responding);
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto try_write_finished;
        }

        unsigned int writes_before = c->poll_writes_seen;
        if (c->poll_write_cb_is_io_handle)
            pump_io_handle(c);
        else
            call_poll_callback(c, 1);

        // callback didn't write anything:
        if (unlikely(!c->wbuf_rinq)) {
            /* The read watcher was stopped when the request completed and
             * writev never runs on an empty buffer, so nothing else ever
             * notices the peer has gone - before this check the loop below
             * kept running at full rate on a closed connection, forever. */
            if (unlikely(peer_is_gone(c))) {
                trace("poll_cb produced nothing and the peer is gone %d\n", w->fd);
                change_responding_state(c, RESPOND_SHUTDOWN);
                goto try_write_finished;
            }
            /* Pure decline: the callback made no write call at all.  The
             * drain invitation was delivered, so park and pace instead of
             * spinning the level-triggered watcher (see the park helper).
             * An empty write() counts as engagement and stays hot - the same
             * distinction the H2 pump draws with writes_seen. */
            if (c->responding == RESPOND_STREAMING && c->poll_write_cb
                && c->poll_writes_seen == writes_before) {
                feersum_poll_retry_park(c);
                goto try_write_cleanup;
            }
            goto try_write_again;
        }
    }
    // Low-water-mark: buffer not empty but below threshold - refill before writing
    else if (c->cached_wbuf_low_water > 0
             && c->wbuf_len <= c->cached_wbuf_low_water
             && c->responding == RESPOND_STREAMING && c->poll_write_cb) {
        if (c->poll_write_cb_is_io_handle)
            pump_io_handle(c);
        else
            call_poll_callback(c, 1);

        // The callback can drain the ring (a nested event loop re-enters
        // try_conn_write), so guard like the empty-buffer branch above does.
        if (unlikely(!c->wbuf_rinq)) goto try_write_again;
    }

try_write_again_immediately:
#if defined(__linux__) && defined(FEERSUM_TCP_CORK)
    // Cork socket when writing headers before sendfile for optimal packet framing
    if (c->sendfile_fd >= 0)
        set_cork(c, 1);
#endif
    m = (struct iomatrix *)c->wbuf_rinq->ref;

    /* Skip zero-length iovecs, as the TLS twin already does.  Alone in a batch
     * they make write()/writev() return 0, which the check below reads as a
     * fatal error and truncates the response mid-body - and under keepalive the
     * connection is then reused, so the client reads the next response as this
     * body.  An empty $w->write() or a placeholder left unfilled by a croak
     * produces one. */
    while (m->offset < m->count && m->iov[m->offset].iov_len == 0) {
        if (m->sv[m->offset]) {
            SvREFCNT_dec(m->sv[m->offset]);
            m->sv[m->offset] = NULL;
        }
        m->offset++;
    }
    if (unlikely(m->offset >= m->count)) {
        rinq_shift(&c->wbuf_rinq);
        IOMATRIX_FREE(m);
        if (!c->wbuf_rinq) {
#ifdef __linux__
            if (c->sendfile_fd >= 0)
                goto try_sendfile;
#endif
            goto try_write_finished;
        }
        goto try_write_again_immediately;
    }
#if DEBUG >= 2
    warn("going to write to %d:\n",c->fd);
    for (i=0; i < m->count; i++) {
        fprintf(stderr,"%.*s",
            (int)m->iov[i].iov_len, (char*)m->iov[i].iov_base);
    }
#endif

    trace("going to write %d off=%d count=%d\n", w->fd, m->offset, m->count);
    errno = 0;
    int iov_count = m->count - m->offset;
#ifdef IOV_MAX
    if (iov_count > IOV_MAX) iov_count = IOV_MAX;
#endif
    ssize_t wrote;
    if (iov_count == 1) {
        // Single element: write() is slightly faster than writev()
        wrote = write(w->fd, m->iov[m->offset].iov_base, m->iov[m->offset].iov_len);
    } else {
        wrote = writev(w->fd, &m->iov[m->offset], iov_count);
    }
    trace("wrote %"Ssz_df" bytes to %d, errno=%d\n", (Ssz)wrote, w->fd, errno);

    if (unlikely(wrote <= 0)) {
        if (likely(errno == EAGAIN || errno == EINTR))
            goto try_write_again;
        /* Same as the read side: a peer that hung up is normal traffic, so it
         * must not warn on every occurrence. */
        if (errno == ECONNRESET || errno == EPIPE)
            trace("try_conn_write fd=%d: %s\n", w->fd, strerror(errno));
        else
            trouble("try_conn_write fd=%d: %s\n", w->fd, strerror(errno));
        CLOSE_SENDFILE_FD(c);
        set_cork(c, 0);
        stop_write_timer(c);
        change_responding_state(c, RESPOND_SHUTDOWN);
        goto try_write_finished;
    }

    c->wbuf_len -= wrote;
    restart_write_timer(c);

    bool consume = 1;
    for (i = m->offset; i < m->count && consume; i++) {
        struct iovec *v = &m->iov[i];
        if (unlikely(v->iov_len > wrote)) {
            trace3("offset vector %d  base=%p len=%"Sz_uf"\n",
                w->fd, v->iov_base, (Sz)v->iov_len);
            v->iov_base = (char*)v->iov_base + wrote;
            v->iov_len  -= wrote;
            // don't consume any more:
            consume = 0;
        }
        else {
            trace3("consume vector %d base=%p len=%"Sz_uf" sv=%p\n",
                w->fd, v->iov_base, (Sz)v->iov_len, m->sv[i]);
            wrote -= v->iov_len;
            m->offset++;
            if (m->sv[i]) {
                SvREFCNT_dec(m->sv[i]);
                m->sv[i] = NULL;
            }
        }
    }

    if (likely(m->offset >= m->count)) {
        trace2("all done with iomatrix %d state=%d\n",w->fd,c->responding);
        rinq_shift(&c->wbuf_rinq);
        IOMATRIX_FREE(m);
        if (!c->wbuf_rinq) {
#ifdef __linux__
            // sendfile pending? do zero-copy file transfer
            if (c->sendfile_fd >= 0)
                goto try_sendfile;
#endif
            goto try_write_finished;
        }
        // Low-water-mark: yield to event loop so poll_cb can fire
        if (c->cached_wbuf_low_water > 0
            && c->wbuf_len <= c->cached_wbuf_low_water
            && c->responding == RESPOND_STREAMING && c->poll_write_cb) {
            goto try_write_again;
        }
        trace2("write again immediately %d state=%d\n",w->fd,c->responding);
        goto try_write_again_immediately;
    }
    // else, fallthrough:
    trace2("write fallthrough %d state=%d\n",w->fd,c->responding);
    goto try_write_again;

#ifdef __linux__
try_sendfile:
    {
        trace("sendfile %d: fd=%d off=%ld remain=%zu\n",
            w->fd, c->sendfile_fd, (long)c->sendfile_off, c->sendfile_remain);
        ssize_t sent = sendfile(w->fd, c->sendfile_fd,
                                &c->sendfile_off, c->sendfile_remain);
        if (sent > 0) {
            c->sendfile_remain -= sent;
            trace("sendfile sent %zd, remain=%zu\n", sent, c->sendfile_remain);
            if (c->sendfile_remain == 0) {
                CLOSE_SENDFILE_FD(c);
                set_cork(c, 0);
                change_responding_state(c, RESPOND_SHUTDOWN);
                goto try_write_finished;
            }
            // Progress: push the deadline out, as writev and TLS-flush do.  A
            // sendfile sits in RESPOND_SHUTDOWN for its whole duration, so
            // without this write_timeout reaps it mid-file.
            restart_write_timer(c);
            // More to send, wait for socket to be writable again
            goto try_write_again;
        }
        else if (sent == 0) {
            // EOF on file (shouldn't happen if sendfile_remain was correct)
            CLOSE_SENDFILE_FD(c);
            set_cork(c, 0);
            if (c->responding == RESPOND_STREAMING) {
                change_responding_state(c, RESPOND_SHUTDOWN);
            }
            goto try_write_finished;
        }
        else {
            // sent < 0, error
            if (errno == EAGAIN || errno == EINTR) {
                // Socket not ready, wait
                goto try_write_again;
            }
            // Real error
            trouble("sendfile fd=%d: %s\n", c->fd, strerror(errno));
            CLOSE_SENDFILE_FD(c);
            set_cork(c, 0);
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto try_write_finished;
        }
    }
#endif

try_write_again:
    trace("write again %d state=%d\n",w->fd,c->responding);
    start_write_watcher(c);
    /* Arm the write deadline whenever we are blocked on writability, not only
     * after a successful write: a response driven by the app's own events
     * (rather than a poll_cb) otherwise gets no write_timeout coverage at all
     * once the peer stops reading.  No-op when write_timeout is 0. */
    ensure_write_timer(c);
    goto try_write_cleanup;

try_write_finished:
    // should always be responding, but just in case
    switch(c->responding) {
    case RESPOND_NOT_STARTED:
        // the write watcher shouldn't ever get called before starting to
        // respond. Shut it down if it does.
        trace("unexpected try_write when response not started %d\n",c->fd);
        goto try_write_shutdown;
    case RESPOND_NORMAL:
        goto try_write_shutdown;
    case RESPOND_STREAMING:
        if (c->poll_write_cb) goto try_write_again;
        else goto try_write_paused;
    case RESPOND_SHUTDOWN:
        goto try_write_shutdown;
    default:
        goto try_write_cleanup;
    }

try_write_paused:
    trace3("write PAUSED %d, refcnt=%d, state=%d\n", c->fd, SvREFCNT(c->self), c->responding);
    stop_write_watcher(c);
    stop_write_timer(c);
    goto try_write_cleanup;

try_write_shutdown:
    handle_keepalive_or_close(c, try_conn_read);

try_write_cleanup:
    SvREFCNT_dec(c->self);
    return;
}

// Parse PROXY protocol v1 text header
// Format: "PROXY TCP4|TCP6|UNKNOWN src_addr dst_addr src_port dst_port\r\n"
// Returns: bytes consumed on success, -1 on error, -2 if need more data
static int
parse_proxy_v1(struct feer_conn *c)
{
    char *buf = SvPVX(c->rbuf);
    STRLEN len = SvCUR(c->rbuf);

    // Need at least "PROXY \r\n" (minimum valid line)
    if (len < 8)
        return -2;  // need more data

    // Verify prefix
    if (memcmp(buf, PROXY_V1_PREFIX, PROXY_V1_PREFIX_LEN) != 0)
        return -1;  // invalid

    // Find CRLF (max 108 bytes total)
    char *crlf = NULL;
    STRLEN search_len = len > PROXY_V1_MAX_LINE ? PROXY_V1_MAX_LINE : len;
    for (STRLEN i = PROXY_V1_PREFIX_LEN; i < search_len - 1; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n') {
            crlf = buf + i;
            break;
        }
        // The v1 line is CRLF-terminated.  Accepting a bare LF let the scan
        // run on to the next CRLF, which swallowed the following request line
        // into the header and framed the connection differently from the
        // sender.
        if (buf[i] == '\n')
            return -1;
    }

    if (!crlf) {
        if (len >= PROXY_V1_MAX_LINE)
            return -1;  // line too long, invalid
        return -2;  // need more data
    }

    size_t header_len = (crlf - buf) + 2;  // include CRLF

    // Null-terminate the line for parsing (temporarily)
    char saved = *crlf;
    *crlf = '\0';

    // Parse protocol family: TCP4, TCP6, or UNKNOWN
    char *p = buf + PROXY_V1_PREFIX_LEN;

    if (strncmp(p, "UNKNOWN", 7) == 0 && (p[7] == '\0' || p[7] == ' ')) {
        // UNKNOWN - keep original address (used for health checks)
        *crlf = saved;
        c->proxy_proto_version = 1;
        trace("PROXY v1 UNKNOWN, keeping original address\n");
        return (int)header_len;
    }

    int is_ipv6 = 0;
    if (strncmp(p, "TCP4 ", 5) == 0) {
        p += 5;
    } else if (strncmp(p, "TCP6 ", 5) == 0) {
        p += 5;
        is_ipv6 = 1;
    } else {
        *crlf = saved;
        return -1;  // unknown protocol
    }

    // Parse: src_addr dst_addr src_port dst_port
    char src_addr[46], dst_addr[46];  // max IPv6 length
    long long src_port, dst_port;

    // Use sscanf to parse the addresses and ports.  The %18lld field width
    // bounds each conversion so oversized port digits cannot overflow the
    // destination type (out-of-range numeric conversion is C UB); anything
    // outside 0-65535 is rejected by the range check below.
    if (sscanf(p, "%45s %45s %18lld %18lld", src_addr, dst_addr, &src_port, &dst_port) != 4) {
        *crlf = saved;
        return -1;  // parse error
    }

    // Validate port ranges
    if (src_port < 0 || src_port > 65535 || dst_port < 0 || dst_port > 65535) {
        *crlf = saved;
        return -1;
    }

    *crlf = saved;  // restore

    // Update connection's source address
    if (is_ipv6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&c->sa;
        sa6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, src_addr, &sa6->sin6_addr) != 1) {
            return -1;  // invalid address
        }
        sa6->sin6_port = htons((uint16_t)src_port);
    } else {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&c->sa;
        sa4->sin_family = AF_INET;
        if (inet_pton(AF_INET, src_addr, &sa4->sin_addr) != 1) {
            return -1;  // invalid address
        }
        sa4->sin_port = htons((uint16_t)src_port);
    }

    c->proxy_proto_version = 1;
    c->proxy_dst_port = (uint16_t)dst_port;
    trace("PROXY v1 %s src=%s:%lld dst_port=%lld\n", is_ipv6 ? "TCP6" : "TCP4", src_addr, src_port, dst_port);
    return (int)header_len;
}

// Parse PROXY protocol v2 binary header
// Returns: bytes consumed on success, -1 on error, -2 if need more data
static int
parse_proxy_v2(struct feer_conn *c)
{
    unsigned char *buf = (unsigned char *)SvPVX(c->rbuf);
    STRLEN len = SvCUR(c->rbuf);

    // Need at least minimum header (16 bytes)
    if (len < PROXY_V2_HDR_MIN)
        return -2;

    // Verify signature
    if (memcmp(buf, PROXY_V2_SIG, PROXY_V2_SIG_LEN) != 0)
        return -1;

    // Parse version and command (byte 12)
    unsigned char ver_cmd = buf[12];
    unsigned char version = ver_cmd & 0xF0;
    unsigned char command = ver_cmd & 0x0F;

    if (version != PROXY_V2_VERSION)
        return -1;  // unsupported version

    // Parse family and protocol (byte 13)
    unsigned char fam_proto = buf[13];
    unsigned char family = fam_proto & 0xF0;

    // Parse address length (bytes 14-15, big-endian)
    uint16_t addr_len = (buf[14] << 8) | buf[15];
    if (unlikely(addr_len > 4096)) { /* spec allows 65535, cap for sanity */
        /* trace, not trouble: 16 attacker-chosen bytes produce one stderr line,
         * so warn()ing here is a log-flood tap for an unauthenticated peer.
         * Every other rejection in this parser is silent. */
        trace("PROXY v2 addr_len too large: %u\n", addr_len);
        return -1;
    }

    // Total header length
    size_t total_len = PROXY_V2_HDR_MIN + addr_len;
    if (len < total_len)
        return -2;  // need more data

    // Handle command
    if (command == PROXY_V2_CMD_LOCAL) {
        // LOCAL command - keep original address (health checks, etc.)
        c->proxy_proto_version = 2;
        trace("PROXY v2 LOCAL, keeping original address\n");
        return (int)total_len;
    }

    if (command != PROXY_V2_CMD_PROXY) {
        return -1;  // unknown command
    }

    // PROXY command - update source address
    unsigned char *addr_data = buf + PROXY_V2_HDR_MIN;

    if (family == PROXY_V2_FAM_INET) {
        // IPv4 - need 12 bytes: src_addr(4) + dst_addr(4) + src_port(2) + dst_port(2)
        if (addr_len < PROXY_V2_ADDR_V4_LEN)
            return -1;

        struct sockaddr_in *sa4 = (struct sockaddr_in *)&c->sa;
        sa4->sin_family = AF_INET;
        memcpy(&sa4->sin_addr, addr_data, 4);      // src addr
        memcpy(&sa4->sin_port, addr_data + 8, 2);  // src port (already network order)

        // Extract dst_port for scheme inference (offset 10, network byte order)
        uint16_t dst_port_n;
        memcpy(&dst_port_n, addr_data + 10, 2);
        c->proxy_dst_port = ntohs(dst_port_n);

        trace("PROXY v2 TCP4 src=%d.%d.%d.%d:%d dst_port=%d\n",
              addr_data[0], addr_data[1], addr_data[2], addr_data[3],
              ntohs(sa4->sin_port), c->proxy_dst_port);
    } else if (family == PROXY_V2_FAM_INET6) {
        // IPv6 - need 36 bytes: src_addr(16) + dst_addr(16) + src_port(2) + dst_port(2)
        if (addr_len < PROXY_V2_ADDR_V6_LEN)
            return -1;

        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&c->sa;
        sa6->sin6_family = AF_INET6;
        memcpy(&sa6->sin6_addr, addr_data, 16);      // src addr
        memcpy(&sa6->sin6_port, addr_data + 32, 2);  // src port (already network order)

        // Extract dst_port for scheme inference (offset 34, network byte order)
        uint16_t dst_port_n;
        memcpy(&dst_port_n, addr_data + 34, 2);
        c->proxy_dst_port = ntohs(dst_port_n);

        trace("PROXY v2 TCP6 port=%d dst_port=%d\n", ntohs(sa6->sin6_port), c->proxy_dst_port);
    } else if (family == PROXY_V2_FAM_UNSPEC) {
        // Unspecified - keep original address
        trace("PROXY v2 UNSPEC, keeping original address\n");
    } else if (family == PROXY_V2_FAM_UNIX) {
        // AF_UNIX - address is 2x108-byte paths, not meaningful as an HTTP
        // REMOTE_ADDR, so keep the original address (like UNSPEC). Per PROXY
        // protocol spec section 2.2; HAProxy/nginx unix-socket frontends emit it.
        // The spec mandates a 216-byte address block; reject short ones
        // (consistent with the INET/INET6 minimum-length checks above).
        if (addr_len < PROXY_V2_ADDR_UNIX_LEN)
            return -1;
        trace("PROXY v2 UNIX, keeping original address\n");
    } else {
        return -1;  // unsupported family
    }

    // Parse TLVs if present
    size_t addr_size = 0;
    if (family == PROXY_V2_FAM_INET) addr_size = PROXY_V2_ADDR_V4_LEN;
    else if (family == PROXY_V2_FAM_INET6) addr_size = PROXY_V2_ADDR_V6_LEN;
    else if (family == PROXY_V2_FAM_UNIX) addr_size = PROXY_V2_ADDR_UNIX_LEN;

    if (addr_len > addr_size) {
        dTHX; /* Perl API calls below (newHV, newSVpvn, hv_store, etc.) */
        // TLVs are present
        unsigned char *tlv_start = addr_data + addr_size;
        size_t tlv_remaining = addr_len - addr_size;

        // Create hash for TLVs
        HV *tlv_hv = newHV();
        unsigned int tlv_count = 0;

        while (tlv_remaining >= 3) {  // minimum TLV: 1 type + 2 length
            // Bound iteration: a malicious sender can pack ~1365 zero-length
            // TLVs into a 4096-byte payload. 64 covers all real-world headers.
            if (++tlv_count > 64) {
                trace("PROXY v2 too many TLVs (>64), rejecting\n");
                SvREFCNT_dec((SV *)tlv_hv);
                return -1;
            }
            unsigned char tlv_type = tlv_start[0];
            uint16_t tlv_len = (tlv_start[1] << 8) | tlv_start[2];

            if (tlv_remaining < 3 + (size_t)tlv_len) {
                // Malformed TLV - reject the whole PROXY header per spec
                trace("PROXY v2 malformed TLV: need %u bytes, have %zu\n",
                      tlv_len, tlv_remaining - 3);
                SvREFCNT_dec((SV *)tlv_hv);
                return -1;
            }

            // struct pp2_tlv_ssl { uint8_t client; uint32_t verify; } - only
            // the PP2_CLIENT_SSL bit means the client hop was TLS.  Treating
            // the TLV's presence as proof told the app a cleartext hop was
            // secure (haproxy emits it bit-clear to carry verify/CN).
            if (tlv_type == PP2_TYPE_SSL && tlv_len >= 5
                && (tlv_start[3] & PP2_CLIENT_SSL)) {
                c->proxy_ssl = 1;
                trace("PROXY v2 TLV PP2_TYPE_SSL, client bit set\n");
            }

            // Store TLV value (skip NOOP type)
            if (tlv_type != PP2_TYPE_NOOP) {
                SV *val = newSVpvn((char *)(tlv_start + 3), tlv_len);
                char key[8];
                int key_len = snprintf(key, sizeof(key), "%u", tlv_type);
                hv_store(tlv_hv, key, key_len, val, 0);
                trace("PROXY v2 TLV type=%u len=%u\n", tlv_type, tlv_len);
            }

            tlv_start += 3 + (size_t)tlv_len;
            tlv_remaining -= 3 + (size_t)tlv_len;
        }

        /* A 1-2 byte tail is too short to be a TLV header, so it is the same
         * malformation a length-overclaiming TLV is, and gets the same answer.
         * The spec pads with PP2_TYPE_NOOP, never with a bare remainder. */
        if (unlikely(tlv_remaining)) {
            trace("PROXY v2 trailing %zu bytes after TLVs, rejecting\n",
                  tlv_remaining);
            SvREFCNT_dec((SV *)tlv_hv);
            return -1;
        }

        // Store hash in connection if non-empty
        if (HvKEYS(tlv_hv) > 0) {
            c->proxy_tlvs = newRV_noinc((SV *)tlv_hv);
        } else {
            SvREFCNT_dec((SV *)tlv_hv);
        }
    }

    c->proxy_proto_version = 2;
    return (int)total_len;
}

// Try to parse PROXY protocol header (auto-detect v1 or v2)
// Returns: bytes consumed on success, -1 on error, -2 if need more data
static int
try_parse_proxy_header(struct feer_conn *c)
{
    if (SvCUR(c->rbuf) == 0)
        return -2;  // need data

    unsigned char first = ((unsigned char *)SvPVX(c->rbuf))[0];

    if (first == 'P') {
        return parse_proxy_v1(c);
    } else if (first == 0x0D) {
        return parse_proxy_v2(c);
    } else {
        return -1;  // neither v1 nor v2
    }
}

