
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

INLINE_UNLESS_DEBUG
static STRLEN
add_sv_to_wbuf(struct feer_conn *c, SV *sv)
{
    struct iomatrix *m = next_iomatrix(c);
    unsigned idx = m->count++;
    STRLEN cur;
    if (unlikely(SvMAGICAL(sv))) {
        sv = newSVsv(sv); // copy to force it to be normal.
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
        case 425: return "Unordered Collection"; // RFC 3648
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
    if (100 <= code && code <= 199) {
        return "Informational";
    }
    else if (200 <= code && code <= 299) {
        return "Success";
    }
    else if (300 <= code && code <= 399) {
        return "Redirection";
    }
    else if (400 <= code && code <= 499) {
        return "Client Error";
    }
    else {
        return "Error";
    }
}

static int
prep_socket(int fd, int is_tcp)
{
#ifdef HAS_ACCEPT4
    int flags = 1;
#else
    int flags;

    // make it non-blocking (preserve existing flags)
    flags = fcntl(fd, F_GETFL);
    if (unlikely(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0))
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
safe_close_conn(struct feer_conn *c, const char *where)
{
    if (unlikely(c->fd < 0))
        return;

#ifdef FEERSUM_HAS_H2
    if (c->is_h2_stream) {
        /* Pseudo-conns share parent's fd — do NOT close or shutdown it.
         * The parent connection owns the fd and will close it. */
        c->fd = -1;
        return;
    }
#endif

    CLOSE_SENDFILE_FD(c);

#ifdef FEERSUM_HAS_TLS
    // Best-effort TLS close_notify before TCP shutdown
    if (c->tls && c->tls_handshake_done) {
        ptls_buffer_t closebuf;
        ptls_buffer_init(&closebuf, "", 0);
        ptls_send_alert(c->tls, &closebuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY);
        if (closebuf.off > 0) {
            // Best-effort write, ignore errors
            ssize_t __attribute__((unused)) wr = write(c->fd, closebuf.base, closebuf.off);
        }
        ptls_buffer_dispose(&closebuf);
    }
#endif

    // Graceful TCP shutdown: send FIN to peer before close
    // This ensures client sees clean EOF instead of RST
    shutdown(c->fd, SHUT_WR);

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
    c->cached_request_cb_is_psgi = srvr->request_cb_is_psgi;
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
    } else {
#endif
        ev_io_init(&c->read_ev_io, try_conn_read, conn_fd, EV_READ);
        ev_io_init(&c->write_ev_io, try_conn_write, conn_fd, EV_WRITE);
#ifdef FEERSUM_HAS_TLS
    }
#endif
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

    if (FEERSUM_CONN_NEW_ENABLED()) {
        feersum_set_conn_remote_info(aTHX_ c);
        FEERSUM_CONN_NEW(c->fd, SvPV_nolen(c->remote_addr), (int)SvIV(c->remote_port));
    }

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
    return sv;
}

static void
init_feer_server (struct feer_server *s)
{
    int i;
    Zero(s, 1, struct feer_server);
    s->read_timeout = READ_TIMEOUT;
    s->header_timeout = HEADER_TIMEOUT;
    s->write_timeout = WRITE_TIMEOUT;
    s->max_accept_per_loop = DEFAULT_MAX_ACCEPT_PER_LOOP;
    s->max_connections = 10000;
    s->max_read_buf = MAX_READ_BUF;
    s->max_body_len = MAX_BODY_LEN;
    s->max_uri_len = MAX_URI_LEN;
    for (i = 0; i < FEER_MAX_LISTENERS; i++) {
        s->listeners[i].fd = -1;
        s->listeners[i].server = s;
#ifdef __linux__
        s->listeners[i].epoll_fd = -1;
#endif
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

INLINE_UNLESS_DEBUG static void
restart_read_timer(struct feer_conn *c) {
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
    if (c->cached_write_timeout <= 0.0) return;
    if (likely(!ev_is_active(&c->write_ev_timer))) {
        trace("restart write timer %d\n",c->fd);
        c->write_ev_timer.repeat = c->cached_write_timeout;
        SvREFCNT_inc_void_NN(c->self);
    }
    ev_timer_again(feersum_ev_loop, &c->write_ev_timer);
}

INLINE_UNLESS_DEBUG static void
stop_write_timer(struct feer_conn *c) {
    if (unlikely(!ev_is_active(&c->write_ev_timer)))
        return;
    trace("stop write timer %d\n",c->fd);
    ev_timer_stop(feersum_ev_loop, &c->write_ev_timer);
    SvREFCNT_dec(c->self);
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

    struct rinq *node;
    RINQ_NEW(node, c);

    struct rinq **head = &c->server->idle_keepalive_rinq;
    if (*head == NULL) {
        *head = node;
    } else {
        node->next = *head;
        node->prev = (*head)->prev;
        node->next->prev = node->prev->next = node;
    }
    c->idle_rinq_node = node;
    trace("conn fd=%d is now idle (added to LRU)\n", c->fd);
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
    // refcount to 0 → DESTROY fires before safe_close_conn.
    SvREFCNT_inc_void_NN(c->self);
    stop_all_watchers(c);
    safe_close_conn(c, "recycled for new connection");
    change_responding_state(c, RESPOND_SHUTDOWN);
    SvREFCNT_dec(c->self);

    // active_conns will be decremented in DESTROY when refcount drops.
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
            struct feer_h2_stream *stream =
                (struct feer_h2_stream *)c->read_ev_timer.data;
            if (stream && stream->parent) {
                struct feer_conn *parent = stream->parent;
                SvREFCNT_inc_void_NN(parent->self);
                feer_h2_session_send(parent);
                h2_check_stream_poll_cbs(aTHX_ parent);
                SvREFCNT_dec(parent->self);
            }
        }
#endif
        SvREFCNT_dec(c->self); // for the rinq
    }
}

static void
prepare_cb (EV_P_ ev_prepare *w, int revents)
{
    struct feer_server *srvr = (struct feer_server *)w->data;
    int i;

    if (unlikely(revents & EV_ERROR)) {
        trouble("EV error in prepare, revents=0x%08x\n", revents);
        ev_break(EV_A, EVBREAK_ALL);
        return;
    }

    if (!srvr->shutting_down) {
        for (i = 0; i < srvr->n_listeners; i++) {
            struct feer_listen *lsnr = &srvr->listeners[i];
            if (!ev_is_active(&lsnr->accept_w)) {
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
 * Shared keepalive-or-close logic for both plain and TLS write paths.
 * read_cb is try_conn_read (plain) or try_tls_conn_read (TLS).
 */
static void
handle_keepalive_or_close(struct feer_conn *c, conn_read_cb_t read_cb)
{
    stop_write_watcher(c);
    stop_write_timer(c);

    /* If request had a Content-Length body and the app didn't consume it all,
     * rbuf contains unread body bytes mixed with any pipelined data.
     * Force-close to prevent pipeline desync (body bytes parsed as HTTP). */
    if (c->is_keepalive && c->expected_cl > 0 && c->rbuf) {
        ssize_t consumed = c->received_cl - (ssize_t)SvCUR(c->rbuf);
        if (consumed < c->expected_cl) {
            trace("body not consumed fd=%d consumed=%"Ssz_df" expected=%"Ssz_df"\n",
                c->fd, (Ssz)consumed, (Ssz)c->expected_cl);
            c->is_keepalive = 0;
        }
    }

    if (c->is_keepalive) {
        change_responding_state(c, RESPOND_NOT_STARTED);
        change_receiving_state(c, RECEIVE_WAIT);
        STRLEN pipelined = 0;
        if (c->rbuf) { pipelined = SvCUR(c->rbuf); }
        if (likely(c->req)) {
            if (likely(pipelined == 0) && c->req->buf && c->rbuf) {
                SV *tmp = c->rbuf;
                c->rbuf = c->req->buf;
                c->req->buf = NULL;
                SvCUR_set(c->rbuf, 0);
                SvREFCNT_dec(tmp);
            } else if (c->req->buf) {
                SvREFCNT_dec(c->req->buf);
                c->req->buf = NULL;
            }
            free_request(c);
        }
        if (unlikely(pipelined > 0 && c->is_http11)) {
            c->pipelined = pipelined;
            if (c->pipeline_depth <= MAX_PIPELINE_DEPTH) {
                c->pipeline_depth++;
                restart_header_timer(c);
                read_cb(feersum_ev_loop, &c->read_ev_io, 0);
                c->pipeline_depth--;
            } else {
                trace("pipeline depth limit reached on %d\n", c->fd);
                start_read_watcher(c);
                restart_read_timer(c);
                restart_header_timer(c);
                feer_conn_set_idle(c);
            }
        } else {
            c->pipelined = 0;
            start_read_watcher(c);
            restart_read_timer(c);
            restart_header_timer(c);
            feer_conn_set_idle(c);
        }
    } else {
        if (c->responding != RESPOND_SHUTDOWN)
            change_responding_state(c, RESPOND_SHUTDOWN);
        safe_close_conn(c, "close at write shutdown");
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
        if (unlikely(c->responding >= RESPOND_SHUTDOWN))
            goto try_write_finished;

#ifdef __linux__
        // Check for sendfile pending (headers already sent)
        if (c->sendfile_fd >= 0)
            goto try_sendfile;
#endif

        if (!c->poll_write_cb) {
            // no callback and no data: wait for app to push to us.
            if (c->responding == RESPOND_STREAMING)
                goto try_write_paused;

            trace("tried to write with an empty buffer %d resp=%d\n",w->fd,c->responding);
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto try_write_finished;
        }

        if (c->poll_write_cb_is_io_handle)
            pump_io_handle(c, c->poll_write_cb);
        else
            call_poll_callback(c, 1);

        // callback didn't write anything:
        if (unlikely(!c->wbuf_rinq)) goto try_write_again;
    }
    // Low-water-mark: buffer not empty but below threshold — refill before writing
    else if (c->cached_wbuf_low_water > 0
             && c->wbuf_len <= c->cached_wbuf_low_water
             && c->responding == RESPOND_STREAMING && c->poll_write_cb) {
        if (c->poll_write_cb_is_io_handle)
            pump_io_handle(c, c->poll_write_cb);
        else
            call_poll_callback(c, 1);
    }

try_write_again_immediately:
#if defined(__linux__) && defined(FEERSUM_TCP_CORK)
    // Cork socket when writing headers before sendfile for optimal packet framing
    if (c->sendfile_fd >= 0)
        set_cork(c, 1);
#endif
    m = (struct iomatrix *)c->wbuf_rinq->ref;
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
        trouble("try_conn_write fd=%d: %s\n", w->fd, strerror(errno));
        CLOSE_SENDFILE_FD(c);
#ifdef FEERSUM_TCP_CORK
        set_cork(c, 0);  // uncork before shutdown (may have been corked for sendfile)
#endif
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
#ifdef FEERSUM_TCP_CORK
                set_cork(c, 0);  // uncork to flush
#endif
                change_responding_state(c, RESPOND_SHUTDOWN);
                goto try_write_finished;
            }
            // More to send, wait for socket to be writable again
            goto try_write_again;
        }
        else if (sent == 0) {
            // EOF on file (shouldn't happen if sendfile_remain was correct)
            CLOSE_SENDFILE_FD(c);
#ifdef FEERSUM_TCP_CORK
            set_cork(c, 0);  // uncork to flush
#endif
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
#ifdef FEERSUM_TCP_CORK
            set_cork(c, 0);  // uncork before shutdown
#endif
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto try_write_finished;
        }
    }
#endif

try_write_again:
    trace("write again %d state=%d\n",w->fd,c->responding);
    start_write_watcher(c);
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
    STRLEN i;
    for (i = PROXY_V1_PREFIX_LEN; i < search_len - 1; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n') {
            crlf = buf + i;
            break;
        }
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

    if (strncmp(p, "UNKNOWN", 7) == 0) {
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
    int src_port, dst_port;

    // Use sscanf to parse the addresses and ports
    if (sscanf(p, "%45s %45s %5d %5d", src_addr, dst_addr, &src_port, &dst_port) != 4) {
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
    trace("PROXY v1 %s src=%s:%d dst_port=%d\n", is_ipv6 ? "TCP6" : "TCP4", src_addr, src_port, dst_port);
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
    if (unlikely(addr_len > 1024)) {
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
    } else {
        return -1;  // unsupported family
    }

    // Parse TLVs if present
    size_t addr_size = 0;
    if (family == PROXY_V2_FAM_INET) addr_size = PROXY_V2_ADDR_V4_LEN;
    else if (family == PROXY_V2_FAM_INET6) addr_size = PROXY_V2_ADDR_V6_LEN;

    if (addr_len > addr_size) {
        dTHX; /* Perl API calls below (newHV, newSVpvn, hv_store, etc.) */
        // TLVs are present
        unsigned char *tlv_start = addr_data + addr_size;
        size_t tlv_remaining = addr_len - addr_size;

        // Create hash for TLVs
        HV *tlv_hv = newHV();

        while (tlv_remaining >= 3) {  // minimum TLV: 1 type + 2 length
            unsigned char tlv_type = tlv_start[0];
            uint16_t tlv_len = (tlv_start[1] << 8) | tlv_start[2];

            if (tlv_remaining < 3 + (size_t)tlv_len) {
                // Malformed TLV - reject the whole PROXY header per spec
                trace("PROXY v2 malformed TLV: need %u bytes, have %zu\n",
                      tlv_len, tlv_remaining - 3);
                SvREFCNT_dec((SV *)tlv_hv);
                return -1;
            }

            // Check for SSL TLV (indicates connection was over SSL/TLS)
            // PP2_TYPE_SSL requires minimum 5 bytes (client flags + verify)
            if (tlv_type == PP2_TYPE_SSL && tlv_len >= 5) {
                c->proxy_ssl = 1;
                trace("PROXY v2 TLV PP2_TYPE_SSL detected\n");
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

