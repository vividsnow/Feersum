/*
 * feersum_h2.c.inc - HTTP/2 support via nghttp2 for Feersum
 *
 * This file is #included into Feersum.xs when FEERSUM_HAS_H2 is defined.
 * It provides nghttp2 session management, stream-to-request mapping,
 * and an H2-specific response path.
 *
 * Each H2 stream creates a pseudo feer_conn so that existing XS methods
 * and Perl handlers work unchanged. The pseudo_conn shares the parent's fd;
 * its read/write I/O watchers are never started (I/O goes through the parent's
 * nghttp2 session) but its write_ev_timer is used for per-stream write timeout.
 */

#ifdef FEERSUM_HAS_H2

#ifdef H2_DIAG
# define h2_diag(f_, ...) trace3("H2DIAG " f_, ##__VA_ARGS__)
#else
# define h2_diag(...)
#endif

/* Submit RST_STREAM with error logging. Marks the stream so the rapid-reset
 * mitigation in h2_on_stream_close_cb knows this RST is server-initiated and
 * does not count it toward the CVE-2023-44487 flood threshold. */
static inline void
h2_submit_rst(nghttp2_session *session, int32_t stream_id, uint32_t error_code)
{
    struct feer_h2_stream *s = nghttp2_session_get_stream_user_data(session, stream_id);
    if (s) s->rst_by_us = 1;
    int rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                       stream_id, error_code);
    if (rv != 0)
        trouble("nghttp2_submit_rst_stream stream=%d: %s\n",
                stream_id, nghttp2_strerror(rv));
}

/* Defined below h2_body_read_cb, but needed by h2_on_frame_recv_cb above it. */
static void h2_submit_error_response(pTHX_ nghttp2_session *session,
                                     struct feer_h2_stream *stream,
                                     int32_t stream_id, int err_code,
                                     const char *msg, bool no_body);

/* Forward declarations for tunnel functions (RFC 8441) */
static void h2_tunnel_sv0_read_cb(EV_P_ struct ev_io *w, int revents);
static void h2_tunnel_sv0_write_cb(EV_P_ struct ev_io *w, int revents);
static int  h2_tunnel_write_or_buffer(struct feer_h2_stream *stream, const char *data, size_t len);
static void h2_tunnel_recv_data(pTHX_ struct feer_h2_stream *stream, const uint8_t *data, size_t len);

/* Bytes available in stream->resp_wbuf (after the consumed prefix). */
static inline STRLEN
h2_resp_wbuf_avail(const struct feer_h2_stream *stream)
{
    return stream->resp_wbuf
        ? (SvCUR(stream->resp_wbuf) - stream->resp_wbuf_pos) : 0;
}

/* Best-effort HTTP status from a response message SV (integer or string). */
static inline UV
h2_status_code_from_sv(pTHX_ SV *message)
{
    if (SvIOK(message)) return SvUV(message);
    UV code = 0;
    STRLEN ml;
    const char *mp = SvPV(message, ml);
    grok_number(mp, ml > 3 ? 3 : ml, &code);
    return code;
}

/* Flush pending nghttp2 frames and refill any starved stream poll_cbs.
 * Holds a refcount on parent->self because session_send invokes nghttp2
 * callbacks that may close streams or even free the parent connection. */
static inline void
h2_session_send_and_poll(pTHX_ struct feer_conn *parent)
{
    SvREFCNT_inc_void_NN(parent->self);
    feer_h2_session_send(parent);
    h2_check_stream_poll_cbs(aTHX_ parent);
    SvREFCNT_dec(parent->self);
}

/*
 * H2 per-stream write timeout callback.
 * Fires when a streaming H2 response makes no write progress within the
 * configured timeout. Sends RST_STREAM to cancel the stalled stream.
 */
static void
h2_stream_write_timeout(EV_P_ ev_timer *w, int revents)
{
    dTHX;
    struct feer_conn *c = (struct feer_conn *)w->data;
    SvREFCNT_inc_void_NN(c->self);

    /* RESPOND_SHUTDOWN does not mean "delivered" here: the whole-body writer
     * enters it as soon as it has SUBMITTED, while the DATA may still be
     * queued behind the peer's window.  A stream that genuinely finished has
     * been freed, and feer_h2_stream_free stops this timer, so arriving here
     * with a live stream means it really is stalled. */
    if (unlikely(!(revents & EV_TIMER))) {
        stop_write_timer(c);
        goto h2_wt_cleanup;
    }

    /* Paced re-invitation of a declining poll_cb (see conn_write_timeout's
     * twin): stop the periodic retry, then run the pump, which re-parks with
     * a longer interval if the app declines again. */
    if (unlikely(c->poll_retry_pending)) {
        c->poll_retry_pending = 0;
        if (likely(ev_is_active(w))) {
            ev_timer_stop(feersum_ev_loop, w);
            SvREFCNT_dec(c->self);
        }
        trace("H2 poll retry pc=%p\n", c);
        conn_write_ready(c);   /* pseudo-conn: dispatches h2_try_stream_write */
        goto h2_wt_cleanup;
    }

    struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
    stop_write_timer(c);

    if (stream && stream->parent && stream->parent->h2_session) {
        struct feer_conn *parent = stream->parent;
        trace("H2 stream write timeout stream=%d fd=%d\n",
              stream->stream_id, parent->fd);
        h2_submit_rst(parent->h2_session, stream->stream_id,
                      NGHTTP2_CANCEL);
        h2_session_send_and_poll(aTHX_ parent);
    }
    change_responding_state(c, RESPOND_SHUTDOWN);

h2_wt_cleanup:
    SvREFCNT_dec(c->self);
}

/*
 * Allocate and initialize an H2 stream.
 */
static struct feer_h2_stream *
feer_h2_stream_new(struct feer_conn *parent, int32_t stream_id)
{
    struct feer_h2_stream *stream;
    Newxz(stream, 1, struct feer_h2_stream); /* zeros all fields */
    stream->parent = parent;
    stream->stream_id = stream_id;
    stream->tunnel_sv0 = -1;  /* -1 = no fd (not zero) */
    stream->tunnel_sv1 = -1;

    /* Link into parent's stream list; mark parent busy so it won't be
     * recycled by feer_server_recycle_idle_conn while streams are active. */
    stream->next = parent->h2_streams;
    parent->h2_streams = stream;
    feer_conn_set_busy(parent);

    return stream;
}

/*
 * Free an H2 stream and all its resources.
 */
static void
feer_h2_stream_free(pTHX_ struct feer_h2_stream *stream)
{
    if (!stream) return;

    free_feer_req(stream->req);
    /* SvREFCNT_dec is NULL-safe - no need to guard each field. */
    SvREFCNT_dec(stream->body_buf);
    SvREFCNT_dec((SV*)stream->trailers);
    SvREFCNT_dec(stream->h2_method);
    SvREFCNT_dec(stream->h2_path);
    SvREFCNT_dec(stream->h2_scheme);
    SvREFCNT_dec(stream->h2_authority);
    SvREFCNT_dec(stream->h2_protocol);
    SvREFCNT_dec(stream->resp_body);
    SvREFCNT_dec(stream->resp_wbuf);
    SvREFCNT_dec(stream->resp_message);
    SvREFCNT_dec(stream->resp_headers);

    /* Clean up tunnel resources */
    if (stream->tunnel_established) {
        ev_io_stop(feersum_ev_loop, &stream->tunnel_read_w);
        ev_io_stop(feersum_ev_loop, &stream->tunnel_write_w);
    }
    if (stream->tunnel_sv0 >= 0) close(stream->tunnel_sv0);
    if (stream->tunnel_sv1 >= 0) close(stream->tunnel_sv1);
    SvREFCNT_dec(stream->tunnel_wbuf);

    /* pseudo_conn is a full feer_conn; its SV refcount handles cleanup.
     * NULL out the back-reference so pseudo_conn operations safely no-op
     * (all H2 response functions check for NULL stream). */
    if (stream->pseudo_conn) {
        struct feer_conn *pc = stream->pseudo_conn;
        stream->pseudo_conn = NULL; /* clear before dec to prevent reentrant access */
        pc->fd = -1; /* prevent double-close in DESTROY */
        pc->read_ev_timer.data = NULL;
        SvREFCNT_inc_void_NN(pc->self); /* guard: stop_write_timer may drop last ref */
        stop_write_timer(pc);
        SvREFCNT_dec(pc->self); /* guard drop */
        SvREFCNT_dec(pc->self); /* balance creation-time ref */
    }

    Safefree(stream);
}

/*
 * Remove a stream from the parent connection's stream list.
 */
static void
feer_h2_unlink_stream(struct feer_conn *c, struct feer_h2_stream *stream)
{
    struct feer_h2_stream **pp = &c->h2_streams;
    while (*pp) {
        if (*pp == stream) {
            *pp = stream->next;
            stream->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}

/*
 * Create a pseudo feer_conn for an H2 stream.
 * This allows existing Perl handlers and XS methods to work unchanged.
 * The pseudo_conn never has active ev watchers - all I/O goes through
 * the parent's nghttp2 session.
 */
static struct feer_conn *
feer_h2_create_pseudo_conn(pTHX_ struct feer_h2_stream *stream)
{
    struct feer_conn *parent = stream->parent;
    struct feer_server *srvr = parent->server;

    /* No max_connections check: the parent was already admitted against it and
     * streams are bounded by max_h2_concurrent_streams.  Re-checking here made
     * max_connections(1) reject every H2 request.  Streams still count toward
     * active_conns. */

    SV *self = newSV(0);
    SvUPGRADE(self, SVt_PVMG);
    SvGROW(self, sizeof(struct feer_conn));
    SvPOK_only(self);
    SvIOK_on(self);
    SvIV_set(self, parent->fd); /* share parent's fd for fileno() */

    struct feer_conn *pc = (struct feer_conn *)SvPVX(self);
    Zero(pc, 1, struct feer_conn);

    pc->self = self;
    pc->server = parent->server;
    pc->listener = parent->listener;
    SvREFCNT_inc_void_NN(parent->server->self);

    /* Only the cached settings the H2 paths actually consult through the
     * pseudo-conn.  The rest (read_timeout, max_conn_reqs, is_tcp,
     * keepalive_default, max_read_buf, max_body_len, max_uri_len) are read
     * either from the PARENT - the socket, its timers and every H2 size limit
     * live there - or only from H1-only code, so copying them here just
     * invited a future reader to trust the wrong copy. */
    pc->cached_use_reverse_proxy = parent->cached_use_reverse_proxy;
    pc->cached_write_timeout = parent->cached_write_timeout;
    pc->cached_wbuf_low_water = parent->cached_wbuf_low_water;

    pc->fd = parent->fd;
    memcpy(&pc->sa, &parent->sa, sizeof(struct sockaddr_storage));
    if (parent->proxy_tlvs) {
        pc->proxy_tlvs = parent->proxy_tlvs;
        SvREFCNT_inc_simple_void_NN(pc->proxy_tlvs);
    }
    pc->receiving = RECEIVE_HEADERS;
    pc->is_http11 = 1; /* pretend HTTP/1.1 for header generation compat */
    pc->sendfile_fd = -1;

    /* h2_session/h2_streams remain NULL - pseudo_conn does NOT own session */
    pc->is_h2_stream = 1;

    /* Store stream back-reference in read_ev_timer.data for H2 response path. */
    pc->read_ev_timer.data = (void *)stream;

    /* Init write_ev_timer for per-stream write timeout */
    ev_init(&pc->write_ev_timer, h2_stream_write_timeout);
    pc->write_ev_timer.data = (void *)pc;

    SV *rv = newRV_inc(pc->self);
    sv_bless(rv, feer_conn_stash);
    SvREFCNT_dec(rv);
    SvREADONLY_on(self);

    srvr->active_conns++;
    srvr->active_h2_streams++;
    stream->pseudo_conn = pc;
    return pc;
}

/*
 * nghttp2 send callback: encrypts data via TLS and queues for writing.
 */
static ssize_t
h2_send_cb(nghttp2_session *session, const uint8_t *data,
           size_t length, int flags, void *user_data)
{
    struct feer_conn *c = (struct feer_conn *)user_data;
    PERL_UNUSED_VAR(session);
    PERL_UNUSED_VAR(flags);

    /* fd may have been closed by an earlier callback in the same session_send
     * (e.g. on_stream_close_cb during shutdown) - abort cleanly instead of
     * writing to -1. */
    if (c->fd < 0)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (feer_tls_send(c, data, length) != 0)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    return (ssize_t)length;
}

/*
 * nghttp2 callback: new stream headers beginning.
 */
static int
h2_on_begin_headers_cb(nghttp2_session *session,
                       const nghttp2_frame *frame, void *user_data)
{
    struct feer_conn *c = (struct feer_conn *)user_data;

    /* Only allocate a new stream for HCAT_REQUEST.  HCAT_HEADERS (trailers)
     * arrives on an existing stream and is handled by h2_on_header_cb. */
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    int32_t stream_id = frame->hd.stream_id;
    trace("H2 begin_headers stream_id=%d fd=%d\n", stream_id, c->fd);

    struct feer_h2_stream *stream = feer_h2_stream_new(c, stream_id);

    FEER_REQ_ALLOC(stream->req);

    /* Store stream as nghttp2 stream user data */
    nghttp2_session_set_stream_user_data(session, stream_id, stream);

    return 0;
}

/*
 * nghttp2 callback: received a header name/value pair.
 * Maps H2 pseudo-headers to HTTP/1.1 request fields.
 */
static int
h2_on_header_cb(nghttp2_session *session, const nghttp2_frame *frame,
                const uint8_t *name, size_t namelen,
                const uint8_t *value, size_t valuelen,
                uint8_t flags, void *user_data)
{
    dTHX;
    PERL_UNUSED_VAR(flags);
    PERL_UNUSED_VAR(user_data);

    if (frame->hd.type != NGHTTP2_HEADERS ||
        (frame->headers.cat != NGHTTP2_HCAT_REQUEST &&
         frame->headers.cat != NGHTTP2_HCAT_HEADERS)) {
        return 0;
    }

    struct feer_h2_stream *stream = nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!stream) return 0;

    trace("H2 header stream=%d cat=%d: %.*s: %.*s\n",
        frame->hd.stream_id, frame->headers.cat, (int)namelen, name, (int)valuelen, value);

    if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
        /* Trailer header - reject pseudo-headers (RFC 9113 section 8.1) */
        if (namelen > 0 && name[0] == ':')
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        if (!stream->trailers) {
            stream->trailers = newAV();
        }
        if (av_len(stream->trailers) + 1 >= MAX_TRAILER_HEADERS * 2) {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        av_push(stream->trailers, newSVpvn((const char *)name, namelen));
        av_push(stream->trailers, newSVpvn((const char *)value, valuelen));
        return 0;
    }

    /* Handle pseudo-headers (reject duplicates per RFC 9113 section 8.3.1) */
    if (namelen > 0 && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
            if (stream->h2_method)
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            stream->h2_method = newSVpvn((const char *)value, valuelen);
            stream->req->method = SvPVX(stream->h2_method);
            stream->req->method_len = valuelen;
        } else if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
            if (stream->h2_path)
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            /* Exceeding an administrative limit is not a protocol error:
             * resetting the stream gave the client INTERNAL_ERROR (curl exits
             * 92, browsers show a generic protocol error, the access log gets
             * nothing) where HTTP/1 answers 414.  Record it and let
             * end_stream_dispatch send a real response. */
            if (valuelen > stream->parent->cached_max_uri_len) {
                stream->limit_status = 414;
                return 0;
            }
            stream->h2_path = newSVpvn((const char *)value, valuelen);
            stream->req->uri = SvPVX(stream->h2_path);
            stream->req->uri_len = valuelen;
        } else if (namelen == 7 && memcmp(name, ":scheme", 7) == 0) {
            if (stream->h2_scheme)
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            stream->h2_scheme = newSVpvn((const char *)value, valuelen);
        } else if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
            if (stream->h2_authority)
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            stream->h2_authority = newSVpvn((const char *)value, valuelen);
        } else if (namelen == 9 && memcmp(name, ":protocol", 9) == 0) {
            if (stream->h2_protocol)
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            stream->h2_protocol = newSVpvn((const char *)value, valuelen);
        } else {
            /* Unknown pseudo-header - malformed per RFC 9113 section 8.3 */
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        return 0;
    }

    /* Reject connection-specific headers forbidden by RFC 9113 section 8.2.2.
     * RFC says SHOULD be treated as a stream error of type PROTOCOL_ERROR. */
    if ((namelen == 10 && memcmp(name, "connection", 10) == 0) ||
        (namelen == 17 && memcmp(name, "transfer-encoding", 17) == 0) ||
        (namelen == 7  && memcmp(name, "upgrade", 7) == 0) ||
        (namelen == 10 && memcmp(name, "keep-alive", 10) == 0) ||
        (namelen == 16 && memcmp(name, "proxy-connection", 16) == 0)) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    /* content-length check (RFC 9113 section 8.3.2) */
    if (namelen == 14 && memcmp(name, "content-length", 14) == 0) {
        UV cl;
        /* RFC 9110 8.6: Content-Length is 1*DIGIT.  grok_number also accepts a
         * leading sign and surrounding space; the HTTP/1 twin screens the first
         * byte for the same reason. */
        if (valuelen > 0 && value[0] >= '0' && value[0] <= '9'
            && grok_number((const char *)value, valuelen, &cl) == IS_NUMBER_IN_UV) {
            if (cl > (UV)stream->parent->cached_max_body_len) {
                trace("H2 content-length %"UVuf" exceeds max_body_len\n", cl);
                stream->limit_status = 413;   /* HTTP/1 answers 413 here too */
                return 0;
            }
        } else {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
    }

    /* te header is only allowed with value "trailers" (RFC 9113 section 8.2.2) */
    if (namelen == 2 && memcmp(name, "te", 2) == 0) {
        if (valuelen != 8 || memcmp(value, "trailers", 8) != 0)
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    /* Regular headers - store in feer_req headers array.  Both limits below
     * are administrative, not protocol errors, so answer 431 like HTTP/1 does
     * rather than resetting the stream - a reset leaves the client with no
     * status at all (curl exits 92) and the access log with nothing. */
    struct feer_req *r = stream->req;
    if (r->num_headers >= MAX_HEADERS) {
        stream->limit_status = 431;
        return 0;
    }

    if (namelen > MAX_HEADER_NAME_LEN) {
        trace("H2 header name too long: %zu\n", namelen);
        stream->limit_status = 431;
        return 0;
    }

    /* We need to keep header data alive - store in a buffer SV */
    if (!r->buf) {
        r->buf = newSV_buf(512);
    }

    STRLEN buf_start = SvCUR(r->buf);
    sv_catpvn(r->buf, (const char *)name, namelen);
    sv_catpvn(r->buf, (const char *)value, valuelen);

    /* picohttpparser headers point into the buffer - we'll fix up pointers
     * after all headers are received. For now store offsets as pointer values. */
    struct phr_header *hdr = &r->headers[r->num_headers];
    hdr->name = (const char *)(uintptr_t)buf_start;
    hdr->name_len = namelen;
    hdr->value = (const char *)(uintptr_t)(buf_start + namelen);
    hdr->value_len = valuelen;
    r->num_headers++;

    return 0;
}

/*
 * Fix up header pointers after all headers have been received.
 * The pointers were stored as offsets into r->buf; now convert to real pointers.
 */
static void
h2_fixup_header_ptrs(struct feer_req *r)
{
    if (!r->buf) return;
    const char *base = SvPVX(r->buf);
    for (size_t i = 0; i < r->num_headers; i++) {
        struct phr_header *hdr = &r->headers[i];
        hdr->name = base + (uintptr_t)hdr->name;
        hdr->value = base + (uintptr_t)hdr->value;
    }
}

/* Transfer request ownership from stream to a new pseudo_conn. */
static struct feer_conn *
h2_dispatch_stream(pTHX_ struct feer_h2_stream *stream)
{
    h2_fixup_header_ptrs(stream->req);
    stream->req->minor_version = 1;

    struct feer_conn *pc = feer_h2_create_pseudo_conn(aTHX_ stream);
    if (!pc) return NULL;

    pc->req = stream->req;
    stream->req = NULL;
    pc->req->h2_method_sv = stream->h2_method;
    stream->h2_method = NULL;
    pc->req->h2_uri_sv = stream->h2_path;
    stream->h2_path = NULL;
    pc->trailers = stream->trailers;
    stream->trailers = NULL;
    pc->responding = RESPOND_NOT_STARTED;
    /* The body is fully buffered before dispatch, which is what SHUTDOWN means
     * on H1 (finish_receiving runs there too).  Left at RECEIVE_BODY, an
     * exhausted psgi.input returned undef/EAGAIN where H1 and both PODs
     * promise 0 for end of input. */
    pc->receiving = RECEIVE_SHUTDOWN;
    return pc;
}

/*
 * nghttp2 callback: frame fully received.
 * On END_STREAM for HEADERS: create pseudo_conn and dispatch request.
 */
static int
h2_on_frame_recv_cb(nghttp2_session *session,
                    const nghttp2_frame *frame, void *user_data)
{
    struct feer_conn *c = (struct feer_conn *)user_data;
    dTHX;
    PERL_UNUSED_VAR(c); /* only read by trace() */

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
    {
        if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                goto end_stream_dispatch;
            }
            break;
        }

        if (frame->headers.cat != NGHTTP2_HCAT_REQUEST)
            break;

        /* A limit tripped in the header block (long :path, a declared
         * content-length past max_body_len, too many header fields, an
         * over-long header name).  Answer with the status HTTP/1 uses rather
         * than resetting, and answer HERE - before anything dispatches.  This
         * check MUST precede the Extended CONNECT branch below: a refused
         * request that reached the app arrived with its header set silently
         * truncated, and its buffered tunnel bytes were dropped by the DATA
         * path, so the app saw a tunnel with a hole in it. */
        {
            struct feer_h2_stream *lim_stream =
                nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            if (unlikely(lim_stream && lim_stream->limit_status)) {
                lim_stream->rst_by_us = 1;   /* our refusal, not a client flood */
                /* Pre-dispatch: h2_dispatch_stream moves h2_method to the
                 * pseudo-conn's req, so read it from the stream here. */
                bool lim_head = lim_stream->h2_method
                             && SvCUR(lim_stream->h2_method) == 4
                             && memcmp(SvPVX(lim_stream->h2_method), "HEAD", 4) == 0;
                const char *lim_msg =
                      lim_stream->limit_status == 414 ? "URI Too Long\n"
                    : lim_stream->limit_status == 431 ? "Request header fields too large\n"
                    :                                   "Request body too large\n";
                h2_submit_error_response(aTHX_ session, lim_stream,
                    frame->hd.stream_id, lim_stream->limit_status,
                    lim_msg, lim_head);
                break;
            }
        }

        /* Detect Extended CONNECT (RFC 8441): method=CONNECT + :protocol set.
         * Extended CONNECT does NOT have END_STREAM on the HEADERS frame -
         * the stream stays open for bidirectional DATA. Dispatch immediately. */
        struct feer_h2_stream *hdr_stream = nghttp2_session_get_stream_user_data(
            session, frame->hd.stream_id);
        if (hdr_stream && hdr_stream->h2_method &&
            SvCUR(hdr_stream->h2_method) == 7 &&
            memcmp(SvPVX(hdr_stream->h2_method), "CONNECT", 7) == 0)
        {
            if (hdr_stream->h2_protocol) {
                if (hdr_stream->req && hdr_stream->h2_path && hdr_stream->h2_scheme
                    && hdr_stream->h2_authority) {
                    /* Extended CONNECT (RFC 8441): dispatch as tunnel */
                    hdr_stream->is_tunnel = 1;
                    struct feer_conn *pc = h2_dispatch_stream(aTHX_ hdr_stream);
                    if (unlikely(!pc)) {
                        h2_submit_rst(session, frame->hd.stream_id,
                                      NGHTTP2_REFUSED_STREAM);
                        break;
                    }
                    trace("H2 Extended CONNECT stream=%d fd=%d\n",
                          frame->hd.stream_id, c->fd);
                    sched_request_callback(pc);
                } else {
                    /* Malformed: has :protocol but missing :path or :scheme.
                     * Per RFC 8441 section 4 both are required. */
                    h2_submit_rst(session, frame->hd.stream_id,
                                  NGHTTP2_PROTOCOL_ERROR);
                }
            } else {
                /* Plain CONNECT (no :protocol): 501 Not Implemented.
                 * Per RFC 9113 section 8.5, forward-proxy tunnel not supported. */
                h2_submit_error_response(aTHX_ session, hdr_stream,
                                         frame->hd.stream_id, 501,
                                         "CONNECT not supported\n", FALSE);
            }
            break;
        }


        /* Normal request: fall through to check END_STREAM */
        if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
            break;

        goto end_stream_dispatch;
    }
    case NGHTTP2_DATA:
    {
        /* For tunnel streams, DATA+END_STREAM means client closed its send side */
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            struct feer_h2_stream *data_stream = nghttp2_session_get_stream_user_data(
                session, frame->hd.stream_id);
            if (data_stream && data_stream->is_tunnel) {
                if (data_stream->tunnel_established) {
                    /* Half-close the write side of sv[0] so app reads EOF on sv[1] */
                    if (data_stream->tunnel_sv0 >= 0) {
                        shutdown(data_stream->tunnel_sv0, SHUT_WR);
                        data_stream->tunnel_eof_sent = 1;
                    }
                } else {
                    /* Tunnel not yet established - defer shutdown until setup */
                    data_stream->tunnel_pending_shutdown = 1;
                }
                break;
            }
        }

        if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
            break;

        /* DATA+END_STREAM for non-tunnel: dispatch request.
         * Falls through to end_stream_dispatch (shared with HEADERS case). */

    end_stream_dispatch: ;
        struct feer_h2_stream *stream = nghttp2_session_get_stream_user_data(
            session, frame->hd.stream_id);
        if (!stream || !stream->req) break;

        /* Body exceeded max_body_len: the stream was already reset, so never
         * hand the app a silently truncated body. */
        if (unlikely(stream->body_overflow)) break;

        /* 413/414 was already answered from the header block and the body
         * dropped; never run the app on a request we rejected.  H1 does not. */
        if (unlikely(stream->limit_status)) break;

        /* RFC 9113 section 8.3.1: non-CONNECT requests MUST include :method, :path,
         * :scheme.  Missing mandatory pseudo-headers -> PROTOCOL_ERROR. */
        if (unlikely(!stream->h2_method || !stream->h2_path || !stream->h2_scheme)) {
            h2_submit_rst(session, frame->hd.stream_id,
                          NGHTTP2_PROTOCOL_ERROR);
            break;
        }

        struct feer_conn *pc = h2_dispatch_stream(aTHX_ stream);
        if (unlikely(!pc)) {
            h2_submit_rst(session, frame->hd.stream_id,
                          NGHTTP2_REFUSED_STREAM);
            break;
        }

        /* Transfer body if any */
        if (stream->body_buf && SvCUR(stream->body_buf) > 0) {
            pc->rbuf = stream->body_buf;
            stream->body_buf = NULL;
            pc->expected_cl = SvCUR(pc->rbuf);
            pc->received_cl = pc->expected_cl;
        }

        trace("H2 request ready stream=%d method=%.*s path=%.*s fd=%d\n",
              frame->hd.stream_id,
              (int)pc->req->method_len, pc->req->method,
              (int)pc->req->uri_len, pc->req->uri,
              c->fd);

        /* Schedule request callback (same mechanism as H1).
         * Note: total_requests is incremented in call_request_callback. */
        sched_request_callback(pc);
    }
        break;

    case NGHTTP2_SETTINGS:
        if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
            trace("H2 SETTINGS ACK received fd=%d\n", c->fd);
        }
        break;

    case NGHTTP2_GOAWAY:
        trace("H2 GOAWAY received fd=%d last_stream=%d error=%d\n",
              c->fd, frame->goaway.last_stream_id, frame->goaway.error_code);
        break;

    default:
        break;
    }

    return 0;
}

/*
 * nghttp2 callback: received a chunk of request body data.
 */
static int
h2_on_data_chunk_recv_cb(nghttp2_session *session, uint8_t flags,
                         int32_t stream_id, const uint8_t *data,
                         size_t len, void *user_data)
{
    dTHX;
    struct feer_conn *c = (struct feer_conn *)user_data;
    PERL_UNUSED_VAR(flags);

    struct feer_h2_stream *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);
    if (!stream) return 0;

    /* Tunnel streams: route DATA directly to the socketpair */
    if (stream->is_tunnel && stream->tunnel_established) {
        h2_tunnel_recv_data(aTHX_ stream, data, len);
        return 0;
    }

    /* We already answered this stream (413/414 from the header block) and the
     * client is still sending.  Drop the payload without buffering it, and do
     * not let the overflow path below RST a stream we have responded on -
     * the RST would reach the client instead of the status. */
    if (unlikely(stream->limit_status)) return 0;

    if (!stream->body_buf) {
        stream->body_buf = newSV_buf(len + 256);
    }

    /* Same body limit as HTTP/1.1.  Returning an error here does NOT reject
     * the request: nghttp2 honours only PAUSE and fatal codes, so the request
     * dispatched with a silently truncated body.  Flag, reset once, skip
     * dispatch instead.  A declared content-length is caught in on_header. */
    if (SvCUR(stream->body_buf) + len > (STRLEN)c->cached_max_body_len) {
        if (!stream->body_overflow) {
            stream->body_overflow = 1;   /* log and RST once, not per chunk */
            trouble("H2 body too large stream=%d (%" UVuf " + %" UVuf " > %" UVuf ")\n",
                    stream_id, (UV)SvCUR(stream->body_buf), (UV)len,
                    (UV)c->cached_max_body_len);
            h2_submit_rst(session, stream_id, NGHTTP2_ENHANCE_YOUR_CALM);
        }
        return 0;   /* drop the chunk; the stream is already being reset */
    }

    sv_catpvn(stream->body_buf, (const char *)data, len);

    return 0;
}

/*
 * nghttp2 callback: stream closed.
 */
static int
h2_on_stream_close_cb(nghttp2_session *session, int32_t stream_id,
                      uint32_t error_code, void *user_data)
{
    struct feer_conn *c = (struct feer_conn *)user_data;
    dTHX;
    trace("H2 stream close stream=%d error=%u fd=%d\n",
          stream_id, error_code, c->fd);
    h2_diag("STREAM-CLOSE stream=%d error=%u fd=%d\n",
            stream_id, error_code, c->fd);

    struct feer_h2_stream *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);

    /* CVE-2023-44487 Rapid Reset mitigation: bound stream closes per interval.
     * A client that opens+resets streams in a tight loop is abusing H2 stream
     * cheapness to cause server CPU exhaustion.  Skip RSTs we sent ourselves
     * (timeouts, internal errors) so the server can't trip its own threshold. */
    if (error_code != 0 && (!stream || !stream->rst_by_us)) {
        ev_tstamp now = ev_now(feersum_ev_loop);
        if (now - c->h2_rst_window_start > FEER_H2_RST_FLOOD_WINDOW) {
            c->h2_rst_window_start = now;
            c->h2_rst_count = 0;
        }
        /* Saturate to avoid wrap under sustained flood (defence-in-depth;
         * uint32 already gives ~4G headroom, but explicit cap is cheap). */
        if (c->h2_rst_count < UINT32_MAX) c->h2_rst_count++;
        if (c->h2_rst_count > FEER_H2_RST_FLOOD_THRESHOLD) {
            trouble("H2 rapid reset flood fd=%d, closing\n", c->fd);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    if (!stream) return 0;

    /* For tunnel streams, half-close sv[0] so the app sees EOF on sv[1] */
    if (stream->tunnel_established && stream->tunnel_sv0 >= 0
        && !stream->tunnel_eof_sent) {
        shutdown(stream->tunnel_sv0, SHUT_WR);
    }

    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    feer_h2_unlink_stream(c, stream);
    feer_h2_stream_free(aTHX_ stream);

    if (c->h2_streams == NULL) {
        if (unlikely(c->server->shutting_down)) {
            /* Do NOT close here: this runs inside nghttp2_session_send, and
             * the frames for the stream that just closed are still in
             * tls_wbuf, flushed only once session_send returns.  Closing
             * sets fd = -1 and that flush discards the response instead.
             * Defer to whoever empties the buffer. */
            c->h2_close_pending = 1;
        } else {
            feer_conn_set_idle(c);
        }
    }

    return 0;
}

static int
h2_on_invalid_frame_recv_cb(nghttp2_session *session,
                            const nghttp2_frame *frame,
                            int lib_error_code, void *user_data)
{
    struct feer_conn *c = (struct feer_conn *)user_data;
    PERL_UNUSED_VAR(session);
    if (c->h2_invalid_frames < 5) {
        c->h2_invalid_frames++;
        trouble("H2 invalid frame type=%d stream=%d fd=%d: %s\n",
                frame->hd.type, frame->hd.stream_id, c->fd,
                nghttp2_strerror(lib_error_code));
    }
    return 0;
}

/*
 * Initialize an nghttp2 server session on a connection.
 * Called after TLS handshake completes with h2 ALPN.
 */
static void
feer_h2_init_session(struct feer_conn *c)
{
    nghttp2_session_callbacks *callbacks;
    int rv = nghttp2_session_callbacks_new(&callbacks);
    if (rv != 0) {
        trouble("nghttp2_session_callbacks_new failed fd=%d: %s\n",
                c->fd, nghttp2_strerror(rv));
        stop_all_watchers(c);
        safe_close_conn(c, "H2 callbacks alloc failed");
        return;
    }
    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, h2_on_begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_on_frame_recv_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_on_data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2_on_stream_close_cb);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(callbacks, h2_on_invalid_frame_recv_cb);

    rv = nghttp2_session_server_new(&c->h2_session, callbacks, c);
    nghttp2_session_callbacks_del(callbacks);
    if (rv != 0) {
        trouble("nghttp2_session_server_new failed fd=%d: %s\n",
                c->fd, nghttp2_strerror(rv));
        stop_all_watchers(c);
        safe_close_conn(c, "H2 session alloc failed");
        return;
    }

    /* Send server connection preface (SETTINGS frame) */
    nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 4096 },  /* cap HPACK table size */
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, c->server->max_h2_concurrent_streams },
        { NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, FEER_H2_MAX_HEADER_LIST_SIZE },
        { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },  /* server doesn't push */
        { NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1 },  /* RFC 8441 */
    };
    rv = nghttp2_submit_settings(c->h2_session, NGHTTP2_FLAG_NONE,
                                 settings, sizeof(settings) / sizeof(settings[0]));
    if (rv != 0) {
        trouble("nghttp2_submit_settings failed fd=%d: %s\n",
                c->fd, nghttp2_strerror(rv));
        nghttp2_session_del(c->h2_session);
        c->h2_session = NULL;
        stop_all_watchers(c);
        safe_close_conn(c, "H2 settings submit failed");
        return;
    }

    /* H2 manages its own framing - mark receiving as "body" so header
     * timeout (Slowloris protection) won't incorrectly fire on this conn */
    change_receiving_state(c, RECEIVE_BODY);
    stop_header_timer(c);

    feer_conn_set_idle(c);

    trace("H2 session initialized fd=%d\n", c->fd);
}

/*
 * Free nghttp2 session and all associated streams.
 */
static void
feer_h2_free_session(struct feer_conn *c)
{
    dTHX;

    if (c->h2_session) {
        nghttp2_session_del(c->h2_session);
        c->h2_session = NULL;
    }

    /* Free all streams */
    struct feer_h2_stream *stream = c->h2_streams;
    while (stream) {
        struct feer_h2_stream *next = stream->next;
        feer_h2_stream_free(aTHX_ stream);
        stream = next;
    }
    c->h2_streams = NULL;
}

/*
 * Feed received (decrypted) data to nghttp2 session.
 */
static void
feer_h2_session_recv(struct feer_conn *c, const uint8_t *data, size_t len)
{
    /* Lazy GOAWAY on graceful shutdown: stop accepting new streams */
    if (unlikely(c->server->shutting_down)) {
        if (!c->h2_goaway_sent) {
            int ga_rv = nghttp2_submit_goaway(c->h2_session, NGHTTP2_FLAG_NONE,
                                  nghttp2_session_get_last_proc_stream_id(c->h2_session),
                                  NGHTTP2_NO_ERROR, NULL, 0);
            if (ga_rv != 0)
                trouble("nghttp2_submit_goaway(graceful) fd=%d: %s\n",
                        c->fd, nghttp2_strerror(ga_rv));
            c->h2_goaway_sent = 1;
        }
    }

    ssize_t rv = nghttp2_session_mem_recv(c->h2_session, data, len);
    if (rv < 0) {
        trouble("nghttp2_session_mem_recv error fd=%d: %s\n",
                c->fd, nghttp2_strerror((int)rv));
        int ga_rv = nghttp2_submit_goaway(c->h2_session, NGHTTP2_FLAG_NONE,
                              nghttp2_session_get_last_proc_stream_id(c->h2_session),
                              NGHTTP2_PROTOCOL_ERROR, NULL, 0);
        if (ga_rv != 0)
            trouble("nghttp2_submit_goaway(error) fd=%d: %s\n",
                    c->fd, nghttp2_strerror(ga_rv));
        feer_h2_session_send(c);
        stop_all_watchers(c);
        safe_close_conn(c, "H2 protocol error");
        return;
    }
    trace("H2 session_recv consumed %zd of %zu bytes fd=%d\n", rv, len, c->fd);
}

/*
 * Send pending nghttp2 frames through TLS.
 */
static void
feer_h2_session_send(struct feer_conn *c)
{
    if (!c->h2_session || c->fd < 0) return;

    /* Guard: nghttp2_session_send invokes callbacks (e.g. on_stream_close)
     * that may call stop_all_watchers, and this function is called from
     * unguarded tunnel callbacks. Prevent premature free. */
    SvREFCNT_inc_void_NN(c->self);

    h2_diag("ENTER fd=%d want_w=%d want_r=%d\n",
            c->fd, nghttp2_session_want_write(c->h2_session),
            nghttp2_session_want_read(c->h2_session));

    /* nghttp2_session_send uses the send_callback we registered */
    int rv = nghttp2_session_send(c->h2_session);
    if (rv != 0) {
        trouble("nghttp2_session_send error fd=%d: %s\n",
                c->fd, nghttp2_strerror(rv));
        stop_all_watchers(c);
        safe_close_conn(c, "H2 send error");
        goto send_done;
    }

    h2_diag("POST-SEND fd=%d rv=%d want_w=%d want_r=%d\n",
            c->fd, rv, nghttp2_session_want_write(c->h2_session),
            nghttp2_session_want_read(c->h2_session));

#ifdef FEERSUM_HAS_TLS
    /* Flush encrypted output to socket */
    if (c->tls_wbuf.off > 0) {
        int flush_ret = feer_tls_flush_wbuf(c);
        h2_diag("FLUSH fd=%d ret=%d remaining=%zu\n",
                c->fd, flush_ret, c->tls_wbuf.off);
        if (flush_ret == -2) {
            trouble("TLS flush error in H2 session_send fd=%d\n", c->fd);
            stop_all_watchers(c);
            safe_close_conn(c, "TLS flush error");
            goto send_done;
        }
        if (c->tls_wbuf.off > 0) {
            /* Partial write or EAGAIN - need write watcher to flush remainder */
            h2_diag("START-WRITE-WATCHER fd=%d remaining=%zu\n",
                    c->fd, c->tls_wbuf.off);
            start_write_watcher(c);
            /* And a deadline, as tls_write_again does on the H1 side.  The
             * watcher alone bounds nothing: it cannot fire while the peer is
             * not reading, so a peer that stops reading and keeps the session
             * busy (a PING flood answers itself) grew tls_wbuf unchecked with
             * nothing to reap the connection. */
            ensure_write_timer(c);
        }
    }
#endif

    /* The last stream closed during shutdown and the wire now has everything,
     * so the deferred close from h2_on_stream_close_cb can happen.  If the
     * buffer is not empty yet, try_tls_conn_write finishes the job. */
    if (unlikely(c->h2_close_pending) && c->tls_wbuf.off == 0) {
        c->h2_close_pending = 0;
        /* Linger: the response is in the kernel, not delivered, and the
         * client WINDOW_UPDATE for it is typically unread right now. */
        c->want_linger_close = 1;
        feer_shutdown_conn(c, "last H2 stream closed during shutdown");
    }

send_done:
    SvREFCNT_dec(c->self);
}

/*
 * nghttp2 data provider read callback for non-streaming (complete) bodies.
 * The stream's resp_body SV holds the entire body; resp_body_pos tracks
 * how far we've read.
 */
static ssize_t
h2_body_read_cb(nghttp2_session *session, int32_t stream_id,
                uint8_t *buf, size_t length, uint32_t *data_flags,
                nghttp2_data_source *source, void *user_data)
{
    PERL_UNUSED_VAR(session);
    PERL_UNUSED_VAR(stream_id);
    PERL_UNUSED_VAR(user_data);

    struct feer_h2_stream *stream = (struct feer_h2_stream *)source->ptr;
    if (!stream || !stream->resp_body)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    STRLEN body_len;
    const char *body = SvPV_nomg(stream->resp_body, body_len);
    size_t remaining = body_len - stream->resp_body_pos;
    size_t to_copy = remaining < length ? remaining : length;

    if (to_copy > 0) {
        memcpy(buf, body + stream->resp_body_pos, to_copy);
        /* Handing bytes to nghttp2 is progress, so push the deadline back the
         * way the H1 writer does.  Without this, arming the timer at submit
         * would reset a body simply too large to deliver inside write_timeout.
         * Refresh only, never arm: restart_write_timer() also starts a stopped
         * timer, which would put a deadline on tunnel streams that are exempt
         * from write_timeout by design (t/89d). */
        if (stream->pseudo_conn
            && ev_is_active(&stream->pseudo_conn->write_ev_timer))
            restart_write_timer(stream->pseudo_conn);
    }
    stream->resp_body_pos += to_copy;

    if (stream->resp_body_pos >= body_len)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return (ssize_t)to_copy;
}

/*
 * Error response with the same shape respond_with_server_error gives HTTP/1.
 * Every H2 error site used to submit a lone :status, so 400/408/413/414/500/501
 * arrived as a blank page with no date and nothing to display or log.
 */
static void
h2_submit_error_response(pTHX_ nghttp2_session *session,
                         struct feer_h2_stream *stream, int32_t stream_id,
                         int err_code, const char *msg, bool no_body)
{
    char status_buf[12];
    char cl_buf[24];
    nghttp2_nv nva[5];
    int n = 0;

    /* No stream means nowhere to park the body SV for the data provider, so
     * advertise zero rather than a length we will not send. */
    size_t body_len = (stream && msg) ? strlen(msg) : 0;

    int slen = my_snprintf(status_buf, sizeof(status_buf), "%d", err_code);
    nva[n].name  = (uint8_t *)":status";  nva[n].namelen  = 7;
    nva[n].value = (uint8_t *)status_buf; nva[n].valuelen = slen;
    nva[n].flags = NGHTTP2_NV_FLAG_NONE;  n++;

    nva[n].name  = (uint8_t *)"content-type"; nva[n].namelen  = 12;
    nva[n].value = (uint8_t *)"text/plain";   nva[n].valuelen = 10;
    nva[n].flags = NGHTTP2_NV_FLAG_NONE;      n++;

    nva[n].name  = (uint8_t *)"cache-control";      nva[n].namelen  = 13;
    nva[n].value = (uint8_t *)"no-cache, no-store"; nva[n].valuelen = 18;
    nva[n].flags = NGHTTP2_NV_FLAG_NONE;            n++;

    nva[n].name  = (uint8_t *)"date";           nva[n].namelen  = 4;
    nva[n].value = (uint8_t *)(DATE_BUF + 6);   nva[n].valuelen = DATE_VALUE_LENGTH;
    nva[n].flags = NGHTTP2_NV_FLAG_NONE;        n++;

    int cl_len = my_snprintf(cl_buf, sizeof(cl_buf), "%"UVuf, (UV)body_len);
    nva[n].name  = (uint8_t *)"content-length"; nva[n].namelen  = 14;
    nva[n].value = (uint8_t *)cl_buf;           nva[n].valuelen = cl_len;
    nva[n].flags = NGHTTP2_NV_FLAG_NONE;        n++;

    /* RFC 9110 9.3.2: HEAD keeps the length a GET would send, carries no body. */
    nghttp2_data_provider data_prd;
    nghttp2_data_provider *prd = NULL;
    if (body_len && !no_body) {
        SvREFCNT_dec(stream->resp_body);   /* NULL-safe; normally already NULL */
        stream->resp_body = newSVpvn(msg, body_len);
        stream->resp_body_pos = 0;
        data_prd.source.ptr = stream;
        data_prd.read_callback = h2_body_read_cb;
        prd = &data_prd;
    }

    int rv = nghttp2_submit_response(session, stream_id, nva, n, prd);
    if (rv != 0) {
        trouble("H2 error response submit failed stream=%d: %s\n",
                stream_id, nghttp2_strerror(rv));
        h2_submit_rst(session, stream_id, NGHTTP2_INTERNAL_ERROR);
    }
}

/*
 * nghttp2 data provider read callback for streaming responses.
 * Data is buffered in stream->resp_wbuf by feersum_h2_write_chunk().
 * Returns NGHTTP2_ERR_DEFERRED when no data is available yet.
 */
static ssize_t
h2_streaming_read_cb(nghttp2_session *session, int32_t stream_id,
                     uint8_t *buf, size_t length, uint32_t *data_flags,
                     nghttp2_data_source *source, void *user_data)
{
    PERL_UNUSED_VAR(session);
    PERL_UNUSED_VAR(stream_id);
    PERL_UNUSED_VAR(user_data);

    struct feer_h2_stream *stream = (struct feer_h2_stream *)source->ptr;
    if (!stream)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    STRLEN total = stream->resp_wbuf ? SvCUR(stream->resp_wbuf) : 0;
    STRLEN avail = total - stream->resp_wbuf_pos;

    if (avail == 0) {
        if (stream->resp_eof) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        return NGHTTP2_ERR_DEFERRED; /* no data yet, will resume later */
    }

    const char *ptr = SvPVX(stream->resp_wbuf) + stream->resp_wbuf_pos;
    size_t to_copy = avail < length ? avail : length;

    memcpy(buf, ptr, to_copy);
    stream->resp_wbuf_pos += to_copy;
    /* Progress: same reasoning as h2_body_read_cb, refresh-only for the same
     * reason - a tunnel stream must not acquire a deadline here. */
    if (to_copy > 0 && stream->pseudo_conn
        && ev_is_active(&stream->pseudo_conn->write_ev_timer))
        restart_write_timer(stream->pseudo_conn);

    /* Compact when fully consumed */
    if (stream->resp_wbuf_pos >= total) {
        SvCUR_set(stream->resp_wbuf, 0);
        stream->resp_wbuf_pos = 0;
        if (stream->resp_eof)
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }

    return (ssize_t)to_copy;
}

/* RFC 9113 section 8.2.2: connection-specific headers must not appear in H2. */
static inline bool
h2_skip_header(const char *hp, STRLEN hlen)
{
    switch (hlen) {
    case 2:  return str_case_eq_fixed("te", hp, 2);
    case 7:  return str_case_eq_fixed("upgrade", hp, 7);
    case 10: return str_case_eq_fixed("connection", hp, 10) ||
                    str_case_eq_fixed("keep-alive", hp, 10);
    case 16: return str_case_eq_fixed("proxy-connection", hp, 16);
    case 17: return str_case_eq_fixed("transfer-encoding", hp, 17);
    default: return false;
    }
}

/*
 * Helper: build nghttp2 nv array from message SV and headers AV.
 * Returns allocated nva (caller must Safefree) and sets *out_len.
 * status_buf must be a caller-provided char[12].
 * nghttp2 copies all name/value data during submit.  The returned nva
 * references *out_lc_buf; caller must Safefree both after the submit call.
 */
/* Is this header "content-length"? (name is compared case-insensitively) */
#define h2_is_content_length(hp, hlen) \
    ((hlen) == 14 && str_case_eq_fixed("content-length", (hp), 14))

/* body_len: the real body length, or -1 when unknown (streaming) or not to be
 * recomputed (304 may carry the would-be length).  A wrong Content-Length is
 * rejected by every nghttp2 client (RFC 9113 8.1.1). */
static nghttp2_nv *
h2_build_nva(pTHX_ SV *message, AV *headers, char *status_buf, int *out_len,
             char **out_lc_buf, IV body_len, char *cl_buf)
{
    /* Parse status code from message */
    UV code = 0;
    if (SvIOK(message))
        code = SvUV(message);
    else {
        STRLEN mlen;
        const char *mp = SvPV(message, mlen);
        const int numtype = grok_number(mp, mlen > 3 ? 3 : mlen, &code);
        if (numtype != IS_NUMBER_IN_UV) {
            trouble("h2_build_nva: invalid status '%.*s', using 500\n",
                    (int)mlen, mp);
            code = 500;
        }
    }
    if (code < 100 || code > 599) {
        trouble("h2_build_nva: status %"UVuf" out of range, using 500\n", code);
        code = 500;
    }

    /* RFC 9110 8.6: 1xx/204 must not carry Content-Length, and 205 sends no
     * DATA either, so an app-supplied value would not match the frame sum.
     * H2 is framed, so unlike H1 no replacement value is needed.  Otherwise,
     * when the real length is known, the app's value is replaced. */
    const bool drop_app_cl = (code < 200 || code == 204 || code == 205);
    const bool emit_own_cl = (!drop_app_cl && body_len >= 0);
    const bool skip_app_cl = (drop_app_cl || emit_own_cl);

    I32 avl = av_len(headers);
    /* :status + headers + date + our own content-length */
    int nva_max = 1 + (avl + 1) / 2 + 2;
    SV **ary = AvARRAY(headers);

    /* Pre-scan: compute exact lowercase name buffer size to avoid Renew */
    STRLEN lc_needed = 0;
    for (I32 i = 0; i + 1 <= avl; i += 2) {
        SV *hdr = ary[i];
        SV *val = ary[i + 1];
        if (!hdr || !SvOK(hdr) || !val || !SvOK(val)) continue;

        STRLEN hlen;
        const char *hp = SvPV_nomg(hdr, hlen);

        if (h2_skip_header(hp, hlen))
            continue;
        if (skip_app_cl && h2_is_content_length(hp, hlen))
            continue;

        lc_needed += hlen;
    }

    nghttp2_nv *nva;
    Newx(nva, nva_max, nghttp2_nv);

    char *lc_buf;
    Newx(lc_buf, lc_needed ? lc_needed : 1, char);

    /* :status pseudo-header */
    int slen = my_snprintf(status_buf, 12, "%d", (int)code);
    nva[0].name = (uint8_t *)":status";
    nva[0].namelen = 7;
    nva[0].value = (uint8_t *)status_buf;
    nva[0].valuelen = slen;
    nva[0].flags = NGHTTP2_NV_FLAG_NONE;

    /* Single pass: lowercase names into lc_buf, build nva directly.
     * lc_buf is pre-sized so no Renew is needed; pointers are stable. */
    int nva_idx = 1;
    STRLEN lc_used = 0;
    for (I32 i = 0; i + 1 <= avl; i += 2) {
        SV *hdr = ary[i];
        SV *val = ary[i + 1];
        if (!hdr || !SvOK(hdr) || !val || !SvOK(val)) continue;

        STRLEN hlen, vlen;
        const char *hp = SvPV_nomg(hdr, hlen);
        const char *vp = SvPV_nomg(val, vlen);

        if (h2_skip_header(hp, hlen))
            continue;
        if (skip_app_cl && h2_is_content_length(hp, hlen))
            continue;

        /* Downgraded emission, as on H1.  The pre-scan sized lc_buf with the
         * encoded (never shorter) name lengths, so the bound still holds. */
        if (unlikely(SvUTF8(hdr))) {
            SV *t = feer_bytes_mortal(hp, hlen);
            hp = SvPVX(t); hlen = SvCUR(t);
        }
        if (unlikely(SvUTF8(val))) {
            SV *t = feer_bytes_mortal(vp, vlen);
            vp = SvPVX(t); vlen = SvCUR(t);
        }

        char *dst = lc_buf + lc_used;
        for (STRLEN j = 0; j < hlen; j++)
            dst[j] = ascii_lower[(unsigned char)hp[j]];

        nva[nva_idx].name = (uint8_t *)dst;
        nva[nva_idx].namelen = hlen;
        nva[nva_idx].value = (uint8_t *)vp;
        nva[nva_idx].valuelen = vlen;
        nva[nva_idx].flags = NGHTTP2_NV_FLAG_NONE;
        nva_idx++;
        lc_used += hlen;
    }

    /* Emit the true Content-Length in place of whatever the app declared. */
    if (emit_own_cl) {
        int cl_len = my_snprintf(cl_buf, 24, "%"IVdf, body_len);
        nva[nva_idx].name = (uint8_t *)"content-length";
        nva[nva_idx].namelen = 14;
        nva[nva_idx].value = (uint8_t *)cl_buf;
        nva[nva_idx].valuelen = cl_len;
        nva[nva_idx].flags = NGHTTP2_NV_FLAG_NONE;
        nva_idx++;
    }

    /* Add Date header (same static buffer as H1 path) */
    nva[nva_idx].name = (uint8_t *)"date";
    nva[nva_idx].namelen = 4;
    nva[nva_idx].value = (uint8_t *)(DATE_BUF + 6);  /* skip "Date: " prefix */
    nva[nva_idx].valuelen = DATE_VALUE_LENGTH;
    nva[nva_idx].flags = NGHTTP2_NV_FLAG_NONE;
    nva_idx++;

    *out_lc_buf = lc_buf;  /* caller frees after nghttp2_submit_response */
    *out_len = nva_idx;
    return nva;
}

/*
 * H2-specific response start.
 * Called from feersum_start_response when c->is_h2_stream is set.
 *
 * Non-streaming: saves message + headers for deferred submission in
 *   feersum_h2_write_whole_body (which has the body available).
 * Streaming: submits HEADERS + deferred DATA provider immediately.
 */
static void
feersum_h2_start_response(pTHX_ struct feer_conn *c, SV *message, AV *headers, int streaming)
{
    if (unlikely(c->responding != RESPOND_NOT_STARTED))
        croak("already responding?!");

    struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
    if (!stream || !stream->parent || !stream->parent->h2_session) {
        /* Stream was reset by client (RST_STREAM) before we could respond.
         * Transition to RESPOND_SHUTDOWN so active_conns is decremented
         * promptly when the pseudo-conn is destroyed. */
        trace("H2 start_response: orphaned pseudo_conn fd=%d\n", c->fd);
        change_responding_state(c, RESPOND_SHUTDOWN);
        return;
    }
    struct feer_conn *parent = stream->parent;

    if (streaming) {
        char status_buf[12];
        char cl_buf[24];
        char *lc_buf = NULL;
        int nva_len;
        /* Streaming: the body length is not known up front, so the app's own
         * Content-Length (if any) is passed through unchanged. */
        nghttp2_nv *nva = h2_build_nva(aTHX_ message, headers, status_buf,
                                       &nva_len, &lc_buf, -1, cl_buf);

        /* No-body status: submit HEADERS with END_STREAM (NULL data provider)
         * and go straight to shutdown. */
        bool no_body = c->no_resp_body
                    || http_status_no_body(h2_status_code_from_sv(aTHX_ message));

        nghttp2_data_provider data_prd;
        nghttp2_data_provider *data_prd_ptr = NULL;
        if (!no_body) {
            change_responding_state(c, RESPOND_STREAMING);
            data_prd.source.ptr = stream;
            data_prd.read_callback = h2_streaming_read_cb;
            data_prd_ptr = &data_prd;
        } else {
            change_responding_state(c, RESPOND_SHUTDOWN);
            /* H1 lets a late $w->write on a no-body status fall through to a
             * silent XSRETURN_IV(0); without this the H2 twin reaches the
             * "can only call write in streaming mode" croak instead. */
            c->no_resp_body = 1;
        }

        int rv = nghttp2_submit_response(parent->h2_session, stream->stream_id,
                                         nva, nva_len, data_prd_ptr);
        Safefree(nva);
        Safefree(lc_buf);
        if (rv != 0) {
            trouble("nghttp2_submit_response error stream=%d: %s\n",
                    stream->stream_id, nghttp2_strerror(rv));
            h2_submit_rst(parent->h2_session, stream->stream_id,
                          NGHTTP2_INTERNAL_ERROR);
            change_responding_state(c, RESPOND_SHUTDOWN);
        }

        h2_session_send_and_poll(aTHX_ parent);
    } else {
        /* Non-streaming: defer submission until write_whole_body has the body.
         * Save message and headers for later nva building. */
        change_responding_state(c, RESPOND_NORMAL);
        stream->resp_message = newSVsv(message);
        stream->resp_headers = newRV_inc((SV *)headers);
    }
}

/*
 * Submit complete response (HEADERS + DATA) for an H2 stream.
 * Called from feersum_write_whole_body for H2 streams.
 * Uses nghttp2_submit_response with a body data provider.
 */
static size_t
feersum_h2_write_whole_body(pTHX_ struct feer_conn *c, SV *body_sv)
{
    struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
    if (!stream || !stream->parent || !stream->parent->h2_session) {
        if (c->responding != RESPOND_SHUTDOWN)
            change_responding_state(c, RESPOND_SHUTDOWN);
        return 0;
    }

    struct feer_conn *parent = stream->parent;

    /* Build nva from saved message + headers - check before allocating body */
    SV *msg = stream->resp_message;
    AV *hdrs = NULL;
    if (stream->resp_headers && SvROK(stream->resp_headers))
        hdrs = (AV *)SvRV(stream->resp_headers);

    if (!msg || !hdrs) {
        trouble("H2 write_whole_body: no saved message/headers fd=%d\n", c->fd);
        h2_submit_rst(parent->h2_session, stream->stream_id,
                      NGHTTP2_INTERNAL_ERROR);
        SvREFCNT_inc_void_NN(parent->self);
        feer_h2_session_send(parent);
        SvREFCNT_dec(parent->self);
        change_responding_state(c, RESPOND_SHUTDOWN);
        return 0;
    }

    /* Store body in stream for the data provider callback.
     * No-body status: discard the body bytes. */
    STRLEN body_len;
    bool status_no_body = http_status_no_body(h2_status_code_from_sv(aTHX_ msg));
    /* HEAD keeps the Content-Length it would have sent for a GET (RFC 9113
     * 8.1.1 explicitly permits that), so measure the body but send no DATA. */
    bool head_only = c->no_resp_body && !status_no_body;
    bool no_body = status_no_body || head_only;
    if (unlikely(head_only)) {
        const char *bp = SvPV(body_sv, body_len);
        /* HEAD advertises the downgraded length the GET would have sent */
        if (unlikely(SvUTF8(body_sv)))
            body_len = SvCUR(feer_bytes_mortal(bp, body_len));
    } else if (unlikely(status_no_body)) {
        body_len = 0;
    } else {
        stream->resp_body = newSVsv(body_sv);
        /* private copy: downgrade in place, matching H1's add_sv_to_wbuf */
        if (unlikely(SvUTF8(stream->resp_body)))
            (void)sv_utf8_downgrade(stream->resp_body, TRUE);
        (void)SvPV(stream->resp_body, body_len);
    }
    stream->resp_body_pos = 0;

    char status_buf[12];
    char cl_buf[24];
    char *lc_buf = NULL;
    int nva_len;
    /* A no-body *status* keeps the app's Content-Length: 304 legitimately
     * carries the would-be length, and 1xx/204 are dropped inside anyway.
     * HEAD still advertises the length the equivalent GET would have sent. */
    nghttp2_nv *nva = h2_build_nva(aTHX_ msg, hdrs, status_buf, &nva_len,
                                   &lc_buf, status_no_body ? -1 : (IV)body_len,
                                   cl_buf);

    /* Set up data provider */
    nghttp2_data_provider data_prd;
    data_prd.source.ptr = stream;
    data_prd.read_callback = h2_body_read_cb;

    h2_diag("SUBMIT stream=%d body=%zu fd=%d\n",
            stream->stream_id, body_len, parent->fd);

    /* no_body covers a no-body status and HEAD; resp_body is unset for both. */
    int submit_rv = nghttp2_submit_response(parent->h2_session, stream->stream_id,
                                             nva, nva_len,
                                             (!no_body && body_len > 0) ? &data_prd : NULL);
    Safefree(nva);
    Safefree(lc_buf);
    if (submit_rv != 0) {
        trouble("nghttp2_submit_response error stream=%d: %s\n",
                stream->stream_id, nghttp2_strerror(submit_rv));
        h2_submit_rst(parent->h2_session, stream->stream_id,
                      NGHTTP2_INTERNAL_ERROR);
    }

    h2_diag("SUBMIT-RV stream=%d rv=%d\n", stream->stream_id, submit_rv);

    SvREFCNT_dec(stream->resp_message);
    stream->resp_message = NULL;
    SvREFCNT_dec(stream->resp_headers);
    stream->resp_headers = NULL;

    {
        int32_t sid = stream->stream_id;
        PERL_UNUSED_VAR(sid); /* only consumed by h2_diag() */
        h2_session_send_and_poll(aTHX_ parent);
        h2_diag("DONE stream=%d\n", sid);
    }
    change_responding_state(c, RESPOND_SHUTDOWN);
    /* Still open after the send means the body did not all go out: it is
     * behind a flow-control window the PEER controls.  Nothing armed a
     * deadline on this path, so a client advertising a zero window and
     * keeping the connection alive (a PING is enough to hold read_timeout
     * off) pinned the stream for as long as it liked, holding resp_body, the
     * pseudo-conn and an active_conns slot - the slow reader write_timeout
     * exists to reap, and does reap on HTTP/1.  Re-fetch instead of reusing
     * `stream`: a completed send frees it. */
    if (unlikely(H2_STREAM_FROM_PC(c) != NULL))
        ensure_write_timer(c);
    return body_len;
}

/* Compact consumed prefix and append new data to stream->resp_wbuf. */
static void
h2_resp_wbuf_append(struct feer_h2_stream *stream, const char *ptr, STRLEN len)
{
    dTHX;
    if (!stream->resp_wbuf) {
        stream->resp_wbuf = newSV_buf(len + 256);
    } else if (stream->resp_wbuf_pos > 0) {
        STRLEN remain = SvCUR(stream->resp_wbuf) - stream->resp_wbuf_pos;
        if (remain > 0)
            memmove(SvPVX(stream->resp_wbuf),
                    SvPVX(stream->resp_wbuf) + stream->resp_wbuf_pos, remain);
        SvCUR_set(stream->resp_wbuf, remain);
        stream->resp_wbuf_pos = 0;
    }
    sv_catpvn(stream->resp_wbuf, ptr, len);
}

/*
 * Buffer a chunk of streaming response data for an H2 stream.
 * Called from the writer's write() XS method for H2 pseudo-conns.
 */
static void
feersum_h2_write_chunk(pTHX_ struct feer_conn *c, SV *body)
{
    struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
    if (!stream || !stream->parent || !stream->parent->h2_session) {
        /* Returning success here left the app writing into a dead stream
         * forever: it never dropped the writer, so the pseudo-conn was never
         * DESTROYed and its active_conns slot never released.  H1 croaks in
         * this situation; make the next write() do the same, as
         * feersum_h2_start_response already does for its half. */
        trace("H2 write_chunk: orphaned pseudo_conn fd=%d\n", c->fd);
        change_responding_state(c, RESPOND_SHUTDOWN);
        return;
    }

    STRLEN len;
    const char *ptr = SvPV(body, len);
    stream->writes_seen++;   /* count it even when empty; see the pump */
    if (len == 0) return;

    /* downgraded bytes, exactly like H1's add_sv_to_wbuf */
    if (unlikely(SvUTF8(body))) {
        SV *t = feer_bytes_mortal(ptr, len);
        ptr = SvPVX(t); len = SvCUR(t);
    }
    h2_resp_wbuf_append(stream, ptr, len);

    nghttp2_session_resume_data(stream->parent->h2_session, stream->stream_id);

    /* If inside a poll_cb callback, defer session_send so the write pump
     * (h2_try_stream_write) can detect progress in resp_wbuf.
     * Same pattern as H1: conn_write_ready defers when in_callback. */
    if (!c->in_callback)
        h2_session_send_and_poll(aTHX_ stream->parent);
    restart_write_timer(c);
}

/*
 * H2 streaming write pump - drives poll_cb for H2 pseudo-conns.
 * Analogous to how try_conn_write drives poll_cb for H1.
 */
static void
h2_try_stream_write(pTHX_ struct feer_conn *c)
{
    struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
    if (!stream || !stream->parent) {
        /* Same orphan case as feersum_h2_write_chunk: without this the poll_cb
         * keeps being invited to write into a dead stream. */
        change_responding_state(c, RESPOND_SHUTDOWN);
        return;
    }
    if (c->responding != RESPOND_STREAMING || !c->poll_write_cb) return;

    SvREFCNT_inc_void_NN(c->self);  /* prevent free during poll_cb */

    int iters = 0;
    int budget_spent = 0;
    int declined = 0;
    while (c->responding == RESPOND_STREAMING && c->poll_write_cb) {
        if (iters++ >= 64) { budget_spent = 1; break; }
        STRLEN avail = h2_resp_wbuf_avail(stream);
        if (avail > c->cached_wbuf_low_water) break;

        STRLEN before = avail;
        unsigned int writes_before = stream->writes_seen;
        /* An IO-handle body is pumped one getline per iteration, so it is
         * paced by this loop exactly like a poll_cb body. */
        if (c->poll_write_cb_is_io_handle) {
            if (!pump_h2_io_step(aTHX_ c)) break;
        }
        else
            call_poll_callback(c, 1);

        /* Recheck stream - callback may have closed or reset */
        stream = H2_STREAM_FROM_PC(c);
        if (!stream || !stream->parent) break;

        STRLEN after = h2_resp_wbuf_avail(stream);
        /* An empty write() leaves the buffer untouched but is NOT the app
         * running dry: breaking there stalled the response for good, since
         * nothing else re-invites the callback.  Only stop when the app did
         * not write at all. */
        if (after == before && stream->writes_seen == writes_before) {
            declined = 1;
            break;
        }
        /* The app wrote but produced nothing.  That is the shape that can spin
         * this pump forever, so put a deadline on it - here rather than at
         * start_response, because a stream that has simply not written yet is
         * a long-poll/SSE app waiting for its own event and must NOT be reaped
         * (lib/Feersum.pm documents that pattern, and H1 allows it). */
        if (unlikely(after == before && !stream->is_tunnel))
            ensure_write_timer(c);

        /* Flush data added by poll_cb (deferred from feersum_h2_write_chunk).
         * Unlike H1 (which yields to the event loop after each poll_cb via
         * the write watcher), H2 pseudo-conns have no write watcher - so we
         * loop until the buffer fills above low_water, flow control blocks,
         * or the callback stops/closes.  For infinite data sources, use
         * wbuf_low_water > 0 to get proper backpressure. */
        struct feer_conn *parent = stream->parent;
        SvREFCNT_inc_void_NN(parent->self);
        feer_h2_session_send(parent);
        SvREFCNT_dec(parent->self);

        /* Re-fetch stream - session_send may have freed it via
         * h2_on_stream_close_cb -> feer_h2_stream_free */
        stream = H2_STREAM_FROM_PC(c);
        if (!stream || !stream->parent) break;
    }

    /* The budget exists to yield to the loop, but a pseudo-conn has no write
     * watcher of its own: with the socket drained and the peer's window still
     * open, no read or write event follows, so nothing invites the poll_cb
     * back and the response stalls mid-body.  Re-arm the PARENT's write
     * watcher - its callback runs session_send plus the poll_cb refill. */
    if (unlikely(budget_spent)) {
        struct feer_h2_stream *st = H2_STREAM_FROM_PC(c);
        if (st && st->parent && c->responding == RESPOND_STREAMING
            && c->poll_write_cb) {
            st->parent->h2_pump_pending = 1;
            start_write_watcher(st->parent);
        }
    }
    /* A pure decline used to stall the stream until the peer happened to send
     * a frame - the same contract hole H1 answered by spinning.  Both now get
     * the paced re-invitation; the timer lands in h2_stream_write_timeout,
     * whose retry branch re-enters this pump.  Only with an EMPTY stream
     * buffer, though: a sub-low-water tail keeps its write deadline and is
     * re-invited by the peer's WINDOW_UPDATEs as before. */
    else if (unlikely(declined) && c->responding == RESPOND_STREAMING
             && c->poll_write_cb) {
        struct feer_h2_stream *st = H2_STREAM_FROM_PC(c);
        if (st && st->parent && h2_resp_wbuf_avail(st) == 0)
            feersum_poll_retry_park(c);
    }

    SvREFCNT_dec(c->self);
}

/*
 * After feer_h2_session_send, check if any streams need poll_cb refill.
 * Called from TLS read/write paths after WINDOW_UPDATE processing.
 */
static void
h2_check_stream_poll_cbs(pTHX_ struct feer_conn *c)
{
    /* Collect candidate stream IDs into a stack array first.
     * h2_try_stream_write -> feer_h2_session_send -> h2_on_stream_close_cb
     * can free ANY sibling stream, invalidating next-pointer iteration. */
    int32_t candidates[FEER_H2_MAX_CONCURRENT_STREAMS];
    int n = 0;
    struct feer_h2_stream *stream;

    for (stream = c->h2_streams; stream && n < FEER_H2_MAX_CONCURRENT_STREAMS;
         stream = stream->next) {
        /* A tunnel relay paused at the resp_wbuf cap resumes here, once the
         * wire has drained it back down.  Checked before the poll_write_cb
         * test below, which a tunnel stream never satisfies. */
        if (unlikely(stream->tunnel_established) && stream->tunnel_sv0 >= 0
            && !ev_is_active(&stream->tunnel_read_w)
            && h2_resp_wbuf_avail(stream) <= FEER_TUNNEL_MAX_WBUF)
            ev_io_start(feersum_ev_loop, &stream->tunnel_read_w);

        struct feer_conn *pc = stream->pseudo_conn;
        if (!pc || pc->responding != RESPOND_STREAMING || !pc->poll_write_cb)
            continue;

        STRLEN buffered = h2_resp_wbuf_avail(stream);
        if (buffered == 0 || (pc->cached_wbuf_low_water > 0
                              && buffered <= pc->cached_wbuf_low_water)) {
            candidates[n++] = stream->stream_id;
        }
    }

    for (int i = 0; i < n; i++) {
        /* Look up by stream_id - safe even after sibling frees.
         * h2_on_stream_close_cb clears stream_user_data before freeing. */
        stream = c->h2_session
            ? nghttp2_session_get_stream_user_data(c->h2_session, candidates[i])
            : NULL;
        if (!stream) continue;

        struct feer_conn *pc = stream->pseudo_conn;
        if (!pc || pc->responding != RESPOND_STREAMING || !pc->poll_write_cb)
            continue;

        h2_try_stream_write(aTHX_ pc);
    }
}

/*
 * ev_io callback: sv[0] is readable - app wrote data to sv[1].
 * Read from sv[0], buffer in resp_wbuf, resume nghttp2 DATA provider.
 */
static void
h2_tunnel_sv0_read_cb(EV_P_ struct ev_io *w, int revents)
{
    dTHX;
    PERL_UNUSED_VAR(revents);
    struct feer_h2_stream *stream = (struct feer_h2_stream *)w->data;
    if (!stream || !stream->parent || !stream->parent->h2_session) return;

    char buf[FEER_TUNNEL_BUFSZ];
    ssize_t nread = read(stream->tunnel_sv0, buf, sizeof(buf));

    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return;
        /* As in the TLS twin: closing sv[1] with unread inbound bytes fails
         * this read ECONNRESET rather than returning 0, and RSTing the stream
         * there threw away every DATA byte still queued in resp_wbuf. */
        if (errno != ECONNRESET && errno != EPIPE) {
            ev_io_stop(EV_A, &stream->tunnel_read_w);
            ev_io_stop(EV_A, &stream->tunnel_write_w);
            h2_submit_rst(stream->parent->h2_session, stream->stream_id,
                          NGHTTP2_CONNECT_ERROR);
            h2_session_send_and_poll(aTHX_ stream->parent);
            return;
        }
        nread = 0;
    }

    if (nread == 0) {
        /* App closed sv[1] - EOF. Signal end of response stream. */
        ev_io_stop(EV_A, &stream->tunnel_read_w);
        /* Only stop write watcher if no buffered client data to drain */
        if (!stream->tunnel_wbuf ||
            SvCUR(stream->tunnel_wbuf) <= stream->tunnel_wbuf_pos)
            ev_io_stop(EV_A, &stream->tunnel_write_w);
        stream->resp_eof = 1;
        nghttp2_session_resume_data(stream->parent->h2_session, stream->stream_id);
        h2_session_send_and_poll(aTHX_ stream->parent);
        return;
    }
    /* Swallow initial HTTP/1.1 response for PSGI H2 tunnel transparency.
     * Apps doing psgix.io write "HTTP/1.1 101 Switching...\r\n\r\n" which
     * is meaningful for H1 but must be discarded for H2 tunnels. */
    if (unlikely(stream->tunnel_swallow_response)) {
        if (!stream->resp_wbuf) {
            stream->resp_wbuf = newSV_buf(nread + 256);
        }
        sv_catpvn(stream->resp_wbuf, buf, nread);

        const char *p = SvPVX(stream->resp_wbuf);
        STRLEN len = SvCUR(stream->resp_wbuf);

        /* Match as much of a real status line ("HTTP/1.x NNN") as has
         * arrived, and relay the moment it diverges.  Requiring 5 bytes
         * before deciding held anything shorter indefinitely - a 2-byte
         * websocket PING is exactly that shape - and matching only "HTTP/"
         * let any payload starting with those five bytes stall or, past 8KB,
         * be discarded. */
        STRLEN n = len < 12 ? len : 12;
        int diverged = 0;
        for (STRLEN k = 0; k < n; k++) {
            char ch = p[k];
            if (k < 7)       diverged = (ch != "HTTP/1."[k]);
            else if (k == 8) diverged = (ch != ' ');
            else             diverged = !(ch >= '0' && ch <= '9');
            if (diverged) break;
        }
        if (diverged) {
            stream->tunnel_swallow_response = 0;
            stream->resp_wbuf_pos = 0;
            /* resp_wbuf already contains all accumulated data including
             * the current buf (appended above) - go straight to send */
            goto relay;
        }

        /* Scan for \r\n\r\n end-of-headers marker */
        if (len >= 4) {
            STRLEN i;
            for (i = 0; i <= len - 4; i++) {
                if (p[i] == '\r' && p[i+1] == '\n' &&
                    p[i+2] == '\r' && p[i+3] == '\n') {
                    /* Found end of HTTP response - discard it */
                    STRLEN after = len - (i + 4);
                    stream->tunnel_swallow_response = 0;
                    if (after > 0) {
                        /* Keep only data after the response headers */
                        memmove(SvPVX(stream->resp_wbuf),
                                p + i + 4, after);
                        SvCUR_set(stream->resp_wbuf, after);
                        stream->resp_wbuf_pos = 0;
                        goto relay;
                    }
                    SvCUR_set(stream->resp_wbuf, 0);
                    stream->resp_wbuf_pos = 0;
                    return;
                }
            }
        }

        /* Safety: 8KB of something that still looks like a status line but
         * has no header terminator is malformed either way.  Relay it rather
         * than discarding: visible garbage is a better failure than silently
         * swallowing the application's bytes. */
        if (SvCUR(stream->resp_wbuf) > 8192) {
            stream->tunnel_swallow_response = 0;
            stream->resp_wbuf_pos = 0;
            goto relay;
        }
        return; /* wait for more data */
    }

    h2_resp_wbuf_append(stream, buf, nread);

    /* Same cap the TLS relay applies to tls_wbuf: resp_wbuf has no bound of
     * its own, and a client that stops reading would otherwise accumulate the
     * whole stream in server memory - which no timeout reaps, because an
     * established tunnel is exempt from them by design.  Stop pulling from
     * the app; h2_check_stream_poll_cbs re-arms once the wire catches up. */
    if (unlikely(h2_resp_wbuf_avail(stream) > FEER_TUNNEL_MAX_WBUF))
        ev_io_stop(EV_A, &stream->tunnel_read_w);

relay:
    nghttp2_session_resume_data(stream->parent->h2_session, stream->stream_id);
    h2_session_send_and_poll(aTHX_ stream->parent);
}

/*
 * ev_io callback: sv[0] is writable - drain tunnel_wbuf (H2 DATA -> app).
 */
static void
h2_tunnel_sv0_write_cb(EV_P_ struct ev_io *w, int revents)
{
    dTHX;
    PERL_UNUSED_VAR(revents);
    struct feer_h2_stream *stream = (struct feer_h2_stream *)w->data;
    if (!stream) return;

    if (!stream->tunnel_wbuf || SvCUR(stream->tunnel_wbuf) <= stream->tunnel_wbuf_pos) {
        /* Nothing to write - stop watcher */
        ev_io_stop(EV_A, &stream->tunnel_write_w);
        if (stream->tunnel_wbuf) {
            SvCUR_set(stream->tunnel_wbuf, 0);
            stream->tunnel_wbuf_pos = 0;
        }
        return;
    }

    STRLEN avail = SvCUR(stream->tunnel_wbuf) - stream->tunnel_wbuf_pos;
    const char *ptr = SvPVX(stream->tunnel_wbuf) + stream->tunnel_wbuf_pos;
    ssize_t nw = write(stream->tunnel_sv0, ptr, avail);

    if (nw < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return;
        /* Write error - reset H2 stream */
        ev_io_stop(EV_A, &stream->tunnel_write_w);
        ev_io_stop(EV_A, &stream->tunnel_read_w);
        if (stream->parent && stream->parent->h2_session) {
            h2_submit_rst(stream->parent->h2_session, stream->stream_id,
                          NGHTTP2_CONNECT_ERROR);
            h2_session_send_and_poll(aTHX_ stream->parent);
        }
        return;
    }

    stream->tunnel_wbuf_pos += nw;
    if (stream->tunnel_wbuf_pos >= SvCUR(stream->tunnel_wbuf)) {
        /* All data drained */
        ev_io_stop(EV_A, &stream->tunnel_write_w);
        SvCUR_set(stream->tunnel_wbuf, 0);
        stream->tunnel_wbuf_pos = 0;
    }
}

/*
 * Try to write data to sv[0]; buffer any remainder in tunnel_wbuf.
 * Returns 0 on success (all written or buffered), -1 on hard write error.
 */
static int
h2_tunnel_write_or_buffer(struct feer_h2_stream *stream,
                          const char *data, size_t len)
{
    dTHX;
    if (stream->tunnel_sv0 < 0) return -1;

    /* Anything already queued must go first.  Writing straight to sv[0] while
     * tunnel_wbuf still holds an undrained remainder overtook those bytes and
     * handed the app its stream out of order - the same defect the H1/TLS
     * tunnel had in tls_tunnel_write_or_buffer, which this mirrors.  Measured
     * before the fix: 25 of 40000 numbered records out of sequence, with all
     * 40000 arriving, so no length or digest check could see it. */
    ssize_t nw = 0;
    if (!(stream->tunnel_wbuf
          && SvCUR(stream->tunnel_wbuf) > stream->tunnel_wbuf_pos)) {
        nw = write(stream->tunnel_sv0, data, len);
        if (nw == (ssize_t)len)
            return 0; /* All written */

        if (nw < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                return -1;
            nw = 0;
        }
    }

    /* Buffer remainder, start write watcher */
    size_t remaining = len - nw;
    if (!stream->tunnel_wbuf) {
        stream->tunnel_wbuf = newSV_buf(remaining + 256);
    }

    /* Compact consumed prefix to prevent unbounded SV growth */
    if (stream->tunnel_wbuf_pos > 0) {
        STRLEN remain = SvCUR(stream->tunnel_wbuf) - stream->tunnel_wbuf_pos;
        if (remain > 0)
            memmove(SvPVX(stream->tunnel_wbuf),
                    SvPVX(stream->tunnel_wbuf) + stream->tunnel_wbuf_pos,
                    remain);
        SvCUR_set(stream->tunnel_wbuf, remain);
        stream->tunnel_wbuf_pos = 0;
    }

    /* Prevent unbounded buffer growth when app side isn't draining */
    if (SvCUR(stream->tunnel_wbuf) + remaining > FEER_TUNNEL_MAX_WBUF) {
        trouble("H2 tunnel wbuf overflow stream=%d\n", stream->stream_id);
        return -1;
    }

    sv_catpvn(stream->tunnel_wbuf, data + nw, remaining);
    if (!ev_is_active(&stream->tunnel_write_w))
        ev_io_start(feersum_ev_loop, &stream->tunnel_write_w);
    return 0;
}

/*
 * Receive H2 DATA from client and write to sv[0] (tunnel -> app).
 * Called from h2_on_data_chunk_recv_cb for tunnel streams.
 */
static void
h2_tunnel_recv_data(pTHX_ struct feer_h2_stream *stream, const uint8_t *data, size_t len)
{
    if (h2_tunnel_write_or_buffer(stream, (const char *)data, len) < 0) {
        /* Write error - reset H2 stream */
        if (stream->tunnel_established) {
            ev_io_stop(feersum_ev_loop, &stream->tunnel_read_w);
            ev_io_stop(feersum_ev_loop, &stream->tunnel_write_w);
        }
        if (stream->parent && stream->parent->h2_session) {
            /* Submit only: this runs inside an nghttp2 recv callback, so
             * flushing here would re-enter the session mid-parse (the same
             * rule the GOAWAY path in h2_on_stream_close_cb states).  Every
             * caller of feer_h2_session_recv runs h2_session_send_and_poll
             * immediately after, so the RST still leaves in this read cycle. */
            h2_submit_rst(stream->parent->h2_session, stream->stream_id,
                          NGHTTP2_CONNECT_ERROR);
        }
    }
}

/*
 * Create the socketpair bridge for an Extended CONNECT tunnel.
 * Called lazily from psgix.io magic or io() method.
 */
static void
feer_h2_setup_tunnel(pTHX_ struct feer_h2_stream *stream)
{
    if (stream->tunnel_established) return;

    int sv[2];
    if (feer_socketpair_nb(sv) < 0) {
        trouble("socketpair/fcntl failed for H2 tunnel stream=%d: %s\n",
                stream->stream_id, strerror(errno));
        return;
    }

    stream->tunnel_sv0 = sv[0]; /* Feersum's end */
    stream->tunnel_sv1 = sv[1]; /* Handler's end */

    /* Read watcher: fires when app writes to sv[1] */
    ev_io_init(&stream->tunnel_read_w, h2_tunnel_sv0_read_cb, sv[0], EV_READ);
    stream->tunnel_read_w.data = (void *)stream;
    ev_io_start(feersum_ev_loop, &stream->tunnel_read_w);

    /* Write watcher: fires when sv[0] is writable (for draining tunnel_wbuf).
     * Initialized but NOT started until we have data to write. */
    ev_io_init(&stream->tunnel_write_w, h2_tunnel_sv0_write_cb, sv[0], EV_WRITE);
    stream->tunnel_write_w.data = (void *)stream;

    stream->tunnel_established = 1;

    /* Flush any pre-tunnel DATA that accumulated before the socketpair
     * was established. Write it through sv[0] so the app reads it from sv[1]. */
    /* Both flushes can overflow FEER_TUNNEL_MAX_WBUF.  Dropping those bytes
     * while carrying on would hand the app a stream with a hole in it, so
     * reset instead - the same decision h2_tunnel_recv_data makes for
     * steady-state DATA. */
    {
        int flush_err = 0;
        if (stream->pseudo_conn && stream->pseudo_conn->rbuf) {
            SV *rbuf = stream->pseudo_conn->rbuf;
            if (SvOK(rbuf) && SvCUR(rbuf) > 0) {
                if (h2_tunnel_write_or_buffer(stream, SvPVX(rbuf), SvCUR(rbuf)) < 0)
                    flush_err = 1;
                SvCUR_set(rbuf, 0);
            }
        }
        if (!flush_err && stream->body_buf && SvCUR(stream->body_buf) > 0) {
            if (h2_tunnel_write_or_buffer(stream, SvPVX(stream->body_buf),
                                          SvCUR(stream->body_buf)) < 0)
                flush_err = 1;
            SvCUR_set(stream->body_buf, 0);
        }
        if (unlikely(flush_err)) {
            trouble("H2 tunnel pre-flush overflowed stream=%d\n", stream->stream_id);
            ev_io_stop(feersum_ev_loop, &stream->tunnel_read_w);
            ev_io_stop(feersum_ev_loop, &stream->tunnel_write_w);
            if (stream->parent && stream->parent->h2_session)
                h2_submit_rst(stream->parent->h2_session, stream->stream_id,
                              NGHTTP2_CONNECT_ERROR);
            return;
        }
    }

    /* If client sent DATA+END_STREAM before the tunnel was established,
     * propagate the half-close now so the app sees EOF on sv[1]. */
    if (stream->tunnel_pending_shutdown) {
        shutdown(stream->tunnel_sv0, SHUT_WR);
        stream->tunnel_pending_shutdown = 0;
        stream->tunnel_eof_sent = 1;
    }

    trace("H2 tunnel socketpair established stream=%d sv0=%d sv1=%d\n",
          stream->stream_id, sv[0], sv[1]);
}

/*
 * Close the write side of a streaming H2 response.
 * Sets EOF flag and does a final resume so the data provider
 * can emit NGHTTP2_DATA_FLAG_EOF.
 */
static void
feersum_h2_close_write(pTHX_ struct feer_conn *c)
{
    struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
    if (!stream || !stream->parent || !stream->parent->h2_session) return;

    /* For tunnel streams, the writer close does NOT end the H2 stream.
     * The tunnel EOF is signaled when the app closes sv[1] (detected by
     * h2_tunnel_sv0_read_cb returning 0 from read). */
    if (stream->is_tunnel)
        return;

    stream->resp_eof = 1;

    /* Final resume - the read_cb will see resp_eof and set EOF flag */
    struct feer_conn *parent = stream->parent;
    nghttp2_session_resume_data(parent->h2_session, stream->stream_id);
    h2_session_send_and_poll(aTHX_ parent);
    /* The app is done, but the tail can still be stalled behind the peer's
     * window.  Stopping the timer here, as this used to, removed the only
     * deadline left on it. */
    if (unlikely(H2_STREAM_FROM_PC(c) != NULL))
        ensure_write_timer(c);
}

/*
 * Send an error response for an H2 stream.
 * If not yet responding: submit a minimal HEADERS frame with the error status.
 * If already streaming: RST_STREAM with INTERNAL_ERROR.
 */
static void
feersum_h2_respond_error(struct feer_conn *c, int err_code, const char *msg)
{
    dTHX;
    struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
    if (!stream || !stream->parent || !stream->parent->h2_session) {
        /* Orphaned pseudo-conn (stream reset by client) */
        if (c->responding != RESPOND_SHUTDOWN)
            change_responding_state(c, RESPOND_SHUTDOWN);
        return;
    }

    struct feer_conn *parent = stream->parent;

    if (c->responding == RESPOND_NOT_STARTED) {
        /* Same test the HTTP/1 twin makes: c->no_resp_body is only set once the
         * app starts a response, which on this path it never did. */
        bool no_body = c->req && c->req->method_len == 4
                    && memcmp(c->req->method, "HEAD", 4) == 0;
        h2_submit_error_response(aTHX_ parent->h2_session, stream,
                                 stream->stream_id, err_code, msg, no_body);
    } else {
        /* Already responding - reset the stream */
        h2_submit_rst(parent->h2_session, stream->stream_id,
                      NGHTTP2_INTERNAL_ERROR);
    }

    stop_write_timer(c);
    change_responding_state(c, RESPOND_SHUTDOWN);
    change_receiving_state(c, RECEIVE_SHUTDOWN);
    h2_session_send_and_poll(aTHX_ parent);
}

#endif /* FEERSUM_HAS_H2 */
