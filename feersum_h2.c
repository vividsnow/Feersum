/*
 * feersum_h2.c - HTTP/2 support via nghttp2 for Feersum
 *
 * This file is #included into Feersum.xs when FEERSUM_HAS_H2 is defined.
 * It provides nghttp2 session management, stream-to-request mapping,
 * and an H2-specific response path.
 *
 * Each H2 stream creates a pseudo feer_conn so that existing XS methods
 * and Perl handlers work unchanged. The pseudo_conn's ev watchers are
 * never started; all I/O goes through the parent connection's nghttp2 session.
 */

#ifdef FEERSUM_HAS_H2

#ifdef H2_DIAG
# define h2_diag(fmt, ...) fprintf(stderr, "H2DIAG %s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__)
#else
# define h2_diag(fmt, ...)
#endif

/* Forward declarations for tunnel functions (RFC 8441) */
static void h2_tunnel_sv0_read_cb(EV_P_ struct ev_io *w, int revents);
static void h2_tunnel_sv0_write_cb(EV_P_ struct ev_io *w, int revents);
static int  h2_tunnel_write_or_buffer(struct feer_h2_stream *stream, const char *data, size_t len);
static void h2_tunnel_recv_data(pTHX_ struct feer_h2_stream *stream, const uint8_t *data, size_t len);
static void feer_h2_setup_tunnel(pTHX_ struct feer_h2_stream *stream);

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

    /* Link into parent's stream list */
    stream->next = parent->h2_streams;
    parent->h2_streams = stream;

    return stream;
}

/*
 * Free an H2 stream and all its resources.
 */
static void
feer_h2_stream_free(pTHX_ struct feer_h2_stream *stream)
{
    if (!stream) return;

    if (stream->req) {
        if (stream->req->buf) SvREFCNT_dec(stream->req->buf);
        if (stream->req->path) SvREFCNT_dec(stream->req->path);
        if (stream->req->query) SvREFCNT_dec(stream->req->query);
        Safefree(stream->req);
    }
    if (stream->body_buf) SvREFCNT_dec(stream->body_buf);
    if (stream->h2_method) SvREFCNT_dec(stream->h2_method);
    if (stream->h2_path) SvREFCNT_dec(stream->h2_path);
    if (stream->h2_scheme) SvREFCNT_dec(stream->h2_scheme);
    if (stream->h2_authority) SvREFCNT_dec(stream->h2_authority);
    if (stream->h2_protocol) SvREFCNT_dec(stream->h2_protocol);
    if (stream->resp_body) SvREFCNT_dec(stream->resp_body);
    if (stream->resp_wbuf) SvREFCNT_dec(stream->resp_wbuf);
    if (stream->resp_message) SvREFCNT_dec(stream->resp_message);
    if (stream->resp_headers) SvREFCNT_dec(stream->resp_headers);

    /* Clean up tunnel resources */
    if (stream->tunnel_established) {
        ev_io_stop(feersum_ev_loop, &stream->tunnel_read_w);
        ev_io_stop(feersum_ev_loop, &stream->tunnel_write_w);
    }
    if (stream->tunnel_sv0 >= 0) close(stream->tunnel_sv0);
    if (stream->tunnel_sv1 >= 0) close(stream->tunnel_sv1);
    if (stream->tunnel_wbuf) SvREFCNT_dec(stream->tunnel_wbuf);

    /* pseudo_conn is a full feer_conn; its SV refcount handles cleanup.
     * NULL out the back-reference so pseudo_conn operations safely no-op
     * (all H2 response functions check for NULL stream). */
    if (stream->pseudo_conn) {
        stream->pseudo_conn->read_ev_timer.data = NULL;
        SvREFCNT_dec(stream->pseudo_conn->self);
        stream->pseudo_conn = NULL;
    }

    Safefree(stream);
}

/*
 * Find a stream by ID in the parent connection's stream list.
 */
static struct feer_h2_stream *
feer_h2_find_stream(struct feer_conn *c, int32_t stream_id)
{
    struct feer_h2_stream *s = c->h2_streams;
    while (s) {
        if (s->stream_id == stream_id)
            return s;
        s = s->next;
    }
    return NULL;
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
 * The pseudo_conn never has active ev watchers — all I/O goes through
 * the parent's nghttp2 session.
 */
static struct feer_conn *
feer_h2_create_pseudo_conn(pTHX_ struct feer_h2_stream *stream)
{
    struct feer_conn *parent = stream->parent;
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

    /* Copy cached config from parent */
    pc->cached_read_timeout = parent->cached_read_timeout;
    pc->cached_max_conn_reqs = parent->cached_max_conn_reqs;
    pc->cached_is_tcp = parent->cached_is_tcp;
    pc->cached_keepalive_default = parent->cached_keepalive_default;
    pc->cached_use_reverse_proxy = parent->cached_use_reverse_proxy;
    pc->cached_request_cb_is_psgi = parent->cached_request_cb_is_psgi;

    pc->fd = parent->fd;
    memcpy(&pc->sa, &parent->sa, sizeof(struct sockaddr_storage));
    pc->responding = RESPOND_NOT_STARTED;
    pc->receiving = RECEIVE_HEADERS;
    pc->is_keepalive = 0; /* H2 multiplexes; no HTTP-level keepalive */
    pc->is_http11 = 1; /* pretend HTTP/1.1 for header generation compat */
    pc->sendfile_fd = -1;

#ifdef FEERSUM_HAS_TLS
    pc->tls = NULL; /* pseudo_conn does NOT own TLS state */
#endif
#ifdef FEERSUM_HAS_H2
    pc->h2_session = NULL; /* pseudo_conn does NOT own session */
    pc->h2_streams = NULL;
    pc->is_h2_stream = 1;
#endif

    /* Do NOT init ev watchers — they're never started for pseudo conns.
     * Store stream back-reference in read_ev_timer.data for H2 response path. */
    pc->read_ev_timer.data = (void *)stream;

    SV *rv = newRV_inc(pc->self);
    sv_bless(rv, feer_conn_stash);
    SvREFCNT_dec(rv);
    SvREADONLY_on(self);

    parent->server->active_conns++;
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
    (void)session;
    (void)flags;

#ifdef FEERSUM_HAS_TLS
    if (c->tls) {
        feer_tls_send(c, data, length);
        return (ssize_t)length;
    }
#endif
    /* Should not happen: H2 is TLS-only */
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

/*
 * nghttp2 callback: new stream headers beginning.
 */
static int
h2_on_begin_headers_cb(nghttp2_session *session,
                       const nghttp2_frame *frame, void *user_data)
{
    struct feer_conn *c = (struct feer_conn *)user_data;
    (void)session;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    int32_t stream_id = frame->hd.stream_id;
    trace("H2 begin_headers stream_id=%d fd=%d\n", stream_id, c->fd);

    struct feer_h2_stream *stream = feer_h2_stream_new(c, stream_id);

    /* Allocate request struct */
    Newxz(stream->req, 1, struct feer_req);
    stream->req->num_headers = 0;

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
    (void)session;
    (void)flags;
    (void)user_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    struct feer_h2_stream *stream = nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!stream) return 0;

    trace("H2 header stream=%d: %.*s: %.*s\n",
        frame->hd.stream_id, (int)namelen, name, (int)valuelen, value);

    /* Handle pseudo-headers (reject duplicates per RFC 9113 §8.3.1) */
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
        }
        return 0;
    }

    /* Reject connection-specific headers forbidden by RFC 9113 §8.2.2 */
    if ((namelen == 10 && memcmp(name, "connection", 10) == 0) ||
        (namelen == 17 && memcmp(name, "transfer-encoding", 17) == 0) ||
        (namelen == 7  && memcmp(name, "upgrade", 7) == 0) ||
        (namelen == 10 && memcmp(name, "keep-alive", 10) == 0) ||
        (namelen == 16 && memcmp(name, "proxy-connection", 16) == 0)) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    /* te header is only allowed with value "trailers" (RFC 9113 §8.2.2) */
    if (namelen == 2 && memcmp(name, "te", 2) == 0) {
        if (valuelen != 8 || memcmp(value, "trailers", 8) != 0)
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    /* Regular headers - store in feer_req headers array */
    struct feer_req *r = stream->req;
    if (r->num_headers >= MAX_HEADERS) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    /* We need to keep header data alive - store in a buffer SV */
    if (!r->buf) {
        r->buf = newSV(512);
        SvPOK_on(r->buf);
        SvCUR_set(r->buf, 0);
    }

    /* Append name and value to buffer, recording offsets */
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
    size_t i;
    for (i = 0; i < r->num_headers; i++) {
        struct phr_header *hdr = &r->headers[i];
        hdr->name = base + (uintptr_t)hdr->name;
        hdr->value = base + (uintptr_t)hdr->value;
    }
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

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
    {
        if (frame->headers.cat != NGHTTP2_HCAT_REQUEST)
            break;

        /* Detect Extended CONNECT (RFC 8441): method=CONNECT + :protocol set.
         * Extended CONNECT does NOT have END_STREAM on the HEADERS frame —
         * the stream stays open for bidirectional DATA. Dispatch immediately. */
        struct feer_h2_stream *hdr_stream = nghttp2_session_get_stream_user_data(
            session, frame->hd.stream_id);
        if (hdr_stream && hdr_stream->req &&
            hdr_stream->h2_method && hdr_stream->h2_protocol &&
            hdr_stream->h2_path && hdr_stream->h2_scheme &&
            SvCUR(hdr_stream->h2_method) == 7 &&
            memcmp(SvPVX(hdr_stream->h2_method), "CONNECT", 7) == 0)
        {
            hdr_stream->is_tunnel = 1;
            h2_fixup_header_ptrs(hdr_stream->req);
            hdr_stream->req->minor_version = 1;

            struct feer_conn *pc = feer_h2_create_pseudo_conn(aTHX_ hdr_stream);
            pc->req = hdr_stream->req;
            hdr_stream->req = NULL;
            /* Transfer ownership of method/uri SVs so they survive stream free */
            pc->req->h2_method_sv = hdr_stream->h2_method;
            hdr_stream->h2_method = NULL;
            pc->req->h2_uri_sv = hdr_stream->h2_path;
            hdr_stream->h2_path = NULL;
            pc->responding = RESPOND_NOT_STARTED;
            pc->receiving = RECEIVE_BODY;

            trace("H2 Extended CONNECT stream=%d fd=%d\n",
                  frame->hd.stream_id, c->fd);

            /* total_requests is incremented in call_request_callback */
            sched_request_callback(pc);
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
            if (data_stream && data_stream->is_tunnel && data_stream->tunnel_established) {
                /* Half-close the write side of sv[0] so app reads EOF on sv[1] */
                if (data_stream->tunnel_sv0 >= 0)
                    shutdown(data_stream->tunnel_sv0, SHUT_WR);
                break;
            }
        }

        if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
            break;

    end_stream_dispatch: ;
        struct feer_h2_stream *stream = nghttp2_session_get_stream_user_data(
            session, frame->hd.stream_id);
        if (!stream || !stream->req) break;

        /* Fix up header pointers */
        h2_fixup_header_ptrs(stream->req);

        /* Set minor_version to 1 (HTTP/2 maps to HTTP/1.1 semantics) */
        stream->req->minor_version = 1;

        /* Create pseudo connection for this stream */
        struct feer_conn *pc = feer_h2_create_pseudo_conn(aTHX_ stream);
        pc->req = stream->req;
        stream->req = NULL; /* ownership transferred */
        /* Transfer ownership of method/uri SVs so they survive stream free */
        pc->req->h2_method_sv = stream->h2_method;
        stream->h2_method = NULL;
        pc->req->h2_uri_sv = stream->h2_path;
        stream->h2_path = NULL;

        /* Transfer body if any */
        if (stream->body_buf && SvCUR(stream->body_buf) > 0) {
            pc->rbuf = stream->body_buf;
            stream->body_buf = NULL;
            pc->expected_cl = SvCUR(pc->rbuf);
            pc->received_cl = pc->expected_cl;
        }

        pc->responding = RESPOND_NOT_STARTED;
        pc->receiving = RECEIVE_BODY;

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
    (void)flags;
    (void)user_data;

    struct feer_h2_stream *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);
    if (!stream) return 0;

    /* Tunnel streams: route DATA directly to the socketpair */
    if (stream->is_tunnel && stream->tunnel_established) {
        h2_tunnel_recv_data(aTHX_ stream, data, len);
        return 0;
    }

    if (!stream->body_buf) {
        stream->body_buf = newSV(len + 256);
        SvPOK_on(stream->body_buf);
        SvCUR_set(stream->body_buf, 0);
    }

    /* Enforce same body size limit as HTTP/1.1 */
    if (SvCUR(stream->body_buf) + len > (STRLEN)MAX_BODY_LEN) {
        trouble("H2 body too large stream=%d (%" UVuf " + %" UVuf " > %d)\n",
                stream_id, (UV)SvCUR(stream->body_buf), (UV)len, MAX_BODY_LEN);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
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
    (void)error_code;

    trace("H2 stream close stream=%d error=%u fd=%d\n",
          stream_id, error_code, c->fd);
    h2_diag("STREAM-CLOSE stream=%d error=%u fd=%d\n",
            stream_id, error_code, c->fd);

    struct feer_h2_stream *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);
    if (!stream) return 0;

    /* For tunnel streams, shut down sv[0] so the app sees EOF on sv[1] */
    if (stream->tunnel_established && stream->tunnel_sv0 >= 0) {
        shutdown(stream->tunnel_sv0, SHUT_RDWR);
    }

    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    feer_h2_unlink_stream(c, stream);
    feer_h2_stream_free(aTHX_ stream);

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
        safe_close_conn(c, "H2 callbacks alloc failed");
        return;
    }
    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, h2_on_begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_on_frame_recv_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_on_data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2_on_stream_close_cb);

    rv = nghttp2_session_server_new(&c->h2_session, callbacks, c);
    nghttp2_session_callbacks_del(callbacks);
    if (rv != 0) {
        trouble("nghttp2_session_server_new failed fd=%d: %s\n",
                c->fd, nghttp2_strerror(rv));
        safe_close_conn(c, "H2 session alloc failed");
        return;
    }

    /* Send server connection preface (SETTINGS frame) */
    nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, FEER_H2_MAX_CONCURRENT_STREAMS },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, FEER_H2_INITIAL_WINDOW_SIZE },
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
        safe_close_conn(c, "H2 settings submit failed");
        return;
    }

    /* H2 manages its own framing — mark receiving as "body" so header
     * timeout (Slowloris protection) won't incorrectly fire on this conn */
    change_receiving_state(c, RECEIVE_BODY);
    stop_header_timer(c);

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
    if (!c->h2_session) return;

    h2_diag("ENTER fd=%d want_w=%d want_r=%d wbuf=%zu\n",
            c->fd, nghttp2_session_want_write(c->h2_session),
            nghttp2_session_want_read(c->h2_session), c->tls_wbuf.off);

    /* nghttp2_session_send uses the send_callback we registered */
    int rv = nghttp2_session_send(c->h2_session);
    if (rv != 0) {
        trouble("nghttp2_session_send error fd=%d: %s\n",
                c->fd, nghttp2_strerror(rv));
        safe_close_conn(c, "H2 send error");
        return;
    }

    h2_diag("POST-SEND fd=%d rv=%d want_w=%d want_r=%d wbuf=%zu\n",
            c->fd, rv, nghttp2_session_want_write(c->h2_session),
            nghttp2_session_want_read(c->h2_session), c->tls_wbuf.off);

#ifdef FEERSUM_HAS_TLS
    /* Flush encrypted output to socket */
    if (c->tls_wbuf.off > 0) {
        int flush_ret = feer_tls_flush_wbuf(c);
        h2_diag("FLUSH fd=%d ret=%d remaining=%zu\n",
                c->fd, flush_ret, c->tls_wbuf.off);
        if (flush_ret == -2) {
            trouble("TLS flush error in H2 session_send fd=%d\n", c->fd);
            safe_close_conn(c, "TLS flush error");
            return;
        }
        if (c->tls_wbuf.off > 0) {
            /* Partial write or EAGAIN — need write watcher to flush remainder */
            h2_diag("START-WRITE-WATCHER fd=%d remaining=%zu\n",
                    c->fd, c->tls_wbuf.off);
            feer_tls_start_write(c);
        }
    }
#endif
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
    (void)session;
    (void)stream_id;
    (void)user_data;

    struct feer_h2_stream *stream = (struct feer_h2_stream *)source->ptr;
    if (!stream || !stream->resp_body)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    STRLEN body_len;
    const char *body = SvPV(stream->resp_body, body_len);
    size_t remaining = body_len - stream->resp_body_pos;
    size_t to_copy = remaining < length ? remaining : length;

    if (to_copy > 0)
        memcpy(buf, body + stream->resp_body_pos, to_copy);
    stream->resp_body_pos += to_copy;

    if (stream->resp_body_pos >= body_len)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return (ssize_t)to_copy;
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
    (void)session;
    (void)stream_id;
    (void)user_data;

    struct feer_h2_stream *stream = (struct feer_h2_stream *)source->ptr;
    if (!stream)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    if (!stream->resp_wbuf || SvCUR(stream->resp_wbuf) == 0) {
        if (stream->resp_eof) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        return NGHTTP2_ERR_DEFERRED; /* no data yet, will resume later */
    }

    STRLEN avail;
    const char *ptr = SvPV(stream->resp_wbuf, avail);
    size_t to_copy = avail < length ? avail : length;

    memcpy(buf, ptr, to_copy);

    /* Remove consumed bytes from front of resp_wbuf */
    if (to_copy >= avail) {
        SvCUR_set(stream->resp_wbuf, 0);
    } else {
        sv_chop(stream->resp_wbuf, SvPVX(stream->resp_wbuf) + to_copy);
    }

    if (SvCUR(stream->resp_wbuf) == 0 && stream->resp_eof)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return (ssize_t)to_copy;
}

/*
 * Helper: build nghttp2 nv array from message SV and headers AV.
 * Returns allocated nva (caller must Safefree) and sets *out_len.
 * status_buf must be a caller-provided char[12].
 * nghttp2 copies all name/value data during submit, so caller buffers
 * do not need to outlive the submit call.
 */
static nghttp2_nv *
h2_build_nva(pTHX_ SV *message, AV *headers, char *status_buf, int *out_len)
{
    /* Parse status code from message */
    UV code = 0;
    if (SvIOK(message))
        code = SvIV(message);
    else if (SvUOK(message))
        code = SvUV(message);
    else {
        const int numtype = grok_number(SvPVX_const(message), 3, &code);
        if (numtype != IS_NUMBER_IN_UV)
            code = 200;
    }

    I32 avl = av_len(headers);
    int nva_max = 1 + (avl + 1) / 2; /* :status + headers */
    nghttp2_nv *nva;
    Newx(nva, nva_max, nghttp2_nv);

    /* Allocate buffer for lowercased header names.
     * We concatenate all lowercased names into one SV, then reference
     * them by offset. This avoids per-name allocations. */
    SV *lc_names = sv_2mortal(newSV(256));
    SvPOK_on(lc_names);
    SvCUR_set(lc_names, 0);

    /* :status pseudo-header */
    snprintf(status_buf, 12, "%lu", (unsigned long)code);
    nva[0].name = (uint8_t *)":status";
    nva[0].namelen = 7;
    nva[0].value = (uint8_t *)status_buf;
    nva[0].valuelen = strlen(status_buf);
    nva[0].flags = NGHTTP2_NV_FLAG_NONE;

    /* First pass: collect lowercased names and filter headers */
    SV **ary = AvARRAY(headers);
    int nva_idx = 1;
    I32 i;

    /* Record offsets for each header name in lc_names */
    size_t *name_offsets = NULL;
    int n_hdrs = (avl + 1) / 2;
    if (n_hdrs > 0)
        Newx(name_offsets, n_hdrs, size_t);

    int hdr_count = 0;
    for (i = 0; i <= avl; i += 2) {
        if (i + 1 > avl) break;
        SV *hdr = ary[i];
        SV *val = ary[i + 1];
        if (!hdr || !SvOK(hdr) || !val || !SvOK(val)) continue;

        STRLEN hlen;
        const char *hp = SvPV(hdr, hlen);

        /* Skip Connection, Transfer-Encoding (H2 handles framing) */
        if ((hlen == 10 && str_case_eq_fixed("connection", hp, 10)) ||
            (hlen == 17 && str_case_eq_fixed("transfer-encoding", hp, 17)))
            continue;

        if (nva_idx >= nva_max) break;

        /* Record offset, then append lowercased name */
        name_offsets[hdr_count] = SvCUR(lc_names);
        SvGROW(lc_names, SvCUR(lc_names) + hlen + 1);
        char *dst = SvPVX(lc_names) + SvCUR(lc_names);
        STRLEN j;
        for (j = 0; j < hlen; j++)
            dst[j] = toLOWER((unsigned char)hp[j]);
        SvCUR_set(lc_names, SvCUR(lc_names) + hlen);

        hdr_count++;
        nva_idx++;
    }

    /* Second pass: build nva with pointers into lc_names and original values */
    nva_idx = 1;
    hdr_count = 0;
    const char *lc_base = SvPVX(lc_names);
    for (i = 0; i <= avl; i += 2) {
        if (i + 1 > avl) break;
        SV *hdr = ary[i];
        SV *val = ary[i + 1];
        if (!hdr || !SvOK(hdr) || !val || !SvOK(val)) continue;

        STRLEN hlen, vlen;
        const char *hp = SvPV(hdr, hlen);
        const char *vp = SvPV(val, vlen);

        if ((hlen == 10 && str_case_eq_fixed("connection", hp, 10)) ||
            (hlen == 17 && str_case_eq_fixed("transfer-encoding", hp, 17)))
            continue;

        if (nva_idx >= nva_max) break;

        nva[nva_idx].name = (uint8_t *)(lc_base + name_offsets[hdr_count]);
        nva[nva_idx].namelen = hlen;
        nva[nva_idx].value = (uint8_t *)vp;
        nva[nva_idx].valuelen = vlen;
        nva[nva_idx].flags = NGHTTP2_NV_FLAG_NONE;
        nva_idx++;
        hdr_count++;
    }

    if (name_offsets) Safefree(name_offsets);

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

    struct feer_h2_stream *stream = (struct feer_h2_stream *)c->read_ev_timer.data;
    if (!stream) {
        trouble("H2 start_response: no stream for pseudo_conn fd=%d\n", c->fd);
        return;
    }
    struct feer_conn *parent = stream->parent;
    if (!parent || !parent->h2_session) {
        trouble("H2 start_response: no parent session fd=%d\n", c->fd);
        return;
    }

    if (streaming) {
        /* Streaming: submit response with deferred data provider now */
        change_responding_state(c, RESPOND_STREAMING);

        char status_buf[12];
        int nva_len;
        nghttp2_nv *nva = h2_build_nva(aTHX_ message, headers, status_buf, &nva_len);

        nghttp2_data_provider data_prd;
        data_prd.source.ptr = stream;
        data_prd.read_callback = h2_streaming_read_cb;

        int rv = nghttp2_submit_response(parent->h2_session, stream->stream_id,
                                         nva, nva_len, &data_prd);
        Safefree(nva);
        if (rv != 0) {
            trouble("nghttp2_submit_response error stream=%d: %s\n",
                    stream->stream_id, nghttp2_strerror(rv));
            nghttp2_submit_rst_stream(parent->h2_session, NGHTTP2_FLAG_NONE,
                                      stream->stream_id, NGHTTP2_INTERNAL_ERROR);
        }

        feer_h2_session_send(parent);
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
    struct feer_h2_stream *stream = (struct feer_h2_stream *)c->read_ev_timer.data;
    if (!stream || !stream->parent || !stream->parent->h2_session)
        return 0;

    struct feer_conn *parent = stream->parent;

    /* Store body in stream for the data provider callback */
    stream->resp_body = newSVsv(body_sv);
    stream->resp_body_pos = 0;

    STRLEN body_len;
    (void)SvPV(stream->resp_body, body_len);

    /* Build nva from saved message + headers */
    SV *msg = stream->resp_message;
    AV *hdrs = NULL;
    if (stream->resp_headers && SvROK(stream->resp_headers))
        hdrs = (AV *)SvRV(stream->resp_headers);

    if (!msg || !hdrs) {
        trouble("H2 write_whole_body: no saved message/headers fd=%d\n", c->fd);
        return 0;
    }

    char status_buf[12];
    int nva_len;
    nghttp2_nv *nva = h2_build_nva(aTHX_ msg, hdrs, status_buf, &nva_len);

    /* Set up data provider */
    nghttp2_data_provider data_prd;
    data_prd.source.ptr = stream;
    data_prd.read_callback = h2_body_read_cb;

    h2_diag("SUBMIT stream=%d body=%zu fd=%d\n",
            stream->stream_id, body_len, parent->fd);

    int submit_rv = nghttp2_submit_response(parent->h2_session, stream->stream_id,
                                             nva, nva_len, body_len > 0 ? &data_prd : NULL);
    Safefree(nva);
    if (submit_rv != 0) {
        trouble("nghttp2_submit_response error stream=%d: %s\n",
                stream->stream_id, nghttp2_strerror(submit_rv));
        nghttp2_submit_rst_stream(parent->h2_session, NGHTTP2_FLAG_NONE,
                                  stream->stream_id, NGHTTP2_INTERNAL_ERROR);
    }

    h2_diag("SUBMIT-RV stream=%d rv=%d\n", stream->stream_id, submit_rv);

    /* Free saved message/headers — no longer needed */
    SvREFCNT_dec(stream->resp_message);
    stream->resp_message = NULL;
    SvREFCNT_dec(stream->resp_headers);
    stream->resp_headers = NULL;

    /* Flush */
    feer_h2_session_send(parent);

    h2_diag("DONE stream=%d\n", stream->stream_id);
    change_responding_state(c, RESPOND_SHUTDOWN);
    return body_len;
}

/*
 * Buffer a chunk of streaming response data for an H2 stream.
 * Called from the writer's write() XS method for H2 pseudo-conns.
 */
static void
feersum_h2_write_chunk(pTHX_ struct feer_conn *c, SV *body)
{
    struct feer_h2_stream *stream = (struct feer_h2_stream *)c->read_ev_timer.data;
    if (!stream || !stream->parent || !stream->parent->h2_session) return;

    STRLEN len;
    const char *ptr = SvPV(body, len);
    if (len == 0) return;

    if (!stream->resp_wbuf) {
        stream->resp_wbuf = newSV(len + 256);
        SvPOK_on(stream->resp_wbuf);
        SvCUR_set(stream->resp_wbuf, 0);
    }
    sv_catpvn(stream->resp_wbuf, ptr, len);

    /* Resume deferred DATA submission */
    nghttp2_session_resume_data(stream->parent->h2_session, stream->stream_id);
    feer_h2_session_send(stream->parent);
}

/*
 * ev_io callback: sv[0] is readable — app wrote data to sv[1].
 * Read from sv[0], buffer in resp_wbuf, resume nghttp2 DATA provider.
 */
static void
h2_tunnel_sv0_read_cb(EV_P_ struct ev_io *w, int revents)
{
    dTHX;
    (void)revents;
    struct feer_h2_stream *stream = (struct feer_h2_stream *)w->data;
    if (!stream || !stream->parent || !stream->parent->h2_session) return;

    char buf[FEER_H2_TUNNEL_BUFSZ];
    ssize_t nread = read(stream->tunnel_sv0, buf, sizeof(buf));

    if (nread == 0) {
        /* App closed sv[1] — EOF. Signal end of response stream. */
        ev_io_stop(EV_A, &stream->tunnel_read_w);
        stream->resp_eof = 1;
        nghttp2_session_resume_data(stream->parent->h2_session, stream->stream_id);
        feer_h2_session_send(stream->parent);
        return;
    }
    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        /* Real error — reset the stream */
        ev_io_stop(EV_A, &stream->tunnel_read_w);
        int rst_rv = nghttp2_submit_rst_stream(stream->parent->h2_session,
                                  NGHTTP2_FLAG_NONE, stream->stream_id,
                                  NGHTTP2_CONNECT_ERROR);
        if (rst_rv != 0)
            trouble("nghttp2_submit_rst_stream(tunnel read) stream=%d: %s\n",
                    stream->stream_id, nghttp2_strerror(rst_rv));
        feer_h2_session_send(stream->parent);
        return;
    }

    /* Append data to resp_wbuf for the H2 streaming data provider */
    if (!stream->resp_wbuf) {
        stream->resp_wbuf = newSV(nread + 256);
        SvPOK_on(stream->resp_wbuf);
        SvCUR_set(stream->resp_wbuf, 0);
    }
    sv_catpvn(stream->resp_wbuf, buf, nread);

    nghttp2_session_resume_data(stream->parent->h2_session, stream->stream_id);
    feer_h2_session_send(stream->parent);
}

/*
 * ev_io callback: sv[0] is writable — drain tunnel_wbuf (H2 DATA → app).
 */
static void
h2_tunnel_sv0_write_cb(EV_P_ struct ev_io *w, int revents)
{
    dTHX;
    (void)revents;
    struct feer_h2_stream *stream = (struct feer_h2_stream *)w->data;
    if (!stream) return;

    if (!stream->tunnel_wbuf || SvCUR(stream->tunnel_wbuf) <= stream->tunnel_wbuf_pos) {
        /* Nothing to write — stop watcher */
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
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        /* Write error — reset H2 stream */
        ev_io_stop(EV_A, &stream->tunnel_write_w);
        ev_io_stop(EV_A, &stream->tunnel_read_w);
        if (stream->parent && stream->parent->h2_session) {
            int rst_rv = nghttp2_submit_rst_stream(stream->parent->h2_session,
                                      NGHTTP2_FLAG_NONE, stream->stream_id,
                                      NGHTTP2_CONNECT_ERROR);
            if (rst_rv != 0)
                trouble("nghttp2_submit_rst_stream(tunnel write) stream=%d: %s\n",
                        stream->stream_id, nghttp2_strerror(rst_rv));
            feer_h2_session_send(stream->parent);
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
    if (stream->tunnel_sv0 < 0) return -1;

    ssize_t nw = write(stream->tunnel_sv0, data, len);
    if (nw == (ssize_t)len)
        return 0; /* All written */

    if (nw < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        nw = 0;
    }

    /* Buffer remainder, start write watcher */
    size_t remaining = len - nw;
    if (!stream->tunnel_wbuf) {
        stream->tunnel_wbuf = newSV(remaining + 256);
        SvPOK_on(stream->tunnel_wbuf);
        SvCUR_set(stream->tunnel_wbuf, 0);
        stream->tunnel_wbuf_pos = 0;
    }

    /* Prevent unbounded buffer growth when app side isn't draining */
    if (SvCUR(stream->tunnel_wbuf) - stream->tunnel_wbuf_pos + remaining
            > FEER_H2_MAX_TUNNEL_WBUF) {
        trouble("H2 tunnel wbuf overflow stream=%d\n", stream->stream_id);
        return -1;
    }

    sv_catpvn(stream->tunnel_wbuf, data + nw, remaining);
    if (!ev_is_active(&stream->tunnel_write_w))
        ev_io_start(feersum_ev_loop, &stream->tunnel_write_w);
    return 0;
}

/*
 * Receive H2 DATA from client and write to sv[0] (tunnel → app).
 * Called from h2_on_data_chunk_recv_cb for tunnel streams.
 */
static void
h2_tunnel_recv_data(pTHX_ struct feer_h2_stream *stream, const uint8_t *data, size_t len)
{
    if (h2_tunnel_write_or_buffer(stream, (const char *)data, len) < 0) {
        /* Write error — reset H2 stream */
        if (stream->tunnel_established) {
            ev_io_stop(feersum_ev_loop, &stream->tunnel_read_w);
            ev_io_stop(feersum_ev_loop, &stream->tunnel_write_w);
        }
        if (stream->parent && stream->parent->h2_session) {
            int rst_rv = nghttp2_submit_rst_stream(stream->parent->h2_session,
                                      NGHTTP2_FLAG_NONE, stream->stream_id,
                                      NGHTTP2_CONNECT_ERROR);
            if (rst_rv != 0)
                trouble("nghttp2_submit_rst_stream(tunnel recv) stream=%d: %s\n",
                        stream->stream_id, nghttp2_strerror(rst_rv));
            feer_h2_session_send(stream->parent);
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
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        trouble("socketpair failed for H2 tunnel stream=%d: %s\n",
                stream->stream_id, strerror(errno));
        return;
    }
    /* Set non-blocking and close-on-exec portably (SOCK_NONBLOCK/SOCK_CLOEXEC
     * are Linux-specific and not available on macOS/older BSDs). */
    if (fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK) < 0 ||
        fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL) | O_NONBLOCK) < 0 ||
        fcntl(sv[0], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(sv[1], F_SETFD, FD_CLOEXEC) < 0) {
        trouble("fcntl failed for H2 tunnel stream=%d: %s\n",
                stream->stream_id, strerror(errno));
        close(sv[0]);
        close(sv[1]);
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
    if (stream->pseudo_conn && stream->pseudo_conn->rbuf) {
        SV *rbuf = stream->pseudo_conn->rbuf;
        if (SvOK(rbuf) && SvCUR(rbuf) > 0) {
            h2_tunnel_write_or_buffer(stream, SvPVX(rbuf), SvCUR(rbuf));
            SvCUR_set(rbuf, 0);
        }
    }
    if (stream->body_buf && SvCUR(stream->body_buf) > 0) {
        h2_tunnel_write_or_buffer(stream, SvPVX(stream->body_buf),
                                  SvCUR(stream->body_buf));
        SvCUR_set(stream->body_buf, 0);
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
    struct feer_h2_stream *stream = (struct feer_h2_stream *)c->read_ev_timer.data;
    if (!stream || !stream->parent || !stream->parent->h2_session) return;

    /* For tunnel streams, the writer close does NOT end the H2 stream.
     * The tunnel EOF is signaled when the app closes sv[1] (detected by
     * h2_tunnel_sv0_read_cb returning 0 from read). */
    if (stream->is_tunnel)
        return;

    stream->resp_eof = 1;

    /* Final resume — the read_cb will see resp_eof and set EOF flag */
    nghttp2_session_resume_data(stream->parent->h2_session, stream->stream_id);
    feer_h2_session_send(stream->parent);
}

#endif /* FEERSUM_HAS_H2 */
