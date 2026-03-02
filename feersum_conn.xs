MODULE = Feersum	PACKAGE = Feersum::Connection::Handle

PROTOTYPES: ENABLE

int
fileno (feer_conn_handle *hdl)
    CODE:
        RETVAL = c->fd;
    OUTPUT:
        RETVAL

void
DESTROY (SV *self)
    ALIAS:
        Feersum::Connection::Reader::DESTROY = 1
        Feersum::Connection::Writer::DESTROY = 2
    PPCODE:
{
    feer_conn_handle *hdl = sv_2feer_conn_handle(self, 0);

    if (hdl == NULL) {
        trace3("DESTROY handle (closed) class=%s\n",
            HvNAME(SvSTASH(SvRV(self))));
    }
    else {
        struct feer_conn *c = (struct feer_conn *)hdl;
        trace3("DESTROY handle fd=%d, class=%s\n", c->fd,
            HvNAME(SvSTASH(SvRV(self))));
        if (ix == 2)
            feersum_close_handle(aTHX_ c, 1);
        else
            SvREFCNT_dec(c->self); // reader: balance new_feer_conn_handle
    }
}

SV*
read (feer_conn_handle *hdl, SV *buf, size_t len, ...)
    PROTOTYPE: $$$;$
    PPCODE:
{
    STRLEN buf_len = 0, src_len = 0;
    ssize_t offset;
    char *src_ptr = NULL;

    // optimizes for the "read everything" case.

    if (unlikely(items == 4) && SvOK(ST(3)) && SvIOK(ST(3)))
        offset = SvIV(ST(3));
    else
        offset = 0;

    trace("read fd=%d : request    len=%"Sz_uf" off=%"Ssz_df"\n",
        c->fd, (Sz)len, (Ssz)offset);

    if (unlikely(c->receiving <= RECEIVE_HEADERS))
        croak("can't call read() until the body begins to arrive");

    if (!SvPOK(buf)) {
        // force to a PV and ensure buffer space
        sv_setpvn(buf,"",0);
        SvGROW(buf, len+1);
    }

    if (unlikely(SvREADONLY(buf)))
        croak("buffer must not be read-only");

    if (unlikely(len == 0))
        XSRETURN_IV(0); // assumes undef buffer got allocated to empty-string

    (void)SvPV(buf, buf_len);
    if (likely(c->rbuf))
        src_ptr = SvPV(c->rbuf, src_len);

    if (unlikely(offset < 0))
        offset = (-offset >= c->received_cl) ? 0 : c->received_cl + offset;

    // Defensive: ensure offset doesn't exceed buffer (shouldn't happen in normal operation)
    if (unlikely(offset > (ssize_t)src_len))
        offset = src_len;

    if (unlikely(len + offset > src_len))
        len = src_len - offset;

    // Don't read past Content-Length boundary into pipelined request data
    if (c->expected_cl > 0) {
        ssize_t consumed = c->received_cl - (ssize_t)src_len;
        ssize_t remaining_body = c->expected_cl - consumed - offset;
        if (remaining_body <= 0)
            XSRETURN_IV(0);
        if ((ssize_t)len > remaining_body)
            len = (size_t)remaining_body;
    }

    trace("read fd=%d : normalized len=%"Sz_uf" off=%"Ssz_df" src_len=%"Sz_uf"\n",
        c->fd, (Sz)len, (Ssz)offset, (Sz)src_len);

    if (unlikely(!c->rbuf || src_len == 0 || offset >= c->received_cl)) {
        trace2("rbuf empty during read %d\n", c->fd);
        if (c->receiving == RECEIVE_SHUTDOWN) {
            XSRETURN_IV(0);
        }
        else {
            errno = EAGAIN;
            XSRETURN_UNDEF;
        }
    }

    if (likely(len == src_len && offset == 0)) {
        trace2("appending entire rbuf fd=%d\n", c->fd);
        sv_2mortal(c->rbuf); // allow pv to be stolen
        if (likely(buf_len == 0)) {
            sv_setsv(buf, c->rbuf);
        }
        else {
            sv_catsv(buf, c->rbuf);
        }
        c->rbuf = NULL;
    }
    else {
        src_ptr += offset;
        trace2("appending partial rbuf fd=%d len=%"Sz_uf" off=%"Ssz_df" ptr=%p\n",
            c->fd, len, offset, src_ptr);
        SvGROW(buf, SvCUR(buf) + len);
        sv_catpvn(buf, src_ptr, len);
        if (likely(items == 3)) {
            // there wasn't an offset param, throw away beginning
            // Ensure we own the buffer before modifying with sv_chop
            if (unlikely(SvREFCNT(c->rbuf) > 1 || SvREADONLY(c->rbuf))) {
                SV *copy = newSVsv(c->rbuf);
                SvREFCNT_dec(c->rbuf);
                c->rbuf = copy;
            }
            // Safety: ensure len doesn't exceed current buffer length
            STRLEN cur_len = SvCUR(c->rbuf);
            if (unlikely(len > cur_len)) len = cur_len;
            sv_chop(c->rbuf, SvPVX(c->rbuf) + len);
        }
    }

    XSRETURN_IV(len);
}

STRLEN
write (feer_conn_handle *hdl, ...)
    PROTOTYPE: $;$
    CODE:
{
    if (unlikely(c->responding != RESPOND_STREAMING))
        croak("can only call write in streaming mode");

    // RFC 7230 §3.3: 1xx/204/205/304 MUST NOT have a body — discard writes
    // (auto_cl is only set for H1; H2 handles this in its own DATA provider)
    if (unlikely(!c->auto_cl && !h2_is_stream(c)))
        XSRETURN_IV(0);

    SV *body = (items == 2) ? ST(1) : &PL_sv_undef;
    if (unlikely(!body || !SvOK(body)))
        XSRETURN_IV(0);

    trace("write fd=%d c=%p, body=%p\n", c->fd, c, body);
    if (SvROK(body)) {
        SV *refd = SvRV(body);
        if (SvOK(refd) && SvPOK(refd)) {
            body = refd;
        }
        else {
            croak("body must be a scalar, scalar ref or undef");
        }
    }
    (void)SvPV(body, RETVAL);

    if (!h2_try_write_chunk(aTHX_ c, body)) {
        if (c->use_chunked)
            add_chunk_sv_to_wbuf(c, body);
        else
            add_sv_to_wbuf(c, body);

        conn_write_ready(c);
    }
}
    OUTPUT:
        RETVAL

void
write_array (feer_conn_handle *hdl, AV *abody)
    PROTOTYPE: $$
    PPCODE:
{
    if (unlikely(c->responding != RESPOND_STREAMING))
        croak("can only call write in streaming mode");

    if (unlikely(!c->auto_cl && !h2_is_stream(c)))
        XSRETURN_EMPTY;

    trace("write_array fd=%d c=%p, abody=%p\n", c->fd, c, abody);

    I32 amax = av_len(abody);
    I32 i;

    if (h2_is_stream(c)) {
        /* H2 stream: feed each element through the H2 data provider */
        for (i=0; i<=amax; i++) {
            SV *sv = fetch_av_normal(aTHX_ abody, i);
            if (likely(sv)) h2_try_write_chunk(aTHX_ c, sv);
        }
        XSRETURN_EMPTY;
    }

    if (c->use_chunked) {
        for (i=0; i<=amax; i++) {
            SV *sv = fetch_av_normal(aTHX_ abody, i);
            if (likely(sv)) add_chunk_sv_to_wbuf(c, sv);
        }
    }
    else {
        for (i=0; i<=amax; i++) {
            SV *sv = fetch_av_normal(aTHX_ abody, i);
            if (likely(sv)) add_sv_to_wbuf(c, sv);
        }
    }

    conn_write_ready(c);
}

void
sendfile (feer_conn_handle *hdl, SV *fh, ...)
    PROTOTYPE: $$;$$
    PPCODE:
{
#ifdef __linux__
    if (h2_is_stream(c))
        croak("sendfile not supported for HTTP/2 streams (use write instead)");
    if (unlikely(c->responding != RESPOND_STREAMING))
        croak("sendfile: can only call after start_streaming()");

    // Get file descriptor from filehandle
    int file_fd = -1;
    off_t offset = 0;
    size_t length = 0;

    if (SvIOK(fh)) {
        // Bare file descriptor
        file_fd = SvIV(fh);
    }
    else if (SvROK(fh) && SvTYPE(SvRV(fh)) == SVt_PVGV) {
        // Glob reference (filehandle)
        IO *io = GvIOp(SvRV(fh));
        if (io && IoIFP(io)) {
            file_fd = PerlIO_fileno(IoIFP(io));
        }
    }
    else if (SvTYPE(fh) == SVt_PVGV) {
        // Bare glob
        IO *io = GvIOp(fh);
        if (io && IoIFP(io)) {
            file_fd = PerlIO_fileno(IoIFP(io));
        }
    }

    if (file_fd < 0)
        croak("sendfile: invalid file handle");

    // Get file size for length if not specified
    struct stat st;
    if (fstat(file_fd, &st) < 0)
        croak("sendfile: fstat failed: %s", strerror(errno));

    if (!S_ISREG(st.st_mode))
        croak("sendfile: not a regular file");

    // Parse optional offset and validate before using
    if (items >= 3 && SvOK(ST(2))) {
        IV offset_iv = SvIV(ST(2));
        if (offset_iv < 0)
            croak("sendfile: offset must be non-negative");
        offset = (off_t)offset_iv;
    }

    if (st.st_size == 0) {
        XSRETURN_EMPTY;
    }
    if (offset >= st.st_size)
        croak("sendfile: offset out of range");

    if (items >= 4 && SvOK(ST(3))) {
        UV length_uv = SvUV(ST(3));
        // Check that length fits in ssize_t (signed) before casting
        // This prevents bypass via values >= 2^63 becoming negative
        // Use (UV)((~(size_t)0) >> 1) as portable SSIZE_MAX
        if (length_uv > (UV)((~(size_t)0) >> 1))
            croak("sendfile: length too large");
        length = (size_t)length_uv;
        // Validate length doesn't exceed file size - offset
        if (length > (size_t)(st.st_size - offset))
            croak("sendfile: offset + length exceeds file size");
    } else {
        // Default: send from offset to end of file
        length = st.st_size - offset;
    }

    if (length == 0) {
        // Nothing to send, just return
        XSRETURN_EMPTY;
    }

    trace("sendfile setup: fd=%d file_fd=%d off=%ld len=%zu\n",
        c->fd, file_fd, (long)offset, length);

    // Close any in-progress sendfile before starting a new one
    CLOSE_SENDFILE_FD(c);
    // Dup the fd so we own it (caller can close their handle)
    c->sendfile_fd = dup(file_fd);
    if (c->sendfile_fd < 0)
        croak("sendfile: dup failed: %s", strerror(errno));

    c->sendfile_off = offset;
    c->sendfile_remain = length;

    conn_write_ready(c);
    XSRETURN_EMPTY;
#else
    PERL_UNUSED_VAR(fh);
    croak("sendfile: only supported on Linux");
#endif
}

int
seek (feer_conn_handle *hdl, ssize_t offset, ...)
    PROTOTYPE: $$;$
    CODE:
{
    int whence = SEEK_CUR;
    if (items == 3 && SvOK(ST(2)) && SvIOK(ST(2)))
        whence = SvIV(ST(2));

    trace("seek fd=%d offset=%"Ssz_df" whence=%d\n", c->fd, offset, whence);

    if (unlikely(!c->rbuf)) {
        // handle is effectively "closed"
        RETVAL = 0;
    }
    else if (offset == 0) {
        RETVAL = 1; // stay put for any whence
    }
    else if (offset > 0 && (whence == SEEK_CUR || whence == SEEK_SET)) {
        STRLEN len;
        const char *str = SvPV_const(c->rbuf, len);
        if (offset > len)
            offset = len;
        // Ensure we own the buffer before modifying with sv_chop
        // (sv_chop modifies the SV in-place, unsafe if shared)
        if (SvREFCNT(c->rbuf) > 1 || SvREADONLY(c->rbuf)) {
            SV *copy = newSVsv(c->rbuf);
            SvREFCNT_dec(c->rbuf);
            c->rbuf = copy;
            str = SvPV_const(c->rbuf, len);
        }
        sv_chop(c->rbuf, str + offset);
        RETVAL = 1;
    }
    else if (offset < 0 && whence == SEEK_END) {
        STRLEN len;
        const char *str = SvPV_const(c->rbuf, len);
        offset += len; // can't be > len since block is offset<0
        if (offset == 0) {
            RETVAL = 1; // no-op, but OK
        }
        else if (offset > 0) {
            // Ensure we own the buffer before modifying
            if (SvREFCNT(c->rbuf) > 1 || SvREADONLY(c->rbuf)) {
                SV *copy = newSVsv(c->rbuf);
                SvREFCNT_dec(c->rbuf);
                c->rbuf = copy;
                str = SvPV_const(c->rbuf, len);
            }
            sv_chop(c->rbuf, str + offset);
            RETVAL = 1;
        }
        else {
            // past beginning of string
            RETVAL = 0;
        }
    }
    else {
        // invalid seek
        RETVAL = 0;
    }
}
    OUTPUT:
        RETVAL

int
close (feer_conn_handle *hdl)
    PROTOTYPE: $
    ALIAS:
        Feersum::Connection::Reader::close = 1
        Feersum::Connection::Writer::close = 2
    CODE:
{
    assert(ix && "close() must be called via Reader::close or Writer::close");
    RETVAL = feersum_close_handle(aTHX_ c, (ix == 2));
    SvUVX(hdl_sv) = 0;
}
    OUTPUT:
        RETVAL

void
_poll_cb (feer_conn_handle *hdl, SV *cb)
    PROTOTYPE: $$
    ALIAS:
        Feersum::Connection::Reader::poll_cb = 1
        Feersum::Connection::Writer::poll_cb = 2
    PPCODE:
{
    if (unlikely(ix < 1 || ix > 2))
        croak("can't call _poll_cb directly");

    bool is_read = (ix == 1);
    SV **cb_slot = is_read ? &c->poll_read_cb : &c->poll_write_cb;

    if (*cb_slot != NULL) {
        SvREFCNT_dec(*cb_slot);
        *cb_slot = NULL;
    }

    if (!SvOK(cb)) {
        trace("unset poll_cb ix=%d\n", ix);
        if (is_read) {
            // Stop streaming mode if callback is unset
            if (c->receiving == RECEIVE_STREAMING) {
                change_receiving_state(c, RECEIVE_BODY);
            }
        }
        return;
    }
    else if (unlikely(!IsCodeRef(cb)))
        croak("must supply a code reference to poll_cb");

    *cb_slot = newSVsv(cb);

    if (is_read) {
        // Switch to streaming receive mode
        // Allow from RECEIVE_BODY (normal body) or RECEIVE_SHUTDOWN
        // (post-upgrade, e.g. WebSocket 101 where body reading was stopped)
        if (c->receiving == RECEIVE_BODY || c->receiving == RECEIVE_SHUTDOWN) {
            change_receiving_state(c, RECEIVE_STREAMING);
        }
        // If there's already body data in rbuf, call the callback immediately
        if (c->rbuf && SvCUR(c->rbuf) > 0) {
            call_poll_callback(c, 0);  // 0 = read callback
        }
        else {
            start_read_watcher(c);
        }
    }
    else {
        conn_write_ready(c);
    }
}

SV*
response_guard (feer_conn_handle *hdl, ...)
    PROTOTYPE: $;$
    CODE:
        RETVAL = feersum_conn_guard(aTHX_ c, (items==2) ? ST(1) : NULL);
    OUTPUT:
        RETVAL

void
return_from_psgix_io (feer_conn_handle *hdl, SV *io_sv)
    PROTOTYPE: $$
    PPCODE:
{
    SSize_t cnt = feersum_return_from_io(aTHX_ c, io_sv, "return_from_psgix_io");
    mXPUSHi(cnt);
}

MODULE = Feersum	PACKAGE = Feersum::Connection

PROTOTYPES: ENABLE

SV *
start_streaming (struct feer_conn *c, SV *message, AV *headers)
    PROTOTYPE: $$\@
    CODE:
        feersum_start_response(aTHX_ c, message, headers, 1);
        RETVAL = new_feer_conn_handle(aTHX_ c, 1); // RETVAL gets mortalized
    OUTPUT:
        RETVAL

int
is_http11 (struct feer_conn *c)
    CODE:
        RETVAL = c->is_http11;
    OUTPUT:
        RETVAL

size_t
send_response (struct feer_conn *c, SV* message, AV *headers, SV *body)
    PROTOTYPE: $$\@$
    CODE:
        if (unlikely(!SvOK(body)))
            croak("can't send_response with an undef body");
        feersum_start_response(aTHX_ c, message, headers, 0);
        RETVAL = feersum_write_whole_body(aTHX_ c, body);
    OUTPUT:
        RETVAL

SV*
_continue_streaming_psgi (struct feer_conn *c, SV *psgi_response)
    PROTOTYPE: $\@
    CODE:
{
    AV *av;
    int len = 0;

    if (IsArrayRef(psgi_response)) {
        av = (AV*)SvRV(psgi_response);
        len = av_len(av) + 1;
    }

    if (len == 3) {
        // 0 is "don't recurse" (i.e. don't allow another code-ref)
        feersum_handle_psgi_response(aTHX_ c, psgi_response, 0);
        RETVAL = &PL_sv_undef;
    }
    else if (len == 2) {
        SV *message = *(av_fetch(av,0,0));
        SV *headers = *(av_fetch(av,1,0));
        if (unlikely(!IsArrayRef(headers)))
            croak("PSGI headers must be an array ref");
        feersum_start_response(aTHX_ c, message, (AV*)SvRV(headers), 1);
        RETVAL = new_feer_conn_handle(aTHX_ c, 1); // RETVAL gets mortalized
    }
    else {
        croak("PSGI response starter expects a 2 or 3 element array-ref");
    }
}
    OUTPUT:
        RETVAL

void
force_http10 (struct feer_conn *c)
    PROTOTYPE: $
    ALIAS:
        force_http11 = 1
    PPCODE:
        c->is_http11 = ix;

SV *
env (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        RETVAL = newRV_noinc((SV*)feersum_env(aTHX_ c));
    OUTPUT:
        RETVAL

SV *
method (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        struct feer_req *r = c->req;
        if (unlikely(!r))
            croak("Cannot access request method: no active request");
#ifdef FEERSUM_HAS_H2
        RETVAL = feersum_env_method_h2(aTHX_ c, r);
#else
        RETVAL = feersum_env_method(aTHX_ r);
#endif
    OUTPUT:
        RETVAL

SV *
uri (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        struct feer_req *r = c->req;
        if (unlikely(!r))
            croak("Cannot access request URI: no active request");
        RETVAL = feersum_env_uri(aTHX_ r);
    OUTPUT:
        RETVAL

SV *
protocol (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        struct feer_req *r = c->req;
        if (unlikely(!r))
            croak("Cannot access request protocol: no active request");
        RETVAL = SvREFCNT_inc_simple_NN(feersum_env_protocol(aTHX_ r));
    OUTPUT:
        RETVAL

SV *
path (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        struct feer_req *r = c->req;
        if (unlikely(!r))
            croak("Cannot access request path: no active request");
        RETVAL = SvREFCNT_inc_simple_NN(feersum_env_path(aTHX_ r));
    OUTPUT:
        RETVAL

SV *
query (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        struct feer_req *r = c->req;
        if (unlikely(!r))
            croak("Cannot access request query: no active request");
        RETVAL = SvREFCNT_inc_simple_NN(feersum_env_query(aTHX_ r));
    OUTPUT:
        RETVAL

SV *
remote_address (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        RETVAL = SvREFCNT_inc_simple_NN(feersum_env_addr(aTHX_ c));
    OUTPUT:
        RETVAL

SV *
remote_port (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        RETVAL = SvREFCNT_inc_simple_NN(feersum_env_port(aTHX_ c));
    OUTPUT:
        RETVAL

SV *
proxy_tlvs (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        // Returns PROXY protocol v2 TLVs hashref (native interface only)
        // Keys are TLV type numbers as strings, values are raw TLV data
        RETVAL = c->proxy_tlvs ? SvREFCNT_inc(c->proxy_tlvs) : &PL_sv_undef;
    OUTPUT:
        RETVAL

SV *
trailers (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        RETVAL = c->trailers ? newRV_inc((SV*)c->trailers) : &PL_sv_undef;
    OUTPUT:
        RETVAL

SV *
client_address (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
{
    SV *fwd = NULL;
    if (c->cached_use_reverse_proxy && c->req)
        fwd = extract_forwarded_addr(aTHX_ c->req);
    RETVAL = fwd ? fwd : SvREFCNT_inc_simple_NN(feersum_env_addr(aTHX_ c));
}
    OUTPUT:
        RETVAL

SV *
url_scheme (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
{
    RETVAL = feer_determine_url_scheme(aTHX_ c);
    if (!RETVAL) RETVAL = newSVpvs("http");
}
    OUTPUT:
        RETVAL

ssize_t
content_length (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        RETVAL = c->expected_cl;
    OUTPUT:
        RETVAL

SV *
input (struct feer_conn *c)
    PROTOTYPE: $
    CODE:
        if (likely(c->expected_cl > 0)) {
            RETVAL = new_feer_conn_handle(aTHX_ c, 0);
        } else {
            RETVAL = &PL_sv_undef;
        }
    OUTPUT:
        RETVAL

SV *
headers (struct feer_conn *c, int norm = 0)
    PROTOTYPE: $;$
    CODE:
        struct feer_req *r = c->req;
        if (unlikely(!r))
            croak("Cannot access request headers: no active request");
        RETVAL = newRV_noinc((SV*)feersum_env_headers(aTHX_ r, norm));
    OUTPUT:
        RETVAL

SV *
header (struct feer_conn *c, SV *name)
    PROTOTYPE: $$
    CODE:
        struct feer_req *r = c->req;
        if (unlikely(!r))
            croak("Cannot access request header: no active request");
        RETVAL = feersum_env_header(aTHX_ r, name);
    OUTPUT:
        RETVAL

int
fileno (struct feer_conn *c)
    CODE:
        RETVAL = c->fd;
    OUTPUT:
        RETVAL

SV *
io (struct feer_conn *c)
    CODE:
        RETVAL = feersum_env_io(aTHX_ c);
    OUTPUT:
        RETVAL

void
return_from_io (struct feer_conn *c, SV *io_sv)
    PROTOTYPE: $$
    PPCODE:
{
    SSize_t cnt = feersum_return_from_io(aTHX_ c, io_sv, "return_from_io");
    mXPUSHi(cnt);
}

bool
is_keepalive (struct feer_conn *c)
    CODE:
        RETVAL = c->is_keepalive;
    OUTPUT:
        RETVAL

SV*
response_guard (struct feer_conn *c, ...)
    PROTOTYPE: $;$
    CODE:
        RETVAL = feersum_conn_guard(aTHX_ c, (items == 2) ? ST(1) : NULL);
    OUTPUT:
        RETVAL

void
DESTROY (struct feer_conn *c)
    PPCODE:
{
    unsigned i;
    int fd = c->fd;
    trace("DESTROY connection fd=%d c=%p\n", fd, c);

    feer_conn_set_busy(c);

    if (FEERSUM_CONN_FREE_ENABLED()) {
        FEERSUM_CONN_FREE(fd);
    }

    // During global destruction, SV arena is being torn down and refcounts
    // are unreliable. Only close the fd; all memory is reclaimed at exit.
    if (unlikely(PL_phase == PERL_PHASE_DESTRUCT)) {
        safe_close_conn(c, "close at destruction");
        return;
    }

    // Stop any active watchers/timers to prevent them from firing on a freed object.
    // We don't decrement refcount here because DESTROY is already cleaning up.
    if (ev_is_active(&c->read_ev_io)) {
        ev_io_stop(feersum_ev_loop, &c->read_ev_io);
    }
    if (ev_is_active(&c->write_ev_io)) {
        ev_io_stop(feersum_ev_loop, &c->write_ev_io);
    }
    if (ev_is_active(&c->read_ev_timer)) {
        ev_timer_stop(feersum_ev_loop, &c->read_ev_timer);
    }
    if (ev_is_active(&c->header_ev_timer)) {
        ev_timer_stop(feersum_ev_loop, &c->header_ev_timer);
    }
    if (ev_is_active(&c->write_ev_timer)) {
        ev_timer_stop(feersum_ev_loop, &c->write_ev_timer);
    }

    if (likely(c->rbuf)) SvREFCNT_dec(c->rbuf);
    if (c->trailers) SvREFCNT_dec((SV*)c->trailers);
    if (c->proxy_tlvs) SvREFCNT_dec(c->proxy_tlvs);

    if (c->wbuf_rinq) {
        struct iomatrix *m;
        while ((m = (struct iomatrix *)rinq_shift(&c->wbuf_rinq)) != NULL) {
            for (i=0; i < m->count; i++) {
                if (m->sv[i]) SvREFCNT_dec(m->sv[i]);
            }
            IOMATRIX_FREE(m);
        }
    }

    free_request(c);
#ifdef FEERSUM_HAS_H2
    if (c->h2_session)
        feer_h2_free_session(c);
#endif
#ifdef FEERSUM_HAS_TLS
#ifdef FEERSUM_HAS_H2
    if (!c->is_h2_stream)
#endif
        feer_tls_free_conn(c);
#endif
    if (c->remote_addr) SvREFCNT_dec(c->remote_addr);
    if (c->remote_port) SvREFCNT_dec(c->remote_port);

    safe_close_conn(c, "close at destruction");

    if (c->poll_write_cb) SvREFCNT_dec(c->poll_write_cb);
    if (c->poll_read_cb) SvREFCNT_dec(c->poll_read_cb);

    if (c->ext_guard) SvREFCNT_dec(c->ext_guard);

    {
        struct feer_server *server = c->server;
        server->active_conns--;
        SvREFCNT_dec(server->self); // release server ref held since new_feer_conn

        /* If a listener was capacity-paused, clear that bit now that a slot
         * is free. Other pause reasons (user pause_accept, EMFILE backoff)
         * are preserved. */
        if (unlikely(server->max_connections > 0
                     && server->active_conns < server->max_connections
                     && !server->shutting_down)) {
            int i;
            for (i = 0; i < server->n_listeners; i++) {
                struct feer_listen *lsnr = &server->listeners[i];
                if (lsnr->pause_flags & FEER_PAUSE_CAP) {
                    lsnr->pause_flags &= ~FEER_PAUSE_CAP;
                    if (!lsnr->pause_flags && lsnr->fd >= 0)
                        ev_io_start(feersum_ev_loop, &lsnr->accept_w);
                }
            }
        }

        if (unlikely(server->shutting_down && server->active_conns <= 0)) {
            ev_idle_stop(feersum_ev_loop, &server->ei);
            ev_prepare_stop(feersum_ev_loop, &server->ep);
            ev_check_stop(feersum_ev_loop, &server->ec);

            trace3("... was last conn, going to try shutdown\n");
            if (server->shutdown_cb_cv)
                invoke_shutdown_cb(aTHX_ server);
        }
    }
}

