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

    if (unlikely(offset < 0)) {
        /* Count back from the end.  Add rather than negate: -offset is UB at
         * IV_MIN and would wrap to a large positive, walking src_ptr off. */
        offset += c->received_cl;
        if (offset < 0) offset = 0;
    }

    // Defensive: ensure offset doesn't exceed buffer (shouldn't happen in normal operation)
    if (unlikely(offset > (ssize_t)src_len))
        offset = src_len;

    /* Clamp against the buffer BEFORE adding: len is a size_t, so a negative
     * length arrives as a huge one, and len+offset then wraps back under
     * src_len and defeats the check below.  Reading more than the buffer
     * holds is impossible anyway, so this costs a compare and no behaviour. */
    if (unlikely(len > src_len))
        len = src_len;

    if (unlikely(len + offset > src_len))
        len = src_len - offset;

    // Don't read past the body boundary into pipelined data.  Must fire for a
    // DEFINITE length, not merely a positive one: a Content-Length: 0 request
    // with a pipelined one behind it fell through to the steal-whole-rbuf path
    // below, handing the app the next request (Cookie, Authorization and all)
    // as its body and swallowing it.  body_framed keeps a streaming connection,
    // where the app owns everything that arrives, out of the clamp.
    if (c->expected_cl > 0
        || (c->body_framed && c->receiving == RECEIVE_SHUTDOWN)) {
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

    // items == 3 means no offset argument was given.  Without that test the
    // steal-the-whole-rbuf fast path also fired for an explicit read($b,$len,0),
    // which the docs define as reading at an offset WITHOUT advancing the
    // position - so a full-length 3-arg read consumed the body and the next
    // read returned 0.  The slow path below already gates its sv_chop this way.
    if (likely(items == 3 && len == src_len && offset == 0)) {
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

SV *
getline (feer_conn_handle *hdl)
    PROTOTYPE: $
    PPCODE:
{
    STRLEN src_len = 0;
    const char *src_ptr = NULL;

    if (unlikely(c->receiving <= RECEIVE_HEADERS))
        croak("can't call getline() until the body begins to arrive");

    if (likely(c->rbuf))
        src_ptr = SvPV(c->rbuf, src_len);

    /* Same body-boundary clamp as read(): a pipelined next request sharing
     * rbuf must be neither returned nor consumed. */
    ssize_t avail = (ssize_t)src_len;
    int body_done = 0;
    if (c->expected_cl > 0
        || (c->body_framed && c->receiving == RECEIVE_SHUTDOWN)) {
        ssize_t consumed = c->received_cl - (ssize_t)src_len;
        ssize_t remaining_body = c->expected_cl - consumed;
        if (remaining_body <= 0) { remaining_body = 0; body_done = 1; }
        if (avail > remaining_body) avail = remaining_body;
    }

    if (unlikely(avail <= 0)) {
        /* streaming mode may yet deliver more; everything else is EOF */
        if (!body_done && c->receiving != RECEIVE_SHUTDOWN)
            errno = EAGAIN;
        XSRETURN_UNDEF;
    }

    /* $/ shapes the record, as core readline does: plain separator, undef
     * slurp, \N fixed records, "" paragraph mode. */
    STRLEN skip = 0, linelen = 0, trail = 0;
    int have_record = 1;
    SV *rs = PL_rs;
    if (!SvOK(rs)) {
        linelen = (STRLEN)avail;
    }
    else if (SvROK(rs)) {
        IV rec = SvIV(SvRV(rs));
        if (rec < 1) rec = 1; /* perl forbids \0 and negatives at assignment */
        linelen = (rec < (IV)avail) ? (STRLEN)rec : (STRLEN)avail;
    }
    else {
        STRLEN rs_len;
        const char *rs_ptr = SvPV_const(rs, rs_len);
        if (unlikely(rs_len == 0)) {
            /* paragraph mode: leading newlines are separators, the record
             * keeps one terminating "\n\n", any longer run is eaten */
            while ((ssize_t)skip < avail && src_ptr[skip] == '\n')
                skip++;
            if ((ssize_t)skip >= avail) {
                have_record = 0; /* nothing but separators: consume, EOF */
            }
            else {
                const char *found = feer_memfind(src_ptr + skip,
                    (size_t)(avail - (ssize_t)skip), "\n\n", 2);
                if (found) {
                    linelen = (STRLEN)(found - (src_ptr + skip)) + 2;
                    while ((ssize_t)(skip + linelen + trail) < avail
                           && src_ptr[skip + linelen + trail] == '\n')
                        trail++;
                }
                else {
                    linelen = (STRLEN)((size_t)avail - skip);
                }
            }
        }
        else {
            const char *found = feer_memfind(src_ptr, (size_t)avail,
                                             rs_ptr, rs_len);
            linelen = found ? (STRLEN)(found - src_ptr) + rs_len
                            : (STRLEN)avail;
        }
    }

    /* Copy the record out BEFORE the ownership guard can swap rbuf. */
    SV *line = have_record ? newSVpvn(src_ptr + skip, linelen) : NULL;

    STRLEN eat = skip + linelen + trail;
    if (likely(eat > 0)) {
        /* consume, with the same ownership guard read() and seek() use */
        if (unlikely(SvREFCNT(c->rbuf) > 1 || SvREADONLY(c->rbuf))) {
            SV *copy = newSVsv(c->rbuf);
            SvREFCNT_dec(c->rbuf);
            c->rbuf = copy;
        }
        sv_chop(c->rbuf, SvPVX(c->rbuf) + eat);
    }

    trace("getline fd=%d skip=%"Sz_uf" len=%"Sz_uf" trail=%"Sz_uf"\n",
        c->fd, (Sz)skip, (Sz)linelen, (Sz)trail);

    if (unlikely(!line)) {
        if (!body_done && c->receiving != RECEIVE_SHUTDOWN)
            errno = EAGAIN;
        XSRETURN_UNDEF;
    }
    XPUSHs(sv_2mortal(line));
}

STRLEN
write (feer_conn_handle *hdl, ...)
    PROTOTYPE: $;$
    CODE:
{
    // The app answered a poll_cb invitation (even with nothing): counted so
    // the write path can tell engagement from a pure decline.  See
    // poll_writes_seen in feersum_core.h; mirrors the H2 pump's writes_seen.
    c->poll_writes_seen++;

    // substr($x,...) passed straight to write() arrives as a magic lvalue
    // whose value has not been fetched yet, so the SvOK guards below read it
    // as undef and the write silently vanished.  Resolve once here: fetching
    // per SvPV instead would give a tied scalar a different value each time.
    if (unlikely(items == 2 && SvGMAGICAL(ST(1))))
        ST(1) = sv_2mortal(newSVsv(ST(1)));

    // HEAD carries no content, so measure the body and discard it.  Must come
    // before the state check: an H2 no-body response is already completed at
    // start_response, so a delayed handler writing later would croak.
    if (unlikely(c->no_resp_body)) {
        SV *b = (items == 2) ? ST(1) : &PL_sv_undef;
        if (!b || !SvOK(b)) XSRETURN_IV(0);
        if (SvROK(b)) {
            SV *refd = SvRV(b);
            if (SvOK(refd) && SvPOK(refd)) b = refd;
            else croak("body must be a scalar, scalar ref or undef");
        }
        const char *bp = SvPV(b, RETVAL);
        // report the downgraded length the GET twin would have written
        if (unlikely(SvUTF8(b)))
            RETVAL = SvCUR(feer_bytes_mortal(bp, RETVAL));
        XSRETURN_UV(RETVAL);
    }

    if (unlikely(c->responding != RESPOND_STREAMING))
        croak("can only call write in streaming mode");

    // RFC 7230 section 3.3: 1xx/204/205/304 MUST NOT have a body - discard writes
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
    // Downgrade once at the entry so H1/H2, chunked or not, queue the same
    // bytes and RETVAL reports what actually goes on the wire.
    if (unlikely(SvUTF8(body))) {
        STRLEN blen;
        const char *bp = SvPV(body, blen);
        body = feer_bytes_mortal(bp, blen);
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
    c->poll_writes_seen++;   // see write() above

    // See write() above: HEAD must not croak on the state check, because an H2
    // no-body response has already reached RESPOND_SHUTDOWN.
    if (unlikely(c->no_resp_body))
        XSRETURN_EMPTY;

    if (unlikely(c->responding != RESPOND_STREAMING))
        croak("can only call write_array in streaming mode");

    if (unlikely(!c->auto_cl && !h2_is_stream(c)))
        XSRETURN_EMPTY;

    trace("write_array fd=%d c=%p, abody=%p\n", c->fd, c, abody);

    I32 amax = av_len(abody);

    if (h2_is_stream(c)) {
        /* H2 stream: feed each element through the H2 data provider */
        for (I32 i = 0; i <= amax; i++) {
            SV *sv = fetch_av_normal(aTHX_ abody, i);
            if (likely(sv)) h2_try_write_chunk(aTHX_ c, sv);
        }
        XSRETURN_EMPTY;
    }

    if (c->use_chunked) {
        for (I32 i = 0; i <= amax; i++) {
            SV *sv = fetch_av_normal(aTHX_ abody, i);
            if (likely(sv)) add_chunk_sv_to_wbuf(c, sv);
        }
    }
    else {
        for (I32 i = 0; i <= amax; i++) {
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
    c->poll_writes_seen++;   // see write() above

    if (h2_is_stream(c))
        croak("sendfile not supported for HTTP/2 streams (use write instead)");
    if (unlikely(c->responding != RESPOND_STREAMING))
        croak("sendfile: can only call after start_streaming()");

    // HEAD (RFC 9110 9.3.2) or a no-body status: accept the call, transmit
    // nothing.  Same screen as write()/write_array() above - such a response
    // carries no framing, so bytes sent here would desync keepalive.
    if (unlikely(c->no_resp_body || !c->auto_cl))
        XSRETURN_EMPTY;

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
        length = st.st_size - offset;
    }

    if (length == 0)
        XSRETURN_EMPTY;

    trace("sendfile setup: fd=%d file_fd=%d off=%ld len=%zu\n",
        c->fd, file_fd, (long)offset, length);

    // sendfile writes the file verbatim - it cannot chunk-frame it.  On a
    // chunked response the result was a corrupt body: the terminating chunk
    // (queued by close()) drained first, then the file's raw bytes with no
    // framing at all, so a conforming client ended the body at the terminator
    // and the file contents desynced the keepalive connection.  Refuse loudly;
    // an explicit Content-Length suppresses chunking and is the supported way.
    // Checked here, after every file-validity test and the empty-file no-op,
    // so those keep reporting their own more specific errors.
    if (unlikely(c->use_chunked))
        croak("sendfile: needs an explicit Content-Length "
              "(a chunked response cannot frame a raw file transfer)");

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

    // Bytes of THIS request's body still in rbuf.  read() clamps to the same
    // boundary; without it here, seeking past the body chops into a pipelined
    // next request - losing it outright, or leaving a partial one that the
    // parser answers 400 and closes on.  -1 means no framing info: don't clamp.
    ssize_t body_avail = -1;
    if (c->rbuf && (c->expected_cl > 0
                    || (c->body_framed && c->receiving == RECEIVE_SHUTDOWN))) {
        ssize_t consumed = c->received_cl - (ssize_t)SvCUR(c->rbuf);
        body_avail = c->expected_cl - consumed;
        if (body_avail < 0) body_avail = 0;
    }

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
        if (body_avail >= 0 && offset > body_avail)
            offset = body_avail;
        if (offset > len)
            offset = len;
        if (offset > 0) {
            // Ensure we own the buffer before modifying with sv_chop
            // (sv_chop modifies the SV in-place, unsafe if shared)
            if (SvREFCNT(c->rbuf) > 1 || SvREADONLY(c->rbuf)) {
                SV *copy = newSVsv(c->rbuf);
                SvREFCNT_dec(c->rbuf);
                c->rbuf = copy;
                str = SvPV_const(c->rbuf, len);
            }
            sv_chop(c->rbuf, str + offset);
        }
        RETVAL = 1;   // clamped to the body end is still a successful seek
    }
    else if (offset < 0 && whence == SEEK_END) {
        STRLEN len;
        const char *str = SvPV_const(c->rbuf, len);
        // SEEK_END means the end of the BODY, not of rbuf: measuring from
        // rbuf's end would treat a pipelined next request as part of it.
        if (body_avail >= 0 && (STRLEN)body_avail < len)
            len = (STRLEN)body_avail;
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
        if (is_read && c->receiving == RECEIVE_STREAMING) {
            /* Do NOT fall back to RECEIVE_BODY: this request has already been
             * dispatched, and RECEIVE_BODY means "buffer the body, then
             * dispatch" - the next bytes off the socket would dispatch it a
             * second time.  Stop receiving instead. */
            if (c->expected_cl > 0 && c->received_cl < c->expected_cl) {
                /* Body still on the wire and nobody will read it now; it
                 * cannot be drained, so the connection must not be reused. */
                c->is_keepalive = 0;
            }
            finish_receiving(c);
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
            // The app owns the byte stream now, so the request's declared
            // framing no longer bounds it.  Unsetting the reader drops back to
            // RECEIVE_SHUTDOWN, which would otherwise re-apply the read clamp
            // retroactively and strand bytes already in rbuf.
            c->body_framed = 0;
            change_receiving_state(c, RECEIVE_STREAMING);
        }
        // On HTTP/1.x the handler runs only once the body is COMPLETE, so this
        // buffered data is all there will ever be and no read watcher is armed
        // below.  Called once, a callback taking a fixed chunk smaller than the
        // body left the response unfinished with no timer to reap it - so pump
        // while it makes progress.  SvCUR < prev stops a no-op cb spinning.
        if (c->rbuf && SvCUR(c->rbuf) > 0) {
            STRLEN prev;
            do {
                prev = c->rbuf ? SvCUR(c->rbuf) : 0;
                call_poll_callback(c, 0);  // 0 = read callback
            } while (c->poll_read_cb && c->rbuf && SvCUR(c->rbuf) > 0
                     && SvCUR(c->rbuf) < prev
                     && c->receiving < RECEIVE_SHUTDOWN);
        }
        else {
#ifdef FEERSUM_HAS_H2
            // H2 bodies arrive via nghttp2's on_data_chunk_recv, never a socket
            // watcher.  A pseudo-conn is Zero()d, so arming read_ev_io would
            // start a NULL-callback watcher on fd 0 and pin the conn forever.
            if (likely(!c->is_h2_stream))
#endif
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
        /* Flatten here rather than inside feersum_start_response: the PSGI and
         * responder paths already flattened before their framing scan, so
         * doing it there too would rescan the list on every response.  This
         * XSUB runs inside the handler's G_EVAL, so croaking is safe. */
        headers = feersum_flatten_headers(aTHX_ headers);
        if (unlikely(!headers)) croak_sv(ERRSV);
        feersum_start_response(aTHX_ c, message, headers, 1, 0);
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
        /* As in write(): a magic lvalue (substr, $1) has no value yet. */
        if (unlikely(SvGMAGICAL(body)))
            body = sv_2mortal(newSVsv(body));
        if (unlikely(!SvOK(body)))
            croak("can't send_response with an undef body");
        /* Screen the body BEFORE start_response: it queues an unterminated
         * header block, after which a croak cannot become a 500 and the next
         * keepalive response is absorbed into this one.  The PSGI dispatcher
         * pre-validates for the same reason. */
        if (unlikely(SvROK(body))) {
            SV *refd = SvRV(body);
            if (!(SvOK(refd) && !SvROK(refd)) && SvTYPE(refd) != SVt_PVAV)
                croak("body must be a scalar, scalar reference or array reference");
        }
        /* See start_streaming: flattened here, not in start_response. */
        headers = feersum_flatten_headers(aTHX_ headers);
        if (unlikely(!headers)) croak_sv(ERRSV);
        feersum_start_response(aTHX_ c, message, headers, 0, 0);
        /* start_response can complete the response by itself - an H2 stream
         * reset between dispatch and response leaves the pseudo-conn in
         * RESPOND_SHUTDOWN - and write_whole_body would then croak.  Harmless
         * here (this XSUB runs inside the handler's G_EVAL) but it hands the
         * app a spurious exception for a request the client already cancelled.
         * Mirrors the guard on the PSGI path. */
        if (unlikely(c->responding >= RESPOND_SHUTDOWN)) XSRETURN_UV(0);
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
        /* A responder is typically called LATER, from a timer or another
         * callback, by which time _initiate_streaming_psgi's G_EVAL has already
         * returned - so every croak reachable from here has to be converted to
         * call_died, exactly as feersum_handle_psgi_response does for the
         * 3-element form.  Only the status check had been ported; an odd-length
         * or non-arrayref header list, or a CRLF-bearing header, left the client
         * with no response at all, and a holed array segfaulted on the NULL
         * av_fetch below. */
        SV **msg_p  = av_fetch(av, 0, 0);
        SV **hdrs_p = av_fetch(av, 1, 0);
        if (unlikely(!msg_p || !hdrs_p || !*msg_p || !*hdrs_p)) {
            sv_setpvs(ERRSV, "PSGI response starter got a hole in its array-ref");
            call_died(aTHX_ c, "PSGI request");
            XSRETURN_UNDEF;
        }
        SV *message = *msg_p;
        SV *headers = *hdrs_p;
        if (unlikely(!IsArrayRef(headers))) {
            sv_setpvs(ERRSV, "PSGI headers must be an array ref");
            call_died(aTHX_ c, "PSGI request");
            XSRETURN_UNDEF;
        }
        /* Materialise before av_len/AvARRAY touch it: a tied array reports its
         * FETCHSIZE while the C-level AvARRAY may be NULL, and the framing
         * scan below indexes AvARRAY directly - that segfaulted.  A responder
         * runs with no G_EVAL above it, so failures go to call_died. */
        AV *hdr_av = feersum_flatten_headers(aTHX_ (AV*)SvRV(headers));
        if (unlikely(!hdr_av)) {
            call_died(aTHX_ c, "PSGI request");
            XSRETURN_UNDEF;
        }
        if (unlikely((av_len(hdr_av) + 1) % 2 == 1)) {
            sv_setpvs(ERRSV, "PSGI headers must be an even-length array");
            call_died(aTHX_ c, "PSGI request");
            XSRETURN_UNDEF;
        }
        {
            const char *serr = feersum_check_psgi_status(aTHX_ message);
            if (!serr)
                serr = feersum_check_response_framing(aTHX_ message, hdr_av);
            if (unlikely(serr)) {
                sv_setpv(ERRSV, serr);
                call_died(aTHX_ c, "PSGI request");
                XSRETURN_UNDEF;
            }
        }
        feersum_start_response(aTHX_ c, message, hdr_av, 1, 1);
        RETVAL = new_feer_conn_handle(aTHX_ c, 1); // RETVAL gets mortalized
    }
    else {
        /* Same reasoning as the 2-element branch: a responder called from a
         * timer has no G_EVAL above it, so croaking here kills the worker. */
        sv_setpvs(ERRSV, "PSGI response starter expects a 2 or 3 element array-ref");
        call_died(aTHX_ c, "PSGI request");
        XSRETURN_UNDEF;
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
        if (unlikely(!c->req))
            croak("Cannot build the environment: no active request");
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

    // During global destruction, SV arena is being torn down and refcounts
    // are unreliable. Only close the fd; all memory is reclaimed at exit.
    // Checked before feer_conn_set_busy, which writes through c->server: the
    // sweep order is not ours to choose, so touching the server here is a
    // use-after-free waiting for the wrong one.
    if (unlikely(PL_phase == PERL_PHASE_DESTRUCT)) {
        safe_close_conn(c, "close at destruction");
        return;
    }

    feer_conn_set_busy(c);

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

    /* SvREFCNT_dec is NULL-safe - no need to guard each field. */
    SvREFCNT_dec(c->rbuf);
    SvREFCNT_dec((SV*)c->trailers);
    SvREFCNT_dec(c->proxy_tlvs);

    if (c->wbuf_rinq) {
        struct iomatrix *m;
        while ((m = (struct iomatrix *)rinq_shift(&c->wbuf_rinq)) != NULL) {
            for (i=0; i < m->count; i++)
                SvREFCNT_dec(m->sv[i]);
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
    SvREFCNT_dec(c->remote_addr);
    SvREFCNT_dec(c->remote_port);

    safe_close_conn(c, "close at destruction");

    SvREFCNT_dec(c->poll_write_cb);
    SvREFCNT_dec(c->poll_read_cb);
    /* NULL before dec: a guard's DESTROY that touches the connection must not
     * find ext_guard still pointing at the SV perl is in the middle of freeing. */
    { SV *g = c->ext_guard; c->ext_guard = NULL; SvREFCNT_dec(g); }
    /* A request whose response never completed - client gone, error teardown,
     * or an H2 stream, which does not pass through handle_keepalive_or_close -
     * still gets its line here, and the captured SVs are always released. */
    feer_emit_access_log(aTHX_ c);

    {
        struct feer_server *server = c->server;
        server->active_conns--;
#ifdef FEERSUM_HAS_H2
        if (c->is_h2_stream) server->active_h2_streams--;
#endif
        SvREFCNT_dec(server->self); // release server ref held since new_feer_conn

        /* If a listener was capacity-paused, clear that bit now that a slot
         * is free. Other pause reasons (user pause_accept, EMFILE backoff)
         * are preserved. */
        /* Count what admission counts.  An H2 stream holds an active_conns
         * slot but no socket, and a client may hold one open indefinitely, so
         * counting them here left a capacity-paused listener paused for good. */
        int socket_conns = server->active_conns;
#ifdef FEERSUM_HAS_H2
        socket_conns -= server->active_h2_streams;
#endif
        if (unlikely(server->max_connections > 0
                     && socket_conns < server->max_connections
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

