
// Extract first IP from X-Forwarded-For header (leftmost = original client)
static SV*
extract_forwarded_addr(pTHX_ struct feer_req *r)
{
    size_t val_len;
    const char *val = find_header_value(r, "x-forwarded-for", 15, &val_len);
    if (!val || val_len == 0) return NULL;

    // Skip leading whitespace
    while (val_len > 0 && (*val == ' ' || *val == '\t')) { val++; val_len--; }
    if (val_len == 0) return NULL;

    // Find end of first IP (comma or space or end)
    size_t ip_len = 0;
    while (ip_len < val_len && val[ip_len] != ',' && val[ip_len] != ' ') ip_len++;

    if (ip_len == 0 || ip_len > 45) return NULL;  // max IPv6 length is 45 chars

    // Copy to null-terminated buffer for inet_pton validation
    char ip_buf[46];
    memcpy(ip_buf, val, ip_len);
    ip_buf[ip_len] = '\0';

    // Validate as IPv4 or IPv6 address using inet_pton
    struct in_addr addr4;
    struct in6_addr addr6;
    if (inet_pton(AF_INET, ip_buf, &addr4) == 1) {
        return newSVpvn(val, ip_len);  // valid IPv4
    }
    if (inet_pton(AF_INET6, ip_buf, &addr6) == 1) {
        return newSVpvn(val, ip_len);  // valid IPv6
    }

    // Not a valid IP address - return NULL (caller will use original REMOTE_ADDR)
    trace("X-Forwarded-For contains invalid IP: %s\n", ip_buf);
    return NULL;
}

static SV*
extract_forwarded_proto(pTHX_ struct feer_req *r)
{
    size_t val_len;
    const char *val = find_header_value(r, "x-forwarded-proto", 17, &val_len);
    if (!val || val_len == 0) return NULL;

    // Skip whitespace
    while (val_len > 0 && (*val == ' ' || *val == '\t')) { val++; val_len--; }

    // Check for exact https/http (reject "httpx", "https2", etc.)
    if (val_len >= 5 && str_case_eq_fixed("https", val, 5) &&
        (val_len == 5 || val[5] == ' ' || val[5] == '\t' || val[5] == ','))
        return newSVpvs("https");
    if (val_len >= 4 && str_case_eq_fixed("http", val, 4) &&
        (val_len == 4 || val[4] == ' ' || val[4] == '\t' || val[4] == ','))
        return newSVpvs("http");

    return NULL;
}

/* Determine the URL scheme for a connection.
 * Returns a new SV ("https" or forwarded proto), or NULL for default "http". */
static SV *
feer_determine_url_scheme(pTHX_ struct feer_conn *c)
{
#ifdef FEERSUM_HAS_H2
    /* H2 requires TLS (ALPN), so scheme is always https.
     * The :scheme pseudo-header is validated but not propagated. */
    if (c->is_h2_stream) return newSVpvs("https");
#endif
#ifdef FEERSUM_HAS_TLS
    if (c->tls) return newSVpvs("https");
#endif
    if (c->proxy_ssl) return newSVpvs("https");
    if (c->proxy_proto_version > 0 && c->proxy_dst_port == 443)
        return newSVpvs("https");
    if (c->cached_use_reverse_proxy && c->req) {
        SV *fwd = extract_forwarded_proto(aTHX_ c->req);
        if (fwd) return fwd;
    }
    return NULL;
}

// Initialize PSGI env constants (called once at startup)
static void
feersum_init_psgi_env_constants(pTHX)
{
    if (psgi_env_version) return;  // already initialized

    // Only share truly immutable values that middleware will never modify
    psgi_env_version = newRV((SV*)psgi_ver);
    psgi_env_errors = newRV((SV*)PL_stderrgv);
}

// Build PSGI env hash directly (optimized - no template clone)
static HV*
feersum_build_psgi_env(pTHX)
{
    HV *e = newHV();
    // Pre-size hash: ~13 constants + ~10 per-request + ~15 headers = ~38
    hv_ksplit(e, 48);

    // Truly immutable constants - safe to share via refcount
    hv_stores(e, "psgi.version", SvREFCNT_inc_simple_NN(psgi_env_version));
    hv_stores(e, "psgi.errors", SvREFCNT_inc_simple_NN(psgi_env_errors));

    // Boolean constants - PL_sv_yes/no are immortal and safe to share
    hv_stores(e, "psgi.run_once", SvREFCNT_inc_simple_NN(&PL_sv_no));
    hv_stores(e, "psgi.nonblocking", SvREFCNT_inc_simple_NN(&PL_sv_yes));
    hv_stores(e, "psgi.multithread", SvREFCNT_inc_simple_NN(&PL_sv_no));
    hv_stores(e, "psgi.multiprocess", SvREFCNT_inc_simple_NN(&PL_sv_no));
    hv_stores(e, "psgi.streaming", SvREFCNT_inc_simple_NN(&PL_sv_yes));
    hv_stores(e, "psgix.input.buffered", SvREFCNT_inc_simple_NN(&PL_sv_yes));
    hv_stores(e, "psgix.output.buffered", SvREFCNT_inc_simple_NN(&PL_sv_yes));
    hv_stores(e, "psgix.body.scalar_refs", SvREFCNT_inc_simple_NN(&PL_sv_yes));
    hv_stores(e, "psgix.output.guard", SvREFCNT_inc_simple_NN(&PL_sv_yes));

    // Values that middleware might modify - create fresh SVs per request
    // (e.g., Plack::Middleware::ReverseProxy modifies psgi.url_scheme)
    hv_stores(e, "psgi.url_scheme", newSVpvs("http"));
    hv_stores(e, "SCRIPT_NAME", newSVpvs(""));

    return e;
}

static HV*
feersum_env(pTHX_ struct feer_conn *c)
{
    HV *e;
    int i,j;
    struct feer_req *r = c->req;

    // Initialize constants on first call
    if (unlikely(!psgi_env_version))
        feersum_init_psgi_env_constants(aTHX);

    // Build env hash directly instead of cloning template (2x faster)
    e = feersum_build_psgi_env(aTHX);

    trace("generating header (fd %d) %.*s\n",
        c->fd, (int)r->uri_len, r->uri);

    // SERVER_NAME and SERVER_PORT - use per-connection listener so multi-listen
    // reports the correct port for each accepted connection.
    // Create copies since middleware may modify them
    // (e.g., Plack::Middleware::ReverseProxy changes SERVER_PORT based on X-Forwarded-Port)
    {
        struct feer_listen *conn_lsnr = c->listener;
        hv_stores(e, "SERVER_NAME",
            conn_lsnr->server_name ? newSVsv(conn_lsnr->server_name) : newSVpvs(""));
        hv_stores(e, "SERVER_PORT",
            conn_lsnr->server_port ? newSVsv(conn_lsnr->server_port) : newSVpvs("0"));
    }
    hv_stores(e, "REQUEST_URI", feersum_env_uri(aTHX_ r));
#ifdef FEERSUM_HAS_H2
    hv_stores(e, "REQUEST_METHOD", feersum_env_method_h2(aTHX_ c, r));
    if (unlikely(c->is_h2_stream))
        hv_stores(e, "SERVER_PROTOCOL", newSVpvs("HTTP/2"));
    else
#else
    hv_stores(e, "REQUEST_METHOD", feersum_env_method(aTHX_ r));
#endif
    hv_stores(e, "SERVER_PROTOCOL", SvREFCNT_inc_simple_NN(feersum_env_protocol(aTHX_ r)));

    feersum_set_conn_remote_info(aTHX_ c);

    // Reverse proxy mode: trust X-Forwarded-For for REMOTE_ADDR
    if (c->cached_use_reverse_proxy) {
        SV *fwd_addr = extract_forwarded_addr(aTHX_ r);
        hv_stores(e, "REMOTE_ADDR", fwd_addr ? fwd_addr : newSVsv(c->remote_addr));
    } else {
        hv_stores(e, "REMOTE_ADDR", newSVsv(c->remote_addr));
    }
    hv_stores(e, "REMOTE_PORT", newSVsv(c->remote_port));

    {
        SV *scheme = feer_determine_url_scheme(aTHX_ c);
        if (scheme)
            hv_stores(e, "psgi.url_scheme", scheme);
    }

    hv_stores(e, "CONTENT_LENGTH", newSViv(c->expected_cl));

    // Always provide psgi.input (for both PSGI and native handlers)
    // For requests without body, it will be an empty stream (returns 0 on read)
    hv_stores(e, "psgi.input", new_feer_conn_handle(aTHX_ c, 0));

    if (c->cached_request_cb_is_psgi) {
        SV *fake_fh = newSViv(c->fd); // fd value for psgix.io magic backing SV
        SV *selfref = sv_2mortal(feer_conn_2sv(c));
        sv_magicext(fake_fh, selfref, PERL_MAGIC_ext, &psgix_io_vtbl, NULL, 0);
        hv_stores(e, "psgix.io", fake_fh);
    }

    if (c->trailers) {
        hv_stores(e, "psgix.h2.trailers", newRV_inc((SV*)c->trailers));
    }

    if (c->proxy_tlvs) {
        hv_stores(e, "psgix.proxy_tlvs", SvREFCNT_inc_simple_NN(c->proxy_tlvs));
    }

    if (likely(!r->path)) feersum_set_path_and_query(aTHX_ r);
    hv_stores(e, "PATH_INFO", SvREFCNT_inc_simple_NN(r->path));
    hv_stores(e, "QUERY_STRING", SvREFCNT_inc_simple_NN(r->query));

    SV *cur_val = NULL;  // tracks current header value for multi-value header merging
    char *kbuf = header_key_buf; // use static buffer (pre-initialized with "HTTP_")

    for (i=0; i<r->num_headers; i++) {
        struct phr_header *hdr = &(r->headers[i]);
        // Note: obs-fold (hdr->name == NULL) is rejected at parse time per RFC 7230
        if (unlikely(hdr->name_len == 14) &&
            str_case_eq_fixed("content-length", hdr->name, 14))
        {
            // content length shouldn't show up as HTTP_CONTENT_LENGTH but
            // as CONTENT_LENGTH in the env-hash.
            continue;
        }
        else if (unlikely(hdr->name_len == 12) &&
            str_case_eq_fixed("content-type", hdr->name, 12))
        {
            cur_val = newSVpvn(hdr->value, hdr->value_len);
            hv_stores(e, "CONTENT_TYPE", cur_val);
            continue;
        }

        // Skip headers with names too long for our buffer (defensive - should be
        // rejected at parse time with 431, but guard against edge cases)
        if (unlikely(hdr->name_len > MAX_HEADER_NAME_LEN)) {
            trace("skipping oversized header name (len=%zu) on fd %d\n",
                  hdr->name_len, c->fd);
            continue;
        }

        size_t klen = 5+hdr->name_len;
        char *key = kbuf + 5;
        for (j=0; j<hdr->name_len; j++) {
            // Use combined lookup table (uppercase + dash-to-underscore)
            *key++ = ascii_upper_dash[(unsigned char)hdr->name[j]];
        }

        SV **fetched = hv_fetch(e, kbuf, klen, 1);
        trace("adding header to env (fd %d) %.*s: %.*s\n",
            c->fd, (int)klen, kbuf, (int)hdr->value_len, hdr->value);

        // hv_fetch with lval=1 should always succeed, but check for OOM safety
        if (unlikely(fetched == NULL)) {
            trace("hv_fetch returned NULL (OOM?) on fd %d\n", c->fd);
            continue;
        }
        cur_val = *fetched;  // track for multi-value header merging
        if (unlikely(SvPOK(cur_val))) {
            trace("... is multivalue\n");
            // extend header with comma
            sv_catpvn(cur_val, ", ", 2);
            sv_catpvn(cur_val, hdr->value, hdr->value_len);
        }
        else {
            // change from undef to a real value
            sv_setpvn(cur_val, hdr->value, hdr->value_len);
        }
    }

#ifdef FEERSUM_HAS_H2
    /* Map :authority pseudo-header to HTTP_HOST for H2 streams (RFC 9113 §8.3.1).
     * Only set if no regular Host header was already present. */
    if (unlikely(c->is_h2_stream)) {
        struct feer_h2_stream *stream = (struct feer_h2_stream *)c->read_ev_timer.data;
        if (stream && stream->h2_authority && !hv_exists(e, "HTTP_HOST", 9)) {
            STRLEN alen;
            const char *aval = SvPV(stream->h2_authority, alen);
            hv_stores(e, "HTTP_HOST", newSVpvn(aval, alen));
        }
        /* Extended CONNECT (RFC 8441): REQUEST_METHOD already set to GET
         * above; add remaining H1-equivalent headers so existing PSGI
         * WebSocket middleware works transparently.
         * Matches HAProxy/nghttpx H2↔H1 upgrade translation. */
        if (stream && stream->is_tunnel && stream->h2_protocol) {
            STRLEN plen;
            const char *pval = SvPV(stream->h2_protocol, plen);
            hv_stores(e, "HTTP_UPGRADE", newSVpvn(pval, plen));
            hv_stores(e, "HTTP_CONNECTION", newSVpvs("Upgrade"));
            hv_stores(e, "psgix.h2.protocol", newSVpvn(pval, plen));
            hv_stores(e, "psgix.h2.extended_connect", newSViv(1));
        }
    }
#endif

    return e;
}

#define COPY_NORM_HEADER(_str) \
for (i = 0; i < r->num_headers; i++) {\
    struct phr_header *hdr = &(r->headers[i]);\
    /* Invariant: obs-fold and oversized names already rejected at parse time */\
    if (unlikely(hdr->name_len > MAX_HEADER_NAME_LEN)) continue; /* defense-in-depth */\
    char *k = kbuf;\
    for (j = 0; j < hdr->name_len; j++) { char n = hdr->name[j]; *k++ = _str; }\
    SV** val = hv_fetch(e, kbuf, hdr->name_len, 1);\
    if (unlikely(!val)) continue; /* OOM safety */\
    if (unlikely(SvPOK(*val))) {\
        sv_catpvn(*val, ", ", 2);\
        sv_catpvn(*val, hdr->value, hdr->value_len);\
    } else {\
        sv_setpvn(*val, hdr->value, hdr->value_len);\
    }\
}\
break;

// Static buffer for feersum_env_headers (reuses header_key_buf area after HTTP_ prefix)
static HV*
feersum_env_headers(pTHX_ struct feer_req *r, int norm)
{
    size_t i; size_t j; HV* e;
    e = newHV();
    // Pre-allocate hash buckets based on expected header count to avoid rehashing
    if (r->num_headers > 0)
        hv_ksplit(e, r->num_headers);
    char *kbuf = header_key_buf + 5; // reuse static buffer, skip the "HTTP_" prefix area
    switch (norm) {
        case HEADER_NORM_SKIP:
            COPY_NORM_HEADER(n)
        case HEADER_NORM_LOCASE:
            COPY_NORM_HEADER(ascii_lower[(unsigned char)n])
        case HEADER_NORM_UPCASE:
            COPY_NORM_HEADER(ascii_upper[(unsigned char)n])
        case HEADER_NORM_LOCASE_DASH:
            COPY_NORM_HEADER(ascii_lower_dash[(unsigned char)n])
        case HEADER_NORM_UPCASE_DASH:
            COPY_NORM_HEADER(ascii_upper_dash[(unsigned char)n])
        default:
            break;
    }
    return e;
}

INLINE_UNLESS_DEBUG static SV*
feersum_env_header(pTHX_ struct feer_req *r, SV *name)
{
    size_t i;
    for (i = 0; i < r->num_headers; i++) {
        struct phr_header *hdr = &(r->headers[i]);
        // Note: continuation headers (name == NULL) are rejected at parse time
        if (unlikely(hdr->name_len == SvCUR(name)
            && str_case_eq_both(SvPVX(name), hdr->name, hdr->name_len))) {
            return newSVpvn(hdr->value, hdr->value_len);
        }
    }
    return &PL_sv_undef;
}

INLINE_UNLESS_DEBUG static ssize_t
feersum_env_content_length(pTHX_ struct feer_conn *c)
{
    return c->expected_cl;
}

static SV*
feersum_env_io(pTHX_ struct feer_conn *c)
{
    dSP;

    // Prevent double-call: io() can only be called once per connection
    if (unlikely(c->io_taken))
        croak("io() already called on this connection");

    trace("feersum_env_io for fd=%d\n", c->fd);

#ifdef FEERSUM_HAS_H2
    /* H2 tunnel: auto-accept, create socketpair, expose sv[1] as IO handle */
    if (c->is_h2_stream) {
        struct feer_h2_stream *stream = (struct feer_h2_stream *)c->read_ev_timer.data;
        if (!stream || !stream->is_tunnel)
            croak("io() is not supported on regular HTTP/2 streams");
        h2_tunnel_auto_accept(aTHX_ c, stream);
        /* Re-fetch stream: auto_accept → session_send may have freed it */
        stream = (struct feer_h2_stream *)c->read_ev_timer.data;
        if (!stream)
            croak("io() tunnel: stream freed during auto-accept");
        feer_h2_setup_tunnel(aTHX_ stream);
        if (!stream->tunnel_established)
            croak("Failed to create tunnel socketpair");

        SV *sv = newSViv(stream->tunnel_sv1);

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv);
        mXPUSHs(newSViv(stream->tunnel_sv1));
        PUTBACK;

        call_pv("Feersum::Connection::_raw", G_VOID|G_DISCARD|G_EVAL);
        SPAGAIN;

        if (unlikely(SvTRUE(ERRSV))) {
            FREETMPS;
            LEAVE;
            SvREFCNT_dec(sv);
            croak("Failed to create tunnel IO handle: %-p", ERRSV);
        }

        if (unlikely(!SvROK(sv))) {
            /* _raw failed: new_from_fd returned undef.
             * Leave tunnel_sv1 intact so feer_h2_stream_free closes it. */
            FREETMPS;
            LEAVE;
            SvREFCNT_dec(sv);
            croak("Failed to create tunnel IO handle");
        }

        SV *io_glob = SvRV(sv);
        GvSV(io_glob) = newRV_inc(c->self);

        /* sv[1] now owned by the IO handle */
        stream->tunnel_sv1 = -1;
        c->io_taken = 1;

        FREETMPS;
        LEAVE;
        return sv;
    }
#endif

#ifdef FEERSUM_HAS_TLS
    /* TLS tunnel: create socketpair relay for bidirectional I/O over TLS */
    if (c->tls) {
        feer_tls_setup_tunnel(c);
        if (!c->tls_tunnel)
            croak("Failed to create TLS tunnel socketpair");

        SV *sv = newSViv(c->tls_tunnel_sv1);

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv);
        mXPUSHs(newSViv(c->tls_tunnel_sv1));
        PUTBACK;

        call_pv("Feersum::Connection::_raw", G_VOID|G_DISCARD|G_EVAL);
        SPAGAIN;

        if (unlikely(SvTRUE(ERRSV))) {
            FREETMPS;
            LEAVE;
            SvREFCNT_dec(sv);
            croak("Failed to create TLS tunnel IO handle: %-p", ERRSV);
        }

        if (unlikely(!SvROK(sv))) {
            /* _raw failed: new_from_fd returned undef.
             * Leave tls_tunnel_sv1 intact so feer_tls_free_conn closes it. */
            FREETMPS;
            LEAVE;
            SvREFCNT_dec(sv);
            croak("Failed to create TLS tunnel IO handle");
        }

        SV *io_glob = SvRV(sv);
        GvSV(io_glob) = newRV_inc(c->self);

        /* sv[1] now owned by the IO handle */
        c->tls_tunnel_sv1 = -1;
        c->io_taken = 1;
        stop_read_timer(c);
        stop_write_timer(c);

        /* Keep read watcher active — TLS reads relay to tunnel */

        FREETMPS;
        LEAVE;
        return sv;
    }
#endif

    // Create a scalar to hold the IO handle
    SV *sv = newSViv(c->fd);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv);
    mXPUSHs(newSViv(c->fd));
    PUTBACK;

    // Call Feersum::Connection::_raw to create IO::Socket::INET
    call_pv("Feersum::Connection::_raw", G_VOID|G_DISCARD|G_EVAL);
    SPAGAIN;

    if (unlikely(SvTRUE(ERRSV))) {
        FREETMPS;
        LEAVE;
        SvREFCNT_dec(sv);
        croak("Failed to create IO handle: %-p", ERRSV);
    }

    // Verify _raw created a valid reference
    if (unlikely(!SvROK(sv))) {
        FREETMPS;
        LEAVE;
        SvREFCNT_dec(sv);
        croak("Failed to create IO handle: new_from_fd returned undef");
    }

    // Store back-reference to connection in the glob's scalar slot
    SV *io_glob = SvRV(sv);
    GvSV(io_glob) = newRV_inc(c->self);

    // Push any remaining rbuf data into the socket buffer
    if (likely(c->rbuf && SvOK(c->rbuf) && SvCUR(c->rbuf))) {
        STRLEN rbuf_len;
        const char *rbuf_ptr = SvPV(c->rbuf, rbuf_len);
        IO *io = GvIOp(io_glob);
        if (io) {
            SSize_t pushed = PerlIO_unread(IoIFP(io), (const void *)rbuf_ptr, rbuf_len);
            if (likely(pushed == (SSize_t)rbuf_len)) {
                SvCUR_set(c->rbuf, 0);
                *SvPVX(c->rbuf) = '\0';
            } else if (pushed > 0) {
                sv_chop(c->rbuf, rbuf_ptr + pushed);
                trouble("PerlIO_unread partial in io(): %zd of %"Sz_uf" bytes fd=%d\n",
                    pushed, (Sz)rbuf_len, c->fd);
            } else {
                trouble("PerlIO_unread failed in io() fd=%d\n", c->fd);
            }
        }
    }

    // Stop Feersum's watchers - user now owns the socket
    stop_read_watcher(c);
    stop_read_timer(c);
    stop_write_timer(c);
    // don't stop write watcher in case there's outstanding data

    // Mark that io() was called
    c->io_taken = 1;

    FREETMPS;
    LEAVE;

    return sv;
}

static SSize_t
feersum_return_from_io(pTHX_ struct feer_conn *c, SV *io_sv, const char *func_name)
{
#ifdef FEERSUM_HAS_H2
    if (unlikely(c->is_h2_stream))
        croak("%s: not supported on HTTP/2 streams", func_name);
#endif

    if (!SvROK(io_sv) || !isGV_with_GP(SvRV(io_sv)))
        croak("%s requires a filehandle", func_name);

    GV *gv = (GV *)SvRV(io_sv);
    IO *io = GvIO(gv);
    if (!io || !IoIFP(io))
        croak("%s: invalid filehandle", func_name);

    PerlIO *fp = IoIFP(io);

    // Check if there's buffered data to pull back
    SSize_t cnt = PerlIO_get_cnt(fp);
    if (cnt > 0) {
        // Get pointer to buffered data
        // Note: ptr remains valid until next PerlIO operation on fp.
        // sv_catpvn doesn't touch fp, so this is safe.
        STDCHAR *ptr = PerlIO_get_ptr(fp);
        if (ptr) {
            // Ensure we have an rbuf
            if (!c->rbuf)
                c->rbuf = newSV(READ_BUFSZ);

            // Append buffered data to feersum's rbuf
            sv_catpvn(c->rbuf, (const char *)ptr, cnt);

            // Mark buffer as consumed (must happen before any other PerlIO ops)
            PerlIO_set_ptrcnt(fp, ptr + cnt, 0);

            trace("pulled %zd bytes back to feersum fd=%d\n", (size_t)cnt, c->fd);
        }
    }

    /* Reset connection state for next request (like keepalive reset) */
    change_responding_state(c, RESPOND_NOT_STARTED);
    change_receiving_state(c, RECEIVE_HEADERS);
    c->expected_cl = 0;
    c->received_cl = 0;
    c->io_taken = 0;
    free_request(c);

    if (c->rbuf && cnt <= 0)
        SvCUR_set(c->rbuf, 0);

    start_read_watcher(c);
    restart_read_timer(c);

    return cnt > 0 ? cnt : 0;
}

static void
feersum_start_response (pTHX_ struct feer_conn *c, SV *message, AV *headers,
                        int streaming)
{
    const char *ptr;
    I32 i;

    trace("start_response fd=%d streaming=%d\n", c->fd, streaming);

    if (unlikely(!SvOK(message) || !(SvIOK(message) || SvPOK(message)))) {
        croak("Must define an HTTP status code or message");
    }

    I32 avl = av_len(headers);
    if (unlikely((avl+1) % 2 == 1)) {
        croak("expected even-length array, got %d", avl+1);
    }

#ifdef FEERSUM_HAS_H2
    if (unlikely(c->is_h2_stream)) {
        feersum_h2_start_response(aTHX_ c, message, headers, streaming);
        return;
    }
#endif

    if (unlikely(c->responding != RESPOND_NOT_STARTED))
        croak("already responding?!");
    change_responding_state(c, streaming ? RESPOND_STREAMING : RESPOND_NORMAL);

    // int or 3 chars? use a stock message
    UV code = 0;
    if (SvIOK(message))
        code = SvIV(message);
    else {
        STRLEN mlen = SvCUR(message);
        const int numtype = grok_number(SvPVX_const(message), mlen > 3 ? 3 : mlen, &code);
        if (unlikely(numtype != IS_NUMBER_IN_UV))
            code = 0;
    }
    trace2("starting response fd=%d code=%"UVuf"\n",c->fd,code);

    if (unlikely(!code))
        croak("first parameter is not a number or doesn't start with digits");

    if (FEERSUM_RESP_START_ENABLED()) {
        FEERSUM_RESP_START(c->fd, (int)code);
    }

    // for PSGI it's always just an IV so optimize for that
    if (likely(!SvPOK(message) || SvCUR(message) == 3)) {
        // Use cached status SVs for common codes to avoid newSVpvf overhead
        switch (code) {
            case 200: message = status_200; break;
            case 201: message = status_201; break;
            case 204: message = status_204; break;
            case 301: message = status_301; break;
            case 302: message = status_302; break;
            case 304: message = status_304; break;
            case 400: message = status_400; break;
            case 404: message = status_404; break;
            case 500: message = status_500; break;
            default:
                ptr = http_code_to_msg(code);
                message = sv_2mortal(newSVpvf("%"UVuf" %s",code,ptr));
                break;
        }
    }

    // don't generate or strip Content-Length headers for responses that MUST NOT have a body
    // RFC 7230: 1xx, 204, 205, 304 responses MUST NOT contain a message body
    c->auto_cl = (code == 204 || code == 205 || code == 304 ||
                  (100 <= code && code <= 199)) ? 0 : 1;

    add_const_to_wbuf(c, c->is_http11 ? "HTTP/1.1 " : "HTTP/1.0 ", 9);
    add_sv_to_wbuf(c, message);
    add_crlf_to_wbuf(c);

    bool has_content_length = 0;
    SV **ary = AvARRAY(headers);
    for (i=0; i<avl; i+= 2) {
        SV *hdr = ary[i];
        SV *val = ary[i+1];
        if (unlikely(!hdr || !SvOK(hdr))) {
            trace("skipping undef header key");
            continue;
        }
        if (unlikely(!val || !SvOK(val))) {
            trace("skipping undef header value");
            continue;
        }

        STRLEN hlen;
        const char *hp = SvPV(hdr, hlen);
        if (unlikely(hlen == 14) && str_case_eq_fixed("content-length", hp, 14)) {
            if (likely(c->auto_cl) && !streaming) {
                trace("ignoring content-length header in the response\n");
                continue;
            }
            // In streaming mode, keep Content-Length (for sendfile support)
            has_content_length = 1;
        }

        add_sv_to_wbuf(c, hdr);
        add_const_to_wbuf(c, ": ", 2);
        add_sv_to_wbuf(c, val);
        add_crlf_to_wbuf(c);
    }

    if (likely(c->is_http11)) {
        #ifdef DATE_HEADER
        // DATE_BUF is updated by periodic timer (date_timer_cb) every second
        add_const_to_wbuf(c, DATE_BUF, DATE_HEADER_LENGTH);
        #endif
        if (!c->is_keepalive)
            add_const_to_wbuf(c, "Connection: close" CRLF, 19);
    } else if (c->is_keepalive && !streaming)
        add_const_to_wbuf(c, "Connection: keep-alive" CRLF, 24);

    if (streaming) {
        // Use chunked encoding only if no Content-Length provided
        // (Content-Length is used with sendfile for zero-copy file transfer)
        // Skip chunked for 1xx responses (e.g. 101 Switching Protocols)
        if (c->is_http11 && !has_content_length && code >= 200) {
            add_const_to_wbuf(c, "Transfer-Encoding: chunked" CRLFx2, 30);
            c->use_chunked = 1;
        }
        else {
            add_crlf_to_wbuf(c);
            c->use_chunked = 0;
            // cant do keep-alive for streaming http/1.0 since client completes read on close
            if (c->is_keepalive && !has_content_length) c->is_keepalive = 0;
        }
    }

    // For streaming responses, start writing headers immediately.
    // For non-streaming (RESPOND_NORMAL), feersum_write_whole_body will
    // call conn_write_ready after the body is buffered. This is critical
    // because conn_write_ready triggers immediate writes and would
    // prematurely finish the response before body is ready.
    if (streaming)
        conn_write_ready(c);
}

static size_t
feersum_write_whole_body (pTHX_ struct feer_conn *c, SV *body)
{
    size_t RETVAL;
    I32 i;
    bool body_is_string = 0;
    STRLEN cur;

    if (c->responding != RESPOND_NORMAL)
        croak("can't use write_whole_body when in streaming mode");

#ifdef FEERSUM_HAS_H2
    if (unlikely(c->is_h2_stream)) {
        /* H2 streams use nghttp2 submit_response, not wbuf */
        SV *body_sv;
        if (!SvOK(body)) {
            body_sv = sv_2mortal(newSVpvs(""));
        } else if (SvROK(body)) {
            SV *refd = SvRV(body);
            if (SvOK(refd) && !SvROK(refd)) {
                body_sv = refd;
            } else if (SvTYPE(refd) == SVt_PVAV) {
                AV *ab = (AV*)refd;
                body_sv = sv_2mortal(newSVpvs(""));
                I32 amax = av_len(ab);
                for (i = 0; i <= amax; i++) {
                    SV *sv = fetch_av_normal(aTHX_ ab, i);
                    if (sv) sv_catsv(body_sv, sv);
                }
            } else {
                croak("body must be a scalar, scalar reference or array reference");
            }
        } else {
            body_sv = body;
        }
        return feersum_h2_write_whole_body(aTHX_ c, body_sv);
    }
#endif

    if (!SvOK(body)) {
        body = sv_2mortal(newSVpvs(""));
        body_is_string = 1;
    }
    else if (SvROK(body)) {
        SV *refd = SvRV(body);
        if (SvOK(refd) && !SvROK(refd)) {
            body = refd;
            body_is_string = 1;
        }
        else if (SvTYPE(refd) != SVt_PVAV) {
            croak("body must be a scalar, scalar reference or array reference");
        }
    }
    else {
        body_is_string = 1;
    }

    SV *cl_sv; // content-length future
    struct iovec *cl_iov;
    if (likely(c->auto_cl))
        add_placeholder_to_wbuf(c, &cl_sv, &cl_iov);
    else
        add_crlf_to_wbuf(c);

    if (body_is_string) {
        cur = add_sv_to_wbuf(c,body);
        RETVAL = cur;
    }
    else {
        AV *abody = (AV*)SvRV(body);
        I32 amax = av_len(abody);
        RETVAL = 0;
        for (i=0; i<=amax; i++) {
            SV *sv = fetch_av_normal(aTHX_ abody, i);
            if (unlikely(!sv)) continue;
            cur = add_sv_to_wbuf(c,sv);
            trace("body part i=%d sv=%p cur=%"Sz_uf"\n", i, sv, (Sz)cur);
            RETVAL += cur;
        }
    }

    if (likely(c->auto_cl)) {
        char cl_buf[48];  // 16 (prefix) + 20 (max uint64) + 4 (CRLF x2) + padding
        int cl_len = format_content_length(cl_buf, RETVAL);
        sv_setpvn(cl_sv, cl_buf, cl_len);
        update_wbuf_placeholder(c, cl_sv, cl_iov);
    }

    change_responding_state(c, RESPOND_SHUTDOWN);
    conn_write_ready(c);
    return RETVAL;
}

static void
call_died (pTHX_ struct feer_conn *c, const char *cb_type)
{
    dSP;
#if DEBUG >= 1
    trace("An error was thrown in the %s callback: %-p\n",cb_type,ERRSV);
#endif
    PUSHMARK(SP);
    mXPUSHs(newSVsv(ERRSV));
    PUTBACK;
    call_pv("Feersum::DIED", G_DISCARD|G_EVAL|G_VOID);
    SPAGAIN;

    respond_with_server_error(c, "Request handler exception\n", 500);
    sv_setsv(ERRSV, &PL_sv_undef);
}

static void
feersum_start_psgi_streaming(pTHX_ struct feer_conn *c, SV *streamer)
{
    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    mXPUSHs(feer_conn_2sv(c));
    XPUSHs(streamer);
    PUTBACK;
    call_method("_initiate_streaming_psgi", G_DISCARD|G_EVAL|G_VOID);
    SPAGAIN;
    if (unlikely(SvTRUE(ERRSV))) {
        call_died(aTHX_ c, "PSGI stream initiator");
    }
    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void
feersum_handle_psgi_response(
    pTHX_ struct feer_conn *c, SV *ret, bool can_recurse)
{
    if (unlikely(!SvOK(ret) || !SvROK(ret))) {
        sv_setpvs(ERRSV, "Invalid PSGI response (expected reference)");
        call_died(aTHX_ c, "PSGI request");
        return;
    }

    if (unlikely(!IsArrayRef(ret))) {
        if (likely(can_recurse)) {
            trace("PSGI response non-array, c=%p ret=%p\n", c, ret);
            feersum_start_psgi_streaming(aTHX_ c, ret);
        }
        else {
            sv_setpvs(ERRSV, "PSGI attempt to recurse in a streaming callback");
            call_died(aTHX_ c, "PSGI request");
        }
        return;
    }

    AV *psgi_triplet = (AV*)SvRV(ret);
    if (unlikely(av_len(psgi_triplet)+1 != 3)) {
        sv_setpvs(ERRSV, "Invalid PSGI array response (expected triplet)");
        call_died(aTHX_ c, "PSGI request");
        return;
    }

    trace("PSGI response triplet, c=%p av=%p\n", c, psgi_triplet);
    // we know there's three elems so *should* be safe to de-ref
    SV **msg_p  = av_fetch(psgi_triplet,0,0);
    SV **hdrs_p = av_fetch(psgi_triplet,1,0);
    SV **body_p = av_fetch(psgi_triplet,2,0);
    if (unlikely(!msg_p || !hdrs_p || !body_p)) {
        sv_setpvs(ERRSV, "Invalid PSGI array response (NULL element)");
        call_died(aTHX_ c, "PSGI request");
        return;
    }
    SV *msg  = *msg_p;
    SV *hdrs = *hdrs_p;
    SV *body = *body_p;

    AV *headers;
    if (IsArrayRef(hdrs))
        headers = (AV*)SvRV(hdrs);
    else {
        sv_setpvs(ERRSV, "PSGI Headers must be an array-ref");
        call_died(aTHX_ c, "PSGI request");
        return;
    }

    if (likely(IsArrayRef(body))) {
        feersum_start_response(aTHX_ c, msg, headers, 0);
        feersum_write_whole_body(aTHX_ c, body);
    }
    else if (likely(SvROK(body))) { // probably an IO::Handle-like object
        feersum_start_response(aTHX_ c, msg, headers, 1);
#ifdef FEERSUM_HAS_H2
        if (unlikely(c->is_h2_stream)) {
            /* H2: drain the IO::Handle synchronously since there is no
             * per-stream write watcher; nghttp2 handles flow control. */
            pump_h2_io_handle(aTHX_ c, body);
        } else
#endif
        {
            c->poll_write_cb = newSVsv(body);
            c->poll_write_cb_is_io_handle = 1;
            conn_write_ready(c);
        }
    }
    else {
        sv_setpvs(ERRSV, "Expected PSGI array-ref or IO::Handle-like body");
        call_died(aTHX_ c, "PSGI request");
        return;
    }
}

static int
feersum_close_handle (pTHX_ struct feer_conn *c, bool is_writer)
{
    int RETVAL;
    if (is_writer) {
        trace("close writer fd=%d, c=%p, refcnt=%d\n", c->fd, c, SvREFCNT(c->self));
        if (c->poll_write_cb) {
            SV *tmp = c->poll_write_cb;
            c->poll_write_cb = NULL;  // NULL before dec: prevents re-entrant double-free
            c->poll_write_cb_is_io_handle = 0;
            SvREFCNT_dec(tmp);
        }
#ifdef FEERSUM_HAS_H2
        if (unlikely(c->is_h2_stream)) {
            if (c->responding < RESPOND_SHUTDOWN) {
                feersum_h2_close_write(aTHX_ c);
                change_responding_state(c, RESPOND_SHUTDOWN);
            }
        } else
#endif
        if (c->responding < RESPOND_SHUTDOWN) {
            finish_wbuf(c);  // only adds terminator if use_chunked is set
            change_responding_state(c, RESPOND_SHUTDOWN);
            conn_write_ready(c);
        }
        RETVAL = 1;
    }
    else {
        trace("close reader fd=%d, c=%p\n", c->fd, c);
        if (c->poll_read_cb) {
            SV *tmp = c->poll_read_cb;
            c->poll_read_cb = NULL;
            SvREFCNT_dec(tmp);
        }
        if (c->rbuf) {
            SvREFCNT_dec(c->rbuf);
            c->rbuf = NULL;
        }
        if (c->fd >= 0
#ifdef FEERSUM_HAS_H2
            && !c->is_h2_stream
#endif
        )
            RETVAL = shutdown(c->fd, SHUT_RD);
        else
            RETVAL = -1;  // already closed or H2 stream
        change_receiving_state(c, RECEIVE_SHUTDOWN);
    }

    // disassociate the handle from the conn
    SvREFCNT_dec(c->self);
    return RETVAL;
}

static SV*
feersum_conn_guard(pTHX_ struct feer_conn *c, SV *guard)
{
    if (guard) {
        if (c->ext_guard) SvREFCNT_dec(c->ext_guard);
        c->ext_guard = SvOK(guard) ? newSVsv(guard) : NULL;
    }
    return c->ext_guard ? newSVsv(c->ext_guard) : &PL_sv_undef;
}

static void
call_request_callback (struct feer_conn *c)
{
    dTHX;
    dSP;
    int flags;
    struct feer_server *server = c->server;
    c->in_callback++;
    SvREFCNT_inc_void_NN(c->self);
    server->total_requests++;

    trace("request callback c=%p\n", c);

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);

    if (server->request_cb_is_psgi) {
        HV *env = feersum_env(aTHX_ c);
        mXPUSHs(newRV_noinc((SV*)env));
        flags = G_EVAL|G_SCALAR;
    }
    else {
        mXPUSHs(feer_conn_2sv(c));
        flags = G_DISCARD|G_EVAL|G_VOID;
    }

    PUTBACK;
    int returned = call_sv(server->request_cb_cv, flags);
    SPAGAIN;

    trace("called request callback, errsv? %d\n", SvTRUE(ERRSV) ? 1 : 0);

    if (unlikely(SvTRUE(ERRSV))) {
        call_died(aTHX_ c, "request");
        returned = 0; // pretend nothing got returned
    }

    SV *psgi_response = NULL;
    if (server->request_cb_is_psgi && likely(returned >= 1)) {
        psgi_response = POPs;
        SvREFCNT_inc_void_NN(psgi_response);
    }

    trace("leaving request callback\n");
    PUTBACK;

    if (psgi_response) {
        feersum_handle_psgi_response(aTHX_ c, psgi_response, 1); // can_recurse
        SvREFCNT_dec(psgi_response);
    }

    c->in_callback--;
    SvREFCNT_dec(c->self);

    FREETMPS;
    LEAVE;
}

static void
call_poll_callback (struct feer_conn *c, bool is_write)
{
    dTHX;
    dSP;

    SV *cb = (is_write) ? c->poll_write_cb : c->poll_read_cb;

    if (unlikely(cb == NULL)) return;

    c->in_callback++;

    trace("%s poll callback c=%p cbrv=%p\n",
        is_write ? "write" : "read", c, cb);

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    SV *hdl = new_feer_conn_handle(aTHX_ c, is_write);
    mXPUSHs(hdl);
    PUTBACK;
    call_sv(cb, G_DISCARD|G_EVAL|G_VOID);
    SPAGAIN;

    trace("called %s poll callback, errsv? %d\n",
        is_write ? "write" : "read", SvTRUE(ERRSV) ? 1 : 0);

    if (unlikely(SvTRUE(ERRSV))) {
        call_died(aTHX_ c, is_write ? "write poll" : "read poll");
    }

    // Neutralize the mortal handle before FREETMPS so its DESTROY doesn't
    // call feersum_close_handle and prematurely close the connection.
    // If the callback already called close(), SvUVX is already 0.
    {
        SV *inner = SvRV(hdl);
        if (SvUVX(inner)) {
            SvUVX(inner) = 0;
            SvREFCNT_dec(c->self);  // balance new_feer_conn_handle's inc
        }
    }

    trace("leaving %s poll callback\n", is_write ? "write" : "read");
    PUTBACK;
    FREETMPS;
    LEAVE;

    c->in_callback--;
}

static void
pump_io_handle (struct feer_conn *c, SV *io)
{
    dTHX;
    dSP;

    if (unlikely(io == NULL)) return;

    c->in_callback++;

    trace("pump io handle %d\n", c->fd);

    SV *old_rs = PL_rs;
    SvREFCNT_inc_simple_void(old_rs);
    PL_rs = sv_2mortal(newRV_noinc(newSViv(IO_PUMP_BUFSZ)));
    sv_setsv(get_sv("/", GV_ADD), PL_rs);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(c->poll_write_cb);
    PUTBACK;
    int returned = call_method("getline", G_SCALAR|G_EVAL);
    SPAGAIN;

    trace("called getline on io handle fd=%d errsv=%d returned=%d\n",
        c->fd, SvTRUE(ERRSV) ? 1 : 0, returned);

    if (unlikely(SvTRUE(ERRSV))) {
        /* Restore PL_rs before call_died — it invokes Feersum::DIED which
         * is Perl code that (or whose callees) may read $/ */
        PL_rs = old_rs;
        sv_setsv(get_sv("/", GV_ADD), old_rs);
        call_died(aTHX_ c, "getline on io handle");
        // Clear poll callback to prevent re-invocation after error
        if (c->poll_write_cb) {
            SvREFCNT_dec(c->poll_write_cb);
            c->poll_write_cb = NULL;
        }
        c->poll_write_cb_is_io_handle = 0;
        goto done_pump_io;
    }

    SV *ret = NULL;
    if (returned > 0)
        ret = POPs;
    if (ret && SvMAGICAL(ret))
        ret = sv_2mortal(newSVsv(ret));

    if (unlikely(!ret || !SvOK(ret))) {
        // returned undef, so call the close method out of nicety
        PUSHMARK(SP);
        XPUSHs(c->poll_write_cb);
        PUTBACK;
        call_method("close", G_VOID|G_DISCARD|G_EVAL);
        SPAGAIN;

        if (unlikely(SvTRUE(ERRSV))) {
            trouble("Couldn't close body IO handle: %-p",ERRSV);
        }

        SvREFCNT_dec(c->poll_write_cb);
        c->poll_write_cb = NULL;
        c->poll_write_cb_is_io_handle = 0;
        finish_wbuf(c);
        change_responding_state(c, RESPOND_SHUTDOWN);

        goto done_pump_io;
    }

    if (c->use_chunked)
        add_chunk_sv_to_wbuf(c, ret);
    else
        add_sv_to_wbuf(c, ret);

done_pump_io:
    trace("leaving pump io handle %d\n", c->fd);

    PUTBACK;
    FREETMPS;
    LEAVE;

    PL_rs = old_rs;
    sv_setsv(get_sv("/", GV_ADD), old_rs);
    SvREFCNT_dec(old_rs);

    c->in_callback--;
}

static int
psgix_io_svt_get (pTHX_ SV *sv, MAGIC *mg)
{
    dSP;

    struct feer_conn *c = sv_2feer_conn(mg->mg_obj);
    trace("invoking psgix.io magic for fd=%d\n", c->fd);

    sv_unmagic(sv, PERL_MAGIC_ext);

#ifdef FEERSUM_HAS_H2
    /* H2 tunnel: create socketpair and expose sv[1] as the IO handle.
     * For PSGI: auto-send 200 HEADERS and enable response swallowing so
     * apps can use the same psgix.io code for H1 and H2 transparently. */
    if (c->is_h2_stream) {
        struct feer_h2_stream *stream = (struct feer_h2_stream *)c->read_ev_timer.data;
        if (!stream || !stream->is_tunnel) {
            trouble("psgix.io: not supported on regular H2 streams fd=%d\n", c->fd);
            return 0;
        }
        h2_tunnel_auto_accept(aTHX_ c, stream);
        /* Re-fetch stream: auto_accept → session_send may have freed it */
        stream = (struct feer_h2_stream *)c->read_ev_timer.data;
        if (!stream) {
            trouble("psgix.io: stream freed during auto_accept fd=%d\n", c->fd);
            return 0;
        }
        feer_h2_setup_tunnel(aTHX_ stream);
        if (!stream->tunnel_established) {
            trouble("psgix.io: tunnel setup failed fd=%d\n", c->fd);
            h2_submit_rst(stream->parent->h2_session, stream->stream_id,
                          NGHTTP2_INTERNAL_ERROR);
            feer_h2_session_send(stream->parent);
            return 0;
        }

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv);
        mXPUSHs(newSViv(stream->tunnel_sv1));
        PUTBACK;

        call_pv("Feersum::Connection::_raw", G_VOID|G_DISCARD|G_EVAL);
        SPAGAIN;

        if (unlikely(SvTRUE(ERRSV))) {
            call_died(aTHX_ c, "psgix.io H2 tunnel magic");
        } else {
            SV *io_glob = SvRV(sv);
            GvSV(io_glob) = newRV_inc(c->self);
            stream->tunnel_sv1 = -1;
        }

        c->io_taken = 1;
        PUTBACK;
        FREETMPS;
        LEAVE;
        return 0;
    }
#endif

#ifdef FEERSUM_HAS_TLS
    /* TLS tunnel: create socketpair relay for psgix.io over TLS */
    if (c->tls) {
        feer_tls_setup_tunnel(c);
        if (!c->tls_tunnel) {
            trouble("psgix.io: TLS tunnel setup failed fd=%d\n", c->fd);
            return 0;
        }

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv);
        mXPUSHs(newSViv(c->tls_tunnel_sv1));
        PUTBACK;

        call_pv("Feersum::Connection::_raw", G_VOID|G_DISCARD|G_EVAL);
        SPAGAIN;

        if (unlikely(SvTRUE(ERRSV))) {
            call_died(aTHX_ c, "psgix.io TLS tunnel magic");
            /* fd NOT consumed by _raw on failure; conn cleanup will close it */
        } else {
            SV *io_glob = SvRV(sv);
            GvSV(io_glob) = newRV_inc(c->self);
            c->tls_tunnel_sv1 = -1;
        }

        c->io_taken = 1;
        stop_read_timer(c);
        stop_write_timer(c);
        PUTBACK;
        FREETMPS;
        LEAVE;
        return 0;
    }
#endif

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv);
    mXPUSHs(newSViv(c->fd));
    PUTBACK;

    call_pv("Feersum::Connection::_raw", G_VOID|G_DISCARD|G_EVAL);
    SPAGAIN;

    if (unlikely(SvTRUE(ERRSV))) {
        call_died(aTHX_ c, "psgix.io magic");
    }
    else {
        SV *io_glob   = SvRV(sv);
        GvSV(io_glob) = newRV_inc(c->self);

        // Put whatever remainder data into the socket buffer.
        // Optimizes for the websocket case.
        // Use return_from_psgix_io() to pull data back for keepalive.
        if (likely(c->rbuf && SvOK(c->rbuf) && SvCUR(c->rbuf))) {
            STRLEN rbuf_len;
            const char *rbuf_ptr = SvPV(c->rbuf, rbuf_len);
            IO *io = GvIOp(io_glob);
            if (unlikely(!io)) {
                trouble("psgix.io: GvIOp returned NULL fd=%d\n", c->fd);
                // Skip unread, data will remain in rbuf
            }
            else {
            // PerlIO_unread copies the data internally, so it's safe to
            // clear rbuf after. Use SvCUR_set to keep buffer allocated
            // (more efficient for potential reuse).
            SSize_t pushed = PerlIO_unread(IoIFP(io), (const void *)rbuf_ptr, rbuf_len);
            if (likely(pushed == (SSize_t)rbuf_len)) {
                // All data pushed back successfully
                SvCUR_set(c->rbuf, 0);
            } else if (pushed > 0) {
                // Partial push - keep remaining data in rbuf
                sv_chop(c->rbuf, rbuf_ptr + pushed);
                trouble("PerlIO_unread partial: %zd of %"Sz_uf" bytes fd=%d\n",
                        (size_t)pushed, (Sz)rbuf_len, c->fd);
            } else {
                // Push failed entirely - keep rbuf as-is
                trouble("PerlIO_unread failed in psgix.io magic fd=%d\n", c->fd);
            }
            }
        }

        // Stop Feersum's watchers - user now owns the socket
        stop_read_watcher(c);
        stop_read_timer(c);
        stop_write_timer(c);
        // don't stop write watcher in case there's outstanding data

        c->io_taken = 1;
    }

    FREETMPS;
    LEAVE;

    return 0;
}

#ifdef FEERSUM_HAS_H2
static void
h2_tunnel_auto_accept(pTHX_ struct feer_conn *c, struct feer_h2_stream *stream)
{
    if (c->responding != RESPOND_NOT_STARTED)
        return;
    AV *empty_hdr = newAV();
    SV *status_sv = newSVpvs("200");
    feersum_start_response(aTHX_ c, status_sv, empty_hdr, 1);
    SvREFCNT_dec(status_sv);
    SvREFCNT_dec((SV *)empty_hdr);
    /* Re-fetch stream: feersum_start_response → feer_h2_session_send may
     * have freed it via h2_on_stream_close_cb (e.g. RST_STREAM queued) */
    stream = (struct feer_h2_stream *)c->read_ev_timer.data;
    if (stream)
        stream->tunnel_swallow_response = 1;
}

static void
pump_h2_io_handle(pTHX_ struct feer_conn *c, SV *body)
{
    dSP;
    SV *io = newSVsv(body);
    c->in_callback++;
    SV *old_rs = PL_rs;
    SvREFCNT_inc_simple_void(old_rs);
    PL_rs = sv_2mortal(newRV_noinc(newSViv(IO_PUMP_BUFSZ)));
    sv_setsv(get_sv("/", GV_ADD), PL_rs);
    ENTER;
    SAVETMPS;
    for (;;) {
        ENTER; SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(io);
        PUTBACK;
        int returned = call_method("getline", G_SCALAR|G_EVAL);
        SPAGAIN;
        if (unlikely(SvTRUE(ERRSV))) {
            /* Restore PL_rs before call_died — it invokes Feersum::DIED which
             * is Perl code that (or whose callees) may read $/ */
            PL_rs = old_rs;
            sv_setsv(get_sv("/", GV_ADD), old_rs);
            call_died(aTHX_ c, "getline on H2 io handle");
            PUTBACK; FREETMPS; LEAVE;
            break;
        }
        SV *ret = NULL;
        if (returned > 0) ret = POPs;
        if (ret && SvMAGICAL(ret)) ret = sv_2mortal(newSVsv(ret));
        if (!ret || !SvOK(ret)) {
            PUSHMARK(SP); XPUSHs(io); PUTBACK;
            call_method("close", G_VOID|G_DISCARD|G_EVAL);
            SPAGAIN;
            if (unlikely(SvTRUE(ERRSV))) trouble("Couldn't close body IO handle: %-p",ERRSV);
            PUTBACK; FREETMPS; LEAVE;
            feersum_h2_close_write(aTHX_ c);
            break;
        }
        feersum_h2_write_chunk(aTHX_ c, ret);
        PUTBACK; FREETMPS; LEAVE;
    }
    FREETMPS; LEAVE;
    PL_rs = old_rs;
    sv_setsv(get_sv("/", GV_ADD), old_rs);
    SvREFCNT_dec(old_rs);
    c->in_callback--;
    SvREFCNT_dec(io);
}

static SV*
feersum_env_method_h2(pTHX_ struct feer_conn *c, struct feer_req *r)
{
    if (unlikely(c->is_h2_stream)) {
        struct feer_h2_stream *stream = (struct feer_h2_stream *)c->read_ev_timer.data;
        if (stream && stream->is_tunnel && stream->h2_protocol)
            return SvREFCNT_inc_simple_NN(method_GET);
    }
    return feersum_env_method(aTHX_ r);
}
#endif
