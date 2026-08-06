
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

static HV *psgi_env_template = NULL;

static void
feersum_init_psgi_env_constants(pTHX)
{
    if (psgi_env_version) return;
    psgi_env_version = newRV((SV*)psgi_ver);
    psgi_env_errors = newRV((SV*)PL_stderrgv);

    /* Constant env keys live in a template that newHVhv clones per request:
     * cloning shares each HEK (refcount bump, no hashing or bucket search)
     * where hv_stores rehashed every key on every request.  Values are
     * newSVsv copies, so apps can assign to them (a shared &PL_sv_yes
     * croaked on write). */
    HV *t = newHV();
    /* ~13 constants + ~10 per-request + ~15 headers ~= 38; the clone
     * inherits the bucket count, so this pre-split covers every request. */
    hv_ksplit(t, 48);
    hv_stores(t, "psgi.version", newSVsv(psgi_env_version));
    hv_stores(t, "psgi.errors", newSVsv(psgi_env_errors));
    hv_stores(t, "psgi.run_once", newSVsv(&PL_sv_no));
    hv_stores(t, "psgi.nonblocking", newSVsv(&PL_sv_yes));
    hv_stores(t, "psgi.multithread", newSVsv(&PL_sv_no));
    hv_stores(t, "psgi.streaming", newSVsv(&PL_sv_yes));
    hv_stores(t, "psgix.input.buffered", newSVsv(&PL_sv_yes));
    hv_stores(t, "psgix.output.buffered", newSVsv(&PL_sv_yes));
    hv_stores(t, "psgix.body.scalar_refs", newSVsv(&PL_sv_yes));
    hv_stores(t, "psgix.output.guard", newSVsv(&PL_sv_yes));
    hv_stores(t, "SCRIPT_NAME", newSVpvs(""));
    psgi_env_template = t;
}

static HV*
feersum_build_psgi_env(pTHX)
{
    /* newHVhv: shared-HEK clone of the constants; values are fresh copies. */
    return newHVhv(psgi_env_template);
}

static HV*
feersum_env(pTHX_ struct feer_conn *c)
{
    HV *e;
    int i,j;
    struct feer_req *r = c->req;

    if (unlikely(!psgi_env_version))
        feersum_init_psgi_env_constants(aTHX);

    e = feersum_build_psgi_env(aTHX);

    trace("generating header (fd %d) %.*s\n",
        c->fd, (int)r->uri_len, r->uri);

    // SERVER_NAME and SERVER_PORT - copy because these SVs are SvREADONLY
    // and middleware may modify in-place (e.g., Plack::Middleware::ReverseProxy).
    {
        struct feer_listen *conn_lsnr = c->listener;
        hv_stores(e, "SERVER_NAME",
            conn_lsnr->server_name ? newSVsv(conn_lsnr->server_name) : newSVpvs(""));
        hv_stores(e, "SERVER_PORT",
            conn_lsnr->server_port ? newSVsv(conn_lsnr->server_port) : newSVpvs("0"));
    }
    hv_stores(e, "REQUEST_URI", feersum_env_uri(aTHX_ r));
#ifdef FEERSUM_HAS_H2
    /* feersum_env_method* return an incremented reference to a shared,
     * read-only method SV; the env needs its own mutable copy. */
    {
        SV *m = feersum_env_method_h2(aTHX_ c, r);
        hv_stores(e, "REQUEST_METHOD", newSVsv(m));
        SvREFCNT_dec(m);
    }
    if (unlikely(c->is_h2_stream))
        hv_stores(e, "SERVER_PROTOCOL", newSVpvs("HTTP/2"));
    else
        hv_stores(e, "SERVER_PROTOCOL", newSVsv(feersum_env_protocol(aTHX_ r)));
#else
    {
        SV *m = feersum_env_method(aTHX_ r);
        hv_stores(e, "REQUEST_METHOD", newSVsv(m));
        SvREFCNT_dec(m);
    }
    hv_stores(e, "SERVER_PROTOCOL", newSVsv(feersum_env_protocol(aTHX_ r)));
#endif

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
        hv_stores(e, "psgi.url_scheme", scheme ? scheme : newSVpvs("http"));
    }

    hv_stores(e, "CONTENT_LENGTH", newSViv(c->expected_cl));

    // Always provide psgi.input (for both PSGI and native handlers)
    // For requests without body, it will be an empty stream (returns 0 on read)
    hv_stores(e, "psgi.input", new_feer_conn_handle(aTHX_ c, 0));

    /* A copy: a shared immortal croaks when middleware assigns to the key. */
    hv_stores(e, "psgi.multiprocess",
        newSVsv(c->server->multiprocess ? &PL_sv_yes : &PL_sv_no));

    /* Both halves live: dispatch picks PSGI-vs-native from the server on
     * every request, so freezing only this half at accept meant a handler
     * swapped after a keepalive connection was accepted got the other
     * interface.s env - a native handler handed a live psgix.io whose magic
     * takes the socket the moment anything reads the value. */
    if (c->server->request_cb_is_psgi && c->server->psgix_io) {
        SV *fake_fh = newSViv(c->fd); // fd value for psgix.io magic backing SV
        SV *selfref = sv_2mortal(feer_conn_2sv(c));
        sv_magicext(fake_fh, selfref, PERL_MAGIC_ext, &psgix_io_vtbl, NULL, 0);
        hv_stores(e, "psgix.io", fake_fh);
    }

    if (c->trailers) {
        hv_stores(e, "psgix.h2.trailers", newRV_inc((SV*)c->trailers));
    }

    if (c->proxy_tlvs) {
        /* A shallow copy per request, like the other env values above: the
         * connection's TLV hash is shared by every request on it (and by every
         * H2 stream), so middleware that normalises or deletes a key would
         * otherwise corrupt later requests and race between streams. */
        HV *tlvs = (HV *)SvRV(c->proxy_tlvs);
        HV *copy = newHVhv(tlvs);
        hv_stores(e, "psgix.proxy_tlvs", newRV_noinc((SV *)copy));
    }

    if (likely(!r->path)) feersum_set_path_and_query(aTHX_ r);
    /* A copy, like every other env value: r->path is per-request today, so
     * sharing it is harmless, but it was the one key left aliasing server
     * state and t/105 asserts the whole set is private. */
    hv_stores(e, "PATH_INFO", newSVsv(r->path));
    hv_stores(e, "QUERY_STRING", newSVsv(r->query));

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
            hv_stores(e, "CONTENT_TYPE", newSVpvn(hdr->value, hdr->value_len));
            continue;
        }
        else if (unlikely(hdr->name_len == 17) &&
            str_case_eq_fixed("transfer-encoding", hdr->name, 17))
        {
            // The body is already decoded, so keeping this alongside the
            // CONTENT_LENGTH above describes a message RFC 9112 6.3 forbids:
            // middleware rebuilding an upstream request from the env would
            // emit both with a plain body (CL.TE smuggling).  Starman also
            // deletes the key.
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
        SV *cur_val = *fetched;  // existing entry means multi-value header
        if (unlikely(SvPOK(cur_val))) {
            trace("... is multivalue\n");
            // RFC 9113 section 8.2.3: cookie uses "; ", others use ", "
            const char *sep = (hdr->name_len == 6
                && str_case_eq_fixed("cookie", hdr->name, 6)) ? "; " : ", ";
            sv_catpvn(cur_val, sep, 2);
            sv_catpvn(cur_val, hdr->value, hdr->value_len);
        }
        else {
            // change from undef to a real value
            sv_setpvn(cur_val, hdr->value, hdr->value_len);
        }
    }

#ifdef FEERSUM_HAS_H2
    /* Map :authority pseudo-header to HTTP_HOST for H2 streams (RFC 9113 section 8.3.1).
     * Only set if no regular Host header was already present. */
    if (unlikely(c->is_h2_stream)) {
        struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
        if (stream && stream->h2_authority && !hv_exists(e, "HTTP_HOST", 9)) {
            STRLEN alen;
            const char *aval = SvPV(stream->h2_authority, alen);
            hv_stores(e, "HTTP_HOST", newSVpvn(aval, alen));
        }
        /* Extended CONNECT (RFC 8441): REQUEST_METHOD already set to GET
         * above; add remaining H1-equivalent headers so existing PSGI
         * WebSocket middleware works transparently.
         * Matches HAProxy/nghttpx H2<->H1 upgrade translation. */
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
        const char *sep = (hdr->name_len == 6\
            && str_case_eq_fixed("cookie", hdr->name, 6)) ? "; " : ", ";\
        sv_catpvn(*val, sep, 2);\
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
    SV *result = NULL;
    STRLEN nlen;
    const char *np = SvPV(name, nlen);
    /* RFC 9113 section 8.2.3: cookie headers joined with "; ", others with ", " */
    const bool is_cookie = (nlen == 6 && str_case_eq_fixed("cookie", np, 6));
    for (size_t i = 0; i < r->num_headers; i++) {
        struct phr_header *hdr = &(r->headers[i]);
        if (unlikely(hdr->name_len == nlen
            && str_case_eq_both(np, hdr->name, nlen))) {
            if (likely(!result)) {
                result = newSVpvn(hdr->value, hdr->value_len);
            } else {
                sv_catpvn(result, is_cookie ? "; " : ", ", 2);
                sv_catpvn(result, hdr->value, hdr->value_len);
            }
        }
    }
    return result ? result : &PL_sv_undef;
}

/* Build an IO::Socket::INET wrapping `fd` via Perl helper Feersum::Connection::_raw,
 * then stash a back-ref to c->self in the glob's scalar slot so the IO handle
 * keeps the connection alive. Returns the blessed RV (refcount 1). Croaks with
 * "Failed to create <who> IO handle..." on any failure; the caller is then
 * responsible for closing the fd it passed in. */
static SV *
feer_make_io_handle(pTHX_ struct feer_conn *c, int fd, const char *who)
{
    dSP;
    SV *sv = newSViv(fd);

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv);
    mXPUSHs(newSViv(fd));
    PUTBACK;

    call_pv("Feersum::Connection::_raw", G_VOID|G_DISCARD|G_EVAL);
    SPAGAIN;

    if (unlikely(SvTRUE(ERRSV))) {
        FREETMPS; LEAVE;
        SvREFCNT_dec(sv);
        croak("Failed to create %s IO handle: %-p", who, ERRSV);
    }
    if (unlikely(!SvROK(sv))) {
        FREETMPS; LEAVE;
        SvREFCNT_dec(sv);
        croak("Failed to create %s IO handle: new_from_fd returned undef", who);
    }

    SV *io_glob = SvRV(sv);
    GvSV(io_glob) = newRV_inc(c->self);

    FREETMPS;
    LEAVE;
    return sv;
}

/* Hand c->fd to an IO handle that SHARES it: push the unread remainder into the
 * handle's buffer, disarm our read side, and record that the descriptor now
 * belongs to the handle's destructor.  Shared by io() and the psgix.io magic;
 * they had drifted apart as separate copies. */
static void
feer_hand_out_raw_fd(pTHX_ struct feer_conn *c, SV *io_glob, const char *who)
{
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
                trouble("PerlIO_unread partial in %s: %zd of %"Sz_uf" bytes fd=%d\n",
                    who, pushed, (Sz)rbuf_len, c->fd);
            } else {
                trouble("PerlIO_unread failed in %s fd=%d\n", who, c->fd);
            }
        }
        else {
            trouble("%s: GvIOp returned NULL fd=%d\n", who, c->fd);
        }
    }

    stop_read_watcher(c);
    stop_read_timer(c);
    stop_write_timer(c);
    // don't stop write watcher in case there's outstanding data

    c->io_taken = 1;
    c->fd_given_away = 1;   // handle shares c->fd; it closes it, we must not
}

static SV*
feersum_env_io(pTHX_ struct feer_conn *c)
{
    // Prevent double-call and misuse after response started
    if (unlikely(c->io_taken))
        croak("io() already called on this connection");
    if (unlikely(c->responding != RESPOND_NOT_STARTED))
        croak("io() cannot be called after send_response/start_response");

    trace("feersum_env_io for fd=%d\n", c->fd);

#ifdef FEERSUM_HAS_H2
    /* H2 tunnel: auto-accept, create socketpair, expose sv[1] as IO handle */
    if (c->is_h2_stream) {
        struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
        if (!stream || !stream->is_tunnel)
            croak("io() is not supported on regular HTTP/2 streams");
        h2_tunnel_auto_accept(aTHX_ c, stream);
        /* Re-fetch stream: auto_accept -> session_send may have freed it */
        stream = H2_STREAM_FROM_PC(c);
        if (!stream)
            croak("io() tunnel: stream freed during auto-accept");
        feer_h2_setup_tunnel(aTHX_ stream);
        if (!stream->tunnel_established)
            croak("Failed to create tunnel socketpair");

        SV *sv = feer_make_io_handle(aTHX_ c, stream->tunnel_sv1, "tunnel");
        /* sv[1] now owned by the IO handle */
        stream->tunnel_sv1 = -1;
        c->io_taken = 1;
        return sv;
    }
#endif

#ifdef FEERSUM_HAS_TLS
    /* TLS tunnel: create socketpair relay for bidirectional I/O over TLS */
    if (c->tls) {
        feer_tls_setup_tunnel(c);
        if (!c->tls_tunnel)
            croak("Failed to create TLS tunnel socketpair");

        SV *sv = feer_make_io_handle(aTHX_ c, c->tls_tunnel_sv1, "TLS tunnel");
        /* sv[1] now owned by the IO handle */
        c->tls_tunnel_sv1 = -1;
        c->io_taken = 1;
        stop_read_timer(c);
        stop_write_timer(c);
        /* Keep read watcher active: TLS reads relay to tunnel */
        return sv;
    }
#endif

    SV *sv = feer_make_io_handle(aTHX_ c, c->fd, "raw socket");
    feer_hand_out_raw_fd(aTHX_ c, SvRV(sv), "io()");
    return sv;
}

static SSize_t
feersum_return_from_io(pTHX_ struct feer_conn *c, SV *io_sv, const char *func_name)
{
    /* Handing back a socket that was never taken silently reset the
     * responding/receiving state and freed the request mid-flight.  io_taken
     * is cleared below, so this also rejects a second return_from_io. */
    if (unlikely(!c->io_taken))
        croak("%s: called without a preceding io()/psgix.io", func_name);
#ifdef FEERSUM_HAS_H2
    if (unlikely(c->is_h2_stream))
        croak("%s: not supported on HTTP/2 streams", func_name);
#endif
#ifdef FEERSUM_HAS_TLS
    if (c->tls_tunnel)
        croak("%s: not supported on TLS tunnel connections "
              "(io() over TLS uses a socketpair relay that cannot be returned)",
              func_name);
#endif

    if (!SvROK(io_sv) || !isGV_with_GP(SvRV(io_sv)))
        croak("%s requires a filehandle", func_name);

    GV *gv = (GV *)SvRV(io_sv);
    IO *io = GvIO(gv);
    if (!io || !IoIFP(io))
        croak("%s: invalid filehandle", func_name);

    PerlIO *fp = IoIFP(io);

    /* Handing back the wrong handle would splice its buffered bytes into this
     * connection's rbuf AND clear fd_given_away while the real handle still
     * shares c->fd, re-arming the cross-connection close this bit exists to
     * prevent.  Croak now instead of killing someone else's client later. */
    if (PerlIO_fileno(fp) != c->fd)
        croak("%s: that handle does not wrap this connection's socket",
              func_name);

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

            trace("pulled %zd bytes back to feersum fd=%d\n", cnt, c->fd);
        }
    }

    /* Reset connection state for next request (like keepalive reset) */
    change_responding_state(c, RESPOND_NOT_STARTED);
    change_receiving_state(c, RECEIVE_HEADERS);
    c->expected_cl = 0;
    c->received_cl = 0;
    c->io_taken = 0;
    c->fd_given_away = 0;   // handed back: Feersum owns the descriptor again
    free_request(c);

    if (c->rbuf && cnt <= 0)
        SvCUR_set(c->rbuf, 0);

    start_read_watcher(c);
    restart_read_timer(c);
    restart_header_timer(c);

    /* Pulled-back bytes (e.g. a pipelined request the IO handle had buffered)
     * are already in rbuf, so no socket event will arrive to make the read
     * watcher fire and the request would sit unparsed until the read timeout
     * turned it into a spurious 408.  Same trick as the pipelined branch of
     * handle_keepalive_or_close; it only parses and enqueues, so this is not a
     * re-entrant dispatch. */
    if (c->rbuf && SvCUR(c->rbuf) > 0) {
        c->pipelined = SvCUR(c->rbuf);
#ifdef FEERSUM_HAS_TLS
        if (c->tls)
            try_tls_conn_read(feersum_ev_loop, &c->read_ev_io, EV_READ);
        else
#endif
            try_conn_read(feersum_ev_loop, &c->read_ev_io, EV_READ);
    }

    return cnt > 0 ? cnt : 0;
}

/* Materialise an app-supplied header list into plain PVs: the scan and both
 * builder passes index AvARRAY and SvPV directly, with no eval above them.
 * Returns the original AV when nothing is magical (hot path), a plain copy
 * otherwise, or NULL if a tied method or overload died (ERRSV set). */
static AV *
feersum_flatten_headers(pTHX_ AV *headers)
{
    bool needs_copy = SvMAGICAL((SV *)headers) ? 1 : 0;
    if (!needs_copy) {
        /* The AV is known non-magical here, so walking AvARRAY is safe. */
        SV **arr = AvARRAY(headers);
        I32 top = AvFILLp(headers);
        for (I32 i = 0; i <= top; i++) {
            SV *e = arr[i];
            if (!e) continue;
            if (SvMAGICAL(e) || (SvROK(e) && SvAMAGIC(e))) { needs_copy = 1; break; }
        }
    }
    if (likely(!needs_copy)) return headers;

    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newRV_inc((SV *)headers)));
    PUTBACK;

    int count = call_pv("Feersum::_flatten_headers", G_SCALAR|G_EVAL);
    SPAGAIN;

    AV *out = NULL;
    if (likely(!SvTRUE(ERRSV)) && count == 1) {
        SV *r = POPs;
        if (IsArrayRef(r)) out = (AV *)SvRV(r);
        if (out) SvREFCNT_inc((SV *)out);
    }
    else if (count > 0) {
        (void)POPs;
    }
    PUTBACK;
    FREETMPS;
    LEAVE;

    if (out) sv_2mortal((SV *)out);
    return out;
}

/* Copy a magical (tied) AV into a plain one, under G_EVAL: av_len/av_fetch on
 * a tied array run FETCHSIZE/FETCH, which can die where no eval can catch it.
 * Returns the original when non-magical, else a plain copy, else NULL with
 * ERRSV set. */
static AV *
feersum_flatten_magical_av(pTHX_ AV *av)
{
    if (likely(!SvMAGICAL((SV *)av))) return av;

    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newRV_inc((SV *)av)));
    PUTBACK;

    int count = call_pv("Feersum::_flatten_body", G_SCALAR|G_EVAL);
    SPAGAIN;

    AV *out = NULL;
    if (likely(!SvTRUE(ERRSV)) && count == 1) {
        SV *r = POPs;
        if (IsArrayRef(r)) out = (AV *)SvRV(r);
        if (out) SvREFCNT_inc((SV *)out);   /* survive FREETMPS below */
    }
    else if (count > 0) {
        (void)POPs;
    }
    PUTBACK;
    FREETMPS;
    LEAVE;

    if (out) sv_2mortal((SV *)out);         /* hand back a mortal copy */
    return out;
}

/* Force get-magic on PSGI array body elements to fire now, under an eval:
 * fetch_av_normal newSVsv's such an element during the body write, on a path
 * with no eval frame above it.  Returns the body to use (the original when
 * there is no magic), or NULL if a FETCH died, with ERRSV set. */
static SV *
feersum_flatten_magical_body(pTHX_ SV *body)
{
    AV *av = (AV *)SvRV(body);
    /* A tied ARRAY dies inside av_len/av_fetch themselves, so test the array
     * before touching its elements. */
    bool magical = SvMAGICAL((SV *)av) ? 1 : 0;
    if (!magical) {
        /* Direct access, not av_fetch: the AV is known non-magical here, so
         * this is a few loads and flag tests over a list that is almost always
         * one element - no call per element on the hot path. */
        SV **arr = AvARRAY(av);
        I32 top = AvFILLp(av);
        for (I32 i = 0; i <= top; i++) {
            SV *e = arr[i];
            if (!e) continue;
            if (SvMAGICAL(e)) { magical = 1; break; }
            /* fetch_av_normal dereferences an RV and the writer SvPV's the
             * referent, so \$tied bites one level down too. */
            if (SvROK(e) && SvMAGICAL(SvRV(e))) { magical = 1; break; }
        }
    }
    if (likely(!magical)) return body;

    dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(body);
    PUTBACK;
    int count = call_pv("Feersum::_flatten_body", G_SCALAR|G_EVAL);
    SPAGAIN;
    SV *out = NULL;
    if (count > 0) {
        SV *r = POPs;
        if (!SvTRUE(ERRSV) && SvROK(r) && SvTYPE(SvRV(r)) == SVt_PVAV)
            out = newSVsv(r);
    }
    PUTBACK;
    FREETMPS;
    LEAVE;
    if (out) return sv_2mortal(out);
    return NULL;
}

/* The one place a response status is turned into a number.  Callers apply
 * their own range policy, but they must all agree on what the digits ARE:
 * feersum_check_psgi_status screens for a croak that feersum_start_response
 * would otherwise raise on a path with no G_EVAL above it, so if the two ever
 * parsed differently the screen would let that croak through and kill the
 * worker.  Only the first three characters are significant ("200 OK"). */
INLINE_UNLESS_DEBUG static UV
feer_status_code(pTHX_ SV *message)
{
    UV code = 0;
    if (SvIOK(message)) return SvIV(message);
    STRLEN mlen = SvCUR(message);
    if (grok_number(SvPVX_const(message), mlen > 3 ? 3 : mlen, &code)
            != IS_NUMBER_IN_UV)
        return 0;
    return code;
}

/* Resolve the status exactly as feersum_start_response will, and apply the same
 * bounds.  start_response croaks on both, and the PSGI dispatch paths have no
 * G_EVAL above them, so every caller there must screen with this first.
 * Returns NULL if acceptable, else a literal error string. */
static const char *
feersum_check_psgi_status(pTHX_ SV *msg)
{
    if (!SvOK(msg) || !(SvIOK(msg) || SvPOK(msg)))
        return "PSGI status must be a number or status string";
    UV code = feer_status_code(aTHX_ msg);
    if (unlikely(!code))
        return "PSGI status must start with a positive number";
    if (unlikely(code < 100 || code > 999))
        return "PSGI status must be a three-digit number";
    return NULL;
}

/* Framing headers an app must not set: Feersum owns framing, and passing the
 * app's through too yields CL+chunked together, which RFC 9112 6.1 forbids and
 * an intermediary desyncs on.  H2 filters the same set (h2_skip_header).
 * Connection and Upgrade are deliberately allowed. */
INLINE_UNLESS_DEBUG static bool
feer_skip_response_header(const char *hp, STRLEN hlen)
{
    switch (hlen) {
    case 2:  return str_case_eq_fixed("te", hp, 2);
    case 10: return str_case_eq_fixed("keep-alive", hp, 10);
    case 16: return str_case_eq_fixed("proxy-connection", hp, 16);
    case 17: return str_case_eq_fixed("transfer-encoding", hp, 17);
    default: return false;
    }
}

/* Does a comma-separated field value carry this token?  Case-insensitive and
 * tolerant of optional whitespace, per RFC 9110 5.6.1. */
static bool
feer_header_has_token(const char *vp, STRLEN vlen, const char *tok, STRLEN tlen)
{
    STRLEN i = 0;
    while (i < vlen) {
        while (i < vlen && (vp[i] == ',' || vp[i] == ' ' || vp[i] == '\t'))
            i++;
        STRLEN start = i;
        while (i < vlen && vp[i] != ',')
            i++;
        STRLEN end = i;
        while (end > start && (vp[end-1] == ' ' || vp[end-1] == '\t'))
            end--;
        if (end - start == tlen && str_case_eq_fixed(tok, vp + start, tlen))
            return true;
    }
    return false;
}

/* What to do with an app's Connection header.  Its value used to be copied to
 * the wire and otherwise ignored, so `close` was announced and then not acted
 * on - RFC 9112 9.6 requires the sender of close to do the closing - and the
 * server's own canonical header went out alongside it, giving `close, close`
 * or, to an HTTP/1.0 client asking for keep-alive, the contradictory pair
 * `close, keep-alive`.  Upgrade and anything else still passes through
 * untouched, which is what the 101 path needs.
 * Returns 1 to drop the header (the tail emits the canonical one). */
INLINE_UNLESS_DEBUG static int
feer_connection_header_drop(struct feer_conn *c, const char *vp, STRLEN vlen,
                            bool apply)
{
    if (feer_header_has_token(vp, vlen, "close", 5)) {
        if (apply) c->is_keepalive = 0;
        return 1;
    }
    return feer_header_has_token(vp, vlen, "keep-alive", 10) ? 1 : 0;
}

/* Scan response status message and headers for bytes that would let an app
 * inject extra headers or a second response (CWE-113 response splitting).
 * Returns NULL on success; a literal error string on failure.  Caller decides
 * whether to croak() (safe inside a Perl handler call_sv G_EVAL frame) or set
 * ERRSV and call_died (PSGI dispatch path is not in a G_EVAL). */
static const char *
feersum_check_response_framing(pTHX_ SV *message, AV *headers)
{
    if (SvPOK(message)) {
        STRLEN mlen;
        const char *mp = SvPV(message, mlen);
        for (STRLEN k = 0; k < mlen; k++)
            if (unlikely(mp[k] == '\r' || mp[k] == '\n'))
                return "Status message contains CR or LF";
    }
    I32 avl = av_len(headers);
    SV **ary = AvARRAY(headers);
    for (I32 j = 0; j < avl; j += 2) {
        SV *hdr = ary[j];
        SV *val = ary[j+1];
        if (!hdr || !SvOK(hdr) || !val || !SvOK(val))
            continue;
        STRLEN hlen, vlen;
        const char *hp = SvPV(hdr, hlen);
        const char *vp = SvPV(val, vlen);
        for (STRLEN k = 0; k < hlen; k++)
            if (unlikely(hp[k] == '\r' || hp[k] == '\n' || hp[k] == ':'))
                return "Response header name contains CR, LF, or colon";
        for (STRLEN k = 0; k < vlen; k++)
            if (unlikely(vp[k] == '\r' || vp[k] == '\n'))
                return "Response header value contains CR or LF";
    }
    return NULL;
}

static void
feersum_start_response (pTHX_ struct feer_conn *c, SV *message, AV *headers,
                        int streaming, bool pre_validated)
{
    const char *ptr;

    trace("start_response fd=%d streaming=%d\n", c->fd, streaming);

    /* headers must already be flattened by the caller (see
     * feersum_flatten_headers).  Deliberately not repeated here: every caller
     * flattens before its own framing scan, and re-scanning would walk the
     * header list a second time on every single response. */

    if (unlikely(!SvOK(message) || !(SvIOK(message) || SvPOK(message)))) {
        croak("Must define an HTTP status code or message");
    }

    I32 avl = av_len(headers);
    if (unlikely((avl+1) % 2 == 1)) {
        croak("expected even-length array, got %d", avl+1);
    }

    /* CR/LF/colon check.  Reached from XS send_response/start_streaming via
     * the user handler (call_sv G_EVAL catches this croak).  The PSGI
     * dispatcher pre-validates with feersum_check_response_framing and
     * call_died, and says so here, so the list is not rescanned per response. */
    if (!pre_validated) {
        const char *err = feersum_check_response_framing(aTHX_ message, headers);
        if (unlikely(err)) croak("%s", err);
    }

    /* RFC 9110 9.3.2: a HEAD response keeps the headers a GET would send but
     * carries no content.  Sending it anyway desyncs keepalive and makes
     * nghttp2 reset the stream.  Set before the H2 dispatch so both see it. */
    c->no_resp_body = (c->req && c->req->method_len == 4
                       && memcmp(c->req->method, "HEAD", 4) == 0) ? 1 : 0;

#ifdef FEERSUM_HAS_H2
    if (unlikely(c->is_h2_stream)) {
        feersum_h2_start_response(aTHX_ c, message, headers, streaming);
        return;
    }
#endif

    if (unlikely(c->responding != RESPOND_NOT_STARTED)) {
        /* A deferred response whose connection went away in the meantime lands
         * here too, and "already responding" sent people looking for a second
         * respond call that does not exist.  Name the real cause. */
        if (c->fd < 0 || c->responding == RESPOND_SHUTDOWN)
            croak("connection is already closed");
        croak("already responding?!");
    }
    /* Mirror of the "io() after send_response" check: responding after
     * merely READING psgix.io would queue HTTP framing onto an fd the app's
     * handle also owns.  return_from_io() clears io_taken for the documented
     * hand-it-back-then-respond flow. */
    if (unlikely(c->io_taken))
        croak("can't respond after io()/psgix.io; call return_from_io first");

    // int or 3 chars? use a stock message
    UV code = feer_status_code(aTHX_ message);
    trace2("starting response fd=%d code=%"UVuf"\n",c->fd,code);

    // Validate the status BEFORE changing state: once we are RESPOND_NORMAL a
    // croak cannot be turned into a 500 (call_died declines - "already
    // responding"), so the client would get nothing at all.  RFC 9112 4 wants
    // exactly three digits; a negative IV would otherwise wrap to a 20-digit UV.
    if (unlikely(!code))
        croak("first parameter is not a number or doesn't start with digits");
    if (unlikely(code < 100 || code > 999))
        croak("response status must be a three-digit number, got %"UVuf, code);

    change_responding_state(c, streaming ? RESPOND_STREAMING : RESPOND_NORMAL);

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

    c->auto_cl = http_status_no_body(code) ? 0 : 1;
    c->app_content_length = 0;   /* per-response; set below if HEAD + app CL */

    /* RFC 9110 8.6: no Content-Length on 1xx or 204.  304 keeps the app's (it
     * carries the representation's length; t/10 asserts this). */
    const bool drop_app_cl = (code < 200 || code == 204 || code == 205);

    /* RFC 7231 6.3.6: a 205 MUST signal its empty content, and it is NOT in
     * RFC 9112 6.3 rule 1 (unlike HEAD, 1xx, 204, 304), so with no delimiter a
     * keepalive client reads the next response as this one's body. */
    const bool emit_zero_cl = (code == 205);

    // Build entire header block into a single buffer to minimize iovecs.
    // Pre-calculate total size to avoid reallocation.
    STRLEN msg_len;
    const char *msg_ptr = SvPV(message, msg_len);

    // First pass: calculate total header size and detect Content-Length.
    bool has_content_length = 0;
    STRLEN hdr_total = 9 + msg_len + 2; // "HTTP/1.x " + message + CRLF
    SV **ary = AvARRAY(headers);
    for (I32 i = 0; i < avl; i += 2) {
        SV *hdr = ary[i];
        SV *val = ary[i+1];
        if (unlikely(!hdr || !SvOK(hdr) || !val || !SvOK(val)))
            continue;
        STRLEN hlen, vlen;
        const char *hp = SvPV(hdr, hlen);
        if (unlikely(feer_skip_response_header(hp, hlen)))
            continue;
        /* Must run in this pass: the tail's size and content are chosen from
         * c->is_keepalive just below. */
        if (unlikely(hlen == 10) && str_case_eq_fixed("connection", hp, 10)) {
            STRLEN cvlen;
            const char *cvp = SvPV(val, cvlen);
            if (feer_connection_header_drop(c, cvp, cvlen, 1))
                continue;
        }
        if (unlikely(hlen == 14) && str_case_eq_fixed("content-length", hp, 14)) {
            /* On a HEAD response keep whatever the app declared: no body
             * follows, so it cannot desync, and RFC 9110 8.6 requires the same
             * value a GET would have sent.  Plack::Middleware::Head empties the
             * body and leaves the real length behind, and recomputing from the
             * now-empty body advertised Content-Length: 0. */
            if (unlikely(c->no_resp_body) && !unlikely(drop_app_cl)) {
                c->app_content_length = 1;
                has_content_length = 1;
            }
            else if ((likely(c->auto_cl) && !streaming) || unlikely(drop_app_cl))
                continue;
            else
                has_content_length = 1;
        }
        (void)SvPV(val, vlen);
        hdr_total += hlen + 2 + vlen + 2; // key + ": " + value + CRLF
    }
    // HTTP/1.0 streaming with a body but no Content-Length: the only way to
    // signal end-of-body is Connection: close.  No-body statuses (auto_cl=0)
    // are exempt - RFC 7230 section 3.3.3 rule 1 says clients MUST NOT expect a body
    // for 1xx/204/304 regardless of framing headers, so keepalive is safe.
    if (streaming && c->is_keepalive && !has_content_length
        && !c->is_http11 && c->auto_cl)
        c->is_keepalive = 0;

    // Content-Length: 0 (205), Date, Connection, Transfer-Encoding, CRLF.
    // Sized separately from the header list: the tail is written after the
    // second pass without any further bounds check, so it has to be re-verified
    // once the (possibly magical) header values are known - see below.
    STRLEN tail_len = 0;
    if (unlikely(emit_zero_cl))
        tail_len += 19;  // "Content-Length: 0\r\n"
    /* Date goes on every version.  RFC 9110 6.6.1 requires an origin server
     * with a clock to send it on 2xx/3xx/4xx/5xx; it used to be emitted only
     * for HTTP/1.1, so every HTTP/1.0 response went out without one (and `ab`
     * speaks 1.0 by default). */
    tail_len += DATE_HEADER_LENGTH;
    if (likely(c->is_http11))
        tail_len += (!c->is_keepalive ? 19 : 0);
    else if (c->is_keepalive)
        tail_len += 24;  // "Connection: keep-alive\r\n"
    if (streaming) {
        if (c->is_http11 && !has_content_length && c->auto_cl)
            tail_len += 30; // "Transfer-Encoding: chunked\r\n\r\n"
        else
            tail_len += 2;  // terminal CRLF
    }
    hdr_total += tail_len;

    // Second pass: build the header buffer
    SV *hdr_sv = newSV(hdr_total + 1);
    SvPOK_on(hdr_sv);
    char *p = SvPVX(hdr_sv);
    STRLEN hdr_alloc = hdr_total;

    // Status line
    const char *ver = c->is_http11 ? "HTTP/1.1 " : "HTTP/1.0 ";
    memcpy(p, ver, 9); p += 9;
    memcpy(p, msg_ptr, msg_len); p += msg_len;
    *p++ = '\r'; *p++ = '\n';

    // Response headers
    for (I32 i = 0; i < avl; i += 2) {
        SV *hdr = ary[i];
        SV *val = ary[i+1];
        if (unlikely(!hdr || !SvOK(hdr) || !val || !SvOK(val)))
            continue;
        STRLEN hlen, vlen;
        const char *hp = SvPV(hdr, hlen);
        if (unlikely(feer_skip_response_header(hp, hlen)))
            continue;
        /* Mirror of pass 1.  apply=0: the flag is already set, and a magical
         * SV could otherwise report a different value on this second read. */
        if (unlikely(hlen == 10) && str_case_eq_fixed("connection", hp, 10)) {
            STRLEN cvlen;
            const char *cvp = SvPV(val, cvlen);
            if (feer_connection_header_drop(c, cvp, cvlen, 0))
                continue;
        }
        if (unlikely(hlen == 14) && str_case_eq_fixed("content-length", hp, 14)) {
            /* Mirror of pass 1: emit the app's value on a HEAD response. */
            if (!(unlikely(c->no_resp_body) && !unlikely(drop_app_cl))
                && ((likely(c->auto_cl) && !streaming) || unlikely(drop_app_cl)))
                continue;
        }
        const char *vp = SvPV(val, vlen);
        STRLEN need = hlen + 2 + vlen + 2;
        // Guard against magical SVs returning longer strings than pass 1
        if (unlikely((p - SvPVX(hdr_sv)) + need > hdr_alloc)) {
            STRLEN pos = p - SvPVX(hdr_sv);
            hdr_alloc = pos + need + 128; // slack covers tail (CL0+Date+Connection+TE <= 105)
            SvGROW(hdr_sv, hdr_alloc + 1);
            p = SvPVX(hdr_sv) + pos;
        }
        memcpy(p, hp, hlen); p += hlen;
        *p++ = ':'; *p++ = ' ';
        memcpy(p, vp, vlen); p += vlen;
        *p++ = '\r'; *p++ = '\n';
    }

    // The in-loop guard's 128-byte slack is not reserved: a later header whose
    // `need` fits inside it consumes it without growing.  Everything below is
    // written unconditionally, so re-check now that the final position is known.
    {
        STRLEN pos = p - SvPVX(hdr_sv);
        if (unlikely(pos + tail_len > hdr_alloc)) {
            hdr_alloc = pos + tail_len;
            SvGROW(hdr_sv, hdr_alloc + 1);
            p = SvPVX(hdr_sv) + pos;
        }
    }

    if (unlikely(emit_zero_cl)) {
        memcpy(p, "Content-Length: 0\r\n", 19); p += 19;
    }

    // Date (every version) and Connection headers
    memcpy(p, DATE_BUF, DATE_HEADER_LENGTH); p += DATE_HEADER_LENGTH;
    if (likely(c->is_http11)) {
        if (!c->is_keepalive) {
            memcpy(p, "Connection: close\r\n", 19); p += 19;
        }
    } else if (c->is_keepalive) {
        memcpy(p, "Connection: keep-alive\r\n", 24); p += 24;
    }

    if (streaming) {
        if (c->is_http11 && !has_content_length && c->auto_cl) {
            memcpy(p, "Transfer-Encoding: chunked\r\n\r\n", 30); p += 30;
            c->use_chunked = 1;
        }
        else {
            *p++ = '\r'; *p++ = '\n';
            c->use_chunked = 0;
        }
    }

    SvCUR_set(hdr_sv, p - SvPVX(hdr_sv));
    *p = '\0';

    // Add as a single iovec entry
    {
        struct iomatrix *m = next_iomatrix(c);
        unsigned idx = m->count++;
        m->iov[idx].iov_base = SvPVX(hdr_sv);
        m->iov[idx].iov_len = SvCUR(hdr_sv);
        m->sv[idx] = hdr_sv;
        c->wbuf_len += SvCUR(hdr_sv);
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
                for (I32 i = 0; i <= amax; i++) {
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

    // For array bodies with a single element, extract the scalar for the fast path
    SV *body_scalar = NULL;
    if (body_is_string) {
        body_scalar = body;
    } else {
        AV *abody = (AV*)SvRV(body);
        if (av_len(abody) == 0) {
            SV *elem = fetch_av_normal(aTHX_ abody, 0);
            if (elem) body_scalar = elem;
        }
    }

    // Optimization: for small scalar bodies with auto_cl, append Content-Length
    // and body directly to the header iomatrix entry, producing a single iovec
    // for the entire HTTP response -> write() fast path.
    // For large bodies (>4KB), keep them as a separate iovec to avoid memcpy;
    // writev with 2-3 iovecs is fine and avoids duplicating the body buffer.
    if (likely(c->auto_cl) && !unlikely(c->app_content_length)
        && body_scalar && c->wbuf_rinq) {
        struct iomatrix *m = (struct iomatrix *)c->wbuf_rinq->prev->ref;
        unsigned last = m->count - 1;
        SV *hdr_sv = m->sv[last];

        // Guard: verify the tail iomatrix entry is the writable header SV
        // from feersum_start_response (not a const entry or NULL).
        if (unlikely(!hdr_sv || SvREADONLY(hdr_sv)))
            goto whole_body_slow_path;

        STRLEN body_len;
        const char *body_ptr = SvPV(body_scalar, body_len);
        char cl_buf[48];
        int cl_len = format_content_length(cl_buf, body_len);
        STRLEN hdr_cur = SvCUR(hdr_sv);

        if (likely(body_len <= 4096)) {
            // Small body: merge headers + CL + body into one buffer -> write()
            // HEAD advertises the same Content-Length but emits no body bytes.
            STRLEN emit_len = unlikely(c->no_resp_body) ? 0 : body_len;
            STRLEN total = hdr_cur + cl_len + emit_len;
            SvGROW(hdr_sv, total + 1);
            char *p = SvPVX(hdr_sv) + hdr_cur;
            memcpy(p, cl_buf, cl_len); p += cl_len;
            if (likely(emit_len)) { memcpy(p, body_ptr, emit_len); p += emit_len; }
            *p = '\0';
            SvCUR_set(hdr_sv, total);
            m->iov[last].iov_len = total;
            c->wbuf_len += cl_len + emit_len;
        } else {
            // Large body: append CL to header buffer, body as separate iovec
            SvGROW(hdr_sv, hdr_cur + cl_len + 1);
            memcpy(SvPVX(hdr_sv) + hdr_cur, cl_buf, cl_len);
            SvCUR_set(hdr_sv, hdr_cur + cl_len);
            SvPVX(hdr_sv)[hdr_cur + cl_len] = '\0';
            m->iov[last].iov_len = hdr_cur + cl_len;
            c->wbuf_len += cl_len;
            if (likely(!c->no_resp_body))
                add_sv_to_wbuf(c, body_scalar);
        }
        m->iov[last].iov_base = SvPVX(hdr_sv);
        RETVAL = body_len;
    }
    else { whole_body_slow_path:;
        SV *cl_sv; // content-length future
        struct iovec *cl_iov;
        /* app_content_length: the app's own Content-Length is already in the
         * header block (HEAD), so terminate the headers rather than reserving
         * a slot for a second, measured one. */
        if (likely(c->auto_cl) && !unlikely(c->app_content_length))
            add_placeholder_to_wbuf(c, &cl_sv, &cl_iov);
        else
            add_crlf_to_wbuf(c);

        // RFC 7230 section 3.3: 1xx/204/205/304 MUST NOT have a message body.
        // Skip body writes when auto_cl is 0 (no-body status codes).
        if (unlikely(!c->auto_cl)) {
            RETVAL = 0;
        }
        else if (body_is_string) {
            // HEAD: measure the body so Content-Length matches the equivalent
            // GET, but queue none of its bytes.
            if (unlikely(c->no_resp_body))
                (void)SvPV(body, cur);
            else
                cur = add_sv_to_wbuf(c,body);
            RETVAL = cur;
        }
        else {
            AV *abody = (AV*)SvRV(body);
            I32 amax = av_len(abody);
            RETVAL = 0;
            for (I32 i = 0; i <= amax; i++) {
                SV *sv = fetch_av_normal(aTHX_ abody, i);
                if (unlikely(!sv)) continue;
                if (unlikely(c->no_resp_body))
                    (void)SvPV(sv, cur);
                else
                    cur = add_sv_to_wbuf(c,sv);
                trace("body part i=%d sv=%p cur=%"Sz_uf"\n", i, sv, (Sz)cur);
                RETVAL += cur;
            }
        }

        if (likely(c->auto_cl) && !unlikely(c->app_content_length)) {
            char cl_buf[48];
            int cl_len = format_content_length(cl_buf, RETVAL);
            sv_setpvn(cl_sv, cl_buf, cl_len);
            update_wbuf_placeholder(c, cl_sv, cl_iov);
        }
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

    /* Mid-response, respond_with_server_error declines and the header block may
     * be on the wire unterminated (a tied SV in an array body whose FETCH dies,
     * say).  We cannot unsend it, but refusing to reuse the connection stops the
     * next response being read as a continuation.  Harmless if the response was
     * in fact complete - it just closes early. */
    if (unlikely(c->responding > RESPOND_NOT_STARTED
                 && c->responding < RESPOND_SHUTDOWN))
        c->is_keepalive = 0;

    /* No 500 once the app owns the byte stream, or mid-response on H1: it
     * would land on whatever protocol the app is speaking.  H2 still needs the
     * call, where it becomes RST_STREAM rather than a decline. */
    if (!c->io_taken
        && (likely(c->responding == RESPOND_NOT_STARTED)
#ifdef FEERSUM_HAS_H2
            || c->is_h2_stream
#endif
    ))
        respond_with_server_error(c, "Request handler exception\n", 500);
    sv_setsv(ERRSV, &PL_sv_undef);
}

/* Balance the pin new_feer_conn_handle took during a guarded callback.
 * errored: the callback died (ERRSV was true at the G_EVAL catch, which is
 * authoritative - the eval clears $@ on success, so an inner caught eval{}
 * cannot leak in here as a false positive).  If the app dropped every ref to
 * a still-streaming writer while dying, the drop was the unwind, not a
 * deliberate completion: seal DIRTY so the truncation is detectable (H1
 * closes without the terminating chunk; H2 was already RST by call_died).
 * A writer close()d before the die is already RESPOND_SHUTDOWN and keeps its
 * clean completion; a writer the app still holds stays usable, as before. */
static void
feersum_writer_unpin(pTHX_ struct feer_conn *c, bool errored)
{
    SV *pin = c->pinned_writer;
    if (likely(!pin)) return;
    c->pinned_writer = NULL;
    if (unlikely(errored) && SvREFCNT(pin) == 1
        && c->responding == RESPOND_STREAMING) {
        trace("callback died mid-stream, sealing dirty fd=%d c=%p\n", c->fd, c);
        c->is_keepalive = 0;    /* call_died did this too; keep it load-bearing */
        change_responding_state(c, RESPOND_SHUTDOWN);
        conn_write_ready(c);    /* flush partial data, then close */
    }
    /* No error: if the app dropped its refs, this dec runs the ordinary
     * DESTROY -> close path and the response completes cleanly as ever. */
    SvREFCNT_dec(pin);
}

static void
feersum_start_psgi_streaming(pTHX_ struct feer_conn *c, SV *streamer)
{
    dSP;
    bool errored;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    mXPUSHs(feer_conn_2sv(c));
    XPUSHs(streamer);
    PUTBACK;
    c->pin_writer = 1;
    call_method("_initiate_streaming_psgi", G_DISCARD|G_EVAL|G_VOID);
    c->pin_writer = 0;
    SPAGAIN;
    errored = SvTRUE(ERRSV) ? TRUE : FALSE;
    if (unlikely(errored)) {
        call_died(aTHX_ c, "PSGI stream initiator");
    }
    feersum_writer_unpin(aTHX_ c, errored);
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
    /* Flatten a tied response array before av_len/av_fetch touch it: those
     * fire FETCHSIZE/FETCH, and a die there has no G_EVAL above it. */
    psgi_triplet = feersum_flatten_magical_av(aTHX_ psgi_triplet);
    if (unlikely(!psgi_triplet)) {
        call_died(aTHX_ c, "PSGI request");
        return;
    }
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
    /* Same treatment as the triplet, and then some: the framing scan and both
     * header-builder passes walk AvARRAY directly and SvPV every element, so a
     * tied array, a dying "" overload and a value that stringifies to a
     * different length on a second read are all hazards here. */
    headers = feersum_flatten_headers(aTHX_ headers);
    if (unlikely(!headers)) {
        call_died(aTHX_ c, "PSGI request");
        return;
    }

    /* Pre-validate everything feersum_start_response would croak() on. The
     * PSGI dispatch path runs outside any G_EVAL frame (call_request_callback
     * already exited its call_sv G_EVAL before reaching here), so a croak
     * would unwind through the libev callback into Perl space and crash the
     * worker. Convert each croak case into call_died here. */
    if (unlikely((av_len(headers) + 1) % 2 == 1)) {
        sv_setpvs(ERRSV, "PSGI headers must be an even-length array");
        call_died(aTHX_ c, "PSGI request");
        return;
    }
    {
        const char *serr = feersum_check_psgi_status(aTHX_ msg);
        if (unlikely(serr)) {
            sv_setpv(ERRSV, serr);
            call_died(aTHX_ c, "PSGI request");
            return;
        }
    }
    /* start_response croaks on this, and this path has no G_EVAL above it. */
    if (unlikely(c->io_taken)) {
        sv_setpvs(ERRSV, "PSGI app took psgix.io and then returned a response; "
                         "call return_from_psgix_io first");
        call_died(aTHX_ c, "PSGI request");
        return;
    }
    {
        const char *err = feersum_check_response_framing(aTHX_ msg, headers);
        if (unlikely(err)) {
            sv_setpv(ERRSV, err);
            call_died(aTHX_ c, "PSGI request");
            return;
        }
    }

    /* start_response can finish the response by itself: an H2 stream reset
     * between dispatch and response leaves an orphaned pseudo-conn in
     * RESPOND_SHUTDOWN, as does a no-body H2 streaming response.  Writing a
     * body then croaks on the state check - fatally, since as noted above
     * there is no G_EVAL over this path.  One HEADERS+RST_STREAM pair used to
     * kill the worker outright. */
    if (likely(IsArrayRef(body))) {
        SV *flat = feersum_flatten_magical_body(aTHX_ body);
        if (unlikely(!flat)) {          /* a tied FETCH died; ERRSV is set */
            call_died(aTHX_ c, "PSGI request");
            return;
        }
        body = flat;
        feersum_start_response(aTHX_ c, msg, headers, 0, 1);
        if (unlikely(c->responding >= RESPOND_SHUTDOWN)) return;
        feersum_write_whole_body(aTHX_ c, body);
    }
    // Only an object, glob or IO can answer getline().  Without this test a
    // plain SCALAR/HASH/CODE ref got its response STARTED and then died on
    // "Can't call method getline on unblessed reference", leaving the client
    // with a 200 and no body (and no terminating chunk), where a bare string
    // body is cleanly rejected with a 500 a few lines below.
    else if (likely(SvROK(body)
                    && (sv_isobject(body)
                        || SvTYPE(SvRV(body)) == SVt_PVGV
                        || SvTYPE(SvRV(body)) == SVt_PVIO))) {
        feersum_start_response(aTHX_ c, msg, headers, 1, 1);
        if (unlikely(c->responding >= RESPOND_SHUTDOWN)) return;
        /* H2 goes through the same paced pump as poll_cb bodies.  Draining
         * the handle synchronously instead never returned to the event loop,
         * so no WINDOW_UPDATE was ever read: past the peer's initial 64 KiB
         * window every further chunk piled into resp_wbuf and the whole body
         * went resident (a 100 MB file cost ~135 MB of RSS). */
        c->poll_write_cb = newSVsv(body);
        c->poll_write_cb_is_io_handle = 1;
        conn_write_ready(c);
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
        /* Body already fully received (the usual case: finish_receiving sets
         * RECEIVE_SHUTDOWN before the handler runs).  Don't touch rbuf or the
         * socket - rbuf may hold a pipelined request, and shutdown(SHUT_RD)
         * would make the next keepalive read hit EOF.  The drain in
         * handle_keepalive_or_close discards leftover body and keeps the
         * pipeline; the POD advises closing psgi.input, so this path must not
         * break connection reuse. */
        if (c->receiving == RECEIVE_SHUTDOWN) {
            RETVAL = 0;
        }
        else {
            /* Still arriving: the app is abandoning an upload. */
            if (c->rbuf) {
                SvREFCNT_dec(c->rbuf);
                c->rbuf = NULL;
            }
            /* fd_given_away: a raw takeover handed this descriptor to the app,
             * so half-closing it here would kill the app's own reads.  The
             * only operation on c->fd outside safe_close_conn, which already
             * refuses for the same reason. */
            if (c->fd >= 0 && !c->fd_given_away
#ifdef FEERSUM_HAS_H2
                && !c->is_h2_stream
#endif
            )
                RETVAL = shutdown(c->fd, SHUT_RD);
            else
                RETVAL = -1;  // already closed or H2 stream
            change_receiving_state(c, RECEIVE_SHUTDOWN);
        }
    }

    // disassociate the handle from the conn
    SvREFCNT_dec(c->self);
    return RETVAL;
}

static SV*
feersum_conn_guard(pTHX_ struct feer_conn *c, SV *guard)
{
    if (guard) {
        SvREFCNT_dec(c->ext_guard); /* NULL-safe */
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

    /* Snapshot for the access log before the handler runs: req->method/uri
     * point into rbuf, which the next request on this connection reuses. */
    if (unlikely(server->access_log_cb_cv != NULL) && likely(c->req != NULL)) {
        SvREFCNT_dec(c->log_method);   /* NULL-safe; a previous line unsent */
        SvREFCNT_dec(c->log_uri);
        c->log_method = newSVpvn(c->req->method, c->req->method_len);
        c->log_uri = newSVpvn(c->req->uri, c->req->uri_len);
        c->req_start = ev_now(feersum_ev_loop);
    }

    /* Worker retirement, checked here rather than from a Perl watcher: a 1s
     * poll overshot by three orders of magnitude under load, and a per-loop
     * Perl callback would cost more than the counter it guards.  One-shot. */
    if (unlikely(server->max_requests)
        && server->total_requests >= server->max_requests
        && !server->shutting_down)
    {
        server->max_requests = 0;      /* one-shot */
        server->retire_pending = 1;    /* check_cb drains at a loop boundary */
    }

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
    c->pin_writer = 1;
    int returned = call_sv(server->request_cb_cv, flags);
    c->pin_writer = 0;
    SPAGAIN;

    trace("called request callback, errsv? %d\n", SvTRUE(ERRSV) ? 1 : 0);

    bool req_cb_errored = SvTRUE(ERRSV) ? TRUE : FALSE;
    if (unlikely(req_cb_errored)) {
        call_died(aTHX_ c, "request");
        // call_sv(G_SCALAR) still pushed a value (undef) before unwinding, and
        // call_died has just run more Perl, so re-fetch SP and drop it.  Simply
        // zeroing `returned` left that slot on the stack and PUTBACK committed
        // the higher SP - one slot leaked per dying request, until the stack
        // had to grow and the process aborted.
        SPAGAIN;
        if (returned > 0) SP -= returned;
        PUTBACK;
        returned = 0;
    }
    /* Native handlers create their writer inside the call above; decide its
     * fate now, before the PSGI streamer (which pins its own) can run. */
    feersum_writer_unpin(aTHX_ c, req_cb_errored);

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
        /* Clear the callback (pump_io_handle does the same on its error
         * path): leaving it installed makes the write path re-arm the watcher
         * and re-invoke it immediately, spinning at 100% CPU forever. */
        SV **cb_slot = is_write ? &c->poll_write_cb : &c->poll_read_cb;
        if (*cb_slot) {
            SV *tmp = *cb_slot;
            *cb_slot = NULL;
            if (is_write) c->poll_write_cb_is_io_handle = 0;
            SvREFCNT_dec(tmp);
        }
        call_died(aTHX_ c, is_write ? "write poll" : "read poll");
        /* Mid-response call_died cannot send a 500, so end the response: a
         * truncated body is detectable, a hung connection is not. */
        if (c->responding > RESPOND_NOT_STARTED
            && c->responding < RESPOND_SHUTDOWN) {
            c->is_keepalive = 0;
            change_responding_state(c, RESPOND_SHUTDOWN);
        }
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
pump_io_handle (struct feer_conn *c)
{
    dTHX;
    dSP;

    if (unlikely(c->poll_write_cb == NULL)) return;

    c->in_callback++;

    trace("pump io handle %d\n", c->fd);

    SV *old_rs = PL_rs;
    SvREFCNT_inc_simple_void(old_rs);

    ENTER;
    SAVETMPS;

    /* Mortalise inside the scope: SAVETMPS sets the floor at the current top,
     * so a mortal made before it is BELOW the floor and the FREETMPS below
     * cannot reap it - which is what the epilogue comment assumes it does. */
    PL_rs = sv_2mortal(newRV_noinc(newSViv(IO_PUMP_BUFSZ)));
    sv_setsv(get_sv("/", GV_ADD), PL_rs);

    // No content to send: HEAD, or a status that carries none.  A no-body
    // status gets neither Content-Length nor chunked framing, so anything
    // pumped here lands undelimited and the next keepalive response is read as
    // its body.  write()/write_array() screen !auto_cl the same way.  EOF falls
    // into the branch below, which closes the handle and finishes up.
    int returned;
    if (unlikely(c->no_resp_body || !c->auto_cl)) {
        returned = 0;
    }
    else {
        PUSHMARK(SP);
        XPUSHs(c->poll_write_cb);
        PUTBACK;
        returned = call_method("getline", G_SCALAR|G_EVAL);
        SPAGAIN;
    }

    trace("called getline on io handle fd=%d errsv=%d returned=%d\n",
        c->fd, SvTRUE(ERRSV) ? 1 : 0, returned);

    if (unlikely(SvTRUE(ERRSV))) {
        /* Restore PL_rs before call_died - it invokes Feersum::DIED which
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
            trouble("Couldn't close body IO handle: %-p\n", ERRSV);
            sv_setsv(ERRSV, &PL_sv_undef);
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

    // Restore PL_rs before FREETMPS - the mortal RV set above
    // would be freed by FREETMPS, leaving PL_rs as a dangling pointer.
    PL_rs = old_rs;
    sv_setsv(get_sv("/", GV_ADD), old_rs);
    SvREFCNT_dec(old_rs);

    PUTBACK;
    FREETMPS;
    LEAVE;

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
        struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
        if (!stream || !stream->is_tunnel) {
            /* Not a tunnel: psgix.io is unavailable. Return undef (magic is
             * already stripped) rather than leaving the fd-int backing value
             * in place, which would read as a truthy handle to the app. The
             * native io() croaks for the same case; magic-get must not, since
             * it can fire from innocuous env inspection. */
            trouble("psgix.io: not supported on regular H2 streams fd=%d\n", c->fd);
            sv_setsv(sv, &PL_sv_undef);
            return 0;
        }
        h2_tunnel_auto_accept(aTHX_ c, stream);
        /* Re-fetch stream: auto_accept -> session_send may have freed it */
        stream = H2_STREAM_FROM_PC(c);
        if (!stream) {
            trouble("psgix.io: stream freed during auto_accept fd=%d\n", c->fd);
            sv_setsv(sv, &PL_sv_undef);
            return 0;
        }
        feer_h2_setup_tunnel(aTHX_ stream);
        if (!stream->tunnel_established) {
            trouble("psgix.io: tunnel setup failed fd=%d\n", c->fd);
            struct feer_conn *parent = stream->parent;
            SvREFCNT_inc_void_NN(parent->self);
            h2_submit_rst(parent->h2_session, stream->stream_id,
                          NGHTTP2_INTERNAL_ERROR);
            feer_h2_session_send(parent);
            SvREFCNT_dec(parent->self);
            sv_setsv(sv, &PL_sv_undef);
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

        /* new_from_fd returns undef without dying when fdopen fails, so a
         * clear ERRSV is not enough: SvRV on a non-RV would deref the fd. */
        if (unlikely(SvTRUE(ERRSV) || !SvROK(sv))) {
            call_died(aTHX_ c, "psgix.io H2 tunnel magic");
            sv_setsv(sv, &PL_sv_undef);
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
            sv_setsv(sv, &PL_sv_undef);
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

        if (unlikely(SvTRUE(ERRSV) || !SvROK(sv))) {
            call_died(aTHX_ c, "psgix.io TLS tunnel magic");
            sv_setsv(sv, &PL_sv_undef);
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

    if (unlikely(SvTRUE(ERRSV) || !SvROK(sv))) {
        call_died(aTHX_ c, "psgix.io magic");
        sv_setsv(sv, &PL_sv_undef);
    }
    else {
        SV *io_glob   = SvRV(sv);
        GvSV(io_glob) = newRV_inc(c->self);

        feer_hand_out_raw_fd(aTHX_ c, io_glob, "psgix.io");
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
    feersum_start_response(aTHX_ c, status_sv, empty_hdr, 1, 1);
    SvREFCNT_dec(status_sv);
    SvREFCNT_dec((SV *)empty_hdr);
    /* Re-fetch stream: feersum_start_response -> feer_h2_session_send may
     * have freed it via h2_on_stream_close_cb (e.g. RST_STREAM queued) */
    stream = H2_STREAM_FROM_PC(c);
    if (stream)
        stream->tunnel_swallow_response = 1;
}

/*
 * One getline from an H2 IO-handle body, called from h2_try_stream_write in
 * place of the poll_cb.  A single step per pump iteration is the whole point:
 * draining the handle in one synchronous loop never returned to the event
 * loop, so no WINDOW_UPDATE was read and the entire body accumulated in
 * resp_wbuf.  Returns 0 at EOF (handle closed, stream finished), 1 otherwise.
 */
static int
pump_h2_io_step(pTHX_ struct feer_conn *c)
{
    dSP;
    if (unlikely(!c->poll_write_cb)) return 0;

    /* in_callback makes feersum_h2_write_chunk BUFFER instead of flushing.
     * Without it the flush re-enters h2_check_stream_poll_cbs -> this same
     * pump recursively, which freed the stream underneath the caller and
     * corrupted the heap.  Same contract call_poll_callback observes. */
    c->in_callback++;

    SV *old_rs = PL_rs;
    SvREFCNT_inc_simple_void(old_rs);
    ENTER;
    SAVETMPS;
    /* Mortalise inside the scope, as pump_io_handle does. */
    PL_rs = sv_2mortal(newRV_noinc(newSViv(IO_PUMP_BUFSZ)));
    sv_setsv(get_sv("/", GV_ADD), PL_rs);

    PUSHMARK(SP);
    XPUSHs(c->poll_write_cb);
    PUTBACK;
    int returned = call_method("getline", G_SCALAR|G_EVAL);
    SPAGAIN;

    if (unlikely(SvTRUE(ERRSV))) {
        PL_rs = old_rs;
        sv_setsv(get_sv("/", GV_ADD), old_rs);
        call_died(aTHX_ c, "getline on H2 io handle");
        SvREFCNT_dec(c->poll_write_cb);
        c->poll_write_cb = NULL;
        c->poll_write_cb_is_io_handle = 0;
        PUTBACK; FREETMPS; LEAVE;
        SvREFCNT_dec(old_rs);
        c->in_callback--;
        feersum_h2_close_write(aTHX_ c);
        return 0;
    }

    SV *ret = NULL;
    if (returned > 0) ret = POPs;
    if (ret && SvMAGICAL(ret)) ret = sv_2mortal(newSVsv(ret));

    int more = 1;
    if (unlikely(!ret || !SvOK(ret))) {   /* undef is EOF; q{} is not */
        PUSHMARK(SP);
        XPUSHs(c->poll_write_cb);
        PUTBACK;
        call_method("close", G_VOID|G_DISCARD|G_EVAL);
        SPAGAIN;
        if (unlikely(SvTRUE(ERRSV))) {
            trouble("Couldn't close body IO handle: %-p\n", ERRSV);
            sv_setsv(ERRSV, &PL_sv_undef);
        }
        SvREFCNT_dec(c->poll_write_cb);
        c->poll_write_cb = NULL;
        c->poll_write_cb_is_io_handle = 0;
        more = 0;
    }
    else {
        feersum_h2_write_chunk(aTHX_ c, ret);
    }

    PL_rs = old_rs;
    sv_setsv(get_sv("/", GV_ADD), old_rs);
    PUTBACK; FREETMPS; LEAVE;
    SvREFCNT_dec(old_rs);

    c->in_callback--;
    if (!more) feersum_h2_close_write(aTHX_ c);
    return more;
}

static SV*
feersum_env_method_h2(pTHX_ struct feer_conn *c, struct feer_req *r)
{
    if (unlikely(c->is_h2_stream)) {
        struct feer_h2_stream *stream = H2_STREAM_FROM_PC(c);
        if (stream && stream->is_tunnel && stream->h2_protocol)
            return SvREFCNT_inc_simple_NN(method_GET);
    }
    return feersum_env_method(aTHX_ r);
}
#endif
