/*
 * feersum_tls.c.inc - TLS 1.3 support via picotls for Feersum
 *
 * This file is #included into Feersum.xs when FEERSUM_HAS_TLS is defined.
 * It provides separate read/write callbacks for TLS connections so that
 * plain HTTP connections are never disturbed.
 *
 * Flow:
 *   Plain:  accept -> try_conn_read/write (unchanged)
 *   TLS+H1: accept -> try_tls_conn_read/write -> decrypt -> H1 parser
 *   TLS+H2: accept -> try_tls_conn_read/write -> decrypt -> nghttp2
 */

#ifdef FEERSUM_HAS_TLS

/* ALPN protocols list for negotiation */
static ptls_iovec_t tls_alpn_protos[] = {
#ifdef FEERSUM_HAS_H2
    { (uint8_t *)ALPN_H2 + 1, 2 },       /* "h2" */
#endif
    { (uint8_t *)ALPN_HTTP11 + 1, 8 },    /* "http/1.1" */
};

/* HTTP/1.1-only ALPN — used when h2 is not enabled on a listener */
static ptls_iovec_t tls_alpn_h1_only[] = {
    { (uint8_t *)ALPN_HTTP11 + 1, 8 },    /* "http/1.1" */
};

static int
negotiate_alpn(ptls_t *tls, const ptls_iovec_t *protos, size_t num_protos,
               ptls_on_client_hello_parameters_t *params)
{
    size_t i, j;
    for (i = 0; i < num_protos; i++) {
        for (j = 0; j < params->negotiated_protocols.count; j++) {
            if (params->negotiated_protocols.list[j].len == protos[i].len &&
                memcmp(params->negotiated_protocols.list[j].base, protos[i].base,
                       protos[i].len) == 0) {
                ptls_set_negotiated_protocol(tls,
                    (const char *)protos[i].base, protos[i].len);
                return 0;
            }
        }
    }
    /* No matching protocol; proceed without ALPN (will default to HTTP/1.1) */
    return 0;
}

/*
 * SNI lookup: find a matching context for the client's server_name.
 * If found, swap tls->ctx so picotls uses the right cert for the handshake.
 */
static void
sni_lookup(ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    struct feer_listen *lsnr = *(struct feer_listen **)ptls_get_data_ptr(tls);
    if (!lsnr || lsnr->n_sni_entries == 0 || !params->server_name.base)
        return;

    /* hostname is pre-lowered at registration; ASCII-only per RFC 6066 */
    size_t name_len = params->server_name.len;
    int i;
    for (i = 0; i < lsnr->n_sni_entries; i++) {
        struct feer_sni_entry *e = &lsnr->sni_entries[i];
        if (strlen(e->hostname) == name_len &&
            str_case_eq_fixed(e->hostname,
                              (const char *)params->server_name.base, name_len)) {
            ptls_set_context(tls, e->ctx_ref->ctx);
            return;
        }
    }
    /* No match — default context stays */
}

static int
on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                   ptls_on_client_hello_parameters_t *params)
{
    PERL_UNUSED_VAR(self);
    sni_lookup(tls, params);
    return negotiate_alpn(tls, tls_alpn_protos,
        sizeof(tls_alpn_protos) / sizeof(tls_alpn_protos[0]), params);
}

static ptls_on_client_hello_t on_client_hello = { on_client_hello_cb };

static int
on_client_hello_no_h2_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                         ptls_on_client_hello_parameters_t *params)
{
    PERL_UNUSED_VAR(self);
    sni_lookup(tls, params);
    return negotiate_alpn(tls, tls_alpn_h1_only,
        sizeof(tls_alpn_h1_only) / sizeof(tls_alpn_h1_only[0]), params);
}

static ptls_on_client_hello_t on_client_hello_no_h2 = { on_client_hello_no_h2_cb };

static ptls_key_exchange_algorithm_t *feer_tls_key_exchanges[] = {
#if PTLS_OPENSSL_HAVE_X25519
    &ptls_openssl_x25519,
#endif
    &ptls_openssl_secp256r1,
    NULL
};

static ptls_cipher_suite_t *feer_tls_cipher_suites[] = {
    &ptls_openssl_aes256gcmsha384,
    &ptls_openssl_aes128gcmsha256,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    &ptls_openssl_chacha20poly1305sha256,
#endif
    NULL
};

/*
 * Create a picotls server context from certificate and key files.
 * Returns NULL on failure (with warnings emitted).
 */
static ptls_context_t *
feer_tls_create_context(pTHX_ const char *cert_file, const char *key_file, int h2)
{
    ptls_context_t *ctx;
    FILE *fp;
    int ret;

    Newxz(ctx, 1, ptls_context_t);

    ctx->random_bytes = ptls_openssl_random_bytes;
    ctx->get_time = &ptls_get_time;
    ctx->key_exchanges = feer_tls_key_exchanges;
    ctx->cipher_suites = feer_tls_cipher_suites;

    /* Load certificate chain */
    ret = ptls_load_certificates(ctx, cert_file);
    if (ret != 0) {
        warn("Feersum TLS: failed to load certificate from '%s' (error %d)\n",
             cert_file, ret);
        feer_tls_free_context(ctx);
        return NULL;
    }

    /* Load private key */
    fp = fopen(key_file, "r");
    if (!fp) {
        warn("Feersum TLS: failed to open key file '%s': %s\n",
             key_file, strerror(errno));
        goto cert_cleanup;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        warn("Feersum TLS: failed to read private key from '%s'\n", key_file);
        goto cert_cleanup;
    }

    ptls_openssl_sign_certificate_t *sign_cert;
    Newx(sign_cert, 1, ptls_openssl_sign_certificate_t);
    if (ptls_openssl_init_sign_certificate(sign_cert, pkey) != 0) {
        Safefree(sign_cert);
        EVP_PKEY_free(pkey);
        warn("Feersum TLS: incompatible private key type in '%s'\n", key_file);
        goto cert_cleanup;
    }
    EVP_PKEY_free(pkey);
    ctx->sign_certificate = &sign_cert->super;

    /* ALPN negotiation via on_client_hello callback */
    if (h2)
        ctx->on_client_hello = &on_client_hello;
    else
        ctx->on_client_hello = &on_client_hello_no_h2;

    trace("TLS context created: cert=%s key=%s h2=%d\n", cert_file, key_file, h2);
    return ctx;

cert_cleanup:
    feer_tls_free_context(ctx);
    return NULL;
}

/*
 * Free a TLS context and its resources.
 */
static void
feer_tls_free_context(ptls_context_t *ctx)
{
    if (!ctx) return;
    if (ctx->certificates.list) {
        size_t i;
        for (i = 0; i < ctx->certificates.count; i++)
            free(ctx->certificates.list[i].base);
        free(ctx->certificates.list);
    }
    /* Free per-context sign certificate (allocated in feer_tls_create_context) */
    if (ctx->sign_certificate) {
        ptls_openssl_sign_certificate_t *sign_cert =
            (ptls_openssl_sign_certificate_t *)ctx->sign_certificate;
        ptls_openssl_dispose_sign_certificate(sign_cert);
        Safefree(sign_cert);
    }
    Safefree(ctx);
}

/*
 * Reference-counted TLS context wrapper.
 * Prevents use-after-free when set_tls rotates certs or accept_on_fd
 * reuses a listener slot while active connections still hold ptls_t
 * objects that reference the old context.
 */
static struct feer_tls_ctx_ref *
feer_tls_ctx_ref_new(ptls_context_t *ctx)
{
    struct feer_tls_ctx_ref *ref;
    Newx(ref, 1, struct feer_tls_ctx_ref);
    ref->ctx = ctx;
    ref->refcount = 1;
    return ref;
}

static void
feer_tls_ctx_ref_dec(struct feer_tls_ctx_ref *ref)
{
    if (--ref->refcount <= 0) {
        feer_tls_free_context(ref->ctx);
        Safefree(ref);
    }
}

/*
 * Free all TLS state on a listener (default context + SNI entries).
 */
static void
feer_tls_cleanup_listener(struct feer_listen *lsnr)
{
    int i;
    if (lsnr->tls_ctx_ref) {
        feer_tls_ctx_ref_dec(lsnr->tls_ctx_ref);
        lsnr->tls_ctx_ref = NULL;
    }
    for (i = 0; i < lsnr->n_sni_entries; i++) {
        Safefree(lsnr->sni_entries[i].hostname);
        feer_tls_ctx_ref_dec(lsnr->sni_entries[i].ctx_ref);
    }
    lsnr->n_sni_entries = 0;
}

/*
 * Initialize TLS state on a newly accepted connection.
 */
static void
feer_tls_init_conn(struct feer_conn *c, struct feer_tls_ctx_ref *ref)
{
    c->tls = ptls_new(ref->ctx, 1 /* is_server */);
    if (unlikely(!c->tls)) {
        trouble("ptls_new failed for fd=%d\n", c->fd);
        return;
    }
    /* Store listener pointer for SNI lookup in on_client_hello */
    *ptls_get_data_ptr(c->tls) = c->listener;
    ref->refcount++;
    c->tls_ctx_ref = ref;
    ptls_buffer_init(&c->tls_wbuf, "", 0);
    c->tls_tunnel_sv0 = -1;
    c->tls_tunnel_sv1 = -1;
}

/*
 * Free TLS state on connection destruction.
 */
static void
feer_tls_free_conn(struct feer_conn *c)
{
    if (c->tls) {
        ptls_free(c->tls);
        c->tls = NULL;
    }
    if (c->tls_ctx_ref) {
        feer_tls_ctx_ref_dec(c->tls_ctx_ref);
        c->tls_ctx_ref = NULL;
    }
    ptls_buffer_dispose(&c->tls_wbuf);
    if (c->tls_rbuf) {
        Safefree(c->tls_rbuf);
        c->tls_rbuf = NULL;
        c->tls_rbuf_len = 0;
    }
    if (c->tls_tunnel) {
        ev_io_stop(feersum_ev_loop, &c->tls_tunnel_read_w);
        ev_io_stop(feersum_ev_loop, &c->tls_tunnel_write_w);
        c->tls_tunnel = 0;
        if (c->tls_tunnel_sv0 >= 0) {
            close(c->tls_tunnel_sv0);
            c->tls_tunnel_sv0 = -1;
        }
        if (c->tls_tunnel_sv1 >= 0) {
            close(c->tls_tunnel_sv1);
            c->tls_tunnel_sv1 = -1;
        }
        if (c->tls_tunnel_wbuf) {
            dTHX;
            SvREFCNT_dec(c->tls_tunnel_wbuf);
            c->tls_tunnel_wbuf = NULL;
            c->tls_tunnel_wbuf_pos = 0;
        }
    }
}

/*
 * Flush accumulated encrypted data from tls_wbuf to the socket.
 * Returns: number of bytes written, 0 if nothing to write, -1 on EAGAIN, -2 on error.
 */
static int
feer_tls_flush_wbuf(struct feer_conn *c)
{
    if (c->tls_wbuf.off == 0)
        return 0;

    ssize_t written = write(c->fd, c->tls_wbuf.base, c->tls_wbuf.off);
    if (written < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return -1;
        }
        trace("TLS flush write error fd=%d: %s\n", c->fd, strerror(errno));
        return -2;
    }

    if ((size_t)written < c->tls_wbuf.off) {
        /* Partial write: shift remaining data to front */
        memmove(c->tls_wbuf.base, c->tls_wbuf.base + written,
                c->tls_wbuf.off - written);
        c->tls_wbuf.off -= written;
        return (int)written;
    }

    /* Full write */
    c->tls_wbuf.off = 0;
    return (int)written;
}

#define tls_wbuf_append(buf, src, len) ptls_buffer__do_pushv(buf, src, len)

/*
 * ======= TLS Tunnel (socketpair relay for io()/psgix.io over TLS) =======
 *
 * When io() is called on a TLS connection, we create a socketpair:
 *   sv[0] = Feersum's end (with ev_io watchers)
 *   sv[1] = handler's end (returned as IO handle)
 *
 * Data flow:
 *   App writes to sv[1] -> sv[0] readable -> encrypt via ptls -> send to TLS fd
 *   TLS fd readable -> decrypt via ptls -> write to sv[0] -> sv[1] readable for app
 */


/*
 * Try to write data to sv[0]; buffer any remainder in tls_tunnel_wbuf.
 * Returns 0 on success, -1 on hard write error.
 */
static int
tls_tunnel_write_or_buffer(struct feer_conn *c, const char *data, size_t len)
{
    dTHX;
    if (c->tls_tunnel_sv0 < 0) return -1;

    ssize_t nw = write(c->tls_tunnel_sv0, data, len);
    if (nw == (ssize_t)len)
        return 0;

    if (nw < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return -1;
        nw = 0;
    }

    size_t remaining = len - nw;
    if (!c->tls_tunnel_wbuf) {
        c->tls_tunnel_wbuf = newSV_buf(remaining + 256);
    }

    /* Compact consumed prefix to prevent unbounded SV growth */
    if (c->tls_tunnel_wbuf_pos > 0) {
        STRLEN remain = SvCUR(c->tls_tunnel_wbuf) - c->tls_tunnel_wbuf_pos;
        if (remain > 0)
            memmove(SvPVX(c->tls_tunnel_wbuf),
                    SvPVX(c->tls_tunnel_wbuf) + c->tls_tunnel_wbuf_pos,
                    remain);
        SvCUR_set(c->tls_tunnel_wbuf, remain);
        c->tls_tunnel_wbuf_pos = 0;
    }

    if (SvCUR(c->tls_tunnel_wbuf) + remaining > FEER_TUNNEL_MAX_WBUF) {
        trouble("TLS tunnel wbuf overflow fd=%d\n", c->fd);
        return -1;
    }

    sv_catpvn(c->tls_tunnel_wbuf, data + nw, remaining);
    if (!ev_is_active(&c->tls_tunnel_write_w))
        ev_io_start(feersum_ev_loop, &c->tls_tunnel_write_w);
    return 0;
}

/*
 * ev_io callback: sv[0] is readable — app wrote data to sv[1].
 * Read from sv[0], encrypt via picotls, send to TLS fd.
 */
static int feer_tls_drain_one_record(struct feer_conn *c, ptls_buffer_t *decbuf);

static void
drain_tls_tunnel_rbuf(struct feer_conn *c)
{
    while (c->tls_tunnel && c->tls_rbuf_len > 0) {
        if (ev_is_active(&c->tls_tunnel_write_w))
            break; /* sv[0] full — let write watcher drain first */
        ptls_buffer_t db;
        int drain_rv = feer_tls_drain_one_record(c, &db);
        if (drain_rv < 0) break;
        if (drain_rv == 1) continue; /* non-data (e.g. KeyUpdate) */
        if (tls_tunnel_write_or_buffer(c, (const char *)db.base, db.off) < 0) {
            ptls_buffer_dispose(&db);
            stop_all_watchers(c);
            safe_close_conn(c, "TLS tunnel drain error");
            change_responding_state(c, RESPOND_SHUTDOWN);
            return;
        }
        ptls_buffer_dispose(&db);
    }
}

static void
tls_tunnel_sv0_read_cb(EV_P_ struct ev_io *w, int revents)
{
    struct feer_conn *c = (struct feer_conn *)w->data;
    PERL_UNUSED_VAR(revents);
    SvREFCNT_inc_void_NN(c->self);

    char buf[FEER_TUNNEL_BUFSZ];
    ssize_t nread = read(c->tls_tunnel_sv0, buf, sizeof(buf));

    if (nread == 0) {
        /* App closed sv[1] — EOF; close connection */
        stop_all_watchers(c);
        safe_close_conn(c, "TLS tunnel EOF");
        change_responding_state(c, RESPOND_SHUTDOWN);
        goto cleanup;
    }
    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            goto cleanup;
        stop_all_watchers(c);
        safe_close_conn(c, "TLS tunnel read error");
        change_responding_state(c, RESPOND_SHUTDOWN);
        goto cleanup;
    }

    /* Encrypt and queue for sending */
    if (feer_tls_send(c, buf, nread) != 0) {
        stop_all_watchers(c);
        safe_close_conn(c, "TLS tunnel encrypt error");
        change_responding_state(c, RESPOND_SHUTDOWN);
        goto cleanup;
    }

    /* Flush encrypted data to socket */
    int flush_ret = feer_tls_flush_wbuf(c);
    if (flush_ret == -2) {
        stop_all_watchers(c);
        safe_close_conn(c, "TLS tunnel flush error");
        change_responding_state(c, RESPOND_SHUTDOWN);
        goto cleanup;
    }
    if (c->tls_wbuf.off > 0)
        start_write_watcher(c);

cleanup:
    SvREFCNT_dec(c->self);
}

/*
 * ev_io callback: sv[0] is writable — drain tls_tunnel_wbuf
 * (decrypted client data -> app).
 */
static void
tls_tunnel_sv0_write_cb(EV_P_ struct ev_io *w, int revents)
{
    PERL_UNUSED_VAR(revents);
    struct feer_conn *c = (struct feer_conn *)w->data;
    SvREFCNT_inc_void_NN(c->self);

    if (!c->tls_tunnel_wbuf ||
        SvCUR(c->tls_tunnel_wbuf) <= c->tls_tunnel_wbuf_pos) {
        ev_io_stop(feersum_ev_loop, &c->tls_tunnel_write_w);
        if (c->tls_tunnel_wbuf) {
            SvCUR_set(c->tls_tunnel_wbuf, 0);
            c->tls_tunnel_wbuf_pos = 0;
        }
        goto cleanup;
    }

    STRLEN avail = SvCUR(c->tls_tunnel_wbuf) - c->tls_tunnel_wbuf_pos;
    const char *ptr = SvPVX(c->tls_tunnel_wbuf) + c->tls_tunnel_wbuf_pos;
    ssize_t nw = write(c->tls_tunnel_sv0, ptr, avail);

    if (nw < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            goto cleanup;
        stop_all_watchers(c);
        safe_close_conn(c, "TLS tunnel write error");
        change_responding_state(c, RESPOND_SHUTDOWN);
        goto cleanup;
    }

    c->tls_tunnel_wbuf_pos += nw;
    if (c->tls_tunnel_wbuf_pos >= SvCUR(c->tls_tunnel_wbuf)) {
        ev_io_stop(feersum_ev_loop, &c->tls_tunnel_write_w);
        SvCUR_set(c->tls_tunnel_wbuf, 0);
        c->tls_tunnel_wbuf_pos = 0;

        /* Resume draining tls_rbuf now that sv[0] has space */
        if (c->tls_rbuf_len > 0)
            drain_tls_tunnel_rbuf(c);
    }

cleanup:
    SvREFCNT_dec(c->self);
}

/*
 * Set up TLS tunnel socketpair for io()/psgix.io over TLS.
 */
static void
feer_tls_setup_tunnel(struct feer_conn *c)
{
    if (c->tls_tunnel) return;

    int sv[2];
    if (feer_socketpair_nb(sv) < 0) {
        trouble("socketpair/fcntl failed for TLS tunnel fd=%d: %s\n",
                c->fd, strerror(errno));
        return;
    }

    c->tls_tunnel_sv0 = sv[0];
    c->tls_tunnel_sv1 = sv[1];

    /* Read watcher: fires when app writes to sv[1] */
    ev_io_init(&c->tls_tunnel_read_w, tls_tunnel_sv0_read_cb, sv[0], EV_READ);
    c->tls_tunnel_read_w.data = (void *)c;
    ev_io_start(feersum_ev_loop, &c->tls_tunnel_read_w);

    /* Write watcher: initialized but NOT started until we have data to write */
    ev_io_init(&c->tls_tunnel_write_w, tls_tunnel_sv0_write_cb, sv[0], EV_WRITE);
    c->tls_tunnel_write_w.data = (void *)c;

    c->tls_tunnel = 1;

    /* Flush any existing rbuf data through the tunnel */
    if (c->rbuf && SvOK(c->rbuf) && SvCUR(c->rbuf) > 0) {
        dTHX;
        if (tls_tunnel_write_or_buffer(c, SvPVX(c->rbuf), SvCUR(c->rbuf)) < 0) {
            trouble("TLS tunnel rbuf flush failed fd=%d\n", c->fd);
        }
        SvCUR_set(c->rbuf, 0);
    }

    /* Keep TLS read watcher active to receive and relay client data */
    start_read_watcher(c);

    trace("TLS tunnel socketpair established fd=%d sv0=%d sv1=%d\n",
          c->fd, sv[0], sv[1]);
}

/*
 * Decrypt one TLS record from tls_rbuf into decbuf.
 * Returns:  0 = success (caller must ptls_buffer_dispose)
 *           1 = no app data (KeyUpdate/NewSessionTicket) but no error;
 *               caller should retry if tls_rbuf still has data
 *          -1 = error or no data available
 */
static int
feer_tls_drain_one_record(struct feer_conn *c, ptls_buffer_t *decbuf)
{
    if (!c->tls_rbuf || c->tls_rbuf_len == 0) return -1;

    uint8_t *saved = c->tls_rbuf;
    size_t saved_len = c->tls_rbuf_len;
    c->tls_rbuf = NULL;
    c->tls_rbuf_len = 0;

    ptls_buffer_init(decbuf, "", 0);
    size_t consumed = saved_len;
    int ret = ptls_receive(c->tls, decbuf, saved, &consumed);
    if (ret == 0 && consumed < saved_len) {
        size_t rem = saved_len - consumed;
        Newx(c->tls_rbuf, rem, uint8_t);
        memcpy(c->tls_rbuf, saved + consumed, rem);
        c->tls_rbuf_len = rem;
    }
    Safefree(saved);

    if (ret != 0) {
        ptls_buffer_dispose(decbuf);
        return -1;
    }
    if (decbuf->off == 0) {
        /* TLS 1.3 non-data record (KeyUpdate, NewSessionTicket) — no app
         * bytes but not an error.  Caller should retry if tls_rbuf remains. */
        ptls_buffer_dispose(decbuf);
        return 1;
    }
    return 0;
}

#ifdef FEERSUM_HAS_H2
/* Drain buffered TLS records and feed them to nghttp2.
 * Called after initial decrypt to process any remaining records in tls_rbuf. */
static void
drain_h2_tls_records(struct feer_conn *c)
{
    dTHX;
    while (c->h2_session) {
        ptls_buffer_t db;
        int drain_rv = feer_tls_drain_one_record(c, &db);
        if (drain_rv < 0) break;
        if (drain_rv == 1) continue; /* non-data TLS record */
        feer_h2_session_recv(c, db.base, db.off);
        ptls_buffer_dispose(&db);
        if (c->fd < 0) break;
        feer_h2_session_send(c);
        h2_check_stream_poll_cbs(aTHX_ c);
        restart_read_timer(c);
    }
}
#endif

/*
 * Reads encrypted data from socket, performs TLS handshake or decryption,
 * then feeds plaintext to either H1 parser or nghttp2.
 */
static void
try_tls_conn_read(EV_P_ ev_io *w, int revents)
{
    struct feer_conn *c = (struct feer_conn *)w->data;
    PERL_UNUSED_VAR(revents);
    PERL_UNUSED_VAR(loop);

    dTHX;
    SvREFCNT_inc_void_NN(c->self); /* prevent premature free during callback */
    feer_conn_set_busy(c);
    trace("tls_conn_read fd=%d hs_done=%d\n", c->fd, c->tls_handshake_done);

    ssize_t got_n = 0;

    if (unlikely(c->pipelined)) goto tls_pipelined;

    if (unlikely(!c->tls)) {
        trouble("tls_conn_read: no TLS context fd=%d\n", c->fd);
        change_receiving_state(c, RECEIVE_SHUTDOWN);
        stop_all_watchers(c);
        safe_close_conn(c, "no TLS context");
        goto tls_read_cleanup;
    }

    uint8_t rawbuf[TLS_RAW_BUFSZ];
    ssize_t nread = read(c->fd, rawbuf, sizeof(rawbuf));

    if (nread == 0) {
        /* EOF */
        trace("TLS EOF fd=%d\n", c->fd);
        change_receiving_state(c, RECEIVE_SHUTDOWN);
        stop_all_watchers(c);
        safe_close_conn(c, "TLS EOF");
        goto tls_read_cleanup;
    }

    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            goto tls_read_cleanup;
        trace("TLS read error fd=%d: %s\n", c->fd, strerror(errno));
        change_receiving_state(c, RECEIVE_SHUTDOWN);
        stop_all_watchers(c);
        safe_close_conn(c, "TLS read error");
        goto tls_read_cleanup;
    }

    /* PROXY protocol: raw PROXY header arrives before the TLS handshake.
     * Buffer bytes into c->rbuf, parse the PROXY header, then either:
     * - fall through to TLS handshake if leftover bytes are present, or
     * - wait for next read event if the PROXY header consumed all data. */
    if (unlikely(c->receiving == RECEIVE_PROXY_HEADER)) {
        if (!c->rbuf) {
            c->rbuf = newSV_buf(nread + 256);
        }
        sv_catpvn(c->rbuf, (const char *)rawbuf, nread);

        int ret = try_parse_proxy_header(c);
        if (ret == -1) {
            stop_all_watchers(c);
            safe_close_conn(c, "Invalid PROXY header on TLS listener");
            goto tls_read_cleanup;
        }
        if (ret == -2) goto tls_read_cleanup; /* need more data */

        /* PROXY header parsed successfully — consume parsed bytes */
        STRLEN remaining = SvCUR(c->rbuf) - ret;

        /* Clear cached remote addr/port so they regenerate from new sockaddr */
        feer_clear_remote_cache(c);

        change_receiving_state(c, RECEIVE_HEADERS);

        if (remaining > 0) {
            /* Leftover bytes are the start of the TLS ClientHello.
             * Save in tls_rbuf (heap) to avoid overflowing stack rawbuf
             * when the PROXY header spans multiple reads. */
            Newx(c->tls_rbuf, remaining, uint8_t);
            memcpy(c->tls_rbuf, SvPVX(c->rbuf) + ret, remaining);
            c->tls_rbuf_len = remaining;
            nread = 0;
        }
        SvREFCNT_dec(c->rbuf);
        c->rbuf = NULL;
        if (remaining == 0)
            goto tls_read_cleanup; /* wait for TLS ClientHello on next read */
        /* Fall through to TLS handshake with rawbuf containing TLS data */
    }

    /* Merge any saved partial TLS record bytes with new data.
     * ptls_receive/ptls_handshake may not consume all input when a TLS record
     * spans two socket reads.  Unconsumed bytes are saved in tls_rbuf and
     * prepended to the next read here. */
    uint8_t *inbuf = rawbuf;
    size_t inlen = (size_t)nread;
    uint8_t *merged = NULL;

    if (c->tls_rbuf_len > 0) {
        if (nread > 0) {
            inlen = c->tls_rbuf_len + (size_t)nread;
            Newx(merged, inlen, uint8_t);
            memcpy(merged, c->tls_rbuf, c->tls_rbuf_len);
            memcpy(merged + c->tls_rbuf_len, rawbuf, (size_t)nread);
            inbuf = merged;
            Safefree(c->tls_rbuf);
        } else {
            /* PROXY leftover only — transfer ownership to merged, no copy */
            merged = c->tls_rbuf;
            inbuf = merged;
            inlen = c->tls_rbuf_len;
        }
        c->tls_rbuf = NULL;
        c->tls_rbuf_len = 0;
    }

    if (!c->tls_handshake_done) {
        /* TLS handshake in progress */
        size_t consumed = inlen;
        ptls_buffer_t hsbuf;
        ptls_buffer_init(&hsbuf, "", 0);

        int ret = ptls_handshake(c->tls, &hsbuf, inbuf, &consumed, NULL);

        if (hsbuf.off > 0) {
            if (tls_wbuf_append(&c->tls_wbuf, hsbuf.base, hsbuf.off) != 0) {
                trouble("TLS wbuf alloc failed during handshake fd=%d\n", c->fd);
                ptls_buffer_dispose(&hsbuf);
                if (merged) Safefree(merged);
                stop_all_watchers(c);
                safe_close_conn(c, "TLS allocation failure");
                goto tls_read_cleanup;
            }
            int flush_ret = feer_tls_flush_wbuf(c);
            if (flush_ret == -2) {
                trouble("TLS flush error during handshake fd=%d\n", c->fd);
                ptls_buffer_dispose(&hsbuf);
                if (merged) Safefree(merged);
                stop_all_watchers(c);
                safe_close_conn(c, "TLS handshake flush error");
                goto tls_read_cleanup;
            }
            if (flush_ret == -1 || c->tls_wbuf.off > 0) {
                /* Need to wait for write readiness (EAGAIN or partial write) */
                start_write_watcher(c);
            }
        }
        ptls_buffer_dispose(&hsbuf);

        if (ret == 0) {
            /* Handshake complete */
            c->tls_handshake_done = 1;
            trace("TLS handshake complete fd=%d\n", c->fd);

            /* Check ALPN result */
            const char *proto = ptls_get_negotiated_protocol(c->tls);
            if (proto && strlen(proto) == 2 && memcmp(proto, "h2", 2) == 0) {
                c->tls_alpn_h2 = 1;
                trace("TLS ALPN: h2 negotiated fd=%d\n", c->fd);
#ifdef FEERSUM_HAS_H2
                feer_h2_init_session(c);
#endif
            } else {
                trace("TLS ALPN: http/1.1 (or none) fd=%d\n", c->fd);
            }

            /* Process any remaining data after handshake */
            if (consumed < inlen) {
                size_t remaining = inlen - consumed;
                uint8_t *extra = inbuf + consumed;

#ifdef FEERSUM_HAS_H2
                if (c->h2_session) {
                    /* Feed to nghttp2 */
                    ptls_buffer_t decbuf;
                    ptls_buffer_init(&decbuf, "", 0);
                    size_t dec_consumed = remaining;
                    int dec_ret = ptls_receive(c->tls, &decbuf, extra, &dec_consumed);
                    if (dec_ret != 0) {
                        ptls_buffer_dispose(&decbuf);
                        if (merged) Safefree(merged);
                        stop_all_watchers(c);
                        safe_close_conn(c, "TLS receive error (post-handshake H2)");
                        goto tls_read_cleanup;
                    }
                    if (dec_consumed < remaining) {
                        size_t leftover = remaining - dec_consumed;
                        Newx(c->tls_rbuf, leftover, uint8_t);
                        memcpy(c->tls_rbuf, extra + dec_consumed, leftover);
                        c->tls_rbuf_len = leftover;
                    }
                    if (decbuf.off > 0) {
                        feer_h2_session_recv(c, decbuf.base, decbuf.off);
                    }
                    ptls_buffer_dispose(&decbuf);
                    if (c->fd < 0) {
                        if (merged) Safefree(merged);
                        goto tls_read_cleanup;
                    }
                    /* Send any pending nghttp2 frames (SETTINGS etc.) */
                    feer_h2_session_send(c);
                    h2_check_stream_poll_cbs(aTHX_ c);
                    restart_read_timer(c);

                    drain_h2_tls_records(c);

                    if (merged) Safefree(merged);
                    goto tls_read_cleanup;
                }
#endif
                /* H1: decrypt and feed to HTTP parser */
                ptls_buffer_t decbuf;
                ptls_buffer_init(&decbuf, "", 0);
                size_t dec_consumed = remaining;
                int dec_ret = ptls_receive(c->tls, &decbuf, extra, &dec_consumed);
                if (dec_ret != 0) {
                    ptls_buffer_dispose(&decbuf);
                    if (merged) Safefree(merged);
                    stop_all_watchers(c);
                    safe_close_conn(c, "TLS receive error (post-handshake H1)");
                    goto tls_read_cleanup;
                }
                if (dec_consumed < remaining) {
                    size_t leftover = remaining - dec_consumed;
                    Newx(c->tls_rbuf, leftover, uint8_t);
                    memcpy(c->tls_rbuf, extra + dec_consumed, leftover);
                    c->tls_rbuf_len = leftover;
                }
                if (decbuf.off > 0) {
                    size_t decrypted_len = decbuf.off;
                    if (!c->rbuf) {
                        c->rbuf = newSV_buf(decrypted_len + READ_BUFSZ);
                    }
                    sv_catpvn(c->rbuf, (const char *)decbuf.base, decrypted_len);
                    ptls_buffer_dispose(&decbuf);

                    restart_read_timer(c);
                    int parse_ret = try_parse_http(c, decrypted_len);
                    if (parse_ret == -1) {
                        respond_with_server_error(c, "Malformed request\n", 400);
                        finish_receiving(c);
                        if (merged) Safefree(merged);
                        goto tls_read_cleanup;
                    }
                    if (parse_ret > 0) {
                        if (!process_request_headers(c, parse_ret))
                            finish_receiving(c);
                    }
                    /* Drain remaining tls_rbuf records so data from the same
                     * TCP segment as the handshake doesn't sit unprocessed.
                     * Handles both incomplete headers (parse_ret == -2) and
                     * body data following complete headers (parse_ret > 0). */
                    if (c->tls_rbuf_len > 0) {
                        ptls_buffer_t db;
                        while (c->tls_rbuf_len > 0) {
                            int drain_rv = feer_tls_drain_one_record(c, &db);
                            if (drain_rv < 0) break;
                            if (drain_rv == 1) continue;
                            sv_catpvn(c->rbuf, (const char *)db.base, db.off);
                            size_t added = db.off;
                            ptls_buffer_dispose(&db);
                            if (parse_ret == -2) {
                                /* Still parsing headers — feed to HTTP parser */
                                restart_read_timer(c);
                                int pr = try_parse_http(c, added);
                                if (pr == -1) {
                                    respond_with_server_error(c, "Malformed request\n", 400);
                                    finish_receiving(c);
                                    break;
                                }
                                if (pr > 0) {
                                    if (!process_request_headers(c, pr))
                                        finish_receiving(c);
                                    parse_ret = pr; /* headers now complete */
                                }
                            }
                            /* parse_ret > 0: body data appended to rbuf */
                        }
                        /* If headers are done and body was drained, check
                         * if the full body is now in rbuf. */
                        if (parse_ret > 0 && c->receiving == RECEIVE_BODY) {
                            c->received_cl = SvCUR(c->rbuf);
                            if (c->expected_cl > 0
                                && c->received_cl >= c->expected_cl) {
                                sched_request_callback(c);
                                finish_receiving(c);
                            }
                        }
                    }
                } else {
                    ptls_buffer_dispose(&decbuf);
                }
            }
        } else if (ret == PTLS_ERROR_IN_PROGRESS) {
            /* Handshake still in progress, wait for more data */
            trace("TLS handshake in progress fd=%d\n", c->fd);
            /* Save unconsumed bytes (partial TLS handshake record) */
            if (consumed < inlen) {
                size_t leftover = inlen - consumed;
                Newx(c->tls_rbuf, leftover, uint8_t);
                memcpy(c->tls_rbuf, inbuf + consumed, leftover);
                c->tls_rbuf_len = leftover;
            }
        } else {
            /* Handshake error */
            trace("TLS handshake error fd=%d ret=%d\n", c->fd, ret);
            stop_all_watchers(c);
            safe_close_conn(c, "TLS handshake error");
        }
        if (merged) Safefree(merged);
        goto tls_read_cleanup;
    }

    /* Handshake is done - decrypt application data */
    {
        ptls_buffer_t decbuf;
        ptls_buffer_init(&decbuf, "", 0);
        size_t consumed = inlen;
        int ret = ptls_receive(c->tls, &decbuf, inbuf, &consumed);

        /* Save unconsumed bytes for next read (partial TLS record) */
        if (ret == 0 && consumed < inlen) {
            size_t remaining = inlen - consumed;
            Newx(c->tls_rbuf, remaining, uint8_t);
            memcpy(c->tls_rbuf, inbuf + consumed, remaining);
            c->tls_rbuf_len = remaining;
        }

        if (merged) Safefree(merged);

        if (ret != 0) {
            trace("TLS receive error fd=%d ret=%d\n", c->fd, ret);
            if (ret == PTLS_ALERT_CLOSE_NOTIFY) {
                trace("TLS close_notify fd=%d\n", c->fd);
            }
            ptls_buffer_dispose(&decbuf);
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            stop_all_watchers(c);
            safe_close_conn(c, "TLS receive error");
            goto tls_read_cleanup;
        }

        if (decbuf.off == 0) {
            ptls_buffer_dispose(&decbuf);
            goto tls_read_cleanup; /* No application data yet */
        }

#ifdef FEERSUM_HAS_H2
        if (c->h2_session) {
            /* Feed decrypted data to nghttp2 */
            feer_h2_session_recv(c, decbuf.base, decbuf.off);
            ptls_buffer_dispose(&decbuf);
            if (c->fd < 0) goto tls_read_cleanup;
            /* Send any pending nghttp2 frames */
            feer_h2_session_send(c);
            h2_check_stream_poll_cbs(aTHX_ c);
            restart_read_timer(c);

            drain_h2_tls_records(c);

            goto tls_read_cleanup;
        }
#endif

        /* TLS tunnel: relay decrypted data to sv[0] for the app */
        if (c->tls_tunnel) {
            if (tls_tunnel_write_or_buffer(c, (const char *)decbuf.base, decbuf.off) < 0) {
                ptls_buffer_dispose(&decbuf);
                stop_all_watchers(c);
                safe_close_conn(c, "TLS tunnel write error");
                change_responding_state(c, RESPOND_SHUTDOWN);
                goto tls_read_cleanup;
            }
            ptls_buffer_dispose(&decbuf);

            /* Drain remaining TLS records from tls_rbuf into the tunnel.
             * Multiple records may have been read in one syscall above;
             * without draining, they sit in tls_rbuf until new socket data
             * arrives — deadlocking if the remote is waiting for a reply. */
            drain_tls_tunnel_rbuf(c);

            goto tls_read_cleanup;
        }

        /* HTTP/1.1 over TLS: append decrypted data to rbuf */
        got_n = (ssize_t)decbuf.off;
        if (!c->rbuf) {
            c->rbuf = newSV_buf(got_n + READ_BUFSZ);
        }
        sv_catpvn(c->rbuf, (const char *)decbuf.base, decbuf.off);
        ptls_buffer_dispose(&decbuf);

        /* Drain remaining TLS records from tls_rbuf */
        {
            ptls_buffer_t db;
            int drain_rv;
            while ((drain_rv = feer_tls_drain_one_record(c, &db)) >= 0) {
                if (drain_rv == 1) continue; /* non-data TLS record */
                got_n += (ssize_t)db.off;
                sv_catpvn(c->rbuf, (const char *)db.base, db.off);
                ptls_buffer_dispose(&db);
            }
        }
    }
    goto tls_parse;

tls_pipelined:
    got_n = c->pipelined;
    c->pipelined = 0;

tls_parse:
    restart_read_timer(c);
    if (c->receiving == RECEIVE_WAIT)
        change_receiving_state(c, RECEIVE_HEADERS);

    if (likely(c->receiving <= RECEIVE_HEADERS)) {
        int parse_ret = try_parse_http(c, (size_t)got_n);
        if (parse_ret == -1) {
            respond_with_server_error(c, "Malformed request\n", 400);
            finish_receiving(c);
            goto tls_read_cleanup;
        }
        if (parse_ret == -2) {
            /* Incomplete, wait for more data (read watcher already active) */
            goto tls_read_cleanup;
        }
        /* Headers complete. parse_ret = body offset */
        if (!process_request_headers(c, parse_ret))
            finish_receiving(c);
    }
    else if (likely(c->receiving == RECEIVE_BODY)) {
        c->received_cl += got_n;
        if (c->received_cl >= c->expected_cl) {
            sched_request_callback(c);
            finish_receiving(c);
        }
    }
    else if (c->receiving == RECEIVE_CHUNKED) {
        int ret = try_parse_chunked(c);
        if (ret == -1) {
            respond_with_server_error(c, "Malformed chunked encoding\n", 400);
            finish_receiving(c);
        }
        else if (ret == 0) {
            sched_request_callback(c);
            finish_receiving(c);
        }
        /* ret == 1: need more data, watcher stays active */
    }
    else if (c->receiving == RECEIVE_STREAMING) {
        c->received_cl += got_n;
        if (c->poll_read_cb) {
            call_poll_callback(c, 0);
        }
        if (c->receiving >= RECEIVE_SHUTDOWN) {
            finish_receiving(c);
            goto tls_read_cleanup;
        }
        if (c->expected_cl > 0 && c->received_cl >= c->expected_cl)
            finish_receiving(c);
    }

tls_read_cleanup:
    SvREFCNT_dec(c->self);
}

/*
 * try_tls_conn_write - libev write callback for TLS connections.
 *
 * Encrypts pending response data via ptls and writes to socket.
 * Also handles sendfile-over-TLS (pread + encrypt + write).
 */
static void
try_tls_conn_write(EV_P_ ev_io *w, int revents)
{
    struct feer_conn *c = (struct feer_conn *)w->data;
    PERL_UNUSED_VAR(revents);
    PERL_UNUSED_VAR(loop);

    dTHX;
    SvREFCNT_inc_void_NN(c->self); /* prevent premature free during callback */
    trace("tls_conn_write fd=%d\n", c->fd);

    if (unlikely(!c->tls)) {
        trouble("tls_conn_write: no TLS context fd=%d\n", c->fd);
        stop_write_watcher(c);
        goto tls_write_cleanup;
    }

    /* First, flush any pending encrypted data from TLS handshake or previous writes */
    if (c->tls_wbuf.off > 0) {
        int flush_ret = feer_tls_flush_wbuf(c);
        if (flush_ret == -1) goto tls_write_cleanup; /* EAGAIN, keep write watcher active */
        if (flush_ret == -2) goto tls_write_error;
        /* If there's still data after partial flush, keep trying */
        if (c->tls_wbuf.off > 0) goto tls_write_cleanup;
    }

#ifdef FEERSUM_HAS_H2
    if (c->h2_session) {
        /* For H2, nghttp2 manages the write buffer.
         * Call session_send to generate frames, encrypt, and write. */
        feer_h2_session_send(c);
        h2_check_stream_poll_cbs(aTHX_ c);
        if (c->tls_wbuf.off > 0) {
            int flush_ret = feer_tls_flush_wbuf(c);
            if (flush_ret == -1) goto tls_write_cleanup;
            if (flush_ret == -2) goto tls_write_error;
        }
        if (c->tls_wbuf.off == 0) {
            stop_write_watcher(c);
        }
        goto tls_write_cleanup;
    }
#endif

    /* HTTP/1.1 over TLS: encrypt wbuf_rinq (headers/body) first, then sendfile */

    /* Pre-encryption low-water check: if buffer is below threshold, let
     * poll_cb refill before we start encrypting (matches H1 plain path). */
    if (c->wbuf_rinq && c->cached_wbuf_low_water > 0
        && c->wbuf_len <= c->cached_wbuf_low_water
        && c->responding == RESPOND_STREAMING && c->poll_write_cb) {
        if (c->poll_write_cb_is_io_handle)
            pump_io_handle(c);
        else
            call_poll_callback(c, 1);
    }

    /* Encrypt data from wbuf_rinq (must come before sendfile to send headers first) */
    if (c->wbuf_rinq) {
        struct iomatrix *m;
        while ((m = (struct iomatrix *)rinq_shift(&c->wbuf_rinq)) != NULL) {
            unsigned int i;
            for (i = 0; i < m->count; i++) {
                if (m->iov[i].iov_len == 0) continue;

                c->wbuf_len -= m->iov[i].iov_len;

                ptls_buffer_t encbuf;
                ptls_buffer_init(&encbuf, "", 0);
                int ret = ptls_send(c->tls, &encbuf,
                                    m->iov[i].iov_base, m->iov[i].iov_len);
                if (ret != 0) {
                    unsigned int j;
                    ptls_buffer_dispose(&encbuf);
                    trouble("ptls_send error fd=%d ret=%d\n", c->fd, ret);
                    for (j = 0; j < m->count; j++) {
                        if (m->sv[j]) SvREFCNT_dec(m->sv[j]);
                    }
                    IOMATRIX_FREE(m);
                    goto tls_write_error;
                }
                if (encbuf.off > 0) {
                    if (tls_wbuf_append(&c->tls_wbuf, encbuf.base, encbuf.off) != 0) {
                        unsigned int j;
                        ptls_buffer_dispose(&encbuf);
                        trouble("TLS wbuf alloc failed fd=%d\n", c->fd);
                        for (j = 0; j < m->count; j++) {
                            if (m->sv[j]) SvREFCNT_dec(m->sv[j]);
                        }
                        IOMATRIX_FREE(m);
                        goto tls_write_error;
                    }
                }
                ptls_buffer_dispose(&encbuf);
            }

            /* Free the iomatrix SVs */
            for (i = 0; i < m->count; i++) {
                if (m->sv[i]) SvREFCNT_dec(m->sv[i]);
            }
            IOMATRIX_FREE(m);

            /* Low-water-mark: fire poll_cb to refill before encrypting more */
            if (c->cached_wbuf_low_water > 0
                && c->wbuf_len <= c->cached_wbuf_low_water
                && c->responding == RESPOND_STREAMING && c->poll_write_cb) {
                if (c->poll_write_cb_is_io_handle)
                    pump_io_handle(c);
                else
                    call_poll_callback(c, 1);
                /* poll_cb may have added more data — loop continues */
            }
        }

        /* Flush all encrypted data */
        int flush_ret = feer_tls_flush_wbuf(c);
        if (flush_ret == -1) goto tls_write_cleanup; /* EAGAIN */
        if (flush_ret == -2) goto tls_write_error;
        if (flush_ret > 0) restart_write_timer(c);
    }

    /* Handle sendfile over TLS: pread + encrypt + write */
    if (c->sendfile_fd >= 0 && c->sendfile_remain > 0) {
        uint8_t filebuf[TLS_RAW_BUFSZ];
        size_t to_read = c->sendfile_remain;
        if (to_read > sizeof(filebuf)) to_read = sizeof(filebuf);

        ssize_t file_nread = pread(c->sendfile_fd, filebuf, to_read, c->sendfile_off);
        if (file_nread < 0) {
            if (errno == EINTR)
                goto tls_write_cleanup; /* retry on next watcher fire */
            trouble("TLS pread(sendfile_fd) fd=%d: %s\n", c->fd, strerror(errno));
            CLOSE_SENDFILE_FD(c);
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto tls_write_finished;
        }
        if (file_nread == 0) {
            CLOSE_SENDFILE_FD(c);
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto tls_write_finished;
        }

        /* Encrypt file data */
        ptls_buffer_t encbuf;
        ptls_buffer_init(&encbuf, "", 0);
        int ret = ptls_send(c->tls, &encbuf, filebuf, file_nread);
        if (ret != 0) {
            ptls_buffer_dispose(&encbuf);
            trouble("ptls_send(sendfile) error fd=%d ret=%d\n", c->fd, ret);
            CLOSE_SENDFILE_FD(c);
            goto tls_write_error;
        }

        /* Queue encrypted data */
        if (encbuf.off > 0) {
            if (tls_wbuf_append(&c->tls_wbuf, encbuf.base, encbuf.off) != 0) {
                ptls_buffer_dispose(&encbuf);
                trouble("TLS wbuf alloc failed (sendfile) fd=%d\n", c->fd);
                CLOSE_SENDFILE_FD(c);
                goto tls_write_error;
            }
        }
        ptls_buffer_dispose(&encbuf);

        c->sendfile_off += file_nread;
        c->sendfile_remain -= file_nread;

        if (c->sendfile_remain == 0) {
            CLOSE_SENDFILE_FD(c);
            change_responding_state(c, RESPOND_SHUTDOWN);
        }

        /* Flush encrypted data */
        {
            int sf_flush_ret = feer_tls_flush_wbuf(c);
            if (sf_flush_ret == -1) goto tls_write_cleanup; /* EAGAIN */
            if (sf_flush_ret == -2) goto tls_write_error;
        }
        if (c->sendfile_remain > 0 || c->tls_wbuf.off > 0)
            goto tls_write_cleanup; /* More to send, keep watcher active */
        goto tls_write_finished;
    }

tls_write_finished:
    if ((!c->wbuf_rinq || (c->cached_wbuf_low_water > 0
         && c->wbuf_len <= c->cached_wbuf_low_water))
        && c->sendfile_fd < 0 && c->tls_wbuf.off == 0) {
        if (c->responding == RESPOND_SHUTDOWN || c->responding == RESPOND_NORMAL) {
            handle_keepalive_or_close(c, try_tls_conn_read);
        } else if (c->responding == RESPOND_STREAMING && c->poll_write_cb) {
            if (c->poll_write_cb_is_io_handle)
                pump_io_handle(c);
            else
                call_poll_callback(c, 1 /* is_write */);
        } else if (c->responding == RESPOND_STREAMING) {
            stop_write_watcher(c);
            stop_write_timer(c);
        } else if (c->responding == RESPOND_NOT_STARTED) {
            /* tls_wbuf drained — nothing else to write. Covers both
             * TLS tunnel (io() called, no HTTP response) and handshake
             * flush (EAGAIN during handshake, now completed). */
            stop_write_watcher(c);
        }
    }
    goto tls_write_cleanup;

tls_write_error:
    stop_all_watchers(c);
    change_responding_state(c, RESPOND_SHUTDOWN);
    safe_close_conn(c, "TLS write error");

tls_write_cleanup:
    SvREFCNT_dec(c->self);
}

/*
 * Encrypt response data and queue for TLS writing.
 * Returns 0 on success, -1 on error.
 */
static int
feer_tls_send(struct feer_conn *c, const void *data, size_t len)
{
    if (!c->tls || len == 0) return 0;

    ptls_buffer_t encbuf;
    ptls_buffer_init(&encbuf, "", 0);
    int ret = ptls_send(c->tls, &encbuf, data, len);
    if (ret != 0) {
        ptls_buffer_dispose(&encbuf);
        trouble("feer_tls_send error fd=%d ret=%d\n", c->fd, ret);
        return -1;
    }
    if (encbuf.off > 0) {
        if (tls_wbuf_append(&c->tls_wbuf, encbuf.base, encbuf.off) != 0) {
            ptls_buffer_dispose(&encbuf);
            trouble("TLS wbuf alloc failed (send) fd=%d\n", c->fd);
            return -1;
        }
    }
    ptls_buffer_dispose(&encbuf);
    return 0;
}

#endif /* FEERSUM_HAS_TLS */
