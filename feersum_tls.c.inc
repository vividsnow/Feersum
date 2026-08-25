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

/* HTTP/1.1-only ALPN - used when h2 is not enabled on a listener */
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
    /* RFC 7301 3.2: advertised protocols but no overlap MUST abort with a
     * no_application_protocol alert, not fall back to HTTP/1.1. */
    if (params->negotiated_protocols.count > 0)
        return PTLS_ALERT_NO_APPLICATION_PROTOCOL;

    /* No ALPN extension at all - proceed without it (defaults to HTTP/1.1). */
    return 0;
}

/*
 * SNI lookup: find a matching context for the client's server_name.
 * If found, swap tls->ctx so picotls uses the right cert for the handshake.
 */
static void
sni_lookup(ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    struct feer_conn *c = *(struct feer_conn **)ptls_get_data_ptr(tls);
    struct feer_listen *lsnr = c ? c->listener : NULL;
    if (!lsnr || lsnr->n_sni_entries == 0 || !params->server_name.base)
        return;

    /* hostname is pre-lowered at registration; ASCII-only per RFC 6066 */
    size_t name_len = params->server_name.len;
    for (int i = 0; i < lsnr->n_sni_entries; i++) {
        struct feer_sni_entry *e = &lsnr->sni_entries[i];
        if (strlen(e->hostname) == name_len &&
            str_case_eq_fixed(e->hostname,
                              (const char *)params->server_name.base, name_len)) {
            /* Re-pin the chosen SNI context onto this connection so a
             * concurrent set_tls() cert rotation for the same hostname can't
             * free the ptls_context_t while this connection still uses it
             * (the default context is pinned the same way at init). */
            /* Drop the old reference LAST: ptls_set_context touches the
             * context it is replacing, so releasing ours first hands it a
             * pointer we may just have freed. */
            struct feer_tls_ctx_ref *old = c->tls_ctx_ref;
            e->ctx_ref->refcount++;
            c->tls_ctx_ref = e->ctx_ref;
            ptls_set_context(tls, e->ctx_ref->ctx);
            feer_tls_ctx_ref_dec(old);
            return;
        }
    }
    /* No match - default context stays */
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
    /* Cap the reassembly buffer for a handshake message split across records.
     * Left at picotls's default of 0 it is UNLIMITED, and none of Feersum's
     * own limits apply during the handshake: max_read_buf only guards the
     * post-handshake read buffer, and read_timeout resets on every read, so a
     * peer that keeps sending fragments of one enormous ClientHello grows the
     * process without bound.  No legitimate handshake message comes close. */
    ctx->max_buffer_size = FEER_TLS_MAX_HANDSHAKE_BUF;

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

    /* Empty password rather than NULL: with NULL, OpenSSL falls back to its
     * terminal prompt, so an encrypted key hangs startup on a tty nobody is
     * necessarily watching.  This way it fails immediately instead. */
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void *)"");
    fclose(fp);
    if (!pkey) {
        warn("Feersum TLS: failed to read private key from '%s' "
             "(encrypted keys are not supported)\n", key_file);
        goto cert_cleanup;
    }

    /* Check the leaf parses and actually matches the key.  picotls's PEM reader
     * treats EOF-before-END as success, so a truncated certificate loads as
     * garbage DER; and nothing otherwise verifies that cert and key belong
     * together.  Either way set_tls() would succeed and then every handshake
     * would fail forever, with nothing logged server-side. */
    if (ctx->certificates.count > 0) {
        const unsigned char *der = ctx->certificates.list[0].base;
        X509 *leaf = d2i_X509(NULL, &der, (long)ctx->certificates.list[0].len);
        if (!leaf) {
            warn("Feersum TLS: certificate in '%s' is not valid DER "
                 "(truncated or corrupt PEM?)\n", cert_file);
            EVP_PKEY_free(pkey);
            goto cert_cleanup;
        }
        if (X509_check_private_key(leaf, pkey) != 1) {
            X509_free(leaf);
            EVP_PKEY_free(pkey);
            warn("Feersum TLS: private key '%s' does not match certificate "
                 "'%s'\n", key_file, cert_file);
            goto cert_cleanup;
        }
        X509_free(leaf);
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
    if (lsnr->tls_ctx_ref) {
        feer_tls_ctx_ref_dec(lsnr->tls_ctx_ref);
        lsnr->tls_ctx_ref = NULL;
    }
    for (int i = 0; i < lsnr->n_sni_entries; i++) {
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
    /* Store the conn for SNI lookup in on_client_hello (it reaches the
     * listener via c->listener and re-pins c->tls_ctx_ref on an SNI match). */
    *ptls_get_data_ptr(c->tls) = c;
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

    /* If an earlier short write left a remainder queued, this data MUST go
     * behind it.  Writing straight to sv[0] here overtook those buffered
     * bytes and handed the app its stream out of order - reached whenever the
     * socketpair fills and then drains again before the write watcher runs,
     * which is routine under load.  Measured: 465 of 60000 numbered records
     * arriving out of sequence. */
    ssize_t nw = 0;
    if (!(c->tls_tunnel_wbuf
          && SvCUR(c->tls_tunnel_wbuf) > c->tls_tunnel_wbuf_pos)) {
        nw = write(c->tls_tunnel_sv0, data, len);
        if (nw == (ssize_t)len)
            return 0;

        if (nw < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                return -1;
            nw = 0;
        }
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

static int feer_tls_drain_one_record(struct feer_conn *c, ptls_buffer_t *decbuf);

static void
drain_tls_tunnel_rbuf(struct feer_conn *c)
{
    while (c->tls_tunnel && c->tls_rbuf_len > 0) {
        if (ev_is_active(&c->tls_tunnel_write_w))
            break; /* sv[0] full - let write watcher drain first */
        ptls_buffer_t db;
        int drain_rv = feer_tls_drain_one_record(c, &db);
        if (unlikely(drain_rv == -2)) {
            feer_shutdown_conn(c, "TLS receive error (tunnel drain)");
            return;
        }
        if (drain_rv < 0) break;
        if (drain_rv == 1) continue; /* non-data (e.g. KeyUpdate) */
        if (tls_tunnel_write_or_buffer(c, (const char *)db.base, db.off) < 0) {
            ptls_buffer_dispose(&db);
            feer_shutdown_conn(c, "TLS tunnel drain error");
            return;
        }
        ptls_buffer_dispose(&db);
    }
}

/*
 * Tear down the Extended CONNECT socketpair bridge: an armed watcher on a
 * readable-at-EOF sv0 spins the loop, and leaving sv0 open means the app never
 * sees EOF so the conn and both fds leak.  feer_tls_free_conn owns sv1.
 * Idempotent.
 */
static void
feer_tls_tunnel_shutdown(struct feer_conn *c)
{
    if (!c->tls_tunnel) return;
    ev_io_stop(feersum_ev_loop, &c->tls_tunnel_read_w);
    ev_io_stop(feersum_ev_loop, &c->tls_tunnel_write_w);
    if (c->tls_tunnel_sv0 >= 0) {
        close(c->tls_tunnel_sv0);
        c->tls_tunnel_sv0 = -1;
    }
}

/*
 * ev_io callback: sv[0] is readable - app wrote data to sv[1].
 * Read from sv[0], encrypt via picotls, send to TLS fd.
 */
static void
tls_tunnel_sv0_read_cb(EV_P_ struct ev_io *w, int revents)
{
    struct feer_conn *c = (struct feer_conn *)w->data;
    PERL_UNUSED_VAR(revents);
    SvREFCNT_inc_void_NN(c->self);

    char buf[FEER_TUNNEL_BUFSZ];
    ssize_t nread = read(c->tls_tunnel_sv0, buf, sizeof(buf));

    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            goto cleanup;
        /* Closing sv[1] while any inbound byte sits unread makes this read
         * fail ECONNRESET instead of returning 0 (Linux AF_UNIX).  The app's
         * end is gone either way, and we still owe the client every byte it
         * already handed us, so take the EOF path and flush rather than
         * discarding the queue. */
        if (errno != ECONNRESET && errno != EPIPE) {
            feer_shutdown_conn(c, "TLS tunnel read error");
            goto cleanup;
        }
        nread = 0;
    }

    if (nread == 0) {
        /* App closed sv[1].  Closing the connection here discarded whatever
         * ciphertext was still queued - up to the whole 16 MB backpressure
         * window when a client had paused - and the peer saw a clean
         * close_notify after a truncated stream.  Flush first, and if there
         * is a remainder let try_tls_conn_write finish it and then shut down. */
        ev_io_stop(feersum_ev_loop, &c->tls_tunnel_read_w);
        if (c->tls_wbuf.off > 0 && feer_tls_flush_wbuf(c) != -2
            && c->tls_wbuf.off > 0) {
            c->tls_tunnel_eof = 1;
            start_write_watcher(c);
            /* The app has given up the socket, so the reason write_timeout is
             * disabled for a takeover no longer applies - and without a
             * deadline a peer that simply stops reading would pin the
             * connection, and its queued ciphertext, indefinitely. */
            ensure_write_timer(c);
            goto cleanup;
        }
        feer_shutdown_conn(c, "TLS tunnel EOF");
        goto cleanup;
    }
    /* Encrypt and queue for sending */
    if (feer_tls_send(c, buf, nread) != 0) {
        feer_shutdown_conn(c, "TLS tunnel encrypt error");
        goto cleanup;
    }

    /* Flush encrypted data to socket */
    int flush_ret = feer_tls_flush_wbuf(c);
    if (flush_ret == -2) {
        feer_shutdown_conn(c, "TLS tunnel flush error");
        goto cleanup;
    }
    if (c->tls_wbuf.off > 0)
        start_write_watcher(c);

    /* Backpressure.  On plain HTTP the app holds the raw fd, so the kernel
     * socket buffer throttles it; the TLS relay replaces that, and encrypts
     * straight into tls_wbuf, which has no bound of its own.  A client that
     * stops reading would otherwise let the whole stream accumulate in server
     * memory - the client->app direction is capped by FEER_TUNNEL_MAX_WBUF,
     * this one was not.  Stop pulling from the app; try_tls_conn_write
     * re-arms this watcher once the wire has caught up. */
    if (unlikely(c->tls_wbuf.off > FEER_TUNNEL_MAX_WBUF))
        ev_io_stop(feersum_ev_loop, &c->tls_tunnel_read_w);

cleanup:
    SvREFCNT_dec(c->self);
}

/*
 * ev_io callback: sv[0] is writable - drain tls_tunnel_wbuf
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
        feer_shutdown_conn(c, "TLS tunnel write error");
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
 * Save unconsumed bytes for next read (partial TLS record/handshake).
 * Caller must guarantee c->tls_rbuf is NULL on entry.
 */
INLINE_UNLESS_DEBUG static void
feer_tls_save_rbuf(struct feer_conn *c, const uint8_t *src, size_t len)
{
    Newx(c->tls_rbuf, len, uint8_t);
    memcpy(c->tls_rbuf, src, len);
    c->tls_rbuf_len = len;
}

/*
 * A ptls_receive failure in the SELF_ALERT class names the alert we owe the
 * peer; RFC 8446 5.2 says a record that fails to decrypt MUST terminate the
 * connection.  safe_close_conn sends it instead of close_notify.
 */
INLINE_UNLESS_DEBUG static void
feer_tls_note_alert(struct feer_conn *c, int ret)
{
    if (PTLS_ERROR_GET_CLASS(ret) == PTLS_ERROR_CLASS_SELF_ALERT)
        c->tls_fatal_alert = (uint8_t)PTLS_ERROR_TO_ALERT(ret);
}

/*
 * Decrypt one TLS record from tls_rbuf into decbuf.
 * Returns:  0 = success (caller must ptls_buffer_dispose)
 *           1 = no app data (KeyUpdate/NewSessionTicket) but no error;
 *               caller should retry if tls_rbuf still has data
 *          -1 = nothing left to drain, or the peer closed cleanly
 *          -2 = the record could not be decrypted; caller must tear down
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
    if (ret == 0 && consumed < saved_len)
        feer_tls_save_rbuf(c, saved + consumed, saved_len - consumed);
    Safefree(saved);

    if (ret != 0) {
        ptls_buffer_dispose(decbuf);
        /* A peer close_notify comes back as an error too, and it is the one
         * that must NOT tear anything down here: a request coalesced ahead of
         * it in the same segment is already decrypted and still owed a
         * response.  Every other failure ends the connection. */
        if (ret == PTLS_ERROR_CLASS_PEER_ALERT + PTLS_ALERT_CLOSE_NOTIFY)
            return -1;
        feer_tls_note_alert(c, ret);
        return -2;
    }
    if (decbuf->off == 0) {
        /* TLS 1.3 non-data record (KeyUpdate, NewSessionTicket) - no app
         * bytes but not an error.  Caller should retry if tls_rbuf remains. */
        ptls_buffer_dispose(decbuf);
        return 1;
    }
    return 0;
}

/* Append decrypted app data to rbuf, then drain any remaining complete TLS
 * records from tls_rbuf into rbuf.  Disposes decbuf.  Returns total bytes
 * appended, and sets *failed if a record could not be decrypted - the byte
 * count has no room to say so, and a caller that parses on regardless would
 * keep a dead connection alive until read_timeout.  Shared by the steady-state
 * and handshake-coalesced H1 read paths so both feed the parser identically. */
static size_t
feer_tls_rbuf_append_drain(struct feer_conn *c, ptls_buffer_t *decbuf, int *failed)
{
    dTHX;
    size_t added = 0;
    if (decbuf->off > 0) {
        if (!c->rbuf)
            c->rbuf = newSV_buf(decbuf->off + READ_BUFSZ);
        sv_catpvn(c->rbuf, (const char *)decbuf->base, decbuf->off);
        added = decbuf->off;
    }
    ptls_buffer_dispose(decbuf);
    ptls_buffer_t db;
    int drain_rv;
    while ((drain_rv = feer_tls_drain_one_record(c, &db)) >= 0) {
        if (drain_rv == 1) continue; /* non-data TLS record */
        if (!c->rbuf)
            c->rbuf = newSV_buf(db.off + READ_BUFSZ);
        sv_catpvn(c->rbuf, (const char *)db.base, db.off);
        added += db.off;
        ptls_buffer_dispose(&db);
    }
    if (unlikely(drain_rv == -2))
        *failed = 1;
    return added;
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
        if (unlikely(drain_rv == -2)) {
            stop_all_watchers(c);
            safe_close_conn(c, "TLS receive error (H2 drain)");
            break;
        }
        if (drain_rv < 0) break;
        if (drain_rv == 1) continue; /* non-data TLS record */
        feer_h2_session_recv(c, db.base, db.off);
        ptls_buffer_dispose(&db);
        if (c->fd < 0) break;
        h2_session_send_and_poll(aTHX_ c);
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
        /* A tunnel peer that half-closes is saying "I am done sending", not
         * "drop what you owe me".  Closing here discarded everything the app
         * had already written and everything it still meant to: 16.1% of a
         * 16MB body arrived, against 100% on both twins.  H2 maps
         * DATA+END_STREAM to exactly this SHUT_WR, and plain H1 never gets
         * here because the app owns the fd outright.  Stop reading, let the
         * app see its EOF, and keep the write side alive so it can still
         * answer; the app closing its end then runs the normal flush path. */
        if (c->tls_tunnel && c->tls_tunnel_sv0 >= 0 && !c->tls_tunnel_eof) {
            ev_io_stop(feersum_ev_loop, &c->read_ev_io);
            shutdown(c->tls_tunnel_sv0, SHUT_WR);
            goto tls_read_cleanup;
        }
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
            feer_shutdown_conn(c, "Invalid PROXY header on TLS listener");
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            goto tls_read_cleanup;
        }
        if (ret == -2) goto tls_read_cleanup; /* need more data */

        /* PROXY header parsed successfully - consume parsed bytes */
        STRLEN remaining = SvCUR(c->rbuf) - ret;

        /* Clear cached remote addr/port so they regenerate from new sockaddr */
        feer_clear_remote_cache(c);

        change_receiving_state(c, RECEIVE_HEADERS);

        if (remaining > 0) {
            /* Leftover bytes are the start of the TLS ClientHello.
             * Save in tls_rbuf (heap) to avoid overflowing stack rawbuf
             * when the PROXY header spans multiple reads. */
            feer_tls_save_rbuf(c, (const uint8_t *)SvPVX(c->rbuf) + ret, remaining);
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
            /* PROXY leftover only - transfer ownership to merged, no copy */
            merged = c->tls_rbuf;
            inbuf = merged;
            inlen = c->tls_rbuf_len;
        }
        c->tls_rbuf = NULL;
        c->tls_rbuf_len = 0;
    }

    if (!c->tls_handshake_done) {
        /* TLS handshake in progress.  Flight bytes go straight into tls_wbuf
         * (ptls appends), sparing a bounce buffer and its extra copy. */
        size_t consumed = inlen;

        int ret = ptls_handshake(c->tls, &c->tls_wbuf, inbuf, &consumed, NULL);

        if (c->tls_wbuf.off > 0) {
            int flush_ret = feer_tls_flush_wbuf(c);
            if (flush_ret == -2) {
                trouble("TLS flush error during handshake fd=%d\n", c->fd);
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

        if (ret == 0) {
            /* Handshake complete */
            c->tls_handshake_done = 1;
            trace("TLS handshake complete fd=%d\n", c->fd);

            /* Check ALPN result */
            const char *proto = ptls_get_negotiated_protocol(c->tls);
            if (proto && strcmp(proto, "h2") == 0) {
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
                        feer_tls_note_alert(c, dec_ret);
                        stop_all_watchers(c);
                        safe_close_conn(c, "TLS receive error (post-handshake H2)");
                        goto tls_read_cleanup;
                    }
                    if (dec_consumed < remaining)
                        feer_tls_save_rbuf(c, extra + dec_consumed, remaining - dec_consumed);
                    if (decbuf.off > 0) {
                        feer_h2_session_recv(c, decbuf.base, decbuf.off);
                    }
                    ptls_buffer_dispose(&decbuf);
                    if (c->fd < 0) {
                        if (merged) Safefree(merged);
                        goto tls_read_cleanup;
                    }
                    /* Send any pending nghttp2 frames (SETTINGS etc.) */
                    h2_session_send_and_poll(aTHX_ c);
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
                    feer_tls_note_alert(c, dec_ret);
                    stop_all_watchers(c);
                    safe_close_conn(c, "TLS receive error (post-handshake H1)");
                    goto tls_read_cleanup;
                }
                if (dec_consumed < remaining)
                    feer_tls_save_rbuf(c, extra + dec_consumed, remaining - dec_consumed);
                /* Drain the remaining records into rbuf and jump to the
                 * shared parse path rather than dispatching per record here:
                 * one dispatch path keeps plain and TLS from drifting. */
                int drain_failed = 0;
                size_t added = feer_tls_rbuf_append_drain(c, &decbuf, &drain_failed);
                if (unlikely(drain_failed)) {
                    if (merged) Safefree(merged);
                    change_receiving_state(c, RECEIVE_SHUTDOWN);
                    stop_all_watchers(c);
                    safe_close_conn(c, "TLS receive error (H1 drain)");
                    goto tls_read_cleanup;
                }
                if (added > 0) {
                    if (merged) Safefree(merged);
                    got_n = (ssize_t)added;
                    goto tls_parse;
                }
            }
        } else if (ret == PTLS_ERROR_IN_PROGRESS) {
            /* Handshake still in progress, wait for more data */
            trace("TLS handshake in progress fd=%d\n", c->fd);
            /* Save unconsumed bytes (partial TLS handshake record) */
            if (consumed < inlen)
                feer_tls_save_rbuf(c, inbuf + consumed, inlen - consumed);
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
        if (ret == 0 && consumed < inlen)
            feer_tls_save_rbuf(c, inbuf + consumed, inlen - consumed);

        if (merged) Safefree(merged);

        if (ret != 0) {
            trace("TLS receive error fd=%d ret=%d\n", c->fd, ret);
            ptls_buffer_dispose(&decbuf);
            feer_tls_note_alert(c, ret);
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
            h2_session_send_and_poll(aTHX_ c);
            restart_read_timer(c);

            drain_h2_tls_records(c);

            goto tls_read_cleanup;
        }
#endif

        /* TLS tunnel: relay decrypted data to sv[0] for the app */
        if (c->tls_tunnel) {
            if (tls_tunnel_write_or_buffer(c, (const char *)decbuf.base, decbuf.off) < 0) {
                ptls_buffer_dispose(&decbuf);
                feer_shutdown_conn(c, "TLS tunnel write error");
                goto tls_read_cleanup;
            }
            ptls_buffer_dispose(&decbuf);

            /* Drain remaining TLS records from tls_rbuf into the tunnel.
             * Multiple records may have been read in one syscall above;
             * without draining, they sit in tls_rbuf until new socket data
             * arrives - deadlocking if the remote is waiting for a reply. */
            drain_tls_tunnel_rbuf(c);

            goto tls_read_cleanup;
        }

        /* HTTP/1.1 over TLS: append decrypted data + drain remaining records */
        int drain_failed = 0;
        got_n = (ssize_t)feer_tls_rbuf_append_drain(c, &decbuf, &drain_failed);
        if (unlikely(drain_failed)) {
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            stop_all_watchers(c);
            safe_close_conn(c, "TLS receive error (H1 drain)");
            goto tls_read_cleanup;
        }
    }
    goto tls_parse;

tls_pipelined:
    got_n = c->pipelined;
    c->pipelined = 0;

tls_parse:
    restart_read_timer(c);
    begin_request_headers(c);

    if (likely(c->receiving <= RECEIVE_HEADERS)) {
        int parse_ret = try_parse_http(c, (size_t)got_n);
        if (parse_ret == -1) {
            /* Same split the plain twin makes: picohttpparser reports "too many
             * headers" and "malformed" both as -1, but only the cap check
             * leaves num_headers at MAX_HEADERS. */
            if (unlikely(c->req && c->req->num_headers >= MAX_HEADERS))
                respond_with_server_error(c, "Too many header fields\n", 431);
            else
                respond_with_server_error(c, "Malformed request\n", 400);
            finish_receiving(c);
            goto tls_read_cleanup;
        }
        if (parse_ret == -2) {
            /* Headers still incomplete. Bound rbuf growth the way the plain
             * path (try_conn_read) does: if we've buffered more than
             * max_read_buf and still can't finish the headers, reject.
             * (Decrypted bytes reach rbuf via sv_catpvn, which is otherwise
             * uncapped. A complete request with a large Content-Length body
             * never lands here - it is bounded by max_body_len instead.) */
            if (unlikely(SvCUR(c->rbuf) > c->cached_max_read_buf)) {
                trace("tls header buffer too large %d: %"Sz_uf" > %"Sz_uf"\n",
                    c->fd, (Sz)SvCUR(c->rbuf), (Sz)c->cached_max_read_buf);
                /* 431 like the plain twin: the fields are too large, not the
                 * payload.  The chunked-body cap below stays 413. */
                respond_with_server_error(c,
                    "Request header fields too large\n", 431);
                finish_receiving(c);
            }
            goto tls_read_cleanup;
        }
        /* Headers complete: parse_ret is the body offset, so it IS the size of
         * the header block.  Measure that rather than SvCUR - one decrypt
         * burst commonly carries the body along with the headers, and counting
         * the whole buffer turned a legitimate 9KB upload into a 431 on TLS
         * while the plain twin served it 200 under the same max_read_buf. */
        if (unlikely((STRLEN)parse_ret > c->cached_max_read_buf)) {
            trace("tls header block too large %d: %"Sz_uf" > %"Sz_uf"\n",
                c->fd, (Sz)parse_ret, (Sz)c->cached_max_read_buf);
            respond_with_server_error(c,
                "Request header fields too large\n", 431);
            finish_receiving(c);
            goto tls_read_cleanup;
        }
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
        if (ret == -2) {
            /* size limit, not a protocol error - the docs promise 413 */
            respond_with_server_error(c, "Request body too large\n", 413);
            finish_receiving(c);
        }
        else if (ret == -1) {
            respond_with_server_error(c, "Malformed chunked encoding\n", 400);
            finish_receiving(c);
        }
        else if (ret == 0) {
            sched_request_callback(c);
            finish_receiving(c);
        }
        else if (unlikely(SvCUR(c->rbuf) > c->cached_max_read_buf)) {
            /* ret == 1: need more data, but the decoded+pending buffer already
             * exceeds max_read_buf (mirrors the plain path's cap on chunked
             * body reception). */
            trace("tls chunked buffer too large %d: %"Sz_uf" > %"Sz_uf"\n",
                c->fd, (Sz)SvCUR(c->rbuf), (Sz)c->cached_max_read_buf);
            respond_with_server_error(c, "Request too large\n", 413);
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
        if (flush_ret == -1) goto tls_write_again; /* EAGAIN */
        if (flush_ret == -2) goto tls_write_error;
        /* Progress: push the deadline out, as the plain path does after every
         * successful write.  Once the whole body is encrypted into tls_wbuf the
         * wbuf_rinq loop below stops running, so this is the only place left
         * that can see progress - without it write_timeout reaped a client that
         * was draining steadily, truncating the response. */
        if (flush_ret > 0) restart_write_timer(c);
        /* If there's still data after partial flush, keep trying */
        if (c->tls_wbuf.off > 0) goto tls_write_again;
    }

#ifdef FEERSUM_HAS_H2
    /* Same shape for H2: the last stream closed during shutdown and its
     * response has only now reached the wire. */
    if (unlikely(c->h2_close_pending) && c->tls_wbuf.off == 0) {
        c->h2_close_pending = 0;
        /* Linger: the response is in the kernel, not delivered, and the
         * client WINDOW_UPDATE for it is typically unread right now. */
        c->want_linger_close = 1;
        feer_shutdown_conn(c, "last H2 stream closed during shutdown");
        goto tls_write_cleanup;
    }
#endif

    /* The app closed its tunnel end and the last ciphertext has now gone out. */
    if (unlikely(c->tls_tunnel_eof)) {
        c->tls_tunnel_eof = 0;
        feer_shutdown_conn(c, "TLS tunnel EOF drained");
        goto tls_write_cleanup;
    }

    /* The wire has caught up: let the tunnel pull from the app again.  Paired
     * with the high-water stop in tls_tunnel_sv0_read_cb - with the reader
     * paused nothing new is appended, so tls_wbuf always reaches empty here
     * and the cycle cannot wedge. */
    if (unlikely(c->tls_tunnel) && c->tls_tunnel_sv0 >= 0
        && !ev_is_active(&c->tls_tunnel_read_w))
        ev_io_start(feersum_ev_loop, &c->tls_tunnel_read_w);

#ifdef FEERSUM_HAS_H2
    if (c->h2_session) {
        /* For H2, nghttp2 manages the write buffer.
         * Call session_send to generate frames, encrypt, and write. */
        h2_session_send_and_poll(aTHX_ c);
        if (c->tls_wbuf.off > 0) {
            int flush_ret = feer_tls_flush_wbuf(c);
            if (flush_ret == -1) goto tls_write_again;
            if (flush_ret == -2) goto tls_write_error;
            if (flush_ret > 0) restart_write_timer(c);
        }
        if (c->tls_wbuf.off == 0) {
            /* A stream's pump stopped on its iteration budget: keep the
             * watcher so this callback re-enters it next loop iteration.
             * Nothing else would - the socket is drained and the peer has no
             * reason to send anything. */
            if (unlikely(c->h2_pump_pending)) {
                c->h2_pump_pending = 0;
            }
            /* Nothing left to write: stop the deadline too, exactly as the
             * plain path's try_write_paused does.  Leaving it armed would reap
             * an idle H2 connection write_timeout after its last byte. */
            else {
                stop_write_watcher(c);
                stop_write_timer(c);
            }
        } else
            goto tls_write_again;
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

                /* Encrypt straight into tls_wbuf (ptls appends): a bounce
                 * buffer here copied every ciphertext byte a second time. */
                int ret = ptls_send(c->tls, &c->tls_wbuf,
                                    m->iov[i].iov_base, m->iov[i].iov_len);
                if (ret != 0) {
                    unsigned int j;
                    trouble("ptls_send error fd=%d ret=%d\n", c->fd, ret);
                    /* SvREFCNT_dec is NULL-safe */
                    for (j = 0; j < m->count; j++) SvREFCNT_dec(m->sv[j]);
                    IOMATRIX_FREE(m);
                    goto tls_write_error;
                }
            }

            /* Free the iomatrix SVs (SvREFCNT_dec is NULL-safe) */
            for (i = 0; i < m->count; i++) SvREFCNT_dec(m->sv[i]);
            IOMATRIX_FREE(m);

            /* Low-water-mark: fire poll_cb to refill before encrypting more.
             * Flush first and only refill once the wire has taken everything:
             * an IO::Handle body pumps until EOF, so refilling on an unflushed
             * buffer piled the whole encrypted file into tls_wbuf - a 128MB
             * body cost 135MB of RSS.  Plain HTTP flushes per iomatrix and
             * stayed at +60kB.  Draining wbuf_rinq continues either way; only
             * asking for more data is deferred. */
            if (c->cached_wbuf_low_water > 0
                && c->wbuf_len <= c->cached_wbuf_low_water
                && c->responding == RESPOND_STREAMING && c->poll_write_cb) {
                int lw_flush = feer_tls_flush_wbuf(c);
                if (unlikely(lw_flush == -2)) goto tls_write_error;
                if (c->tls_wbuf.off == 0) {
                    if (c->poll_write_cb_is_io_handle)
                        pump_io_handle(c);
                    else
                        call_poll_callback(c, 1);
                }
            }
        }

        /* Flush all encrypted data */
        int flush_ret = feer_tls_flush_wbuf(c);
        if (flush_ret == -1) goto tls_write_again; /* EAGAIN */
        if (flush_ret == -2) goto tls_write_error;
        if (flush_ret > 0) restart_write_timer(c);
        /* A partial flush leaves ciphertext pending; tls_write_finished below
         * requires tls_wbuf.off == 0, so falling through would exit with
         * nothing armed to drain the remainder. */
        if (c->tls_wbuf.off > 0) goto tls_write_again;
    }

    /* Handle sendfile over TLS: pread + encrypt + write */
    if (c->sendfile_fd >= 0 && c->sendfile_remain > 0) {
        uint8_t filebuf[TLS_RAW_BUFSZ];
        size_t to_read = c->sendfile_remain;
        if (to_read > sizeof(filebuf)) to_read = sizeof(filebuf);

        ssize_t file_nread = pread(c->sendfile_fd, filebuf, to_read, c->sendfile_off);
        if (file_nread < 0) {
            if (errno == EINTR)
                goto tls_write_again; /* retry on next watcher fire */
            trouble("TLS pread(sendfile_fd) fd=%d: %s\n", c->fd, strerror(errno));
            CLOSE_SENDFILE_FD(c);
            /* Body delivery aborted mid-stream - can't keep this conn alive,
             * the client expects more body bytes that we can't send. */
            c->is_keepalive = 0;
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto tls_write_finished;
        }
        if (file_nread == 0) {
            CLOSE_SENDFILE_FD(c);
            change_responding_state(c, RESPOND_SHUTDOWN);
            goto tls_write_finished;
        }

        /* Encrypt file data straight into tls_wbuf (see the wbuf loop above) */
        int ret = ptls_send(c->tls, &c->tls_wbuf, filebuf, file_nread);
        if (ret != 0) {
            trouble("ptls_send(sendfile) error fd=%d ret=%d\n", c->fd, ret);
            CLOSE_SENDFILE_FD(c);
            goto tls_write_error;
        }

        c->sendfile_off += file_nread;
        c->sendfile_remain -= file_nread;

        if (c->sendfile_remain == 0) {
            CLOSE_SENDFILE_FD(c);
            change_responding_state(c, RESPOND_SHUTDOWN);
        }

        /* Flush encrypted data */
        {
            int sf_flush_ret = feer_tls_flush_wbuf(c);
            if (sf_flush_ret == -1) goto tls_write_again; /* EAGAIN */
            if (sf_flush_ret == -2) goto tls_write_error;
        }
        /* Progress: push the deadline out, as the wbuf path above does.  A
         * sendfile sits in RESPOND_SHUTDOWN for its whole duration, so without
         * this write_timeout reaps it mid-file and truncates the download. */
        if (file_nread > 0)
            restart_write_timer(c);
        if (c->sendfile_remain > 0 || c->tls_wbuf.off > 0)
            goto tls_write_again; /* more to send */
        goto tls_write_finished;
    }

tls_write_finished:
    if ((!c->wbuf_rinq || (c->cached_wbuf_low_water > 0
         && c->wbuf_len <= c->cached_wbuf_low_water))
        && c->sendfile_fd < 0 && c->tls_wbuf.off == 0) {
        if (c->responding == RESPOND_SHUTDOWN || c->responding == RESPOND_NORMAL) {
            handle_keepalive_or_close(c, try_tls_conn_read);
        } else if (c->responding == RESPOND_STREAMING && c->poll_write_cb) {
            unsigned int writes_before = c->poll_writes_seen;
            if (c->poll_write_cb_is_io_handle)
                pump_io_handle(c);
            else
                call_poll_callback(c, 1 /* is_write */);
            /* Pure decline: park and pace, exactly as the plain path does in
             * try_conn_write.  The level-triggered spin was identical here,
             * and this path never had any peer-gone detection at all. */
            if (!c->wbuf_rinq && c->tls_wbuf.off == 0
                && c->responding == RESPOND_STREAMING && c->poll_write_cb
                && c->poll_writes_seen == writes_before) {
                if (unlikely(peer_is_gone(c))) {
                    trace("TLS poll_cb declined and the peer is gone %d\n", c->fd);
                    feer_shutdown_conn(c, "poll_cb decline, peer gone");
                }
                else
                    feersum_poll_retry_park(c);
            }
            else {
                /* The callback produced output or advanced the response.
                 * When the always-armed watcher WAS the pump (pre-park), the
                 * next level-triggered pass flushed it; a paced-retry entry
                 * has no watcher armed, and pump_io_handle in particular
                 * buffers (data or the EOF terminator) without arming
                 * anything - that stranded a chunked tail.  No-op if the
                 * callback's own write already armed it. */
                start_write_watcher(c);
            }
        } else if (c->responding == RESPOND_STREAMING) {
            stop_write_watcher(c);
            stop_write_timer(c);
        } else if (c->responding == RESPOND_NOT_STARTED) {
            /* tls_wbuf drained - nothing else to write. Covers both
             * TLS tunnel (io() called, no HTTP response) and handshake
             * flush (EAGAIN during handshake, now completed).  Stop the
             * deadline as well, or an established tunnel gets reaped
             * write_timeout after its last byte. */
            stop_write_watcher(c);
            stop_write_timer(c);
        }
    }
    goto tls_write_cleanup;

tls_write_again:
    /* Blocked on writability.  Unlike the plain path, this function is not
     * always entered from the write watcher: conn_write_ready() calls it
     * directly whenever in_callback is 0 (deferred responder, timer-driven
     * write or sendfile), so "the watcher is already active" does not hold and
     * the remaining ciphertext would never be flushed.  Mirrors try_write_again
     * on the plain side. */
    start_write_watcher(c);
    ensure_write_timer(c);
    goto tls_write_cleanup;

tls_write_error:
    feer_shutdown_conn(c, "TLS write error");

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

    /* ptls appends to tls_wbuf directly; a bounce buffer double-copied. */
    int ret = ptls_send(c->tls, &c->tls_wbuf, data, len);
    if (ret != 0) {
        trouble("feer_tls_send error fd=%d ret=%d\n", c->fd, ret);
        return -1;
    }
    return 0;
}

#endif /* FEERSUM_HAS_TLS */
