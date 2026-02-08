/*
 * feersum_tls.c - TLS 1.3 support via picotls for Feersum
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

/* Per-context sign certificate (allocated dynamically in feer_tls_create_context) */

/* ALPN protocols list for negotiation */
static ptls_iovec_t tls_alpn_protos[] = {
#ifdef FEERSUM_HAS_H2
    { (uint8_t *)ALPN_H2 + 1, 2 },       /* "h2" */
#endif
    { (uint8_t *)ALPN_HTTP11 + 1, 8 },    /* "http/1.1" */
};

static int
on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                   ptls_on_client_hello_parameters_t *params)
{
    (void)self;
    /* Negotiate ALPN */
    size_t i, j;
    const ptls_iovec_t *negoprotos = tls_alpn_protos;
    size_t num_negoprotos = sizeof(tls_alpn_protos) / sizeof(tls_alpn_protos[0]);

    for (i = 0; i < num_negoprotos; i++) {
        for (j = 0; j < params->negotiated_protocols.count; j++) {
            if (params->negotiated_protocols.list[j].len == negoprotos[i].len &&
                memcmp(params->negotiated_protocols.list[j].base, negoprotos[i].base,
                       negoprotos[i].len) == 0) {
                ptls_set_negotiated_protocol(tls,
                    (const char *)negoprotos[i].base, negoprotos[i].len);
                return 0;
            }
        }
    }
    /* No matching protocol; proceed without ALPN (will default to HTTP/1.1) */
    return 0;
}

static ptls_on_client_hello_t on_client_hello = { on_client_hello_cb };

/* HTTP/1.1-only ALPN — used when h2 is not enabled on a listener */
static ptls_iovec_t tls_alpn_h1_only[] = {
    { (uint8_t *)ALPN_HTTP11 + 1, 8 },    /* "http/1.1" */
};

static int
on_client_hello_no_h2_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                         ptls_on_client_hello_parameters_t *params)
{
    (void)self;
    size_t i;
    for (i = 0; i < params->negotiated_protocols.count; i++) {
        if (params->negotiated_protocols.list[i].len == tls_alpn_h1_only[0].len &&
            memcmp(params->negotiated_protocols.list[i].base, tls_alpn_h1_only[0].base,
                   tls_alpn_h1_only[0].len) == 0) {
            ptls_set_negotiated_protocol(tls,
                (const char *)tls_alpn_h1_only[0].base, tls_alpn_h1_only[0].len);
            return 0;
        }
    }
    /* No matching protocol; proceed without ALPN (will default to HTTP/1.1) */
    return 0;
}

static ptls_on_client_hello_t on_client_hello_no_h2 = { on_client_hello_no_h2_cb };

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

    /* Set up random number generator and time source */
    ctx->random_bytes = ptls_openssl_random_bytes;
    ctx->get_time = &ptls_get_time;

    /* Key exchange: X25519 (not available on LibreSSL) + secp256r1 */
    static ptls_key_exchange_algorithm_t *key_exchanges[] = {
#if PTLS_OPENSSL_HAVE_X25519
        &ptls_openssl_x25519,
#endif
        &ptls_openssl_secp256r1,
        NULL
    };
    ctx->key_exchanges = key_exchanges;

    /* Cipher suites: AES-256-GCM, AES-128-GCM, ChaCha20 */
    static ptls_cipher_suite_t *cipher_suites[] = {
        &ptls_openssl_aes256gcmsha384,
        &ptls_openssl_aes128gcmsha256,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
        &ptls_openssl_chacha20poly1305sha256,
#endif
        NULL
    };
    ctx->cipher_suites = cipher_suites;

    /* Load certificate chain */
    ret = ptls_load_certificates(ctx, cert_file);
    if (ret != 0) {
        warn("Feersum TLS: failed to load certificate from '%s' (error %d)\n",
             cert_file, ret);
        Safefree(ctx);
        return NULL;
    }

    /* Load private key */
    fp = fopen(key_file, "r");
    if (!fp) {
        warn("Feersum TLS: failed to open key file '%s': %s\n",
             key_file, strerror(errno));
        /* Free loaded certificates */
        size_t i;
        for (i = 0; i < ctx->certificates.count; i++)
            free(ctx->certificates.list[i].base);
        free(ctx->certificates.list);
        Safefree(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        warn("Feersum TLS: failed to read private key from '%s'\n", key_file);
        size_t i;
        for (i = 0; i < ctx->certificates.count; i++)
            free(ctx->certificates.list[i].base);
        free(ctx->certificates.list);
        Safefree(ctx);
        return NULL;
    }

    ptls_openssl_sign_certificate_t *sign_cert;
    Newx(sign_cert, 1, ptls_openssl_sign_certificate_t);
    ptls_openssl_init_sign_certificate(sign_cert, pkey);
    EVP_PKEY_free(pkey);
    ctx->sign_certificate = &sign_cert->super;

    /* ALPN negotiation via on_client_hello callback */
    if (h2)
        ctx->on_client_hello = &on_client_hello;
    else
        ctx->on_client_hello = &on_client_hello_no_h2;

    trace("TLS context created: cert=%s key=%s h2=%d\n", cert_file, key_file, h2);
    return ctx;
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
 * Initialize TLS state on a newly accepted connection.
 */
static void
feer_tls_init_conn(struct feer_conn *c, ptls_context_t *tls_ctx)
{
    c->tls = ptls_new(tls_ctx, 1 /* is_server */);
    if (unlikely(!c->tls)) {
        trouble("ptls_new failed for fd=%d\n", c->fd);
        return;
    }
    ptls_buffer_init(&c->tls_wbuf, "", 0);
    c->tls_handshake_done = 0;
    c->tls_wants_write = 0;
    c->tls_alpn_h2 = 0;
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
    ptls_buffer_dispose(&c->tls_wbuf);
    if (c->tls_rbuf) {
        Safefree(c->tls_rbuf);
        c->tls_rbuf = NULL;
        c->tls_rbuf_len = 0;
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
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            c->tls_wants_write = 1;
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
        c->tls_wants_write = 1;
        return (int)written;
    }

    /* Full write */
    c->tls_wbuf.off = 0;
    c->tls_wants_write = 0;
    return (int)written;
}

/*
 * Append data to the TLS write buffer (tls_wbuf).
 * Unlike ptls_buffer_pushv, this doesn't use goto Exit.
 */
static inline int
tls_wbuf_append(ptls_buffer_t *buf, const void *src, size_t len)
{
    return ptls_buffer__do_pushv(buf, src, len);
}

/*
 * try_tls_conn_read - libev read callback for TLS connections.
 *
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
    trace("tls_conn_read fd=%d hs_done=%d\n", c->fd, c->tls_handshake_done);

    ssize_t got_n = 0;

    if (unlikely(c->pipelined)) goto tls_pipelined;

    if (unlikely(!c->tls)) {
        trouble("tls_conn_read: no TLS context fd=%d\n", c->fd);
        goto tls_read_cleanup;
    }

    /* Read encrypted data from socket */
    uint8_t rawbuf[TLS_RAW_BUFSZ];
    ssize_t nread = read(c->fd, rawbuf, sizeof(rawbuf));

    if (nread == 0) {
        /* EOF */
        trace("TLS EOF fd=%d\n", c->fd);
        change_receiving_state(c, RECEIVE_SHUTDOWN);
        safe_close_conn(c, "TLS EOF");
        goto tls_read_cleanup;
    }

    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            goto tls_read_cleanup;
        trace("TLS read error fd=%d: %s\n", c->fd, strerror(errno));
        change_receiving_state(c, RECEIVE_SHUTDOWN);
        safe_close_conn(c, "TLS read error");
        goto tls_read_cleanup;
    }

    /* PROXY protocol: raw PROXY header arrives before the TLS handshake.
     * Buffer bytes into c->rbuf, parse the PROXY header, then either:
     * - fall through to TLS handshake if leftover bytes are present, or
     * - wait for next read event if the PROXY header consumed all data. */
    if (unlikely(c->receiving == RECEIVE_PROXY_HEADER)) {
        if (!c->rbuf) {
            c->rbuf = newSV(nread + 256);
            SvPOK_on(c->rbuf);
            SvCUR_set(c->rbuf, 0);
        }
        sv_catpvn(c->rbuf, (const char *)rawbuf, nread);

        int ret = try_parse_proxy_header(c);
        if (ret == -1) {
            safe_close_conn(c, "Invalid PROXY header on TLS listener");
            goto tls_read_cleanup;
        }
        if (ret == -2) goto tls_read_cleanup; /* need more data */

        /* PROXY header parsed successfully — consume parsed bytes */
        STRLEN remaining = SvCUR(c->rbuf) - ret;

        /* Clear cached remote addr/port so they regenerate from new sockaddr */
        if (c->remote_addr) { SvREFCNT_dec(c->remote_addr); c->remote_addr = NULL; }
        if (c->remote_port) { SvREFCNT_dec(c->remote_port); c->remote_port = NULL; }

        c->receiving = RECEIVE_HEADERS;

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

    if (c->tls_rbuf_len > 0 && c->tls_rbuf) {
        inlen = c->tls_rbuf_len + (size_t)nread;
        Newx(merged, inlen, uint8_t);
        memcpy(merged, c->tls_rbuf, c->tls_rbuf_len);
        memcpy(merged + c->tls_rbuf_len, rawbuf, (size_t)nread);
        inbuf = merged;
        Safefree(c->tls_rbuf);
        c->tls_rbuf = NULL;
        c->tls_rbuf_len = 0;
    }

    if (!c->tls_handshake_done) {
        /* TLS handshake in progress */
        size_t consumed = inlen;
        ptls_buffer_t hsbuf;
        ptls_buffer_init(&hsbuf, "", 0);

        int ret = ptls_handshake(c->tls, &hsbuf, inbuf, &consumed, NULL);

        /* Send handshake response data if any */
        if (hsbuf.off > 0) {
            if (tls_wbuf_append(&c->tls_wbuf, hsbuf.base, hsbuf.off) != 0) {
                trouble("TLS wbuf alloc failed during handshake fd=%d\n", c->fd);
                ptls_buffer_dispose(&hsbuf);
                if (merged) Safefree(merged);
                safe_close_conn(c, "TLS allocation failure");
                goto tls_read_cleanup;
            }
            int flush_ret = feer_tls_flush_wbuf(c);
            if (flush_ret == -1) {
                /* Need to wait for write readiness */
                feer_tls_start_write(c);
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
                if (c->tls_alpn_h2 && c->h2_session) {
                    /* Feed to nghttp2 */
                    ptls_buffer_t decbuf;
                    ptls_buffer_init(&decbuf, "", 0);
                    size_t dec_consumed = remaining;
                    int dec_ret = ptls_receive(c->tls, &decbuf, extra, &dec_consumed);
                    if (dec_ret == 0 && dec_consumed < remaining) {
                        size_t leftover = remaining - dec_consumed;
                        Newx(c->tls_rbuf, leftover, uint8_t);
                        memcpy(c->tls_rbuf, extra + dec_consumed, leftover);
                        c->tls_rbuf_len = leftover;
                    }
                    if (dec_ret == 0 && decbuf.off > 0) {
                        feer_h2_session_recv(c, decbuf.base, decbuf.off);
                    }
                    ptls_buffer_dispose(&decbuf);
                    /* Send any pending nghttp2 frames (SETTINGS etc.) */
                    feer_h2_session_send(c);
                    restart_read_timer(c);
                    if (merged) Safefree(merged);
                    goto tls_read_cleanup;
                }
#endif
                /* H1: decrypt and feed to HTTP parser */
                ptls_buffer_t decbuf;
                ptls_buffer_init(&decbuf, "", 0);
                size_t dec_consumed = remaining;
                int dec_ret = ptls_receive(c->tls, &decbuf, extra, &dec_consumed);
                if (dec_ret == 0 && dec_consumed < remaining) {
                    size_t leftover = remaining - dec_consumed;
                    Newx(c->tls_rbuf, leftover, uint8_t);
                    memcpy(c->tls_rbuf, extra + dec_consumed, leftover);
                    c->tls_rbuf_len = leftover;
                }
                if (dec_ret == 0 && decbuf.off > 0) {
                    size_t decrypted_len = decbuf.off;
                    /* Append decrypted data to connection read buffer */
                    if (!c->rbuf) {
                        c->rbuf = newSV(decrypted_len + READ_BUFSZ);
                        SvPOK_on(c->rbuf);
                        SvCUR_set(c->rbuf, 0);
                    }
                    sv_catpvn(c->rbuf, (const char *)decbuf.base, decrypted_len);
                    ptls_buffer_dispose(&decbuf);

                    restart_read_timer(c);
                    int parse_ret = try_parse_http(c, decrypted_len);
                    if (parse_ret == -1) {
                        respond_with_server_error(c, "Malformed request\n", 0, 400);
                        change_receiving_state(c, RECEIVE_SHUTDOWN);
                        stop_read_watcher(c);
                        stop_read_timer(c);
                        if (merged) Safefree(merged);
                        goto tls_read_cleanup;
                    }
                    if (parse_ret > 0) {
                        if (!process_request_headers(c, parse_ret)) {
                            change_receiving_state(c, RECEIVE_SHUTDOWN);
                            stop_read_watcher(c);
                            stop_read_timer(c);
                        }
                    }
                    /* parse_ret == -2: incomplete, read watcher will get more data */
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
        merged = NULL;

        if (ret != 0) {
            trace("TLS receive error fd=%d ret=%d\n", c->fd, ret);
            if (ret == PTLS_ALERT_CLOSE_NOTIFY) {
                trace("TLS close_notify fd=%d\n", c->fd);
            }
            ptls_buffer_dispose(&decbuf);
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            safe_close_conn(c, "TLS receive error");
            goto tls_read_cleanup;
        }

        if (decbuf.off == 0) {
            ptls_buffer_dispose(&decbuf);
            goto tls_read_cleanup; /* No application data yet */
        }

#ifdef FEERSUM_HAS_H2
        if (c->tls_alpn_h2 && c->h2_session) {
            /* Feed decrypted data to nghttp2 */
            feer_h2_session_recv(c, decbuf.base, decbuf.off);
            ptls_buffer_dispose(&decbuf);
            /* Send any pending nghttp2 frames */
            feer_h2_session_send(c);
            restart_read_timer(c);
            goto tls_read_cleanup;
        }
#endif

        /* HTTP/1.1 over TLS: append decrypted data to rbuf */
        got_n = (ssize_t)decbuf.off;
        if (!c->rbuf) {
            c->rbuf = newSV(got_n + READ_BUFSZ);
            SvPOK_on(c->rbuf);
            SvCUR_set(c->rbuf, 0);
        }
        sv_catpvn(c->rbuf, (const char *)decbuf.base, decbuf.off);
        ptls_buffer_dispose(&decbuf);
    }
    goto tls_parse;

tls_pipelined:
    got_n = c->pipelined;
    c->pipelined = 0;

tls_parse:
    restart_read_timer(c);

    if (likely(c->receiving <= RECEIVE_HEADERS)) {
        int parse_ret = try_parse_http(c, (size_t)got_n);
        if (parse_ret == -1) {
            respond_with_server_error(c, "Malformed request\n", 0, 400);
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            stop_read_watcher(c);
            stop_read_timer(c);
            goto tls_read_cleanup;
        }
        if (parse_ret == -2) {
            /* Incomplete, wait for more data (read watcher already active) */
            goto tls_read_cleanup;
        }
        /* Headers complete. parse_ret = body offset */
        if (!process_request_headers(c, parse_ret)) {
            /* Request fully dispatched (no body to read) */
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            stop_read_watcher(c);
            stop_read_timer(c);
        }
    }
    else if (likely(c->receiving == RECEIVE_BODY)) {
        c->received_cl += got_n;
        if (c->received_cl >= c->expected_cl) {
            sched_request_callback(c);
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            stop_read_watcher(c);
            stop_read_timer(c);
        }
    }
    else if (c->receiving == RECEIVE_CHUNKED) {
        int ret = try_parse_chunked(c);
        if (ret == -1) {
            respond_with_server_error(c, "Malformed chunked encoding\n", 0, 400);
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            stop_read_watcher(c);
            stop_read_timer(c);
        }
        else if (ret == 0) {
            sched_request_callback(c);
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            stop_read_watcher(c);
            stop_read_timer(c);
        }
        /* ret == 1: need more data, watcher stays active */
    }
    else if (c->receiving == RECEIVE_STREAMING) {
        c->received_cl += got_n;
        if (c->poll_read_cb) {
            call_poll_callback(c, 0);
        }
        if (c->expected_cl > 0 && c->received_cl >= c->expected_cl) {
            change_receiving_state(c, RECEIVE_SHUTDOWN);
            stop_read_watcher(c);
            stop_read_timer(c);
        }
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
    if (c->tls_alpn_h2 && c->h2_session) {
        /* For H2, nghttp2 manages the write buffer.
         * Call session_send to generate frames, encrypt, and write. */
        feer_h2_session_send(c);
        if (c->tls_wbuf.off > 0) {
            int flush_ret = feer_tls_flush_wbuf(c);
            if (flush_ret == -1) goto tls_write_cleanup;
        }
        if (c->tls_wbuf.off == 0 && !c->tls_wants_write) {
            stop_write_watcher(c);
        }
        goto tls_write_cleanup;
    }
#endif

    /* HTTP/1.1 over TLS: encrypt wbuf_rinq (headers/body) first, then sendfile */

    /* Encrypt data from wbuf_rinq (must come before sendfile to send headers first) */
    if (c->wbuf_rinq) {
        struct iomatrix *m;
        while ((m = (struct iomatrix *)rinq_shift(&c->wbuf_rinq)) != NULL) {
            unsigned int i;
            for (i = 0; i < m->count; i++) {
                if (m->iov[i].iov_len == 0) continue;

                ptls_buffer_t encbuf;
                ptls_buffer_init(&encbuf, "", 0);
                int ret = ptls_send(c->tls, &encbuf,
                                    m->iov[i].iov_base, m->iov[i].iov_len);
                if (ret != 0) {
                    ptls_buffer_dispose(&encbuf);
                    trouble("ptls_send error fd=%d ret=%d\n", c->fd, ret);
                    /* Free all SVs in this matrix */
                    for (i = 0; i < m->count; i++) {
                        if (m->sv[i]) SvREFCNT_dec(m->sv[i]);
                    }
                    IOMATRIX_FREE(m);
                    goto tls_write_error;
                }
                if (encbuf.off > 0) {
                    if (tls_wbuf_append(&c->tls_wbuf, encbuf.base, encbuf.off) != 0) {
                        ptls_buffer_dispose(&encbuf);
                        trouble("TLS wbuf alloc failed fd=%d\n", c->fd);
                        for (i = 0; i < m->count; i++) {
                            if (m->sv[i]) SvREFCNT_dec(m->sv[i]);
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
        }

        /* Flush all encrypted data */
        int flush_ret = feer_tls_flush_wbuf(c);
        if (flush_ret == -1) goto tls_write_cleanup; /* EAGAIN */
        if (flush_ret == -2) goto tls_write_error;
    }

    /* Handle sendfile over TLS: pread + encrypt + write */
    if (c->sendfile_fd >= 0 && c->sendfile_remain > 0) {
        uint8_t filebuf[TLS_RAW_BUFSZ];
        size_t to_read = c->sendfile_remain;
        if (to_read > sizeof(filebuf)) to_read = sizeof(filebuf);

        ssize_t file_nread = pread(c->sendfile_fd, filebuf, to_read, c->sendfile_off);
        if (file_nread <= 0) {
            if (file_nread < 0)
                trouble("TLS pread(sendfile_fd) fd=%d: %s\n", c->fd, strerror(errno));
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
            goto tls_write_finished;
        }

        /* Queue encrypted data */
        if (encbuf.off > 0) {
            if (tls_wbuf_append(&c->tls_wbuf, encbuf.base, encbuf.off) != 0) {
                ptls_buffer_dispose(&encbuf);
                trouble("TLS wbuf alloc failed (sendfile) fd=%d\n", c->fd);
                CLOSE_SENDFILE_FD(c);
                goto tls_write_finished;
            }
        }
        ptls_buffer_dispose(&encbuf);

        c->sendfile_off += file_nread;
        c->sendfile_remain -= file_nread;

        if (c->sendfile_remain == 0)
            CLOSE_SENDFILE_FD(c);

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
    /* Check if we're done writing */
    if (!c->wbuf_rinq && c->sendfile_fd < 0 && c->tls_wbuf.off == 0) {
        stop_write_watcher(c);

        /* Handle response completion — mirrors try_conn_write's try_write_shutdown.
         * Both RESPOND_NORMAL and RESPOND_SHUTDOWN can have keepalive
         * (send_response sets RESPOND_SHUTDOWN directly). */
        if (c->responding == RESPOND_SHUTDOWN || c->responding == RESPOND_NORMAL) {
            if (c->is_keepalive) {
                change_responding_state(c, RESPOND_NOT_STARTED);
                change_receiving_state(c, RECEIVE_WAIT);
                STRLEN pipelined = 0;
                if (c->rbuf) { pipelined = SvCUR(c->rbuf); }
                if (likely(c->req)) {
                    // reuse req->buf for next request, pool the empty c->rbuf
                    if (likely(pipelined == 0) && c->req->buf && c->rbuf) {
                        SV *tmp = c->rbuf;
                        c->rbuf = c->req->buf;
                        c->req->buf = NULL;
                        SvCUR_set(c->rbuf, 0);
                        rbuf_free(tmp);
                    } else if (c->req->buf) {
                        rbuf_free(c->req->buf);
                        c->req->buf = NULL;
                    }
                    free_request(c);
                }
                if (unlikely(pipelined > 0 && c->is_http11)) {
                    trace("TLS pipelined data on fd=%d len=%"UVuf"\n",
                          c->fd, (UV)pipelined);
                    c->pipelined = pipelined;
                    if (c->pipeline_depth <= MAX_PIPELINE_DEPTH) {
                        c->pipeline_depth++;
                        try_tls_conn_read(feersum_ev_loop, &c->read_ev_io, 0);
                        c->pipeline_depth--;
                    } else {
                        trace("TLS pipeline depth limit on fd=%d\n", c->fd);
                        start_read_watcher(c);
                        restart_read_timer(c);
                    }
                } else {
                    c->pipelined = 0;
                    start_read_watcher(c);
                    restart_read_timer(c);
                }
            } else {
                if (c->responding != RESPOND_SHUTDOWN)
                    change_responding_state(c, RESPOND_SHUTDOWN);
                safe_close_conn(c, "TLS close at write shutdown");
            }
        } else if (c->responding == RESPOND_STREAMING && c->poll_write_cb) {
            call_poll_callback(c, 1 /* is_write */);
        }
    }
    goto tls_write_cleanup;

tls_write_error:
    stop_write_watcher(c);
    change_responding_state(c, RESPOND_SHUTDOWN);
    safe_close_conn(c, "TLS write error");

tls_write_cleanup:
    SvREFCNT_dec(c->self);
}

/*
 * Encrypt response data and queue for TLS writing.
 */
static void
feer_tls_send(struct feer_conn *c, const void *data, size_t len)
{
    if (!c->tls || len == 0) return;

    ptls_buffer_t encbuf;
    ptls_buffer_init(&encbuf, "", 0);
    int ret = ptls_send(c->tls, &encbuf, data, len);
    if (ret != 0) {
        ptls_buffer_dispose(&encbuf);
        trouble("feer_tls_send error fd=%d ret=%d\n", c->fd, ret);
        return;
    }
    if (encbuf.off > 0) {
        if (tls_wbuf_append(&c->tls_wbuf, encbuf.base, encbuf.off) != 0) {
            ptls_buffer_dispose(&encbuf);
            trouble("TLS wbuf alloc failed (send) fd=%d\n", c->fd);
            return;
        }
    }
    ptls_buffer_dispose(&encbuf);
}

/*
 * Start the TLS write watcher to flush pending encrypted data.
 */
static void
feer_tls_start_write(struct feer_conn *c)
{
    if (!ev_is_active(&c->write_ev_io)) {
        SvREFCNT_inc_simple_void_NN(c->self);
        ev_io_start(feersum_ev_loop, &c->write_ev_io);
    }
}

#endif /* FEERSUM_HAS_TLS */
