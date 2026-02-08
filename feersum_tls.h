/*
 * feersum_tls.h - TLS 1.3 support via picotls for Feersum
 *
 * Provides TLS handshake, encryption/decryption, and separate
 * read/write callbacks for TLS connections. Plain HTTP connections
 * never touch this code.
 */

#ifndef FEERSUM_TLS_H
#define FEERSUM_TLS_H

#ifdef FEERSUM_HAS_TLS

#include <picotls.h>
#include <picotls/openssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* TLS read buffer size for raw socket reads */
#define TLS_RAW_BUFSZ 16384

/* ALPN protocol identifiers */
#define ALPN_H2     "\x02h2"
#define ALPN_H2_LEN 3
#define ALPN_HTTP11     "\x08http/1.1"
#define ALPN_HTTP11_LEN 9

/*
 * Forward declarations for functions that don't reference struct feer_conn.
 * Functions taking struct feer_conn * are forward-declared in feersum_tls.c
 * (after the struct is defined) or just defined in order.
 */
static ptls_context_t *feer_tls_create_context(pTHX_ const char *cert_file, const char *key_file, int h2);
static void feer_tls_free_context(ptls_context_t *ctx);

/* ev_io callbacks (these use the standard EV callback signature) */
static void try_tls_conn_read(EV_P_ ev_io *w, int revents);
static void try_tls_conn_write(EV_P_ ev_io *w, int revents);

#endif /* FEERSUM_HAS_TLS */
#endif /* FEERSUM_TLS_H */
