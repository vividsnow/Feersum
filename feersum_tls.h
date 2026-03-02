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
#define ALPN_HTTP11     "\x08http/1.1"


#endif /* FEERSUM_HAS_TLS */
#endif /* FEERSUM_TLS_H */
