/*
 * feersum_h2.h - HTTP/2 support via nghttp2 for Feersum
 *
 * Provides nghttp2 session management, stream-to-request mapping,
 * and H2-specific response path. H2 is TLS-only (no h2c).
 */

#ifndef FEERSUM_H2_H
#define FEERSUM_H2_H

#ifdef FEERSUM_HAS_H2

#ifndef FEERSUM_HAS_TLS
#error "FEERSUM_HAS_H2 requires FEERSUM_HAS_TLS (H2 is TLS-only)"
#endif

#include <nghttp2/nghttp2.h>

/* Maximum concurrent streams per connection (nghttp2 default is 100) */
#define FEER_H2_MAX_CONCURRENT_STREAMS 100

/* Maximum header list size (64KB) */
#define FEER_H2_MAX_HEADER_LIST_SIZE (64 * 1024)

/* H2 stream structure - one per HTTP/2 stream.
 * Forward-declared here; full definition used in feersum_h2.c.inc.
 * struct feer_conn and struct feer_req are not yet defined when this
 * header is included, so we only put the struct definition here (which
 * uses forward-declared struct pointers, which is legal in C). */
struct feer_h2_stream {
    struct feer_h2_stream *next;        /* intrusive linked list per connection */
    struct feer_conn      *parent;      /* the real TLS connection */
    struct feer_conn      *pseudo_conn; /* fake feer_conn exposed to Perl handlers */
    int32_t                stream_id;

    /* Request accumulation */
    struct feer_req       *req;         /* request being built */
    SV                    *body_buf;    /* accumulated request body */
    AV                    *trailers;    /* request trailers (array of name/value pairs) */

    /* H2 pseudo-headers */
    SV *h2_method;
    SV *h2_path;
    SV *h2_scheme;
    SV *h2_authority;

    /* Extended CONNECT / tunnel state (RFC 8441) */
    SV *h2_protocol;                /* :protocol pseudo-header value */
    unsigned int is_tunnel:1;       /* Extended CONNECT stream */
    unsigned int tunnel_established:1;
    unsigned int tunnel_swallow_response:1; /* swallow HTTP/1.1 response for PSGI transparency */
    unsigned int tunnel_pending_shutdown:1; /* DATA+END_STREAM arrived before tunnel_established */
    unsigned int tunnel_eof_sent:1;        /* shutdown(SHUT_WR) already called on sv[0] */

    /* Socketpair bridge */
    int tunnel_sv0;                 /* internal end (Feersum ev_io) */
    int tunnel_sv1;                 /* handler end (psgix.io) */
    struct ev_io tunnel_read_w;     /* sv[0] readable → app wrote to sv[1] */
    struct ev_io tunnel_write_w;    /* sv[0] writable → drain tunnel_wbuf */
    SV *tunnel_wbuf;                /* buffered H2 DATA pending write to sv[0] */
    size_t tunnel_wbuf_pos;

    /* Response state */
    SV                    *resp_body;       /* complete body SV for non-streaming */
    size_t                 resp_body_pos;   /* read position in resp_body */
    SV                    *resp_wbuf;       /* streaming write buffer */
    size_t                 resp_wbuf_pos;   /* read position in resp_wbuf */
    SV                    *resp_message;    /* saved message SV for deferred submit */
    SV                    *resp_headers;    /* saved headers AV ref for deferred submit */
    unsigned int           resp_eof:1;      /* streaming close() called */
};

/*
 * No forward declarations for functions taking struct feer_conn * here,
 * because struct feer_conn is not yet defined at include time.
 * Those functions are declared static in feersum_h2.c.inc which is included
 * after all structs are defined.
 */

#endif /* FEERSUM_HAS_H2 */
#endif /* FEERSUM_H2_H */
