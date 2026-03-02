#ifndef FEERSUM_CORE_H
#define FEERSUM_CORE_H

#include "EVAPI.h"

#define PERL_NO_GET_CONTEXT
#include "ppport.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <time.h>
#include <stdarg.h>
#ifdef __linux__
#include <sys/sendfile.h>
#include <sys/epoll.h>
#endif

#ifdef FEERSUM_HAS_TLS
#include "feersum_tls.h"
#endif
#ifdef FEERSUM_HAS_H2
#include "feersum_h2.h"
#endif
#include "picohttpparser-git/picohttpparser.h"

#ifdef FEERSUM_HAS_USDT
#include "feersum_probes.h"
static void feer_usdt_trace(int level, const char *fmt, ...);
#else
#define FEERSUM_CONN_NEW(fd, addr, port)
#define FEERSUM_CONN_FREE(fd)
#define FEERSUM_REQ_NEW(fd, method, uri)
#define FEERSUM_REQ_BODY(fd, len)
#define FEERSUM_RESP_START(fd, code)
#define FEERSUM_TRACE(level, message)
#define FEERSUM_TRACE_ENABLED() 0
#define FEERSUM_CONN_NEW_ENABLED() 0
#define FEERSUM_CONN_FREE_ENABLED() 0
#define FEERSUM_REQ_NEW_ENABLED() 0
#define FEERSUM_REQ_BODY_ENABLED() 0
#define FEERSUM_RESP_START_ENABLED() 0
#endif

///////////////////////////////////////////////////////////////
// constants

#define FEER_MAX_LISTENERS 16
#ifndef MAX_HEADERS
# define MAX_HEADERS 64
#endif
#ifndef MAX_HEADER_NAME_LEN
# define MAX_HEADER_NAME_LEN 128
#endif
#ifndef MAX_URI_LEN
# define MAX_URI_LEN 8192
#endif
#ifndef MAX_BODY_LEN
# define MAX_BODY_LEN 67108864
#endif
#ifndef MAX_CHUNK_COUNT
# define MAX_CHUNK_COUNT 100000
#endif
#ifndef MAX_TRAILER_HEADERS
# define MAX_TRAILER_HEADERS 64
#endif
#ifndef MAX_READ_BUF
# define MAX_READ_BUF 67108864
#endif

#define CHUNK_STATE_PARSE_SIZE  -1
#define CHUNK_STATE_NEED_CRLF   -3

#define READ_BUFSZ 4096
#define IO_PUMP_BUFSZ 4096
#define READ_INIT_FACTOR 1
#define READ_GROW_FACTOR 4
#define READ_TIMEOUT 5.0
#define HEADER_TIMEOUT 10.0
#define WRITE_TIMEOUT 0.0

#define DATE_HEADER 1
#define DEFAULT_MAX_ACCEPT_PER_LOOP 64
#define MAX_PIPELINE_DEPTH 15
#define FEERSUM_IOMATRIX_SIZE 64

#define PROXY_V1_PREFIX "PROXY "
#define PROXY_V1_PREFIX_LEN 6
#define PROXY_V1_MAX_LINE 108

#define PROXY_V2_SIG "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define PROXY_V2_SIG_LEN 12
#define PROXY_V2_HDR_MIN 16
#define PROXY_V2_ADDR_V4_LEN 12
#define PROXY_V2_ADDR_V6_LEN 36
#define PROXY_V2_VERSION 0x20
#define PROXY_V2_CMD_LOCAL 0x00
#define PROXY_V2_CMD_PROXY 0x01
#define PROXY_V2_FAM_UNSPEC 0x00
#define PROXY_V2_FAM_INET 0x10
#define PROXY_V2_FAM_INET6 0x20

#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_UNIQUE_ID      0x05
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
#define PP2_TYPE_NETNS          0x30

#define FEER_TUNNEL_BUFSZ 16384
#define FEER_TUNNEL_MAX_WBUF (16 * 1024 * 1024)

#define DATE_HEADER_LENGTH 37
#define DATE_VALUE_LENGTH  (DATE_HEADER_LENGTH - 6 - 2)
#define HEADER_KEY_BUFSZ (5 + MAX_HEADER_NAME_LEN)

///////////////////////////////////////////////////////////////
// enums

enum feer_respond_state {
    RESPOND_NOT_STARTED = 0,
    RESPOND_NORMAL = 1,
    RESPOND_STREAMING = 2,
    RESPOND_SHUTDOWN = 3
};

enum feer_receive_state {
    RECEIVE_WAIT = 0,
    RECEIVE_HEADERS = 1,
    RECEIVE_BODY = 2,
    RECEIVE_STREAMING = 3,
    RECEIVE_SHUTDOWN = 4,
    RECEIVE_CHUNKED = 5,
    RECEIVE_PROXY_HEADER = 6
};

enum feer_header_norm_style {
    HEADER_NORM_SKIP = 0,
    HEADER_NORM_UPCASE_DASH = 1,
    HEADER_NORM_LOCASE_DASH = 2,
    HEADER_NORM_UPCASE = 3,
    HEADER_NORM_LOCASE = 4
};

///////////////////////////////////////////////////////////////
// macros

#ifdef __GNUC__
# define likely(x)   __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define likely(x)   (x)
# define unlikely(x) (x)
#endif

#define CLOSE_SENDFILE_FD(c) do { \
    if ((c)->sendfile_fd >= 0) { \
        if (unlikely(close((c)->sendfile_fd) < 0)) \
            trouble("close(sendfile_fd) fd=%d: %s\n", (c)->sendfile_fd, strerror(errno)); \
        (c)->sendfile_fd = -1; \
    } \
} while (0)

#ifndef HAS_ACCEPT4
#ifdef __GLIBC_PREREQ
#if __GLIBC_PREREQ(2, 10)
    // accept4 is available
    #define HAS_ACCEPT4 1
#endif
#endif
#endif

#ifndef HAS_ACCEPT4
    #ifdef __NR_accept4
        #define HAS_ACCEPT4 1
    #endif
#endif

#ifndef CRLF
#define CRLF "\015\012"
#endif
#define CRLFx2 CRLF CRLF

#ifndef SOL_TCP
 #define SOL_TCP IPPROTO_TCP
#endif

#if Size_t_size == LONGSIZE
# define Sz_f "l"
# define Sz_t long
#elif Size_t_size == 8 && defined HAS_QUAD && QUADKIND == QUAD_IS_LONG_LONG
# define Sz_f "ll"
# define Sz_t long long
#else
# define Sz_f ""
# define Sz_t int
#endif

#define Sz_uf Sz_f"u"
#define Sz_xf Sz_f"x"
#define Ssz_df Sz_f"d"
#define Sz unsigned Sz_t
#define Ssz Sz_t

#define WARN_PREFIX "Feersum: "

#ifndef DEBUG
 #define INLINE_UNLESS_DEBUG inline
#else
 #define INLINE_UNLESS_DEBUG
#endif

#define trouble(f_, ...) warn(WARN_PREFIX f_, ##__VA_ARGS__)

#ifdef FEERSUM_HAS_USDT
# define USDT_TRACE(level, f_, ...) feer_usdt_trace(level, f_, ##__VA_ARGS__)
#else
# define USDT_TRACE(level, f_, ...)
#endif

#ifdef DEBUG
# define trace(f_, ...) do { \
    warn("%s:%-4d [%d] " f_, __FILE__, __LINE__, (int)getpid(), ##__VA_ARGS__); \
    USDT_TRACE(1, f_, ##__VA_ARGS__); \
  } while(0)
# define trace2(f_, ...) do { \
    warn("%s:%-4d [%d] " f_, __FILE__, __LINE__, (int)getpid(), ##__VA_ARGS__); \
    USDT_TRACE(2, f_, ##__VA_ARGS__); \
  } while(0)
# define trace3(f_, ...) do { \
    warn("%s:%-4d [%d] " f_, __FILE__, __LINE__, (int)getpid(), ##__VA_ARGS__); \
    USDT_TRACE(3, f_, ##__VA_ARGS__); \
  } while(0)
#else
# define trace(f_, ...)  USDT_TRACE(1, f_, ##__VA_ARGS__)
# define trace2(f_, ...) USDT_TRACE(2, f_, ##__VA_ARGS__)
# define trace3(f_, ...) USDT_TRACE(3, f_, ##__VA_ARGS__)
#endif

#define RESPOND_STR(_n,_s) do { \
    switch(_n) { \
    case RESPOND_NOT_STARTED: _s = "NOT_STARTED(0)"; break; \
    case RESPOND_NORMAL:      _s = "NORMAL(1)"; break; \
    case RESPOND_STREAMING:   _s = "STREAMING(2)"; break; \
    case RESPOND_SHUTDOWN:    _s = "SHUTDOWN(3)"; break; \
    default:                  _s = "UNKNOWN"; break; \
    } \
} while (0)

#define RECEIVE_STR(_n,_s) do { \
    switch(_n) { \
    case RECEIVE_WAIT:         _s = "WAIT(0)"; break; \
    case RECEIVE_HEADERS:      _s = "HEADERS(1)"; break; \
    case RECEIVE_BODY:         _s = "BODY(2)"; break; \
    case RECEIVE_STREAMING:    _s = "STREAMING(3)"; break; \
    case RECEIVE_SHUTDOWN:     _s = "SHUTDOWN(4)"; break; \
    case RECEIVE_CHUNKED:      _s = "CHUNKED(5)"; break; \
    case RECEIVE_PROXY_HEADER: _s = "PROXY(6)"; break; \
    default:                   _s = "UNKNOWN"; break; \
    } \
} while (0)

#ifdef DEBUG
# define change_responding_state(c, _to) do { \
    enum feer_respond_state __to = (_to); \
    enum feer_respond_state __from = (c)->responding; \
    const char *_from_str, *_to_str; \
    if (likely(__from != __to)) { \
        RESPOND_STR((c)->responding, _from_str); \
        RESPOND_STR(__to, _to_str); \
        trace2("==> responding state %d: %s to %s\n", (c)->fd,_from_str,_to_str); \
        (c)->responding = __to; \
    } \
} while (0)
# define change_receiving_state(c, _to) do { \
    enum feer_receive_state __to = (_to); \
    enum feer_receive_state __from = (c)->receiving; \
    const char *_from_str, *_to_str; \
    if (likely(__from != __to)) { \
        RECEIVE_STR((c)->receiving, _from_str); \
        RECEIVE_STR(__to, _to_str); \
        trace2("==> receiving state %d: %s to %s\n", (c)->fd,_from_str,_to_str); \
        (c)->receiving = __to; \
    } \
} while (0)
#else
# define change_responding_state(c, _to) (c)->responding = (_to)
# define change_receiving_state(c, _to) (c)->receiving = (_to)
#endif

#define dCONN struct feer_conn *c = (struct feer_conn *)w->data
#define IsArrayRef(_x) (SvROK(_x) && SvTYPE(SvRV(_x)) == SVt_PVAV)
#define IsCodeRef(_x) (SvROK(_x) && SvTYPE(SvRV(_x)) == SVt_PVCV)
#define rbuf_alloc(src, len) newSVpvn((len) > 0 ? (src) : "", (len))
#define ASSERT_EV_LOOP_INITIALIZED() \
    assert(feersum_ev_loop != NULL && "feersum_ev_loop not initialized - call accept_on_fd first")

#define feer_clear_remote_cache(_c) STMT_START { \
    if ((_c)->remote_addr) { SvREFCNT_dec((_c)->remote_addr); (_c)->remote_addr = NULL; } \
    if ((_c)->remote_port) { SvREFCNT_dec((_c)->remote_port); (_c)->remote_port = NULL; } \
} STMT_END

///////////////////////////////////////////////////////////////
// structs

struct rinq {
    struct rinq *next,*prev;
    void *ref;
};

struct iomatrix {
    unsigned offset;
    unsigned count;
    struct iovec iov[FEERSUM_IOMATRIX_SIZE];
    SV *sv[FEERSUM_IOMATRIX_SIZE];
};

struct feer_req {
    SV *buf;
    const char* method;
    size_t method_len;
    const char* uri;
    size_t uri_len;
    int minor_version;
    size_t num_headers;
    struct phr_header headers[MAX_HEADERS];
    SV* path;
    SV* query;
#ifdef FEERSUM_HAS_H2
    SV* h2_method_sv;
    SV* h2_uri_sv;
#endif
};

struct feer_conn {
    SV *self;
    int fd;
    enum feer_respond_state responding;
    enum feer_receive_state receiving;
    bool is_keepalive;
    int reqs;
    SV *rbuf;
    struct rinq *wbuf_rinq;
    size_t wbuf_len;
    struct feer_req *req;
    struct feer_server *server;
    struct feer_listen *listener;

    double       cached_read_timeout;
    double       cached_write_timeout;
    unsigned int cached_max_conn_reqs;
    bool         cached_is_tcp;
    bool         cached_keepalive_default;
    bool         cached_use_reverse_proxy;
    bool         cached_request_cb_is_psgi;
    size_t       cached_max_read_buf;
    size_t       cached_max_body_len;
    size_t       cached_max_uri_len;
    size_t       cached_wbuf_low_water;
    ssize_t pipelined;
    ssize_t expected_cl;
    ssize_t received_cl;

    unsigned int in_callback;
    unsigned int pipeline_depth;
    unsigned int is_http11:1;
    unsigned int poll_write_cb_is_io_handle:1;
    unsigned int auto_cl:1;
    unsigned int use_chunked:1;
    unsigned int expect_continue:1;
    unsigned int receive_chunked:1;
    unsigned int io_taken:1;
    unsigned int proxy_proto_version:2;
    unsigned int proxy_ssl:1;

    struct ev_io read_ev_io;
    struct ev_io write_ev_io;
    struct ev_timer read_ev_timer;
    struct ev_timer header_ev_timer;
    struct ev_timer write_ev_timer;

    struct sockaddr_storage sa;

    SV *poll_write_cb;
    SV *poll_read_cb;
    SV *ext_guard;

    SV *remote_addr;
    SV *remote_port;
    AV *trailers;

    SV *proxy_tlvs;

    int sendfile_fd;
    off_t sendfile_off;
    size_t sendfile_remain;

    uint16_t proxy_dst_port;
    struct rinq *idle_rinq_node;

    ssize_t chunk_remaining;
    unsigned int chunk_count;
    unsigned int trailer_count;

#ifdef FEERSUM_HAS_TLS
    ptls_t         *tls;
    struct feer_tls_ctx_ref *tls_ctx_ref;
    ptls_buffer_t   tls_wbuf;
    uint8_t        *tls_rbuf;
    size_t          tls_rbuf_len;
    unsigned int    tls_handshake_done:1;
    unsigned int    tls_wants_write:1;
    unsigned int    tls_alpn_h2:1;

    int             tls_tunnel_sv0;
    int             tls_tunnel_sv1;
    struct ev_io    tls_tunnel_read_w;
    struct ev_io    tls_tunnel_write_w;
    SV             *tls_tunnel_wbuf;
    size_t          tls_tunnel_wbuf_pos;
    unsigned int    tls_tunnel:1;
#endif
#ifdef FEERSUM_HAS_H2
    nghttp2_session       *h2_session;
    struct feer_h2_stream *h2_streams;
    unsigned int           is_h2_stream:1;
    unsigned int           h2_goaway_sent:1;
#endif
};

#ifdef FEERSUM_HAS_TLS
/* Reference-counted wrapper for ptls_context_t.
 * Connections hold refs via ptls_t back-pointer; the listener may rotate
 * certificates (set_tls) or be reused (accept_on_fd) while connections
 * still reference the old context. */
struct feer_tls_ctx_ref {
    ptls_context_t *ctx;
    int refcount;
};
#endif

struct feer_listen {
    struct feer_server *server;
    int                 fd;
    ev_io               accept_w;
    bool                is_tcp;
    bool                paused;
    SV                 *server_name;
    SV                 *server_port;
#ifdef __linux__
    int                 epoll_fd;
#endif
#ifdef FEERSUM_HAS_TLS
    struct feer_tls_ctx_ref *tls_ctx_ref;
#endif
};

struct feer_server {
    SV *self;
    struct feer_listen listeners[FEER_MAX_LISTENERS];
    int                n_listeners;
    SV   *request_cb_cv;
    bool  request_cb_is_psgi;
    SV   *shutdown_cb_cv;
    bool  shutting_down;
    int   active_conns;
    UV    total_requests;
    double       read_timeout;
    double       header_timeout;
    double       write_timeout;
    unsigned int max_connection_reqs;
    bool         is_keepalive;
    int          read_priority;
    int          write_priority;
    int          accept_priority;
    int          max_accept_per_loop;
    int          max_connections;
    size_t       max_read_buf;
    size_t       max_body_len;
    size_t       max_uri_len;
    size_t       wbuf_low_water;
    bool         use_reverse_proxy;
    bool         use_proxy_protocol;
#ifdef __linux__
    bool         use_epoll_exclusive;
#endif
    bool         watchers_initialized;
    ev_prepare       ep;
    ev_check         ec;
    struct ev_idle   ei;
    struct rinq     *request_ready_rinq;
    struct rinq     *idle_keepalive_rinq;
};

typedef struct feer_conn feer_conn_handle;

///////////////////////////////////////////////////////////////
// externs

extern char header_key_buf[];
extern const unsigned char ascii_lower[];
extern const unsigned char ascii_upper[];
extern const unsigned char ascii_upper_dash[];
extern const unsigned char ascii_lower_dash[];
extern const unsigned char hex_decode_table[];
extern char DATE_BUF[];
extern HV *feer_stash, *feer_conn_stash;
extern HV *feer_conn_reader_stash, *feer_conn_writer_stash;
extern MGVTBL psgix_io_vtbl;
extern struct feer_server *default_server;
extern struct ev_loop *feersum_ev_loop;
extern AV *psgi_ver;
extern SV *psgi_serv10, *psgi_serv11;
extern SV *method_GET, *method_POST, *method_HEAD, *method_PUT, *method_PATCH, *method_DELETE, *method_OPTIONS;
extern SV *status_200, *status_201, *status_204, *status_301, *status_302, *status_304;
extern SV *status_400, *status_404, *status_500;
extern SV *empty_query_sv;
extern SV *psgi_env_version;
extern SV *psgi_env_errors;
extern ev_timer date_timer;
extern int date_timer_refs;

///////////////////////////////////////////////////////////////
// prototypes

typedef void (*conn_read_cb_t)(EV_P_ ev_io *, int);

static void rinq_push (struct rinq **head, void *ref);
static void* rinq_shift (struct rinq **head);

/* Unconditional H2 shims — always defined (return 0/no-op without FEERSUM_HAS_H2).
 * Called from XS CODE blocks that can't use #ifdef directly. */
static int h2_try_write_chunk (pTHX_ struct feer_conn *c, SV *body);
static int h2_is_stream (struct feer_conn *c);

#ifdef FEERSUM_HAS_H2
static void h2_tunnel_auto_accept(pTHX_ struct feer_conn *c, struct feer_h2_stream *stream);
static void pump_h2_io_handle(pTHX_ struct feer_conn *c, SV *body);
static void feersum_h2_close_write(pTHX_ struct feer_conn *c);
static void feersum_h2_write_chunk(pTHX_ struct feer_conn *c, SV *body);
static void h2_check_stream_poll_cbs(pTHX_ struct feer_conn *c);
static inline void h2_submit_rst(nghttp2_session *session, int32_t stream_id, uint32_t error_code);
static size_t feersum_h2_write_whole_body(pTHX_ struct feer_conn *c, SV *body_sv);
static void feer_h2_setup_tunnel(pTHX_ struct feer_h2_stream *stream);
static void feer_h2_init_session(struct feer_conn *c);
static void feer_h2_free_session(struct feer_conn *c);
static void feer_h2_session_recv(struct feer_conn *c, const uint8_t *data, size_t len);
static void feer_h2_session_send(struct feer_conn *c);
static void feersum_h2_start_response(pTHX_ struct feer_conn *c, SV *message, AV *headers, int streaming);
static void feersum_h2_respond_error(struct feer_conn *c, int err_code);
static void h2_try_stream_write(pTHX_ struct feer_conn *c);
#endif

static void feersum_set_conn_remote_info(pTHX_ struct feer_conn *c);
static SV* feersum_env_method(pTHX_ struct feer_req *r);
#ifdef FEERSUM_HAS_H2
static SV* feersum_env_method_h2(pTHX_ struct feer_conn *c, struct feer_req *r);
#endif
static SV* feersum_env_uri(pTHX_ struct feer_req *r);
static SV* feersum_env_protocol(pTHX_ struct feer_req *r);
static void feersum_set_path_and_query(pTHX_ struct feer_req *r);
static HV* feersum_env(pTHX_ struct feer_conn *c);
static SV* feersum_env_path(pTHX_ struct feer_req *r);
static SV* feersum_env_query(pTHX_ struct feer_req *r);
static HV* feersum_env_headers(pTHX_ struct feer_req *r, int norm);
static SV* feersum_env_header(pTHX_ struct feer_req *r, SV* name);
static SV* feersum_env_addr(pTHX_ struct feer_conn *c);
static SV* feersum_env_port(pTHX_ struct feer_conn *c);
static ssize_t feersum_env_content_length(pTHX_ struct feer_conn *c);
static SV* feersum_env_io(pTHX_ struct feer_conn *c);
static SSize_t feersum_return_from_io(pTHX_ struct feer_conn *c, SV *io_sv, const char *func_name);
static void feersum_start_response(pTHX_ struct feer_conn *c, SV *message, AV *headers, int streaming);
static size_t feersum_write_whole_body (pTHX_ struct feer_conn *c, SV *body);
static void feersum_handle_psgi_response(pTHX_ struct feer_conn *c, SV *ret, bool can_recurse);
static int feersum_close_handle(pTHX_ struct feer_conn *c, bool is_writer);
static SV* feersum_conn_guard(pTHX_ struct feer_conn *c, SV *guard);

static void start_read_watcher(struct feer_conn *c);
static void stop_read_watcher(struct feer_conn *c);
static void restart_read_timer(struct feer_conn *c);
static void stop_read_timer(struct feer_conn *c);
static void start_write_watcher(struct feer_conn *c);
static void stop_write_watcher(struct feer_conn *c);
static void stop_all_watchers(struct feer_conn *c);
static void feer_conn_set_idle(struct feer_conn *c);
static void feer_conn_set_busy(struct feer_conn *c);
static int feer_server_recycle_idle_conn(struct feer_server *srvr);

static void try_conn_write(EV_P_ struct ev_io *w, int revents);
static void try_conn_read(EV_P_ struct ev_io *w, int revents);
static void conn_read_timeout(EV_P_ struct ev_timer *w, int revents);
static void conn_header_timeout(EV_P_ struct ev_timer *w, int revents);
static void conn_write_timeout(EV_P_ struct ev_timer *w, int revents);
static void restart_write_timer(struct feer_conn *c);
static void stop_write_timer(struct feer_conn *c);
static void stop_header_timer(struct feer_conn *c);
static void restart_header_timer(struct feer_conn *c);
static bool process_request_headers(struct feer_conn *c, int body_offset);
static int try_parse_chunked(struct feer_conn *c);
static void sched_request_callback(struct feer_conn *c);
static void call_died (pTHX_ struct feer_conn *c, const char *cb_type);
static void call_request_callback(struct feer_conn *c);
static void call_poll_callback (struct feer_conn *c, bool is_write);
static void pump_io_handle (struct feer_conn *c, SV *io);

static int parse_proxy_v1(struct feer_conn *c);
static int parse_proxy_v2(struct feer_conn *c);
static int try_parse_proxy_header(struct feer_conn *c);
static int try_parse_http(struct feer_conn *c, size_t last_read);
static void finish_receiving(struct feer_conn *c);

#ifdef FEERSUM_HAS_TLS
static void feer_tls_init_conn(struct feer_conn *c, struct feer_tls_ctx_ref *ref);
static void feer_tls_free_conn(struct feer_conn *c);
static int feer_tls_flush_wbuf(struct feer_conn *c);
static int feer_tls_send(struct feer_conn *c, const void *data, size_t len);
static void feer_tls_setup_tunnel(struct feer_conn *c);
static void try_tls_conn_read(EV_P_ ev_io *w, int revents);
static void try_tls_conn_write(EV_P_ ev_io *w, int revents);
static ptls_context_t * feer_tls_create_context(pTHX_ const char *cert_file, const char *key_file, int h2);
static void feer_tls_free_context(ptls_context_t *ctx);
static struct feer_tls_ctx_ref *feer_tls_ctx_ref_new(ptls_context_t *ctx);
static void feer_tls_ctx_ref_dec(struct feer_tls_ctx_ref *ref);
#ifdef FEERSUM_HAS_H2
static void drain_h2_tls_records(struct feer_conn *c);
#endif
static void tls_tunnel_sv0_read_cb(EV_P_ struct ev_io *w, int revents);
static void tls_tunnel_sv0_write_cb(EV_P_ struct ev_io *w, int revents);
static int tls_tunnel_write_or_buffer(struct feer_conn *c, const char *data, size_t len);
#endif

static void conn_write_ready (struct feer_conn *c);
static void respond_with_server_error(struct feer_conn *c, const char *msg, int code);
static void send_100_continue(struct feer_conn *c);
static void free_feer_req(struct feer_req *req);
static void free_request(struct feer_conn *c);

static void update_wbuf_placeholder(struct feer_conn *c, SV *sv, struct iovec *iov);
static STRLEN add_sv_to_wbuf (struct feer_conn *c, SV *sv);
static STRLEN add_const_to_wbuf (struct feer_conn *c, const char *str, size_t str_len);
#define add_crlf_to_wbuf(c) add_const_to_wbuf(c,CRLF,2)
static void finish_wbuf (struct feer_conn *c);
static void add_chunk_sv_to_wbuf (struct feer_conn *c, SV *sv);
static void add_placeholder_to_wbuf (struct feer_conn *c, SV **sv, struct iovec **iov_ref);

static void uri_decode_sv (SV *sv);
static bool str_case_eq_both(const char *a, const char *b, size_t len);
static bool str_case_eq_fixed(const char *a, const char *b, size_t len);

static void date_timer_cb(EV_P_ ev_timer *w, int revents);
// Buffer must be at least 42 bytes. Returns length written.
static int format_content_length(char *buf, size_t len);
static struct iomatrix * next_iomatrix (struct feer_conn *c);
static SV* new_feer_conn_handle (pTHX_ struct feer_conn *c, bool is_writer);
static struct feer_conn * new_feer_conn (EV_P_ int conn_fd, struct sockaddr *sa, socklen_t sa_len, struct feer_server *srvr, struct feer_listen *lsnr);
static struct feer_server * new_feer_server (pTHX);
static void prepare_cb (EV_P_ ev_prepare *w, int revents);
static void check_cb (EV_P_ ev_check *w, int revents);
static void idle_cb (EV_P_ ev_idle *w, int revents);
static int psgix_io_svt_get (pTHX_ SV *sv, MAGIC *mg);
static struct feer_server * sv_2feer_server (SV *rv);
static struct feer_conn * sv_2feer_conn (SV *rv);
static SV* feer_conn_2sv (struct feer_conn *c);
static SV* feer_server_2sv (struct feer_server *s);
static feer_conn_handle * sv_2feer_conn_handle (SV *rv, bool can_croak);

static void handle_keepalive_or_close(struct feer_conn *c, conn_read_cb_t read_cb);
static void safe_close_conn(struct feer_conn *c, const char *where);
static int prep_socket(int fd, int is_tcp);
static void set_cork(struct feer_conn *c, int cork);
static void feersum_init_psgi_env_constants(pTHX);
static HV* feersum_build_psgi_env(pTHX);
static SV* feer_determine_url_scheme(pTHX_ struct feer_conn *c);
static const char* find_header_value(struct feer_req *r, const char *name, size_t name_len, size_t *value_len);
static SV* extract_forwarded_addr(pTHX_ struct feer_req *r);
static SV* extract_forwarded_proto(pTHX_ struct feer_req *r);
static void feersum_start_psgi_streaming(pTHX_ struct feer_conn *c, SV *streamer);
static int feer_socketpair_nb(int sv[2]);
static SV* newSV_buf(STRLEN size);
static const char *http_code_to_msg (int code);
static void setup_accept_watcher(struct feer_listen *lsnr, int listen_fd);
static void init_feer_server (struct feer_server *s);
static void process_request_ready_rinq (struct feer_server *server);
static int setup_accepted_conn(EV_P_ int fd, struct sockaddr *sa, socklen_t sa_len, struct feer_server *srvr, struct feer_listen *lsnr);
static SV* fetch_av_normal (pTHX_ AV *av, I32 i);

#define FEER_REQ_ALLOC(r_) do { \
    extern struct feer_req *feer_req_freelist; \
    extern int feer_req_freelist_count; \
    if (feer_req_freelist != NULL) { \
        r_ = feer_req_freelist; \
        feer_req_freelist = *(struct feer_req **)feer_req_freelist; \
        feer_req_freelist_count--; \
        Zero(r_, 1, struct feer_req); \
    } else { \
        Newxz(r_, 1, struct feer_req); \
    } \
} while(0)

#define FEER_REQ_FREE(r_) do { \
    extern struct feer_req *feer_req_freelist; \
    extern int feer_req_freelist_count; \
    extern int FEERSUM_FREELIST_MAX; \
    if (feer_req_freelist_count < FEERSUM_FREELIST_MAX) { \
        *(struct feer_req **)(r_) = feer_req_freelist; \
        feer_req_freelist = (r_); \
        feer_req_freelist_count++; \
    } else { \
        Safefree(r_); \
    } \
} while(0)

#define IOMATRIX_ALLOC(m_) do { \
    extern struct iomatrix *iomatrix_freelist; \
    extern int iomatrix_freelist_count; \
    if (iomatrix_freelist != NULL) { \
        m_ = iomatrix_freelist; \
        iomatrix_freelist = *(struct iomatrix **)iomatrix_freelist; \
        iomatrix_freelist_count--; \
        Zero(m_->sv, FEERSUM_IOMATRIX_SIZE, SV*); \
    } else { \
        Newxz(m_, 1, struct iomatrix); \
    } \
} while(0)

#define IOMATRIX_FREE(m_) do { \
    extern struct iomatrix *iomatrix_freelist; \
    extern int iomatrix_freelist_count; \
    extern int FEERSUM_FREELIST_MAX; \
    if (iomatrix_freelist_count < FEERSUM_FREELIST_MAX) { \
        *(struct iomatrix **)(m_) = iomatrix_freelist; \
        iomatrix_freelist = (m_); \
        iomatrix_freelist_count++; \
    } else { \
        Safefree(m_); \
    } \
} while(0)

#endif /* FEERSUM_CORE_H */
