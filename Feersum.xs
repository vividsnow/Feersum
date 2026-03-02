#include "EVAPI.h"

#include "feersum_core.h"
#include "picohttpparser-git/picohttpparser.c"

#include "rinq.c"

#include "feersum_core.c.inc"
#include "feersum_utils.c.inc"
#include "feersum_h1.c.inc"
#include "feersum_psgi.c.inc"

#ifdef FEERSUM_HAS_TLS
#include "feersum_tls.c.inc"
#endif
#ifdef FEERSUM_HAS_H2
#include "feersum_h2.c.inc"
#endif

MODULE = Feersum                PACKAGE = Feersum

PROTOTYPES: ENABLE

SV *
_xs_new_server(SV *classname)
    CODE:
{
    PERL_UNUSED_VAR(classname);
    struct feer_server *s = new_feer_server(aTHX);
    RETVAL = feer_server_2sv(s);
}
    OUTPUT:
        RETVAL

SV *
_xs_default_server(SV *classname)
    CODE:
{
    PERL_UNUSED_VAR(classname);
    RETVAL = feer_server_2sv(default_server);
}
    OUTPUT:
        RETVAL

void
set_server_name_and_port(struct feer_server *server, SV *name, SV *port)
    PPCODE:
{
    struct feer_listen *lsnr = &server->listeners[server->n_listeners > 0 ? server->n_listeners - 1 : 0];
    if (lsnr->server_name)
        SvREFCNT_dec(lsnr->server_name);
    lsnr->server_name = newSVsv(name);
    SvREADONLY_on(lsnr->server_name);

    if (lsnr->server_port)
        SvREFCNT_dec(lsnr->server_port);
    lsnr->server_port = newSVsv(port);
    SvREADONLY_on(lsnr->server_port);
}

void
accept_on_fd(struct feer_server *server, int fd)
    PPCODE:
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    struct feer_listen *lsnr;

    // Determine which listener slot to use
    if (server->n_listeners == 0) {
        lsnr = &server->listeners[0];
        server->n_listeners = 1;
    } else {
        // Look for an unused slot (fd == -1) to reuse
        int j;
        lsnr = NULL;
        for (j = 0; j < server->n_listeners; j++) {
            if (server->listeners[j].fd == -1) {
                lsnr = &server->listeners[j];
#ifdef FEERSUM_HAS_TLS
                if (lsnr->tls_ctx_ref) {
                    feer_tls_ctx_ref_dec(lsnr->tls_ctx_ref);
                    lsnr->tls_ctx_ref = NULL;
                }
#endif
                break;
            }
        }
        if (!lsnr) {
            if (server->n_listeners < FEER_MAX_LISTENERS) {
                lsnr = &server->listeners[server->n_listeners];
                // Initialize new listener slot
                Zero(lsnr, 1, struct feer_listen);
                lsnr->server = server;
                lsnr->fd = -1;
                lsnr->is_tcp = 1;
#ifdef __linux__
                lsnr->epoll_fd = -1;
#endif
                server->n_listeners++;
            } else {
                croak("Too many listeners (max %d)", FEER_MAX_LISTENERS);
            }
        }
    }

    // Zero addr to ensure safe defaults if getsockname fails
    Zero(&addr, 1, struct sockaddr_storage);
    if (getsockname(fd, (struct sockaddr*)&addr, &addr_len) == -1) {
        // Log error but continue with safe default (AF_INET assumed)
        // This allows the server to function even if getsockname fails
        warn("getsockname failed: %s (assuming TCP socket)", strerror(errno));
        addr.ss_family = AF_INET;
    }
    switch (addr.ss_family) {
        case AF_INET:
        case AF_INET6:
            lsnr->is_tcp = 1;
#ifdef TCP_DEFER_ACCEPT
            trace("going to defer accept on %d\n",fd);
            if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &(int){1}, sizeof(int)) < 0)
                trouble("setsockopt TCP_DEFER_ACCEPT fd=%d: %s\n", fd, strerror(errno));
#endif
            break;
#ifdef AF_UNIX
        case AF_UNIX:
            lsnr->is_tcp = 0;
            break;
#endif
    }

    trace("going to accept on %d\n",fd);
    feersum_ev_loop = EV_DEFAULT;
    lsnr->fd = fd;

    signal(SIGPIPE, SIG_IGN);

    // Only init per-server watchers once (on first listener)
    if (!server->watchers_initialized) {
        server->watchers_initialized = true;

        ev_prepare_init(&server->ep, prepare_cb);
        server->ep.data = (void *)server;
        ev_prepare_start(feersum_ev_loop, &server->ep);

        ev_check_init(&server->ec, check_cb);
        server->ec.data = (void *)server;
        ev_check_start(feersum_ev_loop, &server->ec);

        ev_idle_init(&server->ei, idle_cb);
        server->ei.data = (void *)server;

        date_timer_refs++;
    } else if (!ev_is_active(&server->ep)) {
        // Re-arm prepare watcher for runtime listener addition
        ev_prepare_start(feersum_ev_loop, &server->ep);
    }

    // Initialize date header and start periodic timer (1 second interval)
    // Shared across all servers - only start once
    if (!ev_is_active(&date_timer)) {
        date_timer_cb(feersum_ev_loop, &date_timer, 0);  // initial update
        ev_timer_init(&date_timer, date_timer_cb, 1.0, 1.0);
        ev_timer_start(feersum_ev_loop, &date_timer);
    }

    setup_accept_watcher(lsnr, fd);
}

void
unlisten (struct feer_server *server)
    PPCODE:
{
    int i;
    trace("stopping accept\n");
    ev_prepare_stop(feersum_ev_loop, &server->ep);
    ev_check_stop(feersum_ev_loop, &server->ec);
    ev_idle_stop(feersum_ev_loop, &server->ei);
    for (i = 0; i < server->n_listeners; i++) {
        struct feer_listen *lsnr = &server->listeners[i];
        ev_io_stop(feersum_ev_loop, &lsnr->accept_w);
#ifdef __linux__
        if (lsnr->epoll_fd >= 0) {
            if (unlikely(close(lsnr->epoll_fd) < 0))
                trouble("close(epoll_fd) fd=%d: %s\n", lsnr->epoll_fd, strerror(errno));
            lsnr->epoll_fd = -1;
        }
#endif
        lsnr->fd = -1;
        lsnr->paused = 0;
    }
    if (--date_timer_refs <= 0) {
        ev_timer_stop(feersum_ev_loop, &date_timer);
        date_timer_refs = 0;
    }
}

void
pause_accept (struct feer_server *server)
    PPCODE:
{
    int i;
    if (server->shutting_down) {
        trace("cannot pause during shutdown\n");
        XSRETURN_NO;
    }
    int paused_any = 0;
    for (i = 0; i < server->n_listeners; i++) {
        struct feer_listen *lsnr = &server->listeners[i];
        if (!lsnr->paused && ev_is_active(&lsnr->accept_w)) {
            trace("pausing accept on listener %d\n", i);
            ev_io_stop(feersum_ev_loop, &lsnr->accept_w);
            lsnr->paused = 1;
            paused_any = 1;
        }
    }
    if (paused_any)
        XSRETURN_YES;
    else
        XSRETURN_NO;
}

void
resume_accept (struct feer_server *server)
    PPCODE:
{
    int i;
    if (server->shutting_down) {
        trace("cannot resume during shutdown\n");
        XSRETURN_NO;
    }
    int resumed_any = 0;
    for (i = 0; i < server->n_listeners; i++) {
        struct feer_listen *lsnr = &server->listeners[i];
        if (lsnr->paused) {
            trace("resuming accept on listener %d\n", i);
            ev_io_start(feersum_ev_loop, &lsnr->accept_w);
            lsnr->paused = 0;
            resumed_any = 1;
        }
    }
    if (resumed_any)
        XSRETURN_YES;
    else
        XSRETURN_NO;
}

bool
accept_is_paused (struct feer_server *server)
    CODE:
    {
        int i;
        RETVAL = (server->n_listeners > 0);
        for (i = 0; i < server->n_listeners; i++) {
            if (!server->listeners[i].paused) { RETVAL = 0; break; }
        }
    }
    OUTPUT:
        RETVAL

void
request_handler(struct feer_server *server, SV *cb)
    PROTOTYPE: $&
    ALIAS:
        psgi_request_handler = 1
    PPCODE:
{
    if (unlikely(!SvOK(cb) || !SvROK(cb)))
        croak("can't supply an undef handler");
    if (server->request_cb_cv)
        SvREFCNT_dec(server->request_cb_cv);
    server->request_cb_cv = newSVsv(cb);
    server->request_cb_is_psgi = ix;
    trace("assigned %s request handler %p\n",
        server->request_cb_is_psgi?"PSGI":"Feersum", server->request_cb_cv);
}

void
graceful_shutdown (struct feer_server *server, SV *cb)
    PROTOTYPE: $&
    PPCODE:
{
    int i;
    if (!IsCodeRef(cb))
        croak("must supply a code reference");
    if (unlikely(server->shutting_down))
        croak("already shutting down");
    server->shutdown_cb_cv = newSVsv(cb);
    trace("shutting down, handler=%p, active=%d\n", SvRV(cb), server->active_conns);

    server->shutting_down = 1;
    for (i = 0; i < server->n_listeners; i++) {
        struct feer_listen *lsnr = &server->listeners[i];
        ev_io_stop(feersum_ev_loop, &lsnr->accept_w);
#ifdef __linux__
        if (lsnr->epoll_fd >= 0) {
            if (unlikely(close(lsnr->epoll_fd) < 0))
                trouble("close(epoll_fd) fd=%d: %s\n", lsnr->epoll_fd, strerror(errno));
            lsnr->epoll_fd = -1;
            // In epoll_exclusive mode, accept_w.fd is the epoll fd (now closed)
            // We still need to close the actual listen socket
            if (lsnr->fd >= 0) {
                if (unlikely(close(lsnr->fd) < 0))
                    trouble("close(listen fd) fd=%d: %s\n", lsnr->fd, strerror(errno));
                lsnr->fd = -1;
            }
        } else
#endif
        {
            if (lsnr->accept_w.fd >= 0) {
                if (unlikely(close(lsnr->accept_w.fd) < 0))
                    trouble("close(accept_w.fd) fd=%d: %s\n", lsnr->accept_w.fd, strerror(errno));
                ev_io_set(&lsnr->accept_w, -1, EV_READ);
                lsnr->fd = -1;
            }
        }
    }

    /* Close idle keepalive connections — they won't get new requests */
    while (feer_server_recycle_idle_conn(server))
        ;

    if (server->active_conns <= 0) {
        trace("shutdown is immediate\n");
        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        call_sv(server->shutdown_cb_cv, G_EVAL|G_VOID|G_DISCARD|G_NOARGS);
        PUTBACK;
        trace3("called shutdown handler\n");
        if (SvTRUE(ERRSV))
            sv_setsv(ERRSV, &PL_sv_undef);
        SvREFCNT_dec(server->shutdown_cb_cv);
        server->shutdown_cb_cv = NULL;
        FREETMPS;
        LEAVE;
    }
}

double
read_timeout (struct feer_server *server, ...)
    PROTOTYPE: $;$
    PREINIT:
        double new_read_timeout = 0.0;
    CODE:
{
    if (items > 1) {
        new_read_timeout = SvNV(ST(1));
        if (!(new_read_timeout > 0.0)) {
            croak("must set a positive (non-zero) value for the timeout");
        }
        trace("set timeout %f\n", new_read_timeout);
        server->read_timeout = new_read_timeout;
    }
    RETVAL = server->read_timeout;
}
    OUTPUT:
        RETVAL

double
header_timeout (struct feer_server *server, ...)
    PROTOTYPE: $;$
    PREINIT:
        double new_header_timeout = 0.0;
    CODE:
{
    if (items > 1) {
        new_header_timeout = SvNV(ST(1));
        if (new_header_timeout < 0.0) {
            croak("header_timeout must be non-negative (0 to disable)");
        }
        trace("set header_timeout %f (Slowloris protection)\n", new_header_timeout);
        server->header_timeout = new_header_timeout;
    }
    RETVAL = server->header_timeout;
}
    OUTPUT:
        RETVAL

double
write_timeout (struct feer_server *server, ...)
    PROTOTYPE: $;$
    CODE:
{
    if (items > 1) {
        double new_write_timeout = SvNV(ST(1));
        if (new_write_timeout < 0.0) {
            croak("write_timeout must be non-negative (0 to disable)");
        }
        trace("set write_timeout %f\n", new_write_timeout);
        server->write_timeout = new_write_timeout;
    }
    RETVAL = server->write_timeout;
}
    OUTPUT:
        RETVAL

void
set_keepalive (struct feer_server *server, SV *set)
    PPCODE:
{
    trace("set keepalive %d\n", SvTRUE(set));
    server->is_keepalive = SvTRUE(set);
}

void
set_reverse_proxy (struct feer_server *server, SV *set)
    PPCODE:
{
    trace("set reverse_proxy %d\n", SvTRUE(set));
    server->use_reverse_proxy = SvTRUE(set);
}

int
get_reverse_proxy (struct feer_server *server)
    CODE:
{
    RETVAL = server->use_reverse_proxy;
}
    OUTPUT:
        RETVAL

void
set_proxy_protocol (struct feer_server *server, SV *set)
    PPCODE:
{
    trace("set proxy_protocol %d\n", SvTRUE(set));
    server->use_proxy_protocol = SvTRUE(set);
}

int
get_proxy_protocol (struct feer_server *server)
    CODE:
{
    RETVAL = server->use_proxy_protocol;
}
    OUTPUT:
        RETVAL

void
set_epoll_exclusive (struct feer_server *server, SV *set)
    PPCODE:
{
#if defined(__linux__) && defined(EPOLLEXCLUSIVE)
    trace("set epoll_exclusive %d (native mode)\n", SvTRUE(set));
    server->use_epoll_exclusive = SvTRUE(set) ? 1 : 0;
#else
    PERL_UNUSED_VAR(server);
    if (SvTRUE(set))
        warn("EPOLLEXCLUSIVE is not available (requires Linux 4.5+)");
#endif
}

int
get_epoll_exclusive (struct feer_server *server)
    CODE:
{
#if defined(__linux__) && defined(EPOLLEXCLUSIVE)
    RETVAL = server->use_epoll_exclusive ? 1 : 0;
#else
    PERL_UNUSED_VAR(server);
    RETVAL = 0;
#endif
}
    OUTPUT:
        RETVAL

int
read_priority (struct feer_server *server, ...)
    ALIAS:
        write_priority = 1
        accept_priority = 2
    PROTOTYPE: $;$
    CODE:
{
    static const char *names[] = {"read", "write", "accept"};
    int *field = ix == 2 ? &server->accept_priority
               : ix == 1 ? &server->write_priority
               :           &server->read_priority;
    if (items > 1) {
        int new_priority = SvIV(ST(1));
        if (new_priority < EV_MINPRI) new_priority = EV_MINPRI;
        if (new_priority > EV_MAXPRI) new_priority = EV_MAXPRI;
        trace("set %s_priority %d\n", names[ix], new_priority);
        *field = new_priority;
    }
    RETVAL = *field;
}
    OUTPUT:
        RETVAL

int
max_accept_per_loop (struct feer_server *server, ...)
    PROTOTYPE: $;$
    CODE:
{
    if (items > 1) {
        int new_max = SvIV(ST(1));
        if (new_max < 1) new_max = 1;
        trace("set max_accept_per_loop %d\n", new_max);
        server->max_accept_per_loop = new_max;
    }
    RETVAL = server->max_accept_per_loop;
}
    OUTPUT:
        RETVAL

int
active_conns (struct feer_server *server)
    CODE:
        RETVAL = server->active_conns;
    OUTPUT:
        RETVAL

int
max_connections (struct feer_server *server, ...)
    PROTOTYPE: $;$
    CODE:
{
    if (items > 1) {
        int new_max = SvIV(ST(1));
        if (new_max < 0) new_max = 0;  // 0 means unlimited
        trace("set max_connections %d\n", new_max);
        server->max_connections = new_max;
    }
    RETVAL = server->max_connections;
}
    OUTPUT:
        RETVAL

size_t
max_read_buf (struct feer_server *server, ...)
    PROTOTYPE: $;$
    CODE:
{
    if (items > 1) {
        size_t new_max = SvUV(ST(1));
        if (new_max == 0) new_max = MAX_READ_BUF;
        server->max_read_buf = new_max;
    }
    RETVAL = server->max_read_buf;
}
    OUTPUT:
        RETVAL

size_t
max_body_len (struct feer_server *server, ...)
    PROTOTYPE: $;$
    CODE:
{
    if (items > 1) {
        size_t new_max = SvUV(ST(1));
        if (new_max == 0) new_max = MAX_BODY_LEN;
        server->max_body_len = new_max;
    }
    RETVAL = server->max_body_len;
}
    OUTPUT:
        RETVAL

size_t
max_uri_len (struct feer_server *server, ...)
    PROTOTYPE: $;$
    CODE:
{
    if (items > 1) {
        size_t new_max = SvUV(ST(1));
        if (new_max == 0) new_max = MAX_URI_LEN;
        server->max_uri_len = new_max;
    }
    RETVAL = server->max_uri_len;
}
    OUTPUT:
        RETVAL

size_t
wbuf_low_water (struct feer_server *server, ...)
    PROTOTYPE: $;$
    CODE:
{
    if (items > 1) {
        SV *val = ST(1);
        if (SvNV(val) < 0.0)
            croak("wbuf_low_water must be non-negative");
        server->wbuf_low_water = SvUV(val);
    }
    RETVAL = server->wbuf_low_water;
}
    OUTPUT:
        RETVAL

UV
total_requests (struct feer_server *server)
    CODE:
        RETVAL = server->total_requests;
    OUTPUT:
        RETVAL

unsigned int
max_connection_reqs (struct feer_server *server, ...)
    PROTOTYPE: $;$
    PREINIT:
        IV new_max_connection_reqs = 0;
    CODE:
{
    if (items > 1) {
        new_max_connection_reqs = SvIV(ST(1));
        if (new_max_connection_reqs < 0) {
            croak("must set a non-negative value (0 for unlimited)");
        }
        trace("set max requests per connection %u\n", (unsigned int)new_max_connection_reqs);
        server->max_connection_reqs = (unsigned int)new_max_connection_reqs;
    }
    RETVAL = server->max_connection_reqs;
}
    OUTPUT:
        RETVAL

void
_xs_destroy (struct feer_server *server)
    PPCODE:
{
    int i;
    trace3("DESTROY server\n");
    if (server->request_cb_cv)
        SvREFCNT_dec(server->request_cb_cv);
    if (server->shutdown_cb_cv)
        SvREFCNT_dec(server->shutdown_cb_cv);
    for (i = 0; i < server->n_listeners; i++) {
        struct feer_listen *lsnr = &server->listeners[i];
        if (lsnr->server_name)
            SvREFCNT_dec(lsnr->server_name);
        if (lsnr->server_port)
            SvREFCNT_dec(lsnr->server_port);
#ifdef FEERSUM_HAS_TLS
        if (lsnr->tls_ctx_ref) {
            feer_tls_ctx_ref_dec(lsnr->tls_ctx_ref);
            lsnr->tls_ctx_ref = NULL;
        }
#endif
    }
}

void
set_tls (struct feer_server *server, ...)
    PPCODE:
{
#ifdef FEERSUM_HAS_TLS
    const char *cert_file = NULL;
    const char *key_file = NULL;
    int listener_idx = -1; /* -1 means last-added listener (default) */
    int h2 = 0;
    int i;

    if (items < 3 || (items - 1) % 2 != 0)
        croak("set_tls requires key => value pairs (cert_file => $path, key_file => $path)");

    for (i = 1; i < items; i += 2) {
        const char *key = SvPV_nolen(ST(i));
        SV *val = ST(i + 1);
        if (strcmp(key, "cert_file") == 0)
            cert_file = SvPV_nolen(val);
        else if (strcmp(key, "key_file") == 0)
            key_file = SvPV_nolen(val);
        else if (strcmp(key, "listener") == 0)
            listener_idx = SvIV(val);
        else if (strcmp(key, "h2") == 0)
            h2 = SvTRUE(val) ? 1 : 0;
        else
            croak("set_tls: unknown option '%s'", key);
    }

    if (!cert_file) croak("set_tls: cert_file is required");
    if (!key_file)  croak("set_tls: key_file is required");

    if (server->n_listeners == 0)
        croak("set_tls: no listeners configured (call use_socket/accept_on_fd first)");

    /* Resolve listener index */
    if (listener_idx < -1)
        croak("set_tls: listener index %d out of range (0..%d or -1)",
              listener_idx, server->n_listeners - 1);
    if (listener_idx < 0)
        listener_idx = server->n_listeners - 1;
    if (listener_idx >= server->n_listeners)
        croak("set_tls: listener index %d out of range (0..%d)",
              listener_idx, server->n_listeners - 1);

    struct feer_listen *lsnr = &server->listeners[listener_idx];
    if (lsnr->tls_ctx_ref) {
        feer_tls_ctx_ref_dec(lsnr->tls_ctx_ref);
        lsnr->tls_ctx_ref = NULL;
    }

    ptls_context_t *new_ctx = feer_tls_create_context(aTHX_ cert_file, key_file, h2);
    if (!new_ctx)
        croak("set_tls: failed to create TLS context");
    lsnr->tls_ctx_ref = feer_tls_ctx_ref_new(new_ctx);

    trace("TLS enabled on listener %d (h2=%d)\n", listener_idx, h2);
#else
    PERL_UNUSED_VAR(server);
    croak("set_tls: Feersum was not compiled with TLS support (need picotls submodule + OpenSSL; see Alien::OpenSSL)");
#endif
}

int
has_tls (struct feer_server *server)
    CODE:
{
    PERL_UNUSED_VAR(server);
#ifdef FEERSUM_HAS_TLS
    RETVAL = 1;
#else
    RETVAL = 0;
#endif
}
    OUTPUT:
        RETVAL

int
has_h2 (struct feer_server *server)
    CODE:
{
    PERL_UNUSED_VAR(server);
#ifdef FEERSUM_HAS_H2
    RETVAL = 1;
#else
    RETVAL = 0;
#endif
}
    OUTPUT:
        RETVAL

BOOT:
    {
        feer_stash = gv_stashpv("Feersum", 1);
        feer_conn_stash = gv_stashpv("Feersum::Connection", 1);
        feer_conn_writer_stash = gv_stashpv("Feersum::Connection::Writer",1);
        feer_conn_reader_stash = gv_stashpv("Feersum::Connection::Reader",1);
        I_EV_API("Feersum");

        const char *env_fl_max = getenv("FEERSUM_FREELIST_MAX");
        if (env_fl_max) {
            FEERSUM_FREELIST_MAX = atoi(env_fl_max);
        }

        // Allocate default server (backed by a blessed Perl SV)
        default_server = new_feer_server(aTHX);
        // Keep an extra refcount so the default server is never GC'd
        SvREFCNT_inc_void_NN(default_server->self);

        psgi_ver = newAV();
        av_extend(psgi_ver, 1);  // pre-allocate for 2 elements (psgi.version = [1, 1])
        av_push(psgi_ver, newSViv(1));
        av_push(psgi_ver, newSViv(1));
        SvREADONLY_on((SV*)psgi_ver);

        psgi_serv10 = newSVpvs("HTTP/1.0");
        SvREADONLY_on(psgi_serv10);
        psgi_serv11 = newSVpvs("HTTP/1.1");
        SvREADONLY_on(psgi_serv11);

        method_GET = newSVpvs("GET");
        SvREADONLY_on(method_GET);
        method_POST = newSVpvs("POST");
        SvREADONLY_on(method_POST);
        method_HEAD = newSVpvs("HEAD");
        SvREADONLY_on(method_HEAD);
        method_PUT = newSVpvs("PUT");
        SvREADONLY_on(method_PUT);
        method_PATCH = newSVpvs("PATCH");
        SvREADONLY_on(method_PATCH);
        method_DELETE = newSVpvs("DELETE");
        SvREADONLY_on(method_DELETE);
        method_OPTIONS = newSVpvs("OPTIONS");
        SvREADONLY_on(method_OPTIONS);

        status_200 = newSVpvs("200 OK");
        SvREADONLY_on(status_200);
        status_201 = newSVpvs("201 Created");
        SvREADONLY_on(status_201);
        status_204 = newSVpvs("204 No Content");
        SvREADONLY_on(status_204);
        status_301 = newSVpvs("301 Moved Permanently");
        SvREADONLY_on(status_301);
        status_302 = newSVpvs("302 Found");
        SvREADONLY_on(status_302);
        status_304 = newSVpvs("304 Not Modified");
        SvREADONLY_on(status_304);
        status_400 = newSVpvs("400 Bad Request");
        SvREADONLY_on(status_400);
        status_404 = newSVpvs("404 Not Found");
        SvREADONLY_on(status_404);
        status_500 = newSVpvs("500 Internal Server Error");
        SvREADONLY_on(status_500);

        empty_query_sv = newSVpvs("");
        SvREADONLY_on(empty_query_sv);

        Zero(&psgix_io_vtbl, 1, MGVTBL);
        psgix_io_vtbl.svt_get = psgix_io_svt_get;
        newCONSTSUB(feer_stash, "HEADER_NORM_SKIP", newSViv(HEADER_NORM_SKIP));
        newCONSTSUB(feer_stash, "HEADER_NORM_UPCASE", newSViv(HEADER_NORM_UPCASE));
        newCONSTSUB(feer_stash, "HEADER_NORM_LOCASE", newSViv(HEADER_NORM_LOCASE));
        newCONSTSUB(feer_stash, "HEADER_NORM_UPCASE_DASH", newSViv(HEADER_NORM_UPCASE_DASH));
        newCONSTSUB(feer_stash, "HEADER_NORM_LOCASE_DASH", newSViv(HEADER_NORM_LOCASE_DASH));

        trace3("Feersum booted, iomatrix %lu, FEERSUM_IOMATRIX_SIZE=%u, "
            "feer_req %lu, feer_conn %lu\n",
            (long unsigned int)sizeof(struct iomatrix),
            (unsigned int)FEERSUM_IOMATRIX_SIZE,
            (long unsigned int)sizeof(struct feer_req),
            (long unsigned int)sizeof(struct feer_conn)
        );
    }

INCLUDE: feersum_conn.xs
