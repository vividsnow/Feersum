provider feersum {
    probe conn_new(int fd, const char *addr, int port);
    probe conn_free(int fd);
    probe req_new(int fd, const char *method, const char *uri);
    probe req_body(int fd, size_t len);
    probe resp_start(int fd, int code);
    probe trace(int level, const char *message);
};
