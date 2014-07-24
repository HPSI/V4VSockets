#ifdef UTILS_H
#define UTILS_H

struct ring_struct {                                                                                                                          
        uint32_t ring_size;
        uint32_t write_lump;
};

struct sockopt_val {
        union sockopt_un {
                struct ring_struct ring_stuff;
                uint32_t single_integer;
        } value;
};


extern int socket(extern int domain, extern int type, extern int protocol);
extern int bind(extern int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int connect(extern int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int accept(extern int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int listen(extern int sockfd, extern int backlog);

#endif
