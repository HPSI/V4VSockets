#ifdef UTILS_H
#define UTILS_H

extern int socket(extern int domain, extern int type, extern int protocol);
extern int bind(extern int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int connect(extern int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int accept(extern int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int listen(extern int sockfd, extern int backlog);

#endif
