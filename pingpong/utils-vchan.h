#ifndef UTILS_H
#define UTILS_H

struct socket_data {
	struct libxenvchan *ctrl;
	int datagram;
	int is_server;
	int magic;
	int real_socket_fd;
	uint32_t ring_size;
	char xs_path[100];
};

extern char *inet_ntoa(struct in_addr in);
//extern int socket(int domain, int type, int protocol);
//extern int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
//extern int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
//extern int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
//extern int listen(int sockfd, int backlog);

#endif
