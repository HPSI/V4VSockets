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

#endif
