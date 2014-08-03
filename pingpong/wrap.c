#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <errno.h>

#define __USE_GNU
#include <dlfcn.h>

#define MAX_SOCKETS 16		/* arbitrary constant */
#include "../driver/v4v.h"

/* Helper stuff to keep both socket descriptors and info about
 * AF_INET and AF_XEN.
 * FIXME: needs major cleanup and thread safe capabilities */

struct shadow_socket {
	int sockfd;
	int v4vsockfd;
	int acc_sockfd;
	uint8_t active;
};

struct socket_array {
	uint32_t counter;
	struct shadow_socket arr[MAX_SOCKETS];
};

void *array;			/* Our global array with socket structs */

/* Init our socket array */
int init_shadow_struct(void **dispatch)
{
	struct socket_array *sock_array;

	if (dispatch != NULL)
		if (*dispatch != NULL)
			return 0;

	printf("will init sock_array");
	//sock_array = malloc(sizeof(struct socket_array)  + sizeof(struct shadow_socket *) * MAX_SOCKETS); 
	sock_array = malloc(sizeof(struct socket_array));
	printf("  sock_array:%p\n", sock_array);

	sock_array->counter = 0;

	*dispatch = sock_array;

	return 0;
}

/* Upon a socket call, we keep both descriptors (even if 
 * we don't succeed to get a v4v one, and defer the decision
 * until the connect/accept call.
 * This function adds the socket to our static array.
 */
int add_shadow_struct(void *dispatch, struct shadow_socket *sock)
{
	struct socket_array *socket_arr;
	struct shadow_socket *shadow_sock;
	int cnt;
	socket_arr = dispatch;
	printf("will add socket:%d, %d to sock_array:%p\n", sock->sockfd,
	       sock->v4vsockfd, socket_arr);
	cnt = socket_arr->counter;
	shadow_sock = &socket_arr->arr[cnt];
	shadow_sock->sockfd = sock->sockfd;
	shadow_sock->v4vsockfd = sock->v4vsockfd;
	shadow_sock->acc_sockfd = 0;
	shadow_sock->active = 0;
	socket_arr->counter++;
	printf("sock_array:%p counter:%d\n", socket_arr, socket_arr->counter);

	return 0;
}

/* Return the socket struct to choose between AF_INET and AF_XEN */
int get_shadow_struct(void *dispatch, int sockfd, struct shadow_socket **sock)
{
	struct socket_array *socket_arr;
	uint32_t counter = 0, end;
	socket_arr = dispatch;
	end = socket_arr->counter;
	while (counter < end) {
		if (socket_arr->arr[counter].sockfd == sockfd
		    || socket_arr->arr[counter].acc_sockfd == sockfd)
			break;
		counter++;
	}

	if (counter != end) {
		*sock = &socket_arr->arr[counter];
		return 0;
	}
	*sock = NULL;
	return -1;
}

/* Macaroni code to actually call both AF_INET and XEN until we succeed to
 * connect FIXME: needs major cleanup and thread safe capabilities */
int socket(int domain, int type, int protocol)
{
	static int (*socket_real) (int, int, int) = NULL;
	int ret, v4vret;
	int domain_real = domain;
	int protocol_real = protocol;
	struct shadow_socket *sock;

	if (!socket_real)
		socket_real = dlsym(RTLD_NEXT, "socket");
	init_shadow_struct(&array);

	/* Try creating a v4vsocket */
	domain = AF_XEN;
	v4vret = socket_real(domain, type, protocol);
	if (v4vret < 0) {
		fprintf(stderr, "shadow socket() %d\n", v4vret);
		goto normal;
		//domain=domain_real;
	}

normal:
	/* Continue creating a normal socket */
	domain = domain_real;
	protocol = protocol_real;
	ret = socket_real(domain, type, protocol);
	if (ret < 0) {
		fprintf(stderr, "Error creating socket with AF:%d\n",
			domain_real);
		return -1;
	}
	sock = malloc(sizeof(struct shadow_socket));
	sock->sockfd = ret;
	sock->v4vsockfd = v4vret;
	printf("adding:%d, %d\n", ret, add_shadow_struct(array, sock));
	sock->active = 0;

	//return ret < 0 ? socket_real(domain,type,protocol) : ret;

	//if (getenv("WRAP_DEBUG"))
	//    fprintf(stderr,"socket_debug() %d\n", domain);

	return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	static int (*bind_real) (int, const struct sockaddr *, socklen_t) =
	    NULL;
	int ret, v4vret;
	struct shadow_socket *sock;

	if (!bind_real)
		bind_real = dlsym(RTLD_NEXT, "bind");

	ret = get_shadow_struct(array, sockfd, &sock);
	if (ret < 0) {
		//fprintf(stderr, "failed to get shadow struct\n");
		goto out;
	}
	v4vret = bind_real(sock->v4vsockfd, addr, addrlen);
	if (v4vret < 0) {
		//fprintf(stderr, "failed to bind sock with fd:%d, ret:%d\n",
		//      sock->v4vsockfd, v4vret);
		goto normal;
	}
normal:
	ret = bind_real(sock->sockfd, addr, addrlen);
	if (ret < 0) {
		//fprintf(stderr, "failed to bind sock with fd:%d, ret:%d\n",
		//      sock->sockfd, ret);
		goto out;
	}

out:
	return ret;

}

int listen(int sockfd, int backlog)
{
	static int (*listen_real) (int, int) = NULL;
	int ret, v4vret;
	struct shadow_socket *sock;
	if (!listen_real)
		listen_real = dlsym(RTLD_NEXT, "listen");

	ret = get_shadow_struct(array, sockfd, &sock);
	if (ret < 0) {
		fprintf(stderr, "failed to get shadow struct\n");
		goto out;
	}
	v4vret = listen_real(sock->v4vsockfd, backlog);
	if (v4vret < 0) {
		//fprintf(stderr, "failed to listen with fd:%d, ret:%d\n",
		//      sock->v4vsockfd, v4vret);
		goto normal;
	}
normal:
	ret = listen_real(sock->sockfd, backlog);
	if (ret < 0) {
		//fprintf(stderr, "failed to listen with fd:%d, ret:%d\n",
		//      sock->sockfd, ret);
		goto out;
	}

out:
	return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t * addrlen)
{
	static int (*accept_real) (int, const struct sockaddr *, socklen_t *) =
	    NULL;
	int ret, v4vret;
	struct shadow_socket *sock;

	if (!accept_real)
		accept_real = dlsym(RTLD_NEXT, "accept");

	ret = get_shadow_struct(array, sockfd, &sock);
	if (ret < 0) {
		//fprintf(stderr, "failed to get shadow struct\n");
		goto out;
	}
	v4vret = accept_real(sock->v4vsockfd, addr, addrlen);
	if (v4vret < 0) {
		//fprintf(stderr, "failed to accept sock with fd:%d, ret:%d\n",
		//      sock->v4vsockfd, v4vret);
		goto normal;
	}
	sock->active = 1;
	sock->acc_sockfd = v4vret;
	ret = v4vret;
	goto out;
normal:
/* lets try this approach first -- after all the server listens to whatever interface there is */
#if 1
	ret = accept_real(sock->sockfd, addr, addrlen);
	if (ret < 0) {
		//fprintf(stderr, "failed to accept sock with fd:%d, ret:%d\n",
		//      sock->sockfd, ret);
		goto out;
	}
	sock->acc_sockfd = ret;
#endif
	printf("accepted_socket:%d\n", ret);

out:
	return ret;

}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	static int (*connect_real) (int, const struct sockaddr *, socklen_t) =
	    NULL;
	int ret, v4vret;
	struct shadow_socket *sock;
	struct sockaddr_in addr_in;

	if (!connect_real)
		connect_real = dlsym(RTLD_NEXT, "connect");

	ret = get_shadow_struct(array, sockfd, &sock);
	if (ret < 0) {
		fprintf(stderr, "failed to get shadow struct\n");
		goto out;
	}
	v4vret = connect_real(sock->v4vsockfd, addr, addrlen);
	if (!v4vret) {
		/* Success!!! */
		sock->active = 1;
		ret = v4vret;
		goto out;
	}
	//fprintf(stderr, "will continue with normal sockets\n");
	//ret = connect_real(sockfd, addr, addrlen);
	ret = connect_real(sock->sockfd, addr, addrlen);
	if (ret < 0) {
		goto out;
	}

out:
	return ret;

}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr * src_addr, socklen_t * addrlen)
{
	static int (*recvfrom_real) (int, const void *, size_t, int,
				     const struct sockaddr *, socklen_t *) =
	    NULL;
	struct shadow_socket *sock;
	int ret = -1;
	int real_sock;
	if (!recvfrom_real)
		recvfrom_real = dlsym(RTLD_NEXT, "recvfrom");

	ret = get_shadow_struct(array, sockfd, &sock);
	if (ret < 0) {
		fprintf(stderr, "failed to get shadow struct\n");
		goto out;
	}

	if (sock->active == 1) {
		real_sock = sock->v4vsockfd;
		if (sock->acc_sockfd)
			real_sock = sock->acc_sockfd;
	} else {
		real_sock = sock->sockfd;
		if (sock->acc_sockfd)
			real_sock = sock->acc_sockfd;
	}

	ret = recvfrom_real(real_sock, buf, len, flags, src_addr, addrlen);
out:
	return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr * dest_addr, socklen_t addrlen)
{
	static int (*sendto_real) (int, const void *, size_t, int,
				   const struct sockaddr *, socklen_t) = NULL;
	struct shadow_socket *sock;
	int real_sock;
	int ret = -1;
	if (!sendto_real)
		sendto_real = dlsym(RTLD_NEXT, "sendto");

	ret = get_shadow_struct(array, sockfd, &sock);
	if (ret < 0) {
		fprintf(stderr, "failed to get shadow struct\n");
		goto out;
	}

	if (sock->active == 1) {
		real_sock = sock->v4vsockfd;
		if (sock->acc_sockfd)
			real_sock = sock->acc_sockfd;
	}

	else {
		real_sock = sock->sockfd;
		if (sock->acc_sockfd)
			real_sock = sock->acc_sockfd;
	}

	ret = sendto_real(real_sock, buf, len, flags, dest_addr, addrlen);
out:
	return ret;
}
