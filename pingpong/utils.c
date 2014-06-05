#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include "v4v.h"


uint32_t ring_size;
int dgram = 0;
v4v_ring_id_t my_ring;
v4v_addr_t peer;

unsigned long inet_addr(char *cp) {
	int ret = -1;
	if(!strcmp(cp,"192.168.129.2"))
		ret = 1;
	if(!strcmp(cp,"192.168.129.3"))
		ret = 2;
	return ret;
}

int socket(int domain, int type, int protocol) {
	int flags = O_RDWR;
	int fd = -1;
	int ret = 0;
	uint32_t real_ring_size;

		ring_size = protocol ? protocol: 64 * 1024;
		if (type == SOCK_STREAM) {
			//real_ring_size = (uint32_t) V4V_ROUNDUP(protocol + 92);
			real_ring_size = ring_size;
			fd = open("/dev/v4v_stream", flags);
		}
		else { 
			dgram = 1;
			fd = open("/dev/v4v_dgram", flags);
			//real_ring_size = (uint32_t) V4V_ROUNDUP(protocol + 84);
			real_ring_size = ring_size;
		}
		printf("real_ring_size = %#lx\n", real_ring_size);
		if (fd > 0)
			ret = ioctl(fd, V4VIOCSETRINGSIZE, &real_ring_size);
		if (ret < 0)
			fd = ret;
	return fd;
}


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int ret = -1;
	struct sockaddr_in addr_in;	

		memcpy(&addr_in, addr, addrlen);
		my_ring.addr.domain = V4V_DOMID_NONE;
		my_ring.partner = addr_in.sin_addr.s_addr;
		my_ring.addr.port = addr_in.sin_port;
		ret = ioctl(sockfd, V4VIOCBIND, &my_ring);
	
	return ret;
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int ret = -1;
	struct sockaddr_in addr_in;

		memcpy(&addr_in, addr, addrlen);
		peer.port = addr_in.sin_port;
		peer.domain = addr_in.sin_addr.s_addr;
		ret = ioctl(sockfd, V4VIOCCONNECT, &peer);
		
	
	return ret;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	int ret = -1;

	ret = ioctl(sockfd, V4VIOCACCEPT, &peer);
	

	return ret;
}


int listen(int sockfd, int backlog)	{
	int ret = -1;
	uint32_t arg;

		ret = ioctl(sockfd, V4VIOCLISTEN, arg);

	return ret;
}


ssize_t my_read(int sockfd, void *buf, size_t len) {
	int ret = 0, rtotal = 0;
	int i;
	
	while(rtotal < len) {
		ret = read(sockfd, buf + (rtotal ? rtotal : 0), len - rtotal);
                if (ret < 0 ) {
			printf(" buf@%p\n", buf + (rtotal ? rtotal : 0));
			printf(" ret %d\n", ret);
			//for (i = 0; i< len; i++) {
			    //printf ("%c", ((char*)buf)[i]);
			//}
                        perror("read");
                        exit(-1);
                }
                rtotal += ret;
        }
	return rtotal;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
	int ret = 0, fret = 0;
	if (dgram) {
		ret = read(sockfd, buf, len);
		goto out;
	}
	while( len > 0 ) {
		ret  = my_read(sockfd, buf + fret, ((ring_size < len) ? ring_size : len));
		len -= ret;
		fret +=ret;
	}
out:
	return fret;
}

ssize_t my_write(int sockfd, const void *buf, size_t len) {
	int ret = 0, wtotal = 0;
	while(wtotal < len) {
                ret = write(sockfd, buf + (wtotal ? wtotal : 0), len - wtotal);
                if (ret < 0 ) {
                         perror("write");
                        exit(-1);
                }
                wtotal += ret;
        }
	return wtotal;
}


ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
	int ret = 0, fret = 0;
	if (dgram) {
		ret  = write(sockfd, buf, len);
		goto out;
	}
	while( len > 0 ) {
		ret = my_write(sockfd, buf + fret, ((ring_size < len) ? ring_size : len));
		len -= ret;
		fret += ret;
	}
out:
	return fret;
}



int getsockopt(int sockfd, int level, int optname,               void *optval,
socklen_t *optlen)
{
return 0;
}
int setsockopt(int sockfd, int level, int optname,
             const void *optval, socklen_t optlen)
{
return 0;
}

