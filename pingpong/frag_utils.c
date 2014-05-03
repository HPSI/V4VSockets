#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include "v4v.h"


uint32_t ring_size;

v4v_ring_id_t my_ring;
v4v_addr_t peer;

unsigned long inet_addr(char *cp) {
	int ret = -1;
	if(!strcmp(cp,"192.168.129.2"))
		ret = 2;
	if(!strcmp(cp,"192.168.129.3"))
		ret = 3;
	return ret;
}

int socket(int domain, int type, int protocol) {
	int flags = O_RDWR;
	int fd = -1;
	int ret = 0;
	uint32_t real_ring_size;

		ring_size = protocol;
		if (type == SOCK_STREAM) {
			real_ring_size = (uint32_t) V4V_ROUNDUP(protocol + 92);
			fd = open("/dev/v4v_stream", flags);
		}
		else { 
			fd = open("/dev/v4v_dgram", flags);
			real_ring_size = (uint32_t) V4V_ROUNDUP(protocol + 84);
		}
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


ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
	int ret = 0;
	int cnt, rcnt = 0 ;

	while(len>0) {
		if (ring_size < len ) 
			cnt = ring_size;
		else 
			cnt = len;
		rcnt = read(sockfd, buf + rcnt, cnt);
		if (ret < 0 ) {
			perror("read");
			exit(-1);
		}
		sleep(1);		
		len -= rcnt;
		ret += rcnt;
	};
	printf("%s : exiting\n", __func__);				
	return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
  int ret = 0;
  int cnt, wcnt = 0;

  while(len>0) {
    if (ring_size < len )
      cnt = ring_size;
    else
      cnt = len;
    printf("%s : cnt  = %d, len = %d, size = %d\n", __func__, cnt, len, ring_size);
    wcnt = write(sockfd, buf + wcnt, cnt);
    if (ret < 0 ) {
      perror("write");  
      exit(-1);
    }
    sleep(1); 
    len -= wcnt;
    ret += wcnt;
  };
  printf("%s: exiting\n", __func__);

  return ret;
}



