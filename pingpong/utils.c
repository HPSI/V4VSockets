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


#define vaxunsign(x) ((unsigned)x & 0xff)
uint32_t ring_size;
int dgram = 0;
v4v_ring_id_t my_ring;
v4v_addr_t peer;

unsigned long inet_addr(char *cp) {
	int ret = -1;
	if(!strcmp(cp,"192.168.129.2"))
		ret = 3;
	if(!strcmp(cp,"192.168.129.3"))
		ret = 4;
	return ret;
}

int socket(int domain, int type, int protocol) {
	int flags = O_RDWR;// | O_NONBLOCK;
	int fd = -1;
	int ret = 0;
	uint32_t real_ring_size;

		ring_size = protocol ? protocol: V4V_ROUNDUP(128 * 4096);
		if (ring_size < 0x1000) {
			ring_size = V4V_ROUNDUP(128 * 4096);
		}
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
		fprintf(stderr,"real_ring_size = %#lx\n", real_ring_size);
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
	fprintf(stderr,"%s: domain: %#lx\n", __func__, my_ring.addr.domain);
	my_ring.partner = addr_in.sin_addr.s_addr;
	fprintf(stderr,"%s: partner: %#lx\n", __func__, my_ring.partner);
	my_ring.addr.port = addr_in.sin_port;
	fprintf(stderr,"%s: port: %#lx\n", __func__, my_ring.addr.port);
	//if (!addr_in.sin_port) my_ring.addr.port=12856;
	ret = ioctl(sockfd, V4VIOCBIND, &my_ring);
	fprintf(stderr,"%s: ret: %#lx\n", __func__, ret);
	
	return ret;
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int ret = -1;
	struct sockaddr_in addr_in;

	do {
		memcpy(&addr_in, addr, addrlen);
		dump_sockaddr(stderr, &addr_in);
		peer.port = addr_in.sin_port;
		if (!addr_in.sin_port) my_ring.addr.port=0x4132;
		fprintf(stderr,"%s: port:%#x\n", __func__, peer.port);
		peer.domain = addr_in.sin_addr.s_addr;
		fprintf(stderr,"%s: domain:%#x\n", __func__, peer.domain);
		//peer.domain=1;
		ret = ioctl(sockfd, V4VIOCCONNECT, &peer);
		fprintf(stderr,"%s: ret: %#lx\n", __func__, ret);
	} while (ret == -EINPROGRESS);
		
	
	return ret;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	int ret = -1;

	do {
	ret = ioctl(sockfd, V4VIOCACCEPT, &peer);
	fprintf(stderr,"%s: ret: %#lx\n", __func__, ret);
	 } while (ret == -1);
	

	return ret;
}


int listen(int sockfd, int backlog)	{
	int ret = -1;
	uint32_t arg;

	do {
	ret = ioctl(sockfd, V4VIOCLISTEN, arg);
	} while (ret == -1);

	fprintf(stderr,"%s: ret: %#lx\n", __func__, ret);
	return ret;
}


ssize_t my_read(int sockfd, void *buf, size_t len) {
	int ret = 0, rtotal = 0;
	int i;
	
	while(rtotal < len) {
		ret = read(sockfd, buf + (rtotal ? rtotal : 0), len - rtotal);
                if (ret < 0 ) {
			fprintf(stderr," buf@%p\n", buf + (rtotal ? rtotal : 0));
			fprintf(stderr," ret %d\n", ret);
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

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
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


ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
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
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in *addr_in = addr;

	addr_in->sin_addr.s_addr = 2;
	addr_in->sin_port = 0x4132;
	addr_in->sin_family = AF_INET;
	return 0;
}
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in *addr_in = addr;

	addr_in->sin_addr.s_addr = 2;
	addr_in->sin_port = 0x4132;
	addr_in->sin_family = AF_INET;
	return 0;
}

int setsockopt(int sockfd, int level, int optname,
             const void *optval, socklen_t optlen)
{
return 0;
}


int	dump_sockaddr(FILE *tfp, struct sockaddr_in *sinptr)
	{
	int	k;

	/*  in <in.h>
	struct	sockaddr_in  {
		short	sin_family;
		u_short	sin_port;
		struct	in_addr	sin_addr;
		char	sin_zero[8];
	}	*/

	if ( (sinptr == (struct sockaddr_in *)NULL) ||
	     (tfp == (FILE *)NULL) )
		return(-1);			/* insurance */

	fprintf(tfp,
	"\n  struct sockaddr_in { ");
	k = sinptr->sin_family;
						/* print port number (or
				0 = "to be assigned by system" */
	fprintf(tfp,
	"\n       u_short sin_port(=%hu);", ntohs(sinptr->sin_port));

						/* print ip address */
	fprintf(tfp,
	"\n       struct  in_addr sin_addr.s_addr(=%u=%d.%d.%d.%d);",
			ntohl(sinptr->sin_addr.s_addr),
			(ntohl(sinptr->sin_addr.s_addr) & 0xff000000) >> 24,
			(ntohl(sinptr->sin_addr.s_addr) & 0x00ff0000) >> 16,
			(ntohl(sinptr->sin_addr.s_addr) & 0x0000ff00) >>  8,
			(ntohl(sinptr->sin_addr.s_addr) & 0x000000ff));
	fprintf(tfp,
	"\n       char    sin_zero[8](=%x %x %x %x %x %x %x %x);",
			vaxunsign(sinptr->sin_zero[0]),
			vaxunsign(sinptr->sin_zero[1]),
			vaxunsign(sinptr->sin_zero[2]),
			vaxunsign(sinptr->sin_zero[3]),
			vaxunsign(sinptr->sin_zero[4]),
			vaxunsign(sinptr->sin_zero[5]),
			vaxunsign(sinptr->sin_zero[6]),
			vaxunsign(sinptr->sin_zero[7]));
	fprintf(tfp,
	"\n  } ");

	fflush(tfp);
	return(0);
}  /* end of dump_sockaddr */

