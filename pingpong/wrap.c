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
#include "../driver/v4v.h"

int socket(int domain, int type, int protocol) 
{
  static int (*socket_real)(int, int, int)=NULL;
  int ret;
  int domain_real = domain;

  if (!socket_real) socket_real=dlsym(RTLD_NEXT,"socket");

  domain = AF_XEN;
  if ((ret = socket_real(domain,type,protocol)) < 0) {
	fprintf(stderr,"socket() %d\n", ret);
	domain=domain_real;
  }
  return ret < 0 ? socket_real(domain,type,protocol) : ret;

  if (getenv("WRAP_DEBUG"))
      fprintf(stderr,"socket_debug() %d\n", domain);

  return -1;
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

#if 0
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
        static int(*recvfrom_real)(int , const void *, size_t , int , const struct sockaddr *, socklen_t *)=NULL;
        int ret = -1, retur=0;
        int lump = 16348;
        int start = 0;
        int wtotal = 0;
        if (!recvfrom_real) recvfrom_real=dlsym(RTLD_NEXT,"recvfrom");
//      dump_sockaddr(stderr, dest_addr);
        ret = recvfrom_real(sockfd, buf, len, flags, src_addr, addrlen);
        if (ret == -EMSGSIZE) {
                printf("will do fragmentation\n");
                while (wtotal <  len) {
                        retur = recvfrom_real(sockfd, buf + (wtotal ? wtotal : 0), len - wtotal > lump ? lump : len-wtotal, flags, src_addr, addrlen);
                        printf("len:%u, lump%d, start:%d, retur:%d\n", len, lump, wtotal,retur);
                        len -= retur;
                        start+=retur;
                        wtotal += retur;
                }
        }
	printf("ret:%d\n", ret);
	printf("ret:%d\n", retur);
        return  ret > 0 ? ret : retur;
}



ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)
{
	static int(*sendto_real)(int , const void *, size_t , int , const struct sockaddr *, socklen_t)=NULL;
	int ret = -1, retur=0;
	int lump = 16348;
	int start = 0;
	int wtotal = 0;
#if 0
	struct sockaddr_in addr_in;

	memcpy(&addr_in, dest_addr, addrlen);

#endif
	if (!sendto_real) sendto_real=dlsym(RTLD_NEXT,"sendto");
//	dump_sockaddr(stderr, dest_addr);
	ret = sendto_real(sockfd, buf, len, flags, dest_addr, addrlen);
	if (ret < 0 ) {
		printf("will do fragmentation, ret:%d\n", ret);
		while (wtotal <  len) {
			retur = sendto_real(sockfd, buf + (wtotal ? wtotal : 0), (len - wtotal) > lump ? lump : len - wtotal, flags, dest_addr, addrlen);
			printf("len:%u, lump%d, start:%d, retur:%d\n", len, lump, wtotal,retur);
			len -= retur;
			start+=retur;
			wtotal += retur;
		}
	}
	printf("ret:%d\n", ret);
	printf("ret:%d\n", retur);
	return  ret > 0 ? ret : retur;
}
#endif

#if 0
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	static int(*connect_real)(int, const struct sockaddr *, socklen_t)=NULL;
	int ret = -1;
	struct sockaddr_in addr_in;

	memcpy(&addr_in, addr, addrlen);

	if (!connect_real) connect_real=dlsym(RTLD_NEXT,"connect");
	dump_sockaddr(stderr, &addr_in);

	if ((ret = connect_real(sockfd,addr,addrlen)) < 0) {
	      fprintf(stderr,"connect() %d\n", ret);
	}
	return ret;

}



ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)
{
	static int(*sendto_real)(int , const void *, size_t , int , const struct sockaddr *, socklen_t)=NULL;
	int ret = -1;
	struct sockaddr_in addr_in;

	memcpy(&addr_in, dest_addr, addrlen);

	if (!sendto_real) sendto_real=dlsym(RTLD_NEXT,"sendto");
	dump_sockaddr(stderr, dest_addr);
	return sendto_real(sockfd, buf, len, flags, dest_addr, addrlen);
}

int     dump_sockaddr(FILE *tfp, struct sockaddr_in *sinptr)
        {
        int     k;

        /*  in <in.h>
        struct  sockaddr_in  {
                short   sin_family;
                u_short sin_port;
                struct  in_addr sin_addr;
                char    sin_zero[8];
        }       */

        if ( (sinptr == (struct sockaddr_in *)NULL) ||
             (tfp == (FILE *)NULL) )
                return(-1);                     /* insurance */

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
        "\n       struct  in_addr sin_addr.s_addr(=%#x, %#x\n)", ntohl(sinptr->sin_addr.s_addr), sinptr->sin_addr.s_addr);
        fprintf(tfp,
        "\n       char    sin_zero[8](=%x %x %x %x %x %x %x %x);",
                        sinptr->sin_zero[0],
                        sinptr->sin_zero[1],
                        sinptr->sin_zero[2],
                        sinptr->sin_zero[3],
                        sinptr->sin_zero[4],
                        sinptr->sin_zero[5],
                        sinptr->sin_zero[6],
                        sinptr->sin_zero[7]);
        fprintf(tfp,
        "\n  } ");

        fflush(tfp);
        return(0);
}  /* end of dump_sockaddr */

#endif
