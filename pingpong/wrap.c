#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>

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

