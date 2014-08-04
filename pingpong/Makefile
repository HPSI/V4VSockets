XEN_PATH=/local/ialif-xen/xen-v4v
TOOLS_PATH=$(XEN_PATH)/tools
LDFLAGS+=-L$(TOOLS_PATH)/libvchan
LDFLAGS+=-L$(TOOLS_PATH)/libxc
LDFLAGS+=-L$(TOOLS_PATH)/xenstore
CFLAGS+=-I$(TOOLS_PATH)/include
CFLAGS+=-I$(TOOLS_PATH)/libvchan
CFLAGS+=-I$(TOOLS_PATH)/libxc
CFLAGS+=-I$(TOOLS_PATH)/xenstore
LDFLAGS+=-lxenvchan

all: intranode.o libutils.so libwrap.so libutils-vchan.so
	gcc intranode.o -o intranode
libutils.so: utils.c
	gcc -Wall -fPIC -shared -o libutils.so utils.c
libutils-vchan.so: utils-vchan.c
	gcc -Wall -fPIC -shared -o libutils-vchan.so utils-vchan.c $(LDFLAGS) $(CFLAGS)
libwrap.so: wrap.c
	gcc -Wall -fPIC -shared -o libwrap.so wrap.c -ldl
intranode.o: intranode.c utils.h
	gcc -I . -c intranode.c

clean:
	rm *.o *.so

