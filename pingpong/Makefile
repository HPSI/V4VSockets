XEN_PATH=/local/ialif-xen/xen-v4v
LD_FLAGS=-L$(XEN_PATH)/tools/libvchan 
LD_FLAGS+=-L$(XEN_PATH)/tools/xenstore
LD_FLAGS+=-L$(XEN_PATH)/tools/libxc
LD_FLAGS+=-lxenvchan
CFLAGS=-I$(XEN_PATH)/tools/libvchan
CFLAGS+=-I$(XEN_PATH)/tools/xenstore
CFLAGS+=-I$(XEN_PATH)/tools/libxc
CFLAGS+=-I$(XEN_PATH)/tools/include

all: intranode.o libutils.so libutils-vchan.so
	gcc intranode.o -o intranode
libutils.so: utils.c
	gcc -Wall -fPIC -shared -o libutils.so utils.c
libutils-vchan.so: utils-vchan.c
	gcc -Wall -fPIC -shared -o libutils-vchan.so utils-vchan.c $(LD_FLAGS) $(CFLAGS)
intranode.o: intranode.c utils.h
	gcc -I . -c intranode.c

clean:
	rm *.o *.so

