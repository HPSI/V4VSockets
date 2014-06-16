all: intranode.o libutils.so libwrap.so
	gcc intranode.o -o intranode
libutils.so: utils.c
	gcc -Wall -fPIC -shared -o libutils.so utils.c
libwrap.so: wrap.c
	gcc -Wall -fPIC -shared -o libwrap.so wrap.c -ldl
intranode.o: intranode.c utils.h
	gcc -I . -c intranode.c

clean:
	rm *.o *.so

