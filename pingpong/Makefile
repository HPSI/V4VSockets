all: intranode.o libutils.so
	gcc intranode.o -o intranode
libutils.so: utils.c
	gcc -Wall -fPIC -shared -o libutils.so utils.c
intranode.o: intranode.c utils.h
	gcc -I . -c intranode.c

clean:
	rm *.o

