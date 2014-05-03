all: intranode.o libutils.so
	gcc intranode.o -o intranode
utils.o: utils.c utils.h
	gcc -I . -c utils.c
libutils.so:
	gcc -Wall -fPIC -shared -o libutils.so utils.c
intranode.o: intranode.c utils.h
	gcc -I . -c intranode.c

clean:
	rm *.o

