all: intranode.o utils.o
	gcc intranode.o -o intranode
utils.o: utils.c utils.h
	gcc -I . -c utils.c
intranode.o: intranode.c utils.h
	gcc -I . -c intranode.c

clean:
	rm *.o

