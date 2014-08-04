#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "utils.h"
#include "../driver/v4v.h"

#define TIMERS_ENABLED
#include "timers.h"
#define FLAG_STREAM 0x0
#define FLAG_DGRAM 0x1
#define FLAG_SERVER 0x2
#define FLAG_CLIENT 0x0
#define FLAG_UNIX 0x0
#define FLAG_V4V 0x4
#define SERVER_PORT 1500
#define CLIENT_PORT 1600
#define F_V4V 12345
#define ALIGN 4096

void print(unsigned char* buf, uint32_t size);
int validate_data(unsigned char* reader, unsigned char* writer, uint32_t size);
void initialize_data(unsigned char *buf, uint32_t size);

static void v4v_hexdump(void *_p, int len)
{
    uint8_t *buf = (uint8_t *)_p;
    int i, j;

    for ( i = 0; i < len; i += 16 )
    {
        printf("%p:", &buf[i]);
        for ( j = 0; j < 16; ++j )
        {
            int k = i + j;
            if ( k < len )
                printf(" %02x", buf[k]);
            else
                printf("   ");
        }
        printf(" ");

        for ( j = 0; j < 16; ++j )
        {
            int k = i + j;
            if ( k < len )
                printf("%c", ((buf[k] > 32) && (buf[k] < 127)) ? buf[k] : '.');
            else
                printf(" ");
        }
        printf("\n");
    }
}

/*global variables*/
int cmdline_validate_data = 0;
int initial_data_size = -1;
int last_data_size = -1;
int print_enabled = 0;
int p = 0;
int family = AF_INET;
int type = -1;
int protocol = 0;
int partner = -1;
int mode = 0;
int data_size = -1;
int backlog = 5;
unsigned long my_address = -1;
unsigned long partner_address = -1;
unsigned char *reader, *writer;
int iteration_num = -1;

#if 1
void* aligned_malloc(size_t size) {
	void *ptr;
	posix_memalign(&ptr, 4096, size);
	//ptr = malloc(size);
	return ptr;
}
#else
void* aligned_malloc(size_t size) {
	void *ptr;
	void *p = malloc(size+ALIGN-1+sizeof(void*));
	if(p!=NULL) {
		ptr = (void*) (((unsigned int)p + sizeof(void*) + ALIGN -1) & ~(ALIGN-1));
		*((void**)((unsigned int)ptr - sizeof(void*))) = p;
		return ptr;
	}
	return NULL;
}
#endif

#if 1
void aligned_free(void *p) {
	free(p);
}
#else

void aligned_free(void *p) {
	void *ptr = *((void**)((unsigned int)p - sizeof(void*)));
	free(ptr);
	return;
}
#endif

void client_dgram() {
	int flags = 0;
        int fd, ret, temp, i, cliLen, serLen;
        struct sockaddr_in client, server;
        timers_t timer_read, timer_write, timer_total;
	double time_read, time_write, time_total;

        /*socket*/

	protocol = IPPROTO_UDP;
        fd = socket(family, type, protocol);
        if(fd<0) {
                perror("socket");
                exit(-1);
        }
        /*bind*/
        client.sin_family = family;
        client.sin_addr.s_addr = my_address;
        client.sin_port = htons(CLIENT_PORT+p);
	printf("will bind with client:%p, client.sin_addr.s_addr:%p\n", &client, &client.sin_addr.s_addr);
        ret = bind(fd, (struct sockaddr *)&client, sizeof(client));
        if (ret<0) {
                perror("bind");
                exit(-1);
        }
        cliLen  = sizeof(client);
        /*connect*/
        server.sin_family = family;
        server.sin_port = htons(SERVER_PORT+p);
        server.sin_addr.s_addr = partner_address;
#if 1
        ret = connect(fd, (struct sockaddr *)&server, sizeof(server));
        if (ret<0) {
                perror("connect");
                exit(-1);
        }
#endif
        serLen = sizeof(server);
	        for(data_size = initial_data_size; data_size <= last_data_size; data_size<<=1 ) {
        TIMER_RESET(&timer_total);
        /*write*/
                writer = (char*) aligned_malloc(data_size);
                reader = (char*) aligned_malloc(data_size);
                initialize_data(writer, data_size);
                initialize_data(reader, data_size);
                if (print_enabled) {
                	print(writer, data_size);
        	}
                TIMER_RESET(&timer_write);
                TIMER_RESET(&timer_read);
                TIMER_START(&timer_total);
                for(i = 0; i < iteration_num; i++) {
                        int rtotal = 0, wtotal = 0;
                        //while(wtotal < data_size) {
				TIMER_START(&timer_write);
                                ret = sendto(fd, writer, data_size, flags, (struct sockaddr*) &server, (socklen_t) serLen);
                                TIMER_STOP(&timer_write);
                                if (ret<0) {
                                        perror("write");
                                        exit(-1);
                                }
                                //wtotal += ret;
                          //}
                          //while(rtotal < data_size) {
                                TIMER_START(&timer_read);
                                ret = recvfrom(fd, reader, data_size, flags, (struct sockaddr*) &server, (socklen_t *) &serLen);
				TIMER_STOP(&timer_read);
                                if (ret<0) {
                                        perror("raaaaead");
                                        exit(-1);
                                }

                            //    rtotal += ret;
                        //}
                TIMER_STOP(&timer_total);
                //reader[130000] = 'A';
                ret = validate_data(reader, writer, data_size);
		if (ret) {
			break;
		}
                TIMER_START(&timer_total);

                        //printf("\nread %ld %ld\n", TIMER_COUNT(&timer_read), TIMER_TOTAL(&timer_read));
                        //printf("\nwrite %ld %ld\n", TIMER_COUNT(&timer_write), TIMER_TOTAL(&timer_write));
                }
                TIMER_STOP(&timer_total);
                aligned_free(reader);
                aligned_free(writer);
		time_read = TIMER_AVG(&timer_read);
                time_write = TIMER_AVG(&timer_write);
                time_total = time_read + time_write;
		/*total time*/
		printf("%ld %lf %lf %lf %lf %lf %lf\n", data_size, time_read, time_write, 1.0 * data_size / (time_read), 1.0 * data_size / time_write, 1.0 * TIMER_TOTAL(&timer_total)/iteration_num/2, 1.0 * data_size * iteration_num /(TIMER_TOTAL(&timer_total)/2));
		fflush(stdout);
                //printf("%ld %lf %lf \n", data_size, 1.0 * TIMER_TOTAL(&timer_total)/iteration_num/2, 1.0 * data_size * iteration_num / (TIMER_TOTAL(&timer_total) / 2));
        }
        //if (ret == 0)
                //printf("OK!\n");
        close(fd);
        return;
}




void client() {
	int flags = 0;
	int fd, ret, temp, i, cliLen, serLen;
	struct sockaddr_in client, server;
	timers_t timer_read, timer_write, timer_total;
	double time_read, time_write, time_total;

	/*socket*/
	fd = socket(family, type, protocol);
	if(fd<0) {
		perror("socket");
		exit(-1);
	}
	/*bind*/
	client.sin_family = family;
	client.sin_addr.s_addr = my_address;
	client.sin_port = htons(CLIENT_PORT+p);
	printf("will bind with client:%p, client.sin_addr.s_addr:%p\n", &client, &client.sin_addr.s_addr);
	ret = bind(fd, (struct sockaddr *)&client, sizeof(client));
	if (ret<0) {
		perror("bind");
		exit(-1);
	}
	cliLen  = sizeof(client);
	/*connect*/
	server.sin_family = family;
	server.sin_port = htons(SERVER_PORT+p);
	server.sin_addr.s_addr = partner_address;
	ret = connect(fd, (struct sockaddr *)&server, sizeof(server));
	if (ret<0) {
		perror("connect");
		exit(-1);
	}
	serLen = sizeof(server);
	for(data_size = initial_data_size; data_size <= last_data_size; data_size<<=1) {
	TIMER_RESET(&timer_total);
	/*write*/
		TIMER_START(&timer_total);
		TIMER_RESET(&timer_read);
		TIMER_RESET(&timer_write);
		for(i = 0; i < iteration_num; i++) {
			int rtotal = 0, wtotal = 0;
			TIMER_STOP(&timer_total);
			writer = (char*) aligned_malloc(data_size);
			reader = (char*) aligned_malloc(data_size);
			//printf ("write ptr @%p\n", writer);
			//printf ("read ptr @%p\n", reader);
			initialize_data(writer, data_size);
			initialize_data(reader, data_size);
			if (print_enabled) {
				print(writer, data_size);
			}

			TIMER_START(&timer_total);
#if 0
			printf("writer iter:%d\n", i);
			if (i == 255) {
				writer[0]='N';
				writer[1]='A';
				writer[2]='N';
				writer[3]='O';
			}
#endif
			while(wtotal < data_size) {
			        TIMER_START(&timer_write);
				ret = sendto(fd, writer + (wtotal ? wtotal : 0 ), data_size - wtotal, flags, (struct sockaddr*) &server, (socklen_t) serLen);
				TIMER_STOP(&timer_write);
				if (ret<0) {
					perror("write");
					exit(-1);
				}
                        	wtotal += ret;
			}
//			printf("total:%d: %d, writer:%#x %#x %#x %#X\n", wtotal, ret, writer[0], writer[1], writer[2], writer[3]);
			//v4v_hexdump(writer, data_size);
			//break;
//			printf("reader iter:%d\n", i);
			while(rtotal < data_size) {
				TIMER_START(&timer_read);
    				ret = recvfrom(fd, reader + (rtotal ? rtotal :0), data_size - rtotal, flags, (struct sockaddr*) &server, (socklen_t *) &serLen);
				TIMER_STOP(&timer_read);
				if (ret<0) {
					perror("rsssead");
					exit(-1);
				}

				rtotal += ret;
			}
//			printf("total:%d: %d\n", rtotal, ret);
                TIMER_STOP(&timer_total);
		ret = validate_data(reader, writer, data_size);
		if (ret) {
			sleep(10);
			break;
		}
		aligned_free(reader);
		aligned_free(writer);
                TIMER_START(&timer_total);

			//printf("\nread %ld %ld\n", TIMER_COUNT(&timer_read), TIMER_AVG(&timer_read));
			//printf("\nwrite %ld %ld\n", TIMER_COUNT(&timer_write), TIMER_AVG(&timer_write));
		}
		TIMER_STOP(&timer_total);
		/*total time*/
		//printf("%ld %lf %lf \n", data_size, 1.0 * TIMER_TOTAL(&timer_total)/iteration_num/2, 1.0 * data_size * iteration_num / (TIMER_TOTAL(&timer_total) / 2));
		time_read = TIMER_AVG(&timer_read);
		time_write = TIMER_AVG(&timer_write);
		//time_read = TIMER_TOTAL(&timer_read) / iteration_num;
		//time_write = TIMER_TOTAL(&timer_write)/ iteration_num;
		time_total = time_read + time_write;
		printf("%ld %lf %lf %lf %lf %lf %lf\n", data_size, time_read, time_write, 1.0 * data_size / (time_read), 1.0 * data_size / time_write, 1.0 * TIMER_TOTAL(&timer_total)/iteration_num/2, 1.0 * data_size * iteration_num /(TIMER_TOTAL(&timer_total)/2));
		printf("%ld %ld %ld %ld %ld %ld \n", TIMER_TOTAL(&timer_read), TIMER_TOTAL(&timer_write), TIMER_COUNT(&timer_read), TIMER_COUNT(&timer_write), TIMER_TOTAL(&timer_total), TIMER_COUNT(&timer_total));
		fflush(stdout);
		//printf("\nread %ld %ld\n", TIMER_COUNT(&timer_read), TIMER_AVG(&timer_read));
		//printf("\nwrite %ld %ld\n", TIMER_COUNT(&timer_write), TIMER_AVG(&timer_write));
	}
	//if (ret == 0)
	//	printf("OK!\n");
	//sleep(16);
	close(fd);
	return;
}


void server_stream() {
        int fd, ret, temp, new_fd, cliLen, i, serLen;
        struct sockaddr_in client, server;
	int flags = 0;

        /*socket*/
        fd = socket(family, type, protocol);
        if (fd<0) {
                perror("socket");
                exit(-1);
        }
        server.sin_family = family;
        server.sin_addr.s_addr = my_address;
        server.sin_port = htons(SERVER_PORT+p);
	serLen = sizeof(server);
        /*bind*/
        ret = bind(fd, (struct sockaddr *) &server, sizeof(server));
        if (ret<0) {
                perror("bind");
                exit(-1);
        }
	/*listen*/
	ret = listen(fd, backlog);
	if (ret<0) {
		perror("listen");
		exit(-1);
	}
	/*accept*/
	client.sin_family = family;
	client.sin_addr.s_addr = partner_address;
	cliLen = sizeof(client);
	ret = accept(fd, (struct sockaddr *)&client, &cliLen);
	if (ret<0) {
		perror("accept");
		exit(-1);
	}
	new_fd = ret;
	/*read*/
	for(data_size = initial_data_size; data_size<= last_data_size; data_size<<=1) {
    		reader = (char*) aligned_malloc(data_size);
                initialize_data(reader, data_size);
		for(i=0; i < iteration_num; i++) {
			int rtotal = 0, wtotal = 0;
			//ret = read(new_fd, reader, data_size);
			//printf("reader:iter:%d\n", i);
			while(rtotal < data_size) {
    	    			ret = recvfrom(new_fd, reader + (rtotal ? rtotal : 0), data_size - rtotal, flags, (struct sockaddr *) &client, (socklen_t *) &cliLen);
        			if (ret<0) {
					printf("ret = %d\n", ret);
                			perror("reaaaaad");
                			exit(-1);
        			}
				rtotal += ret;
			}
			//printf("total:%d: %d\n", rtotal, ret);
       			if (print_enabled) {
                		printf("%s: I have read :\n", __func__);
                		print(reader, data_size);
        		}
			//v4v_hexdump(reader, data_size);
			//break;
			//sleep(10);
        		/*write*/
			//ret = write(new_fd, reader, data_size);
			//sleep(20);
			//printf("writer: iter:%d\n", i);
			while(wtotal < data_size) {
        			ret = sendto(new_fd, reader + (wtotal ? wtotal : 0), data_size - wtotal, flags, (struct sockaddr*) &client, (socklen_t) cliLen);
        			if (ret<0) {
                			perror("write");
                			exit(-1);
        			}
				wtotal += ret;
			}
			//printf("total:%d: %d\n", wtotal, ret);
		}
		aligned_free(reader);
	}
	sleep(2);
	close(fd);
	close(new_fd);
        return;
}

void server_dgram() {
	int fd, ret, temp, i, cliLen, serLen;
	struct sockaddr_in client, server;
	int flags = 0;

	/*socket*/
	fd = socket(family, type, protocol);
	if (fd<0) {
		perror("socket");
		exit(-1);
	}
	server.sin_family = family;
	server.sin_addr.s_addr = my_address;
	server.sin_port = htons(SERVER_PORT+p);
	serLen = sizeof(server);
	/*bind*/
	ret = bind(fd, (struct sockaddr *) &server, sizeof(server));
	if (ret<0) {
		perror("bind");
		exit(-1);
	}

	/***********************/
	client.sin_family = family;
	client.sin_addr.s_addr = partner_address;
        client.sin_port = htons(CLIENT_PORT+p);
	cliLen = sizeof(client);
#if 1
        ret = connect(fd, (struct sockaddr *) &client, sizeof(client));
        if (ret<0) {
                perror("connect");
                exit(-1);
        }
#endif
	/***********************/
	for(data_size=initial_data_size; data_size<=last_data_size; data_size<<=1) {
	/*read*/
		reader = (char*) aligned_malloc(data_size);
                initialize_data(reader, data_size);
		for(i=0; i<iteration_num; i++) {
			int rtotal = 0, wtotal = 0;
			//ret = read(fd, reader, data_size);
			//while(rtotal < data_size) {
				ret = recvfrom(fd, reader, data_size, flags, (struct sockaddr *) &client, (socklen_t *) &cliLen);
				if (ret<0) {
					perror("raaaaead");
					exit(-1);
				}
			//	rtotal += ret;
			//}
			if (print_enabled) {
				printf("%s: I have read :\n", __func__);
				print(reader, data_size);
			}

			/*write*/
			//ret  = write(fd, reader, data_size);
			//while(wtotal < data_size) {
				ret = sendto(fd, reader, data_size, flags, (struct sockaddr *) &client, (socklen_t) cliLen);
				if (ret<0) {
					perror("write");
					exit(-1);
				}
			//	wtotal += ret;
			//}
		}
		aligned_free(reader);
	}
	close(fd);
	return;
}

void print_usage() {

	return;
}


void print(unsigned char *buf, uint32_t size) {
	int i;
	for(i=0; i<size; i++)
		printf("%d ", buf[i]);
	printf("\n\n");
	return;
}


int validate_data(unsigned char* reader, unsigned char* writer, uint32_t size) {
	int i;
	int ret = 0;
	if (cmdline_validate_data) 
		for(i=0; i<size; i++)
			if(reader[i] != writer[i]) {
				printf("Data corruption: (is) %c, (should be) %c, %d (total:%d),\n", reader[i], writer[i], i, size);
				ret = -1;
			}
	if (ret) {
		//v4v_hexdump(reader, size);
		//printf("\n\n\n\n");
		//v4v_hexdump(writer, size);
	}
	return ret;
}

void initialize_data(unsigned char *buf, uint32_t size) {
	int i;
	for(i=0; i<size; i++)
		//buf[i] = (unsigned char) rand();
		//buf[i] = (unsigned char) (rand() % 25 + 65);
		buf[i] = (unsigned char) (rand() % 25 + 65);
	return;
}


int main(int argc, char** argv) {
	int c;
	uint32_t ring_size;
	int temp;
	timers_t hpt1;
	int tem1p;
	timers_t hpt2;

        /* timer example */
        /*
        TIMER_RESET(&hpt1);
        TIMER_START(&hpt1);
	sleep(4);
        TIMER_STOP(&hpt1);
        TIMER_RESET(&hpt2);
        TIMER_START(&hpt2);
	sleep(1);
        TIMER_STOP(&hpt2);
        printf("%ld\t%ld\n", TIMER_COUNT(&hpt1), TIMER_TOTAL(&hpt1));
        printf("%ld\t%ld\n", TIMER_COUNT(&hpt2), TIMER_TOTAL(&hpt2));
	*/
	while ((c = getopt(argc, argv, "o:m:scdtxr:b:e:n:vp:h")) != -1)
		switch(c) {
		case 'o':/*partners id*/
			partner_address = inet_addr(optarg);
			printf("%u:\n", partner_address);
			break;
		case 'm':/*my id*/
			my_address = inet_addr(optarg);
			printf("%u:\n", my_address);
			break;
		case 's':
			mode |= FLAG_SERVER;
			break;
		case 'c':
			mode |= FLAG_CLIENT;
			break;
		case 'd':
			mode |= FLAG_DGRAM;
			type = SOCK_DGRAM;
			break;
		case 't':
			mode |= FLAG_STREAM;
			type = SOCK_STREAM;
			break;
		case 'x':
			my_address = partner_address;
			break;
		case 'r':
			ring_size = atoi(optarg);
			protocol = ring_size;
			break;
		case 'b':
			initial_data_size = atoi(optarg);
			break;
		case 'e':
			last_data_size = atoi(optarg);
		case 'n':
			iteration_num = atoi(optarg);
			break;
		case 'v':
			cmdline_validate_data = 1;
			break;
		case 'p':
			//print_enabled = 1;
			p = atoi(optarg);
			break;
		default:
			printf("Unknown option -%c\n", c);
		case 'h':
			print_usage();
			exit(-1);
			break;
		}

	temp = mode&FLAG_SERVER;
	if (temp) {
		temp = mode&FLAG_DGRAM;
		if (temp)
			server_dgram();
		else
			server_stream();
	}
	else {
		temp = mode&FLAG_DGRAM;
		if (temp)
			client_dgram();
		else
			client();
	}
	printf("\n\n");
	return 0;
}
