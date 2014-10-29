#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h> 

#define SIZE1 1024
#define SIZE2 SIZE1
#define SIZE3 SIZE1
int main(int argc, char *argv[])
{
	char sendBuff1[SIZE1];
	int listenfd = 0, connfd = 0;
	struct sockaddr_in serv_addr; 

	time_t ticks; 

	int n = 0;
	char sendBuff2[SIZE2];
	struct msghdr hdr;
	struct iovec iov[3];
	char sendBuff3[SIZE3];

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&serv_addr, '0', sizeof(serv_addr));

	memset(sendBuff1, '0', sizeof(sendBuff1)); 
	memset(sendBuff2, '0', sizeof(sendBuff2)); 
	memset(sendBuff3, '0', sizeof(sendBuff3)); 

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(5000); 

	if ( bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) ) {
		perror("bind failed. Error");
		return 1;
	}  

	listen(listenfd, 10); 

	while(1)
	{
		if ((connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) < 0) {
			perror("accept failed. Error");
			return 1;
		}  

		ticks = time(NULL);
		snprintf(sendBuff1, sizeof(sendBuff1), "%.24s\r\n", ctime(&ticks));
		memset(sendBuff1, 'a', sizeof(sendBuff1));
		sendBuff1[SIZE1-1]= 'b';
		printf("\nSIZE-1: %d, sendBuff[SIZE-1]: %c\n", SIZE1-1, sendBuff1[SIZE1-1]);

		snprintf(sendBuff2, sizeof(sendBuff2), "%.24s\r\n", ctime(&ticks));
		memset(sendBuff2, 'c', sizeof(sendBuff2));
		sendBuff2[SIZE2-1]= 'b';
		printf("\nSIZE-1: %d, sendBuff[SIZE-1]: %c\n", SIZE2-1, sendBuff2[SIZE2-1]);
		
		snprintf(sendBuff3, sizeof(sendBuff3), "%.24s\r\n", ctime(&ticks));
		memset(sendBuff3, 'd', sizeof(sendBuff3));
		sendBuff3[SIZE3-1]= 'b';
		printf("\nSIZE-1: %d, sendBuff[SIZE-1]: %c\n", SIZE3-1, sendBuff3[SIZE3-1]);

		iov[0].iov_base = (void *)sendBuff1;
		iov[0].iov_len = sizeof(sendBuff1);
		iov[1].iov_base = (void *)sendBuff2;
		iov[1].iov_len = sizeof(sendBuff2);
		iov[2].iov_base = (void *)sendBuff3;
		iov[2].iov_len = sizeof(sendBuff3);

		hdr.msg_name = "sgerag_send";
		hdr.msg_namelen = 11;
		hdr.msg_iov = iov;
		hdr.msg_iovlen = 3;
		hdr.msg_control = NULL;
		hdr.msg_controllen = 0;
		hdr.msg_flags = 0;

		if ( (n = sendmsg(connfd, &hdr, 0)) < 0) {
			perror("sendmsg");
		}

		printf("\n\n total bytes send: %d\n\n", n);

		//write(connfd, sendBuff, sizeof(sendBuff)); 
	}

	close(connfd);
}
