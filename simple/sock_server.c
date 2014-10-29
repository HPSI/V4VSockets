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

#define SIZE 1024*1024
int main(int argc, char *argv[])
{
	int listenfd = 0, connfd = 0;
	struct sockaddr_in serv_addr; 

	char sendBuff[SIZE];
	time_t ticks; 

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&serv_addr, '0', sizeof(serv_addr));
	memset(sendBuff, '0', sizeof(sendBuff)); 

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
		snprintf(sendBuff, sizeof(sendBuff), "%.24s\r\n", ctime(&ticks));
		memset(sendBuff, 'a', sizeof(sendBuff));
		sendBuff[SIZE-1]= 'b';
		printf("\nSIZE-1: %d, sendBuff[SIZE-1]: %c\n", SIZE-1, sendBuff[SIZE-1]);

		send(connfd, sendBuff, sizeof(sendBuff), 0); 
	}

	close(connfd);
}
