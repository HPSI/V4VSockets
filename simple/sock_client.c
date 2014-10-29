#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 


#define SIZE 1024*1024
int main(int argc, char *argv[])
{
	int sockfd = 0, n = 0;
	char recvBuff[SIZE];
	struct sockaddr_in serv_addr; 
	int last_msg = 0;

	if(argc != 2)
	{
		printf("\n Usage: %s <ip of server> \n",argv[0]);
		return 1;
	} 

	memset(recvBuff, '0',sizeof(recvBuff));
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Error : Could not create socket \n");
		return 1;
	} 

	memset(&serv_addr, '0', sizeof(serv_addr)); 

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(5000); 

	if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0)
	{
		printf("\n inet_pton error occured\n");
		return 1;
	} 

	if( (n = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0)
	{
		printf("\n Error : Connect Failed: %d \n",n);
		printf("perror: %d\n",errno);
		return 1;
	} 

	last_msg = 0;
	while ((n = recv(sockfd, recvBuff, sizeof(recvBuff), 0)) > 0)
	{
		printf("\n n_read: %d \n",n);
		if (recvBuff[n-1] != 'b') {
			printf("here0\n");
			last_msg = 0;
		}
		else {
			printf("here1\n");
			last_msg = 1;
		}

		recvBuff[n-1] = '\0';

		//	printf("BUFFER: %s\n", recvBuff);
		if(fputs(recvBuff, stdout) == EOF)
		{
		    printf("\n Error : Fputs error\n");
		}

		if (last_msg) 	break;
	} 

	if(n < 0)
	{
		printf("\n Read error n=%d \n",n);
		printf("1perror: %d\n",errno);
	} 

	close(sockfd);

	return 0;
}
