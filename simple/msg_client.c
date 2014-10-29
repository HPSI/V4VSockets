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


#define SIZE1 1024
#define SIZE2 SIZE1
#define SIZE3 SIZE1
int main(int argc, char *argv[])
{
	int sockfd = 0, n = 0;
	char recvBuff1[SIZE1];
	struct sockaddr_in serv_addr; 
	char recvBuff2[SIZE2];
	//int last_msg = 0;

        struct msghdr hdr;
        struct iovec iov[3];
	char recvBuff3[SIZE3];

	if(argc != 2)
	{
		printf("\n Usage: %s <ip of server> \n",argv[0]);
		return 1;
	} 

	memset(recvBuff1, '0',sizeof(recvBuff1));
	memset(recvBuff2, '0',sizeof(recvBuff2));
	memset(recvBuff3, '0',sizeof(recvBuff3));
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

	iov[0].iov_base = (void *)recvBuff1;
	iov[0].iov_len = sizeof(recvBuff1);
	iov[1].iov_base = (void *)recvBuff2;
	iov[1].iov_len = sizeof(recvBuff2);
	iov[2].iov_base = (void *)recvBuff3;
	iov[2].iov_len = sizeof(recvBuff3);

	hdr.msg_name = "sgerag_recv";
	hdr.msg_namelen = 11;
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 3;
	hdr.msg_control = NULL;
	hdr.msg_controllen = 0;
	hdr.msg_flags = 0;


	//last_msg = 0;
	//while ((n = read(sockfd, recvBuff, sizeof(recvBuff))) > 0)
	//n = read(sockfd, recvBuff, sizeof(recvBuff));
	n = recvmsg(sockfd, &hdr, 0);
	//{
		printf("\n n_read: %d \n",n);
//		if (recvBuff[n-1] != 'b') {
//			printf("here0\n");
//			last_msg = 0;
//		}
//		else {
//			printf("here1\n");
//			last_msg = 1;
//		}
//
//		recvBuff[n-1] = '\0';

		//	printf("BUFFER: %s\n", recvBuff);
		if(fputs(hdr.msg_iov[0].iov_base, stdout) == EOF)
		{
		    printf("\n Error : Fputs error\n");
		}
		if(fputs(hdr.msg_iov[1].iov_base, stdout) == EOF)
		{
		    printf("\n Error : Fputs error\n");
		}
		if(fputs(hdr.msg_iov[2].iov_base, stdout) == EOF)
		{
		    printf("\n Error : Fputs error\n");
		}

		//if (last_msg) 	break;
	//} 

	if(n < 0)
	{
		printf("\n Read error n=%d \n",n);
		printf("1perror: %d\n",errno);
	}

	printf("\n\n\n");

	close(sockfd);

	return 0;
}
