all: fs_server fs_client sock_server sock_client msg_server msg_client

fs_server: fs_server.c
	gcc -Wall fs_server.c -o fs_server

fs_client: fs_client.c
	gcc -Wall fs_client.c -o fs_client

sock_server: sock_server.c
	gcc -Wall sock_server.c -o sock_server

sock_client: sock_client.c
	gcc -Wall sock_client.c -o sock_client

msg_server: msg_server.c
	gcc -Wall msg_server.c -o msg_server

msg_client: msg_client.c
	gcc -Wall msg_client.c -o msg_client

clean:
	rm -v fs_server fs_client sock_server sock_client msg_server msg_client 
