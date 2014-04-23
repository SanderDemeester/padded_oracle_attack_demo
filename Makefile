CFLAGS=-lcrypto -Wdeprecated-declarations

server: server.o
	gcc $(CFLAGS) server.o -o server
server.o:
	gcc $(CFLAGS) -c server.c -o server.o 