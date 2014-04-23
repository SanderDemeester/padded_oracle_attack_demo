#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>
#include <openssl/evp.h>

#define AES_BLOCK_SIZE 256

char response[] = "HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=UTF-8\r\n\r\n"
"<doctype !html><html><head><title>Bye-bye baby bye-bye</title>"
"<style>body { background-color: #111 }"
"h1 { font-size:4cm; text-align: center; color: black;"
" text-shadow: 0 0 2mm red}</style></head>"
  "<body><h1>Goodbye, world!</h1></body></html>\r\n";

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,
	     EVP_CIPHER_CTX *d_ctx){
  int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  int nrounds = 5;
  int x = 0;
  
  if(i != 32){
    printf("Key size is %d bits - it should be 256 bits", i);
    return -1;    
  }
  for(; x<32; x++)
    printf("Key: %x iv: %x \n", key[x], iv[x]);
  
  for(x=0; x<8; x++)
    printf("salt: %x\n", salt[x]);

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}
  

int main(void){
  int one = 1, client_fd;
  struct sockaddr_in srv_addr, cli_addr;
  socklen_t sin_len = sizeof(cli_addr);
  
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    err(1, "can't open socket");
 
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
 
  int port = 8080;
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_addr.s_addr = INADDR_ANY;
  srv_addr.sin_port = htons(port);
 
  if (bind(sock, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) == -1) {
    close(sock);
    err(1, "Can't bind");
  }
 
  listen(sock, 5);
  while (1) {
    client_fd = accept(sock, (struct sockaddr *) &cli_addr, &sin_len);
    printf("got connection\n");
 
    if (client_fd == -1) {
      perror("Can't accept");
      continue;
    }
 
    write(client_fd, response, sizeof(response) - 1); /*-1:'\0'*/
    close(client_fd);
  }
}
