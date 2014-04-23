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
  int nrounds = 5;
  unsigned char key[32];
  unsigned char iv[32];
  int x = 0;
  int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  
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
  
unsigned char*aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *pt, int *len){
  int c_len = *len + AES_BLOCK_SIZE - 1;
  int f_len = 0;
  unsigned char *ciphertext = (unsigned char *)malloc(c_len);
 
  /* allows reusing of 'e' for multiple encryption cycles */
  if(!EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL)){
    printf("ERROR in EVP_EncryptInit_ex \n");
    return NULL;
  }
 
  /* update ciphertext, c_len is filled with the length of ciphertext generated,
   *len is the size of plaintext in bytes */
  if(!EVP_EncryptUpdate(e, ciphertext, &c_len, pt, *len)){
    printf("ERROR in EVP_EncryptUpdate \n");
    return NULL;
  }
 
  /* update ciphertext with the final remaining bytes */
  if(!EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len)){
    printf("ERROR in EVP_EncryptFinal_ex \n");
    return NULL;
  }
 
  *len = c_len + f_len;
  return ciphertext;
}
unsigned char*aes_decrypt(EVP_CIPHER_CTX*e, unsigned char *ct, int *len){
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *pt = (unsigned char *)malloc(p_len);
 
  if(!EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL)){
    printf("ERROR in EVP_DecryptInit_ex \n");
    return NULL;
  }
 
  if(!EVP_DecryptUpdate(e, pt, &p_len, ct, *len)){
    printf("ERROR in EVP_DecryptUpdate\n");
    return NULL;
  }
 
  if(!EVP_DecryptFinal_ex(e, pt+p_len, &f_len)){
    printf("ERROR in EVP_DecryptFinal_ex\n");
    return NULL;
  }
 
  *len = p_len + f_len;
  return pt;
}

int main(void){
  int one = 1, client_fd;
  struct sockaddr_in srv_addr, cli_addr;
  socklen_t sin_len = sizeof(cli_addr);
  char*revc_buffer = (char*) malloc(sizeof(char)*100);
  int recv_len = 0;
  int sock = socket(AF_INET, SOCK_STREAM, 0);

  unsigned char* p_substring_begin;
  unsigned char* p_substring_end;

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
    recv_len = recvfrom(client_fd, revc_buffer, 100, 0,(struct sockaddr*)&cli_addr, &sin_len);
    revc_buffer[recv_len] = 0;
    p_substring_begin = strstr(revc_buffer, "enc=");
    printf("%s", p_substring_begin);
    if(p_substring_begin != 0){
      p_substring_end = strstr(p_substring_begin, " ");
      int n_bytes = p_substring_end - p_substring_begin;      
      printf("%d", n_bytes);
      printf("found foundsubstring");
      printf("%s", p_substring_begin);
    }
    printf(revc_buffer);
    close(client_fd);
  }
  free(revc_buffer);
}
