#define _GNU_SOURCE        /* See feature_test_macros(7). for accept4()*/
#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <zlib.h>

#include "prot.h"
#include "file_io.h"
#include "connections.h"
#include "string_manipulation.h"

char *connection_types[] = {"close", "keep-alive"};

//not all implemented (obviously)
char *one_hundreds[] = {"Continue", "Switching Protocols"};
char *two_hundreds[] = {"OK", "Created", "Accepted", 0, "No Content"};
char *three_hundreds[] = {0, "Moved Permanently", "Found", "See Other"};
char *four_hundreds[] = {"Bad Request", "Unauthorized", "Payment Required", "Forbidden", "Not Found"};
char *five_hundreds[] = {"Internal Server Error", "Not Implemented", "Bad Gateway"};
char **msd[] = {one_hundreds, two_hundreds, three_hundreds, four_hundreds, five_hundreds};


//blocking SSL_read but with attempt limit. If attempt limit is reached, the last SSL_read ret is returned
//max blocking timeout is (limit*5)us
int block_limit_read(SSL* cSSL, uint32_t limit, char* res_text, size_t res_text_size){
  uint32_t idx = 0;
  int ret = SSL_read(cSSL, res_text, res_text_size);
  int errtype = SSL_get_error(cSSL, ret);
  while(errtype == SSL_ERROR_WANT_READ && idx < limit){ //we don't need to check ret as errtype will return a success macro if ret > 0 per docs
    usleep(5);
    ret = SSL_read(cSSL, res_text, res_text_size);
    errtype = SSL_get_error(cSSL, ret);
    idx++;
  }
  return ret;
}

//blocking SSL_write with attempt limit. See block_limit_read()
int block_limit_write(SSL *cSSL, uint32_t limit, char* buf, int buf_size){
  uint32_t idx = 0;
  int ret = SSL_write(cSSL, buf, buf_size);
  int errtype = SSL_get_error(cSSL, ret);
  while(errtype == SSL_ERROR_WANT_WRITE && idx < limit){
    usleep(5);
    ret = SSL_write(cSSL, buf, buf_size);
    errtype = SSL_get_error(cSSL, ret);
    idx++;
  }
  return ret;
}

//blocking SSL_accept() but with attempt limit. See block_limit_read()
int block_limit_accept(SSL* cSSL, uint32_t limit){
  uint32_t idx = 0;
  int ret = SSL_accept(cSSL);
  int errtype = SSL_get_error(cSSL, ret);
  while((errtype == SSL_ERROR_WANT_READ || errtype == SSL_ERROR_WANT_WRITE) && idx < limit){
    usleep(5); //is this portable enough? Without this, the busy loop can be quite taxing
    ret = SSL_accept(cSSL);
    errtype = SSL_get_error(cSSL, ret);
    idx++;
  }
  return ret;
}

void destroy_node(ll_node *node){
  char ignore[1024];
  int ssl_shutdown_retval = SSL_shutdown(node->cSSL);
  switch(ssl_shutdown_retval){
  case 0:
    //still needs to read from socket to complete bilateral shutdown
    fputs(INFO_PREPEND"shutdown not yet finished, reading from socket\n", stderr);
    uint32_t timeout = 300;
    int read_res = block_limit_read(node->cSSL, timeout, ignore, 1024);    //blocks while reading from ssl socket
    int ssl_error_code = SSL_get_error(node->cSSL, read_res);
    if(read_res <= 0 && ssl_error_code != SSL_ERROR_ZERO_RETURN){ //if no error or the "error" is that the peer closed, everything worked
      //SSL_ERROR_ZERO_RETURN = peer sent close_notify
      fputs(SSL_ERROR_PREPEND"couldn't read from unfinished ssl socket: ", stderr);
      print_SSL_errstr(ssl_error_code, stderr);
    }else
      fputs(INFO_PREPEND"shutdown completed\n", stderr);
  case 1: //successful shutdown
    break;
  default: //shutdown error
    fputs(SSL_ERROR_PREPEND"couldn't shut down ssl socket: ", stderr);
    print_SSL_errstr(SSL_get_error(node->cSSL, ssl_shutdown_retval), stderr);
  }

  SSL_free(node->cSSL);
  if(shutdown(node->fd, SHUT_RDWR)<0) perror(WARNING_PREPEND"couldn't shuttdown()");
  if(close(node->fd)<0) perror(WARNING_PREPEND"couldn't close()");
  free(node);
}

//opens a bound listening connection on port port. sockfd is the address of the callers socket, returns 0 for no error
int open_connection(int *sockfd, int port){
  struct sockaddr_in host_addr;
  //init socket
  *sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(*sockfd < 0)
    return -1;

  //socket options
  if(setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) != 0)
    perror("[NON-FATAL] couldn't set sockopt\n");

  //init address
  memset(&host_addr, 0, sizeof(struct sockaddr_in));
  host_addr.sin_family = AF_INET;
  host_addr.sin_port = htons(port); //host byte order (le) to network byte order (be)
  host_addr.sin_addr = (struct in_addr){INADDR_ANY};

  //bind address
  if(bind(*sockfd, (struct sockaddr *)&host_addr, sizeof(host_addr))!=0)
    return -1;


  //set socket to listening
  if(listen(*sockfd, QUEUE_LEN) != 0)
    return -1;
  return 0;
}

//checks poll for unsecured port and sends 301 message back
void unsecured_connection_handler(struct pollfd *poll_settings, char *hostname){
  struct sockaddr_in peer;
  socklen_t peer_size = sizeof(peer);
  int unsec_fd = accept4(poll_settings->fd, (struct sockaddr*)&peer, &peer_size, SOCK_NONBLOCK);
  char incoming_data[1024];
  http_request req = {0};
  unsigned int idx = 0, max_retries = 4000;
  int read_res;

  if(unsec_fd < 0){
    perror(ERROR_PREPEND"couldn't accept() unsecured conn");
    return;
  }

  //try to read up to max_retries times before failing
  read_res = read(unsec_fd, incoming_data, 1023);
  if(read_res<0
     && (errno == EAGAIN || errno == EWOULDBLOCK)
     && idx < max_retries){
    idx++;
    read_res = read(unsec_fd, incoming_data, 1023);
  }
  if(read_res<0){
    perror(ERROR_PREPEND"couldn't read() http conn");
    close(unsec_fd);
    return;
  }

  if(parse_first_line(&req, incoming_data)<0){
    fputs(ERROR_PREPEND"couldn't parse first line\n", stderr);
    close(unsec_fd);
    return;
  }

  snprintf(incoming_data, 1024, "%s%s", hostname, req.path);
  ll_node connection = {
    .fd = unsec_fd,
    .cSSL = NULL,
    .next = NULL
  };
  http_response res = {
    .response_code = 301,
    .location = incoming_data
  };
  if(send_http_response(&connection, &res) < 0)
    perror(ERROR_PREPEND"write");
  puts(WARNING_PREPEND"unsecured connection dealt with");
  close(unsec_fd);
  return;
}

char *http_codestr_from_code(uint16_t response_code){
  int response_cat = response_code - (response_code % 100);
  char *msg = msd[(response_cat/100)-1][response_code-response_cat];
  return msg;
}

size_t construct_headers(http_response *res, char *buffer, size_t buffer_len){
  const char *default_headers = "HTTP/1.1 %d %s\r\nConnection: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"; //headers that will always be sent
  size_t bytes_printed = snprintf(buffer, buffer_len, default_headers,
           res->response_code,
           http_codestr_from_code(res->response_code),
           connection_types[res->connection],
           res->content_type,
           res->content_length);

  if(res->response_code == 301)
    bytes_printed = snprintf(buffer, buffer_len-bytes_printed, "Location: %s\r\n", res->location);

  buffer[bytes_printed] = '\r';
  buffer[bytes_printed+1] = '\n';
  buffer[bytes_printed+2] = 0;

  return bytes_printed+2;
}


int send_http_response(ll_node* connection, http_response *res){
  char *buffer = malloc(res->content_length + 1024);
  size_t bytes_printed;
  /*
  unsigned long len = res->content_length;
  unsigned char *compressed_data = malloc(len);
  switch(compress(compressed_data, &len, (unsigned char*)res->body, res->content_length)){

  case Z_MEM_ERROR:
    fputs(ERROR_PREPEND"compression error: not enough memory\n", stderr);
    break;
  case Z_BUF_ERROR:
    fputs(ERROR_PREPEND"compression error: not enough output buffer\n", stderr);
    break;
  }
  */
  bytes_printed = construct_headers(res, buffer, res->content_length+1024);


  memcpy(buffer+bytes_printed, res->body, res->content_length);
  bytes_printed+=res->content_length;
  *(buffer+bytes_printed) = '\r';
  bytes_printed++;
  *(buffer+bytes_printed) = '\n';
  bytes_printed++;


  printf("response: %s", buffer);
  int bytes;
  if(connection->cSSL != NULL){
    //>0 OK. 0<= ERR
    bytes = block_limit_write(connection->cSSL, 800, buffer, bytes_printed);
    if(bytes <= 0){
      fputs(SSL_ERROR_PREPEND"couldn't SSL_write(): ", stderr);
      print_SSL_errstr(bytes, stderr);
    }
  }else{
    // nbytes OK. <0 ERR
    unsigned int idx = 0, max_retries = 2000;
    bytes = write(connection->fd, buffer, bytes_printed);
    if(bytes<0
       && (errno == EAGAIN || errno == EWOULDBLOCK)
       && idx < max_retries){
      idx++;
      bytes = write(connection->fd, buffer, bytes_printed);
   }
    if(bytes < 0)
      perror(ERROR_PREPEND"couldn't write()");
  }

  if(bytes != (int)bytes_printed)
    printf("%s ITS ALL FRIED, INCOMPLETE WRITE\n", ERROR_PREPEND);
  return bytes;
}

//handler function to accept new SSL connections and append them to the Lnked List
//returns 1 for new connection 0 for no new connection (so you can add it to a total)
//should the arguments be coalesced into a smaller list?
ll_node* new_ssl_connections(ll_node **tail, SSL_CTX *sslctx, int ssl_sockfd, struct pollfd *pfd){
  ll_node *node = malloc(sizeof(ll_node));
  int ssl_err;
  uint32_t timeout = 2000;

  node->peer_addr = malloc(sizeof(struct sockaddr_in));
  node->peer_size = sizeof(struct sockaddr_in);
  node->fd = accept4(ssl_sockfd, (struct sockaddr*)node->peer_addr, &node->peer_size, SOCK_NONBLOCK);
  if(node->fd < 0){
    perror(ERROR_PREPEND"accept");
    return NULL;
  }
  node->cSSL = SSL_new(sslctx);
  SSL_set_fd(node->cSSL, node->fd);

  ssl_err = block_limit_accept(node->cSSL, timeout); //accept new connections (limit blocking)
  if(ssl_err<=0){ //if ssl_accept had an error
    int errtype = SSL_get_error(node->cSSL, ssl_err);
    fputs(SSL_ERROR_PREPEND"could not accept(): ", stderr);
    print_SSL_errstr(errtype, stderr);
    destroy_node(node);
    return NULL;
  }

  node->requests = 0;
  node->conn_opened = time(NULL);
  node->next = NULL;
  (*tail)->next = node;
  pfd->fd = (*tail)->next->fd;
  pfd->events = POLLIN | POLLOUT;
  *tail = node;
  return node;
}
