#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "config.h"
#include "prot.h"
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


void destroy_node(ll_node *node){
  char ignore[1024];
  int ssl_shutdown_retval = SSL_shutdown(node->cSSL);
  switch(ssl_shutdown_retval){
  case 0:
    fputs(INFO_PREPEND"shutdown not yet finished, reading from socket", stderr);
    SSL_read(node->cSSL, ignore, 1024);
  case 1:
    break;
  default:
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

void check_unsec_connection(struct pollfd *poll_settings){
  struct sockaddr_in peer;
  socklen_t peer_size = sizeof(peer);
  if((poll_settings->revents & POLLIN) > 0){
    int unsec_fd = accept(poll_settings->fd, (struct sockaddr*)&peer, &peer_size);
    char incoming_data[1024];
    http_request req = {0};
    read(unsec_fd, incoming_data, 1023);
    if(parse_first_line(&req, incoming_data)<0){
      fputs(ERROR_PREPEND"couldn't parse first line\n", stderr);
      close(unsec_fd);
      return;
    }

    snprintf(incoming_data, 1024, "%s%s", HOST_NAME, req.path);
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
      perror("write");
    puts(WARNING_PREPEND"unsecured connection dealt with");
    close(unsec_fd);
    return;
  }
}

int send_http_response(ll_node* connection, http_response *res){
  char *buffer = malloc(res->content_length + 1024);
  size_t bytes_printed;
  //response category (ie. first digit of response code)
  int response_cat = res->response_code - (res->response_code % 100);
  switch (response_cat){
  case 300:
    bytes_printed = sprintf(buffer, "HTTP/1.1 %d %s\r\nLocation: https://%s\r\nConnection: %s\r\n\r\n", res->response_code, msd[2][res->response_code-response_cat], res->location, connection_types[res->connection]);
    break;
  default:
    bytes_printed = sprintf(buffer, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length:%ld\r\nConnection: %s\r\n\r\n", res->response_code, msd[(response_cat/100)-1][res->response_code-response_cat], res->content_type, res->content_length, connection_types[res->connection]);
    memcpy(buffer+bytes_printed, res->body, res->content_length);
    bytes_printed+=res->content_length;
    *(buffer+bytes_printed) = '\r';
    bytes_printed++;
    *(buffer+bytes_printed) = '\n';
    bytes_printed++;
    break;
  }

  int bytes;
  if(connection->cSSL != NULL)
    bytes = SSL_write(connection->cSSL, buffer, bytes_printed);
  else
    bytes = write(connection->fd, buffer, bytes_printed);

  if(bytes != (int)bytes_printed)
    printf("%s ITS ALL FRIED, INCOMPLETE WRITE\n", ERROR_PREPEND);
  return bytes;
}

//handler function to accept new SSL connections and append them to the Lnked List
//returns 1 for new connection 0 for no new connection (so you can add it to a total)
ll_node* new_ssl_connections(struct pollfd *poll_settings, ll_node *tail, SSL_CTX *sslctx, int ssl_sockfd){
  if((poll_settings->revents & POLLIN) > 0){
    int ssl_err;
    ll_node *node = malloc(sizeof(ll_node));
    node->peer_addr = malloc(sizeof(struct sockaddr_in));
    node->peer_size = sizeof(struct sockaddr_in);
    node->fd = accept(ssl_sockfd, (struct sockaddr*)node->peer_addr, &node->peer_size);
    if(node->fd < 0){
      perror("accept");
      return NULL;
    }
    node->cSSL = SSL_new(sslctx);
    SSL_set_fd(node->cSSL, node->fd);
    ssl_err = SSL_accept(node->cSSL);
    if(ssl_err <= 0){
      //i HATE openssl error handling
      fputs(SSL_ERROR_PREPEND, stdout);
      print_SSL_errstr(SSL_get_error(node->cSSL, ssl_err), stderr);
      destroy_node(node);
      return NULL;
    }
    node->requests = 0;
    node->conn_opened = time(NULL);
    node->next = NULL;
    tail->next = node;
    return tail->next;
  }
  return NULL;
}
