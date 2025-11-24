#ifndef MAIN_PROT
#define MAIN_PROT
#include <openssl/ssl.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define CLIENTS_MAX 10
#define QUEUE_LEN 10
#define POLL_TIMEOUT 50
#define METHOD_GET 1
#define METHOD_POST 2

#define CONNECTION_CLOSE 0
#define CONNECTION_KEEP_ALIVE 1

#define KEEP_ALIVE_MAX_REQ 4
#define KEEP_ALIVE_TIMEOUT 20 //in seconds

#define SSL_ERROR_PREPEND "\x1B[1;31m[SSL_ERROR]\x1B[0m "
#define ERROR_PREPEND "\x1B[1;31m[ERROR]\x1B[0m "
#define WARNING_PREPEND "\x1B[1;33m[WARN]\x1B[0m "

#define LOG_FILE "pws.log"
#define ERROR_FILE "pws_error.log"


typedef struct{
  uint8_t daemonize;
}prog_opts;

typedef struct ll_node{
  uint8_t requests;
  time_t conn_opened;
  struct sockaddr_in *peer_addr;
  socklen_t peer_size;
  int fd;
  SSL *cSSL;
  struct ll_node *next;
}ll_node;


typedef struct{
  char method[10];
  char *path;
  uint8_t connection;
  char *host;
}http_request;

typedef struct{
  uint16_t response_code;
  char *content_type;
  size_t content_length;
  char *location;
  char *body;
  uint8_t connection;
}http_response;

typedef struct{
  char *file_path;
  char *mimetype;
  char *data;
  long length;
}loaded_file;

typedef struct{
  loaded_file *loaded_files;
  loaded_file *not_found;
  loaded_file *internal_server_error;
}root_file_data;

typedef struct {
    char *ext;
    char *mime;
} mime_type_t;
#endif
