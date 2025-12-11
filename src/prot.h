#ifndef MAIN_PROT
#define MAIN_PROT

//prot = short for prototype. for struct prototypes and clearly some other defines

#include <poll.h>
#include <openssl/ssl.h>

#include "tweakables.h"

#define VERSION_NUMBER "PWS 1.0.0-beta"

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define SOCKET_HTTP 0 //these two are for the pollfd array
#define SOCKET_HTTPS 1

#define CONNECTION_CLOSE 0
#define CONNECTION_KEEP_ALIVE 1

//content-encoding macros
#define CE_DEFLATE 0
#define CE_GZIP 1

#define SSL_ERROR_PREPEND "\x1B[1;31m[SSL_ERROR]\x1B[0m "
#define ERROR_PREPEND "\x1B[1;31m[ERROR]\x1B[0m "
#define WARNING_PREPEND "\x1B[1;33m[WARN]\x1B[0m "
#define INFO_PREPEND "\x1B[1;36m[INFO]\x1B[0m "

typedef struct{
  char *private_key_path;
  char *certificate_path;
  char *fullchain_path;
  char *hostname;
  char *document_root;
  unsigned int hostname_len;
}config;

typedef struct{
  config cfg;
  int clients_connected;
  struct pollfd listener_sockets[2];
  struct pollfd secured_sockets[CLIENTS_MAX];
}program_context;

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
  char method[HTTP_REQ_OBJ_METHOD_SIZE];
  char *path;
  uint8_t connection;
  char *host;
}http_request;

typedef struct{
  uint16_t response_code;
  size_t content_length;
  uint8_t connection;
  char *content_type;
  char *location;
  char *content_encoding;
  char *body;
}http_response;

typedef struct{
  char *file_path;
  char *mimetype;
  char *data;
  long length;
  char *compressed_data;
  long compressed_length;
  uint8_t compression_type; //for future expansion, not used currently
}loaded_file;

typedef struct {
    char *ext;
    char *mime;
} mime_type_t;

#endif
