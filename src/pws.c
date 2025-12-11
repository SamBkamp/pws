#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <zlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "prot.h"
#include "file_io.h"
#include "string_manipulation.h"
#include "connections.h"

//I reckon this implementation might be temporary
#define MAX_OPEN_FILES 20

static mime_type_t mime_types[] = {
    {"html", "text/html; charset=utf-8"},
    {"htm",  "text/html; charset=utf-8"},
    {"css",  "text/css; charset=utf-8"},
    {"js",   "application/javascript"},
    {"json", "application/json"},
    {"png",  "image/png"},
    {"jpg",  "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"gif",  "image/gif"},
    {"webp", "image/webp"},
    {"svg",  "image/svg+xml"},
    {"ico",  "image/x-icon"},
    {"txt",  "text/plain; charset=utf-8"},
    {"pdf",  "application/pdf"},
    {"zip",  "application/zip"},
    {"wasm", "application/wasm"},
    {NULL,   "application/octet-stream"}  // default + sentinel
};


loaded_file *files;

//dumps buffered stdout to stdout
//i think this is threadsafe
void dump_logs(int sig){
  if(sig == SIGUSR1)
    fflush(stdout);
}

int compress_file_data(loaded_file *lf){
  unsigned long compressed_data_len = lf->length;
  unsigned char *compressed_data = malloc(compressed_data_len);
  int deflate = compress(compressed_data,
                         &compressed_data_len,
                         (unsigned char*)lf->data,
                         lf->length);
  switch(deflate){
  case Z_MEM_ERROR:
  case Z_BUF_ERROR:
    lf->compressed_data = NULL;
    lf->compressed_length = 0;
    free(compressed_data);
    return deflate;
    break;
  default:
    lf->compressed_data = (char*)compressed_data;
    lf->compressed_length = compressed_data_len;
    break;
  }
  return 0;
}


//file handler: handles file loading and caching. Simply returns file contents. Lazy loads into the cache
loaded_file *get_file_data(char* path){
  loaded_file *found_file = files;
  struct stat sb;

  //check if file even exists, quick return if no. not checking all errno bc regardless of what errno, this function cannot/should not continue
  if(stat(path, &sb) < 0)
    return (loaded_file *)-1;

  while((found_file-files) < MAX_OPEN_FILES
        && found_file->file_path != NULL
        && strcmp(found_file->file_path, path)!=0)
    found_file++;

  //cached file hit
  if((found_file-files) < MAX_OPEN_FILES
     && found_file->file_path != NULL)
    return found_file;

  //cache miss
  long file_length = sb.st_size; //stop re-lookup of file info
  char *file_data  = open_file(path, &file_length);
  //either not found or other mapping/IO failure
  //TODO: let errno propagate explicitly
  if(file_data == MAP_FAILED)
    return (loaded_file *)-1;

  //if file found by while loop returns a non-empty loaded_file, we exhausted the cache and must wrap around
  if(found_file->file_path != NULL){
    fputs(WARNING_PREPEND"File cache full, wrap around\n", stderr);
    for(loaded_file *current_file = files; current_file->file_path != NULL && (current_file-files) < MAX_OPEN_FILES; current_file++){
      printf("%s |", current_file->file_path);
    }
    free(files[0].file_path);
    munmap(files[0].data, files[0].length);
    if(files[0].compressed_data != NULL)
      free(files[0].compressed_data);
    found_file = &files[0];
  }


  found_file->length = file_length;
  found_file->data = file_data;

  //can I store file name data in mmap region? ie say the file is only 3kb large, I still have another 1kb of unused page. Can I store metadata there?
  found_file->file_path = malloc(strlen(path)+1);
  strcpy(found_file->file_path, path);
  char *file_type = get_file_type(path);
  mime_type_t *type;
  for(type = mime_types; type->ext != NULL; type++){
    if(strcmp(type->ext, file_type) == 0)
      break;
  }
  found_file->mimetype = type->mime;
  //only compress files if they are text
  if(strncmp(found_file->mimetype, "text", 4)==0){
    if(compress_file_data(found_file)!=0)
      fprintf(stderr, ERROR_PREPEND"unable to compress %s\n", found_file->file_path);
  }

  return found_file;
}


//takes a request struct and sends back appropriate data to client
//the http workhorse
// returns 0 if successfully handled valid request
//returns -1 if connection is to be closed
ssize_t requests_handler(http_request *req, http_response *res, ll_node *conn_details, config *cfg){
  size_t file_path_size = strlen(cfg->document_root) + strlen(req->path) + 20;
  char file_path[file_path_size];
  loaded_file *file_data;
  size_t content_len; //only used for calls to generate_error()

  res->response_code = 200; //default

  if(++conn_details->requests > KEEP_ALIVE_MAX_REQ)
    res->connection = CONNECTION_CLOSE;
  else
    res->connection = req->connection;

  //second condition is to check for www. connections (but currently accepts  first 4 chars lol) TODO: fix this
  //check if hostname header is valid
  if(strncmp(req->host, cfg->hostname, cfg->hostname_len) != 0
     && strncmp(req->host+4, cfg->hostname, cfg->hostname_len) != 0){
    res->response_code = 301;
    res->location = cfg->hostname;
  }

  //sanitize path
  if(format_dirs(req->path, file_path, file_path_size, cfg->document_root) == NULL)
    res->response_code = 403;
  else{//valid path
    file_data = get_file_data(file_path);
    //file can't be opened
    if(file_data == (loaded_file *)-1)
      res->response_code = 404;
  }


  if(res->response_code != 200){
    res->connection = CONNECTION_CLOSE;
    res->body = generate_error(res->response_code, &content_len);
    res->content_length = content_len;
    res->content_type = "text/html";
    send_http_response(conn_details, res);
    free(res->body);
    return -1;
  }

  //if file is valid and openable
  //check if data has compressed version, send that if available
  if(file_data->compressed_data != NULL){
    res->body = file_data->compressed_data;
    res->content_length = file_data->compressed_length;
    res->content_encoding = encoding_types[CE_DEFLATE];
  }else{
    res->body = file_data->data;
    res->content_length = file_data->length;
  }
  res->content_type = file_data->mimetype;
  send_http_response(conn_details, res);
  return 0;
}



uint8_t connections_handler(program_context *ctx, ll_node *node, http_request *req, http_response *res, int connection_index){
  char buffer[2048], *ip_str;
  int bytes_read;
  struct pollfd connection_pollfd = ctx->secured_sockets[connection_index];

  //socket hung up or error'd
  if((connection_pollfd.revents & POLLHUP) > 0
     || (connection_pollfd.events & POLLERR) > 0)
    return 0;

  //no data ready
  if((connection_pollfd.revents & POLLIN) == 0)
    return 1;


  bytes_read = block_limit_read(node->cSSL, 800, buffer, 2047);
  buffer[bytes_read] = 0;
  //couldn't read data
  if(bytes_read <= 0){
    fputs(SSL_ERROR_PREPEND"couldn't read() from client socket", stderr);
    print_SSL_errstr(SSL_get_error(node->cSSL, bytes_read), stderr);
    return 0;
  }

  //could read but couldn't parse
  if(parse_http_request(req, buffer) < 0
           || req->path == NULL
           || req->host == NULL){
    printf("%s malformed query sent. length: %d\n", WARNING_PREPEND, bytes_read);
    return 0;
  }
  ip_str = long_to_ipstr(node->peer_addr->sin_addr.s_addr);
  //everything has gone right
  printf("[%s-%d-%d/%d] method: %s | path: %s | host: %s | connection: %s\n",
         ip_str,
         node->fd,
         connection_index+1, //connection_index starts at 0
         ctx->clients_connected,
         req->method,
         req->path,
         req->host,
         connection_types[req->connection]);
  free(ip_str);

  requests_handler(req, res, node, &ctx->cfg);
  return req->connection & res->connection; //make sure both the client (req) and the server (res) want to keep-alive
}


int pws(){
  puts(VERSION_NUMBER);
  fputs("zlib ", stdout);
  puts(zlibVersion());
  puts(OPENSSL_VERSION_TEXT);
  program_context p_ctx = {0};
  int ssl_sockfd, unsecured_sockfd;
  ll_node head = {
    .fd = 0,
    .next = NULL
  };
  ll_node *tail = &head;

  //ignore sigpipe errors. They still need to be handled locally but at least this will stop the program from crashing
  signal(SIGPIPE, SIG_IGN);

  if(load_config(&p_ctx.cfg)<0){
    fputs(WARNING_PREPEND"could not load config file\n", stderr);
    return 1;
  }

  signal(SIGUSR1, dump_logs);

  files = malloc(sizeof(loaded_file)*MAX_OPEN_FILES);
  for(size_t i = 0; i < MAX_OPEN_FILES; i++){
    files[i].file_path = NULL;
    files[i].data = NULL;
  }

  //load openSSL nonsense (algos and strings)
  OpenSSL_add_all_algorithms();  //surely this can be changed to load just the ones we want?
  SSL_load_error_strings();
  SSL_library_init();

  //set up SSL context for all connections
  SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method()); //create new ssl context
  SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE); //using single diffie helman, I guess?
  int use_cert = SSL_CTX_use_certificate_file(sslctx, p_ctx.cfg.certificate_path, SSL_FILETYPE_PEM);
  int use_prv_key = SSL_CTX_use_PrivateKey_file(sslctx, p_ctx.cfg.private_key_path, SSL_FILETYPE_PEM);
  int use_chain = SSL_CTX_use_certificate_chain_file(sslctx, p_ctx.cfg.fullchain_path);

  if(use_cert != 1 || use_prv_key != 1){
    fputs(SSL_ERROR_PREPEND"could not load certificate or private key\n", stderr);
    return 1;
  }

  if(use_chain != 1)
    fputs(WARNING_PREPEND"not using certificate chain\n", stdout);

  //opens socket, binds to address and sets socket to listening
  if(open_connection(&ssl_sockfd, HTTPS_PORT) != 0){
    perror("open_connection SSL");
    return 1;
  }
  printf(INFO_PREPEND"SSL port opened on %d\n", HTTPS_PORT);

  if(open_connection(&unsecured_sockfd, HTTP_PORT) != 0){
    perror("open_connection unsecured");
    return 1;
  }
  printf(INFO_PREPEND"unsecured port opened on %d\n", HTTP_PORT);

  p_ctx.listener_sockets[SOCKET_HTTP] = (struct pollfd){
    .fd = unsecured_sockfd,
    .events = POLLIN | POLLOUT
  };
  p_ctx.listener_sockets[SOCKET_HTTPS] = (struct pollfd){
    .fd = ssl_sockfd,
    .events = POLLIN | POLLOUT
  };


  //main event loop
  while(1){
    int ret_poll = poll(p_ctx.listener_sockets, 2, POLL_TIMEOUT);

    if(ret_poll == 0) //no new events
      goto handle_existing_connections; //skip the listener socket handlers (this is probably bad)

    if((p_ctx.listener_sockets[SOCKET_HTTP].revents & POLLIN) > 0)
      unsecured_connection_handler(&p_ctx.listener_sockets[0], p_ctx.cfg.hostname);

    //check for and then set up new connections
    if(p_ctx.clients_connected < CLIENTS_MAX
       && (p_ctx.listener_sockets[SOCKET_HTTPS].revents & POLLIN) > 0
       && new_ssl_connections(&tail, sslctx, ssl_sockfd, &p_ctx.secured_sockets[p_ctx.clients_connected]) != NULL)
      ++p_ctx.clients_connected;

    //reached client connected max
    if(p_ctx.clients_connected >= CLIENTS_MAX)
      fputs(INFO_PREPEND"reached connected client max\n", stderr);

  handle_existing_connections:
    ret_poll = poll(p_ctx.secured_sockets, p_ctx.clients_connected, POLL_TIMEOUT);
    if(ret_poll<0){
      perror(ERROR_PREPEND"poll failure");
      continue;
    }
    uint16_t connection_index = 0;
    ll_node *prev_conn = &head;
    for(ll_node *conn = head.next; conn != NULL; prev_conn = conn, conn = conn->next){
      http_request req = {0};
      http_response res = {0};
      uint8_t keep_alive_flag = connections_handler(&p_ctx, conn, &req, &res, connection_index);
      free_http_request(&req);

      //only skip the connection closing if both the client and the server want to keep the connection alive AND the connection hasn't timedout
      if(((time(NULL) - conn->conn_opened) < KEEP_ALIVE_TIMEOUT) && keep_alive_flag > 0){
        connection_index++;
        continue;
      }

      //close connection and remove from LL
      prev_conn->next = conn->next;
      if(prev_conn->next == NULL) tail = prev_conn; //update tail if needed
      destroy_node(conn);
      conn = prev_conn;
      p_ctx.clients_connected--;
      //remove fd from pollfd array by moving all subsequent items down one (this shouldnt out of bounds bc in the case where connection_index+1 = out of bounds, last argument is 0)
      memmove(&p_ctx.secured_sockets[connection_index],
              &p_ctx.secured_sockets[connection_index+1],
              sizeof(struct pollfd) * (p_ctx.clients_connected-connection_index));
    }
  }
  //shouldnt reach here
  SSL_CTX_free(sslctx);
}
