#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

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


root_file_data files;

//dumps buffered stdout to stdout
//i think this is threadsafe
void dump_logs(int sig){
  if(sig == SIGUSR1)
    fflush(stdout);
}

//file handler: handles file loading and caching. Simply returns file contents. Lazy loads into the cache
loaded_file *get_file_data(char* path){
  loaded_file *found_file = files.loaded_files;
  struct stat sb;

  //check if file even exists, quick return if no. not checking all errno bc regardless of what errno, this function cannot/should not continue
  if(stat(path, &sb) < 0)
    return (loaded_file *)-1;

  while((found_file-files.loaded_files) < MAX_OPEN_FILES
        && found_file->file_path != NULL
        && strcmp(found_file->file_path, path)!=0)
    found_file++;

  //cached file hit
  if((found_file-files.loaded_files) < MAX_OPEN_FILES
     && found_file->file_path != NULL)
    return found_file;

  //cache miss
  long file_length = sb.st_size; //stop re-lookup of file info
  char *file_data  = open_file(path, &file_length);
  //either not found or other mapping/IO failure
  //TODO: let errno propagate explicitly
  if(file_data == MAP_FAILED)
    return (loaded_file *)-1;

  loaded_file *new_load = found_file;

  //if file found by while loop returns a non-empty loaded_file, we exhausted the cache and must wrap around
  if(found_file->file_path != NULL){
    fputs(WARNING_PREPEND"File cache full, wrap around\n", stderr);
    for(loaded_file *current_file = files.loaded_files; current_file->file_path != NULL && (current_file-files.loaded_files) < MAX_OPEN_FILES; current_file++){
      printf("%s |", current_file->file_path);
    }
    free(files.loaded_files[0].file_path);
    munmap(files.loaded_files[0].data, files.loaded_files[0].length);
    new_load = &files.loaded_files[0];
  }


  new_load->length = file_length;
  new_load->data = file_data;

  //can I store file name data in mmap region? ie say the file is only 3kb large, I still have another 1kb of unused page. Can I store metadata there?
  new_load->file_path = malloc(strlen(path)+1);
  strcpy(new_load->file_path, path);
  char *file_type = get_file_type(path);
  mime_type_t *type;
  for(type = mime_types; type->ext != NULL; type++){
    if(strcmp(type->ext, file_type) == 0)
      break;
  }
  new_load->mimetype = type->mime;
  return new_load;
}


//takes a request struct and sends back appropriate data to client
//the http workhorse
// returns 0 if successfully handled valid request
//returns -1 if connection is to be closed
ssize_t requests_handler(http_request *req, http_response *res, ll_node *conn_details, config *cfg){
  if(++conn_details->requests > KEEP_ALIVE_MAX_REQ)
    res->connection = CONNECTION_CLOSE;
  else
    res->connection = req->connection;
  //check if host is valid
  if(strncmp(req->host, cfg->hostname, cfg->hostname_len) != 0
     && strncmp(req->host+4, cfg->hostname, cfg->hostname_len) != 0){ //second condition is to check for www. connections (but currently accepts  first 4 chars lol) TODO: fix this
    res->response_code = 301;
    res->location = cfg->hostname;
    res->connection = CONNECTION_CLOSE;
    send_http_response(conn_details, res);
    return -1;
  }
  //open file
  char file_path[strlen(cfg->document_root) + strlen(req->path) + 20];
  format_dirs(req->path, file_path, cfg->document_root);
  loaded_file *file_data = get_file_data(file_path);

  //file can't be opened for one reason or another
  if(file_data == (loaded_file *)-1 || *file_path == (char)-1){
    res->response_code = 404;
    res->body = files.not_found->data;
    res->content_length = files.not_found->length;
    res->content_type = "text/html";
    send_http_response(conn_details, res);
    return 0;
  }
  //if file is valid and openable
  res->response_code = 200;
  res->content_type = file_data->mimetype;
  res->content_length = file_data->length;
  res->body = file_data->data;
  send_http_response(conn_details, res);
  return 0;
}



uint8_t handle_connection(struct pollfd *pfd, ll_node *node, http_request *req, http_response *res, int connection_index, int clients_connected, config *cfg){
  char buffer[2048], ip_string[20];
  int bytes_read;
  //socket hung up or error'd
  if((pfd->revents & POLLHUP) > 0
     || (pfd->events & POLLERR) > 0)
    return 0;

  //no data ready
  if((pfd->revents & POLLIN) == 0)
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

  //everything has gone right
  printf("[%s-%d-%d/%d] method: %s | path: %s | host: %s | connection: %s\n",
         long_to_ip(ip_string, node->peer_addr->sin_addr.s_addr),
         node->fd,
         connection_index+1, //connection_index starts at 0
         clients_connected,
         req->method,
         req->path,
         req->host,
         connection_types[req->connection]);

  requests_handler(req, res, node, cfg);
  return req->connection & res->connection; //make sure both the client (req) and the server (res) want to keep-alive
}


int pws(){
  config cfg = {0};
  int ssl_sockfd, unsecured_sockfd, clients_connected = 0;
  struct pollfd listener_sockets[2], secured_sockets[CLIENTS_MAX];
  ll_node head = {
    .fd = 0,
    .next = NULL
  };
  ll_node *tail = &head;

  if(load_config(&cfg)<0){
    fputs(WARNING_PREPEND"could not load config file\n", stderr);
    return 1;
  }

  signal(SIGUSR1, dump_logs);

  files.loaded_files = malloc(sizeof(loaded_file)*MAX_OPEN_FILES);
  for(size_t i = 0; i < MAX_OPEN_FILES; i++){
    files.loaded_files[i].file_path = NULL;
    files.loaded_files[i].data = NULL;
  }

  //load default files into memory. Doesn't abort - should it?
  if(load_default_files(&files) == -1)
    perror(WARNING_PREPEND"Couldn't load 404/500 error files");

  //load openSSL nonsense (algos and strings)
  OpenSSL_add_all_algorithms();  //surely this can be changed to load just the ones we want?
  SSL_load_error_strings();
  SSL_library_init();

  //set up SSL context for all connections
  SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method()); //create new ssl context
  SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE); //using single diffie helman, I guess?
  int use_cert = SSL_CTX_use_certificate_file(sslctx, cfg.certificate_path, SSL_FILETYPE_PEM);
  int use_prv_key = SSL_CTX_use_PrivateKey_file(sslctx, cfg.private_key_path, SSL_FILETYPE_PEM);
  int use_chain = SSL_CTX_use_certificate_chain_file(sslctx, cfg.fullchain_path);

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

  listener_sockets[0] = (struct pollfd){
    .fd = unsecured_sockfd,
    .events = POLLIN | POLLOUT
  };
  listener_sockets[1] = (struct pollfd){
    .fd = ssl_sockfd,
    .events = POLLIN | POLLOUT
  };


  //main event loop
  while(1){
    int ret_poll = poll(listener_sockets, 2, POLL_TIMEOUT);
    //checks poll for unsecured port and sends 301 message back
    check_unsec_connection(&listener_sockets[0], cfg.hostname);

    //check for and then set up new connections
    if(clients_connected < CLIENTS_MAX
       && ret_poll > 0
       && (listener_sockets[1].revents & POLLIN) > 0
       && new_ssl_connections(&tail, sslctx, ssl_sockfd, &secured_sockets[clients_connected]) != NULL)
      ++clients_connected;

    //reached client connected max
    if(clients_connected >= CLIENTS_MAX)
      fputs(INFO_PREPEND"reached connected client max\n", stderr);



    //poll existing connections
    ret_poll = poll(secured_sockets, clients_connected, POLL_TIMEOUT);
    if(ret_poll<0){
      fputs(ERROR_PREPEND"poll failure\n", stderr);
      continue;
    }
    if(ret_poll == 0) //no fd ready
      continue;

    //service existing connections
    uint16_t connection_index = 0;
    ll_node *prev_conn = &head;
    for(ll_node *conn = head.next; conn != NULL; prev_conn = conn, conn = conn->next){
      http_request req = {0};
      http_response res = {0};
      uint8_t keep_alive_flag = handle_connection(&secured_sockets[connection_index], conn, &req, &res, connection_index, clients_connected, &cfg);

      //only skip the connection closing if both the client and the server want to keep the connection alive AND the connection hasn't timedout
      if(((time(NULL) - conn->conn_opened) < KEEP_ALIVE_TIMEOUT) && keep_alive_flag > 0){
        connection_index++;
        continue;
      }

      //close connection and remove from LL
      prev_conn->next = conn->next;
      if(prev_conn->next == NULL) tail = prev_conn; //update tail if needed
      destroy_node(conn);
      free_http_request(&req);
      conn = prev_conn;
      clients_connected--;
      //remove fd from pollfd array by moving all subsequent items down one (this shouldnt out of bounds bc in the case where connection_index+1 = out of bounds, last argument is 0)
      memmove(&secured_sockets[connection_index], &secured_sockets[connection_index+1], sizeof(struct pollfd) * (clients_connected-connection_index));
    }
  }
  SSL_CTX_free(sslctx);
}

//make sure out output buffers get flushed
void sig_handler(int sig){
  exit(sig);
}


void fork_worker(const char *path){
  //create new session and become session leader (with no tty)
  setsid();
  //if we wanted to, we could fork again here to make sure we don't reaquire a tty

  //set our chroot (not 100% secure, but this isn't a security feature, just a pragmatic one so we don't block other drives from being unmounted)
  if(chroot(path) < 0 ){
    perror("chroot");
    fputs("bailing\n", stderr);
    return;
  }

  umask(000);

  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
  freopen(LOG_FILE, "w", stdout);
  freopen(ERROR_FILE, "w", stderr);

  //ignore sigpipe errors. They still need to be handled locally but at least this will stop the program from crashing
  signal(SIGPIPE, SIG_IGN);
  //make sure buffer is flushed when signal arrives
  signal(SIGINT, sig_handler);
  signal(SIGABRT, sig_handler);
  signal(SIGTERM, sig_handler);
  signal(SIGSEGV, sig_handler);


  //all done! ready to work
  puts("daemonization successful");
  pws();
}


int main(int argc, char *argv[]){
  prog_opts opts = {0};
  for(uint8_t i = 1; i < argc; i++){
    if(strcmp(argv[i], "--daemonize")==0){
      opts.daemonize = 1;
      break;
    }
  }
  if(opts.daemonize == 1){
    char cwd[1024];
    pid_t f_res;
    if(getcwd(cwd, 1024)==NULL){
      fputs("I couldn't figure out where we are. Did you run me as root?\n", stderr);
      return 1;
    }
    f_res = fork();

    switch(f_res){
    case -1:
      perror("fork");
      return 1;
    case 0: //child
      fork_worker(cwd);
      break;
    default:
      sleep(1); //<- hold terminal open so child can print to stderr if init fails
      printf("child started: [%d]\n", f_res);
      break;
    }
  }
  else{
    puts("running as foreground application");
    return pws();
  }
}
