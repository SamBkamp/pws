#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <poll.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "prot.h"
#include "string_manipulation.h"
#include "file_io.h"
#include "connections.h"

char *map[HASH_MAP_SIZE] = {NULL};

uint8_t calculate_hash(const char* str){
  uint16_t temp_hash = 0;
  size_t len = strlen(str);
  for(size_t i = 0; i < len; i++){
    temp_hash += (str[i]^len); //literally just vibes
  }
  return temp_hash & (HASH_MAP_SIZE-1);
}

int load_blacklink_map(char **token_list){
  uint16_t idx = 0;
  char *current_token = token_list[idx];
  while(current_token){
    uint16_t loc = calculate_hash(current_token);
    if(map[loc] == NULL){
      map[loc] = current_token;
    }else{
      return -1;
    }
    current_token = token_list[++idx];
  }
  return 0;
}

int query_map(char *path){
  char *entry = map[calculate_hash(path)];
  if(entry != NULL && strcmp(entry, path)==0)
    return 0;
  return -1;
}


//takes a string and turns all characters into lowercase. Destructive. ONLY FOR ASCII
char *all_to_upper(char *str){
  const uint8_t mask = ~(1<<5); // 0b001111111
  for(size_t i = 0; i < strlen(str); i++){
    if(str[i] > 0x40 && str[i] < 0x7a)
      str[i] &= mask;
  }
  return str;
}

char *all_to_lower(char *str){
  const uint8_t mask = (1<<5); // 0b00100000
  for(size_t i = 0; i < strlen(str); i++){
    if(str[i] > 0x40 && str[i] < 0x7a)
      str[i] |= mask;
  }
  return str;
}


//function that sanitises and turns the http path into a file path on the system
//retpath should be strlen(document_root) + strlen(path) + 20
//returns ret_path (which contains the sanitised path) if valid path or returns NULL if fatally invalid
char *format_dirs(char *path, char *ret_path, size_t ret_path_size,char *document_root){
  char append[20], *offset;
  int dots;
  //append index.html to the path if the path ends in a '/'
  if(path[strlen(path)-1] == '/')
    sprintf(append, "index.html");
  else
    *append = 0;
  //combine document_root + path + optional append
  snprintf(ret_path, ret_path_size, "%s%s%s", document_root, path, append);

  //check if path is valid (doesn't contain ../ in it)
  dots = 0;
  offset = ret_path;
  while(*offset != 0){
    if(*offset == '.')
      dots++;
    else if(*offset == '/' && dots > 1){ // <- invalid condition, return error
      *ret_path = (char)-1;
      return NULL;
      break;
    }else
      dots = 0;
    offset++;
  }
  return ret_path;
}

//helper function that turns an SSL error code into text. I could use built-in SSL error functions but its so complex and requires like 7 different function calls. This is good enough.
void print_SSL_errstr(int SSL_err, FILE* stream){
  switch(SSL_err){
  case SSL_ERROR_ZERO_RETURN:
    fputs("Connection close by peer: sent close_notify\n", stream);
    break;
  case SSL_ERROR_WANT_READ:
    fputs("Operation did not complete (wants to read), can be retried later\n", stream);
    break;
  case SSL_ERROR_WANT_WRITE:
    fputs("Operation did not complete (wants to write), can be retried later\n", stream);
        break;
  case SSL_ERROR_SYSCALL:
    fputs("Fatal I/O Error\n", stream);
    break;
  case SSL_ERROR_SSL:
    fputs("Fatal SSL Library Error (most likely protocol error)\n", stream);
    break;
  default:
    fputs("some freaking SSL error\n", stream);
    break;
  }
}

//takes a file path and returns a substring with its file type (ie. the characters after the last '.')
//NON-DESTRUCTIVE
char *get_file_type(char* path){
  if(path == NULL)
    return (char *)-1;
  char *end = path + strlen(path)-1;
  //if we don't find a . before the first / then the file doesn't have a fle extension
  while(end != path-1 && *end != '.' && *end != '/')
    end--;
  if (*end != '.')
    return path;
  return end+1;
}

//http parsing stuff
//TODO: remove the need for this
void free_http_request(http_request *req){
  if(req->host != NULL)
    free(req->host);
  if(req->path != NULL)
    free(req->path);
}

//parses the first line of a http request (ie. HTTP/1.1 GET /)
//returns -1 if error
int parse_first_line(http_request *req, char* first_line){
  //method
  char *line_token = strtok(first_line, " ");
  if(line_token == NULL)
    return -1;
  strncpy(req->method, line_token, HTTP_REQ_OBJ_METHOD_SIZE-1);
  //path
  line_token = strtok(NULL, " ");
  if(line_token == NULL)
    return -1;
  req->path = malloc(strlen(line_token)+1); //chars are 1 byte (almost always)
  strcpy(req->path, line_token);
  return 0;
}

//parses the whole http request
int parse_http_request(http_request *req, char* data){
  all_to_lower(data); //this is "destructive"
  size_t data_len = strlen(data);
  char *token = strtok(data, "\r\n");
  size_t token_length;
  if(token == NULL || *token == 0)
    return -1;
  token_length = strlen(token);
  //first line is different
  if(parse_first_line(req, token) != 0){
    free_http_request(req);
    return -1;
  }
  //rest of the lines are normal
  //make sure there is actually data after the end of our first token
  if(token_length+2 > data_len){
    free_http_request(req);
    return -1;
  }
  token = strtok(token+token_length+2, "\r\n");
  //this weird token+strlen math is to go to the next token of the original call to strtok in this function. parse_first_line makes a call to strtok on the substring passed to it and erasing its data of the first call, so we artificially add it back by passing the (untouched) rest of the string data.
  while(token != NULL){
    if(strncmp(token, "host", 3)==0){
      req->host = malloc(strlen((token+6))+1);
      strcpy(req->host, (token+6));
    }else if(strncmp(token, "connection", 9)==0){
      if(strncmp(token+12, "keep-alive", 10)==0)
        req->connection = CONNECTION_KEEP_ALIVE;
      else
        req->connection = CONNECTION_CLOSE;
    }
    token = strtok(NULL, "\r\n");
  }
  return 0;
}

//stolen from: https://github.com/SamBkamp/c-server/blob/main/main.c
char* long_to_ipstr(unsigned long IP){
  //16 bytes max for an IP string (with nullptr)
  char *out = malloc(16);
  memset(out, 0, 16);
  size_t out_idx = 0;
  for(size_t i = 0; i < 3; i++){
    out_idx += sprintf(&out[out_idx], "%d.", ((unsigned char*)&IP)[i]);
  }
  out_idx += sprintf(&out[out_idx], "%d", ((unsigned char*)&IP)[3]); //last digit has no trailing .
  return out;
}

//generates a default page for 404s/500s etc
char *generate_error(size_t code, size_t *len){
  unsigned int response_lo_num = code%100; //2 lowest digits of http status code
  unsigned int response_hi_num = (code - response_lo_num)/100; //highest digit of http status
  char buffer[1024];
  const char *format = "\
<!DOCTYPE html>   \r\n\
<html lang=\"en\">\r\n\
<head> \r\n\
  <meta charset=\"UTF-8\" /> \r\n\
  <title>%s</title> \r\n\
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" /> \r\n\
  <meta name=\"description\" content=\"\" /> \r\n\
  <link rel=\"icon\" href=\"favicon.png\"> \r\n\
</head>\r\n\
<body>\r\n\
  <h1 style='text-align:center'>%ld - %s</h1>\r\n\
    <hr style='height: 1px; width: 70vw; background-color: black; margin: 0 auto;'>\
  <h3 style='text-align:center'>"VERSION_NUMBER"</h3>\r\n                      \
</body>\r\n\
</html>";
  *len = snprintf(buffer,
                  1024,
                  format,
                  msd[response_hi_num-1][response_lo_num],
                  code,
                  msd[response_hi_num-1][response_lo_num]);

  char *retval = malloc(*len);
  strncpy(retval, buffer, *len);
  return retval;
}
