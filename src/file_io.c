#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <stdint.h>
#include <openssl/ssl.h>

#include "prot.h"
#include "string_manipulation.h"
#include "file_io.h"

//OPENS FOR READ ONLY
//off_t is coerced into a long here, but this may not be portable. off_t isn't standard C (bruh), but standard posix (which doesn't give any info abt its width other than its signed...)
//im just gonna assume this works until it doesn't
//if bytes is 0, then file size will be queried and put into bytes, else it uses bytes as the size of the of the file
char *open_file(char *path, long *bytes){
  struct stat sb;
  int filefd = open(path, O_RDONLY);
  if(filefd < 0)
    return MAP_FAILED;
  if(*bytes == 0){
    if(fstat(filefd, &sb)< 0){
      close(filefd);
      return MAP_FAILED;
    }
    *bytes = sb.st_size;
  }
  char *retval = mmap(NULL, *bytes, PROT_READ, MAP_SHARED, filefd, 0);
  close(filefd);
  return retval;
}

//takes a line src and returns a pointer to the value after the '='. puts a null terminator at the start of delimeter. Accounts for spaces either side of equals.
//eg: field = value -> field\0= value (where val points to the first char of the value ie. 'v' in this case)
//or filed=value -> field\0value
char* split_line(char *src){
  char *line_end = src + strlen(src); //points to null terminator
  char *equals_pos;
  for(equals_pos = src; equals_pos < line_end && *equals_pos != '='; equals_pos++){}
  if(equals_pos == line_end)
    return equals_pos;
  if(*(equals_pos-1) == ' ')
    *(equals_pos-1) = 0;
  else
    *equals_pos = 0;

  equals_pos++;
  while(*equals_pos == ' ')
    equals_pos++;

  //handle leading and trailing quotes
  if(*equals_pos == '\'' || *equals_pos == '"')
    equals_pos++;

  if(*(line_end-1) == '\'' || *(line_end-1) == '"')
    *(line_end-1) = 0;

  return equals_pos;
}

//wanna see a ruthlessly optimised, unreadable hellish version of this function?
//https://github.com/SamBkamp/cursed_config_parser
int load_config(config *cfg){
  char file_data[FILE_BUFFER_SIZE];
  struct stat sb;
  ssize_t bytes_read;
  int conf_fd = open("config.pws", O_RDONLY);

  if(conf_fd<0) return -1;
  if(fstat(conf_fd, &sb)<0 || sb.st_size >= FILE_BUFFER_SIZE) return 1;

  bytes_read = read(conf_fd, file_data, FILE_BUFFER_SIZE);
  if(bytes_read < 0) return -1;

  file_data[bytes_read] = 0;
  char *tok = strtok(file_data, "\n");
  while(tok != NULL){
    char *val = split_line(tok);
    if(*tok != '#' && *val != 0){
      if(strcmp(tok, "PRIVATE_KEY_FILE")==0){
        cfg->private_key_path = malloc(strlen(val));
        strcpy(cfg->private_key_path, val);
      }else if(strcmp(tok, "CERTIFICATE_FILE")==0){
        cfg->certificate_path = malloc(strlen(val));
        strcpy(cfg->certificate_path, val);
      }else if(strcmp(tok, "C_FULLCHAIN_FILE")==0){
        cfg->fullchain_path = malloc(strlen(val));
        strcpy(cfg->fullchain_path, val);
      }else if(strcmp(tok, "DOMAIN_HOST_NAME")==0){
        cfg->hostname = malloc(strlen(val));
        strcpy(cfg->hostname, val);
      }else if(strcmp(tok, "DOCUMENT_ROOTDIR")==0){
        cfg->document_root = malloc(strlen(val));
        strcpy(cfg->document_root, val);
      }else{
        printf("unknown directive %s\n", tok);
        return -1;
      }
    }
    tok = strtok(NULL, "\n");
  }
  return 0;
}

//loads the blacklinks file
//returns an array of char * with final entry being a null pointer
//current is a 2-copy operation. One to load file into stack another to load into heap memory. Probably not a huge issue as this only runs once on startup but there is room for improvement
char **load_blacklinks(char *path){
  const uint16_t entries_max = 1024;
  uint16_t entries = 0;
  char *honey_paths[entries_max];
  char buffer[1024];
  char **ret_path_array;
  int bytes_read, conf_fd = open(path, O_RDONLY);
  if(conf_fd<0) return NULL;

  bytes_read = read(conf_fd, buffer, 1023);
  if(bytes_read < 0) return NULL;

  //parse each line
  buffer[bytes_read] = 0;
  char *line = strtok(buffer, "\n");
  while(line){
    honey_paths[entries++] = line;
    line = strtok(NULL,  "\n");
  }

  //load each line (entry) into heap
  ret_path_array = malloc(sizeof(char *)*(entries+1));

  for(int i = 0; i < entries; i++){
    ret_path_array[i] = malloc(strlen(honey_paths[i])+1);
    strcpy(ret_path_array[i], honey_paths[i]);
  }

  ret_path_array[entries] = NULL;
  return ret_path_array;
}
