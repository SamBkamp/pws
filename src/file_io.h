#ifndef PWS_FILE_IO
#define PWS_FILE_IO

#define FILE_BUFFER_SIZE 1024

typedef struct{
  char *private_key_path;
  char *certificate_path;
  char *fullchain_path;
  char *hostname;
  char *document_root;
  unsigned int hostname_len;
}config;

char *open_file(char *path, long *bytes);
int load_default_files(root_file_data *root_file_st);
int load_config(config *cfg);

#endif
