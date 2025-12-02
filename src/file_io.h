#ifndef PWS_FILE_IO
#define PWS_FILE_IO

#define FILE_BUFFER_SIZE 1024

char *open_file(char *path, long *bytes);
int load_default_files(root_file_data *root_file_st);
int load_config(config *cfg);

#endif
