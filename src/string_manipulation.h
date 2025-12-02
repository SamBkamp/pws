//to take care of string manipulation code, file I/O requests parsing that kinda thing
#ifndef PWS_STRING_MANIPULATION
#define PWS_STRING_MANIPULATION
char *format_dirs(char *path, char *ret_path, char *document_root);
int parse_first_line(http_request *req, char* first_line);
int parse_http_request(http_request *req, char* data);
void free_http_request(http_request *req);
char* long_to_ip(char* out, unsigned long IP);
char *get_file_type(char* path);
void print_SSL_errstr(int SSL_err, FILE* stream);
char *open_file(char *path, long *bytes);
int load_default_files(root_file_data *root_file_st);
#endif
