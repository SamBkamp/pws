//to take care of string manipulation code, file I/O requests parsing that kinda thing
#ifndef PWS_STRING_MANIPULATION
#define PWS_STRING_MANIPULATION
#include <poll.h>
#include <stdint.h>
char *format_dirs(char *path, char *ret_path, size_t ret_path_size,char *document_root);
int parse_first_line(http_request *req, char* first_line);
int parse_http_request(http_request *req, char* data);
void free_http_request(http_request *req);
char* long_to_ipstr(unsigned long IP);
char *get_file_type(char* path);
void print_SSL_errstr(int SSL_err, FILE* stream);
char *open_file(char *path, long *bytes);
char *generate_error(size_t code, size_t *len);
#endif
