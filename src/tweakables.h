#ifndef TWEAKABLES_PWS
#define TWEAKABLES_PWS
//for compile time settings that you can tweak

#define CLIENTS_MAX 10
#define QUEUE_LEN 10

#define HTTP_REQ_OBJ_METHOD_SIZE 10 //<- don't touch this. it won't break anything if you do but theres no reason to tweak this. Eventually this implementation will be removed bc its weird
//it defines the char array size for the method field in the http_request struct

#define KEEP_ALIVE_MAX_REQ 4
#define KEEP_ALIVE_TIMEOUT 20 //in seconds

#define LOG_FILE "pws.log"
#define ERROR_FILE "pws_error.log"

#endif
