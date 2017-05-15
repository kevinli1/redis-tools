#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <netinet/in.h>
#define C_RED "\033[31m"
#define C_GREEN "\033[32m"
#define C_YELLOW "\033[33m"
#define C_PURPLE "\033[35m"
#define C_NONE "\033[0m"
#define GB (1024*1024*1024)
#define MB (1024*1024)
#define KB (1024)

enum LEVEL {
    DEBUG = 1,
    INFO,
    WARN,
    ERROR
}; 

void logger(enum LEVEL loglevel,char *fmt, ...);
void set_log_file(char *filename);
void set_log_level(enum LEVEL level);
int speed_human(uint64_t speed, char *buf, int size);

int get_addresses(void);
int parse_addresses(char []);
int free_addresses(void);
int is_local_address(struct in_addr);
#endif
