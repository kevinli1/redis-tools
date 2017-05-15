#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "utils.h"

static char *log_file = NULL;
static enum LEVEL log_level = INFO;

struct address_list {
    struct in_addr in_addr;
    struct address_list *next;
} address_list;

void set_log_level(enum LEVEL level) {
    log_level  = level;
}

void set_log_file(char *filename){
    log_file = filename;
}

void logger(enum LEVEL loglevel,char *fmt, ...){
    FILE *fp;
    va_list ap;
    time_t now;
    char buf[4096];
    char t_buf[64];
    char *msg = NULL;
    const char *color = "";

    if(loglevel < log_level) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    switch(loglevel) {
        case DEBUG: msg = "DEBUG"; break;
        case INFO:  msg = "INFO";  color = C_YELLOW ; break;
        case WARN:  msg = "WARN";  color = C_PURPLE; break;
        case ERROR: msg = "ERROR"; color = C_RED; break;
    }

    now = time(NULL);
    strftime(t_buf,64,"%Y-%m-%d %H:%M:%S",localtime(&now));
    fp = (log_file == NULL) ? stdout : fopen(log_file,"a");
    if(log_file) {
        fprintf(fp, "[%s] [%s] %s\n", t_buf, msg, buf);
        fclose(fp);
    } else {
        fprintf(fp, "%s[%s] [%s] %s"C_NONE"\n", color, t_buf, msg, buf);
    }

    if(loglevel >= ERROR) {
        exit(1);
    }
}

int speed_human(uint64_t speed, char *buf, int size){
    int n;

    if (!buf || size < 16) return -1;
    if (speed > GB) {
        n = snprintf(buf, size, "%.2f GB/s", (speed * 1.0)/GB);
    } else if (speed > MB) {
        n = snprintf(buf, size, "%.2f MB/s", (speed * 1.0)/MB);
    } else if (speed > KB) {
        n = snprintf(buf, size, "%.2f KB/s", (speed * 1.0)/KB);
    } else {
        n = snprintf(buf, size, "%llu B/s", speed);
    }
    buf[n] = '\0';
    return 0;
}

int get_addresses(void) {
    pcap_if_t *devlist, *curr;
    pcap_addr_t *addr;
    struct sockaddr *realaddr;
    struct sockaddr_in *sin;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct address_list *address_list_curr;

    if (pcap_findalldevs(&devlist, errbuf)) {
        logger(ERROR, "You should use -l to assign local ip.\n");
        return 1; /* return 1 would be never reached */
    }
    
    address_list_curr = &address_list;
    for (curr = devlist; curr; curr = curr->next) {
        if (curr->flags & PCAP_IF_LOOPBACK) continue;

        for (addr = curr->addresses; addr; addr = addr->next) {
            if (addr->addr) {
                realaddr = addr->addr;
            } else if (addr->dstaddr) {
                realaddr = addr->dstaddr;
            } else {
                continue;
            }
            if (realaddr->sa_family == AF_INET ||
                    realaddr->sa_family == AF_INET6) {
                sin = (struct sockaddr_in *) realaddr;
                address_list_curr->next = malloc(sizeof(struct address_list));
                if (!address_list_curr->next) abort();
                address_list_curr->next->in_addr = sin->sin_addr;
                address_list_curr->next->next = NULL;
                address_list_curr = address_list_curr->next;
            }
        }
        
    }
    pcap_freealldevs(devlist);
    return 0;
}

int parse_addresses(char addresses[]) {
    char *next, *comma, *current;
    struct address_list *address_list_curr;
    
    next = addresses;
    address_list_curr = &address_list;
    while ((comma = strchr(next, ','))) {
        current = malloc((comma - next) + 1);
        if (!current) abort();
        strncpy(current, next, (comma - next));
        current[comma - next] = '\0';
        address_list_curr->next = malloc(sizeof(struct address_list));
        if (!address_list_curr->next) abort();
        address_list_curr->next->next = NULL;
        if (!inet_aton(current, &address_list_curr->next->in_addr)) {
            free(current);
            return 1;
        }
        address_list_curr = address_list_curr->next;
        free(current);
        next = comma + 1;
    }
    
    address_list_curr->next = malloc(sizeof(struct address_list));
    if (!address_list_curr->next) abort();
    address_list_curr->next->next = NULL;
    if (!inet_aton(next, &address_list_curr->next->in_addr)) {
        return 1;
    }
    
    address_list_curr = address_list_curr->next;
    return 0;
}

int free_addresses(void) {
    struct address_list *next;
    
    while (address_list.next) {
        next = address_list.next->next;
        free(address_list.next);
        address_list.next = next;
        
    }
    return 0;
}

int is_local_address(struct in_addr addr) {
    struct address_list *curr;
    
    for (curr = address_list.next; curr; curr = curr->next) {
        if (curr->in_addr.s_addr == addr.s_addr) {
            return 1;
        }
    }
    return 0;
}
