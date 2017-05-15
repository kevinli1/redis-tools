#ifndef _PCAP_PACKET_H_
#define _PCAP_PACKET_H_

#include "redis-tools.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <pcap.h>

#define CAPTURE_LENGTH 65535
#define READ_TIMEOUT 100 // ms

typedef struct {
    pcap_t *pcap;
    bpf_u_int32 mask;
    bpf_u_int32 net;
} pcap_wrapper;

pcap_wrapper* pw_create(char *dev);
pcap_wrapper* pw_create_offline(const char *filename);
void pw_release (pcap_wrapper* pw);
int pcap_set_filter (pcap_wrapper* pw, char *filter);
int mpcap_loop(pcap_wrapper *pw, char *filter, pcap_handler handler); 

void process_packet(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);
#endif
