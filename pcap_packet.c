#include "pcap_packet.h"
#include "redis-tools.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <pcap/sll.h>

#define NULL_HDRLEN 4

#ifdef _IP_VHL
    #define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#else
    #define IP_HL(ip) (((ip)->ip_hl) & 0x0f)
#endif

static int checkPacketincoming(struct in_addr src, int sport, struct in_addr dst, int dport) {
    int incoming = 0;
	struct tk_options *opts;

    // incoming = 0 means outgoing packet
    // incoming = 1 means incoming packet
    opts = get_global_options();
    if (is_local_address(dst) && is_local_address(src)) {
        // client and server is in the same machine
        if ((dport == opts->port && is_client_mode()) ||
                (sport == opts->port && !is_client_mode())) {
            incoming = 1;
        }
    } else {
        if (is_local_address(dst)) {
            incoming = 1;
        }
    }

    return incoming;
}

static void
push_params(const struct ip *ip, const struct timeval *tv)
{
    int tcp_hdr_size, incoming;
    struct tcphdr *tcp;
    uint8_t flags;
    uint16_t sport, dport;
    unsigned int payload_size, size, iphdr_size, seq, ack;

    iphdr_size = IP_HL(ip)*4;
    tcp = (struct tcphdr *) ((unsigned char *) ip + iphdr_size);
    size = htons(ip->ip_len);

#if defined(__FAVOR_BSD) || defined(__APPLE__)
    seq = htonl(tcp->th_seq);
    ack = htonl(tcp->th_ack);
    flags = tcp->th_flags;
    sport = ntohs(tcp->th_sport);
    dport = ntohs(tcp->th_dport);
    tcp_hdr_size = tcp->th_off * 4;
    payload_size = size - iphdr_size - tcp->th_off * 4;
#else
    seq = htonl(tcp->seq);
    ack = htonl(tcp->ack_seq);
    flags = tcp->fin | (tcp->syn<<1) | (tcp->rst<<2) | (tcp->psh<<3);
    if (tcp->ack) flags |= 0x10; 
    if (tcp->urg) flags |= 0x20; 
    sport = ntohs(tcp->source);
    dport = ntohs(tcp->dest);
    tcp_hdr_size = tcp->doff * 4;
    payload_size = size - iphdr_size - tcp->doff * 4;
#endif
    incoming = checkPacketincoming(ip->ip_src, sport, ip->ip_dst, dport);

    lua_State *L = get_lua_vm();
    lua_newtable(L);
    script_pushtableinteger(L, "tv_sec",  tv->tv_sec);
    script_pushtableinteger(L, "tv_usec", tv->tv_usec);
    script_pushtableinteger(L, "incoming", incoming);
    script_pushtableinteger(L, "len" , payload_size);
    script_pushtablestring(L,  "src", inet_ntoa(ip->ip_src));
    script_pushtablestring(L,  "dst", inet_ntoa(ip->ip_dst));
    script_pushtableinteger(L, "sport", sport);
    script_pushtableinteger(L, "dport", dport);
    script_pushtableinteger(L, "seq", seq);
    script_pushtableinteger(L, "ack", ack);
    script_pushtableinteger(L, "flags", flags);
    script_pushtableinteger(L, "is_client", is_client_mode());
    script_pushtableinteger(L, "udp", 0);

    if (payload_size > 0) {
        // -----------+-----------+----------+-----....-----+
        // | ETHER    |  IP       | TCP      | payload      |
        // -----------+-----------+----------+--------------+
        script_pushtablelstring(L, "payload", (char *)tcp + tcp_hdr_size, payload_size);
    }
}

// handle udp packet
static void udp_packet_callback(const struct ip *ip, const struct timeval *tv) {
    int incoming, sport, dport;
    lua_State *L;
    struct udphdr *udp;
    unsigned int iphdr_size, payload_size;

    L = get_lua_vm();
    if (!L) logger(ERROR, "Lua vm didn't initialed.");
    lua_getglobal(L, DEFAULT_CALLBACK);
    lua_newtable(L);

    iphdr_size = IP_HL(ip)*4;
    udp = (struct udphdr *) ((unsigned char *) ip + iphdr_size);
    script_pushtableinteger(L, "tv_sec",  tv->tv_sec);
    script_pushtableinteger(L, "tv_usec", tv->tv_usec);

    // udp

#if defined(__FAVOR_BSD) || defined(__APPLE__)
    sport = ntohs(udp->uh_sport);
    dport = ntohs(udp->uh_dport);
    payload_size = ntohs(udp->uh_ulen);
#else
    sport = ntohs(udp->source);
    dport = ntohs(udp->dest);
    payload_size = ntohs(udp->len);
#endif
    script_pushtableinteger(L, "len", payload_size);
    script_pushtablestring(L,  "src", inet_ntoa(ip->ip_src));
    script_pushtablestring(L,  "dst", inet_ntoa(ip->ip_dst));
    script_pushtableinteger(L, "sport", sport);
    script_pushtableinteger(L, "dport", dport);
    incoming = checkPacketincoming(ip->ip_src, sport, ip->ip_dst, dport);
    script_pushtableinteger(L, "incoming", incoming);
    script_pushtableinteger(L, "udp", 1);
    if (payload_size > 0) {
        // udp header always = 8 bytes
        script_pushtablelstring(L, "payload", (char *)udp + sizeof(struct udphdr), payload_size);
    }
    if (lua_pcall(L, 1, 1, 0) != 0) {
        logger(ERROR, "%s", lua_tostring(L, -1));
    }
    script_need_gc(L); // check whether need gc.
    lua_tonumber(L, -1);
    lua_pop(L,-1);
}

// handle tcp packet
static void tcp_packet_callback(const struct ip *ip, const struct timeval *tv) {
    lua_State *L;

    L = get_lua_vm();
    if (!L) logger(ERROR, "Lua vm didn't initialed.");

    lua_getglobal(L, DEFAULT_CALLBACK);
    push_params(ip, tv);
    if (lua_pcall(L, 1, 1, 0) != 0) {
        logger(ERROR, "%s", lua_tostring(L, -1));
    }
    script_need_gc(L); // check whether need gc.
    lua_tonumber(L, -1);
    lua_pop(L,-1);
}

static void
calc_bandwidth(const struct ip *ip, const struct timeval *tv)
{ 
    struct bandwidth *bw;

    bw = get_global_bandwidth();
    need_report_bandwidth();
    if (is_local_address(ip->ip_dst)) {
        bw->in_bytes += htons(ip->ip_len);        
        bw->in_packets += 1;
    } else {
        bw->out_bytes += htons(ip->ip_len);       
        bw->out_packets += 1;
    }
}

static int
process_ip_packet(const struct ip *ip, const struct timeval *tv)
{
    struct tk_options *opts;
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            opts = get_global_options();
            if (opts->is_calc_mode) {
                calc_bandwidth(ip, tv);
            } else {
                tcp_packet_callback(ip, tv);
            }
            break;
         case IPPROTO_UDP:
            udp_packet_callback(ip, tv);
            break;

    }
    return 0;
}

void
process_packet(unsigned char *user, const struct pcap_pkthdr *header,
                const unsigned char *packet)
{
    const struct sll_header *sll;
    const struct ether_header *ether_header;
    const struct ip *ip;
    unsigned short packet_type;
    pcap_wrapper *pw;

    pw  = (pcap_wrapper *) user;
    switch (pcap_datalink(pw->pcap)) {
    case DLT_NULL:
        /* BSD loopback */
        ip = (struct ip *)(packet + NULL_HDRLEN);
        break;
    case DLT_LINUX_SLL:
        sll = (struct sll_header *) packet;
        packet_type = ntohs(sll->sll_protocol);
        ip = (const struct ip *) (packet + sizeof(struct sll_header));
        break;
    case DLT_EN10MB:
        ether_header = (struct ether_header *) packet;
        packet_type = ntohs(ether_header->ether_type);
        ip = (const struct ip *) (packet + sizeof(struct ether_header));
        break;
    case DLT_RAW:
        packet_type = ETHERTYPE_IP; //This is raw ip
        ip = (const struct ip *) packet;
        break;

     default: return; 
    }
    
    // prevent warning
    packet_type = 0;
    process_ip_packet(ip, &header->ts); 
}

pcap_wrapper* 
pw_create(char *dev) 
{
    pcap_t *pcap;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        return NULL;
    }

    // promisc = 0, don't put into promiscuous mode
    pcap = pcap_open_live(dev, CAPTURE_LENGTH, 0, READ_TIMEOUT, errbuf);
    if(!pcap) {
        if (strcmp(dev, "any") == 0) {
            dev = pcap_lookupdev(errbuf);
            pcap = pcap_open_live(dev, CAPTURE_LENGTH, 0, READ_TIMEOUT, errbuf);
        }
        if (!pcap) return NULL;
    }
 
    logger(INFO, "listening on device %s", dev);
    pcap_wrapper *pw = malloc(sizeof(*pw));
    pw->pcap = pcap;
    pw->net = net;
    pw->mask = mask;
    return pw; 
}

pcap_wrapper *
pw_create_offline(const char *filename)
{
    FILE *fp;
    pcap_t *pcap;
    pcap_wrapper *pw;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!filename)  return NULL;

    fp = fopen(filename, "r");
    if (!fp) {
        logger(ERROR, "open offline file %s error as %s", filename, strerror(errno));
        return NULL;
    }
    pcap = pcap_fopen_offline(fp, errbuf);
    if (!pcap) {
        logger(ERROR, "pcap: %s\n", errbuf);
        return NULL;
    }

    pw = malloc(sizeof(*pw));
    pw->pcap = pcap;
    return pw;
}

void
pw_release (pcap_wrapper* pw) {
    pcap_breakloop(pw->pcap);
    pcap_close(pw->pcap);
    free(pw);
}

int 
pcap_set_filter (pcap_wrapper* pw, char *filter)
{
    struct bpf_program fp;

    if (pcap_compile(pw->pcap, &fp, filter, 0, 1) == -1) {
        // Can't parse filter.
        return -2;
    }
    
    // return 0 when sucess, return -1 when failed.
    return pcap_setfilter(pw->pcap, &fp); 
}

int
mpcap_loop(pcap_wrapper *pw, char *filter, pcap_handler handler) {
    int ret;
    struct tk_options *opts;

    if(! pw) return -1;

    if(filter && pcap_set_filter(pw, filter) != 0) {
        // install filter failed.
        return -1;    
    }
    
    logger(INFO, "start capturing, filter is = [%s]", filter);
    opts = get_global_options();
    if (opts->is_calc_mode) {
        // default calculate bandwidth every 30 second.
        opts->duration = opts->duration >= 1 ? opts->duration : 30;
        while((ret = pcap_dispatch(pw->pcap, -1, handler, (unsigned char *) pw)) >= 0) {
            need_report_bandwidth();
        }
        return ret;
    } else {
        return pcap_loop(pw->pcap, -1, handler, (unsigned char *) pw); 
    }
}
