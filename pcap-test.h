#ifndef HEADERS_H
#define HEADERS_H

#include <stdint.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define IP_HEADERS_SIZE 20
#define TCP_HEADERS_SIZE 20

struct eth_header {
    u_char  dest_mac[ETHER_ADDR_LEN];
    u_char  src_mac[ETHER_ADDR_LEN];
    u_short eth_type;
};

struct ip_header {
    u_char  ip_ver_ihl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char  ip_ttl;
    u_char  ip_proto;
    u_short ip_cksum;
    struct  in_addr ip_src;
    struct  in_addr ip_dst;
};

struct tcp_header {
    u_short src_port;
    u_short dst_port;
    u_int   seq_num;
    u_int   ack_num;
    u_char  data_offset;
    u_char  flags;
    u_short win_size;
    u_short checksum;
    u_short urg_ptr;
};

#endif