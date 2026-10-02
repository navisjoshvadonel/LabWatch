#ifndef ICMP_H
#define ICMP_H

#include "common.h"

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0
#define ICMP_PAYLOAD_SIZE 32
#define DEFAULT_PING_TIMEOUT_MS 1000

#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} IcmpHeader;

typedef struct {
    IcmpHeader header;
    char payload[ICMP_PAYLOAD_SIZE];
} IcmpPacket;

typedef struct {
    uint8_t  ihl:4;
    uint8_t  version:4;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} Ipv4Header;
#pragma pack(pop)

uint16_t icmp_calculate_checksum(const void *buffer, size_t length);
void icmp_craft_packet(IcmpPacket *packet, uint16_t id, uint16_t seq);
int icmp_ping(const char *ip_address, int timeout_ms, double *rtt_ms);

#endif
