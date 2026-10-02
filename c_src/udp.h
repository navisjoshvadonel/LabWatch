#ifndef UDP_H
#define UDP_H

#include "common.h"

#define WOL_SYNC_LEN 6
#define WOL_MAC_REPETITIONS 16
#define WOL_PACKET_SIZE (WOL_SYNC_LEN + (WOL_MAC_REPETITIONS * 6))
#define DEFAULT_WOL_PORT 9
#define DEFAULT_BROADCAST_IP "255.255.255.255"

void udp_craft_wol_packet(unsigned char packet[WOL_PACKET_SIZE], const unsigned char mac_bytes[6]);
int udp_send_wol(const char *mac_address, const char *broadcast_ip, int port);

#endif
