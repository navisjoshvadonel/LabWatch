#ifndef UDP_H
#define UDP_H

#include "common.h"

/* -------------------------------------------------------------------------
 * WoL Magic Packet constants (AMD/HP Wake-on-LAN specification)
 *   Packet = 6x 0xFF  +  16x target-MAC  =  102 bytes total
 * ------------------------------------------------------------------------- */
#define WOL_SYNC_LEN          6
#define WOL_MAC_REPETITIONS   16
#define WOL_PACKET_SIZE       (WOL_SYNC_LEN + (WOL_MAC_REPETITIONS * 6))   /* 102 bytes */
#define DEFAULT_WOL_PORT      9     /* Standard WoL port (also port 7 is common) */

/* -------------------------------------------------------------------------
 * Broadcast targets
 *   DEFAULT_BROADCAST_IP  - limited broadcast, may be blocked by routers
 *   COLLEGE_BROADCAST_IP  - directed subnet broadcast for 192.16.16.0/24
 *                           (derived from campus gateway 192.16.16.200, mask /24)
 *                           Subnet: 192.16.16.0  →  Broadcast: 192.16.16.255
 *   Both are sent so the packet reaches machines regardless of router config.
 * ------------------------------------------------------------------------- */
#define DEFAULT_BROADCAST_IP      "255.255.255.255"
#define COLLEGE_BROADCAST_IP      "192.16.16.255"   /* Mepco Schlenk /24 subnet broadcast */

/* -------------------------------------------------------------------------
 * Transmission reliability
 *   Send the magic packet WOL_TRANSMIT_COUNT times per target address.
 *   WoL spec recommends 2-3 transmissions to survive transient packet loss.
 * ------------------------------------------------------------------------- */
#define WOL_TRANSMIT_COUNT        3     /* Times to send per broadcast target */
#define WOL_INTER_TX_DELAY_MS   100     /* Milliseconds between each retransmission */

/* -------------------------------------------------------------------------
 * Function declarations
 * ------------------------------------------------------------------------- */

/* Build the 102-byte WoL magic packet into `packet` for the given MAC bytes */
void udp_craft_wol_packet(unsigned char packet[WOL_PACKET_SIZE],
                          const unsigned char mac_bytes[6]);

/* Send WoL to a single broadcast address, `count` times.
 * Returns 0 on success, -1 on MAC parse error, -2 on socket/send failure. */
int udp_send_wol(const char *mac_address, const char *broadcast_ip, int port);

/* Reliable dual-broadcast WoL: sends to BOTH directed subnet broadcast AND 255.255.255.255,
 * each WOL_TRANSMIT_COUNT times.
 * Returns 0 if at least one transmission succeeded, -1 if all failed. */
int udp_send_wol_reliable(const char *mac_address, int port);

/* Adaptive directed subnet WoL: automatically computes the /24 broadcast address from
 * the workstation's IP address and dispatches dual-broadcast magic packets. */
int udp_send_wol_directed(const char *mac_address, const char *ip_address, int port);

#endif
