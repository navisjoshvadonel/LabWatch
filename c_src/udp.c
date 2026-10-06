#include "udp.h"

/* -------------------------------------------------------------------------
 * udp_craft_wol_packet
 *   Builds the 102-byte Wake-on-LAN magic packet in-place.
 *
 *   Layout (AMD WoL specification):
 *     Bytes  0 –  5  : Synchronization header  →  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
 *     Bytes  6 – 101 : Target MAC repeated 16×  →  16 × {AA BB CC DD EE FF}
 * ------------------------------------------------------------------------- */
void udp_craft_wol_packet(unsigned char packet[WOL_PACKET_SIZE],
                          const unsigned char mac_bytes[6]) {
    /* Write the 6-byte sync header */
    memset(packet, 0xFF, WOL_SYNC_LEN);

    /* Repeat the 6-byte MAC address 16 consecutive times */
    for (int i = 0; i < WOL_MAC_REPETITIONS; i++) {
        memcpy(&packet[WOL_SYNC_LEN + (i * 6)], mac_bytes, 6);
    }
}

/* -------------------------------------------------------------------------
 * udp_send_wol
 *   Sends the 102-byte WoL magic packet to `broadcast_ip`:`port`
 *   exactly WOL_TRANSMIT_COUNT times, with WOL_INTER_TX_DELAY_MS between
 *   each retransmission for reliability.
 *
 *   Returns:
 *     0   – at least one transmission delivered successfully
 *    -1   – invalid MAC address string
 *    -2   – socket error (creation or setsockopt failure)
 *    -3   – all transmissions failed to send
 * ------------------------------------------------------------------------- */
int udp_send_wol(const char *mac_address, const char *broadcast_ip, int port) {
    if (!mac_address)   return -1;
    if (!broadcast_ip)  broadcast_ip = DEFAULT_BROADCAST_IP;
    if (port <= 0)      port = DEFAULT_WOL_PORT;

    /* Parse and validate MAC address string (supports XX:XX:XX:XX:XX:XX and XX-XX-...) */
    unsigned char mac_bytes[6];
    if (parse_mac_address(mac_address, mac_bytes) != 0) {
        fprintf(stderr, "[-] [UDP WoL Error] Invalid MAC address format: '%s'\n", mac_address);
        return -1;
    }

    /* Build the 102-byte magic packet once — reuse for all transmissions */
    unsigned char packet[WOL_PACKET_SIZE];
    udp_craft_wol_packet(packet, mac_bytes);

    /* Open a UDP datagram socket */
    socket_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[-] [UDP WoL Error] Socket creation failed: error %d\n", SOCKET_ERRNO);
        return -2;
    }

    /* Enable SO_BROADCAST — required for sending to broadcast addresses */
#ifdef _WIN32
    BOOL broadcast_opt = TRUE;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                   (const char *)&broadcast_opt, sizeof(broadcast_opt)) == SOCKET_ERROR) {
#else
    int broadcast_opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                   &broadcast_opt, sizeof(broadcast_opt)) < 0) {
#endif
        fprintf(stderr, "[-] [UDP WoL Error] Failed to enable SO_BROADCAST: error %d\n", SOCKET_ERRNO);
        CLOSE_SOCKET(sock);
        return -2;
    }

    /* Resolve the destination broadcast address */
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port   = htons((uint16_t)port);

    if (strcmp(broadcast_ip, "255.255.255.255") == 0) {
        dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
    } else {
        dest_addr.sin_addr.s_addr = inet_addr(broadcast_ip);
        if (dest_addr.sin_addr.s_addr == INADDR_NONE) {
            fprintf(stderr, "[-] [UDP WoL Error] Invalid broadcast IP: '%s'\n", broadcast_ip);
            CLOSE_SOCKET(sock);
            return -2;
        }
    }

    /* -----------------------------------------------------------------------
     * Transmit WOL_TRANSMIT_COUNT times with WOL_INTER_TX_DELAY_MS gap.
     * The WoL specification recommends sending the magic packet multiple times
     * to account for transient UDP packet loss on busy lab networks.
     * ----------------------------------------------------------------------- */
    int success_count = 0;

    for (int tx = 1; tx <= WOL_TRANSMIT_COUNT; tx++) {
        int bytes_sent = sendto(sock,
                                (const char *)packet, WOL_PACKET_SIZE,
                                0,
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        char ts[64];
        get_timestamp(ts, sizeof(ts));

        if (bytes_sent == SOCKET_ERROR) {
            fprintf(stderr,
                    "[-] [%s] [UDP WoL TX#%d/%d] Send FAILED → %s:%d  (error %d)\n",
                    ts, tx, WOL_TRANSMIT_COUNT, broadcast_ip, port, SOCKET_ERRNO);
        } else {
            success_count++;
            printf("[+] [%s] [UDP WoL TX#%d/%d] Sent %d bytes → %s:%d  "
                   "(MAC: %02X:%02X:%02X:%02X:%02X:%02X)\n",
                   ts, tx, WOL_TRANSMIT_COUNT, bytes_sent,
                   broadcast_ip, port,
                   mac_bytes[0], mac_bytes[1], mac_bytes[2],
                   mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        }

        /* Delay before next retransmission (skip delay after final send) */
        if (tx < WOL_TRANSMIT_COUNT) {
            SLEEP_MS(WOL_INTER_TX_DELAY_MS);
        }
    }

    CLOSE_SOCKET(sock);

    if (success_count == 0) {
        fprintf(stderr, "[-] [UDP WoL Error] All %d transmissions failed to %s:%d\n",
                WOL_TRANSMIT_COUNT, broadcast_ip, port);
        return -3;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * udp_send_wol_reliable
 *   Dual-broadcast Wake-on-LAN for maximum reach on the Mepco Schlenk
 *   campus network (gateway: 192.16.16.200, subnet: 192.16.16.0/24).
 *
 *   Strategy — sends to TWO broadcast addresses:
 *
 *     1. COLLEGE_BROADCAST_IP  "192.16.16.255"  (directed subnet broadcast)
 *        ↳ Reaches all hosts on the 192.16.16.0/24 segment even if the
 *          campus router is configured to block limited broadcasts.
 *          This is the primary path on your college LAN.
 *
 *     2. DEFAULT_BROADCAST_IP  "255.255.255.255" (limited broadcast)
 *        ↳ Fallback: some NICs wake on this even when directed broadcast
 *          is filtered. Sent second so the subnet broadcast arrives first.
 *
 *   Each address receives WOL_TRANSMIT_COUNT transmissions (×3 = 6 total
 *   packets per call), ensuring at least one reaches the target NIC.
 *
 *   Returns:
 *     0   – at least one of the two broadcast paths succeeded
 *    -1   – MAC address parse error
 *    -4   – both broadcast paths failed completely
 * ------------------------------------------------------------------------- */
int udp_send_wol_reliable(const char *mac_address, int port) {
    if (!mac_address) return -1;
    if (port <= 0)    port = DEFAULT_WOL_PORT;

    /* Validate MAC early so both paths share the same error gate */
    unsigned char mac_bytes[6];
    if (parse_mac_address(mac_address, mac_bytes) != 0) {
        fprintf(stderr, "[-] [UDP WoL Error] Invalid MAC address format: '%s'\n", mac_address);
        return -1;
    }

    char ts[64];
    get_timestamp(ts, sizeof(ts));

    printf("[*] [%s] [UDP WoL] Initiating dual-broadcast WoL for MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
           ts, mac_bytes[0], mac_bytes[1], mac_bytes[2],
           mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    printf("[*]   Target 1: %s (Mepco Schlenk subnet 192.16.16.0/24 directed broadcast)\n",
           COLLEGE_BROADCAST_IP);
    printf("[*]   Target 2: %s (Limited / global broadcast fallback)\n",
           DEFAULT_BROADCAST_IP);
    printf("[*]   Transmissions per target: %d × %d ms apart  →  %d total packets\n",
           WOL_TRANSMIT_COUNT, WOL_INTER_TX_DELAY_MS,
           WOL_TRANSMIT_COUNT * 2);

    /* --- Path 1: Directed subnet broadcast (192.16.16.255) --- */
    printf("\n[*] --- Path 1: Directed Broadcast → %s:%d ---\n",
           COLLEGE_BROADCAST_IP, port);
    int res1 = udp_send_wol(mac_address, COLLEGE_BROADCAST_IP, port);

    /* Brief gap between the two broadcast targets */
    SLEEP_MS(150);

    /* --- Path 2: Limited broadcast (255.255.255.255) --- */
    printf("\n[*] --- Path 2: Limited Broadcast  → %s:%d ---\n",
           DEFAULT_BROADCAST_IP, port);
    int res2 = udp_send_wol(mac_address, DEFAULT_BROADCAST_IP, port);

    /* Summary */
    get_timestamp(ts, sizeof(ts));
    if (res1 == 0 || res2 == 0) {
        printf("\n[+] [%s] [UDP WoL COMPLETE] Magic packet delivered successfully.\n", ts);
        printf("[+]   Subnet broadcast (%s): %s\n",
               COLLEGE_BROADCAST_IP, (res1 == 0) ? "OK" : "FAILED");
        printf("[+]   Global broadcast (%s): %s\n",
               DEFAULT_BROADCAST_IP, (res2 == 0) ? "OK" : "FAILED");
        return 0;
    }

    fprintf(stderr, "\n[-] [%s] [UDP WoL FAILED] Both broadcast paths failed for MAC %s\n",
            ts, mac_address);
    return -4;
}
