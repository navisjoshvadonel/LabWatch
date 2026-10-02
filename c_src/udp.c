#include "udp.h"

void udp_craft_wol_packet(unsigned char packet[WOL_PACKET_SIZE], const unsigned char mac_bytes[6]) {
    memset(packet, 0xFF, WOL_SYNC_LEN);

    for (int i = 0; i < WOL_MAC_REPETITIONS; i++) {
        memcpy(&packet[WOL_SYNC_LEN + (i * 6)], mac_bytes, 6);
    }
}

int udp_send_wol(const char *mac_address, const char *broadcast_ip, int port) {
    if (!mac_address) return -1;
    if (!broadcast_ip) broadcast_ip = DEFAULT_BROADCAST_IP;
    if (port <= 0) port = DEFAULT_WOL_PORT;

    unsigned char mac_bytes[6];
    if (parse_mac_address(mac_address, mac_bytes) != 0) {
        fprintf(stderr, "[-] [UDP WoL Error] Invalid MAC address format: '%s'\n", mac_address);
        return -1;
    }

    unsigned char packet[WOL_PACKET_SIZE];
    udp_craft_wol_packet(packet, mac_bytes);

    socket_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[-] [UDP WoL Error] Socket creation failed: error %d\n", SOCKET_ERRNO);
        return -2;
    }

#ifdef _WIN32
    BOOL broadcast_opt = TRUE;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char *)&broadcast_opt, sizeof(broadcast_opt)) == SOCKET_ERROR) {
#else
    int broadcast_opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_opt, sizeof(broadcast_opt)) < 0) {
#endif
        fprintf(stderr, "[-] [UDP WoL Error] Failed to enable SO_BROADCAST: error %d\n", SOCKET_ERRNO);
        CLOSE_SOCKET(sock);
        return -2;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons((uint16_t)port);

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

    int bytes_sent = sendto(sock, (const char *)packet, sizeof(packet), 0,
                            (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (bytes_sent == SOCKET_ERROR) {
        fprintf(stderr, "[-] [UDP WoL Error] Send failed: error %d\n", SOCKET_ERRNO);
        CLOSE_SOCKET(sock);
        return -2;
    }

    char ts[64];
    get_timestamp(ts, sizeof(ts));
    printf("[+] [%s] [UDP WoL SUCCESS] Broadcasted %d bytes to %s:%d (Target MAC: %02X:%02X:%02X:%02X:%02X:%02X)\n",
           ts, bytes_sent, broadcast_ip, port,
           mac_bytes[0], mac_bytes[1], mac_bytes[2],
           mac_bytes[3], mac_bytes[4], mac_bytes[5]);

    CLOSE_SOCKET(sock);
    return 0;
}
