#include "icmp.h"

uint16_t icmp_calculate_checksum(const void *buffer, size_t length) {
    const uint16_t *buf = (const uint16_t *)buffer;
    uint32_t sum = 0;

    while (length > 1) {
        sum += *buf++;
        length -= 2;
    }

    if (length == 1) {
        sum += *(const uint8_t *)buf;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

void icmp_craft_packet(IcmpPacket *packet, uint16_t id, uint16_t seq) {
    memset(packet, 0, sizeof(IcmpPacket));

    packet->header.type = ICMP_ECHO_REQUEST;
    packet->header.code = 0;
    packet->header.checksum = 0;
    packet->header.id = htons(id);
    packet->header.sequence = htons(seq);

    const char *payload_text = "LabPulse-ICMP-Echo-Monitor";
    strncpy(packet->payload, payload_text, ICMP_PAYLOAD_SIZE - 1);
    packet->payload[ICMP_PAYLOAD_SIZE - 1] = '\0';

    packet->header.checksum = icmp_calculate_checksum(packet, sizeof(IcmpPacket));
}

#ifdef _WIN32
static int icmp_ping_windows_api(const char *ip_address, int timeout_ms, double *rtt_ms) {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return -2;

    unsigned long ip = inet_addr(ip_address);
    if (ip == INADDR_NONE) {
        IcmpCloseHandle(hIcmp);
        return -2;
    }

    char send_data[] = "LabPulse-Ping";
    DWORD reply_size = sizeof(ICMP_ECHO_REPLY) + sizeof(send_data) + 64;
    void *reply_buffer = malloc(reply_size);
    if (!reply_buffer) {
        IcmpCloseHandle(hIcmp);
        return -2;
    }

    DWORD replies = IcmpSendEcho(
        hIcmp, ip, send_data, (WORD)sizeof(send_data),
        NULL, reply_buffer, reply_size, (DWORD)timeout_ms
    );

    int result = -1;
    if (replies > 0) {
        PICMP_ECHO_REPLY pReply = (PICMP_ECHO_REPLY)reply_buffer;
        if (pReply->Status == IP_SUCCESS) {
            if (rtt_ms) *rtt_ms = (double)pReply->RoundTripTime;
            result = 0;
        }
    }

    free(reply_buffer);
    IcmpCloseHandle(hIcmp);
    return result;
}
#endif

static uint16_t get_next_sequence(void) {
    static uint16_t seq = 0;
    static int initialized = 0;
    if (!initialized) {
        seq = (uint16_t)(time(NULL) & 0xFFFF);
        initialized = 1;
    }
    return ++seq;
}

int icmp_ping_single(const char *ip_address, int timeout_ms, double *rtt_ms) {
    if (!ip_address || timeout_ms <= 0) return -2;

    uint16_t pid = (uint16_t)(
#ifdef _WIN32
        GetCurrentProcessId()
#else
        getpid()
#endif
        & 0xFFFF
    );

    socket_t raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (raw_sock == INVALID_SOCKET) {
#ifdef _WIN32
        if (WSAGetLastError() == 10013 || WSAGetLastError() == 10004) {
            return icmp_ping_windows_api(ip_address, timeout_ms, rtt_ms);
        }
        return -2;
#else
        raw_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (raw_sock == INVALID_SOCKET) return -2;
#endif
    }

#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
    setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(raw_sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof(tv));
    setsockopt(raw_sock, SOL_SOCKET, SO_SNDTIMEO, (const void *)&tv, sizeof(tv));
#endif

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(ip_address);

    if (dest_addr.sin_addr.s_addr == INADDR_NONE) {
        CLOSE_SOCKET(raw_sock);
        return -2;
    }

    IcmpPacket packet;
    icmp_craft_packet(&packet, pid, get_next_sequence());

#ifdef _WIN32
    LARGE_INTEGER freq, t_start, t_end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t_start);
#else
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);
#endif

    int bytes_sent = sendto(raw_sock, (const char *)&packet, sizeof(packet), 0,
                            (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent == SOCKET_ERROR) {
        CLOSE_SOCKET(raw_sock);
        return -1;
    }

    char recv_buf[ICMP_RECV_BUF_SIZE];
    struct sockaddr_in from_addr;
#ifdef _WIN32
    int from_len = sizeof(from_addr);
#else
    socklen_t from_len = sizeof(from_addr);
#endif

    while (1) {
        int bytes_recv = recvfrom(raw_sock, recv_buf, sizeof(recv_buf), 0,
                                  (struct sockaddr *)&from_addr, &from_len);

        if (bytes_recv == SOCKET_ERROR) {
            CLOSE_SOCKET(raw_sock);
            return -1;
        }

#ifdef _WIN32
        QueryPerformanceCounter(&t_end);
        double elapsed_ms = ((double)(t_end.QuadPart - t_start.QuadPart) * 1000.0) / (double)freq.QuadPart;
#else
        clock_gettime(CLOCK_MONOTONIC, &t_end);
        double elapsed_ms = ((t_end.tv_sec - t_start.tv_sec) * 1000.0) +
                            ((t_end.tv_nsec - t_start.tv_nsec) / 1000000.0);
#endif

        Ipv4Header *ip_hdr = (Ipv4Header *)recv_buf;
        int ip_hdr_len = (ip_hdr->ihl) * 4;

        if (bytes_recv >= ip_hdr_len + (int)sizeof(IcmpHeader)) {
            IcmpHeader *reply = (IcmpHeader *)(recv_buf + ip_hdr_len);

            if (reply->type == ICMP_ECHO_REPLY && ntohs(reply->id) == pid) {
                if (rtt_ms) *rtt_ms = elapsed_ms;
                CLOSE_SOCKET(raw_sock);
                return 0;
            }
        }

        if (elapsed_ms >= (double)timeout_ms) {
            CLOSE_SOCKET(raw_sock);
            return -1;
        }
    }
}

int icmp_ping(const char *ip_address, int timeout_ms, double *rtt_ms) {
    if (!ip_address || timeout_ms <= 0) return -2;

    int total_attempts = 1 + ICMP_DEFAULT_RETRIES;
    int res = -1;

    for (int attempt = 0; attempt < total_attempts; attempt++) {
        res = icmp_ping_single(ip_address, timeout_ms, rtt_ms);
        if (res == 0) {
            return 0; /* Ping success */
        }
        if (res == -2) {
            /* Unrecoverable error (bad IP, failed socket handle) */
            return -2;
        }
        if (attempt < total_attempts - 1) {
            SLEEP_MS(50); /* Short backoff between retries */
        }
    }

    return res;
}
