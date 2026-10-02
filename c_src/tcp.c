#include "tcp.h"

int tcp_notify_status(
    const char *host,
    int port,
    const char *endpoint,
    const char *pc_id,
    const char *status,
    const char *ip_address,
    const char *mac_address
) {
    if (!host) host = DEFAULT_PYTHON_HOST;
    if (port <= 0) port = DEFAULT_PYTHON_PORT;
    if (!endpoint) endpoint = DEFAULT_PYTHON_ENDPOINT;

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[-] [TCP Error] Socket creation failed: error %d\n", SOCKET_ERRNO);
        return -1;
    }

#ifdef _WIN32
    DWORD tv = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const void *)&tv, sizeof(tv));
#endif

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)port);
    server_addr.sin_addr.s_addr = inet_addr(host);

    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        CLOSE_SOCKET(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
        return -1;
    }

    char json_payload[512];
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    snprintf(json_payload, sizeof(json_payload),
             "{\"pc_id\": \"%s\", \"status\": \"%s\", \"ip_address\": \"%s\", \"mac_address\": \"%s\", \"timestamp\": \"%s\"}",
             pc_id ? pc_id : "UNKNOWN",
             status ? status : "offline",
             ip_address ? ip_address : "",
             mac_address ? mac_address : "",
             timestamp);

    char http_request[1024];
    int req_len = snprintf(http_request, sizeof(http_request),
             "POST %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "User-Agent: LabPulse-TCP-Client/1.0\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             endpoint, host, port, strlen(json_payload), json_payload);

    int sent = send(sock, http_request, req_len, 0);
    if (sent == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
        return -1;
    }

    char response[512];
    int bytes_read = recv(sock, response, sizeof(response) - 1, 0);
    CLOSE_SOCKET(sock);

    if (bytes_read > 0) {
        response[bytes_read] = '\0';
        if (strstr(response, "200 OK") || strstr(response, "201 Created")) {
            printf("[+] [TCP HTTP SUCCESS] Dispatched '%s' status for '%s' to %s:%d%s\n",
                   status, pc_id, host, port, endpoint);
            return 0;
        }
    }

    return 0;
}

int tcp_cli_fallback(
    const char *pc_id,
    const char *status,
    const char *ip_address,
    const char *mac_address
) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "python python_server.py --report \"%s\" \"%s\" \"%s\" \"%s\"",
             pc_id ? pc_id : "UNKNOWN",
             status ? status : "offline",
             ip_address ? ip_address : "",
             mac_address ? mac_address : "");

    printf("[*] [TCP Fallback Hook] Executing CLI call: %s\n", cmd);
    int ret = system(cmd);
    return (ret == 0) ? 0 : -1;
}

int tcp_dispatch_alert(
    const char *pc_id,
    const char *status,
    const char *ip_address,
    const char *mac_address
) {
    int res = tcp_notify_status(
        DEFAULT_PYTHON_HOST,
        DEFAULT_PYTHON_PORT,
        DEFAULT_PYTHON_ENDPOINT,
        pc_id,
        status,
        ip_address,
        mac_address
    );

    if (res == 0) return 0;

    printf("[!] [TCP Bridge] HTTP server offline, using Python CLI fallback...\n");
    return tcp_cli_fallback(pc_id, status, ip_address, mac_address);
}
