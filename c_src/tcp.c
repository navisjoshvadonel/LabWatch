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
    DWORD tv = TCP_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = TCP_TIMEOUT_MS / 1000;
    tv.tv_usec = (TCP_TIMEOUT_MS % 1000) * 1000;
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

    if (req_len < 0 || (size_t)req_len >= sizeof(http_request)) {
        fprintf(stderr, "[-] [TCP Error] HTTP request payload exceeded buffer size\n");
        CLOSE_SOCKET(sock);
        return -1;
    }

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
        int http_status = 0;
        if (sscanf(response, "HTTP/%*d.%*d %d", &http_status) == 1) {
            if (http_status >= 200 && http_status < 300) {
                printf("[+] [TCP HTTP %d] Dispatched '%s' status for '%s' to %s:%d%s\n",
                       http_status, status, pc_id, host, port, endpoint);
                return 0;
            } else {
                fprintf(stderr, "[-] [TCP HTTP %d] Server rejected status update for '%s'\n",
                        http_status, pc_id);
                return -1;
            }
        } else if (strstr(response, "200 OK") || strstr(response, "201 Created")) {
            printf("[+] [TCP HTTP SUCCESS] Dispatched '%s' status for '%s' to %s:%d%s\n",
                   status, pc_id, host, port, endpoint);
            return 0;
        } else {
            fprintf(stderr, "[-] [TCP HTTP Warning] Unexpected HTTP response for '%s'\n", pc_id);
            return -1;
        }
    }

    return -1;
}

int tcp_cli_fallback(
    const char *pc_id,
    const char *status,
    const char *ip_address,
    const char *mac_address
) {
    const char *safe_pc = pc_id ? pc_id : "UNKNOWN";
    const char *safe_status = status ? status : "offline";
    const char *safe_ip = ip_address ? ip_address : "";
    const char *safe_mac = mac_address ? mac_address : "";

    printf("[*] [TCP Fallback Hook] Executing safe CLI dispatch for %s (%s)...\n",
           safe_pc, safe_status);

#ifdef _WIN32
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char cmdline[1024];
    snprintf(cmdline, sizeof(cmdline),
             "python python_server.py --report \"%s\" \"%s\" \"%s\" \"%s\"",
             safe_pc, safe_status, safe_ip, safe_mac);

    /* Use CreateProcess without shell interpreter to avoid shell command injection */
    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return (exit_code == 0) ? 0 : -1;
    } else {
        fprintf(stderr, "[-] [TCP Fallback Error] CreateProcess failed: %lu\n", GetLastError());
        return -1;
    }
#else
    pid_t pid = fork();
    if (pid == 0) {
        char *args[] = {
            "python3",
            "python_server.py",
            "--report",
            (char *)safe_pc,
            (char *)safe_status,
            (char *)safe_ip,
            (char *)safe_mac,
            NULL
        };
        execvp("python3", args);
        execvp("python", args);
        _exit(1);
    } else if (pid > 0) {
        int status_val = 0;
        waitpid(pid, &status_val, 0);
        return (WIFEXITED(status_val) && WEXITSTATUS(status_val) == 0) ? 0 : -1;
    }
    return -1;
#endif
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
