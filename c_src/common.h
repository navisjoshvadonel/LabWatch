#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <icmpapi.h>
    #include <windows.h>

    typedef SOCKET socket_t;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define SOCKET_ERRNO WSAGetLastError()
    #define SLEEP_MS(ms) Sleep(ms)
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/wait.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <sys/time.h>

    typedef int socket_t;
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR   (-1)
    #define CLOSE_SOCKET(s) close(s)
    #define SOCKET_ERRNO errno
    #define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

#define MAX_COMPUTERS 256
#define MAX_LINE_LEN 512
#define MAX_STR_LEN 64

typedef struct {
    char pc_number[MAX_STR_LEN];
    char ip_address[MAX_STR_LEN];
    char mac_address[MAX_STR_LEN];
    char current_status[MAX_STR_LEN];
    char lab_name[MAX_STR_LEN];
    int consecutive_failures;
    int is_offline;
    double last_rtt_ms;
} LabComputer;

static inline int net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[!] WSAStartup failed with error: %d\n", WSAGetLastError());
        return -1;
    }
    /* Enable virtual terminal processing on modern Windows consoles */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            SetConsoleMode(hOut, dwMode | 0x0004);
        }
    }
#endif
    return 0;
}

static inline void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static inline int parse_mac_address(const char *mac_str, unsigned char mac_bytes[6]) {
    if (!mac_str || !mac_bytes) return -1;
    unsigned int bytes[6];
    int parsed = sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                        &bytes[0], &bytes[1], &bytes[2],
                        &bytes[3], &bytes[4], &bytes[5]);
    if (parsed != 6) {
        parsed = sscanf(mac_str, "%x-%x-%x-%x-%x-%x",
                        &bytes[0], &bytes[1], &bytes[2],
                        &bytes[3], &bytes[4], &bytes[5]);
    }
    if (parsed == 6) {
        for (int i = 0; i < 6; i++) {
            if (bytes[i] > 0xFF) return -1; /* Prevent integer overflow / undefined byte value */
            mac_bytes[i] = (unsigned char)bytes[i];
        }
        return 0;
    }
    return -1;
}

static inline void get_timestamp(char *buffer, size_t buf_size) {
    if (!buffer || buf_size == 0) return;
    time_t now = time(NULL);
#if defined(_WIN32)
    struct tm tm_info;
    if (localtime_s(&tm_info, &now) == 0) {
        strftime(buffer, buf_size, "%Y-%m-%d %H:%M:%S", &tm_info);
    } else {
        buffer[0] = '\0';
    }
#elif defined(_POSIX_C_SOURCE) || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(__unix__) || defined(__linux__) || defined(__APPLE__)
    struct tm tm_info;
    if (localtime_r(&now, &tm_info) != NULL) {
        strftime(buffer, buf_size, "%Y-%m-%d %H:%M:%S", &tm_info);
    } else {
        buffer[0] = '\0';
    }
#else
    struct tm *tm_info = localtime(&now);
    if (tm_info) {
        strftime(buffer, buf_size, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        buffer[0] = '\0';
    }
#endif
}

#endif
