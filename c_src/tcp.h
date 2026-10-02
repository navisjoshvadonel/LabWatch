#ifndef TCP_H
#define TCP_H

#include "common.h"

#define DEFAULT_PYTHON_HOST "127.0.0.1"
#define DEFAULT_PYTHON_PORT 5000
#define DEFAULT_PYTHON_ENDPOINT "/api/pc-status"

int tcp_notify_status(
    const char *host,
    int port,
    const char *endpoint,
    const char *pc_id,
    const char *status,
    const char *ip_address,
    const char *mac_address
);

int tcp_cli_fallback(
    const char *pc_id,
    const char *status,
    const char *ip_address,
    const char *mac_address
);

int tcp_dispatch_alert(
    const char *pc_id,
    const char *status,
    const char *ip_address,
    const char *mac_address
);

#endif
