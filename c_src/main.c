#include "common.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"

int load_computers_inventory(const char *filepath, LabComputer computers[], int max_count) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fp = fopen("../computers_monitor.txt", "r");
        if (!fp) {
            fprintf(stderr, "[-] Failed to open '%s'\n", filepath);
            return -1;
        }
    }

    char line[MAX_LINE_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), fp) && count < max_count) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\r' || *p == '\n') continue;

        LabComputer *c = &computers[count];
        memset(c, 0, sizeof(LabComputer));

        int matched = sscanf(p, "%63s %63s %63s %63s %63s",
                             c->pc_number, c->ip_address, c->mac_address,
                             c->current_status, c->lab_name);

        if (matched >= 3) {
            c->consecutive_failures = 0;
            c->is_offline = (strcmp(c->current_status, "Offline") == 0 ||
                             strcmp(c->current_status, "Faulty") == 0);
            c->last_rtt_ms = -1.0;
            count++;
        }
    }

    fclose(fp);
    return count;
}

void run_monitoring_sweep(LabComputer computers[], int count, int auto_wol) {
    char ts[64];
    get_timestamp(ts, sizeof(ts));

    printf("================================================================================\n");
    printf("[*] [%s] Starting ICMP Sweep across %d inventory workstations\n", ts, count);
    printf("================================================================================\n");
    printf("%-8s | %-15s | %-17s | %-10s | %-12s\n", "PC ID", "IP Address", "MAC Address", "Status", "RTT / Action");
    printf("--------------------------------------------------------------------------------\n");

    int online_count = 0;
    int offline_count = 0;

    for (int i = 0; i < count; i++) {
        LabComputer *pc = &computers[i];
        double rtt = 0.0;
        int res = icmp_ping(pc->ip_address, 300, &rtt);

        if (res == 0) {
            pc->consecutive_failures = 0;
            pc->is_offline = 0;
            pc->last_rtt_ms = rtt;
            online_count++;
            printf("%-8s | %-15s | %-17s | \033[32mONLINE\033[0m     | %.2f ms\n",
                   pc->pc_number, pc->ip_address, pc->mac_address, rtt);
        } else {
            pc->consecutive_failures++;
            pc->is_offline = 1;
            offline_count++;
            printf("%-8s | %-15s | %-17s | \033[31mOFFLINE\033[0m    | Timeout (Fail #%d)\n",
                   pc->pc_number, pc->ip_address, pc->mac_address, pc->consecutive_failures);

            tcp_dispatch_alert(pc->pc_number, "offline", pc->ip_address, pc->mac_address);

            if (auto_wol) {
                printf("[*] [Auto-Restart] Sending WoL Magic Packet to %s (MAC: %s)...\n",
                       pc->pc_number, pc->mac_address);
                udp_send_wol(pc->mac_address, "255.255.255.255", DEFAULT_WOL_PORT);
            }
        }
    }

    printf("--------------------------------------------------------------------------------\n");
    printf("[*] Sweep Summary: Total=%d | Online=%d | Offline/Faulty=%d\n\n",
           count, online_count, offline_count);
}

void print_usage(const char *prog_name) {
    printf("LabPulse Core Network Protocols (C Daemon)\n");
    printf("Protocols used: ICMP (Fault Detection), UDP (Remote Restart), TCP (Python API)\n\n");
    printf("Usage:\n");
    printf("  %s --sweep                     : Run ICMP sweep across all lab computers\n", prog_name);
    printf("  %s --daemon [interval_sec]     : Run background ICMP monitoring daemon\n", prog_name);
    printf("  %s --ping-pc <PC_ID>           : Ping workstation dynamically using ICMP\n", prog_name);
    printf("  %s --ping-ip <IP>              : Ping specific IPv4 address using ICMP\n", prog_name);
    printf("  %s --wol <MAC_ADDRESS>         : Broadcast WoL Magic Packet via UDP\n", prog_name);
    printf("  %s --restart <PC_ID>           : Lookup PC MAC and trigger WoL Restart via UDP\n", prog_name);
    printf("  %s --notify <PC_ID> <STATUS>   : Send HTTP POST status alert via TCP to Python\n", prog_name);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (net_init() != 0) return 1;

    const char *inventory_path = "computers_monitor.txt";
    LabComputer computers[MAX_COMPUTERS];
    int comp_count = load_computers_inventory(inventory_path, computers, MAX_COMPUTERS);

    if (comp_count < 0) {
        fprintf(stderr, "[!] Warning: Could not load '%s'\n", inventory_path);
        comp_count = 0;
    } else {
        printf("[+] Loaded %d workstations dynamically from '%s'.\n", comp_count, inventory_path);
    }

    if (argc < 2) {
        print_usage(argv[0]);
        net_cleanup();
        return 0;
    }

    if (strcmp(argv[1], "--sweep") == 0) {
        int auto_wol = (argc >= 3 && strcmp(argv[2], "--auto-wol") == 0);
        run_monitoring_sweep(computers, comp_count, auto_wol);
    } else if (strcmp(argv[1], "--daemon") == 0) {
        int interval_sec = (argc >= 3) ? atoi(argv[2]) : 5;
        if (interval_sec <= 0) interval_sec = 5;
        int auto_wol = (argc >= 4 && strcmp(argv[3], "--auto-wol") == 0);

        printf("[*] Starting Background ICMP Daemon. Interval = %d sec. (Ctrl+C to terminate)\n", interval_sec);
        while (1) {
            run_monitoring_sweep(computers, comp_count, auto_wol);
            SLEEP_MS(interval_sec * 1000);
        }
    } else if (strcmp(argv[1], "--ping-pc") == 0 && argc >= 3) {
        const char *target_pc = argv[2];
        int found = 0;
        for (int i = 0; i < comp_count; i++) {
            if (strcmp(computers[i].pc_number, target_pc) == 0) {
                found = 1;
                printf("[*] [ICMP] Pinging %s (%s, MAC: %s, Lab: %s)...\n",
                       computers[i].pc_number, computers[i].ip_address,
                       computers[i].mac_address, computers[i].lab_name);

                double rtt = 0.0;
                int res = icmp_ping(computers[i].ip_address, 1000, &rtt);
                if (res == 0) {
                    printf("[+] %s is ONLINE! RTT = %.2f ms\n", target_pc, rtt);
                } else {
                    printf("[-] %s is OFFLINE! ICMP Echo Request timed out.\n", target_pc);
                    tcp_dispatch_alert(target_pc, "offline", computers[i].ip_address, computers[i].mac_address);
                }
                break;
            }
        }
        if (!found) fprintf(stderr, "[-] Workstation '%s' not found.\n", target_pc);
    } else if (strcmp(argv[1], "--ping-ip") == 0 && argc >= 3) {
        const char *target_ip = argv[2];
        printf("[*] [ICMP] Pinging IP %s...\n", target_ip);
        double rtt = 0.0;
        int res = icmp_ping(target_ip, 1000, &rtt);
        if (res == 0) {
            printf("[+] IP %s is ONLINE! RTT = %.2f ms\n", target_ip, rtt);
        } else {
            printf("[-] IP %s is OFFLINE (Timed out / Unreachable).\n", target_ip);
        }
    } else if (strcmp(argv[1], "--wol") == 0 && argc >= 3) {
        const char *mac = argv[2];
        const char *bcast = (argc >= 4) ? argv[3] : DEFAULT_BROADCAST_IP;
        udp_send_wol(mac, bcast, DEFAULT_WOL_PORT);
    } else if (strcmp(argv[1], "--restart") == 0 && argc >= 3) {
        const char *target_pc = argv[2];
        int found = 0;
        for (int i = 0; i < comp_count; i++) {
            if (strcmp(computers[i].pc_number, target_pc) == 0) {
                found = 1;
                printf("[*] [UDP] Remote Restart initiated for %s (Lab: %s)\n", target_pc, computers[i].lab_name);
                udp_send_wol(computers[i].mac_address, DEFAULT_BROADCAST_IP, DEFAULT_WOL_PORT);
                break;
            }
        }
        if (!found) fprintf(stderr, "[-] Workstation '%s' not found.\n", target_pc);
    } else if (strcmp(argv[1], "--notify") == 0 && argc >= 4) {
        const char *pc_id = argv[2];
        const char *status = argv[3];
        printf("[*] [TCP] Dispatching notification for %s with status '%s'...\n", pc_id, status);
        tcp_dispatch_alert(pc_id, status, "127.0.0.1", "00:00:00:00:00:00");
    } else {
        print_usage(argv[0]);
    }

    net_cleanup();
    return 0;
}
