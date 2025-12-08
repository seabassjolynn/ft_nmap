#include "net.h"
#include "debug.h"
#include "resources.h"
#include <string.h>
#include "pcap_utils.h"
#include "utils.h"
#include "color_output.h"

static struct in_addr default_gateway_ip(void) {
    struct in_addr gateway_in_addr;
    gateway_in_addr.s_addr = 0;

    FILE *routing_table_stream = fopen("/proc/net/route", "r");
    if (routing_table_stream == NULL) {
        clean_exit_failure("Getting default gateway ip: failed to open routing table");
    }
    
    int line_num = 0;
    int line_len = 1024;
    char line[line_len];
    while (fgets(line, line_len, routing_table_stream) != NULL) {
        if (line_num > 0) {
            if (DEBUG) {
                printf("Getting default gateway ip: Line: %s\n", line);
            }    
            
            char iface[64];
            int flags, refcnt, use, metric, mtu, window, irtt;
            long unsigned int dest_ip, gateway_ip, mask;
            
            if (sscanf(line, "%s %lx %lx %d %d %d %d %lx %d %d %d\n", iface, &dest_ip, &gateway_ip, &flags, &refcnt, &use, &metric, &mask, &mtu, &window, &irtt) == 11) {
                if (DEBUG) {
                    printf("Getting default gateway ip: parsed: iface: %s, dest: %lx, gateway: %lx, flags: %d, refcnt: %d, use: %d, metric: %d, mask: %lx, mtu: %d, window: %d, irtt: %d\n", iface, dest_ip, gateway_ip, flags, refcnt, use, metric, mask, mtu, window, irtt);
                }
                if (dest_ip == 0) {
                    gateway_in_addr.s_addr = gateway_ip;
                    break;
                }
            } else {
                break;
            }
        }
        
        memset(line, 0, line_len);
        line_num++;
    }
    
    fclose(routing_table_stream);

    if (gateway_in_addr.s_addr == 0) {
        clean_exit_failure("Getting default gateway ip: failed to find default gateway");
    }

    if (DEBUG) {
        printf(GREEN"Getting default gateway ip: found default gateway ip %s\n"COLOR_RESET, inet_ntoa(gateway_in_addr));
    }
    
    return gateway_in_addr;
}

void request_gateway_mac(struct s_net_config *config) {
    struct in_addr gateway_ip = default_gateway_ip();
    
    if (DEBUG) {
        printf("Getting default gateway mac: for gateway ip %s\n", inet_ntoa(gateway_ip));
    }
    
    uint8_t arp_request[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    write_local_broadcast_ethernet_header(config, ETHERTYPE_ARP, arp_request);
    
    write_arp_request(config, &gateway_ip, &arp_request[sizeof(struct ether_header)]);
    
    pcap_t *handle = create_capture_handle(config->device_name); 
    
    char *filter = fstring("arp and arp src host %s and arp[6:2] = 2", inet_ntoa(gateway_ip));

    send_packet(handle, arp_request, sizeof(arp_request));
    
    const uint8_t *packet = read_first_packet(handle, filter, sizeof(struct ether_header) + sizeof(struct ether_arp), 1);
    if (packet == NULL) {
        clean_exit_failure("Failed to get gateway mac");
    }
    struct ether_arp *arp_response = (struct ether_arp *) (packet + sizeof(struct ether_header));
    memcpy(config->gateway_mac, arp_response->arp_sha, ETH_ALEN);
    
    if (DEBUG) {
        printf(GREEN"Getting default gateway mac: found gateway mac: %s\n"COLOR_RESET, mac_to_string(config->gateway_mac));
    }
    
    pcap_close(handle);
}