#include "net.h"
#include "resources.h"
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdio.h>
#include <fcntl.h>
#include "debug.h"
#include <netinet/if_ether.h>
#include <stdlib.h>

#define IPV4_LEN 4
#define BROADCAST_MAC {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define DO_NOT_WAIT_TO_ACUMULATE_PACKETS 0

struct in_addr local_ip_for_internet_connection(void) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1) {
        clean_exit_failure("Figuring out locl ip. Failed to create socket");
    }
    
    struct sockaddr_in remote;;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons(80);  // dummy port
    inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr); // Google DNS

    if (connect(socket_fd, (struct sockaddr *)&remote, sizeof(remote)) == -1) {
         close(socket_fd);
         clean_exit_failure("Figuring out locl ip. Failed to connect to remote");
    }

    struct sockaddr_in local_ip;
    socklen_t len = sizeof(local_ip);
    if (getsockname(socket_fd, (struct sockaddr *)&local_ip, &len) < 0) {
        close(socket_fd);
        clean_exit_failure("Figuring out locl ip. Failed to get local ip");
    }

    close(socket_fd);
    return local_ip.sin_addr;
}


#define GET_DEFAULT_GATEWAY_IP "Getting default gateway ip: "

static struct in_addr default_gateway_ip(void) {
    struct in_addr gateway_in_addr;
    gateway_in_addr.s_addr = 0;

    FILE *routing_table_stream = fopen("/proc/net/route", "r");
    if (routing_table_stream == NULL) {
        clean_exit_failure(GET_DEFAULT_GATEWAY_IP"Failed to open routing table");
    }
    
    int line_num = 0;
    int line_len = 1024;
    char line[line_len];
    while (fgets(line, line_len, routing_table_stream) != NULL) {
        if (line_num > 0) {
            if (DEBUG) {
                printf(GET_DEFAULT_GATEWAY_IP"Line: %s\n", line);
            }    
            
            char iface[64];
            int flags, refcnt, use, metric, mtu, window, irtt;
            long unsigned int dest_ip, gateway_ip, mask;
            
            if (sscanf(line, "%s %lx %lx %d %d %d %d %lx %d %d %d\n", iface, &dest_ip, &gateway_ip, &flags, &refcnt, &use, &metric, &mask, &mtu, &window, &irtt) == 11) {
                if (DEBUG) {
                    printf(GET_DEFAULT_GATEWAY_IP"Parsed: iface: %s, dest: %lx, gateway: %lx, flags: %d, refcnt: %d, use: %d, metric: %d, mask: %lx, mtu: %d, window: %d, irtt: %d\n", iface, dest_ip, gateway_ip, flags, refcnt, use, metric, mask, mtu, window, irtt);
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
        clean_exit_failure(GET_DEFAULT_GATEWAY_IP"Failed to find default gateway");
    }
        
    return gateway_in_addr;
}

void device_for_internet_connection(struct in_addr *local_ip, char *device_name_out) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        clean_exit_failure("Figuring out device for internet connection. Failed to get ifaddrs");
    }
    
    struct ifaddrs *ifaaddr_tmp = ifaddr;
    while (ifaaddr_tmp != NULL) {
        struct sockaddr *addr = ifaaddr_tmp->ifa_addr;
        
        if (addr != NULL && addr->sa_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            if (addr_in->sin_addr.s_addr == local_ip->s_addr) {
                strcpy(device_name_out, ifaaddr_tmp->ifa_name);
                break;
            }
        }
        ifaaddr_tmp = ifaaddr_tmp->ifa_next;
    }
    
    freeifaddrs(ifaddr);
    
    if (ifaaddr_tmp == NULL) {
        clean_exit_failure("Figuring out device for internet connection. Failed to find device");
    }
}

void mac_address_for_device(char *device_name, uint8_t *mac_address_out) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        clean_exit_failure("Figuring out mac address for device. Failed to get ifaddrs");
    }

    struct ifaddrs *ifaddr_tmp = ifaddr;
    
    while (ifaddr_tmp != NULL) {
        if (strcmp(ifaddr_tmp->ifa_name, device_name) == 0 && ifaddr_tmp->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *addr_ll = (struct sockaddr_ll *)ifaddr_tmp->ifa_addr;
            memcpy(mac_address_out, addr_ll->sll_addr, 6);
            break;
        }
        ifaddr_tmp = ifaddr_tmp->ifa_next;
    }

    freeifaddrs(ifaddr);

    if (ifaddr_tmp == NULL) {
        clean_exit_failure("Figuring out mac address for device. Failed to find device");
    }
}

void print_mac(uint8_t *arr)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);
}

void write_ethernet_header(const struct NetConfig *config, uint8_t *buffer, uint16_t ether_type)
{
    struct ether_header *eth = (struct ether_header *)buffer;
    memcpy(eth->ether_dhost, config->gateway_mac, ETH_ALEN);
    memcpy(eth->ether_shost, config->device_mac, ETH_ALEN);
    eth->ether_type = htons(ether_type);
}

void write_broadcast_ethernet_header(const struct NetConfig *config, uint8_t *buffer, uint16_t ether_type)
{
    struct ether_header *eth = (struct ether_header *)buffer;
    memset(eth->ether_dhost, 0xFF, ETH_ALEN);
    memcpy(eth->ether_shost, config->device_mac, ETH_ALEN);
    eth->ether_type = htons(ether_type);
}

void write_arp_request_for_gateway(uint8_t *buffer, const struct NetConfig *config)
{
    struct ether_arp *arp_request = (struct ether_arp *)buffer;
    
    memset(arp_request, 0, sizeof(struct ether_arp));

   arp_request->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
   arp_request->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
   arp_request->ea_hdr.ar_hln = ETH_ALEN;
   arp_request->ea_hdr.ar_pln = IPV4_LEN;
   arp_request->ea_hdr.ar_op = htons(ARPOP_REQUEST);

   memcpy(arp_request->arp_sha, config->device_mac, ETH_ALEN);
   memcpy(arp_request->arp_spa, &config->local_ip, sizeof(struct in_addr));
   memset(arp_request->arp_tha, 0xFF, ETH_ALEN); //broadcast mac
   memcpy(arp_request->arp_tpa, &config->target_ip, sizeof(struct in_addr));
}

#define GET_GATEWAY_MAC "Getting default gateway mac: "

void request_gateway_mac(struct NetConfig *config) {
    uint8_t arp_request[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    write_broadcast_ethernet_header(config, arp_request, ETHERTYPE_ARP);
    write_arp_request_for_gateway(&arp_request[sizeof(struct ether_header)], config);

    struct in_addr gateway_ip = default_gateway_ip();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t *capture_handle = pcap_open_live(config->device_name, FULL_LENGTH_PACKET, NON_PROMISCUOUS, DO_NOT_WAIT_TO_ACUMULATE_PACKETS, errbuf);
    if (capture_handle == NULL) {
        pcap_close(capture_handle);
        fprintf(stderr, "Failed to open capture handle: %s\n", errbuf);
        clean_exit_failure(GET_GATEWAY_MAC"Failed to open capture handle");
    }
    
    bpf_u_int32 net=0, mask=0;
    if(pcap_lookupnet(config->device_name, &net, &mask, errbuf)) {
        pcap_close(capture_handle);
        fprintf(stderr, "Failed to lookup network: %s\n", errbuf);
        clean_exit_failure(GET_GATEWAY_MAC"Failed to lookup network");
    }

    struct bpf_program prog;
    
    char filter[256];
    char *target_ip = inet_ntoa(gateway_ip);
    if (target_ip == NULL) {
        pcap_close(capture_handle);
        clean_exit_failure(GET_GATEWAY_MAC"Failed to convert gateway ip to string");
    }
    
    snprintf(filter, sizeof(filter), "icmp and icmp[icmptype] == icmp-echoreply and src host %s", target_ip);
 
    if (pcap_compile(capture_handle, &prog, filter, 1 /*optimize*/, mask)) {
        pcap_perror(capture_handle, GET_GATEWAY_MAC"Failed to compile filter");
        pcap_close(capture_handle);
        pcap_freecode(&prog);
        clean_exit_failure(GET_GATEWAY_MAC"Failed to convert gateway ip to string");
    }
    
    if (pcap_setfilter(capture_handle, &prog)) {
        pcap_perror(capture_handle, GET_GATEWAY_MAC"Failed to set filter");
        pcap_freecode(&prog);
        pcap_close(capture_handle);
    }
    pcap_freecode(&prog);

    if (pcap_sendpacket(capture_handle, arp_request, sizeof(arp_request))) {
        pcap_perror(capture_handle, GET_GATEWAY_MAC"Failed to send arp request");
        pcap_close(capture_handle);
        clean_exit_failure(GET_GATEWAY_MAC"Failed to send arp request");
    }
    pcap_close(capture_handle);
}
