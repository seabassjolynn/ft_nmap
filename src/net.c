#include "net.h"
#include "resources.h"
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include "color_output.h"

#define IPV4_LEN 4
#define BROADCAST_MAC {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define DO_NOT_WAIT_TO_ACUMULATE_PACKETS 0
#define TCP_HEADER_LEN 20

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
    if (DEBUG) {
        printf(GREEN"Local ip for internet connection: %s\n"COLOR_RESET, inet_ntoa(local_ip.sin_addr));
    }
    return local_ip.sin_addr;
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
    
    if (DEBUG) {
        printf(GREEN"Device for internet connection: %s\n"COLOR_RESET, device_name_out);
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

    if (DEBUG) {
        printf(GREEN"Mac address for device: %s\n"COLOR_RESET, mac_to_string(mac_address_out));
    }
}

void print_mac(uint8_t *arr)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);
}

char * mac_to_string(uint8_t *arr)
{
    static char str[18];
    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);
    return str;
}

void write_ethernet_header_local_to_gateway(const struct NetConfig *config, uint16_t ether_type, uint8_t *buffer)
{
    struct ether_header *eth = (struct ether_header *)buffer;
    memcpy(eth->ether_dhost, config->gateway_mac, ETH_ALEN);
    memcpy(eth->ether_shost, config->device_mac, ETH_ALEN);
    eth->ether_type = htons(ether_type);
}

void write_local_broadcast_ethernet_header(const struct NetConfig *config, uint16_t ether_type, uint8_t *buffer)
{
    struct ether_header *eth = (struct ether_header *)buffer;
    memset(eth->ether_dhost, 0xFF, ETH_ALEN);
    memcpy(eth->ether_shost, config->device_mac, ETH_ALEN);
    eth->ether_type = htons(ether_type);
}

void write_arp_request(const struct NetConfig *config, struct in_addr *target_ip, uint8_t *buffer)
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
    memcpy(arp_request->arp_tpa, target_ip, sizeof(struct in_addr));
}

static uint16_t calculate_checksum(void *addr, int len)
{    
    uint32_t sum = 0;
    while (len > 1)
    {
        sum += *((uint16_t *) addr);  
        addr += 2;
        len -= 2;
    }

    if( len > 0 )
    {
        sum += * (uint8_t*) addr;
    }
               

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

void write_ip_header_local_to_remote(const struct NetConfig *config, uint8_t protocol, uint16_t payload_len, uint8_t *buffer)
{
    struct  ip_header *ip_header = (struct ip_header *)buffer;
    ip_header->ihl_and_version = 0x45;
    ip_header->tos = 0;
    ip_header->total_len = htons(5 * 4 + payload_len);
    ip_header->identification = 0;
    ip_header->fragment_offset = 0;
    ip_header->ttl = 64;
    ip_header->protocol_number = protocol;
    ip_header->checksum = 0;
    ip_header->source_address = config->local_ip.s_addr;
    ip_header->destination_address = config->target_ip.s_addr;
    uint16_t checksum = calculate_checksum(ip_header, sizeof(struct ip_header));
    ip_header->checksum = checksum;
};

void write_icmp_echo_request(uint16_t identifier, uint8_t *data, unsigned long data_len, uint8_t *buffer)
{
    struct icmp_header *icmp_header = (struct icmp_header *)buffer;
    icmp_header->type = 8;
    icmp_header->code = 0;
    icmp_header->checksum = 0;
    icmp_header->identifier = htons(identifier);
    icmp_header->sequence_number = 0;

    memcpy(buffer + sizeof(struct icmp_header), data, data_len);

    uint16_t checksum = calculate_checksum(buffer, sizeof(struct icmp_header) + data_len);
    
    icmp_header -> checksum = checksum;
}

void write_icmp_timestamp_request(uint16_t identifier, uint8_t *data, unsigned long data_len, uint8_t *buffer) {
    struct icmp_header *icmp_header = (struct icmp_header *)buffer;
    icmp_header->type = 13;
    icmp_header->code = 0;
    icmp_header->checksum = 0;
    icmp_header->identifier = htons(identifier);
    icmp_header->sequence_number = 0;

    memcpy(buffer + sizeof(struct icmp_header), data, data_len);

    uint16_t checksum = calculate_checksum(buffer, sizeof(struct icmp_header) + data_len);
    
    icmp_header -> checksum = checksum;
}

void init_tcp_parameters(struct tcp_parameters *parameters)
{
    parameters->destination_port = 0;
    parameters->flags = 0;
    parameters->sequence_number = 0;
    parameters->window_size = DEFAULT_WINDOW_SIZE;
}

void write_tcp_header(struct  ip_header *ip_header, struct tcp_parameters *parameters, uint8_t *packet)
{
    struct tcp_header tcp_header;
    memset(&tcp_header, 0, sizeof(struct tcp_header));

    tcp_header.source_port = htons(42000); //random port
    tcp_header.destination_port = htons(parameters->destination_port);
    tcp_header.sequence_number = htonl(parameters->sequence_number);
    tcp_header.acqnowledgement_number = htonl(parameters->ack_number);
    tcp_header.header_length_and_reserved = tcp_header.header_length_and_reserved | ((sizeof(struct tcp_header) / 4) << 4); //header length in 32-bit words (4 bytes each)
    tcp_header.flags = parameters->flags;
    
    tcp_header.window = htons(parameters->window_size);
    
    //checksum calculation
    struct ip_pseudo_header ip_pseudo_header;
    memset(&ip_pseudo_header, 0, sizeof(struct ip_pseudo_header));
    ip_pseudo_header.source_ip = ip_header->source_address;
    ip_pseudo_header.destination_ip = ip_header->destination_address;
    ip_pseudo_header.protocol = IPPROTO_TCP;
    ip_pseudo_header.tcp_length = htons(sizeof(struct tcp_header));

    uint8_t pseudo_tcp_packet[sizeof(struct ip_pseudo_header) + sizeof(struct tcp_header)];
    
    memset(pseudo_tcp_packet, 0, sizeof(pseudo_tcp_packet));
    
    memcpy(pseudo_tcp_packet, &ip_pseudo_header, sizeof(struct ip_pseudo_header));
    memcpy(pseudo_tcp_packet + sizeof(struct ip_pseudo_header), &tcp_header, sizeof(struct tcp_header));
    
    tcp_header.checksum = calculate_checksum(pseudo_tcp_packet, sizeof(pseudo_tcp_packet));

    memcpy(packet, &tcp_header, sizeof(struct tcp_header));
}

bool is_tcp_syn_set(struct tcp_header *tcp_header)
{
    return tcp_header->flags & TCP_FLAG_SYN;
}

bool is_tcp_ack_set(struct tcp_header *tcp_header)
{
    return tcp_header->flags & TCP_FLAG_ACK;
}

bool is_tcp_rst_set(struct tcp_header *tcp_header)
{
    return tcp_header->flags & TCP_FLAG_RST;
}

char *tcp_display_string(struct tcp_header *tcp_header)
{
    static char packet_display[1024];
    int offset = 0;

    memset(packet_display, 0, sizeof(packet_display));
    char *header_str = GREEN"TCP packet data:\n"COLOR_RESET;
    offset = snprintf(packet_display, sizeof(packet_display), "%s", header_str);

    // Source port
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Source Port: %u\n", ntohs(tcp_header->source_port));

    // Destination port
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Destination Port: %u\n", ntohs(tcp_header->destination_port));

    // Sequence number
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Sequence Number: %u\n", ntohl(tcp_header->sequence_number));

    // Acknowledgement number
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Acknowledgement Number: %u\n", ntohl(tcp_header->acqnowledgement_number));

    // Header length
    uint8_t header_length = (tcp_header->header_length_and_reserved >> 4) * 4;
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Header Length: %u bytes\n", header_length);

    // Flags
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Flags: ");
    int flag_count = 0;
    if (tcp_header->flags & TCP_FLAG_FIN) {
        offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
            "%sFIN", flag_count++ > 0 ? ", " : "");
    }
    if (tcp_header->flags & TCP_FLAG_SYN) {
        offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
            "%sSYN", flag_count++ > 0 ? ", " : "");
    }
    if (tcp_header->flags & TCP_FLAG_RST) {
        offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
            "%sRST", flag_count++ > 0 ? ", " : "");
    }
    if (tcp_header->flags & TCP_FLAG_ACK) {
        offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
            "%sACK", flag_count++ > 0 ? ", " : "");
    }
    if (flag_count == 0) {
        offset += snprintf(packet_display + offset, sizeof(packet_display) - offset, "None");
    }
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset, "\n");

    // Window size
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Window Size: %u\n", ntohs(tcp_header->window));

    // Checksum
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Checksum: 0x%04x\n", ntohs(tcp_header->checksum));

    // Urgent pointer
    offset += snprintf(packet_display + offset, sizeof(packet_display) - offset,
        "  Urgent Pointer: %u\n", ntohs(tcp_header->urgent_pointer));

    return packet_display;
}