#ifndef NET_H
#define NET_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE

#define _DEFAULT_SOURCE //otherwise ether_arp is not defined influences #include <netinet/if_ether.h>

#endif


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>

#include <net/ethernet.h>
#include <netinet/if_ether.h>

#define NON_PROMISCUOUS 0
#define FULL_LENGTH_PACKET 262144
#define DO_NOT_WAIT_TO_ACUMULATE_PACKETS 0

struct in_addr local_ip_for_internet_connection(void);

void device_for_internet_connection(struct in_addr *local_ip, char *device_name_out);

void mac_address_for_device(char *device_name, uint8_t *mac_address_out);

void print_mac(uint8_t *arr);

char * mac_to_string(uint8_t *arr);

struct NetConfig {
    char device_name[30];
    uint8_t device_mac[6];
    struct in_addr local_ip;
    
    uint8_t gateway_mac[6];
    struct in_addr target_ip;
    uint16_t target_port;
};

void write_local_to_gateway_ethernet_header(const struct NetConfig *config, uint16_t ether_type, uint8_t *buffer);

void write_local_broadcast_ethernet_header(const struct NetConfig *config, uint16_t ether_type, uint8_t *buffer);

void write_arp_request(const struct NetConfig *config, struct in_addr *target_ip, uint8_t *buffer);

void write_local_to_remote_ip_header(const struct NetConfig *config, uint8_t protocol, uint16_t payload_len, uint8_t *buffer);

void write_icmp_echo_request(uint16_t identifier, uint8_t *data, unsigned long data_len, uint8_t *buffer);

#define ICMP_TYPE_TIMESTAMP_RESPONSE 14
#define ICMP_TYPE_ECHO_REPLY 0

void write_icmp_timestamp_request(uint16_t identifier, uint8_t *data, unsigned long data_len, uint8_t *buffer);

struct ip_header 
{
    uint8_t ihl_and_version;
    uint8_t tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol_number;
    uint16_t checksum;
    uint32_t source_address;
    uint32_t destination_address;
};

struct icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence_number;
};

#endif