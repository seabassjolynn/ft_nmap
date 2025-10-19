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

void write_ethernet_header(const struct NetConfig *config, uint8_t *buffer, uint16_t ether_type);

void write_broadcast_ethernet_header(const struct NetConfig *config, uint8_t *buffer, uint16_t ether_type);

void write_arp_request(uint8_t *buffer, const struct NetConfig *config, struct in_addr *target_ip);

void request_gateway_mac(struct NetConfig *config);

#endif