#ifndef NET_H
#define NET_H

#include <stdbool.h>
#include <stdint.h>
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

struct s_net_config {
    char device_name[30];
    uint8_t device_mac[6];
    struct in_addr local_ip;
    
    uint8_t gateway_mac[6];
    struct in_addr target_ip;
    uint16_t target_port;
};

void write_ethernet_header_local_to_gateway(const struct s_net_config *config, uint16_t ether_type, uint8_t *buffer);

void write_local_broadcast_ethernet_header(const struct s_net_config *config, uint16_t ether_type, uint8_t *buffer);

void write_arp_request(const struct s_net_config *config, struct in_addr *target_ip, uint8_t *buffer);

void write_ip_header_local_to_remote(const struct s_net_config *config, uint8_t protocol, uint16_t payload_len, uint8_t *buffer);

#define ICMP_TYPE_TIMESTAMP_RESPONSE 14
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_DESTINATION_UNREACHABLE_PACKET_LEN 12

void write_icmp_echo_request(uint16_t identifier, uint8_t *data, unsigned long data_len, uint8_t *buffer);

void write_icmp_timestamp_request(uint16_t identifier, uint8_t *data, unsigned long data_len, uint8_t *buffer);

struct s_ip_header 
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

struct s_icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence_number;
};

struct s_icmp_destination_unreachable_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t unused;
    uint8_t original_ip_header[20];
    uint8_t original_data[8];
};

#define DEFAULT_WINDOW_SIZE 2048

#define TCP_FLAG_FIN 1
#define TCP_FLAG_SYN 1 << 1
#define TCP_FLAG_RST 1 << 2
#define TCP_FLAG_PSH 1 << 3
#define TCP_FLAG_ACK 1 << 4
#define TCP_FLAG_URG 1 << 5

struct s_tcp_header
{
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acqnowledgement_number;
    uint8_t header_words_len_and_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct s_ip_pseudo_header
{
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t payload_bytes_length;
};

struct s_tcp_parameters
{
    uint16_t destination_port;
    uint8_t flags;
    uint32_t sequence_number;
    uint16_t window_size;
    uint32_t ack_number;
};

struct s_udp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t total_length;
    uint16_t checksum;
};

void init_tcp_parameters(struct s_tcp_parameters *parameters);

void write_tcp_header(struct  s_ip_header *ip_header, struct s_tcp_parameters *parameters, uint8_t *packet);

bool is_tcp_syn_set(struct s_tcp_header *tcp_header);

bool is_tcp_ack_set(struct s_tcp_header *tcp_header);

bool is_tcp_rst_set(struct s_tcp_header *tcp_header);

char *tcp_display_string(struct s_tcp_header *tcp_header);

void write_udp_header(struct  s_ip_header *ip_header, uint8_t *packet, uint16_t destination_port);

void write_ether_ip_header(const struct s_net_config *config, uint8_t transport_protocol, uint16_t payload_len, uint8_t *packet);

void write_full_tcp_header(const struct s_net_config *config, struct s_tcp_parameters tcp_parameters, uint8_t *packet);

#define PACKET_READING_TIMEOUT_SEC_DEFAULT 1

#endif