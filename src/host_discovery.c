#include "net.h"
#include "host_discovery.h"
#include <unistd.h>
#include "pcap_utils.h"
#include "utils.h"
#include <string.h>
#include "color_output.h"

static bool ping_echo_remote(const struct s_net_config *config, pcap_t *handle)
{   
    char icmp_data[15] = "are you alive?";
    uint16_t icmp_identifier = getpid();
    int expected_packet_len = sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct s_icmp_header) + sizeof(icmp_data);
    uint8_t packet[expected_packet_len];

    write_ethernet_header_local_to_gateway(config, ETHERTYPE_IP, packet);

    write_ip_header_local_to_remote(config, IPPROTO_ICMP, sizeof(struct s_icmp_header) + sizeof(icmp_data), packet + sizeof(struct ether_header));

    write_icmp_echo_request(icmp_identifier, (uint8_t*)icmp_data, sizeof(icmp_data), packet + sizeof(struct ether_header) + sizeof(struct s_ip_header));

    send_packet(handle, packet, sizeof(packet));
    
    char *filter = fstring("icmp and icmp[icmptype] == %d and icmp[4:2] == %d", ICMP_TYPE_ECHO_REPLY, icmp_identifier);

    const uint8_t *received_packet = read_first_packet(handle, filter, expected_packet_len, 1);

    return received_packet != NULL;
}

static bool ping_timestamp_remote(const struct s_net_config *config, pcap_t *handle) {
    int icmp_payload_len = 12;
    char icmp_data[12];
    memset(icmp_data, 0, sizeof(icmp_data));
    
    int packet_len = sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct s_icmp_header) + icmp_payload_len;
    uint8_t packet[packet_len];

    memset(packet, 0, packet_len);

    write_ethernet_header_local_to_gateway(config, ETHERTYPE_IP, packet);

    write_ip_header_local_to_remote(config, IPPROTO_ICMP, sizeof(struct s_icmp_header) + icmp_payload_len, packet + sizeof(struct ether_header));

    uint16_t icmp_identifier = getpid();
    write_icmp_timestamp_request(icmp_identifier, (uint8_t*)icmp_data, icmp_payload_len, packet + sizeof(struct ether_header) + sizeof(struct s_ip_header));

    send_packet(handle, packet, packet_len);
    
    char *filter = fstring("icmp and icmp[icmptype] == %d and icmp[4:2] == %d", ICMP_TYPE_TIMESTAMP_RESPONSE, icmp_identifier);
    
    const uint8_t *received_packet = read_first_packet(handle, filter, packet_len, 1);
    return received_packet != NULL;
}

static bool probe_with_tcp_syn_to_port_80(const struct s_net_config *config, pcap_t *handle)
{
    uint8_t packet[sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct tcp_header)];
    memset(&packet, 0, sizeof(packet));
    
    write_ethernet_header_local_to_gateway(config, ETHERTYPE_IP, packet);
    
    write_ip_header_local_to_remote(config, IPPROTO_TCP, sizeof(struct s_tcp_header), packet + sizeof(struct ether_header));
    
    struct s_ip_header *ip_header = (struct s_ip_header *) (packet + sizeof(struct ether_header));
    
    struct s_tcp_parameters tcp_parameters;
    init_tcp_parameters(&tcp_parameters);
    tcp_parameters.destination_port = 80;
    tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_SYN;
    tcp_parameters.window_size = 1024;
    tcp_parameters.sequence_number = 0;

    int tcp_packet_offset = sizeof(struct ether_header) + sizeof(struct s_ip_header);
    
    write_tcp_header(ip_header, &tcp_parameters, packet + tcp_packet_offset);
    
    send_packet(handle, packet, sizeof(packet));
    int options_syn_ack = 0;
    options_syn_ack = options_syn_ack | 1 << 1; //syn flag
    options_syn_ack = options_syn_ack | 1 << 4; //ack flag
    char *filter = fstring("tcp and tcp src port %d and src host %s and tcp[tcpflags] == %d", tcp_parameters.destination_port, inet_ntoa(config->target_ip), options_syn_ack);
    const uint8_t *received_packet = read_first_packet(handle, filter, sizeof(packet), 1);
    if (received_packet != NULL) {
        init_tcp_parameters(&tcp_parameters);
        tcp_parameters.destination_port = 80;
        tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_RST | TCP_FLAG_ACK;
        tcp_parameters.window_size = 0;
        tcp_parameters.sequence_number = 1;
        tcp_parameters.ack_number = 1;
        write_tcp_header(ip_header, &tcp_parameters, packet + tcp_packet_offset);
        send_packet(handle, packet, sizeof(packet));
    }

    return received_packet != NULL;
}

static bool probe_with_tcp_syn_to_port_443(const struct s_net_config *config, pcap_t *handle)
{
    uint8_t packet[sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct tcp_header)];
    memset(&packet, 0, sizeof(packet));
    
    write_ethernet_header_local_to_gateway(config, ETHERTYPE_IP, packet);
    
    write_ip_header_local_to_remote(config, IPPROTO_TCP, sizeof(struct s_tcp_header), packet + sizeof(struct ether_header));
    
    struct s_ip_header *ip_header = (struct s_ip_header *) (packet + sizeof(struct ether_header));
    
    struct s_tcp_parameters tcp_parameters;
    init_tcp_parameters(&tcp_parameters);
    tcp_parameters.destination_port = 443;
    tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_SYN;
    tcp_parameters.window_size = 1024;
    tcp_parameters.sequence_number = 0;

    int tcp_packet_offset = sizeof(struct ether_header) + sizeof(struct s_ip_header);
    
    write_tcp_header(ip_header, &tcp_parameters, packet + tcp_packet_offset);
    
    send_packet(handle, packet, sizeof(packet));
    int options_rst = 0;
    options_rst = options_rst | TCP_FLAG_RST;
    options_rst = options_rst | TCP_FLAG_ACK;
    char *filter = fstring("tcp and tcp src port %d and src host %s and tcp[tcpflags] == %d", tcp_parameters.destination_port, inet_ntoa(config->target_ip), options_rst);
    const uint8_t *received_packet = read_first_packet(handle, filter, sizeof(packet), 1);
    return received_packet != NULL;
}

bool is_host_up(const struct s_net_config *config) {
    if (DEBUG) {
        printf(GREEN"Host discovery: target ip %s\n"COLOR_RESET, inet_ntoa(config->target_ip));
    }
    
    pcap_t *handle = create_capture_handle(config->device_name);
    
    bool echo_response = ping_echo_remote(config, handle);
    
    if (DEBUG) {
        printf(GREEN"Host discovery: echo response received %s\n"COLOR_RESET, echo_response == true ? "true" : "false");
    }
    bool timestamp_response = ping_timestamp_remote(config, handle);
    
    if (DEBUG) {
        printf(GREEN"Host discovery: timestamp response received %s\n"COLOR_RESET, timestamp_response == true ? "true" : "false");
    }
    
    bool tcp_syn_80_response = probe_with_tcp_syn_to_port_80(config, handle);
    

    if (DEBUG) {
        printf(GREEN"Host discovery: tcp syn 80 response received %s\n"COLOR_RESET, tcp_syn_80_response == true ? "true" : "false");
    }

    bool tcp_syn_443_response = probe_with_tcp_syn_to_port_443(config, handle);

    if (DEBUG) {
        printf(GREEN"Host discovery: tcp syn 443 response received %s\n"COLOR_RESET, tcp_syn_443_response == true ? "true" : "false");
    }
    
    pcap_close(handle);
    
    return echo_response || timestamp_response || tcp_syn_80_response || tcp_syn_443_response;
}