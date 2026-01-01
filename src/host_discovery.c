#include "arguments.h"
#include "net.h"
#include "host_discovery.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <unistd.h>
#include "pcap_utils.h"
#include <string.h>
#include "unique_ids.h"
#include "queue.h"
#define LOG_TAG "Host discovery: "

static bool probe_with_ping_echo_remote(const struct s_net_config *config)
{   
    if (DEBUG) { printf("Host discovery: sending echo ping to host %s\n", inet_ntoa(config->target_ip));}

    pcap_t *handle = create_capture_handle(config->device_name);

    char icmp_data[15] = "are you alive?";
    uint16_t icmp_identifier = get_unique_id();
    int expected_packet_len = sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct s_icmp_header) + sizeof(icmp_data);
    uint8_t packet[expected_packet_len];

    write_ether_ip_header(config, IPPROTO_ICMP, sizeof(struct s_icmp_header) + sizeof(icmp_data), packet);

    write_icmp_echo_request(icmp_identifier, (uint8_t*)icmp_data, sizeof(icmp_data), packet + sizeof(struct ether_header) + sizeof(struct s_ip_header));

    send_packet(handle, packet, sizeof(packet));
    
    char filter[512];
    snprintf(filter, sizeof(filter), "icmp and icmp[icmptype] == %d and icmp[4:2] == %d", ICMP_TYPE_ECHO_REPLY, icmp_identifier);

    struct s_read_packet_result received_packet_result;
    init_read_packet_result(&received_packet_result);
    read_first_packet(handle, filter, &received_packet_result, 1);
    pcap_close(handle);
    return received_packet_result.packet != NULL;
}

static bool probe_with_ping_timestamp_remote(const struct s_net_config *config) 
{
    if (DEBUG) { printf("Host discovery: sending time stamp request to host %s\n", inet_ntoa(config->target_ip));}
    
    pcap_t *handle = create_capture_handle(config->device_name);

    int icmp_payload_len = 12;
    char icmp_data[12];
    memset(icmp_data, 0, sizeof(icmp_data));
    
    int packet_len = sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct s_icmp_header) + icmp_payload_len;
    uint8_t packet[packet_len];

    memset(packet, 0, packet_len);
    
    write_ether_ip_header(config, IPPROTO_ICMP, sizeof(struct s_icmp_header) + icmp_payload_len, packet);

    uint16_t icmp_identifier = get_unique_id();
    
    write_icmp_timestamp_request(icmp_identifier, (uint8_t*)icmp_data, icmp_payload_len, packet + sizeof(struct ether_header) + sizeof(struct s_ip_header));

    send_packet(handle, packet, packet_len);
    
    char filter[512];
    snprintf(filter, sizeof(filter), "icmp and icmp[icmptype] == %d and icmp[4:2] == %d", ICMP_TYPE_TIMESTAMP_RESPONSE, icmp_identifier);
    
    struct s_read_packet_result received_packet_result;
    init_read_packet_result(&received_packet_result);
    read_first_packet(handle, filter, &received_packet_result, 1);
    pcap_close(handle);
    return received_packet_result.packet != NULL;
}

static bool probe_with_tcp_syn_to_port_80(const struct s_net_config *config)
{
    uint8_t packet[sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct s_tcp_header)];
    memset(&packet, 0, sizeof(packet));
    
    struct s_tcp_parameters tcp_parameters;
    init_tcp_parameters(&tcp_parameters);
    tcp_parameters.source_port = get_unique_id();
    tcp_parameters.destination_port = 80;
    tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_SYN;
    tcp_parameters.window_size = 1024;
    tcp_parameters.sequence_number = 0;

    write_full_tcp_header(config, tcp_parameters, packet);
    
    pcap_t *handle = create_capture_handle(config->device_name);

    if (DEBUG) { printf("Host discovery: sending tcp syn to host %s, source port %d destination port %d\n", inet_ntoa(config->target_ip), tcp_parameters.source_port, tcp_parameters.destination_port);}

    send_packet(handle, packet, sizeof(packet));
    char filter[512];
    snprintf(filter, sizeof(filter), "tcp and tcp src port %d and tcp dst port %d and src host %s and tcp[tcpflags] == %d", tcp_parameters.destination_port, tcp_parameters.source_port, inet_ntoa(config->target_ip), TCP_FLAG_SYN | TCP_FLAG_ACK);
    
    struct s_read_packet_result received_packet_result;
    init_read_packet_result(&received_packet_result);
    read_first_packet(handle, filter, &received_packet_result, 1);
    if (received_packet_result.packet != NULL) {
        init_tcp_parameters(&tcp_parameters);
        tcp_parameters.destination_port = 80;
        tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_RST;
        tcp_parameters.window_size = 0;
        tcp_parameters.sequence_number = 1;
        tcp_parameters.ack_number = 0;
        memset(packet, 0, sizeof(packet));
        write_full_tcp_header(config, tcp_parameters, packet);
        send_packet(handle, packet, sizeof(packet));
    }
    pcap_close(handle);
    return received_packet_result.packet != NULL;
}

static bool probe_with_tcp_syn_to_port_443(const struct s_net_config *config)
{
    uint8_t packet[sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct s_tcp_header)];
    memset(&packet, 0, sizeof(packet));
    
    struct s_tcp_parameters tcp_parameters;
    init_tcp_parameters(&tcp_parameters);
    tcp_parameters.source_port = get_unique_id();
    tcp_parameters.destination_port = 443;
    tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_SYN;
    tcp_parameters.window_size = 1024;
    tcp_parameters.sequence_number = 0;

    write_full_tcp_header(config, tcp_parameters, packet);
    
    if (DEBUG) { printf("Host discovery: sending tcp syn to host %s, source port %d destination port %d\n", inet_ntoa(config->target_ip), tcp_parameters.source_port, tcp_parameters.destination_port);}

    pcap_t *handle = create_capture_handle(config->device_name);

    send_packet(handle, packet, sizeof(packet));

    char filter[512];
    snprintf(filter, sizeof(filter), "tcp and tcp src port %d and tcp dst port %d and src host %s and tcp[tcpflags] == %d", tcp_parameters.destination_port, tcp_parameters.source_port, inet_ntoa(config->target_ip), TCP_FLAG_RST | TCP_FLAG_ACK);
    
    struct s_read_packet_result received_packet_result;
    init_read_packet_result(&received_packet_result);
    read_first_packet(handle, filter, &received_packet_result, 1);
    pcap_close(handle);
    return received_packet_result.packet != NULL;
}

void create_host_discovery_tasks_and_add_to_queue(struct s_arguments *arguments, struct s_net_config *net_config)
{
    int i = 0;
    while (i < arguments->hosts_size)
    {
        struct in_addr s = {arguments->hosts[i].target_ip};
        char *ip_str = inet_ntoa(s);
        
        struct s_task task;
        memset(&task, 0, sizeof(struct s_task));
        task.is_scan = false;
        task.net_config = *net_config;
        task.net_config.target_ip.s_addr = arguments->hosts[i].target_ip;
        
        if (DEBUG) { printf(LOG_TAG"Creating task (echo ping probe for host %s)\n", ip_str); }

        task.is_host_up_func = &probe_with_ping_echo_remote;
        queue_add(task);

        if (DEBUG) { printf(LOG_TAG"Creating task (timestamp ping probe for host %s)\n", ip_str); }

        task.is_host_up_func = &probe_with_ping_timestamp_remote;
        queue_add(task);
        
        if (DEBUG) { printf(LOG_TAG"Creating task (tcp syn (443) probe for host %s)\n", ip_str); }

        task.is_host_up_func = &probe_with_tcp_syn_to_port_443;
        queue_add(task);

        if (DEBUG) { printf(LOG_TAG"Creating task (tcp syn (80) probe for host %s)\n", ip_str); }

        task.is_host_up_func = &probe_with_tcp_syn_to_port_80;
        queue_add(task);
        i++;
    }
    
}