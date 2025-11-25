#include "pcap_utils.h"
#include "scans.h"
#include "resources.h"
#include "utils.h"
#include "scan_syn.h"

#include <net/ethernet.h>
#include <netinet/in.h>
#include <string.h>

#define MAX_NO_RESPONSE_RETRIES 2

int scan_syn(const struct NetConfig *config, uint16_t port)
{
    pcap_t *handle = create_capture_handle(config->device_name);
    
    uint8_t outgoing_packet[sizeof(struct ether_header) + sizeof(struct ip_header) + sizeof(struct tcp_header)];
    memset(outgoing_packet, 0, sizeof(outgoing_packet));

    write_local_to_gateway_ethernet_header(config, ETHERTYPE_IP, outgoing_packet);
    write_local_to_remote_ip_header(config, IPPROTO_TCP, sizeof(struct tcp_header), outgoing_packet + sizeof(struct ether_header));
    struct ip_header *outgoing_ip_header = (struct ip_header *) (outgoing_packet + sizeof(struct ether_header));

    struct tcp_parameters tcp_parameters;
    init_tcp_parameters(&tcp_parameters);
    tcp_parameters.destination_port = port;
    tcp_parameters.flags.syn = true;
    tcp_parameters.window_size = DEFAULT_WINDOW_SIZE;
    tcp_parameters.sequence_number = 0;
    
    int tcp_packet_offset = sizeof(struct ether_header) + sizeof(struct ip_header);
    
    write_tcp_packet(outgoing_ip_header, &tcp_parameters, outgoing_packet + tcp_packet_offset);
    
    int response_tcp_flags = 0;
    response_tcp_flags = response_tcp_flags | TCP_FLAG_SYN;
    response_tcp_flags = response_tcp_flags | TCP_FLAG_ACK;
    char *filter = fstring("(tcp");
    //char *filter = fstring("(ip proto tcp && tcp src port %d && src host %s) or (ip proto icmp && icmptype %d)", port, inet_ntoa(config->target_ip), ICMP_TYPE_DESTINATION_UNREACHABLE);
    
    int no_response_retries = 0;
    const uint8_t *received_packet = NULL;
    int ICMP_FULL_FRAME_LEN = sizeof(struct ether_header) + sizeof(struct ip_header) + ICMP_DESTINATION_UNREACHABLE_PACKET_LEN;
    while (received_packet == NULL || no_response_retries < MAX_NO_RESPONSE_RETRIES) {
        send_packet(handle, outgoing_packet, sizeof(outgoing_packet));
        received_packet = read_first_packet(handle, filter, ICMP_FULL_FRAME_LEN, 1);
        no_response_retries++;
    }
    
    if (received_packet != NULL) 
    {
        struct ip_header *ip_header = (struct ip_header *) (received_packet + sizeof(struct ether_header));
        if (ip_header->protocol_number == IPPROTO_TCP) 
        {
            struct tcp_header * tcp_header = (struct tcp_header *) (received_packet + sizeof(struct ether_header) + sizeof (struct ip_header));
            if (is_tcp_syn_set(tcp_header) && is_tcp_ack_set(tcp_header)) 
            {
                init_tcp_parameters(&tcp_parameters);
                tcp_parameters.destination_port = port;
                tcp_parameters.flags.rst = true;
                tcp_parameters.flags.ack = true;
                tcp_parameters.window_size = 0;
                tcp_parameters.sequence_number = 1;
                write_tcp_packet(outgoing_ip_header, &tcp_parameters, outgoing_packet + tcp_packet_offset);
                send_packet(handle, outgoing_packet, sizeof(outgoing_packet));
                return PORT_STATE_OPEN;
            }
            else if (is_tcp_rst_set(tcp_header))
            {
                return PORT_STATE_CLOSED;
            }
            else 
            {
                pcap_close(handle);
                clean_exit_failure(fstring("Expected TCP SYN ACK or RST packet, received:\n %s", tcp_display_string(tcp_header)));
            }
        } 
        else if (ip_header->protocol_number == IPPROTO_ICMP) 
        {
            struct icmp_header *icmp_header = (struct icmp_header *) (received_packet + sizeof(struct ether_header) + sizeof(struct ip_header));
            if (icmp_header->type == ICMP_TYPE_DESTINATION_UNREACHABLE) {
                return PORT_STATE_FILTERED;
            } 
            else 
            {
                pcap_close(handle);
                clean_exit_failure(fstring("Expected ICMP PORT UNREACHABLE type, but received ICMP type: %d", icmp_header->type));
            }
        }
        else 
        {
            pcap_close(handle);
            clean_exit_failure(fstring("Received packet with unknown ip protocol: %d", ip_header->protocol_number));
        }
    } else 
    {
        return PORT_STATE_FILTERED;
    }
    return -1; //should never happen
}