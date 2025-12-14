#include "net.h"
#include "pcap_utils.h"
#include "scans.h"
#include "resources.h"
#include "utils.h"
#include "color_output.h"
#include "debug.h"

#include <net/ethernet.h>
#include <netinet/in.h>
#include <string.h>

#define MAX_NO_RESPONSE_RETRIES 2
#define TCP_FULL_HEADER_LEN (sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct s_tcp_header))
#define TRANSPORT_HEADER_OFFSET (sizeof(struct ether_header) + sizeof(struct s_ip_header))
#define ICMP_FULL_HEADER_LEN (sizeof(struct ether_header) + sizeof(struct s_ip_header) + ICMP_DESTINATION_UNREACHABLE_PACKET_LEN)
#define UDP_FULL_HEADER_LEN (sizeof(struct ether_header) + sizeof(struct s_ip_header) + sizeof(struct s_udp_header))

#define PORT_OFFSET_IN_ICMP_PACKET 30

static void send_and_receive_packet_with_retries(const char *scan_type, pcap_t *handle, uint8_t *outgoing_packet, int outgoing_packet_size, const char *filter, struct s_read_packet_result *received_packet, unsigned int timeout_sec)
{
    int no_response_retries = 0;
    while (received_packet->packet == NULL && no_response_retries <= MAX_NO_RESPONSE_RETRIES)
    {
        if (DEBUG) printf(GREEN"%s SCAN: sending packet, attempt %d out of %d\n"COLOR_RESET, scan_type, no_response_retries + 1, MAX_NO_RESPONSE_RETRIES + 1);
        
        send_packet(handle, outgoing_packet, outgoing_packet_size);
        read_first_packet(handle, filter, received_packet, timeout_sec);
        no_response_retries++;
    }
}

//The scan can detect open, closed and filtered ports.
//If RST is received back - port is closed, ICPM (destination unreachable) - port is filtered, no response - port is open or filtered.
enum port_state scan_syn(const struct s_net_config *config, uint16_t port)
{
    char *scan_type = "SYN";
    if (DEBUG) printf(GREEN"%s SCAN: target ip %s, port %d\n"COLOR_RESET, scan_type, inet_ntoa(config->target_ip), port);
    
    pcap_t *handle = create_capture_handle(config->device_name);
    
    uint8_t outgoing_packet[TCP_FULL_HEADER_LEN];
    memset(outgoing_packet, 0, sizeof(outgoing_packet));

    struct s_tcp_parameters tcp_parameters;
    init_tcp_parameters(&tcp_parameters);
    tcp_parameters.destination_port = port;
    tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_SYN;
    tcp_parameters.window_size = DEFAULT_WINDOW_SIZE;
    tcp_parameters.sequence_number = 0;
    
    write_full_tcp_header(config, tcp_parameters, outgoing_packet);
    
    char *filter = fstring("((tcp && tcp src port %d) or (icmp && icmp[icmptype] == %d && icmp[%d:2] == %d)) && src host %s", port, ICMP_TYPE_DESTINATION_UNREACHABLE, PORT_OFFSET_IN_ICMP_PACKET, port, inet_ntoa(config->target_ip));
    
    enum port_state scan_result = UNKNOWN;

    struct s_read_packet_result received_packet_result;
    init_read_packet_result(&received_packet_result);

    send_and_receive_packet_with_retries(scan_type, handle, outgoing_packet, sizeof(outgoing_packet), filter, &received_packet_result, PACKET_READING_TIMEOUT_SEC_DEFAULT);
    
    if (received_packet_result.packet != NULL)
    {
        if (DEBUG) printf(GREEN"%s SCAN: received packet\n"COLOR_RESET, scan_type);
        
        struct s_ip_header *ip_header = (struct s_ip_header *) (received_packet_result.packet + sizeof(struct ether_header));
        if (ip_header->protocol_number == IPPROTO_TCP) 
        {
            struct s_tcp_header * tcp_header = (struct s_tcp_header *) (received_packet_result.packet + sizeof(struct ether_header) + sizeof (struct s_ip_header));
            if (is_tcp_syn_set(tcp_header) && is_tcp_ack_set(tcp_header)) 
            {
                if (DEBUG) printf(GREEN"%s SCAN: received TCP SYN ACK packet, sending RST packet\n"COLOR_RESET, scan_type);
                
                init_tcp_parameters(&tcp_parameters);
                tcp_parameters.destination_port = port;
                tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_RST;
                tcp_parameters.window_size = 0;
                tcp_parameters.sequence_number = 1;
                
                memset(outgoing_packet, 0, sizeof(outgoing_packet));
                
                write_full_tcp_header(config, tcp_parameters, outgoing_packet);

                send_packet(handle, outgoing_packet, sizeof(outgoing_packet));
                
                if (DEBUG) printf(GREEN"%s SCAN: PORT IS OPEN\n"COLOR_RESET, scan_type);
                scan_result = OPEN;
            }
            else if (is_tcp_rst_set(tcp_header))
            {
                if (DEBUG) printf(GREEN"%s SCAN: received TCP RST packet\n"COLOR_RESET, scan_type);
                if (DEBUG) printf(GREEN"%s SCAN: PORT IS CLOSED\n"COLOR_RESET, scan_type);
                scan_result = CLOSED;
            }
        } 
        else if (ip_header->protocol_number == IPPROTO_ICMP) 
        {   
            if (DEBUG) printf(GREEN"%s SCAN: received ICMP PORT UNREACHABLE packet\n"COLOR_RESET, scan_type);
            if (DEBUG) printf(GREEN"%s SCAN: PORT IS FILTERED\n"COLOR_RESET, scan_type);
            scan_result = FILTERED;
        }
    }
    else 
    {
        if (DEBUG) printf(GREEN"%s SCAN: no response received\n"COLOR_RESET, scan_type);
        if (DEBUG) printf(GREEN"%s SCAN: PORT IS FILTERED\n"COLOR_RESET, scan_type);
        scan_result = FILTERED;
    }
    pcap_close(handle);
    if (scan_result == UNKNOWN)
    {
        clean_exit_failure("Failed to detect port state");
    }
    
    return scan_result;
}

const char *scan_type_to_string(enum scan_type type)
{
    static const char *names[] = {
        [SCAN_FIN]  = "FIN",
        [SCAN_NULL] = "NULL",
        [SCAN_XMAS] = "XMAS"
    };
    return names[type];
}


//This scan can perform NULL, FIN, XMAS scans. The idea of these scans is to send a TCP packet that has unusual flags set - the main thing is no SYN flag.
//According to the RFC, if port is closed, the host should respond with an RST packet in case TCP doesn't have SYN, RST or ACK flags). If port is open, the 
//host should just drop packet without SYN, RST or ACK flags. 
//
// How we interpret host reponse:
// - no response, the port may be opened (host dropped the packet) or filtered (host didn't respond at all).
// - RST packet, the port is closed.
//
//Why do we need this type of scan, when we can for example send SYN scan for which opened port will send us SYN ACK packet - so we know for sure that port is opened or filtered (in case no response).
//Closed ports will respond with RST packet, so we can detect closed port as well. 
//
// This scan is useful in the situation, when closed port is protected by a firewall. So SYN scan receives no reply and we don't know if the port opened or closed. We can only say it is filtered.
//Some times the firewalls only drop the incoming SYN packets. So this scan can surpass anti-SYN firewall protection and detect closed ports. Althogh such firewalls are rare and the OS is not necessarily configured
//to anser with RST on closed ports to packets that don't have SYN, ACK or RST. So this scan is just additional tool that may help to detect closed port protected by specific firewall.
enum port_state scan(enum scan_type scan_type, const struct s_net_config *config, uint16_t port)
{
    if (scan_type == SCAN_SYN || scan_type == SCAN_ACK || scan_type == SCAN_UDP)
    {
        clean_exit_failure("This scan type is not supported");
    }
    if (DEBUG) printf(GREEN"%s SCAN: target ip %s, port %d\n"COLOR_RESET, scan_type_to_string(scan_type), inet_ntoa(config->target_ip), port);
    
    pcap_t *handle = create_capture_handle(config->device_name);
    
    uint8_t outgoing_packet[TCP_FULL_HEADER_LEN];
    memset(outgoing_packet, 0, sizeof(outgoing_packet));

    struct s_tcp_parameters tcp_parameters;
    init_tcp_parameters(&tcp_parameters);
    tcp_parameters.destination_port = port;
    if (scan_type == SCAN_FIN) 
    {
        tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_FIN;
    } 
    else if (scan_type == SCAN_XMAS)
    {
        tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_FIN | TCP_FLAG_PSH | TCP_FLAG_URG;
    }
    else if (scan_type == SCAN_NULL)
    {
        //no flags should be set
    }
    tcp_parameters.window_size = DEFAULT_WINDOW_SIZE;
    tcp_parameters.sequence_number = 0;
    
    write_full_tcp_header(config, tcp_parameters, outgoing_packet);
    
    char *filter = fstring("((tcp && tcp src port %d && tcp[tcpflags] == %d) or (icmp && icmp[icmptype] == %d && icmp[%d:2] == %d)) && src host %s", port, TCP_FLAG_RST, ICMP_TYPE_DESTINATION_UNREACHABLE, PORT_OFFSET_IN_ICMP_PACKET, port, inet_ntoa(config->target_ip));
    
    enum port_state scan_result = UNKNOWN;

    struct s_read_packet_result received_packet_result;
    init_read_packet_result(&received_packet_result);
    
    send_and_receive_packet_with_retries(scan_type_to_string(scan_type), handle, outgoing_packet, sizeof(outgoing_packet), filter, &received_packet_result, PACKET_READING_TIMEOUT_SEC_DEFAULT);
    if (received_packet_result.packet != NULL)
    {
        if (DEBUG) printf(GREEN"%s SCAN: received packet\n"COLOR_RESET, scan_type_to_string(scan_type));
        
        struct s_ip_header *ip_header = (struct s_ip_header *) (received_packet_result.packet + sizeof(struct ether_header));
        if (ip_header->protocol_number == IPPROTO_TCP)
        {
            if (DEBUG) printf(GREEN"%s SCAN: received TCP RST packet\n"COLOR_RESET, scan_type_to_string(scan_type));
            if (DEBUG) printf(GREEN"%s SCAN: PORT IS CLOSED\n"COLOR_RESET, scan_type_to_string(scan_type));
            scan_result = CLOSED;
        }
        else if (ip_header->protocol_number == IPPROTO_ICMP) 
        {   
            if (DEBUG) printf(GREEN"%s SCAN: received ICMP PORT UNREACHABLE packet\n"COLOR_RESET, scan_type_to_string(scan_type));
            if (DEBUG) printf(GREEN"%s SCAN: PORT IS FILTERED\n"COLOR_RESET, scan_type_to_string(scan_type));
            scan_result = FILTERED;
        }
    }
    else 
    {
        if (DEBUG) printf(GREEN"%s SCAN: no response received\n"COLOR_RESET, scan_type_to_string(scan_type));
        if (DEBUG) printf(GREEN"%s SCAN: PORT IS OPEN | FILTERED\n"COLOR_RESET, scan_type_to_string(scan_type));
        scan_result = OPEN_FILTERED;
    }
    pcap_close(handle);
    if (scan_result == UNKNOWN)
    {
        clean_exit_failure("Failed to detect port state");
    }
    return scan_result;
}
//When scanning unfiltered systems, open and closed ports will both return a RST packet. 
//Nmap then labels them as unfiltered, meaning that they are reachable by the ACK packet, but whether they are open or closed is undetermined. 
//Ports that don't respond, or send certain ICMP error messages back, are labeled filtered.
enum port_state scan_ack(const struct s_net_config *config, uint16_t port)
{
    char *scan_type = "ACK";
    if (DEBUG) printf(GREEN"%s SCAN: target ip %s, port %d\n"COLOR_RESET, scan_type, inet_ntoa(config->target_ip), port);
    
    pcap_t *handle = create_capture_handle(config->device_name);
    
    uint8_t outgoing_packet[TCP_FULL_HEADER_LEN];
    memset(outgoing_packet, 0, sizeof(outgoing_packet));
    
    struct s_tcp_parameters tcp_parameters;
    init_tcp_parameters(&tcp_parameters);
    tcp_parameters.destination_port = port;
    tcp_parameters.flags = tcp_parameters.flags | TCP_FLAG_ACK;
    tcp_parameters.window_size = DEFAULT_WINDOW_SIZE;
    tcp_parameters.sequence_number = 0;
    
    write_full_tcp_header(config, tcp_parameters, outgoing_packet);
    
    //possible responses for ack scan:
    //- TCP RST response - unfiltered
    //- No response received (even after retransmissions) - filtered
    //- ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)	 - filtered
    char *filter = fstring("((tcp && tcp src port %d && tcp[tcpflags] == %d) or (icmp && icmp[icmptype] == %d && icmp[%d:2] == %d)) && src host %s", port, TCP_FLAG_RST, ICMP_TYPE_DESTINATION_UNREACHABLE, PORT_OFFSET_IN_ICMP_PACKET, port, inet_ntoa(config->target_ip));
    
    enum port_state scan_result = UNKNOWN;

    struct s_read_packet_result received_packet_result;
    init_read_packet_result(&received_packet_result);
    
    send_and_receive_packet_with_retries(scan_type, handle, outgoing_packet, sizeof(outgoing_packet), filter, &received_packet_result, PACKET_READING_TIMEOUT_SEC_DEFAULT);
    
    if (received_packet_result.packet != NULL)
    {
        if (DEBUG) printf(GREEN"%s SCAN: received packet\n"COLOR_RESET, scan_type);
        
        struct s_ip_header *ip_header = (struct s_ip_header *) (received_packet_result.packet + sizeof(struct ether_header));
        if (ip_header->protocol_number == IPPROTO_TCP)
        {
            if (DEBUG) printf(GREEN"%s SCAN: received TCP RST packet\n"COLOR_RESET, scan_type);
            if (DEBUG) printf(GREEN"%s SCAN: PORT IS UNFILTERED\n"COLOR_RESET, scan_type);
            scan_result = UNFILTERED;
        } 
        else if (ip_header->protocol_number == IPPROTO_ICMP) 
        {   
            if (DEBUG) printf(GREEN"%s SCAN: received ICMP PORT UNREACHABLE packet\n"COLOR_RESET, scan_type);
            if (DEBUG) printf(GREEN"%s SCAN: PORT IS FILTERED\n"COLOR_RESET, scan_type);
            scan_result = FILTERED;
        }
    }
    else 
    {
        if (DEBUG) printf(GREEN"%s SCAN: no response received\n"COLOR_RESET, scan_type);
        if (DEBUG) printf(GREEN"%s SCAN: PORT IS OPEN | FILTERED\n"COLOR_RESET, scan_type);
        scan_result = FILTERED;
    }
    pcap_close(handle);
    if (scan_result == UNKNOWN)
    {
        clean_exit_failure("Failed to detect port state");
    }
    return scan_result;
}

enum port_state scan_udp(const struct s_net_config *config, uint16_t port)
{
    char *scan_type = "UDP";
    if (DEBUG) printf(GREEN"%s SCAN: target ip %s, port %d\n"COLOR_RESET, scan_type, inet_ntoa(config->target_ip), port);
    
    pcap_t *handle = create_capture_handle(config->device_name);
    
    uint8_t outgoing_packet[UDP_FULL_HEADER_LEN];
    memset(outgoing_packet, 0, sizeof(outgoing_packet));

    write_ether_ip_header(config, IPPROTO_UDP, sizeof(struct s_udp_header), outgoing_packet);

    struct s_ip_header *outgoing_ip_header = (struct s_ip_header *) (outgoing_packet + sizeof(struct ether_header));
    write_udp_header(outgoing_ip_header, outgoing_packet + TRANSPORT_HEADER_OFFSET, port);
    
    //possible responses for udp scan:
    //- Any UDP response from target port (unusual) - open
    //- No response received (even after retransmissions) - open|filtered
    //- ICMP port unreachable error (type 3, code 3) - closed
    //- Other ICMP unreachable errors (type 3, code 1, 2, 9, 10, or 13) - filtered
    
    //DO NOT COVERT LOCAL BYTE ORDER TO NETWORK BYTE ORDER IN FILTER STRING
    char *filter = fstring("((udp && udp src port %d) or (icmp && icmp[icmptype] == %d && icmp[%d:2] == %d)) and src host %s", port, ICMP_TYPE_DESTINATION_UNREACHABLE, PORT_OFFSET_IN_ICMP_PACKET, port, inet_ntoa(config->target_ip));
    
    enum port_state scan_result = UNKNOWN;

    struct s_read_packet_result received_packet_result;
    init_read_packet_result(&received_packet_result);
    
    send_and_receive_packet_with_retries(scan_type, handle, outgoing_packet, sizeof(outgoing_packet), filter, &received_packet_result, PACKET_READING_TIMEOUT_SEC_DEFAULT);
    
    if (received_packet_result.packet != NULL)
    {
        if (DEBUG) printf(GREEN"%s SCAN: received packet\n"COLOR_RESET, scan_type);
        
        struct s_ip_header *ip_header = (struct s_ip_header *) (received_packet_result.packet + sizeof(struct ether_header));
        if (ip_header->protocol_number == IPPROTO_UDP)
        {
            if (DEBUG) printf(GREEN"%s SCAN: received UDP reponse packet\n"COLOR_RESET, scan_type);
            if (DEBUG) printf(GREEN"%s SCAN: PORT IS OPEN\n"COLOR_RESET, scan_type);
            scan_result = OPEN;
        } 
        else if (ip_header->protocol_number == IPPROTO_ICMP) 
        {
            struct s_icmp_destination_unreachable_header *icmp_header = (struct s_icmp_destination_unreachable_header *) (received_packet_result.packet + sizeof(struct ether_header) + sizeof(struct s_ip_header));
        
            if (icmp_header->code == 3)
            {
                if (DEBUG) printf(GREEN"%s SCAN: received ICMP PORT UNREACHABLE packet with code 3\n"COLOR_RESET, scan_type);
                if (DEBUG) printf(GREEN"%s SCAN: PORT IS CLOSED\n"COLOR_RESET, scan_type);
                scan_result = CLOSED;
            } else if (icmp_header->code == 1 || icmp_header->code == 2 || icmp_header->code == 9 || icmp_header->code == 10 || icmp_header->code == 13)
            {
                if (DEBUG) printf(GREEN"%s SCAN: received ICMP PORT UNREACHABLE packet with code %d\n"COLOR_RESET, scan_type, icmp_header->code);
                if (DEBUG) printf(GREEN"%s SCAN: PORT IS FILTERED\n"COLOR_RESET, scan_type);
                scan_result = FILTERED;
            } else {
                if (DEBUG) printf(GREEN"%s SCAN: received ICMP PORT UNREACHABLE packet with unknown code %d\n"COLOR_RESET, scan_type, icmp_header->code);
            }
        }
    }
    else 
    {
        if (DEBUG) printf(GREEN"%s SCAN: no response received\n"COLOR_RESET, scan_type);
        if (DEBUG) printf(GREEN"%s SCAN: PORT IS OPEN | FILTERED\n"COLOR_RESET, scan_type);
        scan_result = OPEN_FILTERED;
    }
    pcap_close(handle);
    if (scan_result == UNKNOWN)
    {
        clean_exit_failure("Failed to detect port state");
    }
    return scan_result;
}
