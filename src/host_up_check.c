#include "net.h"
#include "host_up_check.h"
#include <unistd.h>
#include "pcap_utils.h"
#include "utils.h"
#include <string.h>

bool ping_echo_remote(const struct NetConfig *config, pcap_t *handle)
{
    char icmp_data[14] = "are you alive?";
    uint16_t icmp_identifier = getpid();
    int expected_packet_len = sizeof(struct ether_header) + sizeof(struct ip_header) + sizeof(struct icmp_header) + sizeof(icmp_data);
    uint8_t packet[expected_packet_len];

    write_local_to_gateway_ethernet_header(config, ETHERTYPE_IP, packet);

    write_local_to_remote_ip_header(config, IPPROTO_ICMP, sizeof(struct icmp_header) + sizeof(icmp_data), packet + sizeof(struct ether_header));

    write_icmp_echo_request(icmp_identifier, (uint8_t*)icmp_data, sizeof(icmp_data), packet + sizeof(struct ether_header) + sizeof(struct ip_header));

    send_packet(handle, packet, sizeof(packet));
    
    char *filter = fstring("icmp and icmp[4:2] == %d", icmp_identifier);

    set_packet_filter(handle, filter);
    
    uint8_t *received_packet = get_next_packet(handle, expected_packet_len);

    return received_packet != NULL;
}

bool ping_timestamp_remote(const struct NetConfig *config, pcap_t *handle) {
    int icmp_payload_len = 12;
    char icmp_data[12];
    memset(icmp_data, 0, sizeof(icmp_data));
    
    int packet_len = sizeof(struct ether_header) + sizeof(struct ip_header) + sizeof(struct icmp_header) + icmp_payload_len;
    uint8_t packet[packet_len];

    memset(packet, 0, packet_len);

    write_local_to_gateway_ethernet_header(config, ETHERTYPE_IP, packet);

    write_local_to_remote_ip_header(config, IPPROTO_ICMP, sizeof(struct icmp_header) + icmp_payload_len, packet + sizeof(struct ether_header));

    uint16_t icmp_identifier = getpid();
    write_icmp_timestamp_request(icmp_identifier, (uint8_t*)icmp_data, icmp_payload_len, packet + sizeof(struct ether_header) + sizeof(struct ip_header));

    send_packet(handle, packet, packet_len);
    return false;
}