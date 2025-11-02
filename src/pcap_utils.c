#include "pcap_utils.h"
#include "resources.h"
#include "utils.h"

#define MAX_PACKET_LENGTH 65535
#define NO_PROMISCUOUS_MODE 0
//deliver packets right away to pcap, OS don't buffers the packets. Overhead: pcap uses system calls far single packet
//not for bunch of packets
#define IMMEDIATE_MODE_ON 1

pcap_t *create_capture_handle(const char *device_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(device_name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed to create capture handle: %s\n", errbuf);
        clean_exit_failure("Failed to create caputre handle");
    }

    if (pcap_set_snaplen(handle, MAX_PACKET_LENGTH) != 0) {
        pcap_close(handle);
        clean_exit_failure("Failed to set packet length");
    }

    if (pcap_set_promisc(handle, NO_PROMISCUOUS_MODE)) {
        pcap_close(handle);
        clean_exit_failure("Failed to configure promiscuous mode");
    }

    if (pcap_set_immediate_mode(handle, IMMEDIATE_MODE_ON) != 0) {
        pcap_close(handle);
        clean_exit_failure("Failed to configure immediate packet deivery");
    }

    if (pcap_activate(handle) != 0) {
        pcap_perror(handle, "Handle activation failure.");
        pcap_close(handle);
        clean_exit_failure("Handle activation failure.");
    }

    return handle;
}

void set_packet_filter(pcap_t *handle, char *filter) {
    struct bpf_program program;
    
    //mask is used when broadcast packets are filtered, if not PCAP_NETMASK_UNKNOWN may be used
    if (pcap_compile(handle, &program, filter, 1 /*optimize*/, PCAP_NETMASK_UNKNOWN) != 0) {
        pcap_perror(handle, "Failed to compile filter");
        pcap_close(handle);
        pcap_freecode(&program);
        clean_exit_failure("Failed to compile filter");
    }
    
    if (pcap_setfilter(handle, &program) != 0) {
        pcap_perror(handle, "Failed to set filter");
        pcap_freecode(&program);
        pcap_close(handle);
        clean_exit_failure("Failed to set filter");
    }
    pcap_freecode(&program);
}

void send_packet(pcap_t *handle, uint8_t *packet, int packet_size)
{
    if (pcap_sendpacket(handle, packet, packet_size)) {
        pcap_perror(handle, "Failed to send packet");
        pcap_close(handle);
        clean_exit_failure("Failed to send packet");
    }
}

uint8_t *get_next_packet(pcap_t *handle, bpf_u_int32 expected_packet_len)
{
    struct pcap_pkthdr h;
    const uint8_t *packet = pcap_next(handle, &h);
    if (packet == NULL) {
        pcap_close(handle);
        clean_exit_failure("Failed to get next packet");
    }

    if (h.caplen < expected_packet_len) {
        pcap_close(handle);
        clean_exit_failure(fstring("Error when getting next packet. Received packet length is less than expected: %d, but got: %d", expected_packet_len, h.caplen));
    }

    return (uint8_t *)packet;
}





 
    
