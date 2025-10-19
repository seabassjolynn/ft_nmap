#include "pcap_utils.h"
#include "resources.h"

#define MAX_PACKET_LENGTH 65535
#define NO_PROMISCUOUS_MODE 0
//deliver packets right away to pcap, OS don't buffers the packets. Overhead: pcap uses system calls far single packet
//not for bunch of packets
#define IMMEDIATE_MODE_ON 1

pcap_t *create_capture_handle(char *device_name) {
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


 
    
