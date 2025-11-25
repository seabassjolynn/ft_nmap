#include "pcap_utils.h"
#include "resources.h"
#include "utils.h"
#include <unistd.h>
#include <signal.h>
#include "debug.h"

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

void send_packet(pcap_t *handle, uint8_t *packet, int packet_size)
{
    if (pcap_sendpacket(handle, packet, packet_size)) {
        pcap_perror(handle, "Failed to send packet");
        pcap_close(handle);
        clean_exit_failure("Failed to send packet");
    }
}

pcap_t *g_handle = NULL;
const uint8_t *g_packet = NULL;
const struct pcap_pkthdr *g_pkthdr = NULL;

void alarm_handler(int signum) {
    if (signum == SIGALRM) {
        if (DEBUG) {
            printf("Reading packet: timeout when reading packet\n");
        }
        
        if (g_handle != NULL) {
            pcap_breakloop(g_handle);
        } else {
            clean_exit_failure("Reading packet: trying to break loop on timeout, but handle is not set");
        }
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    g_packet = (uint8_t *)bytes;
    g_pkthdr = h;
}

void set_packet_filter(pcap_t *handle, char *filter) {
    if (DEBUG) {
        printf("Setting packet filter: filter: %s\n", filter);
    }
    
    struct bpf_program program;
    
    //mask is used when broadcast packets are filtered, if not PCAP_NETMASK_UNKNOWN may be used
    if (pcap_compile(handle, &program, filter, 1 /*optimize*/, PCAP_NETMASK_UNKNOWN) != 0) {
        pcap_perror(handle, "Setting packet fileter: failed to compile filter");
        pcap_close(handle);
        pcap_freecode(&program);
        clean_exit_failure("Setting packet fileter: failed to compile filter");
    }
    
    if (pcap_setfilter(handle, &program) != 0) {
        pcap_perror(handle, "Setting packet fileter: failed to set filter");
        pcap_freecode(&program);
        pcap_close(handle);
        clean_exit_failure("Setting packet fileter: failed to set filter");
    }
    pcap_freecode(&program);
}

const uint8_t *read_first_packet(pcap_t *handle, char *filter, bpf_u_int32 expected_min_packet_len, unsigned int timeout_sec)
{
    set_packet_filter(handle, filter);
    
    g_handle = handle;
    alarm(timeout_sec);
    signal(SIGALRM, alarm_handler);
    
    int result = pcap_loop(handle, 1, packet_handler, NULL); //if packet is read successfully, packet_handler is called and packet and header are set. If timeout, alarm_handler is called and packet_handler is not called.
    if (result == PCAP_ERROR_BREAK) //loop was terminated by timeout -> alarm_handler was called
    {
        g_packet = NULL;
        g_pkthdr = NULL;
        g_handle = NULL;
        return NULL;
    } else if (result == PCAP_ERROR_NOT_ACTIVATED)
    {
        clean_exit_failure("Reading packet: attemt to read from handle that was not activated");
    } else if (result == PCAP_ERROR)
    {
        clean_exit_failure("Reading packet: reading failed");
    } else if (result != 0)
    {
        clean_exit_failure(fstring("Reading packet: reading failed with unknown error: %d", result));
    }


    if (g_packet == NULL) {
        pcap_close(handle);
        clean_exit_failure("Packet was NULL after successful reading");
    }

    if (g_pkthdr == NULL) {
        pcap_close(handle);
        clean_exit_failure("Packet header was NULL after successful reading");
    }
    
    if (g_pkthdr->caplen < expected_min_packet_len) {
        pcap_close(handle);
        clean_exit_failure(fstring("Reading packet: error when getting next packet. Received packet length is less than expected: %d, but got: %d", expected_min_packet_len, g_pkthdr->caplen));
    }
    
    if (DEBUG) {
        printf("Reading packet: successfully read packet with length %d, expected length %d\n", g_pkthdr->caplen, expected_min_packet_len);
    }
    
    const uint8_t *packet = g_packet;
    g_packet = NULL;
    g_pkthdr = NULL;
    g_handle = NULL;

    return packet;
}





 
    
