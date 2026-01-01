#include "pcap_utils.h"
#include "resources.h"
#include <pcap/pcap.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>
#include "net.h"
#define MAX_PACKET_LENGTH 65535
#define NO_PROMISCUOUS_MODE 0
//deliver packets right away to pcap, OS don't buffers the packets. Overhead: pcap uses system calls far single packet
//not for bunch of packets
#define IMMEDIATE_MODE_ON 1
#define LOG_TAG "Reading packets: "

pcap_t *create_capture_handle(const char *device_name) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(device_name, errbuf);
    if (handle == NULL) 
    {
        char error[MAX_ER_MSG_LEN];
        snprintf(error, MAX_ER_MSG_LEN, "Failed to create caputre handle, error %s\n", errbuf);
        clean_exit_failure(error);
    }

    if (pcap_set_snaplen(handle, MAX_PACKET_LENGTH) != 0) 
    {
        pcap_close(handle);
        char error[MAX_ER_MSG_LEN];
        snprintf(error, MAX_ER_MSG_LEN, "Failed to set packet length. Error: %s\n", errbuf);
        clean_exit_failure(error);
    }

    if (pcap_set_promisc(handle, NO_PROMISCUOUS_MODE)) 
    {
        pcap_close(handle);
        char error[MAX_ER_MSG_LEN];
        snprintf(error, MAX_ER_MSG_LEN, "Failed to configure promiscuous mode, error: %s\n", errbuf);
        clean_exit_failure(error);
    }

    if (pcap_set_immediate_mode(handle, IMMEDIATE_MODE_ON) != 0) 
    {
        pcap_close(handle);
        char error[MAX_ER_MSG_LEN];
        snprintf(error, MAX_ER_MSG_LEN, "Failed to configure immediate packet deivery, error: %s\n", errbuf);
        clean_exit_failure(error);
    }
    
    if (pcap_activate(handle) != 0) 
    {
        pcap_perror(handle, "Handle activation failure.");
        pcap_close(handle);
        clean_exit_failure(NULL);
    }

    return handle;
}

void send_packet(pcap_t *handle, uint8_t *packet, int packet_size)
{
    if (pcap_sendpacket(handle, packet, packet_size)) 
    {
        pcap_perror(handle, "Failed to send packet");
        pcap_close(handle);
        clean_exit_failure("Failed to send packet");
    }
}

void set_packet_filter(pcap_t *handle, const char *filter) 
{
    if (DEBUG) { printf(LOG_TAG"Setting filter for packet reading: %s\n", filter); }
    
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

static int get_selectable_fd(pcap_t *handle)
{
    int pcap_fd = pcap_get_selectable_fd(handle);
    if (pcap_fd < 0) {
        clean_exit_failure("Failed to get selectable fd for packet reading");
    }
    
    return pcap_fd;
}

void read_first_packet(pcap_t *handle, const char *filter, struct s_read_packet_result *result, unsigned int timeout_sec)
{
    set_packet_filter(handle, filter);
    
    int fd = get_selectable_fd(handle);

    struct pollfd fds = { .fd = fd, .events = POLLIN };

    int rc = 1;
    while (rc != 0)
    {
        rc = poll(&fds, 1, timeout_sec * 1000);
        if (rc > 0 && (fds.revents & POLLIN)) 
        {   
            rc = -1;
            struct pcap_pkthdr *pkthdr;
            const u_char *pkt_data;
            int rc =  pcap_next_ex(handle, &pkthdr, &pkt_data);
            if (rc == 0)
            {
                if (DEBUG) { printf(LOG_TAG"Received false packet\n"); }
                
                continue;
            }
            else if (rc != 1)
            {
                clean_exit_failure(LOG_TAG"Failed to read packet due to some other error: %d\n");
            }
            
            result->packet = pkt_data;
            result->packet_len = pkthdr->caplen;    
            if (DEBUG) { printf(LOG_TAG"Received packet\n"); }
            return;
        }
        else if (rc == 0)
        {
            if (DEBUG) { printf(LOG_TAG"Timeout when reading a packet\n"); }
        }
        else 
        {
            clean_exit_failure(LOG_TAG"Poll error\n");
        }
    }
}

void init_read_packet_result(struct s_read_packet_result *result) 
{
    result->packet = NULL;
    result->packet_len = -1;
}
