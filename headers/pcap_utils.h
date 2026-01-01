#ifndef PCAP_UTILS_H
#define PCAP_UTILS_H

#include <pcap/pcap.h>

struct s_read_packet_result
{
    const uint8_t *packet;
    int packet_len;
};

void send_packet(pcap_t *handle, uint8_t *packet, int packet_size);

pcap_t *create_capture_handle(const char *device_name);

void set_packet_filter(pcap_t *handle, const char *filter);

void read_first_packet(pcap_t *handle, const char *filter, struct s_read_packet_result *result, unsigned int timeout_sec);

extern pcap_t *g_handle;

void init_read_packet_result(struct s_read_packet_result *result);

#endif