#ifndef PCAP_UTILS_H
#define PCAP_UTILS_H

#include <pcap/pcap.h>

void send_packet(pcap_t *handle, uint8_t *packet, int packet_size);

pcap_t *create_capture_handle(const char *device_name);

void set_packet_filter(pcap_t *handle, char *filter);

const uint8_t *get_single_packet(pcap_t *handle, char *filter, bpf_u_int32 expected_packet_len, unsigned int timeout_sec);

extern pcap_t *g_handle;

#endif