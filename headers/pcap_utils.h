#ifndef PCAP_UTILS_H
#define PCAP_UTILS_H

#include <pcap/pcap.h>

pcap_t *create_capture_handle(char *device_name);

void set_packet_filter(pcap_t *handle, char *filter);

#endif