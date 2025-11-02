#ifndef HOST_UP_CHECK_H
#define HOST_UP_CHECK_H

#include <stdbool.h>

bool ping_echo_remote(const struct NetConfig *config, pcap_t *handle);

bool ping_timestamp_remote(const struct NetConfig *config, pcap_t *handle);

#endif