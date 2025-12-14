#ifndef SCAN_SYN_H
#define SCAN_SYN_H

#include "net.h"
#include <stdbool.h>
#include <stdint.h>

enum port_state
{
    OPEN,
    CLOSED,
    FILTERED,
    OPEN_FILTERED,
    UNFILTERED,
    UNKNOWN
};

enum scan_type
{
    SCAN_FIN,
    SCAN_NULL,
    SCAN_XMAS,
    SCAN_SYN,
    SCAN_ACK,
    SCAN_UDP
};

enum port_state scan_syn(const struct s_net_config *config, uint16_t port);

enum port_state scan(enum scan_type scan_type, const struct s_net_config *config, uint16_t port);

enum port_state scan_ack(const struct s_net_config *config, uint16_t port);

enum port_state scan_udp(const struct s_net_config *config, uint16_t port);

#define SCAN_TYPES_NUMBER 6

struct s_scan
{
    uint16_t port;
    enum scan_type types[SCAN_TYPES_NUMBER];
    bool types_statuses[SCAN_TYPES_NUMBER];
};

#endif