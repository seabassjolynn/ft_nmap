#ifndef SCAN_SYN_H
#define SCAN_SYN_H

#include "net.h"

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
    SCAN_XMAS
};

enum port_state scan_syn(const struct s_net_config *config, uint16_t port);

enum port_state scan(enum scan_type scan_type, const struct s_net_config *config, uint16_t port);

enum port_state scan_ack(const struct s_net_config *config, uint16_t port);

#endif