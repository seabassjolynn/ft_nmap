#ifndef SCAN_SYN_H
#define SCAN_SYN_H

#include "net.h"
#include <stdbool.h>
#include <stdint.h>
#include "arguments.h"

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

const char *scan_type_to_string(enum scan_type type);

void create_scan_port_tasks_and_add_to_queue(struct s_arguments *arguments);

#endif