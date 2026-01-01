#ifndef HOST_UP_CHECK_H
#define HOST_UP_CHECK_H

#include <stdbool.h>
#include "arguments.h"

void create_host_discovery_tasks_and_add_to_queue(struct s_arguments *arguments, struct s_net_config *net_config);

#endif