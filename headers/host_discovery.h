#ifndef HOST_UP_CHECK_H
#define HOST_UP_CHECK_H

#include <stdbool.h>
#include "net.h"

bool is_host_up(const struct NetConfig *config);

#endif