#ifndef RESOURCES_H
#define RESOURCES_H

#include <unistd.h>

#include "color_output.h"

void free_resources();

void clean_exit_failure(char *error);

void clean_exit_success();

#endif