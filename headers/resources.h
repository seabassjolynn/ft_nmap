#ifndef RESOURCES_H
#define RESOURCES_H

#include <unistd.h>


void free_resources();

void clean_exit_failure(char *error);

void clean_exit_success();

#endif