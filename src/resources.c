#include "resources.h"
#include "stdlib.h" //EXIT_... constants
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "color_output.h"
void free_resources()
{
    
}

void clean_exit_failure(char *error)
{
    printf(RED"%s. Errno value: %s\n"COLOR_RESET, error, strerror(errno));
    free_resources();
    exit(EXIT_FAILURE);
}

void clean_exit_success()
{
    free_resources();
    exit(EXIT_SUCCESS);
}