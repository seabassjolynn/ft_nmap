#include "resources.h"
#include "stdlib.h"
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "color_output.h"
#define LOG_TAG "Resources: "

struct resources g_resources;

void init_resources()
{
    g_resources.queue = NULL;
    g_resources.threads_storage = NULL;
}

void free_resources()
{
    if (DEBUG) printf(LOG_TAG"freeing queue\n");
    free(g_resources.queue);
    
    if (DEBUG) printf(LOG_TAG"freeing threads storage\n");
    free(g_resources.threads_storage);
}


void clean_exit_failure(char *error)
{
    if (error != NULL)
    {
        printf(RED"%s. Errno value: %s\n"COLOR_RESET, error, strerror(errno));
    } 
    free_resources();
    exit(EXIT_FAILURE);
}

void clean_exit_success()
{
    if (DEBUG) { printf(GREEN"Finishing succesful execution\n"COLOR_RESET); }
    free_resources();
    exit(EXIT_SUCCESS);
}