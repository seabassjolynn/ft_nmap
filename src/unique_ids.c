#include <pthread.h>
#include "debug.h"
#include <stdio.h>
#include <inttypes.h>

uint16_t g_unique_id = 4096;

pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

int get_unique_id(void)
{
    
    pthread_mutex_lock(&g_lock);
    int id = g_unique_id++;
    pthread_mutex_unlock(&g_lock);
    if (DEBUG) { printf("Getting unique id: %d\n", id); }
    return id;
}