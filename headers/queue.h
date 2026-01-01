#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>
#include <stdbool.h>
#include "net.h"
#include <pthread.h>
#include "scans.h"

extern struct s_task *g_queue;
extern pthread_cond_t g_queue_condition_task_adding;
extern pthread_mutex_t g_queue_mutex_task_comleting;
extern pthread_mutex_t g_queue_mutex_task_adding;
extern int g_completed_task_count;
extern pthread_cond_t g_queue_condition_task_compling;
extern int g_queue_size;

struct s_task
{
    bool is_scan;
    struct s_net_config net_config;
    uint16_t port;
    enum port_state (*scan_func) (const struct s_net_config *, uint16_t);
    enum port_state scan_result;
    bool (*is_host_up_func) (const struct s_net_config *);
    bool is_host_up_result;
};

struct s_thread
{
    pthread_t thread;
    int id;
};

void queue_start_task_handlers(int count);

void queue_add(struct s_task task);

void queue_notify_task_handlers();

void queue_await_all_tasks_completion();

void queue_terminate();

void queue_await_termination();

#endif