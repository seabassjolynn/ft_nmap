#include "queue.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "resources.h"
#include "net.h"

#define LOG_TAG "Queue: "
#define QUEUE_INITIAL_SIZE 2
#define QUEUE_INCREASE_MILTIPLIER 2

struct s_task *g_queue = NULL;
int g_queue_capacity = 0;
int g_queue_size = 0;
int g_next_task_index = 0;
int g_completed_task_count = 0;

bool g_queue_terminated = false;

pthread_cond_t g_queue_condition_task_adding = PTHREAD_COND_INITIALIZER;
pthread_mutex_t g_queue_mutex_task_adding = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_queue_condition_task_compling = PTHREAD_COND_INITIALIZER;
pthread_mutex_t g_queue_mutex_task_comleting = PTHREAD_MUTEX_INITIALIZER;

struct s_thread *g_threads_storage = NULL;
int g_threads_storage_size = 0;

struct s_task *allocate(int elements_count)
{
    long byte_size = sizeof(struct s_task) * elements_count;
    struct s_task *queue = malloc(byte_size);
    if (queue == NULL)
    {
        clean_exit_failure("Failed to allocate queue\n");
    }
    if (DEBUG) { printf(LOG_TAG"Allocated queue for %d elements\n", elements_count); }
    memset(queue, 0, byte_size);
    g_queue_capacity = elements_count;
    return queue;
}

struct s_task * reallocate()
{
    int new_capacity = g_queue_capacity * QUEUE_INCREASE_MILTIPLIER;
    
    if (DEBUG) { printf(LOG_TAG"Growing queue from size %d to size %d\n", g_queue_capacity, new_capacity); }
    
    struct s_task *new_queue = allocate(new_capacity);
    memcpy(new_queue, g_queue, g_queue_size * sizeof(struct s_task));
    g_queue_capacity = new_capacity;
    
    free(g_queue);
    return new_queue;
}

void queue_add(struct s_task task)
{
    if (g_queue == NULL)
    {
        g_queue = allocate(QUEUE_INITIAL_SIZE);
        g_resources.queue = g_queue;
    }

    if (g_queue_size == g_queue_capacity)
    {
        g_queue = reallocate();
        g_resources.queue = g_queue;
    }
    g_queue[g_queue_size++] = task;
    if (DEBUG) { printf(LOG_TAG"Add one element to the queue (size=%d, capacity=%d)\n", g_queue_size, g_queue_capacity); }
}

void *handle_task(void *arg)
{
    int thread_id = *((int *)arg);
    
    if (DEBUG) { printf(LOG_TAG"Starting task handler # %d\n", thread_id); }
    
    while (1)
    {
        pthread_mutex_lock(&g_queue_mutex_task_adding);
        while (g_next_task_index >= g_queue_size && !g_queue_terminated)
        {
            if (DEBUG) { printf(LOG_TAG"Task handler # %d: Going to wait for the task # %d (last task # %d)\n", thread_id, g_next_task_index + 1, g_queue_size); }
            
            pthread_cond_wait(&g_queue_condition_task_adding, &g_queue_mutex_task_adding);
            if (DEBUG) { printf(LOG_TAG"Task handler # %d: Waking up\n", thread_id); }    
        }
        
        if (g_queue_terminated)
        {
            pthread_mutex_unlock(&g_queue_mutex_task_adding);
            return NULL;
        }

        int task_index = g_next_task_index++;
        
        if (DEBUG) { printf(LOG_TAG"Task handler # %d: Received a task # %d (out of %d)\n", thread_id, task_index + 1, g_queue_size); }
        
        pthread_mutex_unlock(&g_queue_mutex_task_adding);
        
        struct s_task *task = &g_queue[task_index];
        if (task->is_scan)
        {
            task->scan_result = task->scan_func(&task->net_config, task->port);
        }
        else
        {
            task->is_host_up_result = task->is_host_up_func(&task->net_config);
        }

        pthread_mutex_lock(&g_queue_mutex_task_comleting);
        g_completed_task_count++;
        
        if (DEBUG) { printf(LOG_TAG"Task handler # %d: Completing task (completed %d out of %d)\n", thread_id, g_completed_task_count, g_queue_size); }

        if (g_completed_task_count == g_queue_size)
        {
            if (DEBUG) { printf(LOG_TAG"Task handler # %d: All tasks are completed(%d out of %d), waking up pruducer\n", thread_id, g_completed_task_count, g_queue_size); }
            pthread_cond_signal(&g_queue_condition_task_compling);
        }
        pthread_mutex_unlock(&g_queue_mutex_task_comleting);
    }
}

static void* init_threads_storage(int count)
{
    g_threads_storage = malloc(sizeof(struct s_thread) * count);
    g_threads_storage_size = count;
    return g_threads_storage;
}

void queue_start_task_handlers(int count)
{
    if (DEBUG) { printf(LOG_TAG"Starting %d task handler thread(s)\n", count); }
    
    g_resources.threads_storage = init_threads_storage(count);
    int i = 0;
    while (i < g_threads_storage_size)
    {
        g_threads_storage[i].id = i;
        int rc = pthread_create(&g_threads_storage[i].thread, NULL, handle_task, &g_threads_storage[i].id);
        if (rc != 0)
        {
            char error[MAX_ER_MSG_LEN];
            snprintf(error, MAX_ER_MSG_LEN, "Failed to create thread # %d\n", i);
            clean_exit_failure(error);
        }
        i++;
    }
}

void queue_notify_task_handlers()
{   
    int required_handlres_count = g_queue_size - g_completed_task_count;
    int i = 0;
    while (i < required_handlres_count && i < g_threads_storage_size)
    {
        pthread_cond_signal(&g_queue_condition_task_adding);
        i++;
    }
    if (DEBUG) { printf(LOG_TAG"Notified %d handlers (unhanldled tasks in the queue %d, totoal handlers %d)\n", i, required_handlres_count, g_threads_storage_size); }
}

void queue_await_all_tasks_completion()
{
    pthread_mutex_lock(&g_queue_mutex_task_comleting);
    
    while(g_completed_task_count < g_queue_size)
    {
        if (DEBUG) { printf("Task producer: Waiting for all tasks completion\n"); }
        pthread_cond_wait(&g_queue_condition_task_compling, &g_queue_mutex_task_comleting);
    }

    if (DEBUG) { printf("Task producer: All task completed so start handling task results\n"); }

    pthread_mutex_unlock(&g_queue_mutex_task_comleting);
}

void queue_terminate()
{   
    if (DEBUG) { printf(LOG_TAG"Going to terminate queue\n"); }

    pthread_mutex_lock(&g_queue_mutex_task_adding);
    g_queue_terminated = true;

    pthread_cond_broadcast(&g_queue_condition_task_adding);

    pthread_mutex_unlock(&g_queue_mutex_task_adding);
}

void queue_await_termination()
{
    if (DEBUG) { printf(LOG_TAG"Waiting for queue termination\n"); }
    
    int i = 0;
    while(i < g_threads_storage_size)
    {
        pthread_join(g_threads_storage[i].thread, NULL);
        if (DEBUG) { printf(LOG_TAG"Handler # %d terminated\n", i); }
        i++;
    }
    
    if (DEBUG) { printf(LOG_TAG"Queue is terminated\n"); }
}