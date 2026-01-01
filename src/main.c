#include "net.h"
#include "gateway.h"
#include <bits/pthreadtypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include "queue.h"
#include <pthread.h>
#include <signal.h>
#include "arguments.h"
#include "resources.h"
#include "host_discovery.h"
#include "scans.h"

static struct s_net_config get_net_config()
{
    struct s_net_config net_config;
    
    net_config.local_ip = local_ip_for_internet_connection();
    device_for_internet_connection(&net_config.local_ip, net_config.device_name);
    mac_address_for_device(net_config.device_name, net_config.device_mac);
    request_gateway_mac(&net_config);
    return net_config;
}

static void print_help()
{
    printf("------Here is how to use this program------\n");
}

void handle_alarm(int alarm_id)
{
    if (alarm_id == SIGALRM)
    {
        printf("Received alarm\n");
    }
}

int main(int ac, char **av) {
    init_resources();
    struct s_arguments arguments = parse_arguments(ac,  av);
    if (arguments.is_help_requested)
    {
        print_help();
        clean_exit_success();
    }
    //TODO: if number of threads 0 or 1 I allocate 1 worker thread.
    //TODO: handle ICMP port unreachable response types
    //TODO: filter ICMP packets based on icmp reply data (there could be many icmp replies commit back, we need to differenciate them)
    //TODO: make always recompile
    //TODO: align sent probes and received replies using sourcs port numbers (important in parallele execution)
    //TODO: what if the host list has 2 hosts with identical address? Need to restrict to identical addresses
    struct s_net_config net_config = get_net_config();
    
    queue_start_task_handlers(arguments.number_of_threads);

    pthread_mutex_lock(&g_queue_mutex_task_adding);

    create_host_discovery_tasks_and_add_to_queue(&arguments, &net_config);

    queue_notify_task_handlers();
    
    pthread_mutex_unlock(&g_queue_mutex_task_adding);
    
    queue_await_all_tasks_completion();
    
    pthread_mutex_lock(&g_queue_mutex_task_adding);

    create_scan_port_tasks_and_add_to_queue(&arguments);
    
    queue_notify_task_handlers();

    pthread_mutex_unlock(&g_queue_mutex_task_adding);

    queue_await_all_tasks_completion();
    
    //queue_terminate();

    queue_await_termination();
    clean_exit_success();
    
    return 0;
}