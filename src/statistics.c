#include "queue.h"
#include "resources.h"
#include <arpa/inet.h>
#include <bits/types/struct_timeval.h>
#include <netinet/in.h>
#include <sys/time.h>
#include "color_output.h"
#include "scans.h"
#include <string.h>
#include <netdb.h>

#define LOG_TAG "Statistics: "

static const char *get_service_name(enum scan_type scan_type, uint16_t port)
{
    static const char *service = "unknown";
    char *protocol = scan_type == SCAN_UDP ? "udp" : "tcp";
    struct servent *s = getservbyport(htons(port),protocol);
    if (s)
        service = s->s_name;
    else
        service = "unknown";
    return service;
}

struct timeval get_current_time()
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == -1)
        clean_exit_failure(LOG_TAG"Failed to get current time\n");
    return tv;
}

static float get_time_diff_sec(struct timeval *start_time, struct timeval *end_time)
{
    return end_time->tv_sec - start_time->tv_sec + ((float)(end_time->tv_usec - start_time->tv_usec) / 1e6f);
}

static int print_host_scan_results(int index_of_first_host_scan_task)
{
    struct in_addr host_addr = g_queue[index_of_first_host_scan_task].net_config.target_ip;
    uint16_t prev_port = 0;

    printf(GREEN"*** port scan results for host %s (%s)\n"COLOR_RESET, inet_ntoa(host_addr), g_queue[index_of_first_host_scan_task].net_config.host_name);

    while (index_of_first_host_scan_task < g_completed_task_count)
    {
        struct s_task *task = &g_queue[index_of_first_host_scan_task];
        if (task->net_config.target_ip.s_addr == host_addr.s_addr)
        {
            if (task->port == prev_port)
            {
                //we are on the same port
                printf(", %s - %s", scan_type_to_string(task->scan_type), scan_result_to_string(task->scan_result));
            }
            else
            {
                //encountered new port
                if (prev_port != 0)
                {
                    printf("\n");
                }
                printf("Port %d (%s): %s - %s", task->port, get_service_name(task->scan_type, task->port), scan_type_to_string(task->scan_type), scan_result_to_string(task->scan_result));
                prev_port = task->port;
            }
            index_of_first_host_scan_task++;
        }
        else 
        {
            break;
        }
        
    }
    printf("\n");
    return index_of_first_host_scan_task;
}

static int index_of_first_ports_scan_task()
{
    int i = 0;
    while (i < g_completed_task_count)
    {
        struct s_task *task = &g_queue[i];
        if (task->is_scan)
        {
            break;
        }
        i++;
    }
    return i;
}

static void print_scan_results()
{
    int i = index_of_first_ports_scan_task();
    if (i == g_completed_task_count)
    {
        printf(GREEN"*** All hosts are down, so no scan results are available ***\n"COLOR_RESET);
        return;
    }
    
    printf(GREEN"*** Port scan results ***\n"COLOR_RESET);

    while (i < g_completed_task_count)
    {
        i = print_host_scan_results(i);
    }
}

static void print_hosts_statuses()
{
    int i = 0;
    bool is_host_up = false;
    struct in_addr prev_ip;
    memset(&prev_ip, 0, sizeof(struct in_addr));
    while (i < g_completed_task_count)
    {
        struct s_task task = g_queue[i];
        if (task.is_scan)
        {
            break;
        }
        
        if (task.net_config.target_ip.s_addr != prev_ip.s_addr && i > 0)
        {
            //we encountered group of tasks for the next host
            if (!g_queue[i -1].is_scan)
            {
                //previous group of tasks was group of host discovery tasks. We can print host discovery status of the host (host is up or down)
                printf("Host %s (%s) status: %s\n", inet_ntoa(prev_ip), g_queue[i - 1].net_config.host_name, is_host_up ? "up" : "down");
            }
            //reset host status of previous group of tasks
            is_host_up = false;
        }

        if (!task.is_scan && task.is_host_up_result)
        {
            is_host_up = true;
        }
        
        prev_ip = task.net_config.target_ip;
        i++;
    }
    printf("Host %s (%s) status: %s\n", inet_ntoa(prev_ip),g_queue[i - 1].net_config.host_name, is_host_up ? "up" : "down");
}


void print_statistics(struct timeval *scan_start_time, struct timeval *scan_end_time)
{
    printf(GREEN"*** Port scanning completed. Scan results ***\n"COLOR_RESET);
    printf("Scan time: %.4f sec\n", get_time_diff_sec(scan_start_time, scan_end_time));
    print_hosts_statuses();
    print_scan_results();
}
