#include "color_output.h"
#include "net.h"
#include <bits/pthreadtypes.h>
#include <bits/types/struct_timeval.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include "queue.h"
#include <pthread.h>
#include "arguments.h"
#include "resources.h"
#include "host_discovery.h"
#include "scans.h"
#include "statistics.h"

static void print_help()
{
    printf(GREEN"=== ft_nmap - Network Port Scanner ===\n"COLOR_RESET);
    printf("\n");
    printf("USAGE:\n");
    printf("  ft_nmap [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  --help                    Show this help message\n");
    printf("  --ip <address>            Target IP address or hostname\n");
    printf("  --ports <ports>           Port specification (see PORT FORMAT below)\n");
    printf("                            If omitted, scans all ports (1-%d)\n", MAX_SCAN_NUMBER);
    printf("  --scan <types>             Scan types to use (see SCAN TYPES below)\n");
    printf("                            If omitted, all scan types are used\n");
    printf("  --speedup <num>            Number of worker threads (0-%d, default: 0)\n", MAX_SPEEDUP);
    printf("  --file <path>              Read hosts from file (must be first argument)\n");
    printf("\n");
    printf("PORT FORMAT:\n");
    printf("  Ports can be specified as:\n");
    printf("    - Range:        1-1024\n");
    printf("    - Comma-separated:  80,443,8080\n");
    printf("    - Combined:     80,443,1000-2000\n");
    printf("  Maximum ports per host: %d\n", MAX_SCAN_NUMBER);
    printf("\n");
    printf("SCAN TYPES:\n");
    printf("  Available scan types (comma-separated):\n");
    printf("    SYN    - TCP SYN scan (most common)\n");
    printf("    FIN    - TCP FIN scan\n");
    printf("    NULL   - TCP NULL scan\n");
    printf("    XMAS   - TCP XMAS scan\n");
    printf("    ACK    - TCP ACK scan\n");
    printf("    UDP    - UDP scan\n");
    printf("  Example: --scan SYN,ACK,UDP\n");
    printf("\n");
    printf("FILE FORMAT:\n");
    printf("  When using --file, the file should contain one host per line:\n");
    printf("    <ip> <ports> [scan_types]\n");
    printf("\n");
    printf("  Examples:\n");
    printf("    192.168.1.1 1-1024 SYN,ACK\n");
    printf("    192.168.1.2 80,443,8080 UDP\n");
    printf("    10.0.0.1 22-100\n");
    printf("    scanme.nmap.org 1-100 SYN,FIN,NULL,XMAS,ACK,UDP\n");
    printf("\n");
    printf("  File format details:\n");
    printf("    - ip: IP address or hostname (max %d chars)\n", MAX_HOST_ID_LEN);
    printf("    - ports: range (e.g., 1-1024) or comma-separated (e.g., 80,443,8080)\n");
    printf("    - scan_types (optional): comma-separated scan types\n");
    printf("    - Lines starting with # are treated as comments\n");
    printf("    - Empty lines are ignored\n");
    printf("    - Maximum hosts per file: %d\n", MAX_HOSTS);
    printf("\n");
    printf("EXAMPLES:\n");
    printf("  # Scan single host with default settings:\n");
    printf("  ft_nmap --ip 192.168.1.1\n");
    printf("\n");
    printf("  # Scan specific ports:\n");
    printf("  ft_nmap --ip 192.168.1.1 --ports 80,443,8080\n");
    printf("\n");
    printf("  # Scan port range with specific scan types:\n");
    printf("  ft_nmap --ip 192.168.1.1 --ports 1-1024 --scan SYN,ACK\n");
    printf("\n");
    printf("  # Use multiple threads:\n");
    printf("  ft_nmap --ip 192.168.1.1 --ports 1-1000 --speedup 10\n");
    printf("\n");
    printf("  # Scan multiple hosts from file:\n");
    printf("  ft_nmap --file hosts.txt\n");
    printf("\n");
    printf("NOTES:\n");
    printf("  - The program performs host discovery before port scanning\n");
    printf("  - Only hosts that respond to discovery probes will be scanned\n");
    printf("  - Requires root/administrator privileges for raw socket access\n");
    printf("\n");
}

int main(int ac, char **av) 
{
    init_resources();
    struct s_arguments arguments = parse_arguments(ac,  av);
    if (arguments.is_help_requested)
    {
        print_help();
        clean_exit_success();
    }
    print_arguments(&arguments);
    
    struct s_net_config net_config = get_net_config();
    print_net_config(&net_config);
    
    //TODO: handle ICMP port unreachable response types
    //TODO: make always recompile
    //TODO: check if results make sense (compare to wire shark and nmap manual interpretation of results)
    //TODO: Fix small deviation from the ft_nmap description
    //TODO: check for leaks with valgrind
    //TODO: smoke tests in VM
    //TODO: test arguments
    printf(GREEN"*** Start scanning hosts ***\n"COLOR_RESET);
    
    struct timeval scan_start_time = get_current_time();

    queue_start_task_handlers(arguments.number_of_threads + 1);

    pthread_mutex_lock(&g_queue_mutex_task_adding);

    create_host_discovery_tasks_and_add_to_queue(&arguments, &net_config);

    queue_notify_task_handlers();
    
    pthread_mutex_unlock(&g_queue_mutex_task_adding);
    
    queue_await_all_tasks_completion();
    
    pthread_mutex_lock(&g_queue_mutex_task_adding);

    create_scan_tasks_and_add_to_queue(&arguments, &net_config);
    
    queue_notify_task_handlers();

    pthread_mutex_unlock(&g_queue_mutex_task_adding);

    queue_await_all_tasks_completion();
    
    queue_terminate();

    queue_await_termination();
    
    struct timeval scan_finish_time = get_current_time();

    print_statistics(&scan_start_time, &scan_finish_time);

    clean_exit_success();
    
    return 0;
}