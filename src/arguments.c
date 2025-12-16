#include "arguments.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "debug.h"
#include "resources.h"
#include "color_output.h"
#include "net.h"
#include <stdlib.h>
#include "scans.h"
#include "utils.h"
#include <limits.h>

#define MAX_SPEEDUP 250

void print_arguments(const struct s_arguments *args)
{
    printf("Arguments:\n");
    printf("  is_help_requested: %s\n", args->is_help_requested ? "true" : "false");
    printf("  number_of_threads: %u\n", args->number_of_threads);
    
    struct in_addr ip_addr;
    ip_addr.s_addr = args->arg_host_scans.target_ip;
    printf("---argument scan data---\n");
    printf("  target_ip: %s\n", inet_ntoa(ip_addr));
    
    printf("  ports:\n");
    printf("    range: %d-%d\n", args->arg_host_scans.start_port, args->arg_host_scans.end_port);
    printf("    ports: ");
    for (int i = 0; i < MAX_SCAN_NUMBER && args->arg_host_scans.ports[i] != 0; i++)
    {
        if (i > 0)
            printf(", ");
        printf("%d", args->arg_host_scans.ports[i]);
    }
    printf("\n");
    
    printf("  scan_types: ");
    bool scan_printed = false;
    for (int i = 0; i < SCAN_TYPES_NUMBER; i++)
    {
        if (args->arg_host_scans.scan_types[i])
        {
            if (scan_printed)
                printf(", ");
            printf("%s", scan_type_to_string(i));
            scan_printed = true;
        }
    }
    
    if (!scan_printed)
    {
        printf("ALL");
    }
    printf("\n");
}

static void parse_scan_types(const char *scan_types_str, struct s_arguments *arguments)
{
    int i = 0;
    while (scan_types_str[i] != '\0')
    {
        int flag_len = 3;
        bool is_flag_detected = false;
        if (strncmp("SYN", &scan_types_str[i], flag_len) == 0)
        {
            arguments->arg_host_scans.scan_types[SCAN_SYN] = true;
            is_flag_detected = true;
        }
        else if (strncmp("FIN", &scan_types_str[i], flag_len) == 0)
        {
            arguments->arg_host_scans.scan_types[SCAN_FIN] = true;
            is_flag_detected = true;
        }
        else if (strncmp("NULL", &scan_types_str[i], flag_len + 1) == 0)
        {
            arguments->arg_host_scans.scan_types[SCAN_NULL] = true;
            is_flag_detected = true;
            flag_len = 4;
        }
        else if (strncmp("XMAS", &scan_types_str[i], flag_len + 1) == 0)
        {
            arguments->arg_host_scans.scan_types[SCAN_XMAS] = true;
            is_flag_detected = true;
            flag_len = 4;
        }
        else if (strncmp("ACK", &scan_types_str[i], flag_len) == 0)
        {
            arguments->arg_host_scans.scan_types[SCAN_ACK] = true;
            is_flag_detected = true;
        }
        else if (strncmp("UDP", &scan_types_str[i], flag_len) == 0)
        {
            arguments->arg_host_scans.scan_types[SCAN_UDP] = true;
            is_flag_detected = true;
        }
        if (!is_flag_detected)
        {
            clean_exit_failure(fstring(RED"Argument parsing (scan flag) failure: invalid scan type %s\n"COLOR_RESET, &scan_types_str[i]));
        }
        
        i += flag_len;
        if (scan_types_str[i] == ',')
        {
            i++;
        }
    }
}

//(eg: 1-10 or 1,2,3 or 1,5-15)
static void parse_ports(const char *ports_str, struct s_arguments *arguments)
{
    bool is_lower_bound_ecnountered = false;
    int i = 0;
    while (ports_str[i] != '\0')
    {
        long port = -1;
        char *endptr = NULL;
        if (!isspace(ports_str[i]) && !isdigit(ports_str[i]))
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: invalid character %c (ascii code %d) at position %d\n"COLOR_RESET, ports_str[i], (int) ports_str[i], i));
        }
        port = strtol(&ports_str[i], &endptr, 10);
        if (port <= 0 || port > UINT16_MAX)
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: port number is out of range at position %d\n"COLOR_RESET, i));
        }
        if (port <= 0)
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: port number must be greater than 0 at position %d\n"COLOR_RESET, i));
        }
        if (endptr == &ports_str[i])
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: non numeric character %c (ascii code %d) at position %d\n"COLOR_RESET, ports_str[i], (int) ports_str[i], i));
        }
        if (*endptr == '\0')
        {
            if (is_lower_bound_ecnountered)
            {
                arguments->arg_host_scans.end_port = port;
            } 
            else 
            {
                arguments->arg_host_scans.ports[arguments->arg_host_scans.port_count++] = port;
            }
            break;
        }
        else if (*endptr == ',')
        {
            if (is_lower_bound_ecnountered)
            {
                clean_exit_failure("Arguement parsing failure: port upper bound can not have comma separated numbers");
            }
            arguments->arg_host_scans.ports[arguments->arg_host_scans.port_count++] = port;
            i = endptr - ports_str; // index of the comma, at the end of the cycle we move to potential next port
            if (ports_str[i + 1] == '\0')
            {
                clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: port expected after ','\n"COLOR_RESET));
            }
        }
        else if (*endptr == '-')
        {
            arguments->arg_host_scans.start_port = port;
            is_lower_bound_ecnountered = true;
            i = endptr - ports_str; // index of the -, at the end of the cycle we move to potential next port
        } 
        else 
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: invalid character %c (ascii code %d) at position %d\n"COLOR_RESET, *endptr, (int) *endptr, endptr - ports_str));
        }
        i++;
    }
    
    if (arguments->arg_host_scans.start_port == -1 && arguments->arg_host_scans.end_port == -1 && arguments->arg_host_scans.port_count == 0)
    {
        clean_exit_failure("Arguement parsing failure: no ports provided");
    }
    
    if (arguments->arg_host_scans.end_port <= arguments->arg_host_scans.start_port && (arguments->arg_host_scans.start_port != -1 && arguments->arg_host_scans.end_port != -1))
    {
        clean_exit_failure("Arguement parsing failure: port lower bound is greater than or equal to port upper bound");
    }

    if (arguments->arg_host_scans.end_port - arguments->arg_host_scans.start_port > MAX_SCAN_NUMBER)
    {
        clean_exit_failure(fstring("Arguement parsing failure: port range is too large, max is %d", MAX_SCAN_NUMBER));
    }
}

static void parse_file(const char *file_path, struct s_arguments *arguments)
{
    (void)arguments;
    FILE *file = fopen(file_path, "r");
    if (file == NULL)
    {
        fclose(file);
        clean_exit_failure(fstring(RED"Argument parsing failure: failed to open file %s\n"COLOR_RESET, file_path));
    }
    
    char line[1024];
    while (fgets(line, sizeof(line), file) != NULL)
    {
        char *token = strtok(line, " ");
        int i = 0;
        while (token != NULL)
        {
            arguments->file_host_scans[i].ports[arguments->file_host_scans[i].port_count++] = atoi(token);
            token = strtok(NULL, " ");
        }
    }

    fclose(file);
}

struct s_arguments parse_arguments(int ac, char **av)
{
    if (DEBUG) { printf("Parsing arguments\n"); }
    struct s_arguments arguments;
    arguments.is_help_requested = false;
    arguments.number_of_threads = 0;
    arguments.arg_host_scans.target_ip = 0;
    arguments.arg_host_scans.port_count = 0;
    arguments.arg_host_scans.start_port = -1;
    arguments.arg_host_scans.end_port = -1;
    memset(arguments.arg_host_scans.ports, 0, sizeof(arguments.arg_host_scans.ports));
    int i = 1;
    while (i < ac) 
    {
        if (strcmp("--help", av[i]) == 0)
        {
            arguments.is_help_requested = true;
        }
        else if (strcmp("--ip", av[i]) == 0)
        {
            i++;
            if (i >= ac) { clean_exit_failure(RED"Argument parsing failure: no IP address provided after --ip flag"COLOR_RESET); }
            arguments.arg_host_scans.target_ip = get_ipv4_address(av[i]);
        }
        else if (strcmp("--ports", av[i]) == 0)
        {
            int next_arg = i + 1;
            if (next_arg < ac && (strncmp(av[next_arg], "--", 2) != 0))
            {
                parse_ports(av[next_arg], &arguments);
                i = next_arg;
            }
            else
            {
                arguments.arg_host_scans.start_port = 1;
                arguments.arg_host_scans.end_port = MAX_SCAN_NUMBER;
            }
        } 
        else if (strcmp("--speedup", av[i]) == 0) 
        {
            int next_arg = i + 1;
            if (next_arg < ac && (strncmp(av[next_arg], "--", 2) != 0))
            {
                char *endptr = NULL;
                long speedup = strtol(av[next_arg], &endptr, 10);
            
                if (endptr == av[next_arg] || *endptr != '\0')
                {
                    clean_exit_failure(fstring(RED"Argument parsing (speedup flag) failure: invalid speedup value %s\n"COLOR_RESET, av[next_arg]));
                }
            
                if (speedup <= 0 || speedup > MAX_SPEEDUP)
                {
                    clean_exit_failure(fstring(RED"Argument parsing (speedup flag) failure: speedup value must be between 0 and %d\n"COLOR_RESET, MAX_SPEEDUP));
                }
                
                arguments.number_of_threads = speedup;
                i = next_arg;
            }
        }
        else if (strcmp("--scan", av[i]) == 0)
        {
            int next_arg = i + 1;
            if (next_arg < ac && (strncmp(av[next_arg], "--", 2) != 0))
            {
                parse_scan_types(av[next_arg], &arguments);
                i = next_arg;
            }
        }
        else if (strcmp("--file", av[i]) == 0)
        {
            int next_arg = i + 1;
            if (next_arg < ac && (strncmp(av[next_arg], "--", 2) != 0))
            {
                parse_file(av[next_arg], &arguments);
                i = next_arg;
            }
            else
            {
                clean_exit_failure(fstring(RED"Argument parsing failure: no file provided after --file flag\n"COLOR_RESET));
            }
        }
        else
        {
            clean_exit_failure(fstring(RED"Argument parsing failure: invalid argument %s\n"COLOR_RESET, av[i]));
        }
        i++;
    }
    
    if (DEBUG) { print_arguments(&arguments); }
    
    if (arguments.arg_host_scans.target_ip == 0)
    {
        clean_exit_failure("Arguement parsing failure: no target IP address provided");
    }
    return arguments;
}