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
#include "utils.h"

void print_arguments(const struct s_arguments *args)
{
    printf("Arguments:\n");
    printf("  is_help_requested: %s\n", args->is_help_requested ? "true" : "false");
    printf("  number_of_threads: %u\n", args->number_of_threads);
    
    struct in_addr ip_addr;
    ip_addr.s_addr = args->target_ip;
    printf("  target_ip: %s\n", inet_ntoa(ip_addr));
    
    printf("  ports:\n");
    printf("    range: %d-%d\n", args->ports.start_port, args->ports.end_port);
    printf("    ports: ");
    for (int i = 0; i < MAX_SCAN_NUMBER && args->ports.ports[i] != 0; i++)
    {
        if (i > 0)
            printf(", ");
        printf("%d", args->ports.ports[i]);
    }
    printf("\n");
}
//(eg: 1-10 or 1,2,3 or 1,5-15)
static void parse_ports(const char *ports_str, struct s_arguments *arguments)
{
    bool is_lower_bound_ecnountered = false;
    int i = 0;
    while (ports_str[i] != '\0')
    {
        int port = -1;
        char *endptr = NULL;
        port = strtol(&ports_str[i], &endptr, 10);
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
                arguments->ports.end_port = port;
            } 
            else 
            {
                arguments->ports.ports[arguments->ports.port_count++] = port;
            }
            break;
        }
        else if (*endptr == ',')
        {
            if (is_lower_bound_ecnountered)
            {
                clean_exit_failure("Arguement parsing failure: port upper bound can not have comma separated numbers");
            }
            arguments->ports.ports[arguments->ports.port_count++] = port;
            i = endptr - ports_str; // index of the comma, at the end of the cycle we move to potential next port
            if (ports_str[i + 1] == '\0')
            {
                clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: port expected after ','\n"COLOR_RESET));
            }
        }
        else if (*endptr == '-')
        {
            arguments->ports.start_port = port;
            is_lower_bound_ecnountered = true;
            i = endptr - ports_str; // index of the -, at the end of the cycle we move to potential next port
        } 
        else 
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: invalid character %c (ascii code %d) at position %d\n"COLOR_RESET, *endptr, (int) *endptr, endptr - ports_str));
        }
        i++;
    }
    
    if (arguments->ports.start_port == -1 && arguments->ports.end_port == -1 && arguments->ports.port_count == 0)
    {
        clean_exit_failure("Arguement parsing failure: no ports provided");
    }
    
    if (arguments->ports.end_port <= arguments->ports.start_port && (arguments->ports.start_port != -1 && arguments->ports.end_port != -1))
    {
        clean_exit_failure("Arguement parsing failure: port lower bound is greater than or equal to port upper bound");
    }

    if (arguments->ports.end_port - arguments->ports.start_port > MAX_SCAN_NUMBER)
    {
        clean_exit_failure(fstring("Arguement parsing failure: port range is too large, max is %d", MAX_SCAN_NUMBER));
    }
}

struct s_arguments parse_arguments(int ac, char **av)
{
    
    if (DEBUG) { printf("Parsing arguments\n"); }
    struct s_arguments arguments;
    arguments.is_help_requested = false;
    arguments.number_of_threads = 0;
    arguments.target_ip = 0;
    arguments.ports.port_count = 0;
    arguments.ports.start_port = -1;
    arguments.ports.end_port = -1;
    memset(arguments.ports.ports, 0, sizeof(arguments.ports.ports));
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
            arguments.target_ip = get_ipv4_address(av[i]);
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
                arguments.ports.start_port = 1;
                arguments.ports.end_port = MAX_SCAN_NUMBER;
            }
        } 
        else if (strcmp("--threads", av[i]) == 0) 
        {
        
        }
        else
        {
            clean_exit_failure(fstring(RED"Argument parsing failure: invalid argument %s\n"COLOR_RESET, av[i]));
        }
        i++;
    }
    if (DEBUG) { print_arguments(&arguments); }
    if (arguments.target_ip == 0)
    {
        clean_exit_failure("Arguement parsing failure: no target IP address provided");
    }
    return arguments;
}