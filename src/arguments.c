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

static void validate_arguments(const struct s_arguments *args);

static void print_host_scans(const struct s_host_scans *host_scans, int index)
{
    printf("--- host %d ---\n", index);
    
    struct in_addr ip_addr;
    ip_addr.s_addr = host_scans->target_ip;
    printf("  target_ip: %s\n", inet_ntoa(ip_addr));
    
    printf("  ports:\n");
    printf("    range: %d-%d\n", host_scans->start_port, host_scans->end_port);
    printf("    ports: ");
    for (int i = 0; i < MAX_SCAN_NUMBER && host_scans->ports[i] != 0; i++)
    {
        if (i > 0)
            printf(", ");
        printf("%d", host_scans->ports[i]);
    }
    printf("\n");
    
    printf("  scan_types: ");
    bool scan_printed = false;
    for (int i = 0; i < SCAN_TYPES_NUMBER; i++)
    {
        if (host_scans->scan_types[i])
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

void print_arguments(const struct s_arguments *args)
{
    printf("Arguments:\n");
    printf("  is_help_requested: %s\n", args->is_help_requested ? "true" : "false");
    printf("  number_of_threads: %u\n", args->number_of_threads);
    printf("  hosts_size: %d\n", args->hosts_size);
    
    for (int i = 0; i < args->hosts_size; i++)
    {
        print_host_scans(&args->hosts[i], i);
    }
}

static void parse_scan_types(const char *scan_types_str, struct s_host_scans *host_scans)
{
    int i = 0;
    while (scan_types_str[i] != '\0')
    {
        int flag_len = 3;
        bool is_flag_detected = false;
        if (strncmp("SYN", &scan_types_str[i], flag_len) == 0)
        {
            host_scans->scan_types[SCAN_SYN] = true;
            is_flag_detected = true;
        }
        else if (strncmp("FIN", &scan_types_str[i], flag_len) == 0)
        {
            host_scans->scan_types[SCAN_FIN] = true;
            is_flag_detected = true;
        }
        else if (strncmp("NULL", &scan_types_str[i], flag_len + 1) == 0)
        {
            host_scans->scan_types[SCAN_NULL] = true;
            is_flag_detected = true;
            flag_len = 4;
        }
        else if (strncmp("XMAS", &scan_types_str[i], flag_len + 1) == 0)
        {
            host_scans->scan_types[SCAN_XMAS] = true;
            is_flag_detected = true;
            flag_len = 4;
        }
        else if (strncmp("ACK", &scan_types_str[i], flag_len) == 0)
        {
            host_scans->scan_types[SCAN_ACK] = true;
            is_flag_detected = true;
        }
        else if (strncmp("UDP", &scan_types_str[i], flag_len) == 0)
        {
            host_scans->scan_types[SCAN_UDP] = true;
            is_flag_detected = true;
        }
        if (!is_flag_detected)
        {
            clean_exit_failure(fstring(RED"Argument parsing (scan flag) failure: invalid scan type %s"COLOR_RESET, &scan_types_str[i]));
        }
        
        i += flag_len;
        if (scan_types_str[i] == ',')
        {
            i++;
        }
    }
}

//(eg: 1-10 or 1,2,3 or 1,5-15)
static void parse_ports(const char *ports_str, struct s_host_scans *host_scans)
{
    bool is_lower_bound_ecnountered = false;
    int i = 0;
    while (ports_str[i] != '\0')
    {
        long port = -1;
        char *endptr = NULL;
        if (!isspace(ports_str[i]) && !isdigit(ports_str[i]))
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: invalid character %c (ascii code %d) at position %d"COLOR_RESET, ports_str[i], (int) ports_str[i], i));
        }
        port = strtol(&ports_str[i], &endptr, 10);
        if (port <= 0 || port > UINT16_MAX)
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: port number is out of range at position %d"COLOR_RESET, i));
        }
        if (port <= 0)
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: port number must be greater than 0 at position %d"COLOR_RESET, i));
        }
        if (endptr == &ports_str[i])
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: non numeric character %c (ascii code %d) at position %d"COLOR_RESET, ports_str[i], (int) ports_str[i], i));
        }
        if (*endptr == '\0')
        {
            if (is_lower_bound_ecnountered)
            {
                host_scans->end_port = port;
            } 
            else 
            {
                host_scans->ports[host_scans->port_count++] = port;
            }
            break;
        }
        else if (*endptr == ',')
        {
            if (is_lower_bound_ecnountered)
            {
                clean_exit_failure("Argument parsing failure: port upper bound can not have comma separated numbers");
            }
            host_scans->ports[host_scans->port_count++] = port;
            i = endptr - ports_str; // index of the comma, at the end of the cycle we move to potential next port
            if (ports_str[i + 1] == '\0')
            {
                clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: port expected after ','"COLOR_RESET));
            }
        }
        else if (*endptr == '-')
        {
            host_scans->start_port = port;
            is_lower_bound_ecnountered = true;
            i = endptr - ports_str; // index of the -, at the end of the cycle we move to potential next port
        } 
        else 
        {
            clean_exit_failure(fstring(RED"Argument parsing (port flag) failure: invalid character %c (ascii code %d) at position %d"COLOR_RESET, *endptr, (int) *endptr, (int)(endptr - ports_str)));
        }
        i++;
    }
}

// File format: one host per line
// <ip> <ports> [scan_types]
// 
// Examples:
// 192.168.1.1 1-1024 SYN,ACK
// 192.168.1.2 80,443,8080 UDP
// 10.0.0.1 22-100
// scanme.nmap.org 1-100 SYN,FIN,NULL,XMAS,ACK,UDP
//
// - ip: IP address or hostname
// - ports: range (e.g., 1-1024) or comma-separated (e.g., 80,443,8080)
// - scan_types (optional): comma-separated scan types (SYN,FIN,NULL,XMAS,ACK,UDP)
//   If not provided, all scan types are used

static void parse_file(const char *file_path, struct s_arguments *arguments)
{
    FILE *file = fopen(file_path, "r");
    if (file == NULL)
    {
        clean_exit_failure(fstring(RED"Argument parsing failure: failed to open file %s\n"COLOR_RESET, file_path));
    }
    
    char line[1024];
    char original_line[1024];
    int line_number = 0;
    
    while (fgets(line, sizeof(line), file) != NULL)
    {
        line_number++;
        
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
        {
            line[len - 1] = '\0';
        }
        
        // Save original line for error messages (strtok modifies the string)
        strncpy(original_line, line, sizeof(original_line) - 1);
        original_line[sizeof(original_line) - 1] = '\0';
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#')
        {
            continue;
        }
        
        if (arguments->hosts_size >= MAX_HOSTS)
        {
            fclose(file);
            clean_exit_failure(fstring(RED"File parsing failure: too many hosts, max is %d\n  line %d: %s"COLOR_RESET, MAX_HOSTS, line_number, original_line));
        }
        
        struct s_host_scans *host = &arguments->hosts[arguments->hosts_size];
        
        // Parse IP (first token)
        char *ip_str = strtok(line, " \t");
        if (ip_str == NULL)
        {
            continue;
        }
        host->target_ip = get_ipv4_address(ip_str);
        
        // Parse ports (second token)
        char *ports_str = strtok(NULL, " \t");
        if (ports_str == NULL)
        {
            fclose(file);
            clean_exit_failure(fstring(RED"File parsing failure: missing ports\n  line %d: %s"COLOR_RESET, line_number, original_line));
        }
        parse_ports(ports_str, host);
        
        // Parse scan types (third token, optional)
        char *scan_types_str = strtok(NULL, " \t");
        if (scan_types_str != NULL)
        {
            parse_scan_types(scan_types_str, host);
        }
        
        arguments->hosts_size++;
    }

    fclose(file);
    
    if (arguments->hosts_size == 0)
    {
        clean_exit_failure(RED"File parsing failure: no hosts found in file\n"COLOR_RESET);
    }
}

static void init_host_scans(struct s_arguments *arguments)
{
    for (int i = 0; i < MAX_HOSTS; i++)
    {
        struct s_host_scans *host_scans = &arguments->hosts[i];
        host_scans->target_ip = 0;
        host_scans->start_port = -1;
        host_scans->end_port = -1;
        memset(host_scans->ports, 0, sizeof(host_scans->ports));
        host_scans->port_count = 0;
        memset(host_scans->scan_types, 0, sizeof(host_scans->scan_types));
    }
}

struct s_arguments parse_arguments(int ac, char **av)
{
    if (DEBUG) { printf("Parsing arguments\n"); }
    struct s_arguments arguments;
    memset(arguments.hosts, 0, sizeof(arguments.hosts));
    init_host_scans(&arguments);
    int i = 1;
    while (i < ac)
    {
        if (strcmp("--help", av[i]) == 0)
        {
            arguments.is_help_requested = true;
            arguments.hosts_size = 0;
        }
        else if (strcmp("--ip", av[i]) == 0)
        {
            arguments.hosts_size = 1;
            i++;
            if (i >= ac) { clean_exit_failure(RED"Argument parsing failure: no IP address provided after --ip flag"COLOR_RESET); }
            arguments.hosts[arguments.hosts_size].target_ip = get_ipv4_address(av[i]);
        }
        else if (strcmp("--ports", av[i]) == 0)
        {
            int next_arg = i + 1;
            if (next_arg < ac && (strncmp(av[next_arg], "--", 2) != 0))
            {
                parse_ports(av[next_arg], &arguments.hosts[arguments.hosts_size]);
                i = next_arg;
            }
            else
            {
                arguments.hosts[arguments.hosts_size].start_port = 1;
                arguments.hosts[arguments.hosts_size].end_port = MAX_SCAN_NUMBER;
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
                parse_scan_types(av[next_arg], &arguments.hosts[arguments.hosts_size]);
                i = next_arg;
            }
        }
        else if (strcmp("--file", av[i]) == 0)
        {
            if (i != 1)
            {
                clean_exit_failure(fstring(RED"Argument parsing failure: --file flag must be the first argument\n"COLOR_RESET));
            }
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
    
    validate_arguments(&arguments);
    
    return arguments;
}

static void validate_arguments(const struct s_arguments *args)
{
    if (args->is_help_requested)
    {
        return;
    }
    
    if (args->hosts_size == 0)
    {
        clean_exit_failure("Argument validation failure: no hosts provided (use --ip or --file)");
    }
    
    for (int i = 0; i < args->hosts_size; i++)
    {
        const struct s_host_scans *host = &args->hosts[i];
        
        if (host->target_ip == 0)
        {
            clean_exit_failure(fstring("Argument validation failure: host %d has no IP address", i));
        }
        
        bool has_ports = host->port_count > 0 || (host->start_port != -1 && host->end_port != -1);
        if (!has_ports)
        {
            clean_exit_failure(fstring("Argument validation failure: host %d has no ports specified", i));
        }
        
        if (host->start_port != -1 && host->start_port < 1)
        {
            clean_exit_failure(fstring("Argument validation failure: host %d start port must be >= 1", i));
        }
        
        if (host->start_port != -1 && host->end_port != -1 && host->end_port <= host->start_port)
        {
            clean_exit_failure(fstring("Argument validation failure: host %d end port must be greater than start port", i));
        }
        
        int total_ports = host->port_count;
        if (host->start_port != -1 && host->end_port != -1)
        {
            total_ports += host->end_port - host->start_port + 1;
        }
        if (total_ports > MAX_SCAN_NUMBER)
        {
            clean_exit_failure(fstring("Argument validation failure: host %d has too many ports (%d), max is %d", i, total_ports, MAX_SCAN_NUMBER));
        }
    }
}