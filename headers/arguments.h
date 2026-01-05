#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <stdint.h>
#include <stdbool.h>
#define MAX_SCAN_NUMBER 1024
#define SCAN_TYPES_NUMBER 6
#define MAX_HOSTS 10
#define MAX_HOST_ID_LEN 40
#define MAX_SPEEDUP 250
struct s_host_scan
{
    uint32_t target_ip;
    char host_id_as_in_args[MAX_HOST_ID_LEN];
    int16_t start_port;
    int16_t end_port;
    int16_t comma_separated_ports[MAX_SCAN_NUMBER];
    uint16_t comma_separated_port_count;
    bool scan_types[SCAN_TYPES_NUMBER];
};

struct s_arguments
{
    bool is_help_requested;
    struct s_host_scan hosts[MAX_HOSTS];
    int hosts_size;
    long number_of_threads;
};

void print_arguments(const struct s_arguments *args);

struct s_arguments parse_arguments(int argc, char *argv[]);

bool is_port_range_set(const struct s_host_scan *host);

struct s_host_scan *get_host_scans_by_ip(struct s_arguments *arguments, uint32_t ip);

void print_arguments(const struct s_arguments *args);

#endif