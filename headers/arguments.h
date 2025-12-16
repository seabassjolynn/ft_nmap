#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <stdint.h>
#include <stdbool.h>
#define MAX_SCAN_NUMBER 1024
#define SCAN_TYPES_NUMBER 6
#define MAX_FILE_HOSTS 10
struct s_host_scans
{
    uint32_t target_ip;
    int16_t start_port;
    int16_t end_port;
    int16_t ports[MAX_SCAN_NUMBER];
    uint16_t port_count;
    bool scan_types[SCAN_TYPES_NUMBER];
};

struct s_arguments
{
    bool is_help_requested;
    struct s_host_scans file_host_scans[MAX_FILE_HOSTS];
    struct s_host_scans arg_host_scans;
    uint8_t number_of_threads;
};

void print_arguments(const struct s_arguments *args);

struct s_arguments parse_arguments(int argc, char *argv[]);

#endif