#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <stdint.h>
#include <stdbool.h>
#define MAX_SCAN_NUMBER 1024

struct s_ports
{
    int16_t start_port;
    int16_t end_port;
    int16_t ports[MAX_SCAN_NUMBER];
    uint16_t port_count;
};

struct s_arguments
{
    bool is_help_requested;
    struct s_ports ports;
    uint32_t target_ip;
    uint8_t number_of_threads;
};

void print_arguments(const struct s_arguments *args);

struct s_arguments parse_arguments(int argc, char *argv[]);

#endif