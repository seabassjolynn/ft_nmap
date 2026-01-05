#ifndef STATISTICS_H
#define STATISTICS_H

struct timeval get_current_time();

void print_statistics(struct timeval *scan_start_time, struct timeval *scan_end_time);

#endif