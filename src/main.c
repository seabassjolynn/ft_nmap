#include "net.h"
#include "gateway.h"
#include "host_discovery.h"
#include "scans.h"
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include "arguments.h"

int main(int ac, char **av) {
    struct s_arguments arguments = parse_arguments(ac,  av);
    (void)arguments;
    //struct s_scan scans[MAX_SCAN_NUMBER];
    
    //TODO: handle ICMP port unreachable response types
    //TODO: filter ICMP packets based on icmp reply data (there could be many icmp replies commit back, we need to differenciate them)
    //TODO: make always recompile
    //TODO: align sent probes and received replies using sourcs port numbers (important in parallele execution)
    //struct s_net_config net_config;
    //net_config.local_ip = local_ip_for_internet_connection();
    //net_config.target_ip.s_addr = inet_addr("142.251.143.14");
    //45.33.32.156 - scanme.nmap.org
    //142.251.143.14 google.com
    
    //device_for_internet_connection(&net_config.local_ip, net_config.device_name);
    //mac_address_for_device(net_config.device_name, net_config.device_mac);

    //request_gateway_mac(&net_config);
    //is_host_up(&net_config);
    
    //scan_syn(&net_config, 80);
    //scan(SCAN_FIN, &net_config, 81);
    //scan_ack(&net_config, 80);
    //scan_udp(&net_config, 82);
    return 0;
}