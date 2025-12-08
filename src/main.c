#include "net.h"
#include "gateway.h"
#include "host_discovery.h"
#include "scans.h"

int main() {
    //TODO: handle ICMP port unreachable response types
    //TODO: filter ICMP packets based on icmp reply data (there could be many icmp replies commit back, we need to differenciate them)
    struct s_net_config net_config;
    net_config.local_ip = local_ip_for_internet_connection();
    net_config.target_ip.s_addr = inet_addr("45.33.32.156");
    //45.33.32.156 - scanme.nmap.org
    
    device_for_internet_connection(&net_config.local_ip, net_config.device_name);
    mac_address_for_device(net_config.device_name, net_config.device_mac);

    request_gateway_mac(&net_config);
    //is_host_up(&net_config);
    
    scan_syn(&net_config, 80);
    //scan(SCAN_FIN, &net_config, 81);
    //scan_ack(&net_config, 80);
    return 0;
}