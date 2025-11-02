#include <stdio.h>
#include "net.h"
#include "gate_way.h"
#include "host_up_check.h"
#include "pcap_utils.h"

int main() {
    struct NetConfig net_config;
    net_config.local_ip = local_ip_for_internet_connection();
    net_config.target_ip.s_addr = inet_addr("142.251.36.238");
    //142.251.36.238 - google.com
    //45.33.32.156 - scanme.nmap.org
    
    device_for_internet_connection(&net_config.local_ip, net_config.device_name);
    mac_address_for_device(net_config.device_name, net_config.device_mac);

    request_gateway_mac(&net_config);

    is_host_up(&net_config);
    
    return 0;
}