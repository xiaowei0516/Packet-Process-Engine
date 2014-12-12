#include "srv_firewall.h"
#include "srv_octeon.h"


int FW_show_flow_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_show_dp_pkt_stat\n");
    return octeon_rpccall(from, length, fd, param_p, SHOW_FW_FLOW_STAT_ACK, COMMAND_SHOW_FW_FLOW_STAT);
}




int FW_clear_flow_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p)
{
    LOG("octeon_show_dp_pkt_stat\n");
    return octeon_rpccall(from, length, fd, param_p, CLEAR_FW_FLOW_STAT_ACK, COMMAND_CLEAR_FW_FLOW_STAT);
}


