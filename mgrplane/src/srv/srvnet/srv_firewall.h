#ifndef __SRV_FIREWALL_H__
#define __SRV_FIREWALL_H__

#include <common.h>



extern int FW_show_flow_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);
extern int FW_clear_flow_stat(uint8_t * from, uint32_t length, uint32_t fd, void *param_p);


#endif
