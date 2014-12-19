#ifndef __SHM_H__
#define __SHM_H__

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>




#define SHM_RULE_LIST_NAME "RULE_LIST_SPACE"

#define SHM_SRV_DP_SYNC_NAME "SRV_DP_SYNC_NAME"


#define SRV_DP_SYNC_MAGIC  0x86cf0000

typedef struct
{
    uint32_t magic;
    uint32_t srv_initdone;
    uint32_t srv_notify_dp;
    uint32_t dp_ack;
}SRV_DP_SYNC;






#endif
