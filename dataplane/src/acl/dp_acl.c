#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <sec-common.h>
#include <shm.h>
#include <acl_rule.h>
#include "dp_acl.h"
#include <mbuf.h>
#include <sec-debug.h>

CVMX_SHARED uint32_t dp_acl_action_default = ACL_RULE_ACTION_DROP;

rule_list_t *rule_list;

CVMX_SHARED unit_tree g_acltree;




uint32_t DP_Acl_Tree_Init()
{
    void *ptr;

    ptr = (void *)cvmx_bootmem_alloc_named((RULE_ENTRY_MAX + 1) * sizeof(rule_t), 128, DP_ACL_RULELIST_NAME);
    if(NULL == ptr)
    {
        return SEC_NO;
    }

    memset(ptr, 0, (RULE_ENTRY_MAX + 1) * sizeof(rule_t));

    rwlock_init(&g_acltree.hs_rwlock);

    g_acltree.TreeSet.num = 0;
    g_acltree.TreeSet.ruleList = (rule_t *)ptr;

    memset((void *)&g_acltree.TreeNode, 0, sizeof(hs_node_t));

    return SEC_OK;
}


uint32_t DP_Acl_List_Init()
{
    int fd;

    fd = shm_open(SHM_RULE_LIST_NAME, O_RDWR, 0);

    if (fd < 0)
    {
        LOGDBG("Failed to setup CVMX_SHARED(shm_open)\n");
        return SEC_NO;
    }

    ftruncate(fd, sizeof(rule_list_t));

    void *ptr = mmap(NULL, sizeof(rule_list_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == NULL)
    {
        LOGDBG("Failed to setup rule list (mmap copy)");
        return SEC_NO;
    }

    rule_list = (rule_list_t *)ptr;

    return SEC_OK;
}



uint32_t DP_Acl_Rule_Init()
{
    if(SEC_OK != DP_Acl_List_Init())
    {
        return SEC_NO;
    }

    if(SEC_OK != DP_Acl_Tree_Init())
    {
        return SEC_NO;
    }

    if(SEC_OK != HS_Node_Init())
    {
        return SEC_NO;
    }


    return SEC_OK;

}


void DP_Acl_Add_GuardRule(uint32_t id, rule_t* ruleList)
{
#ifdef SEC_ACL_DEBUG
    LOGDBG("guard rule id is %d\n", id);
#endif
    ruleList->pri = id;
    ruleList->action = dp_acl_action_default;
    ruleList->rule_id = RULE_ENTRY_MAX;

    ruleList->range[0][0] = 0;
    ruleList->range[0][1] = 0xffffffffffff;  // SMAC
    ruleList->range[1][0] = 0;
    ruleList->range[1][1] = 0xffffffffffff;  // DMAC
    ruleList->range[2][0] = 0;
    ruleList->range[2][1] = 0xffffffff;      // SIP
    ruleList->range[3][0] = 0;
    ruleList->range[3][1] = 0xffffffff;      // DIP
    ruleList->range[4][0] = 0;
    ruleList->range[4][1] = 0xffff;          // SPORT
    ruleList->range[5][0] = 0;
    ruleList->range[5][1] = 0xffff;          // DPORT
    ruleList->range[6][0] = 0;
    ruleList->range[6][1] = 0xff;            // PROTOCOL
}

extern unsigned int    gChildCount;

extern unsigned int    gNumTreeNode;
extern unsigned int    gNumLeafNode;

extern unsigned int    gWstDepth;
extern unsigned int    gAvgDepth;

extern unsigned long long  gNumTotalNonOverlappings;


uint32_t DP_Acl_Rule_Clean(rule_set_t* ruleset, hs_node_t* node)
{

    gChildCount = 0;

    gNumTreeNode = 0;
    gNumLeafNode = 0;

    gWstDepth = 0;
    gAvgDepth = 0;
    gNumTotalNonOverlappings = 1;

    ruleset->num = 0;
    //memset(ruleset->ruleList, 0, (RULE_ENTRY_MAX + 1) * sizeof(rule_t));
    FreeRootNode(node);

    node->d2s = 0;
    node->depth = 0;
    node->thresh = 0;

    return SEC_OK;
}


uint32_t DP_Acl_Load_Rule(rule_list_t *rule_list,rule_set_t* ruleset, hs_node_t* node)
{
    uint32_t i,j;

    struct FILTER *tempfilt,tempfilt1;
    tempfilt = &tempfilt1;

    if(ruleset == NULL || node == NULL)
    {
    #ifdef SEC_ACL_DEBUG
        LOGDBG("\nwrong parameters\n");
    #endif
        return SEC_NO;
    }

    struct FILTSET* filtset = (struct FILTSET*)malloc(sizeof(struct FILTSET));
    if(NULL == filtset)
    {
        return SEC_NO;
    }

    memset(filtset, 0, sizeof(struct FILTSET));

    for( i = 0; i < RULE_ENTRY_MAX; i++ )
    {
        if(rule_list->rule_entry[i].entry_status == RULE_ENTRY_STATUS_FREE)
        {
            continue;
        }

        memset(tempfilt->dim, 0, DIM * 2 * sizeof(uint64_t));

        tempfilt->action = (unsigned int)rule_list->rule_entry[i].rule_tuple.action;
        tempfilt->rule_id = i;

        /*0 SMAC from to*/
        ReadMACRange(rule_list->rule_entry[i].rule_tuple.smac, tempfilt->dim[0]);

        /*1 DMAC from to*/
        ReadMACRange(rule_list->rule_entry[i].rule_tuple.dmac, tempfilt->dim[1]);

        /*2 SIP from to*/
        ReadIPRange(rule_list->rule_entry[i].rule_tuple.sip,rule_list->rule_entry[i].rule_tuple.sip_mask, &tempfilt->dim[2][0], &tempfilt->dim[2][1]);

        /*3 DIP from to*/
        ReadIPRange(rule_list->rule_entry[i].rule_tuple.dip,rule_list->rule_entry[i].rule_tuple.dip_mask, &tempfilt->dim[3][0], &tempfilt->dim[3][1]);

        /*4 SPORT from to*/
        ReadPort(rule_list->rule_entry[i].rule_tuple.sport_start,
            rule_list->rule_entry[i].rule_tuple.sport_end,
            &(tempfilt->dim[4][0]),
            &(tempfilt->dim[4][1]));

        /*5 DPORT  from to*/
        ReadPort(rule_list->rule_entry[i].rule_tuple.dport_start,
            rule_list->rule_entry[i].rule_tuple.dport_end,
            &(tempfilt->dim[5][0]),
            &(tempfilt->dim[5][1]));

        /*6 PROTO  from to*/
        ReadProto(rule_list->rule_entry[i].rule_tuple.protocol_start,
            rule_list->rule_entry[i].rule_tuple.protocol_end,
            &(tempfilt->dim[6][0]),
            &(tempfilt->dim[6][1]));

        tempfilt->time_start = rule_list->rule_entry[i].rule_tuple.time_start;
        tempfilt->time_end = rule_list->rule_entry[i].rule_tuple.time_end;

        memcpy(&(filtset->filtArr[filtset->numFilters]), tempfilt, sizeof(struct FILTER));

        filtset->numFilters++;

    }

    ruleset->num = filtset->numFilters;
    memset(ruleset->ruleList, 0, (ruleset->num + 1) * sizeof(rule_t));

    for (i = 0; i < ruleset->num; i++)
    {
        ruleset->ruleList[i].pri = i;
        ruleset->ruleList[i].action = filtset->filtArr[i].action;
        ruleset->ruleList[i].rule_id = filtset->filtArr[i].rule_id;
        ruleset->ruleList[i].time_start = filtset->filtArr[i].time_start;
        ruleset->ruleList[i].time_end = filtset->filtArr[i].time_end;
        for (j = 0; j < DIM; j++)
        {
            ruleset->ruleList[i].range[j][0] = filtset->filtArr[i].dim[j][0];
            ruleset->ruleList[i].range[j][1] = filtset->filtArr[i].dim[j][1];
        }
    }

#ifdef SEC_ACL_DEBUG
    LOGDBG("number of rules loaded  %d\n", ruleset->num);
#endif

    DP_Acl_Add_GuardRule(ruleset->num, &ruleset->ruleList[ruleset->num]);
    ruleset->num += 1;

    uint32_t ruleNum;
    for (ruleNum = 0; ruleNum < ruleset->num; ruleNum ++)
    {
    #ifdef SEC_ACL_DEBUG
        LOGDBG("\nRule%d: [%lx %lx] [%lx %lx] [%lx %lx], [%lx %lx], [%lx %lx], [%lx %lx], [%lx %lx]\n", ruleNum,
            ruleset->ruleList[ruleNum].range[0][0], ruleset->ruleList[ruleNum].range[0][1],
            ruleset->ruleList[ruleNum].range[1][0], ruleset->ruleList[ruleNum].range[1][1],
            ruleset->ruleList[ruleNum].range[2][0], ruleset->ruleList[ruleNum].range[2][1],
            ruleset->ruleList[ruleNum].range[3][0], ruleset->ruleList[ruleNum].range[3][1],
            ruleset->ruleList[ruleNum].range[4][0], ruleset->ruleList[ruleNum].range[4][1],
            ruleset->ruleList[ruleNum].range[5][0], ruleset->ruleList[ruleNum].range[5][1],
            ruleset->ruleList[ruleNum].range[6][0], ruleset->ruleList[ruleNum].range[6][1]);
    #endif
    }

    if(BuildHSTree(ruleset,node,0) != 1)
    {
        free(filtset);
        return SEC_NO;
    }

    free(filtset);

    return SEC_OK;
}



uint8_t DP_Acl_Lookup(mbuf_t *mb)
{
    uint64_t packet[7];
    uint64_t z[6];
    uint64_t x, y;
    int i;
    rule_set_t* ruleset;
    hs_node_t* root;
    hs_node_t*  hit_node;
    uint32_t rule;
    uint8_t action;
    uint64_t timestar;
    uint64_t timeend;

    for(i = 0; i < 6; i++)
    {
        z[i] = mb->eth_src[i];
    }

    x  = z[0] << 40;
    x += z[1] << 32;
    x += z[2] << 24;
    x += z[3] << 16;
    x += z[4] << 8;
    x += z[5];

    for(i = 0; i < 6; i++)
    {
        z[i] = mb->eth_dst[i];
    }

    y  = z[0] << 40;
    y += z[1] << 32;
    y += z[2] << 24;
    y += z[3] << 16;
    y += z[4] << 8;
    y += z[5];

    packet[0] = x;
    packet[1] = y;
    packet[2] = mb->ipv4.sip;
    packet[3] = mb->ipv4.dip;
    packet[4] = mb->sport;
    packet[5] = mb->dport;
    packet[6] = mb->proto;

#ifdef SEC_ACL_DEBUG
    LOGDBG("\n>>packet: [%lx  %lx]  [%lx  %lx]  [%lx %lx], [%lx %lx], [%lu %lu], [%lu %lu], [%lx %lx]\n",
            packet[0], packet[0],
            packet[1], packet[1],
            packet[2], packet[2],
            packet[3], packet[3],
            packet[4], packet[4],
            packet[5], packet[5],
            packet[6], packet[6]);
#endif

    if(read_trylock(&g_acltree.hs_rwlock))
    {

        if(g_acltree.TreeSet.num == 0)
        {
        #ifdef SEC_ACL_DEBUG
            LOGDBG("Rule is empty\n");
        #endif

            read_unlock(&g_acltree.hs_rwlock);

            return ACL_RULE_ACTION_FW;
        }

        ruleset = &(g_acltree.TreeSet);
        root = &(g_acltree.TreeNode);

        LookupHSTree(packet, ruleset, root, &hit_node);

#ifdef SEC_ACL_DEBUG
        LOGDBG("\nnode->thresh: ""%" PRId64 "\n",  hit_node->thresh);
#endif

        rule = (uint32_t)hit_node->thresh;
        if(rule == ruleset->num - 1)
        {
            action = ruleset->ruleList[rule].action;

        #ifdef SEC_ACL_DEBUG
            LOGDBG("\nhit guard rule\n");
        #endif

        }
        else
        {

        #ifdef SEC_ACL_DEBUG
            LOGDBG("\n>>hit Rule%ld: [%8lx %8lx] [%8lx %8lx] [%8lx %8lx], [%8lx %8lx], [%5lu %5lu], [%5lu %5lu], [%2lx %2lx]\n", hit_node->thresh+1,
                        ruleset->ruleList[rule].range[0][0], ruleset->ruleList[rule].range[0][1],
                        ruleset->ruleList[rule].range[1][0], ruleset->ruleList[rule].range[1][1],
                        ruleset->ruleList[rule].range[2][0], ruleset->ruleList[rule].range[2][1],
                        ruleset->ruleList[rule].range[3][0], ruleset->ruleList[rule].range[3][1],
                        ruleset->ruleList[rule].range[4][0], ruleset->ruleList[rule].range[4][1],
                        ruleset->ruleList[rule].range[5][0], ruleset->ruleList[rule].range[5][1],
                        ruleset->ruleList[rule].range[6][0], ruleset->ruleList[rule].range[6][1]);
            LOGDBG("hit Rule Id is %d\n", ruleset->ruleList[rule].rule_id);
        #endif

            timestar = ruleset->ruleList[rule].time_start;
            timeend = ruleset->ruleList[rule].time_end;

            if(timestar == 0 && timeend == 0)
            {
                action = ruleset->ruleList[rule].action;
            }
            else
            {
                if(mb->timestamp >= timestar && mb->timestamp <= timeend)
                {
                    action = ruleset->ruleList[rule].action;
                }
                else
                {
                    action = dp_acl_action_default;
                #ifdef SEC_ACL_DEBUG
                    LOGDBG("time not match, not hit\n");
                #endif
                }
            }
        }

        read_unlock(&g_acltree.hs_rwlock);

    }
    else // trylock fail,  must be commiting, pass fw
    {
        return ACL_RULE_ACTION_FW;
    }


#ifdef SEC_ACL_DEBUG
    LOGDBG("hit Rule action is %s\n", action ? "drop" : "fw");
#endif

    return action;
}



static pthread_t dp_acl_build_thread;


void DP_Acl_Build()
{
    if(rule_list->build_status != RULE_BUILD_COMMIT)
    {
        write_lock(&g_acltree.hs_rwlock);

        DP_Acl_Rule_Clean(&(g_acltree.TreeSet),&(g_acltree.TreeNode));

        if(rule_list->rule_entry_free != RULE_ENTRY_MAX)  // rule empty, no need to load
        {
            DP_Acl_Load_Rule(rule_list,&(g_acltree.TreeSet),&(g_acltree.TreeNode));
        }

        write_unlock(&g_acltree.hs_rwlock);

        rule_list->build_status = RULE_BUILD_COMMIT;

        LOGDBG("\nwrst case tree depth: %d\n",gWstDepth);
        if(gChildCount)
            LOGDBG("\naverage tree depth: %f\n",(float)gAvgDepth/gChildCount);
        LOGDBG("\nnumber of tree nodes: %d\n",gNumTreeNode);
        LOGDBG("\nnumber of leaf nodes: %d\n",gNumLeafNode);
        LOGDBG("\nfinished\n");
    }

}


static void *DP_Acl_Build_Fn(void *arg)
{
    int rc;
    cpu_set_t mask;
    cpu_set_t cpuset;
    int j;
    CPU_ZERO(&cpuset);
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);

    printf("dp acl build thread running\n");

    pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    printf("Set returned by pthread_getaffinity_np() contained:\n");
    for (j = 0; j < 2; j++)
        if (CPU_ISSET(j, &cpuset))
            printf("    CPU %d\n", j);

    if(pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        LOGDBG("set thread affinity failed\n");
    }

    LOGDBG("set thread affinity OK\n");

    pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    printf("Set returned by pthread_getaffinity_np() contained:\n");
    for (j = 0; j < 2; j++)
        if (CPU_ISSET(j, &cpuset))
            printf("    CPU %d\n", j);


    while(1)
    {
        rc = sleep(DP_ACL_BUILD_CHECK_INTERVAL);

        if(0 == rc)
        {
            DP_Acl_Build();
        }
    }

    return NULL;

}




void DP_Acl_Build_Thread_Init()
{
    pthread_create(&dp_acl_build_thread, NULL, DP_Acl_Build_Fn, NULL);
}
















