#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <sec-common.h>
#include <shm.h>
#include <acl_rule.h>
#include "dp_acl.h"
#include <mbuf.h>
#include <sec-debug.h>

#include "rule.h"

uint32_t dp_acl_action_default = ACL_RULE_ACTION_DROP;

rule_list_t *rule_list;

unit_tree_t g_acltree_1;
unit_tree_t g_acltree_2;
unsigned long g_acltree_running = 0;
rwlock_t acltree_running_rwlock;



//static pthread_mutex_t rule_list_mutex_dp = PTHREAD_MUTEX_INITIALIZER;

char *rule_conf_filename = "/data/rule_config.rul";

static pthread_t rule_load_thread_dp;
static pthread_cond_t rule_load_cond_dp = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t rule_load_mutex_dp= PTHREAD_MUTEX_INITIALIZER; //mutex for rule config file and load
uint32_t rule_load_notify_dp = 0;



uint32_t DP_Acl_Tree_Init()
{
    void *ptr1;
    void *ptr2;

    ptr1 = (void *)cvmx_bootmem_alloc_named((RULE_ENTRY_MAX + 1) * sizeof(rule_t), 128, DP_ACL_RULELIST_NAME_1);
    if(NULL == ptr1)
    {
        return SEC_NO;
    }

    ptr2 = (void *)cvmx_bootmem_alloc_named((RULE_ENTRY_MAX + 1) * sizeof(rule_t), 128, DP_ACL_RULELIST_NAME_2);
    if(NULL == ptr2)
    {
        return SEC_NO;
    }

    /*init acltree 1*/
    memset(ptr1, 0, (RULE_ENTRY_MAX + 1) * sizeof(rule_t));

    rwlock_init(&g_acltree_1.hs_rwlock);

    g_acltree_1.TreeSet.num = 0;
    g_acltree_1.TreeSet.ruleList = (rule_t *)ptr1;

    memset((void *)&g_acltree_2.TreeNode, 0, sizeof(hs_node_t));

    /*init acltree 2*/
    memset(ptr2, 0, (RULE_ENTRY_MAX + 1) * sizeof(rule_t));

    rwlock_init(&g_acltree_1.hs_rwlock);

    g_acltree_2.TreeSet.num = 0;
    g_acltree_2.TreeSet.ruleList = (rule_t *)ptr2;

    memset((void *)&g_acltree_2.TreeNode, 0, sizeof(hs_node_t));

    g_acltree_running = (unsigned long)(void *)&g_acltree_2;
    rwlock_init(&acltree_running_rwlock);

    return SEC_OK;
}


uint32_t DP_Acl_List_Init()
{
    int fd;

    fd = shm_open(SHM_RULE_LIST_NAME, O_RDWR, 0);
    if (fd < 0)
    {
        printf("Failed to setup CVMX_SHARED(shm_open)\n");
        return SEC_NO;
    }

    ftruncate(fd, sizeof(rule_list_t));

    void *ptr = mmap(NULL, sizeof(rule_list_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == NULL)
    {
        printf("Failed to setup rule list (mmap copy)");
        return SEC_NO;
    }

    rule_list = (rule_list_t *)ptr;

    return SEC_OK;
}





int DP_Rule_load_from_conf()
{
    int line = 0;
    uint32_t ret;
    FILE *fp;

    if(access(rule_conf_filename, F_OK) != 0)
    {
        printf("RULE CONFIG FILE NOT EXIST\n");
        return  -1;
    }

    fp = fopen(rule_conf_filename, "r");
    if (fp == NULL)
    {
        printf("Couldnt open rule config file\n");
        return  -1;
    }

#ifdef RULE_DEBUG
    printf("open rule config success\n");
#endif

    Rule_del_all();

#ifdef RULE_DEBUG
    printf("rule delete all\n");
#endif

    while(!feof(fp))
    {
        ret = Rule_Load_Line(fp, line);
        if(ret != 0)
        {
            //printf("config file line %d format err\n", line);
            fclose(fp);
            return 0;
        }
        line++;
    }

    fclose(fp);

    return 0;

}


void DP_Rule_Conf_Recover()
{
    pthread_mutex_lock(&rule_load_mutex_dp);

    if(DP_Rule_load_from_conf() < 0)
    {
        pthread_mutex_unlock(&rule_load_mutex_dp);
        return;
    }

#ifdef RULE_DEBUG
    printf("success load rule num is %d\n", RULE_ENTRY_MAX - rule_list->rule_entry_free);
#endif

    Rule_Notify_Dp_Build_Sync();

    pthread_mutex_unlock(&rule_load_mutex_dp);
}

static void *DP_Rule_Load_Fn(void *arg)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);

    printf("DP_Rule_Load_Fn thread running\n");

    if(pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        printf("set thread affinity failed\n");
    }

    printf("set thread affinity OK\n");

    cvmx_linux_enable_xkphys_access(0);

    while(1)
    {
        pthread_mutex_lock(&rule_load_mutex_dp);

        while (!rule_load_notify_dp)
        {
            pthread_cond_wait(&rule_load_cond_dp, &rule_load_mutex_dp);
        }

        DP_Rule_load_from_conf();

        printf("success load rule num is %d\n", RULE_ENTRY_MAX - rule_list->rule_entry_free);

        Rule_Notify_Dp_Build_Sync();

        rule_load_notify_dp = 0;

        pthread_mutex_unlock(&rule_load_mutex_dp);
    }

    return NULL;
}


void DP_Rule_load_thread_start()
{
    pthread_create(&rule_load_thread_dp, NULL, DP_Rule_Load_Fn, NULL);
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

    printf("start rule load thread...\n");
    DP_Rule_load_thread_start();

    DP_Rule_Conf_Recover();

    return SEC_OK;
}

void DP_Acl_Rule_Release(void)
{
    int rc;
    rc = cvmx_bootmem_free_named(DP_ACL_RULELIST_NAME_1);
    printf("%s free rc=%d\n", DP_ACL_RULELIST_NAME_1, rc);

    rc = cvmx_bootmem_free_named(DP_ACL_RULELIST_NAME_2);
    printf("%s free rc=%d\n", DP_ACL_RULELIST_NAME_2, rc);


    rc = cvmx_bootmem_free_named(HS_NODE_NAME);
    printf("%s free rc=%d\n", HS_NODE_NAME, rc);

}


void DP_Acl_Add_GuardRule(uint32_t id, rule_t* ruleList)
{
    LOGDBG(SEC_ACL_DBG_BIT, "guard rule id is %d\n", id);

    ruleList->pri = id;
    ruleList->logable = 0;
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
        LOGDBG(SEC_ACL_DBG_BIT, "\nwrong parameters\n");
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
        tempfilt->logable = (unsigned int)rule_list->rule_entry[i].rule_tuple.logable;
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
        ruleset->ruleList[i].logable = filtset->filtArr[i].logable;
        ruleset->ruleList[i].rule_id = filtset->filtArr[i].rule_id;
        ruleset->ruleList[i].time_start = filtset->filtArr[i].time_start;
        ruleset->ruleList[i].time_end = filtset->filtArr[i].time_end;
        for (j = 0; j < DIM; j++)
        {
            ruleset->ruleList[i].range[j][0] = filtset->filtArr[i].dim[j][0];
            ruleset->ruleList[i].range[j][1] = filtset->filtArr[i].dim[j][1];
        }
    }

    LOGDBG(SEC_ACL_DBG_BIT, "number of rules loaded  %d\n", ruleset->num);

    DP_Acl_Add_GuardRule(ruleset->num, &ruleset->ruleList[ruleset->num]);
    ruleset->num += 1;

    uint32_t ruleNum;
    for (ruleNum = 0; ruleNum < ruleset->num; ruleNum ++)
    {
        LOGDBG(SEC_ACL_DBG_BIT, "\nRule%d: [%lx %lx] [%lx %lx] [%lx %lx], [%lx %lx], [%lx %lx], [%lx %lx], [%lx %lx]\n", ruleNum,
            ruleset->ruleList[ruleNum].range[0][0], ruleset->ruleList[ruleNum].range[0][1],
            ruleset->ruleList[ruleNum].range[1][0], ruleset->ruleList[ruleNum].range[1][1],
            ruleset->ruleList[ruleNum].range[2][0], ruleset->ruleList[ruleNum].range[2][1],
            ruleset->ruleList[ruleNum].range[3][0], ruleset->ruleList[ruleNum].range[3][1],
            ruleset->ruleList[ruleNum].range[4][0], ruleset->ruleList[ruleNum].range[4][1],
            ruleset->ruleList[ruleNum].range[5][0], ruleset->ruleList[ruleNum].range[5][1],
            ruleset->ruleList[ruleNum].range[6][0], ruleset->ruleList[ruleNum].range[6][1]);
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
    unit_tree_t *p_running_tree;

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

    LOGDBG(SEC_ACL_DBG_BIT, "\n>>packet: [%lx  %lx]  [%lx  %lx]  [%lx %lx], [%lx %lx], [%lu %lu], [%lu %lu], [%lx %lx]\n",
            packet[0], packet[0],
            packet[1], packet[1],
            packet[2], packet[2],
            packet[3], packet[3],
            packet[4], packet[4],
            packet[5], packet[5],
            packet[6], packet[6]);

    read_lock(&acltree_running_rwlock);

    p_running_tree = (unit_tree_t *)g_acltree_running;

    if(p_running_tree->TreeSet.num == 0)
    {
        LOGDBG(SEC_ACL_DBG_BIT, "Rule is empty\n");

        read_unlock(&acltree_running_rwlock);

        return ACL_RULE_ACTION_FW;
    }

    ruleset = &(p_running_tree->TreeSet);
    root = &(p_running_tree->TreeNode);

    LookupHSTree(packet, ruleset, root, &hit_node);

    LOGDBG(SEC_ACL_DBG_BIT, "\nnode->thresh: ""%" PRId64 "\n",  hit_node->thresh);

    rule = (uint32_t)hit_node->thresh;
    if(rule == ruleset->num - 1)
    {
        action = ruleset->ruleList[rule].action;
        LOGDBG(SEC_ACL_DBG_BIT, "\nhit guard rule\n");
    }
    else
    {
        LOGDBG(SEC_ACL_DBG_BIT, "\n>>hit Rule%ld: [%8lx %8lx] [%8lx %8lx] [%8lx %8lx], [%8lx %8lx], [%5lu %5lu], [%5lu %5lu], [%2lx %2lx]\n", hit_node->thresh+1,
                    ruleset->ruleList[rule].range[0][0], ruleset->ruleList[rule].range[0][1],
                    ruleset->ruleList[rule].range[1][0], ruleset->ruleList[rule].range[1][1],
                    ruleset->ruleList[rule].range[2][0], ruleset->ruleList[rule].range[2][1],
                    ruleset->ruleList[rule].range[3][0], ruleset->ruleList[rule].range[3][1],
                    ruleset->ruleList[rule].range[4][0], ruleset->ruleList[rule].range[4][1],
                    ruleset->ruleList[rule].range[5][0], ruleset->ruleList[rule].range[5][1],
                    ruleset->ruleList[rule].range[6][0], ruleset->ruleList[rule].range[6][1]);
        LOGDBG(SEC_ACL_DBG_BIT, "hit Rule Id is %d\n", ruleset->ruleList[rule].rule_id);

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
                LOGDBG(SEC_ACL_DBG_BIT, "time not match, not hit\n");
            }
        }
    }
    mb->flow_log = ruleset->ruleList[rule].logable;
    read_unlock(&acltree_running_rwlock);

    LOGDBG(SEC_ACL_DBG_BIT, "hit Rule action is %s\n", action ? "drop" : "fw");
    LOGDBG(SEC_ACL_DBG_BIT, "hit Rule log is %s\n", mb->flow_log ? "enable" : "disable");

    return action;
}





void Rule_config()
{
}

void Rule_Load_Notify()
{
    pthread_mutex_lock(&rule_load_mutex_dp);

    Rule_config();  //give a configfile and notify

    rule_load_notify_dp = 1;

    pthread_cond_signal(&rule_load_cond_dp);

    pthread_mutex_unlock(&rule_load_mutex_dp);
}




int DP_Acl_Rule_Add(RCP_BLOCK_ACL_RULE_TUPLE *rule, uint32_t *ruleid)
{
    int ret;

    ret = Rule_add(rule, ruleid);
    if(ret != RULE_OK)
    {
        return ret;
    }

#ifdef RULE_DEBUG
    printf("success load rule num is %d\n", RULE_ENTRY_MAX - rule_list->rule_entry_free);
#endif

    Rule_Notify_Dp_Build();

    return RULE_OK;
}


int DP_Acl_Rule_Delete(uint32_t ruleid)
{
    int ret;
    ret = Rule_del_by_id(ruleid);
    if(ret != RULE_OK)
    {
        return ret;
    }

#ifdef RULE_DEBUG
    printf("success delete rule,now num is %d\n", RULE_ENTRY_MAX - rule_list->rule_entry_free);
#endif

    Rule_Notify_Dp_Build();

    return RULE_OK;
}

uint32_t ruleid = 0;
void DP_Acl_Rule_Add_Test()
{

    RCP_BLOCK_ACL_RULE_TUPLE rule;
    rule.action = 0;
    rule.smac[0] = 0x22;
    rule.smac[1] = 0x22;
    rule.smac[2] = 0x22;
    rule.smac[3] = 0x22;
    rule.smac[4] = 0x22;
    rule.smac[5] = 0x22;

    rule.dmac[0] = 0x33;
    rule.dmac[1] = 0x33;
    rule.dmac[2] = 0x33;
    rule.dmac[3] = 0x33;
    rule.dmac[4] = 0x33;
    rule.dmac[5] = 0x33;

    rule.sip = 0x10101010;
    rule.dip = 0x20202020;

    rule.sip_mask = 32;
    rule.dip_mask = 24;

    rule.sport_start = 2;
    rule.sport_end = 2;

    rule.dport_start = 3;
    rule.dport_end = 3;

    rule.protocol_start = 4;
    rule.protocol_end = 4;

    rule.time_start = 0;
    rule.time_end = 0;

    DP_Acl_Rule_Add(&rule, &ruleid);

}

void DP_Acl_Rule_Delete_Test()
{
    DP_Acl_Rule_Delete(ruleid);
}



