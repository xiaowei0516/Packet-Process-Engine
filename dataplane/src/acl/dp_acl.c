#include <sec-common.h>
#include <shm.h>
#include <acl_rule.h>
#include "dp_acl.h"
#include <mbuf.h>




rule_list_t *rule_list;

unit_tree g_acltree;


uint32_t DP_Acl_Rule_Init()
{
    int fd;
    
    fd = shm_open(SHM_RULE_LIST_NAME, O_RDWR, 0);

    if (fd < 0) {
        printf("Failed to setup CVMX_SHARED(shm_open)");
        return SEC_NO;
    }

    //if (shm_unlink(SHM_RULE_LIST_NAME) < 0)
    //  printf("Failed to shm_unlink shm_name");

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

uint32_t load_rule(rule_list_t *rule_list,rule_set_t* ruleset, hs_node_t* node)
{
    uint32_t i,j;
    uint32_t count = 0;
    struct FILTER *tempfilt,tempfilt1;
    tempfilt = &tempfilt1;

    if(ruleset == NULL || node == NULL)
    {
        printf("\nwrong parameters\n");
        return SEC_NO;
    }
    
    struct FILTSET* filtset = (struct FILTSET*)malloc(sizeof(struct FILTSET));
    if(NULL == filtset)
    {
        return SEC_NO;
    }
   
    memset(filtset, 0, sizeof(struct FILTSET));
    
    //FreeRuleSet(ruleset);
    //FreeRootNode(node);

    
    for( i = 0; i < RULE_ENTRY_MAX; i++ )
    {
        if(rule_list->rule_entry[i].entry_status == RULE_ENTRY_STATUS_FREE)
        {
            continue;
        }

        memset(tempfilt->dim, 0, DIM*2*sizeof(uint32_t *));

        //tempfilt->action = (unsigned int)rule_list->rule_entry[i].rule_tuple.action;
 
        ReadMACRange(rule_list->rule_entry[i].rule_tuple.smac, tempfilt->dim[0]); /*0 SMAC from to*/
        ReadMACRange(rule_list->rule_entry[i].rule_tuple.dmac, tempfilt->dim[1]); /*1 DMAC from to*/
        
        ReadIPRange(rule_list->rule_entry[i].rule_tuple.sip,rule_list->rule_entry[i].rule_tuple.sip_mask, &tempfilt->dim[2][0], &tempfilt->dim[2][1]);/*2 SIP from to*/
        ReadIPRange(rule_list->rule_entry[i].rule_tuple.dip,rule_list->rule_entry[i].rule_tuple.dip_mask, &tempfilt->dim[3][0], &tempfilt->dim[3][1]);/*3 DIP from to*/  

        ReadPort(rule_list->rule_entry[i].rule_tuple.sport_start, 
            rule_list->rule_entry[i].rule_tuple.sport_end, 
            &(tempfilt->dim[4][0]),
            &(tempfilt->dim[4][1]));    /*4 SPORT from to*/ 

        
        ReadPort(rule_list->rule_entry[i].rule_tuple.dport_start, 
            rule_list->rule_entry[i].rule_tuple.dport_end,
            &(tempfilt->dim[5][0]),
            &(tempfilt->dim[5][1]));   /*5 DPORT  from to*/

        ReadProto(rule_list->rule_entry[i].rule_tuple.protocol_start,
            rule_list->rule_entry[i].rule_tuple.protocol_end,
            &(tempfilt->dim[6][0]),
            &(tempfilt->dim[6][1]));   /*6 PROTO  from to*/

        memcpy(&(filtset->filtArr[filtset->numFilters]), tempfilt, sizeof(struct FILTER));
            
        filtset->numFilters++;
        count++;
    }
    
    ruleset->num = filtset->numFilters;
    ruleset->ruleList = (rule_t *) malloc((ruleset->num + 1) * sizeof(rule_t));
    
    memset(ruleset->ruleList, 0, (ruleset->num + 1) * sizeof(rule_t));

    for (i = 0; i < ruleset->num; i++) 
    {
        ruleset->ruleList[i].pri = i;
        for (j = 0; j < DIM; j++) 
        {
            ruleset->ruleList[i].range[j][0] = filtset->filtArr[i].dim[j][0];
            ruleset->ruleList[i].range[j][1] = filtset->filtArr[i].dim[j][1];
        }
    }

    printf("\n>>number of rules loaded  %d\n", ruleset->num);

    printf("gard rule id is %d\n", ruleset->num);
    ruleset->ruleList[ruleset->num].pri = ruleset->num;

    ruleset->ruleList[ruleset->num].range[0][0] = 0;
    ruleset->ruleList[ruleset->num].range[0][1] = 0xffffffffffff;
    ruleset->ruleList[ruleset->num].range[1][0] = 0;
    ruleset->ruleList[ruleset->num].range[1][1] = 0xffffffffffff;
    ruleset->ruleList[ruleset->num].range[2][0] = 0;
    ruleset->ruleList[ruleset->num].range[2][1] = 0xffffffff;
    ruleset->ruleList[ruleset->num].range[3][0] = 0;
    ruleset->ruleList[ruleset->num].range[3][1] = 0xffffffff;
    ruleset->ruleList[ruleset->num].range[4][0] = 0;
    ruleset->ruleList[ruleset->num].range[4][1] = 0xffff;
    ruleset->ruleList[ruleset->num].range[5][0] = 0;
    ruleset->ruleList[ruleset->num].range[5][1] = 0xffff;
    ruleset->ruleList[ruleset->num].range[6][0] = 0;
    ruleset->ruleList[ruleset->num].range[6][1] = 0xff;

    ruleset->num += 1;
    
    uint32_t ruleNum;
    for (ruleNum = 0; ruleNum < ruleset->num; ruleNum ++) 
    {
        printf("\n>> Rule%d: [%lx %lx] [%lx %lx] [%lx %lx], [%lx %lx], [%lx %lx], [%lx %lx], [%lx %lx]\n", ruleNum,
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



uint32_t DP_Acl_Lookup(mbuf_t *mb)
{
    uint64_t packet[7] = {0};
    uint64_t z[6] = { 0 };
    uint64_t x, y;
    int i;
    rule_set_t* ruleset;
    hs_node_t* root;

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

    ruleset = &(g_acltree.TreeSet);
    root = &(g_acltree.TreeNode);

    LookupHSTree(packet, ruleset, root);

    return SEC_OK;
}




