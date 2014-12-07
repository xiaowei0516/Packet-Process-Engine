#ifndef __DP_ACL_H__
#define __DP_ACL_H__


#include "sec-common.h"
#include "acl_rule.h"
#include "hs.h"
#include "mbuf.h"


extern rule_list_t *rule_list;

extern unit_tree g_acltree;
extern uint32_t	gWstDepth;
extern uint32_t gAvgDepth;
extern uint32_t	gChildCount;
extern uint32_t	gNumTreeNode;
extern uint32_t	gNumLeafNode;

extern uint32_t DP_Acl_Rule_Init();

extern uint32_t load_rule(rule_list_t *rule_list,rule_set_t* ruleset, hs_node_t* node);
extern bool firewall_pass_rule(mbuf_t* p);

#endif