#ifndef __DP_ACL_H__
#define __DP_ACL_H__


#include "sec-common.h"
#include "acl_rule.h"
#include "acl64.h"
#include "mbuf.h"


#define DP_ACL_RULELIST_NAME_1 "DP_ACL_RULELIST_1"
#define DP_ACL_RULELIST_NAME_2 "DP_ACL_RULELIST_2"



#define DP_ACL_BUILD_CHECK_INTERVAL  1



extern rule_list_t *rule_list;

extern unit_tree_t g_acltree_1;
extern unit_tree_t g_acltree_2;
extern unsigned long g_acltree_running;
extern rwlock_t acltree_running_rwlock;

extern uint32_t dp_acl_action_default;

extern uint32_t gWstDepth;
extern uint32_t gAvgDepth;
extern uint32_t gChildCount;
extern uint32_t gNumTreeNode;
extern uint32_t gNumLeafNode;

extern uint32_t DP_Acl_Rule_Init();
extern uint32_t DP_Acl_Load_Rule(rule_list_t *rule_list,rule_set_t* ruleset, hs_node_t* node);
extern bool firewall_pass_rule(mbuf_t* p);
extern uint32_t DP_Acl_Rule_Clean(rule_set_t* ruleset, hs_node_t* node);
extern uint8_t DP_Acl_Lookup(mbuf_t *mb);
extern int DP_Acl_Rule_Add(RCP_BLOCK_ACL_RULE_TUPLE *rule, uint32_t *ruleid);
extern int DP_Acl_Rule_Delete(uint32_t ruleid);

extern void DP_Acl_Rule_Add_Test();
extern void DP_Acl_Rule_Delete_Test();


#endif
