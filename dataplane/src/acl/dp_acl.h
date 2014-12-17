#ifndef __DP_ACL_H__
#define __DP_ACL_H__


#include "sec-common.h"
#include "acl_rule.h"
#include "acl64.h"
#include "mbuf.h"


#define DP_ACL_RULELIST_NAME "DP_ACL_RULELIST"


#define DP_ACL_BUILD_CHECK_INTERVAL  1



extern rule_list_t *rule_list;

extern CVMX_SHARED unit_tree g_acltree;

extern CVMX_SHARED uint32_t dp_acl_action_default;

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

#endif
