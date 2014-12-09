#ifndef  __ACL64_H__
#define  __ACL64_H__

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "inttypes.h"
#include "acl_rule.h"
#include <sec-common.h>
#include <oct-common.h>


/*-----------------------------------------------------------------------------
 *  constant
 *-----------------------------------------------------------------------------*/

//#define   DEBUG
//#define   LOOKUP

/* for 7-tuple classification */
#define DIM         7

/* for function return value */
#define SUCCESS     1
#define FAILURE     0



/*-----------------------------------------------------------------------------
 *  structure
 *-----------------------------------------------------------------------------*/
struct FILTER
{
    uint64_t dim[DIM][2];
    uint8_t  action;
    int32_t  rule_id;
};

struct FILTSET
{
    uint32_t    numFilters;
    struct FILTER   filtArr[RULE_ENTRY_MAX];
};




/*for hyper-splitting tree*/
typedef struct rule_s
{
    uint32_t    pri;
    uint8_t     action;
    uint32_t    rule_id;
    uint64_t    range[DIM][2];
} rule_t;

typedef struct rule_set_s
{
    uint32_t num; /* number of rules in the rule set */
    rule_t* ruleList; /* rules in the set */
} rule_set_t;



typedef struct hs_node_s
{
    unsigned char       d2s;        /* dimension to split, 2bit is enough */
    unsigned char       depth;      /* tree depth of the node, x bits supports 2^(2^x) segments */
    uint64_t            thresh;     /* thresh value to split the current segments */
    struct hs_node_s*   child[2];   /* pointer to child-node, 2 for binary split */
} hs_node_t;


typedef struct {
    rule_set_t TreeSet;
    hs_node_t  TreeNode;
} unit_tree;


#define HS_NODE_NUM_MAX 300000
#define HS_NODE_NAME "hs_node_ring"
typedef struct
{
    uint32_t rd_index;
    uint32_t wr_index;

    uint64_t node_ptr[HS_NODE_NUM_MAX];

}HS_Node_Ring_t;



/*-----------------------------------------------------------------------------
 *  function declaration
 *-----------------------------------------------------------------------------*/

/* read rules from file */

/* build hyper-split-tree */
int BuildHSTree(rule_set_t* ruleset, hs_node_t* node, unsigned int depth); /* main */
int SegPointCompare(const void * a, const void * b);

/* lookup hyper-split-tree */
extern int LookupHSTree(uint64_t packet[DIM], rule_set_t* ruleset,hs_node_t* root, hs_node_t **hitnode);
extern void ReadMACRange(uint8_t *mac, uint64_t *MACrange);
extern void ReadIPRange(uint32_t ipnet, uint32_t ipmask, uint64_t* IPranges, uint64_t* IPrangee);
extern void ReadPort(uint16_t sport_start, uint16_t sport_end, uint64_t* from, uint64_t* to);
extern void ReadProto(uint8_t proto_start, uint8_t proto_end, uint64_t* from, uint64_t* to);
extern uint32_t HS_Node_Init();
extern void FreeRootNode(hs_node_t *rootnode);
#endif   /* ----- #ifndef _HS_H ----- */

