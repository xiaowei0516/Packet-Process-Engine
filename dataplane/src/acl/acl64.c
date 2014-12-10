#include "acl64.h"

/*-----------------------------------------------------------------------------
 *  globals
 *-----------------------------------------------------------------------------*/
unsigned int    gChildCount = 0;

unsigned int    gNumTreeNode = 0;
unsigned int    gNumLeafNode = 0;

unsigned int    gWstDepth = 0;
unsigned int    gAvgDepth = 0;

unsigned int    gNumNonOverlappings[DIM];
unsigned long long  gNumTotalNonOverlappings = 1;

struct timeval  gStartTime,gEndTime;



HS_Node_Ring_t *hsnode_ring;
uint32_t HS_Node_Init()
{
    int i = 0;
    uint64_t start;

    void *ptr = (void *)cvmx_bootmem_alloc_named(sizeof(HS_Node_Ring_t) + (HS_NODE_NUM_MAX - 1) * sizeof(hs_node_t), 128, HS_NODE_NAME);
    if(NULL == ptr)
    {
        return SEC_NO;
    }

    memset(ptr, 0, sizeof(HS_Node_Ring_t) + HS_NODE_NUM_MAX * sizeof(hs_node_t));

    hsnode_ring = (HS_Node_Ring_t *)ptr;

    start = (uint64_t)ptr + sizeof(HS_Node_Ring_t);

    for(i = 0; i < HS_NODE_NUM_MAX - 1; i++)
    {
        hsnode_ring->node_ptr[i] = start + sizeof(hs_node_t) * i;
    }

    hsnode_ring->rd_index = 0;
    hsnode_ring->wr_index = HS_NODE_NUM_MAX;

    return SEC_OK;
}





void *HS_NODE_ALLOC()
{
    void *ptr;
    if(hsnode_ring->rd_index == hsnode_ring->wr_index)
    {
        return NULL;
    }

    ptr = (void *)hsnode_ring->node_ptr[hsnode_ring->rd_index];
    hsnode_ring->rd_index = (hsnode_ring->rd_index + 1) % HS_NODE_NUM_MAX;
    return ptr;
}

void HS_NODE_FREE(void *ptr)
{
    if( (hsnode_ring->wr_index + 1) % HS_NODE_NUM_MAX == hsnode_ring->rd_index)
    {
        return;
    }

    hsnode_ring->node_ptr[hsnode_ring->wr_index] = (uint64_t)ptr;

    hsnode_ring->wr_index = (hsnode_ring->wr_index + 1) % HS_NODE_NUM_MAX;
}


int SegPointCompare (const void * a, const void * b)
{
    if ( *(uint64_t*)a < *(uint64_t*)b )
        return -1;
    else if ( *(uint64_t*)a == *(uint64_t*)b )
        return 0;
    else
        return 1;
}


static void _FreeRootNode(hs_node_t *rootnode, uint32_t depth)
{
    uint32_t i = 0;

    if( NULL == rootnode )
    {
        return ;
    }

    if( 0 == depth && NULL == rootnode->child[0] && NULL == rootnode->child[1])
    {
        return ;
    }


    for( i = 0; i < sizeof(rootnode->child)/sizeof(hs_node_t *); i++)
    {
        if(NULL != rootnode->child[i])
        {
            _FreeRootNode(rootnode->child[i], depth+1);
        }
    }

    if(0 != depth && rootnode)
    {
        HS_NODE_FREE(rootnode);
    }

    return ;
}



void FreeRootNode(hs_node_t *rootnode)
{
    _FreeRootNode(rootnode, 0);
}



void release_ruleset(rule_set_t* childRuleSet)
{
    if(childRuleSet->ruleList)
    {
        free(childRuleSet->ruleList);
    }

    if(childRuleSet)
    {
        free(childRuleSet);
    }
}



int BuildHSTree (rule_set_t* ruleset, hs_node_t* currNode, unsigned int depth)
{
     /* generate segments for input filtset */
    unsigned int dim, num, pos;
    unsigned int maxDiffSegPts = 1; /* maximum different segment points */
    unsigned int d2s = 0;   /* dimension to split (with max diffseg) */
    uint64_t    thresh = 0;
    uint64_t    range[2][2] = {{0,0}, {0,0}}; /* sub-space ranges for child-nodes */
    uint64_t    *segPoints[DIM];
    uint64_t    *segPointsInfo[DIM];
    uint64_t    *tempSegPoints;
    unsigned int    *tempRuleNumList;
    float hightAvg, hightAll;
    rule_set_t      *childRuleSet = NULL;

#ifdef DEBUG
    /*if (depth > 10)  exit(0);*/
    printf("\n\n>>BuildHSTree at depth=%d", depth);
    printf("\n>>Current Rules:");
    for (num = 0; num < ruleset->num; num++) {
        printf ("\n>>%5dth Rule:", ruleset->ruleList[num].pri);
        for (dim = 0; dim < DIM; dim++) {
            printf (" [%-8lx, %-8lx]", ruleset->ruleList[num].range[dim][0], ruleset->ruleList[num].range[dim][1]);
        }
    }
#endif /* DEBUG */

    /*Generate Segment Points from Rules*/
    for (dim = 0; dim < DIM; dim ++) {
        /* N rules have 2*N segPoints */
        segPoints[dim] = (uint64_t *) malloc ( 2 * ruleset->num * sizeof(uint64_t));
        segPointsInfo[dim] = (uint64_t *) malloc ( 2 * ruleset->num * sizeof(uint64_t));
        for (num = 0; num < ruleset->num; num ++) {
            segPoints[dim][2*num] = ruleset->ruleList[num].range[dim][0];
            segPoints[dim][2*num + 1] = ruleset->ruleList[num].range[dim][1];
        }
    }
    /*Sort the Segment Points*/
    for(dim = 0; dim < DIM; dim ++) {
        qsort(segPoints[dim], 2*ruleset->num, sizeof(uint64_t), SegPointCompare);
    }

    /*Compress the Segment Points, and select the dimension to split (d2s)*/
    tempSegPoints  = (uint64_t*) malloc(2 * ruleset->num * sizeof(uint64_t));
    hightAvg = 2*ruleset->num + 1;
    for (dim = 0; dim < DIM; dim ++) {
        unsigned int    i, j;
        unsigned int    *hightList;
        unsigned int    diffSegPts = 1; /* at least there are one differnt segment point */
        tempSegPoints[0] = segPoints[dim][0];
        for (num = 1; num < 2*ruleset->num; num ++) {
            if (segPoints[dim][num] != tempSegPoints[diffSegPts-1]) {
                tempSegPoints[diffSegPts] = segPoints[dim][num];
                diffSegPts ++;
            }
        }
        /*Span the segment points which is both start and end of some rules*/
        pos = 0;
        for (num = 0; num < diffSegPts; num ++) {
            uint32_t i;
            int ifStart = 0;
            int ifEnd   = 0;
            segPoints[dim][pos] = tempSegPoints[num];
            for (i = 0; i < ruleset->num; i ++) {
                if (ruleset->ruleList[i].range[dim][0] == tempSegPoints[num]) {
                    /*printf ("\n>>rule[%d] range[0]=%x", i, ruleset->ruleList[i].range[dim][0]);*/
                    /*this segment point is a start point*/
                    ifStart = 1;
                    break;
                }
            }
            for (i = 0; i < ruleset->num; i ++) {
                if (ruleset->ruleList[i].range[dim][1] == tempSegPoints[num]) {
                    /*printf ("\n>>rule[%d] range[1]=%x", i, ruleset->ruleList[i].range[dim][1]);*/
                    /* this segment point is an end point */
                    ifEnd = 1;
                    break;
                }
            }
            if (ifStart && ifEnd) {
                segPointsInfo[dim][pos] = 0;
                pos ++;
                segPoints[dim][pos] = tempSegPoints[num];
                segPointsInfo[dim][pos] = 1;
                pos ++;
            }
            else if (ifStart) {
                segPointsInfo[dim][pos] = 0;
                pos ++;
            }
            else {
                segPointsInfo[dim][pos] = 1;
                pos ++;
            }
        }

        /* now pos is the total number of points in the spanned segment point list */

        if (depth == 0) {
            gNumNonOverlappings[dim] = pos;
            gNumTotalNonOverlappings *= (unsigned long long) pos;
        }

#ifdef  DEBUG
        printf("\n>>dim[%d] segs: ", dim);
        for (num = 0; num < pos; num++) {
            /*if (!(num % 10))  printf("\n");*/
            printf ("%lx(%lu) ", segPoints[dim][num], segPointsInfo[dim][num]);
        }
#endif /* DEBUG */

        if (pos >= 3) {
            hightAll = 0;
            hightList = (unsigned int *) malloc(pos * sizeof(unsigned int));
            for (i = 0; i < pos-1; i++) {
                hightList[i] = 0;
                for (j = 0; j < ruleset->num; j++) {
                    if (ruleset->ruleList[j].range[dim][0] <= segPoints[dim][i] \
                            && ruleset->ruleList[j].range[dim][1] >= segPoints[dim][i+1]) {
                        hightList[i]++;
                        hightAll++;
                    }
                }
            }
            if (hightAvg > hightAll/(pos-1)) {  /* possible choice for d2s, pos-1 is the number of segs */
                float hightSum = 0;

                /* select current dimension */
                d2s = dim;
                hightAvg = hightAll/(pos-1);

                /* the first segment MUST belong to the leff child */
                hightSum += hightList[0];
                for (num = 1; num < pos-1; num++) {  /* pos-1 >= 2; seg# = num */
                    if (segPointsInfo[d2s][num] == 0)
                        thresh = segPoints[d2s][num] - 1;
                    else
                        thresh = segPoints[d2s][num];

                    if (hightSum > hightAll/2) {
                        break;
                    }
                    hightSum += hightList[num];
                }
                /*printf("\n>>d2s=%u thresh=%x\n", d2s, thresh);*/
                range[0][0] = segPoints[d2s][0];
                range[0][1] = thresh;
                range[1][0] = thresh + 1;
                range[1][1] = segPoints[d2s][pos-1];
            }
            /* print segment list of each dim */
#ifdef  DEBUG
            printf("\n>>hightAvg=%f, hightAll=%f, segs=%d", hightAll/(pos-1), hightAll, pos-1);
            for (num = 0; num < pos-1; num++) {
                printf ("\nseg%5d[%8lx, %8lx](%u) ",
                        num, segPoints[dim][num], segPoints[dim][num+1], hightList[num]);
            }
#endif /* DEBUG */
            free(hightList);
        } /* pos >=3 */

        if (maxDiffSegPts < pos) {
            maxDiffSegPts = pos;
        }
    }
    free(tempSegPoints);

    /*Update Leaf node*/
    if (maxDiffSegPts <= 2) {
        currNode->d2s = 0;
        currNode->depth = depth;
        currNode->thresh = (uint64_t ) ruleset->ruleList[0].pri;
        currNode->child[0] = NULL;
        currNode->child[1] = NULL;

        for (dim = 0; dim < DIM; dim ++) {
            free(segPoints[dim]);
            free(segPointsInfo[dim]);
        }
#ifdef DEBUG
        printf("\n>>LEAF-NODE: matching rule %d", ruleset->ruleList[0].pri);
#endif /* DEBUG */

        gChildCount ++;
        gNumLeafNode ++;
        if (gNumLeafNode % 1000000 == 0)
            printf(".");
            /*printf("\n>>#%8dM leaf-node generated", gNumLeafNode/1000000);*/
        if (gWstDepth < depth)
            gWstDepth = depth;
        gAvgDepth += depth;
        return  SUCCESS;
    }

    /*Update currNode*/
    /*Binary split along d2s*/


#ifdef DEBUG
    /* split info */
    printf("\n>>d2s=%u; thresh=0x%8lx, range0=[%8lx, %8lx], range1=[%8lx, %8lx]",
            d2s, thresh, range[0][0], range[0][1], range[1][0], range[1][1]);
#endif /* DEBUG */

    if (range[1][0] > range[1][1]) {
        printf("\n>>maxDiffSegPts=%d  range[1][0]=%lx  range[1][1]=%lx",
                maxDiffSegPts, range[1][0], range[1][1]);
        printf("\n>>fuck\n"); exit(0);
    }


    for (dim = 0; dim < DIM; dim ++) {
        free(segPoints[dim]);
        free(segPointsInfo[dim]);
    }

    gNumTreeNode ++;
    currNode->d2s = (unsigned char) d2s;
    currNode->depth = (unsigned char) depth;
    currNode->thresh = thresh;
    currNode->child[0] = (hs_node_t *) HS_NODE_ALLOC();
    memset((void *)currNode->child[0], 0, sizeof(hs_node_t));
    /*Generate left child rule list*/
    tempRuleNumList = (unsigned int*) malloc(ruleset->num * sizeof(unsigned int)); /* need to be freed */
    pos = 0;
    for (num = 0; num < ruleset->num; num++) {
        if (ruleset->ruleList[num].range[d2s][0] <= range[0][1]
        &&  ruleset->ruleList[num].range[d2s][1] >= range[0][0]) {
            tempRuleNumList[pos] = num;
            pos++;
        }
    }
    childRuleSet = (rule_set_t *) malloc(sizeof(rule_set_t));
    childRuleSet->num = pos;
    childRuleSet->ruleList = (rule_t*) malloc( childRuleSet->num * sizeof(rule_t) );
    for (num = 0; num < childRuleSet->num; num++) {
        childRuleSet->ruleList[num] = ruleset->ruleList[tempRuleNumList[num]];
        /* in d2s dim, the search space needs to be trimmed off */
        if (childRuleSet->ruleList[num].range[d2s][0] < range[0][0])
            childRuleSet->ruleList[num].range[d2s][0] = range[0][0];
        if (childRuleSet->ruleList[num].range[d2s][1] > range[0][1])
            childRuleSet->ruleList[num].range[d2s][1] = range[0][1];
    }
    free(tempRuleNumList);

    BuildHSTree(childRuleSet, currNode->child[0], depth+1);
    release_ruleset(childRuleSet);

    /*Generate right child rule list*/
    currNode->child[1] = (hs_node_t *) HS_NODE_ALLOC();
    memset((void *)currNode->child[1], 0, sizeof(hs_node_t));
    tempRuleNumList = (unsigned int*) malloc(ruleset->num * sizeof(unsigned int)); /* need to be free */
    pos = 0;
    for (num = 0; num < ruleset->num; num++) {
        if (ruleset->ruleList[num].range[d2s][0] <= range[1][1]
        &&  ruleset->ruleList[num].range[d2s][1] >= range[1][0]) {
            tempRuleNumList[pos] = num;
            pos++;
        }
    }

    childRuleSet = (rule_set_t*) malloc(sizeof(rule_set_t));
    childRuleSet->num = pos;
    childRuleSet->ruleList = (rule_t*) malloc( childRuleSet->num * sizeof(rule_t) );
    for (num = 0; num < childRuleSet->num; num++) {
        childRuleSet->ruleList[num] = ruleset->ruleList[tempRuleNumList[num]];
        /* in d2s dim, the search space needs to be trimmed off */
        if (childRuleSet->ruleList[num].range[d2s][0] < range[1][0])
            childRuleSet->ruleList[num].range[d2s][0] = range[1][0];
        if (childRuleSet->ruleList[num].range[d2s][1] > range[1][1])
            childRuleSet->ruleList[num].range[d2s][1] = range[1][1];
    }

    free(tempRuleNumList);
    BuildHSTree(childRuleSet, currNode->child[1], depth+1);
    release_ruleset(childRuleSet);

    return  SUCCESS;
}





void ReadMACRange(uint8_t *mac, uint64_t *MACrange)
{
    uint64_t x = 0;
    uint64_t z[6] = { 0 };
    int i;
    for ( i = 0; i < 6; i++)
    {
        z[i] = mac[i];
    }
    if(z[0] == 0 && z[1] == 0 && z[2] == 0 && z[3] == 0 && z[4] == 0 && z[5] == 0)
    {
        MACrange[0] = 0;
        MACrange[1] = 0xffffffffffff;
    }
    else
    {
        x = z[0] << 40;
        x += z[1] << 32;
        x += z[2] << 24;
        x += z[3] << 16;
        x += z[4] << 8;
        x += z[5];

        MACrange[0] = x;
        MACrange[1] = x;
    }

}


void ReadIPRange(uint32_t ipnet, uint32_t ipmask, uint64_t* IPranges, uint64_t* IPrangee)
{
    /*asindmemacces IPv4 prefixes*/
    /*temporary variables to store IP range */
    unsigned int trange[4];
    unsigned int mask;
    int masklit1;
    unsigned int masklit2,masklit3;
    unsigned int ptrange[4];
    int i;

    if(ipnet == 0 && ipmask == 0)
    {
        IPranges[0] = 0;
        IPrangee[0] = 0xffffffff;
    }
    else
    {
        mask = ipmask;
        trange[0] = ipnet>>24;
        trange[1] = ipnet>>16 & 0x00FF;
        trange[2] = ipnet>>8 & 0x0000FF;
        trange[3] = ipnet & 0x000000FF;

        mask = 32 - mask;
        masklit1 = mask / 8;
        masklit2 = mask % 8;

        for(i=0;i<4;i++)
            ptrange[i] = trange[i];

        /*count the start IP */
        for(i=3;i>3-masklit1;i--)
            ptrange[i] = 0;
        if(masklit2 != 0){
            masklit3 = 1;
            masklit3 <<= masklit2;
            masklit3 -= 1;
            masklit3 = ~masklit3;
            ptrange[3-masklit1] &= masklit3;
        }
        /*store start IP */
        IPranges[0] = ptrange[0];
        IPranges[0] <<= 8;
        IPranges[0] += ptrange[1];
        IPranges[0] <<= 8;
        IPranges[0] += ptrange[2];
        IPranges[0] <<= 8;
        IPranges[0] += ptrange[3];
#ifdef DEBUGv2
        printf("%x\n", IPranges[0]);
#endif
        /*count the end IP*/
        for(i=3;i>3-masklit1;i--)
            ptrange[i] = 255;
        if(masklit2 != 0){
            masklit3 = 1;
            masklit3 <<= masklit2;
            masklit3 -= 1;
            ptrange[3-masklit1] |= masklit3;
        }
        /*store end IP*/
        IPrangee[0] = ptrange[0];
        IPrangee[0] <<= 8;
        IPrangee[0] += ptrange[1];
        IPrangee[0] <<= 8;
        IPrangee[0] += ptrange[2];
        IPrangee[0] <<= 8;
        IPrangee[0] += ptrange[3];
#ifdef DEBUGv2
        printf("%x\n", IPrangee[0]);
#endif
    }

}

void ReadPort(uint16_t sport_start, uint16_t sport_end, uint64_t* from, uint64_t* to)
{
    *from = sport_start;
    *to = sport_end;
}

void ReadProto(uint8_t proto_start, uint8_t proto_end, uint64_t* from, uint64_t* to)
{
    *from = proto_start;
    *to = proto_end;
}


int LookupHSTree(uint64_t packet[DIM], rule_set_t* ruleset,hs_node_t* root, hs_node_t **hitnode)
{
    hs_node_t*  node = root;
    while (node->child[0] != NULL)
    {
        if (packet[node->d2s] <= node->thresh)
            node = node->child[0];
        else
            node = node->child[1];
    }

    *hitnode = node;

    return  SUCCESS;
}









