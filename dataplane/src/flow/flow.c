/********************************************************************************
 *
 *        Copyright (C) 2014-2015  Beijing winicssec Technology
 *        All rights reserved
 *
 *        filename :       flow.c
 *        description :    flow manage
 *
 *        created by  luoye  at  2014-11-18
 *
 ********************************************************************************/

#include <mbuf.h>
#include <decode.h>

#include <sec-common.h>
#include <oct-init.h>
#include "flow.h"
#include "tluhash.h"
#include "decode-statistic.h"



extern void l7_deliver(mbuf_t *m);


CVMX_SHARED uint64_t new_flow[CPU_HW_RUNNING_MAX] = {0, 0, 0, 0};
CVMX_SHARED uint64_t del_flow[CPU_HW_RUNNING_MAX] = {0, 0, 0, 0};


flow_table_info_t *flow_table;

static inline flow_item_t *flow_item_alloc()
{
    Mem_Slice_Ctrl_B *mscb;
    void *buf = mem_pool_fpa_slice_alloc(FPA_POOL_ID_FLOW_NODE);
    if(NULL == buf)
        return NULL;

    mscb = (Mem_Slice_Ctrl_B *)buf;
    mscb->magic = MEM_POOL_MAGIC_NUM;
    mscb->pool_id = FPA_POOL_ID_FLOW_NODE;

    return (flow_item_t *)((uint8_t *)buf + sizeof(Mem_Slice_Ctrl_B));
}

static inline void flow_item_free(flow_item_t *f)
{
    Mem_Slice_Ctrl_B *mscb = (Mem_Slice_Ctrl_B *)((uint8_t *)f - sizeof(Mem_Slice_Ctrl_B));
    if(MEM_POOL_MAGIC_NUM != mscb->magic)
    {
        LOGDBG("magic num err %d\n", mscb->magic);
        return;
    }
    if(FPA_POOL_ID_FLOW_NODE != mscb->pool_id)
    {
        LOGDBG("pool id err %d\n", mscb->pool_id);
        return;
    }

    mem_pool_fpa_slice_free((void *)mscb, FPA_POOL_ID_FLOW_NODE);

    return;
}


static void FlowInsert(flow_bucket_t *fb, flow_item_t *fi)
{
    hlist_add_head(&fi->list, &fb->hash);
}



static inline uint32_t flowhashfn(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t prot)
{
    return flow_hashfn(prot, saddr, daddr, sport, dport) & FLOW_BUCKET_MASK;
}

static uint32_t FlowMatch(flow_item_t *f, mbuf_t *mbuf)
{
    return ((f->ipv4.sip   == mbuf->ipv4.sip
            && f->ipv4.dip == mbuf->ipv4.dip
            && f->sport    == mbuf->sport
            && f->dport    == mbuf->dport
            && f->protocol == mbuf->proto)
        || (f->ipv4.sip    == mbuf->ipv4.dip
            && f->ipv4.dip == mbuf->ipv4.sip
            && f->sport    == mbuf->dport
            && f->dport    == mbuf->sport
            && f->protocol == mbuf->proto));
}


static inline flow_item_t *FlowFind(flow_bucket_t *fb, mbuf_t *mbuf, unsigned int hash)
{
    flow_item_t *f;
    struct hlist_node *n;

#ifdef SEC_FLOW_DEBUG
    LOGDBG("============>enter FlowFind\n");
#endif

    hlist_for_each_entry(f, n, &fb->hash, list)
    {
        if(FlowMatch(f, mbuf))
        {
        #ifdef SEC_FLOW_DEBUG
            LOGDBG("FlowMatch is ok\n");
        #endif
            FLOW_UPDATE_TIMESTAMP(f);
            return f;
        }
    }
#ifdef SEC_FLOW_DEBUG
    LOGDBG("FlowMatch is fail\n");
#endif
    return NULL;
}

flow_item_t *FlowAdd(flow_bucket_t *fb, unsigned int hash, mbuf_t *mbuf)
{
#ifdef SEC_FLOW_DEBUG
    LOGDBG("==========>enter FlowAdd\n");
#endif
    flow_item_t *newf = flow_item_alloc();
    if(NULL == newf)
    {
        return NULL;
    }

    memset((void *)newf, 0, FLOW_ITEM_SIZE);

    /*TODO: init flow node with necessary info*/
    newf->ipv4.sip = mbuf->ipv4.sip;
    newf->ipv4.dip = mbuf->ipv4.dip;
    newf->sport    = mbuf->sport;
    newf->dport    = mbuf->dport;
    newf->protocol = mbuf->proto;
    FLOW_UPDATE_TIMESTAMP(newf);

    FlowInsert(fb, newf);
    new_flow[local_cpu_id]++;
    return newf;

}



/*update flow node info*/
static inline void FlowUpdate(flow_item_t *f, mbuf_t *m)
{

    if(m->sport == f->sport)
    {
        f->pktcnts2d++;
        f->bytecnts2d += m->pkt_totallen;
    }
    else
    {
        f->pktcntd2s++;
        f->bytecntd2s += m->pkt_totallen;
    }

    return;
}


flow_item_t *FlowGetFlowFromHash(mbuf_t *mbuf)
{
    unsigned int hash;
    flow_item_t * flow;
    flow_bucket_t *base;
    flow_bucket_t *fb;

    hash = flowhashfn(mbuf->ipv4.sip, mbuf->ipv4.dip, mbuf->sport, mbuf->dport, mbuf->proto);

    base = (flow_bucket_t *)flow_table->bucket_base_ptr;
    fb = &base[hash];

#ifdef SEC_FLOW_DEBUG
    LOGDBG("hash value is %d\n", hash);
#endif

    flow = FlowFind(fb, mbuf, hash);
    if(NULL != flow)    /*find and return*/
    {
        return flow;
    }
    else                /*not find, create a new node and insert it*/
    {
        return FlowAdd(fb, hash, mbuf);
    }
}


void FlowHandlePacket(mbuf_t *m)
{

#ifdef SEC_FLOW_DEBUG
    LOGDBG("=========>enter FlowHandlePacket\n");
#endif

    flow_item_t *f;

    f = FlowGetFlowFromHash(m);  /*return a locked flow item*/
    if(NULL == f)
    {
        /*flow failed, destroy packet*/
        PACKET_DESTROY_ALL(m);
        STAT_FLOW_GETNODE_ERR;
        return;
    }

    STAT_FLOW_PROC_OK;

    /*TODO:  update info in the flow*/
    FlowUpdate(f, m);

    m->flow = (void *)f;
    m->flags |= PKT_HAS_FLOW;

    if(FLOW_ACTION_DROP == f->action)
    {
        PACKET_DESTROY_ALL(m);
        return;
    }

    l7_deliver(m);

    return;
}


uint32_t FlowTimeOut(flow_item_t *f, uint64_t current_cycle)
{
    if(cvmx_atomic_get32(&f->use_cnt) > 0)
    {
        return 0;
    }

    if((current_cycle > f->cycle) && ((current_cycle - f->cycle) > FLOW_MAX_TIMEOUT))
    {
        return 1;
    }

    return 0;
}


void FlowAgeTimeoutCB(Oct_Timer_Threat *o, void *param)
{
    int i;
    uint64_t current_cycle;

    flow_bucket_t *base;
    flow_bucket_t *fb;
    flow_item_t *f;
    flow_item_t *tf;
    struct hlist_node *n;
    struct hlist_node *t;
    struct hlist_head timeout;

    base = (flow_bucket_t *)flow_table->bucket_base_ptr;

    current_cycle = cvmx_get_cycle();

    for(i = 0; i < FLOW_BUCKET_NUM; i++)
    {
        INIT_HLIST_HEAD(&timeout);

        fb = &base[i];

        hlist_for_each_entry_safe(f, t, n, &fb->hash, list)
        {
            if(FlowTimeOut(f, current_cycle))
            {
                hlist_del(&f->list);
            #ifdef SEC_FLOW_DEBUG
                LOGDBG("delete one flow node 0x%p\n", f);
            #endif
                del_flow[local_cpu_id]++;
                hlist_add_head(&f->list, &timeout);
            }
        }

        hlist_for_each_entry_safe(tf, t, n, &timeout, list)
        {
            hlist_del(&tf->list);
            /*TODO: session ageing do something*/
            flow_item_free(tf);
        }

    }

    return;
}



int FlowInit(void)
{
    int i = 0;

    flow_bucket_t *base = NULL;
    char buf[10] = { 0 };

    flow_item_size_judge();

    sprintf(buf, "Flow_Hash_Table_%d", local_cpu_id);

    flow_table = (flow_table_info_t *)cvmx_bootmem_alloc_named((sizeof(flow_table_info_t) + FLOW_BUCKET_NUM * FLOW_BUCKET_SIZE), CACHE_LINE_SIZE, buf);
    if(NULL == flow_table)
    {
        LOGDBG("flow init: no memory\n");
        return SEC_NO;
    }

    flow_table->bucket_num = FLOW_BUCKET_NUM;
    flow_table->bucket_size = FLOW_BUCKET_SIZE;

    flow_table->item_num = FLOW_ITEM_NUM;
    flow_table->item_size = FLOW_ITEM_SIZE;

    flow_table->bucket_base_ptr = (void *)((uint8_t *)flow_table + sizeof(flow_table_info_t));


    base = (flow_bucket_t *)flow_table->bucket_base_ptr;

    for(i = 0; i < FLOW_BUCKET_NUM; i++)
    {
        INIT_HLIST_HEAD(&base[i].hash);
    }

    if(OCT_Timer_Create(0xFFFFFF, 0, 2, local_cpu_id, FlowAgeTimeoutCB, NULL, 0, 1000))/*1s*/
    {
        LOGDBG("timer create fail\n");
        return SEC_NO;
    }

    LOGDBG("flow age timer create ok\n");

    return SEC_OK;
}




