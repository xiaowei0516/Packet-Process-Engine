#include "dp_cmd.h"
#include "decode-statistic.h"
#include "dp_acl.h"

void oct_send_response(cvmx_wqe_t *work, uint16_t opcode, void *data, uint32_t size)
{
    void *resp = NULL;
    rpc_ether_hdr_t *hdr;
    rpc_msg_t *rpcmsg;

    resp = (void *)cvmx_phys_to_ptr(work->packet_ptr.s.addr);

    hdr = (rpc_ether_hdr_t *)resp;

    hdr->type = ETH_P;

    rpcmsg = (rpc_msg_t *)((uint8_t *)resp + sizeof(rpc_ether_hdr_t));
    rpcmsg->opcode = opcode;
    rpcmsg->info_len = size;
    memcpy((void *)rpcmsg->info_buf, data, size);

    work->packet_ptr.s.size = sizeof(rpc_ether_hdr_t) + sizeof(rpc_msg_t) + rpcmsg->info_len;

    cvmx_wqe_set_len(work, work->packet_ptr.s.size);
    cvmx_wqe_set_port(work, 0);
    cvmx_wqe_set_grp(work, TO_LINUX_GROUP);

    cvmx_pow_work_submit(work, work->word1.tag, work->word1.tag_type, cvmx_wqe_get_qos(work), TO_LINUX_GROUP);
}

uint16_t oct_rx_command_get(cvmx_wqe_t *work)
{
    uint8_t *data;
    rpc_msg_t *rpcmsg;

    if(cvmx_wqe_get_bufs(work))
    {
        data = cvmx_phys_to_ptr(work->packet_ptr.s.addr);
        if(NULL == data)
            return COMMAND_INVALID;
    }
    else
    {
        return COMMAND_INVALID;
    }

    rpcmsg = (rpc_msg_t *)data;

    return rpcmsg->opcode;
}

void dp_show_build_time(cvmx_wqe_t *wq, void *data)
{
    char out[1024];
    uint32_t len;
    memset((void *)out, 0, sizeof(out));

    sprintf(out, "%s, %s\n", __DATE__, __TIME__);
    len = strlen(out);

    oct_send_response(wq, ((rpc_msg_t *)data)->opcode, out, len);
}

void dp_show_pkt_stat(cvmx_wqe_t *wq, void *data)
{
    char out[1024];
    uint32_t len = 0;
    int i;
    uint32_t totallen = 0;
    uint8_t *ptr;
    memset((void *)out, 0, sizeof(out));

    ptr = (uint8_t *)&out;

    len = sprintf((void *)ptr, "packet statistic:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------------------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "recv_count:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    uint64_t x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rc.recv_packet_count;
    }

    len = sprintf((void *)ptr, "recv_packet_count: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rc.recv_packet_bytes;
    }

    len = sprintf((void *)ptr, "recv_packet_bytes: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rc.recv_packet_count_sum;
    }

    len = sprintf((void *)ptr, "recv_packet_count_sum: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rc.recv_packet_bytes_sum;
    }

    len = sprintf((void *)ptr, "recv_packet_bytes_sum: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "rx_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.rx_err;
    }

    len = sprintf((void *)ptr, "rx_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.addr_err;
    }

    len = sprintf((void *)ptr, "addr_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->rxstat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "ether_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->l2stat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->l2stat.unsupport;
    }

    len = sprintf((void *)ptr, "unsupport: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->l2stat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "ipv4_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.version_err;
    }

    len = sprintf((void *)ptr, "version_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.pktlen_err;
    }

    len = sprintf((void *)ptr, "pktlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.unsupport;
    }

    len = sprintf((void *)ptr, "unsupport: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->ipv4stat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "tcp_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstat.pktlen_err;
    }

    len = sprintf((void *)ptr, "pktlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->tcpstat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "udp_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->udpstat.headerlen_err;
    }

    len = sprintf((void *)ptr, "headerlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->udpstat.pktlen_err;
    }

    len = sprintf((void *)ptr, "pktlen_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->udpstat.rx_ok;
    }

    len = sprintf((void *)ptr, "rx_ok: %ld\n", x);
    ptr += len;
    totallen += len;


    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "acl_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->aclstat.drop;
    }

    len = sprintf((void *)ptr, "drop: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->aclstat.fw;
    }

    len = sprintf((void *)ptr, "fw: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "flow_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->flowstat.getnode_err;
    }

    len = sprintf((void *)ptr, "getnode_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->flowstat.proc_ok;
    }

    len = sprintf((void *)ptr, "proc_ok: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "tx_stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.port_err;
    }

    len = sprintf((void *)ptr, "port_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.hw_send_err;
    }

    len = sprintf((void *)ptr, "hw_send_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.sw_desc_err;
    }

    len = sprintf((void *)ptr, "sw_desc_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.sw_send_err;
    }

    len = sprintf((void *)ptr, "sw_send_err: %ld\n", x);
    ptr += len;
    totallen += len;

    x = 0;
    for(i = 0; i < CPU_HW_RUNNING_MAX; i++)
    {
        x += pktstat[i]->txstat.send_over;
    }

    len = sprintf((void *)ptr, "send_over: %ld\n", x);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "\n");
    ptr += len;
    totallen += len;





    printf("total len is %d\n",totallen);

    oct_send_response(wq, ((rpc_msg_t *)data)->opcode, out, totallen);
}


void dp_show_mem_pool(cvmx_wqe_t *wq, void *data)
{
    char out[1024];
    uint32_t len = 0;
    int i;
    uint32_t totallen = 0;
    uint8_t *ptr;
    memset((void *)out, 0, sizeof(out));

    ptr = (uint8_t *)&out;

    len = sprintf((void *)ptr, "mem pool stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "small pool(%d bytes):\n", MEM_POOL_SMALL_BUFFER_SIZE);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "total slice num %d.\n", MEM_POOL_SMALL_BUFFER_NUM);
    ptr += len;
    totallen += len;

    for(i = 0; i < MEM_POOL_INTERNAL_NUM; i++)
    {
        len = sprintf((void *)ptr, "pool %d:  free num %d(%d)\n", i, mem_pool[MEM_POOL_ID_SMALL_BUFFER]->mpc.msc[i].freenum, MEM_POOL_SMALL_BUFFER_NUM/MEM_POOL_INTERNAL_NUM);
        ptr += len;
        totallen += len;
    }

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "large pool(%d bytes):\n", MEM_POOL_LARGE_BUFFER_SIZE);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "total slice num %d.\n", MEM_POOL_LARGE_BUFFER_NUM);
    ptr += len;
    totallen += len;

    for(i = 0; i < MEM_POOL_INTERNAL_NUM; i++)
    {
        len = sprintf((void *)ptr, "pool %d:  free num %d(%d)\n", i, mem_pool[MEM_POOL_ID_LARGE_BUFFER]->mpc.msc[i].freenum, MEM_POOL_SMALL_BUFFER_NUM/MEM_POOL_INTERNAL_NUM);
        ptr += len;
        totallen += len;
    }

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

#if 0
    len = sprintf((void *)ptr, "sos mem pool stat:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "----------------\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "Global pool info:\n");
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "start: %p    totalsize: %d\n", sos_mem_pool->start, sos_mem_pool->total_size);
    ptr += len;
    totallen += len;

    len = sprintf((void *)ptr, "cur_start: %p    cur_size: %d\n", sos_mem_pool->current_start, sos_mem_pool->current_size);
    ptr += len;
    totallen += len;
#endif
    printf("total len is %d\n",totallen);

    oct_send_response(wq, ((rpc_msg_t *)data)->opcode, out, totallen);

}

void dp_acl_rule_commit(cvmx_wqe_t *wq, void *data)
{
    char out[1024];
    uint32_t len, totallen = 0;
    uint32_t ret;
    memset((void *)out, 0, sizeof(out));
    uint8_t *ptr;

    ptr = (uint8_t *)&out;

    cvmx_rwlock_wp_write_lock(&g_acltree.rwlock_hs);

    DP_Acl_Rule_Clean(&(g_acltree.TreeSet),&(g_acltree.TreeNode));

    if(rule_list->rule_entry_free == RULE_ENTRY_MAX)  // rule empty, no need to load
    {
        rule_list->build_status = RULE_BUILD_COMMIT;
        cvmx_rwlock_wp_write_unlock(&g_acltree.rwlock_hs);

        len = sprintf((void *)ptr, "no rule exist\n");
        ptr += len;
        totallen += len;
    }
    else
    {

        ret = DP_Acl_Load_Rule(rule_list,&(g_acltree.TreeSet),&(g_acltree.TreeNode));

        rule_list->build_status = RULE_BUILD_COMMIT;
        cvmx_rwlock_wp_write_unlock(&g_acltree.rwlock_hs);

        if(SEC_OK != ret)
        {
            len = sprintf((void *)ptr, "commit failed\n");
            ptr += len;
            totallen += len;
        }
        else
        {
            printf("\nwrst case tree depth: %d\n",gWstDepth);
            if(gChildCount)
                printf("\naverage tree depth: %f\n",(float)gAvgDepth/gChildCount);
            printf("\nnumber of tree nodes: %d\n",gNumTreeNode);
            printf("\nnumber of leaf nodes: %d\n",gNumLeafNode);
            printf("\ntotal mem: %d(KB)\n",((gNumTreeNode*8)>>10) + ((gNumLeafNode*8)>>10));

            printf("\nfinished\n");

            len = sprintf((void *)ptr, "commit ok\n");
            ptr += len;
            totallen += len;
        }
    }

    printf("total len is %d\n",totallen);

    oct_send_response(wq, ((rpc_msg_t *)data)->opcode, out, totallen);
}


void dp_acl_def_act_set(cvmx_wqe_t *wq, void *data)
{
    char out[1024];
    uint32_t len, totallen = 0;

    dp_acl_action_default = rule_list->rule_def_act;

    memset((void *)out, 0, sizeof(out));
    uint8_t *ptr;

    ptr = (uint8_t *)&out;

    len = sprintf((void *)ptr, "ok\n");
    ptr += len;
    totallen += len;

    oct_send_response(wq, ((rpc_msg_t *)data)->opcode, out, totallen);
}

void oct_rx_process_command(cvmx_wqe_t *wq)
{
    uint16_t opcode = oct_rx_command_get(wq);
    void *data;
    if(opcode == COMMAND_INVALID)
    {
        oct_packet_free(wq, wqe_pool);
        return;
    }

    data = cvmx_phys_to_ptr(wq->packet_ptr.s.addr);

    switch(opcode)
    {
        case COMMAND_SHOW_BUILD_TIME:
        {
            dp_show_build_time(wq, data);
            break;
        }
        case COMMAND_SHOW_PKT_STAT:
        {
            dp_show_pkt_stat(wq, data);
            break;
        }
        case COMMAND_SHOW_MEM_POOL:
        {
            dp_show_mem_pool(wq, data);
            break;
        }
        case COMMAND_ACL_RULE_COMMIT:
        {
            dp_acl_rule_commit(wq, data);
            break;
        }
        case COMMAND_ACL_DEF_ACT_SET:
        {
            dp_acl_def_act_set(wq, data);
            break;
        }
        default:
        {
            printf("unsupport command\n");
            break;
        }
    }
}
