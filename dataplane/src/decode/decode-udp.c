#include <mbuf.h>
#include <sec-util.h>
#include <sec-common.h>
#include "decode-ipv4.h"
#include "decode-udp.h"
#include "decode-statistic.h"
#include "decode-defrag.h"
#include <dp_acl.h>


extern void FlowHandlePacket(mbuf_t *m);

static int DecodeUDPPacket(mbuf_t *mbuf, uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < UDP_HEADER_LEN)) {
        STAT_UDP_HEADER_ERR;
        return DECODE_DROP;
    }

    mbuf->transport_header= (void *)pkt;

    if (unlikely(len < UDP_GET_LEN(mbuf))) {
        STAT_UDP_LEN_ERR;
        return DECODE_DROP;
    }

    if (unlikely(len != UDP_GET_LEN(mbuf))) {
        STAT_UDP_LEN_ERR;
        return DECODE_DROP;
    }

    mbuf->sport = UDP_GET_SRC_PORT(mbuf);
    mbuf->dport = UDP_GET_DST_PORT(mbuf);

#ifdef SEC_UDP_DEBUG
    LOGDBG("src port is %d\n", mbuf->sport);
    LOGDBG("dst port is %d\n", mbuf->dport);
#endif

    mbuf->payload = (void *)(pkt + UDP_HEADER_LEN);
    mbuf->payload_len = len - UDP_HEADER_LEN;

    return DECODE_OK;
}



/*
  *  @mbuf
  *  @pkt:    start of transport header
  *  @len:    length of transport packet
  */
int DecodeUDP(mbuf_t *mbuf, uint8_t *pkt, uint16_t len)
{
#ifdef SEC_UDP_DEBUG
    LOGDBG("=========>enter DecodeUDP\n");
#endif

    if (unlikely(DECODE_OK != DecodeUDPPacket(mbuf, pkt, len)))
    {
        return DECODE_DROP;
    }

    STAT_UDP_RECV_OK;

    if(ACL_RULE_ACTION_DROP == DP_Acl_Lookup(mbuf))
    {
        STAT_ACL_DROP;
        PACKET_DESTROY_ALL(mbuf);
        return DECODE_OK;
    }

    STAT_ACL_FW;

    FlowHandlePacket(mbuf);

    return DECODE_OK;
}

