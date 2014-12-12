#ifndef __SEC_DEBUG_H__
#define __SEC_DEBUG_H__




#define SEC_RX_DEBUG
//#define SEC_PACKET_DUMP
#define SEC_DECODE_DEBUG
#define SEC_ETHERNET_DEBUG
#define SEC_IPV4_DEBUG
#define SEC_TCP_DEBUG
#define SEC_UDP_DEBUG
#define SEC_FLOW_DEBUG
#define SEC_L7_DEBUG
#define SEC_DEFRAG_DEBUG

#define SEC_ACL_DEBUG


#define DEBUG_PRINT

extern int debugprint;

#ifdef DEBUG_PRINT
#define LOGDBG(str...)   \
{                     \
    if(debugprint)    \
    {                 \
        printf(str);  \
    }                 \
}
#else
#define LOGDBG(str...)
#endif




#endif
