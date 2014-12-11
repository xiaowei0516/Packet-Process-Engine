#ifndef __SEC_DEBUG_H__
#define __SEC_DEBUG_H__




//#define SEC_RXTX_DEBUG
#define SEC_DECODE_DEBUG
#define SEC_ETHERNET_DEBUG
#define SEC_IPV4_DEBUG
#define SEC_TCP_DEBUG
#define SEC_UDP_DEBUG
#define SEC_FLOW_DEBUG
#define SEC_L7_DEBUG
#define SEC_DEFRAG_DEBUG



#define DEBUG_PRINT

extern int debugprint;

#ifdef DEBUG_PRINT
#define LOG(str...)   \
{                     \
    if(debugprint)    \
    {                 \
        printf(str);  \
    }                 \
}
#else
#define LOG(str...)
#endif




#endif
