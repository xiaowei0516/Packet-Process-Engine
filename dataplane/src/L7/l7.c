#include <mbuf.h>
#include <oct-rxtx.h>
#include <sec-debug.h>
void l7_deliver(mbuf_t *m)
{
#ifdef SEC_L7_DEBUG
    LOGDBG("===============>l7 enter\n");
#endif

    oct_tx_process_mbuf(m);

    return;
}

