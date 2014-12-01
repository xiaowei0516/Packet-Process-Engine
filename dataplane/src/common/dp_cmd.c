#include "dp_cmd.h"

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
	}
}