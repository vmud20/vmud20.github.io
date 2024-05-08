
























static DEFINE_RWLOCK(sctp_lock);



static const char *sctp_conntrack_names[] = {
	"NONE", "CLOSED", "COOKIE_WAIT", "COOKIE_ECHOED", "ESTABLISHED", "SHUTDOWN_SENT", "SHUTDOWN_RECD", "SHUTDOWN_ACK_SENT", };













static unsigned int nf_ct_sctp_timeout_closed            =  10 SECS;
static unsigned int nf_ct_sctp_timeout_cookie_wait       =   3 SECS;
static unsigned int nf_ct_sctp_timeout_cookie_echoed     =   3 SECS;
static unsigned int nf_ct_sctp_timeout_established       =   5 DAYS;
static unsigned int nf_ct_sctp_timeout_shutdown_sent     = 300 SECS / 1000;
static unsigned int nf_ct_sctp_timeout_shutdown_recd     = 300 SECS / 1000;
static unsigned int nf_ct_sctp_timeout_shutdown_ack_sent =   3 SECS;

static unsigned int * sctp_timeouts[] = { NULL, &nf_ct_sctp_timeout_closed, &nf_ct_sctp_timeout_cookie_wait, &nf_ct_sctp_timeout_cookie_echoed, &nf_ct_sctp_timeout_established, &nf_ct_sctp_timeout_shutdown_sent, &nf_ct_sctp_timeout_shutdown_recd, &nf_ct_sctp_timeout_shutdown_ack_sent };
























static enum sctp_conntrack sctp_conntracks[2][9][SCTP_CONNTRACK_MAX] = {
	{


 {sCW, sCW, sCW, sCE, sES, sSS, sSR, sSA}, {sCL, sCL, sCW, sCE, sES, sSS, sSR, sSA}, {sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL}, {sCL, sCL, sCW, sCE, sSS, sSS, sSR, sSA}, {sSA, sCL, sCW, sCE, sES, sSA, sSA, sSA}, {sCL, sCL, sCW, sCE, sES, sSS, sSR, sSA}, {sCL, sCL, sCE, sCE, sES, sSS, sSR, sSA}, {sCL, sCL, sCW, sCE, sES, sSS, sSR, sSA}, {sCL, sCL, sCW, sCE, sES, sSS, sSR, sCL}







	}, {


 {sIV, sCL, sCW, sCE, sES, sSS, sSR, sSA}, {sIV, sCL, sCW, sCE, sES, sSS, sSR, sSA}, {sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL}, {sIV, sCL, sCW, sCE, sSR, sSS, sSR, sSA}, {sIV, sCL, sCW, sCE, sES, sSA, sSA, sSA}, {sIV, sCL, sCW, sCL, sES, sSS, sSR, sSA}, {sIV, sCL, sCW, sCE, sES, sSS, sSR, sSA}, {sIV, sCL, sCW, sES, sES, sSS, sSR, sSA}, {sIV, sCL, sCW, sCE, sES, sSS, sSR, sCL}







	}
};

static int sctp_pkt_to_tuple(const struct sk_buff *skb, unsigned int dataoff, struct nf_conntrack_tuple *tuple)

{
	sctp_sctphdr_t _hdr, *hp;

	DEBUGP(__FUNCTION__);
	DEBUGP("\n");

	
	hp = skb_header_pointer(skb, dataoff, 8, &_hdr);
	if (hp == NULL)
		return 0;

	tuple->src.u.sctp.port = hp->source;
	tuple->dst.u.sctp.port = hp->dest;
	return 1;
}

static int sctp_invert_tuple(struct nf_conntrack_tuple *tuple, const struct nf_conntrack_tuple *orig)
{
	DEBUGP(__FUNCTION__);
	DEBUGP("\n");

	tuple->src.u.sctp.port = orig->dst.u.sctp.port;
	tuple->dst.u.sctp.port = orig->src.u.sctp.port;
	return 1;
}


static int sctp_print_tuple(struct seq_file *s, const struct nf_conntrack_tuple *tuple)
{
	DEBUGP(__FUNCTION__);
	DEBUGP("\n");

	return seq_printf(s, "sport=%hu dport=%hu ", ntohs(tuple->src.u.sctp.port), ntohs(tuple->dst.u.sctp.port));

}


static int sctp_print_conntrack(struct seq_file *s, const struct nf_conn *conntrack)
{
	enum sctp_conntrack state;

	DEBUGP(__FUNCTION__);
	DEBUGP("\n");

	read_lock_bh(&sctp_lock);
	state = conntrack->proto.sctp.state;
	read_unlock_bh(&sctp_lock);

	return seq_printf(s, "%s ", sctp_conntrack_names[state]);
}







static int do_basic_checks(struct nf_conn *conntrack, const struct sk_buff *skb, unsigned int dataoff, char *map)


{
	u_int32_t offset, count;
	sctp_chunkhdr_t _sch, *sch;
	int flag;

	DEBUGP(__FUNCTION__);
	DEBUGP("\n");

	flag = 0;

	for_each_sctp_chunk (skb, sch, _sch, offset, dataoff, count) {
		DEBUGP("Chunk Num: %d  Type: %d\n", count, sch->type);

		if (sch->type == SCTP_CID_INIT  || sch->type == SCTP_CID_INIT_ACK || sch->type == SCTP_CID_SHUTDOWN_COMPLETE) {

			flag = 1;
		}

		
		if ((sch->type == SCTP_CID_COOKIE_ACK  || sch->type == SCTP_CID_COOKIE_ECHO || flag)

		     && count !=0 ) {
			DEBUGP("Basic checks failed\n");
			return 1;
		}

		if (map) {
			set_bit(sch->type, (void *)map);
		}
	}

	DEBUGP("Basic checks passed\n");
	return 0;
}

static int new_state(enum ip_conntrack_dir dir, enum sctp_conntrack cur_state, int chunk_type)

{
	int i;

	DEBUGP(__FUNCTION__);
	DEBUGP("\n");

	DEBUGP("Chunk type: %d\n", chunk_type);

	switch (chunk_type) {
		case SCTP_CID_INIT: 
			DEBUGP("SCTP_CID_INIT\n");
			i = 0; break;
		case SCTP_CID_INIT_ACK: 
			DEBUGP("SCTP_CID_INIT_ACK\n");
			i = 1; break;
		case SCTP_CID_ABORT: 
			DEBUGP("SCTP_CID_ABORT\n");
			i = 2; break;
		case SCTP_CID_SHUTDOWN: 
			DEBUGP("SCTP_CID_SHUTDOWN\n");
			i = 3; break;
		case SCTP_CID_SHUTDOWN_ACK: 
			DEBUGP("SCTP_CID_SHUTDOWN_ACK\n");
			i = 4; break;
		case SCTP_CID_ERROR: 
			DEBUGP("SCTP_CID_ERROR\n");
			i = 5; break;
		case SCTP_CID_COOKIE_ECHO: 
			DEBUGP("SCTP_CID_COOKIE_ECHO\n");
			i = 6; break;
		case SCTP_CID_COOKIE_ACK: 
			DEBUGP("SCTP_CID_COOKIE_ACK\n");
			i = 7; break;
		case SCTP_CID_SHUTDOWN_COMPLETE: 
			DEBUGP("SCTP_CID_SHUTDOWN_COMPLETE\n");
			i = 8; break;
		default:
			
			DEBUGP("Unknown chunk type, Will stay in %s\n",  sctp_conntrack_names[cur_state]);
			return cur_state;
	}

	DEBUGP("dir: %d   cur_state: %s  chunk_type: %d  new_state: %s\n",  dir, sctp_conntrack_names[cur_state], chunk_type, sctp_conntrack_names[sctp_conntracks[dir][i][cur_state]]);


	return sctp_conntracks[dir][i][cur_state];
}


static int sctp_packet(struct nf_conn *conntrack, const struct sk_buff *skb, unsigned int dataoff, enum ip_conntrack_info ctinfo, int pf, unsigned int hooknum)




{
	enum sctp_conntrack newconntrack, oldsctpstate;
	sctp_sctphdr_t _sctph, *sh;
	sctp_chunkhdr_t _sch, *sch;
	u_int32_t offset, count;
	char map[256 / sizeof (char)] = {0};

	DEBUGP(__FUNCTION__);
	DEBUGP("\n");

	sh = skb_header_pointer(skb, dataoff, sizeof(_sctph), &_sctph);
	if (sh == NULL)
		return -1;

	if (do_basic_checks(conntrack, skb, dataoff, map) != 0)
		return -1;

	
	if (!test_bit(SCTP_CID_INIT, (void *)map)
		&& !test_bit(SCTP_CID_SHUTDOWN_COMPLETE, (void *)map)
		&& !test_bit(SCTP_CID_COOKIE_ECHO, (void *)map)
		&& !test_bit(SCTP_CID_ABORT, (void *)map)
		&& !test_bit(SCTP_CID_SHUTDOWN_ACK, (void *)map)
		&& (sh->vtag != conntrack->proto.sctp.vtag[CTINFO2DIR(ctinfo)])) {
		DEBUGP("Verification tag check failed\n");
		return -1;
	}

	oldsctpstate = newconntrack = SCTP_CONNTRACK_MAX;
	for_each_sctp_chunk (skb, sch, _sch, offset, dataoff, count) {
		write_lock_bh(&sctp_lock);

		
		if (sch->type == SCTP_CID_INIT) {
			
			if (sh->vtag != 0) {
				write_unlock_bh(&sctp_lock);
				return -1;
			}
		} else if (sch->type == SCTP_CID_ABORT) {
			
			if (!(sh->vtag == conntrack->proto.sctp.vtag[CTINFO2DIR(ctinfo)])
				&& !(sh->vtag == conntrack->proto.sctp.vtag [1 - CTINFO2DIR(ctinfo)])) {
				write_unlock_bh(&sctp_lock);
				return -1;
			}
		} else if (sch->type == SCTP_CID_SHUTDOWN_COMPLETE) {
			
			if (!(sh->vtag == conntrack->proto.sctp.vtag[CTINFO2DIR(ctinfo)])
				&& !(sh->vtag == conntrack->proto.sctp.vtag [1 - CTINFO2DIR(ctinfo)] && (sch->flags & 1))) {

				write_unlock_bh(&sctp_lock);
				return -1;
			}
		} else if (sch->type == SCTP_CID_COOKIE_ECHO) {
			
			if (!(sh->vtag == conntrack->proto.sctp.vtag[CTINFO2DIR(ctinfo)])) {
				write_unlock_bh(&sctp_lock);
				return -1;
			}
		}

		oldsctpstate = conntrack->proto.sctp.state;
		newconntrack = new_state(CTINFO2DIR(ctinfo), oldsctpstate, sch->type);

		
		if (newconntrack == SCTP_CONNTRACK_MAX) {
			DEBUGP("nf_conntrack_sctp: Invalid dir=%i ctype=%u conntrack=%u\n", CTINFO2DIR(ctinfo), sch->type, oldsctpstate);
			write_unlock_bh(&sctp_lock);
			return -1;
		}

		
		if (sch->type == SCTP_CID_INIT  || sch->type == SCTP_CID_INIT_ACK) {
			sctp_inithdr_t _inithdr, *ih;

			ih = skb_header_pointer(skb, offset + sizeof(sctp_chunkhdr_t), sizeof(_inithdr), &_inithdr);
			if (ih == NULL) {
					write_unlock_bh(&sctp_lock);
					return -1;
			}
			DEBUGP("Setting vtag %x for dir %d\n",  ih->init_tag, !CTINFO2DIR(ctinfo));
			conntrack->proto.sctp.vtag[!CTINFO2DIR(ctinfo)] = ih->init_tag;
		}

		conntrack->proto.sctp.state = newconntrack;
		if (oldsctpstate != newconntrack)
			nf_conntrack_event_cache(IPCT_PROTOINFO, skb);
		write_unlock_bh(&sctp_lock);
	}

	nf_ct_refresh_acct(conntrack, ctinfo, skb, *sctp_timeouts[newconntrack]);

	if (oldsctpstate == SCTP_CONNTRACK_COOKIE_ECHOED && CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY && newconntrack == SCTP_CONNTRACK_ESTABLISHED) {

		DEBUGP("Setting assured bit\n");
		set_bit(IPS_ASSURED_BIT, &conntrack->status);
		nf_conntrack_event_cache(IPCT_STATUS, skb);
	}

	return NF_ACCEPT;
}


static int sctp_new(struct nf_conn *conntrack, const struct sk_buff *skb, unsigned int dataoff)
{
	enum sctp_conntrack newconntrack;
	sctp_sctphdr_t _sctph, *sh;
	sctp_chunkhdr_t _sch, *sch;
	u_int32_t offset, count;
	char map[256 / sizeof (char)] = {0};

	DEBUGP(__FUNCTION__);
	DEBUGP("\n");

	sh = skb_header_pointer(skb, dataoff, sizeof(_sctph), &_sctph);
	if (sh == NULL)
		return 0;

	if (do_basic_checks(conntrack, skb, dataoff, map) != 0)
		return 0;

	
	if ((test_bit (SCTP_CID_ABORT, (void *)map))
		|| (test_bit (SCTP_CID_SHUTDOWN_COMPLETE, (void *)map))
		|| (test_bit (SCTP_CID_COOKIE_ACK, (void *)map))) {
		return 0;
	}

	newconntrack = SCTP_CONNTRACK_MAX;
	for_each_sctp_chunk (skb, sch, _sch, offset, dataoff, count) {
		
		newconntrack = new_state(IP_CT_DIR_ORIGINAL,  SCTP_CONNTRACK_NONE, sch->type);

		
		if (newconntrack == SCTP_CONNTRACK_MAX) {
			DEBUGP("nf_conntrack_sctp: invalid new deleting.\n");
			return 0;
		}

		
		if (sch->type == SCTP_CID_INIT) {
			if (sh->vtag == 0) {
				sctp_inithdr_t _inithdr, *ih;

				ih = skb_header_pointer(skb, offset + sizeof(sctp_chunkhdr_t), sizeof(_inithdr), &_inithdr);
				if (ih == NULL)
					return 0;

				DEBUGP("Setting vtag %x for new conn\n",  ih->init_tag);

				conntrack->proto.sctp.vtag[IP_CT_DIR_REPLY] =  ih->init_tag;
			} else {
				
				return 0;
			}
		}
		
		else {
			DEBUGP("Setting vtag %x for new conn OOTB\n",  sh->vtag);
			conntrack->proto.sctp.vtag[IP_CT_DIR_REPLY] = sh->vtag;
		}

		conntrack->proto.sctp.state = newconntrack;
	}

	return 1;
}

struct nf_conntrack_protocol nf_conntrack_protocol_sctp4 = { 
	.l3proto	 = PF_INET, .proto 		 = IPPROTO_SCTP, .name 		 = "sctp", .pkt_to_tuple 	 = sctp_pkt_to_tuple, .invert_tuple 	 = sctp_invert_tuple, .print_tuple 	 = sctp_print_tuple, .print_conntrack = sctp_print_conntrack, .packet 	 = sctp_packet, .new 		 = sctp_new, .destroy 	 = NULL, .me 		 = THIS_MODULE };











struct nf_conntrack_protocol nf_conntrack_protocol_sctp6 = { 
	.l3proto	 = PF_INET6, .proto 		 = IPPROTO_SCTP, .name 		 = "sctp", .pkt_to_tuple 	 = sctp_pkt_to_tuple, .invert_tuple 	 = sctp_invert_tuple, .print_tuple 	 = sctp_print_tuple, .print_conntrack = sctp_print_conntrack, .packet 	 = sctp_packet, .new 		 = sctp_new, .destroy 	 = NULL, .me 		 = THIS_MODULE };












static ctl_table nf_ct_sysctl_table[] = {
	{
		.ctl_name	= NET_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED, .procname	= "nf_conntrack_sctp_timeout_closed", .data		= &nf_ct_sctp_timeout_closed, .maxlen		= sizeof(unsigned int), .mode		= 0644, .proc_handler	= &proc_dointvec_jiffies, }, {






		.ctl_name	= NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT, .procname	= "nf_conntrack_sctp_timeout_cookie_wait", .data		= &nf_ct_sctp_timeout_cookie_wait, .maxlen		= sizeof(unsigned int), .mode		= 0644, .proc_handler	= &proc_dointvec_jiffies, }, {






		.ctl_name	= NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED, .procname	= "nf_conntrack_sctp_timeout_cookie_echoed", .data		= &nf_ct_sctp_timeout_cookie_echoed, .maxlen		= sizeof(unsigned int), .mode		= 0644, .proc_handler	= &proc_dointvec_jiffies, }, {






		.ctl_name	= NET_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED, .procname	= "nf_conntrack_sctp_timeout_established", .data		= &nf_ct_sctp_timeout_established, .maxlen		= sizeof(unsigned int), .mode		= 0644, .proc_handler	= &proc_dointvec_jiffies, }, {






		.ctl_name	= NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT, .procname	= "nf_conntrack_sctp_timeout_shutdown_sent", .data		= &nf_ct_sctp_timeout_shutdown_sent, .maxlen		= sizeof(unsigned int), .mode		= 0644, .proc_handler	= &proc_dointvec_jiffies, }, {






		.ctl_name	= NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD, .procname	= "nf_conntrack_sctp_timeout_shutdown_recd", .data		= &nf_ct_sctp_timeout_shutdown_recd, .maxlen		= sizeof(unsigned int), .mode		= 0644, .proc_handler	= &proc_dointvec_jiffies, }, {






		.ctl_name	= NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT, .procname	= "nf_conntrack_sctp_timeout_shutdown_ack_sent", .data		= &nf_ct_sctp_timeout_shutdown_ack_sent, .maxlen		= sizeof(unsigned int), .mode		= 0644, .proc_handler	= &proc_dointvec_jiffies, }, { .ctl_name = 0 }






};

static ctl_table nf_ct_netfilter_table[] = {
	{
		.ctl_name	= NET_NETFILTER, .procname	= "netfilter", .mode		= 0555, .child		= nf_ct_sysctl_table, }, { .ctl_name = 0 }




};

static ctl_table nf_ct_net_table[] = {
	{
		.ctl_name	= CTL_NET, .procname	= "net", .mode		= 0555, .child		= nf_ct_netfilter_table, }, { .ctl_name = 0 }




};

static struct ctl_table_header *nf_ct_sysctl_header;


int __init nf_conntrack_proto_sctp_init(void)
{
	int ret;

	ret = nf_conntrack_protocol_register(&nf_conntrack_protocol_sctp4);
	if (ret) {
		printk("nf_conntrack_proto_sctp4: protocol register failed\n");
		goto out;
	}
	ret = nf_conntrack_protocol_register(&nf_conntrack_protocol_sctp6);
	if (ret) {
		printk("nf_conntrack_proto_sctp6: protocol register failed\n");
		goto cleanup_sctp4;
	}


	nf_ct_sysctl_header = register_sysctl_table(nf_ct_net_table, 0);
	if (nf_ct_sysctl_header == NULL) {
		printk("nf_conntrack_proto_sctp: can't register to sysctl.\n");
		goto cleanup;
	}


	return ret;


 cleanup:
	nf_conntrack_protocol_unregister(&nf_conntrack_protocol_sctp6);

 cleanup_sctp4:
	nf_conntrack_protocol_unregister(&nf_conntrack_protocol_sctp4);
 out:
	DEBUGP("SCTP conntrack module loading %s\n",  ret ? "failed": "succeeded");
	return ret;
}

void __exit nf_conntrack_proto_sctp_fini(void)
{
	nf_conntrack_protocol_unregister(&nf_conntrack_protocol_sctp6);
	nf_conntrack_protocol_unregister(&nf_conntrack_protocol_sctp4);

 	unregister_sysctl_table(nf_ct_sysctl_header);

	DEBUGP("SCTP conntrack module unloaded\n");
}

module_init(nf_conntrack_proto_sctp_init);
module_exit(nf_conntrack_proto_sctp_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kiran Kumar Immidi");
MODULE_DESCRIPTION("Netfilter connection tracking protocol helper for SCTP");
