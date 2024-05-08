


__FBSDID("$FreeBSD$");


























































































uma_zone_t rack_zone;
uma_zone_t rack_pcb_zone;





struct sysctl_ctx_list rack_sysctl_ctx;
struct sysctl_oid *rack_sysctl_root;





static int32_t rack_precache = 1;
static int32_t rack_tlp_thresh = 1;
static int32_t rack_reorder_thresh = 2;
static int32_t rack_reorder_fade = 60000;	
static int32_t rack_pkt_delay = 1;
static int32_t rack_inc_var = 0;
static int32_t rack_reduce_largest_on_idle = 0;
static int32_t rack_min_pace_time = 0;
static int32_t rack_min_pace_time_seg_req=6;
static int32_t rack_early_recovery = 1;
static int32_t rack_early_recovery_max_seg = 6;
static int32_t rack_send_a_lot_in_prr = 1;
static int32_t rack_min_to = 1;	
static int32_t rack_tlp_in_recovery = 1;	
static int32_t rack_verbose_logging = 0;
static int32_t rack_ignore_data_after_close = 1;

static int32_t rack_tlp_min = 10;
static int32_t rack_rto_min = 30;	
static int32_t rack_rto_max = 30000;	
static const int32_t rack_free_cache = 2;
static int32_t rack_hptsi_segments = 40;
static int32_t rack_rate_sample_method = USE_RTT_LOW;
static int32_t rack_pace_every_seg = 1;
static int32_t rack_delayed_ack_time = 200;	
static int32_t rack_slot_reduction = 4;
static int32_t rack_lower_cwnd_at_tlp = 0;
static int32_t rack_use_proportional_reduce = 0;
static int32_t rack_proportional_rate = 10;
static int32_t rack_tlp_max_resend = 2;
static int32_t rack_limited_retran = 0;
static int32_t rack_always_send_oldest = 0;
static int32_t rack_sack_block_limit = 128;
static int32_t rack_use_sack_filter = 1;
static int32_t rack_tlp_threshold_use = TLP_USE_TWO_ONE;


counter_u64_t rack_badfr;
counter_u64_t rack_badfr_bytes;
counter_u64_t rack_rtm_prr_retran;
counter_u64_t rack_rtm_prr_newdata;
counter_u64_t rack_timestamp_mismatch;
counter_u64_t rack_reorder_seen;
counter_u64_t rack_paced_segments;
counter_u64_t rack_unpaced_segments;
counter_u64_t rack_saw_enobuf;
counter_u64_t rack_saw_enetunreach;


counter_u64_t rack_tlp_tot;
counter_u64_t rack_tlp_newdata;
counter_u64_t rack_tlp_retran;
counter_u64_t rack_tlp_retran_bytes;
counter_u64_t rack_tlp_retran_fail;
counter_u64_t rack_to_tot;
counter_u64_t rack_to_arm_rack;
counter_u64_t rack_to_arm_tlp;
counter_u64_t rack_to_alloc;
counter_u64_t rack_to_alloc_hard;
counter_u64_t rack_to_alloc_emerg;

counter_u64_t rack_sack_proc_all;
counter_u64_t rack_sack_proc_short;
counter_u64_t rack_sack_proc_restart;
counter_u64_t rack_runt_sacks;
counter_u64_t rack_used_tlpmethod;
counter_u64_t rack_used_tlpmethod2;
counter_u64_t rack_enter_tlp_calc;
counter_u64_t rack_input_idle_reduces;
counter_u64_t rack_tlp_does_nada;


counter_u64_t rack_find_high;

counter_u64_t rack_progress_drops;
counter_u64_t rack_out_size[TCP_MSS_ACCT_SIZE];
counter_u64_t rack_opts_arry[RACK_OPTS_SIZE];

static void rack_log_progress_event(struct tcp_rack *rack, struct tcpcb *tp, uint32_t tick,  int event, int line);

static int rack_process_ack(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, uint32_t tiwin, int32_t tlen, int32_t * ofia, int32_t thflags, int32_t * ret_val);


static int rack_process_data(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static void rack_ack_received(struct tcpcb *tp, struct tcp_rack *rack, struct tcphdr *th, uint16_t nsegs, uint16_t type, int32_t recovery);

static struct rack_sendmap *rack_alloc(struct tcp_rack *rack);
static struct rack_sendmap * rack_check_recovery_mode(struct tcpcb *tp, uint32_t tsused);

static void rack_cong_signal(struct tcpcb *tp, struct tcphdr *th, uint32_t type);

static void rack_counter_destroy(void);
static int rack_ctloutput(struct socket *so, struct sockopt *sopt, struct inpcb *inp, struct tcpcb *tp);

static int32_t rack_ctor(void *mem, int32_t size, void *arg, int32_t how);
static void rack_do_segment(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint8_t iptos);


static void rack_dtor(void *mem, int32_t size, void *arg);
static void rack_earlier_retran(struct tcpcb *tp, struct rack_sendmap *rsm, uint32_t t, uint32_t cts);

static struct rack_sendmap * rack_find_high_nonack(struct tcp_rack *rack, struct rack_sendmap *rsm);

static struct rack_sendmap *rack_find_lowest_rsm(struct tcp_rack *rack);
static void rack_free(struct tcp_rack *rack, struct rack_sendmap *rsm);
static void rack_fini(struct tcpcb *tp, int32_t tcb_is_purged);
static int rack_get_sockopt(struct socket *so, struct sockopt *sopt, struct inpcb *inp, struct tcpcb *tp, struct tcp_rack *rack);

static int32_t rack_handoff_ok(struct tcpcb *tp);
static int32_t rack_init(struct tcpcb *tp);
static void rack_init_sysctls(void);
static void rack_log_ack(struct tcpcb *tp, struct tcpopt *to, struct tcphdr *th);

static void rack_log_output(struct tcpcb *tp, struct tcpopt *to, int32_t len, uint32_t seq_out, uint8_t th_flags, int32_t err, uint32_t ts, uint8_t pass, struct rack_sendmap *hintrsm);


static void rack_log_sack_passed(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm);

static void rack_log_to_event(struct tcp_rack *rack, int32_t to_num);
static int32_t rack_output(struct tcpcb *tp);
static void rack_hpts_do_segment(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint8_t iptos, int32_t nxt_pkt, struct timeval *tv);



static uint32_t rack_proc_sack_blk(struct tcpcb *tp, struct tcp_rack *rack, struct sackblk *sack, struct tcpopt *to, struct rack_sendmap **prsm, uint32_t cts);


static void rack_post_recovery(struct tcpcb *tp, struct tcphdr *th);
static void rack_remxt_tmr(struct tcpcb *tp);
static int rack_set_sockopt(struct socket *so, struct sockopt *sopt, struct inpcb *inp, struct tcpcb *tp, struct tcp_rack *rack);

static void rack_set_state(struct tcpcb *tp, struct tcp_rack *rack);
static int32_t rack_stopall(struct tcpcb *tp);
static void rack_timer_activate(struct tcpcb *tp, uint32_t timer_type, uint32_t delta);

static int32_t rack_timer_active(struct tcpcb *tp, uint32_t timer_type);
static void rack_timer_cancel(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts, int line);
static void rack_timer_stop(struct tcpcb *tp, uint32_t timer_type);
static uint32_t rack_update_entry(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm, uint32_t ts, int32_t * lenp);

static void rack_update_rsm(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm, uint32_t ts);

static int rack_update_rtt(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm, struct tcpopt *to, uint32_t cts, int32_t ack_type);

static int32_t tcp_addrack(module_t mod, int32_t type, void *data);
static void rack_challenge_ack(struct mbuf *m, struct tcphdr *th, struct tcpcb *tp, int32_t * ret_val);

static int rack_do_close_wait(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static int rack_do_closing(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static void rack_do_drop(struct mbuf *m, struct tcpcb *tp);
static void rack_do_dropafterack(struct mbuf *m, struct tcpcb *tp, struct tcphdr *th, int32_t thflags, int32_t tlen, int32_t * ret_val);

static void rack_do_dropwithreset(struct mbuf *m, struct tcpcb *tp, struct tcphdr *th, int32_t rstreason, int32_t tlen);

static int rack_do_established(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static int rack_do_fastnewdata(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t nxt_pkt);


static int rack_do_fin_wait_1(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static int rack_do_fin_wait_2(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static int rack_do_lastack(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static int rack_do_syn_recv(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static int rack_do_syn_sent(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt);


static int rack_drop_checks(struct tcpopt *to, struct mbuf *m, struct tcphdr *th, struct tcpcb *tp, int32_t * tlenp, int32_t * thf, int32_t * drop_hdrlen, int32_t * ret_val);


static int rack_process_rst(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp);

struct rack_sendmap * tcp_rack_output(struct tcpcb *tp, struct tcp_rack *rack, uint32_t tsused);

static void tcp_rack_xmit_timer(struct tcp_rack *rack, int32_t rtt);
static void tcp_rack_partialack(struct tcpcb *tp, struct tcphdr *th);

static int rack_ts_check(struct mbuf *m, struct tcphdr *th, struct tcpcb *tp, int32_t tlen, int32_t thflags, int32_t * ret_val);


int32_t rack_clear_counter=0;


static int sysctl_rack_clear(SYSCTL_HANDLER_ARGS)
{
	uint32_t stat;
	int32_t error;

	error = SYSCTL_OUT(req, &rack_clear_counter, sizeof(uint32_t));
	if (error || req->newptr == NULL)
		return error;

	error = SYSCTL_IN(req, &stat, sizeof(uint32_t));
	if (error)
		return (error);
	if (stat == 1) {

		printf("Clearing RACK counters\n");

		counter_u64_zero(rack_badfr);
		counter_u64_zero(rack_badfr_bytes);
		counter_u64_zero(rack_rtm_prr_retran);
		counter_u64_zero(rack_rtm_prr_newdata);
		counter_u64_zero(rack_timestamp_mismatch);
		counter_u64_zero(rack_reorder_seen);
		counter_u64_zero(rack_tlp_tot);
		counter_u64_zero(rack_tlp_newdata);
		counter_u64_zero(rack_tlp_retran);
		counter_u64_zero(rack_tlp_retran_bytes);
		counter_u64_zero(rack_tlp_retran_fail);
		counter_u64_zero(rack_to_tot);
		counter_u64_zero(rack_to_arm_rack);
		counter_u64_zero(rack_to_arm_tlp);
		counter_u64_zero(rack_paced_segments);
		counter_u64_zero(rack_unpaced_segments);
		counter_u64_zero(rack_saw_enobuf);
		counter_u64_zero(rack_saw_enetunreach);
		counter_u64_zero(rack_to_alloc_hard);
		counter_u64_zero(rack_to_alloc_emerg);
		counter_u64_zero(rack_sack_proc_all);
		counter_u64_zero(rack_sack_proc_short);
		counter_u64_zero(rack_sack_proc_restart);
		counter_u64_zero(rack_to_alloc);
		counter_u64_zero(rack_find_high);
		counter_u64_zero(rack_runt_sacks);
		counter_u64_zero(rack_used_tlpmethod);
		counter_u64_zero(rack_used_tlpmethod2);
		counter_u64_zero(rack_enter_tlp_calc);
		counter_u64_zero(rack_progress_drops);
		counter_u64_zero(rack_tlp_does_nada);
	}
	rack_clear_counter = 0;
	return (0);
}



static void rack_init_sysctls()
{
	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "rate_sample_method", CTLFLAG_RW, &rack_rate_sample_method , USE_RTT_LOW, "What method should we use for rate sampling 0=high, 1=low ");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "data_after_close", CTLFLAG_RW, &rack_ignore_data_after_close, 0, "Do we hold off sending a RST until all pending data is ack'd");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlpmethod", CTLFLAG_RW, &rack_tlp_threshold_use, TLP_USE_TWO_ONE, "What method do we do for TLP time calc 0=no-de-ack-comp, 1=ID, 2=2.1, 3=2.2");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "min_pace_time", CTLFLAG_RW, &rack_min_pace_time, 0, "Should we enforce a minimum pace time of 1ms");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "min_pace_segs", CTLFLAG_RW, &rack_min_pace_time_seg_req, 6, "How many segments have to be in the len to enforce min-pace-time");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "idle_reduce_high", CTLFLAG_RW, &rack_reduce_largest_on_idle, 0, "Should we reduce the largest cwnd seen to IW on idle reduction");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "bb_verbose", CTLFLAG_RW, &rack_verbose_logging, 0, "Should RACK black box logging be verbose");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "sackfiltering", CTLFLAG_RW, &rack_use_sack_filter, 1, "Do we use sack filtering?");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "delayed_ack", CTLFLAG_RW, &rack_delayed_ack_time, 200, "Delayed ack time (200ms)");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlpminto", CTLFLAG_RW, &rack_tlp_min, 10, "TLP minimum timeout per the specification (10ms)");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "precache", CTLFLAG_RW, &rack_precache, 0, "Where should we precache the mcopy (0 is not at all)");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "sblklimit", CTLFLAG_RW, &rack_sack_block_limit, 128, "When do we start paying attention to small sack blocks");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "send_oldest", CTLFLAG_RW, &rack_always_send_oldest, 1, "Should we always send the oldest TLP and RACK-TLP");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "rack_tlp_in_recovery", CTLFLAG_RW, &rack_tlp_in_recovery, 1, "Can we do a TLP during recovery?");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "rack_tlimit", CTLFLAG_RW, &rack_limited_retran, 0, "How many times can a rack timeout drive out sends");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "minrto", CTLFLAG_RW, &rack_rto_min, 0, "Minimum RTO in ms -- set with caution below 1000 due to TLP");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "maxrto", CTLFLAG_RW, &rack_rto_max, 0, "Maxiumum RTO in ms -- should be at least as large as min_rto");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_retry", CTLFLAG_RW, &rack_tlp_max_resend, 2, "How many times does TLP retry a single segment or multiple with no ACK");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "recovery_loss_prop", CTLFLAG_RW, &rack_use_proportional_reduce, 0, "Should we proportionaly reduce cwnd based on the number of losses ");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "recovery_prop", CTLFLAG_RW, &rack_proportional_rate, 10, "What percent reduction per loss");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_cwnd_flag", CTLFLAG_RW, &rack_lower_cwnd_at_tlp, 0, "When a TLP completes a retran should we enter recovery?");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "hptsi_reduces", CTLFLAG_RW, &rack_slot_reduction, 4, "When setting a slot should we reduce by divisor");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "hptsi_every_seg", CTLFLAG_RW, &rack_pace_every_seg, 1, "Should we pace out every segment hptsi");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "hptsi_seg_max", CTLFLAG_RW, &rack_hptsi_segments, 6, "Should we pace out only a limited size of segments");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "prr_sendalot", CTLFLAG_RW, &rack_send_a_lot_in_prr, 1, "Send a lot in prr");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "minto", CTLFLAG_RW, &rack_min_to, 1, "Minimum rack timeout in milliseconds");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "earlyrecoveryseg", CTLFLAG_RW, &rack_early_recovery_max_seg, 6, "Max segments in early recovery");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "earlyrecovery", CTLFLAG_RW, &rack_early_recovery, 1, "Do we do early recovery with rack");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "reorder_thresh", CTLFLAG_RW, &rack_reorder_thresh, 2, "What factor for rack will be added when seeing reordering (shift right)");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "rtt_tlp_thresh", CTLFLAG_RW, &rack_tlp_thresh, 1, "what divisor for TLP rtt/retran will be added (1=rtt, 2=1/2 rtt etc)");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "reorder_fade", CTLFLAG_RW, &rack_reorder_fade, 0, "Does reorder detection fade, if so how many ms (0 means never)");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "pktdelay", CTLFLAG_RW, &rack_pkt_delay, 1, "Extra RACK time (in ms) besides reordering thresh");



	SYSCTL_ADD_S32(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "inc_var", CTLFLAG_RW, &rack_inc_var, 0, "Should rack add to the TLP timer the variance in rtt calculation");



	rack_badfr = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "badfr", CTLFLAG_RD, &rack_badfr, "Total number of bad FRs");


	rack_badfr_bytes = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "badfr_bytes", CTLFLAG_RD, &rack_badfr_bytes, "Total number of bad FRs");


	rack_rtm_prr_retran = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "prrsndret", CTLFLAG_RD, &rack_rtm_prr_retran, "Total number of prr based retransmits");



	rack_rtm_prr_newdata = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "prrsndnew", CTLFLAG_RD, &rack_rtm_prr_newdata, "Total number of prr based new transmits");



	rack_timestamp_mismatch = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tsnf", CTLFLAG_RD, &rack_timestamp_mismatch, "Total number of timestamps that we could not find the reported ts");



	rack_find_high = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "findhigh", CTLFLAG_RD, &rack_find_high, "Total number of FIN causing find-high");



	rack_reorder_seen = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "reordering", CTLFLAG_RD, &rack_reorder_seen, "Total number of times we added delay due to reordering");



	rack_tlp_tot = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_to_total", CTLFLAG_RD, &rack_tlp_tot, "Total number of tail loss probe expirations");



	rack_tlp_newdata = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_new", CTLFLAG_RD, &rack_tlp_newdata, "Total number of tail loss probe sending new data");




	rack_tlp_retran = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_retran", CTLFLAG_RD, &rack_tlp_retran, "Total number of tail loss probe sending retransmitted data");



	rack_tlp_retran_bytes = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_retran_bytes", CTLFLAG_RD, &rack_tlp_retran_bytes, "Total bytes of tail loss probe sending retransmitted data");



	rack_tlp_retran_fail = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_retran_fail", CTLFLAG_RD, &rack_tlp_retran_fail, "Total number of tail loss probe sending retransmitted data that failed (wait for t3)");



	rack_to_tot = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "rack_to_tot", CTLFLAG_RD, &rack_to_tot, "Total number of times the rack to expired?");



	rack_to_arm_rack = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "arm_rack", CTLFLAG_RD, &rack_to_arm_rack, "Total number of times the rack timer armed?");



	rack_to_arm_tlp = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "arm_tlp", CTLFLAG_RD, &rack_to_arm_tlp, "Total number of times the tlp timer armed?");



	rack_paced_segments = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "paced", CTLFLAG_RD, &rack_paced_segments, "Total number of times a segment send caused hptsi");



	rack_unpaced_segments = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "unpaced", CTLFLAG_RD, &rack_unpaced_segments, "Total number of times a segment did not cause hptsi");



	rack_saw_enobuf = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "saw_enobufs", CTLFLAG_RD, &rack_saw_enobuf, "Total number of times a segment did not cause hptsi");



	rack_saw_enetunreach = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "saw_enetunreach", CTLFLAG_RD, &rack_saw_enetunreach, "Total number of times a segment did not cause hptsi");



	rack_to_alloc = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "allocs", CTLFLAG_RD, &rack_to_alloc, "Total allocations of tracking structures");



	rack_to_alloc_hard = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "allochard", CTLFLAG_RD, &rack_to_alloc_hard, "Total allocations done with sleeping the hard way");



	rack_to_alloc_emerg = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "allocemerg", CTLFLAG_RD, &rack_to_alloc_emerg, "Total alocations done from emergency cache");



	rack_sack_proc_all = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "sack_long", CTLFLAG_RD, &rack_sack_proc_all, "Total times we had to walk whole list for sack processing");




	rack_sack_proc_restart = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "sack_restart", CTLFLAG_RD, &rack_sack_proc_restart, "Total times we had to walk whole list due to a restart");



	rack_sack_proc_short = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "sack_short", CTLFLAG_RD, &rack_sack_proc_short, "Total times we took shortcut for sack processing");



	rack_enter_tlp_calc = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_calc_entered", CTLFLAG_RD, &rack_enter_tlp_calc, "Total times we called calc-tlp");



	rack_used_tlpmethod = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "hit_tlp_method", CTLFLAG_RD, &rack_used_tlpmethod, "Total number of runt sacks");



	rack_used_tlpmethod2 = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "hit_tlp_method2", CTLFLAG_RD, &rack_used_tlpmethod2, "Total number of runt sacks 2");



	rack_runt_sacks = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "runtsacks", CTLFLAG_RD, &rack_runt_sacks, "Total number of runt sacks");



	rack_progress_drops = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "prog_drops", CTLFLAG_RD, &rack_progress_drops, "Total number of progress drops");



	rack_input_idle_reduces = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "idle_reduce_oninput", CTLFLAG_RD, &rack_input_idle_reduces, "Total number of idle reductions on input");



	rack_tlp_does_nada = counter_u64_alloc(M_WAITOK);
	SYSCTL_ADD_COUNTER_U64(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "tlp_nada", CTLFLAG_RD, &rack_tlp_does_nada, "Total number of nada tlp calls");



	COUNTER_ARRAY_ALLOC(rack_out_size, TCP_MSS_ACCT_SIZE, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "outsize", CTLFLAG_RD, rack_out_size, TCP_MSS_ACCT_SIZE, "MSS send sizes");

	COUNTER_ARRAY_ALLOC(rack_opts_arry, RACK_OPTS_SIZE, M_WAITOK);
	SYSCTL_ADD_COUNTER_U64_ARRAY(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "opts", CTLFLAG_RD, rack_opts_arry, RACK_OPTS_SIZE, "RACK Option Stats");

	SYSCTL_ADD_PROC(&rack_sysctl_ctx, SYSCTL_CHILDREN(rack_sysctl_root), OID_AUTO, "clear", CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_MPSAFE, &rack_clear_counter, 0, sysctl_rack_clear, "IU", "Clear counters");


}

static inline int32_t rack_progress_timeout_check(struct tcpcb *tp)
{
	if (tp->t_maxunacktime && tp->t_acktime && TSTMP_GT(ticks, tp->t_acktime)) {
		if ((ticks - tp->t_acktime) >= tp->t_maxunacktime) {
			
			struct tcp_rack *rack;
			rack = (struct tcp_rack *)tp->t_fb_ptr;
			counter_u64_add(rack_progress_drops, 1);

			TCPSTAT_INC(tcps_progdrops);

			rack_log_progress_event(rack, tp, ticks, PROGRESS_DROP, __LINE__);
			return (1);
		}
	}
	return (0);
}


static void rack_log_to_start(struct tcp_rack *rack, uint32_t cts, uint32_t to, int32_t slot, uint8_t which)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = TICKS_2_MSEC(rack->rc_tp->t_srtt >> TCP_RTT_SHIFT);
		log.u_bbr.flex2 = to;
		log.u_bbr.flex3 = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.flex4 = slot;
		log.u_bbr.flex5 = rack->rc_inp->inp_hptsslot;
		log.u_bbr.flex6 = rack->rc_tp->t_rxtcur;
		log.u_bbr.flex8 = which;
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		TCP_LOG_EVENT(rack->rc_tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_TIMERSTAR, 0, 0, &log, false);



	}
}

static void rack_log_to_event(struct tcp_rack *rack, int32_t to_num)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex8 = to_num;
		log.u_bbr.flex1 = rack->r_ctl.rc_rack_min_rtt;
		log.u_bbr.flex2 = rack->rc_rack_rtt;
		TCP_LOG_EVENT(rack->rc_tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_RTO, 0, 0, &log, false);



	}
}

static void rack_log_rtt_upd(struct tcpcb *tp, struct tcp_rack *rack, int32_t t, uint32_t o_srtt, uint32_t o_var)

{
	if (tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = t;
		log.u_bbr.flex2 = o_srtt;
		log.u_bbr.flex3 = o_var;
		log.u_bbr.flex4 = rack->r_ctl.rack_rs.rs_rtt_lowest;
		log.u_bbr.flex5 = rack->r_ctl.rack_rs.rs_rtt_highest;		
		log.u_bbr.flex6 = rack->r_ctl.rack_rs.rs_rtt_cnt;
		log.u_bbr.rttProp = rack->r_ctl.rack_rs.rs_rtt_tot;
		log.u_bbr.flex8 = rack->r_ctl.rc_rate_sample_method;
		TCP_LOG_EVENT(tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_BBRRTT, 0, 0, &log, false);



	}
}

static void rack_log_rtt_sample(struct tcp_rack *rack, uint32_t rtt)
{
	
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		struct timeval tv;
		
		
		log.u_bbr.flex1 = rtt * 1000;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		TCP_LOG_EVENTP(rack->rc_tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, TCP_LOG_RTT, 0, 0, &log, false, &tv);



	}
}


static inline void rack_log_progress_event(struct tcp_rack *rack, struct tcpcb *tp, uint32_t tick,  int event, int line)
{
	if (rack_verbose_logging && (tp->t_logstate != TCP_LOG_STATE_OFF)) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = line;
		log.u_bbr.flex2 = tick;
		log.u_bbr.flex3 = tp->t_maxunacktime;
		log.u_bbr.flex4 = tp->t_acktime;
		log.u_bbr.flex8 = event;
		TCP_LOG_EVENT(tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_PROGRESS, 0, 0, &log, false);



	}
}

static void rack_log_type_bbrsnd(struct tcp_rack *rack, uint32_t len, uint32_t slot, uint32_t cts)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = slot;
		log.u_bbr.flex7 = (0x0000ffff & rack->r_ctl.rc_hpts_flags);
		log.u_bbr.flex8 = rack->rc_in_persist;
		TCP_LOG_EVENT(rack->rc_tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_BBRSND, 0, 0, &log, false);



	}
}

static void rack_log_doseg_done(struct tcp_rack *rack, uint32_t cts, int32_t nxt_pkt, int32_t did_out, int way_out)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;
		log.u_bbr.flex1 = did_out;
		log.u_bbr.flex2 = nxt_pkt;
		log.u_bbr.flex3 = way_out;
		log.u_bbr.flex4 = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.flex7 = rack->r_wanted_output;
		log.u_bbr.flex8 = rack->rc_in_persist;
		TCP_LOG_EVENT(rack->rc_tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_DOSEG_DONE, 0, 0, &log, false);



	}
}


static void rack_log_type_just_return(struct tcp_rack *rack, uint32_t cts, uint32_t tlen, uint32_t slot, uint8_t hpts_calling)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = slot;
		log.u_bbr.flex2 = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.flex7 = hpts_calling;
		log.u_bbr.flex8 = rack->rc_in_persist;
		TCP_LOG_EVENT(rack->rc_tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_JUSTRET, 0, tlen, &log, false);



	}
}

static void rack_log_to_cancel(struct tcp_rack *rack, int32_t hpts_removed, int line)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = line;
		log.u_bbr.flex2 = 0;
		log.u_bbr.flex3 = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.flex4 = 0;
		log.u_bbr.flex6 = rack->rc_tp->t_rxtcur;
		log.u_bbr.flex8 = hpts_removed;
		TCP_LOG_EVENT(rack->rc_tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_TIMERCANC, 0, 0, &log, false);



	}
}

static void rack_log_to_processing(struct tcp_rack *rack, uint32_t cts, int32_t ret, int32_t timers)
{
	if (rack->rc_tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.flex1 = timers;
		log.u_bbr.flex2 = ret;
		log.u_bbr.flex3 = rack->r_ctl.rc_timer_exp;
		log.u_bbr.flex4 = rack->r_ctl.rc_hpts_flags;
		log.u_bbr.flex5 = cts;
		TCP_LOG_EVENT(rack->rc_tp, NULL, &rack->rc_inp->inp_socket->so_rcv, &rack->rc_inp->inp_socket->so_snd, BBR_LOG_TO_PROCESS, 0, 0, &log, false);



	}
}

static void rack_counter_destroy()
{
	counter_u64_free(rack_badfr);
	counter_u64_free(rack_badfr_bytes);
	counter_u64_free(rack_rtm_prr_retran);
	counter_u64_free(rack_rtm_prr_newdata);
	counter_u64_free(rack_timestamp_mismatch);
	counter_u64_free(rack_reorder_seen);
	counter_u64_free(rack_tlp_tot);
	counter_u64_free(rack_tlp_newdata);
	counter_u64_free(rack_tlp_retran);
	counter_u64_free(rack_tlp_retran_bytes);
	counter_u64_free(rack_tlp_retran_fail);
	counter_u64_free(rack_to_tot);
	counter_u64_free(rack_to_arm_rack);
	counter_u64_free(rack_to_arm_tlp);
	counter_u64_free(rack_paced_segments);
	counter_u64_free(rack_unpaced_segments);
	counter_u64_free(rack_saw_enobuf);
	counter_u64_free(rack_saw_enetunreach);
	counter_u64_free(rack_to_alloc_hard);
	counter_u64_free(rack_to_alloc_emerg);
	counter_u64_free(rack_sack_proc_all);
	counter_u64_free(rack_sack_proc_short);
	counter_u64_free(rack_sack_proc_restart);
	counter_u64_free(rack_to_alloc);
	counter_u64_free(rack_find_high);
	counter_u64_free(rack_runt_sacks);
	counter_u64_free(rack_enter_tlp_calc);
	counter_u64_free(rack_used_tlpmethod);
	counter_u64_free(rack_used_tlpmethod2);
	counter_u64_free(rack_progress_drops);
	counter_u64_free(rack_input_idle_reduces);
	counter_u64_free(rack_tlp_does_nada);
	COUNTER_ARRAY_FREE(rack_out_size, TCP_MSS_ACCT_SIZE);
	COUNTER_ARRAY_FREE(rack_opts_arry, RACK_OPTS_SIZE);
}

static struct rack_sendmap * rack_alloc(struct tcp_rack *rack)
{
	struct rack_sendmap *rsm;

	counter_u64_add(rack_to_alloc, 1);
	rack->r_ctl.rc_num_maps_alloced++;
	rsm = uma_zalloc(rack_zone, M_NOWAIT);
	if (rsm) {
		return (rsm);
	}
	if (rack->rc_free_cnt) {
		counter_u64_add(rack_to_alloc_emerg, 1);
		rsm = TAILQ_FIRST(&rack->r_ctl.rc_free);
		TAILQ_REMOVE(&rack->r_ctl.rc_free, rsm, r_next);
		rack->rc_free_cnt--;
		return (rsm);
	}
	return (NULL);
}

static void rack_free(struct tcp_rack *rack, struct rack_sendmap *rsm)
{
	rack->r_ctl.rc_num_maps_alloced--;
	if (rack->r_ctl.rc_tlpsend == rsm)
		rack->r_ctl.rc_tlpsend = NULL;
	if (rack->r_ctl.rc_next == rsm)
		rack->r_ctl.rc_next = NULL;
	if (rack->r_ctl.rc_sacklast == rsm)
		rack->r_ctl.rc_sacklast = NULL;
	if (rack->rc_free_cnt < rack_free_cache) {
		memset(rsm, 0, sizeof(struct rack_sendmap));
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_free, rsm, r_next);
		rack->rc_free_cnt++;
		return;
	}
	uma_zfree(rack_zone, rsm);
}


static void rack_ack_received(struct tcpcb *tp, struct tcp_rack *rack, struct tcphdr *th, uint16_t nsegs, uint16_t type, int32_t recovery)

{

	int32_t gput;


	u_long old_cwnd = tp->snd_cwnd;


	INP_WLOCK_ASSERT(tp->t_inpcb);
	tp->ccv->nsegs = nsegs;
	tp->ccv->bytes_this_ack = BYTES_THIS_ACK(tp, th);
	if ((recovery) && (rack->r_ctl.rc_early_recovery_segs)) {
		uint32_t max;

		max = rack->r_ctl.rc_early_recovery_segs * tp->t_maxseg;
		if (tp->ccv->bytes_this_ack > max) {
			tp->ccv->bytes_this_ack = max;
		}
	}
	if (tp->snd_cwnd <= tp->snd_wnd)
		tp->ccv->flags |= CCF_CWND_LIMITED;
	else tp->ccv->flags &= ~CCF_CWND_LIMITED;

	if (type == CC_ACK) {

		stats_voi_update_abs_s32(tp->t_stats, VOI_TCP_CALCFRWINDIFF, ((int32_t) tp->snd_cwnd) - tp->snd_wnd);
		if ((tp->t_flags & TF_GPUTINPROG) && SEQ_GEQ(th->th_ack, tp->gput_ack)) {
			gput = (((int64_t) (th->th_ack - tp->gput_seq)) << 3) / max(1, tcp_ts_getticks() - tp->gput_ts);
			stats_voi_update_abs_u32(tp->t_stats, VOI_TCP_GPUT, gput);
			
			if (tp->t_stats_gput_prev > 0)
				stats_voi_update_abs_s32(tp->t_stats, VOI_TCP_GPUT_ND, ((gput - tp->t_stats_gput_prev) * 100) / tp->t_stats_gput_prev);


			tp->t_flags &= ~TF_GPUTINPROG;
			tp->t_stats_gput_prev = gput;

			if (tp->t_maxpeakrate) {
				
				tcp_update_peakrate_thr(tp);
			}

		}

		if (tp->snd_cwnd > tp->snd_ssthresh) {
			tp->t_bytes_acked += min(tp->ccv->bytes_this_ack, nsegs * V_tcp_abc_l_var * tp->t_maxseg);
			if (tp->t_bytes_acked >= tp->snd_cwnd) {
				tp->t_bytes_acked -= tp->snd_cwnd;
				tp->ccv->flags |= CCF_ABC_SENTAWND;
			}
		} else {
			tp->ccv->flags &= ~CCF_ABC_SENTAWND;
			tp->t_bytes_acked = 0;
		}
	}
	if (CC_ALGO(tp)->ack_received != NULL) {
		
		tp->ccv->curack = th->th_ack;
		CC_ALGO(tp)->ack_received(tp->ccv, type);
	}

	stats_voi_update_abs_ulong(tp->t_stats, VOI_TCP_LCWIN, tp->snd_cwnd);

	if (rack->r_ctl.rc_rack_largest_cwnd < tp->snd_cwnd) {
		rack->r_ctl.rc_rack_largest_cwnd = tp->snd_cwnd;
	}

	if (tp->cwv_enabled) {
		
		if ((tp->snd_cwnd > old_cwnd) && (tp->cwv_cwnd_valid == 0) && (!(tp->ccv->flags & CCF_CWND_LIMITED))) {

			tp->snd_cwnd = old_cwnd;
		}
		
		if (TCPS_HAVEESTABLISHED(tp->t_state) && !IN_RECOVERY(tp->t_flags)) {
			uint32_t data = sbavail(&(tp->t_inpcb->inp_socket->so_snd));

			tcp_newcwv_update_pipeack(tp, data);
		}
	}
	
	if (tp->t_peakrate_thr && tp->snd_cwnd > tp->t_peakrate_thr) {
		tp->snd_cwnd = tp->t_peakrate_thr;
	}

}

static void tcp_rack_partialack(struct tcpcb *tp, struct tcphdr *th)
{
	struct tcp_rack *rack;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	INP_WLOCK_ASSERT(tp->t_inpcb);
	if (rack->r_ctl.rc_prr_sndcnt > 0)
		rack->r_wanted_output++;
}

static void rack_post_recovery(struct tcpcb *tp, struct tcphdr *th)
{
	struct tcp_rack *rack;

	INP_WLOCK_ASSERT(tp->t_inpcb);
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (CC_ALGO(tp)->post_recovery != NULL) {
		tp->ccv->curack = th->th_ack;
		CC_ALGO(tp)->post_recovery(tp->ccv);
	}
	
	if (rack->r_ctl.rc_prop_reduce && rack->r_ctl.rc_prop_rate) {
		int32_t reduce;

		reduce = (rack->r_ctl.rc_loss_count * rack->r_ctl.rc_prop_rate);
		if (reduce > 50) {
			reduce = 50;
		}
		tp->snd_cwnd -= ((reduce * tp->snd_cwnd) / 100);
	} else {
		if (tp->snd_cwnd > tp->snd_ssthresh) {
			
			tp->snd_cwnd = tp->snd_ssthresh;
		}
	}
	if (rack->r_ctl.rc_prr_sndcnt > 0) {
		
		tp->snd_cwnd += rack->r_ctl.rc_prr_sndcnt;
		rack->r_ctl.rc_prr_sndcnt = 0;
	}
	EXIT_RECOVERY(tp->t_flags);



	if (tp->cwv_enabled) {
		if ((tp->cwv_cwnd_valid == 0) && (tp->snd_cwv.in_recovery))
			tcp_newcwv_end_recovery(tp);
	}

}

static void rack_cong_signal(struct tcpcb *tp, struct tcphdr *th, uint32_t type)
{
	struct tcp_rack *rack;

	INP_WLOCK_ASSERT(tp->t_inpcb);

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	switch (type) {
	case CC_NDUPACK:

		if (!IN_FASTRECOVERY(tp->t_flags)) {
			rack->r_ctl.rc_tlp_rtx_out = 0;
			rack->r_ctl.rc_prr_delivered = 0;
			rack->r_ctl.rc_prr_out = 0;
			rack->r_ctl.rc_loss_count = 0;
			rack->r_ctl.rc_prr_sndcnt = tp->t_maxseg;
			rack->r_ctl.rc_prr_recovery_fs = tp->snd_max - tp->snd_una;
			tp->snd_recover = tp->snd_max;
			if (tp->t_flags & TF_ECN_PERMIT)
				tp->t_flags |= TF_ECN_SND_CWR;
		}
		break;
	case CC_ECN:
		if (!IN_CONGRECOVERY(tp->t_flags)) {
			TCPSTAT_INC(tcps_ecn_rcwnd);
			tp->snd_recover = tp->snd_max;
			if (tp->t_flags & TF_ECN_PERMIT)
				tp->t_flags |= TF_ECN_SND_CWR;
		}
		break;
	case CC_RTO:
		tp->t_dupacks = 0;
		tp->t_bytes_acked = 0;
		EXIT_RECOVERY(tp->t_flags);
		tp->snd_ssthresh = max(2, min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg) * tp->t_maxseg;
		tp->snd_cwnd = tp->t_maxseg;
		break;
	case CC_RTO_ERR:
		TCPSTAT_INC(tcps_sndrexmitbad);
		
		tp->snd_cwnd = tp->snd_cwnd_prev;
		tp->snd_ssthresh = tp->snd_ssthresh_prev;
		tp->snd_recover = tp->snd_recover_prev;
		if (tp->t_flags & TF_WASFRECOVERY)
			ENTER_FASTRECOVERY(tp->t_flags);
		if (tp->t_flags & TF_WASCRECOVERY)
			ENTER_CONGRECOVERY(tp->t_flags);
		tp->snd_nxt = tp->snd_max;
		tp->t_badrxtwin = 0;
		break;
	}

	if (CC_ALGO(tp)->cong_signal != NULL) {
		if (th != NULL)
			tp->ccv->curack = th->th_ack;
		CC_ALGO(tp)->cong_signal(tp->ccv, type);
	}

	if (tp->cwv_enabled) {
		if (tp->snd_cwv.in_recovery == 0 && IN_RECOVERY(tp->t_flags)) {
			tcp_newcwv_enter_recovery(tp);
		}
		if (type == CC_RTO) {
			tcp_newcwv_reset(tp);
		}
	}

}



static inline void rack_cc_after_idle(struct tcpcb *tp, int reduce_largest)
{
	uint32_t i_cwnd;

	INP_WLOCK_ASSERT(tp->t_inpcb);


	TCPSTAT_INC(tcps_idle_restarts);
	if (tp->t_state == TCPS_ESTABLISHED)
		TCPSTAT_INC(tcps_idle_estrestarts);

	if (CC_ALGO(tp)->after_idle != NULL)
		CC_ALGO(tp)->after_idle(tp->ccv);

	if (tp->snd_cwnd == 1)
		i_cwnd = tp->t_maxseg;		
	else  i_cwnd = tcp_compute_initwnd(tcp_maxseg(tp));

	if (reduce_largest) {
		
		if (((struct tcp_rack *)tp->t_fb_ptr)->r_ctl.rc_rack_largest_cwnd  > i_cwnd)
			((struct tcp_rack *)tp->t_fb_ptr)->r_ctl.rc_rack_largest_cwnd = i_cwnd;
	}
	
	if (tp->snd_cwnd < i_cwnd) {
		tp->snd_cwnd = i_cwnd;
	}
}








static inline void rack_calc_rwin(struct socket *so, struct tcpcb *tp)
{
	int32_t win;

	
	win = sbspace(&so->so_rcv);
	if (win < 0)
		win = 0;
	tp->rcv_wnd = imax(win, (int)(tp->rcv_adv - tp->rcv_nxt));
}

static void rack_do_drop(struct mbuf *m, struct tcpcb *tp)
{
	
	if (tp != NULL)
		INP_WUNLOCK(tp->t_inpcb);
	if (m)
		m_freem(m);
}

static void rack_do_dropwithreset(struct mbuf *m, struct tcpcb *tp, struct tcphdr *th, int32_t rstreason, int32_t tlen)

{
	if (tp != NULL) {
		tcp_dropwithreset(m, th, tp, tlen, rstreason);
		INP_WUNLOCK(tp->t_inpcb);
	} else tcp_dropwithreset(m, th, NULL, tlen, rstreason);
}


static void rack_do_dropafterack(struct mbuf *m, struct tcpcb *tp, struct tcphdr *th, int32_t thflags, int32_t tlen, int32_t * ret_val)
{
	
	struct tcp_rack *rack;

	if (tp->t_state == TCPS_SYN_RECEIVED && (thflags & TH_ACK) && (SEQ_GT(tp->snd_una, th->th_ack) || SEQ_GT(th->th_ack, tp->snd_max))) {

		*ret_val = 1;
		rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return;
	} else *ret_val = 0;
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	rack->r_wanted_output++;
	tp->t_flags |= TF_ACKNOW;
	if (m)
		m_freem(m);
}


static int rack_process_rst(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp)
{
	
	int dropped = 0;

	if ((SEQ_GEQ(th->th_seq, (tp->last_ack_sent - 1)) && SEQ_LT(th->th_seq, tp->last_ack_sent + tp->rcv_wnd)) || (tp->rcv_wnd == 0 && tp->last_ack_sent == th->th_seq)) {


		INP_INFO_RLOCK_ASSERT(&V_tcbinfo);
		KASSERT(tp->t_state != TCPS_SYN_SENT, ("%s: TH_RST for TCPS_SYN_SENT th %p tp %p", __func__, th, tp));


		if (V_tcp_insecure_rst || (tp->last_ack_sent == th->th_seq) || (tp->rcv_nxt == th->th_seq) || ((tp->last_ack_sent - 1) == th->th_seq)) {


			TCPSTAT_INC(tcps_drops);
			
			switch (tp->t_state) {
			case TCPS_SYN_RECEIVED:
				so->so_error = ECONNREFUSED;
				goto close;
			case TCPS_ESTABLISHED:
			case TCPS_FIN_WAIT_1:
			case TCPS_FIN_WAIT_2:
			case TCPS_CLOSE_WAIT:
			case TCPS_CLOSING:
			case TCPS_LAST_ACK:
				so->so_error = ECONNRESET;
		close:
				tcp_state_change(tp, TCPS_CLOSED);
				
			default:
				tp = tcp_close(tp);
			}
			dropped = 1;
			rack_do_drop(m, tp);
		} else {
			TCPSTAT_INC(tcps_badrst);
			
			tcp_respond(tp, mtod(m, void *), th, m, tp->rcv_nxt, tp->snd_nxt, TH_ACK);
			tp->last_ack_sent = tp->rcv_nxt;
		}
	} else {
		m_freem(m);
	}
	return (dropped);
}


static void rack_challenge_ack(struct mbuf *m, struct tcphdr *th, struct tcpcb *tp, int32_t * ret_val)
{
	INP_INFO_RLOCK_ASSERT(&V_tcbinfo);

	TCPSTAT_INC(tcps_badsyn);
	if (V_tcp_insecure_syn && SEQ_GEQ(th->th_seq, tp->last_ack_sent) && SEQ_LT(th->th_seq, tp->last_ack_sent + tp->rcv_wnd)) {

		tp = tcp_drop(tp, ECONNRESET);
		*ret_val = 1;
		rack_do_drop(m, tp);
	} else {
		
		tcp_respond(tp, mtod(m, void *), th, m, tp->rcv_nxt, tp->snd_nxt, TH_ACK);
		tp->last_ack_sent = tp->rcv_nxt;
		m = NULL;
		*ret_val = 0;
		rack_do_drop(m, NULL);
	}
}


static int rack_ts_check(struct mbuf *m, struct tcphdr *th, struct tcpcb *tp, int32_t tlen, int32_t thflags, int32_t * ret_val)
{

	
	if (tcp_ts_getticks() - tp->ts_recent_age > TCP_PAWS_IDLE) {
		
		tp->ts_recent = 0;
	} else {
		TCPSTAT_INC(tcps_rcvduppack);
		TCPSTAT_ADD(tcps_rcvdupbyte, tlen);
		TCPSTAT_INC(tcps_pawsdrop);
		*ret_val = 0;
		if (tlen) {
			rack_do_dropafterack(m, tp, th, thflags, tlen, ret_val);
		} else {
			rack_do_drop(m, NULL);
		}
		return (1);
	}
	return (0);
}


static int rack_drop_checks(struct tcpopt *to, struct mbuf *m, struct tcphdr *th, struct tcpcb *tp, int32_t * tlenp,  int32_t * thf, int32_t * drop_hdrlen, int32_t * ret_val)
{
	int32_t todrop;
	int32_t thflags;
	int32_t tlen;

	thflags = *thf;
	tlen = *tlenp;
	todrop = tp->rcv_nxt - th->th_seq;
	if (todrop > 0) {
		if (thflags & TH_SYN) {
			thflags &= ~TH_SYN;
			th->th_seq++;
			if (th->th_urp > 1)
				th->th_urp--;
			else thflags &= ~TH_URG;
			todrop--;
		}
		
		if (todrop > tlen || (todrop == tlen && (thflags & TH_FIN) == 0)) {
			
			thflags &= ~TH_FIN;
			
			tp->t_flags |= TF_ACKNOW;
			todrop = tlen;
			TCPSTAT_INC(tcps_rcvduppack);
			TCPSTAT_ADD(tcps_rcvdupbyte, todrop);
		} else {
			TCPSTAT_INC(tcps_rcvpartduppack);
			TCPSTAT_ADD(tcps_rcvpartdupbyte, todrop);
		}
		
		if (tp->t_flags & TF_SACK_PERMIT) {
			tcp_update_sack_list(tp, th->th_seq, th->th_seq + tlen);
			
			tp->t_flags |= TF_ACKNOW;
		}
		*drop_hdrlen += todrop;	
		th->th_seq += todrop;
		tlen -= todrop;
		if (th->th_urp > todrop)
			th->th_urp -= todrop;
		else {
			thflags &= ~TH_URG;
			th->th_urp = 0;
		}
	}
	
	todrop = (th->th_seq + tlen) - (tp->rcv_nxt + tp->rcv_wnd);
	if (todrop > 0) {
		TCPSTAT_INC(tcps_rcvpackafterwin);
		if (todrop >= tlen) {
			TCPSTAT_ADD(tcps_rcvbyteafterwin, tlen);
			
			if (tp->rcv_wnd == 0 && th->th_seq == tp->rcv_nxt) {
				tp->t_flags |= TF_ACKNOW;
				TCPSTAT_INC(tcps_rcvwinprobe);
			} else {
				rack_do_dropafterack(m, tp, th, thflags, tlen, ret_val);
				return (1);
			}
		} else TCPSTAT_ADD(tcps_rcvbyteafterwin, todrop);
		m_adj(m, -todrop);
		tlen -= todrop;
		thflags &= ~(TH_PUSH | TH_FIN);
	}
	*thf = thflags;
	*tlenp = tlen;
	return (0);
}

static struct rack_sendmap * rack_find_lowest_rsm(struct tcp_rack *rack)
{
	struct rack_sendmap *rsm;

	
	TAILQ_FOREACH(rsm, &rack->r_ctl.rc_tmap, r_tnext) {
		if (rsm->r_flags & RACK_ACKED) {
			continue;
		}
		goto finish;
	}
finish:
	return (rsm);
}

static struct rack_sendmap * rack_find_high_nonack(struct tcp_rack *rack, struct rack_sendmap *rsm)
{
	struct rack_sendmap *prsm;

	
	counter_u64_add(rack_find_high, 1);
	prsm = rsm;
	TAILQ_FOREACH_REVERSE_FROM(prsm, &rack->r_ctl.rc_map, rack_head, r_next) {
		if (prsm->r_flags & (RACK_ACKED | RACK_HAS_FIN)) {
			continue;
		}
		return (prsm);
	}
	return (NULL);
}


static uint32_t rack_calc_thresh_rack(struct tcp_rack *rack, uint32_t srtt, uint32_t cts)
{
	int32_t lro;
	uint32_t thresh;

	
	if (srtt == 0)
		srtt = 1;
	if (rack->r_ctl.rc_reorder_ts) {
		if (rack->r_ctl.rc_reorder_fade) {
			if (SEQ_GEQ(cts, rack->r_ctl.rc_reorder_ts)) {
				lro = cts - rack->r_ctl.rc_reorder_ts;
				if (lro == 0) {
					
					lro = 1;
				}
			} else {
				
				lro = 0;
			}
			if (lro > rack->r_ctl.rc_reorder_fade) {
				
				rack->r_ctl.rc_reorder_ts = 0;
				lro = 0;
			}
		} else {
			
			lro = 1;
		}
	} else {
		lro = 0;
	}
	thresh = srtt + rack->r_ctl.rc_pkt_delay;
	if (lro) {
		
		if (rack->r_ctl.rc_reorder_shift)
			thresh += (srtt >> rack->r_ctl.rc_reorder_shift);
		else thresh += (srtt >> 2);
	} else {
		thresh += 1;
	}
	
	
	if (thresh > TICKS_2_MSEC(rack->rc_tp->t_rxtcur)) {
		thresh = TICKS_2_MSEC(rack->rc_tp->t_rxtcur);
	}
	
	if (thresh > rack_rto_max) {
		thresh = rack_rto_max;
	}
	return (thresh);
}

static uint32_t rack_calc_thresh_tlp(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm, uint32_t srtt)

{
	struct rack_sendmap *prsm;
	uint32_t thresh, len;
	int maxseg;
	
	if (srtt == 0)
		srtt = 1;
	if (rack->r_ctl.rc_tlp_threshold)
		thresh = srtt + (srtt / rack->r_ctl.rc_tlp_threshold);
	else thresh = (srtt * 2);
	
	
	maxseg = tcp_maxseg(tp);
	counter_u64_add(rack_enter_tlp_calc, 1);
	len = rsm->r_end - rsm->r_start;
	if (rack->rack_tlp_threshold_use == TLP_USE_ID) {
		
		if (((tp->snd_max - tp->snd_una) - rack->r_ctl.rc_sacked + rack->r_ctl.rc_holes_rxt) <= maxseg) {
			uint32_t alt_thresh;
			
			counter_u64_add(rack_used_tlpmethod, 1);
			alt_thresh = srtt + (srtt / 2) + rack_delayed_ack_time;
			if (alt_thresh > thresh)
				thresh = alt_thresh;
		}
	} else if (rack->rack_tlp_threshold_use == TLP_USE_TWO_ONE) {
		
		prsm = TAILQ_PREV(rsm, rack_head, r_tnext);
		if (prsm && (len <= maxseg)) {
			
			uint32_t inter_gap = 0;
			int idx, nidx;
			
			counter_u64_add(rack_used_tlpmethod, 1);
			idx = rsm->r_rtr_cnt - 1;
			nidx = prsm->r_rtr_cnt - 1;
			if (TSTMP_GEQ(rsm->r_tim_lastsent[nidx], prsm->r_tim_lastsent[idx])) {
				
				inter_gap = rsm->r_tim_lastsent[idx] - prsm->r_tim_lastsent[nidx];
			}
			thresh += inter_gap;
		} else 	if (len <= maxseg) {
			
			uint32_t alt_thresh;
			
			counter_u64_add(rack_used_tlpmethod2, 1);
			alt_thresh = srtt + (srtt / 2) + rack_delayed_ack_time;
			if (alt_thresh > thresh)
				thresh = alt_thresh;
		}
	} else if (rack->rack_tlp_threshold_use == TLP_USE_TWO_TWO) {
		
		if (len <= maxseg) {
			uint32_t alt_thresh;
			
			counter_u64_add(rack_used_tlpmethod, 1);
			alt_thresh = srtt + (srtt / 2) + rack_delayed_ack_time;
			if (alt_thresh > thresh)
				thresh = alt_thresh;
		}
	}
 	
	if (thresh > TICKS_2_MSEC(tp->t_rxtcur)) {
		thresh = TICKS_2_MSEC(tp->t_rxtcur);
	}
	
	if (thresh > rack_rto_max) {
		thresh = rack_rto_max;
	}
	
	if (thresh < rack_tlp_min) {
		thresh = rack_tlp_min;
	}
	return (thresh);
}

static struct rack_sendmap * rack_check_recovery_mode(struct tcpcb *tp, uint32_t tsused)
{
	
	struct tcp_rack *rack;
	struct rack_sendmap *rsm;
	int32_t idx;
	uint32_t srtt_cur, srtt, thresh;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (TAILQ_EMPTY(&rack->r_ctl.rc_map)) {
		return (NULL);
	}
	srtt_cur = tp->t_srtt >> TCP_RTT_SHIFT;
	srtt = TICKS_2_MSEC(srtt_cur);
	if (rack->rc_rack_rtt && (srtt > rack->rc_rack_rtt))
		srtt = rack->rc_rack_rtt;

	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (rsm == NULL)
		return (NULL);

	if (rsm->r_flags & RACK_ACKED) {
		rsm = rack_find_lowest_rsm(rack);
		if (rsm == NULL)
			return (NULL);
	}
	idx = rsm->r_rtr_cnt - 1;
	thresh = rack_calc_thresh_rack(rack, srtt, tsused);
	if (tsused < rsm->r_tim_lastsent[idx]) {
		return (NULL);
	}
	if ((tsused - rsm->r_tim_lastsent[idx]) < thresh) {
		return (NULL);
	}
	
	rack->r_ctl.rc_rsm_start = rsm->r_start;
	rack->r_ctl.rc_cwnd_at = tp->snd_cwnd;
	rack->r_ctl.rc_ssthresh_at = tp->snd_ssthresh;
	rack_cong_signal(tp, NULL, CC_NDUPACK);
	return (rsm);
}

static uint32_t rack_get_persists_timer_val(struct tcpcb *tp, struct tcp_rack *rack)
{
	int32_t t;
	int32_t tt;
	uint32_t ret_val;

	t = TICKS_2_MSEC((tp->t_srtt >> TCP_RTT_SHIFT) + ((tp->t_rttvar * 4) >> TCP_RTT_SHIFT));
	TCPT_RANGESET(tt, t * tcp_backoff[tp->t_rxtshift], tcp_persmin, tcp_persmax);
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
	rack->r_ctl.rc_hpts_flags |= PACE_TMR_PERSIT;
	ret_val = (uint32_t)tt;
	return (ret_val);
}

static uint32_t rack_timer_start(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	
	uint32_t thresh, exp, to, srtt, time_since_sent;
	uint32_t srtt_cur;
	int32_t idx;
	int32_t is_tlp_timer = 0;
	struct rack_sendmap *rsm;
	
	if (rack->t_timers_stopped) {
		
		return (0);
	}
	if (rack->rc_in_persist) {
		
		return (rack_get_persists_timer_val(tp, rack));
	}
	if (tp->t_state < TCPS_ESTABLISHED)
		goto activate_rxt;
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (rsm == NULL) {
		
activate_rxt:
		if (SEQ_LT(tp->snd_una, tp->snd_max) || sbavail(&(tp->t_inpcb->inp_socket->so_snd))) {
			rack->r_ctl.rc_hpts_flags |= PACE_TMR_RXT;
			to = TICKS_2_MSEC(tp->t_rxtcur);
			if (to == 0)
				to = 1;
			return (to);
		}
		return (0);
	}
	if (rsm->r_flags & RACK_ACKED) {
		rsm = rack_find_lowest_rsm(rack);
		if (rsm == NULL) {
			
			goto activate_rxt;
		}
	}
	
	if (rsm->r_flags & RACK_SACK_PASSED) {
		if ((tp->t_flags & TF_SENTFIN) && ((tp->snd_max - tp->snd_una) == 1) && (rsm->r_flags & RACK_HAS_FIN)) {

			
			goto activate_rxt;
		}
		if (tp->t_srtt) {
			srtt_cur = (tp->t_srtt >> TCP_RTT_SHIFT);
			srtt = TICKS_2_MSEC(srtt_cur);
		} else srtt = RACK_INITIAL_RTO;

		thresh = rack_calc_thresh_rack(rack, srtt, cts);
		idx = rsm->r_rtr_cnt - 1;
		exp = rsm->r_tim_lastsent[idx] + thresh;
		if (SEQ_GEQ(exp, cts)) {
			to = exp - cts;
			if (to < rack->r_ctl.rc_min_to) {
				to = rack->r_ctl.rc_min_to;
			}
		} else {
			to = rack->r_ctl.rc_min_to;
		}
	} else {
		
		if ((rack->rc_tlp_in_progress != 0) || (rack->r_ctl.rc_tlp_rtx_out != 0)) {
			
			goto activate_rxt;
		}
		rsm = TAILQ_LAST_FAST(&rack->r_ctl.rc_tmap, rack_sendmap, r_tnext);
		if (rsm == NULL) {
			
			goto activate_rxt;
		}
		if (rsm->r_flags & RACK_HAS_FIN) {
			
			rsm = NULL;
			goto activate_rxt;
		}
		idx = rsm->r_rtr_cnt - 1;
		if (TSTMP_GT(cts,  rsm->r_tim_lastsent[idx])) 
			time_since_sent = cts - rsm->r_tim_lastsent[idx];
		else time_since_sent = 0;
		is_tlp_timer = 1;
		if (tp->t_srtt) {
			srtt_cur = (tp->t_srtt >> TCP_RTT_SHIFT);
			srtt = TICKS_2_MSEC(srtt_cur);
		} else srtt = RACK_INITIAL_RTO;
		thresh = rack_calc_thresh_tlp(tp, rack, rsm, srtt);
		if (thresh > time_since_sent)
			to = thresh - time_since_sent;
		else to = rack->r_ctl.rc_min_to;
		if (to > TCPTV_REXMTMAX) {
			
			goto activate_rxt;
		}
		if (rsm->r_start != rack->r_ctl.rc_last_tlp_seq) {
			
			rack->r_ctl.rc_tlp_seg_send_cnt = 0;
			rack->r_ctl.rc_last_tlp_seq = rsm->r_start;
		}
	}
	if (is_tlp_timer == 0) {
		rack->r_ctl.rc_hpts_flags |= PACE_TMR_RACK;
	} else {
		if ((rack->r_ctl.rc_tlp_send_cnt > rack_tlp_max_resend) || (rack->r_ctl.rc_tlp_seg_send_cnt > rack_tlp_max_resend)) {
			
			goto activate_rxt;
		} else {
			rack->r_ctl.rc_hpts_flags |= PACE_TMR_TLP;
		}
	}
	if (to == 0)
		to = 1;
	return (to);
}

static void rack_enter_persist(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	if (rack->rc_in_persist == 0) {
		if (((tp->t_flags & TF_SENTFIN) == 0) && (tp->snd_max - tp->snd_una) >= sbavail(&rack->rc_inp->inp_socket->so_snd))
			
			return;
		rack->r_ctl.rc_went_idle_time = cts;
		rack_timer_cancel(tp, rack, cts, __LINE__);
		tp->t_rxtshift = 0;
		rack->rc_in_persist = 1;
	}
}

static void rack_exit_persist(struct tcpcb *tp, struct tcp_rack *rack)
{
	if (rack->rc_inp->inp_in_hpts)  {
		tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
		rack->r_ctl.rc_hpts_flags  = 0;
	}
	rack->rc_in_persist = 0;
	rack->r_ctl.rc_went_idle_time = 0;
	tp->t_flags &= ~TF_FORCEDATA;
	tp->t_rxtshift = 0;
}

static void rack_start_hpts_timer(struct tcp_rack *rack, struct tcpcb *tp, uint32_t cts, int32_t line, int32_t slot, uint32_t tot_len_this_send, int32_t frm_out_sbavail)

{
	struct inpcb *inp;
	uint32_t delayed_ack = 0;
	uint32_t hpts_timeout;
	uint8_t stopped;
	uint32_t left = 0;

	inp = tp->t_inpcb;
	if (inp->inp_in_hpts) {
		
		return;
	}
	if (tp->t_state == TCPS_CLOSED) {
		return;
	}
	stopped = rack->rc_tmr_stopped;
	if (stopped && TSTMP_GT(rack->r_ctl.rc_timer_exp, cts)) {
		left = rack->r_ctl.rc_timer_exp - cts;
	}
	rack->r_ctl.rc_timer_exp = 0;
	if (rack->rc_inp->inp_in_hpts == 0) {
		rack->r_ctl.rc_hpts_flags = 0;
	} 
	if (slot) {
		
		rack->r_ctl.rc_hpts_flags |= PACE_PKT_OUTPUT;
	} else if (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) {
		
		if (TSTMP_GT(cts, rack->r_ctl.rc_last_output_to))
			slot = cts - rack->r_ctl.rc_last_output_to;
		else slot = 1;
	}
	if ((tp->snd_wnd == 0) && TCPS_HAVEESTABLISHED(tp->t_state)) {
		
		rack_enter_persist(tp, rack, cts);
	} else if ((frm_out_sbavail && (frm_out_sbavail > (tp->snd_max - tp->snd_una)) && (tp->snd_wnd < tp->t_maxseg)) && TCPS_HAVEESTABLISHED(tp->t_state)) {


		
		rack_enter_persist(tp, rack, cts);
	}
	hpts_timeout = rack_timer_start(tp, rack, cts);
	if (tp->t_flags & TF_DELACK) {
		delayed_ack = TICKS_2_MSEC(tcp_delacktime);
		rack->r_ctl.rc_hpts_flags |= PACE_TMR_DELACK;
	}
	if (delayed_ack && ((hpts_timeout == 0) || (delayed_ack < hpts_timeout)))
		hpts_timeout = delayed_ack;
	else  rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_DELACK;
	
	if ((hpts_timeout == 0) && (slot == 0)) {
		if ((tcp_always_keepalive || inp->inp_socket->so_options & SO_KEEPALIVE) && (tp->t_state <= TCPS_CLOSING)) {
			
			if (TCPS_HAVEESTABLISHED(tp->t_state)) {
				
				hpts_timeout = TP_KEEPIDLE(tp);
			} else {
				
				hpts_timeout = TP_KEEPINIT(tp);
			}
			rack->r_ctl.rc_hpts_flags |= PACE_TMR_KEEP;
		}
	}
	if (left && (stopped & (PACE_TMR_KEEP | PACE_TMR_DELACK)) == (rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK)) {
		
		if (left < hpts_timeout)
			hpts_timeout = left;
	}
	if (hpts_timeout) {
		
		if (hpts_timeout > 0x7ffffffe)
			hpts_timeout = 0x7ffffffe;
		rack->r_ctl.rc_timer_exp = cts + hpts_timeout;
	}
	if (slot) {
		rack->r_ctl.rc_last_output_to = cts + slot;
		if ((hpts_timeout == 0) || (hpts_timeout > slot)) {
			if (rack->rc_inp->inp_in_hpts == 0)
				tcp_hpts_insert(tp->t_inpcb, HPTS_MS_TO_SLOTS(slot));
			rack_log_to_start(rack, cts, hpts_timeout, slot, 1);
		} else {
			
			if (rack->rc_inp->inp_in_hpts == 0)
				tcp_hpts_insert(tp->t_inpcb, HPTS_MS_TO_SLOTS(hpts_timeout));
			rack_log_to_start(rack, cts, hpts_timeout, slot, 0);
		}
	} else if (hpts_timeout) {
		if (rack->rc_inp->inp_in_hpts == 0)
			tcp_hpts_insert(tp->t_inpcb, HPTS_MS_TO_SLOTS(hpts_timeout));
		rack_log_to_start(rack, cts, hpts_timeout, slot, 0);
	} else {
		

		if (SEQ_GT(tp->snd_max, tp->snd_una)) {
			panic("tp:%p rack:%p tlts:%d cts:%u slot:%u pto:%u -- no timer started?", tp, rack, tot_len_this_send, cts, slot, hpts_timeout);
		}

	}
	rack->rc_tmr_stopped = 0;
	if (slot)
		rack_log_type_bbrsnd(rack, tot_len_this_send, slot, cts);
}


static int rack_timeout_rack(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	
	struct rack_sendmap *rsm;
	int32_t recovery;

	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	if (TSTMP_LT(cts, rack->r_ctl.rc_timer_exp)) {
		
		return (0);
	}
	rack_log_to_event(rack, RACK_TO_FRM_RACK);
	recovery = IN_RECOVERY(tp->t_flags);
	counter_u64_add(rack_to_tot, 1);
	if (rack->r_state && (rack->r_state != tp->t_state))
		rack_set_state(tp, rack);
	rsm = rack_check_recovery_mode(tp, cts);
	if (rsm) {
		uint32_t rtt;

		rtt = rack->rc_rack_rtt;
		if (rtt == 0)
			rtt = 1;
		if ((recovery == 0) && (rack->r_ctl.rc_prr_sndcnt < tp->t_maxseg)) {
			
			rack->r_ctl.rc_prr_sndcnt = tp->t_maxseg;
		} else if ((rack->r_ctl.rc_prr_sndcnt < tp->t_maxseg) && ((rsm->r_end - rsm->r_start) > rack->r_ctl.rc_prr_sndcnt)) {
			
			rack->r_ctl.rc_prr_sndcnt = tp->t_maxseg;
		}
	} else {
		
		counter_u64_add(rack_tlp_does_nada, 1);

		tcp_log_dump_tp_logbuf(tp, "nada counter trips", M_NOWAIT, true);

		rack->r_ctl.rc_resend = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	}
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_RACK;
	return (0);
}


static int rack_timeout_tlp(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	
	struct rack_sendmap *rsm = NULL;
	struct socket *so;
	uint32_t amm, old_prr_snd = 0;
	uint32_t out, avail;

	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	if (TSTMP_LT(cts, rack->r_ctl.rc_timer_exp)) {
		
		return (0);
	}
	if (rack_progress_timeout_check(tp)) {
		tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
		return (1);
	}
	
	rack_log_to_event(rack, RACK_TO_FRM_TLP);
	counter_u64_add(rack_tlp_tot, 1);
	if (rack->r_state && (rack->r_state != tp->t_state))
		rack_set_state(tp, rack);
	so = tp->t_inpcb->inp_socket;
	avail = sbavail(&so->so_snd);
	out = tp->snd_max - tp->snd_una;
	rack->rc_timer_up = 1;
	
	if ((avail > out) && ((rack_always_send_oldest == 0) || (TAILQ_EMPTY(&rack->r_ctl.rc_tmap)))) {
		
		amm = avail - out;
		if (amm > tp->t_maxseg) {
			amm = tp->t_maxseg;
		} else if ((amm < tp->t_maxseg) && ((tp->t_flags & TF_NODELAY) == 0)) {
			
			goto need_retran;
		}
		if (IN_RECOVERY(tp->t_flags)) {
			
			old_prr_snd = rack->r_ctl.rc_prr_sndcnt;
			if (out + amm <= tp->snd_wnd)
				rack->r_ctl.rc_prr_sndcnt = amm;
			else goto need_retran;
		} else {
			
			if (out + amm <= tp->snd_wnd)
				rack->r_ctl.rc_tlp_new_data = amm;
			else goto need_retran;
		}
		rack->r_ctl.rc_tlp_seg_send_cnt = 0;
		rack->r_ctl.rc_last_tlp_seq = tp->snd_max;
		rack->r_ctl.rc_tlpsend = NULL;
		counter_u64_add(rack_tlp_newdata, 1);
		goto send;
	}
need_retran:
	
	if (rack_always_send_oldest)
		rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	else {
		rsm = TAILQ_LAST_FAST(&rack->r_ctl.rc_map, rack_sendmap, r_next);
		if (rsm && (rsm->r_flags & (RACK_ACKED | RACK_HAS_FIN))) {
			rsm = rack_find_high_nonack(rack, rsm);
		}
	}
	if (rsm == NULL) {
		counter_u64_add(rack_tlp_does_nada, 1);

		tcp_log_dump_tp_logbuf(tp, "nada counter trips", M_NOWAIT, true);

		goto out;
	}
	if ((rsm->r_end - rsm->r_start) > tp->t_maxseg) {
		
		int32_t idx;
		struct rack_sendmap *nrsm;

		nrsm = rack_alloc(rack);
		if (nrsm == NULL) {
			
			counter_u64_add(rack_tlp_does_nada, 1);
			goto out;
		}
		nrsm->r_start = (rsm->r_end - tp->t_maxseg);
		nrsm->r_end = rsm->r_end;
		nrsm->r_rtr_cnt = rsm->r_rtr_cnt;
		nrsm->r_flags = rsm->r_flags;
		nrsm->r_sndcnt = rsm->r_sndcnt;
		nrsm->r_rtr_bytes = 0;
		rsm->r_end = nrsm->r_start;
		for (idx = 0; idx < nrsm->r_rtr_cnt; idx++) {
			nrsm->r_tim_lastsent[idx] = rsm->r_tim_lastsent[idx];
		}
		TAILQ_INSERT_AFTER(&rack->r_ctl.rc_map, rsm, nrsm, r_next);
		if (rsm->r_in_tmap) {
			TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
			nrsm->r_in_tmap = 1;
		}
		rsm->r_flags &= (~RACK_HAS_FIN);
		rsm = nrsm;
	}
	rack->r_ctl.rc_tlpsend = rsm;
	rack->r_ctl.rc_tlp_rtx_out = 1;
	if (rsm->r_start == rack->r_ctl.rc_last_tlp_seq) {
		rack->r_ctl.rc_tlp_seg_send_cnt++;
		tp->t_rxtshift++;
	} else {
		rack->r_ctl.rc_last_tlp_seq = rsm->r_start;
		rack->r_ctl.rc_tlp_seg_send_cnt = 1;
	}
send:
	rack->r_ctl.rc_tlp_send_cnt++;
	if (rack->r_ctl.rc_tlp_send_cnt > rack_tlp_max_resend) {
		
restore:
		rack->r_ctl.rc_tlpsend = NULL;
		if (rsm)
			rsm->r_flags &= ~RACK_TLP;
		rack->r_ctl.rc_prr_sndcnt = old_prr_snd;
		counter_u64_add(rack_tlp_retran_fail, 1);
		goto out;
	} else if (rsm) {
		rsm->r_flags |= RACK_TLP;
	}
	if (rsm && (rsm->r_start == rack->r_ctl.rc_last_tlp_seq) && (rack->r_ctl.rc_tlp_seg_send_cnt > rack_tlp_max_resend)) {
		
		goto restore;
	}
	rack->r_timer_override = 1;
	rack->r_tlp_running = 1;
	rack->rc_tlp_in_progress = 1;
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_TLP;
	return (0);
out:
	rack->rc_timer_up = 0;
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_TLP;
	return (0);
}


static int rack_timeout_delack(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	rack_log_to_event(rack, RACK_TO_FRM_DELACK);
	tp->t_flags &= ~TF_DELACK;
	tp->t_flags |= TF_ACKNOW;
	TCPSTAT_INC(tcps_delack);
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_DELACK;
	return (0);
}


static int rack_timeout_persist(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	struct inpcb *inp;
	int32_t retval = 0;

	inp = tp->t_inpcb;

	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	if (rack->rc_in_persist == 0)
		return (0);
	if (rack_progress_timeout_check(tp)) {
		tcp_set_inp_to_drop(inp, ETIMEDOUT);
		return (1);
	}
	KASSERT(inp != NULL, ("%s: tp %p tp->t_inpcb == NULL", __func__, tp));
	
	TCPSTAT_INC(tcps_persisttimeo);
	
	if (tp->t_rxtshift == TCP_MAXRXTSHIFT && (ticks - tp->t_rcvtime >= tcp_maxpersistidle || ticks - tp->t_rcvtime >= TCP_REXMTVAL(tp) * tcp_totbackoff)) {

		TCPSTAT_INC(tcps_persistdrop);
		retval = 1;
		tcp_set_inp_to_drop(rack->rc_inp, ETIMEDOUT);
		goto out;
	}
	if ((sbavail(&rack->rc_inp->inp_socket->so_snd) == 0) && tp->snd_una == tp->snd_max)
		rack_exit_persist(tp, rack);
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_PERSIT;
	
	if (tp->t_state > TCPS_CLOSE_WAIT && (ticks - tp->t_rcvtime) >= TCPTV_PERSMAX) {
		retval = 1;
		TCPSTAT_INC(tcps_persistdrop);
		tcp_set_inp_to_drop(rack->rc_inp, ETIMEDOUT);
		goto out;
	}
	tp->t_flags |= TF_FORCEDATA;
out:
	rack_log_to_event(rack, RACK_TO_FRM_PERSIST);
	return (retval);
}


static int rack_timeout_keepalive(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	struct tcptemp *t_template;
	struct inpcb *inp;

	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_KEEP;
	inp = tp->t_inpcb;
	rack_log_to_event(rack, RACK_TO_FRM_KEEP);
	
	TCPSTAT_INC(tcps_keeptimeo);
	if (tp->t_state < TCPS_ESTABLISHED)
		goto dropit;
	if ((tcp_always_keepalive || inp->inp_socket->so_options & SO_KEEPALIVE) && tp->t_state <= TCPS_CLOSING) {
		if (ticks - tp->t_rcvtime >= TP_KEEPIDLE(tp) + TP_MAXIDLE(tp))
			goto dropit;
		
		TCPSTAT_INC(tcps_keepprobe);
		t_template = tcpip_maketemplate(inp);
		if (t_template) {
			tcp_respond(tp, t_template->tt_ipgen, &t_template->tt_t, (struct mbuf *)NULL, tp->rcv_nxt, tp->snd_una - 1, 0);

			free(t_template, M_TEMP);
		}
	}
	rack_start_hpts_timer(rack, tp, cts, __LINE__, 0, 0, 0);
	return (1);
dropit:
	TCPSTAT_INC(tcps_keepdrops);
	tcp_set_inp_to_drop(rack->rc_inp, ETIMEDOUT);
	return (1);
}


static void rack_remxt_tmr(struct tcpcb *tp)
{
	
	struct rack_sendmap *rsm, *trsm = NULL;
	struct tcp_rack *rack;
	int32_t cnt = 0;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	rack_timer_cancel(tp, rack, tcp_ts_getticks(), __LINE__);
	rack_log_to_event(rack, RACK_TO_FRM_TMR);
	if (rack->r_state && (rack->r_state != tp->t_state))
		rack_set_state(tp, rack);
	
	TAILQ_FOREACH(rsm, &rack->r_ctl.rc_map, r_next) {
		if (rsm->r_flags & RACK_ACKED) {
			cnt++;
			rsm->r_sndcnt = 0;
			if (rsm->r_in_tmap == 0) {
				
				if (trsm == NULL) {
					TAILQ_INSERT_HEAD(&rack->r_ctl.rc_tmap, rsm, r_tnext);
				} else {
					TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, trsm, rsm, r_tnext);
				}
				rsm->r_in_tmap = 1;
				trsm = rsm;
			}
		}
		rsm->r_flags &= ~(RACK_ACKED | RACK_SACK_PASSED | RACK_WAS_SACKPASS);
	}
	
	rack->r_ctl.rc_sacked = 0;
	
	rack->r_ctl.rc_tlp_rtx_out = 0;
	rack->r_ctl.rc_tlp_seg_send_cnt = 0;
	rack->r_ctl.rc_resend = TAILQ_FIRST(&rack->r_ctl.rc_map);
	
	if (rack->r_ctl.rc_prr_sndcnt < tp->t_maxseg)
		rack->r_ctl.rc_prr_sndcnt = tp->t_maxseg;
	rack->r_timer_override = 1;
}


static int rack_timeout_rxt(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts)
{
	int32_t rexmt;
	struct inpcb *inp;
	int32_t retval = 0;

	inp = tp->t_inpcb;
	if (tp->t_timers->tt_flags & TT_STOPPED) {
		return (1);
	}
	if (rack_progress_timeout_check(tp)) {
		tcp_set_inp_to_drop(inp, ETIMEDOUT);
		return (1);
	}
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_RXT;
	if (TCPS_HAVEESTABLISHED(tp->t_state) && (tp->snd_una == tp->snd_max)) {
		
		return (0);
	}
	
	if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
		tp->t_rxtshift = TCP_MAXRXTSHIFT;
		TCPSTAT_INC(tcps_timeoutdrop);
		retval = 1;
		tcp_set_inp_to_drop(rack->rc_inp, (tp->t_softerror ? (uint16_t) tp->t_softerror : ETIMEDOUT));
		goto out;
	}
	rack_remxt_tmr(tp);
	if (tp->t_state == TCPS_SYN_SENT) {
		
		tp->snd_cwnd = 1;
	} else if (tp->t_rxtshift == 1) {
		
		tp->snd_cwnd_prev = tp->snd_cwnd;
		tp->snd_ssthresh_prev = tp->snd_ssthresh;
		tp->snd_recover_prev = tp->snd_recover;
		if (IN_FASTRECOVERY(tp->t_flags))
			tp->t_flags |= TF_WASFRECOVERY;
		else tp->t_flags &= ~TF_WASFRECOVERY;
		if (IN_CONGRECOVERY(tp->t_flags))
			tp->t_flags |= TF_WASCRECOVERY;
		else tp->t_flags &= ~TF_WASCRECOVERY;
		tp->t_badrxtwin = ticks + (tp->t_srtt >> (TCP_RTT_SHIFT + 1));
		tp->t_flags |= TF_PREVVALID;
	} else tp->t_flags &= ~TF_PREVVALID;
	TCPSTAT_INC(tcps_rexmttimeo);
	if ((tp->t_state == TCPS_SYN_SENT) || (tp->t_state == TCPS_SYN_RECEIVED))
		rexmt = MSEC_2_TICKS(RACK_INITIAL_RTO * tcp_backoff[tp->t_rxtshift]);
	else rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
	TCPT_RANGESET(tp->t_rxtcur, rexmt, max(MSEC_2_TICKS(rack_rto_min), rexmt), MSEC_2_TICKS(rack_rto_max));

	
	if (V_tcp_pmtud_blackhole_detect && (((tp->t_state == TCPS_ESTABLISHED))
	    || (tp->t_state == TCPS_FIN_WAIT_1))) {

		int32_t isipv6;


		
		if (((tp->t_flags2 & (TF2_PLPMTU_PMTUD | TF2_PLPMTU_MAXSEGSNT)) == (TF2_PLPMTU_PMTUD | TF2_PLPMTU_MAXSEGSNT)) && (tp->t_rxtshift >= 2 && tp->t_rxtshift < 6 && tp->t_rxtshift % 2 == 0)) {


			
			if ((tp->t_flags2 & TF2_PLPMTU_BLACKHOLE) == 0) {
				
				tp->t_flags2 |= TF2_PLPMTU_BLACKHOLE;
				
				tp->t_pmtud_saved_maxseg = tp->t_maxseg;
			}

			

			isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV6) ? 1 : 0;
			if (isipv6 && tp->t_maxseg > V_tcp_v6pmtud_blackhole_mss) {
				
				tp->t_maxseg = V_tcp_v6pmtud_blackhole_mss;
				TCPSTAT_INC(tcps_pmtud_blackhole_activated);
			} else if (isipv6) {
				
				tp->t_maxseg = V_tcp_v6mssdflt;
				
				tp->t_flags2 &= ~TF2_PLPMTU_PMTUD;
				TCPSTAT_INC(tcps_pmtud_blackhole_activated_min_mss);
			}


			else   if (tp->t_maxseg > V_tcp_pmtud_blackhole_mss) {


				
				tp->t_maxseg = V_tcp_pmtud_blackhole_mss;
				TCPSTAT_INC(tcps_pmtud_blackhole_activated);
			} else {
				
				tp->t_maxseg = V_tcp_mssdflt;
				
				tp->t_flags2 &= ~TF2_PLPMTU_PMTUD;
				TCPSTAT_INC(tcps_pmtud_blackhole_activated_min_mss);
			}

		} else {
			
			if ((tp->t_flags2 & TF2_PLPMTU_BLACKHOLE) && (tp->t_rxtshift >= 6)) {
				tp->t_flags2 |= TF2_PLPMTU_PMTUD;
				tp->t_flags2 &= ~TF2_PLPMTU_BLACKHOLE;
				tp->t_maxseg = tp->t_pmtud_saved_maxseg;
				TCPSTAT_INC(tcps_pmtud_blackhole_failed);
			}
		}
	}
	
	if (tcp_rexmit_drop_options && (tp->t_state == TCPS_SYN_SENT) && (tp->t_rxtshift == 3))
		tp->t_flags &= ~(TF_REQ_SCALE | TF_REQ_TSTMP | TF_SACK_PERMIT);
	
	if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {

		if ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0)
			in6_losing(tp->t_inpcb);
		else  in_losing(tp->t_inpcb);

		tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
		tp->t_srtt = 0;
	}
	if (rack_use_sack_filter)
		sack_filter_clear(&rack->r_ctl.rack_sf, tp->snd_una);
	tp->snd_recover = tp->snd_max;
	tp->t_flags |= TF_ACKNOW;
	tp->t_rtttime = 0;
	rack_cong_signal(tp, NULL, CC_RTO);
out:
	return (retval);
}

static int rack_process_timers(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts, uint8_t hpts_calling)
{
	int32_t ret = 0;
	int32_t timers = (rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK);

	if (timers == 0) {
		return (0);
	}
	if (tp->t_state == TCPS_LISTEN) {
		
		if (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)
			return (0);
		return (1);
	}
	if (TSTMP_LT(cts, rack->r_ctl.rc_timer_exp)) {
		uint32_t left;

		if (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) {
			ret = -1;
			rack_log_to_processing(rack, cts, ret, 0);
			return (0);
		}
		if (hpts_calling == 0) {
			ret = -2;
			rack_log_to_processing(rack, cts, ret, 0);
			return (0);
		}
		
		ret = -3;
		left = rack->r_ctl.rc_timer_exp - cts;
		tcp_hpts_insert(tp->t_inpcb, HPTS_MS_TO_SLOTS(left));
		rack_log_to_processing(rack, cts, ret, left);
		rack->rc_last_pto_set = 0;
		return (1);
	}
	rack->rc_tmr_stopped = 0;
	rack->r_ctl.rc_hpts_flags &= ~PACE_TMR_MASK;
	if (timers & PACE_TMR_DELACK) {
		ret = rack_timeout_delack(tp, rack, cts);
	} else if (timers & PACE_TMR_RACK) {
		ret = rack_timeout_rack(tp, rack, cts);
	} else if (timers & PACE_TMR_TLP) {
		ret = rack_timeout_tlp(tp, rack, cts);
	} else if (timers & PACE_TMR_RXT) {
		ret = rack_timeout_rxt(tp, rack, cts);
	} else if (timers & PACE_TMR_PERSIT) {
		ret = rack_timeout_persist(tp, rack, cts);
	} else if (timers & PACE_TMR_KEEP) {
		ret = rack_timeout_keepalive(tp, rack, cts);
	}
	rack_log_to_processing(rack, cts, ret, timers);
	return (ret);
}

static void rack_timer_cancel(struct tcpcb *tp, struct tcp_rack *rack, uint32_t cts, int line)
{
	uint8_t hpts_removed = 0;

	if ((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) && TSTMP_GEQ(cts, rack->r_ctl.rc_last_output_to)) {
		tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
		hpts_removed = 1;
	}
	if (rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK) {
		rack->rc_tmr_stopped = rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK;
		if (rack->rc_inp->inp_in_hpts && ((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) == 0)) {
			
			tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
			hpts_removed = 1;
		}
		rack_log_to_cancel(rack, hpts_removed, line);
		rack->r_ctl.rc_hpts_flags &= ~(PACE_TMR_MASK);
	}
}

static void rack_timer_stop(struct tcpcb *tp, uint32_t timer_type)
{
	return;
}

static int rack_stopall(struct tcpcb *tp)
{
	struct tcp_rack *rack;
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	rack->t_timers_stopped = 1;
	return (0);
}

static void rack_timer_activate(struct tcpcb *tp, uint32_t timer_type, uint32_t delta)
{
	return;
}

static int rack_timer_active(struct tcpcb *tp, uint32_t timer_type)
{
	return (0);
}

static void rack_stop_all_timers(struct tcpcb *tp)
{
	struct tcp_rack *rack;

	
	if (tcp_timer_active(tp, TT_PERSIST)) {
		
		rack = (struct tcp_rack *)tp->t_fb_ptr;
		rack->rc_in_persist = 1;
	}
	tcp_timer_suspend(tp, TT_PERSIST);
	tcp_timer_suspend(tp, TT_REXMT);
	tcp_timer_suspend(tp, TT_KEEP);
	tcp_timer_suspend(tp, TT_DELACK);
}

static void rack_update_rsm(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm, uint32_t ts)

{
	int32_t idx;

	rsm->r_rtr_cnt++;
	rsm->r_sndcnt++;
	if (rsm->r_rtr_cnt > RACK_NUM_OF_RETRANS) {
		rsm->r_rtr_cnt = RACK_NUM_OF_RETRANS;
		rsm->r_flags |= RACK_OVERMAX;
	}
	if ((rsm->r_rtr_cnt > 1) && (rack->r_tlp_running == 0)) {
		rack->r_ctl.rc_holes_rxt += (rsm->r_end - rsm->r_start);
		rsm->r_rtr_bytes += (rsm->r_end - rsm->r_start);
	}
	idx = rsm->r_rtr_cnt - 1;
	rsm->r_tim_lastsent[idx] = ts;
	if (rsm->r_flags & RACK_ACKED) {
		
		rsm->r_flags &= ~RACK_ACKED;
		rack->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);
	}
	if (rsm->r_in_tmap) {
		TAILQ_REMOVE(&rack->r_ctl.rc_tmap, rsm, r_tnext);
	}
	TAILQ_INSERT_TAIL(&rack->r_ctl.rc_tmap, rsm, r_tnext);
	rsm->r_in_tmap = 1;
	if (rsm->r_flags & RACK_SACK_PASSED) {
		
		rsm->r_flags &= ~RACK_SACK_PASSED;
		rsm->r_flags |= RACK_WAS_SACKPASS;
	}
	
	rack->r_ctl.rc_next = TAILQ_NEXT(rsm, r_next);
}


static uint32_t rack_update_entry(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm, uint32_t ts, int32_t * lenp)

{
	
	struct rack_sendmap *nrsm;
	uint32_t c_end;
	int32_t len;
	int32_t idx;

	len = *lenp;
	c_end = rsm->r_start + len;
	if (SEQ_GEQ(c_end, rsm->r_end)) {
		
		rack_update_rsm(tp, rack, rsm, ts);
		if (c_end == rsm->r_end) {
			*lenp = 0;
			return (0);
		} else {
			int32_t act_len;

			
			act_len = rsm->r_end - rsm->r_start;
			*lenp = (len - act_len);
			return (rsm->r_end);
		}
		
	}
	
	nrsm = rack_alloc(rack);
	if (nrsm == NULL) {
		
		*lenp = 0;
		return (0);
	}
	
	nrsm->r_start = c_end;
	nrsm->r_end = rsm->r_end;
	nrsm->r_rtr_cnt = rsm->r_rtr_cnt;
	nrsm->r_flags = rsm->r_flags;
	nrsm->r_sndcnt = rsm->r_sndcnt;
	nrsm->r_rtr_bytes = 0;
	rsm->r_end = c_end;
	for (idx = 0; idx < nrsm->r_rtr_cnt; idx++) {
		nrsm->r_tim_lastsent[idx] = rsm->r_tim_lastsent[idx];
	}
	TAILQ_INSERT_AFTER(&rack->r_ctl.rc_map, rsm, nrsm, r_next);
	if (rsm->r_in_tmap) {
		TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
		nrsm->r_in_tmap = 1;
	}
	rsm->r_flags &= (~RACK_HAS_FIN);
	rack_update_rsm(tp, rack, rsm, ts);
	*lenp = 0;
	return (0);
}


static void rack_log_output(struct tcpcb *tp, struct tcpopt *to, int32_t len, uint32_t seq_out, uint8_t th_flags, int32_t err, uint32_t ts, uint8_t pass, struct rack_sendmap *hintrsm)


{
	struct tcp_rack *rack;
	struct rack_sendmap *rsm, *nrsm;
	register uint32_t snd_max, snd_una;
	int32_t idx;

	
	
	INP_WLOCK_ASSERT(tp->t_inpcb);
	if (err)
		
		return;

	if (th_flags & TH_RST) {
		
		return;
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	snd_una = tp->snd_una;
	if (SEQ_LEQ((seq_out + len), snd_una)) {
		
		return;
	}
	if (SEQ_LT(seq_out, snd_una)) {
		
		uint32_t end;

		end = seq_out + len;
		seq_out = snd_una;
		len = end - seq_out;
	}
	snd_max = tp->snd_max;
	if (th_flags & (TH_SYN | TH_FIN)) {
		
		if (th_flags & TH_SYN)
			len++;
		if (th_flags & TH_FIN)
			len++;
		if (SEQ_LT(snd_max, tp->snd_nxt)) {
			
			snd_max = tp->snd_nxt;
		}
	}
	if (len == 0) {
		
		return;
	}
	rack->r_ctl.rc_time_last_sent = ts;
	if (IN_RECOVERY(tp->t_flags)) {
		rack->r_ctl.rc_prr_out += len;
	}
	
	if (seq_out == snd_max) {
again:
		rsm = rack_alloc(rack);
		if (rsm == NULL) {
			

			panic("Out of memory when we should not be rack:%p", rack);

			return;
		}
		if (th_flags & TH_FIN) {
			rsm->r_flags = RACK_HAS_FIN;
		} else {
			rsm->r_flags = 0;
		}
		rsm->r_tim_lastsent[0] = ts;
		rsm->r_rtr_cnt = 1;
		rsm->r_rtr_bytes = 0;
		if (th_flags & TH_SYN) {
			
			rsm->r_start = seq_out + 1;
			rsm->r_end = rsm->r_start + (len - 1);
		} else {
			
			rsm->r_start = seq_out;
			rsm->r_end = rsm->r_start + len;
		}
		rsm->r_sndcnt = 0;
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_map, rsm, r_next);
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 1;
		return;
	}
	
more:
	if (hintrsm && (hintrsm->r_start == seq_out)) {
		rsm = hintrsm;
		hintrsm = NULL;
	} else if (rack->r_ctl.rc_next) {
		
		rsm = rack->r_ctl.rc_next;
	} else {
		
		rsm = NULL;
	}
	if ((rsm) && (rsm->r_start == seq_out)) {
		
		seq_out = rack_update_entry(tp, rack, rsm, ts, &len);
		if (len == 0) {
			return;
		} else {
			goto more;
		}
	}
	
	TAILQ_FOREACH(rsm, &rack->r_ctl.rc_map, r_next) {
		if (rsm->r_start == seq_out) {
			seq_out = rack_update_entry(tp, rack, rsm, ts, &len);
			rack->r_ctl.rc_next = TAILQ_NEXT(rsm, r_next);
			if (len == 0) {
				return;
			} else {
				continue;
			}
		}
		if (SEQ_GEQ(seq_out, rsm->r_start) && SEQ_LT(seq_out, rsm->r_end)) {
			
			
			nrsm = rack_alloc(rack);
			if (nrsm == NULL) {

				panic("Ran out of memory that was preallocated? rack:%p", rack);

				rack_update_rsm(tp, rack, rsm, ts);
				return;
			}
			
			nrsm->r_start = seq_out;
			nrsm->r_end = rsm->r_end;
			nrsm->r_rtr_cnt = rsm->r_rtr_cnt;
			nrsm->r_flags = rsm->r_flags;
			nrsm->r_sndcnt = rsm->r_sndcnt;
			nrsm->r_rtr_bytes = 0;
			for (idx = 0; idx < nrsm->r_rtr_cnt; idx++) {
				nrsm->r_tim_lastsent[idx] = rsm->r_tim_lastsent[idx];
			}
			rsm->r_end = nrsm->r_start;
			TAILQ_INSERT_AFTER(&rack->r_ctl.rc_map, rsm, nrsm, r_next);
			if (rsm->r_in_tmap) {
				TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
				nrsm->r_in_tmap = 1;
			}
			rsm->r_flags &= (~RACK_HAS_FIN);
			seq_out = rack_update_entry(tp, rack, nrsm, ts, &len);
			if (len == 0) {
				return;
			}
		}
	}
	
	if (seq_out == tp->snd_max) {
		goto again;
	} else if (SEQ_LT(seq_out, tp->snd_max)) {

		printf("seq_out:%u len:%d snd_una:%u snd_max:%u -- but rsm not found?\n", seq_out, len, tp->snd_una, tp->snd_max);
		printf("Starting Dump of all rack entries\n");
		TAILQ_FOREACH(rsm, &rack->r_ctl.rc_map, r_next) {
			printf("rsm:%p start:%u end:%u\n", rsm, rsm->r_start, rsm->r_end);
		}
		printf("Dump complete\n");
		panic("seq_out not found rack:%p tp:%p", rack, tp);

	} else {

		
		panic("seq_out:%u(%d) is beyond snd_max:%u tp:%p", seq_out, len, tp->snd_max, tp);

	}
}


static void tcp_rack_xmit_timer(struct tcp_rack *rack, int32_t rtt)
{
	if ((rack->r_ctl.rack_rs.rs_flags & RACK_RTT_EMPTY) || (rack->r_ctl.rack_rs.rs_rtt_lowest > rtt)) {
		rack->r_ctl.rack_rs.rs_rtt_lowest = rtt;
	}
	if ((rack->r_ctl.rack_rs.rs_flags & RACK_RTT_EMPTY) || (rack->r_ctl.rack_rs.rs_rtt_highest < rtt)) {
		rack->r_ctl.rack_rs.rs_rtt_highest = rtt;
	}
	rack->r_ctl.rack_rs.rs_flags = RACK_RTT_VALID;
	rack->r_ctl.rack_rs.rs_rtt_tot += rtt;
	rack->r_ctl.rack_rs.rs_rtt_cnt++;
}


static void tcp_rack_xmit_timer_commit(struct tcp_rack *rack, struct tcpcb *tp)
{
	int32_t delta;
	uint32_t o_srtt, o_var;
	int32_t rtt;

	if (rack->r_ctl.rack_rs.rs_flags & RACK_RTT_EMPTY)
		
		return;
	if (rack->r_ctl.rc_rate_sample_method == USE_RTT_LOW) {
		
		rtt = rack->r_ctl.rack_rs.rs_rtt_lowest;
	} else if (rack->r_ctl.rc_rate_sample_method == USE_RTT_HIGH) {
		
		rtt = rack->r_ctl.rack_rs.rs_rtt_highest;
	} else if (rack->r_ctl.rc_rate_sample_method == USE_RTT_AVG) {
		
		rtt = (int32_t)(rack->r_ctl.rack_rs.rs_rtt_tot / (uint64_t)rack->r_ctl.rack_rs.rs_rtt_cnt);
	} else {

		panic("Unknown rtt variant %d", rack->r_ctl.rc_rate_sample_method);

		return;
	}
	if (rtt == 0)
		rtt = 1;
	rack_log_rtt_sample(rack, rtt);
	o_srtt = tp->t_srtt;
	o_var = tp->t_rttvar;
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (tp->t_srtt != 0) {
		
		delta = ((rtt - 1) << TCP_DELTA_SHIFT)
		    - (tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

		tp->t_srtt += delta;
		if (tp->t_srtt <= 0)
			tp->t_srtt = 1;

		
		if (delta < 0)
			delta = -delta;
		delta -= tp->t_rttvar >> (TCP_RTTVAR_SHIFT - TCP_DELTA_SHIFT);
		tp->t_rttvar += delta;
		if (tp->t_rttvar <= 0)
			tp->t_rttvar = 1;
		if (tp->t_rttbest > tp->t_srtt + tp->t_rttvar)
			tp->t_rttbest = tp->t_srtt + tp->t_rttvar;
	} else {
		
		tp->t_srtt = rtt << TCP_RTT_SHIFT;
		tp->t_rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
		tp->t_rttbest = tp->t_srtt + tp->t_rttvar;
	}
	TCPSTAT_INC(tcps_rttupdated);
	rack_log_rtt_upd(tp, rack, rtt, o_srtt, o_var);
	tp->t_rttupdated++;

	stats_voi_update_abs_u32(tp->t_stats, VOI_TCP_RTT, imax(0, rtt));

	tp->t_rxtshift = 0;

	
	TCPT_RANGESET(tp->t_rxtcur, TCP_REXMTVAL(tp), max(MSEC_2_TICKS(rack_rto_min), rtt + 2), MSEC_2_TICKS(rack_rto_max));
	tp->t_softerror = 0;
}

static void rack_earlier_retran(struct tcpcb *tp, struct rack_sendmap *rsm, uint32_t t, uint32_t cts)

{
	
	struct tcp_rack *rack;

	if (rsm->r_flags & RACK_HAS_FIN) {
		
		return;
	}
	if (rsm->r_flags & RACK_TLP) {
		
		return;
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	
	if (IN_RECOVERY(tp->t_flags)) {
		if (rack->r_ctl.rc_rsm_start == rsm->r_start) {
			
			EXIT_RECOVERY(tp->t_flags);
			tp->snd_recover = tp->snd_una;
			if (rack->r_ctl.rc_cwnd_at > tp->snd_cwnd)
				tp->snd_cwnd = rack->r_ctl.rc_cwnd_at;
			if (rack->r_ctl.rc_ssthresh_at > tp->snd_ssthresh)
				tp->snd_ssthresh = rack->r_ctl.rc_ssthresh_at;
		}
	}
	if (rsm->r_flags & RACK_WAS_SACKPASS) {
		
		counter_u64_add(rack_reorder_seen, 1);
		rack->r_ctl.rc_reorder_ts = cts;
	}
	counter_u64_add(rack_badfr, 1);
	counter_u64_add(rack_badfr_bytes, (rsm->r_end - rsm->r_start));
}


static int rack_update_rtt(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm, struct tcpopt *to, uint32_t cts, int32_t ack_type)

{
	int32_t i;
	uint32_t t;

	if (rsm->r_flags & RACK_ACKED)
		
		return (0);


	if ((rsm->r_rtr_cnt == 1) || ((ack_type == CUM_ACKED) && (to->to_flags & TOF_TS) && (to->to_tsecr) && (rsm->r_tim_lastsent[rsm->r_rtr_cnt - 1] == to->to_tsecr))



	    ) {
		
		t = cts - rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)];
		if ((int)t <= 0)
			t = 1;
		if (!tp->t_rttlow || tp->t_rttlow > t)
			tp->t_rttlow = t;
		if (!rack->r_ctl.rc_rack_min_rtt || SEQ_LT(t, rack->r_ctl.rc_rack_min_rtt)) {
			rack->r_ctl.rc_rack_min_rtt = t;
			if (rack->r_ctl.rc_rack_min_rtt == 0) {
				rack->r_ctl.rc_rack_min_rtt = 1;
			}
		}
		tcp_rack_xmit_timer(rack, TCP_TS_TO_TICKS(t) + 1);
		if ((rsm->r_flags & RACK_TLP) && (!IN_RECOVERY(tp->t_flags))) {
			
			if (rack->r_ctl.rc_tlp_cwnd_reduce) {
				rack->r_ctl.rc_rsm_start = tp->snd_max;
				rack->r_ctl.rc_cwnd_at = tp->snd_cwnd;
				rack->r_ctl.rc_ssthresh_at = tp->snd_ssthresh;
				rack_cong_signal(tp, NULL, CC_NDUPACK);
				
				rack->r_ctl.rc_prr_sndcnt = tp->t_maxseg;
			} else rack->r_ctl.rc_tlp_rtx_out = 0;
		}
		if (SEQ_LT(rack->r_ctl.rc_rack_tmit_time, rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)])) {
			
			rack->r_ctl.rc_rack_tmit_time = rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)];
			rack->rc_rack_rtt = t;
		}
		return (1);
	}
	
	tp->t_rxtshift = 0;
	tp->t_softerror = 0;
	if ((to->to_flags & TOF_TS) && (ack_type == CUM_ACKED) && (to->to_tsecr) && ((rsm->r_flags & (RACK_DEFERRED | RACK_OVERMAX)) == 0)) {


		
		for (i = 0; i < rsm->r_rtr_cnt; i++) {
			if (rsm->r_tim_lastsent[i] == to->to_tsecr) {
				t = cts - rsm->r_tim_lastsent[i];
				if ((int)t <= 0)
					t = 1;
				if ((i + 1) < rsm->r_rtr_cnt) {
					
					rack_earlier_retran(tp, rsm, t, cts);
				}
				if (!tp->t_rttlow || tp->t_rttlow > t)
					tp->t_rttlow = t;
				if (!rack->r_ctl.rc_rack_min_rtt || SEQ_LT(t, rack->r_ctl.rc_rack_min_rtt)) {
					rack->r_ctl.rc_rack_min_rtt = t;
					if (rack->r_ctl.rc_rack_min_rtt == 0) {
						rack->r_ctl.rc_rack_min_rtt = 1;
					}
				}
                                
				if (SEQ_LT(rack->r_ctl.rc_rack_tmit_time, rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)])) {
					
					rack->r_ctl.rc_rack_tmit_time = rsm->r_tim_lastsent[(rsm->r_rtr_cnt - 1)];
					rack->rc_rack_rtt = t;
				}
				return (1);
			}
		}
		goto ts_not_found;
	} else {
		
ts_not_found:
		i = rsm->r_rtr_cnt - 1;
		t = cts - rsm->r_tim_lastsent[i];
		if ((int)t <= 0)
			t = 1;
		if (rack->r_ctl.rc_rack_min_rtt && SEQ_LT(t, rack->r_ctl.rc_rack_min_rtt)) {
			
			i = rsm->r_rtr_cnt - 2;
			t = cts - rsm->r_tim_lastsent[i];
			rack_earlier_retran(tp, rsm, t, cts);
		} else if (rack->r_ctl.rc_rack_min_rtt) {
			
			if (!rack->r_ctl.rc_rack_min_rtt || SEQ_LT(t, rack->r_ctl.rc_rack_min_rtt)) {
				rack->r_ctl.rc_rack_min_rtt = t;
				if (rack->r_ctl.rc_rack_min_rtt == 0) {
					rack->r_ctl.rc_rack_min_rtt = 1;
				}
			}
			if (SEQ_LT(rack->r_ctl.rc_rack_tmit_time, rsm->r_tim_lastsent[i])) {
				
				rack->r_ctl.rc_rack_tmit_time = rsm->r_tim_lastsent[i];
				rack->rc_rack_rtt = t;
			}
			return (1);
		}
	}
	return (0);
}


static void rack_log_sack_passed(struct tcpcb *tp, struct tcp_rack *rack, struct rack_sendmap *rsm)

{
	struct rack_sendmap *nrsm;
	uint32_t ts;
	int32_t idx;

	idx = rsm->r_rtr_cnt - 1;
	ts = rsm->r_tim_lastsent[idx];
	nrsm = rsm;
	TAILQ_FOREACH_REVERSE_FROM(nrsm, &rack->r_ctl.rc_tmap, rack_head, r_tnext) {
		if (nrsm == rsm) {
			
			continue;
		}
		if (nrsm->r_flags & RACK_ACKED) {
			
			continue;
		}
		idx = nrsm->r_rtr_cnt - 1;
		if (ts == nrsm->r_tim_lastsent[idx]) {
			
			if (SEQ_LT(nrsm->r_start, rsm->r_start)) {
				nrsm->r_flags |= RACK_SACK_PASSED;
				nrsm->r_flags &= ~RACK_WAS_SACKPASS;
			}
		} else {
			
			nrsm->r_flags |= RACK_SACK_PASSED;
			nrsm->r_flags &= ~RACK_WAS_SACKPASS;
		}
	}
}

static uint32_t rack_proc_sack_blk(struct tcpcb *tp, struct tcp_rack *rack, struct sackblk *sack, struct tcpopt *to, struct rack_sendmap **prsm, uint32_t cts)

{
	int32_t idx;
	int32_t times = 0;
	uint32_t start, end, changed = 0;
	struct rack_sendmap *rsm, *nrsm;
	int32_t used_ref = 1;

	start = sack->start;
	end = sack->end;
	rsm = *prsm;
	if (rsm && SEQ_LT(start, rsm->r_start)) {
		TAILQ_FOREACH_REVERSE_FROM(rsm, &rack->r_ctl.rc_map, rack_head, r_next) {
			if (SEQ_GEQ(start, rsm->r_start) && SEQ_LT(start, rsm->r_end)) {
				goto do_rest_ofb;
			}
		}
	}
	if (rsm == NULL) {
start_at_beginning:
		rsm = NULL;
		used_ref = 0;
	}
	
	TAILQ_FOREACH_FROM(rsm, &rack->r_ctl.rc_map, r_next) {
		if (SEQ_GEQ(start, rsm->r_start) && SEQ_LT(start, rsm->r_end)) {
			break;
		}
	}
do_rest_ofb:
	if (rsm == NULL) {
		
		if (tp->t_flags & TF_SENTFIN) {
			
			nrsm = TAILQ_LAST_FAST(&rack->r_ctl.rc_map, rack_sendmap, r_next);
			if (nrsm && (nrsm->r_end + 1) == tp->snd_max) {
				
				nrsm->r_end++;
				rsm = nrsm;
				goto do_rest_ofb;
			}
		}
		if (times == 1) {

			panic("tp:%p rack:%p sack:%p to:%p prsm:%p", tp, rack, sack, to, prsm);

			goto out;

		}
		times++;
		counter_u64_add(rack_sack_proc_restart, 1);
		goto start_at_beginning;
	}
	
	if (rsm->r_start != start) {
		
		nrsm = rack_alloc(rack);
		if (nrsm == NULL) {
			
			goto out;
		}
		nrsm->r_start = start;
		nrsm->r_rtr_bytes = 0;
		nrsm->r_end = rsm->r_end;
		nrsm->r_rtr_cnt = rsm->r_rtr_cnt;
		nrsm->r_flags = rsm->r_flags;
		nrsm->r_sndcnt = rsm->r_sndcnt;
		for (idx = 0; idx < nrsm->r_rtr_cnt; idx++) {
			nrsm->r_tim_lastsent[idx] = rsm->r_tim_lastsent[idx];
		}
		rsm->r_end = nrsm->r_start;
		TAILQ_INSERT_AFTER(&rack->r_ctl.rc_map, rsm, nrsm, r_next);
		if (rsm->r_in_tmap) {
			TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
			nrsm->r_in_tmap = 1;
		}
		rsm->r_flags &= (~RACK_HAS_FIN);
		rsm = nrsm;
	}
	if (SEQ_GEQ(end, rsm->r_end)) {
		

		if ((rsm->r_flags & RACK_ACKED) == 0) {
			rack_update_rtt(tp, rack, rsm, to, cts, SACKED);
			changed += (rsm->r_end - rsm->r_start);
			rack->r_ctl.rc_sacked += (rsm->r_end - rsm->r_start);
			rack_log_sack_passed(tp, rack, rsm);
			
			if (rsm->r_flags & RACK_SACK_PASSED) {
				counter_u64_add(rack_reorder_seen, 1);
				rack->r_ctl.rc_reorder_ts = cts;
			}
			rsm->r_flags |= RACK_ACKED;
			rsm->r_flags &= ~RACK_TLP;
			if (rsm->r_in_tmap) {
				TAILQ_REMOVE(&rack->r_ctl.rc_tmap, rsm, r_tnext);
				rsm->r_in_tmap = 0;
			}
		}
		if (end == rsm->r_end) {
			
			goto out;
		}
		
		start = rsm->r_end;
		nrsm = TAILQ_NEXT(rsm, r_next);
		rsm = nrsm;
		times = 0;
		goto do_rest_ofb;
	}
	
	nrsm = rack_alloc(rack);
	if (nrsm == NULL) {
		
		goto out;
	}
	
	nrsm->r_start = end;
	nrsm->r_end = rsm->r_end;
	nrsm->r_rtr_bytes = 0;
	nrsm->r_rtr_cnt = rsm->r_rtr_cnt;
	nrsm->r_flags = rsm->r_flags;
	nrsm->r_sndcnt = rsm->r_sndcnt;
	for (idx = 0; idx < nrsm->r_rtr_cnt; idx++) {
		nrsm->r_tim_lastsent[idx] = rsm->r_tim_lastsent[idx];
	}
	
	rsm->r_flags &= (~RACK_HAS_FIN);
	rsm->r_end = end;
	TAILQ_INSERT_AFTER(&rack->r_ctl.rc_map, rsm, nrsm, r_next);
	if (rsm->r_in_tmap) {
		TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, rsm, nrsm, r_tnext);
		nrsm->r_in_tmap = 1;
	}
	if (rsm->r_flags & RACK_ACKED) {
		
		goto out;
	}
	rack_update_rtt(tp, rack, rsm, to, cts, SACKED);
	changed += (rsm->r_end - rsm->r_start);
	rack->r_ctl.rc_sacked += (rsm->r_end - rsm->r_start);
	rack_log_sack_passed(tp, rack, rsm);
	
	if (rsm->r_flags & RACK_SACK_PASSED) {
		counter_u64_add(rack_reorder_seen, 1);
		rack->r_ctl.rc_reorder_ts = cts;
	}
	rsm->r_flags |= RACK_ACKED;
	rsm->r_flags &= ~RACK_TLP;
	if (rsm->r_in_tmap) {
		TAILQ_REMOVE(&rack->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 0;
	}
out:
	if (used_ref == 0) {
		counter_u64_add(rack_sack_proc_all, 1);
	} else {
		counter_u64_add(rack_sack_proc_short, 1);
	}
	
	if (rsm)
		rack->r_ctl.rc_sacklast = TAILQ_NEXT(rsm, r_next);
	else rack->r_ctl.rc_sacklast = NULL;
	*prsm = rsm;
	return (changed);
}

static void inline  rack_peer_reneges(struct tcp_rack *rack, struct rack_sendmap *rsm, tcp_seq th_ack)
{
	struct rack_sendmap *tmap;

	tmap = NULL;
	while (rsm && (rsm->r_flags & RACK_ACKED)) {
		
		rack->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);

		if (rsm->r_in_tmap) {
			panic("rack:%p rsm:%p flags:0x%x in tmap?", rack, rsm, rsm->r_flags);
		}

		rsm->r_flags &= ~(RACK_ACKED|RACK_SACK_PASSED|RACK_WAS_SACKPASS);
		
		if (tmap == NULL) {
			TAILQ_INSERT_HEAD(&rack->r_ctl.rc_tmap, rsm, r_tnext);
			tmap = rsm;
		} else {
			TAILQ_INSERT_AFTER(&rack->r_ctl.rc_tmap, tmap, rsm, r_tnext);
			tmap = rsm;
		}
		tmap->r_in_tmap = 1;
		rsm = TAILQ_NEXT(rsm, r_next);
	}
	
	if (rack_use_sack_filter)
		sack_filter_clear(&rack->r_ctl.rack_sf, th_ack);

}

static void rack_log_ack(struct tcpcb *tp, struct tcpopt *to, struct tcphdr *th)
{
	uint32_t changed, last_seq, entered_recovery = 0;
	struct tcp_rack *rack;
	struct rack_sendmap *rsm;
	struct sackblk sack, sack_blocks[TCP_MAX_SACK + 1];
	register uint32_t th_ack;
	int32_t i, j, k, num_sack_blks = 0;
	uint32_t cts, acked, ack_point, sack_changed = 0;

	INP_WLOCK_ASSERT(tp->t_inpcb);
	if (th->th_flags & TH_RST) {
		
		return;
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	cts = tcp_ts_getticks();
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_map);
	changed = 0;
	th_ack = th->th_ack;

	if (SEQ_GT(th_ack, tp->snd_una)) {
		rack_log_progress_event(rack, tp, ticks, PROGRESS_UPDATE, __LINE__);
		tp->t_acktime = ticks;
	}
	if (rsm && SEQ_GT(th_ack, rsm->r_start))
		changed = th_ack - rsm->r_start;
	if (changed) {
		
		rack->r_wanted_output++;
more:
		rsm = TAILQ_FIRST(&rack->r_ctl.rc_map);
		if (rsm == NULL) {
			if ((th_ack - 1) == tp->iss) {
				
				goto proc_sack;
			}
			if (tp->t_flags & TF_SENTFIN) {
				
				goto proc_sack;
			}

			panic("No rack map tp:%p for th:%p state:%d rack:%p snd_una:%u snd_max:%u snd_nxt:%u chg:%d\n", tp, th, tp->t_state, rack, tp->snd_una, tp->snd_max, tp->snd_nxt, changed);



			goto proc_sack;
		}
		if (SEQ_LT(th_ack, rsm->r_start)) {
			

			printf("Rack map starts at r_start:%u for th_ack:%u huh? ts:%d rs:%d\n", rsm->r_start, th_ack, tp->t_state, rack->r_state);


			goto proc_sack;
		}
		rack_update_rtt(tp, rack, rsm, to, cts, CUM_ACKED);
		
		if (SEQ_GEQ(th_ack, rsm->r_end)) {
			
			uint32_t left;

			rack->r_ctl.rc_holes_rxt -= rsm->r_rtr_bytes;
			rsm->r_rtr_bytes = 0;
			TAILQ_REMOVE(&rack->r_ctl.rc_map, rsm, r_next);
			if (rsm->r_in_tmap) {
				TAILQ_REMOVE(&rack->r_ctl.rc_tmap, rsm, r_tnext);
				rsm->r_in_tmap = 0;
			}
			if (rack->r_ctl.rc_next == rsm) {
				
				rack->r_ctl.rc_next = TAILQ_FIRST(&rack->r_ctl.rc_map);
			}
			if (rsm->r_flags & RACK_ACKED) {
				
				rack->r_ctl.rc_sacked -= (rsm->r_end - rsm->r_start);
			} else if (rsm->r_flags & RACK_SACK_PASSED) {
				
				counter_u64_add(rack_reorder_seen, 1);
				rsm->r_flags |= RACK_ACKED;
				rack->r_ctl.rc_reorder_ts = cts;
			}
			left = th_ack - rsm->r_end;
			if (rsm->r_rtr_cnt > 1) {
				
				rack->r_ctl.rc_loss_count += (rsm->r_rtr_cnt - 1);
			}
			
			rack_free(rack, rsm);
			if (left) {
				goto more;
			}
			goto proc_sack;
		}
		if (rsm->r_flags & RACK_ACKED) {
			
			rack->r_ctl.rc_sacked -= (th_ack - rsm->r_start);
		}
		rack->r_ctl.rc_holes_rxt -= rsm->r_rtr_bytes;
		rsm->r_rtr_bytes = 0;
		rsm->r_start = th_ack;
	}
proc_sack:
	
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_map);
	if (rsm && (rsm->r_flags & RACK_ACKED) && (th_ack == rsm->r_start)) {
		
		rack_peer_reneges(rack, rsm, th->th_ack);
	}
	if ((to->to_flags & TOF_SACK) == 0) {
		
		goto out;
	}
	rsm = TAILQ_LAST_FAST(&rack->r_ctl.rc_map, rack_sendmap, r_next);
	if (rsm) {
		last_seq = rsm->r_end;
	} else {
		last_seq = tp->snd_max;
	}
	
	if (SEQ_GT(th_ack, tp->snd_una))
		ack_point = th_ack;
	else ack_point = tp->snd_una;
	for (i = 0; i < to->to_nsacks; i++) {
		bcopy((to->to_sacks + i * TCPOLEN_SACK), &sack, sizeof(sack));
		sack.start = ntohl(sack.start);
		sack.end = ntohl(sack.end);
		if (SEQ_GT(sack.end, sack.start) && SEQ_GT(sack.start, ack_point) && SEQ_LT(sack.start, tp->snd_max) && SEQ_GT(sack.end, ack_point) && SEQ_LEQ(sack.end, tp->snd_max)) {



			if ((rack->r_ctl.rc_num_maps_alloced > rack_sack_block_limit) && (SEQ_LT(sack.end, last_seq)) && ((sack.end - sack.start) < (tp->t_maxseg / 8))) {

				
				counter_u64_add(rack_runt_sacks, 1);
				continue;
			}
			sack_blocks[num_sack_blks] = sack;
			num_sack_blks++;

		} else if (SEQ_LEQ(sack.start, th_ack) && SEQ_LEQ(sack.end, th_ack)) {
			
			tcp_record_dsack(sack.start, sack.end);

		}

	}
	if (num_sack_blks == 0)
		goto out;
	
	if (rack_use_sack_filter) {
		num_sack_blks = sack_filter_blks(&rack->r_ctl.rack_sf, sack_blocks, num_sack_blks, th->th_ack);
	}
	if (num_sack_blks < 2) {
		goto do_sack_work;
	}
	
	for (i = 0; i < num_sack_blks; i++) {
		for (j = i + 1; j < num_sack_blks; j++) {
			if (SEQ_GT(sack_blocks[i].end, sack_blocks[j].end)) {
				sack = sack_blocks[i];
				sack_blocks[i] = sack_blocks[j];
				sack_blocks[j] = sack;
			}
		}
	}
	
again:
	if (num_sack_blks > 1) {
		for (i = 0; i < num_sack_blks; i++) {
			for (j = i + 1; j < num_sack_blks; j++) {
				if (sack_blocks[i].end == sack_blocks[j].end) {
					
					if (SEQ_LT(sack_blocks[j].start, sack_blocks[i].start)) {
						
						sack_blocks[i].start = sack_blocks[j].start;
					}
					
					for (k = (j + 1); k < num_sack_blks; k++) {
						sack_blocks[j].start = sack_blocks[k].start;
						sack_blocks[j].end = sack_blocks[k].end;
						j++;
					}
					num_sack_blks--;
					goto again;
				}
			}
		}
	}
do_sack_work:
	rsm = rack->r_ctl.rc_sacklast;
	for (i = 0; i < num_sack_blks; i++) {
		acked = rack_proc_sack_blk(tp, rack, &sack_blocks[i], to, &rsm, cts);
		if (acked) {
			rack->r_wanted_output++;
			changed += acked;
			sack_changed += acked;
		}
	}
out:
	if (changed) {
		
		rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
	}
	if ((sack_changed) && (!IN_RECOVERY(tp->t_flags))) {
		
		struct rack_sendmap *rsm;
		uint32_t tsused;

		tsused = tcp_ts_getticks();
		rsm = tcp_rack_output(tp, rack, tsused);
		if (rsm) {
			
			rack->r_ctl.rc_rsm_start = rsm->r_start;
			rack->r_ctl.rc_cwnd_at = tp->snd_cwnd;
			rack->r_ctl.rc_ssthresh_at = tp->snd_ssthresh;
			entered_recovery = 1;
			rack_cong_signal(tp, NULL, CC_NDUPACK);
			
			rack->r_ctl.rc_prr_sndcnt = tp->t_maxseg;
			rack->r_timer_override = 1;
		}
	}
	if (IN_RECOVERY(tp->t_flags) && (entered_recovery == 0)) {
		
		uint32_t pipe, snd_una;

		rack->r_ctl.rc_prr_delivered += changed;
		
		if (SEQ_GT(tp->snd_una, th_ack)) {
			snd_una = tp->snd_una;
		} else {
			snd_una = th_ack;
		}
		pipe = ((tp->snd_max - snd_una) - rack->r_ctl.rc_sacked) + rack->r_ctl.rc_holes_rxt;
		if (pipe > tp->snd_ssthresh) {
			long sndcnt;

			sndcnt = rack->r_ctl.rc_prr_delivered * tp->snd_ssthresh;
			if (rack->r_ctl.rc_prr_recovery_fs > 0)
				sndcnt /= (long)rack->r_ctl.rc_prr_recovery_fs;
			else {
				rack->r_ctl.rc_prr_sndcnt = 0;
				sndcnt = 0;
			}
			sndcnt++;
			if (sndcnt > (long)rack->r_ctl.rc_prr_out)
				sndcnt -= rack->r_ctl.rc_prr_out;
			else sndcnt = 0;
			rack->r_ctl.rc_prr_sndcnt = sndcnt;
		} else {
			uint32_t limit;

			if (rack->r_ctl.rc_prr_delivered > rack->r_ctl.rc_prr_out)
				limit = (rack->r_ctl.rc_prr_delivered - rack->r_ctl.rc_prr_out);
			else limit = 0;
			if (changed > limit)
				limit = changed;
			limit += tp->t_maxseg;
			if (tp->snd_ssthresh > pipe) {
				rack->r_ctl.rc_prr_sndcnt = min((tp->snd_ssthresh - pipe), limit);
			} else {
				rack->r_ctl.rc_prr_sndcnt = min(0, limit);
			}
		}
		if (rack->r_ctl.rc_prr_sndcnt >= tp->t_maxseg) {
			rack->r_timer_override = 1;
		}
	}
}


static int rack_process_ack(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, uint32_t tiwin, int32_t tlen, int32_t * ofia, int32_t thflags, int32_t * ret_val)



{
	int32_t ourfinisacked = 0;
	int32_t nsegs, acked_amount;
	int32_t acked;
	struct mbuf *mfree;
	struct tcp_rack *rack;
	int32_t recovery = 0;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (SEQ_GT(th->th_ack, tp->snd_max)) {
		rack_do_dropafterack(m, tp, th, thflags, tlen, ret_val);
		return (1);
	}
	if (SEQ_GEQ(th->th_ack, tp->snd_una) || to->to_nsacks) {
		rack_log_ack(tp, to, th);
	}
	if (__predict_false(SEQ_LEQ(th->th_ack, tp->snd_una))) {
		
		return (0);
	}
	
	if (tp->t_flags & TF_NEEDSYN) {
		
		tp->t_flags &= ~TF_NEEDSYN;
		tp->snd_una++;
		
		if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) == (TF_RCVD_SCALE | TF_REQ_SCALE)) {
			tp->rcv_scale = tp->request_r_scale;
			
		}
	}
	nsegs = max(1, m->m_pkthdr.lro_nsegs);
	INP_WLOCK_ASSERT(tp->t_inpcb);

	acked = BYTES_THIS_ACK(tp, th);
	TCPSTAT_ADD(tcps_rcvackpack, nsegs);
	TCPSTAT_ADD(tcps_rcvackbyte, acked);

	
	if (tp->t_flags & TF_PREVVALID) {
		tp->t_flags &= ~TF_PREVVALID;
		if (tp->t_rxtshift == 1 && (int)(ticks - tp->t_badrxtwin) < 0)
			rack_cong_signal(tp, th, CC_RTO_ERR);
	}
	
	
	if (th->th_ack == tp->snd_max) {
		rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
		rack->r_wanted_output++;
	}
	
	if (acked == 0) {
		if (ofia)
			*ofia = ourfinisacked;
		return (0);
	}
	if (rack->r_ctl.rc_early_recovery) {
		if (IN_FASTRECOVERY(tp->t_flags)) {
			if (SEQ_LT(th->th_ack, tp->snd_recover)) {
				tcp_rack_partialack(tp, th);
			} else {
				rack_post_recovery(tp, th);
				recovery = 1;
			}
		}
	}
	
	rack_ack_received(tp, rack, th, nsegs, CC_ACK, recovery);
	SOCKBUF_LOCK(&so->so_snd);
	acked_amount = min(acked, (int)sbavail(&so->so_snd));
	tp->snd_wnd -= acked_amount;
	mfree = sbcut_locked(&so->so_snd, acked_amount);
	if ((sbused(&so->so_snd) == 0) && (acked > acked_amount) && (tp->t_state >= TCPS_FIN_WAIT_1)) {

		ourfinisacked = 1;
	}
	
	sowwakeup_locked(so);
	m_freem(mfree);
	if (rack->r_ctl.rc_early_recovery == 0) {
		if (IN_FASTRECOVERY(tp->t_flags)) {
			if (SEQ_LT(th->th_ack, tp->snd_recover)) {
				tcp_rack_partialack(tp, th);
			} else {
				rack_post_recovery(tp, th);
			}
		}
	}
	tp->snd_una = th->th_ack;
	if (SEQ_GT(tp->snd_una, tp->snd_recover))
		tp->snd_recover = tp->snd_una;

	if (SEQ_LT(tp->snd_nxt, tp->snd_una)) {
		tp->snd_nxt = tp->snd_una;
	}
	if (tp->snd_una == tp->snd_max) {
		
		rack_log_progress_event(rack, tp, 0, PROGRESS_CLEAR, __LINE__);
		tp->t_acktime = 0;
		rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
		
		rack->r_wanted_output++;
		if (rack_use_sack_filter)
			sack_filter_clear(&rack->r_ctl.rack_sf, tp->snd_una);
		if ((tp->t_state >= TCPS_FIN_WAIT_1) && (sbavail(&so->so_snd) == 0) && (tp->t_flags2 & TF2_DROP_AF_DATA)) {

			
			*ret_val = 1;
			tp = tcp_close(tp);
			rack_do_dropwithreset(m, tp, th, BANDLIM_UNLIMITED, tlen);
			return (1);
		}
	}
	if (ofia)
		*ofia = ourfinisacked;
	return (0);
}



static int rack_process_data(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	
	int32_t nsegs;
	int32_t tfo_syn;
	struct tcp_rack *rack;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	INP_WLOCK_ASSERT(tp->t_inpcb);
	nsegs = max(1, m->m_pkthdr.lro_nsegs);
	if ((thflags & TH_ACK) && (SEQ_LT(tp->snd_wl1, th->th_seq) || (tp->snd_wl1 == th->th_seq && (SEQ_LT(tp->snd_wl2, th->th_ack) || (tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd))))) {


		
		if (tlen == 0 && tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd)
			TCPSTAT_INC(tcps_rcvwinupd);
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		tp->snd_wl2 = th->th_ack;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
		rack->r_wanted_output++;
	} else if (thflags & TH_ACK) {
		if ((tp->snd_wl2 == th->th_ack) && (tiwin < tp->snd_wnd)) {
			tp->snd_wnd = tiwin;
			tp->snd_wl1 = th->th_seq;
			tp->snd_wl2 = th->th_ack;
		}
	}
	
	if ((rack->rc_in_persist != 0) && tp->snd_wnd) {
		rack_exit_persist(tp, rack);
		tp->snd_nxt = tp->snd_max;
		
		rack->r_wanted_output++;
	}
	if (tp->t_flags2 & TF2_DROP_AF_DATA) {
		m_freem(m);
		return (0);
	}
	
	if ((thflags & TH_URG) && th->th_urp && TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		
		SOCKBUF_LOCK(&so->so_rcv);
		if (th->th_urp + sbavail(&so->so_rcv) > sb_max) {
			th->th_urp = 0;	
			thflags &= ~TH_URG;	
			SOCKBUF_UNLOCK(&so->so_rcv);	
			goto dodata;	
		}
		
		if (SEQ_GT(th->th_seq + th->th_urp, tp->rcv_up)) {
			tp->rcv_up = th->th_seq + th->th_urp;
			so->so_oobmark = sbavail(&so->so_rcv) + (tp->rcv_up - tp->rcv_nxt) - 1;
			if (so->so_oobmark == 0)
				so->so_rcv.sb_state |= SBS_RCVATMARK;
			sohasoutofband(so);
			tp->t_oobflags &= ~(TCPOOB_HAVEDATA | TCPOOB_HADDATA);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
		
		if (th->th_urp <= (uint32_t) tlen && !(so->so_options & SO_OOBINLINE)) {
			
			tcp_pulloutofband(so, th, m, drop_hdrlen);
		}
	} else {
		
		if (SEQ_GT(tp->rcv_nxt, tp->rcv_up))
			tp->rcv_up = tp->rcv_nxt;
	}
dodata:				
	INP_WLOCK_ASSERT(tp->t_inpcb);

	
	tfo_syn = ((tp->t_state == TCPS_SYN_RECEIVED) && IS_FASTOPEN(tp->t_flags));
	if ((tlen || (thflags & TH_FIN) || tfo_syn) && TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		tcp_seq save_start = th->th_seq;
		tcp_seq save_rnxt  = tp->rcv_nxt;
		int     save_tlen  = tlen;

		m_adj(m, drop_hdrlen);	
		
		if (th->th_seq == tp->rcv_nxt && SEGQ_EMPTY(tp) && (TCPS_HAVEESTABLISHED(tp->t_state) || tfo_syn)) {


			if (DELAY_ACK(tp, tlen) || tfo_syn) {
				rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
				tp->t_flags |= TF_DELACK;
			} else {
				rack->r_wanted_output++;
				tp->t_flags |= TF_ACKNOW;
			}
			tp->rcv_nxt += tlen;
			thflags = th->th_flags & TH_FIN;
			TCPSTAT_ADD(tcps_rcvpack, nsegs);
			TCPSTAT_ADD(tcps_rcvbyte, tlen);
			SOCKBUF_LOCK(&so->so_rcv);
			if (so->so_rcv.sb_state & SBS_CANTRCVMORE)
				m_freem(m);
			else sbappendstream_locked(&so->so_rcv, m, 0);
			
			sorwakeup_locked(so);
		} else {
			
			tcp_seq temp = save_start;
			thflags = tcp_reass(tp, th, &temp, &tlen, m);
			tp->t_flags |= TF_ACKNOW;
		}
		if (((tlen == 0) && (save_tlen > 0) && (SEQ_LT(save_start, save_rnxt)))) {
			
			tcp_update_sack_list(tp, save_start, save_start + save_tlen);
		} else if ((tlen > 0) && SEQ_GT(tp->rcv_nxt, save_rnxt)) {
			
			tcp_update_sack_list(tp, save_start, save_start);
		} else if ((tlen > 0) && (tlen >= save_tlen)) {
			
			tcp_update_sack_list(tp, save_start, save_start + save_tlen);
		} else if (tlen > 0) {
			tcp_update_sack_list(tp, save_start, save_start+tlen);
		}
	} else {
		m_freem(m);
		thflags &= ~TH_FIN;
	}

	
	if (thflags & TH_FIN) {
		if (TCPS_HAVERCVDFIN(tp->t_state) == 0) {
			socantrcvmore(so);
			
			if (tp->t_flags & TF_NEEDSYN) {
				rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
				tp->t_flags |= TF_DELACK;
			} else {
				tp->t_flags |= TF_ACKNOW;
			}
			tp->rcv_nxt++;
		}
		switch (tp->t_state) {

			
		case TCPS_SYN_RECEIVED:
			tp->t_starttime = ticks;
			
		case TCPS_ESTABLISHED:
			rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
			tcp_state_change(tp, TCPS_CLOSE_WAIT);
			break;

			
		case TCPS_FIN_WAIT_1:
			rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
			tcp_state_change(tp, TCPS_CLOSING);
			break;

			
		case TCPS_FIN_WAIT_2:
			rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
			INP_INFO_RLOCK_ASSERT(&V_tcbinfo);
			tcp_twstart(tp);
			return (1);
		}
	}
	
	if ((tp->t_flags & TF_ACKNOW) || (sbavail(&so->so_snd) > (tp->snd_max - tp->snd_una))) {
		rack->r_wanted_output++;
	}
	INP_WLOCK_ASSERT(tp->t_inpcb);
	return (0);
}


static int rack_do_fastnewdata(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t nxt_pkt)


{
	int32_t nsegs;
	int32_t newsize = 0;	
	struct tcp_rack *rack;

	
	u_char tcp_saveipgen[IP6_HDR_LEN];
	struct tcphdr tcp_savetcp;
	short ostate = 0;


	
	if (__predict_false(th->th_seq != tp->rcv_nxt)) {
		return (0);
	}
	if (__predict_false(tp->snd_nxt != tp->snd_max)) {
		return (0);
	}
	if (tiwin && tiwin != tp->snd_wnd) {
		return (0);
	}
	if (__predict_false((tp->t_flags & (TF_NEEDSYN | TF_NEEDFIN)))) {
		return (0);
	}
	if (__predict_false((to->to_flags & TOF_TS) && (TSTMP_LT(to->to_tsval, tp->ts_recent)))) {
		return (0);
	}
	if (__predict_false((th->th_ack != tp->snd_una))) {
		return (0);
	}
	if (__predict_false(tlen > sbspace(&so->so_rcv))) {
		return (0);
	}
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	
	nsegs = max(1, m->m_pkthdr.lro_nsegs);


	
	if (tp->rcv_numsacks)
		tcp_clean_sackreport(tp);
	TCPSTAT_INC(tcps_preddat);
	tp->rcv_nxt += tlen;
	
	tp->snd_wl1 = th->th_seq;
	
	tp->rcv_up = tp->rcv_nxt;
	TCPSTAT_ADD(tcps_rcvpack, nsegs);
	TCPSTAT_ADD(tcps_rcvbyte, tlen);

	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_INPUT, ostate, tp, (void *)tcp_saveipgen, &tcp_savetcp, 0);

	newsize = tcp_autorcvbuf(m, th, so, tp, tlen);

	
	SOCKBUF_LOCK(&so->so_rcv);
	if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
		m_freem(m);
	} else {
		
		if (newsize)
			if (!sbreserve_locked(&so->so_rcv, newsize, so, NULL))
				so->so_rcv.sb_flags &= ~SB_AUTOSIZE;
		m_adj(m, drop_hdrlen);	
		sbappendstream_locked(&so->so_rcv, m, 0);
		rack_calc_rwin(so, tp);
	}
	
	sorwakeup_locked(so);
	if (DELAY_ACK(tp, tlen)) {
		rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
		tp->t_flags |= TF_DELACK;
	} else {
		tp->t_flags |= TF_ACKNOW;
		rack->r_wanted_output++;
	}
	if ((tp->snd_una == tp->snd_max) && rack_use_sack_filter)
		sack_filter_clear(&rack->r_ctl.rack_sf, tp->snd_una);
	return (1);
}


static int rack_fastack(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t nxt_pkt, uint32_t cts)


{
	int32_t acked;
	int32_t nsegs;


	
	u_char tcp_saveipgen[IP6_HDR_LEN];
	struct tcphdr tcp_savetcp;
	short ostate = 0;


	struct tcp_rack *rack;

	if (__predict_false(SEQ_LEQ(th->th_ack, tp->snd_una))) {
		
		return (0);
	}
	if (__predict_false(SEQ_GT(th->th_ack, tp->snd_max))) {
		
		return (0);
	}
	if (__predict_false(tp->snd_nxt != tp->snd_max)) {
		
		return (0);
	}
	if (__predict_false(tiwin == 0)) {
		
		return (0);
	}
	if (__predict_false(tp->t_flags & (TF_NEEDSYN | TF_NEEDFIN))) {
		
		return (0);
	}
	if ((to->to_flags & TOF_TS) && __predict_false(TSTMP_LT(to->to_tsval, tp->ts_recent))) {
		
		return (0);
	}
	if (__predict_false(IN_RECOVERY(tp->t_flags))) {
		
		return (0);
	}
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (rack->r_ctl.rc_sacked) {
		
		return (0);
	}
	
	nsegs = max(1, m->m_pkthdr.lro_nsegs);
	rack_log_ack(tp, to, th);
	
	if (tiwin != tp->snd_wnd) {
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
	}
	if ((rack->rc_in_persist != 0) && (tp->snd_wnd >= tp->t_maxseg)) {
		rack_exit_persist(tp, rack);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	
	TCPSTAT_INC(tcps_predack);

	
	if (tp->t_flags & TF_PREVVALID) {
		tp->t_flags &= ~TF_PREVVALID;
		if (tp->t_rxtshift == 1 && (int)(ticks - tp->t_badrxtwin) < 0)
			rack_cong_signal(tp, th, CC_RTO_ERR);
	}
	
	acked = BYTES_THIS_ACK(tp, th);


	
	hhook_run_tcp_est_in(tp, th, to);


	TCPSTAT_ADD(tcps_rcvackpack, nsegs);
	TCPSTAT_ADD(tcps_rcvackbyte, acked);
	sbdrop(&so->so_snd, acked);
	
	rack_ack_received(tp, rack, th, nsegs, CC_ACK, 0);

	tp->snd_una = th->th_ack;
	
	tp->snd_wl2 = th->th_ack;
	tp->t_dupacks = 0;
	m_freem(m);
	

	

	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_INPUT, ostate, tp, (void *)tcp_saveipgen, &tcp_savetcp, 0);


	if (tp->snd_una == tp->snd_max) {
		rack_log_progress_event(rack, tp, 0, PROGRESS_CLEAR, __LINE__);
		tp->t_acktime = 0;
		rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
	}
	
	sowwakeup(so);
	if (sbavail(&so->so_snd)) {
		rack->r_wanted_output++;
	}
	return (1);
}


static int rack_do_syn_sent(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	int32_t ret_val = 0;
	int32_t todrop;
	int32_t ourfinisacked = 0;

	rack_calc_rwin(so, tp);
	
	if ((thflags & TH_ACK) && (SEQ_LEQ(th->th_ack, tp->iss) || SEQ_GT(th->th_ack, tp->snd_max))) {

		rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if ((thflags & (TH_ACK | TH_RST)) == (TH_ACK | TH_RST)) {
		TCP_PROBE5(connect__refused, NULL, tp, mtod(m, const char *), tp, th);
		tp = tcp_drop(tp, ECONNREFUSED);
		rack_do_drop(m, tp);
		return (1);
	}
	if (thflags & TH_RST) {
		rack_do_drop(m, tp);
		return (1);
	}
	if (!(thflags & TH_SYN)) {
		rack_do_drop(m, tp);
		return (1);
	}
	tp->irs = th->th_seq;
	tcp_rcvseqinit(tp);
	if (thflags & TH_ACK) {
		int tfo_partial = 0;
		
		TCPSTAT_INC(tcps_connects);
		soisconnected(so);

		mac_socketpeer_set_from_mbuf(m, so);

		
		if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) == (TF_RCVD_SCALE | TF_REQ_SCALE)) {
			tp->rcv_scale = tp->request_r_scale;
		}
		tp->rcv_adv += min(tp->rcv_wnd, TCP_MAXWIN << tp->rcv_scale);
		
		if (IS_FASTOPEN(tp->t_flags) && (tp->snd_una != tp->snd_max)) {
			tp->snd_nxt = th->th_ack;
			tfo_partial = 1;
		}
		
		if (DELAY_ACK(tp, tlen) && tlen != 0 && (tfo_partial == 0)) {
			rack_timer_cancel(tp, (struct tcp_rack *)tp->t_fb_ptr, ((struct tcp_rack *)tp->t_fb_ptr)->r_ctl.rc_rcvtime, __LINE__);
			tp->t_flags |= TF_DELACK;
		} else {
			((struct tcp_rack *)tp->t_fb_ptr)->r_wanted_output++;
			tp->t_flags |= TF_ACKNOW;
		}

		if (((thflags & (TH_CWR | TH_ECE)) == TH_ECE) && V_tcp_do_ecn) {
			tp->t_flags |= TF_ECN_PERMIT;
			TCPSTAT_INC(tcps_ecn_shs);
		}
		if (SEQ_GT(th->th_ack, tp->snd_una)) {
			
			tp->snd_una++;
		}
		
		tp->t_starttime = ticks;
		if (tp->t_flags & TF_NEEDFIN) {
			tcp_state_change(tp, TCPS_FIN_WAIT_1);
			tp->t_flags &= ~TF_NEEDFIN;
			thflags &= ~TH_SYN;
		} else {
			tcp_state_change(tp, TCPS_ESTABLISHED);
			TCP_PROBE5(connect__established, NULL, tp, mtod(m, const char *), tp, th);
			cc_conn_init(tp);
		}
	} else {
		
		tp->t_flags |= (TF_ACKNOW | TF_NEEDSYN);
		tcp_state_change(tp, TCPS_SYN_RECEIVED);
	}
	INP_INFO_RLOCK_ASSERT(&V_tcbinfo);
	INP_WLOCK_ASSERT(tp->t_inpcb);
	
	th->th_seq++;
	if (tlen > tp->rcv_wnd) {
		todrop = tlen - tp->rcv_wnd;
		m_adj(m, -todrop);
		tlen = tp->rcv_wnd;
		thflags &= ~TH_FIN;
		TCPSTAT_INC(tcps_rcvpackafterwin);
		TCPSTAT_ADD(tcps_rcvbyteafterwin, todrop);
	}
	tp->snd_wl1 = th->th_seq - 1;
	tp->rcv_up = th->th_seq;
	
	if (thflags & TH_ACK) {
		if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val))
			return (ret_val);
		
		if (tp->t_state == TCPS_FIN_WAIT_1) {
			
			if (ourfinisacked) {
				
				if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
					soisdisconnected(so);
					tcp_timer_activate(tp, TT_2MSL, (tcp_fast_finwait2_recycle ? tcp_finwait2_timeout :

					    TP_MAXIDLE(tp)));
				}
				tcp_state_change(tp, TCPS_FIN_WAIT_2);
			}
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
}


static int rack_do_syn_recv(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	rack_calc_rwin(so, tp);

	if ((thflags & TH_ACK) && (SEQ_LEQ(th->th_ack, tp->snd_una) || SEQ_GT(th->th_ack, tp->snd_max))) {

		rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if (IS_FASTOPEN(tp->t_flags)) {
		
		if ((thflags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
			rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		} else if (thflags & TH_SYN) {
			
			struct tcp_rack *rack;

			rack = (struct tcp_rack *)tp->t_fb_ptr;
			if ((rack->r_ctl.rc_hpts_flags & PACE_TMR_RXT) || (rack->r_ctl.rc_hpts_flags & PACE_TMR_TLP) || (rack->r_ctl.rc_hpts_flags & PACE_TMR_RACK)) {

				rack_do_drop(m, NULL);
				return (0);
			}
		} else if (!(thflags & (TH_ACK | TH_FIN | TH_RST))) {
			rack_do_drop(m, NULL);
			return (0);
		}
	}
	if (thflags & TH_RST)
		return (rack_process_rst(m, th, so, tp));
	
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent && TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (rack_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	
	if (SEQ_LT(th->th_seq, tp->irs)) {
		rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return (1);
	}
	if (rack_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent) && SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen + ((thflags & (TH_SYN | TH_FIN)) != 0))) {


		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	tp->snd_wnd = tiwin;
	
	if ((thflags & TH_ACK) == 0) {
		if (IS_FASTOPEN(tp->t_flags)) {
			cc_conn_init(tp);
		}
		return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
	}
	TCPSTAT_INC(tcps_connects);
	soisconnected(so);
	
	if ((tp->t_flags & (TF_RCVD_SCALE | TF_REQ_SCALE)) == (TF_RCVD_SCALE | TF_REQ_SCALE)) {
		tp->rcv_scale = tp->request_r_scale;
	}
	
	tp->t_starttime = ticks;
	if (IS_FASTOPEN(tp->t_flags) && tp->t_tfo_pending) {
		tcp_fastopen_decrement_counter(tp->t_tfo_pending);
		tp->t_tfo_pending = NULL;

		 
		tp->snd_una++;
	}
	if (tp->t_flags & TF_NEEDFIN) {
		tcp_state_change(tp, TCPS_FIN_WAIT_1);
		tp->t_flags &= ~TF_NEEDFIN;
	} else {
		tcp_state_change(tp, TCPS_ESTABLISHED);
		TCP_PROBE5(accept__established, NULL, tp, mtod(m, const char *), tp, th);
		
		if (!IS_FASTOPEN(tp->t_flags))
			cc_conn_init(tp);
	}
	
	if (tlen == 0 && (thflags & TH_FIN) == 0)
		(void) tcp_reass(tp, (struct tcphdr *)0, NULL, 0, (struct mbuf *)0);
	tp->snd_wl1 = th->th_seq - 1;
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (tp->t_state == TCPS_FIN_WAIT_1) {
		
		
		if (ourfinisacked) {
			
			if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
				soisdisconnected(so);
				tcp_timer_activate(tp, TT_2MSL, (tcp_fast_finwait2_recycle ? tcp_finwait2_timeout :

				    TP_MAXIDLE(tp)));
			}
			tcp_state_change(tp, TCPS_FIN_WAIT_2);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
}


static int rack_do_established(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	int32_t ret_val = 0;

	
	if (__predict_true(((to->to_flags & TOF_SACK) == 0)) && __predict_true((thflags & (TH_SYN | TH_FIN | TH_RST | TH_URG | TH_ACK)) == TH_ACK) && __predict_true(SEGQ_EMPTY(tp)) && __predict_true(th->th_seq == tp->rcv_nxt)) {


		struct tcp_rack *rack;

		rack = (struct tcp_rack *)tp->t_fb_ptr;
		if (tlen == 0) {
			if (rack_fastack(m, th, so, tp, to, drop_hdrlen, tlen, tiwin, nxt_pkt, rack->r_ctl.rc_rcvtime)) {
				return (0);
			}
		} else {
			if (rack_do_fastnewdata(m, th, so, tp, to, drop_hdrlen, tlen, tiwin, nxt_pkt)) {
				return (0);
			}
		}
	}
	rack_calc_rwin(so, tp);

	if (thflags & TH_RST)
		return (rack_process_rst(m, th, so, tp));

	
	if (thflags & TH_SYN) {
		rack_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent && TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (rack_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (rack_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent) && SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen + ((thflags & (TH_SYN | TH_FIN)) != 0))) {


		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {

			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));

		} else if (tp->t_flags & TF_ACKNOW) {
			rack_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			return (ret_val);
		} else {
			rack_do_drop(m, NULL);
			return (0);
		}
	}
	
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, NULL, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (rack_progress_timeout_check(tp)) {
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
}


static int rack_do_close_wait(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	int32_t ret_val = 0;

	rack_calc_rwin(so, tp);
	if (thflags & TH_RST)
		return (rack_process_rst(m, th, so, tp));
	
	if (thflags & TH_SYN) {
		rack_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent && TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (rack_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (rack_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent) && SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen + ((thflags & (TH_SYN | TH_FIN)) != 0))) {


		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));

		} else if (tp->t_flags & TF_ACKNOW) {
			rack_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			return (ret_val);
		} else {
			rack_do_drop(m, NULL);
			return (0);
		}
	}
	
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, NULL, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (rack_progress_timeout_check(tp)) {
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
}

static int rack_check_data_after_close(struct mbuf *m, struct tcpcb *tp, int32_t *tlen, struct tcphdr *th, struct socket *so)

{
	struct tcp_rack *rack;

	INP_INFO_RLOCK_ASSERT(&V_tcbinfo);
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (rack->rc_allow_data_af_clo == 0) {
	close_now:
		tp = tcp_close(tp);
		TCPSTAT_INC(tcps_rcvafterclose);
		rack_do_dropwithreset(m, tp, th, BANDLIM_UNLIMITED, (*tlen));
		return (1);
	}
	if (sbavail(&so->so_snd) == 0)
		goto close_now;
	
	tp->rcv_nxt = th->th_seq + *tlen;
	tp->t_flags2 |= TF2_DROP_AF_DATA;
	rack->r_wanted_output = 1;
	*tlen = 0;
	return (0);
}


static int rack_do_fin_wait_1(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	rack_calc_rwin(so, tp);

	if (thflags & TH_RST)
		return (rack_process_rst(m, th, so, tp));
	
	if (thflags & TH_SYN) {
		rack_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent && TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (rack_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (rack_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	
	if ((so->so_state & SS_NOFDREF) && tlen) {
		if (rack_check_data_after_close(m, tp, &tlen, th, so))
			return (1);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent) && SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen + ((thflags & (TH_SYN | TH_FIN)) != 0))) {


		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			rack_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			return (ret_val);
		} else {
			rack_do_drop(m, NULL);
			return (0);
		}
	}
	
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
		
		if (so->so_rcv.sb_state & SBS_CANTRCVMORE) {
			soisdisconnected(so);
			tcp_timer_activate(tp, TT_2MSL, (tcp_fast_finwait2_recycle ? tcp_finwait2_timeout :

			    TP_MAXIDLE(tp)));
		}
		tcp_state_change(tp, TCPS_FIN_WAIT_2);
	}
	if (sbavail(&so->so_snd)) {
		if (rack_progress_timeout_check(tp)) {
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
}


static int rack_do_closing(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	rack_calc_rwin(so, tp);

	if (thflags & TH_RST)
		return (rack_process_rst(m, th, so, tp));
	
	if (thflags & TH_SYN) {
		rack_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent && TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (rack_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (rack_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	
	if ((so->so_state & SS_NOFDREF) && tlen) {
		if (rack_check_data_after_close(m, tp, &tlen, th, so))
			return (1);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent) && SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen + ((thflags & (TH_SYN | TH_FIN)) != 0))) {


		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			rack_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			return (ret_val);
		} else {
			rack_do_drop(m, NULL);
			return (0);
		}
	}
	
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
		INP_INFO_RLOCK_ASSERT(&V_tcbinfo);
		tcp_twstart(tp);
		m_freem(m);
		return (1);
	}
	if (sbavail(&so->so_snd)) {
		if (rack_progress_timeout_check(tp)) {
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
}


static int rack_do_lastack(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	rack_calc_rwin(so, tp);

	if (thflags & TH_RST)
		return (rack_process_rst(m, th, so, tp));
	
	if (thflags & TH_SYN) {
		rack_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent && TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (rack_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (rack_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	
	if ((so->so_state & SS_NOFDREF) && tlen) {
		if (rack_check_data_after_close(m, tp, &tlen, th, so))
			return (1);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent) && SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen + ((thflags & (TH_SYN | TH_FIN)) != 0))) {


		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			rack_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			return (ret_val);
		} else {
			rack_do_drop(m, NULL);
			return (0);
		}
	}
	
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (ourfinisacked) {
		INP_INFO_RLOCK_ASSERT(&V_tcbinfo);
		tp = tcp_close(tp);
		rack_do_drop(m, tp);
		return (1);
	}
	if (sbavail(&so->so_snd)) {
		if (rack_progress_timeout_check(tp)) {
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
}



static int rack_do_fin_wait_2(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, struct tcpopt *to, int32_t drop_hdrlen, int32_t tlen, uint32_t tiwin, int32_t thflags, int32_t nxt_pkt)


{
	int32_t ret_val = 0;
	int32_t ourfinisacked = 0;

	rack_calc_rwin(so, tp);

	
	if (thflags & TH_RST)
		return (rack_process_rst(m, th, so, tp));
	
	if (thflags & TH_SYN) {
		rack_challenge_ack(m, th, tp, &ret_val);
		return (ret_val);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && tp->ts_recent && TSTMP_LT(to->to_tsval, tp->ts_recent)) {
		if (rack_ts_check(m, th, tp, tlen, thflags, &ret_val))
			return (ret_val);
	}
	if (rack_drop_checks(to, m, th, tp, &tlen, &thflags, &drop_hdrlen, &ret_val)) {
		return (ret_val);
	}
	
	if ((so->so_state & SS_NOFDREF) && tlen) {
		if (rack_check_data_after_close(m, tp, &tlen, th, so))
			return (1);
	}
	
	if ((to->to_flags & TOF_TS) != 0 && SEQ_LEQ(th->th_seq, tp->last_ack_sent) && SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen + ((thflags & (TH_SYN | TH_FIN)) != 0))) {


		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to->to_tsval;
	}
	
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_flags & TF_NEEDSYN) {
			return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
		} else if (tp->t_flags & TF_ACKNOW) {
			rack_do_dropafterack(m, tp, th, thflags, tlen, &ret_val);
			return (ret_val);
		} else {
			rack_do_drop(m, NULL);
			return (0);
		}
	}
	
	if (rack_process_ack(m, th, so, tp, to, tiwin, tlen, &ourfinisacked, thflags, &ret_val)) {
		return (ret_val);
	}
	if (sbavail(&so->so_snd)) {
		if (rack_progress_timeout_check(tp)) {
			tcp_set_inp_to_drop(tp->t_inpcb, ETIMEDOUT);
			rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
			return (1);
		}
	}
	return (rack_process_data(m, th, so, tp, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt));
}


static void inline rack_clear_rate_sample(struct tcp_rack *rack)
{
	rack->r_ctl.rack_rs.rs_flags = RACK_RTT_EMPTY;
	rack->r_ctl.rack_rs.rs_rtt_cnt = 0;
	rack->r_ctl.rack_rs.rs_rtt_tot = 0;
}

static int rack_init(struct tcpcb *tp)
{
	struct tcp_rack *rack = NULL;

	tp->t_fb_ptr = uma_zalloc(rack_pcb_zone, M_NOWAIT);
	if (tp->t_fb_ptr == NULL) {
		
		return (ENOMEM);
	}
	memset(tp->t_fb_ptr, 0, sizeof(struct tcp_rack));

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	TAILQ_INIT(&rack->r_ctl.rc_map);
	TAILQ_INIT(&rack->r_ctl.rc_free);
	TAILQ_INIT(&rack->r_ctl.rc_tmap);
	rack->rc_tp = tp;
	if (tp->t_inpcb) {
		rack->rc_inp = tp->t_inpcb;
	}
	
	rack_clear_rate_sample(rack);
	rack->r_cpu = 0;
	rack->r_ctl.rc_reorder_fade = rack_reorder_fade;
	rack->rc_allow_data_af_clo = rack_ignore_data_after_close;
	rack->r_ctl.rc_tlp_threshold = rack_tlp_thresh;
	rack->rc_pace_reduce = rack_slot_reduction;
	if (V_tcp_delack_enabled)
		tp->t_delayed_ack = 1;
	else tp->t_delayed_ack = 0;
	rack->rc_pace_max_segs = rack_hptsi_segments;
	rack->r_ctl.rc_early_recovery_segs = rack_early_recovery_max_seg;
	rack->r_ctl.rc_reorder_shift = rack_reorder_thresh;
	rack->r_ctl.rc_pkt_delay = rack_pkt_delay;
	rack->r_ctl.rc_prop_reduce = rack_use_proportional_reduce;
	rack->r_idle_reduce_largest  = rack_reduce_largest_on_idle;
	rack->r_enforce_min_pace = rack_min_pace_time;
	rack->r_min_pace_seg_thresh = rack_min_pace_time_seg_req;
	rack->r_ctl.rc_prop_rate = rack_proportional_rate;
	rack->r_ctl.rc_tlp_cwnd_reduce = rack_lower_cwnd_at_tlp;
	rack->r_ctl.rc_early_recovery = rack_early_recovery;
	rack->rc_always_pace = rack_pace_every_seg;
	rack->r_ctl.rc_rate_sample_method = rack_rate_sample_method;
	rack->rack_tlp_threshold_use = rack_tlp_threshold_use;
	rack->r_ctl.rc_prr_sendalot = rack_send_a_lot_in_prr;
	rack->r_ctl.rc_min_to = rack_min_to;
	rack->r_ctl.rc_prr_inc_var = rack_inc_var;
	rack_start_hpts_timer(rack, tp, tcp_ts_getticks(), __LINE__, 0, 0, 0);
	if (tp->snd_una != tp->snd_max) {
		
		struct rack_sendmap *rsm;

		rsm = rack_alloc(rack);
		if (rsm == NULL) {
			uma_zfree(rack_pcb_zone, tp->t_fb_ptr);
			tp->t_fb_ptr = NULL;
			return (ENOMEM);
		}
		rsm->r_flags = RACK_OVERMAX;
		rsm->r_tim_lastsent[0] = tcp_ts_getticks();
		rsm->r_rtr_cnt = 1;
		rsm->r_rtr_bytes = 0;
		rsm->r_start = tp->snd_una;
		rsm->r_end = tp->snd_max;
		rsm->r_sndcnt = 0;
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_map, rsm, r_next);
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_tmap, rsm, r_tnext);
		rsm->r_in_tmap = 1;
	}
	return (0);
}

static int rack_handoff_ok(struct tcpcb *tp)
{
	if ((tp->t_state == TCPS_CLOSED) || (tp->t_state == TCPS_LISTEN)) {
		
		return (0);
	}
	if ((tp->t_state == TCPS_SYN_SENT) || (tp->t_state == TCPS_SYN_RECEIVED)) {
		
		return (EAGAIN);
	}
	if (tp->t_flags & TF_SACK_PERMIT) {
		return (0);
	}
	
	return (EINVAL);
}

static void rack_fini(struct tcpcb *tp, int32_t tcb_is_purged)
{
	if (tp->t_fb_ptr) {
		struct tcp_rack *rack;
		struct rack_sendmap *rsm;

		rack = (struct tcp_rack *)tp->t_fb_ptr;

		tcp_log_flowend(tp);

		rsm = TAILQ_FIRST(&rack->r_ctl.rc_map);
		while (rsm) {
			TAILQ_REMOVE(&rack->r_ctl.rc_map, rsm, r_next);
			uma_zfree(rack_zone, rsm);
			rsm = TAILQ_FIRST(&rack->r_ctl.rc_map);
		}
		rsm = TAILQ_FIRST(&rack->r_ctl.rc_free);
		while (rsm) {
			TAILQ_REMOVE(&rack->r_ctl.rc_free, rsm, r_next);
			uma_zfree(rack_zone, rsm);
			rsm = TAILQ_FIRST(&rack->r_ctl.rc_free);
		}
		rack->rc_free_cnt = 0;
		uma_zfree(rack_pcb_zone, tp->t_fb_ptr);
		tp->t_fb_ptr = NULL;
	}
}

static void rack_set_state(struct tcpcb *tp, struct tcp_rack *rack)
{
	switch (tp->t_state) {
	case TCPS_SYN_SENT:
		rack->r_state = TCPS_SYN_SENT;
		rack->r_substate = rack_do_syn_sent;
		break;
	case TCPS_SYN_RECEIVED:
		rack->r_state = TCPS_SYN_RECEIVED;
		rack->r_substate = rack_do_syn_recv;
		break;
	case TCPS_ESTABLISHED:
		rack->r_state = TCPS_ESTABLISHED;
		rack->r_substate = rack_do_established;
		break;
	case TCPS_CLOSE_WAIT:
		rack->r_state = TCPS_CLOSE_WAIT;
		rack->r_substate = rack_do_close_wait;
		break;
	case TCPS_FIN_WAIT_1:
		rack->r_state = TCPS_FIN_WAIT_1;
		rack->r_substate = rack_do_fin_wait_1;
		break;
	case TCPS_CLOSING:
		rack->r_state = TCPS_CLOSING;
		rack->r_substate = rack_do_closing;
		break;
	case TCPS_LAST_ACK:
		rack->r_state = TCPS_LAST_ACK;
		rack->r_substate = rack_do_lastack;
		break;
	case TCPS_FIN_WAIT_2:
		rack->r_state = TCPS_FIN_WAIT_2;
		rack->r_substate = rack_do_fin_wait_2;
		break;
	case TCPS_LISTEN:
	case TCPS_CLOSED:
	case TCPS_TIME_WAIT:
	default:

		panic("tcp tp:%p state:%d sees impossible state?", tp, tp->t_state);

		break;
	};
}


static void rack_timer_audit(struct tcpcb *tp, struct tcp_rack *rack, struct sockbuf *sb)
{
	
	struct rack_sendmap *rsm;
	int tmr_up;
	
	tmr_up = rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK;
	if (rack->rc_in_persist && (tmr_up == PACE_TMR_PERSIT))
		return;
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (((rsm == NULL) || (tp->t_state < TCPS_ESTABLISHED)) && (tmr_up == PACE_TMR_RXT)) {
		
		return;
	}
	if (rsm == NULL) {
		
		if (tp->t_flags & TF_DELACK) {
			if (tmr_up == PACE_TMR_DELACK)
				
				return;
		} else if (sbavail(&tp->t_inpcb->inp_socket->so_snd) && (tmr_up == PACE_TMR_RXT)) {
			
			return;
		} else if (((tcp_always_keepalive || rack->rc_inp->inp_socket->so_options & SO_KEEPALIVE) && (tp->t_state <= TCPS_CLOSING)) && (tmr_up == PACE_TMR_KEEP) && (tp->snd_max == tp->snd_una)) {



			
			return;
		}
	}
	if (rsm && (rsm->r_flags & RACK_SACK_PASSED)) {
		if ((tp->t_flags & TF_SENTFIN) && ((tp->snd_max - tp->snd_una) == 1) && (rsm->r_flags & RACK_HAS_FIN)) {

			
			if (tmr_up == PACE_TMR_RXT)
				return;
		} else if (tmr_up == PACE_TMR_RACK)
			return;
	} else if (SEQ_GT(tp->snd_max,tp->snd_una) && ((tmr_up == PACE_TMR_TLP) || (tmr_up == PACE_TMR_RXT))) {

		
		return;
	} else if (tmr_up == PACE_TMR_DELACK) {
		
		return;
	}
	
	rack_timer_cancel(tp, rack, rack->r_ctl.rc_rcvtime, __LINE__);
	rack_start_hpts_timer(rack, tp, tcp_ts_getticks(), __LINE__, 0, 0, 0);
}

static void rack_hpts_do_segment(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint8_t iptos, int32_t nxt_pkt, struct timeval *tv)


{
	int32_t thflags, retval, did_out = 0;
	int32_t way_out = 0;
	uint32_t cts;
	uint32_t tiwin;
	struct tcpopt to;
	struct tcp_rack *rack;
	struct rack_sendmap *rsm;
	int32_t prev_state = 0;

	cts = tcp_tv_to_mssectick(tv);
	rack = (struct tcp_rack *)tp->t_fb_ptr;

	kern_prefetch(rack, &prev_state);
	prev_state = 0;
	thflags = th->th_flags;
	
	if ((thflags & (TH_SYN | TH_FIN | TH_RST)) != 0 || tp->t_state != TCPS_ESTABLISHED) {
		INP_INFO_RLOCK_ASSERT(&V_tcbinfo);
	}
	INP_WLOCK_ASSERT(tp->t_inpcb);
	KASSERT(tp->t_state > TCPS_LISTEN, ("%s: TCPS_LISTEN", __func__));
	KASSERT(tp->t_state != TCPS_TIME_WAIT, ("%s: TCPS_TIME_WAIT", __func__));
	{
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		TCP_LOG_EVENT(tp, th, &so->so_rcv, &so->so_snd, TCP_LOG_IN, 0, tlen, &log, true);
	}
	if ((thflags & TH_SYN) && (thflags & TH_FIN) && V_drop_synfin) {
		way_out = 4;
		goto done_with_input;
	}
	
	if ((tp->t_state == TCPS_SYN_SENT) && (thflags & TH_ACK) && (SEQ_LEQ(th->th_ack, tp->iss) || SEQ_GT(th->th_ack, tp->snd_max))) {
		rack_do_dropwithreset(m, tp, th, BANDLIM_RST_OPENPORT, tlen);
		return;
	}
	
	if  (tp->t_idle_reduce && (tp->snd_max == tp->snd_una)) {

		if ((tp->cwv_enabled) && ((tp->cwv_cwnd_valid == 0) && TCPS_HAVEESTABLISHED(tp->t_state) && (tp->snd_cwnd > tp->snd_cwv.init_cwnd))) {


			tcp_newcwv_nvp_closedown(tp);
		} else   if ((ticks - tp->t_rcvtime) >= tp->t_rxtcur) {

			counter_u64_add(rack_input_idle_reduces, 1);
			rack_cc_after_idle(tp, (rack->r_idle_reduce_largest ? 1 :0));
		}
	}
	rack->r_ctl.rc_rcvtime = cts;
	tp->t_rcvtime = ticks;


	if (tp->cwv_enabled) {
		if ((tp->cwv_cwnd_valid == 0) && TCPS_HAVEESTABLISHED(tp->t_state) && (tp->snd_cwnd > tp->snd_cwv.init_cwnd))

			tcp_newcwv_nvp_closedown(tp);
	}

	
	tiwin = th->th_win << tp->snd_scale;

	stats_voi_update_abs_ulong(tp->t_stats, VOI_TCP_FRWIN, tiwin);

	
	if (tp->t_flags & TF_ECN_PERMIT) {
		if (thflags & TH_CWR)
			tp->t_flags &= ~TF_ECN_SND_ECE;
		switch (iptos & IPTOS_ECN_MASK) {
		case IPTOS_ECN_CE:
			tp->t_flags |= TF_ECN_SND_ECE;
			TCPSTAT_INC(tcps_ecn_ce);
			break;
		case IPTOS_ECN_ECT0:
			TCPSTAT_INC(tcps_ecn_ect0);
			break;
		case IPTOS_ECN_ECT1:
			TCPSTAT_INC(tcps_ecn_ect1);
			break;
		}
		
		if (thflags & TH_ECE) {
			rack_cong_signal(tp, th, CC_ECN);
		}
	}
	
	tcp_dooptions(&to, (u_char *)(th + 1), (th->th_off << 2) - sizeof(struct tcphdr), (thflags & TH_SYN) ? TO_SYN : 0);


	
	if ((to.to_flags & TOF_TS) && (to.to_tsecr != 0)) {
		to.to_tsecr -= tp->ts_offset;
		if (TSTMP_GT(to.to_tsecr, cts))
			to.to_tsecr = 0;
	}
	
	if (rack->r_state == 0) {
		
		KASSERT(rack->rc_inp != NULL, ("%s: rack->rc_inp unexpectedly NULL", __func__));
		if (rack->rc_inp == NULL) {
			rack->rc_inp = tp->t_inpcb;
		}

		
		rack->r_cpu = inp_to_cpuid(tp->t_inpcb);
		if (tp->t_state == TCPS_SYN_SENT && (thflags & TH_SYN)) {
			if ((to.to_flags & TOF_SCALE) && (tp->t_flags & TF_REQ_SCALE)) {
				tp->t_flags |= TF_RCVD_SCALE;
				tp->snd_scale = to.to_wscale;
			}
			
			tp->snd_wnd = th->th_win;
			if (to.to_flags & TOF_TS) {
				tp->t_flags |= TF_RCVD_TSTMP;
				tp->ts_recent = to.to_tsval;
				tp->ts_recent_age = cts;
			}
			if (to.to_flags & TOF_MSS)
				tcp_mss(tp, to.to_mss);
			if ((tp->t_flags & TF_SACK_PERMIT) && (to.to_flags & TOF_SACKPERM) == 0)
				tp->t_flags &= ~TF_SACK_PERMIT;
			if (IS_FASTOPEN(tp->t_flags)) {
				if (to.to_flags & TOF_FASTOPEN) {
					uint16_t mss;

					if (to.to_flags & TOF_MSS)
						mss = to.to_mss;
					else if ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0)
							mss = TCP6_MSS;
						else mss = TCP_MSS;
					tcp_fastopen_update_cache(tp, mss, to.to_tfo_len, to.to_tfo_cookie);
				} else tcp_fastopen_disable_path(tp);
			}
		}
		
		if ((tp->t_flags & TF_SACK_PERMIT) == 0) {
			tcp_switch_back_to_default(tp);
			(*tp->t_fb->tfb_tcp_do_segment) (m, th, so, tp, drop_hdrlen, tlen, iptos);
			return;
		}
		
		rack->r_is_v6 = (tp->t_inpcb->inp_vflag & INP_IPV6) != 0;
		tcp_set_hpts(tp->t_inpcb);
		rack_stop_all_timers(tp);
		sack_filter_clear(&rack->r_ctl.rack_sf, th->th_ack);
	}
	
	if (rack->r_state != tp->t_state)
		rack_set_state(tp, rack);
	if (SEQ_GT(th->th_ack, tp->snd_una) && (rsm = TAILQ_FIRST(&rack->r_ctl.rc_map)) != NULL)
		kern_prefetch(rsm, &prev_state);
	prev_state = rack->r_state;
	rack->r_ctl.rc_tlp_send_cnt = 0;
	rack_clear_rate_sample(rack);
	retval = (*rack->r_substate) (m, th, so, tp, &to, drop_hdrlen, tlen, tiwin, thflags, nxt_pkt);


	if ((retval == 0) && (tp->t_inpcb == NULL)) {
		panic("retval:%d tp:%p t_inpcb:NULL state:%d", retval, tp, prev_state);
	}

	if (retval == 0) {
		
		INP_WLOCK_ASSERT(tp->t_inpcb);
		tcp_rack_xmit_timer_commit(rack, tp);
		if (((tp->snd_max - tp->snd_una) > tp->snd_wnd) && (rack->rc_in_persist == 0)){
			
			if (rack->rc_inp->inp_in_hpts)
				tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
			rack_timer_cancel(tp, rack, cts, __LINE__);
			rack_enter_persist(tp, rack, cts);
			rack_start_hpts_timer(rack, tp, tcp_ts_getticks(), __LINE__, 0, 0, 0);
			way_out = 3;
			goto done_with_input;
		}
		if (nxt_pkt == 0) {
			if (rack->r_wanted_output != 0) {
				did_out = 1;
				(void)tp->t_fb->tfb_tcp_output(tp);
			}
			rack_start_hpts_timer(rack, tp, cts, __LINE__, 0, 0, 0);
		}
		if (((rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK) == 0) && (SEQ_GT(tp->snd_max, tp->snd_una) || (tp->t_flags & TF_DELACK) || ((tcp_always_keepalive || rack->rc_inp->inp_socket->so_options & SO_KEEPALIVE) && (tp->t_state <= TCPS_CLOSING)))) {



			
			if ((tp->snd_max == tp->snd_una) && ((tp->t_flags & TF_DELACK) == 0) && (rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT)) {

				
				;
			} else {
				if (rack->rc_inp->inp_in_hpts)
					tcp_hpts_remove(rack->rc_inp, HPTS_REMOVE_OUTPUT);
				rack_start_hpts_timer(rack, tp, tcp_ts_getticks(), __LINE__, 0, 0, 0);
			}
			way_out = 1;
		} else {
			
			rack_timer_audit(tp, rack, &so->so_snd);
			way_out = 2;
		}
	done_with_input:
		rack_log_doseg_done(rack, cts, nxt_pkt, did_out, way_out);
		if (did_out)
			rack->r_wanted_output = 0;

		if (tp->t_inpcb == NULL) {
			panic("OP:%d retval:%d tp:%p t_inpcb:NULL state:%d", did_out, retval, tp, prev_state);

		}

		INP_WUNLOCK(tp->t_inpcb);
	}
}

void rack_do_segment(struct mbuf *m, struct tcphdr *th, struct socket *so, struct tcpcb *tp, int32_t drop_hdrlen, int32_t tlen, uint8_t iptos)

{
	struct timeval tv;

	struct tcp_function_block *tfb;
	struct tcp_rack *rack;
	struct epoch_tracker et;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (rack->r_state == 0) {
		
		INP_INFO_RLOCK_ET(&V_tcbinfo, et);
		tcp_get_usecs(&tv);
		rack_hpts_do_segment(m, th, so, tp, drop_hdrlen, tlen, iptos, 0, &tv);
		INP_INFO_RUNLOCK_ET(&V_tcbinfo, et);
		return;
	}
	tcp_queue_to_input(tp, m, th, tlen, drop_hdrlen, iptos);
	INP_WUNLOCK(tp->t_inpcb);

	tcp_get_usecs(&tv);
	rack_hpts_do_segment(m, th, so, tp, drop_hdrlen, tlen, iptos, 0, &tv);

}

struct rack_sendmap * tcp_rack_output(struct tcpcb *tp, struct tcp_rack *rack, uint32_t tsused)
{
	struct rack_sendmap *rsm = NULL;
	int32_t idx;
	uint32_t srtt_cur, srtt = 0, thresh = 0, ts_low = 0;

	
	if (TAILQ_EMPTY(&rack->r_ctl.rc_map)) {
		return (NULL);
	}
	if (tp->t_flags & TF_SENTFIN) {
		
		return (NULL);
	}
	
	rsm = TAILQ_FIRST(&rack->r_ctl.rc_tmap);
	if (rsm && ((rsm->r_flags & RACK_ACKED) == 0)) {
		goto check_it;
	}
	rsm = rack_find_lowest_rsm(rack);
	if (rsm == NULL) {
		return (NULL);
	}
check_it:
	srtt_cur = tp->t_srtt >> TCP_RTT_SHIFT;
	srtt = TICKS_2_MSEC(srtt_cur);
	if (rack->rc_rack_rtt && (srtt > rack->rc_rack_rtt))
		srtt = rack->rc_rack_rtt;
	if (rsm->r_flags & RACK_ACKED) {
		return (NULL);
	}
	if ((rsm->r_flags & RACK_SACK_PASSED) == 0) {
		
		return (NULL);
	}
	idx = rsm->r_rtr_cnt - 1;
	ts_low = rsm->r_tim_lastsent[idx];
	thresh = rack_calc_thresh_rack(rack, srtt, tsused);
	if (tsused <= ts_low) {
		return (NULL);
	}
	if ((tsused - ts_low) >= thresh) {
		return (rsm);
	}
	return (NULL);
}

static int rack_output(struct tcpcb *tp)
{
	struct socket *so;
	uint32_t recwin, sendwin;
	uint32_t sb_offset;
	int32_t len, flags, error = 0;
	struct mbuf *m;
	struct mbuf *mb;
	uint32_t if_hw_tsomaxsegcount = 0;
	uint32_t if_hw_tsomaxsegsize;
	long tot_len_this_send = 0;
	struct ip *ip = NULL;

	struct ipovly *ipov = NULL;

	struct udphdr *udp = NULL;
	struct tcp_rack *rack;
	struct tcphdr *th;
	uint8_t pass = 0;
	uint8_t wanted_cookie = 0;
	u_char opt[TCP_MAXOLEN];
	unsigned ipoptlen, optlen, hdrlen, ulen=0;
	uint32_t rack_seq;


	unsigned ipsec_optlen = 0;


	int32_t idle, sendalot;
	int32_t sub_from_prr = 0;
	volatile int32_t sack_rxmit;
	struct rack_sendmap *rsm = NULL;
	int32_t tso, mtu, would_have_fin = 0;
	struct tcpopt to;
	int32_t slot = 0;
	uint32_t cts;
	uint8_t hpts_calling, doing_tlp = 0;
	int32_t do_a_prefetch;
	int32_t prefetch_rsm = 0;
	int32_t prefetch_so_done = 0;
	struct tcp_log_buffer *lgb = NULL;
	struct inpcb *inp;
	struct sockbuf *sb;

	struct ip6_hdr *ip6 = NULL;
	int32_t isipv6;

	
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	inp = rack->rc_inp;
	so = inp->inp_socket;
	sb = &so->so_snd;
	kern_prefetch(sb, &do_a_prefetch);
	do_a_prefetch = 1;
	
	INP_WLOCK_ASSERT(inp);

	if (tp->t_flags & TF_TOE)
		return (tcp_offload_output(tp));


	if (rack->r_state) {
		
		isipv6 = rack->r_is_v6;
	} else {
		isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
	}

	cts = tcp_ts_getticks();
	if (((rack->r_ctl.rc_hpts_flags & PACE_PKT_OUTPUT) == 0) && inp->inp_in_hpts) {
		
		rack_timer_cancel(tp, rack, cts, __LINE__);
	}
	
	if ((rack->r_timer_override) || (tp->t_flags & TF_FORCEDATA) || (tp->t_state < TCPS_ESTABLISHED)) {

		if (tp->t_inpcb->inp_in_hpts)
			tcp_hpts_remove(tp->t_inpcb, HPTS_REMOVE_OUTPUT);
	} else if (tp->t_inpcb->inp_in_hpts) {
		
		counter_u64_add(rack_out_size[TCP_MSS_ACCT_INPACE], 1);
		return (0);
	}
	hpts_calling = inp->inp_hpts_calls;
	inp->inp_hpts_calls = 0;
	if (rack->r_ctl.rc_hpts_flags & PACE_TMR_MASK) {
		if (rack_process_timers(tp, rack, cts, hpts_calling)) {
			counter_u64_add(rack_out_size[TCP_MSS_ACCT_ATIMER], 1);
			return (0);
		}
	}
	rack->r_wanted_output = 0;
	rack->r_timer_override = 0;
	
	if (IS_FASTOPEN(tp->t_flags) && ((tp->t_state == TCPS_SYN_RECEIVED) || (tp->t_state == TCPS_SYN_SENT)) && SEQ_GT(tp->snd_max, tp->snd_una) && (tp->t_rxtshift == 0))



		return (0);
	
	idle = (tp->t_flags & TF_LASTIDLE) || (tp->snd_max == tp->snd_una);

	if (tp->cwv_enabled) {
		if ((tp->cwv_cwnd_valid == 0) && TCPS_HAVEESTABLISHED(tp->t_state) && (tp->snd_cwnd > tp->snd_cwv.init_cwnd))

			tcp_newcwv_nvp_closedown(tp);
	} else  if (tp->t_idle_reduce) {

		if (idle && ((ticks - tp->t_rcvtime) >= tp->t_rxtcur))
			rack_cc_after_idle(tp, (rack->r_idle_reduce_largest ? 1 :0));
	}
	tp->t_flags &= ~TF_LASTIDLE;
	if (idle) {
		if (tp->t_flags & TF_MORETOCOME) {
			tp->t_flags |= TF_LASTIDLE;
			idle = 0;
		}
	}
again:
	
	sendalot = 0;
	cts = tcp_ts_getticks();
	tso = 0;
	mtu = 0;
	sb_offset = tp->snd_max - tp->snd_una;
	sendwin = min(tp->snd_wnd, tp->snd_cwnd);

	flags = tcp_outflags[tp->t_state];
	
	
	while (rack->rc_free_cnt < rack_free_cache) {
		rsm = rack_alloc(rack);
		if (rsm == NULL) {
			if (inp->inp_hpts_calls)
				
				slot = 1;
			goto just_return_nolock;
		}
		TAILQ_INSERT_TAIL(&rack->r_ctl.rc_free, rsm, r_next);
		rack->rc_free_cnt++;
		rsm = NULL;
	}
	if (inp->inp_hpts_calls)
		inp->inp_hpts_calls = 0;
	sack_rxmit = 0;
	len = 0;
	rsm = NULL;
	if (flags & TH_RST) {
		SOCKBUF_LOCK(sb);
		goto send;
	}
	if (rack->r_ctl.rc_tlpsend) {
		
		long cwin;
		long tlen;

		doing_tlp = 1;
		rsm = rack->r_ctl.rc_tlpsend;
		rack->r_ctl.rc_tlpsend = NULL;
		sack_rxmit = 1;
		tlen = rsm->r_end - rsm->r_start;
		if (tlen > tp->t_maxseg)
			tlen = tp->t_maxseg;
		KASSERT(SEQ_LEQ(tp->snd_una, rsm->r_start), ("%s:%d: r.start:%u < SND.UNA:%u; tp:%p, rack:%p, rsm:%p", __func__, __LINE__, rsm->r_start, tp->snd_una, tp, rack, rsm));


		sb_offset = rsm->r_start - tp->snd_una;
		cwin = min(tp->snd_wnd, tlen);
		len = cwin;
	} else if (rack->r_ctl.rc_resend) {
		
		rsm = rack->r_ctl.rc_resend;
		rack->r_ctl.rc_resend = NULL;
		len = rsm->r_end - rsm->r_start;
		sack_rxmit = 1;
		sendalot = 0;
		KASSERT(SEQ_LEQ(tp->snd_una, rsm->r_start), ("%s:%d: r.start:%u < SND.UNA:%u; tp:%p, rack:%p, rsm:%p", __func__, __LINE__, rsm->r_start, tp->snd_una, tp, rack, rsm));


		sb_offset = rsm->r_start - tp->snd_una;
		if (len >= tp->t_maxseg) {
			len = tp->t_maxseg;
		}
	} else if ((rack->rc_in_persist == 0) && ((rsm = tcp_rack_output(tp, rack, cts)) != NULL)) {
		long tlen;

		if ((!IN_RECOVERY(tp->t_flags)) && ((tp->t_flags & (TF_WASFRECOVERY | TF_WASCRECOVERY)) == 0)) {
			
			rack->r_ctl.rc_rsm_start = rsm->r_start;
			rack->r_ctl.rc_cwnd_at = tp->snd_cwnd;
			rack->r_ctl.rc_ssthresh_at = tp->snd_ssthresh;
			rack_cong_signal(tp, NULL, CC_NDUPACK);
			
			rack->r_ctl.rc_prr_sndcnt = tp->t_maxseg;
		}

		if (SEQ_LT(rsm->r_start, tp->snd_una)) {
			panic("Huh, tp:%p rack:%p rsm:%p start:%u < snd_una:%u\n", tp, rack, rsm, rsm->r_start, tp->snd_una);
		}

		tlen = rsm->r_end - rsm->r_start;
		KASSERT(SEQ_LEQ(tp->snd_una, rsm->r_start), ("%s:%d: r.start:%u < SND.UNA:%u; tp:%p, rack:%p, rsm:%p", __func__, __LINE__, rsm->r_start, tp->snd_una, tp, rack, rsm));


		sb_offset = rsm->r_start - tp->snd_una;
		if (tlen > rack->r_ctl.rc_prr_sndcnt) {
			len = rack->r_ctl.rc_prr_sndcnt;
		} else {
			len = tlen;
		}
		if (len >= tp->t_maxseg) {
			sendalot = 1;
			len = tp->t_maxseg;
		} else {
			sendalot = 0;
			if ((rack->rc_timer_up == 0) && (len < tlen)) {
				
				len = 0;
				goto just_return_nolock;
			}
		}
		if (len > 0) {
			sub_from_prr = 1;
			sack_rxmit = 1;
			TCPSTAT_INC(tcps_sack_rexmits);
			TCPSTAT_ADD(tcps_sack_rexmit_bytes, min(len, tp->t_maxseg));
			counter_u64_add(rack_rtm_prr_retran, 1);
		}
	}
	if (rsm && (rsm->r_flags & RACK_HAS_FIN)) {
		
		len--;
		if (len) {
			
			flags &= ~TH_FIN;
		}
	}

	
	rack->r_ctl.rc_rsm_at_retran = rsm;

	
	if (tp->t_flags & TF_NEEDFIN)
		flags |= TH_FIN;
	if (tp->t_flags & TF_NEEDSYN)
		flags |= TH_SYN;
	if ((sack_rxmit == 0) && (prefetch_rsm == 0)) {
		void *end_rsm;
		end_rsm = TAILQ_LAST_FAST(&rack->r_ctl.rc_tmap, rack_sendmap, r_tnext);
		if (end_rsm)
			kern_prefetch(end_rsm, &prefetch_rsm);
		prefetch_rsm = 1;
	}
	SOCKBUF_LOCK(sb);
	
	if (tp->t_flags & TF_FORCEDATA) {
		if (sendwin == 0) {
			
			if (sb_offset < sbused(sb))
				flags &= ~TH_FIN;
			sendwin = 1;
		} else {
			if (rack->rc_in_persist)
				rack_exit_persist(tp, rack);
			
			tp->snd_nxt = tp->snd_max;
			sb_offset = tp->snd_nxt - tp->snd_una;
		}
	}
	
	if (sack_rxmit == 0) {
		uint32_t avail;

		avail = sbavail(sb);
		if (SEQ_GT(tp->snd_nxt, tp->snd_una) && avail)
			sb_offset = tp->snd_nxt - tp->snd_una;
		else sb_offset = 0;
		if (IN_RECOVERY(tp->t_flags) == 0) {
			if (rack->r_ctl.rc_tlp_new_data) {
				
				if (rack->r_ctl.rc_tlp_new_data > (uint32_t) (avail - sb_offset)) {
					rack->r_ctl.rc_tlp_new_data = (uint32_t) (avail - sb_offset);
				}
				if (rack->r_ctl.rc_tlp_new_data > tp->snd_wnd)
					len = tp->snd_wnd;
				else len = rack->r_ctl.rc_tlp_new_data;
				rack->r_ctl.rc_tlp_new_data = 0;
				doing_tlp = 1;
			} else {
				if (sendwin > avail) {
					
					if (avail > sb_offset) {
						len = (int32_t)(avail - sb_offset);
					} else {
						len = 0;
					}
				} else {
					if (sendwin > sb_offset) {
						len = (int32_t)(sendwin - sb_offset);
					} else {
						len = 0;
					}
				}
			}
		} else {
			uint32_t outstanding;

			
			outstanding = tp->snd_max - tp->snd_una;
			if ((rack->r_ctl.rc_prr_sndcnt + outstanding) > tp->snd_wnd)
				len = 0;
			else if (avail > sb_offset)
				len = avail - sb_offset;
			else len = 0;
			if (len > 0) {
				if (len > rack->r_ctl.rc_prr_sndcnt)
					len = rack->r_ctl.rc_prr_sndcnt;

				if (len > 0) {
					sub_from_prr = 1;
					counter_u64_add(rack_rtm_prr_newdata, 1);
				}
			}
			if (len > tp->t_maxseg) {
				
				if (rack->r_ctl.rc_prr_sendalot == 0)
					len = tp->t_maxseg;
			} else if (len < tp->t_maxseg) {
				
				long leftinsb;

				leftinsb = sbavail(sb) - sb_offset;
				if (leftinsb > len) {
					
					len = 0;
				}
			}
		}
	}
	if (prefetch_so_done == 0) {
		kern_prefetch(so, &prefetch_so_done);
		prefetch_so_done = 1;
	}
	
	if ((flags & TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una) && ((sack_rxmit == 0) && (tp->t_rxtshift == 0))) {
		if (tp->t_state != TCPS_SYN_RECEIVED)
			flags &= ~TH_SYN;
		
		if (IS_FASTOPEN(tp->t_flags) && (tp->t_state == TCPS_SYN_RECEIVED))
			flags &= ~TH_SYN;
		sb_offset--, len++;
	}
	
	if ((flags & TH_SYN) && (tp->t_flags & TF_NOOPT)) {
		len = 0;
		flags &= ~TH_FIN;
	}
	
	if (IS_FASTOPEN(tp->t_flags) && (((flags & TH_SYN) && (tp->t_rxtshift > 0)) || ((tp->t_state == TCPS_SYN_SENT) && (tp->t_tfo_client_cookie_len == 0)) || (flags & TH_RST))) {



		sack_rxmit = 0;
		len = 0;
	}
	
	if ((flags & TH_SYN) && (!IS_FASTOPEN(tp->t_flags)))
		len = 0;
	if (len <= 0) {
		
		len = 0;
		if ((tp->snd_wnd == 0) && (TCPS_HAVEESTABLISHED(tp->t_state)) && (sb_offset < (int)sbavail(sb))) {

			tp->snd_nxt = tp->snd_una;
			rack_enter_persist(tp, rack, cts);
		}
	}
	
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));
	tcp_sndbuf_autoscale(tp, so, sendwin);
	


	if (isipv6)
		ipoptlen = ip6_optlen(tp->t_inpcb);
	else  if (tp->t_inpcb->inp_options)

			ipoptlen = tp->t_inpcb->inp_options->m_len - offsetof(struct ipoption, ipopt_list);
		else ipoptlen = 0;

	

	if (isipv6 && IPSEC_ENABLED(ipv6))
		ipsec_optlen = IPSEC_HDRSIZE(ipv6, tp->t_inpcb);

	else    if (IPSEC_ENABLED(ipv4))



		ipsec_optlen = IPSEC_HDRSIZE(ipv4, tp->t_inpcb);




	ipoptlen += ipsec_optlen;

	if ((tp->t_flags & TF_TSO) && V_tcp_do_tso && len > tp->t_maxseg && (tp->t_port == 0) && ((tp->t_flags & TF_SIGNATURE) == 0) && tp->rcv_numsacks == 0 && sack_rxmit == 0 && ipoptlen == 0)



		tso = 1;
	{
		uint32_t outstanding;

		outstanding = tp->snd_max - tp->snd_una;
		if (tp->t_flags & TF_SENTFIN) {
			
			outstanding--;
		}
		if (outstanding > 0) {
			
			if (flags & TH_FIN) {
				flags &= ~TH_FIN;
				would_have_fin = 1;
			}
		} else if (sack_rxmit) {
			if ((rsm->r_flags & RACK_HAS_FIN) == 0)
				flags &= ~TH_FIN;
		} else {
			if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + sbused(sb)))
				flags &= ~TH_FIN;
		}
	}
	recwin = sbspace(&so->so_rcv);

	
	if (len) {
		if (len >= tp->t_maxseg) {
			pass = 1;
			goto send;
		}
		
		if (!(tp->t_flags & TF_MORETOCOME) &&	 (idle || (tp->t_flags & TF_NODELAY)) && ((uint32_t)len + (uint32_t)sb_offset >= sbavail(&so->so_snd)) && (tp->t_flags & TF_NOPUSH) == 0) {


			pass = 2;
			goto send;
		}
		if (tp->t_flags & TF_FORCEDATA) {	
			pass = 3;
			goto send;
		}
		if ((tp->snd_una == tp->snd_max) && len) {	
			goto send;
		}
		if (len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0) {
			pass = 4;
			goto send;
		}
		if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {	
			pass = 5;
			goto send;
		}
		if (sack_rxmit) {
			pass = 6;
			goto send;
		}
	}
	
	if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN) && !(tp->t_flags & TF_DELACK) && !TCPS_HAVERCVDFIN(tp->t_state)) {

		
		int32_t adv;
		int oldwin;

		adv = min(recwin, (long)TCP_MAXWIN << tp->rcv_scale);
		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt)) {
			oldwin = (tp->rcv_adv - tp->rcv_nxt);
			adv -= oldwin;
		} else oldwin = 0;

		
		if (oldwin >> tp->rcv_scale == (adv + oldwin) >> tp->rcv_scale)
			goto dontupdate;

		if (adv >= (int32_t)(2 * tp->t_maxseg) && (adv >= (int32_t)(so->so_rcv.sb_hiwat / 4) || recwin <= (int32_t)(so->so_rcv.sb_hiwat / 8) || so->so_rcv.sb_hiwat <= 8 * tp->t_maxseg)) {


			pass = 7;
			goto send;
		}
		if (2 * adv >= (int32_t) so->so_rcv.sb_hiwat)
			goto send;
	}
dontupdate:

	
	if (tp->t_flags & TF_ACKNOW) {
		pass = 8;
		goto send;
	}
	if (((flags & TH_SYN) && (tp->t_flags & TF_NEEDSYN) == 0)) {
		pass = 9;
		goto send;
	}
	if (SEQ_GT(tp->snd_up, tp->snd_una)) {
		pass = 10;
		goto send;
	}
	
	if ((flags & TH_FIN) && (tp->snd_nxt == tp->snd_una)) {
		pass = 11;
		goto send;
	}
	
just_return:
	SOCKBUF_UNLOCK(sb);
just_return_nolock:
	if (tot_len_this_send == 0)
		counter_u64_add(rack_out_size[TCP_MSS_ACCT_JUSTRET], 1);
	rack_start_hpts_timer(rack, tp, cts, __LINE__, slot, tot_len_this_send, 1);
	rack_log_type_just_return(rack, cts, tot_len_this_send, slot, hpts_calling);
	tp->t_flags &= ~TF_FORCEDATA;
	return (0);

send:
	if (doing_tlp == 0) {
		
		rack->rc_tlp_in_progress = 0;
	}
	SOCKBUF_LOCK_ASSERT(sb);
	if (len > 0) {
		if (len >= tp->t_maxseg)
			tp->t_flags2 |= TF2_PLPMTU_MAXSEGSNT;
		else tp->t_flags2 &= ~TF2_PLPMTU_MAXSEGSNT;
	}
	
	optlen = 0;

	if (isipv6)
		hdrlen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
	else  hdrlen = sizeof(struct tcpiphdr);


	
	to.to_flags = 0;
	if ((tp->t_flags & TF_NOOPT) == 0) {
		
		if (flags & TH_SYN) {
			tp->snd_nxt = tp->iss;
			to.to_mss = tcp_mssopt(&inp->inp_inc);

			if (tp->t_port)
				to.to_mss -= V_tcp_udp_tunneling_overhead;

			to.to_flags |= TOF_MSS;

			
			if (IS_FASTOPEN(tp->t_flags) && (tp->t_rxtshift == 0)) {
				if (tp->t_state == TCPS_SYN_RECEIVED) {
					to.to_tfo_len = TCP_FASTOPEN_COOKIE_LEN;
					to.to_tfo_cookie = (u_int8_t *)&tp->t_tfo_cookie.server;
					to.to_flags |= TOF_FASTOPEN;
					wanted_cookie = 1;
				} else if (tp->t_state == TCPS_SYN_SENT) {
					to.to_tfo_len = tp->t_tfo_client_cookie_len;
					to.to_tfo_cookie = tp->t_tfo_cookie.client;
					to.to_flags |= TOF_FASTOPEN;
					wanted_cookie = 1;
					
					sendalot = 0;
				}
			}
		}
		
		if ((flags & TH_SYN) && (tp->t_flags & TF_REQ_SCALE)) {
			to.to_wscale = tp->request_r_scale;
			to.to_flags |= TOF_SCALE;
		}
		
		if ((tp->t_flags & TF_RCVD_TSTMP) || ((flags & TH_SYN) && (tp->t_flags & TF_REQ_TSTMP))) {
			to.to_tsval = cts + tp->ts_offset;
			to.to_tsecr = tp->ts_recent;
			to.to_flags |= TOF_TS;
		}
		
		if (tp->rfbuf_ts == 0 && (so->so_rcv.sb_flags & SB_AUTOSIZE))
			tp->rfbuf_ts = tcp_ts_getticks();
		
		if (flags & TH_SYN)
			to.to_flags |= TOF_SACKPERM;
		else if (TCPS_HAVEESTABLISHED(tp->t_state) && tp->rcv_numsacks > 0) {
			to.to_flags |= TOF_SACK;
			to.to_nsacks = tp->rcv_numsacks;
			to.to_sacks = (u_char *)tp->sackblks;
		}

		
		if (tp->t_flags & TF_SIGNATURE)
			to.to_flags |= TOF_SIGNATURE;


		
		hdrlen += optlen = tcp_addoptions(&to, opt);
		
		if (IS_FASTOPEN(tp->t_flags) && wanted_cookie && !(to.to_flags & TOF_FASTOPEN))
			len = 0;
	}

	if (tp->t_port) {
		if (V_tcp_udp_tunneling_port == 0) {
			
			SOCKBUF_UNLOCK(&so->so_snd);
			return (EHOSTUNREACH);
		}
		hdrlen += sizeof(struct udphdr);
	}

	ipoptlen = 0;

	ipoptlen += ipsec_optlen;


	
	if (len + optlen + ipoptlen > tp->t_maxseg) {
		if (flags & TH_FIN) {
			would_have_fin = 1;
			flags &= ~TH_FIN;
		}
		if (tso) {
			uint32_t if_hw_tsomax;
			uint32_t moff;
			int32_t max_len;

			
			if_hw_tsomax = tp->t_tsomax;
			if_hw_tsomaxsegcount = tp->t_tsomaxsegcount;
			if_hw_tsomaxsegsize = tp->t_tsomaxsegsize;
			KASSERT(ipoptlen == 0, ("%s: TSO can't do IP options", __func__));

			
			if (if_hw_tsomax != 0) {
				
				max_len = (if_hw_tsomax - hdrlen - max_linkhdr);
				if (max_len <= 0) {
					len = 0;
				} else if (len > max_len) {
					sendalot = 1;
					len = max_len;
				}
			}
			
			max_len = (tp->t_maxseg - optlen);
			if ((sb_offset + len) < sbavail(sb)) {
				moff = len % (u_int)max_len;
				if (moff != 0) {
					len -= moff;
					sendalot = 1;
				}
			}
			
			if (len <= max_len) {
				len = max_len;
				sendalot = 1;
				tso = 0;
			}
			
			if (tp->t_flags & TF_NEEDFIN)
				sendalot = 1;

		} else {
			len = tp->t_maxseg - optlen - ipoptlen;
			sendalot = 1;
		}
	} else tso = 0;
	KASSERT(len + hdrlen + ipoptlen <= IP_MAXPACKET, ("%s: len > IP_MAXPACKET", __func__));


	if (max_linkhdr + hdrlen > MCLBYTES)

	if (max_linkhdr + hdrlen > MHLEN)

		panic("tcphdr too big");


	
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));
	if ((len == 0) && (flags & TH_FIN) && (sbused(sb))) {

		
		goto just_return;
	}
	
	if (len) {
		uint32_t max_val;
		uint32_t moff;

		if (rack->rc_pace_max_segs)
			max_val = rack->rc_pace_max_segs * tp->t_maxseg;
		else max_val = len;
		
		if (len > max_val) {
			len = max_val;
		}

		if (MHLEN < hdrlen + max_linkhdr)
			m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
		else  m = m_gethdr(M_NOWAIT, MT_DATA);


		if (m == NULL) {
			SOCKBUF_UNLOCK(sb);
			error = ENOBUFS;
			sack_rxmit = 0;
			goto out;
		}
		m->m_data += max_linkhdr;
		m->m_len = hdrlen;

		
		mb = sbsndptr_noadv(sb, sb_offset, &moff);
		if (len <= MHLEN - hdrlen - max_linkhdr) {
			m_copydata(mb, moff, (int)len, mtod(m, caddr_t)+hdrlen);
			if (SEQ_LT(tp->snd_nxt, tp->snd_max))
				sbsndptr_adv(sb, mb, len);
			m->m_len += len;
		} else {
			struct sockbuf *msb;

			if (SEQ_LT(tp->snd_nxt, tp->snd_max))
				msb = NULL;
			else msb = sb;
			m->m_next = tcp_m_copym(mb, moff, &len, if_hw_tsomaxsegcount, if_hw_tsomaxsegsize, msb);
			if (len <= (tp->t_maxseg - optlen)) {
				
				tso = 0;
			}
			if (m->m_next == NULL) {
				SOCKBUF_UNLOCK(sb);
				(void)m_free(m);
				error = ENOBUFS;
				sack_rxmit = 0;
				goto out;
			}
		}
		if ((tp->t_flags & TF_FORCEDATA) && len == 1) {
			TCPSTAT_INC(tcps_sndprobe);

			if (SEQ_LT(tp->snd_nxt, tp->snd_max))
				stats_voi_update_abs_u32(tp->t_stats, VOI_TCP_RETXPB, len);
			else stats_voi_update_abs_u64(tp->t_stats, VOI_TCP_TXPB, len);


		} else if (SEQ_LT(tp->snd_nxt, tp->snd_max) || sack_rxmit) {
			if (rsm && (rsm->r_flags & RACK_TLP)) {
				
				counter_u64_add(rack_tlp_retran, 1);
				counter_u64_add(rack_tlp_retran_bytes, len);
			} else {
				tp->t_sndrexmitpack++;
				TCPSTAT_INC(tcps_sndrexmitpack);
				TCPSTAT_ADD(tcps_sndrexmitbyte, len);
			}

			stats_voi_update_abs_u32(tp->t_stats, VOI_TCP_RETXPB, len);

		} else {
			TCPSTAT_INC(tcps_sndpack);
			TCPSTAT_ADD(tcps_sndbyte, len);

			stats_voi_update_abs_u64(tp->t_stats, VOI_TCP_TXPB, len);

		}
		
		if (sb_offset + len == sbused(sb) && sbused(sb) && !(flags & TH_SYN))

			flags |= TH_PUSH;

		
		if (((tp->t_state == TCPS_ESTABLISHED) || (tp->t_state == TCPS_CLOSE_WAIT) || ((tp->t_state == TCPS_FIN_WAIT_1) && ((tp->t_flags & TF_SENTFIN) == 0) && ((flags & TH_FIN) == 0))) && ((flags & TH_RST) == 0) && (rack->rc_always_pace)) {





			
			uint32_t srtt, cwnd, tr_perms = 0;
	
			if (rack->r_ctl.rc_rack_min_rtt)
				srtt = rack->r_ctl.rc_rack_min_rtt;
			else srtt = TICKS_2_MSEC((tp->t_srtt >> TCP_RTT_SHIFT));
			if (rack->r_ctl.rc_rack_largest_cwnd)
				cwnd = rack->r_ctl.rc_rack_largest_cwnd;
			else cwnd = tp->snd_cwnd;
			tr_perms = cwnd / srtt;
			if (tr_perms == 0) {
				tr_perms = tp->t_maxseg;
			}
			tot_len_this_send += len;
			
			slot = tot_len_this_send / tr_perms;
			
			if (slot && rack->rc_pace_reduce) {
				int32_t reduce;

				reduce = (slot / rack->rc_pace_reduce);
				if (reduce < slot) {
					slot -= reduce;
				} else slot = 0;
			}
			if (rack->r_enforce_min_pace && (slot == 0) && (tot_len_this_send >= (rack->r_min_pace_seg_thresh * tp->t_maxseg))) {

				
				slot = rack->r_enforce_min_pace;
			}
		}
		SOCKBUF_UNLOCK(sb);
	} else {
		SOCKBUF_UNLOCK(sb);
		if (tp->t_flags & TF_ACKNOW)
			TCPSTAT_INC(tcps_sndacks);
		else if (flags & (TH_SYN | TH_FIN | TH_RST))
			TCPSTAT_INC(tcps_sndctrl);
		else if (SEQ_GT(tp->snd_up, tp->snd_una))
			TCPSTAT_INC(tcps_sndurg);
		else TCPSTAT_INC(tcps_sndwinup);

		m = m_gethdr(M_NOWAIT, MT_DATA);
		if (m == NULL) {
			error = ENOBUFS;
			sack_rxmit = 0;
			goto out;
		}

		if (isipv6 && (MHLEN < hdrlen + max_linkhdr) && MHLEN >= hdrlen) {
			M_ALIGN(m, hdrlen);
		} else  m->m_data += max_linkhdr;

		m->m_len = hdrlen;
	}
	SOCKBUF_UNLOCK_ASSERT(sb);
	m->m_pkthdr.rcvif = (struct ifnet *)0;

	mac_inpcb_create_mbuf(inp, m);


	if (isipv6) {
		ip6 = mtod(m, struct ip6_hdr *);

		if (tp->t_port) {
			udp = (struct udphdr *)((caddr_t)ip6 + ipoptlen + sizeof(struct ip6_hdr));
			udp->uh_sport = htons(V_tcp_udp_tunneling_port);
			udp->uh_dport = tp->t_port;
			ulen = hdrlen + len - sizeof(struct ip6_hdr);
			udp->uh_ulen = htons(ulen);
			th = (struct tcphdr *)(udp + 1);
		} else  th = (struct tcphdr *)(ip6 + 1);

		tcpip_fillheaders(inp, ip6, th);
	} else  {

		ip = mtod(m, struct ip *);

		ipov = (struct ipovly *)ip;


		if (tp->t_port) {
			udp = (struct udphdr *)((caddr_t)ip + ipoptlen + sizeof(struct ip));
			udp->uh_sport = htons(V_tcp_udp_tunneling_port);
			udp->uh_dport = tp->t_port;
			ulen = hdrlen + len - sizeof(struct ip);
			udp->uh_ulen = htons(ulen);
			th = (struct tcphdr *)(udp + 1);
		} else  th = (struct tcphdr *)(ip + 1);

		tcpip_fillheaders(inp, ip, th);
	}
	
	if (flags & TH_FIN && tp->t_flags & TF_SENTFIN && tp->snd_nxt == tp->snd_max)
		tp->snd_nxt--;
	
	if (tp->t_state == TCPS_SYN_SENT && V_tcp_do_ecn == 1) {
		if (tp->t_rxtshift >= 1) {
			if (tp->t_rxtshift <= V_tcp_ecn_maxretries)
				flags |= TH_ECE | TH_CWR;
		} else flags |= TH_ECE | TH_CWR;
	}
	if (tp->t_state == TCPS_ESTABLISHED && (tp->t_flags & TF_ECN_PERMIT)) {
		
		if (len > 0 && SEQ_GEQ(tp->snd_nxt, tp->snd_max) && !((tp->t_flags & TF_FORCEDATA) && len == 1)) {

			if (isipv6)
				ip6->ip6_flow |= htonl(IPTOS_ECN_ECT0 << 20);
			else  ip->ip_tos |= IPTOS_ECN_ECT0;

			TCPSTAT_INC(tcps_ecn_ect0);
		}
		
		if (tp->t_flags & TF_ECN_SND_CWR) {
			flags |= TH_CWR;
			tp->t_flags &= ~TF_ECN_SND_CWR;
		}
		if (tp->t_flags & TF_ECN_SND_ECE)
			flags |= TH_ECE;
	}
	
	if (sack_rxmit == 0) {
		if (len || (flags & (TH_SYN | TH_FIN)) || rack->rc_in_persist) {
			th->th_seq = htonl(tp->snd_nxt);
			rack_seq = tp->snd_nxt;
		} else if (flags & TH_RST) {
			
			th->th_seq = htonl(tp->snd_una);
			rack_seq = tp->snd_una;
		} else {
			th->th_seq = htonl(tp->snd_max);
			rack_seq = tp->snd_max;
		}
	} else {
		th->th_seq = htonl(rsm->r_start);
		rack_seq = rsm->r_start;
	}
	th->th_ack = htonl(tp->rcv_nxt);
	if (optlen) {
		bcopy(opt, th + 1, optlen);
		th->th_off = (sizeof(struct tcphdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	
	if (flags & TH_RST) {
		recwin = 0;
	} else {
		if (recwin < (long)(so->so_rcv.sb_hiwat / 4) && recwin < (long)tp->t_maxseg)
			recwin = 0;
		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt) && recwin < (long)(tp->rcv_adv - tp->rcv_nxt))
			recwin = (long)(tp->rcv_adv - tp->rcv_nxt);
		if (recwin > (long)TCP_MAXWIN << tp->rcv_scale)
			recwin = (long)TCP_MAXWIN << tp->rcv_scale;
	}

	
	if (flags & TH_SYN)
		th->th_win = htons((u_short)
		    (min(sbspace(&so->so_rcv), TCP_MAXWIN)));
	else th->th_win = htons((u_short)(recwin >> tp->rcv_scale));
	
	if (th->th_win == 0) {
		tp->t_sndzerowin++;
		tp->t_flags |= TF_RXWIN0SENT;
	} else tp->t_flags &= ~TF_RXWIN0SENT;
	if (SEQ_GT(tp->snd_up, tp->snd_nxt)) {
		th->th_urp = htons((u_short)(tp->snd_up - tp->snd_nxt));
		th->th_flags |= TH_URG;
	} else  tp->snd_up = tp->snd_una;



	if (to.to_flags & TOF_SIGNATURE) {
		
		if (!TCPMD5_ENABLED() || TCPMD5_OUTPUT(m, th, (u_char *)(th + 1) + (to.to_signature - opt)) != 0) {
			
			goto out;
		}
	}


	
	m->m_pkthdr.len = hdrlen + len;	

	if (isipv6) {
		
		if (tp->t_port) {
			m->m_pkthdr.csum_flags = CSUM_UDP_IPV6;
			m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
			udp->uh_sum = in6_cksum_pseudo(ip6, ulen, IPPROTO_UDP, 0);
			th->th_sum = htons(0);
		} else {
			m->m_pkthdr.csum_flags = CSUM_TCP_IPV6;
			m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
			th->th_sum = in6_cksum_pseudo(ip6, sizeof(struct tcphdr) + optlen + len, IPPROTO_TCP, 0);

		}
	}


	else   {


		if (tp->t_port) {
			m->m_pkthdr.csum_flags = CSUM_UDP;
			m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
			udp->uh_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr, htons(ulen + IPPROTO_UDP));
			th->th_sum = htons(0);
		} else {
			m->m_pkthdr.csum_flags = CSUM_TCP;
			m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
			th->th_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr, htons(sizeof(struct tcphdr) + IPPROTO_TCP + len + optlen));

		}
		
		KASSERT(ip->ip_v == IPVERSION, ("%s: IP version incorrect: %d", __func__, ip->ip_v));
	}


	
	if (tso) {
		KASSERT(len > tp->t_maxseg - optlen, ("%s: len <= tso_segsz", __func__));
		m->m_pkthdr.csum_flags |= CSUM_TSO;
		m->m_pkthdr.tso_segsz = tp->t_maxseg - optlen;
	}

	KASSERT(len + hdrlen + ipoptlen - ipsec_optlen == m_length(m, NULL), ("%s: mbuf chain shorter than expected: %d + %u + %u - %u != %u", __func__, len, hdrlen, ipoptlen, ipsec_optlen, m_length(m, NULL)));


	KASSERT(len + hdrlen + ipoptlen == m_length(m, NULL), ("%s: mbuf chain shorter than expected: %d + %u + %u != %u", __func__, len, hdrlen, ipoptlen, m_length(m, NULL)));




	
	hhook_run_tcp_est_out(tp, th, &to, len, tso);



	
	if (so->so_options & SO_DEBUG) {
		u_short save = 0;


		if (!isipv6)

		{
			save = ipov->ih_len;
			ipov->ih_len = htons(m->m_pkthdr.len	 );
		}
		tcp_trace(TA_OUTPUT, tp->t_state, tp, mtod(m, void *), th, 0);

		if (!isipv6)

			ipov->ih_len = save;
	}


	
	if (tp->t_logstate != TCP_LOG_STATE_OFF) {
		union tcp_log_stackspecific log;

		memset(&log.u_bbr, 0, sizeof(log.u_bbr));
		log.u_bbr.inhpts = rack->rc_inp->inp_in_hpts;
		log.u_bbr.ininput = rack->rc_inp->inp_in_input;
		log.u_bbr.flex1 = rack->r_ctl.rc_prr_sndcnt;
		if (rsm || sack_rxmit) {
			log.u_bbr.flex8 = 1;
		} else {
			log.u_bbr.flex8 = 0;
		}
		lgb = tcp_log_event_(tp, th, &so->so_rcv, &so->so_snd, TCP_LOG_OUT, ERRNO_UNK, len, &log, false, NULL, NULL, 0, NULL);
	} else lgb = NULL;

	
	

	if (isipv6) {
		
		ip6->ip6_hlim = in6_selecthlim(inp, NULL);

		
		ip6->ip6_plen = htons(m->m_pkthdr.len - sizeof(*ip6));

		if (V_path_mtu_discovery && tp->t_maxseg > V_tcp_minmss)
			tp->t_flags2 |= TF2_PLPMTU_PMTUD;
		else tp->t_flags2 &= ~TF2_PLPMTU_PMTUD;

		if (tp->t_state == TCPS_SYN_SENT)
			TCP_PROBE5(connect__request, NULL, tp, ip6, tp, th);

		TCP_PROBE5(send, NULL, tp, ip6, tp, th);
		
		error = ip6_output(m, tp->t_inpcb->in6p_outputopts, &inp->inp_route6, ((so->so_options & SO_DONTROUTE) ? IP_ROUTETOIF : 0), NULL, NULL, inp);



		if (error == EMSGSIZE && inp->inp_route6.ro_rt != NULL)
			mtu = inp->inp_route6.ro_rt->rt_mtu;
	}


	else   {


		ip->ip_len = htons(m->m_pkthdr.len);

		if (inp->inp_vflag & INP_IPV6PROTO)
			ip->ip_ttl = in6_selecthlim(inp, NULL);

		
		if (V_path_mtu_discovery && tp->t_maxseg > V_tcp_minmss) {
			tp->t_flags2 |= TF2_PLPMTU_PMTUD;
			if (tp->t_port == 0 || len < V_tcp_minmss) {
				ip->ip_off |= htons(IP_DF);
			}
		} else {
			tp->t_flags2 &= ~TF2_PLPMTU_PMTUD;
		}

		if (tp->t_state == TCPS_SYN_SENT)
			TCP_PROBE5(connect__request, NULL, tp, ip, tp, th);

		TCP_PROBE5(send, NULL, tp, ip, tp, th);

		error = ip_output(m, tp->t_inpcb->inp_options, &inp->inp_route, ((so->so_options & SO_DONTROUTE) ? IP_ROUTETOIF : 0), 0, inp);

		if (error == EMSGSIZE && inp->inp_route.ro_rt != NULL)
			mtu = inp->inp_route.ro_rt->rt_mtu;
	}


out:
	if (lgb) {
		lgb->tlb_errno = error;
		lgb = NULL;
	}
	
	if (error == 0) {
		if (len == 0)
			counter_u64_add(rack_out_size[TCP_MSS_ACCT_SNDACK], 1);
		else if (len == 1) {
			counter_u64_add(rack_out_size[TCP_MSS_ACCT_PERSIST], 1);
		} else if (len > 1) {
			int idx;

			idx = (len / tp->t_maxseg) + 3;
			if (idx >= TCP_MSS_ACCT_ATIMER)
				counter_u64_add(rack_out_size[(TCP_MSS_ACCT_ATIMER-1)], 1);
			else counter_u64_add(rack_out_size[idx], 1);
		}
	}
	if (sub_from_prr && (error == 0)) {
		rack->r_ctl.rc_prr_sndcnt -= len;
	}
	sub_from_prr = 0;
	rack_log_output(tp, &to, len, rack_seq, (uint8_t) flags, error, cts, pass, rsm);
	if ((tp->t_flags & TF_FORCEDATA) == 0 || (rack->rc_in_persist == 0)) {
		tcp_seq startseq = tp->snd_nxt;

		
		if (error)
			
			goto timer;

		if (flags & (TH_SYN | TH_FIN)) {
			if (flags & TH_SYN)
				tp->snd_nxt++;
			if (flags & TH_FIN) {
				tp->snd_nxt++;
				tp->t_flags |= TF_SENTFIN;
			}
		}
		
		if (sack_rxmit)
			goto timer;

		tp->snd_nxt += len;
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
			if (tp->snd_una == tp->snd_max) {
				
				rack_log_progress_event(rack, tp, ticks, PROGRESS_START, __LINE__);
				tp->t_acktime = ticks;
			}
			tp->snd_max = tp->snd_nxt;
			
			if (tp->t_rtttime == 0) {
				tp->t_rtttime = ticks;
				tp->t_rtseq = startseq;
				TCPSTAT_INC(tcps_segstimed);
			}

			if (!(tp->t_flags & TF_GPUTINPROG) && len) {
				tp->t_flags |= TF_GPUTINPROG;
				tp->gput_seq = startseq;
				tp->gput_ack = startseq + ulmin(sbavail(sb) - sb_offset, sendwin);
				tp->gput_ts = tcp_ts_getticks();
			}

		}
		
timer:
		if ((tp->snd_wnd == 0) && TCPS_HAVEESTABLISHED(tp->t_state)) {
			
			if (rack->rc_in_persist == 0) {
				rack_enter_persist(tp, rack, cts);
			}
		}
	} else {
		
		int32_t xlen = len;

		if (error)
			goto nomore;

		if (flags & TH_SYN)
			++xlen;
		if (flags & TH_FIN) {
			++xlen;
			tp->t_flags |= TF_SENTFIN;
		}
		
		if (SEQ_GT(tp->snd_nxt + xlen, tp->snd_max)) {
			if (tp->snd_una == tp->snd_max) {
				
				rack_log_progress_event(rack, tp, ticks, PROGRESS_START, __LINE__);
				tp->t_acktime = ticks;
			}
			tp->snd_max = tp->snd_nxt + len;
		}
	}
nomore:
	if (error) {
		SOCKBUF_UNLOCK_ASSERT(sb);	
		
		sendalot = 0;
		switch (error) {
		case EPERM:
			tp->t_flags &= ~TF_FORCEDATA;
			tp->t_softerror = error;
			return (error);
		case ENOBUFS:
			if (slot == 0) {
				
				slot = 1 + rack->rc_enobuf;
				if (rack->rc_enobuf < 255)
					rack->rc_enobuf++;
				if (slot > (rack->rc_rack_rtt / 2)) {
					slot = rack->rc_rack_rtt / 2;
				}
				if (slot < 10)
					slot = 10;
			}
			counter_u64_add(rack_saw_enobuf, 1);
			error = 0;
			goto enobufs;
		case EMSGSIZE:
			
			if (tso)
				tp->t_flags &= ~TF_TSO;
			if (mtu != 0) {
				tcp_mss_update(tp, -1, mtu, NULL, NULL);
				goto again;
			}
			slot = 10;
			rack_start_hpts_timer(rack, tp, cts, __LINE__, slot, 0, 1);
			tp->t_flags &= ~TF_FORCEDATA;
			return (error);
		case ENETUNREACH:
			counter_u64_add(rack_saw_enetunreach, 1);
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ENETDOWN:
			if (TCPS_HAVERCVDSYN(tp->t_state)) {
				tp->t_softerror = error;
			}
			
		default:
			slot = 10;
			rack_start_hpts_timer(rack, tp, cts, __LINE__, slot, 0, 1);
			tp->t_flags &= ~TF_FORCEDATA;
			return (error);
		}
	} else {
		rack->rc_enobuf = 0;
	}
	TCPSTAT_INC(tcps_sndtotal);

	
	if (recwin > 0 && SEQ_GT(tp->rcv_nxt + recwin, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + recwin;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW | TF_DELACK);
enobufs:
	rack->r_tlp_running = 0;
	if ((flags & TH_RST) || (would_have_fin == 1)) {
		
		slot = 0;
		sendalot = 0;
	}
	if (slot) {
		
		counter_u64_add(rack_paced_segments, 1);
	} else if (sendalot) {
		if (len)
			counter_u64_add(rack_unpaced_segments, 1);
		sack_rxmit = 0;
		tp->t_flags &= ~TF_FORCEDATA;
		goto again;
	} else if (len) {
		counter_u64_add(rack_unpaced_segments, 1);
	}
	tp->t_flags &= ~TF_FORCEDATA;
	rack_start_hpts_timer(rack, tp, cts, __LINE__, slot, tot_len_this_send, 1);
	return (error);
}


static int rack_set_sockopt(struct socket *so, struct sockopt *sopt, struct inpcb *inp, struct tcpcb *tp, struct tcp_rack *rack)

{
	int32_t error = 0, optval;

	switch (sopt->sopt_name) {
	case TCP_RACK_PROP_RATE:
	case TCP_RACK_PROP:
	case TCP_RACK_TLP_REDUCE:
	case TCP_RACK_EARLY_RECOV:
	case TCP_RACK_PACE_ALWAYS:
	case TCP_DELACK:
	case TCP_RACK_PACE_REDUCE:
	case TCP_RACK_PACE_MAX_SEG:
	case TCP_RACK_PRR_SENDALOT:
	case TCP_RACK_MIN_TO:
	case TCP_RACK_EARLY_SEG:
	case TCP_RACK_REORD_THRESH:
	case TCP_RACK_REORD_FADE:
	case TCP_RACK_TLP_THRESH:
	case TCP_RACK_PKT_DELAY:
	case TCP_RACK_TLP_USE:
	case TCP_RACK_TLP_INC_VAR:
	case TCP_RACK_IDLE_REDUCE_HIGH:
	case TCP_RACK_MIN_PACE:
	case TCP_RACK_MIN_PACE_SEG:
	case TCP_BBR_RACK_RTT_USE:
	case TCP_DATA_AFTER_CLOSE:
		break;
	default:
		return (tcp_default_ctloutput(so, sopt, inp, tp));
		break;
	}
	INP_WUNLOCK(inp);
	error = sooptcopyin(sopt, &optval, sizeof(optval), sizeof(optval));
	if (error)
		return (error);
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);
	rack = (struct tcp_rack *)tp->t_fb_ptr;
	switch (sopt->sopt_name) {
	case TCP_RACK_PROP_RATE:
		if ((optval <= 0) || (optval >= 100)) {
			error = EINVAL;
			break;
		}
		RACK_OPTS_INC(tcp_rack_prop_rate);
		rack->r_ctl.rc_prop_rate = optval;
		break;
	case TCP_RACK_TLP_USE:
		if ((optval < TLP_USE_ID) || (optval > TLP_USE_TWO_TWO)) {
			error = EINVAL;
			break;
		}
		RACK_OPTS_INC(tcp_tlp_use);
		rack->rack_tlp_threshold_use = optval;
		break;
	case TCP_RACK_PROP:
		
		RACK_OPTS_INC(tcp_rack_prop);
		rack->r_ctl.rc_prop_reduce = optval;
		break;
	case TCP_RACK_TLP_REDUCE:
		
		RACK_OPTS_INC(tcp_rack_tlp_reduce);
		rack->r_ctl.rc_tlp_cwnd_reduce = optval;
		break;
	case TCP_RACK_EARLY_RECOV:
		
		RACK_OPTS_INC(tcp_rack_early_recov);
		rack->r_ctl.rc_early_recovery = optval;
		break;
	case TCP_RACK_PACE_ALWAYS:
		
		RACK_OPTS_INC(tcp_rack_pace_always);
		if (optval > 0)
			rack->rc_always_pace = 1;
		else rack->rc_always_pace = 0;
		break;
	case TCP_RACK_PACE_REDUCE:
		
		RACK_OPTS_INC(tcp_rack_pace_reduce);
		if (optval)
			
			rack->rc_pace_reduce = optval;
		else error = EINVAL;
		break;
	case TCP_RACK_PACE_MAX_SEG:
		
		RACK_OPTS_INC(tcp_rack_max_seg);
		rack->rc_pace_max_segs = optval;
		break;
	case TCP_RACK_PRR_SENDALOT:
		
		RACK_OPTS_INC(tcp_rack_prr_sendalot);
		rack->r_ctl.rc_prr_sendalot = optval;
		break;
	case TCP_RACK_MIN_TO:
		
		RACK_OPTS_INC(tcp_rack_min_to);
		rack->r_ctl.rc_min_to = optval;
		break;
	case TCP_RACK_EARLY_SEG:
		
		RACK_OPTS_INC(tcp_rack_early_seg);
		rack->r_ctl.rc_early_recovery_segs = optval;
		break;
	case TCP_RACK_REORD_THRESH:
		
		RACK_OPTS_INC(tcp_rack_reord_thresh);
		if ((optval > 0) && (optval < 31))
			rack->r_ctl.rc_reorder_shift = optval;
		else error = EINVAL;
		break;
	case TCP_RACK_REORD_FADE:
		
		RACK_OPTS_INC(tcp_rack_reord_fade);
		rack->r_ctl.rc_reorder_fade = optval;
		break;
	case TCP_RACK_TLP_THRESH:
		
		RACK_OPTS_INC(tcp_rack_tlp_thresh);
		if (optval)
			rack->r_ctl.rc_tlp_threshold = optval;
		else error = EINVAL;
		break;
	case TCP_RACK_PKT_DELAY:
		
		RACK_OPTS_INC(tcp_rack_pkt_delay);
		rack->r_ctl.rc_pkt_delay = optval;
		break;
	case TCP_RACK_TLP_INC_VAR:
		
		RACK_OPTS_INC(tcp_rack_tlp_inc_var);
		rack->r_ctl.rc_prr_inc_var = optval;
		break;
	case TCP_RACK_IDLE_REDUCE_HIGH:
		RACK_OPTS_INC(tcp_rack_idle_reduce_high);
		if (optval)
			rack->r_idle_reduce_largest = 1;
		else rack->r_idle_reduce_largest = 0;
		break;
	case TCP_DELACK:
		if (optval == 0)
			tp->t_delayed_ack = 0;
		else tp->t_delayed_ack = 1;
		if (tp->t_flags & TF_DELACK) {
			tp->t_flags &= ~TF_DELACK;
			tp->t_flags |= TF_ACKNOW;
			rack_output(tp);
		}
		break;
	case TCP_RACK_MIN_PACE:
		RACK_OPTS_INC(tcp_rack_min_pace);
		if (optval > 3)
			rack->r_enforce_min_pace = 3;
		else rack->r_enforce_min_pace = optval;
		break;
	case TCP_RACK_MIN_PACE_SEG:
		RACK_OPTS_INC(tcp_rack_min_pace_seg);
		if (optval >= 16)
			rack->r_min_pace_seg_thresh = 15;
		else rack->r_min_pace_seg_thresh = optval;
		break;
	case TCP_BBR_RACK_RTT_USE:
		if ((optval != USE_RTT_HIGH) && (optval != USE_RTT_LOW) && (optval != USE_RTT_AVG))

			error = EINVAL;
		else rack->r_ctl.rc_rate_sample_method = optval;
		break;
	case TCP_DATA_AFTER_CLOSE:
		if (optval)
			rack->rc_allow_data_af_clo = 1;
		else rack->rc_allow_data_af_clo = 0;
		break;
	default:
		return (tcp_default_ctloutput(so, sopt, inp, tp));
		break;
	}

	tcp_log_socket_option(tp, sopt->sopt_name, optval, error);

	INP_WUNLOCK(inp);
	return (error);
}

static int rack_get_sockopt(struct socket *so, struct sockopt *sopt, struct inpcb *inp, struct tcpcb *tp, struct tcp_rack *rack)

{
	int32_t error, optval;

	
	switch (sopt->sopt_name) {
	case TCP_RACK_PROP_RATE:
		optval = rack->r_ctl.rc_prop_rate;
		break;
	case TCP_RACK_PROP:
		
		optval = rack->r_ctl.rc_prop_reduce;
		break;
	case TCP_RACK_TLP_REDUCE:
		
		optval = rack->r_ctl.rc_tlp_cwnd_reduce;
		break;
	case TCP_RACK_EARLY_RECOV:
		
		optval = rack->r_ctl.rc_early_recovery;
		break;
	case TCP_RACK_PACE_REDUCE:
		
		optval = rack->rc_pace_reduce;
		break;
	case TCP_RACK_PACE_MAX_SEG:
		
		optval = rack->rc_pace_max_segs;
		break;
	case TCP_RACK_PACE_ALWAYS:
		
		optval = rack->rc_always_pace;
		break;
	case TCP_RACK_PRR_SENDALOT:
		
		optval = rack->r_ctl.rc_prr_sendalot;
		break;
	case TCP_RACK_MIN_TO:
		
		optval = rack->r_ctl.rc_min_to;
		break;
	case TCP_RACK_EARLY_SEG:
		
		optval = rack->r_ctl.rc_early_recovery_segs;
		break;
	case TCP_RACK_REORD_THRESH:
		
		optval = rack->r_ctl.rc_reorder_shift;
		break;
	case TCP_RACK_REORD_FADE:
		
		optval = rack->r_ctl.rc_reorder_fade;
		break;
	case TCP_RACK_TLP_THRESH:
		
		optval = rack->r_ctl.rc_tlp_threshold;
		break;
	case TCP_RACK_PKT_DELAY:
		
		optval = rack->r_ctl.rc_pkt_delay;
		break;
	case TCP_RACK_TLP_USE:
		optval = rack->rack_tlp_threshold_use;
		break;
	case TCP_RACK_TLP_INC_VAR:
		
		optval = rack->r_ctl.rc_prr_inc_var;
		break;
	case TCP_RACK_IDLE_REDUCE_HIGH:
		optval = rack->r_idle_reduce_largest;
		break;
	case TCP_RACK_MIN_PACE:
		optval = rack->r_enforce_min_pace;
		break;
	case TCP_RACK_MIN_PACE_SEG:
		optval = rack->r_min_pace_seg_thresh;
		break;
	case TCP_BBR_RACK_RTT_USE:
		optval = rack->r_ctl.rc_rate_sample_method;
		break;
	case TCP_DELACK:
		optval = tp->t_delayed_ack;
		break;
	case TCP_DATA_AFTER_CLOSE:
		optval = rack->rc_allow_data_af_clo;
		break;
	default:
		return (tcp_default_ctloutput(so, sopt, inp, tp));
		break;
	}
	INP_WUNLOCK(inp);
	error = sooptcopyout(sopt, &optval, sizeof optval);
	return (error);
}

static int rack_ctloutput(struct socket *so, struct sockopt *sopt, struct inpcb *inp, struct tcpcb *tp)
{
	int32_t error = EINVAL;
	struct tcp_rack *rack;

	rack = (struct tcp_rack *)tp->t_fb_ptr;
	if (rack == NULL) {
		
		goto out;
	}
	if (sopt->sopt_dir == SOPT_SET) {
		return (rack_set_sockopt(so, sopt, inp, tp, rack));
	} else if (sopt->sopt_dir == SOPT_GET) {
		return (rack_get_sockopt(so, sopt, inp, tp, rack));
	}
out:
	INP_WUNLOCK(inp);
	return (error);
}


struct tcp_function_block __tcp_rack = {
	.tfb_tcp_block_name = __XSTRING(STACKNAME), .tfb_tcp_output = rack_output, .tfb_tcp_do_segment = rack_do_segment, .tfb_tcp_hpts_do_segment = rack_hpts_do_segment, .tfb_tcp_ctloutput = rack_ctloutput, .tfb_tcp_fb_init = rack_init, .tfb_tcp_fb_fini = rack_fini, .tfb_tcp_timer_stop_all = rack_stopall, .tfb_tcp_timer_activate = rack_timer_activate, .tfb_tcp_timer_active = rack_timer_active, .tfb_tcp_timer_stop = rack_timer_stop, .tfb_tcp_rexmit_tmr = rack_remxt_tmr, .tfb_tcp_handoff_ok = rack_handoff_ok };













static const char *rack_stack_names[] = {
	__XSTRING(STACKNAME),  __XSTRING(STACKALIAS),  };




static int rack_ctor(void *mem, int32_t size, void *arg, int32_t how)
{
	memset(mem, 0, size);
	return (0);
}

static void rack_dtor(void *mem, int32_t size, void *arg)
{

}

static bool rack_mod_inited = false;

static int tcp_addrack(module_t mod, int32_t type, void *data)
{
	int32_t err = 0;
	int num_stacks;

	switch (type) {
	case MOD_LOAD:
		rack_zone = uma_zcreate(__XSTRING(MODNAME) "_map", sizeof(struct rack_sendmap), rack_ctor, rack_dtor, NULL, NULL, UMA_ALIGN_PTR, 0);


		rack_pcb_zone = uma_zcreate(__XSTRING(MODNAME) "_pcb", sizeof(struct tcp_rack), rack_ctor, NULL, NULL, NULL, UMA_ALIGN_CACHE, 0);


		sysctl_ctx_init(&rack_sysctl_ctx);
		rack_sysctl_root = SYSCTL_ADD_NODE(&rack_sysctl_ctx, SYSCTL_STATIC_CHILDREN(_net_inet_tcp), OID_AUTO, __XSTRING(STACKNAME), CTLFLAG_RW, 0, "");




		if (rack_sysctl_root == NULL) {
			printf("Failed to add sysctl node\n");
			err = EFAULT;
			goto free_uma;
		}
		rack_init_sysctls();
		num_stacks = nitems(rack_stack_names);
		err = register_tcp_functions_as_names(&__tcp_rack, M_WAITOK, rack_stack_names, &num_stacks);
		if (err) {
			printf("Failed to register %s stack name for " "%s module\n", rack_stack_names[num_stacks], __XSTRING(MODNAME));

			sysctl_ctx_free(&rack_sysctl_ctx);
free_uma:
			uma_zdestroy(rack_zone);
			uma_zdestroy(rack_pcb_zone);
			rack_counter_destroy();
			printf("Failed to register rack module -- err:%d\n", err);
			return (err);
		}
		rack_mod_inited = true;
		break;
	case MOD_QUIESCE:
		err = deregister_tcp_functions(&__tcp_rack, true, false);
		break;
	case MOD_UNLOAD:
		err = deregister_tcp_functions(&__tcp_rack, false, true);
		if (err == EBUSY)
			break;
		if (rack_mod_inited) {
			uma_zdestroy(rack_zone);
			uma_zdestroy(rack_pcb_zone);
			sysctl_ctx_free(&rack_sysctl_ctx);
			rack_counter_destroy();
			rack_mod_inited = false;
		}
		err = 0;
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (err);
}

static moduledata_t tcp_rack = {
	.name = __XSTRING(MODNAME), .evhand = tcp_addrack, .priv = 0 };



MODULE_VERSION(MODNAME, 1);
DECLARE_MODULE(MODNAME, tcp_rack, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY);
MODULE_DEPEND(MODNAME, tcphpts, 1, 1, 1);
