








typedef struct {
	pmixp_coll_t *coll;
	pmixp_coll_ring_ctx_t *coll_ctx;
	Buf buf;
	uint32_t seq;
} pmixp_coll_ring_cbdata_t;

static void _progress_coll_ring(pmixp_coll_ring_ctx_t *coll_ctx);

static inline int _ring_prev_id(pmixp_coll_t *coll)
{
	return (coll->my_peerid + coll->peers_cnt - 1) % coll->peers_cnt;
}

static inline int _ring_next_id(pmixp_coll_t *coll)
{
	return (coll->my_peerid + 1) % coll->peers_cnt;
}

static inline pmixp_coll_t *_ctx_get_coll(pmixp_coll_ring_ctx_t *coll_ctx)
{
	return coll_ctx->coll;
}

static inline pmixp_coll_ring_t *_ctx_get_coll_ring( pmixp_coll_ring_ctx_t *coll_ctx)
{
	return &coll_ctx->coll->state.ring;
}

static inline uint32_t _ring_remain_contrib(pmixp_coll_ring_ctx_t *coll_ctx)
{
	return coll_ctx->coll->peers_cnt - (coll_ctx->contrib_prev + coll_ctx->contrib_local);
}

static inline uint32_t _ring_fwd_done(pmixp_coll_ring_ctx_t *coll_ctx)
{
	return !(coll_ctx->coll->peers_cnt - coll_ctx->forward_cnt - 1);
}

static void _ring_sent_cb(int rc, pmixp_p2p_ctx_t ctx, void *_cbdata)
{
	pmixp_coll_ring_cbdata_t *cbdata = (pmixp_coll_ring_cbdata_t*)_cbdata;
	pmixp_coll_ring_ctx_t *coll_ctx = cbdata->coll_ctx;
	pmixp_coll_t *coll = cbdata->coll;
	Buf buf = cbdata->buf;

	pmixp_coll_sanity_check(coll);

	if (PMIXP_P2P_REGULAR == ctx) {
		
		slurm_mutex_lock(&coll->lock);
	}

	PMIXP_DEBUG("%p: called %d", coll_ctx, coll_ctx->seq);

	if (cbdata->seq != coll_ctx->seq) {
		
		PMIXP_DEBUG("%p: collective was reset!", coll_ctx);
		goto exit;
	}
	coll_ctx->forward_cnt++;
	_progress_coll_ring(coll_ctx);

exit:
	pmixp_server_buf_reset(buf);
	list_push(coll->state.ring.fwrd_buf_pool, buf);

	if (PMIXP_P2P_REGULAR == ctx) {
		
		slurm_mutex_unlock(&coll->lock);
	}
	xfree(cbdata);
}

static inline void pmixp_coll_ring_ctx_sanity_check( pmixp_coll_ring_ctx_t *coll_ctx)
{
	xassert(NULL != coll_ctx);
	xassert(coll_ctx->in_use);
	pmixp_coll_sanity_check(coll_ctx->coll);
}


pmixp_coll_t *pmixp_coll_ring_from_cbdata(void *cbdata)
{
	pmixp_coll_ring_cbdata_t *ptr = (pmixp_coll_ring_cbdata_t*)cbdata;
	pmixp_coll_sanity_check(ptr->coll);
	return ptr->coll;
}

int pmixp_coll_ring_unpack(Buf buf, pmixp_coll_type_t *type, pmixp_coll_ring_msg_hdr_t *ring_hdr, pmixp_proc_t **r, size_t *nr)

{
	pmixp_proc_t *procs = NULL;
	uint32_t nprocs = 0;
	uint32_t tmp;
	int rc, i;

	
	if (SLURM_SUCCESS != (rc = unpack32(&tmp, buf))) {
		PMIXP_ERROR("Cannot unpack collective type");
		return rc;
	}
	*type = tmp;

	
	if (SLURM_SUCCESS != (rc = unpack32(&nprocs, buf))) {
		PMIXP_ERROR("Cannot unpack collective type");
		return rc;
	}
	*nr = nprocs;

	procs = xmalloc(sizeof(pmixp_proc_t) * nprocs);
	*r = procs;

	
	for (i = 0; i < (int)nprocs; i++) {
		rc = unpackmem(procs[i].nspace, &tmp, buf);
		if (SLURM_SUCCESS != rc) {
			PMIXP_ERROR("Cannot unpack namespace for process #%d", i);
			return rc;
		}
		procs[i].nspace[tmp] = '\0';

		rc = unpack32(&tmp, buf);
		procs[i].rank = tmp;
		if (SLURM_SUCCESS != rc) {
			PMIXP_ERROR("Cannot unpack ranks for process #%d, nsp=%s", i, procs[i].nspace);
			return rc;
		}
	}

	
	if (SLURM_SUCCESS != (rc = unpackmem((char *)ring_hdr, &tmp, buf))) {
		PMIXP_ERROR("Cannot unpack ring info");
		return rc;
	}

	return SLURM_SUCCESS;
}

static int _pack_coll_ring_info(pmixp_coll_t *coll, pmixp_coll_ring_msg_hdr_t *ring_hdr, Buf buf)

{
	pmixp_proc_t *procs = coll->pset.procs;
	size_t nprocs = coll->pset.nprocs;
	uint32_t type = PMIXP_COLL_TYPE_FENCE_RING;
	int i;

	
	pack32(type, buf);

	
	pack32(nprocs, buf);
	for (i = 0; i < (int)nprocs; i++) {
		
		packmem(procs->nspace, strlen(procs->nspace) + 1, buf);
		pack32(procs->rank, buf);
	}

	
	packmem((char*)ring_hdr, sizeof(pmixp_coll_ring_msg_hdr_t), buf);

	return SLURM_SUCCESS;
}

static Buf _get_fwd_buf(pmixp_coll_ring_ctx_t *coll_ctx)
{
	pmixp_coll_ring_t *ring = _ctx_get_coll_ring(coll_ctx);
	Buf buf = list_pop(ring->fwrd_buf_pool);
	if (!buf) {
		buf = pmixp_server_buf_new();
	}
	return buf;
}

static Buf _get_contrib_buf(pmixp_coll_ring_ctx_t *coll_ctx)
{
	pmixp_coll_ring_t *ring = _ctx_get_coll_ring(coll_ctx);
	Buf ring_buf = list_pop(ring->ring_buf_pool);
	if (!ring_buf) {
		ring_buf = create_buf(NULL, 0);
	}
	return ring_buf;
}

static int _ring_forward_data(pmixp_coll_ring_ctx_t *coll_ctx, uint32_t contrib_id, uint32_t hop_seq, void *data, size_t size)
{
	pmixp_coll_ring_msg_hdr_t hdr;
	pmixp_coll_t *coll = _ctx_get_coll(coll_ctx);
	pmixp_coll_ring_t *ring = &coll->state.ring;
	hdr.nodeid = coll->my_peerid;
	hdr.msgsize = size;
	hdr.seq = coll_ctx->seq;
	hdr.hop_seq = hop_seq;
	hdr.contrib_id = contrib_id;
	pmixp_ep_t *ep = (pmixp_ep_t*)xmalloc(sizeof(*ep));
	pmixp_coll_ring_cbdata_t *cbdata = NULL;
	uint32_t offset = 0;
	Buf buf = _get_fwd_buf(coll_ctx);
	int rc = SLURM_SUCCESS;


	pmixp_coll_ring_ctx_sanity_check(coll_ctx);


	PMIXP_DEBUG("%p: transit data to nodeid=%d, seq=%d, hop=%d, size=%lu, contrib=%d", coll_ctx, _ring_next_id(coll), hdr.seq, hdr.hop_seq, hdr.msgsize, hdr.contrib_id);


	if (!buf) {
		rc = SLURM_ERROR;
		goto exit;
	}
	ep->type = PMIXP_EP_NOIDEID;
	ep->ep.nodeid = ring->next_peerid;

	
	_pack_coll_ring_info(coll, &hdr, buf);

	
	offset = get_buf_offset(buf);
	pmixp_server_buf_reserve(buf, size);
	memcpy(get_buf_data(buf) + offset, data, size);
	set_buf_offset(buf, offset + size);

	cbdata = xmalloc(sizeof(pmixp_coll_ring_cbdata_t));
	cbdata->buf = buf;
	cbdata->coll = coll;
	cbdata->coll_ctx = coll_ctx;
	cbdata->seq = coll_ctx->seq;
	rc = pmixp_server_send_nb(ep, PMIXP_MSG_RING, coll_ctx->seq, buf, _ring_sent_cb, cbdata);
exit:
	return rc;
}

static void _reset_coll_ring(pmixp_coll_ring_ctx_t *coll_ctx)
{
	pmixp_coll_t *coll = _ctx_get_coll(coll_ctx);

	PMIXP_DEBUG("%p: called", coll_ctx);

	pmixp_coll_ring_ctx_sanity_check(coll_ctx);
	coll_ctx->in_use = false;
	coll_ctx->state = PMIXP_COLL_RING_SYNC;
	coll_ctx->contrib_local = false;
	coll_ctx->contrib_prev = 0;
	coll_ctx->forward_cnt = 0;
	coll->ts = time(NULL);
	memset(coll_ctx->contrib_map, 0, sizeof(bool) * coll->peers_cnt);
	coll_ctx->ring_buf = NULL;
}

static void _libpmix_cb(void *_vcbdata)
{
	pmixp_coll_ring_cbdata_t *cbdata = (pmixp_coll_ring_cbdata_t*)_vcbdata;
	pmixp_coll_t *coll = cbdata->coll;
	Buf buf = cbdata->buf;

	pmixp_coll_sanity_check(coll);

	
	slurm_mutex_lock(&coll->lock);

	
	buf->processed = 0;
	
	list_push(coll->state.ring.ring_buf_pool, buf);

	
	slurm_mutex_unlock(&coll->lock);

	xfree(cbdata);
}

static void _invoke_callback(pmixp_coll_ring_ctx_t *coll_ctx)
{
	pmixp_coll_ring_cbdata_t *cbdata;
	char *data;
	size_t data_sz;
	pmixp_coll_t *coll = _ctx_get_coll(coll_ctx);

	if (!coll->cbfunc)
		return;

	data = get_buf_data(coll_ctx->ring_buf);
	data_sz = get_buf_offset(coll_ctx->ring_buf);
	cbdata = xmalloc(sizeof(pmixp_coll_ring_cbdata_t));

	cbdata->coll = coll;
	cbdata->coll_ctx = coll_ctx;
	cbdata->buf = coll_ctx->ring_buf;
	cbdata->seq = coll_ctx->seq;
	pmixp_lib_modex_invoke(coll->cbfunc, SLURM_SUCCESS, data, data_sz, coll->cbdata, _libpmix_cb, (void *)cbdata);

	
	coll->cbfunc = NULL;
	coll->cbdata = NULL;
}

static void _progress_coll_ring(pmixp_coll_ring_ctx_t *coll_ctx)
{
	int ret = 0;
	pmixp_coll_t *coll = _ctx_get_coll(coll_ctx);

	pmixp_coll_ring_ctx_sanity_check(coll_ctx);

	do {
		ret = false;
		switch(coll_ctx->state) {
		case PMIXP_COLL_RING_SYNC:
			if (coll_ctx->contrib_local || coll_ctx->contrib_prev) {
				coll_ctx->state = PMIXP_COLL_RING_PROGRESS;
				ret = true;
			}
			break;
		case PMIXP_COLL_RING_PROGRESS:
			
			if (!_ring_remain_contrib(coll_ctx) ) {
				coll_ctx->state = PMIXP_COLL_RING_FINALIZE;
				_invoke_callback(coll_ctx);
				ret = true;
			}
			break;
		case PMIXP_COLL_RING_FINALIZE:
			if(_ring_fwd_done(coll_ctx)) {

				PMIXP_DEBUG("%p: %s seq=%d is DONE", coll, pmixp_coll_type2str(coll->type), coll_ctx->seq);


				
				coll->seq++;
				_reset_coll_ring(coll_ctx);
				ret = true;

			}
			break;
		default:
			PMIXP_ERROR("%p: unknown state = %d", coll_ctx, (int)coll_ctx->state);
		}
	} while(ret);
}

pmixp_coll_ring_ctx_t *pmixp_coll_ring_ctx_new(pmixp_coll_t *coll)
{
	int i;
	pmixp_coll_ring_ctx_t *coll_ctx = NULL, *ret_ctx = NULL, *free_ctx = NULL;
	pmixp_coll_ring_t *ring = &coll->state.ring;
	uint32_t seq = coll->seq;

	for (i = 0; i < PMIXP_COLL_RING_CTX_NUM; i++) {
		coll_ctx = &ring->ctx_array[i];
		
		if (coll_ctx->in_use) {
			switch(coll_ctx->state) {
			case PMIXP_COLL_RING_FINALIZE:
				seq++;
				break;
			case PMIXP_COLL_RING_SYNC:
			case PMIXP_COLL_RING_PROGRESS:
				if (!ret_ctx && !coll_ctx->contrib_local) {
					ret_ctx = coll_ctx;
				}
				break;
			}
		} else {
			free_ctx = coll_ctx;
			xassert(!free_ctx->in_use);
		}
	}
	
	if (!ret_ctx && free_ctx) {
		ret_ctx = free_ctx;
		ret_ctx->in_use = true;
		ret_ctx->seq = seq;
		ret_ctx->ring_buf = _get_contrib_buf(ret_ctx);
	}
	return ret_ctx;
}

pmixp_coll_ring_ctx_t *pmixp_coll_ring_ctx_select(pmixp_coll_t *coll, const uint32_t seq)
{
	int i;
	pmixp_coll_ring_ctx_t *coll_ctx = NULL, *ret = NULL;
	pmixp_coll_ring_t *ring = &coll->state.ring;

	
	for (i = 0; i < PMIXP_COLL_RING_CTX_NUM; i++) {
		coll_ctx = &ring->ctx_array[i];
		if (coll_ctx->in_use && coll_ctx->seq == seq) {
			return coll_ctx;
		} else if (!coll_ctx->in_use) {
			ret = coll_ctx;
			continue;
		}
	}
	
	if (ret && !ret->in_use) {
		ret->in_use = true;
		ret->seq = seq;
		ret->ring_buf = _get_contrib_buf(ret);
	}
	return ret;
}

int pmixp_coll_ring_init(pmixp_coll_t *coll, hostlist_t *hl)
{

	PMIXP_DEBUG("called");

	int i;
	pmixp_coll_ring_ctx_t *coll_ctx = NULL;
	pmixp_coll_ring_t *ring = &coll->state.ring;
	char *p;
	int rel_id = hostlist_find(*hl, pmixp_info_hostname());

	
	p = hostlist_nth(*hl, (rel_id + 1) % coll->peers_cnt);
	ring->next_peerid = pmixp_info_job_hostid(p);
	free(p);

	ring->fwrd_buf_pool = list_create(pmixp_free_buf);
	ring->ring_buf_pool = list_create(pmixp_free_buf);

	for (i = 0; i < PMIXP_COLL_RING_CTX_NUM; i++) {
		coll_ctx = &ring->ctx_array[i];
		coll_ctx->coll = coll;
		coll_ctx->in_use = false;
		coll_ctx->seq = coll->seq;
		coll_ctx->contrib_local = false;
		coll_ctx->contrib_prev = 0;
		coll_ctx->state = PMIXP_COLL_RING_SYNC;
		
		coll_ctx->contrib_map = xmalloc(sizeof(bool) * coll->peers_cnt);
	}

	return SLURM_SUCCESS;
}

void pmixp_coll_ring_free(pmixp_coll_ring_t *ring)
{
	int i;

	pmixp_coll_ring_ctx_t *coll_ctx;
	for (i = 0; i < PMIXP_COLL_RING_CTX_NUM; i++) {
		coll_ctx = &ring->ctx_array[i];
		FREE_NULL_BUFFER(coll_ctx->ring_buf);
		xfree(coll_ctx->contrib_map);
	}
	list_destroy(ring->fwrd_buf_pool);
	list_destroy(ring->ring_buf_pool);
}

inline static int _pmixp_coll_contrib(pmixp_coll_ring_ctx_t *coll_ctx, int contrib_id, uint32_t hop, char *data, size_t size)

{
	pmixp_coll_t *coll = _ctx_get_coll(coll_ctx);
	char *data_ptr = NULL;
	int ret;

	
	coll->ts = time(NULL);

	
	if (!size_buf(coll_ctx->ring_buf)) {
		grow_buf(coll_ctx->ring_buf, size * coll->peers_cnt);
	} else if(remaining_buf(coll_ctx->ring_buf) < size) {
		uint32_t new_size = size_buf(coll_ctx->ring_buf) + size * _ring_remain_contrib(coll_ctx);
		grow_buf(coll_ctx->ring_buf, new_size);
	}
	grow_buf(coll_ctx->ring_buf, size);
	data_ptr = get_buf_data(coll_ctx->ring_buf) + get_buf_offset(coll_ctx->ring_buf);
	memcpy(data_ptr, data, size);
	set_buf_offset(coll_ctx->ring_buf, get_buf_offset(coll_ctx->ring_buf) + size);

	
	if (contrib_id != _ring_next_id(coll)) {
		
		ret = _ring_forward_data(coll_ctx, contrib_id, hop, data_ptr, size);
		if (ret) {
			PMIXP_ERROR("Cannot forward ring data");
			return SLURM_ERROR;
		}
	}

	return SLURM_SUCCESS;
}

int pmixp_coll_ring_local(pmixp_coll_t *coll, char *data, size_t size, void *cbfunc, void *cbdata)
{
	int ret = SLURM_SUCCESS;
	pmixp_coll_ring_ctx_t *coll_ctx = NULL;

	
	slurm_mutex_lock(&coll->lock);

	
	pmixp_coll_sanity_check(coll);

	
	coll->cbfunc = cbfunc;
	coll->cbdata = cbdata;

	coll_ctx = pmixp_coll_ring_ctx_new(coll);
	if (!coll_ctx) {
		PMIXP_ERROR("Can not get new ring collective context, seq=%u", coll->seq);
		ret = SLURM_ERROR;
		goto exit;
	}


	PMIXP_DEBUG("%p: contrib/loc: seqnum=%u, state=%d, size=%lu", coll_ctx, coll_ctx->seq, coll_ctx->state, size);


	if (_pmixp_coll_contrib(coll_ctx, coll->my_peerid, 0, data, size)) {
		goto exit;
	}

	
	coll_ctx->contrib_local = true;
	_progress_coll_ring(coll_ctx);

exit:
	
	slurm_mutex_unlock(&coll->lock);

	return ret;
}

int pmixp_coll_ring_check(pmixp_coll_t *coll, pmixp_coll_ring_msg_hdr_t *hdr)
{
	char *nodename = NULL;
	int rc;

	if (hdr->nodeid != _ring_prev_id(coll)) {
		nodename = pmixp_info_job_host(hdr->nodeid);
		PMIXP_ERROR("%p: unexpected contrib from %s:%u, expected is %d", coll, nodename, hdr->nodeid, _ring_prev_id(coll));
		return SLURM_ERROR;
	}
	rc = pmixp_coll_check(coll, hdr->seq);
	if (PMIXP_COLL_REQ_FAILURE == rc) {
		
		nodename = pmixp_info_job_host(hdr->nodeid);
		PMIXP_ERROR("Bad collective seq. #%d from %s:%u, current is %d", hdr->seq, nodename, hdr->nodeid, coll->seq);
		pmixp_debug_hang(0); 
		slurm_kill_job_step(pmixp_info_jobid(), pmixp_info_stepid(), SIGKILL);
		xfree(nodename);
		return SLURM_SUCCESS;
	} else if (PMIXP_COLL_REQ_SKIP == rc) {

		nodename = pmixp_info_job_host(hdr->nodeid);
		PMIXP_ERROR("Wrong collective seq. #%d from nodeid %u, current is %d, skip this message", hdr->seq, hdr->nodeid, coll->seq);

		return SLURM_ERROR;
	}
	return SLURM_SUCCESS;
}

int pmixp_coll_ring_neighbor(pmixp_coll_t *coll, pmixp_coll_ring_msg_hdr_t *hdr, Buf buf)
{
	int ret = SLURM_SUCCESS;
	char *data_ptr = NULL;
	pmixp_coll_ring_ctx_t *coll_ctx = NULL;
	uint32_t hop_seq;

	
	slurm_mutex_lock(&coll->lock);

	coll_ctx = pmixp_coll_ring_ctx_select(coll, hdr->seq);
	if (!coll_ctx) {
		PMIXP_ERROR("Can not get ring collective context, seq=%u", hdr->seq);
		ret = SLURM_ERROR;
		goto exit;
	}

	PMIXP_DEBUG("%p: contrib/nbr: seqnum=%u, state=%d, nodeid=%d, contrib=%d, seq=%d, size=%lu", coll_ctx, coll_ctx->seq, coll_ctx->state, hdr->nodeid, hdr->contrib_id, hdr->hop_seq, hdr->msgsize);




	
	if (hdr->msgsize != remaining_buf(buf)) {

		PMIXP_DEBUG("%p: unexpected message size=%d, expect=%zu", coll, remaining_buf(buf), hdr->msgsize);

		goto exit;
	}

	
	hop_seq = (coll->my_peerid + coll->peers_cnt - hdr->contrib_id) % coll->peers_cnt - 1;
	if (hdr->hop_seq != hop_seq) {

		PMIXP_DEBUG("%p: unexpected ring seq number=%d, expect=%d, coll seq=%d", coll, hdr->hop_seq, hop_seq, coll->seq);

		goto exit;
	}

	if (hdr->contrib_id >= coll->peers_cnt) {
		goto exit;
	}

	if (coll_ctx->contrib_map[hdr->contrib_id]) {

		PMIXP_DEBUG("%p: double receiving was detected from %d, " "local seq=%d, seq=%d, rejected", coll, hdr->contrib_id, coll->seq, hdr->seq);


		goto exit;
	}

	
	coll_ctx->contrib_map[hdr->contrib_id] = true;

	data_ptr = get_buf_data(buf) + get_buf_offset(buf);
	if (_pmixp_coll_contrib(coll_ctx, hdr->contrib_id, hdr->hop_seq + 1, data_ptr, remaining_buf(buf))) {
		goto exit;
	}

	
	coll_ctx->contrib_prev++;

	
	_progress_coll_ring(coll_ctx);
exit:
	
	slurm_mutex_unlock(&coll->lock);
	return ret;
}

void pmixp_coll_ring_reset_if_to(pmixp_coll_t *coll, time_t ts) {
	pmixp_coll_ring_ctx_t *coll_ctx;
	int i;

	
	slurm_mutex_lock(&coll->lock);
	for (i = 0; i < PMIXP_COLL_RING_CTX_NUM; i++) {
		coll_ctx = &coll->state.ring.ctx_array[i];
		if (!coll_ctx->in_use || (PMIXP_COLL_RING_SYNC == coll_ctx->state)) {
			continue;
		}
		if (ts - coll->ts > pmixp_info_timeout()) {
			
			pmixp_coll_localcb_nodata(coll, PMIXP_ERR_TIMEOUT);

			
			PMIXP_ERROR("%p: collective timeout seq=%d", coll, coll_ctx->seq);
			pmixp_coll_log(coll);
			
			_reset_coll_ring(coll_ctx);
		}
	}
	
	slurm_mutex_unlock(&coll->lock);
}

void pmixp_coll_ring_log(pmixp_coll_t *coll)
{
	int i;
	pmixp_coll_ring_t *ring = &coll->state.ring;
	char *nodename, *next, *prev;
	char *out_str = NULL;

	PMIXP_ERROR("%p: %s state seq=%d", coll, pmixp_coll_type2str(coll->type), coll->seq);
	nodename = pmixp_info_job_host(coll->my_peerid);
	PMIXP_ERROR("my peerid: %d:%s", coll->my_peerid, nodename);
	xfree(nodename);

	next = pmixp_info_job_host(_ring_next_id(coll));
	prev = pmixp_info_job_host(_ring_prev_id(coll));
	xstrfmtcat(out_str,"neighbor id: next %d:%s, prev %d:%s", _ring_next_id(coll), next, _ring_prev_id(coll), prev);
	PMIXP_ERROR("%s", out_str);
	xfree(next);
	xfree(prev);
	xfree(out_str);


	for (i = 0; i < PMIXP_COLL_RING_CTX_NUM; i++) {
		pmixp_coll_ring_ctx_t *coll_ctx = &ring->ctx_array[i];

		PMIXP_ERROR("Context ptr=%p, #%d, in-use=%d", coll_ctx, i, coll_ctx->in_use);

		if (coll_ctx->in_use) {
			int id;
			char *done_contrib = NULL, *wait_contrib = NULL;
			hostlist_t hl_done_contrib = NULL, hl_wait_contrib = NULL, *tmp_list;

			PMIXP_ERROR("\t seq=%d contribs: loc=%d/prev=%d/fwd=%d", coll_ctx->seq, coll_ctx->contrib_local, coll_ctx->contrib_prev, coll_ctx->forward_cnt);


			PMIXP_ERROR("\t neighbor contribs [%d]:", coll->peers_cnt);

			for (id = 0; id < coll->peers_cnt; id++) {
				char *nodename;

				if (coll->my_peerid == id)
					continue;

				nodename = pmixp_info_job_host(id);

				tmp_list = coll_ctx->contrib_map[id] ? &hl_done_contrib : &hl_wait_contrib;

				if (!*tmp_list)
					*tmp_list = hostlist_create(nodename);
				else hostlist_push_host(*tmp_list, nodename);
				xfree(nodename);
			}
			if (hl_done_contrib) {
				done_contrib = slurm_hostlist_ranged_string_xmalloc( hl_done_contrib);

				FREE_NULL_HOSTLIST(hl_done_contrib);
			}

			if (hl_wait_contrib) {
				wait_contrib = slurm_hostlist_ranged_string_xmalloc( hl_wait_contrib);

				FREE_NULL_HOSTLIST(hl_wait_contrib);
			}
			PMIXP_ERROR("\t\t done contrib: %s", done_contrib ? done_contrib : "-");
			PMIXP_ERROR("\t\t wait contrib: %s", wait_contrib ? wait_contrib : "-");
			PMIXP_ERROR("\t status=%s", pmixp_coll_ring_state2str(coll_ctx->state));
			if (coll_ctx->ring_buf) {
				PMIXP_ERROR("\t buf (offset/size): %u/%u", get_buf_offset(coll_ctx->ring_buf), size_buf(coll_ctx->ring_buf));

			}
			xfree(done_contrib);
			xfree(wait_contrib);
		}
	}
}
