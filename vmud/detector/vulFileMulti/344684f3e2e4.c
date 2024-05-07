





































struct vhost_scsi_inflight {
	
	struct completion comp;
	
	struct kref kref;
};

struct vhost_scsi_cmd {
	
	int tvc_vq_desc;
	
	int tvc_task_attr;
	
	int tvc_in_iovs;
	
	enum dma_data_direction tvc_data_direction;
	
	u32 tvc_exp_data_len;
	
	u64 tvc_tag;
	
	u32 tvc_sgl_count;
	u32 tvc_prot_sgl_count;
	
	u32 tvc_lun;
	
	struct scatterlist *tvc_sgl;
	struct scatterlist *tvc_prot_sgl;
	struct page **tvc_upages;
	
	struct iovec tvc_resp_iov;
	
	struct vhost_scsi *tvc_vhost;
	
	struct vhost_virtqueue *tvc_vq;
	
	struct vhost_scsi_nexus *tvc_nexus;
	
	struct se_cmd tvc_se_cmd;
	
	struct work_struct work;
	
	unsigned char tvc_cdb[VHOST_SCSI_MAX_CDB_SIZE];
	
	unsigned char tvc_sense_buf[TRANSPORT_SENSE_BUFFER];
	
	struct llist_node tvc_completion_list;
	
	struct vhost_scsi_inflight *inflight;
};

struct vhost_scsi_nexus {
	
	struct se_session *tvn_se_sess;
};

struct vhost_scsi_tpg {
	
	u16 tport_tpgt;
	
	int tv_tpg_port_count;
	
	int tv_tpg_vhost_count;
	
	int tv_fabric_prot_type;
	
	struct list_head tv_tpg_list;
	
	struct mutex tv_tpg_mutex;
	
	struct vhost_scsi_nexus *tpg_nexus;
	
	struct vhost_scsi_tport *tport;
	
	struct se_portal_group se_tpg;
	
	struct vhost_scsi *vhost_scsi;
};

struct vhost_scsi_tport {
	
	u8 tport_proto_id;
	
	u64 tport_wwpn;
	
	char tport_name[VHOST_SCSI_NAMELEN];
	
	struct se_wwn tport_wwn;
};

struct vhost_scsi_evt {
	
	struct virtio_scsi_event event;
	
	struct llist_node list;
};

enum {
	VHOST_SCSI_VQ_CTL = 0, VHOST_SCSI_VQ_EVT = 1, VHOST_SCSI_VQ_IO = 2, };




enum {
	VHOST_SCSI_FEATURES = VHOST_FEATURES | (1ULL << VIRTIO_SCSI_F_HOTPLUG) | (1ULL << VIRTIO_SCSI_F_T10_PI)
};





struct vhost_scsi_virtqueue {
	struct vhost_virtqueue vq;
	
	struct vhost_scsi_inflight inflights[2];
	
	int inflight_idx;
};

struct vhost_scsi {
	
	struct vhost_scsi_tpg **vs_tpg;
	char vs_vhost_wwpn[TRANSPORT_IQN_LEN];

	struct vhost_dev dev;
	struct vhost_scsi_virtqueue vqs[VHOST_SCSI_MAX_VQ];

	struct vhost_work vs_completion_work; 
	struct llist_head vs_completion_list; 

	struct vhost_work vs_event_work; 
	struct llist_head vs_event_list; 

	bool vs_events_missed; 
	int vs_events_nr; 
};


struct vhost_scsi_ctx {
	int head;
	unsigned int out, in;
	size_t req_size, rsp_size;
	size_t out_size, in_size;
	u8 *target, *lunp;
	void *req;
	struct iov_iter out_iter;
};

static struct workqueue_struct *vhost_scsi_workqueue;


static DEFINE_MUTEX(vhost_scsi_mutex);
static LIST_HEAD(vhost_scsi_list);

static void vhost_scsi_done_inflight(struct kref *kref)
{
	struct vhost_scsi_inflight *inflight;

	inflight = container_of(kref, struct vhost_scsi_inflight, kref);
	complete(&inflight->comp);
}

static void vhost_scsi_init_inflight(struct vhost_scsi *vs, struct vhost_scsi_inflight *old_inflight[])
{
	struct vhost_scsi_inflight *new_inflight;
	struct vhost_virtqueue *vq;
	int idx, i;

	for (i = 0; i < VHOST_SCSI_MAX_VQ; i++) {
		vq = &vs->vqs[i].vq;

		mutex_lock(&vq->mutex);

		
		idx = vs->vqs[i].inflight_idx;
		if (old_inflight)
			old_inflight[i] = &vs->vqs[i].inflights[idx];

		
		vs->vqs[i].inflight_idx = idx ^ 1;
		new_inflight = &vs->vqs[i].inflights[idx ^ 1];
		kref_init(&new_inflight->kref);
		init_completion(&new_inflight->comp);

		mutex_unlock(&vq->mutex);
	}
}

static struct vhost_scsi_inflight * vhost_scsi_get_inflight(struct vhost_virtqueue *vq)
{
	struct vhost_scsi_inflight *inflight;
	struct vhost_scsi_virtqueue *svq;

	svq = container_of(vq, struct vhost_scsi_virtqueue, vq);
	inflight = &svq->inflights[svq->inflight_idx];
	kref_get(&inflight->kref);

	return inflight;
}

static void vhost_scsi_put_inflight(struct vhost_scsi_inflight *inflight)
{
	kref_put(&inflight->kref, vhost_scsi_done_inflight);
}

static int vhost_scsi_check_true(struct se_portal_group *se_tpg)
{
	return 1;
}

static int vhost_scsi_check_false(struct se_portal_group *se_tpg)
{
	return 0;
}

static char *vhost_scsi_get_fabric_wwn(struct se_portal_group *se_tpg)
{
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);
	struct vhost_scsi_tport *tport = tpg->tport;

	return &tport->tport_name[0];
}

static u16 vhost_scsi_get_tpgt(struct se_portal_group *se_tpg)
{
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);
	return tpg->tport_tpgt;
}

static int vhost_scsi_check_prot_fabric_only(struct se_portal_group *se_tpg)
{
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);

	return tpg->tv_fabric_prot_type;
}

static u32 vhost_scsi_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	return 1;
}

static void vhost_scsi_release_cmd(struct se_cmd *se_cmd)
{
	struct vhost_scsi_cmd *tv_cmd = container_of(se_cmd, struct vhost_scsi_cmd, tvc_se_cmd);
	struct se_session *se_sess = tv_cmd->tvc_nexus->tvn_se_sess;
	int i;

	if (tv_cmd->tvc_sgl_count) {
		for (i = 0; i < tv_cmd->tvc_sgl_count; i++)
			put_page(sg_page(&tv_cmd->tvc_sgl[i]));
	}
	if (tv_cmd->tvc_prot_sgl_count) {
		for (i = 0; i < tv_cmd->tvc_prot_sgl_count; i++)
			put_page(sg_page(&tv_cmd->tvc_prot_sgl[i]));
	}

	vhost_scsi_put_inflight(tv_cmd->inflight);
	target_free_tag(se_sess, se_cmd);
}

static u32 vhost_scsi_sess_get_index(struct se_session *se_sess)
{
	return 0;
}

static int vhost_scsi_write_pending(struct se_cmd *se_cmd)
{
	
	target_execute_cmd(se_cmd);
	return 0;
}

static int vhost_scsi_write_pending_status(struct se_cmd *se_cmd)
{
	return 0;
}

static void vhost_scsi_set_default_node_attrs(struct se_node_acl *nacl)
{
	return;
}

static int vhost_scsi_get_cmd_state(struct se_cmd *se_cmd)
{
	return 0;
}

static void vhost_scsi_complete_cmd(struct vhost_scsi_cmd *cmd)
{
	struct vhost_scsi *vs = cmd->tvc_vhost;

	llist_add(&cmd->tvc_completion_list, &vs->vs_completion_list);

	vhost_work_queue(&vs->dev, &vs->vs_completion_work);
}

static int vhost_scsi_queue_data_in(struct se_cmd *se_cmd)
{
	struct vhost_scsi_cmd *cmd = container_of(se_cmd, struct vhost_scsi_cmd, tvc_se_cmd);
	vhost_scsi_complete_cmd(cmd);
	return 0;
}

static int vhost_scsi_queue_status(struct se_cmd *se_cmd)
{
	struct vhost_scsi_cmd *cmd = container_of(se_cmd, struct vhost_scsi_cmd, tvc_se_cmd);
	vhost_scsi_complete_cmd(cmd);
	return 0;
}

static void vhost_scsi_queue_tm_rsp(struct se_cmd *se_cmd)
{
	return;
}

static void vhost_scsi_aborted_task(struct se_cmd *se_cmd)
{
	return;
}

static void vhost_scsi_free_evt(struct vhost_scsi *vs, struct vhost_scsi_evt *evt)
{
	vs->vs_events_nr--;
	kfree(evt);
}

static struct vhost_scsi_evt * vhost_scsi_allocate_evt(struct vhost_scsi *vs, u32 event, u32 reason)

{
	struct vhost_virtqueue *vq = &vs->vqs[VHOST_SCSI_VQ_EVT].vq;
	struct vhost_scsi_evt *evt;

	if (vs->vs_events_nr > VHOST_SCSI_MAX_EVENT) {
		vs->vs_events_missed = true;
		return NULL;
	}

	evt = kzalloc(sizeof(*evt), GFP_KERNEL);
	if (!evt) {
		vq_err(vq, "Failed to allocate vhost_scsi_evt\n");
		vs->vs_events_missed = true;
		return NULL;
	}

	evt->event.event = cpu_to_vhost32(vq, event);
	evt->event.reason = cpu_to_vhost32(vq, reason);
	vs->vs_events_nr++;

	return evt;
}

static void vhost_scsi_free_cmd(struct vhost_scsi_cmd *cmd)
{
	struct se_cmd *se_cmd = &cmd->tvc_se_cmd;

	
	transport_generic_free_cmd(se_cmd, 0);

}

static int vhost_scsi_check_stop_free(struct se_cmd *se_cmd)
{
	return target_put_sess_cmd(se_cmd);
}

static void vhost_scsi_do_evt_work(struct vhost_scsi *vs, struct vhost_scsi_evt *evt)
{
	struct vhost_virtqueue *vq = &vs->vqs[VHOST_SCSI_VQ_EVT].vq;
	struct virtio_scsi_event *event = &evt->event;
	struct virtio_scsi_event __user *eventp;
	unsigned out, in;
	int head, ret;

	if (!vq->private_data) {
		vs->vs_events_missed = true;
		return;
	}

again:
	vhost_disable_notify(&vs->dev, vq);
	head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov), &out, &in, NULL, NULL);

	if (head < 0) {
		vs->vs_events_missed = true;
		return;
	}
	if (head == vq->num) {
		if (vhost_enable_notify(&vs->dev, vq))
			goto again;
		vs->vs_events_missed = true;
		return;
	}

	if ((vq->iov[out].iov_len != sizeof(struct virtio_scsi_event))) {
		vq_err(vq, "Expecting virtio_scsi_event, got %zu bytes\n", vq->iov[out].iov_len);
		vs->vs_events_missed = true;
		return;
	}

	if (vs->vs_events_missed) {
		event->event |= cpu_to_vhost32(vq, VIRTIO_SCSI_T_EVENTS_MISSED);
		vs->vs_events_missed = false;
	}

	eventp = vq->iov[out].iov_base;
	ret = __copy_to_user(eventp, event, sizeof(*event));
	if (!ret)
		vhost_add_used_and_signal(&vs->dev, vq, head, 0);
	else vq_err(vq, "Faulted on vhost_scsi_send_event\n");
}

static void vhost_scsi_evt_work(struct vhost_work *work)
{
	struct vhost_scsi *vs = container_of(work, struct vhost_scsi, vs_event_work);
	struct vhost_virtqueue *vq = &vs->vqs[VHOST_SCSI_VQ_EVT].vq;
	struct vhost_scsi_evt *evt, *t;
	struct llist_node *llnode;

	mutex_lock(&vq->mutex);
	llnode = llist_del_all(&vs->vs_event_list);
	llist_for_each_entry_safe(evt, t, llnode, list) {
		vhost_scsi_do_evt_work(vs, evt);
		vhost_scsi_free_evt(vs, evt);
	}
	mutex_unlock(&vq->mutex);
}


static void vhost_scsi_complete_cmd_work(struct vhost_work *work)
{
	struct vhost_scsi *vs = container_of(work, struct vhost_scsi, vs_completion_work);
	DECLARE_BITMAP(signal, VHOST_SCSI_MAX_VQ);
	struct virtio_scsi_cmd_resp v_rsp;
	struct vhost_scsi_cmd *cmd, *t;
	struct llist_node *llnode;
	struct se_cmd *se_cmd;
	struct iov_iter iov_iter;
	int ret, vq;

	bitmap_zero(signal, VHOST_SCSI_MAX_VQ);
	llnode = llist_del_all(&vs->vs_completion_list);
	llist_for_each_entry_safe(cmd, t, llnode, tvc_completion_list) {
		se_cmd = &cmd->tvc_se_cmd;

		pr_debug("%s tv_cmd %p resid %u status %#02x\n", __func__, cmd, se_cmd->residual_count, se_cmd->scsi_status);

		memset(&v_rsp, 0, sizeof(v_rsp));
		v_rsp.resid = cpu_to_vhost32(cmd->tvc_vq, se_cmd->residual_count);
		
		v_rsp.status = se_cmd->scsi_status;
		v_rsp.sense_len = cpu_to_vhost32(cmd->tvc_vq, se_cmd->scsi_sense_length);
		memcpy(v_rsp.sense, cmd->tvc_sense_buf, se_cmd->scsi_sense_length);

		iov_iter_init(&iov_iter, READ, &cmd->tvc_resp_iov, cmd->tvc_in_iovs, sizeof(v_rsp));
		ret = copy_to_iter(&v_rsp, sizeof(v_rsp), &iov_iter);
		if (likely(ret == sizeof(v_rsp))) {
			struct vhost_scsi_virtqueue *q;
			vhost_add_used(cmd->tvc_vq, cmd->tvc_vq_desc, 0);
			q = container_of(cmd->tvc_vq, struct vhost_scsi_virtqueue, vq);
			vq = q - vs->vqs;
			__set_bit(vq, signal);
		} else pr_err("Faulted on virtio_scsi_cmd_resp\n");

		vhost_scsi_free_cmd(cmd);
	}

	vq = -1;
	while ((vq = find_next_bit(signal, VHOST_SCSI_MAX_VQ, vq + 1))
		< VHOST_SCSI_MAX_VQ)
		vhost_signal(&vs->dev, &vs->vqs[vq].vq);
}

static struct vhost_scsi_cmd * vhost_scsi_get_tag(struct vhost_virtqueue *vq, struct vhost_scsi_tpg *tpg, unsigned char *cdb, u64 scsi_tag, u16 lun, u8 task_attr, u32 exp_data_len, int data_direction)


{
	struct vhost_scsi_cmd *cmd;
	struct vhost_scsi_nexus *tv_nexus;
	struct se_session *se_sess;
	struct scatterlist *sg, *prot_sg;
	struct page **pages;
	int tag, cpu;

	tv_nexus = tpg->tpg_nexus;
	if (!tv_nexus) {
		pr_err("Unable to locate active struct vhost_scsi_nexus\n");
		return ERR_PTR(-EIO);
	}
	se_sess = tv_nexus->tvn_se_sess;

	tag = sbitmap_queue_get(&se_sess->sess_tag_pool, &cpu);
	if (tag < 0) {
		pr_err("Unable to obtain tag for vhost_scsi_cmd\n");
		return ERR_PTR(-ENOMEM);
	}

	cmd = &((struct vhost_scsi_cmd *)se_sess->sess_cmd_map)[tag];
	sg = cmd->tvc_sgl;
	prot_sg = cmd->tvc_prot_sgl;
	pages = cmd->tvc_upages;
	memset(cmd, 0, sizeof(*cmd));
	cmd->tvc_sgl = sg;
	cmd->tvc_prot_sgl = prot_sg;
	cmd->tvc_upages = pages;
	cmd->tvc_se_cmd.map_tag = tag;
	cmd->tvc_se_cmd.map_cpu = cpu;
	cmd->tvc_tag = scsi_tag;
	cmd->tvc_lun = lun;
	cmd->tvc_task_attr = task_attr;
	cmd->tvc_exp_data_len = exp_data_len;
	cmd->tvc_data_direction = data_direction;
	cmd->tvc_nexus = tv_nexus;
	cmd->inflight = vhost_scsi_get_inflight(vq);

	memcpy(cmd->tvc_cdb, cdb, VHOST_SCSI_MAX_CDB_SIZE);

	return cmd;
}


static int vhost_scsi_map_to_sgl(struct vhost_scsi_cmd *cmd, struct iov_iter *iter, struct scatterlist *sgl, bool write)



{
	struct page **pages = cmd->tvc_upages;
	struct scatterlist *sg = sgl;
	ssize_t bytes;
	size_t offset;
	unsigned int npages = 0;

	bytes = iov_iter_get_pages(iter, pages, LONG_MAX, VHOST_SCSI_PREALLOC_UPAGES, &offset);
	
	if (bytes <= 0)
		return bytes < 0 ? bytes : -EFAULT;

	iov_iter_advance(iter, bytes);

	while (bytes) {
		unsigned n = min_t(unsigned, PAGE_SIZE - offset, bytes);
		sg_set_page(sg++, pages[npages++], n, offset);
		bytes -= n;
		offset = 0;
	}
	return npages;
}

static int vhost_scsi_calc_sgls(struct iov_iter *iter, size_t bytes, int max_sgls)
{
	int sgl_count = 0;

	if (!iter || !iter->iov) {
		pr_err("%s: iter->iov is NULL, but expected bytes: %zu" " present\n", __func__, bytes);
		return -EINVAL;
	}

	sgl_count = iov_iter_npages(iter, 0xffff);
	if (sgl_count > max_sgls) {
		pr_err("%s: requested sgl_count: %d exceeds pre-allocated" " max_sgls: %d\n", __func__, sgl_count, max_sgls);
		return -EINVAL;
	}
	return sgl_count;
}

static int vhost_scsi_iov_to_sgl(struct vhost_scsi_cmd *cmd, bool write, struct iov_iter *iter, struct scatterlist *sg, int sg_count)


{
	struct scatterlist *p = sg;
	int ret;

	while (iov_iter_count(iter)) {
		ret = vhost_scsi_map_to_sgl(cmd, iter, sg, write);
		if (ret < 0) {
			while (p < sg) {
				struct page *page = sg_page(p++);
				if (page)
					put_page(page);
			}
			return ret;
		}
		sg += ret;
	}
	return 0;
}

static int vhost_scsi_mapal(struct vhost_scsi_cmd *cmd, size_t prot_bytes, struct iov_iter *prot_iter, size_t data_bytes, struct iov_iter *data_iter)


{
	int sgl_count, ret;
	bool write = (cmd->tvc_data_direction == DMA_FROM_DEVICE);

	if (prot_bytes) {
		sgl_count = vhost_scsi_calc_sgls(prot_iter, prot_bytes, VHOST_SCSI_PREALLOC_PROT_SGLS);
		if (sgl_count < 0)
			return sgl_count;

		sg_init_table(cmd->tvc_prot_sgl, sgl_count);
		cmd->tvc_prot_sgl_count = sgl_count;
		pr_debug("%s prot_sg %p prot_sgl_count %u\n", __func__, cmd->tvc_prot_sgl, cmd->tvc_prot_sgl_count);

		ret = vhost_scsi_iov_to_sgl(cmd, write, prot_iter, cmd->tvc_prot_sgl, cmd->tvc_prot_sgl_count);

		if (ret < 0) {
			cmd->tvc_prot_sgl_count = 0;
			return ret;
		}
	}
	sgl_count = vhost_scsi_calc_sgls(data_iter, data_bytes, VHOST_SCSI_PREALLOC_SGLS);
	if (sgl_count < 0)
		return sgl_count;

	sg_init_table(cmd->tvc_sgl, sgl_count);
	cmd->tvc_sgl_count = sgl_count;
	pr_debug("%s data_sg %p data_sgl_count %u\n", __func__, cmd->tvc_sgl, cmd->tvc_sgl_count);

	ret = vhost_scsi_iov_to_sgl(cmd, write, data_iter, cmd->tvc_sgl, cmd->tvc_sgl_count);
	if (ret < 0) {
		cmd->tvc_sgl_count = 0;
		return ret;
	}
	return 0;
}

static int vhost_scsi_to_tcm_attr(int attr)
{
	switch (attr) {
	case VIRTIO_SCSI_S_SIMPLE:
		return TCM_SIMPLE_TAG;
	case VIRTIO_SCSI_S_ORDERED:
		return TCM_ORDERED_TAG;
	case VIRTIO_SCSI_S_HEAD:
		return TCM_HEAD_TAG;
	case VIRTIO_SCSI_S_ACA:
		return TCM_ACA_TAG;
	default:
		break;
	}
	return TCM_SIMPLE_TAG;
}

static void vhost_scsi_submission_work(struct work_struct *work)
{
	struct vhost_scsi_cmd *cmd = container_of(work, struct vhost_scsi_cmd, work);
	struct vhost_scsi_nexus *tv_nexus;
	struct se_cmd *se_cmd = &cmd->tvc_se_cmd;
	struct scatterlist *sg_ptr, *sg_prot_ptr = NULL;
	int rc;

	
	if (cmd->tvc_sgl_count) {
		sg_ptr = cmd->tvc_sgl;

		if (cmd->tvc_prot_sgl_count)
			sg_prot_ptr = cmd->tvc_prot_sgl;
		else se_cmd->prot_pto = true;
	} else {
		sg_ptr = NULL;
	}
	tv_nexus = cmd->tvc_nexus;

	se_cmd->tag = 0;
	rc = target_submit_cmd_map_sgls(se_cmd, tv_nexus->tvn_se_sess, cmd->tvc_cdb, &cmd->tvc_sense_buf[0], cmd->tvc_lun, cmd->tvc_exp_data_len, vhost_scsi_to_tcm_attr(cmd->tvc_task_attr), cmd->tvc_data_direction, TARGET_SCF_ACK_KREF, sg_ptr, cmd->tvc_sgl_count, NULL, 0, sg_prot_ptr, cmd->tvc_prot_sgl_count);





	if (rc < 0) {
		transport_send_check_condition_and_sense(se_cmd, TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
		transport_generic_free_cmd(se_cmd, 0);
	}
}

static void vhost_scsi_send_bad_target(struct vhost_scsi *vs, struct vhost_virtqueue *vq, int head, unsigned out)


{
	struct virtio_scsi_cmd_resp __user *resp;
	struct virtio_scsi_cmd_resp rsp;
	int ret;

	memset(&rsp, 0, sizeof(rsp));
	rsp.response = VIRTIO_SCSI_S_BAD_TARGET;
	resp = vq->iov[out].iov_base;
	ret = __copy_to_user(resp, &rsp, sizeof(rsp));
	if (!ret)
		vhost_add_used_and_signal(&vs->dev, vq, head, 0);
	else pr_err("Faulted on virtio_scsi_cmd_resp\n");
}

static int vhost_scsi_get_desc(struct vhost_scsi *vs, struct vhost_virtqueue *vq, struct vhost_scsi_ctx *vc)

{
	int ret = -ENXIO;

	vc->head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov), &vc->out, &vc->in, NULL, NULL);


	pr_debug("vhost_get_vq_desc: head: %d, out: %u in: %u\n", vc->head, vc->out, vc->in);

	
	if (unlikely(vc->head < 0))
		goto done;

	
	if (vc->head == vq->num) {
		if (unlikely(vhost_enable_notify(&vs->dev, vq))) {
			vhost_disable_notify(&vs->dev, vq);
			ret = -EAGAIN;
		}
		goto done;
	}

	
	vc->out_size = iov_length(vq->iov, vc->out);
	vc->in_size = iov_length(&vq->iov[vc->out], vc->in);

	
	iov_iter_init(&vc->out_iter, WRITE, vq->iov, vc->out, vc->out_size);
	ret = 0;

done:
	return ret;
}

static int vhost_scsi_chk_size(struct vhost_virtqueue *vq, struct vhost_scsi_ctx *vc)
{
	if (unlikely(vc->in_size < vc->rsp_size)) {
		vq_err(vq, "Response buf too small, need min %zu bytes got %zu", vc->rsp_size, vc->in_size);

		return -EINVAL;
	} else if (unlikely(vc->out_size < vc->req_size)) {
		vq_err(vq, "Request buf too small, need min %zu bytes got %zu", vc->req_size, vc->out_size);

		return -EIO;
	}

	return 0;
}

static int vhost_scsi_get_req(struct vhost_virtqueue *vq, struct vhost_scsi_ctx *vc, struct vhost_scsi_tpg **tpgp)

{
	int ret = -EIO;

	if (unlikely(!copy_from_iter_full(vc->req, vc->req_size, &vc->out_iter))) {
		vq_err(vq, "Faulted on copy_from_iter_full\n");
	} else if (unlikely(*vc->lunp != 1)) {
		
		vq_err(vq, "Illegal virtio-scsi lun: %u\n", *vc->lunp);
	} else {
		struct vhost_scsi_tpg **vs_tpg, *tpg;

		vs_tpg = vq->private_data;	

		tpg = READ_ONCE(vs_tpg[*vc->target]);
		if (unlikely(!tpg)) {
			vq_err(vq, "Target 0x%x does not exist\n", *vc->target);
		} else {
			if (tpgp)
				*tpgp = tpg;
			ret = 0;
		}
	}

	return ret;
}

static void vhost_scsi_handle_vq(struct vhost_scsi *vs, struct vhost_virtqueue *vq)
{
	struct vhost_scsi_tpg **vs_tpg, *tpg;
	struct virtio_scsi_cmd_req v_req;
	struct virtio_scsi_cmd_req_pi v_req_pi;
	struct vhost_scsi_ctx vc;
	struct vhost_scsi_cmd *cmd;
	struct iov_iter in_iter, prot_iter, data_iter;
	u64 tag;
	u32 exp_data_len, data_direction;
	int ret, prot_bytes;
	u16 lun;
	u8 task_attr;
	bool t10_pi = vhost_has_feature(vq, VIRTIO_SCSI_F_T10_PI);
	void *cdb;

	mutex_lock(&vq->mutex);
	
	vs_tpg = vq->private_data;
	if (!vs_tpg)
		goto out;

	memset(&vc, 0, sizeof(vc));
	vc.rsp_size = sizeof(struct virtio_scsi_cmd_resp);

	vhost_disable_notify(&vs->dev, vq);

	for (;;) {
		ret = vhost_scsi_get_desc(vs, vq, &vc);
		if (ret)
			goto err;

		
		if (t10_pi) {
			vc.req = &v_req_pi;
			vc.req_size = sizeof(v_req_pi);
			vc.lunp = &v_req_pi.lun[0];
			vc.target = &v_req_pi.lun[1];
		} else {
			vc.req = &v_req;
			vc.req_size = sizeof(v_req);
			vc.lunp = &v_req.lun[0];
			vc.target = &v_req.lun[1];
		}

		
		ret = vhost_scsi_chk_size(vq, &vc);
		if (ret)
			goto err;

		ret = vhost_scsi_get_req(vq, &vc, &tpg);
		if (ret)
			goto err;

		ret = -EIO;	

		
		prot_bytes = 0;

		if (vc.out_size > vc.req_size) {
			data_direction = DMA_TO_DEVICE;
			exp_data_len = vc.out_size - vc.req_size;
			data_iter = vc.out_iter;
		} else if (vc.in_size > vc.rsp_size) {
			data_direction = DMA_FROM_DEVICE;
			exp_data_len = vc.in_size - vc.rsp_size;

			iov_iter_init(&in_iter, READ, &vq->iov[vc.out], vc.in, vc.rsp_size + exp_data_len);
			iov_iter_advance(&in_iter, vc.rsp_size);
			data_iter = in_iter;
		} else {
			data_direction = DMA_NONE;
			exp_data_len = 0;
		}
		
		if (t10_pi) {
			if (v_req_pi.pi_bytesout) {
				if (data_direction != DMA_TO_DEVICE) {
					vq_err(vq, "Received non zero pi_bytesout," " but wrong data_direction\n");
					goto err;
				}
				prot_bytes = vhost32_to_cpu(vq, v_req_pi.pi_bytesout);
			} else if (v_req_pi.pi_bytesin) {
				if (data_direction != DMA_FROM_DEVICE) {
					vq_err(vq, "Received non zero pi_bytesin," " but wrong data_direction\n");
					goto err;
				}
				prot_bytes = vhost32_to_cpu(vq, v_req_pi.pi_bytesin);
			}
			
			if (prot_bytes) {
				exp_data_len -= prot_bytes;
				prot_iter = data_iter;
				iov_iter_truncate(&prot_iter, prot_bytes);
				iov_iter_advance(&data_iter, prot_bytes);
			}
			tag = vhost64_to_cpu(vq, v_req_pi.tag);
			task_attr = v_req_pi.task_attr;
			cdb = &v_req_pi.cdb[0];
			lun = ((v_req_pi.lun[2] << 8) | v_req_pi.lun[3]) & 0x3FFF;
		} else {
			tag = vhost64_to_cpu(vq, v_req.tag);
			task_attr = v_req.task_attr;
			cdb = &v_req.cdb[0];
			lun = ((v_req.lun[2] << 8) | v_req.lun[3]) & 0x3FFF;
		}
		
		if (unlikely(scsi_command_size(cdb) > VHOST_SCSI_MAX_CDB_SIZE)) {
			vq_err(vq, "Received SCSI CDB with command_size: %d that" " exceeds SCSI_MAX_VARLEN_CDB_SIZE: %d\n", scsi_command_size(cdb), VHOST_SCSI_MAX_CDB_SIZE);

				goto err;
		}
		cmd = vhost_scsi_get_tag(vq, tpg, cdb, tag, lun, task_attr, exp_data_len + prot_bytes, data_direction);

		if (IS_ERR(cmd)) {
			vq_err(vq, "vhost_scsi_get_tag failed %ld\n", PTR_ERR(cmd));
			goto err;
		}
		cmd->tvc_vhost = vs;
		cmd->tvc_vq = vq;
		cmd->tvc_resp_iov = vq->iov[vc.out];
		cmd->tvc_in_iovs = vc.in;

		pr_debug("vhost_scsi got command opcode: %#02x, lun: %d\n", cmd->tvc_cdb[0], cmd->tvc_lun);
		pr_debug("cmd: %p exp_data_len: %d, prot_bytes: %d data_direction:" " %d\n", cmd, exp_data_len, prot_bytes, data_direction);

		if (data_direction != DMA_NONE) {
			if (unlikely(vhost_scsi_mapal(cmd, prot_bytes, &prot_iter, exp_data_len, &data_iter))) {

				vq_err(vq, "Failed to map iov to sgl\n");
				vhost_scsi_release_cmd(&cmd->tvc_se_cmd);
				goto err;
			}
		}
		
		cmd->tvc_vq_desc = vc.head;
		
		INIT_WORK(&cmd->work, vhost_scsi_submission_work);
		queue_work(vhost_scsi_workqueue, &cmd->work);
		ret = 0;
err:
		
		if (ret == -ENXIO)
			break;
		else if (ret == -EIO)
			vhost_scsi_send_bad_target(vs, vq, vc.head, vc.out);
	}
out:
	mutex_unlock(&vq->mutex);
}

static void vhost_scsi_send_tmf_reject(struct vhost_scsi *vs, struct vhost_virtqueue *vq, struct vhost_scsi_ctx *vc)


{
	struct virtio_scsi_ctrl_tmf_resp rsp;
	struct iov_iter iov_iter;
	int ret;

	pr_debug("%s\n", __func__);
	memset(&rsp, 0, sizeof(rsp));
	rsp.response = VIRTIO_SCSI_S_FUNCTION_REJECTED;

	iov_iter_init(&iov_iter, READ, &vq->iov[vc->out], vc->in, sizeof(rsp));

	ret = copy_to_iter(&rsp, sizeof(rsp), &iov_iter);
	if (likely(ret == sizeof(rsp)))
		vhost_add_used_and_signal(&vs->dev, vq, vc->head, 0);
	else pr_err("Faulted on virtio_scsi_ctrl_tmf_resp\n");
}

static void vhost_scsi_send_an_resp(struct vhost_scsi *vs, struct vhost_virtqueue *vq, struct vhost_scsi_ctx *vc)


{
	struct virtio_scsi_ctrl_an_resp rsp;
	struct iov_iter iov_iter;
	int ret;

	pr_debug("%s\n", __func__);
	memset(&rsp, 0, sizeof(rsp));	
	rsp.response = VIRTIO_SCSI_S_OK;

	iov_iter_init(&iov_iter, READ, &vq->iov[vc->out], vc->in, sizeof(rsp));

	ret = copy_to_iter(&rsp, sizeof(rsp), &iov_iter);
	if (likely(ret == sizeof(rsp)))
		vhost_add_used_and_signal(&vs->dev, vq, vc->head, 0);
	else pr_err("Faulted on virtio_scsi_ctrl_an_resp\n");
}

static void vhost_scsi_ctl_handle_vq(struct vhost_scsi *vs, struct vhost_virtqueue *vq)
{
	union {
		__virtio32 type;
		struct virtio_scsi_ctrl_an_req an;
		struct virtio_scsi_ctrl_tmf_req tmf;
	} v_req;
	struct vhost_scsi_ctx vc;
	size_t typ_size;
	int ret;

	mutex_lock(&vq->mutex);
	
	if (!vq->private_data)
		goto out;

	memset(&vc, 0, sizeof(vc));

	vhost_disable_notify(&vs->dev, vq);

	for (;;) {
		ret = vhost_scsi_get_desc(vs, vq, &vc);
		if (ret)
			goto err;

		
		vc.req = &v_req.type;
		typ_size = sizeof(v_req.type);

		if (unlikely(!copy_from_iter_full(vc.req, typ_size, &vc.out_iter))) {
			vq_err(vq, "Faulted on copy_from_iter tmf type\n");
			
			continue;
		}

		switch (v_req.type) {
		case VIRTIO_SCSI_T_TMF:
			vc.req = &v_req.tmf;
			vc.req_size = sizeof(struct virtio_scsi_ctrl_tmf_req);
			vc.rsp_size = sizeof(struct virtio_scsi_ctrl_tmf_resp);
			vc.lunp = &v_req.tmf.lun[0];
			vc.target = &v_req.tmf.lun[1];
			break;
		case VIRTIO_SCSI_T_AN_QUERY:
		case VIRTIO_SCSI_T_AN_SUBSCRIBE:
			vc.req = &v_req.an;
			vc.req_size = sizeof(struct virtio_scsi_ctrl_an_req);
			vc.rsp_size = sizeof(struct virtio_scsi_ctrl_an_resp);
			vc.lunp = &v_req.an.lun[0];
			vc.target = NULL;
			break;
		default:
			vq_err(vq, "Unknown control request %d", v_req.type);
			continue;
		}

		
		ret = vhost_scsi_chk_size(vq, &vc);
		if (ret)
			goto err;

		
		vc.req += typ_size;
		vc.req_size -= typ_size;

		ret = vhost_scsi_get_req(vq, &vc, NULL);
		if (ret)
			goto err;

		if (v_req.type == VIRTIO_SCSI_T_TMF)
			vhost_scsi_send_tmf_reject(vs, vq, &vc);
		else vhost_scsi_send_an_resp(vs, vq, &vc);
err:
		
		if (ret == -ENXIO)
			break;
		else if (ret == -EIO)
			vhost_scsi_send_bad_target(vs, vq, vc.head, vc.out);
	}
out:
	mutex_unlock(&vq->mutex);
}

static void vhost_scsi_ctl_handle_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_scsi *vs = container_of(vq->dev, struct vhost_scsi, dev);

	pr_debug("%s: The handling func for control queue.\n", __func__);
	vhost_scsi_ctl_handle_vq(vs, vq);
}

static void vhost_scsi_send_evt(struct vhost_scsi *vs, struct vhost_scsi_tpg *tpg, struct se_lun *lun, u32 event, u32 reason)




{
	struct vhost_scsi_evt *evt;

	evt = vhost_scsi_allocate_evt(vs, event, reason);
	if (!evt)
		return;

	if (tpg && lun) {
		
		
		evt->event.lun[0] = 0x01;
		evt->event.lun[1] = tpg->tport_tpgt;
		if (lun->unpacked_lun >= 256)
			evt->event.lun[2] = lun->unpacked_lun >> 8 | 0x40 ;
		evt->event.lun[3] = lun->unpacked_lun & 0xFF;
	}

	llist_add(&evt->list, &vs->vs_event_list);
	vhost_work_queue(&vs->dev, &vs->vs_event_work);
}

static void vhost_scsi_evt_handle_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_scsi *vs = container_of(vq->dev, struct vhost_scsi, dev);

	mutex_lock(&vq->mutex);
	if (!vq->private_data)
		goto out;

	if (vs->vs_events_missed)
		vhost_scsi_send_evt(vs, NULL, NULL, VIRTIO_SCSI_T_NO_EVENT, 0);
out:
	mutex_unlock(&vq->mutex);
}

static void vhost_scsi_handle_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_scsi *vs = container_of(vq->dev, struct vhost_scsi, dev);

	vhost_scsi_handle_vq(vs, vq);
}

static void vhost_scsi_flush_vq(struct vhost_scsi *vs, int index)
{
	vhost_poll_flush(&vs->vqs[index].vq.poll);
}


static void vhost_scsi_flush(struct vhost_scsi *vs)
{
	struct vhost_scsi_inflight *old_inflight[VHOST_SCSI_MAX_VQ];
	int i;

	
	vhost_scsi_init_inflight(vs, old_inflight);

	
	for (i = 0; i < VHOST_SCSI_MAX_VQ; i++)
		kref_put(&old_inflight[i]->kref, vhost_scsi_done_inflight);

	
	for (i = 0; i < VHOST_SCSI_MAX_VQ; i++)
		vhost_scsi_flush_vq(vs, i);
	vhost_work_flush(&vs->dev, &vs->vs_completion_work);
	vhost_work_flush(&vs->dev, &vs->vs_event_work);

	
	for (i = 0; i < VHOST_SCSI_MAX_VQ; i++)
		wait_for_completion(&old_inflight[i]->comp);
}


static int vhost_scsi_set_endpoint(struct vhost_scsi *vs, struct vhost_scsi_target *t)

{
	struct se_portal_group *se_tpg;
	struct vhost_scsi_tport *tv_tport;
	struct vhost_scsi_tpg *tpg;
	struct vhost_scsi_tpg **vs_tpg;
	struct vhost_virtqueue *vq;
	int index, ret, i, len;
	bool match = false;

	mutex_lock(&vhost_scsi_mutex);
	mutex_lock(&vs->dev.mutex);

	
	for (index = 0; index < vs->dev.nvqs; ++index) {
		
		if (!vhost_vq_access_ok(&vs->vqs[index].vq)) {
			ret = -EFAULT;
			goto out;
		}
	}

	len = sizeof(vs_tpg[0]) * VHOST_SCSI_MAX_TARGET;
	vs_tpg = kzalloc(len, GFP_KERNEL);
	if (!vs_tpg) {
		ret = -ENOMEM;
		goto out;
	}
	if (vs->vs_tpg)
		memcpy(vs_tpg, vs->vs_tpg, len);

	list_for_each_entry(tpg, &vhost_scsi_list, tv_tpg_list) {
		mutex_lock(&tpg->tv_tpg_mutex);
		if (!tpg->tpg_nexus) {
			mutex_unlock(&tpg->tv_tpg_mutex);
			continue;
		}
		if (tpg->tv_tpg_vhost_count != 0) {
			mutex_unlock(&tpg->tv_tpg_mutex);
			continue;
		}
		tv_tport = tpg->tport;

		if (!strcmp(tv_tport->tport_name, t->vhost_wwpn)) {
			if (vs->vs_tpg && vs->vs_tpg[tpg->tport_tpgt]) {
				kfree(vs_tpg);
				mutex_unlock(&tpg->tv_tpg_mutex);
				ret = -EEXIST;
				goto out;
			}
			
			se_tpg = &tpg->se_tpg;
			ret = target_depend_item(&se_tpg->tpg_group.cg_item);
			if (ret) {
				pr_warn("target_depend_item() failed: %d\n", ret);
				kfree(vs_tpg);
				mutex_unlock(&tpg->tv_tpg_mutex);
				goto out;
			}
			tpg->tv_tpg_vhost_count++;
			tpg->vhost_scsi = vs;
			vs_tpg[tpg->tport_tpgt] = tpg;
			smp_mb__after_atomic();
			match = true;
		}
		mutex_unlock(&tpg->tv_tpg_mutex);
	}

	if (match) {
		memcpy(vs->vs_vhost_wwpn, t->vhost_wwpn, sizeof(vs->vs_vhost_wwpn));
		for (i = 0; i < VHOST_SCSI_MAX_VQ; i++) {
			vq = &vs->vqs[i].vq;
			mutex_lock(&vq->mutex);
			vq->private_data = vs_tpg;
			vhost_vq_init_access(vq);
			mutex_unlock(&vq->mutex);
		}
		ret = 0;
	} else {
		ret = -EEXIST;
	}

	
	vhost_scsi_flush(vs);
	kfree(vs->vs_tpg);
	vs->vs_tpg = vs_tpg;

out:
	mutex_unlock(&vs->dev.mutex);
	mutex_unlock(&vhost_scsi_mutex);
	return ret;
}

static int vhost_scsi_clear_endpoint(struct vhost_scsi *vs, struct vhost_scsi_target *t)

{
	struct se_portal_group *se_tpg;
	struct vhost_scsi_tport *tv_tport;
	struct vhost_scsi_tpg *tpg;
	struct vhost_virtqueue *vq;
	bool match = false;
	int index, ret, i;
	u8 target;

	mutex_lock(&vhost_scsi_mutex);
	mutex_lock(&vs->dev.mutex);
	
	for (index = 0; index < vs->dev.nvqs; ++index) {
		if (!vhost_vq_access_ok(&vs->vqs[index].vq)) {
			ret = -EFAULT;
			goto err_dev;
		}
	}

	if (!vs->vs_tpg) {
		ret = 0;
		goto err_dev;
	}

	for (i = 0; i < VHOST_SCSI_MAX_TARGET; i++) {
		target = i;
		tpg = vs->vs_tpg[target];
		if (!tpg)
			continue;

		mutex_lock(&tpg->tv_tpg_mutex);
		tv_tport = tpg->tport;
		if (!tv_tport) {
			ret = -ENODEV;
			goto err_tpg;
		}

		if (strcmp(tv_tport->tport_name, t->vhost_wwpn)) {
			pr_warn("tv_tport->tport_name: %s, tpg->tport_tpgt: %hu" " does not match t->vhost_wwpn: %s, t->vhost_tpgt: %hu\n", tv_tport->tport_name, tpg->tport_tpgt, t->vhost_wwpn, t->vhost_tpgt);


			ret = -EINVAL;
			goto err_tpg;
		}
		tpg->tv_tpg_vhost_count--;
		tpg->vhost_scsi = NULL;
		vs->vs_tpg[target] = NULL;
		match = true;
		mutex_unlock(&tpg->tv_tpg_mutex);
		
		se_tpg = &tpg->se_tpg;
		target_undepend_item(&se_tpg->tpg_group.cg_item);
	}
	if (match) {
		for (i = 0; i < VHOST_SCSI_MAX_VQ; i++) {
			vq = &vs->vqs[i].vq;
			mutex_lock(&vq->mutex);
			vq->private_data = NULL;
			mutex_unlock(&vq->mutex);
		}
	}
	
	vhost_scsi_flush(vs);
	kfree(vs->vs_tpg);
	vs->vs_tpg = NULL;
	WARN_ON(vs->vs_events_nr);
	mutex_unlock(&vs->dev.mutex);
	mutex_unlock(&vhost_scsi_mutex);
	return 0;

err_tpg:
	mutex_unlock(&tpg->tv_tpg_mutex);
err_dev:
	mutex_unlock(&vs->dev.mutex);
	mutex_unlock(&vhost_scsi_mutex);
	return ret;
}

static int vhost_scsi_set_features(struct vhost_scsi *vs, u64 features)
{
	struct vhost_virtqueue *vq;
	int i;

	if (features & ~VHOST_SCSI_FEATURES)
		return -EOPNOTSUPP;

	mutex_lock(&vs->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) && !vhost_log_access_ok(&vs->dev)) {
		mutex_unlock(&vs->dev.mutex);
		return -EFAULT;
	}

	for (i = 0; i < VHOST_SCSI_MAX_VQ; i++) {
		vq = &vs->vqs[i].vq;
		mutex_lock(&vq->mutex);
		vq->acked_features = features;
		mutex_unlock(&vq->mutex);
	}
	mutex_unlock(&vs->dev.mutex);
	return 0;
}

static int vhost_scsi_open(struct inode *inode, struct file *f)
{
	struct vhost_scsi *vs;
	struct vhost_virtqueue **vqs;
	int r = -ENOMEM, i;

	vs = kzalloc(sizeof(*vs), GFP_KERNEL | __GFP_NOWARN | __GFP_RETRY_MAYFAIL);
	if (!vs) {
		vs = vzalloc(sizeof(*vs));
		if (!vs)
			goto err_vs;
	}

	vqs = kmalloc_array(VHOST_SCSI_MAX_VQ, sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vqs;

	vhost_work_init(&vs->vs_completion_work, vhost_scsi_complete_cmd_work);
	vhost_work_init(&vs->vs_event_work, vhost_scsi_evt_work);

	vs->vs_events_nr = 0;
	vs->vs_events_missed = false;

	vqs[VHOST_SCSI_VQ_CTL] = &vs->vqs[VHOST_SCSI_VQ_CTL].vq;
	vqs[VHOST_SCSI_VQ_EVT] = &vs->vqs[VHOST_SCSI_VQ_EVT].vq;
	vs->vqs[VHOST_SCSI_VQ_CTL].vq.handle_kick = vhost_scsi_ctl_handle_kick;
	vs->vqs[VHOST_SCSI_VQ_EVT].vq.handle_kick = vhost_scsi_evt_handle_kick;
	for (i = VHOST_SCSI_VQ_IO; i < VHOST_SCSI_MAX_VQ; i++) {
		vqs[i] = &vs->vqs[i].vq;
		vs->vqs[i].vq.handle_kick = vhost_scsi_handle_kick;
	}
	vhost_dev_init(&vs->dev, vqs, VHOST_SCSI_MAX_VQ);

	vhost_scsi_init_inflight(vs, NULL);

	f->private_data = vs;
	return 0;

err_vqs:
	kvfree(vs);
err_vs:
	return r;
}

static int vhost_scsi_release(struct inode *inode, struct file *f)
{
	struct vhost_scsi *vs = f->private_data;
	struct vhost_scsi_target t;

	mutex_lock(&vs->dev.mutex);
	memcpy(t.vhost_wwpn, vs->vs_vhost_wwpn, sizeof(t.vhost_wwpn));
	mutex_unlock(&vs->dev.mutex);
	vhost_scsi_clear_endpoint(vs, &t);
	vhost_dev_stop(&vs->dev);
	vhost_dev_cleanup(&vs->dev);
	
	vhost_scsi_flush(vs);
	kfree(vs->dev.vqs);
	kvfree(vs);
	return 0;
}

static long vhost_scsi_ioctl(struct file *f, unsigned int ioctl, unsigned long arg)


{
	struct vhost_scsi *vs = f->private_data;
	struct vhost_scsi_target backend;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u32 __user *eventsp = argp;
	u32 events_missed;
	u64 features;
	int r, abi_version = VHOST_SCSI_ABI_VERSION;
	struct vhost_virtqueue *vq = &vs->vqs[VHOST_SCSI_VQ_EVT].vq;

	switch (ioctl) {
	case VHOST_SCSI_SET_ENDPOINT:
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;
		if (backend.reserved != 0)
			return -EOPNOTSUPP;

		return vhost_scsi_set_endpoint(vs, &backend);
	case VHOST_SCSI_CLEAR_ENDPOINT:
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;
		if (backend.reserved != 0)
			return -EOPNOTSUPP;

		return vhost_scsi_clear_endpoint(vs, &backend);
	case VHOST_SCSI_GET_ABI_VERSION:
		if (copy_to_user(argp, &abi_version, sizeof abi_version))
			return -EFAULT;
		return 0;
	case VHOST_SCSI_SET_EVENTS_MISSED:
		if (get_user(events_missed, eventsp))
			return -EFAULT;
		mutex_lock(&vq->mutex);
		vs->vs_events_missed = events_missed;
		mutex_unlock(&vq->mutex);
		return 0;
	case VHOST_SCSI_GET_EVENTS_MISSED:
		mutex_lock(&vq->mutex);
		events_missed = vs->vs_events_missed;
		mutex_unlock(&vq->mutex);
		if (put_user(events_missed, eventsp))
			return -EFAULT;
		return 0;
	case VHOST_GET_FEATURES:
		features = VHOST_SCSI_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;
		return vhost_scsi_set_features(vs, features);
	default:
		mutex_lock(&vs->dev.mutex);
		r = vhost_dev_ioctl(&vs->dev, ioctl, argp);
		
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&vs->dev, ioctl, argp);
		mutex_unlock(&vs->dev.mutex);
		return r;
	}
}


static long vhost_scsi_compat_ioctl(struct file *f, unsigned int ioctl, unsigned long arg)
{
	return vhost_scsi_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}


static const struct file_operations vhost_scsi_fops = {
	.owner          = THIS_MODULE, .release        = vhost_scsi_release, .unlocked_ioctl = vhost_scsi_ioctl,  .compat_ioctl	= vhost_scsi_compat_ioctl,  .open           = vhost_scsi_open, .llseek		= noop_llseek, };








static struct miscdevice vhost_scsi_misc = {
	MISC_DYNAMIC_MINOR, "vhost-scsi", &vhost_scsi_fops, };



static int __init vhost_scsi_register(void)
{
	return misc_register(&vhost_scsi_misc);
}

static void vhost_scsi_deregister(void)
{
	misc_deregister(&vhost_scsi_misc);
}

static char *vhost_scsi_dump_proto_id(struct vhost_scsi_tport *tport)
{
	switch (tport->tport_proto_id) {
	case SCSI_PROTOCOL_SAS:
		return "SAS";
	case SCSI_PROTOCOL_FCP:
		return "FCP";
	case SCSI_PROTOCOL_ISCSI:
		return "iSCSI";
	default:
		break;
	}

	return "Unknown";
}

static void vhost_scsi_do_plug(struct vhost_scsi_tpg *tpg, struct se_lun *lun, bool plug)

{

	struct vhost_scsi *vs = tpg->vhost_scsi;
	struct vhost_virtqueue *vq;
	u32 reason;

	if (!vs)
		return;

	mutex_lock(&vs->dev.mutex);

	if (plug)
		reason = VIRTIO_SCSI_EVT_RESET_RESCAN;
	else reason = VIRTIO_SCSI_EVT_RESET_REMOVED;

	vq = &vs->vqs[VHOST_SCSI_VQ_EVT].vq;
	mutex_lock(&vq->mutex);
	if (vhost_has_feature(vq, VIRTIO_SCSI_F_HOTPLUG))
		vhost_scsi_send_evt(vs, tpg, lun, VIRTIO_SCSI_T_TRANSPORT_RESET, reason);
	mutex_unlock(&vq->mutex);
	mutex_unlock(&vs->dev.mutex);
}

static void vhost_scsi_hotplug(struct vhost_scsi_tpg *tpg, struct se_lun *lun)
{
	vhost_scsi_do_plug(tpg, lun, true);
}

static void vhost_scsi_hotunplug(struct vhost_scsi_tpg *tpg, struct se_lun *lun)
{
	vhost_scsi_do_plug(tpg, lun, false);
}

static int vhost_scsi_port_link(struct se_portal_group *se_tpg, struct se_lun *lun)
{
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);

	mutex_lock(&vhost_scsi_mutex);

	mutex_lock(&tpg->tv_tpg_mutex);
	tpg->tv_tpg_port_count++;
	mutex_unlock(&tpg->tv_tpg_mutex);

	vhost_scsi_hotplug(tpg, lun);

	mutex_unlock(&vhost_scsi_mutex);

	return 0;
}

static void vhost_scsi_port_unlink(struct se_portal_group *se_tpg, struct se_lun *lun)
{
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);

	mutex_lock(&vhost_scsi_mutex);

	mutex_lock(&tpg->tv_tpg_mutex);
	tpg->tv_tpg_port_count--;
	mutex_unlock(&tpg->tv_tpg_mutex);

	vhost_scsi_hotunplug(tpg, lun);

	mutex_unlock(&vhost_scsi_mutex);
}

static void vhost_scsi_free_cmd_map_res(struct se_session *se_sess)
{
	struct vhost_scsi_cmd *tv_cmd;
	unsigned int i;

	if (!se_sess->sess_cmd_map)
		return;

	for (i = 0; i < VHOST_SCSI_DEFAULT_TAGS; i++) {
		tv_cmd = &((struct vhost_scsi_cmd *)se_sess->sess_cmd_map)[i];

		kfree(tv_cmd->tvc_sgl);
		kfree(tv_cmd->tvc_prot_sgl);
		kfree(tv_cmd->tvc_upages);
	}
}

static ssize_t vhost_scsi_tpg_attrib_fabric_prot_type_store( struct config_item *item, const char *page, size_t count)
{
	struct se_portal_group *se_tpg = attrib_to_tpg(item);
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);
	unsigned long val;
	int ret = kstrtoul(page, 0, &val);

	if (ret) {
		pr_err("kstrtoul() returned %d for fabric_prot_type\n", ret);
		return ret;
	}
	if (val != 0 && val != 1 && val != 3) {
		pr_err("Invalid vhost_scsi fabric_prot_type: %lu\n", val);
		return -EINVAL;
	}
	tpg->tv_fabric_prot_type = val;

	return count;
}

static ssize_t vhost_scsi_tpg_attrib_fabric_prot_type_show( struct config_item *item, char *page)
{
	struct se_portal_group *se_tpg = attrib_to_tpg(item);
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);

	return sprintf(page, "%d\n", tpg->tv_fabric_prot_type);
}

CONFIGFS_ATTR(vhost_scsi_tpg_attrib_, fabric_prot_type);

static struct configfs_attribute *vhost_scsi_tpg_attrib_attrs[] = {
	&vhost_scsi_tpg_attrib_attr_fabric_prot_type, NULL, };


static int vhost_scsi_nexus_cb(struct se_portal_group *se_tpg, struct se_session *se_sess, void *p)
{
	struct vhost_scsi_cmd *tv_cmd;
	unsigned int i;

	for (i = 0; i < VHOST_SCSI_DEFAULT_TAGS; i++) {
		tv_cmd = &((struct vhost_scsi_cmd *)se_sess->sess_cmd_map)[i];

		tv_cmd->tvc_sgl = kcalloc(VHOST_SCSI_PREALLOC_SGLS, sizeof(struct scatterlist), GFP_KERNEL);

		if (!tv_cmd->tvc_sgl) {
			pr_err("Unable to allocate tv_cmd->tvc_sgl\n");
			goto out;
		}

		tv_cmd->tvc_upages = kcalloc(VHOST_SCSI_PREALLOC_UPAGES, sizeof(struct page *), GFP_KERNEL);

		if (!tv_cmd->tvc_upages) {
			pr_err("Unable to allocate tv_cmd->tvc_upages\n");
			goto out;
		}

		tv_cmd->tvc_prot_sgl = kcalloc(VHOST_SCSI_PREALLOC_PROT_SGLS, sizeof(struct scatterlist), GFP_KERNEL);

		if (!tv_cmd->tvc_prot_sgl) {
			pr_err("Unable to allocate tv_cmd->tvc_prot_sgl\n");
			goto out;
		}
	}
	return 0;
out:
	vhost_scsi_free_cmd_map_res(se_sess);
	return -ENOMEM;
}

static int vhost_scsi_make_nexus(struct vhost_scsi_tpg *tpg, const char *name)
{
	struct vhost_scsi_nexus *tv_nexus;

	mutex_lock(&tpg->tv_tpg_mutex);
	if (tpg->tpg_nexus) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		pr_debug("tpg->tpg_nexus already exists\n");
		return -EEXIST;
	}

	tv_nexus = kzalloc(sizeof(*tv_nexus), GFP_KERNEL);
	if (!tv_nexus) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		pr_err("Unable to allocate struct vhost_scsi_nexus\n");
		return -ENOMEM;
	}
	
	tv_nexus->tvn_se_sess = target_setup_session(&tpg->se_tpg, VHOST_SCSI_DEFAULT_TAGS, sizeof(struct vhost_scsi_cmd), TARGET_PROT_DIN_PASS | TARGET_PROT_DOUT_PASS, (unsigned char *)name, tv_nexus, vhost_scsi_nexus_cb);




	if (IS_ERR(tv_nexus->tvn_se_sess)) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		kfree(tv_nexus);
		return -ENOMEM;
	}
	tpg->tpg_nexus = tv_nexus;

	mutex_unlock(&tpg->tv_tpg_mutex);
	return 0;
}

static int vhost_scsi_drop_nexus(struct vhost_scsi_tpg *tpg)
{
	struct se_session *se_sess;
	struct vhost_scsi_nexus *tv_nexus;

	mutex_lock(&tpg->tv_tpg_mutex);
	tv_nexus = tpg->tpg_nexus;
	if (!tv_nexus) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		return -ENODEV;
	}

	se_sess = tv_nexus->tvn_se_sess;
	if (!se_sess) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		return -ENODEV;
	}

	if (tpg->tv_tpg_port_count != 0) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		pr_err("Unable to remove TCM_vhost I_T Nexus with" " active TPG port count: %d\n", tpg->tv_tpg_port_count);

		return -EBUSY;
	}

	if (tpg->tv_tpg_vhost_count != 0) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		pr_err("Unable to remove TCM_vhost I_T Nexus with" " active TPG vhost count: %d\n", tpg->tv_tpg_vhost_count);

		return -EBUSY;
	}

	pr_debug("TCM_vhost_ConfigFS: Removing I_T Nexus to emulated" " %s Initiator Port: %s\n", vhost_scsi_dump_proto_id(tpg->tport), tv_nexus->tvn_se_sess->se_node_acl->initiatorname);


	vhost_scsi_free_cmd_map_res(se_sess);
	
	target_remove_session(se_sess);
	tpg->tpg_nexus = NULL;
	mutex_unlock(&tpg->tv_tpg_mutex);

	kfree(tv_nexus);
	return 0;
}

static ssize_t vhost_scsi_tpg_nexus_show(struct config_item *item, char *page)
{
	struct se_portal_group *se_tpg = to_tpg(item);
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);
	struct vhost_scsi_nexus *tv_nexus;
	ssize_t ret;

	mutex_lock(&tpg->tv_tpg_mutex);
	tv_nexus = tpg->tpg_nexus;
	if (!tv_nexus) {
		mutex_unlock(&tpg->tv_tpg_mutex);
		return -ENODEV;
	}
	ret = snprintf(page, PAGE_SIZE, "%s\n", tv_nexus->tvn_se_sess->se_node_acl->initiatorname);
	mutex_unlock(&tpg->tv_tpg_mutex);

	return ret;
}

static ssize_t vhost_scsi_tpg_nexus_store(struct config_item *item, const char *page, size_t count)
{
	struct se_portal_group *se_tpg = to_tpg(item);
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);
	struct vhost_scsi_tport *tport_wwn = tpg->tport;
	unsigned char i_port[VHOST_SCSI_NAMELEN], *ptr, *port_ptr;
	int ret;
	
	if (!strncmp(page, "NULL", 4)) {
		ret = vhost_scsi_drop_nexus(tpg);
		return (!ret) ? count : ret;
	}
	
	if (strlen(page) >= VHOST_SCSI_NAMELEN) {
		pr_err("Emulated NAA Sas Address: %s, exceeds" " max: %d\n", page, VHOST_SCSI_NAMELEN);
		return -EINVAL;
	}
	snprintf(&i_port[0], VHOST_SCSI_NAMELEN, "%s", page);

	ptr = strstr(i_port, "naa.");
	if (ptr) {
		if (tport_wwn->tport_proto_id != SCSI_PROTOCOL_SAS) {
			pr_err("Passed SAS Initiator Port %s does not" " match target port protoid: %s\n", i_port, vhost_scsi_dump_proto_id(tport_wwn));

			return -EINVAL;
		}
		port_ptr = &i_port[0];
		goto check_newline;
	}
	ptr = strstr(i_port, "fc.");
	if (ptr) {
		if (tport_wwn->tport_proto_id != SCSI_PROTOCOL_FCP) {
			pr_err("Passed FCP Initiator Port %s does not" " match target port protoid: %s\n", i_port, vhost_scsi_dump_proto_id(tport_wwn));

			return -EINVAL;
		}
		port_ptr = &i_port[3]; 
		goto check_newline;
	}
	ptr = strstr(i_port, "iqn.");
	if (ptr) {
		if (tport_wwn->tport_proto_id != SCSI_PROTOCOL_ISCSI) {
			pr_err("Passed iSCSI Initiator Port %s does not" " match target port protoid: %s\n", i_port, vhost_scsi_dump_proto_id(tport_wwn));

			return -EINVAL;
		}
		port_ptr = &i_port[0];
		goto check_newline;
	}
	pr_err("Unable to locate prefix for emulated Initiator Port:" " %s\n", i_port);
	return -EINVAL;
	
check_newline:
	if (i_port[strlen(i_port)-1] == '\n')
		i_port[strlen(i_port)-1] = '\0';

	ret = vhost_scsi_make_nexus(tpg, port_ptr);
	if (ret < 0)
		return ret;

	return count;
}

CONFIGFS_ATTR(vhost_scsi_tpg_, nexus);

static struct configfs_attribute *vhost_scsi_tpg_attrs[] = {
	&vhost_scsi_tpg_attr_nexus, NULL, };


static struct se_portal_group * vhost_scsi_make_tpg(struct se_wwn *wwn, const char *name)
{
	struct vhost_scsi_tport *tport = container_of(wwn, struct vhost_scsi_tport, tport_wwn);

	struct vhost_scsi_tpg *tpg;
	u16 tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (kstrtou16(name + 5, 10, &tpgt) || tpgt >= VHOST_SCSI_MAX_TARGET)
		return ERR_PTR(-EINVAL);

	tpg = kzalloc(sizeof(*tpg), GFP_KERNEL);
	if (!tpg) {
		pr_err("Unable to allocate struct vhost_scsi_tpg");
		return ERR_PTR(-ENOMEM);
	}
	mutex_init(&tpg->tv_tpg_mutex);
	INIT_LIST_HEAD(&tpg->tv_tpg_list);
	tpg->tport = tport;
	tpg->tport_tpgt = tpgt;

	ret = core_tpg_register(wwn, &tpg->se_tpg, tport->tport_proto_id);
	if (ret < 0) {
		kfree(tpg);
		return NULL;
	}
	mutex_lock(&vhost_scsi_mutex);
	list_add_tail(&tpg->tv_tpg_list, &vhost_scsi_list);
	mutex_unlock(&vhost_scsi_mutex);

	return &tpg->se_tpg;
}

static void vhost_scsi_drop_tpg(struct se_portal_group *se_tpg)
{
	struct vhost_scsi_tpg *tpg = container_of(se_tpg, struct vhost_scsi_tpg, se_tpg);

	mutex_lock(&vhost_scsi_mutex);
	list_del(&tpg->tv_tpg_list);
	mutex_unlock(&vhost_scsi_mutex);
	
	vhost_scsi_drop_nexus(tpg);
	
	core_tpg_deregister(se_tpg);
	kfree(tpg);
}

static struct se_wwn * vhost_scsi_make_tport(struct target_fabric_configfs *tf, struct config_group *group, const char *name)


{
	struct vhost_scsi_tport *tport;
	char *ptr;
	u64 wwpn = 0;
	int off = 0;

	

	tport = kzalloc(sizeof(*tport), GFP_KERNEL);
	if (!tport) {
		pr_err("Unable to allocate struct vhost_scsi_tport");
		return ERR_PTR(-ENOMEM);
	}
	tport->tport_wwpn = wwpn;
	
	ptr = strstr(name, "naa.");
	if (ptr) {
		tport->tport_proto_id = SCSI_PROTOCOL_SAS;
		goto check_len;
	}
	ptr = strstr(name, "fc.");
	if (ptr) {
		tport->tport_proto_id = SCSI_PROTOCOL_FCP;
		off = 3; 
		goto check_len;
	}
	ptr = strstr(name, "iqn.");
	if (ptr) {
		tport->tport_proto_id = SCSI_PROTOCOL_ISCSI;
		goto check_len;
	}

	pr_err("Unable to locate prefix for emulated Target Port:" " %s\n", name);
	kfree(tport);
	return ERR_PTR(-EINVAL);

check_len:
	if (strlen(name) >= VHOST_SCSI_NAMELEN) {
		pr_err("Emulated %s Address: %s, exceeds" " max: %d\n", name, vhost_scsi_dump_proto_id(tport), VHOST_SCSI_NAMELEN);

		kfree(tport);
		return ERR_PTR(-EINVAL);
	}
	snprintf(&tport->tport_name[0], VHOST_SCSI_NAMELEN, "%s", &name[off]);

	pr_debug("TCM_VHost_ConfigFS: Allocated emulated Target" " %s Address: %s\n", vhost_scsi_dump_proto_id(tport), name);

	return &tport->tport_wwn;
}

static void vhost_scsi_drop_tport(struct se_wwn *wwn)
{
	struct vhost_scsi_tport *tport = container_of(wwn, struct vhost_scsi_tport, tport_wwn);

	pr_debug("TCM_VHost_ConfigFS: Deallocating emulated Target" " %s Address: %s\n", vhost_scsi_dump_proto_id(tport), tport->tport_name);


	kfree(tport);
}

static ssize_t vhost_scsi_wwn_version_show(struct config_item *item, char *page)
{
	return sprintf(page, "TCM_VHOST fabric module %s on %s/%s" "on "UTS_RELEASE"\n", VHOST_SCSI_VERSION, utsname()->sysname, utsname()->machine);

}

CONFIGFS_ATTR_RO(vhost_scsi_wwn_, version);

static struct configfs_attribute *vhost_scsi_wwn_attrs[] = {
	&vhost_scsi_wwn_attr_version, NULL, };


static const struct target_core_fabric_ops vhost_scsi_ops = {
	.module				= THIS_MODULE, .fabric_name			= "vhost", .tpg_get_wwn			= vhost_scsi_get_fabric_wwn, .tpg_get_tag			= vhost_scsi_get_tpgt, .tpg_check_demo_mode		= vhost_scsi_check_true, .tpg_check_demo_mode_cache	= vhost_scsi_check_true, .tpg_check_demo_mode_write_protect = vhost_scsi_check_false, .tpg_check_prod_mode_write_protect = vhost_scsi_check_false, .tpg_check_prot_fabric_only	= vhost_scsi_check_prot_fabric_only, .tpg_get_inst_index		= vhost_scsi_tpg_get_inst_index, .release_cmd			= vhost_scsi_release_cmd, .check_stop_free		= vhost_scsi_check_stop_free, .sess_get_index			= vhost_scsi_sess_get_index, .sess_get_initiator_sid		= NULL, .write_pending			= vhost_scsi_write_pending, .write_pending_status		= vhost_scsi_write_pending_status, .set_default_node_attributes	= vhost_scsi_set_default_node_attrs, .get_cmd_state			= vhost_scsi_get_cmd_state, .queue_data_in			= vhost_scsi_queue_data_in, .queue_status			= vhost_scsi_queue_status, .queue_tm_rsp			= vhost_scsi_queue_tm_rsp, .aborted_task			= vhost_scsi_aborted_task,  .fabric_make_wwn		= vhost_scsi_make_tport, .fabric_drop_wwn		= vhost_scsi_drop_tport, .fabric_make_tpg		= vhost_scsi_make_tpg, .fabric_drop_tpg		= vhost_scsi_drop_tpg, .fabric_post_link		= vhost_scsi_port_link, .fabric_pre_unlink		= vhost_scsi_port_unlink,  .tfc_wwn_attrs			= vhost_scsi_wwn_attrs, .tfc_tpg_base_attrs		= vhost_scsi_tpg_attrs, .tfc_tpg_attrib_attrs		= vhost_scsi_tpg_attrib_attrs, };

































static int __init vhost_scsi_init(void)
{
	int ret = -ENOMEM;

	pr_debug("TCM_VHOST fabric module %s on %s/%s" " on "UTS_RELEASE"\n", VHOST_SCSI_VERSION, utsname()->sysname, utsname()->machine);


	
	vhost_scsi_workqueue = alloc_workqueue("vhost_scsi", 0, 0);
	if (!vhost_scsi_workqueue)
		goto out;

	ret = vhost_scsi_register();
	if (ret < 0)
		goto out_destroy_workqueue;

	ret = target_register_template(&vhost_scsi_ops);
	if (ret < 0)
		goto out_vhost_scsi_deregister;

	return 0;

out_vhost_scsi_deregister:
	vhost_scsi_deregister();
out_destroy_workqueue:
	destroy_workqueue(vhost_scsi_workqueue);
out:
	return ret;
};

static void vhost_scsi_exit(void)
{
	target_unregister_template(&vhost_scsi_ops);
	vhost_scsi_deregister();
	destroy_workqueue(vhost_scsi_workqueue);
};

MODULE_DESCRIPTION("VHOST_SCSI series fabric driver");
MODULE_ALIAS("tcm_vhost");
MODULE_LICENSE("GPL");
module_init(vhost_scsi_init);
module_exit(vhost_scsi_exit);
