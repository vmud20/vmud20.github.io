



















































static bool con_flag_valid(unsigned long con_flag)
{
	switch (con_flag) {
	case CON_FLAG_LOSSYTX:
	case CON_FLAG_KEEPALIVE_PENDING:
	case CON_FLAG_WRITE_PENDING:
	case CON_FLAG_SOCK_CLOSED:
	case CON_FLAG_BACKOFF:
		return true;
	default:
		return false;
	}
}

static void con_flag_clear(struct ceph_connection *con, unsigned long con_flag)
{
	BUG_ON(!con_flag_valid(con_flag));

	clear_bit(con_flag, &con->flags);
}

static void con_flag_set(struct ceph_connection *con, unsigned long con_flag)
{
	BUG_ON(!con_flag_valid(con_flag));

	set_bit(con_flag, &con->flags);
}

static bool con_flag_test(struct ceph_connection *con, unsigned long con_flag)
{
	BUG_ON(!con_flag_valid(con_flag));

	return test_bit(con_flag, &con->flags);
}

static bool con_flag_test_and_clear(struct ceph_connection *con, unsigned long con_flag)
{
	BUG_ON(!con_flag_valid(con_flag));

	return test_and_clear_bit(con_flag, &con->flags);
}

static bool con_flag_test_and_set(struct ceph_connection *con, unsigned long con_flag)
{
	BUG_ON(!con_flag_valid(con_flag));

	return test_and_set_bit(con_flag, &con->flags);
}



static struct kmem_cache	*ceph_msg_cache;
static struct kmem_cache	*ceph_msg_data_cache;


static char tag_msg = CEPH_MSGR_TAG_MSG;
static char tag_ack = CEPH_MSGR_TAG_ACK;
static char tag_keepalive = CEPH_MSGR_TAG_KEEPALIVE;
static char tag_keepalive2 = CEPH_MSGR_TAG_KEEPALIVE2;


static struct lock_class_key socket_class;


static void queue_con(struct ceph_connection *con);
static void cancel_con(struct ceph_connection *con);
static void ceph_con_workfn(struct work_struct *);
static void con_fault(struct ceph_connection *con);







static char addr_str[ADDR_STR_COUNT][MAX_ADDR_STR_LEN];
static atomic_t addr_str_seq = ATOMIC_INIT(0);

static struct page *zero_page;		

const char *ceph_pr_addr(const struct sockaddr_storage *ss)
{
	int i;
	char *s;
	struct sockaddr_in *in4 = (struct sockaddr_in *) ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) ss;

	i = atomic_inc_return(&addr_str_seq) & ADDR_STR_COUNT_MASK;
	s = addr_str[i];

	switch (ss->ss_family) {
	case AF_INET:
		snprintf(s, MAX_ADDR_STR_LEN, "%pI4:%hu", &in4->sin_addr, ntohs(in4->sin_port));
		break;

	case AF_INET6:
		snprintf(s, MAX_ADDR_STR_LEN, "[%pI6c]:%hu", &in6->sin6_addr, ntohs(in6->sin6_port));
		break;

	default:
		snprintf(s, MAX_ADDR_STR_LEN, "(unknown sockaddr family %hu)", ss->ss_family);
	}

	return s;
}
EXPORT_SYMBOL(ceph_pr_addr);

static void encode_my_addr(struct ceph_messenger *msgr)
{
	memcpy(&msgr->my_enc_addr, &msgr->inst.addr, sizeof(msgr->my_enc_addr));
	ceph_encode_addr(&msgr->my_enc_addr);
}


static struct workqueue_struct *ceph_msgr_wq;

static int ceph_msgr_slab_init(void)
{
	BUG_ON(ceph_msg_cache);
	ceph_msg_cache = KMEM_CACHE(ceph_msg, 0);
	if (!ceph_msg_cache)
		return -ENOMEM;

	BUG_ON(ceph_msg_data_cache);
	ceph_msg_data_cache = KMEM_CACHE(ceph_msg_data, 0);
	if (ceph_msg_data_cache)
		return 0;

	kmem_cache_destroy(ceph_msg_cache);
	ceph_msg_cache = NULL;

	return -ENOMEM;
}

static void ceph_msgr_slab_exit(void)
{
	BUG_ON(!ceph_msg_data_cache);
	kmem_cache_destroy(ceph_msg_data_cache);
	ceph_msg_data_cache = NULL;

	BUG_ON(!ceph_msg_cache);
	kmem_cache_destroy(ceph_msg_cache);
	ceph_msg_cache = NULL;
}

static void _ceph_msgr_exit(void)
{
	if (ceph_msgr_wq) {
		destroy_workqueue(ceph_msgr_wq);
		ceph_msgr_wq = NULL;
	}

	BUG_ON(zero_page == NULL);
	put_page(zero_page);
	zero_page = NULL;

	ceph_msgr_slab_exit();
}

int __init ceph_msgr_init(void)
{
	if (ceph_msgr_slab_init())
		return -ENOMEM;

	BUG_ON(zero_page != NULL);
	zero_page = ZERO_PAGE(0);
	get_page(zero_page);

	
	ceph_msgr_wq = alloc_workqueue("ceph-msgr", WQ_MEM_RECLAIM, 0);
	if (ceph_msgr_wq)
		return 0;

	pr_err("msgr_init failed to create workqueue\n");
	_ceph_msgr_exit();

	return -ENOMEM;
}

void ceph_msgr_exit(void)
{
	BUG_ON(ceph_msgr_wq == NULL);

	_ceph_msgr_exit();
}

void ceph_msgr_flush(void)
{
	flush_workqueue(ceph_msgr_wq);
}
EXPORT_SYMBOL(ceph_msgr_flush);



static void con_sock_state_init(struct ceph_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSED);
	if (WARN_ON(old_state != CON_SOCK_STATE_NEW))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	dout("%s con %p sock %d -> %d\n", __func__, con, old_state, CON_SOCK_STATE_CLOSED);
}

static void con_sock_state_connecting(struct ceph_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CONNECTING);
	if (WARN_ON(old_state != CON_SOCK_STATE_CLOSED))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	dout("%s con %p sock %d -> %d\n", __func__, con, old_state, CON_SOCK_STATE_CONNECTING);
}

static void con_sock_state_connected(struct ceph_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CONNECTED);
	if (WARN_ON(old_state != CON_SOCK_STATE_CONNECTING))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	dout("%s con %p sock %d -> %d\n", __func__, con, old_state, CON_SOCK_STATE_CONNECTED);
}

static void con_sock_state_closing(struct ceph_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSING);
	if (WARN_ON(old_state != CON_SOCK_STATE_CONNECTING && old_state != CON_SOCK_STATE_CONNECTED && old_state != CON_SOCK_STATE_CLOSING))

		printk("%s: unexpected old state %d\n", __func__, old_state);
	dout("%s con %p sock %d -> %d\n", __func__, con, old_state, CON_SOCK_STATE_CLOSING);
}

static void con_sock_state_closed(struct ceph_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSED);
	if (WARN_ON(old_state != CON_SOCK_STATE_CONNECTED && old_state != CON_SOCK_STATE_CLOSING && old_state != CON_SOCK_STATE_CONNECTING && old_state != CON_SOCK_STATE_CLOSED))


		printk("%s: unexpected old state %d\n", __func__, old_state);
	dout("%s con %p sock %d -> %d\n", __func__, con, old_state, CON_SOCK_STATE_CLOSED);
}




static void ceph_sock_data_ready(struct sock *sk)
{
	struct ceph_connection *con = sk->sk_user_data;
	if (atomic_read(&con->msgr->stopping)) {
		return;
	}

	if (sk->sk_state != TCP_CLOSE_WAIT) {
		dout("%s on %p state = %lu, queueing work\n", __func__, con, con->state);
		queue_con(con);
	}
}


static void ceph_sock_write_space(struct sock *sk)
{
	struct ceph_connection *con = sk->sk_user_data;

	
	if (con_flag_test(con, CON_FLAG_WRITE_PENDING)) {
		if (sk_stream_is_writeable(sk)) {
			dout("%s %p queueing write work\n", __func__, con);
			clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			queue_con(con);
		}
	} else {
		dout("%s %p nothing to write\n", __func__, con);
	}
}


static void ceph_sock_state_change(struct sock *sk)
{
	struct ceph_connection *con = sk->sk_user_data;

	dout("%s %p state = %lu sk_state = %u\n", __func__, con, con->state, sk->sk_state);

	switch (sk->sk_state) {
	case TCP_CLOSE:
		dout("%s TCP_CLOSE\n", __func__);
		
	case TCP_CLOSE_WAIT:
		dout("%s TCP_CLOSE_WAIT\n", __func__);
		con_sock_state_closing(con);
		con_flag_set(con, CON_FLAG_SOCK_CLOSED);
		queue_con(con);
		break;
	case TCP_ESTABLISHED:
		dout("%s TCP_ESTABLISHED\n", __func__);
		con_sock_state_connected(con);
		queue_con(con);
		break;
	default:	
		break;
	}
}


static void set_sock_callbacks(struct socket *sock, struct ceph_connection *con)
{
	struct sock *sk = sock->sk;
	sk->sk_user_data = con;
	sk->sk_data_ready = ceph_sock_data_ready;
	sk->sk_write_space = ceph_sock_write_space;
	sk->sk_state_change = ceph_sock_state_change;
}





static int ceph_tcp_connect(struct ceph_connection *con)
{
	struct sockaddr_storage *paddr = &con->peer_addr.in_addr;
	struct socket *sock;
	unsigned int noio_flag;
	int ret;

	BUG_ON(con->sock);

	
	noio_flag = memalloc_noio_save();
	ret = sock_create_kern(read_pnet(&con->msgr->net), paddr->ss_family, SOCK_STREAM, IPPROTO_TCP, &sock);
	memalloc_noio_restore(noio_flag);
	if (ret)
		return ret;
	sock->sk->sk_allocation = GFP_NOFS;


	lockdep_set_class(&sock->sk->sk_lock, &socket_class);


	set_sock_callbacks(sock, con);

	dout("connect %s\n", ceph_pr_addr(&con->peer_addr.in_addr));

	con_sock_state_connecting(con);
	ret = sock->ops->connect(sock, (struct sockaddr *)paddr, sizeof(*paddr), O_NONBLOCK);
	if (ret == -EINPROGRESS) {
		dout("connect %s EINPROGRESS sk_state = %u\n", ceph_pr_addr(&con->peer_addr.in_addr), sock->sk->sk_state);

	} else if (ret < 0) {
		pr_err("connect %s error %d\n", ceph_pr_addr(&con->peer_addr.in_addr), ret);
		sock_release(sock);
		return ret;
	}

	if (ceph_test_opt(from_msgr(con->msgr), TCP_NODELAY)) {
		int optval = 1;

		ret = kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
		if (ret)
			pr_err("kernel_setsockopt(TCP_NODELAY) failed: %d", ret);
	}

	con->sock = sock;
	return 0;
}


static int ceph_tcp_recvmsg(struct socket *sock, void *buf, size_t len)
{
	struct kvec iov = {buf, len};
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	int r;

	if (!buf)
		msg.msg_flags |= MSG_TRUNC;

	iov_iter_kvec(&msg.msg_iter, READ | ITER_KVEC, &iov, 1, len);
	r = sock_recvmsg(sock, &msg, msg.msg_flags);
	if (r == -EAGAIN)
		r = 0;
	return r;
}

static int ceph_tcp_recvpage(struct socket *sock, struct page *page, int page_offset, size_t length)
{
	struct bio_vec bvec = {
		.bv_page = page, .bv_offset = page_offset, .bv_len = length };


	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	int r;

	BUG_ON(page_offset + length > PAGE_SIZE);
	iov_iter_bvec(&msg.msg_iter, READ | ITER_BVEC, &bvec, 1, length);
	r = sock_recvmsg(sock, &msg, msg.msg_flags);
	if (r == -EAGAIN)
		r = 0;
	return r;
}


static int ceph_tcp_sendmsg(struct socket *sock, struct kvec *iov, size_t kvlen, size_t len, int more)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	int r;

	if (more)
		msg.msg_flags |= MSG_MORE;
	else msg.msg_flags |= MSG_EOR;

	r = kernel_sendmsg(sock, &msg, iov, kvlen, len);
	if (r == -EAGAIN)
		r = 0;
	return r;
}

static int __ceph_tcp_sendpage(struct socket *sock, struct page *page, int offset, size_t size, bool more)
{
	int flags = MSG_DONTWAIT | MSG_NOSIGNAL | (more ? MSG_MORE : MSG_EOR);
	int ret;

	ret = kernel_sendpage(sock, page, offset, size, flags);
	if (ret == -EAGAIN)
		ret = 0;

	return ret;
}

static int ceph_tcp_sendpage(struct socket *sock, struct page *page, int offset, size_t size, bool more)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct bio_vec bvec;
	int ret;

	
	if (page_count(page) >= 1)
		return __ceph_tcp_sendpage(sock, page, offset, size, more);

	bvec.bv_page = page;
	bvec.bv_offset = offset;
	bvec.bv_len = size;

	if (more)
		msg.msg_flags |= MSG_MORE;
	else msg.msg_flags |= MSG_EOR;

	iov_iter_bvec(&msg.msg_iter, WRITE | ITER_BVEC, &bvec, 1, size);
	ret = sock_sendmsg(sock, &msg);
	if (ret == -EAGAIN)
		ret = 0;

	return ret;
}


static int con_close_socket(struct ceph_connection *con)
{
	int rc = 0;

	dout("con_close_socket on %p sock %p\n", con, con->sock);
	if (con->sock) {
		rc = con->sock->ops->shutdown(con->sock, SHUT_RDWR);
		sock_release(con->sock);
		con->sock = NULL;
	}

	
	con_flag_clear(con, CON_FLAG_SOCK_CLOSED);

	con_sock_state_closed(con);
	return rc;
}


static void ceph_msg_remove(struct ceph_msg *msg)
{
	list_del_init(&msg->list_head);

	ceph_msg_put(msg);
}
static void ceph_msg_remove_list(struct list_head *head)
{
	while (!list_empty(head)) {
		struct ceph_msg *msg = list_first_entry(head, struct ceph_msg, list_head);
		ceph_msg_remove(msg);
	}
}

static void reset_connection(struct ceph_connection *con)
{
	
	
	dout("reset_connection %p\n", con);
	ceph_msg_remove_list(&con->out_queue);
	ceph_msg_remove_list(&con->out_sent);

	if (con->in_msg) {
		BUG_ON(con->in_msg->con != con);
		ceph_msg_put(con->in_msg);
		con->in_msg = NULL;
	}

	con->connect_seq = 0;
	con->out_seq = 0;
	if (con->out_msg) {
		BUG_ON(con->out_msg->con != con);
		ceph_msg_put(con->out_msg);
		con->out_msg = NULL;
	}
	con->in_seq = 0;
	con->in_seq_acked = 0;

	con->out_skip = 0;
}


void ceph_con_close(struct ceph_connection *con)
{
	mutex_lock(&con->mutex);
	dout("con_close %p peer %s\n", con, ceph_pr_addr(&con->peer_addr.in_addr));
	con->state = CON_STATE_CLOSED;

	con_flag_clear(con, CON_FLAG_LOSSYTX);	
	con_flag_clear(con, CON_FLAG_KEEPALIVE_PENDING);
	con_flag_clear(con, CON_FLAG_WRITE_PENDING);
	con_flag_clear(con, CON_FLAG_BACKOFF);

	reset_connection(con);
	con->peer_global_seq = 0;
	cancel_con(con);
	con_close_socket(con);
	mutex_unlock(&con->mutex);
}
EXPORT_SYMBOL(ceph_con_close);


void ceph_con_open(struct ceph_connection *con, __u8 entity_type, __u64 entity_num, struct ceph_entity_addr *addr)

{
	mutex_lock(&con->mutex);
	dout("con_open %p %s\n", con, ceph_pr_addr(&addr->in_addr));

	WARN_ON(con->state != CON_STATE_CLOSED);
	con->state = CON_STATE_PREOPEN;

	con->peer_name.type = (__u8) entity_type;
	con->peer_name.num = cpu_to_le64(entity_num);

	memcpy(&con->peer_addr, addr, sizeof(*addr));
	con->delay = 0;      
	mutex_unlock(&con->mutex);
	queue_con(con);
}
EXPORT_SYMBOL(ceph_con_open);


bool ceph_con_opened(struct ceph_connection *con)
{
	return con->connect_seq > 0;
}


void ceph_con_init(struct ceph_connection *con, void *private, const struct ceph_connection_operations *ops, struct ceph_messenger *msgr)

{
	dout("con_init %p\n", con);
	memset(con, 0, sizeof(*con));
	con->private = private;
	con->ops = ops;
	con->msgr = msgr;

	con_sock_state_init(con);

	mutex_init(&con->mutex);
	INIT_LIST_HEAD(&con->out_queue);
	INIT_LIST_HEAD(&con->out_sent);
	INIT_DELAYED_WORK(&con->work, ceph_con_workfn);

	con->state = CON_STATE_CLOSED;
}
EXPORT_SYMBOL(ceph_con_init);



static u32 get_global_seq(struct ceph_messenger *msgr, u32 gt)
{
	u32 ret;

	spin_lock(&msgr->global_seq_lock);
	if (msgr->global_seq < gt)
		msgr->global_seq = gt;
	ret = ++msgr->global_seq;
	spin_unlock(&msgr->global_seq_lock);
	return ret;
}

static void con_out_kvec_reset(struct ceph_connection *con)
{
	BUG_ON(con->out_skip);

	con->out_kvec_left = 0;
	con->out_kvec_bytes = 0;
	con->out_kvec_cur = &con->out_kvec[0];
}

static void con_out_kvec_add(struct ceph_connection *con, size_t size, void *data)
{
	int index = con->out_kvec_left;

	BUG_ON(con->out_skip);
	BUG_ON(index >= ARRAY_SIZE(con->out_kvec));

	con->out_kvec[index].iov_len = size;
	con->out_kvec[index].iov_base = data;
	con->out_kvec_left++;
	con->out_kvec_bytes += size;
}


static int con_out_kvec_skip(struct ceph_connection *con)
{
	int off = con->out_kvec_cur - con->out_kvec;
	int skip = 0;

	if (con->out_kvec_bytes > 0) {
		skip = con->out_kvec[off + con->out_kvec_left - 1].iov_len;
		BUG_ON(con->out_kvec_bytes < skip);
		BUG_ON(!con->out_kvec_left);
		con->out_kvec_bytes -= skip;
		con->out_kvec_left--;
	}

	return skip;
}




static void ceph_msg_data_bio_cursor_init(struct ceph_msg_data_cursor *cursor, size_t length)
{
	struct ceph_msg_data *data = cursor->data;
	struct ceph_bio_iter *it = &cursor->bio_iter;

	cursor->resid = min_t(size_t, length, data->bio_length);
	*it = data->bio_pos;
	if (cursor->resid < it->iter.bi_size)
		it->iter.bi_size = cursor->resid;

	BUG_ON(cursor->resid < bio_iter_len(it->bio, it->iter));
	cursor->last_piece = cursor->resid == bio_iter_len(it->bio, it->iter);
}

static struct page *ceph_msg_data_bio_next(struct ceph_msg_data_cursor *cursor, size_t *page_offset, size_t *length)

{
	struct bio_vec bv = bio_iter_iovec(cursor->bio_iter.bio, cursor->bio_iter.iter);

	*page_offset = bv.bv_offset;
	*length = bv.bv_len;
	return bv.bv_page;
}

static bool ceph_msg_data_bio_advance(struct ceph_msg_data_cursor *cursor, size_t bytes)
{
	struct ceph_bio_iter *it = &cursor->bio_iter;

	BUG_ON(bytes > cursor->resid);
	BUG_ON(bytes > bio_iter_len(it->bio, it->iter));
	cursor->resid -= bytes;
	bio_advance_iter(it->bio, &it->iter, bytes);

	if (!cursor->resid) {
		BUG_ON(!cursor->last_piece);
		return false;   
	}

	if (!bytes || (it->iter.bi_size && it->iter.bi_bvec_done))
		return false;	

	if (!it->iter.bi_size) {
		it->bio = it->bio->bi_next;
		it->iter = it->bio->bi_iter;
		if (cursor->resid < it->iter.bi_size)
			it->iter.bi_size = cursor->resid;
	}

	BUG_ON(cursor->last_piece);
	BUG_ON(cursor->resid < bio_iter_len(it->bio, it->iter));
	cursor->last_piece = cursor->resid == bio_iter_len(it->bio, it->iter);
	return true;
}


static void ceph_msg_data_bvecs_cursor_init(struct ceph_msg_data_cursor *cursor, size_t length)
{
	struct ceph_msg_data *data = cursor->data;
	struct bio_vec *bvecs = data->bvec_pos.bvecs;

	cursor->resid = min_t(size_t, length, data->bvec_pos.iter.bi_size);
	cursor->bvec_iter = data->bvec_pos.iter;
	cursor->bvec_iter.bi_size = cursor->resid;

	BUG_ON(cursor->resid < bvec_iter_len(bvecs, cursor->bvec_iter));
	cursor->last_piece = cursor->resid == bvec_iter_len(bvecs, cursor->bvec_iter);
}

static struct page *ceph_msg_data_bvecs_next(struct ceph_msg_data_cursor *cursor, size_t *page_offset, size_t *length)

{
	struct bio_vec bv = bvec_iter_bvec(cursor->data->bvec_pos.bvecs, cursor->bvec_iter);

	*page_offset = bv.bv_offset;
	*length = bv.bv_len;
	return bv.bv_page;
}

static bool ceph_msg_data_bvecs_advance(struct ceph_msg_data_cursor *cursor, size_t bytes)
{
	struct bio_vec *bvecs = cursor->data->bvec_pos.bvecs;

	BUG_ON(bytes > cursor->resid);
	BUG_ON(bytes > bvec_iter_len(bvecs, cursor->bvec_iter));
	cursor->resid -= bytes;
	bvec_iter_advance(bvecs, &cursor->bvec_iter, bytes);

	if (!cursor->resid) {
		BUG_ON(!cursor->last_piece);
		return false;   
	}

	if (!bytes || cursor->bvec_iter.bi_bvec_done)
		return false;	

	BUG_ON(cursor->last_piece);
	BUG_ON(cursor->resid < bvec_iter_len(bvecs, cursor->bvec_iter));
	cursor->last_piece = cursor->resid == bvec_iter_len(bvecs, cursor->bvec_iter);
	return true;
}


static void ceph_msg_data_pages_cursor_init(struct ceph_msg_data_cursor *cursor, size_t length)
{
	struct ceph_msg_data *data = cursor->data;
	int page_count;

	BUG_ON(data->type != CEPH_MSG_DATA_PAGES);

	BUG_ON(!data->pages);
	BUG_ON(!data->length);

	cursor->resid = min(length, data->length);
	page_count = calc_pages_for(data->alignment, (u64)data->length);
	cursor->page_offset = data->alignment & ~PAGE_MASK;
	cursor->page_index = 0;
	BUG_ON(page_count > (int)USHRT_MAX);
	cursor->page_count = (unsigned short)page_count;
	BUG_ON(length > SIZE_MAX - cursor->page_offset);
	cursor->last_piece = cursor->page_offset + cursor->resid <= PAGE_SIZE;
}

static struct page * ceph_msg_data_pages_next(struct ceph_msg_data_cursor *cursor, size_t *page_offset, size_t *length)

{
	struct ceph_msg_data *data = cursor->data;

	BUG_ON(data->type != CEPH_MSG_DATA_PAGES);

	BUG_ON(cursor->page_index >= cursor->page_count);
	BUG_ON(cursor->page_offset >= PAGE_SIZE);

	*page_offset = cursor->page_offset;
	if (cursor->last_piece)
		*length = cursor->resid;
	else *length = PAGE_SIZE - *page_offset;

	return data->pages[cursor->page_index];
}

static bool ceph_msg_data_pages_advance(struct ceph_msg_data_cursor *cursor, size_t bytes)
{
	BUG_ON(cursor->data->type != CEPH_MSG_DATA_PAGES);

	BUG_ON(cursor->page_offset + bytes > PAGE_SIZE);

	

	cursor->resid -= bytes;
	cursor->page_offset = (cursor->page_offset + bytes) & ~PAGE_MASK;
	if (!bytes || cursor->page_offset)
		return false;	

	if (!cursor->resid)
		return false;   

	

	BUG_ON(cursor->page_index >= cursor->page_count);
	cursor->page_index++;
	cursor->last_piece = cursor->resid <= PAGE_SIZE;

	return true;
}


static void ceph_msg_data_pagelist_cursor_init(struct ceph_msg_data_cursor *cursor, size_t length)

{
	struct ceph_msg_data *data = cursor->data;
	struct ceph_pagelist *pagelist;
	struct page *page;

	BUG_ON(data->type != CEPH_MSG_DATA_PAGELIST);

	pagelist = data->pagelist;
	BUG_ON(!pagelist);

	if (!length)
		return;		

	BUG_ON(list_empty(&pagelist->head));
	page = list_first_entry(&pagelist->head, struct page, lru);

	cursor->resid = min(length, pagelist->length);
	cursor->page = page;
	cursor->offset = 0;
	cursor->last_piece = cursor->resid <= PAGE_SIZE;
}

static struct page * ceph_msg_data_pagelist_next(struct ceph_msg_data_cursor *cursor, size_t *page_offset, size_t *length)

{
	struct ceph_msg_data *data = cursor->data;
	struct ceph_pagelist *pagelist;

	BUG_ON(data->type != CEPH_MSG_DATA_PAGELIST);

	pagelist = data->pagelist;
	BUG_ON(!pagelist);

	BUG_ON(!cursor->page);
	BUG_ON(cursor->offset + cursor->resid != pagelist->length);

	
	*page_offset = cursor->offset & ~PAGE_MASK;
	if (cursor->last_piece)
		*length = cursor->resid;
	else *length = PAGE_SIZE - *page_offset;

	return cursor->page;
}

static bool ceph_msg_data_pagelist_advance(struct ceph_msg_data_cursor *cursor, size_t bytes)
{
	struct ceph_msg_data *data = cursor->data;
	struct ceph_pagelist *pagelist;

	BUG_ON(data->type != CEPH_MSG_DATA_PAGELIST);

	pagelist = data->pagelist;
	BUG_ON(!pagelist);

	BUG_ON(cursor->offset + cursor->resid != pagelist->length);
	BUG_ON((cursor->offset & ~PAGE_MASK) + bytes > PAGE_SIZE);

	

	cursor->resid -= bytes;
	cursor->offset += bytes;
	
	if (!bytes || cursor->offset & ~PAGE_MASK)
		return false;	

	if (!cursor->resid)
		return false;   

	

	BUG_ON(list_is_last(&cursor->page->lru, &pagelist->head));
	cursor->page = list_next_entry(cursor->page, lru);
	cursor->last_piece = cursor->resid <= PAGE_SIZE;

	return true;
}


static void __ceph_msg_data_cursor_init(struct ceph_msg_data_cursor *cursor)
{
	size_t length = cursor->total_resid;

	switch (cursor->data->type) {
	case CEPH_MSG_DATA_PAGELIST:
		ceph_msg_data_pagelist_cursor_init(cursor, length);
		break;
	case CEPH_MSG_DATA_PAGES:
		ceph_msg_data_pages_cursor_init(cursor, length);
		break;

	case CEPH_MSG_DATA_BIO:
		ceph_msg_data_bio_cursor_init(cursor, length);
		break;

	case CEPH_MSG_DATA_BVECS:
		ceph_msg_data_bvecs_cursor_init(cursor, length);
		break;
	case CEPH_MSG_DATA_NONE:
	default:
		
		break;
	}
	cursor->need_crc = true;
}

static void ceph_msg_data_cursor_init(struct ceph_msg *msg, size_t length)
{
	struct ceph_msg_data_cursor *cursor = &msg->cursor;
	struct ceph_msg_data *data;

	BUG_ON(!length);
	BUG_ON(length > msg->data_length);
	BUG_ON(list_empty(&msg->data));

	cursor->data_head = &msg->data;
	cursor->total_resid = length;
	data = list_first_entry(&msg->data, struct ceph_msg_data, links);
	cursor->data = data;

	__ceph_msg_data_cursor_init(cursor);
}


static struct page *ceph_msg_data_next(struct ceph_msg_data_cursor *cursor, size_t *page_offset, size_t *length, bool *last_piece)

{
	struct page *page;

	switch (cursor->data->type) {
	case CEPH_MSG_DATA_PAGELIST:
		page = ceph_msg_data_pagelist_next(cursor, page_offset, length);
		break;
	case CEPH_MSG_DATA_PAGES:
		page = ceph_msg_data_pages_next(cursor, page_offset, length);
		break;

	case CEPH_MSG_DATA_BIO:
		page = ceph_msg_data_bio_next(cursor, page_offset, length);
		break;

	case CEPH_MSG_DATA_BVECS:
		page = ceph_msg_data_bvecs_next(cursor, page_offset, length);
		break;
	case CEPH_MSG_DATA_NONE:
	default:
		page = NULL;
		break;
	}

	BUG_ON(!page);
	BUG_ON(*page_offset + *length > PAGE_SIZE);
	BUG_ON(!*length);
	BUG_ON(*length > cursor->resid);
	if (last_piece)
		*last_piece = cursor->last_piece;

	return page;
}


static void ceph_msg_data_advance(struct ceph_msg_data_cursor *cursor, size_t bytes)
{
	bool new_piece;

	BUG_ON(bytes > cursor->resid);
	switch (cursor->data->type) {
	case CEPH_MSG_DATA_PAGELIST:
		new_piece = ceph_msg_data_pagelist_advance(cursor, bytes);
		break;
	case CEPH_MSG_DATA_PAGES:
		new_piece = ceph_msg_data_pages_advance(cursor, bytes);
		break;

	case CEPH_MSG_DATA_BIO:
		new_piece = ceph_msg_data_bio_advance(cursor, bytes);
		break;

	case CEPH_MSG_DATA_BVECS:
		new_piece = ceph_msg_data_bvecs_advance(cursor, bytes);
		break;
	case CEPH_MSG_DATA_NONE:
	default:
		BUG();
		break;
	}
	cursor->total_resid -= bytes;

	if (!cursor->resid && cursor->total_resid) {
		WARN_ON(!cursor->last_piece);
		BUG_ON(list_is_last(&cursor->data->links, cursor->data_head));
		cursor->data = list_next_entry(cursor->data, links);
		__ceph_msg_data_cursor_init(cursor);
		new_piece = true;
	}
	cursor->need_crc = new_piece;
}

static size_t sizeof_footer(struct ceph_connection *con)
{
	return (con->peer_features & CEPH_FEATURE_MSG_AUTH) ? sizeof(struct ceph_msg_footer) :
	    sizeof(struct ceph_msg_footer_old);
}

static void prepare_message_data(struct ceph_msg *msg, u32 data_len)
{
	BUG_ON(!msg);
	BUG_ON(!data_len);

	

	ceph_msg_data_cursor_init(msg, (size_t)data_len);
}


static void prepare_write_message_footer(struct ceph_connection *con)
{
	struct ceph_msg *m = con->out_msg;

	m->footer.flags |= CEPH_MSG_FOOTER_COMPLETE;

	dout("prepare_write_message_footer %p\n", con);
	con_out_kvec_add(con, sizeof_footer(con), &m->footer);
	if (con->peer_features & CEPH_FEATURE_MSG_AUTH) {
		if (con->ops->sign_message)
			con->ops->sign_message(m);
		else m->footer.sig = 0;
	} else {
		m->old_footer.flags = m->footer.flags;
	}
	con->out_more = m->more_to_follow;
	con->out_msg_done = true;
}


static void prepare_write_message(struct ceph_connection *con)
{
	struct ceph_msg *m;
	u32 crc;

	con_out_kvec_reset(con);
	con->out_msg_done = false;

	
	if (con->in_seq > con->in_seq_acked) {
		con->in_seq_acked = con->in_seq;
		con_out_kvec_add(con, sizeof (tag_ack), &tag_ack);
		con->out_temp_ack = cpu_to_le64(con->in_seq_acked);
		con_out_kvec_add(con, sizeof (con->out_temp_ack), &con->out_temp_ack);
	}

	BUG_ON(list_empty(&con->out_queue));
	m = list_first_entry(&con->out_queue, struct ceph_msg, list_head);
	con->out_msg = m;
	BUG_ON(m->con != con);

	
	ceph_msg_get(m);
	list_move_tail(&m->list_head, &con->out_sent);

	
	if (m->needs_out_seq) {
		m->hdr.seq = cpu_to_le64(++con->out_seq);
		m->needs_out_seq = false;

		if (con->ops->reencode_message)
			con->ops->reencode_message(m);
	}

	dout("prepare_write_message %p seq %lld type %d len %d+%d+%zd\n", m, con->out_seq, le16_to_cpu(m->hdr.type), le32_to_cpu(m->hdr.front_len), le32_to_cpu(m->hdr.middle_len), m->data_length);


	WARN_ON(m->front.iov_len != le32_to_cpu(m->hdr.front_len));
	WARN_ON(m->data_length != le32_to_cpu(m->hdr.data_len));

	
	con_out_kvec_add(con, sizeof (tag_msg), &tag_msg);
	con_out_kvec_add(con, sizeof(con->out_hdr), &con->out_hdr);
	con_out_kvec_add(con, m->front.iov_len, m->front.iov_base);

	if (m->middle)
		con_out_kvec_add(con, m->middle->vec.iov_len, m->middle->vec.iov_base);

	
	crc = crc32c(0, &m->hdr, offsetof(struct ceph_msg_header, crc));
	con->out_msg->hdr.crc = cpu_to_le32(crc);
	memcpy(&con->out_hdr, &con->out_msg->hdr, sizeof(con->out_hdr));

	
	crc = crc32c(0, m->front.iov_base, m->front.iov_len);
	con->out_msg->footer.front_crc = cpu_to_le32(crc);
	if (m->middle) {
		crc = crc32c(0, m->middle->vec.iov_base, m->middle->vec.iov_len);
		con->out_msg->footer.middle_crc = cpu_to_le32(crc);
	} else con->out_msg->footer.middle_crc = 0;
	dout("%s front_crc %u middle_crc %u\n", __func__, le32_to_cpu(con->out_msg->footer.front_crc), le32_to_cpu(con->out_msg->footer.middle_crc));

	con->out_msg->footer.flags = 0;

	
	con->out_msg->footer.data_crc = 0;
	if (m->data_length) {
		prepare_message_data(con->out_msg, m->data_length);
		con->out_more = 1;  
	} else {
		
		prepare_write_message_footer(con);
	}

	con_flag_set(con, CON_FLAG_WRITE_PENDING);
}


static void prepare_write_ack(struct ceph_connection *con)
{
	dout("prepare_write_ack %p %llu -> %llu\n", con, con->in_seq_acked, con->in_seq);
	con->in_seq_acked = con->in_seq;

	con_out_kvec_reset(con);

	con_out_kvec_add(con, sizeof (tag_ack), &tag_ack);

	con->out_temp_ack = cpu_to_le64(con->in_seq_acked);
	con_out_kvec_add(con, sizeof (con->out_temp_ack), &con->out_temp_ack);

	con->out_more = 1;  
	con_flag_set(con, CON_FLAG_WRITE_PENDING);
}


static void prepare_write_seq(struct ceph_connection *con)
{
	dout("prepare_write_seq %p %llu -> %llu\n", con, con->in_seq_acked, con->in_seq);
	con->in_seq_acked = con->in_seq;

	con_out_kvec_reset(con);

	con->out_temp_ack = cpu_to_le64(con->in_seq_acked);
	con_out_kvec_add(con, sizeof (con->out_temp_ack), &con->out_temp_ack);

	con_flag_set(con, CON_FLAG_WRITE_PENDING);
}


static void prepare_write_keepalive(struct ceph_connection *con)
{
	dout("prepare_write_keepalive %p\n", con);
	con_out_kvec_reset(con);
	if (con->peer_features & CEPH_FEATURE_MSGR_KEEPALIVE2) {
		struct timespec64 now;

		ktime_get_real_ts64(&now);
		con_out_kvec_add(con, sizeof(tag_keepalive2), &tag_keepalive2);
		ceph_encode_timespec64(&con->out_temp_keepalive2, &now);
		con_out_kvec_add(con, sizeof(con->out_temp_keepalive2), &con->out_temp_keepalive2);
	} else {
		con_out_kvec_add(con, sizeof(tag_keepalive), &tag_keepalive);
	}
	con_flag_set(con, CON_FLAG_WRITE_PENDING);
}



static int get_connect_authorizer(struct ceph_connection *con)
{
	struct ceph_auth_handshake *auth;
	int auth_proto;

	if (!con->ops->get_authorizer) {
		con->auth = NULL;
		con->out_connect.authorizer_protocol = CEPH_AUTH_UNKNOWN;
		con->out_connect.authorizer_len = 0;
		return 0;
	}

	auth = con->ops->get_authorizer(con, &auth_proto, con->auth_retry);
	if (IS_ERR(auth))
		return PTR_ERR(auth);

	con->auth = auth;
	con->out_connect.authorizer_protocol = cpu_to_le32(auth_proto);
	con->out_connect.authorizer_len = cpu_to_le32(auth->authorizer_buf_len);
	return 0;
}


static void prepare_write_banner(struct ceph_connection *con)
{
	con_out_kvec_add(con, strlen(CEPH_BANNER), CEPH_BANNER);
	con_out_kvec_add(con, sizeof (con->msgr->my_enc_addr), &con->msgr->my_enc_addr);

	con->out_more = 0;
	con_flag_set(con, CON_FLAG_WRITE_PENDING);
}

static void __prepare_write_connect(struct ceph_connection *con)
{
	con_out_kvec_add(con, sizeof(con->out_connect), &con->out_connect);
	if (con->auth)
		con_out_kvec_add(con, con->auth->authorizer_buf_len, con->auth->authorizer_buf);

	con->out_more = 0;
	con_flag_set(con, CON_FLAG_WRITE_PENDING);
}

static int prepare_write_connect(struct ceph_connection *con)
{
	unsigned int global_seq = get_global_seq(con->msgr, 0);
	int proto;
	int ret;

	switch (con->peer_name.type) {
	case CEPH_ENTITY_TYPE_MON:
		proto = CEPH_MONC_PROTOCOL;
		break;
	case CEPH_ENTITY_TYPE_OSD:
		proto = CEPH_OSDC_PROTOCOL;
		break;
	case CEPH_ENTITY_TYPE_MDS:
		proto = CEPH_MDSC_PROTOCOL;
		break;
	default:
		BUG();
	}

	dout("prepare_write_connect %p cseq=%d gseq=%d proto=%d\n", con, con->connect_seq, global_seq, proto);

	con->out_connect.features = cpu_to_le64(from_msgr(con->msgr)->supported_features);
	con->out_connect.host_type = cpu_to_le32(CEPH_ENTITY_TYPE_CLIENT);
	con->out_connect.connect_seq = cpu_to_le32(con->connect_seq);
	con->out_connect.global_seq = cpu_to_le32(global_seq);
	con->out_connect.protocol_version = cpu_to_le32(proto);
	con->out_connect.flags = 0;

	ret = get_connect_authorizer(con);
	if (ret)
		return ret;

	__prepare_write_connect(con);
	return 0;
}


static int write_partial_kvec(struct ceph_connection *con)
{
	int ret;

	dout("write_partial_kvec %p %d left\n", con, con->out_kvec_bytes);
	while (con->out_kvec_bytes > 0) {
		ret = ceph_tcp_sendmsg(con->sock, con->out_kvec_cur, con->out_kvec_left, con->out_kvec_bytes, con->out_more);

		if (ret <= 0)
			goto out;
		con->out_kvec_bytes -= ret;
		if (con->out_kvec_bytes == 0)
			break;            

		
		while (ret >= con->out_kvec_cur->iov_len) {
			BUG_ON(!con->out_kvec_left);
			ret -= con->out_kvec_cur->iov_len;
			con->out_kvec_cur++;
			con->out_kvec_left--;
		}
		
		if (ret) {
			con->out_kvec_cur->iov_len -= ret;
			con->out_kvec_cur->iov_base += ret;
		}
	}
	con->out_kvec_left = 0;
	ret = 1;
out:
	dout("write_partial_kvec %p %d left in %d kvecs ret = %d\n", con, con->out_kvec_bytes, con->out_kvec_left, ret);
	return ret;  
}

static u32 ceph_crc32c_page(u32 crc, struct page *page, unsigned int page_offset, unsigned int length)

{
	char *kaddr;

	kaddr = kmap(page);
	BUG_ON(kaddr == NULL);
	crc = crc32c(crc, kaddr + page_offset, length);
	kunmap(page);

	return crc;
}

static int write_partial_message_data(struct ceph_connection *con)
{
	struct ceph_msg *msg = con->out_msg;
	struct ceph_msg_data_cursor *cursor = &msg->cursor;
	bool do_datacrc = !ceph_test_opt(from_msgr(con->msgr), NOCRC);
	u32 crc;

	dout("%s %p msg %p\n", __func__, con, msg);

	if (list_empty(&msg->data))
		return -EINVAL;

	
	crc = do_datacrc ? le32_to_cpu(msg->footer.data_crc) : 0;
	while (cursor->total_resid) {
		struct page *page;
		size_t page_offset;
		size_t length;
		bool last_piece;
		int ret;

		if (!cursor->resid) {
			ceph_msg_data_advance(cursor, 0);
			continue;
		}

		page = ceph_msg_data_next(cursor, &page_offset, &length, &last_piece);
		ret = ceph_tcp_sendpage(con->sock, page, page_offset, length, !last_piece);
		if (ret <= 0) {
			if (do_datacrc)
				msg->footer.data_crc = cpu_to_le32(crc);

			return ret;
		}
		if (do_datacrc && cursor->need_crc)
			crc = ceph_crc32c_page(crc, page, page_offset, length);
		ceph_msg_data_advance(cursor, (size_t)ret);
	}

	dout("%s %p msg %p done\n", __func__, con, msg);

	
	if (do_datacrc)
		msg->footer.data_crc = cpu_to_le32(crc);
	else msg->footer.flags |= CEPH_MSG_FOOTER_NOCRC;
	con_out_kvec_reset(con);
	prepare_write_message_footer(con);

	return 1;	
}


static int write_partial_skip(struct ceph_connection *con)
{
	int ret;

	dout("%s %p %d left\n", __func__, con, con->out_skip);
	while (con->out_skip > 0) {
		size_t size = min(con->out_skip, (int) PAGE_SIZE);

		ret = ceph_tcp_sendpage(con->sock, zero_page, 0, size, true);
		if (ret <= 0)
			goto out;
		con->out_skip -= ret;
	}
	ret = 1;
out:
	return ret;
}


static void prepare_read_banner(struct ceph_connection *con)
{
	dout("prepare_read_banner %p\n", con);
	con->in_base_pos = 0;
}

static void prepare_read_connect(struct ceph_connection *con)
{
	dout("prepare_read_connect %p\n", con);
	con->in_base_pos = 0;
}

static void prepare_read_ack(struct ceph_connection *con)
{
	dout("prepare_read_ack %p\n", con);
	con->in_base_pos = 0;
}

static void prepare_read_seq(struct ceph_connection *con)
{
	dout("prepare_read_seq %p\n", con);
	con->in_base_pos = 0;
	con->in_tag = CEPH_MSGR_TAG_SEQ;
}

static void prepare_read_tag(struct ceph_connection *con)
{
	dout("prepare_read_tag %p\n", con);
	con->in_base_pos = 0;
	con->in_tag = CEPH_MSGR_TAG_READY;
}

static void prepare_read_keepalive_ack(struct ceph_connection *con)
{
	dout("prepare_read_keepalive_ack %p\n", con);
	con->in_base_pos = 0;
}


static int prepare_read_message(struct ceph_connection *con)
{
	dout("prepare_read_message %p\n", con);
	BUG_ON(con->in_msg != NULL);
	con->in_base_pos = 0;
	con->in_front_crc = con->in_middle_crc = con->in_data_crc = 0;
	return 0;
}


static int read_partial(struct ceph_connection *con, int end, int size, void *object)
{
	while (con->in_base_pos < end) {
		int left = end - con->in_base_pos;
		int have = size - left;
		int ret = ceph_tcp_recvmsg(con->sock, object + have, left);
		if (ret <= 0)
			return ret;
		con->in_base_pos += ret;
	}
	return 1;
}



static int read_partial_banner(struct ceph_connection *con)
{
	int size;
	int end;
	int ret;

	dout("read_partial_banner %p at %d\n", con, con->in_base_pos);

	
	size = strlen(CEPH_BANNER);
	end = size;
	ret = read_partial(con, end, size, con->in_banner);
	if (ret <= 0)
		goto out;

	size = sizeof (con->actual_peer_addr);
	end += size;
	ret = read_partial(con, end, size, &con->actual_peer_addr);
	if (ret <= 0)
		goto out;

	size = sizeof (con->peer_addr_for_me);
	end += size;
	ret = read_partial(con, end, size, &con->peer_addr_for_me);
	if (ret <= 0)
		goto out;

out:
	return ret;
}

static int read_partial_connect(struct ceph_connection *con)
{
	int size;
	int end;
	int ret;

	dout("read_partial_connect %p at %d\n", con, con->in_base_pos);

	size = sizeof (con->in_reply);
	end = size;
	ret = read_partial(con, end, size, &con->in_reply);
	if (ret <= 0)
		goto out;

	if (con->auth) {
		size = le32_to_cpu(con->in_reply.authorizer_len);
		end += size;
		ret = read_partial(con, end, size, con->auth->authorizer_reply_buf);
		if (ret <= 0)
			goto out;
	}

	dout("read_partial_connect %p tag %d, con_seq = %u, g_seq = %u\n", con, (int)con->in_reply.tag, le32_to_cpu(con->in_reply.connect_seq), le32_to_cpu(con->in_reply.global_seq));


out:
	return ret;
}


static int verify_hello(struct ceph_connection *con)
{
	if (memcmp(con->in_banner, CEPH_BANNER, strlen(CEPH_BANNER))) {
		pr_err("connect to %s got bad banner\n", ceph_pr_addr(&con->peer_addr.in_addr));
		con->error_msg = "protocol error, bad banner";
		return -1;
	}
	return 0;
}

static bool addr_is_blank(struct sockaddr_storage *ss)
{
	struct in_addr *addr = &((struct sockaddr_in *)ss)->sin_addr;
	struct in6_addr *addr6 = &((struct sockaddr_in6 *)ss)->sin6_addr;

	switch (ss->ss_family) {
	case AF_INET:
		return addr->s_addr == htonl(INADDR_ANY);
	case AF_INET6:
		return ipv6_addr_any(addr6);
	default:
		return true;
	}
}

static int addr_port(struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)ss)->sin_port);
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)ss)->sin6_port);
	}
	return 0;
}

static void addr_set_port(struct sockaddr_storage *ss, int p)
{
	switch (ss->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)ss)->sin_port = htons(p);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)ss)->sin6_port = htons(p);
		break;
	}
}


static int ceph_pton(const char *str, size_t len, struct sockaddr_storage *ss, char delim, const char **ipend)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *) ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) ss;

	memset(ss, 0, sizeof(*ss));

	if (in4_pton(str, len, (u8 *)&in4->sin_addr.s_addr, delim, ipend)) {
		ss->ss_family = AF_INET;
		return 0;
	}

	if (in6_pton(str, len, (u8 *)&in6->sin6_addr.s6_addr, delim, ipend)) {
		ss->ss_family = AF_INET6;
		return 0;
	}

	return -EINVAL;
}



static int ceph_dns_resolve_name(const char *name, size_t namelen, struct sockaddr_storage *ss, char delim, const char **ipend)
{
	const char *end, *delim_p;
	char *colon_p, *ip_addr = NULL;
	int ip_len, ret;

	
	delim_p = memchr(name, delim, namelen);
	colon_p = memchr(name, ':', namelen);

	if (delim_p && colon_p)
		end = delim_p < colon_p ? delim_p : colon_p;
	else if (!delim_p && colon_p)
		end = colon_p;
	else {
		end = delim_p;
		if (!end) 
			end = name + namelen;
	}

	if (end <= name)
		return -EINVAL;

	
	ip_len = dns_query(NULL, name, end - name, NULL, &ip_addr, NULL);
	if (ip_len > 0)
		ret = ceph_pton(ip_addr, ip_len, ss, -1, NULL);
	else ret = -ESRCH;

	kfree(ip_addr);

	*ipend = end;

	pr_info("resolve '%.*s' (ret=%d): %s\n", (int)(end - name), name, ret, ret ? "failed" : ceph_pr_addr(ss));

	return ret;
}

static inline int ceph_dns_resolve_name(const char *name, size_t namelen, struct sockaddr_storage *ss, char delim, const char **ipend)
{
	return -EINVAL;
}



static int ceph_parse_server_name(const char *name, size_t namelen, struct sockaddr_storage *ss, char delim, const char **ipend)
{
	int ret;

	ret = ceph_pton(name, namelen, ss, delim, ipend);
	if (ret)
		ret = ceph_dns_resolve_name(name, namelen, ss, delim, ipend);

	return ret;
}


int ceph_parse_ips(const char *c, const char *end, struct ceph_entity_addr *addr, int max_count, int *count)

{
	int i, ret = -EINVAL;
	const char *p = c;

	dout("parse_ips on '%.*s'\n", (int)(end-c), c);
	for (i = 0; i < max_count; i++) {
		const char *ipend;
		struct sockaddr_storage *ss = &addr[i].in_addr;
		int port;
		char delim = ',';

		if (*p == '[') {
			delim = ']';
			p++;
		}

		ret = ceph_parse_server_name(p, end - p, ss, delim, &ipend);
		if (ret)
			goto bad;
		ret = -EINVAL;

		p = ipend;

		if (delim == ']') {
			if (*p != ']') {
				dout("missing matching ']'\n");
				goto bad;
			}
			p++;
		}

		
		if (p < end && *p == ':') {
			port = 0;
			p++;
			while (p < end && *p >= '0' && *p <= '9') {
				port = (port * 10) + (*p - '0');
				p++;
			}
			if (port == 0)
				port = CEPH_MON_PORT;
			else if (port > 65535)
				goto bad;
		} else {
			port = CEPH_MON_PORT;
		}

		addr_set_port(ss, port);

		dout("parse_ips got %s\n", ceph_pr_addr(ss));

		if (p == end)
			break;
		if (*p != ',')
			goto bad;
		p++;
	}

	if (p != end)
		goto bad;

	if (count)
		*count = i + 1;
	return 0;

bad:
	pr_err("parse_ips bad ip '%.*s'\n", (int)(end - c), c);
	return ret;
}
EXPORT_SYMBOL(ceph_parse_ips);

static int process_banner(struct ceph_connection *con)
{
	dout("process_banner on %p\n", con);

	if (verify_hello(con) < 0)
		return -1;

	ceph_decode_addr(&con->actual_peer_addr);
	ceph_decode_addr(&con->peer_addr_for_me);

	
	if (memcmp(&con->peer_addr, &con->actual_peer_addr, sizeof(con->peer_addr)) != 0 && !(addr_is_blank(&con->actual_peer_addr.in_addr) && con->actual_peer_addr.nonce == con->peer_addr.nonce)) {


		pr_warn("wrong peer, want %s/%d, got %s/%d\n", ceph_pr_addr(&con->peer_addr.in_addr), (int)le32_to_cpu(con->peer_addr.nonce), ceph_pr_addr(&con->actual_peer_addr.in_addr), (int)le32_to_cpu(con->actual_peer_addr.nonce));



		con->error_msg = "wrong peer at address";
		return -1;
	}

	
	if (addr_is_blank(&con->msgr->inst.addr.in_addr)) {
		int port = addr_port(&con->msgr->inst.addr.in_addr);

		memcpy(&con->msgr->inst.addr.in_addr, &con->peer_addr_for_me.in_addr, sizeof(con->peer_addr_for_me.in_addr));

		addr_set_port(&con->msgr->inst.addr.in_addr, port);
		encode_my_addr(con->msgr);
		dout("process_banner learned my addr is %s\n", ceph_pr_addr(&con->msgr->inst.addr.in_addr));
	}

	return 0;
}

static int process_connect(struct ceph_connection *con)
{
	u64 sup_feat = from_msgr(con->msgr)->supported_features;
	u64 req_feat = from_msgr(con->msgr)->required_features;
	u64 server_feat = le64_to_cpu(con->in_reply.features);
	int ret;

	dout("process_connect on %p tag %d\n", con, (int)con->in_tag);

	if (con->auth) {
		
		ret = con->ops->verify_authorizer_reply(con);
		if (ret < 0) {
			con->error_msg = "bad authorize reply";
			return ret;
		}
	}

	switch (con->in_reply.tag) {
	case CEPH_MSGR_TAG_FEATURES:
		pr_err("%s%lld %s feature set mismatch," " my %llx < server's %llx, missing %llx\n", ENTITY_NAME(con->peer_name), ceph_pr_addr(&con->peer_addr.in_addr), sup_feat, server_feat, server_feat & ~sup_feat);



		con->error_msg = "missing required protocol features";
		reset_connection(con);
		return -1;

	case CEPH_MSGR_TAG_BADPROTOVER:
		pr_err("%s%lld %s protocol version mismatch," " my %d != server's %d\n", ENTITY_NAME(con->peer_name), ceph_pr_addr(&con->peer_addr.in_addr), le32_to_cpu(con->out_connect.protocol_version), le32_to_cpu(con->in_reply.protocol_version));




		con->error_msg = "protocol version mismatch";
		reset_connection(con);
		return -1;

	case CEPH_MSGR_TAG_BADAUTHORIZER:
		con->auth_retry++;
		dout("process_connect %p got BADAUTHORIZER attempt %d\n", con, con->auth_retry);
		if (con->auth_retry == 2) {
			con->error_msg = "connect authorization failure";
			return -1;
		}
		con_out_kvec_reset(con);
		ret = prepare_write_connect(con);
		if (ret < 0)
			return ret;
		prepare_read_connect(con);
		break;

	case CEPH_MSGR_TAG_RESETSESSION:
		
		dout("process_connect got RESET peer seq %u\n", le32_to_cpu(con->in_reply.connect_seq));
		pr_err("%s%lld %s connection reset\n", ENTITY_NAME(con->peer_name), ceph_pr_addr(&con->peer_addr.in_addr));

		reset_connection(con);
		con_out_kvec_reset(con);
		ret = prepare_write_connect(con);
		if (ret < 0)
			return ret;
		prepare_read_connect(con);

		
		mutex_unlock(&con->mutex);
		pr_info("reset on %s%lld\n", ENTITY_NAME(con->peer_name));
		if (con->ops->peer_reset)
			con->ops->peer_reset(con);
		mutex_lock(&con->mutex);
		if (con->state != CON_STATE_NEGOTIATING)
			return -EAGAIN;
		break;

	case CEPH_MSGR_TAG_RETRY_SESSION:
		
		dout("process_connect got RETRY_SESSION my seq %u, peer %u\n", le32_to_cpu(con->out_connect.connect_seq), le32_to_cpu(con->in_reply.connect_seq));

		con->connect_seq = le32_to_cpu(con->in_reply.connect_seq);
		con_out_kvec_reset(con);
		ret = prepare_write_connect(con);
		if (ret < 0)
			return ret;
		prepare_read_connect(con);
		break;

	case CEPH_MSGR_TAG_RETRY_GLOBAL:
		
		dout("process_connect got RETRY_GLOBAL my %u peer_gseq %u\n", con->peer_global_seq, le32_to_cpu(con->in_reply.global_seq));

		get_global_seq(con->msgr, le32_to_cpu(con->in_reply.global_seq));
		con_out_kvec_reset(con);
		ret = prepare_write_connect(con);
		if (ret < 0)
			return ret;
		prepare_read_connect(con);
		break;

	case CEPH_MSGR_TAG_SEQ:
	case CEPH_MSGR_TAG_READY:
		if (req_feat & ~server_feat) {
			pr_err("%s%lld %s protocol feature mismatch," " my required %llx > server's %llx, need %llx\n", ENTITY_NAME(con->peer_name), ceph_pr_addr(&con->peer_addr.in_addr), req_feat, server_feat, req_feat & ~server_feat);



			con->error_msg = "missing required protocol features";
			reset_connection(con);
			return -1;
		}

		WARN_ON(con->state != CON_STATE_NEGOTIATING);
		con->state = CON_STATE_OPEN;
		con->auth_retry = 0;    
		con->peer_global_seq = le32_to_cpu(con->in_reply.global_seq);
		con->connect_seq++;
		con->peer_features = server_feat;
		dout("process_connect got READY gseq %d cseq %d (%d)\n", con->peer_global_seq, le32_to_cpu(con->in_reply.connect_seq), con->connect_seq);


		WARN_ON(con->connect_seq != le32_to_cpu(con->in_reply.connect_seq));

		if (con->in_reply.flags & CEPH_MSG_CONNECT_LOSSY)
			con_flag_set(con, CON_FLAG_LOSSYTX);

		con->delay = 0;      

		if (con->in_reply.tag == CEPH_MSGR_TAG_SEQ) {
			prepare_write_seq(con);
			prepare_read_seq(con);
		} else {
			prepare_read_tag(con);
		}
		break;

	case CEPH_MSGR_TAG_WAIT:
		
		con->error_msg = "protocol error, got WAIT as client";
		return -1;

	default:
		con->error_msg = "protocol error, garbage tag during connect";
		return -1;
	}
	return 0;
}



static int read_partial_ack(struct ceph_connection *con)
{
	int size = sizeof (con->in_temp_ack);
	int end = size;

	return read_partial(con, end, size, &con->in_temp_ack);
}


static void process_ack(struct ceph_connection *con)
{
	struct ceph_msg *m;
	u64 ack = le64_to_cpu(con->in_temp_ack);
	u64 seq;
	bool reconnect = (con->in_tag == CEPH_MSGR_TAG_SEQ);
	struct list_head *list = reconnect ? &con->out_queue : &con->out_sent;

	
	while (!list_empty(list)) {
		m = list_first_entry(list, struct ceph_msg, list_head);
		if (reconnect && m->needs_out_seq)
			break;
		seq = le64_to_cpu(m->hdr.seq);
		if (seq > ack)
			break;
		dout("got ack for seq %llu type %d at %p\n", seq, le16_to_cpu(m->hdr.type), m);
		m->ack_stamp = jiffies;
		ceph_msg_remove(m);
	}

	prepare_read_tag(con);
}


static int read_partial_message_section(struct ceph_connection *con, struct kvec *section, unsigned int sec_len, u32 *crc)

{
	int ret, left;

	BUG_ON(!section);

	while (section->iov_len < sec_len) {
		BUG_ON(section->iov_base == NULL);
		left = sec_len - section->iov_len;
		ret = ceph_tcp_recvmsg(con->sock, (char *)section->iov_base + section->iov_len, left);
		if (ret <= 0)
			return ret;
		section->iov_len += ret;
	}
	if (section->iov_len == sec_len)
		*crc = crc32c(0, section->iov_base, section->iov_len);

	return 1;
}

static int read_partial_msg_data(struct ceph_connection *con)
{
	struct ceph_msg *msg = con->in_msg;
	struct ceph_msg_data_cursor *cursor = &msg->cursor;
	bool do_datacrc = !ceph_test_opt(from_msgr(con->msgr), NOCRC);
	struct page *page;
	size_t page_offset;
	size_t length;
	u32 crc = 0;
	int ret;

	BUG_ON(!msg);
	if (list_empty(&msg->data))
		return -EIO;

	if (do_datacrc)
		crc = con->in_data_crc;
	while (cursor->total_resid) {
		if (!cursor->resid) {
			ceph_msg_data_advance(cursor, 0);
			continue;
		}

		page = ceph_msg_data_next(cursor, &page_offset, &length, NULL);
		ret = ceph_tcp_recvpage(con->sock, page, page_offset, length);
		if (ret <= 0) {
			if (do_datacrc)
				con->in_data_crc = crc;

			return ret;
		}

		if (do_datacrc)
			crc = ceph_crc32c_page(crc, page, page_offset, ret);
		ceph_msg_data_advance(cursor, (size_t)ret);
	}
	if (do_datacrc)
		con->in_data_crc = crc;

	return 1;	
}


static int ceph_con_in_msg_alloc(struct ceph_connection *con, int *skip);

static int read_partial_message(struct ceph_connection *con)
{
	struct ceph_msg *m = con->in_msg;
	int size;
	int end;
	int ret;
	unsigned int front_len, middle_len, data_len;
	bool do_datacrc = !ceph_test_opt(from_msgr(con->msgr), NOCRC);
	bool need_sign = (con->peer_features & CEPH_FEATURE_MSG_AUTH);
	u64 seq;
	u32 crc;

	dout("read_partial_message con %p msg %p\n", con, m);

	
	size = sizeof (con->in_hdr);
	end = size;
	ret = read_partial(con, end, size, &con->in_hdr);
	if (ret <= 0)
		return ret;

	crc = crc32c(0, &con->in_hdr, offsetof(struct ceph_msg_header, crc));
	if (cpu_to_le32(crc) != con->in_hdr.crc) {
		pr_err("read_partial_message bad hdr crc %u != expected %u\n", crc, con->in_hdr.crc);
		return -EBADMSG;
	}

	front_len = le32_to_cpu(con->in_hdr.front_len);
	if (front_len > CEPH_MSG_MAX_FRONT_LEN)
		return -EIO;
	middle_len = le32_to_cpu(con->in_hdr.middle_len);
	if (middle_len > CEPH_MSG_MAX_MIDDLE_LEN)
		return -EIO;
	data_len = le32_to_cpu(con->in_hdr.data_len);
	if (data_len > CEPH_MSG_MAX_DATA_LEN)
		return -EIO;

	
	seq = le64_to_cpu(con->in_hdr.seq);
	if ((s64)seq - (s64)con->in_seq < 1) {
		pr_info("skipping %s%lld %s seq %lld expected %lld\n", ENTITY_NAME(con->peer_name), ceph_pr_addr(&con->peer_addr.in_addr), seq, con->in_seq + 1);


		con->in_base_pos = -front_len - middle_len - data_len - sizeof_footer(con);
		con->in_tag = CEPH_MSGR_TAG_READY;
		return 1;
	} else if ((s64)seq - (s64)con->in_seq > 1) {
		pr_err("read_partial_message bad seq %lld expected %lld\n", seq, con->in_seq + 1);
		con->error_msg = "bad message sequence # for incoming message";
		return -EBADE;
	}

	
	if (!con->in_msg) {
		int skip = 0;

		dout("got hdr type %d front %d data %d\n", con->in_hdr.type, front_len, data_len);
		ret = ceph_con_in_msg_alloc(con, &skip);
		if (ret < 0)
			return ret;

		BUG_ON(!con->in_msg ^ skip);
		if (skip) {
			
			dout("alloc_msg said skip message\n");
			con->in_base_pos = -front_len - middle_len - data_len - sizeof_footer(con);
			con->in_tag = CEPH_MSGR_TAG_READY;
			con->in_seq++;
			return 1;
		}

		BUG_ON(!con->in_msg);
		BUG_ON(con->in_msg->con != con);
		m = con->in_msg;
		m->front.iov_len = 0;    
		if (m->middle)
			m->middle->vec.iov_len = 0;

		

		if (data_len)
			prepare_message_data(con->in_msg, data_len);
	}

	
	ret = read_partial_message_section(con, &m->front, front_len, &con->in_front_crc);
	if (ret <= 0)
		return ret;

	
	if (m->middle) {
		ret = read_partial_message_section(con, &m->middle->vec, middle_len, &con->in_middle_crc);

		if (ret <= 0)
			return ret;
	}

	
	if (data_len) {
		ret = read_partial_msg_data(con);
		if (ret <= 0)
			return ret;
	}

	
	size = sizeof_footer(con);
	end += size;
	ret = read_partial(con, end, size, &m->footer);
	if (ret <= 0)
		return ret;

	if (!need_sign) {
		m->footer.flags = m->old_footer.flags;
		m->footer.sig = 0;
	}

	dout("read_partial_message got msg %p %d (%u) + %d (%u) + %d (%u)\n", m, front_len, m->footer.front_crc, middle_len, m->footer.middle_crc, data_len, m->footer.data_crc);


	
	if (con->in_front_crc != le32_to_cpu(m->footer.front_crc)) {
		pr_err("read_partial_message %p front crc %u != exp. %u\n", m, con->in_front_crc, m->footer.front_crc);
		return -EBADMSG;
	}
	if (con->in_middle_crc != le32_to_cpu(m->footer.middle_crc)) {
		pr_err("read_partial_message %p middle crc %u != exp %u\n", m, con->in_middle_crc, m->footer.middle_crc);
		return -EBADMSG;
	}
	if (do_datacrc && (m->footer.flags & CEPH_MSG_FOOTER_NOCRC) == 0 && con->in_data_crc != le32_to_cpu(m->footer.data_crc)) {

		pr_err("read_partial_message %p data crc %u != exp. %u\n", m, con->in_data_crc, le32_to_cpu(m->footer.data_crc));
		return -EBADMSG;
	}

	if (need_sign && con->ops->check_message_signature && con->ops->check_message_signature(m)) {
		pr_err("read_partial_message %p signature check failed\n", m);
		return -EBADMSG;
	}

	return 1; 
}


static void process_message(struct ceph_connection *con)
{
	struct ceph_msg *msg = con->in_msg;

	BUG_ON(con->in_msg->con != con);
	con->in_msg = NULL;

	
	if (con->peer_name.type == 0)
		con->peer_name = msg->hdr.src;

	con->in_seq++;
	mutex_unlock(&con->mutex);

	dout("===== %p %llu from %s%lld %d=%s len %d+%d (%u %u %u) =====\n", msg, le64_to_cpu(msg->hdr.seq), ENTITY_NAME(msg->hdr.src), le16_to_cpu(msg->hdr.type), ceph_msg_type_name(le16_to_cpu(msg->hdr.type)), le32_to_cpu(msg->hdr.front_len), le32_to_cpu(msg->hdr.data_len), con->in_front_crc, con->in_middle_crc, con->in_data_crc);






	con->ops->dispatch(con, msg);

	mutex_lock(&con->mutex);
}

static int read_keepalive_ack(struct ceph_connection *con)
{
	struct ceph_timespec ceph_ts;
	size_t size = sizeof(ceph_ts);
	int ret = read_partial(con, size, size, &ceph_ts);
	if (ret <= 0)
		return ret;
	ceph_decode_timespec64(&con->last_keepalive_ack, &ceph_ts);
	prepare_read_tag(con);
	return 1;
}


static int try_write(struct ceph_connection *con)
{
	int ret = 1;

	dout("try_write start %p state %lu\n", con, con->state);
	if (con->state != CON_STATE_PREOPEN && con->state != CON_STATE_CONNECTING && con->state != CON_STATE_NEGOTIATING && con->state != CON_STATE_OPEN)


		return 0;

	
	if (con->state == CON_STATE_PREOPEN) {
		BUG_ON(con->sock);
		con->state = CON_STATE_CONNECTING;

		con_out_kvec_reset(con);
		prepare_write_banner(con);
		prepare_read_banner(con);

		BUG_ON(con->in_msg);
		con->in_tag = CEPH_MSGR_TAG_READY;
		dout("try_write initiating connect on %p new state %lu\n", con, con->state);
		ret = ceph_tcp_connect(con);
		if (ret < 0) {
			con->error_msg = "connect error";
			goto out;
		}
	}

more:
	dout("try_write out_kvec_bytes %d\n", con->out_kvec_bytes);
	BUG_ON(!con->sock);

	
	if (con->out_kvec_left) {
		ret = write_partial_kvec(con);
		if (ret <= 0)
			goto out;
	}
	if (con->out_skip) {
		ret = write_partial_skip(con);
		if (ret <= 0)
			goto out;
	}

	
	if (con->out_msg) {
		if (con->out_msg_done) {
			ceph_msg_put(con->out_msg);
			con->out_msg = NULL;   
			goto do_next;
		}

		ret = write_partial_message_data(con);
		if (ret == 1)
			goto more;  
		if (ret == 0)
			goto out;
		if (ret < 0) {
			dout("try_write write_partial_message_data err %d\n", ret);
			goto out;
		}
	}

do_next:
	if (con->state == CON_STATE_OPEN) {
		if (con_flag_test_and_clear(con, CON_FLAG_KEEPALIVE_PENDING)) {
			prepare_write_keepalive(con);
			goto more;
		}
		
		if (!list_empty(&con->out_queue)) {
			prepare_write_message(con);
			goto more;
		}
		if (con->in_seq > con->in_seq_acked) {
			prepare_write_ack(con);
			goto more;
		}
	}

	
	con_flag_clear(con, CON_FLAG_WRITE_PENDING);
	dout("try_write nothing else to write.\n");
	ret = 0;
out:
	dout("try_write done on %p ret %d\n", con, ret);
	return ret;
}


static int try_read(struct ceph_connection *con)
{
	int ret = -1;

more:
	dout("try_read start on %p state %lu\n", con, con->state);
	if (con->state != CON_STATE_CONNECTING && con->state != CON_STATE_NEGOTIATING && con->state != CON_STATE_OPEN)

		return 0;

	BUG_ON(!con->sock);

	dout("try_read tag %d in_base_pos %d\n", (int)con->in_tag, con->in_base_pos);

	if (con->state == CON_STATE_CONNECTING) {
		dout("try_read connecting\n");
		ret = read_partial_banner(con);
		if (ret <= 0)
			goto out;
		ret = process_banner(con);
		if (ret < 0)
			goto out;

		con->state = CON_STATE_NEGOTIATING;

		
		ret = prepare_write_connect(con);
		if (ret < 0)
			goto out;
		prepare_read_connect(con);

		
		goto out;
	}

	if (con->state == CON_STATE_NEGOTIATING) {
		dout("try_read negotiating\n");
		ret = read_partial_connect(con);
		if (ret <= 0)
			goto out;
		ret = process_connect(con);
		if (ret < 0)
			goto out;
		goto more;
	}

	WARN_ON(con->state != CON_STATE_OPEN);

	if (con->in_base_pos < 0) {
		
		ret = ceph_tcp_recvmsg(con->sock, NULL, -con->in_base_pos);
		if (ret <= 0)
			goto out;
		dout("skipped %d / %d bytes\n", ret, -con->in_base_pos);
		con->in_base_pos += ret;
		if (con->in_base_pos)
			goto more;
	}
	if (con->in_tag == CEPH_MSGR_TAG_READY) {
		
		ret = ceph_tcp_recvmsg(con->sock, &con->in_tag, 1);
		if (ret <= 0)
			goto out;
		dout("try_read got tag %d\n", (int)con->in_tag);
		switch (con->in_tag) {
		case CEPH_MSGR_TAG_MSG:
			prepare_read_message(con);
			break;
		case CEPH_MSGR_TAG_ACK:
			prepare_read_ack(con);
			break;
		case CEPH_MSGR_TAG_KEEPALIVE2_ACK:
			prepare_read_keepalive_ack(con);
			break;
		case CEPH_MSGR_TAG_CLOSE:
			con_close_socket(con);
			con->state = CON_STATE_CLOSED;
			goto out;
		default:
			goto bad_tag;
		}
	}
	if (con->in_tag == CEPH_MSGR_TAG_MSG) {
		ret = read_partial_message(con);
		if (ret <= 0) {
			switch (ret) {
			case -EBADMSG:
				con->error_msg = "bad crc/signature";
				
			case -EBADE:
				ret = -EIO;
				break;
			case -EIO:
				con->error_msg = "io error";
				break;
			}
			goto out;
		}
		if (con->in_tag == CEPH_MSGR_TAG_READY)
			goto more;
		process_message(con);
		if (con->state == CON_STATE_OPEN)
			prepare_read_tag(con);
		goto more;
	}
	if (con->in_tag == CEPH_MSGR_TAG_ACK || con->in_tag == CEPH_MSGR_TAG_SEQ) {
		
		ret = read_partial_ack(con);
		if (ret <= 0)
			goto out;
		process_ack(con);
		goto more;
	}
	if (con->in_tag == CEPH_MSGR_TAG_KEEPALIVE2_ACK) {
		ret = read_keepalive_ack(con);
		if (ret <= 0)
			goto out;
		goto more;
	}

out:
	dout("try_read done on %p ret %d\n", con, ret);
	return ret;

bad_tag:
	pr_err("try_read bad con->in_tag = %d\n", (int)con->in_tag);
	con->error_msg = "protocol error, garbage tag";
	ret = -1;
	goto out;
}



static int queue_con_delay(struct ceph_connection *con, unsigned long delay)
{
	if (!con->ops->get(con)) {
		dout("%s %p ref count 0\n", __func__, con);
		return -ENOENT;
	}

	if (!queue_delayed_work(ceph_msgr_wq, &con->work, delay)) {
		dout("%s %p - already queued\n", __func__, con);
		con->ops->put(con);
		return -EBUSY;
	}

	dout("%s %p %lu\n", __func__, con, delay);
	return 0;
}

static void queue_con(struct ceph_connection *con)
{
	(void) queue_con_delay(con, 0);
}

static void cancel_con(struct ceph_connection *con)
{
	if (cancel_delayed_work(&con->work)) {
		dout("%s %p\n", __func__, con);
		con->ops->put(con);
	}
}

static bool con_sock_closed(struct ceph_connection *con)
{
	if (!con_flag_test_and_clear(con, CON_FLAG_SOCK_CLOSED))
		return false;





	switch (con->state) {
	CASE(CLOSED);
	CASE(PREOPEN);
	CASE(CONNECTING);
	CASE(NEGOTIATING);
	CASE(OPEN);
	CASE(STANDBY);
	default:
		pr_warn("%s con %p unrecognized state %lu\n", __func__, con, con->state);
		con->error_msg = "unrecognized con state";
		BUG();
		break;
	}


	return true;
}

static bool con_backoff(struct ceph_connection *con)
{
	int ret;

	if (!con_flag_test_and_clear(con, CON_FLAG_BACKOFF))
		return false;

	ret = queue_con_delay(con, round_jiffies_relative(con->delay));
	if (ret) {
		dout("%s: con %p FAILED to back off %lu\n", __func__, con, con->delay);
		BUG_ON(ret == -ENOENT);
		con_flag_set(con, CON_FLAG_BACKOFF);
	}

	return true;
}



static void con_fault_finish(struct ceph_connection *con)
{
	dout("%s %p\n", __func__, con);

	
	if (con->auth_retry) {
		dout("auth_retry %d, invalidating\n", con->auth_retry);
		if (con->ops->invalidate_authorizer)
			con->ops->invalidate_authorizer(con);
		con->auth_retry = 0;
	}

	if (con->ops->fault)
		con->ops->fault(con);
}


static void ceph_con_workfn(struct work_struct *work)
{
	struct ceph_connection *con = container_of(work, struct ceph_connection, work.work);
	bool fault;

	mutex_lock(&con->mutex);
	while (true) {
		int ret;

		if ((fault = con_sock_closed(con))) {
			dout("%s: con %p SOCK_CLOSED\n", __func__, con);
			break;
		}
		if (con_backoff(con)) {
			dout("%s: con %p BACKOFF\n", __func__, con);
			break;
		}
		if (con->state == CON_STATE_STANDBY) {
			dout("%s: con %p STANDBY\n", __func__, con);
			break;
		}
		if (con->state == CON_STATE_CLOSED) {
			dout("%s: con %p CLOSED\n", __func__, con);
			BUG_ON(con->sock);
			break;
		}
		if (con->state == CON_STATE_PREOPEN) {
			dout("%s: con %p PREOPEN\n", __func__, con);
			BUG_ON(con->sock);
		}

		ret = try_read(con);
		if (ret < 0) {
			if (ret == -EAGAIN)
				continue;
			if (!con->error_msg)
				con->error_msg = "socket error on read";
			fault = true;
			break;
		}

		ret = try_write(con);
		if (ret < 0) {
			if (ret == -EAGAIN)
				continue;
			if (!con->error_msg)
				con->error_msg = "socket error on write";
			fault = true;
		}

		break;	
	}
	if (fault)
		con_fault(con);
	mutex_unlock(&con->mutex);

	if (fault)
		con_fault_finish(con);

	con->ops->put(con);
}


static void con_fault(struct ceph_connection *con)
{
	dout("fault %p state %lu to peer %s\n", con, con->state, ceph_pr_addr(&con->peer_addr.in_addr));

	pr_warn("%s%lld %s %s\n", ENTITY_NAME(con->peer_name), ceph_pr_addr(&con->peer_addr.in_addr), con->error_msg);
	con->error_msg = NULL;

	WARN_ON(con->state != CON_STATE_CONNECTING && con->state != CON_STATE_NEGOTIATING && con->state != CON_STATE_OPEN);


	con_close_socket(con);

	if (con_flag_test(con, CON_FLAG_LOSSYTX)) {
		dout("fault on LOSSYTX channel, marking CLOSED\n");
		con->state = CON_STATE_CLOSED;
		return;
	}

	if (con->in_msg) {
		BUG_ON(con->in_msg->con != con);
		ceph_msg_put(con->in_msg);
		con->in_msg = NULL;
	}

	
	list_splice_init(&con->out_sent, &con->out_queue);

	
	if (list_empty(&con->out_queue) && !con_flag_test(con, CON_FLAG_KEEPALIVE_PENDING)) {
		dout("fault %p setting STANDBY clearing WRITE_PENDING\n", con);
		con_flag_clear(con, CON_FLAG_WRITE_PENDING);
		con->state = CON_STATE_STANDBY;
	} else {
		
		con->state = CON_STATE_PREOPEN;
		if (con->delay == 0)
			con->delay = BASE_DELAY_INTERVAL;
		else if (con->delay < MAX_DELAY_INTERVAL)
			con->delay *= 2;
		con_flag_set(con, CON_FLAG_BACKOFF);
		queue_con(con);
	}
}




void ceph_messenger_init(struct ceph_messenger *msgr, struct ceph_entity_addr *myaddr)
{
	spin_lock_init(&msgr->global_seq_lock);

	if (myaddr)
		msgr->inst.addr = *myaddr;

	
	msgr->inst.addr.type = 0;
	get_random_bytes(&msgr->inst.addr.nonce, sizeof(msgr->inst.addr.nonce));
	encode_my_addr(msgr);

	atomic_set(&msgr->stopping, 0);
	write_pnet(&msgr->net, get_net(current->nsproxy->net_ns));

	dout("%s %p\n", __func__, msgr);
}
EXPORT_SYMBOL(ceph_messenger_init);

void ceph_messenger_fini(struct ceph_messenger *msgr)
{
	put_net(read_pnet(&msgr->net));
}
EXPORT_SYMBOL(ceph_messenger_fini);

static void msg_con_set(struct ceph_msg *msg, struct ceph_connection *con)
{
	if (msg->con)
		msg->con->ops->put(msg->con);

	msg->con = con ? con->ops->get(con) : NULL;
	BUG_ON(msg->con != con);
}

static void clear_standby(struct ceph_connection *con)
{
	
	if (con->state == CON_STATE_STANDBY) {
		dout("clear_standby %p and ++connect_seq\n", con);
		con->state = CON_STATE_PREOPEN;
		con->connect_seq++;
		WARN_ON(con_flag_test(con, CON_FLAG_WRITE_PENDING));
		WARN_ON(con_flag_test(con, CON_FLAG_KEEPALIVE_PENDING));
	}
}


void ceph_con_send(struct ceph_connection *con, struct ceph_msg *msg)
{
	
	msg->hdr.src = con->msgr->inst.name;
	BUG_ON(msg->front.iov_len != le32_to_cpu(msg->hdr.front_len));
	msg->needs_out_seq = true;

	mutex_lock(&con->mutex);

	if (con->state == CON_STATE_CLOSED) {
		dout("con_send %p closed, dropping %p\n", con, msg);
		ceph_msg_put(msg);
		mutex_unlock(&con->mutex);
		return;
	}

	msg_con_set(msg, con);

	BUG_ON(!list_empty(&msg->list_head));
	list_add_tail(&msg->list_head, &con->out_queue);
	dout("----- %p to %s%lld %d=%s len %d+%d+%d -----\n", msg, ENTITY_NAME(con->peer_name), le16_to_cpu(msg->hdr.type), ceph_msg_type_name(le16_to_cpu(msg->hdr.type)), le32_to_cpu(msg->hdr.front_len), le32_to_cpu(msg->hdr.middle_len), le32_to_cpu(msg->hdr.data_len));





	clear_standby(con);
	mutex_unlock(&con->mutex);

	
	if (con_flag_test_and_set(con, CON_FLAG_WRITE_PENDING) == 0)
		queue_con(con);
}
EXPORT_SYMBOL(ceph_con_send);


void ceph_msg_revoke(struct ceph_msg *msg)
{
	struct ceph_connection *con = msg->con;

	if (!con) {
		dout("%s msg %p null con\n", __func__, msg);
		return;		
	}

	mutex_lock(&con->mutex);
	if (!list_empty(&msg->list_head)) {
		dout("%s %p msg %p - was on queue\n", __func__, con, msg);
		list_del_init(&msg->list_head);
		msg->hdr.seq = 0;

		ceph_msg_put(msg);
	}
	if (con->out_msg == msg) {
		BUG_ON(con->out_skip);
		
		if (con->out_msg_done) {
			con->out_skip += con_out_kvec_skip(con);
		} else {
			BUG_ON(!msg->data_length);
			con->out_skip += sizeof_footer(con);
		}
		
		if (msg->data_length)
			con->out_skip += msg->cursor.total_resid;
		if (msg->middle)
			con->out_skip += con_out_kvec_skip(con);
		con->out_skip += con_out_kvec_skip(con);

		dout("%s %p msg %p - was sending, will write %d skip %d\n", __func__, con, msg, con->out_kvec_bytes, con->out_skip);
		msg->hdr.seq = 0;
		con->out_msg = NULL;
		ceph_msg_put(msg);
	}

	mutex_unlock(&con->mutex);
}


void ceph_msg_revoke_incoming(struct ceph_msg *msg)
{
	struct ceph_connection *con = msg->con;

	if (!con) {
		dout("%s msg %p null con\n", __func__, msg);
		return;		
	}

	mutex_lock(&con->mutex);
	if (con->in_msg == msg) {
		unsigned int front_len = le32_to_cpu(con->in_hdr.front_len);
		unsigned int middle_len = le32_to_cpu(con->in_hdr.middle_len);
		unsigned int data_len = le32_to_cpu(con->in_hdr.data_len);

		
		dout("%s %p msg %p revoked\n", __func__, con, msg);
		con->in_base_pos = con->in_base_pos - sizeof(struct ceph_msg_header) - front_len - middle_len - data_len - sizeof(struct ceph_msg_footer);




		ceph_msg_put(con->in_msg);
		con->in_msg = NULL;
		con->in_tag = CEPH_MSGR_TAG_READY;
		con->in_seq++;
	} else {
		dout("%s %p in_msg %p msg %p no-op\n", __func__, con, con->in_msg, msg);
	}
	mutex_unlock(&con->mutex);
}


void ceph_con_keepalive(struct ceph_connection *con)
{
	dout("con_keepalive %p\n", con);
	mutex_lock(&con->mutex);
	clear_standby(con);
	mutex_unlock(&con->mutex);
	if (con_flag_test_and_set(con, CON_FLAG_KEEPALIVE_PENDING) == 0 && con_flag_test_and_set(con, CON_FLAG_WRITE_PENDING) == 0)
		queue_con(con);
}
EXPORT_SYMBOL(ceph_con_keepalive);

bool ceph_con_keepalive_expired(struct ceph_connection *con, unsigned long interval)
{
	if (interval > 0 && (con->peer_features & CEPH_FEATURE_MSGR_KEEPALIVE2)) {
		struct timespec64 now;
		struct timespec64 ts;
		ktime_get_real_ts64(&now);
		jiffies_to_timespec64(interval, &ts);
		ts = timespec64_add(con->last_keepalive_ack, ts);
		return timespec64_compare(&now, &ts) >= 0;
	}
	return false;
}

static struct ceph_msg_data *ceph_msg_data_create(enum ceph_msg_data_type type)
{
	struct ceph_msg_data *data;

	if (WARN_ON(!ceph_msg_data_type_valid(type)))
		return NULL;

	data = kmem_cache_zalloc(ceph_msg_data_cache, GFP_NOFS);
	if (!data)
		return NULL;

	data->type = type;
	INIT_LIST_HEAD(&data->links);

	return data;
}

static void ceph_msg_data_destroy(struct ceph_msg_data *data)
{
	if (!data)
		return;

	WARN_ON(!list_empty(&data->links));
	if (data->type == CEPH_MSG_DATA_PAGELIST)
		ceph_pagelist_release(data->pagelist);
	kmem_cache_free(ceph_msg_data_cache, data);
}

void ceph_msg_data_add_pages(struct ceph_msg *msg, struct page **pages, size_t length, size_t alignment)
{
	struct ceph_msg_data *data;

	BUG_ON(!pages);
	BUG_ON(!length);

	data = ceph_msg_data_create(CEPH_MSG_DATA_PAGES);
	BUG_ON(!data);
	data->pages = pages;
	data->length = length;
	data->alignment = alignment & ~PAGE_MASK;

	list_add_tail(&data->links, &msg->data);
	msg->data_length += length;
}
EXPORT_SYMBOL(ceph_msg_data_add_pages);

void ceph_msg_data_add_pagelist(struct ceph_msg *msg, struct ceph_pagelist *pagelist)
{
	struct ceph_msg_data *data;

	BUG_ON(!pagelist);
	BUG_ON(!pagelist->length);

	data = ceph_msg_data_create(CEPH_MSG_DATA_PAGELIST);
	BUG_ON(!data);
	data->pagelist = pagelist;

	list_add_tail(&data->links, &msg->data);
	msg->data_length += pagelist->length;
}
EXPORT_SYMBOL(ceph_msg_data_add_pagelist);


void ceph_msg_data_add_bio(struct ceph_msg *msg, struct ceph_bio_iter *bio_pos, u32 length)
{
	struct ceph_msg_data *data;

	data = ceph_msg_data_create(CEPH_MSG_DATA_BIO);
	BUG_ON(!data);
	data->bio_pos = *bio_pos;
	data->bio_length = length;

	list_add_tail(&data->links, &msg->data);
	msg->data_length += length;
}
EXPORT_SYMBOL(ceph_msg_data_add_bio);


void ceph_msg_data_add_bvecs(struct ceph_msg *msg, struct ceph_bvec_iter *bvec_pos)
{
	struct ceph_msg_data *data;

	data = ceph_msg_data_create(CEPH_MSG_DATA_BVECS);
	BUG_ON(!data);
	data->bvec_pos = *bvec_pos;

	list_add_tail(&data->links, &msg->data);
	msg->data_length += bvec_pos->iter.bi_size;
}
EXPORT_SYMBOL(ceph_msg_data_add_bvecs);


struct ceph_msg *ceph_msg_new(int type, int front_len, gfp_t flags, bool can_fail)
{
	struct ceph_msg *m;

	m = kmem_cache_zalloc(ceph_msg_cache, flags);
	if (m == NULL)
		goto out;

	m->hdr.type = cpu_to_le16(type);
	m->hdr.priority = cpu_to_le16(CEPH_MSG_PRIO_DEFAULT);
	m->hdr.front_len = cpu_to_le32(front_len);

	INIT_LIST_HEAD(&m->list_head);
	kref_init(&m->kref);
	INIT_LIST_HEAD(&m->data);

	
	if (front_len) {
		m->front.iov_base = ceph_kvmalloc(front_len, flags);
		if (m->front.iov_base == NULL) {
			dout("ceph_msg_new can't allocate %d bytes\n", front_len);
			goto out2;
		}
	} else {
		m->front.iov_base = NULL;
	}
	m->front_alloc_len = m->front.iov_len = front_len;

	dout("ceph_msg_new %p front %d\n", m, front_len);
	return m;

out2:
	ceph_msg_put(m);
out:
	if (!can_fail) {
		pr_err("msg_new can't create type %d front %d\n", type, front_len);
		WARN_ON(1);
	} else {
		dout("msg_new can't create type %d front %d\n", type, front_len);
	}
	return NULL;
}
EXPORT_SYMBOL(ceph_msg_new);


static int ceph_alloc_middle(struct ceph_connection *con, struct ceph_msg *msg)
{
	int type = le16_to_cpu(msg->hdr.type);
	int middle_len = le32_to_cpu(msg->hdr.middle_len);

	dout("alloc_middle %p type %d %s middle_len %d\n", msg, type, ceph_msg_type_name(type), middle_len);
	BUG_ON(!middle_len);
	BUG_ON(msg->middle);

	msg->middle = ceph_buffer_new(middle_len, GFP_NOFS);
	if (!msg->middle)
		return -ENOMEM;
	return 0;
}


static int ceph_con_in_msg_alloc(struct ceph_connection *con, int *skip)
{
	struct ceph_msg_header *hdr = &con->in_hdr;
	int middle_len = le32_to_cpu(hdr->middle_len);
	struct ceph_msg *msg;
	int ret = 0;

	BUG_ON(con->in_msg != NULL);
	BUG_ON(!con->ops->alloc_msg);

	mutex_unlock(&con->mutex);
	msg = con->ops->alloc_msg(con, hdr, skip);
	mutex_lock(&con->mutex);
	if (con->state != CON_STATE_OPEN) {
		if (msg)
			ceph_msg_put(msg);
		return -EAGAIN;
	}
	if (msg) {
		BUG_ON(*skip);
		msg_con_set(msg, con);
		con->in_msg = msg;
	} else {
		
		if (*skip)
			return 0;

		con->error_msg = "error allocating memory for incoming message";
		return -ENOMEM;
	}
	memcpy(&con->in_msg->hdr, &con->in_hdr, sizeof(con->in_hdr));

	if (middle_len && !con->in_msg->middle) {
		ret = ceph_alloc_middle(con, con->in_msg);
		if (ret < 0) {
			ceph_msg_put(con->in_msg);
			con->in_msg = NULL;
		}
	}

	return ret;
}



static void ceph_msg_free(struct ceph_msg *m)
{
	dout("%s %p\n", __func__, m);
	kvfree(m->front.iov_base);
	kmem_cache_free(ceph_msg_cache, m);
}

static void ceph_msg_release(struct kref *kref)
{
	struct ceph_msg *m = container_of(kref, struct ceph_msg, kref);
	struct ceph_msg_data *data, *next;

	dout("%s %p\n", __func__, m);
	WARN_ON(!list_empty(&m->list_head));

	msg_con_set(m, NULL);

	
	if (m->middle) {
		ceph_buffer_put(m->middle);
		m->middle = NULL;
	}

	list_for_each_entry_safe(data, next, &m->data, links) {
		list_del_init(&data->links);
		ceph_msg_data_destroy(data);
	}
	m->data_length = 0;

	if (m->pool)
		ceph_msgpool_put(m->pool, m);
	else ceph_msg_free(m);
}

struct ceph_msg *ceph_msg_get(struct ceph_msg *msg)
{
	dout("%s %p (was %d)\n", __func__, msg, kref_read(&msg->kref));
	kref_get(&msg->kref);
	return msg;
}
EXPORT_SYMBOL(ceph_msg_get);

void ceph_msg_put(struct ceph_msg *msg)
{
	dout("%s %p (was %d)\n", __func__, msg, kref_read(&msg->kref));
	kref_put(&msg->kref, ceph_msg_release);
}
EXPORT_SYMBOL(ceph_msg_put);

void ceph_msg_dump(struct ceph_msg *msg)
{
	pr_debug("msg_dump %p (front_alloc_len %d length %zd)\n", msg, msg->front_alloc_len, msg->data_length);
	print_hex_dump(KERN_DEBUG, "header: ", DUMP_PREFIX_OFFSET, 16, 1, &msg->hdr, sizeof(msg->hdr), true);

	print_hex_dump(KERN_DEBUG, " front: ", DUMP_PREFIX_OFFSET, 16, 1, msg->front.iov_base, msg->front.iov_len, true);

	if (msg->middle)
		print_hex_dump(KERN_DEBUG, "middle: ", DUMP_PREFIX_OFFSET, 16, 1, msg->middle->vec.iov_base, msg->middle->vec.iov_len, true);


	print_hex_dump(KERN_DEBUG, "footer: ", DUMP_PREFIX_OFFSET, 16, 1, &msg->footer, sizeof(msg->footer), true);

}
EXPORT_SYMBOL(ceph_msg_dump);
