















































































































static void evbuffer_chain_align(struct evbuffer_chain *chain);
static int evbuffer_chain_should_realign(struct evbuffer_chain *chain, size_t datalen);
static void evbuffer_deferred_callback(struct event_callback *cb, void *arg);
static int evbuffer_ptr_memcmp(const struct evbuffer *buf, const struct evbuffer_ptr *pos, const char *mem, size_t len);
static struct evbuffer_chain *evbuffer_expand_singlechain(struct evbuffer *buf, size_t datlen);
static int evbuffer_ptr_subtract(struct evbuffer *buf, struct evbuffer_ptr *pos, size_t howfar);
static int evbuffer_file_segment_materialize(struct evbuffer_file_segment *seg);
static inline void evbuffer_chain_incref(struct evbuffer_chain *chain);

static struct evbuffer_chain * evbuffer_chain_new(size_t size)
{
	struct evbuffer_chain *chain;
	size_t to_alloc;

	size += EVBUFFER_CHAIN_SIZE;

	
	to_alloc = MIN_BUFFER_SIZE;
	while (to_alloc < size)
		to_alloc <<= 1;

	
	if ((chain = mm_malloc(to_alloc)) == NULL)
		return (NULL);

	memset(chain, 0, EVBUFFER_CHAIN_SIZE);

	chain->buffer_len = to_alloc - EVBUFFER_CHAIN_SIZE;

	
	chain->buffer = EVBUFFER_CHAIN_EXTRA(u_char, chain);

	chain->refcnt = 1;

	return (chain);
}

static inline void evbuffer_chain_free(struct evbuffer_chain *chain)
{
	EVUTIL_ASSERT(chain->refcnt > 0);
	if (--chain->refcnt > 0) {
		
		return;
	}

	if (CHAIN_PINNED(chain)) {
		
		chain->refcnt++;
		chain->flags |= EVBUFFER_DANGLING;
		return;
	}

	
	if (chain->flags & EVBUFFER_REFERENCE) {
		struct evbuffer_chain_reference *info = EVBUFFER_CHAIN_EXTRA( struct evbuffer_chain_reference, chain);


		if (info->cleanupfn)
			(*info->cleanupfn)(chain->buffer, chain->buffer_len, info->extra);

	}
	if (chain->flags & EVBUFFER_FILESEGMENT) {
		struct evbuffer_chain_file_segment *info = EVBUFFER_CHAIN_EXTRA( struct evbuffer_chain_file_segment, chain);


		if (info->segment) {

			if (info->segment->is_mapping)
				UnmapViewOfFile(chain->buffer);

			evbuffer_file_segment_free(info->segment);
		}
	}
	if (chain->flags & EVBUFFER_MULTICAST) {
		struct evbuffer_multicast_parent *info = EVBUFFER_CHAIN_EXTRA( struct evbuffer_multicast_parent, chain);


		
		EVUTIL_ASSERT(info->source != NULL);
		EVUTIL_ASSERT(info->parent != NULL);
		EVBUFFER_LOCK(info->source);
		evbuffer_chain_free(info->parent);
		evbuffer_decref_and_unlock_(info->source);
	}

	mm_free(chain);
}

static void evbuffer_free_all_chains(struct evbuffer_chain *chain)
{
	struct evbuffer_chain *next;
	for (; chain; chain = next) {
		next = chain->next;
		evbuffer_chain_free(chain);
	}
}


static int evbuffer_chains_all_empty(struct evbuffer_chain *chain)
{
	for (; chain; chain = chain->next) {
		if (chain->off)
			return 0;
	}
	return 1;
}


static inline int evbuffer_chains_all_empty(struct evbuffer_chain *chain) {
	return 1;
}



static struct evbuffer_chain ** evbuffer_free_trailing_empty_chains(struct evbuffer *buf)
{
	struct evbuffer_chain **ch = buf->last_with_datap;
	
	while ((*ch) && ((*ch)->off != 0 || CHAIN_PINNED(*ch)))
		ch = &(*ch)->next;
	if (*ch) {
		EVUTIL_ASSERT(evbuffer_chains_all_empty(*ch));
		evbuffer_free_all_chains(*ch);
		*ch = NULL;
	}
	return ch;
}


static void evbuffer_chain_insert(struct evbuffer *buf, struct evbuffer_chain *chain)

{
	ASSERT_EVBUFFER_LOCKED(buf);
	if (*buf->last_with_datap == NULL) {
		
		EVUTIL_ASSERT(buf->last_with_datap == &buf->first);
		EVUTIL_ASSERT(buf->first == NULL);
		buf->first = buf->last = chain;
	} else {
		struct evbuffer_chain **chp;
		chp = evbuffer_free_trailing_empty_chains(buf);
		*chp = chain;
		if (chain->off)
			buf->last_with_datap = chp;
		buf->last = chain;
	}
	buf->total_len += chain->off;
}

static inline struct evbuffer_chain * evbuffer_chain_insert_new(struct evbuffer *buf, size_t datlen)
{
	struct evbuffer_chain *chain;
	if ((chain = evbuffer_chain_new(datlen)) == NULL)
		return NULL;
	evbuffer_chain_insert(buf, chain);
	return chain;
}

void evbuffer_chain_pin_(struct evbuffer_chain *chain, unsigned flag)
{
	EVUTIL_ASSERT((chain->flags & flag) == 0);
	chain->flags |= flag;
}

void evbuffer_chain_unpin_(struct evbuffer_chain *chain, unsigned flag)
{
	EVUTIL_ASSERT((chain->flags & flag) != 0);
	chain->flags &= ~flag;
	if (chain->flags & EVBUFFER_DANGLING)
		evbuffer_chain_free(chain);
}

static inline void evbuffer_chain_incref(struct evbuffer_chain *chain)
{
    ++chain->refcnt;
}

struct evbuffer * evbuffer_new(void)
{
	struct evbuffer *buffer;

	buffer = mm_calloc(1, sizeof(struct evbuffer));
	if (buffer == NULL)
		return (NULL);

	LIST_INIT(&buffer->callbacks);
	buffer->refcnt = 1;
	buffer->last_with_datap = &buffer->first;

	return (buffer);
}

int evbuffer_set_flags(struct evbuffer *buf, ev_uint64_t flags)
{
	EVBUFFER_LOCK(buf);
	buf->flags |= (ev_uint32_t)flags;
	EVBUFFER_UNLOCK(buf);
	return 0;
}

int evbuffer_clear_flags(struct evbuffer *buf, ev_uint64_t flags)
{
	EVBUFFER_LOCK(buf);
	buf->flags &= ~(ev_uint32_t)flags;
	EVBUFFER_UNLOCK(buf);
	return 0;
}

void evbuffer_incref_(struct evbuffer *buf)
{
	EVBUFFER_LOCK(buf);
	++buf->refcnt;
	EVBUFFER_UNLOCK(buf);
}

void evbuffer_incref_and_lock_(struct evbuffer *buf)
{
	EVBUFFER_LOCK(buf);
	++buf->refcnt;
}

int evbuffer_defer_callbacks(struct evbuffer *buffer, struct event_base *base)
{
	EVBUFFER_LOCK(buffer);
	buffer->cb_queue = base;
	buffer->deferred_cbs = 1;
	event_deferred_cb_init_(&buffer->deferred, event_base_get_npriorities(base) / 2, evbuffer_deferred_callback, buffer);

	EVBUFFER_UNLOCK(buffer);
	return 0;
}

int evbuffer_enable_locking(struct evbuffer *buf, void *lock)
{

	return -1;

	if (buf->lock)
		return -1;

	if (!lock) {
		EVTHREAD_ALLOC_LOCK(lock, EVTHREAD_LOCKTYPE_RECURSIVE);
		if (!lock)
			return -1;
		buf->lock = lock;
		buf->own_lock = 1;
	} else {
		buf->lock = lock;
		buf->own_lock = 0;
	}

	return 0;

}

void evbuffer_set_parent_(struct evbuffer *buf, struct bufferevent *bev)
{
	EVBUFFER_LOCK(buf);
	buf->parent = bev;
	EVBUFFER_UNLOCK(buf);
}

static void evbuffer_run_callbacks(struct evbuffer *buffer, int running_deferred)
{
	struct evbuffer_cb_entry *cbent, *next;
	struct evbuffer_cb_info info;
	size_t new_size;
	ev_uint32_t mask, masked_val;
	int clear = 1;

	if (running_deferred) {
		mask = EVBUFFER_CB_NODEFER|EVBUFFER_CB_ENABLED;
		masked_val = EVBUFFER_CB_ENABLED;
	} else if (buffer->deferred_cbs) {
		mask = EVBUFFER_CB_NODEFER|EVBUFFER_CB_ENABLED;
		masked_val = EVBUFFER_CB_NODEFER|EVBUFFER_CB_ENABLED;
		
		clear = 0;
	} else {
		mask = EVBUFFER_CB_ENABLED;
		masked_val = EVBUFFER_CB_ENABLED;
	}

	ASSERT_EVBUFFER_LOCKED(buffer);

	if (LIST_EMPTY(&buffer->callbacks)) {
		buffer->n_add_for_cb = buffer->n_del_for_cb = 0;
		return;
	}
	if (buffer->n_add_for_cb == 0 && buffer->n_del_for_cb == 0)
		return;

	new_size = buffer->total_len;
	info.orig_size = new_size + buffer->n_del_for_cb - buffer->n_add_for_cb;
	info.n_added = buffer->n_add_for_cb;
	info.n_deleted = buffer->n_del_for_cb;
	if (clear) {
		buffer->n_add_for_cb = 0;
		buffer->n_del_for_cb = 0;
	}
	for (cbent = LIST_FIRST(&buffer->callbacks);
	     cbent != LIST_END(&buffer->callbacks);
	     cbent = next) {
		
		next = LIST_NEXT(cbent, next);

		if ((cbent->flags & mask) != masked_val)
			continue;

		if ((cbent->flags & EVBUFFER_CB_OBSOLETE))
			cbent->cb.cb_obsolete(buffer, info.orig_size, new_size, cbent->cbarg);
		else cbent->cb.cb_func(buffer, &info, cbent->cbarg);
	}
}

void evbuffer_invoke_callbacks_(struct evbuffer *buffer)
{
	if (LIST_EMPTY(&buffer->callbacks)) {
		buffer->n_add_for_cb = buffer->n_del_for_cb = 0;
		return;
	}

	if (buffer->deferred_cbs) {
		if (event_deferred_cb_schedule_(buffer->cb_queue, &buffer->deferred)) {
			evbuffer_incref_and_lock_(buffer);
			if (buffer->parent)
				bufferevent_incref_(buffer->parent);
		}
		EVBUFFER_UNLOCK(buffer);
	}

	evbuffer_run_callbacks(buffer, 0);
}

static void evbuffer_deferred_callback(struct event_callback *cb, void *arg)
{
	struct bufferevent *parent = NULL;
	struct evbuffer *buffer = arg;

	
	EVBUFFER_LOCK(buffer);
	parent = buffer->parent;
	evbuffer_run_callbacks(buffer, 1);
	evbuffer_decref_and_unlock_(buffer);
	if (parent)
		bufferevent_decref_(parent);
}

static void evbuffer_remove_all_callbacks(struct evbuffer *buffer)
{
	struct evbuffer_cb_entry *cbent;

	while ((cbent = LIST_FIRST(&buffer->callbacks))) {
		LIST_REMOVE(cbent, next);
		mm_free(cbent);
	}
}

void evbuffer_decref_and_unlock_(struct evbuffer *buffer)
{
	struct evbuffer_chain *chain, *next;
	ASSERT_EVBUFFER_LOCKED(buffer);

	EVUTIL_ASSERT(buffer->refcnt > 0);

	if (--buffer->refcnt > 0) {
		EVBUFFER_UNLOCK(buffer);
		return;
	}

	for (chain = buffer->first; chain != NULL; chain = next) {
		next = chain->next;
		evbuffer_chain_free(chain);
	}
	evbuffer_remove_all_callbacks(buffer);
	if (buffer->deferred_cbs)
		event_deferred_cb_cancel_(buffer->cb_queue, &buffer->deferred);

	EVBUFFER_UNLOCK(buffer);
	if (buffer->own_lock)
		EVTHREAD_FREE_LOCK(buffer->lock, EVTHREAD_LOCKTYPE_RECURSIVE);
	mm_free(buffer);
}

void evbuffer_free(struct evbuffer *buffer)
{
	EVBUFFER_LOCK(buffer);
	evbuffer_decref_and_unlock_(buffer);
}

void evbuffer_lock(struct evbuffer *buf)
{
	EVBUFFER_LOCK(buf);
}

void evbuffer_unlock(struct evbuffer *buf)
{
	EVBUFFER_UNLOCK(buf);
}

size_t evbuffer_get_length(const struct evbuffer *buffer)
{
	size_t result;

	EVBUFFER_LOCK(buffer);

	result = (buffer->total_len);

	EVBUFFER_UNLOCK(buffer);

	return result;
}

size_t evbuffer_get_contiguous_space(const struct evbuffer *buf)
{
	struct evbuffer_chain *chain;
	size_t result;

	EVBUFFER_LOCK(buf);
	chain = buf->first;
	result = (chain != NULL ? chain->off : 0);
	EVBUFFER_UNLOCK(buf);

	return result;
}

size_t evbuffer_add_iovec(struct evbuffer * buf, struct evbuffer_iovec * vec, int n_vec) {
	int n;
	size_t res;
	size_t to_alloc;

	EVBUFFER_LOCK(buf);

	res = to_alloc = 0;

	for (n = 0; n < n_vec; n++) {
		to_alloc += vec[n].iov_len;
	}

	if (evbuffer_expand_fast_(buf, to_alloc, 2) < 0) {
		goto done;
	}

	for (n = 0; n < n_vec; n++) {
		

		if (evbuffer_add(buf, vec[n].iov_base, vec[n].iov_len) < 0) {
			goto done;
		}

		res += vec[n].iov_len;
	}

done:
    EVBUFFER_UNLOCK(buf);
    return res;
}

int evbuffer_reserve_space(struct evbuffer *buf, ev_ssize_t size, struct evbuffer_iovec *vec, int n_vecs)

{
	struct evbuffer_chain *chain, **chainp;
	int n = -1;

	EVBUFFER_LOCK(buf);
	if (buf->freeze_end)
		goto done;
	if (n_vecs < 1)
		goto done;
	if (n_vecs == 1) {
		if ((chain = evbuffer_expand_singlechain(buf, size)) == NULL)
			goto done;

		vec[0].iov_base = CHAIN_SPACE_PTR(chain);
		vec[0].iov_len = (size_t) CHAIN_SPACE_LEN(chain);
		EVUTIL_ASSERT(size<0 || (size_t)vec[0].iov_len >= (size_t)size);
		n = 1;
	} else {
		if (evbuffer_expand_fast_(buf, size, n_vecs)<0)
			goto done;
		n = evbuffer_read_setup_vecs_(buf, size, vec, n_vecs, &chainp, 0);
	}

done:
	EVBUFFER_UNLOCK(buf);
	return n;

}

static int advance_last_with_data(struct evbuffer *buf)
{
	int n = 0;
	ASSERT_EVBUFFER_LOCKED(buf);

	if (!*buf->last_with_datap)
		return 0;

	while ((*buf->last_with_datap)->next && (*buf->last_with_datap)->next->off) {
		buf->last_with_datap = &(*buf->last_with_datap)->next;
		++n;
	}
	return n;
}

int evbuffer_commit_space(struct evbuffer *buf, struct evbuffer_iovec *vec, int n_vecs)

{
	struct evbuffer_chain *chain, **firstchainp, **chainp;
	int result = -1;
	size_t added = 0;
	int i;

	EVBUFFER_LOCK(buf);

	if (buf->freeze_end)
		goto done;
	if (n_vecs == 0) {
		result = 0;
		goto done;
	} else if (n_vecs == 1 && (buf->last && vec[0].iov_base == (void*)CHAIN_SPACE_PTR(buf->last))) {
		
		if ((size_t)vec[0].iov_len > (size_t)CHAIN_SPACE_LEN(buf->last))
			goto done;
		buf->last->off += vec[0].iov_len;
		added = vec[0].iov_len;
		if (added)
			advance_last_with_data(buf);
		goto okay;
	}

	
	firstchainp = buf->last_with_datap;
	if (!*firstchainp)
		goto done;
	if (CHAIN_SPACE_LEN(*firstchainp) == 0) {
		firstchainp = &(*firstchainp)->next;
	}

	chain = *firstchainp;
	
	for (i=0; i<n_vecs; ++i) {
		if (!chain)
			goto done;
		if (vec[i].iov_base != (void*)CHAIN_SPACE_PTR(chain) || (size_t)vec[i].iov_len > CHAIN_SPACE_LEN(chain))
			goto done;
		chain = chain->next;
	}
	
	chainp = firstchainp;
	for (i=0; i<n_vecs; ++i) {
		(*chainp)->off += vec[i].iov_len;
		added += vec[i].iov_len;
		if (vec[i].iov_len) {
			buf->last_with_datap = chainp;
		}
		chainp = &(*chainp)->next;
	}

okay:
	buf->total_len += added;
	buf->n_add_for_cb += added;
	result = 0;
	evbuffer_invoke_callbacks_(buf);

done:
	EVBUFFER_UNLOCK(buf);
	return result;
}

static inline int HAS_PINNED_R(struct evbuffer *buf)
{
	return (buf->last && CHAIN_PINNED_R(buf->last));
}

static inline void ZERO_CHAIN(struct evbuffer *dst)
{
	ASSERT_EVBUFFER_LOCKED(dst);
	dst->first = NULL;
	dst->last = NULL;
	dst->last_with_datap = &(dst)->first;
	dst->total_len = 0;
}


static int PRESERVE_PINNED(struct evbuffer *src, struct evbuffer_chain **first, struct evbuffer_chain **last)

{
	struct evbuffer_chain *chain, **pinned;

	ASSERT_EVBUFFER_LOCKED(src);

	if (!HAS_PINNED_R(src)) {
		*first = *last = NULL;
		return 0;
	}

	pinned = src->last_with_datap;
	if (!CHAIN_PINNED_R(*pinned))
		pinned = &(*pinned)->next;
	EVUTIL_ASSERT(CHAIN_PINNED_R(*pinned));
	chain = *first = *pinned;
	*last = src->last;

	
	if (chain->off) {
		struct evbuffer_chain *tmp;

		EVUTIL_ASSERT(pinned == src->last_with_datap);
		tmp = evbuffer_chain_new(chain->off);
		if (!tmp)
			return -1;
		memcpy(tmp->buffer, chain->buffer + chain->misalign, chain->off);
		tmp->off = chain->off;
		*src->last_with_datap = tmp;
		src->last = tmp;
		chain->misalign += chain->off;
		chain->off = 0;
	} else {
		src->last = *src->last_with_datap;
		*pinned = NULL;
	}

	return 0;
}

static inline void RESTORE_PINNED(struct evbuffer *src, struct evbuffer_chain *pinned, struct evbuffer_chain *last)

{
	ASSERT_EVBUFFER_LOCKED(src);

	if (!pinned) {
		ZERO_CHAIN(src);
		return;
	}

	src->first = pinned;
	src->last = last;
	src->last_with_datap = &src->first;
	src->total_len = 0;
}

static inline void COPY_CHAIN(struct evbuffer *dst, struct evbuffer *src)
{
	ASSERT_EVBUFFER_LOCKED(dst);
	ASSERT_EVBUFFER_LOCKED(src);
	dst->first = src->first;
	if (src->last_with_datap == &src->first)
		dst->last_with_datap = &dst->first;
	else dst->last_with_datap = src->last_with_datap;
	dst->last = src->last;
	dst->total_len = src->total_len;
}

static void APPEND_CHAIN(struct evbuffer *dst, struct evbuffer *src)
{
	ASSERT_EVBUFFER_LOCKED(dst);
	ASSERT_EVBUFFER_LOCKED(src);
	dst->last->next = src->first;
	if (src->last_with_datap == &src->first)
		dst->last_with_datap = &dst->last->next;
	else dst->last_with_datap = src->last_with_datap;
	dst->last = src->last;
	dst->total_len += src->total_len;
}

static inline void APPEND_CHAIN_MULTICAST(struct evbuffer *dst, struct evbuffer *src)
{
	struct evbuffer_chain *tmp;
	struct evbuffer_chain *chain = src->first;
	struct evbuffer_multicast_parent *extra;

	ASSERT_EVBUFFER_LOCKED(dst);
	ASSERT_EVBUFFER_LOCKED(src);

	for (; chain; chain = chain->next) {
		if (!chain->off || chain->flags & EVBUFFER_DANGLING) {
			
			continue;
		}

		tmp = evbuffer_chain_new(sizeof(struct evbuffer_multicast_parent));
		if (!tmp) {
			event_warn("%s: out of memory", __func__);
			return;
		}
		extra = EVBUFFER_CHAIN_EXTRA(struct evbuffer_multicast_parent, tmp);
		
		evbuffer_incref_(src);
		extra->source = src;
		
		evbuffer_chain_incref(chain);
		extra->parent = chain;
		chain->flags |= EVBUFFER_IMMUTABLE;
		tmp->buffer_len = chain->buffer_len;
		tmp->misalign = chain->misalign;
		tmp->off = chain->off;
		tmp->flags |= EVBUFFER_MULTICAST|EVBUFFER_IMMUTABLE;
		tmp->buffer = chain->buffer;
		evbuffer_chain_insert(dst, tmp);
	}
}

static void PREPEND_CHAIN(struct evbuffer *dst, struct evbuffer *src)
{
	ASSERT_EVBUFFER_LOCKED(dst);
	ASSERT_EVBUFFER_LOCKED(src);
	src->last->next = dst->first;
	dst->first = src->first;
	dst->total_len += src->total_len;
	if (*dst->last_with_datap == NULL) {
		if (src->last_with_datap == &(src)->first)
			dst->last_with_datap = &dst->first;
		else dst->last_with_datap = src->last_with_datap;
	} else if (dst->last_with_datap == &dst->first) {
		dst->last_with_datap = &src->last->next;
	}
}

int evbuffer_add_buffer(struct evbuffer *outbuf, struct evbuffer *inbuf)
{
	struct evbuffer_chain *pinned, *last;
	size_t in_total_len, out_total_len;
	int result = 0;

	EVBUFFER_LOCK2(inbuf, outbuf);
	in_total_len = inbuf->total_len;
	out_total_len = outbuf->total_len;

	if (in_total_len == 0 || outbuf == inbuf)
		goto done;

	if (outbuf->freeze_end || inbuf->freeze_start) {
		result = -1;
		goto done;
	}

	if (PRESERVE_PINNED(inbuf, &pinned, &last) < 0) {
		result = -1;
		goto done;
	}

	if (out_total_len == 0) {
		
		evbuffer_free_all_chains(outbuf->first);
		COPY_CHAIN(outbuf, inbuf);
	} else {
		APPEND_CHAIN(outbuf, inbuf);
	}

	RESTORE_PINNED(inbuf, pinned, last);

	inbuf->n_del_for_cb += in_total_len;
	outbuf->n_add_for_cb += in_total_len;

	evbuffer_invoke_callbacks_(inbuf);
	evbuffer_invoke_callbacks_(outbuf);

done:
	EVBUFFER_UNLOCK2(inbuf, outbuf);
	return result;
}

int evbuffer_add_buffer_reference(struct evbuffer *outbuf, struct evbuffer *inbuf)
{
	size_t in_total_len, out_total_len;
	struct evbuffer_chain *chain;
	int result = 0;

	EVBUFFER_LOCK2(inbuf, outbuf);
	in_total_len = inbuf->total_len;
	out_total_len = outbuf->total_len;
	chain = inbuf->first;

	if (in_total_len == 0)
		goto done;

	if (outbuf->freeze_end || outbuf == inbuf) {
		result = -1;
		goto done;
	}

	for (; chain; chain = chain->next) {
		if ((chain->flags & (EVBUFFER_FILESEGMENT|EVBUFFER_SENDFILE|EVBUFFER_MULTICAST)) != 0) {
			
			result = -1;
			goto done;
		}
	}

	if (out_total_len == 0) {
		
		evbuffer_free_all_chains(outbuf->first);
	}
	APPEND_CHAIN_MULTICAST(outbuf, inbuf);

	outbuf->n_add_for_cb += in_total_len;
	evbuffer_invoke_callbacks_(outbuf);

done:
	EVBUFFER_UNLOCK2(inbuf, outbuf);
	return result;
}

int evbuffer_prepend_buffer(struct evbuffer *outbuf, struct evbuffer *inbuf)
{
	struct evbuffer_chain *pinned, *last;
	size_t in_total_len, out_total_len;
	int result = 0;

	EVBUFFER_LOCK2(inbuf, outbuf);

	in_total_len = inbuf->total_len;
	out_total_len = outbuf->total_len;

	if (!in_total_len || inbuf == outbuf)
		goto done;

	if (outbuf->freeze_start || inbuf->freeze_start) {
		result = -1;
		goto done;
	}

	if (PRESERVE_PINNED(inbuf, &pinned, &last) < 0) {
		result = -1;
		goto done;
	}

	if (out_total_len == 0) {
		
		evbuffer_free_all_chains(outbuf->first);
		COPY_CHAIN(outbuf, inbuf);
	} else {
		PREPEND_CHAIN(outbuf, inbuf);
	}

	RESTORE_PINNED(inbuf, pinned, last);

	inbuf->n_del_for_cb += in_total_len;
	outbuf->n_add_for_cb += in_total_len;

	evbuffer_invoke_callbacks_(inbuf);
	evbuffer_invoke_callbacks_(outbuf);
done:
	EVBUFFER_UNLOCK2(inbuf, outbuf);
	return result;
}

int evbuffer_drain(struct evbuffer *buf, size_t len)
{
	struct evbuffer_chain *chain, *next;
	size_t remaining, old_len;
	int result = 0;

	EVBUFFER_LOCK(buf);
	old_len = buf->total_len;

	if (old_len == 0)
		goto done;

	if (buf->freeze_start) {
		result = -1;
		goto done;
	}

	if (len >= old_len && !HAS_PINNED_R(buf)) {
		len = old_len;
		for (chain = buf->first; chain != NULL; chain = next) {
			next = chain->next;
			evbuffer_chain_free(chain);
		}

		ZERO_CHAIN(buf);
	} else {
		if (len >= old_len)
			len = old_len;

		buf->total_len -= len;
		remaining = len;
		for (chain = buf->first;
		     remaining >= chain->off;
		     chain = next) {
			next = chain->next;
			remaining -= chain->off;

			if (chain == *buf->last_with_datap) {
				buf->last_with_datap = &buf->first;
			}
			if (&chain->next == buf->last_with_datap)
				buf->last_with_datap = &buf->first;

			if (CHAIN_PINNED_R(chain)) {
				EVUTIL_ASSERT(remaining == 0);
				chain->misalign += chain->off;
				chain->off = 0;
				break;
			} else evbuffer_chain_free(chain);
		}

		buf->first = chain;
		chain->misalign += remaining;
		chain->off -= remaining;
	}

	buf->n_del_for_cb += len;
	
	evbuffer_invoke_callbacks_(buf);

done:
	EVBUFFER_UNLOCK(buf);
	return result;
}


int evbuffer_remove(struct evbuffer *buf, void *data_out, size_t datlen)
{
	ev_ssize_t n;
	EVBUFFER_LOCK(buf);
	n = evbuffer_copyout_from(buf, NULL, data_out, datlen);
	if (n > 0) {
		if (evbuffer_drain(buf, n)<0)
			n = -1;
	}
	EVBUFFER_UNLOCK(buf);
	return (int)n;
}

ev_ssize_t evbuffer_copyout(struct evbuffer *buf, void *data_out, size_t datlen)
{
	return evbuffer_copyout_from(buf, NULL, data_out, datlen);
}

ev_ssize_t evbuffer_copyout_from(struct evbuffer *buf, const struct evbuffer_ptr *pos, void *data_out, size_t datlen)

{
	
	struct evbuffer_chain *chain;
	char *data = data_out;
	size_t nread;
	ev_ssize_t result = 0;
	size_t pos_in_chain;

	EVBUFFER_LOCK(buf);

	if (pos) {
		chain = pos->internal_.chain;
		pos_in_chain = pos->internal_.pos_in_chain;
		if (datlen + pos->pos > buf->total_len)
			datlen = buf->total_len - pos->pos;
	} else {
		chain = buf->first;
		pos_in_chain = 0;
		if (datlen > buf->total_len)
			datlen = buf->total_len;
	}


	if (datlen == 0)
		goto done;

	if (buf->freeze_start) {
		result = -1;
		goto done;
	}

	nread = datlen;

	while (datlen && datlen >= chain->off - pos_in_chain) {
		size_t copylen = chain->off - pos_in_chain;
		memcpy(data, chain->buffer + chain->misalign + pos_in_chain, copylen);

		data += copylen;
		datlen -= copylen;

		chain = chain->next;
		pos_in_chain = 0;
		EVUTIL_ASSERT(chain || datlen==0);
	}

	if (datlen) {
		EVUTIL_ASSERT(chain);
		memcpy(data, chain->buffer + chain->misalign + pos_in_chain, datlen);
	}

	result = nread;
done:
	EVBUFFER_UNLOCK(buf);
	return result;
}



int evbuffer_remove_buffer(struct evbuffer *src, struct evbuffer *dst, size_t datlen)

{
	

	
	struct evbuffer_chain *chain, *previous;
	size_t nread = 0;
	int result;

	EVBUFFER_LOCK2(src, dst);

	chain = previous = src->first;

	if (datlen == 0 || dst == src) {
		result = 0;
		goto done;
	}

	if (dst->freeze_end || src->freeze_start) {
		result = -1;
		goto done;
	}

	
	if (datlen >= src->total_len) {
		datlen = src->total_len;
		evbuffer_add_buffer(dst, src);
		result = (int)datlen; 
		goto done;
	}

	
	while (chain->off <= datlen) {
		
		EVUTIL_ASSERT(chain != *src->last_with_datap);
		nread += chain->off;
		datlen -= chain->off;
		previous = chain;
		if (src->last_with_datap == &chain->next)
			src->last_with_datap = &src->first;
		chain = chain->next;
	}

	if (nread) {
		
		struct evbuffer_chain **chp;
		chp = evbuffer_free_trailing_empty_chains(dst);

		if (dst->first == NULL) {
			dst->first = src->first;
		} else {
			*chp = src->first;
		}
		dst->last = previous;
		previous->next = NULL;
		src->first = chain;
		advance_last_with_data(dst);

		dst->total_len += nread;
		dst->n_add_for_cb += nread;
	}

	
	evbuffer_add(dst, chain->buffer + chain->misalign, datlen);
	chain->misalign += datlen;
	chain->off -= datlen;
	nread += datlen;

	
	src->total_len -= nread;
	src->n_del_for_cb += nread;

	if (nread) {
		evbuffer_invoke_callbacks_(dst);
		evbuffer_invoke_callbacks_(src);
	}
	result = (int)nread;

done:
	EVBUFFER_UNLOCK2(src, dst);
	return result;
}

unsigned char * evbuffer_pullup(struct evbuffer *buf, ev_ssize_t size)
{
	struct evbuffer_chain *chain, *next, *tmp, *last_with_data;
	unsigned char *buffer, *result = NULL;
	ev_ssize_t remaining;
	int removed_last_with_data = 0;
	int removed_last_with_datap = 0;

	EVBUFFER_LOCK(buf);

	chain = buf->first;

	if (size < 0)
		size = buf->total_len;
	
	if (size == 0 || (size_t)size > buf->total_len)
		goto done;

	
	if (chain->off >= (size_t)size) {
		result = chain->buffer + chain->misalign;
		goto done;
	}

	
	remaining = size - chain->off;
	EVUTIL_ASSERT(remaining >= 0);
	for (tmp=chain->next; tmp; tmp=tmp->next) {
		if (CHAIN_PINNED(tmp))
			goto done;
		if (tmp->off >= (size_t)remaining)
			break;
		remaining -= tmp->off;
	}

	if (CHAIN_PINNED(chain)) {
		size_t old_off = chain->off;
		if (CHAIN_SPACE_LEN(chain) < size - chain->off) {
			
			goto done;
		}
		buffer = CHAIN_SPACE_PTR(chain);
		tmp = chain;
		tmp->off = size;
		size -= old_off;
		chain = chain->next;
	} else if (chain->buffer_len - chain->misalign >= (size_t)size) {
		
		size_t old_off = chain->off;
		buffer = chain->buffer + chain->misalign + chain->off;
		tmp = chain;
		tmp->off = size;
		size -= old_off;
		chain = chain->next;
	} else {
		if ((tmp = evbuffer_chain_new(size)) == NULL) {
			event_warn("%s: out of memory", __func__);
			goto done;
		}
		buffer = tmp->buffer;
		tmp->off = size;
		buf->first = tmp;
	}

	

	
	last_with_data = *buf->last_with_datap;
	for (; chain != NULL && (size_t)size >= chain->off; chain = next) {
		next = chain->next;

		memcpy(buffer, chain->buffer + chain->misalign, chain->off);
		size -= chain->off;
		buffer += chain->off;
		if (chain == last_with_data)
			removed_last_with_data = 1;
		if (&chain->next == buf->last_with_datap)
			removed_last_with_datap = 1;

		evbuffer_chain_free(chain);
	}

	if (chain != NULL) {
		memcpy(buffer, chain->buffer + chain->misalign, size);
		chain->misalign += size;
		chain->off -= size;
	} else {
		buf->last = tmp;
	}

	tmp->next = chain;

	if (removed_last_with_data) {
		buf->last_with_datap = &buf->first;
	} else if (removed_last_with_datap) {
		if (buf->first->next && buf->first->next->off)
			buf->last_with_datap = &buf->first->next;
		else buf->last_with_datap = &buf->first;
	}

	result = (tmp->buffer + tmp->misalign);

done:
	EVBUFFER_UNLOCK(buf);
	return result;
}


char * evbuffer_readline(struct evbuffer *buffer)
{
	return evbuffer_readln(buffer, NULL, EVBUFFER_EOL_ANY);
}

static inline ev_ssize_t evbuffer_strchr(struct evbuffer_ptr *it, const char chr)
{
	struct evbuffer_chain *chain = it->internal_.chain;
	size_t i = it->internal_.pos_in_chain;
	while (chain != NULL) {
		char *buffer = (char *)chain->buffer + chain->misalign;
		char *cp = memchr(buffer+i, chr, chain->off-i);
		if (cp) {
			it->internal_.chain = chain;
			it->internal_.pos_in_chain = cp - buffer;
			it->pos += (cp - buffer - i);
			return it->pos;
		}
		it->pos += chain->off - i;
		i = 0;
		chain = chain->next;
	}

	return (-1);
}

static inline char * find_eol_char(char *s, size_t len)
{

	
	char *s_end, *cr, *lf;
	s_end = s+len;
	while (s < s_end) {
		size_t chunk = (s + CHUNK_SZ < s_end) ? CHUNK_SZ : (s_end - s);
		cr = memchr(s, '\r', chunk);
		lf = memchr(s, '\n', chunk);
		if (cr) {
			if (lf && lf < cr)
				return lf;
			return cr;
		} else if (lf) {
			return lf;
		}
		s += CHUNK_SZ;
	}

	return NULL;

}

static ev_ssize_t evbuffer_find_eol_char(struct evbuffer_ptr *it)
{
	struct evbuffer_chain *chain = it->internal_.chain;
	size_t i = it->internal_.pos_in_chain;
	while (chain != NULL) {
		char *buffer = (char *)chain->buffer + chain->misalign;
		char *cp = find_eol_char(buffer+i, chain->off-i);
		if (cp) {
			it->internal_.chain = chain;
			it->internal_.pos_in_chain = cp - buffer;
			it->pos += (cp - buffer) - i;
			return it->pos;
		}
		it->pos += chain->off - i;
		i = 0;
		chain = chain->next;
	}

	return (-1);
}

static inline int evbuffer_strspn( struct evbuffer_ptr *ptr, const char *chrset)

{
	int count = 0;
	struct evbuffer_chain *chain = ptr->internal_.chain;
	size_t i = ptr->internal_.pos_in_chain;

	if (!chain)
		return 0;

	while (1) {
		char *buffer = (char *)chain->buffer + chain->misalign;
		for (; i < chain->off; ++i) {
			const char *p = chrset;
			while (*p) {
				if (buffer[i] == *p++)
					goto next;
			}
			ptr->internal_.chain = chain;
			ptr->internal_.pos_in_chain = i;
			ptr->pos += count;
			return count;
		next:
			++count;
		}
		i = 0;

		if (! chain->next) {
			ptr->internal_.chain = chain;
			ptr->internal_.pos_in_chain = i;
			ptr->pos += count;
			return count;
		}

		chain = chain->next;
	}
}


static inline int evbuffer_getchr(struct evbuffer_ptr *it)
{
	struct evbuffer_chain *chain = it->internal_.chain;
	size_t off = it->internal_.pos_in_chain;

	if (chain == NULL)
		return -1;

	return (unsigned char)chain->buffer[chain->misalign + off];
}

struct evbuffer_ptr evbuffer_search_eol(struct evbuffer *buffer, struct evbuffer_ptr *start, size_t *eol_len_out, enum evbuffer_eol_style eol_style)


{
	struct evbuffer_ptr it, it2;
	size_t extra_drain = 0;
	int ok = 0;

	
	if (start && start->internal_.chain == NULL) {
		PTR_NOT_FOUND(&it);
		if (eol_len_out)
			*eol_len_out = extra_drain;
		return it;
	}

	EVBUFFER_LOCK(buffer);

	if (start) {
		memcpy(&it, start, sizeof(it));
	} else {
		it.pos = 0;
		it.internal_.chain = buffer->first;
		it.internal_.pos_in_chain = 0;
	}

	
	switch (eol_style) {
	case EVBUFFER_EOL_ANY:
		if (evbuffer_find_eol_char(&it) < 0)
			goto done;
		memcpy(&it2, &it, sizeof(it));
		extra_drain = evbuffer_strspn(&it2, "\r\n");
		break;
	case EVBUFFER_EOL_CRLF_STRICT: {
		it = evbuffer_search(buffer, "\r\n", 2, &it);
		if (it.pos < 0)
			goto done;
		extra_drain = 2;
		break;
	}
	case EVBUFFER_EOL_CRLF: {
		ev_ssize_t start_pos = it.pos;
		
		if (evbuffer_strchr(&it, '\n') < 0)
			goto done;
		extra_drain = 1;
		
		if (it.pos == start_pos)
			break; 
		
		memcpy(&it2, &it, sizeof(it));
		if (evbuffer_ptr_subtract(buffer, &it2, 1)<0)
			break;
		if (evbuffer_getchr(&it2) == '\r') {
			memcpy(&it, &it2, sizeof(it));
			extra_drain = 2;
		}
		break;
	}
	case EVBUFFER_EOL_LF:
		if (evbuffer_strchr(&it, '\n') < 0)
			goto done;
		extra_drain = 1;
		break;
	case EVBUFFER_EOL_NUL:
		if (evbuffer_strchr(&it, '\0') < 0)
			goto done;
		extra_drain = 1;
		break;
	default:
		goto done;
	}

	ok = 1;
done:
	EVBUFFER_UNLOCK(buffer);

	if (!ok)
		PTR_NOT_FOUND(&it);
	if (eol_len_out)
		*eol_len_out = extra_drain;

	return it;
}

char * evbuffer_readln(struct evbuffer *buffer, size_t *n_read_out, enum evbuffer_eol_style eol_style)

{
	struct evbuffer_ptr it;
	char *line;
	size_t n_to_copy=0, extra_drain=0;
	char *result = NULL;

	EVBUFFER_LOCK(buffer);

	if (buffer->freeze_start) {
		goto done;
	}

	it = evbuffer_search_eol(buffer, NULL, &extra_drain, eol_style);
	if (it.pos < 0)
		goto done;
	n_to_copy = it.pos;

	if ((line = mm_malloc(n_to_copy+1)) == NULL) {
		event_warn("%s: out of memory", __func__);
		goto done;
	}

	evbuffer_remove(buffer, line, n_to_copy);
	line[n_to_copy] = '\0';

	evbuffer_drain(buffer, extra_drain);
	result = line;
done:
	EVBUFFER_UNLOCK(buffer);

	if (n_read_out)
		*n_read_out = result ? n_to_copy : 0;

	return result;
}





int evbuffer_add(struct evbuffer *buf, const void *data_in, size_t datlen)
{
	struct evbuffer_chain *chain, *tmp;
	const unsigned char *data = data_in;
	size_t remain, to_alloc;
	int result = -1;

	EVBUFFER_LOCK(buf);

	if (buf->freeze_end) {
		goto done;
	}

	chain = buf->last;

	
	if (chain == NULL) {
		chain = evbuffer_chain_new(datlen);
		if (!chain)
			goto done;
		evbuffer_chain_insert(buf, chain);
	}

	if ((chain->flags & EVBUFFER_IMMUTABLE) == 0) {
		remain = (size_t)(chain->buffer_len - chain->misalign - chain->off);
		if (remain >= datlen) {
			
			memcpy(chain->buffer + chain->misalign + chain->off, data, datlen);
			chain->off += datlen;
			buf->total_len += datlen;
			buf->n_add_for_cb += datlen;
			goto out;
		} else if (!CHAIN_PINNED(chain) && evbuffer_chain_should_realign(chain, datlen)) {
			
			evbuffer_chain_align(chain);

			memcpy(chain->buffer + chain->off, data, datlen);
			chain->off += datlen;
			buf->total_len += datlen;
			buf->n_add_for_cb += datlen;
			goto out;
		}
	} else {
		
		remain = 0;
	}

	
	to_alloc = chain->buffer_len;
	if (to_alloc <= EVBUFFER_CHAIN_MAX_AUTO_SIZE/2)
		to_alloc <<= 1;
	if (datlen > to_alloc)
		to_alloc = datlen;
	tmp = evbuffer_chain_new(to_alloc);
	if (tmp == NULL)
		goto done;

	if (remain) {
		memcpy(chain->buffer + chain->misalign + chain->off, data, remain);
		chain->off += remain;
		buf->total_len += remain;
		buf->n_add_for_cb += remain;
	}

	data += remain;
	datlen -= remain;

	memcpy(tmp->buffer, data, datlen);
	tmp->off = datlen;
	evbuffer_chain_insert(buf, tmp);
	buf->n_add_for_cb += datlen;

out:
	evbuffer_invoke_callbacks_(buf);
	result = 0;
done:
	EVBUFFER_UNLOCK(buf);
	return result;
}

int evbuffer_prepend(struct evbuffer *buf, const void *data, size_t datlen)
{
	struct evbuffer_chain *chain, *tmp;
	int result = -1;

	EVBUFFER_LOCK(buf);

	if (buf->freeze_start) {
		goto done;
	}

	chain = buf->first;

	if (chain == NULL) {
		chain = evbuffer_chain_new(datlen);
		if (!chain)
			goto done;
		evbuffer_chain_insert(buf, chain);
	}

	
	if ((chain->flags & EVBUFFER_IMMUTABLE) == 0) {
		
		if (chain->off == 0)
			chain->misalign = chain->buffer_len;

		if ((size_t)chain->misalign >= datlen) {
			
			memcpy(chain->buffer + chain->misalign - datlen, data, datlen);
			chain->off += datlen;
			chain->misalign -= datlen;
			buf->total_len += datlen;
			buf->n_add_for_cb += datlen;
			goto out;
		} else if (chain->misalign) {
			
			memcpy(chain->buffer, (char*)data + datlen - chain->misalign, (size_t)chain->misalign);

			chain->off += (size_t)chain->misalign;
			buf->total_len += (size_t)chain->misalign;
			buf->n_add_for_cb += (size_t)chain->misalign;
			datlen -= (size_t)chain->misalign;
			chain->misalign = 0;
		}
	}

	
	if ((tmp = evbuffer_chain_new(datlen)) == NULL)
		goto done;
	buf->first = tmp;
	if (buf->last_with_datap == &buf->first)
		buf->last_with_datap = &tmp->next;

	tmp->next = chain;

	tmp->off = datlen;
	tmp->misalign = tmp->buffer_len - datlen;

	memcpy(tmp->buffer + tmp->misalign, data, datlen);
	buf->total_len += datlen;
	buf->n_add_for_cb += (size_t)chain->misalign;

out:
	evbuffer_invoke_callbacks_(buf);
	result = 0;
done:
	EVBUFFER_UNLOCK(buf);
	return result;
}


static void evbuffer_chain_align(struct evbuffer_chain *chain)
{
	EVUTIL_ASSERT(!(chain->flags & EVBUFFER_IMMUTABLE));
	EVUTIL_ASSERT(!(chain->flags & EVBUFFER_MEM_PINNED_ANY));
	memmove(chain->buffer, chain->buffer + chain->misalign, chain->off);
	chain->misalign = 0;
}





static int evbuffer_chain_should_realign(struct evbuffer_chain *chain, size_t datlen)

{
	return chain->buffer_len - chain->off >= datlen && (chain->off < chain->buffer_len / 2) && (chain->off <= MAX_TO_REALIGN_IN_EXPAND);

}


static struct evbuffer_chain * evbuffer_expand_singlechain(struct evbuffer *buf, size_t datlen)
{
	struct evbuffer_chain *chain, **chainp;
	struct evbuffer_chain *result = NULL;
	ASSERT_EVBUFFER_LOCKED(buf);

	chainp = buf->last_with_datap;

	
	if (*chainp && CHAIN_SPACE_LEN(*chainp) == 0)
		chainp = &(*chainp)->next;

	
	chain = *chainp;

	if (chain == NULL || (chain->flags & (EVBUFFER_IMMUTABLE|EVBUFFER_MEM_PINNED_ANY))) {
		
		goto insert_new;
	}

	
	if (CHAIN_SPACE_LEN(chain) >= datlen) {
		result = chain;
		goto ok;
	}

	
	if (chain->off == 0) {
		goto insert_new;
	}

	
	if (evbuffer_chain_should_realign(chain, datlen)) {
		evbuffer_chain_align(chain);
		result = chain;
		goto ok;
	}

	

	
	if (CHAIN_SPACE_LEN(chain) < chain->buffer_len / 8 || chain->off > MAX_TO_COPY_IN_EXPAND) {
		
		if (chain->next && CHAIN_SPACE_LEN(chain->next) >= datlen) {
			
			result = chain->next;
			goto ok;
		} else {
			
			goto insert_new;
		}
	} else {
		
		
		size_t length = chain->off + datlen;
		struct evbuffer_chain *tmp = evbuffer_chain_new(length);
		if (tmp == NULL)
			goto err;

		
		tmp->off = chain->off;
		memcpy(tmp->buffer, chain->buffer + chain->misalign, chain->off);
		
		EVUTIL_ASSERT(*chainp == chain);
		result = *chainp = tmp;

		if (buf->last == chain)
			buf->last = tmp;

		tmp->next = chain->next;
		evbuffer_chain_free(chain);
		goto ok;
	}

insert_new:
	result = evbuffer_chain_insert_new(buf, datlen);
	if (!result)
		goto err;
ok:
	EVUTIL_ASSERT(result);
	EVUTIL_ASSERT(CHAIN_SPACE_LEN(result) >= datlen);
err:
	return result;
}


int evbuffer_expand_fast_(struct evbuffer *buf, size_t datlen, int n)
{
	struct evbuffer_chain *chain = buf->last, *tmp, *next;
	size_t avail;
	int used;

	ASSERT_EVBUFFER_LOCKED(buf);
	EVUTIL_ASSERT(n >= 2);

	if (chain == NULL || (chain->flags & EVBUFFER_IMMUTABLE)) {
		
		chain = evbuffer_chain_new(datlen);
		if (chain == NULL)
			return (-1);

		evbuffer_chain_insert(buf, chain);
		return (0);
	}

	used = 0; 
	avail = 0; 
	
	for (chain = *buf->last_with_datap; chain; chain = chain->next) {
		if (chain->off) {
			size_t space = (size_t) CHAIN_SPACE_LEN(chain);
			EVUTIL_ASSERT(chain == *buf->last_with_datap);
			if (space) {
				avail += space;
				++used;
			}
		} else {
			
			chain->misalign = 0;
			avail += chain->buffer_len;
			++used;
		}
		if (avail >= datlen) {
			
			return (0);
		}
		if (used == n)
			break;
	}

	
	if (used < n) {
		
		EVUTIL_ASSERT(chain == NULL);

		tmp = evbuffer_chain_new(datlen - avail);
		if (tmp == NULL)
			return (-1);

		buf->last->next = tmp;
		buf->last = tmp;
		
		return (0);
	} else {
		
		int rmv_all = 0; 
		chain = *buf->last_with_datap;
		if (!chain->off) {
			EVUTIL_ASSERT(chain == buf->first);
			rmv_all = 1;
			avail = 0;
		} else {
			avail = (size_t) CHAIN_SPACE_LEN(chain);
			chain = chain->next;
		}


		for (; chain; chain = next) {
			next = chain->next;
			EVUTIL_ASSERT(chain->off == 0);
			evbuffer_chain_free(chain);
		}
		tmp = evbuffer_chain_new(datlen - avail);
		if (tmp == NULL) {
			if (rmv_all) {
				ZERO_CHAIN(buf);
			} else {
				buf->last = *buf->last_with_datap;
				(*buf->last_with_datap)->next = NULL;
			}
			return (-1);
		}

		if (rmv_all) {
			buf->first = buf->last = tmp;
			buf->last_with_datap = &buf->first;
		} else {
			(*buf->last_with_datap)->next = tmp;
			buf->last = tmp;
		}
		return (0);
	}
}

int evbuffer_expand(struct evbuffer *buf, size_t datlen)
{
	struct evbuffer_chain *chain;

	EVBUFFER_LOCK(buf);
	chain = evbuffer_expand_singlechain(buf, datlen);
	EVBUFFER_UNLOCK(buf);
	return chain ? 0 : -1;
}







































int evbuffer_read_setup_vecs_(struct evbuffer *buf, ev_ssize_t howmuch, struct evbuffer_iovec *vecs, int n_vecs_avail, struct evbuffer_chain ***chainp, int exact)


{
	struct evbuffer_chain *chain;
	struct evbuffer_chain **firstchainp;
	size_t so_far;
	int i;
	ASSERT_EVBUFFER_LOCKED(buf);

	if (howmuch < 0)
		return -1;

	so_far = 0;
	
	firstchainp = buf->last_with_datap;
	if (CHAIN_SPACE_LEN(*firstchainp) == 0) {
		firstchainp = &(*firstchainp)->next;
	}

	chain = *firstchainp;
	for (i = 0; i < n_vecs_avail && so_far < (size_t)howmuch; ++i) {
		size_t avail = (size_t) CHAIN_SPACE_LEN(chain);
		if (avail > (howmuch - so_far) && exact)
			avail = howmuch - so_far;
		vecs[i].iov_base = CHAIN_SPACE_PTR(chain);
		vecs[i].iov_len = avail;
		so_far += avail;
		chain = chain->next;
	}

	*chainp = firstchainp;
	return i;
}

static int get_n_bytes_readable_on_socket(evutil_socket_t fd)
{

	unsigned long lng = EVBUFFER_MAX_READ;
	if (ioctlsocket(fd, FIONREAD, &lng) < 0)
		return -1;
	return (int)lng;

	int n = EVBUFFER_MAX_READ;
	if (ioctl(fd, FIONREAD, &n) < 0)
		return -1;
	return n;

	return EVBUFFER_MAX_READ;

}


int evbuffer_read(struct evbuffer *buf, evutil_socket_t fd, int howmuch)
{
	struct evbuffer_chain **chainp;
	int n;
	int result;


	int nvecs, i, remaining;

	struct evbuffer_chain *chain;
	unsigned char *p;


	EVBUFFER_LOCK(buf);

	if (buf->freeze_end) {
		result = -1;
		goto done;
	}

	n = get_n_bytes_readable_on_socket(fd);
	if (n <= 0 || n > EVBUFFER_MAX_READ)
		n = EVBUFFER_MAX_READ;
	if (howmuch < 0 || howmuch > n)
		howmuch = n;


	
	if (evbuffer_expand_fast_(buf, howmuch, NUM_READ_IOVEC) == -1) {
		result = -1;
		goto done;
	} else {
		IOV_TYPE vecs[NUM_READ_IOVEC];

		nvecs = evbuffer_read_setup_vecs_(buf, howmuch, vecs, NUM_READ_IOVEC, &chainp, 1);

		
		struct evbuffer_iovec ev_vecs[NUM_READ_IOVEC];
		nvecs = evbuffer_read_setup_vecs_(buf, howmuch, ev_vecs, 2, &chainp, 1);

		for (i=0; i < nvecs; ++i)
			WSABUF_FROM_EVBUFFER_IOV(&vecs[i], &ev_vecs[i]);



		{
			DWORD bytesRead;
			DWORD flags=0;
			if (WSARecv(fd, vecs, nvecs, &bytesRead, &flags, NULL, NULL)) {
				
				if (WSAGetLastError() == WSAECONNABORTED)
					n = 0;
				else n = -1;
			} else n = bytesRead;
		}

		n = readv(fd, vecs, nvecs);

	}


	
	
	if ((chain = evbuffer_expand_singlechain(buf, howmuch)) == NULL) {
		result = -1;
		goto done;
	}

	
	p = chain->buffer + chain->misalign + chain->off;


	n = read(fd, p, howmuch);

	n = recv(fd, p, howmuch, 0);



	if (n == -1) {
		result = -1;
		goto done;
	}
	if (n == 0) {
		result = 0;
		goto done;
	}


	remaining = n;
	for (i=0; i < nvecs; ++i) {
		ev_ssize_t space = (ev_ssize_t) CHAIN_SPACE_LEN(*chainp);
		if (space < remaining) {
			(*chainp)->off += space;
			remaining -= (int)space;
		} else {
			(*chainp)->off += remaining;
			buf->last_with_datap = chainp;
			break;
		}
		chainp = &(*chainp)->next;
	}

	chain->off += n;
	advance_last_with_data(buf);

	buf->total_len += n;
	buf->n_add_for_cb += n;

	
	evbuffer_invoke_callbacks_(buf);
	result = n;
done:
	EVBUFFER_UNLOCK(buf);
	return result;
}


static inline int evbuffer_write_iovec(struct evbuffer *buffer, evutil_socket_t fd, ev_ssize_t howmuch)

{
	IOV_TYPE iov[NUM_WRITE_IOVEC];
	struct evbuffer_chain *chain = buffer->first;
	int n, i = 0;

	if (howmuch < 0)
		return -1;

	ASSERT_EVBUFFER_LOCKED(buffer);
	
	while (chain != NULL && i < NUM_WRITE_IOVEC && howmuch) {

		
		if (chain->flags & EVBUFFER_SENDFILE)
			break;

		iov[i].IOV_PTR_FIELD = (void *) (chain->buffer + chain->misalign);
		if ((size_t)howmuch >= chain->off) {
			
			iov[i++].IOV_LEN_FIELD = (IOV_LEN_TYPE)chain->off;
			howmuch -= chain->off;
		} else {
			
			iov[i++].IOV_LEN_FIELD = (IOV_LEN_TYPE)howmuch;
			break;
		}
		chain = chain->next;
	}
	if (! i)
		return 0;


	{
		DWORD bytesSent;
		if (WSASend(fd, iov, i, &bytesSent, 0, NULL, NULL))
			n = -1;
		else n = bytesSent;
	}

	n = writev(fd, iov, i);

	return (n);
}



static inline int evbuffer_write_sendfile(struct evbuffer *buffer, evutil_socket_t dest_fd, ev_ssize_t howmuch)

{
	struct evbuffer_chain *chain = buffer->first;
	struct evbuffer_chain_file_segment *info = EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_file_segment, chain);

	const int source_fd = info->segment->fd;

	int res;
	ev_off_t len = chain->off;

	ev_ssize_t res;
	ev_off_t offset = chain->misalign;


	ASSERT_EVBUFFER_LOCKED(buffer);


	res = sendfile(source_fd, dest_fd, chain->misalign, &len, NULL, 0);
	if (res == -1 && !EVUTIL_ERR_RW_RETRIABLE(errno))
		return (-1);

	return (len);

	res = sendfile(source_fd, dest_fd, chain->misalign, chain->off, NULL, &len, 0);
	if (res == -1 && !EVUTIL_ERR_RW_RETRIABLE(errno))
		return (-1);

	return (len);

	
	res = sendfile(dest_fd, source_fd, &offset, chain->off);
	if (res == -1 && EVUTIL_ERR_RW_RETRIABLE(errno)) {
		
		return (0);
	}
	return (res);

	{
		const off_t offset_orig = offset;
		res = sendfile(dest_fd, source_fd, &offset, chain->off);
		if (res == -1 && EVUTIL_ERR_RW_RETRIABLE(errno)) {
			if (offset - offset_orig)
				return offset - offset_orig;
			
			return (0);
		}
		return (res);
	}

}


int evbuffer_write_atmost(struct evbuffer *buffer, evutil_socket_t fd, ev_ssize_t howmuch)

{
	int n = -1;

	EVBUFFER_LOCK(buffer);

	if (buffer->freeze_start) {
		goto done;
	}

	if (howmuch < 0 || (size_t)howmuch > buffer->total_len)
		howmuch = buffer->total_len;

	if (howmuch > 0) {

		struct evbuffer_chain *chain = buffer->first;
		if (chain != NULL && (chain->flags & EVBUFFER_SENDFILE))
			n = evbuffer_write_sendfile(buffer, fd, howmuch);
		else {


		n = evbuffer_write_iovec(buffer, fd, howmuch);

		
		void *p = evbuffer_pullup(buffer, howmuch);
		EVUTIL_ASSERT(p || !howmuch);
		n = send(fd, p, howmuch, 0);

		void *p = evbuffer_pullup(buffer, howmuch);
		EVUTIL_ASSERT(p || !howmuch);
		n = write(fd, p, howmuch);


		}

	}

	if (n > 0)
		evbuffer_drain(buffer, n);

done:
	EVBUFFER_UNLOCK(buffer);
	return (n);
}

int evbuffer_write(struct evbuffer *buffer, evutil_socket_t fd)
{
	return evbuffer_write_atmost(buffer, fd, -1);
}

unsigned char * evbuffer_find(struct evbuffer *buffer, const unsigned char *what, size_t len)
{
	unsigned char *search;
	struct evbuffer_ptr ptr;

	EVBUFFER_LOCK(buffer);

	ptr = evbuffer_search(buffer, (const char *)what, len, NULL);
	if (ptr.pos < 0) {
		search = NULL;
	} else {
		search = evbuffer_pullup(buffer, ptr.pos + len);
		if (search)
			search += ptr.pos;
	}
	EVBUFFER_UNLOCK(buffer);
	return search;
}


static int evbuffer_ptr_subtract(struct evbuffer *buf, struct evbuffer_ptr *pos, size_t howfar)

{
	if (howfar > (size_t)pos->pos)
		return -1;
	if (pos->internal_.chain && howfar <= pos->internal_.pos_in_chain) {
		pos->internal_.pos_in_chain -= howfar;
		pos->pos -= howfar;
		return 0;
	} else {
		const size_t newpos = pos->pos - howfar;
		
		return evbuffer_ptr_set(buf, pos, newpos, EVBUFFER_PTR_SET);
	}
}

int evbuffer_ptr_set(struct evbuffer *buf, struct evbuffer_ptr *pos, size_t position, enum evbuffer_ptr_how how)

{
	size_t left = position;
	struct evbuffer_chain *chain = NULL;
	int result = 0;

	EVBUFFER_LOCK(buf);

	switch (how) {
	case EVBUFFER_PTR_SET:
		chain = buf->first;
		pos->pos = position;
		position = 0;
		break;
	case EVBUFFER_PTR_ADD:
		
		chain = pos->internal_.chain;
		pos->pos += position;
		position = pos->internal_.pos_in_chain;
		break;
	}

	while (chain && position + left >= chain->off) {
		left -= chain->off - position;
		chain = chain->next;
		position = 0;
	}
	if (chain) {
		pos->internal_.chain = chain;
		pos->internal_.pos_in_chain = position + left;
	} else if (left == 0) {
		
		pos->internal_.chain = NULL;
		pos->internal_.pos_in_chain = 0;
	} else {
		PTR_NOT_FOUND(pos);
		result = -1;
	}

	EVBUFFER_UNLOCK(buf);

	return result;
}


static int evbuffer_ptr_memcmp(const struct evbuffer *buf, const struct evbuffer_ptr *pos, const char *mem, size_t len)

{
	struct evbuffer_chain *chain;
	size_t position;
	int r;

	ASSERT_EVBUFFER_LOCKED(buf);

	if (pos->pos + len > buf->total_len)
		return -1;

	chain = pos->internal_.chain;
	position = pos->internal_.pos_in_chain;
	while (len && chain) {
		size_t n_comparable;
		if (len + position > chain->off)
			n_comparable = chain->off - position;
		else n_comparable = len;
		r = memcmp(chain->buffer + chain->misalign + position, mem, n_comparable);
		if (r)
			return r;
		mem += n_comparable;
		len -= n_comparable;
		position = 0;
		chain = chain->next;
	}

	return 0;
}

struct evbuffer_ptr evbuffer_search(struct evbuffer *buffer, const char *what, size_t len, const struct evbuffer_ptr *start)
{
	return evbuffer_search_range(buffer, what, len, start, NULL);
}

struct evbuffer_ptr evbuffer_search_range(struct evbuffer *buffer, const char *what, size_t len, const struct evbuffer_ptr *start, const struct evbuffer_ptr *end)
{
	struct evbuffer_ptr pos;
	struct evbuffer_chain *chain, *last_chain = NULL;
	const unsigned char *p;
	char first;

	EVBUFFER_LOCK(buffer);

	if (start) {
		memcpy(&pos, start, sizeof(pos));
		chain = pos.internal_.chain;
	} else {
		pos.pos = 0;
		chain = pos.internal_.chain = buffer->first;
		pos.internal_.pos_in_chain = 0;
	}

	if (end)
		last_chain = end->internal_.chain;

	if (!len || len > EV_SSIZE_MAX)
		goto done;

	first = what[0];

	while (chain) {
		const unsigned char *start_at = chain->buffer + chain->misalign + pos.internal_.pos_in_chain;

		p = memchr(start_at, first, chain->off - pos.internal_.pos_in_chain);
		if (p) {
			pos.pos += p - start_at;
			pos.internal_.pos_in_chain += p - start_at;
			if (!evbuffer_ptr_memcmp(buffer, &pos, what, len)) {
				if (end && pos.pos + (ev_ssize_t)len > end->pos)
					goto not_found;
				else goto done;
			}
			++pos.pos;
			++pos.internal_.pos_in_chain;
			if (pos.internal_.pos_in_chain == chain->off) {
				chain = pos.internal_.chain = chain->next;
				pos.internal_.pos_in_chain = 0;
			}
		} else {
			if (chain == last_chain)
				goto not_found;
			pos.pos += chain->off - pos.internal_.pos_in_chain;
			chain = pos.internal_.chain = chain->next;
			pos.internal_.pos_in_chain = 0;
		}
	}

not_found:
	PTR_NOT_FOUND(&pos);
done:
	EVBUFFER_UNLOCK(buffer);
	return pos;
}

int evbuffer_peek(struct evbuffer *buffer, ev_ssize_t len, struct evbuffer_ptr *start_at, struct evbuffer_iovec *vec, int n_vec)


{
	struct evbuffer_chain *chain;
	int idx = 0;
	ev_ssize_t len_so_far = 0;

	
	if (start_at && start_at->internal_.chain == NULL)
		return 0;

	EVBUFFER_LOCK(buffer);

	if (start_at) {
		chain = start_at->internal_.chain;
		len_so_far = chain->off - start_at->internal_.pos_in_chain;
		idx = 1;
		if (n_vec > 0) {
			vec[0].iov_base = chain->buffer + chain->misalign + start_at->internal_.pos_in_chain;
			vec[0].iov_len = len_so_far;
		}
		chain = chain->next;
	} else {
		chain = buffer->first;
	}

	if (n_vec == 0 && len < 0) {
		
		len = buffer->total_len;
		if (start_at) {
			len -= start_at->pos;
		}
	}

	while (chain) {
		if (len >= 0 && len_so_far >= len)
			break;
		if (idx<n_vec) {
			vec[idx].iov_base = chain->buffer + chain->misalign;
			vec[idx].iov_len = chain->off;
		} else if (len<0) {
			break;
		}
		++idx;
		len_so_far += chain->off;
		chain = chain->next;
	}

	EVBUFFER_UNLOCK(buffer);

	return idx;
}


int evbuffer_add_vprintf(struct evbuffer *buf, const char *fmt, va_list ap)
{
	char *buffer;
	size_t space;
	int sz, result = -1;
	va_list aq;
	struct evbuffer_chain *chain;


	EVBUFFER_LOCK(buf);

	if (buf->freeze_end) {
		goto done;
	}

	
	if ((chain = evbuffer_expand_singlechain(buf, 64)) == NULL)
		goto done;

	for (;;) {

		size_t used = chain->misalign + chain->off;
		buffer = (char *)chain->buffer + chain->misalign + chain->off;
		EVUTIL_ASSERT(chain->buffer_len >= used);
		space = chain->buffer_len - used;

		buffer = (char*) CHAIN_SPACE_PTR(chain);
		space = (size_t) CHAIN_SPACE_LEN(chain);




		va_copy(aq, ap);

		sz = evutil_vsnprintf(buffer, space, fmt, aq);

		va_end(aq);

		if (sz < 0)
			goto done;
		if ((size_t)sz < space) {
			chain->off += sz;
			buf->total_len += sz;
			buf->n_add_for_cb += sz;

			advance_last_with_data(buf);
			evbuffer_invoke_callbacks_(buf);
			result = sz;
			goto done;
		}
		if ((chain = evbuffer_expand_singlechain(buf, sz + 1)) == NULL)
			goto done;
	}
	

done:
	EVBUFFER_UNLOCK(buf);
	return result;
}

int evbuffer_add_printf(struct evbuffer *buf, const char *fmt, ...)
{
	int res = -1;
	va_list ap;

	va_start(ap, fmt);
	res = evbuffer_add_vprintf(buf, fmt, ap);
	va_end(ap);

	return (res);
}

int evbuffer_add_reference(struct evbuffer *outbuf, const void *data, size_t datlen, evbuffer_ref_cleanup_cb cleanupfn, void *extra)


{
	struct evbuffer_chain *chain;
	struct evbuffer_chain_reference *info;
	int result = -1;

	chain = evbuffer_chain_new(sizeof(struct evbuffer_chain_reference));
	if (!chain)
		return (-1);
	chain->flags |= EVBUFFER_REFERENCE | EVBUFFER_IMMUTABLE;
	chain->buffer = (u_char *)data;
	chain->buffer_len = datlen;
	chain->off = datlen;

	info = EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_reference, chain);
	info->cleanupfn = cleanupfn;
	info->extra = extra;

	EVBUFFER_LOCK(outbuf);
	if (outbuf->freeze_end) {
		
		mm_free(chain);
		goto done;
	}
	evbuffer_chain_insert(outbuf, chain);
	outbuf->n_add_for_cb += datlen;

	evbuffer_invoke_callbacks_(outbuf);

	result = 0;
done:
	EVBUFFER_UNLOCK(outbuf);

	return result;
}


struct evbuffer_file_segment * evbuffer_file_segment_new( int fd, ev_off_t offset, ev_off_t length, unsigned flags)

{
	struct evbuffer_file_segment *seg = mm_calloc(sizeof(struct evbuffer_file_segment), 1);
	if (!seg)
		return NULL;
	seg->refcnt = 1;
	seg->fd = fd;
	seg->flags = flags;
	seg->file_offset = offset;
	seg->cleanup_cb = NULL;
	seg->cleanup_cb_arg = NULL;











	if (length == -1) {
		struct stat st;
		if (fstat(fd, &st) < 0)
			goto err;
		length = st.st_size;
	}
	seg->length = length;


	if (!(flags & EVBUF_FS_DISABLE_SENDFILE)) {
		seg->can_sendfile = 1;
		goto done;
	}


	if (evbuffer_file_segment_materialize(seg)<0)
		goto err;


done:

	if (!(flags & EVBUF_FS_DISABLE_LOCKING)) {
		EVTHREAD_ALLOC_LOCK(seg->lock, 0);
	}
	return seg;
err:
	mm_free(seg);
	return NULL;
}


static long get_page_size(void)
{

	return sysconf(SC_PAGE_SIZE);

	return sysconf(_SC_PAGE_SIZE);

	return 1;

}




static int evbuffer_file_segment_materialize(struct evbuffer_file_segment *seg)
{
	const unsigned flags = seg->flags;
	const int fd = seg->fd;
	const ev_off_t length = seg->length;
	const ev_off_t offset = seg->file_offset;

	if (seg->contents)
		return 0; 


	if (!(flags & EVBUF_FS_DISABLE_MMAP)) {
		off_t offset_rounded = 0, offset_leftover = 0;
		void *mapped;
		if (offset) {
			
			long page_size = get_page_size();
			if (page_size == -1)
				goto err;
			offset_leftover = offset % page_size;
			offset_rounded = offset - offset_leftover;
		}
		mapped = mmap(NULL, length + offset_leftover, PROT_READ,  MAP_NOCACHE |   MAP_FILE |  MAP_PRIVATE, fd, offset_rounded);








		if (mapped == MAP_FAILED) {
			event_warn("%s: mmap(%d, %d, %zu) failed", __func__, fd, 0, (size_t)(offset + length));
		} else {
			seg->mapping = mapped;
			seg->contents = (char*)mapped+offset_leftover;
			seg->mmap_offset = 0;
			seg->is_mapping = 1;
			goto done;
		}
	}


	if (!(flags & EVBUF_FS_DISABLE_MMAP)) {
		intptr_t h = _get_osfhandle(fd);
		HANDLE m;
		ev_uint64_t total_size = length+offset;
		if ((HANDLE)h == INVALID_HANDLE_VALUE)
			goto err;
		m = CreateFileMapping((HANDLE)h, NULL, PAGE_READONLY, (total_size >> 32), total_size & 0xfffffffful, NULL);

		if (m != INVALID_HANDLE_VALUE) { 
			seg->mapping_handle = m;
			seg->mmap_offset = offset;
			seg->is_mapping = 1;
			goto done;
		}
	}

	{
		ev_off_t start_pos = lseek(fd, 0, SEEK_CUR), pos;
		ev_off_t read_so_far = 0;
		char *mem;
		int e;
		ev_ssize_t n = 0;
		if (!(mem = mm_malloc(length)))
			goto err;
		if (start_pos < 0) {
			mm_free(mem);
			goto err;
		}
		if (lseek(fd, offset, SEEK_SET) < 0) {
			mm_free(mem);
			goto err;
		}
		while (read_so_far < length) {
			n = read(fd, mem+read_so_far, length-read_so_far);
			if (n <= 0)
				break;
			read_so_far += n;
		}

		e = errno;
		pos = lseek(fd, start_pos, SEEK_SET);
		if (n < 0 || (n == 0 && length > read_so_far)) {
			mm_free(mem);
			errno = e;
			goto err;
		} else if (pos < 0) {
			mm_free(mem);
			goto err;
		}

		seg->contents = mem;
	}

done:
	return 0;
err:
	return -1;
}

void evbuffer_file_segment_add_cleanup_cb(struct evbuffer_file_segment *seg, evbuffer_file_segment_cleanup_cb cb, void* arg)
{
	EVUTIL_ASSERT(seg->refcnt > 0);
	seg->cleanup_cb = cb;
	seg->cleanup_cb_arg = arg;
}

void evbuffer_file_segment_free(struct evbuffer_file_segment *seg)
{
	int refcnt;
	EVLOCK_LOCK(seg->lock, 0);
	refcnt = --seg->refcnt;
	EVLOCK_UNLOCK(seg->lock, 0);
	if (refcnt > 0)
		return;
	EVUTIL_ASSERT(refcnt == 0);

	if (seg->is_mapping) {

		CloseHandle(seg->mapping_handle);

		off_t offset_leftover;
		offset_leftover = seg->file_offset % get_page_size();
		if (munmap(seg->mapping, seg->length + offset_leftover) == -1)
			event_warn("%s: munmap failed", __func__);

	} else if (seg->contents) {
		mm_free(seg->contents);
	}

	if ((seg->flags & EVBUF_FS_CLOSE_ON_FREE) && seg->fd >= 0) {
		close(seg->fd);
	}
	
	if (seg->cleanup_cb) {
		(*seg->cleanup_cb)((struct evbuffer_file_segment const*)seg,  seg->flags, seg->cleanup_cb_arg);
		seg->cleanup_cb = NULL;
		seg->cleanup_cb_arg = NULL;
	}

	EVTHREAD_FREE_LOCK(seg->lock, 0);
	mm_free(seg);
}

int evbuffer_add_file_segment(struct evbuffer *buf, struct evbuffer_file_segment *seg, ev_off_t offset, ev_off_t length)

{
	struct evbuffer_chain *chain;
	struct evbuffer_chain_file_segment *extra;
	int can_use_sendfile = 0;

	EVBUFFER_LOCK(buf);
	EVLOCK_LOCK(seg->lock, 0);
	if (buf->flags & EVBUFFER_FLAG_DRAINS_TO_FD) {
		can_use_sendfile = 1;
	} else {
		if (!seg->contents) {
			if (evbuffer_file_segment_materialize(seg)<0) {
				EVLOCK_UNLOCK(seg->lock, 0);
				EVBUFFER_UNLOCK(buf);
				return -1;
			}
		}
	}
	++seg->refcnt;
	EVLOCK_UNLOCK(seg->lock, 0);

	if (buf->freeze_end)
		goto err;

	if (length < 0) {
		if (offset > seg->length)
			goto err;
		length = seg->length - offset;
	}

	
	if (offset+length > seg->length)
		goto err;

	chain = evbuffer_chain_new(sizeof(struct evbuffer_chain_file_segment));
	if (!chain)
		goto err;
	extra = EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_file_segment, chain);

	chain->flags |= EVBUFFER_IMMUTABLE|EVBUFFER_FILESEGMENT;
	if (can_use_sendfile && seg->can_sendfile) {
		chain->flags |= EVBUFFER_SENDFILE;
		chain->misalign = seg->file_offset + offset;
		chain->off = length;
		chain->buffer_len = chain->misalign + length;
	} else if (seg->is_mapping) {

		ev_uint64_t total_offset = seg->mmap_offset+offset;
		ev_uint64_t offset_rounded=0, offset_remaining=0;
		LPVOID data;
		if (total_offset) {
			SYSTEM_INFO si;
			memset(&si, 0, sizeof(si)); 
			GetSystemInfo(&si);
			offset_remaining = total_offset % si.dwAllocationGranularity;
			offset_rounded = total_offset - offset_remaining;
		}
		data = MapViewOfFile( seg->mapping_handle, FILE_MAP_READ, offset_rounded >> 32, offset_rounded & 0xfffffffful, length + offset_remaining);




		if (data == NULL) {
			mm_free(chain);
			goto err;
		}
		chain->buffer = (unsigned char*) data;
		chain->buffer_len = length+offset_remaining;
		chain->misalign = offset_remaining;
		chain->off = length;

		chain->buffer = (unsigned char*)(seg->contents + offset);
		chain->buffer_len = length;
		chain->off = length;

	} else {
		chain->buffer = (unsigned char*)(seg->contents + offset);
		chain->buffer_len = length;
		chain->off = length;
	}

	extra->segment = seg;
	buf->n_add_for_cb += length;
	evbuffer_chain_insert(buf, chain);

	evbuffer_invoke_callbacks_(buf);

	EVBUFFER_UNLOCK(buf);

	return 0;
err:
	EVBUFFER_UNLOCK(buf);
	evbuffer_file_segment_free(seg); 
	return -1;
}

int evbuffer_add_file(struct evbuffer *buf, int fd, ev_off_t offset, ev_off_t length)
{
	struct evbuffer_file_segment *seg;
	unsigned flags = EVBUF_FS_CLOSE_ON_FREE;
	int r;

	seg = evbuffer_file_segment_new(fd, offset, length, flags);
	if (!seg)
		return -1;
	r = evbuffer_add_file_segment(buf, seg, 0, length);
	if (r == 0)
		evbuffer_file_segment_free(seg);
	return r;
}

void evbuffer_setcb(struct evbuffer *buffer, evbuffer_cb cb, void *cbarg)
{
	EVBUFFER_LOCK(buffer);

	if (!LIST_EMPTY(&buffer->callbacks))
		evbuffer_remove_all_callbacks(buffer);

	if (cb) {
		struct evbuffer_cb_entry *ent = evbuffer_add_cb(buffer, NULL, cbarg);
		ent->cb.cb_obsolete = cb;
		ent->flags |= EVBUFFER_CB_OBSOLETE;
	}
	EVBUFFER_UNLOCK(buffer);
}

struct evbuffer_cb_entry * evbuffer_add_cb(struct evbuffer *buffer, evbuffer_cb_func cb, void *cbarg)
{
	struct evbuffer_cb_entry *e;
	if (! (e = mm_calloc(1, sizeof(struct evbuffer_cb_entry))))
		return NULL;
	EVBUFFER_LOCK(buffer);
	e->cb.cb_func = cb;
	e->cbarg = cbarg;
	e->flags = EVBUFFER_CB_ENABLED;
	LIST_INSERT_HEAD(&buffer->callbacks, e, next);
	EVBUFFER_UNLOCK(buffer);
	return e;
}

int evbuffer_remove_cb_entry(struct evbuffer *buffer, struct evbuffer_cb_entry *ent)

{
	EVBUFFER_LOCK(buffer);
	LIST_REMOVE(ent, next);
	EVBUFFER_UNLOCK(buffer);
	mm_free(ent);
	return 0;
}

int evbuffer_remove_cb(struct evbuffer *buffer, evbuffer_cb_func cb, void *cbarg)
{
	struct evbuffer_cb_entry *cbent;
	int result = -1;
	EVBUFFER_LOCK(buffer);
	LIST_FOREACH(cbent, &buffer->callbacks, next) {
		if (cb == cbent->cb.cb_func && cbarg == cbent->cbarg) {
			result = evbuffer_remove_cb_entry(buffer, cbent);
			goto done;
		}
	}
done:
	EVBUFFER_UNLOCK(buffer);
	return result;
}

int evbuffer_cb_set_flags(struct evbuffer *buffer, struct evbuffer_cb_entry *cb, ev_uint32_t flags)

{
	
	flags &= ~EVBUFFER_CB_INTERNAL_FLAGS;
	EVBUFFER_LOCK(buffer);
	cb->flags |= flags;
	EVBUFFER_UNLOCK(buffer);
	return 0;
}

int evbuffer_cb_clear_flags(struct evbuffer *buffer, struct evbuffer_cb_entry *cb, ev_uint32_t flags)

{
	
	flags &= ~EVBUFFER_CB_INTERNAL_FLAGS;
	EVBUFFER_LOCK(buffer);
	cb->flags &= ~flags;
	EVBUFFER_UNLOCK(buffer);
	return 0;
}

int evbuffer_freeze(struct evbuffer *buffer, int start)
{
	EVBUFFER_LOCK(buffer);
	if (start)
		buffer->freeze_start = 1;
	else buffer->freeze_end = 1;
	EVBUFFER_UNLOCK(buffer);
	return 0;
}

int evbuffer_unfreeze(struct evbuffer *buffer, int start)
{
	EVBUFFER_LOCK(buffer);
	if (start)
		buffer->freeze_start = 0;
	else buffer->freeze_end = 0;
	EVBUFFER_UNLOCK(buffer);
	return 0;
}


void evbuffer_cb_suspend(struct evbuffer *buffer, struct evbuffer_cb_entry *cb)
{
	if (!(cb->flags & EVBUFFER_CB_SUSPENDED)) {
		cb->size_before_suspend = evbuffer_get_length(buffer);
		cb->flags |= EVBUFFER_CB_SUSPENDED;
	}
}

void evbuffer_cb_unsuspend(struct evbuffer *buffer, struct evbuffer_cb_entry *cb)
{
	if ((cb->flags & EVBUFFER_CB_SUSPENDED)) {
		unsigned call = (cb->flags & EVBUFFER_CB_CALL_ON_UNSUSPEND);
		size_t sz = cb->size_before_suspend;
		cb->flags &= ~(EVBUFFER_CB_SUSPENDED| EVBUFFER_CB_CALL_ON_UNSUSPEND);
		cb->size_before_suspend = 0;
		if (call && (cb->flags & EVBUFFER_CB_ENABLED)) {
			cb->cb(buffer, sz, evbuffer_get_length(buffer), cb->cbarg);
		}
	}
}


int evbuffer_get_callbacks_(struct evbuffer *buffer, struct event_callback **cbs, int max_cbs)

{
	int r = 0;
	EVBUFFER_LOCK(buffer);
	if (buffer->deferred_cbs) {
		if (max_cbs < 1) {
			r = -1;
			goto done;
		}
		cbs[0] = &buffer->deferred;
		r = 1;
	}
done:
	EVBUFFER_UNLOCK(buffer);
	return r;
}
