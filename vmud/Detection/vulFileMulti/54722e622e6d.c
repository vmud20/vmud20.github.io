


























static int sctp_writeable(struct sock *sk);
static void sctp_wfree(struct sk_buff *skb);
static int sctp_wait_for_sndbuf(struct sctp_association *, long *timeo_p, size_t msg_len);
static int sctp_wait_for_packet(struct sock * sk, int *err, long *timeo_p);
static int sctp_wait_for_connect(struct sctp_association *, long *timeo_p);
static int sctp_wait_for_accept(struct sock *sk, long timeo);
static void sctp_wait_for_close(struct sock *sk, long timeo);
static struct sctp_af *sctp_sockaddr_af(struct sctp_sock *opt, union sctp_addr *addr, int len);
static int sctp_bindx_add(struct sock *, struct sockaddr *, int);
static int sctp_bindx_rem(struct sock *, struct sockaddr *, int);
static int sctp_send_asconf_add_ip(struct sock *, struct sockaddr *, int);
static int sctp_send_asconf_del_ip(struct sock *, struct sockaddr *, int);
static int sctp_send_asconf(struct sctp_association *asoc, struct sctp_chunk *chunk);
static int sctp_do_bind(struct sock *, union sctp_addr *, int);
static int sctp_autobind(struct sock *sk);
static void sctp_sock_migrate(struct sock *, struct sock *, struct sctp_association *, sctp_socket_type_t);
static char *sctp_hmac_alg = SCTP_COOKIE_HMAC_ALG;

extern kmem_cache_t *sctp_bucket_cachep;


static inline int sctp_wspace(struct sctp_association *asoc)
{
	struct sock *sk = asoc->base.sk;
	int amt = 0;

	if (asoc->ep->sndbuf_policy) {
		
		amt = sk->sk_sndbuf - asoc->sndbuf_used;
	} else {
		
		amt = sk->sk_sndbuf - atomic_read(&sk->sk_wmem_alloc);
	}

	if (amt < 0)
		amt = 0;

	return amt;
}


static inline void sctp_set_owner_w(struct sctp_chunk *chunk)
{
	struct sctp_association *asoc = chunk->asoc;
	struct sock *sk = asoc->base.sk;

	
	sctp_association_hold(asoc);

	skb_set_owner_w(chunk->skb, sk);

	chunk->skb->destructor = sctp_wfree;
	
	*((struct sctp_chunk **)(chunk->skb->cb)) = chunk;

	asoc->sndbuf_used += SCTP_DATA_SNDSIZE(chunk) + sizeof(struct sk_buff) + sizeof(struct sctp_chunk);


	atomic_add(sizeof(struct sctp_chunk), &sk->sk_wmem_alloc);
}


static inline int sctp_verify_addr(struct sock *sk, union sctp_addr *addr, int len)
{
	struct sctp_af *af;

	
	af = sctp_sockaddr_af(sctp_sk(sk), addr, len);
	if (!af)
		return -EINVAL;

	
	if (!af->addr_valid(addr, sctp_sk(sk), NULL))
		return -EINVAL;

	if (!sctp_sk(sk)->pf->send_verify(sctp_sk(sk), (addr)))
		return -EINVAL;

	return 0;
}


struct sctp_association *sctp_id2assoc(struct sock *sk, sctp_assoc_t id)
{
	struct sctp_association *asoc = NULL;

	
	if (!sctp_style(sk, UDP)) {
		
		if (!sctp_sstate(sk, ESTABLISHED))
			return NULL;

		
		if (!list_empty(&sctp_sk(sk)->ep->asocs))
			asoc = list_entry(sctp_sk(sk)->ep->asocs.next, struct sctp_association, asocs);
		return asoc;
	}

	
	if (!id || (id == (sctp_assoc_t)-1))
		return NULL;

	spin_lock_bh(&sctp_assocs_id_lock);
	asoc = (struct sctp_association *)idr_find(&sctp_assocs_id, (int)id);
	spin_unlock_bh(&sctp_assocs_id_lock);

	if (!asoc || (asoc->base.sk != sk) || asoc->base.dead)
		return NULL;

	return asoc;
}


static struct sctp_transport *sctp_addr_id2transport(struct sock *sk, struct sockaddr_storage *addr, sctp_assoc_t id)

{
	struct sctp_association *addr_asoc = NULL, *id_asoc = NULL;
	struct sctp_transport *transport;
	union sctp_addr *laddr = (union sctp_addr *)addr;

	laddr->v4.sin_port = ntohs(laddr->v4.sin_port);
	addr_asoc = sctp_endpoint_lookup_assoc(sctp_sk(sk)->ep, (union sctp_addr *)addr, &transport);

	laddr->v4.sin_port = htons(laddr->v4.sin_port);

	if (!addr_asoc)
		return NULL;

	id_asoc = sctp_id2assoc(sk, id);
	if (id_asoc && (id_asoc != addr_asoc))
		return NULL;

	sctp_get_pf_specific(sk->sk_family)->addr_v4map(sctp_sk(sk), (union sctp_addr *)addr);

	return transport;
}


SCTP_STATIC int sctp_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	int retval = 0;

	sctp_lock_sock(sk);

	SCTP_DEBUG_PRINTK("sctp_bind(sk: %p, addr: %p, addr_len: %d)\n", sk, addr, addr_len);

	
	if (!sctp_sk(sk)->ep->base.bind_addr.port)
		retval = sctp_do_bind(sk, (union sctp_addr *)addr, addr_len);
	else retval = -EINVAL;

	sctp_release_sock(sk);

	return retval;
}

static long sctp_get_port_local(struct sock *, union sctp_addr *);


static struct sctp_af *sctp_sockaddr_af(struct sctp_sock *opt, union sctp_addr *addr, int len)
{
	struct sctp_af *af;

	
	if (len < sizeof (struct sockaddr))
		return NULL;

	
	if (!opt->pf->af_supported(addr->sa.sa_family, opt))
		return NULL;

	
	af = sctp_get_af_specific(addr->sa.sa_family);

	if (len < af->sockaddr_len)
		return NULL;

	return af;
}


SCTP_STATIC int sctp_do_bind(struct sock *sk, union sctp_addr *addr, int len)
{
	struct sctp_sock *sp = sctp_sk(sk);
	struct sctp_endpoint *ep = sp->ep;
	struct sctp_bind_addr *bp = &ep->base.bind_addr;
	struct sctp_af *af;
	unsigned short snum;
	int ret = 0;

	
	af = sctp_sockaddr_af(sp, addr, len);
	if (!af) {
		SCTP_DEBUG_PRINTK("sctp_do_bind(sk: %p, newaddr: %p, len: %d) EINVAL\n", sk, addr, len);
		return -EINVAL;
	}

	snum = ntohs(addr->v4.sin_port);

	SCTP_DEBUG_PRINTK_IPADDR("sctp_do_bind(sk: %p, new addr: ", ", port: %d, new port: %d, len: %d)\n", sk, addr, bp->port, snum, len);





	
	if (!sp->pf->bind_verify(sp, addr))
		return -EADDRNOTAVAIL;

	
	if (bp->port && (snum != bp->port)) {
		SCTP_DEBUG_PRINTK("sctp_do_bind:" " New port %d does not match existing port " "%d.\n", snum, bp->port);

		return -EINVAL;
	}

	if (snum && snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		return -EACCES;

	
	if ((ret = sctp_get_port_local(sk, addr))) {
		if (ret == (long) sk) {
			
			return -EINVAL;
		} else {
			return -EADDRINUSE;
		}
	}

	
	if (!bp->port)
		bp->port = inet_sk(sk)->num;

	
	sctp_local_bh_disable();
	sctp_write_lock(&ep->base.addr_lock);

	
	addr->v4.sin_port = ntohs(addr->v4.sin_port);
	ret = sctp_add_bind_addr(bp, addr, 1, GFP_ATOMIC);
	addr->v4.sin_port = htons(addr->v4.sin_port);
	sctp_write_unlock(&ep->base.addr_lock);
	sctp_local_bh_enable();

	
	if (!ret) {
		inet_sk(sk)->sport = htons(inet_sk(sk)->num);
		af->to_sk_saddr(addr, sk);
	}

	return ret;
}

 
static int sctp_send_asconf(struct sctp_association *asoc, struct sctp_chunk *chunk)
{
	int		retval = 0;

		
	if (asoc->addip_last_asconf) {
		list_add_tail(&chunk->list, &asoc->addip_chunk_list);
		goto out;	
	}

	
	sctp_chunk_hold(chunk);
	retval = sctp_primitive_ASCONF(asoc, chunk);
	if (retval)
		sctp_chunk_free(chunk);
	else asoc->addip_last_asconf = chunk;

out:
	return retval;
}


int sctp_bindx_add(struct sock *sk, struct sockaddr *addrs, int addrcnt)
{
	int cnt;
	int retval = 0;
	void *addr_buf;
	struct sockaddr *sa_addr;
	struct sctp_af *af;

	SCTP_DEBUG_PRINTK("sctp_bindx_add (sk: %p, addrs: %p, addrcnt: %d)\n", sk, addrs, addrcnt);

	addr_buf = addrs;
	for (cnt = 0; cnt < addrcnt; cnt++) {
		
		sa_addr = (struct sockaddr *)addr_buf;
		af = sctp_get_af_specific(sa_addr->sa_family);
		if (!af) {
			retval = -EINVAL;
			goto err_bindx_add;
		}

		retval = sctp_do_bind(sk, (union sctp_addr *)sa_addr,  af->sockaddr_len);

		addr_buf += af->sockaddr_len;

err_bindx_add:
		if (retval < 0) {
			
			if (cnt > 0)
				sctp_bindx_rem(sk, addrs, cnt);
			return retval;
		}
	}

	return retval;
}


static int sctp_send_asconf_add_ip(struct sock		*sk,  struct sockaddr	*addrs, int 			addrcnt)

{
	struct sctp_sock		*sp;
	struct sctp_endpoint		*ep;
	struct sctp_association		*asoc;
	struct sctp_bind_addr		*bp;
	struct sctp_chunk		*chunk;
	struct sctp_sockaddr_entry	*laddr;
	union sctp_addr			*addr;
	union sctp_addr			saveaddr;
	void				*addr_buf;
	struct sctp_af			*af;
	struct list_head		*pos;
	struct list_head		*p;
	int 				i;
	int 				retval = 0;

	if (!sctp_addip_enable)
		return retval;

	sp = sctp_sk(sk);
	ep = sp->ep;

	SCTP_DEBUG_PRINTK("%s: (sk: %p, addrs: %p, addrcnt: %d)\n", __FUNCTION__, sk, addrs, addrcnt);

	list_for_each(pos, &ep->asocs) {
		asoc = list_entry(pos, struct sctp_association, asocs);

		if (!asoc->peer.asconf_capable)
			continue;

		if (asoc->peer.addip_disabled_mask & SCTP_PARAM_ADD_IP)
			continue;

		if (!sctp_state(asoc, ESTABLISHED))
			continue;

		
		addr_buf = addrs;
		for (i = 0; i < addrcnt; i++) {
			addr = (union sctp_addr *)addr_buf;
			af = sctp_get_af_specific(addr->v4.sin_family);
			if (!af) {
				retval = -EINVAL;
				goto out;
			}

			if (sctp_assoc_lookup_laddr(asoc, addr))
				break;

			addr_buf += af->sockaddr_len;
		}
		if (i < addrcnt)
			continue;

		
		sctp_read_lock(&asoc->base.addr_lock);
		bp = &asoc->base.bind_addr;
		p = bp->address_list.next;
		laddr = list_entry(p, struct sctp_sockaddr_entry, list);
		sctp_read_unlock(&asoc->base.addr_lock);

		chunk = sctp_make_asconf_update_ip(asoc, &laddr->a, addrs, addrcnt, SCTP_PARAM_ADD_IP);
		if (!chunk) {
			retval = -ENOMEM;
			goto out;
		}

		retval = sctp_send_asconf(asoc, chunk);
		if (retval)
			goto out;

		
		sctp_local_bh_disable();
		sctp_write_lock(&asoc->base.addr_lock);
		addr_buf = addrs;
		for (i = 0; i < addrcnt; i++) {
			addr = (union sctp_addr *)addr_buf;
			af = sctp_get_af_specific(addr->v4.sin_family);
			memcpy(&saveaddr, addr, af->sockaddr_len);
			saveaddr.v4.sin_port = ntohs(saveaddr.v4.sin_port);
			retval = sctp_add_bind_addr(bp, &saveaddr, 0, GFP_ATOMIC);
			addr_buf += af->sockaddr_len;
		}
		sctp_write_unlock(&asoc->base.addr_lock);
		sctp_local_bh_enable();
	}

out:
	return retval;
}


int sctp_bindx_rem(struct sock *sk, struct sockaddr *addrs, int addrcnt)
{
	struct sctp_sock *sp = sctp_sk(sk);
	struct sctp_endpoint *ep = sp->ep;
	int cnt;
	struct sctp_bind_addr *bp = &ep->base.bind_addr;
	int retval = 0;
	union sctp_addr saveaddr;
	void *addr_buf;
	struct sockaddr *sa_addr;
	struct sctp_af *af;

	SCTP_DEBUG_PRINTK("sctp_bindx_rem (sk: %p, addrs: %p, addrcnt: %d)\n", sk, addrs, addrcnt);

	addr_buf = addrs;
	for (cnt = 0; cnt < addrcnt; cnt++) {
		
		if (list_empty(&bp->address_list) || (sctp_list_single_entry(&bp->address_list))) {
			retval = -EBUSY;
			goto err_bindx_rem;
		}

		
		sa_addr = (struct sockaddr *)addr_buf;
		af = sctp_get_af_specific(sa_addr->sa_family);
		if (!af) {
			retval = -EINVAL;
			goto err_bindx_rem;
		}
		memcpy(&saveaddr, sa_addr, af->sockaddr_len); 
		saveaddr.v4.sin_port = ntohs(saveaddr.v4.sin_port);
		if (saveaddr.v4.sin_port != bp->port) {
			retval = -EINVAL;
			goto err_bindx_rem;
		}

		
		sctp_local_bh_disable();
		sctp_write_lock(&ep->base.addr_lock);

		retval = sctp_del_bind_addr(bp, &saveaddr);

		sctp_write_unlock(&ep->base.addr_lock);
		sctp_local_bh_enable();

		addr_buf += af->sockaddr_len;
err_bindx_rem:
		if (retval < 0) {
			
			if (cnt > 0)
				sctp_bindx_add(sk, addrs, cnt);
			return retval;
		}
	}

	return retval;
}


static int sctp_send_asconf_del_ip(struct sock		*sk, struct sockaddr	*addrs, int			addrcnt)

{
	struct sctp_sock	*sp;
	struct sctp_endpoint	*ep;
	struct sctp_association	*asoc;
	struct sctp_transport	*transport;
	struct sctp_bind_addr	*bp;
	struct sctp_chunk	*chunk;
	union sctp_addr		*laddr;
	union sctp_addr		saveaddr;
	void			*addr_buf;
	struct sctp_af		*af;
	struct list_head	*pos, *pos1;
	struct sctp_sockaddr_entry *saddr;
	int 			i;
	int 			retval = 0;

	if (!sctp_addip_enable)
		return retval;

	sp = sctp_sk(sk);
	ep = sp->ep;

	SCTP_DEBUG_PRINTK("%s: (sk: %p, addrs: %p, addrcnt: %d)\n", __FUNCTION__, sk, addrs, addrcnt);

	list_for_each(pos, &ep->asocs) {
		asoc = list_entry(pos, struct sctp_association, asocs);

		if (!asoc->peer.asconf_capable)
			continue;

		if (asoc->peer.addip_disabled_mask & SCTP_PARAM_DEL_IP)
			continue;

		if (!sctp_state(asoc, ESTABLISHED))
			continue;

		
		addr_buf = addrs;
		for (i = 0; i < addrcnt; i++) {
			laddr = (union sctp_addr *)addr_buf;
			af = sctp_get_af_specific(laddr->v4.sin_family);
			if (!af) {
				retval = -EINVAL;
				goto out;
			}

			if (!sctp_assoc_lookup_laddr(asoc, laddr))
				break;

			addr_buf += af->sockaddr_len;
		}
		if (i < addrcnt)
			continue;

		
		sctp_read_lock(&asoc->base.addr_lock);
		bp = &asoc->base.bind_addr;
		laddr = sctp_find_unmatch_addr(bp, (union sctp_addr *)addrs, addrcnt, sp);
		sctp_read_unlock(&asoc->base.addr_lock);
		if (!laddr)
			continue;

		chunk = sctp_make_asconf_update_ip(asoc, laddr, addrs, addrcnt, SCTP_PARAM_DEL_IP);
		if (!chunk) {
			retval = -ENOMEM;
			goto out;
		}

		
		sctp_local_bh_disable();
		sctp_write_lock(&asoc->base.addr_lock);
		addr_buf = addrs;
		for (i = 0; i < addrcnt; i++) {
			laddr = (union sctp_addr *)addr_buf;
			af = sctp_get_af_specific(laddr->v4.sin_family);
			memcpy(&saveaddr, laddr, af->sockaddr_len);
			saveaddr.v4.sin_port = ntohs(saveaddr.v4.sin_port);
			list_for_each(pos1, &bp->address_list) {
				saddr = list_entry(pos1, struct sctp_sockaddr_entry, list);

				if (sctp_cmp_addr_exact(&saddr->a, &saveaddr))
					saddr->use_as_src = 0;
			}
			addr_buf += af->sockaddr_len;
		}
		sctp_write_unlock(&asoc->base.addr_lock);
		sctp_local_bh_enable();

		
		list_for_each(pos1, &asoc->peer.transport_addr_list) {
			transport = list_entry(pos1, struct sctp_transport, transports);
			dst_release(transport->dst);
			sctp_transport_route(transport, NULL, sctp_sk(asoc->base.sk));
		}

		retval = sctp_send_asconf(asoc, chunk);
	}
out:
	return retval;
}


SCTP_STATIC int sctp_setsockopt_bindx(struct sock* sk, struct sockaddr __user *addrs, int addrs_size, int op)

{
	struct sockaddr *kaddrs;
	int err;
	int addrcnt = 0;
	int walk_size = 0;
	struct sockaddr *sa_addr;
	void *addr_buf;
	struct sctp_af *af;

	SCTP_DEBUG_PRINTK("sctp_setsocktopt_bindx: sk %p addrs %p" " addrs_size %d opt %d\n", sk, addrs, addrs_size, op);

	if (unlikely(addrs_size <= 0))
		return -EINVAL;

	
	if (unlikely(!access_ok(VERIFY_READ, addrs, addrs_size)))
		return -EFAULT;

	
	kaddrs = kmalloc(addrs_size, GFP_KERNEL);
	if (unlikely(!kaddrs))
		return -ENOMEM;

	if (__copy_from_user(kaddrs, addrs, addrs_size)) {
		kfree(kaddrs);
		return -EFAULT;
	}

	 
	addr_buf = kaddrs;
	while (walk_size < addrs_size) {
		sa_addr = (struct sockaddr *)addr_buf;
		af = sctp_get_af_specific(sa_addr->sa_family);

		 
		if (!af || (walk_size + af->sockaddr_len) > addrs_size) {
			kfree(kaddrs);
			return -EINVAL;
		}
		addrcnt++;
		addr_buf += af->sockaddr_len;
		walk_size += af->sockaddr_len;
	}

	
	switch (op) {
	case SCTP_BINDX_ADD_ADDR:
		err = sctp_bindx_add(sk, kaddrs, addrcnt);
		if (err)
			goto out;
		err = sctp_send_asconf_add_ip(sk, kaddrs, addrcnt);
		break;

	case SCTP_BINDX_REM_ADDR:
		err = sctp_bindx_rem(sk, kaddrs, addrcnt);
		if (err)
			goto out;
		err = sctp_send_asconf_del_ip(sk, kaddrs, addrcnt);
		break;

	default:
		err = -EINVAL;
		break;
        };

out:
	kfree(kaddrs);

	return err;
}


static int __sctp_connect(struct sock* sk, struct sockaddr *kaddrs, int addrs_size)

{
	struct sctp_sock *sp;
	struct sctp_endpoint *ep;
	struct sctp_association *asoc = NULL;
	struct sctp_association *asoc2;
	struct sctp_transport *transport;
	union sctp_addr to;
	struct sctp_af *af;
	sctp_scope_t scope;
	long timeo;
	int err = 0;
	int addrcnt = 0;
	int walk_size = 0;
	struct sockaddr *sa_addr;
	void *addr_buf;

	sp = sctp_sk(sk);
	ep = sp->ep;

	
	if (sctp_sstate(sk, ESTABLISHED) || (sctp_style(sk, TCP) && sctp_sstate(sk, LISTENING))) {
		err = -EISCONN;
		goto out_free;
	}

	
	addr_buf = kaddrs;
	while (walk_size < addrs_size) {
		sa_addr = (struct sockaddr *)addr_buf;
		af = sctp_get_af_specific(sa_addr->sa_family);

		
		if (!af || (walk_size + af->sockaddr_len) > addrs_size) {
			err = -EINVAL;
			goto out_free;
		}

		err = sctp_verify_addr(sk, (union sctp_addr *)sa_addr, af->sockaddr_len);
		if (err)
			goto out_free;

		memcpy(&to, sa_addr, af->sockaddr_len);
		to.v4.sin_port = ntohs(to.v4.sin_port);

		
		asoc2 = sctp_endpoint_lookup_assoc(ep, &to, &transport);
		if (asoc2 && asoc2 != asoc) {
			if (asoc2->state >= SCTP_STATE_ESTABLISHED)
				err = -EISCONN;
			else err = -EALREADY;
			goto out_free;
		}

		
		if (sctp_endpoint_is_peeled_off(ep, &to)) {
			err = -EADDRNOTAVAIL;
			goto out_free;
		}

		if (!asoc) {
			
			if (!ep->base.bind_addr.port) {
				if (sctp_autobind(sk)) {
					err = -EAGAIN;
					goto out_free;
				}
			} else {
				
				if (ep->base.bind_addr.port < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE)) {
					err = -EACCES;
					goto out_free;
				}
			}

			scope = sctp_scope(&to);
			asoc = sctp_association_new(ep, sk, scope, GFP_KERNEL);
			if (!asoc) {
				err = -ENOMEM;
				goto out_free;
			}
		}

		
		transport = sctp_assoc_add_peer(asoc, &to, GFP_KERNEL, SCTP_UNKNOWN);
		if (!transport) {
			err = -ENOMEM;
			goto out_free;
		}

		addrcnt++;
		addr_buf += af->sockaddr_len;
		walk_size += af->sockaddr_len;
	}

	err = sctp_assoc_set_bind_addr_from_ep(asoc, GFP_KERNEL);
	if (err < 0) {
		goto out_free;
	}

	err = sctp_primitive_ASSOCIATE(asoc, NULL);
	if (err < 0) {
		goto out_free;
	}

	
	inet_sk(sk)->dport = htons(asoc->peer.port);
	af = sctp_get_af_specific(to.sa.sa_family);
	af->to_sk_daddr(&to, sk);
	sk->sk_err = 0;

	timeo = sock_sndtimeo(sk, sk->sk_socket->file->f_flags & O_NONBLOCK);
	err = sctp_wait_for_connect(asoc, &timeo);

	
	asoc = NULL;

out_free:

	SCTP_DEBUG_PRINTK("About to exit __sctp_connect() free asoc: %p" " kaddrs: %p err: %d\n", asoc, kaddrs, err);

	if (asoc)
		sctp_association_free(asoc);
	return err;
}


SCTP_STATIC int sctp_setsockopt_connectx(struct sock* sk, struct sockaddr __user *addrs, int addrs_size)

{
	int err = 0;
	struct sockaddr *kaddrs;

	SCTP_DEBUG_PRINTK("%s - sk %p addrs %p addrs_size %d\n", __FUNCTION__, sk, addrs, addrs_size);

	if (unlikely(addrs_size <= 0))
		return -EINVAL;

	
	if (unlikely(!access_ok(VERIFY_READ, addrs, addrs_size)))
		return -EFAULT;

	
	kaddrs = kmalloc(addrs_size, GFP_KERNEL);
	if (unlikely(!kaddrs))
		return -ENOMEM;

	if (__copy_from_user(kaddrs, addrs, addrs_size)) {
		err = -EFAULT;
	} else {
		err = __sctp_connect(sk, kaddrs, addrs_size);
	}

	kfree(kaddrs);
	return err;
}


SCTP_STATIC void sctp_close(struct sock *sk, long timeout)
{
	struct sctp_endpoint *ep;
	struct sctp_association *asoc;
	struct list_head *pos, *temp;

	SCTP_DEBUG_PRINTK("sctp_close(sk: 0x%p, timeout:%ld)\n", sk, timeout);

	sctp_lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	ep = sctp_sk(sk)->ep;

	
	list_for_each_safe(pos, temp, &ep->asocs) {
		asoc = list_entry(pos, struct sctp_association, asocs);

		if (sctp_style(sk, TCP)) {
			
			if (sctp_state(asoc, CLOSED)) {
				sctp_unhash_established(asoc);
				sctp_association_free(asoc);
				continue;
			}
		}

		if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime)
			sctp_primitive_ABORT(asoc, NULL);
		else sctp_primitive_SHUTDOWN(asoc, NULL);
	}

	
	sctp_queue_purge_ulpevents(&sk->sk_receive_queue);
	sctp_queue_purge_ulpevents(&sctp_sk(sk)->pd_lobby);

	
	if (sctp_style(sk, TCP) && timeout)
		sctp_wait_for_close(sk, timeout);

	
	sctp_release_sock(sk);

	
	sctp_local_bh_disable();
	sctp_bh_lock_sock(sk);

	
	sock_hold(sk);
	sk_common_release(sk);

	sctp_bh_unlock_sock(sk);
	sctp_local_bh_enable();

	sock_put(sk);

	SCTP_DBG_OBJCNT_DEC(sock);
}


static int sctp_error(struct sock *sk, int flags, int err)
{
	if (err == -EPIPE)
		err = sock_error(sk) ? : -EPIPE;
	if (err == -EPIPE && !(flags & MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);
	return err;
}




SCTP_STATIC int sctp_msghdr_parse(const struct msghdr *, sctp_cmsgs_t *);

SCTP_STATIC int sctp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct sctp_sock *sp;
	struct sctp_endpoint *ep;
	struct sctp_association *new_asoc=NULL, *asoc=NULL;
	struct sctp_transport *transport, *chunk_tp;
	struct sctp_chunk *chunk;
	union sctp_addr to;
	struct sockaddr *msg_name = NULL;
	struct sctp_sndrcvinfo default_sinfo = { 0 };
	struct sctp_sndrcvinfo *sinfo;
	struct sctp_initmsg *sinit;
	sctp_assoc_t associd = 0;
	sctp_cmsgs_t cmsgs = { NULL };
	int err;
	sctp_scope_t scope;
	long timeo;
	__u16 sinfo_flags = 0;
	struct sctp_datamsg *datamsg;
	struct list_head *pos;
	int msg_flags = msg->msg_flags;

	SCTP_DEBUG_PRINTK("sctp_sendmsg(sk: %p, msg: %p, msg_len: %zu)\n", sk, msg, msg_len);

	err = 0;
	sp = sctp_sk(sk);
	ep = sp->ep;

	SCTP_DEBUG_PRINTK("Using endpoint: %p.\n", ep);

	
	if (sctp_style(sk, TCP) && sctp_sstate(sk, LISTENING)) {
		err = -EPIPE;
		goto out_nounlock;
	}

	
	err = sctp_msghdr_parse(msg, &cmsgs);

	if (err) {
		SCTP_DEBUG_PRINTK("msghdr parse err = %x\n", err);
		goto out_nounlock;
	}

	
	if (!sctp_style(sk, UDP_HIGH_BANDWIDTH) && msg->msg_name) {
		int msg_namelen = msg->msg_namelen;

		err = sctp_verify_addr(sk, (union sctp_addr *)msg->msg_name, msg_namelen);
		if (err)
			return err;

		if (msg_namelen > sizeof(to))
			msg_namelen = sizeof(to);
		memcpy(&to, msg->msg_name, msg_namelen);
		SCTP_DEBUG_PRINTK("Just memcpy'd. msg_name is " "0x%x:%u.\n", to.v4.sin_addr.s_addr, to.v4.sin_port);


		to.v4.sin_port = ntohs(to.v4.sin_port);
		msg_name = msg->msg_name;
	}

	sinfo = cmsgs.info;
	sinit = cmsgs.init;

	
	if (sinfo) {
		sinfo_flags = sinfo->sinfo_flags;
		associd = sinfo->sinfo_assoc_id;
	}

	SCTP_DEBUG_PRINTK("msg_len: %zu, sinfo_flags: 0x%x\n", msg_len, sinfo_flags);

	
	if (sctp_style(sk, TCP) && (sinfo_flags & (SCTP_EOF | SCTP_ABORT))) {
		err = -EINVAL;
		goto out_nounlock;
	}

	
	if (((sinfo_flags & SCTP_EOF) && (msg_len > 0)) || (!(sinfo_flags & (SCTP_EOF|SCTP_ABORT)) && (msg_len == 0))) {
		err = -EINVAL;
		goto out_nounlock;
	}

	
	if ((sinfo_flags & SCTP_ADDR_OVER) && (!msg->msg_name)) {
		err = -EINVAL;
		goto out_nounlock;
	}

	transport = NULL;

	SCTP_DEBUG_PRINTK("About to look up association.\n");

	sctp_lock_sock(sk);

	
	if (msg_name) {
		
		asoc = sctp_endpoint_lookup_assoc(ep, &to, &transport);
		if (!asoc) {
			
			if ((sctp_style(sk, TCP) && sctp_sstate(sk, ESTABLISHED)) || sctp_endpoint_is_peeled_off(ep, &to)) {

				err = -EADDRNOTAVAIL;
				goto out_unlock;
			}
		}
	} else {
		asoc = sctp_id2assoc(sk, associd);
		if (!asoc) {
			err = -EPIPE;
			goto out_unlock;
		}
	}

	if (asoc) {
		SCTP_DEBUG_PRINTK("Just looked up association: %p.\n", asoc);

		
		if (sctp_state(asoc, CLOSED) && sctp_style(sk, TCP)) {
			err = -EPIPE;
			goto out_unlock;
		}

		if (sinfo_flags & SCTP_EOF) {
			SCTP_DEBUG_PRINTK("Shutting down association: %p\n", asoc);
			sctp_primitive_SHUTDOWN(asoc, NULL);
			err = 0;
			goto out_unlock;
		}
		if (sinfo_flags & SCTP_ABORT) {
			SCTP_DEBUG_PRINTK("Aborting association: %p\n", asoc);
			sctp_primitive_ABORT(asoc, msg);
			err = 0;
			goto out_unlock;
		}
	}

	
	if (!asoc) {
		SCTP_DEBUG_PRINTK("There is no association yet.\n");

		if (sinfo_flags & (SCTP_EOF | SCTP_ABORT)) {
			err = -EINVAL;
			goto out_unlock;
		}

		
		if (sinfo) {
			if (!sinit || (sinit && !sinit->sinit_num_ostreams)) {
				
				if (sinfo->sinfo_stream >= sp->initmsg.sinit_num_ostreams) {
					err = -EINVAL;
					goto out_unlock;
				}
			} else {
				
				if (sinfo->sinfo_stream >= sinit->sinit_num_ostreams) {
					err = -EINVAL;
					goto out_unlock;
				}
			}
		}

		
		if (!ep->base.bind_addr.port) {
			if (sctp_autobind(sk)) {
				err = -EAGAIN;
				goto out_unlock;
			}
		} else {
			
			if (ep->base.bind_addr.port < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE)) {
				err = -EACCES;
				goto out_unlock;
			}
		}

		scope = sctp_scope(&to);
		new_asoc = sctp_association_new(ep, sk, scope, GFP_KERNEL);
		if (!new_asoc) {
			err = -ENOMEM;
			goto out_unlock;
		}
		asoc = new_asoc;

		
		if (sinit) {
			if (sinit->sinit_num_ostreams) {
				asoc->c.sinit_num_ostreams = sinit->sinit_num_ostreams;
			}
			if (sinit->sinit_max_instreams) {
				asoc->c.sinit_max_instreams = sinit->sinit_max_instreams;
			}
			if (sinit->sinit_max_attempts) {
				asoc->max_init_attempts = sinit->sinit_max_attempts;
			}
			if (sinit->sinit_max_init_timeo) {
				asoc->max_init_timeo =  msecs_to_jiffies(sinit->sinit_max_init_timeo);
			}
		}

		
		transport = sctp_assoc_add_peer(asoc, &to, GFP_KERNEL, SCTP_UNKNOWN);
		if (!transport) {
			err = -ENOMEM;
			goto out_free;
		}
		err = sctp_assoc_set_bind_addr_from_ep(asoc, GFP_KERNEL);
		if (err < 0) {
			err = -ENOMEM;
			goto out_free;
		}
	}

	
	SCTP_DEBUG_PRINTK("We have a valid association.\n");

	if (!sinfo) {
		
		default_sinfo.sinfo_stream = asoc->default_stream;
		default_sinfo.sinfo_flags = asoc->default_flags;
		default_sinfo.sinfo_ppid = asoc->default_ppid;
		default_sinfo.sinfo_context = asoc->default_context;
		default_sinfo.sinfo_timetolive = asoc->default_timetolive;
		default_sinfo.sinfo_assoc_id = sctp_assoc2id(asoc);
		sinfo = &default_sinfo;
	}

	
	if (msg_len > sk->sk_sndbuf) {
		err = -EMSGSIZE;
		goto out_free;
	}

	
	if (sctp_sk(sk)->disable_fragments && (msg_len > asoc->frag_point)) {
		err = -EMSGSIZE;
		goto out_free;
	}

	if (sinfo) {
		
		if (sinfo->sinfo_stream >= asoc->c.sinit_num_ostreams) {
			err = -EINVAL;
			goto out_free;
		}
	}

	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	if (!sctp_wspace(asoc)) {
		err = sctp_wait_for_sndbuf(asoc, &timeo, msg_len);
		if (err)
			goto out_free;
	}

	
	if ((sctp_style(sk, TCP) && msg_name) || (sinfo_flags & SCTP_ADDR_OVER)) {
		chunk_tp = sctp_assoc_lookup_paddr(asoc, &to);
		if (!chunk_tp) {
			err = -EINVAL;
			goto out_free;
		}
	} else chunk_tp = NULL;

	
	if (sctp_state(asoc, CLOSED)) {
		err = sctp_primitive_ASSOCIATE(asoc, NULL);
		if (err < 0)
			goto out_free;
		SCTP_DEBUG_PRINTK("We associated primitively.\n");
	}

	
	datamsg = sctp_datamsg_from_user(asoc, sinfo, msg, msg_len);
	if (!datamsg) {
		err = -ENOMEM;
		goto out_free;
	}

	
	list_for_each(pos, &datamsg->chunks) {
		chunk = list_entry(pos, struct sctp_chunk, frag_list);
		sctp_datamsg_track(chunk);

		
		sctp_set_owner_w(chunk);

		chunk->transport = chunk_tp;

		
		err = sctp_primitive_SEND(asoc, chunk);
		
		if (err)
			sctp_chunk_free(chunk);
		SCTP_DEBUG_PRINTK("We sent primitively.\n");
	}

	sctp_datamsg_free(datamsg);
	if (err)
		goto out_free;
	else err = msg_len;

	
	goto out_unlock;

out_free:
	if (new_asoc)
		sctp_association_free(asoc);
out_unlock:
	sctp_release_sock(sk);

out_nounlock:
	return sctp_error(sk, msg_flags, err);


do_sock_err:
	if (msg_len)
		err = msg_len;
	else err = sock_error(sk);
	goto out;

do_interrupted:
	if (msg_len)
		err = msg_len;
	goto out;

}


static int sctp_skb_pull(struct sk_buff *skb, int len)
{
	struct sk_buff *list;
	int skb_len = skb_headlen(skb);
	int rlen;

	if (len <= skb_len) {
		__skb_pull(skb, len);
		return 0;
	}
	len -= skb_len;
	__skb_pull(skb, skb_len);

	for (list = skb_shinfo(skb)->frag_list; list; list = list->next) {
		rlen = sctp_skb_pull(list, len);
		skb->len -= (len-rlen);
		skb->data_len -= (len-rlen);

		if (!rlen)
			return 0;

		len = rlen;
	}

	return len;
}


static struct sk_buff *sctp_skb_recv_datagram(struct sock *, int, int, int *);

SCTP_STATIC int sctp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)

{
	struct sctp_ulpevent *event = NULL;
	struct sctp_sock *sp = sctp_sk(sk);
	struct sk_buff *skb;
	int copied;
	int err = 0;
	int skb_len;

	SCTP_DEBUG_PRINTK("sctp_recvmsg(%s: %p, %s: %p, %s: %zd, %s: %d, %s: " "0x%x, %s: %p)\n", "sk", sk, "msghdr", msg, "len", len, "knoblauch", noblock, "flags", flags, "addr_len", addr_len);



	sctp_lock_sock(sk);

	if (sctp_style(sk, TCP) && !sctp_sstate(sk, ESTABLISHED)) {
		err = -ENOTCONN;
		goto out;
	}

	skb = sctp_skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	
	skb_len = skb->len;

	copied = skb_len;
	if (copied > len)
		copied = len;

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);

	event = sctp_skb2event(skb);

	if (err)
		goto out_free;

	sock_recv_timestamp(msg, sk, skb);
	if (sctp_ulpevent_is_notification(event)) {
		msg->msg_flags |= MSG_NOTIFICATION;
		sp->pf->event_msgname(event, msg->msg_name, addr_len);
	} else {
		sp->pf->skb_msgname(skb, msg->msg_name, addr_len);
	}

	
	if (sp->subscribe.sctp_data_io_event)
		sctp_ulpevent_read_sndrcvinfo(event, msg);

	
	if (sk->sk_protinfo.af_inet.cmsg_flags)
		ip_cmsg_recv(msg, skb);


	err = copied;

	
	if (skb_len > copied) {
		msg->msg_flags &= ~MSG_EOR;
		if (flags & MSG_PEEK)
			goto out_free;
		sctp_skb_pull(skb, copied);
		skb_queue_head(&sk->sk_receive_queue, skb);

		
		sctp_assoc_rwnd_increase(event->asoc, copied);
		goto out;
	} else if ((event->msg_flags & MSG_NOTIFICATION) || (event->msg_flags & MSG_EOR))
		msg->msg_flags |= MSG_EOR;
	else msg->msg_flags &= ~MSG_EOR;

out_free:
	if (flags & MSG_PEEK) {
		
		kfree_skb(skb);
	} else {
		
		sctp_ulpevent_free(event);
	}
out:
	sctp_release_sock(sk);
	return err;
}


static int sctp_setsockopt_disable_fragments(struct sock *sk, char __user *optval, int optlen)
{
	int val;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	sctp_sk(sk)->disable_fragments = (val == 0) ? 0 : 1;

	return 0;
}

static int sctp_setsockopt_events(struct sock *sk, char __user *optval, int optlen)
{
	if (optlen != sizeof(struct sctp_event_subscribe))
		return -EINVAL;
	if (copy_from_user(&sctp_sk(sk)->subscribe, optval, optlen))
		return -EFAULT;
	return 0;
}


static int sctp_setsockopt_autoclose(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_sock *sp = sctp_sk(sk);

	
	if (sctp_style(sk, TCP))
		return -EOPNOTSUPP;
	if (optlen != sizeof(int))
		return -EINVAL;
	if (copy_from_user(&sp->autoclose, optval, optlen))
		return -EFAULT;

	return 0;
}


int sctp_apply_peer_addr_params(struct sctp_paddrparams *params, struct sctp_transport   *trans, struct sctp_association *asoc, struct sctp_sock        *sp, int                      hb_change, int                      pmtud_change, int                      sackdelay_change)





{
	int error;

	if (params->spp_flags & SPP_HB_DEMAND && trans) {
		error = sctp_primitive_REQUESTHEARTBEAT (trans->asoc, trans);
		if (error)
			return error;
	}

	if (params->spp_hbinterval) {
		if (trans) {
			trans->hbinterval = msecs_to_jiffies(params->spp_hbinterval);
		} else if (asoc) {
			asoc->hbinterval = msecs_to_jiffies(params->spp_hbinterval);
		} else {
			sp->hbinterval = params->spp_hbinterval;
		}
	}

	if (hb_change) {
		if (trans) {
			trans->param_flags = (trans->param_flags & ~SPP_HB) | hb_change;
		} else if (asoc) {
			asoc->param_flags = (asoc->param_flags & ~SPP_HB) | hb_change;
		} else {
			sp->param_flags = (sp->param_flags & ~SPP_HB) | hb_change;
		}
	}

	if (params->spp_pathmtu) {
		if (trans) {
			trans->pathmtu = params->spp_pathmtu;
			sctp_assoc_sync_pmtu(asoc);
		} else if (asoc) {
			asoc->pathmtu = params->spp_pathmtu;
			sctp_frag_point(sp, params->spp_pathmtu);
		} else {
			sp->pathmtu = params->spp_pathmtu;
		}
	}

	if (pmtud_change) {
		if (trans) {
			int update = (trans->param_flags & SPP_PMTUD_DISABLE) && (params->spp_flags & SPP_PMTUD_ENABLE);
			trans->param_flags = (trans->param_flags & ~SPP_PMTUD) | pmtud_change;
			if (update) {
				sctp_transport_pmtu(trans);
				sctp_assoc_sync_pmtu(asoc);
			}
		} else if (asoc) {
			asoc->param_flags = (asoc->param_flags & ~SPP_PMTUD) | pmtud_change;
		} else {
			sp->param_flags = (sp->param_flags & ~SPP_PMTUD) | pmtud_change;
		}
	}

	if (params->spp_sackdelay) {
		if (trans) {
			trans->sackdelay = msecs_to_jiffies(params->spp_sackdelay);
		} else if (asoc) {
			asoc->sackdelay = msecs_to_jiffies(params->spp_sackdelay);
		} else {
			sp->sackdelay = params->spp_sackdelay;
		}
	}

	if (sackdelay_change) {
		if (trans) {
			trans->param_flags = (trans->param_flags & ~SPP_SACKDELAY) | sackdelay_change;

		} else if (asoc) {
			asoc->param_flags = (asoc->param_flags & ~SPP_SACKDELAY) | sackdelay_change;

		} else {
			sp->param_flags = (sp->param_flags & ~SPP_SACKDELAY) | sackdelay_change;

		}
	}

	if (params->spp_pathmaxrxt) {
		if (trans) {
			trans->pathmaxrxt = params->spp_pathmaxrxt;
		} else if (asoc) {
			asoc->pathmaxrxt = params->spp_pathmaxrxt;
		} else {
			sp->pathmaxrxt = params->spp_pathmaxrxt;
		}
	}

	return 0;
}

static int sctp_setsockopt_peer_addr_params(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_paddrparams  params;
	struct sctp_transport   *trans = NULL;
	struct sctp_association *asoc = NULL;
	struct sctp_sock        *sp = sctp_sk(sk);
	int error;
	int hb_change, pmtud_change, sackdelay_change;

	if (optlen != sizeof(struct sctp_paddrparams))
		return - EINVAL;

	if (copy_from_user(&params, optval, optlen))
		return -EFAULT;

	
	hb_change        = params.spp_flags & SPP_HB;
	pmtud_change     = params.spp_flags & SPP_PMTUD;
	sackdelay_change = params.spp_flags & SPP_SACKDELAY;

	if (hb_change        == SPP_HB || pmtud_change     == SPP_PMTUD || sackdelay_change == SPP_SACKDELAY || params.spp_sackdelay > 500 || (params.spp_pathmtu && params.spp_pathmtu < SCTP_DEFAULT_MINSEGMENT))




		return -EINVAL;

	
	if (!sctp_is_any(( union sctp_addr *)&params.spp_address)) {
		trans = sctp_addr_id2transport(sk, &params.spp_address, params.spp_assoc_id);
		if (!trans)
			return -EINVAL;
	}

	
	asoc = sctp_id2assoc(sk, params.spp_assoc_id);
	if (!asoc && params.spp_assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	
	if (params.spp_flags & SPP_HB_DEMAND && !trans && !asoc)
		return -EINVAL;

	
	error = sctp_apply_peer_addr_params(&params, trans, asoc, sp, hb_change, pmtud_change, sackdelay_change);


	if (error)
		return error;

	
	if (!trans && asoc) {
		struct list_head *pos;

		list_for_each(pos, &asoc->peer.transport_addr_list) {
			trans = list_entry(pos, struct sctp_transport, transports);
			sctp_apply_peer_addr_params(&params, trans, asoc, sp, hb_change, pmtud_change, sackdelay_change);

		}
	}

	return 0;
}



static int sctp_setsockopt_delayed_ack_time(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_assoc_value  params;
	struct sctp_transport   *trans = NULL;
	struct sctp_association *asoc = NULL;
	struct sctp_sock        *sp = sctp_sk(sk);

	if (optlen != sizeof(struct sctp_assoc_value))
		return - EINVAL;

	if (copy_from_user(&params, optval, optlen))
		return -EFAULT;

	
	if (params.assoc_value > 500)
		return -EINVAL;

	
	asoc = sctp_id2assoc(sk, params.assoc_id);
	if (!asoc && params.assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	if (params.assoc_value) {
		if (asoc) {
			asoc->sackdelay = msecs_to_jiffies(params.assoc_value);
			asoc->param_flags =  (asoc->param_flags & ~SPP_SACKDELAY) | SPP_SACKDELAY_ENABLE;

		} else {
			sp->sackdelay = params.assoc_value;
			sp->param_flags =  (sp->param_flags & ~SPP_SACKDELAY) | SPP_SACKDELAY_ENABLE;

		}
	} else {
		if (asoc) {
			asoc->param_flags =  (asoc->param_flags & ~SPP_SACKDELAY) | SPP_SACKDELAY_DISABLE;

		} else {
			sp->param_flags =  (sp->param_flags & ~SPP_SACKDELAY) | SPP_SACKDELAY_DISABLE;

		}
	}

	
	if (asoc) {
		struct list_head *pos;

		list_for_each(pos, &asoc->peer.transport_addr_list) {
			trans = list_entry(pos, struct sctp_transport, transports);
			if (params.assoc_value) {
				trans->sackdelay = msecs_to_jiffies(params.assoc_value);
				trans->param_flags =  (trans->param_flags & ~SPP_SACKDELAY) | SPP_SACKDELAY_ENABLE;

			} else {
				trans->param_flags =  (trans->param_flags & ~SPP_SACKDELAY) | SPP_SACKDELAY_DISABLE;

			}
		}
	}
 
	return 0;
}


static int sctp_setsockopt_initmsg(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_initmsg sinit;
	struct sctp_sock *sp = sctp_sk(sk);

	if (optlen != sizeof(struct sctp_initmsg))
		return -EINVAL;
	if (copy_from_user(&sinit, optval, optlen))
		return -EFAULT;

	if (sinit.sinit_num_ostreams)
		sp->initmsg.sinit_num_ostreams = sinit.sinit_num_ostreams;	
	if (sinit.sinit_max_instreams)
		sp->initmsg.sinit_max_instreams = sinit.sinit_max_instreams;	
	if (sinit.sinit_max_attempts)
		sp->initmsg.sinit_max_attempts = sinit.sinit_max_attempts;	
	if (sinit.sinit_max_init_timeo)
		sp->initmsg.sinit_max_init_timeo = sinit.sinit_max_init_timeo;	

	return 0;
}


static int sctp_setsockopt_default_send_param(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_sndrcvinfo info;
	struct sctp_association *asoc;
	struct sctp_sock *sp = sctp_sk(sk);

	if (optlen != sizeof(struct sctp_sndrcvinfo))
		return -EINVAL;
	if (copy_from_user(&info, optval, optlen))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, info.sinfo_assoc_id);
	if (!asoc && info.sinfo_assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	if (asoc) {
		asoc->default_stream = info.sinfo_stream;
		asoc->default_flags = info.sinfo_flags;
		asoc->default_ppid = info.sinfo_ppid;
		asoc->default_context = info.sinfo_context;
		asoc->default_timetolive = info.sinfo_timetolive;
	} else {
		sp->default_stream = info.sinfo_stream;
		sp->default_flags = info.sinfo_flags;
		sp->default_ppid = info.sinfo_ppid;
		sp->default_context = info.sinfo_context;
		sp->default_timetolive = info.sinfo_timetolive;
	}

	return 0;
}


static int sctp_setsockopt_primary_addr(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_prim prim;
	struct sctp_transport *trans;

	if (optlen != sizeof(struct sctp_prim))
		return -EINVAL;

	if (copy_from_user(&prim, optval, sizeof(struct sctp_prim)))
		return -EFAULT;

	trans = sctp_addr_id2transport(sk, &prim.ssp_addr, prim.ssp_assoc_id);
	if (!trans)
		return -EINVAL;

	sctp_assoc_set_primary(trans->asoc, trans);

	return 0;
}


static int sctp_setsockopt_nodelay(struct sock *sk, char __user *optval, int optlen)
{
	int val;

	if (optlen < sizeof(int))
		return -EINVAL;
	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	sctp_sk(sk)->nodelay = (val == 0) ? 0 : 1;
	return 0;
}


static int sctp_setsockopt_rtoinfo(struct sock *sk, char __user *optval, int optlen) {
	struct sctp_rtoinfo rtoinfo;
	struct sctp_association *asoc;

	if (optlen != sizeof (struct sctp_rtoinfo))
		return -EINVAL;

	if (copy_from_user(&rtoinfo, optval, optlen))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, rtoinfo.srto_assoc_id);

	
	if (!asoc && rtoinfo.srto_assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	if (asoc) {
		if (rtoinfo.srto_initial != 0)
			asoc->rto_initial =  msecs_to_jiffies(rtoinfo.srto_initial);
		if (rtoinfo.srto_max != 0)
			asoc->rto_max = msecs_to_jiffies(rtoinfo.srto_max);
		if (rtoinfo.srto_min != 0)
			asoc->rto_min = msecs_to_jiffies(rtoinfo.srto_min);
	} else {
		
		struct sctp_sock *sp = sctp_sk(sk);

		if (rtoinfo.srto_initial != 0)
			sp->rtoinfo.srto_initial = rtoinfo.srto_initial;
		if (rtoinfo.srto_max != 0)
			sp->rtoinfo.srto_max = rtoinfo.srto_max;
		if (rtoinfo.srto_min != 0)
			sp->rtoinfo.srto_min = rtoinfo.srto_min;
	}

	return 0;
}


static int sctp_setsockopt_associnfo(struct sock *sk, char __user *optval, int optlen)
{

	struct sctp_assocparams assocparams;
	struct sctp_association *asoc;

	if (optlen != sizeof(struct sctp_assocparams))
		return -EINVAL;
	if (copy_from_user(&assocparams, optval, optlen))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, assocparams.sasoc_assoc_id);

	if (!asoc && assocparams.sasoc_assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	
	if (asoc) {
		if (assocparams.sasoc_asocmaxrxt != 0) {
			__u32 path_sum = 0;
			int   paths = 0;
			struct list_head *pos;
			struct sctp_transport *peer_addr;

			list_for_each(pos, &asoc->peer.transport_addr_list) {
				peer_addr = list_entry(pos, struct sctp_transport, transports);

				path_sum += peer_addr->pathmaxrxt;
				paths++;
			}

			
			if (paths > 1 && assocparams.sasoc_asocmaxrxt > path_sum)
				return -EINVAL;

			asoc->max_retrans = assocparams.sasoc_asocmaxrxt;
		}

		if (assocparams.sasoc_cookie_life != 0) {
			asoc->cookie_life.tv_sec = assocparams.sasoc_cookie_life / 1000;
			asoc->cookie_life.tv_usec = (assocparams.sasoc_cookie_life % 1000)
					* 1000;
		}
	} else {
		
		struct sctp_sock *sp = sctp_sk(sk);

		if (assocparams.sasoc_asocmaxrxt != 0)
			sp->assocparams.sasoc_asocmaxrxt = assocparams.sasoc_asocmaxrxt;
		if (assocparams.sasoc_cookie_life != 0)
			sp->assocparams.sasoc_cookie_life = assocparams.sasoc_cookie_life;
	}
	return 0;
}


static int sctp_setsockopt_mappedv4(struct sock *sk, char __user *optval, int optlen)
{
	int val;
	struct sctp_sock *sp = sctp_sk(sk);

	if (optlen < sizeof(int))
		return -EINVAL;
	if (get_user(val, (int __user *)optval))
		return -EFAULT;
	if (val)
		sp->v4mapped = 1;
	else sp->v4mapped = 0;

	return 0;
}


static int sctp_setsockopt_maxseg(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_association *asoc;
	struct list_head *pos;
	struct sctp_sock *sp = sctp_sk(sk);
	int val;

	if (optlen < sizeof(int))
		return -EINVAL;
	if (get_user(val, (int __user *)optval))
		return -EFAULT;
	if ((val != 0) && ((val < 8) || (val > SCTP_MAX_CHUNK_LEN)))
		return -EINVAL;
	sp->user_frag = val;

	
	list_for_each(pos, &(sp->ep->asocs)) {
		asoc = list_entry(pos, struct sctp_association, asocs);
		asoc->frag_point = sctp_frag_point(sp, asoc->pathmtu); 
	}

	return 0;
}



static int sctp_setsockopt_peer_primary_addr(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_sock	*sp;
	struct sctp_endpoint	*ep;
	struct sctp_association	*asoc = NULL;
	struct sctp_setpeerprim	prim;
	struct sctp_chunk	*chunk;
	int 			err;

	sp = sctp_sk(sk);
	ep = sp->ep;

	if (!sctp_addip_enable)
		return -EPERM;

	if (optlen != sizeof(struct sctp_setpeerprim))
		return -EINVAL;

	if (copy_from_user(&prim, optval, optlen))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, prim.sspp_assoc_id);
	if (!asoc) 
		return -EINVAL;

	if (!asoc->peer.asconf_capable)
		return -EPERM;

	if (asoc->peer.addip_disabled_mask & SCTP_PARAM_SET_PRIMARY)
		return -EPERM;

	if (!sctp_state(asoc, ESTABLISHED))
		return -ENOTCONN;

	if (!sctp_assoc_lookup_laddr(asoc, (union sctp_addr *)&prim.sspp_addr))
		return -EADDRNOTAVAIL;

	
	chunk = sctp_make_asconf_set_prim(asoc, (union sctp_addr *)&prim.sspp_addr);
	if (!chunk)
		return -ENOMEM;

	err = sctp_send_asconf(asoc, chunk);

	SCTP_DEBUG_PRINTK("We set peer primary addr primitively.\n");

	return err;
}

static int sctp_setsockopt_adaption_layer(struct sock *sk, char __user *optval, int optlen)
{
	struct sctp_setadaption adaption;

	if (optlen != sizeof(struct sctp_setadaption))
		return -EINVAL;
	if (copy_from_user(&adaption, optval, optlen)) 
		return -EFAULT;

	sctp_sk(sk)->adaption_ind = adaption.ssb_adaption_ind;

	return 0;
}


SCTP_STATIC int sctp_setsockopt(struct sock *sk, int level, int optname, char __user *optval, int optlen)
{
	int retval = 0;

	SCTP_DEBUG_PRINTK("sctp_setsockopt(sk: %p... optname: %d)\n", sk, optname);

	
	if (level != SOL_SCTP) {
		struct sctp_af *af = sctp_sk(sk)->pf->af;
		retval = af->setsockopt(sk, level, optname, optval, optlen);
		goto out_nounlock;
	}

	sctp_lock_sock(sk);

	switch (optname) {
	case SCTP_SOCKOPT_BINDX_ADD:
		
		retval = sctp_setsockopt_bindx(sk, (struct sockaddr __user *)optval, optlen, SCTP_BINDX_ADD_ADDR);
		break;

	case SCTP_SOCKOPT_BINDX_REM:
		
		retval = sctp_setsockopt_bindx(sk, (struct sockaddr __user *)optval, optlen, SCTP_BINDX_REM_ADDR);
		break;

	case SCTP_SOCKOPT_CONNECTX:
		
		retval = sctp_setsockopt_connectx(sk, (struct sockaddr __user *)optval, optlen);
		break;

	case SCTP_DISABLE_FRAGMENTS:
		retval = sctp_setsockopt_disable_fragments(sk, optval, optlen);
		break;

	case SCTP_EVENTS:
		retval = sctp_setsockopt_events(sk, optval, optlen);
		break;

	case SCTP_AUTOCLOSE:
		retval = sctp_setsockopt_autoclose(sk, optval, optlen);
		break;

	case SCTP_PEER_ADDR_PARAMS:
		retval = sctp_setsockopt_peer_addr_params(sk, optval, optlen);
		break;

	case SCTP_DELAYED_ACK_TIME:
		retval = sctp_setsockopt_delayed_ack_time(sk, optval, optlen);
		break;

	case SCTP_INITMSG:
		retval = sctp_setsockopt_initmsg(sk, optval, optlen);
		break;
	case SCTP_DEFAULT_SEND_PARAM:
		retval = sctp_setsockopt_default_send_param(sk, optval, optlen);
		break;
	case SCTP_PRIMARY_ADDR:
		retval = sctp_setsockopt_primary_addr(sk, optval, optlen);
		break;
	case SCTP_SET_PEER_PRIMARY_ADDR:
		retval = sctp_setsockopt_peer_primary_addr(sk, optval, optlen);
		break;
	case SCTP_NODELAY:
		retval = sctp_setsockopt_nodelay(sk, optval, optlen);
		break;
	case SCTP_RTOINFO:
		retval = sctp_setsockopt_rtoinfo(sk, optval, optlen);
		break;
	case SCTP_ASSOCINFO:
		retval = sctp_setsockopt_associnfo(sk, optval, optlen);
		break;
	case SCTP_I_WANT_MAPPED_V4_ADDR:
		retval = sctp_setsockopt_mappedv4(sk, optval, optlen);
		break;
	case SCTP_MAXSEG:
		retval = sctp_setsockopt_maxseg(sk, optval, optlen);
		break;
	case SCTP_ADAPTION_LAYER:
		retval = sctp_setsockopt_adaption_layer(sk, optval, optlen);
		break;

	default:
		retval = -ENOPROTOOPT;
		break;
	};

	sctp_release_sock(sk);

out_nounlock:
	return retval;
}


SCTP_STATIC int sctp_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	int err = 0;
	struct sctp_af *af;

	sctp_lock_sock(sk);

	SCTP_DEBUG_PRINTK("%s - sk: %p, sockaddr: %p, addr_len: %d\n", __FUNCTION__, sk, addr, addr_len);

	
	af = sctp_get_af_specific(addr->sa_family);
	if (!af || addr_len < af->sockaddr_len) {
		err = -EINVAL;
	} else {
		
		err = __sctp_connect(sk, addr, af->sockaddr_len);
	}

	sctp_release_sock(sk);
	return err;
}


SCTP_STATIC int sctp_disconnect(struct sock *sk, int flags)
{
	return -EOPNOTSUPP; 
}


SCTP_STATIC struct sock *sctp_accept(struct sock *sk, int flags, int *err)
{
	struct sctp_sock *sp;
	struct sctp_endpoint *ep;
	struct sock *newsk = NULL;
	struct sctp_association *asoc;
	long timeo;
	int error = 0;

	sctp_lock_sock(sk);

	sp = sctp_sk(sk);
	ep = sp->ep;

	if (!sctp_style(sk, TCP)) {
		error = -EOPNOTSUPP;
		goto out;
	}

	if (!sctp_sstate(sk, LISTENING)) {
		error = -EINVAL;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, sk->sk_socket->file->f_flags & O_NONBLOCK);

	error = sctp_wait_for_accept(sk, timeo);
	if (error)
		goto out;

	
	asoc = list_entry(ep->asocs.next, struct sctp_association, asocs);

	newsk = sp->pf->create_accept_sk(sk, asoc);
	if (!newsk) {
		error = -ENOMEM;
		goto out;
	}

	
	sctp_sock_migrate(sk, newsk, asoc, SCTP_SOCKET_TCP);

out:
	sctp_release_sock(sk);
 	*err = error;
	return newsk;
}


SCTP_STATIC int sctp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	return -ENOIOCTLCMD;
}


SCTP_STATIC int sctp_init_sock(struct sock *sk)
{
	struct sctp_endpoint *ep;
	struct sctp_sock *sp;

	SCTP_DEBUG_PRINTK("sctp_init_sock(sk: %p)\n", sk);

	sp = sctp_sk(sk);

	
	switch (sk->sk_type) {
	case SOCK_SEQPACKET:
		sp->type = SCTP_SOCKET_UDP;
		break;
	case SOCK_STREAM:
		sp->type = SCTP_SOCKET_TCP;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	
	sp->default_stream = 0;
	sp->default_ppid = 0;
	sp->default_flags = 0;
	sp->default_context = 0;
	sp->default_timetolive = 0;

	
	sp->initmsg.sinit_num_ostreams   = sctp_max_outstreams;
	sp->initmsg.sinit_max_instreams  = sctp_max_instreams;
	sp->initmsg.sinit_max_attempts   = sctp_max_retrans_init;
	sp->initmsg.sinit_max_init_timeo = jiffies_to_msecs(sctp_rto_max);

	
	sp->rtoinfo.srto_initial = jiffies_to_msecs(sctp_rto_initial);
	sp->rtoinfo.srto_max     = jiffies_to_msecs(sctp_rto_max);
	sp->rtoinfo.srto_min     = jiffies_to_msecs(sctp_rto_min);

	
	sp->assocparams.sasoc_asocmaxrxt = sctp_max_retrans_association;
	sp->assocparams.sasoc_number_peer_destinations = 0;
	sp->assocparams.sasoc_peer_rwnd = 0;
	sp->assocparams.sasoc_local_rwnd = 0;
	sp->assocparams.sasoc_cookie_life =  jiffies_to_msecs(sctp_valid_cookie_life);

	
	memset(&sp->subscribe, 0, sizeof(struct sctp_event_subscribe));

	
	sp->hbinterval  = jiffies_to_msecs(sctp_hb_interval);
	sp->pathmaxrxt  = sctp_max_retrans_path;
	sp->pathmtu     = 0; 
	sp->sackdelay   = jiffies_to_msecs(sctp_sack_timeout);
	sp->param_flags = SPP_HB_ENABLE | SPP_PMTUD_ENABLE | SPP_SACKDELAY_ENABLE;


	
	sp->disable_fragments = 0;

	
	sp->nodelay           = 1;

	
	sp->v4mapped          = 1;

	
	sp->autoclose         = 0;

	
	sp->user_frag         = 0;

	sp->adaption_ind = 0;

	sp->pf = sctp_get_pf_specific(sk->sk_family);

	
	sp->pd_mode           = 0;
	skb_queue_head_init(&sp->pd_lobby);

	
	ep = sctp_endpoint_new(sk, GFP_KERNEL);
	if (!ep)
		return -ENOMEM;

	sp->ep = ep;
	sp->hmac = NULL;

	SCTP_DBG_OBJCNT_INC(sock);
	return 0;
}


SCTP_STATIC int sctp_destroy_sock(struct sock *sk)
{
	struct sctp_endpoint *ep;

	SCTP_DEBUG_PRINTK("sctp_destroy_sock(sk: %p)\n", sk);

	
	ep = sctp_sk(sk)->ep;
	sctp_endpoint_free(ep);

	return 0;
}


SCTP_STATIC void sctp_shutdown(struct sock *sk, int how)
{
	struct sctp_endpoint *ep;
	struct sctp_association *asoc;

	if (!sctp_style(sk, TCP))
		return;

	if (how & SEND_SHUTDOWN) {
		ep = sctp_sk(sk)->ep;
		if (!list_empty(&ep->asocs)) {
			asoc = list_entry(ep->asocs.next, struct sctp_association, asocs);
			sctp_primitive_SHUTDOWN(asoc, NULL);
		}
	}
}


static int sctp_getsockopt_sctp_status(struct sock *sk, int len, char __user *optval, int __user *optlen)

{
	struct sctp_status status;
	struct sctp_association *asoc = NULL;
	struct sctp_transport *transport;
	sctp_assoc_t associd;
	int retval = 0;

	if (len != sizeof(status)) {
		retval = -EINVAL;
		goto out;
	}

	if (copy_from_user(&status, optval, sizeof(status))) {
		retval = -EFAULT;
		goto out;
	}

	associd = status.sstat_assoc_id;
	asoc = sctp_id2assoc(sk, associd);
	if (!asoc) {
		retval = -EINVAL;
		goto out;
	}

	transport = asoc->peer.primary_path;

	status.sstat_assoc_id = sctp_assoc2id(asoc);
	status.sstat_state = asoc->state;
	status.sstat_rwnd =  asoc->peer.rwnd;
	status.sstat_unackdata = asoc->unack_data;

	status.sstat_penddata = sctp_tsnmap_pending(&asoc->peer.tsn_map);
	status.sstat_instrms = asoc->c.sinit_max_instreams;
	status.sstat_outstrms = asoc->c.sinit_num_ostreams;
	status.sstat_fragmentation_point = asoc->frag_point;
	status.sstat_primary.spinfo_assoc_id = sctp_assoc2id(transport->asoc);
	memcpy(&status.sstat_primary.spinfo_address, &(transport->ipaddr), sizeof(union sctp_addr));
	
	sctp_get_pf_specific(sk->sk_family)->addr_v4map(sctp_sk(sk), (union sctp_addr *)&status.sstat_primary.spinfo_address);
	status.sstat_primary.spinfo_state = transport->state;
	status.sstat_primary.spinfo_cwnd = transport->cwnd;
	status.sstat_primary.spinfo_srtt = transport->srtt;
	status.sstat_primary.spinfo_rto = jiffies_to_msecs(transport->rto);
	status.sstat_primary.spinfo_mtu = transport->pathmtu;

	if (status.sstat_primary.spinfo_state == SCTP_UNKNOWN)
		status.sstat_primary.spinfo_state = SCTP_ACTIVE;

	if (put_user(len, optlen)) {
		retval = -EFAULT;
		goto out;
	}

	SCTP_DEBUG_PRINTK("sctp_getsockopt_sctp_status(%d): %d %d %d\n", len, status.sstat_state, status.sstat_rwnd, status.sstat_assoc_id);


	if (copy_to_user(optval, &status, len)) {
		retval = -EFAULT;
		goto out;
	}

out:
	return (retval);
}



static int sctp_getsockopt_peer_addr_info(struct sock *sk, int len, char __user *optval, int __user *optlen)

{
	struct sctp_paddrinfo pinfo;
	struct sctp_transport *transport;
	int retval = 0;

	if (len != sizeof(pinfo)) {
		retval = -EINVAL;
		goto out;
	}

	if (copy_from_user(&pinfo, optval, sizeof(pinfo))) {
		retval = -EFAULT;
		goto out;
	}

	transport = sctp_addr_id2transport(sk, &pinfo.spinfo_address, pinfo.spinfo_assoc_id);
	if (!transport)
		return -EINVAL;

	pinfo.spinfo_assoc_id = sctp_assoc2id(transport->asoc);
	pinfo.spinfo_state = transport->state;
	pinfo.spinfo_cwnd = transport->cwnd;
	pinfo.spinfo_srtt = transport->srtt;
	pinfo.spinfo_rto = jiffies_to_msecs(transport->rto);
	pinfo.spinfo_mtu = transport->pathmtu;

	if (pinfo.spinfo_state == SCTP_UNKNOWN)
		pinfo.spinfo_state = SCTP_ACTIVE;

	if (put_user(len, optlen)) {
		retval = -EFAULT;
		goto out;
	}

	if (copy_to_user(optval, &pinfo, len)) {
		retval = -EFAULT;
		goto out;
	}

out:
	return (retval);
}


static int sctp_getsockopt_disable_fragments(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	int val;

	if (len < sizeof(int))
		return -EINVAL;

	len = sizeof(int);
	val = (sctp_sk(sk)->disable_fragments == 1);
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}


static int sctp_getsockopt_events(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	if (len != sizeof(struct sctp_event_subscribe))
		return -EINVAL;
	if (copy_to_user(optval, &sctp_sk(sk)->subscribe, len))
		return -EFAULT;
	return 0;
}


static int sctp_getsockopt_autoclose(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	
	if (sctp_style(sk, TCP))
		return -EOPNOTSUPP;
	if (len != sizeof(int))
		return -EINVAL;
	if (copy_to_user(optval, &sctp_sk(sk)->autoclose, len))
		return -EFAULT;
	return 0;
}


SCTP_STATIC int sctp_do_peeloff(struct sctp_association *asoc, struct socket **sockp)
{
	struct sock *sk = asoc->base.sk;
	struct socket *sock;
	int err = 0;

	
	if (!sctp_style(sk, UDP))
		return -EINVAL;

	
	err = sock_create(sk->sk_family, SOCK_SEQPACKET, IPPROTO_SCTP, &sock);
	if (err < 0)
		return err;

	
	sctp_sock_migrate(sk, sock->sk, asoc, SCTP_SOCKET_UDP_HIGH_BANDWIDTH);
	*sockp = sock;

	return err;
}

static int sctp_getsockopt_peeloff(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	sctp_peeloff_arg_t peeloff;
	struct socket *newsock;
	int retval = 0;
	struct sctp_association *asoc;

	if (len != sizeof(sctp_peeloff_arg_t))
		return -EINVAL;
	if (copy_from_user(&peeloff, optval, len))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, peeloff.associd);
	if (!asoc) {
		retval = -EINVAL;
		goto out;
	}

	SCTP_DEBUG_PRINTK("%s: sk: %p asoc: %p\n", __FUNCTION__, sk, asoc);

	retval = sctp_do_peeloff(asoc, &newsock);
	if (retval < 0)
		goto out;

	
	retval = sock_map_fd(newsock);
	if (retval < 0) {
		sock_release(newsock);
		goto out;
	}

	SCTP_DEBUG_PRINTK("%s: sk: %p asoc: %p newsk: %p sd: %d\n", __FUNCTION__, sk, asoc, newsock->sk, retval);

	
	peeloff.sd = retval;
	if (copy_to_user(optval, &peeloff, len))
		retval = -EFAULT;

out:
	return retval;
}


static int sctp_getsockopt_peer_addr_params(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct sctp_paddrparams  params;
	struct sctp_transport   *trans = NULL;
	struct sctp_association *asoc = NULL;
	struct sctp_sock        *sp = sctp_sk(sk);

	if (len != sizeof(struct sctp_paddrparams))
		return -EINVAL;

	if (copy_from_user(&params, optval, len))
		return -EFAULT;

	
	if (!sctp_is_any(( union sctp_addr *)&params.spp_address)) {
		trans = sctp_addr_id2transport(sk, &params.spp_address, params.spp_assoc_id);
		if (!trans) {
			SCTP_DEBUG_PRINTK("Failed no transport\n");
			return -EINVAL;
		}
	}

	
	asoc = sctp_id2assoc(sk, params.spp_assoc_id);
	if (!asoc && params.spp_assoc_id && sctp_style(sk, UDP)) {
		SCTP_DEBUG_PRINTK("Failed no association\n");
		return -EINVAL;
	}

	if (trans) {
		
		params.spp_hbinterval = jiffies_to_msecs(trans->hbinterval);
		params.spp_pathmtu    = trans->pathmtu;
		params.spp_pathmaxrxt = trans->pathmaxrxt;
		params.spp_sackdelay  = jiffies_to_msecs(trans->sackdelay);

		
		params.spp_flags      = trans->param_flags;
	} else if (asoc) {
		
		params.spp_hbinterval = jiffies_to_msecs(asoc->hbinterval);
		params.spp_pathmtu    = asoc->pathmtu;
		params.spp_pathmaxrxt = asoc->pathmaxrxt;
		params.spp_sackdelay  = jiffies_to_msecs(asoc->sackdelay);

		
		params.spp_flags      = asoc->param_flags;
	} else {
		
		params.spp_hbinterval = sp->hbinterval;
		params.spp_pathmtu    = sp->pathmtu;
		params.spp_sackdelay  = sp->sackdelay;
		params.spp_pathmaxrxt = sp->pathmaxrxt;

		
		params.spp_flags      = sp->param_flags;
	}

	if (copy_to_user(optval, &params, len))
		return -EFAULT;

	if (put_user(len, optlen))
		return -EFAULT;

	return 0;
}


static int sctp_getsockopt_delayed_ack_time(struct sock *sk, int len, char __user *optval, int __user *optlen)

{
	struct sctp_assoc_value  params;
	struct sctp_association *asoc = NULL;
	struct sctp_sock        *sp = sctp_sk(sk);

	if (len != sizeof(struct sctp_assoc_value))
		return - EINVAL;

	if (copy_from_user(&params, optval, len))
		return -EFAULT;

	
	asoc = sctp_id2assoc(sk, params.assoc_id);
	if (!asoc && params.assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	if (asoc) {
		
		if (asoc->param_flags & SPP_SACKDELAY_ENABLE)
			params.assoc_value = jiffies_to_msecs( asoc->sackdelay);
		else params.assoc_value = 0;
	} else {
		
		if (sp->param_flags & SPP_SACKDELAY_ENABLE)
			params.assoc_value  = sp->sackdelay;
		else params.assoc_value  = 0;
	}

	if (copy_to_user(optval, &params, len))
		return -EFAULT;

	if (put_user(len, optlen))
		return -EFAULT;

	return 0;
}


static int sctp_getsockopt_initmsg(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	if (len != sizeof(struct sctp_initmsg))
		return -EINVAL;
	if (copy_to_user(optval, &sctp_sk(sk)->initmsg, len))
		return -EFAULT;
	return 0;
}

static int sctp_getsockopt_peer_addrs_num_old(struct sock *sk, int len, char __user *optval, int __user *optlen)

{
	sctp_assoc_t id;
	struct sctp_association *asoc;
	struct list_head *pos;
	int cnt = 0;

	if (len != sizeof(sctp_assoc_t))
		return -EINVAL;

	if (copy_from_user(&id, optval, sizeof(sctp_assoc_t)))
		return -EFAULT;

	
	asoc = sctp_id2assoc(sk, id);
	if (!asoc)
		return -EINVAL;

	list_for_each(pos, &asoc->peer.transport_addr_list) {
		cnt ++;
	}

	return cnt;
}


static int sctp_getsockopt_peer_addrs_old(struct sock *sk, int len, char __user *optval, int __user *optlen)

{
	struct sctp_association *asoc;
	struct list_head *pos;
	int cnt = 0;
	struct sctp_getaddrs_old getaddrs;
	struct sctp_transport *from;
	void __user *to;
	union sctp_addr temp;
	struct sctp_sock *sp = sctp_sk(sk);
	int addrlen;

	if (len != sizeof(struct sctp_getaddrs_old))
		return -EINVAL;

	if (copy_from_user(&getaddrs, optval, sizeof(struct sctp_getaddrs_old)))
		return -EFAULT;

	if (getaddrs.addr_num <= 0) return -EINVAL;

	
	asoc = sctp_id2assoc(sk, getaddrs.assoc_id);
	if (!asoc)
		return -EINVAL;

	to = (void __user *)getaddrs.addrs;
	list_for_each(pos, &asoc->peer.transport_addr_list) {
		from = list_entry(pos, struct sctp_transport, transports);
		memcpy(&temp, &from->ipaddr, sizeof(temp));
		sctp_get_pf_specific(sk->sk_family)->addr_v4map(sp, &temp);
		addrlen = sctp_get_af_specific(sk->sk_family)->sockaddr_len;
		temp.v4.sin_port = htons(temp.v4.sin_port);
		if (copy_to_user(to, &temp, addrlen))
			return -EFAULT;
		to += addrlen ;
		cnt ++;
		if (cnt >= getaddrs.addr_num) break;
	}
	getaddrs.addr_num = cnt;
	if (copy_to_user(optval, &getaddrs, sizeof(struct sctp_getaddrs_old)))
		return -EFAULT;

	return 0;
}

static int sctp_getsockopt_peer_addrs(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct sctp_association *asoc;
	struct list_head *pos;
	int cnt = 0;
	struct sctp_getaddrs getaddrs;
	struct sctp_transport *from;
	void __user *to;
	union sctp_addr temp;
	struct sctp_sock *sp = sctp_sk(sk);
	int addrlen;
	size_t space_left;
	int bytes_copied;

	if (len < sizeof(struct sctp_getaddrs))
		return -EINVAL;

	if (copy_from_user(&getaddrs, optval, sizeof(struct sctp_getaddrs)))
		return -EFAULT;

	
	asoc = sctp_id2assoc(sk, getaddrs.assoc_id);
	if (!asoc)
		return -EINVAL;

	to = optval + offsetof(struct sctp_getaddrs,addrs);
	space_left = len - sizeof(struct sctp_getaddrs) -  offsetof(struct sctp_getaddrs,addrs);

	list_for_each(pos, &asoc->peer.transport_addr_list) {
		from = list_entry(pos, struct sctp_transport, transports);
		memcpy(&temp, &from->ipaddr, sizeof(temp));
		sctp_get_pf_specific(sk->sk_family)->addr_v4map(sp, &temp);
		addrlen = sctp_get_af_specific(sk->sk_family)->sockaddr_len;
		if(space_left < addrlen)
			return -ENOMEM;
		temp.v4.sin_port = htons(temp.v4.sin_port);
		if (copy_to_user(to, &temp, addrlen))
			return -EFAULT;
		to += addrlen;
		cnt++;
		space_left -= addrlen;
	}

	if (put_user(cnt, &((struct sctp_getaddrs __user *)optval)->addr_num))
		return -EFAULT;
	bytes_copied = ((char __user *)to) - optval;
	if (put_user(bytes_copied, optlen))
		return -EFAULT;

	return 0;
}

static int sctp_getsockopt_local_addrs_num_old(struct sock *sk, int len, char __user *optval, int __user *optlen)

{
	sctp_assoc_t id;
	struct sctp_bind_addr *bp;
	struct sctp_association *asoc;
	struct list_head *pos;
	struct sctp_sockaddr_entry *addr;
	rwlock_t *addr_lock;
	unsigned long flags;
	int cnt = 0;

	if (len != sizeof(sctp_assoc_t))
		return -EINVAL;

	if (copy_from_user(&id, optval, sizeof(sctp_assoc_t)))
		return -EFAULT;

	
	if (0 == id) {
		bp = &sctp_sk(sk)->ep->base.bind_addr;
		addr_lock = &sctp_sk(sk)->ep->base.addr_lock;
	} else {
		asoc = sctp_id2assoc(sk, id);
		if (!asoc)
			return -EINVAL;
		bp = &asoc->base.bind_addr;
		addr_lock = &asoc->base.addr_lock;
	}

	sctp_read_lock(addr_lock);

	
	if (sctp_list_single_entry(&bp->address_list)) {
		addr = list_entry(bp->address_list.next, struct sctp_sockaddr_entry, list);
		if (sctp_is_any(&addr->a)) {
			sctp_spin_lock_irqsave(&sctp_local_addr_lock, flags);
			list_for_each(pos, &sctp_local_addr_list) {
				addr = list_entry(pos, struct sctp_sockaddr_entry, list);

				if ((PF_INET == sk->sk_family) &&  (AF_INET6 == addr->a.sa.sa_family))
					continue;
				cnt++;
			}
			sctp_spin_unlock_irqrestore(&sctp_local_addr_lock, flags);
		} else {
			cnt = 1;
		}
		goto done;
	}

	list_for_each(pos, &bp->address_list) {
		cnt ++;
	}

done:
	sctp_read_unlock(addr_lock);
	return cnt;
}


static int sctp_copy_laddrs_to_user_old(struct sock *sk, __u16 port, int max_addrs, void __user *to)
{
	struct list_head *pos;
	struct sctp_sockaddr_entry *addr;
	unsigned long flags;
	union sctp_addr temp;
	int cnt = 0;
	int addrlen;

	sctp_spin_lock_irqsave(&sctp_local_addr_lock, flags);
	list_for_each(pos, &sctp_local_addr_list) {
		addr = list_entry(pos, struct sctp_sockaddr_entry, list);
		if ((PF_INET == sk->sk_family) &&  (AF_INET6 == addr->a.sa.sa_family))
			continue;
		memcpy(&temp, &addr->a, sizeof(temp));
		sctp_get_pf_specific(sk->sk_family)->addr_v4map(sctp_sk(sk), &temp);
		addrlen = sctp_get_af_specific(temp.sa.sa_family)->sockaddr_len;
		temp.v4.sin_port = htons(port);
		if (copy_to_user(to, &temp, addrlen)) {
			sctp_spin_unlock_irqrestore(&sctp_local_addr_lock, flags);
			return -EFAULT;
		}
		to += addrlen;
		cnt ++;
		if (cnt >= max_addrs) break;
	}
	sctp_spin_unlock_irqrestore(&sctp_local_addr_lock, flags);

	return cnt;
}

static int sctp_copy_laddrs_to_user(struct sock *sk, __u16 port, void __user **to, size_t space_left)
{
	struct list_head *pos;
	struct sctp_sockaddr_entry *addr;
	unsigned long flags;
	union sctp_addr temp;
	int cnt = 0;
	int addrlen;

	sctp_spin_lock_irqsave(&sctp_local_addr_lock, flags);
	list_for_each(pos, &sctp_local_addr_list) {
		addr = list_entry(pos, struct sctp_sockaddr_entry, list);
		if ((PF_INET == sk->sk_family) &&  (AF_INET6 == addr->a.sa.sa_family))
			continue;
		memcpy(&temp, &addr->a, sizeof(temp));
		sctp_get_pf_specific(sk->sk_family)->addr_v4map(sctp_sk(sk), &temp);
		addrlen = sctp_get_af_specific(temp.sa.sa_family)->sockaddr_len;
		if(space_left<addrlen)
			return -ENOMEM;
		temp.v4.sin_port = htons(port);
		if (copy_to_user(*to, &temp, addrlen)) {
			sctp_spin_unlock_irqrestore(&sctp_local_addr_lock, flags);
			return -EFAULT;
		}
		*to += addrlen;
		cnt ++;
		space_left -= addrlen;
	}
	sctp_spin_unlock_irqrestore(&sctp_local_addr_lock, flags);

	return cnt;
}


static int sctp_getsockopt_local_addrs_old(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct sctp_bind_addr *bp;
	struct sctp_association *asoc;
	struct list_head *pos;
	int cnt = 0;
	struct sctp_getaddrs_old getaddrs;
	struct sctp_sockaddr_entry *addr;
	void __user *to;
	union sctp_addr temp;
	struct sctp_sock *sp = sctp_sk(sk);
	int addrlen;
	rwlock_t *addr_lock;
	int err = 0;

	if (len != sizeof(struct sctp_getaddrs_old))
		return -EINVAL;

	if (copy_from_user(&getaddrs, optval, sizeof(struct sctp_getaddrs_old)))
		return -EFAULT;

	if (getaddrs.addr_num <= 0) return -EINVAL;
	
	if (0 == getaddrs.assoc_id) {
		bp = &sctp_sk(sk)->ep->base.bind_addr;
		addr_lock = &sctp_sk(sk)->ep->base.addr_lock;
	} else {
		asoc = sctp_id2assoc(sk, getaddrs.assoc_id);
		if (!asoc)
			return -EINVAL;
		bp = &asoc->base.bind_addr;
		addr_lock = &asoc->base.addr_lock;
	}

	to = getaddrs.addrs;

	sctp_read_lock(addr_lock);

	
	if (sctp_list_single_entry(&bp->address_list)) {
		addr = list_entry(bp->address_list.next, struct sctp_sockaddr_entry, list);
		if (sctp_is_any(&addr->a)) {
			cnt = sctp_copy_laddrs_to_user_old(sk, bp->port, getaddrs.addr_num, to);

			if (cnt < 0) {
				err = cnt;
				goto unlock;
			}
			goto copy_getaddrs;		
		}
	}

	list_for_each(pos, &bp->address_list) {
		addr = list_entry(pos, struct sctp_sockaddr_entry, list);
		memcpy(&temp, &addr->a, sizeof(temp));
		sctp_get_pf_specific(sk->sk_family)->addr_v4map(sp, &temp);
		addrlen = sctp_get_af_specific(temp.sa.sa_family)->sockaddr_len;
		temp.v4.sin_port = htons(temp.v4.sin_port);
		if (copy_to_user(to, &temp, addrlen)) {
			err = -EFAULT;
			goto unlock;
		}
		to += addrlen;
		cnt ++;
		if (cnt >= getaddrs.addr_num) break;
	}

copy_getaddrs:
	getaddrs.addr_num = cnt;
	if (copy_to_user(optval, &getaddrs, sizeof(struct sctp_getaddrs_old)))
		err = -EFAULT;

unlock:
	sctp_read_unlock(addr_lock);
	return err;
}

static int sctp_getsockopt_local_addrs(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct sctp_bind_addr *bp;
	struct sctp_association *asoc;
	struct list_head *pos;
	int cnt = 0;
	struct sctp_getaddrs getaddrs;
	struct sctp_sockaddr_entry *addr;
	void __user *to;
	union sctp_addr temp;
	struct sctp_sock *sp = sctp_sk(sk);
	int addrlen;
	rwlock_t *addr_lock;
	int err = 0;
	size_t space_left;
	int bytes_copied;

	if (len <= sizeof(struct sctp_getaddrs))
		return -EINVAL;

	if (copy_from_user(&getaddrs, optval, sizeof(struct sctp_getaddrs)))
		return -EFAULT;

	
	if (0 == getaddrs.assoc_id) {
		bp = &sctp_sk(sk)->ep->base.bind_addr;
		addr_lock = &sctp_sk(sk)->ep->base.addr_lock;
	} else {
		asoc = sctp_id2assoc(sk, getaddrs.assoc_id);
		if (!asoc)
			return -EINVAL;
		bp = &asoc->base.bind_addr;
		addr_lock = &asoc->base.addr_lock;
	}

	to = optval + offsetof(struct sctp_getaddrs,addrs);
	space_left = len - sizeof(struct sctp_getaddrs) - offsetof(struct sctp_getaddrs,addrs);

	sctp_read_lock(addr_lock);

	
	if (sctp_list_single_entry(&bp->address_list)) {
		addr = list_entry(bp->address_list.next, struct sctp_sockaddr_entry, list);
		if (sctp_is_any(&addr->a)) {
			cnt = sctp_copy_laddrs_to_user(sk, bp->port, &to, space_left);
			if (cnt < 0) {
				err = cnt;
				goto unlock;
			}
			goto copy_getaddrs;		
		}
	}

	list_for_each(pos, &bp->address_list) {
		addr = list_entry(pos, struct sctp_sockaddr_entry, list);
		memcpy(&temp, &addr->a, sizeof(temp));
		sctp_get_pf_specific(sk->sk_family)->addr_v4map(sp, &temp);
		addrlen = sctp_get_af_specific(temp.sa.sa_family)->sockaddr_len;
		if(space_left < addrlen)
			return -ENOMEM; 
		temp.v4.sin_port = htons(temp.v4.sin_port);
		if (copy_to_user(to, &temp, addrlen)) {
			err = -EFAULT;
			goto unlock;
		}
		to += addrlen;
		cnt ++;
		space_left -= addrlen;
	}

copy_getaddrs:
	if (put_user(cnt, &((struct sctp_getaddrs __user *)optval)->addr_num))
		return -EFAULT;
	bytes_copied = ((char __user *)to) - optval;
	if (put_user(bytes_copied, optlen))
		return -EFAULT;

unlock:
	sctp_read_unlock(addr_lock);
	return err;
}


static int sctp_getsockopt_primary_addr(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct sctp_prim prim;
	struct sctp_association *asoc;
	struct sctp_sock *sp = sctp_sk(sk);

	if (len != sizeof(struct sctp_prim))
		return -EINVAL;

	if (copy_from_user(&prim, optval, sizeof(struct sctp_prim)))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, prim.ssp_assoc_id);
	if (!asoc)
		return -EINVAL;

	if (!asoc->peer.primary_path)
		return -ENOTCONN;
	
	asoc->peer.primary_path->ipaddr.v4.sin_port = htons(asoc->peer.primary_path->ipaddr.v4.sin_port);
	memcpy(&prim.ssp_addr, &asoc->peer.primary_path->ipaddr, sizeof(union sctp_addr));
	asoc->peer.primary_path->ipaddr.v4.sin_port = ntohs(asoc->peer.primary_path->ipaddr.v4.sin_port);

	sctp_get_pf_specific(sk->sk_family)->addr_v4map(sp, (union sctp_addr *)&prim.ssp_addr);

	if (copy_to_user(optval, &prim, sizeof(struct sctp_prim)))
		return -EFAULT;

	return 0;
}


static int sctp_getsockopt_adaption_layer(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	struct sctp_setadaption adaption;

	if (len != sizeof(struct sctp_setadaption))
		return -EINVAL;

	adaption.ssb_adaption_ind = sctp_sk(sk)->adaption_ind;
	if (copy_to_user(optval, &adaption, len))
		return -EFAULT;

	return 0;
}


static int sctp_getsockopt_default_send_param(struct sock *sk, int len, char __user *optval, int __user *optlen)

{
	struct sctp_sndrcvinfo info;
	struct sctp_association *asoc;
	struct sctp_sock *sp = sctp_sk(sk);

	if (len != sizeof(struct sctp_sndrcvinfo))
		return -EINVAL;
	if (copy_from_user(&info, optval, sizeof(struct sctp_sndrcvinfo)))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, info.sinfo_assoc_id);
	if (!asoc && info.sinfo_assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	if (asoc) {
		info.sinfo_stream = asoc->default_stream;
		info.sinfo_flags = asoc->default_flags;
		info.sinfo_ppid = asoc->default_ppid;
		info.sinfo_context = asoc->default_context;
		info.sinfo_timetolive = asoc->default_timetolive;
	} else {
		info.sinfo_stream = sp->default_stream;
		info.sinfo_flags = sp->default_flags;
		info.sinfo_ppid = sp->default_ppid;
		info.sinfo_context = sp->default_context;
		info.sinfo_timetolive = sp->default_timetolive;
	}

	if (copy_to_user(optval, &info, sizeof(struct sctp_sndrcvinfo)))
		return -EFAULT;

	return 0;
}



static int sctp_getsockopt_nodelay(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	int val;

	if (len < sizeof(int))
		return -EINVAL;

	len = sizeof(int);
	val = (sctp_sk(sk)->nodelay == 1);
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}


static int sctp_getsockopt_rtoinfo(struct sock *sk, int len, char __user *optval, int __user *optlen) {

	struct sctp_rtoinfo rtoinfo;
	struct sctp_association *asoc;

	if (len != sizeof (struct sctp_rtoinfo))
		return -EINVAL;

	if (copy_from_user(&rtoinfo, optval, sizeof (struct sctp_rtoinfo)))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, rtoinfo.srto_assoc_id);

	if (!asoc && rtoinfo.srto_assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	
	if (asoc) {
		rtoinfo.srto_initial = jiffies_to_msecs(asoc->rto_initial);
		rtoinfo.srto_max = jiffies_to_msecs(asoc->rto_max);
		rtoinfo.srto_min = jiffies_to_msecs(asoc->rto_min);
	} else {
		
		struct sctp_sock *sp = sctp_sk(sk);

		rtoinfo.srto_initial = sp->rtoinfo.srto_initial;
		rtoinfo.srto_max = sp->rtoinfo.srto_max;
		rtoinfo.srto_min = sp->rtoinfo.srto_min;
	}

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &rtoinfo, len))
		return -EFAULT;

	return 0;
}


static int sctp_getsockopt_associnfo(struct sock *sk, int len, char __user *optval, int __user *optlen)

{

	struct sctp_assocparams assocparams;
	struct sctp_association *asoc;
	struct list_head *pos;
	int cnt = 0;

	if (len != sizeof (struct sctp_assocparams))
		return -EINVAL;

	if (copy_from_user(&assocparams, optval, sizeof (struct sctp_assocparams)))
		return -EFAULT;

	asoc = sctp_id2assoc(sk, assocparams.sasoc_assoc_id);

	if (!asoc && assocparams.sasoc_assoc_id && sctp_style(sk, UDP))
		return -EINVAL;

	
	if (asoc) {
		assocparams.sasoc_asocmaxrxt = asoc->max_retrans;
		assocparams.sasoc_peer_rwnd = asoc->peer.rwnd;
		assocparams.sasoc_local_rwnd = asoc->a_rwnd;
		assocparams.sasoc_cookie_life = (asoc->cookie_life.tv_sec * 1000) + (asoc->cookie_life.tv_usec / 1000);



		list_for_each(pos, &asoc->peer.transport_addr_list) {
			cnt ++;
		}

		assocparams.sasoc_number_peer_destinations = cnt;
	} else {
		
		struct sctp_sock *sp = sctp_sk(sk);

		assocparams.sasoc_asocmaxrxt = sp->assocparams.sasoc_asocmaxrxt;
		assocparams.sasoc_peer_rwnd = sp->assocparams.sasoc_peer_rwnd;
		assocparams.sasoc_local_rwnd = sp->assocparams.sasoc_local_rwnd;
		assocparams.sasoc_cookie_life = sp->assocparams.sasoc_cookie_life;
		assocparams.sasoc_number_peer_destinations = sp->assocparams. sasoc_number_peer_destinations;

	}

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &assocparams, len))
		return -EFAULT;

	return 0;
}


static int sctp_getsockopt_mappedv4(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	int val;
	struct sctp_sock *sp = sctp_sk(sk);

	if (len < sizeof(int))
		return -EINVAL;

	len = sizeof(int);
	val = sp->v4mapped;
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return 0;
}


static int sctp_getsockopt_maxseg(struct sock *sk, int len, char __user *optval, int __user *optlen)
{
	int val;

	if (len < sizeof(int))
		return -EINVAL;

	len = sizeof(int);

	val = sctp_sk(sk)->user_frag;
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return 0;
}

SCTP_STATIC int sctp_getsockopt(struct sock *sk, int level, int optname, char __user *optval, int __user *optlen)
{
	int retval = 0;
	int len;

	SCTP_DEBUG_PRINTK("sctp_getsockopt(sk: %p... optname: %d)\n", sk, optname);

	
	if (level != SOL_SCTP) {
		struct sctp_af *af = sctp_sk(sk)->pf->af;

		retval = af->getsockopt(sk, level, optname, optval, optlen);
		return retval;
	}

	if (get_user(len, optlen))
		return -EFAULT;

	sctp_lock_sock(sk);

	switch (optname) {
	case SCTP_STATUS:
		retval = sctp_getsockopt_sctp_status(sk, len, optval, optlen);
		break;
	case SCTP_DISABLE_FRAGMENTS:
		retval = sctp_getsockopt_disable_fragments(sk, len, optval, optlen);
		break;
	case SCTP_EVENTS:
		retval = sctp_getsockopt_events(sk, len, optval, optlen);
		break;
	case SCTP_AUTOCLOSE:
		retval = sctp_getsockopt_autoclose(sk, len, optval, optlen);
		break;
	case SCTP_SOCKOPT_PEELOFF:
		retval = sctp_getsockopt_peeloff(sk, len, optval, optlen);
		break;
	case SCTP_PEER_ADDR_PARAMS:
		retval = sctp_getsockopt_peer_addr_params(sk, len, optval, optlen);
		break;
	case SCTP_DELAYED_ACK_TIME:
		retval = sctp_getsockopt_delayed_ack_time(sk, len, optval, optlen);
		break;
	case SCTP_INITMSG:
		retval = sctp_getsockopt_initmsg(sk, len, optval, optlen);
		break;
	case SCTP_GET_PEER_ADDRS_NUM_OLD:
		retval = sctp_getsockopt_peer_addrs_num_old(sk, len, optval, optlen);
		break;
	case SCTP_GET_LOCAL_ADDRS_NUM_OLD:
		retval = sctp_getsockopt_local_addrs_num_old(sk, len, optval, optlen);
		break;
	case SCTP_GET_PEER_ADDRS_OLD:
		retval = sctp_getsockopt_peer_addrs_old(sk, len, optval, optlen);
		break;
	case SCTP_GET_LOCAL_ADDRS_OLD:
		retval = sctp_getsockopt_local_addrs_old(sk, len, optval, optlen);
		break;
	case SCTP_GET_PEER_ADDRS:
		retval = sctp_getsockopt_peer_addrs(sk, len, optval, optlen);
		break;
	case SCTP_GET_LOCAL_ADDRS:
		retval = sctp_getsockopt_local_addrs(sk, len, optval, optlen);
		break;
	case SCTP_DEFAULT_SEND_PARAM:
		retval = sctp_getsockopt_default_send_param(sk, len, optval, optlen);
		break;
	case SCTP_PRIMARY_ADDR:
		retval = sctp_getsockopt_primary_addr(sk, len, optval, optlen);
		break;
	case SCTP_NODELAY:
		retval = sctp_getsockopt_nodelay(sk, len, optval, optlen);
		break;
	case SCTP_RTOINFO:
		retval = sctp_getsockopt_rtoinfo(sk, len, optval, optlen);
		break;
	case SCTP_ASSOCINFO:
		retval = sctp_getsockopt_associnfo(sk, len, optval, optlen);
		break;
	case SCTP_I_WANT_MAPPED_V4_ADDR:
		retval = sctp_getsockopt_mappedv4(sk, len, optval, optlen);
		break;
	case SCTP_MAXSEG:
		retval = sctp_getsockopt_maxseg(sk, len, optval, optlen);
		break;
	case SCTP_GET_PEER_ADDR_INFO:
		retval = sctp_getsockopt_peer_addr_info(sk, len, optval, optlen);
		break;
	case SCTP_ADAPTION_LAYER:
		retval = sctp_getsockopt_adaption_layer(sk, len, optval, optlen);
		break;
	default:
		retval = -ENOPROTOOPT;
		break;
	};

	sctp_release_sock(sk);
	return retval;
}

static void sctp_hash(struct sock *sk)
{
	
}

static void sctp_unhash(struct sock *sk)
{
	
}


static struct sctp_bind_bucket *sctp_bucket_create( struct sctp_bind_hashbucket *head, unsigned short snum);

static long sctp_get_port_local(struct sock *sk, union sctp_addr *addr)
{
	struct sctp_bind_hashbucket *head; 
	struct sctp_bind_bucket *pp; 
	unsigned short snum;
	int ret;

	
	addr->v4.sin_port = ntohs(addr->v4.sin_port);
	snum = addr->v4.sin_port;

	SCTP_DEBUG_PRINTK("sctp_get_port() begins, snum=%d\n", snum);
	sctp_local_bh_disable();

	if (snum == 0) {
		
		int low = sysctl_local_port_range[0];
		int high = sysctl_local_port_range[1];
		int remaining = (high - low) + 1;
		int rover;
		int index;

		sctp_spin_lock(&sctp_port_alloc_lock);
		rover = sctp_port_rover;
		do {
			rover++;
			if ((rover < low) || (rover > high))
				rover = low;
			index = sctp_phashfn(rover);
			head = &sctp_port_hashtable[index];
			sctp_spin_lock(&head->lock);
			for (pp = head->chain; pp; pp = pp->next)
				if (pp->port == rover)
					goto next;
			break;
		next:
			sctp_spin_unlock(&head->lock);
		} while (--remaining > 0);
		sctp_port_rover = rover;
		sctp_spin_unlock(&sctp_port_alloc_lock);

		
		ret = 1;
		if (remaining <= 0)
			goto fail;

		
		snum = rover;
	} else {
		
		head = &sctp_port_hashtable[sctp_phashfn(snum)];
		sctp_spin_lock(&head->lock);
		for (pp = head->chain; pp; pp = pp->next) {
			if (pp->port == snum)
				goto pp_found;
		}
	}
	pp = NULL;
	goto pp_not_found;
pp_found:
	if (!hlist_empty(&pp->owner)) {
		
		int reuse = sk->sk_reuse;
		struct sock *sk2;
		struct hlist_node *node;

		SCTP_DEBUG_PRINTK("sctp_get_port() found a possible match\n");
		if (pp->fastreuse && sk->sk_reuse)
			goto success;

		
		sk_for_each_bound(sk2, node, &pp->owner) {
			struct sctp_endpoint *ep2;
			ep2 = sctp_sk(sk2)->ep;

			if (reuse && sk2->sk_reuse)
				continue;

			if (sctp_bind_addr_match(&ep2->base.bind_addr, addr, sctp_sk(sk))) {
				ret = (long)sk2;
				goto fail_unlock;
			}
		}
		SCTP_DEBUG_PRINTK("sctp_get_port(): Found a match\n");
	}
pp_not_found:
	
	ret = 1;
	if (!pp && !(pp = sctp_bucket_create(head, snum)))
		goto fail_unlock;

	
	if (hlist_empty(&pp->owner))
		pp->fastreuse = sk->sk_reuse ? 1 : 0;
	else if (pp->fastreuse && !sk->sk_reuse)
		pp->fastreuse = 0;

	
success:
	inet_sk(sk)->num = snum;
	if (!sctp_sk(sk)->bind_hash) {
		sk_add_bind_node(sk, &pp->owner);
		sctp_sk(sk)->bind_hash = pp;
	}
	ret = 0;

fail_unlock:
	sctp_spin_unlock(&head->lock);

fail:
	sctp_local_bh_enable();
	addr->v4.sin_port = htons(addr->v4.sin_port);
	return ret;
}


static int sctp_get_port(struct sock *sk, unsigned short snum)
{
	long ret;
	union sctp_addr addr;
	struct sctp_af *af = sctp_sk(sk)->pf->af;

	
	af->from_sk(&addr, sk);
	addr.v4.sin_port = htons(snum);

	
	ret = sctp_get_port_local(sk, &addr);

	return (ret ? 1 : 0);
}


SCTP_STATIC int sctp_seqpacket_listen(struct sock *sk, int backlog)
{
	struct sctp_sock *sp = sctp_sk(sk);
	struct sctp_endpoint *ep = sp->ep;

	
	if (!sctp_style(sk, UDP))
		return -EINVAL;

	
	if (!backlog) {
		if (sctp_sstate(sk, CLOSED))
			return 0;
		
		sctp_unhash_endpoint(ep);
		sk->sk_state = SCTP_SS_CLOSED;
	}

	
	if (sctp_sstate(sk, LISTENING))
		return 0;
		
	
	if (!ep->base.bind_addr.port) {
		if (sctp_autobind(sk))
			return -EAGAIN;
	}
	sk->sk_state = SCTP_SS_LISTENING;
	sctp_hash_endpoint(ep);
	return 0;
}


SCTP_STATIC int sctp_stream_listen(struct sock *sk, int backlog)
{
	struct sctp_sock *sp = sctp_sk(sk);
	struct sctp_endpoint *ep = sp->ep;

	
	if (!backlog) {
		if (sctp_sstate(sk, CLOSED))
			return 0;
		
		sctp_unhash_endpoint(ep);
		sk->sk_state = SCTP_SS_CLOSED;
	}

	if (sctp_sstate(sk, LISTENING))
		return 0;

	
	if (!ep->base.bind_addr.port) {
		if (sctp_autobind(sk))
			return -EAGAIN;
	}
	sk->sk_state = SCTP_SS_LISTENING;
	sk->sk_max_ack_backlog = backlog;
	sctp_hash_endpoint(ep);
	return 0;
}


int sctp_inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct crypto_tfm *tfm=NULL;
	int err = -EINVAL;

	if (unlikely(backlog < 0))
		goto out;

	sctp_lock_sock(sk);

	if (sock->state != SS_UNCONNECTED)
		goto out;

	
	if (sctp_hmac_alg) {
		tfm = sctp_crypto_alloc_tfm(sctp_hmac_alg, 0);
		if (!tfm) {
			err = -ENOSYS;
			goto out;
		}
	}

	switch (sock->type) {
	case SOCK_SEQPACKET:
		err = sctp_seqpacket_listen(sk, backlog);
		break;
	case SOCK_STREAM:
		err = sctp_stream_listen(sk, backlog);
		break;
	default:
		break;
	};
	if (err)
		goto cleanup;

	
	sctp_sk(sk)->hmac = tfm;
out:
	sctp_release_sock(sk);
	return err;
cleanup:
	sctp_crypto_free_tfm(tfm);
	goto out;
}


unsigned int sctp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct sctp_sock *sp = sctp_sk(sk);
	unsigned int mask;

	poll_wait(file, sk->sk_sleep, wait);

	
	if (sctp_style(sk, TCP) && sctp_sstate(sk, LISTENING))
		return (!list_empty(&sp->ep->asocs)) ? (POLLIN | POLLRDNORM) : 0;

	mask = 0;

	
	if (sk->sk_err || !skb_queue_empty(&sk->sk_error_queue))
		mask |= POLLERR;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLRDHUP;
	if (sk->sk_shutdown == SHUTDOWN_MASK)
		mask |= POLLHUP;

	
	if (!skb_queue_empty(&sk->sk_receive_queue) || (sk->sk_shutdown & RCV_SHUTDOWN))
		mask |= POLLIN | POLLRDNORM;

	
	if (!sctp_style(sk, UDP) && sctp_sstate(sk, CLOSED))
		return mask;

	
	if (sctp_writeable(sk)) {
		mask |= POLLOUT | POLLWRNORM;
	} else {
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
		
		if (sctp_writeable(sk))
			mask |= POLLOUT | POLLWRNORM;
	}
	return mask;
}



static struct sctp_bind_bucket *sctp_bucket_create( struct sctp_bind_hashbucket *head, unsigned short snum)
{
	struct sctp_bind_bucket *pp;

	pp = kmem_cache_alloc(sctp_bucket_cachep, SLAB_ATOMIC);
	SCTP_DBG_OBJCNT_INC(bind_bucket);
	if (pp) {
		pp->port = snum;
		pp->fastreuse = 0;
		INIT_HLIST_HEAD(&pp->owner);
		if ((pp->next = head->chain) != NULL)
			pp->next->pprev = &pp->next;
		head->chain = pp;
		pp->pprev = &head->chain;
	}
	return pp;
}


static void sctp_bucket_destroy(struct sctp_bind_bucket *pp)
{
	if (pp && hlist_empty(&pp->owner)) {
		if (pp->next)
			pp->next->pprev = pp->pprev;
		*(pp->pprev) = pp->next;
		kmem_cache_free(sctp_bucket_cachep, pp);
		SCTP_DBG_OBJCNT_DEC(bind_bucket);
	}
}


static inline void __sctp_put_port(struct sock *sk)
{
	struct sctp_bind_hashbucket *head = &sctp_port_hashtable[sctp_phashfn(inet_sk(sk)->num)];
	struct sctp_bind_bucket *pp;

	sctp_spin_lock(&head->lock);
	pp = sctp_sk(sk)->bind_hash;
	__sk_del_bind_node(sk);
	sctp_sk(sk)->bind_hash = NULL;
	inet_sk(sk)->num = 0;
	sctp_bucket_destroy(pp);
	sctp_spin_unlock(&head->lock);
}

void sctp_put_port(struct sock *sk)
{
	sctp_local_bh_disable();
	__sctp_put_port(sk);
	sctp_local_bh_enable();
}


static int sctp_autobind(struct sock *sk)
{
	union sctp_addr autoaddr;
	struct sctp_af *af;
	unsigned short port;

	
	af = sctp_sk(sk)->pf->af;

	port = htons(inet_sk(sk)->num);
	af->inaddr_any(&autoaddr, port);

	return sctp_do_bind(sk, &autoaddr, af->sockaddr_len);
}


SCTP_STATIC int sctp_msghdr_parse(const struct msghdr *msg, sctp_cmsgs_t *cmsgs)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR((struct msghdr*)msg, cmsg)) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		
		if (cmsg->cmsg_level != IPPROTO_SCTP)
			continue;

		
		switch (cmsg->cmsg_type) {
		case SCTP_INIT:
			
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct sctp_initmsg)))
				return -EINVAL;
			cmsgs->init = (struct sctp_initmsg *)CMSG_DATA(cmsg);
			break;

		case SCTP_SNDRCV:
			
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct sctp_sndrcvinfo)))
				return -EINVAL;

			cmsgs->info = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);

			
			if (cmsgs->info->sinfo_flags & ~(SCTP_UNORDERED | SCTP_ADDR_OVER | SCTP_ABORT | SCTP_EOF))

				return -EINVAL;
			break;

		default:
			return -EINVAL;
		};
	}
	return 0;
}


static int sctp_wait_for_packet(struct sock * sk, int *err, long *timeo_p)
{
	int error;
	DEFINE_WAIT(wait);

	prepare_to_wait_exclusive(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

	
	error = sock_error(sk);
	if (error)
		goto out;

	if (!skb_queue_empty(&sk->sk_receive_queue))
		goto ready;

	
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		goto out;

	
	error = -ENOTCONN;

	
	if (list_empty(&sctp_sk(sk)->ep->asocs) && !sctp_sstate(sk, LISTENING))
		goto out;

	
	if (signal_pending(current))
		goto interrupted;

	
	sctp_release_sock(sk);
	*timeo_p = schedule_timeout(*timeo_p);
	sctp_lock_sock(sk);

ready:
	finish_wait(sk->sk_sleep, &wait);
	return 0;

interrupted:
	error = sock_intr_errno(*timeo_p);

out:
	finish_wait(sk->sk_sleep, &wait);
	*err = error;
	return error;
}


static struct sk_buff *sctp_skb_recv_datagram(struct sock *sk, int flags, int noblock, int *err)
{
	int error;
	struct sk_buff *skb;
	long timeo;

	timeo = sock_rcvtimeo(sk, noblock);

	SCTP_DEBUG_PRINTK("Timeout: timeo: %ld, MAX: %ld.\n", timeo, MAX_SCHEDULE_TIMEOUT);

	do {
		
		if (flags & MSG_PEEK) {
			spin_lock_bh(&sk->sk_receive_queue.lock);
			skb = skb_peek(&sk->sk_receive_queue);
			if (skb)
				atomic_inc(&skb->users);
			spin_unlock_bh(&sk->sk_receive_queue.lock);
		} else {
			skb = skb_dequeue(&sk->sk_receive_queue);
		}

		if (skb)
			return skb;

		
		error = sock_error(sk);
		if (error)
			goto no_packet;

		if (sk->sk_shutdown & RCV_SHUTDOWN)
			break;

		
		error = -EAGAIN;
		if (!timeo)
			goto no_packet;
	} while (sctp_wait_for_packet(sk, err, &timeo) == 0);

	return NULL;

no_packet:
	*err = error;
	return NULL;
}


static void __sctp_write_space(struct sctp_association *asoc)
{
	struct sock *sk = asoc->base.sk;
	struct socket *sock = sk->sk_socket;

	if ((sctp_wspace(asoc) > 0) && sock) {
		if (waitqueue_active(&asoc->wait))
			wake_up_interruptible(&asoc->wait);

		if (sctp_writeable(sk)) {
			if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
				wake_up_interruptible(sk->sk_sleep);

			
			if (sock->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
				sock_wake_async(sock, 2, POLL_OUT);
		}
	}
}


static void sctp_wfree(struct sk_buff *skb)
{
	struct sctp_association *asoc;
	struct sctp_chunk *chunk;
	struct sock *sk;

	
	chunk = *((struct sctp_chunk **)(skb->cb));
	asoc = chunk->asoc;
	sk = asoc->base.sk;
	asoc->sndbuf_used -= SCTP_DATA_SNDSIZE(chunk) + sizeof(struct sk_buff) + sizeof(struct sctp_chunk);


	atomic_sub(sizeof(struct sctp_chunk), &sk->sk_wmem_alloc);

	sock_wfree(skb);
	__sctp_write_space(asoc);

	sctp_association_put(asoc);
}


static int sctp_wait_for_sndbuf(struct sctp_association *asoc, long *timeo_p, size_t msg_len)
{
	struct sock *sk = asoc->base.sk;
	int err = 0;
	long current_timeo = *timeo_p;
	DEFINE_WAIT(wait);

	SCTP_DEBUG_PRINTK("wait_for_sndbuf: asoc=%p, timeo=%ld, msg_len=%zu\n", asoc, (long)(*timeo_p), msg_len);

	
	sctp_association_hold(asoc);

	
	for (;;) {
		prepare_to_wait_exclusive(&asoc->wait, &wait, TASK_INTERRUPTIBLE);
		if (!*timeo_p)
			goto do_nonblock;
		if (sk->sk_err || asoc->state >= SCTP_STATE_SHUTDOWN_PENDING || asoc->base.dead)
			goto do_error;
		if (signal_pending(current))
			goto do_interrupted;
		if (msg_len <= sctp_wspace(asoc))
			break;

		
		sctp_release_sock(sk);
		current_timeo = schedule_timeout(current_timeo);
		BUG_ON(sk != asoc->base.sk);
		sctp_lock_sock(sk);

		*timeo_p = current_timeo;
	}

out:
	finish_wait(&asoc->wait, &wait);

	
	sctp_association_put(asoc);

	return err;

do_error:
	err = -EPIPE;
	goto out;

do_interrupted:
	err = sock_intr_errno(*timeo_p);
	goto out;

do_nonblock:
	err = -EAGAIN;
	goto out;
}


void sctp_write_space(struct sock *sk)
{
	struct sctp_association *asoc;
	struct list_head *pos;

	
	list_for_each(pos, &((sctp_sk(sk))->ep->asocs)) {
		asoc = list_entry(pos, struct sctp_association, asocs);
		__sctp_write_space(asoc);
	}
}


static int sctp_writeable(struct sock *sk)
{
	int amt = 0;

	amt = sk->sk_sndbuf - atomic_read(&sk->sk_wmem_alloc);
	if (amt < 0)
		amt = 0;
	return amt;
}


static int sctp_wait_for_connect(struct sctp_association *asoc, long *timeo_p)
{
	struct sock *sk = asoc->base.sk;
	int err = 0;
	long current_timeo = *timeo_p;
	DEFINE_WAIT(wait);

	SCTP_DEBUG_PRINTK("%s: asoc=%p, timeo=%ld\n", __FUNCTION__, asoc, (long)(*timeo_p));

	
	sctp_association_hold(asoc);

	for (;;) {
		prepare_to_wait_exclusive(&asoc->wait, &wait, TASK_INTERRUPTIBLE);
		if (!*timeo_p)
			goto do_nonblock;
		if (sk->sk_shutdown & RCV_SHUTDOWN)
			break;
		if (sk->sk_err || asoc->state >= SCTP_STATE_SHUTDOWN_PENDING || asoc->base.dead)
			goto do_error;
		if (signal_pending(current))
			goto do_interrupted;

		if (sctp_state(asoc, ESTABLISHED))
			break;

		
		sctp_release_sock(sk);
		current_timeo = schedule_timeout(current_timeo);
		sctp_lock_sock(sk);

		*timeo_p = current_timeo;
	}

out:
	finish_wait(&asoc->wait, &wait);

	
	sctp_association_put(asoc);

	return err;

do_error:
	if (asoc->init_err_counter + 1 > asoc->max_init_attempts)
		err = -ETIMEDOUT;
	else err = -ECONNREFUSED;
	goto out;

do_interrupted:
	err = sock_intr_errno(*timeo_p);
	goto out;

do_nonblock:
	err = -EINPROGRESS;
	goto out;
}

static int sctp_wait_for_accept(struct sock *sk, long timeo)
{
	struct sctp_endpoint *ep;
	int err = 0;
	DEFINE_WAIT(wait);

	ep = sctp_sk(sk)->ep;


	for (;;) {
		prepare_to_wait_exclusive(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

		if (list_empty(&ep->asocs)) {
			sctp_release_sock(sk);
			timeo = schedule_timeout(timeo);
			sctp_lock_sock(sk);
		}

		err = -EINVAL;
		if (!sctp_sstate(sk, LISTENING))
			break;

		err = 0;
		if (!list_empty(&ep->asocs))
			break;

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;

		err = -EAGAIN;
		if (!timeo)
			break;
	}

	finish_wait(sk->sk_sleep, &wait);

	return err;
}

void sctp_wait_for_close(struct sock *sk, long timeout)
{
	DEFINE_WAIT(wait);

	do {
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
		if (list_empty(&sctp_sk(sk)->ep->asocs))
			break;
		sctp_release_sock(sk);
		timeout = schedule_timeout(timeout);
		sctp_lock_sock(sk);
	} while (!signal_pending(current) && timeout);

	finish_wait(sk->sk_sleep, &wait);
}


static void sctp_sock_migrate(struct sock *oldsk, struct sock *newsk, struct sctp_association *assoc, sctp_socket_type_t type)

{
	struct sctp_sock *oldsp = sctp_sk(oldsk);
	struct sctp_sock *newsp = sctp_sk(newsk);
	struct sctp_bind_bucket *pp; 
	struct sctp_endpoint *newep = newsp->ep;
	struct sk_buff *skb, *tmp;
	struct sctp_ulpevent *event;
	int flags = 0;

	
	newsk->sk_sndbuf = oldsk->sk_sndbuf;
	newsk->sk_rcvbuf = oldsk->sk_rcvbuf;
	
	inet_sk_copy_descendant(newsk, oldsk);

	
	newsp->ep = newep;
	newsp->hmac = NULL;

	
	pp = sctp_sk(oldsk)->bind_hash;
	sk_add_bind_node(newsk, &pp->owner);
	sctp_sk(newsk)->bind_hash = pp;
	inet_sk(newsk)->num = inet_sk(oldsk)->num;

	
	if (assoc->peer.ipv4_address)
		flags |= SCTP_ADDR4_PEERSUPP;
	if (assoc->peer.ipv6_address)
		flags |= SCTP_ADDR6_PEERSUPP;
	sctp_bind_addr_copy(&newsp->ep->base.bind_addr, &oldsp->ep->base.bind_addr, SCTP_SCOPE_GLOBAL, GFP_KERNEL, flags);


	
	sctp_skb_for_each(skb, &oldsk->sk_receive_queue, tmp) {
		event = sctp_skb2event(skb);
		if (event->asoc == assoc) {
			sock_rfree(skb);
			__skb_unlink(skb, &oldsk->sk_receive_queue);
			__skb_queue_tail(&newsk->sk_receive_queue, skb);
			skb_set_owner_r(skb, newsk);
		}
	}

	
	skb_queue_head_init(&newsp->pd_lobby);
	sctp_sk(newsk)->pd_mode = assoc->ulpq.pd_mode;

	if (sctp_sk(oldsk)->pd_mode) {
		struct sk_buff_head *queue;

		
		if (assoc->ulpq.pd_mode) {
			queue = &newsp->pd_lobby;
		} else queue = &newsk->sk_receive_queue;

		
		sctp_skb_for_each(skb, &oldsp->pd_lobby, tmp) {
			event = sctp_skb2event(skb);
			if (event->asoc == assoc) {
				sock_rfree(skb);
				__skb_unlink(skb, &oldsp->pd_lobby);
				__skb_queue_tail(queue, skb);
				skb_set_owner_r(skb, newsk);
			}
		}

		
		if (assoc->ulpq.pd_mode)
			sctp_clear_pd(oldsk);

	}

	
	newsp->type = type;

	
	sctp_lock_sock(newsk);
	sctp_assoc_migrate(assoc, newsk);

	
	if (sctp_state(assoc, CLOSED) && sctp_style(newsk, TCP))
		newsk->sk_shutdown |= RCV_SHUTDOWN;

	newsk->sk_state = SCTP_SS_ESTABLISHED;
	sctp_release_sock(newsk);
}


struct proto sctp_prot = {
	.name        =	"SCTP", .owner       =	THIS_MODULE, .close       =	sctp_close, .connect     =	sctp_connect, .disconnect  =	sctp_disconnect, .accept      =	sctp_accept, .ioctl       =	sctp_ioctl, .init        =	sctp_init_sock, .destroy     =	sctp_destroy_sock, .shutdown    =	sctp_shutdown, .setsockopt  =	sctp_setsockopt, .getsockopt  =	sctp_getsockopt, .sendmsg     =	sctp_sendmsg, .recvmsg     =	sctp_recvmsg, .bind        =	sctp_bind, .backlog_rcv =	sctp_backlog_rcv, .hash        =	sctp_hash, .unhash      =	sctp_unhash, .get_port    =	sctp_get_port, .obj_size    =  sizeof(struct sctp_sock), };





















struct proto sctpv6_prot = {
	.name		= "SCTPv6", .owner		= THIS_MODULE, .close		= sctp_close, .connect	= sctp_connect, .disconnect	= sctp_disconnect, .accept		= sctp_accept, .ioctl		= sctp_ioctl, .init		= sctp_init_sock, .destroy	= sctp_destroy_sock, .shutdown	= sctp_shutdown, .setsockopt	= sctp_setsockopt, .getsockopt	= sctp_getsockopt, .sendmsg	= sctp_sendmsg, .recvmsg	= sctp_recvmsg, .bind		= sctp_bind, .backlog_rcv	= sctp_backlog_rcv, .hash		= sctp_hash, .unhash		= sctp_unhash, .get_port	= sctp_get_port, .obj_size	= sizeof(struct sctp6_sock), };




















