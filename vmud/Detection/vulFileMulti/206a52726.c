






























































struct pppol2tp_session {
	int			owner;		

	struct sock		*sock;		
	struct sock		*tunnel_sock;	
	int			flags;		
};

static int pppol2tp_xmit(struct ppp_channel *chan, struct sk_buff *skb);

static const struct ppp_channel_ops pppol2tp_chan_ops = {
	.start_xmit =  pppol2tp_xmit, };

static const struct proto_ops pppol2tp_ops;


static inline struct l2tp_session *pppol2tp_sock_to_session(struct sock *sk)
{
	struct l2tp_session *session;

	if (sk == NULL)
		return NULL;

	sock_hold(sk);
	session = (struct l2tp_session *)(sk->sk_user_data);
	if (session == NULL) {
		sock_put(sk);
		goto out;
	}

	BUG_ON(session->magic != L2TP_SESSION_MAGIC);

out:
	return session;
}



static int pppol2tp_recv_payload_hook(struct sk_buff *skb)
{
	
	if (!pskb_may_pull(skb, 2))
		return 1;

	if ((skb->data[0] == 0xff) && (skb->data[1] == 0x03))
		skb_pull(skb, 2);

	return 0;
}


static int pppol2tp_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags)

{
	int err;
	struct sk_buff *skb;
	struct sock *sk = sock->sk;

	err = -EIO;
	if (sk->sk_state & PPPOX_BOUND)
		goto end;

	err = 0;
	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT, flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto end;

	if (len > skb->len)
		len = skb->len;
	else if (len < skb->len)
		msg->msg_flags |= MSG_TRUNC;

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, len);
	if (likely(err == 0))
		err = len;

	kfree_skb(skb);
end:
	return err;
}

static void pppol2tp_recv(struct l2tp_session *session, struct sk_buff *skb, int data_len)
{
	struct pppol2tp_session *ps = l2tp_session_priv(session);
	struct sock *sk = NULL;

	
	sk = ps->sock;
	if (sk == NULL)
		goto no_sock;

	if (sk->sk_state & PPPOX_BOUND) {
		struct pppox_sock *po;
		PRINTK(session->debug, PPPOL2TP_MSG_DATA, KERN_DEBUG, "%s: recv %d byte data frame, passing to ppp\n", session->name, data_len);


		
		secpath_reset(skb);
		skb_dst_drop(skb);
		nf_reset(skb);

		po = pppox_sk(sk);
		ppp_input(&po->chan, skb);
	} else {
		PRINTK(session->debug, PPPOL2TP_MSG_DATA, KERN_INFO, "%s: recv %d byte data frame, passing to L2TP socket\n", session->name, data_len);


		if (sock_queue_rcv_skb(sk, skb) < 0) {
			session->stats.rx_errors++;
			kfree_skb(skb);
		}
	}

	return;

no_sock:
	PRINTK(session->debug, PPPOL2TP_MSG_DATA, KERN_INFO, "%s: no socket\n", session->name);
	kfree_skb(skb);
}

static void pppol2tp_session_sock_hold(struct l2tp_session *session)
{
	struct pppol2tp_session *ps = l2tp_session_priv(session);

	if (ps->sock)
		sock_hold(ps->sock);
}

static void pppol2tp_session_sock_put(struct l2tp_session *session)
{
	struct pppol2tp_session *ps = l2tp_session_priv(session);

	if (ps->sock)
		sock_put(ps->sock);
}




static int pppol2tp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *m, size_t total_len)
{
	static const unsigned char ppph[2] = { 0xff, 0x03 };
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int error;
	struct l2tp_session *session;
	struct l2tp_tunnel *tunnel;
	struct pppol2tp_session *ps;
	int uhlen;

	error = -ENOTCONN;
	if (sock_flag(sk, SOCK_DEAD) || !(sk->sk_state & PPPOX_CONNECTED))
		goto error;

	
	error = -EBADF;
	session = pppol2tp_sock_to_session(sk);
	if (session == NULL)
		goto error;

	ps = l2tp_session_priv(session);
	tunnel = l2tp_sock_to_tunnel(ps->tunnel_sock);
	if (tunnel == NULL)
		goto error_put_sess;

	uhlen = (tunnel->encap == L2TP_ENCAPTYPE_UDP) ? sizeof(struct udphdr) : 0;

	
	error = -ENOMEM;
	skb = sock_wmalloc(sk, NET_SKB_PAD + sizeof(struct iphdr) + uhlen + session->hdr_len + sizeof(ppph) + total_len, 0, GFP_KERNEL);


	if (!skb)
		goto error_put_sess_tun;

	
	skb_reserve(skb, NET_SKB_PAD);
	skb_reset_network_header(skb);
	skb_reserve(skb, sizeof(struct iphdr));
	skb_reset_transport_header(skb);
	skb_reserve(skb, uhlen);

	
	skb->data[0] = ppph[0];
	skb->data[1] = ppph[1];
	skb_put(skb, 2);

	
	error = memcpy_fromiovec(skb_put(skb, total_len), m->msg_iov, total_len);
	if (error < 0) {
		kfree_skb(skb);
		goto error_put_sess_tun;
	}

	local_bh_disable();
	l2tp_xmit_skb(session, skb, session->hdr_len);
	local_bh_enable();

	sock_put(ps->tunnel_sock);
	sock_put(sk);

	return total_len;

error_put_sess_tun:
	sock_put(ps->tunnel_sock);
error_put_sess:
	sock_put(sk);
error:
	return error;
}


static int pppol2tp_xmit(struct ppp_channel *chan, struct sk_buff *skb)
{
	static const u8 ppph[2] = { 0xff, 0x03 };
	struct sock *sk = (struct sock *) chan->private;
	struct sock *sk_tun;
	struct l2tp_session *session;
	struct l2tp_tunnel *tunnel;
	struct pppol2tp_session *ps;
	int uhlen, headroom;

	if (sock_flag(sk, SOCK_DEAD) || !(sk->sk_state & PPPOX_CONNECTED))
		goto abort;

	
	session = pppol2tp_sock_to_session(sk);
	if (session == NULL)
		goto abort;

	ps = l2tp_session_priv(session);
	sk_tun = ps->tunnel_sock;
	if (sk_tun == NULL)
		goto abort_put_sess;
	tunnel = l2tp_sock_to_tunnel(sk_tun);
	if (tunnel == NULL)
		goto abort_put_sess;

	uhlen = (tunnel->encap == L2TP_ENCAPTYPE_UDP) ? sizeof(struct udphdr) : 0;
	headroom = NET_SKB_PAD_ORIG + sizeof(struct iphdr) + uhlen + session->hdr_len + sizeof(ppph);



	if (skb_cow_head(skb, headroom))
		goto abort_put_sess_tun;

	
	__skb_push(skb, sizeof(ppph));
	skb->data[0] = ppph[0];
	skb->data[1] = ppph[1];

	local_bh_disable();
	l2tp_xmit_skb(session, skb, session->hdr_len);
	local_bh_enable();

	sock_put(sk_tun);
	sock_put(sk);
	return 1;

abort_put_sess_tun:
	sock_put(sk_tun);
abort_put_sess:
	sock_put(sk);
abort:
	
	kfree_skb(skb);
	return 1;
}




static void pppol2tp_session_close(struct l2tp_session *session)
{
	struct pppol2tp_session *ps = l2tp_session_priv(session);
	struct sock *sk = ps->sock;
	struct sk_buff *skb;

	BUG_ON(session->magic != L2TP_SESSION_MAGIC);

	if (session->session_id == 0)
		goto out;

	if (sk != NULL) {
		lock_sock(sk);

		if (sk->sk_state & (PPPOX_CONNECTED | PPPOX_BOUND)) {
			pppox_unbind_sock(sk);
			sk->sk_state = PPPOX_DEAD;
			sk->sk_state_change(sk);
		}

		
		skb_queue_purge(&sk->sk_receive_queue);
		skb_queue_purge(&sk->sk_write_queue);
		while ((skb = skb_dequeue(&session->reorder_q))) {
			kfree_skb(skb);
			sock_put(sk);
		}

		release_sock(sk);
	}

out:
	return;
}


static void pppol2tp_session_destruct(struct sock *sk)
{
	struct l2tp_session *session;

	if (sk->sk_user_data != NULL) {
		session = sk->sk_user_data;
		if (session == NULL)
			goto out;

		sk->sk_user_data = NULL;
		BUG_ON(session->magic != L2TP_SESSION_MAGIC);
		l2tp_session_dec_refcount(session);
	}

out:
	return;
}


static int pppol2tp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct l2tp_session *session;
	int error;

	if (!sk)
		return 0;

	error = -EBADF;
	lock_sock(sk);
	if (sock_flag(sk, SOCK_DEAD) != 0)
		goto error;

	pppox_unbind_sock(sk);

	
	sk->sk_state = PPPOX_DEAD;
	sock_orphan(sk);
	sock->sk = NULL;

	session = pppol2tp_sock_to_session(sk);

	
	skb_queue_purge(&sk->sk_receive_queue);
	skb_queue_purge(&sk->sk_write_queue);
	if (session != NULL) {
		struct sk_buff *skb;
		while ((skb = skb_dequeue(&session->reorder_q))) {
			kfree_skb(skb);
			sock_put(sk);
		}
		sock_put(sk);
	}

	release_sock(sk);

	
	sock_put(sk);

	return 0;

error:
	release_sock(sk);
	return error;
}

static struct proto pppol2tp_sk_proto = {
	.name	  = "PPPOL2TP", .owner	  = THIS_MODULE, .obj_size = sizeof(struct pppox_sock), };



static int pppol2tp_backlog_recv(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	rc = l2tp_udp_encap_recv(sk, skb);
	if (rc)
		kfree_skb(skb);

	return NET_RX_SUCCESS;
}


static int pppol2tp_create(struct net *net, struct socket *sock)
{
	int error = -ENOMEM;
	struct sock *sk;

	sk = sk_alloc(net, PF_PPPOX, GFP_KERNEL, &pppol2tp_sk_proto);
	if (!sk)
		goto out;

	sock_init_data(sock, sk);

	sock->state  = SS_UNCONNECTED;
	sock->ops    = &pppol2tp_ops;

	sk->sk_backlog_rcv = pppol2tp_backlog_recv;
	sk->sk_protocol	   = PX_PROTO_OL2TP;
	sk->sk_family	   = PF_PPPOX;
	sk->sk_state	   = PPPOX_NONE;
	sk->sk_type	   = SOCK_STREAM;
	sk->sk_destruct	   = pppol2tp_session_destruct;

	error = 0;

out:
	return error;
}


static void pppol2tp_show(struct seq_file *m, void *arg)
{
	struct l2tp_session *session = arg;
	struct pppol2tp_session *ps = l2tp_session_priv(session);

	if (ps) {
		struct pppox_sock *po = pppox_sk(ps->sock);
		if (po)
			seq_printf(m, "   interface %s\n", ppp_dev_name(&po->chan));
	}
}



static int pppol2tp_connect(struct socket *sock, struct sockaddr *uservaddr, int sockaddr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_pppol2tp *sp = (struct sockaddr_pppol2tp *) uservaddr;
	struct sockaddr_pppol2tpv3 *sp3 = (struct sockaddr_pppol2tpv3 *) uservaddr;
	struct pppox_sock *po = pppox_sk(sk);
	struct l2tp_session *session = NULL;
	struct l2tp_tunnel *tunnel;
	struct pppol2tp_session *ps;
	struct dst_entry *dst;
	struct l2tp_session_cfg cfg = { 0, };
	int error = 0;
	u32 tunnel_id, peer_tunnel_id;
	u32 session_id, peer_session_id;
	int ver = 2;
	int fd;

	lock_sock(sk);

	error = -EINVAL;
	if (sp->sa_protocol != PX_PROTO_OL2TP)
		goto end;

	
	error = -EBUSY;
	if (sk->sk_state & PPPOX_CONNECTED)
		goto end;

	
	error = -EALREADY;
	if (sk->sk_user_data)
		goto end; 

	
	if (sockaddr_len == sizeof(struct sockaddr_pppol2tp)) {
		fd = sp->pppol2tp.fd;
		tunnel_id = sp->pppol2tp.s_tunnel;
		peer_tunnel_id = sp->pppol2tp.d_tunnel;
		session_id = sp->pppol2tp.s_session;
		peer_session_id = sp->pppol2tp.d_session;
	} else if (sockaddr_len == sizeof(struct sockaddr_pppol2tpv3)) {
		ver = 3;
		fd = sp3->pppol2tp.fd;
		tunnel_id = sp3->pppol2tp.s_tunnel;
		peer_tunnel_id = sp3->pppol2tp.d_tunnel;
		session_id = sp3->pppol2tp.s_session;
		peer_session_id = sp3->pppol2tp.d_session;
	} else {
		error = -EINVAL;
		goto end; 
	}

	
	error = -EINVAL;
	if (tunnel_id == 0)
		goto end;

	tunnel = l2tp_tunnel_find(sock_net(sk), tunnel_id);

	
	if ((session_id == 0) && (peer_session_id == 0)) {
		if (tunnel == NULL) {
			struct l2tp_tunnel_cfg tcfg = {
				.encap = L2TP_ENCAPTYPE_UDP, .debug = 0, };

			error = l2tp_tunnel_create(sock_net(sk), fd, ver, tunnel_id, peer_tunnel_id, &tcfg, &tunnel);
			if (error < 0)
				goto end;
		}
	} else {
		
		error = -ENOENT;
		if (tunnel == NULL)
			goto end;

		
		if (tunnel->sock == NULL)
			goto end;
	}

	if (tunnel->recv_payload_hook == NULL)
		tunnel->recv_payload_hook = pppol2tp_recv_payload_hook;

	if (tunnel->peer_tunnel_id == 0) {
		if (ver == 2)
			tunnel->peer_tunnel_id = sp->pppol2tp.d_tunnel;
		else tunnel->peer_tunnel_id = sp3->pppol2tp.d_tunnel;
	}

	
	session = l2tp_session_find(sock_net(sk), tunnel, session_id);
	if (session == NULL) {
		
		cfg.mtu = cfg.mru = 1500 - PPPOL2TP_HEADER_OVERHEAD;

		
		session = l2tp_session_create(sizeof(struct pppol2tp_session), tunnel, session_id, peer_session_id, &cfg);

		if (session == NULL) {
			error = -ENOMEM;
			goto end;
		}
	} else {
		ps = l2tp_session_priv(session);
		error = -EEXIST;
		if (ps->sock != NULL)
			goto end;

		
		if (ps->tunnel_sock != tunnel->sock)
			goto end;
	}

	
	ps = l2tp_session_priv(session);
	ps->owner	     = current->pid;
	ps->sock	     = sk;
	ps->tunnel_sock = tunnel->sock;

	session->recv_skb	= pppol2tp_recv;
	session->session_close	= pppol2tp_session_close;

	session->show		= pppol2tp_show;


	
	session->ref = pppol2tp_session_sock_hold;
	session->deref = pppol2tp_session_sock_put;

	
	dst = sk_dst_get(tunnel->sock);
	if (dst != NULL) {
		u32 pmtu = dst_mtu(__sk_dst_get(tunnel->sock));
		if (pmtu != 0)
			session->mtu = session->mru = pmtu - PPPOL2TP_HEADER_OVERHEAD;
		dst_release(dst);
	}

	
	if ((session->session_id == 0) && (session->peer_session_id == 0)) {
		error = 0;
		goto out_no_ppp;
	}

	
	po->chan.hdrlen = PPPOL2TP_L2TP_HDR_SIZE_NOSEQ;
	po->chan.hdrlen += NET_SKB_PAD_ORIG + sizeof(struct iphdr) + sizeof(struct udphdr) + 2;

	po->chan.private = sk;
	po->chan.ops	 = &pppol2tp_chan_ops;
	po->chan.mtu	 = session->mtu;

	error = ppp_register_net_channel(sock_net(sk), &po->chan);
	if (error)
		goto end;

out_no_ppp:
	
	sk->sk_user_data = session;
	sk->sk_state = PPPOX_CONNECTED;
	PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: created\n", session->name);

end:
	release_sock(sk);

	return error;
}




static int pppol2tp_session_create(struct net *net, u32 tunnel_id, u32 session_id, u32 peer_session_id, struct l2tp_session_cfg *cfg)
{
	int error;
	struct l2tp_tunnel *tunnel;
	struct l2tp_session *session;
	struct pppol2tp_session *ps;

	tunnel = l2tp_tunnel_find(net, tunnel_id);

	
	error = -ENOENT;
	if (tunnel == NULL)
		goto out;

	
	if (tunnel->sock == NULL)
		goto out;

	
	error = -EEXIST;
	session = l2tp_session_find(net, tunnel, session_id);
	if (session != NULL)
		goto out;

	
	if (cfg->mtu == 0)
		cfg->mtu = 1500 - PPPOL2TP_HEADER_OVERHEAD;
	if (cfg->mru == 0)
		cfg->mru = cfg->mtu;

	
	error = -ENOMEM;
	session = l2tp_session_create(sizeof(struct pppol2tp_session), tunnel, session_id, peer_session_id, cfg);

	if (session == NULL)
		goto out;

	ps = l2tp_session_priv(session);
	ps->tunnel_sock = tunnel->sock;

	PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: created\n", session->name);

	error = 0;

out:
	return error;
}


static int pppol2tp_session_delete(struct l2tp_session *session)
{
	struct pppol2tp_session *ps = l2tp_session_priv(session);

	if (ps->sock == NULL)
		l2tp_session_dec_refcount(session);

	return 0;
}




static int pppol2tp_getname(struct socket *sock, struct sockaddr *uaddr, int *usockaddr_len, int peer)
{
	int len = 0;
	int error = 0;
	struct l2tp_session *session;
	struct l2tp_tunnel *tunnel;
	struct sock *sk = sock->sk;
	struct inet_sock *inet;
	struct pppol2tp_session *pls;

	error = -ENOTCONN;
	if (sk == NULL)
		goto end;
	if (sk->sk_state != PPPOX_CONNECTED)
		goto end;

	error = -EBADF;
	session = pppol2tp_sock_to_session(sk);
	if (session == NULL)
		goto end;

	pls = l2tp_session_priv(session);
	tunnel = l2tp_sock_to_tunnel(pls->tunnel_sock);
	if (tunnel == NULL) {
		error = -EBADF;
		goto end_put_sess;
	}

	inet = inet_sk(tunnel->sock);
	if (tunnel->version == 2) {
		struct sockaddr_pppol2tp sp;
		len = sizeof(sp);
		memset(&sp, 0, len);
		sp.sa_family	= AF_PPPOX;
		sp.sa_protocol	= PX_PROTO_OL2TP;
		sp.pppol2tp.fd  = tunnel->fd;
		sp.pppol2tp.pid = pls->owner;
		sp.pppol2tp.s_tunnel = tunnel->tunnel_id;
		sp.pppol2tp.d_tunnel = tunnel->peer_tunnel_id;
		sp.pppol2tp.s_session = session->session_id;
		sp.pppol2tp.d_session = session->peer_session_id;
		sp.pppol2tp.addr.sin_family = AF_INET;
		sp.pppol2tp.addr.sin_port = inet->inet_dport;
		sp.pppol2tp.addr.sin_addr.s_addr = inet->inet_daddr;
		memcpy(uaddr, &sp, len);
	} else if (tunnel->version == 3) {
		struct sockaddr_pppol2tpv3 sp;
		len = sizeof(sp);
		memset(&sp, 0, len);
		sp.sa_family	= AF_PPPOX;
		sp.sa_protocol	= PX_PROTO_OL2TP;
		sp.pppol2tp.fd  = tunnel->fd;
		sp.pppol2tp.pid = pls->owner;
		sp.pppol2tp.s_tunnel = tunnel->tunnel_id;
		sp.pppol2tp.d_tunnel = tunnel->peer_tunnel_id;
		sp.pppol2tp.s_session = session->session_id;
		sp.pppol2tp.d_session = session->peer_session_id;
		sp.pppol2tp.addr.sin_family = AF_INET;
		sp.pppol2tp.addr.sin_port = inet->inet_dport;
		sp.pppol2tp.addr.sin_addr.s_addr = inet->inet_daddr;
		memcpy(uaddr, &sp, len);
	}

	*usockaddr_len = len;

	sock_put(pls->tunnel_sock);
end_put_sess:
	sock_put(sk);
	error = 0;

end:
	return error;
}



static void pppol2tp_copy_stats(struct pppol2tp_ioc_stats *dest, struct l2tp_stats *stats)
{
	dest->tx_packets = stats->tx_packets;
	dest->tx_bytes = stats->tx_bytes;
	dest->tx_errors = stats->tx_errors;
	dest->rx_packets = stats->rx_packets;
	dest->rx_bytes = stats->rx_bytes;
	dest->rx_seq_discards = stats->rx_seq_discards;
	dest->rx_oos_packets = stats->rx_oos_packets;
	dest->rx_errors = stats->rx_errors;
}


static int pppol2tp_session_ioctl(struct l2tp_session *session, unsigned int cmd, unsigned long arg)
{
	struct ifreq ifr;
	int err = 0;
	struct sock *sk;
	int val = (int) arg;
	struct pppol2tp_session *ps = l2tp_session_priv(session);
	struct l2tp_tunnel *tunnel = session->tunnel;
	struct pppol2tp_ioc_stats stats;

	PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_DEBUG, "%s: pppol2tp_session_ioctl(cmd=%#x, arg=%#lx)\n", session->name, cmd, arg);


	sk = ps->sock;
	sock_hold(sk);

	switch (cmd) {
	case SIOCGIFMTU:
		err = -ENXIO;
		if (!(sk->sk_state & PPPOX_CONNECTED))
			break;

		err = -EFAULT;
		if (copy_from_user(&ifr, (void __user *) arg, sizeof(struct ifreq)))
			break;
		ifr.ifr_mtu = session->mtu;
		if (copy_to_user((void __user *) arg, &ifr, sizeof(struct ifreq)))
			break;

		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get mtu=%d\n", session->name, session->mtu);
		err = 0;
		break;

	case SIOCSIFMTU:
		err = -ENXIO;
		if (!(sk->sk_state & PPPOX_CONNECTED))
			break;

		err = -EFAULT;
		if (copy_from_user(&ifr, (void __user *) arg, sizeof(struct ifreq)))
			break;

		session->mtu = ifr.ifr_mtu;

		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set mtu=%d\n", session->name, session->mtu);
		err = 0;
		break;

	case PPPIOCGMRU:
		err = -ENXIO;
		if (!(sk->sk_state & PPPOX_CONNECTED))
			break;

		err = -EFAULT;
		if (put_user(session->mru, (int __user *) arg))
			break;

		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get mru=%d\n", session->name, session->mru);
		err = 0;
		break;

	case PPPIOCSMRU:
		err = -ENXIO;
		if (!(sk->sk_state & PPPOX_CONNECTED))
			break;

		err = -EFAULT;
		if (get_user(val, (int __user *) arg))
			break;

		session->mru = val;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set mru=%d\n", session->name, session->mru);
		err = 0;
		break;

	case PPPIOCGFLAGS:
		err = -EFAULT;
		if (put_user(ps->flags, (int __user *) arg))
			break;

		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get flags=%d\n", session->name, ps->flags);
		err = 0;
		break;

	case PPPIOCSFLAGS:
		err = -EFAULT;
		if (get_user(val, (int __user *) arg))
			break;
		ps->flags = val;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set flags=%d\n", session->name, ps->flags);
		err = 0;
		break;

	case PPPIOCGL2TPSTATS:
		err = -ENXIO;
		if (!(sk->sk_state & PPPOX_CONNECTED))
			break;

		memset(&stats, 0, sizeof(stats));
		stats.tunnel_id = tunnel->tunnel_id;
		stats.session_id = session->session_id;
		pppol2tp_copy_stats(&stats, &session->stats);
		if (copy_to_user((void __user *) arg, &stats, sizeof(stats)))
			break;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get L2TP stats\n", session->name);
		err = 0;
		break;

	default:
		err = -ENOSYS;
		break;
	}

	sock_put(sk);

	return err;
}


static int pppol2tp_tunnel_ioctl(struct l2tp_tunnel *tunnel, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	struct sock *sk;
	struct pppol2tp_ioc_stats stats;

	PRINTK(tunnel->debug, PPPOL2TP_MSG_CONTROL, KERN_DEBUG, "%s: pppol2tp_tunnel_ioctl(cmd=%#x, arg=%#lx)\n", tunnel->name, cmd, arg);


	sk = tunnel->sock;
	sock_hold(sk);

	switch (cmd) {
	case PPPIOCGL2TPSTATS:
		err = -ENXIO;
		if (!(sk->sk_state & PPPOX_CONNECTED))
			break;

		if (copy_from_user(&stats, (void __user *) arg, sizeof(stats))) {
			err = -EFAULT;
			break;
		}
		if (stats.session_id != 0) {
			
			struct l2tp_session *session = l2tp_session_find(sock_net(sk), tunnel, stats.session_id);
			if (session != NULL)
				err = pppol2tp_session_ioctl(session, cmd, arg);
			else err = -EBADR;
			break;
		}

		stats.using_ipsec = (sk->sk_policy[0] || sk->sk_policy[1]) ? 1 : 0;

		pppol2tp_copy_stats(&stats, &tunnel->stats);
		if (copy_to_user((void __user *) arg, &stats, sizeof(stats))) {
			err = -EFAULT;
			break;
		}
		PRINTK(tunnel->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get L2TP stats\n", tunnel->name);
		err = 0;
		break;

	default:
		err = -ENOSYS;
		break;
	}

	sock_put(sk);

	return err;
}


static int pppol2tp_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct l2tp_session *session;
	struct l2tp_tunnel *tunnel;
	struct pppol2tp_session *ps;
	int err;

	if (!sk)
		return 0;

	err = -EBADF;
	if (sock_flag(sk, SOCK_DEAD) != 0)
		goto end;

	err = -ENOTCONN;
	if ((sk->sk_user_data == NULL) || (!(sk->sk_state & (PPPOX_CONNECTED | PPPOX_BOUND))))
		goto end;

	
	err = -EBADF;
	session = pppol2tp_sock_to_session(sk);
	if (session == NULL)
		goto end;

	
	ps = l2tp_session_priv(session);
	if ((session->session_id == 0) && (session->peer_session_id == 0)) {
		err = -EBADF;
		tunnel = l2tp_sock_to_tunnel(ps->tunnel_sock);
		if (tunnel == NULL)
			goto end_put_sess;

		err = pppol2tp_tunnel_ioctl(tunnel, cmd, arg);
		sock_put(ps->tunnel_sock);
		goto end_put_sess;
	}

	err = pppol2tp_session_ioctl(session, cmd, arg);

end_put_sess:
	sock_put(sk);
end:
	return err;
}




static int pppol2tp_tunnel_setsockopt(struct sock *sk, struct l2tp_tunnel *tunnel, int optname, int val)

{
	int err = 0;

	switch (optname) {
	case PPPOL2TP_SO_DEBUG:
		tunnel->debug = val;
		PRINTK(tunnel->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set debug=%x\n", tunnel->name, tunnel->debug);
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	return err;
}


static int pppol2tp_session_setsockopt(struct sock *sk, struct l2tp_session *session, int optname, int val)

{
	int err = 0;
	struct pppol2tp_session *ps = l2tp_session_priv(session);

	switch (optname) {
	case PPPOL2TP_SO_RECVSEQ:
		if ((val != 0) && (val != 1)) {
			err = -EINVAL;
			break;
		}
		session->recv_seq = val ? -1 : 0;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set recv_seq=%d\n", session->name, session->recv_seq);
		break;

	case PPPOL2TP_SO_SENDSEQ:
		if ((val != 0) && (val != 1)) {
			err = -EINVAL;
			break;
		}
		session->send_seq = val ? -1 : 0;
		{
			struct sock *ssk      = ps->sock;
			struct pppox_sock *po = pppox_sk(ssk);
			po->chan.hdrlen = val ? PPPOL2TP_L2TP_HDR_SIZE_SEQ :
				PPPOL2TP_L2TP_HDR_SIZE_NOSEQ;
			po->chan.hdrlen += NET_SKB_PAD_ORIG + sizeof(struct iphdr) + sizeof(struct udphdr) + 2;
		}
		l2tp_session_set_header_len(session, session->tunnel->version);
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set send_seq=%d\n", session->name, session->send_seq);
		break;

	case PPPOL2TP_SO_LNSMODE:
		if ((val != 0) && (val != 1)) {
			err = -EINVAL;
			break;
		}
		session->lns_mode = val ? -1 : 0;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set lns_mode=%d\n", session->name, session->lns_mode);
		break;

	case PPPOL2TP_SO_DEBUG:
		session->debug = val;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set debug=%x\n", session->name, session->debug);
		break;

	case PPPOL2TP_SO_REORDERTO:
		session->reorder_timeout = msecs_to_jiffies(val);
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: set reorder_timeout=%d\n", session->name, session->reorder_timeout);
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	return err;
}


static int pppol2tp_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct l2tp_session *session;
	struct l2tp_tunnel *tunnel;
	struct pppol2tp_session *ps;
	int val;
	int err;

	if (level != SOL_PPPOL2TP)
		return udp_prot.setsockopt(sk, level, optname, optval, optlen);

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	err = -ENOTCONN;
	if (sk->sk_user_data == NULL)
		goto end;

	
	err = -EBADF;
	session = pppol2tp_sock_to_session(sk);
	if (session == NULL)
		goto end;

	
	ps = l2tp_session_priv(session);
	if ((session->session_id == 0) && (session->peer_session_id == 0)) {
		err = -EBADF;
		tunnel = l2tp_sock_to_tunnel(ps->tunnel_sock);
		if (tunnel == NULL)
			goto end_put_sess;

		err = pppol2tp_tunnel_setsockopt(sk, tunnel, optname, val);
		sock_put(ps->tunnel_sock);
	} else err = pppol2tp_session_setsockopt(sk, session, optname, val);

	err = 0;

end_put_sess:
	sock_put(sk);
end:
	return err;
}


static int pppol2tp_tunnel_getsockopt(struct sock *sk, struct l2tp_tunnel *tunnel, int optname, int *val)

{
	int err = 0;

	switch (optname) {
	case PPPOL2TP_SO_DEBUG:
		*val = tunnel->debug;
		PRINTK(tunnel->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get debug=%x\n", tunnel->name, tunnel->debug);
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	return err;
}


static int pppol2tp_session_getsockopt(struct sock *sk, struct l2tp_session *session, int optname, int *val)

{
	int err = 0;

	switch (optname) {
	case PPPOL2TP_SO_RECVSEQ:
		*val = session->recv_seq;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get recv_seq=%d\n", session->name, *val);
		break;

	case PPPOL2TP_SO_SENDSEQ:
		*val = session->send_seq;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get send_seq=%d\n", session->name, *val);
		break;

	case PPPOL2TP_SO_LNSMODE:
		*val = session->lns_mode;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get lns_mode=%d\n", session->name, *val);
		break;

	case PPPOL2TP_SO_DEBUG:
		*val = session->debug;
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get debug=%d\n", session->name, *val);
		break;

	case PPPOL2TP_SO_REORDERTO:
		*val = (int) jiffies_to_msecs(session->reorder_timeout);
		PRINTK(session->debug, PPPOL2TP_MSG_CONTROL, KERN_INFO, "%s: get reorder_timeout=%d\n", session->name, *val);
		break;

	default:
		err = -ENOPROTOOPT;
	}

	return err;
}


static int pppol2tp_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct l2tp_session *session;
	struct l2tp_tunnel *tunnel;
	int val, len;
	int err;
	struct pppol2tp_session *ps;

	if (level != SOL_PPPOL2TP)
		return udp_prot.getsockopt(sk, level, optname, optval, optlen);

	if (get_user(len, (int __user *) optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	err = -ENOTCONN;
	if (sk->sk_user_data == NULL)
		goto end;

	
	err = -EBADF;
	session = pppol2tp_sock_to_session(sk);
	if (session == NULL)
		goto end;

	
	ps = l2tp_session_priv(session);
	if ((session->session_id == 0) && (session->peer_session_id == 0)) {
		err = -EBADF;
		tunnel = l2tp_sock_to_tunnel(ps->tunnel_sock);
		if (tunnel == NULL)
			goto end_put_sess;

		err = pppol2tp_tunnel_getsockopt(sk, tunnel, optname, &val);
		sock_put(ps->tunnel_sock);
	} else err = pppol2tp_session_getsockopt(sk, session, optname, &val);

	err = -EFAULT;
	if (put_user(len, (int __user *) optlen))
		goto end_put_sess;

	if (copy_to_user((void __user *) optval, &val, len))
		goto end_put_sess;

	err = 0;

end_put_sess:
	sock_put(sk);
end:
	return err;
}



static unsigned int pppol2tp_net_id;



struct pppol2tp_seq_data {
	struct seq_net_private p;
	int tunnel_idx;			
	int session_idx;		
	struct l2tp_tunnel *tunnel;
	struct l2tp_session *session;	
};

static void pppol2tp_next_tunnel(struct net *net, struct pppol2tp_seq_data *pd)
{
	for (;;) {
		pd->tunnel = l2tp_tunnel_find_nth(net, pd->tunnel_idx);
		pd->tunnel_idx++;

		if (pd->tunnel == NULL)
			break;

		
		if (pd->tunnel->version < 3)
			break;
	}
}

static void pppol2tp_next_session(struct net *net, struct pppol2tp_seq_data *pd)
{
	pd->session = l2tp_session_find_nth(pd->tunnel, pd->session_idx);
	pd->session_idx++;

	if (pd->session == NULL) {
		pd->session_idx = 0;
		pppol2tp_next_tunnel(net, pd);
	}
}

static void *pppol2tp_seq_start(struct seq_file *m, loff_t *offs)
{
	struct pppol2tp_seq_data *pd = SEQ_START_TOKEN;
	loff_t pos = *offs;
	struct net *net;

	if (!pos)
		goto out;

	BUG_ON(m->private == NULL);
	pd = m->private;
	net = seq_file_net(m);

	if (pd->tunnel == NULL)
		pppol2tp_next_tunnel(net, pd);
	else pppol2tp_next_session(net, pd);

	
	if ((pd->tunnel == NULL) && (pd->session == NULL))
		pd = NULL;

out:
	return pd;
}

static void *pppol2tp_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void pppol2tp_seq_stop(struct seq_file *p, void *v)
{
	
}

static void pppol2tp_seq_tunnel_show(struct seq_file *m, void *v)
{
	struct l2tp_tunnel *tunnel = v;

	seq_printf(m, "\nTUNNEL '%s', %c %d\n", tunnel->name, (tunnel == tunnel->sock->sk_user_data) ? 'Y' : 'N', atomic_read(&tunnel->ref_count) - 1);


	seq_printf(m, " %08x %llu/%llu/%llu %llu/%llu/%llu\n", tunnel->debug, (unsigned long long)tunnel->stats.tx_packets, (unsigned long long)tunnel->stats.tx_bytes, (unsigned long long)tunnel->stats.tx_errors, (unsigned long long)tunnel->stats.rx_packets, (unsigned long long)tunnel->stats.rx_bytes, (unsigned long long)tunnel->stats.rx_errors);






}

static void pppol2tp_seq_session_show(struct seq_file *m, void *v)
{
	struct l2tp_session *session = v;
	struct l2tp_tunnel *tunnel = session->tunnel;
	struct pppol2tp_session *ps = l2tp_session_priv(session);
	struct pppox_sock *po = pppox_sk(ps->sock);
	u32 ip = 0;
	u16 port = 0;

	if (tunnel->sock) {
		struct inet_sock *inet = inet_sk(tunnel->sock);
		ip = ntohl(inet->inet_saddr);
		port = ntohs(inet->inet_sport);
	}

	seq_printf(m, "  SESSION '%s' %08X/%d %04X/%04X -> " "%04X/%04X %d %c\n", session->name, ip, port, tunnel->tunnel_id, session->session_id, tunnel->peer_tunnel_id, session->peer_session_id, ps->sock->sk_state, (session == ps->sock->sk_user_data) ? 'Y' : 'N');








	seq_printf(m, "   %d/%d/%c/%c/%s %08x %u\n", session->mtu, session->mru, session->recv_seq ? 'R' : '-', session->send_seq ? 'S' : '-', session->lns_mode ? "LNS" : "LAC", session->debug, jiffies_to_msecs(session->reorder_timeout));





	seq_printf(m, "   %hu/%hu %llu/%llu/%llu %llu/%llu/%llu\n", session->nr, session->ns, (unsigned long long)session->stats.tx_packets, (unsigned long long)session->stats.tx_bytes, (unsigned long long)session->stats.tx_errors, (unsigned long long)session->stats.rx_packets, (unsigned long long)session->stats.rx_bytes, (unsigned long long)session->stats.rx_errors);







	if (po)
		seq_printf(m, "   interface %s\n", ppp_dev_name(&po->chan));
}

static int pppol2tp_seq_show(struct seq_file *m, void *v)
{
	struct pppol2tp_seq_data *pd = v;

	
	if (v == SEQ_START_TOKEN) {
		seq_puts(m, "PPPoL2TP driver info, " PPPOL2TP_DRV_VERSION "\n");
		seq_puts(m, "TUNNEL name, user-data-ok session-count\n");
		seq_puts(m, " debug tx-pkts/bytes/errs rx-pkts/bytes/errs\n");
		seq_puts(m, "  SESSION name, addr/port src-tid/sid " "dest-tid/sid state user-data-ok\n");
		seq_puts(m, "   mtu/mru/rcvseq/sendseq/lns debug reorderto\n");
		seq_puts(m, "   nr/ns tx-pkts/bytes/errs rx-pkts/bytes/errs\n");
		goto out;
	}

	
	if (pd->session == NULL)
		pppol2tp_seq_tunnel_show(m, pd->tunnel);
	else pppol2tp_seq_session_show(m, pd->session);

out:
	return 0;
}

static const struct seq_operations pppol2tp_seq_ops = {
	.start		= pppol2tp_seq_start, .next		= pppol2tp_seq_next, .stop		= pppol2tp_seq_stop, .show		= pppol2tp_seq_show, };





static int pppol2tp_proc_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &pppol2tp_seq_ops, sizeof(struct pppol2tp_seq_data));
}

static const struct file_operations pppol2tp_proc_fops = {
	.owner		= THIS_MODULE, .open		= pppol2tp_proc_open, .read		= seq_read, .llseek		= seq_lseek, .release	= seq_release_net, };









static __net_init int pppol2tp_init_net(struct net *net)
{
	struct proc_dir_entry *pde;
	int err = 0;

	pde = proc_net_fops_create(net, "pppol2tp", S_IRUGO, &pppol2tp_proc_fops);
	if (!pde) {
		err = -ENOMEM;
		goto out;
	}

out:
	return err;
}

static __net_exit void pppol2tp_exit_net(struct net *net)
{
	proc_net_remove(net, "pppol2tp");
}

static struct pernet_operations pppol2tp_net_ops = {
	.init = pppol2tp_init_net, .exit = pppol2tp_exit_net, .id   = &pppol2tp_net_id, };





static const struct proto_ops pppol2tp_ops = {
	.family		= AF_PPPOX, .owner		= THIS_MODULE, .release	= pppol2tp_release, .bind		= sock_no_bind, .connect	= pppol2tp_connect, .socketpair	= sock_no_socketpair, .accept		= sock_no_accept, .getname	= pppol2tp_getname, .poll		= datagram_poll, .listen		= sock_no_listen, .shutdown	= sock_no_shutdown, .setsockopt	= pppol2tp_setsockopt, .getsockopt	= pppol2tp_getsockopt, .sendmsg	= pppol2tp_sendmsg, .recvmsg	= pppol2tp_recvmsg, .mmap		= sock_no_mmap, .ioctl		= pppox_ioctl, };

















static const struct pppox_proto pppol2tp_proto = {
	.create		= pppol2tp_create, .ioctl		= pppol2tp_ioctl, .owner		= THIS_MODULE, };





static const struct l2tp_nl_cmd_ops pppol2tp_nl_cmd_ops = {
	.session_create	= pppol2tp_session_create, .session_delete	= pppol2tp_session_delete, };




static int __init pppol2tp_init(void)
{
	int err;

	err = register_pernet_device(&pppol2tp_net_ops);
	if (err)
		goto out;

	err = proto_register(&pppol2tp_sk_proto, 0);
	if (err)
		goto out_unregister_pppol2tp_pernet;

	err = register_pppox_proto(PX_PROTO_OL2TP, &pppol2tp_proto);
	if (err)
		goto out_unregister_pppol2tp_proto;


	err = l2tp_nl_register_ops(L2TP_PWTYPE_PPP, &pppol2tp_nl_cmd_ops);
	if (err)
		goto out_unregister_pppox;


	printk(KERN_INFO "PPPoL2TP kernel driver, %s\n", PPPOL2TP_DRV_VERSION);

out:
	return err;


out_unregister_pppox:
	unregister_pppox_proto(PX_PROTO_OL2TP);

out_unregister_pppol2tp_proto:
	proto_unregister(&pppol2tp_sk_proto);
out_unregister_pppol2tp_pernet:
	unregister_pernet_device(&pppol2tp_net_ops);
	goto out;
}

static void __exit pppol2tp_exit(void)
{

	l2tp_nl_unregister_ops(L2TP_PWTYPE_PPP);

	unregister_pppox_proto(PX_PROTO_OL2TP);
	proto_unregister(&pppol2tp_sk_proto);
	unregister_pernet_device(&pppol2tp_net_ops);
}

module_init(pppol2tp_init);
module_exit(pppol2tp_exit);

MODULE_AUTHOR("James Chapman <jchapman@katalix.com>");
MODULE_DESCRIPTION("PPP over L2TP over UDP");
MODULE_LICENSE("GPL");
MODULE_VERSION(PPPOL2TP_DRV_VERSION);
MODULE_ALIAS("pppox-proto-" __stringify(PX_PROTO_OL2TP));
