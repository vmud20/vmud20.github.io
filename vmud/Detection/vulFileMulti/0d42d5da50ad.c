














struct datalink_proto *ddp_dl, *aarp_dl;
static const struct proto_ops atalk_dgram_ops;



HLIST_HEAD(atalk_sockets);
DEFINE_RWLOCK(atalk_sockets_lock);

static inline void __atalk_insert_socket(struct sock *sk)
{
	sk_add_node(sk, &atalk_sockets);
}

static inline void atalk_remove_socket(struct sock *sk)
{
	write_lock_bh(&atalk_sockets_lock);
	sk_del_node_init(sk);
	write_unlock_bh(&atalk_sockets_lock);
}

static struct sock *atalk_search_socket(struct sockaddr_at *to, struct atalk_iface *atif)
{
	struct sock *s;
	struct hlist_node *node;

	read_lock_bh(&atalk_sockets_lock);
	sk_for_each(s, node, &atalk_sockets) {
		struct atalk_sock *at = at_sk(s);

		if (to->sat_port != at->src_port)
			continue;

		if (to->sat_addr.s_net == ATADDR_ANYNET && to->sat_addr.s_node == ATADDR_BCAST)
			goto found;

		if (to->sat_addr.s_net == at->src_net && (to->sat_addr.s_node == at->src_node || to->sat_addr.s_node == ATADDR_BCAST || to->sat_addr.s_node == ATADDR_ANYNODE))


			goto found;

		
		if (to->sat_addr.s_node == ATADDR_ANYNODE && to->sat_addr.s_net != ATADDR_ANYNET && atif->address.s_node == at->src_node) {

			to->sat_addr.s_node = atif->address.s_node;
			goto found;
		}
	}
	s = NULL;
found:
	read_unlock_bh(&atalk_sockets_lock);
	return s;
}


static struct sock *atalk_find_or_insert_socket(struct sock *sk, struct sockaddr_at *sat)
{
	struct sock *s;
	struct hlist_node *node;
	struct atalk_sock *at;

	write_lock_bh(&atalk_sockets_lock);
	sk_for_each(s, node, &atalk_sockets) {
		at = at_sk(s);

		if (at->src_net == sat->sat_addr.s_net && at->src_node == sat->sat_addr.s_node && at->src_port == sat->sat_port)

			goto found;
	}
	s = NULL;
	__atalk_insert_socket(sk); 
found:
	write_unlock_bh(&atalk_sockets_lock);
	return s;
}

static void atalk_destroy_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	if (sk_has_allocations(sk)) {
		sk->sk_timer.expires = jiffies + SOCK_DESTROY_TIME;
		add_timer(&sk->sk_timer);
	} else sock_put(sk);
}

static inline void atalk_destroy_socket(struct sock *sk)
{
	atalk_remove_socket(sk);
	skb_queue_purge(&sk->sk_receive_queue);

	if (sk_has_allocations(sk)) {
		setup_timer(&sk->sk_timer, atalk_destroy_timer, (unsigned long)sk);
		sk->sk_timer.expires	= jiffies + SOCK_DESTROY_TIME;
		add_timer(&sk->sk_timer);
	} else sock_put(sk);
}




struct atalk_route *atalk_routes;
DEFINE_RWLOCK(atalk_routes_lock);

struct atalk_iface *atalk_interfaces;
DEFINE_RWLOCK(atalk_interfaces_lock);


struct atalk_route atrtr_default;



static void atif_drop_device(struct net_device *dev)
{
	struct atalk_iface **iface = &atalk_interfaces;
	struct atalk_iface *tmp;

	write_lock_bh(&atalk_interfaces_lock);
	while ((tmp = *iface) != NULL) {
		if (tmp->dev == dev) {
			*iface = tmp->next;
			dev_put(dev);
			kfree(tmp);
			dev->atalk_ptr = NULL;
		} else iface = &tmp->next;
	}
	write_unlock_bh(&atalk_interfaces_lock);
}

static struct atalk_iface *atif_add_device(struct net_device *dev, struct atalk_addr *sa)
{
	struct atalk_iface *iface = kzalloc(sizeof(*iface), GFP_KERNEL);

	if (!iface)
		goto out;

	dev_hold(dev);
	iface->dev = dev;
	dev->atalk_ptr = iface;
	iface->address = *sa;
	iface->status = 0;

	write_lock_bh(&atalk_interfaces_lock);
	iface->next = atalk_interfaces;
	atalk_interfaces = iface;
	write_unlock_bh(&atalk_interfaces_lock);
out:
	return iface;
}


static int atif_probe_device(struct atalk_iface *atif)
{
	int netrange = ntohs(atif->nets.nr_lastnet) - ntohs(atif->nets.nr_firstnet) + 1;
	int probe_net = ntohs(atif->address.s_net);
	int probe_node = atif->address.s_node;
	int netct, nodect;

	
	if (probe_net == ATADDR_ANYNET) {
		probe_net = ntohs(atif->nets.nr_firstnet);
		if (netrange)
			probe_net += jiffies % netrange;
	}
	if (probe_node == ATADDR_ANYNODE)
		probe_node = jiffies & 0xFF;

	
	atif->status |= ATIF_PROBE;
	for (netct = 0; netct <= netrange; netct++) {
		
		atif->address.s_net = htons(probe_net);
		for (nodect = 0; nodect < 256; nodect++) {
			atif->address.s_node = (nodect + probe_node) & 0xFF;
			if (atif->address.s_node > 0 && atif->address.s_node < 254) {
				
				aarp_probe_network(atif);

				if (!(atif->status & ATIF_PROBE_FAIL)) {
					atif->status &= ~ATIF_PROBE;
					return 0;
				}
			}
			atif->status &= ~ATIF_PROBE_FAIL;
		}
		probe_net++;
		if (probe_net > ntohs(atif->nets.nr_lastnet))
			probe_net = ntohs(atif->nets.nr_firstnet);
	}
	atif->status &= ~ATIF_PROBE;

	return -EADDRINUSE;	
}



static int atif_proxy_probe_device(struct atalk_iface *atif, struct atalk_addr* proxy_addr)
{
	int netrange = ntohs(atif->nets.nr_lastnet) - ntohs(atif->nets.nr_firstnet) + 1;
	
	int probe_net = ntohs(atif->address.s_net);
	int probe_node = ATADDR_ANYNODE;	    
	int netct, nodect;

	
	if (probe_net == ATADDR_ANYNET) {
		probe_net = ntohs(atif->nets.nr_firstnet);
		if (netrange)
			probe_net += jiffies % netrange;
	}

	if (probe_node == ATADDR_ANYNODE)
		probe_node = jiffies & 0xFF;

	
	for (netct = 0; netct <= netrange; netct++) {
		
		proxy_addr->s_net = htons(probe_net);
		for (nodect = 0; nodect < 256; nodect++) {
			proxy_addr->s_node = (nodect + probe_node) & 0xFF;
			if (proxy_addr->s_node > 0 && proxy_addr->s_node < 254) {
				
				int ret = aarp_proxy_probe_network(atif, proxy_addr);

				if (ret != -EADDRINUSE)
					return ret;
			}
		}
		probe_net++;
		if (probe_net > ntohs(atif->nets.nr_lastnet))
			probe_net = ntohs(atif->nets.nr_firstnet);
	}

	return -EADDRINUSE;	
}


struct atalk_addr *atalk_find_dev_addr(struct net_device *dev)
{
	struct atalk_iface *iface = dev->atalk_ptr;
	return iface ? &iface->address : NULL;
}

static struct atalk_addr *atalk_find_primary(void)
{
	struct atalk_iface *fiface = NULL;
	struct atalk_addr *retval;
	struct atalk_iface *iface;

	
	read_lock_bh(&atalk_interfaces_lock);
	for (iface = atalk_interfaces; iface; iface = iface->next) {
		if (!fiface && !(iface->dev->flags & IFF_LOOPBACK))
			fiface = iface;
		if (!(iface->dev->flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) {
			retval = &iface->address;
			goto out;
		}
	}

	if (fiface)
		retval = &fiface->address;
	else if (atalk_interfaces)
		retval = &atalk_interfaces->address;
	else retval = NULL;
out:
	read_unlock_bh(&atalk_interfaces_lock);
	return retval;
}


static struct atalk_iface *atalk_find_anynet(int node, struct net_device *dev)
{
	struct atalk_iface *iface = dev->atalk_ptr;

	if (!iface || iface->status & ATIF_PROBE)
		goto out_err;

	if (node != ATADDR_BCAST && iface->address.s_node != node && node != ATADDR_ANYNODE)

		goto out_err;
out:
	return iface;
out_err:
	iface = NULL;
	goto out;
}


static struct atalk_iface *atalk_find_interface(__be16 net, int node)
{
	struct atalk_iface *iface;

	read_lock_bh(&atalk_interfaces_lock);
	for (iface = atalk_interfaces; iface; iface = iface->next) {
		if ((node == ATADDR_BCAST || node == ATADDR_ANYNODE || iface->address.s_node == node) && iface->address.s_net == net && !(iface->status & ATIF_PROBE))



			break;

		
		if (node == ATADDR_ANYNODE && net != ATADDR_ANYNET && ntohs(iface->nets.nr_firstnet) <= ntohs(net) && ntohs(net) <= ntohs(iface->nets.nr_lastnet))

			break;
	}
	read_unlock_bh(&atalk_interfaces_lock);
	return iface;
}



static struct atalk_route *atrtr_find(struct atalk_addr *target)
{
	
	struct atalk_route *net_route = NULL;
	struct atalk_route *r;

	read_lock_bh(&atalk_routes_lock);
	for (r = atalk_routes; r; r = r->next) {
		if (!(r->flags & RTF_UP))
			continue;

		if (r->target.s_net == target->s_net) {
			if (r->flags & RTF_HOST) {
				
				if (r->target.s_node == target->s_node)
					goto out;
			} else  net_route = r;

		}
	}

	
	if (net_route)
		r = net_route;
	else if (atrtr_default.dev)
		r = &atrtr_default;
	else  r = NULL;
out:
	read_unlock_bh(&atalk_routes_lock);
	return r;
}



struct net_device *atrtr_get_dev(struct atalk_addr *sa)
{
	struct atalk_route *atr = atrtr_find(sa);
	return atr ? atr->dev : NULL;
}


static void atrtr_set_default(struct net_device *dev)
{
	atrtr_default.dev	     = dev;
	atrtr_default.flags	     = RTF_UP;
	atrtr_default.gateway.s_net  = htons(0);
	atrtr_default.gateway.s_node = 0;
}


static int atrtr_create(struct rtentry *r, struct net_device *devhint)
{
	struct sockaddr_at *ta = (struct sockaddr_at *)&r->rt_dst;
	struct sockaddr_at *ga = (struct sockaddr_at *)&r->rt_gateway;
	struct atalk_route *rt;
	struct atalk_iface *iface, *riface;
	int retval = -EINVAL;

	

	
	if (ta->sat_family != AF_APPLETALK || (!devhint && ga->sat_family != AF_APPLETALK))
		goto out;

	
	write_lock_bh(&atalk_routes_lock);
	for (rt = atalk_routes; rt; rt = rt->next) {
		if (r->rt_flags != rt->flags)
			continue;

		if (ta->sat_addr.s_net == rt->target.s_net) {
			if (!(rt->flags & RTF_HOST))
				break;
			if (ta->sat_addr.s_node == rt->target.s_node)
				break;
		}
	}

	if (!devhint) {
		riface = NULL;

		read_lock_bh(&atalk_interfaces_lock);
		for (iface = atalk_interfaces; iface; iface = iface->next) {
			if (!riface && ntohs(ga->sat_addr.s_net) >= ntohs(iface->nets.nr_firstnet) && ntohs(ga->sat_addr.s_net) <= ntohs(iface->nets.nr_lastnet))



				riface = iface;

			if (ga->sat_addr.s_net == iface->address.s_net && ga->sat_addr.s_node == iface->address.s_node)
				riface = iface;
		}
		read_unlock_bh(&atalk_interfaces_lock);

		retval = -ENETUNREACH;
		if (!riface)
			goto out_unlock;

		devhint = riface->dev;
	}

	if (!rt) {
		rt = kzalloc(sizeof(*rt), GFP_ATOMIC);

		retval = -ENOBUFS;
		if (!rt)
			goto out_unlock;

		rt->next = atalk_routes;
		atalk_routes = rt;
	}

	
	rt->target  = ta->sat_addr;
	dev_hold(devhint);
	rt->dev     = devhint;
	rt->flags   = r->rt_flags;
	rt->gateway = ga->sat_addr;

	retval = 0;
out_unlock:
	write_unlock_bh(&atalk_routes_lock);
out:
	return retval;
}


static int atrtr_delete(struct atalk_addr * addr)
{
	struct atalk_route **r = &atalk_routes;
	int retval = 0;
	struct atalk_route *tmp;

	write_lock_bh(&atalk_routes_lock);
	while ((tmp = *r) != NULL) {
		if (tmp->target.s_net == addr->s_net && (!(tmp->flags&RTF_GATEWAY) || tmp->target.s_node == addr->s_node)) {

			*r = tmp->next;
			dev_put(tmp->dev);
			kfree(tmp);
			goto out;
		}
		r = &tmp->next;
	}
	retval = -ENOENT;
out:
	write_unlock_bh(&atalk_routes_lock);
	return retval;
}


static void atrtr_device_down(struct net_device *dev)
{
	struct atalk_route **r = &atalk_routes;
	struct atalk_route *tmp;

	write_lock_bh(&atalk_routes_lock);
	while ((tmp = *r) != NULL) {
		if (tmp->dev == dev) {
			*r = tmp->next;
			dev_put(dev);
			kfree(tmp);
		} else r = &tmp->next;
	}
	write_unlock_bh(&atalk_routes_lock);

	if (atrtr_default.dev == dev)
		atrtr_set_default(NULL);
}


static inline void atalk_dev_down(struct net_device *dev)
{
	atrtr_device_down(dev);	
	aarp_device_down(dev);	
	atif_drop_device(dev);	
}


static int ddp_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	if (event == NETDEV_DOWN)
		
		atalk_dev_down(dev);

	return NOTIFY_DONE;
}



static int atif_ioctl(int cmd, void __user *arg)
{
	static char aarp_mcast[6] = { 0x09, 0x00, 0x00, 0xFF, 0xFF, 0xFF };
	struct ifreq atreq;
	struct atalk_netrange *nr;
	struct sockaddr_at *sa;
	struct net_device *dev;
	struct atalk_iface *atif;
	int ct;
	int limit;
	struct rtentry rtdef;
	int add_route;

	if (copy_from_user(&atreq, arg, sizeof(atreq)))
		return -EFAULT;

	dev = __dev_get_by_name(&init_net, atreq.ifr_name);
	if (!dev)
		return -ENODEV;

	sa = (struct sockaddr_at *)&atreq.ifr_addr;
	atif = atalk_find_dev(dev);

	switch (cmd) {
		case SIOCSIFADDR:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
			if (sa->sat_family != AF_APPLETALK)
				return -EINVAL;
			if (dev->type != ARPHRD_ETHER && dev->type != ARPHRD_LOOPBACK && dev->type != ARPHRD_LOCALTLK && dev->type != ARPHRD_PPP)


				return -EPROTONOSUPPORT;

			nr = (struct atalk_netrange *)&sa->sat_zero[0];
			add_route = 1;

			
			if ((dev->flags & IFF_POINTOPOINT) && atalk_find_interface(sa->sat_addr.s_net, sa->sat_addr.s_node)) {

				printk(KERN_DEBUG "AppleTalk: point-to-point " "interface added with " "existing address\n");

				add_route = 0;
			}

			
			if (dev->type == ARPHRD_ETHER && nr->nr_phase != 2)
				return -EPROTONOSUPPORT;
			if (sa->sat_addr.s_node == ATADDR_BCAST || sa->sat_addr.s_node == 254)
				return -EINVAL;
			if (atif) {
				
				if (atif->status & ATIF_PROBE)
					return -EBUSY;

				atif->address.s_net  = sa->sat_addr.s_net;
				atif->address.s_node = sa->sat_addr.s_node;
				atrtr_device_down(dev);	
			} else {
				atif = atif_add_device(dev, &sa->sat_addr);
				if (!atif)
					return -ENOMEM;
			}
			atif->nets = *nr;

			

			if (!(dev->flags & IFF_LOOPBACK) && !(dev->flags & IFF_POINTOPOINT) && atif_probe_device(atif) < 0) {

				atif_drop_device(dev);
				return -EADDRINUSE;
			}

			
			sa = (struct sockaddr_at *)&rtdef.rt_gateway;
			sa->sat_family = AF_APPLETALK;
			sa->sat_addr.s_net  = atif->address.s_net;
			sa->sat_addr.s_node = atif->address.s_node;
			sa = (struct sockaddr_at *)&rtdef.rt_dst;
			rtdef.rt_flags = RTF_UP;
			sa->sat_family = AF_APPLETALK;
			sa->sat_addr.s_node = ATADDR_ANYNODE;
			if (dev->flags & IFF_LOOPBACK || dev->flags & IFF_POINTOPOINT)
				rtdef.rt_flags |= RTF_HOST;

			
			if (nr->nr_firstnet == htons(0) && nr->nr_lastnet == htons(0xFFFE)) {
				sa->sat_addr.s_net = atif->address.s_net;
				atrtr_create(&rtdef, dev);
				atrtr_set_default(dev);
			} else {
				limit = ntohs(nr->nr_lastnet);
				if (limit - ntohs(nr->nr_firstnet) > 4096) {
					printk(KERN_WARNING "Too many routes/" "iface.\n");
					return -EINVAL;
				}
				if (add_route)
					for (ct = ntohs(nr->nr_firstnet);
					     ct <= limit; ct++) {
						sa->sat_addr.s_net = htons(ct);
						atrtr_create(&rtdef, dev);
					}
			}
			dev_mc_add(dev, aarp_mcast, 6, 1);
			return 0;

		case SIOCGIFADDR:
			if (!atif)
				return -EADDRNOTAVAIL;

			sa->sat_family = AF_APPLETALK;
			sa->sat_addr = atif->address;
			break;

		case SIOCGIFBRDADDR:
			if (!atif)
				return -EADDRNOTAVAIL;

			sa->sat_family = AF_APPLETALK;
			sa->sat_addr.s_net = atif->address.s_net;
			sa->sat_addr.s_node = ATADDR_BCAST;
			break;

		case SIOCATALKDIFADDR:
		case SIOCDIFADDR:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
			if (sa->sat_family != AF_APPLETALK)
				return -EINVAL;
			atalk_dev_down(dev);
			break;

		case SIOCSARP:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
			if (sa->sat_family != AF_APPLETALK)
				return -EINVAL;
			
			if (dev->type != ARPHRD_ETHER)
				return -EPROTONOSUPPORT;

			
			if (!atif)
				return -EADDRNOTAVAIL;

			nr = (struct atalk_netrange *)&(atif->nets);
			
			if (dev->type == ARPHRD_ETHER && nr->nr_phase != 2)
				return -EPROTONOSUPPORT;

			if (sa->sat_addr.s_node == ATADDR_BCAST || sa->sat_addr.s_node == 254)
				return -EINVAL;

			
			if (atif_proxy_probe_device(atif, &(sa->sat_addr)) < 0)
				return -EADDRINUSE;

			
			break;

		case SIOCDARP:
			if (!capable(CAP_NET_ADMIN))
				return -EPERM;
			if (sa->sat_family != AF_APPLETALK)
				return -EINVAL;
			if (!atif)
				return -EADDRNOTAVAIL;

			
			aarp_proxy_remove(atif->dev, &(sa->sat_addr));
			return 0;
	}

	return copy_to_user(arg, &atreq, sizeof(atreq)) ? -EFAULT : 0;
}


static int atrtr_ioctl(unsigned int cmd, void __user *arg)
{
	struct rtentry rt;

	if (copy_from_user(&rt, arg, sizeof(rt)))
		return -EFAULT;

	switch (cmd) {
		case SIOCDELRT:
			if (rt.rt_dst.sa_family != AF_APPLETALK)
				return -EINVAL;
			return atrtr_delete(&((struct sockaddr_at *)
						&rt.rt_dst)->sat_addr);

		case SIOCADDRT: {
			struct net_device *dev = NULL;
			if (rt.rt_dev) {
				char name[IFNAMSIZ];
				if (copy_from_user(name, rt.rt_dev, IFNAMSIZ-1))
					return -EFAULT;
				name[IFNAMSIZ-1] = '\0';
				dev = __dev_get_by_name(&init_net, name);
				if (!dev)
					return -ENODEV;
			}
			return atrtr_create(&rt, dev);
		}
	}
	return -EINVAL;
}




static unsigned long atalk_sum_partial(const unsigned char *data, int len, unsigned long sum)
{
	
	while (len--) {
		sum += *data;
		sum <<= 1;
		if (sum & 0x10000) {
			sum++;
			sum &= 0xffff;
		}
		data++;
	}
	return sum;
}


static unsigned long atalk_sum_skb(const struct sk_buff *skb, int offset, int len, unsigned long sum)
{
	int start = skb_headlen(skb);
	struct sk_buff *frag_iter;
	int i, copy;

	
	if ( (copy = start - offset) > 0) {
		if (copy > len)
			copy = len;
		sum = atalk_sum_partial(skb->data + offset, copy, sum);
		if ( (len -= copy) == 0)
			return sum;

		offset += copy;
	}

	
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			u8 *vaddr;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			if (copy > len)
				copy = len;
			vaddr = kmap_skb_frag(frag);
			sum = atalk_sum_partial(vaddr + frag->page_offset + offset - start, copy, sum);
			kunmap_skb_frag(vaddr);

			if (!(len -= copy))
				return sum;
			offset += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			sum = atalk_sum_skb(frag_iter, offset - start, copy, sum);
			if ((len -= copy) == 0)
				return sum;
			offset += copy;
		}
		start = end;
	}

	BUG_ON(len > 0);

	return sum;
}

static __be16 atalk_checksum(const struct sk_buff *skb, int len)
{
	unsigned long sum;

	
	sum = atalk_sum_skb(skb, 4, len-4, 0);

	
	return sum ? htons((unsigned short)sum) : htons(0xFFFF);
}

static struct proto ddp_proto = {
	.name	  = "DDP", .owner	  = THIS_MODULE, .obj_size = sizeof(struct atalk_sock), };




static int atalk_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc = -ESOCKTNOSUPPORT;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	
	if (sock->type != SOCK_RAW && sock->type != SOCK_DGRAM)
		goto out;
	rc = -ENOMEM;
	sk = sk_alloc(net, PF_APPLETALK, GFP_KERNEL, &ddp_proto);
	if (!sk)
		goto out;
	rc = 0;
	sock->ops = &atalk_dgram_ops;
	sock_init_data(sock, sk);

	
	sock_set_flag(sk, SOCK_ZAPPED);
out:
	return rc;
}


static int atalk_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		sock_orphan(sk);
		sock->sk = NULL;
		atalk_destroy_socket(sk);
	}
	return 0;
}


static int atalk_pick_and_bind_port(struct sock *sk, struct sockaddr_at *sat)
{
	int retval;

	write_lock_bh(&atalk_sockets_lock);

	for (sat->sat_port = ATPORT_RESERVED;
	     sat->sat_port < ATPORT_LAST;
	     sat->sat_port++) {
		struct sock *s;
		struct hlist_node *node;

		sk_for_each(s, node, &atalk_sockets) {
			struct atalk_sock *at = at_sk(s);

			if (at->src_net == sat->sat_addr.s_net && at->src_node == sat->sat_addr.s_node && at->src_port == sat->sat_port)

				goto try_next_port;
		}

		
		__atalk_insert_socket(sk);
		at_sk(sk)->src_port = sat->sat_port;
		retval = 0;
		goto out;

try_next_port:;
	}

	retval = -EBUSY;
out:
	write_unlock_bh(&atalk_sockets_lock);
	return retval;
}

static int atalk_autobind(struct sock *sk)
{
	struct atalk_sock *at = at_sk(sk);
	struct sockaddr_at sat;
	struct atalk_addr *ap = atalk_find_primary();
	int n = -EADDRNOTAVAIL;

	if (!ap || ap->s_net == htons(ATADDR_ANYNET))
		goto out;

	at->src_net  = sat.sat_addr.s_net  = ap->s_net;
	at->src_node = sat.sat_addr.s_node = ap->s_node;

	n = atalk_pick_and_bind_port(sk, &sat);
	if (!n)
		sock_reset_flag(sk, SOCK_ZAPPED);
out:
	return n;
}


static int atalk_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_at *addr = (struct sockaddr_at *)uaddr;
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);

	if (!sock_flag(sk, SOCK_ZAPPED) || addr_len != sizeof(struct sockaddr_at))
		return -EINVAL;

	if (addr->sat_family != AF_APPLETALK)
		return -EAFNOSUPPORT;

	if (addr->sat_addr.s_net == htons(ATADDR_ANYNET)) {
		struct atalk_addr *ap = atalk_find_primary();

		if (!ap)
			return -EADDRNOTAVAIL;

		at->src_net  = addr->sat_addr.s_net = ap->s_net;
		at->src_node = addr->sat_addr.s_node= ap->s_node;
	} else {
		if (!atalk_find_interface(addr->sat_addr.s_net, addr->sat_addr.s_node))
			return -EADDRNOTAVAIL;

		at->src_net  = addr->sat_addr.s_net;
		at->src_node = addr->sat_addr.s_node;
	}

	if (addr->sat_port == ATADDR_ANYPORT) {
		int n = atalk_pick_and_bind_port(sk, addr);

		if (n < 0)
			return n;
	} else {
		at->src_port = addr->sat_port;

		if (atalk_find_or_insert_socket(sk, addr))
			return -EADDRINUSE;
	}

	sock_reset_flag(sk, SOCK_ZAPPED);
	return 0;
}


static int atalk_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);
	struct sockaddr_at *addr;

	sk->sk_state   = TCP_CLOSE;
	sock->state = SS_UNCONNECTED;

	if (addr_len != sizeof(*addr))
		return -EINVAL;

	addr = (struct sockaddr_at *)uaddr;

	if (addr->sat_family != AF_APPLETALK)
		return -EAFNOSUPPORT;

	if (addr->sat_addr.s_node == ATADDR_BCAST && !sock_flag(sk, SOCK_BROADCAST)) {

		printk(KERN_WARNING "%s is broken and did not set " "SO_BROADCAST. It will break when 2.2 is " "released.\n", current->comm);



		return -EACCES;

	}

	if (sock_flag(sk, SOCK_ZAPPED))
		if (atalk_autobind(sk) < 0)
			return -EBUSY;

	if (!atrtr_get_dev(&addr->sat_addr))
		return -ENETUNREACH;

	at->dest_port = addr->sat_port;
	at->dest_net  = addr->sat_addr.s_net;
	at->dest_node = addr->sat_addr.s_node;

	sock->state  = SS_CONNECTED;
	sk->sk_state = TCP_ESTABLISHED;
	return 0;
}


static int atalk_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len, int peer)
{
	struct sockaddr_at sat;
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);

	if (sock_flag(sk, SOCK_ZAPPED))
		if (atalk_autobind(sk) < 0)
			return -ENOBUFS;

	*uaddr_len = sizeof(struct sockaddr_at);
	memset(&sat.sat_zero, 0, sizeof(sat.sat_zero));

	if (peer) {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -ENOTCONN;

		sat.sat_addr.s_net  = at->dest_net;
		sat.sat_addr.s_node = at->dest_node;
		sat.sat_port	    = at->dest_port;
	} else {
		sat.sat_addr.s_net  = at->src_net;
		sat.sat_addr.s_node = at->src_node;
		sat.sat_port	    = at->src_port;
	}

	sat.sat_family = AF_APPLETALK;
	memcpy(uaddr, &sat, sizeof(sat));
	return 0;
}


static __inline__ int is_ip_over_ddp(struct sk_buff *skb)
{
	return skb->data[12] == 22;
}

static int handle_ip_over_ddp(struct sk_buff *skb)
{
	struct net_device *dev = __dev_get_by_name(&init_net, "ipddp0");
	struct net_device_stats *stats;

	
	if (!dev)
		return -ENODEV;

	skb->protocol = htons(ETH_P_IP);
	skb_pull(skb, 13);
	skb->dev   = dev;
	skb_reset_transport_header(skb);

	stats = netdev_priv(dev);
	stats->rx_packets++;
	stats->rx_bytes += skb->len + 13;
	netif_rx(skb);  
	return 0;
}






static void atalk_route_packet(struct sk_buff *skb, struct net_device *dev, struct ddpehdr *ddp, __u16 len_hops, int origlen)

{
	struct atalk_route *rt;
	struct atalk_addr ta;

	
	if (skb->pkt_type != PACKET_HOST || !ddp->deh_dnet) {
		
		if (dev->type == ARPHRD_PPP)
			printk(KERN_DEBUG "AppleTalk: didn't forward broadcast " "packet received from PPP iface\n");
		goto free_it;
	}

	ta.s_net  = ddp->deh_dnet;
	ta.s_node = ddp->deh_dnode;

	
	rt = atrtr_find(&ta);
	
	len_hops += 1 << 10;
	if (!rt || !(len_hops & (15 << 10)))
		goto free_it;

	

	

	if (rt->flags & RTF_GATEWAY) {
		ta.s_net  = rt->gateway.s_net;
		ta.s_node = rt->gateway.s_node;
	}

	
	skb_trim(skb, min_t(unsigned int, origlen, (rt->dev->hard_header_len + ddp_dl->header_length + (len_hops & 1023))));


	
	ddp->deh_len_hops = htons(len_hops);

	
	if (skb_headroom(skb) < 22) {
		
		struct sk_buff *nskb = skb_realloc_headroom(skb, 32);
		kfree_skb(skb);
		if (!nskb)
			goto out;
		skb = nskb;
	} else skb = skb_unshare(skb, GFP_ATOMIC);

	
	if (skb && aarp_send_ddp(rt->dev, skb, &ta, NULL) == -1)
		goto free_it;
out:
	return;
free_it:
	kfree_skb(skb);
}


static int atalk_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct ddpehdr *ddp;
	struct sock *sock;
	struct atalk_iface *atif;
	struct sockaddr_at tosat;
	int origlen;
	__u16 len_hops;

	if (!net_eq(dev_net(dev), &init_net))
		goto drop;

	
	if (!(skb = skb_share_check(skb, GFP_ATOMIC)))
		goto out;

	
	if (!pskb_may_pull(skb, sizeof(*ddp)))
		goto drop;

	ddp = ddp_hdr(skb);

	len_hops = ntohs(ddp->deh_len_hops);

	
	origlen = skb->len;
	skb_trim(skb, min_t(unsigned int, skb->len, len_hops & 1023));

	
	if (skb->len < sizeof(*ddp) || skb->len < (len_hops & 1023)) {
		pr_debug("AppleTalk: dropping corrupted frame (deh_len=%u, " "skb->len=%u)\n", len_hops & 1023, skb->len);
		goto drop;
	}

	
	if (ddp->deh_sum && atalk_checksum(skb, len_hops & 1023) != ddp->deh_sum)
		
		goto drop;

	
	if (!ddp->deh_dnet)	
		atif = atalk_find_anynet(ddp->deh_dnode, dev);
	else atif = atalk_find_interface(ddp->deh_dnet, ddp->deh_dnode);

	if (!atif) {
		
		atalk_route_packet(skb, dev, ddp, len_hops, origlen);
		return NET_RX_SUCCESS;
	}

	
	if (is_ip_over_ddp(skb))
		return handle_ip_over_ddp(skb);
	
	tosat.sat_addr.s_net  = ddp->deh_dnet;
	tosat.sat_addr.s_node = ddp->deh_dnode;
	tosat.sat_port	      = ddp->deh_dport;

	sock = atalk_search_socket(&tosat, atif);
	if (!sock) 
		goto drop;

	
	skb->sk = sock;

	if (sock_queue_rcv_skb(sock, skb) < 0)
		goto drop;

	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;

}


static int ltalk_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	if (!net_eq(dev_net(dev), &init_net))
		goto freeit;

	
	if (skb_mac_header(skb)[2] == 1) {
		struct ddpehdr *ddp;
		
		struct atalk_addr *ap = atalk_find_dev_addr(dev);

		if (!ap || skb->len < sizeof(__be16) || skb->len > 1023)
			goto freeit;

		
		if (!(skb = skb_share_check(skb, GFP_ATOMIC)))
			return 0;

		
		ddp = (struct ddpehdr *) skb_push(skb, sizeof(*ddp) - 4);

		

		

		ddp->deh_dnode = skb_mac_header(skb)[0];     
		ddp->deh_snode = skb_mac_header(skb)[1];     

		ddp->deh_dnet  = ap->s_net;	
		ddp->deh_snet  = ap->s_net;
		ddp->deh_sum   = 0;		
		
		
		ddp->deh_len_hops = htons(skb->len + (DDP_MAXHOPS << 10));
	}
	skb_reset_transport_header(skb);

	return atalk_rcv(skb, dev, pt, orig_dev);
freeit:
	kfree_skb(skb);
	return 0;
}

static int atalk_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);
	struct sockaddr_at *usat = (struct sockaddr_at *)msg->msg_name;
	int flags = msg->msg_flags;
	int loopback = 0;
	struct sockaddr_at local_satalk, gsat;
	struct sk_buff *skb;
	struct net_device *dev;
	struct ddpehdr *ddp;
	int size;
	struct atalk_route *rt;
	int err;

	if (flags & ~(MSG_DONTWAIT|MSG_CMSG_COMPAT))
		return -EINVAL;

	if (len > DDP_MAXSZ)
		return -EMSGSIZE;

	if (usat) {
		if (sock_flag(sk, SOCK_ZAPPED))
			if (atalk_autobind(sk) < 0)
				return -EBUSY;

		if (msg->msg_namelen < sizeof(*usat) || usat->sat_family != AF_APPLETALK)
			return -EINVAL;

		
		if (usat->sat_addr.s_node == ATADDR_BCAST && !sock_flag(sk, SOCK_BROADCAST)) {
			return -EPERM;
		}
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -ENOTCONN;
		usat = &local_satalk;
		usat->sat_family      = AF_APPLETALK;
		usat->sat_port	      = at->dest_port;
		usat->sat_addr.s_node = at->dest_node;
		usat->sat_addr.s_net  = at->dest_net;
	}

	
	SOCK_DEBUG(sk, "SK %p: Got address.\n", sk);

	
	size = sizeof(struct ddpehdr) + len + ddp_dl->header_length;

	if (usat->sat_addr.s_net || usat->sat_addr.s_node == ATADDR_ANYNODE) {
		rt = atrtr_find(&usat->sat_addr);
	} else {
		struct atalk_addr at_hint;

		at_hint.s_node = 0;
		at_hint.s_net  = at->src_net;

		rt = atrtr_find(&at_hint);
	}
	if (!rt)
		return -ENETUNREACH;

	dev = rt->dev;

	SOCK_DEBUG(sk, "SK %p: Size needed %d, device %s\n", sk, size, dev->name);

	size += dev->hard_header_len;
	skb = sock_alloc_send_skb(sk, size, (flags & MSG_DONTWAIT), &err);
	if (!skb)
		return err;

	skb->sk = sk;
	skb_reserve(skb, ddp_dl->header_length);
	skb_reserve(skb, dev->hard_header_len);
	skb->dev = dev;

	SOCK_DEBUG(sk, "SK %p: Begin build.\n", sk);

	ddp = (struct ddpehdr *)skb_put(skb, sizeof(struct ddpehdr));
	ddp->deh_len_hops  = htons(len + sizeof(*ddp));
	ddp->deh_dnet  = usat->sat_addr.s_net;
	ddp->deh_snet  = at->src_net;
	ddp->deh_dnode = usat->sat_addr.s_node;
	ddp->deh_snode = at->src_node;
	ddp->deh_dport = usat->sat_port;
	ddp->deh_sport = at->src_port;

	SOCK_DEBUG(sk, "SK %p: Copy user data (%Zd bytes).\n", sk, len);

	err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if (err) {
		kfree_skb(skb);
		return -EFAULT;
	}

	if (sk->sk_no_check == 1)
		ddp->deh_sum = 0;
	else ddp->deh_sum = atalk_checksum(skb, len + sizeof(*ddp));

	
	if (ddp->deh_dnode == ATADDR_BCAST && !(rt->flags & RTF_GATEWAY) && !(dev->flags & IFF_LOOPBACK)) {
		struct sk_buff *skb2 = skb_copy(skb, GFP_KERNEL);

		if (skb2) {
			loopback = 1;
			SOCK_DEBUG(sk, "SK %p: send out(copy).\n", sk);
			if (aarp_send_ddp(dev, skb2, &usat->sat_addr, NULL) == -1)
				kfree_skb(skb2);
				
		}
	}

	if (dev->flags & IFF_LOOPBACK || loopback) {
		SOCK_DEBUG(sk, "SK %p: Loop back.\n", sk);
		
		skb_orphan(skb);
		if (ddp->deh_dnode == ATADDR_BCAST) {
			struct atalk_addr at_lo;

			at_lo.s_node = 0;
			at_lo.s_net  = 0;

			rt = atrtr_find(&at_lo);
			if (!rt) {
				kfree_skb(skb);
				return -ENETUNREACH;
			}
			dev = rt->dev;
			skb->dev = dev;
		}
		ddp_dl->request(ddp_dl, skb, dev->dev_addr);
	} else {
		SOCK_DEBUG(sk, "SK %p: send out.\n", sk);
		if (rt->flags & RTF_GATEWAY) {
		    gsat.sat_addr = rt->gateway;
		    usat = &gsat;
		}

		if (aarp_send_ddp(dev, skb, &usat->sat_addr, NULL) == -1)
			kfree_skb(skb);
		
	}
	SOCK_DEBUG(sk, "SK %p: Done write (%Zd).\n", sk, len);

	return len;
}

static int atalk_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_at *sat = (struct sockaddr_at *)msg->msg_name;
	struct ddpehdr *ddp;
	int copied = 0;
	int offset = 0;
	int err = 0;
	struct sk_buff *skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT, flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	
	ddp = ddp_hdr(skb);
	copied = ntohs(ddp->deh_len_hops) & 1023;

	if (sk->sk_type != SOCK_RAW) {
		offset = sizeof(*ddp);
		copied -= offset;
	}

	if (copied > size) {
		copied = size;
		msg->msg_flags |= MSG_TRUNC;
	}
	err = skb_copy_datagram_iovec(skb, offset, msg->msg_iov, copied);

	if (!err) {
		if (sat) {
			sat->sat_family      = AF_APPLETALK;
			sat->sat_port        = ddp->deh_sport;
			sat->sat_addr.s_node = ddp->deh_snode;
			sat->sat_addr.s_net  = ddp->deh_snet;
		}
		msg->msg_namelen = sizeof(*sat);
	}

	skb_free_datagram(sk, skb);	
	return err ? : copied;
}



static int atalk_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int rc = -ENOIOCTLCMD;
	struct sock *sk = sock->sk;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
		
		case TIOCOUTQ: {
			long amount = sk->sk_sndbuf - sk_wmem_alloc_get(sk);

			if (amount < 0)
				amount = 0;
			rc = put_user(amount, (int __user *)argp);
			break;
		}
		case TIOCINQ: {
			
			struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
			long amount = 0;

			if (skb)
				amount = skb->len - sizeof(struct ddpehdr);
			rc = put_user(amount, (int __user *)argp);
			break;
		}
		case SIOCGSTAMP:
			rc = sock_get_timestamp(sk, argp);
			break;
		case SIOCGSTAMPNS:
			rc = sock_get_timestampns(sk, argp);
			break;
		
		case SIOCADDRT:
		case SIOCDELRT:
			rc = -EPERM;
			if (capable(CAP_NET_ADMIN))
				rc = atrtr_ioctl(cmd, argp);
			break;
		
		case SIOCGIFADDR:
		case SIOCSIFADDR:
		case SIOCGIFBRDADDR:
		case SIOCATALKDIFADDR:
		case SIOCDIFADDR:
		case SIOCSARP:		
		case SIOCDARP:		
			rtnl_lock();
			rc = atif_ioctl(cmd, argp);
			rtnl_unlock();
			break;
	}

	return rc;
}



static int atalk_compat_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	
	return -ENOIOCTLCMD;
}



static struct net_proto_family atalk_family_ops = {
	.family		= PF_APPLETALK, .create		= atalk_create, .owner		= THIS_MODULE, };



static const struct proto_ops SOCKOPS_WRAPPED(atalk_dgram_ops) = {
	.family		= PF_APPLETALK, .owner		= THIS_MODULE, .release	= atalk_release, .bind		= atalk_bind, .connect	= atalk_connect, .socketpair	= sock_no_socketpair, .accept		= sock_no_accept, .getname	= atalk_getname, .poll		= datagram_poll, .ioctl		= atalk_ioctl,  .compat_ioctl	= atalk_compat_ioctl,  .listen		= sock_no_listen, .shutdown	= sock_no_shutdown, .setsockopt	= sock_no_setsockopt, .getsockopt	= sock_no_getsockopt, .sendmsg	= atalk_sendmsg, .recvmsg	= atalk_recvmsg, .mmap		= sock_no_mmap, .sendpage	= sock_no_sendpage, };





















SOCKOPS_WRAP(atalk_dgram, PF_APPLETALK);

static struct notifier_block ddp_notifier = {
	.notifier_call	= ddp_device_event, };

static struct packet_type ltalk_packet_type __read_mostly = {
	.type		= cpu_to_be16(ETH_P_LOCALTALK), .func		= ltalk_rcv, };


static struct packet_type ppptalk_packet_type __read_mostly = {
	.type		= cpu_to_be16(ETH_P_PPPTALK), .func		= atalk_rcv, };


static unsigned char ddp_snap_id[] = { 0x08, 0x00, 0x07, 0x80, 0x9B };


EXPORT_SYMBOL(aarp_send_ddp);
EXPORT_SYMBOL(atrtr_get_dev);
EXPORT_SYMBOL(atalk_find_dev_addr);

static const char atalk_err_snap[] __initconst = KERN_CRIT "Unable to register DDP with SNAP.\n";


static int __init atalk_init(void)
{
	int rc = proto_register(&ddp_proto, 0);

	if (rc != 0)
		goto out;

	(void)sock_register(&atalk_family_ops);
	ddp_dl = register_snap_client(ddp_snap_id, atalk_rcv);
	if (!ddp_dl)
		printk(atalk_err_snap);

	dev_add_pack(&ltalk_packet_type);
	dev_add_pack(&ppptalk_packet_type);

	register_netdevice_notifier(&ddp_notifier);
	aarp_proto_init();
	atalk_proc_init();
	atalk_register_sysctl();
out:
	return rc;
}
module_init(atalk_init);


static void __exit atalk_exit(void)
{

	atalk_unregister_sysctl();

	atalk_proc_exit();
	aarp_cleanup_module();	
	unregister_netdevice_notifier(&ddp_notifier);
	dev_remove_pack(&ltalk_packet_type);
	dev_remove_pack(&ppptalk_packet_type);
	unregister_snap_client(ddp_dl);
	sock_unregister(PF_APPLETALK);
	proto_unregister(&ddp_proto);
}
module_exit(atalk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alan Cox <alan@lxorguk.ukuu.org.uk>");
MODULE_DESCRIPTION("AppleTalk 0.20\n");
MODULE_ALIAS_NETPROTO(PF_APPLETALK);
