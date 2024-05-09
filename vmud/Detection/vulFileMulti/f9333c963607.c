





static struct sk_buff *__skb_udp_tunnel_segment(struct sk_buff *skb, netdev_features_t features, struct sk_buff *(*gso_inner_segment)(struct sk_buff *skb, netdev_features_t features), __be16 new_protocol, bool is_ipv6)



{
	int tnl_hlen = skb_inner_mac_header(skb) - skb_transport_header(skb);
	bool remcsum, need_csum, offload_csum, ufo, gso_partial;
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct udphdr *uh = udp_hdr(skb);
	u16 mac_offset = skb->mac_header;
	__be16 protocol = skb->protocol;
	u16 mac_len = skb->mac_len;
	int udp_offset, outer_hlen;
	__wsum partial;

	if (unlikely(!pskb_may_pull(skb, tnl_hlen)))
		goto out;

	
	if (skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL)
		partial = (__force __wsum)uh->len;
	else partial = (__force __wsum)htonl(skb->len);
	partial = csum_sub(csum_unfold(uh->check), partial);

	
	skb->encapsulation = 0;
	SKB_GSO_CB(skb)->encap_level = 0;
	__skb_pull(skb, tnl_hlen);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, skb_inner_network_offset(skb));
	skb->mac_len = skb_inner_network_offset(skb);
	skb->protocol = new_protocol;

	need_csum = !!(skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM);
	skb->encap_hdr_csum = need_csum;

	remcsum = !!(skb_shinfo(skb)->gso_type & SKB_GSO_TUNNEL_REMCSUM);
	skb->remcsum_offload = remcsum;

	ufo = !!(skb_shinfo(skb)->gso_type & SKB_GSO_UDP);

	
	offload_csum = !!(need_csum && (skb->dev->features & (is_ipv6 ? (NETIF_F_HW_CSUM | NETIF_F_IPV6_CSUM) :

				      (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM))));

	features &= skb->dev->hw_enc_features;

	
	if (remcsum || ufo) {
		features &= ~NETIF_F_CSUM_MASK;
		if (!need_csum || offload_csum)
			features |= NETIF_F_HW_CSUM;
	}

	
	segs = gso_inner_segment(skb, features);
	if (IS_ERR_OR_NULL(segs)) {
		skb_gso_error_unwind(skb, protocol, tnl_hlen, mac_offset, mac_len);
		goto out;
	}

	gso_partial = !!(skb_shinfo(segs)->gso_type & SKB_GSO_PARTIAL);

	outer_hlen = skb_tnl_header_len(skb);
	udp_offset = outer_hlen - tnl_hlen;
	skb = segs;
	do {
		unsigned int len;

		if (remcsum)
			skb->ip_summed = CHECKSUM_NONE;

		
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			skb_reset_inner_headers(skb);
			skb->encapsulation = 1;
		}

		skb->mac_len = mac_len;
		skb->protocol = protocol;

		__skb_push(skb, outer_hlen);
		skb_reset_mac_header(skb);
		skb_set_network_header(skb, mac_len);
		skb_set_transport_header(skb, udp_offset);
		len = skb->len - udp_offset;
		uh = udp_hdr(skb);

		
		if (gso_partial) {
			uh->len = htons(skb_shinfo(skb)->gso_size + SKB_GSO_CB(skb)->data_offset + skb->head - (unsigned char *)uh);

		} else {
			uh->len = htons(len);
		}

		if (!need_csum)
			continue;

		uh->check = ~csum_fold(csum_add(partial, (__force __wsum)htonl(len)));

		if (skb->encapsulation || !offload_csum) {
			uh->check = gso_make_checksum(skb, ~uh->check);
			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
		} else {
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_transport_header(skb) - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
		}
	} while ((skb = skb->next));
out:
	return segs;
}

struct sk_buff *skb_udp_tunnel_segment(struct sk_buff *skb, netdev_features_t features, bool is_ipv6)

{
	__be16 protocol = skb->protocol;
	const struct net_offload **offloads;
	const struct net_offload *ops;
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct sk_buff *(*gso_inner_segment)(struct sk_buff *skb, netdev_features_t features);

	rcu_read_lock();

	switch (skb->inner_protocol_type) {
	case ENCAP_TYPE_ETHER:
		protocol = skb->inner_protocol;
		gso_inner_segment = skb_mac_gso_segment;
		break;
	case ENCAP_TYPE_IPPROTO:
		offloads = is_ipv6 ? inet6_offloads : inet_offloads;
		ops = rcu_dereference(offloads[skb->inner_ipproto]);
		if (!ops || !ops->callbacks.gso_segment)
			goto out_unlock;
		gso_inner_segment = ops->callbacks.gso_segment;
		break;
	default:
		goto out_unlock;
	}

	segs = __skb_udp_tunnel_segment(skb, features, gso_inner_segment, protocol, is_ipv6);

out_unlock:
	rcu_read_unlock();

	return segs;
}
EXPORT_SYMBOL(skb_udp_tunnel_segment);

static struct sk_buff *udp4_ufo_fragment(struct sk_buff *skb, netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	unsigned int mss;
	__wsum csum;
	struct udphdr *uh;
	struct iphdr *iph;

	if (skb->encapsulation && (skb_shinfo(skb)->gso_type & (SKB_GSO_UDP_TUNNEL|SKB_GSO_UDP_TUNNEL_CSUM))) {

		segs = skb_udp_tunnel_segment(skb, features, false);
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto out;

	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(skb->len <= mss))
		goto out;

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}

	

	uh = udp_hdr(skb);
	iph = ip_hdr(skb);

	uh->check = 0;
	csum = skb_checksum(skb, 0, skb->len, 0);
	uh->check = udp_v4_check(skb->len, iph->saddr, iph->daddr, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

	skb->ip_summed = CHECKSUM_NONE;

	
	if (!skb->encap_hdr_csum)
		features |= NETIF_F_HW_CSUM;

	
	segs = skb_segment(skb, features);
out:
	return segs;
}

struct sk_buff **udp_gro_receive(struct sk_buff **head, struct sk_buff *skb, struct udphdr *uh, udp_lookup_t lookup)
{
	struct sk_buff *p, **pp = NULL;
	struct udphdr *uh2;
	unsigned int off = skb_gro_offset(skb);
	int flush = 1;
	struct sock *sk;

	if (NAPI_GRO_CB(skb)->encap_mark || (skb->ip_summed != CHECKSUM_PARTIAL && NAPI_GRO_CB(skb)->csum_cnt == 0 && !NAPI_GRO_CB(skb)->csum_valid))


		goto out;

	
	NAPI_GRO_CB(skb)->encap_mark = 1;

	rcu_read_lock();
	sk = (*lookup)(skb, uh->source, uh->dest);

	if (sk && udp_sk(sk)->gro_receive)
		goto unflush;
	goto out_unlock;

unflush:
	flush = 0;

	for (p = *head; p; p = p->next) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		uh2 = (struct udphdr   *)(p->data + off);

		
		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source) || (!uh->check ^ !uh2->check)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	skb_gro_pull(skb, sizeof(struct udphdr)); 
	skb_gro_postpull_rcsum(skb, uh, sizeof(struct udphdr));
	pp = udp_sk(sk)->gro_receive(sk, head, skb);

out_unlock:
	rcu_read_unlock();
out:
	NAPI_GRO_CB(skb)->flush |= flush;
	return pp;
}
EXPORT_SYMBOL(udp_gro_receive);

static struct sk_buff **udp4_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct udphdr *uh = udp_gro_udphdr(skb);

	if (unlikely(!uh))
		goto flush;

	
	if (NAPI_GRO_CB(skb)->flush)
		goto skip;

	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_UDP, uh->check, inet_gro_compute_pseudo))
		goto flush;
	else if (uh->check)
		skb_gro_checksum_try_convert(skb, IPPROTO_UDP, uh->check, inet_gro_compute_pseudo);
skip:
	NAPI_GRO_CB(skb)->is_ipv6 = 0;
	return udp_gro_receive(head, skb, uh, udp4_lib_lookup_skb);

flush:
	NAPI_GRO_CB(skb)->flush = 1;
	return NULL;
}

int udp_gro_complete(struct sk_buff *skb, int nhoff, udp_lookup_t lookup)
{
	__be16 newlen = htons(skb->len - nhoff);
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);
	int err = -ENOSYS;
	struct sock *sk;

	uh->len = newlen;

	
	skb->encapsulation = 1;

	rcu_read_lock();
	sk = (*lookup)(skb, uh->source, uh->dest);
	if (sk && udp_sk(sk)->gro_complete)
		err = udp_sk(sk)->gro_complete(sk, skb, nhoff + sizeof(struct udphdr));
	rcu_read_unlock();

	if (skb->remcsum_offload)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TUNNEL_REMCSUM;

	return err;
}
EXPORT_SYMBOL(udp_gro_complete);

static int udp4_gro_complete(struct sk_buff *skb, int nhoff)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);

	if (uh->check) {
		skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;
		uh->check = ~udp_v4_check(skb->len - nhoff, iph->saddr, iph->daddr, 0);
	} else {
		skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL;
	}

	return udp_gro_complete(skb, nhoff, udp4_lib_lookup_skb);
}

static const struct net_offload udpv4_offload = {
	.callbacks = {
		.gso_segment = udp4_ufo_fragment, .gro_receive  =	udp4_gro_receive, .gro_complete =	udp4_gro_complete, }, };




int __init udpv4_offload_init(void)
{
	return inet_add_offload(&udpv4_offload, IPPROTO_UDP);
}
