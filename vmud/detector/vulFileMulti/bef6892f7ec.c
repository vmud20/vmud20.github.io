





















































struct ip6_exthdrs {
	struct mbuf *ip6e_ip6;
	struct mbuf *ip6e_hbh;
	struct mbuf *ip6e_dest1;
	struct mbuf *ip6e_rthdr;
	struct mbuf *ip6e_dest2;
};

int ip6_pcbopt(int, u_char *, int, struct ip6_pktopts **, int, int);
int ip6_getpcbopt(struct ip6_pktopts *, int, struct mbuf **);
int ip6_setpktopt(int, u_char *, int, struct ip6_pktopts *, int, int, int);
int ip6_setmoptions(int, struct ip6_moptions **, struct mbuf *);
int ip6_getmoptions(int, struct ip6_moptions *, struct mbuf **);
int ip6_copyexthdr(struct mbuf **, caddr_t, int);
int ip6_insertfraghdr(struct mbuf *, struct mbuf *, int, struct ip6_frag **);
int ip6_insert_jumboopt(struct ip6_exthdrs *, u_int32_t);
int ip6_splithdr(struct mbuf *, struct ip6_exthdrs *);
int ip6_getpmtu(struct rtentry *, struct ifnet *, u_long *, int *);
int copypktopts(struct ip6_pktopts *, struct ip6_pktopts *, int);
static __inline u_int16_t __attribute__((__unused__))
    in6_cksum_phdr(const struct in6_addr *, const struct in6_addr *, u_int32_t, u_int32_t);
void in6_delayed_cksum(struct mbuf *, u_int8_t);


struct idgen32_ctx ip6_id_ctx;


int ip6_output(struct mbuf *m0, struct ip6_pktopts *opt, struct route_in6 *ro, int flags, struct ip6_moptions *im6o, struct inpcb *inp)

{
	struct ip6_hdr *ip6;
	struct ifnet *ifp = NULL;
	struct mbuf *m = m0;
	int hlen, tlen;
	struct route_in6 ip6route;
	struct rtentry *rt = NULL;
	struct sockaddr_in6 *dst, dstsock;
	int error = 0;
	u_long mtu;
	int alwaysfrag, dontfrag;
	u_int16_t src_scope, dst_scope;
	u_int32_t optlen = 0, plen = 0, unfragpartlen = 0;
	struct ip6_exthdrs exthdrs;
	struct in6_addr finaldst;
	struct route_in6 *ro_pmtu = NULL;
	int hdrsplit = 0;
	u_int8_t sproto = 0;

	struct tdb *tdb = NULL;



	if (inp && (inp->inp_flags & INP_IPV6) == 0)
		panic("ip6_output: IPv4 pcb is passed");


	ip6 = mtod(m, struct ip6_hdr *);
	finaldst = ip6->ip6_dst;











	bzero(&exthdrs, sizeof(exthdrs));

	if (opt) {
		
		MAKE_EXTHDR(opt->ip6po_hbh, &exthdrs.ip6e_hbh);
		
		MAKE_EXTHDR(opt->ip6po_dest1, &exthdrs.ip6e_dest1);
		
		MAKE_EXTHDR(opt->ip6po_rthdr, &exthdrs.ip6e_rthdr);
		
		MAKE_EXTHDR(opt->ip6po_dest2, &exthdrs.ip6e_dest2);
	}


	if (ipsec_in_use || inp) {
		tdb = ip6_output_ipsec_lookup(m, &error, inp);
		if (error != 0) {
		        
		        if (error == -EINVAL) 
				error = 0;

			goto freehdrs;
		}
	}


	
	optlen = 0;
	if (exthdrs.ip6e_hbh) optlen += exthdrs.ip6e_hbh->m_len;
	if (exthdrs.ip6e_dest1) optlen += exthdrs.ip6e_dest1->m_len;
	if (exthdrs.ip6e_rthdr) optlen += exthdrs.ip6e_rthdr->m_len;
	unfragpartlen = optlen + sizeof(struct ip6_hdr);
	
	if (exthdrs.ip6e_dest2) optlen += exthdrs.ip6e_dest2->m_len;

	
	if ((sproto || optlen) && !hdrsplit) {
		if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
			m = NULL;
			goto freehdrs;
		}
		m = exthdrs.ip6e_ip6;
		hdrsplit++;
	}

	
	ip6 = mtod(m, struct ip6_hdr *);

	
	m->m_pkthdr.len += optlen;
	plen = m->m_pkthdr.len - sizeof(*ip6);

	
	if (plen > IPV6_MAXPACKET) {
		if (!hdrsplit) {
			if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
				m = NULL;
				goto freehdrs;
			}
			m = exthdrs.ip6e_ip6;
			hdrsplit++;
		}
		
		ip6 = mtod(m, struct ip6_hdr *);
		if ((error = ip6_insert_jumboopt(&exthdrs, plen)) != 0)
			goto freehdrs;
		ip6->ip6_plen = 0;
	} else ip6->ip6_plen = htons(plen);

	
	{
		u_char *nexthdrp = &ip6->ip6_nxt;
		struct mbuf *mprev = m;

		
		if (exthdrs.ip6e_dest2) {
			if (!hdrsplit)
				panic("assumption failed: hdr not split");
			exthdrs.ip6e_dest2->m_next = m->m_next;
			m->m_next = exthdrs.ip6e_dest2;
			*mtod(exthdrs.ip6e_dest2, u_char *) = ip6->ip6_nxt;
			ip6->ip6_nxt = IPPROTO_DSTOPTS;
		}













		
		MAKE_CHAIN(exthdrs.ip6e_hbh, mprev, nexthdrp, IPPROTO_HOPOPTS);
		MAKE_CHAIN(exthdrs.ip6e_dest1, mprev, nexthdrp, IPPROTO_DSTOPTS);
		MAKE_CHAIN(exthdrs.ip6e_rthdr, mprev, nexthdrp, IPPROTO_ROUTING);
	}

	
	if (exthdrs.ip6e_rthdr) {
		struct ip6_rthdr *rh;
		struct ip6_rthdr0 *rh0;
		struct in6_addr *addr;

		rh = (struct ip6_rthdr *)(mtod(exthdrs.ip6e_rthdr, struct ip6_rthdr *));
		switch (rh->ip6r_type) {
		case IPV6_RTHDR_TYPE_0:
			 rh0 = (struct ip6_rthdr0 *)rh;
			 addr = (struct in6_addr *)(rh0 + 1);
			 ip6->ip6_dst = addr[0];
			 bcopy(&addr[1], &addr[0], sizeof(struct in6_addr) * (rh0->ip6r0_segleft - 1));
			 addr[rh0->ip6r0_segleft - 1] = finaldst;
			 break;
		default:	
			 error = EINVAL;
			 goto bad;
		}
	}

	
	if (!(flags & IPV6_UNSPECSRC) && IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
		
		error = EOPNOTSUPP;
		ip6stat.ip6s_badscope++;
		goto bad;
	}
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src)) {
		error = EOPNOTSUPP;
		ip6stat.ip6s_badscope++;
		goto bad;
	}

	ip6stat.ip6s_localout++;

	

reroute:


	
	if (ro == NULL) {
		ro = &ip6route;
		bzero((caddr_t)ro, sizeof(*ro));
	}
	ro_pmtu = ro;
	if (opt && opt->ip6po_rthdr)
		ro = &opt->ip6po_route;
	dst = &ro->ro_dst;

	
	if (opt && opt->ip6po_tclass >= 0) {
		int mask = 0;

		if ((ip6->ip6_flow & htonl(0xfc << 20)) == 0)
			mask |= 0xfc;
		if ((ip6->ip6_flow & htonl(0x03 << 20)) == 0)
			mask |= 0x03;
		if (mask != 0)
			ip6->ip6_flow |= htonl((opt->ip6po_tclass & mask) << 20);
	}

	
	if (opt && opt->ip6po_hlim != -1)
		ip6->ip6_hlim = opt->ip6po_hlim & 0xff;
	else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		if (im6o != NULL)
			ip6->ip6_hlim = im6o->im6o_hlim;
		else ip6->ip6_hlim = ip6_defmcasthlim;
	}


	if (tdb) {
		
		
		error = ip6_output_ipsec_send(tdb, m, exthdrs.ip6e_rthdr ? 1 : 0, 0);
		goto done;
	}


	bzero(&dstsock, sizeof(dstsock));
	dstsock.sin6_family = AF_INET6;
	dstsock.sin6_addr = ip6->ip6_dst;
	dstsock.sin6_len = sizeof(dstsock);
	ro->ro_tableid = m->m_pkthdr.ph_rtableid;

	if (IN6_IS_ADDR_MULTICAST(&dstsock.sin6_addr)) {
		struct in6_pktinfo *pi = NULL;

		
		if (opt != NULL && (pi = opt->ip6po_pktinfo) != NULL)
			ifp = if_get(pi->ipi6_ifindex);

		if (ifp == NULL && im6o != NULL)
			ifp = if_get(im6o->im6o_ifidx);
	}

	if (ifp == NULL) {
		rt = in6_selectroute(&dstsock, opt, ro, ro->ro_tableid);
		if (rt == NULL) {
			ip6stat.ip6s_noroute++;
			error = EHOSTUNREACH;
			goto bad;
		}
		if (ISSET(rt->rt_flags, RTF_LOCAL))
			ifp = if_get(rtable_loindex(m->m_pkthdr.ph_rtableid));
		else ifp = if_get(rt->rt_ifidx);
	} else {
		*dst = dstsock;
	}

	if (rt && (rt->rt_flags & RTF_GATEWAY) && !IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
		dst = satosin6(rt->rt_gateway);

	if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		

		m->m_flags &= ~(M_BCAST | M_MCAST);	
	} else {
		

		m->m_flags = (m->m_flags & ~M_BCAST) | M_MCAST;

		
		if ((ifp->if_flags & IFF_MULTICAST) == 0) {
			ip6stat.ip6s_noroute++;
			error = ENETUNREACH;
			goto bad;
		}

		if ((im6o == NULL || im6o->im6o_loop) && in6_hasmulti(&ip6->ip6_dst, ifp)) {
			
			in6_proto_cksum_out(m, NULL);
			ip6_mloopback(ifp, m, dst);
		}

		else {
			
			if (ip6_mforwarding && ip6_mrouter && (flags & IPV6_FORWARDING) == 0) {
				if (ip6_mforward(ip6, ifp, m) != 0) {
					m_freem(m);
					goto done;
				}
			}
		}

		
		if (ip6->ip6_hlim == 0 || (ifp->if_flags & IFF_LOOPBACK) || IN6_IS_ADDR_MC_INTFACELOCAL(&ip6->ip6_dst)) {
			m_freem(m);
			goto done;
		}
	}

	
	if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src)) {
		if (ifp->if_flags & IFF_LOOPBACK)
			src_scope = ip6->ip6_src.s6_addr16[1];
		ip6->ip6_src.s6_addr16[1] = 0;
	}
	if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst)) {
		if (ifp->if_flags & IFF_LOOPBACK)
			dst_scope = ip6->ip6_dst.s6_addr16[1];
		ip6->ip6_dst.s6_addr16[1] = 0;
	}

	
	if ((error = ip6_getpmtu(ro_pmtu->ro_rt, ifp, &mtu, &alwaysfrag)) != 0)
		goto bad;

	
	if (mtu > IPV6_MMTU) {
		if ((flags & IPV6_MINMTU))
			mtu = IPV6_MMTU;
		else if (opt && opt->ip6po_minmtu == IP6PO_MINMTU_ALL)
			mtu = IPV6_MMTU;
		else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) && (opt == NULL || opt->ip6po_minmtu != IP6PO_MINMTU_DISABLE)) {

			mtu = IPV6_MMTU;
		}
	}

	
	if (exthdrs.ip6e_hbh) {
		struct ip6_hbh *hbh = mtod(exthdrs.ip6e_hbh, struct ip6_hbh *);
		u_int32_t dummy1; 
		u_int32_t dummy2; 

		
		m->m_flags |= M_LOOP;
		m->m_pkthdr.ph_ifidx = ifp->if_index;
		if (ip6_process_hopopts(m, (u_int8_t *)(hbh + 1), ((hbh->ip6h_len + 1) << 3) - sizeof(struct ip6_hbh), &dummy1, &dummy2) < 0) {

			
			error = EINVAL;
			goto done;
		}
		m->m_flags &= ~M_LOOP; 
		m->m_pkthdr.ph_ifidx = 0;
	}


	if (pf_test(AF_INET6, PF_OUT, ifp, &m) != PF_PASS) {
		error = EHOSTUNREACH;
		m_freem(m);
		goto done;
	}
	if (m == NULL)
		goto done;
	ip6 = mtod(m, struct ip6_hdr *);
	if ((m->m_pkthdr.pf.flags & (PF_TAG_REROUTE | PF_TAG_GENERATED)) == (PF_TAG_REROUTE | PF_TAG_GENERATED)) {
		
		m->m_pkthdr.pf.flags &= ~(PF_TAG_GENERATED | PF_TAG_REROUTE);
	} else if (m->m_pkthdr.pf.flags & PF_TAG_REROUTE) {
		
		m->m_pkthdr.pf.flags |= PF_TAG_GENERATED;
		finaldst = ip6->ip6_dst;
		ro = NULL;
		if_put(ifp); 
		ifp = NULL;
		goto reroute;
	}


	
	if (ifp->if_flags & IFF_LOOPBACK) {
		if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src))
			ip6->ip6_src.s6_addr16[1] = src_scope;
		if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst))
			ip6->ip6_dst.s6_addr16[1] = dst_scope;
	}

	in6_proto_cksum_out(m, ifp);

	
	tlen = m->m_pkthdr.len;

	if (opt && (opt->ip6po_flags & IP6PO_DONTFRAG))
		dontfrag = 1;
	else dontfrag = 0;
	if (dontfrag && alwaysfrag) {	
		
		error = EMSGSIZE;
		goto bad;
	}
	if (dontfrag && tlen > ifp->if_mtu) {	
		error = EMSGSIZE;
		goto bad;
	}

	
	if (dontfrag || (!alwaysfrag && tlen <= mtu)) {	
		error = ifp->if_output(ifp, m, sin6tosa(dst), ro->ro_rt);
		goto done;
	}

	
	if (mtu < IPV6_MMTU) {
		
		error = EMSGSIZE;
		goto bad;
	} else if (ip6->ip6_plen == 0) {
		
		error = EMSGSIZE;
		goto bad;
	} else {
		u_char nextproto;

		struct ip6ctlparam ip6cp;
		u_int32_t mtu32;


		
		hlen = unfragpartlen;
		if (mtu > IPV6_MAXPACKET)
			mtu = IPV6_MAXPACKET;


		
		mtu32 = (u_int32_t)mtu;
		bzero(&ip6cp, sizeof(ip6cp));
		ip6cp.ip6c_cmdarg = (void *)&mtu32;
		pfctlinput2(PRC_MSGSIZE, sin6tosa(&ro_pmtu->ro_dst), (void *)&ip6cp);


		
		if (exthdrs.ip6e_rthdr) {
			nextproto = *mtod(exthdrs.ip6e_rthdr, u_char *);
			*mtod(exthdrs.ip6e_rthdr, u_char *) = IPPROTO_FRAGMENT;
		} else if (exthdrs.ip6e_dest1) {
			nextproto = *mtod(exthdrs.ip6e_dest1, u_char *);
			*mtod(exthdrs.ip6e_dest1, u_char *) = IPPROTO_FRAGMENT;
		} else if (exthdrs.ip6e_hbh) {
			nextproto = *mtod(exthdrs.ip6e_hbh, u_char *);
			*mtod(exthdrs.ip6e_hbh, u_char *) = IPPROTO_FRAGMENT;
		} else {
			nextproto = ip6->ip6_nxt;
			ip6->ip6_nxt = IPPROTO_FRAGMENT;
		}

		m0 = m;
		error = ip6_fragment(m0, hlen, nextproto, mtu);
		if (error)
			ip6stat.ip6s_odropped++;
	}

	
	m = m0->m_nextpkt;
	m0->m_nextpkt = 0;
	m_freem(m0);
	for (m0 = m; m; m = m0) {
		m0 = m->m_nextpkt;
		m->m_nextpkt = 0;
		if (error == 0) {
			ip6stat.ip6s_ofragments++;
			error = ifp->if_output(ifp, m, sin6tosa(dst), ro->ro_rt);
		} else m_freem(m);
	}

	if (error == 0)
		ip6stat.ip6s_fragmented++;

done:
	if_put(ifp);
	if (ro == &ip6route && ro->ro_rt) {
		rtfree(ro->ro_rt);
	} else if (ro_pmtu == &ip6route && ro_pmtu->ro_rt) {
		rtfree(ro_pmtu->ro_rt);
	}

	return (error);

freehdrs:
	m_freem(exthdrs.ip6e_hbh);	
	m_freem(exthdrs.ip6e_dest1);
	m_freem(exthdrs.ip6e_rthdr);
	m_freem(exthdrs.ip6e_dest2);
	
bad:
	m_freem(m);
	goto done;
}

int ip6_fragment(struct mbuf *m0, int hlen, u_char nextproto, u_long mtu)
{
	struct mbuf	*m, **mnext, *m_frgpart;
	struct ip6_hdr	*mhip6;
	struct ip6_frag	*ip6f;
	u_int32_t	 id;
	int		 tlen, len, off;
	int		 error;

	id = htonl(ip6_randomid());

	mnext = &m0->m_nextpkt;
	*mnext = NULL;

	tlen = m0->m_pkthdr.len;
	len = (mtu - hlen - sizeof(struct ip6_frag)) & ~7;
	if (len < 8)
		return (EMSGSIZE);

	
	for (off = hlen; off < tlen; off += len) {
		struct mbuf *mlast;

		if ((m = m_gethdr(M_DONTWAIT, MT_HEADER)) == NULL)
			return (ENOBUFS);
		*mnext = m;
		mnext = &m->m_nextpkt;
		if ((error = m_dup_pkthdr(m, m0, M_DONTWAIT)) != 0)
			return (error);
		m->m_data += max_linkhdr;
		mhip6 = mtod(m, struct ip6_hdr *);
		*mhip6 = *mtod(m0, struct ip6_hdr *);
		m->m_len = sizeof(*mhip6);
		if ((error = ip6_insertfraghdr(m0, m, hlen, &ip6f)) != 0)
			return (error);
		ip6f->ip6f_offlg = htons((u_int16_t)((off - hlen) & ~7));
		if (off + len >= tlen)
			len = tlen - off;
		else ip6f->ip6f_offlg |= IP6F_MORE_FRAG;
		mhip6->ip6_plen = htons((u_int16_t)(len + hlen + sizeof(*ip6f) - sizeof(struct ip6_hdr)));
		if ((m_frgpart = m_copym(m0, off, len, M_DONTWAIT)) == NULL)
			return (ENOBUFS);
		for (mlast = m; mlast->m_next; mlast = mlast->m_next)
			;
		mlast->m_next = m_frgpart;
		m->m_pkthdr.len = len + hlen + sizeof(*ip6f);
		ip6f->ip6f_reserved = 0;
		ip6f->ip6f_ident = id;
		ip6f->ip6f_nxt = nextproto;
	}

	return (0);
}

int ip6_copyexthdr(struct mbuf **mp, caddr_t hdr, int hlen)
{
	struct mbuf *m;

	if (hlen > MCLBYTES)
		return (ENOBUFS); 

	MGET(m, M_DONTWAIT, MT_DATA);
	if (!m)
		return (ENOBUFS);

	if (hlen > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (ENOBUFS);
		}
	}
	m->m_len = hlen;
	if (hdr)
		bcopy(hdr, mtod(m, caddr_t), hlen);

	*mp = m;
	return (0);
}


int ip6_insert_jumboopt(struct ip6_exthdrs *exthdrs, u_int32_t plen)
{
	struct mbuf *mopt;
	u_int8_t *optbuf;
	u_int32_t v;



	
	if (exthdrs->ip6e_hbh == 0) {
		MGET(mopt, M_DONTWAIT, MT_DATA);
		if (mopt == NULL)
			return (ENOBUFS);
		mopt->m_len = JUMBOOPTLEN;
		optbuf = mtod(mopt, u_int8_t *);
		optbuf[1] = 0;	
		exthdrs->ip6e_hbh = mopt;
	} else {
		struct ip6_hbh *hbh;

		mopt = exthdrs->ip6e_hbh;
		if (M_TRAILINGSPACE(mopt) < JUMBOOPTLEN) {
			
			int oldoptlen = mopt->m_len;
			struct mbuf *n;

			
			if (oldoptlen + JUMBOOPTLEN > MCLBYTES)
				return (ENOBUFS);

			
			MGET(n, M_DONTWAIT, MT_DATA);
			if (n) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_freem(n);
					n = NULL;
				}
			}
			if (!n)
				return (ENOBUFS);
			n->m_len = oldoptlen + JUMBOOPTLEN;
			bcopy(mtod(mopt, caddr_t), mtod(n, caddr_t), oldoptlen);
			optbuf = mtod(n, u_int8_t *) + oldoptlen;
			m_freem(mopt);
			mopt = exthdrs->ip6e_hbh = n;
		} else {
			optbuf = mtod(mopt, u_int8_t *) + mopt->m_len;
			mopt->m_len += JUMBOOPTLEN;
		}
		optbuf[0] = IP6OPT_PADN;
		optbuf[1] = 0;

		
		hbh = mtod(mopt, struct ip6_hbh *);
		hbh->ip6h_len += (JUMBOOPTLEN >> 3);
	}

	
	optbuf[2] = IP6OPT_JUMBO;
	optbuf[3] = 4;
	v = (u_int32_t)htonl(plen + JUMBOOPTLEN);
	memcpy(&optbuf[4], &v, sizeof(u_int32_t));

	
	exthdrs->ip6e_ip6->m_pkthdr.len += JUMBOOPTLEN;

	return (0);

}


int ip6_insertfraghdr(struct mbuf *m0, struct mbuf *m, int hlen, struct ip6_frag **frghdrp)

{
	struct mbuf *n, *mlast;

	if (hlen > sizeof(struct ip6_hdr)) {
		n = m_copym(m0, sizeof(struct ip6_hdr), hlen - sizeof(struct ip6_hdr), M_DONTWAIT);
		if (n == NULL)
			return (ENOBUFS);
		m->m_next = n;
	} else n = m;

	
	for (mlast = n; mlast->m_next; mlast = mlast->m_next)
		;

	if ((mlast->m_flags & M_EXT) == 0 && M_TRAILINGSPACE(mlast) >= sizeof(struct ip6_frag)) {
		
		*frghdrp = (struct ip6_frag *)(mtod(mlast, caddr_t) + mlast->m_len);
		mlast->m_len += sizeof(struct ip6_frag);
		m->m_pkthdr.len += sizeof(struct ip6_frag);
	} else {
		
		struct mbuf *mfrg;

		MGET(mfrg, M_DONTWAIT, MT_DATA);
		if (mfrg == NULL)
			return (ENOBUFS);
		mfrg->m_len = sizeof(struct ip6_frag);
		*frghdrp = mtod(mfrg, struct ip6_frag *);
		mlast->m_next = mfrg;
	}

	return (0);
}

int ip6_getpmtu(struct rtentry *rt, struct ifnet *ifp, u_long *mtup, int *alwaysfragp)

{
	u_int32_t mtu = 0;
	int alwaysfrag = 0;
	int error = 0;

	if (rt != NULL) {
		mtu = rt->rt_rmx.rmx_mtu;
		if (mtu == 0)
			mtu = ifp->if_mtu;
		else if (mtu < IPV6_MMTU) {
			
			alwaysfrag = 1;
			mtu = IPV6_MMTU;
		} else if (mtu > ifp->if_mtu) {
			
			mtu = ifp->if_mtu;
			if (!(rt->rt_rmx.rmx_locks & RTV_MTU))
				rt->rt_rmx.rmx_mtu = mtu;
		}
	} else {
		mtu = ifp->if_mtu;
	}

	*mtup = mtu;
	if (alwaysfragp)
		*alwaysfragp = alwaysfrag;
	return (error);
}


int ip6_ctloutput(int op, struct socket *so, int level, int optname, struct mbuf **mp)

{
	int privileged, optdatalen, uproto;
	void *optdata;
	struct inpcb *inp = sotoinpcb(so);
	struct mbuf *m = *mp;
	int error, optval;
	struct proc *p = curproc; 
	u_int rtid = 0;

	error = optval = 0;

	privileged = (inp->inp_socket->so_state & SS_PRIV);
	uproto = (int)so->so_proto->pr_protocol;

	if (level == IPPROTO_IPV6) {
		switch (op) {
		case PRCO_SETOPT:
			switch (optname) {
			
			case IPV6_RECVHOPOPTS:
			case IPV6_RECVDSTOPTS:
				if (!privileged) {
					error = EPERM;
					break;
				}
				
			case IPV6_UNICAST_HOPS:
			case IPV6_MINHOPCOUNT:
			case IPV6_HOPLIMIT:

			case IPV6_RECVPKTINFO:
			case IPV6_RECVHOPLIMIT:
			case IPV6_RECVRTHDR:
			case IPV6_RECVPATHMTU:
			case IPV6_RECVTCLASS:
			case IPV6_V6ONLY:
			case IPV6_AUTOFLOWLABEL:
			case IPV6_RECVDSTPORT:
				if (m == NULL || m->m_len != sizeof(int)) {
					error = EINVAL;
					break;
				}
				optval = *mtod(m, int *);
				switch (optname) {

				case IPV6_UNICAST_HOPS:
					if (optval < -1 || optval >= 256)
						error = EINVAL;
					else {
						
						inp->inp_hops = optval;
					}
					break;

				case IPV6_MINHOPCOUNT:
					if (optval < 0 || optval > 255)
						error = EINVAL;
					else inp->inp_ip6_minhlim = optval;
					break;









				case IPV6_RECVPKTINFO:
					OPTSET(IN6P_PKTINFO);
					break;

				case IPV6_HOPLIMIT:
				{
					struct ip6_pktopts **optp;

					optp = &inp->inp_outputopts6;
					error = ip6_pcbopt(IPV6_HOPLIMIT, (u_char *)&optval, sizeof(optval), optp, privileged, uproto);



					break;
				}

				case IPV6_RECVHOPLIMIT:
					OPTSET(IN6P_HOPLIMIT);
					break;

				case IPV6_RECVHOPOPTS:
					OPTSET(IN6P_HOPOPTS);
					break;

				case IPV6_RECVDSTOPTS:
					OPTSET(IN6P_DSTOPTS);
					break;

				case IPV6_RECVRTHDR:
					OPTSET(IN6P_RTHDR);
					break;

				case IPV6_RECVPATHMTU:
					
					if (uproto != IPPROTO_TCP)
						OPTSET(IN6P_MTU);
					break;

				case IPV6_V6ONLY:
					
					if (inp->inp_lport || !IN6_IS_ADDR_UNSPECIFIED(&inp->inp_laddr6)) {
						error = EINVAL;
						break;
					}
					
					if (!optval)
						error = EINVAL;
					else error = 0;
					break;
				case IPV6_RECVTCLASS:
					OPTSET(IN6P_TCLASS);
					break;
				case IPV6_AUTOFLOWLABEL:
					OPTSET(IN6P_AUTOFLOWLABEL);
					break;

				case IPV6_RECVDSTPORT:
					OPTSET(IN6P_RECVDSTPORT);
					break;
				}
				break;

			case IPV6_TCLASS:
			case IPV6_DONTFRAG:
			case IPV6_USE_MIN_MTU:
				if (m == NULL || m->m_len != sizeof(optval)) {
					error = EINVAL;
					break;
				}
				optval = *mtod(m, int *);
				{
					struct ip6_pktopts **optp;
					optp = &inp->inp_outputopts6;
					error = ip6_pcbopt(optname, (u_char *)&optval, sizeof(optval), optp, privileged, uproto);



					break;
				}

			case IPV6_PKTINFO:
			case IPV6_HOPOPTS:
			case IPV6_RTHDR:
			case IPV6_DSTOPTS:
			case IPV6_RTHDRDSTOPTS:
			{
				
				u_char *optbuf;
				int optbuflen;
				struct ip6_pktopts **optp;

				if (m && m->m_next) {
					error = EINVAL;	
					break;
				}
				if (m) {
					optbuf = mtod(m, u_char *);
					optbuflen = m->m_len;
				} else {
					optbuf = NULL;
					optbuflen = 0;
				}
				optp = &inp->inp_outputopts6;
				error = ip6_pcbopt(optname, optbuf, optbuflen, optp, privileged, uproto);

				break;
			}


			case IPV6_MULTICAST_IF:
			case IPV6_MULTICAST_HOPS:
			case IPV6_MULTICAST_LOOP:
			case IPV6_JOIN_GROUP:
			case IPV6_LEAVE_GROUP:
				error =	ip6_setmoptions(optname, &inp->inp_moptions6, m);

				break;

			case IPV6_PORTRANGE:
				if (m == NULL || m->m_len != sizeof(int)) {
					error = EINVAL;
					break;
				}
				optval = *mtod(m, int *);

				switch (optval) {
				case IPV6_PORTRANGE_DEFAULT:
					inp->inp_flags &= ~(IN6P_LOWPORT);
					inp->inp_flags &= ~(IN6P_HIGHPORT);
					break;

				case IPV6_PORTRANGE_HIGH:
					inp->inp_flags &= ~(IN6P_LOWPORT);
					inp->inp_flags |= IN6P_HIGHPORT;
					break;

				case IPV6_PORTRANGE_LOW:
					inp->inp_flags &= ~(IN6P_HIGHPORT);
					inp->inp_flags |= IN6P_LOWPORT;
					break;

				default:
					error = EINVAL;
					break;
				}
				break;

			case IPSEC6_OUTSA:
				error = EINVAL;
				break;

			case IPV6_AUTH_LEVEL:
			case IPV6_ESP_TRANS_LEVEL:
			case IPV6_ESP_NETWORK_LEVEL:
			case IPV6_IPCOMP_LEVEL:

				error = EINVAL;

				if (m == NULL || m->m_len != sizeof(int)) {
					error = EINVAL;
					break;
				}
				optval = *mtod(m, int *);

				if (optval < IPSEC_LEVEL_BYPASS || optval > IPSEC_LEVEL_UNIQUE) {
					error = EINVAL;
					break;
				}

				switch (optname) {
				case IPV6_AUTH_LEVEL:
				        if (optval < IPSEC_AUTH_LEVEL_DEFAULT && suser(p, 0)) {
						error = EACCES;
						break;
					}
					inp->inp_seclevel[SL_AUTH] = optval;
					break;

				case IPV6_ESP_TRANS_LEVEL:
				        if (optval < IPSEC_ESP_TRANS_LEVEL_DEFAULT && suser(p, 0)) {
						error = EACCES;
						break;
					}
					inp->inp_seclevel[SL_ESP_TRANS] = optval;
					break;

				case IPV6_ESP_NETWORK_LEVEL:
				        if (optval < IPSEC_ESP_NETWORK_LEVEL_DEFAULT && suser(p, 0)) {
						error = EACCES;
						break;
					}
					inp->inp_seclevel[SL_ESP_NETWORK] = optval;
					break;

				case IPV6_IPCOMP_LEVEL:
				        if (optval < IPSEC_IPCOMP_LEVEL_DEFAULT && suser(p, 0)) {
						error = EACCES;
						break;
					}
					inp->inp_seclevel[SL_IPCOMP] = optval;
					break;
				}

				break;
			case SO_RTABLE:
				if (m == NULL || m->m_len < sizeof(u_int)) {
					error = EINVAL;
					break;
				}
				rtid = *mtod(m, u_int *);
				if (inp->inp_rtableid == rtid)
					break;
				
				if (p->p_p->ps_rtableid != rtid && p->p_p->ps_rtableid != 0 && (error = suser(p, 0)) != 0)

					break;
				
				if (!rtable_exists(rtid)) {
					error = EINVAL;
					break;
				}
				if (inp->inp_lport) {
					error = EBUSY;
					break;
				}
				inp->inp_rtableid = rtid;
				in_pcbrehash(inp);
				break;
			case IPV6_PIPEX:
				if (m != NULL && m->m_len == sizeof(int))
					inp->inp_pipex = *mtod(m, int *);
				else error = EINVAL;
				break;

			default:
				error = ENOPROTOOPT;
				break;
			}
			m_free(m);
			break;

		case PRCO_GETOPT:
			switch (optname) {

			case IPV6_RECVHOPOPTS:
			case IPV6_RECVDSTOPTS:
			case IPV6_UNICAST_HOPS:
			case IPV6_MINHOPCOUNT:
			case IPV6_RECVPKTINFO:
			case IPV6_RECVHOPLIMIT:
			case IPV6_RECVRTHDR:
			case IPV6_RECVPATHMTU:

			case IPV6_V6ONLY:
			case IPV6_PORTRANGE:
			case IPV6_RECVTCLASS:
			case IPV6_AUTOFLOWLABEL:
			case IPV6_RECVDSTPORT:
				switch (optname) {

				case IPV6_RECVHOPOPTS:
					optval = OPTBIT(IN6P_HOPOPTS);
					break;

				case IPV6_RECVDSTOPTS:
					optval = OPTBIT(IN6P_DSTOPTS);
					break;

				case IPV6_UNICAST_HOPS:
					optval = inp->inp_hops;
					break;

				case IPV6_MINHOPCOUNT:
					optval = inp->inp_ip6_minhlim;
					break;

				case IPV6_RECVPKTINFO:
					optval = OPTBIT(IN6P_PKTINFO);
					break;

				case IPV6_RECVHOPLIMIT:
					optval = OPTBIT(IN6P_HOPLIMIT);
					break;

				case IPV6_RECVRTHDR:
					optval = OPTBIT(IN6P_RTHDR);
					break;

				case IPV6_RECVPATHMTU:
					optval = OPTBIT(IN6P_MTU);
					break;

				case IPV6_V6ONLY:
					optval = 1;
					break;

				case IPV6_PORTRANGE:
				    {
					int flags;
					flags = inp->inp_flags;
					if (flags & IN6P_HIGHPORT)
						optval = IPV6_PORTRANGE_HIGH;
					else if (flags & IN6P_LOWPORT)
						optval = IPV6_PORTRANGE_LOW;
					else optval = 0;
					break;
				    }
				case IPV6_RECVTCLASS:
					optval = OPTBIT(IN6P_TCLASS);
					break;

				case IPV6_AUTOFLOWLABEL:
					optval = OPTBIT(IN6P_AUTOFLOWLABEL);
					break;

				case IPV6_RECVDSTPORT:
					optval = OPTBIT(IN6P_RECVDSTPORT);
					break;
				}
				if (error)
					break;
				*mp = m = m_get(M_WAIT, MT_SOOPTS);
				m->m_len = sizeof(int);
				*mtod(m, int *) = optval;
				break;

			case IPV6_PATHMTU:
			{
				u_long pmtu = 0;
				struct ip6_mtuinfo mtuinfo;
				struct ifnet *ifp;
				struct rtentry *rt;

				if (!(so->so_state & SS_ISCONNECTED))
					return (ENOTCONN);

				rt = in_pcbrtentry(inp);
				if (!rtisvalid(rt))
					return (EHOSTUNREACH);

				ifp = if_get(rt->rt_ifidx);
				if (ifp == NULL)
					return (EHOSTUNREACH);
				
				error = ip6_getpmtu(rt, ifp, &pmtu, NULL);
				if_put(ifp);
				if (error)
					break;
				if (pmtu > IPV6_MAXPACKET)
					pmtu = IPV6_MAXPACKET;

				bzero(&mtuinfo, sizeof(mtuinfo));
				mtuinfo.ip6m_mtu = (u_int32_t)pmtu;
				optdata = (void *)&mtuinfo;
				optdatalen = sizeof(mtuinfo);
				if (optdatalen > MCLBYTES)
					return (EMSGSIZE); 
				*mp = m = m_get(M_WAIT, MT_SOOPTS);
				if (optdatalen > MLEN)
					MCLGET(m, M_WAIT);
				m->m_len = optdatalen;
				bcopy(optdata, mtod(m, void *), optdatalen);
				break;
			}

			case IPV6_PKTINFO:
			case IPV6_HOPOPTS:
			case IPV6_RTHDR:
			case IPV6_DSTOPTS:
			case IPV6_RTHDRDSTOPTS:
			case IPV6_TCLASS:
			case IPV6_DONTFRAG:
			case IPV6_USE_MIN_MTU:
				error = ip6_getpcbopt(inp->inp_outputopts6, optname, mp);
				break;

			case IPV6_MULTICAST_IF:
			case IPV6_MULTICAST_HOPS:
			case IPV6_MULTICAST_LOOP:
			case IPV6_JOIN_GROUP:
			case IPV6_LEAVE_GROUP:
				error = ip6_getmoptions(optname, inp->inp_moptions6, mp);
				break;

			case IPSEC6_OUTSA:
				error = EINVAL;
				break;

			case IPV6_AUTH_LEVEL:
			case IPV6_ESP_TRANS_LEVEL:
			case IPV6_ESP_NETWORK_LEVEL:
			case IPV6_IPCOMP_LEVEL:
				*mp = m = m_get(M_WAIT, MT_SOOPTS);

				m->m_len = sizeof(int);
				*mtod(m, int *) = IPSEC_LEVEL_NONE;

				m->m_len = sizeof(int);
				switch (optname) {
				case IPV6_AUTH_LEVEL:
					optval = inp->inp_seclevel[SL_AUTH];
					break;

				case IPV6_ESP_TRANS_LEVEL:
					optval = inp->inp_seclevel[SL_ESP_TRANS];
					break;

				case IPV6_ESP_NETWORK_LEVEL:
					optval = inp->inp_seclevel[SL_ESP_NETWORK];
					break;

				case IPV6_IPCOMP_LEVEL:
					optval = inp->inp_seclevel[SL_IPCOMP];
					break;
				}
				*mtod(m, int *) = optval;

				break;
			case SO_RTABLE:
				*mp = m = m_get(M_WAIT, MT_SOOPTS);
				m->m_len = sizeof(u_int);
				*mtod(m, u_int *) = optval;
				break;
			case IPV6_PIPEX:
				*mp = m = m_get(M_WAIT, MT_SOOPTS);
				m->m_len = sizeof(int);
				*mtod(m, int *) = optval;
				break;

			default:
				error = ENOPROTOOPT;
				break;
			}
			break;
		}
	} else {
		error = EINVAL;
		if (op == PRCO_SETOPT)
			(void)m_free(*mp);
	}
	return (error);
}

int ip6_raw_ctloutput(int op, struct socket *so, int level, int optname, struct mbuf **mp)

{
	int error = 0, optval;
	const int icmp6off = offsetof(struct icmp6_hdr, icmp6_cksum);
	struct inpcb *inp = sotoinpcb(so);
	struct mbuf *m = *mp;

	if (level != IPPROTO_IPV6) {
		if (op == PRCO_SETOPT)
			(void)m_free(*mp);
		return (EINVAL);
	}

	switch (optname) {
	case IPV6_CHECKSUM:
		
		switch (op) {
		case PRCO_SETOPT:
			if (m == NULL || m->m_len != sizeof(int)) {
				error = EINVAL;
				break;
			}
			optval = *mtod(m, int *);
			if ((optval % 2) != 0) {
				
				error = EINVAL;
			} else if (so->so_proto->pr_protocol == IPPROTO_ICMPV6) {
				if (optval != icmp6off)
					error = EINVAL;
			} else inp->inp_cksum6 = optval;
			break;

		case PRCO_GETOPT:
			if (so->so_proto->pr_protocol == IPPROTO_ICMPV6)
				optval = icmp6off;
			else optval = inp->inp_cksum6;

			*mp = m = m_get(M_WAIT, MT_SOOPTS);
			m->m_len = sizeof(int);
			*mtod(m, int *) = optval;
			break;

		default:
			error = EINVAL;
			break;
		}
		break;

	default:
		error = ENOPROTOOPT;
		break;
	}

	if (op == PRCO_SETOPT)
		(void)m_free(m);

	return (error);
}


void ip6_initpktopts(struct ip6_pktopts *opt)
{

	bzero(opt, sizeof(*opt));
	opt->ip6po_hlim = -1;	
	opt->ip6po_tclass = -1;	
	opt->ip6po_minmtu = IP6PO_MINMTU_MCASTONLY;
}

int ip6_pcbopt(int optname, u_char *buf, int len, struct ip6_pktopts **pktopt, int priv, int uproto)

{
	struct ip6_pktopts *opt;

	if (*pktopt == NULL) {
		*pktopt = malloc(sizeof(struct ip6_pktopts), M_IP6OPT, M_WAITOK);
		ip6_initpktopts(*pktopt);
	}
	opt = *pktopt;

	return (ip6_setpktopt(optname, buf, len, opt, priv, 1, uproto));
}

int ip6_getpcbopt(struct ip6_pktopts *pktopt, int optname, struct mbuf **mp)
{
	void *optdata = NULL;
	int optdatalen = 0;
	struct ip6_ext *ip6e;
	int error = 0;
	struct in6_pktinfo null_pktinfo;
	int deftclass = 0, on;
	int defminmtu = IP6PO_MINMTU_MCASTONLY;
	struct mbuf *m;

	switch (optname) {
	case IPV6_PKTINFO:
		if (pktopt && pktopt->ip6po_pktinfo)
			optdata = (void *)pktopt->ip6po_pktinfo;
		else {
			
			bzero(&null_pktinfo, sizeof(null_pktinfo));
			optdata = (void *)&null_pktinfo;
		}
		optdatalen = sizeof(struct in6_pktinfo);
		break;
	case IPV6_TCLASS:
		if (pktopt && pktopt->ip6po_tclass >= 0)
			optdata = (void *)&pktopt->ip6po_tclass;
		else optdata = (void *)&deftclass;
		optdatalen = sizeof(int);
		break;
	case IPV6_HOPOPTS:
		if (pktopt && pktopt->ip6po_hbh) {
			optdata = (void *)pktopt->ip6po_hbh;
			ip6e = (struct ip6_ext *)pktopt->ip6po_hbh;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_RTHDR:
		if (pktopt && pktopt->ip6po_rthdr) {
			optdata = (void *)pktopt->ip6po_rthdr;
			ip6e = (struct ip6_ext *)pktopt->ip6po_rthdr;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_RTHDRDSTOPTS:
		if (pktopt && pktopt->ip6po_dest1) {
			optdata = (void *)pktopt->ip6po_dest1;
			ip6e = (struct ip6_ext *)pktopt->ip6po_dest1;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_DSTOPTS:
		if (pktopt && pktopt->ip6po_dest2) {
			optdata = (void *)pktopt->ip6po_dest2;
			ip6e = (struct ip6_ext *)pktopt->ip6po_dest2;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_USE_MIN_MTU:
		if (pktopt)
			optdata = (void *)&pktopt->ip6po_minmtu;
		else optdata = (void *)&defminmtu;
		optdatalen = sizeof(int);
		break;
	case IPV6_DONTFRAG:
		if (pktopt && ((pktopt->ip6po_flags) & IP6PO_DONTFRAG))
			on = 1;
		else on = 0;
		optdata = (void *)&on;
		optdatalen = sizeof(on);
		break;
	default:		

		panic("ip6_getpcbopt: unexpected option");

		return (ENOPROTOOPT);
	}

	if (optdatalen > MCLBYTES)
		return (EMSGSIZE); 
	*mp = m = m_get(M_WAIT, MT_SOOPTS);
	if (optdatalen > MLEN)
		MCLGET(m, M_WAIT);
	m->m_len = optdatalen;
	if (optdatalen)
		bcopy(optdata, mtod(m, void *), optdatalen);

	return (error);
}

void ip6_clearpktopts(struct ip6_pktopts *pktopt, int optname)
{
	if (optname == -1 || optname == IPV6_PKTINFO) {
		if (pktopt->ip6po_pktinfo)
			free(pktopt->ip6po_pktinfo, M_IP6OPT, 0);
		pktopt->ip6po_pktinfo = NULL;
	}
	if (optname == -1 || optname == IPV6_HOPLIMIT)
		pktopt->ip6po_hlim = -1;
	if (optname == -1 || optname == IPV6_TCLASS)
		pktopt->ip6po_tclass = -1;
	if (optname == -1 || optname == IPV6_HOPOPTS) {
		if (pktopt->ip6po_hbh)
			free(pktopt->ip6po_hbh, M_IP6OPT, 0);
		pktopt->ip6po_hbh = NULL;
	}
	if (optname == -1 || optname == IPV6_RTHDRDSTOPTS) {
		if (pktopt->ip6po_dest1)
			free(pktopt->ip6po_dest1, M_IP6OPT, 0);
		pktopt->ip6po_dest1 = NULL;
	}
	if (optname == -1 || optname == IPV6_RTHDR) {
		if (pktopt->ip6po_rhinfo.ip6po_rhi_rthdr)
			free(pktopt->ip6po_rhinfo.ip6po_rhi_rthdr, M_IP6OPT, 0);
		pktopt->ip6po_rhinfo.ip6po_rhi_rthdr = NULL;
		if (pktopt->ip6po_route.ro_rt) {
			rtfree(pktopt->ip6po_route.ro_rt);
			pktopt->ip6po_route.ro_rt = NULL;
		}
	}
	if (optname == -1 || optname == IPV6_DSTOPTS) {
		if (pktopt->ip6po_dest2)
			free(pktopt->ip6po_dest2, M_IP6OPT, 0);
		pktopt->ip6po_dest2 = NULL;
	}
}











int copypktopts(struct ip6_pktopts *dst, struct ip6_pktopts *src, int canwait)
{
	dst->ip6po_hlim = src->ip6po_hlim;
	dst->ip6po_tclass = src->ip6po_tclass;
	dst->ip6po_flags = src->ip6po_flags;
	if (src->ip6po_pktinfo) {
		dst->ip6po_pktinfo = malloc(sizeof(*dst->ip6po_pktinfo), M_IP6OPT, canwait);
		if (dst->ip6po_pktinfo == NULL)
			goto bad;
		*dst->ip6po_pktinfo = *src->ip6po_pktinfo;
	}
	PKTOPT_EXTHDRCPY(ip6po_hbh);
	PKTOPT_EXTHDRCPY(ip6po_dest1);
	PKTOPT_EXTHDRCPY(ip6po_dest2);
	PKTOPT_EXTHDRCPY(ip6po_rthdr); 
	return (0);

  bad:
	ip6_clearpktopts(dst, -1);
	return (ENOBUFS);
}


void ip6_freepcbopts(struct ip6_pktopts *pktopt)
{
	if (pktopt == NULL)
		return;

	ip6_clearpktopts(pktopt, -1);

	free(pktopt, M_IP6OPT, 0);
}


int ip6_setmoptions(int optname, struct ip6_moptions **im6op, struct mbuf *m)
{
	int error = 0;
	u_int loop, ifindex;
	struct ipv6_mreq *mreq;
	struct ifnet *ifp;
	struct ip6_moptions *im6o = *im6op;
	struct in6_multi_mship *imm;
	struct proc *p = curproc;	

	if (im6o == NULL) {
		
		im6o = (struct ip6_moptions *)
			malloc(sizeof(*im6o), M_IPMOPTS, M_WAITOK);

		if (im6o == NULL)
			return (ENOBUFS);
		*im6op = im6o;
		im6o->im6o_ifidx = 0;
		im6o->im6o_hlim = ip6_defmcasthlim;
		im6o->im6o_loop = IPV6_DEFAULT_MULTICAST_LOOP;
		LIST_INIT(&im6o->im6o_memberships);
	}

	switch (optname) {

	case IPV6_MULTICAST_IF:
		
		if (m == NULL || m->m_len != sizeof(u_int)) {
			error = EINVAL;
			break;
		}
		memcpy(&ifindex, mtod(m, u_int *), sizeof(ifindex));
		if (ifindex != 0) {
			ifp = if_get(ifindex);
			if (ifp == NULL) {
				error = ENXIO;	
				break;
			}
			if ((ifp->if_flags & IFF_MULTICAST) == 0) {
				error = EADDRNOTAVAIL;
				if_put(ifp);
				break;
			}
			if_put(ifp);
		}
		im6o->im6o_ifidx = ifindex;
		break;

	case IPV6_MULTICAST_HOPS:
	    {
		
		int optval;
		if (m == NULL || m->m_len != sizeof(int)) {
			error = EINVAL;
			break;
		}
		memcpy(&optval, mtod(m, u_int *), sizeof(optval));
		if (optval < -1 || optval >= 256)
			error = EINVAL;
		else if (optval == -1)
			im6o->im6o_hlim = ip6_defmcasthlim;
		else im6o->im6o_hlim = optval;
		break;
	    }

	case IPV6_MULTICAST_LOOP:
		
		if (m == NULL || m->m_len != sizeof(u_int)) {
			error = EINVAL;
			break;
		}
		memcpy(&loop, mtod(m, u_int *), sizeof(loop));
		if (loop > 1) {
			error = EINVAL;
			break;
		}
		im6o->im6o_loop = loop;
		break;

	case IPV6_JOIN_GROUP:
		
		if (m == NULL || m->m_len != sizeof(struct ipv6_mreq)) {
			error = EINVAL;
			break;
		}
		mreq = mtod(m, struct ipv6_mreq *);
		if (IN6_IS_ADDR_UNSPECIFIED(&mreq->ipv6mr_multiaddr)) {
			
			if (suser(p, 0))
			{
				error = EACCES;
				break;
			}
		} else if (!IN6_IS_ADDR_MULTICAST(&mreq->ipv6mr_multiaddr)) {
			error = EINVAL;
			break;
		}

		
		if (mreq->ipv6mr_interface == 0) {
			struct rtentry *rt;
			struct sockaddr_in6 dst;

			memset(&dst, 0, sizeof(dst));
			dst.sin6_len = sizeof(dst);
			dst.sin6_family = AF_INET6;
			dst.sin6_addr = mreq->ipv6mr_multiaddr;
			rt = rtalloc(sin6tosa(&dst), RT_RESOLVE, m->m_pkthdr.ph_rtableid);
			if (rt == NULL) {
				error = EADDRNOTAVAIL;
				break;
			}
			ifp = if_get(rt->rt_ifidx);
			rtfree(rt);
		} else {
			
			ifp = if_get(mreq->ipv6mr_interface);
			if (ifp == NULL) {
				error = ENXIO;	
				break;
			}
		}

		
		if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0) {
			if_put(ifp);
			error = EADDRNOTAVAIL;
			break;
		}
		
		if (IN6_IS_SCOPE_EMBED(&mreq->ipv6mr_multiaddr)) {
			mreq->ipv6mr_multiaddr.s6_addr16[1] = htons(ifp->if_index);
		}
		
		LIST_FOREACH(imm, &im6o->im6o_memberships, i6mm_chain)
			if (imm->i6mm_maddr->in6m_ifidx == ifp->if_index && IN6_ARE_ADDR_EQUAL(&imm->i6mm_maddr->in6m_addr, &mreq->ipv6mr_multiaddr))

				break;
		if (imm != NULL) {
			if_put(ifp);
			error = EADDRINUSE;
			break;
		}
		
		imm = in6_joingroup(ifp, &mreq->ipv6mr_multiaddr, &error);
		if_put(ifp);
		if (!imm)
			break;
		LIST_INSERT_HEAD(&im6o->im6o_memberships, imm, i6mm_chain);
		break;

	case IPV6_LEAVE_GROUP:
		
		if (m == NULL || m->m_len != sizeof(struct ipv6_mreq)) {
			error = EINVAL;
			break;
		}
		mreq = mtod(m, struct ipv6_mreq *);
		if (IN6_IS_ADDR_UNSPECIFIED(&mreq->ipv6mr_multiaddr)) {
			if (suser(p, 0))
			{
				error = EACCES;
				break;
			}
		} else if (!IN6_IS_ADDR_MULTICAST(&mreq->ipv6mr_multiaddr)) {
			error = EINVAL;
			break;
		}

		
		if (IN6_IS_ADDR_MC_LINKLOCAL(&mreq->ipv6mr_multiaddr)) {
			mreq->ipv6mr_multiaddr.s6_addr16[1] = htons(mreq->ipv6mr_interface);
		}

		
		if (mreq->ipv6mr_interface == 0)
			ifp = NULL;
		else {
			ifp = if_get(mreq->ipv6mr_interface);
			if (ifp == NULL) {
				error = ENXIO;	
				break;
			}
		}

		
		LIST_FOREACH(imm, &im6o->im6o_memberships, i6mm_chain) {
			if ((ifp == NULL || imm->i6mm_maddr->in6m_ifidx == ifp->if_index) && IN6_ARE_ADDR_EQUAL(&imm->i6mm_maddr->in6m_addr, &mreq->ipv6mr_multiaddr))


				break;
		}

		if_put(ifp);

		if (imm == NULL) {
			
			error = EADDRNOTAVAIL;
			break;
		}
		
		LIST_REMOVE(imm, i6mm_chain);
		in6_leavegroup(imm);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	
	if (im6o->im6o_ifidx == 0 && im6o->im6o_hlim == ip6_defmcasthlim && im6o->im6o_loop == IPV6_DEFAULT_MULTICAST_LOOP && LIST_EMPTY(&im6o->im6o_memberships)) {


		free(*im6op, M_IPMOPTS, 0);
		*im6op = NULL;
	}

	return (error);
}


int ip6_getmoptions(int optname, struct ip6_moptions *im6o, struct mbuf **mp)
{
	u_int *hlim, *loop, *ifindex;

	*mp = m_get(M_WAIT, MT_SOOPTS);

	switch (optname) {

	case IPV6_MULTICAST_IF:
		ifindex = mtod(*mp, u_int *);
		(*mp)->m_len = sizeof(u_int);
		if (im6o == NULL || im6o->im6o_ifidx == 0)
			*ifindex = 0;
		else *ifindex = im6o->im6o_ifidx;
		return (0);

	case IPV6_MULTICAST_HOPS:
		hlim = mtod(*mp, u_int *);
		(*mp)->m_len = sizeof(u_int);
		if (im6o == NULL)
			*hlim = ip6_defmcasthlim;
		else *hlim = im6o->im6o_hlim;
		return (0);

	case IPV6_MULTICAST_LOOP:
		loop = mtod(*mp, u_int *);
		(*mp)->m_len = sizeof(u_int);
		if (im6o == NULL)
			*loop = ip6_defmcasthlim;
		else *loop = im6o->im6o_loop;
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}


void ip6_freemoptions(struct ip6_moptions *im6o)
{
	struct in6_multi_mship *imm;

	if (im6o == NULL)
		return;

	while (!LIST_EMPTY(&im6o->im6o_memberships)) {
		imm = LIST_FIRST(&im6o->im6o_memberships);
		LIST_REMOVE(imm, i6mm_chain);
		in6_leavegroup(imm);
	}
	free(im6o, M_IPMOPTS, 0);
}


int ip6_setpktopts(struct mbuf *control, struct ip6_pktopts *opt, struct ip6_pktopts *stickyopt, int priv, int uproto)

{
	u_int clen;
	struct cmsghdr *cm = 0;
	caddr_t cmsgs;
	int error;

	if (control == NULL || opt == NULL)
		return (EINVAL);

	ip6_initpktopts(opt);
	if (stickyopt) {
		int error;

		
		if ((error = copypktopts(opt, stickyopt, M_NOWAIT)) != 0)
			return (error);
	}

	
	if (control->m_next)
		return (EINVAL);

	clen = control->m_len;
	cmsgs = mtod(control, caddr_t);
	do {
		if (clen < CMSG_LEN(0))
			return (EINVAL);
		cm = (struct cmsghdr *)cmsgs;
		if (cm->cmsg_len < CMSG_LEN(0) || cm->cmsg_len > clen || CMSG_ALIGN(cm->cmsg_len) > clen)
			return (EINVAL);
		if (cm->cmsg_level == IPPROTO_IPV6) {
			error = ip6_setpktopt(cm->cmsg_type, CMSG_DATA(cm), cm->cmsg_len - CMSG_LEN(0), opt, priv, 0, uproto);
			if (error)
				return (error);
		}

		clen -= CMSG_ALIGN(cm->cmsg_len);
		cmsgs += CMSG_ALIGN(cm->cmsg_len);
	} while (clen);

	return (0);
}


int ip6_setpktopt(int optname, u_char *buf, int len, struct ip6_pktopts *opt, int priv, int sticky, int uproto)

{
	int minmtupolicy;

	switch (optname) {
	case IPV6_PKTINFO:
	{
		struct ifnet *ifp = NULL;
		struct in6_pktinfo *pktinfo;

		if (len != sizeof(struct in6_pktinfo))
			return (EINVAL);

		pktinfo = (struct in6_pktinfo *)buf;

		
		if (opt->ip6po_pktinfo && pktinfo->ipi6_ifindex == 0 && IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {

			ip6_clearpktopts(opt, optname);
			break;
		}

		if (uproto == IPPROTO_TCP && sticky && !IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
			return (EINVAL);
		}

		if (pktinfo->ipi6_ifindex) {
			ifp = if_get(pktinfo->ipi6_ifindex);
			if (ifp == NULL)
				return (ENXIO);
			if_put(ifp);
		}

		
		if (opt->ip6po_pktinfo == NULL) {
			opt->ip6po_pktinfo = malloc(sizeof(*pktinfo), M_IP6OPT, M_NOWAIT);
			if (opt->ip6po_pktinfo == NULL)
				return (ENOBUFS);
		}
		bcopy(pktinfo, opt->ip6po_pktinfo, sizeof(*pktinfo));
		break;
	}

	case IPV6_HOPLIMIT:
	{
		int *hlimp;

		
		if (sticky)
			return (ENOPROTOOPT);

		if (len != sizeof(int))
			return (EINVAL);
		hlimp = (int *)buf;
		if (*hlimp < -1 || *hlimp > 255)
			return (EINVAL);

		opt->ip6po_hlim = *hlimp;
		break;
	}

	case IPV6_TCLASS:
	{
		int tclass;

		if (len != sizeof(int))
			return (EINVAL);
		tclass = *(int *)buf;
		if (tclass < -1 || tclass > 255)
			return (EINVAL);

		opt->ip6po_tclass = tclass;
		break;
	}
	case IPV6_HOPOPTS:
	{
		struct ip6_hbh *hbh;
		int hbhlen;

		
		if (!priv)
			return (EPERM);

		if (len == 0) {
			ip6_clearpktopts(opt, IPV6_HOPOPTS);
			break;	
		}

		
		if (len < sizeof(struct ip6_hbh))
			return (EINVAL);
		hbh = (struct ip6_hbh *)buf;
		hbhlen = (hbh->ip6h_len + 1) << 3;
		if (len != hbhlen)
			return (EINVAL);

		
		ip6_clearpktopts(opt, IPV6_HOPOPTS);
		opt->ip6po_hbh = malloc(hbhlen, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_hbh == NULL)
			return (ENOBUFS);
		memcpy(opt->ip6po_hbh, hbh, hbhlen);

		break;
	}

	case IPV6_DSTOPTS:
	case IPV6_RTHDRDSTOPTS:
	{
		struct ip6_dest *dest, **newdest = NULL;
		int destlen;

		if (!priv)	
			return (EPERM);

		if (len == 0) {
			ip6_clearpktopts(opt, optname);
			break;	
		}

		
		if (len < sizeof(struct ip6_dest))
			return (EINVAL);
		dest = (struct ip6_dest *)buf;
		destlen = (dest->ip6d_len + 1) << 3;
		if (len != destlen)
			return (EINVAL);
		
		switch (optname) {
		case IPV6_RTHDRDSTOPTS:
			newdest = &opt->ip6po_dest1;
			break;
		case IPV6_DSTOPTS:
			newdest = &opt->ip6po_dest2;
			break;
		}

		
		ip6_clearpktopts(opt, optname);
		*newdest = malloc(destlen, M_IP6OPT, M_NOWAIT);
		if (*newdest == NULL)
			return (ENOBUFS);
		memcpy(*newdest, dest, destlen);

		break;
	}

	case IPV6_RTHDR:
	{
		struct ip6_rthdr *rth;
		int rthlen;

		if (len == 0) {
			ip6_clearpktopts(opt, IPV6_RTHDR);
			break;	
		}

		
		if (len < sizeof(struct ip6_rthdr))
			return (EINVAL);
		rth = (struct ip6_rthdr *)buf;
		rthlen = (rth->ip6r_len + 1) << 3;
		if (len != rthlen)
			return (EINVAL);

		switch (rth->ip6r_type) {
		case IPV6_RTHDR_TYPE_0:
			if (rth->ip6r_len == 0)	
				return (EINVAL);
			if (rth->ip6r_len % 2) 
				return (EINVAL);
			if (rth->ip6r_len / 2 != rth->ip6r_segleft)
				return (EINVAL);
			break;
		default:
			return (EINVAL);	
		}
		
		ip6_clearpktopts(opt, IPV6_RTHDR);
		opt->ip6po_rthdr = malloc(rthlen, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_rthdr == NULL)
			return (ENOBUFS);
		memcpy(opt->ip6po_rthdr, rth, rthlen);
		break;
	}

	case IPV6_USE_MIN_MTU:
		if (len != sizeof(int))
			return (EINVAL);
		minmtupolicy = *(int *)buf;
		if (minmtupolicy != IP6PO_MINMTU_MCASTONLY && minmtupolicy != IP6PO_MINMTU_DISABLE && minmtupolicy != IP6PO_MINMTU_ALL) {

			return (EINVAL);
		}
		opt->ip6po_minmtu = minmtupolicy;
		break;

	case IPV6_DONTFRAG:
		if (len != sizeof(int))
			return (EINVAL);

		if (uproto == IPPROTO_TCP || *(int *)buf == 0) {
			
			opt->ip6po_flags &= ~IP6PO_DONTFRAG;
		} else opt->ip6po_flags |= IP6PO_DONTFRAG;
		break;

	default:
		return (ENOPROTOOPT);
	} 

	return (0);
}


void ip6_mloopback(struct ifnet *ifp, struct mbuf *m, struct sockaddr_in6 *dst)
{
	struct mbuf *copym;
	struct ip6_hdr *ip6;

	
	copym = m_copym(m, 0, M_COPYALL, M_NOWAIT);
	if (copym == NULL)
		return;

	
	if ((copym->m_flags & M_EXT) != 0 || copym->m_len < sizeof(struct ip6_hdr)) {
		copym = m_pullup(copym, sizeof(struct ip6_hdr));
		if (copym == NULL)
			return;
	}


	if (copym->m_len < sizeof(*ip6)) {
		m_freem(copym);
		return;
	}


	ip6 = mtod(copym, struct ip6_hdr *);
	if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src))
		ip6->ip6_src.s6_addr16[1] = 0;
	if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst))
		ip6->ip6_dst.s6_addr16[1] = 0;

	if_input_local(ifp, copym, dst->sin6_family);
}


int ip6_splithdr(struct mbuf *m, struct ip6_exthdrs *exthdrs)
{
	struct mbuf *mh;
	struct ip6_hdr *ip6;

	ip6 = mtod(m, struct ip6_hdr *);
	if (m->m_len > sizeof(*ip6)) {
		MGETHDR(mh, M_DONTWAIT, MT_HEADER);
		if (mh == NULL) {
			m_freem(m);
			return ENOBUFS;
		}
		M_MOVE_PKTHDR(mh, m);
		MH_ALIGN(mh, sizeof(*ip6));
		m->m_len -= sizeof(*ip6);
		m->m_data += sizeof(*ip6);
		mh->m_next = m;
		m = mh;
		m->m_len = sizeof(*ip6);
		bcopy((caddr_t)ip6, mtod(m, caddr_t), sizeof(*ip6));
	}
	exthdrs->ip6e_ip6 = m;
	return 0;
}

u_int32_t ip6_randomid(void)
{
	return idgen32(&ip6_id_ctx);
}

void ip6_randomid_init(void)
{
	idgen32_init(&ip6_id_ctx);
}


static __inline u_int16_t __attribute__((__unused__))
in6_cksum_phdr(const struct in6_addr *src, const struct in6_addr *dst, u_int32_t len, u_int32_t nxt)
{
	u_int32_t sum = 0;
	const u_int16_t *w;

	w = (const u_int16_t *) src;
	sum += w[0];
	if (!IN6_IS_SCOPE_EMBED(src))
		sum += w[1];
	sum += w[2]; sum += w[3]; sum += w[4]; sum += w[5];
	sum += w[6]; sum += w[7];

	w = (const u_int16_t *) dst;
	sum += w[0];
	if (!IN6_IS_SCOPE_EMBED(dst))
		sum += w[1];
	sum += w[2]; sum += w[3]; sum += w[4]; sum += w[5];
	sum += w[6]; sum += w[7];

	sum += (u_int16_t)(len >> 16) + (u_int16_t)(len );

	sum += (u_int16_t)(nxt >> 16) + (u_int16_t)(nxt );

	sum = (u_int16_t)(sum >> 16) + (u_int16_t)(sum );

	if (sum > 0xffff)
		sum -= 0xffff;

	return (sum);
}


void in6_delayed_cksum(struct mbuf *m, u_int8_t nxt)
{
	int nxtp, offset;
	u_int16_t csum;

	offset = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxtp);
	if (offset <= 0 || nxtp != nxt)
		
		return;
	csum = (u_int16_t)(in6_cksum(m, 0, offset, m->m_pkthdr.len - offset));

	switch (nxt) {
	case IPPROTO_TCP:
		offset += offsetof(struct tcphdr, th_sum);
		break;

	case IPPROTO_UDP:
		offset += offsetof(struct udphdr, uh_sum);
		if (csum == 0)
			csum = 0xffff;
		break;

	case IPPROTO_ICMPV6:
		offset += offsetof(struct icmp6_hdr, icmp6_cksum);
		break;
	}

	if ((offset + sizeof(u_int16_t)) > m->m_len)
		m_copyback(m, offset, sizeof(csum), &csum, M_NOWAIT);
	else *(u_int16_t *)(mtod(m, caddr_t) + offset) = csum;
}

void in6_proto_cksum_out(struct mbuf *m, struct ifnet *ifp)
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);

	
	if (m->m_pkthdr.csum_flags & (M_TCP_CSUM_OUT|M_UDP_CSUM_OUT|M_ICMP_CSUM_OUT)) {
		int nxt, offset;
		u_int16_t csum;

		offset = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
		csum = in6_cksum_phdr(&ip6->ip6_src, &ip6->ip6_dst, htonl(m->m_pkthdr.len - offset), htonl(nxt));
		if (nxt == IPPROTO_TCP)
			offset += offsetof(struct tcphdr, th_sum);
		else if (nxt == IPPROTO_UDP)
			offset += offsetof(struct udphdr, uh_sum);
		else if (nxt == IPPROTO_ICMPV6)
			offset += offsetof(struct icmp6_hdr, icmp6_cksum);
		if ((offset + sizeof(u_int16_t)) > m->m_len)
			m_copyback(m, offset, sizeof(csum), &csum, M_NOWAIT);
		else *(u_int16_t *)(mtod(m, caddr_t) + offset) = csum;
	}

	if (m->m_pkthdr.csum_flags & M_TCP_CSUM_OUT) {
		if (!ifp || !(ifp->if_capabilities & IFCAP_CSUM_TCPv6) || ip6->ip6_nxt != IPPROTO_TCP || ifp->if_bridgeport != NULL) {

			tcpstat.tcps_outswcsum++;
			in6_delayed_cksum(m, IPPROTO_TCP);
			m->m_pkthdr.csum_flags &= ~M_TCP_CSUM_OUT; 
		}
	} else if (m->m_pkthdr.csum_flags & M_UDP_CSUM_OUT) {
		if (!ifp || !(ifp->if_capabilities & IFCAP_CSUM_UDPv6) || ip6->ip6_nxt != IPPROTO_UDP || ifp->if_bridgeport != NULL) {

			udpstat_inc(udps_outswcsum);
			in6_delayed_cksum(m, IPPROTO_UDP);
			m->m_pkthdr.csum_flags &= ~M_UDP_CSUM_OUT; 
		}
	} else if (m->m_pkthdr.csum_flags & M_ICMP_CSUM_OUT) {
		in6_delayed_cksum(m, IPPROTO_ICMPV6);
		m->m_pkthdr.csum_flags &= ~M_ICMP_CSUM_OUT; 
	}
}


struct tdb * ip6_output_ipsec_lookup(struct mbuf *m, int *error, struct inpcb *inp)
{
	struct tdb *tdb;
	struct m_tag *mtag;
	struct tdb_ident *tdbi;

	

	
	tdb = ipsp_spd_lookup(m, AF_INET6, sizeof(struct ip6_hdr), error, IPSP_DIRECTION_OUT, NULL, inp, 0);

	if (tdb == NULL)
		return NULL;
	
	for (mtag = m_tag_first(m); mtag != NULL; mtag = m_tag_next(m, mtag)) {
		if (mtag->m_tag_id != PACKET_TAG_IPSEC_OUT_DONE)
			continue;
		tdbi = (struct tdb_ident *)(mtag + 1);
		if (tdbi->spi == tdb->tdb_spi && tdbi->proto == tdb->tdb_sproto && tdbi->rdomain == tdb->tdb_rdomain && !memcmp(&tdbi->dst, &tdb->tdb_dst, sizeof(union sockaddr_union))) {



			
			return NULL;
		}
	}
	return tdb;
}

int ip6_output_ipsec_send(struct tdb *tdb, struct mbuf *m, int tunalready, int fwd)
{

	struct ifnet *encif;



	if ((encif = enc_getif(tdb->tdb_rdomain, tdb->tdb_tap)) == NULL || pf_test(AF_INET6, fwd ? PF_FWD : PF_OUT, encif, &m) != PF_PASS) {
		m_freem(m);
		return EHOSTUNREACH;
	}
	if (m == NULL)
		return 0;
	
	in6_proto_cksum_out(m, encif);

	m->m_flags &= ~(M_BCAST | M_MCAST);	

	
	return ipsp_process_packet(m, tdb, AF_INET6, tunalready);
}

