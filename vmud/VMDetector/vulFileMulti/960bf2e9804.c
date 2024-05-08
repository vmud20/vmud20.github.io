















































struct icmp6stat icmp6stat;

extern struct inpcbtable rawin6pcbtable;
extern int icmp6errppslim;
static int icmp6errpps_count = 0;
static struct timeval icmp6errppslim_last;


struct icmp6_mtudisc_callback {
	LIST_ENTRY(icmp6_mtudisc_callback) mc_list;
	void (*mc_func)(struct sockaddr_in6 *, u_int);
};

LIST_HEAD(, icmp6_mtudisc_callback) icmp6_mtudisc_callbacks = LIST_HEAD_INITIALIZER(icmp6_mtudisc_callbacks);

struct rttimer_queue *icmp6_mtudisc_timeout_q = NULL;


static int icmp6_mtudisc_hiwat = 1280;
static int icmp6_mtudisc_lowat = 256;


static struct rttimer_queue *icmp6_redirect_timeout_q = NULL;


static int icmp6_redirect_lowat = -1;

void	icmp6_errcount(struct icmp6errstat *, int, int);
int	icmp6_rip6_input(struct mbuf **, int);
int	icmp6_ratelimit(const struct in6_addr *, const int, const int);
const char *icmp6_redirect_diag(struct in6_addr *, struct in6_addr *, struct in6_addr *);
int	icmp6_notify_error(struct mbuf *, int, int, int);
struct rtentry *icmp6_mtudisc_clone(struct sockaddr *, u_int);
void	icmp6_mtudisc_timeout(struct rtentry *, struct rttimer *);
void	icmp6_redirect_timeout(struct rtentry *, struct rttimer *);

void icmp6_init(void)
{
	mld6_init();
	icmp6_mtudisc_timeout_q = rt_timer_queue_create(ip6_mtudisc_timeout);
	icmp6_redirect_timeout_q = rt_timer_queue_create(icmp6_redirtimeout);
}

void icmp6_errcount(struct icmp6errstat *stat, int type, int code)
{
	switch (type) {
	case ICMP6_DST_UNREACH:
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			stat->icp6errs_dst_unreach_noroute++;
			return;
		case ICMP6_DST_UNREACH_ADMIN:
			stat->icp6errs_dst_unreach_admin++;
			return;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			stat->icp6errs_dst_unreach_beyondscope++;
			return;
		case ICMP6_DST_UNREACH_ADDR:
			stat->icp6errs_dst_unreach_addr++;
			return;
		case ICMP6_DST_UNREACH_NOPORT:
			stat->icp6errs_dst_unreach_noport++;
			return;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		stat->icp6errs_packet_too_big++;
		return;
	case ICMP6_TIME_EXCEEDED:
		switch (code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			stat->icp6errs_time_exceed_transit++;
			return;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			stat->icp6errs_time_exceed_reassembly++;
			return;
		}
		break;
	case ICMP6_PARAM_PROB:
		switch (code) {
		case ICMP6_PARAMPROB_HEADER:
			stat->icp6errs_paramprob_header++;
			return;
		case ICMP6_PARAMPROB_NEXTHEADER:
			stat->icp6errs_paramprob_nextheader++;
			return;
		case ICMP6_PARAMPROB_OPTION:
			stat->icp6errs_paramprob_option++;
			return;
		}
		break;
	case ND_REDIRECT:
		stat->icp6errs_redirect++;
		return;
	}
	stat->icp6errs_unknown++;
}


void icmp6_mtudisc_callback_register(void (*func)(struct sockaddr_in6 *, u_int))
{
	struct icmp6_mtudisc_callback *mc;

	LIST_FOREACH(mc, &icmp6_mtudisc_callbacks, mc_list) {
		if (mc->mc_func == func)
			return;
	}

	mc = malloc(sizeof(*mc), M_PCB, M_NOWAIT);
	if (mc == NULL)
		panic("icmp6_mtudisc_callback_register");

	mc->mc_func = func;
	LIST_INSERT_HEAD(&icmp6_mtudisc_callbacks, mc, mc_list);
}


void icmp6_error(struct mbuf *m, int type, int code, int param)
{
	struct ip6_hdr *oip6, *nip6;
	struct icmp6_hdr *icmp6;
	u_int preplen;
	int off;
	int nxt;

	icmp6stat.icp6s_error++;

	
	icmp6_errcount(&icmp6stat.icp6s_outerrhist, type, code);

	if (m->m_len < sizeof(struct ip6_hdr)) {
		m = m_pullup(m, sizeof(struct ip6_hdr));
		if (m == NULL)
			return;
	}
	oip6 = mtod(m, struct ip6_hdr *);

	
	if ((m->m_flags & (M_BCAST|M_MCAST) || IN6_IS_ADDR_MULTICAST(&oip6->ip6_dst)) && (type != ICMP6_PACKET_TOO_BIG && (type != ICMP6_PARAM_PROB || code != ICMP6_PARAMPROB_OPTION)))



		goto freeit;

	
	if (IN6_IS_ADDR_UNSPECIFIED(&oip6->ip6_src) || IN6_IS_ADDR_MULTICAST(&oip6->ip6_src))
		goto freeit;

	
	nxt = -1;
	off = ip6_lasthdr(m, 0, IPPROTO_IPV6, &nxt);
	if (off >= 0 && nxt == IPPROTO_ICMPV6) {
		struct icmp6_hdr *icp;

		IP6_EXTHDR_GET(icp, struct icmp6_hdr *, m, off, sizeof(*icp));
		if (icp == NULL) {
			icmp6stat.icp6s_tooshort++;
			return;
		}
		if (icp->icmp6_type < ICMP6_ECHO_REQUEST || icp->icmp6_type == ND_REDIRECT) {
			
			icmp6stat.icp6s_canterror++;
			goto freeit;
		} else {
			
		}
	}
	else {
		
	}

	oip6 = mtod(m, struct ip6_hdr *); 

	
	if (icmp6_ratelimit(&oip6->ip6_src, type, code)) {
		icmp6stat.icp6s_toofreq++;
		goto freeit;
	}

	

	if (m->m_pkthdr.len >= ICMPV6_PLD_MAXLEN)
		m_adj(m, ICMPV6_PLD_MAXLEN - m->m_pkthdr.len);

	preplen = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
	M_PREPEND(m, preplen, M_DONTWAIT);
	if (m && m->m_len < preplen)
		m = m_pullup(m, preplen);
	if (m == NULL) {
		nd6log((LOG_DEBUG, "ENOBUFS in icmp6_error %d\n", __LINE__));
		return;
	}

	nip6 = mtod(m, struct ip6_hdr *);
	nip6->ip6_src  = oip6->ip6_src;
	nip6->ip6_dst  = oip6->ip6_dst;

	if (IN6_IS_SCOPE_EMBED(&oip6->ip6_src))
		oip6->ip6_src.s6_addr16[1] = 0;
	if (IN6_IS_SCOPE_EMBED(&oip6->ip6_dst))
		oip6->ip6_dst.s6_addr16[1] = 0;

	icmp6 = (struct icmp6_hdr *)(nip6 + 1);
	icmp6->icmp6_type = type;
	icmp6->icmp6_code = code;
	icmp6->icmp6_pptr = htonl((u_int32_t)param);

	
	m->m_pkthdr.ph_ifidx = 0;

	icmp6stat.icp6s_outhist[type]++;
	icmp6_reflect(m, sizeof(struct ip6_hdr)); 

	return;

  freeit:
	
	m_freem(m);
}


int icmp6_input(struct mbuf **mp, int *offp, int proto)
{

	struct ifnet *ifp;

	struct mbuf *m = *mp, *n;
	struct ip6_hdr *ip6, *nip6;
	struct icmp6_hdr *icmp6, *nicmp6;
	int off = *offp;
	int icmp6len = m->m_pkthdr.len - *offp;
	int code, sum, noff;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

	

	ip6 = mtod(m, struct ip6_hdr *);
	if (icmp6len < sizeof(struct icmp6_hdr)) {
		icmp6stat.icp6s_tooshort++;
		goto freeit;
	}

	
	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6));
	if (icmp6 == NULL) {
		icmp6stat.icp6s_tooshort++;
		return IPPROTO_DONE;
	}
	code = icmp6->icmp6_code;

	if ((sum = in6_cksum(m, IPPROTO_ICMPV6, off, icmp6len)) != 0) {
		nd6log((LOG_ERR, "ICMP6 checksum error(%d|%x) %s\n", icmp6->icmp6_type, sum, inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src))));


		icmp6stat.icp6s_checksum++;
		goto freeit;
	}


	if (m->m_pkthdr.pf.flags & PF_TAG_DIVERTED) {
		switch (icmp6->icmp6_type) {
		
		case ICMP6_DST_UNREACH:
		case ICMP6_PACKET_TOO_BIG:
		case ICMP6_TIME_EXCEEDED:
		case ICMP6_PARAM_PROB:
			break;
		default:
			goto raw;
		}
	}



	ifp = if_get(m->m_pkthdr.ph_ifidx);
	if (ifp == NULL)
		goto freeit;

	if (ifp->if_type == IFT_CARP && icmp6->icmp6_type == ICMP6_ECHO_REQUEST && carp_lsdrop(m, AF_INET6, ip6->ip6_src.s6_addr32, ip6->ip6_dst.s6_addr32)) {


		if_put(ifp);
		goto freeit;
	}

	if_put(ifp);

	icmp6stat.icp6s_inhist[icmp6->icmp6_type]++;

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			code = PRC_UNREACH_NET;
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			code = PRC_UNREACH_PROTOCOL; 
			break;
		case ICMP6_DST_UNREACH_ADDR:
			code = PRC_HOSTDEAD;
			break;

		case ICMP6_DST_UNREACH_NOTNEIGHBOR:
			code = PRC_UNREACH_SRCFAIL;
			break;

		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			
			code = PRC_PARAMPROB;
			break;

		case ICMP6_DST_UNREACH_NOPORT:
			code = PRC_UNREACH_PORT;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_PACKET_TOO_BIG:
		
		code = PRC_MSGSIZE;

		
		goto deliver;

	case ICMP6_TIME_EXCEEDED:
		switch (code) {
		case ICMP6_TIME_EXCEED_TRANSIT:
			code = PRC_TIMXCEED_INTRANS;
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			code = PRC_TIMXCEED_REASS;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_PARAM_PROB:
		switch (code) {
		case ICMP6_PARAMPROB_NEXTHEADER:
			code = PRC_UNREACH_PROTOCOL;
			break;
		case ICMP6_PARAMPROB_HEADER:
		case ICMP6_PARAMPROB_OPTION:
			code = PRC_PARAMPROB;
			break;
		default:
			goto badcode;
		}
		goto deliver;

	case ICMP6_ECHO_REQUEST:
		if (code != 0)
			goto badcode;
		
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			
			n = m;
			m = NULL;
			goto deliverecho;
		}
		
		if ((n->m_flags & M_EXT) != 0 || n->m_len < off + sizeof(struct icmp6_hdr)) {
			struct mbuf *n0 = n;
			const int maxlen = sizeof(*nip6) + sizeof(*nicmp6);

			
			if (maxlen >= MCLBYTES) {
				
				m_freem(n0);
				break;
			}
			MGETHDR(n, M_DONTWAIT, n0->m_type);
			if (n && maxlen >= MHLEN) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_free(n);
					n = NULL;
				}
			}
			if (n == NULL) {
				
				m_freem(n0);
				n = m;
				m = NULL;
				goto deliverecho;
			}
			M_MOVE_PKTHDR(n, n0);
			
			nip6 = mtod(n, struct ip6_hdr *);
			bcopy(ip6, nip6, sizeof(struct ip6_hdr));
			nicmp6 = (struct icmp6_hdr *)(nip6 + 1);
			bcopy(icmp6, nicmp6, sizeof(struct icmp6_hdr));
			noff = sizeof(struct ip6_hdr);
			n->m_len = noff + sizeof(struct icmp6_hdr);
			
			n->m_pkthdr.len += noff + sizeof(struct icmp6_hdr);
			n->m_pkthdr.len -= (off + sizeof(struct icmp6_hdr));
			m_adj(n0, off + sizeof(struct icmp6_hdr));
			n->m_next = n0;
		} else {
	 deliverecho:
			IP6_EXTHDR_GET(nicmp6, struct icmp6_hdr *, n, off, sizeof(*nicmp6));
			noff = off;
		}
		nicmp6->icmp6_type = ICMP6_ECHO_REPLY;
		nicmp6->icmp6_code = 0;
		if (n) {
			icmp6stat.icp6s_reflect++;
			icmp6stat.icp6s_outhist[ICMP6_ECHO_REPLY]++;
			icmp6_reflect(n, noff);
		}
		if (!m)
			goto freeit;
		break;

	case ICMP6_ECHO_REPLY:
		if (code != 0)
			goto badcode;
		break;

	case MLD_LISTENER_QUERY:
	case MLD_LISTENER_REPORT:
		if (icmp6len < sizeof(struct mld_hdr))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			
			mld6_input(m, off);
			m = NULL;
			goto freeit;
		}
		mld6_input(n, off);
		
		break;

	case MLD_LISTENER_DONE:
		if (icmp6len < sizeof(struct mld_hdr))	
			goto badlen;
		break;		

	case MLD_MTRACE_RESP:
	case MLD_MTRACE:
		
		
		break;		

	case ICMP6_WRUREQUEST:	
		
		break;
	case ICMP6_WRUREPLY:
		break;

	case ND_ROUTER_SOLICIT:
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_router_solicit))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			
			nd6_rs_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_rs_input(n, off, icmp6len);
		
		break;

	case ND_ROUTER_ADVERT:
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_router_advert))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			
			nd6_ra_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_ra_input(n, off, icmp6len);
		
		break;

	case ND_NEIGHBOR_SOLICIT:
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_neighbor_solicit))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			
			nd6_ns_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_ns_input(n, off, icmp6len);
		
		break;

	case ND_NEIGHBOR_ADVERT:
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_neighbor_advert))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			
			nd6_na_input(m, off, icmp6len);
			m = NULL;
			goto freeit;
		}
		nd6_na_input(n, off, icmp6len);
		
		break;

	case ND_REDIRECT:
		if (code != 0)
			goto badcode;
		if (icmp6len < sizeof(struct nd_redirect))
			goto badlen;
		if ((n = m_copym(m, 0, M_COPYALL, M_DONTWAIT)) == NULL) {
			
			icmp6_redirect_input(m, off);
			m = NULL;
			goto freeit;
		}
		icmp6_redirect_input(n, off);
		
		break;

	case ICMP6_ROUTER_RENUMBERING:
		if (code != ICMP6_ROUTER_RENUMBERING_COMMAND && code != ICMP6_ROUTER_RENUMBERING_RESULT)
			goto badcode;
		if (icmp6len < sizeof(struct icmp6_router_renum))
			goto badlen;
		break;

	default:
		nd6log((LOG_DEBUG, "icmp6_input: unknown type %d(src=%s, dst=%s, ifid=%u)\n", icmp6->icmp6_type, inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src)), inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst)), m->m_pkthdr.ph_ifidx));




		if (icmp6->icmp6_type < ICMP6_ECHO_REQUEST) {
			
			code = PRC_NCMDS;
			
		} else {
			
			break;
		}
deliver:
		if (icmp6_notify_error(m, off, icmp6len, code)) {
			
			return (IPPROTO_DONE);
		}
		break;

badcode:
		icmp6stat.icp6s_badcode++;
		break;

badlen:
		icmp6stat.icp6s_badlen++;
		break;
	}


raw:

	
	icmp6_rip6_input(&m, *offp);

	return IPPROTO_DONE;

 freeit:
	m_freem(m);
	return IPPROTO_DONE;
}

int icmp6_notify_error(struct mbuf *m, int off, int icmp6len, int code)
{
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *eip6;
	u_int32_t notifymtu;
	struct sockaddr_in6 icmp6src, icmp6dst;

	if (icmp6len < sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr)) {
		icmp6stat.icp6s_tooshort++;
		goto freeit;
	}
	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6) + sizeof(struct ip6_hdr));
	if (icmp6 == NULL) {
		icmp6stat.icp6s_tooshort++;
		return (-1);
	}
	eip6 = (struct ip6_hdr *)(icmp6 + 1);

	
	{
		void (*ctlfunc)(int, struct sockaddr *, u_int, void *);
		u_int8_t nxt = eip6->ip6_nxt;
		int eoff = off + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr);
		struct ip6ctlparam ip6cp;
		struct in6_addr *finaldst = NULL;
		int icmp6type = icmp6->icmp6_type;
		struct ip6_frag *fh;
		struct ip6_rthdr *rth;
		struct ip6_rthdr0 *rth0;
		int rthlen;

		while (1) { 
			struct ip6_ext *eh;

			switch (nxt) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_DSTOPTS:
			case IPPROTO_AH:
				IP6_EXTHDR_GET(eh, struct ip6_ext *, m, eoff, sizeof(*eh));
				if (eh == NULL) {
					icmp6stat.icp6s_tooshort++;
					return (-1);
				}

				if (nxt == IPPROTO_AH)
					eoff += (eh->ip6e_len + 2) << 2;
				else eoff += (eh->ip6e_len + 1) << 3;
				nxt = eh->ip6e_nxt;
				break;
			case IPPROTO_ROUTING:
				
				IP6_EXTHDR_GET(rth, struct ip6_rthdr *, m, eoff, sizeof(*rth));
				if (rth == NULL) {
					icmp6stat.icp6s_tooshort++;
					return (-1);
				}
				rthlen = (rth->ip6r_len + 1) << 3;
				
				if (rth->ip6r_segleft && rth->ip6r_type == IPV6_RTHDR_TYPE_0) {
					int hops;

					IP6_EXTHDR_GET(rth0, struct ip6_rthdr0 *, m, eoff, rthlen);

					if (rth0 == NULL) {
						icmp6stat.icp6s_tooshort++;
						return (-1);
					}
					
					if ((rth0->ip6r0_len % 2) == 0 && (hops = rth0->ip6r0_len/2))
						finaldst = (struct in6_addr *)(rth0 + 1) + (hops - 1);
				}
				eoff += rthlen;
				nxt = rth->ip6r_nxt;
				break;
			case IPPROTO_FRAGMENT:
				IP6_EXTHDR_GET(fh, struct ip6_frag *, m, eoff, sizeof(*fh));
				if (fh == NULL) {
					icmp6stat.icp6s_tooshort++;
					return (-1);
				}
				
				if (fh->ip6f_offlg & IP6F_OFF_MASK)
					goto notify;

				eoff += sizeof(struct ip6_frag);
				nxt = fh->ip6f_nxt;
				break;
			default:
				
				goto notify;
			}
		}
	  notify:
		IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6) + sizeof(struct ip6_hdr));
		if (icmp6 == NULL) {
			icmp6stat.icp6s_tooshort++;
			return (-1);
		}

		eip6 = (struct ip6_hdr *)(icmp6 + 1);
		bzero(&icmp6dst, sizeof(icmp6dst));
		icmp6dst.sin6_len = sizeof(struct sockaddr_in6);
		icmp6dst.sin6_family = AF_INET6;
		if (finaldst == NULL)
			icmp6dst.sin6_addr = eip6->ip6_dst;
		else icmp6dst.sin6_addr = *finaldst;
		icmp6dst.sin6_scope_id = in6_addr2scopeid(m->m_pkthdr.ph_ifidx, &icmp6dst.sin6_addr);
		if (in6_embedscope(&icmp6dst.sin6_addr, &icmp6dst, NULL)) {
			
			nd6log((LOG_DEBUG, "icmp6_notify_error: in6_embedscope failed\n"));
			goto freeit;
		}

		
		bzero(&icmp6src, sizeof(icmp6src));
		icmp6src.sin6_len = sizeof(struct sockaddr_in6);
		icmp6src.sin6_family = AF_INET6;
		icmp6src.sin6_addr = eip6->ip6_src;
		icmp6src.sin6_scope_id = in6_addr2scopeid(m->m_pkthdr.ph_ifidx, &icmp6src.sin6_addr);
		if (in6_embedscope(&icmp6src.sin6_addr, &icmp6src, NULL)) {
			
			nd6log((LOG_DEBUG, "icmp6_notify_error: in6_embedscope failed\n"));
			goto freeit;
		}
		icmp6src.sin6_flowinfo = (eip6->ip6_flow & IPV6_FLOWLABEL_MASK);

		if (finaldst == NULL)
			finaldst = &eip6->ip6_dst;
		ip6cp.ip6c_m = m;
		ip6cp.ip6c_icmp6 = icmp6;
		ip6cp.ip6c_ip6 = (struct ip6_hdr *)(icmp6 + 1);
		ip6cp.ip6c_off = eoff;
		ip6cp.ip6c_finaldst = finaldst;
		ip6cp.ip6c_src = &icmp6src;
		ip6cp.ip6c_nxt = nxt;

		pf_pkt_addr_changed(m);


		if (icmp6type == ICMP6_PACKET_TOO_BIG) {
			notifymtu = ntohl(icmp6->icmp6_mtu);
			ip6cp.ip6c_cmdarg = (void *)&notifymtu;
		}

		ctlfunc = inet6sw[ip6_protox[nxt]].pr_ctlinput;
		if (ctlfunc)
			(*ctlfunc)(code, sin6tosa(&icmp6dst), m->m_pkthdr.ph_rtableid, &ip6cp);
	}
	return (0);

  freeit:
	m_freem(m);
	return (-1);
}

void icmp6_mtudisc_update(struct ip6ctlparam *ip6cp, int validated)
{
	unsigned long rtcount;
	struct icmp6_mtudisc_callback *mc;
	struct in6_addr *dst = ip6cp->ip6c_finaldst;
	struct icmp6_hdr *icmp6 = ip6cp->ip6c_icmp6;
	struct mbuf *m = ip6cp->ip6c_m;	
	u_int mtu = ntohl(icmp6->icmp6_mtu);
	struct rtentry *rt = NULL;
	struct sockaddr_in6 sin6;

	
	if (mtu < IPV6_MMTU - sizeof(struct ip6_frag))
		return;

	
	rtcount = rt_timer_queue_count(icmp6_mtudisc_timeout_q);
	if (validated) {
		if (0 <= icmp6_mtudisc_hiwat && rtcount > icmp6_mtudisc_hiwat)
			return;
		else if (0 <= icmp6_mtudisc_lowat && rtcount > icmp6_mtudisc_lowat) {
			
		}
	} else {
		if (0 <= icmp6_mtudisc_lowat && rtcount > icmp6_mtudisc_lowat)
			return;
	}

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = PF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_addr = *dst;
	
	if (IN6_IS_ADDR_LINKLOCAL(dst)) {
		sin6.sin6_addr.s6_addr16[1] = htons(m->m_pkthdr.ph_ifidx);
	}
	sin6.sin6_scope_id = in6_addr2scopeid(m->m_pkthdr.ph_ifidx, &sin6.sin6_addr);

	rt = icmp6_mtudisc_clone(sin6tosa(&sin6), m->m_pkthdr.ph_rtableid);

	if (rt != NULL && ISSET(rt->rt_flags, RTF_HOST) && !(rt->rt_rmx.rmx_locks & RTV_MTU) && (rt->rt_rmx.rmx_mtu > mtu || rt->rt_rmx.rmx_mtu == 0)) {

		struct ifnet *ifp;

		ifp = if_get(rt->rt_ifidx);
		if (ifp != NULL && mtu < ifp->if_mtu) {
			icmp6stat.icp6s_pmtuchg++;
			rt->rt_rmx.rmx_mtu = mtu;
		}
		if_put(ifp);
	}
	rtfree(rt);

	
	LIST_FOREACH(mc, &icmp6_mtudisc_callbacks, mc_list)
		(*mc->mc_func)(&sin6, m->m_pkthdr.ph_rtableid);
}


int icmp6_rip6_input(struct mbuf **mp, int off)
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct inpcb *in6p;
	struct inpcb *last = NULL;
	struct sockaddr_in6 rip6src;
	struct icmp6_hdr *icmp6;
	struct mbuf *opts = NULL;

	IP6_EXTHDR_GET(icmp6, struct icmp6_hdr *, m, off, sizeof(*icmp6));
	if (icmp6 == NULL) {
		
		return IPPROTO_DONE;
	}

	bzero(&rip6src, sizeof(rip6src));
	rip6src.sin6_len = sizeof(struct sockaddr_in6);
	rip6src.sin6_family = AF_INET6;
	
	in6_recoverscope(&rip6src, &ip6->ip6_src);

	TAILQ_FOREACH(in6p, &rawin6pcbtable.inpt_queue, inp_queue) {
		if (!(in6p->inp_flags & INP_IPV6))
			continue;
		if (in6p->inp_ipv6.ip6_nxt != IPPROTO_ICMPV6)
			continue;

		if (m->m_pkthdr.pf.flags & PF_TAG_DIVERTED) {
			struct pf_divert *divert;

			
			if ((divert = pf_find_divert(m)) == NULL)
				continue;
			if (IN6_IS_ADDR_UNSPECIFIED(&divert->addr.v6))
				goto divert_reply;
			if (!IN6_ARE_ADDR_EQUAL(&in6p->inp_laddr6, &divert->addr.v6))
				continue;
		} else divert_reply:

		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->inp_laddr6) && !IN6_ARE_ADDR_EQUAL(&in6p->inp_laddr6, &ip6->ip6_dst))
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->inp_faddr6) && !IN6_ARE_ADDR_EQUAL(&in6p->inp_faddr6, &ip6->ip6_src))
			continue;
		if (in6p->inp_icmp6filt && ICMP6_FILTER_WILLBLOCK(icmp6->icmp6_type, in6p->inp_icmp6filt))

			continue;
		if (last) {
			struct	mbuf *n;
			if ((n = m_copym(m, 0, M_COPYALL, M_NOWAIT)) != NULL) {
				if (last->inp_flags & IN6P_CONTROLOPTS)
					ip6_savecontrol(last, n, &opts);
				
				m_adj(n, off);
				if (sbappendaddr(&last->inp_socket->so_rcv, sin6tosa(&rip6src), n, opts) == 0) {
					
					m_freem(n);
					m_freem(opts);
				} else sorwakeup(last->inp_socket);
				opts = NULL;
			}
		}
		last = in6p;
	}
	if (last) {
		if (last->inp_flags & IN6P_CONTROLOPTS)
			ip6_savecontrol(last, m, &opts);
		
		m_adj(m, off);
		if (sbappendaddr(&last->inp_socket->so_rcv, sin6tosa(&rip6src), m, opts) == 0) {
			m_freem(m);
			m_freem(opts);
		} else sorwakeup(last->inp_socket);
	} else {
		m_freem(m);
		ip6stat.ip6s_delivered--;
	}
	return IPPROTO_DONE;
}


void icmp6_reflect(struct mbuf *m, size_t off)
{
	struct rtentry *rt = NULL;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct in6_ifaddr *ia6;
	struct in6_addr t, *src = NULL;
	struct sockaddr_in6 sa6_src, sa6_dst;

	
	if (off < sizeof(struct ip6_hdr)) {
		nd6log((LOG_DEBUG, "sanity fail: off=%lx, sizeof(ip6)=%lx in %s:%d\n", (u_long)off, (u_long)sizeof(struct ip6_hdr), __FILE__, __LINE__));


		goto bad;
	}

	

	if (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) > MHLEN)
		panic("assumption failed in icmp6_reflect");

	if (off > sizeof(struct ip6_hdr)) {
		size_t l;
		struct ip6_hdr nip6;

		l = off - sizeof(struct ip6_hdr);
		m_copydata(m, 0, sizeof(nip6), (caddr_t)&nip6);
		m_adj(m, l);
		l = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
		if (m->m_len < l) {
			if ((m = m_pullup(m, l)) == NULL)
				return;
		}
		bcopy((caddr_t)&nip6, mtod(m, caddr_t), sizeof(nip6));
	} else  {
		size_t l;
		l = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
		if (m->m_len < l) {
			if ((m = m_pullup(m, l)) == NULL)
				return;
		}
	}
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	icmp6 = (struct icmp6_hdr *)(ip6 + 1);

	t = ip6->ip6_dst;
	
	ip6->ip6_dst = ip6->ip6_src;

	
	bzero(&sa6_src, sizeof(sa6_src));
	sa6_src.sin6_family = AF_INET6;
	sa6_src.sin6_len = sizeof(sa6_src);
	sa6_src.sin6_addr = ip6->ip6_dst;
	in6_recoverscope(&sa6_src, &ip6->ip6_dst);
	in6_embedscope(&ip6->ip6_dst, &sa6_src, NULL);
	bzero(&sa6_dst, sizeof(sa6_dst));
	sa6_dst.sin6_family = AF_INET6;
	sa6_dst.sin6_len = sizeof(sa6_dst);
	sa6_dst.sin6_addr = t;
	in6_recoverscope(&sa6_dst, &t);
	in6_embedscope(&t, &sa6_dst, NULL);

	
	TAILQ_FOREACH(ia6, &in6_ifaddr, ia_list)
		if (IN6_ARE_ADDR_EQUAL(&t, &ia6->ia_addr.sin6_addr) && (ia6->ia6_flags & (IN6_IFF_ANYCAST|IN6_IFF_TENTATIVE| IN6_IFF_DUPLICATED)) == 0) {

			src = &t;
			break;
		}
	if (ia6 == NULL && IN6_IS_ADDR_LINKLOCAL(&t) && (m->m_flags & M_LOOP)) {
		
		src = &t;
	}

	if (src == NULL) {
		
		rt = rtalloc(sin6tosa(&sa6_src), RT_RESOLVE, m->m_pkthdr.ph_rtableid);
		if (!rtisvalid(rt)) {
			char addr[INET6_ADDRSTRLEN];

			nd6log((LOG_DEBUG, "%s: source can't be determined: dst=%s\n", __func__, inet_ntop(AF_INET6, &sa6_src.sin6_addr, addr, sizeof(addr))));


			rtfree(rt);
			goto bad;
		}
		src = &ifatoia6(rt->rt_ifa)->ia_addr.sin6_addr;
	}

	ip6->ip6_src = *src;
	rtfree(rt);

	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = ip6_defhlim;

	icmp6->icmp6_cksum = 0;
	m->m_pkthdr.csum_flags = M_ICMP_CSUM_OUT;

	

	m->m_flags &= ~(M_BCAST|M_MCAST);

	

	pf_pkt_addr_changed(m);

	ip6_send(m);
	return;

 bad:
	m_freem(m);
	return;
}

void icmp6_fasttimo(void)
{

	mld6_fasttimeo();
}

const char * icmp6_redirect_diag(struct in6_addr *src6, struct in6_addr *dst6, struct in6_addr *tgt6)

{
	static char buf[1024]; 
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	char tgt[INET6_ADDRSTRLEN];

	snprintf(buf, sizeof(buf), "(src=%s dst=%s tgt=%s)", inet_ntop(AF_INET6, src6, src, sizeof(src)), inet_ntop(AF_INET6, dst6, dst, sizeof(dst)), inet_ntop(AF_INET6, tgt6, tgt, sizeof(tgt)));


	return buf;
}

void icmp6_redirect_input(struct mbuf *m, int off)
{
	struct ifnet *ifp;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_redirect *nd_rd;
	int icmp6len = ntohs(ip6->ip6_plen);
	char *lladdr = NULL;
	int lladdrlen = 0;
	struct rtentry *rt = NULL;
	int is_router;
	int is_onlink;
	struct in6_addr src6 = ip6->ip6_src;
	struct in6_addr redtgt6;
	struct in6_addr reddst6;
	union nd_opts ndopts;
	char addr[INET6_ADDRSTRLEN];

	ifp = if_get(m->m_pkthdr.ph_ifidx);
	if (ifp == NULL)
		return;

	
	if (ip6_forwarding)
		goto freeit;
	if (!(ifp->if_xflags & IFXF_AUTOCONF6))
		goto freeit;

	IP6_EXTHDR_GET(nd_rd, struct nd_redirect *, m, off, icmp6len);
	if (nd_rd == NULL) {
		icmp6stat.icp6s_tooshort++;
		if_put(ifp);
		return;
	}
	redtgt6 = nd_rd->nd_rd_target;
	reddst6 = nd_rd->nd_rd_dst;

	if (IN6_IS_ADDR_LINKLOCAL(&redtgt6))
		redtgt6.s6_addr16[1] = htons(ifp->if_index);
	if (IN6_IS_ADDR_LINKLOCAL(&reddst6))
		reddst6.s6_addr16[1] = htons(ifp->if_index);

	
	if (!IN6_IS_ADDR_LINKLOCAL(&src6)) {
		nd6log((LOG_ERR, "ICMP6 redirect sent from %s rejected; " "must be from linklocal\n", inet_ntop(AF_INET6, &src6, addr, sizeof(addr))));


		goto bad;
	}
	if (ip6->ip6_hlim != 255) {
		nd6log((LOG_ERR, "ICMP6 redirect sent from %s rejected; " "hlim=%d (must be 255)\n", inet_ntop(AF_INET6, &src6, addr, sizeof(addr)), ip6->ip6_hlim));



		goto bad;
	}
	if (IN6_IS_ADDR_MULTICAST(&reddst6)) {
		nd6log((LOG_ERR, "ICMP6 redirect rejected; " "redirect dst must be unicast: %s\n", icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));


		goto bad;
	}
    {
	
	struct sockaddr_in6 sin6;
	struct in6_addr *gw6;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&reddst6, &sin6.sin6_addr, sizeof(reddst6));
	rt = rtalloc(sin6tosa(&sin6), 0, m->m_pkthdr.ph_rtableid);
	if (rt) {
		if (rt->rt_gateway == NULL || rt->rt_gateway->sa_family != AF_INET6) {
			nd6log((LOG_ERR, "ICMP6 redirect rejected; no route " "with inet6 gateway found for redirect dst: %s\n", icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));


			rtfree(rt);
			goto bad;
		}

		gw6 = &(satosin6(rt->rt_gateway)->sin6_addr);
		if (bcmp(&src6, gw6, sizeof(struct in6_addr)) != 0) {
			nd6log((LOG_ERR, "ICMP6 redirect rejected; " "not equal to gw-for-src=%s (must be same): " "%s\n", inet_ntop(AF_INET6, gw6, addr, sizeof(addr)), icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));




			rtfree(rt);
			goto bad;
		}
	} else {
		nd6log((LOG_ERR, "ICMP6 redirect rejected; " "no route found for redirect dst: %s\n", icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));


		goto bad;
	}
	rtfree(rt);
	rt = NULL;
    }

	is_router = is_onlink = 0;
	if (IN6_IS_ADDR_LINKLOCAL(&redtgt6))
		is_router = 1;	
	if (bcmp(&redtgt6, &reddst6, sizeof(redtgt6)) == 0)
		is_onlink = 1;	
	if (!is_router && !is_onlink) {
		nd6log((LOG_ERR, "ICMP6 redirect rejected; " "neither router case nor onlink case: %s\n", icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));


		goto bad;
	}
	

	icmp6len -= sizeof(*nd_rd);
	nd6_option_init(nd_rd + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log((LOG_INFO, "icmp6_redirect_input: " "invalid ND option, rejected: %s\n", icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));

		
		goto freeit;
	}

	if (ndopts.nd_opts_tgt_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_tgt_lladdr + 1);
		lladdrlen = ndopts.nd_opts_tgt_lladdr->nd_opt_len << 3;
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log((LOG_INFO, "icmp6_redirect_input: lladdrlen mismatch for %s " "(if %d, icmp6 packet %d): %s\n", inet_ntop(AF_INET6, &redtgt6, addr, sizeof(addr)), ifp->if_addrlen, lladdrlen - 2, icmp6_redirect_diag(&src6, &reddst6, &redtgt6)));




		goto bad;
	}

	
	nd6_cache_lladdr(ifp, &redtgt6, lladdr, lladdrlen, ND_REDIRECT, is_onlink ? ND_REDIRECT_ONLINK : ND_REDIRECT_ROUTER);

	if (!is_onlink) {	
		
		struct sockaddr_in6 sdst;
		struct sockaddr_in6 sgw;
		struct sockaddr_in6 ssrc;
		unsigned long rtcount;
		struct rtentry *newrt = NULL;

		
		rtcount = rt_timer_queue_count(icmp6_redirect_timeout_q);
		if (0 <= ip6_maxdynroutes && rtcount >= ip6_maxdynroutes)
			goto freeit;
		else if (0 <= icmp6_redirect_lowat && rtcount > icmp6_redirect_lowat) {
			
		}

		bzero(&sdst, sizeof(sdst));
		bzero(&sgw, sizeof(sgw));
		bzero(&ssrc, sizeof(ssrc));
		sdst.sin6_family = sgw.sin6_family = ssrc.sin6_family = AF_INET6;
		sdst.sin6_len = sgw.sin6_len = ssrc.sin6_len = sizeof(struct sockaddr_in6);
		bcopy(&redtgt6, &sgw.sin6_addr, sizeof(struct in6_addr));
		bcopy(&reddst6, &sdst.sin6_addr, sizeof(struct in6_addr));
		bcopy(&src6, &ssrc.sin6_addr, sizeof(struct in6_addr));
		rtredirect(sin6tosa(&sdst), sin6tosa(&sgw), sin6tosa(&ssrc), &newrt, m->m_pkthdr.ph_rtableid);

		if (newrt) {
			(void)rt_timer_add(newrt, icmp6_redirect_timeout, icmp6_redirect_timeout_q, m->m_pkthdr.ph_rtableid);
			rtfree(newrt);
		}
	}
	
	{
		struct sockaddr_in6 sdst;

		bzero(&sdst, sizeof(sdst));
		sdst.sin6_family = AF_INET6;
		sdst.sin6_len = sizeof(struct sockaddr_in6);
		bcopy(&reddst6, &sdst.sin6_addr, sizeof(struct in6_addr));
		pfctlinput(PRC_REDIRECT_HOST, sin6tosa(&sdst));
	}

 freeit:
	if_put(ifp);
	m_freem(m);
	return;

 bad:
	if_put(ifp);
	icmp6stat.icp6s_badredirect++;
	m_freem(m);
}

void icmp6_redirect_output(struct mbuf *m0, struct rtentry *rt)
{
	struct ifnet *ifp = NULL;
	struct in6_addr *ifp_ll6;
	struct in6_addr *nexthop;
	struct ip6_hdr *sip6;	
	struct mbuf *m = NULL;	
	struct ip6_hdr *ip6;	
	struct nd_redirect *nd_rd;
	size_t maxlen;
	u_char *p;
	struct sockaddr_in6 src_sa;

	icmp6_errcount(&icmp6stat.icp6s_outerrhist, ND_REDIRECT, 0);

	
	if (!ip6_forwarding)
		goto fail;

	
	if (m0 == NULL || !rtisvalid(rt))
		goto fail;

	ifp = if_get(rt->rt_ifidx);
	if (ifp == NULL)
		goto fail;

	
	sip6 = mtod(m0, struct ip6_hdr *);
	bzero(&src_sa, sizeof(src_sa));
	src_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = sizeof(src_sa);
	src_sa.sin6_addr = sip6->ip6_src;
	
	src_sa.sin6_scope_id = in6_addr2scopeid(ifp->if_index, &sip6->ip6_src);
	if (nd6_is_addr_neighbor(&src_sa, ifp) == 0)
		goto fail;
	if (IN6_IS_ADDR_MULTICAST(&sip6->ip6_dst))
		goto fail;	

	
	if (icmp6_ratelimit(&sip6->ip6_src, ND_REDIRECT, 0))
		goto fail;

	



	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m && IPV6_MMTU >= MHLEN)
		MCLGET(m, M_DONTWAIT);
	if (!m)
		goto fail;
	m->m_pkthdr.ph_ifidx = 0;
	m->m_len = 0;
	maxlen = M_TRAILINGSPACE(m);
	maxlen = min(IPV6_MMTU, maxlen);
	
	if (maxlen < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + ((sizeof(struct nd_opt_hdr) + ifp->if_addrlen + 7) & ~7)) {
		goto fail;
	}

	{
		
		struct in6_ifaddr *ia6;
		if ((ia6 = in6ifa_ifpforlinklocal(ifp, IN6_IFF_TENTATIVE| IN6_IFF_DUPLICATED|IN6_IFF_ANYCAST)) == NULL)
			goto fail;
		ifp_ll6 = &ia6->ia_addr.sin6_addr;
	}

	
	if (rt->rt_gateway && (rt->rt_flags & RTF_GATEWAY)) {
		struct sockaddr_in6 *sin6;
		sin6 = satosin6(rt->rt_gateway);
		nexthop = &sin6->sin6_addr;
		if (!IN6_IS_ADDR_LINKLOCAL(nexthop))
			nexthop = NULL;
	} else nexthop = NULL;

	
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	
	bcopy(ifp_ll6, &ip6->ip6_src, sizeof(struct in6_addr));
	bcopy(&sip6->ip6_src, &ip6->ip6_dst, sizeof(struct in6_addr));

	
	nd_rd = (struct nd_redirect *)(ip6 + 1);
	nd_rd->nd_rd_type = ND_REDIRECT;
	nd_rd->nd_rd_code = 0;
	nd_rd->nd_rd_reserved = 0;
	if (rt->rt_flags & RTF_GATEWAY) {
		
		if (!nexthop)
			goto fail;
		bcopy(nexthop, &nd_rd->nd_rd_target, sizeof(nd_rd->nd_rd_target));
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_dst, sizeof(nd_rd->nd_rd_dst));
	} else {
		
		nexthop = &sip6->ip6_dst;
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_target, sizeof(nd_rd->nd_rd_target));
		bcopy(&sip6->ip6_dst, &nd_rd->nd_rd_dst, sizeof(nd_rd->nd_rd_dst));
	}

	p = (u_char *)(nd_rd + 1);

	{
		
		struct rtentry *nrt;
		int len;
		struct sockaddr_dl *sdl;
		struct nd_opt_hdr *nd_opt;
		char *lladdr;

		len = sizeof(*nd_opt) + ifp->if_addrlen;
		len = (len + 7) & ~7;	
		
		if (len + (p - (u_char *)ip6) > maxlen)
			goto nolladdropt;
		nrt = nd6_lookup(nexthop, 0, ifp, ifp->if_rdomain);
		if ((nrt != NULL) && (nrt->rt_flags & (RTF_GATEWAY|RTF_LLINFO)) == RTF_LLINFO && (nrt->rt_gateway->sa_family == AF_LINK) && (sdl = satosdl(nrt->rt_gateway)) && sdl->sdl_alen) {



			nd_opt = (struct nd_opt_hdr *)p;
			nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
			nd_opt->nd_opt_len = len >> 3;
			lladdr = (char *)(nd_opt + 1);
			bcopy(LLADDR(sdl), lladdr, ifp->if_addrlen);
			p += len;
		}
		rtfree(nrt);
	}
  nolladdropt:;

	m->m_pkthdr.len = m->m_len = p - (u_char *)ip6;

	
	if (p - (u_char *)ip6 > maxlen)
		goto noredhdropt;

	{
		
		int len;
		struct nd_opt_rd_hdr *nd_opt_rh;

		
		len = maxlen - (p - (u_char *)ip6);
		len &= ~7;

		
		if (len - sizeof(*nd_opt_rh) < m0->m_pkthdr.len) {
			
			m_adj(m0, (len - sizeof(*nd_opt_rh)) - m0->m_pkthdr.len);
		} else {
			
			size_t extra;

			extra = m0->m_pkthdr.len % 8;
			if (extra) {
				
				m_adj(m0, -extra);
			}
			len = m0->m_pkthdr.len + sizeof(*nd_opt_rh);
		}

		nd_opt_rh = (struct nd_opt_rd_hdr *)p;
		bzero(nd_opt_rh, sizeof(*nd_opt_rh));
		nd_opt_rh->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
		nd_opt_rh->nd_opt_rh_len = len >> 3;
		p += sizeof(*nd_opt_rh);
		m->m_pkthdr.len = m->m_len = p - (u_char *)ip6;

		
		m->m_pkthdr.len += m0->m_pkthdr.len;
		m_cat(m, m0);
		m0 = NULL;
	}
noredhdropt:
	m_freem(m0);
	m0 = NULL;

	sip6 = mtod(m, struct ip6_hdr *);
	if (IN6_IS_ADDR_LINKLOCAL(&sip6->ip6_src))
		sip6->ip6_src.s6_addr16[1] = 0;
	if (IN6_IS_ADDR_LINKLOCAL(&sip6->ip6_dst))
		sip6->ip6_dst.s6_addr16[1] = 0;

	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src))
		ip6->ip6_src.s6_addr16[1] = 0;
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst))
		ip6->ip6_dst.s6_addr16[1] = 0;

	if (IN6_IS_ADDR_LINKLOCAL(&nd_rd->nd_rd_target))
		nd_rd->nd_rd_target.s6_addr16[1] = 0;
	if (IN6_IS_ADDR_LINKLOCAL(&nd_rd->nd_rd_dst))
		nd_rd->nd_rd_dst.s6_addr16[1] = 0;

	ip6->ip6_plen = htons(m->m_pkthdr.len - sizeof(struct ip6_hdr));

	nd_rd->nd_rd_cksum = 0;
	m->m_pkthdr.csum_flags = M_ICMP_CSUM_OUT;

	
	ip6_output(m, NULL, NULL, 0, NULL, NULL);

	icmp6stat.icp6s_outhist[ND_REDIRECT]++;

	if_put(ifp);
	return;

fail:
	if_put(ifp);
	m_freem(m);
	m_freem(m0);
}


int icmp6_ctloutput(int op, struct socket *so, int level, int optname, struct mbuf **mp)

{
	int error = 0;
	struct inpcb *in6p = sotoinpcb(so);
	struct mbuf *m = *mp;

	if (level != IPPROTO_ICMPV6) {
		if (op == PRCO_SETOPT)
			(void)m_free(m);
		return EINVAL;
	}

	switch (op) {
	case PRCO_SETOPT:
		switch (optname) {
		case ICMP6_FILTER:
		    {
			struct icmp6_filter *p;

			if (m == NULL || m->m_len != sizeof(*p)) {
				error = EMSGSIZE;
				break;
			}
			p = mtod(m, struct icmp6_filter *);
			if (!p || !in6p->inp_icmp6filt) {
				error = EINVAL;
				break;
			}
			bcopy(p, in6p->inp_icmp6filt, sizeof(struct icmp6_filter));
			error = 0;
			break;
		    }

		default:
			error = ENOPROTOOPT;
			break;
		}
		m_freem(m);
		break;

	case PRCO_GETOPT:
		switch (optname) {
		case ICMP6_FILTER:
		    {
			struct icmp6_filter *p;

			if (!in6p->inp_icmp6filt) {
				error = EINVAL;
				break;
			}
			*mp = m = m_get(M_WAIT, MT_SOOPTS);
			m->m_len = sizeof(struct icmp6_filter);
			p = mtod(m, struct icmp6_filter *);
			bcopy(in6p->inp_icmp6filt, p, sizeof(struct icmp6_filter));
			error = 0;
			break;
		    }

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}

	return (error);
}


int icmp6_ratelimit(const struct in6_addr *dst, const int type, const int code)
{
	
	if (!ppsratecheck(&icmp6errppslim_last, &icmp6errpps_count, icmp6errppslim))
		return 1;	
	return 0;		
}

struct rtentry * icmp6_mtudisc_clone(struct sockaddr *dst, u_int rtableid)
{
	struct rtentry *rt;
	int    error;

	rt = rtalloc(dst, RT_RESOLVE, rtableid);

	
	if (!rtisvalid(rt) || (rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE))) {
		rtfree(rt);
		return (NULL);
	}

	
	if ((rt->rt_flags & RTF_HOST) == 0) {
		struct rtentry *nrt;
		struct rt_addrinfo info;
		struct sockaddr_rtlabel sa_rl;

		memset(&info, 0, sizeof(info));
		info.rti_ifa = rt->rt_ifa;
		info.rti_flags = RTF_GATEWAY | RTF_HOST | RTF_DYNAMIC;
		info.rti_info[RTAX_DST] = dst;
		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[RTAX_LABEL] = rtlabel_id2sa(rt->rt_labelid, &sa_rl);

		error = rtrequest(RTM_ADD, &info, rt->rt_priority, &nrt, rtableid);
		if (error) {
			rtfree(rt);
			return (NULL);
		}
		nrt->rt_rmx = rt->rt_rmx;
		rtfree(rt);
		rt = nrt;
	}
	error = rt_timer_add(rt, icmp6_mtudisc_timeout, icmp6_mtudisc_timeout_q, rtableid);
	if (error) {
		rtfree(rt);
		return (NULL);
	}

	return (rt);
}

void icmp6_mtudisc_timeout(struct rtentry *rt, struct rttimer *r)
{
	struct ifnet *ifp;

	NET_ASSERT_LOCKED();

	ifp = if_get(rt->rt_ifidx);
	if (ifp == NULL)
		return;

	if ((rt->rt_flags & (RTF_DYNAMIC|RTF_HOST)) == (RTF_DYNAMIC|RTF_HOST)) {
		rtdeletemsg(rt, ifp, r->rtt_tableid);
	} else {
		if (!(rt->rt_rmx.rmx_locks & RTV_MTU))
			rt->rt_rmx.rmx_mtu = 0;
	}

	if_put(ifp);
}

void icmp6_redirect_timeout(struct rtentry *rt, struct rttimer *r)
{
	struct ifnet *ifp;

	NET_ASSERT_LOCKED();

	ifp = if_get(rt->rt_ifidx);
	if (ifp == NULL)
		return;

	if ((rt->rt_flags & (RTF_DYNAMIC|RTF_HOST)) == (RTF_DYNAMIC|RTF_HOST)) {
		rtdeletemsg(rt, ifp, r->rtt_tableid);
	}

	if_put(ifp);
}

int *icmpv6ctl_vars[ICMPV6CTL_MAXID] = ICMPV6CTL_VARS;

int icmp6_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)

{
	
	if (namelen != 1)
		return ENOTDIR;

	switch (name[0]) {

	case ICMPV6CTL_STATS:
		return sysctl_rdstruct(oldp, oldlenp, newp, &icmp6stat, sizeof(icmp6stat));
	case ICMPV6CTL_ND6_DRLIST:
	case ICMPV6CTL_ND6_PRLIST:
		return nd6_sysctl(name[0], oldp, oldlenp, newp, newlen);
	default:
		if (name[0] < ICMPV6CTL_MAXID)
			return (sysctl_int_arr(icmpv6ctl_vars, name, namelen, oldp, oldlenp, newp, newlen));
		return ENOPROTOOPT;
	}
	
}
