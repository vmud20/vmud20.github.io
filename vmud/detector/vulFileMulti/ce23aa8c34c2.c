




__FBSDID("$FreeBSD$");







































union sockunion {
	struct sockaddr_storage	ss;
	struct sockaddr		sa;
	struct sockaddr_dl	sdl;
	struct sockaddr_in6	sin6;
};
typedef union sockunion sockunion_t;



static MALLOC_DEFINE(M_IN6MFILTER, "in6_mfilter", "IPv6 multicast PCB-layer source filter");
static MALLOC_DEFINE(M_IP6MADDR, "in6_multi", "IPv6 multicast group");
static MALLOC_DEFINE(M_IP6MOPTS, "ip6_moptions", "IPv6 multicast options");
static MALLOC_DEFINE(M_IP6MSOURCE, "ip6_msource", "IPv6 multicast MLD-layer source filter");

RB_GENERATE(ip6_msource_tree, ip6_msource, im6s_link, ip6_msource_cmp);


struct mtx in6_multi_mtx;
MTX_SYSINIT(in6_multi_mtx, &in6_multi_mtx, "in6_multi_mtx", MTX_DEF);

static void	im6f_commit(struct in6_mfilter *);
static int	im6f_get_source(struct in6_mfilter *imf, const struct sockaddr_in6 *psin, struct in6_msource **);

static struct in6_msource * im6f_graft(struct in6_mfilter *, const uint8_t, const struct sockaddr_in6 *);

static void	im6f_leave(struct in6_mfilter *);
static int	im6f_prune(struct in6_mfilter *, const struct sockaddr_in6 *);
static void	im6f_purge(struct in6_mfilter *);
static void	im6f_rollback(struct in6_mfilter *);
static void	im6f_reap(struct in6_mfilter *);
static int	im6o_grow(struct ip6_moptions *);
static size_t	im6o_match_group(const struct ip6_moptions *, const struct ifnet *, const struct sockaddr *);
static struct in6_msource * im6o_match_source(const struct ip6_moptions *, const size_t, const struct sockaddr *);

static void	im6s_merge(struct ip6_msource *ims, const struct in6_msource *lims, const int rollback);
static int	in6_mc_get(struct ifnet *, const struct in6_addr *, struct in6_multi **);
static int	in6m_get_source(struct in6_multi *inm, const struct in6_addr *addr, const int noalloc, struct ip6_msource **pims);

static int	in6m_is_ifp_detached(const struct in6_multi *);
static int	in6m_merge(struct in6_multi *,  struct in6_mfilter *);
static void	in6m_purge(struct in6_multi *);
static void	in6m_reap(struct in6_multi *);
static struct ip6_moptions * in6p_findmoptions(struct inpcb *);
static int	in6p_get_source_filters(struct inpcb *, struct sockopt *);
static int	in6p_join_group(struct inpcb *, struct sockopt *);
static int	in6p_leave_group(struct inpcb *, struct sockopt *);
static struct ifnet * in6p_lookup_mcast_ifp(const struct inpcb *, const struct sockaddr_in6 *);

static int	in6p_block_unblock_source(struct inpcb *, struct sockopt *);
static int	in6p_set_multicast_if(struct inpcb *, struct sockopt *);
static int	in6p_set_source_filters(struct inpcb *, struct sockopt *);
static int	sysctl_ip6_mcast_filters(SYSCTL_HANDLER_ARGS);

SYSCTL_DECL(_net_inet6_ip6);	

static SYSCTL_NODE(_net_inet6_ip6, OID_AUTO, mcast, CTLFLAG_RW, 0, "IPv6 multicast");

static u_long in6_mcast_maxgrpsrc = IPV6_MAX_GROUP_SRC_FILTER;
SYSCTL_ULONG(_net_inet6_ip6_mcast, OID_AUTO, maxgrpsrc, CTLFLAG_RW | CTLFLAG_TUN, &in6_mcast_maxgrpsrc, 0, "Max source filters per group");

TUNABLE_ULONG("net.inet6.ip6.mcast.maxgrpsrc", &in6_mcast_maxgrpsrc);

static u_long in6_mcast_maxsocksrc = IPV6_MAX_SOCK_SRC_FILTER;
SYSCTL_ULONG(_net_inet6_ip6_mcast, OID_AUTO, maxsocksrc, CTLFLAG_RW | CTLFLAG_TUN, &in6_mcast_maxsocksrc, 0, "Max source filters per socket");

TUNABLE_ULONG("net.inet6.ip6.mcast.maxsocksrc", &in6_mcast_maxsocksrc);


int in6_mcast_loop = IPV6_DEFAULT_MULTICAST_LOOP;
SYSCTL_INT(_net_inet6_ip6_mcast, OID_AUTO, loop, CTLFLAG_RW | CTLFLAG_TUN, &in6_mcast_loop, 0, "Loopback multicast datagrams by default");
TUNABLE_INT("net.inet6.ip6.mcast.loop", &in6_mcast_loop);

static SYSCTL_NODE(_net_inet6_ip6_mcast, OID_AUTO, filters, CTLFLAG_RD | CTLFLAG_MPSAFE, sysctl_ip6_mcast_filters, "Per-interface stack-wide source filters");



static int __inline in6m_is_ifp_detached(const struct in6_multi *inm)
{
	struct ifnet *ifp;

	KASSERT(inm->in6m_ifma != NULL, ("%s: no ifma", __func__));
	ifp = inm->in6m_ifma->ifma_ifp;
	if (ifp != NULL) {
		
		KASSERT(inm->in6m_ifp == ifp, ("%s: bad ifp", __func__));
	}

	return (ifp == NULL);
}


static __inline void im6f_init(struct in6_mfilter *imf, const int st0, const int st1)
{
	memset(imf, 0, sizeof(struct in6_mfilter));
	RB_INIT(&imf->im6f_sources);
	imf->im6f_st[0] = st0;
	imf->im6f_st[1] = st1;
}


static int im6o_grow(struct ip6_moptions *imo)
{
	struct in6_multi	**nmships;
	struct in6_multi	**omships;
	struct in6_mfilter	 *nmfilters;
	struct in6_mfilter	 *omfilters;
	size_t			  idx;
	size_t			  newmax;
	size_t			  oldmax;

	nmships = NULL;
	nmfilters = NULL;
	omships = imo->im6o_membership;
	omfilters = imo->im6o_mfilters;
	oldmax = imo->im6o_max_memberships;
	newmax = ((oldmax + 1) * 2) - 1;

	if (newmax <= IPV6_MAX_MEMBERSHIPS) {
		nmships = (struct in6_multi **)realloc(omships, sizeof(struct in6_multi *) * newmax, M_IP6MOPTS, M_NOWAIT);
		nmfilters = (struct in6_mfilter *)realloc(omfilters, sizeof(struct in6_mfilter) * newmax, M_IN6MFILTER, M_NOWAIT);

		if (nmships != NULL && nmfilters != NULL) {
			
			for (idx = oldmax; idx < newmax; idx++) {
				im6f_init(&nmfilters[idx], MCAST_UNDEFINED, MCAST_EXCLUDE);
			}
			imo->im6o_max_memberships = newmax;
			imo->im6o_membership = nmships;
			imo->im6o_mfilters = nmfilters;
		}
	}

	if (nmships == NULL || nmfilters == NULL) {
		if (nmships != NULL)
			free(nmships, M_IP6MOPTS);
		if (nmfilters != NULL)
			free(nmfilters, M_IN6MFILTER);
		return (ETOOMANYREFS);
	}

	return (0);
}


static size_t im6o_match_group(const struct ip6_moptions *imo, const struct ifnet *ifp, const struct sockaddr *group)

{
	const struct sockaddr_in6 *gsin6;
	struct in6_multi	**pinm;
	int		  idx;
	int		  nmships;

	gsin6 = (const struct sockaddr_in6 *)group;

	
	if (imo->im6o_membership == NULL || imo->im6o_num_memberships == 0)
		return (-1);

	nmships = imo->im6o_num_memberships;
	pinm = &imo->im6o_membership[0];
	for (idx = 0; idx < nmships; idx++, pinm++) {
		if (*pinm == NULL)
			continue;
		if ((ifp == NULL || ((*pinm)->in6m_ifp == ifp)) && IN6_ARE_ADDR_EQUAL(&(*pinm)->in6m_addr, &gsin6->sin6_addr)) {

			break;
		}
	}
	if (idx >= nmships)
		idx = -1;

	return (idx);
}


static struct in6_msource * im6o_match_source(const struct ip6_moptions *imo, const size_t gidx, const struct sockaddr *src)

{
	struct ip6_msource	 find;
	struct in6_mfilter	*imf;
	struct ip6_msource	*ims;
	const sockunion_t	*psa;

	KASSERT(src->sa_family == AF_INET6, ("%s: !AF_INET6", __func__));
	KASSERT(gidx != -1 && gidx < imo->im6o_num_memberships, ("%s: invalid index %d\n", __func__, (int)gidx));

	
	if (imo->im6o_mfilters == NULL)
		return (NULL);
	imf = &imo->im6o_mfilters[gidx];

	psa = (const sockunion_t *)src;
	find.im6s_addr = psa->sin6.sin6_addr;
	in6_clearscope(&find.im6s_addr);		
	ims = RB_FIND(ip6_msource_tree, &imf->im6f_sources, &find);

	return ((struct in6_msource *)ims);
}


int im6o_mc_filter(const struct ip6_moptions *imo, const struct ifnet *ifp, const struct sockaddr *group, const struct sockaddr *src)

{
	size_t gidx;
	struct in6_msource *ims;
	int mode;

	KASSERT(ifp != NULL, ("%s: null ifp", __func__));

	gidx = im6o_match_group(imo, ifp, group);
	if (gidx == -1)
		return (MCAST_NOTGMEMBER);

	
	mode = imo->im6o_mfilters[gidx].im6f_st[1];
	ims = im6o_match_source(imo, gidx, src);

	if ((ims == NULL && mode == MCAST_INCLUDE) || (ims != NULL && ims->im6sl_st[0] != mode))
		return (MCAST_NOTSMEMBER);

	return (MCAST_PASS);
}


static int in6_mc_get(struct ifnet *ifp, const struct in6_addr *group, struct in6_multi **pinm)

{
	struct sockaddr_in6	 gsin6;
	struct ifmultiaddr	*ifma;
	struct in6_multi	*inm;
	int			 error;

	error = 0;

	
	IN6_MULTI_LOCK_ASSERT();
	IF_ADDR_WLOCK(ifp);

	inm = in6m_lookup_locked(ifp, group);
	if (inm != NULL) {
		
		KASSERT(inm->in6m_refcount >= 1, ("%s: bad refcount %d", __func__, inm->in6m_refcount));
		++inm->in6m_refcount;
		*pinm = inm;
		goto out_locked;
	}

	memset(&gsin6, 0, sizeof(gsin6));
	gsin6.sin6_family = AF_INET6;
	gsin6.sin6_len = sizeof(struct sockaddr_in6);
	gsin6.sin6_addr = *group;

	
	IF_ADDR_WUNLOCK(ifp);
	error = if_addmulti(ifp, (struct sockaddr *)&gsin6, &ifma);
	if (error != 0)
		return (error);
	IF_ADDR_WLOCK(ifp);

	
	if (ifma->ifma_protospec != NULL) {
		inm = (struct in6_multi *)ifma->ifma_protospec;

		KASSERT(ifma->ifma_addr != NULL, ("%s: no ifma_addr", __func__));
		KASSERT(ifma->ifma_addr->sa_family == AF_INET6, ("%s: ifma not AF_INET6", __func__));
		KASSERT(inm != NULL, ("%s: no ifma_protospec", __func__));
		if (inm->in6m_ifma != ifma || inm->in6m_ifp != ifp || !IN6_ARE_ADDR_EQUAL(&inm->in6m_addr, group))
			panic("%s: ifma %p is inconsistent with %p (%p)", __func__, ifma, inm, group);

		++inm->in6m_refcount;
		*pinm = inm;
		goto out_locked;
	}

	IF_ADDR_WLOCK_ASSERT(ifp);

	
	inm = malloc(sizeof(*inm), M_IP6MADDR, M_NOWAIT | M_ZERO);
	if (inm == NULL) {
		if_delmulti_ifma(ifma);
		error = ENOMEM;
		goto out_locked;
	}
	inm->in6m_addr = *group;
	inm->in6m_ifp = ifp;
	inm->in6m_mli = MLD_IFINFO(ifp);
	inm->in6m_ifma = ifma;
	inm->in6m_refcount = 1;
	inm->in6m_state = MLD_NOT_MEMBER;
	IFQ_SET_MAXLEN(&inm->in6m_scq, MLD_MAX_STATE_CHANGES);

	inm->in6m_st[0].iss_fmode = MCAST_UNDEFINED;
	inm->in6m_st[1].iss_fmode = MCAST_UNDEFINED;
	RB_INIT(&inm->in6m_srcs);

	ifma->ifma_protospec = inm;
	*pinm = inm;

out_locked:
	IF_ADDR_WUNLOCK(ifp);
	return (error);
}


void in6m_release_locked(struct in6_multi *inm)
{
	struct ifmultiaddr *ifma;

	IN6_MULTI_LOCK_ASSERT();

	CTR2(KTR_MLD, "%s: refcount is %d", __func__, inm->in6m_refcount);

	if (--inm->in6m_refcount > 0) {
		CTR2(KTR_MLD, "%s: refcount is now %d", __func__, inm->in6m_refcount);
		return;
	}

	CTR2(KTR_MLD, "%s: freeing inm %p", __func__, inm);

	ifma = inm->in6m_ifma;

	
	CTR2(KTR_MLD, "%s: purging ifma %p", __func__, ifma);
	KASSERT(ifma->ifma_protospec == inm, ("%s: ifma_protospec != inm", __func__));
	ifma->ifma_protospec = NULL;

	in6m_purge(inm);

	free(inm, M_IP6MADDR);

	if_delmulti_ifma(ifma);
}


void in6m_clear_recorded(struct in6_multi *inm)
{
	struct ip6_msource	*ims;

	IN6_MULTI_LOCK_ASSERT();

	RB_FOREACH(ims, ip6_msource_tree, &inm->in6m_srcs) {
		if (ims->im6s_stp) {
			ims->im6s_stp = 0;
			--inm->in6m_st[1].iss_rec;
		}
	}
	KASSERT(inm->in6m_st[1].iss_rec == 0, ("%s: iss_rec %d not 0", __func__, inm->in6m_st[1].iss_rec));
}


int in6m_record_source(struct in6_multi *inm, const struct in6_addr *addr)
{
	struct ip6_msource	 find;
	struct ip6_msource	*ims, *nims;

	IN6_MULTI_LOCK_ASSERT();

	find.im6s_addr = *addr;
	ims = RB_FIND(ip6_msource_tree, &inm->in6m_srcs, &find);
	if (ims && ims->im6s_stp)
		return (0);
	if (ims == NULL) {
		if (inm->in6m_nsrc == in6_mcast_maxgrpsrc)
			return (-ENOSPC);
		nims = malloc(sizeof(struct ip6_msource), M_IP6MSOURCE, M_NOWAIT | M_ZERO);
		if (nims == NULL)
			return (-ENOMEM);
		nims->im6s_addr = find.im6s_addr;
		RB_INSERT(ip6_msource_tree, &inm->in6m_srcs, nims);
		++inm->in6m_nsrc;
		ims = nims;
	}

	
	++ims->im6s_stp;
	++inm->in6m_st[1].iss_rec;

	return (1);
}


static int im6f_get_source(struct in6_mfilter *imf, const struct sockaddr_in6 *psin, struct in6_msource **plims)

{
	struct ip6_msource	 find;
	struct ip6_msource	*ims, *nims;
	struct in6_msource	*lims;
	int			 error;

	error = 0;
	ims = NULL;
	lims = NULL;

	find.im6s_addr = psin->sin6_addr;
	ims = RB_FIND(ip6_msource_tree, &imf->im6f_sources, &find);
	lims = (struct in6_msource *)ims;
	if (lims == NULL) {
		if (imf->im6f_nsrc == in6_mcast_maxsocksrc)
			return (ENOSPC);
		nims = malloc(sizeof(struct in6_msource), M_IN6MFILTER, M_NOWAIT | M_ZERO);
		if (nims == NULL)
			return (ENOMEM);
		lims = (struct in6_msource *)nims;
		lims->im6s_addr = find.im6s_addr;
		lims->im6sl_st[0] = MCAST_UNDEFINED;
		RB_INSERT(ip6_msource_tree, &imf->im6f_sources, nims);
		++imf->im6f_nsrc;
	}

	*plims = lims;

	return (error);
}


static struct in6_msource * im6f_graft(struct in6_mfilter *imf, const uint8_t st1, const struct sockaddr_in6 *psin)

{
	struct ip6_msource	*nims;
	struct in6_msource	*lims;

	nims = malloc(sizeof(struct in6_msource), M_IN6MFILTER, M_NOWAIT | M_ZERO);
	if (nims == NULL)
		return (NULL);
	lims = (struct in6_msource *)nims;
	lims->im6s_addr = psin->sin6_addr;
	lims->im6sl_st[0] = MCAST_UNDEFINED;
	lims->im6sl_st[1] = st1;
	RB_INSERT(ip6_msource_tree, &imf->im6f_sources, nims);
	++imf->im6f_nsrc;

	return (lims);
}


static int im6f_prune(struct in6_mfilter *imf, const struct sockaddr_in6 *psin)
{
	struct ip6_msource	 find;
	struct ip6_msource	*ims;
	struct in6_msource	*lims;

	find.im6s_addr = psin->sin6_addr;
	ims = RB_FIND(ip6_msource_tree, &imf->im6f_sources, &find);
	if (ims == NULL)
		return (ENOENT);
	lims = (struct in6_msource *)ims;
	lims->im6sl_st[1] = MCAST_UNDEFINED;
	return (0);
}


static void im6f_rollback(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims, *tims;
	struct in6_msource	*lims;

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &imf->im6f_sources, tims) {
		lims = (struct in6_msource *)ims;
		if (lims->im6sl_st[0] == lims->im6sl_st[1]) {
			
			continue;
		} else if (lims->im6sl_st[0] != MCAST_UNDEFINED) {
			
			lims->im6sl_st[1] = lims->im6sl_st[0];
		} else {
			
			CTR2(KTR_MLD, "%s: free ims %p", __func__, ims);
			RB_REMOVE(ip6_msource_tree, &imf->im6f_sources, ims);
			free(ims, M_IN6MFILTER);
			imf->im6f_nsrc--;
		}
	}
	imf->im6f_st[1] = imf->im6f_st[0];
}


static void im6f_leave(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims;
	struct in6_msource	*lims;

	RB_FOREACH(ims, ip6_msource_tree, &imf->im6f_sources) {
		lims = (struct in6_msource *)ims;
		lims->im6sl_st[1] = MCAST_UNDEFINED;
	}
	imf->im6f_st[1] = MCAST_INCLUDE;
}


static void im6f_commit(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims;
	struct in6_msource	*lims;

	RB_FOREACH(ims, ip6_msource_tree, &imf->im6f_sources) {
		lims = (struct in6_msource *)ims;
		lims->im6sl_st[0] = lims->im6sl_st[1];
	}
	imf->im6f_st[0] = imf->im6f_st[1];
}


static void im6f_reap(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims, *tims;
	struct in6_msource	*lims;

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &imf->im6f_sources, tims) {
		lims = (struct in6_msource *)ims;
		if ((lims->im6sl_st[0] == MCAST_UNDEFINED) && (lims->im6sl_st[1] == MCAST_UNDEFINED)) {
			CTR2(KTR_MLD, "%s: free lims %p", __func__, ims);
			RB_REMOVE(ip6_msource_tree, &imf->im6f_sources, ims);
			free(ims, M_IN6MFILTER);
			imf->im6f_nsrc--;
		}
	}
}


static void im6f_purge(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &imf->im6f_sources, tims) {
		CTR2(KTR_MLD, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip6_msource_tree, &imf->im6f_sources, ims);
		free(ims, M_IN6MFILTER);
		imf->im6f_nsrc--;
	}
	imf->im6f_st[0] = imf->im6f_st[1] = MCAST_UNDEFINED;
	KASSERT(RB_EMPTY(&imf->im6f_sources), ("%s: im6f_sources not empty", __func__));
}


static int in6m_get_source(struct in6_multi *inm, const struct in6_addr *addr, const int noalloc, struct ip6_msource **pims)

{
	struct ip6_msource	 find;
	struct ip6_msource	*ims, *nims;

	char			 ip6tbuf[INET6_ADDRSTRLEN];


	find.im6s_addr = *addr;
	ims = RB_FIND(ip6_msource_tree, &inm->in6m_srcs, &find);
	if (ims == NULL && !noalloc) {
		if (inm->in6m_nsrc == in6_mcast_maxgrpsrc)
			return (ENOSPC);
		nims = malloc(sizeof(struct ip6_msource), M_IP6MSOURCE, M_NOWAIT | M_ZERO);
		if (nims == NULL)
			return (ENOMEM);
		nims->im6s_addr = *addr;
		RB_INSERT(ip6_msource_tree, &inm->in6m_srcs, nims);
		++inm->in6m_nsrc;
		ims = nims;
		CTR3(KTR_MLD, "%s: allocated %s as %p", __func__, ip6_sprintf(ip6tbuf, addr), ims);
	}

	*pims = ims;
	return (0);
}


static void im6s_merge(struct ip6_msource *ims, const struct in6_msource *lims, const int rollback)

{
	int n = rollback ? -1 : 1;

	char ip6tbuf[INET6_ADDRSTRLEN];

	ip6_sprintf(ip6tbuf, &lims->im6s_addr);


	if (lims->im6sl_st[0] == MCAST_EXCLUDE) {
		CTR3(KTR_MLD, "%s: t1 ex -= %d on %s", __func__, n, ip6tbuf);
		ims->im6s_st[1].ex -= n;
	} else if (lims->im6sl_st[0] == MCAST_INCLUDE) {
		CTR3(KTR_MLD, "%s: t1 in -= %d on %s", __func__, n, ip6tbuf);
		ims->im6s_st[1].in -= n;
	}

	if (lims->im6sl_st[1] == MCAST_EXCLUDE) {
		CTR3(KTR_MLD, "%s: t1 ex += %d on %s", __func__, n, ip6tbuf);
		ims->im6s_st[1].ex += n;
	} else if (lims->im6sl_st[1] == MCAST_INCLUDE) {
		CTR3(KTR_MLD, "%s: t1 in += %d on %s", __func__, n, ip6tbuf);
		ims->im6s_st[1].in += n;
	}
}


static int in6m_merge(struct in6_multi *inm,  struct in6_mfilter *imf)
{
	struct ip6_msource	*ims, *nims;
	struct in6_msource	*lims;
	int			 schanged, error;
	int			 nsrc0, nsrc1;

	schanged = 0;
	error = 0;
	nsrc1 = nsrc0 = 0;

	
	RB_FOREACH(ims, ip6_msource_tree, &imf->im6f_sources) {
		lims = (struct in6_msource *)ims;
		if (lims->im6sl_st[0] == imf->im6f_st[0]) nsrc0++;
		if (lims->im6sl_st[1] == imf->im6f_st[1]) nsrc1++;
		if (lims->im6sl_st[0] == lims->im6sl_st[1]) continue;
		error = in6m_get_source(inm, &lims->im6s_addr, 0, &nims);
		++schanged;
		if (error)
			break;
		im6s_merge(nims, lims, 0);
	}
	if (error) {
		struct ip6_msource *bims;

		RB_FOREACH_REVERSE_FROM(ims, ip6_msource_tree, nims) {
			lims = (struct in6_msource *)ims;
			if (lims->im6sl_st[0] == lims->im6sl_st[1])
				continue;
			(void)in6m_get_source(inm, &lims->im6s_addr, 1, &bims);
			if (bims == NULL)
				continue;
			im6s_merge(bims, lims, 1);
		}
		goto out_reap;
	}

	CTR3(KTR_MLD, "%s: imf filters in-mode: %d at t0, %d at t1", __func__, nsrc0, nsrc1);

	
	if (imf->im6f_st[0] == imf->im6f_st[1] && imf->im6f_st[1] == MCAST_INCLUDE) {
		if (nsrc1 == 0) {
			CTR1(KTR_MLD, "%s: --in on inm at t1", __func__);
			--inm->in6m_st[1].iss_in;
		}
	}

	
	if (imf->im6f_st[0] != imf->im6f_st[1]) {
		CTR3(KTR_MLD, "%s: imf transition %d to %d", __func__, imf->im6f_st[0], imf->im6f_st[1]);

		if (imf->im6f_st[0] == MCAST_EXCLUDE) {
			CTR1(KTR_MLD, "%s: --ex on inm at t1", __func__);
			--inm->in6m_st[1].iss_ex;
		} else if (imf->im6f_st[0] == MCAST_INCLUDE) {
			CTR1(KTR_MLD, "%s: --in on inm at t1", __func__);
			--inm->in6m_st[1].iss_in;
		}

		if (imf->im6f_st[1] == MCAST_EXCLUDE) {
			CTR1(KTR_MLD, "%s: ex++ on inm at t1", __func__);
			inm->in6m_st[1].iss_ex++;
		} else if (imf->im6f_st[1] == MCAST_INCLUDE && nsrc1 > 0) {
			CTR1(KTR_MLD, "%s: in++ on inm at t1", __func__);
			inm->in6m_st[1].iss_in++;
		}
	}

	
	if (inm->in6m_st[1].iss_ex > 0) {
		CTR1(KTR_MLD, "%s: transition to EX", __func__);
		inm->in6m_st[1].iss_fmode = MCAST_EXCLUDE;
	} else if (inm->in6m_st[1].iss_in > 0) {
		CTR1(KTR_MLD, "%s: transition to IN", __func__);
		inm->in6m_st[1].iss_fmode = MCAST_INCLUDE;
	} else {
		CTR1(KTR_MLD, "%s: transition to UNDEF", __func__);
		inm->in6m_st[1].iss_fmode = MCAST_UNDEFINED;
	}

	
	if (imf->im6f_st[0] == MCAST_EXCLUDE && nsrc0 == 0) {
		if ((imf->im6f_st[1] != MCAST_EXCLUDE) || (imf->im6f_st[1] == MCAST_EXCLUDE && nsrc1 > 0))
			CTR1(KTR_MLD, "%s: --asm on inm at t1", __func__);
			--inm->in6m_st[1].iss_asm;
	}

	
	if (imf->im6f_st[1] == MCAST_EXCLUDE && nsrc1 == 0) {
		CTR1(KTR_MLD, "%s: asm++ on inm at t1", __func__);
		inm->in6m_st[1].iss_asm++;
	}

	CTR3(KTR_MLD, "%s: merged imf %p to inm %p", __func__, imf, inm);
	in6m_print(inm);

out_reap:
	if (schanged > 0) {
		CTR1(KTR_MLD, "%s: sources changed; reaping", __func__);
		in6m_reap(inm);
	}
	return (error);
}


void in6m_commit(struct in6_multi *inm)
{
	struct ip6_msource	*ims;

	CTR2(KTR_MLD, "%s: commit inm %p", __func__, inm);
	CTR1(KTR_MLD, "%s: pre commit:", __func__);
	in6m_print(inm);

	RB_FOREACH(ims, ip6_msource_tree, &inm->in6m_srcs) {
		ims->im6s_st[0] = ims->im6s_st[1];
	}
	inm->in6m_st[0] = inm->in6m_st[1];
}


static void in6m_reap(struct in6_multi *inm)
{
	struct ip6_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &inm->in6m_srcs, tims) {
		if (ims->im6s_st[0].ex > 0 || ims->im6s_st[0].in > 0 || ims->im6s_st[1].ex > 0 || ims->im6s_st[1].in > 0 || ims->im6s_stp != 0)

			continue;
		CTR2(KTR_MLD, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip6_msource_tree, &inm->in6m_srcs, ims);
		free(ims, M_IP6MSOURCE);
		inm->in6m_nsrc--;
	}
}


static void in6m_purge(struct in6_multi *inm)
{
	struct ip6_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &inm->in6m_srcs, tims) {
		CTR2(KTR_MLD, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip6_msource_tree, &inm->in6m_srcs, ims);
		free(ims, M_IP6MSOURCE);
		inm->in6m_nsrc--;
	}
}


struct in6_multi_mship * in6_joingroup(struct ifnet *ifp, struct in6_addr *mcaddr, int *errorp, int delay)

{
	struct in6_multi_mship *imm;
	int error;

	imm = malloc(sizeof(*imm), M_IP6MADDR, M_NOWAIT);
	if (imm == NULL) {
		*errorp = ENOBUFS;
		return (NULL);
	}

	delay = (delay * PR_FASTHZ) / hz;

	error = in6_mc_join(ifp, mcaddr, NULL, &imm->i6mm_maddr, delay);
	if (error) {
		*errorp = error;
		free(imm, M_IP6MADDR);
		return (NULL);
	}

	return (imm);
}


int in6_leavegroup(struct in6_multi_mship *imm)
{

	if (imm->i6mm_maddr != NULL)
		in6_mc_leave(imm->i6mm_maddr, NULL);
	free(imm,  M_IP6MADDR);
	return 0;
}


int in6_mc_join(struct ifnet *ifp, const struct in6_addr *mcaddr, struct in6_mfilter *imf, struct in6_multi **pinm, const int delay)


{
	int error;

	IN6_MULTI_LOCK();
	error = in6_mc_join_locked(ifp, mcaddr, imf, pinm, delay);
	IN6_MULTI_UNLOCK();

	return (error);
}


int in6_mc_join_locked(struct ifnet *ifp, const struct in6_addr *mcaddr, struct in6_mfilter *imf, struct in6_multi **pinm, const int delay)


{
	struct in6_mfilter	 timf;
	struct in6_multi	*inm;
	int			 error;

	char			 ip6tbuf[INET6_ADDRSTRLEN];



	
	KASSERT(IN6_IS_ADDR_MULTICAST(mcaddr), ("%s: not a multicast address", __func__));
	if (IN6_IS_ADDR_MC_LINKLOCAL(mcaddr) || IN6_IS_ADDR_MC_INTFACELOCAL(mcaddr)) {
		KASSERT(mcaddr->s6_addr16[1] != 0, ("%s: scope zone ID not set", __func__));
	}


	IN6_MULTI_LOCK_ASSERT();

	CTR4(KTR_MLD, "%s: join %s on %p(%s))", __func__, ip6_sprintf(ip6tbuf, mcaddr), ifp, ifp->if_xname);

	error = 0;
	inm = NULL;

	
	if (imf == NULL) {
		im6f_init(&timf, MCAST_UNDEFINED, MCAST_EXCLUDE);
		imf = &timf;
	}

	error = in6_mc_get(ifp, mcaddr, &inm);
	if (error) {
		CTR1(KTR_MLD, "%s: in6_mc_get() failure", __func__);
		return (error);
	}

	CTR1(KTR_MLD, "%s: merge inm state", __func__);
	error = in6m_merge(inm, imf);
	if (error) {
		CTR1(KTR_MLD, "%s: failed to merge inm state", __func__);
		goto out_in6m_release;
	}

	CTR1(KTR_MLD, "%s: doing mld downcall", __func__);
	error = mld_change_state(inm, delay);
	if (error) {
		CTR1(KTR_MLD, "%s: failed to update source", __func__);
		goto out_in6m_release;
	}

out_in6m_release:
	if (error) {
		CTR2(KTR_MLD, "%s: dropping ref on %p", __func__, inm);
		in6m_release_locked(inm);
	} else {
		*pinm = inm;
	}

	return (error);
}


int in6_mc_leave(struct in6_multi *inm,  struct in6_mfilter *imf)
{
	struct ifnet *ifp;
	int error;

	ifp = inm->in6m_ifp;

	IN6_MULTI_LOCK();
	error = in6_mc_leave_locked(inm, imf);
	IN6_MULTI_UNLOCK();

	return (error);
}


int in6_mc_leave_locked(struct in6_multi *inm,  struct in6_mfilter *imf)
{
	struct in6_mfilter	 timf;
	int			 error;

	char			 ip6tbuf[INET6_ADDRSTRLEN];


	error = 0;

	IN6_MULTI_LOCK_ASSERT();

	CTR5(KTR_MLD, "%s: leave inm %p, %s/%s, imf %p", __func__, inm, ip6_sprintf(ip6tbuf, &inm->in6m_addr), (in6m_is_ifp_detached(inm) ? "null" : inm->in6m_ifp->if_xname), imf);



	
	if (imf == NULL) {
		im6f_init(&timf, MCAST_EXCLUDE, MCAST_UNDEFINED);
		imf = &timf;
	}

	
	CTR1(KTR_MLD, "%s: merge inm state", __func__);
	error = in6m_merge(inm, imf);
	KASSERT(error == 0, ("%s: failed to merge inm state", __func__));

	CTR1(KTR_MLD, "%s: doing mld downcall", __func__);
	error = mld_change_state(inm, 0);
	if (error)
		CTR1(KTR_MLD, "%s: failed mld downcall", __func__);

	CTR2(KTR_MLD, "%s: dropping ref on %p", __func__, inm);
	in6m_release_locked(inm);

	return (error);
}


static int in6p_block_unblock_source(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req		 gsr;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in6_mfilter		*imf;
	struct ip6_moptions		*imo;
	struct in6_msource		*ims;
	struct in6_multi			*inm;
	size_t				 idx;
	uint16_t			 fmode;
	int				 error, doblock;

	char				 ip6tbuf[INET6_ADDRSTRLEN];


	ifp = NULL;
	error = 0;
	doblock = 0;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	ssa = (sockunion_t *)&gsr.gsr_source;

	switch (sopt->sopt_name) {
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		error = sooptcopyin(sopt, &gsr, sizeof(struct group_source_req), sizeof(struct group_source_req));

		if (error)
			return (error);

		if (gsa->sin6.sin6_family != AF_INET6 || gsa->sin6.sin6_len != sizeof(struct sockaddr_in6))
			return (EINVAL);

		if (ssa->sin6.sin6_family != AF_INET6 || ssa->sin6.sin6_len != sizeof(struct sockaddr_in6))
			return (EINVAL);

		if (gsr.gsr_interface == 0 || V_if_index < gsr.gsr_interface)
			return (EADDRNOTAVAIL);

		ifp = ifnet_byindex(gsr.gsr_interface);

		if (sopt->sopt_name == MCAST_BLOCK_SOURCE)
			doblock = 1;
		break;

	default:
		CTR2(KTR_MLD, "%s: unknown sopt_name %d", __func__, sopt->sopt_name);
		return (EOPNOTSUPP);
		break;
	}

	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	(void)in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);

	
	imo = in6p_findmoptions(inp);
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == -1 || imo->im6o_mfilters == NULL) {
		error = EADDRNOTAVAIL;
		goto out_in6p_locked;
	}

	KASSERT(imo->im6o_mfilters != NULL, ("%s: im6o_mfilters not allocated", __func__));
	imf = &imo->im6o_mfilters[idx];
	inm = imo->im6o_membership[idx];

	
	fmode = imf->im6f_st[0];
	if (fmode != MCAST_EXCLUDE) {
		error = EINVAL;
		goto out_in6p_locked;
	}

	
	ims = im6o_match_source(imo, idx, &ssa->sa);
	if ((ims != NULL && doblock) || (ims == NULL && !doblock)) {
		CTR3(KTR_MLD, "%s: source %s %spresent", __func__, ip6_sprintf(ip6tbuf, &ssa->sin6.sin6_addr), doblock ? "" : "not ");

		error = EADDRNOTAVAIL;
		goto out_in6p_locked;
	}

	INP_WLOCK_ASSERT(inp);

	
	if (doblock) {
		CTR2(KTR_MLD, "%s: %s source", __func__, "block");
		ims = im6f_graft(imf, fmode, &ssa->sin6);
		if (ims == NULL)
			error = ENOMEM;
	} else {
		CTR2(KTR_MLD, "%s: %s source", __func__, "allow");
		error = im6f_prune(imf, &ssa->sin6);
	}

	if (error) {
		CTR1(KTR_MLD, "%s: merge imf state failed", __func__);
		goto out_im6f_rollback;
	}

	
	IN6_MULTI_LOCK();

	CTR1(KTR_MLD, "%s: merge inm state", __func__);
	error = in6m_merge(inm, imf);
	if (error) {
		CTR1(KTR_MLD, "%s: failed to merge inm state", __func__);
		goto out_im6f_rollback;
	}

	CTR1(KTR_MLD, "%s: doing mld downcall", __func__);
	error = mld_change_state(inm, 0);
	if (error)
		CTR1(KTR_MLD, "%s: failed mld downcall", __func__);

	IN6_MULTI_UNLOCK();

out_im6f_rollback:
	if (error)
		im6f_rollback(imf);
	else im6f_commit(imf);

	im6f_reap(imf);

out_in6p_locked:
	INP_WUNLOCK(inp);
	return (error);
}


static struct ip6_moptions * in6p_findmoptions(struct inpcb *inp)
{
	struct ip6_moptions	 *imo;
	struct in6_multi		**immp;
	struct in6_mfilter	 *imfp;
	size_t			  idx;

	INP_WLOCK(inp);
	if (inp->in6p_moptions != NULL)
		return (inp->in6p_moptions);

	INP_WUNLOCK(inp);

	imo = malloc(sizeof(*imo), M_IP6MOPTS, M_WAITOK);
	immp = malloc(sizeof(*immp) * IPV6_MIN_MEMBERSHIPS, M_IP6MOPTS, M_WAITOK | M_ZERO);
	imfp = malloc(sizeof(struct in6_mfilter) * IPV6_MIN_MEMBERSHIPS, M_IN6MFILTER, M_WAITOK);

	imo->im6o_multicast_ifp = NULL;
	imo->im6o_multicast_hlim = V_ip6_defmcasthlim;
	imo->im6o_multicast_loop = in6_mcast_loop;
	imo->im6o_num_memberships = 0;
	imo->im6o_max_memberships = IPV6_MIN_MEMBERSHIPS;
	imo->im6o_membership = immp;

	
	for (idx = 0; idx < IPV6_MIN_MEMBERSHIPS; idx++)
		im6f_init(&imfp[idx], MCAST_UNDEFINED, MCAST_EXCLUDE);
	imo->im6o_mfilters = imfp;

	INP_WLOCK(inp);
	if (inp->in6p_moptions != NULL) {
		free(imfp, M_IN6MFILTER);
		free(immp, M_IP6MOPTS);
		free(imo, M_IP6MOPTS);
		return (inp->in6p_moptions);
	}
	inp->in6p_moptions = imo;
	return (imo);
}


void ip6_freemoptions(struct ip6_moptions *imo)
{
	struct in6_mfilter	*imf;
	size_t			 idx, nmships;

	KASSERT(imo != NULL, ("%s: ip6_moptions is NULL", __func__));

	nmships = imo->im6o_num_memberships;
	for (idx = 0; idx < nmships; ++idx) {
		imf = imo->im6o_mfilters ? &imo->im6o_mfilters[idx] : NULL;
		if (imf)
			im6f_leave(imf);
		
		(void)in6_mc_leave(imo->im6o_membership[idx], imf);
		if (imf)
			im6f_purge(imf);
	}

	if (imo->im6o_mfilters)
		free(imo->im6o_mfilters, M_IN6MFILTER);
	free(imo->im6o_membership, M_IP6MOPTS);
	free(imo, M_IP6MOPTS);
}


static int in6p_get_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq	 msfr;
	sockunion_t		*gsa;
	struct ifnet		*ifp;
	struct ip6_moptions	*imo;
	struct in6_mfilter	*imf;
	struct ip6_msource	*ims;
	struct in6_msource	*lims;
	struct sockaddr_in6	*psin;
	struct sockaddr_storage	*ptss;
	struct sockaddr_storage	*tss;
	int			 error;
	size_t			 idx, nsrcs, ncsrcs;

	INP_WLOCK_ASSERT(inp);

	imo = inp->in6p_moptions;
	KASSERT(imo != NULL, ("%s: null ip6_moptions", __func__));

	INP_WUNLOCK(inp);

	error = sooptcopyin(sopt, &msfr, sizeof(struct __msfilterreq), sizeof(struct __msfilterreq));
	if (error)
		return (error);

	if (msfr.msfr_group.ss_family != AF_INET6 || msfr.msfr_group.ss_len != sizeof(struct sockaddr_in6))
		return (EINVAL);

	gsa = (sockunion_t *)&msfr.msfr_group;
	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	if (msfr.msfr_ifindex == 0 || V_if_index < msfr.msfr_ifindex)
		return (EADDRNOTAVAIL);
	ifp = ifnet_byindex(msfr.msfr_ifindex);
	if (ifp == NULL)
		return (EADDRNOTAVAIL);
	(void)in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);

	INP_WLOCK(inp);

	
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == -1 || imo->im6o_mfilters == NULL) {
		INP_WUNLOCK(inp);
		return (EADDRNOTAVAIL);
	}
	imf = &imo->im6o_mfilters[idx];

	
	if (imf->im6f_st[1] == MCAST_UNDEFINED) {
		INP_WUNLOCK(inp);
		return (EAGAIN);
	}
	msfr.msfr_fmode = imf->im6f_st[1];

	
	tss = NULL;
	if (msfr.msfr_srcs != NULL && msfr.msfr_nsrcs > 0) {
		tss = malloc(sizeof(struct sockaddr_storage) * msfr.msfr_nsrcs, M_TEMP, M_NOWAIT | M_ZERO);
		if (tss == NULL) {
			INP_WUNLOCK(inp);
			return (ENOBUFS);
		}
	}

	
	nsrcs = msfr.msfr_nsrcs;
	ncsrcs = 0;
	ptss = tss;
	RB_FOREACH(ims, ip6_msource_tree, &imf->im6f_sources) {
		lims = (struct in6_msource *)ims;
		if (lims->im6sl_st[0] == MCAST_UNDEFINED || lims->im6sl_st[0] != imf->im6f_st[0])
			continue;
		++ncsrcs;
		if (tss != NULL && nsrcs > 0) {
			psin = (struct sockaddr_in6 *)ptss;
			psin->sin6_family = AF_INET6;
			psin->sin6_len = sizeof(struct sockaddr_in6);
			psin->sin6_addr = lims->im6s_addr;
			psin->sin6_port = 0;
			--nsrcs;
			++ptss;
		}
	}

	INP_WUNLOCK(inp);

	if (tss != NULL) {
		error = copyout(tss, msfr.msfr_srcs, sizeof(struct sockaddr_storage) * msfr.msfr_nsrcs);
		free(tss, M_TEMP);
		if (error)
			return (error);
	}

	msfr.msfr_nsrcs = ncsrcs;
	error = sooptcopyout(sopt, &msfr, sizeof(struct __msfilterreq));

	return (error);
}


int ip6_getmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ip6_moptions	*im6o;
	int			 error;
	u_int			 optval;

	INP_WLOCK(inp);
	im6o = inp->in6p_moptions;
	
	if (inp->inp_socket->so_proto->pr_protocol == IPPROTO_DIVERT || (inp->inp_socket->so_proto->pr_type != SOCK_RAW && inp->inp_socket->so_proto->pr_type != SOCK_DGRAM)) {

		INP_WUNLOCK(inp);
		return (EOPNOTSUPP);
	}

	error = 0;
	switch (sopt->sopt_name) {
	case IPV6_MULTICAST_IF:
		if (im6o == NULL || im6o->im6o_multicast_ifp == NULL) {
			optval = 0;
		} else {
			optval = im6o->im6o_multicast_ifp->if_index;
		}
		INP_WUNLOCK(inp);
		error = sooptcopyout(sopt, &optval, sizeof(u_int));
		break;

	case IPV6_MULTICAST_HOPS:
		if (im6o == NULL)
			optval = V_ip6_defmcasthlim;
		else optval = im6o->im6o_multicast_hlim;
		INP_WUNLOCK(inp);
		error = sooptcopyout(sopt, &optval, sizeof(u_int));
		break;

	case IPV6_MULTICAST_LOOP:
		if (im6o == NULL)
			optval = in6_mcast_loop; 
		else optval = im6o->im6o_multicast_loop;
		INP_WUNLOCK(inp);
		error = sooptcopyout(sopt, &optval, sizeof(u_int));
		break;

	case IPV6_MSFILTER:
		if (im6o == NULL) {
			error = EADDRNOTAVAIL;
			INP_WUNLOCK(inp);
		} else {
			error = in6p_get_source_filters(inp, sopt);
		}
		break;

	default:
		INP_WUNLOCK(inp);
		error = ENOPROTOOPT;
		break;
	}

	INP_UNLOCK_ASSERT(inp);

	return (error);
}


static struct ifnet * in6p_lookup_mcast_ifp(const struct inpcb *in6p, const struct sockaddr_in6 *gsin6)

{
	struct route_in6	 ro6;
	struct ifnet		*ifp;

	KASSERT(in6p->inp_vflag & INP_IPV6, ("%s: not INP_IPV6 inpcb", __func__));
	KASSERT(gsin6->sin6_family == AF_INET6, ("%s: not AF_INET6 group", __func__));
	KASSERT(IN6_IS_ADDR_MULTICAST(&gsin6->sin6_addr), ("%s: not multicast", __func__));

	ifp = NULL;
	memset(&ro6, 0, sizeof(struct route_in6));
	memcpy(&ro6.ro_dst, gsin6, sizeof(struct sockaddr_in6));
	rtalloc_ign_fib((struct route *)&ro6, 0, in6p ? in6p->inp_inc.inc_fibnum : RT_DEFAULT_FIB);
	if (ro6.ro_rt != NULL) {
		ifp = ro6.ro_rt->rt_ifp;
		KASSERT(ifp != NULL, ("%s: null ifp", __func__));
		RTFREE(ro6.ro_rt);
	}

	return (ifp);
}


static int in6p_join_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req		 gsr;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in6_mfilter		*imf;
	struct ip6_moptions		*imo;
	struct in6_multi		*inm;
	struct in6_msource		*lims;
	size_t				 idx;
	int				 error, is_new;

	ifp = NULL;
	imf = NULL;
	lims = NULL;
	error = 0;
	is_new = 0;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	gsa->ss.ss_family = AF_UNSPEC;
	ssa = (sockunion_t *)&gsr.gsr_source;
	ssa->ss.ss_family = AF_UNSPEC;

	
	switch (sopt->sopt_name) {
	case IPV6_JOIN_GROUP: {
		struct ipv6_mreq mreq;

		error = sooptcopyin(sopt, &mreq, sizeof(struct ipv6_mreq), sizeof(struct ipv6_mreq));
		if (error)
			return (error);

		gsa->sin6.sin6_family = AF_INET6;
		gsa->sin6.sin6_len = sizeof(struct sockaddr_in6);
		gsa->sin6.sin6_addr = mreq.ipv6mr_multiaddr;

		if (mreq.ipv6mr_interface == 0) {
			ifp = in6p_lookup_mcast_ifp(inp, &gsa->sin6);
		} else {
			if (mreq.ipv6mr_interface < 0 || V_if_index < mreq.ipv6mr_interface)
				return (EADDRNOTAVAIL);
			ifp = ifnet_byindex(mreq.ipv6mr_interface);
		}
		CTR3(KTR_MLD, "%s: ipv6mr_interface = %d, ifp = %p", __func__, mreq.ipv6mr_interface, ifp);
	} break;

	case MCAST_JOIN_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
		if (sopt->sopt_name == MCAST_JOIN_GROUP) {
			error = sooptcopyin(sopt, &gsr, sizeof(struct group_req), sizeof(struct group_req));

		} else if (sopt->sopt_name == MCAST_JOIN_SOURCE_GROUP) {
			error = sooptcopyin(sopt, &gsr, sizeof(struct group_source_req), sizeof(struct group_source_req));

		}
		if (error)
			return (error);

		if (gsa->sin6.sin6_family != AF_INET6 || gsa->sin6.sin6_len != sizeof(struct sockaddr_in6))
			return (EINVAL);

		if (sopt->sopt_name == MCAST_JOIN_SOURCE_GROUP) {
			if (ssa->sin6.sin6_family != AF_INET6 || ssa->sin6.sin6_len != sizeof(struct sockaddr_in6))
				return (EINVAL);
			if (IN6_IS_ADDR_MULTICAST(&ssa->sin6.sin6_addr))
				return (EINVAL);
			
			in6_clearscope(&ssa->sin6.sin6_addr);
			ssa->sin6.sin6_port = 0;
			ssa->sin6.sin6_scope_id = 0;
		}

		if (gsr.gsr_interface == 0 || V_if_index < gsr.gsr_interface)
			return (EADDRNOTAVAIL);
		ifp = ifnet_byindex(gsr.gsr_interface);
		break;

	default:
		CTR2(KTR_MLD, "%s: unknown sopt_name %d", __func__, sopt->sopt_name);
		return (EOPNOTSUPP);
		break;
	}

	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0)
		return (EADDRNOTAVAIL);

	gsa->sin6.sin6_port = 0;
	gsa->sin6.sin6_scope_id = 0;

	
	(void)in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);

	imo = in6p_findmoptions(inp);
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == -1) {
		is_new = 1;
	} else {
		inm = imo->im6o_membership[idx];
		imf = &imo->im6o_mfilters[idx];
		if (ssa->ss.ss_family != AF_UNSPEC) {
			
			if (imf->im6f_st[1] != MCAST_INCLUDE) {
				error = EINVAL;
				goto out_in6p_locked;
			}
			
			lims = im6o_match_source(imo, idx, &ssa->sa);
			if (lims != NULL ) {
				error = EADDRNOTAVAIL;
				goto out_in6p_locked;
			}
		} else {
			
			error = EINVAL;
			goto out_in6p_locked;
		}
	}

	
	INP_WLOCK_ASSERT(inp);

	if (is_new) {
		if (imo->im6o_num_memberships == imo->im6o_max_memberships) {
			error = im6o_grow(imo);
			if (error)
				goto out_in6p_locked;
		}
		
		idx = imo->im6o_num_memberships;
		imo->im6o_membership[idx] = NULL;
		imo->im6o_num_memberships++;
		KASSERT(imo->im6o_mfilters != NULL, ("%s: im6f_mfilters vector was not allocated", __func__));
		imf = &imo->im6o_mfilters[idx];
		KASSERT(RB_EMPTY(&imf->im6f_sources), ("%s: im6f_sources not empty", __func__));
	}

	
	if (ssa->ss.ss_family != AF_UNSPEC) {
		
		if (is_new) {
			CTR1(KTR_MLD, "%s: new join w/source", __func__);
			im6f_init(imf, MCAST_UNDEFINED, MCAST_INCLUDE);
		} else {
			CTR2(KTR_MLD, "%s: %s source", __func__, "allow");
		}
		lims = im6f_graft(imf, MCAST_INCLUDE, &ssa->sin6);
		if (lims == NULL) {
			CTR1(KTR_MLD, "%s: merge imf state failed", __func__);
			error = ENOMEM;
			goto out_im6o_free;
		}
	} else {
		
		if (is_new) {
			CTR1(KTR_MLD, "%s: new join w/o source", __func__);
			im6f_init(imf, MCAST_UNDEFINED, MCAST_EXCLUDE);
		}
	}

	
	IN6_MULTI_LOCK();

	if (is_new) {
		error = in6_mc_join_locked(ifp, &gsa->sin6.sin6_addr, imf, &inm, 0);
		if (error)
			goto out_im6o_free;
		imo->im6o_membership[idx] = inm;
	} else {
		CTR1(KTR_MLD, "%s: merge inm state", __func__);
		error = in6m_merge(inm, imf);
		if (error) {
			CTR1(KTR_MLD, "%s: failed to merge inm state", __func__);
			goto out_im6f_rollback;
		}
		CTR1(KTR_MLD, "%s: doing mld downcall", __func__);
		error = mld_change_state(inm, 0);
		if (error) {
			CTR1(KTR_MLD, "%s: failed mld downcall", __func__);
			goto out_im6f_rollback;
		}
	}

	IN6_MULTI_UNLOCK();

out_im6f_rollback:
	INP_WLOCK_ASSERT(inp);
	if (error) {
		im6f_rollback(imf);
		if (is_new)
			im6f_purge(imf);
		else im6f_reap(imf);
	} else {
		im6f_commit(imf);
	}

out_im6o_free:
	if (error && is_new) {
		imo->im6o_membership[idx] = NULL;
		--imo->im6o_num_memberships;
	}

out_in6p_locked:
	INP_WUNLOCK(inp);
	return (error);
}


static int in6p_leave_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct ipv6_mreq		 mreq;
	struct group_source_req		 gsr;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in6_mfilter		*imf;
	struct ip6_moptions		*imo;
	struct in6_msource		*ims;
	struct in6_multi		*inm;
	uint32_t			 ifindex;
	size_t				 idx;
	int				 error, is_final;

	char				 ip6tbuf[INET6_ADDRSTRLEN];


	ifp = NULL;
	ifindex = 0;
	error = 0;
	is_final = 1;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	gsa->ss.ss_family = AF_UNSPEC;
	ssa = (sockunion_t *)&gsr.gsr_source;
	ssa->ss.ss_family = AF_UNSPEC;

	
	switch (sopt->sopt_name) {
	case IPV6_LEAVE_GROUP:
		error = sooptcopyin(sopt, &mreq, sizeof(struct ipv6_mreq), sizeof(struct ipv6_mreq));
		if (error)
			return (error);
		gsa->sin6.sin6_family = AF_INET6;
		gsa->sin6.sin6_len = sizeof(struct sockaddr_in6);
		gsa->sin6.sin6_addr = mreq.ipv6mr_multiaddr;
		gsa->sin6.sin6_port = 0;
		gsa->sin6.sin6_scope_id = 0;
		ifindex = mreq.ipv6mr_interface;
		break;

	case MCAST_LEAVE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
		if (sopt->sopt_name == MCAST_LEAVE_GROUP) {
			error = sooptcopyin(sopt, &gsr, sizeof(struct group_req), sizeof(struct group_req));

		} else if (sopt->sopt_name == MCAST_LEAVE_SOURCE_GROUP) {
			error = sooptcopyin(sopt, &gsr, sizeof(struct group_source_req), sizeof(struct group_source_req));

		}
		if (error)
			return (error);

		if (gsa->sin6.sin6_family != AF_INET6 || gsa->sin6.sin6_len != sizeof(struct sockaddr_in6))
			return (EINVAL);
		if (sopt->sopt_name == MCAST_LEAVE_SOURCE_GROUP) {
			if (ssa->sin6.sin6_family != AF_INET6 || ssa->sin6.sin6_len != sizeof(struct sockaddr_in6))
				return (EINVAL);
			if (IN6_IS_ADDR_MULTICAST(&ssa->sin6.sin6_addr))
				return (EINVAL);
			
			in6_clearscope(&ssa->sin6.sin6_addr);
		}
		gsa->sin6.sin6_port = 0;
		gsa->sin6.sin6_scope_id = 0;
		ifindex = gsr.gsr_interface;
		break;

	default:
		CTR2(KTR_MLD, "%s: unknown sopt_name %d", __func__, sopt->sopt_name);
		return (EOPNOTSUPP);
		break;
	}

	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	
	if (ifindex != 0) {
		if (ifindex < 0 || V_if_index < ifindex)
			return (EADDRNOTAVAIL);
		ifp = ifnet_byindex(ifindex);
		if (ifp == NULL)
			return (EADDRNOTAVAIL);
		(void)in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);
	} else {
		error = sa6_embedscope(&gsa->sin6, V_ip6_use_defzone);
		if (error)
			return (EADDRNOTAVAIL);
		
		ifindex = ntohs(gsa->sin6.sin6_addr.s6_addr16[1]);
		if (ifindex == 0) {
			CTR2(KTR_MLD, "%s: warning: no ifindex, looking up " "ifp for group %s.", __func__, ip6_sprintf(ip6tbuf, &gsa->sin6.sin6_addr));

			ifp = in6p_lookup_mcast_ifp(inp, &gsa->sin6);
		} else {
			ifp = ifnet_byindex(ifindex);
		}
		if (ifp == NULL)
			return (EADDRNOTAVAIL);
	}

	CTR2(KTR_MLD, "%s: ifp = %p", __func__, ifp);
	KASSERT(ifp != NULL, ("%s: ifp did not resolve", __func__));

	
	imo = in6p_findmoptions(inp);
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == -1) {
		error = EADDRNOTAVAIL;
		goto out_in6p_locked;
	}
	inm = imo->im6o_membership[idx];
	imf = &imo->im6o_mfilters[idx];

	if (ssa->ss.ss_family != AF_UNSPEC)
		is_final = 0;

	
	INP_WLOCK_ASSERT(inp);

	
	if (is_final) {
		im6f_leave(imf);
	} else {
		if (imf->im6f_st[0] == MCAST_EXCLUDE) {
			error = EADDRNOTAVAIL;
			goto out_in6p_locked;
		}
		ims = im6o_match_source(imo, idx, &ssa->sa);
		if (ims == NULL) {
			CTR3(KTR_MLD, "%s: source %p %spresent", __func__, ip6_sprintf(ip6tbuf, &ssa->sin6.sin6_addr), "not ");

			error = EADDRNOTAVAIL;
			goto out_in6p_locked;
		}
		CTR2(KTR_MLD, "%s: %s source", __func__, "block");
		error = im6f_prune(imf, &ssa->sin6);
		if (error) {
			CTR1(KTR_MLD, "%s: merge imf state failed", __func__);
			goto out_in6p_locked;
		}
	}

	
	IN6_MULTI_LOCK();

	if (is_final) {
		
		(void)in6_mc_leave_locked(inm, imf);
	} else {
		CTR1(KTR_MLD, "%s: merge inm state", __func__);
		error = in6m_merge(inm, imf);
		if (error) {
			CTR1(KTR_MLD, "%s: failed to merge inm state", __func__);
			goto out_im6f_rollback;
		}

		CTR1(KTR_MLD, "%s: doing mld downcall", __func__);
		error = mld_change_state(inm, 0);
		if (error) {
			CTR1(KTR_MLD, "%s: failed mld downcall", __func__);
		}
	}

	IN6_MULTI_UNLOCK();

out_im6f_rollback:
	if (error)
		im6f_rollback(imf);
	else im6f_commit(imf);

	im6f_reap(imf);

	if (is_final) {
		
		for (++idx; idx < imo->im6o_num_memberships; ++idx) {
			imo->im6o_membership[idx-1] = imo->im6o_membership[idx];
			imo->im6o_mfilters[idx-1] = imo->im6o_mfilters[idx];
		}
		imo->im6o_num_memberships--;
	}

out_in6p_locked:
	INP_WUNLOCK(inp);
	return (error);
}


static int in6p_set_multicast_if(struct inpcb *inp, struct sockopt *sopt)
{
	struct ifnet		*ifp;
	struct ip6_moptions	*imo;
	u_int			 ifindex;
	int			 error;

	if (sopt->sopt_valsize != sizeof(u_int))
		return (EINVAL);

	error = sooptcopyin(sopt, &ifindex, sizeof(u_int), sizeof(u_int));
	if (error)
		return (error);
	if (ifindex < 0 || V_if_index < ifindex)
		return (EINVAL);

	ifp = ifnet_byindex(ifindex);
	if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0)
		return (EADDRNOTAVAIL);

	imo = in6p_findmoptions(inp);
	imo->im6o_multicast_ifp = ifp;
	INP_WUNLOCK(inp);

	return (0);
}


static int in6p_set_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq	 msfr;
	sockunion_t		*gsa;
	struct ifnet		*ifp;
	struct in6_mfilter	*imf;
	struct ip6_moptions	*imo;
	struct in6_multi		*inm;
	size_t			 idx;
	int			 error;

	error = sooptcopyin(sopt, &msfr, sizeof(struct __msfilterreq), sizeof(struct __msfilterreq));
	if (error)
		return (error);

	if (msfr.msfr_nsrcs > in6_mcast_maxsocksrc)
		return (ENOBUFS);

	if (msfr.msfr_fmode != MCAST_EXCLUDE && msfr.msfr_fmode != MCAST_INCLUDE)
		return (EINVAL);

	if (msfr.msfr_group.ss_family != AF_INET6 || msfr.msfr_group.ss_len != sizeof(struct sockaddr_in6))
		return (EINVAL);

	gsa = (sockunion_t *)&msfr.msfr_group;
	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	gsa->sin6.sin6_port = 0;	

	if (msfr.msfr_ifindex == 0 || V_if_index < msfr.msfr_ifindex)
		return (EADDRNOTAVAIL);
	ifp = ifnet_byindex(msfr.msfr_ifindex);
	if (ifp == NULL)
		return (EADDRNOTAVAIL);
	(void)in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);

	
	imo = in6p_findmoptions(inp);
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == -1 || imo->im6o_mfilters == NULL) {
		error = EADDRNOTAVAIL;
		goto out_in6p_locked;
	}
	inm = imo->im6o_membership[idx];
	imf = &imo->im6o_mfilters[idx];

	
	INP_WLOCK_ASSERT(inp);

	imf->im6f_st[1] = msfr.msfr_fmode;

	
	if (msfr.msfr_nsrcs > 0) {
		struct in6_msource	*lims;
		struct sockaddr_in6	*psin;
		struct sockaddr_storage	*kss, *pkss;
		int			 i;

		INP_WUNLOCK(inp);
 
		CTR2(KTR_MLD, "%s: loading %lu source list entries", __func__, (unsigned long)msfr.msfr_nsrcs);
		kss = malloc(sizeof(struct sockaddr_storage) * msfr.msfr_nsrcs, M_TEMP, M_WAITOK);
		error = copyin(msfr.msfr_srcs, kss, sizeof(struct sockaddr_storage) * msfr.msfr_nsrcs);
		if (error) {
			free(kss, M_TEMP);
			return (error);
		}

		INP_WLOCK(inp);

		
		im6f_leave(imf);
		imf->im6f_st[1] = msfr.msfr_fmode;

		
		for (i = 0, pkss = kss; i < msfr.msfr_nsrcs; i++, pkss++) {
			psin = (struct sockaddr_in6 *)pkss;
			if (psin->sin6_family != AF_INET6) {
				error = EAFNOSUPPORT;
				break;
			}
			if (psin->sin6_len != sizeof(struct sockaddr_in6)) {
				error = EINVAL;
				break;
			}
			if (IN6_IS_ADDR_MULTICAST(&psin->sin6_addr)) {
				error = EINVAL;
				break;
			}
			
			in6_clearscope(&psin->sin6_addr);
			error = im6f_get_source(imf, psin, &lims);
			if (error)
				break;
			lims->im6sl_st[1] = imf->im6f_st[1];
		}
		free(kss, M_TEMP);
	}

	if (error)
		goto out_im6f_rollback;

	INP_WLOCK_ASSERT(inp);
	IN6_MULTI_LOCK();

	
	CTR1(KTR_MLD, "%s: merge inm state", __func__);
	error = in6m_merge(inm, imf);
	if (error) {
		CTR1(KTR_MLD, "%s: failed to merge inm state", __func__);
		goto out_im6f_rollback;
	}

	CTR1(KTR_MLD, "%s: doing mld downcall", __func__);
	error = mld_change_state(inm, 0);
	if (error)
		CTR1(KTR_MLD, "%s: failed mld downcall", __func__);

	IN6_MULTI_UNLOCK();

out_im6f_rollback:
	if (error)
		im6f_rollback(imf);
	else im6f_commit(imf);

	im6f_reap(imf);

out_in6p_locked:
	INP_WUNLOCK(inp);
	return (error);
}


int ip6_setmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ip6_moptions	*im6o;
	int			 error;

	error = 0;

	
	if (inp->inp_socket->so_proto->pr_protocol == IPPROTO_DIVERT || (inp->inp_socket->so_proto->pr_type != SOCK_RAW && inp->inp_socket->so_proto->pr_type != SOCK_DGRAM))

		return (EOPNOTSUPP);

	switch (sopt->sopt_name) {
	case IPV6_MULTICAST_IF:
		error = in6p_set_multicast_if(inp, sopt);
		break;

	case IPV6_MULTICAST_HOPS: {
		int hlim;

		if (sopt->sopt_valsize != sizeof(int)) {
			error = EINVAL;
			break;
		}
		error = sooptcopyin(sopt, &hlim, sizeof(hlim), sizeof(int));
		if (error)
			break;
		if (hlim < -1 || hlim > 255) {
			error = EINVAL;
			break;
		} else if (hlim == -1) {
			hlim = V_ip6_defmcasthlim;
		}
		im6o = in6p_findmoptions(inp);
		im6o->im6o_multicast_hlim = hlim;
		INP_WUNLOCK(inp);
		break;
	}

	case IPV6_MULTICAST_LOOP: {
		u_int loop;

		
		if (sopt->sopt_valsize != sizeof(u_int)) {
			error = EINVAL;
			break;
		}
		error = sooptcopyin(sopt, &loop, sizeof(u_int), sizeof(u_int));
		if (error)
			break;
		if (loop > 1) {
			error = EINVAL;
			break;
		}
		im6o = in6p_findmoptions(inp);
		im6o->im6o_multicast_loop = loop;
		INP_WUNLOCK(inp);
		break;
	}

	case IPV6_JOIN_GROUP:
	case MCAST_JOIN_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
		error = in6p_join_group(inp, sopt);
		break;

	case IPV6_LEAVE_GROUP:
	case MCAST_LEAVE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
		error = in6p_leave_group(inp, sopt);
		break;

	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		error = in6p_block_unblock_source(inp, sopt);
		break;

	case IPV6_MSFILTER:
		error = in6p_set_source_filters(inp, sopt);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	INP_UNLOCK_ASSERT(inp);

	return (error);
}


static int sysctl_ip6_mcast_filters(SYSCTL_HANDLER_ARGS)
{
	struct in6_addr			 mcaddr;
	struct in6_addr			 src;
	struct ifnet			*ifp;
	struct ifmultiaddr		*ifma;
	struct in6_multi		*inm;
	struct ip6_msource		*ims;
	int				*name;
	int				 retval;
	u_int				 namelen;
	uint32_t			 fmode, ifindex;

	char				 ip6tbuf[INET6_ADDRSTRLEN];


	name = (int *)arg1;
	namelen = arg2;

	if (req->newptr != NULL)
		return (EPERM);

	
	if (namelen != 5)
		return (EINVAL);

	ifindex = name[0];
	if (ifindex <= 0 || ifindex > V_if_index) {
		CTR2(KTR_MLD, "%s: ifindex %u out of range", __func__, ifindex);
		return (ENOENT);
	}

	memcpy(&mcaddr, &name[1], sizeof(struct in6_addr));
	if (!IN6_IS_ADDR_MULTICAST(&mcaddr)) {
		CTR2(KTR_MLD, "%s: group %s is not multicast", __func__, ip6_sprintf(ip6tbuf, &mcaddr));
		return (EINVAL);
	}

	ifp = ifnet_byindex(ifindex);
	if (ifp == NULL) {
		CTR2(KTR_MLD, "%s: no ifp for ifindex %u", __func__, ifindex);
		return (ENOENT);
	}
	
	(void)in6_setscope(&mcaddr, ifp, NULL);

	retval = sysctl_wire_old_buffer(req, sizeof(uint32_t) + (in6_mcast_maxgrpsrc * sizeof(struct in6_addr)));
	if (retval)
		return (retval);

	IN6_MULTI_LOCK();

	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_INET6 || ifma->ifma_protospec == NULL)
			continue;
		inm = (struct in6_multi *)ifma->ifma_protospec;
		if (!IN6_ARE_ADDR_EQUAL(&inm->in6m_addr, &mcaddr))
			continue;
		fmode = inm->in6m_st[1].iss_fmode;
		retval = SYSCTL_OUT(req, &fmode, sizeof(uint32_t));
		if (retval != 0)
			break;
		RB_FOREACH(ims, ip6_msource_tree, &inm->in6m_srcs) {
			CTR2(KTR_MLD, "%s: visit node %p", __func__, ims);
			
			if (fmode != im6s_get_mode(inm, ims, 1)) {
				CTR1(KTR_MLD, "%s: skip non-in-mode", __func__);
				continue;
			}
			src = ims->im6s_addr;
			retval = SYSCTL_OUT(req, &src, sizeof(struct in6_addr));
			if (retval != 0)
				break;
		}
	}
	IF_ADDR_RUNLOCK(ifp);

	IN6_MULTI_UNLOCK();

	return (retval);
}



static const char *in6m_modestrs[] = { "un", "in", "ex" };

static const char * in6m_mode_str(const int mode)
{

	if (mode >= MCAST_UNDEFINED && mode <= MCAST_EXCLUDE)
		return (in6m_modestrs[mode]);
	return ("??");
}

static const char *in6m_statestrs[] = {
	"not-member", "silent", "idle", "lazy", "sleeping", "awakening", "query-pending", "sg-query-pending", "leaving" };









static const char * in6m_state_str(const int state)
{

	if (state >= MLD_NOT_MEMBER && state <= MLD_LEAVING_MEMBER)
		return (in6m_statestrs[state]);
	return ("??");
}


void in6m_print(const struct in6_multi *inm)
{
	int t;
	char ip6tbuf[INET6_ADDRSTRLEN];

	if ((ktr_mask & KTR_MLD) == 0)
		return;

	printf("%s: --- begin in6m %p ---\n", __func__, inm);
	printf("addr %s ifp %p(%s) ifma %p\n", ip6_sprintf(ip6tbuf, &inm->in6m_addr), inm->in6m_ifp, inm->in6m_ifp->if_xname, inm->in6m_ifma);



	printf("timer %u state %s refcount %u scq.len %u\n", inm->in6m_timer, in6m_state_str(inm->in6m_state), inm->in6m_refcount, inm->in6m_scq.ifq_len);



	printf("mli %p nsrc %lu sctimer %u scrv %u\n", inm->in6m_mli, inm->in6m_nsrc, inm->in6m_sctimer, inm->in6m_scrv);



	for (t = 0; t < 2; t++) {
		printf("t%d: fmode %s asm %u ex %u in %u rec %u\n", t, in6m_mode_str(inm->in6m_st[t].iss_fmode), inm->in6m_st[t].iss_asm, inm->in6m_st[t].iss_ex, inm->in6m_st[t].iss_in, inm->in6m_st[t].iss_rec);




	}
	printf("%s: --- end in6m %p ---\n", __func__, inm);
}



void in6m_print(const struct in6_multi *inm)
{

}

