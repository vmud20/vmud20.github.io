




__FBSDID("$FreeBSD$");
































union sockunion {
	struct sockaddr_storage	ss;
	struct sockaddr		sa;
	struct sockaddr_dl	sdl;
	struct sockaddr_in	sin;
};
typedef union sockunion sockunion_t;



static MALLOC_DEFINE(M_INMFILTER, "in_mfilter", "IPv4 multicast PCB-layer source filter");
static MALLOC_DEFINE(M_IPMADDR, "in_multi", "IPv4 multicast group");
static MALLOC_DEFINE(M_IPMOPTS, "ip_moptions", "IPv4 multicast options");
static MALLOC_DEFINE(M_IPMSOURCE, "ip_msource", "IPv4 multicast IGMP-layer source filter");


struct mtx in_multi_mtx;
MTX_SYSINIT(in_multi_mtx, &in_multi_mtx, "in_multi_mtx", MTX_DEF);


static void	imf_commit(struct in_mfilter *);
static int	imf_get_source(struct in_mfilter *imf, const struct sockaddr_in *psin, struct in_msource **);

static struct in_msource * imf_graft(struct in_mfilter *, const uint8_t, const struct sockaddr_in *);

static void	imf_leave(struct in_mfilter *);
static int	imf_prune(struct in_mfilter *, const struct sockaddr_in *);
static void	imf_purge(struct in_mfilter *);
static void	imf_rollback(struct in_mfilter *);
static void	imf_reap(struct in_mfilter *);
static int	imo_grow(struct ip_moptions *);
static size_t	imo_match_group(const struct ip_moptions *, const struct ifnet *, const struct sockaddr *);
static struct in_msource * imo_match_source(const struct ip_moptions *, const size_t, const struct sockaddr *);

static void	ims_merge(struct ip_msource *ims, const struct in_msource *lims, const int rollback);
static int	in_getmulti(struct ifnet *, const struct in_addr *, struct in_multi **);
static int	inm_get_source(struct in_multi *inm, const in_addr_t haddr, const int noalloc, struct ip_msource **pims);
static int	inm_is_ifp_detached(const struct in_multi *);
static int	inm_merge(struct in_multi *,  struct in_mfilter *);
static void	inm_purge(struct in_multi *);
static void	inm_reap(struct in_multi *);
static struct ip_moptions * inp_findmoptions(struct inpcb *);
static void	inp_freemoptions_internal(struct ip_moptions *);
static void	inp_gcmoptions(void *, int);
static int	inp_get_source_filters(struct inpcb *, struct sockopt *);
static int	inp_join_group(struct inpcb *, struct sockopt *);
static int	inp_leave_group(struct inpcb *, struct sockopt *);
static struct ifnet * inp_lookup_mcast_ifp(const struct inpcb *, const struct sockaddr_in *, const struct in_addr);

static int	inp_block_unblock_source(struct inpcb *, struct sockopt *);
static int	inp_set_multicast_if(struct inpcb *, struct sockopt *);
static int	inp_set_source_filters(struct inpcb *, struct sockopt *);
static int	sysctl_ip_mcast_filters(SYSCTL_HANDLER_ARGS);

static SYSCTL_NODE(_net_inet_ip, OID_AUTO, mcast, CTLFLAG_RW, 0, "IPv4 multicast");

static u_long in_mcast_maxgrpsrc = IP_MAX_GROUP_SRC_FILTER;
SYSCTL_ULONG(_net_inet_ip_mcast, OID_AUTO, maxgrpsrc, CTLFLAG_RW | CTLFLAG_TUN, &in_mcast_maxgrpsrc, 0, "Max source filters per group");

TUNABLE_ULONG("net.inet.ip.mcast.maxgrpsrc", &in_mcast_maxgrpsrc);

static u_long in_mcast_maxsocksrc = IP_MAX_SOCK_SRC_FILTER;
SYSCTL_ULONG(_net_inet_ip_mcast, OID_AUTO, maxsocksrc, CTLFLAG_RW | CTLFLAG_TUN, &in_mcast_maxsocksrc, 0, "Max source filters per socket");

TUNABLE_ULONG("net.inet.ip.mcast.maxsocksrc", &in_mcast_maxsocksrc);

int in_mcast_loop = IP_DEFAULT_MULTICAST_LOOP;
SYSCTL_INT(_net_inet_ip_mcast, OID_AUTO, loop, CTLFLAG_RW | CTLFLAG_TUN, &in_mcast_loop, 0, "Loopback multicast datagrams by default");
TUNABLE_INT("net.inet.ip.mcast.loop", &in_mcast_loop);

static SYSCTL_NODE(_net_inet_ip_mcast, OID_AUTO, filters, CTLFLAG_RD | CTLFLAG_MPSAFE, sysctl_ip_mcast_filters, "Per-interface stack-wide source filters");


static STAILQ_HEAD(, ip_moptions) imo_gc_list = STAILQ_HEAD_INITIALIZER(imo_gc_list);
static struct task imo_gc_task = TASK_INITIALIZER(0, inp_gcmoptions, NULL);


static int __inline inm_is_ifp_detached(const struct in_multi *inm)
{
	struct ifnet *ifp;

	KASSERT(inm->inm_ifma != NULL, ("%s: no ifma", __func__));
	ifp = inm->inm_ifma->ifma_ifp;
	if (ifp != NULL) {
		
		KASSERT(inm->inm_ifp == ifp, ("%s: bad ifp", __func__));
	}

	return (ifp == NULL);
}


static __inline void imf_init(struct in_mfilter *imf, const int st0, const int st1)
{
	memset(imf, 0, sizeof(struct in_mfilter));
	RB_INIT(&imf->imf_sources);
	imf->imf_st[0] = st0;
	imf->imf_st[1] = st1;
}


static int imo_grow(struct ip_moptions *imo)
{
	struct in_multi		**nmships;
	struct in_multi		**omships;
	struct in_mfilter	 *nmfilters;
	struct in_mfilter	 *omfilters;
	size_t			  idx;
	size_t			  newmax;
	size_t			  oldmax;

	nmships = NULL;
	nmfilters = NULL;
	omships = imo->imo_membership;
	omfilters = imo->imo_mfilters;
	oldmax = imo->imo_max_memberships;
	newmax = ((oldmax + 1) * 2) - 1;

	if (newmax <= IP_MAX_MEMBERSHIPS) {
		nmships = (struct in_multi **)realloc(omships, sizeof(struct in_multi *) * newmax, M_IPMOPTS, M_NOWAIT);
		nmfilters = (struct in_mfilter *)realloc(omfilters, sizeof(struct in_mfilter) * newmax, M_INMFILTER, M_NOWAIT);
		if (nmships != NULL && nmfilters != NULL) {
			
			for (idx = oldmax; idx < newmax; idx++) {
				imf_init(&nmfilters[idx], MCAST_UNDEFINED, MCAST_EXCLUDE);
			}
			imo->imo_max_memberships = newmax;
			imo->imo_membership = nmships;
			imo->imo_mfilters = nmfilters;
		}
	}

	if (nmships == NULL || nmfilters == NULL) {
		if (nmships != NULL)
			free(nmships, M_IPMOPTS);
		if (nmfilters != NULL)
			free(nmfilters, M_INMFILTER);
		return (ETOOMANYREFS);
	}

	return (0);
}


static size_t imo_match_group(const struct ip_moptions *imo, const struct ifnet *ifp, const struct sockaddr *group)

{
	const struct sockaddr_in *gsin;
	struct in_multi	**pinm;
	int		  idx;
	int		  nmships;

	gsin = (const struct sockaddr_in *)group;

	
	if (imo->imo_membership == NULL || imo->imo_num_memberships == 0)
		return (-1);

	nmships = imo->imo_num_memberships;
	pinm = &imo->imo_membership[0];
	for (idx = 0; idx < nmships; idx++, pinm++) {
		if (*pinm == NULL)
			continue;
		if ((ifp == NULL || ((*pinm)->inm_ifp == ifp)) && in_hosteq((*pinm)->inm_addr, gsin->sin_addr)) {
			break;
		}
	}
	if (idx >= nmships)
		idx = -1;

	return (idx);
}


static struct in_msource * imo_match_source(const struct ip_moptions *imo, const size_t gidx, const struct sockaddr *src)

{
	struct ip_msource	 find;
	struct in_mfilter	*imf;
	struct ip_msource	*ims;
	const sockunion_t	*psa;

	KASSERT(src->sa_family == AF_INET, ("%s: !AF_INET", __func__));
	KASSERT(gidx != -1 && gidx < imo->imo_num_memberships, ("%s: invalid index %d\n", __func__, (int)gidx));

	
	if (imo->imo_mfilters == NULL)
		return (NULL);
	imf = &imo->imo_mfilters[gidx];

	
	psa = (const sockunion_t *)src;
	find.ims_haddr = ntohl(psa->sin.sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);

	return ((struct in_msource *)ims);
}


int imo_multi_filter(const struct ip_moptions *imo, const struct ifnet *ifp, const struct sockaddr *group, const struct sockaddr *src)

{
	size_t gidx;
	struct in_msource *ims;
	int mode;

	KASSERT(ifp != NULL, ("%s: null ifp", __func__));

	gidx = imo_match_group(imo, ifp, group);
	if (gidx == -1)
		return (MCAST_NOTGMEMBER);

	
	mode = imo->imo_mfilters[gidx].imf_st[1];
	ims = imo_match_source(imo, gidx, src);

	if ((ims == NULL && mode == MCAST_INCLUDE) || (ims != NULL && ims->imsl_st[0] != mode))
		return (MCAST_NOTSMEMBER);

	return (MCAST_PASS);
}


static int in_getmulti(struct ifnet *ifp, const struct in_addr *group, struct in_multi **pinm)

{
	struct sockaddr_in	 gsin;
	struct ifmultiaddr	*ifma;
	struct in_ifinfo	*ii;
	struct in_multi		*inm;
	int error;

	IN_MULTI_LOCK_ASSERT();

	ii = (struct in_ifinfo *)ifp->if_afdata[AF_INET];

	inm = inm_lookup(ifp, *group);
	if (inm != NULL) {
		
		KASSERT(inm->inm_refcount >= 1, ("%s: bad refcount %d", __func__, inm->inm_refcount));
		++inm->inm_refcount;
		*pinm = inm;
		return (0);
	}

	memset(&gsin, 0, sizeof(gsin));
	gsin.sin_family = AF_INET;
	gsin.sin_len = sizeof(struct sockaddr_in);
	gsin.sin_addr = *group;

	
	error = if_addmulti(ifp, (struct sockaddr *)&gsin, &ifma);
	if (error != 0)
		return (error);

	
	IF_ADDR_WLOCK(ifp);

	
	if (ifma->ifma_protospec != NULL) {
		inm = (struct in_multi *)ifma->ifma_protospec;

		KASSERT(ifma->ifma_addr != NULL, ("%s: no ifma_addr", __func__));
		KASSERT(ifma->ifma_addr->sa_family == AF_INET, ("%s: ifma not AF_INET", __func__));
		KASSERT(inm != NULL, ("%s: no ifma_protospec", __func__));
		if (inm->inm_ifma != ifma || inm->inm_ifp != ifp || !in_hosteq(inm->inm_addr, *group))
			panic("%s: ifma %p is inconsistent with %p (%s)", __func__, ifma, inm, inet_ntoa(*group));

		++inm->inm_refcount;
		*pinm = inm;
		IF_ADDR_WUNLOCK(ifp);
		return (0);
	}

	IF_ADDR_WLOCK_ASSERT(ifp);

	
	inm = malloc(sizeof(*inm), M_IPMADDR, M_NOWAIT | M_ZERO);
	if (inm == NULL) {
		if_delmulti_ifma(ifma);
		IF_ADDR_WUNLOCK(ifp);
		return (ENOMEM);
	}
	inm->inm_addr = *group;
	inm->inm_ifp = ifp;
	inm->inm_igi = ii->ii_igmp;
	inm->inm_ifma = ifma;
	inm->inm_refcount = 1;
	inm->inm_state = IGMP_NOT_MEMBER;

	
	IFQ_SET_MAXLEN(&inm->inm_scq, IGMP_MAX_STATE_CHANGES);

	inm->inm_st[0].iss_fmode = MCAST_UNDEFINED;
	inm->inm_st[1].iss_fmode = MCAST_UNDEFINED;
	RB_INIT(&inm->inm_srcs);

	ifma->ifma_protospec = inm;

	*pinm = inm;

	IF_ADDR_WUNLOCK(ifp);
	return (0);
}


void inm_release_locked(struct in_multi *inm)
{
	struct ifmultiaddr *ifma;

	IN_MULTI_LOCK_ASSERT();

	CTR2(KTR_IGMPV3, "%s: refcount is %d", __func__, inm->inm_refcount);

	if (--inm->inm_refcount > 0) {
		CTR2(KTR_IGMPV3, "%s: refcount is now %d", __func__, inm->inm_refcount);
		return;
	}

	CTR2(KTR_IGMPV3, "%s: freeing inm %p", __func__, inm);

	ifma = inm->inm_ifma;

	
	CTR2(KTR_IGMPV3, "%s: purging ifma %p", __func__, ifma);
	KASSERT(ifma->ifma_protospec == inm, ("%s: ifma_protospec != inm", __func__));
	ifma->ifma_protospec = NULL;

	inm_purge(inm);

	free(inm, M_IPMADDR);

	if_delmulti_ifma(ifma);
}


void inm_clear_recorded(struct in_multi *inm)
{
	struct ip_msource	*ims;

	IN_MULTI_LOCK_ASSERT();

	RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {
		if (ims->ims_stp) {
			ims->ims_stp = 0;
			--inm->inm_st[1].iss_rec;
		}
	}
	KASSERT(inm->inm_st[1].iss_rec == 0, ("%s: iss_rec %d not 0", __func__, inm->inm_st[1].iss_rec));
}


int inm_record_source(struct in_multi *inm, const in_addr_t naddr)
{
	struct ip_msource	 find;
	struct ip_msource	*ims, *nims;

	IN_MULTI_LOCK_ASSERT();

	find.ims_haddr = ntohl(naddr);
	ims = RB_FIND(ip_msource_tree, &inm->inm_srcs, &find);
	if (ims && ims->ims_stp)
		return (0);
	if (ims == NULL) {
		if (inm->inm_nsrc == in_mcast_maxgrpsrc)
			return (-ENOSPC);
		nims = malloc(sizeof(struct ip_msource), M_IPMSOURCE, M_NOWAIT | M_ZERO);
		if (nims == NULL)
			return (-ENOMEM);
		nims->ims_haddr = find.ims_haddr;
		RB_INSERT(ip_msource_tree, &inm->inm_srcs, nims);
		++inm->inm_nsrc;
		ims = nims;
	}

	
	++ims->ims_stp;
	++inm->inm_st[1].iss_rec;

	return (1);
}


static int imf_get_source(struct in_mfilter *imf, const struct sockaddr_in *psin, struct in_msource **plims)

{
	struct ip_msource	 find;
	struct ip_msource	*ims, *nims;
	struct in_msource	*lims;
	int			 error;

	error = 0;
	ims = NULL;
	lims = NULL;

	
	find.ims_haddr = ntohl(psin->sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);
	lims = (struct in_msource *)ims;
	if (lims == NULL) {
		if (imf->imf_nsrc == in_mcast_maxsocksrc)
			return (ENOSPC);
		nims = malloc(sizeof(struct in_msource), M_INMFILTER, M_NOWAIT | M_ZERO);
		if (nims == NULL)
			return (ENOMEM);
		lims = (struct in_msource *)nims;
		lims->ims_haddr = find.ims_haddr;
		lims->imsl_st[0] = MCAST_UNDEFINED;
		RB_INSERT(ip_msource_tree, &imf->imf_sources, nims);
		++imf->imf_nsrc;
	}

	*plims = lims;

	return (error);
}


static struct in_msource * imf_graft(struct in_mfilter *imf, const uint8_t st1, const struct sockaddr_in *psin)

{
	struct ip_msource	*nims;
	struct in_msource	*lims;

	nims = malloc(sizeof(struct in_msource), M_INMFILTER, M_NOWAIT | M_ZERO);
	if (nims == NULL)
		return (NULL);
	lims = (struct in_msource *)nims;
	lims->ims_haddr = ntohl(psin->sin_addr.s_addr);
	lims->imsl_st[0] = MCAST_UNDEFINED;
	lims->imsl_st[1] = st1;
	RB_INSERT(ip_msource_tree, &imf->imf_sources, nims);
	++imf->imf_nsrc;

	return (lims);
}


static int imf_prune(struct in_mfilter *imf, const struct sockaddr_in *psin)
{
	struct ip_msource	 find;
	struct ip_msource	*ims;
	struct in_msource	*lims;

	
	find.ims_haddr = ntohl(psin->sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);
	if (ims == NULL)
		return (ENOENT);
	lims = (struct in_msource *)ims;
	lims->imsl_st[1] = MCAST_UNDEFINED;
	return (0);
}


static void imf_rollback(struct in_mfilter *imf)
{
	struct ip_msource	*ims, *tims;
	struct in_msource	*lims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		lims = (struct in_msource *)ims;
		if (lims->imsl_st[0] == lims->imsl_st[1]) {
			
			continue;
		} else if (lims->imsl_st[0] != MCAST_UNDEFINED) {
			
			lims->imsl_st[1] = lims->imsl_st[0];
		} else {
			
			CTR2(KTR_IGMPV3, "%s: free ims %p", __func__, ims);
			RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
			free(ims, M_INMFILTER);
			imf->imf_nsrc--;
		}
	}
	imf->imf_st[1] = imf->imf_st[0];
}


static void imf_leave(struct in_mfilter *imf)
{
	struct ip_msource	*ims;
	struct in_msource	*lims;

	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct in_msource *)ims;
		lims->imsl_st[1] = MCAST_UNDEFINED;
	}
	imf->imf_st[1] = MCAST_INCLUDE;
}


static void imf_commit(struct in_mfilter *imf)
{
	struct ip_msource	*ims;
	struct in_msource	*lims;

	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct in_msource *)ims;
		lims->imsl_st[0] = lims->imsl_st[1];
	}
	imf->imf_st[0] = imf->imf_st[1];
}


static void imf_reap(struct in_mfilter *imf)
{
	struct ip_msource	*ims, *tims;
	struct in_msource	*lims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		lims = (struct in_msource *)ims;
		if ((lims->imsl_st[0] == MCAST_UNDEFINED) && (lims->imsl_st[1] == MCAST_UNDEFINED)) {
			CTR2(KTR_IGMPV3, "%s: free lims %p", __func__, ims);
			RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
			free(ims, M_INMFILTER);
			imf->imf_nsrc--;
		}
	}
}


static void imf_purge(struct in_mfilter *imf)
{
	struct ip_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		CTR2(KTR_IGMPV3, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
		free(ims, M_INMFILTER);
		imf->imf_nsrc--;
	}
	imf->imf_st[0] = imf->imf_st[1] = MCAST_UNDEFINED;
	KASSERT(RB_EMPTY(&imf->imf_sources), ("%s: imf_sources not empty", __func__));
}


static int inm_get_source(struct in_multi *inm, const in_addr_t haddr, const int noalloc, struct ip_msource **pims)

{
	struct ip_msource	 find;
	struct ip_msource	*ims, *nims;

	struct in_addr ia;


	find.ims_haddr = haddr;
	ims = RB_FIND(ip_msource_tree, &inm->inm_srcs, &find);
	if (ims == NULL && !noalloc) {
		if (inm->inm_nsrc == in_mcast_maxgrpsrc)
			return (ENOSPC);
		nims = malloc(sizeof(struct ip_msource), M_IPMSOURCE, M_NOWAIT | M_ZERO);
		if (nims == NULL)
			return (ENOMEM);
		nims->ims_haddr = haddr;
		RB_INSERT(ip_msource_tree, &inm->inm_srcs, nims);
		++inm->inm_nsrc;
		ims = nims;

		ia.s_addr = htonl(haddr);
		CTR3(KTR_IGMPV3, "%s: allocated %s as %p", __func__, inet_ntoa(ia), ims);

	}

	*pims = ims;
	return (0);
}


static void ims_merge(struct ip_msource *ims, const struct in_msource *lims, const int rollback)

{
	int n = rollback ? -1 : 1;

	struct in_addr ia;

	ia.s_addr = htonl(ims->ims_haddr);


	if (lims->imsl_st[0] == MCAST_EXCLUDE) {
		CTR3(KTR_IGMPV3, "%s: t1 ex -= %d on %s", __func__, n, inet_ntoa(ia));
		ims->ims_st[1].ex -= n;
	} else if (lims->imsl_st[0] == MCAST_INCLUDE) {
		CTR3(KTR_IGMPV3, "%s: t1 in -= %d on %s", __func__, n, inet_ntoa(ia));
		ims->ims_st[1].in -= n;
	}

	if (lims->imsl_st[1] == MCAST_EXCLUDE) {
		CTR3(KTR_IGMPV3, "%s: t1 ex += %d on %s", __func__, n, inet_ntoa(ia));
		ims->ims_st[1].ex += n;
	} else if (lims->imsl_st[1] == MCAST_INCLUDE) {
		CTR3(KTR_IGMPV3, "%s: t1 in += %d on %s", __func__, n, inet_ntoa(ia));
		ims->ims_st[1].in += n;
	}
}


static int inm_merge(struct in_multi *inm,  struct in_mfilter *imf)
{
	struct ip_msource	*ims, *nims;
	struct in_msource	*lims;
	int			 schanged, error;
	int			 nsrc0, nsrc1;

	schanged = 0;
	error = 0;
	nsrc1 = nsrc0 = 0;

	
	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct in_msource *)ims;
		if (lims->imsl_st[0] == imf->imf_st[0]) nsrc0++;
		if (lims->imsl_st[1] == imf->imf_st[1]) nsrc1++;
		if (lims->imsl_st[0] == lims->imsl_st[1]) continue;
		error = inm_get_source(inm, lims->ims_haddr, 0, &nims);
		++schanged;
		if (error)
			break;
		ims_merge(nims, lims, 0);
	}
	if (error) {
		struct ip_msource *bims;

		RB_FOREACH_REVERSE_FROM(ims, ip_msource_tree, nims) {
			lims = (struct in_msource *)ims;
			if (lims->imsl_st[0] == lims->imsl_st[1])
				continue;
			(void)inm_get_source(inm, lims->ims_haddr, 1, &bims);
			if (bims == NULL)
				continue;
			ims_merge(bims, lims, 1);
		}
		goto out_reap;
	}

	CTR3(KTR_IGMPV3, "%s: imf filters in-mode: %d at t0, %d at t1", __func__, nsrc0, nsrc1);

	
	if (imf->imf_st[0] == imf->imf_st[1] && imf->imf_st[1] == MCAST_INCLUDE) {
		if (nsrc1 == 0) {
			CTR1(KTR_IGMPV3, "%s: --in on inm at t1", __func__);
			--inm->inm_st[1].iss_in;
		}
	}

	
	if (imf->imf_st[0] != imf->imf_st[1]) {
		CTR3(KTR_IGMPV3, "%s: imf transition %d to %d", __func__, imf->imf_st[0], imf->imf_st[1]);

		if (imf->imf_st[0] == MCAST_EXCLUDE) {
			CTR1(KTR_IGMPV3, "%s: --ex on inm at t1", __func__);
			--inm->inm_st[1].iss_ex;
		} else if (imf->imf_st[0] == MCAST_INCLUDE) {
			CTR1(KTR_IGMPV3, "%s: --in on inm at t1", __func__);
			--inm->inm_st[1].iss_in;
		}

		if (imf->imf_st[1] == MCAST_EXCLUDE) {
			CTR1(KTR_IGMPV3, "%s: ex++ on inm at t1", __func__);
			inm->inm_st[1].iss_ex++;
		} else if (imf->imf_st[1] == MCAST_INCLUDE && nsrc1 > 0) {
			CTR1(KTR_IGMPV3, "%s: in++ on inm at t1", __func__);
			inm->inm_st[1].iss_in++;
		}
	}

	
	if (inm->inm_st[1].iss_ex > 0) {
		CTR1(KTR_IGMPV3, "%s: transition to EX", __func__);
		inm->inm_st[1].iss_fmode = MCAST_EXCLUDE;
	} else if (inm->inm_st[1].iss_in > 0) {
		CTR1(KTR_IGMPV3, "%s: transition to IN", __func__);
		inm->inm_st[1].iss_fmode = MCAST_INCLUDE;
	} else {
		CTR1(KTR_IGMPV3, "%s: transition to UNDEF", __func__);
		inm->inm_st[1].iss_fmode = MCAST_UNDEFINED;
	}

	
	if (imf->imf_st[0] == MCAST_EXCLUDE && nsrc0 == 0) {
		if ((imf->imf_st[1] != MCAST_EXCLUDE) || (imf->imf_st[1] == MCAST_EXCLUDE && nsrc1 > 0))
			CTR1(KTR_IGMPV3, "%s: --asm on inm at t1", __func__);
			--inm->inm_st[1].iss_asm;
	}

	
	if (imf->imf_st[1] == MCAST_EXCLUDE && nsrc1 == 0) {
		CTR1(KTR_IGMPV3, "%s: asm++ on inm at t1", __func__);
		inm->inm_st[1].iss_asm++;
	}

	CTR3(KTR_IGMPV3, "%s: merged imf %p to inm %p", __func__, imf, inm);
	inm_print(inm);

out_reap:
	if (schanged > 0) {
		CTR1(KTR_IGMPV3, "%s: sources changed; reaping", __func__);
		inm_reap(inm);
	}
	return (error);
}


void inm_commit(struct in_multi *inm)
{
	struct ip_msource	*ims;

	CTR2(KTR_IGMPV3, "%s: commit inm %p", __func__, inm);
	CTR1(KTR_IGMPV3, "%s: pre commit:", __func__);
	inm_print(inm);

	RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {
		ims->ims_st[0] = ims->ims_st[1];
	}
	inm->inm_st[0] = inm->inm_st[1];
}


static void inm_reap(struct in_multi *inm)
{
	struct ip_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &inm->inm_srcs, tims) {
		if (ims->ims_st[0].ex > 0 || ims->ims_st[0].in > 0 || ims->ims_st[1].ex > 0 || ims->ims_st[1].in > 0 || ims->ims_stp != 0)

			continue;
		CTR2(KTR_IGMPV3, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip_msource_tree, &inm->inm_srcs, ims);
		free(ims, M_IPMSOURCE);
		inm->inm_nsrc--;
	}
}


static void inm_purge(struct in_multi *inm)
{
	struct ip_msource	*ims, *tims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &inm->inm_srcs, tims) {
		CTR2(KTR_IGMPV3, "%s: free ims %p", __func__, ims);
		RB_REMOVE(ip_msource_tree, &inm->inm_srcs, ims);
		free(ims, M_IPMSOURCE);
		inm->inm_nsrc--;
	}
}


int in_joingroup(struct ifnet *ifp, const struct in_addr *gina, struct in_mfilter *imf, struct in_multi **pinm)

{
	int error;

	IN_MULTI_LOCK();
	error = in_joingroup_locked(ifp, gina, imf, pinm);
	IN_MULTI_UNLOCK();

	return (error);
}


int in_joingroup_locked(struct ifnet *ifp, const struct in_addr *gina, struct in_mfilter *imf, struct in_multi **pinm)

{
	struct in_mfilter	 timf;
	struct in_multi		*inm;
	int			 error;

	IN_MULTI_LOCK_ASSERT();

	CTR4(KTR_IGMPV3, "%s: join %s on %p(%s))", __func__, inet_ntoa(*gina), ifp, ifp->if_xname);

	error = 0;
	inm = NULL;

	
	if (imf == NULL) {
		imf_init(&timf, MCAST_UNDEFINED, MCAST_EXCLUDE);
		imf = &timf;
	}

	error = in_getmulti(ifp, gina, &inm);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: in_getmulti() failure", __func__);
		return (error);
	}

	CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
	error = inm_merge(inm, imf);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: failed to merge inm state", __func__);
		goto out_inm_release;
	}

	CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
	error = igmp_change_state(inm);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: failed to update source", __func__);
		goto out_inm_release;
	}

out_inm_release:
	if (error) {
		CTR2(KTR_IGMPV3, "%s: dropping ref on %p", __func__, inm);
		inm_release_locked(inm);
	} else {
		*pinm = inm;
	}

	return (error);
}


int in_leavegroup(struct in_multi *inm,  struct in_mfilter *imf)
{
	int error;

	IN_MULTI_LOCK();
	error = in_leavegroup_locked(inm, imf);
	IN_MULTI_UNLOCK();

	return (error);
}


int in_leavegroup_locked(struct in_multi *inm,  struct in_mfilter *imf)
{
	struct in_mfilter	 timf;
	int			 error;

	error = 0;

	IN_MULTI_LOCK_ASSERT();

	CTR5(KTR_IGMPV3, "%s: leave inm %p, %s/%s, imf %p", __func__, inm, inet_ntoa(inm->inm_addr), (inm_is_ifp_detached(inm) ? "null" : inm->inm_ifp->if_xname), imf);



	
	if (imf == NULL) {
		imf_init(&timf, MCAST_EXCLUDE, MCAST_UNDEFINED);
		imf = &timf;
	}

	
	CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
	error = inm_merge(inm, imf);
	KASSERT(error == 0, ("%s: failed to merge inm state", __func__));

	CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
	CURVNET_SET(inm->inm_ifp->if_vnet);
	error = igmp_change_state(inm);
	CURVNET_RESTORE();
	if (error)
		CTR1(KTR_IGMPV3, "%s: failed igmp downcall", __func__);

	CTR2(KTR_IGMPV3, "%s: dropping ref on %p", __func__, inm);
	inm_release_locked(inm);

	return (error);
}



struct in_multi * in_addmulti(struct in_addr *ap, struct ifnet *ifp)
{
	struct in_multi *pinm;
	int error;

	KASSERT(IN_LOCAL_GROUP(ntohl(ap->s_addr)), ("%s: %s not in 224.0.0.0/24", __func__, inet_ntoa(*ap)));

	error = in_joingroup(ifp, ap, NULL, &pinm);
	if (error != 0)
		pinm = NULL;

	return (pinm);
}


void in_delmulti(struct in_multi *inm)
{

	(void)in_leavegroup(inm, NULL);
}



static int inp_block_unblock_source(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req		 gsr;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in_mfilter		*imf;
	struct ip_moptions		*imo;
	struct in_msource		*ims;
	struct in_multi			*inm;
	size_t				 idx;
	uint16_t			 fmode;
	int				 error, doblock;

	ifp = NULL;
	error = 0;
	doblock = 0;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	ssa = (sockunion_t *)&gsr.gsr_source;

	switch (sopt->sopt_name) {
	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE: {
		struct ip_mreq_source	 mreqs;

		error = sooptcopyin(sopt, &mreqs, sizeof(struct ip_mreq_source), sizeof(struct ip_mreq_source));

		if (error)
			return (error);

		gsa->sin.sin_family = AF_INET;
		gsa->sin.sin_len = sizeof(struct sockaddr_in);
		gsa->sin.sin_addr = mreqs.imr_multiaddr;

		ssa->sin.sin_family = AF_INET;
		ssa->sin.sin_len = sizeof(struct sockaddr_in);
		ssa->sin.sin_addr = mreqs.imr_sourceaddr;

		if (!in_nullhost(mreqs.imr_interface))
			INADDR_TO_IFP(mreqs.imr_interface, ifp);

		if (sopt->sopt_name == IP_BLOCK_SOURCE)
			doblock = 1;

		CTR3(KTR_IGMPV3, "%s: imr_interface = %s, ifp = %p", __func__, inet_ntoa(mreqs.imr_interface), ifp);
		break;
	    }

	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		error = sooptcopyin(sopt, &gsr, sizeof(struct group_source_req), sizeof(struct group_source_req));

		if (error)
			return (error);

		if (gsa->sin.sin_family != AF_INET || gsa->sin.sin_len != sizeof(struct sockaddr_in))
			return (EINVAL);

		if (ssa->sin.sin_family != AF_INET || ssa->sin.sin_len != sizeof(struct sockaddr_in))
			return (EINVAL);

		if (gsr.gsr_interface == 0 || V_if_index < gsr.gsr_interface)
			return (EADDRNOTAVAIL);

		ifp = ifnet_byindex(gsr.gsr_interface);

		if (sopt->sopt_name == MCAST_BLOCK_SOURCE)
			doblock = 1;
		break;

	default:
		CTR2(KTR_IGMPV3, "%s: unknown sopt_name %d", __func__, sopt->sopt_name);
		return (EOPNOTSUPP);
		break;
	}

	if (!IN_MULTICAST(ntohl(gsa->sin.sin_addr.s_addr)))
		return (EINVAL);

	
	imo = inp_findmoptions(inp);
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if (idx == -1 || imo->imo_mfilters == NULL) {
		error = EADDRNOTAVAIL;
		goto out_inp_locked;
	}

	KASSERT(imo->imo_mfilters != NULL, ("%s: imo_mfilters not allocated", __func__));
	imf = &imo->imo_mfilters[idx];
	inm = imo->imo_membership[idx];

	
	fmode = imf->imf_st[0];
	if (fmode != MCAST_EXCLUDE) {
		error = EINVAL;
		goto out_inp_locked;
	}

	
	ims = imo_match_source(imo, idx, &ssa->sa);
	if ((ims != NULL && doblock) || (ims == NULL && !doblock)) {
		CTR3(KTR_IGMPV3, "%s: source %s %spresent", __func__, inet_ntoa(ssa->sin.sin_addr), doblock ? "" : "not ");
		error = EADDRNOTAVAIL;
		goto out_inp_locked;
	}

	INP_WLOCK_ASSERT(inp);

	
	if (doblock) {
		CTR2(KTR_IGMPV3, "%s: %s source", __func__, "block");
		ims = imf_graft(imf, fmode, &ssa->sin);
		if (ims == NULL)
			error = ENOMEM;
	} else {
		CTR2(KTR_IGMPV3, "%s: %s source", __func__, "allow");
		error = imf_prune(imf, &ssa->sin);
	}

	if (error) {
		CTR1(KTR_IGMPV3, "%s: merge imf state failed", __func__);
		goto out_imf_rollback;
	}

	
	IN_MULTI_LOCK();

	CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
	error = inm_merge(inm, imf);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: failed to merge inm state", __func__);
		goto out_imf_rollback;
	}

	CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
	error = igmp_change_state(inm);
	if (error)
		CTR1(KTR_IGMPV3, "%s: failed igmp downcall", __func__);

	IN_MULTI_UNLOCK();

out_imf_rollback:
	if (error)
		imf_rollback(imf);
	else imf_commit(imf);

	imf_reap(imf);

out_inp_locked:
	INP_WUNLOCK(inp);
	return (error);
}


static struct ip_moptions * inp_findmoptions(struct inpcb *inp)
{
	struct ip_moptions	 *imo;
	struct in_multi		**immp;
	struct in_mfilter	 *imfp;
	size_t			  idx;

	INP_WLOCK(inp);
	if (inp->inp_moptions != NULL)
		return (inp->inp_moptions);

	INP_WUNLOCK(inp);

	imo = malloc(sizeof(*imo), M_IPMOPTS, M_WAITOK);
	immp = malloc(sizeof(*immp) * IP_MIN_MEMBERSHIPS, M_IPMOPTS, M_WAITOK | M_ZERO);
	imfp = malloc(sizeof(struct in_mfilter) * IP_MIN_MEMBERSHIPS, M_INMFILTER, M_WAITOK);

	imo->imo_multicast_ifp = NULL;
	imo->imo_multicast_addr.s_addr = INADDR_ANY;
	imo->imo_multicast_vif = -1;
	imo->imo_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
	imo->imo_multicast_loop = in_mcast_loop;
	imo->imo_num_memberships = 0;
	imo->imo_max_memberships = IP_MIN_MEMBERSHIPS;
	imo->imo_membership = immp;

	
	for (idx = 0; idx < IP_MIN_MEMBERSHIPS; idx++)
		imf_init(&imfp[idx], MCAST_UNDEFINED, MCAST_EXCLUDE);
	imo->imo_mfilters = imfp;

	INP_WLOCK(inp);
	if (inp->inp_moptions != NULL) {
		free(imfp, M_INMFILTER);
		free(immp, M_IPMOPTS);
		free(imo, M_IPMOPTS);
		return (inp->inp_moptions);
	}
	inp->inp_moptions = imo;
	return (imo);
}


void inp_freemoptions(struct ip_moptions *imo)
{

	KASSERT(imo != NULL, ("%s: ip_moptions is NULL", __func__));
	IN_MULTI_LOCK();
	STAILQ_INSERT_TAIL(&imo_gc_list, imo, imo_link);
	IN_MULTI_UNLOCK();
	taskqueue_enqueue(taskqueue_thread, &imo_gc_task);
}

static void inp_freemoptions_internal(struct ip_moptions *imo)
{
	struct in_mfilter	*imf;
	size_t			 idx, nmships;

	nmships = imo->imo_num_memberships;
	for (idx = 0; idx < nmships; ++idx) {
		imf = imo->imo_mfilters ? &imo->imo_mfilters[idx] : NULL;
		if (imf)
			imf_leave(imf);
		(void)in_leavegroup(imo->imo_membership[idx], imf);
		if (imf)
			imf_purge(imf);
	}

	if (imo->imo_mfilters)
		free(imo->imo_mfilters, M_INMFILTER);
	free(imo->imo_membership, M_IPMOPTS);
	free(imo, M_IPMOPTS);
}

static void inp_gcmoptions(void *context, int pending)
{
	struct ip_moptions *imo;

	IN_MULTI_LOCK();
	while (!STAILQ_EMPTY(&imo_gc_list)) {
		imo = STAILQ_FIRST(&imo_gc_list);
		STAILQ_REMOVE_HEAD(&imo_gc_list, imo_link);
		IN_MULTI_UNLOCK();
		inp_freemoptions_internal(imo);
		IN_MULTI_LOCK();
	}
	IN_MULTI_UNLOCK();
}


static int inp_get_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq	 msfr;
	sockunion_t		*gsa;
	struct ifnet		*ifp;
	struct ip_moptions	*imo;
	struct in_mfilter	*imf;
	struct ip_msource	*ims;
	struct in_msource	*lims;
	struct sockaddr_in	*psin;
	struct sockaddr_storage	*ptss;
	struct sockaddr_storage	*tss;
	int			 error;
	size_t			 idx, nsrcs, ncsrcs;

	INP_WLOCK_ASSERT(inp);

	imo = inp->inp_moptions;
	KASSERT(imo != NULL, ("%s: null ip_moptions", __func__));

	INP_WUNLOCK(inp);

	error = sooptcopyin(sopt, &msfr, sizeof(struct __msfilterreq), sizeof(struct __msfilterreq));
	if (error)
		return (error);

	if (msfr.msfr_ifindex == 0 || V_if_index < msfr.msfr_ifindex)
		return (EINVAL);

	ifp = ifnet_byindex(msfr.msfr_ifindex);
	if (ifp == NULL)
		return (EINVAL);

	INP_WLOCK(inp);

	
	gsa = (sockunion_t *)&msfr.msfr_group;
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if (idx == -1 || imo->imo_mfilters == NULL) {
		INP_WUNLOCK(inp);
		return (EADDRNOTAVAIL);
	}
	imf = &imo->imo_mfilters[idx];

	
	if (imf->imf_st[1] == MCAST_UNDEFINED) {
		INP_WUNLOCK(inp);
		return (EAGAIN);
	}
	msfr.msfr_fmode = imf->imf_st[1];

	
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
	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct in_msource *)ims;
		if (lims->imsl_st[0] == MCAST_UNDEFINED || lims->imsl_st[0] != imf->imf_st[0])
			continue;
		++ncsrcs;
		if (tss != NULL && nsrcs > 0) {
			psin = (struct sockaddr_in *)ptss;
			psin->sin_family = AF_INET;
			psin->sin_len = sizeof(struct sockaddr_in);
			psin->sin_addr.s_addr = htonl(lims->ims_haddr);
			psin->sin_port = 0;
			++ptss;
			--nsrcs;
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


int inp_getmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ip_mreqn		 mreqn;
	struct ip_moptions	*imo;
	struct ifnet		*ifp;
	struct in_ifaddr	*ia;
	int			 error, optval;
	u_char			 coptval;

	INP_WLOCK(inp);
	imo = inp->inp_moptions;
	
	if (inp->inp_socket->so_proto->pr_protocol == IPPROTO_DIVERT || (inp->inp_socket->so_proto->pr_type != SOCK_RAW && inp->inp_socket->so_proto->pr_type != SOCK_DGRAM)) {

		INP_WUNLOCK(inp);
		return (EOPNOTSUPP);
	}

	error = 0;
	switch (sopt->sopt_name) {
	case IP_MULTICAST_VIF:
		if (imo != NULL)
			optval = imo->imo_multicast_vif;
		else optval = -1;
		INP_WUNLOCK(inp);
		error = sooptcopyout(sopt, &optval, sizeof(int));
		break;

	case IP_MULTICAST_IF:
		memset(&mreqn, 0, sizeof(struct ip_mreqn));
		if (imo != NULL) {
			ifp = imo->imo_multicast_ifp;
			if (!in_nullhost(imo->imo_multicast_addr)) {
				mreqn.imr_address = imo->imo_multicast_addr;
			} else if (ifp != NULL) {
				mreqn.imr_ifindex = ifp->if_index;
				IFP_TO_IA(ifp, ia);
				if (ia != NULL) {
					mreqn.imr_address = IA_SIN(ia)->sin_addr;
					ifa_free(&ia->ia_ifa);
				}
			}
		}
		INP_WUNLOCK(inp);
		if (sopt->sopt_valsize == sizeof(struct ip_mreqn)) {
			error = sooptcopyout(sopt, &mreqn, sizeof(struct ip_mreqn));
		} else {
			error = sooptcopyout(sopt, &mreqn.imr_address, sizeof(struct in_addr));
		}
		break;

	case IP_MULTICAST_TTL:
		if (imo == 0)
			optval = coptval = IP_DEFAULT_MULTICAST_TTL;
		else optval = coptval = imo->imo_multicast_ttl;
		INP_WUNLOCK(inp);
		if (sopt->sopt_valsize == sizeof(u_char))
			error = sooptcopyout(sopt, &coptval, sizeof(u_char));
		else error = sooptcopyout(sopt, &optval, sizeof(int));
		break;

	case IP_MULTICAST_LOOP:
		if (imo == 0)
			optval = coptval = IP_DEFAULT_MULTICAST_LOOP;
		else optval = coptval = imo->imo_multicast_loop;
		INP_WUNLOCK(inp);
		if (sopt->sopt_valsize == sizeof(u_char))
			error = sooptcopyout(sopt, &coptval, sizeof(u_char));
		else error = sooptcopyout(sopt, &optval, sizeof(int));
		break;

	case IP_MSFILTER:
		if (imo == NULL) {
			error = EADDRNOTAVAIL;
			INP_WUNLOCK(inp);
		} else {
			error = inp_get_source_filters(inp, sopt);
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


static struct ifnet * inp_lookup_mcast_ifp(const struct inpcb *inp, const struct sockaddr_in *gsin, const struct in_addr ina)

{
	struct ifnet *ifp;

	KASSERT(gsin->sin_family == AF_INET, ("%s: not AF_INET", __func__));
	KASSERT(IN_MULTICAST(ntohl(gsin->sin_addr.s_addr)), ("%s: not multicast", __func__));

	ifp = NULL;
	if (!in_nullhost(ina)) {
		INADDR_TO_IFP(ina, ifp);
	} else {
		struct route ro;

		ro.ro_rt = NULL;
		memcpy(&ro.ro_dst, gsin, sizeof(struct sockaddr_in));
		in_rtalloc_ign(&ro, 0, inp ? inp->inp_inc.inc_fibnum : 0);
		if (ro.ro_rt != NULL) {
			ifp = ro.ro_rt->rt_ifp;
			KASSERT(ifp != NULL, ("%s: null ifp", __func__));
			RTFREE(ro.ro_rt);
		} else {
			struct in_ifaddr *ia;
			struct ifnet *mifp;

			mifp = NULL;
			IN_IFADDR_RLOCK();
			TAILQ_FOREACH(ia, &V_in_ifaddrhead, ia_link) {
				mifp = ia->ia_ifp;
				if (!(mifp->if_flags & IFF_LOOPBACK) && (mifp->if_flags & IFF_MULTICAST)) {
					ifp = mifp;
					break;
				}
			}
			IN_IFADDR_RUNLOCK();
		}
	}

	return (ifp);
}


static int inp_join_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req		 gsr;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in_mfilter		*imf;
	struct ip_moptions		*imo;
	struct in_multi			*inm;
	struct in_msource		*lims;
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
	case IP_ADD_MEMBERSHIP:
	case IP_ADD_SOURCE_MEMBERSHIP: {
		struct ip_mreq_source	 mreqs;

		if (sopt->sopt_name == IP_ADD_MEMBERSHIP) {
			error = sooptcopyin(sopt, &mreqs, sizeof(struct ip_mreq), sizeof(struct ip_mreq));

			
			mreqs.imr_interface = mreqs.imr_sourceaddr;
			mreqs.imr_sourceaddr.s_addr = INADDR_ANY;
		} else if (sopt->sopt_name == IP_ADD_SOURCE_MEMBERSHIP) {
			error = sooptcopyin(sopt, &mreqs, sizeof(struct ip_mreq_source), sizeof(struct ip_mreq_source));

		}
		if (error)
			return (error);

		gsa->sin.sin_family = AF_INET;
		gsa->sin.sin_len = sizeof(struct sockaddr_in);
		gsa->sin.sin_addr = mreqs.imr_multiaddr;

		if (sopt->sopt_name == IP_ADD_SOURCE_MEMBERSHIP) {
			ssa->sin.sin_family = AF_INET;
			ssa->sin.sin_len = sizeof(struct sockaddr_in);
			ssa->sin.sin_addr = mreqs.imr_sourceaddr;
		}

		if (!IN_MULTICAST(ntohl(gsa->sin.sin_addr.s_addr)))
			return (EINVAL);

		ifp = inp_lookup_mcast_ifp(inp, &gsa->sin, mreqs.imr_interface);
		CTR3(KTR_IGMPV3, "%s: imr_interface = %s, ifp = %p", __func__, inet_ntoa(mreqs.imr_interface), ifp);
		break;
	}

	case MCAST_JOIN_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
		if (sopt->sopt_name == MCAST_JOIN_GROUP) {
			error = sooptcopyin(sopt, &gsr, sizeof(struct group_req), sizeof(struct group_req));

		} else if (sopt->sopt_name == MCAST_JOIN_SOURCE_GROUP) {
			error = sooptcopyin(sopt, &gsr, sizeof(struct group_source_req), sizeof(struct group_source_req));

		}
		if (error)
			return (error);

		if (gsa->sin.sin_family != AF_INET || gsa->sin.sin_len != sizeof(struct sockaddr_in))
			return (EINVAL);

		
		gsa->sin.sin_port = 0;
		if (sopt->sopt_name == MCAST_JOIN_SOURCE_GROUP) {
			if (ssa->sin.sin_family != AF_INET || ssa->sin.sin_len != sizeof(struct sockaddr_in))
				return (EINVAL);
			ssa->sin.sin_port = 0;
		}

		if (!IN_MULTICAST(ntohl(gsa->sin.sin_addr.s_addr)))
			return (EINVAL);

		if (gsr.gsr_interface == 0 || V_if_index < gsr.gsr_interface)
			return (EADDRNOTAVAIL);
		ifp = ifnet_byindex(gsr.gsr_interface);
		break;

	default:
		CTR2(KTR_IGMPV3, "%s: unknown sopt_name %d", __func__, sopt->sopt_name);
		return (EOPNOTSUPP);
		break;
	}

	if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0)
		return (EADDRNOTAVAIL);

	imo = inp_findmoptions(inp);
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if (idx == -1) {
		is_new = 1;
	} else {
		inm = imo->imo_membership[idx];
		imf = &imo->imo_mfilters[idx];
		if (ssa->ss.ss_family != AF_UNSPEC) {
			
			if (imf->imf_st[1] != MCAST_INCLUDE) {
				error = EINVAL;
				goto out_inp_locked;
			}
			
			lims = imo_match_source(imo, idx, &ssa->sa);
			if (lims != NULL ) {
				error = EADDRNOTAVAIL;
				goto out_inp_locked;
			}
		} else {
			
			error = EINVAL;
			if (imf->imf_st[1] == MCAST_EXCLUDE)
				error = EADDRINUSE;
			goto out_inp_locked;
		}
	}

	
	INP_WLOCK_ASSERT(inp);

	if (is_new) {
		if (imo->imo_num_memberships == imo->imo_max_memberships) {
			error = imo_grow(imo);
			if (error)
				goto out_inp_locked;
		}
		
		idx = imo->imo_num_memberships;
		imo->imo_membership[idx] = NULL;
		imo->imo_num_memberships++;
		KASSERT(imo->imo_mfilters != NULL, ("%s: imf_mfilters vector was not allocated", __func__));
		imf = &imo->imo_mfilters[idx];
		KASSERT(RB_EMPTY(&imf->imf_sources), ("%s: imf_sources not empty", __func__));
	}

	
	if (ssa->ss.ss_family != AF_UNSPEC) {
		
		if (is_new) {
			CTR1(KTR_IGMPV3, "%s: new join w/source", __func__);
			imf_init(imf, MCAST_UNDEFINED, MCAST_INCLUDE);
		} else {
			CTR2(KTR_IGMPV3, "%s: %s source", __func__, "allow");
		}
		lims = imf_graft(imf, MCAST_INCLUDE, &ssa->sin);
		if (lims == NULL) {
			CTR1(KTR_IGMPV3, "%s: merge imf state failed", __func__);
			error = ENOMEM;
			goto out_imo_free;
		}
	} else {
		
		if (is_new) {
			CTR1(KTR_IGMPV3, "%s: new join w/o source", __func__);
			imf_init(imf, MCAST_UNDEFINED, MCAST_EXCLUDE);
		}
	}

	
	IN_MULTI_LOCK();

	if (is_new) {
		error = in_joingroup_locked(ifp, &gsa->sin.sin_addr, imf, &inm);
		if (error)
			goto out_imo_free;
		imo->imo_membership[idx] = inm;
	} else {
		CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
		error = inm_merge(inm, imf);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: failed to merge inm state", __func__);
			goto out_imf_rollback;
		}
		CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
		error = igmp_change_state(inm);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: failed igmp downcall", __func__);
			goto out_imf_rollback;
		}
	}

	IN_MULTI_UNLOCK();

out_imf_rollback:
	INP_WLOCK_ASSERT(inp);
	if (error) {
		imf_rollback(imf);
		if (is_new)
			imf_purge(imf);
		else imf_reap(imf);
	} else {
		imf_commit(imf);
	}

out_imo_free:
	if (error && is_new) {
		imo->imo_membership[idx] = NULL;
		--imo->imo_num_memberships;
	}

out_inp_locked:
	INP_WUNLOCK(inp);
	return (error);
}


static int inp_leave_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req		 gsr;
	struct ip_mreq_source		 mreqs;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in_mfilter		*imf;
	struct ip_moptions		*imo;
	struct in_msource		*ims;
	struct in_multi			*inm;
	size_t				 idx;
	int				 error, is_final;

	ifp = NULL;
	error = 0;
	is_final = 1;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	gsa->ss.ss_family = AF_UNSPEC;
	ssa = (sockunion_t *)&gsr.gsr_source;
	ssa->ss.ss_family = AF_UNSPEC;

	switch (sopt->sopt_name) {
	case IP_DROP_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
		if (sopt->sopt_name == IP_DROP_MEMBERSHIP) {
			error = sooptcopyin(sopt, &mreqs, sizeof(struct ip_mreq), sizeof(struct ip_mreq));

			
			mreqs.imr_interface = mreqs.imr_sourceaddr;
			mreqs.imr_sourceaddr.s_addr = INADDR_ANY;
		} else if (sopt->sopt_name == IP_DROP_SOURCE_MEMBERSHIP) {
			error = sooptcopyin(sopt, &mreqs, sizeof(struct ip_mreq_source), sizeof(struct ip_mreq_source));

		}
		if (error)
			return (error);

		gsa->sin.sin_family = AF_INET;
		gsa->sin.sin_len = sizeof(struct sockaddr_in);
		gsa->sin.sin_addr = mreqs.imr_multiaddr;

		if (sopt->sopt_name == IP_DROP_SOURCE_MEMBERSHIP) {
			ssa->sin.sin_family = AF_INET;
			ssa->sin.sin_len = sizeof(struct sockaddr_in);
			ssa->sin.sin_addr = mreqs.imr_sourceaddr;
		}

		
		if (!in_nullhost(mreqs.imr_interface))
			INADDR_TO_IFP(mreqs.imr_interface, ifp);

		CTR3(KTR_IGMPV3, "%s: imr_interface = %s, ifp = %p", __func__, inet_ntoa(mreqs.imr_interface), ifp);

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

		if (gsa->sin.sin_family != AF_INET || gsa->sin.sin_len != sizeof(struct sockaddr_in))
			return (EINVAL);

		if (sopt->sopt_name == MCAST_LEAVE_SOURCE_GROUP) {
			if (ssa->sin.sin_family != AF_INET || ssa->sin.sin_len != sizeof(struct sockaddr_in))
				return (EINVAL);
		}

		if (gsr.gsr_interface == 0 || V_if_index < gsr.gsr_interface)
			return (EADDRNOTAVAIL);

		ifp = ifnet_byindex(gsr.gsr_interface);

		if (ifp == NULL)
			return (EADDRNOTAVAIL);
		break;

	default:
		CTR2(KTR_IGMPV3, "%s: unknown sopt_name %d", __func__, sopt->sopt_name);
		return (EOPNOTSUPP);
		break;
	}

	if (!IN_MULTICAST(ntohl(gsa->sin.sin_addr.s_addr)))
		return (EINVAL);

	
	imo = inp_findmoptions(inp);
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if (idx == -1) {
		error = EADDRNOTAVAIL;
		goto out_inp_locked;
	}
	inm = imo->imo_membership[idx];
	imf = &imo->imo_mfilters[idx];

	if (ssa->ss.ss_family != AF_UNSPEC)
		is_final = 0;

	
	INP_WLOCK_ASSERT(inp);

	
	if (is_final) {
		imf_leave(imf);
	} else {
		if (imf->imf_st[0] == MCAST_EXCLUDE) {
			error = EADDRNOTAVAIL;
			goto out_inp_locked;
		}
		ims = imo_match_source(imo, idx, &ssa->sa);
		if (ims == NULL) {
			CTR3(KTR_IGMPV3, "%s: source %s %spresent", __func__, inet_ntoa(ssa->sin.sin_addr), "not ");
			error = EADDRNOTAVAIL;
			goto out_inp_locked;
		}
		CTR2(KTR_IGMPV3, "%s: %s source", __func__, "block");
		error = imf_prune(imf, &ssa->sin);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: merge imf state failed", __func__);
			goto out_inp_locked;
		}
	}

	
	IN_MULTI_LOCK();

	if (is_final) {
		
		(void)in_leavegroup_locked(inm, imf);
	} else {
		CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
		error = inm_merge(inm, imf);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: failed to merge inm state", __func__);
			goto out_imf_rollback;
		}

		CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
		error = igmp_change_state(inm);
		if (error) {
			CTR1(KTR_IGMPV3, "%s: failed igmp downcall", __func__);
		}
	}

	IN_MULTI_UNLOCK();

out_imf_rollback:
	if (error)
		imf_rollback(imf);
	else imf_commit(imf);

	imf_reap(imf);

	if (is_final) {
		
		for (++idx; idx < imo->imo_num_memberships; ++idx) {
			imo->imo_membership[idx-1] = imo->imo_membership[idx];
			imo->imo_mfilters[idx-1] = imo->imo_mfilters[idx];
		}
		imo->imo_num_memberships--;
	}

out_inp_locked:
	INP_WUNLOCK(inp);
	return (error);
}


static int inp_set_multicast_if(struct inpcb *inp, struct sockopt *sopt)
{
	struct in_addr		 addr;
	struct ip_mreqn		 mreqn;
	struct ifnet		*ifp;
	struct ip_moptions	*imo;
	int			 error;

	if (sopt->sopt_valsize == sizeof(struct ip_mreqn)) {
		
		error = sooptcopyin(sopt, &mreqn, sizeof(struct ip_mreqn), sizeof(struct ip_mreqn));
		if (error)
			return (error);

		if (mreqn.imr_ifindex < 0 || V_if_index < mreqn.imr_ifindex)
			return (EINVAL);

		if (mreqn.imr_ifindex == 0) {
			ifp = NULL;
		} else {
			ifp = ifnet_byindex(mreqn.imr_ifindex);
			if (ifp == NULL)
				return (EADDRNOTAVAIL);
		}
	} else {
		
		error = sooptcopyin(sopt, &addr, sizeof(struct in_addr), sizeof(struct in_addr));
		if (error)
			return (error);
		if (in_nullhost(addr)) {
			ifp = NULL;
		} else {
			INADDR_TO_IFP(addr, ifp);
			if (ifp == NULL)
				return (EADDRNOTAVAIL);
		}
		CTR3(KTR_IGMPV3, "%s: ifp = %p, addr = %s", __func__, ifp, inet_ntoa(addr));
	}

	
	if (ifp != NULL && (ifp->if_flags & IFF_MULTICAST) == 0)
		return (EOPNOTSUPP);

	imo = inp_findmoptions(inp);
	imo->imo_multicast_ifp = ifp;
	imo->imo_multicast_addr.s_addr = INADDR_ANY;
	INP_WUNLOCK(inp);

	return (0);
}


static int inp_set_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq	 msfr;
	sockunion_t		*gsa;
	struct ifnet		*ifp;
	struct in_mfilter	*imf;
	struct ip_moptions	*imo;
	struct in_multi		*inm;
	size_t			 idx;
	int			 error;

	error = sooptcopyin(sopt, &msfr, sizeof(struct __msfilterreq), sizeof(struct __msfilterreq));
	if (error)
		return (error);

	if (msfr.msfr_nsrcs > in_mcast_maxsocksrc)
		return (ENOBUFS);

	if ((msfr.msfr_fmode != MCAST_EXCLUDE && msfr.msfr_fmode != MCAST_INCLUDE))
		return (EINVAL);

	if (msfr.msfr_group.ss_family != AF_INET || msfr.msfr_group.ss_len != sizeof(struct sockaddr_in))
		return (EINVAL);

	gsa = (sockunion_t *)&msfr.msfr_group;
	if (!IN_MULTICAST(ntohl(gsa->sin.sin_addr.s_addr)))
		return (EINVAL);

	gsa->sin.sin_port = 0;	

	if (msfr.msfr_ifindex == 0 || V_if_index < msfr.msfr_ifindex)
		return (EADDRNOTAVAIL);

	ifp = ifnet_byindex(msfr.msfr_ifindex);
	if (ifp == NULL)
		return (EADDRNOTAVAIL);

	
	imo = inp_findmoptions(inp);
	idx = imo_match_group(imo, ifp, &gsa->sa);
	if (idx == -1 || imo->imo_mfilters == NULL) {
		error = EADDRNOTAVAIL;
		goto out_inp_locked;
	}
	inm = imo->imo_membership[idx];
	imf = &imo->imo_mfilters[idx];

	
	INP_WLOCK_ASSERT(inp);

	imf->imf_st[1] = msfr.msfr_fmode;

	
	if (msfr.msfr_nsrcs > 0) {
		struct in_msource	*lims;
		struct sockaddr_in	*psin;
		struct sockaddr_storage	*kss, *pkss;
		int			 i;

		INP_WUNLOCK(inp);
 
		CTR2(KTR_IGMPV3, "%s: loading %lu source list entries", __func__, (unsigned long)msfr.msfr_nsrcs);
		kss = malloc(sizeof(struct sockaddr_storage) * msfr.msfr_nsrcs, M_TEMP, M_WAITOK);
		error = copyin(msfr.msfr_srcs, kss, sizeof(struct sockaddr_storage) * msfr.msfr_nsrcs);
		if (error) {
			free(kss, M_TEMP);
			return (error);
		}

		INP_WLOCK(inp);

		
		imf_leave(imf);
		imf->imf_st[1] = msfr.msfr_fmode;

		
		for (i = 0, pkss = kss; i < msfr.msfr_nsrcs; i++, pkss++) {
			psin = (struct sockaddr_in *)pkss;
			if (psin->sin_family != AF_INET) {
				error = EAFNOSUPPORT;
				break;
			}
			if (psin->sin_len != sizeof(struct sockaddr_in)) {
				error = EINVAL;
				break;
			}
			error = imf_get_source(imf, psin, &lims);
			if (error)
				break;
			lims->imsl_st[1] = imf->imf_st[1];
		}
		free(kss, M_TEMP);
	}

	if (error)
		goto out_imf_rollback;

	INP_WLOCK_ASSERT(inp);
	IN_MULTI_LOCK();

	
	CTR1(KTR_IGMPV3, "%s: merge inm state", __func__);
	error = inm_merge(inm, imf);
	if (error) {
		CTR1(KTR_IGMPV3, "%s: failed to merge inm state", __func__);
		goto out_imf_rollback;
	}

	CTR1(KTR_IGMPV3, "%s: doing igmp downcall", __func__);
	error = igmp_change_state(inm);
	if (error)
		CTR1(KTR_IGMPV3, "%s: failed igmp downcall", __func__);

	IN_MULTI_UNLOCK();

out_imf_rollback:
	if (error)
		imf_rollback(imf);
	else imf_commit(imf);

	imf_reap(imf);

out_inp_locked:
	INP_WUNLOCK(inp);
	return (error);
}


int inp_setmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ip_moptions	*imo;
	int			 error;

	error = 0;

	
	if (inp->inp_socket->so_proto->pr_protocol == IPPROTO_DIVERT || (inp->inp_socket->so_proto->pr_type != SOCK_RAW && inp->inp_socket->so_proto->pr_type != SOCK_DGRAM))

		return (EOPNOTSUPP);

	switch (sopt->sopt_name) {
	case IP_MULTICAST_VIF: {
		int vifi;
		
		if (legal_vif_num == NULL) {
			error = EOPNOTSUPP;
			break;
		}
		error = sooptcopyin(sopt, &vifi, sizeof(int), sizeof(int));
		if (error)
			break;
		if (!legal_vif_num(vifi) && (vifi != -1)) {
			error = EINVAL;
			break;
		}
		imo = inp_findmoptions(inp);
		imo->imo_multicast_vif = vifi;
		INP_WUNLOCK(inp);
		break;
	}

	case IP_MULTICAST_IF:
		error = inp_set_multicast_if(inp, sopt);
		break;

	case IP_MULTICAST_TTL: {
		u_char ttl;

		
		if (sopt->sopt_valsize == sizeof(u_char)) {
			error = sooptcopyin(sopt, &ttl, sizeof(u_char), sizeof(u_char));
			if (error)
				break;
		} else {
			u_int ittl;

			error = sooptcopyin(sopt, &ittl, sizeof(u_int), sizeof(u_int));
			if (error)
				break;
			if (ittl > 255) {
				error = EINVAL;
				break;
			}
			ttl = (u_char)ittl;
		}
		imo = inp_findmoptions(inp);
		imo->imo_multicast_ttl = ttl;
		INP_WUNLOCK(inp);
		break;
	}

	case IP_MULTICAST_LOOP: {
		u_char loop;

		
		if (sopt->sopt_valsize == sizeof(u_char)) {
			error = sooptcopyin(sopt, &loop, sizeof(u_char), sizeof(u_char));
			if (error)
				break;
		} else {
			u_int iloop;

			error = sooptcopyin(sopt, &iloop, sizeof(u_int), sizeof(u_int));
			if (error)
				break;
			loop = (u_char)iloop;
		}
		imo = inp_findmoptions(inp);
		imo->imo_multicast_loop = !!loop;
		INP_WUNLOCK(inp);
		break;
	}

	case IP_ADD_MEMBERSHIP:
	case IP_ADD_SOURCE_MEMBERSHIP:
	case MCAST_JOIN_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
		error = inp_join_group(inp, sopt);
		break;

	case IP_DROP_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
	case MCAST_LEAVE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
		error = inp_leave_group(inp, sopt);
		break;

	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE:
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		error = inp_block_unblock_source(inp, sopt);
		break;

	case IP_MSFILTER:
		error = inp_set_source_filters(inp, sopt);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	INP_UNLOCK_ASSERT(inp);

	return (error);
}


static int sysctl_ip_mcast_filters(SYSCTL_HANDLER_ARGS)
{
	struct in_addr			 src, group;
	struct ifnet			*ifp;
	struct ifmultiaddr		*ifma;
	struct in_multi			*inm;
	struct ip_msource		*ims;
	int				*name;
	int				 retval;
	u_int				 namelen;
	uint32_t			 fmode, ifindex;

	name = (int *)arg1;
	namelen = arg2;

	if (req->newptr != NULL)
		return (EPERM);

	if (namelen != 2)
		return (EINVAL);

	ifindex = name[0];
	if (ifindex <= 0 || ifindex > V_if_index) {
		CTR2(KTR_IGMPV3, "%s: ifindex %u out of range", __func__, ifindex);
		return (ENOENT);
	}

	group.s_addr = name[1];
	if (!IN_MULTICAST(ntohl(group.s_addr))) {
		CTR2(KTR_IGMPV3, "%s: group %s is not multicast", __func__, inet_ntoa(group));
		return (EINVAL);
	}

	ifp = ifnet_byindex(ifindex);
	if (ifp == NULL) {
		CTR2(KTR_IGMPV3, "%s: no ifp for ifindex %u", __func__, ifindex);
		return (ENOENT);
	}

	retval = sysctl_wire_old_buffer(req, sizeof(uint32_t) + (in_mcast_maxgrpsrc * sizeof(struct in_addr)));
	if (retval)
		return (retval);

	IN_MULTI_LOCK();

	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_INET || ifma->ifma_protospec == NULL)
			continue;
		inm = (struct in_multi *)ifma->ifma_protospec;
		if (!in_hosteq(inm->inm_addr, group))
			continue;
		fmode = inm->inm_st[1].iss_fmode;
		retval = SYSCTL_OUT(req, &fmode, sizeof(uint32_t));
		if (retval != 0)
			break;
		RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {

			struct in_addr ina;
			ina.s_addr = htonl(ims->ims_haddr);
			CTR2(KTR_IGMPV3, "%s: visit node %s", __func__, inet_ntoa(ina));

			
			if (fmode != ims_get_mode(inm, ims, 1)) {
				CTR1(KTR_IGMPV3, "%s: skip non-in-mode", __func__);
				continue;
			}
			src.s_addr = htonl(ims->ims_haddr);
			retval = SYSCTL_OUT(req, &src, sizeof(struct in_addr));
			if (retval != 0)
				break;
		}
	}
	IF_ADDR_RUNLOCK(ifp);

	IN_MULTI_UNLOCK();

	return (retval);
}



static const char *inm_modestrs[] = { "un", "in", "ex" };

static const char * inm_mode_str(const int mode)
{

	if (mode >= MCAST_UNDEFINED && mode <= MCAST_EXCLUDE)
		return (inm_modestrs[mode]);
	return ("??");
}

static const char *inm_statestrs[] = {
	"not-member", "silent", "idle", "lazy", "sleeping", "awakening", "query-pending", "sg-query-pending", "leaving" };









static const char * inm_state_str(const int state)
{

	if (state >= IGMP_NOT_MEMBER && state <= IGMP_LEAVING_MEMBER)
		return (inm_statestrs[state]);
	return ("??");
}


void inm_print(const struct in_multi *inm)
{
	int t;

	if ((ktr_mask & KTR_IGMPV3) == 0)
		return;

	printf("%s: --- begin inm %p ---\n", __func__, inm);
	printf("addr %s ifp %p(%s) ifma %p\n", inet_ntoa(inm->inm_addr), inm->inm_ifp, inm->inm_ifp->if_xname, inm->inm_ifma);



	printf("timer %u state %s refcount %u scq.len %u\n", inm->inm_timer, inm_state_str(inm->inm_state), inm->inm_refcount, inm->inm_scq.ifq_len);



	printf("igi %p nsrc %lu sctimer %u scrv %u\n", inm->inm_igi, inm->inm_nsrc, inm->inm_sctimer, inm->inm_scrv);



	for (t = 0; t < 2; t++) {
		printf("t%d: fmode %s asm %u ex %u in %u rec %u\n", t, inm_mode_str(inm->inm_st[t].iss_fmode), inm->inm_st[t].iss_asm, inm->inm_st[t].iss_ex, inm->inm_st[t].iss_in, inm->inm_st[t].iss_rec);




	}
	printf("%s: --- end inm %p ---\n", __func__, inm);
}



void inm_print(const struct in_multi *inm)
{

}



RB_GENERATE(ip_msource_tree, ip_msource, ims_link, ip_msource_cmp);
