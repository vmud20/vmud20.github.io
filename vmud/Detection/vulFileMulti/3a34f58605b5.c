




__FBSDID("$FreeBSD$");













































static uma_zone_t	unp_zone;
static unp_gen_t	unp_gencnt;	
static u_int		unp_count;	
static ino_t		unp_ino;	
static int		unp_rights;	
static struct unp_head	unp_shead;	
static struct unp_head	unp_dhead;	
static struct unp_head	unp_sphead;	

struct unp_defer {
	SLIST_ENTRY(unp_defer) ud_link;
	struct file *ud_fp;
};
static SLIST_HEAD(, unp_defer) unp_defers;
static int unp_defers_count;

static const struct sockaddr	sun_noname = { sizeof(sun_noname), AF_LOCAL };


static struct task	unp_gc_task;


static struct task	unp_defer_task;





static u_long	unpst_sendspace = PIPSIZ;
static u_long	unpst_recvspace = PIPSIZ;
static u_long	unpdg_sendspace = 2*1024;	
static u_long	unpdg_recvspace = 4*1024;
static u_long	unpsp_sendspace = PIPSIZ;	
static u_long	unpsp_recvspace = PIPSIZ;

SYSCTL_NODE(_net, PF_LOCAL, local, CTLFLAG_RW, 0, "Local domain");
SYSCTL_NODE(_net_local, SOCK_STREAM, stream, CTLFLAG_RW, 0, "SOCK_STREAM");
SYSCTL_NODE(_net_local, SOCK_DGRAM, dgram, CTLFLAG_RW, 0, "SOCK_DGRAM");
SYSCTL_NODE(_net_local, SOCK_SEQPACKET, seqpacket, CTLFLAG_RW, 0, "SOCK_SEQPACKET");

SYSCTL_ULONG(_net_local_stream, OID_AUTO, sendspace, CTLFLAG_RW, &unpst_sendspace, 0, "Default stream send space.");
SYSCTL_ULONG(_net_local_stream, OID_AUTO, recvspace, CTLFLAG_RW, &unpst_recvspace, 0, "Default stream receive space.");
SYSCTL_ULONG(_net_local_dgram, OID_AUTO, maxdgram, CTLFLAG_RW, &unpdg_sendspace, 0, "Default datagram send space.");
SYSCTL_ULONG(_net_local_dgram, OID_AUTO, recvspace, CTLFLAG_RW, &unpdg_recvspace, 0, "Default datagram receive space.");
SYSCTL_ULONG(_net_local_seqpacket, OID_AUTO, maxseqpacket, CTLFLAG_RW, &unpsp_sendspace, 0, "Default seqpacket send space.");
SYSCTL_ULONG(_net_local_seqpacket, OID_AUTO, recvspace, CTLFLAG_RW, &unpsp_recvspace, 0, "Default seqpacket receive space.");
SYSCTL_INT(_net_local, OID_AUTO, inflight, CTLFLAG_RD, &unp_rights, 0, "File descriptors in flight.");
SYSCTL_INT(_net_local, OID_AUTO, deferred, CTLFLAG_RD, &unp_defers_count, 0, "File descriptors deferred to taskqueue for close.");



static struct rwlock	unp_link_rwlock;
static struct mtx	unp_list_lock;
static struct mtx	unp_defers_lock;



























static int	uipc_connect2(struct socket *, struct socket *);
static int	uipc_ctloutput(struct socket *, struct sockopt *);
static int	unp_connect(struct socket *, struct sockaddr *, struct thread *);
static int	unp_connect2(struct socket *so, struct socket *so2, int);
static void	unp_disconnect(struct unpcb *unp, struct unpcb *unp2);
static void	unp_dispose(struct mbuf *);
static void	unp_shutdown(struct unpcb *);
static void	unp_drop(struct unpcb *, int);
static void	unp_gc(__unused void *, int);
static void	unp_scan(struct mbuf *, void (*)(struct file *));
static void	unp_discard(struct file *);
static void	unp_freerights(struct file **, int);
static void	unp_init(void);
static int	unp_internalize(struct mbuf **, struct thread *);
static void	unp_internalize_fp(struct file *);
static int	unp_externalize(struct mbuf *, struct mbuf **);
static int	unp_externalize_fp(struct file *);
static struct mbuf	*unp_addsockcred(struct thread *, struct mbuf *);
static void	unp_process_defers(void * __unused, int);


static struct domain localdomain;
static struct pr_usrreqs uipc_usrreqs_dgram, uipc_usrreqs_stream;
static struct pr_usrreqs uipc_usrreqs_seqpacket;
static struct protosw localsw[] = {
{
	.pr_type =		SOCK_STREAM, .pr_domain =		&localdomain, .pr_flags =		PR_CONNREQUIRED|PR_WANTRCVD|PR_RIGHTS, .pr_ctloutput =		&uipc_ctloutput, .pr_usrreqs =		&uipc_usrreqs_stream }, {





	.pr_type =		SOCK_DGRAM, .pr_domain =		&localdomain, .pr_flags =		PR_ATOMIC|PR_ADDR|PR_RIGHTS, .pr_usrreqs =		&uipc_usrreqs_dgram }, {




	.pr_type =		SOCK_SEQPACKET, .pr_domain =		&localdomain,   .pr_flags =		PR_ADDR|PR_ATOMIC|PR_CONNREQUIRED|PR_WANTRCVD| PR_RIGHTS, .pr_usrreqs =		&uipc_usrreqs_seqpacket, }, };








static struct domain localdomain = {
	.dom_family =		AF_LOCAL, .dom_name =		"local", .dom_init =		unp_init, .dom_externalize =	unp_externalize, .dom_dispose =		unp_dispose, .dom_protosw =		localsw, .dom_protoswNPROTOSW =	&localsw[sizeof(localsw)/sizeof(localsw[0])] };






DOMAIN_SET(local);

static void uipc_abort(struct socket *so)
{
	struct unpcb *unp, *unp2;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_abort: unp == NULL"));

	UNP_LINK_WLOCK();
	UNP_PCB_LOCK(unp);
	unp2 = unp->unp_conn;
	if (unp2 != NULL) {
		UNP_PCB_LOCK(unp2);
		unp_drop(unp2, ECONNABORTED);
		UNP_PCB_UNLOCK(unp2);
	}
	UNP_PCB_UNLOCK(unp);
	UNP_LINK_WUNLOCK();
}

static int uipc_accept(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp, *unp2;
	const struct sockaddr *sa;

	
	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_accept: unp == NULL"));

	*nam = malloc(sizeof(struct sockaddr_un), M_SONAME, M_WAITOK);
	UNP_LINK_RLOCK();
	unp2 = unp->unp_conn;
	if (unp2 != NULL && unp2->unp_addr != NULL) {
		UNP_PCB_LOCK(unp2);
		sa = (struct sockaddr *) unp2->unp_addr;
		bcopy(sa, *nam, sa->sa_len);
		UNP_PCB_UNLOCK(unp2);
	} else {
		sa = &sun_noname;
		bcopy(sa, *nam, sa->sa_len);
	}
	UNP_LINK_RUNLOCK();
	return (0);
}

static int uipc_attach(struct socket *so, int proto, struct thread *td)
{
	u_long sendspace, recvspace;
	struct unpcb *unp;
	int error;

	KASSERT(so->so_pcb == NULL, ("uipc_attach: so_pcb != NULL"));
	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		switch (so->so_type) {
		case SOCK_STREAM:
			sendspace = unpst_sendspace;
			recvspace = unpst_recvspace;
			break;

		case SOCK_DGRAM:
			sendspace = unpdg_sendspace;
			recvspace = unpdg_recvspace;
			break;

		case SOCK_SEQPACKET:
			sendspace = unpsp_sendspace;
			recvspace = unpsp_recvspace;
			break;

		default:
			panic("uipc_attach");
		}
		error = soreserve(so, sendspace, recvspace);
		if (error)
			return (error);
	}
	unp = uma_zalloc(unp_zone, M_NOWAIT | M_ZERO);
	if (unp == NULL)
		return (ENOBUFS);
	LIST_INIT(&unp->unp_refs);
	UNP_PCB_LOCK_INIT(unp);
	unp->unp_socket = so;
	so->so_pcb = unp;
	unp->unp_refcount = 1;

	UNP_LIST_LOCK();
	unp->unp_gencnt = ++unp_gencnt;
	unp_count++;
	switch (so->so_type) {
	case SOCK_STREAM:
		LIST_INSERT_HEAD(&unp_shead, unp, unp_link);
		break;

	case SOCK_DGRAM:
		LIST_INSERT_HEAD(&unp_dhead, unp, unp_link);
		break;

	case SOCK_SEQPACKET:
		LIST_INSERT_HEAD(&unp_sphead, unp, unp_link);
		break;

	default:
		panic("uipc_attach");
	}
	UNP_LIST_UNLOCK();

	return (0);
}

static int uipc_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct sockaddr_un *soun = (struct sockaddr_un *)nam;
	struct vattr vattr;
	int error, namelen, vfslocked;
	struct nameidata nd;
	struct unpcb *unp;
	struct vnode *vp;
	struct mount *mp;
	char *buf;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_bind: unp == NULL"));

	namelen = soun->sun_len - offsetof(struct sockaddr_un, sun_path);
	if (namelen <= 0)
		return (EINVAL);

	
	UNP_PCB_LOCK(unp);
	if (unp->unp_vnode != NULL) {
		UNP_PCB_UNLOCK(unp);
		return (EINVAL);
	}
	if (unp->unp_flags & UNP_BINDING) {
		UNP_PCB_UNLOCK(unp);
		return (EALREADY);
	}
	unp->unp_flags |= UNP_BINDING;
	UNP_PCB_UNLOCK(unp);

	buf = malloc(namelen + 1, M_TEMP, M_WAITOK);
	bcopy(soun->sun_path, buf, namelen);
	buf[namelen] = 0;

restart:
	vfslocked = 0;
	NDINIT(&nd, CREATE, MPSAFE | NOFOLLOW | LOCKPARENT | SAVENAME, UIO_SYSSPACE, buf, td);

	error = namei(&nd);
	if (error)
		goto error;
	vp = nd.ni_vp;
	vfslocked = NDHASGIANT(&nd);
	if (vp != NULL || vn_start_write(nd.ni_dvp, &mp, V_NOWAIT) != 0) {
		NDFREE(&nd, NDF_ONLY_PNBUF);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else vput(nd.ni_dvp);
		if (vp != NULL) {
			vrele(vp);
			error = EADDRINUSE;
			goto error;
		}
		error = vn_start_write(NULL, &mp, V_XSLEEP | PCATCH);
		if (error)
			goto error;
		VFS_UNLOCK_GIANT(vfslocked);
		goto restart;
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VSOCK;
	vattr.va_mode = (ACCESSPERMS & ~td->td_proc->p_fd->fd_cmask);

	error = mac_vnode_check_create(td->td_ucred, nd.ni_dvp, &nd.ni_cnd, &vattr);

	if (error == 0)
		error = VOP_CREATE(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vput(nd.ni_dvp);
	if (error) {
		vn_finished_write(mp);
		goto error;
	}
	vp = nd.ni_vp;
	ASSERT_VOP_ELOCKED(vp, "uipc_bind");
	soun = (struct sockaddr_un *)sodupsockaddr(nam, M_WAITOK);

	UNP_LINK_WLOCK();
	UNP_PCB_LOCK(unp);
	vp->v_socket = unp->unp_socket;
	unp->unp_vnode = vp;
	unp->unp_addr = soun;
	unp->unp_flags &= ~UNP_BINDING;
	UNP_PCB_UNLOCK(unp);
	UNP_LINK_WUNLOCK();
	VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);
	VFS_UNLOCK_GIANT(vfslocked);
	free(buf, M_TEMP);
	return (0);

error:
	VFS_UNLOCK_GIANT(vfslocked);
	UNP_PCB_LOCK(unp);
	unp->unp_flags &= ~UNP_BINDING;
	UNP_PCB_UNLOCK(unp);
	free(buf, M_TEMP);
	return (error);
}

static int uipc_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	int error;

	KASSERT(td == curthread, ("uipc_connect: td != curthread"));
	UNP_LINK_WLOCK();
	error = unp_connect(so, nam, td);
	UNP_LINK_WUNLOCK();
	return (error);
}

static void uipc_close(struct socket *so)
{
	struct unpcb *unp, *unp2;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_close: unp == NULL"));

	UNP_LINK_WLOCK();
	UNP_PCB_LOCK(unp);
	unp2 = unp->unp_conn;
	if (unp2 != NULL) {
		UNP_PCB_LOCK(unp2);
		unp_disconnect(unp, unp2);
		UNP_PCB_UNLOCK(unp2);
	}
	UNP_PCB_UNLOCK(unp);
	UNP_LINK_WUNLOCK();
}

static int uipc_connect2(struct socket *so1, struct socket *so2)
{
	struct unpcb *unp, *unp2;
	int error;

	UNP_LINK_WLOCK();
	unp = so1->so_pcb;
	KASSERT(unp != NULL, ("uipc_connect2: unp == NULL"));
	UNP_PCB_LOCK(unp);
	unp2 = so2->so_pcb;
	KASSERT(unp2 != NULL, ("uipc_connect2: unp2 == NULL"));
	UNP_PCB_LOCK(unp2);
	error = unp_connect2(so1, so2, PRU_CONNECT2);
	UNP_PCB_UNLOCK(unp2);
	UNP_PCB_UNLOCK(unp);
	UNP_LINK_WUNLOCK();
	return (error);
}

static void uipc_detach(struct socket *so)
{
	struct unpcb *unp, *unp2;
	struct sockaddr_un *saved_unp_addr;
	struct vnode *vp;
	int freeunp, local_unp_rights;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_detach: unp == NULL"));

	UNP_LINK_WLOCK();
	UNP_LIST_LOCK();
	UNP_PCB_LOCK(unp);
	LIST_REMOVE(unp, unp_link);
	unp->unp_gencnt = ++unp_gencnt;
	--unp_count;
	UNP_LIST_UNLOCK();

	
	if ((vp = unp->unp_vnode) != NULL) {
		unp->unp_vnode->v_socket = NULL;
		unp->unp_vnode = NULL;
	}
	unp2 = unp->unp_conn;
	if (unp2 != NULL) {
		UNP_PCB_LOCK(unp2);
		unp_disconnect(unp, unp2);
		UNP_PCB_UNLOCK(unp2);
	}

	
	while (!LIST_EMPTY(&unp->unp_refs)) {
		struct unpcb *ref = LIST_FIRST(&unp->unp_refs);

		UNP_PCB_LOCK(ref);
		unp_drop(ref, ECONNRESET);
		UNP_PCB_UNLOCK(ref);
	}
	local_unp_rights = unp_rights;
	UNP_LINK_WUNLOCK();
	unp->unp_socket->so_pcb = NULL;
	saved_unp_addr = unp->unp_addr;
	unp->unp_addr = NULL;
	unp->unp_refcount--;
	freeunp = (unp->unp_refcount == 0);
	if (saved_unp_addr != NULL)
		free(saved_unp_addr, M_SONAME);
	if (freeunp) {
		UNP_PCB_LOCK_DESTROY(unp);
		uma_zfree(unp_zone, unp);
	} else UNP_PCB_UNLOCK(unp);
	if (vp) {
		int vfslocked;

		vfslocked = VFS_LOCK_GIANT(vp->v_mount);
		vrele(vp);
		VFS_UNLOCK_GIANT(vfslocked);
	}
	if (local_unp_rights)
		taskqueue_enqueue(taskqueue_thread, &unp_gc_task);
}

static int uipc_disconnect(struct socket *so)
{
	struct unpcb *unp, *unp2;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_disconnect: unp == NULL"));

	UNP_LINK_WLOCK();
	UNP_PCB_LOCK(unp);
	unp2 = unp->unp_conn;
	if (unp2 != NULL) {
		UNP_PCB_LOCK(unp2);
		unp_disconnect(unp, unp2);
		UNP_PCB_UNLOCK(unp2);
	}
	UNP_PCB_UNLOCK(unp);
	UNP_LINK_WUNLOCK();
	return (0);
}

static int uipc_listen(struct socket *so, int backlog, struct thread *td)
{
	struct unpcb *unp;
	int error;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_listen: unp == NULL"));

	UNP_PCB_LOCK(unp);
	if (unp->unp_vnode == NULL) {
		UNP_PCB_UNLOCK(unp);
		return (EINVAL);
	}

	SOCK_LOCK(so);
	error = solisten_proto_check(so);
	if (error == 0) {
		cru2x(td->td_ucred, &unp->unp_peercred);
		unp->unp_flags |= UNP_HAVEPCCACHED;
		solisten_proto(so, backlog);
	}
	SOCK_UNLOCK(so);
	UNP_PCB_UNLOCK(unp);
	return (error);
}

static int uipc_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp, *unp2;
	const struct sockaddr *sa;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_peeraddr: unp == NULL"));

	*nam = malloc(sizeof(struct sockaddr_un), M_SONAME, M_WAITOK);
	UNP_LINK_RLOCK();
	
	unp2 = unp->unp_conn;
	if (unp2 != NULL) {
		UNP_PCB_LOCK(unp2);
		if (unp2->unp_addr != NULL)
			sa = (struct sockaddr *) unp2->unp_addr;
		else sa = &sun_noname;
		bcopy(sa, *nam, sa->sa_len);
		UNP_PCB_UNLOCK(unp2);
	} else {
		sa = &sun_noname;
		bcopy(sa, *nam, sa->sa_len);
	}
	UNP_LINK_RUNLOCK();
	return (0);
}

static int uipc_rcvd(struct socket *so, int flags)
{
	struct unpcb *unp, *unp2;
	struct socket *so2;
	u_int mbcnt, sbcc;
	u_long newhiwat;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_rcvd: unp == NULL"));

	if (so->so_type != SOCK_STREAM && so->so_type != SOCK_SEQPACKET)
		panic("uipc_rcvd socktype %d", so->so_type);

	
	SOCKBUF_LOCK(&so->so_rcv);
	mbcnt = so->so_rcv.sb_mbcnt;
	sbcc = so->so_rcv.sb_cc;
	SOCKBUF_UNLOCK(&so->so_rcv);
	UNP_PCB_LOCK(unp);
	unp2 = unp->unp_conn;
	if (unp2 == NULL) {
		UNP_PCB_UNLOCK(unp);
		return (0);
	}
	so2 = unp2->unp_socket;
	SOCKBUF_LOCK(&so2->so_snd);
	so2->so_snd.sb_mbmax += unp->unp_mbcnt - mbcnt;
	newhiwat = so2->so_snd.sb_hiwat + unp->unp_cc - sbcc;
	(void)chgsbsize(so2->so_cred->cr_uidinfo, &so2->so_snd.sb_hiwat, newhiwat, RLIM_INFINITY);
	sowwakeup_locked(so2);
	unp->unp_mbcnt = mbcnt;
	unp->unp_cc = sbcc;
	UNP_PCB_UNLOCK(unp);
	return (0);
}

static int uipc_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam, struct mbuf *control, struct thread *td)

{
	struct unpcb *unp, *unp2;
	struct socket *so2;
	u_int mbcnt_delta, sbcc;
	u_int newhiwat;
	int error = 0;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_send: unp == NULL"));

	if (flags & PRUS_OOB) {
		error = EOPNOTSUPP;
		goto release;
	}
	if (control != NULL && (error = unp_internalize(&control, td)))
		goto release;
	if ((nam != NULL) || (flags & PRUS_EOF))
		UNP_LINK_WLOCK();
	else UNP_LINK_RLOCK();
	switch (so->so_type) {
	case SOCK_DGRAM:
	{
		const struct sockaddr *from;

		unp2 = unp->unp_conn;
		if (nam != NULL) {
			UNP_LINK_WLOCK_ASSERT();
			if (unp2 != NULL) {
				error = EISCONN;
				break;
			}
			error = unp_connect(so, nam, td);
			if (error)
				break;
			unp2 = unp->unp_conn;
		}

		
		if (unp2 == NULL) {
			error = ENOTCONN;
			break;
		}
		
		if (unp2->unp_flags & UNP_WANTCRED)
			control = unp_addsockcred(td, control);
		UNP_PCB_LOCK(unp);
		if (unp->unp_addr != NULL)
			from = (struct sockaddr *)unp->unp_addr;
		else from = &sun_noname;
		so2 = unp2->unp_socket;
		SOCKBUF_LOCK(&so2->so_rcv);
		if (sbappendaddr_locked(&so2->so_rcv, from, m, control)) {
			sorwakeup_locked(so2);
			m = NULL;
			control = NULL;
		} else {
			SOCKBUF_UNLOCK(&so2->so_rcv);
			error = ENOBUFS;
		}
		if (nam != NULL) {
			UNP_LINK_WLOCK_ASSERT();
			UNP_PCB_LOCK(unp2);
			unp_disconnect(unp, unp2);
			UNP_PCB_UNLOCK(unp2);
		}
		UNP_PCB_UNLOCK(unp);
		break;
	}

	case SOCK_SEQPACKET:
	case SOCK_STREAM:
		if ((so->so_state & SS_ISCONNECTED) == 0) {
			if (nam != NULL) {
				UNP_LINK_WLOCK_ASSERT();
				error = unp_connect(so, nam, td);
				if (error)
					break;	
			} else {
				error = ENOTCONN;
				break;
			}
		}

		
		if (so->so_snd.sb_state & SBS_CANTSENDMORE) {
			error = EPIPE;
			break;
		}

		
		unp2 = unp->unp_conn;
		if (unp2 == NULL) {
			error = ENOTCONN;
			break;
		}
		so2 = unp2->unp_socket;
		UNP_PCB_LOCK(unp2);
		SOCKBUF_LOCK(&so2->so_rcv);
		if (unp2->unp_flags & UNP_WANTCRED) {
			
			unp2->unp_flags &= ~UNP_WANTCRED;
			control = unp_addsockcred(td, control);
		}
		
		switch (so->so_type) {
		case SOCK_STREAM:
			if (control != NULL) {
				if (sbappendcontrol_locked(&so2->so_rcv, m, control))
					control = NULL;
			} else sbappend_locked(&so2->so_rcv, m);
			break;

		case SOCK_SEQPACKET: {
			const struct sockaddr *from;

			from = &sun_noname;
			if (sbappendaddr_locked(&so2->so_rcv, from, m, control))
				control = NULL;
			break;
			}
		}

		
		mbcnt_delta = so2->so_rcv.sb_mbcnt - unp2->unp_mbcnt;
		unp2->unp_mbcnt = so2->so_rcv.sb_mbcnt;
		sbcc = so2->so_rcv.sb_cc;
		sorwakeup_locked(so2);

		SOCKBUF_LOCK(&so->so_snd);
		if ((int)so->so_snd.sb_hiwat >= (int)(sbcc - unp2->unp_cc))
			newhiwat = so->so_snd.sb_hiwat - (sbcc - unp2->unp_cc);
		else newhiwat = 0;
		(void)chgsbsize(so->so_cred->cr_uidinfo, &so->so_snd.sb_hiwat, newhiwat, RLIM_INFINITY);
		so->so_snd.sb_mbmax -= mbcnt_delta;
		SOCKBUF_UNLOCK(&so->so_snd);
		unp2->unp_cc = sbcc;
		UNP_PCB_UNLOCK(unp2);
		m = NULL;
		break;

	default:
		panic("uipc_send unknown socktype");
	}

	
	if (flags & PRUS_EOF) {
		UNP_PCB_LOCK(unp);
		socantsendmore(so);
		unp_shutdown(unp);
		UNP_PCB_UNLOCK(unp);
	}

	if ((nam != NULL) || (flags & PRUS_EOF))
		UNP_LINK_WUNLOCK();
	else UNP_LINK_RUNLOCK();

	if (control != NULL && error != 0)
		unp_dispose(control);

release:
	if (control != NULL)
		m_freem(control);
	if (m != NULL)
		m_freem(m);
	return (error);
}

static int uipc_sense(struct socket *so, struct stat *sb)
{
	struct unpcb *unp, *unp2;
	struct socket *so2;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_sense: unp == NULL"));

	sb->st_blksize = so->so_snd.sb_hiwat;
	UNP_LINK_RLOCK();
	UNP_PCB_LOCK(unp);
	unp2 = unp->unp_conn;
	if ((so->so_type == SOCK_STREAM || so->so_type == SOCK_SEQPACKET) && unp2 != NULL) {
		so2 = unp2->unp_socket;
		sb->st_blksize += so2->so_rcv.sb_cc;
	}
	sb->st_dev = NODEV;
	if (unp->unp_ino == 0)
		unp->unp_ino = (++unp_ino == 0) ? ++unp_ino : unp_ino;
	sb->st_ino = unp->unp_ino;
	UNP_PCB_UNLOCK(unp);
	UNP_LINK_RUNLOCK();
	return (0);
}

static int uipc_shutdown(struct socket *so)
{
	struct unpcb *unp;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_shutdown: unp == NULL"));

	UNP_LINK_WLOCK();
	UNP_PCB_LOCK(unp);
	socantsendmore(so);
	unp_shutdown(unp);
	UNP_PCB_UNLOCK(unp);
	UNP_LINK_WUNLOCK();
	return (0);
}

static int uipc_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct unpcb *unp;
	const struct sockaddr *sa;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_sockaddr: unp == NULL"));

	*nam = malloc(sizeof(struct sockaddr_un), M_SONAME, M_WAITOK);
	UNP_PCB_LOCK(unp);
	if (unp->unp_addr != NULL)
		sa = (struct sockaddr *) unp->unp_addr;
	else sa = &sun_noname;
	bcopy(sa, *nam, sa->sa_len);
	UNP_PCB_UNLOCK(unp);
	return (0);
}

static struct pr_usrreqs uipc_usrreqs_dgram = {
	.pru_abort = 		uipc_abort, .pru_accept =		uipc_accept, .pru_attach =		uipc_attach, .pru_bind =		uipc_bind, .pru_connect =		uipc_connect, .pru_connect2 =		uipc_connect2, .pru_detach =		uipc_detach, .pru_disconnect =	uipc_disconnect, .pru_listen =		uipc_listen, .pru_peeraddr =		uipc_peeraddr, .pru_rcvd =		uipc_rcvd, .pru_send =		uipc_send, .pru_sense =		uipc_sense, .pru_shutdown =		uipc_shutdown, .pru_sockaddr =		uipc_sockaddr, .pru_soreceive =	soreceive_dgram, .pru_close =		uipc_close, };

















static struct pr_usrreqs uipc_usrreqs_seqpacket = {
	.pru_abort =		uipc_abort, .pru_accept =		uipc_accept, .pru_attach =		uipc_attach, .pru_bind =		uipc_bind, .pru_connect =		uipc_connect, .pru_connect2 =		uipc_connect2, .pru_detach =		uipc_detach, .pru_disconnect =	uipc_disconnect, .pru_listen =		uipc_listen, .pru_peeraddr =		uipc_peeraddr, .pru_rcvd =		uipc_rcvd, .pru_send =		uipc_send, .pru_sense =		uipc_sense, .pru_shutdown =		uipc_shutdown, .pru_sockaddr =		uipc_sockaddr, .pru_soreceive =	soreceive_generic, .pru_close =		uipc_close, };

















static struct pr_usrreqs uipc_usrreqs_stream = {
	.pru_abort = 		uipc_abort, .pru_accept =		uipc_accept, .pru_attach =		uipc_attach, .pru_bind =		uipc_bind, .pru_connect =		uipc_connect, .pru_connect2 =		uipc_connect2, .pru_detach =		uipc_detach, .pru_disconnect =	uipc_disconnect, .pru_listen =		uipc_listen, .pru_peeraddr =		uipc_peeraddr, .pru_rcvd =		uipc_rcvd, .pru_send =		uipc_send, .pru_sense =		uipc_sense, .pru_shutdown =		uipc_shutdown, .pru_sockaddr =		uipc_sockaddr, .pru_soreceive =	soreceive_generic, .pru_close =		uipc_close, };

















static int uipc_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct unpcb *unp;
	struct xucred xu;
	int error, optval;

	if (sopt->sopt_level != 0)
		return (EINVAL);

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("uipc_ctloutput: unp == NULL"));
	error = 0;
	switch (sopt->sopt_dir) {
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case LOCAL_PEERCRED:
			UNP_PCB_LOCK(unp);
			if (unp->unp_flags & UNP_HAVEPC)
				xu = unp->unp_peercred;
			else {
				if (so->so_type == SOCK_STREAM)
					error = ENOTCONN;
				else error = EINVAL;
			}
			UNP_PCB_UNLOCK(unp);
			if (error == 0)
				error = sooptcopyout(sopt, &xu, sizeof(xu));
			break;

		case LOCAL_CREDS:
			
			optval = unp->unp_flags & UNP_WANTCRED ? 1 : 0;
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;

		case LOCAL_CONNWAIT:
			
			optval = unp->unp_flags & UNP_CONNWAIT ? 1 : 0;
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;

		default:
			error = EOPNOTSUPP;
			break;
		}
		break;

	case SOPT_SET:
		switch (sopt->sopt_name) {
		case LOCAL_CREDS:
		case LOCAL_CONNWAIT:
			error = sooptcopyin(sopt, &optval, sizeof(optval), sizeof(optval));
			if (error)
				break;









			switch (sopt->sopt_name) {
			case LOCAL_CREDS:
				OPTSET(UNP_WANTCRED);
				break;

			case LOCAL_CONNWAIT:
				OPTSET(UNP_CONNWAIT);
				break;

			default:
				break;
			}
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

static int unp_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct sockaddr_un *soun = (struct sockaddr_un *)nam;
	struct vnode *vp;
	struct socket *so2, *so3;
	struct unpcb *unp, *unp2, *unp3;
	int error, len, vfslocked;
	struct nameidata nd;
	char buf[SOCK_MAXADDRLEN];
	struct sockaddr *sa;

	UNP_LINK_WLOCK_ASSERT();

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("unp_connect: unp == NULL"));

	len = nam->sa_len - offsetof(struct sockaddr_un, sun_path);
	if (len <= 0)
		return (EINVAL);
	bcopy(soun->sun_path, buf, len);
	buf[len] = 0;

	UNP_PCB_LOCK(unp);
	if (unp->unp_flags & UNP_CONNECTING) {
		UNP_PCB_UNLOCK(unp);
		return (EALREADY);
	}
	UNP_LINK_WUNLOCK();
	unp->unp_flags |= UNP_CONNECTING;
	UNP_PCB_UNLOCK(unp);

	sa = malloc(sizeof(struct sockaddr_un), M_SONAME, M_WAITOK);
	NDINIT(&nd, LOOKUP, MPSAFE | FOLLOW | LOCKLEAF, UIO_SYSSPACE, buf, td);
	error = namei(&nd);
	if (error)
		vp = NULL;
	else vp = nd.ni_vp;
	ASSERT_VOP_LOCKED(vp, "unp_connect");
	vfslocked = NDHASGIANT(&nd);
	NDFREE(&nd, NDF_ONLY_PNBUF);
	if (error)
		goto bad;

	if (vp->v_type != VSOCK) {
		error = ENOTSOCK;
		goto bad;
	}

	error = mac_vnode_check_open(td->td_ucred, vp, VWRITE | VREAD);
	if (error)
		goto bad;

	error = VOP_ACCESS(vp, VWRITE, td->td_ucred, td);
	if (error)
		goto bad;
	VFS_UNLOCK_GIANT(vfslocked);

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("unp_connect: unp == NULL"));

	
	UNP_LINK_WLOCK();
	so2 = vp->v_socket;
	if (so2 == NULL) {
		error = ECONNREFUSED;
		goto bad2;
	}
	if (so->so_type != so2->so_type) {
		error = EPROTOTYPE;
		goto bad2;
	}
	if (so->so_proto->pr_flags & PR_CONNREQUIRED) {
		if (so2->so_options & SO_ACCEPTCONN) {
			CURVNET_SET(so2->so_vnet);
			so3 = sonewconn(so2, 0);
			CURVNET_RESTORE();
		} else so3 = NULL;
		if (so3 == NULL) {
			error = ECONNREFUSED;
			goto bad2;
		}
		unp = sotounpcb(so);
		unp2 = sotounpcb(so2);
		unp3 = sotounpcb(so3);
		UNP_PCB_LOCK(unp);
		UNP_PCB_LOCK(unp2);
		UNP_PCB_LOCK(unp3);
		if (unp2->unp_addr != NULL) {
			bcopy(unp2->unp_addr, sa, unp2->unp_addr->sun_len);
			unp3->unp_addr = (struct sockaddr_un *) sa;
			sa = NULL;
		}

		
		cru2x(td->td_ucred, &unp3->unp_peercred);
		unp3->unp_flags |= UNP_HAVEPC;

		
		KASSERT(unp2->unp_flags & UNP_HAVEPCCACHED, ("unp_connect: listener without cached peercred"));
		memcpy(&unp->unp_peercred, &unp2->unp_peercred, sizeof(unp->unp_peercred));
		unp->unp_flags |= UNP_HAVEPC;
		if (unp2->unp_flags & UNP_WANTCRED)
			unp3->unp_flags |= UNP_WANTCRED;
		UNP_PCB_UNLOCK(unp3);
		UNP_PCB_UNLOCK(unp2);
		UNP_PCB_UNLOCK(unp);

		mac_socketpeer_set_from_socket(so, so3);
		mac_socketpeer_set_from_socket(so3, so);


		so2 = so3;
	}
	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("unp_connect: unp == NULL"));
	unp2 = sotounpcb(so2);
	KASSERT(unp2 != NULL, ("unp_connect: unp2 == NULL"));
	UNP_PCB_LOCK(unp);
	UNP_PCB_LOCK(unp2);
	error = unp_connect2(so, so2, PRU_CONNECT);
	UNP_PCB_UNLOCK(unp2);
	UNP_PCB_UNLOCK(unp);
bad2:
	UNP_LINK_WUNLOCK();
	if (vfslocked)
		
		mtx_lock(&Giant);
bad:
	if (vp != NULL)
		vput(vp);
	VFS_UNLOCK_GIANT(vfslocked);
	free(sa, M_SONAME);
	UNP_LINK_WLOCK();
	UNP_PCB_LOCK(unp);
	unp->unp_flags &= ~UNP_CONNECTING;
	UNP_PCB_UNLOCK(unp);
	return (error);
}

static int unp_connect2(struct socket *so, struct socket *so2, int req)
{
	struct unpcb *unp;
	struct unpcb *unp2;

	unp = sotounpcb(so);
	KASSERT(unp != NULL, ("unp_connect2: unp == NULL"));
	unp2 = sotounpcb(so2);
	KASSERT(unp2 != NULL, ("unp_connect2: unp2 == NULL"));

	UNP_LINK_WLOCK_ASSERT();
	UNP_PCB_LOCK_ASSERT(unp);
	UNP_PCB_LOCK_ASSERT(unp2);

	if (so2->so_type != so->so_type)
		return (EPROTOTYPE);
	unp->unp_conn = unp2;

	switch (so->so_type) {
	case SOCK_DGRAM:
		LIST_INSERT_HEAD(&unp2->unp_refs, unp, unp_reflink);
		soisconnected(so);
		break;

	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		unp2->unp_conn = unp;
		if (req == PRU_CONNECT && ((unp->unp_flags | unp2->unp_flags) & UNP_CONNWAIT))
			soisconnecting(so);
		else soisconnected(so);
		soisconnected(so2);
		break;

	default:
		panic("unp_connect2");
	}
	return (0);
}

static void unp_disconnect(struct unpcb *unp, struct unpcb *unp2)
{
	struct socket *so;

	KASSERT(unp2 != NULL, ("unp_disconnect: unp2 == NULL"));

	UNP_LINK_WLOCK_ASSERT();
	UNP_PCB_LOCK_ASSERT(unp);
	UNP_PCB_LOCK_ASSERT(unp2);

	unp->unp_conn = NULL;
	switch (unp->unp_socket->so_type) {
	case SOCK_DGRAM:
		LIST_REMOVE(unp, unp_reflink);
		so = unp->unp_socket;
		SOCK_LOCK(so);
		so->so_state &= ~SS_ISCONNECTED;
		SOCK_UNLOCK(so);
		break;

	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		soisdisconnected(unp->unp_socket);
		unp2->unp_conn = NULL;
		soisdisconnected(unp2->unp_socket);
		break;
	}
}


static int unp_pcblist(SYSCTL_HANDLER_ARGS)
{
	int error, i, n;
	int freeunp;
	struct unpcb *unp, **unp_list;
	unp_gen_t gencnt;
	struct xunpgen *xug;
	struct unp_head *head;
	struct xunpcb *xu;

	switch ((intptr_t)arg1) {
	case SOCK_STREAM:
		head = &unp_shead;
		break;

	case SOCK_DGRAM:
		head = &unp_dhead;
		break;

	case SOCK_SEQPACKET:
		head = &unp_sphead;
		break;

	default:
		panic("unp_pcblist: arg1 %d", (int)(intptr_t)arg1);
	}

	
	if (req->oldptr == NULL) {
		n = unp_count;
		req->oldidx = 2 * (sizeof *xug)
			+ (n + n/8) * sizeof(struct xunpcb);
		return (0);
	}

	if (req->newptr != NULL)
		return (EPERM);

	
	xug = malloc(sizeof(*xug), M_TEMP, M_WAITOK);
	UNP_LIST_LOCK();
	gencnt = unp_gencnt;
	n = unp_count;
	UNP_LIST_UNLOCK();

	xug->xug_len = sizeof *xug;
	xug->xug_count = n;
	xug->xug_gen = gencnt;
	xug->xug_sogen = so_gencnt;
	error = SYSCTL_OUT(req, xug, sizeof *xug);
	if (error) {
		free(xug, M_TEMP);
		return (error);
	}

	unp_list = malloc(n * sizeof *unp_list, M_TEMP, M_WAITOK);

	UNP_LIST_LOCK();
	for (unp = LIST_FIRST(head), i = 0; unp && i < n;
	     unp = LIST_NEXT(unp, unp_link)) {
		UNP_PCB_LOCK(unp);
		if (unp->unp_gencnt <= gencnt) {
			if (cr_cansee(req->td->td_ucred, unp->unp_socket->so_cred)) {
				UNP_PCB_UNLOCK(unp);
				continue;
			}
			unp_list[i++] = unp;
			unp->unp_refcount++;
		}
		UNP_PCB_UNLOCK(unp);
	}
	UNP_LIST_UNLOCK();
	n = i;			

	error = 0;
	xu = malloc(sizeof(*xu), M_TEMP, M_WAITOK | M_ZERO);
	for (i = 0; i < n; i++) {
		unp = unp_list[i];
		UNP_PCB_LOCK(unp);
		unp->unp_refcount--;
	        if (unp->unp_refcount != 0 && unp->unp_gencnt <= gencnt) {
			xu->xu_len = sizeof *xu;
			xu->xu_unpp = unp;
			
			if (unp->unp_addr != NULL)
				bcopy(unp->unp_addr, &xu->xu_addr, unp->unp_addr->sun_len);
			if (unp->unp_conn != NULL && unp->unp_conn->unp_addr != NULL)
				bcopy(unp->unp_conn->unp_addr, &xu->xu_caddr, unp->unp_conn->unp_addr->sun_len);

			bcopy(unp, &xu->xu_unp, sizeof *unp);
			sotoxsocket(unp->unp_socket, &xu->xu_socket);
			UNP_PCB_UNLOCK(unp);
			error = SYSCTL_OUT(req, xu, sizeof *xu);
		} else {
			freeunp = (unp->unp_refcount == 0);
			UNP_PCB_UNLOCK(unp);
			if (freeunp) {
				UNP_PCB_LOCK_DESTROY(unp);
				uma_zfree(unp_zone, unp);
			}
		}
	}
	free(xu, M_TEMP);
	if (!error) {
		
		xug->xug_gen = unp_gencnt;
		xug->xug_sogen = so_gencnt;
		xug->xug_count = unp_count;
		error = SYSCTL_OUT(req, xug, sizeof *xug);
	}
	free(unp_list, M_TEMP);
	free(xug, M_TEMP);
	return (error);
}

SYSCTL_PROC(_net_local_dgram, OID_AUTO, pcblist, CTLTYPE_OPAQUE | CTLFLAG_RD, (void *)(intptr_t)SOCK_DGRAM, 0, unp_pcblist, "S,xunpcb", "List of active local datagram sockets");

SYSCTL_PROC(_net_local_stream, OID_AUTO, pcblist, CTLTYPE_OPAQUE | CTLFLAG_RD, (void *)(intptr_t)SOCK_STREAM, 0, unp_pcblist, "S,xunpcb", "List of active local stream sockets");

SYSCTL_PROC(_net_local_seqpacket, OID_AUTO, pcblist, CTLTYPE_OPAQUE | CTLFLAG_RD, (void *)(intptr_t)SOCK_SEQPACKET, 0, unp_pcblist, "S,xunpcb", "List of active local seqpacket sockets");



static void unp_shutdown(struct unpcb *unp)
{
	struct unpcb *unp2;
	struct socket *so;

	UNP_LINK_WLOCK_ASSERT();
	UNP_PCB_LOCK_ASSERT(unp);

	unp2 = unp->unp_conn;
	if ((unp->unp_socket->so_type == SOCK_STREAM || (unp->unp_socket->so_type == SOCK_SEQPACKET)) && unp2 != NULL) {
		so = unp2->unp_socket;
		if (so != NULL)
			socantrcvmore(so);
	}
}

static void unp_drop(struct unpcb *unp, int errno)
{
	struct socket *so = unp->unp_socket;
	struct unpcb *unp2;

	UNP_LINK_WLOCK_ASSERT();
	UNP_PCB_LOCK_ASSERT(unp);

	so->so_error = errno;
	unp2 = unp->unp_conn;
	if (unp2 == NULL)
		return;
	UNP_PCB_LOCK(unp2);
	unp_disconnect(unp, unp2);
	UNP_PCB_UNLOCK(unp2);
}

static void unp_freerights(struct file **rp, int fdcount)
{
	int i;
	struct file *fp;

	for (i = 0; i < fdcount; i++) {
		fp = *rp;
		*rp++ = NULL;
		unp_discard(fp);
	}
}

static int unp_externalize(struct mbuf *control, struct mbuf **controlp)
{
	struct thread *td = curthread;		
	struct cmsghdr *cm = mtod(control, struct cmsghdr *);
	int i;
	int *fdp;
	struct file **rp;
	struct file *fp;
	void *data;
	socklen_t clen = control->m_len, datalen;
	int error, newfds;
	int f;
	u_int newlen;

	UNP_LINK_UNLOCK_ASSERT();

	error = 0;
	if (controlp != NULL) 
		*controlp = NULL;
	while (cm != NULL) {
		if (sizeof(*cm) > clen || cm->cmsg_len > clen) {
			error = EINVAL;
			break;
		}
		data = CMSG_DATA(cm);
		datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
			newfds = datalen / sizeof(struct file *);
			rp = data;

			
			if (error || controlp == NULL) {
				unp_freerights(rp, newfds);
				goto next;
			}
			FILEDESC_XLOCK(td->td_proc->p_fd);
			
			if (!fdavail(td, newfds)) {
				FILEDESC_XUNLOCK(td->td_proc->p_fd);
				error = EMSGSIZE;
				unp_freerights(rp, newfds);
				goto next;
			}

			
			newlen = newfds * sizeof(int);
			*controlp = sbcreatecontrol(NULL, newlen, SCM_RIGHTS, SOL_SOCKET);
			if (*controlp == NULL) {
				FILEDESC_XUNLOCK(td->td_proc->p_fd);
				error = E2BIG;
				unp_freerights(rp, newfds);
				goto next;
			}

			fdp = (int *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			for (i = 0; i < newfds; i++) {
				if (fdalloc(td, 0, &f))
					panic("unp_externalize fdalloc failed");
				fp = *rp++;
				td->td_proc->p_fd->fd_ofiles[f] = fp;
				unp_externalize_fp(fp);
				*fdp++ = f;
			}
			FILEDESC_XUNLOCK(td->td_proc->p_fd);
		} else {
			
			if (error || controlp == NULL)
				goto next;
			*controlp = sbcreatecontrol(NULL, datalen, cm->cmsg_type, cm->cmsg_level);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto next;
			}
			bcopy(data, CMSG_DATA(mtod(*controlp, struct cmsghdr *)), datalen);

		}
		controlp = &(*controlp)->m_next;

next:
		if (CMSG_SPACE(datalen) < clen) {
			clen -= CMSG_SPACE(datalen);
			cm = (struct cmsghdr *)
			    ((caddr_t)cm + CMSG_SPACE(datalen));
		} else {
			clen = 0;
			cm = NULL;
		}
	}

	m_freem(control);
	return (error);
}

static void unp_zone_change(void *tag)
{

	uma_zone_set_max(unp_zone, maxsockets);
}

static void unp_init(void)
{


	if (!IS_DEFAULT_VNET(curvnet))
		return;

	unp_zone = uma_zcreate("unpcb", sizeof(struct unpcb), NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	if (unp_zone == NULL)
		panic("unp_init");
	uma_zone_set_max(unp_zone, maxsockets);
	EVENTHANDLER_REGISTER(maxsockets_change, unp_zone_change, NULL, EVENTHANDLER_PRI_ANY);
	LIST_INIT(&unp_dhead);
	LIST_INIT(&unp_shead);
	LIST_INIT(&unp_sphead);
	SLIST_INIT(&unp_defers);
	TASK_INIT(&unp_gc_task, 0, unp_gc, NULL);
	TASK_INIT(&unp_defer_task, 0, unp_process_defers, NULL);
	UNP_LINK_LOCK_INIT();
	UNP_LIST_LOCK_INIT();
	UNP_DEFERRED_LOCK_INIT();
}

static int unp_internalize(struct mbuf **controlp, struct thread *td)
{
	struct mbuf *control = *controlp;
	struct proc *p = td->td_proc;
	struct filedesc *fdescp = p->p_fd;
	struct cmsghdr *cm = mtod(control, struct cmsghdr *);
	struct cmsgcred *cmcred;
	struct file **rp;
	struct file *fp;
	struct timeval *tv;
	int i, fd, *fdp;
	void *data;
	socklen_t clen = control->m_len, datalen;
	int error, oldfds;
	u_int newlen;

	UNP_LINK_UNLOCK_ASSERT();

	error = 0;
	*controlp = NULL;
	while (cm != NULL) {
		if (sizeof(*cm) > clen || cm->cmsg_level != SOL_SOCKET || cm->cmsg_len > clen) {
			error = EINVAL;
			goto out;
		}
		data = CMSG_DATA(cm);
		datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;

		switch (cm->cmsg_type) {
		
		case SCM_CREDS:
			*controlp = sbcreatecontrol(NULL, sizeof(*cmcred), SCM_CREDS, SOL_SOCKET);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto out;
			}
			cmcred = (struct cmsgcred *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			cmcred->cmcred_pid = p->p_pid;
			cmcred->cmcred_uid = td->td_ucred->cr_ruid;
			cmcred->cmcred_gid = td->td_ucred->cr_rgid;
			cmcred->cmcred_euid = td->td_ucred->cr_uid;
			cmcred->cmcred_ngroups = MIN(td->td_ucred->cr_ngroups, CMGROUP_MAX);
			for (i = 0; i < cmcred->cmcred_ngroups; i++)
				cmcred->cmcred_groups[i] = td->td_ucred->cr_groups[i];
			break;

		case SCM_RIGHTS:
			oldfds = datalen / sizeof (int);
			
			fdp = data;
			FILEDESC_SLOCK(fdescp);
			for (i = 0; i < oldfds; i++) {
				fd = *fdp++;
				if ((unsigned)fd >= fdescp->fd_nfiles || fdescp->fd_ofiles[fd] == NULL) {
					FILEDESC_SUNLOCK(fdescp);
					error = EBADF;
					goto out;
				}
				fp = fdescp->fd_ofiles[fd];
				if (!(fp->f_ops->fo_flags & DFLAG_PASSABLE)) {
					FILEDESC_SUNLOCK(fdescp);
					error = EOPNOTSUPP;
					goto out;
				}

			}

			
			newlen = oldfds * sizeof(struct file *);
			*controlp = sbcreatecontrol(NULL, newlen, SCM_RIGHTS, SOL_SOCKET);
			if (*controlp == NULL) {
				FILEDESC_SUNLOCK(fdescp);
				error = E2BIG;
				goto out;
			}
			fdp = data;
			rp = (struct file **)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			for (i = 0; i < oldfds; i++) {
				fp = fdescp->fd_ofiles[*fdp++];
				*rp++ = fp;
				unp_internalize_fp(fp);
			}
			FILEDESC_SUNLOCK(fdescp);
			break;

		case SCM_TIMESTAMP:
			*controlp = sbcreatecontrol(NULL, sizeof(*tv), SCM_TIMESTAMP, SOL_SOCKET);
			if (*controlp == NULL) {
				error = ENOBUFS;
				goto out;
			}
			tv = (struct timeval *)
			    CMSG_DATA(mtod(*controlp, struct cmsghdr *));
			microtime(tv);
			break;

		default:
			error = EINVAL;
			goto out;
		}

		controlp = &(*controlp)->m_next;
		if (CMSG_SPACE(datalen) < clen) {
			clen -= CMSG_SPACE(datalen);
			cm = (struct cmsghdr *)
			    ((caddr_t)cm + CMSG_SPACE(datalen));
		} else {
			clen = 0;
			cm = NULL;
		}
	}

out:
	m_freem(control);
	return (error);
}

static struct mbuf * unp_addsockcred(struct thread *td, struct mbuf *control)
{
	struct mbuf *m, *n, *n_prev;
	struct sockcred *sc;
	const struct cmsghdr *cm;
	int ngroups;
	int i;

	ngroups = MIN(td->td_ucred->cr_ngroups, CMGROUP_MAX);
	m = sbcreatecontrol(NULL, SOCKCREDSIZE(ngroups), SCM_CREDS, SOL_SOCKET);
	if (m == NULL)
		return (control);

	sc = (struct sockcred *) CMSG_DATA(mtod(m, struct cmsghdr *));
	sc->sc_uid = td->td_ucred->cr_ruid;
	sc->sc_euid = td->td_ucred->cr_uid;
	sc->sc_gid = td->td_ucred->cr_rgid;
	sc->sc_egid = td->td_ucred->cr_gid;
	sc->sc_ngroups = ngroups;
	for (i = 0; i < sc->sc_ngroups; i++)
		sc->sc_groups[i] = td->td_ucred->cr_groups[i];

	
	if (control != NULL)
		for (n = control, n_prev = NULL; n != NULL;) {
			cm = mtod(n, struct cmsghdr *);
    			if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_CREDS) {
    				if (n_prev == NULL)
					control = n->m_next;
				else n_prev->m_next = n->m_next;
				n = m_free(n);
			} else {
				n_prev = n;
				n = n->m_next;
			}
		}

	
	m->m_next = control;
	return (m);
}

static struct unpcb * fptounp(struct file *fp)
{
	struct socket *so;

	if (fp->f_type != DTYPE_SOCKET)
		return (NULL);
	if ((so = fp->f_data) == NULL)
		return (NULL);
	if (so->so_proto->pr_domain != &localdomain)
		return (NULL);
	return sotounpcb(so);
}

static void unp_discard(struct file *fp)
{
	struct unp_defer *dr;

	if (unp_externalize_fp(fp)) {
		dr = malloc(sizeof(*dr), M_TEMP, M_WAITOK);
		dr->ud_fp = fp;
		UNP_DEFERRED_LOCK();
		SLIST_INSERT_HEAD(&unp_defers, dr, ud_link);
		UNP_DEFERRED_UNLOCK();
		atomic_add_int(&unp_defers_count, 1);
		taskqueue_enqueue(taskqueue_thread, &unp_defer_task);
	} else (void) closef(fp, (struct thread *)NULL);
}

static void unp_process_defers(void *arg __unused, int pending)
{
	struct unp_defer *dr;
	SLIST_HEAD(, unp_defer) drl;
	int count;

	SLIST_INIT(&drl);
	for (;;) {
		UNP_DEFERRED_LOCK();
		if (SLIST_FIRST(&unp_defers) == NULL) {
			UNP_DEFERRED_UNLOCK();
			break;
		}
		SLIST_SWAP(&unp_defers, &drl, unp_defer);
		UNP_DEFERRED_UNLOCK();
		count = 0;
		while ((dr = SLIST_FIRST(&drl)) != NULL) {
			SLIST_REMOVE_HEAD(&drl, ud_link);
			closef(dr->ud_fp, NULL);
			free(dr, M_TEMP);
			count++;
		}
		atomic_add_int(&unp_defers_count, -count);
	}
}

static void unp_internalize_fp(struct file *fp)
{
	struct unpcb *unp;

	UNP_LINK_WLOCK();
	if ((unp = fptounp(fp)) != NULL) {
		unp->unp_file = fp;
		unp->unp_msgcount++;
	}
	fhold(fp);
	unp_rights++;
	UNP_LINK_WUNLOCK();
}

static int unp_externalize_fp(struct file *fp)
{
	struct unpcb *unp;
	int ret;

	UNP_LINK_WLOCK();
	if ((unp = fptounp(fp)) != NULL) {
		unp->unp_msgcount--;
		ret = 1;
	} else ret = 0;
	unp_rights--;
	UNP_LINK_WUNLOCK();
	return (ret);
}


static int	unp_marked;
static int	unp_unreachable;

static void unp_accessable(struct file *fp)
{
	struct unpcb *unp;

	if ((unp = fptounp(fp)) == NULL)
		return;
	if (unp->unp_gcflag & UNPGC_REF)
		return;
	unp->unp_gcflag &= ~UNPGC_DEAD;
	unp->unp_gcflag |= UNPGC_REF;
	unp_marked++;
}

static void unp_gc_process(struct unpcb *unp)
{
	struct socket *soa;
	struct socket *so;
	struct file *fp;

	
	if (unp->unp_gcflag & UNPGC_SCANNED)
		return;
	fp = unp->unp_file;

	
	if ((unp->unp_gcflag & UNPGC_REF) == 0 && fp && unp->unp_msgcount != 0 && fp->f_count == unp->unp_msgcount) {
		unp->unp_gcflag |= UNPGC_DEAD;
		unp_unreachable++;
		return;
	}

	
	so = unp->unp_socket;
	SOCKBUF_LOCK(&so->so_rcv);
	unp_scan(so->so_rcv.sb_mb, unp_accessable);
	SOCKBUF_UNLOCK(&so->so_rcv);

	
	ACCEPT_LOCK();
	TAILQ_FOREACH(soa, &so->so_comp, so_list) {
		SOCKBUF_LOCK(&soa->so_rcv);
		unp_scan(soa->so_rcv.sb_mb, unp_accessable);
		SOCKBUF_UNLOCK(&soa->so_rcv);
	}
	ACCEPT_UNLOCK();
	unp->unp_gcflag |= UNPGC_SCANNED;
}

static int unp_recycled;
SYSCTL_INT(_net_local, OID_AUTO, recycled, CTLFLAG_RD, &unp_recycled, 0,  "Number of unreachable sockets claimed by the garbage collector.");

static int unp_taskcount;
SYSCTL_INT(_net_local, OID_AUTO, taskcount, CTLFLAG_RD, &unp_taskcount, 0,  "Number of times the garbage collector has run.");

static void unp_gc(__unused void *arg, int pending)
{
	struct unp_head *heads[] = { &unp_dhead, &unp_shead, &unp_sphead, NULL };
	struct unp_head **head;
	struct file *f, **unref;
	struct unpcb *unp;
	int i, total;

	unp_taskcount++;
	UNP_LIST_LOCK();
	
	for (head = heads; *head != NULL; head++)
		LIST_FOREACH(unp, *head, unp_link)
			unp->unp_gcflag = 0;

	
	do {
		unp_unreachable = 0;
		unp_marked = 0;
		for (head = heads; *head != NULL; head++)
			LIST_FOREACH(unp, *head, unp_link)
				unp_gc_process(unp);
	} while (unp_marked);
	UNP_LIST_UNLOCK();
	if (unp_unreachable == 0)
		return;

	
	unref = malloc(unp_unreachable * sizeof(struct file *), M_TEMP, M_WAITOK);

	
	UNP_LINK_RLOCK();
	UNP_LIST_LOCK();
	for (total = 0, head = heads; *head != NULL; head++)
		LIST_FOREACH(unp, *head, unp_link)
			if ((unp->unp_gcflag & UNPGC_DEAD) != 0) {
				f = unp->unp_file;
				if (unp->unp_msgcount == 0 || f == NULL || f->f_count != unp->unp_msgcount)
					continue;
				unref[total++] = f;
				fhold(f);
				KASSERT(total <= unp_unreachable, ("unp_gc: incorrect unreachable count."));
			}
	UNP_LIST_UNLOCK();
	UNP_LINK_RUNLOCK();

	
	for (i = 0; i < total; i++) {
		struct socket *so;

		so = unref[i]->f_data;
		CURVNET_SET(so->so_vnet);
		sorflush(so);
		CURVNET_RESTORE();
	}

	
	for (i = 0; i < total; i++)
		fdrop(unref[i], NULL);
	unp_recycled += total;
	free(unref, M_TEMP);
}

static void unp_dispose(struct mbuf *m)
{

	if (m)
		unp_scan(m, unp_discard);
}

static void unp_scan(struct mbuf *m0, void (*op)(struct file *))
{
	struct mbuf *m;
	struct file **rp;
	struct cmsghdr *cm;
	void *data;
	int i;
	socklen_t clen, datalen;
	int qfds;

	while (m0 != NULL) {
		for (m = m0; m; m = m->m_next) {
			if (m->m_type != MT_CONTROL)
				continue;

			cm = mtod(m, struct cmsghdr *);
			clen = m->m_len;

			while (cm != NULL) {
				if (sizeof(*cm) > clen || cm->cmsg_len > clen)
					break;

				data = CMSG_DATA(cm);
				datalen = (caddr_t)cm + cm->cmsg_len - (caddr_t)data;

				if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
					qfds = datalen / sizeof (struct file *);
					rp = data;
					for (i = 0; i < qfds; i++)
						(*op)(*rp++);
				}

				if (CMSG_SPACE(datalen) < clen) {
					clen -= CMSG_SPACE(datalen);
					cm = (struct cmsghdr *)
					    ((caddr_t)cm + CMSG_SPACE(datalen));
				} else {
					clen = 0;
					cm = NULL;
				}
			}
		}
		m0 = m0->m_act;
	}
}


static void db_print_indent(int indent)
{
	int i;

	for (i = 0; i < indent; i++)
		db_printf(" ");
}

static void db_print_unpflags(int unp_flags)
{
	int comma;

	comma = 0;
	if (unp_flags & UNP_HAVEPC) {
		db_printf("%sUNP_HAVEPC", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_HAVEPCCACHED) {
		db_printf("%sUNP_HAVEPCCACHED", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_WANTCRED) {
		db_printf("%sUNP_WANTCRED", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_CONNWAIT) {
		db_printf("%sUNP_CONNWAIT", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_CONNECTING) {
		db_printf("%sUNP_CONNECTING", comma ? ", " : "");
		comma = 1;
	}
	if (unp_flags & UNP_BINDING) {
		db_printf("%sUNP_BINDING", comma ? ", " : "");
		comma = 1;
	}
}

static void db_print_xucred(int indent, struct xucred *xu)
{
	int comma, i;

	db_print_indent(indent);
	db_printf("cr_version: %u   cr_uid: %u   cr_ngroups: %d\n", xu->cr_version, xu->cr_uid, xu->cr_ngroups);
	db_print_indent(indent);
	db_printf("cr_groups: ");
	comma = 0;
	for (i = 0; i < xu->cr_ngroups; i++) {
		db_printf("%s%u", comma ? ", " : "", xu->cr_groups[i]);
		comma = 1;
	}
	db_printf("\n");
}

static void db_print_unprefs(int indent, struct unp_head *uh)
{
	struct unpcb *unp;
	int counter;

	counter = 0;
	LIST_FOREACH(unp, uh, unp_reflink) {
		if (counter % 4 == 0)
			db_print_indent(indent);
		db_printf("%p  ", unp);
		if (counter % 4 == 3)
			db_printf("\n");
		counter++;
	}
	if (counter != 0 && counter % 4 != 0)
		db_printf("\n");
}

DB_SHOW_COMMAND(unpcb, db_show_unpcb)
{
	struct unpcb *unp;

        if (!have_addr) {
                db_printf("usage: show unpcb <addr>\n");
                return;
        }
        unp = (struct unpcb *)addr;

	db_printf("unp_socket: %p   unp_vnode: %p\n", unp->unp_socket, unp->unp_vnode);

	db_printf("unp_ino: %d   unp_conn: %p\n", unp->unp_ino, unp->unp_conn);

	db_printf("unp_refs:\n");
	db_print_unprefs(2, &unp->unp_refs);

	
	db_printf("unp_addr: %p\n", unp->unp_addr);

	db_printf("unp_cc: %d   unp_mbcnt: %d   unp_gencnt: %llu\n", unp->unp_cc, unp->unp_mbcnt, (unsigned long long)unp->unp_gencnt);


	db_printf("unp_flags: %x (", unp->unp_flags);
	db_print_unpflags(unp->unp_flags);
	db_printf(")\n");

	db_printf("unp_peercred:\n");
	db_print_xucred(2, &unp->unp_peercred);

	db_printf("unp_refcount: %u\n", unp->unp_refcount);
}

