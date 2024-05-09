













static const char tstr[] = "[|wb]";














struct pkt_hdr {
	uint32_t ph_src;		
	uint32_t ph_ts;		
	uint16_t ph_version;	
	u_char ph_type;		
	u_char ph_flags;	
};


















struct PageID {
	uint32_t p_sid;		
	uint32_t p_uid;		
};

struct dophdr {
	uint32_t  dh_ts;		
	uint16_t	dh_len;		
	u_char	dh_flags;
	u_char	dh_type;	
	
};


















struct pkt_dop {
	struct PageID pd_page;	
	uint32_t	pd_sseq;	
	uint32_t	pd_eseq;	
	
};


struct pkt_rreq {
        uint32_t pr_id;           
        struct PageID pr_page;           
        uint32_t pr_sseq;         
        uint32_t pr_eseq;         
};


struct pkt_rrep {
	uint32_t pr_id;	
	struct pkt_dop pr_dop;
	
};

struct id_off {
        uint32_t id;
        uint32_t off;
};

struct pgstate {
	uint32_t slot;
	struct PageID page;
	uint16_t nid;
	uint16_t rsvd;
        
};


struct pkt_id {
	uint32_t pi_mslot;
        struct PageID    pi_mpage;        
	struct pgstate pi_ps;
        
        
};

struct pkt_preq {
        struct PageID  pp_page;
        uint32_t  pp_low;
        uint32_t  pp_high;
};

struct pkt_prep {
        uint32_t  pp_n;           
        
};

static int wb_id(netdissect_options *ndo, const struct pkt_id *id, u_int len)

{
	int i;
	const char *cp;
	const struct id_off *io;
	char c;
	int nid;

	ND_PRINT((ndo, " wb-id:"));
	if (len < sizeof(*id) || !ND_TTEST(*id))
		return (-1);
	len -= sizeof(*id);

	ND_PRINT((ndo, " %u/%s:%u (max %u/%s:%u) ", EXTRACT_32BITS(&id->pi_ps.slot), ipaddr_string(ndo, &id->pi_ps.page.p_sid), EXTRACT_32BITS(&id->pi_ps.page.p_uid), EXTRACT_32BITS(&id->pi_mslot), ipaddr_string(ndo, &id->pi_mpage.p_sid), EXTRACT_32BITS(&id->pi_mpage.p_uid)));






	nid = EXTRACT_16BITS(&id->pi_ps.nid);
	len -= sizeof(*io) * nid;
	io = (const struct id_off *)(id + 1);
	cp = (const char *)(io + nid);
	if (ND_TTEST2(cp, len)) {
		ND_PRINT((ndo, "\""));
		fn_print(ndo, (const u_char *)cp, (const u_char *)cp + len);
		ND_PRINT((ndo, "\""));
	}

	c = '<';
	for (i = 0; i < nid && ND_TTEST(*io); ++io, ++i) {
		ND_PRINT((ndo, "%c%s:%u", c, ipaddr_string(ndo, &io->id), EXTRACT_32BITS(&io->off)));
		c = ',';
	}
	if (i >= nid) {
		ND_PRINT((ndo, ">"));
		return (0);
	}
	return (-1);
}

static int wb_rreq(netdissect_options *ndo, const struct pkt_rreq *rreq, u_int len)

{
	ND_PRINT((ndo, " wb-rreq:"));
	if (len < sizeof(*rreq) || !ND_TTEST(*rreq))
		return (-1);

	ND_PRINT((ndo, " please repair %s %s:%u<%u:%u>", ipaddr_string(ndo, &rreq->pr_id), ipaddr_string(ndo, &rreq->pr_page.p_sid), EXTRACT_32BITS(&rreq->pr_page.p_uid), EXTRACT_32BITS(&rreq->pr_sseq), EXTRACT_32BITS(&rreq->pr_eseq)));




	return (0);
}

static int wb_preq(netdissect_options *ndo, const struct pkt_preq *preq, u_int len)

{
	ND_PRINT((ndo, " wb-preq:"));
	if (len < sizeof(*preq) || !ND_TTEST(*preq))
		return (-1);

	ND_PRINT((ndo, " need %u/%s:%u", EXTRACT_32BITS(&preq->pp_low), ipaddr_string(ndo, &preq->pp_page.p_sid), EXTRACT_32BITS(&preq->pp_page.p_uid)));


	return (0);
}

static int wb_prep(netdissect_options *ndo, const struct pkt_prep *prep, u_int len)

{
	int n;
	const struct pgstate *ps;
	const u_char *ep = ndo->ndo_snapend;

	ND_PRINT((ndo, " wb-prep:"));
	if (len < sizeof(*prep)) {
		return (-1);
	}
	n = EXTRACT_32BITS(&prep->pp_n);
	ps = (const struct pgstate *)(prep + 1);
	while (--n >= 0 && ND_TTEST(*ps)) {
		const struct id_off *io, *ie;
		char c = '<';

		ND_PRINT((ndo, " %u/%s:%u", EXTRACT_32BITS(&ps->slot), ipaddr_string(ndo, &ps->page.p_sid), EXTRACT_32BITS(&ps->page.p_uid)));


		io = (const struct id_off *)(ps + 1);
		for (ie = io + ps->nid; io < ie && ND_TTEST(*io); ++io) {
			ND_PRINT((ndo, "%c%s:%u", c, ipaddr_string(ndo, &io->id), EXTRACT_32BITS(&io->off)));
			c = ',';
		}
		ND_PRINT((ndo, ">"));
		ps = (const struct pgstate *)io;
	}
	return ((const u_char *)ps <= ep? 0 : -1);
}


static const char *dopstr[] = {
	"dop-0!", "dop-1!", "RECT", "LINE", "ML", "DEL", "XFORM", "ELL", "CHAR", "STR", "NOP", "PSCODE", "PSCOMP", "REF", "SKIP", "HOLE", };
















static int wb_dops(netdissect_options *ndo, const struct pkt_dop *dop, uint32_t ss, uint32_t es)

{
	const struct dophdr *dh = (const struct dophdr *)((const u_char *)dop + sizeof(*dop));

	ND_PRINT((ndo, " <"));
	for ( ; ss <= es; ++ss) {
		int t;

		if (!ND_TTEST(*dh)) {
			ND_PRINT((ndo, "%s", tstr));
			break;
		}
		t = dh->dh_type;

		if (t > DT_MAXTYPE)
			ND_PRINT((ndo, " dop-%d!", t));
		else {
			ND_PRINT((ndo, " %s", dopstr[t]));
			if (t == DT_SKIP || t == DT_HOLE) {
				uint32_t ts = EXTRACT_32BITS(&dh->dh_ts);
				ND_PRINT((ndo, "%d", ts - ss + 1));
				if (ss > ts || ts > es) {
					ND_PRINT((ndo, "[|]"));
					if (ts < ss)
						return (0);
				}
				ss = ts;
			}
		}
		dh = DOP_NEXT(dh);
	}
	ND_PRINT((ndo, " >"));
	return (0);
}

static int wb_rrep(netdissect_options *ndo, const struct pkt_rrep *rrep, u_int len)

{
	const struct pkt_dop *dop = &rrep->pr_dop;

	ND_PRINT((ndo, " wb-rrep:"));
	if (len < sizeof(*rrep) || !ND_TTEST(*rrep))
		return (-1);
	len -= sizeof(*rrep);

	ND_PRINT((ndo, " for %s %s:%u<%u:%u>", ipaddr_string(ndo, &rrep->pr_id), ipaddr_string(ndo, &dop->pd_page.p_sid), EXTRACT_32BITS(&dop->pd_page.p_uid), EXTRACT_32BITS(&dop->pd_sseq), EXTRACT_32BITS(&dop->pd_eseq)));





	if (ndo->ndo_vflag)
		return (wb_dops(ndo, dop, EXTRACT_32BITS(&dop->pd_sseq), EXTRACT_32BITS(&dop->pd_eseq)));

	return (0);
}

static int wb_drawop(netdissect_options *ndo, const struct pkt_dop *dop, u_int len)

{
	ND_PRINT((ndo, " wb-dop:"));
	if (len < sizeof(*dop) || !ND_TTEST(*dop))
		return (-1);
	len -= sizeof(*dop);

	ND_PRINT((ndo, " %s:%u<%u:%u>", ipaddr_string(ndo, &dop->pd_page.p_sid), EXTRACT_32BITS(&dop->pd_page.p_uid), EXTRACT_32BITS(&dop->pd_sseq), EXTRACT_32BITS(&dop->pd_eseq)));




	if (ndo->ndo_vflag)
		return (wb_dops(ndo, dop, EXTRACT_32BITS(&dop->pd_sseq), EXTRACT_32BITS(&dop->pd_eseq)));

	return (0);
}


void wb_print(netdissect_options *ndo, register const void *hdr, register u_int len)

{
	register const struct pkt_hdr *ph;

	ph = (const struct pkt_hdr *)hdr;
	if (len < sizeof(*ph) || !ND_TTEST(*ph)) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	}
	len -= sizeof(*ph);

	if (ph->ph_flags)
		ND_PRINT((ndo, "*"));
	switch (ph->ph_type) {

	case PT_KILL:
		ND_PRINT((ndo, " wb-kill"));
		return;

	case PT_ID:
		if (wb_id(ndo, (const struct pkt_id *)(ph + 1), len) >= 0)
			return;
		break;

	case PT_RREQ:
		if (wb_rreq(ndo, (const struct pkt_rreq *)(ph + 1), len) >= 0)
			return;
		break;

	case PT_RREP:
		if (wb_rrep(ndo, (const struct pkt_rrep *)(ph + 1), len) >= 0)
			return;
		break;

	case PT_DRAWOP:
		if (wb_drawop(ndo, (const struct pkt_dop *)(ph + 1), len) >= 0)
			return;
		break;

	case PT_PREQ:
		if (wb_preq(ndo, (const struct pkt_preq *)(ph + 1), len) >= 0)
			return;
		break;

	case PT_PREP:
		if (wb_prep(ndo, (const struct pkt_prep *)(ph + 1), len) >= 0)
			return;
		break;

	default:
		ND_PRINT((ndo, " wb-%d!", ph->ph_type));
		return;
	}
}
