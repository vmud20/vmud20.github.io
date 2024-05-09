

















static const char tstr[] = "[|igmp]";




struct tr_query {
    uint32_t  tr_src;          
    uint32_t  tr_dst;          
    uint32_t  tr_raddr;        
    uint32_t  tr_rttlqid;      
};





struct tr_resp {
    uint32_t tr_qarr;          
    uint32_t tr_inaddr;        
    uint32_t tr_outaddr;       
    uint32_t tr_rmtaddr;       
    uint32_t tr_vifin;         
    uint32_t tr_vifout;        
    uint32_t tr_pktcnt;        
    uint8_t  tr_rproto;      
    uint8_t  tr_fttl;        
    uint8_t  tr_smask;       
    uint8_t  tr_rflags;      
};























static const struct tok igmpv3report2str[] = {
	{ 1,	"is_in" }, { 2,	"is_ex" }, { 3,	"to_in" }, { 4,	"to_ex" }, { 5,	"allow" }, { 6,	"block" }, { 0,	NULL }





};

static void print_mtrace(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
    register const struct tr_query *tr = (const struct tr_query *)(bp + 8);

    ND_TCHECK(*tr);
    if (len < 8 + sizeof (struct tr_query)) {
	ND_PRINT((ndo, " [invalid len %d]", len));
	return;
    }
    ND_PRINT((ndo, "mtrace %u: %s to %s reply-to %s", TR_GETQID(EXTRACT_32BITS(&tr->tr_rttlqid)), ipaddr_string(ndo, &tr->tr_src), ipaddr_string(ndo, &tr->tr_dst), ipaddr_string(ndo, &tr->tr_raddr)));


    if (IN_CLASSD(EXTRACT_32BITS(&tr->tr_raddr)))
        ND_PRINT((ndo, " with-ttl %d", TR_GETTTL(EXTRACT_32BITS(&tr->tr_rttlqid))));
    return;
trunc:
    ND_PRINT((ndo, "%s", tstr));
}

static void print_mresp(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
    register const struct tr_query *tr = (const struct tr_query *)(bp + 8);

    ND_TCHECK(*tr);
    if (len < 8 + sizeof (struct tr_query)) {
	ND_PRINT((ndo, " [invalid len %d]", len));
	return;
    }
    ND_PRINT((ndo, "mresp %lu: %s to %s reply-to %s", (u_long)TR_GETQID(EXTRACT_32BITS(&tr->tr_rttlqid)), ipaddr_string(ndo, &tr->tr_src), ipaddr_string(ndo, &tr->tr_dst), ipaddr_string(ndo, &tr->tr_raddr)));


    if (IN_CLASSD(EXTRACT_32BITS(&tr->tr_raddr)))
        ND_PRINT((ndo, " with-ttl %d", TR_GETTTL(EXTRACT_32BITS(&tr->tr_rttlqid))));
    return;
trunc:
    ND_PRINT((ndo, "%s", tstr));
}

static void print_igmpv3_report(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
    u_int group, nsrcs, ngroups;
    register u_int i, j;

    
    if (len < 16 || len & 0x03) {
	ND_PRINT((ndo, " [invalid len %d]", len));
	return;
    }
    ND_TCHECK2(bp[6], 2);
    ngroups = EXTRACT_16BITS(&bp[6]);
    ND_PRINT((ndo, ", %d group record(s)", ngroups));
    if (ndo->ndo_vflag > 0) {
	
	group = 8;
        for (i=0; i<ngroups; i++) {
	    if (len < group+8) {
		ND_PRINT((ndo, " [invalid number of groups]"));
		return;
	    }
	    ND_TCHECK2(bp[group+4], 4);
            ND_PRINT((ndo, " [gaddr %s", ipaddr_string(ndo, &bp[group+4])));
	    ND_PRINT((ndo, " %s", tok2str(igmpv3report2str, " [v3-report-#%d]", bp[group])));
            nsrcs = EXTRACT_16BITS(&bp[group+2]);
	    
	    if (len < group+8+(nsrcs<<2)) {
		ND_PRINT((ndo, " [invalid number of sources %d]", nsrcs));
		return;
	    }
            if (ndo->ndo_vflag == 1)
                ND_PRINT((ndo, ", %d source(s)", nsrcs));
            else {
		
                ND_PRINT((ndo, " {"));
                for (j=0; j<nsrcs; j++) {
		    ND_TCHECK2(bp[group+8+(j<<2)], 4);
		    ND_PRINT((ndo, " %s", ipaddr_string(ndo, &bp[group+8+(j<<2)])));
		}
                ND_PRINT((ndo, " }"));
            }
	    
            group += 8 + (nsrcs << 2);
	    ND_PRINT((ndo, "]"));
        }
    }
    return;
trunc:
    ND_PRINT((ndo, "%s", tstr));
}

static void print_igmpv3_query(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
    u_int mrc;
    int mrt;
    u_int nsrcs;
    register u_int i;

    ND_PRINT((ndo, " v3"));
    
    if (len < 12 || len & 0x03) {
	ND_PRINT((ndo, " [invalid len %d]", len));
	return;
    }
    ND_TCHECK(bp[1]);
    mrc = bp[1];
    if (mrc < 128) {
	mrt = mrc;
    } else {
        mrt = ((mrc & 0x0f) | 0x10) << (((mrc & 0x70) >> 4) + 3);
    }
    if (mrc != 100) {
	ND_PRINT((ndo, " [max resp time "));
        if (mrt < 600) {
            ND_PRINT((ndo, "%.1fs", mrt * 0.1));
        } else {
            relts_print(ndo, mrt / 10);
        }
	ND_PRINT((ndo, "]"));
    }
    ND_TCHECK2(bp[4], 4);
    if (EXTRACT_32BITS(&bp[4]) == 0)
	return;
    ND_PRINT((ndo, " [gaddr %s", ipaddr_string(ndo, &bp[4])));
    ND_TCHECK2(bp[10], 2);
    nsrcs = EXTRACT_16BITS(&bp[10]);
    if (nsrcs > 0) {
	if (len < 12 + (nsrcs << 2))
	    ND_PRINT((ndo, " [invalid number of sources]"));
	else if (ndo->ndo_vflag > 1) {
	    ND_PRINT((ndo, " {"));
	    for (i=0; i<nsrcs; i++) {
		ND_TCHECK2(bp[12+(i<<2)], 4);
		ND_PRINT((ndo, " %s", ipaddr_string(ndo, &bp[12+(i<<2)])));
	    }
	    ND_PRINT((ndo, " }"));
	} else ND_PRINT((ndo, ", %d source(s)", nsrcs));
    }
    ND_PRINT((ndo, "]"));
    return;
trunc:
    ND_PRINT((ndo, "%s", tstr));
}

void igmp_print(netdissect_options *ndo, register const u_char *bp, register u_int len)

{
    struct cksum_vec vec[1];

    if (ndo->ndo_qflag) {
        ND_PRINT((ndo, "igmp"));
        return;
    }

    ND_TCHECK(bp[0]);
    switch (bp[0]) {
    case 0x11:
        ND_PRINT((ndo, "igmp query"));
	if (len >= 12)
	    print_igmpv3_query(ndo, bp, len);
	else {
            ND_TCHECK(bp[1]);
	    if (bp[1]) {
		ND_PRINT((ndo, " v2"));
		if (bp[1] != 100)
		    ND_PRINT((ndo, " [max resp time %d]", bp[1]));
	    } else ND_PRINT((ndo, " v1"));
            ND_TCHECK2(bp[4], 4);
	    if (EXTRACT_32BITS(&bp[4]))
                ND_PRINT((ndo, " [gaddr %s]", ipaddr_string(ndo, &bp[4])));
            if (len != 8)
                ND_PRINT((ndo, " [len %d]", len));
	}
        break;
    case 0x12:
        ND_TCHECK2(bp[4], 4);
        ND_PRINT((ndo, "igmp v1 report %s", ipaddr_string(ndo, &bp[4])));
        if (len != 8)
            ND_PRINT((ndo, " [len %d]", len));
        break;
    case 0x16:
        ND_TCHECK2(bp[4], 4);
        ND_PRINT((ndo, "igmp v2 report %s", ipaddr_string(ndo, &bp[4])));
        break;
    case 0x22:
        ND_PRINT((ndo, "igmp v3 report"));
	print_igmpv3_report(ndo, bp, len);
        break;
    case 0x17:
        ND_TCHECK2(bp[4], 4);
        ND_PRINT((ndo, "igmp leave %s", ipaddr_string(ndo, &bp[4])));
        break;
    case 0x13:
        ND_PRINT((ndo, "igmp dvmrp"));
        if (len < 8)
            ND_PRINT((ndo, " [len %d]", len));
        else dvmrp_print(ndo, bp, len);
        break;
    case 0x14:
        ND_PRINT((ndo, "igmp pimv1"));
        pimv1_print(ndo, bp, len);
        break;
    case 0x1e:
        print_mresp(ndo, bp, len);
        break;
    case 0x1f:
        print_mtrace(ndo, bp, len);
        break;
    default:
        ND_PRINT((ndo, "igmp-%d", bp[0]));
        break;
    }

    if (ndo->ndo_vflag && ND_TTEST2(bp[0], len)) {
        
        vec[0].ptr = bp;
        vec[0].len = len;
        if (in_cksum(vec, 1))
            ND_PRINT((ndo, " bad igmp cksum %x!", EXTRACT_16BITS(&bp[2])));
    }
    return;
trunc:
    ND_PRINT((ndo, "%s", tstr));
}
