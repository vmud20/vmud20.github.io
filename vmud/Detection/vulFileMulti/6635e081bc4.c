

























struct xrdata {
	dns_rdata_t	rdata;
	unsigned int	order;
};


static int compare_rdata(const void *p1, const void *p2) {
	const struct xrdata *x1 = p1;
	const struct xrdata *x2 = p2;
	return (dns_rdata_compare(&x1->rdata, &x2->rdata));
}


static void fillin_offsets(unsigned char *offsetbase, unsigned int *offsettable, unsigned length)

{
	unsigned int i, j;
	unsigned char *raw;

	for (i = 0, j = 0; i < length; i++) {

		if (offsettable[i] == 0)
			continue;

		
		raw = &offsetbase[j*4 + 2];
		*raw++ = (offsettable[i] & 0xff000000) >> 24;
		*raw++ = (offsettable[i] & 0xff0000) >> 16;
		*raw++ = (offsettable[i] & 0xff00) >> 8;
		*raw = offsettable[i] & 0xff;

		
		raw = offsetbase + offsettable[i] + 2;
		*raw++ = (j & 0xff00) >> 8;
		*raw = j++ & 0xff;
	}
}


isc_result_t dns_rdataslab_fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region, unsigned int reservelen)

{
	struct xrdata  *x;
	unsigned char  *rawbuf;

	unsigned char  *offsetbase;

	unsigned int	buflen;
	isc_result_t	result;
	unsigned int	nitems;
	unsigned int	nalloc;
	unsigned int	i;

	unsigned int   *offsettable;


	buflen = reservelen + 2;

	nalloc = dns_rdataset_count(rdataset);
	nitems = nalloc;
	if (nitems == 0)
		return (ISC_R_FAILURE);

	if (nalloc > 0xffff)
		return (ISC_R_NOSPACE);

	x = isc_mem_get(mctx, nalloc * sizeof(struct xrdata));
	if (x == NULL)
		return (ISC_R_NOMEMORY);

	
	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS)
		goto free_rdatas;
	for (i = 0; i < nalloc && result == ISC_R_SUCCESS; i++) {
		INSIST(result == ISC_R_SUCCESS);
		dns_rdata_init(&x[i].rdata);
		dns_rdataset_current(rdataset, &x[i].rdata);

		x[i].order = i;

		result = dns_rdataset_next(rdataset);
	}
	if (result != ISC_R_NOMORE)
		goto free_rdatas;
	if (i != nalloc) {
		
		result = ISC_R_FAILURE;
		goto free_rdatas;
	}

	
	qsort(x, nalloc, sizeof(struct xrdata), compare_rdata);

	
	for (i = 1; i < nalloc; i++) {
		if (compare_rdata(&x[i-1].rdata, &x[i].rdata) == 0) {
			x[i-1].rdata.data = NULL;
			x[i-1].rdata.length = 0;

			
			if (x[i-1].order < x[i].order)
				x[i].order = x[i-1].order;

			nitems--;
		} else  buflen += (8 + x[i-1].rdata.length);


			buflen += (2 + x[i-1].rdata.length);

	}
	

	buflen += (8 + x[i-1].rdata.length);

	buflen += (2 + x[i-1].rdata.length);


	
	if (nitems > 1 && dns_rdatatype_issingleton(rdataset->type)) {
		
		result = DNS_R_SINGLETON;
		goto free_rdatas;
	}

	
	rawbuf = isc_mem_get(mctx, buflen);
	if (rawbuf == NULL) {
		result = ISC_R_NOMEMORY;
		goto free_rdatas;
	}
	

	
	offsettable = isc_mem_get(mctx, nalloc * sizeof(unsigned int));
	if (offsettable == NULL) {
		isc_mem_put(mctx, rawbuf, buflen);
		result = ISC_R_NOMEMORY;
		goto free_rdatas;
	}
	memset(offsettable, 0, nalloc * sizeof(unsigned int));


	region->base = rawbuf;
	region->length = buflen;

	rawbuf += reservelen;

	offsetbase = rawbuf;


	*rawbuf++ = (nitems & 0xff00) >> 8;
	*rawbuf++ = (nitems & 0x00ff);


	
	rawbuf += nitems * 4;


	for (i = 0; i < nalloc; i++) {
		if (x[i].rdata.data == NULL)
			continue;

		offsettable[x[i].order] = rawbuf - offsetbase;

		*rawbuf++ = (x[i].rdata.length & 0xff00) >> 8;
		*rawbuf++ = (x[i].rdata.length & 0x00ff);

		rawbuf += 2;	

		memcpy(rawbuf, x[i].rdata.data, x[i].rdata.length);
		rawbuf += x[i].rdata.length;
	}
	

	fillin_offsets(offsetbase, offsettable, nalloc);
	isc_mem_put(mctx, offsettable, nalloc * sizeof(unsigned int));


	result = ISC_R_SUCCESS;

 free_rdatas:
	isc_mem_put(mctx, x, nalloc * sizeof(struct xrdata));
	return (result);
}

static void rdataset_disassociate(dns_rdataset_t *rdataset) {
	UNUSED(rdataset);
}

static isc_result_t rdataset_first(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->private3;
	unsigned int count;

	count = raw[0] * 256 + raw[1];
	if (count == 0) {
		rdataset->private5 = NULL;
		return (ISC_R_NOMORE);
	}

	raw += 2 + (4 * count);

	raw += 2;

	
	count--;
	rdataset->privateuint4 = count;
	rdataset->private5 = raw;

	return (ISC_R_SUCCESS);
}

static isc_result_t rdataset_next(dns_rdataset_t *rdataset) {
	unsigned int count;
	unsigned int length;
	unsigned char *raw;

	count = rdataset->privateuint4;
	if (count == 0)
		return (ISC_R_NOMORE);
	count--;
	rdataset->privateuint4 = count;
	raw = rdataset->private5;
	length = raw[0] * 256 + raw[1];

	raw += length + 4;

	raw += length + 2;

	rdataset->private5 = raw;

	return (ISC_R_SUCCESS);
}

static void rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = rdataset->private5;
	isc_region_t r;

	REQUIRE(raw != NULL);

	r.length = raw[0] * 256 + raw[1];

	raw += 4;

	raw += 2;

	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
}

static void rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	*target = *source;

	
	target->privateuint4 = 0;
	target->private5 = NULL;
}

static unsigned int rdataset_count(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->private3;
	unsigned int count;

	count = raw[0] * 256 + raw[1];

	return (count);
}

static dns_rdatasetmethods_t rdataset_methods = {
	rdataset_disassociate, rdataset_first, rdataset_next, rdataset_current, rdataset_clone, rdataset_count, NULL, NULL, NULL, NULL, NULL };











void dns_rdataslab_tordataset(unsigned char *slab, unsigned int reservelen, dns_rdataclass_t rdclass, dns_rdatatype_t rdtype, dns_rdatatype_t covers, dns_ttl_t ttl, dns_rdataset_t *rdataset)



{
	REQUIRE(slab != NULL);
	REQUIRE(!dns_rdataset_isassociated(rdataset));

	rdataset->methods = &rdataset_methods;
	rdataset->rdclass = rdclass;
	rdataset->type = rdtype;
	rdataset->covers = covers;
	rdataset->ttl = ttl;
	rdataset->trust = 0;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;
	rdataset->private3 = slab + reservelen;

	
	rdataset->privateuint4 = 0;
	rdataset->private5 = NULL;
}

unsigned int dns_rdataslab_size(unsigned char *slab, unsigned int reservelen) {
	unsigned int count, length;
	unsigned char *current;

	REQUIRE(slab != NULL);

	current = slab + reservelen;
	count = *current++ * 256;
	count += *current++;

	current += (4 * count);

	while (count > 0) {
		count--;
		length = *current++ * 256;
		length += *current++;

		current += length + 2;

		current += length;

	}

	return ((unsigned int)(current - slab));
}


static inline void rdata_from_slab(unsigned char **current, dns_rdataclass_t rdclass, dns_rdatatype_t type, dns_rdata_t *rdata)


{
	unsigned char *tcurrent = *current;
	isc_region_t region;

	region.length = *tcurrent++ * 256;
	region.length += *tcurrent++;

	tcurrent += 2;

	region.base = tcurrent;
	tcurrent += region.length;
	dns_rdata_fromregion(rdata, rdclass, type, &region);
	*current = tcurrent;
}


static inline isc_boolean_t rdata_in_slab(unsigned char *slab, unsigned int reservelen, dns_rdataclass_t rdclass, dns_rdatatype_t type, dns_rdata_t *rdata)


{
	unsigned int count, i;
	unsigned char *current;
	dns_rdata_t trdata = DNS_RDATA_INIT;
	int n;

	current = slab + reservelen;
	count = *current++ * 256;
	count += *current++;


	current += (4 * count);


	for (i = 0; i < count; i++) {
		rdata_from_slab(&current, rdclass, type, &trdata);
		
		n = dns_rdata_compare(&trdata, rdata);
		if (n == 0)
			return (ISC_TRUE);
		if (n > 0)	
			break;
		dns_rdata_reset(&trdata);
	}
	return (ISC_FALSE);
}

isc_result_t dns_rdataslab_merge(unsigned char *oslab, unsigned char *nslab, unsigned int reservelen, isc_mem_t *mctx, dns_rdataclass_t rdclass, dns_rdatatype_t type, unsigned int flags, unsigned char **tslabp)



{
	unsigned char *ocurrent, *ostart, *ncurrent, *tstart, *tcurrent;
	unsigned int ocount, ncount, count, olength, tlength, tcount, length;
	isc_region_t nregion;
	dns_rdata_t ordata = DNS_RDATA_INIT;
	dns_rdata_t nrdata = DNS_RDATA_INIT;
	isc_boolean_t added_something = ISC_FALSE;
	unsigned int oadded = 0;
	unsigned int nadded = 0;
	unsigned int nncount = 0;

	unsigned int oncount;
	unsigned int norder = 0;
	unsigned int oorder = 0;
	unsigned char *offsetbase;
	unsigned int *offsettable;


	

	REQUIRE(tslabp != NULL && *tslabp == NULL);
	REQUIRE(oslab != NULL && nslab != NULL);

	ocurrent = oslab + reservelen;
	ocount = *ocurrent++ * 256;
	ocount += *ocurrent++;

	ocurrent += (4 * ocount);

	ostart = ocurrent;
	ncurrent = nslab + reservelen;
	ncount = *ncurrent++ * 256;
	ncount += *ncurrent++;

	ncurrent += (4 * ncount);

	INSIST(ocount > 0 && ncount > 0);


	oncount = ncount;


	

	
	olength = 0;
	for (count = 0; count < ocount; count++) {
		length = *ocurrent++ * 256;
		length += *ocurrent++;

		olength += length + 8;
		ocurrent += length + 2;

		olength += length + 2;
		ocurrent += length;

	}

	
	tlength = reservelen + 2 + olength;
	tcount = ocount;

	
	do {
		nregion.length = *ncurrent++ * 256;
		nregion.length += *ncurrent++;

		ncurrent += 2;			

		nregion.base = ncurrent;
		dns_rdata_init(&nrdata);
		dns_rdata_fromregion(&nrdata, rdclass, type, &nregion);
		if (!rdata_in_slab(oslab, reservelen, rdclass, type, &nrdata))
		{
			

			tlength += nregion.length + 8;

			tlength += nregion.length + 2;

			tcount++;
			nncount++;
			added_something = ISC_TRUE;
		}
		ncurrent += nregion.length;
		ncount--;
	} while (ncount > 0);
	ncount = nncount;

	if (((flags & DNS_RDATASLAB_EXACT) != 0) && (tcount != ncount + ocount))
		return (DNS_R_NOTEXACT);

	if (!added_something && (flags & DNS_RDATASLAB_FORCE) == 0)
		return (DNS_R_UNCHANGED);

	
	if (tcount > 1 && dns_rdatatype_issingleton(type)) {
		
		return (DNS_R_SINGLETON);
	}

	if (tcount > 0xffff)
		return (ISC_R_NOSPACE);

	
	tstart = isc_mem_get(mctx, tlength);
	if (tstart == NULL)
		return (ISC_R_NOMEMORY);
	memcpy(tstart, nslab, reservelen);
	tcurrent = tstart + reservelen;

	offsetbase = tcurrent;


	
	*tcurrent++ = (tcount & 0xff00) >> 8;
	*tcurrent++ = (tcount & 0x00ff);


	
	tcurrent += (tcount * 4);

	offsettable = isc_mem_get(mctx, (ocount + oncount) * sizeof(unsigned int));
	if (offsettable == NULL) {
		isc_mem_put(mctx, tstart, tlength);
		return (ISC_R_NOMEMORY);
	}
	memset(offsettable, 0, (ocount + oncount) * sizeof(unsigned int));


	
	ocurrent = ostart;
	INSIST(ocount != 0);

	oorder = ocurrent[2] * 256 + ocurrent[3];
	INSIST(oorder < ocount);

	rdata_from_slab(&ocurrent, rdclass, type, &ordata);

	ncurrent = nslab + reservelen + 2;

	ncurrent += (4 * oncount);


	if (ncount > 0) {
		do {
			dns_rdata_reset(&nrdata);

			norder = ncurrent[2] * 256 + ncurrent[3];

			INSIST(norder < oncount);

			rdata_from_slab(&ncurrent, rdclass, type, &nrdata);
		} while (rdata_in_slab(oslab, reservelen, rdclass, type, &nrdata));
	}

	while (oadded < ocount || nadded < ncount) {
		isc_boolean_t fromold;
		if (oadded == ocount)
			fromold = ISC_FALSE;
		else if (nadded == ncount)
			fromold = ISC_TRUE;
		else fromold = ISC_TF(compare_rdata(&ordata, &nrdata) < 0);
		if (fromold) {

			offsettable[oorder] = tcurrent - offsetbase;

			length = ordata.length;
			*tcurrent++ = (length & 0xff00) >> 8;
			*tcurrent++ = (length & 0x00ff);

			tcurrent += 2;	

			memcpy(tcurrent, ordata.data, length);
			tcurrent += length;
			oadded++;
			if (oadded < ocount) {
				dns_rdata_reset(&ordata);

				oorder = ocurrent[2] * 256 + ocurrent[3];
				INSIST(oorder < ocount);

				rdata_from_slab(&ocurrent, rdclass, type, &ordata);
			}
		} else {

			offsettable[ocount + norder] = tcurrent - offsetbase;

			length = nrdata.length;
			*tcurrent++ = (length & 0xff00) >> 8;
			*tcurrent++ = (length & 0x00ff);

			tcurrent += 2;	

			memcpy(tcurrent, nrdata.data, length);
			tcurrent += length;
			nadded++;
			if (nadded < ncount) {
				do {
					dns_rdata_reset(&nrdata);

					norder = ncurrent[2] * 256 + ncurrent[3];
					INSIST(norder < oncount);

					rdata_from_slab(&ncurrent, rdclass, type, &nrdata);
				} while (rdata_in_slab(oslab, reservelen, rdclass, type, &nrdata));

			}
		}
	}


	fillin_offsets(offsetbase, offsettable, ocount + oncount);

	isc_mem_put(mctx, offsettable, (ocount + oncount) * sizeof(unsigned int));


	INSIST(tcurrent == tstart + tlength);

	*tslabp = tstart;

	return (ISC_R_SUCCESS);
}

isc_result_t dns_rdataslab_subtract(unsigned char *mslab, unsigned char *sslab, unsigned int reservelen, isc_mem_t *mctx, dns_rdataclass_t rdclass, dns_rdatatype_t type, unsigned int flags, unsigned char **tslabp)



{
	unsigned char *mcurrent, *sstart, *scurrent, *tstart, *tcurrent;
	unsigned int mcount, scount, rcount ,count, tlength, tcount, i;
	dns_rdata_t srdata = DNS_RDATA_INIT;
	dns_rdata_t mrdata = DNS_RDATA_INIT;

	unsigned char *offsetbase;
	unsigned int *offsettable;

	unsigned int order;

	REQUIRE(tslabp != NULL && *tslabp == NULL);
	REQUIRE(mslab != NULL && sslab != NULL);

	mcurrent = mslab + reservelen;
	mcount = *mcurrent++ * 256;
	mcount += *mcurrent++;
	scurrent = sslab + reservelen;
	scount = *scurrent++ * 256;
	scount += *scurrent++;
	INSIST(mcount > 0 && scount > 0);

	

	
	tlength = reservelen + 2;
	tcount = 0;
	rcount = 0;


	mcurrent += 4 * mcount;
	scurrent += 4 * scount;

	sstart = scurrent;

	
	for (i = 0; i < mcount; i++) {
		unsigned char *mrdatabegin = mcurrent;
		rdata_from_slab(&mcurrent, rdclass, type, &mrdata);
		scurrent = sstart;
		for (count = 0; count < scount; count++) {
			dns_rdata_reset(&srdata);
			rdata_from_slab(&scurrent, rdclass, type, &srdata);
			if (dns_rdata_compare(&mrdata, &srdata) == 0)
				break;
		}
		if (count == scount) {
			
			tlength += mcurrent - mrdatabegin;
			tcount++;
		} else rcount++;
		dns_rdata_reset(&mrdata);
	}


	tlength += (4 * tcount);


	
	if (((flags & DNS_RDATASLAB_EXACT) != 0) && (rcount != scount))
		return (DNS_R_NOTEXACT);

	
	if (tcount == 0)
		return (DNS_R_NXRRSET);

	
	if (rcount == 0)
		return (DNS_R_UNCHANGED);

	
	tstart = isc_mem_get(mctx, tlength);
	if (tstart == NULL)
		return (ISC_R_NOMEMORY);
	memcpy(tstart, mslab, reservelen);
	tcurrent = tstart + reservelen;

	offsetbase = tcurrent;

	offsettable = isc_mem_get(mctx, mcount * sizeof(unsigned int));
	if (offsettable == NULL) {
		isc_mem_put(mctx, tstart, tlength);
		return (ISC_R_NOMEMORY);
	}
	memset(offsettable, 0, mcount * sizeof(unsigned int));


	
	*tcurrent++ = (tcount & 0xff00) >> 8;
	*tcurrent++ = (tcount & 0x00ff);


	tcurrent += (4 * tcount);


	
	mcurrent = mslab + reservelen;
	mcount = *mcurrent++ * 256;
	mcount += *mcurrent++;

	mcurrent += (4 * mcount);

	for (i = 0; i < mcount; i++) {
		unsigned char *mrdatabegin = mcurrent;

		order = mcurrent[2] * 256 + mcurrent[3];
		INSIST(order < mcount);

		rdata_from_slab(&mcurrent, rdclass, type, &mrdata);
		scurrent = sstart;
		for (count = 0; count < scount; count++) {
			dns_rdata_reset(&srdata);
			rdata_from_slab(&scurrent, rdclass, type, &srdata);
			if (dns_rdata_compare(&mrdata, &srdata) == 0)
				break;
		}
		if (count == scount) {
			
			unsigned int length = mcurrent - mrdatabegin;

			offsettable[order] = tcurrent - offsetbase;

			memcpy(tcurrent, mrdatabegin, length);
			tcurrent += length;
		}
		dns_rdata_reset(&mrdata);
	}


	fillin_offsets(offsetbase, offsettable, mcount);

	isc_mem_put(mctx, offsettable, mcount * sizeof(unsigned int));


	INSIST(tcurrent == tstart + tlength);

	*tslabp = tstart;

	return (ISC_R_SUCCESS);
}

isc_boolean_t dns_rdataslab_equal(unsigned char *slab1, unsigned char *slab2, unsigned int reservelen)

{
	unsigned char *current1, *current2;
	unsigned int count1, count2;
	unsigned int length1, length2;

	current1 = slab1 + reservelen;
	count1 = *current1++ * 256;
	count1 += *current1++;

	current2 = slab2 + reservelen;
	count2 = *current2++ * 256;
	count2 += *current2++;

	if (count1 != count2)
		return (ISC_FALSE);


	current1 += (4 * count1);
	current2 += (4 * count2);


	while (count1 > 0) {
		length1 = *current1++ * 256;
		length1 += *current1++;

		length2 = *current2++ * 256;
		length2 += *current2++;


		current1 += 2;
		current2 += 2;


		if (length1 != length2 || memcmp(current1, current2, length1) != 0)
			return (ISC_FALSE);

		current1 += length1;
		current2 += length1;

		count1--;
	}
	return (ISC_TRUE);
}

isc_boolean_t dns_rdataslab_equalx(unsigned char *slab1, unsigned char *slab2, unsigned int reservelen, dns_rdataclass_t rdclass, dns_rdatatype_t type)


{
	unsigned char *current1, *current2;
	unsigned int count1, count2;
	dns_rdata_t rdata1 = DNS_RDATA_INIT;
	dns_rdata_t rdata2 = DNS_RDATA_INIT;

	current1 = slab1 + reservelen;
	count1 = *current1++ * 256;
	count1 += *current1++;

	current2 = slab2 + reservelen;
	count2 = *current2++ * 256;
	count2 += *current2++;

	if (count1 != count2)
		return (ISC_FALSE);


	current1 += (4 * count1);
	current2 += (4 * count2);


	while (count1-- > 0) {
		rdata_from_slab(&current1, rdclass, type, &rdata1);
		rdata_from_slab(&current2, rdclass, type, &rdata2);
		if (dns_rdata_compare(&rdata1, &rdata2) != 0)
			return (ISC_FALSE);
		dns_rdata_reset(&rdata1);
		dns_rdata_reset(&rdata2);
	}
	return (ISC_TRUE);
}