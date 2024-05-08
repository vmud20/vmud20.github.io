














typedef quad_t          longlong_t;     
typedef u_quad_t        u_longlong_t;   







static const char xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };


void xdr_free(proc, objp)
	xdrproc_t proc;
	void *objp;
{
	XDR x;
	
	x.x_op = XDR_FREE;
	(*proc)(&x, objp);
}


bool_t xdr_void(void)
{

	return (TRUE);
}



bool_t xdr_int(xdrs, ip)
	XDR *xdrs;
	int *ip;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *ip;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*ip = (int) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}


bool_t xdr_u_int(xdrs, up)
	XDR *xdrs;
	u_int *up;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *up;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*up = (u_int) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}



bool_t xdr_long(xdrs, lp)
	XDR *xdrs;
	long *lp;
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		return (XDR_PUTLONG(xdrs, lp));
	case XDR_DECODE:
		return (XDR_GETLONG(xdrs, lp));
	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}


bool_t xdr_u_long(xdrs, ulp)
	XDR *xdrs;
	u_long *ulp;
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		return (XDR_PUTLONG(xdrs, (long *)ulp));
	case XDR_DECODE:
		return (XDR_GETLONG(xdrs, (long *)ulp));
	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}



bool_t xdr_int32_t(xdrs, int32_p)
	XDR *xdrs;
	int32_t *int32_p;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *int32_p;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*int32_p = (int32_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}


bool_t xdr_u_int32_t(xdrs, u_int32_p)
	XDR *xdrs;
	u_int32_t *u_int32_p;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *u_int32_p;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*u_int32_p = (u_int32_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}



bool_t xdr_short(xdrs, sp)
	XDR *xdrs;
	short *sp;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *sp;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*sp = (short) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}


bool_t xdr_u_short(xdrs, usp)
	XDR *xdrs;
	u_short *usp;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *usp;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*usp = (u_short) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}



bool_t xdr_int16_t(xdrs, int16_p)
	XDR *xdrs;
	int16_t *int16_p;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *int16_p;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*int16_p = (int16_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}


bool_t xdr_u_int16_t(xdrs, u_int16_p)
	XDR *xdrs;
	u_int16_t *u_int16_p;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *u_int16_p;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*u_int16_p = (u_int16_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}



bool_t xdr_char(xdrs, cp)
	XDR *xdrs;
	char *cp;
{
	int i;

	i = (*cp);
	if (!xdr_int(xdrs, &i)) {
		return (FALSE);
	}
	*cp = (char)i;
	return (TRUE);
}


bool_t xdr_u_char(xdrs, cp)
	XDR *xdrs;
	u_char *cp;
{
	u_int u;

	u = (*cp);
	if (!xdr_u_int(xdrs, &u)) {
		return (FALSE);
	}
	*cp = (u_char)u;
	return (TRUE);
}


bool_t xdr_bool(xdrs, bp)
	XDR *xdrs;
	bool_t *bp;
{
	long lb;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		lb = *bp ? XDR_TRUE : XDR_FALSE;
		return (XDR_PUTLONG(xdrs, &lb));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &lb)) {
			return (FALSE);
		}
		*bp = (lb == XDR_FALSE) ? FALSE : TRUE;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}


bool_t xdr_enum(xdrs, ep)
	XDR *xdrs;
	enum_t *ep;
{
	enum sizecheck { SIZEVAL };	

	
	 if (sizeof (enum sizecheck) == sizeof (long)) {
		return (xdr_long(xdrs, (long *)(void *)ep));
	} else  if (sizeof (enum sizecheck) == sizeof (int)) {
		return (xdr_int(xdrs, (int *)(void *)ep));
	} else  if (sizeof (enum sizecheck) == sizeof (short)) {
		return (xdr_short(xdrs, (short *)(void *)ep));
	} else {
		return (FALSE);
	}
}


bool_t xdr_opaque(xdrs, cp, cnt)
	XDR *xdrs;
	caddr_t cp;
	u_int cnt;
{
	u_int rndup;
	static int crud[BYTES_PER_XDR_UNIT];

	
	if (cnt == 0)
		return (TRUE);

	
	rndup = cnt % BYTES_PER_XDR_UNIT;
	if (rndup > 0)
		rndup = BYTES_PER_XDR_UNIT - rndup;

	if (xdrs->x_op == XDR_DECODE) {
		if (!XDR_GETBYTES(xdrs, cp, cnt)) {
			return (FALSE);
		}
		if (rndup == 0)
			return (TRUE);
		return (XDR_GETBYTES(xdrs, (caddr_t)(void *)crud, rndup));
	}

	if (xdrs->x_op == XDR_ENCODE) {
		if (!XDR_PUTBYTES(xdrs, cp, cnt)) {
			return (FALSE);
		}
		if (rndup == 0)
			return (TRUE);
		return (XDR_PUTBYTES(xdrs, xdr_zero, rndup));
	}

	if (xdrs->x_op == XDR_FREE) {
		return (TRUE);
	}

	return (FALSE);
}


bool_t xdr_bytes(xdrs, cpp, sizep, maxsize)
	XDR *xdrs;
	char **cpp;
	u_int *sizep;
	u_int maxsize;
{
	char *sp = *cpp;  
	u_int nodesize;

	
	if (! xdr_u_int(xdrs, sizep)) {
		return (FALSE);
	}
	nodesize = *sizep;
	if ((nodesize > maxsize) && (xdrs->x_op != XDR_FREE)) {
		return (FALSE);
	}

	
	switch (xdrs->x_op) {

	case XDR_DECODE:
		if (nodesize == 0) {
			return (TRUE);
		}
		if (sp == NULL) {
			*cpp = sp = mem_alloc(nodesize);
		}
		if (sp == NULL) {
			
			return (FALSE);
		}
		

	case XDR_ENCODE:
		return (xdr_opaque(xdrs, sp, nodesize));

	case XDR_FREE:
		if (sp != NULL) {
			mem_free(sp, nodesize);
			*cpp = NULL;
		}
		return (TRUE);
	}
	
	return (FALSE);
}


bool_t xdr_netobj(xdrs, np)
	XDR *xdrs;
	struct netobj *np;
{

	return (xdr_bytes(xdrs, &np->n_bytes, &np->n_len, MAX_NETOBJ_SZ));
}


bool_t xdr_union(xdrs, dscmp, unp, choices, dfault)
	XDR *xdrs;
	enum_t *dscmp;		
	char *unp;		
	const struct xdr_discrim *choices;	
	xdrproc_t dfault;	
{
	enum_t dscm;

	
	if (! xdr_enum(xdrs, dscmp)) {
		return (FALSE);
	}
	dscm = *dscmp;

	
	for (; choices->proc != NULL_xdrproc_t; choices++) {
		if (choices->value == dscm)
			return ((*(choices->proc))(xdrs, unp));
	}

	
	return ((dfault == NULL_xdrproc_t) ? FALSE :
	    (*dfault)(xdrs, unp));
}






bool_t xdr_string(xdrs, cpp, maxsize)
	XDR *xdrs;
	char **cpp;
	u_int maxsize;
{
	char *sp = *cpp;  
	u_int size;
	u_int nodesize;

	
	switch (xdrs->x_op) {
	case XDR_FREE:
		if (sp == NULL) {
			return(TRUE);	
		}
		
	case XDR_ENCODE:
		if (sp == NULL)
			return FALSE;
		size = strlen(sp);
		break;
	case XDR_DECODE:
		break;
	}
	if (! xdr_u_int(xdrs, &size)) {
		return (FALSE);
	}
	if (size > maxsize) {
		return (FALSE);
	}
	nodesize = size + 1;
	if (nodesize == 0) {
		
		return FALSE;
	}

	
	switch (xdrs->x_op) {

	case XDR_DECODE:
		if (sp == NULL)
			*cpp = sp = mem_alloc(nodesize);
		if (sp == NULL) {
			
			return (FALSE);
		}
		sp[size] = 0;
		

	case XDR_ENCODE:
		return (xdr_opaque(xdrs, sp, size));

	case XDR_FREE:
		mem_free(sp, nodesize);
		*cpp = NULL;
		return (TRUE);
	}
	
	return (FALSE);
}


bool_t xdr_wrapstring(xdrs, cpp)
	XDR *xdrs;
	char **cpp;
{
	return xdr_string(xdrs, cpp, LASTUNSIGNED);
}




bool_t xdr_int64_t(xdrs, llp)
	XDR *xdrs;
	int64_t *llp;
{
	u_long ul[2];

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		ul[0] = (u_long)((u_int64_t)*llp >> 32) & 0xffffffff;
		ul[1] = (u_long)((u_int64_t)*llp) & 0xffffffff;
		if (XDR_PUTLONG(xdrs, (long *)&ul[0]) == FALSE)
			return (FALSE);
		return (XDR_PUTLONG(xdrs, (long *)&ul[1]));
	case XDR_DECODE:
		if (XDR_GETLONG(xdrs, (long *)&ul[0]) == FALSE)
			return (FALSE);
		if (XDR_GETLONG(xdrs, (long *)&ul[1]) == FALSE)
			return (FALSE);
		*llp = (int64_t)
		    (((u_int64_t)ul[0] << 32) | ((u_int64_t)ul[1]));
		return (TRUE);
	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}



bool_t xdr_u_int64_t(xdrs, ullp)
	XDR *xdrs;
	u_int64_t *ullp;
{
	u_long ul[2];

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		ul[0] = (u_long)(*ullp >> 32) & 0xffffffff;
		ul[1] = (u_long)(*ullp) & 0xffffffff;
		if (XDR_PUTLONG(xdrs, (long *)&ul[0]) == FALSE)
			return (FALSE);
		return (XDR_PUTLONG(xdrs, (long *)&ul[1]));
	case XDR_DECODE:
		if (XDR_GETLONG(xdrs, (long *)&ul[0]) == FALSE)
			return (FALSE);
		if (XDR_GETLONG(xdrs, (long *)&ul[1]) == FALSE)
			return (FALSE);
		*ullp = (u_int64_t)
		    (((u_int64_t)ul[0] << 32) | ((u_int64_t)ul[1]));
		return (TRUE);
	case XDR_FREE:
		return (TRUE);
	}
	
	return (FALSE);
}



bool_t xdr_hyper(xdrs, llp)
	XDR *xdrs;
	longlong_t *llp;
{

	
	return (xdr_int64_t(xdrs, (int64_t *)llp));
}



bool_t xdr_u_hyper(xdrs, ullp)
	XDR *xdrs;
	u_longlong_t *ullp;
{

	
	return (xdr_u_int64_t(xdrs, (u_int64_t *)ullp));
}



bool_t xdr_longlong_t(xdrs, llp)
	XDR *xdrs;
	longlong_t *llp;
{

	
	return (xdr_int64_t(xdrs, (int64_t *)llp));
}



bool_t xdr_u_longlong_t(xdrs, ullp)
	XDR *xdrs;
	u_longlong_t *ullp;
{

	
	return (xdr_u_int64_t(xdrs, (u_int64_t *)ullp));
}
