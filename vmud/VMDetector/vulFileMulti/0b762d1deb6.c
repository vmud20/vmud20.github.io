











bool_t xdr_rpcb(xdrs, objp)
	XDR *xdrs;
	RPCB *objp;
{
	if (!xdr_u_int32_t(xdrs, &objp->r_prog)) {
		return (FALSE);
	}
	if (!xdr_u_int32_t(xdrs, &objp->r_vers)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_netid, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_addr, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_owner, (u_int)~0)) {
		return (FALSE);
	}
	return (TRUE);
}



bool_t xdr_rpcblist_ptr(xdrs, rp)
	XDR *xdrs;
	rpcblist_ptr *rp;
{
	
	bool_t more_elements;
	int freeing = (xdrs->x_op == XDR_FREE);
	rpcblist_ptr next;
	rpcblist_ptr next_copy;

	next = NULL;
	for (;;) {
		more_elements = (bool_t)(*rp != NULL);
		if (! xdr_bool(xdrs, &more_elements)) {
			return (FALSE);
		}
		if (! more_elements) {
			return (TRUE);  
		}
		
		if (freeing)
			next = (*rp)->rpcb_next;
		if (! xdr_reference(xdrs, (caddr_t *)rp, (u_int)sizeof (rpcblist), (xdrproc_t)xdr_rpcb)) {
			return (FALSE);
		}
		if (freeing) {
			next_copy = next;
			rp = &next_copy;
			
		} else {
			rp = &((*rp)->rpcb_next);
		}
	}
	
}


bool_t xdr_rpcblist(xdrs, rp)
	XDR *xdrs;
	RPCBLIST **rp;
{
	bool_t	dummy;

	dummy = xdr_rpcblist_ptr(xdrs, (rpcblist_ptr *)rp);
	return (dummy);
}


bool_t xdr_rpcb_entry(xdrs, objp)
	XDR *xdrs;
	rpcb_entry *objp;
{
	if (!xdr_string(xdrs, &objp->r_maddr, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_nc_netid, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_u_int32_t(xdrs, &objp->r_nc_semantics)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_nc_protofmly, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->r_nc_proto, (u_int)~0)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t xdr_rpcb_entry_list_ptr(xdrs, rp)
	XDR *xdrs;
	rpcb_entry_list_ptr *rp;
{
	
	bool_t more_elements;
	int freeing = (xdrs->x_op == XDR_FREE);
	rpcb_entry_list_ptr next;
	rpcb_entry_list_ptr next_copy;

	next = NULL;
	for (;;) {
		more_elements = (bool_t)(*rp != NULL);
		if (! xdr_bool(xdrs, &more_elements)) {
			return (FALSE);
		}
		if (! more_elements) {
			return (TRUE);  
		}
		
		if (freeing)
			next = (*rp)->rpcb_entry_next;
		if (! xdr_reference(xdrs, (caddr_t *)rp, (u_int)sizeof (rpcb_entry_list), (xdrproc_t)xdr_rpcb_entry)) {

			return (FALSE);
		}
		if (freeing) {
			next_copy = next;
			rp = &next_copy;
			
		} else {
			rp = &((*rp)->rpcb_entry_next);
		}
	}
	
}


bool_t xdr_rpcb_rmtcallargs(xdrs, p)
	XDR *xdrs;
	struct rpcb_rmtcallargs *p;
{
	struct r_rpcb_rmtcallargs *objp = (struct r_rpcb_rmtcallargs *)(void *)p;
	u_int lenposition, argposition, position;
	int32_t *buf;

	buf = XDR_INLINE(xdrs, 3 * BYTES_PER_XDR_UNIT);
	if (buf == NULL) {
		if (!xdr_u_int32_t(xdrs, &objp->prog)) {
			return (FALSE);
		}
		if (!xdr_u_int32_t(xdrs, &objp->vers)) {
			return (FALSE);
		}
		if (!xdr_u_int32_t(xdrs, &objp->proc)) {
			return (FALSE);
		}
	} else {
		IXDR_PUT_U_INT32(buf, objp->prog);
		IXDR_PUT_U_INT32(buf, objp->vers);
		IXDR_PUT_U_INT32(buf, objp->proc);
	}

	
	lenposition = XDR_GETPOS(xdrs);
	if (! xdr_u_int(xdrs, &(objp->args.args_len))) {
		return (FALSE);
	}
	argposition = XDR_GETPOS(xdrs);
	if (! (*objp->xdr_args)(xdrs, objp->args.args_val)) {
		return (FALSE);
	}
	position = XDR_GETPOS(xdrs);
	objp->args.args_len = (u_int)((u_long)position - (u_long)argposition);
	XDR_SETPOS(xdrs, lenposition);
	if (! xdr_u_int(xdrs, &(objp->args.args_len))) {
		return (FALSE);
	}
	XDR_SETPOS(xdrs, position);
	return (TRUE);
}


bool_t xdr_rpcb_rmtcallres(xdrs, p)
	XDR *xdrs;
	struct rpcb_rmtcallres *p;
{
	bool_t dummy;
	struct r_rpcb_rmtcallres *objp = (struct r_rpcb_rmtcallres *)(void *)p;

	if (!xdr_string(xdrs, &objp->addr, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->results.results_len)) {
		return (FALSE);
	}
	dummy = (*(objp->xdr_res))(xdrs, objp->results.results_val);
	return (dummy);
}

bool_t xdr_netbuf(xdrs, objp)
	XDR *xdrs;
	struct netbuf *objp;
{
	bool_t dummy;

	if (!xdr_u_int32_t(xdrs, (u_int32_t *) &objp->maxlen)) {
		return (FALSE);
	}
	dummy = xdr_bytes(xdrs, (char **)&(objp->buf), (u_int *)&(objp->len), objp->maxlen);
	return (dummy);
}
