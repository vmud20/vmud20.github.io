











bool_t xdr_rpcbs_addrlist(xdrs, objp)
	XDR *xdrs;
	rpcbs_addrlist *objp;
{

	    if (!xdr_u_int32_t(xdrs, &objp->prog)) {
		return (FALSE);
	    }
	    if (!xdr_u_int32_t(xdrs, &objp->vers)) {
		return (FALSE);
	    }
	    if (!xdr_int(xdrs, &objp->success)) {
		return (FALSE);
	    }
	    if (!xdr_int(xdrs, &objp->failure)) {
		return (FALSE);
	    }
	    if (!xdr_string(xdrs, &objp->netid, (u_int)~0)) {
		return (FALSE);
	    }

	    if (!xdr_pointer(xdrs, (char **)&objp->next, sizeof (rpcbs_addrlist), (xdrproc_t)xdr_rpcbs_addrlist)) {

		return (FALSE);
	    }

	return (TRUE);
}



bool_t xdr_rpcbs_rmtcalllist(xdrs, objp)
	XDR *xdrs;
	rpcbs_rmtcalllist *objp;
{
	int32_t *buf;

	if (xdrs->x_op == XDR_ENCODE) {
	buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
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
		if (!xdr_int(xdrs, &objp->success)) {
			return (FALSE);
		}
		if (!xdr_int(xdrs, &objp->failure)) {
			return (FALSE);
		}
		if (!xdr_int(xdrs, &objp->indirect)) {
			return (FALSE);
		}
	} else {
		IXDR_PUT_U_INT32(buf, objp->prog);
		IXDR_PUT_U_INT32(buf, objp->vers);
		IXDR_PUT_U_INT32(buf, objp->proc);
		IXDR_PUT_INT32(buf, objp->success);
		IXDR_PUT_INT32(buf, objp->failure);
		IXDR_PUT_INT32(buf, objp->indirect);
	}
	if (!xdr_string(xdrs, &objp->netid, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_pointer(xdrs, (char **)&objp->next, sizeof (rpcbs_rmtcalllist), (xdrproc_t)xdr_rpcbs_rmtcalllist)) {

		return (FALSE);
	}
	return (TRUE);
	} else if (xdrs->x_op == XDR_DECODE) {
	buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
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
		if (!xdr_int(xdrs, &objp->success)) {
			return (FALSE);
		}
		if (!xdr_int(xdrs, &objp->failure)) {
			return (FALSE);
		}
		if (!xdr_int(xdrs, &objp->indirect)) {
			return (FALSE);
		}
	} else {
		objp->prog = (rpcprog_t)IXDR_GET_U_INT32(buf);
		objp->vers = (rpcvers_t)IXDR_GET_U_INT32(buf);
		objp->proc = (rpcproc_t)IXDR_GET_U_INT32(buf);
		objp->success = (int)IXDR_GET_INT32(buf);
		objp->failure = (int)IXDR_GET_INT32(buf);
		objp->indirect = (int)IXDR_GET_INT32(buf);
	}
	if (!xdr_string(xdrs, &objp->netid, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_pointer(xdrs, (char **)&objp->next, sizeof (rpcbs_rmtcalllist), (xdrproc_t)xdr_rpcbs_rmtcalllist)) {

		return (FALSE);
	}
	return (TRUE);
	}
	if (!xdr_u_int32_t(xdrs, &objp->prog)) {
		return (FALSE);
	}
	if (!xdr_u_int32_t(xdrs, &objp->vers)) {
		return (FALSE);
	}
	if (!xdr_u_int32_t(xdrs, &objp->proc)) {
		return (FALSE);
	}
	if (!xdr_int(xdrs, &objp->success)) {
		return (FALSE);
	}
	if (!xdr_int(xdrs, &objp->failure)) {
		return (FALSE);
	}
	if (!xdr_int(xdrs, &objp->indirect)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->netid, (u_int)~0)) {
		return (FALSE);
	}
	if (!xdr_pointer(xdrs, (char **)&objp->next, sizeof (rpcbs_rmtcalllist), (xdrproc_t)xdr_rpcbs_rmtcalllist)) {

		return (FALSE);
	}
	return (TRUE);
}

bool_t xdr_rpcbs_proc(xdrs, objp)
	XDR *xdrs;
	rpcbs_proc objp;
{
	if (!xdr_vector(xdrs, (char *)(void *)objp, RPCBSTAT_HIGHPROC, sizeof (int), (xdrproc_t)xdr_int)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t xdr_rpcbs_addrlist_ptr(xdrs, objp)
	XDR *xdrs;
	rpcbs_addrlist_ptr *objp;
{
	if (!xdr_pointer(xdrs, (char **)objp, sizeof (rpcbs_addrlist), (xdrproc_t)xdr_rpcbs_addrlist)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t xdr_rpcbs_rmtcalllist_ptr(xdrs, objp)
	XDR *xdrs;
	rpcbs_rmtcalllist_ptr *objp;
{
	if (!xdr_pointer(xdrs, (char **)objp, sizeof (rpcbs_rmtcalllist), (xdrproc_t)xdr_rpcbs_rmtcalllist)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t xdr_rpcb_stat(xdrs, objp)
	XDR *xdrs;
	rpcb_stat *objp;
{

	if (!xdr_rpcbs_proc(xdrs, objp->info)) {
		return (FALSE);
	}
	if (!xdr_int(xdrs, &objp->setinfo)) {
		return (FALSE);
	}
	if (!xdr_int(xdrs, &objp->unsetinfo)) {
		return (FALSE);
	}
	if (!xdr_rpcbs_addrlist_ptr(xdrs, &objp->addrinfo)) {
		return (FALSE);
	}
	if (!xdr_rpcbs_rmtcalllist_ptr(xdrs, &objp->rmtinfo)) {
		return (FALSE);
	}
	return (TRUE);
}


bool_t xdr_rpcb_stat_byvers(xdrs, objp)
    XDR *xdrs;
    rpcb_stat_byvers objp;
{
	if (!xdr_vector(xdrs, (char *)(void *)objp, RPCBVERS_STAT, sizeof (rpcb_stat), (xdrproc_t)xdr_rpcb_stat)) {
		return (FALSE);
	}
	return (TRUE);
}
