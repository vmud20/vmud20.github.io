







PG_FUNCTION_INFO_V1(ltxtq_in);
Datum		ltxtq_in(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(ltxtq_out);
Datum		ltxtq_out(PG_FUNCTION_ARGS);








typedef struct NODE {
	int32		type;
	int32		val;
	int16		distance;
	int16		length;
	uint16		flag;
	struct NODE *next;
} NODE;

typedef struct {
	char	   *buf;
	int32		state;
	int32		count;
	
	NODE	   *str;
	
	int32		num;

	
	int32		lenop;
	int32		sumlen;
	char	   *op;
	char	   *curop;
} QPRS_STATE;


static int32 gettoken_query(QPRS_STATE *state, int32 *val, int32 *lenval, char **strval, uint16 *flag)
{
	int			charlen;

	for (;;)
	{
		charlen = pg_mblen(state->buf);

		switch (state->state)
		{
			case WAITOPERAND:
				if (charlen == 1 && t_iseq(state->buf, '!'))
				{
					(state->buf)++;
					*val = (int32) '!';
					return OPR;
				}
				else if (charlen == 1 && t_iseq(state->buf, '('))
				{
					state->count++;
					(state->buf)++;
					return OPEN;
				}
				else if (ISALNUM(state->buf))
				{
					state->state = INOPERAND;
					*strval = state->buf;
					*lenval = charlen;
					*flag = 0;
				}
				else if (!t_isspace(state->buf))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("operand syntax error")));

				break;
			case INOPERAND:
				if (ISALNUM(state->buf))
				{
					if (*flag)
						ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("modificators syntax error")));

					*lenval += charlen;
				}
				else if (charlen == 1 && t_iseq(state->buf, '%'))
					*flag |= LVAR_SUBLEXEME;
				else if (charlen == 1 && t_iseq(state->buf, '@'))
					*flag |= LVAR_INCASE;
				else if (charlen == 1 && t_iseq(state->buf, '*'))
					*flag |= LVAR_ANYEND;
				else {
					state->state = WAITOPERATOR;
					return VAL;
				}
				break;
			case WAITOPERATOR:
				if (charlen == 1 && (t_iseq(state->buf, '&') || t_iseq(state->buf, '|')))
				{
					state->state = WAITOPERAND;
					*val = (int32) *(state->buf);
					(state->buf)++;
					return OPR;
				}
				else if (charlen == 1 && t_iseq(state->buf, ')'))
				{
					(state->buf)++;
					state->count--;
					return (state->count < 0) ? ERR : CLOSE;
				}
				else if (*(state->buf) == '\0')
					return (state->count) ? ERR : END;
				else if (charlen == 1 && !t_iseq(state->buf, ' '))
					return ERR;
				break;
			default:
				return ERR;
				break;
		}

		state->buf += charlen;
	}
}


static void pushquery(QPRS_STATE *state, int32 type, int32 val, int32 distance, int32 lenval, uint16 flag)
{
	NODE	   *tmp = (NODE *) palloc(sizeof(NODE));

	tmp->type = type;
	tmp->val = val;
	tmp->flag = flag;
	if (distance > 0xffff)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("value is too big")));

	if (lenval > 0xff)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("operand is too long")));

	tmp->distance = distance;
	tmp->length = lenval;
	tmp->next = state->str;
	state->str = tmp;
	state->num++;
}


static void pushval_asis(QPRS_STATE *state, int type, char *strval, int lenval, uint16 flag)
{
	if (lenval > 0xffff)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("word is too long")));


	pushquery(state, type, ltree_crc32_sz(strval, lenval), state->curop - state->op, lenval, flag);

	while (state->curop - state->op + lenval + 1 >= state->lenop)
	{
		int32		tmp = state->curop - state->op;

		state->lenop *= 2;
		state->op = (char *) repalloc((void *) state->op, state->lenop);
		state->curop = state->op + tmp;
	}
	memcpy((void *) state->curop, (void *) strval, lenval);
	state->curop += lenval;
	*(state->curop) = '\0';
	state->curop++;
	state->sumlen += lenval + 1;
	return;
}



static int32 makepol(QPRS_STATE *state)
{
	int32		val = 0, type;
	int32		lenval = 0;
	char	   *strval = NULL;
	int32		stack[STACKDEPTH];
	int32		lenstack = 0;
	uint16		flag = 0;

	while ((type = gettoken_query(state, &val, &lenval, &strval, &flag)) != END)
	{
		switch (type)
		{
			case VAL:
				pushval_asis(state, VAL, strval, lenval, flag);
				while (lenstack && (stack[lenstack - 1] == (int32) '&' || stack[lenstack - 1] == (int32) '!'))
				{
					lenstack--;
					pushquery(state, OPR, stack[lenstack], 0, 0, 0);
				}
				break;
			case OPR:
				if (lenstack && val == (int32) '|')
					pushquery(state, OPR, val, 0, 0, 0);
				else {
					if (lenstack == STACKDEPTH)
						
						elog(ERROR, "stack too short");
					stack[lenstack] = val;
					lenstack++;
				}
				break;
			case OPEN:
				if (makepol(state) == ERR)
					return ERR;
				while (lenstack && (stack[lenstack - 1] == (int32) '&' || stack[lenstack - 1] == (int32) '!'))
				{
					lenstack--;
					pushquery(state, OPR, stack[lenstack], 0, 0, 0);
				}
				break;
			case CLOSE:
				while (lenstack)
				{
					lenstack--;
					pushquery(state, OPR, stack[lenstack], 0, 0, 0);
				};
				return END;
				break;
			case ERR:
			default:
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("syntax error")));


				return ERR;

		}
	}
	while (lenstack)
	{
		lenstack--;
		pushquery(state, OPR, stack[lenstack], 0, 0, 0);
	};
	return END;
}

static void findoprnd(ITEM *ptr, int32 *pos)
{
	if (ptr[*pos].type == VAL || ptr[*pos].type == VALTRUE)
	{
		ptr[*pos].left = 0;
		(*pos)++;
	}
	else if (ptr[*pos].val == (int32) '!')
	{
		ptr[*pos].left = 1;
		(*pos)++;
		findoprnd(ptr, pos);
	}
	else {
		ITEM	   *curitem = &ptr[*pos];
		int32		tmp = *pos;

		(*pos)++;
		findoprnd(ptr, pos);
		curitem->left = *pos - tmp;
		findoprnd(ptr, pos);
	}
}



static ltxtquery * queryin(char *buf)
{
	QPRS_STATE	state;
	int32		i;
	ltxtquery  *query;
	int32		commonlen;
	ITEM	   *ptr;
	NODE	   *tmp;
	int32		pos = 0;


	char		pbuf[16384], *cur;


	
	state.buf = buf;
	state.state = WAITOPERAND;
	state.count = 0;
	state.num = 0;
	state.str = NULL;

	
	state.sumlen = 0;
	state.lenop = 64;
	state.curop = state.op = (char *) palloc(state.lenop);
	*(state.curop) = '\0';

	
	makepol(&state);
	if (!state.num)
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("syntax error"), errdetail("Empty query.")));



	
	commonlen = COMPUTESIZE(state.num, state.sumlen);
	query = (ltxtquery *) palloc(commonlen);
	SET_VARSIZE(query, commonlen);
	query->size = state.num;
	ptr = GETQUERY(query);

	
	for (i = 0; i < state.num; i++)
	{
		ptr[i].type = state.str->type;
		ptr[i].val = state.str->val;
		ptr[i].distance = state.str->distance;
		ptr[i].length = state.str->length;
		ptr[i].flag = state.str->flag;
		tmp = state.str->next;
		pfree(state.str);
		state.str = tmp;
	}

	
	memcpy((void *) GETOPERAND(query), (void *) state.op, state.sumlen);
	pfree(state.op);

	
	pos = 0;
	findoprnd(ptr, &pos);

	return query;
}


Datum ltxtq_in(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(queryin((char *) PG_GETARG_POINTER(0)));
}


typedef struct {
	ITEM	   *curpol;
	char	   *buf;
	char	   *cur;
	char	   *op;
	int32		buflen;
} INFIX;










static void infix(INFIX *in, bool first)
{
	if (in->curpol->type == VAL)
	{
		char	   *op = in->op + in->curpol->distance;

		RESIZEBUF(in, in->curpol->length * 2 + 5);
		while (*op)
		{
			*(in->cur) = *op;
			op++;
			in->cur++;
		}
		if (in->curpol->flag & LVAR_SUBLEXEME)
		{
			*(in->cur) = '%';
			in->cur++;
		}
		if (in->curpol->flag & LVAR_INCASE)
		{
			*(in->cur) = '@';
			in->cur++;
		}
		if (in->curpol->flag & LVAR_ANYEND)
		{
			*(in->cur) = '*';
			in->cur++;
		}
		*(in->cur) = '\0';
		in->curpol++;
	}
	else if (in->curpol->val == (int32) '!')
	{
		bool		isopr = false;

		RESIZEBUF(in, 1);
		*(in->cur) = '!';
		in->cur++;
		*(in->cur) = '\0';
		in->curpol++;
		if (in->curpol->type == OPR)
		{
			isopr = true;
			RESIZEBUF(in, 2);
			sprintf(in->cur, "( ");
			in->cur = strchr(in->cur, '\0');
		}
		infix(in, isopr);
		if (isopr)
		{
			RESIZEBUF(in, 2);
			sprintf(in->cur, " )");
			in->cur = strchr(in->cur, '\0');
		}
	}
	else {
		int32		op = in->curpol->val;
		INFIX		nrm;

		in->curpol++;
		if (op == (int32) '|' && !first)
		{
			RESIZEBUF(in, 2);
			sprintf(in->cur, "( ");
			in->cur = strchr(in->cur, '\0');
		}

		nrm.curpol = in->curpol;
		nrm.op = in->op;
		nrm.buflen = 16;
		nrm.cur = nrm.buf = (char *) palloc(sizeof(char) * nrm.buflen);

		
		infix(&nrm, false);

		
		in->curpol = nrm.curpol;
		infix(in, false);

		
		RESIZEBUF(in, 3 + (nrm.cur - nrm.buf));
		sprintf(in->cur, " %c %s", op, nrm.buf);
		in->cur = strchr(in->cur, '\0');
		pfree(nrm.buf);

		if (op == (int32) '|' && !first)
		{
			RESIZEBUF(in, 2);
			sprintf(in->cur, " )");
			in->cur = strchr(in->cur, '\0');
		}
	}
}

Datum ltxtq_out(PG_FUNCTION_ARGS)
{
	ltxtquery  *query = PG_GETARG_LTXTQUERY(0);
	INFIX		nrm;

	if (query->size == 0)
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("syntax error"), errdetail("Empty query.")));



	nrm.curpol = GETQUERY(query);
	nrm.buflen = 32;
	nrm.cur = nrm.buf = (char *) palloc(sizeof(char) * nrm.buflen);
	*(nrm.cur) = '\0';
	nrm.op = GETOPERAND(query);
	infix(&nrm, true);

	PG_FREE_IF_COPY(query, 0);
	PG_RETURN_POINTER(nrm.buf);
}
