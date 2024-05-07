











struct TSQueryParserStateData {
	
	char	   *buffer;			
	char	   *buf;			
	int			state;
	int			count;			

	
	List	   *polstr;

	
	char	   *op;
	char	   *curop;
	int			lenop;			
	int			sumlen;			

	
	TSVectorParseState valstate;
};








static char * get_modifiers(char *buf, int16 *weight, bool *prefix)
{
	*weight = 0;
	*prefix = false;

	if (!t_iseq(buf, ':'))
		return buf;

	buf++;
	while (*buf && pg_mblen(buf) == 1)
	{
		switch (*buf)
		{
			case 'a':
			case 'A':
				*weight |= 1 << 3;
				break;
			case 'b':
			case 'B':
				*weight |= 1 << 2;
				break;
			case 'c':
			case 'C':
				*weight |= 1 << 1;
				break;
			case 'd':
			case 'D':
				*weight |= 1;
				break;
			case '*':
				*prefix = true;
				break;
			default:
				return buf;
		}
		buf++;
	}

	return buf;
}


typedef enum {
	PT_END = 0, PT_ERR = 1, PT_VAL = 2, PT_OPR = 3, PT_OPEN = 4, PT_CLOSE = 5 } ts_tokentype;







static ts_tokentype gettoken_query(TSQueryParserState state, int8 *operator, int *lenval, char **strval, int16 *weight, bool *prefix)


{
	*weight = 0;
	*prefix = false;

	while (1)
	{
		switch (state->state)
		{
			case WAITFIRSTOPERAND:
			case WAITOPERAND:
				if (t_iseq(state->buf, '!'))
				{
					(state->buf)++;		
					*operator = OP_NOT;
					state->state = WAITOPERAND;
					return PT_OPR;
				}
				else if (t_iseq(state->buf, '('))
				{
					state->count++;
					(state->buf)++;
					state->state = WAITOPERAND;
					return PT_OPEN;
				}
				else if (t_iseq(state->buf, ':'))
				{
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("syntax error in tsquery: \"%s\"", state->buffer)));


				}
				else if (!t_isspace(state->buf))
				{
					
					reset_tsvector_parser(state->valstate, state->buf);
					if (gettoken_tsvector(state->valstate, strval, lenval, NULL, NULL, &state->buf))
					{
						state->buf = get_modifiers(state->buf, weight, prefix);
						state->state = WAITOPERATOR;
						return PT_VAL;
					}
					else if (state->state == WAITFIRSTOPERAND)
						return PT_END;
					else ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("no operand in tsquery: \"%s\"", state->buffer)));



				}
				break;
			case WAITOPERATOR:
				if (t_iseq(state->buf, '&'))
				{
					state->state = WAITOPERAND;
					*operator = OP_AND;
					(state->buf)++;
					return PT_OPR;
				}
				if (t_iseq(state->buf, '|'))
				{
					state->state = WAITOPERAND;
					*operator = OP_OR;
					(state->buf)++;
					return PT_OPR;
				}
				else if (t_iseq(state->buf, ')'))
				{
					(state->buf)++;
					state->count--;
					return (state->count < 0) ? PT_ERR : PT_CLOSE;
				}
				else if (*(state->buf) == '\0')
					return (state->count) ? PT_ERR : PT_END;
				else if (!t_isspace(state->buf))
					return PT_ERR;
				break;
			case WAITSINGLEOPERAND:
				if (*(state->buf) == '\0')
					return PT_END;
				*strval = state->buf;
				*lenval = strlen(state->buf);
				state->buf += strlen(state->buf);
				state->count++;
				return PT_VAL;
			default:
				return PT_ERR;
				break;
		}
		state->buf += pg_mblen(state->buf);
	}
}


void pushOperator(TSQueryParserState state, int8 oper)
{
	QueryOperator *tmp;

	Assert(oper == OP_NOT || oper == OP_AND || oper == OP_OR);

	tmp = (QueryOperator *) palloc0(sizeof(QueryOperator));
	tmp->type = QI_OPR;
	tmp->oper = oper;
	

	state->polstr = lcons(tmp, state->polstr);
}

static void pushValue_internal(TSQueryParserState state, pg_crc32 valcrc, int distance, int lenval, int weight, bool prefix)
{
	QueryOperand *tmp;

	if (distance >= MAXSTRPOS)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("value is too big in tsquery: \"%s\"", state->buffer)));


	if (lenval >= MAXSTRLEN)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("operand is too long in tsquery: \"%s\"", state->buffer)));



	tmp = (QueryOperand *) palloc0(sizeof(QueryOperand));
	tmp->type = QI_VAL;
	tmp->weight = weight;
	tmp->prefix = prefix;
	tmp->valcrc = (int32) valcrc;
	tmp->length = lenval;
	tmp->distance = distance;

	state->polstr = lcons(tmp, state->polstr);
}


void pushValue(TSQueryParserState state, char *strval, int lenval, int16 weight, bool prefix)
{
	pg_crc32	valcrc;

	if (lenval >= MAXSTRLEN)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("word is too long in tsquery: \"%s\"", state->buffer)));



	INIT_CRC32(valcrc);
	COMP_CRC32(valcrc, strval, lenval);
	FIN_CRC32(valcrc);
	pushValue_internal(state, valcrc, state->curop - state->op, lenval, weight, prefix);

	
	while (state->curop - state->op + lenval + 1 >= state->lenop)
	{
		int			used = state->curop - state->op;

		state->lenop *= 2;
		state->op = (char *) repalloc((void *) state->op, state->lenop);
		state->curop = state->op + used;
	}
	memcpy((void *) state->curop, (void *) strval, lenval);
	state->curop += lenval;
	*(state->curop) = '\0';
	state->curop++;
	state->sumlen += lenval + 1  ;
}



void pushStop(TSQueryParserState state)
{
	QueryOperand *tmp;

	tmp = (QueryOperand *) palloc0(sizeof(QueryOperand));
	tmp->type = QI_VALSTOP;

	state->polstr = lcons(tmp, state->polstr);
}





static void makepol(TSQueryParserState state, PushFunction pushval, Datum opaque)


{
	int8		operator = 0;
	ts_tokentype type;
	int			lenval = 0;
	char	   *strval = NULL;
	int8		opstack[STACKDEPTH];
	int			lenstack = 0;
	int16		weight = 0;
	bool		prefix;

	
	check_stack_depth();

	while ((type = gettoken_query(state, &operator, &lenval, &strval, &weight, &prefix)) != PT_END)
	{
		switch (type)
		{
			case PT_VAL:
				pushval(opaque, state, strval, lenval, weight, prefix);
				while (lenstack && (opstack[lenstack - 1] == OP_AND || opstack[lenstack - 1] == OP_NOT))
				{
					lenstack--;
					pushOperator(state, opstack[lenstack]);
				}
				break;
			case PT_OPR:
				if (lenstack && operator == OP_OR)
					pushOperator(state, OP_OR);
				else {
					if (lenstack == STACKDEPTH) 
						elog(ERROR, "tsquery stack too small");
					opstack[lenstack] = operator;
					lenstack++;
				}
				break;
			case PT_OPEN:
				makepol(state, pushval, opaque);

				while (lenstack && (opstack[lenstack - 1] == OP_AND || opstack[lenstack - 1] == OP_NOT))
				{
					lenstack--;
					pushOperator(state, opstack[lenstack]);
				}
				break;
			case PT_CLOSE:
				while (lenstack)
				{
					lenstack--;
					pushOperator(state, opstack[lenstack]);
				};
				return;
			case PT_ERR:
			default:
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("syntax error in tsquery: \"%s\"", state->buffer)));


		}
	}
	while (lenstack)
	{
		lenstack--;
		pushOperator(state, opstack[lenstack]);
	}
}

static void findoprnd_recurse(QueryItem *ptr, uint32 *pos, int nnodes)
{
	
	check_stack_depth();

	if (*pos >= nnodes)
		elog(ERROR, "malformed tsquery: operand not found");

	if (ptr[*pos].type == QI_VAL || ptr[*pos].type == QI_VALSTOP)
	{
		(*pos)++;
	}
	else {
		Assert(ptr[*pos].type == QI_OPR);

		if (ptr[*pos].qoperator.oper == OP_NOT)
		{
			ptr[*pos].qoperator.left = 1;
			(*pos)++;
			findoprnd_recurse(ptr, pos, nnodes);
		}
		else {
			QueryOperator *curitem = &ptr[*pos].qoperator;
			int			tmp = *pos;

			Assert(curitem->oper == OP_AND || curitem->oper == OP_OR);

			(*pos)++;
			findoprnd_recurse(ptr, pos, nnodes);
			curitem->left = *pos - tmp;
			findoprnd_recurse(ptr, pos, nnodes);
		}
	}
}



static void findoprnd(QueryItem *ptr, int size)
{
	uint32		pos;

	pos = 0;
	findoprnd_recurse(ptr, &pos, size);

	if (pos != size)
		elog(ERROR, "malformed tsquery: extra nodes");
}



TSQuery parse_tsquery(char *buf, PushFunction pushval, Datum opaque, bool isplain)



{
	struct TSQueryParserStateData state;
	int			i;
	TSQuery		query;
	int			commonlen;
	QueryItem  *ptr;
	ListCell   *cell;

	
	state.buffer = buf;
	state.buf = buf;
	state.state = (isplain) ? WAITSINGLEOPERAND : WAITFIRSTOPERAND;
	state.count = 0;
	state.polstr = NIL;

	
	state.valstate = init_tsvector_parser(state.buffer, true, true);

	
	state.sumlen = 0;
	state.lenop = 64;
	state.curop = state.op = (char *) palloc(state.lenop);
	*(state.curop) = '\0';

	
	makepol(&state, pushval, opaque);

	close_tsvector_parser(state.valstate);

	if (list_length(state.polstr) == 0)
	{
		ereport(NOTICE, (errmsg("text-search query doesn't contain lexemes: \"%s\"", state.buffer)));

		query = (TSQuery) palloc(HDRSIZETQ);
		SET_VARSIZE(query, HDRSIZETQ);
		query->size = 0;
		return query;
	}

	
	commonlen = COMPUTESIZE(list_length(state.polstr), state.sumlen);
	query = (TSQuery) palloc0(commonlen);
	SET_VARSIZE(query, commonlen);
	query->size = list_length(state.polstr);
	ptr = GETQUERY(query);

	
	i = 0;
	foreach(cell, state.polstr)
	{
		QueryItem  *item = (QueryItem *) lfirst(cell);

		switch (item->type)
		{
			case QI_VAL:
				memcpy(&ptr[i], item, sizeof(QueryOperand));
				break;
			case QI_VALSTOP:
				ptr[i].type = QI_VALSTOP;
				break;
			case QI_OPR:
				memcpy(&ptr[i], item, sizeof(QueryOperator));
				break;
			default:
				elog(ERROR, "unrecognized QueryItem type: %d", item->type);
		}
		i++;
	}

	
	memcpy((void *) GETOPERAND(query), (void *) state.op, state.sumlen);
	pfree(state.op);

	
	findoprnd(ptr, query->size);

	return query;
}

static void pushval_asis(Datum opaque, TSQueryParserState state, char *strval, int lenval, int16 weight, bool prefix)

{
	pushValue(state, strval, lenval, weight, prefix);
}


Datum tsqueryin(PG_FUNCTION_ARGS)
{
	char	   *in = PG_GETARG_CSTRING(0);

	PG_RETURN_TSQUERY(parse_tsquery(in, pushval_asis, PointerGetDatum(NULL), false));
}


typedef struct {
	QueryItem  *curpol;
	char	   *buf;
	char	   *cur;
	char	   *op;
	int			buflen;
} INFIX;











static void infix(INFIX *in, bool first)
{
	
	check_stack_depth();

	if (in->curpol->type == QI_VAL)
	{
		QueryOperand *curpol = &in->curpol->qoperand;
		char	   *op = in->op + curpol->distance;
		int			clen;

		RESIZEBUF(in, curpol->length * (pg_database_encoding_max_length() + 1) + 2 + 6);
		*(in->cur) = '\'';
		in->cur++;
		while (*op)
		{
			if (t_iseq(op, '\''))
			{
				*(in->cur) = '\'';
				in->cur++;
			}
			else if (t_iseq(op, '\\'))
			{
				*(in->cur) = '\\';
				in->cur++;
			}
			COPYCHAR(in->cur, op);

			clen = pg_mblen(op);
			op += clen;
			in->cur += clen;
		}
		*(in->cur) = '\'';
		in->cur++;
		if (curpol->weight || curpol->prefix)
		{
			*(in->cur) = ':';
			in->cur++;
			if (curpol->prefix)
			{
				*(in->cur) = '*';
				in->cur++;
			}
			if (curpol->weight & (1 << 3))
			{
				*(in->cur) = 'A';
				in->cur++;
			}
			if (curpol->weight & (1 << 2))
			{
				*(in->cur) = 'B';
				in->cur++;
			}
			if (curpol->weight & (1 << 1))
			{
				*(in->cur) = 'C';
				in->cur++;
			}
			if (curpol->weight & 1)
			{
				*(in->cur) = 'D';
				in->cur++;
			}
		}
		*(in->cur) = '\0';
		in->curpol++;
	}
	else if (in->curpol->qoperator.oper == OP_NOT)
	{
		bool		isopr = false;

		RESIZEBUF(in, 1);
		*(in->cur) = '!';
		in->cur++;
		*(in->cur) = '\0';
		in->curpol++;

		if (in->curpol->type == QI_OPR)
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
		int8		op = in->curpol->qoperator.oper;
		INFIX		nrm;

		in->curpol++;
		if (op == OP_OR && !first)
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
		switch (op)
		{
			case OP_OR:
				sprintf(in->cur, " | %s", nrm.buf);
				break;
			case OP_AND:
				sprintf(in->cur, " & %s", nrm.buf);
				break;
			default:
				
				elog(ERROR, "unrecognized operator type: %d", op);
		}
		in->cur = strchr(in->cur, '\0');
		pfree(nrm.buf);

		if (op == OP_OR && !first)
		{
			RESIZEBUF(in, 2);
			sprintf(in->cur, " )");
			in->cur = strchr(in->cur, '\0');
		}
	}
}


Datum tsqueryout(PG_FUNCTION_ARGS)
{
	TSQuery		query = PG_GETARG_TSQUERY(0);
	INFIX		nrm;

	if (query->size == 0)
	{
		char	   *b = palloc(1);

		*b = '\0';
		PG_RETURN_POINTER(b);
	}
	nrm.curpol = GETQUERY(query);
	nrm.buflen = 32;
	nrm.cur = nrm.buf = (char *) palloc(sizeof(char) * nrm.buflen);
	*(nrm.cur) = '\0';
	nrm.op = GETOPERAND(query);
	infix(&nrm, true);

	PG_FREE_IF_COPY(query, 0);
	PG_RETURN_CSTRING(nrm.buf);
}


Datum tsquerysend(PG_FUNCTION_ARGS)
{
	TSQuery		query = PG_GETARG_TSQUERY(0);
	StringInfoData buf;
	int			i;
	QueryItem  *item = GETQUERY(query);

	pq_begintypsend(&buf);

	pq_sendint(&buf, query->size, sizeof(uint32));
	for (i = 0; i < query->size; i++)
	{
		pq_sendint(&buf, item->type, sizeof(item->type));

		switch (item->type)
		{
			case QI_VAL:
				pq_sendint(&buf, item->qoperand.weight, sizeof(uint8));
				pq_sendint(&buf, item->qoperand.prefix, sizeof(uint8));
				pq_sendstring(&buf, GETOPERAND(query) + item->qoperand.distance);
				break;
			case QI_OPR:
				pq_sendint(&buf, item->qoperator.oper, sizeof(item->qoperator.oper));
				break;
			default:
				elog(ERROR, "unrecognized tsquery node type: %d", item->type);
		}
		item++;
	}

	PG_FREE_IF_COPY(query, 0);

	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

Datum tsqueryrecv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	TSQuery		query;
	int			i, len;
	QueryItem  *item;
	int			datalen;
	char	   *ptr;
	uint32		size;
	const char **operands;

	size = pq_getmsgint(buf, sizeof(uint32));
	if (size > (MaxAllocSize / sizeof(QueryItem)))
		elog(ERROR, "invalid size of tsquery");

	
	operands = palloc(size * sizeof(char *));

	
	len = HDRSIZETQ + sizeof(QueryItem) * size;
	query = (TSQuery) palloc0(len);
	query->size = size;
	item = GETQUERY(query);

	datalen = 0;
	for (i = 0; i < size; i++)
	{
		item->type = (int8) pq_getmsgint(buf, sizeof(int8));

		if (item->type == QI_VAL)
		{
			size_t		val_len;	
			uint8		weight;
			uint8		prefix;
			const char *val;
			pg_crc32	valcrc;

			weight = (uint8) pq_getmsgint(buf, sizeof(uint8));
			prefix = (uint8) pq_getmsgint(buf, sizeof(uint8));
			val = pq_getmsgstring(buf);
			val_len = strlen(val);

			

			if (weight > 0xF)
				elog(ERROR, "invalid tsquery: invalid weight bitmap");

			if (val_len > MAXSTRLEN)
				elog(ERROR, "invalid tsquery: operand too long");

			if (datalen > MAXSTRPOS)
				elog(ERROR, "invalid tsquery: total operand length exceeded");

			

			INIT_CRC32(valcrc);
			COMP_CRC32(valcrc, val, val_len);
			FIN_CRC32(valcrc);

			item->qoperand.weight = weight;
			item->qoperand.prefix = (prefix) ? true : false;
			item->qoperand.valcrc = (int32) valcrc;
			item->qoperand.length = val_len;
			item->qoperand.distance = datalen;

			
			operands[i] = val;

			datalen += val_len + 1;		
		}
		else if (item->type == QI_OPR)
		{
			int8		oper;

			oper = (int8) pq_getmsgint(buf, sizeof(int8));
			if (oper != OP_NOT && oper != OP_OR && oper != OP_AND)
				elog(ERROR, "invalid tsquery: unrecognized operator type %d", (int) oper);
			if (i == size - 1)
				elog(ERROR, "invalid pointer to right operand");

			item->qoperator.oper = oper;
		}
		else elog(ERROR, "unrecognized tsquery node type: %d", item->type);

		item++;
	}

	
	query = (TSQuery) repalloc(query, len + datalen);
	item = GETQUERY(query);
	ptr = GETOPERAND(query);

	
	findoprnd(item, size);

	
	for (i = 0; i < size; i++)
	{
		if (item->type == QI_VAL)
		{
			memcpy(ptr, operands[i], item->qoperand.length + 1);
			ptr += item->qoperand.length + 1;
		}
		item++;
	}

	pfree(operands);

	Assert(ptr - GETOPERAND(query) == datalen);

	SET_VARSIZE(query, len + datalen);

	PG_RETURN_TSVECTOR(query);
}


Datum tsquerytree(PG_FUNCTION_ARGS)
{
	TSQuery		query = PG_GETARG_TSQUERY(0);
	INFIX		nrm;
	text	   *res;
	QueryItem  *q;
	int			len;

	if (query->size == 0)
	{
		res = (text *) palloc(VARHDRSZ);
		SET_VARSIZE(res, VARHDRSZ);
		PG_RETURN_POINTER(res);
	}

	q = clean_NOT(GETQUERY(query), &len);

	if (!q)
	{
		res = cstring_to_text("T");
	}
	else {
		nrm.curpol = q;
		nrm.buflen = 32;
		nrm.cur = nrm.buf = (char *) palloc(sizeof(char) * nrm.buflen);
		*(nrm.cur) = '\0';
		nrm.op = GETOPERAND(query);
		infix(&nrm, true);
		res = cstring_to_text_with_len(nrm.buf, nrm.cur - nrm.buf);
		pfree(q);
	}

	PG_FREE_IF_COPY(query, 0);

	PG_RETURN_TEXT_P(res);
}
