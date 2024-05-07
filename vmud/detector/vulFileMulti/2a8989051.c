












static struct lump *lumps[MAX_STREAMS];
static int lumps_len;

enum{
	FIND, DELETE, ADD_TO_FRONT, ADD_TO_BACK };




enum{
	DESC_NAME, DESC_NAME_AND_CLOCK, DESC_REGEXP, DESC_REGEXP_COMPLEMENT };





static int do_for_all_streams(struct sip_msg* msg, str* str1,str * str2, regex_t* re, int op,int desc);
static int stream_process(struct sip_msg * msg, struct sdp_stream_cell *cell, str * s, str* ss, regex_t* re, int op,int description);



static int create_codec_lumps(struct sip_msg * msg)
{

	struct sdp_session_cell * cur_session;
	struct lump * tmp;
	int count;

	
	lumps_len = 0;
	cur_session = get_sdp(msg)->sessions;

	while(cur_session)
	{
		lumps_len += cur_session->streams_num;
		cur_session = cur_session->next;
	}

	if (lumps_len>MAX_STREAMS)
	{
		LM_ERR("Overflow - too many streams (%d), limit is %d\n", lumps_len, MAX_STREAMS);
		return -1;
	}
	memset(lumps, 0, MAX_STREAMS * sizeof(struct lump*));

	

	LM_DBG("creating %d streams\n",lumps_len);

	count = 0;
	cur_session = get_sdp(msg)->sessions;

	while(cur_session)
	{
		struct sdp_stream_cell * cur_cell = cur_session->streams;
		struct lump* l;
		str text;
		str payloads;

		while(cur_cell)
		{
			payloads = cur_cell->payloads;
			
			while (payloads.s > cur_cell->body.s && *(payloads.s-1) == ' ') {
				payloads.s--;
				payloads.len++;
			}

			l = del_lump(msg, payloads.s - msg->buf, payloads.len, 0);

			lumps[count] = l;

			if( l == NULL)
			{
				LM_ERR("Error adding delete lump for m=\n");
				return -1;
			}

			l->flags |= LUMPFLAG_CODEC;

			tmp = insert_skip_lump_after( l );
			if(tmp == NULL)
			{
				LM_ERR("Error adding skip lump for m=\n");
				return -1;
			}

			text.len = payloads.len;
			text.s = (char*)pkg_malloc(payloads.len);

			if( text.s == NULL )
			{
				LM_ERR("Error allocating lump buffer\n");
				return -1;
			}

			memcpy(text.s,payloads.s,payloads.len);

			tmp = insert_new_lump_after( tmp, text.s, text.len, 0);
			if(tmp == NULL)
			{
				LM_ERR("Error adding insert lump for m=\n");
				return -1;
			}

			count ++;
			cur_cell = cur_cell->next;
		}

		cur_session = cur_session->next;

	}

	return 0;
};



static int find_codec_lumps(struct sip_msg * msg)
{
	struct lump *cur = msg->body_lumps;
	int count = 0;

	while( cur)
	{
		if( cur->flags & LUMPFLAG_CODEC && cur->after && cur->after->after)
			count++;
		cur = cur->next;
	}

	if (count>MAX_STREAMS) {
		LM_CRIT("BUG: too many codec lumps found (%d)\n",count);
		return -1;
	}

	if( count==0 ) {
		lumps_len = -1;
		return 1;
	}

	lumps_len=0;
	cur = msg->body_lumps;
	while( cur)
	{
		if( cur->flags & LUMPFLAG_CODEC && cur->after && cur->after->after)
		{
			lumps[lumps_len] = cur;
			lumps_len++;
		}
		cur = cur->next;
	}
	LM_DBG("found %d streams\n",lumps_len);

	return 0;
};


static int clone_codec_lumps(void)
{
	struct lump *l;
	int i;
	char *s;

	LM_DBG("cloning %d streams\n",lumps_len);

	for( i=0 ; i<lumps_len ; i++ ) {
		
		for( l=lumps[i] ; l->after ; l=l->after );

		s = pkg_malloc( l->len+1 );
		if (s==NULL) {
			LM_ERR("failed to alloc new lump pkg buffer\n");
			return -1;
		}
		memcpy( s, l->u.value, l->len);

		if (insert_new_lump_after( l, s, l->len, 0)==NULL) {
			LM_ERR("failed to create new lump\n");
			return -1;
		}
	}

	return 0;
}


static int get_codec_lumps( struct sip_msg *msg )
{
	int rc;

	rc = find_codec_lumps(msg);
	if (rc<0) {
		LM_ERR("error while searching for codec flags\n");
		return -1;
	}

	
	if (rc==1) {
		if( create_codec_lumps(msg)<0 ) {
			LM_ERR("failed to create codec lumps\n");
			return -1;
		}
		
		return 0;
	}

	
	if( route_type & (REQUEST_ROUTE | ONREPLY_ROUTE | LOCAL_ROUTE)  )
	{
		
		return 0;
	}

	if( route_type & (FAILURE_ROUTE | BRANCH_ROUTE) )
	{
		
		if ( clone_codec_lumps()<0 ) {
			LM_ERR("failed to clone codec lumps\n");
			return -1;
		}
		return 0;
	}

	
	return -1;
};



static struct lump * get_associated_lump(struct sip_msg * msg, struct sdp_stream_cell * cell)
{
	struct lump *lmp;
	char *payload;
	int i, have,want;

	LM_DBG("Have %d lumps\n",lumps_len);

	for( i =0 ; i< lumps_len; i++)
	{
		have = lumps[i]->u.offset;
		payload = cell->payloads.s;
		while (payload > cell->body.s && *(payload - 1) == ' ')
			payload--;
		want = payload - msg->buf;

		LM_DBG("have lump at %d want at %d\n", have, want );
		if( have == want ) {
			
			for( lmp=lumps[i] ; lmp->after ; lmp=lmp->after);
			return lmp;
		}
	}

	return NULL;
};


static int do_for_all_streams(struct sip_msg* msg, str* str1,str * str2, regex_t* re, int op,int desc)
{
	struct sdp_session_cell * cur_session;
	sdp_info_t *sdp;
	int rez;

	if (msg==NULL || msg==FAKED_REPLY)
		return -1;

	sdp = parse_sdp(msg);
	if (!sdp) {
		LM_DBG("Message has no SDP\n");
		return -1;
	}

	if (get_codec_lumps(msg)<0) {
		LM_ERR("failed to prepare changes for codecs\n");
		return -1;
	}

	cur_session = sdp->sessions;
	rez = -1;

	while(cur_session)
	{
		struct sdp_stream_cell * cur_cell = cur_session->streams;

		while(cur_cell)
		{
			if(stream_process(msg,cur_cell,str1,str2,re,op,desc)==1)
				rez = 1;
			cur_cell = cur_cell->next;
		}

		cur_session = cur_session->next;

	}

	return rez;
}


int delete_sdp_line( struct sip_msg * msg, char * s)
{
	char * start,*end;

	if( !s )
		return 1;

	start = s;
	end  = s;

	while(*start != '\n')
		start--;
	start++;

	while(*end != '\n')
		end++;
	end++;

	
	if( del_lump(msg, start - msg->buf, end - start,0) == NULL )
	{
		return -1;
	}

	return 0;
}



static int stream_process(struct sip_msg * msg, struct sdp_stream_cell *cell, str * s, str* ss, regex_t* re, int op,int description)
{
	static sdp_payload_attr_t static_payloads[] = {
	
	{ NULL,0,{ "0",1},{"PCMU",4},{ "8000",4},{NULL,0},{NULL,0} },    { NULL,0,{ "3",1},{ "GSM",3},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{ "4",1},{"G723",4},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{ "5",1},{"DVI4",4},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{ "6",1},{"DVI4",4},{"16000",5},{NULL,0},{NULL,0} }, { NULL,0,{ "7",1},{ "LPC",3},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{ "8",1},{"PCMA",4},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{ "9",1},{"G722",4},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{"10",2},{ "L16",3},{"44100",5},{NULL,0},{NULL,0} }, { NULL,0,{"11",2},{ "L16",3},{"44100",5},{NULL,0},{NULL,0} }, { NULL,0,{"12",2},{"QCELP",5},{"8000",4},{NULL,0},{NULL,0} }, { NULL,0,{"13",2},{  "CN",2},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{"14",2},{ "MPA",3},{"90000",5},{NULL,0},{NULL,0} }, { NULL,0,{"15",2},{"G728",4},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{"16",2},{"DVI4",4},{"11025",5},{NULL,0},{NULL,0} }, { NULL,0,{"17",2},{"DVI4",4},{"22050",5},{NULL,0},{NULL,0} }, { NULL,0,{"18",2},{"G729",4},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{"25",2},{"CelB",4},{ "8000",4},{NULL,0},{NULL,0} }, { NULL,0,{"26",2},{"JPEG",4},{"90000",5},{NULL,0},{NULL,0} }, { NULL,0,{"28",2},{  "nv",2},{"90000",5},{NULL,0},{NULL,0} }, { NULL,0,{"31",2},{"H261",4},{"90000",5},{NULL,0},{NULL,0} }, { NULL,0,{"32",2},{ "MPV",3},{"90000",5},{NULL,0},{NULL,0} }, { NULL,0,{"33",2},{"MP2T",4},{"90000",5},{NULL,0},{NULL,0} }, { NULL,0,{"34",2},{"H263",4},{"90000",5},{NULL,0},{NULL,0} }, { NULL,0,{"t38",3},{"t38",3},{     "",0},{NULL,0},{NULL,0} }, { NULL,0,{NULL,0},{  NULL,0},{   NULL,0},{NULL,0},{NULL,0} }
























	};
	sdp_payload_attr_t *payload;
	char *cur, *tmp, *buff, temp;
	struct lump * lmp;
	str found;
	int ret, i,match, buff_len, is_static;
	regmatch_t pmatch;


	lmp = get_associated_lump(msg, cell);
	if( lmp == NULL)
	{
		LM_ERR("There is no lump for this sdp cell\n");
		return -1;
	}

	
	if (lmp->len == 0)
		return -1;


	buff_len = 0;
	ret = 0;

	buff = pkg_malloc(lmp->len+1);
	if( buff == NULL)
	{
		LM_ERR("Out of memory\n");
		return -1;
	}

	
	is_static = 0;
	payload = cell->payload_attr;

	while(payload)
	{
		if( payload->rtp_enc.s == NULL || (payload->rtp_clock.s == NULL && ss != NULL)
		 || payload->rtp_payload.s == NULL)
		{
			goto next_payload;
		}

		match = 0;

		if( description == DESC_REGEXP ||description == DESC_REGEXP_COMPLEMENT )
		{
			
			if (is_static) {
				match = regexec( re, payload->rtp_enc.s, 1, &pmatch, 0) == 0;
			} else {
				temp = payload->rtp_enc.s[payload->rtp_enc.len];
				payload->rtp_enc.s[payload->rtp_enc.len] = 0;
				match = regexec( re, payload->rtp_enc.s, 1, &pmatch, 0) == 0;
				payload->rtp_enc.s[payload->rtp_enc.len] = temp;
			}
		}

		if( description == DESC_REGEXP_COMPLEMENT)
			match = !match;

		if( description == DESC_NAME  )
		{
			match = s->len == payload->rtp_enc.len && strncasecmp( s->s, payload->rtp_enc.s ,	payload->rtp_enc.len) == 0;
		}

		if( description == DESC_NAME_AND_CLOCK)
		{
			
			match = s->len == payload->rtp_enc.len && strncasecmp( s->s, payload->rtp_enc.s , payload->rtp_enc.len) == 0 && (ss == NULL || ( ss->len == payload->rtp_clock.len && strncasecmp( ss->s, payload->rtp_clock.s , payload->rtp_clock.len) == 0 ) );






		}

		
		if (match) {

			match = 0;

			cur = lmp->u.value;
			while( !match && cur < lmp->u.value + lmp->len)
			{
				
				found.s = cur;

				while(  cur < lmp->u.value + lmp->len &&  *cur != ' ' )
					cur++;

				found.len = cur - found.s;

				
				if ( found.len == payload->rtp_payload.len && strncmp( found.s,payload->rtp_payload.s,found.len) == 0) {
					match = 1;
				} else {
					
					while( cur < lmp->u.value + lmp->len && * cur == ' '  )
						cur++;
				}
			}

			
			if (match) {

				if(op == FIND)
				{
					ret = 1;
					goto end;
				}

				if( op == DELETE && !is_static )
				{
					

					if( delete_sdp_line( msg, payload->rtp_enc.s) < 0 )
					{
						LM_ERR("Unable to add delete lump for a=\n");
						ret = -1;
						goto end;
					}

					if( delete_sdp_line( msg, payload->fmtp_string.s) < 0 )
					{
						LM_ERR("Unable to add delete lump for a=\n");
						ret = -1;
						goto end;
					}
				}

				{
					
					while (found.s > lmp->u.value && *(found.s - 1) == ' ') {
						found.s--;
						found.len++;
					}

					
					if (cur == lmp->u.value + lmp->len) {
						tmp = found.s;
						while (*(--tmp) == ' ') {
							found.s--;
							found.len++;
						}
					}

					
					for(tmp=found.s ; tmp< lmp->u.value + lmp->len ; tmp++ )
						*tmp  = *(tmp+found.len);

					
					lmp->len -= found.len;
				}

				
				if( op == ADD_TO_FRONT  || op == ADD_TO_BACK)
				{
					memcpy(&buff[buff_len]," ",1);
					buff_len++;

					memcpy(&buff[buff_len],payload->rtp_payload.s, payload->rtp_payload.len);

					buff_len += payload->rtp_payload.len;
				}

				ret = 1;
			}

		}

		
	next_payload:
		if (!is_static) {
			payload = payload->next;
			if (payload==NULL) {
				payload = static_payloads;
				is_static = 1;
			}
		} else {
			payload ++;
			if (payload->rtp_payload.s==NULL)
				payload=NULL;
		}
	}


	if( op == ADD_TO_FRONT && buff_len >0 )
	{
		lmp->u.value = (char*)pkg_realloc(lmp->u.value, lmp->len+buff_len);
		if(!lmp->u.value) {
			LM_ERR("No more pkg memory\n");
			ret = -1;
			goto end;
		}

		for( i = lmp->len -1 ; i>=0;i--)
			lmp->u.value[i+buff_len] = lmp->u.value[i];

		memcpy(lmp->u.value,buff,buff_len);

		lmp->len += buff_len;

	}

	if( op == ADD_TO_BACK && buff_len >0 )
	{

		lmp->u.value = (char*)pkg_realloc(lmp->u.value, lmp->len+buff_len);
		if(!lmp->u.value) {
			LM_ERR("No more pkg memory\n");
			ret = -1;
			goto end;
		}

		memcpy(&lmp->u.value[lmp->len],buff,buff_len);

		lmp->len += buff_len;

	}

	
	if (lmp->len == 0) {
		
		lmp = del_lump(msg, cell->port.s - msg->buf - 1, cell->port.len + 2, 0);
		if (!lmp) {
			LM_ERR("could not add lump to disable stream!\n");
			goto end;
		}
		tmp = pkg_malloc(3);
		if (!tmp) {
			LM_ERR("oom for port 0\n");
			goto end;
		}
		memcpy(tmp, " 0 ", 3);
		if (!insert_new_lump_after(lmp, tmp, 3, 0))
			LM_ERR("could not insert lump to disable stream!\n");
	}

end:
	pkg_free(buff);
	return ret;
}


int codec_find(struct sip_msg* msg, str* codec, str* clock)
{
	LM_DBG("searching for codec <%.*s>, clock <%.*s> \n", codec->len, codec->s, clock ? clock->len : 0, clock ? clock->s : NULL);


	return do_for_all_streams(msg, codec, clock, NULL, FIND, DESC_NAME);
}

int codec_find_re (struct sip_msg* msg, regex_t* re)
{
	return do_for_all_streams(msg, NULL, NULL, re, FIND, DESC_REGEXP);
}


int codec_delete_re(struct sip_msg* msg, regex_t* re)
{
	return do_for_all_streams(msg, NULL, NULL, re, DELETE, DESC_REGEXP);
}


int codec_delete_except_re(struct sip_msg* msg, regex_t* re)
{
	return do_for_all_streams( msg, NULL, NULL, re, DELETE, DESC_REGEXP_COMPLEMENT);
}


int codec_delete(struct sip_msg* msg, str* codec, str* clock)
{
	LM_DBG("deleting codec <%.*s> with clock <%.*s> \n", codec->len, codec->s, clock ? clock->len : 0, clock ? clock->s : NULL);

	return do_for_all_streams( msg, codec, clock, NULL, DELETE, DESC_NAME_AND_CLOCK);
}


int codec_move_up_re(struct sip_msg* msg, regex_t* re)
{
	return do_for_all_streams( msg, NULL, NULL, re, ADD_TO_FRONT, DESC_REGEXP);
}


int codec_move_up(struct sip_msg* msg, str* codec, str* clock)
{
	LM_DBG("moving up codec <%.*s> with clock <%.*s> \n", codec->len, codec->s, clock ? clock->len : 0, clock ? clock->s : NULL);

	return do_for_all_streams(msg, codec, clock, NULL, ADD_TO_FRONT, DESC_NAME_AND_CLOCK);
}


int codec_move_down_re(struct sip_msg* msg, regex_t* re)
{
	return do_for_all_streams( msg, NULL, NULL, re, ADD_TO_BACK, DESC_REGEXP);
}


int codec_move_down(struct sip_msg* msg, str* codec, str* clock)
{
	LM_DBG("moving down codec <%.*s> with clock <%.*s> \n", codec->len, codec->s, clock ? clock->len : 0, clock ? clock->s : NULL);

	return do_for_all_streams( msg, codec, clock, NULL, ADD_TO_BACK, DESC_NAME_AND_CLOCK);
}


static int handle_streams(struct sip_msg* msg, regex_t* re, regex_t* re2, int delete)
{
	struct sdp_session_cell *session;
	struct sdp_stream_cell *stream;
	struct sdp_stream_cell *prev_stream;
	regmatch_t pmatch;
	struct lump *lmp, *l;
	char *begin, *end;
	char temp;
	str body;
	int match;

	if (msg==NULL || msg==FAKED_REPLY)
		return -1;

	if(!parse_sdp(msg))
	{
		LM_DBG("Message has no SDP\n");
		return -1;
	}

	
	match = 0;
	for (session = get_sdp(msg)->sessions; session && !match;
	     session = session->next) {
		prev_stream = NULL;
		for( stream=session->streams ; stream ;
		prev_stream=stream,stream=stream->next){
			
			temp = stream->media.s[stream->media.len];
			stream->media.s[stream->media.len] = 0;
			match = regexec( re, stream->media.s, 1, &pmatch, 0) == 0;
			stream->media.s[stream->media.len] = temp;
			
			if (match && re2) {
				temp = stream->transport.s[stream->transport.len];
				stream->transport.s[stream->transport.len] = 0;
				match = regexec( re2, stream->transport.s, 1, &pmatch, 0) == 0;
				stream->transport.s[stream->transport.len] = temp;
			}
			if (match) break;
		}
	}

	if (!match)
		return -1;

	LM_DBG(" found stream media [%.*s], transport [%.*s]\n", stream->media.len,stream->media.s, stream->transport.len,stream->transport.s);


	
	if (!delete)
		return 1;


	
	if (get_codec_lumps(msg)<0) {
		LM_ERR("failed to get lumps for streams\n");
		return -1;
	}
	lmp = get_associated_lump(msg, stream);
	if( lmp == NULL) {
		LM_ERR("There is no lump for this sdp cell\n");
		return -1;
	}

	
	if (lmp->len == 0)
		return -1;

	

	
	begin = stream->media.s ;
	while( *(begin-1)!='\n' && *(begin-1)!='\r') begin--;

	
	if (prev_stream) {
		
		end = prev_stream->media.s ;
		while( *(end-1)!='\n' && *(end-1)!='\r') end--;
	} else {
		
		body.s = NULL; body.len = 0;
		get_body(msg, &body);
		end = body.s + body.len;
	}

	

	l = del_lump( msg, (unsigned int)(begin-msg->buf), (unsigned int)(end-begin), 0);
	if (l==NULL) {
		LM_ERR("failed to create delete lump\n");
		return -1;
	}

	
	lmp->len = 0;


	return 1;
}


int stream_find(struct sip_msg* msg, regex_t* re, regex_t* re2)
{
	return handle_streams(msg, re, re2, 0);
}


int stream_delete(struct sip_msg* msg, regex_t* re, regex_t* re2)
{
	return handle_streams(msg, re, re2, 1);
}



