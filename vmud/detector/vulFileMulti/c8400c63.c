















static int ipsecmod_apply_cfg(struct ipsecmod_env* ipsecmod_env, struct config_file* cfg)
{
	if(!cfg->ipsecmod_hook || (cfg->ipsecmod_hook && !cfg->ipsecmod_hook[0])) {
		log_err("ipsecmod: missing ipsecmod-hook.");
		return 0;
	}
	if(cfg->ipsecmod_whitelist && !ipsecmod_whitelist_apply_cfg(ipsecmod_env, cfg))
		return 0;
	return 1;
}

int ipsecmod_init(struct module_env* env, int id)
{
	struct ipsecmod_env* ipsecmod_env = (struct ipsecmod_env*)calloc(1, sizeof(struct ipsecmod_env));
	if(!ipsecmod_env) {
		log_err("malloc failure");
		return 0;
	}
	env->modinfo[id] = (void*)ipsecmod_env;
	ipsecmod_env->whitelist = NULL;
	if(!ipsecmod_apply_cfg(ipsecmod_env, env->cfg)) {
		log_err("ipsecmod: could not apply configuration settings.");
		return 0;
	}
	return 1;
}

void ipsecmod_deinit(struct module_env* env, int id)
{
	struct ipsecmod_env* ipsecmod_env;
	if(!env || !env->modinfo[id])
		return;
	ipsecmod_env = (struct ipsecmod_env*)env->modinfo[id];
	
	ipsecmod_whitelist_delete(ipsecmod_env->whitelist);
	free(ipsecmod_env);
	env->modinfo[id] = NULL;
}


static int ipsecmod_new(struct module_qstate* qstate, int id)
{
	struct ipsecmod_qstate* iq = (struct ipsecmod_qstate*)regional_alloc( qstate->region, sizeof(struct ipsecmod_qstate));
	memset(iq, 0, sizeof(*iq));
	qstate->minfo[id] = iq;
	if(!iq)
		return 0;
	
	iq->enabled = qstate->env->cfg->ipsecmod_enabled;
	iq->is_whitelisted = ipsecmod_domain_is_whitelisted( (struct ipsecmod_env*)qstate->env->modinfo[id], qstate->qinfo.qname, qstate->qinfo.qname_len, qstate->qinfo.qclass);

	return 1;
}


static void ipsecmod_error(struct module_qstate* qstate, int id)
{
	qstate->ext_state[id] = module_error;
	qstate->return_rcode = LDNS_RCODE_SERVFAIL;
}


static int generate_request(struct module_qstate* qstate, int id, uint8_t* name, size_t namelen, uint16_t qtype, uint16_t qclass, uint16_t flags)

{
	struct module_qstate* newq;
	struct query_info ask;
	ask.qname = name;
	ask.qname_len = namelen;
	ask.qtype = qtype;
	ask.qclass = qclass;
	ask.local_alias = NULL;
	log_query_info(VERB_ALGO, "ipsecmod: generate request", &ask);
	fptr_ok(fptr_whitelist_modenv_attach_sub(qstate->env->attach_sub));
	if(!(*qstate->env->attach_sub)(qstate, &ask, (uint16_t)(BIT_RD|flags), 0, 0, &newq)){
		log_err("Could not generate request: out of memory");
		return 0;
	}
	qstate->ext_state[id] = module_wait_subquery;
	return 1;
}


static int call_hook(struct module_qstate* qstate, struct ipsecmod_qstate* iq, struct ipsecmod_env* ATTR_UNUSED(ie))

{
	size_t slen, tempdata_len, tempstring_len, i;
	char str[65535], *s, *tempstring;
	int w;
	struct ub_packed_rrset_key* rrset_key;
	struct packed_rrset_data* rrset_data;
	uint8_t *tempdata;

	
	if(system(NULL) == 0) {
		log_err("ipsecmod: no shell available for ipsecmod-hook");
		return 0;
	}

	
	s = str;
	slen = sizeof(str);
	memset(s, 0, slen);

	
	sldns_str_print(&s, &slen, "%s", qstate->env->cfg->ipsecmod_hook);
	
	sldns_str_print(&s, &slen, " ");
	
	tempstring = sldns_wire2str_dname(qstate->qinfo.qname, qstate->qinfo.qname_len);
	if(!tempstring) {
		log_err("ipsecmod: out of memory when calling the hook");
		return 0;
	}
	sldns_str_print(&s, &slen, "\"%s\"", tempstring);
	free(tempstring);
	
	sldns_str_print(&s, &slen, " ");
	
	rrset_data = (struct packed_rrset_data*)iq->ipseckey_rrset->entry.data;
	sldns_str_print(&s, &slen, "\"%ld\"", (long)rrset_data->ttl);
	
	sldns_str_print(&s, &slen, " ");
	
	rrset_key = reply_find_answer_rrset(&qstate->return_msg->qinfo, qstate->return_msg->rep);
	rrset_data = (struct packed_rrset_data*)rrset_key->entry.data;
	sldns_str_print(&s, &slen, "\"");
	for(i=0; i<rrset_data->count; i++) {
		if(i > 0) {
			
			sldns_str_print(&s, &slen, " ");
		}
		
		w = sldns_wire2str_rdata_buf(rrset_data->rr_data[i] + 2, rrset_data->rr_len[i] - 2, s, slen, qstate->qinfo.qtype);
		if(w < 0) {
			
			return -1;
		} else if((size_t)w >= slen) {
			s = NULL; 
			slen = 0;
			return -1;
		} else {
			s += w;
			slen -= w;
		}
	}
	sldns_str_print(&s, &slen, "\"");
	
	sldns_str_print(&s, &slen, " ");
	
	sldns_str_print(&s, &slen, "\"");
	rrset_data = (struct packed_rrset_data*)iq->ipseckey_rrset->entry.data;
	for(i=0; i<rrset_data->count; i++) {
		if(i > 0) {
			
			sldns_str_print(&s, &slen, " ");
		}
		
		tempdata = rrset_data->rr_data[i] + 2;
		tempdata_len = rrset_data->rr_len[i] - 2;
		
		tempstring = s; tempstring_len = slen;
		w = sldns_wire2str_ipseckey_scan(&tempdata, &tempdata_len, &s, &slen, NULL, 0);
		
		if(w == -1){
			s = tempstring; slen = tempstring_len;
		}
	}
	sldns_str_print(&s, &slen, "\"");
	verbose(VERB_ALGO, "ipsecmod: hook command: '%s'", str);
	
	if(system(str) != 0)
		return 0;
	return 1;
}


static void ipsecmod_handle_query(struct module_qstate* qstate, struct ipsecmod_qstate* iq, struct ipsecmod_env* ie, int id)

{
	struct ub_packed_rrset_key* rrset_key;
	struct packed_rrset_data* rrset_data;
	size_t i;
	
	if(!(iq->enabled && iq->is_whitelisted)) {
		qstate->ext_state[id] = module_wait_module;
		return;
	}
	
	if(!iq->ipseckey_done) {
		if(qstate->qinfo.qtype == LDNS_RR_TYPE_A || qstate->qinfo.qtype == LDNS_RR_TYPE_AAAA) {
			char type[16];
			sldns_wire2str_type_buf(qstate->qinfo.qtype, type, sizeof(type));
			verbose(VERB_ALGO, "ipsecmod: query for %s; engaging", type);
			qstate->no_cache_store = 1;
		}
		
		qstate->ext_state[id] = module_wait_module;
		return;
	}
	
	
	if(iq->ipseckey_rrset) {
		rrset_data = (struct packed_rrset_data*)iq->ipseckey_rrset->entry.data;
		if(rrset_data) {
			
			if(!qstate->env->cfg->ipsecmod_ignore_bogus && rrset_data->security == sec_status_bogus) {
				log_err("ipsecmod: bogus IPSECKEY");
				ipsecmod_error(qstate, id);
				return;
			}
			
			if(!call_hook(qstate, iq, ie) && qstate->env->cfg->ipsecmod_strict) {
				log_err("ipsecmod: ipsecmod-hook failed");
				ipsecmod_error(qstate, id);
				return;
			}
			
			rrset_key = reply_find_answer_rrset(&qstate->return_msg->qinfo, qstate->return_msg->rep);
			rrset_data = (struct packed_rrset_data*)rrset_key->entry.data;
			if(rrset_data->ttl > (time_t)qstate->env->cfg->ipsecmod_max_ttl) {
				
				rrset_data->ttl = qstate->env->cfg->ipsecmod_max_ttl;
				for(i=0; i<rrset_data->count+rrset_data->rrsig_count; i++)
					rrset_data->rr_ttl[i] = qstate->env->cfg->ipsecmod_max_ttl;
				
				if(qstate->return_msg->rep->ttl > (time_t)qstate->env->cfg->ipsecmod_max_ttl) {
					qstate->return_msg->rep->ttl = qstate->env->cfg->ipsecmod_max_ttl;
					qstate->return_msg->rep->prefetch_ttl = PREFETCH_TTL_CALC( qstate->return_msg->rep->ttl);
					qstate->return_msg->rep->serve_expired_ttl = qstate->return_msg->rep->ttl + qstate->env->cfg->serve_expired_ttl;
				}
			}
		}
	}
	
	if(!dns_cache_store(qstate->env, &qstate->qinfo, qstate->return_msg->rep, 0, qstate->prefetch_leeway, 0, qstate->region, qstate->query_flags)) {

		log_err("ipsecmod: out of memory caching record");
	}
	qstate->ext_state[id] = module_finished;
}


static void ipsecmod_handle_response(struct module_qstate* qstate, struct ipsecmod_qstate* ATTR_UNUSED(iq), struct ipsecmod_env* ATTR_UNUSED(ie), int id)


{
	
	if(!(iq->enabled && iq->is_whitelisted)) {
		qstate->ext_state[id] = module_finished;
		return;
	}
	
	if((qstate->qinfo.qtype == LDNS_RR_TYPE_A || qstate->qinfo.qtype == LDNS_RR_TYPE_AAAA) &&  qstate->return_msg && reply_find_answer_rrset(&qstate->return_msg->qinfo, qstate->return_msg->rep) &&  qstate->return_rcode == LDNS_RCODE_NOERROR) {






		char type[16];
		sldns_wire2str_type_buf(qstate->qinfo.qtype, type, sizeof(type));
		verbose(VERB_ALGO, "ipsecmod: response for %s; generating IPSECKEY " "subquery", type);
		
		if(!generate_request(qstate, id, qstate->qinfo.qname, qstate->qinfo.qname_len, LDNS_RR_TYPE_IPSECKEY, qstate->qinfo.qclass, 0)) {

			log_err("ipsecmod: could not generate subquery.");
			ipsecmod_error(qstate, id);
		}
		return;
	}
	
	qstate->ext_state[id] = module_finished;
}

void ipsecmod_operate(struct module_qstate* qstate, enum module_ev event, int id, struct outbound_entry* outbound)

{
	struct ipsecmod_env* ie = (struct ipsecmod_env*)qstate->env->modinfo[id];
	struct ipsecmod_qstate* iq = (struct ipsecmod_qstate*)qstate->minfo[id];
	verbose(VERB_QUERY, "ipsecmod[module %d] operate: extstate:%s event:%s", id, strextstate(qstate->ext_state[id]), strmodulevent(event));
	if(iq) log_query_info(VERB_QUERY, "ipsecmod operate: query", &qstate->qinfo);

	
	if((event == module_event_new || event == module_event_pass) && iq == NULL) {
		if(!ipsecmod_new(qstate, id)) {
			ipsecmod_error(qstate, id);
			return;
		}
		iq = (struct ipsecmod_qstate*)qstate->minfo[id];
	}
	if(iq && (event == module_event_pass || event == module_event_new)) {
		ipsecmod_handle_query(qstate, iq, ie, id);
		return;
	}
	if(iq && (event == module_event_moddone)) {
		ipsecmod_handle_response(qstate, iq, ie, id);
		return;
	}
	if(iq && outbound) {
		
		return;
	}
	if(event == module_event_error) {
		verbose(VERB_ALGO, "got called with event error, giving up");
		ipsecmod_error(qstate, id);
		return;
	}
	if(!iq && (event == module_event_moddone)) {
		
		qstate->ext_state[id] = module_finished;
		return;
	}

	log_err("ipsecmod: bad event %s", strmodulevent(event));
	ipsecmod_error(qstate, id);
	return;
}

void ipsecmod_inform_super(struct module_qstate* qstate, int id, struct module_qstate* super)

{
	struct ipsecmod_qstate* siq;
	log_query_info(VERB_ALGO, "ipsecmod: inform_super, sub is", &qstate->qinfo);
	log_query_info(VERB_ALGO, "super is", &super->qinfo);
	siq = (struct ipsecmod_qstate*)super->minfo[id];
	if(!siq) {
		verbose(VERB_ALGO, "super has no ipsecmod state");
		return;
	}

	if(qstate->return_msg) {
		struct ub_packed_rrset_key* rrset_key = reply_find_answer_rrset( &qstate->return_msg->qinfo, qstate->return_msg->rep);
		if(rrset_key) {
			
			
			rrset_key = packed_rrset_copy_region(rrset_key, super->region, 0);
			siq->ipseckey_rrset = rrset_key;
			if(!rrset_key) {
				log_err("ipsecmod: out of memory.");
			}
		}
	}
	
	siq->ipseckey_done = 1;
}

void ipsecmod_clear(struct module_qstate* qstate, int id)
{
	if(!qstate)
		return;
	qstate->minfo[id] = NULL;
}

size_t ipsecmod_get_mem(struct module_env* env, int id)
{
	struct ipsecmod_env* ie = (struct ipsecmod_env*)env->modinfo[id];
	if(!ie)
		return 0;
	return sizeof(*ie) + ipsecmod_whitelist_get_mem(ie->whitelist);
}


static struct module_func_block ipsecmod_block = {
	"ipsecmod", &ipsecmod_init, &ipsecmod_deinit, &ipsecmod_operate, &ipsecmod_inform_super, &ipsecmod_clear, &ipsecmod_get_mem };



struct module_func_block* ipsecmod_get_funcblock(void)
{
	return &ipsecmod_block;
}

