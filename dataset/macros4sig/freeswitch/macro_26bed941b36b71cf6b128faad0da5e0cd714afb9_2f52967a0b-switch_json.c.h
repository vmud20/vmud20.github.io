#include<setjmp.h>

#include<stdint.h>

#include<sys/socket.h>
#include<unistd.h>


#include<stddef.h>
#include<limits.h>

#include<time.h>
#include<assert.h>


#include<errno.h>
#include<stdarg.h>
#include<inttypes.h>
#include<ctype.h>

#include<signal.h>

#include<arpa/inet.h>

#include<string.h>

#include<strings.h>

#include<sys/types.h>

#include<math.h>

#include<netdb.h>
#include<float.h>

#include<stdio.h>
#include<netinet/in.h>


#include<stdlib.h>
#include<fcntl.h>

#include<sys/stat.h>
#include<pthread.h>
#define cJSON_AddFalseToObject(object,name)		cJSON_AddItemToObject(object, name, cJSON_CreateFalse())
#define cJSON_AddNullToObject(object,name)	cJSON_AddItemToObject(object, name, cJSON_CreateNull())
#define cJSON_AddNumberToObject(object,name,n)	cJSON_AddItemToObject(object, name, cJSON_CreateNumber(n))
#define cJSON_AddStringToObject(object,name,s)	cJSON_AddItemToObject(object, name, cJSON_CreateString(s))
#define cJSON_AddTrueToObject(object,name)	cJSON_AddItemToObject(object, name, cJSON_CreateTrue())
#define cJSON_Array 5
#define cJSON_False 0
#define cJSON_IsReference 256
#define cJSON_NULL 2
#define cJSON_Number 3
#define cJSON_Object 6
#define cJSON_String 4
#define cJSON_True 1

#define FREESWITCH_ITAD "543"
#define FREESWITCH_OID_PREFIX ".1.3.6.1.4.1." FREESWITCH_PEN
#define FREESWITCH_PEN "27880"
#define SWITCH_BEGIN_EXTERN_C       extern "C" {
#define SWITCH_END_EXTERN_C         }





#define _XOPEN_SOURCE 600
#define __BSD_VISIBLE 1
#define __EXTENSIONS__ 1



#define SWITCH_MAX_CAND_ACL 25
#define switch_core_media_gen_key_frame(_session) switch_core_media_codec_control(_session, SWITCH_MEDIA_TYPE_VIDEO, SWITCH_IO_WRITE, \
																				  SCC_VIDEO_GEN_KEYFRAME, SCCT_NONE, NULL, SCCT_NONE, NULL, NULL, NULL) \

#define switch_core_media_read_lock(_s, _t) switch_core_media_read_lock_unlock(_s, _t, SWITCH_TRUE) 
#define switch_core_media_read_unlock(_s, _t) switch_core_media_read_lock_unlock(_s, _t, SWITCH_FALSE)
#define switch_core_media_write_bandwidth(_session, _val) switch_core_media_codec_control(_session, SWITCH_MEDIA_TYPE_VIDEO, SWITCH_IO_WRITE, \
																						  SCC_VIDEO_BANDWIDTH, SCCT_STRING, _val, SCCT_NONE, NULL, NULL, NULL) \

#define LIMIT_BACKEND_VARIABLE "limit_backend"
#define LIMIT_DEF_XFER_EXTEN "limit_exceeded"
#define LIMIT_EVENT_USAGE "limit::usage"
#define LIMIT_IGNORE_TRANSFER_VARIABLE "limit_ignore_transfer"
#define SWITCH_LIMIT_INCR(name) static switch_status_t name (switch_core_session_t *session, const char *realm, const char *resource, const int max, const int interval)
#define SWITCH_LIMIT_INTERVAL_RESET(name) static switch_status_t name (const char *realm, const char *resource)
#define SWITCH_LIMIT_RELEASE(name) static switch_status_t name (switch_core_session_t *session, const char *realm, const char *resource)
#define SWITCH_LIMIT_RESET(name) static switch_status_t name (void)
#define SWITCH_LIMIT_STATUS(name) static char * name (void)
#define SWITCH_LIMIT_USAGE(name) static int name (const char *realm, const char *resource, uint32_t *rcount)

#define DEFAULT_PGSQL_RETRIES 120

#define switch_pgsql_cancel(handle) switch_pgsql_cancel_real("__FILE__", (char * )__SWITCH_FUNC__, "__LINE__", handle)
#define switch_pgsql_finish_results(handle) switch_pgsql_finish_results_real("__FILE__", (char * )__SWITCH_FUNC__, "__LINE__", handle)
#define switch_pgsql_handle_callback_exec(handle,  sql,  callback, pdata, err) \
		switch_pgsql_handle_callback_exec_detailed("__FILE__", (char * )__SWITCH_FUNC__, "__LINE__", \
												  handle, sql, callback, pdata, err)
#define switch_pgsql_handle_exec(handle, sql, err) switch_pgsql_handle_exec_detailed("__FILE__", (char * )__SWITCH_FUNC__, "__LINE__", handle, sql, err)
#define switch_pgsql_handle_exec_base(handle, sql, err) switch_pgsql_handle_exec_base_detailed("__FILE__", (char * )__SWITCH_FUNC__, "__LINE__", handle, sql, err)
#define switch_pgsql_handle_exec_string(handle, sql, resbuf, len, err) switch_pgsql_handle_exec_string_detailed("__FILE__", (char * )__SWITCH_FUNC__, "__LINE__", handle, sql, resbuf, len, err)
#define switch_pgsql_next_result(h, r) switch_pgsql_next_result_timed(h, r, 10000)
#define DEFAULT_ODBC_RETRIES 120

#define switch_odbc_handle_callback_exec(handle,  sql,  callback, pdata, err) \
		switch_odbc_handle_callback_exec_detailed("__FILE__", (char * )__SWITCH_FUNC__, "__LINE__", \
												  handle, sql, callback, pdata, err)



#define NEW_HOOK_DECL(_NAME) NEW_HOOK_DECL_ADD_P(_NAME)					\
	{																	\
		switch_io_event_hook_##_NAME##_t *hook, *ptr;					\
		assert(_NAME != NULL);											\
		for (ptr = session->event_hooks._NAME; ptr && ptr->next; ptr = ptr->next) \
			if (ptr->_NAME == _NAME) return SWITCH_STATUS_FALSE;		\
		if (ptr && ptr->_NAME == _NAME) return SWITCH_STATUS_FALSE;		\
		if ((hook = switch_core_session_alloc(session, sizeof(*hook))) != 0) { \
			hook->_NAME = _NAME ;										\
			if (! session->event_hooks._NAME ) {						\
				session->event_hooks._NAME = hook;						\
			} else {													\
				ptr->next = hook;										\
			}															\
			return SWITCH_STATUS_SUCCESS;								\
		}																\
		return SWITCH_STATUS_MEMERR;									\
	}																	\
	NEW_HOOK_DECL_REM_P(_NAME)											\
	{																	\
		switch_io_event_hook_##_NAME##_t *ptr, *last = NULL;			\
		assert(_NAME != NULL);											\
		for (ptr = session->event_hooks._NAME; ptr; ptr = ptr->next) {	\
			if (ptr->_NAME == _NAME) {									\
				if (last) {												\
					last->next = ptr->next;								\
				} else {												\
					session->event_hooks._NAME = ptr->next;				\
				}														\
				return SWITCH_STATUS_SUCCESS;							\
			}															\
			last = ptr;													\
		}																\
		return SWITCH_STATUS_FALSE;										\
	}
#define NEW_HOOK_DECL_ADD_P(_NAME) SWITCH_DECLARE(switch_status_t) switch_core_event_hook_add_##_NAME \
															   (switch_core_session_t *session, switch_##_NAME##_hook_t _NAME)
#define NEW_HOOK_DECL_REM_P(_NAME) SWITCH_DECLARE(switch_status_t) switch_core_event_hook_remove_##_NAME \
																   (switch_core_session_t *session, switch_##_NAME##_hook_t _NAME)

#define SWITCH_CONFIG_ITEM(_key, _type, _flags, _ptr, _defaultvalue, _data, _syntax, _helptext)	{ _key, _type, _flags, _ptr, (void*)_defaultvalue, (void*)_data, NULL, _syntax, _helptext }
#define SWITCH_CONFIG_ITEM_CALLBACK(_key, _type, _flags, _ptr, _defaultvalue, _function, _functiondata, _syntax, _helptext)	{ _key, _type, _flags, _ptr, (void*)_defaultvalue, _functiondata, _function, _syntax, _helptext }
#define SWITCH_CONFIG_ITEM_END() { NULL, SWITCH_CONFIG_LAST, 0, NULL, NULL, NULL, NULL, NULL, NULL }
#define SWITCH_CONFIG_ITEM_STRING_STRDUP(_key, _flags, _ptr, _defaultvalue, _syntax, _helptext)	{ (_key), SWITCH_CONFIG_STRING, (_flags), (_ptr), ((void*)_defaultvalue), (NULL), (NULL), (_syntax), (_helptext) }
#define SWITCH_CONFIG_SET_ITEM(_item, _key, _type, _flags, _ptr, _defaultvalue, _data, _syntax, _helptext)  switch_config_perform_set_item(&(_item), _key, _type, _flags, _ptr, (void*)(_defaultvalue), _data, NULL, _syntax, _helptext)
#define SWITCH_CONFIG_SET_ITEM_CALLBACK(_item, _key, _type, _flags, _ptr, _defaultvalue, _data, _function, _syntax, _helptext)  switch_config_perform_set_item(&(_item), _key, _type, _flags, _ptr, (void*)(_defaultvalue), _data, _function, _syntax, _helptext)


#define SWITCH_XML_BUFSIZE 1024	
#define switch_xml_add_child_d(xml, name, off) \
    switch_xml_set_flag(switch_xml_add_child(xml, strdup(name), off), SWITCH_XML_NAMEM)
#define switch_xml_bind_search_function(_f, _s, _u) switch_xml_bind_search_function_ret(_f, _s, _u, NULL)
#define switch_xml_move(xml, dest, off) switch_xml_insert(switch_xml_cut(xml), dest, off)
#define switch_xml_name(xml) ((xml) ? xml->name : NULL)
#define switch_xml_new_d(name) switch_xml_set_flag(switch_xml_new(strdup(name)), SWITCH_XML_NAMEM)
#define switch_xml_next(xml) ((xml) ? xml->next : NULL)
#define switch_xml_parse_str_dup(x)  switch_xml_parse_str_dynamic(x, SWITCH_TRUE)
#define switch_xml_remove(xml) switch_xml_free(switch_xml_cut(xml))
#define switch_xml_set_attr_d(xml, name, value) \
    switch_xml_set_attr(switch_xml_set_flag(xml, SWITCH_XML_DUP), strdup(name), strdup(switch_str_nil(value)))
#define switch_xml_set_attr_d_buf(xml, name, value) \
    switch_xml_set_attr(switch_xml_set_flag(xml, SWITCH_XML_DUP), strdup(name), strdup(value))
#define switch_xml_set_txt_d(xml, txt) \
    switch_xml_set_flag(switch_xml_set_txt(xml, strdup(txt)), SWITCH_XML_TXTM)
#define switch_xml_txt(xml) ((xml) ? xml->txt : "")

#define switch_log_check_mask(_mask, _level) (_mask & ((size_t)1 << _level))
#define MAX_CAND 50
#define SWITCH_RTCP_MAX_BUF_LEN 16384
#define SWITCH_RTP_CRYPTO_KEY_80 "AES_CM_128_HMAC_SHA1_80"

#define SWITCH_RTP_MAX_BUF_LEN 16384
#define SWITCH_RTP_MAX_BUF_LEN_WORDS 4094 
#define SWITCH_RTP_MAX_CRYPTO_LEN 64

#define SWITCH_IVR_VERIFY_SILENCE_DIVISOR(divisor) \
	{ \
		if ((divisor) <= 0 && (divisor) != -1) { \
			divisor = 400; \
		} \
	}
#define switch_ivr_phrase_macro(session, macro_name, data, lang, args) switch_ivr_phrase_macro_event(session, macro_name, data, NULL, lang, args)

#define SWITCH_RESAMPLE_QUALITY 2
#define switch_normalize_volume(x) if (x > 4) x = 4; if (x < -4) x = -4;
#define switch_normalize_volume_granular(x) if (x > 13) x = 13; if (x < -13) x = -13;
#define switch_resample_calc_buffer_size(_to, _from, _srclen) ((uint32_t)(((float)_to / (float)_from) * (float)_srclen) * 2)
#define switch_resample_create(_n, _fr, _tr, _ts, _q, _c) switch_resample_perform_create(_n, _fr, _tr, _ts, _q, _c, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define NO_EVENT_CHANNEL_ID 0
#define SWITCH_EVENT_CHANNEL_GLOBAL "__global__"

#define SWITCH_EVENT_SUBCLASS_ANY NULL
#define switch_event_create(event, id) switch_event_create_subclass(event, id, SWITCH_EVENT_SUBCLASS_ANY)
#define switch_event_create_pres_in(event) switch_event_create_pres_in_detailed("__FILE__", (const char * )__SWITCH_FUNC__, "__LINE__", \
											proto, login, from, from_domain, status, event_type, alt_event_type, event_count, \
											unique_id, channel_state, answer_state, call_direction)
#define switch_event_create_subclass(_e, _eid, _sn) switch_event_create_subclass_detailed("__FILE__", (const char * )__SWITCH_FUNC__, "__LINE__", _e, _eid, _sn)
#define switch_event_del_header(_e, _h) switch_event_del_header_val(_e, _h, NULL)
#define switch_event_expand_headers(_event, _in) switch_event_expand_headers_check(_event, _in, NULL, NULL, 0)
#define switch_event_fire(event) switch_event_fire_detailed("__FILE__", (const char * )__SWITCH_FUNC__, "__LINE__", event, NULL)
#define switch_event_fire_data(event, data) switch_event_fire_detailed("__FILE__", (const char * )__SWITCH_FUNC__, "__LINE__", event, data)
#define switch_event_free_subclass(subclass_name) switch_event_free_subclass_detailed("__FILE__", subclass_name)
#define switch_event_get_header(_e, _h) switch_event_get_header_idx(_e, _h, -1)
#define switch_event_get_header_nil(e, h) switch_str_nil(switch_event_get_header(e,h))
#define switch_event_prep_for_delivery(_event) switch_event_prep_for_delivery_detailed("__FILE__", (const char * )__SWITCH_FUNC__, "__LINE__", _event)
#define switch_event_reserve_subclass(subclass_name) switch_event_reserve_subclass_detailed("__FILE__", subclass_name)
#define switch_event_safe_destroy(_event) if (_event) switch_event_destroy(_event)


#define switch_channel_answer(channel) switch_channel_perform_answer(channel, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_audio_sync(_c)  switch_channel_perform_audio_sync(_c, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_clear_app_flag(_c, _f) switch_channel_clear_app_flag_key("__FILE__", _c, _f)
#define switch_channel_down(_channel) (switch_channel_check_signal(_channel, SWITCH_TRUE) || switch_channel_get_state(_channel) >= CS_HANGUP)
#define switch_channel_down_nosig(_channel) (switch_channel_get_state(_channel) >= CS_HANGUP)
#define switch_channel_expand_variables(_channel, _in) switch_channel_expand_variables_check(_channel, _in, NULL, NULL, 0)
#define switch_channel_export_variable(_channel, _varname, _value, _ev) switch_channel_export_variable_var_check(_channel, _varname, _value, _ev, SWITCH_TRUE)
#define switch_channel_get_variable(_c, _v) switch_channel_get_variable_dup(_c, _v, SWITCH_TRUE, -1)
#define switch_channel_hangup(channel, hangup_cause) switch_channel_perform_hangup(channel, "__FILE__", __SWITCH_FUNC__, "__LINE__", hangup_cause)
#define switch_channel_inbound_display(_channel) ((switch_channel_direction(_channel) == SWITCH_CALL_DIRECTION_INBOUND && !switch_channel_test_flag(_channel, CF_BLEG)) || (switch_channel_direction(_channel) == SWITCH_CALL_DIRECTION_OUTBOUND && switch_channel_test_flag(_channel, CF_DIALPLAN)))
#define switch_channel_mark_answered(channel) switch_channel_perform_mark_answered(channel, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_mark_pre_answered(channel) switch_channel_perform_mark_pre_answered(channel, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_mark_ring_ready(channel) \
	switch_channel_perform_mark_ring_ready_value(channel, SWITCH_RING_READY_RINGING, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_mark_ring_ready_value(channel, _rv)					\
	switch_channel_perform_mark_ring_ready_value(channel, _rv, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_media_ack(_channel) (!switch_channel_test_cap(_channel, CC_MEDIA_ACK) || switch_channel_test_flag(_channel, CF_MEDIA_ACK))
#define switch_channel_media_ready(_channel) switch_channel_test_ready(_channel, SWITCH_TRUE, SWITCH_TRUE)
#define switch_channel_media_up(_channel) (switch_channel_test_flag(_channel, CF_ANSWERED) || switch_channel_test_flag(_channel, CF_EARLY_MEDIA))
#define switch_channel_outbound_display(_channel) ((switch_channel_direction(_channel) == SWITCH_CALL_DIRECTION_INBOUND && switch_channel_test_flag(_channel, CF_BLEG)) || (switch_channel_direction(_channel) == SWITCH_CALL_DIRECTION_OUTBOUND && !switch_channel_test_flag(_channel, CF_DIALPLAN)))
#define switch_channel_pre_answer(channel) switch_channel_perform_pre_answer(channel, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_presence(_a, _b, _c, _d) switch_channel_perform_presence(_a, _b, _c, _d, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_ready(_channel) switch_channel_test_ready(_channel, SWITCH_TRUE, SWITCH_FALSE)
#define switch_channel_ring_ready(channel) switch_channel_perform_ring_ready_value(channel, SWITCH_RING_READY_RINGING, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_ring_ready_value(channel, _rv)					\
	switch_channel_perform_ring_ready_value(channel, _rv, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_set_app_flag(_c, _f) switch_channel_set_app_flag_key("__FILE__", _c, _f)
#define switch_channel_set_callstate(channel, state) switch_channel_perform_set_callstate(channel, state, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_set_cap(_c, _cc) switch_channel_set_cap_value(_c, _cc, 1)
#define switch_channel_set_flag(_c, _f) switch_channel_set_flag_value(_c, _f, 1)
#define switch_channel_set_running_state(channel, state) switch_channel_perform_set_running_state(channel, state, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_channel_set_state(channel, state) switch_channel_perform_set_state(channel, "__FILE__", __SWITCH_FUNC__, "__LINE__", state)
#define switch_channel_set_variable(_channel, _var, _val) switch_channel_set_variable_var_check(_channel, _var, _val, SWITCH_TRUE)
#define switch_channel_set_variable_partner(_channel, _var, _val) switch_channel_set_variable_partner_var_check(_channel, _var, _val, SWITCH_TRUE)
#define switch_channel_set_variable_safe(_channel, _var, _val) switch_channel_set_variable_var_check(_channel, _var, _val, SWITCH_FALSE)
#define switch_channel_stop_broadcast(_channel)	for(;;) {if (switch_channel_test_flag(_channel, CF_BROADCAST)) {switch_channel_set_flag(_channel, CF_STOP_BROADCAST); switch_channel_set_flag(_channel, CF_BREAK); } break;}
#define switch_channel_test_app_flag(_c, _f) switch_channel_test_app_flag_key("__FILE__", _c, _f)
#define switch_channel_up(_channel) (switch_channel_check_signal(_channel, SWITCH_TRUE) || switch_channel_get_state(_channel) < CS_HANGUP)
#define switch_channel_up_nosig(_channel) (switch_channel_get_state(_channel) < CS_HANGUP)
#define switch_channel_video_sync(_c)  switch_channel_perform_video_sync(_c, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define PROTECT_INTERFACE(_it) if (_it) {switch_mutex_lock(_it->reflock); switch_thread_rwlock_rdlock(_it->parent->rwlock); switch_thread_rwlock_rdlock(_it->rwlock); _it->refs++; _it->parent->refs++; switch_mutex_unlock(_it->reflock);}	

#define UNPROTECT_INTERFACE(_it) if (_it) {switch_mutex_lock(_it->reflock); switch_thread_rwlock_unlock(_it->rwlock); switch_thread_rwlock_unlock(_it->parent->rwlock); _it->refs--; _it->parent->refs--; switch_mutex_unlock(_it->reflock);}	

#define MAX_REPORT_BLOCKS 5


#define profile_dup(a,b,p) if (!zstr(a)) { b = switch_core_strdup(p, a); } else { b = SWITCH_BLANK_STRING; }
#define profile_dup_clean(a,b,p) if (!zstr(a)) { b = switch_var_clean_string(switch_clean_string(switch_core_strdup(p, a)));} else { b = SWITCH_BLANK_STRING; }
#define DUMP_EVENT(_e) 	{char *event_str;switch_event_serialize(_e, &event_str, SWITCH_FALSE);switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "DUMP\n%s\n", event_str);free(event_str);}
#define SWITCH_DECLARE_GLOBAL_STRING_FUNC(fname, vname) static void fname(const char *string) { if (!string) return;\
		if (vname) {free(vname); vname = NULL;}vname = strdup(string);} static void fname(const char *string)
#define SWITCH_READ_ACCEPTABLE(status) (status == SWITCH_STATUS_SUCCESS || status == SWITCH_STATUS_BREAK || status == SWITCH_STATUS_INUSE)
#define SWITCH_SMAX 32767
#define SWITCH_SMIN -32768
#define SWITCH_STATUS_IS_BREAK(x) (x == SWITCH_STATUS_BREAK || x == 730035 || x == 35 || x == SWITCH_STATUS_INTR)
#define SWITCH_URL_UNSAFE "\r\n #%&+:;<=>?@[\\]^`{|}\""

#define end_of(_s) *(*_s == '\0' ? _s : _s + strlen(_s) - 1)
#define end_of_p(_s) (*_s == '\0' ? _s : _s + strlen(_s) - 1)
#define is_dtmf(key)  ((key > 47 && key < 58) || (key > 64 && key < 69) || (key > 96 && key < 101) || key == 35 || key == 42 || key == 87 || key == 119 || key == 70 || key == 102)
#define switch_arraylen(_a) (sizeof(_a) / sizeof(_a[0]))
#define switch_clear_flag(obj, flag) (obj)->flags &= ~(flag)
#define switch_clear_flag_locked(obj, flag) switch_mutex_lock(obj->flag_mutex); (obj)->flags &= ~(flag); switch_mutex_unlock(obj->flag_mutex);
#define switch_codec2str(codec,buf,len) snprintf(buf, len, "%s@%uh@%ui", \
                                                 codec->implementation->iananame, \
                                                 codec->implementation->samples_per_second, \
                                                 codec->implementation->microseconds_per_packet / 1000)
#define switch_copy_flags(dest, src, flags) (dest)->flags &= ~(flags);	(dest)->flags |= ((src)->flags & (flags))
#define switch_errno() WSAGetLastError()
#define switch_goto_int(_n, _i, _label) _n = _i; goto _label
#define switch_goto_status(_status, _label) status = _status; goto _label
#define switch_inet_ntop inet_ntop
#define switch_is_valid_rate(_tmp) (_tmp == 8000 || _tmp == 12000 || _tmp == 16000 || _tmp == 24000 || _tmp == 32000 || _tmp == 11025 || _tmp == 22050 || _tmp == 44100 || _tmp == 48000)
#define switch_malloc(ptr, len) (void)( (!!(ptr = malloc(len))) || (fprintf(stderr,"ABORT! Malloc failure at: %s:%d", "__FILE__", "__LINE__"),abort(), 0), ptr )
#define switch_network_list_add_cidr(_list, _cidr_str, _ok) switch_network_list_add_cidr_token(_list, _cidr_str, _ok, NULL)
#define switch_network_list_validate_ip(_list, _ip) switch_network_list_validate_ip_token(_list, _ip, NULL);
#define switch_normalize_to_16bit(n) if (n > SWITCH_SMAX) n = SWITCH_SMAX; else if (n < SWITCH_SMIN) n = SWITCH_SMIN;
#define switch_safe_free(it) if (it) {free(it);it=NULL;}
#define switch_samples_per_packet(rate, interval) ((uint32_t)((float)rate / (1000.0f / (float)interval)))
#define switch_set_flag(obj, flag) (obj)->flags |= (flag)
#define switch_set_flag_locked(obj, flag) assert(obj->flag_mutex != NULL);\
switch_mutex_lock(obj->flag_mutex);\
(obj)->flags |= (flag);\
switch_mutex_unlock(obj->flag_mutex);
#define switch_set_string(_dst, _src) switch_copy_string(_dst, _src, sizeof(_dst))
#define switch_split(_data, _delim, _array) switch_separate_string(_data, _delim, _array, switch_arraylen(_array))
#define switch_str_nil(s) (s ? s : "")
#define switch_strdup(ptr, s) (void)( (!!(ptr = _strdup(s))) || (fprintf(stderr,"ABORT! Malloc failure at: %s:%d", "__FILE__", "__LINE__"),abort(), 0), ptr)
#define switch_strlen_zero(x) zstr(x)
#define switch_strlen_zero_buf(x) zstr_buf(x)
#define switch_test_flag(obj, flag) ((obj)->flags & flag)
#define switch_test_subnet(_ip, _net, _mask) (_mask ? ((_net & _mask) == (_ip & _mask)) : _net ? _net == _ip : 1)
#define switch_time_from_sec(sec)   ((switch_time_t)(sec) * 1000000)
#define switch_true_buf(expr)\
((( !strcasecmp(expr, "yes") ||\
!strcasecmp(expr, "on") ||\
!strcasecmp(expr, "true") ||\
!strcasecmp(expr, "t") ||\
!strcasecmp(expr, "enabled") ||\
!strcasecmp(expr, "active") ||\
!strcasecmp(expr, "allow") ||\
(switch_is_number(expr) && atoi(expr)))) ? SWITCH_TRUE : SWITCH_FALSE)
#define switch_yield(ms) switch_sleep(ms);
#define switch_zmalloc(ptr, len) (void)( (!!(ptr = calloc(1, (len)))) || (fprintf(stderr,"ABORT! Malloc failure at: %s:%d", "__FILE__", "__LINE__"),abort(), 0), ptr)
#define zset(_a, _b) if (!zstr(_b)) _a = _b
#define zstr(x) (_zstr(x) ? 1 : __analysis_assume(x),0)
#define zstr_buf(s) (*(s) == '\0')
#define SWITCH_CMD_CHUNK_LEN 1024

#define SWITCH_STANDARD_STREAM(s) memset(&s, 0, sizeof(s)); s.data = malloc(SWITCH_CMD_CHUNK_LEN); \
	switch_assert(s.data);												\
	memset(s.data, 0, SWITCH_CMD_CHUNK_LEN);							\
	s.end = s.data;														\
	s.data_size = SWITCH_CMD_CHUNK_LEN;									\
	s.write_function = switch_console_stream_write;						\
	s.raw_write_function = switch_console_stream_raw_write;				\
	s.alloc_len = SWITCH_CMD_CHUNK_LEN;									\
	s.alloc_chunk = SWITCH_CMD_CHUNK_LEN
#define SWITCH_ADD_API(api_int, int_name, descript, funcptr, syntax_string) \
	for (;;) { \
	api_int = (switch_api_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_API_INTERFACE); \
	api_int->interface_name = int_name; \
	api_int->desc = descript; \
	api_int->function = funcptr; \
	api_int->syntax = syntax_string; \
	break; \
	}
#define SWITCH_ADD_APP(app_int, int_name, short_descript, long_descript, funcptr, syntax_string, app_flags) \
	for (;;) { \
	app_int = (switch_application_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_APPLICATION_INTERFACE); \
	app_int->interface_name = int_name; \
	app_int->application_function = funcptr; \
	app_int->short_desc = short_descript; \
	app_int->long_desc = long_descript; \
	app_int->syntax = syntax_string; \
	app_int->flags = app_flags; \
	break; \
	}
#define SWITCH_ADD_CHAT(chat_int, int_name, funcptr) \
	for (;;) { \
	chat_int = (switch_chat_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_CHAT_INTERFACE); \
	chat_int->chat_send = funcptr; \
	chat_int->interface_name = int_name; \
	break; \
	}
#define SWITCH_ADD_CHAT_APP(app_int, int_name, short_descript, long_descript, funcptr, syntax_string, app_flags) \
	for (;;) { \
	app_int = (switch_chat_application_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_CHAT_APPLICATION_INTERFACE); \
	app_int->interface_name = int_name; \
	app_int->chat_application_function = funcptr; \
	app_int->short_desc = short_descript; \
	app_int->long_desc = long_descript; \
	app_int->syntax = syntax_string; \
	app_int->flags = app_flags; \
	break; \
	}
#define SWITCH_ADD_CODEC(codec_int, int_name) \
	for (;;) { \
		codec_int = (switch_codec_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_CODEC_INTERFACE); \
		codec_int->modname = switch_core_strdup(pool, (*module_interface)->module_name);	\
		codec_int->interface_name = switch_core_strdup(pool, int_name);	\
		codec_int->codec_id = switch_core_codec_next_id();				\
		break;															\
	}
#define SWITCH_ADD_DIALPLAN(dp_int, int_name, funcptr) \
	for (;;) { \
	dp_int = (switch_dialplan_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_DIALPLAN_INTERFACE); \
	dp_int->hunt_function = funcptr; \
	dp_int->interface_name = int_name; \
	break; \
	}
#define SWITCH_ADD_JSON_API(json_api_int, int_name, descript, funcptr, syntax_string) \
	for (;;) { \
	json_api_int = (switch_json_api_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_JSON_API_INTERFACE); \
	json_api_int->interface_name = int_name; \
	json_api_int->desc = descript; \
	json_api_int->function = funcptr; \
	json_api_int->syntax = syntax_string; \
	break; \
	}
#define SWITCH_ADD_LIMIT(limit_int, int_name, incrptr, releaseptr, usageptr, resetptr, statusptr, interval_resetptr) \
	for (;;) { \
	limit_int = (switch_limit_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_LIMIT_INTERFACE); \
	limit_int->incr = incrptr; \
	limit_int->release = releaseptr; \
	limit_int->usage = usageptr; \
	limit_int->reset = resetptr; \
	limit_int->interval_reset = interval_resetptr; \
	limit_int->status = statusptr; \
	limit_int->interface_name = int_name; \
	break; \
	}
#define SWITCH_DECLARE_STATIC_MODULE(init, load, run, shut) void init(void) { \
		switch_loadable_module_build_dynamic("__FILE__", load, run, shut, SWITCH_FALSE); \
	}

#define CACHE_DB_LEN 256
#define DTLS_SRTP_FNAME "dtls-srtp"
#define MAX_FPLEN 64
#define MAX_FPSTRLEN 192
#define MESSAGE_STAMP_FFL(_m) _m->_file = "__FILE__"; _m->_func = __SWITCH_FUNC__; _m->_line = "__LINE__"
#define MESSAGE_STRING_ARG_MAX 10

#define SWITCH_MAX_CORE_THREAD_SESSION_OBJS 128
#define SWITCH_MAX_STREAMS 128
#define switch_cache_db_get_db_handle(_a, _b, _c) _switch_cache_db_get_db_handle(_a, _b, _c, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_cache_db_get_db_handle_dsn(_a, _b) _switch_cache_db_get_db_handle_dsn(_a, _b, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_cache_db_persistant_execute_trans(_d, _s, _r) switch_cache_db_persistant_execute_trans_full(_d, _s, _r, NULL, NULL, NULL, NULL)
#define switch_check_network_list_ip(_ip_str, _list_name) switch_check_network_list_ip_token(_ip_str, _list_name, NULL)
#define switch_core_alloc(_pool, _mem) switch_core_perform_alloc(_pool, _mem, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_codec_init(_codec, _codec_name, _modname, _fmtp, _rate, _ms, _channels, _flags, _codec_settings, _pool) \
	switch_core_codec_init_with_bitrate(_codec, _codec_name, _modname, _fmtp, _rate, _ms, _channels, 0, _flags, _codec_settings, _pool)
#define switch_core_db_handle(_a) _switch_core_db_handle(_a, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_destroy_memory_pool(p) switch_core_perform_destroy_memory_pool(p, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_file_open(_fh, _file_path, _channels, _rate, _flags, _pool) \
	switch_core_perform_file_open("__FILE__", __SWITCH_FUNC__, "__LINE__", _fh, _file_path, _channels, _rate, _flags, _pool)
#define switch_core_hash_first(_h) switch_core_hash_first_iter(_h, NULL)
#define switch_core_hash_init(_hash) switch_core_hash_init_case(_hash, SWITCH_TRUE)
#define switch_core_hash_init_nocase(_hash) switch_core_hash_init_case(_hash, SWITCH_FALSE)
#define switch_core_hash_insert(_h, _k, _d) switch_core_hash_insert_destructor(_h, _k, _d, NULL)
#define switch_core_media_bug_remove_all(_s) switch_core_media_bug_remove_all_function(_s, NULL)
#define switch_core_new_memory_pool(p) switch_core_perform_new_memory_pool(p, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_permanent_alloc(_memory) switch_core_perform_permanent_alloc(_memory, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_permanent_strdup(_todup) switch_core_perform_permanent_strdup(_todup, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_service_session(_s) switch_core_service_session_av(_s, SWITCH_TRUE, SWITCH_FALSE)
#define switch_core_session_alloc(_session, _memory) switch_core_perform_session_alloc(_session, _memory, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_destroy(session) switch_core_session_perform_destroy(session, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_execute_application(_a, _b, _c) switch_core_session_execute_application_get_flags(_a, _b, _c, NULL)
#define switch_core_session_force_locate(uuid_str) switch_core_session_perform_force_locate(uuid_str, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_get_name(_s) switch_channel_get_name(switch_core_session_get_channel(_s))
#define switch_core_session_get_partner(_session, _partner) switch_core_session_perform_get_partner(_session, _partner, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_get_private(_s) switch_core_session_get_private_class(_s, SWITCH_PVT_PRIMARY)
#define switch_core_session_hupall_matching_var(_vn, _vv, _c) switch_core_session_hupall_matching_var_ans(_vn, _vv, _c, SHT_UNANSWERED | SHT_ANSWERED)
#define switch_core_session_kill_channel(session, sig) switch_core_session_perform_kill_channel(session, "__FILE__", __SWITCH_FUNC__, "__LINE__", sig)
#define switch_core_session_locate(uuid_str) switch_core_session_perform_locate(uuid_str, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_read_lock(session) switch_core_session_perform_read_lock(session, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_read_lock_hangup(session) switch_core_session_perform_read_lock_hangup(session, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_receive_message(_session, _message) switch_core_session_perform_receive_message(_session, _message, \
																											"__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_request(_ep, _d, _f, _p) switch_core_session_request_uuid(_ep, _d, _f, _p, NULL)
#define switch_core_session_rwunlock(session) switch_core_session_perform_rwunlock(session, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_set_private(_s, _p) switch_core_session_set_private_class(_s, _p, SWITCH_PVT_PRIMARY)
#define switch_core_session_strdup(_session, _todup) switch_core_perform_session_strdup(_session, _todup, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_session_write_lock(session) switch_core_session_perform_write_lock(session, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_core_strdup(_pool, _todup)  switch_core_perform_strdup(_pool, _todup, "__FILE__", __SWITCH_FUNC__, "__LINE__")
#define switch_sql_queue_manager_init(_q, _n, _d, _m, _p1, _p2, _ip1, _ip2) switch_sql_queue_manager_init_name("__FILE__", _q, _n, _d, _m, _p1, _p2, _ip1, _ip2)

#define switch_regex_safe_free(re)	if (re) {\
				switch_regex_free(re);\
				re = NULL;\
			}

#define SWITCH_CORE_DB_ABORT        4	
#define SWITCH_CORE_DB_AUTH        23	
#define SWITCH_CORE_DB_BUSY         5	
#define SWITCH_CORE_DB_CANTOPEN    14	
#define SWITCH_CORE_DB_CONSTRAINT  19	
#define SWITCH_CORE_DB_CORRUPT     11	
#define SWITCH_CORE_DB_DONE        101	
#define SWITCH_CORE_DB_EMPTY       16	
#define SWITCH_CORE_DB_ERROR        1	
#define SWITCH_CORE_DB_FORMAT      24	
#define SWITCH_CORE_DB_FULL        13	

#define SWITCH_CORE_DB_INTERNAL     2	
#define SWITCH_CORE_DB_INTERRUPT    9	
#define SWITCH_CORE_DB_IOERR       10	
#define SWITCH_CORE_DB_LOCKED       6	
#define SWITCH_CORE_DB_MISMATCH    20	
#define SWITCH_CORE_DB_MISUSE      21	
#define SWITCH_CORE_DB_NOLFS       22	
#define SWITCH_CORE_DB_NOMEM        7	
#define SWITCH_CORE_DB_NOTADB      26	
#define SWITCH_CORE_DB_NOTFOUND    12	
#define SWITCH_CORE_DB_OK           0	
#define SWITCH_CORE_DB_PERM         3	
#define SWITCH_CORE_DB_PROTOCOL    15	
#define SWITCH_CORE_DB_RANGE       25	
#define SWITCH_CORE_DB_READONLY     8	
#define SWITCH_CORE_DB_ROW         100	
#define SWITCH_CORE_DB_SCHEMA      17	
#define SWITCH_CORE_DB_STATIC      ((switch_core_db_destructor_type_t)0)
#define SWITCH_CORE_DB_TOOBIG      18	
#define SWITCH_CORE_DB_TRANSIENT   ((switch_core_db_destructor_type_t)-1)


#define SWITCH_FLOCK_EXCLUSIVE     2	   
#define SWITCH_FLOCK_NONBLOCK      0x0010  
#define SWITCH_FLOCK_SHARED        1	   
#define SWITCH_FLOCK_TYPEMASK      0x000F  
#define SWITCH_FPROT_FILE_SOURCE_PERMS 0x1000	
#define SWITCH_FPROT_GEXECUTE 0x0010		
#define SWITCH_FPROT_GREAD 0x0040			
#define SWITCH_FPROT_GSETID 0x4000			
#define SWITCH_FPROT_GWRITE 0x0020			
#define SWITCH_FPROT_OS_DEFAULT 0x0FFF		
#define SWITCH_FPROT_UEXECUTE 0x0100		
#define SWITCH_FPROT_UREAD 0x0400			
#define SWITCH_FPROT_USETID 0x8000			
#define SWITCH_FPROT_UWRITE 0x0200			
#define SWITCH_FPROT_WEXECUTE 0x0001		
#define SWITCH_FPROT_WREAD 0x0004			
#define SWITCH_FPROT_WSTICKY 0x2000
#define SWITCH_FPROT_WWRITE 0x0002			
#define SWITCH_INET     AF_INET
#define SWITCH_INET6    AF_INET6
#define SWITCH_MD5_DIGESTSIZE 16
#define SWITCH_MD5_DIGEST_STRING_SIZE 33
#define SWITCH_POLLERR 0x010			
#define SWITCH_POLLHUP 0x020			
#define SWITCH_POLLIN 0x001			
#define SWITCH_POLLNVAL 0x040		
#define SWITCH_POLLOUT 0x004			
#define SWITCH_POLLPRI 0x002			
#define SWITCH_PROTO_SCTP    132   
#define SWITCH_PROTO_TCP       6   
#define SWITCH_PROTO_UDP      17   
#define SWITCH_SEEK_CUR SEEK_CUR
#define SWITCH_SEEK_END SEEK_END
#define SWITCH_SEEK_SET SEEK_SET
#define SWITCH_SO_DEBUG 4
#define SWITCH_SO_DISCONNECTED 256
#define SWITCH_SO_KEEPALIVE 2
#define SWITCH_SO_LINGER 1
#define SWITCH_SO_NONBLOCK 8
#define SWITCH_SO_RCVBUF 128
#define SWITCH_SO_REUSEADDR 16
#define SWITCH_SO_SNDBUF 64
#define SWITCH_SO_TCP_KEEPIDLE 520
#define SWITCH_SO_TCP_KEEPINTVL 530
#define SWITCH_SO_TCP_NODELAY 512
#define SWITCH_UNSPEC   AF_UNSPEC
#define SWITCH_UUID_FORMATTED_LENGTH 256
#define DMACHINE_MAX_DIGIT_LEN 512
#define IPDV_THRESHOLD 1.0
#define JITTER_VARIANCE_THRESHOLD 400.0
#define LOST_BURST_ANALYZE 500
#define LOST_BURST_CAPTURE 1024
#define MAX_ARG_RECURSION 25
#define SWITCH_ACCEPTABLE_INTERVAL(_i) (_i && _i <= SWITCH_MAX_INTERVAL && (_i % 10) == 0)
#define SWITCH_ADVERTISED_MEDIA_IP_VARIABLE "advertised_media_ip"
#define SWITCH_API_BRIDGE_END_VARIABLE "api_after_bridge"
#define SWITCH_API_BRIDGE_START_VARIABLE "api_before_bridge"
#define SWITCH_API_HANGUP_HOOK_VARIABLE "api_hangup_hook"
#define SWITCH_API_REPORTING_HOOK_VARIABLE "api_reporting_hook"
#define SWITCH_API_VERSION 5
#define SWITCH_ATT_XFER_RESULT_VARIABLE "att_xfer_result"
#define SWITCH_AUDIO_SPOOL_PATH_VARIABLE "audio_spool_path"
#define SWITCH_BITS_PER_BYTE 8
#define SWITCH_BLANK_STRING ""
#define SWITCH_BRIDGE_CHANNEL_VARIABLE "bridge_channel"
#define SWITCH_BRIDGE_EXPORT_VARS_VARIABLE "bridge_export_vars"
#define SWITCH_BRIDGE_HANGUP_CAUSE_VARIABLE "bridge_hangup_cause"
#define SWITCH_BRIDGE_UUID_VARIABLE "bridge_uuid"
#define SWITCH_BRIDGE_VARIABLE "bridge_to"
#define SWITCH_BYPASS_MEDIA_AFTER_BRIDGE_VARIABLE "bypass_media_after_bridge"
#define SWITCH_BYPASS_MEDIA_VARIABLE "bypass_media"
#define SWITCH_BYTES_PER_SAMPLE 2	
#define SWITCH_B_SDP_VARIABLE "switch_m_sdp"
#define SWITCH_CACHE_SPEECH_HANDLES_OBJ_NAME "__cache_speech_handles_obj__"
#define SWITCH_CACHE_SPEECH_HANDLES_VARIABLE "cache_speech_handles"
#define SWITCH_CALL_TIMEOUT_VARIABLE "call_timeout"
#define SWITCH_CHANNEL_API_ON_ANSWER_VARIABLE "api_on_answer"
#define SWITCH_CHANNEL_API_ON_MEDIA_VARIABLE "api_on_media"
#define SWITCH_CHANNEL_API_ON_ORIGINATE_VARIABLE "api_on_originate"
#define SWITCH_CHANNEL_API_ON_POST_ORIGINATE_VARIABLE "api_on_post_originate"
#define SWITCH_CHANNEL_API_ON_PRE_ANSWER_VARIABLE "api_on_pre_answer"
#define SWITCH_CHANNEL_API_ON_PRE_ORIGINATE_VARIABLE "api_on_pre_originate"
#define SWITCH_CHANNEL_API_ON_RING_VARIABLE "api_on_ring"
#define SWITCH_CHANNEL_API_ON_TONE_DETECT_VARIABLE "api_on_tone_detect"
#define SWITCH_CHANNEL_CHANNEL_LOG(x) SWITCH_CHANNEL_ID_SESSION, "__FILE__", __SWITCH_FUNC__, "__LINE__", (const char*)switch_channel_get_session(x)
#define SWITCH_CHANNEL_EVENT SWITCH_CHANNEL_ID_EVENT, "__FILE__", __SWITCH_FUNC__, "__LINE__", NULL
#define SWITCH_CHANNEL_EXECUTE_ON_ANSWER_VARIABLE "execute_on_answer"
#define SWITCH_CHANNEL_EXECUTE_ON_MEDIA_VARIABLE "execute_on_media"
#define SWITCH_CHANNEL_EXECUTE_ON_ORIGINATE_VARIABLE "execute_on_originate"
#define SWITCH_CHANNEL_EXECUTE_ON_POST_BRIDGE_VARIABLE "execute_on_post_bridge"
#define SWITCH_CHANNEL_EXECUTE_ON_POST_ORIGINATE_VARIABLE "execute_on_post_originate"
#define SWITCH_CHANNEL_EXECUTE_ON_PRE_ANSWER_VARIABLE "execute_on_pre_answer"
#define SWITCH_CHANNEL_EXECUTE_ON_PRE_BRIDGE_VARIABLE "execute_on_pre_bridge"
#define SWITCH_CHANNEL_EXECUTE_ON_PRE_ORIGINATE_VARIABLE "execute_on_pre_originate"
#define SWITCH_CHANNEL_EXECUTE_ON_RING_VARIABLE "execute_on_ring"
#define SWITCH_CHANNEL_EXECUTE_ON_TONE_DETECT_VARIABLE "execute_on_tone_detect"
#define SWITCH_CHANNEL_LOG SWITCH_CHANNEL_ID_LOG, "__FILE__", __SWITCH_FUNC__, "__LINE__", NULL
#define SWITCH_CHANNEL_LOG_CLEAN SWITCH_CHANNEL_ID_LOG_CLEAN, "__FILE__", __SWITCH_FUNC__, "__LINE__", NULL
#define SWITCH_CHANNEL_NAME_VARIABLE "channel_name"
#define SWITCH_CHANNEL_SESSION_LOG(x) SWITCH_CHANNEL_ID_SESSION, "__FILE__", __SWITCH_FUNC__, "__LINE__", (const char*)(x)
#define SWITCH_CHANNEL_SESSION_LOG_CLEAN(x) SWITCH_CHANNEL_ID_LOG_CLEAN, "__FILE__", __SWITCH_FUNC__, "__LINE__", switch_core_session_get_uuid((x))
#define SWITCH_CHANNEL_UUID_LOG(x) SWITCH_CHANNEL_ID_LOG, "__FILE__", __SWITCH_FUNC__, "__LINE__", (x)
#define SWITCH_CONTINUE_ON_FAILURE_VARIABLE "continue_on_fail"
#define SWITCH_COPY_JSON_CDR_VARIABLE "copy_json_cdr"
#define SWITCH_COPY_XML_CDR_VARIABLE "copy_xml_cdr"
#define SWITCH_CORE_QUEUE_LEN 100000
#define SWITCH_CORE_SESSION_MAX_PRIVATES 2
#define SWITCH_CURRENT_APPLICATION_DATA_VARIABLE "current_application_data"
#define SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE "current_application_response"
#define SWITCH_CURRENT_APPLICATION_VARIABLE "current_application"
#define SWITCH_DEFAULT_CLID_NAME ""
#define SWITCH_DEFAULT_CLID_NUMBER "0000000000"
#define SWITCH_DEFAULT_DIR_PERMS SWITCH_FPROT_UREAD | SWITCH_FPROT_UWRITE | SWITCH_FPROT_UEXECUTE | SWITCH_FPROT_GREAD | SWITCH_FPROT_GEXECUTE
#define SWITCH_DEFAULT_DTMF_DURATION 2000
#define SWITCH_DEFAULT_FILE_BUFFER_LEN 65536
#define SWITCH_DEFAULT_VIDEO_SIZE 1200
#define SWITCH_DISABLE_APP_LOG_VARIABLE "disable_app_log"
#define SWITCH_DTMF_LOG_LEN 1000
#define SWITCH_ENABLE_HEARTBEAT_EVENTS_VARIABLE "enable_heartbeat_events"
#define SWITCH_ENDPOINT_DISPOSITION_VARIABLE "endpoint_disposition"
#define SWITCH_ENT_ORIGINATE_DELIM ":_:"
#define SWITCH_EXEC_AFTER_BRIDGE_APP_VARIABLE "exec_after_bridge_app"
#define SWITCH_EXEC_AFTER_BRIDGE_ARG_VARIABLE "exec_after_bridge_arg"
#define SWITCH_EXPORT_VARS_VARIABLE "export_vars"
#define SWITCH_FORCE_PROCESS_CDR_VARIABLE "force_process_cdr"
#define SWITCH_HANGUP_AFTER_BRIDGE_VARIABLE "hangup_after_bridge"
#define SWITCH_HASH_DELETE_FUNC(name) static switch_bool_t name (const void *key, const void *val, void *pData)
#define SWITCH_HOLDING_UUID_VARIABLE "holding_uuid"
#define SWITCH_HOLD_MUSIC_VARIABLE "hold_music"
#define SWITCH_IGNORE_DISPLAY_UPDATES_VARIABLE "ignore_display_updates"
#define SWITCH_INTERVAL_PAD 10	
#define SWITCH_LAST_BRIDGE_VARIABLE "last_bridge_to"
#define SWITCH_LOCAL_MEDIA_IP_VARIABLE "local_media_ip"
#define SWITCH_LOCAL_MEDIA_PORT_VARIABLE "local_media_port"
#define SWITCH_LOCAL_VIDEO_IP_VARIABLE "local_video_ip"
#define SWITCH_LOCAL_VIDEO_PORT_VARIABLE "local_video_port"
#define SWITCH_L_SDP_VARIABLE "switch_l_sdp"
#define SWITCH_MAX_CODECS 50
#define SWITCH_MAX_DTMF_DURATION 192000
#define SWITCH_MAX_FORWARDS_VARIABLE "max_forwards"
#define SWITCH_MAX_INTERVAL 120	
#define SWITCH_MAX_MANAGEMENT_BUFFER_LEN 1024 * 8
#define SWITCH_MAX_SAMPLE_LEN 48
#define SWITCH_MAX_SESSION_TRANSFERS_VARIABLE "max_session_transfers"
#define SWITCH_MAX_STACKS 16
#define SWITCH_MAX_STATE_HANDLERS 30
#define SWITCH_MAX_TRANS 2000
#define SWITCH_MEDIA_TYPE_TOTAL 2
#define SWITCH_MIN_DTMF_DURATION 400
#define SWITCH_MODULE_DEFINITION(name, load, shutdown, runtime)								\
		SWITCH_MODULE_DEFINITION_EX(name, load, shutdown, runtime, SMODF_NONE)
#define SWITCH_MODULE_DEFINITION_EX(name, load, shutdown, runtime, flags)					\
static const char modname[] =  #name ;														\
SWITCH_MOD_DECLARE_DATA switch_loadable_module_function_table_t name##_module_interface = {	\
	SWITCH_API_VERSION,																		\
	load,																					\
	shutdown,																				\
	runtime,																				\
	flags																					\
}
#define SWITCH_MODULE_LOAD_ARGS (switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool)
#define SWITCH_MODULE_LOAD_FUNCTION(name) switch_status_t name SWITCH_MODULE_LOAD_ARGS
#define SWITCH_MODULE_RUNTIME_ARGS (void)
#define SWITCH_MODULE_RUNTIME_FUNCTION(name) switch_status_t name SWITCH_MODULE_RUNTIME_ARGS
#define SWITCH_MODULE_SHUTDOWN_ARGS (void)
#define SWITCH_MODULE_SHUTDOWN_FUNCTION(name) switch_status_t name SWITCH_MODULE_SHUTDOWN_ARGS
#define SWITCH_NUMPLAN_UNDEF 255
#define SWITCH_ORIGINATE_SIGNAL_BOND_VARIABLE "originate_signal_bond"
#define SWITCH_ORIGINATOR_CODEC_VARIABLE "originator_codec"
#define SWITCH_ORIGINATOR_VARIABLE "originator"
#define SWITCH_ORIGINATOR_VIDEO_CODEC_VARIABLE "originator_video_codec"
#define SWITCH_PARK_AFTER_BRIDGE_VARIABLE "park_after_bridge"
#define SWITCH_PASSTHRU_PTIME_MISMATCH_VARIABLE "passthru_ptime_mismatch"
#define SWITCH_PATH_SEPARATOR "/"
#define SWITCH_PLAYBACK_TERMINATORS_VARIABLE "playback_terminators"
#define SWITCH_PLAYBACK_TERMINATOR_USED "playback_terminator_used"
#define SWITCH_PROCESS_CDR_VARIABLE "process_cdr"
#define SWITCH_PROTO_SPECIFIC_HANGUP_CAUSE_VARIABLE "proto_specific_hangup_cause"
#define SWITCH_PROXY_MEDIA_VARIABLE "proxy_media"
#define SWITCH_READ_RESULT_VARIABLE "read_result"
#define SWITCH_READ_TERMINATOR_USED_VARIABLE "read_terminator_used"
#define SWITCH_RECOMMENDED_BUFFER_SIZE 8192
#define SWITCH_RECORD_POST_PROCESS_EXEC_API_VARIABLE "record_post_process_exec_api"
#define SWITCH_RECORD_POST_PROCESS_EXEC_APP_VARIABLE "record_post_process_exec_app"
#define SWITCH_REMOTE_MEDIA_IP_VARIABLE "remote_media_ip"
#define SWITCH_REMOTE_MEDIA_PORT_VARIABLE "remote_media_port"
#define SWITCH_REMOTE_VIDEO_IP_VARIABLE "remote_video_ip"
#define SWITCH_REMOTE_VIDEO_PORT_VARIABLE "remote_video_port"
#define SWITCH_RTCP_AUDIO_INTERVAL_MSEC "5000"
#define SWITCH_RTCP_VIDEO_INTERVAL_MSEC "2000"
#define SWITCH_RTP_CNG_PAYLOAD 13
#define SWITCH_R_SDP_VARIABLE "switch_r_sdp"
#define SWITCH_SEND_SILENCE_WHEN_IDLE_VARIABLE "send_silence_when_idle"
#define SWITCH_SENSITIVE_DTMF_VARIABLE "sensitive_dtmf"
#define SWITCH_SEQ_DEFAULT_COLOR SWITCH_SEQ_FWHITE
#define SWITCH_SEQ_FCYAN FOREGROUND_GREEN | FOREGROUND_BLUE
#define SWITCH_SEQ_FGREEN FOREGROUND_GREEN
#define SWITCH_SEQ_FMAGEN FOREGROUND_BLUE | FOREGROUND_RED
#define SWITCH_SEQ_FRED FOREGROUND_RED | FOREGROUND_INTENSITY
#define SWITCH_SEQ_FWHITE FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define SWITCH_SEQ_FYELLOW FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define SWITCH_SESSION_IN_HANGUP_HOOK_VARIABLE "session_in_hangup_hook"
#define SWITCH_SIGNAL_BOND_VARIABLE "signal_bond"
#define SWITCH_SIGNAL_BRIDGE_VARIABLE "signal_bridge_to"
#define SWITCH_SKIP_CDR_CAUSES_VARIABLE "skip_cdr_causes"
#define SWITCH_SOCK_INVALID INVALID_SOCKET
#define SWITCH_SOFT_HOLDING_UUID_VARIABLE "soft_holding_uuid"
#define SWITCH_SPEECH_KEY "speech"
#define SWITCH_STANDARD_API(name) static switch_status_t name (_In_opt_z_ const char *cmd, _In_opt_ switch_core_session_t *session, _In_ switch_stream_handle_t *stream)
#define SWITCH_STANDARD_APP(name) static void name (switch_core_session_t *session, const char *data)
#define SWITCH_STANDARD_CHAT_APP(name) static switch_status_t name (switch_event_t *message, const char *data)
#define SWITCH_STANDARD_DIALPLAN(name) static switch_caller_extension_t *name (switch_core_session_t *session, void *arg, switch_caller_profile_t *caller_profile)
#define SWITCH_STANDARD_JSON_API(name) static switch_status_t name (const cJSON *json, _In_opt_ switch_core_session_t *session, cJSON **json_reply)
#define SWITCH_STANDARD_SCHED_FUNC(name) static void name (switch_scheduler_task_t *task)
#define SWITCH_SYSTEM_THREAD_STACKSIZE 8192 * 1024
#define SWITCH_TEMP_HOLD_MUSIC_VARIABLE "temp_hold_music"
#define SWITCH_THREAD_STACKSIZE 240 * 1024
#define SWITCH_TON_UNDEF 255
#define SWITCH_TRANSFER_AFTER_BRIDGE_VARIABLE "transfer_after_bridge"
#define SWITCH_TRANSFER_HISTORY_VARIABLE "transfer_history"
#define SWITCH_TRANSFER_SOURCE_VARIABLE "transfer_source"

#define SWITCH_URL_SEPARATOR "://"
#define SWITCH_UUID_BRIDGE "uuid_bridge"
#define SWITCH_ZRTP_PASSTHRU_VARIABLE "zrtp_passthru"
#define arg_recursion_check_start(_args) if (_args) {					\
		if (_args->loops >= MAX_ARG_RECURSION) {						\
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,		\
							  "RECURSION ERROR!  It's not the best idea to call things that collect input recursively from an input callback.\n"); \
			return SWITCH_STATUS_GENERR;								\
		} else {_args->loops++;}										\
	}
#define arg_recursion_check_stop(_args) if (_args) _args->loops--
#define SWITCH_IMG_FMT_HAS_ALPHA VPX_IMG_FMT_HAS_ALPHA
#define SWITCH_IMG_FMT_HIGH      VPX_IMG_FMT_HIGH
#define SWITCH_IMG_FMT_PLANAR    VPX_IMG_FMT_PLANAR
#define SWITCH_IMG_FMT_UV_FLIP   VPX_IMG_FMT_UV_FLIP
#define SWITCH_PLANE_ALPHA  VPX_PLANE_ALPHA
#define SWITCH_PLANE_PACKED VPX_PLANE_PACKED
#define SWITCH_PLANE_U      VPX_PLANE_U
#define SWITCH_PLANE_V      VPX_PLANE_V
#define SWITCH_PLANE_Y      VPX_PLANE_Y

#define VPX_IMG_FMT_HIGH         0x800  
#define VPX_IMAGE_ABI_VERSION (3) 
#define VPX_IMG_FMT_HAS_ALPHA  0x400  
#define VPX_IMG_FMT_HIGHBITDEPTH 0x800  
#define VPX_IMG_FMT_PLANAR     0x100  
#define VPX_IMG_FMT_UV_FLIP    0x200  
#define VPX_PLANE_ALPHA  3   
#define VPX_PLANE_PACKED 0   
#define VPX_PLANE_U      1   
#define VPX_PLANE_V      2   
#define VPX_PLANE_Y      0   

#define DoxyDefine(x) x
#define FALSE 0
#define FS_64BIT 1



#define O_BINARY 0

#define PRINTF_FUNCTION(fmtstr,vars) __attribute__((format(printf,fmtstr,vars)))
#define SIGHUP SIGTERM
#define SWITCH_DECLARE(type)			type __stdcall

#define SWITCH_DECLARE_CONSTRUCTOR SWITCH_DECLARE_DATA

#define SWITCH_DECLARE_NONSTD(type)		type __cdecl
#define SWITCH_HAVE_ODBC 1
#define SWITCH_INT64_T_FMT          "lld"
#define SWITCH_MOD_DECLARE(type)		type __stdcall

#define SWITCH_MOD_DECLARE_NONSTD(type)	type __cdecl

#define SWITCH_SIZE_T_FMT           "lld"
#define SWITCH_SSIZE_T_FMT          "lld"
#define SWITCH_THREAD_FUNC  __stdcall
#define SWITCH_TIME_T_FMT SWITCH_SIZE_T_FMT
#define SWITCH_UINT64_T_FMT         "llu"

#define SWITCH_VA_NONE "%s", ""
#define SW_HIDE             0
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define TIME_T_FMT SWITCH_INT64_T_FMT
#define TRUE (!FALSE)

























#define _WIN32_WINNT 0x0400
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER SWITCH_BYTE_ORDER
#define __FUNCTION__ ""
#define __LITTLE_ENDIAN 1234
#define __SWITCH_FUNC__ __FUNCTION__
#define atoll _atoi64
#define inline __inline
#define snprintf _snprintf
#define strcasecmp(s1, s2) stricmp(s1, s2)
#define strncasecmp(s1, s2, n) strnicmp(s1, s2, n)
#define switch_assert(expr) assert(expr)
