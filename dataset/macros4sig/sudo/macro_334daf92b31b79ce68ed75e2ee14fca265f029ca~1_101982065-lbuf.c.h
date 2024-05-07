#include<unistd.h>
#include<stdlib.h>
#include<stdarg.h>

#include<sys/types.h>
#include<sys/stat.h>
#include<string.h>
#include<stdio.h>
#include<ctype.h>

# define TIMESPEC_TO_TIMEVAL(tv, ts)					       \
    do {								       \
	(tv)->tv_sec = (ts)->tv_sec;					       \
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				       \
    } while (0)
# define TIMEVAL_TO_TIMESPEC(tv, ts)					       \
    do {								       \
	(ts)->tv_sec = (tv)->tv_sec;					       \
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				       \
    } while (0)
#define aix_getauthregistry(_a, _b) aix_getauthregistry_v1((_a), (_b))
#define aix_prep_user(_a, _b) aix_prep_user_v1((_a), (_b))
#define aix_restoreauthdb() aix_restoreauthdb_v1()
#define aix_setauthdb(_a, _b) aix_setauthdb_v2((_a), (_b))
# define ignore_result(x) do {						       \
    __typeof__(x) y = (x);						       \
    (void)y;								       \
} while(0)
#  define mtim_get(_x, _y)	do { (_y).tv_sec = (_x)->SUDO_ST_MTIM.tv_sec; (_y).tv_nsec = (_x)->SUDO_ST_MTIM.tv_nsec; } while (0)
#define ssizeof(_x)	((ssize_t)sizeof(_x))
#define sudo_basename(_a) sudo_basename_v1(_a)
#define sudo_clrbit(_a, _i)	((_a)[(_i) / NBBY] &= ~(1<<((_i) % NBBY)))
#define sudo_get_ttysize(_a, _b) sudo_get_ttysize_v1((_a), (_b))
#define sudo_getgrouplist2(_a, _b, _c, _d) sudo_getgrouplist2_v1((_a), (_b), (_c), (_d))
#define sudo_gethostname() sudo_gethostname_v1()
#define sudo_gettime_awake(_a) sudo_gettime_awake_v1((_a))
#define sudo_gettime_mono(_a) sudo_gettime_mono_v1((_a))
#define sudo_gettime_real(_a) sudo_gettime_real_v1((_a))
#define sudo_hexchar(_a) sudo_hexchar_v1(_a)
#define sudo_isclr(_a, _i)	(((_a)[(_i) / NBBY] & (1<<((_i) % NBBY))) == 0)
#define sudo_isset(_a, _i)	((_a)[(_i) / NBBY] & (1<<((_i) % NBBY)))
#define sudo_lock_file(_a, _b) sudo_lock_file_v1((_a), (_b))
#define sudo_lock_region(_a, _b, _c) sudo_lock_region_v1((_a), (_b), (_c))
#define sudo_logfac2str(_a) sudo_logfac2str_v1((_a))
#define sudo_logpri2str(_a) sudo_logpri2str_v1((_a))
#define sudo_mkdir_parents(_a, _b, _c, _d, _e) sudo_mkdir_parents_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_mmap_alloc(_a) sudo_mmap_alloc_v1(_a)
#define sudo_mmap_allocarray(_a, _b) sudo_mmap_allocarray_v1((_a), (_b))
#define sudo_mmap_free(_a) sudo_mmap_free_v1(_a)
#define sudo_mmap_protect(_a) sudo_mmap_protect_v1(_a)
#define sudo_mmap_strdup(_a) sudo_mmap_strdup_v1(_a)
#define sudo_new_key_val(_a, _b) sudo_new_key_val_v1((_a), (_b))
#define sudo_open_parent_dir(_a, _b, _c, _d, _e) sudo_open_parent_dir_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_parse_gids(_a, _b, _c) sudo_parse_gids_v1((_a), (_b), (_c))
#define sudo_parseln(_a, _b, _c, _d, _e) sudo_parseln_v2((_a), (_b), (_c), (_d), (_e))
#define sudo_pow2_roundup(_a) sudo_pow2_roundup_v1((_a))
#define sudo_regex_compile(_a, _b, _c) sudo_regex_compile_v1((_a), (_b), (_c))
#define sudo_secure_dir(_a, _b, _c, _d) sudo_secure_dir_v1((_a), (_b), (_c), (_d))
#define sudo_secure_file(_a, _b, _c, _d) sudo_secure_file_v1((_a), (_b), (_c), (_d))
#define sudo_secure_open_dir(_a, _b, _c, _d, _e) sudo_secure_open_dir_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_secure_open_file(_a, _b, _c, _d, _e) sudo_secure_open_file_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_setbit(_a, _i)	((_a)[(_i) / NBBY] |= 1 << ((_i) % NBBY))
#define sudo_setgroups(_a, _b) sudo_setgroups_v1((_a), (_b))
#define sudo_stat_multiarch(_a, _b) sudo_stat_multiarch_v1((_a), (_b))
#define sudo_str2logfac(_a, _b) sudo_str2logfac_v1((_a), (_b))
#define sudo_str2logpri(_a, _b) sudo_str2logpri_v1((_a), (_b))
#define sudo_strsplit(_a, _b, _c, _d) sudo_strsplit_v1(_a, _b, _c, _d)
#define sudo_strtobool(_a) sudo_strtobool_v1((_a))
#define sudo_strtoid(_a, _b) sudo_strtoid_v2((_a), (_b))
#define sudo_strtoidx(_a, _b, _c, _d) sudo_strtoidx_v1((_a), (_b), (_c), (_d))
#define sudo_strtomode(_a, _b) sudo_strtomode_v1((_a), (_b))
#define sudo_term_cbreak(_a) sudo_term_cbreak_v1((_a))
#define sudo_term_copy(_a, _b) sudo_term_copy_v1((_a), (_b))
#define sudo_term_is_raw(_a) sudo_term_is_raw_v1((_a))
#define sudo_term_noecho(_a) sudo_term_noecho_v1((_a))
#define sudo_term_raw(_a, _b) sudo_term_raw_v1((_a), (_b))
#define sudo_term_restore(_a, _b) sudo_term_restore_v1((_a), (_b))
#define sudo_timespecadd(ts1, ts2, ts3)					       \
    do {								       \
	(ts3)->tv_sec = (ts1)->tv_sec + (ts2)->tv_sec;			       \
	(ts3)->tv_nsec = (ts1)->tv_nsec + (ts2)->tv_nsec;		       \
	while ((ts3)->tv_nsec >= 1000000000) {				       \
	    (ts3)->tv_sec++;						       \
	    (ts3)->tv_nsec -= 1000000000;				       \
	}								       \
    } while (0)
#define sudo_timespecclear(ts)	((ts)->tv_sec = (ts)->tv_nsec = 0)
#define sudo_timespeccmp(ts1, ts2, op)					       \
    (((ts1)->tv_sec == (ts2)->tv_sec) ?					       \
	((ts1)->tv_nsec op (ts2)->tv_nsec) :				       \
	((ts1)->tv_sec op (ts2)->tv_sec))
#define sudo_timespecisset(ts)	((ts)->tv_sec || (ts)->tv_nsec)
#define sudo_timespecsub(ts1, ts2, ts3)					       \
    do {								       \
	(ts3)->tv_sec = (ts1)->tv_sec - (ts2)->tv_sec;			       \
	(ts3)->tv_nsec = (ts1)->tv_nsec - (ts2)->tv_nsec;		       \
	while ((ts3)->tv_nsec < 0) {					       \
	    (ts3)->tv_sec--;						       \
	    (ts3)->tv_nsec += 1000000000;				       \
	}								       \
    } while (0)
#define sudo_timevaladd(tv1, tv2, tv3)					       \
    do {								       \
	(tv3)->tv_sec = (tv1)->tv_sec + (tv2)->tv_sec;			       \
	(tv3)->tv_usec = (tv1)->tv_usec + (tv2)->tv_usec;		       \
	if ((tv3)->tv_usec >= 1000000) {				       \
	    (tv3)->tv_sec++;						       \
	    (tv3)->tv_usec -= 1000000;					       \
	}								       \
    } while (0)
#define sudo_timevalclear(tv)	((tv)->tv_sec = (tv)->tv_usec = 0)
#define sudo_timevalcmp(tv1, tv2, op)					       \
    (((tv1)->tv_sec == (tv2)->tv_sec) ?					       \
	((tv1)->tv_usec op (tv2)->tv_usec) :				       \
	((tv1)->tv_sec op (tv2)->tv_sec))
#define sudo_timevalisset(tv)	((tv)->tv_sec || (tv)->tv_usec)
#define sudo_timevalsub(tv1, tv2, tv3)					       \
    do {								       \
	(tv3)->tv_sec = (tv1)->tv_sec - (tv2)->tv_sec;			       \
	(tv3)->tv_usec = (tv1)->tv_usec - (tv2)->tv_usec;		       \
	if ((tv3)->tv_usec < 0) {					       \
	    (tv3)->tv_sec--;						       \
	    (tv3)->tv_usec += 1000000;					       \
	}								       \
    } while (0)
#define sudo_ttyname_dev(_a, _b, _c) sudo_ttyname_dev_v1((_a), (_b), (_c))
#define sudo_uuid_create(_a) sudo_uuid_create_v1((_a))
#define sudo_uuid_to_string(_a, _b, _c) sudo_uuid_to_string_v1((_a), (_b), (_c))

#define sudo_lbuf_append sudo_lbuf_append_v1
#define sudo_lbuf_append_quoted sudo_lbuf_append_quoted_v1
#define sudo_lbuf_clearerr(_a) sudo_lbuf_clearerr_v1((_a))
#define sudo_lbuf_destroy(_a) sudo_lbuf_destroy_v1((_a))
#define sudo_lbuf_error(_a) sudo_lbuf_error_v1((_a))
#define sudo_lbuf_init(_a, _b, _c, _d, _e) sudo_lbuf_init_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_lbuf_print(_a) sudo_lbuf_print_v1((_a))
#define SUDO_DEBUG_APPARMOR     (15<<6)    

#define SUDO_DEBUG_PRI(n) (((n) & 0x0f) - 1)
#define SUDO_DEBUG_SUBSYS(n) (((n) >> 6) - 1)
#define debug_decl(funcname, subsys)					       \
    debug_decl_vars((funcname), (subsys));				       \
    sudo_debug_enter(__func__, "__FILE__", "__LINE__", sudo_debug_subsys)
# define debug_decl_func(funcname)
# define debug_decl_vars(funcname, subsys)				       \
    const int sudo_debug_subsys = (subsys)
#define debug_return_bool(ret)						       \
    do {								       \
	bool sudo_debug_ret = (ret);					       \
	sudo_debug_exit_bool(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,  \
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_const_ptr(ret)					       \
    do {								       \
	const void *sudo_debug_ret = (ret);				       \
	sudo_debug_exit_ptr(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,   \
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_const_str(ret)					       \
    do {								       \
	const char *sudo_debug_ret = (ret);				       \
	sudo_debug_exit_str(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,   \
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_id_t(ret)					       \
    do {								       \
	id_t sudo_debug_ret = (ret);				       \
	sudo_debug_exit_id_t(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,\
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_int(ret)						       \
    do {								       \
	int sudo_debug_ret = (ret);					       \
	sudo_debug_exit_int(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,   \
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_long(ret)						       \
    do {								       \
	long sudo_debug_ret = (ret);					       \
	sudo_debug_exit_long(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,  \
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_ptr(ret)						       \
    do {								       \
	void *sudo_debug_ret = (ret);					       \
	sudo_debug_exit_ptr(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,   \
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_size_t(ret)					       \
    do {								       \
	size_t sudo_debug_ret = (ret);				       \
	sudo_debug_exit_size_t(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,\
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_ssize_t(ret)					       \
    do {								       \
	ssize_t sudo_debug_ret = (ret);				       \
	sudo_debug_exit_ssize_t(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,\
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_str(ret)						       \
    do {								       \
	char *sudo_debug_ret = (ret);					       \
	sudo_debug_exit_str(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,   \
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_str_masked(ret)					       \
    do {								       \
	char *sudo_debug_ret = (ret);					       \
	sudo_debug_exit_str_masked(__func__, "__FILE__", "__LINE__",	       \
	    sudo_debug_subsys, sudo_debug_ret);			       \
	return sudo_debug_ret;						       \
    } while (0)
#define debug_return_time_t(ret)					       \
    do {								       \
	time_t sudo_debug_ret = (ret);				       \
	sudo_debug_exit_time_t(__func__, "__FILE__", "__LINE__", sudo_debug_subsys,\
	    sudo_debug_ret);						       \
	return sudo_debug_ret;						       \
    } while (0)
#define sudo_debug_deregister(_a) sudo_debug_deregister_v1((_a))
#define sudo_debug_enter(_a, _b, _c, _d) sudo_debug_enter_v1((_a), (_b), (_c), (_d))
#define sudo_debug_execve(pri, path, argv, envp) \
    sudo_debug_execve2((pri)|sudo_debug_subsys, (path), (argv), (envp))
#define sudo_debug_execve2(_a, _b, _c, _d) sudo_debug_execve2_v1((_a), (_b), (_c), (_d))
#define sudo_debug_exit(_a, _b, _c, _d) sudo_debug_exit_v1((_a), (_b), (_c), (_d))
#define sudo_debug_exit_bool(_a, _b, _c, _d, _e) sudo_debug_exit_bool_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_id_t(_a, _b, _c, _d, _e) sudo_debug_exit_id_t_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_int(_a, _b, _c, _d, _e) sudo_debug_exit_int_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_long(_a, _b, _c, _d, _e) sudo_debug_exit_long_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_ptr(_a, _b, _c, _d, _e) sudo_debug_exit_ptr_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_size_t(_a, _b, _c, _d, _e) sudo_debug_exit_size_t_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_ssize_t(_a, _b, _c, _d, _e) sudo_debug_exit_ssize_t_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_str(_a, _b, _c, _d, _e) sudo_debug_exit_str_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_str_masked(_a, _b, _c, _d, _e) sudo_debug_exit_str_masked_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_exit_time_t(_a, _b, _c, _d, _e) sudo_debug_exit_time_t_v1((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_fork() sudo_debug_fork_v1()
#define sudo_debug_get_active_instance() sudo_debug_get_active_instance_v1()
#define sudo_debug_get_fds(_a) sudo_debug_get_fds_v1((_a))
#define sudo_debug_get_instance(_a) sudo_debug_get_instance_v1((_a))
#define sudo_debug_needed(level) sudo_debug_needed_v1((level)|sudo_debug_subsys)
#define sudo_debug_parse_flags(_a, _b) sudo_debug_parse_flags_v1((_a), (_b))
# define sudo_debug_printf sudo_debug_printf_nvm
#define sudo_debug_printf2 sudo_debug_printf2_v1
#define sudo_debug_printf_nvm sudo_debug_printf_nvm_v1
#define sudo_debug_register(_a, _b, _c, _d, _e) sudo_debug_register_v2((_a), (_b), (_c), (_d), (_e))
#define sudo_debug_set_active_instance(_a) sudo_debug_set_active_instance_v1((_a))
#define sudo_debug_update_fd(_a, _b) sudo_debug_update_fd_v1((_a), (_b))
#define sudo_debug_vprintf2(_a, _b, _c, _d, _e, _f) sudo_debug_vprintf2_v1((_a), (_b), (_c), (_d), (_e), (_f))
#define sudo_debug_write(fd, str, len, errnum) \
    sudo_debug_write2(fd, NULL, NULL, 0, (str), (len), (errnum))
#define sudo_debug_write2(_a, _b, _c, _d, _e, _f, _g) sudo_debug_write2_v1((_a), (_b), (_c), (_d), (_e), (_f), (_g))
# define ANALYZER_ASSERT(x) do {					\
	if (!__builtin_expect(!(x), 0))					\
		__builtin_trap();					\
} while (0)
#define HLTQ_CONCAT(queue1, queue2, field) do {				\
	(queue2)->field.tqe_prev = (queue1)->field.tqe_prev;		\
	*(queue1)->field.tqe_prev = (queue2);				\
	(queue1)->field.tqe_prev = &(queue2)->field.tqe_next;		\
} while (0)
#define HLTQ_ENTRY(type)		TAILQ_ENTRY(type)
#define HLTQ_FOREACH(var, head, field)					\
	for ((var) = HLTQ_FIRST(head);					\
	    (var) != HLTQ_END(head);					\
	    (var) = HLTQ_NEXT(var, field))
#define HLTQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = HLTQ_LAST(head, headname);				\
	    (var) != HLTQ_END(head);					\
	    (var) = HLTQ_PREV(var, headname, field))
#define HLTQ_INITIALIZER(entry, field)				\
	{ NULL, &(entry)->field.tqe_next }
#define HLTQ_LAST(elm, type, field)					\
	((elm)->field.tqe_next == NULL ? (elm) :			\
	    __containerof((elm)->field.tqe_prev, struct type, field.tqe_next))
#define HLTQ_PREV(elm, type, field)					\
	(*(elm)->field.tqe_prev == NULL ? NULL :			\
	    __containerof((elm)->field.tqe_prev, struct type, field.tqe_next))
#define HLTQ_TO_TAILQ(head, hl, field) do {				\
	(head)->tqh_first = (hl);					\
	(head)->tqh_last = (hl)->field.tqe_prev;			\
	(hl)->field.tqe_prev = &(head)->tqh_first;			\
} while (0)
#define LIST_SWAP(head1, head2, type, field) do {			\
	struct type *swap_tmp = LIST_FIRST((head1));			\
	LIST_FIRST((head1)) = LIST_FIRST((head2));			\
	LIST_FIRST((head2)) = swap_tmp;					\
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head1));		\
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head2));		\
} while (0)
#define SLIST_REMOVE_AFTER(elm, field) do {				\
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
} while (0)
#define SLIST_SWAP(head1, head2, type) do {				\
	struct type *swap_first = SLIST_FIRST(head1);			\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)
#define STAILQ_SWAP(head1, head2, type) do {				\
	struct type *swap_first = STAILQ_FIRST(head1);			\
	struct type **swap_last = (head1)->stqh_last;			\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
} while (0)
#define TAILQ_CONCAT_HLTQ(head, hl, field) do {				\
	void *last = (hl)->field.tqe_prev;				\
	(hl)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (hl);					\
	(head)->tqh_last = last;					\
} while (0)
#define TAILQ_SWAP(head1, head2, type, field) do {			\
	struct type *swap_first = (head1)->tqh_first;			\
	struct type **swap_last = (head1)->tqh_last;			\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)
#  define ASN1_STRING_get0_data(x)      ASN1_STRING_data(x)
#define CLR(t, f)	((t) &= ~(f))
# define HAVE_DIRFD
# define HAVE_INNETGR 1
#    define HAVE_SETEUID 1
#define ISSET(t, f)     ((t) & (f))
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#  define NBBY 8
#  define NSIG 64
#  define PATH_MAX		_POSIX_PATH_MAX
#define SET(t, f)	((t) |= (f))
# define SIG2STR_MAX 32

#  define TLS_method()                  SSLv23_method()
# define WCOREDUMP(x)	((x) & 0x80)
# define W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
#  define X509_STORE_CTX_get0_cert(x)   ((x)->cert)
# define __containerof(x, s, m)	((s *)((char *)(x) - offsetof(s, m)))
# define asprintf sudo_asprintf
# define cfmakeraw(_a) sudo_cfmakeraw((_a))
# define closefrom(_a) sudo_closefrom((_a))
# define dirfd(_d)	((_d)->dd_fd)
# define dup3(_a, _b, _c) sudo_dup3((_a), (_b), (_c))
# define endusershell() sudo_endusershell()
# define explicit_bzero(_a, _b) sudo_explicit_bzero((_a), (_b))
# define fchmodat(_a, _b, _c, _d) sudo_fchmodat((_a), (_b), (_c), (_d))
# define fchownat(_a, _b, _c, _d, _e) sudo_fchownat((_a), (_b), (_c), (_d), (_e))
# define freezero(_a, _b) sudo_freezero((_a), (_b))
# define fseeko(f, o, w)	fseek((f), (long)(o), (w))
# define fstatat(_a, _b, _c, _d) sudo_fstatat((_a), (_b), (_c), (_d))
# define futimens(_a, _b) sudo_futimens((_a), (_b))
# define getcwd(_a, _b) sudo_getcwd((_a), (_b))
# define getdelim(_a, _b, _c, _d) sudo_getdelim((_a), (_b), (_c), (_d))
# define getgrouplist(_a, _b, _c, _d) sudo_getgrouplist((_a), (_b), (_c), (_d))
# define getprogname() sudo_getprogname()
# define getusershell() sudo_getusershell()
# define gmtime_r(_a, _b) sudo_gmtime_r((_a), (_b))
# define howmany(x, y)	(((x) + ((y) - 1)) / (y))
# define inet_ntop(_a, _b, _c, _d) sudo_inet_ntop((_a), (_b), (_c), (_d))
# define inet_pton(_a, _b, _c) sudo_inet_pton((_a), (_b), (_c))
# define isblank(_x)	((_x) == ' ' || (_x) == '\t')
# define killpg(p, s)	kill(-(p), (s))
# define localtime_r(_a, _b) sudo_localtime_r((_a), (_b))
# define memrchr(_a, _b, _c) sudo_memrchr((_a), (_b), (_c))
# define mkdirat(_a, _b, _c) sudo_mkdirat((_a), (_b), (_c))
#  define mkdtemp(_a) sudo_mkdtemp((_a))
#  define mkdtempat mkdtempat_np
#  define mkostempsat mkostempsat_np
#  define mkstemp(_a) sudo_mkstemp((_a))
#  define mkstemps(_a, _b) sudo_mkstemps((_a), (_b))
# define nanosleep(_a, _b) sudo_nanosleep((_a), (_b))
# define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
# define openat(_a, _b, _c, _d) sudo_openat((_a), (_b), (_c), (_d))
# define pipe2(_a, _b) sudo_pipe2((_a), (_b))
#  define pread(_a, _b, _c, _d) pread64((_a), (_b), (_c), (_d))
# define pw_dup(_a) sudo_pw_dup((_a))
#  define pwrite(_a, _b, _c, _d) pwrite64((_a), (_b), (_c), (_d))
# define reallocarray(_a, _b, _c) sudo_reallocarray((_a), (_b), (_c))
#    define setegid(g)	setresgid(-1, (g), -1)
#    define seteuid(u)	setresuid(-1, (u), -1)
# define setprogname(_a) sudo_setprogname(_a)
# define setusershell() sudo_setusershell()
# define sig2str(_a, _b) sudo_sig2str((_a), (_b))
# define snprintf sudo_snprintf
# define str2sig(_a, _b) sudo_str2sig((_a), (_b))
# define strlcat(_a, _b, _c) sudo_strlcat((_a), (_b), (_c))
# define strlcpy(_a, _b, _c) sudo_strlcpy((_a), (_b), (_c))
# define strndup(_a, _b) sudo_strndup((_a), (_b))
# define strnlen(_a, _b) sudo_strnlen((_a), (_b))
# define strsignal(_a) sudo_strsignal((_a))
# define unlinkat(_a, _b, _c) sudo_unlinkat((_a), (_b), (_c))
# define utimensat(_a, _b, _c, _d) sudo_utimensat((_a), (_b), (_c), (_d))
#  define va_copy(d, s) memcpy(&(d), &(s), sizeof(d));
# define vasprintf sudo_vasprintf
# define vsnprintf sudo_vsnprintf
