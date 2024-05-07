#include<dirent.h>
#include<stdio.h>
#include<malloc.h>

#include<stdlib.h>
#include<inttypes.h>
#include<sys/ioctl.h>
#include<errno.h>
#include<sys/un.h>
#include<signal.h>
#include<pwd.h>
#include<regex.h>
#include<string.h>
#include<stdarg.h>
#include<netinet/in.h>


#include<sys/time.h>
#include<sys/select.h>

#include<sys/socket.h>

#include<wchar.h>
#include<stddef.h>

#include<arpa/inet.h>


#include<sys/utsname.h>

#include<sys/poll.h>
#include<syslog.h>
#include<poll.h>

#include<zlib.h>
#include<sys/resource.h>
#include<utime.h>
#include<time.h>
#include<unistd.h>
#include<iconv.h>
#include<libgen.h>
#include<paths.h>



#include<sys/wait.h>
#include<strings.h>
#include<sys/types.h>



#include<limits.h>
#include<termios.h>



#include<assert.h>
#include<sys/param.h>
#include<pthread.h>

#include<sys/sysctl.h>
#include<netinet/tcp.h>
#include<fcntl.h>

#include<netdb.h>
#include<stdint.h>


#include<sys/mman.h>



#include<grp.h>
#include<sys/stat.h>

#define CONNECT_DIAG_URL      (1u << 1)

#define CONNECT_IPV4          (1u << 2)
#define CONNECT_IPV6          (1u << 3)
#define CONNECT_VERBOSE       (1u << 0)
#define PACK_REFS_ALL   0x0002
#define PACK_REFS_PRUNE 0x0001
#define REFNAME_ALLOW_ONELEVEL 1
#define REFNAME_REFSPEC_PATTERN 2

#define REF_BAD_NAME 0x08
#define REF_FORCE_CREATE_REFLOG 0x40
#define REF_ISBROKEN 0x04
#define REF_ISPACKED 0x02
#define REF_ISSYMREF 0x01
#define REF_TRANSACTION_UPDATE_ALLOWED_FLAGS \
	REF_ISPRUNING |                      \
	REF_FORCE_CREATE_REFLOG |            \
	REF_NODEREF
#define RESOLVE_REF_ALLOW_BAD_NAME 0x04
#define RESOLVE_REF_NO_RECURSE 0x02
#define RESOLVE_REF_READING 0x01
#define TRANSACTION_GENERIC_ERROR -2
#define TRANSACTION_NAME_CONFLICT -1
#define CAS_OPT_NAME "force-with-lease"


#define OPT_ARGUMENT(l, h)          { OPTION_ARGUMENT, 0, (l), NULL, NULL, \
				      (h), PARSE_OPT_NOARG}
#define OPT_BIT(s, l, v, h, b)      { OPTION_BIT, (s), (l), (v), NULL, (h), \
				      PARSE_OPT_NOARG, NULL, (b) }
#define OPT_BOOL(s, l, v, h)        OPT_SET_INT(s, l, v, h, 1)
#define OPT_CALLBACK(s, l, v, a, h, f) \
	{ OPTION_CALLBACK, (s), (l), (v), (a), (h), 0, (f) }
#define OPT_CMDMODE(s, l, v, h, i)  { OPTION_CMDMODE, (s), (l), (v), NULL, \
				      (h), PARSE_OPT_NOARG|PARSE_OPT_NONEG, NULL, (i) }
#define OPT_COLOR_FLAG(s, l, v, h) \
	{ OPTION_CALLBACK, (s), (l), (v), N_("when"), (h), PARSE_OPT_OPTARG, \
		parse_opt_color_flag_cb, (intptr_t)"always" }
#define OPT_COLUMN(s, l, v, h) \
	{ OPTION_CALLBACK, (s), (l), (v), N_("style"), (h), PARSE_OPT_OPTARG, parseopt_column_callback }
#define OPT_CONTAINS(v, h) _OPT_CONTAINS_OR_WITH("contains", v, h, PARSE_OPT_NONEG)
#define OPT_COUNTUP(s, l, v, h)     { OPTION_COUNTUP, (s), (l), (v), NULL, \
				      (h), PARSE_OPT_NOARG }
#define OPT_DATE(s, l, v, h) \
	{ OPTION_CALLBACK, (s), (l), (v), N_("time"),(h), 0,	\
	  parse_opt_approxidate_cb }
#define OPT_END()                   { OPTION_END }
#define OPT_EXPIRY_DATE(s, l, v, h) \
	{ OPTION_CALLBACK, (s), (l), (v), N_("expiry-date"),(h), 0,	\
	  parse_opt_expiry_date_cb }
#define OPT_FILENAME(s, l, v, h)    { OPTION_FILENAME, (s), (l), (v), \
				       N_("file"), (h) }
#define OPT_GROUP(h)                { OPTION_GROUP, 0, NULL, NULL, NULL, (h) }
#define OPT_HIDDEN_BOOL(s, l, v, h) { OPTION_SET_INT, (s), (l), (v), NULL, \
				      (h), PARSE_OPT_NOARG | PARSE_OPT_HIDDEN, NULL, 1}
#define OPT_INTEGER(s, l, v, h)     { OPTION_INTEGER, (s), (l), (v), N_("n"), (h) }
#define OPT_MAGNITUDE(s, l, v, h)   { OPTION_MAGNITUDE, (s), (l), (v), \
				      N_("n"), (h), PARSE_OPT_NONEG }
#define OPT_NEGBIT(s, l, v, h, b)   { OPTION_NEGBIT, (s), (l), (v), NULL, \
				      (h), PARSE_OPT_NOARG, NULL, (b) }
#define OPT_NOOP_NOARG(s, l) \
	{ OPTION_CALLBACK, (s), (l), NULL, NULL, \
	  N_("no-op (backward compatibility)"),		\
	  PARSE_OPT_HIDDEN | PARSE_OPT_NOARG, parse_opt_noop_cb }
#define OPT_NO_CONTAINS(v, h) _OPT_CONTAINS_OR_WITH("no-contains", v, h, PARSE_OPT_NONEG)
#define OPT_NUMBER_CALLBACK(v, h, f) \
	{ OPTION_NUMBER, 0, NULL, (v), NULL, (h), \
	  PARSE_OPT_NOARG | PARSE_OPT_NONEG, (f) }
#define OPT_PASSTHRU(s, l, v, a, h, f) \
	{ OPTION_CALLBACK, (s), (l), (v), (a), (h), (f), parse_opt_passthru }
#define OPT_PASSTHRU_ARGV(s, l, v, a, h, f) \
	{ OPTION_CALLBACK, (s), (l), (v), (a), (h), (f), parse_opt_passthru_argv }
#define OPT_SET_INT(s, l, v, h, i)  { OPTION_SET_INT, (s), (l), (v), NULL, \
				      (h), PARSE_OPT_NOARG, NULL, (i) }
#define OPT_STRING(s, l, v, a, h)   { OPTION_STRING,  (s), (l), (v), (a), (h) }
#define OPT_STRING_LIST(s, l, v, a, h) \
				    { OPTION_CALLBACK, (s), (l), (v), (a), \
				      (h), 0, &parse_opt_string_list }
#define OPT_UYN(s, l, v, h)         { OPTION_CALLBACK, (s), (l), (v), NULL, \
				      (h), PARSE_OPT_NOARG, &parse_opt_tertiary }
#define OPT_WITH(v, h) _OPT_CONTAINS_OR_WITH("with", v, h, PARSE_OPT_HIDDEN | PARSE_OPT_NONEG)
#define OPT_WITHOUT(v, h) _OPT_CONTAINS_OR_WITH("without", v, h, PARSE_OPT_HIDDEN | PARSE_OPT_NONEG)
#define OPT__ABBREV(var)  \
	{ OPTION_CALLBACK, 0, "abbrev", (var), N_("n"),	\
	  N_("use <n> digits to display SHA-1s"),	\
	  PARSE_OPT_OPTARG, &parse_opt_abbrev_cb, 0 }
#define OPT__COLOR(var, h) \
	OPT_COLOR_FLAG(0, "color", (var), (h))
#define OPT__DRY_RUN(var, h)  OPT_BOOL('n', "dry-run", (var), (h))
#define OPT__FORCE(var, h)    OPT_COUNTUP('f', "force",   (var), (h))
#define OPT__QUIET(var, h)    OPT_COUNTUP('q', "quiet",   (var), (h))
#define OPT__VERBOSE(var, h)  OPT_COUNTUP('v', "verbose", (var), (h))
#define OPT__VERBOSITY(var) \
	{ OPTION_CALLBACK, 'v', "verbose", (var), NULL, N_("be more verbose"), \
	  PARSE_OPT_NOARG, &parse_opt_verbosity_cb, 0 }, \
	{ OPTION_CALLBACK, 'q', "quiet", (var), NULL, N_("be more quiet"), \
	  PARSE_OPT_NOARG, &parse_opt_verbosity_cb, 0 }

#define _OPT_CONTAINS_OR_WITH(name, variable, help, flag) \
	{ OPTION_CALLBACK, 0, name, (variable), N_("commit"), (help), \
	  PARSE_OPT_LASTARG_DEFAULT | flag, \
	  parse_opt_commits, (intptr_t) "HEAD" \
	}
#define opterror(o,r,f) (opterror((o),(r),(f)), const_error())
#define CHILD_PROCESS_INIT { NULL, ARGV_ARRAY_INIT, ARGV_ARRAY_INIT }
#define RUN_CLEAN_ON_EXIT 32

#define RUN_COMMAND_NO_STDIN 1
#define RUN_COMMAND_STDOUT_TO_STDERR 4
#define RUN_SILENT_EXEC_FAILURE 8
#define RUN_USING_SHELL 16

#define ARGV_ARRAY_INIT { empty_argv, 0, 0 }

#define STRING_LIST_INIT_DUP   { NULL, 0, 0, 1, NULL }
#define STRING_LIST_INIT_NODUP { NULL, 0, 0, 0, NULL }
#define for_each_string_list_item(item,list)            \
	for (item = (list)->items;                      \
	     item && item < (list)->items + (list)->nr; \
	     ++item)


#define STRBUF_INIT  { 0, 0, strbuf_slopbuf }
#define strbuf_reset(sb)  strbuf_setlen(sb, 0)
#define ABSORB_GITDIR_RECURSE_SUBMODULES (1<<0)

#define SUBMODULE_MOVE_HEAD_DRY_RUN (1<<0)
#define SUBMODULE_MOVE_HEAD_FORCE   (1<<1)
#define SUBMODULE_REMOVAL_DIE_ON_ERROR (1<<0)
#define SUBMODULE_REMOVAL_IGNORE_IGNORED_UNTRACKED (1<<2)
#define SUBMODULE_REMOVAL_IGNORE_UNTRACKED (1<<1)
#define SUBMODULE_UPDATE_STRATEGY_INIT {SM_UPDATE_UNSPECIFIED, NULL}

#define EXC_CMDL 0
#define EXC_DIRS 1
#define EXC_FILE 2
#define EXC_FLAG_ENDSWITH 4
#define EXC_FLAG_MUSTBEDIR 8
#define EXC_FLAG_NEGATIVE 16
#define EXC_FLAG_NODIR 1
#define MATCHED_EXACTLY 3
#define MATCHED_FNMATCH 2
#define MATCHED_RECURSIVELY 1
#define REMOVE_DIR_EMPTY_ONLY 01
#define REMOVE_DIR_KEEP_NESTED_GIT 02
#define REMOVE_DIR_KEEP_TOPLEVEL 04
#define GUARD_PATHSPEC(ps, mask) \
	do { \
		if ((ps)->magic & ~(mask))	       \
			die("BUG:%s:%d: unsupported magic %x",	\
			    "__FILE__", "__LINE__", (ps)->magic & ~(mask)); \
	} while (0)

#define PATHSPEC_KEEP_ORDER (1<<5)
#define PATHSPEC_LITERAL_PATH (1<<6)
#define PATHSPEC_MAXDEPTH_VALID (1<<2) 
#define PATHSPEC_ONESTAR 1	
#define PATHSPEC_PREFER_CWD (1<<0) 
#define PATHSPEC_PREFER_FULL (1<<1) 
#define PATHSPEC_PREFIX_ORIGIN (1<<4)
#define PATHSPEC_SYMLINK_LEADING_PATH (1<<3)

#define CONFIG_GENERIC_ERROR 7

#define CONFIG_INCLUDE_INIT { 0 }
#define CONFIG_INVALID_FILE 3
#define CONFIG_INVALID_KEY 1
#define CONFIG_INVALID_PATTERN 6
#define CONFIG_NOTHING_SET 5
#define CONFIG_NO_LOCK -1
#define CONFIG_NO_SECTION_OR_NAME 2
#define CONFIG_NO_WRITE 4
#define CONFIG_REGEX_NONE ((void *)1)
#define config_error_nonbool(s) (config_error_nonbool(s), const_error())
#define ADD_CACHE_IGNORE_REMOVAL 8
#define ADD_CACHE_INTENT 16
#define ADD_CACHE_JUST_APPEND 8		
#define ADD_CACHE_KEEP_CACHE_TREE 32	
#define ADD_CACHE_NEW_ONLY 16		
#define ADD_CACHE_OK_TO_ADD 1		
#define ADD_CACHE_OK_TO_REPLACE 2	
#define ADD_CACHE_PRETEND 2
#define ADD_CACHE_SKIP_DFCHECK 4	
#define ADD_CACHE_VERBOSE 1
#define ALLOC_GROW(x, nr, alloc) \
	do { \
		if ((nr) > alloc) { \
			if (alloc_nr(alloc) < (nr)) \
				alloc = (nr); \
			else \
				alloc = alloc_nr(alloc); \
			REALLOC_ARRAY(x, alloc); \
		} \
	} while (0)
#define ALTERNATE_DB_ENVIRONMENT "GIT_ALTERNATE_OBJECT_DIRECTORIES"
#define ATTRIBUTE_MACRO_PREFIX "[attr]"
#define CACHE_DEF_INIT { STRBUF_INIT, 0, 0, 0 }

#define CACHE_SIGNATURE 0x44495243	
#define CEILING_DIRECTORIES_ENVIRONMENT "GIT_CEILING_DIRECTORIES"
#define CE_ADDED             (1 << 19)
#define CE_CONFLICTED        (1 << 23)
#define CE_EXTENDED  (0x4000)
#define CE_EXTENDED2         (1U << 31)
#define CE_EXTENDED_FLAGS (CE_INTENT_TO_ADD | CE_SKIP_WORKTREE)
#define CE_HASHED            (1 << 20)
#define CE_INTENT_TO_ADD     (1 << 29)
#define CE_MATCHED           (1 << 26)
#define CE_NEW_SKIP_WORKTREE (1 << 25)
#define CE_REMOVE            (1 << 17)
#define CE_SKIP_WORKTREE     (1 << 30)
#define CE_STAGEMASK (0x3000)
#define CE_STAGESHIFT 12
#define CE_STRIP_NAME        (1 << 28)
#define CE_UNPACKED          (1 << 24)
#define CE_UPDATE            (1 << 16)
#define CE_UPDATE_IN_BASE    (1 << 27)
#define CE_UPTODATE          (1 << 18)
#define CE_VALID     (0x8000)
#define CE_WT_REMOVE         (1 << 22) 
#define CHECKOUT_INIT { NULL, "" }
#define CONFIG_DATA_ENVIRONMENT "GIT_CONFIG_PARAMETERS"
#define CONFIG_ENVIRONMENT "GIT_CONFIG"
#define COPY_READ_ERROR (-2)
#define COPY_WRITE_ERROR (-3)
#define DATA_CHANGED    0x0020
#define DATE_MODE(t) date_mode_from_type(DATE_##t)
#define DB_ENVIRONMENT "GIT_OBJECT_DIRECTORY"
#define DEFAULT_ABBREV default_abbrev
#define DEFAULT_GIT_DIR_ENVIRONMENT ".git"
#define DEFAULT_GIT_PORT 9418
#define DTYPE(de)	((de)->d_type)
#define EMPTY_BLOB_SHA1_BIN (empty_blob_oid.hash)
#define EMPTY_BLOB_SHA1_BIN_LITERAL \
	"\xe6\x9d\xe2\x9b\xb2\xd1\xd6\x43\x4b\x8b" \
	"\x29\xae\x77\x5a\xd8\xc2\xe4\x8c\x53\x91"
#define EMPTY_BLOB_SHA1_HEX \
	"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
#define EMPTY_TREE_SHA1_BIN (empty_tree_oid.hash)
#define EMPTY_TREE_SHA1_BIN_LITERAL \
	 "\x4b\x82\x5d\xc6\x42\xcb\x6e\xb9\xa0\x60" \
	 "\xe5\x4b\xf8\xd6\x92\x88\xfb\xee\x49\x04"
#define EMPTY_TREE_SHA1_HEX \
	"4b825dc642cb6eb9a060e54bf8d69288fbee4904"
#define EXEC_PATH_ENVIRONMENT "GIT_EXEC_PATH"
#define FALLBACK_DEFAULT_ABBREV 7
#define FOR_EACH_OBJECT_LOCAL_ONLY 0x1
#define GET_SHA1_BLOB             040
#define GET_SHA1_COMMIT            02
#define GET_SHA1_COMMITTISH        04
#define GET_SHA1_DISAMBIGUATORS \
	(GET_SHA1_COMMIT | GET_SHA1_COMMITTISH | \
	GET_SHA1_TREE | GET_SHA1_TREEISH | \
	GET_SHA1_BLOB)
#define GET_SHA1_FOLLOW_SYMLINKS 0100
#define GET_SHA1_ONLY_TO_DIE    04000
#define GET_SHA1_QUIETLY           01
#define GET_SHA1_RECORD_PATH     0200
#define GET_SHA1_TREE             010
#define GET_SHA1_TREEISH          020
#define GITATTRIBUTES_FILE ".gitattributes"
#define GIT_COMMON_DIR_ENVIRONMENT "GIT_COMMON_DIR"
#define GIT_DIR_ENVIRONMENT "GIT_DIR"
#define GIT_GLOB_PATHSPECS_ENVIRONMENT "GIT_GLOB_PATHSPECS"
#define GIT_ICASE_PATHSPECS_ENVIRONMENT "GIT_ICASE_PATHSPECS"
#define GIT_IMPLICIT_WORK_TREE_ENVIRONMENT "GIT_IMPLICIT_WORK_TREE"
#define GIT_LITERAL_PATHSPECS_ENVIRONMENT "GIT_LITERAL_PATHSPECS"
#define GIT_MAX_HEXSZ GIT_SHA1_HEXSZ
#define GIT_MAX_RAWSZ GIT_SHA1_RAWSZ
#define GIT_NAMESPACE_ENVIRONMENT "GIT_NAMESPACE"
#define GIT_NOGLOB_PATHSPECS_ENVIRONMENT "GIT_NOGLOB_PATHSPECS"
#define GIT_NOTES_DEFAULT_REF "refs/notes/commits"
#define GIT_NOTES_DISPLAY_REF_ENVIRONMENT "GIT_NOTES_DISPLAY_REF"
#define GIT_NOTES_REF_ENVIRONMENT "GIT_NOTES_REF"
#define GIT_NOTES_REWRITE_MODE_ENVIRONMENT "GIT_NOTES_REWRITE_MODE"
#define GIT_NOTES_REWRITE_REF_ENVIRONMENT "GIT_NOTES_REWRITE_REF"
#define GIT_PREFIX_ENVIRONMENT "GIT_PREFIX"
#define GIT_QUARANTINE_ENVIRONMENT "GIT_QUARANTINE_PATH"
#define GIT_REPLACE_REF_BASE_ENVIRONMENT "GIT_REPLACE_REF_BASE"
#define GIT_REPO_VERSION 0
#define GIT_REPO_VERSION_READ 1
#define GIT_SHA1_HEXSZ (2 * GIT_SHA1_RAWSZ)
#define GIT_SHA1_RAWSZ 20
#define GIT_SHALLOW_FILE_ENVIRONMENT "GIT_SHALLOW_FILE"
#define GIT_SUPER_PREFIX_ENVIRONMENT "GIT_INTERNAL_SUPER_PREFIX"
#define GIT_TOPLEVEL_PREFIX_ENVIRONMENT "GIT_INTERNAL_TOPLEVEL_PREFIX"
#define GIT_WORK_TREE_ENVIRONMENT "GIT_WORK_TREE"
#define GRAFT_ENVIRONMENT "GIT_GRAFT_FILE"
#define HASH_FORMAT_CHECK 2
#define HASH_WRITE_OBJECT 1
#define INDEX_ENVIRONMENT "GIT_INDEX_FILE"
#define INDEX_FORMAT_LB 2
#define INDEX_FORMAT_UB 4
#define INFOATTRIBUTES_FILE "info/attributes"
#define INIT_DB_EXIST_OK 0x0002
#define INIT_DB_QUIET 0x0001
#define INODE_CHANGED   0x0010
#define INTERPRET_BRANCH_HEAD (1<<2)
#define INTERPRET_BRANCH_LOCAL (1<<0)
#define INTERPRET_BRANCH_REMOTE (1<<1)
#define MINIMUM_ABBREV minimum_abbrev
#define MODE_CHANGED    0x0008
#define NO_REPLACE_OBJECTS_ENVIRONMENT "GIT_NO_REPLACE_OBJECTS"
#define OBJECT_INFO_ALLOW_UNKNOWN_TYPE 2
#define OBJECT_INFO_INIT {NULL}
#define OBJECT_INFO_LOOKUP_REPLACE 1
#define OBJECT_INFO_QUICK 8
#define OBJECT_INFO_SKIP_CACHED 4
#define PACKDIR_FILE_GARBAGE 4
#define PACKDIR_FILE_IDX 2
#define PACKDIR_FILE_PACK 1
#define READ_GITFILE_ERR_INVALID_FORMAT 5
#define READ_GITFILE_ERR_NOT_A_FILE 2
#define READ_GITFILE_ERR_NOT_A_REPO 7
#define READ_GITFILE_ERR_NO_PATH 6
#define READ_GITFILE_ERR_OPEN_FAILED 3
#define READ_GITFILE_ERR_READ_FAILED 4
#define READ_GITFILE_ERR_STAT_FAILED 1
#define READ_GITFILE_ERR_TOO_LARGE 8
#define S_IFINVALID     0030000
#define S_ISGITLINK(m)	(((m) & S_IFMT) == S_IFGITLINK)
#define TEMPLATE_DIR_ENVIRONMENT "GIT_TEMPLATE_DIR"
#define TEMPORARY_FILENAME_LENGTH 25
#define TYPE_CHANGED    0x0040
#define WS_BLANK_AT_EOF        02000
#define WS_BLANK_AT_EOL         0100
#define WS_CR_AT_EOL           01000
#define WS_DEFAULT_RULE (WS_TRAILING_SPACE|WS_SPACE_BEFORE_TAB|8)
#define WS_INDENT_WITH_NON_TAB  0400
#define WS_SPACE_BEFORE_TAB     0200
#define WS_TAB_IN_INDENT       04000
#define WS_TAB_WIDTH_MASK        077
#define WS_TRAILING_SPACE      (WS_BLANK_AT_EOL|WS_BLANK_AT_EOF)
#define active_alloc (the_index.cache_alloc)
#define active_cache (the_index.cache)
#define active_cache_changed (the_index.cache_changed)
#define active_cache_tree (the_index.cache_tree)
#define active_nr (the_index.cache_nr)
#define add_cache_entry(ce, option) add_index_entry(&the_index, (ce), (option))
#define add_file_to_cache(path, flags) add_file_to_index(&the_index, (path), (flags))
#define add_to_cache(path, st, flags) add_to_index(&the_index, (path), (st), (flags))
#define alloc_nr(x) (((x)+16)*3/2)
#define approxidate(s) approxidate_careful((s), NULL)
#define cache_dir_exists(name, namelen) index_dir_exists(&the_index, (name), (namelen))
#define cache_entry_size(len) (offsetof(struct cache_entry,name) + (len) + 1)
#define cache_file_exists(name, namelen, igncase) index_file_exists(&the_index, (name), (namelen), (igncase))
#define cache_name_is_other(name, namelen) index_name_is_other(&the_index, (name), (namelen))
#define cache_name_pos(name, namelen) index_name_pos(&the_index,(name),(namelen))
#define ce_intent_to_add(ce) ((ce)->ce_flags & CE_INTENT_TO_ADD)
#define ce_mark_uptodate(ce) ((ce)->ce_flags |= CE_UPTODATE)
#define ce_match_stat(ce, st, options) ie_match_stat(&the_index, (ce), (st), (options))
#define ce_modified(ce, st, options) ie_modified(&the_index, (ce), (st), (options))
#define ce_namelen(ce) ((ce)->ce_namelen)
#define ce_permissions(mode) (((mode) & 0100) ? 0755 : 0644)
#define ce_size(ce) cache_entry_size(ce_namelen(ce))
#define ce_skip_worktree(ce) ((ce)->ce_flags & CE_SKIP_WORKTREE)
#define ce_stage(ce) ((CE_STAGEMASK & (ce)->ce_flags) >> CE_STAGESHIFT)
#define ce_uptodate(ce) ((ce)->ce_flags & CE_UPTODATE)
#define chmod_cache_entry(ce, flip) chmod_index_entry(&the_index, (ce), (flip))
#define discard_cache() discard_index(&the_index)
#define git_open(name) git_open_cloexec(name, O_RDONLY)
#define is_cache_unborn() is_index_unborn(&the_index)
#define platform_SHA1_Final    	SHA1_Final
#define read_blob_data_from_cache(path, sz) read_blob_data_from_index(&the_index, (path), (sz))
#define read_cache() read_index(&the_index)
#define read_cache_from(path) read_index_from(&the_index, (path))
#define read_cache_preload(pathspec) read_index_preload(&the_index, (pathspec))
#define read_cache_unmerged() read_index_unmerged(&the_index)
#define read_gitfile(path) read_gitfile_gently((path), NULL)
#define refresh_cache(flags) refresh_index(&the_index, (flags), NULL, NULL, NULL)
#define remove_cache_entry_at(pos) remove_index_entry_at(&the_index, (pos))
#define remove_file_from_cache(path) remove_file_from_index(&the_index, (path))
#define rename_cache_entry_at(pos, new_name) rename_index_entry_at(&the_index, (pos), (new_name))
#define resolve_gitdir(path) resolve_gitdir_gently((path), NULL)
#define resolve_undo_clear() resolve_undo_clear_index(&the_index)
#define unmerge_cache(pathspec) unmerge_index(&the_index, pathspec)
#define unmerge_cache_entry_at(at) unmerge_index_entry_at(&the_index, at)
#define unmerged_cache() unmerged_index(&the_index)
#define ws_tab_width(rule)     ((rule) & WS_TAB_WIDTH_MASK)
#define OID_ARRAY_INIT { NULL, 0, 0, 0 }

#define GIT_PATH_FUNC(func, filename) \
	const char *func(void) \
	{ \
		static char *ret; \
		if (!ret) \
			ret = git_pathdup(filename); \
		return ret; \
	}




# define TRACE_CONTEXT "__FILE__"

#define TRACE_KEY_INIT(name) { "GIT_TRACE_" #name, 0, 0, 0 }
#define trace_argv_printf(argv, ...) \
	trace_argv_printf_fl(TRACE_CONTEXT, "__LINE__", argv, __VA_ARGS__)
#define trace_performance(nanos, ...) \
	trace_performance_fl(TRACE_CONTEXT, "__LINE__", nanos, __VA_ARGS__)
#define trace_performance_since(start, ...) \
	trace_performance_fl(TRACE_CONTEXT, "__LINE__", getnanotime() - (start), \
			     __VA_ARGS__)
#define trace_printf(...) \
	trace_printf_key_fl(TRACE_CONTEXT, "__LINE__", NULL, __VA_ARGS__)
#define trace_printf_key(key, ...) \
	trace_printf_key_fl(TRACE_CONTEXT, "__LINE__", key, __VA_ARGS__)
#define trace_strbuf(key, data) \
	trace_strbuf_fl(TRACE_CONTEXT, "__LINE__", key, data)
#define ACCESS_EACCES_OK (1U << 0)
#define ALLOC_ARRAY(x, alloc) (x) = xmalloc(st_mult(sizeof(*(x)), (alloc)))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]) + BARF_UNLESS_AN_ARRAY(x))
# define BARF_UNLESS_AN_ARRAY(arr)						\
	BUILD_ASSERT_OR_ZERO(!__builtin_types_compatible_p(__typeof__(arr), \
							   __typeof__(&(arr)[0])))
#define BUG(...) BUG_fl("__FILE__", "__LINE__", __VA_ARGS__)
#define BUILD_ASSERT_OR_ZERO(cond) \
	(sizeof(char [1 - 2*!(cond)]) - 1)
#define COPY_ARRAY(dst, src, n) copy_array((dst), (src), (n), sizeof(*(dst)) + \
	BUILD_ASSERT_OR_ZERO(sizeof(*(dst)) == sizeof(*(src))))
#define DEFAULT_PACKED_GIT_LIMIT \
	((1024L * 1024L) * (size_t)(sizeof(void*) >= 8 ? (32 * 1024L * 1024L) : 256))
#define DEFAULT_PACKED_GIT_WINDOW_SIZE (1 * 1024 * 1024)

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define FLEXPTR_ALLOC_MEM(x, ptrname, buf, len) do { \
	size_t flex_array_len_ = (len); \
	(x) = xcalloc(1, st_add3(sizeof(*(x)), flex_array_len_, 1)); \
	memcpy((x) + 1, (buf), flex_array_len_); \
	(x)->ptrname = (void *)((x)+1); \
} while(0)
#define FLEXPTR_ALLOC_STR(x, ptrname, str) \
	FLEXPTR_ALLOC_MEM((x), ptrname, (str), strlen(str))
#define FLEX_ALLOC_MEM(x, flexname, buf, len) do { \
	size_t flex_array_len_ = (len); \
	(x) = xcalloc(1, st_add3(sizeof(*(x)), flex_array_len_, 1)); \
	memcpy((void *)(x)->flexname, (buf), flex_array_len_); \
} while (0)
#define FLEX_ALLOC_STR(x, flexname, str) \
	FLEX_ALLOC_MEM((x), flexname, (str), strlen(str))
#  define FLEX_ARRAY 
# define FORCE_DIR_SET_GID S_ISGID
#define FREE_AND_NULL(p) do { free(p); (p) = NULL; } while (0)
#define GIT_ALPHA 0x04
#define GIT_CNTRL 0x40

#define GIT_DIGIT 0x02
#define GIT_GLOB_SPECIAL 0x08
 #define GIT_GNUC_PREREQ(maj, min) 0
#define GIT_PATHSPEC_MAGIC 0x20
#define GIT_PUNCT 0x80
#define GIT_REGEX_SPECIAL 0x10
#define GIT_SPACE 0x01

#define HAS_MULTI_BITS(i)  ((i) & ((i) - 1))  

#define HAVE_VARIADIC_MACROS 1
#define HOST_NAME_MAX 256
#define LAST_ARG_MUST_BE_NULL __attribute__((sentinel))
#define MAP_FAILED ((void *)-1)
#define MAP_PRIVATE 1
#define MOVE_ARRAY(dst, src, n) move_array((dst), (src), (n), sizeof(*(dst)) + \
	BUILD_ASSERT_OR_ZERO(sizeof(*(dst)) == sizeof(*(src))))
#define MSB(x, bits) ((x) & TYPEOF(x)(~0ULL << (bitsizeof(x) - (bits))))
#define NI_MAXHOST 1025
#define NI_MAXSERV 32
#define NORETURN __attribute__((noreturn))
#define NORETURN_PTR __attribute__((__noreturn__))
#define O_CLOEXEC 0
#define PATH_MAX 4096
#define PATH_SEP ':'
#define PRIo32 "o"
#define PRItime PRIuMAX
#define PRIu32 "u"
#define PRIuMAX "llu"
#define PRIx32 "x"
#define PROT_READ 1
#define PROT_WRITE 2
#define QSORT(base, n, compar) sane_qsort((base), (n), sizeof(*(base)), compar)
#define QSORT_S(base, n, compar, ctx) do {			\
	if (qsort_s((base), (n), sizeof(*(base)), compar, ctx))	\
		die("BUG: qsort_s() failed");			\
} while (0)
#define REALLOC_ARRAY(x, alloc) (x) = xrealloc((x), st_mult(sizeof(*(x)), (alloc)))
#define SCNuMAX PRIuMAX
# define SHELL_PATH "/bin/sh"
#define ST_CTIME_NSEC(st) 0
#define ST_MTIME_NSEC(st) 0
#define SWAP(a, b) do {						\
	void *_swap_a_ptr = &(a);				\
	void *_swap_b_ptr = &(b);				\
	unsigned char _swap_buffer[sizeof(a)];			\
	memcpy(_swap_buffer, _swap_a_ptr, sizeof(a));		\
	memcpy(_swap_a_ptr, _swap_b_ptr, sizeof(a) +		\
	       BUILD_ASSERT_OR_ZERO(sizeof(a) == sizeof(b)));	\
	memcpy(_swap_b_ptr, _swap_buffer, sizeof(a));		\
} while (0)
#define S_IFBLK  0060000
#define S_IFCHR  0020000
#define S_IFDIR  0040000
#define S_IFIFO  0010000
#define S_IFLNK  0120000
#define S_IFMT   0170000
#define S_IFREG  0100000
#define S_IFSOCK 0140000
#define TIME_MAX UINTMAX_MAX
#define TYPEOF(x) (__typeof__(x))
#define USE_PARENS_AROUND_GETTEXT_N 1
#define WIN32_LEAN_AND_MEAN  
#define _ALL_SOURCE 1
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE 1
#define _NETBSD_SOURCE 1
#define _PATH_DEFPATH "/usr/local/bin:/usr/bin:/bin"
#define _SGI_SOURCE 1
#  define _WIN32_WINNT 0x0502
# define _XOPEN_SOURCE 600
#define _XOPEN_SOURCE_EXTENDED 1 
#define __AVAILABILITY_MACROS_USES_AVAILABILITY 0

#define atexit git_atexit
#define basename gitbasename
#define bitsizeof(x)  (CHAR_BIT * sizeof(x))
#define decimal_length(x)	((int)(sizeof(x) * 2.56 + 0.5) + 1)
#define dirname gitdirname
#define error(...) (error(__VA_ARGS__), const_error())
#define error_errno(...) (error_errno(__VA_ARGS__), const_error())
#define find_last_dir_sep git_find_last_dir_sep

#  define fopen(a,b) git_fopen(a,b)
#define fstat(fd, buf) git_fstat(fd, buf)
#define fstat_is_reliable() 0

#define getc_unlocked(fh) getc(fh)
#define getpagesize() sysconf(_SC_PAGESIZE)
#define gmtime git_gmtime
#define gmtime_r git_gmtime_r
#define has_dos_drive_prefix git_has_dos_drive_prefix
#define hstrerror githstrerror
#define is_dir_sep git_is_dir_sep
#define is_glob_special(x) sane_istest(x,GIT_GLOB_SPECIAL)
#define is_pathspec_magic(x) sane_istest(x,GIT_PATHSPEC_MAGIC)
#define is_regex_special(x) sane_istest(x,GIT_GLOB_SPECIAL | GIT_REGEX_SPECIAL)
#define isalnum(x) sane_istest(x,GIT_ALPHA | GIT_DIGIT)
#define isalpha(x) sane_istest(x,GIT_ALPHA)
#define isascii(x) (((x) & ~0x7f) == 0)
#define iscntrl(x) (sane_istest(x,GIT_CNTRL))
#define isdigit(x) sane_istest(x,GIT_DIGIT)
#define islower(x) sane_iscase(x, 1)
#define isprint(x) ((x) >= 0x20 && (x) <= 0x7e)
#define ispunct(x) sane_istest(x, GIT_PUNCT | GIT_REGEX_SPECIAL | \
		GIT_GLOB_SPECIAL | GIT_PATHSPEC_MAGIC)
#define isspace(x) sane_istest(x,GIT_SPACE)
#define isupper(x) sane_iscase(x, 0)
#define isxdigit(x) (hexval_table[(unsigned char)(x)] != -1)
#define lstat(path, buf) git_lstat(path, buf)
#define maximum_signed_value_of_type(a) \
    (INTMAX_MAX >> (bitsizeof(intmax_t) - bitsizeof(a)))
#define maximum_unsigned_value_of_type(a) \
    (UINTMAX_MAX >> (bitsizeof(uintmax_t) - bitsizeof(a)))
#define memmem gitmemmem
#define mkdir(a,b) compat_mkdir_wo_trailing_slash((a),(b))
#define mkdtemp gitmkdtemp
#define mmap git_mmap
#define munmap git_munmap
#define offset_1st_component git_offset_1st_component
#define on_disk_bytes(st) ((st).st_size)
#define parse_timestamp strtoumax
#define pread git_pread



#define qsort git_qsort
#define qsort_s git_qsort_s
#define sane_istest(x,mask) ((sane_ctype[(unsigned char)(x)] & (mask)) != 0)
#define setenv gitsetenv

#define signed_add_overflows(a, b) \
    ((b) > maximum_signed_value_of_type(a) - (a))
#define skip_dos_drive_prefix git_skip_dos_drive_prefix
#define snprintf git_snprintf
#define st_add3(a,b,c)   st_add(st_add((a),(b)),(c))
#define st_add4(a,b,c,d) st_add(st_add3((a),(b),(c)),(d))
#define stat(path, buf) git_stat(path, buf)
#define strcasestr gitstrcasestr
#define strchrnul gitstrchrnul
#define strdup gitstrdup
#define strlcpy gitstrlcpy
#define strtoimax gitstrtoimax
#define strtoumax gitstrtoumax
#define tolower(x) sane_case((unsigned char)(x), 0x20)
#define toupper(x) sane_case((unsigned char)(x), 0)
#define unsetenv gitunsetenv
#define unsigned_add_overflows(a, b) \
    ((b) > maximum_unsigned_value_of_type(a) - (a))
#define unsigned_mult_overflows(a, b) \
    ((a) && (b) > maximum_unsigned_value_of_type(a) / (a))
#define va_copy(dst, src) __va_copy(dst, src)
#define vsnprintf git_vsnprintf
# define xalloca(size)      (alloca(size))
# define xalloca_free(p)    do {} while (0)

#define EVP_DecodeBlock git_CC_EVP_DecodeBlock
#define EVP_EncodeBlock git_CC_EVP_EncodeBlock
#define EVP_md5(...) kCCHmacAlgMD5


#define HMAC git_CC_HMAC

#define git_CC_error_check(pattern, err) \
	do { \
		if (err) { \
			die(pattern, (long)CFErrorGetCode(err)); \
		} \
	} while(0)

#define WM_ABORT_ALL -1
#define WM_ABORT_MALFORMED 2
#define WM_ABORT_TO_STARSTAR -2
#define WM_CASEFOLD 1
#define WM_MATCH 0
#define WM_NOMATCH 1
#define WM_PATHNAME 2
# define GIT_BIG_ENDIAN __BIG_ENDIAN
#  define GIT_BYTE_ORDER GIT_BIG_ENDIAN
# define GIT_LITTLE_ENDIAN __LITTLE_ENDIAN
#define bswap32 git_bswap32
#define bswap64 git_bswap64
#define get_be16(p)	ntohs(*(unsigned short *)(p))
#define get_be32(p)	ntohl(*(unsigned int *)(p))
#define htonl(x) bswap32(x)
# define htonll(n) (n)
#define ntohl(x) bswap32(x)
# define ntohll(n) (n)
#define put_be32(p, v)	do { *(unsigned int *)(p) = htonl(v); } while (0)
#define DIR PREC_DIR
#define  PRECOMPOSE_UNICODE_H
#define closedir(d) precompose_utf8_closedir(d)
#define dirent dirent_prec_psx
#define opendir(n) precompose_utf8_opendir(n)
#define readdir(d) precompose_utf8_readdir(d)

#define __inline__ __inline
#define ftruncate    _chsize
#define inline __inline
#define strncasecmp  _strnicmp
#define strtoll      _strtoi64
#define strtoull     _strtoui64
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define ECONNABORTED WSAECONNABORTED
#define ELOOP EMLINK
#define ENOTSOCK WSAENOTSOCK
#define EWOULDBLOCK EAGAIN
#define FD_CLOEXEC 0x1
#define F_GETFD 1
#define F_SETFD 2
#define ITIMER_REAL 0
#define PRId64 "I64d"
#define RLIMIT_NOFILE 0
#define SA_RESTART 0
#define SHUT_WR SD_SEND
#define SIGALRM 14
#define SIGCHLD 17
#define SIGHUP 1
#define SIGKILL 9
#define SIGPIPE 13
#define SIGQUIT 3
#define SIG_BLOCK 0
#define SIG_UNBLOCK 0
#define SSL_set_fd mingw_SSL_set_fd
#define SSL_set_rfd mingw_SSL_set_rfd
#define SSL_set_wfd mingw_SSL_set_wfd
#define S_IRGRP 0
#define S_IROTH 0
#define S_IRWXG (S_IRGRP | S_IWGRP | S_IXGRP)
#define S_IRWXO (S_IROTH | S_IWOTH | S_IXOTH)
#define S_ISGID 0002000
#define S_ISLNK(x) (((x) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(x) 0
#define S_ISUID 0004000
#define S_ISVTX 0001000
#define S_IWGRP 0
#define S_IWOTH 0
#define S_IXGRP 0
#define S_IXOTH 0
#define WEXITSTATUS(x) ((x) & 0xff)
#define WIFEXITED(x) 1
#define WIFSIGNALED(x) 0
#define WNOHANG 1
#define WTERMSIG(x) SIGTERM
# define _stat32i64(x,y) mingw_stat(x,y)
# define _stat64(x,y) mingw_stat(x,y)
# define _stati64(x,y) mingw_stat(x,y)
#define accept mingw_accept
#define access mingw_access
#define bind mingw_bind
#define chdir mingw_chdir
#define chmod mingw_chmod
#define connect mingw_connect
#define execv mingw_execv
#define execvp mingw_execvp
#define exit(code) exit((code) & 0xff)
#define fflush mingw_fflush
#define fgetc mingw_fgetc
#define freeaddrinfo mingw_freeaddrinfo
#define freopen mingw_freopen
#define getaddrinfo mingw_getaddrinfo
#define getcwd mingw_getcwd
#define getenv mingw_getenv
#define gethostbyname mingw_gethostbyname
#define gethostname mingw_gethostname
#define getnameinfo mingw_getnameinfo
#define isatty winansi_isatty
#define kill mingw_kill
#define listen mingw_listen
#define lseek _lseeki64
#define main(c,v) dummy_decl_mingw_main(void); \
static int mingw_main(c,v); \
int main(int argc, const char **argv) \
{ \
	mingw_startup(); \
	return mingw_main(__argc, (void *)__argv); \
} \
static int mingw_main(c,v)
#define mktemp mingw_mktemp
#define off_t off64_t
#define open mingw_open
#define putenv mingw_putenv
#define raise mingw_raise
#define rename mingw_rename
#define rmdir mingw_rmdir
#define setsockopt mingw_setsockopt
#define shutdown mingw_shutdown
#define sigemptyset(x) (void)0
#define signal mingw_signal
#define socket mingw_socket
#define unlink mingw_unlink
#define utime mingw_utime
#define write mingw_write

#define FORMAT_PRESERVING(n) __attribute__((format_arg(n)))

#define N_(msgid) msgid
#define use_gettext_poison() 0



#define DEFAULT_MERGE_LOG_LEN 20
#define PRUNE_PACKED_DRY_RUN 01
#define PRUNE_PACKED_VERBOSE 02

#define INFINITE_DEPTH 0x7fffffff
#define merge_remote_util(commit) ((struct merge_remote_desc *)((commit)->util))


#define READ_TREE_RECURSIVE 1

#define FLAG_BITS  27
#define OBJECT_ARRAY_INIT { 0, 0, NULL }

#define TYPE_BITS   3
#define type_from_string(str) type_from_string_gently(str, -1, 0)
