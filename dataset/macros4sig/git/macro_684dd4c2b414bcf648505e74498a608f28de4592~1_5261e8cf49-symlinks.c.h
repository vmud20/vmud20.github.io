
#include<sys/socket.h>
#include<sys/resource.h>

#include<utime.h>
#include<wchar.h>
#include<sys/mman.h>
#include<sys/utsname.h>
#include<termios.h>
#include<limits.h>
#include<syslog.h>


#include<sys/un.h>

#include<poll.h>
#include<errno.h>
#include<iconv.h>
#include<fcntl.h>
#include<arpa/inet.h>
#include<dirent.h>


#include<strings.h>
#include<stdint.h>

#include<regex.h>


#include<netinet/tcp.h>
#include<sys/stat.h>
#include<grp.h>
#include<assert.h>


#include<sys/ioctl.h>
#include<sys/types.h>
#include<pwd.h>
#include<sys/select.h>



#include<inttypes.h>
#include<netdb.h>
#include<time.h>

#include<zlib.h>
#include<netinet/in.h>
#include<sys/poll.h>
#include<sys/param.h>
#include<stdlib.h>
#include<sys/sysctl.h>
#include<paths.h>
#include<stdio.h>


#include<stdarg.h>
#include<malloc.h>
#include<signal.h>
#include<sys/wait.h>
#include<stddef.h>



#include<sys/time.h>

#include<string.h>
#include<unistd.h>

#include<libgen.h>
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
#define CE_FSMONITOR_VALID   (1 << 21)
#define CE_HASHED            (1 << 20)
#define CE_INTENT_TO_ADD     (1 << 29)
#define CE_MATCHED           (1 << 26)
#define CE_MATCH_IGNORE_FSMONITOR 0X20
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
#define GET_OID_BLOB             040
#define GET_OID_COMMIT            02
#define GET_OID_COMMITTISH        04
#define GET_OID_DISAMBIGUATORS \
	(GET_OID_COMMIT | GET_OID_COMMITTISH | \
	GET_OID_TREE | GET_OID_TREEISH | \
	GET_OID_BLOB)
#define GET_OID_FOLLOW_SYMLINKS 0100
#define GET_OID_ONLY_TO_DIE    04000
#define GET_OID_QUIETLY           01
#define GET_OID_RECORD_PATH     0200
#define GET_OID_TREE             010
#define GET_OID_TREEISH          020
#define GITATTRIBUTES_FILE ".gitattributes"
#define GITMODULES_FILE ".gitmodules"
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
#define GIT_OPTIONAL_LOCKS_ENVIRONMENT "GIT_OPTIONAL_LOCKS"
#define GIT_PREFIX_ENVIRONMENT "GIT_PREFIX"
#define GIT_PROTOCOL_ENVIRONMENT "GIT_PROTOCOL"
#define GIT_PROTOCOL_HEADER "Git-Protocol"
#define GIT_QUARANTINE_ENVIRONMENT "GIT_QUARANTINE_PATH"
#define GIT_REPLACE_REF_BASE_ENVIRONMENT "GIT_REPLACE_REF_BASE"
#define GIT_REPO_VERSION 0
#define GIT_REPO_VERSION_READ 1
#define GIT_SHA1_HEXSZ (2 * GIT_SHA1_RAWSZ)
#define GIT_SHA1_RAWSZ 20
#define GIT_SHALLOW_FILE_ENVIRONMENT "GIT_SHALLOW_FILE"
#define GIT_SUPER_PREFIX_ENVIRONMENT "GIT_INTERNAL_SUPER_PREFIX"
#define GIT_WORK_TREE_ENVIRONMENT "GIT_WORK_TREE"
#define GRAFT_ENVIRONMENT "GIT_GRAFT_FILE"
#define HASH_FORMAT_CHECK 2
#define HASH_RENORMALIZE  4
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
#define WS_RULE_MASK           07777
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
#define read_blob_data_from_cache(path, sz) read_blob_data_from_index(&the_index, (path), (sz))
#define read_cache() read_index(&the_index)
#define read_cache_from(path) read_index_from(&the_index, (path), (get_git_dir()))
#define read_cache_preload(pathspec) read_index_preload(&the_index, (pathspec))
#define read_cache_unmerged() read_index_unmerged(&the_index)
#define read_gitfile(path) read_gitfile_gently((path), NULL)
#define refresh_cache(flags) refresh_index(&the_index, (flags), NULL, NULL, NULL)
#define remove_cache_entry_at(pos) remove_index_entry_at(&the_index, (pos))
#define remove_file_from_cache(path) remove_file_from_index(&the_index, (path))
#define rename_cache_entry_at(pos, new_name) rename_index_entry_at(&the_index, (pos), (new_name))
#define resolve_gitdir(path) resolve_gitdir_gently((path), NULL)
#define resolve_undo_clear() resolve_undo_clear_index(&the_index)
#define the_hash_algo the_repository->hash_algo
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

#define GIT_HASH_NALGOS (GIT_HASH_SHA1 + 1)
#define GIT_HASH_SHA1 1
#define GIT_HASH_UNKNOWN 0

#define git_SHA1_Update		git_SHA1_Update_Chunked
#define platform_SHA1_Final    	SHA1_Final
#define platform_SHA1_Init git_SHA1DCInit
#define platform_SHA1_Update git_SHA1DCUpdate
#define platform_SHA_CTX SHA1_CTX

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
#define UNLEAK(var) unleak_memory(&(var), sizeof(var))
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
#define is_valid_path(path) 1
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
#define va_copy(dst, src) ((dst) = (src))
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
#define get_be64(p)	ntohll(*(uint64_t *)(p))
#define htonl(x) bswap32(x)
# define htonll(n) (n)
#define ntohl(x) bswap32(x)
# define ntohll(n) (n)
#define put_be32(p, v)	do { *(unsigned int *)(p) = htonl(v); } while (0)
#define put_be64(p, v)	do { *(uint64_t *)(p) = htonll(v); } while (0)
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
#define strftime mingw_strftime
#define unlink mingw_unlink
#define utime mingw_utime
#define write mingw_write


#define STRING_LIST_INIT_DUP   { NULL, 0, 0, 1, NULL }
#define STRING_LIST_INIT_NODUP { NULL, 0, 0, 0, NULL }
#define for_each_string_list_item(item,list)            \
	for (item = (list)->items;                      \
	     item && item < (list)->items + (list)->nr; \
	     ++item)
# define TRACE_CONTEXT "__FILE__"

#define TRACE_KEY_INIT(name) { "GIT_TRACE_" #name, 0, 0, 0 }
#define trace_argv_printf(argv, ...)					    \
	do {								    \
		if (trace_pass_fl(&trace_default_key))			    \
			trace_argv_printf_fl(TRACE_CONTEXT, "__LINE__",	    \
					    argv, __VA_ARGS__);		    \
	} while (0)
#define trace_performance(nanos, ...)					    \
	do {								    \
		if (trace_pass_fl(&trace_perf_key))			    \
			trace_performance_fl(TRACE_CONTEXT, "__LINE__", nanos,\
					     __VA_ARGS__);		    \
	} while (0)
#define trace_performance_since(start, ...)				    \
	do {								    \
		if (trace_pass_fl(&trace_perf_key))			    \
			trace_performance_fl(TRACE_CONTEXT, "__LINE__",       \
					     getnanotime() - (start),	    \
					     __VA_ARGS__);		    \
	} while (0)
#define trace_printf(...) trace_printf_key(&trace_default_key, __VA_ARGS__)
#define trace_printf_key(key, ...)					    \
	do {								    \
		if (trace_pass_fl(key))					    \
			trace_printf_key_fl(TRACE_CONTEXT, "__LINE__", key,   \
					    __VA_ARGS__);		    \
	} while (0)
#define trace_strbuf(key, data)						    \
	do {								    \
		if (trace_pass_fl(key))					    \
			trace_strbuf_fl(TRACE_CONTEXT, "__LINE__", key, data);\
	} while (0)

#define STRBUF_INIT  { .alloc = 0, .len = 0, .buf = strbuf_slopbuf }
#define strbuf_reset(sb)  strbuf_setlen(sb, 0)

#define CONV_EOL_KEEP_CRLF    (1<<3) 
#define CONV_EOL_RENORMALIZE  (1<<2) 
#define CONV_EOL_RNDTRP_DIE   (1<<0) 
#define CONV_EOL_RNDTRP_WARN  (1<<1) 
#define FORMAT_PRESERVING(n) __attribute__((format_arg(n)))

#define N_(msgid) msgid
#define use_gettext_poison() 0

#define INIT_LIST_HEAD(ptr) \
	(ptr)->next = (ptr)->prev = (ptr)
#define LIST_HEAD(name) \
	struct list_head name = { &(name), &(name) }
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define VOLATILE_LIST_HEAD(name) \
	volatile struct volatile_list_head name = { &(name), &(name) }
#define list_entry(ptr, type, member) \
	((type *) ((char *) (ptr) - offsetof(type, member)))
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)
#define list_for_each_prev_safe(pos, p, head) \
	for (pos = (head)->prev, p = pos->prev; \
		pos != (head); \
		pos = p, p = pos->prev)
#define list_for_each_safe(pos, p, head) \
	for (pos = (head)->next, p = pos->next; \
		pos != (head); \
		pos = p, p = pos->next)

