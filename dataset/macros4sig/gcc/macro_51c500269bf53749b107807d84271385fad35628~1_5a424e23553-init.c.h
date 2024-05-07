#include<sys/types.h>
#include<stdarg.h>
#include<stdio.h>
#include<iconv.h>

#include<libintl.h>



#include<stddef.h>

#include<errno.h>

#include<string.h>

#include<ctype.h>



#define FILENAME_CMP(s1, s2)	filename_cmp(s1, s2)
#define HAS_DOS_DRIVE_SPEC(f) HAS_DRIVE_SPEC_1 (1, f)
#  define HAS_DRIVE_SPEC(f) HAS_DOS_DRIVE_SPEC (f)
#define HAS_DRIVE_SPEC_1(dos_based, f)			\
  ((f)[0] && ((f)[1] == ':') && (dos_based))
#    define HAVE_CASE_INSENSITIVE_FILE_SYSTEM 1
#    define HAVE_DOS_BASED_FILE_SYSTEM 1
#  define IS_ABSOLUTE_PATH(f) IS_DOS_ABSOLUTE_PATH (f)
#define IS_ABSOLUTE_PATH_1(dos_based, f)		 \
  (IS_DIR_SEPARATOR_1 (dos_based, (f)[0])		 \
   || HAS_DRIVE_SPEC_1 (dos_based, f))
#  define IS_DIR_SEPARATOR(c) IS_DOS_DIR_SEPARATOR (c)
#define IS_DIR_SEPARATOR_1(dos_based, c)				\
  (((c) == '/')								\
   || (((c) == '\\') && (dos_based)))
#define IS_DOS_ABSOLUTE_PATH(f) IS_ABSOLUTE_PATH_1 (1, f)
#define IS_DOS_DIR_SEPARATOR(c) IS_DIR_SEPARATOR_1 (1, c)
#define IS_UNIX_ABSOLUTE_PATH(f) IS_ABSOLUTE_PATH_1 (0, f)
#define IS_UNIX_DIR_SEPARATOR(c) IS_DIR_SEPARATOR_1 (0, c)
#define STRIP_DRIVE_SPEC(f)	((f) + 2)
#define HTAB_DELETED_ENTRY  ((PTR) 1)
#define HTAB_EMPTY_ENTRY    ((PTR) 0)

#define iterative_hash_object(OB,INIT) iterative_hash (&OB, sizeof (OB), INIT)
# define ARG_UNUSED(NAME) NAME ATTRIBUTE_UNUSED
#  define ATTRIBUTE_ALIGNED_ALIGNOF(m) __attribute__ ((__aligned__ (__alignof__ (m))))
#  define ATTRIBUTE_COLD __attribute__ ((__cold__))
#  define ATTRIBUTE_FPTR_PRINTF(m, n) ATTRIBUTE_PRINTF(m, n)
# define ATTRIBUTE_FPTR_PRINTF_1 ATTRIBUTE_FPTR_PRINTF(1, 2)
# define ATTRIBUTE_FPTR_PRINTF_2 ATTRIBUTE_FPTR_PRINTF(2, 3)
# define ATTRIBUTE_FPTR_PRINTF_3 ATTRIBUTE_FPTR_PRINTF(3, 4)
# define ATTRIBUTE_FPTR_PRINTF_4 ATTRIBUTE_FPTR_PRINTF(4, 5)
# define ATTRIBUTE_FPTR_PRINTF_5 ATTRIBUTE_FPTR_PRINTF(5, 6)
#  define ATTRIBUTE_HOT __attribute__ ((__hot__))
#  define ATTRIBUTE_MALLOC __attribute__ ((__malloc__))
#  define ATTRIBUTE_NONNULL(m) __attribute__ ((__nonnull__ (m)))
#  define ATTRIBUTE_NONSTRING __attribute__ ((__nonstring__))
#define ATTRIBUTE_NORETURN __attribute__ ((__noreturn__))
#  define ATTRIBUTE_NO_SANITIZE_UNDEFINED __attribute__ ((no_sanitize_undefined))
#  define ATTRIBUTE_NULL_PRINTF(m, n) __attribute__ ((__format__ (__printf__, m, n)))
# define ATTRIBUTE_NULL_PRINTF_1 ATTRIBUTE_NULL_PRINTF(1, 2)
# define ATTRIBUTE_NULL_PRINTF_2 ATTRIBUTE_NULL_PRINTF(2, 3)
# define ATTRIBUTE_NULL_PRINTF_3 ATTRIBUTE_NULL_PRINTF(3, 4)
# define ATTRIBUTE_NULL_PRINTF_4 ATTRIBUTE_NULL_PRINTF(4, 5)
# define ATTRIBUTE_NULL_PRINTF_5 ATTRIBUTE_NULL_PRINTF(5, 6)
# define ATTRIBUTE_PACKED __attribute__ ((packed))
#define ATTRIBUTE_PRINTF(m, n) __attribute__ ((__format__ (__printf__, m, n))) ATTRIBUTE_NONNULL(m)
#define ATTRIBUTE_PRINTF_1 ATTRIBUTE_PRINTF(1, 2)
#define ATTRIBUTE_PRINTF_2 ATTRIBUTE_PRINTF(2, 3)
#define ATTRIBUTE_PRINTF_3 ATTRIBUTE_PRINTF(3, 4)
#define ATTRIBUTE_PRINTF_4 ATTRIBUTE_PRINTF(4, 5)
#define ATTRIBUTE_PRINTF_5 ATTRIBUTE_PRINTF(5, 6)
#  define ATTRIBUTE_PURE __attribute__ ((__pure__))
#  define ATTRIBUTE_RESULT_SIZE_1 __attribute__ ((alloc_size (1)))
#  define ATTRIBUTE_RESULT_SIZE_1_2 __attribute__ ((alloc_size (1, 2)))
#  define ATTRIBUTE_RESULT_SIZE_2 __attribute__ ((alloc_size (2)))
#  define ATTRIBUTE_RETURNS_NONNULL __attribute__ ((__returns_nonnull__))
#  define ATTRIBUTE_SENTINEL __attribute__ ((__sentinel__))
#  define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#   define ATTRIBUTE_UNUSED_LABEL ATTRIBUTE_UNUSED
#  define ATTRIBUTE_WARN_UNUSED_RESULT __attribute__ ((warn_unused_result))
#define CONSTEXPR constexpr
#define DISABLE_COPY_AND_ASSIGN(TYPE)		\
  TYPE (const TYPE&) = delete;			\
  void operator= (const TYPE &) = delete
#define ENUM_BITFIELD(TYPE) enum TYPE
#define EXPORTED_CONST extern const
#   define FINAL
#define GCC_VERSION ("__GNUC__" * 1000 + "__GNUC_MINOR__")
#   define OVERRIDE
# define __attribute__(x)


# define CPPCHAR_SIGNED_T int
#define CPP_HASHNODE(HNODE)	((cpp_hashnode *) (HNODE))
#define CPP_N_CATEGORY  0x000F
#define HT_NODE(NODE)		(&(NODE)->ident)
#define INO_T_CPP ino_t ino[3]

#define NODE_CONDITIONAL (1 << 6)	
#define NODE_DIAGNOSTIC (1 << 2)	
#define NODE_LEN(NODE)		HT_LEN (HT_NODE (NODE))
#define NODE_MODULE (1 << 8)		
#define NODE_NAME(NODE)		HT_STR (HT_NODE (NODE))
#define NODE_WARN_OPERATOR (1 << 7)	
#define OP(e, s) CPP_ ## e,
#define PREV_FALLTHROUGH (1 << 5) 
#define TK(e, s) CPP_ ## e,

#define linemap_assert(EXPR)                  \
  do {                                                \
    if (! (EXPR))                             \
      abort ();                                       \
  } while (0)
#define linemap_assert_fails(EXPR) __extension__ \
  ({linemap_assert (EXPR); false;})
#define HT_HASHFINISH(r, len) ((r) + (len))
#define HT_HASHSTEP(r, c) ((r) * 67 + ((c) - 113));
#define HT_LEN(NODE) ((NODE)->len)
#define HT_STR(NODE) ((NODE)->str)

# define _CHUNK_SIZE_T unsigned long
# define _OBSTACK_CAST(type, expr) ((type) (expr))
#define _OBSTACK_H 1
# define _OBSTACK_INTERFACE_VERSION 2
# define _OBSTACK_SIZE_T unsigned int
#define __BPTR_ALIGN(B, P, A) ((B) + (((P) - (B) + (A)) & ~(A)))
#define __PTR_ALIGN(B, P, A)						\
  (sizeof (ptrdiff_t) < sizeof (void *) ? __BPTR_ALIGN (B, P, A)	\
   : (char *) (((ptrdiff_t) (P) + (A)) & ~(A)))
#  define __attribute_pure__ __attribute__ ((__pure__))
# define obstack_1grow(OBSTACK, datum)					      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);					      \
       if (obstack_room (__o) < 1)					      \
         _obstack_newchunk (__o, 1);					      \
       obstack_1grow_fast (__o, datum); })
#define obstack_1grow_fast(h, achar) ((void) (*((h)->next_free)++ = (achar)))
#define obstack_alignment_mask(h) ((h)->alignment_mask)
# define obstack_alloc(OBSTACK, length)					      \
  __extension__								      \
    ({ struct obstack *__h = (OBSTACK);					      \
       obstack_blank (__h, (length));					      \
       obstack_finish (__h); })
#define obstack_base(h) ((void *) (h)->object_base)
#define obstack_begin(h, size)						      \
  _obstack_begin ((h), (size), 0,					      \
                  _OBSTACK_CAST (void *(*) (size_t), obstack_chunk_alloc), \
                  _OBSTACK_CAST (void (*) (void *), obstack_chunk_free))
# define obstack_blank(OBSTACK, length)					      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);					      \
       _OBSTACK_SIZE_T __len = (length);				      \
       if (obstack_room (__o) < __len)					      \
         _obstack_newchunk (__o, __len);				      \
       obstack_blank_fast (__o, __len); })
#define obstack_blank_fast(h, n) ((void) ((h)->next_free += (n)))
#define obstack_chunk_size(h) ((h)->chunk_size)
#define obstack_chunkfun(h, newchunkfun)				      \
  ((void) ((h)->chunkfun.extra = (void *(*) (void *, size_t)) (newchunkfun)))
# define obstack_copy(OBSTACK, where, length)				      \
  __extension__								      \
    ({ struct obstack *__h = (OBSTACK);					      \
       obstack_grow (__h, (where), (length));				      \
       obstack_finish (__h); })
# define obstack_copy0(OBSTACK, where, length)				      \
  __extension__								      \
    ({ struct obstack *__h = (OBSTACK);					      \
       obstack_grow0 (__h, (where), (length));				      \
       obstack_finish (__h); })
# define obstack_empty_p(OBSTACK)					      \
  __extension__								      \
    ({ struct obstack const *__o = (OBSTACK);				      \
       (__o->chunk->prev == 0						      \
        && __o->next_free == __PTR_ALIGN ((char *) __o->chunk,		      \
                                          __o->chunk->contents,		      \
                                          __o->alignment_mask)); })
# define obstack_finish(OBSTACK)					      \
  __extension__								      \
    ({ struct obstack *__o1 = (OBSTACK);				      \
       void *__value = (void *) __o1->object_base;			      \
       if (__o1->next_free == __value)					      \
         __o1->maybe_empty_object = 1;					      \
       __o1->next_free							      \
         = __PTR_ALIGN (__o1->object_base, __o1->next_free,		      \
                        __o1->alignment_mask);				      \
       if ((size_t) (__o1->next_free - (char *) __o1->chunk)		      \
           > (size_t) (__o1->chunk_limit - (char *) __o1->chunk))	      \
         __o1->next_free = __o1->chunk_limit;				      \
       __o1->object_base = __o1->next_free;				      \
       __value; })
# define obstack_free(OBSTACK, OBJ)					      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);					      \
       void *__obj = (void *) (OBJ);					      \
       if (__obj > (void *) __o->chunk && __obj < (void *) __o->chunk_limit)  \
         __o->next_free = __o->object_base = (char *) __obj;		      \
       else								      \
         _obstack_free (__o, __obj); })
#define obstack_freefun(h, newfreefun)					      \
  ((void) ((h)->freefun.extra = (void *(*) (void *, void *)) (newfreefun)))
# define obstack_grow(OBSTACK, where, length)				      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);					      \
       _OBSTACK_SIZE_T __len = (length);				      \
       if (obstack_room (__o) < __len)					      \
         _obstack_newchunk (__o, __len);				      \
       memcpy (__o->next_free, where, __len);				      \
       __o->next_free += __len;						      \
       (void) 0; })
# define obstack_grow0(OBSTACK, where, length)				      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);					      \
       _OBSTACK_SIZE_T __len = (length);				      \
       if (obstack_room (__o) < __len + 1)				      \
         _obstack_newchunk (__o, __len + 1);				      \
       memcpy (__o->next_free, where, __len);				      \
       __o->next_free += __len;						      \
       *(__o->next_free)++ = 0;						      \
       (void) 0; })
#define obstack_init(h)							      \
  _obstack_begin ((h), 0, 0,						      \
                  _OBSTACK_CAST (void *(*) (size_t), obstack_chunk_alloc),    \
                  _OBSTACK_CAST (void (*) (void *), obstack_chunk_free))
# define obstack_int_grow(OBSTACK, datum)				      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);					      \
       if (obstack_room (__o) < sizeof (int))				      \
         _obstack_newchunk (__o, sizeof (int));				      \
       obstack_int_grow_fast (__o, datum); })
# define obstack_int_grow_fast(OBSTACK, aint)				      \
  __extension__								      \
    ({ struct obstack *__o1 = (OBSTACK);				      \
       void *__p1 = __o1->next_free;					      \
       *(int *) __p1 = (aint);						      \
       __o1->next_free += sizeof (int);					      \
       (void) 0; })
# define obstack_make_room(OBSTACK, length)				      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);					      \
       _OBSTACK_SIZE_T __len = (length);				      \
       if (obstack_room (__o) < __len)					      \
         _obstack_newchunk (__o, __len);				      \
       (void) 0; })
#define obstack_memory_used(h) _obstack_memory_used (h)
#define obstack_next_free(h) ((void *) (h)->next_free)
# define obstack_object_size(OBSTACK)					      \
  __extension__								      \
    ({ struct obstack const *__o = (OBSTACK);				      \
       (_OBSTACK_SIZE_T) (__o->next_free - __o->object_base); })
# define obstack_ptr_grow(OBSTACK, datum)				      \
  __extension__								      \
    ({ struct obstack *__o = (OBSTACK);					      \
       if (obstack_room (__o) < sizeof (void *))			      \
         _obstack_newchunk (__o, sizeof (void *));			      \
       obstack_ptr_grow_fast (__o, datum); })
# define obstack_ptr_grow_fast(OBSTACK, aptr)				      \
  __extension__								      \
    ({ struct obstack *__o1 = (OBSTACK);				      \
       void *__p1 = __o1->next_free;					      \
       *(const void **) __p1 = (aptr);					      \
       __o1->next_free += sizeof (const void *);			      \
       (void) 0; })
# define obstack_room(OBSTACK)						      \
  __extension__								      \
    ({ struct obstack const *__o1 = (OBSTACK);				      \
       (_OBSTACK_SIZE_T) (__o1->chunk_limit - __o1->next_free); })
#define obstack_specify_allocation(h, size, alignment, chunkfun, freefun)     \
  _obstack_begin ((h), (size), (alignment),				      \
                  _OBSTACK_CAST (void *(*) (size_t), chunkfun),		      \
                  _OBSTACK_CAST (void (*) (void *), freefun))
#define obstack_specify_allocation_with_arg(h, size, alignment, chunkfun, freefun, arg) \
  _obstack_begin_1 ((h), (size), (alignment),				      \
                    _OBSTACK_CAST (void *(*) (void *, size_t), chunkfun),     \
                    _OBSTACK_CAST (void (*) (void *, void *), freefun), arg)
#define BITS_PER_CPPCHAR_T (CHAR_BIT * sizeof (cppchar_t))
#define BUFF_FRONT(BUFF) ((BUFF)->cur)
#define BUFF_LIMIT(BUFF) ((BUFF)->limit)
#define BUFF_ROOM(BUFF) (size_t) ((BUFF)->limit - (BUFF)->cur)
#define CPP_ALIGN(size) CPP_ALIGN2 (size, DEFAULT_ALIGNMENT)
#define CPP_ALIGN2(size, align) (((size) + ((align) - 1)) & ~((align) - 1))
#define CPP_BUFFER(PFILE) ((PFILE)->buffer)
#define CPP_BUF_COL(BUF) CPP_BUF_COLUMN(BUF, (BUF)->cur)
#define CPP_BUF_COLUMN(BUF, CUR) ((CUR) - (BUF)->line_base)
#define CPP_INCREMENT_LINE(PFILE, COLS_HINT) do { \
    const class line_maps *line_table = PFILE->line_table; \
    const struct line_map_ordinary *map = \
      LINEMAPS_LAST_ORDINARY_MAP (line_table); \
    linenum_type line = SOURCE_LINE (map, line_table->highest_line); \
    linemap_line_start (PFILE->line_table, line + 1, COLS_HINT); \
  } while (0)
#define CPP_OPTION(PFILE, OPTION) ((PFILE)->opts.OPTION)
#define CPP_PEDANTIC(PF) CPP_OPTION (PF, cpp_pedantic)
#define CPP_WTRADITIONAL(PF) CPP_OPTION (PF, cpp_warn_traditional)
#define CUR(c) ((c)->u.trad.cur)
#define DEFAULT_ALIGNMENT offsetof (struct dummy, u)
#define DIGIT_SEP(c) ((c) == '\'' && CPP_OPTION (pfile, digit_separators))
#define DSC(str) (const unsigned char *)str, sizeof str - 1
#define FIRST(c) ((c)->u.iso.first)
#define HAVE_ICONV 0
#define INITIAL_NORMALIZE_STATE { 0, 0, normalized_KC }
#define LAST(c) ((c)->u.iso.last)

#define NORMALIZE_STATE_RESULT(st) ((st)->level)
#define NORMALIZE_STATE_UPDATE_IDNUM(st, c)	\
  ((st)->previous = (c), (st)->prev_class = 0)
#define RLIMIT(c) ((c)->u.trad.rlimit)
#define SEEN_EOL() (pfile->cur_token[-1].type == CPP_EOF)
#define UC (const uchar *)  
#define VALID_SIGN(c, prevc) \
  (((c) == '+' || (c) == '-') && \
   ((prevc) == 'e' || (prevc) == 'E' \
    || (((prevc) == 'p' || (prevc) == 'P') \
        && CPP_OPTION (pfile, extended_numbers))))
#define _cpp_mark_macro_used(NODE) 					\
  (cpp_user_macro_p (NODE) ? (NODE)->value.macro->used = 1 : 0)
#define _dollar_ok(x)	((x) == '$' && CPP_OPTION (pfile, dollars_in_ident))
#define is_hspace(x)	ISBLANK(x)
#define is_idchar(x)	(ISIDNUM(x) || _dollar_ok(x))
#define is_idstart(x)	(ISIDST(x) || _dollar_ok(x))
#define is_numchar(x)	ISIDNUM(x)
#define is_numstart(x)	ISDIGIT(x)
#define is_nvspace(x)	IS_NVSPACE(x)
#define is_space(x)	IS_SPACE_OR_NUL(x)
#define is_vspace(x)	IS_VSPACE(x)
#define HAVE_DESIGNATED_INITIALIZERS 0
#define INTTYPE_MAXIMUM(t) ((t) (~ (t) 0 - INTTYPE_MINIMUM (t)))
#define INTTYPE_MINIMUM(t) ((t) (INTTYPE_SIGNED (t) \
			    ? (t) 1 << (sizeof (t) * CHAR_BIT - 1) : (t) 0))
#define INTTYPE_SIGNED(t) (! ((t) 0 < (t) -1))

#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define NULL 0
# define N_(msgid) msgid
# define O_BINARY 0
#define O_NOCTTY 0
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#  define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#   define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
# define UCHAR_MAX INTTYPE_MAXIMUM (unsigned char)
# define _(msgid) dgettext (PACKAGE, msgid)

#define __builtin_expect(a, b) (a)
#define abort() fancy_abort ("__FILE__", "__LINE__", __FUNCTION__)
#  define clearerr(Stream) clearerr_unlocked (Stream)
# define dgettext(package, msgid) (msgid)
#define fdopen(FILDES,MODE) fdopen_unlocked(FILDES,MODE)
#  define feof(Stream) feof_unlocked (Stream)
#  define ferror(Stream) ferror_unlocked (Stream)
#  define fflush(Stream) fflush_unlocked (Stream)
#  define fgetc(Stream) fgetc_unlocked (Stream)
#  define fgets(S, n, Stream) fgets_unlocked (S, n, Stream)
#  define fileno(Stream) fileno_unlocked (Stream)
#define fopen(PATH,MODE) fopen_unlocked(PATH,MODE)
#  define fprintf fprintf_unlocked
#  define fputc(C, Stream) fputc_unlocked (C, Stream)
#  define fputs(String, Stream) fputs_unlocked (String, Stream)
#  define fread(Ptr, Size, N, Stream) fread_unlocked (Ptr, Size, N, Stream)
#define freopen(PATH,MODE,STREAM) freopen_unlocked(PATH,MODE,STREAM)
#  define fwrite(Ptr, Size, N, Stream) fwrite_unlocked (Ptr, Size, N, Stream)
#define gcc_assert(EXPR) 						\
   ((void)(!(EXPR) ? fancy_abort ("__FILE__", "__LINE__", __FUNCTION__), 0 : 0))
#define gcc_checking_assert(EXPR) gcc_assert (EXPR)
#  define getc(Stream) getc_unlocked (Stream)
#  define getchar() getchar_unlocked ()
#define offsetof(TYPE, MEMBER)	((size_t) &((TYPE *) 0)->MEMBER)
#  define putc(C, Stream) putc_unlocked (C, Stream)
#  define putchar(C) putchar_unlocked (C)
# define setlocale(category, locale) (locale)
#  define HOST_CHARSET HOST_CHARSET_ASCII
#define HOST_CHARSET_ASCII   1
#define HOST_CHARSET_EBCDIC  2
#define HOST_CHARSET_UNKNOWN 0
#define ISALNUM(c)  _sch_test(c, _sch_isalnum)
#define ISALPHA(c)  _sch_test(c, _sch_isalpha)
#define ISBLANK(c)  _sch_test(c, _sch_isblank)
#define ISCNTRL(c)  _sch_test(c, _sch_iscntrl)
#define ISDIGIT(c)  _sch_test(c, _sch_isdigit)
#define ISGRAPH(c)  _sch_test(c, _sch_isgraph)
#define ISIDNUM(c)	_sch_test(c, _sch_isidnum)
#define ISIDST(c)	_sch_test(c, _sch_isidst)
#define ISLOWER(c)  _sch_test(c, _sch_islower)
#define ISPRINT(c)  _sch_test(c, _sch_isprint)
#define ISPUNCT(c)  _sch_test(c, _sch_ispunct)
#define ISSPACE(c)  _sch_test(c, _sch_isspace)
#define ISUPPER(c)  _sch_test(c, _sch_isupper)
#define ISXDIGIT(c) _sch_test(c, _sch_isxdigit)
#define IS_ISOBASIC(c)	_sch_test(c, _sch_isbasic)
#define IS_NVSPACE(c)	_sch_test(c, _sch_isnvsp)
#define IS_SPACE_OR_NUL(c)	_sch_test(c, _sch_iscppsp)
#define IS_VSPACE(c)	_sch_test(c, _sch_isvsp)

#define TOLOWER(c) _sch_tolower[(c) & 0xff]
#define TOUPPER(c) _sch_toupper[(c) & 0xff]
#define _sch_test(c, bit) (_sch_istable[(c) & 0xff] & (unsigned short)(bit))
#define isalnum(c) do_not_use_isalnum_with_safe_ctype
#define isalpha(c) do_not_use_isalpha_with_safe_ctype
#define iscntrl(c) do_not_use_iscntrl_with_safe_ctype
#define isdigit(c) do_not_use_isdigit_with_safe_ctype
#define isgraph(c) do_not_use_isgraph_with_safe_ctype
#define islower(c) do_not_use_islower_with_safe_ctype
#define isprint(c) do_not_use_isprint_with_safe_ctype
#define ispunct(c) do_not_use_ispunct_with_safe_ctype
#define isspace(c) do_not_use_isspace_with_safe_ctype
#define isupper(c) do_not_use_isupper_with_safe_ctype
#define isxdigit(c) do_not_use_isxdigit_with_safe_ctype
#define tolower(c) do_not_use_tolower_with_safe_ctype
#define toupper(c) do_not_use_toupper_with_safe_ctype
#define ACONCAT(ACONCAT_PARAMS) \
  (libiberty_concat_ptr = (char *) alloca (concat_length ACONCAT_PARAMS + 1), \
   concat_copy2 ACONCAT_PARAMS)
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
# define ASTRDUP(X) \
  (__extension__ ({ const char *const libiberty_optr = (X); \
   const unsigned long libiberty_len = strlen (libiberty_optr) + 1; \
   char *const libiberty_nptr = (char *) alloca (libiberty_len); \
   (char *) memcpy (libiberty_nptr, libiberty_optr, libiberty_len); }))
# define C_ALLOCA 1

#define PEXECUTE_FIRST   1
#define PEXECUTE_LAST    2
#define PEXECUTE_ONE     (PEXECUTE_FIRST + PEXECUTE_LAST)
#define PEXECUTE_SEARCH  4
#define PEXECUTE_VERBOSE 8
# define USE_C_ALLOCA 1
#define XALLOCA(T)		((T *) alloca (sizeof (T)))
#define XALLOCAVAR(T, S)	((T *) alloca ((S)))
#define XALLOCAVEC(T, N)	((T *) alloca (sizeof (T) * (N)))
#define XCNEW(T)		((T *) xcalloc (1, sizeof (T)))
#define XCNEWVAR(T, S)		((T *) xcalloc (1, (S)))
#define XCNEWVEC(T, N)		((T *) xcalloc ((N), sizeof (T)))
#define XDELETE(P)		free ((void*) (P))
#define XDELETEVEC(P)		free ((void*) (P))
#define XDUP(T, P)		((T *) xmemdup ((P), sizeof (T), sizeof (T)))
#define XDUPVAR(T, P, S1, S2)	((T *) xmemdup ((P), (S1), (S2)))
#define XDUPVEC(T, P, N)	((T *) xmemdup ((P), sizeof (T) * (N), sizeof (T) * (N)))
#define XNEW(T)			((T *) xmalloc (sizeof (T)))
#define XNEWVAR(T, S)		((T *) xmalloc ((S)))
#define XNEWVEC(T, N)		((T *) xmalloc (sizeof (T) * (N)))
#define XOBFINISH(O, T)         ((T) obstack_finish ((O)))
#define XOBNEW(O, T)		((T *) obstack_alloc ((O), sizeof (T)))
#define XOBNEWVAR(O, T, S)	((T *) obstack_alloc ((O), (S)))
#define XOBNEWVEC(O, T, N)	((T *) obstack_alloc ((O), sizeof (T) * (N)))
#define XRESIZEVAR(T, P, S)	((T *) xrealloc ((P), (S)))
#define XRESIZEVEC(T, P, N)	((T *) xrealloc ((void *) (P), sizeof (T) * (N)))
#define _hex_array_size 256
# define alloca(x) __builtin_alloca(x)
#define basename basename_cannot_be_used_without_a_prototype
#define hex_p(c)	(hex_value (c) != _hex_bad)
#define hex_value(c)	((unsigned int) _hex_value[(unsigned char) (c)])
