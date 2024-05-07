#include<stdarg.h>

#include<limits.h>
#include<float.h>
#include<string.h>
#include<sys/types.h>

#include<math.h>


#include<stdint.h>




#include<assert.h>
#include<stddef.h>

#define FETCH_B() do {a=READ_B();} while (0)
#define FETCH_BB() do {a=READ_B(); b=READ_B();} while (0)
#define FETCH_BBB() do {a=READ_B(); b=READ_B(); c=READ_B();} while (0)
#define FETCH_BBB_1() do {a=READ_S(); b=READ_B(); c=READ_B();} while (0)
#define FETCH_BBB_2() do {a=READ_B(); b=READ_S(); c=READ_B();} while (0)
#define FETCH_BBB_3() do {a=READ_S(); b=READ_S(); c=READ_B();} while (0)
#define FETCH_BB_1() do {a=READ_S(); b=READ_B();} while (0)
#define FETCH_BB_2() do {a=READ_B(); b=READ_S();} while (0)
#define FETCH_BB_3() do {a=READ_S(); b=READ_S();} while (0)
#define FETCH_BS() do {a=READ_B(); b=READ_S();} while (0)
#define FETCH_BSS() do {a=READ_B(); b=READ_S(); c=READ_S();} while (0)
#define FETCH_BSS_1() do {a=READ_S(); b=READ_S();c=READ_S();} while (0)
#define FETCH_BSS_2() FETCH_BSS()
#define FETCH_BSS_3() FETCH_BSS_1()
#define FETCH_BS_1() do {a=READ_S(); b=READ_S();} while (0)
#define FETCH_BS_2() FETCH_BS()
#define FETCH_BS_3() do {a=READ_S(); b=READ_S();} while (0)
#define FETCH_B_1() FETCH_S()
#define FETCH_B_2() FETCH_B()
#define FETCH_B_3() FETCH_B()
#define FETCH_S() do {a=READ_S();} while (0)
#define FETCH_S_1() FETCH_S()
#define FETCH_S_2() FETCH_S()
#define FETCH_S_3() FETCH_S()
#define FETCH_W() do {a=READ_W();} while (0)
#define FETCH_W_1() FETCH_W()
#define FETCH_W_2() FETCH_W()
#define FETCH_W_3() FETCH_W()
#define FETCH_Z_1() FETCH_Z()
#define FETCH_Z_2() FETCH_Z()
#define FETCH_Z_3() FETCH_Z()

#define OPCODE(x,_) OP_ ## x,
#define OP_L_BLOCK   OP_L_CAPTURE
#define OP_L_CAPTURE 2
#define OP_L_LAMBDA  (OP_L_STRICT|OP_L_CAPTURE)
#define OP_L_METHOD  OP_L_STRICT
#define OP_L_STRICT  1
#define OP_R_BREAK  1
#define OP_R_NORMAL 0
#define OP_R_RETURN 2
#define PEEK_B(pc) (*(pc))
#define PEEK_S(pc) ((pc)[0]<<8|(pc)[1])
#define PEEK_W(pc) ((pc)[0]<<16|(pc)[1]<<8|(pc)[2])
#define READ_B() PEEK_B(pc++)
#define READ_S() (pc+=2, PEEK_S(pc-2))
#define READ_W() (pc+=3, PEEK_W(pc-3))
#define ISTRUCT_DATA_SIZE (sizeof(void*) * 3)
#define ISTRUCT_PTR(obj)      (RISTRUCT(obj)->inline_data)

#define RISTRUCT(obj)         ((struct RIStruct*)(mrb_ptr(obj)))
#define DATA_CHECK_GET_PTR(mrb,obj,dtype,type) (type*)mrb_data_check_get_ptr(mrb,obj,dtype)
#define DATA_GET_PTR(mrb,obj,dtype,type) (type*)mrb_data_get_ptr(mrb,obj,dtype)
#define DATA_PTR(d)        (RDATA(d)->data)
#define DATA_TYPE(d)       (RDATA(d)->type)
#define Data_Get_Struct(mrb,obj,type,sval) do {\
  *(void**)&sval = mrb_data_get_ptr(mrb, obj, type); \
} while (0)
#define Data_Make_Struct(mrb,klass,strct,type,sval,data_obj) do { \
  (data_obj) = Data_Wrap_Struct(mrb,klass,type,NULL);\
  (sval) = (strct *)mrb_malloc(mrb, sizeof(strct));                     \
  { static const strct zero = { 0 }; *(sval) = zero; };\
  (data_obj)->data = (sval);\
} while (0)
#define Data_Wrap_Struct(mrb,klass,type,ptr)\
  mrb_data_object_alloc(mrb,klass,ptr,type)

#define RDATA(obj)         ((struct RData *)(mrb_ptr(obj)))
#define mrb_check_datatype(mrb,val,type) mrb_data_get_ptr(mrb, val, type)
#define mrb_data_check_and_get(mrb,obj,dtype) mrb_data_get_ptr(mrb,obj,dtype)
#define mrb_get_datatype(mrb,val,type) mrb_data_get_ptr(mrb, val, type)
#define MRB_EXC_MESG_STRING_FLAG 0x100

#define RBREAK_TAG_BIT          3
#define RBREAK_TAG_BIT_OFF      8
#define RBREAK_TAG_DEFINE(tag, i) tag = i,
#define RBREAK_TAG_FOREACH(f) \
  f(RBREAK_TAG_BREAK, 0) \
  f(RBREAK_TAG_BREAK_UPPER, 1) \
  f(RBREAK_TAG_BREAK_INTARGET, 2) \
  f(RBREAK_TAG_RETURN_BLOCK, 3) \
  f(RBREAK_TAG_RETURN, 4) \
  f(RBREAK_TAG_RETURN_TOPLEVEL, 5) \
  f(RBREAK_TAG_JUMP, 6) \
  f(RBREAK_TAG_STOP, 7)
#define RBREAK_TAG_MASK         (~(~UINT32_C(0) << RBREAK_TAG_BIT))
#define RBREAK_VALUE_TT_MASK ((1 << 8) - 1)
#define mrb_break_proc_get(brk) ((brk)->proc)
#define mrb_break_proc_set(brk, p) ((brk)->proc = p)
#define mrb_break_value_get(brk) ((brk)->val)
#define mrb_break_value_set(brk, v) ((brk)->val = v)
#define mrb_exc_new_lit(mrb, c, lit) mrb_exc_new_str(mrb, c, mrb_str_new_lit(mrb, lit))
#define mrb_exc_new_str_lit(mrb, c, lit) mrb_exc_new_lit(mrb, c, lit)
#define mrb_exc_ptr(v) ((struct RException*)mrb_ptr(v))

#define MRB_STR_ASCII    16
#define MRB_STR_EMBED     8  
#define MRB_STR_EMBED_LEN_BIT 5
#define MRB_STR_EMBED_LEN_MASK (((1 << MRB_STR_EMBED_LEN_BIT) - 1) << MRB_STR_EMBED_LEN_SHIFT)
#define MRB_STR_EMBED_LEN_SHIFT 6
#define MRB_STR_FSHARED   2
#define MRB_STR_NOFREE    4
#define MRB_STR_SHARED    1
#define MRB_STR_TYPE_MASK 15

#define RSTRING(s)           mrb_str_ptr(s)
#define RSTRING_CAPA(s)      RSTR_CAPA(RSTRING(s))
#define RSTRING_CSTR(mrb,s)  mrb_string_cstr(mrb, s)
#define RSTRING_EMBED_LEN(s) RSTR_EMBED_LEN(RSTRING(s))
#define RSTRING_EMBED_LEN_MAX \
  ((mrb_int)(sizeof(void*) * 3 + sizeof(void*) - 32 / CHAR_BIT - 1))
#define RSTRING_END(s)       (RSTRING_PTR(s) + RSTRING_LEN(s))
#define RSTRING_LEN(s)       RSTR_LEN(RSTRING(s))
#define RSTRING_PTR(s)       RSTR_PTR(RSTRING(s))
# define RSTR_ASCII_P(s) ((s)->flags & MRB_STR_ASCII)
#define RSTR_CAPA(s) (RSTR_EMBED_P(s) ? RSTRING_EMBED_LEN_MAX : (s)->as.heap.aux.capa)
# define RSTR_COPY_ASCII_FLAG(dst, src) RSTR_WRITE_ASCII_FLAG(dst, RSTR_ASCII_P(src))
#define RSTR_EMBEDDABLE_P(len) ((len) <= RSTRING_EMBED_LEN_MAX)
#define RSTR_EMBED_LEN(s)\
  (mrb_int)(((s)->flags & MRB_STR_EMBED_LEN_MASK) >> MRB_STR_EMBED_LEN_SHIFT)
#define RSTR_EMBED_P(s) ((s)->flags & MRB_STR_EMBED)
#define RSTR_EMBED_PTR(s) (((struct RStringEmbed*)(s))->ary)
#define RSTR_FSHARED_P(s) ((s)->flags & MRB_STR_FSHARED)
#define RSTR_LEN(s) ((RSTR_EMBED_P(s)) ? RSTR_EMBED_LEN(s) : (s)->as.heap.len)
#define RSTR_NOFREE_P(s) ((s)->flags & MRB_STR_NOFREE)
#define RSTR_PTR(s) ((RSTR_EMBED_P(s)) ? RSTR_EMBED_PTR(s) : (s)->as.heap.ptr)
# define RSTR_SET_ASCII_FLAG(s) ((s)->flags |= MRB_STR_ASCII)
#define RSTR_SET_EMBED_FLAG(s) ((s)->flags |= MRB_STR_EMBED)
#define RSTR_SET_EMBED_LEN(s, n) do {\
  size_t tmp_n = (n);\
  (s)->flags &= ~MRB_STR_EMBED_LEN_MASK;\
  (s)->flags |= (tmp_n) << MRB_STR_EMBED_LEN_SHIFT;\
} while (0)
#define RSTR_SET_FSHARED_FLAG(s) ((s)->flags |= MRB_STR_FSHARED)
#define RSTR_SET_LEN(s, n) do {\
  if (RSTR_EMBED_P(s)) {\
    RSTR_SET_EMBED_LEN((s),(n));\
  }\
  else {\
    (s)->as.heap.len = (mrb_ssize)(n);\
  }\
} while (0)
#define RSTR_SET_NOFREE_FLAG(s) ((s)->flags |= MRB_STR_NOFREE)
#define RSTR_SET_SHARED_FLAG(s) ((s)->flags |= MRB_STR_SHARED)
#define RSTR_SET_TYPE_FLAG(s, type) (RSTR_UNSET_TYPE_FLAG(s), (s)->flags |= MRB_STR_##type)
#define RSTR_SHARED_P(s) ((s)->flags & MRB_STR_SHARED)
# define RSTR_UNSET_ASCII_FLAG(s) ((s)->flags &= ~MRB_STR_ASCII)
#define RSTR_UNSET_EMBED_FLAG(s) ((s)->flags &= ~(MRB_STR_EMBED|MRB_STR_EMBED_LEN_MASK))
#define RSTR_UNSET_FSHARED_FLAG(s) ((s)->flags &= ~MRB_STR_FSHARED)
#define RSTR_UNSET_NOFREE_FLAG(s) ((s)->flags &= ~MRB_STR_NOFREE)
#define RSTR_UNSET_SHARED_FLAG(s) ((s)->flags &= ~MRB_STR_SHARED)
#define RSTR_UNSET_TYPE_FLAG(s) ((s)->flags &= ~(MRB_STR_TYPE_MASK|MRB_STR_EMBED_LEN_MASK))
# define RSTR_WRITE_ASCII_FLAG(s, v) (RSTR_UNSET_ASCII_FLAG(s), (s)->flags |= v)
#define mrb_str_buf_append(mrb, str, str2) mrb_str_cat_str(mrb, str, str2)
#define mrb_str_buf_cat(mrb, str, ptr, len) mrb_str_cat(mrb, str, ptr, len)
#define mrb_str_buf_new(mrb, capa) mrb_str_new_capa(mrb, (capa))
#define mrb_str_cat2(mrb, str, ptr) mrb_str_cat_cstr(mrb, str, ptr)
#define mrb_str_cat_lit(mrb, str, lit) mrb_str_cat(mrb, str, lit, mrb_strlen_lit(lit))
#define mrb_str_index_lit(mrb, str, lit, off) mrb_str_index(mrb, str, lit, mrb_strlen_lit(lit), off);
#define mrb_str_ptr(s)       ((struct RString*)(mrb_ptr(s)))
#define mrb_str_to_inum(mrb, str, base, badcheck) mrb_str_to_integer(mrb, str, base, badcheck)
#define MRB_ASPEC_BLOCK(a)        ((a) & 1)
#define MRB_ASPEC_KDICT(a)        (((a) >> 1) & 0x1)
#define MRB_ASPEC_KEY(a)          (((a) >> 2) & 0x1f)
#define MRB_ASPEC_OPT(a)          (((a) >> 13) & 0x1f)
#define MRB_ASPEC_POST(a)         (((a) >> 7) & 0x1f)
#define MRB_ASPEC_REQ(a)          (((a) >> 18) & 0x1f)
#define MRB_ASPEC_REST(a)         (((a) >> 12) & 0x1)
#define MRB_ENV_BIDX(e) (((e)->flags >> 8) & 0xff)
#define MRB_ENV_CLOSE(e) ((e)->flags |= MRB_ENV_CLOSED)
#define MRB_ENV_CLOSED (1<<20)
#define MRB_ENV_HEAP(e) ((e)->flags |= MRB_ENV_HEAPED)
#define MRB_ENV_HEAPED (1<<18)
#define MRB_ENV_HEAP_P(e) ((e)->flags & MRB_ENV_HEAPED)
#define MRB_ENV_LEN(e) ((mrb_int)((e)->flags & 0xff))
#define MRB_ENV_ONSTACK_P(e) (((e)->flags & MRB_ENV_CLOSED) == 0)
#define MRB_ENV_SET_BIDX(e,idx) ((e)->flags = (((e)->flags & ~(0xff<<8))|((unsigned int)(idx) & 0xff)<<8))
#define MRB_ENV_SET_LEN(e,len) ((e)->flags = (((e)->flags & ~0xff)|((unsigned int)(len) & 0xff)))
#define MRB_ENV_TOUCH(e) ((e)->flags |= MRB_ENV_TOUCHED)
#define MRB_ENV_TOUCHED (1<<19)
#define MRB_METHOD_CFUNC(m) (MRB_METHOD_FUNC_P(m)?MRB_METHOD_FUNC(m):((MRB_METHOD_PROC(m)&&MRB_PROC_CFUNC_P(MRB_METHOD_PROC(m)))?MRB_PROC_CFUNC(MRB_METHOD_PROC(m)):NULL))
#define MRB_METHOD_CFUNC_P(m) (MRB_METHOD_FUNC_P(m)?TRUE:(MRB_METHOD_PROC(m)?(MRB_PROC_CFUNC_P(MRB_METHOD_PROC(m))):FALSE))
#define MRB_METHOD_FROM_FUNC(m,fn) ((m)=(mrb_method_t)((((uintptr_t)(fn))<<2)|MRB_METHOD_FUNC_FL))
#define MRB_METHOD_FROM_PROC(m,pr) ((m)=(mrb_method_t)(pr))
#define MRB_METHOD_FUNC(m) ((mrb_func_t)((uintptr_t)(m)>>2))
#define MRB_METHOD_FUNC_FL 1
#define MRB_METHOD_FUNC_P(m) (((uintptr_t)(m))&MRB_METHOD_FUNC_FL)
#define MRB_METHOD_NOARG_FL 2
#define MRB_METHOD_NOARG_P(m) ((((uintptr_t)(m))&MRB_METHOD_NOARG_FL)?1:0)
#define MRB_METHOD_NOARG_SET(m) ((m)=(mrb_method_t)(((uintptr_t)(m))|MRB_METHOD_NOARG_FL))
#define MRB_METHOD_PROC(m) ((struct RProc*)(m))
#define MRB_METHOD_PROC_P(m) (!MRB_METHOD_FUNC_P(m))
#define MRB_METHOD_UNDEF_P(m) ((m)==0)
#define MRB_PROC_CFUNC(p) (p)->body.func
#define MRB_PROC_CFUNC_FL 128
#define MRB_PROC_CFUNC_P(p) (((p)->flags & MRB_PROC_CFUNC_FL) != 0)
#define MRB_PROC_ENV(p) (MRB_PROC_ENV_P(p) ? (p)->e.env : NULL)
#define MRB_PROC_ENVSET 1024
#define MRB_PROC_ENV_P(p) (((p)->flags & MRB_PROC_ENVSET) != 0)
#define MRB_PROC_NOARG 4096 
#define MRB_PROC_NOARG_P(p) (((p)->flags & MRB_PROC_NOARG) != 0)
#define MRB_PROC_ORPHAN 512
#define MRB_PROC_ORPHAN_P(p) (((p)->flags & MRB_PROC_ORPHAN) != 0)
#define MRB_PROC_SCOPE 2048
#define MRB_PROC_SCOPE_P(p) (((p)->flags & MRB_PROC_SCOPE) != 0)
#define MRB_PROC_SET_TARGET_CLASS(p,tc) do {\
  if (MRB_PROC_ENV_P(p)) {\
    (p)->e.env->c = (tc);\
    mrb_field_write_barrier(mrb, (struct RBasic*)(p)->e.env, (struct RBasic*)(tc));\
  }\
  else {\
    (p)->e.target_class = (tc);\
    mrb_field_write_barrier(mrb, (struct RBasic*)p, (struct RBasic*)(tc));\
  }\
} while (0)
#define MRB_PROC_STRICT 256
#define MRB_PROC_STRICT_P(p) (((p)->flags & MRB_PROC_STRICT) != 0)
#define MRB_PROC_TARGET_CLASS(p) (MRB_PROC_ENV_P(p) ? (p)->e.env->c : (p)->e.target_class)

#define mrb_cfunc_env_get(mrb, idx) mrb_proc_cfunc_env_get(mrb, idx)
#define mrb_proc_ptr(v)    ((struct RProc*)(mrb_ptr(v)))
#define KHASH_DECLARE(name, khkey_t, khval_t, kh_is_map)                \
  typedef struct kh_##name {                                            \
    khint_t n_buckets;                                                  \
    khint_t size;                                                       \
    uint8_t *ed_flags;                                                  \
    khkey_t *keys;                                                      \
    khval_t *vals;                                                      \
  } kh_##name##_t;                                                      \
  void kh_alloc_##name(mrb_state *mrb, kh_##name##_t *h);               \
  kh_##name##_t *kh_init_##name##_size(mrb_state *mrb, khint_t size);   \
  kh_##name##_t *kh_init_##name(mrb_state *mrb);                        \
  void kh_destroy_##name(mrb_state *mrb, kh_##name##_t *h);             \
  void kh_clear_##name(mrb_state *mrb, kh_##name##_t *h);               \
  khint_t kh_get_##name(mrb_state *mrb, kh_##name##_t *h, khkey_t key);           \
  khint_t kh_put_##name(mrb_state *mrb, kh_##name##_t *h, khkey_t key, int *ret); \
  void kh_resize_##name(mrb_state *mrb, kh_##name##_t *h, khint_t new_n_buckets); \
  void kh_del_##name(mrb_state *mrb, kh_##name##_t *h, khint_t x);                \
  kh_##name##_t *kh_copy_##name(mrb_state *mrb, kh_##name##_t *h);
# define KHASH_DEFAULT_SIZE 32
#define KHASH_DEFINE(name, khkey_t, khval_t, kh_is_map, __hash_func, __hash_equal) \
  mrb_noreturn void mrb_raise_nomemory(mrb_state *mrb);                 \
  int kh_alloc_simple_##name(mrb_state *mrb, kh_##name##_t *h)          \
  {                                                                     \
    khint_t sz = h->n_buckets;                                          \
    size_t len = sizeof(khkey_t) + (kh_is_map ? sizeof(khval_t) : 0);   \
    uint8_t *p = (uint8_t*)mrb_malloc_simple(mrb, sizeof(uint8_t)*sz/4+len*sz); \
    if (!p) { return 1; }                                               \
    h->size = 0;                                                        \
    h->keys = (khkey_t *)p;                                             \
    h->vals = kh_is_map ? (khval_t *)(p+sizeof(khkey_t)*sz) : NULL;     \
    h->ed_flags = p+len*sz;                                             \
    kh_fill_flags(h->ed_flags, 0xaa, sz/4);                             \
    return 0;                                                           \
  }                                                                     \
  void kh_alloc_##name(mrb_state *mrb, kh_##name##_t *h)                \
  {                                                                     \
    if (kh_alloc_simple_##name(mrb, h)) {                               \
      mrb_raise_nomemory(mrb);                                          \
    }                                                                   \
  }                                                                     \
  kh_##name##_t *kh_init_##name##_size(mrb_state *mrb, khint_t size) {  \
    kh_##name##_t *h = (kh_##name##_t*)mrb_calloc(mrb, 1, sizeof(kh_##name##_t)); \
    if (size < KHASH_MIN_SIZE)                                          \
      size = KHASH_MIN_SIZE;                                            \
    khash_power2(size);                                                 \
    h->n_buckets = size;                                                \
    if (kh_alloc_simple_##name(mrb, h)) {                               \
      mrb_free(mrb, h);                                                 \
      mrb_raise_nomemory(mrb);                                          \
    }                                                                   \
    return h;                                                           \
  }                                                                     \
  kh_##name##_t *kh_init_##name(mrb_state *mrb) {                       \
    return kh_init_##name##_size(mrb, KHASH_DEFAULT_SIZE);              \
  }                                                                     \
  void kh_destroy_##name(mrb_state *mrb, kh_##name##_t *h)              \
  {                                                                     \
    if (h) {                                                            \
      mrb_free(mrb, h->keys);                                           \
      mrb_free(mrb, h);                                                 \
    }                                                                   \
  }                                                                     \
  void kh_clear_##name(mrb_state *mrb, kh_##name##_t *h)                \
  {                                                                     \
    (void)mrb;                                                          \
    if (h && h->ed_flags) {                                             \
      kh_fill_flags(h->ed_flags, 0xaa, h->n_buckets/4);                 \
      h->size = 0;                                                      \
    }                                                                   \
  }                                                                     \
  khint_t kh_get_##name(mrb_state *mrb, kh_##name##_t *h, khkey_t key)  \
  {                                                                     \
    khint_t k = __hash_func(mrb,key) & khash_mask(h), step = 0;         \
    (void)mrb;                                                          \
    while (!__ac_isempty(h->ed_flags, k)) {                             \
      if (!__ac_isdel(h->ed_flags, k)) {                                \
        if (__hash_equal(mrb,h->keys[k], key)) return k;                \
      }                                                                 \
      k = (k+(++step)) & khash_mask(h);                                 \
    }                                                                   \
    return kh_end(h);                                                   \
  }                                                                     \
  void kh_resize_##name(mrb_state *mrb, kh_##name##_t *h, khint_t new_n_buckets) \
  {                                                                     \
    if (new_n_buckets < KHASH_MIN_SIZE)                                 \
      new_n_buckets = KHASH_MIN_SIZE;                                   \
    khash_power2(new_n_buckets);                                        \
    {                                                                   \
      kh_##name##_t hh;                                                 \
      uint8_t *old_ed_flags = h->ed_flags;                              \
      khkey_t *old_keys = h->keys;                                      \
      khval_t *old_vals = h->vals;                                      \
      khint_t old_n_buckets = h->n_buckets;                             \
      khint_t i;                                                        \
      hh.n_buckets = new_n_buckets;                                     \
      kh_alloc_##name(mrb, &hh);                                        \
                                                          \
      for (i=0 ; i<old_n_buckets ; i++) {                               \
        if (!__ac_iseither(old_ed_flags, i)) {                          \
          khint_t k = kh_put_##name(mrb, &hh, old_keys[i], NULL);       \
          if (kh_is_map) kh_value(&hh,k) = old_vals[i];                 \
        }                                                               \
      }                                                                 \
                                                      \
      *h = hh;                                                          \
      mrb_free(mrb, old_keys);                                          \
    }                                                                   \
  }                                                                     \
  khint_t kh_put_##name(mrb_state *mrb, kh_##name##_t *h, khkey_t key, int *ret) \
  {                                                                     \
    khint_t k, del_k, step = 0;                                         \
    if (h->size >= khash_upper_bound(h)) {                              \
      kh_resize_##name(mrb, h, h->n_buckets*2);                         \
    }                                                                   \
    k = __hash_func(mrb,key) & khash_mask(h);                           \
    del_k = kh_end(h);                                                  \
    while (!__ac_isempty(h->ed_flags, k)) {                             \
      if (!__ac_isdel(h->ed_flags, k)) {                                \
        if (__hash_equal(mrb,h->keys[k], key)) {                        \
          if (ret) *ret = 0;                                            \
          return k;                                                     \
        }                                                               \
      }                                                                 \
      else if (del_k == kh_end(h)) {                                    \
        del_k = k;                                                      \
      }                                                                 \
      k = (k+(++step)) & khash_mask(h);                                 \
    }                                                                   \
    if (del_k != kh_end(h)) {                                           \
                                                        \
      h->keys[del_k] = key;                                             \
      h->ed_flags[del_k/4] &= ~__m_del[del_k%4];                        \
      h->size++;                                                        \
      if (ret) *ret = 2;                                                \
      return del_k;                                                     \
    }                                                                   \
    else {                                                              \
                                                      \
      h->keys[k] = key;                                                 \
      h->ed_flags[k/4] &= ~__m_empty[k%4];                              \
      h->size++;                                                        \
      if (ret) *ret = 1;                                                \
      return k;                                                         \
    }                                                                   \
  }                                                                     \
  void kh_del_##name(mrb_state *mrb, kh_##name##_t *h, khint_t x)       \
  {                                                                     \
    (void)mrb;                                                          \
    mrb_assert(x != h->n_buckets && !__ac_iseither(h->ed_flags, x));    \
    h->ed_flags[x/4] |= __m_del[x%4];                                   \
    h->size--;                                                          \
  }                                                                     \
  kh_##name##_t *kh_copy_##name(mrb_state *mrb, kh_##name##_t *h)       \
  {                                                                     \
    kh_##name##_t *h2;                                                  \
    khiter_t k, k2;                                                     \
                                                                        \
    h2 = kh_init_##name(mrb);                                           \
    for (k = kh_begin(h); k != kh_end(h); k++) {                        \
      if (kh_exist(h, k)) {                                             \
        k2 = kh_put_##name(mrb, h2, kh_key(h, k), NULL);                \
        if (kh_is_map) kh_value(h2, k2) = kh_value(h, k);               \
      }                                                                 \
    }                                                                   \
    return h2;                                                          \
  }
#define KHASH_MIN_SIZE 8

#define UPPER_BOUND(x) ((x)>>2|(x)>>1)
#define __ac_isdel(ed_flag, i) (ed_flag[(i)/4]&__m_del[(i)%4])
#define __ac_iseither(ed_flag, i) (ed_flag[(i)/4]&__m_either[(i)%4])
#define __ac_isempty(ed_flag, i) (ed_flag[(i)/4]&__m_empty[(i)%4])
#define kh_begin(h) (khint_t)(0)
#define kh_clear(name, mrb, h) kh_clear_##name(mrb, h)
#define kh_copy(name, mrb, h) kh_copy_##name(mrb, h)
#define kh_del(name, mrb, h, k) kh_del_##name(mrb, h, k)
#define kh_destroy(name, mrb, h) kh_destroy_##name(mrb, h)
#define kh_end(h) ((h)->n_buckets)
#define kh_exist(h, x) (!__ac_iseither((h)->ed_flags, (x)))
#define kh_get(name, mrb, h, k) kh_get_##name(mrb, h, k)
#define kh_init(name,mrb) kh_init_##name(mrb)
#define kh_init_size(name,mrb,size) kh_init_##name##_size(mrb,size)
#define kh_int64_hash_equal(mrb,a, b) (a == b)
#define kh_int64_hash_func(mrb,key) (khint_t)((key)>>33^(key)^(key)<<11)
#define kh_int_hash_equal(mrb,a, b) (a == b)
#define kh_int_hash_func(mrb,key) (khint_t)((key)^((key)<<2)^((key)>>2))
#define kh_key(h, x) ((h)->keys[x])
#define kh_n_buckets(h) ((h)->n_buckets)
#define kh_put(name, mrb, h, k) kh_put_##name(mrb, h, k, NULL)
#define kh_put2(name, mrb, h, k, r) kh_put_##name(mrb, h, k, r)
#define kh_resize(name, mrb, h, s) kh_resize_##name(mrb, h, s)
#define kh_size(h) ((h)->size)
#define kh_str_hash_equal(mrb,a, b) (strcmp(a, b) == 0)
#define kh_str_hash_func(mrb,key) __ac_X31_hash_string(key)
#define kh_val(h, x) ((h)->vals[x])
#define kh_value(h, x) ((h)->vals[x])
#define khash_mask(h) ((h)->n_buckets-1)
#define khash_power2(v) do { \
  v--;\
  v |= v >> 1;\
  v |= v >> 2;\
  v |= v >> 4;\
  v |= v >> 8;\
  v |= v >> 16;\
  v++;\
} while (0)
#define khash_t(name) kh_##name##_t
#define khash_upper_bound(h) (UPPER_BOUND((h)->n_buckets))
#define DBL_EPSILON ((double)2.22044604925031308085e-16L)
#define E_ARGUMENT_ERROR     mrb_exc_get_id(mrb, MRB_ERROR_SYM(ArgumentError))
#define E_FIBER_ERROR mrb_exc_get_id(mrb, MRB_ERROR_SYM(FiberError))
# define E_FLOATDOMAIN_ERROR mrb_exc_get_id(mrb, MRB_ERROR_SYM(FloatDomainError))
#define E_FROZEN_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(FrozenError))
#define E_INDEX_ERROR        mrb_exc_get_id(mrb, MRB_ERROR_SYM(IndexError))
#define E_KEY_ERROR          mrb_exc_get_id(mrb, MRB_ERROR_SYM(KeyError))
#define E_LOCALJUMP_ERROR    mrb_exc_get_id(mrb, MRB_ERROR_SYM(LocalJumpError))
#define E_NAME_ERROR         mrb_exc_get_id(mrb, MRB_ERROR_SYM(NameError))
#define E_NOMETHOD_ERROR     mrb_exc_get_id(mrb, MRB_ERROR_SYM(NoMethodError))
#define E_NOTIMP_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(NotImplementedError))
#define E_RANGE_ERROR        mrb_exc_get_id(mrb, MRB_ERROR_SYM(RangeError))
#define E_REGEXP_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(RegexpError))
#define E_RUNTIME_ERROR      mrb_exc_get_id(mrb, MRB_ERROR_SYM(RuntimeError))
#define E_SCRIPT_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(ScriptError))
#define E_SYNTAX_ERROR       mrb_exc_get_id(mrb, MRB_ERROR_SYM(SyntaxError))
#define E_TYPE_ERROR         mrb_exc_get_id(mrb, MRB_ERROR_SYM(TypeError))
#define E_ZERODIV_ERROR      mrb_exc_get_id(mrb, MRB_ERROR_SYM(ZeroDivisionError))
#define FLT_EPSILON (1.19209290e-07f)
#define ISALNUM(c) (ISALPHA(c) || ISDIGIT(c))
#define ISALPHA(c) ((((unsigned)(c) | 0x20) - 'a') < 26)
#define ISASCII(c) ((unsigned)(c) <= 0x7f)
#define ISBLANK(c) ((c) == ' ' || (c) == '\t')
#define ISCNTRL(c) ((unsigned)(c) < 0x20 || (c) == 0x7f)
#define ISDIGIT(c) (((unsigned)(c) - '0') < 10)
#define ISLOWER(c) (((unsigned)(c) - 'a') < 26)
#define ISPRINT(c) (((unsigned)(c) - 0x20) < 0x5f)
#define ISSPACE(c) ((c) == ' ' || (unsigned)(c) - '\t' < 5)
#define ISUPPER(c) (((unsigned)(c) - 'A') < 26)
#define ISXDIGIT(c) (ISDIGIT(c) || ((unsigned)(c) | 0x20) - 'a' < 6)
#define LDBL_EPSILON (1.08420217248550443401e-19L)
#define MRB_ARGS_ANY()      MRB_ARGS_REST()
#define MRB_ARGS_ARG(n1,n2)   (MRB_ARGS_REQ(n1)|MRB_ARGS_OPT(n2))
#define MRB_ARGS_BLOCK()    ((mrb_aspec)1)
#define MRB_ARGS_KEY(n1,n2) ((mrb_aspec)((((n1)&0x1f) << 2) | ((n2)?(1<<1):0)))
#define MRB_ARGS_NONE()     ((mrb_aspec)0)
#define MRB_ARGS_OPT(n)     ((mrb_aspec)((n)&0x1f) << 13)
#define MRB_ARGS_POST(n)    ((mrb_aspec)((n)&0x1f) << 7)
#define MRB_ARGS_REQ(n)     ((mrb_aspec)((n)&0x1f) << 18)
#define MRB_ARGS_REST()     ((mrb_aspec)(1 << 12))
#define MRB_ERROR_SYM(sym) mrb_intern_lit(mrb, #sym)
#define MRB_FIXED_STATE_ATEXIT_STACK_SIZE 5
#define MRB_FLOAT_EPSILON FLT_EPSILON
# define MRB_METHOD_CACHE_SIZE (1<<8)
#define MRB_OBJ_ALLOC(mrb, tt, klass) ((MRB_VTYPE_TYPEOF(tt)*)mrb_obj_alloc(mrb, tt, klass))

#define SIZE_MAX __SIZE_MAX__
#define TOLOWER(c) (ISUPPER(c) ? ((c) | 0x20) : (c))
#define TOUPPER(c) (ISLOWER(c) ? ((c) & 0x5f) : (c))



# define __func__ __FUNCTION__
# define _mrb_static_assert_cat(a, b) _mrb_static_assert_cat0(a, b)
# define _mrb_static_assert_cat0(a, b) a##b
#  define _mrb_static_assert_id(prefix) _mrb_static_assert_cat(prefix, __COUNTER__)
#define mrb_as_float(mrb, x) mrb_float(mrb_ensure_float_type(mrb, x))
#define mrb_as_int(mrb, val) mrb_integer(mrb_ensure_int_type(mrb, val))
#define mrb_assert(p) assert(p)
#define mrb_assert_int_fit(t1,n,t2,max) assert((n)>=0 && ((sizeof(n)<=sizeof(t2))||(n<=(t1)(max))))
#define mrb_check_convert_type(mrb, val, type, tname, method) mrb_type_convert_check(mrb, val, type, mrb_intern_lit(mrb, method))
#define mrb_context_run(m,p,s,k) mrb_vm_run((m),(p),(s),(k))
#define mrb_convert_type(mrb, val, type, tname, method) mrb_type_convert(mrb, val, type, mrb_intern_lit(mrb, method))
#define mrb_exc_get(mrb, name) mrb_exc_get_id(mrb, mrb_intern_cstr(mrb, name))
#define mrb_field_write_barrier_value(mrb, obj, val) do{\
  if (!mrb_immediate_p(val)) mrb_field_write_barrier((mrb), (obj), mrb_basic_ptr(val)); \
} while (0)
#define mrb_gc_mark_value(mrb,val) do {\
  if (!mrb_immediate_p(val)) mrb_gc_mark((mrb), mrb_basic_ptr(val)); \
} while (0)
#define mrb_int(mrb, val) mrb_as_int(mrb, val)
#define mrb_intern_lit(mrb, lit) mrb_intern_static(mrb, (lit ""), mrb_strlen_lit(lit))
#define mrb_locale_free(p) free(p)
#define mrb_locale_from_utf8(p, l) ((char*)(p))
# define mrb_static_assert(...) \
    mrb_static_assert_expand(mrb_static_assert_selector(__VA_ARGS__, mrb_static_assert2, mrb_static_assert1, _)(__VA_ARGS__))
# define mrb_static_assert1(exp) static_assert(exp)
# define mrb_static_assert2(exp, str) static_assert(exp, str)
# define mrb_static_assert_expand(...) __VA_ARGS__ 
#define mrb_static_assert_powerof2(num) mrb_static_assert((num) > 0 && (num) == ((num) & -(num)), "need power of 2 for " #num)
# define mrb_static_assert_selector(a, b, name, ...) name
#define mrb_str_new_cstr_frozen(mrb,p) mrb_obj_freeze(mrb,mrb_str_new_cstr(mrb,p))
#define mrb_str_new_frozen(mrb,p,len) mrb_obj_freeze(mrb,mrb_str_new(mrb,p,len))
#define mrb_str_new_lit(mrb, lit) mrb_str_new_static(mrb, (lit), mrb_strlen_lit(lit))
#define mrb_str_new_lit_frozen(mrb,lit) mrb_obj_freeze(mrb,mrb_str_new_lit(mrb,lit))
#define mrb_str_new_static_frozen(mrb,p,len) mrb_obj_freeze(mrb,mrb_str_new_static(mrb,p,len))
#define mrb_str_to_str(mrb, str) mrb_obj_as_string(mrb, str)
#define mrb_string_type(mrb, str) mrb_ensure_string_type(mrb,str)
#define mrb_strlen_lit(lit) (sizeof(lit "") - 1)
#define mrb_sym2name(mrb,sym) mrb_sym_name(mrb,sym)
#define mrb_sym2name_len(mrb,sym,len) mrb_sym_name_len(mrb,sym,len)
#define mrb_sym2str(mrb,sym) mrb_sym_str(mrb,sym)
#define mrb_to_float(mrb, val) mrb_ensure_float_type(mrb, val)
#define mrb_to_int(mrb, val) mrb_ensure_int_type(mrb, val)
#define mrb_to_integer(mrb, val) mrb_ensure_int_type(mrb, val)
#define mrb_to_str(mrb, str) mrb_ensure_string_type(mrb,str)
#define mrb_toplevel_run(m,p) mrb_toplevel_run_keep((m),(p),0)
#define mrb_toplevel_run_keep(m,p,k) mrb_top_run((m),(p),mrb_top_self(m),(k))
#define mrb_utf8_free(p) free(p)
#define mrb_utf8_from_locale(p, l) ((char*)(p))
#define MRB_STRINGIZE(expr) MRB_STRINGIZE0(expr)
#define MRB_STRINGIZE0(expr) #expr
#define MRUBY_AUTHOR "mruby developers"
#define MRUBY_BIRTH_YEAR 2010
#define MRUBY_COPYRIGHT                \
  "mruby - Copyright (c) "             \
  MRB_STRINGIZE(MRUBY_BIRTH_YEAR)"-"   \
  MRB_STRINGIZE(MRUBY_RELEASE_YEAR)" " \
  MRUBY_AUTHOR                         \

#define MRUBY_DESCRIPTION     \
  "mruby " MRUBY_VERSION      \
  MRUBY_PATCHLEVEL_STR        \
  " (" MRUBY_RELEASE_DATE ")" \

#define MRUBY_PATCHLEVEL -1
#   define MRUBY_PATCHLEVEL_STR "dev"
#define MRUBY_RELEASE_DATE    \
  MRUBY_RELEASE_YEAR_STR "-"  \
  MRUBY_RELEASE_MONTH_STR "-" \
  MRUBY_RELEASE_DAY_STR
#define MRUBY_RELEASE_DAY 31
#define MRUBY_RELEASE_DAY_STR "0" MRB_STRINGIZE(MRUBY_RELEASE_DAY)
#define MRUBY_RELEASE_MAJOR 3
#define MRUBY_RELEASE_MINOR 1
#define MRUBY_RELEASE_MONTH 3
#define MRUBY_RELEASE_MONTH_STR "0" MRB_STRINGIZE(MRUBY_RELEASE_MONTH)
#define MRUBY_RELEASE_NO (MRUBY_RELEASE_MAJOR * 100 * 100 + MRUBY_RELEASE_MINOR * 100 + MRUBY_RELEASE_TEENY)
#define MRUBY_RELEASE_TEENY 0
#define MRUBY_RELEASE_YEAR 2022
#define MRUBY_RELEASE_YEAR_STR MRB_STRINGIZE(MRUBY_RELEASE_YEAR)
#define MRUBY_RUBY_ENGINE  "mruby"
#define MRUBY_RUBY_VERSION "3.1"
#define MRUBY_VERSION MRB_STRINGIZE(MRUBY_RELEASE_MAJOR) "." MRB_STRINGIZE(MRUBY_RELEASE_MINOR) "." MRB_STRINGIZE(MRUBY_RELEASE_TEENY)

#define MRB_EACH_OBJ_BREAK 1
#define MRB_EACH_OBJ_OK 0
#define MRB_GC_ARENA_SIZE 100
#define MRB_GC_RED 7

#  define FALSE false
#  define INFINITY (*(float *)&IEEE754_INFINITY_BITS_SINGLE)
# define MRB_ENDIAN_LOHI(a,b) b a
# define MRB_INT_BIT 64
# define MRB_INT_MAX INT64_MAX
# define MRB_INT_MIN INT64_MIN

# define MRB_PRId PRId64
# define MRB_PRIo PRIo64
# define MRB_PRIx PRIx64
# define MRB_SSIZE_MAX INTPTR_MAX
#define MRB_TT_FIXNUM MRB_TT_INTEGER
#define MRB_VTYPE_DEFINE(tt, type, name) tt,
#define MRB_VTYPE_FOREACH(f) \
                  \
  f(MRB_TT_FALSE,       void,               "false") \
  f(MRB_TT_TRUE,        void,               "true") \
  f(MRB_TT_SYMBOL,      void,               "Symbol") \
  f(MRB_TT_UNDEF,       void,               "undefined") \
  f(MRB_TT_FREE,        void,               "free") \
  f(MRB_TT_FLOAT,       struct RFloat,      "Float") \
  f(MRB_TT_INTEGER,     struct RInteger,    "Integer") \
  f(MRB_TT_CPTR,        struct RCptr,       "cptr") \
  f(MRB_TT_OBJECT,      struct RObject,     "Object") \
  f(MRB_TT_CLASS,       struct RClass,      "Class") \
  f(MRB_TT_MODULE,      struct RClass,      "Module") \
  f(MRB_TT_ICLASS,      struct RClass,      "iClass") \
  f(MRB_TT_SCLASS,      struct RClass,      "SClass") \
  f(MRB_TT_PROC,        struct RProc,       "Proc") \
  f(MRB_TT_ARRAY,       struct RArray,      "Array") \
  f(MRB_TT_HASH,        struct RHash,       "Hash") \
  f(MRB_TT_STRING,      struct RString,     "String") \
  f(MRB_TT_RANGE,       struct RRange,      "Range") \
  f(MRB_TT_EXCEPTION,   struct RException,  "Exception") \
  f(MRB_TT_ENV,         struct REnv,        "env") \
  f(MRB_TT_DATA,        struct RData,       "Data") \
  f(MRB_TT_FIBER,       struct RFiber,      "Fiber") \
  f(MRB_TT_STRUCT,      struct RArray,      "Struct") \
  f(MRB_TT_ISTRUCT,     struct RIStruct,    "istruct") \
  f(MRB_TT_BREAK,       struct RBreak,      "break") \
  f(MRB_TT_COMPLEX,     struct RComplex,    "Complex") \
  f(MRB_TT_RATIONAL,    struct RRational,   "Rational")
#define MRB_VTYPE_TYPEDEF(tt, type, name) typedef type MRB_VTYPE_TYPEOF(tt);
#define MRB_VTYPE_TYPEOF(tt) MRB_TYPEOF_##tt

#  define NAN ((float)(INFINITY - INFINITY))
# define PRId16 "hd"
# define PRId32 "d"
# define PRId64 "lld"
# define PRIo16 "ho"
# define PRIo32 "o"
# define PRIo64 "llo"
# define PRIu16 "hu"
# define PRIu32 "u"
# define PRIu64 "llu"
# define PRIx16 "hx"
# define PRIx32 "x"
# define PRIx64 "llx"
#  define TRUE true
#  define isfinite(n) _finite(n)
#  define isinf(n) (!_finite(n) && !_isnan(n))
#  define isnan _isnan
#define mrb_array_p(o) (mrb_type(o) == MRB_TT_ARRAY)
#define mrb_bool(o)   (mrb_type(o) != MRB_TT_FALSE)
#define mrb_break_p(o) (mrb_type(o) == MRB_TT_BREAK)
#define mrb_class_p(o) (mrb_type(o) == MRB_TT_CLASS)
#define mrb_cptr_p(o) (mrb_type(o) == MRB_TT_CPTR)
#define mrb_data_p(o) (mrb_type(o) == MRB_TT_DATA)
#define mrb_env_p(o) (mrb_type(o) == MRB_TT_ENV)
#define mrb_exception_p(o) (mrb_type(o) == MRB_TT_EXCEPTION)
#define mrb_false_p(o) (mrb_type(o) == MRB_TT_FALSE && !!mrb_fixnum(o))
#define mrb_fiber_p(o) (mrb_type(o) == MRB_TT_FIBER)
#define mrb_fixnum_p(o) mrb_integer_p(o)
#define mrb_float_p(o) (mrb_type(o) == MRB_TT_FLOAT)
#define mrb_free_p(o) (mrb_type(o) == MRB_TT_FREE)
#define mrb_hash_p(o) (mrb_type(o) == MRB_TT_HASH)
#define mrb_iclass_p(o) (mrb_type(o) == MRB_TT_ICLASS)
#define mrb_immediate_p(o) (mrb_type(o) <= MRB_TT_CPTR)
#define mrb_integer_p(o) (mrb_type(o) == MRB_TT_INTEGER)
#define mrb_istruct_p(o) (mrb_type(o) == MRB_TT_ISTRUCT)
#define mrb_module_p(o) (mrb_type(o) == MRB_TT_MODULE)
#define mrb_nil_p(o)  (mrb_type(o) == MRB_TT_FALSE && !mrb_fixnum(o))
#define mrb_object_p(o) (mrb_type(o) == MRB_TT_OBJECT)
#define mrb_proc_p(o) (mrb_type(o) == MRB_TT_PROC)
#define mrb_range_p(o) (mrb_type(o) == MRB_TT_RANGE)
# define mrb_ro_data_p(p) FALSE
#define mrb_sclass_p(o) (mrb_type(o) == MRB_TT_SCLASS)
#define mrb_string_p(o) (mrb_type(o) == MRB_TT_STRING)
#define mrb_symbol_p(o) (mrb_type(o) == MRB_TT_SYMBOL)
#define mrb_test(o)   mrb_bool(o)
#define mrb_true_p(o)  (mrb_type(o) == MRB_TT_TRUE)
#define mrb_undef_p(o) (mrb_type(o) == MRB_TT_UNDEF)
#  define signbit(n) (_copysign(1.0, (n)) < 0.0)
# define snprintf(s, n, format, ...) mrb_msvc_snprintf(s, n, format, __VA_ARGS__)
# define vsnprintf(s, n, format, arg) mrb_msvc_vsnprintf(s, n, format, arg)
#define MRB_FLAG_TEST(obj, flag) ((obj)->flags & (flag))
#define MRB_FL_OBJ_IS_FROZEN (1 << 20)
#define MRB_FROZEN_P(o) ((o)->flags & MRB_FL_OBJ_IS_FROZEN)
#define MRB_OBJECT_HEADER \
  struct RClass *c;       \
  struct RBasic *gcnext;  \
  enum mrb_vtype tt:8;    \
  uint32_t color:3;       \
  uint32_t flags:21
#define MRB_SET_FROZEN_FLAG(o) ((o)->flags |= MRB_FL_OBJ_IS_FROZEN)
#define MRB_UNSET_FROZEN_FLAG(o) ((o)->flags &= ~MRB_FL_OBJ_IS_FROZEN)

#define mrb_basic_ptr(v) ((struct RBasic*)(mrb_ptr(v)))
#define mrb_frozen_p(o) MRB_FROZEN_P(o)
#define mrb_obj_ptr(v)   ((struct RObject*)(mrb_ptr(v)))
#define mrb_special_const_p(x) mrb_immediate_p(x)
# define MRB_API __declspec(dllexport)
# define MRB_BEGIN_DECL extern "C" {
# define MRB_END_DECL }
#define MRB_INLINE static inline
#   define MRB_MINGW32_LEGACY
#  define MRB_MINGW64_VERSION  (__MINGW64_VERSION_MAJOR * 1000 + __MINGW64_VERSION_MINOR)

#  define inline __inline
# define mrb_deprecated __attribute__((deprecated))
# define mrb_noreturn _Noreturn


#  define MRB_ENDIAN_BIG
#  define MRB_HEAP_PAGE_SIZE 256
#  define MRB_INT32
#  define MRB_INT64
# define MRB_NO_DIRECT_THREADING
# define MRB_NO_FLOAT
#  define MRB_NO_METHOD_CACHE
# define MRB_NO_STDIO
# define MRB_USE_ALL_SYMBOLS
# define MRB_USE_CXX_ABI
# define MRB_USE_CXX_EXCEPTION
# define MRB_USE_DEBUG_HOOK

# define MRB_USE_FLOAT32
#   define MRB_USE_METHOD_T_STRUCT
# define MRB_WORD_BOXING

#define IREP_TT_NFLAG 1       
#define IREP_TT_SFLAG 2       
#define MRB_IREP_NO_FREE 2
#define MRB_IREP_STATIC  (MRB_ISEQ_NO_FREE | MRB_IREP_NO_FREE)
#define MRB_ISEQ_NO_FREE 1

#define mrb_irep_catch_handler_pack(n, v)   uint32_to_bin(n, v)
#define mrb_irep_catch_handler_unpack(v)    bin_to_uint32(v)
#define MRB_PARSER_TOKBUF_MAX (UINT16_MAX-1)
#define MRB_PARSER_TOKBUF_SIZE 256

#define STR_FUNC_ARRAY   0x20
#define STR_FUNC_EXPAND  0x02
#define STR_FUNC_HEREDOC 0x40
#define STR_FUNC_PARSING 0x01
#define STR_FUNC_REGEXP  0x04
#define STR_FUNC_SYMBOL  0x10
#define STR_FUNC_WORD    0x08
#define STR_FUNC_XQUOTE  0x80
#define FIXABLE(f) TYPED_FIXABLE(f,mrb_int)
#define FIXABLE_FLOAT(f) ((f)>=-9223372036854775808.0 && (f)<9223372036854775808.0)
#  define MRB_FLT_DIG           FLT_DIG
#  define MRB_FLT_EPSILON       FLT_EPSILON
#  define MRB_FLT_MANT_DIG      FLT_MANT_DIG
#  define MRB_FLT_MAX           FLT_MAX
#  define MRB_FLT_MAX_10_EXP    FLT_MAX_10_EXP
#  define MRB_FLT_MAX_EXP       FLT_MAX_EXP
#  define MRB_FLT_MIN           FLT_MIN
#  define MRB_FLT_MIN_10_EXP    FLT_MIN_10_EXP
#  define MRB_FLT_MIN_EXP       FLT_MIN_EXP
# define MRB_FLT_RADIX          FLT_RADIX
# define MRB_HAVE_TYPE_GENERIC_CHECKED_ARITHMETIC_BUILTINS
#define MRB_INT_OVERFLOW_MASK ((mrb_uint)1 << (MRB_INT_BIT - 1))

#define NEGFIXABLE(f) TYPED_NEGFIXABLE(f,mrb_int)
#define POSFIXABLE(f) TYPED_POSFIXABLE(f,mrb_int)
#define TYPED_FIXABLE(f,t) (TYPED_POSFIXABLE(f,t) && TYPED_NEGFIXABLE(f,t))
#define TYPED_NEGFIXABLE(f,t) ((f) >= (t)MRB_FIXNUM_MIN)
#define TYPED_POSFIXABLE(f,t) ((f) <= (t)MRB_FIXNUM_MAX)
  #define __has_builtin(x) 0
#define mrb_fixnum_to_str(mrb, x, base) mrb_integer_to_str(mrb, x, base)
#define mrb_flo_to_fixnum(mrb, val) mrb_float_to_integer(mrb, val)
#define mrb_to_flo(mrb, x) mrb_as_float(mrb, x)
#define MRB_CLASS_ORIGIN(c) do {\
  if ((c)->flags & MRB_FL_CLASS_IS_PREPENDED) {\
    (c) = (c)->super;\
    while (!((c)->flags & MRB_FL_CLASS_IS_ORIGIN)) {\
      (c) = (c)->super;\
    }\
  }\
} while (0)
#define MRB_FL_CLASS_IS_INHERITED (1 << 17)
#define MRB_FL_CLASS_IS_ORIGIN (1 << 18)
#define MRB_FL_CLASS_IS_PREPENDED (1 << 19)
#define MRB_INSTANCE_TT(c) (enum mrb_vtype)((c)->flags & MRB_INSTANCE_TT_MASK)
#define MRB_INSTANCE_TT_MASK (0xFF)
#define MRB_SET_INSTANCE_TT(c, tt) ((c)->flags = (((c)->flags & ~MRB_INSTANCE_TT_MASK) | (char)(tt)))

#define mrb_class_ptr(v)    ((struct RClass*)(mrb_ptr(v)))

#define MRB_HASH_AR_EA_CAPA_BIT     5
#define MRB_HASH_AR_EA_CAPA_MASK    ((1 << MRB_HASH_AR_EA_CAPA_BIT) - 1)
#define MRB_HASH_AR_EA_CAPA_SHIFT   0
#define MRB_HASH_AR_EA_N_USED_MASK  (MRB_HASH_AR_EA_CAPA_MASK << MRB_HASH_AR_EA_N_USED_SHIFT)
#define MRB_HASH_AR_EA_N_USED_SHIFT MRB_HASH_AR_EA_CAPA_BIT
#define MRB_HASH_DEFAULT            (1 << (MRB_HASH_SIZE_FLAGS_SHIFT + 0))
#define MRB_HASH_HT                 (1 << (MRB_HASH_SIZE_FLAGS_SHIFT + 2))
#define MRB_HASH_IB_BIT_BIT         5
#define MRB_HASH_IB_BIT_MASK        ((1 << MRB_HASH_IB_BIT_BIT) - 1)
#define MRB_HASH_IB_BIT_SHIFT       0
#define MRB_HASH_PROC_DEFAULT       (1 << (MRB_HASH_SIZE_FLAGS_SHIFT + 1))
#define MRB_HASH_SIZE_FLAGS_SHIFT   (MRB_HASH_AR_EA_CAPA_BIT * 2)
#define MRB_RHASH_DEFAULT_P(hash) (RHASH(hash)->flags & MRB_HASH_DEFAULT)
#define MRB_RHASH_PROCDEFAULT_P(hash) (RHASH(hash)->flags & MRB_HASH_PROC_DEFAULT)

#define RHASH(hash) ((struct RHash*)(mrb_ptr(hash)))
#define mrb_hash_ptr(v)    ((struct RHash*)(mrb_ptr(v)))
#define mrb_hash_value(p)  mrb_obj_value((void*)(p))
#define ARY_CAPA(a) (ARY_EMBED_P(a)?MRB_ARY_EMBED_LEN_MAX:(a)->as.heap.aux.capa)
#define ARY_EMBED_LEN(a) 0
#define ARY_EMBED_P(a) 0
#define ARY_EMBED_PTR(a) 0
#define ARY_LEN(a) (ARY_EMBED_P(a)?ARY_EMBED_LEN(a):(mrb_int)(a)->as.heap.len)
#define ARY_PTR(a) (ARY_EMBED_P(a)?ARY_EMBED_PTR(a):(a)->as.heap.ptr)
#define ARY_SET_EMBED_LEN(a,len) (void)0
#define ARY_SET_LEN(a,n) do {\
  if (ARY_EMBED_P(a)) {\
    mrb_assert((n) <= MRB_ARY_EMBED_LEN_MAX); \
    ARY_SET_EMBED_LEN(a,n);\
  }\
  else\
    (a)->as.heap.len = (n);\
} while (0)
#define ARY_SET_SHARED_FLAG(a) ((a)->flags |= MRB_ARY_SHARED)
#define ARY_SHARED_P(a) ((a)->flags & MRB_ARY_SHARED)
#define ARY_UNSET_EMBED_FLAG(a) (void)0
#define ARY_UNSET_SHARED_FLAG(a) ((a)->flags &= ~MRB_ARY_SHARED)
# define MRB_ARY_EMBED_LEN_MAX 0
#define MRB_ARY_EMBED_MASK  7
# define MRB_ARY_NO_EMBED
#define MRB_ARY_SHARED      256

#define RARRAY(v)  ((struct RArray*)(mrb_ptr(v)))
#define RARRAY_LEN(a) ARY_LEN(RARRAY(a))
#define RARRAY_PTR(a) ARY_PTR(RARRAY(a))
#define mrb_ary_ptr(v)    ((struct RArray*)(mrb_ptr(v)))
#define mrb_ary_ref(mrb, ary, n) mrb_ary_entry(ary, n)
#define mrb_ary_value(p)  mrb_obj_value((void*)(p))
