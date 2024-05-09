






































MG_INTERNAL struct mg_connection *mg_do_connect(struct mg_connection *nc, int proto, union socket_address *sa);


MG_INTERNAL int mg_parse_address(const char *str, union socket_address *sa, int *proto, char *host, size_t host_len);
MG_INTERNAL void mg_call(struct mg_connection *nc, mg_event_handler_t ev_handler, void *user_data, int ev, void *ev_data);

void mg_forward(struct mg_connection *from, struct mg_connection *to);
MG_INTERNAL void mg_add_conn(struct mg_mgr *mgr, struct mg_connection *c);
MG_INTERNAL void mg_remove_conn(struct mg_connection *c);
MG_INTERNAL struct mg_connection *mg_create_connection( struct mg_mgr *mgr, mg_event_handler_t callback, struct mg_add_sock_opts opts);



int to_wchar(const char *path, wchar_t *wbuf, size_t wbuf_len);


struct ctl_msg {
  mg_event_handler_t callback;
  char message[MG_CTL_MSG_MESSAGE_SIZE];
};


struct mg_mqtt_message;




MG_INTERNAL int parse_mqtt(struct mbuf *io, struct mg_mqtt_message *mm);



extern void *(*test_malloc)(size_t size);
extern void *(*test_calloc)(size_t count, size_t size);






struct mg_serve_http_opts;


MG_INTERNAL size_t mg_handle_chunked(struct mg_connection *nc, struct http_message *hm, char *buf, size_t blen);



MG_INTERNAL int mg_uri_to_local_path(struct http_message *hm, const struct mg_serve_http_opts *opts, char **local_path, struct mg_str *remainder);


MG_INTERNAL time_t mg_parse_date_string(const char *datetime);
MG_INTERNAL int mg_is_not_modified(struct http_message *hm, cs_stat_t *st);


MG_INTERNAL void mg_handle_cgi(struct mg_connection *nc, const char *prog, const struct mg_str *path_info, const struct http_message *hm, const struct mg_serve_http_opts *opts);


struct mg_http_proto_data_cgi;
MG_INTERNAL void mg_http_free_proto_data_cgi(struct mg_http_proto_data_cgi *d);


MG_INTERNAL void mg_handle_ssi_request(struct mg_connection *nc, struct http_message *hm, const char *path, const struct mg_serve_http_opts *opts);




MG_INTERNAL int mg_is_dav_request(const struct mg_str *s);
MG_INTERNAL void mg_handle_propfind(struct mg_connection *nc, const char *path, cs_stat_t *stp, struct http_message *hm, struct mg_serve_http_opts *opts);

MG_INTERNAL void mg_handle_lock(struct mg_connection *nc, const char *path);
MG_INTERNAL void mg_handle_mkcol(struct mg_connection *nc, const char *path, struct http_message *hm);
MG_INTERNAL void mg_handle_move(struct mg_connection *c, const struct mg_serve_http_opts *opts, const char *path, struct http_message *hm);

MG_INTERNAL void mg_handle_delete(struct mg_connection *nc, const struct mg_serve_http_opts *opts, const char *path);

MG_INTERNAL void mg_handle_put(struct mg_connection *nc, const char *path, struct http_message *hm);


MG_INTERNAL void mg_ws_handler(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data));
MG_INTERNAL void mg_ws_handshake(struct mg_connection *nc, const struct mg_str *key, struct http_message *);




MG_INTERNAL int mg_get_errno(void);

MG_INTERNAL void mg_close_conn(struct mg_connection *conn);


MG_INTERNAL int mg_sntp_parse_reply(const char *buf, int len, struct mg_sntp_message *msg);












extern "C" {



















}























static void cs_base64_emit_code(struct cs_base64_ctx *ctx, int v) {
  if (v < NUM_UPPERCASES) {
    ctx->b64_putc(v + 'A', ctx->user_data);
  } else if (v < (NUM_LETTERS)) {
    ctx->b64_putc(v - NUM_UPPERCASES + 'a', ctx->user_data);
  } else if (v < (NUM_LETTERS + NUM_DIGITS)) {
    ctx->b64_putc(v - NUM_LETTERS + '0', ctx->user_data);
  } else {
    ctx->b64_putc(v - NUM_LETTERS - NUM_DIGITS == 0 ? '+' : '/', ctx->user_data);
  }
}

static void cs_base64_emit_chunk(struct cs_base64_ctx *ctx) {
  int a, b, c;

  a = ctx->chunk[0];
  b = ctx->chunk[1];
  c = ctx->chunk[2];

  cs_base64_emit_code(ctx, a >> 2);
  cs_base64_emit_code(ctx, ((a & 3) << 4) | (b >> 4));
  if (ctx->chunk_size > 1) {
    cs_base64_emit_code(ctx, (b & 15) << 2 | (c >> 6));
  }
  if (ctx->chunk_size > 2) {
    cs_base64_emit_code(ctx, c & 63);
  }
}

void cs_base64_init(struct cs_base64_ctx *ctx, cs_base64_putc_t b64_putc, void *user_data) {
  ctx->chunk_size = 0;
  ctx->b64_putc = b64_putc;
  ctx->user_data = user_data;
}

void cs_base64_update(struct cs_base64_ctx *ctx, const char *str, size_t len) {
  const unsigned char *src = (const unsigned char *) str;
  size_t i;
  for (i = 0; i < len; i++) {
    ctx->chunk[ctx->chunk_size++] = src[i];
    if (ctx->chunk_size == 3) {
      cs_base64_emit_chunk(ctx);
      ctx->chunk_size = 0;
    }
  }
}

void cs_base64_finish(struct cs_base64_ctx *ctx) {
  if (ctx->chunk_size > 0) {
    int i;
    memset(&ctx->chunk[ctx->chunk_size], 0, 3 - ctx->chunk_size);
    cs_base64_emit_chunk(ctx);
    for (i = 0; i < (3 - ctx->chunk_size); i++) {
      ctx->b64_putc('=', ctx->user_data);
    }
  }
}

































void cs_base64_encode(const unsigned char *src, int src_len, char *dst) {
  BASE64_ENCODE_BODY;
}












void cs_fprint_base64(FILE *f, const unsigned char *src, int src_len) {
  BASE64_ENCODE_BODY;
}






static unsigned char from_b64(unsigned char ch) {
  
  static const unsigned char tab[128] = {
      255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63, 52,  53,  54,  55, 56,  57,  58,  59, 60,  61,  255, 255, 255, 200, 255, 255, 255, 0,   1,   2, 3,   4,   5,   6, 7,   8,   9,   10, 11,  12,  13,  14, 15,  16,  17,  18, 19,  20,  21,  22, 23,  24,  25,  255, 255, 255, 255, 255, 255, 26,  27,  28, 29,  30,  31,  32, 33,  34,  35,  36, 37,  38,  39,  40, 41,  42,  43,  44, 45,  46,  47,  48, 49,  50,  51,  255, 255, 255, 255, 255, };































  return tab[ch & 127];
}

int cs_base64_decode(const unsigned char *s, int len, char *dst, int *dec_len) {
  unsigned char a, b, c, d;
  int orig_len = len;
  char *orig_dst = dst;
  while (len >= 4 && (a = from_b64(s[0])) != 255 && (b = from_b64(s[1])) != 255 && (c = from_b64(s[2])) != 255 && (d = from_b64(s[3])) != 255) {

    s += 4;
    len -= 4;
    if (a == 200 || b == 200) break; 
    *dst++ = a << 2 | b >> 4;
    if (c == 200) break;
    *dst++ = b << 4 | c >> 2;
    if (d == 200) break;
    *dst++ = c << 6 | d;
  }
  *dst = 0;
  if (dec_len != NULL) *dec_len = (dst - orig_dst);
  return orig_len - len;
}

























extern "C" {



enum cs_log_level {
  LL_NONE = -1, LL_ERROR = 0, LL_WARN = 1, LL_INFO = 2, LL_DEBUG = 3, LL_VERBOSE_DEBUG = 4,  _LL_MIN = -2, _LL_MAX = 5, };










void cs_log_set_level(enum cs_log_level level);


void cs_log_set_filter(const char *pattern);


int cs_log_print_prefix(enum cs_log_level level, const char *func, const char *filename);

extern enum cs_log_level cs_log_threshold;




void cs_log_set_file(FILE *file);


void cs_log_printf(const char *fmt, ...) PRINTF_LIKE(1, 2);

































}

















enum cs_log_level cs_log_threshold WEAK =  LL_VERBOSE_DEBUG;


    LL_ERROR;



static char *s_filter_pattern = NULL;
static size_t s_filter_pattern_len;

void cs_log_set_filter(const char *pattern) WEAK;

FILE *cs_log_file WEAK = NULL;


double cs_log_ts WEAK;


enum cs_log_level cs_log_cur_msg_level WEAK = LL_NONE;

void cs_log_set_filter(const char *pattern) {
  free(s_filter_pattern);
  if (pattern != NULL) {
    s_filter_pattern = strdup(pattern);
    s_filter_pattern_len = strlen(pattern);
  } else {
    s_filter_pattern = NULL;
    s_filter_pattern_len = 0;
  }
}

int cs_log_print_prefix(enum cs_log_level, const char *, const char *) WEAK;
int cs_log_print_prefix(enum cs_log_level level, const char *func, const char *filename) {
  char prefix[21];

  if (level > cs_log_threshold) return 0;
  if (s_filter_pattern != NULL && mg_match_prefix(s_filter_pattern, s_filter_pattern_len, func) == 0 && mg_match_prefix(s_filter_pattern, s_filter_pattern_len, filename) == 0) {

    return 0;
  }

  strncpy(prefix, func, 20);
  prefix[20] = '\0';
  if (cs_log_file == NULL) cs_log_file = stderr;
  cs_log_cur_msg_level = level;
  fprintf(cs_log_file, "%-20s ", prefix);

  {
    double now = cs_time();
    fprintf(cs_log_file, "%7u ", (unsigned int) ((now - cs_log_ts) * 1000000));
    cs_log_ts = now;
  }

  return 1;
}

void cs_log_printf(const char *fmt, ...) WEAK;
void cs_log_printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(cs_log_file, fmt, ap);
  va_end(ap);
  fputc('\n', cs_log_file);
  fflush(cs_log_file);
  cs_log_cur_msg_level = LL_NONE;
}

void cs_log_set_file(FILE *file) WEAK;
void cs_log_set_file(FILE *file) {
  cs_log_file = file;
}



void cs_log_set_filter(const char *pattern) {
  (void) pattern;
}



void cs_log_set_level(enum cs_log_level level) WEAK;
void cs_log_set_level(enum cs_log_level level) {
  cs_log_threshold = level;

  cs_log_ts = cs_time();

}













extern "C" {



typedef struct { int dummy; } DIR;

struct dirent {
  int d_ino;

  char d_name[MAX_PATH];

  
  char d_name[256];

};

DIR *opendir(const char *dir_name);
int closedir(DIR *dir);
struct dirent *readdir(DIR *dir);



}
















struct win32_dir {
  DIR d;
  HANDLE handle;
  WIN32_FIND_DATAW info;
  struct dirent result;
};

DIR *opendir(const char *name) {
  struct win32_dir *dir = NULL;
  wchar_t wpath[MAX_PATH];
  DWORD attrs;

  if (name == NULL) {
    SetLastError(ERROR_BAD_ARGUMENTS);
  } else if ((dir = (struct win32_dir *) MG_MALLOC(sizeof(*dir))) == NULL) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
  } else {
    to_wchar(name, wpath, ARRAY_SIZE(wpath));
    attrs = GetFileAttributesW(wpath);
    if (attrs != 0xFFFFFFFF && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
      (void) wcscat(wpath, L"\\*");
      dir->handle = FindFirstFileW(wpath, &dir->info);
      dir->result.d_name[0] = '\0';
    } else {
      MG_FREE(dir);
      dir = NULL;
    }
  }

  return (DIR *) dir;
}

int closedir(DIR *d) {
  struct win32_dir *dir = (struct win32_dir *) d;
  int result = 0;

  if (dir != NULL) {
    if (dir->handle != INVALID_HANDLE_VALUE)
      result = FindClose(dir->handle) ? 0 : -1;
    MG_FREE(dir);
  } else {
    result = -1;
    SetLastError(ERROR_BAD_ARGUMENTS);
  }

  return result;
}

struct dirent *readdir(DIR *d) {
  struct win32_dir *dir = (struct win32_dir *) d;
  struct dirent *result = NULL;

  if (dir) {
    memset(&dir->result, 0, sizeof(dir->result));
    if (dir->handle != INVALID_HANDLE_VALUE) {
      result = &dir->result;
      (void) WideCharToMultiByte(CP_UTF8, 0, dir->info.cFileName, -1, result->d_name, sizeof(result->d_name), NULL, NULL);


      if (!FindNextFileW(dir->handle, &dir->info)) {
        (void) FindClose(dir->handle);
        dir->handle = INVALID_HANDLE_VALUE;
      }

    } else {
      SetLastError(ERROR_FILE_NOT_FOUND);
    }
  } else {
    SetLastError(ERROR_BAD_ARGUMENTS);
  }

  return result;
}





typedef int cs_dirent_dummy;


















double cs_time(void) WEAK;
double cs_time(void) {
  double now;

  struct timeval tv;
  if (gettimeofday(&tv, NULL ) != 0) return 0;
  now = (double) tv.tv_sec + (((double) tv.tv_usec) / 1000000.0);

  SYSTEMTIME sysnow;
  FILETIME ftime;
  GetLocalTime(&sysnow);
  SystemTimeToFileTime(&sysnow, &ftime);
  
  now = (double) (((int64_t) ftime.dwLowDateTime + ((int64_t) ftime.dwHighDateTime << 32)) / 10000000.0) - 11644473600;



  return now;
}

double cs_timegm(const struct tm *tm) {
  
  static const int month_day[12] = {0,   31,  59,  90,  120, 151, 181, 212, 243, 273, 304, 334};

  
  int month = tm->tm_mon % 12;
  int year = tm->tm_year + tm->tm_mon / 12;
  int year_for_leap;
  int64_t rt;

  if (month < 0) { 
    month += 12;
    --year;
  }

  
  year_for_leap = (month > 1) ? year + 1 : year;

  rt = tm->tm_sec + 60 * (tm->tm_min + 60 * (tm->tm_hour + 24 * (month_day[month] + tm->tm_mday - 1 + 365 * (year - 70)








                       + (year_for_leap - 69) / 4  - (year_for_leap - 1) / 100 + (year_for_leap + 299) / 400)));

  return rt < 0 ? -1 : (double) rt;
}









extern "C" {














}
















static void byteReverse(unsigned char *buf, unsigned longs) {


  do {
    uint32_t t = (uint32_t)((unsigned) buf[3] << 8 | buf[2]) << 16 | ((unsigned) buf[1] << 8 | buf[0]);
    *(uint32_t *) buf = t;
    buf += 4;
  } while (--longs);

  (void) buf;
  (void) longs;

}









void cs_md5_init(cs_md5_ctx *ctx) {
  ctx->buf[0] = 0x67452301;
  ctx->buf[1] = 0xefcdab89;
  ctx->buf[2] = 0x98badcfe;
  ctx->buf[3] = 0x10325476;

  ctx->bits[0] = 0;
  ctx->bits[1] = 0;
}

static void cs_md5_transform(uint32_t buf[4], uint32_t const in[16]) {
  register uint32_t a, b, c, d;

  a = buf[0];
  b = buf[1];
  c = buf[2];
  d = buf[3];

  MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
  MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
  MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
  MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
  MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
  MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
  MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
  MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
  MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

  MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
  MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
  MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
  MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
  MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
  MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
  MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
  MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
  MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
  MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
  MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
  MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
  MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

  MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
  MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
  MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
  MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
  MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
  MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
  MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
  MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
  MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

  MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
  MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
  MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
  MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
  MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
  MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
  MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
  MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
  MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

void cs_md5_update(cs_md5_ctx *ctx, const unsigned char *buf, size_t len) {
  uint32_t t;

  t = ctx->bits[0];
  if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t) ctx->bits[1]++;
  ctx->bits[1] += (uint32_t) len >> 29;

  t = (t >> 3) & 0x3f;

  if (t) {
    unsigned char *p = (unsigned char *) ctx->in + t;

    t = 64 - t;
    if (len < t) {
      memcpy(p, buf, len);
      return;
    }
    memcpy(p, buf, t);
    byteReverse(ctx->in, 16);
    cs_md5_transform(ctx->buf, (uint32_t *) ctx->in);
    buf += t;
    len -= t;
  }

  while (len >= 64) {
    memcpy(ctx->in, buf, 64);
    byteReverse(ctx->in, 16);
    cs_md5_transform(ctx->buf, (uint32_t *) ctx->in);
    buf += 64;
    len -= 64;
  }

  memcpy(ctx->in, buf, len);
}

void cs_md5_final(unsigned char digest[16], cs_md5_ctx *ctx) {
  unsigned count;
  unsigned char *p;
  uint32_t *a;

  count = (ctx->bits[0] >> 3) & 0x3F;

  p = ctx->in + count;
  *p++ = 0x80;
  count = 64 - 1 - count;
  if (count < 8) {
    memset(p, 0, count);
    byteReverse(ctx->in, 16);
    cs_md5_transform(ctx->buf, (uint32_t *) ctx->in);
    memset(ctx->in, 0, 56);
  } else {
    memset(p, 0, count - 8);
  }
  byteReverse(ctx->in, 14);

  a = (uint32_t *) ctx->in;
  a[14] = ctx->bits[0];
  a[15] = ctx->bits[1];

  cs_md5_transform(ctx->buf, (uint32_t *) ctx->in);
  byteReverse((unsigned char *) ctx->buf, 4);
  memcpy(digest, ctx->buf, 16);
  memset((char *) ctx, 0, sizeof(*ctx));
}




















union char64long16 {
  unsigned char c[64];
  uint32_t l[16];
};



static uint32_t blk0(union char64long16 *block, int i) {


  block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) | (rol(block->l[i], 8) & 0x00FF00FF);

  return block->l[i];
}























void cs_sha1_transform(uint32_t state[5], const unsigned char buffer[64]) {
  uint32_t a, b, c, d, e;
  union char64long16 block[1];

  memcpy(block, buffer, 64);
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  R0(a, b, c, d, e, 0);
  R0(e, a, b, c, d, 1);
  R0(d, e, a, b, c, 2);
  R0(c, d, e, a, b, 3);
  R0(b, c, d, e, a, 4);
  R0(a, b, c, d, e, 5);
  R0(e, a, b, c, d, 6);
  R0(d, e, a, b, c, 7);
  R0(c, d, e, a, b, 8);
  R0(b, c, d, e, a, 9);
  R0(a, b, c, d, e, 10);
  R0(e, a, b, c, d, 11);
  R0(d, e, a, b, c, 12);
  R0(c, d, e, a, b, 13);
  R0(b, c, d, e, a, 14);
  R0(a, b, c, d, e, 15);
  R1(e, a, b, c, d, 16);
  R1(d, e, a, b, c, 17);
  R1(c, d, e, a, b, 18);
  R1(b, c, d, e, a, 19);
  R2(a, b, c, d, e, 20);
  R2(e, a, b, c, d, 21);
  R2(d, e, a, b, c, 22);
  R2(c, d, e, a, b, 23);
  R2(b, c, d, e, a, 24);
  R2(a, b, c, d, e, 25);
  R2(e, a, b, c, d, 26);
  R2(d, e, a, b, c, 27);
  R2(c, d, e, a, b, 28);
  R2(b, c, d, e, a, 29);
  R2(a, b, c, d, e, 30);
  R2(e, a, b, c, d, 31);
  R2(d, e, a, b, c, 32);
  R2(c, d, e, a, b, 33);
  R2(b, c, d, e, a, 34);
  R2(a, b, c, d, e, 35);
  R2(e, a, b, c, d, 36);
  R2(d, e, a, b, c, 37);
  R2(c, d, e, a, b, 38);
  R2(b, c, d, e, a, 39);
  R3(a, b, c, d, e, 40);
  R3(e, a, b, c, d, 41);
  R3(d, e, a, b, c, 42);
  R3(c, d, e, a, b, 43);
  R3(b, c, d, e, a, 44);
  R3(a, b, c, d, e, 45);
  R3(e, a, b, c, d, 46);
  R3(d, e, a, b, c, 47);
  R3(c, d, e, a, b, 48);
  R3(b, c, d, e, a, 49);
  R3(a, b, c, d, e, 50);
  R3(e, a, b, c, d, 51);
  R3(d, e, a, b, c, 52);
  R3(c, d, e, a, b, 53);
  R3(b, c, d, e, a, 54);
  R3(a, b, c, d, e, 55);
  R3(e, a, b, c, d, 56);
  R3(d, e, a, b, c, 57);
  R3(c, d, e, a, b, 58);
  R3(b, c, d, e, a, 59);
  R4(a, b, c, d, e, 60);
  R4(e, a, b, c, d, 61);
  R4(d, e, a, b, c, 62);
  R4(c, d, e, a, b, 63);
  R4(b, c, d, e, a, 64);
  R4(a, b, c, d, e, 65);
  R4(e, a, b, c, d, 66);
  R4(d, e, a, b, c, 67);
  R4(c, d, e, a, b, 68);
  R4(b, c, d, e, a, 69);
  R4(a, b, c, d, e, 70);
  R4(e, a, b, c, d, 71);
  R4(d, e, a, b, c, 72);
  R4(c, d, e, a, b, 73);
  R4(b, c, d, e, a, 74);
  R4(a, b, c, d, e, 75);
  R4(e, a, b, c, d, 76);
  R4(d, e, a, b, c, 77);
  R4(c, d, e, a, b, 78);
  R4(b, c, d, e, a, 79);
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  
  memset(block, 0, sizeof(block));
  a = b = c = d = e = 0;
  (void) a;
  (void) b;
  (void) c;
  (void) d;
  (void) e;
}

void cs_sha1_init(cs_sha1_ctx *context) {
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}

void cs_sha1_update(cs_sha1_ctx *context, const unsigned char *data, uint32_t len) {
  uint32_t i, j;

  j = context->count[0];
  if ((context->count[0] += len << 3) < j) context->count[1]++;
  context->count[1] += (len >> 29);
  j = (j >> 3) & 63;
  if ((j + len) > 63) {
    memcpy(&context->buffer[j], data, (i = 64 - j));
    cs_sha1_transform(context->state, context->buffer);
    for (; i + 63 < len; i += 64) {
      cs_sha1_transform(context->state, &data[i]);
    }
    j = 0;
  } else i = 0;
  memcpy(&context->buffer[j], &data[i], len - i);
}

void cs_sha1_final(unsigned char digest[20], cs_sha1_ctx *context) {
  unsigned i;
  unsigned char finalcount[8], c;

  for (i = 0; i < 8; i++) {
    finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);

  }
  c = 0200;
  cs_sha1_update(context, &c, 1);
  while ((context->count[0] & 504) != 448) {
    c = 0000;
    cs_sha1_update(context, &c, 1);
  }
  cs_sha1_update(context, finalcount, 8);
  for (i = 0; i < 20; i++) {
    digest[i] = (unsigned char) ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
  }
  memset(context, '\0', sizeof(*context));
  memset(&finalcount, '\0', sizeof(finalcount));
}

void cs_hmac_sha1(const unsigned char *key, size_t keylen, const unsigned char *data, size_t datalen, unsigned char out[20]) {

  cs_sha1_ctx ctx;
  unsigned char buf1[64], buf2[64], tmp_key[20], i;

  if (keylen > sizeof(buf1)) {
    cs_sha1_init(&ctx);
    cs_sha1_update(&ctx, key, keylen);
    cs_sha1_final(tmp_key, &ctx);
    key = tmp_key;
    keylen = sizeof(tmp_key);
  }

  memset(buf1, 0, sizeof(buf1));
  memset(buf2, 0, sizeof(buf2));
  memcpy(buf1, key, keylen);
  memcpy(buf2, key, keylen);

  for (i = 0; i < sizeof(buf1); i++) {
    buf1[i] ^= 0x36;
    buf2[i] ^= 0x5c;
  }

  cs_sha1_init(&ctx);
  cs_sha1_update(&ctx, buf1, sizeof(buf1));
  cs_sha1_update(&ctx, data, datalen);
  cs_sha1_final(out, &ctx);

  cs_sha1_init(&ctx);
  cs_sha1_update(&ctx, buf2, sizeof(buf2));
  cs_sha1_update(&ctx, out, 20);
  cs_sha1_final(out, &ctx);
}





















void mbuf_init(struct mbuf *mbuf, size_t initial_size) WEAK;
void mbuf_init(struct mbuf *mbuf, size_t initial_size) {
  mbuf->len = mbuf->size = 0;
  mbuf->buf = NULL;
  mbuf_resize(mbuf, initial_size);
}

void mbuf_free(struct mbuf *mbuf) WEAK;
void mbuf_free(struct mbuf *mbuf) {
  if (mbuf->buf != NULL) {
    MBUF_FREE(mbuf->buf);
    mbuf_init(mbuf, 0);
  }
}

void mbuf_resize(struct mbuf *a, size_t new_size) WEAK;
void mbuf_resize(struct mbuf *a, size_t new_size) {
  if (new_size > a->size || (new_size < a->size && new_size >= a->len)) {
    char *buf = (char *) MBUF_REALLOC(a->buf, new_size);
    
    if (buf == NULL && new_size != 0) return;
    a->buf = buf;
    a->size = new_size;
  }
}

void mbuf_trim(struct mbuf *mbuf) WEAK;
void mbuf_trim(struct mbuf *mbuf) {
  mbuf_resize(mbuf, mbuf->len);
}

size_t mbuf_insert(struct mbuf *a, size_t off, const void *buf, size_t) WEAK;
size_t mbuf_insert(struct mbuf *a, size_t off, const void *buf, size_t len) {
  char *p = NULL;

  assert(a != NULL);
  assert(a->len <= a->size);
  assert(off <= a->len);

  
  if (~(size_t) 0 - (size_t) a->buf < len) return 0;

  if (a->len + len <= a->size) {
    memmove(a->buf + off + len, a->buf + off, a->len - off);
    if (buf != NULL) {
      memcpy(a->buf + off, buf, len);
    }
    a->len += len;
  } else {
    size_t min_size = (a->len + len);
    size_t new_size = (size_t)(min_size * MBUF_SIZE_MULTIPLIER);
    if (new_size - min_size > MBUF_SIZE_MAX_HEADROOM) {
      new_size = min_size + MBUF_SIZE_MAX_HEADROOM;
    }
    p = (char *) MBUF_REALLOC(a->buf, new_size);
    if (p == NULL && new_size != min_size) {
      new_size = min_size;
      p = (char *) MBUF_REALLOC(a->buf, new_size);
    }
    if (p != NULL) {
      a->buf = p;
      if (off != a->len) {
        memmove(a->buf + off + len, a->buf + off, a->len - off);
      }
      if (buf != NULL) memcpy(a->buf + off, buf, len);
      a->len += len;
      a->size = new_size;
    } else {
      len = 0;
    }
  }

  return len;
}

size_t mbuf_append(struct mbuf *a, const void *buf, size_t len) WEAK;
size_t mbuf_append(struct mbuf *a, const void *buf, size_t len) {
  return mbuf_insert(a, a->len, buf, len);
}

void mbuf_remove(struct mbuf *mb, size_t n) WEAK;
void mbuf_remove(struct mbuf *mb, size_t n) {
  if (n > 0 && n <= mb->len) {
    memmove(mb->buf, mb->buf + n, mb->len - n);
    mb->len -= n;
  }
}














int mg_ncasecmp(const char *s1, const char *s2, size_t len) WEAK;

struct mg_str mg_mk_str(const char *s) WEAK;
struct mg_str mg_mk_str(const char *s) {
  struct mg_str ret = {s, 0};
  if (s != NULL) ret.len = strlen(s);
  return ret;
}

struct mg_str mg_mk_str_n(const char *s, size_t len) WEAK;
struct mg_str mg_mk_str_n(const char *s, size_t len) {
  struct mg_str ret = {s, len};
  return ret;
}

int mg_vcmp(const struct mg_str *str1, const char *str2) WEAK;
int mg_vcmp(const struct mg_str *str1, const char *str2) {
  size_t n2 = strlen(str2), n1 = str1->len;
  int r = strncmp(str1->p, str2, (n1 < n2) ? n1 : n2);
  if (r == 0) {
    return n1 - n2;
  }
  return r;
}

int mg_vcasecmp(const struct mg_str *str1, const char *str2) WEAK;
int mg_vcasecmp(const struct mg_str *str1, const char *str2) {
  size_t n2 = strlen(str2), n1 = str1->len;
  int r = mg_ncasecmp(str1->p, str2, (n1 < n2) ? n1 : n2);
  if (r == 0) {
    return n1 - n2;
  }
  return r;
}

static struct mg_str mg_strdup_common(const struct mg_str s, int nul_terminate) {
  struct mg_str r = {NULL, 0};
  if (s.len > 0 && s.p != NULL) {
    char *sc = (char *) MG_MALLOC(s.len + (nul_terminate ? 1 : 0));
    if (sc != NULL) {
      memcpy(sc, s.p, s.len);
      if (nul_terminate) sc[s.len] = '\0';
      r.p = sc;
      r.len = s.len;
    }
  }
  return r;
}

struct mg_str mg_strdup(const struct mg_str s) WEAK;
struct mg_str mg_strdup(const struct mg_str s) {
  return mg_strdup_common(s, 0 );
}

struct mg_str mg_strdup_nul(const struct mg_str s) WEAK;
struct mg_str mg_strdup_nul(const struct mg_str s) {
  return mg_strdup_common(s, 1 );
}

const char *mg_strchr(const struct mg_str s, int c) WEAK;
const char *mg_strchr(const struct mg_str s, int c) {
  size_t i;
  for (i = 0; i < s.len; i++) {
    if (s.p[i] == c) return &s.p[i];
  }
  return NULL;
}

int mg_strcmp(const struct mg_str str1, const struct mg_str str2) WEAK;
int mg_strcmp(const struct mg_str str1, const struct mg_str str2) {
  size_t i = 0;
  while (i < str1.len && i < str2.len) {
    if (str1.p[i] < str2.p[i]) return -1;
    if (str1.p[i] > str2.p[i]) return 1;
    i++;
  }
  if (i < str1.len) return 1;
  if (i < str2.len) return -1;
  return 0;
}

int mg_strncmp(const struct mg_str, const struct mg_str, size_t n) WEAK;
int mg_strncmp(const struct mg_str str1, const struct mg_str str2, size_t n) {
  struct mg_str s1 = str1;
  struct mg_str s2 = str2;

  if (s1.len > n) {
    s1.len = n;
  }
  if (s2.len > n) {
    s2.len = n;
  }
  return mg_strcmp(s1, s2);
}

const char *mg_strstr(const struct mg_str haystack, const struct mg_str needle) WEAK;
const char *mg_strstr(const struct mg_str haystack, const struct mg_str needle) {
  size_t i;
  if (needle.len > haystack.len) return NULL;
  for (i = 0; i <= haystack.len - needle.len; i++) {
    if (memcmp(haystack.p + i, needle.p, needle.len) == 0) {
      return haystack.p + i;
    }
  }
  return NULL;
}

struct mg_str mg_strstrip(struct mg_str s) WEAK;
struct mg_str mg_strstrip(struct mg_str s) {
  while (s.len > 0 && isspace((int) *s.p)) {
    s.p++;
    s.len--;
  }
  while (s.len > 0 && isspace((int) *(s.p + s.len - 1))) {
    s.len--;
  }
  return s;
}

















size_t c_strnlen(const char *s, size_t maxlen) WEAK;
size_t c_strnlen(const char *s, size_t maxlen) {
  size_t l = 0;
  for (; l < maxlen && s[l] != '\0'; l++) {
  }
  return l;
}









int c_vsnprintf(char *buf, size_t buf_size, const char *fmt, va_list ap) WEAK;
int c_vsnprintf(char *buf, size_t buf_size, const char *fmt, va_list ap) {
  return vsnprintf(buf, buf_size, fmt, ap);
}

static int c_itoa(char *buf, size_t buf_size, int64_t num, int base, int flags, int field_width) {
  char tmp[40];
  int i = 0, k = 0, neg = 0;

  if (num < 0) {
    neg++;
    num = -num;
  }

  
  do {
    int rem = num % base;
    if (rem < 10) {
      tmp[k++] = '0' + rem;
    } else {
      tmp[k++] = 'a' + (rem - 10);
    }
    num /= base;
  } while (num > 0);

  
  if (flags && C_SNPRINTF_FLAG_ZERO) {
    while (k < field_width && k < (int) sizeof(tmp) - 1) {
      tmp[k++] = '0';
    }
  }

  
  if (neg) {
    tmp[k++] = '-';
  }

  
  while (--k >= 0) {
    C_SNPRINTF_APPEND_CHAR(tmp[k]);
  }

  return i;
}

int c_vsnprintf(char *buf, size_t buf_size, const char *fmt, va_list ap) WEAK;
int c_vsnprintf(char *buf, size_t buf_size, const char *fmt, va_list ap) {
  int ch, i = 0, len_mod, flags, precision, field_width;

  while ((ch = *fmt++) != '\0') {
    if (ch != '%') {
      C_SNPRINTF_APPEND_CHAR(ch);
    } else {
      
      flags = field_width = precision = len_mod = 0;

      
      if (*fmt == '0') {
        flags |= C_SNPRINTF_FLAG_ZERO;
      }

      
      while (*fmt >= '0' && *fmt <= '9') {
        field_width *= 10;
        field_width += *fmt++ - '0';
      }
      
      if (*fmt == '*') {
        field_width = va_arg(ap, int);
        fmt++;
      }

      
      if (*fmt == '.') {
        fmt++;
        if (*fmt == '*') {
          precision = va_arg(ap, int);
          fmt++;
        } else {
          while (*fmt >= '0' && *fmt <= '9') {
            precision *= 10;
            precision += *fmt++ - '0';
          }
        }
      }

      
      switch (*fmt) {
        case 'h':
        case 'l':
        case 'L':
        case 'I':
        case 'q':
        case 'j':
        case 'z':
        case 't':
          len_mod = *fmt++;
          if (*fmt == 'h') {
            len_mod = 'H';
            fmt++;
          }
          if (*fmt == 'l') {
            len_mod = 'q';
            fmt++;
          }
          break;
      }

      ch = *fmt++;
      if (ch == 's') {
        const char *s = va_arg(ap, const char *); 
        int j;
        int pad = field_width - (precision >= 0 ? c_strnlen(s, precision) : 0);
        for (j = 0; j < pad; j++) {
          C_SNPRINTF_APPEND_CHAR(' ');
        }

        
        if (s != NULL) {
          
          for (j = 0; (precision <= 0 || j < precision) && s[j] != '\0'; j++) {
            C_SNPRINTF_APPEND_CHAR(s[j]);
          }
        }
      } else if (ch == 'c') {
        ch = va_arg(ap, int); 
        C_SNPRINTF_APPEND_CHAR(ch);
      } else if (ch == 'd' && len_mod == 0) {
        i += c_itoa(buf + i, buf_size - i, va_arg(ap, int), 10, flags, field_width);
      } else if (ch == 'd' && len_mod == 'l') {
        i += c_itoa(buf + i, buf_size - i, va_arg(ap, long), 10, flags, field_width);

      } else if (ch == 'd' && len_mod == 'z') {
        i += c_itoa(buf + i, buf_size - i, va_arg(ap, ssize_t), 10, flags, field_width);

      } else if (ch == 'd' && len_mod == 'q') {
        i += c_itoa(buf + i, buf_size - i, va_arg(ap, int64_t), 10, flags, field_width);
      } else if ((ch == 'x' || ch == 'u') && len_mod == 0) {
        i += c_itoa(buf + i, buf_size - i, va_arg(ap, unsigned), ch == 'x' ? 16 : 10, flags, field_width);
      } else if ((ch == 'x' || ch == 'u') && len_mod == 'l') {
        i += c_itoa(buf + i, buf_size - i, va_arg(ap, unsigned long), ch == 'x' ? 16 : 10, flags, field_width);
      } else if ((ch == 'x' || ch == 'u') && len_mod == 'z') {
        i += c_itoa(buf + i, buf_size - i, va_arg(ap, size_t), ch == 'x' ? 16 : 10, flags, field_width);
      } else if (ch == 'p') {
        unsigned long num = (unsigned long) (uintptr_t) va_arg(ap, void *);
        C_SNPRINTF_APPEND_CHAR('0');
        C_SNPRINTF_APPEND_CHAR('x');
        i += c_itoa(buf + i, buf_size - i, num, 16, flags, 0);
      } else {

        
        abort();

      }
    }
  }

  
  if (buf_size > 0) {
    buf[i < (int) buf_size ? i : (int) buf_size - 1] = '\0';
  }

  return i;
}


int c_snprintf(char *buf, size_t buf_size, const char *fmt, ...) WEAK;
int c_snprintf(char *buf, size_t buf_size, const char *fmt, ...) {
  int result;
  va_list ap;
  va_start(ap, fmt);
  result = c_vsnprintf(buf, buf_size, fmt, ap);
  va_end(ap);
  return result;
}


int to_wchar(const char *path, wchar_t *wbuf, size_t wbuf_len) {
  int ret;
  char buf[MAX_PATH * 2], buf2[MAX_PATH * 2], *p;

  strncpy(buf, path, sizeof(buf));
  buf[sizeof(buf) - 1] = '\0';

  
  p = buf + strlen(buf) - 1;
  while (p > buf && p[-1] != ':' && (p[0] == '\\' || p[0] == '/')) *p-- = '\0';

  memset(wbuf, 0, wbuf_len * sizeof(wchar_t));
  ret = MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int) wbuf_len);

  
  WideCharToMultiByte(CP_UTF8, 0, wbuf, (int) wbuf_len, buf2, sizeof(buf2), NULL, NULL);
  if (strcmp(buf, buf2) != 0) {
    wbuf[0] = L'\0';
    ret = 0;
  }

  return ret;
}



const char *c_strnstr(const char *s, const char *find, size_t slen) WEAK;
const char *c_strnstr(const char *s, const char *find, size_t slen) {
  size_t find_length = strlen(find);
  size_t i;

  for (i = 0; i < slen; i++) {
    if (i + find_length > slen) {
      return NULL;
    }

    if (strncmp(&s[i], find, find_length) == 0) {
      return &s[i];
    }
  }

  return NULL;
}


char *strdup(const char *src) WEAK;
char *strdup(const char *src) {
  size_t len = strlen(src) + 1;
  char *ret = MG_MALLOC(len);
  if (ret != NULL) {
    strcpy(ret, src);
  }
  return ret;
}


void cs_to_hex(char *to, const unsigned char *p, size_t len) WEAK;
void cs_to_hex(char *to, const unsigned char *p, size_t len) {
  static const char *hex = "0123456789abcdef";

  for (; len--; p++) {
    *to++ = hex[p[0] >> 4];
    *to++ = hex[p[0] & 0x0f];
  }
  *to = '\0';
}

static int fourbit(int ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  } else if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  } else if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  }
  return 0;
}

void cs_from_hex(char *to, const char *p, size_t len) WEAK;
void cs_from_hex(char *to, const char *p, size_t len) {
  size_t i;

  for (i = 0; i < len; i += 2) {
    *to++ = (fourbit(p[i]) << 4) + fourbit(p[i + 1]);
  }
  *to = '\0';
}


int64_t cs_to64(const char *s) WEAK;
int64_t cs_to64(const char *s) {
  int64_t result = 0;
  int64_t neg = 1;
  while (*s && isspace((unsigned char) *s)) s++;
  if (*s == '-') {
    neg = -1;
    s++;
  }
  while (isdigit((unsigned char) *s)) {
    result *= 10;
    result += (*s - '0');
    s++;
  }
  return result * neg;
}


static int str_util_lowercase(const char *s) {
  return tolower(*(const unsigned char *) s);
}

int mg_ncasecmp(const char *s1, const char *s2, size_t len) WEAK;
int mg_ncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0) do {
      diff = str_util_lowercase(s1++) - str_util_lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

int mg_casecmp(const char *s1, const char *s2) WEAK;
int mg_casecmp(const char *s1, const char *s2) {
  return mg_ncasecmp(s1, s2, (size_t) ~0);
}

int mg_asprintf(char **buf, size_t size, const char *fmt, ...) WEAK;
int mg_asprintf(char **buf, size_t size, const char *fmt, ...) {
  int ret;
  va_list ap;
  va_start(ap, fmt);
  ret = mg_avprintf(buf, size, fmt, ap);
  va_end(ap);
  return ret;
}

int mg_avprintf(char **buf, size_t size, const char *fmt, va_list ap) WEAK;
int mg_avprintf(char **buf, size_t size, const char *fmt, va_list ap) {
  va_list ap_copy;
  int len;

  va_copy(ap_copy, ap);
  len = vsnprintf(*buf, size, fmt, ap_copy);
  va_end(ap_copy);

  if (len < 0) {
    
    *buf = NULL; 
    while (len < 0) {
      MG_FREE(*buf);
      if (size == 0) {
        size = 5;
      }
      size *= 2;
      if ((*buf = (char *) MG_MALLOC(size)) == NULL) {
        len = -1;
        break;
      }
      va_copy(ap_copy, ap);
      len = vsnprintf(*buf, size - 1, fmt, ap_copy);
      va_end(ap_copy);
    }

    
    (*buf)[len] = 0;
    
  } else if (len >= (int) size) {
    
    if ((*buf = (char *) MG_MALLOC(len + 1)) == NULL) {
      len = -1; 
    } else {    
      va_copy(ap_copy, ap);
      len = vsnprintf(*buf, len + 1, fmt, ap_copy);
      va_end(ap_copy);
    }
  }

  return len;
}

const char *mg_next_comma_list_entry(const char *, struct mg_str *, struct mg_str *) WEAK;
const char *mg_next_comma_list_entry(const char *list, struct mg_str *val, struct mg_str *eq_val) {
  struct mg_str ret = mg_next_comma_list_entry_n(mg_mk_str(list), val, eq_val);
  return ret.p;
}

struct mg_str mg_next_comma_list_entry_n(struct mg_str list, struct mg_str *val, struct mg_str *eq_val) WEAK;
struct mg_str mg_next_comma_list_entry_n(struct mg_str list, struct mg_str *val, struct mg_str *eq_val) {
  if (list.len == 0) {
    
    list = mg_mk_str(NULL);
  } else {
    const char *chr = NULL;
    *val = list;

    if ((chr = mg_strchr(*val, ',')) != NULL) {
      
      val->len = chr - val->p;
      chr++;
      list.len -= (chr - list.p);
      list.p = chr;
    } else {
      
      list = mg_mk_str_n(list.p + list.len, 0);
    }

    if (eq_val != NULL) {
      
      
      eq_val->len = 0;
      eq_val->p = (const char *) memchr(val->p, '=', val->len);
      if (eq_val->p != NULL) {
        eq_val->p++; 
        eq_val->len = val->p + val->len - eq_val->p;
        val->len = (eq_val->p - val->p) - 1;
      }
    }
  }

  return list;
}

size_t mg_match_prefix_n(const struct mg_str, const struct mg_str) WEAK;
size_t mg_match_prefix_n(const struct mg_str pattern, const struct mg_str str) {
  const char *or_str;
  size_t res = 0, len = 0, i = 0, j = 0;

  if ((or_str = (const char *) memchr(pattern.p, '|', pattern.len)) != NULL || (or_str = (const char *) memchr(pattern.p, ',', pattern.len)) != NULL) {
    struct mg_str pstr = {pattern.p, (size_t)(or_str - pattern.p)};
    res = mg_match_prefix_n(pstr, str);
    if (res > 0) return res;
    pstr.p = or_str + 1;
    pstr.len = (pattern.p + pattern.len) - (or_str + 1);
    return mg_match_prefix_n(pstr, str);
  }

  for (; i < pattern.len && j < str.len; i++, j++) {
    if (pattern.p[i] == '?') {
      continue;
    } else if (pattern.p[i] == '*') {
      i++;
      if (i < pattern.len && pattern.p[i] == '*') {
        i++;
        len = str.len - j;
      } else {
        len = 0;
        while (j + len < str.len && str.p[j + len] != '/') len++;
      }
      if (i == pattern.len || (pattern.p[i] == '$' && i == pattern.len - 1))
        return j + len;
      do {
        const struct mg_str pstr = {pattern.p + i, pattern.len - i};
        const struct mg_str sstr = {str.p + j + len, str.len - j - len};
        res = mg_match_prefix_n(pstr, sstr);
      } while (res == 0 && len != 0 && len-- > 0);
      return res == 0 ? 0 : j + res + len;
    } else if (str_util_lowercase(&pattern.p[i]) != str_util_lowercase(&str.p[j])) {
      break;
    }
  }
  if (i < pattern.len && pattern.p[i] == '$') {
    return j == str.len ? str.len : 0;
  }
  return i == pattern.len ? j : 0;
}

size_t mg_match_prefix(const char *, int, const char *) WEAK;
size_t mg_match_prefix(const char *pattern, int pattern_len, const char *str) {
  const struct mg_str pstr = {pattern, (size_t) pattern_len};
  struct mg_str s = {str, 0};
  if (str != NULL) s.len = strlen(str);
  return mg_match_prefix_n(pstr, s);
}




































MG_INTERNAL void mg_add_conn(struct mg_mgr *mgr, struct mg_connection *c) {
  DBG(("%p %p", mgr, c));
  c->mgr = mgr;
  c->next = mgr->active_connections;
  mgr->active_connections = c;
  c->prev = NULL;
  if (c->next != NULL) c->next->prev = c;
  if (c->sock != INVALID_SOCKET) {
    c->iface->vtable->add_conn(c);
  }
}

MG_INTERNAL void mg_remove_conn(struct mg_connection *conn) {
  if (conn->prev == NULL) conn->mgr->active_connections = conn->next;
  if (conn->prev) conn->prev->next = conn->next;
  if (conn->next) conn->next->prev = conn->prev;
  conn->prev = conn->next = NULL;
  conn->iface->vtable->remove_conn(conn);
}

MG_INTERNAL void mg_call(struct mg_connection *nc, mg_event_handler_t ev_handler, void *user_data, int ev, void *ev_data) {

  if (ev_handler == NULL) {
    
    ev_handler = nc->proto_handler ? nc->proto_handler : nc->handler;
  }
  if (ev != MG_EV_POLL) {
    DBG(("%p %s ev=%d ev_data=%p flags=0x%lx rmbl=%d smbl=%d", nc, ev_handler == nc->handler ? "user" : "proto", ev, ev_data, nc->flags, (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));

  }


  if (nc->mgr->hexdump_file != NULL && ev != MG_EV_POLL && ev != MG_EV_RECV && ev != MG_EV_SEND ) {
    mg_hexdump_connection(nc, nc->mgr->hexdump_file, NULL, 0, ev);
  }

  if (ev_handler != NULL) {
    unsigned long flags_before = nc->flags;
    ev_handler(nc, ev, ev_data MG_UD_ARG(user_data));
    
    if (ev_handler == nc->handler && nc->flags != flags_before) {
      nc->flags = (flags_before & ~_MG_CALLBACK_MODIFIABLE_FLAGS_MASK) | (nc->flags & _MG_CALLBACK_MODIFIABLE_FLAGS_MASK);
    }
  }
  if (ev != MG_EV_POLL) {
    DBG(("%p after %s flags=0x%lx rmbl=%d smbl=%d", nc, ev_handler == nc->handler ? "user" : "proto", nc->flags, (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));

  }

  (void) user_data;

}

MG_INTERNAL void mg_timer(struct mg_connection *c, double now) {
  if (c->ev_timer_time > 0 && now >= c->ev_timer_time) {
    double old_value = c->ev_timer_time;
    c->ev_timer_time = 0;
    mg_call(c, NULL, c->user_data, MG_EV_TIMER, &old_value);
  }
}

MG_INTERNAL size_t recv_avail_size(struct mg_connection *conn, size_t max) {
  size_t avail;
  if (conn->recv_mbuf_limit < conn->recv_mbuf.len) return 0;
  avail = conn->recv_mbuf_limit - conn->recv_mbuf.len;
  return avail > max ? max : avail;
}

static int mg_do_recv(struct mg_connection *nc);

int mg_if_poll(struct mg_connection *nc, double now) {
  if ((nc->flags & MG_F_CLOSE_IMMEDIATELY) || (nc->send_mbuf.len == 0 && (nc->flags & MG_F_SEND_AND_CLOSE))) {
    mg_close_conn(nc);
    return 0;
  }

  if ((nc->flags & (MG_F_SSL | MG_F_LISTENING | MG_F_CONNECTING)) == MG_F_SSL) {
    
    int recved = 0;
    do {
      if (nc->flags & (MG_F_WANT_READ | MG_F_WANT_WRITE)) break;
      if (recv_avail_size(nc, MG_TCP_IO_SIZE) <= 0) break;
      recved = mg_do_recv(nc);
    } while (recved > 0);
  }

  mg_timer(nc, now);
  {
    time_t now_t = (time_t) now;
    mg_call(nc, NULL, nc->user_data, MG_EV_POLL, &now_t);
  }
  return 1;
}

void mg_destroy_conn(struct mg_connection *conn, int destroy_if) {
  if (conn->sock != INVALID_SOCKET) { 
    LOG(LL_DEBUG, ("%p 0x%lx %d", conn, conn->flags, destroy_if));
  }
  if (destroy_if) conn->iface->vtable->destroy_conn(conn);
  if (conn->proto_data != NULL && conn->proto_data_destructor != NULL) {
    conn->proto_data_destructor(conn->proto_data);
  }

  mg_ssl_if_conn_free(conn);

  mbuf_free(&conn->recv_mbuf);
  mbuf_free(&conn->send_mbuf);

  memset(conn, 0, sizeof(*conn));
  MG_FREE(conn);
}

void mg_close_conn(struct mg_connection *conn) {

  if (conn->flags & MG_F_SSL_HANDSHAKE_DONE) {
    mg_ssl_if_conn_close_notify(conn);
  }

  
  conn->flags |= MG_F_CLOSE_IMMEDIATELY;
  mg_remove_conn(conn);
  conn->iface->vtable->destroy_conn(conn);
  mg_call(conn, NULL, conn->user_data, MG_EV_CLOSE, NULL);
  mg_destroy_conn(conn, 0 );
}

void mg_mgr_init(struct mg_mgr *m, void *user_data) {
  struct mg_mgr_init_opts opts;
  memset(&opts, 0, sizeof(opts));
  mg_mgr_init_opt(m, user_data, opts);
}

void mg_mgr_init_opt(struct mg_mgr *m, void *user_data, struct mg_mgr_init_opts opts) {
  memset(m, 0, sizeof(*m));

  m->ctl[0] = m->ctl[1] = INVALID_SOCKET;

  m->user_data = user_data;


  {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  }

  
  signal(SIGPIPE, SIG_IGN);


  {
    int i;
    if (opts.num_ifaces == 0) {
      opts.num_ifaces = mg_num_ifaces;
      opts.ifaces = mg_ifaces;
    }
    if (opts.main_iface != NULL) {
      opts.ifaces[MG_MAIN_IFACE] = opts.main_iface;
    }
    m->num_ifaces = opts.num_ifaces;
    m->ifaces = (struct mg_iface **) MG_MALLOC(sizeof(*m->ifaces) * opts.num_ifaces);
    for (i = 0; i < opts.num_ifaces; i++) {
      m->ifaces[i] = mg_if_create_iface(opts.ifaces[i], m);
      m->ifaces[i]->vtable->init(m->ifaces[i]);
    }
  }
  if (opts.nameserver != NULL) {
    m->nameserver = strdup(opts.nameserver);
  }
  DBG(("=================================="));
  DBG(("init mgr=%p", m));

  {
    static int init_done;
    if (!init_done) {
      mg_ssl_if_init();
      init_done++;
    }
  }

}

void mg_mgr_free(struct mg_mgr *m) {
  struct mg_connection *conn, *tmp_conn;

  DBG(("%p", m));
  if (m == NULL) return;
  
  mg_mgr_poll(m, 0);


  if (m->ctl[0] != INVALID_SOCKET) closesocket(m->ctl[0]);
  if (m->ctl[1] != INVALID_SOCKET) closesocket(m->ctl[1]);
  m->ctl[0] = m->ctl[1] = INVALID_SOCKET;


  for (conn = m->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    mg_close_conn(conn);
  }

  {
    int i;
    for (i = 0; i < m->num_ifaces; i++) {
      m->ifaces[i]->vtable->free(m->ifaces[i]);
      MG_FREE(m->ifaces[i]);
    }
    MG_FREE(m->ifaces);
  }

  MG_FREE((char *) m->nameserver);
}

time_t mg_mgr_poll(struct mg_mgr *m, int timeout_ms) {
  int i;
  time_t now = 0; 

  if (m->num_ifaces == 0) {
    LOG(LL_ERROR, ("cannot poll: no interfaces"));
    return 0;
  }

  for (i = 0; i < m->num_ifaces; i++) {
    now = m->ifaces[i]->vtable->poll(m->ifaces[i], timeout_ms);
  }
  return now;
}

int mg_vprintf(struct mg_connection *nc, const char *fmt, va_list ap) {
  char mem[MG_VPRINTF_BUFFER_SIZE], *buf = mem;
  int len;

  if ((len = mg_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    mg_send(nc, buf, len);
  }
  if (buf != mem && buf != NULL) {
    MG_FREE(buf); 
  }               

  return len;
}

int mg_printf(struct mg_connection *conn, const char *fmt, ...) {
  int len;
  va_list ap;
  va_start(ap, fmt);
  len = mg_vprintf(conn, fmt, ap);
  va_end(ap);
  return len;
}



static int mg_resolve2(const char *host, struct in_addr *ina) {

  int rv = 0;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_in *h = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if ((rv = getaddrinfo(host, NULL, NULL, &servinfo)) != 0) {
    DBG(("getaddrinfo(%s) failed: %s", host, strerror(mg_get_errno())));
    return 0;
  }
  for (p = servinfo; p != NULL; p = p->ai_next) {
    memcpy(&h, &p->ai_addr, sizeof(struct sockaddr_in *));
    memcpy(ina, &h->sin_addr, sizeof(ina));
  }
  freeaddrinfo(servinfo);
  return 1;

  struct hostent *he;
  if ((he = gethostbyname(host)) == NULL) {
    DBG(("gethostbyname(%s) failed: %s", host, strerror(mg_get_errno())));
  } else {
    memcpy(ina, he->h_addr_list[0], sizeof(*ina));
    return 1;
  }
  return 0;

}

int mg_resolve(const char *host, char *buf, size_t n) {
  struct in_addr ad;
  return mg_resolve2(host, &ad) ? snprintf(buf, n, "%s", inet_ntoa(ad)) : 0;
}


MG_INTERNAL struct mg_connection *mg_create_connection_base( struct mg_mgr *mgr, mg_event_handler_t callback, struct mg_add_sock_opts opts) {

  struct mg_connection *conn;

  if ((conn = (struct mg_connection *) MG_CALLOC(1, sizeof(*conn))) != NULL) {
    conn->sock = INVALID_SOCKET;
    conn->handler = callback;
    conn->mgr = mgr;
    conn->last_io_time = (time_t) mg_time();
    conn->iface = (opts.iface != NULL ? opts.iface : mgr->ifaces[MG_MAIN_IFACE]);
    conn->flags = opts.flags & _MG_ALLOWED_CONNECT_FLAGS_MASK;
    conn->user_data = opts.user_data;
    
    conn->recv_mbuf_limit = ~0;
  } else {
    MG_SET_PTRPTR(opts.error_string, "failed to create connection");
  }

  return conn;
}

MG_INTERNAL struct mg_connection *mg_create_connection( struct mg_mgr *mgr, mg_event_handler_t callback, struct mg_add_sock_opts opts) {

  struct mg_connection *conn = mg_create_connection_base(mgr, callback, opts);

  if (conn != NULL && !conn->iface->vtable->create_conn(conn)) {
    MG_FREE(conn);
    conn = NULL;
  }
  if (conn == NULL) {
    MG_SET_PTRPTR(opts.error_string, "failed to init connection");
  }

  return conn;
}


MG_INTERNAL int mg_parse_address(const char *str, union socket_address *sa, int *proto, char *host, size_t host_len) {
  unsigned int a, b, c, d, port = 0;
  int ch, len = 0;

  char buf[100];


  
  memset(sa, 0, sizeof(*sa));
  sa->sin.sin_family = AF_INET;

  *proto = SOCK_STREAM;

  if (strncmp(str, "udp://", 6) == 0) {
    str += 6;
    *proto = SOCK_DGRAM;
  } else if (strncmp(str, "tcp://", 6) == 0) {
    str += 6;
  }

  if (sscanf(str, "%u.%u.%u.%u:%u%n", &a, &b, &c, &d, &port, &len) == 5) {
    
    sa->sin.sin_addr.s_addr = htonl(((uint32_t) a << 24) | ((uint32_t) b << 16) | c << 8 | d);
    sa->sin.sin_port = htons((uint16_t) port);

  } else if (sscanf(str, "[%99[^]]]:%u%n", buf, &port, &len) == 2 && inet_pton(AF_INET6, buf, &sa->sin6.sin6_addr)) {
    
    sa->sin6.sin6_family = AF_INET6;
    sa->sin.sin_port = htons((uint16_t) port);


  } else if (strlen(str) < host_len && sscanf(str, "%[^ :]:%u%n", host, &port, &len) == 2) {
    sa->sin.sin_port = htons((uint16_t) port);
    if (mg_resolve_from_hosts_file(host, sa) != 0) {
      
      if (mg_ncasecmp(host, "localhost", 9) != 0) {
        return 0;
      }


      if (!mg_resolve2(host, &sa->sin.sin_addr)) {
        return -1;
      }

      return -1;

    }

  } else if (sscanf(str, ":%u%n", &port, &len) == 1 || sscanf(str, "%u%n", &port, &len) == 1) {
    
    sa->sin.sin_port = htons((uint16_t) port);
  } else {
    return -1;
  }

  
  (void) host;
  (void) host_len;

  ch = str[len]; 
  return port < 0xffffUL && (ch == '\0' || ch == ',' || isspace(ch)) ? len : -1;
}


MG_INTERNAL void mg_ssl_handshake(struct mg_connection *nc) {
  int err = 0;
  int server_side = (nc->listener != NULL);
  enum mg_ssl_if_result res;
  if (nc->flags & MG_F_SSL_HANDSHAKE_DONE) return;
  res = mg_ssl_if_handshake(nc);
  LOG(LL_DEBUG, ("%p %d res %d", nc, server_side, res));

  if (res == MG_SSL_OK) {
    nc->flags |= MG_F_SSL_HANDSHAKE_DONE;
    nc->flags &= ~(MG_F_WANT_READ | MG_F_WANT_WRITE);
    if (server_side) {
      mg_call(nc, NULL, nc->user_data, MG_EV_ACCEPT, &nc->sa);
    } else {
      mg_call(nc, NULL, nc->user_data, MG_EV_CONNECT, &err);
    }
  } else if (res == MG_SSL_WANT_READ) {
    nc->flags |= MG_F_WANT_READ;
  } else if (res == MG_SSL_WANT_WRITE) {
    nc->flags |= MG_F_WANT_WRITE;
  } else {
    if (!server_side) {
      err = res;
      mg_call(nc, NULL, nc->user_data, MG_EV_CONNECT, &err);
    }
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  }
}


struct mg_connection *mg_if_accept_new_conn(struct mg_connection *lc) {
  struct mg_add_sock_opts opts;
  struct mg_connection *nc;
  memset(&opts, 0, sizeof(opts));
  nc = mg_create_connection(lc->mgr, lc->handler, opts);
  if (nc == NULL) return NULL;
  nc->listener = lc;
  nc->proto_handler = lc->proto_handler;
  nc->user_data = lc->user_data;
  nc->recv_mbuf_limit = lc->recv_mbuf_limit;
  nc->iface = lc->iface;
  if (lc->flags & MG_F_SSL) nc->flags |= MG_F_SSL;
  mg_add_conn(nc->mgr, nc);
  LOG(LL_DEBUG, ("%p %p %d %d", lc, nc, nc->sock, (int) nc->flags));
  return nc;
}

void mg_if_accept_tcp_cb(struct mg_connection *nc, union socket_address *sa, size_t sa_len) {
  LOG(LL_DEBUG, ("%p %s://%s:%hu", nc, (nc->flags & MG_F_UDP ? "udp" : "tcp"), inet_ntoa(sa->sin.sin_addr), ntohs(sa->sin.sin_port)));
  nc->sa = *sa;

  if (nc->listener->flags & MG_F_SSL) {
    nc->flags |= MG_F_SSL;
    if (mg_ssl_if_conn_accept(nc, nc->listener) == MG_SSL_OK) {
      mg_ssl_handshake(nc);
    } else {
      mg_close_conn(nc);
    }
  } else  {

    mg_call(nc, NULL, nc->user_data, MG_EV_ACCEPT, &nc->sa);
  }
  (void) sa_len;
}

void mg_send(struct mg_connection *nc, const void *buf, int len) {
  nc->last_io_time = (time_t) mg_time();
  mbuf_append(&nc->send_mbuf, buf, len);
}

static int mg_recv_tcp(struct mg_connection *nc, char *buf, size_t len);
static int mg_recv_udp(struct mg_connection *nc, char *buf, size_t len);

static int mg_do_recv(struct mg_connection *nc) {
  int res = 0;
  char *buf = NULL;
  size_t len = (nc->flags & MG_F_UDP ? MG_UDP_IO_SIZE : MG_TCP_IO_SIZE);
  if ((nc->flags & (MG_F_CLOSE_IMMEDIATELY | MG_F_CONNECTING)) || ((nc->flags & MG_F_LISTENING) && !(nc->flags & MG_F_UDP))) {
    return -1;
  }
  len = recv_avail_size(nc, len);
  if (len == 0) return -2;
  if (nc->recv_mbuf.size < nc->recv_mbuf.len + len) {
    mbuf_resize(&nc->recv_mbuf, nc->recv_mbuf.len + len);
  }
  buf = nc->recv_mbuf.buf + nc->recv_mbuf.len;
  len = nc->recv_mbuf.size - nc->recv_mbuf.len;
  if (nc->flags & MG_F_UDP) {
    res = mg_recv_udp(nc, buf, len);
  } else {
    res = mg_recv_tcp(nc, buf, len);
  }
  return res;
}

void mg_if_can_recv_cb(struct mg_connection *nc) {
  mg_do_recv(nc);
}

static int mg_recv_tcp(struct mg_connection *nc, char *buf, size_t len) {
  int n = 0;

  if (nc->flags & MG_F_SSL) {
    if (nc->flags & MG_F_SSL_HANDSHAKE_DONE) {
      n = mg_ssl_if_read(nc, buf, len);
      DBG(("%p <- %d bytes (SSL)", nc, n));
      if (n < 0) {
        if (n == MG_SSL_WANT_READ) {
          nc->flags |= MG_F_WANT_READ;
          n = 0;
        } else {
          nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        }
      } else if (n > 0) {
        nc->flags &= ~MG_F_WANT_READ;
      }
    } else {
      mg_ssl_handshake(nc);
    }
  } else  {

    n = nc->iface->vtable->tcp_recv(nc, buf, len);
    DBG(("%p <- %d bytes", nc, n));
  }
  if (n > 0) {
    nc->recv_mbuf.len += n;
    nc->last_io_time = (time_t) mg_time();

    if (nc->mgr && nc->mgr->hexdump_file != NULL) {
      mg_hexdump_connection(nc, nc->mgr->hexdump_file, buf, n, MG_EV_RECV);
    }

    mg_call(nc, NULL, nc->user_data, MG_EV_RECV, &n);
  } else if (n < 0) {
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  }
  return n;
}

static int mg_recv_udp(struct mg_connection *nc, char *buf, size_t len) {
  int n = 0;
  struct mg_connection *lc = nc;
  union socket_address sa;
  size_t sa_len = sizeof(sa);
  n = nc->iface->vtable->udp_recv(lc, buf, len, &sa, &sa_len);
  if (n < 0) {
    lc->flags |= MG_F_CLOSE_IMMEDIATELY;
    goto out;
  }
  if (nc->flags & MG_F_LISTENING) {
    
    lc = nc;
    for (nc = mg_next(lc->mgr, NULL); nc != NULL; nc = mg_next(lc->mgr, nc)) {
      if (memcmp(&nc->sa.sa, &sa.sa, sa_len) == 0 && nc->listener == lc) {
        break;
      }
    }
    if (nc == NULL) {
      struct mg_add_sock_opts opts;
      memset(&opts, 0, sizeof(opts));
      
      nc = mg_create_connection_base(lc->mgr, lc->handler, opts);
      if (nc != NULL) {
        nc->sock = lc->sock;
        nc->listener = lc;
        nc->sa = sa;
        nc->proto_handler = lc->proto_handler;
        nc->user_data = lc->user_data;
        nc->recv_mbuf_limit = lc->recv_mbuf_limit;
        nc->flags = MG_F_UDP;
        
        nc->flags |= MG_F_SEND_AND_CLOSE;
        mg_add_conn(lc->mgr, nc);
        mg_call(nc, NULL, nc->user_data, MG_EV_ACCEPT, &nc->sa);
      }
    }
  }
  if (nc != NULL) {
    DBG(("%p <- %d bytes from %s:%d", nc, n, inet_ntoa(nc->sa.sin.sin_addr), ntohs(nc->sa.sin.sin_port)));
    if (nc == lc) {
      nc->recv_mbuf.len += n;
    } else {
      mbuf_append(&nc->recv_mbuf, buf, n);
    }
    mbuf_trim(&lc->recv_mbuf);
    lc->last_io_time = nc->last_io_time = (time_t) mg_time();

    if (nc->mgr && nc->mgr->hexdump_file != NULL) {
      mg_hexdump_connection(nc, nc->mgr->hexdump_file, buf, n, MG_EV_RECV);
    }

    mg_call(nc, NULL, nc->user_data, MG_EV_RECV, &n);
  }

out:
  mbuf_free(&lc->recv_mbuf);
  return n;
}

void mg_if_can_send_cb(struct mg_connection *nc) {
  int n = 0;
  const char *buf = nc->send_mbuf.buf;
  size_t len = nc->send_mbuf.len;

  if (nc->flags & (MG_F_CLOSE_IMMEDIATELY | MG_F_CONNECTING)) {
    return;
  }
  if (!(nc->flags & MG_F_UDP)) {
    if (nc->flags & MG_F_LISTENING) return;
    if (len > MG_TCP_IO_SIZE) len = MG_TCP_IO_SIZE;
  }

  if (nc->flags & MG_F_SSL) {
    if (nc->flags & MG_F_SSL_HANDSHAKE_DONE) {
      if (len > 0) {
        n = mg_ssl_if_write(nc, buf, len);
        DBG(("%p -> %d bytes (SSL)", nc, n));
      }
      if (n < 0) {
        if (n == MG_SSL_WANT_WRITE) {
          nc->flags |= MG_F_WANT_WRITE;
          n = 0;
        } else {
          nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        }
      } else {
        nc->flags &= ~MG_F_WANT_WRITE;
      }
    } else {
      mg_ssl_handshake(nc);
    }
  } else  {

    if (nc->flags & MG_F_UDP) {
      n = nc->iface->vtable->udp_send(nc, buf, len);
    } else {
      n = nc->iface->vtable->tcp_send(nc, buf, len);
    }
    DBG(("%p -> %d bytes", nc, n));
  }


  if (n > 0 && nc->mgr && nc->mgr->hexdump_file != NULL) {
    mg_hexdump_connection(nc, nc->mgr->hexdump_file, buf, n, MG_EV_SEND);
  }

  if (n < 0) {
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  } else if (n > 0) {
    nc->last_io_time = (time_t) mg_time();
    mbuf_remove(&nc->send_mbuf, n);
    mbuf_trim(&nc->send_mbuf);
  }
  if (n != 0) mg_call(nc, NULL, nc->user_data, MG_EV_SEND, &n);
}


MG_INTERNAL struct mg_connection *mg_do_connect(struct mg_connection *nc, int proto, union socket_address *sa) {

  LOG(LL_DEBUG, ("%p %s://%s:%hu", nc, proto == SOCK_DGRAM ? "udp" : "tcp", inet_ntoa(sa->sin.sin_addr), ntohs(sa->sin.sin_port)));

  nc->flags |= MG_F_CONNECTING;
  if (proto == SOCK_DGRAM) {
    nc->iface->vtable->connect_udp(nc);
  } else {
    nc->iface->vtable->connect_tcp(nc, sa);
  }
  mg_add_conn(nc->mgr, nc);
  return nc;
}

void mg_if_connect_cb(struct mg_connection *nc, int err) {
  LOG(LL_DEBUG, ("%p %s://%s:%hu -> %d", nc, (nc->flags & MG_F_UDP ? "udp" : "tcp"), inet_ntoa(nc->sa.sin.sin_addr), ntohs(nc->sa.sin.sin_port), err));

  nc->flags &= ~MG_F_CONNECTING;
  if (err != 0) {
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  }

  if (err == 0 && (nc->flags & MG_F_SSL)) {
    mg_ssl_handshake(nc);
  } else  {

    mg_call(nc, NULL, nc->user_data, MG_EV_CONNECT, &err);
  }
}



static void resolve_cb(struct mg_dns_message *msg, void *data, enum mg_resolve_err e) {
  struct mg_connection *nc = (struct mg_connection *) data;
  int i;
  int failure = -1;

  nc->flags &= ~MG_F_RESOLVING;
  if (msg != NULL) {
    
    for (i = 0; i < msg->num_answers; i++) {
      if (msg->answers[i].rtype == MG_DNS_A_RECORD) {
        
        mg_dns_parse_record_data(msg, &msg->answers[i], &nc->sa.sin.sin_addr, 4);
        mg_do_connect(nc, nc->flags & MG_F_UDP ? SOCK_DGRAM : SOCK_STREAM, &nc->sa);
        return;
      }
    }
  }

  if (e == MG_RESOLVE_TIMEOUT) {
    double now = mg_time();
    mg_call(nc, NULL, nc->user_data, MG_EV_TIMER, &now);
  }

  
  mg_call(nc, NULL, nc->user_data, MG_EV_CONNECT, &failure);
  mg_call(nc, NULL, nc->user_data, MG_EV_CLOSE, NULL);
  mg_destroy_conn(nc, 1 );
}


struct mg_connection *mg_connect(struct mg_mgr *mgr, const char *address, MG_CB(mg_event_handler_t callback, void *user_data)) {

  struct mg_connect_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_connect_opt(mgr, address, MG_CB(callback, user_data), opts);
}

struct mg_connection *mg_connect_opt(struct mg_mgr *mgr, const char *address, MG_CB(mg_event_handler_t callback, void *user_data), struct mg_connect_opts opts) {


  struct mg_connection *nc = NULL;
  int proto, rc;
  struct mg_add_sock_opts add_sock_opts;
  char host[MG_MAX_HOST_LEN];

  MG_COPY_COMMON_CONNECTION_OPTIONS(&add_sock_opts, &opts);

  if ((nc = mg_create_connection(mgr, callback, add_sock_opts)) == NULL) {
    return NULL;
  }

  if ((rc = mg_parse_address(address, &nc->sa, &proto, host, sizeof(host))) < 0) {
    
    MG_SET_PTRPTR(opts.error_string, "cannot parse address");
    mg_destroy_conn(nc, 1 );
    return NULL;
  }

  nc->flags |= opts.flags & _MG_ALLOWED_CONNECT_FLAGS_MASK;
  nc->flags |= (proto == SOCK_DGRAM) ? MG_F_UDP : 0;

  nc->user_data = user_data;

  nc->user_data = opts.user_data;



  LOG(LL_DEBUG, ("%p %s %s,%s,%s", nc, address, (opts.ssl_cert ? opts.ssl_cert : "-"), (opts.ssl_key ? opts.ssl_key : "-"), (opts.ssl_ca_cert ? opts.ssl_ca_cert : "-")));



  if (opts.ssl_cert != NULL || opts.ssl_ca_cert != NULL || opts.ssl_psk_identity != NULL) {
    const char *err_msg = NULL;
    struct mg_ssl_if_conn_params params;
    if (nc->flags & MG_F_UDP) {
      MG_SET_PTRPTR(opts.error_string, "SSL for UDP is not supported");
      mg_destroy_conn(nc, 1 );
      return NULL;
    }
    memset(&params, 0, sizeof(params));
    params.cert = opts.ssl_cert;
    params.key = opts.ssl_key;
    params.ca_cert = opts.ssl_ca_cert;
    params.cipher_suites = opts.ssl_cipher_suites;
    params.psk_identity = opts.ssl_psk_identity;
    params.psk_key = opts.ssl_psk_key;
    if (opts.ssl_ca_cert != NULL) {
      if (opts.ssl_server_name != NULL) {
        if (strcmp(opts.ssl_server_name, "*") != 0) {
          params.server_name = opts.ssl_server_name;
        }
      } else if (rc == 0) { 
        params.server_name = host;
      }
    }
    if (mg_ssl_if_conn_init(nc, &params, &err_msg) != MG_SSL_OK) {
      MG_SET_PTRPTR(opts.error_string, err_msg);
      mg_destroy_conn(nc, 1 );
      return NULL;
    }
    nc->flags |= MG_F_SSL;
  }


  if (rc == 0) {

    
    struct mg_connection *dns_conn = NULL;
    struct mg_resolve_async_opts o;
    memset(&o, 0, sizeof(o));
    o.dns_conn = &dns_conn;
    o.nameserver = opts.nameserver;
    if (mg_resolve_async_opt(nc->mgr, host, MG_DNS_A_RECORD, resolve_cb, nc, o) != 0) {
      MG_SET_PTRPTR(opts.error_string, "cannot schedule DNS lookup");
      mg_destroy_conn(nc, 1 );
      return NULL;
    }
    nc->priv_2 = dns_conn;
    nc->flags |= MG_F_RESOLVING;
    return nc;

    MG_SET_PTRPTR(opts.error_string, "Resolver is disabled");
    mg_destroy_conn(nc, 1 );
    return NULL;

  } else {
    
    return mg_do_connect(nc, proto, &nc->sa);
  }
}

struct mg_connection *mg_bind(struct mg_mgr *srv, const char *address, MG_CB(mg_event_handler_t event_handler, void *user_data)) {

  struct mg_bind_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_bind_opt(srv, address, MG_CB(event_handler, user_data), opts);
}

struct mg_connection *mg_bind_opt(struct mg_mgr *mgr, const char *address, MG_CB(mg_event_handler_t callback, void *user_data), struct mg_bind_opts opts) {


  union socket_address sa;
  struct mg_connection *nc = NULL;
  int proto, rc;
  struct mg_add_sock_opts add_sock_opts;
  char host[MG_MAX_HOST_LEN];


  opts.user_data = user_data;


  if (callback == NULL) {
    MG_SET_PTRPTR(opts.error_string, "handler is required");
    return NULL;
  }

  MG_COPY_COMMON_CONNECTION_OPTIONS(&add_sock_opts, &opts);

  if (mg_parse_address(address, &sa, &proto, host, sizeof(host)) <= 0) {
    MG_SET_PTRPTR(opts.error_string, "cannot parse address");
    return NULL;
  }

  nc = mg_create_connection(mgr, callback, add_sock_opts);
  if (nc == NULL) {
    return NULL;
  }

  nc->sa = sa;
  nc->flags |= MG_F_LISTENING;
  if (proto == SOCK_DGRAM) nc->flags |= MG_F_UDP;


  DBG(("%p %s %s,%s,%s", nc, address, (opts.ssl_cert ? opts.ssl_cert : "-"), (opts.ssl_key ? opts.ssl_key : "-"), (opts.ssl_ca_cert ? opts.ssl_ca_cert : "-")));


  if (opts.ssl_cert != NULL || opts.ssl_ca_cert != NULL) {
    const char *err_msg = NULL;
    struct mg_ssl_if_conn_params params;
    if (nc->flags & MG_F_UDP) {
      MG_SET_PTRPTR(opts.error_string, "SSL for UDP is not supported");
      mg_destroy_conn(nc, 1 );
      return NULL;
    }
    memset(&params, 0, sizeof(params));
    params.cert = opts.ssl_cert;
    params.key = opts.ssl_key;
    params.ca_cert = opts.ssl_ca_cert;
    params.cipher_suites = opts.ssl_cipher_suites;
    if (mg_ssl_if_conn_init(nc, &params, &err_msg) != MG_SSL_OK) {
      MG_SET_PTRPTR(opts.error_string, err_msg);
      mg_destroy_conn(nc, 1 );
      return NULL;
    }
    nc->flags |= MG_F_SSL;
  }


  if (nc->flags & MG_F_UDP) {
    rc = nc->iface->vtable->listen_udp(nc, &nc->sa);
  } else {
    rc = nc->iface->vtable->listen_tcp(nc, &nc->sa);
  }
  if (rc != 0) {
    DBG(("Failed to open listener: %d", rc));
    MG_SET_PTRPTR(opts.error_string, "failed to open listener");
    mg_destroy_conn(nc, 1 );
    return NULL;
  }
  mg_add_conn(nc->mgr, nc);

  return nc;
}

struct mg_connection *mg_next(struct mg_mgr *s, struct mg_connection *conn) {
  return conn == NULL ? s->active_connections : conn->next;
}


void mg_broadcast(struct mg_mgr *mgr, mg_event_handler_t cb, void *data, size_t len) {
  struct ctl_msg ctl_msg;

  
  if (mgr->ctl[0] != INVALID_SOCKET && data != NULL && len < sizeof(ctl_msg.message)) {
    size_t dummy;

    ctl_msg.callback = cb;
    memcpy(ctl_msg.message, data, len);
    dummy = MG_SEND_FUNC(mgr->ctl[0], (char *) &ctl_msg, offsetof(struct ctl_msg, message) + len, 0);
    dummy = MG_RECV_FUNC(mgr->ctl[0], (char *) &len, 1, 0);
    (void) dummy; 
  }
}


static int isbyte(int n) {
  return n >= 0 && n <= 255;
}

static int parse_net(const char *spec, uint32_t *net, uint32_t *mask) {
  int n, a, b, c, d, slash = 32, len = 0;

  if ((sscanf(spec, "%d.%d.%d.%d/%d%n", &a, &b, &c, &d, &slash, &n) == 5 || sscanf(spec, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4) && isbyte(a) && isbyte(b) && isbyte(c) && isbyte(d) && slash >= 0 && slash < 33) {


    len = n;
    *net = ((uint32_t) a << 24) | ((uint32_t) b << 16) | ((uint32_t) c << 8) | d;
    *mask = slash ? 0xffffffffU << (32 - slash) : 0;
  }

  return len;
}

int mg_check_ip_acl(const char *acl, uint32_t remote_ip) {
  int allowed, flag;
  uint32_t net, mask;
  struct mg_str vec;

  
  allowed = (acl == NULL || *acl == '\0') ? '+' : '-';

  while ((acl = mg_next_comma_list_entry(acl, &vec, NULL)) != NULL) {
    flag = vec.p[0];
    if ((flag != '+' && flag != '-') || parse_net(&vec.p[1], &net, &mask) == 0) {
      return -1;
    }

    if (net == (remote_ip & mask)) {
      allowed = flag;
    }
  }

  DBG(("%08x %c", (unsigned int) remote_ip, allowed));
  return allowed == '+';
}


void mg_forward(struct mg_connection *from, struct mg_connection *to) {
  mg_send(to, from->recv_mbuf.buf, from->recv_mbuf.len);
  mbuf_remove(&from->recv_mbuf, from->recv_mbuf.len);
}

double mg_set_timer(struct mg_connection *c, double timestamp) {
  double result = c->ev_timer_time;
  c->ev_timer_time = timestamp;
  
  DBG(("%p %p %d -> %lu", c, c->priv_2, (c->flags & MG_F_RESOLVING ? 1 : 0), (unsigned long) timestamp));
  if ((c->flags & MG_F_RESOLVING) && c->priv_2 != NULL) {
    mg_set_timer((struct mg_connection *) c->priv_2, timestamp);
  }
  return result;
}

void mg_sock_set(struct mg_connection *nc, sock_t sock) {
  if (sock != INVALID_SOCKET) {
    nc->iface->vtable->sock_set(nc, sock);
  }
}

void mg_if_get_conn_addr(struct mg_connection *nc, int remote, union socket_address *sa) {
  nc->iface->vtable->get_conn_addr(nc, remote, sa);
}

struct mg_connection *mg_add_sock_opt(struct mg_mgr *s, sock_t sock, MG_CB(mg_event_handler_t callback, void *user_data), struct mg_add_sock_opts opts) {



  opts.user_data = user_data;


  struct mg_connection *nc = mg_create_connection_base(s, callback, opts);
  if (nc != NULL) {
    mg_sock_set(nc, sock);
    mg_add_conn(nc->mgr, nc);
  }
  return nc;
}

struct mg_connection *mg_add_sock(struct mg_mgr *s, sock_t sock, MG_CB(mg_event_handler_t callback, void *user_data)) {

  struct mg_add_sock_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_add_sock_opt(s, sock, MG_CB(callback, user_data), opts);
}

double mg_time(void) {
  return cs_time();
}











extern "C" {






extern const struct mg_iface_vtable mg_socket_iface_vtable;


}















extern "C" {


extern const struct mg_iface_vtable mg_socks_iface_vtable;


}










extern const struct mg_iface_vtable mg_default_iface_vtable;

const struct mg_iface_vtable *mg_ifaces[] = {
    &mg_default_iface_vtable, };

int mg_num_ifaces = (int) (sizeof(mg_ifaces) / sizeof(mg_ifaces[0]));

struct mg_iface *mg_if_create_iface(const struct mg_iface_vtable *vtable, struct mg_mgr *mgr) {
  struct mg_iface *iface = (struct mg_iface *) MG_CALLOC(1, sizeof(*iface));
  iface->mgr = mgr;
  iface->data = NULL;
  iface->vtable = vtable;
  return iface;
}

struct mg_iface *mg_find_iface(struct mg_mgr *mgr, const struct mg_iface_vtable *vtable, struct mg_iface *from) {

  int i = 0;
  if (from != NULL) {
    for (i = 0; i < mgr->num_ifaces; i++) {
      if (mgr->ifaces[i] == from) {
        i++;
        break;
      }
    }
  }

  for (; i < mgr->num_ifaces; i++) {
    if (mgr->ifaces[i]->vtable == vtable) {
      return mgr->ifaces[i];
    }
  }
  return NULL;
}











static sock_t mg_open_listening_socket(union socket_address *sa, int type, int proto);

void mg_set_non_blocking_mode(sock_t sock) {

  unsigned long on = 1;
  ioctlsocket(sock, FIONBIO, &on);

  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

}

static int mg_is_error(void) {
  int err = mg_get_errno();
  return err != EINPROGRESS && err != EWOULDBLOCK  && err != EAGAIN && err != EINTR   && WSAGetLastError() != WSAEINTR && WSAGetLastError() != WSAEWOULDBLOCK  ;






}

void mg_socket_if_connect_tcp(struct mg_connection *nc, const union socket_address *sa) {
  int rc, proto = 0;
  nc->sock = socket(AF_INET, SOCK_STREAM, proto);
  if (nc->sock == INVALID_SOCKET) {
    nc->err = mg_get_errno() ? mg_get_errno() : 1;
    return;
  }

  mg_set_non_blocking_mode(nc->sock);

  rc = connect(nc->sock, &sa->sa, sizeof(sa->sin));
  nc->err = rc < 0 && mg_is_error() ? mg_get_errno() : 0;
  DBG(("%p sock %d rc %d errno %d err %d", nc, nc->sock, rc, mg_get_errno(), nc->err));
}

void mg_socket_if_connect_udp(struct mg_connection *nc) {
  nc->sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (nc->sock == INVALID_SOCKET) {
    nc->err = mg_get_errno() ? mg_get_errno() : 1;
    return;
  }
  if (nc->flags & MG_F_ENABLE_BROADCAST) {
    int optval = 1;
    if (setsockopt(nc->sock, SOL_SOCKET, SO_BROADCAST, (const char *) &optval, sizeof(optval)) < 0) {
      nc->err = mg_get_errno() ? mg_get_errno() : 1;
      return;
    }
  }
  nc->err = 0;
}

int mg_socket_if_listen_tcp(struct mg_connection *nc, union socket_address *sa) {
  int proto = 0;
  sock_t sock = mg_open_listening_socket(sa, SOCK_STREAM, proto);
  if (sock == INVALID_SOCKET) {
    return (mg_get_errno() ? mg_get_errno() : 1);
  }
  mg_sock_set(nc, sock);
  return 0;
}

static int mg_socket_if_listen_udp(struct mg_connection *nc, union socket_address *sa) {
  sock_t sock = mg_open_listening_socket(sa, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) return (mg_get_errno() ? mg_get_errno() : 1);
  mg_sock_set(nc, sock);
  return 0;
}

static int mg_socket_if_tcp_send(struct mg_connection *nc, const void *buf, size_t len) {
  int n = (int) MG_SEND_FUNC(nc->sock, buf, len, 0);
  if (n < 0 && !mg_is_error()) n = 0;
  return n;
}

static int mg_socket_if_udp_send(struct mg_connection *nc, const void *buf, size_t len) {
  int n = sendto(nc->sock, buf, len, 0, &nc->sa.sa, sizeof(nc->sa.sin));
  if (n < 0 && !mg_is_error()) n = 0;
  return n;
}

static int mg_socket_if_tcp_recv(struct mg_connection *nc, void *buf, size_t len) {
  int n = (int) MG_RECV_FUNC(nc->sock, buf, len, 0);
  if (n == 0) {
    
    nc->flags |= MG_F_SEND_AND_CLOSE;
  } else if (n < 0 && !mg_is_error()) {
    n = 0;
  }
  return n;
}

static int mg_socket_if_udp_recv(struct mg_connection *nc, void *buf, size_t len, union socket_address *sa, size_t *sa_len) {

  socklen_t sa_len_st = *sa_len;
  int n = recvfrom(nc->sock, buf, len, 0, &sa->sa, &sa_len_st);
  *sa_len = sa_len_st;
  if (n < 0 && !mg_is_error()) n = 0;
  return n;
}

int mg_socket_if_create_conn(struct mg_connection *nc) {
  (void) nc;
  return 1;
}

void mg_socket_if_destroy_conn(struct mg_connection *nc) {
  if (nc->sock == INVALID_SOCKET) return;
  if (!(nc->flags & MG_F_UDP)) {
    closesocket(nc->sock);
  } else {
    
    if (nc->listener == NULL) closesocket(nc->sock);
  }
  nc->sock = INVALID_SOCKET;
}

static int mg_accept_conn(struct mg_connection *lc) {
  struct mg_connection *nc;
  union socket_address sa;
  socklen_t sa_len = sizeof(sa);
  
  sock_t sock = accept(lc->sock, &sa.sa, &sa_len);
  if (sock == INVALID_SOCKET) {
    if (mg_is_error()) {
      DBG(("%p: failed to accept: %d", lc, mg_get_errno()));
    }
    return 0;
  }
  nc = mg_if_accept_new_conn(lc);
  if (nc == NULL) {
    closesocket(sock);
    return 0;
  }
  DBG(("%p conn from %s:%d", nc, inet_ntoa(sa.sin.sin_addr), ntohs(sa.sin.sin_port)));
  mg_sock_set(nc, sock);
  mg_if_accept_tcp_cb(nc, &sa, sa_len);
  return 1;
}


static sock_t mg_open_listening_socket(union socket_address *sa, int type, int proto) {
  socklen_t sa_len = (sa->sa.sa_family == AF_INET) ? sizeof(sa->sin) : sizeof(sa->sin6);
  sock_t sock = INVALID_SOCKET;

  int on = 1;


  if ((sock = socket(sa->sa.sa_family, type, proto)) != INVALID_SOCKET &&    !setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (void *) &on, sizeof(on)) &&     !setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) &&    !bind(sock, &sa->sa, sa_len) && (type == SOCK_DGRAM || listen(sock, SOMAXCONN) == 0)) {















    mg_set_non_blocking_mode(sock);
    
    (void) getsockname(sock, &sa->sa, &sa_len);

  } else if (sock != INVALID_SOCKET) {
    closesocket(sock);
    sock = INVALID_SOCKET;
  }

  return sock;
}





void mg_mgr_handle_conn(struct mg_connection *nc, int fd_flags, double now) {
  int worth_logging = fd_flags != 0 || (nc->flags & (MG_F_WANT_READ | MG_F_WANT_WRITE));
  if (worth_logging) {
    DBG(("%p fd=%d fd_flags=%d nc_flags=0x%lx rmbl=%d smbl=%d", nc, nc->sock, fd_flags, nc->flags, (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));

  }

  if (!mg_if_poll(nc, now)) return;

  if (nc->flags & MG_F_CONNECTING) {
    if (fd_flags != 0) {
      int err = 0;

      if (!(nc->flags & MG_F_UDP)) {
        socklen_t len = sizeof(err);
        int ret = getsockopt(nc->sock, SOL_SOCKET, SO_ERROR, (char *) &err, &len);
        if (ret != 0) {
          err = 1;
        } else if (err == EAGAIN || err == EWOULDBLOCK) {
          err = 0;
        }
      }

      
      err = nc->err;

      mg_if_connect_cb(nc, err);
    } else if (nc->err != 0) {
      mg_if_connect_cb(nc, nc->err);
    }
  }

  if (fd_flags & _MG_F_FD_CAN_READ) {
    if (nc->flags & MG_F_UDP) {
      mg_if_can_recv_cb(nc);
    } else {
      if (nc->flags & MG_F_LISTENING) {
        
        mg_accept_conn(nc);
      } else {
        mg_if_can_recv_cb(nc);
      }
    }
  }

  if (fd_flags & _MG_F_FD_CAN_WRITE) mg_if_can_send_cb(nc);

  if (worth_logging) {
    DBG(("%p after fd=%d nc_flags=0x%lx rmbl=%d smbl=%d", nc, nc->sock, nc->flags, (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));
  }
}


static void mg_mgr_handle_ctl_sock(struct mg_mgr *mgr) {
  struct ctl_msg ctl_msg;
  int len = (int) MG_RECV_FUNC(mgr->ctl[1], (char *) &ctl_msg, sizeof(ctl_msg), 0);
  size_t dummy = MG_SEND_FUNC(mgr->ctl[1], ctl_msg.message, 1, 0);
  DBG(("read %d from ctl socket", len));
  (void) dummy; 
  if (len >= (int) sizeof(ctl_msg.callback) && ctl_msg.callback != NULL) {
    struct mg_connection *nc;
    for (nc = mg_next(mgr, NULL); nc != NULL; nc = mg_next(mgr, nc)) {
      ctl_msg.callback(nc, MG_EV_POLL, ctl_msg.message MG_UD_ARG(nc->user_data));
    }
  }
}



void mg_socket_if_sock_set(struct mg_connection *nc, sock_t sock) {
  mg_set_non_blocking_mode(sock);
  mg_set_close_on_exec(sock);
  nc->sock = sock;
  DBG(("%p %d", nc, sock));
}

void mg_socket_if_init(struct mg_iface *iface) {
  (void) iface;
  DBG(("%p using select()", iface->mgr));

  mg_socketpair(iface->mgr->ctl, SOCK_DGRAM);

}

void mg_socket_if_free(struct mg_iface *iface) {
  (void) iface;
}

void mg_socket_if_add_conn(struct mg_connection *nc) {
  (void) nc;
}

void mg_socket_if_remove_conn(struct mg_connection *nc) {
  (void) nc;
}

void mg_add_to_set(sock_t sock, fd_set *set, sock_t *max_fd) {
  if (sock != INVALID_SOCKET  && sock < (sock_t) FD_SETSIZE  ) {



    FD_SET(sock, set);
    if (*max_fd == INVALID_SOCKET || sock > *max_fd) {
      *max_fd = sock;
    }
  }
}

time_t mg_socket_if_poll(struct mg_iface *iface, int timeout_ms) {
  struct mg_mgr *mgr = iface->mgr;
  double now = mg_time();
  double min_timer;
  struct mg_connection *nc, *tmp;
  struct timeval tv;
  fd_set read_set, write_set, err_set;
  sock_t max_fd = INVALID_SOCKET;
  int num_fds, num_ev, num_timers = 0;

  int try_dup = 1;


  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  FD_ZERO(&err_set);

  mg_add_to_set(mgr->ctl[1], &read_set, &max_fd);


  
  min_timer = 0;
  for (nc = mgr->active_connections, num_fds = 0; nc != NULL; nc = tmp) {
    tmp = nc->next;

    if (nc->sock != INVALID_SOCKET) {
      num_fds++;


      
      if (nc->sock >= (sock_t) FD_SETSIZE && try_dup) {
        int new_sock = dup(nc->sock);
        if (new_sock >= 0) {
          if (new_sock < (sock_t) FD_SETSIZE) {
            closesocket(nc->sock);
            DBG(("new sock %d -> %d", nc->sock, new_sock));
            nc->sock = new_sock;
          } else {
            closesocket(new_sock);
            DBG(("new sock is still larger than FD_SETSIZE, disregard"));
            try_dup = 0;
          }
        } else {
          try_dup = 0;
        }
      }


      if (nc->recv_mbuf.len < nc->recv_mbuf_limit && (!(nc->flags & MG_F_UDP) || nc->listener == NULL)) {
        mg_add_to_set(nc->sock, &read_set, &max_fd);
      }

      if (((nc->flags & MG_F_CONNECTING) && !(nc->flags & MG_F_WANT_READ)) || (nc->send_mbuf.len > 0 && !(nc->flags & MG_F_CONNECTING))) {
        mg_add_to_set(nc->sock, &write_set, &max_fd);
        mg_add_to_set(nc->sock, &err_set, &max_fd);
      }
    }

    if (nc->ev_timer_time > 0) {
      if (num_timers == 0 || nc->ev_timer_time < min_timer) {
        min_timer = nc->ev_timer_time;
      }
      num_timers++;
    }
  }

  
  if (num_timers > 0) {
    double timer_timeout_ms = (min_timer - mg_time()) * 1000 + 1 ;
    if (timer_timeout_ms < timeout_ms) {
      timeout_ms = (int) timer_timeout_ms;
    }
  }
  if (timeout_ms < 0) timeout_ms = 0;

  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  num_ev = select((int) max_fd + 1, &read_set, &write_set, &err_set, &tv);
  now = mg_time();

  DBG(("select @ %ld num_ev=%d of %d, timeout=%d", (long) now, num_ev, num_fds, timeout_ms));



  if (num_ev > 0 && mgr->ctl[1] != INVALID_SOCKET && FD_ISSET(mgr->ctl[1], &read_set)) {
    mg_mgr_handle_ctl_sock(mgr);
  }


  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    int fd_flags = 0;
    if (nc->sock != INVALID_SOCKET) {
      if (num_ev > 0) {
        fd_flags = (FD_ISSET(nc->sock, &read_set) && (!(nc->flags & MG_F_UDP) || nc->listener == NULL)
                        ? _MG_F_FD_CAN_READ : 0) | (FD_ISSET(nc->sock, &write_set) ? _MG_F_FD_CAN_WRITE : 0) | (FD_ISSET(nc->sock, &err_set) ? _MG_F_FD_ERROR : 0);


      }

      
      if ((nc->flags & MG_F_UDP) && nc->listener == NULL) {
        fd_flags |= _MG_F_FD_CAN_WRITE;
      }

    }
    tmp = nc->next;
    mg_mgr_handle_conn(nc, fd_flags, now);
  }

  return (time_t) now;
}


MG_INTERNAL void mg_socketpair_close(sock_t *sock) {
  while (1) {
    if (closesocket(*sock) == -1 && errno == EINTR) continue;
    break;
  }
  *sock = INVALID_SOCKET;
}

MG_INTERNAL sock_t mg_socketpair_accept(sock_t sock, union socket_address *sa, socklen_t sa_len) {
  sock_t rc;
  while (1) {
    if ((rc = accept(sock, &sa->sa, &sa_len)) == INVALID_SOCKET && errno == EINTR)
      continue;
    break;
  }
  return rc;
}

int mg_socketpair(sock_t sp[2], int sock_type) {
  union socket_address sa, sa2;
  sock_t sock;
  socklen_t len = sizeof(sa.sin);
  int ret = 0;

  sock = sp[0] = sp[1] = INVALID_SOCKET;

  (void) memset(&sa, 0, sizeof(sa));
  sa.sin.sin_family = AF_INET;
  sa.sin.sin_addr.s_addr = htonl(0x7f000001); 
  sa2 = sa;

  if ((sock = socket(AF_INET, sock_type, 0)) == INVALID_SOCKET) {
  } else if (bind(sock, &sa.sa, len) != 0) {
  } else if (sock_type == SOCK_STREAM && listen(sock, 1) != 0) {
  } else if (getsockname(sock, &sa.sa, &len) != 0) {
  } else if ((sp[0] = socket(AF_INET, sock_type, 0)) == INVALID_SOCKET) {
  } else if (sock_type == SOCK_STREAM && connect(sp[0], &sa.sa, len) != 0) {
  } else if (sock_type == SOCK_DGRAM && (bind(sp[0], &sa2.sa, len) != 0 || getsockname(sp[0], &sa2.sa, &len) != 0 || connect(sp[0], &sa.sa, len) != 0 || connect(sock, &sa2.sa, len) != 0)) {



  } else if ((sp[1] = (sock_type == SOCK_DGRAM ? sock : mg_socketpair_accept( sock, &sa, len))) == INVALID_SOCKET) {

  } else {
    mg_set_close_on_exec(sp[0]);
    mg_set_close_on_exec(sp[1]);
    if (sock_type == SOCK_STREAM) mg_socketpair_close(&sock);
    ret = 1;
  }

  if (!ret) {
    if (sp[0] != INVALID_SOCKET) mg_socketpair_close(&sp[0]);
    if (sp[1] != INVALID_SOCKET) mg_socketpair_close(&sp[1]);
    if (sock != INVALID_SOCKET) mg_socketpair_close(&sock);
  }

  return ret;
}


static void mg_sock_get_addr(sock_t sock, int remote, union socket_address *sa) {
  socklen_t slen = sizeof(*sa);
  memset(sa, 0, slen);
  if (remote) {
    getpeername(sock, &sa->sa, &slen);
  } else {
    getsockname(sock, &sa->sa, &slen);
  }
}

void mg_sock_to_str(sock_t sock, char *buf, size_t len, int flags) {
  union socket_address sa;
  mg_sock_get_addr(sock, flags & MG_SOCK_STRINGIFY_REMOTE, &sa);
  mg_sock_addr_to_str(&sa, buf, len, flags);
}

void mg_socket_if_get_conn_addr(struct mg_connection *nc, int remote, union socket_address *sa) {
  if ((nc->flags & MG_F_UDP) && remote) {
    memcpy(sa, &nc->sa, sizeof(*sa));
    return;
  }
  mg_sock_get_addr(nc->sock, remote, sa);
}























const struct mg_iface_vtable mg_socket_iface_vtable = MG_SOCKET_IFACE_VTABLE;

const struct mg_iface_vtable mg_default_iface_vtable = MG_SOCKET_IFACE_VTABLE;










struct socksdata {
  char *proxy_addr;        
  struct mg_connection *s; 
  struct mg_connection *c; 
};

static void socks_if_disband(struct socksdata *d) {
  LOG(LL_DEBUG, ("disbanding proxy %p %p", d->c, d->s));
  if (d->c) {
    d->c->flags |= MG_F_SEND_AND_CLOSE;
    d->c->user_data = NULL;
    d->c = NULL;
  }
  if (d->s) {
    d->s->flags |= MG_F_SEND_AND_CLOSE;
    d->s->user_data = NULL;
    d->s = NULL;
  }
}

static void socks_if_relay(struct mg_connection *s) {
  struct socksdata *d = (struct socksdata *) s->user_data;
  if (d == NULL || d->c == NULL || !(s->flags & MG_SOCKS_CONNECT_DONE) || d->s == NULL) {
    return;
  }
  if (s->recv_mbuf.len > 0) mg_if_can_recv_cb(d->c);
  if (d->c->send_mbuf.len > 0 && s->send_mbuf.len == 0) mg_if_can_send_cb(d->c);
}

static void socks_if_handler(struct mg_connection *c, int ev, void *ev_data) {
  struct socksdata *d = (struct socksdata *) c->user_data;
  if (d == NULL) return;
  if (ev == MG_EV_CONNECT) {
    int res = *(int *) ev_data;
    if (res == 0) {
      
      unsigned char buf[] = {MG_SOCKS_VERSION, 1, MG_SOCKS_HANDSHAKE_NOAUTH};
      mg_send(d->s, buf, sizeof(buf));
      LOG(LL_DEBUG, ("Sent handshake to %s", d->proxy_addr));
    } else {
      LOG(LL_ERROR, ("Cannot connect to %s: %d", d->proxy_addr, res));
      d->c->flags |= MG_F_CLOSE_IMMEDIATELY;
    }
  } else if (ev == MG_EV_CLOSE) {
    socks_if_disband(d);
  } else if (ev == MG_EV_RECV) {
    
    if (!(c->flags & MG_SOCKS_HANDSHAKE_DONE)) {
      
      unsigned char buf[10] = {MG_SOCKS_VERSION, MG_SOCKS_CMD_CONNECT, 0, MG_SOCKS_ADDR_IPV4};
      if (c->recv_mbuf.len < 2) return;
      if ((unsigned char) c->recv_mbuf.buf[1] == MG_SOCKS_HANDSHAKE_FAILURE) {
        LOG(LL_ERROR, ("Server kicked us out"));
        socks_if_disband(d);
        return;
      }
      mbuf_remove(&c->recv_mbuf, 2);
      c->flags |= MG_SOCKS_HANDSHAKE_DONE;

      
      memcpy(buf + 4, &d->c->sa.sin.sin_addr, 4);
      memcpy(buf + 8, &d->c->sa.sin.sin_port, 2);
      mg_send(c, buf, sizeof(buf));
      LOG(LL_DEBUG, ("%p Sent connect request", c));
    }
    
    if ((c->flags & MG_SOCKS_HANDSHAKE_DONE) && !(c->flags & MG_SOCKS_CONNECT_DONE)) {
      if (c->recv_mbuf.len < 10) return;
      if (c->recv_mbuf.buf[1] != MG_SOCKS_SUCCESS) {
        LOG(LL_ERROR, ("Socks connection error: %d", c->recv_mbuf.buf[1]));
        socks_if_disband(d);
        return;
      }
      mbuf_remove(&c->recv_mbuf, 10);
      c->flags |= MG_SOCKS_CONNECT_DONE;
      LOG(LL_DEBUG, ("%p Connect done %p", c, d->c));
      mg_if_connect_cb(d->c, 0);
    }
    socks_if_relay(c);
  } else if (ev == MG_EV_SEND || ev == MG_EV_POLL) {
    socks_if_relay(c);
  }
}

static void mg_socks_if_connect_tcp(struct mg_connection *c, const union socket_address *sa) {
  struct socksdata *d = (struct socksdata *) c->iface->data;
  d->c = c;
  d->s = mg_connect(c->mgr, d->proxy_addr, socks_if_handler);
  d->s->user_data = d;
  LOG(LL_DEBUG, ("%p %s %p %p", c, d->proxy_addr, d, d->s));
  (void) sa;
}

static void mg_socks_if_connect_udp(struct mg_connection *c) {
  (void) c;
}

static int mg_socks_if_listen_tcp(struct mg_connection *c, union socket_address *sa) {
  (void) c;
  (void) sa;
  return 0;
}

static int mg_socks_if_listen_udp(struct mg_connection *c, union socket_address *sa) {
  (void) c;
  (void) sa;
  return -1;
}

static int mg_socks_if_tcp_send(struct mg_connection *c, const void *buf, size_t len) {
  int res;
  struct socksdata *d = (struct socksdata *) c->iface->data;
  if (d->s == NULL) return -1;
  res = (int) mbuf_append(&d->s->send_mbuf, buf, len);
  DBG(("%p -> %d -> %p", c, res, d->s));
  return res;
}

static int mg_socks_if_udp_send(struct mg_connection *c, const void *buf, size_t len) {
  (void) c;
  (void) buf;
  (void) len;
  return -1;
}

int mg_socks_if_tcp_recv(struct mg_connection *c, void *buf, size_t len) {
  struct socksdata *d = (struct socksdata *) c->iface->data;
  if (d->s == NULL) return -1;
  if (len > d->s->recv_mbuf.len) len = d->s->recv_mbuf.len;
  if (len > 0) {
    memcpy(buf, d->s->recv_mbuf.buf, len);
    mbuf_remove(&d->s->recv_mbuf, len);
  }
  DBG(("%p <- %d <- %p", c, (int) len, d->s));
  return len;
}

int mg_socks_if_udp_recv(struct mg_connection *c, void *buf, size_t len, union socket_address *sa, size_t *sa_len) {
  (void) c;
  (void) buf;
  (void) len;
  (void) sa;
  (void) sa_len;
  return -1;
}

static int mg_socks_if_create_conn(struct mg_connection *c) {
  (void) c;
  return 1;
}

static void mg_socks_if_destroy_conn(struct mg_connection *c) {
  c->iface->vtable->free(c->iface);
  MG_FREE(c->iface);
  c->iface = NULL;
  LOG(LL_DEBUG, ("%p", c));
}

static void mg_socks_if_sock_set(struct mg_connection *c, sock_t sock) {
  (void) c;
  (void) sock;
}

static void mg_socks_if_init(struct mg_iface *iface) {
  (void) iface;
}

static void mg_socks_if_free(struct mg_iface *iface) {
  struct socksdata *d = (struct socksdata *) iface->data;
  LOG(LL_DEBUG, ("%p", iface));
  if (d != NULL) {
    socks_if_disband(d);
    MG_FREE(d->proxy_addr);
    MG_FREE(d);
    iface->data = NULL;
  }
}

static void mg_socks_if_add_conn(struct mg_connection *c) {
  c->sock = INVALID_SOCKET;
}

static void mg_socks_if_remove_conn(struct mg_connection *c) {
  (void) c;
}

static time_t mg_socks_if_poll(struct mg_iface *iface, int timeout_ms) {
  LOG(LL_DEBUG, ("%p", iface));
  (void) iface;
  (void) timeout_ms;
  return (time_t) cs_time();
}

static void mg_socks_if_get_conn_addr(struct mg_connection *c, int remote, union socket_address *sa) {
  LOG(LL_DEBUG, ("%p", c));
  (void) c;
  (void) remote;
  (void) sa;
}

const struct mg_iface_vtable mg_socks_iface_vtable = {
    mg_socks_if_init,          mg_socks_if_free, mg_socks_if_add_conn,      mg_socks_if_remove_conn, mg_socks_if_poll,          mg_socks_if_listen_tcp, mg_socks_if_listen_udp,    mg_socks_if_connect_tcp, mg_socks_if_connect_udp,   mg_socks_if_tcp_send, mg_socks_if_udp_send,      mg_socks_if_tcp_recv, mg_socks_if_udp_recv,      mg_socks_if_create_conn, mg_socks_if_destroy_conn,  mg_socks_if_sock_set, mg_socks_if_get_conn_addr, };









struct mg_iface *mg_socks_mk_iface(struct mg_mgr *mgr, const char *proxy_addr) {
  struct mg_iface *iface = mg_if_create_iface(&mg_socks_iface_vtable, mgr);
  iface->data = MG_CALLOC(1, sizeof(struct socksdata));
  ((struct socksdata *) iface->data)->proxy_addr = strdup(proxy_addr);
  return iface;
}


















struct mg_ssl_if_ctx {
  SSL *ssl;
  SSL_CTX *ssl_ctx;
  struct mbuf psk;
  size_t identity_len;
};

void mg_ssl_if_init() {
  SSL_library_init();
}

enum mg_ssl_if_result mg_ssl_if_conn_accept(struct mg_connection *nc, struct mg_connection *lc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) MG_CALLOC(1, sizeof(*ctx));
  struct mg_ssl_if_ctx *lc_ctx = (struct mg_ssl_if_ctx *) lc->ssl_if_data;
  nc->ssl_if_data = ctx;
  if (ctx == NULL || lc_ctx == NULL) return MG_SSL_ERROR;
  ctx->ssl_ctx = lc_ctx->ssl_ctx;
  if ((ctx->ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
    return MG_SSL_ERROR;
  }
  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_use_cert(SSL_CTX *ctx, const char *cert, const char *key, const char **err_msg);
static enum mg_ssl_if_result mg_use_ca_cert(SSL_CTX *ctx, const char *cert);
static enum mg_ssl_if_result mg_set_cipher_list(SSL_CTX *ctx, const char *cl);
static enum mg_ssl_if_result mg_ssl_if_ossl_set_psk(struct mg_ssl_if_ctx *ctx, const char *identity, const char *key_str);


enum mg_ssl_if_result mg_ssl_if_conn_init( struct mg_connection *nc, const struct mg_ssl_if_conn_params *params, const char **err_msg) {

  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) MG_CALLOC(1, sizeof(*ctx));
  DBG(("%p %s,%s,%s", nc, (params->cert ? params->cert : ""), (params->key ? params->key : ""), (params->ca_cert ? params->ca_cert : "")));

  if (ctx == NULL) {
    MG_SET_PTRPTR(err_msg, "Out of memory");
    return MG_SSL_ERROR;
  }
  nc->ssl_if_data = ctx;
  if (nc->flags & MG_F_LISTENING) {
    ctx->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  } else {
    ctx->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  }
  if (ctx->ssl_ctx == NULL) {
    MG_SET_PTRPTR(err_msg, "Failed to create SSL context");
    return MG_SSL_ERROR;
  }


  
  SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv3);
  SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);

  SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);


  SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);





  if (params->cert != NULL && mg_use_cert(ctx->ssl_ctx, params->cert, params->key, err_msg) != MG_SSL_OK) {

    return MG_SSL_ERROR;
  }

  if (params->ca_cert != NULL && mg_use_ca_cert(ctx->ssl_ctx, params->ca_cert) != MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL CA cert");
    return MG_SSL_ERROR;
  }

  if (mg_set_cipher_list(ctx->ssl_ctx, params->cipher_suites) != MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid cipher suite list");
    return MG_SSL_ERROR;
  }

  mbuf_init(&ctx->psk, 0);
  if (mg_ssl_if_ossl_set_psk(ctx, params->psk_identity, params->psk_key) != MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid PSK settings");
    return MG_SSL_ERROR;
  }

  if (!(nc->flags & MG_F_LISTENING) && (ctx->ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
    MG_SET_PTRPTR(err_msg, "Failed to create SSL session");
    return MG_SSL_ERROR;
  }

  if (params->server_name != NULL) {

    SSL_CTX_kr_set_verify_name(ctx->ssl_ctx, params->server_name);

    SSL_set_tlsext_host_name(ctx->ssl, params->server_name);

  }

  nc->flags |= MG_F_SSL;

  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_ssl_if_ssl_err(struct mg_connection *nc, int res) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  int err = SSL_get_error(ctx->ssl, res);
  if (err == SSL_ERROR_WANT_READ) return MG_SSL_WANT_READ;
  if (err == SSL_ERROR_WANT_WRITE) return MG_SSL_WANT_WRITE;
  DBG(("%p %p SSL error: %d %d", nc, ctx->ssl_ctx, res, err));
  nc->err = err;
  return MG_SSL_ERROR;
}

enum mg_ssl_if_result mg_ssl_if_handshake(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  int server_side = (nc->listener != NULL);
  int res;
  
  if (SSL_get_fd(ctx->ssl) < 0) {
    if (SSL_set_fd(ctx->ssl, nc->sock) != 1) return MG_SSL_ERROR;
  }
  res = server_side ? SSL_accept(ctx->ssl) : SSL_connect(ctx->ssl);
  if (res != 1) return mg_ssl_if_ssl_err(nc, res);
  return MG_SSL_OK;
}

int mg_ssl_if_read(struct mg_connection *nc, void *buf, size_t buf_size) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  int n = SSL_read(ctx->ssl, buf, buf_size);
  DBG(("%p %d -> %d", nc, (int) buf_size, n));
  if (n < 0) return mg_ssl_if_ssl_err(nc, n);
  if (n == 0) nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  return n;
}

int mg_ssl_if_write(struct mg_connection *nc, const void *data, size_t len) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  int n = SSL_write(ctx->ssl, data, len);
  DBG(("%p %d -> %d", nc, (int) len, n));
  if (n <= 0) return mg_ssl_if_ssl_err(nc, n);
  return n;
}

void mg_ssl_if_conn_close_notify(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  if (ctx == NULL) return;
  SSL_shutdown(ctx->ssl);
}

void mg_ssl_if_conn_free(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  if (ctx == NULL) return;
  nc->ssl_if_data = NULL;
  if (ctx->ssl != NULL) SSL_free(ctx->ssl);
  if (ctx->ssl_ctx != NULL && nc->listener == NULL) SSL_CTX_free(ctx->ssl_ctx);
  mbuf_free(&ctx->psk);
  memset(ctx, 0, sizeof(*ctx));
  MG_FREE(ctx);
}


static const char mg_s_cipher_list[] =  "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:" "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:" "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:" "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:" "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:" "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:" "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:" "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:" "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:" "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:" "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:" "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:" "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:" "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:" "ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:" "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:" "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:" "!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"  "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:" "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:" "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:" "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:" "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:" "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:" "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:" "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:" "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:" "DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:" "!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"  ;







































static const char mg_s_default_dh_params[] = " -----BEGIN DH PARAMETERS-----\n MIIBCAKCAQEAlvbgD/qh9znWIlGFcV0zdltD7rq8FeShIqIhkQ0C7hYFThrBvF2E\n Z9bmgaP+sfQwGpVlv9mtaWjvERbu6mEG7JTkgmVUJrUt/wiRzwTaCXBqZkdUO8Tq\n +E6VOEQAilstG90ikN1Tfo+K6+X68XkRUIlgawBTKuvKVwBhuvlqTGerOtnXWnrt\n ym//hd3cd5PBYGBix0i7oR4xdghvfR2WLVu0LgdThTBb6XP7gLd19cQ1JuBtAajZ\n wMuPn7qlUkEFDIkAZy59/Hue/H2Q2vU/JsvVhHWCQBL4F1ofEAt50il6ZxR1QfFK\n 9VGKDC4oOgm9DlxwwBoC2FjqmvQlqVV3kwIBAg==\n -----END DH PARAMETERS-----\n"          static enum mg_ssl_if_result mg_use_ca_cert(SSL_CTX *ctx, const char *cert) {










  if (cert == NULL || strcmp(cert, "*") == 0) {
    return MG_SSL_OK;
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
  return SSL_CTX_load_verify_locations(ctx, cert, NULL) == 1 ? MG_SSL_OK : MG_SSL_ERROR;
}

static enum mg_ssl_if_result mg_use_cert(SSL_CTX *ctx, const char *cert, const char *key, const char **err_msg) {

  if (key == NULL) key = cert;
  if (cert == NULL || cert[0] == '\0' || key == NULL || key[0] == '\0') {
    return MG_SSL_OK;
  } else if (SSL_CTX_use_certificate_file(ctx, cert, 1) == 0) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL cert");
    return MG_SSL_ERROR;
  } else if (SSL_CTX_use_PrivateKey_file(ctx, key, 1) == 0) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL key");
    return MG_SSL_ERROR;
  } else if (SSL_CTX_use_certificate_chain_file(ctx, cert) == 0) {
    MG_SET_PTRPTR(err_msg, "Invalid CA bundle");
    return MG_SSL_ERROR;
  } else {
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    BIO *bio = NULL;
    DH *dh = NULL;

    
    bio = BIO_new_file(cert, "r");
    if (bio != NULL) {
      dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
    
    if (dh == NULL) {
      bio = BIO_new_mem_buf((void *) mg_s_default_dh_params, -1);
      dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
    if (dh != NULL) {
      SSL_CTX_set_tmp_dh(ctx, dh);
      SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
      DH_free(dh);
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);


  }
  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_set_cipher_list(SSL_CTX *ctx, const char *cl) {
  return (SSL_CTX_set_cipher_list(ctx, cl ? cl : mg_s_cipher_list) == 1 ? MG_SSL_OK : MG_SSL_ERROR);

}


static unsigned int mg_ssl_if_ossl_psk_cb(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len) {



  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
  size_t key_len = ctx->psk.len - ctx->identity_len - 1;
  DBG(("hint: '%s'", (hint ? hint : "")));
  if (ctx->identity_len + 1 > max_identity_len) {
    DBG(("identity too long"));
    return 0;
  }
  if (key_len > max_psk_len) {
    DBG(("key too long"));
    return 0;
  }
  memcpy(identity, ctx->psk.buf, ctx->identity_len + 1);
  memcpy(psk, ctx->psk.buf + ctx->identity_len + 1, key_len);
  (void) ssl;
  return key_len;
}

static enum mg_ssl_if_result mg_ssl_if_ossl_set_psk(struct mg_ssl_if_ctx *ctx, const char *identity, const char *key_str) {

  unsigned char key[32];
  size_t key_len;
  size_t i = 0;
  if (identity == NULL && key_str == NULL) return MG_SSL_OK;
  if (identity == NULL || key_str == NULL) return MG_SSL_ERROR;
  key_len = strlen(key_str);
  if (key_len != 32 && key_len != 64) return MG_SSL_ERROR;
  memset(key, 0, sizeof(key));
  key_len = 0;
  for (i = 0; key_str[i] != '\0'; i++) {
    unsigned char c;
    char hc = tolower((int) key_str[i]);
    if (hc >= '0' && hc <= '9') {
      c = hc - '0';
    } else if (hc >= 'a' && hc <= 'f') {
      c = hc - 'a' + 0xa;
    } else {
      return MG_SSL_ERROR;
    }
    key_len = i / 2;
    key[key_len] <<= 4;
    key[key_len] |= c;
  }
  key_len++;
  DBG(("identity = '%s', key = (%u)", identity, (unsigned int) key_len));
  ctx->identity_len = strlen(identity);
  mbuf_append(&ctx->psk, identity, ctx->identity_len + 1);
  mbuf_append(&ctx->psk, key, key_len);
  SSL_CTX_set_psk_client_callback(ctx->ssl_ctx, mg_ssl_if_ossl_psk_cb);
  SSL_CTX_set_app_data(ctx->ssl_ctx, ctx);
  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_ssl_if_ossl_set_psk(struct mg_ssl_if_ctx *ctx, const char *identity, const char *key_str) {

  (void) ctx;
  (void) identity;
  (void) key_str;
  
  return MG_SSL_ERROR;
}


const char *mg_set_ssl(struct mg_connection *nc, const char *cert, const char *ca_cert) {
  const char *err_msg = NULL;
  struct mg_ssl_if_conn_params params;
  memset(&params, 0, sizeof(params));
  params.cert = cert;
  params.ca_cert = ca_cert;
  if (mg_ssl_if_conn_init(nc, &params, &err_msg) != MG_SSL_OK) {
    return err_msg;
  }
  return NULL;
}


















static void mg_ssl_mbed_log(void *ctx, int level, const char *file, int line, const char *str) {
  enum cs_log_level cs_level;
  switch (level) {
    case 1:
      cs_level = LL_ERROR;
      break;
    case 2:
      cs_level = LL_INFO;
      break;
    case 3:
      cs_level = LL_DEBUG;
      break;
    default:
      cs_level = LL_VERBOSE_DEBUG;
  }
  
  LOG(cs_level, ("%p %.*s", ctx, (int) (strlen(str) - 1), str));
  (void) file;
  (void) line;
  (void) cs_level;
}

struct mg_ssl_if_ctx {
  mbedtls_ssl_config *conf;
  mbedtls_ssl_context *ssl;
  mbedtls_x509_crt *cert;
  mbedtls_pk_context *key;
  mbedtls_x509_crt *ca_cert;
  struct mbuf cipher_suites;
  size_t saved_len;
};


extern int mg_ssl_if_mbed_random(void *ctx, unsigned char *buf, size_t len);

void mg_ssl_if_init() {
  LOG(LL_INFO, ("%s", MBEDTLS_VERSION_STRING_FULL));
}

enum mg_ssl_if_result mg_ssl_if_conn_accept(struct mg_connection *nc, struct mg_connection *lc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) MG_CALLOC(1, sizeof(*ctx));
  struct mg_ssl_if_ctx *lc_ctx = (struct mg_ssl_if_ctx *) lc->ssl_if_data;
  nc->ssl_if_data = ctx;
  if (ctx == NULL || lc_ctx == NULL) return MG_SSL_ERROR;
  ctx->ssl = (mbedtls_ssl_context *) MG_CALLOC(1, sizeof(*ctx->ssl));
  if (mbedtls_ssl_setup(ctx->ssl, lc_ctx->conf) != 0) {
    return MG_SSL_ERROR;
  }
  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_use_cert(struct mg_ssl_if_ctx *ctx, const char *cert, const char *key, const char **err_msg);

static enum mg_ssl_if_result mg_use_ca_cert(struct mg_ssl_if_ctx *ctx, const char *cert);
static enum mg_ssl_if_result mg_set_cipher_list(struct mg_ssl_if_ctx *ctx, const char *ciphers);

static enum mg_ssl_if_result mg_ssl_if_mbed_set_psk(struct mg_ssl_if_ctx *ctx, const char *identity, const char *key);



enum mg_ssl_if_result mg_ssl_if_conn_init( struct mg_connection *nc, const struct mg_ssl_if_conn_params *params, const char **err_msg) {

  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) MG_CALLOC(1, sizeof(*ctx));
  DBG(("%p %s,%s,%s", nc, (params->cert ? params->cert : ""), (params->key ? params->key : ""), (params->ca_cert ? params->ca_cert : "")));


  if (ctx == NULL) {
    MG_SET_PTRPTR(err_msg, "Out of memory");
    return MG_SSL_ERROR;
  }
  nc->ssl_if_data = ctx;
  ctx->conf = (mbedtls_ssl_config *) MG_CALLOC(1, sizeof(*ctx->conf));
  mbuf_init(&ctx->cipher_suites, 0);
  mbedtls_ssl_config_init(ctx->conf);
  mbedtls_ssl_conf_dbg(ctx->conf, mg_ssl_mbed_log, nc);
  if (mbedtls_ssl_config_defaults( ctx->conf, (nc->flags & MG_F_LISTENING ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT), MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {


    MG_SET_PTRPTR(err_msg, "Failed to init SSL config");
    return MG_SSL_ERROR;
  }

  
  mbedtls_ssl_conf_min_version(ctx->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_rng(ctx->conf, mg_ssl_if_mbed_random, nc);

  if (params->cert != NULL && mg_use_cert(ctx, params->cert, params->key, err_msg) != MG_SSL_OK) {
    return MG_SSL_ERROR;
  }

  if (params->ca_cert != NULL && mg_use_ca_cert(ctx, params->ca_cert) != MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL CA cert");
    return MG_SSL_ERROR;
  }

  if (mg_set_cipher_list(ctx, params->cipher_suites) != MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid cipher suite list");
    return MG_SSL_ERROR;
  }


  if (mg_ssl_if_mbed_set_psk(ctx, params->psk_identity, params->psk_key) != MG_SSL_OK) {
    MG_SET_PTRPTR(err_msg, "Invalid PSK settings");
    return MG_SSL_ERROR;
  }


  if (!(nc->flags & MG_F_LISTENING)) {
    ctx->ssl = (mbedtls_ssl_context *) MG_CALLOC(1, sizeof(*ctx->ssl));
    mbedtls_ssl_init(ctx->ssl);
    if (mbedtls_ssl_setup(ctx->ssl, ctx->conf) != 0) {
      MG_SET_PTRPTR(err_msg, "Failed to create SSL session");
      return MG_SSL_ERROR;
    }
    if (params->server_name != NULL && mbedtls_ssl_set_hostname(ctx->ssl, params->server_name) != 0) {
      return MG_SSL_ERROR;
    }
  }


  if (mbedtls_ssl_conf_max_frag_len(ctx->conf,  MBEDTLS_SSL_MAX_FRAG_LEN_512  MBEDTLS_SSL_MAX_FRAG_LEN_1024  MBEDTLS_SSL_MAX_FRAG_LEN_2048  MBEDTLS_SSL_MAX_FRAG_LEN_4096    ) != 0) {











    return MG_SSL_ERROR;
  }


  nc->flags |= MG_F_SSL;

  return MG_SSL_OK;
}

static int mg_ssl_if_mbed_send(void *ctx, const unsigned char *buf, size_t len) {
  struct mg_connection *nc = (struct mg_connection *) ctx;
  int n = nc->iface->vtable->tcp_send(nc, buf, len);
  if (n > 0) return n;
  if (n == 0) return MBEDTLS_ERR_SSL_WANT_WRITE;
  return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int mg_ssl_if_mbed_recv(void *ctx, unsigned char *buf, size_t len) {
  struct mg_connection *nc = (struct mg_connection *) ctx;
  int n = nc->iface->vtable->tcp_recv(nc, buf, len);
  if (n > 0) return n;
  if (n == 0) return MBEDTLS_ERR_SSL_WANT_READ;
  return MBEDTLS_ERR_NET_RECV_FAILED;
}

static enum mg_ssl_if_result mg_ssl_if_mbed_err(struct mg_connection *nc, int ret) {
  enum mg_ssl_if_result res = MG_SSL_OK;
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
    res = MG_SSL_WANT_READ;
  } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    res = MG_SSL_WANT_WRITE;
  } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
    LOG(LL_DEBUG, ("%p TLS connection closed by peer", nc));
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    res = MG_SSL_OK;
  } else {
    LOG(LL_ERROR, ("%p mbedTLS error: -0x%04x", nc, -ret));
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    res = MG_SSL_ERROR;
  }
  nc->err = ret;
  return res;
}

static void mg_ssl_if_mbed_free_certs_and_keys(struct mg_ssl_if_ctx *ctx) {
  if (ctx->cert != NULL) {
    mbedtls_x509_crt_free(ctx->cert);
    MG_FREE(ctx->cert);
    ctx->cert = NULL;
    mbedtls_pk_free(ctx->key);
    MG_FREE(ctx->key);
    ctx->key = NULL;
  }
  if (ctx->ca_cert != NULL) {
    mbedtls_ssl_conf_ca_chain(ctx->conf, NULL, NULL);

    if (ctx->ca_cert->ca_chain_file != NULL) {
      MG_FREE((void *) ctx->ca_cert->ca_chain_file);
      ctx->ca_cert->ca_chain_file = NULL;
    }

    mbedtls_x509_crt_free(ctx->ca_cert);
    MG_FREE(ctx->ca_cert);
    ctx->ca_cert = NULL;
  }
}

enum mg_ssl_if_result mg_ssl_if_handshake(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  int err;
  
  if (ctx->ssl->p_bio == NULL) {
    mbedtls_ssl_set_bio(ctx->ssl, nc, mg_ssl_if_mbed_send, mg_ssl_if_mbed_recv, NULL);
  }
  err = mbedtls_ssl_handshake(ctx->ssl);
  if (err != 0) return mg_ssl_if_mbed_err(nc, err);

  
  mbedtls_x509_crt_free(ctx->ssl->session->peer_cert);
  mbedtls_free(ctx->ssl->session->peer_cert);
  ctx->ssl->session->peer_cert = NULL;
  
  if (nc->listener == NULL) {
    if (ctx->conf->key_cert != NULL) {
      
      MG_FREE(ctx->conf->key_cert);
      ctx->conf->key_cert = NULL;
    }
    mbedtls_ssl_conf_ca_chain(ctx->conf, NULL, NULL);
    mg_ssl_if_mbed_free_certs_and_keys(ctx);
  }

  return MG_SSL_OK;
}

int mg_ssl_if_read(struct mg_connection *nc, void *buf, size_t len) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  int n = mbedtls_ssl_read(ctx->ssl, (unsigned char *) buf, len);
  DBG(("%p %d -> %d", nc, (int) len, n));
  if (n < 0) return mg_ssl_if_mbed_err(nc, n);
  if (n == 0) nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  return n;
}

int mg_ssl_if_write(struct mg_connection *nc, const void *buf, size_t len) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  
  size_t l = len;
  if (ctx->saved_len > 0 && ctx->saved_len < l) l = ctx->saved_len;
  int n = mbedtls_ssl_write(ctx->ssl, (const unsigned char *) buf, l);
  DBG(("%p %d,%d,%d -> %d", nc, (int) len, (int) ctx->saved_len, (int) l, n));
  if (n < 0) {
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
      ctx->saved_len = len;
    }
    return mg_ssl_if_mbed_err(nc, n);
  } else if (n > 0) {
    ctx->saved_len = 0;
  }
  return n;
}

void mg_ssl_if_conn_close_notify(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  if (ctx == NULL) return;
  mbedtls_ssl_close_notify(ctx->ssl);
}

void mg_ssl_if_conn_free(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  if (ctx == NULL) return;
  nc->ssl_if_data = NULL;
  if (ctx->ssl != NULL) {
    mbedtls_ssl_free(ctx->ssl);
    MG_FREE(ctx->ssl);
  }
  mg_ssl_if_mbed_free_certs_and_keys(ctx);
  if (ctx->conf != NULL) {
    mbedtls_ssl_config_free(ctx->conf);
    MG_FREE(ctx->conf);
  }
  mbuf_free(&ctx->cipher_suites);
  memset(ctx, 0, sizeof(*ctx));
  MG_FREE(ctx);
}

static enum mg_ssl_if_result mg_use_ca_cert(struct mg_ssl_if_ctx *ctx, const char *ca_cert) {
  if (ca_cert == NULL || strcmp(ca_cert, "*") == 0) {
    mbedtls_ssl_conf_authmode(ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
    return MG_SSL_OK;
  }
  ctx->ca_cert = (mbedtls_x509_crt *) MG_CALLOC(1, sizeof(*ctx->ca_cert));
  mbedtls_x509_crt_init(ctx->ca_cert);

  ca_cert = strdup(ca_cert);
  if (mbedtls_x509_crt_set_ca_chain_file(ctx->ca_cert, ca_cert) != 0) {
    return MG_SSL_ERROR;
  }

  if (mbedtls_x509_crt_parse_file(ctx->ca_cert, ca_cert) != 0) {
    return MG_SSL_ERROR;
  }

  mbedtls_ssl_conf_ca_chain(ctx->conf, ctx->ca_cert, NULL);
  mbedtls_ssl_conf_authmode(ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  return MG_SSL_OK;
}

static enum mg_ssl_if_result mg_use_cert(struct mg_ssl_if_ctx *ctx, const char *cert, const char *key, const char **err_msg) {

  if (key == NULL) key = cert;
  if (cert == NULL || cert[0] == '\0' || key == NULL || key[0] == '\0') {
    return MG_SSL_OK;
  }
  ctx->cert = (mbedtls_x509_crt *) MG_CALLOC(1, sizeof(*ctx->cert));
  mbedtls_x509_crt_init(ctx->cert);
  ctx->key = (mbedtls_pk_context *) MG_CALLOC(1, sizeof(*ctx->key));
  mbedtls_pk_init(ctx->key);
  if (mbedtls_x509_crt_parse_file(ctx->cert, cert) != 0) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL cert");
    return MG_SSL_ERROR;
  }
  if (mbedtls_pk_parse_keyfile(ctx->key, key, NULL) != 0) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL key");
    return MG_SSL_ERROR;
  }
  if (mbedtls_ssl_conf_own_cert(ctx->conf, ctx->cert, ctx->key) != 0) {
    MG_SET_PTRPTR(err_msg, "Invalid SSL key or cert");
    return MG_SSL_ERROR;
  }
  return MG_SSL_OK;
}

static const int mg_s_cipher_list[] = {

    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,   MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,  0, };

































static enum mg_ssl_if_result mg_set_cipher_list(struct mg_ssl_if_ctx *ctx, const char *ciphers) {
  if (ciphers != NULL) {
    int l, id;
    const char *s = ciphers, *e;
    char tmp[50];
    while (s != NULL) {
      e = strchr(s, ':');
      l = (e != NULL ? (e - s) : (int) strlen(s));
      strncpy(tmp, s, l);
      tmp[l] = '\0';
      id = mbedtls_ssl_get_ciphersuite_id(tmp);
      DBG(("%s -> %04x", tmp, id));
      if (id != 0) {
        mbuf_append(&ctx->cipher_suites, &id, sizeof(id));
      }
      s = (e != NULL ? e + 1 : NULL);
    }
    if (ctx->cipher_suites.len == 0) return MG_SSL_ERROR;
    id = 0;
    mbuf_append(&ctx->cipher_suites, &id, sizeof(id));
    mbuf_trim(&ctx->cipher_suites);
    mbedtls_ssl_conf_ciphersuites(ctx->conf, (const int *) ctx->cipher_suites.buf);
  } else {
    mbedtls_ssl_conf_ciphersuites(ctx->conf, mg_s_cipher_list);
  }
  return MG_SSL_OK;
}


static enum mg_ssl_if_result mg_ssl_if_mbed_set_psk(struct mg_ssl_if_ctx *ctx, const char *identity, const char *key_str) {

  unsigned char key[32];
  size_t key_len;
  if (identity == NULL && key_str == NULL) return MG_SSL_OK;
  if (identity == NULL || key_str == NULL) return MG_SSL_ERROR;
  key_len = strlen(key_str);
  if (key_len != 32 && key_len != 64) return MG_SSL_ERROR;
  size_t i = 0;
  memset(key, 0, sizeof(key));
  key_len = 0;
  for (i = 0; key_str[i] != '\0'; i++) {
    unsigned char c;
    char hc = tolower((int) key_str[i]);
    if (hc >= '0' && hc <= '9') {
      c = hc - '0';
    } else if (hc >= 'a' && hc <= 'f') {
      c = hc - 'a' + 0xa;
    } else {
      return MG_SSL_ERROR;
    }
    key_len = i / 2;
    key[key_len] <<= 4;
    key[key_len] |= c;
  }
  key_len++;
  DBG(("identity = '%s', key = (%u)", identity, (unsigned int) key_len));
  
  if (mbedtls_ssl_conf_psk(ctx->conf, (const unsigned char *) key, key_len, (const unsigned char *) identity, strlen(identity)) != 0) {

    return MG_SSL_ERROR;
  }
  return MG_SSL_OK;
}


const char *mg_set_ssl(struct mg_connection *nc, const char *cert, const char *ca_cert) {
  const char *err_msg = NULL;
  struct mg_ssl_if_conn_params params;
  memset(&params, 0, sizeof(params));
  params.cert = cert;
  params.ca_cert = ca_cert;
  if (mg_ssl_if_conn_init(nc, &params, &err_msg) != MG_SSL_OK) {
    return err_msg;
  }
  return NULL;
}



int mg_ssl_if_mbed_random(void *ctx, unsigned char *buf, size_t len) {
  (void) ctx;
  while (len--) *buf++ = rand();
  return 0;
}












static void parse_uri_component(const char **p, const char *end, const char *seps, struct mg_str *res) {
  const char *q;
  res->p = *p;
  for (; *p < end; (*p)++) {
    for (q = seps; *q != '\0'; q++) {
      if (**p == *q) break;
    }
    if (*q != '\0') break;
  }
  res->len = (*p) - res->p;
  if (*p < end) (*p)++;
}

int mg_parse_uri(const struct mg_str uri, struct mg_str *scheme, struct mg_str *user_info, struct mg_str *host, unsigned int *port, struct mg_str *path, struct mg_str *query, struct mg_str *fragment) {


  struct mg_str rscheme = {0, 0}, ruser_info = {0, 0}, rhost = {0, 0}, rpath = {0, 0}, rquery = {0, 0}, rfragment = {0, 0};
  unsigned int rport = 0;
  enum {
    P_START, P_SCHEME_OR_PORT, P_USER_INFO, P_HOST, P_PORT, P_REST } state = P_START;






  const char *p = uri.p, *end = p + uri.len;
  while (p < end) {
    switch (state) {
      case P_START:
        
        if (*p == '[') {
          state = P_HOST;
          break;
        }
        for (; p < end; p++) {
          if (*p == ':') {
            state = P_SCHEME_OR_PORT;
            break;
          } else if (*p == '/') {
            state = P_REST;
            break;
          }
        }
        if (state == P_START || state == P_REST) {
          rhost.p = uri.p;
          rhost.len = p - uri.p;
        }
        break;
      case P_SCHEME_OR_PORT:
        if (end - p >= 3 && strncmp(p, "://", 3) == 0) {
          rscheme.p = uri.p;
          rscheme.len = p - uri.p;
          state = P_USER_INFO;
          p += 3;
        } else {
          rhost.p = uri.p;
          rhost.len = p - uri.p;
          state = P_PORT;
        }
        break;
      case P_USER_INFO:
        ruser_info.p = p;
        for (; p < end; p++) {
          if (*p == '@' || *p == '[' || *p == '/') {
            break;
          }
        }
        if (p == end || *p == '/' || *p == '[') {
          
          p = ruser_info.p;
        }
        ruser_info.len = p - ruser_info.p;
        state = P_HOST;
        break;
      case P_HOST:
        if (*p == '@') p++;
        rhost.p = p;
        if (*p == '[') {
          int found = 0;
          for (; !found && p < end; p++) {
            found = (*p == ']');
          }
          if (!found) return -1;
        } else {
          for (; p < end; p++) {
            if (*p == ':' || *p == '/') break;
          }
        }
        rhost.len = p - rhost.p;
        if (p < end) {
          if (*p == ':') {
            state = P_PORT;
            break;
          } else if (*p == '/') {
            state = P_REST;
            break;
          }
        }
        break;
      case P_PORT:
        p++;
        for (; p < end; p++) {
          if (*p == '/') {
            state = P_REST;
            break;
          }
          rport *= 10;
          rport += *p - '0';
        }
        break;
      case P_REST:
        
        parse_uri_component(&p, end, "?#", &rpath);
        if (p < end && *(p - 1) == '?') {
          parse_uri_component(&p, end, "#", &rquery);
        }
        parse_uri_component(&p, end, "", &rfragment);
        break;
    }
  }

  if (scheme != 0) *scheme = rscheme;
  if (user_info != 0) *user_info = ruser_info;
  if (host != 0) *host = rhost;
  if (port != 0) *port = rport;
  if (path != 0) *path = rpath;
  if (query != 0) *query = rquery;
  if (fragment != 0) *fragment = rfragment;

  return 0;
}


int mg_normalize_uri_path(const struct mg_str *in, struct mg_str *out) {
  const char *s = in->p, *se = s + in->len;
  char *cp = (char *) out->p, *d;

  if (in->len == 0 || *s != '/') {
    out->len = 0;
    return 0;
  }

  d = cp;

  while (s < se) {
    const char *next = s;
    struct mg_str component;
    parse_uri_component(&next, se, "/", &component);
    if (mg_vcmp(&component, ".") == 0) {
      
    } else if (mg_vcmp(&component, "..") == 0) {
      
      if (d > cp + 1 && *(d - 1) == '/') d--;
      while (d > cp && *(d - 1) != '/') d--;
    } else {
      memmove(d, s, next - s);
      d += next - s;
    }
    s = next;
  }
  if (d == cp) *d++ = '/';

  out->p = cp;
  out->len = d - cp;
  return 1;
}

int mg_assemble_uri(const struct mg_str *scheme, const struct mg_str *user_info, const struct mg_str *host, unsigned int port, const struct mg_str *path, const struct mg_str *query, const struct mg_str *fragment, int normalize_path, struct mg_str *uri) {



  int result = -1;
  struct mbuf out;
  mbuf_init(&out, 0);

  if (scheme != NULL && scheme->len > 0) {
    mbuf_append(&out, scheme->p, scheme->len);
    mbuf_append(&out, "://", 3);
  }

  if (user_info != NULL && user_info->len > 0) {
    mbuf_append(&out, user_info->p, user_info->len);
    mbuf_append(&out, "@", 1);
  }

  if (host != NULL && host->len > 0) {
    mbuf_append(&out, host->p, host->len);
  }

  if (port != 0) {
    char port_str[20];
    int port_str_len = sprintf(port_str, ":%u", port);
    mbuf_append(&out, port_str, port_str_len);
  }

  if (path != NULL && path->len > 0) {
    if (normalize_path) {
      struct mg_str npath = mg_strdup(*path);
      if (npath.len != path->len) goto out;
      if (!mg_normalize_uri_path(path, &npath)) {
        free((void *) npath.p);
        goto out;
      }
      mbuf_append(&out, npath.p, npath.len);
      free((void *) npath.p);
    } else {
      mbuf_append(&out, path->p, path->len);
    }
  } else if (normalize_path) {
    mbuf_append(&out, "/", 1);
  }

  if (query != NULL && query->len > 0) {
    mbuf_append(&out, "?", 1);
    mbuf_append(&out, query->p, query->len);
  }

  if (fragment != NULL && fragment->len > 0) {
    mbuf_append(&out, "#", 1);
    mbuf_append(&out, fragment->p, fragment->len);
  }

  result = 0;

out:
  if (result == 0) {
    uri->p = out.buf;
    uri->len = out.len;
  } else {
    mbuf_free(&out);
    uri->p = NULL;
    uri->len = 0;
  }
  return result;
}














struct altbuf {
  struct mbuf m;
  char *user_buf;
  size_t len;
  size_t user_buf_size;
};


MG_INTERNAL void altbuf_init(struct altbuf *ab, char *buf, size_t buf_size) {
  mbuf_init(&ab->m, 0);
  ab->user_buf = buf;
  ab->user_buf_size = buf_size;
  ab->len = 0;
}


MG_INTERNAL void altbuf_append(struct altbuf *ab, char c) {
  if (ab->len < ab->user_buf_size) {
    
    ab->user_buf[ab->len++] = c;
  } else {
    

    
    if (ab->len > 0 && ab->m.len == 0) {
      mbuf_append(&ab->m, ab->user_buf, ab->len);
    }

    mbuf_append(&ab->m, &c, 1);
    ab->len = ab->m.len;
  }
}


MG_INTERNAL void altbuf_reset(struct altbuf *ab) {
  mbuf_free(&ab->m);
  ab->len = 0;
}


MG_INTERNAL int altbuf_reallocated(struct altbuf *ab) {
  return ab->len > ab->user_buf_size;
}


MG_INTERNAL char *altbuf_get_buf(struct altbuf *ab, int trim) {
  if (altbuf_reallocated(ab)) {
    if (trim) {
      mbuf_trim(&ab->m);
    }
    return ab->m.buf;
  } else {
    return ab->user_buf;
  }
}



static const char *mg_version_header = "Mongoose/" MG_VERSION;

enum mg_http_proto_data_type { DATA_NONE, DATA_FILE, DATA_PUT };

struct mg_http_proto_data_file {
  FILE *fp;      
  int64_t cl;    
  int64_t sent;  
  int keepalive; 
  enum mg_http_proto_data_type type;
};


struct mg_http_proto_data_cgi {
  struct mg_connection *cgi_nc;
};


struct mg_http_proto_data_chuncked {
  int64_t body_len; 
};

struct mg_http_endpoint {
  struct mg_http_endpoint *next;
  struct mg_str uri_pattern; 
  char *auth_domain;         
  char *auth_file;           

  mg_event_handler_t handler;

  void *user_data;

};

enum mg_http_multipart_stream_state {
  MPS_BEGIN, MPS_WAITING_FOR_BOUNDARY, MPS_WAITING_FOR_CHUNK, MPS_GOT_BOUNDARY, MPS_FINALIZE, MPS_FINISHED };






struct mg_http_multipart_stream {
  const char *boundary;
  int boundary_len;
  const char *var_name;
  const char *file_name;
  void *user_data;
  enum mg_http_multipart_stream_state state;
  int processing_part;
};

struct mg_reverse_proxy_data {
  struct mg_connection *linked_conn;
};

struct mg_ws_proto_data {
  
  size_t reass_len;
};

struct mg_http_proto_data {

  struct mg_http_proto_data_file file;


  struct mg_http_proto_data_cgi cgi;


  struct mg_http_multipart_stream mp_stream;


  struct mg_ws_proto_data ws_data;

  struct mg_http_proto_data_chuncked chunk;
  struct mg_http_endpoint *endpoints;
  mg_event_handler_t endpoint_handler;
  struct mg_reverse_proxy_data reverse_proxy_data;
  size_t rcvd; 
};

static void mg_http_conn_destructor(void *proto_data);
struct mg_connection *mg_connect_http_base( struct mg_mgr *mgr, MG_CB(mg_event_handler_t ev_handler, void *user_data), struct mg_connect_opts opts, const char *scheme1, const char *scheme2, const char *scheme_ssl1, const char *scheme_ssl2, const char *url, struct mg_str *path, struct mg_str *user_info, struct mg_str *host);




static struct mg_http_proto_data *mg_http_get_proto_data( struct mg_connection *c) {
  if (c->proto_data == NULL) {
    c->proto_data = MG_CALLOC(1, sizeof(struct mg_http_proto_data));
    c->proto_data_destructor = mg_http_conn_destructor;
  }

  return (struct mg_http_proto_data *) c->proto_data;
}


static void mg_http_free_proto_data_mp_stream( struct mg_http_multipart_stream *mp) {
  MG_FREE((void *) mp->boundary);
  MG_FREE((void *) mp->var_name);
  MG_FREE((void *) mp->file_name);
  memset(mp, 0, sizeof(*mp));
}



static void mg_http_free_proto_data_file(struct mg_http_proto_data_file *d) {
  if (d != NULL) {
    if (d->fp != NULL) {
      fclose(d->fp);
    }
    memset(d, 0, sizeof(struct mg_http_proto_data_file));
  }
}


static void mg_http_free_proto_data_endpoints(struct mg_http_endpoint **ep) {
  struct mg_http_endpoint *current = *ep;

  while (current != NULL) {
    struct mg_http_endpoint *tmp = current->next;
    MG_FREE((void *) current->uri_pattern.p);
    MG_FREE((void *) current->auth_domain);
    MG_FREE((void *) current->auth_file);
    MG_FREE(current);
    current = tmp;
  }

  ep = NULL;
}

static void mg_http_free_reverse_proxy_data(struct mg_reverse_proxy_data *rpd) {
  if (rpd->linked_conn != NULL) {
    
    struct mg_http_proto_data *pd = mg_http_get_proto_data(rpd->linked_conn);
    if (pd->reverse_proxy_data.linked_conn != NULL) {
      pd->reverse_proxy_data.linked_conn->flags |= MG_F_SEND_AND_CLOSE;
      pd->reverse_proxy_data.linked_conn = NULL;
    }
    rpd->linked_conn = NULL;
  }
}

static void mg_http_conn_destructor(void *proto_data) {
  struct mg_http_proto_data *pd = (struct mg_http_proto_data *) proto_data;

  mg_http_free_proto_data_file(&pd->file);


  mg_http_free_proto_data_cgi(&pd->cgi);


  mg_http_free_proto_data_mp_stream(&pd->mp_stream);

  mg_http_free_proto_data_endpoints(&pd->endpoints);
  mg_http_free_reverse_proxy_data(&pd->reverse_proxy_data);
  MG_FREE(proto_data);
}




static const struct {
  const char *extension;
  size_t ext_len;
  const char *mime_type;
} mg_static_builtin_mime_types[] = {
    MIME_ENTRY("html", "text/html"), MIME_ENTRY("html", "text/html"), MIME_ENTRY("htm", "text/html"), MIME_ENTRY("shtm", "text/html"), MIME_ENTRY("shtml", "text/html"), MIME_ENTRY("css", "text/css"), MIME_ENTRY("js", "application/x-javascript"), MIME_ENTRY("ico", "image/x-icon"), MIME_ENTRY("gif", "image/gif"), MIME_ENTRY("jpg", "image/jpeg"), MIME_ENTRY("jpeg", "image/jpeg"), MIME_ENTRY("png", "image/png"), MIME_ENTRY("svg", "image/svg+xml"), MIME_ENTRY("txt", "text/plain"), MIME_ENTRY("torrent", "application/x-bittorrent"), MIME_ENTRY("wav", "audio/x-wav"), MIME_ENTRY("mp3", "audio/x-mp3"), MIME_ENTRY("mid", "audio/mid"), MIME_ENTRY("m3u", "audio/x-mpegurl"), MIME_ENTRY("ogg", "application/ogg"), MIME_ENTRY("ram", "audio/x-pn-realaudio"), MIME_ENTRY("xml", "text/xml"), MIME_ENTRY("ttf", "application/x-font-ttf"), MIME_ENTRY("json", "application/json"), MIME_ENTRY("xslt", "application/xml"), MIME_ENTRY("xsl", "application/xml"), MIME_ENTRY("ra", "audio/x-pn-realaudio"), MIME_ENTRY("doc", "application/msword"), MIME_ENTRY("exe", "application/octet-stream"), MIME_ENTRY("zip", "application/x-zip-compressed"), MIME_ENTRY("xls", "application/excel"), MIME_ENTRY("tgz", "application/x-tar-gz"), MIME_ENTRY("tar", "application/x-tar"), MIME_ENTRY("gz", "application/x-gunzip"), MIME_ENTRY("arj", "application/x-arj-compressed"), MIME_ENTRY("rar", "application/x-rar-compressed"), MIME_ENTRY("rtf", "application/rtf"), MIME_ENTRY("pdf", "application/pdf"), MIME_ENTRY("swf", "application/x-shockwave-flash"), MIME_ENTRY("mpg", "video/mpeg"), MIME_ENTRY("webm", "video/webm"), MIME_ENTRY("mpeg", "video/mpeg"), MIME_ENTRY("mov", "video/quicktime"), MIME_ENTRY("mp4", "video/mp4"), MIME_ENTRY("m4v", "video/x-m4v"), MIME_ENTRY("asf", "video/x-ms-asf"), MIME_ENTRY("avi", "video/x-msvideo"), MIME_ENTRY("bmp", "image/bmp"), {NULL, 0, NULL}};
















































static struct mg_str mg_get_mime_type(const char *path, const char *dflt, const struct mg_serve_http_opts *opts) {
  const char *ext, *overrides;
  size_t i, path_len;
  struct mg_str r, k, v;

  path_len = strlen(path);

  overrides = opts->custom_mime_types;
  while ((overrides = mg_next_comma_list_entry(overrides, &k, &v)) != NULL) {
    ext = path + (path_len - k.len);
    if (path_len > k.len && mg_vcasecmp(&k, ext) == 0) {
      return v;
    }
  }

  for (i = 0; mg_static_builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - mg_static_builtin_mime_types[i].ext_len);
    if (path_len > mg_static_builtin_mime_types[i].ext_len && ext[-1] == '.' && mg_casecmp(ext, mg_static_builtin_mime_types[i].extension) == 0) {
      r.p = mg_static_builtin_mime_types[i].mime_type;
      r.len = strlen(r.p);
      return r;
    }
  }

  r.p = dflt;
  r.len = strlen(r.p);
  return r;
}



static int mg_http_get_request_len(const char *s, int buf_len) {
  const unsigned char *buf = (unsigned char *) s;
  int i;

  for (i = 0; i < buf_len; i++) {
    if (!isprint(buf[i]) && buf[i] != '\r' && buf[i] != '\n' && buf[i] < 128) {
      return -1;
    } else if (buf[i] == '\n' && i + 1 < buf_len && buf[i + 1] == '\n') {
      return i + 2;
    } else if (buf[i] == '\n' && i + 2 < buf_len && buf[i + 1] == '\r' && buf[i + 2] == '\n') {
      return i + 3;
    }
  }

  return 0;
}

static const char *mg_http_parse_headers(const char *s, const char *end, int len, struct http_message *req) {
  int i = 0;
  while (i < (int) ARRAY_SIZE(req->header_names) - 1) {
    struct mg_str *k = &req->header_names[i], *v = &req->header_values[i];

    s = mg_skip(s, end, ": ", k);
    s = mg_skip(s, end, "\r\n", v);

    while (v->len > 0 && v->p[v->len - 1] == ' ') {
      v->len--; 
    }

    
    if (k->len != 0 && v->len == 0) {
      continue;
    }

    if (k->len == 0 || v->len == 0) {
      k->p = v->p = NULL;
      k->len = v->len = 0;
      break;
    }

    if (!mg_ncasecmp(k->p, "Content-Length", 14)) {
      req->body.len = (size_t) to64(v->p);
      req->message.len = len + req->body.len;
    }

    i++;
  }

  return s;
}

int mg_parse_http(const char *s, int n, struct http_message *hm, int is_req) {
  const char *end, *qs;
  int len = mg_http_get_request_len(s, n);

  if (len <= 0) return len;

  memset(hm, 0, sizeof(*hm));
  hm->message.p = s;
  hm->body.p = s + len;
  hm->message.len = hm->body.len = (size_t) ~0;
  end = s + len;

  
  while (s < end && isspace(*(unsigned char *) s)) s++;

  if (is_req) {
    
    s = mg_skip(s, end, " ", &hm->method);
    s = mg_skip(s, end, " ", &hm->uri);
    s = mg_skip(s, end, "\r\n", &hm->proto);
    if (hm->uri.p <= hm->method.p || hm->proto.p <= hm->uri.p) return -1;

    
    if ((qs = (char *) memchr(hm->uri.p, '?', hm->uri.len)) != NULL) {
      hm->query_string.p = qs + 1;
      hm->query_string.len = &hm->uri.p[hm->uri.len] - (qs + 1);
      hm->uri.len = qs - hm->uri.p;
    }
  } else {
    s = mg_skip(s, end, " ", &hm->proto);
    if (end - s < 4 || s[3] != ' ') return -1;
    hm->resp_code = atoi(s);
    if (hm->resp_code < 100 || hm->resp_code >= 600) return -1;
    s += 4;
    s = mg_skip(s, end, "\r\n", &hm->resp_status_msg);
  }

  s = mg_http_parse_headers(s, end, len, hm);

  
  if (hm->body.len == (size_t) ~0 && is_req && mg_vcasecmp(&hm->method, "PUT") != 0 && mg_vcasecmp(&hm->method, "POST") != 0) {

    hm->body.len = 0;
    hm->message.len = len;
  }

  return len;
}

struct mg_str *mg_get_http_header(struct http_message *hm, const char *name) {
  size_t i, len = strlen(name);

  for (i = 0; hm->header_names[i].len > 0; i++) {
    struct mg_str *h = &hm->header_names[i], *v = &hm->header_values[i];
    if (h->p != NULL && h->len == len && !mg_ncasecmp(h->p, name, len))
      return v;
  }

  return NULL;
}


static void mg_http_transfer_file_data(struct mg_connection *nc) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  char buf[MG_MAX_HTTP_SEND_MBUF];
  size_t n = 0, to_read = 0, left = (size_t)(pd->file.cl - pd->file.sent);

  if (pd->file.type == DATA_FILE) {
    struct mbuf *io = &nc->send_mbuf;
    if (io->len >= MG_MAX_HTTP_SEND_MBUF) {
      to_read = 0;
    } else {
      to_read = MG_MAX_HTTP_SEND_MBUF - io->len;
    }
    if (to_read > left) {
      to_read = left;
    }
    if (to_read > 0) {
      n = mg_fread(buf, 1, to_read, pd->file.fp);
      if (n > 0) {
        mg_send(nc, buf, n);
        pd->file.sent += n;
        DBG(("%p sent %d (total %d)", nc, (int) n, (int) pd->file.sent));
      }
    } else {
      
    }
    if (pd->file.sent >= pd->file.cl) {
      LOG(LL_DEBUG, ("%p done, %d bytes", nc, (int) pd->file.sent));
      if (!pd->file.keepalive) nc->flags |= MG_F_SEND_AND_CLOSE;
      mg_http_free_proto_data_file(&pd->file);
    }
  } else if (pd->file.type == DATA_PUT) {
    struct mbuf *io = &nc->recv_mbuf;
    size_t to_write = left <= 0 ? 0 : left < io->len ? (size_t) left : io->len;
    size_t n = mg_fwrite(io->buf, 1, to_write, pd->file.fp);
    if (n > 0) {
      mbuf_remove(io, n);
      pd->file.sent += n;
    }
    if (n == 0 || pd->file.sent >= pd->file.cl) {
      if (!pd->file.keepalive) nc->flags |= MG_F_SEND_AND_CLOSE;
      mg_http_free_proto_data_file(&pd->file);
    }
  }

  else if (pd->cgi.cgi_nc != NULL) {
    
    if (pd->cgi.cgi_nc != NULL) {
      mg_forward(nc, pd->cgi.cgi_nc);
    } else {
      nc->flags |= MG_F_SEND_AND_CLOSE;
    }
  }

}



static size_t mg_http_parse_chunk(char *buf, size_t len, char **chunk_data, size_t *chunk_len) {
  unsigned char *s = (unsigned char *) buf;
  size_t n = 0; 
  size_t i = 0; 

  
  while (i < len && isxdigit(s[i])) {
    n *= 16;
    n += (s[i] >= '0' && s[i] <= '9') ? s[i] - '0' : tolower(s[i]) - 'a' + 10;
    i++;
  }

  
  if (i == 0 || i + 2 > len || s[i] != '\r' || s[i + 1] != '\n') {
    return 0;
  }
  i += 2;

  
  *chunk_data = (char *) s + i;
  *chunk_len = n;

  
  i += n;

  
  if (i == 0 || i + 2 > len || s[i] != '\r' || s[i + 1] != '\n') {
    return 0;
  }
  return i + 2;
}

MG_INTERNAL size_t mg_handle_chunked(struct mg_connection *nc, struct http_message *hm, char *buf, size_t blen) {

  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  char *data;
  size_t i, n, data_len, body_len, zero_chunk_received = 0;
  
  body_len = (size_t) pd->chunk.body_len;
  assert(blen >= body_len);

  
  for (i = body_len;
       (n = mg_http_parse_chunk(buf + i, blen - i, &data, &data_len)) > 0;
       i += n) {
    
    memmove(buf + body_len, data, data_len);
    body_len += data_len;
    hm->body.len = body_len;

    if (data_len == 0) {
      zero_chunk_received = 1;
      i += n;
      break;
    }
  }

  if (i > body_len) {
    
    assert(i <= blen);
    memmove(buf + body_len, buf + i, blen - i);
    memset(buf + body_len + blen - i, 0, i - body_len);
    nc->recv_mbuf.len -= i - body_len;
    pd->chunk.body_len = body_len;

    
    nc->flags &= ~MG_F_DELETE_CHUNK;
    mg_call(nc, nc->handler, nc->user_data, MG_EV_HTTP_CHUNK, hm);

    
    if (nc->flags & MG_F_DELETE_CHUNK) {
      memset(buf, 0, body_len);
      memmove(buf, buf + body_len, blen - i);
      nc->recv_mbuf.len -= body_len;
      hm->body.len = 0;
      pd->chunk.body_len = 0;
    }

    if (zero_chunk_received) {
      
      hm->message.len = (size_t) pd->chunk.body_len + blen - i + (hm->body.p - hm->message.p);
    }
  }

  return body_len;
}

struct mg_http_endpoint *mg_http_get_endpoint_handler(struct mg_connection *nc, struct mg_str *uri_path) {
  struct mg_http_proto_data *pd;
  struct mg_http_endpoint *ret = NULL;
  int matched, matched_max = 0;
  struct mg_http_endpoint *ep;

  if (nc == NULL) {
    return NULL;
  }

  pd = mg_http_get_proto_data(nc);

  ep = pd->endpoints;
  while (ep != NULL) {
    if ((matched = mg_match_prefix_n(ep->uri_pattern, *uri_path)) > 0) {
      if (matched > matched_max) {
        
        ret = ep;
        matched_max = matched;
      }
    }

    ep = ep->next;
  }

  return ret;
}


static void mg_http_multipart_continue(struct mg_connection *nc);

static void mg_http_multipart_begin(struct mg_connection *nc, struct http_message *hm, int req_len);



static void mg_http_call_endpoint_handler(struct mg_connection *nc, int ev, struct http_message *hm);

static void deliver_chunk(struct mg_connection *c, struct http_message *hm, int req_len) {
  
  hm->body.len = c->recv_mbuf.len - req_len;
  c->flags &= ~MG_F_DELETE_CHUNK;
  mg_call(c, c->handler, c->user_data, MG_EV_HTTP_CHUNK, hm);
  
  if (c->flags & MG_F_DELETE_CHUNK) c->recv_mbuf.len = req_len;
}



static void mg_http_handler2(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data), struct http_message *hm) __attribute__((noinline));


void mg_http_handler(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data)) {
  struct http_message hm;
  mg_http_handler2(nc, ev, ev_data MG_UD_ARG(user_data), &hm);
}

static void mg_http_handler2(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data), struct http_message *hm) {


void mg_http_handler(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data)) {
  struct http_message shm, *hm = &shm;

  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  struct mbuf *io = &nc->recv_mbuf;
  int req_len;
  const int is_req = (nc->listener != NULL);

  struct mg_str *vec;

  if (ev == MG_EV_CLOSE) {

    
    if (pd->cgi.cgi_nc != NULL) {
      pd->cgi.cgi_nc->user_data = NULL;
      pd->cgi.cgi_nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    }


    if (pd->mp_stream.boundary != NULL) {
      
      struct mg_http_multipart_part mp;
      memset(&mp, 0, sizeof(mp));
      mp.status = -1;
      mp.var_name = pd->mp_stream.var_name;
      mp.file_name = pd->mp_stream.file_name;
      mg_call(nc, (pd->endpoint_handler ? pd->endpoint_handler : nc->handler), nc->user_data, MG_EV_HTTP_PART_END, &mp);
      mp.var_name = NULL;
      mp.file_name = NULL;
      mg_call(nc, (pd->endpoint_handler ? pd->endpoint_handler : nc->handler), nc->user_data, MG_EV_HTTP_MULTIPART_REQUEST_END, &mp);
    } else  if (io->len > 0 && (req_len = mg_parse_http(io->buf, io->len, hm, is_req)) > 0) {


      
      int ev2 = is_req ? MG_EV_HTTP_REQUEST : MG_EV_HTTP_REPLY;
      hm->message.len = io->len;
      hm->body.len = io->buf + io->len - hm->body.p;
      deliver_chunk(nc, hm, req_len);
      mg_http_call_endpoint_handler(nc, ev2, hm);
    }
    pd->rcvd = 0;
  }


  if (pd->file.fp != NULL) {
    mg_http_transfer_file_data(nc);
  }


  mg_call(nc, nc->handler, nc->user_data, ev, ev_data);

  if (ev == MG_EV_RECV) {
    struct mg_str *s;
    pd->rcvd += *(int *) ev_data;


    if (pd->mp_stream.boundary != NULL) {
      mg_http_multipart_continue(nc);
      return;
    }


  again:
    req_len = mg_parse_http(io->buf, io->len, hm, is_req);

    if (req_len > 0 && (s = mg_get_http_header(hm, "Transfer-Encoding")) != NULL && mg_vcasecmp(s, "chunked") == 0) {

      mg_handle_chunked(nc, hm, io->buf + req_len, io->len - req_len);
    }


    if (req_len > 0 && (s = mg_get_http_header(hm, "Content-Type")) != NULL && s->len >= 9 && strncmp(s->p, "multipart", 9) == 0) {
      mg_http_multipart_begin(nc, hm, req_len);
      mg_http_multipart_continue(nc);
      return;
    }


    
    if ((req_len < 0 || (req_len == 0 && io->len >= MG_MAX_HTTP_REQUEST_SIZE))) {
      DBG(("invalid request"));
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    } else if (req_len == 0) {
      
    }

    else if (nc->listener == NULL && mg_get_http_header(hm, "Sec-WebSocket-Accept")) {
      
      
      mbuf_remove(io, req_len);
      nc->proto_handler = mg_ws_handler;
      nc->flags |= MG_F_IS_WEBSOCKET;
      mg_call(nc, nc->handler, nc->user_data, MG_EV_WEBSOCKET_HANDSHAKE_DONE, NULL);
      mg_ws_handler(nc, MG_EV_RECV, ev_data MG_UD_ARG(user_data));
    } else if (nc->listener != NULL && (vec = mg_get_http_header(hm, "Sec-WebSocket-Key")) != NULL) {
      struct mg_http_endpoint *ep;

      
      mbuf_remove(io, req_len);
      nc->proto_handler = mg_ws_handler;
      nc->flags |= MG_F_IS_WEBSOCKET;

      
      ep = mg_http_get_endpoint_handler(nc->listener, &hm->uri);
      if (ep != NULL) {
        nc->handler = ep->handler;

        nc->user_data = ep->user_data;

      }

      
      mg_call(nc, nc->handler, nc->user_data, MG_EV_WEBSOCKET_HANDSHAKE_REQUEST, hm);
      if (!(nc->flags & (MG_F_CLOSE_IMMEDIATELY | MG_F_SEND_AND_CLOSE))) {
        if (nc->send_mbuf.len == 0) {
          mg_ws_handshake(nc, vec, hm);
        }
        mg_call(nc, nc->handler, nc->user_data, MG_EV_WEBSOCKET_HANDSHAKE_DONE, NULL);
        mg_ws_handler(nc, MG_EV_RECV, ev_data MG_UD_ARG(user_data));
      }
    }

    else if (hm->message.len > pd->rcvd) {
      
      deliver_chunk(nc, hm, req_len);
      if (nc->recv_mbuf_limit > 0 && nc->recv_mbuf.len >= nc->recv_mbuf_limit) {
        LOG(LL_ERROR, ("%p recv buffer (%lu bytes) exceeds the limit " "%lu bytes, and not drained, closing", nc, (unsigned long) nc->recv_mbuf.len, (unsigned long) nc->recv_mbuf_limit));


        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      }
    } else {
      
      int trigger_ev = nc->listener ? MG_EV_HTTP_REQUEST : MG_EV_HTTP_REPLY;
      char addr[32];
      mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
      DBG(("%p %s %.*s %.*s", nc, addr, (int) hm->method.len, hm->method.p, (int) hm->uri.len, hm->uri.p));
      deliver_chunk(nc, hm, req_len);
      
      mg_http_call_endpoint_handler(nc, trigger_ev, hm);
      mbuf_remove(io, hm->message.len);
      pd->rcvd -= hm->message.len;
      if (io->len > 0) {
        goto again;
      }
    }
  }
}

static size_t mg_get_line_len(const char *buf, size_t buf_len) {
  size_t len = 0;
  while (len < buf_len && buf[len] != '\n') len++;
  return len == buf_len ? 0 : len + 1;
}


static void mg_http_multipart_begin(struct mg_connection *nc, struct http_message *hm, int req_len) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  struct mg_str *ct;
  struct mbuf *io = &nc->recv_mbuf;

  char boundary_buf[100];
  char *boundary = boundary_buf;
  int boundary_len;

  ct = mg_get_http_header(hm, "Content-Type");
  if (ct == NULL) {
    
    goto exit_mp;
  }

  
  if (ct->len < 9 || strncmp(ct->p, "multipart", 9) != 0) {
    goto exit_mp;
  }

  boundary_len = mg_http_parse_header2(ct, "boundary", &boundary, sizeof(boundary_buf));
  if (boundary_len == 0) {
    
    nc->flags = MG_F_CLOSE_IMMEDIATELY;
    DBG(("invalid request"));
    goto exit_mp;
  }

  

  if (pd->mp_stream.boundary != NULL) {
    
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  } else {
    struct mg_http_endpoint *ep = NULL;
    pd->mp_stream.state = MPS_BEGIN;
    pd->mp_stream.boundary = strdup(boundary);
    pd->mp_stream.boundary_len = strlen(boundary);
    pd->mp_stream.var_name = pd->mp_stream.file_name = NULL;
    pd->endpoint_handler = nc->handler;

    ep = mg_http_get_endpoint_handler(nc->listener, &hm->uri);
    if (ep != NULL) {
      pd->endpoint_handler = ep->handler;
    }

    mg_http_call_endpoint_handler(nc, MG_EV_HTTP_MULTIPART_REQUEST, hm);

    mbuf_remove(io, req_len);
  }
exit_mp:
  if (boundary != boundary_buf) MG_FREE(boundary);
}



static void mg_http_multipart_call_handler(struct mg_connection *c, int ev, const char *data, size_t data_len) {
  struct mg_http_multipart_part mp;
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  memset(&mp, 0, sizeof(mp));

  mp.var_name = pd->mp_stream.var_name;
  mp.file_name = pd->mp_stream.file_name;
  mp.user_data = pd->mp_stream.user_data;
  mp.data.p = data;
  mp.data.len = data_len;
  mg_call(c, pd->endpoint_handler, c->user_data, ev, &mp);
  pd->mp_stream.user_data = mp.user_data;
}

static int mg_http_multipart_finalize(struct mg_connection *c) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);

  mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_END, NULL, 0);
  MG_FREE((void *) pd->mp_stream.file_name);
  pd->mp_stream.file_name = NULL;
  MG_FREE((void *) pd->mp_stream.var_name);
  pd->mp_stream.var_name = NULL;
  mg_http_multipart_call_handler(c, MG_EV_HTTP_MULTIPART_REQUEST_END, NULL, 0);
  mg_http_free_proto_data_mp_stream(&pd->mp_stream);
  pd->mp_stream.state = MPS_FINISHED;

  return 1;
}

static int mg_http_multipart_wait_for_boundary(struct mg_connection *c) {
  const char *boundary;
  struct mbuf *io = &c->recv_mbuf;
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);

  if (pd->mp_stream.boundary == NULL) {
    pd->mp_stream.state = MPS_FINALIZE;
    DBG(("Invalid request: boundary not initialized"));
    return 0;
  }

  if ((int) io->len < pd->mp_stream.boundary_len + 2) {
    return 0;
  }

  boundary = c_strnstr(io->buf, pd->mp_stream.boundary, io->len);
  if (boundary != NULL) {
    const char *boundary_end = (boundary + pd->mp_stream.boundary_len);
    if (io->len - (boundary_end - io->buf) < 4) {
      return 0;
    }
    if (strncmp(boundary_end, "--\r\n", 4) == 0) {
      pd->mp_stream.state = MPS_FINALIZE;
      mbuf_remove(io, (boundary_end - io->buf) + 4);
    } else {
      pd->mp_stream.state = MPS_GOT_BOUNDARY;
    }
  } else {
    return 0;
  }

  return 1;
}

static void mg_http_parse_header_internal(struct mg_str *hdr, const char *var_name, struct altbuf *ab);


static int mg_http_multipart_process_boundary(struct mg_connection *c) {
  int data_size;
  const char *boundary, *block_begin;
  struct mbuf *io = &c->recv_mbuf;
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  struct altbuf ab_file_name, ab_var_name;
  int line_len;
  boundary = c_strnstr(io->buf, pd->mp_stream.boundary, io->len);
  block_begin = boundary + pd->mp_stream.boundary_len + 2;
  data_size = io->len - (block_begin - io->buf);

  altbuf_init(&ab_file_name, NULL, 0);
  altbuf_init(&ab_var_name, NULL, 0);

  while (data_size > 0 && (line_len = mg_get_line_len(block_begin, data_size)) != 0) {
    if (line_len > (int) sizeof(CONTENT_DISPOSITION) && mg_ncasecmp(block_begin, CONTENT_DISPOSITION, sizeof(CONTENT_DISPOSITION) - 1) == 0) {

      struct mg_str header;

      header.p = block_begin + sizeof(CONTENT_DISPOSITION) - 1;
      header.len = line_len - sizeof(CONTENT_DISPOSITION) - 1;

      altbuf_reset(&ab_var_name);
      mg_http_parse_header_internal(&header, "name", &ab_var_name);

      altbuf_reset(&ab_file_name);
      mg_http_parse_header_internal(&header, "filename", &ab_file_name);

      block_begin += line_len;
      data_size -= line_len;

      continue;
    }

    if (line_len == 2 && mg_ncasecmp(block_begin, "\r\n", 2) == 0) {
      mbuf_remove(io, block_begin - io->buf + 2);

      if (pd->mp_stream.processing_part != 0) {
        mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_END, NULL, 0);
      }

      
      altbuf_append(&ab_file_name, '\0');
      altbuf_append(&ab_file_name, '\0');
      altbuf_append(&ab_var_name, '\0');
      altbuf_append(&ab_var_name, '\0');

      MG_FREE((void *) pd->mp_stream.file_name);
      pd->mp_stream.file_name = altbuf_get_buf(&ab_file_name, 1 );
      MG_FREE((void *) pd->mp_stream.var_name);
      pd->mp_stream.var_name = altbuf_get_buf(&ab_var_name, 1 );

      mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_BEGIN, NULL, 0);
      pd->mp_stream.state = MPS_WAITING_FOR_CHUNK;
      pd->mp_stream.processing_part++;
      return 1;
    }

    block_begin += line_len;
  }

  pd->mp_stream.state = MPS_WAITING_FOR_BOUNDARY;

  altbuf_reset(&ab_var_name);
  altbuf_reset(&ab_file_name);

  return 0;
}

static int mg_http_multipart_continue_wait_for_chunk(struct mg_connection *c) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  struct mbuf *io = &c->recv_mbuf;

  const char *boundary;
  if ((int) io->len < pd->mp_stream.boundary_len + 6 ) {
    return 0;
  }

  boundary = c_strnstr(io->buf, pd->mp_stream.boundary, io->len);
  if (boundary == NULL) {
    int data_size = (io->len - (pd->mp_stream.boundary_len + 6));
    if (data_size > 0) {
      mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_DATA, io->buf, data_size);
      mbuf_remove(io, data_size);
    }
    return 0;
  } else if (boundary != NULL) {
    int data_size = (boundary - io->buf - 4);
    mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_DATA, io->buf, data_size);
    mbuf_remove(io, (boundary - io->buf));
    pd->mp_stream.state = MPS_WAITING_FOR_BOUNDARY;
    return 1;
  } else {
    return 0;
  }
}

static void mg_http_multipart_continue(struct mg_connection *c) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  while (1) {
    switch (pd->mp_stream.state) {
      case MPS_BEGIN: {
        pd->mp_stream.state = MPS_WAITING_FOR_BOUNDARY;
        break;
      }
      case MPS_WAITING_FOR_BOUNDARY: {
        if (mg_http_multipart_wait_for_boundary(c) == 0) {
          return;
        }
        break;
      }
      case MPS_GOT_BOUNDARY: {
        if (mg_http_multipart_process_boundary(c) == 0) {
          return;
        }
        break;
      }
      case MPS_WAITING_FOR_CHUNK: {
        if (mg_http_multipart_continue_wait_for_chunk(c) == 0) {
          return;
        }
        break;
      }
      case MPS_FINALIZE: {
        if (mg_http_multipart_finalize(c) == 0) {
          return;
        }
        break;
      }
      case MPS_FINISHED: {
        return;
      }
    }
  }
}

struct file_upload_state {
  char *lfn;
  size_t num_recd;
  FILE *fp;
};



void mg_set_protocol_http_websocket(struct mg_connection *nc) {
  nc->proto_handler = mg_http_handler;
}

const char *mg_status_message(int status_code) {
  switch (status_code) {
    case 206:
      return "Partial Content";
    case 301:
      return "Moved";
    case 302:
      return "Found";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 416:
      return "Requested Range Not Satisfiable";
    case 418:
      return "I'm a teapot";
    case 500:
      return "Internal Server Error";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";


    case 100:
      return "Continue";
    case 101:
      return "Switching Protocols";
    case 102:
      return "Processing";
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 202:
      return "Accepted";
    case 203:
      return "Non-Authoritative Information";
    case 204:
      return "No Content";
    case 205:
      return "Reset Content";
    case 207:
      return "Multi-Status";
    case 208:
      return "Already Reported";
    case 226:
      return "IM Used";
    case 300:
      return "Multiple Choices";
    case 303:
      return "See Other";
    case 304:
      return "Not Modified";
    case 305:
      return "Use Proxy";
    case 306:
      return "Switch Proxy";
    case 307:
      return "Temporary Redirect";
    case 308:
      return "Permanent Redirect";
    case 402:
      return "Payment Required";
    case 405:
      return "Method Not Allowed";
    case 406:
      return "Not Acceptable";
    case 407:
      return "Proxy Authentication Required";
    case 408:
      return "Request Timeout";
    case 409:
      return "Conflict";
    case 410:
      return "Gone";
    case 411:
      return "Length Required";
    case 412:
      return "Precondition Failed";
    case 413:
      return "Payload Too Large";
    case 414:
      return "URI Too Long";
    case 415:
      return "Unsupported Media Type";
    case 417:
      return "Expectation Failed";
    case 422:
      return "Unprocessable Entity";
    case 423:
      return "Locked";
    case 424:
      return "Failed Dependency";
    case 426:
      return "Upgrade Required";
    case 428:
      return "Precondition Required";
    case 429:
      return "Too Many Requests";
    case 431:
      return "Request Header Fields Too Large";
    case 451:
      return "Unavailable For Legal Reasons";
    case 501:
      return "Not Implemented";
    case 504:
      return "Gateway Timeout";
    case 505:
      return "HTTP Version Not Supported";
    case 506:
      return "Variant Also Negotiates";
    case 507:
      return "Insufficient Storage";
    case 508:
      return "Loop Detected";
    case 510:
      return "Not Extended";
    case 511:
      return "Network Authentication Required";


    default:
      return "OK";
  }
}

void mg_send_response_line_s(struct mg_connection *nc, int status_code, const struct mg_str extra_headers) {
  mg_printf(nc, "HTTP/1.1 %d %s\r\n", status_code, mg_status_message(status_code));

  mg_printf(nc, "Server: %s\r\n", mg_version_header);

  if (extra_headers.len > 0) {
    mg_printf(nc, "%.*s\r\n", (int) extra_headers.len, extra_headers.p);
  }
}

void mg_send_response_line(struct mg_connection *nc, int status_code, const char *extra_headers) {
  mg_send_response_line_s(nc, status_code, mg_mk_str(extra_headers));
}

void mg_http_send_redirect(struct mg_connection *nc, int status_code, const struct mg_str location, const struct mg_str extra_headers) {

  char bbody[100], *pbody = bbody;
  int bl = mg_asprintf(&pbody, sizeof(bbody), "<p>Moved <a href='%.*s'>here</a>.\r\n", (int) location.len, location.p);

  char bhead[150], *phead = bhead;
  mg_asprintf(&phead, sizeof(bhead), "Location: %.*s\r\n" "Content-Type: text/html\r\n" "Content-Length: %d\r\n" "Cache-Control: no-cache\r\n" "%.*s%s", (int) location.len, location.p, bl, (int) extra_headers.len, extra_headers.p, (extra_headers.len > 0 ? "\r\n" : ""));






  mg_send_response_line(nc, status_code, phead);
  if (phead != bhead) MG_FREE(phead);
  mg_send(nc, pbody, bl);
  if (pbody != bbody) MG_FREE(pbody);
}

void mg_send_head(struct mg_connection *c, int status_code, int64_t content_length, const char *extra_headers) {
  mg_send_response_line(c, status_code, extra_headers);
  if (content_length < 0) {
    mg_printf(c, "%s", "Transfer-Encoding: chunked\r\n");
  } else {
    mg_printf(c, "Content-Length: %" INT64_FMT "\r\n", content_length);
  }
  mg_send(c, "\r\n", 2);
}

void mg_http_send_error(struct mg_connection *nc, int code, const char *reason) {
  if (!reason) reason = mg_status_message(code);
  LOG(LL_DEBUG, ("%p %d %s", nc, code, reason));
  mg_send_head(nc, code, strlen(reason), "Content-Type: text/plain\r\nConnection: close");
  mg_send(nc, reason, strlen(reason));
  nc->flags |= MG_F_SEND_AND_CLOSE;
}


static void mg_http_construct_etag(char *buf, size_t buf_len, const cs_stat_t *st) {
  snprintf(buf, buf_len, "\"%lx.%" INT64_FMT "\"", (unsigned long) st->st_mtime, (int64_t) st->st_size);
}


static void mg_gmt_time_string(char *buf, size_t buf_len, time_t *t) {
  strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", gmtime(t));
}


static void mg_gmt_time_string(char *buf, size_t buf_len, time_t *t);


static int mg_http_parse_range_header(const struct mg_str *header, int64_t *a, int64_t *b) {
  
  int result;
  char *p = (char *) MG_MALLOC(header->len + 1);
  if (p == NULL) return 0;
  memcpy(p, header->p, header->len);
  p[header->len] = '\0';
  result = sscanf(p, "bytes=%" INT64_FMT "-%" INT64_FMT, a, b);
  MG_FREE(p);
  return result;
}

void mg_http_serve_file(struct mg_connection *nc, struct http_message *hm, const char *path, const struct mg_str mime_type, const struct mg_str extra_headers) {

  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  cs_stat_t st;
  LOG(LL_DEBUG, ("%p [%s] %.*s", nc, path, (int) mime_type.len, mime_type.p));
  if (mg_stat(path, &st) != 0 || (pd->file.fp = mg_fopen(path, "rb")) == NULL) {
    int code, err = mg_get_errno();
    switch (err) {
      case EACCES:
        code = 403;
        break;
      case ENOENT:
        code = 404;
        break;
      default:
        code = 500;
    };
    mg_http_send_error(nc, code, "Open failed");
  } else {
    char etag[50], current_time[50], last_modified[50], range[70];
    time_t t = (time_t) mg_time();
    int64_t r1 = 0, r2 = 0, cl = st.st_size;
    struct mg_str *range_hdr = mg_get_http_header(hm, "Range");
    int n, status_code = 200;

    
    range[0] = '\0';
    if (range_hdr != NULL && (n = mg_http_parse_range_header(range_hdr, &r1, &r2)) > 0 && r1 >= 0 && r2 >= 0) {

      
      if (n == 1) {
        r2 = cl - 1;
      }
      if (r1 > r2 || r2 >= cl) {
        status_code = 416;
        cl = 0;
        snprintf(range, sizeof(range), "Content-Range: bytes */%" INT64_FMT "\r\n", (int64_t) st.st_size);

      } else {
        status_code = 206;
        cl = r2 - r1 + 1;
        snprintf(range, sizeof(range), "Content-Range: bytes %" INT64_FMT "-%" INT64_FMT "/%" INT64_FMT "\r\n", r1, r1 + cl - 1, (int64_t) st.st_size);


        fseeko(pd->file.fp, r1, SEEK_SET);

        fseek(pd->file.fp, (long) r1, SEEK_SET);

      }
    }


    {
      struct mg_str *conn_hdr = mg_get_http_header(hm, "Connection");
      if (conn_hdr != NULL) {
        pd->file.keepalive = (mg_vcasecmp(conn_hdr, "keep-alive") == 0);
      } else {
        pd->file.keepalive = (mg_vcmp(&hm->proto, "HTTP/1.1") == 0);
      }
    }


    mg_http_construct_etag(etag, sizeof(etag), &st);
    mg_gmt_time_string(current_time, sizeof(current_time), &t);
    mg_gmt_time_string(last_modified, sizeof(last_modified), &st.st_mtime);
    
    mg_send_response_line_s(nc, status_code, extra_headers);
    mg_printf(nc, "Date: %s\r\n" "Last-Modified: %s\r\n" "Accept-Ranges: bytes\r\n" "Content-Type: %.*s\r\n" "Connection: %s\r\n" "Content-Length: %" SIZE_T_FMT "\r\n" "%sEtag: %s\r\n\r\n", current_time, last_modified, (int) mime_type.len, mime_type.p, (pd->file.keepalive ? "keep-alive" : "close"), (size_t) cl, range, etag);











    pd->file.cl = cl;
    pd->file.type = DATA_FILE;
    mg_http_transfer_file_data(nc);
  }
}

static void mg_http_serve_file2(struct mg_connection *nc, const char *path, struct http_message *hm, struct mg_serve_http_opts *opts) {


  if (mg_match_prefix(opts->ssi_pattern, strlen(opts->ssi_pattern), path) > 0) {
    mg_handle_ssi_request(nc, hm, path, opts);
    return;
  }

  mg_http_serve_file(nc, hm, path, mg_get_mime_type(path, "text/plain", opts), mg_mk_str(opts->extra_headers));
}



int mg_url_decode(const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded) {
  int i, j, a, b;


  for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
    if (src[i] == '%') {
      if (i < src_len - 2 && isxdigit(*(const unsigned char *) (src + i + 1)) && isxdigit(*(const unsigned char *) (src + i + 2))) {
        a = tolower(*(const unsigned char *) (src + i + 1));
        b = tolower(*(const unsigned char *) (src + i + 2));
        dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
        i += 2;
      } else {
        return -1;
      }
    } else if (is_form_url_encoded && src[i] == '+') {
      dst[j] = ' ';
    } else {
      dst[j] = src[i];
    }
  }

  dst[j] = '\0'; 

  return i >= src_len ? j : -1;
}

int mg_get_http_var(const struct mg_str *buf, const char *name, char *dst, size_t dst_len) {
  const char *p, *e, *s;
  size_t name_len;
  int len;

  
  if (dst == NULL || dst_len == 0) {
    len = -2;
  } else if (buf->p == NULL || name == NULL || buf->len == 0) {
    len = -1;
    dst[0] = '\0';
  } else {
    name_len = strlen(name);
    e = buf->p + buf->len;
    len = -4;
    dst[0] = '\0';

    for (p = buf->p; p + name_len < e; p++) {
      if ((p == buf->p || p[-1] == '&') && p[name_len] == '=' && !mg_ncasecmp(name, p, name_len)) {
        p += name_len + 1;
        s = (const char *) memchr(p, '&', (size_t)(e - p));
        if (s == NULL) {
          s = e;
        }
        len = mg_url_decode(p, (size_t)(s - p), dst, dst_len, 1);
        
        if (len == -1) {
          len = -3;
        }
        break;
      }
    }
  }

  return len;
}

void mg_send_http_chunk(struct mg_connection *nc, const char *buf, size_t len) {
  char chunk_size[50];
  int n;

  n = snprintf(chunk_size, sizeof(chunk_size), "%lX\r\n", (unsigned long) len);
  mg_send(nc, chunk_size, n);
  mg_send(nc, buf, len);
  mg_send(nc, "\r\n", 2);
}

void mg_printf_http_chunk(struct mg_connection *nc, const char *fmt, ...) {
  char mem[MG_VPRINTF_BUFFER_SIZE], *buf = mem;
  int len;
  va_list ap;

  va_start(ap, fmt);
  len = mg_avprintf(&buf, sizeof(mem), fmt, ap);
  va_end(ap);

  if (len >= 0) {
    mg_send_http_chunk(nc, buf, len);
  }

  
  if (buf != mem && buf != NULL) {
    MG_FREE(buf);
  }
  
}

void mg_printf_html_escape(struct mg_connection *nc, const char *fmt, ...) {
  char mem[MG_VPRINTF_BUFFER_SIZE], *buf = mem;
  int i, j, len;
  va_list ap;

  va_start(ap, fmt);
  len = mg_avprintf(&buf, sizeof(mem), fmt, ap);
  va_end(ap);

  if (len >= 0) {
    for (i = j = 0; i < len; i++) {
      if (buf[i] == '<' || buf[i] == '>') {
        mg_send(nc, buf + j, i - j);
        mg_send(nc, buf[i] == '<' ? "&lt;" : "&gt;", 4);
        j = i + 1;
      }
    }
    mg_send(nc, buf + j, i - j);
  }

  
  if (buf != mem && buf != NULL) {
    MG_FREE(buf);
  }
  
}

static void mg_http_parse_header_internal(struct mg_str *hdr, const char *var_name, struct altbuf *ab) {

  int ch = ' ', ch1 = ',', ch2 = ';', n = strlen(var_name);
  const char *p, *end = hdr ? hdr->p + hdr->len : NULL, *s = NULL;

  
  for (s = hdr->p; s != NULL && s + n < end; s++) {
    if ((s == hdr->p || s[-1] == ch || s[-1] == ch1 || s[-1] == ';') && s[n] == '=' && !strncmp(s, var_name, n))
      break;
  }

  if (s != NULL && &s[n + 1] < end) {
    s += n + 1;
    if (*s == '"' || *s == '\'') {
      ch = ch1 = ch2 = *s++;
    }
    p = s;
    while (p < end && p[0] != ch && p[0] != ch1 && p[0] != ch2) {
      if (ch != ' ' && p[0] == '\\' && p[1] == ch) p++;
      altbuf_append(ab, *p++);
    }

    if (ch != ' ' && *p != ch) {
      altbuf_reset(ab);
    }
  }

  
  if (ab->len > 0) {
    altbuf_append(ab, '\0');
  }
}

int mg_http_parse_header2(struct mg_str *hdr, const char *var_name, char **buf, size_t buf_size) {
  struct altbuf ab;
  altbuf_init(&ab, *buf, buf_size);
  if (hdr == NULL) return 0;
  if (*buf != NULL && buf_size > 0) *buf[0] = '\0';

  mg_http_parse_header_internal(hdr, var_name, &ab);

  
  *buf = altbuf_get_buf(&ab, 1 );
  return ab.len > 0 ? ab.len - 1 : 0;
}

int mg_http_parse_header(struct mg_str *hdr, const char *var_name, char *buf, size_t buf_size) {
  char *buf2 = buf;

  int len = mg_http_parse_header2(hdr, var_name, &buf2, buf_size);

  if (buf2 != buf) {
    
    MG_FREE(buf2);
    return 0;
  }

  return len;
}

int mg_get_http_basic_auth(struct http_message *hm, char *user, size_t user_len, char *pass, size_t pass_len) {
  struct mg_str *hdr = mg_get_http_header(hm, "Authorization");
  if (hdr == NULL) return -1;
  return mg_parse_http_basic_auth(hdr, user, user_len, pass, pass_len);
}

int mg_parse_http_basic_auth(struct mg_str *hdr, char *user, size_t user_len, char *pass, size_t pass_len) {
  char *buf = NULL;
  char fmt[64];
  int res = 0;

  if (mg_strncmp(*hdr, mg_mk_str("Basic "), 6) != 0) return -1;

  buf = (char *) MG_MALLOC(hdr->len);
  cs_base64_decode((unsigned char *) hdr->p + 6, hdr->len, buf, NULL);

  
  snprintf(fmt, sizeof(fmt), "%%%" SIZE_T_FMT "[^:]:%%%" SIZE_T_FMT "[^\n]", user_len - 1, pass_len - 1);
  if (sscanf(buf, fmt, user, pass) == 0) {
    res = -1;
  }

  MG_FREE(buf);
  return res;
}


static int mg_is_file_hidden(const char *path, const struct mg_serve_http_opts *opts, int exclude_specials) {

  const char *p1 = opts->per_directory_auth_file;
  const char *p2 = opts->hidden_file_pattern;

  
  const char *pdir = strrchr(path, DIRSEP);
  if (pdir != NULL) {
    path = pdir + 1;
  }

  return (exclude_specials && (!strcmp(path, ".") || !strcmp(path, ".."))) || (p1 != NULL && mg_match_prefix(p1, strlen(p1), path) == strlen(p1)) || (p2 != NULL && mg_match_prefix(p2, strlen(p2), path) > 0);

}




void mg_hash_md5_v(size_t num_msgs, const uint8_t *msgs[], const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  cs_md5_ctx md5_ctx;
  cs_md5_init(&md5_ctx);
  for (i = 0; i < num_msgs; i++) {
    cs_md5_update(&md5_ctx, msgs[i], msg_lens[i]);
  }
  cs_md5_final(digest, &md5_ctx);
}

extern void mg_hash_md5_v(size_t num_msgs, const uint8_t *msgs[], const size_t *msg_lens, uint8_t *digest);


void cs_md5(char buf[33], ...) {
  unsigned char hash[16];
  const uint8_t *msgs[20], *p;
  size_t msg_lens[20];
  size_t num_msgs = 0;
  va_list ap;

  va_start(ap, buf);
  while ((p = va_arg(ap, const unsigned char *) ) != NULL) {
    msgs[num_msgs] = p;
    msg_lens[num_msgs] = va_arg(ap, size_t);
    num_msgs++;
  }
  va_end(ap);

  mg_hash_md5_v(num_msgs, msgs, msg_lens, hash);
  cs_to_hex(buf, hash, sizeof(hash));
}

static void mg_mkmd5resp(const char *method, size_t method_len, const char *uri, size_t uri_len, const char *ha1, size_t ha1_len, const char *nonce, size_t nonce_len, const char *nc, size_t nc_len, const char *cnonce, size_t cnonce_len, const char *qop, size_t qop_len, char *resp) {



  static const char colon[] = ":";
  static const size_t one = 1;
  char ha2[33];
  cs_md5(ha2, method, method_len, colon, one, uri, uri_len, NULL);
  cs_md5(resp, ha1, ha1_len, colon, one, nonce, nonce_len, colon, one, nc, nc_len, colon, one, cnonce, cnonce_len, colon, one, qop, qop_len, colon, one, ha2, sizeof(ha2) - 1, NULL);

}

int mg_http_create_digest_auth_header(char *buf, size_t buf_len, const char *method, const char *uri, const char *auth_domain, const char *user, const char *passwd, const char *nonce) {


  static const char colon[] = ":", qop[] = "auth";
  static const size_t one = 1;
  char ha1[33], resp[33], cnonce[40];

  snprintf(cnonce, sizeof(cnonce), "%lx", (unsigned long) mg_time());
  cs_md5(ha1, user, (size_t) strlen(user), colon, one, auth_domain, (size_t) strlen(auth_domain), colon, one, passwd, (size_t) strlen(passwd), NULL);

  mg_mkmd5resp(method, strlen(method), uri, strlen(uri), ha1, sizeof(ha1) - 1, nonce, strlen(nonce), "1", one, cnonce, strlen(cnonce), qop, sizeof(qop) - 1, resp);

  return snprintf(buf, buf_len, "Authorization: Digest username=\"%s\"," "realm=\"%s\",uri=\"%s\",qop=%s,nc=1,cnonce=%s," "nonce=%s,response=%s\r\n", user, auth_domain, uri, qop, cnonce, nonce, resp);



}


static int mg_check_nonce(const char *nonce) {
  unsigned long now = (unsigned long) mg_time();
  unsigned long val = (unsigned long) strtoul(nonce, NULL, 16);
  return (now >= val) && (now - val < 60 * 60);
}

int mg_http_check_digest_auth(struct http_message *hm, const char *auth_domain, FILE *fp) {
  int ret = 0;
  struct mg_str *hdr;
  char username_buf[50], cnonce_buf[64], response_buf[40], uri_buf[200], qop_buf[20], nc_buf[20], nonce_buf[16];

  char *username = username_buf, *cnonce = cnonce_buf, *response = response_buf, *uri = uri_buf, *qop = qop_buf, *nc = nc_buf, *nonce = nonce_buf;

  
  if (hm == NULL || fp == NULL || (hdr = mg_get_http_header(hm, "Authorization")) == NULL || mg_http_parse_header2(hdr, "username", &username, sizeof(username_buf)) == 0 || mg_http_parse_header2(hdr, "cnonce", &cnonce, sizeof(cnonce_buf)) == 0 || mg_http_parse_header2(hdr, "response", &response, sizeof(response_buf)) == 0 || mg_http_parse_header2(hdr, "uri", &uri, sizeof(uri_buf)) == 0 || mg_http_parse_header2(hdr, "qop", &qop, sizeof(qop_buf)) == 0 || mg_http_parse_header2(hdr, "nc", &nc, sizeof(nc_buf)) == 0 || mg_http_parse_header2(hdr, "nonce", &nonce, sizeof(nonce_buf)) == 0 || mg_check_nonce(nonce) == 0) {










    ret = 0;
    goto clean;
  }

  

  ret = mg_check_digest_auth( hm->method, mg_mk_str_n( hm->uri.p, hm->uri.len + (hm->query_string.len ? hm->query_string.len + 1 : 0)), mg_mk_str(username), mg_mk_str(cnonce), mg_mk_str(response), mg_mk_str(qop), mg_mk_str(nc), mg_mk_str(nonce), mg_mk_str(auth_domain), fp);







clean:
  if (username != username_buf) MG_FREE(username);
  if (cnonce != cnonce_buf) MG_FREE(cnonce);
  if (response != response_buf) MG_FREE(response);
  if (uri != uri_buf) MG_FREE(uri);
  if (qop != qop_buf) MG_FREE(qop);
  if (nc != nc_buf) MG_FREE(nc);
  if (nonce != nonce_buf) MG_FREE(nonce);

  return ret;
}

int mg_check_digest_auth(struct mg_str method, struct mg_str uri, struct mg_str username, struct mg_str cnonce, struct mg_str response, struct mg_str qop, struct mg_str nc, struct mg_str nonce, struct mg_str auth_domain, FILE *fp) {



  char buf[128], f_user[sizeof(buf)], f_ha1[sizeof(buf)], f_domain[sizeof(buf)];
  char expected_response[33];

  
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (sscanf(buf, "%[^:]:%[^:]:%s", f_user, f_domain, f_ha1) == 3 && mg_vcmp(&username, f_user) == 0 && mg_vcmp(&auth_domain, f_domain) == 0) {

      
      mg_mkmd5resp(method.p, method.len, uri.p, uri.len, f_ha1, strlen(f_ha1), nonce.p, nonce.len, nc.p, nc.len, cnonce.p, cnonce.len, qop.p, qop.len, expected_response);

      LOG(LL_DEBUG, ("%.*s %s %.*s %s", (int) username.len, username.p, f_domain, (int) response.len, response.p, expected_response));

      return mg_ncasecmp(response.p, expected_response, response.len) == 0;
    }
  }

  
  return 0;
}

int mg_http_is_authorized(struct http_message *hm, struct mg_str path, const char *domain, const char *passwords_file, int flags) {

  char buf[MG_MAX_PATH];
  const char *p;
  FILE *fp;
  int authorized = 1;

  if (domain != NULL && passwords_file != NULL) {
    if (flags & MG_AUTH_FLAG_IS_GLOBAL_PASS_FILE) {
      fp = mg_fopen(passwords_file, "r");
    } else if (flags & MG_AUTH_FLAG_IS_DIRECTORY) {
      snprintf(buf, sizeof(buf), "%.*s%c%s", (int) path.len, path.p, DIRSEP, passwords_file);
      fp = mg_fopen(buf, "r");
    } else {
      p = strrchr(path.p, DIRSEP);
      if (p == NULL) p = path.p;
      snprintf(buf, sizeof(buf), "%.*s%c%s", (int) (p - path.p), path.p, DIRSEP, passwords_file);
      fp = mg_fopen(buf, "r");
    }

    if (fp != NULL) {
      authorized = mg_http_check_digest_auth(hm, domain, fp);
      fclose(fp);
    } else if (!(flags & MG_AUTH_FLAG_ALLOW_MISSING_FILE)) {
      authorized = 0;
    }
  }

  LOG(LL_DEBUG, ("%.*s %s %x %d", (int) path.len, path.p, passwords_file ? passwords_file : "", flags, authorized));
  return authorized;
}

int mg_http_is_authorized(struct http_message *hm, const struct mg_str path, const char *domain, const char *passwords_file, int flags) {

  (void) hm;
  (void) path;
  (void) domain;
  (void) passwords_file;
  (void) flags;
  return 1;
}



static void mg_escape(const char *src, char *dst, size_t dst_len) {
  size_t n = 0;
  while (*src != '\0' && n + 5 < dst_len) {
    unsigned char ch = *(unsigned char *) src++;
    if (ch == '<') {
      n += snprintf(dst + n, dst_len - n, "%s", "&lt;");
    } else {
      dst[n++] = ch;
    }
  }
  dst[n] = '\0';
}

static void mg_print_dir_entry(struct mg_connection *nc, const char *file_name, cs_stat_t *stp) {
  char size[64], mod[64], path[MG_MAX_PATH];
  int64_t fsize = stp->st_size;
  int is_dir = S_ISDIR(stp->st_mode);
  const char *slash = is_dir ? "/" : "";
  struct mg_str href;

  if (is_dir) {
    snprintf(size, sizeof(size), "%s", "[DIRECTORY]");
  } else {
    
    if (fsize < 1024) {
      snprintf(size, sizeof(size), "%d", (int) fsize);
    } else if (fsize < 0x100000) {
      snprintf(size, sizeof(size), "%.1fk", (double) fsize / 1024.0);
    } else if (fsize < 0x40000000) {
      snprintf(size, sizeof(size), "%.1fM", (double) fsize / 1048576);
    } else {
      snprintf(size, sizeof(size), "%.1fG", (double) fsize / 1073741824);
    }
  }
  strftime(mod, sizeof(mod), "%d-%b-%Y %H:%M", localtime(&stp->st_mtime));
  mg_escape(file_name, path, sizeof(path));
  href = mg_url_encode(mg_mk_str(file_name));
  mg_printf_http_chunk(nc, "<tr><td><a href=\"%s%s\">%s%s</a></td>" "<td>%s</td><td name=%" INT64_FMT ">%s</td></tr>\n", href.p, slash, path, slash, mod, is_dir ? -1 : fsize, size);



  free((void *) href.p);
}

static void mg_scan_directory(struct mg_connection *nc, const char *dir, const struct mg_serve_http_opts *opts, void (*func)(struct mg_connection *, const char *, cs_stat_t *)) {


  char path[MG_MAX_PATH + 1];
  cs_stat_t st;
  struct dirent *dp;
  DIR *dirp;

  LOG(LL_DEBUG, ("%p [%s]", nc, dir));
  if ((dirp = (opendir(dir))) != NULL) {
    while ((dp = readdir(dirp)) != NULL) {
      
      if (mg_is_file_hidden((const char *) dp->d_name, opts, 1)) {
        continue;
      }
      snprintf(path, sizeof(path), "%s/%s", dir, dp->d_name);
      if (mg_stat(path, &st) == 0) {
        func(nc, (const char *) dp->d_name, &st);
      }
    }
    closedir(dirp);
  } else {
    LOG(LL_DEBUG, ("%p opendir(%s) -> %d", nc, dir, mg_get_errno()));
  }
}

static void mg_send_directory_listing(struct mg_connection *nc, const char *dir, struct http_message *hm, struct mg_serve_http_opts *opts) {

  static const char *sort_js_code = "<script>function srt(tb, sc, so, d) {" "var tr = Array.prototype.slice.call(tb.rows, 0)," "tr = tr.sort(function (a, b) { var c1 = a.cells[sc], c2 = b.cells[sc]," "n1 = c1.getAttribute('name'), n2 = c2.getAttribute('name'), " "t1 = a.cells[2].getAttribute('name'), " "t2 = b.cells[2].getAttribute('name'); " "return so * (t1 < 0 && t2 >= 0 ? -1 : t2 < 0 && t1 >= 0 ? 1 : " "n1 ? parseInt(n2) - parseInt(n1) : " "c1.textContent.trim().localeCompare(c2.textContent.trim())); });";








  static const char *sort_js_code2 = "for (var i = 0; i < tr.length; i++) tb.appendChild(tr[i]); " "if (!d) window.location.hash = ('sc=' + sc + '&so=' + so); " "};" "window.onload = function() {" "var tb = document.getElementById('tb');" "var m = /sc=([012]).so=(1|-1)/.exec(window.location.hash) || [0, 2, 1];" "var sc = m[1], so = m[2]; document.onclick = function(ev) { " "var c = ev.target.rel; if (c) {if (c == sc) so *= -1; srt(tb, c, so); " "sc = c; ev.preventDefault();}};" "srt(tb, sc, so, true);" "}" "</script>";












  mg_send_response_line(nc, 200, opts->extra_headers);
  mg_printf(nc, "%s: %s\r\n%s: %s\r\n\r\n", "Transfer-Encoding", "chunked", "Content-Type", "text/html; charset=utf-8");

  mg_printf_http_chunk( nc, "<html><head><title>Index of %.*s</title>%s%s" "<style>th,td {text-align: left; padding-right: 1em; " "font-family: monospace; }</style></head>\n" "<body><h1>Index of %.*s</h1>\n<table cellpadding=0><thead>" "<tr><th><a href=# rel=0>Name</a></th><th>" "<a href=# rel=1>Modified</a</th>" "<th><a href=# rel=2>Size</a></th></tr>" "<tr><td colspan=3><hr></td></tr>\n" "</thead>\n" "<tbody id=tb>", (int) hm->uri.len, hm->uri.p, sort_js_code, sort_js_code2, (int) hm->uri.len, hm->uri.p);












  mg_scan_directory(nc, dir, opts, mg_print_dir_entry);
  mg_printf_http_chunk(nc, "</tbody><tr><td colspan=3><hr></td></tr>\n" "</table>\n" "<address>%s</address>\n" "</body></html>", mg_version_header);




  mg_send_http_chunk(nc, "", 0);
  
  nc->flags |= MG_F_SEND_AND_CLOSE;
}



MG_INTERNAL void mg_find_index_file(const char *path, const char *list, char **index_file, cs_stat_t *stp) {
  struct mg_str vec;
  size_t path_len = strlen(path);
  int found = 0;
  *index_file = NULL;

  
  
  while ((list = mg_next_comma_list_entry(list, &vec, NULL)) != NULL) {
    cs_stat_t st;
    size_t len = path_len + 1 + vec.len + 1;
    *index_file = (char *) MG_REALLOC(*index_file, len);
    if (*index_file == NULL) break;
    snprintf(*index_file, len, "%s%c%.*s", path, DIRSEP, (int) vec.len, vec.p);

    
    if (mg_stat(*index_file, &st) == 0 && S_ISREG(st.st_mode)) {
      
      *stp = st;
      found = 1;
      break;
    }
  }
  if (!found) {
    MG_FREE(*index_file);
    *index_file = NULL;
  }
  LOG(LL_DEBUG, ("[%s] [%s]", path, (*index_file ? *index_file : "")));
}


static int mg_http_send_port_based_redirect( struct mg_connection *c, struct http_message *hm, const struct mg_serve_http_opts *opts) {

  const char *rewrites = opts->url_rewrites;
  struct mg_str a, b;
  char local_port[20] = {'%';

  mg_conn_addr_to_str(c, local_port + 1, sizeof(local_port) - 1, MG_SOCK_STRINGIFY_PORT);

  while ((rewrites = mg_next_comma_list_entry(rewrites, &a, &b)) != NULL) {
    if (mg_vcmp(&a, local_port) == 0) {
      mg_send_response_line(c, 301, NULL);
      mg_printf(c, "Content-Length: 0\r\nLocation: %.*s%.*s\r\n\r\n", (int) b.len, b.p, (int) (hm->proto.p - hm->uri.p - 1), hm->uri.p);

      return 1;
    }
  }

  return 0;
}

static void mg_reverse_proxy_handler(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data)) {
  struct http_message *hm = (struct http_message *) ev_data;
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);

  if (pd == NULL || pd->reverse_proxy_data.linked_conn == NULL) {
    DBG(("%p: upstream closed", nc));
    return;
  }

  switch (ev) {
    case MG_EV_CONNECT:
      if (*(int *) ev_data != 0) {
        mg_http_send_error(pd->reverse_proxy_data.linked_conn, 502, NULL);
      }
      break;
    
    case MG_EV_HTTP_REPLY:
      mg_send(pd->reverse_proxy_data.linked_conn, hm->message.p, hm->message.len);
      pd->reverse_proxy_data.linked_conn->flags |= MG_F_SEND_AND_CLOSE;
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      break;
    case MG_EV_CLOSE:
      pd->reverse_proxy_data.linked_conn->flags |= MG_F_SEND_AND_CLOSE;
      break;
  }


  (void) user_data;

}

void mg_http_reverse_proxy(struct mg_connection *nc, const struct http_message *hm, struct mg_str mount, struct mg_str upstream) {

  struct mg_connection *be;
  char burl[256], *purl = burl;
  int i;
  const char *error;
  struct mg_connect_opts opts;
  struct mg_str path = MG_NULL_STR, user_info = MG_NULL_STR, host = MG_NULL_STR;
  memset(&opts, 0, sizeof(opts));
  opts.error_string = &error;

  mg_asprintf(&purl, sizeof(burl), "%.*s%.*s", (int) upstream.len, upstream.p, (int) (hm->uri.len - mount.len), hm->uri.p + mount.len);

  be = mg_connect_http_base(nc->mgr, MG_CB(mg_reverse_proxy_handler, NULL), opts, "http", NULL, "https", NULL, purl, &path, &user_info, &host);

  LOG(LL_DEBUG, ("Proxying %.*s to %s (rule: %.*s)", (int) hm->uri.len, hm->uri.p, purl, (int) mount.len, mount.p));

  if (be == NULL) {
    LOG(LL_ERROR, ("Error connecting to %s: %s", purl, error));
    mg_http_send_error(nc, 502, NULL);
    goto cleanup;
  }

  
  mg_http_get_proto_data(be)->reverse_proxy_data.linked_conn = nc;
  mg_http_get_proto_data(nc)->reverse_proxy_data.linked_conn = be;

  
  mg_printf(be, "%.*s %.*s HTTP/1.1\r\n", (int) hm->method.len, hm->method.p, (int) path.len, path.p);

  mg_printf(be, "Host: %.*s\r\n", (int) host.len, host.p);
  for (i = 0; i < MG_MAX_HTTP_HEADERS && hm->header_names[i].len > 0; i++) {
    struct mg_str hn = hm->header_names[i];
    struct mg_str hv = hm->header_values[i];

    
    if (mg_vcasecmp(&hn, "Host") == 0) continue;
    
    if (mg_vcasecmp(&hn, "Transfer-encoding") == 0 && mg_vcasecmp(&hv, "chunked") == 0) {
      mg_printf(be, "Content-Length: %" SIZE_T_FMT "\r\n", hm->body.len);
      continue;
    }
    
    if (mg_vcasecmp(&hn, "Expect") == 0 && mg_vcasecmp(&hv, "100-continue") == 0) {
      continue;
    }

    mg_printf(be, "%.*s: %.*s\r\n", (int) hn.len, hn.p, (int) hv.len, hv.p);
  }

  mg_send(be, "\r\n", 2);
  mg_send(be, hm->body.p, hm->body.len);

cleanup:
  if (purl != burl) MG_FREE(purl);
}

static int mg_http_handle_forwarding(struct mg_connection *nc, struct http_message *hm, const struct mg_serve_http_opts *opts) {

  const char *rewrites = opts->url_rewrites;
  struct mg_str a, b;
  struct mg_str p1 = MG_MK_STR("http://"), p2 = MG_MK_STR("https://");

  while ((rewrites = mg_next_comma_list_entry(rewrites, &a, &b)) != NULL) {
    if (mg_strncmp(a, hm->uri, a.len) == 0) {
      if (mg_strncmp(b, p1, p1.len) == 0 || mg_strncmp(b, p2, p2.len) == 0) {
        mg_http_reverse_proxy(nc, hm, a, b);
        return 1;
      }
    }
  }

  return 0;
}


MG_INTERNAL int mg_uri_to_local_path(struct http_message *hm, const struct mg_serve_http_opts *opts, char **local_path, struct mg_str *remainder) {


  int ok = 1;
  const char *cp = hm->uri.p, *cp_end = hm->uri.p + hm->uri.len;
  struct mg_str root = {NULL, 0};
  const char *file_uri_start = cp;
  *local_path = NULL;
  remainder->p = NULL;
  remainder->len = 0;

  { 


    const char *rewrites = opts->url_rewrites;

    const char *rewrites = "";

    struct mg_str *hh = mg_get_http_header(hm, "Host");
    struct mg_str a, b;
    
    while ((rewrites = mg_next_comma_list_entry(rewrites, &a, &b)) != NULL) {
      if (a.len > 1 && a.p[0] == '@') {
        
        if (hh != NULL && hh->len == a.len - 1 && mg_ncasecmp(a.p + 1, hh->p, a.len - 1) == 0) {
          root = b;
          break;
        }
      } else {
        
        size_t match_len = mg_match_prefix_n(a, hm->uri);
        if (match_len > 0) {
          file_uri_start = hm->uri.p + match_len;
          if (*file_uri_start == '/' || file_uri_start == cp_end) {
            
          } else if (*(file_uri_start - 1) == '/') {
            
            file_uri_start--;
          } else {
            
            continue;
          }
          root = b;
          break;
        }
      }
    }
    
    if (root.p == NULL) {

      if (opts->dav_document_root != NULL && mg_is_dav_request(&hm->method)) {
        root.p = opts->dav_document_root;
        root.len = strlen(opts->dav_document_root);
      } else  {

        root.p = opts->document_root;
        root.len = strlen(opts->document_root);
      }
    }
    assert(root.p != NULL && root.len > 0);
  }

  { 
    const char *u = file_uri_start + 1;
    char *lp = (char *) MG_MALLOC(root.len + hm->uri.len + 1);
    char *lp_end = lp + root.len + hm->uri.len + 1;
    char *p = lp, *ps;
    int exists = 1;
    if (lp == NULL) {
      ok = 0;
      goto out;
    }
    memcpy(p, root.p, root.len);
    p += root.len;
    if (*(p - 1) == DIRSEP) p--;
    *p = '\0';
    ps = p;

    
    while (u <= cp_end) {
      const char *next = u;
      struct mg_str component;
      if (exists) {
        cs_stat_t st;
        exists = (mg_stat(lp, &st) == 0);
        if (exists && S_ISREG(st.st_mode)) {
          
          if (*(u - 1) == '/') u--;
          break;
        }
      }
      if (u >= cp_end) break;
      parse_uri_component((const char **) &next, cp_end, "/", &component);
      if (component.len > 0) {
        int len;
        memmove(p + 1, component.p, component.len);
        len = mg_url_decode(p + 1, component.len, p + 1, lp_end - p - 1, 0);
        if (len <= 0) {
          ok = 0;
          break;
        }
        component.p = p + 1;
        component.len = len;
        if (mg_vcmp(&component, ".") == 0) {
          
        } else if (mg_vcmp(&component, "..") == 0) {
          while (p > ps && *p != DIRSEP) p--;
          *p = '\0';
        } else {
          size_t i;

          
          wchar_t buf[MG_MAX_PATH * 2];
          if (to_wchar(component.p, buf, MG_MAX_PATH) == 0) {
            DBG(("[%.*s] smells funny", (int) component.len, component.p));
            ok = 0;
            break;
          }

          *p++ = DIRSEP;
          
          for (i = 0; i < component.len; i++, p++) {
            if (*p == '\0' || *p == DIRSEP   || *p == '/'  ) {





              ok = 0;
              break;
            }
          }
        }
      }
      u = next;
    }
    if (ok) {
      *local_path = lp;
      if (u > cp_end) u = cp_end;
      remainder->p = u;
      remainder->len = cp_end - u;
    } else {
      MG_FREE(lp);
    }
  }

out:
  LOG(LL_DEBUG, ("'%.*s' -> '%s' + '%.*s'", (int) hm->uri.len, hm->uri.p, *local_path ? *local_path : "", (int) remainder->len, remainder->p));

  return ok;
}

static int mg_get_month_index(const char *s) {
  static const char *month_names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec";
  size_t i;

  for (i = 0; i < ARRAY_SIZE(month_names); i++)
    if (!strcmp(s, month_names[i])) return (int) i;

  return -1;
}

static int mg_num_leap_years(int year) {
  return year / 4 - year / 100 + year / 400;
}


MG_INTERNAL time_t mg_parse_date_string(const char *datetime) {
  static const unsigned short days_before_month[] = {
      0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
  char month_str[32];
  int second, minute, hour, day, month, year, leap_days, days;
  time_t result = (time_t) 0;

  if (((sscanf(datetime, "%d/%3s/%d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second) == 6) || (sscanf(datetime, "%d %3s %d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second) == 6) || (sscanf(datetime, "%*3s, %d %3s %d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second) == 6) || (sscanf(datetime, "%d-%3s-%d %d:%d:%d", &day, month_str, &year, &hour, &minute, &second) == 6)) && year > 1970 && (month = mg_get_month_index(month_str)) != -1) {







    leap_days = mg_num_leap_years(year) - mg_num_leap_years(1970);
    year -= 1970;
    days = year * 365 + days_before_month[month] + (day - 1) + leap_days;
    result = days * 24 * 3600 + hour * 3600 + minute * 60 + second;
  }

  return result;
}

MG_INTERNAL int mg_is_not_modified(struct http_message *hm, cs_stat_t *st) {
  struct mg_str *hdr;
  if ((hdr = mg_get_http_header(hm, "If-None-Match")) != NULL) {
    char etag[64];
    mg_http_construct_etag(etag, sizeof(etag), st);
    return mg_vcasecmp(hdr, etag) == 0;
  } else if ((hdr = mg_get_http_header(hm, "If-Modified-Since")) != NULL) {
    return st->st_mtime <= mg_parse_date_string(hdr->p);
  } else {
    return 0;
  }
}

void mg_http_send_digest_auth_request(struct mg_connection *c, const char *domain) {
  mg_printf(c, "HTTP/1.1 401 Unauthorized\r\n" "WWW-Authenticate: Digest qop=\"auth\", " "realm=\"%s\", nonce=\"%lx\"\r\n" "Content-Length: 0\r\n\r\n", domain, (unsigned long) mg_time());




}

static void mg_http_send_options(struct mg_connection *nc) {
  mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAllow: GET, POST, HEAD, CONNECT, OPTIONS"  ", MKCOL, PUT, DELETE, PROPFIND, MOVE\r\nDAV: 1,2"  "\r\n\r\n");




  nc->flags |= MG_F_SEND_AND_CLOSE;
}

static int mg_is_creation_request(const struct http_message *hm) {
  return mg_vcmp(&hm->method, "MKCOL") == 0 || mg_vcmp(&hm->method, "PUT") == 0;
}

MG_INTERNAL void mg_send_http_file(struct mg_connection *nc, char *path, const struct mg_str *path_info, struct http_message *hm, struct mg_serve_http_opts *opts) {


  int exists, is_directory, is_cgi;

  int is_dav = mg_is_dav_request(&hm->method);

  int is_dav = 0;

  char *index_file = NULL;
  cs_stat_t st;

  exists = (mg_stat(path, &st) == 0);
  is_directory = exists && S_ISDIR(st.st_mode);

  if (is_directory)
    mg_find_index_file(path, opts->index_files, &index_file, &st);

  is_cgi = (mg_match_prefix(opts->cgi_file_pattern, strlen(opts->cgi_file_pattern), index_file ? index_file : path) > 0);


  LOG(LL_DEBUG, ("%p %.*s [%s] exists=%d is_dir=%d is_dav=%d is_cgi=%d index=%s", nc, (int) hm->method.len, hm->method.p, path, exists, is_directory, is_dav, is_cgi, index_file ? index_file : ""));



  if (is_directory && hm->uri.p[hm->uri.len - 1] != '/' && !is_dav) {
    mg_printf(nc, "HTTP/1.1 301 Moved\r\nLocation: %.*s/\r\n" "Content-Length: 0\r\n\r\n", (int) hm->uri.len, hm->uri.p);


    MG_FREE(index_file);
    return;
  }

  
  if (path_info->len > 0 && !is_cgi) {
    mg_http_send_error(nc, 501, NULL);
    MG_FREE(index_file);
    return;
  }

  if (is_dav && opts->dav_document_root == NULL) {
    mg_http_send_error(nc, 501, NULL);
  } else if (!mg_http_is_authorized( hm, mg_mk_str(path), opts->auth_domain, opts->global_auth_file, ((is_directory ? MG_AUTH_FLAG_IS_DIRECTORY : 0) | MG_AUTH_FLAG_IS_GLOBAL_PASS_FILE | MG_AUTH_FLAG_ALLOW_MISSING_FILE)) || !mg_http_is_authorized( hm, mg_mk_str(path), opts->auth_domain, opts->per_directory_auth_file, ((is_directory ? MG_AUTH_FLAG_IS_DIRECTORY : 0) | MG_AUTH_FLAG_ALLOW_MISSING_FILE))) {








    mg_http_send_digest_auth_request(nc, opts->auth_domain);
  } else if (is_cgi) {

    mg_handle_cgi(nc, index_file ? index_file : path, path_info, hm, opts);

    mg_http_send_error(nc, 501, NULL);

  } else if ((!exists || mg_is_file_hidden(path, opts, 0 )) && !mg_is_creation_request(hm)) {

    mg_http_send_error(nc, 404, NULL);

  } else if (!mg_vcmp(&hm->method, "PROPFIND")) {
    mg_handle_propfind(nc, path, &st, hm, opts);

  } else if (is_dav && (opts->dav_auth_file == NULL || (strcmp(opts->dav_auth_file, "-") != 0 && !mg_http_is_authorized( hm, mg_mk_str(path), opts->auth_domain, opts->dav_auth_file, ((is_directory ? MG_AUTH_FLAG_IS_DIRECTORY : 0) | MG_AUTH_FLAG_IS_GLOBAL_PASS_FILE | MG_AUTH_FLAG_ALLOW_MISSING_FILE))))) {






    mg_http_send_digest_auth_request(nc, opts->auth_domain);

  } else if (!mg_vcmp(&hm->method, "MKCOL")) {
    mg_handle_mkcol(nc, path, hm);
  } else if (!mg_vcmp(&hm->method, "DELETE")) {
    mg_handle_delete(nc, opts, path);
  } else if (!mg_vcmp(&hm->method, "PUT")) {
    mg_handle_put(nc, path, hm);
  } else if (!mg_vcmp(&hm->method, "MOVE")) {
    mg_handle_move(nc, opts, path, hm);

  } else if (!mg_vcmp(&hm->method, "LOCK")) {
    mg_handle_lock(nc, path);


  } else if (!mg_vcmp(&hm->method, "OPTIONS")) {
    mg_http_send_options(nc);
  } else if (is_directory && index_file == NULL) {

    if (strcmp(opts->enable_directory_listing, "yes") == 0) {
      mg_send_directory_listing(nc, path, hm, opts);
    } else {
      mg_http_send_error(nc, 403, NULL);
    }

    mg_http_send_error(nc, 501, NULL);

  } else if (mg_is_not_modified(hm, &st)) {
    mg_http_send_error(nc, 304, "Not Modified");
  } else {
    mg_http_serve_file2(nc, index_file ? index_file : path, hm, opts);
  }
  MG_FREE(index_file);
}

void mg_serve_http(struct mg_connection *nc, struct http_message *hm, struct mg_serve_http_opts opts) {
  char *path = NULL;
  struct mg_str *hdr, path_info;
  uint32_t remote_ip = ntohl(*(uint32_t *) &nc->sa.sin.sin_addr);

  if (mg_check_ip_acl(opts.ip_acl, remote_ip) != 1) {
    
    mg_http_send_error(nc, 403, NULL);
    nc->flags |= MG_F_SEND_AND_CLOSE;
    return;
  }


  if (mg_http_handle_forwarding(nc, hm, &opts)) {
    return;
  }

  if (mg_http_send_port_based_redirect(nc, hm, &opts)) {
    return;
  }


  if (opts.document_root == NULL) {
    opts.document_root = ".";
  }
  if (opts.per_directory_auth_file == NULL) {
    opts.per_directory_auth_file = ".htpasswd";
  }
  if (opts.enable_directory_listing == NULL) {
    opts.enable_directory_listing = "yes";
  }
  if (opts.cgi_file_pattern == NULL) {
    opts.cgi_file_pattern = "**.cgi$|**.php$";
  }
  if (opts.ssi_pattern == NULL) {
    opts.ssi_pattern = "**.shtml$|**.shtm$";
  }
  if (opts.index_files == NULL) {
    opts.index_files = "index.html,index.htm,index.shtml,index.cgi,index.php";
  }
  
  if (!mg_normalize_uri_path(&hm->uri, &hm->uri)) {
    mg_http_send_error(nc, 400, NULL);
    return;
  }
  if (mg_uri_to_local_path(hm, &opts, &path, &path_info) == 0) {
    mg_http_send_error(nc, 404, NULL);
    return;
  }
  mg_send_http_file(nc, path, &path_info, hm, &opts);

  MG_FREE(path);
  path = NULL;

  
  if (mg_vcmp(&hm->proto, "HTTP/1.1") != 0 || ((hdr = mg_get_http_header(hm, "Connection")) != NULL && mg_vcmp(hdr, "keep-alive") != 0)) {


    nc->flags |= MG_F_SEND_AND_CLOSE;

  }
}


void mg_file_upload_handler(struct mg_connection *nc, int ev, void *ev_data, mg_fu_fname_fn local_name_fn MG_UD_ARG(void *user_data)) {

  switch (ev) {
    case MG_EV_HTTP_PART_BEGIN: {
      struct mg_http_multipart_part *mp = (struct mg_http_multipart_part *) ev_data;
      struct file_upload_state *fus;
      struct mg_str lfn = local_name_fn(nc, mg_mk_str(mp->file_name));
      mp->user_data = NULL;
      if (lfn.p == NULL || lfn.len == 0) {
        LOG(LL_ERROR, ("%p Not allowed to upload %s", nc, mp->file_name));
        mg_printf(nc, "HTTP/1.1 403 Not Allowed\r\n" "Content-Type: text/plain\r\n" "Connection: close\r\n\r\n" "Not allowed to upload %s\r\n", mp->file_name);




        nc->flags |= MG_F_SEND_AND_CLOSE;
        return;
      }
      fus = (struct file_upload_state *) MG_CALLOC(1, sizeof(*fus));
      if (fus == NULL) {
        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        return;
      }
      fus->lfn = (char *) MG_MALLOC(lfn.len + 1);
      memcpy(fus->lfn, lfn.p, lfn.len);
      fus->lfn[lfn.len] = '\0';
      if (lfn.p != mp->file_name) MG_FREE((char *) lfn.p);
      LOG(LL_DEBUG, ("%p Receiving file %s -> %s", nc, mp->file_name, fus->lfn));
      fus->fp = mg_fopen(fus->lfn, "w");
      if (fus->fp == NULL) {
        mg_printf(nc, "HTTP/1.1 500 Internal Server Error\r\n" "Content-Type: text/plain\r\n" "Connection: close\r\n\r\n");


        LOG(LL_ERROR, ("Failed to open %s: %d\n", fus->lfn, mg_get_errno()));
        mg_printf(nc, "Failed to open %s: %d\n", fus->lfn, mg_get_errno());
        
      }
      mp->user_data = (void *) fus;
      break;
    }
    case MG_EV_HTTP_PART_DATA: {
      struct mg_http_multipart_part *mp = (struct mg_http_multipart_part *) ev_data;
      struct file_upload_state *fus = (struct file_upload_state *) mp->user_data;
      if (fus == NULL || fus->fp == NULL) break;
      if (mg_fwrite(mp->data.p, 1, mp->data.len, fus->fp) != mp->data.len) {
        LOG(LL_ERROR, ("Failed to write to %s: %d, wrote %d", fus->lfn, mg_get_errno(), (int) fus->num_recd));
        if (mg_get_errno() == ENOSPC  || mg_get_errno() == SPIFFS_ERR_FULL  ) {



          mg_printf(nc, "HTTP/1.1 413 Payload Too Large\r\n" "Content-Type: text/plain\r\n" "Connection: close\r\n\r\n");


          mg_printf(nc, "Failed to write to %s: no space left; wrote %d\r\n", fus->lfn, (int) fus->num_recd);
        } else {
          mg_printf(nc, "HTTP/1.1 500 Internal Server Error\r\n" "Content-Type: text/plain\r\n" "Connection: close\r\n\r\n");


          mg_printf(nc, "Failed to write to %s: %d, wrote %d", mp->file_name, mg_get_errno(), (int) fus->num_recd);
        }
        fclose(fus->fp);
        remove(fus->lfn);
        fus->fp = NULL;
        
        return;
      }
      fus->num_recd += mp->data.len;
      LOG(LL_DEBUG, ("%p rec'd %d bytes, %d total", nc, (int) mp->data.len, (int) fus->num_recd));
      break;
    }
    case MG_EV_HTTP_PART_END: {
      struct mg_http_multipart_part *mp = (struct mg_http_multipart_part *) ev_data;
      struct file_upload_state *fus = (struct file_upload_state *) mp->user_data;
      if (fus == NULL) break;
      if (mp->status >= 0 && fus->fp != NULL) {
        LOG(LL_DEBUG, ("%p Uploaded %s (%s), %d bytes", nc, mp->file_name, fus->lfn, (int) fus->num_recd));
      } else {
        LOG(LL_ERROR, ("Failed to store %s (%s)", mp->file_name, fus->lfn));
        
      }
      if (fus->fp != NULL) fclose(fus->fp);
      MG_FREE(fus->lfn);
      MG_FREE(fus);
      mp->user_data = NULL;
      
      break;
    }
    case MG_EV_HTTP_MULTIPART_REQUEST_END: {
      mg_printf(nc, "HTTP/1.1 200 OK\r\n" "Content-Type: text/plain\r\n" "Connection: close\r\n\r\n" "Ok.\r\n");



      nc->flags |= MG_F_SEND_AND_CLOSE;
      break;
    }
  }


  (void) user_data;

}




struct mg_connection *mg_connect_http_base( struct mg_mgr *mgr, MG_CB(mg_event_handler_t ev_handler, void *user_data), struct mg_connect_opts opts, const char *scheme1, const char *scheme2, const char *scheme_ssl1, const char *scheme_ssl2, const char *url, struct mg_str *path, struct mg_str *user_info, struct mg_str *host) {



  struct mg_connection *nc = NULL;
  unsigned int port_i = 0;
  int use_ssl = 0;
  struct mg_str scheme, query, fragment;
  char conn_addr_buf[2];
  char *conn_addr = conn_addr_buf;

  if (mg_parse_uri(mg_mk_str(url), &scheme, user_info, host, &port_i, path, &query, &fragment) != 0) {
    MG_SET_PTRPTR(opts.error_string, "cannot parse url");
    goto out;
  }

  
  if (query.len > 0) path->len += query.len + 1;

  if (scheme.len == 0 || mg_vcmp(&scheme, scheme1) == 0 || (scheme2 != NULL && mg_vcmp(&scheme, scheme2) == 0)) {
    use_ssl = 0;
    if (port_i == 0) port_i = 80;
  } else if (mg_vcmp(&scheme, scheme_ssl1) == 0 || (scheme2 != NULL && mg_vcmp(&scheme, scheme_ssl2) == 0)) {
    use_ssl = 1;
    if (port_i == 0) port_i = 443;
  } else {
    goto out;
  }

  mg_asprintf(&conn_addr, sizeof(conn_addr_buf), "tcp://%.*s:%u", (int) host->len, host->p, port_i);
  if (conn_addr == NULL) goto out;

  LOG(LL_DEBUG, ("%s use_ssl? %d %s", url, use_ssl, conn_addr));
  if (use_ssl) {

    
    if (opts.ssl_ca_cert == NULL) {
      opts.ssl_ca_cert = "*";
    }

    MG_SET_PTRPTR(opts.error_string, "ssl is disabled");
    goto out;

  }

  if ((nc = mg_connect_opt(mgr, conn_addr, MG_CB(ev_handler, user_data), opts)) != NULL) {
    mg_set_protocol_http_websocket(nc);
  }

out:
  if (conn_addr != NULL && conn_addr != conn_addr_buf) MG_FREE(conn_addr);
  return nc;
}

struct mg_connection *mg_connect_http_opt( struct mg_mgr *mgr, MG_CB(mg_event_handler_t ev_handler, void *user_data), struct mg_connect_opts opts, const char *url, const char *extra_headers, const char *post_data) {


  struct mg_str user = MG_NULL_STR, null_str = MG_NULL_STR;
  struct mg_str host = MG_NULL_STR, path = MG_NULL_STR;
  struct mbuf auth;
  struct mg_connection *nc = mg_connect_http_base(mgr, MG_CB(ev_handler, user_data), opts, "http", NULL, "https", NULL, url, &path, &user, &host);


  if (nc == NULL) {
    return NULL;
  }

  mbuf_init(&auth, 0);
  if (user.len > 0) {
    mg_basic_auth_header(user, null_str, &auth);
  }

  if (post_data == NULL) post_data = "";
  if (extra_headers == NULL) extra_headers = "";
  if (path.len == 0) path = mg_mk_str("/");
  if (host.len == 0) host = mg_mk_str("");

  mg_printf(nc, "%s %.*s HTTP/1.1\r\nHost: %.*s\r\nContent-Length: %" SIZE_T_FMT "\r\n%.*s%s\r\n%s", (post_data[0] == '\0' ? "GET" : "POST"), (int) path.len, path.p, (int) (path.p - host.p), host.p, strlen(post_data), (int) auth.len, (auth.buf == NULL ? "" : auth.buf), extra_headers, post_data);




  mbuf_free(&auth);
  return nc;
}

struct mg_connection *mg_connect_http( struct mg_mgr *mgr, MG_CB(mg_event_handler_t ev_handler, void *user_data), const char *url, const char *extra_headers, const char *post_data) {

  struct mg_connect_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_connect_http_opt(mgr, MG_CB(ev_handler, user_data), opts, url, extra_headers, post_data);
}

size_t mg_parse_multipart(const char *buf, size_t buf_len, char *var_name, size_t var_name_len, char *file_name, size_t file_name_len, const char **data, size_t *data_len) {


  static const char cd[] = "Content-Disposition: ";
  size_t hl, bl, n, ll, pos, cdl = sizeof(cd) - 1;
  int shl;

  if (buf == NULL || buf_len <= 0) return 0;
  if ((shl = mg_http_get_request_len(buf, buf_len)) <= 0) return 0;
  hl = shl;
  if (buf[0] != '-' || buf[1] != '-' || buf[2] == '\n') return 0;

  
  bl = mg_get_line_len(buf, buf_len);

  
  var_name[0] = file_name[0] = '\0';
  for (n = bl; (ll = mg_get_line_len(buf + n, hl - n)) > 0; n += ll) {
    if (mg_ncasecmp(cd, buf + n, cdl) == 0) {
      struct mg_str header;
      header.p = buf + n + cdl;
      header.len = ll - (cdl + 2);
      {
        char *var_name2 = var_name;
        mg_http_parse_header2(&header, "name", &var_name2, var_name_len);
        
        if (var_name2 != var_name) {
          MG_FREE(var_name2);
          var_name[0] = '\0';
        }
      }
      {
        char *file_name2 = file_name;
        mg_http_parse_header2(&header, "filename", &file_name2, file_name_len);
        
        if (file_name2 != file_name) {
          MG_FREE(file_name2);
          file_name[0] = '\0';
        }
      }
    }
  }

  
  for (pos = hl; pos + (bl - 2) < buf_len; pos++) {
    if (buf[pos] == '-' && !strncmp(buf, &buf[pos], bl - 2)) {
      if (data_len != NULL) *data_len = (pos - 2) - hl;
      if (data != NULL) *data = buf + hl;
      return pos;
    }
  }

  return 0;
}

void mg_register_http_endpoint_opt(struct mg_connection *nc, const char *uri_path, mg_event_handler_t handler, struct mg_http_endpoint_opts opts) {


  struct mg_http_proto_data *pd = NULL;
  struct mg_http_endpoint *new_ep = NULL;

  if (nc == NULL) return;
  new_ep = (struct mg_http_endpoint *) MG_CALLOC(1, sizeof(*new_ep));
  if (new_ep == NULL) return;

  pd = mg_http_get_proto_data(nc);
  new_ep->uri_pattern = mg_strdup(mg_mk_str(uri_path));
  if (opts.auth_domain != NULL && opts.auth_file != NULL) {
    new_ep->auth_domain = strdup(opts.auth_domain);
    new_ep->auth_file = strdup(opts.auth_file);
  }
  new_ep->handler = handler;

  new_ep->user_data = opts.user_data;

  new_ep->next = pd->endpoints;
  pd->endpoints = new_ep;
}

static void mg_http_call_endpoint_handler(struct mg_connection *nc, int ev, struct http_message *hm) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  void *user_data = nc->user_data;

  if (ev == MG_EV_HTTP_REQUEST  || ev == MG_EV_HTTP_MULTIPART_REQUEST  ) {



    struct mg_http_endpoint *ep = mg_http_get_endpoint_handler(nc->listener, &hm->uri);
    if (ep != NULL) {

      if (!mg_http_is_authorized(hm, hm->uri, ep->auth_domain, ep->auth_file, MG_AUTH_FLAG_IS_GLOBAL_PASS_FILE)) {
        mg_http_send_digest_auth_request(nc, ep->auth_domain);
        return;
      }

      pd->endpoint_handler = ep->handler;

      user_data = ep->user_data;

    }
  }
  mg_call(nc, pd->endpoint_handler ? pd->endpoint_handler : nc->handler, user_data, ev, hm);
}

void mg_register_http_endpoint(struct mg_connection *nc, const char *uri_path, MG_CB(mg_event_handler_t handler, void *user_data)) {

  struct mg_http_endpoint_opts opts;
  memset(&opts, 0, sizeof(opts));

  opts.user_data = user_data;

  mg_register_http_endpoint_opt(nc, uri_path, handler, opts);
}
























struct mg_cgi_env_block {
  struct mg_connection *nc;
  char buf[MG_CGI_ENVIRONMENT_SIZE];       
  const char *vars[MG_MAX_CGI_ENVIR_VARS]; 
  int len;                                 
  int nvars;                               
};


struct mg_threadparam {
  sock_t s;
  HANDLE hPipe;
};

static int mg_wait_until_ready(sock_t sock, int for_read) {
  fd_set set;
  FD_ZERO(&set);
  FD_SET(sock, &set);
  return select(sock + 1, for_read ? &set : 0, for_read ? 0 : &set, 0, 0) == 1;
}

static void *mg_push_to_stdin(void *arg) {
  struct mg_threadparam *tp = (struct mg_threadparam *) arg;
  int n, sent, stop = 0;
  DWORD k;
  char buf[BUFSIZ];

  while (!stop && mg_wait_until_ready(tp->s, 1) && (n = recv(tp->s, buf, sizeof(buf), 0)) > 0) {
    if (n == -1 && GetLastError() == WSAEWOULDBLOCK) continue;
    for (sent = 0; !stop && sent < n; sent += k) {
      if (!WriteFile(tp->hPipe, buf + sent, n - sent, &k, 0)) stop = 1;
    }
  }
  DBG(("%s", "FORWARED EVERYTHING TO CGI"));
  CloseHandle(tp->hPipe);
  MG_FREE(tp);
  return NULL;
}

static void *mg_pull_from_stdout(void *arg) {
  struct mg_threadparam *tp = (struct mg_threadparam *) arg;
  int k = 0, stop = 0;
  DWORD n, sent;
  char buf[BUFSIZ];

  while (!stop && ReadFile(tp->hPipe, buf, sizeof(buf), &n, NULL)) {
    for (sent = 0; !stop && sent < n; sent += k) {
      if (mg_wait_until_ready(tp->s, 0) && (k = send(tp->s, buf + sent, n - sent, 0)) <= 0)
        stop = 1;
    }
  }
  DBG(("%s", "EOF FROM CGI"));
  CloseHandle(tp->hPipe);
  shutdown(tp->s, 2);  
  closesocket(tp->s);
  MG_FREE(tp);
  return NULL;
}

static void mg_spawn_stdio_thread(sock_t sock, HANDLE hPipe, void *(*func)(void *)) {
  struct mg_threadparam *tp = (struct mg_threadparam *) MG_MALLOC(sizeof(*tp));
  if (tp != NULL) {
    tp->s = sock;
    tp->hPipe = hPipe;
    mg_start_thread(func, tp);
  }
}

static void mg_abs_path(const char *utf8_path, char *abs_path, size_t len) {
  wchar_t buf[MG_MAX_PATH], buf2[MG_MAX_PATH];
  to_wchar(utf8_path, buf, ARRAY_SIZE(buf));
  GetFullPathNameW(buf, ARRAY_SIZE(buf2), buf2, NULL);
  WideCharToMultiByte(CP_UTF8, 0, buf2, wcslen(buf2) + 1, abs_path, len, 0, 0);
}

static int mg_start_process(const char *interp, const char *cmd, const char *env, const char *envp[], const char *dir, sock_t sock) {

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  HANDLE a[2], b[2], me = GetCurrentProcess();
  wchar_t wcmd[MG_MAX_PATH], full_dir[MG_MAX_PATH];
  char buf[MG_MAX_PATH], buf2[MG_MAX_PATH], buf5[MG_MAX_PATH], buf4[MG_MAX_PATH], cmdline[MG_MAX_PATH];
  DWORD flags = DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS;
  FILE *fp;

  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));

  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  CreatePipe(&a[0], &a[1], NULL, 0);
  CreatePipe(&b[0], &b[1], NULL, 0);
  DuplicateHandle(me, a[0], me, &si.hStdInput, 0, TRUE, flags);
  DuplicateHandle(me, b[1], me, &si.hStdOutput, 0, TRUE, flags);

  if (interp == NULL && (fp = mg_fopen(cmd, "r")) != NULL) {
    buf[0] = buf[1] = '\0';
    fgets(buf, sizeof(buf), fp);
    buf[sizeof(buf) - 1] = '\0';
    if (buf[0] == '#' && buf[1] == '!') {
      interp = buf + 2;
      
      while (*interp != '\0' && isspace(*(unsigned char *) interp)) {
        interp++;
      }
    }
    fclose(fp);
  }

  snprintf(buf, sizeof(buf), "%s/%s", dir, cmd);
  mg_abs_path(buf, buf2, ARRAY_SIZE(buf2));

  mg_abs_path(dir, buf5, ARRAY_SIZE(buf5));
  to_wchar(dir, full_dir, ARRAY_SIZE(full_dir));

  if (interp != NULL) {
    mg_abs_path(interp, buf4, ARRAY_SIZE(buf4));
    snprintf(cmdline, sizeof(cmdline), "%s \"%s\"", buf4, buf2);
  } else {
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", buf2);
  }
  to_wchar(cmdline, wcmd, ARRAY_SIZE(wcmd));

  if (CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP, (void *) env, full_dir, &si, &pi) != 0) {
    mg_spawn_stdio_thread(sock, a[1], mg_push_to_stdin);
    mg_spawn_stdio_thread(sock, b[0], mg_pull_from_stdout);

    CloseHandle(si.hStdOutput);
    CloseHandle(si.hStdInput);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  } else {
    CloseHandle(a[1]);
    CloseHandle(b[0]);
    closesocket(sock);
  }
  DBG(("CGI command: [%ls] -> %p", wcmd, pi.hProcess));

  
  (void) envp;
  return (pi.hProcess != NULL);
}

static int mg_start_process(const char *interp, const char *cmd, const char *env, const char *envp[], const char *dir, sock_t sock) {

  char buf[500];
  pid_t pid = fork();
  (void) env;

  if (pid == 0) {
    
    int tmp = chdir(dir);
    (void) tmp;
    (void) dup2(sock, 0);
    (void) dup2(sock, 1);
    closesocket(sock);

    
    signal(SIGCHLD, SIG_DFL);

    if (interp == NULL) {
      execle(cmd, cmd, (char *) 0, envp); 
    } else {
      execle(interp, interp, cmd, (char *) 0, envp);
    }
    snprintf(buf, sizeof(buf), "Status: 500\r\n\r\n" "500 Server Error: %s%s%s: %s", interp == NULL ? "" : interp, interp == NULL ? "" : " ", cmd, strerror(errno));



    send(1, buf, strlen(buf), 0);
    _exit(EXIT_FAILURE); 
  }

  return (pid != 0);
}



static char *mg_addenv(struct mg_cgi_env_block *block, const char *fmt, ...) {
  int n, space;
  char *added = block->buf + block->len;
  va_list ap;

  
  space = sizeof(block->buf) - (block->len + 2);
  if (space > 0) {
    
    va_start(ap, fmt);
    n = vsnprintf(added, (size_t) space, fmt, ap);
    va_end(ap);

    
    if (n > 0 && n + 1 < space && block->nvars < (int) ARRAY_SIZE(block->vars) - 2) {
      
      block->vars[block->nvars++] = added;
      
      block->len += n + 1;
    }
  }

  return added;
}

static void mg_addenv2(struct mg_cgi_env_block *blk, const char *name) {
  const char *s;
  if ((s = getenv(name)) != NULL) mg_addenv(blk, "%s=%s", name, s);
}

static void mg_prepare_cgi_environment(struct mg_connection *nc, const char *prog, const struct mg_str *path_info, const struct http_message *hm, const struct mg_serve_http_opts *opts, struct mg_cgi_env_block *blk) {




  const char *s;
  struct mg_str *h;
  char *p;
  size_t i;
  char buf[100];
  size_t path_info_len = path_info != NULL ? path_info->len : 0;

  blk->len = blk->nvars = 0;
  blk->nc = nc;

  if ((s = getenv("SERVER_NAME")) != NULL) {
    mg_addenv(blk, "SERVER_NAME=%s", s);
  } else {
    mg_sock_to_str(nc->sock, buf, sizeof(buf), 3);
    mg_addenv(blk, "SERVER_NAME=%s", buf);
  }
  mg_addenv(blk, "SERVER_ROOT=%s", opts->document_root);
  mg_addenv(blk, "DOCUMENT_ROOT=%s", opts->document_root);
  mg_addenv(blk, "SERVER_SOFTWARE=%s/%s", "Mongoose", MG_VERSION);

  
  mg_addenv(blk, "%s", "GATEWAY_INTERFACE=CGI/1.1");
  mg_addenv(blk, "%s", "SERVER_PROTOCOL=HTTP/1.1");
  mg_addenv(blk, "%s", "REDIRECT_STATUS=200"); 

  mg_addenv(blk, "REQUEST_METHOD=%.*s", (int) hm->method.len, hm->method.p);

  mg_addenv(blk, "REQUEST_URI=%.*s%s%.*s", (int) hm->uri.len, hm->uri.p, hm->query_string.len == 0 ? "" : "?", (int) hm->query_string.len, hm->query_string.p);


  mg_conn_addr_to_str(nc, buf, sizeof(buf), MG_SOCK_STRINGIFY_REMOTE | MG_SOCK_STRINGIFY_IP);
  mg_addenv(blk, "REMOTE_ADDR=%s", buf);
  mg_conn_addr_to_str(nc, buf, sizeof(buf), MG_SOCK_STRINGIFY_PORT);
  mg_addenv(blk, "SERVER_PORT=%s", buf);

  s = hm->uri.p + hm->uri.len - path_info_len - 1;
  if (*s == '/') {
    const char *base_name = strrchr(prog, DIRSEP);
    mg_addenv(blk, "SCRIPT_NAME=%.*s/%s", (int) (s - hm->uri.p), hm->uri.p, (base_name != NULL ? base_name + 1 : prog));
  } else {
    mg_addenv(blk, "SCRIPT_NAME=%.*s", (int) (s - hm->uri.p + 1), hm->uri.p);
  }
  mg_addenv(blk, "SCRIPT_FILENAME=%s", prog);

  if (path_info != NULL && path_info->len > 0) {
    mg_addenv(blk, "PATH_INFO=%.*s", (int) path_info->len, path_info->p);
    
    mg_addenv(blk, "PATH_TRANSLATED=%.*s", (int) path_info->len, path_info->p);
  }


  mg_addenv(blk, "HTTPS=%s", (nc->flags & MG_F_SSL ? "on" : "off"));

  mg_addenv(blk, "HTTPS=off");


  if ((h = mg_get_http_header((struct http_message *) hm, "Content-Type")) != NULL) {
    mg_addenv(blk, "CONTENT_TYPE=%.*s", (int) h->len, h->p);
  }

  if (hm->query_string.len > 0) {
    mg_addenv(blk, "QUERY_STRING=%.*s", (int) hm->query_string.len, hm->query_string.p);
  }

  if ((h = mg_get_http_header((struct http_message *) hm, "Content-Length")) != NULL) {
    mg_addenv(blk, "CONTENT_LENGTH=%.*s", (int) h->len, h->p);
  }

  mg_addenv2(blk, "PATH");
  mg_addenv2(blk, "TMP");
  mg_addenv2(blk, "TEMP");
  mg_addenv2(blk, "TMPDIR");
  mg_addenv2(blk, "PERLLIB");
  mg_addenv2(blk, MG_ENV_EXPORT_TO_CGI);


  mg_addenv2(blk, "COMSPEC");
  mg_addenv2(blk, "SYSTEMROOT");
  mg_addenv2(blk, "SystemDrive");
  mg_addenv2(blk, "ProgramFiles");
  mg_addenv2(blk, "ProgramFiles(x86)");
  mg_addenv2(blk, "CommonProgramFiles(x86)");

  mg_addenv2(blk, "LD_LIBRARY_PATH");


  
  for (i = 0; hm->header_names[i].len > 0; i++) {
    p = mg_addenv(blk, "HTTP_%.*s=%.*s", (int) hm->header_names[i].len, hm->header_names[i].p, (int) hm->header_values[i].len, hm->header_values[i].p);


    
    for (; *p != '=' && *p != '\0'; p++) {
      if (*p == '-') *p = '_';
      *p = (char) toupper(*(unsigned char *) p);
    }
  }

  blk->vars[blk->nvars++] = NULL;
  blk->buf[blk->len++] = '\0';
}

static void mg_cgi_ev_handler(struct mg_connection *cgi_nc, int ev, void *ev_data MG_UD_ARG(void *user_data)) {

  void *user_data = cgi_nc->user_data;

  struct mg_connection *nc = (struct mg_connection *) user_data;
  (void) ev_data;

  if (nc == NULL) {
    
    cgi_nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    return;
  }

  switch (ev) {
    case MG_EV_RECV:
      
      if (nc->flags & MG_F_HTTP_CGI_PARSE_HEADERS) {
        struct mbuf *io = &cgi_nc->recv_mbuf;
        int len = mg_http_get_request_len(io->buf, io->len);

        if (len == 0) break;
        if (len < 0 || io->len > MG_MAX_HTTP_REQUEST_SIZE) {
          cgi_nc->flags |= MG_F_CLOSE_IMMEDIATELY;
          mg_http_send_error(nc, 500, "Bad headers");
        } else {
          struct http_message hm;
          struct mg_str *h;
          mg_http_parse_headers(io->buf, io->buf + io->len, io->len, &hm);
          if (mg_get_http_header(&hm, "Location") != NULL) {
            mg_printf(nc, "%s", "HTTP/1.1 302 Moved\r\n");
          } else if ((h = mg_get_http_header(&hm, "Status")) != NULL) {
            mg_printf(nc, "HTTP/1.1 %.*s\r\n", (int) h->len, h->p);
          } else {
            mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\n");
          }
        }
        nc->flags &= ~MG_F_HTTP_CGI_PARSE_HEADERS;
      }
      if (!(nc->flags & MG_F_HTTP_CGI_PARSE_HEADERS)) {
        mg_forward(cgi_nc, nc);
      }
      break;
    case MG_EV_CLOSE:
      DBG(("%p CLOSE", cgi_nc));
      mg_http_free_proto_data_cgi(&mg_http_get_proto_data(nc)->cgi);
      nc->flags |= MG_F_SEND_AND_CLOSE;
      break;
  }
}

MG_INTERNAL void mg_handle_cgi(struct mg_connection *nc, const char *prog, const struct mg_str *path_info, const struct http_message *hm, const struct mg_serve_http_opts *opts) {


  struct mg_cgi_env_block blk;
  char dir[MG_MAX_PATH];
  const char *p;
  sock_t fds[2];

  DBG(("%p [%s]", nc, prog));
  mg_prepare_cgi_environment(nc, prog, path_info, hm, opts, &blk);
  
  if ((p = strrchr(prog, DIRSEP)) == NULL) {
    snprintf(dir, sizeof(dir), "%s", ".");
  } else {
    snprintf(dir, sizeof(dir), "%.*s", (int) (p - prog), prog);
    prog = p + 1;
  }

  if (!mg_socketpair(fds, SOCK_STREAM)) {
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    return;
  }


  struct sigaction sa;

  sigemptyset(&sa.sa_mask);
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigaction(SIGCHLD, &sa, NULL);


  if (mg_start_process(opts->cgi_interpreter, prog, blk.buf, blk.vars, dir, fds[1]) != 0) {
    size_t n = nc->recv_mbuf.len - (hm->message.len - hm->body.len);
    struct mg_connection *cgi_nc = mg_add_sock(nc->mgr, fds[0], mg_cgi_ev_handler MG_UD_ARG(nc));
    struct mg_http_proto_data *cgi_pd = mg_http_get_proto_data(nc);
    cgi_pd->cgi.cgi_nc = cgi_nc;

    cgi_pd->cgi.cgi_nc->user_data = nc;

    nc->flags |= MG_F_HTTP_CGI_PARSE_HEADERS;
    
    if (n > 0 && n < nc->recv_mbuf.len) {
      mg_send(cgi_pd->cgi.cgi_nc, hm->body.p, n);
    }
    mbuf_remove(&nc->recv_mbuf, nc->recv_mbuf.len);
  } else {
    closesocket(fds[0]);
    mg_http_send_error(nc, 500, "CGI failure");
  }


  closesocket(fds[1]); 

}

MG_INTERNAL void mg_http_free_proto_data_cgi(struct mg_http_proto_data_cgi *d) {
  if (d == NULL) return;
  if (d->cgi_nc != NULL) {
    d->cgi_nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    d->cgi_nc->user_data = NULL;
  }
  memset(d, 0, sizeof(*d));
}









static void mg_send_ssi_file(struct mg_connection *nc, struct http_message *hm, const char *path, FILE *fp, int include_level, const struct mg_serve_http_opts *opts);


static void mg_send_file_data(struct mg_connection *nc, FILE *fp) {
  char buf[BUFSIZ];
  size_t n;
  while ((n = mg_fread(buf, 1, sizeof(buf), fp)) > 0) {
    mg_send(nc, buf, n);
  }
}

static void mg_do_ssi_include(struct mg_connection *nc, struct http_message *hm, const char *ssi, char *tag, int include_level, const struct mg_serve_http_opts *opts) {

  char file_name[MG_MAX_PATH], path[MG_MAX_PATH], *p;
  FILE *fp;

  
  if (sscanf(tag, " virtual=\"%[^\"]\"", file_name) == 1) {
    
    snprintf(path, sizeof(path), "%s/%s", opts->document_root, file_name);
  } else if (sscanf(tag, " abspath=\"%[^\"]\"", file_name) == 1) {
    
    snprintf(path, sizeof(path), "%s", file_name);
  } else if (sscanf(tag, " file=\"%[^\"]\"", file_name) == 1 || sscanf(tag, " \"%[^\"]\"", file_name) == 1) {
    
    snprintf(path, sizeof(path), "%s", ssi);
    if ((p = strrchr(path, DIRSEP)) != NULL) {
      p[1] = '\0';
    }
    snprintf(path + strlen(path), sizeof(path) - strlen(path), "%s", file_name);
  } else {
    mg_printf(nc, "Bad SSI #include: [%s]", tag);
    return;
  }

  if ((fp = mg_fopen(path, "rb")) == NULL) {
    mg_printf(nc, "SSI include error: mg_fopen(%s): %s", path, strerror(mg_get_errno()));
  } else {
    mg_set_close_on_exec((sock_t) fileno(fp));
    if (mg_match_prefix(opts->ssi_pattern, strlen(opts->ssi_pattern), path) > 0) {
      mg_send_ssi_file(nc, hm, path, fp, include_level + 1, opts);
    } else {
      mg_send_file_data(nc, fp);
    }
    fclose(fp);
  }
}


static void do_ssi_exec(struct mg_connection *nc, char *tag) {
  char cmd[BUFSIZ];
  FILE *fp;

  if (sscanf(tag, " \"%[^\"]\"", cmd) != 1) {
    mg_printf(nc, "Bad SSI #exec: [%s]", tag);
  } else if ((fp = popen(cmd, "r")) == NULL) {
    mg_printf(nc, "Cannot SSI #exec: [%s]: %s", cmd, strerror(mg_get_errno()));
  } else {
    mg_send_file_data(nc, fp);
    pclose(fp);
  }
}



static void mg_send_ssi_file(struct mg_connection *nc, struct http_message *hm, const char *path, FILE *fp, int include_level, const struct mg_serve_http_opts *opts) {

  static const struct mg_str btag = MG_MK_STR("<!--#");
  static const struct mg_str d_include = MG_MK_STR("include");
  static const struct mg_str d_call = MG_MK_STR("call");

  static const struct mg_str d_exec = MG_MK_STR("exec");

  char buf[BUFSIZ], *p = buf + btag.len; 
  int ch, len, in_ssi_tag;

  if (include_level > 10) {
    mg_printf(nc, "SSI #include level is too deep (%s)", path);
    return;
  }

  in_ssi_tag = len = 0;
  while ((ch = fgetc(fp)) != EOF) {
    if (in_ssi_tag && ch == '>' && buf[len - 1] == '-' && buf[len - 2] == '-') {
      size_t i = len - 2;
      in_ssi_tag = 0;

      
      buf[i--] = '\0';
      while (i > 0 && buf[i] == ' ') {
        buf[i--] = '\0';
      }

      
      if (strncmp(p, d_include.p, d_include.len) == 0) {
        mg_do_ssi_include(nc, hm, path, p + d_include.len + 1, include_level, opts);
      } else if (strncmp(p, d_call.p, d_call.len) == 0) {
        struct mg_ssi_call_ctx cctx;
        memset(&cctx, 0, sizeof(cctx));
        cctx.req = hm;
        cctx.file = mg_mk_str(path);
        cctx.arg = mg_mk_str(p + d_call.len + 1);
        mg_call(nc, NULL, nc->user_data, MG_EV_SSI_CALL, (void *) cctx.arg.p);
        mg_call(nc, NULL, nc->user_data, MG_EV_SSI_CALL_CTX, &cctx);

      } else if (strncmp(p, d_exec.p, d_exec.len) == 0) {
        do_ssi_exec(nc, p + d_exec.len + 1);

      } else {
        
      }
      len = 0;
    } else if (ch == '<') {
      in_ssi_tag = 1;
      if (len > 0) {
        mg_send(nc, buf, (size_t) len);
      }
      len = 0;
      buf[len++] = ch & 0xff;
    } else if (in_ssi_tag) {
      if (len == (int) btag.len && strncmp(buf, btag.p, btag.len) != 0) {
        
        in_ssi_tag = 0;
      } else if (len == (int) sizeof(buf) - 2) {
        mg_printf(nc, "%s: SSI tag is too large", path);
        len = 0;
      }
      buf[len++] = ch & 0xff;
    } else {
      buf[len++] = ch & 0xff;
      if (len == (int) sizeof(buf)) {
        mg_send(nc, buf, (size_t) len);
        len = 0;
      }
    }
  }

  
  if (len > 0) {
    mg_send(nc, buf, (size_t) len);
  }
}

MG_INTERNAL void mg_handle_ssi_request(struct mg_connection *nc, struct http_message *hm, const char *path, const struct mg_serve_http_opts *opts) {


  FILE *fp;
  struct mg_str mime_type;
  DBG(("%p %s", nc, path));

  if ((fp = mg_fopen(path, "rb")) == NULL) {
    mg_http_send_error(nc, 404, NULL);
  } else {
    mg_set_close_on_exec((sock_t) fileno(fp));

    mime_type = mg_get_mime_type(path, "text/plain", opts);
    mg_send_response_line(nc, 200, opts->extra_headers);
    mg_printf(nc, "Content-Type: %.*s\r\n" "Connection: close\r\n\r\n", (int) mime_type.len, mime_type.p);


    mg_send_ssi_file(nc, hm, path, fp, 0, opts);
    fclose(fp);
    nc->flags |= MG_F_SEND_AND_CLOSE;
  }
}









MG_INTERNAL int mg_is_dav_request(const struct mg_str *s) {
  static const char *methods[] = {
    "PUT", "DELETE", "MKCOL", "PROPFIND", "MOVE"  , "LOCK", "UNLOCK"  };









  size_t i;

  for (i = 0; i < ARRAY_SIZE(methods); i++) {
    if (mg_vcmp(s, methods[i]) == 0) {
      return 1;
    }
  }

  return 0;
}

static int mg_mkdir(const char *path, uint32_t mode) {

  return mkdir(path, mode);

  (void) mode;
  return _mkdir(path);

}

static void mg_print_props(struct mg_connection *nc, const char *name, cs_stat_t *stp) {
  char mtime[64];
  time_t t = stp->st_mtime; 
  struct mg_str name_esc = mg_url_encode(mg_mk_str(name));
  mg_gmt_time_string(mtime, sizeof(mtime), &t);
  mg_printf(nc, "<d:response>" "<d:href>%s</d:href>" "<d:propstat>" "<d:prop>" "<d:resourcetype>%s</d:resourcetype>" "<d:getcontentlength>%" INT64_FMT "</d:getcontentlength>" "<d:getlastmodified>%s</d:getlastmodified>" "</d:prop>" "<d:status>HTTP/1.1 200 OK</d:status>" "</d:propstat>" "</d:response>\n", name_esc.p, S_ISDIR(stp->st_mode) ? "<d:collection/>" : "", (int64_t) stp->st_size, mtime);













  free((void *) name_esc.p);
}

MG_INTERNAL void mg_handle_propfind(struct mg_connection *nc, const char *path, cs_stat_t *stp, struct http_message *hm, struct mg_serve_http_opts *opts) {

  static const char header[] = "HTTP/1.1 207 Multi-Status\r\n" "Connection: close\r\n" "Content-Type: text/xml; charset=utf-8\r\n\r\n" "<?xml version=\"1.0\" encoding=\"utf-8\"?>" "<d:multistatus xmlns:d='DAV:'>\n";




  static const char footer[] = "</d:multistatus>\n";
  const struct mg_str *depth = mg_get_http_header(hm, "Depth");

  
  if (S_ISDIR(stp->st_mode) && strcmp(opts->enable_directory_listing, "yes") != 0) {
    mg_printf(nc, "%s", "HTTP/1.1 403 Directory Listing Denied\r\n\r\n");
  } else {
    char uri[MG_MAX_PATH];
    mg_send(nc, header, sizeof(header) - 1);
    snprintf(uri, sizeof(uri), "%.*s", (int) hm->uri.len, hm->uri.p);
    mg_print_props(nc, uri, stp);
    if (S_ISDIR(stp->st_mode) && (depth == NULL || mg_vcmp(depth, "0") != 0)) {
      mg_scan_directory(nc, path, opts, mg_print_props);
    }
    mg_send(nc, footer, sizeof(footer) - 1);
    nc->flags |= MG_F_SEND_AND_CLOSE;
  }
}



MG_INTERNAL void mg_handle_lock(struct mg_connection *nc, const char *path) {
  static const char *reply = "HTTP/1.1 207 Multi-Status\r\n" "Connection: close\r\n" "Content-Type: text/xml; charset=utf-8\r\n\r\n" "<?xml version=\"1.0\" encoding=\"utf-8\"?>" "<d:multistatus xmlns:d='DAV:'>\n" "<D:lockdiscovery>\n" "<D:activelock>\n" "<D:locktoken>\n" "<D:href>\n" "opaquelocktoken:%s%u" "</D:href>" "</D:locktoken>" "</D:activelock>\n" "</D:lockdiscovery>" "</d:multistatus>\n";














  mg_printf(nc, reply, path, (unsigned int) mg_time());
  nc->flags |= MG_F_SEND_AND_CLOSE;
}


MG_INTERNAL void mg_handle_mkcol(struct mg_connection *nc, const char *path, struct http_message *hm) {
  int status_code = 500;
  if (hm->body.len != (size_t) ~0 && hm->body.len > 0) {
    status_code = 415;
  } else if (!mg_mkdir(path, 0755)) {
    status_code = 201;
  } else if (errno == EEXIST) {
    status_code = 405;
  } else if (errno == EACCES) {
    status_code = 403;
  } else if (errno == ENOENT) {
    status_code = 409;
  } else {
    status_code = 500;
  }
  mg_http_send_error(nc, status_code, NULL);
}

static int mg_remove_directory(const struct mg_serve_http_opts *opts, const char *dir) {
  char path[MG_MAX_PATH];
  struct dirent *dp;
  cs_stat_t st;
  DIR *dirp;

  if ((dirp = opendir(dir)) == NULL) return 0;

  while ((dp = readdir(dirp)) != NULL) {
    if (mg_is_file_hidden((const char *) dp->d_name, opts, 1)) {
      continue;
    }
    snprintf(path, sizeof(path), "%s%c%s", dir, '/', dp->d_name);
    mg_stat(path, &st);
    if (S_ISDIR(st.st_mode)) {
      mg_remove_directory(opts, path);
    } else {
      remove(path);
    }
  }
  closedir(dirp);
  rmdir(dir);

  return 1;
}

MG_INTERNAL void mg_handle_move(struct mg_connection *c, const struct mg_serve_http_opts *opts, const char *path, struct http_message *hm) {

  const struct mg_str *dest = mg_get_http_header(hm, "Destination");
  if (dest == NULL) {
    mg_http_send_error(c, 411, NULL);
  } else {
    const char *p = (char *) memchr(dest->p, '/', dest->len);
    if (p != NULL && p[1] == '/' && (p = (char *) memchr(p + 2, '/', dest->p + dest->len - p)) != NULL) {
      char buf[MG_MAX_PATH];
      snprintf(buf, sizeof(buf), "%s%.*s", opts->dav_document_root, (int) (dest->p + dest->len - p), p);
      if (rename(path, buf) == 0) {
        mg_http_send_error(c, 200, NULL);
      } else {
        mg_http_send_error(c, 418, NULL);
      }
    } else {
      mg_http_send_error(c, 500, NULL);
    }
  }
}

MG_INTERNAL void mg_handle_delete(struct mg_connection *nc, const struct mg_serve_http_opts *opts, const char *path) {

  cs_stat_t st;
  if (mg_stat(path, &st) != 0) {
    mg_http_send_error(nc, 404, NULL);
  } else if (S_ISDIR(st.st_mode)) {
    mg_remove_directory(opts, path);
    mg_http_send_error(nc, 204, NULL);
  } else if (remove(path) == 0) {
    mg_http_send_error(nc, 204, NULL);
  } else {
    mg_http_send_error(nc, 423, NULL);
  }
}


static int mg_create_itermediate_directories(const char *path) {
  const char *s;

  
  for (s = path + 1; *s != '\0'; s++) {
    if (*s == '/') {
      char buf[MG_MAX_PATH];
      cs_stat_t st;
      snprintf(buf, sizeof(buf), "%.*s", (int) (s - path), path);
      buf[sizeof(buf) - 1] = '\0';
      if (mg_stat(buf, &st) != 0 && mg_mkdir(buf, 0755) != 0) {
        return -1;
      }
    }
  }

  return 1;
}

MG_INTERNAL void mg_handle_put(struct mg_connection *nc, const char *path, struct http_message *hm) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  cs_stat_t st;
  const struct mg_str *cl_hdr = mg_get_http_header(hm, "Content-Length");
  int rc, status_code = mg_stat(path, &st) == 0 ? 200 : 201;

  mg_http_free_proto_data_file(&pd->file);
  if ((rc = mg_create_itermediate_directories(path)) == 0) {
    mg_printf(nc, "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", status_code);
  } else if (rc == -1) {
    mg_http_send_error(nc, 500, NULL);
  } else if (cl_hdr == NULL) {
    mg_http_send_error(nc, 411, NULL);
  } else if ((pd->file.fp = mg_fopen(path, "w+b")) == NULL) {
    mg_http_send_error(nc, 500, NULL);
  } else {
    const struct mg_str *range_hdr = mg_get_http_header(hm, "Content-Range");
    int64_t r1 = 0, r2 = 0;
    pd->file.type = DATA_PUT;
    mg_set_close_on_exec((sock_t) fileno(pd->file.fp));
    pd->file.cl = to64(cl_hdr->p);
    if (range_hdr != NULL && mg_http_parse_range_header(range_hdr, &r1, &r2) > 0) {
      status_code = 206;
      fseeko(pd->file.fp, r1, SEEK_SET);
      pd->file.cl = r2 > r1 ? r2 - r1 + 1 : pd->file.cl - r1;
    }
    mg_printf(nc, "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", status_code);
    
    mbuf_remove(&nc->recv_mbuf, hm->message.len - hm->body.len);
    mg_http_transfer_file_data(nc);
  }
}


















static int mg_is_ws_fragment(unsigned char flags) {
  return (flags & FLAGS_MASK_FIN) == 0 || (flags & FLAGS_MASK_OP) == WEBSOCKET_OP_CONTINUE;
}

static int mg_is_ws_first_fragment(unsigned char flags) {
  return (flags & FLAGS_MASK_FIN) == 0 && (flags & FLAGS_MASK_OP) != WEBSOCKET_OP_CONTINUE;
}

static int mg_is_ws_control_frame(unsigned char flags) {
  unsigned char op = (flags & FLAGS_MASK_OP);
  return op == WEBSOCKET_OP_CLOSE || op == WEBSOCKET_OP_PING || op == WEBSOCKET_OP_PONG;
}

static void mg_handle_incoming_websocket_frame(struct mg_connection *nc, struct websocket_message *wsm) {
  if (wsm->flags & 0x8) {
    mg_call(nc, nc->handler, nc->user_data, MG_EV_WEBSOCKET_CONTROL_FRAME, wsm);
  } else {
    mg_call(nc, nc->handler, nc->user_data, MG_EV_WEBSOCKET_FRAME, wsm);
  }
}

static struct mg_ws_proto_data *mg_ws_get_proto_data(struct mg_connection *nc) {
  struct mg_http_proto_data *htd = mg_http_get_proto_data(nc);
  return (htd != NULL ? &htd->ws_data : NULL);
}


static void mg_ws_close(struct mg_connection *nc, const void *data, size_t len) {
  if ((int) len == ~0) {
    len = strlen((const char *) data);
  }
  mg_send_websocket_frame(nc, WEBSOCKET_OP_CLOSE, data, len);
  nc->flags |= MG_F_SEND_AND_CLOSE;
}

static int mg_deliver_websocket_data(struct mg_connection *nc) {
  
  uint64_t i, data_len = 0, frame_len = 0, new_data_len = nc->recv_mbuf.len, len, mask_len = 0, header_len = 0;
  struct mg_ws_proto_data *wsd = mg_ws_get_proto_data(nc);
  unsigned char *new_data = (unsigned char *) nc->recv_mbuf.buf, *e = (unsigned char *) nc->recv_mbuf.buf + nc->recv_mbuf.len;
  uint8_t flags;
  int ok, reass;

  if (wsd->reass_len > 0) {
    

    size_t existing_len = wsd->reass_len;
    assert(new_data_len >= existing_len);

    new_data += existing_len;
    new_data_len -= existing_len;
  }

  flags = new_data[0];

  reass = new_data_len > 0 && mg_is_ws_fragment(flags) && !(nc->flags & MG_F_WEBSOCKET_NO_DEFRAG);

  if (reass && mg_is_ws_control_frame(flags)) {
    
    mg_ws_close(nc, "fragmented control frames are illegal", ~0);
    return 0;
  } else if (new_data_len > 0 && !reass && !mg_is_ws_control_frame(flags) && wsd->reass_len > 0) {
    
    mg_ws_close(nc, "non-continuation in the middle of a fragmented message", ~0);
    return 0;
  }

  if (new_data_len >= 2) {
    len = new_data[1] & 0x7f;
    mask_len = new_data[1] & FLAGS_MASK_FIN ? 4 : 0;
    if (len < 126 && new_data_len >= mask_len) {
      data_len = len;
      header_len = 2 + mask_len;
    } else if (len == 126 && new_data_len >= 4 + mask_len) {
      header_len = 4 + mask_len;
      data_len = ntohs(*(uint16_t *) &new_data[2]);
    } else if (new_data_len >= 10 + mask_len) {
      header_len = 10 + mask_len;
      data_len = (((uint64_t) ntohl(*(uint32_t *) &new_data[2])) << 32) + ntohl(*(uint32_t *) &new_data[6]);
    }
  }

  frame_len = header_len + data_len;
  ok = (frame_len > 0 && frame_len <= new_data_len);

  
  if (frame_len < header_len || frame_len < data_len) {
    ok = 0;
    mg_ws_close(nc, "overflowed message", ~0);
  }

  if (ok) {
    size_t cleanup_len = 0;
    struct websocket_message wsm;

    wsm.size = (size_t) data_len;
    wsm.data = new_data + header_len;
    wsm.flags = flags;

    
    if (mask_len > 0) {
      for (i = 0; i < data_len; i++) {
        new_data[i + header_len] ^= (new_data + header_len - mask_len)[i % 4];
      }
    }

    if (reass) {
      

      if (mg_is_ws_first_fragment(flags)) {
        
        new_data += 1;
        wsd->reass_len = 1 ;
      }

      
      memmove(new_data, wsm.data, e - wsm.data);
      wsd->reass_len += wsm.size;
      nc->recv_mbuf.len -= wsm.data - new_data;

      if (flags & FLAGS_MASK_FIN) {
        
        wsm.flags = FLAGS_MASK_FIN | nc->recv_mbuf.buf[0];
        wsm.data = (unsigned char *) nc->recv_mbuf.buf + 1 ;
        wsm.size = wsd->reass_len - 1 ;
        cleanup_len = wsd->reass_len;
        wsd->reass_len = 0;

        
        mg_handle_incoming_websocket_frame(nc, &wsm);
        mbuf_remove(&nc->recv_mbuf, cleanup_len); 
      }
    } else {
      
      cleanup_len = (size_t) frame_len;

      
      switch (flags & FLAGS_MASK_OP) {
        case WEBSOCKET_OP_PING:
          mg_send_websocket_frame(nc, WEBSOCKET_OP_PONG, wsm.data, wsm.size);
          break;

        case WEBSOCKET_OP_CLOSE:
          mg_ws_close(nc, wsm.data, wsm.size);
          break;
      }

      
      mg_handle_incoming_websocket_frame(nc, &wsm);

      
      memmove(nc->recv_mbuf.buf + wsd->reass_len, nc->recv_mbuf.buf + wsd->reass_len + cleanup_len, nc->recv_mbuf.len - wsd->reass_len - cleanup_len);

      nc->recv_mbuf.len -= cleanup_len;
    }
  }

  return ok;
}

struct ws_mask_ctx {
  size_t pos; 
  uint32_t mask;
};

static uint32_t mg_ws_random_mask(void) {
  uint32_t mask;


  mask = 0xefbeadde; 

  if (sizeof(long) >= 4) {
    mask = (uint32_t) rand();
  } else if (sizeof(long) == 2) {
    mask = (uint32_t) rand() << 16 | (uint32_t) rand();
  }

  return mask;
}

static void mg_send_ws_header(struct mg_connection *nc, int op, size_t len, struct ws_mask_ctx *ctx) {
  int header_len;
  unsigned char header[10];

  header[0] = (op & WEBSOCKET_DONT_FIN ? 0x0 : FLAGS_MASK_FIN) | (op & FLAGS_MASK_OP);
  if (len < 126) {
    header[1] = (unsigned char) len;
    header_len = 2;
  } else if (len < 65535) {
    uint16_t tmp = htons((uint16_t) len);
    header[1] = 126;
    memcpy(&header[2], &tmp, sizeof(tmp));
    header_len = 4;
  } else {
    uint32_t tmp;
    header[1] = 127;
    tmp = htonl((uint32_t)((uint64_t) len >> 32));
    memcpy(&header[2], &tmp, sizeof(tmp));
    tmp = htonl((uint32_t)(len & 0xffffffff));
    memcpy(&header[6], &tmp, sizeof(tmp));
    header_len = 10;
  }

  
  if (nc->listener == NULL) {
    header[1] |= 1 << 7; 
    mg_send(nc, header, header_len);
    ctx->mask = mg_ws_random_mask();
    mg_send(nc, &ctx->mask, sizeof(ctx->mask));
    ctx->pos = nc->send_mbuf.len;
  } else {
    mg_send(nc, header, header_len);
    ctx->pos = 0;
  }
}

static void mg_ws_mask_frame(struct mbuf *mbuf, struct ws_mask_ctx *ctx) {
  size_t i;
  if (ctx->pos == 0) return;
  for (i = 0; i < (mbuf->len - ctx->pos); i++) {
    mbuf->buf[ctx->pos + i] ^= ((char *) &ctx->mask)[i % 4];
  }
}

void mg_send_websocket_frame(struct mg_connection *nc, int op, const void *data, size_t len) {
  struct ws_mask_ctx ctx;
  DBG(("%p %d %d", nc, op, (int) len));
  mg_send_ws_header(nc, op, len, &ctx);
  mg_send(nc, data, len);

  mg_ws_mask_frame(&nc->send_mbuf, &ctx);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= MG_F_SEND_AND_CLOSE;
  }
}

void mg_send_websocket_framev(struct mg_connection *nc, int op, const struct mg_str *strv, int strvcnt) {
  struct ws_mask_ctx ctx;
  int i;
  int len = 0;
  for (i = 0; i < strvcnt; i++) {
    len += strv[i].len;
  }

  mg_send_ws_header(nc, op, len, &ctx);

  for (i = 0; i < strvcnt; i++) {
    mg_send(nc, strv[i].p, strv[i].len);
  }

  mg_ws_mask_frame(&nc->send_mbuf, &ctx);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= MG_F_SEND_AND_CLOSE;
  }
}

void mg_printf_websocket_frame(struct mg_connection *nc, int op, const char *fmt, ...) {
  char mem[MG_VPRINTF_BUFFER_SIZE], *buf = mem;
  va_list ap;
  int len;

  va_start(ap, fmt);
  if ((len = mg_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    mg_send_websocket_frame(nc, op, buf, len);
  }
  va_end(ap);

  if (buf != mem && buf != NULL) {
    MG_FREE(buf);
  }
}

MG_INTERNAL void mg_ws_handler(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data)) {
  mg_call(nc, nc->handler, nc->user_data, ev, ev_data);

  switch (ev) {
    case MG_EV_RECV:
      do {
      } while (mg_deliver_websocket_data(nc));
      break;
    case MG_EV_POLL:
      
      {
        time_t now = *(time_t *) ev_data;
        if (nc->flags & MG_F_IS_WEBSOCKET && now > nc->last_io_time + MG_WEBSOCKET_PING_INTERVAL_SECONDS) {
          mg_send_websocket_frame(nc, WEBSOCKET_OP_PING, "", 0);
        }
      }
      break;
    default:
      break;
  }

  (void) user_data;

}


void mg_hash_sha1_v(size_t num_msgs, const uint8_t *msgs[], const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  cs_sha1_ctx sha_ctx;
  cs_sha1_init(&sha_ctx);
  for (i = 0; i < num_msgs; i++) {
    cs_sha1_update(&sha_ctx, msgs[i], msg_lens[i]);
  }
  cs_sha1_final(digest, &sha_ctx);
}

extern void mg_hash_sha1_v(size_t num_msgs, const uint8_t *msgs[], const size_t *msg_lens, uint8_t *digest);


MG_INTERNAL void mg_ws_handshake(struct mg_connection *nc, const struct mg_str *key, struct http_message *hm) {

  static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const uint8_t *msgs[2] = {(const uint8_t *) key->p, (const uint8_t *) magic};
  const size_t msg_lens[2] = {key->len, 36};
  unsigned char sha[20];
  char b64_sha[30];
  struct mg_str *s;

  mg_hash_sha1_v(2, msgs, msg_lens, sha);
  mg_base64_encode(sha, sizeof(sha), b64_sha);
  mg_printf(nc, "%s", "HTTP/1.1 101 Switching Protocols\r\n" "Upgrade: websocket\r\n" "Connection: Upgrade\r\n");



  s = mg_get_http_header(hm, "Sec-WebSocket-Protocol");
  if (s != NULL) {
    mg_printf(nc, "Sec-WebSocket-Protocol: %.*s\r\n", (int) s->len, s->p);
  }
  mg_printf(nc, "Sec-WebSocket-Accept: %s%s", b64_sha, "\r\n\r\n");

  DBG(("%p %.*s %s", nc, (int) key->len, key->p, b64_sha));
}

void mg_send_websocket_handshake2(struct mg_connection *nc, const char *path, const char *host, const char *protocol, const char *extra_headers) {

  mg_send_websocket_handshake3(nc, path, host, protocol, extra_headers, NULL, NULL);
}

void mg_send_websocket_handshake3(struct mg_connection *nc, const char *path, const char *host, const char *protocol, const char *extra_headers, const char *user, const char *pass) {


  mg_send_websocket_handshake3v(nc, mg_mk_str(path), mg_mk_str(host), mg_mk_str(protocol), mg_mk_str(extra_headers), mg_mk_str(user), mg_mk_str(pass));

}

void mg_send_websocket_handshake3v(struct mg_connection *nc, const struct mg_str path, const struct mg_str host, const struct mg_str protocol, const struct mg_str extra_headers, const struct mg_str user, const struct mg_str pass) {





  struct mbuf auth;
  char key[25];
  uint32_t nonce[4];
  nonce[0] = mg_ws_random_mask();
  nonce[1] = mg_ws_random_mask();
  nonce[2] = mg_ws_random_mask();
  nonce[3] = mg_ws_random_mask();
  mg_base64_encode((unsigned char *) &nonce, sizeof(nonce), key);

  mbuf_init(&auth, 0);
  if (user.len > 0) {
    mg_basic_auth_header(user, pass, &auth);
  }

  
  mg_printf(nc, "GET %.*s HTTP/1.1\r\n" "Upgrade: websocket\r\n" "Connection: Upgrade\r\n" "%.*s" "Sec-WebSocket-Version: 13\r\n" "Sec-WebSocket-Key: %s\r\n", (int) path.len, path.p, (int) auth.len, (auth.buf == NULL ? "" : auth.buf), key);








  
  if (host.len > 0) {
    int host_len = (int) (path.p - host.p); 
    mg_printf(nc, "Host: %.*s\r\n", host_len, host.p);
  }
  if (protocol.len > 0) {
    mg_printf(nc, "Sec-WebSocket-Protocol: %.*s\r\n", (int) protocol.len, protocol.p);
  }
  if (extra_headers.len > 0) {
    mg_printf(nc, "%.*s", (int) extra_headers.len, extra_headers.p);
  }
  mg_printf(nc, "\r\n");

  mbuf_free(&auth);
}

void mg_send_websocket_handshake(struct mg_connection *nc, const char *path, const char *extra_headers) {
  struct mg_str null_str = MG_NULL_STR;
  mg_send_websocket_handshake3v( nc, mg_mk_str(path), null_str , null_str , mg_mk_str(extra_headers), null_str , null_str );

}

struct mg_connection *mg_connect_ws_opt( struct mg_mgr *mgr, MG_CB(mg_event_handler_t ev_handler, void *user_data), struct mg_connect_opts opts, const char *url, const char *protocol, const char *extra_headers) {


  struct mg_str null_str = MG_NULL_STR;
  struct mg_str host = MG_NULL_STR, path = MG_NULL_STR, user_info = MG_NULL_STR;
  struct mg_connection *nc = mg_connect_http_base(mgr, MG_CB(ev_handler, user_data), opts, "http", "ws", "https", "wss", url, &path, &user_info, &host);

  if (nc != NULL) {
    mg_send_websocket_handshake3v(nc, path, host, mg_mk_str(protocol), mg_mk_str(extra_headers), user_info, null_str);

  }
  return nc;
}

struct mg_connection *mg_connect_ws( struct mg_mgr *mgr, MG_CB(mg_event_handler_t ev_handler, void *user_data), const char *url, const char *protocol, const char *extra_headers) {

  struct mg_connect_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_connect_ws_opt(mgr, MG_CB(ev_handler, user_data), opts, url, protocol, extra_headers);
}















const char *mg_skip(const char *s, const char *end, const char *delims, struct mg_str *v) {
  v->p = s;
  while (s < end && strchr(delims, *(unsigned char *) s) == NULL) s++;
  v->len = s - v->p;
  while (s < end && strchr(delims, *(unsigned char *) s) != NULL) s++;
  return s;
}


int mg_stat(const char *path, cs_stat_t *st) {

  wchar_t wpath[MG_MAX_PATH];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  DBG(("[%ls] -> %d", wpath, _wstati64(wpath, st)));
  return _wstati64(wpath, st);

  return stat(path, st);

}

FILE *mg_fopen(const char *path, const char *mode) {

  wchar_t wpath[MG_MAX_PATH], wmode[10];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  to_wchar(mode, wmode, ARRAY_SIZE(wmode));
  return _wfopen(wpath, wmode);

  return fopen(path, mode);

}

int mg_open(const char *path, int flag, int mode) { 

  wchar_t wpath[MG_MAX_PATH];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  return _wopen(wpath, flag, mode);

  return open(path, flag, mode); 

}

size_t mg_fread(void *ptr, size_t size, size_t count, FILE *f) {
  return fread(ptr, size, count, f);
}

size_t mg_fwrite(const void *ptr, size_t size, size_t count, FILE *f) {
  return fwrite(ptr, size, count, f);
}


void mg_base64_encode(const unsigned char *src, int src_len, char *dst) {
  cs_base64_encode(src, src_len, dst);
}

int mg_base64_decode(const unsigned char *s, int len, char *dst) {
  return cs_base64_decode(s, len, dst, NULL);
}


void *mg_start_thread(void *(*f)(void *), void *p) {

  return (void *) CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) f, p, 0, NULL);

  return (void *) _beginthread((void(__cdecl *) (void *) ) f, 0, p);

  pthread_t thread_id = (pthread_t) 0;
  pthread_attr_t attr;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);


  (void) pthread_attr_setstacksize(&attr, MG_STACK_SIZE);


  pthread_create(&thread_id, &attr, f, p);
  pthread_attr_destroy(&attr);

  return (void *) thread_id;

}



void mg_set_close_on_exec(sock_t sock) {

  (void) SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0);

  fcntl(sock, F_SETFD, FD_CLOEXEC);

  (void) sock;

}

int mg_sock_addr_to_str(const union socket_address *sa, char *buf, size_t len, int flags) {
  int is_v6;
  if (buf == NULL || len <= 0) return 0;
  memset(buf, 0, len);

  is_v6 = sa->sa.sa_family == AF_INET6;

  is_v6 = 0;

  if (flags & MG_SOCK_STRINGIFY_IP) {

    const void *addr = NULL;
    char *start = buf;
    socklen_t capacity = len;
    if (!is_v6) {
      addr = &sa->sin.sin_addr;
    } else {
      addr = (void *) &sa->sin6.sin6_addr;
      if (flags & MG_SOCK_STRINGIFY_PORT) {
        *buf = '[';
        start++;
        capacity--;
      }
    }
    if (inet_ntop(sa->sa.sa_family, addr, start, capacity) == NULL) {
      goto cleanup;
    }

    
    char *addr_str = inet_ntoa(sa->sin.sin_addr);
    if (addr_str != NULL) {
      strncpy(buf, inet_ntoa(sa->sin.sin_addr), len - 1);
    } else {
      goto cleanup;
    }

    if (inet_ntop(AF_INET, (void *) &sa->sin.sin_addr, buf, len) == NULL) {
      goto cleanup;
    }

  }
  if (flags & MG_SOCK_STRINGIFY_PORT) {
    int port = ntohs(sa->sin.sin_port);
    if (flags & MG_SOCK_STRINGIFY_IP) {
      int buf_len = strlen(buf);
      snprintf(buf + buf_len, len - (buf_len + 1), "%s:%d", (is_v6 ? "]" : ""), port);
    } else {
      snprintf(buf, len, "%d", port);
    }
  }

  return strlen(buf);

cleanup:
  *buf = '\0';
  return 0;
}

int mg_conn_addr_to_str(struct mg_connection *nc, char *buf, size_t len, int flags) {
  union socket_address sa;
  memset(&sa, 0, sizeof(sa));
  mg_if_get_conn_addr(nc, flags & MG_SOCK_STRINGIFY_REMOTE, &sa);
  return mg_sock_addr_to_str(&sa, buf, len, flags);
}


static int mg_hexdump_n(const void *buf, int len, char *dst, int dst_len, int offset) {
  const unsigned char *p = (const unsigned char *) buf;
  char ascii[17] = "";
  int i, idx, n = 0;

  for (i = 0; i < len; i++) {
    idx = i % 16;
    if (idx == 0) {
      if (i > 0) n += snprintf(dst + n, MAX(dst_len - n, 0), "  %s\n", ascii);
      n += snprintf(dst + n, MAX(dst_len - n, 0), "%04x ", i + offset);
    }
    if (dst_len - n < 0) {
      return n;
    }
    n += snprintf(dst + n, MAX(dst_len - n, 0), " %02x", p[i]);
    ascii[idx] = p[i] < 0x20 || p[i] > 0x7e ? '.' : p[i];
    ascii[idx + 1] = '\0';
  }

  while (i++ % 16) n += snprintf(dst + n, MAX(dst_len - n, 0), "%s", "   ");
  n += snprintf(dst + n, MAX(dst_len - n, 0), "  %s\n", ascii);

  return n;
}

int mg_hexdump(const void *buf, int len, char *dst, int dst_len) {
  return mg_hexdump_n(buf, len, dst, dst_len, 0);
}

void mg_hexdumpf(FILE *fp, const void *buf, int len) {
  char tmp[80];
  int offset = 0, n;
  while (len > 0) {
    n = (len < 16 ? len : 16);
    mg_hexdump_n(((const char *) buf) + offset, n, tmp, sizeof(tmp), offset);
    fputs(tmp, fp);
    offset += n;
    len -= n;
  }
}

void mg_hexdump_connection(struct mg_connection *nc, const char *path, const void *buf, int num_bytes, int ev) {
  FILE *fp = NULL;
  char src[60], dst[60];
  const char *tag = NULL;
  switch (ev) {
    case MG_EV_RECV:
      tag = "<-";
      break;
    case MG_EV_SEND:
      tag = "->";
      break;
    case MG_EV_ACCEPT:
      tag = "<A";
      break;
    case MG_EV_CONNECT:
      tag = "C>";
      break;
    case MG_EV_CLOSE:
      tag = "XX";
      break;
  }
  if (tag == NULL) return; 

  if (strcmp(path, "-") == 0) {
    fp = stdout;
  } else if (strcmp(path, "--") == 0) {
    fp = stderr;

  } else {
    fp = mg_fopen(path, "a");

  }
  if (fp == NULL) return;

  mg_conn_addr_to_str(nc, src, sizeof(src), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
  mg_conn_addr_to_str(nc, dst, sizeof(dst), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT | MG_SOCK_STRINGIFY_REMOTE);

  fprintf(fp, "%lu %p %s %s %s %d\n", (unsigned long) mg_time(), (void *) nc, src, tag, dst, (int) num_bytes);
  if (num_bytes > 0) {
    mg_hexdumpf(fp, buf, num_bytes);
  }
  if (fp != stdout && fp != stderr) fclose(fp);
}


int mg_is_big_endian(void) {
  static const int n = 1;
  
  return ((char *) &n)[0] == 0;
}

DO_NOT_WARN_UNUSED MG_INTERNAL int mg_get_errno(void) {

  return errno;

  
  return GetLastError();

}

void mg_mbuf_append_base64_putc(char ch, void *user_data) {
  struct mbuf *mbuf = (struct mbuf *) user_data;
  mbuf_append(mbuf, &ch, sizeof(ch));
}

void mg_mbuf_append_base64(struct mbuf *mbuf, const void *data, size_t len) {
  struct cs_base64_ctx ctx;
  cs_base64_init(&ctx, mg_mbuf_append_base64_putc, mbuf);
  cs_base64_update(&ctx, (const char *) data, len);
  cs_base64_finish(&ctx);
}

void mg_basic_auth_header(const struct mg_str user, const struct mg_str pass, struct mbuf *buf) {
  const char *header_prefix = "Authorization: Basic ";
  const char *header_suffix = "\r\n";

  struct cs_base64_ctx ctx;
  cs_base64_init(&ctx, mg_mbuf_append_base64_putc, buf);

  mbuf_append(buf, header_prefix, strlen(header_prefix));

  cs_base64_update(&ctx, user.p, user.len);
  if (pass.len > 0) {
    cs_base64_update(&ctx, ":", 1);
    cs_base64_update(&ctx, pass.p, pass.len);
  }
  cs_base64_finish(&ctx);
  mbuf_append(buf, header_suffix, strlen(header_suffix));
}

struct mg_str mg_url_encode_opt(const struct mg_str src, const struct mg_str safe, unsigned int flags) {
  const char *hex = (flags & MG_URL_ENCODE_F_UPPERCASE_HEX ? "0123456789ABCDEF" : "0123456789abcdef");

  size_t i = 0;
  struct mbuf mb;
  mbuf_init(&mb, src.len);

  for (i = 0; i < src.len; i++) {
    const unsigned char c = *((const unsigned char *) src.p + i);
    if (isalnum(c) || mg_strchr(safe, c) != NULL) {
      mbuf_append(&mb, &c, 1);
    } else if (c == ' ' && (flags & MG_URL_ENCODE_F_SPACE_AS_PLUS)) {
      mbuf_append(&mb, "+", 1);
    } else {
      mbuf_append(&mb, "%", 1);
      mbuf_append(&mb, &hex[c >> 4], 1);
      mbuf_append(&mb, &hex[c & 15], 1);
    }
  }
  mbuf_append(&mb, "", 1);
  mbuf_trim(&mb);
  return mg_mk_str_n(mb.buf, mb.len - 1);
}

struct mg_str mg_url_encode(const struct mg_str src) {
  return mg_url_encode_opt(src, mg_mk_str("._-$,;~()/"), 0);
}












static uint16_t getu16(const char *p) {
  const uint8_t *up = (const uint8_t *) p;
  return (up[0] << 8) + up[1];
}

static const char *scanto(const char *p, struct mg_str *s) {
  s->len = getu16(p);
  s->p = p + 2;
  return s->p + s->len;
}

MG_INTERNAL int parse_mqtt(struct mbuf *io, struct mg_mqtt_message *mm) {
  uint8_t header;
  size_t len = 0, len_len = 0;
  const char *p, *end;
  unsigned char lc = 0;
  int cmd;

  if (io->len < 2) return MG_MQTT_ERROR_INCOMPLETE_MSG;
  header = io->buf[0];
  cmd = header >> 4;

  
  len = len_len = 0;
  p = io->buf + 1;
  while ((size_t)(p - io->buf) < io->len) {
    lc = *((const unsigned char *) p++);
    len += (lc & 0x7f) << 7 * len_len;
    len_len++;
    if (!(lc & 0x80)) break;
    if (len_len > 4) return MG_MQTT_ERROR_MALFORMED_MSG;
  }

  end = p + len;
  if (lc & 0x80 || len > (io->len - (p - io->buf))) {
    return MG_MQTT_ERROR_INCOMPLETE_MSG;
  }

  mm->cmd = cmd;
  mm->qos = MG_MQTT_GET_QOS(header);

  switch (cmd) {
    case MG_MQTT_CMD_CONNECT: {
      p = scanto(p, &mm->protocol_name);
      if (p > end - 4) return MG_MQTT_ERROR_MALFORMED_MSG;
      mm->protocol_version = *(uint8_t *) p++;
      mm->connect_flags = *(uint8_t *) p++;
      mm->keep_alive_timer = getu16(p);
      p += 2;
      if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
      p = scanto(p, &mm->client_id);
      if (p > end) return MG_MQTT_ERROR_MALFORMED_MSG;
      if (mm->connect_flags & MG_MQTT_HAS_WILL) {
        if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
        p = scanto(p, &mm->will_topic);
      }
      if (mm->connect_flags & MG_MQTT_HAS_WILL) {
        if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
        p = scanto(p, &mm->will_message);
      }
      if (mm->connect_flags & MG_MQTT_HAS_USER_NAME) {
        if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
        p = scanto(p, &mm->user_name);
      }
      if (mm->connect_flags & MG_MQTT_HAS_PASSWORD) {
        if (p >= end) return MG_MQTT_ERROR_MALFORMED_MSG;
        p = scanto(p, &mm->password);
      }
      if (p != end) return MG_MQTT_ERROR_MALFORMED_MSG;

      LOG(LL_DEBUG, ("%d %2x %d proto [%.*s] client_id [%.*s] will_topic [%.*s] " "will_msg [%.*s] user_name [%.*s] password [%.*s]", (int) len, (int) mm->connect_flags, (int) mm->keep_alive_timer, (int) mm->protocol_name.len, mm->protocol_name.p, (int) mm->client_id.len, mm->client_id.p, (int) mm->will_topic.len, mm->will_topic.p, (int) mm->will_message.len, mm->will_message.p, (int) mm->user_name.len, mm->user_name.p, (int) mm->password.len, mm->password.p));







      break;
    }
    case MG_MQTT_CMD_CONNACK:
      if (end - p < 2) return MG_MQTT_ERROR_MALFORMED_MSG;
      mm->connack_ret_code = p[1];
      break;
    case MG_MQTT_CMD_PUBACK:
    case MG_MQTT_CMD_PUBREC:
    case MG_MQTT_CMD_PUBREL:
    case MG_MQTT_CMD_PUBCOMP:
    case MG_MQTT_CMD_SUBACK:
      mm->message_id = getu16(p);
      break;
    case MG_MQTT_CMD_PUBLISH: {
      p = scanto(p, &mm->topic);
      if (p > end) return MG_MQTT_ERROR_MALFORMED_MSG;
      if (mm->qos > 0) {
        if (end - p < 2) return MG_MQTT_ERROR_MALFORMED_MSG;
        mm->message_id = getu16(p);
        p += 2;
      }
      mm->payload.p = p;
      mm->payload.len = end - p;
      break;
    }
    case MG_MQTT_CMD_SUBSCRIBE:
      if (end - p < 2) return MG_MQTT_ERROR_MALFORMED_MSG;
      mm->message_id = getu16(p);
      p += 2;
      
      mm->payload.p = p;
      mm->payload.len = end - p;
      break;
    default:
      
      break;
  }

  mm->len = end - io->buf;
  return mm->len;
}

static void mqtt_handler(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data)) {
  struct mbuf *io = &nc->recv_mbuf;
  struct mg_mqtt_message mm;
  memset(&mm, 0, sizeof(mm));

  nc->handler(nc, ev, ev_data MG_UD_ARG(user_data));

  switch (ev) {
    case MG_EV_ACCEPT:
      if (nc->proto_data == NULL) mg_set_protocol_mqtt(nc);
      break;
    case MG_EV_RECV: {
      
      while (1) {
        int len = parse_mqtt(io, &mm);
        if (len < 0) {
          if (len == MG_MQTT_ERROR_MALFORMED_MSG) {
            
            nc->flags |= MG_F_CLOSE_IMMEDIATELY;
          } else if (len == MG_MQTT_ERROR_INCOMPLETE_MSG) {
            
            if (nc->recv_mbuf_limit > 0 && nc->recv_mbuf.len >= nc->recv_mbuf_limit) {
              LOG(LL_ERROR, ("%p recv buffer (%lu bytes) exceeds the limit " "%lu bytes, and not drained, closing", nc, (unsigned long) nc->recv_mbuf.len, (unsigned long) nc->recv_mbuf_limit));


              nc->flags |= MG_F_CLOSE_IMMEDIATELY;
            }
          } else {
            
            LOG(LL_ERROR, ("%p invalid len: %d, closing", nc, len));
            nc->flags |= MG_F_CLOSE_IMMEDIATELY;
          }
          break;
        }

        nc->handler(nc, MG_MQTT_EVENT_BASE + mm.cmd, &mm MG_UD_ARG(user_data));
        mbuf_remove(io, len);
      }
      break;
    }
    case MG_EV_POLL: {
      struct mg_mqtt_proto_data *pd = (struct mg_mqtt_proto_data *) nc->proto_data;
      double now = mg_time();
      if (pd->keep_alive > 0 && pd->last_control_time > 0 && (now - pd->last_control_time) > pd->keep_alive) {
        LOG(LL_DEBUG, ("Send PINGREQ"));
        mg_mqtt_ping(nc);
      }
      break;
    }
  }
}

static void mg_mqtt_proto_data_destructor(void *proto_data) {
  MG_FREE(proto_data);
}

int mg_mqtt_match_topic_expression(struct mg_str exp, struct mg_str topic) {
  
  if (memchr(exp.p, '#', exp.len)) {
    
    exp.len -= 1;
    
    if (topic.len <= exp.len) {
      return 0;
    }

    
    topic.len = exp.len;
  }
  if (topic.len != exp.len) {
    return 0;
  }
  return strncmp(topic.p, exp.p, exp.len) == 0;
}

int mg_mqtt_vmatch_topic_expression(const char *exp, struct mg_str topic) {
  return mg_mqtt_match_topic_expression(mg_mk_str(exp), topic);
}

void mg_set_protocol_mqtt(struct mg_connection *nc) {
  nc->proto_handler = mqtt_handler;
  nc->proto_data = MG_CALLOC(1, sizeof(struct mg_mqtt_proto_data));
  nc->proto_data_destructor = mg_mqtt_proto_data_destructor;
}

static void mg_mqtt_prepend_header(struct mg_connection *nc, uint8_t cmd, uint8_t flags, size_t len) {
  struct mg_mqtt_proto_data *pd = (struct mg_mqtt_proto_data *) nc->proto_data;
  size_t off = nc->send_mbuf.len - len;
  uint8_t header = cmd << 4 | (uint8_t) flags;

  uint8_t buf[1 + sizeof(size_t)];
  uint8_t *vlen = &buf[1];

  assert(nc->send_mbuf.len >= len);

  buf[0] = header;

  
  do {
    *vlen = len % 0x80;
    len /= 0x80;
    if (len > 0) *vlen |= 0x80;
    vlen++;
  } while (len > 0);

  mbuf_insert(&nc->send_mbuf, off, buf, vlen - buf);
  pd->last_control_time = mg_time();
}

void mg_send_mqtt_handshake(struct mg_connection *nc, const char *client_id) {
  static struct mg_send_mqtt_handshake_opts opts;
  mg_send_mqtt_handshake_opt(nc, client_id, opts);
}

void mg_send_mqtt_handshake_opt(struct mg_connection *nc, const char *client_id, struct mg_send_mqtt_handshake_opts opts) {
  uint16_t hlen, nlen, rem_len = 0;
  struct mg_mqtt_proto_data *pd = (struct mg_mqtt_proto_data *) nc->proto_data;

  mg_send(nc, "\00\04MQTT\04", 7);
  rem_len += 7;

  if (opts.user_name != NULL) {
    opts.flags |= MG_MQTT_HAS_USER_NAME;
  }
  if (opts.password != NULL) {
    opts.flags |= MG_MQTT_HAS_PASSWORD;
  }
  if (opts.will_topic != NULL && opts.will_message != NULL) {
    opts.flags |= MG_MQTT_HAS_WILL;
  }
  if (opts.keep_alive == 0) {
    opts.keep_alive = 60;
  }

  mg_send(nc, &opts.flags, 1);
  rem_len += 1;

  nlen = htons(opts.keep_alive);
  mg_send(nc, &nlen, 2);
  rem_len += 2;

  hlen = strlen(client_id);
  nlen = htons((uint16_t) hlen);
  mg_send(nc, &nlen, 2);
  mg_send(nc, client_id, hlen);
  rem_len += 2 + hlen;

  if (opts.flags & MG_MQTT_HAS_WILL) {
    hlen = strlen(opts.will_topic);
    nlen = htons((uint16_t) hlen);
    mg_send(nc, &nlen, 2);
    mg_send(nc, opts.will_topic, hlen);
    rem_len += 2 + hlen;

    hlen = strlen(opts.will_message);
    nlen = htons((uint16_t) hlen);
    mg_send(nc, &nlen, 2);
    mg_send(nc, opts.will_message, hlen);
    rem_len += 2 + hlen;
  }

  if (opts.flags & MG_MQTT_HAS_USER_NAME) {
    hlen = strlen(opts.user_name);
    nlen = htons((uint16_t) hlen);
    mg_send(nc, &nlen, 2);
    mg_send(nc, opts.user_name, hlen);
    rem_len += 2 + hlen;
  }
  if (opts.flags & MG_MQTT_HAS_PASSWORD) {
    hlen = strlen(opts.password);
    nlen = htons((uint16_t) hlen);
    mg_send(nc, &nlen, 2);
    mg_send(nc, opts.password, hlen);
    rem_len += 2 + hlen;
  }

  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_CONNECT, 0, rem_len);

  if (pd != NULL) {
    pd->keep_alive = opts.keep_alive;
  }
}

void mg_mqtt_publish(struct mg_connection *nc, const char *topic, uint16_t message_id, int flags, const void *data, size_t len) {

  size_t old_len = nc->send_mbuf.len;

  uint16_t topic_len = htons((uint16_t) strlen(topic));
  uint16_t message_id_net = htons(message_id);

  mg_send(nc, &topic_len, 2);
  mg_send(nc, topic, strlen(topic));
  if (MG_MQTT_GET_QOS(flags) > 0) {
    mg_send(nc, &message_id_net, 2);
  }
  mg_send(nc, data, len);

  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_PUBLISH, flags, nc->send_mbuf.len - old_len);
}

void mg_mqtt_subscribe(struct mg_connection *nc, const struct mg_mqtt_topic_expression *topics, size_t topics_len, uint16_t message_id) {

  size_t old_len = nc->send_mbuf.len;

  uint16_t message_id_n = htons(message_id);
  size_t i;

  mg_send(nc, (char *) &message_id_n, 2);
  for (i = 0; i < topics_len; i++) {
    uint16_t topic_len_n = htons((uint16_t) strlen(topics[i].topic));
    mg_send(nc, &topic_len_n, 2);
    mg_send(nc, topics[i].topic, strlen(topics[i].topic));
    mg_send(nc, &topics[i].qos, 1);
  }

  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_SUBSCRIBE, MG_MQTT_QOS(1), nc->send_mbuf.len - old_len);
}

int mg_mqtt_next_subscribe_topic(struct mg_mqtt_message *msg, struct mg_str *topic, uint8_t *qos, int pos) {
  unsigned char *buf = (unsigned char *) msg->payload.p + pos;
  int new_pos;

  if ((size_t) pos >= msg->payload.len) return -1;

  topic->len = buf[0] << 8 | buf[1];
  topic->p = (char *) buf + 2;
  new_pos = pos + 2 + topic->len + 1;
  if ((size_t) new_pos > msg->payload.len) return -1;
  *qos = buf[2 + topic->len];
  return new_pos;
}

void mg_mqtt_unsubscribe(struct mg_connection *nc, char **topics, size_t topics_len, uint16_t message_id) {
  size_t old_len = nc->send_mbuf.len;

  uint16_t message_id_n = htons(message_id);
  size_t i;

  mg_send(nc, (char *) &message_id_n, 2);
  for (i = 0; i < topics_len; i++) {
    uint16_t topic_len_n = htons((uint16_t) strlen(topics[i]));
    mg_send(nc, &topic_len_n, 2);
    mg_send(nc, topics[i], strlen(topics[i]));
  }

  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_UNSUBSCRIBE, MG_MQTT_QOS(1), nc->send_mbuf.len - old_len);
}

void mg_mqtt_connack(struct mg_connection *nc, uint8_t return_code) {
  uint8_t unused = 0;
  mg_send(nc, &unused, 1);
  mg_send(nc, &return_code, 1);
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_CONNACK, 0, 2);
}


static void mg_send_mqtt_short_command(struct mg_connection *nc, uint8_t cmd, uint16_t message_id) {
  uint16_t message_id_net = htons(message_id);
  uint8_t flags = (cmd == MG_MQTT_CMD_PUBREL ? 2 : 0);
  mg_send(nc, &message_id_net, 2);
  mg_mqtt_prepend_header(nc, cmd, flags, 2 );
}

void mg_mqtt_puback(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_PUBACK, message_id);
}

void mg_mqtt_pubrec(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_PUBREC, message_id);
}

void mg_mqtt_pubrel(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_PUBREL, message_id);
}

void mg_mqtt_pubcomp(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_PUBCOMP, message_id);
}

void mg_mqtt_suback(struct mg_connection *nc, uint8_t *qoss, size_t qoss_len, uint16_t message_id) {
  size_t i;
  uint16_t message_id_net = htons(message_id);
  mg_send(nc, &message_id_net, 2);
  for (i = 0; i < qoss_len; i++) {
    mg_send(nc, &qoss[i], 1);
  }
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_SUBACK, MG_MQTT_QOS(1), 2 + qoss_len);
}

void mg_mqtt_unsuback(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_UNSUBACK, message_id);
}

void mg_mqtt_ping(struct mg_connection *nc) {
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_PINGREQ, 0, 0);
}

void mg_mqtt_pong(struct mg_connection *nc) {
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_PINGRESP, 0, 0);
}

void mg_mqtt_disconnect(struct mg_connection *nc) {
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_DISCONNECT, 0, 0);
}












static void mg_mqtt_session_init(struct mg_mqtt_broker *brk, struct mg_mqtt_session *s, struct mg_connection *nc) {

  s->brk = brk;
  s->subscriptions = NULL;
  s->num_subscriptions = 0;
  s->nc = nc;
}

static void mg_mqtt_add_session(struct mg_mqtt_session *s) {
  LIST_INSERT_HEAD(&s->brk->sessions, s, link);
}

static void mg_mqtt_remove_session(struct mg_mqtt_session *s) {
  LIST_REMOVE(s, link);
}

static void mg_mqtt_destroy_session(struct mg_mqtt_session *s) {
  size_t i;
  for (i = 0; i < s->num_subscriptions; i++) {
    MG_FREE((void *) s->subscriptions[i].topic);
  }
  MG_FREE(s->subscriptions);
  MG_FREE(s);
}

static void mg_mqtt_close_session(struct mg_mqtt_session *s) {
  mg_mqtt_remove_session(s);
  mg_mqtt_destroy_session(s);
}

void mg_mqtt_broker_init(struct mg_mqtt_broker *brk, void *user_data) {
  LIST_INIT(&brk->sessions);
  brk->user_data = user_data;
}

static void mg_mqtt_broker_handle_connect(struct mg_mqtt_broker *brk, struct mg_connection *nc) {
  struct mg_mqtt_session *s = (struct mg_mqtt_session *) MG_CALLOC(1, sizeof *s);
  if (s == NULL) {
    
    mg_mqtt_connack(nc, MG_EV_MQTT_CONNACK_SERVER_UNAVAILABLE);
    return;
    
  }

  

  mg_mqtt_session_init(brk, s, nc);
  nc->priv_2 = s;
  mg_mqtt_add_session(s);

  mg_mqtt_connack(nc, MG_EV_MQTT_CONNACK_ACCEPTED);
}

static void mg_mqtt_broker_handle_subscribe(struct mg_connection *nc, struct mg_mqtt_message *msg) {
  struct mg_mqtt_session *ss = (struct mg_mqtt_session *) nc->priv_2;
  uint8_t qoss[MG_MQTT_MAX_SESSION_SUBSCRIPTIONS];
  size_t num_subs = 0;
  struct mg_str topic;
  uint8_t qos;
  int pos;
  struct mg_mqtt_topic_expression *te;

  for (pos = 0;
       (pos = mg_mqtt_next_subscribe_topic(msg, &topic, &qos, pos)) != -1;) {
    if (num_subs >= sizeof(MG_MQTT_MAX_SESSION_SUBSCRIPTIONS) || (ss->num_subscriptions + num_subs >= MG_MQTT_MAX_SESSION_SUBSCRIPTIONS)) {

      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      return;
    }
    qoss[num_subs++] = qos;
  }

  if (num_subs > 0) {
    te = (struct mg_mqtt_topic_expression *) MG_REALLOC( ss->subscriptions, sizeof(*ss->subscriptions) * (ss->num_subscriptions + num_subs));

    if (te == NULL) {
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      return;
    }
    ss->subscriptions = te;
    for (pos = 0;
         pos < (int) msg->payload.len && (pos = mg_mqtt_next_subscribe_topic(msg, &topic, &qos, pos)) != -1;
         ss->num_subscriptions++) {
      te = &ss->subscriptions[ss->num_subscriptions];
      te->topic = (char *) MG_MALLOC(topic.len + 1);
      te->qos = qos;
      memcpy((char *) te->topic, topic.p, topic.len);
      ((char *) te->topic)[topic.len] = '\0';
    }
  }

  if (pos == (int) msg->payload.len) {
    mg_mqtt_suback(nc, qoss, num_subs, msg->message_id);
  } else {
    
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  }
}

static void mg_mqtt_broker_handle_publish(struct mg_mqtt_broker *brk, struct mg_mqtt_message *msg) {
  struct mg_mqtt_session *s;
  size_t i;

  for (s = mg_mqtt_next(brk, NULL); s != NULL; s = mg_mqtt_next(brk, s)) {
    for (i = 0; i < s->num_subscriptions; i++) {
      if (mg_mqtt_vmatch_topic_expression(s->subscriptions[i].topic, msg->topic)) {
        char buf[100], *p = buf;
        mg_asprintf(&p, sizeof(buf), "%.*s", (int) msg->topic.len, msg->topic.p);
        if (p == NULL) {
          return;
        }
        mg_mqtt_publish(s->nc, p, 0, 0, msg->payload.p, msg->payload.len);
        if (p != buf) {
          MG_FREE(p);
        }
        break;
      }
    }
  }
}

void mg_mqtt_broker(struct mg_connection *nc, int ev, void *data) {
  struct mg_mqtt_message *msg = (struct mg_mqtt_message *) data;
  struct mg_mqtt_broker *brk;

  if (nc->listener) {
    brk = (struct mg_mqtt_broker *) nc->listener->priv_2;
  } else {
    brk = (struct mg_mqtt_broker *) nc->priv_2;
  }

  switch (ev) {
    case MG_EV_ACCEPT:
      if (nc->proto_data == NULL) mg_set_protocol_mqtt(nc);
      nc->priv_2 = NULL; 
      break;
    case MG_EV_MQTT_CONNECT:
      if (nc->priv_2 == NULL) {
        mg_mqtt_broker_handle_connect(brk, nc);
      } else {
        
        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      }
      break;
    case MG_EV_MQTT_SUBSCRIBE:
      if (nc->priv_2 != NULL) {
        mg_mqtt_broker_handle_subscribe(nc, msg);
      } else {
        
        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      }
      break;
    case MG_EV_MQTT_PUBLISH:
      if (nc->priv_2 != NULL) {
        mg_mqtt_broker_handle_publish(brk, msg);
      } else {
        
        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      }
      break;
    case MG_EV_CLOSE:
      if (nc->listener && nc->priv_2 != NULL) {
        mg_mqtt_close_session((struct mg_mqtt_session *) nc->priv_2);
      }
      break;
  }
}

struct mg_mqtt_session *mg_mqtt_next(struct mg_mqtt_broker *brk, struct mg_mqtt_session *s) {
  return s == NULL ? LIST_FIRST(&brk->sessions) : LIST_NEXT(s, link);
}












static int mg_dns_tid = 0xa0;

struct mg_dns_header {
  uint16_t transaction_id;
  uint16_t flags;
  uint16_t num_questions;
  uint16_t num_answers;
  uint16_t num_authority_prs;
  uint16_t num_other_prs;
};

struct mg_dns_resource_record *mg_dns_next_record( struct mg_dns_message *msg, int query, struct mg_dns_resource_record *prev) {

  struct mg_dns_resource_record *rr;

  for (rr = (prev == NULL ? msg->answers : prev + 1);
       rr - msg->answers < msg->num_answers; rr++) {
    if (rr->rtype == query) {
      return rr;
    }
  }
  return NULL;
}

int mg_dns_parse_record_data(struct mg_dns_message *msg, struct mg_dns_resource_record *rr, void *data, size_t data_len) {

  switch (rr->rtype) {
    case MG_DNS_A_RECORD:
      if (data_len < sizeof(struct in_addr)) {
        return -1;
      }
      if (rr->rdata.p + data_len > msg->pkt.p + msg->pkt.len) {
        return -1;
      }
      memcpy(data, rr->rdata.p, data_len);
      return 0;

    case MG_DNS_AAAA_RECORD:
      if (data_len < sizeof(struct in6_addr)) {
        return -1; 
      }
      memcpy(data, rr->rdata.p, data_len);
      return 0;

    case MG_DNS_CNAME_RECORD:
      mg_dns_uncompress_name(msg, &rr->rdata, (char *) data, data_len);
      return 0;
  }

  return -1;
}

int mg_dns_insert_header(struct mbuf *io, size_t pos, struct mg_dns_message *msg) {
  struct mg_dns_header header;

  memset(&header, 0, sizeof(header));
  header.transaction_id = msg->transaction_id;
  header.flags = htons(msg->flags);
  header.num_questions = htons(msg->num_questions);
  header.num_answers = htons(msg->num_answers);

  return mbuf_insert(io, pos, &header, sizeof(header));
}

int mg_dns_copy_questions(struct mbuf *io, struct mg_dns_message *msg) {
  unsigned char *begin, *end;
  struct mg_dns_resource_record *last_q;
  if (msg->num_questions <= 0) return 0;
  begin = (unsigned char *) msg->pkt.p + sizeof(struct mg_dns_header);
  last_q = &msg->questions[msg->num_questions - 1];
  end = (unsigned char *) last_q->name.p + last_q->name.len + 4;
  return mbuf_append(io, begin, end - begin);
}

int mg_dns_encode_name(struct mbuf *io, const char *name, size_t len) {
  const char *s;
  unsigned char n;
  size_t pos = io->len;

  do {
    if ((s = strchr(name, '.')) == NULL) {
      s = name + len;
    }

    if (s - name > 127) {
      return -1; 
    }
    n = s - name;           
    mbuf_append(io, &n, 1); 
    mbuf_append(io, name, n);

    if (*s == '.') {
      n++;
    }

    name += n;
    len -= n;
  } while (*s != '\0');
  mbuf_append(io, "\0", 1); 

  return io->len - pos;
}

int mg_dns_encode_record(struct mbuf *io, struct mg_dns_resource_record *rr, const char *name, size_t nlen, const void *rdata, size_t rlen) {

  size_t pos = io->len;
  uint16_t u16;
  uint32_t u32;

  if (rr->kind == MG_DNS_INVALID_RECORD) {
    return -1; 
  }

  if (mg_dns_encode_name(io, name, nlen) == -1) {
    return -1;
  }

  u16 = htons(rr->rtype);
  mbuf_append(io, &u16, 2);
  u16 = htons(rr->rclass);
  mbuf_append(io, &u16, 2);

  if (rr->kind == MG_DNS_ANSWER) {
    u32 = htonl(rr->ttl);
    mbuf_append(io, &u32, 4);

    if (rr->rtype == MG_DNS_CNAME_RECORD) {
      int clen;
      
      size_t off = io->len;
      mbuf_append(io, &u16, 2);
      if ((clen = mg_dns_encode_name(io, (const char *) rdata, rlen)) == -1) {
        return -1;
      }
      u16 = clen;
      io->buf[off] = u16 >> 8;
      io->buf[off + 1] = u16 & 0xff;
    } else {
      u16 = htons((uint16_t) rlen);
      mbuf_append(io, &u16, 2);
      mbuf_append(io, rdata, rlen);
    }
  }

  return io->len - pos;
}

void mg_send_dns_query(struct mg_connection *nc, const char *name, int query_type) {
  struct mg_dns_message *msg = (struct mg_dns_message *) MG_CALLOC(1, sizeof(*msg));
  struct mbuf pkt;
  struct mg_dns_resource_record *rr = &msg->questions[0];

  DBG(("%s %d", name, query_type));

  mbuf_init(&pkt, 64 );

  msg->transaction_id = ++mg_dns_tid;
  msg->flags = 0x100;
  msg->num_questions = 1;

  mg_dns_insert_header(&pkt, 0, msg);

  rr->rtype = query_type;
  rr->rclass = 1; 
  rr->kind = MG_DNS_QUESTION;

  if (mg_dns_encode_record(&pkt, rr, name, strlen(name), NULL, 0) == -1) {
    
    goto cleanup; 
  }

  
  if (!(nc->flags & MG_F_UDP)) {
    uint16_t len = htons((uint16_t) pkt.len);
    mbuf_insert(&pkt, 0, &len, 2);
  }

  mg_send(nc, pkt.buf, pkt.len);
  mbuf_free(&pkt);

cleanup:
  MG_FREE(msg);
}

static unsigned char *mg_parse_dns_resource_record( unsigned char *data, unsigned char *end, struct mg_dns_resource_record *rr, int reply) {

  unsigned char *name = data;
  int chunk_len, data_len;

  while (data < end && (chunk_len = *data)) {
    if (((unsigned char *) data)[0] & 0xc0) {
      data += 1;
      break;
    }
    data += chunk_len + 1;
  }

  if (data > end - 5) {
    return NULL;
  }

  rr->name.p = (char *) name;
  rr->name.len = data - name + 1;
  data++;

  rr->rtype = data[0] << 8 | data[1];
  data += 2;

  rr->rclass = data[0] << 8 | data[1];
  data += 2;

  rr->kind = reply ? MG_DNS_ANSWER : MG_DNS_QUESTION;
  if (reply) {
    if (data >= end - 6) {
      return NULL;
    }

    rr->ttl = (uint32_t) data[0] << 24 | (uint32_t) data[1] << 16 | data[2] << 8 | data[3];
    data += 4;

    data_len = *data << 8 | *(data + 1);
    data += 2;

    rr->rdata.p = (char *) data;
    rr->rdata.len = data_len;
    data += data_len;
  }
  return data;
}

int mg_parse_dns(const char *buf, int len, struct mg_dns_message *msg) {
  struct mg_dns_header *header = (struct mg_dns_header *) buf;
  unsigned char *data = (unsigned char *) buf + sizeof(*header);
  unsigned char *end = (unsigned char *) buf + len;
  int i;

  memset(msg, 0, sizeof(*msg));
  msg->pkt.p = buf;
  msg->pkt.len = len;

  if (len < (int) sizeof(*header)) return -1;

  msg->transaction_id = header->transaction_id;
  msg->flags = ntohs(header->flags);
  msg->num_questions = ntohs(header->num_questions);
  if (msg->num_questions > (int) ARRAY_SIZE(msg->questions)) {
    msg->num_questions = (int) ARRAY_SIZE(msg->questions);
  }
  msg->num_answers = ntohs(header->num_answers);
  if (msg->num_answers > (int) ARRAY_SIZE(msg->answers)) {
    msg->num_answers = (int) ARRAY_SIZE(msg->answers);
  }

  for (i = 0; i < msg->num_questions; i++) {
    data = mg_parse_dns_resource_record(data, end, &msg->questions[i], 0);
    if (data == NULL) return -1;
  }

  for (i = 0; i < msg->num_answers; i++) {
    data = mg_parse_dns_resource_record(data, end, &msg->answers[i], 1);
    if (data == NULL) return -1;
  }

  return 0;
}

size_t mg_dns_uncompress_name(struct mg_dns_message *msg, struct mg_str *name, char *dst, int dst_len) {
  int chunk_len, num_ptrs = 0;
  char *old_dst = dst;
  const unsigned char *data = (unsigned char *) name->p;
  const unsigned char *end = (unsigned char *) msg->pkt.p + msg->pkt.len;

  if (data >= end) {
    return 0;
  }

  while ((chunk_len = *data++)) {
    int leeway = dst_len - (dst - old_dst);
    if (data >= end) {
      return 0;
    }

    if ((chunk_len & 0xc0) == 0xc0) {
      uint16_t off = (data[-1] & (~0xc0)) << 8 | data[0];
      if (off >= msg->pkt.len) {
        return 0;
      }
      
      if (++num_ptrs > 15) {
        return 0;
      }
      data = (unsigned char *) msg->pkt.p + off;
      continue;
    }
    if (chunk_len > 63) {
      return 0;
    }
    if (chunk_len > leeway) {
      chunk_len = leeway;
    }

    if (data + chunk_len >= end) {
      return 0;
    }

    memcpy(dst, data, chunk_len);
    data += chunk_len;
    dst += chunk_len;
    leeway -= chunk_len;
    if (leeway == 0) {
      return dst - old_dst;
    }
    *dst++ = '.';
  }

  if (dst != old_dst) {
    *--dst = 0;
  }
  return dst - old_dst;
}

static void dns_handler(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data)) {
  struct mbuf *io = &nc->recv_mbuf;
  struct mg_dns_message msg;

  
  nc->handler(nc, ev, ev_data MG_UD_ARG(user_data));

  switch (ev) {
    case MG_EV_RECV:
      if (!(nc->flags & MG_F_UDP)) {
        mbuf_remove(&nc->recv_mbuf, 2);
      }
      if (mg_parse_dns(nc->recv_mbuf.buf, nc->recv_mbuf.len, &msg) == -1) {
        
        memset(&msg, 0, sizeof(msg));
        msg.flags = 0x8081;
        mg_dns_insert_header(io, 0, &msg);
        if (!(nc->flags & MG_F_UDP)) {
          uint16_t len = htons((uint16_t) io->len);
          mbuf_insert(io, 0, &len, 2);
        }
        mg_send(nc, io->buf, io->len);
      } else {
        
        nc->handler(nc, MG_DNS_MESSAGE, &msg MG_UD_ARG(user_data));
      }
      mbuf_remove(io, io->len);
      break;
  }
}

void mg_set_protocol_dns(struct mg_connection *nc) {
  nc->proto_handler = dns_handler;
}












struct mg_dns_reply mg_dns_create_reply(struct mbuf *io, struct mg_dns_message *msg) {
  struct mg_dns_reply rep;
  rep.msg = msg;
  rep.io = io;
  rep.start = io->len;

  
  msg->flags |= 0x8080;
  mg_dns_copy_questions(io, msg);

  msg->num_answers = 0;
  return rep;
}

void mg_dns_send_reply(struct mg_connection *nc, struct mg_dns_reply *r) {
  size_t sent = r->io->len - r->start;
  mg_dns_insert_header(r->io, r->start, r->msg);
  if (!(nc->flags & MG_F_UDP)) {
    uint16_t len = htons((uint16_t) sent);
    mbuf_insert(r->io, r->start, &len, 2);
  }

  if (&nc->send_mbuf != r->io) {
    mg_send(nc, r->io->buf + r->start, r->io->len - r->start);
    r->io->len = r->start;
  }
}

int mg_dns_reply_record(struct mg_dns_reply *reply, struct mg_dns_resource_record *question, const char *name, int rtype, int ttl, const void *rdata, size_t rdata_len) {


  struct mg_dns_message *msg = (struct mg_dns_message *) reply->msg;
  char rname[512];
  struct mg_dns_resource_record *ans = &msg->answers[msg->num_answers];
  if (msg->num_answers >= MG_MAX_DNS_ANSWERS) {
    return -1; 
  }

  if (name == NULL) {
    name = rname;
    rname[511] = 0;
    mg_dns_uncompress_name(msg, &question->name, rname, sizeof(rname) - 1);
  }

  *ans = *question;
  ans->kind = MG_DNS_ANSWER;
  ans->rtype = rtype;
  ans->ttl = ttl;

  if (mg_dns_encode_record(reply->io, ans, name, strlen(name), rdata, rdata_len) == -1) {
    return -1; 
  };

  msg->num_answers++;
  return 0;
}
















struct mg_resolve_async_request {
  char name[1024];
  int query;
  mg_resolve_callback_t callback;
  void *data;
  time_t timeout;
  int max_retries;
  enum mg_resolve_err err;

  
  time_t last_time;
  int retries;
};


static int mg_get_ip_address_of_nameserver(char *name, size_t name_len) {
  int ret = -1;


  int i;
  LONG err;
  HKEY hKey, hSub;
  wchar_t subkey[512], value[128], *key = L"SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";

  if ((err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey)) != ERROR_SUCCESS) {
    fprintf(stderr, "cannot open reg key %S: %ld\n", key, err);
    ret = -1;
  } else {
    for (ret = -1, i = 0; 1; i++) {
      DWORD subkey_size = sizeof(subkey), type, len = sizeof(value);
      if (RegEnumKeyExW(hKey, i, subkey, &subkey_size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
        break;
      }
      if (RegOpenKeyExW(hKey, subkey, 0, KEY_READ, &hSub) == ERROR_SUCCESS && ((RegQueryValueExW(hSub, L"NameServer", 0, &type, (void *) value, &len) == ERROR_SUCCESS && value[0] != '\0') || (RegQueryValueExW(hSub, L"DhcpNameServer", 0, &type, (void *) value, &len) == ERROR_SUCCESS && value[0] != '\0'))) {





        
        wchar_t *comma = wcschr(value, ',');
        if (comma != NULL) {
          *comma = '\0';
        }
        
        snprintf(name, name_len, "%S", value);
        ret = 0;
        RegCloseKey(hSub);
        break;
      }
    }
    RegCloseKey(hKey);
  }

  FILE *fp;
  char line[512];

  if ((fp = mg_fopen(MG_RESOLV_CONF_FILE_NAME, "r")) == NULL) {
    ret = -1;
  } else {
    
    for (ret = -1; fgets(line, sizeof(line), fp) != NULL;) {
      unsigned int a, b, c, d;
      if (sscanf(line, "nameserver %u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        snprintf(name, name_len, "%u.%u.%u.%u", a, b, c, d);
        ret = 0;
        break;
      }
    }
    (void) fclose(fp);
  }

  snprintf(name, name_len, "%s", MG_DEFAULT_NAMESERVER);


  return ret;
}

int mg_resolve_from_hosts_file(const char *name, union socket_address *usa) {

  
  FILE *fp;
  char line[1024];
  char *p;
  char alias[256];
  unsigned int a, b, c, d;
  int len = 0;

  if ((fp = mg_fopen(MG_HOSTS_FILE_NAME, "r")) == NULL) {
    return -1;
  }

  for (; fgets(line, sizeof(line), fp) != NULL;) {
    if (line[0] == '#') continue;

    if (sscanf(line, "%u.%u.%u.%u%n", &a, &b, &c, &d, &len) == 0) {
      
      continue;
    }
    for (p = line + len; sscanf(p, "%s%n", alias, &len) == 1; p += len) {
      if (strcmp(alias, name) == 0) {
        usa->sin.sin_addr.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
        fclose(fp);
        return 0;
      }
    }
  }

  fclose(fp);

  (void) name;
  (void) usa;


  return -1;
}

static void mg_resolve_async_eh(struct mg_connection *nc, int ev, void *data MG_UD_ARG(void *user_data)) {
  time_t now = (time_t) mg_time();
  struct mg_resolve_async_request *req;
  struct mg_dns_message *msg;

  void *user_data = nc->user_data;


  if (ev != MG_EV_POLL) DBG(("ev=%d user_data=%p", ev, user_data));

  req = (struct mg_resolve_async_request *) user_data;

  if (req == NULL) {
    return;
  }

  switch (ev) {
    case MG_EV_POLL:
      if (req->retries > req->max_retries) {
        req->err = MG_RESOLVE_EXCEEDED_RETRY_COUNT;
        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        break;
      }
      if (nc->flags & MG_F_CONNECTING) break;
    
    case MG_EV_CONNECT:
      if (req->retries == 0 || now - req->last_time >= req->timeout) {
        mg_send_dns_query(nc, req->name, req->query);
        req->last_time = now;
        req->retries++;
      }
      break;
    case MG_EV_RECV:
      msg = (struct mg_dns_message *) MG_MALLOC(sizeof(*msg));
      if (mg_parse_dns(nc->recv_mbuf.buf, *(int *) data, msg) == 0 && msg->num_answers > 0) {
        req->callback(msg, req->data, MG_RESOLVE_OK);
        nc->user_data = NULL;
        MG_FREE(req);
      } else {
        req->err = MG_RESOLVE_NO_ANSWERS;
      }
      MG_FREE(msg);
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      break;
    case MG_EV_SEND:
      
      nc->flags &= ~MG_F_CLOSE_IMMEDIATELY;
      mbuf_remove(&nc->send_mbuf, nc->send_mbuf.len);
      break;
    case MG_EV_TIMER:
      req->err = MG_RESOLVE_TIMEOUT;
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      break;
    case MG_EV_CLOSE:
      
      if (req != NULL) {
        char addr[32];
        mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP);

        LOG(LL_ERROR, ("Failed to resolve '%s', server %s", req->name, addr));

        req->callback(NULL, req->data, req->err);
        nc->user_data = NULL;
        MG_FREE(req);
      }
      break;
  }
}

int mg_resolve_async(struct mg_mgr *mgr, const char *name, int query, mg_resolve_callback_t cb, void *data) {
  struct mg_resolve_async_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_resolve_async_opt(mgr, name, query, cb, data, opts);
}

int mg_resolve_async_opt(struct mg_mgr *mgr, const char *name, int query, mg_resolve_callback_t cb, void *data, struct mg_resolve_async_opts opts) {

  struct mg_resolve_async_request *req;
  struct mg_connection *dns_nc;
  const char *nameserver = opts.nameserver;
  char dns_server_buff[17], nameserver_url[26];

  if (nameserver == NULL) {
    nameserver = mgr->nameserver;
  }

  DBG(("%s %d %p", name, query, opts.dns_conn));

  
  req = (struct mg_resolve_async_request *) MG_CALLOC(1, sizeof(*req));
  if (req == NULL) {
    return -1;
  }

  strncpy(req->name, name, sizeof(req->name));
  req->name[sizeof(req->name) - 1] = '\0';

  req->query = query;
  req->callback = cb;
  req->data = data;
  
  req->max_retries = opts.max_retries ? opts.max_retries : 2;
  req->timeout = opts.timeout ? opts.timeout : 5;

  
  if (nameserver == NULL) {
    if (mg_get_ip_address_of_nameserver(dns_server_buff, sizeof(dns_server_buff)) != -1) {
      nameserver = dns_server_buff;
    } else {
      nameserver = MG_DEFAULT_NAMESERVER;
    }
  }

  snprintf(nameserver_url, sizeof(nameserver_url), "udp://%s:53", nameserver);

  dns_nc = mg_connect(mgr, nameserver_url, MG_CB(mg_resolve_async_eh, NULL));
  if (dns_nc == NULL) {
    MG_FREE(req);
    return -1;
  }
  dns_nc->user_data = req;
  if (opts.dns_conn != NULL) {
    *opts.dns_conn = dns_nc;
  }

  return 0;
}

void mg_set_nameserver(struct mg_mgr *mgr, const char *nameserver) {
  MG_FREE((char *) mgr->nameserver);
  mgr->nameserver = NULL;
  if (nameserver != NULL) {
    mgr->nameserver = strdup(nameserver);
  }
}












void mg_coap_free_options(struct mg_coap_message *cm) {
  while (cm->options != NULL) {
    struct mg_coap_option *next = cm->options->next;
    MG_FREE(cm->options);
    cm->options = next;
  }
}

struct mg_coap_option *mg_coap_add_option(struct mg_coap_message *cm, uint32_t number, char *value, size_t len) {

  struct mg_coap_option *new_option = (struct mg_coap_option *) MG_CALLOC(1, sizeof(*new_option));

  new_option->number = number;
  new_option->value.p = value;
  new_option->value.len = len;

  if (cm->options == NULL) {
    cm->options = cm->optiomg_tail = new_option;
  } else {
    
    if (cm->optiomg_tail->number <= new_option->number) {
      
      cm->optiomg_tail = cm->optiomg_tail->next = new_option;
    } else {
      
      struct mg_coap_option *current_opt = cm->options;
      struct mg_coap_option *prev_opt = 0;

      while (current_opt != NULL) {
        if (current_opt->number > new_option->number) {
          break;
        }
        prev_opt = current_opt;
        current_opt = current_opt->next;
      }

      if (prev_opt != NULL) {
        prev_opt->next = new_option;
        new_option->next = current_opt;
      } else {
        
        new_option->next = cm->options;
        cm->options = new_option;
      }
    }
  }

  return new_option;
}


static char *coap_parse_header(char *ptr, struct mbuf *io, struct mg_coap_message *cm) {
  if (io->len < sizeof(uint32_t)) {
    cm->flags |= MG_COAP_NOT_ENOUGH_DATA;
    return NULL;
  }

  
  if (((uint8_t) *ptr >> 6) != 1) {
    cm->flags |= MG_COAP_IGNORE;
    return NULL;
  }

  
  cm->msg_type = ((uint8_t) *ptr & 0x30) >> 4;
  cm->flags |= MG_COAP_MSG_TYPE_FIELD;

  
  cm->token.len = *ptr & 0x0F;
  if (cm->token.len > 8) {
    cm->flags |= MG_COAP_FORMAT_ERROR;
    return NULL;
  }

  ptr++;

  
  cm->code_class = (uint8_t) *ptr >> 5;
  cm->code_detail = *ptr & 0x1F;
  cm->flags |= (MG_COAP_CODE_CLASS_FIELD | MG_COAP_CODE_DETAIL_FIELD);

  ptr++;

  
  cm->msg_id = (uint8_t) *ptr << 8 | (uint8_t) * (ptr + 1);
  cm->flags |= MG_COAP_MSG_ID_FIELD;

  ptr += 2;

  return ptr;
}


static char *coap_get_token(char *ptr, struct mbuf *io, struct mg_coap_message *cm) {
  if (cm->token.len != 0) {
    if (ptr + cm->token.len > io->buf + io->len) {
      cm->flags |= MG_COAP_NOT_ENOUGH_DATA;
      return NULL;
    } else {
      cm->token.p = ptr;
      ptr += cm->token.len;
      cm->flags |= MG_COAP_TOKEN_FIELD;
    }
  }

  return ptr;
}


static int coap_get_ext_opt(char *ptr, struct mbuf *io, uint16_t *opt_info) {
  int ret = 0;

  if (*opt_info == 13) {
    
    if (ptr < io->buf + io->len) {
      *opt_info = (uint8_t) *ptr + 13;
      ret = sizeof(uint8_t);
    } else {
      ret = -1; 
    }
  } else if (*opt_info == 14) {
    
    if (ptr + sizeof(uint8_t) < io->buf + io->len) {
      *opt_info = ((uint8_t) *ptr << 8 | (uint8_t) * (ptr + 1)) + 269;
      ret = sizeof(uint16_t);
    } else {
      ret = -1; 
    }
  }

  return ret;
}


static char *coap_get_options(char *ptr, struct mbuf *io, struct mg_coap_message *cm) {
  uint16_t prev_opt = 0;

  if (ptr == io->buf + io->len) {
    
    return NULL;
  }

  
  while (ptr < io->buf + io->len && (uint8_t) *ptr != 0xFF) {
    uint16_t option_delta, option_lenght;
    int optinfo_len;

    
    option_delta = ((uint8_t) *ptr & 0xF0) >> 4;
    
    option_lenght = *ptr & 0x0F;

    if (option_delta == 15 || option_lenght == 15) {
      
      cm->flags |= MG_COAP_FORMAT_ERROR;
      break;
    }

    ptr++;

    
    optinfo_len = coap_get_ext_opt(ptr, io, &option_delta);
    if (optinfo_len == -1) {
      cm->flags |= MG_COAP_NOT_ENOUGH_DATA; 
      break;                                
    }

    ptr += optinfo_len;

    
    optinfo_len = coap_get_ext_opt(ptr, io, &option_lenght);
    if (optinfo_len == -1) {
      cm->flags |= MG_COAP_NOT_ENOUGH_DATA; 
      break;                                
    }

    ptr += optinfo_len;

    
    option_delta += prev_opt;

    mg_coap_add_option(cm, option_delta, ptr, option_lenght);

    prev_opt = option_delta;

    if (ptr + option_lenght > io->buf + io->len) {
      cm->flags |= MG_COAP_NOT_ENOUGH_DATA; 
      break;                                
    }

    ptr += option_lenght;
  }

  if ((cm->flags & MG_COAP_ERROR) != 0) {
    mg_coap_free_options(cm);
    return NULL;
  }

  cm->flags |= MG_COAP_OPTIOMG_FIELD;

  if (ptr == io->buf + io->len) {
    
    return NULL;
  }

  ptr++;

  return ptr;
}

uint32_t mg_coap_parse(struct mbuf *io, struct mg_coap_message *cm) {
  char *ptr;

  memset(cm, 0, sizeof(*cm));

  if ((ptr = coap_parse_header(io->buf, io, cm)) == NULL) {
    return cm->flags;
  }

  if ((ptr = coap_get_token(ptr, io, cm)) == NULL) {
    return cm->flags;
  }

  if ((ptr = coap_get_options(ptr, io, cm)) == NULL) {
    return cm->flags;
  }

  
  cm->payload.len = io->len - (ptr - io->buf);
  if (cm->payload.len != 0) {
    cm->payload.p = ptr;
    cm->flags |= MG_COAP_PAYLOAD_FIELD;
  }

  return cm->flags;
}


static size_t coap_get_ext_opt_size(uint32_t value) {
  int ret = 0;

  if (value >= 13 && value <= 0xFF + 13) {
    ret = sizeof(uint8_t);
  } else if (value > 0xFF + 13 && value <= 0xFFFF + 269) {
    ret = sizeof(uint16_t);
  }

  return ret;
}


static int coap_split_opt(uint32_t value, uint8_t *base, uint16_t *ext) {
  int ret = 0;

  if (value < 13) {
    *base = value;
  } else if (value >= 13 && value <= 0xFF + 13) {
    *base = 13;
    *ext = value - 13;
    ret = sizeof(uint8_t);
  } else if (value > 0xFF + 13 && value <= 0xFFFF + 269) {
    *base = 14;
    *ext = value - 269;
    ret = sizeof(uint16_t);
  }

  return ret;
}


static char *coap_add_uint16(char *ptr, uint16_t val) {
  *ptr = val >> 8;
  ptr++;
  *ptr = val & 0x00FF;
  ptr++;
  return ptr;
}


static char *coap_add_opt_info(char *ptr, uint16_t val, size_t len) {
  if (len == sizeof(uint8_t)) {
    *ptr = (char) val;
    ptr++;
  } else if (len == sizeof(uint16_t)) {
    ptr = coap_add_uint16(ptr, val);
  }

  return ptr;
}


static uint32_t coap_calculate_packet_size(struct mg_coap_message *cm, size_t *len) {
  struct mg_coap_option *opt;
  uint32_t prev_opt_number;

  *len = 4; 
  if (cm->msg_type > MG_COAP_MSG_MAX) {
    return MG_COAP_ERROR | MG_COAP_MSG_TYPE_FIELD;
  }
  if (cm->token.len > 8) {
    return MG_COAP_ERROR | MG_COAP_TOKEN_FIELD;
  }
  if (cm->code_class > 7) {
    return MG_COAP_ERROR | MG_COAP_CODE_CLASS_FIELD;
  }
  if (cm->code_detail > 31) {
    return MG_COAP_ERROR | MG_COAP_CODE_DETAIL_FIELD;
  }

  *len += cm->token.len;
  if (cm->payload.len != 0) {
    *len += cm->payload.len + 1; 
  }

  opt = cm->options;
  prev_opt_number = 0;
  while (opt != NULL) {
    *len += 1; 
    *len += coap_get_ext_opt_size(opt->number - prev_opt_number);
    *len += coap_get_ext_opt_size((uint32_t) opt->value.len);
    
    if ((opt->next != NULL && opt->number > opt->next->number) || opt->value.len > 0xFFFF + 269 || opt->number - prev_opt_number > 0xFFFF + 269) {

      return MG_COAP_ERROR | MG_COAP_OPTIOMG_FIELD;
    }
    *len += opt->value.len;
    prev_opt_number = opt->number;
    opt = opt->next;
  }

  return 0;
}

uint32_t mg_coap_compose(struct mg_coap_message *cm, struct mbuf *io) {
  struct mg_coap_option *opt;
  uint32_t res, prev_opt_number;
  size_t prev_io_len, packet_size;
  char *ptr;

  res = coap_calculate_packet_size(cm, &packet_size);
  if (res != 0) {
    return res;
  }

  
  prev_io_len = io->len;
  if (mbuf_append(io, NULL, packet_size) == 0) return MG_COAP_ERROR;
  ptr = io->buf + prev_io_len;

  

  
  *ptr = (1 << 6) | (cm->msg_type << 4) | (uint8_t)(cm->token.len);
  ptr++;

  
  *ptr = (cm->code_class << 5) | (cm->code_detail);
  ptr++;

  ptr = coap_add_uint16(ptr, cm->msg_id);

  if (cm->token.len != 0) {
    memcpy(ptr, cm->token.p, cm->token.len);
    ptr += cm->token.len;
  }

  opt = cm->options;
  prev_opt_number = 0;
  while (opt != NULL) {
    uint8_t delta_base = 0, length_base = 0;
    uint16_t delta_ext = 0, length_ext = 0;

    size_t opt_delta_len = coap_split_opt(opt->number - prev_opt_number, &delta_base, &delta_ext);
    size_t opt_lenght_len = coap_split_opt((uint32_t) opt->value.len, &length_base, &length_ext);

    *ptr = (delta_base << 4) | length_base;
    ptr++;

    ptr = coap_add_opt_info(ptr, delta_ext, opt_delta_len);
    ptr = coap_add_opt_info(ptr, length_ext, opt_lenght_len);

    if (opt->value.len != 0) {
      memcpy(ptr, opt->value.p, opt->value.len);
      ptr += opt->value.len;
    }

    prev_opt_number = opt->number;
    opt = opt->next;
  }

  if (cm->payload.len != 0) {
    *ptr = (char) -1;
    ptr++;
    memcpy(ptr, cm->payload.p, cm->payload.len);
  }

  return 0;
}

uint32_t mg_coap_send_message(struct mg_connection *nc, struct mg_coap_message *cm) {
  struct mbuf packet_out;
  uint32_t compose_res;

  mbuf_init(&packet_out, 0);
  compose_res = mg_coap_compose(cm, &packet_out);
  if (compose_res != 0) {
    return compose_res; 
  }

  mg_send(nc, packet_out.buf, (int) packet_out.len);
  mbuf_free(&packet_out);

  return 0;
}

uint32_t mg_coap_send_ack(struct mg_connection *nc, uint16_t msg_id) {
  struct mg_coap_message cm;
  memset(&cm, 0, sizeof(cm));
  cm.msg_type = MG_COAP_MSG_ACK;
  cm.msg_id = msg_id;

  return mg_coap_send_message(nc, &cm);
}

static void coap_handler(struct mg_connection *nc, int ev, void *ev_data MG_UD_ARG(void *user_data)) {
  struct mbuf *io = &nc->recv_mbuf;
  struct mg_coap_message cm;
  uint32_t parse_res;

  memset(&cm, 0, sizeof(cm));

  nc->handler(nc, ev, ev_data MG_UD_ARG(user_data));

  switch (ev) {
    case MG_EV_RECV:
      parse_res = mg_coap_parse(io, &cm);
      if ((parse_res & MG_COAP_IGNORE) == 0) {
        if ((cm.flags & MG_COAP_NOT_ENOUGH_DATA) != 0) {
          
          cm.flags |= MG_COAP_FORMAT_ERROR; 
        }                                   
        nc->handler(nc, MG_COAP_EVENT_BASE + cm.msg_type, &cm MG_UD_ARG(user_data));
      }

      mg_coap_free_options(&cm);
      mbuf_remove(io, io->len);
      break;
  }
}

int mg_set_protocol_coap(struct mg_connection *nc) {
  
  if ((nc->flags & MG_F_UDP) == 0) {
    return -1;
  }

  nc->proto_handler = coap_handler;

  return 0;
}























static uint64_t mg_get_sec(uint64_t val) {
  return (val & 0xFFFFFFFF00000000) >> 32;
}

static uint64_t mg_get_usec(uint64_t val) {
  uint64_t tmp = (val & 0x00000000FFFFFFFF);
  tmp *= 1000000;
  tmp >>= 32;
  return tmp;
}

static void mg_ntp_to_tv(uint64_t val, struct timeval *tv) {
  uint64_t tmp;
  tmp = mg_get_sec(val);
  tmp -= SNTP_TIME_OFFSET;
  tv->tv_sec = tmp;
  tv->tv_usec = mg_get_usec(val);
}

static void mg_get_ntp_ts(const char *ntp, uint64_t *val) {
  uint32_t tmp;
  memcpy(&tmp, ntp, sizeof(tmp));
  tmp = ntohl(tmp);
  *val = (uint64_t) tmp << 32;
  memcpy(&tmp, ntp + 4, sizeof(tmp));
  tmp = ntohl(tmp);
  *val |= tmp;
}

void mg_sntp_send_request(struct mg_connection *c) {
  uint8_t buf[48] = {0};
  
  buf[0] = (3 << 6) | (4 << 3) | 3;





  uint32_t sec;
  sec = htonl((uint32_t)(mg_time() + SNTP_TIME_OFFSET));
  memcpy(&buf[40], &sec, sizeof(sec));


  mg_send(c, buf, sizeof(buf));
}


static uint64_t mg_calculate_delay(uint64_t t1, uint64_t t2, uint64_t t3) {
  
  uint64_t d1 = ((mg_time() + SNTP_TIME_OFFSET) * 1000000) - (mg_get_sec(t1) * 1000000 + mg_get_usec(t1));
  uint64_t d2 = (mg_get_sec(t3) * 1000000 + mg_get_usec(t3)) - (mg_get_sec(t2) * 1000000 + mg_get_usec(t2));

  return (d1 > d2) ? d1 - d2 : 0;
}


MG_INTERNAL int mg_sntp_parse_reply(const char *buf, int len, struct mg_sntp_message *msg) {
  uint8_t hdr;
  uint64_t trsm_ts_T3, delay = 0;
  int mode;
  struct timeval tv;

  if (len < 48) {
    return -1;
  }

  hdr = buf[0];

  if ((hdr & 0x38) >> 3 != 4) {
    
    return -1;
  }

  mode = hdr & 0x7;
  if (mode != 4 && mode != 5) {
    
    return -1;
  }

  memset(msg, 0, sizeof(*msg));

  msg->kiss_of_death = (buf[1] == 0); 

  mg_get_ntp_ts(&buf[40], &trsm_ts_T3);


  {
    uint64_t orig_ts_T1, recv_ts_T2;
    mg_get_ntp_ts(&buf[24], &orig_ts_T1);
    mg_get_ntp_ts(&buf[32], &recv_ts_T2);
    delay = mg_calculate_delay(orig_ts_T1, recv_ts_T2, trsm_ts_T3);
  }


  mg_ntp_to_tv(trsm_ts_T3, &tv);

  msg->time = (double) tv.tv_sec + (((double) tv.tv_usec + delay) / 1000000.0);

  return 0;
}

static void mg_sntp_handler(struct mg_connection *c, int ev, void *ev_data MG_UD_ARG(void *user_data)) {
  struct mbuf *io = &c->recv_mbuf;
  struct mg_sntp_message msg;

  c->handler(c, ev, ev_data MG_UD_ARG(user_data));

  switch (ev) {
    case MG_EV_RECV: {
      if (mg_sntp_parse_reply(io->buf, io->len, &msg) < 0) {
        DBG(("Invalid SNTP packet received (%d)", (int) io->len));
        c->handler(c, MG_SNTP_MALFORMED_REPLY, NULL MG_UD_ARG(user_data));
      } else {
        c->handler(c, MG_SNTP_REPLY, (void *) &msg MG_UD_ARG(user_data));
      }

      mbuf_remove(io, io->len);
      break;
    }
  }
}

int mg_set_protocol_sntp(struct mg_connection *c) {
  if ((c->flags & MG_F_UDP) == 0) {
    return -1;
  }

  c->proto_handler = mg_sntp_handler;

  return 0;
}

struct mg_connection *mg_sntp_connect(struct mg_mgr *mgr, MG_CB(mg_event_handler_t event_handler, void *user_data), const char *sntp_server_name) {


  struct mg_connection *c = NULL;
  char url[100], *p_url = url;
  const char *proto = "", *port = "", *tmp;

  
  tmp = strchr(sntp_server_name, ':');
  if (tmp != NULL && *(tmp + 1) == '/') {
    tmp = strchr(tmp + 1, ':');
  }

  if (tmp == NULL) {
    port = ":123";
  }

  
  if (strncmp(sntp_server_name, "udp://", 6) != 0) {
    proto = "udp://";
  }

  mg_asprintf(&p_url, sizeof(url), "%s%s%s", proto, sntp_server_name, port);

  c = mg_connect(mgr, p_url, event_handler MG_UD_ARG(user_data));

  if (c == NULL) {
    goto cleanup;
  }

  mg_set_protocol_sntp(c);

cleanup:
  if (p_url != url) {
    MG_FREE(p_url);
  }

  return c;
}

struct sntp_data {
  mg_event_handler_t hander;
  int count;
};

static void mg_sntp_util_ev_handler(struct mg_connection *c, int ev, void *ev_data MG_UD_ARG(void *user_data)) {

  void *user_data = c->user_data;

  struct sntp_data *sd = (struct sntp_data *) user_data;

  switch (ev) {
    case MG_EV_CONNECT:
      if (*(int *) ev_data != 0) {
        mg_call(c, sd->hander, c->user_data, MG_SNTP_FAILED, NULL);
        break;
      }
    
    case MG_EV_TIMER:
      if (sd->count <= SNTP_ATTEMPTS) {
        mg_sntp_send_request(c);
        mg_set_timer(c, mg_time() + 10);
        sd->count++;
      } else {
        mg_call(c, sd->hander, c->user_data, MG_SNTP_FAILED, NULL);
        c->flags |= MG_F_CLOSE_IMMEDIATELY;
      }
      break;
    case MG_SNTP_MALFORMED_REPLY:
      mg_call(c, sd->hander, c->user_data, MG_SNTP_FAILED, NULL);
      c->flags |= MG_F_CLOSE_IMMEDIATELY;
      break;
    case MG_SNTP_REPLY:
      mg_call(c, sd->hander, c->user_data, MG_SNTP_REPLY, ev_data);
      c->flags |= MG_F_CLOSE_IMMEDIATELY;
      break;
    case MG_EV_CLOSE:
      MG_FREE(user_data);
      c->user_data = NULL;
      break;
  }
}

struct mg_connection *mg_sntp_get_time(struct mg_mgr *mgr, mg_event_handler_t event_handler, const char *sntp_server_name) {

  struct mg_connection *c;
  struct sntp_data *sd = (struct sntp_data *) MG_CALLOC(1, sizeof(*sd));
  if (sd == NULL) {
    return NULL;
  }

  c = mg_sntp_connect(mgr, MG_CB(mg_sntp_util_ev_handler, sd), sntp_server_name);
  if (c == NULL) {
    MG_FREE(sd);
    return NULL;
  }

  sd->hander = event_handler;

  c->user_data = sd;


  return c;
}













static void mg_socks5_handshake(struct mg_connection *c) {
  struct mbuf *r = &c->recv_mbuf;
  if (r->buf[0] != MG_SOCKS_VERSION) {
    c->flags |= MG_F_CLOSE_IMMEDIATELY;
  } else if (r->len > 2 && (size_t) r->buf[1] + 2 <= r->len) {
    
    unsigned char reply[2] = {MG_SOCKS_VERSION, MG_SOCKS_HANDSHAKE_FAILURE};
    int i;
    for (i = 2; i < r->buf[1] + 2; i++) {
      
      if (r->buf[i] == MG_SOCKS_HANDSHAKE_NOAUTH) reply[1] = r->buf[i];
    }
    mbuf_remove(r, 2 + r->buf[1]);
    mg_send(c, reply, sizeof(reply));
    c->flags |= MG_SOCKS_HANDSHAKE_DONE; 
  }
}

static void disband(struct mg_connection *c) {
  struct mg_connection *c2 = (struct mg_connection *) c->user_data;
  if (c2 != NULL) {
    c2->flags |= MG_F_SEND_AND_CLOSE;
    c2->user_data = NULL;
  }
  c->flags |= MG_F_SEND_AND_CLOSE;
  c->user_data = NULL;
}

static void relay_data(struct mg_connection *c) {
  struct mg_connection *c2 = (struct mg_connection *) c->user_data;
  if (c2 != NULL) {
    mg_send(c2, c->recv_mbuf.buf, c->recv_mbuf.len);
    mbuf_remove(&c->recv_mbuf, c->recv_mbuf.len);
  } else {
    c->flags |= MG_F_SEND_AND_CLOSE;
  }
}

static void serv_ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_CLOSE) {
    disband(c);
  } else if (ev == MG_EV_RECV) {
    relay_data(c);
  } else if (ev == MG_EV_CONNECT) {
    int res = *(int *) ev_data;
    if (res != 0) LOG(LL_ERROR, ("connect error: %d", res));
  }
}

static void mg_socks5_connect(struct mg_connection *c, const char *addr) {
  struct mg_connection *serv = mg_connect(c->mgr, addr, serv_ev_handler);
  serv->user_data = c;
  c->user_data = serv;
}


static void mg_socks5_handle_request(struct mg_connection *c) {
  struct mbuf *r = &c->recv_mbuf;
  unsigned char *p = (unsigned char *) r->buf;
  unsigned char addr_len = 4, reply = MG_SOCKS_SUCCESS;
  int ver, cmd, atyp;
  char addr[300];

  if (r->len < 8) return; 
  ver = p[0];
  cmd = p[1];
  atyp = p[3];

  
  if (ver != MG_SOCKS_VERSION || cmd != MG_SOCKS_CMD_CONNECT) {
    reply = MG_SOCKS_CMD_NOT_SUPPORTED;
  } else if (atyp == MG_SOCKS_ADDR_IPV4) {
    addr_len = 4;
    if (r->len < (size_t) addr_len + 6) return; 
    snprintf(addr, sizeof(addr), "%d.%d.%d.%d:%d", p[4], p[5], p[6], p[7], p[8] << 8 | p[9]);
    mg_socks5_connect(c, addr);
  } else if (atyp == MG_SOCKS_ADDR_IPV6) {
    addr_len = 16;
    if (r->len < (size_t) addr_len + 6) return; 
    snprintf(addr, sizeof(addr), "[%x:%x:%x:%x:%x:%x:%x:%x]:%d", p[4] << 8 | p[5], p[6] << 8 | p[7], p[8] << 8 | p[9], p[10] << 8 | p[11], p[12] << 8 | p[13], p[14] << 8 | p[15], p[16] << 8 | p[17], p[18] << 8 | p[19], p[20] << 8 | p[21]);


    mg_socks5_connect(c, addr);
  } else if (atyp == MG_SOCKS_ADDR_DOMAIN) {
    addr_len = p[4] + 1;
    if (r->len < (size_t) addr_len + 6) return; 
    snprintf(addr, sizeof(addr), "%.*s:%d", p[4], p + 5, p[4 + addr_len] << 8 | p[4 + addr_len + 1]);
    mg_socks5_connect(c, addr);
  } else {
    reply = MG_SOCKS_ADDR_NOT_SUPPORTED;
  }

  
  {
    unsigned char buf[] = {MG_SOCKS_VERSION, reply, 0};
    mg_send(c, buf, sizeof(buf));
  }
  mg_send(c, r->buf + 3, addr_len + 1 + 2);

  mbuf_remove(r, 6 + addr_len);      
  c->flags |= MG_SOCKS_CONNECT_DONE; 
}

static void socks_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_RECV) {
    if (!(c->flags & MG_SOCKS_HANDSHAKE_DONE)) mg_socks5_handshake(c);
    if (c->flags & MG_SOCKS_HANDSHAKE_DONE && !(c->flags & MG_SOCKS_CONNECT_DONE)) {
      mg_socks5_handle_request(c);
    }
    if (c->flags & MG_SOCKS_CONNECT_DONE) relay_data(c);
  } else if (ev == MG_EV_CLOSE) {
    disband(c);
  }
  (void) ev_data;
}

void mg_set_protocol_socks(struct mg_connection *c) {
  c->proto_handler = socks_handler;
}






























int asprintf(char **strp, const char *fmt, ...) {
  va_list ap;
  int len;

  *strp = MG_MALLOC(BUFSIZ);
  if (*strp == NULL) return -1;

  va_start(ap, fmt);
  len = vsnprintf(*strp, BUFSIZ, fmt, ap);
  va_end(ap);

  if (len > 0) {
    *strp = MG_REALLOC(*strp, len + 1);
    if (*strp == NULL) return -1;
  }

  if (len >= BUFSIZ) {
    va_start(ap, fmt);
    len = vsnprintf(*strp, len + 1, fmt, ap);
    va_end(ap);
  }

  return len;
}


time_t HOSTtime() {
  struct timeval tp;
  gettimeofday(&tp, NULL);
  return tp.tv_sec;
}




void fprint_str(FILE *fp, const char *str) {
  while (*str != '\0') {
    if (*str == '\n') MAP_UARTCharPut(CONSOLE_UART, '\r');
    MAP_UARTCharPut(CONSOLE_UART, *str++);
  }
}

void _exit(int status) {
  fprint_str(stderr, "_exit\n");
  
  *(int *) 1 = status;
  while (1)
    ; 
}

void _not_implemented(const char *what) {
  fprint_str(stderr, what);
  fprint_str(stderr, " is not implemented\n");
  _exit(42);
}

int _kill(int pid, int sig) {
  (void) pid;
  (void) sig;
  _not_implemented("_kill");
  return -1;
}

int _getpid() {
  fprint_str(stderr, "_getpid is not implemented\n");
  return 42;
}

int _isatty(int fd) {
  
  return fd < 2;
}












int gettimeofday(struct timeval *tp, void *tzp) {
  uint32_t ticks = Clock_getTicks();
  tp->tv_sec = ticks / 1000;
  tp->tv_usec = (ticks % 1000) * 1000;
  return 0;
}








int gettimeofday(struct timeval *tp, void *tzp) {
  
  tp->tv_sec = 0;
  tp->tv_usec = 0;
  return 0;
}




















int fs_slfs_open(const char *pathname, int flags, mode_t mode);
int fs_slfs_close(int fd);
ssize_t fs_slfs_read(int fd, void *buf, size_t count);
ssize_t fs_slfs_write(int fd, const void *buf, size_t count);
int fs_slfs_stat(const char *pathname, struct stat *s);
int fs_slfs_fstat(int fd, struct stat *s);
off_t fs_slfs_lseek(int fd, off_t offset, int whence);
int fs_slfs_unlink(const char *filename);
int fs_slfs_rename(const char *from, const char *to);

void fs_slfs_set_new_file_size(const char *name, size_t size);

























int slfs_open(const unsigned char *fname, uint32_t flags) {
  _i32 fh;
  _i32 r = sl_FsOpen(fname, flags, NULL , &fh);
  return (r < 0 ? r : fh);
}

int slfs_open(const unsigned char *fname, uint32_t flags) {
  return sl_FsOpen(fname, flags, NULL );
}



int set_errno(int e);
const char *drop_dir(const char *fname, bool *is_slfs);






struct sl_file_size_hint {
  char *name;
  size_t size;
};

struct sl_fd_info {
  _i32 fh;
  _off_t pos;
  size_t size;
};

static struct sl_fd_info s_sl_fds[MAX_OPEN_SLFS_FILES];
static struct sl_file_size_hint s_sl_file_size_hints[MAX_OPEN_SLFS_FILES];

static int sl_fs_to_errno(_i32 r) {
  DBG(("SL error: %d", (int) r));
  switch (r) {
    case SL_FS_OK:
      return 0;
    case SL_ERROR_FS_FILE_NAME_EXIST:
      return EEXIST;
    case SL_ERROR_FS_WRONG_FILE_NAME:
      return EINVAL;
    case SL_ERROR_FS_NO_AVAILABLE_NV_INDEX:
    case SL_ERROR_FS_NOT_ENOUGH_STORAGE_SPACE:
      return ENOSPC;
    case SL_ERROR_FS_FAILED_TO_ALLOCATE_MEM:
      return ENOMEM;
    case SL_ERROR_FS_FILE_NOT_EXISTS:
      return ENOENT;
    case SL_ERROR_FS_NOT_SUPPORTED:
      return ENOTSUP;
  }
  return ENXIO;
}

int fs_slfs_open(const char *pathname, int flags, mode_t mode) {
  int fd;
  for (fd = 0; fd < MAX_OPEN_SLFS_FILES; fd++) {
    if (s_sl_fds[fd].fh <= 0) break;
  }
  if (fd >= MAX_OPEN_SLFS_FILES) return set_errno(ENOMEM);
  struct sl_fd_info *fi = &s_sl_fds[fd];

  
  pathname = drop_dir(pathname, NULL);

  _u32 am = 0;
  fi->size = (size_t) -1;
  int rw = (flags & 3);
  size_t new_size = FS_SLFS_MAX_FILE_SIZE;
  if (rw == O_RDONLY) {
    SlFsFileInfo_t sl_fi;
    _i32 r = sl_FsGetInfo((const _u8 *) pathname, 0, &sl_fi);
    if (r == SL_FS_OK) {
      fi->size = SL_FI_FILE_SIZE(sl_fi);
    }
    am = SL_FS_READ;
  } else {
    if (!(flags & O_TRUNC) || (flags & O_APPEND)) {
      
      
      return set_errno(ENOTSUP);
    }
    if (flags & O_CREAT) {
      size_t i;
      for (i = 0; i < MAX_OPEN_SLFS_FILES; i++) {
        if (s_sl_file_size_hints[i].name != NULL && strcmp(s_sl_file_size_hints[i].name, pathname) == 0) {
          new_size = s_sl_file_size_hints[i].size;
          MG_FREE(s_sl_file_size_hints[i].name);
          s_sl_file_size_hints[i].name = NULL;
          break;
        }
      }
      am = FS_MODE_OPEN_CREATE(new_size, 0);
    } else {
      am = SL_FS_WRITE;
    }
  }
  fi->fh = slfs_open((_u8 *) pathname, am);
  LOG(LL_DEBUG, ("sl_FsOpen(%s, 0x%x) sz %u = %d", pathname, (int) am, (unsigned int) new_size, (int) fi->fh));
  int r;
  if (fi->fh >= 0) {
    fi->pos = 0;
    r = fd;
  } else {
    r = set_errno(sl_fs_to_errno(fi->fh));
  }
  return r;
}

int fs_slfs_close(int fd) {
  struct sl_fd_info *fi = &s_sl_fds[fd];
  if (fi->fh <= 0) return set_errno(EBADF);
  _i32 r = sl_FsClose(fi->fh, NULL, NULL, 0);
  LOG(LL_DEBUG, ("sl_FsClose(%d) = %d", (int) fi->fh, (int) r));
  s_sl_fds[fd].fh = -1;
  return set_errno(sl_fs_to_errno(r));
}

ssize_t fs_slfs_read(int fd, void *buf, size_t count) {
  struct sl_fd_info *fi = &s_sl_fds[fd];
  if (fi->fh <= 0) return set_errno(EBADF);
  
  if (fi->pos == fi->size) return 0;
  _i32 r = sl_FsRead(fi->fh, fi->pos, buf, count);
  DBG(("sl_FsRead(%d, %d, %d) = %d", (int) fi->fh, (int) fi->pos, (int) count, (int) r));
  if (r >= 0) {
    fi->pos += r;
    return r;
  }
  return set_errno(sl_fs_to_errno(r));
}

ssize_t fs_slfs_write(int fd, const void *buf, size_t count) {
  struct sl_fd_info *fi = &s_sl_fds[fd];
  if (fi->fh <= 0) return set_errno(EBADF);
  _i32 r = sl_FsWrite(fi->fh, fi->pos, (_u8 *) buf, count);
  DBG(("sl_FsWrite(%d, %d, %d) = %d", (int) fi->fh, (int) fi->pos, (int) count, (int) r));
  if (r >= 0) {
    fi->pos += r;
    return r;
  }
  return set_errno(sl_fs_to_errno(r));
}

int fs_slfs_stat(const char *pathname, struct stat *s) {
  SlFsFileInfo_t sl_fi;
  
  pathname = drop_dir(pathname, NULL);
  _i32 r = sl_FsGetInfo((const _u8 *) pathname, 0, &sl_fi);
  if (r == SL_FS_OK) {
    s->st_mode = S_IFREG | 0666;
    s->st_nlink = 1;
    s->st_size = SL_FI_FILE_SIZE(sl_fi);
    return 0;
  }
  return set_errno(sl_fs_to_errno(r));
}

int fs_slfs_fstat(int fd, struct stat *s) {
  struct sl_fd_info *fi = &s_sl_fds[fd];
  if (fi->fh <= 0) return set_errno(EBADF);
  s->st_mode = 0666;
  s->st_mode = S_IFREG | 0666;
  s->st_nlink = 1;
  s->st_size = fi->size;
  return 0;
}

off_t fs_slfs_lseek(int fd, off_t offset, int whence) {
  if (s_sl_fds[fd].fh <= 0) return set_errno(EBADF);
  switch (whence) {
    case SEEK_SET:
      s_sl_fds[fd].pos = offset;
      break;
    case SEEK_CUR:
      s_sl_fds[fd].pos += offset;
      break;
    case SEEK_END:
      return set_errno(ENOTSUP);
  }
  return 0;
}

int fs_slfs_unlink(const char *pathname) {
  
  pathname = drop_dir(pathname, NULL);
  return set_errno(sl_fs_to_errno(sl_FsDel((const _u8 *) pathname, 0)));
}

int fs_slfs_rename(const char *from, const char *to) {
  return set_errno(ENOTSUP);
}

void fs_slfs_set_new_file_size(const char *name, size_t size) {
  int i;
  for (i = 0; i < MAX_OPEN_SLFS_FILES; i++) {
    if (s_sl_file_size_hints[i].name == NULL) {
      DBG(("File size hint: %s %d", name, (int) size));
      s_sl_file_size_hints[i].name = strdup(name);
      s_sl_file_size_hints[i].size = size;
      break;
    }
  }
}









int set_errno(int e) {
  errno = e;
  return (e == 0 ? 0 : -1);
}

const char *drop_dir(const char *fname, bool *is_slfs) {
  if (is_slfs != NULL) {
    *is_slfs = (strncmp(fname, "SL:", 3) == 0);
    if (*is_slfs) fname += 3;
  }
  
  if (fname[0] == '.' && fname[1] == '/') {
    fname += 2;
  }
  
  if (fname[0] == '/' && strchr(fname + 1, '/') == NULL) {
    fname++;
  }
  return fname;
}








































enum fd_type {
  FD_INVALID, FD_SYS,  FD_SPIFFS,   FD_SLFS  };







static int fd_type(int fd) {
  if (fd >= 0 && fd < NUM_SYS_FDS) return FD_SYS;

  if (fd >= SPIFFS_FD_BASE && fd < SPIFFS_FD_BASE + MAX_OPEN_SPIFFS_FILES) {
    return FD_SPIFFS;
  }


  if (fd >= SLFS_FD_BASE && fd < SLFS_FD_BASE + MAX_OPEN_SLFS_FILES) {
    return FD_SLFS;
  }

  return FD_INVALID;
}


int open(const char *pathname, unsigned flags, int mode) {

int _open(const char *pathname, int flags, mode_t mode) {

  int fd = -1;
  bool is_sl;
  const char *fname = drop_dir(pathname, &is_sl);
  if (is_sl) {

    fd = fs_slfs_open(fname, flags, mode);
    if (fd >= 0) fd += SLFS_FD_BASE;

  } else {

    fd = fs_spiffs_open(fname, flags, mode);
    if (fd >= 0) fd += SPIFFS_FD_BASE;

  }
  LOG(LL_DEBUG, ("open(%s, 0x%x) = %d, fname = %s", pathname, flags, fd, fname));
  return fd;
}

int _stat(const char *pathname, struct stat *st) {
  int res = -1;
  bool is_sl;
  const char *fname = drop_dir(pathname, &is_sl);
  memset(st, 0, sizeof(*st));
  
  if (fname[0] == '\0' || strcmp(fname, ".") == 0) {
    st->st_ino = 0;
    st->st_mode = S_IFDIR | 0777;
    st->st_nlink = 1;
    st->st_size = 0;
    return 0;
  }
  if (is_sl) {

    res = fs_slfs_stat(fname, st);

  } else {

    res = fs_spiffs_stat(fname, st);

  }
  LOG(LL_DEBUG, ("stat(%s) = %d; fname = %s", pathname, res, fname));
  return res;
}


int close(int fd) {

int _close(int fd) {

  int r = -1;
  switch (fd_type(fd)) {
    case FD_INVALID:
      r = set_errno(EBADF);
      break;
    case FD_SYS:
      r = set_errno(EACCES);
      break;

    case FD_SPIFFS:
      r = fs_spiffs_close(fd - SPIFFS_FD_BASE);
      break;


    case FD_SLFS:
      r = fs_slfs_close(fd - SLFS_FD_BASE);
      break;

  }
  DBG(("close(%d) = %d", fd, r));
  return r;
}


off_t lseek(int fd, off_t offset, int whence) {

off_t _lseek(int fd, off_t offset, int whence) {

  int r = -1;
  switch (fd_type(fd)) {
    case FD_INVALID:
      r = set_errno(EBADF);
      break;
    case FD_SYS:
      r = set_errno(ESPIPE);
      break;

    case FD_SPIFFS:
      r = fs_spiffs_lseek(fd - SPIFFS_FD_BASE, offset, whence);
      break;


    case FD_SLFS:
      r = fs_slfs_lseek(fd - SLFS_FD_BASE, offset, whence);
      break;

  }
  DBG(("lseek(%d, %d, %d) = %d", fd, (int) offset, whence, r));
  return r;
}

int _fstat(int fd, struct stat *s) {
  int r = -1;
  memset(s, 0, sizeof(*s));
  switch (fd_type(fd)) {
    case FD_INVALID:
      r = set_errno(EBADF);
      break;
    case FD_SYS: {
      
      memset(s, 0, sizeof(*s));
      s->st_ino = fd;
      s->st_mode = S_IFCHR | 0666;
      r = 0;
      break;
    }

    case FD_SPIFFS:
      r = fs_spiffs_fstat(fd - SPIFFS_FD_BASE, s);
      break;


    case FD_SLFS:
      r = fs_slfs_fstat(fd - SLFS_FD_BASE, s);
      break;

  }
  DBG(("fstat(%d) = %d", fd, r));
  return r;
}


int read(int fd, char *buf, unsigned count) {

ssize_t _read(int fd, void *buf, size_t count) {

  int r = -1;
  switch (fd_type(fd)) {
    case FD_INVALID:
      r = set_errno(EBADF);
      break;
    case FD_SYS: {
      if (fd != 0) {
        r = set_errno(EACCES);
        break;
      }
      
      r = set_errno(ENOTSUP);
      break;
    }

    case FD_SPIFFS:
      r = fs_spiffs_read(fd - SPIFFS_FD_BASE, buf, count);
      break;


    case FD_SLFS:
      r = fs_slfs_read(fd - SLFS_FD_BASE, buf, count);
      break;

  }
  DBG(("read(%d, %u) = %d", fd, count, r));
  return r;
}


int write(int fd, const char *buf, unsigned count) {

ssize_t _write(int fd, const void *buf, size_t count) {

  int r = -1;
  switch (fd_type(fd)) {
    case FD_INVALID:
      r = set_errno(EBADF);
      break;
    case FD_SYS: {
      if (fd == 0) {
        r = set_errno(EACCES);
        break;
      }

      MG_UART_WRITE(fd, buf, count);

      {
        size_t i;
        for (i = 0; i < count; i++) {
          const char c = ((const char *) buf)[i];
          if (c == '\n') MG_UART_CHAR_PUT(fd, '\r');
          MG_UART_CHAR_PUT(fd, c);
        }
      }

      r = count;
      break;
    }

    case FD_SPIFFS:
      r = fs_spiffs_write(fd - SPIFFS_FD_BASE, buf, count);
      break;


    case FD_SLFS:
      r = fs_slfs_write(fd - SLFS_FD_BASE, buf, count);
      break;

  }
  return r;
}



int rename(const char *frompath, const char *topath) {
  int r = -1;
  bool is_sl_from, is_sl_to;
  const char *from = drop_dir(frompath, &is_sl_from);
  const char *to = drop_dir(topath, &is_sl_to);
  if (is_sl_from || is_sl_to) {
    set_errno(ENOTSUP);
  } else {

    r = fs_spiffs_rename(from, to);

  }
  DBG(("rename(%s, %s) = %d", from, to, r));
  return r;
}



int unlink(const char *pathname) {

int _unlink(const char *pathname) {

  int r = -1;
  bool is_sl;
  const char *fname = drop_dir(pathname, &is_sl);
  if (is_sl) {

    r = fs_slfs_unlink(fname);

  } else {

    r = fs_spiffs_unlink(fname);

  }
  DBG(("unlink(%s) = %d, fname = %s", pathname, r, fname));
  return r;
}


DIR *opendir(const char *dir_name) {
  DIR *r = NULL;
  bool is_sl;
  drop_dir(dir_name, &is_sl);
  if (is_sl) {
    r = NULL;
    set_errno(ENOTSUP);
  } else {
    r = fs_spiffs_opendir(dir_name);
  }
  DBG(("opendir(%s) = %p", dir_name, r));
  return r;
}

struct dirent *readdir(DIR *dir) {
  struct dirent *res = fs_spiffs_readdir(dir);
  DBG(("readdir(%p) = %p", dir, res));
  return res;
}

int closedir(DIR *dir) {
  int res = fs_spiffs_closedir(dir);
  DBG(("closedir(%p) = %d", dir, res));
  return res;
}

int rmdir(const char *path) {
  return fs_spiffs_rmdir(path);
}

int mkdir(const char *path, mode_t mode) {
  (void) path;
  (void) mode;
  
  return (strlen(path) == 1 && *path == '.') ? 0 : ENOTDIR;
}


int sl_fs_init(void) {
  int ret = 1;




  ret = (add_device("SL", _MSA, fs_slfs_open, fs_slfs_close, fs_slfs_read, fs_slfs_write, fs_slfs_lseek, fs_slfs_unlink, fs_slfs_rename) == 0);




  return ret;
}















const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
  int res;
  struct in_addr *in = (struct in_addr *) src;
  if (af != AF_INET) {
    errno = ENOTSUP;
    return NULL;
  }
  res = snprintf(dst, size, "%lu.%lu.%lu.%lu", SL_IPV4_BYTE(in->s_addr, 0), SL_IPV4_BYTE(in->s_addr, 1), SL_IPV4_BYTE(in->s_addr, 2), SL_IPV4_BYTE(in->s_addr, 3));

  return res > 0 ? dst : NULL;
}

char *inet_ntoa(struct in_addr n) {
  static char a[16];
  return (char *) inet_ntop(AF_INET, &n, a, sizeof(a));
}

int inet_pton(int af, const char *src, void *dst) {
  uint32_t a0, a1, a2, a3;
  uint8_t *db = (uint8_t *) dst;
  if (af != AF_INET) {
    errno = ENOTSUP;
    return 0;
  }
  if (sscanf(src, "%lu.%lu.%lu.%lu", &a0, &a1, &a2, &a3) != 4) {
    return 0;
  }
  *db = a3;
  *(db + 1) = a2;
  *(db + 2) = a1;
  *(db + 3) = a0;
  return 1;
}











enum mg_q_msg_type {
  MG_Q_MSG_CB, };
struct mg_q_msg {
  enum mg_q_msg_type type;
  void (*cb)(struct mg_mgr *mgr, void *arg);
  void *arg;
};
static OsiMsgQ_t s_mg_q;
static void mg_task(void *arg);

bool mg_start_task(int priority, int stack_size, mg_init_cb mg_init) {
  if (osi_MsgQCreate(&s_mg_q, "MG", sizeof(struct mg_q_msg), 16) != OSI_OK) {
    return false;
  }
  if (osi_TaskCreate(mg_task, (const signed char *) "MG", stack_size, (void *) mg_init, priority, NULL) != OSI_OK) {
    return false;
  }
  return true;
}

static void mg_task(void *arg) {
  struct mg_mgr mgr;
  mg_init_cb mg_init = (mg_init_cb) arg;
  mg_mgr_init(&mgr, NULL);
  mg_init(&mgr);
  while (1) {
    struct mg_q_msg msg;
    mg_mgr_poll(&mgr, 1);
    if (osi_MsgQRead(&s_mg_q, &msg, 1) != OSI_OK) continue;
    switch (msg.type) {
      case MG_Q_MSG_CB: {
        msg.cb(&mgr, msg.arg);
      }
    }
  }
}

void mg_run_in_task(void (*cb)(struct mg_mgr *mgr, void *arg), void *cb_arg) {
  struct mg_q_msg msg = {MG_Q_MSG_CB, cb, cb_arg};
  osi_MsgQWrite(&s_mg_q, &msg, OSI_NO_WAIT);
}













extern "C" {






extern const struct mg_iface_vtable mg_simplelink_iface_vtable;


}


















static sock_t mg_open_listening_socket(struct mg_connection *nc, union socket_address *sa, int type, int proto);


static void mg_set_non_blocking_mode(sock_t sock) {
  SlSockNonblocking_t opt;

  opt.NonblockingEnabled = 1;

  opt.NonBlockingEnabled = 1;

  sl_SetSockOpt(sock, SL_SOL_SOCKET, SL_SO_NONBLOCKING, &opt, sizeof(opt));
}

static int mg_is_error(int n) {
  return (n < 0 && n != SL_ERROR_BSD_EALREADY && n != SL_ERROR_BSD_EAGAIN);
}

static void mg_sl_if_connect_tcp(struct mg_connection *nc, const union socket_address *sa) {
  int proto = 0;

  if (nc->flags & MG_F_SSL) proto = SL_SEC_SOCKET;

  sock_t sock = sl_Socket(AF_INET, SOCK_STREAM, proto);
  if (sock < 0) {
    nc->err = sock;
    goto out;
  }
  mg_sock_set(nc, sock);

  nc->err = sl_set_ssl_opts(sock, nc);
  if (nc->err != 0) goto out;

  nc->err = sl_Connect(sock, &sa->sa, sizeof(sa->sin));
out:
  DBG(("%p to %s:%d sock %d %d err %d", nc, inet_ntoa(sa->sin.sin_addr), ntohs(sa->sin.sin_port), nc->sock, proto, nc->err));
}

static void mg_sl_if_connect_udp(struct mg_connection *nc) {
  sock_t sock = sl_Socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    nc->err = sock;
    return;
  }
  mg_sock_set(nc, sock);
  nc->err = 0;
}

static int mg_sl_if_listen_tcp(struct mg_connection *nc, union socket_address *sa) {
  int proto = 0;
  if (nc->flags & MG_F_SSL) proto = SL_SEC_SOCKET;
  sock_t sock = mg_open_listening_socket(nc, sa, SOCK_STREAM, proto);
  if (sock < 0) return sock;
  mg_sock_set(nc, sock);
  return 0;
}

static int mg_sl_if_listen_udp(struct mg_connection *nc, union socket_address *sa) {
  sock_t sock = mg_open_listening_socket(nc, sa, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) return (errno ? errno : 1);
  mg_sock_set(nc, sock);
  return 0;
}

static int mg_sl_if_tcp_send(struct mg_connection *nc, const void *buf, size_t len) {
  int n = (int) sl_Send(nc->sock, buf, len, 0);
  if (n < 0 && !mg_is_error(n)) n = 0;
  return n;
}

static int mg_sl_if_udp_send(struct mg_connection *nc, const void *buf, size_t len) {
  int n = sl_SendTo(nc->sock, buf, len, 0, &nc->sa.sa, sizeof(nc->sa.sin));
  if (n < 0 && !mg_is_error(n)) n = 0;
  return n;
}

static int mg_sl_if_tcp_recv(struct mg_connection *nc, void *buf, size_t len) {
  int n = sl_Recv(nc->sock, buf, len, 0);
  if (n == 0) {
    
    nc->flags |= MG_F_SEND_AND_CLOSE;
  } else if (n < 0 && !mg_is_error(n)) {
    n = 0;
  }
  return n;
}

static int mg_sl_if_udp_recv(struct mg_connection *nc, void *buf, size_t len, union socket_address *sa, size_t *sa_len) {
  SlSocklen_t sa_len_t = *sa_len;
  int n = sl_RecvFrom(nc->sock, buf, MG_UDP_RECV_BUFFER_SIZE, 0, (SlSockAddr_t *) sa, &sa_len_t);
  *sa_len = sa_len_t;
  if (n < 0 && !mg_is_error(n)) n = 0;
  return n;
}

static int mg_sl_if_create_conn(struct mg_connection *nc) {
  (void) nc;
  return 1;
}

void mg_sl_if_destroy_conn(struct mg_connection *nc) {
  if (nc->sock == INVALID_SOCKET) return;
  
  if (!(nc->flags & MG_F_UDP) || nc->listener == NULL) {
    sl_Close(nc->sock);
  }
  nc->sock = INVALID_SOCKET;
}

static int mg_accept_conn(struct mg_connection *lc) {
  struct mg_connection *nc;
  union socket_address sa;
  socklen_t sa_len = sizeof(sa);
  sock_t sock = sl_Accept(lc->sock, &sa.sa, &sa_len);
  if (sock < 0) {
    DBG(("%p: failed to accept: %d", lc, sock));
    return 0;
  }
  nc = mg_if_accept_new_conn(lc);
  if (nc == NULL) {
    sl_Close(sock);
    return 0;
  }
  DBG(("%p conn from %s:%d", nc, inet_ntoa(sa.sin.sin_addr), ntohs(sa.sin.sin_port)));
  mg_sock_set(nc, sock);
  mg_if_accept_tcp_cb(nc, &sa, sa_len);
  return 1;
}


static sock_t mg_open_listening_socket(struct mg_connection *nc, union socket_address *sa, int type, int proto) {

  int r;
  socklen_t sa_len = (sa->sa.sa_family == AF_INET) ? sizeof(sa->sin) : sizeof(sa->sin6);
  sock_t sock = sl_Socket(sa->sa.sa_family, type, proto);
  if (sock < 0) return sock;

  if ((r = sl_set_ssl_opts(sock, nc)) < 0) goto clean;

  if ((r = sl_Bind(sock, &sa->sa, sa_len)) < 0) goto clean;
  if (type != SOCK_DGRAM) {
    if ((r = sl_Listen(sock, SOMAXCONN)) < 0) goto clean;
  }
  mg_set_non_blocking_mode(sock);
clean:
  if (r < 0) {
    sl_Close(sock);
    sock = r;
  }
  return sock;
}





void mg_mgr_handle_conn(struct mg_connection *nc, int fd_flags, double now) {
  DBG(("%p fd=%d fd_flags=%d nc_flags=0x%lx rmbl=%d smbl=%d", nc, nc->sock, fd_flags, nc->flags, (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));

  if (!mg_if_poll(nc, now)) return;

  if (nc->flags & MG_F_CONNECTING) {
    if ((nc->flags & MG_F_UDP) || nc->err != SL_ERROR_BSD_EALREADY) {
      mg_if_connect_cb(nc, nc->err);
    } else {
      
      if (fd_flags & _MG_F_FD_CAN_WRITE) {
        nc->err = sl_Connect(nc->sock, &nc->sa.sa, sizeof(nc->sa.sin));
        DBG(("%p conn res=%d", nc, nc->err));
        if (nc->err == SL_ERROR_BSD_ESECSNOVERIFY ||  nc->err == SL_ERROR_BSD_ESECDATEERROR   || nc->err == SL_ERROR_BSD_ESECUNKNOWNROOTCA  ) {







          nc->err = 0;
        }
        mg_if_connect_cb(nc, nc->err);
      }
    }
    
    fd_flags &= ~(_MG_F_FD_CAN_READ | _MG_F_FD_CAN_WRITE);
  }

  if (fd_flags & _MG_F_FD_CAN_READ) {
    if (nc->flags & MG_F_UDP) {
      mg_if_can_recv_cb(nc);
    } else {
      if (nc->flags & MG_F_LISTENING) {
        mg_accept_conn(nc);
      } else {
        mg_if_can_recv_cb(nc);
      }
    }
  }

  if (fd_flags & _MG_F_FD_CAN_WRITE) {
    mg_if_can_send_cb(nc);
  }

  DBG(("%p after fd=%d nc_flags=0x%lx rmbl=%d smbl=%d", nc, nc->sock, nc->flags, (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));
}


void mg_sl_if_sock_set(struct mg_connection *nc, sock_t sock) {
  mg_set_non_blocking_mode(sock);
  nc->sock = sock;
  DBG(("%p %d", nc, sock));
}

void mg_sl_if_init(struct mg_iface *iface) {
  (void) iface;
  DBG(("%p using sl_Select()", iface->mgr));
}

void mg_sl_if_free(struct mg_iface *iface) {
  (void) iface;
}

void mg_sl_if_add_conn(struct mg_connection *nc) {
  (void) nc;
}

void mg_sl_if_remove_conn(struct mg_connection *nc) {
  (void) nc;
}

time_t mg_sl_if_poll(struct mg_iface *iface, int timeout_ms) {
  struct mg_mgr *mgr = iface->mgr;
  double now = mg_time();
  double min_timer;
  struct mg_connection *nc, *tmp;
  struct SlTimeval_t tv;
  SlFdSet_t read_set, write_set, err_set;
  sock_t max_fd = INVALID_SOCKET;
  int num_fds, num_ev = 0, num_timers = 0;

  SL_SOCKET_FD_ZERO(&read_set);
  SL_SOCKET_FD_ZERO(&write_set);
  SL_SOCKET_FD_ZERO(&err_set);

  
  min_timer = 0;
  for (nc = mgr->active_connections, num_fds = 0; nc != NULL; nc = tmp) {
    tmp = nc->next;

    if (nc->sock != INVALID_SOCKET) {
      num_fds++;

      if (!(nc->flags & MG_F_WANT_WRITE) && nc->recv_mbuf.len < nc->recv_mbuf_limit && (!(nc->flags & MG_F_UDP) || nc->listener == NULL)) {

        SL_SOCKET_FD_SET(nc->sock, &read_set);
        if (max_fd == INVALID_SOCKET || nc->sock > max_fd) max_fd = nc->sock;
      }

      if (((nc->flags & MG_F_CONNECTING) && !(nc->flags & MG_F_WANT_READ)) || (nc->send_mbuf.len > 0 && !(nc->flags & MG_F_CONNECTING))) {
        SL_SOCKET_FD_SET(nc->sock, &write_set);
        SL_SOCKET_FD_SET(nc->sock, &err_set);
        if (max_fd == INVALID_SOCKET || nc->sock > max_fd) max_fd = nc->sock;
      }
    }

    if (nc->ev_timer_time > 0) {
      if (num_timers == 0 || nc->ev_timer_time < min_timer) {
        min_timer = nc->ev_timer_time;
      }
      num_timers++;
    }
  }

  
  if (num_timers > 0) {
    double timer_timeout_ms = (min_timer - mg_time()) * 1000 + 1 ;
    if (timer_timeout_ms < timeout_ms) {
      timeout_ms = timer_timeout_ms;
    }
  }
  if (timeout_ms < 0) timeout_ms = 0;

  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  if (num_fds > 0) {
    num_ev = sl_Select((int) max_fd + 1, &read_set, &write_set, &err_set, &tv);
  }

  now = mg_time();
  DBG(("sl_Select @ %ld num_ev=%d of %d, timeout=%d", (long) now, num_ev, num_fds, timeout_ms));

  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    int fd_flags = 0;
    if (nc->sock != INVALID_SOCKET) {
      if (num_ev > 0) {
        fd_flags = (SL_SOCKET_FD_ISSET(nc->sock, &read_set) && (!(nc->flags & MG_F_UDP) || nc->listener == NULL)

                 ? _MG_F_FD_CAN_READ : 0) | (SL_SOCKET_FD_ISSET(nc->sock, &write_set) ? _MG_F_FD_CAN_WRITE : 0) | (SL_SOCKET_FD_ISSET(nc->sock, &err_set) ? _MG_F_FD_ERROR : 0);



      }
      
      if (nc->flags & MG_F_UDP && nc->send_mbuf.len > 0) {
        fd_flags |= _MG_F_FD_CAN_WRITE;
      }
    }
    tmp = nc->next;
    mg_mgr_handle_conn(nc, fd_flags, now);
  }

  return now;
}

void mg_sl_if_get_conn_addr(struct mg_connection *nc, int remote, union socket_address *sa) {
  
  if (remote) memcpy(sa, &nc->sa, sizeof(*sa));
}

void sl_restart_cb(struct mg_mgr *mgr) {
  
  struct mg_connection *nc;
  for (nc = mg_next(mgr, NULL); nc != NULL; nc = mg_next(mgr, nc)) {
    if (nc->sock == INVALID_SOCKET) continue; 
    if (nc->flags & MG_F_LISTENING) {
      DBG(("restarting %p %s:%d", nc, inet_ntoa(nc->sa.sin.sin_addr), ntohs(nc->sa.sin.sin_port)));
      int res = (nc->flags & MG_F_UDP ? mg_sl_if_listen_udp(nc, &nc->sa)
                                      : mg_sl_if_listen_tcp(nc, &nc->sa));
      if (res == 0) continue;
      
    }
    nc->sock = INVALID_SOCKET;
    DBG(("terminating %p %s:%d", nc, inet_ntoa(nc->sa.sin.sin_addr), ntohs(nc->sa.sin.sin_port)));
    
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  }
}























const struct mg_iface_vtable mg_simplelink_iface_vtable = MG_SL_IFACE_VTABLE;

const struct mg_iface_vtable mg_default_iface_vtable = MG_SL_IFACE_VTABLE;


















struct mg_ssl_if_ctx {
  char *ssl_cert;
  char *ssl_key;
  char *ssl_ca_cert;
  char *ssl_server_name;
};

void mg_ssl_if_init() {
}

enum mg_ssl_if_result mg_ssl_if_conn_init( struct mg_connection *nc, const struct mg_ssl_if_conn_params *params, const char **err_msg) {

  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) MG_CALLOC(1, sizeof(*ctx));
  if (ctx == NULL) {
    MG_SET_PTRPTR(err_msg, "Out of memory");
    return MG_SSL_ERROR;
  }
  nc->ssl_if_data = ctx;

  if (params->cert != NULL || params->key != NULL) {
    if (params->cert != NULL && params->key != NULL) {
      ctx->ssl_cert = strdup(params->cert);
      ctx->ssl_key = strdup(params->key);
    } else {
      MG_SET_PTRPTR(err_msg, "Both cert and key are required.");
      return MG_SSL_ERROR;
    }
  }
  if (params->ca_cert != NULL && strcmp(params->ca_cert, "*") != 0) {
    ctx->ssl_ca_cert = strdup(params->ca_cert);
  }
  
  if (params->server_name != NULL) {
    ctx->ssl_server_name = strdup(params->server_name);
  }
  return MG_SSL_OK;
}

enum mg_ssl_if_result mg_ssl_if_conn_accept(struct mg_connection *nc, struct mg_connection *lc) {
  
  (void) nc;
  (void) lc;
  return MG_SSL_OK;
}

enum mg_ssl_if_result mg_ssl_if_handshake(struct mg_connection *nc) {
  
  return MG_SSL_OK;
}

int mg_ssl_if_read(struct mg_connection *nc, void *buf, size_t len) {
  
  int n = nc->iface->vtable->tcp_recv(nc, buf, len);
  if (n == 0) nc->flags |= MG_F_WANT_READ;
  return n;
}

int mg_ssl_if_write(struct mg_connection *nc, const void *buf, size_t len) {
  
  return nc->iface->vtable->tcp_send(nc, buf, len);
}

void mg_ssl_if_conn_close_notify(struct mg_connection *nc) {
  
  (void) nc;
}

void mg_ssl_if_conn_free(struct mg_connection *nc) {
  struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  if (ctx == NULL) return;
  nc->ssl_if_data = NULL;
  MG_FREE(ctx->ssl_cert);
  MG_FREE(ctx->ssl_key);
  MG_FREE(ctx->ssl_ca_cert);
  MG_FREE(ctx->ssl_server_name);
  memset(ctx, 0, sizeof(*ctx));
  MG_FREE(ctx);
}

bool pem_to_der(const char *pem_file, const char *der_file) {
  bool ret = false;
  FILE *pf = NULL, *df = NULL;
  bool writing = false;
  pf = fopen(pem_file, "r");
  if (pf == NULL) goto clean;
  remove(der_file);
  fs_slfs_set_new_file_size(der_file + MG_SSL_IF_SIMPLELINK_SLFS_PREFIX_LEN, 2048);
  df = fopen(der_file, "w");
  if (df == NULL) goto clean;
  while (1) {
    char pem_buf[70];
    char der_buf[48];
    if (!fgets(pem_buf, sizeof(pem_buf), pf)) break;
    if (writing) {
      if (strstr(pem_buf, "-----END ") != NULL) {
        ret = true;
        break;
      }
      int l = 0;
      while (!isspace((unsigned int) pem_buf[l])) l++;
      int der_len = 0;
      cs_base64_decode((const unsigned char *) pem_buf, sizeof(pem_buf), der_buf, &der_len);
      if (der_len <= 0) break;
      if (fwrite(der_buf, 1, der_len, df) != der_len) break;
    } else if (strstr(pem_buf, "-----BEGIN ") != NULL) {
      writing = true;
    }
  }

clean:
  if (pf != NULL) fclose(pf);
  if (df != NULL) {
    fclose(df);
    if (!ret) remove(der_file);
  }
  return ret;
}



static char *sl_pem2der(const char *pem_file) {
  const char *pem_ext = strstr(pem_file, ".pem");
  if (pem_ext == NULL || *(pem_ext + 4) != '\0') {
    return strdup(pem_file);
  }
  char *der_file = NULL;
  
  int l = mg_asprintf(&der_file, 0, MG_SSL_IF_SIMPLELINK_SLFS_PREFIX "%.*s.der", (int) (pem_ext - pem_file), pem_file);
  if (der_file == NULL) return NULL;
  bool result = false;
  cs_stat_t st;
  if (mg_stat(der_file, &st) != 0) {
    result = pem_to_der(pem_file, der_file);
    LOG(LL_DEBUG, ("%s -> %s = %d", pem_file, der_file, result));
  } else {
    
    result = true;
  }
  if (result) {
    
    memmove(der_file, der_file + MG_SSL_IF_SIMPLELINK_SLFS_PREFIX_LEN, l - 2 );
  } else {
    MG_FREE(der_file);
    der_file = NULL;
  }
  return der_file;
}

static char *sl_pem2der(const char *pem_file) {
  return strdup(pem_file);
}


int sl_set_ssl_opts(int sock, struct mg_connection *nc) {
  int err;
  const struct mg_ssl_if_ctx *ctx = (struct mg_ssl_if_ctx *) nc->ssl_if_data;
  DBG(("%p ssl ctx: %p", nc, ctx));

  if (ctx == NULL) return 0;
  DBG(("%p %s,%s,%s,%s", nc, (ctx->ssl_cert ? ctx->ssl_cert : "-"), (ctx->ssl_key ? ctx->ssl_cert : "-"), (ctx->ssl_ca_cert ? ctx->ssl_ca_cert : "-"), (ctx->ssl_server_name ? ctx->ssl_server_name : "-")));


  if (ctx->ssl_cert != NULL && ctx->ssl_key != NULL) {
    char *ssl_cert = sl_pem2der(ctx->ssl_cert), *ssl_key = NULL;
    if (ssl_cert != NULL) {
      err = sl_SetSockOpt(sock, SL_SOL_SOCKET, SL_SO_SECURE_FILES_CERTIFICATE_FILE_NAME, ssl_cert, strlen(ssl_cert));

      MG_FREE(ssl_cert);
      LOG(LL_DEBUG, ("CERTIFICATE_FILE_NAME %s -> %d", ssl_cert, err));
      ssl_key = sl_pem2der(ctx->ssl_key);
      if (ssl_key != NULL) {
        err = sl_SetSockOpt(sock, SL_SOL_SOCKET, SL_SO_SECURE_FILES_PRIVATE_KEY_FILE_NAME, ssl_key, strlen(ssl_key));

        MG_FREE(ssl_key);
        LOG(LL_DEBUG, ("PRIVATE_KEY_FILE_NAME %s -> %d", ssl_key, err));
      } else {
        err = -1;
      }
    } else {
      err = -1;
    }
    if (err != 0) return err;
  }
  if (ctx->ssl_ca_cert != NULL) {
    if (ctx->ssl_ca_cert[0] != '\0') {
      char *ssl_ca_cert = sl_pem2der(ctx->ssl_ca_cert);
      if (ssl_ca_cert != NULL) {
        err = sl_SetSockOpt(sock, SL_SOL_SOCKET, SL_SO_SECURE_FILES_CA_FILE_NAME, ssl_ca_cert, strlen(ssl_ca_cert));

        LOG(LL_DEBUG, ("CA_FILE_NAME %s -> %d", ssl_ca_cert, err));
      } else {
        err = -1;
      }
      MG_FREE(ssl_ca_cert);
      if (err != 0) return err;
    }
  }
  if (ctx->ssl_server_name != NULL) {
    err = sl_SetSockOpt(sock, SL_SOL_SOCKET, SL_SO_SECURE_DOMAIN_NAME_VERIFICATION, ctx->ssl_server_name, strlen(ctx->ssl_server_name));

    DBG(("DOMAIN_NAME_VERIFICATION %s -> %d", ctx->ssl_server_name, err));
    
    if (err != 0 && err != SL_ERROR_BSD_ENOPROTOOPT) return err;
  }
  return 0;
}


















extern const struct mg_iface_vtable mg_lwip_iface_vtable;

struct mg_lwip_conn_state {
  struct mg_connection *nc;
  struct mg_connection *lc;
  union {
    struct tcp_pcb *tcp;
    struct udp_pcb *udp;
  } pcb;
  err_t err;
  size_t num_sent; 
  struct pbuf *rx_chain; 
  size_t rx_offset; 
  
  int last_ssl_write_size;
  
  int recv_pending;
  
  int draining_rx_chain;
};

enum mg_sig_type {
  MG_SIG_CONNECT_RESULT = 1, MG_SIG_RECV = 2, MG_SIG_CLOSE_CONN = 3, MG_SIG_TOMBSTONE = 4, MG_SIG_ACCEPT = 5, };





void mg_lwip_post_signal(enum mg_sig_type sig, struct mg_connection *nc);


void mg_lwip_mgr_schedule_poll(struct mg_mgr *mgr);





















































typedef void (*tcpip_callback_fn)(void *arg);


void mg_lwip_if_init(struct mg_iface *iface);
void mg_lwip_if_free(struct mg_iface *iface);
void mg_lwip_if_add_conn(struct mg_connection *nc);
void mg_lwip_if_remove_conn(struct mg_connection *nc);
time_t mg_lwip_if_poll(struct mg_iface *iface, int timeout_ms);


extern void mgos_lock();
extern void mgos_unlock();





static void mg_lwip_recv_common(struct mg_connection *nc, struct pbuf *p);


void mg_lwip_set_keepalive_params(struct mg_connection *nc, int idle, int interval, int count) {
  if (nc->sock == INVALID_SOCKET || nc->flags & MG_F_UDP) {
    return;
  }
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  struct tcp_pcb *tpcb = cs->pcb.tcp;
  if (idle > 0 && interval > 0 && count > 0) {
    tpcb->keep_idle = idle * 1000;
    tpcb->keep_intvl = interval * 1000;
    tpcb->keep_cnt = count;
    tpcb->so_options |= SOF_KEEPALIVE;
  } else {
    tpcb->so_options &= ~SOF_KEEPALIVE;
  }
}




static err_t mg_lwip_tcp_conn_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
  struct mg_connection *nc = (struct mg_connection *) arg;
  DBG(("%p connect to %s:%u = %d", nc, IPADDR_NTOA(ipX_2_ip(&tpcb->remote_ip)), tpcb->remote_port, err));
  if (nc == NULL) {
    tcp_abort(tpcb);
    return ERR_ARG;
  }
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  cs->err = err;

  if (err == 0) mg_lwip_set_keepalive_params(nc, 60, 10, 6);

  mg_lwip_post_signal(MG_SIG_CONNECT_RESULT, nc);
  return ERR_OK;
}

static void mg_lwip_tcp_error_cb(void *arg, err_t err) {
  struct mg_connection *nc = (struct mg_connection *) arg;
  DBG(("%p conn error %d", nc, err));
  if (nc == NULL || (nc->flags & MG_F_CLOSE_IMMEDIATELY)) return;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  cs->pcb.tcp = NULL; 
  if (nc->flags & MG_F_CONNECTING) {
    cs->err = err;
    mg_lwip_post_signal(MG_SIG_CONNECT_RESULT, nc);
  } else {
    mg_lwip_post_signal(MG_SIG_CLOSE_CONN, nc);
  }
}

static err_t mg_lwip_tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  struct mg_connection *nc = (struct mg_connection *) arg;
  struct mg_lwip_conn_state *cs = (nc ? (struct mg_lwip_conn_state *) nc->sock : NULL);
  DBG(("%p %p %p %p %u %d", nc, cs, tpcb, p, (p != NULL ? p->tot_len : 0), err));
  if (p == NULL) {
    if (nc != NULL && !(nc->flags & MG_F_CLOSE_IMMEDIATELY)) {
      if (cs->rx_chain != NULL) {
        
        cs->draining_rx_chain = 1;
      } else {
        mg_lwip_post_signal(MG_SIG_CLOSE_CONN, nc);
      }
    } else {
      
    }
    return ERR_OK;
  } else if (nc == NULL) {
    tcp_abort(tpcb);
    return ERR_ARG;
  }
  
  if (p->next != NULL) {
    struct pbuf *q = p->next;
    for (; q != NULL; q = q->next) pbuf_ref(q);
  }
  mgos_lock();
  if (cs->rx_chain == NULL) {
    cs->rx_offset = 0;
  } else if (pbuf_clen(cs->rx_chain) >= 4) {
    
    struct pbuf *np = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
    if (np != NULL) {
      pbuf_copy(np, p);
      pbuf_free(p);
      p = np;
    }
  }
  mg_lwip_recv_common(nc, p);
  mgos_unlock();
  return ERR_OK;
}

static err_t mg_lwip_tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t num_sent) {
  struct mg_connection *nc = (struct mg_connection *) arg;
  DBG(("%p %p %u %p %p", nc, tpcb, num_sent, tpcb->unsent, tpcb->unacked));
  if (nc == NULL) return ERR_OK;
  if ((nc->flags & MG_F_SEND_AND_CLOSE) && !(nc->flags & MG_F_WANT_WRITE) && nc->send_mbuf.len == 0 && tpcb->unsent == NULL && tpcb->unacked == NULL) {
    mg_lwip_post_signal(MG_SIG_CLOSE_CONN, nc);
  }
  return ERR_OK;
}

struct mg_lwip_if_connect_tcp_ctx {
  struct mg_connection *nc;
  const union socket_address *sa;
};

static void mg_lwip_if_connect_tcp_tcpip(void *arg) {
  struct mg_lwip_if_connect_tcp_ctx *ctx = (struct mg_lwip_if_connect_tcp_ctx *) arg;
  struct mg_connection *nc = ctx->nc;
  const union socket_address *sa = ctx->sa;

  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  struct tcp_pcb *tpcb = TCP_NEW();
  cs->pcb.tcp = tpcb;
  ip_addr_t *ip = (ip_addr_t *) &sa->sin.sin_addr.s_addr;
  u16_t port = ntohs(sa->sin.sin_port);
  tcp_arg(tpcb, nc);
  tcp_err(tpcb, mg_lwip_tcp_error_cb);
  tcp_sent(tpcb, mg_lwip_tcp_sent_cb);
  tcp_recv(tpcb, mg_lwip_tcp_recv_cb);
  cs->err = TCP_BIND(tpcb, IP_ADDR_ANY, 0 );
  DBG(("%p tcp_bind = %d", nc, cs->err));
  if (cs->err != ERR_OK) {
    mg_lwip_post_signal(MG_SIG_CONNECT_RESULT, nc);
    return;
  }
  cs->err = tcp_connect(tpcb, ip, port, mg_lwip_tcp_conn_cb);
  DBG(("%p tcp_connect %p = %d", nc, tpcb, cs->err));
  if (cs->err != ERR_OK) {
    mg_lwip_post_signal(MG_SIG_CONNECT_RESULT, nc);
    return;
  }
}

void mg_lwip_if_connect_tcp(struct mg_connection *nc, const union socket_address *sa) {
  struct mg_lwip_if_connect_tcp_ctx ctx = {.nc = nc, .sa = sa};
  tcpip_callback(mg_lwip_if_connect_tcp_tcpip, &ctx);
}



static void mg_lwip_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)

static void mg_lwip_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *addr, u16_t port)

{
  struct mg_connection *nc = (struct mg_connection *) arg;
  DBG(("%p %s:%u %p %u %u", nc, IPADDR_NTOA(addr), port, p, p->ref, p->len));
  
  struct pbuf *sap = pbuf_alloc(PBUF_RAW, sizeof(union socket_address), PBUF_RAM);
  if (sap == NULL) {
    pbuf_free(p);
    return;
  }
  union socket_address *sa = (union socket_address *) sap->payload;

  sa->sin.sin_addr.s_addr = ip_2_ip4(addr)->addr;

  sa->sin.sin_addr.s_addr = addr->addr;

  sa->sin.sin_port = htons(port);
  
  p = pbuf_coalesce(p, PBUF_RAW);
  pbuf_chain(sap, p);
  mgos_lock();
  mg_lwip_recv_common(nc, sap);
  mgos_unlock();
  (void) pcb;
}

static void mg_lwip_recv_common(struct mg_connection *nc, struct pbuf *p) {
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (cs->rx_chain == NULL) {
    cs->rx_chain = p;
  } else {
    pbuf_chain(cs->rx_chain, p);
  }
  if (!cs->recv_pending) {
    cs->recv_pending = 1;
    mg_lwip_post_signal(MG_SIG_RECV, nc);
  }
}

static int mg_lwip_if_udp_recv(struct mg_connection *nc, void *buf, size_t len, union socket_address *sa, size_t *sa_len) {
  
  int res = 0;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (nc->sock == INVALID_SOCKET) return -1;
  mgos_lock();
  if (cs->rx_chain != NULL) {
    struct pbuf *ap = cs->rx_chain;
    struct pbuf *dp = ap->next;
    cs->rx_chain = pbuf_dechain(dp);
    res = MIN(dp->len, len);
    pbuf_copy_partial(dp, buf, res, 0);
    pbuf_free(dp);
    pbuf_copy_partial(ap, sa, MIN(*sa_len, ap->len), 0);
    pbuf_free(ap);
  }
  mgos_unlock();
  return res;
}

static void mg_lwip_if_connect_udp_tcpip(void *arg) {
  struct mg_connection *nc = (struct mg_connection *) arg;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  struct udp_pcb *upcb = udp_new();
  cs->err = UDP_BIND(upcb, IP_ADDR_ANY, 0 );
  DBG(("%p udp_bind %p = %d", nc, upcb, cs->err));
  if (cs->err == ERR_OK) {
    udp_recv(upcb, mg_lwip_udp_recv_cb, nc);
    cs->pcb.udp = upcb;
  } else {
    udp_remove(upcb);
  }
  mg_lwip_post_signal(MG_SIG_CONNECT_RESULT, nc);
}

void mg_lwip_if_connect_udp(struct mg_connection *nc) {
  tcpip_callback(mg_lwip_if_connect_udp_tcpip, nc);
}

static void tcp_close_tcpip(void *arg) {
  tcp_close((struct tcp_pcb *) arg);
}

void mg_lwip_handle_accept(struct mg_connection *nc) {
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (cs->pcb.tcp == NULL) return;
  union socket_address sa;
  struct tcp_pcb *tpcb = cs->pcb.tcp;
  SET_ADDR(&sa, &tpcb->remote_ip);
  sa.sin.sin_port = htons(tpcb->remote_port);
  mg_if_accept_tcp_cb(nc, &sa, sizeof(sa.sin));
}

static err_t mg_lwip_accept_cb(void *arg, struct tcp_pcb *newtpcb, err_t err) {
  struct mg_connection *lc = (struct mg_connection *) arg, *nc;
  struct mg_lwip_conn_state *lcs, *cs;
  struct tcp_pcb_listen *lpcb;
  LOG(LL_DEBUG, ("%p conn %p from %s:%u", lc, newtpcb, IPADDR_NTOA(ipX_2_ip(&newtpcb->remote_ip)), newtpcb->remote_port));

  if (lc == NULL) {
    tcp_abort(newtpcb);
    return ERR_ABRT;
  }
  lcs = (struct mg_lwip_conn_state *) lc->sock;
  lpcb = (struct tcp_pcb_listen *) lcs->pcb.tcp;

  tcp_accepted(lpcb);

  nc = mg_if_accept_new_conn(lc);
  if (nc == NULL) {
    tcp_abort(newtpcb);
    return ERR_ABRT;
  }
  cs = (struct mg_lwip_conn_state *) nc->sock;
  cs->lc = lc;
  cs->pcb.tcp = newtpcb;
  
  tcp_arg(newtpcb, nc);
  tcp_err(newtpcb, mg_lwip_tcp_error_cb);
  tcp_sent(newtpcb, mg_lwip_tcp_sent_cb);
  tcp_recv(newtpcb, mg_lwip_tcp_recv_cb);

  mg_lwip_set_keepalive_params(nc, 60, 10, 6);

  mg_lwip_post_signal(MG_SIG_ACCEPT, nc);
  (void) err;
  (void) lpcb;
  return ERR_OK;
}

struct mg_lwip_if_listen_ctx {
  struct mg_connection *nc;
  union socket_address *sa;
  int ret;
};

static void mg_lwip_if_listen_tcp_tcpip(void *arg) {
  struct mg_lwip_if_listen_ctx *ctx = (struct mg_lwip_if_listen_ctx *) arg;
  struct mg_connection *nc = ctx->nc;
  union socket_address *sa = ctx->sa;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  struct tcp_pcb *tpcb = TCP_NEW();
  ip_addr_t *ip = (ip_addr_t *) &sa->sin.sin_addr.s_addr;
  u16_t port = ntohs(sa->sin.sin_port);
  cs->err = TCP_BIND(tpcb, ip, port);
  DBG(("%p tcp_bind(%s:%u) = %d", nc, IPADDR_NTOA(ip), port, cs->err));
  if (cs->err != ERR_OK) {
    tcp_close(tpcb);
    ctx->ret = -1;
    return;
  }
  tcp_arg(tpcb, nc);
  tpcb = tcp_listen(tpcb);
  cs->pcb.tcp = tpcb;
  tcp_accept(tpcb, mg_lwip_accept_cb);
  ctx->ret = 0;
}

int mg_lwip_if_listen_tcp(struct mg_connection *nc, union socket_address *sa) {
  struct mg_lwip_if_listen_ctx ctx = {.nc = nc, .sa = sa};
  tcpip_callback(mg_lwip_if_listen_tcp_tcpip, &ctx);
  return ctx.ret;
}

static void mg_lwip_if_listen_udp_tcpip(void *arg) {
  struct mg_lwip_if_listen_ctx *ctx = (struct mg_lwip_if_listen_ctx *) arg;
  struct mg_connection *nc = ctx->nc;
  union socket_address *sa = ctx->sa;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  struct udp_pcb *upcb = udp_new();
  ip_addr_t *ip = (ip_addr_t *) &sa->sin.sin_addr.s_addr;
  u16_t port = ntohs(sa->sin.sin_port);
  cs->err = UDP_BIND(upcb, ip, port);
  DBG(("%p udb_bind(%s:%u) = %d", nc, IPADDR_NTOA(ip), port, cs->err));
  if (cs->err != ERR_OK) {
    udp_remove(upcb);
    ctx->ret = -1;
  } else {
    udp_recv(upcb, mg_lwip_udp_recv_cb, nc);
    cs->pcb.udp = upcb;
    ctx->ret = 0;
  }
}

int mg_lwip_if_listen_udp(struct mg_connection *nc, union socket_address *sa) {
  struct mg_lwip_if_listen_ctx ctx = {.nc = nc, .sa = sa};
  tcpip_callback(mg_lwip_if_listen_udp_tcpip, &ctx);
  return ctx.ret;
}

struct mg_lwip_tcp_write_ctx {
  struct mg_connection *nc;
  const void *data;
  uint16_t len;
  int ret;
};

static void tcp_output_tcpip(void *arg) {
  tcp_output((struct tcp_pcb *) arg);
}

static void mg_lwip_tcp_write_tcpip(void *arg) {
  struct mg_lwip_tcp_write_ctx *ctx = (struct mg_lwip_tcp_write_ctx *) arg;
  struct mg_connection *nc = ctx->nc;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  struct tcp_pcb *tpcb = cs->pcb.tcp;
  size_t len = MIN(tpcb->mss, MIN(ctx->len, tpcb->snd_buf));
  size_t unsent, unacked;
  if (len == 0) {
    DBG(("%p no buf avail %u %u %p %p", tpcb, tpcb->snd_buf, tpcb->snd_queuelen, tpcb->unsent, tpcb->unacked));
    tcpip_callback(tcp_output_tcpip, tpcb);
    ctx->ret = 0;
    return;
  }
  unsent = (tpcb->unsent != NULL ? tpcb->unsent->len : 0);
  unacked = (tpcb->unacked != NULL ? tpcb->unacked->len : 0);


  if (unacked > 0) {
    ctx->ret = 0;
    return;
  }
  len = MIN(len, (TCP_MSS - unsent));

  cs->err = tcp_write(tpcb, ctx->data, len, TCP_WRITE_FLAG_COPY);
  unsent = (tpcb->unsent != NULL ? tpcb->unsent->len : 0);
  unacked = (tpcb->unacked != NULL ? tpcb->unacked->len : 0);
  DBG(("%p tcp_write %u = %d, %u %u", tpcb, len, cs->err, unsent, unacked));
  if (cs->err != ERR_OK) {
    
    ctx->ret = (cs->err == ERR_MEM ? 0 : -1);
    return;
  }
  ctx->ret = len;
  (void) unsent;
  (void) unacked;
}

int mg_lwip_if_tcp_send(struct mg_connection *nc, const void *buf, size_t len) {
  struct mg_lwip_tcp_write_ctx ctx = {.nc = nc, .data = buf, .len = len};
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (nc->sock == INVALID_SOCKET) return -1;
  struct tcp_pcb *tpcb = cs->pcb.tcp;
  if (tpcb == NULL) return -1;
  if (tpcb->snd_buf <= 0) return 0;
  tcpip_callback(mg_lwip_tcp_write_tcpip, &ctx);
  return ctx.ret;
}

struct udp_sendto_ctx {
  struct udp_pcb *upcb;
  struct pbuf *p;
  ip_addr_t *ip;
  uint16_t port;
  int ret;
};

static void udp_sendto_tcpip(void *arg) {
  struct udp_sendto_ctx *ctx = (struct udp_sendto_ctx *) arg;
  ctx->ret = udp_sendto(ctx->upcb, ctx->p, ctx->ip, ctx->port);
}

static int mg_lwip_if_udp_send(struct mg_connection *nc, const void *data, size_t len) {
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (nc->sock == INVALID_SOCKET || cs->pcb.udp == NULL) return -1;
  struct udp_pcb *upcb = cs->pcb.udp;
  struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);

  ip_addr_t ip = {.u_addr.ip4.addr = nc->sa.sin.sin_addr.s_addr, .type = 0};

  ip_addr_t ip = {.addr = nc->sa.sin.sin_addr.s_addr};

  u16_t port = ntohs(nc->sa.sin.sin_port);
  if (p == NULL) return 0;
  memcpy(p->payload, data, len);
  struct udp_sendto_ctx ctx = {.upcb = upcb, .p = p, .ip = &ip, .port = port};
  tcpip_callback(udp_sendto_tcpip, &ctx);
  cs->err = ctx.ret;
  pbuf_free(p);
  return (cs->err == ERR_OK ? (int) len : -2);
}

static int mg_lwip_if_can_send(struct mg_connection *nc, struct mg_lwip_conn_state *cs) {
  int can_send = 0;
  if (nc->send_mbuf.len > 0 || (nc->flags & MG_F_WANT_WRITE)) {
    
    if (nc->flags & MG_F_UDP) {
      
      can_send = (cs->pcb.udp != NULL);
    } else {
      can_send = (cs->pcb.tcp != NULL && cs->pcb.tcp->snd_buf > 0);
    }
  }
  return can_send;
}

struct tcp_recved_ctx {
  struct tcp_pcb *tpcb;
  size_t len;
};

void tcp_recved_tcpip(void *arg) {
  struct tcp_recved_ctx *ctx = (struct tcp_recved_ctx *) arg;
  tcp_recved(ctx->tpcb, ctx->len);
}

static int mg_lwip_if_tcp_recv(struct mg_connection *nc, void *buf, size_t len) {
  int res = 0;
  char *bufp = buf;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (nc->sock == INVALID_SOCKET) return -1;
  mgos_lock();
  while (cs->rx_chain != NULL && len > 0) {
    struct pbuf *seg = cs->rx_chain;
    size_t seg_len = (seg->len - cs->rx_offset);
    size_t copy_len = MIN(len, seg_len);

    pbuf_copy_partial(seg, bufp, copy_len, cs->rx_offset);
    len -= copy_len;
    res += copy_len;
    bufp += copy_len;
    cs->rx_offset += copy_len;
    if (cs->rx_offset == cs->rx_chain->len) {
      cs->rx_chain = pbuf_dechain(cs->rx_chain);
      pbuf_free(seg);
      cs->rx_offset = 0;
    }
  }
  mgos_unlock();
  if (res > 0) {
    struct tcp_recved_ctx ctx = {.tpcb = cs->pcb.tcp, .len = res};
    tcpip_callback(tcp_recved_tcpip, &ctx);
  }
  return res;
}

int mg_lwip_if_create_conn(struct mg_connection *nc) {
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) MG_CALLOC(1, sizeof(*cs));
  if (cs == NULL) return 0;
  cs->nc = nc;
  nc->sock = (intptr_t) cs;
  return 1;
}

static void udp_remove_tcpip(void *arg) {
  udp_remove((struct udp_pcb *) arg);
}

void mg_lwip_if_destroy_conn(struct mg_connection *nc) {
  if (nc->sock == INVALID_SOCKET) return;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (!(nc->flags & MG_F_UDP)) {
    struct tcp_pcb *tpcb = cs->pcb.tcp;
    if (tpcb != NULL) {
      tcp_arg(tpcb, NULL);
      DBG(("%p tcp_close %p", nc, tpcb));
      tcp_arg(tpcb, NULL);
      tcpip_callback(tcp_close_tcpip, tpcb);
    }
    while (cs->rx_chain != NULL) {
      struct pbuf *seg = cs->rx_chain;
      cs->rx_chain = pbuf_dechain(cs->rx_chain);
      pbuf_free(seg);
    }
    memset(cs, 0, sizeof(*cs));
    MG_FREE(cs);
  } else if (nc->listener == NULL) {
    
    struct udp_pcb *upcb = cs->pcb.udp;
    if (upcb != NULL) {
      DBG(("%p udp_remove %p", nc, upcb));
      tcpip_callback(udp_remove_tcpip, upcb);
    }
    memset(cs, 0, sizeof(*cs));
    MG_FREE(cs);
  }
  nc->sock = INVALID_SOCKET;
}

void mg_lwip_if_get_conn_addr(struct mg_connection *nc, int remote, union socket_address *sa) {
  memset(sa, 0, sizeof(*sa));
  if (nc == NULL || nc->sock == INVALID_SOCKET) return;
  struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
  if (nc->flags & MG_F_UDP) {
    struct udp_pcb *upcb = cs->pcb.udp;
    if (remote) {
      memcpy(sa, &nc->sa, sizeof(*sa));
    } else if (upcb != NULL) {
      sa->sin.sin_port = htons(upcb->local_port);
      SET_ADDR(sa, &upcb->local_ip);
    }
  } else {
    struct tcp_pcb *tpcb = cs->pcb.tcp;
    if (remote) {
      memcpy(sa, &nc->sa, sizeof(*sa));
    } else if (tpcb != NULL) {
      sa->sin.sin_port = htons(tpcb->local_port);
      SET_ADDR(sa, &tpcb->local_ip);
    }
  }
}

void mg_lwip_if_sock_set(struct mg_connection *nc, sock_t sock) {
  nc->sock = sock;
}























const struct mg_iface_vtable mg_lwip_iface_vtable = MG_LWIP_IFACE_VTABLE;

const struct mg_iface_vtable mg_default_iface_vtable = MG_LWIP_IFACE_VTABLE;














struct mg_ev_mgr_lwip_signal {
  int sig;
  struct mg_connection *nc;
};

struct mg_ev_mgr_lwip_data {
  struct mg_ev_mgr_lwip_signal sig_queue[MG_SIG_QUEUE_LEN];
  int sig_queue_len;
  int start_index;
};

void mg_lwip_post_signal(enum mg_sig_type sig, struct mg_connection *nc) {
  struct mg_ev_mgr_lwip_data *md = (struct mg_ev_mgr_lwip_data *) nc->iface->data;
  mgos_lock();
  if (md->sig_queue_len >= MG_SIG_QUEUE_LEN) {
    mgos_unlock();
    return;
  }
  int end_index = (md->start_index + md->sig_queue_len) % MG_SIG_QUEUE_LEN;
  md->sig_queue[end_index].sig = sig;
  md->sig_queue[end_index].nc = nc;
  md->sig_queue_len++;
  mg_lwip_mgr_schedule_poll(nc->mgr);
  mgos_unlock();
}

void mg_ev_mgr_lwip_process_signals(struct mg_mgr *mgr) {
  struct mg_ev_mgr_lwip_data *md = (struct mg_ev_mgr_lwip_data *) mgr->ifaces[MG_MAIN_IFACE]->data;
  while (md->sig_queue_len > 0) {
    mgos_lock();
    int i = md->start_index;
    int sig = md->sig_queue[i].sig;
    struct mg_connection *nc = md->sig_queue[i].nc;
    struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
    md->start_index = (i + 1) % MG_SIG_QUEUE_LEN;
    md->sig_queue_len--;
    mgos_unlock();
    if (nc->iface == NULL || nc->mgr == NULL) continue;
    switch (sig) {
      case MG_SIG_CONNECT_RESULT: {
        mg_if_connect_cb(nc, cs->err);
        break;
      }
      case MG_SIG_CLOSE_CONN: {
        nc->flags |= MG_F_SEND_AND_CLOSE;
        mg_close_conn(nc);
        break;
      }
      case MG_SIG_RECV: {
        cs->recv_pending = 0;
        mg_if_can_recv_cb(nc);
        mbuf_trim(&nc->recv_mbuf);
        break;
      }
      case MG_SIG_TOMBSTONE: {
        break;
      }
      case MG_SIG_ACCEPT: {
        mg_lwip_handle_accept(nc);
        break;
      }
    }
  }
}

void mg_lwip_if_init(struct mg_iface *iface) {
  LOG(LL_INFO, ("Mongoose %s, LwIP %u.%u.%u", MG_VERSION, LWIP_VERSION_MAJOR, LWIP_VERSION_MINOR, LWIP_VERSION_REVISION));
  iface->data = MG_CALLOC(1, sizeof(struct mg_ev_mgr_lwip_data));
}

void mg_lwip_if_free(struct mg_iface *iface) {
  MG_FREE(iface->data);
  iface->data = NULL;
}

void mg_lwip_if_add_conn(struct mg_connection *nc) {
  (void) nc;
}

void mg_lwip_if_remove_conn(struct mg_connection *nc) {
  struct mg_ev_mgr_lwip_data *md = (struct mg_ev_mgr_lwip_data *) nc->iface->data;
  
  for (int i = 0; i < MG_SIG_QUEUE_LEN; i++) {
    if (md->sig_queue[i].nc == nc) {
      md->sig_queue[i].sig = MG_SIG_TOMBSTONE;
    }
  }
}

time_t mg_lwip_if_poll(struct mg_iface *iface, int timeout_ms) {
  struct mg_mgr *mgr = iface->mgr;
  int n = 0;
  double now = mg_time();
  struct mg_connection *nc, *tmp;
  double min_timer = 0;
  int num_timers = 0;

  DBG(("begin poll @%u", (unsigned int) (now * 1000)));

  mg_ev_mgr_lwip_process_signals(mgr);
  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
    tmp = nc->next;
    n++;
    if (!mg_if_poll(nc, now)) continue;
    if (nc->sock != INVALID_SOCKET && !(nc->flags & (MG_F_UDP | MG_F_LISTENING)) && cs->pcb.tcp != NULL && cs->pcb.tcp->unsent != NULL) {

      tcpip_callback(tcp_output_tcpip, cs->pcb.tcp);
    }
    if (nc->ev_timer_time > 0) {
      if (num_timers == 0 || nc->ev_timer_time < min_timer) {
        min_timer = nc->ev_timer_time;
      }
      num_timers++;
    }

    if (nc->sock != INVALID_SOCKET) {
      if (mg_lwip_if_can_send(nc, cs)) {
        mg_if_can_send_cb(nc);
        mbuf_trim(&nc->send_mbuf);
      }
      if (cs->rx_chain != NULL) {
        mg_if_can_recv_cb(nc);
      } else if (cs->draining_rx_chain) {
        
        mg_lwip_post_signal(MG_SIG_CLOSE_CONN, nc);
      }
    }
  }

  DBG(("end poll @%u, %d conns, %d timers (min %u), next in %d ms", (unsigned int) (now * 1000), n, num_timers, (unsigned int) (min_timer * 1000), timeout_ms));


  (void) timeout_ms;
  return now;
}

uint32_t mg_lwip_get_poll_delay_ms(struct mg_mgr *mgr) {
  struct mg_connection *nc;
  double now;
  double min_timer = 0;
  int num_timers = 0;
  mg_ev_mgr_lwip_process_signals(mgr);
  for (nc = mg_next(mgr, NULL); nc != NULL; nc = mg_next(mgr, nc)) {
    struct mg_lwip_conn_state *cs = (struct mg_lwip_conn_state *) nc->sock;
    if (nc->ev_timer_time > 0) {
      if (num_timers == 0 || nc->ev_timer_time < min_timer) {
        min_timer = nc->ev_timer_time;
      }
      num_timers++;
    }
    
    if (nc->sock != INVALID_SOCKET && mg_lwip_if_can_send(nc, cs)) {
      return 0;
    }
  }
  uint32_t timeout_ms = ~0;
  now = mg_time();
  if (num_timers > 0) {
    
    if (min_timer < now) return 0;
    double timer_timeout_ms = (min_timer - now) * 1000 + 1 ;
    if (timer_timeout_ms < timeout_ms) {
      timeout_ms = timer_timeout_ms;
    }
  }
  return timeout_ms;
}









const char *strerror(int err) {
  
  static char buf[10];
  snprintf(buf, sizeof(buf), "%d", err);
  return buf;
}

int open(const char *filename, int oflag, int pmode) {
  
  DebugBreak();
  return 0; 
}

int _wstati64(const wchar_t *path, cs_stat_t *st) {
  DWORD fa = GetFileAttributesW(path);
  if (fa == INVALID_FILE_ATTRIBUTES) {
    return -1;
  }
  memset(st, 0, sizeof(*st));
  if ((fa & FILE_ATTRIBUTE_DIRECTORY) == 0) {
    HANDLE h;
    FILETIME ftime;
    st->st_mode |= _S_IFREG;
    h = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
      return -1;
    }
    st->st_size = GetFileSize(h, NULL);
    GetFileTime(h, NULL, NULL, &ftime);
    st->st_mtime = (uint32_t)((((uint64_t) ftime.dwLowDateTime + ((uint64_t) ftime.dwHighDateTime << 32)) / 10000000.0) - 11644473600);


    CloseHandle(h);
  } else {
    st->st_mode |= _S_IFDIR;
  }
  return 0;
}


static void mg_gmt_time_string(char *buf, size_t buf_len, time_t *t) {
  FILETIME ft;
  SYSTEMTIME systime;
  if (t != NULL) {
    uint64_t filetime = (*t + 11644473600) * 10000000;
    ft.dwLowDateTime = filetime & 0xFFFFFFFF;
    ft.dwHighDateTime = (filetime & 0xFFFFFFFF00000000) >> 32;
    FileTimeToSystemTime(&ft, &systime);
  } else {
    GetSystemTime(&systime);
  }
  
  snprintf(buf, buf_len, "%d.%d.%d %d:%d:%d GMT", (int) systime.wYear, (int) systime.wMonth, (int) systime.wDay, (int) systime.wHour, (int) systime.wMinute, (int) systime.wSecond);

}













extern "C" {






extern const struct mg_iface_vtable mg_pic32_iface_vtable;


}










int mg_pic32_if_create_conn(struct mg_connection *nc) {
  (void) nc;
  return 1;
}

void mg_pic32_if_recved(struct mg_connection *nc, size_t len) {
  (void) nc;
  (void) len;
}

void mg_pic32_if_add_conn(struct mg_connection *nc) {
  (void) nc;
}

void mg_pic32_if_init(struct mg_iface *iface) {
  (void) iface;
  (void) mg_get_errno(); 
}

void mg_pic32_if_free(struct mg_iface *iface) {
  (void) iface;
}

void mg_pic32_if_remove_conn(struct mg_connection *nc) {
  (void) nc;
}

void mg_pic32_if_destroy_conn(struct mg_connection *nc) {
  if (nc->sock == INVALID_SOCKET) return;
  
  if (!(nc->flags & MG_F_UDP)) {
    
    TCPIP_TCP_Close((TCP_SOCKET) nc->sock);
  } else if (nc->listener == NULL) {
    
    TCPIP_UDP_Close((UDP_SOCKET) nc->sock);
  }

  nc->sock = INVALID_SOCKET;
}

int mg_pic32_if_listen_udp(struct mg_connection *nc, union socket_address *sa) {
  nc->sock = TCPIP_UDP_ServerOpen( sa->sin.sin_family == AF_INET ? IP_ADDRESS_TYPE_IPV4 : IP_ADDRESS_TYPE_IPV6, ntohs(sa->sin.sin_port), sa->sin.sin_addr.s_addr == 0 ? 0 : (IP_MULTI_ADDRESS *) &sa->sin);



  if (nc->sock == INVALID_SOCKET) {
    return -1;
  }
  return 0;
}

void mg_pic32_if_udp_send(struct mg_connection *nc, const void *buf, size_t len) {
  mbuf_append(&nc->send_mbuf, buf, len);
}

void mg_pic32_if_tcp_send(struct mg_connection *nc, const void *buf, size_t len) {
  mbuf_append(&nc->send_mbuf, buf, len);
}

int mg_pic32_if_listen_tcp(struct mg_connection *nc, union socket_address *sa) {
  nc->sock = TCPIP_TCP_ServerOpen( sa->sin.sin_family == AF_INET ? IP_ADDRESS_TYPE_IPV4 : IP_ADDRESS_TYPE_IPV6, ntohs(sa->sin.sin_port), sa->sin.sin_addr.s_addr == 0 ? 0 : (IP_MULTI_ADDRESS *) &sa->sin);



  memcpy(&nc->sa, sa, sizeof(*sa));
  if (nc->sock == INVALID_SOCKET) {
    return -1;
  }
  return 0;
}

static int mg_accept_conn(struct mg_connection *lc) {
  struct mg_connection *nc;
  TCP_SOCKET_INFO si;
  union socket_address sa;

  nc = mg_if_accept_new_conn(lc);

  if (nc == NULL) {
    return 0;
  }

  nc->sock = lc->sock;
  nc->flags &= ~MG_F_LISTENING;

  if (!TCPIP_TCP_SocketInfoGet((TCP_SOCKET) nc->sock, &si)) {
    return 0;
  }

  if (si.addressType == IP_ADDRESS_TYPE_IPV4) {
    sa.sin.sin_family = AF_INET;
    sa.sin.sin_port = htons(si.remotePort);
    sa.sin.sin_addr.s_addr = si.remoteIPaddress.v4Add.Val;
  } else {
    
    memset(&sa, 0, sizeof(sa));
  }

  mg_if_accept_tcp_cb(nc, (union socket_address *) &sa, sizeof(sa));

  return mg_pic32_if_listen_tcp(lc, &lc->sa) >= 0;
}

char *inet_ntoa(struct in_addr in) {
  static char addr[17];
  snprintf(addr, sizeof(addr), "%d.%d.%d.%d", (int) in.S_un.S_un_b.s_b1, (int) in.S_un.S_un_b.s_b2, (int) in.S_un.S_un_b.s_b3, (int) in.S_un.S_un_b.s_b4);

  return addr;
}

static void mg_handle_send(struct mg_connection *nc) {
  uint16_t bytes_written = 0;
  if (nc->flags & MG_F_UDP) {
    if (!TCPIP_UDP_RemoteBind( (UDP_SOCKET) nc->sock, nc->sa.sin.sin_family == AF_INET ? IP_ADDRESS_TYPE_IPV4 : IP_ADDRESS_TYPE_IPV6, ntohs(nc->sa.sin.sin_port), (IP_MULTI_ADDRESS *) &nc->sa.sin)) {



      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      return;
    }
    bytes_written = TCPIP_UDP_TxPutIsReady((UDP_SOCKET) nc->sock, 0);
    if (bytes_written >= nc->send_mbuf.len) {
      if (TCPIP_UDP_ArrayPut((UDP_SOCKET) nc->sock, (uint8_t *) nc->send_mbuf.buf, nc->send_mbuf.len) != nc->send_mbuf.len) {

        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        bytes_written = 0;
      }
    }
  } else {
    bytes_written = TCPIP_TCP_FifoTxFreeGet((TCP_SOCKET) nc->sock);
    if (bytes_written != 0) {
      if (bytes_written > nc->send_mbuf.len) {
        bytes_written = nc->send_mbuf.len;
      }
      if (TCPIP_TCP_ArrayPut((TCP_SOCKET) nc->sock, (uint8_t *) nc->send_mbuf.buf, bytes_written) != bytes_written) {

        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        bytes_written = 0;
      }
    }
  }

  mg_if_sent_cb(nc, bytes_written);
}

static void mg_handle_recv(struct mg_connection *nc) {
  uint16_t bytes_read = 0;
  uint8_t *buf = NULL;
  if (nc->flags & MG_F_UDP) {
    bytes_read = TCPIP_UDP_GetIsReady((UDP_SOCKET) nc->sock);
    if (bytes_read != 0 && (nc->recv_mbuf_limit == -1 || nc->recv_mbuf.len + bytes_read < nc->recv_mbuf_limit)) {

      buf = (uint8_t *) MG_MALLOC(bytes_read);
      if (TCPIP_UDP_ArrayGet((UDP_SOCKET) nc->sock, buf, bytes_read) != bytes_read) {
        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        bytes_read = 0;
        MG_FREE(buf);
      }
    }
  } else {
    bytes_read = TCPIP_TCP_GetIsReady((TCP_SOCKET) nc->sock);
    if (bytes_read != 0) {
      if (nc->recv_mbuf_limit != -1 && nc->recv_mbuf_limit - nc->recv_mbuf.len > bytes_read) {
        bytes_read = nc->recv_mbuf_limit - nc->recv_mbuf.len;
      }
      buf = (uint8_t *) MG_MALLOC(bytes_read);
      if (TCPIP_TCP_ArrayGet((TCP_SOCKET) nc->sock, buf, bytes_read) != bytes_read) {
        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        MG_FREE(buf);
        bytes_read = 0;
      }
    }
  }

  if (bytes_read != 0) {
    mg_if_recv_tcp_cb(nc, buf, bytes_read, 1 );
  }
}

time_t mg_pic32_if_poll(struct mg_iface *iface, int timeout_ms) {
  struct mg_mgr *mgr = iface->mgr;
  double now = mg_time();
  struct mg_connection *nc, *tmp;

  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    tmp = nc->next;

    if (nc->flags & MG_F_CONNECTING) {
      
      if (nc->flags & MG_F_UDP || TCPIP_TCP_IsConnected((TCP_SOCKET) nc->sock)) {
        mg_if_connect_cb(nc, 0);
      }
    } else if (nc->flags & MG_F_LISTENING) {
      if (TCPIP_TCP_IsConnected((TCP_SOCKET) nc->sock)) {
        
        mg_accept_conn(nc);
      }
    } else {
      if (nc->send_mbuf.len != 0) {
        mg_handle_send(nc);
      }

      if (nc->recv_mbuf_limit == -1 || nc->recv_mbuf.len < nc->recv_mbuf_limit) {
        mg_handle_recv(nc);
      }
    }
  }

  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    tmp = nc->next;
    if ((nc->flags & MG_F_CLOSE_IMMEDIATELY) || (nc->send_mbuf.len == 0 && (nc->flags & MG_F_SEND_AND_CLOSE))) {
      mg_close_conn(nc);
    }
  }

  return now;
}

void mg_pic32_if_sock_set(struct mg_connection *nc, sock_t sock) {
  nc->sock = sock;
}

void mg_pic32_if_get_conn_addr(struct mg_connection *nc, int remote, union socket_address *sa) {
  
}

void mg_pic32_if_connect_tcp(struct mg_connection *nc, const union socket_address *sa) {
  nc->sock = TCPIP_TCP_ClientOpen( sa->sin.sin_family == AF_INET ? IP_ADDRESS_TYPE_IPV4 : IP_ADDRESS_TYPE_IPV6, ntohs(sa->sin.sin_port), (IP_MULTI_ADDRESS *) &sa->sin);


  nc->err = (nc->sock == INVALID_SOCKET) ? -1 : 0;
}

void mg_pic32_if_connect_udp(struct mg_connection *nc) {
  nc->sock = TCPIP_UDP_ClientOpen(IP_ADDRESS_TYPE_ANY, 0, NULL);
  nc->err = (nc->sock == INVALID_SOCKET) ? -1 : 0;
}






















const struct mg_iface_vtable mg_pic32_iface_vtable = MG_PIC32_IFACE_VTABLE;

const struct mg_iface_vtable mg_default_iface_vtable = MG_PIC32_IFACE_VTABLE;










int rmdir(const char *dirname) {
  return _rmdir(dirname);
}

unsigned int sleep(unsigned int seconds) {
  Sleep(seconds * 1000);
  return 0;
}


