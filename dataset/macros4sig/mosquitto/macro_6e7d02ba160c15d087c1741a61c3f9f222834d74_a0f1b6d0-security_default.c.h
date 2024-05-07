
#define MQTT3_LOG_ALL 0xFF
#define MQTT3_LOG_FILE 0x02
#define MQTT3_LOG_NONE 0x00
#define MQTT3_LOG_STDERR 0x08
#define MQTT3_LOG_STDOUT 0x04
#define MQTT3_LOG_SYSLOG 0x01
#define MQTT3_LOG_TOPIC 0x10
#define WEBSOCKET_CLIENT -2

#    define libwebsocket lws
#    define libwebsocket_callback_on_writable(A, B) lws_callback_on_writable((B))
#    define libwebsocket_callback_reasons lws_callback_reasons
#    define libwebsocket_context lws_context
#    define libwebsocket_context_destroy(A) lws_context_destroy((A))
#    define libwebsocket_create_context(A) lws_create_context((A))
#    define libwebsocket_get_socket_fd(A) lws_get_socket_fd((A))
#    define libwebsocket_protocols lws_protocols
#    define libwebsocket_service(A, B) lws_service((A), (B))
#    define libwebsocket_write(A, B, C, D) lws_write((A), (B), (C), (D))
#    define libwebsockets_get_protocol(A) lws_get_protocol((A))
#    define libwebsockets_return_http_status(A, B, C, D) lws_return_http_status((B), (C), (D))
#define DECLTYPE(x) (decltype(x))
#define DECLTYPE_ASSIGN(dst,src)                                                 \
do {                                                                             \
  char **_da_dst = (char**)(&(dst));                                             \
  *_da_dst = (char*)(src);                                                       \
} while(0)
#define ELMT_FROM_HH(tbl,hhp) ((void*)(((char*)(hhp)) - ((tbl)->hho)))
#define HASH_ADD(hh,head,fieldname,keylen_in,add)                                \
        HASH_ADD_KEYPTR(hh,head,&((add)->fieldname),keylen_in,add)
#define HASH_ADD_INT(head,intfield,add)                                          \
    HASH_ADD(hh,head,intfield,sizeof(int),add)
#define HASH_ADD_KEYPTR(hh,head,keyptr,keylen_in,add)                            \
do {                                                                             \
 unsigned _ha_bkt;                                                               \
 (add)->hh.next = NULL;                                                          \
 (add)->hh.key = (char*)keyptr;                                                  \
 (add)->hh.keylen = (unsigned)keylen_in;                                                   \
 if (!(head)) {                                                                  \
    head = (add);                                                                \
    (head)->hh.prev = NULL;                                                      \
    HASH_MAKE_TABLE(hh,head);                                                    \
 } else {                                                                        \
    (head)->hh.tbl->tail->next = (add);                                          \
    (add)->hh.prev = ELMT_FROM_HH((head)->hh.tbl, (head)->hh.tbl->tail);         \
    (head)->hh.tbl->tail = &((add)->hh);                                         \
 }                                                                               \
 (head)->hh.tbl->num_items++;                                                    \
 (add)->hh.tbl = (head)->hh.tbl;                                                 \
 HASH_FCN(keyptr,keylen_in, (head)->hh.tbl->num_buckets,                         \
         (add)->hh.hashv, _ha_bkt);                                              \
 HASH_ADD_TO_BKT((head)->hh.tbl->buckets[_ha_bkt],&(add)->hh);                   \
 HASH_BLOOM_ADD((head)->hh.tbl,(add)->hh.hashv);                                 \
 HASH_EMIT_KEY(hh,head,keyptr,keylen_in);                                        \
 HASH_FSCK(hh,head);                                                             \
} while(0)
#define HASH_ADD_PTR(head,ptrfield,add)                                          \
    HASH_ADD(hh,head,ptrfield,sizeof(void *),add)
#define HASH_ADD_STR(head,strfield,add)                                          \
    HASH_ADD(hh,head,strfield,strlen(add->strfield),add)
#define HASH_ADD_TO_BKT(head,addhh)                                              \
do {                                                                             \
 head.count++;                                                                   \
 (addhh)->hh_next = head.hh_head;                                                \
 (addhh)->hh_prev = NULL;                                                        \
 if (head.hh_head) { (head).hh_head->hh_prev = (addhh); }                        \
 (head).hh_head=addhh;                                                           \
 if (head.count >= ((head.expand_mult+1) * HASH_BKT_CAPACITY_THRESH)             \
     && (addhh)->tbl->noexpand != 1) {                                           \
       HASH_EXPAND_BUCKETS((addhh)->tbl);                                        \
 }                                                                               \
} while(0)
#define HASH_BER(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _hb_keylen=keylen;                                                    \
  char *_hb_key=(char*)(key);                                                    \
  (hashv) = 0;                                                                   \
  while (_hb_keylen--)  { (hashv) = ((hashv) * 33) + *_hb_key++; }               \
  bkt = (hashv) & (num_bkts-1);                                                  \
} while (0)
#define HASH_BKT_CAPACITY_THRESH 10      
#define HASH_BLOOM_ADD(tbl,hashv)                                                \
  HASH_BLOOM_BITSET((tbl)->bloom_bv, (hashv & (uint32_t)((1ULL << (tbl)->bloom_nbits) - 1)))
#define HASH_BLOOM_BITLEN (1ULL << HASH_BLOOM)
#define HASH_BLOOM_BITSET(bv,idx) (bv[(idx)/8] |= (1U << ((idx)%8)))
#define HASH_BLOOM_BITTEST(bv,idx) (bv[(idx)/8] & (1U << ((idx)%8)))
#define HASH_BLOOM_BYTELEN (HASH_BLOOM_BITLEN/8) + ((HASH_BLOOM_BITLEN%8) ? 1:0)
#define HASH_BLOOM_FREE(tbl)                                                     \
do {                                                                             \
  uthash_free((tbl)->bloom_bv, HASH_BLOOM_BYTELEN);                              \
} while (0) 
#define HASH_BLOOM_MAKE(tbl)                                                     \
do {                                                                             \
  (tbl)->bloom_nbits = HASH_BLOOM;                                               \
  (tbl)->bloom_bv = (uint8_t*)uthash_malloc(HASH_BLOOM_BYTELEN);                 \
  if (!((tbl)->bloom_bv))  { uthash_fatal( "out of memory"); }                   \
  memset((tbl)->bloom_bv, 0, HASH_BLOOM_BYTELEN);                                \
  (tbl)->bloom_sig = HASH_BLOOM_SIGNATURE;                                       \
} while (0) 
#define HASH_BLOOM_SIGNATURE 0xb12220f2
#define HASH_BLOOM_TEST(tbl,hashv)                                               \
  HASH_BLOOM_BITTEST((tbl)->bloom_bv, (hashv & (uint32_t)((1ULL << (tbl)->bloom_nbits) - 1)))
#define HASH_CLEAR(hh,head)                                                      \
do {                                                                             \
  if (head) {                                                                    \
    uthash_free((head)->hh.tbl->buckets,                                         \
                (head)->hh.tbl->num_buckets*sizeof(struct UT_hash_bucket));      \
    HASH_BLOOM_FREE((head)->hh.tbl);                                             \
    uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                          \
    (head)=NULL;                                                                 \
  }                                                                              \
} while(0)
#define HASH_CNT(hh,head) ((head)?((head)->hh.tbl->num_items):0)
#define HASH_COUNT(head) HASH_CNT(hh,head) 
#define HASH_DEL(head,delptr)                                                    \
    HASH_DELETE(hh,head,delptr)
#define HASH_DELETE(hh,head,delptr)                                              \
do {                                                                             \
    unsigned _hd_bkt;                                                            \
    struct UT_hash_handle *_hd_hh_del;                                           \
    if ( ((delptr)->hh.prev == NULL) && ((delptr)->hh.next == NULL) )  {         \
        uthash_free((head)->hh.tbl->buckets,                                     \
                    (head)->hh.tbl->num_buckets*sizeof(struct UT_hash_bucket) ); \
        HASH_BLOOM_FREE((head)->hh.tbl);                                         \
        uthash_free((head)->hh.tbl, sizeof(UT_hash_table));                      \
        head = NULL;                                                             \
    } else {                                                                     \
        _hd_hh_del = &((delptr)->hh);                                            \
        if ((delptr) == ELMT_FROM_HH((head)->hh.tbl,(head)->hh.tbl->tail)) {     \
            (head)->hh.tbl->tail =                                               \
                (UT_hash_handle*)((ptrdiff_t)((delptr)->hh.prev) +               \
                (head)->hh.tbl->hho);                                            \
        }                                                                        \
        if ((delptr)->hh.prev) {                                                 \
            ((UT_hash_handle*)((ptrdiff_t)((delptr)->hh.prev) +                  \
                    (head)->hh.tbl->hho))->next = (delptr)->hh.next;             \
        } else {                                                                 \
            DECLTYPE_ASSIGN(head,(delptr)->hh.next);                             \
        }                                                                        \
        if (_hd_hh_del->next) {                                                  \
            ((UT_hash_handle*)((ptrdiff_t)_hd_hh_del->next +                     \
                    (head)->hh.tbl->hho))->prev =                                \
                    _hd_hh_del->prev;                                            \
        }                                                                        \
        HASH_TO_BKT( _hd_hh_del->hashv, (head)->hh.tbl->num_buckets, _hd_bkt);   \
        HASH_DEL_IN_BKT(hh,(head)->hh.tbl->buckets[_hd_bkt], _hd_hh_del);        \
        (head)->hh.tbl->num_items--;                                             \
    }                                                                            \
    HASH_FSCK(hh,head);                                                          \
} while (0)
#define HASH_DEL_IN_BKT(hh,head,hh_del)                                          \
    (head).count--;                                                              \
    if ((head).hh_head == hh_del) {                                              \
      (head).hh_head = hh_del->hh_next;                                          \
    }                                                                            \
    if (hh_del->hh_prev) {                                                       \
        hh_del->hh_prev->hh_next = hh_del->hh_next;                              \
    }                                                                            \
    if (hh_del->hh_next) {                                                       \
        hh_del->hh_next->hh_prev = hh_del->hh_prev;                              \
    }                                                                
#define HASH_EMIT_KEY(hh,head,keyptr,fieldlen)                                   \
do {                                                                             \
    unsigned _klen = fieldlen;                                                   \
    write(HASH_EMIT_KEYS, &_klen, sizeof(_klen));                                \
    write(HASH_EMIT_KEYS, keyptr, fieldlen);                                     \
} while (0)
#define HASH_EXPAND_BUCKETS(tbl)                                                 \
do {                                                                             \
    unsigned _he_bkt;                                                            \
    unsigned _he_bkt_i;                                                          \
    struct UT_hash_handle *_he_thh, *_he_hh_nxt;                                 \
    UT_hash_bucket *_he_new_buckets, *_he_newbkt;                                \
    _he_new_buckets = (UT_hash_bucket*)uthash_malloc(                            \
             2 * tbl->num_buckets * sizeof(struct UT_hash_bucket));              \
    if (!_he_new_buckets) { uthash_fatal( "out of memory"); }                    \
    memset(_he_new_buckets, 0,                                                   \
            2 * tbl->num_buckets * sizeof(struct UT_hash_bucket));               \
    tbl->ideal_chain_maxlen =                                                    \
       (tbl->num_items >> (tbl->log2_num_buckets+1)) +                           \
       ((tbl->num_items & ((tbl->num_buckets*2)-1)) ? 1 : 0);                    \
    tbl->nonideal_items = 0;                                                     \
    for(_he_bkt_i = 0; _he_bkt_i < tbl->num_buckets; _he_bkt_i++)                \
    {                                                                            \
        _he_thh = tbl->buckets[ _he_bkt_i ].hh_head;                             \
        while (_he_thh) {                                                        \
           _he_hh_nxt = _he_thh->hh_next;                                        \
           HASH_TO_BKT( _he_thh->hashv, tbl->num_buckets*2, _he_bkt);            \
           _he_newbkt = &(_he_new_buckets[ _he_bkt ]);                           \
           if (++(_he_newbkt->count) > tbl->ideal_chain_maxlen) {                \
             tbl->nonideal_items++;                                              \
             _he_newbkt->expand_mult = _he_newbkt->count /                       \
                                        tbl->ideal_chain_maxlen;                 \
           }                                                                     \
           _he_thh->hh_prev = NULL;                                              \
           _he_thh->hh_next = _he_newbkt->hh_head;                               \
           if (_he_newbkt->hh_head) _he_newbkt->hh_head->hh_prev =               \
                _he_thh;                                                         \
           _he_newbkt->hh_head = _he_thh;                                        \
           _he_thh = _he_hh_nxt;                                                 \
        }                                                                        \
    }                                                                            \
    uthash_free( tbl->buckets, tbl->num_buckets*sizeof(struct UT_hash_bucket) ); \
    tbl->num_buckets *= 2;                                                       \
    tbl->log2_num_buckets++;                                                     \
    tbl->buckets = _he_new_buckets;                                              \
    tbl->ineff_expands = (tbl->nonideal_items > (tbl->num_items >> 1)) ?         \
        (tbl->ineff_expands+1) : 0;                                              \
    if (tbl->ineff_expands > 1) {                                                \
        tbl->noexpand=1;                                                         \
        uthash_noexpand_fyi(tbl);                                                \
    }                                                                            \
    uthash_expand_fyi(tbl);                                                      \
} while(0)
#define HASH_FCN HASH_FUNCTION
#define HASH_FIND(hh,head,keyptr,keylen,out)                                     \
do {                                                                             \
  unsigned _hf_bkt,_hf_hashv;                                                    \
  out=NULL;                                                                      \
  if (head) {                                                                    \
     HASH_FCN(keyptr,keylen, (head)->hh.tbl->num_buckets, _hf_hashv, _hf_bkt);   \
     if (HASH_BLOOM_TEST((head)->hh.tbl, _hf_hashv)) {                           \
       HASH_FIND_IN_BKT((head)->hh.tbl, hh, (head)->hh.tbl->buckets[ _hf_bkt ],  \
                        keyptr,keylen,out);                                      \
     }                                                                           \
  }                                                                              \
} while (0)
#define HASH_FIND_INT(head,findint,out)                                          \
    HASH_FIND(hh,head,findint,sizeof(int),out)
#define HASH_FIND_IN_BKT(tbl,hh,head,keyptr,keylen_in,out)                       \
do {                                                                             \
 if (head.hh_head) DECLTYPE_ASSIGN(out,ELMT_FROM_HH(tbl,head.hh_head));          \
 else out=NULL;                                                                  \
 while (out) {                                                                   \
    if ((out)->hh.keylen == keylen_in) {                                           \
        if ((HASH_KEYCMP((out)->hh.key,keyptr,keylen_in)) == 0) break;             \
    }                                                                            \
    if ((out)->hh.hh_next) DECLTYPE_ASSIGN(out,ELMT_FROM_HH(tbl,(out)->hh.hh_next)); \
    else out = NULL;                                                             \
 }                                                                               \
} while(0)
#define HASH_FIND_PTR(head,findptr,out)                                          \
    HASH_FIND(hh,head,findptr,sizeof(void *),out)
#define HASH_FIND_STR(head,findstr,out)                                          \
    HASH_FIND(hh,head,findstr,strlen(findstr),out)
#define HASH_FNV(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _fn_i;                                                                \
  char *_hf_key=(char*)(key);                                                    \
  hashv = 2166136261UL;                                                          \
  for(_fn_i=0; _fn_i < keylen; _fn_i++)                                          \
      hashv = (hashv * 16777619) ^ _hf_key[_fn_i];                               \
  bkt = hashv & (num_bkts-1);                                                    \
} while(0) 
#define HASH_FSCK(hh,head)                                                       \
do {                                                                             \
    unsigned _bkt_i;                                                             \
    unsigned _count, _bkt_count;                                                 \
    char *_prev;                                                                 \
    struct UT_hash_handle *_thh;                                                 \
    if (head) {                                                                  \
        _count = 0;                                                              \
        for( _bkt_i = 0; _bkt_i < (head)->hh.tbl->num_buckets; _bkt_i++) {       \
            _bkt_count = 0;                                                      \
            _thh = (head)->hh.tbl->buckets[_bkt_i].hh_head;                      \
            _prev = NULL;                                                        \
            while (_thh) {                                                       \
               if (_prev != (char*)(_thh->hh_prev)) {                            \
                   HASH_OOPS("invalid hh_prev %p, actual %p\n",                  \
                    _thh->hh_prev, _prev );                                      \
               }                                                                 \
               _bkt_count++;                                                     \
               _prev = (char*)(_thh);                                            \
               _thh = _thh->hh_next;                                             \
            }                                                                    \
            _count += _bkt_count;                                                \
            if ((head)->hh.tbl->buckets[_bkt_i].count !=  _bkt_count) {          \
               HASH_OOPS("invalid bucket count %d, actual %d\n",                 \
                (head)->hh.tbl->buckets[_bkt_i].count, _bkt_count);              \
            }                                                                    \
        }                                                                        \
        if (_count != (head)->hh.tbl->num_items) {                               \
            HASH_OOPS("invalid hh item count %d, actual %d\n",                   \
                (head)->hh.tbl->num_items, _count );                             \
        }                                                                        \
                 \
        _count = 0;                                                              \
        _prev = NULL;                                                            \
        _thh =  &(head)->hh;                                                     \
        while (_thh) {                                                           \
           _count++;                                                             \
           if (_prev !=(char*)(_thh->prev)) {                                    \
              HASH_OOPS("invalid prev %p, actual %p\n",                          \
                    _thh->prev, _prev );                                         \
           }                                                                     \
           _prev = (char*)ELMT_FROM_HH((head)->hh.tbl, _thh);                    \
           _thh = ( _thh->next ?  (UT_hash_handle*)((char*)(_thh->next) +        \
                                  (head)->hh.tbl->hho) : NULL );                 \
        }                                                                        \
        if (_count != (head)->hh.tbl->num_items) {                               \
            HASH_OOPS("invalid app item count %d, actual %d\n",                  \
                (head)->hh.tbl->num_items, _count );                             \
        }                                                                        \
    }                                                                            \
} while (0)
#define HASH_INITIAL_NUM_BUCKETS 32      
#define HASH_INITIAL_NUM_BUCKETS_LOG2 5  
#define HASH_ITER(hh,head,el,tmp)                                                \
for((el)=(head), (*(char**)(&(tmp)))=(char*)((head)?(head)->hh.next:NULL);       \
  el; (el)=(tmp),(*(char**)(&(tmp)))=(char*)((tmp)?(tmp)->hh.next:NULL)) 
#define HASH_JEN(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _hj_i,_hj_j,_hj_k;                                                    \
  unsigned char *_hj_key=(unsigned char*)(key);                                  \
  hashv = 0xfeedbeef;                                                            \
  _hj_i = _hj_j = 0x9e3779b9;                                                    \
  _hj_k = (unsigned)keylen;                                                      \
  while (_hj_k >= 12) {                                                          \
    _hj_i +=    (_hj_key[0] + ( (unsigned)_hj_key[1] << 8 )                      \
        + ( (unsigned)_hj_key[2] << 16 )                                         \
        + ( (unsigned)_hj_key[3] << 24 ) );                                      \
    _hj_j +=    (_hj_key[4] + ( (unsigned)_hj_key[5] << 8 )                      \
        + ( (unsigned)_hj_key[6] << 16 )                                         \
        + ( (unsigned)_hj_key[7] << 24 ) );                                      \
    hashv += (_hj_key[8] + ( (unsigned)_hj_key[9] << 8 )                         \
        + ( (unsigned)_hj_key[10] << 16 )                                        \
        + ( (unsigned)_hj_key[11] << 24 ) );                                     \
                                                                                 \
     HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                          \
                                                                                 \
     _hj_key += 12;                                                              \
     _hj_k -= 12;                                                                \
  }                                                                              \
  hashv += keylen;                                                               \
  switch ( _hj_k ) {                                                             \
     case 11: hashv += ( (unsigned)_hj_key[10] << 24 );                          \
     case 10: hashv += ( (unsigned)_hj_key[9] << 16 );                           \
     case 9:  hashv += ( (unsigned)_hj_key[8] << 8 );                            \
     case 8:  _hj_j += ( (unsigned)_hj_key[7] << 24 );                           \
     case 7:  _hj_j += ( (unsigned)_hj_key[6] << 16 );                           \
     case 6:  _hj_j += ( (unsigned)_hj_key[5] << 8 );                            \
     case 5:  _hj_j += _hj_key[4];                                               \
     case 4:  _hj_i += ( (unsigned)_hj_key[3] << 24 );                           \
     case 3:  _hj_i += ( (unsigned)_hj_key[2] << 16 );                           \
     case 2:  _hj_i += ( (unsigned)_hj_key[1] << 8 );                            \
     case 1:  _hj_i += _hj_key[0];                                               \
  }                                                                              \
  HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                             \
  bkt = hashv & (num_bkts-1);                                                    \
} while(0)
#define HASH_JEN_MIX(a,b,c)                                                      \
do {                                                                             \
  a -= b; a -= c; a ^= ( c >> 13 );                                              \
  b -= c; b -= a; b ^= ( a << 8 );                                               \
  c -= a; c -= b; c ^= ( b >> 13 );                                              \
  a -= b; a -= c; a ^= ( c >> 12 );                                              \
  b -= c; b -= a; b ^= ( a << 16 );                                              \
  c -= a; c -= b; c ^= ( b >> 5 );                                               \
  a -= b; a -= c; a ^= ( c >> 3 );                                               \
  b -= c; b -= a; b ^= ( a << 10 );                                              \
  c -= a; c -= b; c ^= ( b >> 15 );                                              \
} while (0)
#define HASH_KEYCMP(a,b,len) memcmp(a,b,len) 
#define HASH_MAKE_TABLE(hh,head)                                                 \
do {                                                                             \
  (head)->hh.tbl = (UT_hash_table*)uthash_malloc(                                \
                  sizeof(UT_hash_table));                                        \
  if (!((head)->hh.tbl))  { uthash_fatal( "out of memory"); }                    \
  memset((head)->hh.tbl, 0, sizeof(UT_hash_table));                              \
  (head)->hh.tbl->tail = &((head)->hh);                                          \
  (head)->hh.tbl->num_buckets = HASH_INITIAL_NUM_BUCKETS;                        \
  (head)->hh.tbl->log2_num_buckets = HASH_INITIAL_NUM_BUCKETS_LOG2;              \
  (head)->hh.tbl->hho = (char*)(&(head)->hh) - (char*)(head);                    \
  (head)->hh.tbl->buckets = (UT_hash_bucket*)uthash_malloc(                      \
          HASH_INITIAL_NUM_BUCKETS*sizeof(struct UT_hash_bucket));               \
  if (! (head)->hh.tbl->buckets) { uthash_fatal( "out of memory"); }             \
  memset((head)->hh.tbl->buckets, 0,                                             \
          HASH_INITIAL_NUM_BUCKETS*sizeof(struct UT_hash_bucket));               \
  HASH_BLOOM_MAKE((head)->hh.tbl);                                               \
  (head)->hh.tbl->signature = HASH_SIGNATURE;                                    \
} while(0)
#define HASH_MUR(key,keylen,num_bkts,hashv,bkt)                        \
do {                                                                   \
  const uint8_t *_mur_data = (const uint8_t*)(key);                    \
  const int _mur_nblocks = (keylen) / 4;                               \
  uint32_t _mur_h1 = 0xf88D5353;                                       \
  uint32_t _mur_c1 = 0xcc9e2d51;                                       \
  uint32_t _mur_c2 = 0x1b873593;                                       \
  uint32_t _mur_k1 = 0;                                                \
  const uint8_t *_mur_tail;                                            \
  const uint32_t *_mur_blocks = (const uint32_t*)(_mur_data+_mur_nblocks*4); \
  int _mur_i;                                                          \
  for(_mur_i = -_mur_nblocks; _mur_i; _mur_i++) {                      \
    _mur_k1 = MUR_GETBLOCK(_mur_blocks,_mur_i);                        \
    _mur_k1 *= _mur_c1;                                                \
    _mur_k1 = MUR_ROTL32(_mur_k1,15);                                  \
    _mur_k1 *= _mur_c2;                                                \
                                                                       \
    _mur_h1 ^= _mur_k1;                                                \
    _mur_h1 = MUR_ROTL32(_mur_h1,13);                                  \
    _mur_h1 = _mur_h1*5+0xe6546b64;                                    \
  }                                                                    \
  _mur_tail = (const uint8_t*)(_mur_data + _mur_nblocks*4);            \
  _mur_k1=0;                                                           \
  switch((keylen) & 3) {                                               \
    case 3: _mur_k1 ^= _mur_tail[2] << 16;                             \
    case 2: _mur_k1 ^= _mur_tail[1] << 8;                              \
    case 1: _mur_k1 ^= _mur_tail[0];                                   \
    _mur_k1 *= _mur_c1;                                                \
    _mur_k1 = MUR_ROTL32(_mur_k1,15);                                  \
    _mur_k1 *= _mur_c2;                                                \
    _mur_h1 ^= _mur_k1;                                                \
  }                                                                    \
  _mur_h1 ^= (keylen);                                                 \
  MUR_FMIX(_mur_h1);                                                   \
  hashv = _mur_h1;                                                     \
  bkt = hashv & (num_bkts-1);                                          \
} while(0)
#define HASH_OAT(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _ho_i;                                                                \
  char *_ho_key=(char*)(key);                                                    \
  hashv = 0;                                                                     \
  for(_ho_i=0; _ho_i < keylen; _ho_i++) {                                        \
      hashv += _ho_key[_ho_i];                                                   \
      hashv += (hashv << 10);                                                    \
      hashv ^= (hashv >> 6);                                                     \
  }                                                                              \
  hashv += (hashv << 3);                                                         \
  hashv ^= (hashv >> 11);                                                        \
  hashv += (hashv << 15);                                                        \
  bkt = hashv & (num_bkts-1);                                                    \
} while(0)
#define HASH_OOPS(...) do { fprintf(stderr,__VA_ARGS__); exit(-1); } while (0)
#define HASH_OVERHEAD(hh,head)                                                   \
 (size_t)((((head)->hh.tbl->num_items   * sizeof(UT_hash_handle))   +            \
           ((head)->hh.tbl->num_buckets * sizeof(UT_hash_bucket))   +            \
            (sizeof(UT_hash_table))                                 +            \
            (HASH_BLOOM_BYTELEN)))
#define HASH_REPLACE(hh,head,fieldname,keylen_in,add,replaced)                   \
do {                                                                             \
  replaced=NULL;                                                                 \
  HASH_FIND(hh,head,&((add)->fieldname),keylen_in,replaced);                     \
  if (replaced!=NULL) {                                                          \
     HASH_DELETE(hh,head,replaced);                                              \
  };                                                                             \
  HASH_ADD(hh,head,fieldname,keylen_in,add);                                     \
} while(0)
#define HASH_REPLACE_INT(head,intfield,add,replaced)                             \
    HASH_REPLACE(hh,head,intfield,sizeof(int),add,replaced)
#define HASH_REPLACE_PTR(head,ptrfield,add)                                      \
    HASH_REPLACE(hh,head,ptrfield,sizeof(void *),add,replaced)
#define HASH_REPLACE_STR(head,strfield,add,replaced)                             \
  HASH_REPLACE(hh,head,strfield,strlen(add->strfield),add,replaced)
#define HASH_SAX(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned _sx_i;                                                                \
  char *_hs_key=(char*)(key);                                                    \
  hashv = 0;                                                                     \
  for(_sx_i=0; _sx_i < keylen; _sx_i++)                                          \
      hashv ^= (hashv << 5) + (hashv >> 2) + _hs_key[_sx_i];                     \
  bkt = hashv & (num_bkts-1);                                                    \
} while (0)
#define HASH_SELECT(hh_dst, dst, hh_src, src, cond)                              \
do {                                                                             \
  unsigned _src_bkt, _dst_bkt;                                                   \
  void *_last_elt=NULL, *_elt;                                                   \
  UT_hash_handle *_src_hh, *_dst_hh, *_last_elt_hh=NULL;                         \
  ptrdiff_t _dst_hho = ((char*)(&(dst)->hh_dst) - (char*)(dst));                 \
  if (src) {                                                                     \
    for(_src_bkt=0; _src_bkt < (src)->hh_src.tbl->num_buckets; _src_bkt++) {     \
      for(_src_hh = (src)->hh_src.tbl->buckets[_src_bkt].hh_head;                \
          _src_hh;                                                               \
          _src_hh = _src_hh->hh_next) {                                          \
          _elt = ELMT_FROM_HH((src)->hh_src.tbl, _src_hh);                       \
          if (cond(_elt)) {                                                      \
            _dst_hh = (UT_hash_handle*)(((char*)_elt) + _dst_hho);               \
            _dst_hh->key = _src_hh->key;                                         \
            _dst_hh->keylen = _src_hh->keylen;                                   \
            _dst_hh->hashv = _src_hh->hashv;                                     \
            _dst_hh->prev = _last_elt;                                           \
            _dst_hh->next = NULL;                                                \
            if (_last_elt_hh) { _last_elt_hh->next = _elt; }                     \
            if (!dst) {                                                          \
              DECLTYPE_ASSIGN(dst,_elt);                                         \
              HASH_MAKE_TABLE(hh_dst,dst);                                       \
            } else {                                                             \
              _dst_hh->tbl = (dst)->hh_dst.tbl;                                  \
            }                                                                    \
            HASH_TO_BKT(_dst_hh->hashv, _dst_hh->tbl->num_buckets, _dst_bkt);    \
            HASH_ADD_TO_BKT(_dst_hh->tbl->buckets[_dst_bkt],_dst_hh);            \
            (dst)->hh_dst.tbl->num_items++;                                      \
            _last_elt = _elt;                                                    \
            _last_elt_hh = _dst_hh;                                              \
          }                                                                      \
      }                                                                          \
    }                                                                            \
  }                                                                              \
  HASH_FSCK(hh_dst,dst);                                                         \
} while (0)
#define HASH_SFH(key,keylen,num_bkts,hashv,bkt)                                  \
do {                                                                             \
  unsigned char *_sfh_key=(unsigned char*)(key);                                 \
  uint32_t _sfh_tmp, _sfh_len = keylen;                                          \
                                                                                 \
  int _sfh_rem = _sfh_len & 3;                                                   \
  _sfh_len >>= 2;                                                                \
  hashv = 0xcafebabe;                                                            \
                                                                                 \
                                                                  \
  for (;_sfh_len > 0; _sfh_len--) {                                              \
    hashv    += get16bits (_sfh_key);                                            \
    _sfh_tmp       = (uint32_t)(get16bits (_sfh_key+2)) << 11  ^ hashv;          \
    hashv     = (hashv << 16) ^ _sfh_tmp;                                        \
    _sfh_key += 2*sizeof (uint16_t);                                             \
    hashv    += hashv >> 11;                                                     \
  }                                                                              \
                                                                                 \
                                                           \
  switch (_sfh_rem) {                                                            \
    case 3: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 16;                                                \
            hashv ^= (uint32_t)(_sfh_key[sizeof (uint16_t)] << 18);              \
            hashv += hashv >> 11;                                                \
            break;                                                               \
    case 2: hashv += get16bits (_sfh_key);                                       \
            hashv ^= hashv << 11;                                                \
            hashv += hashv >> 17;                                                \
            break;                                                               \
    case 1: hashv += *_sfh_key;                                                  \
            hashv ^= hashv << 10;                                                \
            hashv += hashv >> 1;                                                 \
  }                                                                              \
                                                                                 \
                                      \
    hashv ^= hashv << 3;                                                         \
    hashv += hashv >> 5;                                                         \
    hashv ^= hashv << 4;                                                         \
    hashv += hashv >> 17;                                                        \
    hashv ^= hashv << 25;                                                        \
    hashv += hashv >> 6;                                                         \
    bkt = hashv & (num_bkts-1);                                                  \
} while(0) 
#define HASH_SIGNATURE 0xa0111fe1
#define HASH_SORT(head,cmpfcn) HASH_SRT(hh,head,cmpfcn)
#define HASH_SRT(hh,head,cmpfcn)                                                 \
do {                                                                             \
  unsigned _hs_i;                                                                \
  unsigned _hs_looping,_hs_nmerges,_hs_insize,_hs_psize,_hs_qsize;               \
  struct UT_hash_handle *_hs_p, *_hs_q, *_hs_e, *_hs_list, *_hs_tail;            \
  if (head) {                                                                    \
      _hs_insize = 1;                                                            \
      _hs_looping = 1;                                                           \
      _hs_list = &((head)->hh);                                                  \
      while (_hs_looping) {                                                      \
          _hs_p = _hs_list;                                                      \
          _hs_list = NULL;                                                       \
          _hs_tail = NULL;                                                       \
          _hs_nmerges = 0;                                                       \
          while (_hs_p) {                                                        \
              _hs_nmerges++;                                                     \
              _hs_q = _hs_p;                                                     \
              _hs_psize = 0;                                                     \
              for ( _hs_i = 0; _hs_i  < _hs_insize; _hs_i++ ) {                  \
                  _hs_psize++;                                                   \
                  _hs_q = (UT_hash_handle*)((_hs_q->next) ?                      \
                          ((void*)((char*)(_hs_q->next) +                        \
                          (head)->hh.tbl->hho)) : NULL);                         \
                  if (! (_hs_q) ) break;                                         \
              }                                                                  \
              _hs_qsize = _hs_insize;                                            \
              while ((_hs_psize > 0) || ((_hs_qsize > 0) && _hs_q )) {           \
                  if (_hs_psize == 0) {                                          \
                      _hs_e = _hs_q;                                             \
                      _hs_q = (UT_hash_handle*)((_hs_q->next) ?                  \
                              ((void*)((char*)(_hs_q->next) +                    \
                              (head)->hh.tbl->hho)) : NULL);                     \
                      _hs_qsize--;                                               \
                  } else if ( (_hs_qsize == 0) || !(_hs_q) ) {                   \
                      _hs_e = _hs_p;                                             \
                      if (_hs_p){                                                \
                        _hs_p = (UT_hash_handle*)((_hs_p->next) ?                \
                                ((void*)((char*)(_hs_p->next) +                  \
                                (head)->hh.tbl->hho)) : NULL);                   \
                       }                                                         \
                      _hs_psize--;                                               \
                  } else if ((                                                   \
                      cmpfcn(DECLTYPE(head)(ELMT_FROM_HH((head)->hh.tbl,_hs_p)), \
                             DECLTYPE(head)(ELMT_FROM_HH((head)->hh.tbl,_hs_q))) \
                             ) <= 0) {                                           \
                      _hs_e = _hs_p;                                             \
                      if (_hs_p){                                                \
                        _hs_p = (UT_hash_handle*)((_hs_p->next) ?                \
                               ((void*)((char*)(_hs_p->next) +                   \
                               (head)->hh.tbl->hho)) : NULL);                    \
                       }                                                         \
                      _hs_psize--;                                               \
                  } else {                                                       \
                      _hs_e = _hs_q;                                             \
                      _hs_q = (UT_hash_handle*)((_hs_q->next) ?                  \
                              ((void*)((char*)(_hs_q->next) +                    \
                              (head)->hh.tbl->hho)) : NULL);                     \
                      _hs_qsize--;                                               \
                  }                                                              \
                  if ( _hs_tail ) {                                              \
                      _hs_tail->next = ((_hs_e) ?                                \
                            ELMT_FROM_HH((head)->hh.tbl,_hs_e) : NULL);          \
                  } else {                                                       \
                      _hs_list = _hs_e;                                          \
                  }                                                              \
                  if (_hs_e) {                                                   \
                  _hs_e->prev = ((_hs_tail) ?                                    \
                     ELMT_FROM_HH((head)->hh.tbl,_hs_tail) : NULL);              \
                  }                                                              \
                  _hs_tail = _hs_e;                                              \
              }                                                                  \
              _hs_p = _hs_q;                                                     \
          }                                                                      \
          if (_hs_tail){                                                         \
            _hs_tail->next = NULL;                                               \
          }                                                                      \
          if ( _hs_nmerges <= 1 ) {                                              \
              _hs_looping=0;                                                     \
              (head)->hh.tbl->tail = _hs_tail;                                   \
              DECLTYPE_ASSIGN(head,ELMT_FROM_HH((head)->hh.tbl, _hs_list));      \
          }                                                                      \
          _hs_insize *= 2;                                                       \
      }                                                                          \
      HASH_FSCK(hh,head);                                                        \
 }                                                                               \
} while (0)
#define HASH_TO_BKT( hashv, num_bkts, bkt )                                      \
do {                                                                             \
  bkt = ((hashv) & ((num_bkts) - 1));                                            \
} while(0)
#define MUR_FMIX(_h) \
do {                 \
  _h ^= _h >> 16;    \
  _h *= 0x85ebca6b;  \
  _h ^= _h >> 13;    \
  _h *= 0xc2b2ae35l; \
  _h ^= _h >> 16;    \
} while(0)
#define MUR_GETBLOCK(p,i) p[i]
#define MUR_ONE_THREE(p) ((((*WP(p))&0x000000ff) <<24) | (((*(WP(p)+1))&0xffffff00) >>  8))
#define MUR_PLUS0_ALIGNED(p) (((unsigned long)p & 0x3) == 0)
#define MUR_PLUS1_ALIGNED(p) (((unsigned long)p & 0x3) == 1)
#define MUR_PLUS2_ALIGNED(p) (((unsigned long)p & 0x3) == 2)
#define MUR_PLUS3_ALIGNED(p) (((unsigned long)p & 0x3) == 3)
#define MUR_ROTL32(x,r) (((x) << (r)) | ((x) >> (32 - (r))))
#define MUR_THREE_ONE(p) ((((*WP(p))&0x00ffffff) << 8) | (((*(WP(p)+1))&0xff000000) >> 24))
#define MUR_TWO_TWO(p)   ((((*WP(p))&0x0000ffff) <<16) | (((*(WP(p)+1))&0xffff0000) >> 16))

#define UTHASH_H 
#define UTHASH_VERSION 1.9.8
#define WP(p) ((uint32_t*)((unsigned long)(p) & ~3UL))
#define get16bits(d) (*((const uint16_t *) (d)))
#define uthash_expand_fyi(tbl)            
#define uthash_fatal(msg) exit(-1)        
#define uthash_free(ptr,sz) free(ptr)     
#define uthash_malloc(sz) malloc(sz)      
#define uthash_noexpand_fyi(tbl)          

#define MOSQ_ACL_NONE 0x00
#define MOSQ_ACL_READ 0x01
#define MOSQ_ACL_WRITE 0x02
#define MOSQ_AUTH_PLUGIN_VERSION 2
#  define EPROTO ECONNABORTED
#  define snprintf sprintf_s
#    define strcasecmp strcmpi
#define strerror_r(e, b, l) strerror_s(b, l, e)
#define strtok_r strtok_s
