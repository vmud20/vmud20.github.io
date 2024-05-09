






















char* rdbFileBeingLoaded = NULL; 
extern int rdbCheckMode;
void rdbCheckError(const char *fmt, ...);
void rdbCheckSetError(const char *fmt, ...);


void rdbReportError(int corruption_error, int linenum, char *reason, ...) __attribute__ ((format (printf, 3, 4)));

void rdbReportError(int corruption_error, int linenum, char *reason, ...) {
    va_list ap;
    char msg[1024];
    int len;

    len = snprintf(msg,sizeof(msg), "Internal error in RDB reading offset %llu, function at rdb.c:%d -> ", (unsigned long long)server.loading_loaded_bytes, linenum);

    va_start(ap,reason);
    vsnprintf(msg+len,sizeof(msg)-len,reason,ap);
    va_end(ap);

    if (!server.loading) {
        
        
        serverLog(LL_VERBOSE, "%s", msg);
        return;
    } else if (rdbCheckMode) {
        
        rdbCheckError("%s",msg);
    } else if (rdbFileBeingLoaded) {
        
        serverLog(LL_WARNING, "%s", msg);
        char *argv[2] = {"",rdbFileBeingLoaded};
        redis_check_rdb_main(2,argv,NULL);
    } else if (corruption_error) {
        
        serverLog(LL_WARNING, "%s. Failure loading rdb format", msg);
    } else {
        
        serverLog(LL_WARNING, "%s. Failure loading rdb format from socket, assuming connection error, resuming operation.", msg);
        return;
    }
    serverLog(LL_WARNING, "Terminating server after rdb file reading failure.");
    exit(1);
}

static ssize_t rdbWriteRaw(rio *rdb, void *p, size_t len) {
    if (rdb && rioWrite(rdb,p,len) == 0)
        return -1;
    return len;
}

int rdbSaveType(rio *rdb, unsigned char type) {
    return rdbWriteRaw(rdb,&type,1);
}


int rdbLoadType(rio *rdb) {
    unsigned char type;
    if (rioRead(rdb,&type,1) == 0) return -1;
    return type;
}


time_t rdbLoadTime(rio *rdb) {
    int32_t t32;
    if (rioRead(rdb,&t32,4) == 0) return -1;
    return (time_t)t32;
}

int rdbSaveMillisecondTime(rio *rdb, long long t) {
    int64_t t64 = (int64_t) t;
    memrev64ifbe(&t64); 
    return rdbWriteRaw(rdb,&t64,8);
}


long long rdbLoadMillisecondTime(rio *rdb, int rdbver) {
    int64_t t64;
    if (rioRead(rdb,&t64,8) == 0) return LLONG_MAX;
    if (rdbver >= 9) 
        memrev64ifbe(&t64); 
    return (long long)t64;
}


int rdbSaveLen(rio *rdb, uint64_t len) {
    unsigned char buf[2];
    size_t nwritten;

    if (len < (1<<6)) {
        
        buf[0] = (len&0xFF)|(RDB_6BITLEN<<6);
        if (rdbWriteRaw(rdb,buf,1) == -1) return -1;
        nwritten = 1;
    } else if (len < (1<<14)) {
        
        buf[0] = ((len>>8)&0xFF)|(RDB_14BITLEN<<6);
        buf[1] = len&0xFF;
        if (rdbWriteRaw(rdb,buf,2) == -1) return -1;
        nwritten = 2;
    } else if (len <= UINT32_MAX) {
        
        buf[0] = RDB_32BITLEN;
        if (rdbWriteRaw(rdb,buf,1) == -1) return -1;
        uint32_t len32 = htonl(len);
        if (rdbWriteRaw(rdb,&len32,4) == -1) return -1;
        nwritten = 1+4;
    } else {
        
        buf[0] = RDB_64BITLEN;
        if (rdbWriteRaw(rdb,buf,1) == -1) return -1;
        len = htonu64(len);
        if (rdbWriteRaw(rdb,&len,8) == -1) return -1;
        nwritten = 1+8;
    }
    return nwritten;
}



int rdbLoadLenByRef(rio *rdb, int *isencoded, uint64_t *lenptr) {
    unsigned char buf[2];
    int type;

    if (isencoded) *isencoded = 0;
    if (rioRead(rdb,buf,1) == 0) return -1;
    type = (buf[0]&0xC0)>>6;
    if (type == RDB_ENCVAL) {
        
        if (isencoded) *isencoded = 1;
        *lenptr = buf[0]&0x3F;
    } else if (type == RDB_6BITLEN) {
        
        *lenptr = buf[0]&0x3F;
    } else if (type == RDB_14BITLEN) {
        
        if (rioRead(rdb,buf+1,1) == 0) return -1;
        *lenptr = ((buf[0]&0x3F)<<8)|buf[1];
    } else if (buf[0] == RDB_32BITLEN) {
        
        uint32_t len;
        if (rioRead(rdb,&len,4) == 0) return -1;
        *lenptr = ntohl(len);
    } else if (buf[0] == RDB_64BITLEN) {
        
        uint64_t len;
        if (rioRead(rdb,&len,8) == 0) return -1;
        *lenptr = ntohu64(len);
    } else {
        rdbReportCorruptRDB( "Unknown length encoding %d in rdbLoadLen()",type);
        return -1; 
    }
    return 0;
}


uint64_t rdbLoadLen(rio *rdb, int *isencoded) {
    uint64_t len;

    if (rdbLoadLenByRef(rdb,isencoded,&len) == -1) return RDB_LENERR;
    return len;
}


int rdbEncodeInteger(long long value, unsigned char *enc) {
    if (value >= -(1<<7) && value <= (1<<7)-1) {
        enc[0] = (RDB_ENCVAL<<6)|RDB_ENC_INT8;
        enc[1] = value&0xFF;
        return 2;
    } else if (value >= -(1<<15) && value <= (1<<15)-1) {
        enc[0] = (RDB_ENCVAL<<6)|RDB_ENC_INT16;
        enc[1] = value&0xFF;
        enc[2] = (value>>8)&0xFF;
        return 3;
    } else if (value >= -((long long)1<<31) && value <= ((long long)1<<31)-1) {
        enc[0] = (RDB_ENCVAL<<6)|RDB_ENC_INT32;
        enc[1] = value&0xFF;
        enc[2] = (value>>8)&0xFF;
        enc[3] = (value>>16)&0xFF;
        enc[4] = (value>>24)&0xFF;
        return 5;
    } else {
        return 0;
    }
}


void *rdbLoadIntegerObject(rio *rdb, int enctype, int flags, size_t *lenptr) {
    int plain = flags & RDB_LOAD_PLAIN;
    int sds = flags & RDB_LOAD_SDS;
    int encode = flags & RDB_LOAD_ENC;
    unsigned char enc[4];
    long long val;

    if (enctype == RDB_ENC_INT8) {
        if (rioRead(rdb,enc,1) == 0) return NULL;
        val = (signed char)enc[0];
    } else if (enctype == RDB_ENC_INT16) {
        uint16_t v;
        if (rioRead(rdb,enc,2) == 0) return NULL;
        v = enc[0]|(enc[1]<<8);
        val = (int16_t)v;
    } else if (enctype == RDB_ENC_INT32) {
        uint32_t v;
        if (rioRead(rdb,enc,4) == 0) return NULL;
        v = enc[0]|(enc[1]<<8)|(enc[2]<<16)|(enc[3]<<24);
        val = (int32_t)v;
    } else {
        rdbReportCorruptRDB("Unknown RDB integer encoding type %d",enctype);
        return NULL; 
    }
    if (plain || sds) {
        char buf[LONG_STR_SIZE], *p;
        int len = ll2string(buf,sizeof(buf),val);
        if (lenptr) *lenptr = len;
        p = plain ? zmalloc(len) : sdsnewlen(SDS_NOINIT,len);
        memcpy(p,buf,len);
        return p;
    } else if (encode) {
        return createStringObjectFromLongLongForValue(val);
    } else {
        return createObject(OBJ_STRING,sdsfromlonglong(val));
    }
}


int rdbTryIntegerEncoding(char *s, size_t len, unsigned char *enc) {
    long long value;
    if (string2ll(s, len, &value)) {
        return rdbEncodeInteger(value, enc);
    } else {
        return 0;
    }
}

ssize_t rdbSaveLzfBlob(rio *rdb, void *data, size_t compress_len, size_t original_len) {
    unsigned char byte;
    ssize_t n, nwritten = 0;

    
    byte = (RDB_ENCVAL<<6)|RDB_ENC_LZF;
    if ((n = rdbWriteRaw(rdb,&byte,1)) == -1) goto writeerr;
    nwritten += n;

    if ((n = rdbSaveLen(rdb,compress_len)) == -1) goto writeerr;
    nwritten += n;

    if ((n = rdbSaveLen(rdb,original_len)) == -1) goto writeerr;
    nwritten += n;

    if ((n = rdbWriteRaw(rdb,data,compress_len)) == -1) goto writeerr;
    nwritten += n;

    return nwritten;

writeerr:
    return -1;
}

ssize_t rdbSaveLzfStringObject(rio *rdb, unsigned char *s, size_t len) {
    size_t comprlen, outlen;
    void *out;

    
    if (len <= 4) return 0;
    outlen = len-4;
    if ((out = zmalloc(outlen+1)) == NULL) return 0;
    comprlen = lzf_compress(s, len, out, outlen);
    if (comprlen == 0) {
        zfree(out);
        return 0;
    }
    ssize_t nwritten = rdbSaveLzfBlob(rdb, out, comprlen, len);
    zfree(out);
    return nwritten;
}


void *rdbLoadLzfStringObject(rio *rdb, int flags, size_t *lenptr) {
    int plain = flags & RDB_LOAD_PLAIN;
    int sds = flags & RDB_LOAD_SDS;
    uint64_t len, clen;
    unsigned char *c = NULL;
    char *val = NULL;

    if ((clen = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return NULL;
    if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return NULL;
    if ((c = ztrymalloc(clen)) == NULL) {
        serverLog(server.loading? LL_WARNING: LL_VERBOSE, "rdbLoadLzfStringObject failed allocating %llu bytes", (unsigned long long)clen);
        goto err;
    }

    
    if (plain) {
        val = ztrymalloc(len);
    } else {
        val = sdstrynewlen(SDS_NOINIT,len);
    }
    if (!val) {
        serverLog(server.loading? LL_WARNING: LL_VERBOSE, "rdbLoadLzfStringObject failed allocating %llu bytes", (unsigned long long)len);
        goto err;
    }

    if (lenptr) *lenptr = len;

    
    if (rioRead(rdb,c,clen) == 0) goto err;
    if (lzf_decompress(c,clen,val,len) != len) {
        rdbReportCorruptRDB("Invalid LZF compressed string");
        goto err;
    }
    zfree(c);

    if (plain || sds) {
        return val;
    } else {
        return createObject(OBJ_STRING,val);
    }
err:
    zfree(c);
    if (plain)
        zfree(val);
    else sdsfree(val);
    return NULL;
}


ssize_t rdbSaveRawString(rio *rdb, unsigned char *s, size_t len) {
    int enclen;
    ssize_t n, nwritten = 0;

    
    if (len <= 11) {
        unsigned char buf[5];
        if ((enclen = rdbTryIntegerEncoding((char*)s,len,buf)) > 0) {
            if (rdbWriteRaw(rdb,buf,enclen) == -1) return -1;
            return enclen;
        }
    }

    
    if (server.rdb_compression && len > 20) {
        n = rdbSaveLzfStringObject(rdb,s,len);
        if (n == -1) return -1;
        if (n > 0) return n;
        
    }

    
    if ((n = rdbSaveLen(rdb,len)) == -1) return -1;
    nwritten += n;
    if (len > 0) {
        if (rdbWriteRaw(rdb,s,len) == -1) return -1;
        nwritten += len;
    }
    return nwritten;
}


ssize_t rdbSaveLongLongAsStringObject(rio *rdb, long long value) {
    unsigned char buf[32];
    ssize_t n, nwritten = 0;
    int enclen = rdbEncodeInteger(value,buf);
    if (enclen > 0) {
        return rdbWriteRaw(rdb,buf,enclen);
    } else {
        
        enclen = ll2string((char*)buf,32,value);
        serverAssert(enclen < 32);
        if ((n = rdbSaveLen(rdb,enclen)) == -1) return -1;
        nwritten += n;
        if ((n = rdbWriteRaw(rdb,buf,enclen)) == -1) return -1;
        nwritten += n;
    }
    return nwritten;
}


ssize_t rdbSaveStringObject(rio *rdb, robj *obj) {
    
    if (obj->encoding == OBJ_ENCODING_INT) {
        return rdbSaveLongLongAsStringObject(rdb,(long)obj->ptr);
    } else {
        serverAssertWithInfo(NULL,obj,sdsEncodedObject(obj));
        return rdbSaveRawString(rdb,obj->ptr,sdslen(obj->ptr));
    }
}


void *rdbGenericLoadStringObject(rio *rdb, int flags, size_t *lenptr) {
    int encode = flags & RDB_LOAD_ENC;
    int plain = flags & RDB_LOAD_PLAIN;
    int sds = flags & RDB_LOAD_SDS;
    int isencoded;
    unsigned long long len;

    len = rdbLoadLen(rdb,&isencoded);
    if (len == RDB_LENERR) return NULL;

    if (isencoded) {
        switch(len) {
        case RDB_ENC_INT8:
        case RDB_ENC_INT16:
        case RDB_ENC_INT32:
            return rdbLoadIntegerObject(rdb,len,flags,lenptr);
        case RDB_ENC_LZF:
            return rdbLoadLzfStringObject(rdb,flags,lenptr);
        default:
            rdbReportCorruptRDB("Unknown RDB string encoding type %llu",len);
            return NULL;
        }
    }

    if (plain || sds) {
        void *buf = plain ? ztrymalloc(len) : sdstrynewlen(SDS_NOINIT,len);
        if (!buf) {
            serverLog(server.loading? LL_WARNING: LL_VERBOSE, "rdbGenericLoadStringObject failed allocating %llu bytes", len);
            return NULL;
        }
        if (lenptr) *lenptr = len;
        if (len && rioRead(rdb,buf,len) == 0) {
            if (plain)
                zfree(buf);
            else sdsfree(buf);
            return NULL;
        }
        return buf;
    } else {
        robj *o = encode ? tryCreateStringObject(SDS_NOINIT,len) :
                           tryCreateRawStringObject(SDS_NOINIT,len);
        if (!o) {
            serverLog(server.loading? LL_WARNING: LL_VERBOSE, "rdbGenericLoadStringObject failed allocating %llu bytes", len);
            return NULL;
        }
        if (len && rioRead(rdb,o->ptr,len) == 0) {
            decrRefCount(o);
            return NULL;
        }
        return o;
    }
}

robj *rdbLoadStringObject(rio *rdb) {
    return rdbGenericLoadStringObject(rdb,RDB_LOAD_NONE,NULL);
}

robj *rdbLoadEncodedStringObject(rio *rdb) {
    return rdbGenericLoadStringObject(rdb,RDB_LOAD_ENC,NULL);
}


int rdbSaveDoubleValue(rio *rdb, double val) {
    unsigned char buf[128];
    int len;

    if (isnan(val)) {
        buf[0] = 253;
        len = 1;
    } else if (!isfinite(val)) {
        len = 1;
        buf[0] = (val < 0) ? 255 : 254;
    } else {

        
        double min = -4503599627370495; 
        double max = 4503599627370496; 
        if (val > min && val < max && val == ((double)((long long)val)))
            ll2string((char*)buf+1,sizeof(buf)-1,(long long)val);
        else  snprintf((char*)buf+1,sizeof(buf)-1,"%.17g",val);

        buf[0] = strlen((char*)buf+1);
        len = buf[0]+1;
    }
    return rdbWriteRaw(rdb,buf,len);
}


int rdbLoadDoubleValue(rio *rdb, double *val) {
    char buf[256];
    unsigned char len;

    if (rioRead(rdb,&len,1) == 0) return -1;
    switch(len) {
    case 255: *val = R_NegInf; return 0;
    case 254: *val = R_PosInf; return 0;
    case 253: *val = R_Nan; return 0;
    default:
        if (rioRead(rdb,buf,len) == 0) return -1;
        buf[len] = '\0';
        if (sscanf(buf, "%lg", val)!=1) return -1;
        return 0;
    }
}


int rdbSaveBinaryDoubleValue(rio *rdb, double val) {
    memrev64ifbe(&val);
    return rdbWriteRaw(rdb,&val,sizeof(val));
}


int rdbLoadBinaryDoubleValue(rio *rdb, double *val) {
    if (rioRead(rdb,val,sizeof(*val)) == 0) return -1;
    memrev64ifbe(val);
    return 0;
}


int rdbSaveBinaryFloatValue(rio *rdb, float val) {
    memrev32ifbe(&val);
    return rdbWriteRaw(rdb,&val,sizeof(val));
}


int rdbLoadBinaryFloatValue(rio *rdb, float *val) {
    if (rioRead(rdb,val,sizeof(*val)) == 0) return -1;
    memrev32ifbe(val);
    return 0;
}


int rdbSaveObjectType(rio *rdb, robj *o) {
    switch (o->type) {
    case OBJ_STRING:
        return rdbSaveType(rdb,RDB_TYPE_STRING);
    case OBJ_LIST:
        if (o->encoding == OBJ_ENCODING_QUICKLIST)
            return rdbSaveType(rdb,RDB_TYPE_LIST_QUICKLIST);
        else serverPanic("Unknown list encoding");
    case OBJ_SET:
        if (o->encoding == OBJ_ENCODING_INTSET)
            return rdbSaveType(rdb,RDB_TYPE_SET_INTSET);
        else if (o->encoding == OBJ_ENCODING_HT)
            return rdbSaveType(rdb,RDB_TYPE_SET);
        else serverPanic("Unknown set encoding");
    case OBJ_ZSET:
        if (o->encoding == OBJ_ENCODING_LISTPACK)
            return rdbSaveType(rdb,RDB_TYPE_ZSET_LISTPACK);
        else if (o->encoding == OBJ_ENCODING_SKIPLIST)
            return rdbSaveType(rdb,RDB_TYPE_ZSET_2);
        else serverPanic("Unknown sorted set encoding");
    case OBJ_HASH:
        if (o->encoding == OBJ_ENCODING_LISTPACK)
            return rdbSaveType(rdb,RDB_TYPE_HASH_LISTPACK);
        else if (o->encoding == OBJ_ENCODING_HT)
            return rdbSaveType(rdb,RDB_TYPE_HASH);
        else serverPanic("Unknown hash encoding");
    case OBJ_STREAM:
        return rdbSaveType(rdb,RDB_TYPE_STREAM_LISTPACKS);
    case OBJ_MODULE:
        return rdbSaveType(rdb,RDB_TYPE_MODULE_2);
    default:
        serverPanic("Unknown object type");
    }
    return -1; 
}


int rdbLoadObjectType(rio *rdb) {
    int type;
    if ((type = rdbLoadType(rdb)) == -1) return -1;
    if (!rdbIsObjectType(type)) return -1;
    return type;
}


ssize_t rdbSaveStreamPEL(rio *rdb, rax *pel, int nacks) {
    ssize_t n, nwritten = 0;

    
    if ((n = rdbSaveLen(rdb,raxSize(pel))) == -1) return -1;
    nwritten += n;

    
    raxIterator ri;
    raxStart(&ri,pel);
    raxSeek(&ri,"^",NULL,0);
    while(raxNext(&ri)) {
        
        if ((n = rdbWriteRaw(rdb,ri.key,sizeof(streamID))) == -1) {
            raxStop(&ri);
            return -1;
        }
        nwritten += n;

        if (nacks) {
            streamNACK *nack = ri.data;
            if ((n = rdbSaveMillisecondTime(rdb,nack->delivery_time)) == -1) {
                raxStop(&ri);
                return -1;
            }
            nwritten += n;
            if ((n = rdbSaveLen(rdb,nack->delivery_count)) == -1) {
                raxStop(&ri);
                return -1;
            }
            nwritten += n;
            
        }
    }
    raxStop(&ri);
    return nwritten;
}


size_t rdbSaveStreamConsumers(rio *rdb, streamCG *cg) {
    ssize_t n, nwritten = 0;

    
    if ((n = rdbSaveLen(rdb,raxSize(cg->consumers))) == -1) return -1;
    nwritten += n;

    
    raxIterator ri;
    raxStart(&ri,cg->consumers);
    raxSeek(&ri,"^",NULL,0);
    while(raxNext(&ri)) {
        streamConsumer *consumer = ri.data;

        
        if ((n = rdbSaveRawString(rdb,ri.key,ri.key_len)) == -1) {
            raxStop(&ri);
            return -1;
        }
        nwritten += n;

        
        if ((n = rdbSaveMillisecondTime(rdb,consumer->seen_time)) == -1) {
            raxStop(&ri);
            return -1;
        }
        nwritten += n;

        
        if ((n = rdbSaveStreamPEL(rdb,consumer->pel,0)) == -1) {
            raxStop(&ri);
            return -1;
        }
        nwritten += n;
    }
    raxStop(&ri);
    return nwritten;
}


ssize_t rdbSaveObject(rio *rdb, robj *o, robj *key, int dbid) {
    ssize_t n = 0, nwritten = 0;

    if (o->type == OBJ_STRING) {
        
        if ((n = rdbSaveStringObject(rdb,o)) == -1) return -1;
        nwritten += n;
    } else if (o->type == OBJ_LIST) {
        
        if (o->encoding == OBJ_ENCODING_QUICKLIST) {
            quicklist *ql = o->ptr;
            quicklistNode *node = ql->head;

            if ((n = rdbSaveLen(rdb,ql->len)) == -1) return -1;
            nwritten += n;

            while(node) {
                if (quicklistNodeIsCompressed(node)) {
                    void *data;
                    size_t compress_len = quicklistGetLzf(node, &data);
                    if ((n = rdbSaveLzfBlob(rdb,data,compress_len,node->sz)) == -1) return -1;
                    nwritten += n;
                } else {
                    if ((n = rdbSaveRawString(rdb,node->zl,node->sz)) == -1) return -1;
                    nwritten += n;
                }
                node = node->next;
            }
        } else {
            serverPanic("Unknown list encoding");
        }
    } else if (o->type == OBJ_SET) {
        
        if (o->encoding == OBJ_ENCODING_HT) {
            dict *set = o->ptr;
            dictIterator *di = dictGetIterator(set);
            dictEntry *de;

            if ((n = rdbSaveLen(rdb,dictSize(set))) == -1) {
                dictReleaseIterator(di);
                return -1;
            }
            nwritten += n;

            while((de = dictNext(di)) != NULL) {
                sds ele = dictGetKey(de);
                if ((n = rdbSaveRawString(rdb,(unsigned char*)ele,sdslen(ele)))
                    == -1)
                {
                    dictReleaseIterator(di);
                    return -1;
                }
                nwritten += n;
            }
            dictReleaseIterator(di);
        } else if (o->encoding == OBJ_ENCODING_INTSET) {
            size_t l = intsetBlobLen((intset*)o->ptr);

            if ((n = rdbSaveRawString(rdb,o->ptr,l)) == -1) return -1;
            nwritten += n;
        } else {
            serverPanic("Unknown set encoding");
        }
    } else if (o->type == OBJ_ZSET) {
        
        if (o->encoding == OBJ_ENCODING_LISTPACK) {
            size_t l = lpBytes((unsigned char*)o->ptr);

            if ((n = rdbSaveRawString(rdb,o->ptr,l)) == -1) return -1;
            nwritten += n;
        } else if (o->encoding == OBJ_ENCODING_SKIPLIST) {
            zset *zs = o->ptr;
            zskiplist *zsl = zs->zsl;

            if ((n = rdbSaveLen(rdb,zsl->length)) == -1) return -1;
            nwritten += n;

            
            zskiplistNode *zn = zsl->tail;
            while (zn != NULL) {
                if ((n = rdbSaveRawString(rdb, (unsigned char*)zn->ele,sdslen(zn->ele))) == -1)
                {
                    return -1;
                }
                nwritten += n;
                if ((n = rdbSaveBinaryDoubleValue(rdb,zn->score)) == -1)
                    return -1;
                nwritten += n;
                zn = zn->backward;
            }
        } else {
            serverPanic("Unknown sorted set encoding");
        }
    } else if (o->type == OBJ_HASH) {
        
        if (o->encoding == OBJ_ENCODING_LISTPACK) {
            size_t l = lpBytes((unsigned char*)o->ptr);

            if ((n = rdbSaveRawString(rdb,o->ptr,l)) == -1) return -1;
            nwritten += n;
        } else if (o->encoding == OBJ_ENCODING_HT) {
            dictIterator *di = dictGetIterator(o->ptr);
            dictEntry *de;

            if ((n = rdbSaveLen(rdb,dictSize((dict*)o->ptr))) == -1) {
                dictReleaseIterator(di);
                return -1;
            }
            nwritten += n;

            while((de = dictNext(di)) != NULL) {
                sds field = dictGetKey(de);
                sds value = dictGetVal(de);

                if ((n = rdbSaveRawString(rdb,(unsigned char*)field, sdslen(field))) == -1)
                {
                    dictReleaseIterator(di);
                    return -1;
                }
                nwritten += n;
                if ((n = rdbSaveRawString(rdb,(unsigned char*)value, sdslen(value))) == -1)
                {
                    dictReleaseIterator(di);
                    return -1;
                }
                nwritten += n;
            }
            dictReleaseIterator(di);
        } else {
            serverPanic("Unknown hash encoding");
        }
    } else if (o->type == OBJ_STREAM) {
        
        stream *s = o->ptr;
        rax *rax = s->rax;
        if ((n = rdbSaveLen(rdb,raxSize(rax))) == -1) return -1;
        nwritten += n;

        
        raxIterator ri;
        raxStart(&ri,rax);
        raxSeek(&ri,"^",NULL,0);
        while (raxNext(&ri)) {
            unsigned char *lp = ri.data;
            size_t lp_bytes = lpBytes(lp);
            if ((n = rdbSaveRawString(rdb,ri.key,ri.key_len)) == -1) {
                raxStop(&ri);
                return -1;
            }
            nwritten += n;
            if ((n = rdbSaveRawString(rdb,lp,lp_bytes)) == -1) {
                raxStop(&ri);
                return -1;
            }
            nwritten += n;
        }
        raxStop(&ri);

        
        if ((n = rdbSaveLen(rdb,s->length)) == -1) return -1;
        nwritten += n;
        
        if ((n = rdbSaveLen(rdb,s->last_id.ms)) == -1) return -1;
        nwritten += n;
        if ((n = rdbSaveLen(rdb,s->last_id.seq)) == -1) return -1;
        nwritten += n;

        

        
        size_t num_cgroups = s->cgroups ? raxSize(s->cgroups) : 0;
        if ((n = rdbSaveLen(rdb,num_cgroups)) == -1) return -1;
        nwritten += n;

        if (num_cgroups) {
            
            raxStart(&ri,s->cgroups);
            raxSeek(&ri,"^",NULL,0);
            while(raxNext(&ri)) {
                streamCG *cg = ri.data;

                
                if ((n = rdbSaveRawString(rdb,ri.key,ri.key_len)) == -1) {
                    raxStop(&ri);
                    return -1;
                }
                nwritten += n;

                
                if ((n = rdbSaveLen(rdb,cg->last_id.ms)) == -1) {
                    raxStop(&ri);
                    return -1;
                }
                nwritten += n;
                if ((n = rdbSaveLen(rdb,cg->last_id.seq)) == -1) {
                    raxStop(&ri);
                    return -1;
                }
                nwritten += n;

                
                if ((n = rdbSaveStreamPEL(rdb,cg->pel,1)) == -1) {
                    raxStop(&ri);
                    return -1;
                }
                nwritten += n;

                
                if ((n = rdbSaveStreamConsumers(rdb,cg)) == -1) {
                    raxStop(&ri);
                    return -1;
                }
                nwritten += n;
            }
            raxStop(&ri);
        }
    } else if (o->type == OBJ_MODULE) {
        
        RedisModuleIO io;
        moduleValue *mv = o->ptr;
        moduleType *mt = mv->type;

        
        int retval = rdbSaveLen(rdb,mt->id);
        if (retval == -1) return -1;
        moduleInitIOContext(io,mt,rdb,key,dbid);
        io.bytes += retval;

        
        mt->rdb_save(&io,mv->value);
        retval = rdbSaveLen(rdb,RDB_MODULE_OPCODE_EOF);
        if (retval == -1)
            io.error = 1;
        else io.bytes += retval;

        if (io.ctx) {
            moduleFreeContext(io.ctx);
            zfree(io.ctx);
        }
        return io.error ? -1 : (ssize_t)io.bytes;
    } else {
        serverPanic("Unknown object type");
    }
    return nwritten;
}


size_t rdbSavedObjectLen(robj *o, robj *key, int dbid) {
    ssize_t len = rdbSaveObject(NULL,o,key,dbid);
    serverAssertWithInfo(NULL,o,len != -1);
    return len;
}


int rdbSaveKeyValuePair(rio *rdb, robj *key, robj *val, long long expiretime, int dbid) {
    int savelru = server.maxmemory_policy & MAXMEMORY_FLAG_LRU;
    int savelfu = server.maxmemory_policy & MAXMEMORY_FLAG_LFU;

    
    if (expiretime != -1) {
        if (rdbSaveType(rdb,RDB_OPCODE_EXPIRETIME_MS) == -1) return -1;
        if (rdbSaveMillisecondTime(rdb,expiretime) == -1) return -1;
    }

    
    if (savelru) {
        uint64_t idletime = estimateObjectIdleTime(val);
        idletime /= 1000; 
        if (rdbSaveType(rdb,RDB_OPCODE_IDLE) == -1) return -1;
        if (rdbSaveLen(rdb,idletime) == -1) return -1;
    }

    
    if (savelfu) {
        uint8_t buf[1];
        buf[0] = LFUDecrAndReturn(val);
        
        if (rdbSaveType(rdb,RDB_OPCODE_FREQ) == -1) return -1;
        if (rdbWriteRaw(rdb,buf,1) == -1) return -1;
    }

    
    if (rdbSaveObjectType(rdb,val) == -1) return -1;
    if (rdbSaveStringObject(rdb,key) == -1) return -1;
    if (rdbSaveObject(rdb,val,key,dbid) == -1) return -1;

    
    if (server.rdb_key_save_delay)
        debugDelay(server.rdb_key_save_delay);

    return 1;
}


ssize_t rdbSaveAuxField(rio *rdb, void *key, size_t keylen, void *val, size_t vallen) {
    ssize_t ret, len = 0;
    if ((ret = rdbSaveType(rdb,RDB_OPCODE_AUX)) == -1) return -1;
    len += ret;
    if ((ret = rdbSaveRawString(rdb,key,keylen)) == -1) return -1;
    len += ret;
    if ((ret = rdbSaveRawString(rdb,val,vallen)) == -1) return -1;
    len += ret;
    return len;
}


ssize_t rdbSaveAuxFieldStrStr(rio *rdb, char *key, char *val) {
    return rdbSaveAuxField(rdb,key,strlen(key),val,strlen(val));
}


ssize_t rdbSaveAuxFieldStrInt(rio *rdb, char *key, long long val) {
    char buf[LONG_STR_SIZE];
    int vlen = ll2string(buf,sizeof(buf),val);
    return rdbSaveAuxField(rdb,key,strlen(key),buf,vlen);
}


int rdbSaveInfoAuxFields(rio *rdb, int rdbflags, rdbSaveInfo *rsi) {
    int redis_bits = (sizeof(void*) == 8) ? 64 : 32;
    int aof_preamble = (rdbflags & RDBFLAGS_AOF_PREAMBLE) != 0;

    
    if (rdbSaveAuxFieldStrStr(rdb,"redis-ver",REDIS_VERSION) == -1) return -1;
    if (rdbSaveAuxFieldStrInt(rdb,"redis-bits",redis_bits) == -1) return -1;
    if (rdbSaveAuxFieldStrInt(rdb,"ctime",time(NULL)) == -1) return -1;
    if (rdbSaveAuxFieldStrInt(rdb,"used-mem",zmalloc_used_memory()) == -1) return -1;

    
    if (rsi) {
        if (rdbSaveAuxFieldStrInt(rdb,"repl-stream-db",rsi->repl_stream_db)
            == -1) return -1;
        if (rdbSaveAuxFieldStrStr(rdb,"repl-id",server.replid)
            == -1) return -1;
        if (rdbSaveAuxFieldStrInt(rdb,"repl-offset",server.master_repl_offset)
            == -1) return -1;
    }
    if (rdbSaveAuxFieldStrInt(rdb,"aof-preamble",aof_preamble) == -1) return -1;
    return 1;
}

ssize_t rdbSaveSingleModuleAux(rio *rdb, int when, moduleType *mt) {
    
    RedisModuleIO io;
    int retval = rdbSaveType(rdb, RDB_OPCODE_MODULE_AUX);
    if (retval == -1) return -1;
    moduleInitIOContext(io,mt,rdb,NULL,-1);
    io.bytes += retval;

    
    retval = rdbSaveLen(rdb,mt->id);
    if (retval == -1) return -1;
    io.bytes += retval;

    
    retval = rdbSaveLen(rdb,RDB_MODULE_OPCODE_UINT);
    if (retval == -1) return -1;
    io.bytes += retval;
    retval = rdbSaveLen(rdb,when);
    if (retval == -1) return -1;
    io.bytes += retval;

    
    mt->aux_save(&io,when);
    retval = rdbSaveLen(rdb,RDB_MODULE_OPCODE_EOF);
    if (retval == -1)
        io.error = 1;
    else io.bytes += retval;

    if (io.ctx) {
        moduleFreeContext(io.ctx);
        zfree(io.ctx);
    }
    if (io.error)
        return -1;
    return io.bytes;
}


int rdbSaveRio(rio *rdb, int *error, int rdbflags, rdbSaveInfo *rsi) {
    dictIterator *di = NULL;
    dictEntry *de;
    char magic[10];
    uint64_t cksum;
    size_t processed = 0;
    int j;
    long key_count = 0;
    long long info_updated_time = 0;
    char *pname = (rdbflags & RDBFLAGS_AOF_PREAMBLE) ? "AOF rewrite" :  "RDB";

    if (server.rdb_checksum)
        rdb->update_cksum = rioGenericUpdateChecksum;
    snprintf(magic,sizeof(magic),"REDIS%04d",RDB_VERSION);
    if (rdbWriteRaw(rdb,magic,9) == -1) goto werr;
    if (rdbSaveInfoAuxFields(rdb,rdbflags,rsi) == -1) goto werr;
    if (rdbSaveModulesAux(rdb, REDISMODULE_AUX_BEFORE_RDB) == -1) goto werr;

    for (j = 0; j < server.dbnum; j++) {
        redisDb *db = server.db+j;
        dict *d = db->dict;
        if (dictSize(d) == 0) continue;
        di = dictGetSafeIterator(d);

        
        if (rdbSaveType(rdb,RDB_OPCODE_SELECTDB) == -1) goto werr;
        if (rdbSaveLen(rdb,j) == -1) goto werr;

        
        uint64_t db_size, expires_size;
        db_size = dictSize(db->dict);
        expires_size = dictSize(db->expires);
        if (rdbSaveType(rdb,RDB_OPCODE_RESIZEDB) == -1) goto werr;
        if (rdbSaveLen(rdb,db_size) == -1) goto werr;
        if (rdbSaveLen(rdb,expires_size) == -1) goto werr;

        
        while((de = dictNext(di)) != NULL) {
            sds keystr = dictGetKey(de);
            robj key, *o = dictGetVal(de);
            long long expire;
            size_t rdb_bytes_before_key = rdb->processed_bytes;

            initStaticStringObject(key,keystr);
            expire = getExpire(db,&key);
            if (rdbSaveKeyValuePair(rdb,&key,o,expire,j) == -1) goto werr;

            
            size_t dump_size = rdb->processed_bytes - rdb_bytes_before_key;
            if (server.in_fork_child) dismissObject(o, dump_size);

            
            if (rdbflags & RDBFLAGS_AOF_PREAMBLE && rdb->processed_bytes > processed+AOF_READ_DIFF_INTERVAL_BYTES)
            {
                processed = rdb->processed_bytes;
                aofReadDiffFromParent();
            }

            
            if ((key_count++ & 1023) == 0) {
                long long now = mstime();
                if (now - info_updated_time >= 1000) {
                    sendChildInfo(CHILD_INFO_TYPE_CURRENT_INFO, key_count, pname);
                    info_updated_time = now;
                }
            }
        }
        dictReleaseIterator(di);
        di = NULL; 
    }

    
    if (rsi && dictSize(server.lua_scripts)) {
        di = dictGetIterator(server.lua_scripts);
        while((de = dictNext(di)) != NULL) {
            robj *body = dictGetVal(de);
            if (rdbSaveAuxField(rdb,"lua",3,body->ptr,sdslen(body->ptr)) == -1)
                goto werr;
        }
        dictReleaseIterator(di);
        di = NULL; 
    }

    if (rdbSaveModulesAux(rdb, REDISMODULE_AUX_AFTER_RDB) == -1) goto werr;

    
    if (rdbSaveType(rdb,RDB_OPCODE_EOF) == -1) goto werr;

    
    cksum = rdb->cksum;
    memrev64ifbe(&cksum);
    if (rioWrite(rdb,&cksum,8) == 0) goto werr;
    return C_OK;

werr:
    if (error) *error = errno;
    if (di) dictReleaseIterator(di);
    return C_ERR;
}


int rdbSaveRioWithEOFMark(rio *rdb, int *error, rdbSaveInfo *rsi) {
    char eofmark[RDB_EOF_MARK_SIZE];

    startSaving(RDBFLAGS_REPLICATION);
    getRandomHexChars(eofmark,RDB_EOF_MARK_SIZE);
    if (error) *error = 0;
    if (rioWrite(rdb,"$EOF:",5) == 0) goto werr;
    if (rioWrite(rdb,eofmark,RDB_EOF_MARK_SIZE) == 0) goto werr;
    if (rioWrite(rdb,"\r\n",2) == 0) goto werr;
    if (rdbSaveRio(rdb,error,RDBFLAGS_NONE,rsi) == C_ERR) goto werr;
    if (rioWrite(rdb,eofmark,RDB_EOF_MARK_SIZE) == 0) goto werr;
    stopSaving(1);
    return C_OK;

werr: 
    
    if (error && *error == 0) *error = errno;
    stopSaving(0);
    return C_ERR;
}


int rdbSave(char *filename, rdbSaveInfo *rsi) {
    char tmpfile[256];
    char cwd[MAXPATHLEN]; 
    FILE *fp = NULL;
    rio rdb;
    int error = 0;

    snprintf(tmpfile,256,"temp-%d.rdb", (int) getpid());
    fp = fopen(tmpfile,"w");
    if (!fp) {
        char *cwdp = getcwd(cwd,MAXPATHLEN);
        serverLog(LL_WARNING, "Failed opening the RDB file %s (in server root dir %s) " "for saving: %s", filename, cwdp ? cwdp : "unknown", strerror(errno));




        return C_ERR;
    }

    rioInitWithFile(&rdb,fp);
    startSaving(RDBFLAGS_NONE);

    if (server.rdb_save_incremental_fsync)
        rioSetAutoSync(&rdb,REDIS_AUTOSYNC_BYTES);

    if (rdbSaveRio(&rdb,&error,RDBFLAGS_NONE,rsi) == C_ERR) {
        errno = error;
        goto werr;
    }

    
    if (fflush(fp)) goto werr;
    if (fsync(fileno(fp))) goto werr;
    if (fclose(fp)) { fp = NULL; goto werr; }
    fp = NULL;
    
    
    if (rename(tmpfile,filename) == -1) {
        char *cwdp = getcwd(cwd,MAXPATHLEN);
        serverLog(LL_WARNING, "Error moving temp DB file %s on the final " "destination %s (in server root dir %s): %s", tmpfile, filename, cwdp ? cwdp : "unknown", strerror(errno));





        unlink(tmpfile);
        stopSaving(0);
        return C_ERR;
    }

    serverLog(LL_NOTICE,"DB saved on disk");
    server.dirty = 0;
    server.lastsave = time(NULL);
    server.lastbgsave_status = C_OK;
    stopSaving(1);
    return C_OK;

werr:
    serverLog(LL_WARNING,"Write error saving DB on disk: %s", strerror(errno));
    if (fp) fclose(fp);
    unlink(tmpfile);
    stopSaving(0);
    return C_ERR;
}

int rdbSaveBackground(char *filename, rdbSaveInfo *rsi) {
    pid_t childpid;

    if (hasActiveChildProcess()) return C_ERR;

    server.dirty_before_bgsave = server.dirty;
    server.lastbgsave_try = time(NULL);

    if ((childpid = redisFork(CHILD_TYPE_RDB)) == 0) {
        int retval;

        
        redisSetProcTitle("redis-rdb-bgsave");
        redisSetCpuAffinity(server.bgsave_cpulist);
        retval = rdbSave(filename,rsi);
        if (retval == C_OK) {
            sendChildCowInfo(CHILD_INFO_TYPE_RDB_COW_SIZE, "RDB");
        }
        exitFromChild((retval == C_OK) ? 0 : 1);
    } else {
        
        if (childpid == -1) {
            server.lastbgsave_status = C_ERR;
            serverLog(LL_WARNING,"Can't save in background: fork: %s", strerror(errno));
            return C_ERR;
        }
        serverLog(LL_NOTICE,"Background saving started by pid %ld",(long) childpid);
        server.rdb_save_time_start = time(NULL);
        server.rdb_child_type = RDB_CHILD_TYPE_DISK;
        return C_OK;
    }
    return C_OK; 
}


void rdbRemoveTempFile(pid_t childpid, int from_signal) {
    char tmpfile[256];
    char pid[32];

    
    int pid_len = ll2string(pid, sizeof(pid), childpid);
    strcpy(tmpfile, "temp-");
    strncpy(tmpfile+5, pid, pid_len);
    strcpy(tmpfile+5+pid_len, ".rdb");

    if (from_signal) {
        
        int fd = open(tmpfile, O_RDONLY|O_NONBLOCK);
        UNUSED(fd);
        unlink(tmpfile);
    } else {
        bg_unlink(tmpfile);
    }
}


robj *rdbLoadCheckModuleValue(rio *rdb, char *modulename) {
    uint64_t opcode;
    while((opcode = rdbLoadLen(rdb,NULL)) != RDB_MODULE_OPCODE_EOF) {
        if (opcode == RDB_MODULE_OPCODE_SINT || opcode == RDB_MODULE_OPCODE_UINT)
        {
            uint64_t len;
            if (rdbLoadLenByRef(rdb,NULL,&len) == -1) {
                rdbReportCorruptRDB( "Error reading integer from module %s value", modulename);
            }
        } else if (opcode == RDB_MODULE_OPCODE_STRING) {
            robj *o = rdbGenericLoadStringObject(rdb,RDB_LOAD_NONE,NULL);
            if (o == NULL) {
                rdbReportCorruptRDB( "Error reading string from module %s value", modulename);
            }
            decrRefCount(o);
        } else if (opcode == RDB_MODULE_OPCODE_FLOAT) {
            float val;
            if (rdbLoadBinaryFloatValue(rdb,&val) == -1) {
                rdbReportCorruptRDB( "Error reading float from module %s value", modulename);
            }
        } else if (opcode == RDB_MODULE_OPCODE_DOUBLE) {
            double val;
            if (rdbLoadBinaryDoubleValue(rdb,&val) == -1) {
                rdbReportCorruptRDB( "Error reading double from module %s value", modulename);
            }
        }
    }
    return createStringObject("module-dummy-value",18);
}


static int _ziplistPairsEntryConvertAndValidate(unsigned char *p, unsigned int head_count, void *userdata) {
    unsigned char *str;
    unsigned int slen;
    long long vll;

    struct {
        long count;
        dict *fields;
        unsigned char **lp;
    } *data = userdata;

    if (data->fields == NULL) {
        data->fields = dictCreate(&hashDictType);
        dictExpand(data->fields, head_count/2);
    }

    if (!ziplistGet(p, &str, &slen, &vll))
        return 0;

    
    if (((data->count) & 1) == 0) {
        sds field = str? sdsnewlen(str, slen): sdsfromlonglong(vll);
        if (dictAdd(data->fields, field, NULL) != DICT_OK) {
            
            sdsfree(field);
            return 0;
        }
    }

    if (str) {
        *(data->lp) = lpAppend(*(data->lp), (unsigned char*)str, slen);
    } else {
        *(data->lp) = lpAppendInteger(*(data->lp), vll);
    }

    (data->count)++;
    return 1;
}


int ziplistPairsConvertAndValidateIntegrity(unsigned char *zl, size_t size, unsigned char **lp) {
    
    struct {
        long count;
        dict *fields; 
        unsigned char **lp;
    } data = {0, NULL, lp};

    int ret = ziplistValidateIntegrity(zl, size, 1, _ziplistPairsEntryConvertAndValidate, &data);

    
    if (data.count & 1)
        ret = 0;

    if (data.fields) dictRelease(data.fields);
    return ret;
}


static int _lpPairsEntryValidation(unsigned char *p, unsigned int head_count, void *userdata) {
    struct {
        long count;
        dict *fields;
    } *data = userdata;

    if (data->fields == NULL) {
        data->fields = dictCreate(&hashDictType);
        dictExpand(data->fields, head_count/2);
    }

    
    if (((data->count) & 1) == 0) {
        unsigned char *str;
        int64_t slen;
        unsigned char buf[LP_INTBUF_SIZE];

        str = lpGet(p, &slen, buf);
        sds field = sdsnewlen(str, slen);
        if (dictAdd(data->fields, field, NULL) != DICT_OK) {
            
            sdsfree(field);
            return 0;
        }
    }

    (data->count)++;
    return 1;
}


int lpPairsValidateIntegrityAndDups(unsigned char *lp, size_t size, int deep) {
    if (!deep)
        return lpValidateIntegrity(lp, size, 0, NULL, NULL);

    
    struct {
        long count;
        dict *fields; 
    } data = {0, NULL};

    int ret = lpValidateIntegrity(lp, size, 1, _lpPairsEntryValidation, &data);

    
    if (data.count & 1)
        ret = 0;

    if (data.fields) dictRelease(data.fields);
    return ret;
}


robj *rdbLoadObject(int rdbtype, rio *rdb, sds key, int dbid, int *error) {
    robj *o = NULL, *ele, *dec;
    uint64_t len;
    unsigned int i;

    
    if (error) *error = RDB_LOAD_ERR_OTHER;

    int deep_integrity_validation = server.sanitize_dump_payload == SANITIZE_DUMP_YES;
    if (server.sanitize_dump_payload == SANITIZE_DUMP_CLIENTS) {
        
        int skip = server.loading || (server.current_client && (server.current_client->flags & CLIENT_MASTER));
        if (!skip && server.current_client && server.current_client->user)
            skip = !!(server.current_client->user->flags & USER_FLAG_SANITIZE_PAYLOAD_SKIP);
        deep_integrity_validation = !skip;
    }

    if (rdbtype == RDB_TYPE_STRING) {
        
        if ((o = rdbLoadEncodedStringObject(rdb)) == NULL) return NULL;
        o = tryObjectEncoding(o);
    } else if (rdbtype == RDB_TYPE_LIST) {
        
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return NULL;
        if (len == 0) goto emptykey;

        o = createQuicklistObject();
        quicklistSetOptions(o->ptr, server.list_max_ziplist_size, server.list_compress_depth);

        
        while(len--) {
            if ((ele = rdbLoadEncodedStringObject(rdb)) == NULL) {
                decrRefCount(o);
                return NULL;
            }
            dec = getDecodedObject(ele);
            size_t len = sdslen(dec->ptr);
            quicklistPushTail(o->ptr, dec->ptr, len);
            decrRefCount(dec);
            decrRefCount(ele);
        }
    } else if (rdbtype == RDB_TYPE_SET) {
        
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return NULL;
        if (len == 0) goto emptykey;

        
        if (len > server.set_max_intset_entries) {
            o = createSetObject();
            
            if (len > DICT_HT_INITIAL_SIZE && dictTryExpand(o->ptr,len) != DICT_OK) {
                rdbReportCorruptRDB("OOM in dictTryExpand %llu", (unsigned long long)len);
                decrRefCount(o);
                return NULL;
            }
        } else {
            o = createIntsetObject();
        }

        
        for (i = 0; i < len; i++) {
            long long llval;
            sds sdsele;

            if ((sdsele = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL)) == NULL) {
                decrRefCount(o);
                return NULL;
            }

            if (o->encoding == OBJ_ENCODING_INTSET) {
                
                if (isSdsRepresentableAsLongLong(sdsele,&llval) == C_OK) {
                    uint8_t success;
                    o->ptr = intsetAdd(o->ptr,llval,&success);
                    if (!success) {
                        rdbReportCorruptRDB("Duplicate set members detected");
                        decrRefCount(o);
                        sdsfree(sdsele);
                        return NULL;
                    }
                } else {
                    setTypeConvert(o,OBJ_ENCODING_HT);
                    if (dictTryExpand(o->ptr,len) != DICT_OK) {
                        rdbReportCorruptRDB("OOM in dictTryExpand %llu", (unsigned long long)len);
                        sdsfree(sdsele);
                        decrRefCount(o);
                        return NULL;
                    }
                }
            }

            
            if (o->encoding == OBJ_ENCODING_HT) {
                if (dictAdd((dict*)o->ptr,sdsele,NULL) != DICT_OK) {
                    rdbReportCorruptRDB("Duplicate set members detected");
                    decrRefCount(o);
                    sdsfree(sdsele);
                    return NULL;
                }
            } else {
                sdsfree(sdsele);
            }
        }
    } else if (rdbtype == RDB_TYPE_ZSET_2 || rdbtype == RDB_TYPE_ZSET) {
        
        uint64_t zsetlen;
        size_t maxelelen = 0;
        zset *zs;

        if ((zsetlen = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return NULL;
        if (zsetlen == 0) goto emptykey;

        o = createZsetObject();
        zs = o->ptr;

        if (zsetlen > DICT_HT_INITIAL_SIZE && dictTryExpand(zs->dict,zsetlen) != DICT_OK) {
            rdbReportCorruptRDB("OOM in dictTryExpand %llu", (unsigned long long)zsetlen);
            decrRefCount(o);
            return NULL;
        }

        
        while(zsetlen--) {
            sds sdsele;
            double score;
            zskiplistNode *znode;

            if ((sdsele = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL)) == NULL) {
                decrRefCount(o);
                return NULL;
            }

            if (rdbtype == RDB_TYPE_ZSET_2) {
                if (rdbLoadBinaryDoubleValue(rdb,&score) == -1) {
                    decrRefCount(o);
                    sdsfree(sdsele);
                    return NULL;
                }
            } else {
                if (rdbLoadDoubleValue(rdb,&score) == -1) {
                    decrRefCount(o);
                    sdsfree(sdsele);
                    return NULL;
                }
            }

            
            if (sdslen(sdsele) > maxelelen) maxelelen = sdslen(sdsele);

            znode = zslInsert(zs->zsl,score,sdsele);
            if (dictAdd(zs->dict,sdsele,&znode->score) != DICT_OK) {
                rdbReportCorruptRDB("Duplicate zset fields detected");
                decrRefCount(o);
                
                return NULL;
            }
        }

        
        if (zsetLength(o) <= server.zset_max_listpack_entries && maxelelen <= server.zset_max_listpack_value)
                zsetConvert(o,OBJ_ENCODING_LISTPACK);
    } else if (rdbtype == RDB_TYPE_HASH) {
        uint64_t len;
        int ret;
        sds field, value;
        dict *dupSearchDict = NULL;

        len = rdbLoadLen(rdb, NULL);
        if (len == RDB_LENERR) return NULL;
        if (len == 0) goto emptykey;

        o = createHashObject();

        
        if (len > server.hash_max_listpack_entries)
            hashTypeConvert(o, OBJ_ENCODING_HT);
        else if (deep_integrity_validation) {
            
            dupSearchDict = dictCreate(&hashDictType);
        }


        
        while (o->encoding == OBJ_ENCODING_LISTPACK && len > 0) {
            len--;
            
            if ((field = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL)) == NULL) {
                decrRefCount(o);
                if (dupSearchDict) dictRelease(dupSearchDict);
                return NULL;
            }
            if ((value = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL)) == NULL) {
                sdsfree(field);
                decrRefCount(o);
                if (dupSearchDict) dictRelease(dupSearchDict);
                return NULL;
            }

            if (dupSearchDict) {
                sds field_dup = sdsdup(field);
                if (dictAdd(dupSearchDict, field_dup, NULL) != DICT_OK) {
                    rdbReportCorruptRDB("Hash with dup elements");
                    dictRelease(dupSearchDict);
                    decrRefCount(o);
                    sdsfree(field_dup);
                    sdsfree(field);
                    sdsfree(value);
                    return NULL;
                }
            }

            
            o->ptr = lpAppend(o->ptr, (unsigned char*)field, sdslen(field));
            o->ptr = lpAppend(o->ptr, (unsigned char*)value, sdslen(value));

            
            if (sdslen(field) > server.hash_max_listpack_value || sdslen(value) > server.hash_max_listpack_value)
            {
                sdsfree(field);
                sdsfree(value);
                hashTypeConvert(o, OBJ_ENCODING_HT);
                break;
            }
            sdsfree(field);
            sdsfree(value);
        }

        if (dupSearchDict) {
            
            dictRelease(dupSearchDict);
            dupSearchDict = NULL;
        }

        if (o->encoding == OBJ_ENCODING_HT && len > DICT_HT_INITIAL_SIZE) {
            if (dictTryExpand(o->ptr,len) != DICT_OK) {
                rdbReportCorruptRDB("OOM in dictTryExpand %llu", (unsigned long long)len);
                decrRefCount(o);
                return NULL;
            }
        }

        
        while (o->encoding == OBJ_ENCODING_HT && len > 0) {
            len--;
            
            if ((field = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL)) == NULL) {
                decrRefCount(o);
                return NULL;
            }
            if ((value = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL)) == NULL) {
                sdsfree(field);
                decrRefCount(o);
                return NULL;
            }

            
            ret = dictAdd((dict*)o->ptr, field, value);
            if (ret == DICT_ERR) {
                rdbReportCorruptRDB("Duplicate hash fields detected");
                sdsfree(value);
                sdsfree(field);
                decrRefCount(o);
                return NULL;
            }
        }

        
        serverAssert(len == 0);
    } else if (rdbtype == RDB_TYPE_LIST_QUICKLIST) {
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return NULL;
        if (len == 0) goto emptykey;

        o = createQuicklistObject();
        quicklistSetOptions(o->ptr, server.list_max_ziplist_size, server.list_compress_depth);

        while (len--) {
            size_t encoded_len;
            unsigned char *zl = rdbGenericLoadStringObject(rdb,RDB_LOAD_PLAIN,&encoded_len);
            if (zl == NULL) {
                decrRefCount(o);
                return NULL;
            }
            if (deep_integrity_validation) server.stat_dump_payload_sanitizations++;
            if (!ziplistValidateIntegrity(zl, encoded_len, deep_integrity_validation, NULL, NULL)) {
                rdbReportCorruptRDB("Ziplist integrity check failed.");
                decrRefCount(o);
                zfree(zl);
                return NULL;
            }

            
            if (ziplistLen(zl) == 0) {
                zfree(zl);
                continue;
            } else {
                quicklistAppendZiplist(o->ptr, zl);
            }
        }

        if (quicklistCount(o->ptr) == 0) {
            decrRefCount(o);
            goto emptykey;
        }
    } else if (rdbtype == RDB_TYPE_HASH_ZIPMAP  || rdbtype == RDB_TYPE_LIST_ZIPLIST || rdbtype == RDB_TYPE_SET_INTSET   || rdbtype == RDB_TYPE_ZSET_ZIPLIST || rdbtype == RDB_TYPE_ZSET_LISTPACK || rdbtype == RDB_TYPE_HASH_ZIPLIST || rdbtype == RDB_TYPE_HASH_LISTPACK)





    {
        size_t encoded_len;
        unsigned char *encoded = rdbGenericLoadStringObject(rdb,RDB_LOAD_PLAIN,&encoded_len);
        if (encoded == NULL) return NULL;

        o = createObject(OBJ_STRING,encoded); 

        
        switch(rdbtype) {
            case RDB_TYPE_HASH_ZIPMAP:
                
                if (!zipmapValidateIntegrity(encoded, encoded_len, 1)) {
                    rdbReportCorruptRDB("Zipmap integrity check failed.");
                    zfree(encoded);
                    o->ptr = NULL;
                    decrRefCount(o);
                    return NULL;
                }
                
                {
                    unsigned char *zl = lpNew(0);
                    unsigned char *zi = zipmapRewind(o->ptr);
                    unsigned char *fstr, *vstr;
                    unsigned int flen, vlen;
                    unsigned int maxlen = 0;
                    dict *dupSearchDict = dictCreate(&hashDictType);

                    while ((zi = zipmapNext(zi, &fstr, &flen, &vstr, &vlen)) != NULL) {
                        if (flen > maxlen) maxlen = flen;
                        if (vlen > maxlen) maxlen = vlen;
                        zl = lpAppend(zl, fstr, flen);
                        zl = lpAppend(zl, vstr, vlen);

                        
                        sds field = sdstrynewlen(fstr, flen);
                        if (!field || dictAdd(dupSearchDict, field, NULL) != DICT_OK) {
                            rdbReportCorruptRDB("Hash zipmap with dup elements, or big length (%u)", flen);
                            dictRelease(dupSearchDict);
                            sdsfree(field);
                            zfree(encoded);
                            o->ptr = NULL;
                            decrRefCount(o);
                            return NULL;
                        }
                    }

                    dictRelease(dupSearchDict);
                    zfree(o->ptr);
                    o->ptr = zl;
                    o->type = OBJ_HASH;
                    o->encoding = OBJ_ENCODING_LISTPACK;

                    if (hashTypeLength(o) > server.hash_max_listpack_entries || maxlen > server.hash_max_listpack_value)
                    {
                        hashTypeConvert(o, OBJ_ENCODING_HT);
                    }
                }
                break;
            case RDB_TYPE_LIST_ZIPLIST:
                if (deep_integrity_validation) server.stat_dump_payload_sanitizations++;
                if (!ziplistValidateIntegrity(encoded, encoded_len, deep_integrity_validation, NULL, NULL)) {
                    rdbReportCorruptRDB("List ziplist integrity check failed.");
                    zfree(encoded);
                    o->ptr = NULL;
                    decrRefCount(o);
                    return NULL;
                }

                if (ziplistLen(encoded) == 0) {
                    zfree(encoded);
                    o->ptr = NULL;
                    decrRefCount(o);
                    goto emptykey;
                }

                o->type = OBJ_LIST;
                o->encoding = OBJ_ENCODING_ZIPLIST;
                listTypeConvert(o,OBJ_ENCODING_QUICKLIST);
                break;
            case RDB_TYPE_SET_INTSET:
                if (deep_integrity_validation) server.stat_dump_payload_sanitizations++;
                if (!intsetValidateIntegrity(encoded, encoded_len, deep_integrity_validation)) {
                    rdbReportCorruptRDB("Intset integrity check failed.");
                    zfree(encoded);
                    o->ptr = NULL;
                    decrRefCount(o);
                    return NULL;
                }
                o->type = OBJ_SET;
                o->encoding = OBJ_ENCODING_INTSET;
                if (intsetLen(o->ptr) > server.set_max_intset_entries)
                    setTypeConvert(o,OBJ_ENCODING_HT);
                break;
            case RDB_TYPE_ZSET_ZIPLIST:
                {
                    unsigned char *lp = lpNew(encoded_len);
                    if (!ziplistPairsConvertAndValidateIntegrity(encoded, encoded_len, &lp)) {
                        rdbReportCorruptRDB("Zset ziplist integrity check failed.");
                        zfree(lp);
                        zfree(encoded);
                        o->ptr = NULL;
                        decrRefCount(o);
                        return NULL;
                    }

                    zfree(o->ptr);
                    o->type = OBJ_ZSET;
                    o->ptr = lp;
                    o->encoding = OBJ_ENCODING_LISTPACK;
                    if (zsetLength(o) == 0) {
                        decrRefCount(o);
                        goto emptykey;
                    }

                    if (zsetLength(o) > server.zset_max_listpack_entries)
                        zsetConvert(o,OBJ_ENCODING_SKIPLIST);
                    break;
                }
            case RDB_TYPE_ZSET_LISTPACK:
                if (deep_integrity_validation) server.stat_dump_payload_sanitizations++;
                if (!lpPairsValidateIntegrityAndDups(encoded, encoded_len, deep_integrity_validation)) {
                    rdbReportCorruptRDB("Zset listpack integrity check failed.");
                    zfree(encoded);
                    o->ptr = NULL;
                    decrRefCount(o);
                    return NULL;
                }
                o->type = OBJ_ZSET;
                o->encoding = OBJ_ENCODING_LISTPACK;
                if (zsetLength(o) == 0) {
                    decrRefCount(o);
                    goto emptykey;
                }

                if (zsetLength(o) > server.zset_max_listpack_entries)
                    zsetConvert(o,OBJ_ENCODING_SKIPLIST);
                break;
            case RDB_TYPE_HASH_ZIPLIST:
                {
                    unsigned char *lp = lpNew(encoded_len);
                    if (!ziplistPairsConvertAndValidateIntegrity(encoded, encoded_len, &lp)) {
                        rdbReportCorruptRDB("Hash ziplist integrity check failed.");
                        zfree(lp);
                        zfree(encoded);
                        o->ptr = NULL;
                        decrRefCount(o);
                        return NULL;
                    }

                    zfree(o->ptr);
                    o->ptr = lp;
                    o->type = OBJ_HASH;
                    o->encoding = OBJ_ENCODING_LISTPACK;
                    if (hashTypeLength(o) == 0) {
                        decrRefCount(o);
                        goto emptykey;
                    }

                    if (hashTypeLength(o) > server.hash_max_listpack_entries) {
                        hashTypeConvert(o, OBJ_ENCODING_HT);
                    } 
                    break;
                }
            case RDB_TYPE_HASH_LISTPACK:
                if (deep_integrity_validation) server.stat_dump_payload_sanitizations++;
                if (!lpPairsValidateIntegrityAndDups(encoded, encoded_len, deep_integrity_validation)) {
                    rdbReportCorruptRDB("Hash listpack integrity check failed.");
                    zfree(encoded);
                    o->ptr = NULL;
                    decrRefCount(o);
                    return NULL;
                }
                o->type = OBJ_HASH;
                o->encoding = OBJ_ENCODING_LISTPACK;
                if (hashTypeLength(o) == 0) {
                    decrRefCount(o);
                    goto emptykey;
                }

                if (hashTypeLength(o) > server.hash_max_listpack_entries)
                    hashTypeConvert(o, OBJ_ENCODING_HT);
                break;
            default:
                
                rdbReportCorruptRDB("Unknown RDB encoding type %d",rdbtype);
                break;
        }
    } else if (rdbtype == RDB_TYPE_STREAM_LISTPACKS) {
        o = createStreamObject();
        stream *s = o->ptr;
        uint64_t listpacks = rdbLoadLen(rdb,NULL);
        if (listpacks == RDB_LENERR) {
            rdbReportReadError("Stream listpacks len loading failed.");
            decrRefCount(o);
            return NULL;
        }

        while(listpacks--) {
            
            sds nodekey = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL);
            if (nodekey == NULL) {
                rdbReportReadError("Stream master ID loading failed: invalid encoding or I/O error.");
                decrRefCount(o);
                return NULL;
            }
            if (sdslen(nodekey) != sizeof(streamID)) {
                rdbReportCorruptRDB("Stream node key entry is not the " "size of a stream ID");
                sdsfree(nodekey);
                decrRefCount(o);
                return NULL;
            }

            
            size_t lp_size;
            unsigned char *lp = rdbGenericLoadStringObject(rdb,RDB_LOAD_PLAIN,&lp_size);
            if (lp == NULL) {
                rdbReportReadError("Stream listpacks loading failed.");
                sdsfree(nodekey);
                decrRefCount(o);
                return NULL;
            }
            if (deep_integrity_validation) server.stat_dump_payload_sanitizations++;
            if (!streamValidateListpackIntegrity(lp, lp_size, deep_integrity_validation)) {
                rdbReportCorruptRDB("Stream listpack integrity check failed.");
                sdsfree(nodekey);
                decrRefCount(o);
                zfree(lp);
                return NULL;
            }

            unsigned char *first = lpFirst(lp);
            if (first == NULL) {
                
                rdbReportCorruptRDB("Empty listpack inside stream");
                sdsfree(nodekey);
                decrRefCount(o);
                zfree(lp);
                return NULL;
            }

            
            int retval = raxTryInsert(s->rax, (unsigned char*)nodekey,sizeof(streamID),lp,NULL);
            sdsfree(nodekey);
            if (!retval) {
                rdbReportCorruptRDB("Listpack re-added with existing key");
                decrRefCount(o);
                zfree(lp);
                return NULL;
            }
        }
        
        s->length = rdbLoadLen(rdb,NULL);

        
        s->last_id.ms = rdbLoadLen(rdb,NULL);
        s->last_id.seq = rdbLoadLen(rdb,NULL);

        if (rioGetReadError(rdb)) {
            rdbReportReadError("Stream object metadata loading failed.");
            decrRefCount(o);
            return NULL;
        }

        
        uint64_t cgroups_count = rdbLoadLen(rdb,NULL);
        if (cgroups_count == RDB_LENERR) {
            rdbReportReadError("Stream cgroup count loading failed.");
            decrRefCount(o);
            return NULL;
        }
        while(cgroups_count--) {
            
            streamID cg_id;
            sds cgname = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL);
            if (cgname == NULL) {
                rdbReportReadError( "Error reading the consumer group name from Stream");
                decrRefCount(o);
                return NULL;
            }

            cg_id.ms = rdbLoadLen(rdb,NULL);
            cg_id.seq = rdbLoadLen(rdb,NULL);
            if (rioGetReadError(rdb)) {
                rdbReportReadError("Stream cgroup ID loading failed.");
                sdsfree(cgname);
                decrRefCount(o);
                return NULL;
            }

            streamCG *cgroup = streamCreateCG(s,cgname,sdslen(cgname),&cg_id);
            if (cgroup == NULL) {
                rdbReportCorruptRDB("Duplicated consumer group name %s", cgname);
                decrRefCount(o);
                sdsfree(cgname);
                return NULL;
            }
            sdsfree(cgname);

            
            uint64_t pel_size = rdbLoadLen(rdb,NULL);
            if (pel_size == RDB_LENERR) {
                rdbReportReadError("Stream PEL size loading failed.");
                decrRefCount(o);
                return NULL;
            }
            while(pel_size--) {
                unsigned char rawid[sizeof(streamID)];
                if (rioRead(rdb,rawid,sizeof(rawid)) == 0) {
                    rdbReportReadError("Stream PEL ID loading failed.");
                    decrRefCount(o);
                    return NULL;
                }
                streamNACK *nack = streamCreateNACK(NULL);
                nack->delivery_time = rdbLoadMillisecondTime(rdb,RDB_VERSION);
                nack->delivery_count = rdbLoadLen(rdb,NULL);
                if (rioGetReadError(rdb)) {
                    rdbReportReadError("Stream PEL NACK loading failed.");
                    decrRefCount(o);
                    streamFreeNACK(nack);
                    return NULL;
                }
                if (!raxTryInsert(cgroup->pel,rawid,sizeof(rawid),nack,NULL)) {
                    rdbReportCorruptRDB("Duplicated global PEL entry " "loading stream consumer group");
                    decrRefCount(o);
                    streamFreeNACK(nack);
                    return NULL;
                }
            }

            
            uint64_t consumers_num = rdbLoadLen(rdb,NULL);
            if (consumers_num == RDB_LENERR) {
                rdbReportReadError("Stream consumers num loading failed.");
                decrRefCount(o);
                return NULL;
            }
            while(consumers_num--) {
                sds cname = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL);
                if (cname == NULL) {
                    rdbReportReadError( "Error reading the consumer name from Stream group.");
                    decrRefCount(o);
                    return NULL;
                }
                streamConsumer *consumer = streamCreateConsumer(cgroup,cname,NULL,0, SCC_NO_NOTIFY|SCC_NO_DIRTIFY);
                sdsfree(cname);
                consumer->seen_time = rdbLoadMillisecondTime(rdb,RDB_VERSION);
                if (rioGetReadError(rdb)) {
                    rdbReportReadError("Stream short read reading seen time.");
                    decrRefCount(o);
                    return NULL;
                }

                
                pel_size = rdbLoadLen(rdb,NULL);
                if (pel_size == RDB_LENERR) {
                    rdbReportReadError( "Stream consumer PEL num loading failed.");
                    decrRefCount(o);
                    return NULL;
                }
                while(pel_size--) {
                    unsigned char rawid[sizeof(streamID)];
                    if (rioRead(rdb,rawid,sizeof(rawid)) == 0) {
                        rdbReportReadError( "Stream short read reading PEL streamID.");
                        decrRefCount(o);
                        return NULL;
                    }
                    streamNACK *nack = raxFind(cgroup->pel,rawid,sizeof(rawid));
                    if (nack == raxNotFound) {
                        rdbReportCorruptRDB("Consumer entry not found in " "group global PEL");
                        decrRefCount(o);
                        return NULL;
                    }

                    
                    nack->consumer = consumer;
                    if (!raxTryInsert(consumer->pel,rawid,sizeof(rawid),nack,NULL)) {
                        rdbReportCorruptRDB("Duplicated consumer PEL entry " " loading a stream consumer " "group");

                        decrRefCount(o);
                        streamFreeNACK(nack);
                        return NULL;
                    }
                }
            }

            
            if (deep_integrity_validation) {
                raxIterator ri_cg_pel;
                raxStart(&ri_cg_pel,cgroup->pel);
                raxSeek(&ri_cg_pel,"^",NULL,0);
                while(raxNext(&ri_cg_pel)) {
                    streamNACK *nack = ri_cg_pel.data;
                    if (!nack->consumer) {
                        raxStop(&ri_cg_pel);
                        rdbReportCorruptRDB("Stream CG PEL entry without consumer");
                        decrRefCount(o);
                        return NULL;
                    }
                }
                raxStop(&ri_cg_pel);
            }
        }
    } else if (rdbtype == RDB_TYPE_MODULE || rdbtype == RDB_TYPE_MODULE_2) {
        uint64_t moduleid = rdbLoadLen(rdb,NULL);
        if (rioGetReadError(rdb)) {
            rdbReportReadError("Short read module id");
            return NULL;
        }
        moduleType *mt = moduleTypeLookupModuleByID(moduleid);

        if (rdbCheckMode && rdbtype == RDB_TYPE_MODULE_2) {
            char name[10];
            moduleTypeNameByID(name,moduleid);
            return rdbLoadCheckModuleValue(rdb,name);
        }

        if (mt == NULL) {
            char name[10];
            moduleTypeNameByID(name,moduleid);
            rdbReportCorruptRDB("The RDB file contains module data I can't load: no matching module type '%s'", name);
            return NULL;
        }
        RedisModuleIO io;
        robj keyobj;
        initStaticStringObject(keyobj,key);
        moduleInitIOContext(io,mt,rdb,&keyobj,dbid);
        io.ver = (rdbtype == RDB_TYPE_MODULE) ? 1 : 2;
        
        void *ptr = mt->rdb_load(&io,moduleid&1023);
        if (io.ctx) {
            moduleFreeContext(io.ctx);
            zfree(io.ctx);
        }

        
        if (io.ver == 2) {
            uint64_t eof = rdbLoadLen(rdb,NULL);
            if (eof == RDB_LENERR) {
                if (ptr) {
                    o = createModuleObject(mt,ptr); 
                    decrRefCount(o);
                }
                return NULL;
            }
            if (eof != RDB_MODULE_OPCODE_EOF) {
                rdbReportCorruptRDB("The RDB file contains module data for the module '%s' that is not terminated by " "the proper module value EOF marker", moduleTypeModuleName(mt));
                if (ptr) {
                    o = createModuleObject(mt,ptr); 
                    decrRefCount(o);
                }
                return NULL;
            }
        }

        if (ptr == NULL) {
            rdbReportCorruptRDB("The RDB file contains module data for the module type '%s', that the responsible " "module is not able to load. Check for modules log above for additional clues.", moduleTypeModuleName(mt));

            return NULL;
        }
        o = createModuleObject(mt,ptr);
    } else {
        rdbReportReadError("Unknown RDB encoding type %d",rdbtype);
        return NULL;
    }
    if (error) *error = 0;
    return o;

emptykey:
    if (error) *error = RDB_LOAD_ERR_EMPTY_KEY;
    return NULL;
}


void startLoading(size_t size, int rdbflags) {
    
    server.loading = 1;
    server.loading_start_time = time(NULL);
    server.loading_loaded_bytes = 0;
    server.loading_total_bytes = size;
    server.loading_rdb_used_mem = 0;
    server.rdb_last_load_keys_expired = 0;
    server.rdb_last_load_keys_loaded = 0;
    blockingOperationStarts();

    
    int subevent;
    if (rdbflags & RDBFLAGS_AOF_PREAMBLE)
        subevent = REDISMODULE_SUBEVENT_LOADING_AOF_START;
    else if(rdbflags & RDBFLAGS_REPLICATION)
        subevent = REDISMODULE_SUBEVENT_LOADING_REPL_START;
    else subevent = REDISMODULE_SUBEVENT_LOADING_RDB_START;
    moduleFireServerEvent(REDISMODULE_EVENT_LOADING,subevent,NULL);
}


void startLoadingFile(FILE *fp, char* filename, int rdbflags) {
    struct stat sb;
    if (fstat(fileno(fp), &sb) == -1)
        sb.st_size = 0;
    rdbFileBeingLoaded = filename;
    startLoading(sb.st_size, rdbflags);
}


void loadingProgress(off_t pos) {
    server.loading_loaded_bytes = pos;
    if (server.stat_peak_memory < zmalloc_used_memory())
        server.stat_peak_memory = zmalloc_used_memory();
}


void stopLoading(int success) {
    server.loading = 0;
    blockingOperationEnds();
    rdbFileBeingLoaded = NULL;

    
    moduleFireServerEvent(REDISMODULE_EVENT_LOADING, success? REDISMODULE_SUBEVENT_LOADING_ENDED:

                            REDISMODULE_SUBEVENT_LOADING_FAILED, NULL);
}

void startSaving(int rdbflags) {
    
    int subevent;
    if (rdbflags & RDBFLAGS_AOF_PREAMBLE)
        subevent = REDISMODULE_SUBEVENT_PERSISTENCE_AOF_START;
    else if (getpid()!=server.pid)
        subevent = REDISMODULE_SUBEVENT_PERSISTENCE_RDB_START;
    else subevent = REDISMODULE_SUBEVENT_PERSISTENCE_SYNC_RDB_START;
    moduleFireServerEvent(REDISMODULE_EVENT_PERSISTENCE,subevent,NULL);
}

void stopSaving(int success) {
    
    moduleFireServerEvent(REDISMODULE_EVENT_PERSISTENCE, success? REDISMODULE_SUBEVENT_PERSISTENCE_ENDED:

                            REDISMODULE_SUBEVENT_PERSISTENCE_FAILED, NULL);
}


void rdbLoadProgressCallback(rio *r, const void *buf, size_t len) {
    if (server.rdb_checksum)
        rioGenericUpdateChecksum(r, buf, len);
    if (server.loading_process_events_interval_bytes && (r->processed_bytes + len)/server.loading_process_events_interval_bytes > r->processed_bytes/server.loading_process_events_interval_bytes)
    {
        if (server.masterhost && server.repl_state == REPL_STATE_TRANSFER)
            replicationSendNewlineToMaster();
        loadingProgress(r->processed_bytes);
        processEventsWhileBlocked();
        processModuleLoadingProgressEvent(0);
    }
}


int rdbLoadRio(rio *rdb, int rdbflags, rdbSaveInfo *rsi) {
    uint64_t dbid = 0;
    int type, rdbver;
    redisDb *db = server.db+0;
    char buf[1024];
    int error;
    long long empty_keys_skipped = 0;

    rdb->update_cksum = rdbLoadProgressCallback;
    rdb->max_processing_chunk = server.loading_process_events_interval_bytes;
    if (rioRead(rdb,buf,9) == 0) goto eoferr;
    buf[9] = '\0';
    if (memcmp(buf,"REDIS",5) != 0) {
        serverLog(LL_WARNING,"Wrong signature trying to load DB from file");
        errno = EINVAL;
        return C_ERR;
    }
    rdbver = atoi(buf+5);
    if (rdbver < 1 || rdbver > RDB_VERSION) {
        serverLog(LL_WARNING,"Can't handle RDB format version %d",rdbver);
        errno = EINVAL;
        return C_ERR;
    }

    
    long long lru_idle = -1, lfu_freq = -1, expiretime = -1, now = mstime();
    long long lru_clock = LRU_CLOCK();

    while(1) {
        sds key;
        robj *val;

        
        if ((type = rdbLoadType(rdb)) == -1) goto eoferr;

        
        if (type == RDB_OPCODE_EXPIRETIME) {
            
            expiretime = rdbLoadTime(rdb);
            expiretime *= 1000;
            if (rioGetReadError(rdb)) goto eoferr;
            continue; 
        } else if (type == RDB_OPCODE_EXPIRETIME_MS) {
            
            expiretime = rdbLoadMillisecondTime(rdb,rdbver);
            if (rioGetReadError(rdb)) goto eoferr;
            continue; 
        } else if (type == RDB_OPCODE_FREQ) {
            
            uint8_t byte;
            if (rioRead(rdb,&byte,1) == 0) goto eoferr;
            lfu_freq = byte;
            continue; 
        } else if (type == RDB_OPCODE_IDLE) {
            
            uint64_t qword;
            if ((qword = rdbLoadLen(rdb,NULL)) == RDB_LENERR) goto eoferr;
            lru_idle = qword;
            continue; 
        } else if (type == RDB_OPCODE_EOF) {
            
            break;
        } else if (type == RDB_OPCODE_SELECTDB) {
            
            if ((dbid = rdbLoadLen(rdb,NULL)) == RDB_LENERR) goto eoferr;
            if (dbid >= (unsigned)server.dbnum) {
                serverLog(LL_WARNING, "FATAL: Data file was created with a Redis " "server configured to handle more than %d " "databases. Exiting\n", server.dbnum);


                exit(1);
            }
            db = server.db+dbid;
            continue; 
        } else if (type == RDB_OPCODE_RESIZEDB) {
            
            uint64_t db_size, expires_size;
            if ((db_size = rdbLoadLen(rdb,NULL)) == RDB_LENERR)
                goto eoferr;
            if ((expires_size = rdbLoadLen(rdb,NULL)) == RDB_LENERR)
                goto eoferr;
            dictExpand(db->dict,db_size);
            dictExpand(db->expires,expires_size);
            continue; 
        } else if (type == RDB_OPCODE_AUX) {
            
            robj *auxkey, *auxval;
            if ((auxkey = rdbLoadStringObject(rdb)) == NULL) goto eoferr;
            if ((auxval = rdbLoadStringObject(rdb)) == NULL) goto eoferr;

            if (((char*)auxkey->ptr)[0] == '%') {
                
                serverLog(LL_NOTICE,"RDB '%s': %s", (char*)auxkey->ptr, (char*)auxval->ptr);

            } else if (!strcasecmp(auxkey->ptr,"repl-stream-db")) {
                if (rsi) rsi->repl_stream_db = atoi(auxval->ptr);
            } else if (!strcasecmp(auxkey->ptr,"repl-id")) {
                if (rsi && sdslen(auxval->ptr) == CONFIG_RUN_ID_SIZE) {
                    memcpy(rsi->repl_id,auxval->ptr,CONFIG_RUN_ID_SIZE+1);
                    rsi->repl_id_is_set = 1;
                }
            } else if (!strcasecmp(auxkey->ptr,"repl-offset")) {
                if (rsi) rsi->repl_offset = strtoll(auxval->ptr,NULL,10);
            } else if (!strcasecmp(auxkey->ptr,"lua")) {
                
                if (luaCreateFunction(NULL,server.lua,auxval) == NULL) {
                    rdbReportCorruptRDB( "Can't load Lua script from RDB file! " "BODY: %s", (char*)auxval->ptr);

                }
            } else if (!strcasecmp(auxkey->ptr,"redis-ver")) {
                serverLog(LL_NOTICE,"Loading RDB produced by version %s", (char*)auxval->ptr);
            } else if (!strcasecmp(auxkey->ptr,"ctime")) {
                time_t age = time(NULL)-strtol(auxval->ptr,NULL,10);
                if (age < 0) age = 0;
                serverLog(LL_NOTICE,"RDB age %ld seconds", (unsigned long) age);
            } else if (!strcasecmp(auxkey->ptr,"used-mem")) {
                long long usedmem = strtoll(auxval->ptr,NULL,10);
                serverLog(LL_NOTICE,"RDB memory usage when created %.2f Mb", (double) usedmem / (1024*1024));
                server.loading_rdb_used_mem = usedmem;
            } else if (!strcasecmp(auxkey->ptr,"aof-preamble")) {
                long long haspreamble = strtoll(auxval->ptr,NULL,10);
                if (haspreamble) serverLog(LL_NOTICE,"RDB has an AOF tail");
            } else if (!strcasecmp(auxkey->ptr,"redis-bits")) {
                
            } else {
                
                serverLog(LL_DEBUG,"Unrecognized RDB AUX field: '%s'", (char*)auxkey->ptr);
            }

            decrRefCount(auxkey);
            decrRefCount(auxval);
            continue; 
        } else if (type == RDB_OPCODE_MODULE_AUX) {
            
            uint64_t moduleid = rdbLoadLen(rdb,NULL);
            int when_opcode = rdbLoadLen(rdb,NULL);
            int when = rdbLoadLen(rdb,NULL);
            if (rioGetReadError(rdb)) goto eoferr;
            if (when_opcode != RDB_MODULE_OPCODE_UINT) {
                rdbReportReadError("bad when_opcode");
                goto eoferr;
            }
            moduleType *mt = moduleTypeLookupModuleByID(moduleid);
            char name[10];
            moduleTypeNameByID(name,moduleid);

            if (!rdbCheckMode && mt == NULL) {
                
                serverLog(LL_WARNING,"The RDB file contains AUX module data I can't load: no matching module '%s'", name);
                exit(1);
            } else if (!rdbCheckMode && mt != NULL) {
                if (!mt->aux_load) {
                    
                    serverLog(LL_WARNING,"The RDB file contains module AUX data, but the module '%s' doesn't seem to support it.", name);
                    exit(1);
                }

                RedisModuleIO io;
                moduleInitIOContext(io,mt,rdb,NULL,-1);
                io.ver = 2;
                
                if (mt->aux_load(&io,moduleid&1023, when) != REDISMODULE_OK || io.error) {
                    moduleTypeNameByID(name,moduleid);
                    serverLog(LL_WARNING,"The RDB file contains module AUX data for the module type '%s', that the responsible module is not able to load. Check for modules log above for additional clues.", name);
                    goto eoferr;
                }
                if (io.ctx) {
                    moduleFreeContext(io.ctx);
                    zfree(io.ctx);
                }
                uint64_t eof = rdbLoadLen(rdb,NULL);
                if (eof != RDB_MODULE_OPCODE_EOF) {
                    serverLog(LL_WARNING,"The RDB file contains module AUX data for the module '%s' that is not terminated by the proper module value EOF marker", name);
                    goto eoferr;
                }
                continue;
            } else {
                
                robj *aux = rdbLoadCheckModuleValue(rdb,name);
                decrRefCount(aux);
                continue; 
            }
        }

        
        if ((key = rdbGenericLoadStringObject(rdb,RDB_LOAD_SDS,NULL)) == NULL)
            goto eoferr;
        
        val = rdbLoadObject(type,rdb,key,db->id,&error);

        
        if (val == NULL) {
            
            if (error == RDB_LOAD_ERR_EMPTY_KEY) {
                if(empty_keys_skipped++ < 10)
                    serverLog(LL_WARNING, "rdbLoadObject skipping empty key: %s", key);
                sdsfree(key);
            } else {
                sdsfree(key);
                goto eoferr;
            }
        } else if (iAmMaster() && !(rdbflags&RDBFLAGS_AOF_PREAMBLE) && expiretime != -1 && expiretime < now)

        {
            if (rdbflags & RDBFLAGS_FEED_REPL) {
                
                serverAssert(server.repl_backlog != NULL && listLength(server.slaves) == 0);
                robj keyobj;
                initStaticStringObject(keyobj,key);
                robj *argv[2];
                argv[0] = server.lazyfree_lazy_expire ? shared.unlink : shared.del;
                argv[1] = &keyobj;
                replicationFeedSlaves(server.slaves,dbid,argv,2);
            }
            sdsfree(key);
            decrRefCount(val);
            server.rdb_last_load_keys_expired++;
        } else {
            robj keyobj;
            initStaticStringObject(keyobj,key);

            
            int added = dbAddRDBLoad(db,key,val);
            server.rdb_last_load_keys_loaded++;
            if (!added) {
                if (rdbflags & RDBFLAGS_ALLOW_DUP) {
                    
                    dbSyncDelete(db,&keyobj);
                    dbAddRDBLoad(db,key,val);
                } else {
                    serverLog(LL_WARNING, "RDB has duplicated key '%s' in DB %d",key,db->id);
                    serverPanic("Duplicated key found in RDB file");
                }
            }

            
            if (expiretime != -1) {
                setExpire(NULL,db,&keyobj,expiretime);
            }

            
            objectSetLRUOrLFU(val,lfu_freq,lru_idle,lru_clock,1000);

            
            moduleNotifyKeyspaceEvent(NOTIFY_LOADED, "loaded", &keyobj, db->id);
        }

        
        if (server.key_load_delay)
            debugDelay(server.key_load_delay);

        
        expiretime = -1;
        lfu_freq = -1;
        lru_idle = -1;
    }
    
    if (rdbver >= 5) {
        uint64_t cksum, expected = rdb->cksum;

        if (rioRead(rdb,&cksum,8) == 0) goto eoferr;
        if (server.rdb_checksum && !server.skip_checksum_validation) {
            memrev64ifbe(&cksum);
            if (cksum == 0) {
                serverLog(LL_WARNING,"RDB file was saved with checksum disabled: no check performed.");
            } else if (cksum != expected) {
                serverLog(LL_WARNING,"Wrong RDB checksum expected: (%llx) but " "got (%llx). Aborting now.", (unsigned long long)expected, (unsigned long long)cksum);


                rdbReportCorruptRDB("RDB CRC error");
                return C_ERR;
            }
        }
    }

    if (empty_keys_skipped) {
        serverLog(LL_WARNING, "Done loading RDB, keys loaded: %lld, keys expired: %lld, empty keys skipped: %lld.", server.rdb_last_load_keys_loaded, server.rdb_last_load_keys_expired, empty_keys_skipped);

    } else {
        serverLog(LL_NOTICE, "Done loading RDB, keys loaded: %lld, keys expired: %lld.", server.rdb_last_load_keys_loaded, server.rdb_last_load_keys_expired);

    }
    return C_OK;

    
eoferr:
    serverLog(LL_WARNING, "Short read or OOM loading DB. Unrecoverable error, aborting now.");
    rdbReportReadError("Unexpected EOF reading RDB file");
    return C_ERR;
}


int rdbLoad(char *filename, rdbSaveInfo *rsi, int rdbflags) {
    FILE *fp;
    rio rdb;
    int retval;

    if ((fp = fopen(filename,"r")) == NULL) return C_ERR;
    startLoadingFile(fp, filename,rdbflags);
    rioInitWithFile(&rdb,fp);
    retval = rdbLoadRio(&rdb,rdbflags,rsi);
    fclose(fp);
    stopLoading(retval==C_OK);
    return retval;
}


static void backgroundSaveDoneHandlerDisk(int exitcode, int bysignal) {
    if (!bysignal && exitcode == 0) {
        serverLog(LL_NOTICE, "Background saving terminated with success");
        server.dirty = server.dirty - server.dirty_before_bgsave;
        server.lastsave = time(NULL);
        server.lastbgsave_status = C_OK;
    } else if (!bysignal && exitcode != 0) {
        serverLog(LL_WARNING, "Background saving error");
        server.lastbgsave_status = C_ERR;
    } else {
        mstime_t latency;

        serverLog(LL_WARNING, "Background saving terminated by signal %d", bysignal);
        latencyStartMonitor(latency);
        rdbRemoveTempFile(server.child_pid, 0);
        latencyEndMonitor(latency);
        latencyAddSampleIfNeeded("rdb-unlink-temp-file",latency);
        
        if (bysignal != SIGUSR1)
            server.lastbgsave_status = C_ERR;
    }
}


static void backgroundSaveDoneHandlerSocket(int exitcode, int bysignal) {
    if (!bysignal && exitcode == 0) {
        serverLog(LL_NOTICE, "Background RDB transfer terminated with success");
    } else if (!bysignal && exitcode != 0) {
        serverLog(LL_WARNING, "Background transfer error");
    } else {
        serverLog(LL_WARNING, "Background transfer terminated by signal %d", bysignal);
    }
    if (server.rdb_child_exit_pipe!=-1)
        close(server.rdb_child_exit_pipe);
    aeDeleteFileEvent(server.el, server.rdb_pipe_read, AE_READABLE);
    close(server.rdb_pipe_read);
    server.rdb_child_exit_pipe = -1;
    server.rdb_pipe_read = -1;
    zfree(server.rdb_pipe_conns);
    server.rdb_pipe_conns = NULL;
    server.rdb_pipe_numconns = 0;
    server.rdb_pipe_numconns_writing = 0;
    zfree(server.rdb_pipe_buff);
    server.rdb_pipe_buff = NULL;
    server.rdb_pipe_bufflen = 0;
}


void backgroundSaveDoneHandler(int exitcode, int bysignal) {
    int type = server.rdb_child_type;
    switch(server.rdb_child_type) {
    case RDB_CHILD_TYPE_DISK:
        backgroundSaveDoneHandlerDisk(exitcode,bysignal);
        break;
    case RDB_CHILD_TYPE_SOCKET:
        backgroundSaveDoneHandlerSocket(exitcode,bysignal);
        break;
    default:
        serverPanic("Unknown RDB child type.");
        break;
    }

    server.rdb_child_type = RDB_CHILD_TYPE_NONE;
    server.rdb_save_time_last = time(NULL)-server.rdb_save_time_start;
    server.rdb_save_time_start = -1;
    
    updateSlavesWaitingBgsave((!bysignal && exitcode == 0) ? C_OK : C_ERR, type);
}


void killRDBChild(void) {
    kill(server.child_pid, SIGUSR1);
    
}


int rdbSaveToSlavesSockets(rdbSaveInfo *rsi) {
    listNode *ln;
    listIter li;
    pid_t childpid;
    int pipefds[2], rdb_pipe_write, safe_to_exit_pipe;

    if (hasActiveChildProcess()) return C_ERR;

    
    if (server.rdb_pipe_conns) return C_ERR;

    
    if (pipe(pipefds) == -1) return C_ERR;
    server.rdb_pipe_read = pipefds[0]; 
    rdb_pipe_write = pipefds[1]; 
    anetNonBlock(NULL, server.rdb_pipe_read);

    
    if (pipe(pipefds) == -1) {
        close(rdb_pipe_write);
        close(server.rdb_pipe_read);
        return C_ERR;
    }
    safe_to_exit_pipe = pipefds[0]; 
    server.rdb_child_exit_pipe = pipefds[1]; 

    
    server.rdb_pipe_conns = zmalloc(sizeof(connection *)*listLength(server.slaves));
    server.rdb_pipe_numconns = 0;
    server.rdb_pipe_numconns_writing = 0;
    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;
        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
            server.rdb_pipe_conns[server.rdb_pipe_numconns++] = slave->conn;
            replicationSetupSlaveForFullResync(slave,getPsyncInitialOffset());
        }
    }

    
    if ((childpid = redisFork(CHILD_TYPE_RDB)) == 0) {
        
        int retval, dummy;
        rio rdb;

        rioInitWithFd(&rdb,rdb_pipe_write);

        redisSetProcTitle("redis-rdb-to-slaves");
        redisSetCpuAffinity(server.bgsave_cpulist);

        retval = rdbSaveRioWithEOFMark(&rdb,NULL,rsi);
        if (retval == C_OK && rioFlush(&rdb) == 0)
            retval = C_ERR;

        if (retval == C_OK) {
            sendChildCowInfo(CHILD_INFO_TYPE_RDB_COW_SIZE, "RDB");
        }

        rioFreeFd(&rdb);
        
        close(rdb_pipe_write);
        close(server.rdb_child_exit_pipe); 
        
        dummy = read(safe_to_exit_pipe, pipefds, 1);
        UNUSED(dummy);
        exitFromChild((retval == C_OK) ? 0 : 1);
    } else {
        
        close(safe_to_exit_pipe);
        if (childpid == -1) {
            serverLog(LL_WARNING,"Can't save in background: fork: %s", strerror(errno));

            
            listRewind(server.slaves,&li);
            while((ln = listNext(&li))) {
                client *slave = ln->value;
                if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END) {
                    slave->replstate = SLAVE_STATE_WAIT_BGSAVE_START;
                }
            }
            close(rdb_pipe_write);
            close(server.rdb_pipe_read);
            zfree(server.rdb_pipe_conns);
            server.rdb_pipe_conns = NULL;
            server.rdb_pipe_numconns = 0;
            server.rdb_pipe_numconns_writing = 0;
        } else {
            serverLog(LL_NOTICE,"Background RDB transfer started by pid %ld", (long) childpid);
            server.rdb_save_time_start = time(NULL);
            server.rdb_child_type = RDB_CHILD_TYPE_SOCKET;
            close(rdb_pipe_write); 
            if (aeCreateFileEvent(server.el, server.rdb_pipe_read, AE_READABLE, rdbPipeReadHandler,NULL) == AE_ERR) {
                serverPanic("Unrecoverable error creating server.rdb_pipe_read file event.");
            }
        }
        return (childpid == -1) ? C_ERR : C_OK;
    }
    return C_OK; 
}

void saveCommand(client *c) {
    if (server.child_type == CHILD_TYPE_RDB) {
        addReplyError(c,"Background save already in progress");
        return;
    }
    rdbSaveInfo rsi, *rsiptr;
    rsiptr = rdbPopulateSaveInfo(&rsi);
    if (rdbSave(server.rdb_filename,rsiptr) == C_OK) {
        addReply(c,shared.ok);
    } else {
        addReplyErrorObject(c,shared.err);
    }
}


void bgsaveCommand(client *c) {
    int schedule = 0;

    
    if (c->argc > 1) {
        if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"schedule")) {
            schedule = 1;
        } else {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        }
    }

    rdbSaveInfo rsi, *rsiptr;
    rsiptr = rdbPopulateSaveInfo(&rsi);

    if (server.child_type == CHILD_TYPE_RDB) {
        addReplyError(c,"Background save already in progress");
    } else if (hasActiveChildProcess()) {
        if (schedule) {
            server.rdb_bgsave_scheduled = 1;
            addReplyStatus(c,"Background saving scheduled");
        } else {
            addReplyError(c, "Another child process is active (AOF?): can't BGSAVE right now. " "Use BGSAVE SCHEDULE in order to schedule a BGSAVE whenever " "possible.");


        }
    } else if (rdbSaveBackground(server.rdb_filename,rsiptr) == C_OK) {
        addReplyStatus(c,"Background saving started");
    } else {
        addReplyErrorObject(c,shared.err);
    }
}


rdbSaveInfo *rdbPopulateSaveInfo(rdbSaveInfo *rsi) {
    rdbSaveInfo rsi_init = RDB_SAVE_INFO_INIT;
    *rsi = rsi_init;

    
    if (!server.masterhost && server.repl_backlog) {
        
        rsi->repl_stream_db = server.slaveseldb == -1 ? 0 : server.slaveseldb;
        return rsi;
    }

    
    if (server.master) {
        rsi->repl_stream_db = server.master->db->id;
        return rsi;
    }

    
    if (server.cached_master) {
        rsi->repl_stream_db = server.cached_master->db->id;
        return rsi;
    }
    return NULL;
}
