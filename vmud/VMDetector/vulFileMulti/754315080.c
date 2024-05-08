







void hashTypeTryConversion(robj *o, robj **argv, int start, int end) {
    int i;
    size_t sum = 0;

    if (o->encoding != OBJ_ENCODING_LISTPACK) return;

    for (i = start; i <= end; i++) {
        if (!sdsEncodedObject(argv[i]))
            continue;
        size_t len = sdslen(argv[i]->ptr);
        if (len > server.hash_max_listpack_value) {
            hashTypeConvert(o, OBJ_ENCODING_HT);
            return;
        }
        sum += len;
    }
    if (!lpSafeToAdd(o->ptr, sum))
        hashTypeConvert(o, OBJ_ENCODING_HT);
}


int hashTypeGetFromListpack(robj *o, sds field, unsigned char **vstr, unsigned int *vlen, long long *vll)


{
    unsigned char *zl, *fptr = NULL, *vptr = NULL;

    serverAssert(o->encoding == OBJ_ENCODING_LISTPACK);

    zl = o->ptr;
    fptr = lpFirst(zl);
    if (fptr != NULL) {
        fptr = lpFind(zl, fptr, (unsigned char*)field, sdslen(field), 1);
        if (fptr != NULL) {
            
            vptr = lpNext(zl, fptr);
            serverAssert(vptr != NULL);
        }
    }

    if (vptr != NULL) {
        *vstr = lpGetValue(vptr, vlen, vll);
        return 0;
    }

    return -1;
}


sds hashTypeGetFromHashTable(robj *o, sds field) {
    dictEntry *de;

    serverAssert(o->encoding == OBJ_ENCODING_HT);

    de = dictFind(o->ptr, field);
    if (de == NULL) return NULL;
    return dictGetVal(de);
}


int hashTypeGetValue(robj *o, sds field, unsigned char **vstr, unsigned int *vlen, long long *vll) {
    if (o->encoding == OBJ_ENCODING_LISTPACK) {
        *vstr = NULL;
        if (hashTypeGetFromListpack(o, field, vstr, vlen, vll) == 0)
            return C_OK;
    } else if (o->encoding == OBJ_ENCODING_HT) {
        sds value;
        if ((value = hashTypeGetFromHashTable(o, field)) != NULL) {
            *vstr = (unsigned char*) value;
            *vlen = sdslen(value);
            return C_OK;
        }
    } else {
        serverPanic("Unknown hash encoding");
    }
    return C_ERR;
}


robj *hashTypeGetValueObject(robj *o, sds field) {
    unsigned char *vstr;
    unsigned int vlen;
    long long vll;

    if (hashTypeGetValue(o,field,&vstr,&vlen,&vll) == C_ERR) return NULL;
    if (vstr) return createStringObject((char*)vstr,vlen);
    else return createStringObjectFromLongLong(vll);
}


size_t hashTypeGetValueLength(robj *o, sds field) {
    size_t len = 0;
    unsigned char *vstr = NULL;
    unsigned int vlen = UINT_MAX;
    long long vll = LLONG_MAX;

    if (hashTypeGetValue(o, field, &vstr, &vlen, &vll) == C_OK)
        len = vstr ? vlen : sdigits10(vll);

    return len;
}


int hashTypeExists(robj *o, sds field) {
    unsigned char *vstr = NULL;
    unsigned int vlen = UINT_MAX;
    long long vll = LLONG_MAX;

    return hashTypeGetValue(o, field, &vstr, &vlen, &vll) == C_OK;
}





int hashTypeSet(robj *o, sds field, sds value, int flags) {
    int update = 0;

    
    if (o->encoding == OBJ_ENCODING_LISTPACK) {
        if (sdslen(field) > server.hash_max_listpack_value || sdslen(value) > server.hash_max_listpack_value)
            hashTypeConvert(o, OBJ_ENCODING_HT);
    }
    
    if (o->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl, *fptr, *vptr;

        zl = o->ptr;
        fptr = lpFirst(zl);
        if (fptr != NULL) {
            fptr = lpFind(zl, fptr, (unsigned char*)field, sdslen(field), 1);
            if (fptr != NULL) {
                
                vptr = lpNext(zl, fptr);
                serverAssert(vptr != NULL);
                update = 1;

                
                zl = lpReplace(zl, &vptr, (unsigned char*)value, sdslen(value));
            }
        }

        if (!update) {
            
            zl = lpAppend(zl, (unsigned char*)field, sdslen(field));
            zl = lpAppend(zl, (unsigned char*)value, sdslen(value));
        }
        o->ptr = zl;

        
        if (hashTypeLength(o) > server.hash_max_listpack_entries)
            hashTypeConvert(o, OBJ_ENCODING_HT);
    } else if (o->encoding == OBJ_ENCODING_HT) {
        dictEntry *de = dictFind(o->ptr,field);
        if (de) {
            sdsfree(dictGetVal(de));
            if (flags & HASH_SET_TAKE_VALUE) {
                dictGetVal(de) = value;
                value = NULL;
            } else {
                dictGetVal(de) = sdsdup(value);
            }
            update = 1;
        } else {
            sds f,v;
            if (flags & HASH_SET_TAKE_FIELD) {
                f = field;
                field = NULL;
            } else {
                f = sdsdup(field);
            }
            if (flags & HASH_SET_TAKE_VALUE) {
                v = value;
                value = NULL;
            } else {
                v = sdsdup(value);
            }
            dictAdd(o->ptr,f,v);
        }
    } else {
        serverPanic("Unknown hash encoding");
    }

    
    if (flags & HASH_SET_TAKE_FIELD && field) sdsfree(field);
    if (flags & HASH_SET_TAKE_VALUE && value) sdsfree(value);
    return update;
}


int hashTypeDelete(robj *o, sds field) {
    int deleted = 0;

    if (o->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl, *fptr;

        zl = o->ptr;
        fptr = lpFirst(zl);
        if (fptr != NULL) {
            fptr = lpFind(zl, fptr, (unsigned char*)field, sdslen(field), 1);
            if (fptr != NULL) {
                
                zl = lpDeleteRangeWithEntry(zl,&fptr,2);
                o->ptr = zl;
                deleted = 1;
            }
        }
    } else if (o->encoding == OBJ_ENCODING_HT) {
        if (dictDelete((dict*)o->ptr, field) == C_OK) {
            deleted = 1;

            
            if (htNeedsResize(o->ptr)) dictResize(o->ptr);
        }

    } else {
        serverPanic("Unknown hash encoding");
    }
    return deleted;
}


unsigned long hashTypeLength(const robj *o) {
    unsigned long length = ULONG_MAX;

    if (o->encoding == OBJ_ENCODING_LISTPACK) {
        length = lpLength(o->ptr) / 2;
    } else if (o->encoding == OBJ_ENCODING_HT) {
        length = dictSize((const dict*)o->ptr);
    } else {
        serverPanic("Unknown hash encoding");
    }
    return length;
}

hashTypeIterator *hashTypeInitIterator(robj *subject) {
    hashTypeIterator *hi = zmalloc(sizeof(hashTypeIterator));
    hi->subject = subject;
    hi->encoding = subject->encoding;

    if (hi->encoding == OBJ_ENCODING_LISTPACK) {
        hi->fptr = NULL;
        hi->vptr = NULL;
    } else if (hi->encoding == OBJ_ENCODING_HT) {
        hi->di = dictGetIterator(subject->ptr);
    } else {
        serverPanic("Unknown hash encoding");
    }
    return hi;
}

void hashTypeReleaseIterator(hashTypeIterator *hi) {
    if (hi->encoding == OBJ_ENCODING_HT)
        dictReleaseIterator(hi->di);
    zfree(hi);
}


int hashTypeNext(hashTypeIterator *hi) {
    if (hi->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl;
        unsigned char *fptr, *vptr;

        zl = hi->subject->ptr;
        fptr = hi->fptr;
        vptr = hi->vptr;

        if (fptr == NULL) {
            
            serverAssert(vptr == NULL);
            fptr = lpFirst(zl);
        } else {
            
            serverAssert(vptr != NULL);
            fptr = lpNext(zl, vptr);
        }
        if (fptr == NULL) return C_ERR;

        
        vptr = lpNext(zl, fptr);
        serverAssert(vptr != NULL);

        
        hi->fptr = fptr;
        hi->vptr = vptr;
    } else if (hi->encoding == OBJ_ENCODING_HT) {
        if ((hi->de = dictNext(hi->di)) == NULL) return C_ERR;
    } else {
        serverPanic("Unknown hash encoding");
    }
    return C_OK;
}


void hashTypeCurrentFromListpack(hashTypeIterator *hi, int what, unsigned char **vstr, unsigned int *vlen, long long *vll)


{
    serverAssert(hi->encoding == OBJ_ENCODING_LISTPACK);

    if (what & OBJ_HASH_KEY) {
        *vstr = lpGetValue(hi->fptr, vlen, vll);
    } else {
        *vstr = lpGetValue(hi->vptr, vlen, vll);
    }
}


sds hashTypeCurrentFromHashTable(hashTypeIterator *hi, int what) {
    serverAssert(hi->encoding == OBJ_ENCODING_HT);

    if (what & OBJ_HASH_KEY) {
        return dictGetKey(hi->de);
    } else {
        return dictGetVal(hi->de);
    }
}


void hashTypeCurrentObject(hashTypeIterator *hi, int what, unsigned char **vstr, unsigned int *vlen, long long *vll) {
    if (hi->encoding == OBJ_ENCODING_LISTPACK) {
        *vstr = NULL;
        hashTypeCurrentFromListpack(hi, what, vstr, vlen, vll);
    } else if (hi->encoding == OBJ_ENCODING_HT) {
        sds ele = hashTypeCurrentFromHashTable(hi, what);
        *vstr = (unsigned char*) ele;
        *vlen = sdslen(ele);
    } else {
        serverPanic("Unknown hash encoding");
    }
}


sds hashTypeCurrentObjectNewSds(hashTypeIterator *hi, int what) {
    unsigned char *vstr;
    unsigned int vlen;
    long long vll;

    hashTypeCurrentObject(hi,what,&vstr,&vlen,&vll);
    if (vstr) return sdsnewlen(vstr,vlen);
    return sdsfromlonglong(vll);
}

robj *hashTypeLookupWriteOrCreate(client *c, robj *key) {
    robj *o = lookupKeyWrite(c->db,key);
    if (checkType(c,o,OBJ_HASH)) return NULL;

    if (o == NULL) {
        o = createHashObject();
        dbAdd(c->db,key,o);
    }
    return o;
}


void hashTypeConvertListpack(robj *o, int enc) {
    serverAssert(o->encoding == OBJ_ENCODING_LISTPACK);

    if (enc == OBJ_ENCODING_LISTPACK) {
        

    } else if (enc == OBJ_ENCODING_HT) {
        hashTypeIterator *hi;
        dict *dict;
        int ret;

        hi = hashTypeInitIterator(o);
        dict = dictCreate(&hashDictType);

        
        dictExpand(dict,hashTypeLength(o));

        while (hashTypeNext(hi) != C_ERR) {
            sds key, value;

            key = hashTypeCurrentObjectNewSds(hi,OBJ_HASH_KEY);
            value = hashTypeCurrentObjectNewSds(hi,OBJ_HASH_VALUE);
            ret = dictAdd(dict, key, value);
            if (ret != DICT_OK) {
                sdsfree(key); sdsfree(value); 
                hashTypeReleaseIterator(hi);  
                serverLogHexDump(LL_WARNING,"listpack with dup elements dump", o->ptr,lpBytes(o->ptr));
                serverPanic("Listpack corruption detected");
            }
        }
        hashTypeReleaseIterator(hi);
        zfree(o->ptr);
        o->encoding = OBJ_ENCODING_HT;
        o->ptr = dict;
    } else {
        serverPanic("Unknown hash encoding");
    }
}

void hashTypeConvert(robj *o, int enc) {
    if (o->encoding == OBJ_ENCODING_LISTPACK) {
        hashTypeConvertListpack(o, enc);
    } else if (o->encoding == OBJ_ENCODING_HT) {
        serverPanic("Not implemented");
    } else {
        serverPanic("Unknown hash encoding");
    }
}


robj *hashTypeDup(robj *o) {
    robj *hobj;
    hashTypeIterator *hi;

    serverAssert(o->type == OBJ_HASH);

    if(o->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = o->ptr;
        size_t sz = lpBytes(zl);
        unsigned char *new_zl = zmalloc(sz);
        memcpy(new_zl, zl, sz);
        hobj = createObject(OBJ_HASH, new_zl);
        hobj->encoding = OBJ_ENCODING_LISTPACK;
    } else if(o->encoding == OBJ_ENCODING_HT){
        dict *d = dictCreate(&hashDictType);
        dictExpand(d, dictSize((const dict*)o->ptr));

        hi = hashTypeInitIterator(o);
        while (hashTypeNext(hi) != C_ERR) {
            sds field, value;
            sds newfield, newvalue;
            
            field = hashTypeCurrentFromHashTable(hi, OBJ_HASH_KEY);
            value = hashTypeCurrentFromHashTable(hi, OBJ_HASH_VALUE);
            newfield = sdsdup(field);
            newvalue = sdsdup(value);

            
            dictAdd(d,newfield,newvalue);
        }
        hashTypeReleaseIterator(hi);

        hobj = createObject(OBJ_HASH, d);
        hobj->encoding = OBJ_ENCODING_HT;
    } else {
        serverPanic("Unknown hash encoding");
    }
    return hobj;
}


sds hashSdsFromListpackEntry(listpackEntry *e) {
    return e->sval ? sdsnewlen(e->sval, e->slen) : sdsfromlonglong(e->lval);
}


void hashReplyFromListpackEntry(client *c, listpackEntry *e) {
    if (e->sval)
        addReplyBulkCBuffer(c, e->sval, e->slen);
    else addReplyBulkLongLong(c, e->lval);
}


void hashTypeRandomElement(robj *hashobj, unsigned long hashsize, listpackEntry *key, listpackEntry *val) {
    if (hashobj->encoding == OBJ_ENCODING_HT) {
        dictEntry *de = dictGetFairRandomKey(hashobj->ptr);
        sds s = dictGetKey(de);
        key->sval = (unsigned char*)s;
        key->slen = sdslen(s);
        if (val) {
            sds s = dictGetVal(de);
            val->sval = (unsigned char*)s;
            val->slen = sdslen(s);
        }
    } else if (hashobj->encoding == OBJ_ENCODING_LISTPACK) {
        lpRandomPair(hashobj->ptr, hashsize, key, val);
    } else {
        serverPanic("Unknown hash encoding");
    }
}




void hsetnxCommand(client *c) {
    robj *o;
    if ((o = hashTypeLookupWriteOrCreate(c,c->argv[1])) == NULL) return;

    if (hashTypeExists(o, c->argv[2]->ptr)) {
        addReply(c, shared.czero);
    } else {
        hashTypeTryConversion(o,c->argv,2,3);
        hashTypeSet(o,c->argv[2]->ptr,c->argv[3]->ptr,HASH_SET_COPY);
        addReply(c, shared.cone);
        signalModifiedKey(c,c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_HASH,"hset",c->argv[1],c->db->id);
        server.dirty++;
    }
}

void hsetCommand(client *c) {
    int i, created = 0;
    robj *o;

    if ((c->argc % 2) == 1) {
        addReplyErrorArity(c);
        return;
    }

    if ((o = hashTypeLookupWriteOrCreate(c,c->argv[1])) == NULL) return;
    hashTypeTryConversion(o,c->argv,2,c->argc-1);

    for (i = 2; i < c->argc; i += 2)
        created += !hashTypeSet(o,c->argv[i]->ptr,c->argv[i+1]->ptr,HASH_SET_COPY);

    
    char *cmdname = c->argv[0]->ptr;
    if (cmdname[1] == 's' || cmdname[1] == 'S') {
        
        addReplyLongLong(c, created);
    } else {
        
        addReply(c, shared.ok);
    }
    signalModifiedKey(c,c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_HASH,"hset",c->argv[1],c->db->id);
    server.dirty += (c->argc - 2)/2;
}

void hincrbyCommand(client *c) {
    long long value, incr, oldvalue;
    robj *o;
    sds new;
    unsigned char *vstr;
    unsigned int vlen;

    if (getLongLongFromObjectOrReply(c,c->argv[3],&incr,NULL) != C_OK) return;
    if ((o = hashTypeLookupWriteOrCreate(c,c->argv[1])) == NULL) return;
    if (hashTypeGetValue(o,c->argv[2]->ptr,&vstr,&vlen,&value) == C_OK) {
        if (vstr) {
            if (string2ll((char*)vstr,vlen,&value) == 0) {
                addReplyError(c,"hash value is not an integer");
                return;
            }
        } 
    } else {
        value = 0;
    }

    oldvalue = value;
    if ((incr < 0 && oldvalue < 0 && incr < (LLONG_MIN-oldvalue)) || (incr > 0 && oldvalue > 0 && incr > (LLONG_MAX-oldvalue))) {
        addReplyError(c,"increment or decrement would overflow");
        return;
    }
    value += incr;
    new = sdsfromlonglong(value);
    hashTypeSet(o,c->argv[2]->ptr,new,HASH_SET_TAKE_VALUE);
    addReplyLongLong(c,value);
    signalModifiedKey(c,c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_HASH,"hincrby",c->argv[1],c->db->id);
    server.dirty++;
}

void hincrbyfloatCommand(client *c) {
    long double value, incr;
    long long ll;
    robj *o;
    sds new;
    unsigned char *vstr;
    unsigned int vlen;

    if (getLongDoubleFromObjectOrReply(c,c->argv[3],&incr,NULL) != C_OK) return;
    if ((o = hashTypeLookupWriteOrCreate(c,c->argv[1])) == NULL) return;
    if (hashTypeGetValue(o,c->argv[2]->ptr,&vstr,&vlen,&ll) == C_OK) {
        if (vstr) {
            if (string2ld((char*)vstr,vlen,&value) == 0) {
                addReplyError(c,"hash value is not a float");
                return;
            }
        } else {
            value = (long double)ll;
        }
    } else {
        value = 0;
    }

    value += incr;
    if (isnan(value) || isinf(value)) {
        addReplyError(c,"increment would produce NaN or Infinity");
        return;
    }

    char buf[MAX_LONG_DOUBLE_CHARS];
    int len = ld2string(buf,sizeof(buf),value,LD_STR_HUMAN);
    new = sdsnewlen(buf,len);
    hashTypeSet(o,c->argv[2]->ptr,new,HASH_SET_TAKE_VALUE);
    addReplyBulkCBuffer(c,buf,len);
    signalModifiedKey(c,c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_HASH,"hincrbyfloat",c->argv[1],c->db->id);
    server.dirty++;

    
    robj *newobj;
    newobj = createRawStringObject(buf,len);
    rewriteClientCommandArgument(c,0,shared.hset);
    rewriteClientCommandArgument(c,3,newobj);
    decrRefCount(newobj);
}

static void addHashFieldToReply(client *c, robj *o, sds field) {
    if (o == NULL) {
        addReplyNull(c);
        return;
    }

    unsigned char *vstr = NULL;
    unsigned int vlen = UINT_MAX;
    long long vll = LLONG_MAX;

    if (hashTypeGetValue(o, field, &vstr, &vlen, &vll) == C_OK) {
        if (vstr) {
            addReplyBulkCBuffer(c, vstr, vlen);
        } else {
            addReplyBulkLongLong(c, vll);
        }
    } else {
        addReplyNull(c);
    }
}

void hgetCommand(client *c) {
    robj *o;

    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.null[c->resp])) == NULL || checkType(c,o,OBJ_HASH)) return;

    addHashFieldToReply(c, o, c->argv[2]->ptr);
}

void hmgetCommand(client *c) {
    robj *o;
    int i;

    
    o = lookupKeyRead(c->db, c->argv[1]);
    if (checkType(c,o,OBJ_HASH)) return;

    addReplyArrayLen(c, c->argc-2);
    for (i = 2; i < c->argc; i++) {
        addHashFieldToReply(c, o, c->argv[i]->ptr);
    }
}

void hdelCommand(client *c) {
    robj *o;
    int j, deleted = 0, keyremoved = 0;

    if ((o = lookupKeyWriteOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_HASH)) return;

    for (j = 2; j < c->argc; j++) {
        if (hashTypeDelete(o,c->argv[j]->ptr)) {
            deleted++;
            if (hashTypeLength(o) == 0) {
                dbDelete(c->db,c->argv[1]);
                keyremoved = 1;
                break;
            }
        }
    }
    if (deleted) {
        signalModifiedKey(c,c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_HASH,"hdel",c->argv[1],c->db->id);
        if (keyremoved)
            notifyKeyspaceEvent(NOTIFY_GENERIC,"del",c->argv[1], c->db->id);
        server.dirty += deleted;
    }
    addReplyLongLong(c,deleted);
}

void hlenCommand(client *c) {
    robj *o;

    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_HASH)) return;

    addReplyLongLong(c,hashTypeLength(o));
}

void hstrlenCommand(client *c) {
    robj *o;

    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_HASH)) return;
    addReplyLongLong(c,hashTypeGetValueLength(o,c->argv[2]->ptr));
}

static void addHashIteratorCursorToReply(client *c, hashTypeIterator *hi, int what) {
    if (hi->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *vstr = NULL;
        unsigned int vlen = UINT_MAX;
        long long vll = LLONG_MAX;

        hashTypeCurrentFromListpack(hi, what, &vstr, &vlen, &vll);
        if (vstr)
            addReplyBulkCBuffer(c, vstr, vlen);
        else addReplyBulkLongLong(c, vll);
    } else if (hi->encoding == OBJ_ENCODING_HT) {
        sds value = hashTypeCurrentFromHashTable(hi, what);
        addReplyBulkCBuffer(c, value, sdslen(value));
    } else {
        serverPanic("Unknown hash encoding");
    }
}

void genericHgetallCommand(client *c, int flags) {
    robj *o;
    hashTypeIterator *hi;
    int length, count = 0;

    robj *emptyResp = (flags & OBJ_HASH_KEY && flags & OBJ_HASH_VALUE) ? shared.emptymap[c->resp] : shared.emptyarray;
    if ((o = lookupKeyReadOrReply(c,c->argv[1],emptyResp))
        == NULL || checkType(c,o,OBJ_HASH)) return;

    
    length = hashTypeLength(o);
    if (flags & OBJ_HASH_KEY && flags & OBJ_HASH_VALUE) {
        addReplyMapLen(c, length);
    } else {
        addReplyArrayLen(c, length);
    }

    hi = hashTypeInitIterator(o);
    while (hashTypeNext(hi) != C_ERR) {
        if (flags & OBJ_HASH_KEY) {
            addHashIteratorCursorToReply(c, hi, OBJ_HASH_KEY);
            count++;
        }
        if (flags & OBJ_HASH_VALUE) {
            addHashIteratorCursorToReply(c, hi, OBJ_HASH_VALUE);
            count++;
        }
    }

    hashTypeReleaseIterator(hi);

    
    if (flags & OBJ_HASH_KEY && flags & OBJ_HASH_VALUE) count /= 2;
    serverAssert(count == length);
}

void hkeysCommand(client *c) {
    genericHgetallCommand(c,OBJ_HASH_KEY);
}

void hvalsCommand(client *c) {
    genericHgetallCommand(c,OBJ_HASH_VALUE);
}

void hgetallCommand(client *c) {
    genericHgetallCommand(c,OBJ_HASH_KEY|OBJ_HASH_VALUE);
}

void hexistsCommand(client *c) {
    robj *o;
    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_HASH)) return;

    addReply(c, hashTypeExists(o,c->argv[2]->ptr) ? shared.cone : shared.czero);
}

void hscanCommand(client *c) {
    robj *o;
    unsigned long cursor;

    if (parseScanCursorOrReply(c,c->argv[2],&cursor) == C_ERR) return;
    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.emptyscan)) == NULL || checkType(c,o,OBJ_HASH)) return;
    scanGenericCommand(c,o,cursor);
}

static void hrandfieldReplyWithListpack(client *c, unsigned int count, listpackEntry *keys, listpackEntry *vals) {
    for (unsigned long i = 0; i < count; i++) {
        if (vals && c->resp > 2)
            addReplyArrayLen(c,2);
        if (keys[i].sval)
            addReplyBulkCBuffer(c, keys[i].sval, keys[i].slen);
        else addReplyBulkLongLong(c, keys[i].lval);
        if (vals) {
            if (vals[i].sval)
                addReplyBulkCBuffer(c, vals[i].sval, vals[i].slen);
            else addReplyBulkLongLong(c, vals[i].lval);
        }
    }
}







void hrandfieldWithCountCommand(client *c, long l, int withvalues) {
    unsigned long count, size;
    int uniq = 1;
    robj *hash;

    if ((hash = lookupKeyReadOrReply(c,c->argv[1],shared.emptyarray))
        == NULL || checkType(c,hash,OBJ_HASH)) return;
    size = hashTypeLength(hash);

    if(l >= 0) {
        count = (unsigned long) l;
    } else {
        count = -l;
        uniq = 0;
    }

    
    if (count == 0) {
        addReply(c,shared.emptyarray);
        return;
    }

    
    if (!uniq || count == 1) {
        if (withvalues && c->resp == 2)
            addReplyArrayLen(c, count*2);
        else addReplyArrayLen(c, count);
        if (hash->encoding == OBJ_ENCODING_HT) {
            sds key, value;
            while (count--) {
                dictEntry *de = dictGetFairRandomKey(hash->ptr);
                key = dictGetKey(de);
                value = dictGetVal(de);
                if (withvalues && c->resp > 2)
                    addReplyArrayLen(c,2);
                addReplyBulkCBuffer(c, key, sdslen(key));
                if (withvalues)
                    addReplyBulkCBuffer(c, value, sdslen(value));
                if (c->flags & CLIENT_CLOSE_ASAP)
                    break;
            }
        } else if (hash->encoding == OBJ_ENCODING_LISTPACK) {
            listpackEntry *keys, *vals = NULL;
            unsigned long limit, sample_count;

            limit = count > HRANDFIELD_RANDOM_SAMPLE_LIMIT ? HRANDFIELD_RANDOM_SAMPLE_LIMIT : count;
            keys = zmalloc(sizeof(listpackEntry)*limit);
            if (withvalues)
                vals = zmalloc(sizeof(listpackEntry)*limit);
            while (count) {
                sample_count = count > limit ? limit : count;
                count -= sample_count;
                lpRandomPairs(hash->ptr, sample_count, keys, vals);
                hrandfieldReplyWithListpack(c, sample_count, keys, vals);
                if (c->flags & CLIENT_CLOSE_ASAP)
                    break;
            }
            zfree(keys);
            zfree(vals);
        }
        return;
    }

    
    long reply_size = count < size ? count : size;
    if (withvalues && c->resp == 2)
        addReplyArrayLen(c, reply_size*2);
    else addReplyArrayLen(c, reply_size);

    
    if(count >= size) {
        hashTypeIterator *hi = hashTypeInitIterator(hash);
        while (hashTypeNext(hi) != C_ERR) {
            if (withvalues && c->resp > 2)
                addReplyArrayLen(c,2);
            addHashIteratorCursorToReply(c, hi, OBJ_HASH_KEY);
            if (withvalues)
                addHashIteratorCursorToReply(c, hi, OBJ_HASH_VALUE);
        }
        hashTypeReleaseIterator(hi);
        return;
    }

    
    if (count*HRANDFIELD_SUB_STRATEGY_MUL > size) {
        dict *d = dictCreate(&sdsReplyDictType);
        dictExpand(d, size);
        hashTypeIterator *hi = hashTypeInitIterator(hash);

        
        while ((hashTypeNext(hi)) != C_ERR) {
            int ret = DICT_ERR;
            sds key, value = NULL;

            key = hashTypeCurrentObjectNewSds(hi,OBJ_HASH_KEY);
            if (withvalues)
                value = hashTypeCurrentObjectNewSds(hi,OBJ_HASH_VALUE);
            ret = dictAdd(d, key, value);

            serverAssert(ret == DICT_OK);
        }
        serverAssert(dictSize(d) == size);
        hashTypeReleaseIterator(hi);

        
        while (size > count) {
            dictEntry *de;
            de = dictGetFairRandomKey(d);
            dictUnlink(d,dictGetKey(de));
            sdsfree(dictGetKey(de));
            sdsfree(dictGetVal(de));
            dictFreeUnlinkedEntry(d,de);
            size--;
        }

        
        dictIterator *di;
        dictEntry *de;
        di = dictGetIterator(d);
        while ((de = dictNext(di)) != NULL) {
            sds key = dictGetKey(de);
            sds value = dictGetVal(de);
            if (withvalues && c->resp > 2)
                addReplyArrayLen(c,2);
            addReplyBulkSds(c, key);
            if (withvalues)
                addReplyBulkSds(c, value);
        }

        dictReleaseIterator(di);
        dictRelease(d);
    }

    
    else {
        if (hash->encoding == OBJ_ENCODING_LISTPACK) {
            
            listpackEntry *keys, *vals = NULL;
            keys = zmalloc(sizeof(listpackEntry)*count);
            if (withvalues)
                vals = zmalloc(sizeof(listpackEntry)*count);
            serverAssert(lpRandomPairsUnique(hash->ptr, count, keys, vals) == count);
            hrandfieldReplyWithListpack(c, count, keys, vals);
            zfree(keys);
            zfree(vals);
            return;
        }

        
        unsigned long added = 0;
        listpackEntry key, value;
        dict *d = dictCreate(&hashDictType);
        dictExpand(d, count);
        while(added < count) {
            hashTypeRandomElement(hash, size, &key, withvalues? &value : NULL);

            
            sds skey = hashSdsFromListpackEntry(&key);
            if (dictAdd(d,skey,NULL) != DICT_OK) {
                sdsfree(skey);
                continue;
            }
            added++;

            
            if (withvalues && c->resp > 2)
                addReplyArrayLen(c,2);
            hashReplyFromListpackEntry(c, &key);
            if (withvalues)
                hashReplyFromListpackEntry(c, &value);
        }

        
        dictRelease(d);
    }
}


void hrandfieldCommand(client *c) {
    long l;
    int withvalues = 0;
    robj *hash;
    listpackEntry ele;

    if (c->argc >= 3) {
        if (getLongFromObjectOrReply(c,c->argv[2],&l,NULL) != C_OK) return;
        if (c->argc > 4 || (c->argc == 4 && strcasecmp(c->argv[3]->ptr,"withvalues"))) {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        } else if (c->argc == 4) {
            withvalues = 1;
            if (l < LONG_MIN/2 || l > LONG_MAX/2) {
                addReplyError(c,"value is out of range");
                return;
            }
        }
        hrandfieldWithCountCommand(c, l, withvalues);
        return;
    }

    
    if ((hash = lookupKeyReadOrReply(c,c->argv[1],shared.null[c->resp]))== NULL || checkType(c,hash,OBJ_HASH)) {
        return;
    }

    hashTypeRandomElement(hash,hashTypeLength(hash),&ele,NULL);
    hashReplyFromListpackEntry(c, &ele);
}
