




























































extern const encodeJsonSignature encodeJsonJumpTable[UA_DATATYPEKINDS];
extern const decodeJsonSignature decodeJsonJumpTable[UA_DATATYPEKINDS];


UA_String UA_DateTime_toJSON(UA_DateTime t);
ENCODE_JSON(ByteString);

static status UA_FUNC_ATTR_WARN_UNUSED_RESULT writeChar(CtxJson *ctx, char c) {
    if(ctx->pos >= ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(!ctx->calcOnly)
        *ctx->pos = (UA_Byte)c;
    ctx->pos++;
    return UA_STATUSCODE_GOOD;
}




static WRITE_JSON_ELEMENT(Quote) {
    return writeChar(ctx, '\"');
}

WRITE_JSON_ELEMENT(ObjStart) {
    
    ctx->depth++;
    ctx->commaNeeded[ctx->depth] = false;
    return writeChar(ctx, '{');
}

WRITE_JSON_ELEMENT(ObjEnd) {
    ctx->depth--; 
    ctx->commaNeeded[ctx->depth] = true;
    return writeChar(ctx, '}');
}

WRITE_JSON_ELEMENT(ArrStart) {
    
    ctx->commaNeeded[++ctx->depth] = false;
    return writeChar(ctx, '[');
}

WRITE_JSON_ELEMENT(ArrEnd) {
    ctx->depth--; 
    ctx->commaNeeded[ctx->depth] = true;
    return writeChar(ctx, ']');
}

WRITE_JSON_ELEMENT(CommaIfNeeded) {
    if(ctx->commaNeeded[ctx->depth])
        return writeChar(ctx, ',');
    return UA_STATUSCODE_GOOD;
}

status writeJsonArrElm(CtxJson *ctx, const void *value, const UA_DataType *type) {

    status ret = writeJsonCommaIfNeeded(ctx);
    ctx->commaNeeded[ctx->depth] = true;
    ret |= encodeJsonInternal(value, type, ctx);
    return ret;
}

status writeJsonObjElm(CtxJson *ctx, const char *key, const void *value, const UA_DataType *type){
    return writeJsonKey(ctx, key) | encodeJsonInternal(value, type, ctx);
}

status writeJsonNull(CtxJson *ctx) {
    if(ctx->pos + 4 > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(ctx->calcOnly) {
        ctx->pos += 4;
    } else {
        *(ctx->pos++) = 'n';
        *(ctx->pos++) = 'u';
        *(ctx->pos++) = 'l';
        *(ctx->pos++) = 'l';
    }
    return UA_STATUSCODE_GOOD;
}




static const char* UA_JSONKEY_LOCALE = "Locale";
static const char* UA_JSONKEY_TEXT = "Text";


static const char* UA_JSONKEY_NAME = "Name";
static const char* UA_JSONKEY_URI = "Uri";


static const char* UA_JSONKEY_ID = "Id";
static const char* UA_JSONKEY_IDTYPE = "IdType";
static const char* UA_JSONKEY_NAMESPACE = "Namespace";


static const char* UA_JSONKEY_SERVERURI = "ServerUri";


static const char* UA_JSONKEY_TYPE = "Type";
static const char* UA_JSONKEY_BODY = "Body";
static const char* UA_JSONKEY_DIMENSION = "Dimension";


static const char* UA_JSONKEY_VALUE = "Value";
static const char* UA_JSONKEY_STATUS = "Status";
static const char* UA_JSONKEY_SOURCETIMESTAMP = "SourceTimestamp";
static const char* UA_JSONKEY_SOURCEPICOSECONDS = "SourcePicoseconds";
static const char* UA_JSONKEY_SERVERTIMESTAMP = "ServerTimestamp";
static const char* UA_JSONKEY_SERVERPICOSECONDS = "ServerPicoseconds";


static const char* UA_JSONKEY_ENCODING = "Encoding";
static const char* UA_JSONKEY_TYPEID = "TypeId";


static const char* UA_JSONKEY_CODE = "Code";
static const char* UA_JSONKEY_SYMBOL = "Symbol";


static const char* UA_JSONKEY_SYMBOLICID = "SymbolicId";
static const char* UA_JSONKEY_NAMESPACEURI = "NamespaceUri";
static const char* UA_JSONKEY_LOCALIZEDTEXT = "LocalizedText";
static const char* UA_JSONKEY_ADDITIONALINFO = "AdditionalInfo";
static const char* UA_JSONKEY_INNERSTATUSCODE = "InnerStatusCode";
static const char* UA_JSONKEY_INNERDIAGNOSTICINFO = "InnerDiagnosticInfo";


status UA_FUNC_ATTR_WARN_UNUSED_RESULT writeJsonKey(CtxJson *ctx, const char* key) {
    size_t size = strlen(key);
    if(ctx->pos + size + 4 > ctx->end) 
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    status ret = writeJsonCommaIfNeeded(ctx);
    ctx->commaNeeded[ctx->depth] = true;
    if(ctx->calcOnly) {
        ctx->commaNeeded[ctx->depth] = true;
        ctx->pos += 3;
        ctx->pos += size;
        return ret;
    }

    ret |= writeChar(ctx, '\"');
    for(size_t i = 0; i < size; i++) {
        *(ctx->pos++) = (u8)key[i];
    }
    ret |= writeChar(ctx, '\"');
    ret |= writeChar(ctx, ':');
    return ret;
}


ENCODE_JSON(Boolean) {
    size_t sizeOfJSONBool;
    if(*src == true) {
        sizeOfJSONBool = 4; 
    } else {
        sizeOfJSONBool = 5; 
    }

    if(ctx->calcOnly) {
        ctx->pos += sizeOfJSONBool;
        return UA_STATUSCODE_GOOD;
    }

    if(ctx->pos + sizeOfJSONBool > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(*src) {
        *(ctx->pos++) = 't';
        *(ctx->pos++) = 'r';
        *(ctx->pos++) = 'u';
        *(ctx->pos++) = 'e';
    } else {
        *(ctx->pos++) = 'f';
        *(ctx->pos++) = 'a';
        *(ctx->pos++) = 'l';
        *(ctx->pos++) = 's';
        *(ctx->pos++) = 'e';
    }
    return UA_STATUSCODE_GOOD;
}






ENCODE_JSON(Byte) {
    char buf[4];
    UA_UInt16 digits = itoaUnsigned(*src, buf, 10);

    
    if(ctx->pos + digits > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    
    if(!ctx->calcOnly)
        memcpy(ctx->pos, buf, digits);
    ctx->pos += digits;
    return UA_STATUSCODE_GOOD;
}


ENCODE_JSON(SByte) {
    char buf[5];
    UA_UInt16 digits = itoaSigned(*src, buf);
    if(ctx->pos + digits > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    if(!ctx->calcOnly)
        memcpy(ctx->pos, buf, digits);
    ctx->pos += digits;
    return UA_STATUSCODE_GOOD;
}


ENCODE_JSON(UInt16) {
    char buf[6];
    UA_UInt16 digits = itoaUnsigned(*src, buf, 10);

    if(ctx->pos + digits > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(!ctx->calcOnly)
        memcpy(ctx->pos, buf, digits);
    ctx->pos += digits;
    return UA_STATUSCODE_GOOD;
}


ENCODE_JSON(Int16) {
    char buf[7];
    UA_UInt16 digits = itoaSigned(*src, buf);

    if(ctx->pos + digits > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(!ctx->calcOnly)
        memcpy(ctx->pos, buf, digits);
    ctx->pos += digits;
    return UA_STATUSCODE_GOOD;
}


ENCODE_JSON(UInt32) {
    char buf[11];
    UA_UInt16 digits = itoaUnsigned(*src, buf, 10);

    if(ctx->pos + digits > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(!ctx->calcOnly)
        memcpy(ctx->pos, buf, digits);
    ctx->pos += digits;
    return UA_STATUSCODE_GOOD;
}


ENCODE_JSON(Int32) {
    char buf[12];
    UA_UInt16 digits = itoaSigned(*src, buf);

    if(ctx->pos + digits > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(!ctx->calcOnly)
        memcpy(ctx->pos, buf, digits);
    ctx->pos += digits;
    return UA_STATUSCODE_GOOD;
}


ENCODE_JSON(UInt64) {
    char buf[23];
    buf[0] = '\"';
    UA_UInt16 digits = itoaUnsigned(*src, buf + 1, 10);
    buf[digits + 1] = '\"';
    UA_UInt16 length = (UA_UInt16)(digits + 2);

    if(ctx->pos + length > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(!ctx->calcOnly)
        memcpy(ctx->pos, buf, length);

    ctx->pos += length;
    return UA_STATUSCODE_GOOD;
}


ENCODE_JSON(Int64) {
    char buf[23];
    buf[0] = '\"';
    UA_UInt16 digits = itoaSigned(*src, buf + 1);
    buf[digits + 1] = '\"';
    UA_UInt16 length = (UA_UInt16)(digits + 2);

    if(ctx->pos + length > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(!ctx->calcOnly)
        memcpy(ctx->pos, buf, length);
    ctx->pos += length;
    return UA_STATUSCODE_GOOD;
}






static status checkAndEncodeSpecialFloatingPoint(char *buffer, size_t *len) {
    
    if(*len == 3 &&  (buffer[0] == 'n' || buffer[0] == 'N') && (buffer[1] == 'a' || buffer[1] == 'A') && (buffer[2] == 'n' || buffer[2] == 'N')) {


        *len = 5;
        memcpy(buffer, "\"NaN\"", *len);
        return UA_STATUSCODE_GOOD;
    }

    
    if(*len == 4 && buffer[0] == '-' &&  (buffer[1] == 'n' || buffer[1] == 'N') && (buffer[2] == 'a' || buffer[2] == 'A') && (buffer[3] == 'n' || buffer[3] == 'N')) {


        *len = 6;
        memcpy(buffer, "\"-NaN\"", *len);
        return UA_STATUSCODE_GOOD;
    }

    
    if(*len == 3 &&  (buffer[0] == 'i' || buffer[0] == 'I') && (buffer[1] == 'n' || buffer[1] == 'N') && (buffer[2] == 'f' || buffer[2] == 'F')) {


        *len = 10;
        memcpy(buffer, "\"Infinity\"", *len);
        return UA_STATUSCODE_GOOD;
    }

    
    if(*len == 4 && buffer[0] == '-' &&  (buffer[1] == 'i' || buffer[1] == 'I') && (buffer[2] == 'n' || buffer[2] == 'N') && (buffer[3] == 'f' || buffer[3] == 'F')) {


        *len = 11;
        memcpy(buffer, "\"-Infinity\"", *len);
        return UA_STATUSCODE_GOOD;
    }
    return UA_STATUSCODE_GOOD;
}

ENCODE_JSON(Float) {
    char buffer[200];
    if(*src == *src) {

        fmt_fp(buffer, *src, 0, -1, 0, 'g');

        UA_snprintf(buffer, 200, "%.149g", (UA_Double)*src);

    } else {
        strcpy(buffer, "NaN");
    }

    size_t len = strlen(buffer);
    if(len == 0)
        return UA_STATUSCODE_BADENCODINGERROR;
    
    checkAndEncodeSpecialFloatingPoint(buffer, &len);
    
    if(ctx->pos + len > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(!ctx->calcOnly)
        memcpy(ctx->pos, buffer, len);

    ctx->pos += len;
    return UA_STATUSCODE_GOOD;
}

ENCODE_JSON(Double) {
    char buffer[2000];
    if(*src == *src) {

        fmt_fp(buffer, *src, 0, 17, 0, 'g');

        UA_snprintf(buffer, 2000, "%.1074g", *src);

    } else {
        strcpy(buffer, "NaN");
    }

    size_t len = strlen(buffer);
    checkAndEncodeSpecialFloatingPoint(buffer, &len);    

    if(ctx->pos + len > ctx->end)
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;

    if(!ctx->calcOnly)
        memcpy(ctx->pos, buffer, len);

    ctx->pos += len;
    return UA_STATUSCODE_GOOD;
}

static status encodeJsonArray(CtxJson *ctx, const void *ptr, size_t length, const UA_DataType *type) {

    encodeJsonSignature encodeType = encodeJsonJumpTable[type->typeKind];
    status ret = writeJsonArrStart(ctx);
    uintptr_t uptr = (uintptr_t)ptr;
    for(size_t i = 0; i < length && ret == UA_STATUSCODE_GOOD; ++i) {
        ret |= writeJsonCommaIfNeeded(ctx);
        ret |= encodeType((const void*)uptr, type, ctx);
        ctx->commaNeeded[ctx->depth] = true;
        uptr += type->memSize;
    }
    ret |= writeJsonArrEnd(ctx);
    return ret;
}





static const u8 hexmapLower[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f';
static const u8 hexmapUpper[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F';

ENCODE_JSON(String) {
    if(!src->data)
        return writeJsonNull(ctx);

    if(src->length == 0) {
        status retval = writeJsonQuote(ctx);
        retval |= writeJsonQuote(ctx);
        return  retval;
    }

    UA_StatusCode ret = writeJsonQuote(ctx);
    
    

    const char *str = (char*)src->data;
    const char *pos = str;
    const char *end = str;
    const char *lim = str + src->length;
    UA_UInt32 codepoint = 0;
    while(1) {
        const char *text;
        u8 seq[13];
        size_t length;

        while(end < lim) {
            end = utf8_iterate(pos, (size_t)(lim - pos), (int32_t *)&codepoint);
            if(!end)
                return UA_STATUSCODE_BADENCODINGERROR;

            
            if(codepoint == '\\' || codepoint == '"' || codepoint < 0x20)
                break;

            
            

            

            pos = end;
        }

        if(pos != str) {
            if(ctx->pos + (pos - str) > ctx->end)
                return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
            if(!ctx->calcOnly)
                memcpy(ctx->pos, str, (size_t)(pos - str));
            ctx->pos += pos - str;
        }

        if(end == pos)
            break;

        
        length = 2;
        switch(codepoint) {
        case '\\': text = "\\\\"; break;
        case '\"': text = "\\\""; break;
        case '\b': text = "\\b"; break;
        case '\f': text = "\\f"; break;
        case '\n': text = "\\n"; break;
        case '\r': text = "\\r"; break;
        case '\t': text = "\\t"; break;
        case '/':  text = "\\/"; break;
        default:
            if(codepoint < 0x10000) {
                
                seq[0] = '\\';
                seq[1] = 'u';
                UA_Byte b1 = (UA_Byte)(codepoint >> 8u);
                UA_Byte b2 = (UA_Byte)(codepoint >> 0u);
                seq[2] = hexmapLower[(b1 & 0xF0u) >> 4u];
                seq[3] = hexmapLower[b1 & 0x0Fu];
                seq[4] = hexmapLower[(b2 & 0xF0u) >> 4u];
                seq[5] = hexmapLower[b2 & 0x0Fu];
                length = 6;
            } else {
                
                codepoint -= 0x10000;
                UA_UInt32 first = 0xD800u | ((codepoint & 0xffc00u) >> 10u);
                UA_UInt32 last = 0xDC00u | (codepoint & 0x003ffu);

                UA_Byte fb1 = (UA_Byte)(first >> 8u);
                UA_Byte fb2 = (UA_Byte)(first >> 0u);
                    
                UA_Byte lb1 = (UA_Byte)(last >> 8u);
                UA_Byte lb2 = (UA_Byte)(last >> 0u);
                    
                seq[0] = '\\';
                seq[1] = 'u';
                seq[2] = hexmapLower[(fb1 & 0xF0u) >> 4u];
                seq[3] = hexmapLower[fb1 & 0x0Fu];
                seq[4] = hexmapLower[(fb2 & 0xF0u) >> 4u];
                seq[5] = hexmapLower[fb2 & 0x0Fu];
                    
                seq[6] = '\\';
                seq[7] = 'u';
                seq[8] = hexmapLower[(lb1 & 0xF0u) >> 4u];
                seq[9] = hexmapLower[lb1 & 0x0Fu];
                seq[10] = hexmapLower[(lb2 & 0xF0u) >> 4u];
                seq[11] = hexmapLower[lb2 & 0x0Fu];
                length = 12;
            }
            text = (char*)seq;
            break;
        }

        if(ctx->pos + length > ctx->end)
            return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
        if(!ctx->calcOnly)
            memcpy(ctx->pos, text, length);
        ctx->pos += length;
        str = pos = end;
    }

    ret |= writeJsonQuote(ctx);
    return ret;
}
    
ENCODE_JSON(ByteString) {
    if(!src->data)
        return writeJsonNull(ctx);

    if(src->length == 0) {
        status retval = writeJsonQuote(ctx);
        retval |= writeJsonQuote(ctx);
        return retval;
    }

    status ret = writeJsonQuote(ctx);
    size_t flen = 0;
    unsigned char *ba64 = UA_base64(src->data, src->length, &flen);
    
    
    if(!ba64)
        return UA_STATUSCODE_BADENCODINGERROR;

    if(ctx->pos + flen > ctx->end) {
        UA_free(ba64);
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    }
    
    
    if(!ctx->calcOnly)
        memcpy(ctx->pos, ba64, flen);
    ctx->pos += flen;

    
    UA_free(ba64);
    
    ret |= writeJsonQuote(ctx);
    return ret;
}


static void UA_Guid_to_hex(const UA_Guid *guid, u8* out) {
    


    const u8 *hexmap = hexmapLower;

    const u8 *hexmap = hexmapUpper;

    size_t i = 0, j = 28;
    for(; i<8;i++,j-=4)         
        out[i] = hexmap[(guid->data1 >> j) & 0x0Fu];
    out[i++] = '-';             
    for(j=12; i<13;i++,j-=4)    
        out[i] = hexmap[(uint16_t)(guid->data2 >> j) & 0x0Fu];
    out[i++] = '-';             
    for(j=12; i<18;i++,j-=4)    
        out[i] = hexmap[(uint16_t)(guid->data3 >> j) & 0x0Fu];
    out[i++] = '-';             
    for(j=0;i<23;i+=2,j++) {     
        out[i] = hexmap[(guid->data4[j] & 0xF0u) >> 4u];
        out[i+1] = hexmap[guid->data4[j] & 0x0Fu];
    }
    out[i++] = '-';             
    for(j=2; i<36;i+=2,j++) {    
        out[i] = hexmap[(guid->data4[j] & 0xF0u) >> 4u];
        out[i+1] = hexmap[guid->data4[j] & 0x0Fu];
    }
}


ENCODE_JSON(Guid) {
    if(ctx->pos + 38 > ctx->end) 
        return UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED;
    status ret = writeJsonQuote(ctx);
    u8 *buf = ctx->pos;
    if(!ctx->calcOnly)
        UA_Guid_to_hex(src, buf);
    ctx->pos += 36;
    ret |= writeJsonQuote(ctx);
    return ret;
}

static void printNumber(u16 n, u8 *pos, size_t digits) {
    for(size_t i = digits; i > 0; --i) {
        pos[i - 1] = (u8) ((n % 10) + '0');
        n = n / 10;
    }
}

ENCODE_JSON(DateTime) {
    UA_DateTimeStruct tSt = UA_DateTime_toStruct(*src);

    
    UA_Byte buffer[UA_JSON_DATETIME_LENGTH];

    printNumber(tSt.year, &buffer[0], 4);
    buffer[4] = '-';
    printNumber(tSt.month, &buffer[5], 2);
    buffer[7] = '-';
    printNumber(tSt.day, &buffer[8], 2);
    buffer[10] = 'T';
    printNumber(tSt.hour, &buffer[11], 2);
    buffer[13] = ':';
    printNumber(tSt.min, &buffer[14], 2);
    buffer[16] = ':';
    printNumber(tSt.sec, &buffer[17], 2);
    buffer[19] = '.';
    printNumber(tSt.milliSec, &buffer[20], 3);
    printNumber(tSt.microSec, &buffer[23], 3);
    printNumber(tSt.nanoSec, &buffer[26], 3);

    size_t length = 28;
    while (buffer[length] == '0')
        length--;
    if (length != 19)
         length++;

    buffer[length] = 'Z';
    UA_String str = {length + 1, buffer};
    return ENCODE_DIRECT_JSON(&str, String);
}


static status NodeId_encodeJsonInternal(UA_NodeId const *src, CtxJson *ctx) {
    status ret = UA_STATUSCODE_GOOD;
    switch (src->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
        ret |= writeJsonKey(ctx, UA_JSONKEY_ID);
        ret |= ENCODE_DIRECT_JSON(&src->identifier.numeric, UInt32);
        break;
    case UA_NODEIDTYPE_STRING:
        ret |= writeJsonKey(ctx, UA_JSONKEY_IDTYPE);
        ret |= writeChar(ctx, '1');
        ret |= writeJsonKey(ctx, UA_JSONKEY_ID);
        ret |= ENCODE_DIRECT_JSON(&src->identifier.string, String);
        break;
    case UA_NODEIDTYPE_GUID:
        ret |= writeJsonKey(ctx, UA_JSONKEY_IDTYPE);
        ret |= writeChar(ctx, '2');
        ret |= writeJsonKey(ctx, UA_JSONKEY_ID); 
        ret |= ENCODE_DIRECT_JSON(&src->identifier.guid, Guid);
        break;
    case UA_NODEIDTYPE_BYTESTRING:
        ret |= writeJsonKey(ctx, UA_JSONKEY_IDTYPE);
        ret |= writeChar(ctx, '3');
        ret |= writeJsonKey(ctx, UA_JSONKEY_ID); 
        ret |= ENCODE_DIRECT_JSON(&src->identifier.byteString, ByteString);
        break;
    default:
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return ret;
}

ENCODE_JSON(NodeId) {
    UA_StatusCode ret = writeJsonObjStart(ctx);
    ret |= NodeId_encodeJsonInternal(src, ctx);
    if(ctx->useReversible) {
        if(src->namespaceIndex > 0) {
            ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACE);
            ret |= ENCODE_DIRECT_JSON(&src->namespaceIndex, UInt16);
        }
    } else {
        
        if(src->namespaceIndex == 1) {
            ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACE);
            ret |= ENCODE_DIRECT_JSON(&src->namespaceIndex, UInt16);
        } else {
            ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACE);
            
            
            if(src->namespaceIndex < ctx->namespacesSize && ctx->namespaces != NULL) {
                UA_String namespaceEntry = ctx->namespaces[src->namespaceIndex];
                ret |= ENCODE_DIRECT_JSON(&namespaceEntry, String);
            } else {
                return UA_STATUSCODE_BADNOTFOUND;
            }
        }
    }

    ret |= writeJsonObjEnd(ctx);
    return ret;
}


ENCODE_JSON(ExpandedNodeId) {
    status ret = writeJsonObjStart(ctx);
    
    ret |= NodeId_encodeJsonInternal(&src->nodeId, ctx);
    
    if(ctx->useReversible) {
        if(src->namespaceUri.data != NULL && src->namespaceUri.length != 0 &&  (void*) src->namespaceUri.data > UA_EMPTY_ARRAY_SENTINEL) {
             
            ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACE);
            ret |= ENCODE_DIRECT_JSON(&src->namespaceUri, String);
        } else {
            
            if(src->nodeId.namespaceIndex > 0) {
                ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACE);
                ret |= ENCODE_DIRECT_JSON(&src->nodeId.namespaceIndex, UInt16);
            }
        }

        
        if(src->serverIndex > 0) {
            ret |= writeJsonKey(ctx, UA_JSONKEY_SERVERURI);
            ret |= ENCODE_DIRECT_JSON(&src->serverIndex, UInt32);
        }

        ret |= writeJsonObjEnd(ctx);
        return ret;
    }
    
    
    

    

    if(src->namespaceUri.data != NULL && src->namespaceUri.length != 0) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACE);
        ret |= ENCODE_DIRECT_JSON(&src->namespaceUri, String);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    } else {
        if(src->nodeId.namespaceIndex == 1) {
            ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACE);
            ret |= ENCODE_DIRECT_JSON(&src->nodeId.namespaceIndex, UInt16);
            if(ret != UA_STATUSCODE_GOOD)
                return ret;
        } else {
            ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACE);

            
            if(src->nodeId.namespaceIndex < ctx->namespacesSize  && ctx->namespaces != NULL) {

                UA_String namespaceEntry = ctx->namespaces[src->nodeId.namespaceIndex];
                ret |= ENCODE_DIRECT_JSON(&namespaceEntry, String);
                if(ret != UA_STATUSCODE_GOOD)
                    return ret;
            } else {
                return UA_STATUSCODE_BADNOTFOUND;
            }
        }
    }

    

    
    if(src->serverIndex < ctx->serverUrisSize && ctx->serverUris != NULL) {
        UA_String serverUriEntry = ctx->serverUris[src->serverIndex];
        ret |= writeJsonKey(ctx, UA_JSONKEY_SERVERURI);
        ret |= ENCODE_DIRECT_JSON(&serverUriEntry, String);
    } else {
        return UA_STATUSCODE_BADNOTFOUND;
    }
    ret |= writeJsonObjEnd(ctx);
    return ret;
}


ENCODE_JSON(LocalizedText) {
    if(ctx->useReversible) {
        status ret = writeJsonObjStart(ctx);
        ret |= writeJsonKey(ctx, UA_JSONKEY_LOCALE);
        ret |= ENCODE_DIRECT_JSON(&src->locale, String);
        ret |= writeJsonKey(ctx, UA_JSONKEY_TEXT);
        ret |= ENCODE_DIRECT_JSON(&src->text, String);
        ret |= writeJsonObjEnd(ctx);
        return ret;
    }
    
    
    return ENCODE_DIRECT_JSON(&src->text, String);
}

ENCODE_JSON(QualifiedName) {
    status ret = writeJsonObjStart(ctx);
    ret |= writeJsonKey(ctx, UA_JSONKEY_NAME);
    ret |= ENCODE_DIRECT_JSON(&src->name, String);

    if(ctx->useReversible) {
        if(src->namespaceIndex != 0) {
            ret |= writeJsonKey(ctx, UA_JSONKEY_URI);
            ret |= ENCODE_DIRECT_JSON(&src->namespaceIndex, UInt16);
        }
    } else {
        
        if(src->namespaceIndex == 1) {
            ret |= writeJsonKey(ctx, UA_JSONKEY_URI);
            ret |= ENCODE_DIRECT_JSON(&src->namespaceIndex, UInt16);
        } else {
            ret |= writeJsonKey(ctx, UA_JSONKEY_URI);

             
            if(src->namespaceIndex < ctx->namespacesSize && ctx->namespaces != NULL) {
                UA_String namespaceEntry = ctx->namespaces[src->namespaceIndex];
                ret |= ENCODE_DIRECT_JSON(&namespaceEntry, String);
            } else {
                
                ret |= ENCODE_DIRECT_JSON(&src->namespaceIndex, UInt16);
            }
        }
    }

    return ret | writeJsonObjEnd(ctx);
}

ENCODE_JSON(StatusCode) {
    if(!src)
        return writeJsonNull(ctx);

    if(ctx->useReversible)
        return ENCODE_DIRECT_JSON(src, UInt32);

    if(*src == UA_STATUSCODE_GOOD)
        return writeJsonNull(ctx);

    status ret = UA_STATUSCODE_GOOD;
    ret |= writeJsonObjStart(ctx);
    ret |= writeJsonKey(ctx, UA_JSONKEY_CODE);
    ret |= ENCODE_DIRECT_JSON(src, UInt32);
    ret |= writeJsonKey(ctx, UA_JSONKEY_SYMBOL);
    const char *codename = UA_StatusCode_name(*src);
    UA_String statusDescription = UA_STRING((char*)(uintptr_t)codename);
    ret |= ENCODE_DIRECT_JSON(&statusDescription, String);
    ret |= writeJsonObjEnd(ctx);
    return ret;
}


ENCODE_JSON(ExtensionObject) {
    u8 encoding = (u8) src->encoding;
    if(encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY)
        return writeJsonNull(ctx);
    
    status ret = UA_STATUSCODE_GOOD;
    
    if(encoding <= UA_EXTENSIONOBJECT_ENCODED_XML) {
        ret |= writeJsonObjStart(ctx);
        if(ctx->useReversible) {
            ret |= writeJsonKey(ctx, UA_JSONKEY_TYPEID);
            ret |= ENCODE_DIRECT_JSON(&src->content.encoded.typeId, NodeId);
            if(ret != UA_STATUSCODE_GOOD)
                return ret;
        }
        
        switch (src->encoding) {
            case UA_EXTENSIONOBJECT_ENCODED_BYTESTRING:
            {
                if(ctx->useReversible) {
                    ret |= writeJsonKey(ctx, UA_JSONKEY_ENCODING);
                    ret |= writeChar(ctx, '1');
                }
                ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
                ret |= ENCODE_DIRECT_JSON(&src->content.encoded.body, String);
                break;
            }
            case UA_EXTENSIONOBJECT_ENCODED_XML:
            {
                if(ctx->useReversible) {
                    ret |= writeJsonKey(ctx, UA_JSONKEY_ENCODING);
                    ret |= writeChar(ctx, '2');
                }
                ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
                ret |= ENCODE_DIRECT_JSON(&src->content.encoded.body, String);
                break;
            }
            default:
                ret = UA_STATUSCODE_BADINTERNALERROR;
        }

        ret |= writeJsonObjEnd(ctx);
        return ret;
    } 
         
    
    if(!src->content.decoded.type)
        return UA_STATUSCODE_BADENCODINGERROR;

    if(!src->content.decoded.data)
        return writeJsonNull(ctx);

    UA_NodeId typeId = src->content.decoded.type->typeId;
    if(typeId.identifierType != UA_NODEIDTYPE_NUMERIC)
        return UA_STATUSCODE_BADENCODINGERROR;

    ret |= writeJsonObjStart(ctx);
    const UA_DataType *contentType = src->content.decoded.type;
    if(ctx->useReversible) {
        
        ret |= writeJsonKey(ctx, UA_JSONKEY_TYPEID);
        ret |= ENCODE_DIRECT_JSON(&typeId, NodeId);

        
        ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
        ret |= encodeJsonInternal(src->content.decoded.data, contentType, ctx);
    } else {
        
        ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
        ret |= encodeJsonInternal(src->content.decoded.data, contentType, ctx);
    }

    ret |= writeJsonObjEnd(ctx);
    return ret;
}

static status Variant_encodeJsonWrapExtensionObject(const UA_Variant *src, const bool isArray, CtxJson *ctx) {
    size_t length = 1;

    status ret = UA_STATUSCODE_GOOD;
    if(isArray) {
        if(src->arrayLength > UA_INT32_MAX)
            return UA_STATUSCODE_BADENCODINGERROR;
        
        length = src->arrayLength;
    }

    
    UA_ExtensionObject eo;
    UA_ExtensionObject_init(&eo);
    eo.encoding = UA_EXTENSIONOBJECT_DECODED;
    eo.content.decoded.type = src->type;
    const u16 memSize = src->type->memSize;
    uintptr_t ptr = (uintptr_t) src->data;

    if(isArray) {
        ret |= writeJsonArrStart(ctx);
        ctx->commaNeeded[ctx->depth] = false;

        
        for(size_t i = 0; i <  length && ret == UA_STATUSCODE_GOOD; ++i) {
            eo.content.decoded.data = (void*) ptr;
            ret |= writeJsonArrElm(ctx, &eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
            ptr += memSize;
        }
    
        ret |= writeJsonArrEnd(ctx);
        return ret;
    }

    eo.content.decoded.data = (void*) ptr;
    return encodeJsonInternal(&eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], ctx);
}

static status addMultiArrayContentJSON(CtxJson *ctx, void* array, const UA_DataType *type, size_t *index, UA_UInt32 *arrayDimensions, size_t dimensionIndex, size_t dimensionSize) {


    
    if(ctx->depth > UA_JSON_ENCODING_MAX_RECURSION)
        return UA_STATUSCODE_BADENCODINGERROR;
    
    
    status ret;
    if(dimensionIndex == (dimensionSize - 1)) {
        ret = encodeJsonArray(ctx, ((u8*)array) + (type->memSize * *index), arrayDimensions[dimensionIndex], type);
        (*index) += arrayDimensions[dimensionIndex];
        return ret;
    }

    
    ret = writeJsonArrStart(ctx);
    for(size_t i = 0; i < arrayDimensions[dimensionIndex]; i++) {
        ret |= writeJsonCommaIfNeeded(ctx);
        ret |= addMultiArrayContentJSON(ctx, array, type, index, arrayDimensions, dimensionIndex + 1, dimensionSize);
        ctx->commaNeeded[ctx->depth] = true;
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }
    ret |= writeJsonArrEnd(ctx);
    return ret;
}

ENCODE_JSON(Variant) {
    
    if(!src->type) {
        return writeJsonNull(ctx);
    }
        
    
    const UA_Boolean isBuiltin = (src->type->typeKind <= UA_DATATYPEKIND_DIAGNOSTICINFO);
    const UA_Boolean isEnum = (src->type->typeKind == UA_DATATYPEKIND_ENUM);
    
    
    const bool isArray = src->arrayLength > 0 || src->data <= UA_EMPTY_ARRAY_SENTINEL;
    const bool hasDimensions = isArray && src->arrayDimensionsSize > 0;
    status ret = UA_STATUSCODE_GOOD;
    
    if(ctx->useReversible) {
        ret |= writeJsonObjStart(ctx);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;

        
        if(!isBuiltin && !isEnum) {
            
            ret |= writeJsonKey(ctx, UA_JSONKEY_TYPE);
            ret |= ENCODE_DIRECT_JSON(&UA_TYPES[UA_TYPES_EXTENSIONOBJECT].typeId.identifier.numeric, UInt32);
            ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
            ret |= Variant_encodeJsonWrapExtensionObject(src, isArray, ctx);
        } else if(!isArray) {
            
            ret |= writeJsonKey(ctx, UA_JSONKEY_TYPE);
            ret |= ENCODE_DIRECT_JSON(&src->type->typeId.identifier.numeric, UInt32);
            ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
            ret |= encodeJsonInternal(src->data, src->type, ctx);
        } else {
            
            ret |= writeJsonKey(ctx, UA_JSONKEY_TYPE);
            ret |= ENCODE_DIRECT_JSON(&src->type->typeId.identifier.numeric, UInt32);
            ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
            ret |= encodeJsonArray(ctx, src->data, src->arrayLength, src->type);
        }
        
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
        
        
        if(hasDimensions && ret == UA_STATUSCODE_GOOD) {
            ret |= writeJsonKey(ctx, UA_JSONKEY_DIMENSION);
            ret |= encodeJsonArray(ctx, src->arrayDimensions, src->arrayDimensionsSize,  &UA_TYPES[UA_TYPES_INT32]);
            if(ret != UA_STATUSCODE_GOOD)
                return ret;
        }

        ret |= writeJsonObjEnd(ctx);
        return ret;
    } 

    
    

    ret |= writeJsonObjStart(ctx);
    if(!isBuiltin && !isEnum) {
        
        if(src->arrayDimensionsSize > 1) {
            return UA_STATUSCODE_BADNOTIMPLEMENTED;
        }

        ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
        ret |= Variant_encodeJsonWrapExtensionObject(src, isArray, ctx);
    } else if(!isArray) {
        
        ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);
        ret |= encodeJsonInternal(src->data, src->type, ctx);
    } else {
        
        ret |= writeJsonKey(ctx, UA_JSONKEY_BODY);

        size_t dimensionSize = src->arrayDimensionsSize;
        if(dimensionSize > 1) {
            
            size_t index = 0;  size_t dimensionIndex = 0;
            void *ptr = src->data;
            const UA_DataType *arraytype = src->type;
            ret |= addMultiArrayContentJSON(ctx, ptr, arraytype, &index,  src->arrayDimensions, dimensionIndex, dimensionSize);
        } else {
            
            ret |= encodeJsonArray(ctx, src->data, src->arrayLength, src->type);
        }
    }

    ret |= writeJsonObjEnd(ctx);
    return ret;
}


ENCODE_JSON(DataValue) {
    UA_Boolean hasValue = src->hasValue && src->value.type != NULL;
    UA_Boolean hasStatus = src->hasStatus && src->status;
    UA_Boolean hasSourceTimestamp = src->hasSourceTimestamp && src->sourceTimestamp;
    UA_Boolean hasSourcePicoseconds = src->hasSourcePicoseconds && src->sourcePicoseconds;
    UA_Boolean hasServerTimestamp = src->hasServerTimestamp && src->serverTimestamp;
    UA_Boolean hasServerPicoseconds = src->hasServerPicoseconds && src->serverPicoseconds;

    if(!hasValue && !hasStatus && !hasSourceTimestamp && !hasSourcePicoseconds && !hasServerTimestamp && !hasServerPicoseconds) {
        return writeJsonNull(ctx); 
    }

    status ret = UA_STATUSCODE_GOOD;
    ret |= writeJsonObjStart(ctx);

    if(hasValue) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_VALUE);
        ret |= ENCODE_DIRECT_JSON(&src->value, Variant);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(hasStatus) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_STATUS);
        ret |= ENCODE_DIRECT_JSON(&src->status, StatusCode);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(hasSourceTimestamp) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_SOURCETIMESTAMP);
        ret |= ENCODE_DIRECT_JSON(&src->sourceTimestamp, DateTime);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(hasSourcePicoseconds) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_SOURCEPICOSECONDS);
        ret |= ENCODE_DIRECT_JSON(&src->sourcePicoseconds, UInt16);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(hasServerTimestamp) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_SERVERTIMESTAMP);
        ret |= ENCODE_DIRECT_JSON(&src->serverTimestamp, DateTime);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(hasServerPicoseconds) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_SERVERPICOSECONDS);
        ret |= ENCODE_DIRECT_JSON(&src->serverPicoseconds, UInt16);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    ret |= writeJsonObjEnd(ctx);
    return ret;
}


ENCODE_JSON(DiagnosticInfo) {
    status ret = UA_STATUSCODE_GOOD;
    if(!src->hasSymbolicId && !src->hasNamespaceUri && !src->hasLocalizedText && !src->hasLocale && !src->hasAdditionalInfo && !src->hasInnerDiagnosticInfo && !src->hasInnerStatusCode) {

        return writeJsonNull(ctx); 
    }
    
    ret |= writeJsonObjStart(ctx);
    
    if(src->hasSymbolicId) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_SYMBOLICID);
        ret |= ENCODE_DIRECT_JSON(&src->symbolicId, UInt32);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(src->hasNamespaceUri) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_NAMESPACEURI);
        ret |= ENCODE_DIRECT_JSON(&src->namespaceUri, UInt32);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }
    
    if(src->hasLocalizedText) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_LOCALIZEDTEXT);
        ret |= ENCODE_DIRECT_JSON(&src->localizedText, UInt32);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }
    
    if(src->hasLocale) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_LOCALE);
        ret |= ENCODE_DIRECT_JSON(&src->locale, UInt32);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }
    
    if(src->hasAdditionalInfo) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_ADDITIONALINFO);
        ret |= ENCODE_DIRECT_JSON(&src->additionalInfo, String);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(src->hasInnerStatusCode) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_INNERSTATUSCODE);
        ret |= ENCODE_DIRECT_JSON(&src->innerStatusCode, StatusCode);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    if(src->hasInnerDiagnosticInfo && src->innerDiagnosticInfo) {
        ret |= writeJsonKey(ctx, UA_JSONKEY_INNERDIAGNOSTICINFO);
        
        ret |= encodeJsonInternal(src->innerDiagnosticInfo, &UA_TYPES[UA_TYPES_DIAGNOSTICINFO], ctx);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
    }

    ret |= writeJsonObjEnd(ctx);
    return ret;
}

static status encodeJsonStructure(const void *src, const UA_DataType *type, CtxJson *ctx) {
    
    if(ctx->depth > UA_JSON_ENCODING_MAX_RECURSION)
        return UA_STATUSCODE_BADENCODINGERROR;
    ctx->depth++;

    status ret = writeJsonObjStart(ctx);

    uintptr_t ptr = (uintptr_t) src;
    u8 membersSize = type->membersSize;
    const UA_DataType * typelists[2] = {UA_TYPES, &type[-type->typeIndex]};
    for(size_t i = 0; i < membersSize && ret == UA_STATUSCODE_GOOD; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = &typelists[!m->namespaceZero][m->memberTypeIndex];

        if(m->memberName != NULL && *m->memberName != 0)
            ret |= writeJsonKey(ctx, m->memberName);

        if(!m->isArray) {
            ptr += m->padding;
            size_t memSize = mt->memSize;
            ret |= encodeJsonJumpTable[mt->typeKind]((const void*) ptr, mt, ctx);
            ptr += memSize;
        } else {
            ptr += m->padding;
            const size_t length = *((const size_t*) ptr);
            ptr += sizeof (size_t);
            ret |= encodeJsonArray(ctx, *(void * const *)ptr, length, mt);
            ptr += sizeof (void*);
        }
    }

    ret |= writeJsonObjEnd(ctx);

    ctx->depth--;
    return ret;
}

static status encodeJsonNotImplemented(const void *src, const UA_DataType *type, CtxJson *ctx) {
    (void) src, (void) type, (void)ctx;
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

const encodeJsonSignature encodeJsonJumpTable[UA_DATATYPEKINDS] = {
    (encodeJsonSignature)Boolean_encodeJson, (encodeJsonSignature)SByte_encodeJson, (encodeJsonSignature)Byte_encodeJson, (encodeJsonSignature)Int16_encodeJson, (encodeJsonSignature)UInt16_encodeJson, (encodeJsonSignature)Int32_encodeJson, (encodeJsonSignature)UInt32_encodeJson, (encodeJsonSignature)Int64_encodeJson, (encodeJsonSignature)UInt64_encodeJson, (encodeJsonSignature)Float_encodeJson, (encodeJsonSignature)Double_encodeJson, (encodeJsonSignature)String_encodeJson, (encodeJsonSignature)DateTime_encodeJson, (encodeJsonSignature)Guid_encodeJson, (encodeJsonSignature)ByteString_encodeJson, (encodeJsonSignature)String_encodeJson, (encodeJsonSignature)NodeId_encodeJson, (encodeJsonSignature)ExpandedNodeId_encodeJson, (encodeJsonSignature)StatusCode_encodeJson, (encodeJsonSignature)QualifiedName_encodeJson, (encodeJsonSignature)LocalizedText_encodeJson, (encodeJsonSignature)ExtensionObject_encodeJson, (encodeJsonSignature)DataValue_encodeJson, (encodeJsonSignature)Variant_encodeJson, (encodeJsonSignature)DiagnosticInfo_encodeJson, (encodeJsonSignature)encodeJsonNotImplemented, (encodeJsonSignature)Int32_encodeJson, (encodeJsonSignature)encodeJsonStructure, (encodeJsonSignature)encodeJsonNotImplemented, (encodeJsonSignature)encodeJsonNotImplemented, (encodeJsonSignature)encodeJsonNotImplemented };































status encodeJsonInternal(const void *src, const UA_DataType *type, CtxJson *ctx) {
    return encodeJsonJumpTable[type->typeKind](src, type, ctx);
}

status UA_FUNC_ATTR_WARN_UNUSED_RESULT UA_encodeJson(const void *src, const UA_DataType *type, u8 **bufPos, const u8 **bufEnd, UA_String *namespaces, size_t namespaceSize, UA_String *serverUris, size_t serverUriSize, UA_Boolean useReversible) {



    if(!src || !type)
        return UA_STATUSCODE_BADINTERNALERROR;
    
    
    CtxJson ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pos = *bufPos;
    ctx.end = *bufEnd;
    ctx.depth = 0;
    ctx.namespaces = namespaces;
    ctx.namespacesSize = namespaceSize;
    ctx.serverUris = serverUris;
    ctx.serverUrisSize = serverUriSize;
    ctx.useReversible = useReversible;
    ctx.calcOnly = false;
    
    
    status ret = encodeJsonJumpTable[type->typeKind](src, type, &ctx);
    
    *bufPos = ctx.pos;
    *bufEnd = ctx.end;
    return ret;
}




size_t UA_calcSizeJson(const void *src, const UA_DataType *type, UA_String *namespaces, size_t namespaceSize, UA_String *serverUris, size_t serverUriSize, UA_Boolean useReversible) {



    if(!src || !type)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    CtxJson ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pos = 0;
    ctx.end = (const UA_Byte*)(uintptr_t)SIZE_MAX;
    ctx.depth = 0;
    ctx.namespaces = namespaces;
    ctx.namespacesSize = namespaceSize;
    ctx.serverUris = serverUris;
    ctx.serverUrisSize = serverUriSize;
    ctx.useReversible = useReversible;
    ctx.calcOnly = true;

    
    status ret = encodeJsonJumpTable[type->typeKind](src, type, &ctx);
    if(ret != UA_STATUSCODE_GOOD)
        return 0;
    return (size_t)ctx.pos;
}






































static void skipObject(ParseCtx *parseCtx) {
    int end = parseCtx->tokenArray[parseCtx->index].end;
    do {
        parseCtx->index++;
    } while(parseCtx->index < parseCtx->tokenCount && parseCtx->tokenArray[parseCtx->index].start < end);
}

static status Array_decodeJson(void *dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken);


static status Array_decodeJson_internal(void **dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken);


static status Variant_decodeJsonUnwrapExtensionObject(UA_Variant *dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken);



jsmntype_t getJsmnType(const ParseCtx *parseCtx) {
    if(parseCtx->index >= parseCtx->tokenCount)
        return JSMN_UNDEFINED;
    return parseCtx->tokenArray[parseCtx->index].type;
}

UA_Boolean isJsonNull(const CtxJson *ctx, const ParseCtx *parseCtx) {
    if(parseCtx->index >= parseCtx->tokenCount)
        return false;

    if(parseCtx->tokenArray[parseCtx->index].type != JSMN_PRIMITIVE) {
        return false;
    }
    char* elem = (char*)(ctx->pos + parseCtx->tokenArray[parseCtx->index].start);
    return (elem[0] == 'n' && elem[1] == 'u' && elem[2] == 'l' && elem[3] == 'l');
}

static UA_SByte jsoneq(const char *json, jsmntok_t *tok, const char *searchKey) {
    
    
    if(tok->type == JSMN_STRING) {
         if(strlen(searchKey) == (size_t)(tok->end - tok->start) ) {
             if(strncmp(json + tok->start, (const char*)searchKey, (size_t)(tok->end - tok->start)) == 0) {
                 return 0;
             }   
         }
    }
    return -1;
}

DECODE_JSON(Boolean) {
    CHECK_PRIMITIVE;
    CHECK_TOKEN_BOUNDS;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    if(tokenSize == 4 && tokenData[0] == 't' && tokenData[1] == 'r' && tokenData[2] == 'u' && tokenData[3] == 'e') {

        *dst = true;
    } else if(tokenSize == 5 && tokenData[0] == 'f' && tokenData[1] == 'a' && tokenData[2] == 'l' && tokenData[3] == 's' && tokenData[4] == 'e') {


        *dst = false;
    } else {
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    
    if(moveToken)
        parseCtx->index++;
    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode parseUnsignedInteger(char* inputBuffer, size_t sizeOfBuffer, UA_UInt64 *destinationOfNumber) {

    UA_UInt64 d = 0;
    atoiUnsigned(inputBuffer, sizeOfBuffer, &d);
    if(!destinationOfNumber)
        return UA_STATUSCODE_BADDECODINGERROR;
    *destinationOfNumber = d;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode parseSignedInteger(char* inputBuffer, size_t sizeOfBuffer, UA_Int64 *destinationOfNumber) {

    UA_Int64 d = 0;
    atoiSigned(inputBuffer, sizeOfBuffer, &d);
    if(!destinationOfNumber)
        return UA_STATUSCODE_BADDECODINGERROR;
    *destinationOfNumber = d;
    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode parseUnsignedInteger(char* inputBuffer, size_t sizeOfBuffer, UA_UInt64 *destinationOfNumber) {

    
    if(sizeOfBuffer > 20) {
        return UA_STATUSCODE_BADDECODINGERROR;
    }

    
    UA_STACKARRAY(char, string, sizeOfBuffer+1);
    memcpy(string, inputBuffer, sizeOfBuffer);
    string[sizeOfBuffer] = 0;

    
    char *endptr, *str;
    str = string;
    errno = 0;    
    UA_UInt64 val = strtoull(str, &endptr, 10);

    
    if((errno == ERANGE && (val == LLONG_MAX || val == 0))
          || (errno != 0 )) {
        return UA_STATUSCODE_BADDECODINGERROR;
    }

    
    if(endptr == str)
        return UA_STATUSCODE_BADDECODINGERROR;

    
    *destinationOfNumber = val;
    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode parseSignedInteger(char* inputBuffer, size_t sizeOfBuffer, UA_Int64 *destinationOfNumber) {

    
    if(sizeOfBuffer > 20)
        return UA_STATUSCODE_BADDECODINGERROR;

    
    UA_STACKARRAY(char, string, sizeOfBuffer + 1);
    memcpy(string, inputBuffer, sizeOfBuffer);
    string[sizeOfBuffer] = 0;

    
    char *endptr, *str;
    str = string;
    errno = 0;    
    UA_Int64 val = strtoll(str, &endptr, 10);

    
    if((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
          || (errno != 0 )) {
        return UA_STATUSCODE_BADDECODINGERROR;
    }

    
    if(endptr == str)
        return UA_STATUSCODE_BADDECODINGERROR;

    
    *destinationOfNumber = val;
    return UA_STATUSCODE_GOOD;
}


DECODE_JSON(Byte) {
    CHECK_TOKEN_BOUNDS;
    CHECK_PRIMITIVE;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    UA_UInt64 out = 0;
    UA_StatusCode s = parseUnsignedInteger(tokenData, tokenSize, &out);
    *dst = (UA_Byte)out;

    if(moveToken)
        parseCtx->index++;
    return s;
}

DECODE_JSON(UInt16) {
    CHECK_TOKEN_BOUNDS;
    CHECK_PRIMITIVE;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    UA_UInt64 out = 0;
    UA_StatusCode s = parseUnsignedInteger(tokenData, tokenSize, &out);
    *dst = (UA_UInt16)out;

    if(moveToken)
        parseCtx->index++;
    return s;
}

DECODE_JSON(UInt32) {
    CHECK_TOKEN_BOUNDS;
    CHECK_PRIMITIVE;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    UA_UInt64 out = 0;
    UA_StatusCode s = parseUnsignedInteger(tokenData, tokenSize, &out);
    *dst = (UA_UInt32)out;

    if(moveToken)
        parseCtx->index++;
    return s;
}

DECODE_JSON(UInt64) {
    CHECK_TOKEN_BOUNDS;
    CHECK_STRING;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    UA_UInt64 out = 0;
    UA_StatusCode s = parseUnsignedInteger(tokenData, tokenSize, &out);
    *dst = (UA_UInt64)out;

    if(moveToken)
        parseCtx->index++;
    return s;
}

DECODE_JSON(SByte) {
    CHECK_TOKEN_BOUNDS;
    CHECK_PRIMITIVE;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    UA_Int64 out = 0;
    UA_StatusCode s = parseSignedInteger(tokenData, tokenSize, &out);
    *dst = (UA_SByte)out;

    if(moveToken)
        parseCtx->index++;
    return s;
}

DECODE_JSON(Int16) {
    CHECK_TOKEN_BOUNDS;
    CHECK_PRIMITIVE;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    UA_Int64 out = 0;
    UA_StatusCode s = parseSignedInteger(tokenData, tokenSize, &out);
    *dst = (UA_Int16)out;

    if(moveToken)
        parseCtx->index++;
    return s;
}

DECODE_JSON(Int32) {
    CHECK_TOKEN_BOUNDS;
    CHECK_PRIMITIVE;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    UA_Int64 out = 0;
    UA_StatusCode s = parseSignedInteger(tokenData, tokenSize, &out);
    *dst = (UA_Int32)out;

    if(moveToken)
        parseCtx->index++;
    return s;
}

DECODE_JSON(Int64) {
    CHECK_TOKEN_BOUNDS;
    CHECK_STRING;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    UA_Int64 out = 0;
    UA_StatusCode s = parseSignedInteger(tokenData, tokenSize, &out);
    *dst = (UA_Int64)out;

    if(moveToken)
        parseCtx->index++;
    return s;
}

static UA_UInt32 hex2int(char ch) {
    if(ch >= '0' && ch <= '9')
        return (UA_UInt32)(ch - '0');
    if(ch >= 'A' && ch <= 'F')
        return (UA_UInt32)(ch - 'A' + 10);
    if(ch >= 'a' && ch <= 'f')
        return (UA_UInt32)(ch - 'a' + 10);
    return 0;
}


DECODE_JSON(Float) {
    CHECK_TOKEN_BOUNDS;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);
    
    
    if(tokenSize > 150)
        return UA_STATUSCODE_BADDECODINGERROR;

    jsmntype_t tokenType = getJsmnType(parseCtx);
    if(tokenType == JSMN_STRING) {
        
        if(tokenSize == 8 && memcmp(tokenData, "Infinity", 8) == 0) {
            *dst = (UA_Float)INFINITY;
            return UA_STATUSCODE_GOOD;
        }
        
        if(tokenSize == 9 && memcmp(tokenData, "-Infinity", 9) == 0) {
            
            *dst = (UA_Float)-INFINITY;
            return UA_STATUSCODE_GOOD;
        }
        
        if(tokenSize == 3 && memcmp(tokenData, "NaN", 3) == 0) {
            *dst = (UA_Float)NAN;
            return UA_STATUSCODE_GOOD;
        }
        
        if(tokenSize == 4 && memcmp(tokenData, "-NaN", 4) == 0) {
            *dst = (UA_Float)NAN;
            return UA_STATUSCODE_GOOD;
        }
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    
    if(tokenType != JSMN_PRIMITIVE)
        return UA_STATUSCODE_BADDECODINGERROR;

    
    UA_STACKARRAY(char, string, tokenSize+1);
    memcpy(string, tokenData, tokenSize);
    string[tokenSize] = 0;
    
    UA_Float d = 0;

    d = (UA_Float)__floatscan(string, 1, 0);

    char c = 0;
    
    int ret = sscanf(string, "%f%c", &d, &c);

    
    if(ret == EOF || (ret != 1))
        return UA_STATUSCODE_BADDECODINGERROR;

    
    *dst = d;

    parseCtx->index++;
    return UA_STATUSCODE_GOOD;
}


DECODE_JSON(Double) {
    CHECK_TOKEN_BOUNDS;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);
    
    
    if(tokenSize > 1075)
        return UA_STATUSCODE_BADDECODINGERROR;

    jsmntype_t tokenType = getJsmnType(parseCtx);
    if(tokenType == JSMN_STRING) {
        
        if(tokenSize == 8 && memcmp(tokenData, "Infinity", 8) == 0) {
            *dst = INFINITY;
            return UA_STATUSCODE_GOOD;
        }
        
        if(tokenSize == 9 && memcmp(tokenData, "-Infinity", 9) == 0) {
            
            *dst = -INFINITY;
            return UA_STATUSCODE_GOOD;
        }
        
        if(tokenSize == 3 && memcmp(tokenData, "NaN", 3) == 0) {
            *dst = NAN;
            return UA_STATUSCODE_GOOD;
        }
        
        if(tokenSize == 4 && memcmp(tokenData, "-NaN", 4) == 0) {
            *dst = NAN;
            return UA_STATUSCODE_GOOD;
        }
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    
    if(tokenType != JSMN_PRIMITIVE)
        return UA_STATUSCODE_BADDECODINGERROR;

    
    UA_STACKARRAY(char, string, tokenSize+1);
    memcpy(string, tokenData, tokenSize);
    string[tokenSize] = 0;
    
    UA_Double d = 0;

    d = (UA_Double)__floatscan(string, 2, 0);

    char c = 0;
    
    int ret = sscanf(string, "%lf%c", &d, &c);

    
    if(ret == EOF || (ret != 1))
        return UA_STATUSCODE_BADDECODINGERROR;

    
    *dst = d;

    parseCtx->index++;
    return UA_STATUSCODE_GOOD;
}


static UA_Guid UA_Guid_fromChars(const char* chars) {
    UA_Guid dst;
    UA_Guid_init(&dst);
    for(size_t i = 0; i < 8; i++)
        dst.data1 |= (UA_UInt32)(hex2int(chars[i]) << (28 - (i*4)));
    for(size_t i = 0; i < 4; i++) {
        dst.data2 |= (UA_UInt16)(hex2int(chars[9+i]) << (12 - (i*4)));
        dst.data3 |= (UA_UInt16)(hex2int(chars[14+i]) << (12 - (i*4)));
    }
    dst.data4[0] |= (UA_Byte)(hex2int(chars[19]) << 4u);
    dst.data4[0] |= (UA_Byte)(hex2int(chars[20]) << 0u);
    dst.data4[1] |= (UA_Byte)(hex2int(chars[21]) << 4u);
    dst.data4[1] |= (UA_Byte)(hex2int(chars[22]) << 0u);
    for(size_t i = 0; i < 6; i++) {
        dst.data4[2+i] |= (UA_Byte)(hex2int(chars[24 + i*2]) << 4u);
        dst.data4[2+i] |= (UA_Byte)(hex2int(chars[25 + i*2]) << 0u);
    }
    return dst;
}

DECODE_JSON(Guid) {
    CHECK_STRING;
    CHECK_TOKEN_BOUNDS;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    if(tokenSize != 36)
        return UA_STATUSCODE_BADDECODINGERROR;

    
    for(size_t i = 0; i < tokenSize; i++) {
        if(!(tokenData[i] == '-' || (tokenData[i] >= '0' && tokenData[i] <= '9')
                || (tokenData[i] >= 'A' && tokenData[i] <= 'F')
                || (tokenData[i] >= 'a' && tokenData[i] <= 'f'))) {
            return UA_STATUSCODE_BADDECODINGERROR;
        }
    }

    *dst = UA_Guid_fromChars(tokenData);

    if(moveToken)
        parseCtx->index++;
    return UA_STATUSCODE_GOOD;
}

DECODE_JSON(String) {
    ALLOW_NULL;
    CHECK_STRING;
    CHECK_TOKEN_BOUNDS;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    
    if(tokenSize == 0) {
        dst->data = (UA_Byte*)UA_EMPTY_ARRAY_SENTINEL;
        dst->length = 0;
        if(moveToken)
            parseCtx->index++;
        return UA_STATUSCODE_GOOD;
    }
    
    
    char *outputBuffer = (char*)UA_malloc(tokenSize);
    if(!outputBuffer)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    
    const char *p = (char*)tokenData;
    const char *end = (char*)&tokenData[tokenSize];
    char *pos = outputBuffer;
    while(p < end) {
        
        if(*p != '\\') {
            *(pos++) = *(p++);
            continue;
        }

        
        p++;
        if(p == end)
            goto cleanup;
        
        if(*p != 'u') {
            switch(*p) {
            case '"': case '\\': case '/': *pos = *p; break;
            case 'b': *pos = '\b'; break;
            case 'f': *pos = '\f'; break;
            case 'n': *pos = '\n'; break;
            case 'r': *pos = '\r'; break;
            case 't': *pos = '\t'; break;
            default: goto cleanup;
            }
            pos++;
            p++;
            continue;
        }
            
        
        if(p + 4 >= end)
            goto cleanup;
        int32_t value_signed = decode_unicode_escape(p);
        if(value_signed < 0)
            goto cleanup;
        uint32_t value = (uint32_t)value_signed;
        p += 5;

        if(0xD800 <= value && value <= 0xDBFF) {
            
            if(p + 5 >= end)
                goto cleanup;
            if(*p != '\\' || *(p + 1) != 'u')
                goto cleanup;
            int32_t value2 = decode_unicode_escape(p + 1);
            if(value2 < 0xDC00 || value2 > 0xDFFF)
                goto cleanup;
            value = ((value - 0xD800u) << 10u) + (uint32_t)((value2 - 0xDC00) + 0x10000);
            p += 6;
        } else if(0xDC00 <= value && value <= 0xDFFF) {
            
            goto cleanup;
        }

        size_t length;
        if(utf8_encode((int32_t)value, pos, &length))
            goto cleanup;

        pos += length;
    }

    dst->length = (size_t)(pos - outputBuffer);
    if(dst->length > 0) {
        dst->data = (UA_Byte*)outputBuffer;
    } else {
        dst->data = (UA_Byte*)UA_EMPTY_ARRAY_SENTINEL;
        UA_free(outputBuffer);
    }

    if(moveToken)
        parseCtx->index++;
    return UA_STATUSCODE_GOOD;
    
cleanup:
    UA_free(outputBuffer);  
    return UA_STATUSCODE_BADDECODINGERROR;
}

DECODE_JSON(ByteString) {
    ALLOW_NULL;
    CHECK_STRING;
    CHECK_TOKEN_BOUNDS;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);

    
    if(tokenSize == 0) {
        dst->data = (UA_Byte*)UA_EMPTY_ARRAY_SENTINEL;
        dst->length = 0;
        return UA_STATUSCODE_GOOD;
    }

    size_t flen = 0;
    unsigned char* unB64 = UA_unbase64((unsigned char*)tokenData, tokenSize, &flen);
    if(unB64 == 0)
        return UA_STATUSCODE_BADDECODINGERROR;

    dst->data = (u8*)unB64;
    dst->length = flen;
    
    if(moveToken)
        parseCtx->index++;
    return UA_STATUSCODE_GOOD;
}

DECODE_JSON(LocalizedText) {
    ALLOW_NULL;
    CHECK_OBJECT;

    DecodeEntry entries[2] = {
        {UA_JSONKEY_LOCALE, &dst->locale, (decodeJsonSignature) String_decodeJson, false, NULL}, {UA_JSONKEY_TEXT, &dst->text, (decodeJsonSignature) String_decodeJson, false, NULL}
    };

    return decodeFields(ctx, parseCtx, entries, 2, type);
}

DECODE_JSON(QualifiedName) {
    ALLOW_NULL;
    CHECK_OBJECT;

    DecodeEntry entries[2] = {
        {UA_JSONKEY_NAME, &dst->name, (decodeJsonSignature) String_decodeJson, false, NULL}, {UA_JSONKEY_URI, &dst->namespaceIndex, (decodeJsonSignature) UInt16_decodeJson, false, NULL}
    };

    return decodeFields(ctx, parseCtx, entries, 2, type);
}


static status searchObjectForKeyRec(const char *searchKey, CtxJson *ctx, ParseCtx *parseCtx, size_t *resultIndex, UA_UInt16 depth) {

    UA_StatusCode ret = UA_STATUSCODE_BADNOTFOUND;
    
    CHECK_TOKEN_BOUNDS;
    
    if(parseCtx->tokenArray[parseCtx->index].type == JSMN_OBJECT) {
        size_t objectCount = (size_t)parseCtx->tokenArray[parseCtx->index].size;
        parseCtx->index++; 
        
        for(size_t i = 0; i < objectCount; i++) {
            CHECK_TOKEN_BOUNDS;
            if(depth == 0) { 
                if(jsoneq((char*)ctx->pos, &parseCtx->tokenArray[parseCtx->index], searchKey) == 0) {
                    
                    parseCtx->index++; 
                    if (parseCtx->index >= parseCtx->tokenCount)
                        
                        return UA_STATUSCODE_BADOUTOFRANGE;
                    *resultIndex = parseCtx->index;
                    return UA_STATUSCODE_GOOD;
                }
            }
               
            parseCtx->index++; 
            CHECK_TOKEN_BOUNDS;
            
            if(parseCtx->tokenArray[parseCtx->index].type == JSMN_OBJECT) {
               ret = searchObjectForKeyRec(searchKey, ctx, parseCtx, resultIndex, (UA_UInt16)(depth + 1));
            } else if(parseCtx->tokenArray[parseCtx->index].type == JSMN_ARRAY) {
               ret = searchObjectForKeyRec(searchKey, ctx, parseCtx, resultIndex, (UA_UInt16)(depth + 1));
            } else {
                
                parseCtx->index++;
            }
        }
    } else if(parseCtx->tokenArray[parseCtx->index].type == JSMN_ARRAY) {
        size_t arraySize = (size_t)parseCtx->tokenArray[parseCtx->index].size;
        parseCtx->index++; 
        
        for(size_t i = 0; i < arraySize; i++) {
            CHECK_TOKEN_BOUNDS;
            if(parseCtx->tokenArray[parseCtx->index].type == JSMN_OBJECT) {
               ret = searchObjectForKeyRec(searchKey, ctx, parseCtx, resultIndex, (UA_UInt16)(depth + 1));
            } else if(parseCtx->tokenArray[parseCtx->index].type == JSMN_ARRAY) {
               ret = searchObjectForKeyRec(searchKey, ctx, parseCtx, resultIndex, (UA_UInt16)(depth + 1));
            } else {
                
                parseCtx->index++;
            }
        }
    }
    return ret;
}

UA_FUNC_ATTR_WARN_UNUSED_RESULT status lookAheadForKey(const char* search, CtxJson *ctx, ParseCtx *parseCtx, size_t *resultIndex) {

    UA_UInt16 oldIndex = parseCtx->index; 
    
    UA_UInt16 depth = 0;
    UA_StatusCode ret  = searchObjectForKeyRec(search, ctx, parseCtx, resultIndex, depth);

    parseCtx->index = oldIndex; 
    return ret;
}


static status jumpOverRec(CtxJson *ctx, ParseCtx *parseCtx, size_t *resultIndex, UA_UInt16 depth) {

    UA_StatusCode ret = UA_STATUSCODE_BADDECODINGERROR;
    CHECK_TOKEN_BOUNDS;
    
    if(parseCtx->tokenArray[parseCtx->index].type == JSMN_OBJECT) {
        size_t objectCount = (size_t)(parseCtx->tokenArray[parseCtx->index].size);
        
        parseCtx->index++; 
        CHECK_TOKEN_BOUNDS;
        
        size_t i;
        for(i = 0; i < objectCount; i++) {
            CHECK_TOKEN_BOUNDS;
             
            parseCtx->index++; 
            CHECK_TOKEN_BOUNDS;
            
            if(parseCtx->tokenArray[parseCtx->index].type == JSMN_OBJECT) {
               jumpOverRec(ctx, parseCtx, resultIndex, (UA_UInt16)(depth + 1));
            } else if(parseCtx->tokenArray[parseCtx->index].type == JSMN_ARRAY) {
               jumpOverRec(ctx, parseCtx, resultIndex, (UA_UInt16)(depth + 1));
            } else {
                
                parseCtx->index++;
            }
        }
    } else if(parseCtx->tokenArray[parseCtx->index].type == JSMN_ARRAY) {
        size_t arraySize = (size_t)(parseCtx->tokenArray[parseCtx->index].size);
        
        parseCtx->index++; 
        CHECK_TOKEN_BOUNDS;
        
        size_t i;
        for(i = 0; i < arraySize; i++) {
            if(parseCtx->tokenArray[parseCtx->index].type == JSMN_OBJECT) {
               jumpOverRec(ctx, parseCtx, resultIndex, (UA_UInt16)(depth + 1));
            } else if(parseCtx->tokenArray[parseCtx->index].type == JSMN_ARRAY) {
               jumpOverRec(ctx, parseCtx, resultIndex, (UA_UInt16)(depth + 1));
            } else {
                
                parseCtx->index++;
            }
        }
    }
    return ret;
}

static status jumpOverObject(CtxJson *ctx, ParseCtx *parseCtx, size_t *resultIndex) {
    UA_UInt16 oldIndex = parseCtx->index; 
    UA_UInt16 depth = 0;
    jumpOverRec(ctx, parseCtx, resultIndex, depth);
    *resultIndex = parseCtx->index;
    parseCtx->index = oldIndex; 
    return UA_STATUSCODE_GOOD;
}

static status prepareDecodeNodeIdJson(UA_NodeId *dst, CtxJson *ctx, ParseCtx *parseCtx, u8 *fieldCount, DecodeEntry *entries) {

    
    
    entries[*fieldCount].fieldName = UA_JSONKEY_ID;
    entries[*fieldCount].found = false;
    entries[*fieldCount].type = NULL;
    
    
    UA_Boolean hasIdType = false;
    size_t searchResult = 0; 
    status ret = lookAheadForKey(UA_JSONKEY_IDTYPE, ctx, parseCtx, &searchResult);
    if(ret == UA_STATUSCODE_GOOD) { 
         hasIdType = true;
    }
    
    if(hasIdType) {
        size_t size = (size_t)(parseCtx->tokenArray[searchResult].end - parseCtx->tokenArray[searchResult].start);
        if(size < 1) {
            return UA_STATUSCODE_BADDECODINGERROR;
        }

        char *idType = (char*)(ctx->pos + parseCtx->tokenArray[searchResult].start);
      
        if(idType[0] == '2') {
            dst->identifierType = UA_NODEIDTYPE_GUID;
            entries[*fieldCount].fieldPointer = &dst->identifier.guid;
            entries[*fieldCount].function = (decodeJsonSignature) Guid_decodeJson;
        } else if(idType[0] == '1') {
            dst->identifierType = UA_NODEIDTYPE_STRING;
            entries[*fieldCount].fieldPointer = &dst->identifier.string;
            entries[*fieldCount].function = (decodeJsonSignature) String_decodeJson;
        } else if(idType[0] == '3') {
            dst->identifierType = UA_NODEIDTYPE_BYTESTRING;
            entries[*fieldCount].fieldPointer = &dst->identifier.byteString;
            entries[*fieldCount].function = (decodeJsonSignature) ByteString_decodeJson;
        } else {
            return UA_STATUSCODE_BADDECODINGERROR;
        }
        
        
        (*fieldCount)++;
        
        entries[*fieldCount].fieldName = UA_JSONKEY_IDTYPE;
        entries[*fieldCount].fieldPointer = NULL;
        entries[*fieldCount].function = NULL;
        entries[*fieldCount].found = false;
        entries[*fieldCount].type = NULL;
        
        
        (*fieldCount)++;
    } else {
        dst->identifierType = UA_NODEIDTYPE_NUMERIC;
        entries[*fieldCount].fieldPointer = &dst->identifier.numeric;
        entries[*fieldCount].function = (decodeJsonSignature) UInt32_decodeJson;
        entries[*fieldCount].type = NULL;
        (*fieldCount)++;
    }
    
    return UA_STATUSCODE_GOOD;
}

DECODE_JSON(NodeId) {
    ALLOW_NULL;
    CHECK_OBJECT;

    
    UA_Boolean hasNamespace = false;
    size_t searchResultNamespace = 0;
    status ret = lookAheadForKey(UA_JSONKEY_NAMESPACE, ctx, parseCtx, &searchResultNamespace);
    if(ret != UA_STATUSCODE_GOOD) {
        dst->namespaceIndex = 0;
    } else {
        hasNamespace = true;
    }
    
    
    u8 fieldCount = 0;
    DecodeEntry entries[3];
    ret = prepareDecodeNodeIdJson(dst, ctx, parseCtx, &fieldCount, entries);
    if(ret != UA_STATUSCODE_GOOD)
        return ret;

    if(hasNamespace) {
        entries[fieldCount].fieldName = UA_JSONKEY_NAMESPACE;
        entries[fieldCount].fieldPointer = &dst->namespaceIndex;
        entries[fieldCount].function = (decodeJsonSignature) UInt16_decodeJson;
        entries[fieldCount].found = false;
        entries[fieldCount].type = NULL;
        fieldCount++;
    } else {
        dst->namespaceIndex = 0;
    }
    ret = decodeFields(ctx, parseCtx, entries, fieldCount, type);
    return ret;
}

DECODE_JSON(ExpandedNodeId) {
    ALLOW_NULL;
    CHECK_OBJECT;

    
    u8 fieldCount = 0;
    
    
    UA_Boolean hasServerUri = false;
    size_t searchResultServerUri = 0;
    status ret = lookAheadForKey(UA_JSONKEY_SERVERURI, ctx, parseCtx, &searchResultServerUri);
    if(ret != UA_STATUSCODE_GOOD) {
        dst->serverIndex = 0; 
    } else {
        hasServerUri = true;
    }
    
    
    UA_Boolean hasNamespace = false;
    UA_Boolean isNamespaceString = false;
    size_t searchResultNamespace = 0;
    ret = lookAheadForKey(UA_JSONKEY_NAMESPACE, ctx, parseCtx, &searchResultNamespace);
    if(ret != UA_STATUSCODE_GOOD) {
        dst->namespaceUri = UA_STRING_NULL;
    } else {
        hasNamespace = true;
        jsmntok_t nsToken = parseCtx->tokenArray[searchResultNamespace];
        if(nsToken.type == JSMN_STRING)
            isNamespaceString = true;
    }

    DecodeEntry entries[4];
    ret = prepareDecodeNodeIdJson(&dst->nodeId, ctx, parseCtx, &fieldCount, entries);
    if(ret != UA_STATUSCODE_GOOD)
        return ret;

    if(hasNamespace) {
        entries[fieldCount].fieldName = UA_JSONKEY_NAMESPACE;
        if(isNamespaceString) {
            entries[fieldCount].fieldPointer = &dst->namespaceUri;
            entries[fieldCount].function = (decodeJsonSignature) String_decodeJson;
        } else {
            entries[fieldCount].fieldPointer = &dst->nodeId.namespaceIndex;
            entries[fieldCount].function = (decodeJsonSignature) UInt16_decodeJson;
        }
        entries[fieldCount].found = false;
        entries[fieldCount].type = NULL;
        fieldCount++; 
    }
    
    if(hasServerUri) {
        entries[fieldCount].fieldName = UA_JSONKEY_SERVERURI;
        entries[fieldCount].fieldPointer = &dst->serverIndex;
        entries[fieldCount].function = (decodeJsonSignature) UInt32_decodeJson;
        entries[fieldCount].found = false;
        entries[fieldCount].type = NULL;
        fieldCount++;  
    } else {
        dst->serverIndex = 0;
    }
    
    return decodeFields(ctx, parseCtx, entries, fieldCount, type);
}

DECODE_JSON(DateTime) {
    CHECK_STRING;
    CHECK_TOKEN_BOUNDS;
    size_t tokenSize;
    char* tokenData;
    GET_TOKEN(tokenData, tokenSize);
    
    
    
    if(tokenSize != 20 && tokenSize != 24) {
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    
    
    if(tokenData[4] != '-' || tokenData[7] != '-' || tokenData[10] != 'T' || tokenData[13] != ':' || tokenData[16] != ':' || !(tokenData[19] == 'Z' || tokenData[19] == '.')) {

        return UA_STATUSCODE_BADDECODINGERROR;
    }
    
    struct mytm dts;
    memset(&dts, 0, sizeof(dts));
    
    UA_UInt64 year = 0;
    atoiUnsigned(&tokenData[0], 4, &year);
    dts.tm_year = (UA_UInt16)year - 1900;
    UA_UInt64 month = 0;
    atoiUnsigned(&tokenData[5], 2, &month);
    dts.tm_mon = (UA_UInt16)month - 1;
    UA_UInt64 day = 0;
    atoiUnsigned(&tokenData[8], 2, &day);
    dts.tm_mday = (UA_UInt16)day;
    UA_UInt64 hour = 0;
    atoiUnsigned(&tokenData[11], 2, &hour);
    dts.tm_hour = (UA_UInt16)hour;
    UA_UInt64 min = 0;
    atoiUnsigned(&tokenData[14], 2, &min);
    dts.tm_min = (UA_UInt16)min;
    UA_UInt64 sec = 0;
    atoiUnsigned(&tokenData[17], 2, &sec);
    dts.tm_sec = (UA_UInt16)sec;
    
    UA_UInt64 msec = 0;
    if(tokenSize == 24) {
        atoiUnsigned(&tokenData[20], 3, &msec);
    }
    
    long long sinceunix = __tm_to_secs(&dts);
    UA_DateTime dt = (UA_DateTime)((UA_UInt64)(sinceunix*UA_DATETIME_SEC + UA_DATETIME_UNIX_EPOCH) + (UA_UInt64)(UA_DATETIME_MSEC * msec));

    *dst = dt;
  
    if(moveToken)
        parseCtx->index++;
    return UA_STATUSCODE_GOOD;
}

DECODE_JSON(StatusCode) {
    status ret = DECODE_DIRECT_JSON(dst, UInt32);
    if(ret != UA_STATUSCODE_GOOD)
        return ret;

    if(moveToken)
        parseCtx->index++;
    return UA_STATUSCODE_GOOD;
}

static status VariantDimension_decodeJson(void * dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken) {

    (void) type;
    const UA_DataType *dimType = &UA_TYPES[UA_TYPES_UINT32];
    return Array_decodeJson_internal((void**)dst, dimType, ctx, parseCtx, moveToken);
}

DECODE_JSON(Variant) {
    ALLOW_NULL;
    CHECK_OBJECT;

    
    size_t searchResultType = 0;
    status ret = lookAheadForKey(UA_JSONKEY_TYPE, ctx, parseCtx, &searchResultType);
    if(ret != UA_STATUSCODE_GOOD) {
        skipObject(parseCtx);
        return UA_STATUSCODE_GOOD;
    }

    size_t size = ((size_t)parseCtx->tokenArray[searchResultType].end - (size_t)parseCtx->tokenArray[searchResultType].start);

    
    if(size < 1 || parseCtx->tokenArray[searchResultType].type != JSMN_PRIMITIVE)
        return UA_STATUSCODE_BADDECODINGERROR;
    
    
    UA_UInt64 idTypeDecoded = 0;
    char *idTypeEncoded = (char*)(ctx->pos + parseCtx->tokenArray[searchResultType].start);
    status typeDecodeStatus = atoiUnsigned(idTypeEncoded, size, &idTypeDecoded);
    if(typeDecodeStatus != UA_STATUSCODE_GOOD)
        return typeDecodeStatus;

    
    if(idTypeDecoded == 0) {
        skipObject(parseCtx);
        return UA_STATUSCODE_GOOD;
    }

    
    UA_NodeId typeNodeId = UA_NODEID_NUMERIC(0, (UA_UInt32)idTypeDecoded);
    dst->type = UA_findDataType(&typeNodeId);
    if(!dst->type)
        return UA_STATUSCODE_BADDECODINGERROR;
    
    
    size_t searchResultBody = 0;
    ret = lookAheadForKey(UA_JSONKEY_BODY, ctx, parseCtx, &searchResultBody);
    if(ret != UA_STATUSCODE_GOOD) {
        
        return UA_STATUSCODE_BADDECODINGERROR;
    }

    
    UA_Boolean isArray = false;
    if(parseCtx->tokenArray[searchResultBody].type == JSMN_ARRAY) {
        isArray = true;
        dst->arrayLength = (size_t)parseCtx->tokenArray[searchResultBody].size;
    }

    
    UA_Boolean hasDimension = false;
    size_t searchResultDim = 0;
    ret = lookAheadForKey(UA_JSONKEY_DIMENSION, ctx, parseCtx, &searchResultDim);
    if(ret == UA_STATUSCODE_GOOD) {
        hasDimension = true;
        dst->arrayDimensionsSize = (size_t)parseCtx->tokenArray[searchResultDim].size;
    }
    
    
    if(!isArray && hasDimension)
        return UA_STATUSCODE_BADDECODINGERROR;
    
    
    if(dst->type->typeKind > UA_TYPES_DIAGNOSTICINFO)
        return UA_STATUSCODE_BADDECODINGERROR;

    
    if(dst->type->typeKind == UA_DATATYPEKIND_VARIANT && !isArray)
        return UA_STATUSCODE_BADDECODINGERROR;
    
    
    if(isArray) {
        DecodeEntry entries[3] = {
            {UA_JSONKEY_TYPE, NULL, NULL, false, NULL}, {UA_JSONKEY_BODY, &dst->data, (decodeJsonSignature) Array_decodeJson, false, NULL}, {UA_JSONKEY_DIMENSION, &dst->arrayDimensions, (decodeJsonSignature) VariantDimension_decodeJson, false, NULL}};


        if(!hasDimension) {
            ret = decodeFields(ctx, parseCtx, entries, 2, dst->type); 
        } else {
            ret = decodeFields(ctx, parseCtx, entries, 3, dst->type); 
        }      
        return ret;
    }

    
    if(dst->type->typeKind == UA_DATATYPEKIND_EXTENSIONOBJECT) {
        DecodeEntry entries[2] = {{UA_JSONKEY_TYPE, NULL, NULL, false, NULL}, {UA_JSONKEY_BODY, dst, (decodeJsonSignature)Variant_decodeJsonUnwrapExtensionObject, false, NULL}};


        return decodeFields(ctx, parseCtx, entries, 2, dst->type);
    }

    
    dst->data = UA_new(dst->type);
    if(!dst->data)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    DecodeEntry entries[2] = {{UA_JSONKEY_TYPE, NULL, NULL, false, NULL}, {UA_JSONKEY_BODY, dst->data, (decodeJsonSignature) decodeJsonInternal, false, NULL}};

    return decodeFields(ctx, parseCtx, entries, 2, dst->type);
}

DECODE_JSON(DataValue) {
    ALLOW_NULL;
    CHECK_OBJECT;

    DecodeEntry entries[6] = {
       {UA_JSONKEY_VALUE, &dst->value, (decodeJsonSignature) Variant_decodeJson, false, NULL}, {UA_JSONKEY_STATUS, &dst->status, (decodeJsonSignature) StatusCode_decodeJson, false, NULL}, {UA_JSONKEY_SOURCETIMESTAMP, &dst->sourceTimestamp, (decodeJsonSignature) DateTime_decodeJson, false, NULL}, {UA_JSONKEY_SOURCEPICOSECONDS, &dst->sourcePicoseconds, (decodeJsonSignature) UInt16_decodeJson, false, NULL}, {UA_JSONKEY_SERVERTIMESTAMP, &dst->serverTimestamp, (decodeJsonSignature) DateTime_decodeJson, false, NULL}, {UA_JSONKEY_SERVERPICOSECONDS, &dst->serverPicoseconds, (decodeJsonSignature) UInt16_decodeJson, false, NULL}};





    status ret = decodeFields(ctx, parseCtx, entries, 6, type);
    dst->hasValue = entries[0].found; dst->hasStatus = entries[1].found;
    dst->hasSourceTimestamp = entries[2].found; dst->hasSourcePicoseconds = entries[3].found;
    dst->hasServerTimestamp = entries[4].found; dst->hasServerPicoseconds = entries[5].found;
    return ret;
}

DECODE_JSON(ExtensionObject) {
    ALLOW_NULL;
    CHECK_OBJECT;

    
    size_t searchEncodingResult = 0;
    status ret = lookAheadForKey(UA_JSONKEY_ENCODING, ctx, parseCtx, &searchEncodingResult);
    
    
    if(ret != UA_STATUSCODE_GOOD) {
        UA_NodeId typeId;
        UA_NodeId_init(&typeId);

        size_t searchTypeIdResult = 0;
        ret = lookAheadForKey(UA_JSONKEY_TYPEID, ctx, parseCtx, &searchTypeIdResult);
        if(ret != UA_STATUSCODE_GOOD) {
            
            return UA_STATUSCODE_BADENCODINGERROR;
        }

        
        
        UA_UInt16 index = parseCtx->index;
        parseCtx->index = (UA_UInt16)searchTypeIdResult;
        ret = NodeId_decodeJson(&typeId, &UA_TYPES[UA_TYPES_NODEID], ctx, parseCtx, true);
        if(ret != UA_STATUSCODE_GOOD)
            return ret;
        
        
        parseCtx->index = index;
        const UA_DataType *typeOfBody = UA_findDataType(&typeId);
        if(!typeOfBody) {
            
            dst->encoding = UA_EXTENSIONOBJECT_ENCODED_BYTESTRING;
            UA_NodeId_copy(&typeId, &dst->content.encoded.typeId);
            
            
            if(getJsmnType(parseCtx) != JSMN_OBJECT) {
                UA_NodeId_deleteMembers(&typeId);
                return UA_STATUSCODE_BADDECODINGERROR;
            }
            
            
            size_t searchBodyResult = 0;
            ret = lookAheadForKey(UA_JSONKEY_BODY, ctx, parseCtx, &searchBodyResult);
            if(ret != UA_STATUSCODE_GOOD) {
                
                UA_NodeId_deleteMembers(&typeId);
                return UA_STATUSCODE_BADDECODINGERROR;
            }
            
            if(searchBodyResult >= (size_t)parseCtx->tokenCount) {
                
                UA_NodeId_deleteMembers(&typeId);
                return UA_STATUSCODE_BADDECODINGERROR;
            }

            
            UA_Int64 sizeOfJsonString =(parseCtx->tokenArray[searchBodyResult].end - parseCtx->tokenArray[searchBodyResult].start);
            
            char* bodyJsonString = (char*)(ctx->pos + parseCtx->tokenArray[searchBodyResult].start);
            
            if(sizeOfJsonString <= 0) {
                UA_NodeId_deleteMembers(&typeId);
                return UA_STATUSCODE_BADDECODINGERROR;
            }
            
            
            ret = UA_ByteString_allocBuffer(&dst->content.encoded.body, (size_t)sizeOfJsonString);
            if(ret != UA_STATUSCODE_GOOD) {
                UA_NodeId_deleteMembers(&typeId);
                return ret;
            }

            memcpy(dst->content.encoded.body.data, bodyJsonString, (size_t)sizeOfJsonString);
            
            size_t tokenAfteExtensionObject = 0;
            jumpOverObject(ctx, parseCtx, &tokenAfteExtensionObject);
            
            if(tokenAfteExtensionObject == 0) {
                
                UA_NodeId_deleteMembers(&typeId);
                UA_ByteString_deleteMembers(&dst->content.encoded.body);
                return UA_STATUSCODE_BADDECODINGERROR;
            }
            
            parseCtx->index = (UA_UInt16)tokenAfteExtensionObject;
            
            return UA_STATUSCODE_GOOD;
        }
        
        
        UA_NodeId_deleteMembers(&typeId);
        
        
        dst->content.decoded.type = typeOfBody;
        dst->encoding = UA_EXTENSIONOBJECT_DECODED;
        
        if(searchTypeIdResult != 0) {
            dst->content.decoded.data = UA_new(typeOfBody);
            if(!dst->content.decoded.data)
                return UA_STATUSCODE_BADOUTOFMEMORY;

            UA_NodeId typeId_dummy;
            DecodeEntry entries[2] = {
                {UA_JSONKEY_TYPEID, &typeId_dummy, (decodeJsonSignature) NodeId_decodeJson, false, NULL}, {UA_JSONKEY_BODY, dst->content.decoded.data, (decodeJsonSignature) decodeJsonJumpTable[typeOfBody->typeKind], false, NULL}

            };

            return decodeFields(ctx, parseCtx, entries, 2, typeOfBody);
        } else {
           return UA_STATUSCODE_BADDECODINGERROR;
        }
    } else { 
        
        UA_UInt64 encoding = 0;
        char *extObjEncoding = (char*)(ctx->pos + parseCtx->tokenArray[searchEncodingResult].start);
        size_t size = (size_t)(parseCtx->tokenArray[searchEncodingResult].end - parseCtx->tokenArray[searchEncodingResult].start);
        atoiUnsigned(extObjEncoding, size, &encoding);

        if(encoding == 1) {
            
            dst->encoding = UA_EXTENSIONOBJECT_ENCODED_BYTESTRING;
            UA_UInt16 encodingTypeJson;
            DecodeEntry entries[3] = {
                {UA_JSONKEY_ENCODING, &encodingTypeJson, (decodeJsonSignature) UInt16_decodeJson, false, NULL}, {UA_JSONKEY_BODY, &dst->content.encoded.body, (decodeJsonSignature) String_decodeJson, false, NULL}, {UA_JSONKEY_TYPEID, &dst->content.encoded.typeId, (decodeJsonSignature) NodeId_decodeJson, false, NULL}

            };

            return decodeFields(ctx, parseCtx, entries, 3, type);
        } else if(encoding == 2) {
            
            dst->encoding = UA_EXTENSIONOBJECT_ENCODED_XML;
            UA_UInt16 encodingTypeJson;
            DecodeEntry entries[3] = {
                {UA_JSONKEY_ENCODING, &encodingTypeJson, (decodeJsonSignature) UInt16_decodeJson, false, NULL}, {UA_JSONKEY_BODY, &dst->content.encoded.body, (decodeJsonSignature) String_decodeJson, false, NULL}, {UA_JSONKEY_TYPEID, &dst->content.encoded.typeId, (decodeJsonSignature) NodeId_decodeJson, false, NULL}

            };
            return decodeFields(ctx, parseCtx, entries, 3, type);
        } else {
            return UA_STATUSCODE_BADDECODINGERROR;
        }
    }
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

static status Variant_decodeJsonUnwrapExtensionObject(UA_Variant *dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken) {

    (void) type, (void) moveToken;
    
    UA_UInt16 old_index = parseCtx->index;
    UA_Boolean typeIdFound;
    
    
    UA_NodeId typeId;
    UA_NodeId_init(&typeId);

    size_t searchTypeIdResult = 0;
    status ret = lookAheadForKey(UA_JSONKEY_TYPEID, ctx, parseCtx, &searchTypeIdResult);

    if(ret != UA_STATUSCODE_GOOD) {
        
        typeIdFound = false;
        
    } else {
        typeIdFound = true;
        
        parseCtx->index = (UA_UInt16)searchTypeIdResult;
        ret = NodeId_decodeJson(&typeId, &UA_TYPES[UA_TYPES_NODEID], ctx, parseCtx, true);
        if(ret != UA_STATUSCODE_GOOD) {
            UA_NodeId_deleteMembers(&typeId);
            return ret;
        }

        
        parseCtx->index = old_index;
    }

    
    if(!typeIdFound)
        return UA_STATUSCODE_BADDECODINGERROR;

    UA_Boolean encodingFound = false;
    
    size_t searchEncodingResult = 0;
    ret = lookAheadForKey(UA_JSONKEY_ENCODING, ctx, parseCtx, &searchEncodingResult);

    UA_UInt64 encoding = 0;
    
    if(ret == UA_STATUSCODE_GOOD) { 
        encodingFound = true;
        char *extObjEncoding = (char*)(ctx->pos + parseCtx->tokenArray[searchEncodingResult].start);
        size_t size = (size_t)(parseCtx->tokenArray[searchEncodingResult].end  - parseCtx->tokenArray[searchEncodingResult].start);
        atoiUnsigned(extObjEncoding, size, &encoding);
    }
        
    const UA_DataType *typeOfBody = UA_findDataType(&typeId);
        
    if(encoding == 0 || typeOfBody != NULL) {
        
        
        if (typeOfBody == NULL)
            return UA_STATUSCODE_BADDECODINGERROR;

        dst->type = typeOfBody;

        
        dst->data = UA_new(dst->type);
        if(!dst->data) {
            UA_NodeId_deleteMembers(&typeId);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }

        
        UA_NodeId nodeIddummy;
        DecodeEntry entries[3] = {
             {UA_JSONKEY_TYPEID, &nodeIddummy, (decodeJsonSignature) NodeId_decodeJson, false, NULL}, {UA_JSONKEY_BODY, dst->data, (decodeJsonSignature) decodeJsonJumpTable[dst->type->typeKind], false, NULL}, {UA_JSONKEY_ENCODING, NULL, NULL, false, NULL}};



        ret = decodeFields(ctx, parseCtx, entries, encodingFound ? 3:2, typeOfBody);
        if(ret != UA_STATUSCODE_GOOD) {
            UA_free(dst->data);
            dst->data = NULL;
        }
    } else if(encoding == 1 || encoding == 2 || typeOfBody == NULL) {
        UA_NodeId_deleteMembers(&typeId);
            
        
        dst->type = &UA_TYPES[UA_TYPES_EXTENSIONOBJECT];

        
        dst->data = UA_new(dst->type);
        if(!dst->data)
            return UA_STATUSCODE_BADOUTOFMEMORY;

        
        ret = DECODE_DIRECT_JSON(dst->data, ExtensionObject);
        if(ret != UA_STATUSCODE_GOOD) {
            UA_free(dst->data);
            dst->data = NULL;
        }
    } else {
        
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    return ret;
}
status DiagnosticInfoInner_decodeJson(void* dst, const UA_DataType* type,  CtxJson* ctx, ParseCtx* parseCtx, UA_Boolean moveToken);

DECODE_JSON(DiagnosticInfo) {
    ALLOW_NULL;
    CHECK_OBJECT;

    DecodeEntry entries[7] = {
       {UA_JSONKEY_SYMBOLICID, &dst->symbolicId, (decodeJsonSignature) Int32_decodeJson, false, NULL}, {UA_JSONKEY_NAMESPACEURI, &dst->namespaceUri, (decodeJsonSignature) Int32_decodeJson, false, NULL}, {UA_JSONKEY_LOCALIZEDTEXT, &dst->localizedText, (decodeJsonSignature) Int32_decodeJson, false, NULL}, {UA_JSONKEY_LOCALE, &dst->locale, (decodeJsonSignature) Int32_decodeJson, false, NULL}, {UA_JSONKEY_ADDITIONALINFO, &dst->additionalInfo, (decodeJsonSignature) String_decodeJson, false, NULL}, {UA_JSONKEY_INNERSTATUSCODE, &dst->innerStatusCode, (decodeJsonSignature) StatusCode_decodeJson, false, NULL}, {UA_JSONKEY_INNERDIAGNOSTICINFO, &dst->innerDiagnosticInfo, (decodeJsonSignature) DiagnosticInfoInner_decodeJson, false, NULL}};





    status ret = decodeFields(ctx, parseCtx, entries, 7, type);

    dst->hasSymbolicId = entries[0].found; dst->hasNamespaceUri = entries[1].found;
    dst->hasLocalizedText = entries[2].found; dst->hasLocale = entries[3].found;
    dst->hasAdditionalInfo = entries[4].found; dst->hasInnerStatusCode = entries[5].found;
    dst->hasInnerDiagnosticInfo = entries[6].found;
    return ret;
}

status DiagnosticInfoInner_decodeJson(void* dst, const UA_DataType* type, CtxJson* ctx, ParseCtx* parseCtx, UA_Boolean moveToken) {

    UA_DiagnosticInfo *inner = (UA_DiagnosticInfo*)UA_calloc(1, sizeof(UA_DiagnosticInfo));
    if(inner == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    memcpy(dst, &inner, sizeof(UA_DiagnosticInfo*)); 
    return DiagnosticInfo_decodeJson(inner, type, ctx, parseCtx, moveToken);
}

status  decodeFields(CtxJson *ctx, ParseCtx *parseCtx, DecodeEntry *entries, size_t entryCount, const UA_DataType *type) {

    CHECK_TOKEN_BOUNDS;
    size_t objectCount = (size_t)(parseCtx->tokenArray[parseCtx->index].size);
    status ret = UA_STATUSCODE_GOOD;

    if(entryCount == 1) {
        if(*(entries[0].fieldName) == 0) { 
            return entries[0].function(entries[0].fieldPointer, type, ctx, parseCtx, true);
        }
    } else if(entryCount == 0) {
        return UA_STATUSCODE_BADDECODINGERROR;
    }

    parseCtx->index++; 
    CHECK_TOKEN_BOUNDS;
    
    for (size_t currentObjectCount = 0; currentObjectCount < objectCount && parseCtx->index < parseCtx->tokenCount; currentObjectCount++) {

        
        for (size_t i = currentObjectCount; i < entryCount + currentObjectCount; i++) {
            
            size_t index = i % entryCount;
            
            CHECK_TOKEN_BOUNDS;
            if(jsoneq((char*) ctx->pos, &parseCtx->tokenArray[parseCtx->index],  entries[index].fieldName) != 0)
                continue;

            if(entries[index].found) {
                
                return UA_STATUSCODE_BADDECODINGERROR;
            }

            entries[index].found = true;

            parseCtx->index++; 
            CHECK_TOKEN_BOUNDS;
            
            
            const UA_DataType *membertype = type;
            if(entries[index].type)
                membertype = entries[index].type;

            if(entries[index].function != NULL) {
                ret = entries[index].function(entries[index].fieldPointer, membertype, ctx, parseCtx, true);
                if(ret != UA_STATUSCODE_GOOD)
                    return ret;
            } else {
                
                parseCtx->index++;
            }
            break;
        }
    }
    return ret;
}

static status Array_decodeJson_internal(void **dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken) {

    (void) moveToken;
    status ret;
    
    if(parseCtx->tokenArray[parseCtx->index].type != JSMN_ARRAY)
        return UA_STATUSCODE_BADDECODINGERROR;
    
    size_t length = (size_t)parseCtx->tokenArray[parseCtx->index].size;

    
    size_t *p = (size_t*) dst - 1;
    *p = length;

    
    if(length == 0) {
        *dst = UA_EMPTY_ARRAY_SENTINEL;
        return UA_STATUSCODE_GOOD;
    }

    
    *dst = UA_calloc(length, type->memSize);
    if(*dst == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    
    parseCtx->index++; 
    
    
    uintptr_t ptr = (uintptr_t)*dst;
    for(size_t i = 0; i < length; ++i) {
        ret = decodeJsonJumpTable[type->typeKind]((void*)ptr, type, ctx, parseCtx, true);
        if(ret != UA_STATUSCODE_GOOD) {
            UA_Array_delete(*dst, i+1, type);
            *dst = NULL;
            return ret;
        }
        ptr += type->memSize;
    }
    return UA_STATUSCODE_GOOD;
}


static status Array_decodeJson(void * dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken) {

    return Array_decodeJson_internal((void **)dst, type, ctx, parseCtx, moveToken);
}

static status decodeJsonStructure(void *dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken) {

    (void) moveToken;
    
    if(ctx->depth > UA_JSON_ENCODING_MAX_RECURSION)
        return UA_STATUSCODE_BADENCODINGERROR;
    ctx->depth++;

    uintptr_t ptr = (uintptr_t)dst;
    status ret = UA_STATUSCODE_GOOD;
    u8 membersSize = type->membersSize;
    const UA_DataType *typelists[2] = { UA_TYPES, &type[-type->typeIndex] };
    
    UA_STACKARRAY(DecodeEntry, entries, membersSize);

    for(size_t i = 0; i < membersSize && ret == UA_STATUSCODE_GOOD; ++i) {
        const UA_DataTypeMember *m = &type->members[i];
        const UA_DataType *mt = &typelists[!m->namespaceZero][m->memberTypeIndex];

        entries[i].type = mt;
        if(!m->isArray) {
            ptr += m->padding;
            entries[i].fieldName = m->memberName;
            entries[i].fieldPointer = (void*)ptr;
            entries[i].function = decodeJsonJumpTable[mt->typeKind];
            entries[i].found = false;
            ptr += mt->memSize;
        } else {
            ptr += m->padding;
            ptr += sizeof(size_t);
            entries[i].fieldName = m->memberName;
            entries[i].fieldPointer = (void*)ptr;
            entries[i].function = (decodeJsonSignature)Array_decodeJson;
            entries[i].found = false;
            ptr += sizeof(void*);
        }
    }
    
    ret = decodeFields(ctx, parseCtx, entries, membersSize, type);

    ctx->depth--;
    return ret;
}

static status decodeJsonNotImplemented(void *dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken) {

    (void)dst, (void)type, (void)ctx, (void)parseCtx, (void)moveToken;
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

const decodeJsonSignature decodeJsonJumpTable[UA_DATATYPEKINDS] = {
    (decodeJsonSignature)Boolean_decodeJson, (decodeJsonSignature)SByte_decodeJson, (decodeJsonSignature)Byte_decodeJson, (decodeJsonSignature)Int16_decodeJson, (decodeJsonSignature)UInt16_decodeJson, (decodeJsonSignature)Int32_decodeJson, (decodeJsonSignature)UInt32_decodeJson, (decodeJsonSignature)Int64_decodeJson, (decodeJsonSignature)UInt64_decodeJson, (decodeJsonSignature)Float_decodeJson, (decodeJsonSignature)Double_decodeJson, (decodeJsonSignature)String_decodeJson, (decodeJsonSignature)DateTime_decodeJson, (decodeJsonSignature)Guid_decodeJson, (decodeJsonSignature)ByteString_decodeJson, (decodeJsonSignature)String_decodeJson, (decodeJsonSignature)NodeId_decodeJson, (decodeJsonSignature)ExpandedNodeId_decodeJson, (decodeJsonSignature)StatusCode_decodeJson, (decodeJsonSignature)QualifiedName_decodeJson, (decodeJsonSignature)LocalizedText_decodeJson, (decodeJsonSignature)ExtensionObject_decodeJson, (decodeJsonSignature)DataValue_decodeJson, (decodeJsonSignature)Variant_decodeJson, (decodeJsonSignature)DiagnosticInfo_decodeJson, (decodeJsonSignature)decodeJsonNotImplemented, (decodeJsonSignature)Int32_decodeJson, (decodeJsonSignature)decodeJsonStructure, (decodeJsonSignature)decodeJsonNotImplemented, (decodeJsonSignature)decodeJsonNotImplemented, (decodeJsonSignature)decodeJsonNotImplemented };































decodeJsonSignature getDecodeSignature(u8 index) {
    return decodeJsonJumpTable[index];
}

status tokenize(ParseCtx *parseCtx, CtxJson *ctx, const UA_ByteString *src) {
    
    ctx->pos = &src->data[0];
    ctx->end = &src->data[src->length];
    ctx->depth = 0;
    parseCtx->tokenCount = 0;
    parseCtx->index = 0;

    
    jsmn_parser p;
    jsmn_init(&p);
    parseCtx->tokenCount = (UA_Int32)
        jsmn_parse(&p, (char*)src->data, src->length, parseCtx->tokenArray, UA_JSON_MAXTOKENCOUNT);
    
    if(parseCtx->tokenCount < 0) {
        if(parseCtx->tokenCount == JSMN_ERROR_NOMEM)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode decodeJsonInternal(void *dst, const UA_DataType *type, CtxJson *ctx, ParseCtx *parseCtx, UA_Boolean moveToken) {


    return decodeJsonJumpTable[type->typeKind](dst, type, ctx, parseCtx, moveToken);
}

status UA_FUNC_ATTR_WARN_UNUSED_RESULT UA_decodeJson(const UA_ByteString *src, void *dst, const UA_DataType *type) {
    

    return UA_STATUSCODE_BADNOTSUPPORTED;

    
    if(dst == NULL || src == NULL || type == NULL) {
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    }
    
    
    CtxJson ctx;
    ParseCtx parseCtx;
    parseCtx.tokenArray = (jsmntok_t*)UA_malloc(sizeof(jsmntok_t) * UA_JSON_MAXTOKENCOUNT);
    if(!parseCtx.tokenArray)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    
    status ret = tokenize(&parseCtx, &ctx, src);
    if(ret != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    if(parseCtx.tokenCount < 1 || parseCtx.tokenArray[0].type != JSMN_OBJECT) {
        if(parseCtx.tokenCount == 1) {
            if(parseCtx.tokenArray[0].type == JSMN_PRIMITIVE || parseCtx.tokenArray[0].type == JSMN_STRING) {
               
               memset(dst, 0, type->memSize); 
               ret = decodeJsonJumpTable[type->typeKind](dst, type, &ctx, &parseCtx, true);
               goto cleanup;
            }
        }
        ret = UA_STATUSCODE_BADDECODINGERROR;
        goto cleanup;
    }

    
    memset(dst, 0, type->memSize); 
    ret = decodeJsonJumpTable[type->typeKind](dst, type, &ctx, &parseCtx, true);

    cleanup:
    UA_free(parseCtx.tokenArray);
    
    
    if(!(parseCtx.index == parseCtx.tokenCount || parseCtx.index == parseCtx.tokenCount-1)) {
        ret = UA_STATUSCODE_BADDECODINGERROR;
    }
    
    if(ret != UA_STATUSCODE_GOOD)
        UA_deleteMembers(dst, type); 
    return ret;
}
