

























static mat_complex_split_t null_complex_data = {NULL,NULL};


static int GetTypeBufSize(matvar_t *matvar, size_t *size);
static int GetStructFieldBufSize(matvar_t *matvar, size_t *size);
static int GetCellArrayFieldBufSize(matvar_t *matvar, size_t *size);
static void SetFieldNames(matvar_t *matvar, char *buf, size_t nfields, mat_uint32_t fieldname_length);
static size_t ReadSparse(mat_t *mat, matvar_t *matvar, int *n, mat_int32_t **v);

static int GetMatrixMaxBufSize(matvar_t *matvar, size_t *size);

static int GetEmptyMatrixMaxBufSize(const char *name, int rank, size_t *size);
static size_t WriteCharData(mat_t *mat, void *data, int N,enum matio_types data_type);
static size_t ReadNextCell( mat_t *mat, matvar_t *matvar );
static size_t ReadNextStructField( mat_t *mat, matvar_t *matvar );
static size_t ReadNextFunctionHandle(mat_t *mat, matvar_t *matvar);
static size_t ReadRankDims(mat_t *mat, matvar_t *matvar, enum matio_types data_type, mat_uint32_t nbytes);
static int    WriteType(mat_t *mat,matvar_t *matvar);
static int    WriteCellArrayField(mat_t *mat,matvar_t *matvar );
static int    WriteStructField(mat_t *mat,matvar_t *matvar);
static int    WriteData(mat_t *mat,void *data,int N,enum matio_types data_type);
static size_t Mat_WriteEmptyVariable5(mat_t *mat,const char *name,int rank, size_t *dims);
static void   Mat_VarReadNumeric5(mat_t *mat,matvar_t *matvar,void *data,size_t N);

static size_t WriteCompressedCharData(mat_t *mat,z_streamp z,void *data,int N, enum matio_types data_type);
static size_t WriteCompressedData(mat_t *mat,z_streamp z,void *data,int N, enum matio_types data_type);
static size_t WriteCompressedTypeArrayFlags(mat_t *mat,matvar_t *matvar, z_streamp z);
static size_t WriteCompressedType(mat_t *mat,matvar_t *matvar,z_streamp z);
static size_t WriteCompressedCellArrayField(mat_t *mat,matvar_t *matvar, z_streamp z);
static size_t WriteCompressedStructField(mat_t *mat,matvar_t *matvar, z_streamp z);
static size_t Mat_WriteCompressedEmptyVariable5(mat_t *mat,const char *name, int rank,size_t *dims,z_streamp z);



static int GetTypeBufSize(matvar_t *matvar, size_t *size)
{
    int err;
    size_t nBytes, data_bytes;
    size_t tag_size = 8;
    size_t nelems = 1;
    size_t rank_size;

    *size = 0;

    err = SafeMulDims(matvar, &nelems);
    if ( err )
        return 1;

    
    err = SafeMul(&rank_size, matvar->rank, 4);
    if ( err )
        return 1;

    if ( matvar->rank % 2 )
        nBytes = tag_size + 4;
    else nBytes = tag_size;

    err = SafeAdd(&nBytes, nBytes, rank_size);
    if ( err )
        return 1;

    switch ( matvar->class_type ) {
        case MAT_C_STRUCT:
        {
            matvar_t **fields = (matvar_t**)matvar->data;
            size_t nfields = matvar->internal->num_fields;
            size_t maxlen = 0, i, field_buf_size;

            for ( i = 0; i < nfields; i++ ) {
                char *fieldname = matvar->internal->fieldnames[i];
                if ( NULL != fieldname && strlen(fieldname) > maxlen )
                    maxlen = strlen(fieldname);
            }
            maxlen++;
            while ( nfields*maxlen % 8 != 0 )
                maxlen++;

            err = SafeMul(&field_buf_size, maxlen, nfields);
            err |= SafeAdd(&nBytes, nBytes, tag_size + tag_size);
            err |= SafeAdd(&nBytes, nBytes, field_buf_size);
            if ( err )
                return 1;

            
            if ( NULL != fields && nfields > 0 ) {
                size_t nelems_x_nfields = 1;
                err = SafeMul(&nelems_x_nfields, nelems, nfields);
                if ( err )
                    return 1;

                for ( i = 0; i < nelems_x_nfields; i++ ) {
                    err = GetStructFieldBufSize(fields[i], &field_buf_size);
                    err |= SafeAdd(&nBytes, nBytes, tag_size);
                    err |= SafeAdd(&nBytes, nBytes, field_buf_size);
                    if ( err )
                        return 1;
                }
            }
            break;
        }
        case MAT_C_CELL:
        {
            matvar_t **cells = (matvar_t**)matvar->data;

            if ( matvar->nbytes == 0 || matvar->data_size == 0 )
                break;

            nelems = matvar->nbytes / matvar->data_size;
            if ( NULL != cells && nelems > 0 ) {
                size_t i, field_buf_size;
                for ( i = 0; i < nelems; i++ ) {
                    err = GetCellArrayFieldBufSize(cells[i], &field_buf_size);
                    err |= SafeAdd(&nBytes, nBytes, tag_size);
                    err |= SafeAdd(&nBytes, nBytes, field_buf_size);
                    if ( err )
                        return 1;
                }
            }
            break;
        }
        case MAT_C_SPARSE:
        {
            mat_sparse_t *sparse = (mat_sparse_t*)matvar->data;

            err = SafeMul(&data_bytes, sparse->nir, sizeof(mat_int32_t));
            if ( data_bytes % 8 )
                err |= SafeAdd(&data_bytes, data_bytes, 8 - data_bytes % 8);
            err |= SafeAdd(&nBytes, nBytes, tag_size);
            err |= SafeAdd(&nBytes, nBytes, data_bytes);

            err |= SafeMul(&data_bytes, sparse->njc, sizeof(mat_int32_t));
            if ( data_bytes % 8 )
                err |= SafeAdd(&data_bytes, data_bytes, 8 - data_bytes % 8);
            err |= SafeAdd(&nBytes, nBytes, tag_size);
            err |= SafeAdd(&nBytes, nBytes, data_bytes);

            err |= SafeMul(&data_bytes, sparse->ndata, Mat_SizeOf(matvar->data_type));
            if ( data_bytes % 8 )
                err |= SafeAdd(&data_bytes, data_bytes, 8 - data_bytes % 8);
            err |= SafeAdd(&nBytes, nBytes, tag_size);
            err |= SafeAdd(&nBytes, nBytes, data_bytes);

            if ( matvar->isComplex ) {
                err |= SafeAdd(&nBytes, nBytes, tag_size);
                err |= SafeAdd(&nBytes, nBytes, data_bytes);
            }

            if ( err )
                return 1;

            break;
        }
        case MAT_C_CHAR:
            if ( MAT_T_UINT8 == matvar->data_type || MAT_T_INT8 == matvar->data_type )
                err = SafeMul(&data_bytes, nelems, Mat_SizeOf(MAT_T_UINT16));
            else err = SafeMul(&data_bytes, nelems, Mat_SizeOf(matvar->data_type));
            if ( data_bytes % 8 )
                err |= SafeAdd(&data_bytes, data_bytes, 8 - data_bytes % 8);

            err |= SafeAdd(&nBytes, nBytes, tag_size);
            err |= SafeAdd(&nBytes, nBytes, data_bytes);

            if ( matvar->isComplex ) {
                err |= SafeAdd(&nBytes, nBytes, tag_size);
                err |= SafeAdd(&nBytes, nBytes, data_bytes);
            }

            if ( err )
                return 1;

            break;
        default:
            err = SafeMul(&data_bytes, nelems, Mat_SizeOf(matvar->data_type));
            if ( data_bytes % 8 )
                err |= SafeAdd(&data_bytes, data_bytes, 8 - data_bytes % 8);

            err |= SafeAdd(&nBytes, nBytes, tag_size);
            err |= SafeAdd(&nBytes, nBytes, data_bytes);

            if ( matvar->isComplex ) {
                err |= SafeAdd(&nBytes, nBytes, tag_size);
                err |= SafeAdd(&nBytes, nBytes, data_bytes);
            }

            if ( err )
                return 1;
    } 

    *size = nBytes;
    return 0;
}


static int GetStructFieldBufSize(matvar_t *matvar, size_t *size)
{
    int err;
    size_t nBytes = 0, type_buf_size;
    size_t tag_size = 8, array_flags_size = 8;

    *size = 0;

    if ( matvar == NULL )
        return GetEmptyMatrixMaxBufSize(NULL, 2, size);

    
    nBytes += tag_size + array_flags_size;

    
    nBytes += tag_size;

    err = GetTypeBufSize(matvar, &type_buf_size);
    err |= SafeAdd(&nBytes, nBytes, type_buf_size);
    if ( err )
        return 1;

    *size = nBytes;
    return 0;
}


static int GetCellArrayFieldBufSize(matvar_t *matvar, size_t *size)
{
    int err;
    size_t nBytes = 0, type_buf_size;
    size_t tag_size = 8, array_flags_size = 8;

    *size = 0;

    if ( matvar == NULL )
        return 1;

    
    nBytes += tag_size + array_flags_size;

    
    nBytes += tag_size;

    err = GetTypeBufSize(matvar, &type_buf_size);
    err |= SafeAdd(&nBytes, nBytes, type_buf_size);
    if ( err )
        return 1;

    *size = nBytes;
    return 0;
}


static int GetEmptyMatrixMaxBufSize(const char *name, int rank, size_t *size)
{
    int err = 0;
    size_t nBytes = 0, len, rank_size;
    size_t tag_size = 8, array_flags_size = 8;

    
    nBytes += tag_size + array_flags_size;

    
    if ( NULL != name )
        len = strlen(name);
    else len = 4;

    if ( len <= 4 ) {
        nBytes += tag_size;
    } else {
        nBytes += tag_size;
        if ( len % 8 )
            err |= SafeAdd(&len, len, 8 - len % 8);

        err |= SafeAdd(&nBytes, nBytes, len);
    }

    
    err |= SafeMul(&rank_size, rank, 4);
    if ( rank % 2 )
        err |= SafeAdd(&nBytes, nBytes, tag_size + 4);
    else err |= SafeAdd(&nBytes, nBytes, tag_size);

    err |= SafeAdd(&nBytes, nBytes, rank_size);
    
    err |= SafeAdd(&nBytes, nBytes, tag_size);

    if ( err )
        return 1;

    *size = nBytes;
    return 0;
}

static void SetFieldNames(matvar_t *matvar, char *buf, size_t nfields, mat_uint32_t fieldname_length)
{
    size_t i;
    matvar->internal->num_fields = nfields;
    matvar->internal->fieldnames = (char**)calloc(nfields,sizeof(*matvar->internal->fieldnames));
    if ( NULL != matvar->internal->fieldnames ) {
        for ( i = 0; i < nfields; i++ ) {
            matvar->internal->fieldnames[i] = (char*)malloc(fieldname_length);
            if ( NULL != matvar->internal->fieldnames[i] ) {
                memcpy(matvar->internal->fieldnames[i], buf+i*fieldname_length, fieldname_length);
                matvar->internal->fieldnames[i][fieldname_length-1] = '\0';
            }
        }
    }
}

static size_t ReadSparse(mat_t *mat, matvar_t *matvar, int *n, mat_int32_t **v)
{
    int data_in_tag = 0;
    enum matio_types packed_type;
    mat_uint32_t tag[2];
    size_t bytesread = 0;
    mat_int32_t N = 0;

    if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {

        matvar->internal->z->avail_in = 0;
        InflateDataType(mat,matvar->internal->z,tag);
        if ( mat->byteswap )
            (void)Mat_uint32Swap(tag);
        packed_type = TYPE_FROM_TAG(tag[0]);
        if ( tag[0] & 0xffff0000 ) { 
            data_in_tag = 1;
            N = (tag[0] & 0xffff0000) >> 16;
        } else {
            data_in_tag = 0;
            (void)ReadCompressedInt32Data(mat,matvar->internal->z, (mat_int32_t*)&N,MAT_T_INT32,1);
        }

    } else {
        bytesread += fread(tag,4,1,(FILE*)mat->fp);
        if ( mat->byteswap )
            (void)Mat_uint32Swap(tag);
        packed_type = TYPE_FROM_TAG(tag[0]);
        if ( tag[0] & 0xffff0000 ) { 
            data_in_tag = 1;
            N = (tag[0] & 0xffff0000) >> 16;
        } else {
            data_in_tag = 0;
            bytesread += fread(&N,4,1,(FILE*)mat->fp);
            if ( mat->byteswap )
                (void)Mat_int32Swap(&N);
        }
    }
    *n = N / 4;
    *v = (mat_int32_t*)malloc(*n*sizeof(mat_int32_t));
    if ( NULL != *v ) {
        int nBytes;
        if ( matvar->compression == MAT_COMPRESSION_NONE ) {
            nBytes = ReadInt32Data(mat,*v,packed_type,*n);
            
            if ( data_in_tag )
                nBytes+=4;
            if ( (nBytes % 8) != 0 )
                (void)fseek((FILE*)mat->fp,8-(nBytes % 8),SEEK_CUR);

        } else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {
            nBytes = ReadCompressedInt32Data(mat,matvar->internal->z, *v,packed_type,*n);
            
            if ( data_in_tag )
                nBytes+=4;
            if ( (nBytes % 8) != 0 )
                InflateSkip(mat,matvar->internal->z,8-(nBytes % 8));

        }
    } else {
        Mat_Critical("Couldn't allocate memory");
    }

    return bytesread;
}



static int GetMatrixMaxBufSize(matvar_t *matvar, size_t *size)
{
    int err = 0;
    size_t nBytes = 0, len, type_buf_size;
    size_t tag_size = 8, array_flags_size = 8;

    if ( matvar == NULL )
        return 1;

    
    nBytes += tag_size + array_flags_size;

    
    if ( NULL != matvar->name )
        len = strlen(matvar->name);
    else len = 4;

    if ( len <= 4 ) {
        nBytes += tag_size;
    } else {
        nBytes += tag_size;
        if ( len % 8 )
            err |= SafeAdd(&len, len, 8 - len % 8);

        err |= SafeAdd(&nBytes, nBytes, len);
    }

    err |= GetTypeBufSize(matvar, &type_buf_size);
    err |= SafeAdd(&nBytes, nBytes, type_buf_size);

    if ( err )
        return 1;

    *size = nBytes;
    return 0;
}



mat_t * Mat_Create5(const char *matname,const char *hdr_str)
{
    FILE *fp;
    mat_int16_t endian = 0, version;
    mat_t *mat = NULL;
    size_t err;
    time_t t;

    fp = fopen(matname,"w+b");
    if ( !fp )
        return NULL;

    mat = (mat_t*)malloc(sizeof(*mat));
    if ( mat == NULL ) {
        fclose(fp);
        return NULL;
    }

    mat->fp            = NULL;
    mat->header        = NULL;
    mat->subsys_offset = NULL;
    mat->filename      = NULL;
    mat->version       = 0;
    mat->byteswap      = 0;
    mat->mode          = 0;
    mat->bof           = 128;
    mat->next_index    = 0;
    mat->num_datasets  = 0;

    mat->refs_id       = -1;

    mat->dir           = NULL;

    t = time(NULL);
    mat->fp       = fp;
    mat->filename = strdup_printf("%s",matname);
    mat->mode     = MAT_ACC_RDWR;
    mat->byteswap = 0;
    mat->header   = (char*)malloc(128*sizeof(char));
    mat->subsys_offset = (char*)malloc(8*sizeof(char));
    memset(mat->header,' ',128);
    if ( hdr_str == NULL ) {
        err = mat_snprintf(mat->header,116,"MATLAB 5.0 MAT-file, Platform: %s, " "Created by: libmatio v%d.%d.%d on %s", MATIO_PLATFORM, MATIO_MAJOR_VERSION, MATIO_MINOR_VERSION, MATIO_RELEASE_LEVEL, ctime(&t));


    } else {
        err = mat_snprintf(mat->header,116,"%s",hdr_str);
    }
    if ( err >= 116 )
        mat->header[115] = '\0'; 
    memset(mat->subsys_offset,' ',8);
    mat->version = (int)0x0100;
    endian = 0x4d49;

    version = 0x0100;

    fwrite(mat->header,1,116,(FILE*)mat->fp);
    fwrite(mat->subsys_offset,1,8,(FILE*)mat->fp);
    fwrite(&version,2,1,(FILE*)mat->fp);
    fwrite(&endian,2,1,(FILE*)mat->fp);

    return mat;
}


static size_t WriteCharData(mat_t *mat, void *data, int N,enum matio_types data_type)
{
    int nBytes = 0, i;
    size_t byteswritten = 0;
    mat_int8_t pad1 = 0;

    switch ( data_type ) {
        case MAT_T_UINT16:
        {
            nBytes = N*2;
            fwrite(&data_type,4,1,(FILE*)mat->fp);
            fwrite(&nBytes,4,1,(FILE*)mat->fp);
            if ( NULL != data && N > 0 )
                fwrite(data,2,N,(FILE*)mat->fp);
            if ( nBytes % 8 )
                for ( i = nBytes % 8; i < 8; i++ )
                    fwrite(&pad1,1,1,(FILE*)mat->fp);
            break;
        }
        case MAT_T_INT8:
        case MAT_T_UINT8:
        {
            mat_uint8_t *ptr;
            mat_uint16_t c;

            
            nBytes = N*2;
            data_type = MAT_T_UINT16;
            fwrite(&data_type,4,1,(FILE*)mat->fp);
            fwrite(&nBytes,4,1,(FILE*)mat->fp);
            ptr = (mat_uint8_t*)data;
            if ( NULL == ptr )
                break;
            for ( i = 0; i < N; i++ ) {
                c = (mat_uint16_t)*(char *)ptr;
                fwrite(&c,2,1,(FILE*)mat->fp);
                ptr++;
            }
            if ( nBytes % 8 )
                for ( i = nBytes % 8; i < 8; i++ )
                    fwrite(&pad1,1,1,(FILE*)mat->fp);
            break;
        }
        case MAT_T_UTF8:
        {
            mat_uint8_t *ptr;

            nBytes = N;
            fwrite(&data_type,4,1,(FILE*)mat->fp);
            fwrite(&nBytes,4,1,(FILE*)mat->fp);
            ptr = (mat_uint8_t*)data;
            if ( NULL != ptr && nBytes > 0 )
                fwrite(ptr,1,nBytes,(FILE*)mat->fp);
            if ( nBytes % 8 )
                for ( i = nBytes % 8; i < 8; i++ )
                    fwrite(&pad1,1,1,(FILE*)mat->fp);
            break;
        }
        case MAT_T_UNKNOWN:
        {
            
            nBytes = N*2;
            data_type = MAT_T_UINT16;
            fwrite(&data_type,4,1,(FILE*)mat->fp);
            fwrite(&nBytes,4,1,(FILE*)mat->fp);
            break;
        }
        default:
            break;
    }
    byteswritten += nBytes;
    return byteswritten;
}



static size_t WriteCompressedCharData(mat_t *mat,z_streamp z,void *data,int N, enum matio_types data_type)

{
    int data_size, data_tag[2], byteswritten = 0;
    int buf_size = 1024;
    mat_uint8_t   buf[1024], pad[8] = {0,};

    if ( mat == NULL || mat->fp == NULL )
        return 0;

    switch ( data_type ) {
        case MAT_T_UINT8:
        case MAT_T_UINT16:
        case MAT_T_UTF8:
        case MAT_T_UTF16:
            data_size = Mat_SizeOf(data_type);
            data_tag[0] = MAT_T_UINT8 == data_type ? MAT_T_UTF8 : data_type;
            data_tag[1] = N*data_size;
            z->next_in  = ZLIB_BYTE_PTR(data_tag);
            z->avail_in = 8;
            do {
                z->next_out  = buf;
                z->avail_out = buf_size;
                deflate(z,Z_NO_FLUSH);
                byteswritten += fwrite(buf,1,buf_size-z->avail_out,(FILE*)mat->fp);
            } while ( z->avail_out == 0 );

            
            if ( NULL == data || N < 1 )
                break;

            z->next_in  = (Bytef*)data;
            z->avail_in = data_size*N;
            do {
                z->next_out  = buf;
                z->avail_out = buf_size;
                deflate(z,Z_NO_FLUSH);
                byteswritten += fwrite(buf,1,buf_size-z->avail_out,(FILE*)mat->fp);
            } while ( z->avail_out == 0 );
            
            if ( N*data_size % 8 ) {
                z->next_in  = pad;
                z->avail_in = 8 - (N*data_size % 8);
                do {
                    z->next_out  = buf;
                    z->avail_out = buf_size;
                    deflate(z,Z_NO_FLUSH);
                    byteswritten += fwrite(buf,1,buf_size-z->avail_out,(FILE*)mat->fp);
                } while ( z->avail_out == 0 );
            }
            break;
        case MAT_T_UNKNOWN:
            
            data_size = 2;
            data_tag[0] = MAT_T_UINT16;
            data_tag[1] = N*data_size;
            z->next_in  = ZLIB_BYTE_PTR(data_tag);
            z->avail_in = 8;
            do {
                z->next_out  = buf;
                z->avail_out = buf_size;
                deflate(z,Z_NO_FLUSH);
                byteswritten += fwrite(buf,1,buf_size-z->avail_out,(FILE*)mat->fp);
            } while ( z->avail_out == 0 );
            break;
        default:
            break;
    }

    return byteswritten;
}



static int WriteData(mat_t *mat,void *data,int N,enum matio_types data_type)
{
    int nBytes = 0, data_size;

    if ( mat == NULL || mat->fp == NULL )
        return 0;

    data_size = Mat_SizeOf(data_type);
    nBytes    = N*data_size;
    fwrite(&data_type,4,1,(FILE*)mat->fp);
    fwrite(&nBytes,4,1,(FILE*)mat->fp);

    if ( data != NULL && N > 0 )
        fwrite(data,data_size,N,(FILE*)mat->fp);

    return nBytes;
}



static size_t WriteCompressedData(mat_t *mat,z_streamp z,void *data,int N, enum matio_types data_type)

{
    int nBytes = 0, data_size, data_tag[2], byteswritten = 0;
    int buf_size = 1024;
    mat_uint8_t buf[1024], pad[8] = {0,};

    if ( mat == NULL || mat->fp == NULL )
        return 0;

    data_size   = Mat_SizeOf(data_type);
    data_tag[0] = data_type;
    data_tag[1] = data_size*N;
    z->next_in  = ZLIB_BYTE_PTR(data_tag);
    z->avail_in = 8;
    do {
        z->next_out  = buf;
        z->avail_out = buf_size;
        deflate(z,Z_NO_FLUSH);
        byteswritten += fwrite(buf,1,buf_size-z->avail_out,(FILE*)mat->fp);
    } while ( z->avail_out == 0 );

    
    if ( NULL == data || N < 1 )
        return byteswritten;

    z->next_in  = (Bytef*)data;
    z->avail_in = N*data_size;
    do {
        z->next_out  = buf;
        z->avail_out = buf_size;
        deflate(z,Z_NO_FLUSH);
        byteswritten += fwrite(buf,1,buf_size-z->avail_out,(FILE*)mat->fp);
    } while ( z->avail_out == 0 );
    
    if ( N*data_size % 8 ) {
        z->next_in  = pad;
        z->avail_in = 8 - (N*data_size % 8);
        do {
            z->next_out  = buf;
            z->avail_out = buf_size;
            deflate(z,Z_NO_FLUSH);
            byteswritten += fwrite(buf,1,buf_size-z->avail_out,(FILE*)mat->fp);
        } while ( z->avail_out == 0 );
    }
    nBytes = byteswritten;
    return nBytes;
}



static size_t ReadNextCell( mat_t *mat, matvar_t *matvar )
{
    size_t bytesread = 0, i;
    int err;
    matvar_t **cells = NULL;
    size_t nelems = 1;

    err = SafeMulDims(matvar, &nelems);
    if ( err ) {
        Mat_Critical("Integer multiplication overflow");
        return bytesread;
    }
    matvar->data_size = sizeof(matvar_t *);
    err = SafeMul(&matvar->nbytes, nelems, matvar->data_size);
    if ( err ) {
        Mat_Critical("Integer multiplication overflow");
        return bytesread;
    }

    matvar->data = calloc(nelems, matvar->data_size);
    if ( NULL == matvar->data ) {
        if ( NULL != matvar->name )
            Mat_Critical("Couldn't allocate memory for %s->data", matvar->name);
        return bytesread;
    }
    cells = (matvar_t **)matvar->data;

    if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {

        mat_uint32_t uncomp_buf[16] = {0,};
        int nbytes;
        mat_uint32_t array_flags;

        for ( i = 0; i < nelems; i++ ) {
            cells[i] = Mat_VarCalloc();
            if ( NULL == cells[i] ) {
                Mat_Critical("Couldn't allocate memory for cell %" SIZE_T_FMTSTR, i);
                continue;
            }

            
            uncomp_buf[0] = 0;
            uncomp_buf[1] = 0;
            bytesread += InflateVarTag(mat,matvar,uncomp_buf);
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(uncomp_buf);
                (void)Mat_uint32Swap(uncomp_buf+1);
            }
            nbytes = uncomp_buf[1];
            if ( 0 == nbytes ) {
                
                free(cells[i]->internal);
                cells[i]->internal = NULL;
                continue;
            } else if ( uncomp_buf[0] != MAT_T_MATRIX ) {
                Mat_VarFree(cells[i]);
                cells[i] = NULL;
                Mat_Critical("cells[%" SIZE_T_FMTSTR "], Uncompressed type not MAT_T_MATRIX", i);
                break;
            }
            cells[i]->compression = MAT_COMPRESSION_ZLIB;
            bytesread += InflateArrayFlags(mat,matvar,uncomp_buf);
            nbytes -= 16;
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(uncomp_buf);
                (void)Mat_uint32Swap(uncomp_buf+1);
                (void)Mat_uint32Swap(uncomp_buf+2);
                (void)Mat_uint32Swap(uncomp_buf+3);
            }
            
            if ( uncomp_buf[0] == MAT_T_UINT32 ) {
               array_flags = uncomp_buf[2];
               cells[i]->class_type = CLASS_FROM_ARRAY_FLAGS(array_flags);
               cells[i]->isComplex  = (array_flags & MAT_F_COMPLEX);
               cells[i]->isGlobal   = (array_flags & MAT_F_GLOBAL);
               cells[i]->isLogical  = (array_flags & MAT_F_LOGICAL);
               if ( cells[i]->class_type == MAT_C_SPARSE ) {
                   
                   cells[i]->nbytes = uncomp_buf[3];
               }
            } else {
                Mat_Critical("Expected MAT_T_UINT32 for array tags, got %d", uncomp_buf[0]);
                bytesread+=InflateSkip(mat,matvar->internal->z,nbytes);
            }
            if ( cells[i]->class_type != MAT_C_OPAQUE ) {
                mat_uint32_t* dims = NULL;
                int do_clean = 0;
                bytesread += InflateRankDims(mat,matvar,uncomp_buf,sizeof(uncomp_buf),&dims);
                if ( NULL == dims )
                    dims = uncomp_buf + 2;
                else do_clean = 1;
                nbytes -= 8;
                if ( mat->byteswap ) {
                    (void)Mat_uint32Swap(uncomp_buf);
                    (void)Mat_uint32Swap(uncomp_buf+1);
                }
                
                if ( uncomp_buf[0] == MAT_T_INT32 ) {
                    int j;
                    cells[i]->rank = uncomp_buf[1];
                    nbytes -= cells[i]->rank;
                    cells[i]->rank /= 4;
                    cells[i]->dims = (size_t*)malloc(cells[i]->rank*sizeof(*cells[i]->dims));
                    if ( mat->byteswap ) {
                        for ( j = 0; j < cells[i]->rank; j++ )
                            cells[i]->dims[j] = Mat_uint32Swap(dims + j);
                    } else {
                        for ( j = 0; j < cells[i]->rank; j++ )
                            cells[i]->dims[j] = dims[j];
                    }
                    if ( cells[i]->rank % 2 != 0 )
                        nbytes -= 4;
                }
                if ( do_clean )
                    free(dims);
                
                bytesread += InflateVarTag(mat,matvar,uncomp_buf);
                nbytes -= 8;
                if ( mat->byteswap ) {
                    (void)Mat_uint32Swap(uncomp_buf);
                    (void)Mat_uint32Swap(uncomp_buf+1);
                }
                
                if ( uncomp_buf[1] > 0 ) {
                    
                    if ( uncomp_buf[0] == MAT_T_INT8 ) {    
                        mat_uint32_t len = uncomp_buf[1];

                        if ( len % 8 > 0 )
                            len = len+(8-(len % 8));
                        cells[i]->name = (char*)malloc(len+1);
                        nbytes -= len;
                        if ( NULL != cells[i]->name ) {
                            
                            bytesread += InflateVarName(mat,matvar,cells[i]->name,len);
                            cells[i]->name[len] = '\0';
                        }
                    } else {
                        mat_uint32_t len = (uncomp_buf[0] & 0xffff0000) >> 16;
                        if ( ((uncomp_buf[0] & 0x0000ffff) == MAT_T_INT8) && len > 0 && len <= 4 ) {
                            
                            cells[i]->name = (char*)malloc(len+1);
                            if ( NULL != cells[i]->name ) {
                                memcpy(cells[i]->name,uncomp_buf+1,len);
                                cells[i]->name[len] = '\0';
                            }
                        }
                    }
                }
                cells[i]->internal->z = (z_streamp)calloc(1,sizeof(z_stream));
                if ( cells[i]->internal->z != NULL ) {
                    err = inflateCopy(cells[i]->internal->z,matvar->internal->z);
                    if ( err == Z_OK ) {
                        cells[i]->internal->datapos = ftell((FILE*)mat->fp);
                        if ( cells[i]->internal->datapos != -1L ) {
                            cells[i]->internal->datapos -= matvar->internal->z->avail_in;
                            if ( cells[i]->class_type == MAT_C_STRUCT )
                                bytesread+=ReadNextStructField(mat,cells[i]);
                            else if ( cells[i]->class_type == MAT_C_CELL )
                                bytesread+=ReadNextCell(mat,cells[i]);
                            else if ( nbytes <= (1 << MAX_WBITS) ) {
                                
                                Mat_VarRead5(mat,cells[i]);
                                cells[i]->internal->data = cells[i]->data;
                                cells[i]->data = NULL;
                            }
                            (void)fseek((FILE*)mat->fp,cells[i]->internal->datapos,SEEK_SET);
                        } else {
                            Mat_Critical("Couldn't determine file position");
                        }
                        if ( cells[i]->internal->data != NULL || cells[i]->class_type == MAT_C_STRUCT || cells[i]->class_type == MAT_C_CELL ) {

                            
                            inflateEnd(cells[i]->internal->z);
                            free(cells[i]->internal->z);
                            cells[i]->internal->z = NULL;
                        }
                    } else {
                        Mat_Critical("inflateCopy returned error %s",zError(err));
                    }
                } else {
                    Mat_Critical("Couldn't allocate memory");
                }
            }
            bytesread+=InflateSkip(mat,matvar->internal->z,nbytes);
        }

        Mat_Critical("Not compiled with zlib support");


    } else {
        mat_uint32_t buf[6];
        int nBytes;
        mat_uint32_t array_flags;

        for ( i = 0; i < nelems; i++ ) {
            int cell_bytes_read,name_len;
            cells[i] = Mat_VarCalloc();
            if ( !cells[i] ) {
                Mat_Critical("Couldn't allocate memory for cell %" SIZE_T_FMTSTR, i);
                continue;
            }

            
            cell_bytes_read = fread(buf,4,2,(FILE*)mat->fp);

            
            if ( !cell_bytes_read )
                continue;
            bytesread += cell_bytes_read;
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(buf);
                (void)Mat_uint32Swap(buf+1);
            }
            nBytes = buf[1];
            if ( 0 == nBytes ) {
                
                free(cells[i]->internal);
                cells[i]->internal = NULL;
                continue;
            } else if ( buf[0] != MAT_T_MATRIX ) {
                Mat_VarFree(cells[i]);
                cells[i] = NULL;
                Mat_Critical("cells[%" SIZE_T_FMTSTR "] not MAT_T_MATRIX, fpos = %ld", i, ftell((FILE*)mat->fp));
                break;
            }

            
            bytesread += fread(buf,4,6,(FILE*)mat->fp);
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(buf);
                (void)Mat_uint32Swap(buf+1);
                (void)Mat_uint32Swap(buf+2);
                (void)Mat_uint32Swap(buf+3);
                (void)Mat_uint32Swap(buf+4);
                (void)Mat_uint32Swap(buf+5);
            }
            nBytes-=24;
            
            if ( buf[0] == MAT_T_UINT32 ) {
               array_flags = buf[2];
               cells[i]->class_type = CLASS_FROM_ARRAY_FLAGS(array_flags);
               cells[i]->isComplex  = (array_flags & MAT_F_COMPLEX);
               cells[i]->isGlobal   = (array_flags & MAT_F_GLOBAL);
               cells[i]->isLogical  = (array_flags & MAT_F_LOGICAL);
               if ( cells[i]->class_type == MAT_C_SPARSE ) {
                   
                   cells[i]->nbytes = buf[3];
               }
            }
            
            {
                size_t nbytes = ReadRankDims(mat, cells[i], (enum matio_types)buf[4], buf[5]);
                bytesread += nbytes;
                nBytes -= nbytes;
            }
            
            bytesread+=fread(buf,1,8,(FILE*)mat->fp);
            nBytes-=8;
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(buf);
                (void)Mat_uint32Swap(buf+1);
            }
            name_len = 0;
            if ( buf[1] > 0 ) {
                
                if ( buf[0] == MAT_T_INT8 ) {    
                    name_len = buf[1];
                    if ( name_len % 8 > 0 )
                        name_len = name_len+(8-(name_len % 8));
                    nBytes -= name_len;
                    (void)fseek((FILE*)mat->fp,name_len,SEEK_CUR);
                }
            }
            cells[i]->internal->datapos = ftell((FILE*)mat->fp);
            if ( cells[i]->internal->datapos != -1L ) {
                if ( cells[i]->class_type == MAT_C_STRUCT )
                    bytesread+=ReadNextStructField(mat,cells[i]);
                if ( cells[i]->class_type == MAT_C_CELL )
                    bytesread+=ReadNextCell(mat,cells[i]);
                (void)fseek((FILE*)mat->fp,cells[i]->internal->datapos+nBytes,SEEK_SET);
            } else {
                Mat_Critical("Couldn't determine file position");
            }
        }
    }

    return bytesread;
}


static size_t ReadNextStructField( mat_t *mat, matvar_t *matvar )
{
    mat_uint32_t fieldname_size;
    int err;
    size_t bytesread = 0, nfields, i;
    matvar_t **fields = NULL;
    size_t nelems = 1, nelems_x_nfields;

    err = SafeMulDims(matvar, &nelems);
    if ( err ) {
        Mat_Critical("Integer multiplication overflow");
        return bytesread;
    }
    if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {

        mat_uint32_t uncomp_buf[16] = {0,};
        int nbytes;
        mat_uint32_t array_flags, len;

        
        bytesread += InflateVarTag(mat,matvar,uncomp_buf);
        if ( mat->byteswap ) {
            (void)Mat_uint32Swap(uncomp_buf);
            (void)Mat_uint32Swap(uncomp_buf+1);
        }
        if ( (uncomp_buf[0] & 0x0000ffff) == MAT_T_INT32 && uncomp_buf[1] > 0 ) {
            fieldname_size = uncomp_buf[1];
        } else {
            Mat_Critical("Error getting fieldname size");
            return bytesread;
        }

        
        bytesread += InflateVarTag(mat,matvar,uncomp_buf);
        if ( mat->byteswap )
            (void)Mat_uint32Swap(uncomp_buf);
        
        if ( uncomp_buf[0] == MAT_T_INT8 ) {    
            if ( mat->byteswap )
                len = Mat_uint32Swap(uncomp_buf+1);
            else len = uncomp_buf[1];
            nfields = len / fieldname_size;
            if ( nfields*fieldname_size % 8 != 0 )
                i = 8-(nfields*fieldname_size % 8);
            else i = 0;
            if ( nfields ) {
                char *ptr = (char*)malloc(nfields*fieldname_size+i);
                if ( NULL != ptr ) {
                    bytesread += InflateVarName(mat,matvar,ptr,nfields*fieldname_size+i);
                    SetFieldNames(matvar, ptr, nfields, fieldname_size);
                    free(ptr);
                }
            } else {
                matvar->internal->num_fields = 0;
                matvar->internal->fieldnames = NULL;
            }
        } else {
            len = (uncomp_buf[0] & 0xffff0000) >> 16;
            if ( ((uncomp_buf[0] & 0x0000ffff) == MAT_T_INT8) && len > 0 && len <= 4 ) {
                
                nfields = len / fieldname_size;
                if ( nfields ) {
                    SetFieldNames(matvar, (char*)(uncomp_buf + 1), nfields, fieldname_size);
                } else {
                    matvar->internal->num_fields = 0;
                    matvar->internal->fieldnames = NULL;
                }
            } else {
                nfields = 0;
            }
        }

        matvar->data_size = sizeof(matvar_t *);
        err = SafeMul(&nelems_x_nfields, nelems, nfields);
        if ( err ) {
            Mat_Critical("Integer multiplication overflow");
            return bytesread;
        }
        err = SafeMul(&matvar->nbytes, nelems_x_nfields, matvar->data_size);
        if ( err ) {
            Mat_Critical("Integer multiplication overflow");
            return bytesread;
        }
        if ( !matvar->nbytes )
            return bytesread;

        matvar->data = calloc(nelems_x_nfields, matvar->data_size);
        if ( NULL == matvar->data ) {
            Mat_Critical("Couldn't allocate memory for the data");
            return bytesread;
        }

        fields = (matvar_t**)matvar->data;
        for ( i = 0; i < nelems; i++ ) {
            size_t k;
            for ( k = 0; k < nfields; k++ ) {
                fields[i*nfields+k] = Mat_VarCalloc();
            }
        }
        if ( NULL != matvar->internal->fieldnames ) {
            for ( i = 0; i < nelems; i++ ) {
                size_t k;
                for ( k = 0; k < nfields; k++ ) {
                    if ( NULL != matvar->internal->fieldnames[k] ) {
                        fields[i*nfields+k]->name = strdup(matvar->internal->fieldnames[k]);
                    }
                }
            }
        }

        for ( i = 0; i < nelems_x_nfields; i++ ) {
            
            bytesread += InflateVarTag(mat,matvar,uncomp_buf);
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(uncomp_buf);
                (void)Mat_uint32Swap(uncomp_buf+1);
            }
            nbytes = uncomp_buf[1];
            if ( uncomp_buf[0] != MAT_T_MATRIX ) {
                Mat_VarFree(fields[i]);
                fields[i] = NULL;
                Mat_Critical("fields[%" SIZE_T_FMTSTR "], Uncompressed type not MAT_T_MATRIX", i);
                continue;
            } else if ( 0 == nbytes ) {
                
                free(fields[i]->internal);
                fields[i]->internal = NULL;
                continue;
            }
            fields[i]->compression = MAT_COMPRESSION_ZLIB;
            bytesread += InflateArrayFlags(mat,matvar,uncomp_buf);
            nbytes -= 16;
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(uncomp_buf);
                (void)Mat_uint32Swap(uncomp_buf+1);
                (void)Mat_uint32Swap(uncomp_buf+2);
                (void)Mat_uint32Swap(uncomp_buf+3);
            }
            
            if ( uncomp_buf[0] == MAT_T_UINT32 ) {
               array_flags = uncomp_buf[2];
               fields[i]->class_type = CLASS_FROM_ARRAY_FLAGS(array_flags);
               fields[i]->isComplex  = (array_flags & MAT_F_COMPLEX);
               fields[i]->isGlobal   = (array_flags & MAT_F_GLOBAL);
               fields[i]->isLogical  = (array_flags & MAT_F_LOGICAL);
               if ( fields[i]->class_type == MAT_C_SPARSE ) {
                   
                   fields[i]->nbytes = uncomp_buf[3];
               }
            } else {
                Mat_Critical("Expected MAT_T_UINT32 for array tags, got %d", uncomp_buf[0]);
                bytesread+=InflateSkip(mat,matvar->internal->z,nbytes);
            }
            if ( fields[i]->class_type != MAT_C_OPAQUE ) {
                mat_uint32_t* dims = NULL;
                int do_clean = 0;
                bytesread += InflateRankDims(mat,matvar,uncomp_buf,sizeof(uncomp_buf),&dims);
                if ( NULL == dims )
                    dims = uncomp_buf + 2;
                else do_clean = 1;
                nbytes -= 8;
                if ( mat->byteswap ) {
                    (void)Mat_uint32Swap(uncomp_buf);
                    (void)Mat_uint32Swap(uncomp_buf+1);
                }
                
                if ( uncomp_buf[0] == MAT_T_INT32 ) {
                    int j;
                    fields[i]->rank = uncomp_buf[1];
                    nbytes -= fields[i]->rank;
                    fields[i]->rank /= 4;
                    fields[i]->dims = (size_t*)malloc(fields[i]->rank* sizeof(*fields[i]->dims));
                    if ( mat->byteswap ) {
                        for ( j = 0; j < fields[i]->rank; j++ )
                            fields[i]->dims[j] = Mat_uint32Swap(dims+j);
                    } else {
                        for ( j = 0; j < fields[i]->rank; j++ )
                            fields[i]->dims[j] = dims[j];
                    }
                    if ( fields[i]->rank % 2 != 0 )
                        nbytes -= 4;
                }
                if ( do_clean )
                    free(dims);
                
                bytesread += InflateVarTag(mat,matvar,uncomp_buf);
                nbytes -= 8;
                fields[i]->internal->z = (z_streamp)calloc(1,sizeof(z_stream));
                if ( fields[i]->internal->z != NULL ) {
                    err = inflateCopy(fields[i]->internal->z,matvar->internal->z);
                    if ( err == Z_OK ) {
                        fields[i]->internal->datapos = ftell((FILE*)mat->fp);
                        if ( fields[i]->internal->datapos != -1L ) {
                            fields[i]->internal->datapos -= matvar->internal->z->avail_in;
                            if ( fields[i]->class_type == MAT_C_STRUCT )
                                bytesread+=ReadNextStructField(mat,fields[i]);
                            else if ( fields[i]->class_type == MAT_C_CELL )
                                bytesread+=ReadNextCell(mat,fields[i]);
                            else if ( nbytes <= (1 << MAX_WBITS) ) {
                                
                                Mat_VarRead5(mat,fields[i]);
                                fields[i]->internal->data = fields[i]->data;
                                fields[i]->data = NULL;
                            }
                            (void)fseek((FILE*)mat->fp,fields[i]->internal->datapos,SEEK_SET);
                        } else {
                            Mat_Critical("Couldn't determine file position");
                        }
                        if ( fields[i]->internal->data != NULL || fields[i]->class_type == MAT_C_STRUCT || fields[i]->class_type == MAT_C_CELL ) {

                            
                            inflateEnd(fields[i]->internal->z);
                            free(fields[i]->internal->z);
                            fields[i]->internal->z = NULL;
                        }
                    } else {
                        Mat_Critical("inflateCopy returned error %s",zError(err));
                    }
                } else {
                    Mat_Critical("Couldn't allocate memory");
                }
            }
            bytesread+=InflateSkip(mat,matvar->internal->z,nbytes);
        }

        Mat_Critical("Not compiled with zlib support");

    } else {
        mat_uint32_t buf[6];
        int nBytes;
        mat_uint32_t array_flags, len;

        bytesread+=fread(buf,4,2,(FILE*)mat->fp);
        if ( mat->byteswap ) {
            (void)Mat_uint32Swap(buf);
            (void)Mat_uint32Swap(buf+1);
        }
        if ( (buf[0] & 0x0000ffff) == MAT_T_INT32 && buf[1] > 0 ) {
            fieldname_size = buf[1];
        } else {
            Mat_Critical("Error getting fieldname size");
            return bytesread;
        }

        
        bytesread+=fread(buf,4,2,(FILE*)mat->fp);
        if ( mat->byteswap )
            (void)Mat_uint32Swap(buf);
        
        if ( buf[0] == MAT_T_INT8 ) {    
            if ( mat->byteswap )
                len = Mat_uint32Swap(buf+1);
            else len = buf[1];
            nfields = len / fieldname_size;
            if ( nfields ) {
                char *ptr = (char*)malloc(nfields*fieldname_size);
                if ( NULL != ptr ) {
                    size_t readresult = fread(ptr, 1, nfields*fieldname_size, (FILE*)mat->fp);
                    bytesread += readresult;
                    if ( nfields*fieldname_size == readresult )
                        SetFieldNames(matvar, ptr, nfields, fieldname_size);
                    else matvar->internal->fieldnames = NULL;
                    free(ptr);
                }
                if ( (nfields*fieldname_size) % 8 ) {
                    (void)fseek((FILE*)mat->fp,8-((nfields*fieldname_size) % 8),SEEK_CUR);
                    bytesread+=8-((nfields*fieldname_size) % 8);
                }
            } else {
                matvar->internal->num_fields = 0;
                matvar->internal->fieldnames = NULL;
            }
       } else {
            len = (buf[0] & 0xffff0000) >> 16;
            if ( ((buf[0] & 0x0000ffff) == MAT_T_INT8) && len > 0 && len <= 4 ) {
                
                nfields = len / fieldname_size;
                if ( nfields ) {
                    SetFieldNames(matvar, (char*)(buf + 1), nfields, fieldname_size);
                } else {
                    matvar->internal->num_fields = 0;
                    matvar->internal->fieldnames = NULL;
                }
            } else {
                nfields = 0;
            }
        }

        matvar->data_size = sizeof(matvar_t *);
        err = SafeMul(&nelems_x_nfields, nelems, nfields);
        if ( err ) {
            Mat_Critical("Integer multiplication overflow");
            return bytesread;
        }
        err = SafeMul(&matvar->nbytes, nelems_x_nfields, matvar->data_size);
        if ( err ) {
            Mat_Critical("Integer multiplication overflow");
            return bytesread;
        }
        if ( !matvar->nbytes )
            return bytesread;

        matvar->data = malloc(matvar->nbytes);
        if ( NULL == matvar->data )
            return bytesread;

        fields = (matvar_t**)matvar->data;
        for ( i = 0; i < nelems; i++ ) {
            size_t k;
            for ( k = 0; k < nfields; k++ ) {
                fields[i*nfields+k] = Mat_VarCalloc();
            }
        }
        if ( NULL != matvar->internal->fieldnames ) {
            for ( i = 0; i < nelems; i++ ) {
                size_t k;
                for ( k = 0; k < nfields; k++ ) {
                    if ( NULL != matvar->internal->fieldnames[k] ) {
                        fields[i*nfields+k]->name = strdup(matvar->internal->fieldnames[k]);
                    }
                }
            }
        }

        for ( i = 0; i < nelems_x_nfields; i++ ) {
            
            bytesread += fread(buf,4,2,(FILE*)mat->fp);
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(buf);
                (void)Mat_uint32Swap(buf+1);
            }
            nBytes = buf[1];
            if ( buf[0] != MAT_T_MATRIX ) {
                Mat_VarFree(fields[i]);
                fields[i] = NULL;
                Mat_Critical("fields[%" SIZE_T_FMTSTR "] not MAT_T_MATRIX, fpos = %ld", i, ftell((FILE*)mat->fp));
                return bytesread;
            } else if ( 0 == nBytes ) {
                
                free(fields[i]->internal);
                fields[i]->internal = NULL;
                continue;
            }

            
            bytesread += fread(buf,4,6,(FILE*)mat->fp);
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(buf);
                (void)Mat_uint32Swap(buf+1);
                (void)Mat_uint32Swap(buf+2);
                (void)Mat_uint32Swap(buf+3);
                (void)Mat_uint32Swap(buf+4);
                (void)Mat_uint32Swap(buf+5);
            }
            nBytes-=24;
            
            if ( buf[0] == MAT_T_UINT32 ) {
                array_flags = buf[2];
                fields[i]->class_type = CLASS_FROM_ARRAY_FLAGS(array_flags);
                fields[i]->isComplex  = (array_flags & MAT_F_COMPLEX);
                fields[i]->isGlobal   = (array_flags & MAT_F_GLOBAL);
                fields[i]->isLogical  = (array_flags & MAT_F_LOGICAL);
                if ( fields[i]->class_type == MAT_C_SPARSE ) {
                    
                    fields[i]->nbytes = buf[3];
                }
            }
            
            {
                size_t nbytes = ReadRankDims(mat, fields[i], (enum matio_types)buf[4], buf[5]);
                bytesread += nbytes;
                nBytes -= nbytes;
            }
            
            bytesread+=fread(buf,1,8,(FILE*)mat->fp);
            nBytes-=8;
            fields[i]->internal->datapos = ftell((FILE*)mat->fp);
            if ( fields[i]->internal->datapos != -1L ) {
                if ( fields[i]->class_type == MAT_C_STRUCT )
                    bytesread+=ReadNextStructField(mat,fields[i]);
                else if ( fields[i]->class_type == MAT_C_CELL )
                    bytesread+=ReadNextCell(mat,fields[i]);
                (void)fseek((FILE*)mat->fp,fields[i]->internal->datapos+nBytes,SEEK_SET);
            } else {
                Mat_Critical("Couldn't determine file position");
            }
        }
    }

    return bytesread;
}


static size_t ReadNextFunctionHandle(mat_t *mat, matvar_t *matvar)
{
    int err;
    size_t nelems = 1;

    err = SafeMulDims(matvar, &nelems);
    matvar->data_size = sizeof(matvar_t *);
    err |= SafeMul(&matvar->nbytes, nelems, matvar->data_size);
    if ( err )
        return 0;

    matvar->data = malloc(matvar->nbytes);
    if ( matvar->data != NULL ) {
        size_t i;
        matvar_t **functions = (matvar_t**)matvar->data;;
        for ( i = 0; i < nelems; i++ )
            functions[i] = Mat_VarReadNextInfo(mat);
    } else {
        matvar->data_size = 0;
        matvar->nbytes    = 0;
    }

    return 0;
}


static size_t ReadRankDims(mat_t *mat, matvar_t *matvar, enum matio_types data_type, mat_uint32_t nbytes)
{
    size_t bytesread = 0;
    
    if ( data_type == MAT_T_INT32 ) {
        matvar->rank = nbytes / sizeof(mat_uint32_t);
        matvar->dims = (size_t*)malloc(matvar->rank*sizeof(*matvar->dims));
        if ( NULL != matvar->dims ) {
            int i;
            mat_uint32_t buf;

            for ( i = 0; i < matvar->rank; i++) {
                size_t readresult = fread(&buf, sizeof(mat_uint32_t), 1, (FILE*)mat->fp);
                if ( 1 == readresult ) {
                    bytesread += sizeof(mat_uint32_t);
                    if ( mat->byteswap ) {
                        matvar->dims[i] = Mat_uint32Swap(&buf);
                    } else {
                        matvar->dims[i] = buf;
                    }
                } else {
                    free(matvar->dims);
                    matvar->dims = NULL;
                    matvar->rank = 0;
                    return 0;
                }
            }

            if ( matvar->rank % 2 != 0 ) {
                size_t readresult = fread(&buf, sizeof(mat_uint32_t), 1, (FILE*)mat->fp);
                if ( 1 == readresult ) {
                    bytesread += sizeof(mat_uint32_t);
                } else {
                    free(matvar->dims);
                    matvar->dims = NULL;
                    matvar->rank = 0;
                    return 0;
                }
            }
        } else {
            matvar->rank = 0;
            Mat_Critical("Error allocating memory for dims");
        }
    }
    return bytesread;
}


static int WriteType(mat_t *mat,matvar_t *matvar)
{
    int err;
    mat_int16_t array_name_type = MAT_T_INT8;
    mat_int8_t pad1 = 0;
    int nBytes, j;
    size_t nelems = 1;

    err = SafeMulDims(matvar, &nelems);
    if ( err )
        return err;

    switch ( matvar->class_type ) {
        case MAT_C_DOUBLE:
        case MAT_C_SINGLE:
        case MAT_C_INT64:
        case MAT_C_UINT64:
        case MAT_C_INT32:
        case MAT_C_UINT32:
        case MAT_C_INT16:
        case MAT_C_UINT16:
        case MAT_C_INT8:
        case MAT_C_UINT8:
        {
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = (mat_complex_split_t*)matvar->data;

                if ( NULL == matvar->data )
                    complex_data = &null_complex_data;

                nBytes=WriteData(mat,complex_data->Re,nelems,matvar->data_type);
                if ( nBytes % 8 )
                    for ( j = nBytes % 8; j < 8; j++ )
                        fwrite(&pad1,1,1,(FILE*)mat->fp);
                nBytes=WriteData(mat,complex_data->Im,nelems,matvar->data_type);
                if ( nBytes % 8 )
                    for ( j = nBytes % 8; j < 8; j++ )
                        fwrite(&pad1,1,1,(FILE*)mat->fp);
            } else {
                nBytes=WriteData(mat,matvar->data,nelems,matvar->data_type);
                if ( nBytes % 8 )
                    for ( j = nBytes % 8; j < 8; j++ )
                        fwrite(&pad1,1,1,(FILE*)mat->fp);
            }
            break;
        }
        case MAT_C_CHAR:
            nBytes=WriteCharData(mat,matvar->data,nelems,matvar->data_type);
            break;
        case MAT_C_CELL:
        {
            size_t i;
            matvar_t **cells = (matvar_t **)matvar->data;

            
            if ( matvar->nbytes == 0 || matvar->data_size == 0 || matvar->data   == NULL )
                break;
            nelems = matvar->nbytes / matvar->data_size;
            for ( i = 0; i < nelems; i++ )
                WriteCellArrayField(mat,cells[i]);
            break;
        }
        case MAT_C_STRUCT:
        {
            mat_int16_t fieldname_type = MAT_T_INT32;
            mat_int16_t fieldname_data_size = 4;
            char *padzero;
            int fieldname_size;
            size_t maxlen = 0, nfields, i, nelems_x_nfields;
            matvar_t **fields = (matvar_t **)matvar->data;
            unsigned fieldname;

            
            nfields = matvar->internal->num_fields;
            
            if ( nfields < 1 ) {

                fwrite(&fieldname_type,2,1,(FILE*)mat->fp);
                fwrite(&fieldname_data_size,2,1,(FILE*)mat->fp);

                fieldname = (fieldname_data_size<<16) | fieldname_type;
                fwrite(&fieldname,4,1,(FILE*)mat->fp);

                fieldname_size = 1;
                fwrite(&fieldname_size,4,1,(FILE*)mat->fp);
                fwrite(&array_name_type,2,1,(FILE*)mat->fp);
                fwrite(&pad1,1,1,(FILE*)mat->fp);
                fwrite(&pad1,1,1,(FILE*)mat->fp);
                nBytes = 0;
                fwrite(&nBytes,4,1,(FILE*)mat->fp);
                break;
            }

            for ( i = 0; i < nfields; i++ ) {
                size_t len = strlen(matvar->internal->fieldnames[i]);
                if ( len > maxlen )
                    maxlen = len;
            }
            maxlen++;
            fieldname_size = maxlen;
            while ( nfields*fieldname_size % 8 != 0 )
                fieldname_size++;

            fwrite(&fieldname_type,2,1,(FILE*)mat->fp);
            fwrite(&fieldname_data_size,2,1,(FILE*)mat->fp);

            fieldname = (fieldname_data_size<<16) | fieldname_type;
            fwrite(&fieldname,4,1,(FILE*)mat->fp);

            fwrite(&fieldname_size,4,1,(FILE*)mat->fp);
            fwrite(&array_name_type,2,1,(FILE*)mat->fp);
            fwrite(&pad1,1,1,(FILE*)mat->fp);
            fwrite(&pad1,1,1,(FILE*)mat->fp);
            nBytes = nfields*fieldname_size;
            fwrite(&nBytes,4,1,(FILE*)mat->fp);
            padzero = (char*)calloc(fieldname_size,1);
            for ( i = 0; i < nfields; i++ ) {
                size_t len = strlen(matvar->internal->fieldnames[i]);
                fwrite(matvar->internal->fieldnames[i],1,len,(FILE*)mat->fp);
                fwrite(padzero,1,fieldname_size-len,(FILE*)mat->fp);
            }
            free(padzero);
            err = SafeMul(&nelems_x_nfields, nelems, nfields);
            if ( err )
                break;
            for ( i = 0; i < nelems_x_nfields; i++ )
                WriteStructField(mat,fields[i]);
            break;
        }
        case MAT_C_SPARSE:
        {
            mat_sparse_t *sparse = (mat_sparse_t*)matvar->data;

            nBytes = WriteData(mat,sparse->ir,sparse->nir,MAT_T_INT32);
            if ( nBytes % 8 )
                for ( j = nBytes % 8; j < 8; j++ )
                    fwrite(&pad1,1,1,(FILE*)mat->fp);
            nBytes = WriteData(mat,sparse->jc,sparse->njc,MAT_T_INT32);
            if ( nBytes % 8 )
                for ( j = nBytes % 8; j < 8; j++ )
                    fwrite(&pad1,1,1,(FILE*)mat->fp);
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = (mat_complex_split_t*)sparse->data;
                nBytes = WriteData(mat,complex_data->Re,sparse->ndata, matvar->data_type);
                if ( nBytes % 8 )
                    for ( j = nBytes % 8; j < 8; j++ )
                        fwrite(&pad1,1,1,(FILE*)mat->fp);
                nBytes = WriteData(mat,complex_data->Im,sparse->ndata, matvar->data_type);
                if ( nBytes % 8 )
                    for ( j = nBytes % 8; j < 8; j++ )
                        fwrite(&pad1,1,1,(FILE*)mat->fp);
            } else {
                nBytes = WriteData(mat,sparse->data,sparse->ndata, matvar->data_type);
                if ( nBytes % 8 )
                    for ( j = nBytes % 8; j < 8; j++ )
                        fwrite(&pad1,1,1,(FILE*)mat->fp);
            }
        }
        case MAT_C_FUNCTION:
        case MAT_C_OBJECT:
        case MAT_C_EMPTY:
        case MAT_C_OPAQUE:
            break;
    }

    return err;
}


static int WriteCellArrayField(mat_t *mat,matvar_t *matvar)
{
    mat_uint32_t array_flags;
    mat_int16_t array_name_type = MAT_T_INT8;
    int array_flags_type = MAT_T_UINT32, dims_array_type = MAT_T_INT32;
    int array_flags_size = 8, pad4 = 0, matrix_type = MAT_T_MATRIX;
    const mat_int8_t pad1 = 0;
    int nBytes, i, nzmax = 0;
    long start = 0, end = 0;

    if ( matvar == NULL || mat == NULL )
        return 1;

    fwrite(&matrix_type,4,1,(FILE*)mat->fp);
    fwrite(&pad4,4,1,(FILE*)mat->fp);
    if ( MAT_C_EMPTY == matvar->class_type ) {
        
        return 0;
    }
    start = ftell((FILE*)mat->fp);

    
    array_flags = matvar->class_type & CLASS_TYPE_MASK;
    if ( matvar->isComplex )
        array_flags |= MAT_F_COMPLEX;
    if ( matvar->isGlobal )
        array_flags |= MAT_F_GLOBAL;
    if ( matvar->isLogical )
        array_flags |= MAT_F_LOGICAL;
    if ( matvar->class_type == MAT_C_SPARSE )
        nzmax = ((mat_sparse_t *)matvar->data)->nzmax;

    if ( mat->byteswap )
        array_flags = Mat_int32Swap((mat_int32_t*)&array_flags);
    fwrite(&array_flags_type,4,1,(FILE*)mat->fp);
    fwrite(&array_flags_size,4,1,(FILE*)mat->fp);
    fwrite(&array_flags,4,1,(FILE*)mat->fp);
    fwrite(&nzmax,4,1,(FILE*)mat->fp);
    
    nBytes = matvar->rank * 4;
    fwrite(&dims_array_type,4,1,(FILE*)mat->fp);
    fwrite(&nBytes,4,1,(FILE*)mat->fp);
    for ( i = 0; i < matvar->rank; i++ ) {
        mat_int32_t dim;
        dim = matvar->dims[i];
        fwrite(&dim,4,1,(FILE*)mat->fp);
    }
    if ( matvar->rank % 2 != 0 )
        fwrite(&pad4,4,1,(FILE*)mat->fp);
    
    if ( !matvar->name ) {
        fwrite(&array_name_type,2,1,(FILE*)mat->fp);
        fwrite(&pad1,1,1,(FILE*)mat->fp);
        fwrite(&pad1,1,1,(FILE*)mat->fp);
        fwrite(&pad4,4,1,(FILE*)mat->fp);
    } else if ( strlen(matvar->name) <= 4 ) {
        mat_int16_t array_name_len = (mat_int16_t)strlen(matvar->name);
        fwrite(&array_name_type,2,1,(FILE*)mat->fp);
        fwrite(&array_name_len,2,1,(FILE*)mat->fp);
        fwrite(matvar->name,1,array_name_len,(FILE*)mat->fp);
        for ( i = array_name_len; i < 4; i++ )
            fwrite(&pad1,1,1,(FILE*)mat->fp);
    } else {
        mat_int32_t array_name_len = (mat_int32_t)strlen(matvar->name);
        fwrite(&array_name_type,2,1,(FILE*)mat->fp);
        fwrite(&pad1,1,1,(FILE*)mat->fp);
        fwrite(&pad1,1,1,(FILE*)mat->fp);
        fwrite(&array_name_len,4,1,(FILE*)mat->fp);
        fwrite(matvar->name,1,array_name_len,(FILE*)mat->fp);
        if ( array_name_len % 8 )
            for ( i = array_name_len % 8; i < 8; i++ )
                fwrite(&pad1,1,1,(FILE*)mat->fp);
    }

    WriteType(mat,matvar);
    end = ftell((FILE*)mat->fp);
    if ( start != -1L && end != -1L ) {
        nBytes = (int)(end-start);
        (void)fseek((FILE*)mat->fp,(long)-(nBytes+4),SEEK_CUR);
        fwrite(&nBytes,4,1,(FILE*)mat->fp);
        (void)fseek((FILE*)mat->fp,end,SEEK_SET);
    } else {
        Mat_Critical("Couldn't determine file position");
    }

    return 0;
}



static size_t WriteCompressedTypeArrayFlags(mat_t *mat,matvar_t *matvar,z_streamp z)
{
    mat_uint32_t array_flags;
    mat_int16_t  array_name_type = MAT_T_INT8;
    int array_flags_type = MAT_T_UINT32, dims_array_type = MAT_T_INT32;
    int array_flags_size = 8;
    int nBytes, i, nzmax = 0;

    mat_uint32_t comp_buf[512];
    mat_uint32_t uncomp_buf[512] = {0,};
    int buf_size = 512;
    size_t byteswritten = 0;

    if ( MAT_C_EMPTY == matvar->class_type ) {
        
        return byteswritten;
    }

    
    array_flags = matvar->class_type & CLASS_TYPE_MASK;
    if ( matvar->isComplex )
        array_flags |= MAT_F_COMPLEX;
    if ( matvar->isGlobal )
        array_flags |= MAT_F_GLOBAL;
    if ( matvar->isLogical )
        array_flags |= MAT_F_LOGICAL;
    if ( matvar->class_type == MAT_C_SPARSE )
        nzmax = ((mat_sparse_t *)matvar->data)->nzmax;
    uncomp_buf[0] = array_flags_type;
    uncomp_buf[1] = array_flags_size;
    uncomp_buf[2] = array_flags;
    uncomp_buf[3] = nzmax;
    
    nBytes = matvar->rank * 4;
    uncomp_buf[4] = dims_array_type;
    uncomp_buf[5] = nBytes;
    for ( i = 0; i < matvar->rank; i++ ) {
        mat_int32_t dim;
        dim = matvar->dims[i];
        uncomp_buf[6+i] = dim;
    }
    if ( matvar->rank % 2 != 0 ) {
        int pad4 = 0;
        uncomp_buf[6+i] = pad4;
        i++;
    }

    z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
    z->avail_in = (6+i)*sizeof(*uncomp_buf);
    do {
        z->next_out  = ZLIB_BYTE_PTR(comp_buf);
        z->avail_out = buf_size*sizeof(*comp_buf);
        deflate(z,Z_NO_FLUSH);
        byteswritten += fwrite(comp_buf,1,buf_size*sizeof(*comp_buf)-z->avail_out, (FILE*)mat->fp);
    } while ( z->avail_out == 0 );
    
    uncomp_buf[0] = array_name_type;
    uncomp_buf[1] = 0;
    z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
    z->avail_in = 8;
    do {
        z->next_out  = ZLIB_BYTE_PTR(comp_buf);
        z->avail_out = buf_size*sizeof(*comp_buf);
        deflate(z,Z_NO_FLUSH);
        byteswritten += fwrite(comp_buf,1,buf_size*sizeof(*comp_buf)-z->avail_out, (FILE*)mat->fp);
    } while ( z->avail_out == 0 );

    matvar->internal->datapos = ftell((FILE*)mat->fp);
    if ( matvar->internal->datapos == -1L ) {
        Mat_Critical("Couldn't determine file position");
    }

    byteswritten += WriteCompressedType(mat,matvar,z);
    return byteswritten;
}


static size_t WriteCompressedType(mat_t *mat,matvar_t *matvar,z_streamp z)
{
    int err;
    mat_uint32_t comp_buf[512];
    mat_uint32_t uncomp_buf[512] = {0,};
    size_t byteswritten = 0, nelems = 1;

    if ( MAT_C_EMPTY == matvar->class_type ) {
        
        return byteswritten;
    }

    err = SafeMulDims(matvar, &nelems);
    if ( err ) {
        Mat_Critical("Integer multiplication overflow");
        return byteswritten;
    }

    switch ( matvar->class_type ) {
        case MAT_C_DOUBLE:
        case MAT_C_SINGLE:
        case MAT_C_INT64:
        case MAT_C_UINT64:
        case MAT_C_INT32:
        case MAT_C_UINT32:
        case MAT_C_INT16:
        case MAT_C_UINT16:
        case MAT_C_INT8:
        case MAT_C_UINT8:
        {
            
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = (mat_complex_split_t*)matvar->data;

                if ( NULL == matvar->data )
                    complex_data = &null_complex_data;

                byteswritten += WriteCompressedData(mat,z, complex_data->Re,nelems,matvar->data_type);
                byteswritten += WriteCompressedData(mat,z, complex_data->Im,nelems,matvar->data_type);
            } else {
                byteswritten += WriteCompressedData(mat,z, matvar->data,nelems,matvar->data_type);
            }
            break;
        }
        case MAT_C_CHAR:
        {
            byteswritten += WriteCompressedCharData(mat,z,matvar->data, nelems,matvar->data_type);
            break;
        }
        case MAT_C_CELL:
        {
            size_t i;
            matvar_t **cells = (matvar_t **)matvar->data;

            
            if ( matvar->nbytes == 0 || matvar->data_size == 0 || matvar->data   == NULL )
                break;
            nelems = matvar->nbytes / matvar->data_size;
            for ( i = 0; i < nelems; i++ )
                WriteCompressedCellArrayField(mat,cells[i],z);
            break;
        }
        case MAT_C_STRUCT:
        {
            int buf_size = 512;
            mat_int16_t fieldname_type = MAT_T_INT32;
            mat_int16_t fieldname_data_size = 4;
            unsigned char *padzero;
            int fieldname_size;
            size_t maxlen = 0, nfields, i, nelems_x_nfields;
            mat_int32_t array_name_type = MAT_T_INT8;
            matvar_t **fields = (matvar_t **)matvar->data;

            nfields = matvar->internal->num_fields;
            
            if ( nfields < 1 ) {
                fieldname_size = 1;
                uncomp_buf[0] = (fieldname_data_size << 16) | fieldname_type;
                uncomp_buf[1] = fieldname_size;
                uncomp_buf[2] = array_name_type;
                uncomp_buf[3] = 0;
                z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
                z->avail_in = 16;
                do {
                    z->next_out  = ZLIB_BYTE_PTR(comp_buf);
                    z->avail_out = buf_size*sizeof(*comp_buf);
                    deflate(z,Z_NO_FLUSH);
                    byteswritten += fwrite(comp_buf,1,buf_size* sizeof(*comp_buf)-z->avail_out,(FILE*)mat->fp);
                } while ( z->avail_out == 0 );
                break;
            }

            for ( i = 0; i < nfields; i++ ) {
                size_t len = strlen(matvar->internal->fieldnames[i]);
                if ( len > maxlen )
                    maxlen = len;
            }
            maxlen++;
            fieldname_size = maxlen;
            while ( nfields*fieldname_size % 8 != 0 )
                fieldname_size++;
            uncomp_buf[0] = (fieldname_data_size << 16) | fieldname_type;
            uncomp_buf[1] = fieldname_size;
            uncomp_buf[2] = array_name_type;
            uncomp_buf[3] = nfields*fieldname_size;

            padzero = (unsigned char*)calloc(fieldname_size,1);
            z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
            z->avail_in = 16;
            do {
                z->next_out  = ZLIB_BYTE_PTR(comp_buf);
                z->avail_out = buf_size*sizeof(*comp_buf);
                deflate(z,Z_NO_FLUSH);
                byteswritten += fwrite(comp_buf,1, buf_size*sizeof(*comp_buf)-z->avail_out,(FILE*)mat->fp);
            } while ( z->avail_out == 0 );
            for ( i = 0; i < nfields; i++ ) {
                size_t len = strlen(matvar->internal->fieldnames[i]);
                memset(padzero,'\0',fieldname_size);
                memcpy(padzero,matvar->internal->fieldnames[i],len);
                z->next_in  = ZLIB_BYTE_PTR(padzero);
                z->avail_in = fieldname_size;
                do {
                    z->next_out  = ZLIB_BYTE_PTR(comp_buf);
                    z->avail_out = buf_size*sizeof(*comp_buf);
                    deflate(z,Z_NO_FLUSH);
                    byteswritten += fwrite(comp_buf,1, buf_size*sizeof(*comp_buf)-z->avail_out,(FILE*)mat->fp);
                } while ( z->avail_out == 0 );
            }
            free(padzero);
            err = SafeMul(&nelems_x_nfields, nelems, nfields);
            if ( err ) {
                Mat_Critical("Integer multiplication overflow");
                return byteswritten;
            }
            for ( i = 0; i < nelems_x_nfields; i++ )
                byteswritten += WriteCompressedStructField(mat,fields[i],z);
            break;
        }
        case MAT_C_SPARSE:
        {
            mat_sparse_t *sparse = (mat_sparse_t*)matvar->data;

            byteswritten += WriteCompressedData(mat,z,sparse->ir, sparse->nir,MAT_T_INT32);
            byteswritten += WriteCompressedData(mat,z,sparse->jc, sparse->njc,MAT_T_INT32);
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = (mat_complex_split_t*)sparse->data;
                byteswritten += WriteCompressedData(mat,z, complex_data->Re,sparse->ndata,matvar->data_type);
                byteswritten += WriteCompressedData(mat,z, complex_data->Im,sparse->ndata,matvar->data_type);
            } else {
                byteswritten += WriteCompressedData(mat,z, sparse->data,sparse->ndata,matvar->data_type);
            }
            break;
        }
        case MAT_C_FUNCTION:
        case MAT_C_OBJECT:
        case MAT_C_EMPTY:
        case MAT_C_OPAQUE:
            break;
    }

    return byteswritten;
}


static size_t WriteCompressedCellArrayField(mat_t *mat,matvar_t *matvar,z_streamp z)
{
    mat_uint32_t comp_buf[512];
    mat_uint32_t uncomp_buf[512] = {0,};
    int buf_size = 512;
    size_t byteswritten = 0, field_buf_size;

    if ( NULL == matvar || NULL == mat || NULL == z)
        return 0;

    uncomp_buf[0] = MAT_T_MATRIX;
    if ( MAT_C_EMPTY != matvar->class_type ) {
        int err = GetCellArrayFieldBufSize(matvar, &field_buf_size);
        if (err || field_buf_size > UINT32_MAX)
            return 0;

        uncomp_buf[1] = field_buf_size;
    } else {
        uncomp_buf[1] = 0;
    }
    z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
    z->avail_in = 8;
    do {
        z->next_out  = ZLIB_BYTE_PTR(comp_buf);
        z->avail_out = buf_size*sizeof(*comp_buf);
        deflate(z,Z_NO_FLUSH);
        byteswritten += fwrite(comp_buf,1,buf_size*sizeof(*comp_buf)-z->avail_out, (FILE*)mat->fp);
    } while ( z->avail_out == 0 );

    byteswritten += WriteCompressedTypeArrayFlags(mat,matvar,z);
    return byteswritten;
}



static int WriteStructField(mat_t *mat,matvar_t *matvar)
{
    mat_uint32_t array_flags;
    mat_int32_t  array_name_type = MAT_T_INT8;
    int array_flags_type = MAT_T_UINT32, dims_array_type = MAT_T_INT32;
    int array_flags_size = 8, pad4 = 0, matrix_type = MAT_T_MATRIX;
    int nBytes, i, nzmax = 0;
    long start = 0, end = 0;

    if ( mat == NULL )
        return 1;

    if ( NULL == matvar ) {
        size_t dims[2] = {0,0};
        Mat_WriteEmptyVariable5(mat, NULL, 2, dims);
        return 0;
    }

    fwrite(&matrix_type,4,1,(FILE*)mat->fp);
    fwrite(&pad4,4,1,(FILE*)mat->fp);
    if ( MAT_C_EMPTY == matvar->class_type ) {
        
        return 0;
    }
    start = ftell((FILE*)mat->fp);

    
    array_flags = matvar->class_type & CLASS_TYPE_MASK;
    if ( matvar->isComplex )
        array_flags |= MAT_F_COMPLEX;
    if ( matvar->isGlobal )
        array_flags |= MAT_F_GLOBAL;
    if ( matvar->isLogical )
        array_flags |= MAT_F_LOGICAL;
    if ( matvar->class_type == MAT_C_SPARSE )
        nzmax = ((mat_sparse_t *)matvar->data)->nzmax;

    if ( mat->byteswap )
        array_flags = Mat_int32Swap((mat_int32_t*)&array_flags);
    fwrite(&array_flags_type,4,1,(FILE*)mat->fp);
    fwrite(&array_flags_size,4,1,(FILE*)mat->fp);
    fwrite(&array_flags,4,1,(FILE*)mat->fp);
    fwrite(&nzmax,4,1,(FILE*)mat->fp);
    
    nBytes = matvar->rank * 4;
    fwrite(&dims_array_type,4,1,(FILE*)mat->fp);
    fwrite(&nBytes,4,1,(FILE*)mat->fp);
    for ( i = 0; i < matvar->rank; i++ ) {
        mat_int32_t dim;
        dim = matvar->dims[i];
        fwrite(&dim,4,1,(FILE*)mat->fp);
    }
    if ( matvar->rank % 2 != 0 )
        fwrite(&pad4,4,1,(FILE*)mat->fp);

    
    fwrite(&array_name_type,4,1,(FILE*)mat->fp);
    fwrite(&pad4,4,1,(FILE*)mat->fp);

    WriteType(mat,matvar);
    end = ftell((FILE*)mat->fp);
    if ( start != -1L && end != -1L ) {
        nBytes = (int)(end-start);
        (void)fseek((FILE*)mat->fp,(long)-(nBytes+4),SEEK_CUR);
        fwrite(&nBytes,4,1,(FILE*)mat->fp);
        (void)fseek((FILE*)mat->fp,end,SEEK_SET);
    } else {
        Mat_Critical("Couldn't determine file position");
    }

    return 0;
}



static size_t WriteCompressedStructField(mat_t *mat,matvar_t *matvar,z_streamp z)
{
    mat_uint32_t comp_buf[512];
    mat_uint32_t uncomp_buf[512] = {0,};
    int buf_size = 512;
    size_t byteswritten = 0, field_buf_size;

    if ( NULL == mat || NULL == z)
        return 0;

    if ( NULL == matvar ) {
        size_t dims[2] = {0,0};
        byteswritten = Mat_WriteCompressedEmptyVariable5(mat, NULL, 2, dims, z);
        return byteswritten;
    }

    uncomp_buf[0] = MAT_T_MATRIX;
    if ( MAT_C_EMPTY != matvar->class_type ) {
        int err = GetStructFieldBufSize(matvar, &field_buf_size);
        if (err || field_buf_size > UINT32_MAX)
            return 0;
        uncomp_buf[1] = field_buf_size;
    } else {
        uncomp_buf[1] = 0;
    }
    z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
    z->avail_in = 8;
    do {
        z->next_out  = ZLIB_BYTE_PTR(comp_buf);
        z->avail_out = buf_size*sizeof(*comp_buf);
        deflate(z,Z_NO_FLUSH);
        byteswritten += fwrite(comp_buf,1,buf_size*sizeof(*comp_buf)-z->avail_out, (FILE*)mat->fp);
    } while ( z->avail_out == 0 );

    byteswritten += WriteCompressedTypeArrayFlags(mat,matvar,z);
    return byteswritten;
}


static size_t Mat_WriteEmptyVariable5(mat_t *mat,const char *name,int rank,size_t *dims)
{
    mat_uint32_t array_flags;
    mat_int32_t  array_name_type = MAT_T_INT8, matrix_type = MAT_T_MATRIX;
    int array_flags_type = MAT_T_UINT32, dims_array_type = MAT_T_INT32;
    int array_flags_size = 8, pad4 = 0, nBytes, i;
    const mat_int8_t pad1 = 0;
    size_t byteswritten = 0;
    long start = 0, end = 0;

    fwrite(&matrix_type,4,1,(FILE*)mat->fp);
    fwrite(&pad4,4,1,(FILE*)mat->fp);
    start = ftell((FILE*)mat->fp);

    
    array_flags = MAT_C_DOUBLE;

    if ( mat->byteswap )
        array_flags = Mat_int32Swap((mat_int32_t*)&array_flags);
    byteswritten += fwrite(&array_flags_type,4,1,(FILE*)mat->fp);
    byteswritten += fwrite(&array_flags_size,4,1,(FILE*)mat->fp);
    byteswritten += fwrite(&array_flags,4,1,(FILE*)mat->fp);
    byteswritten += fwrite(&pad4,4,1,(FILE*)mat->fp);
    
    nBytes = rank * 4;
    byteswritten += fwrite(&dims_array_type,4,1,(FILE*)mat->fp);
    byteswritten += fwrite(&nBytes,4,1,(FILE*)mat->fp);
    for ( i = 0; i < rank; i++ ) {
        mat_int32_t dim;
        dim = dims[i];
        byteswritten += fwrite(&dim,4,1,(FILE*)mat->fp);
    }
    if ( rank % 2 != 0 )
        byteswritten += fwrite(&pad4,4,1,(FILE*)mat->fp);

    if ( NULL == name ) {
        
        byteswritten += fwrite(&array_name_type,4,1,(FILE*)mat->fp);
        byteswritten += fwrite(&pad4,4,1,(FILE*)mat->fp);
    } else {
        mat_int32_t array_name_len = (mat_int32_t)strlen(name);
        
        if ( array_name_len <= 4 ) {
            array_name_type = (array_name_len << 16) | array_name_type;
            byteswritten += fwrite(&array_name_type,4,1,(FILE*)mat->fp);
            byteswritten += fwrite(name,1,array_name_len,(FILE*)mat->fp);
            for ( i = array_name_len; i < 4; i++ )
                byteswritten += fwrite(&pad1,1,1,(FILE*)mat->fp);
        } else {
            byteswritten += fwrite(&array_name_type,4,1,(FILE*)mat->fp);
            byteswritten += fwrite(&array_name_len,4,1,(FILE*)mat->fp);
            byteswritten += fwrite(name,1,array_name_len,(FILE*)mat->fp);
            if ( array_name_len % 8 )
                for ( i = array_name_len % 8; i < 8; i++ )
                    byteswritten += fwrite(&pad1,1,1,(FILE*)mat->fp);
        }
    }

    nBytes = WriteData(mat,NULL,0,MAT_T_DOUBLE);
    byteswritten += nBytes;
    if ( nBytes % 8 )
        for ( i = nBytes % 8; i < 8; i++ )
            byteswritten += fwrite(&pad1,1,1,(FILE*)mat->fp);

    end = ftell((FILE*)mat->fp);
    if ( start != -1L && end != -1L ) {
        nBytes = (int)(end-start);
        (void)fseek((FILE*)mat->fp,(long)-(nBytes+4),SEEK_CUR);
        fwrite(&nBytes,4,1,(FILE*)mat->fp);
        (void)fseek((FILE*)mat->fp,end,SEEK_SET);
    } else {
        Mat_Critical("Couldn't determine file position");
    }

    return byteswritten;
}


static size_t Mat_WriteCompressedEmptyVariable5(mat_t *mat,const char *name,int rank, size_t *dims,z_streamp z)

{
    mat_uint32_t array_flags;
    int array_flags_type = MAT_T_UINT32, dims_array_type = MAT_T_INT32;
    int array_flags_size = 8;
    int i, err;
    size_t nBytes, empty_matrix_max_buf_size;

    mat_uint32_t comp_buf[512];
    mat_uint32_t uncomp_buf[512] = {0,};
    int buf_size = 512;
    size_t byteswritten = 0, buf_size_bytes;

    if ( NULL == mat || NULL == z)
        return byteswritten;

    buf_size_bytes = buf_size*sizeof(*comp_buf);

    
    array_flags = MAT_C_DOUBLE;

    uncomp_buf[0] = MAT_T_MATRIX;
    err = GetEmptyMatrixMaxBufSize(name, rank, &empty_matrix_max_buf_size);
    if (err || empty_matrix_max_buf_size > UINT32_MAX)
        return byteswritten;
    uncomp_buf[1] = empty_matrix_max_buf_size;
    z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
    z->avail_in = 8;
    do {
        z->next_out  = ZLIB_BYTE_PTR(comp_buf);
        z->avail_out = buf_size_bytes;
        deflate(z,Z_NO_FLUSH);
        byteswritten += fwrite(comp_buf,1,buf_size_bytes-z->avail_out,(FILE*)mat->fp);
    } while ( z->avail_out == 0 );
    uncomp_buf[0] = array_flags_type;
    uncomp_buf[1] = array_flags_size;
    uncomp_buf[2] = array_flags;
    uncomp_buf[3] = 0;
    
    nBytes = rank * 4;
    uncomp_buf[4] = dims_array_type;
    uncomp_buf[5] = nBytes;
    for ( i = 0; i < rank; i++ ) {
        mat_int32_t dim;
        dim = dims[i];
        uncomp_buf[6+i] = dim;
    }
    if ( rank % 2 != 0 ) {
        int pad4 = 0;
        uncomp_buf[6+i] = pad4;
        i++;
    }

    z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
    z->avail_in = (6+i)*sizeof(*uncomp_buf);
    do {
        z->next_out  = ZLIB_BYTE_PTR(comp_buf);
        z->avail_out = buf_size_bytes;
        deflate(z,Z_NO_FLUSH);
        byteswritten += fwrite(comp_buf,1,buf_size_bytes-z->avail_out,(FILE*)mat->fp);
    } while ( z->avail_out == 0 );
    
    if ( NULL == name ) {
        mat_int16_t array_name_type = MAT_T_INT8;
        uncomp_buf[0] = array_name_type;
        uncomp_buf[1] = 0;
        z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
        z->avail_in = 8;
        do {
            z->next_out  = ZLIB_BYTE_PTR(comp_buf);
            z->avail_out = buf_size_bytes;
            deflate(z,Z_NO_FLUSH);
            byteswritten += fwrite(comp_buf,1,buf_size_bytes-z->avail_out,(FILE*)mat->fp);
        } while ( z->avail_out == 0 );
    } else if ( strlen(name) <= 4 ) {
        mat_int16_t array_name_len = (mat_int16_t)strlen(name);
        mat_int16_t array_name_type = MAT_T_INT8;

        memset(uncomp_buf,0,8);
        uncomp_buf[0] = (array_name_len << 16) | array_name_type;
        memcpy(uncomp_buf+1,name,array_name_len);
        if ( array_name_len % 4 )
            array_name_len += 4-(array_name_len % 4);

        z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
        z->avail_in = 8;
        do {
            z->next_out  = ZLIB_BYTE_PTR(comp_buf);
            z->avail_out = buf_size_bytes;
            deflate(z,Z_NO_FLUSH);
            byteswritten += fwrite(comp_buf,1,buf_size_bytes-z->avail_out, (FILE*)mat->fp);
        } while ( z->avail_out == 0 );
    } else {
        mat_int32_t array_name_len = (mat_int32_t)strlen(name);
        mat_int32_t array_name_type = MAT_T_INT8;

        memset(uncomp_buf,0,buf_size*sizeof(*uncomp_buf));
        uncomp_buf[0] = array_name_type;
        uncomp_buf[1] = array_name_len;
        memcpy(uncomp_buf+2,name,array_name_len);
        if ( array_name_len % 8 )
            array_name_len += 8-(array_name_len % 8);
        z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
        z->avail_in = 8+array_name_len;
        do {
            z->next_out  = ZLIB_BYTE_PTR(comp_buf);
            z->avail_out = buf_size_bytes;
            deflate(z,Z_NO_FLUSH);
            byteswritten += fwrite(comp_buf,1,buf_size_bytes-z->avail_out, (FILE*)mat->fp);
        } while ( z->avail_out == 0 );
    }

    byteswritten += WriteCompressedData(mat,z,NULL,0,MAT_T_DOUBLE);
    return byteswritten;
}



static void Mat_VarReadNumeric5(mat_t *mat,matvar_t *matvar,void *data,size_t N)
{
    int nBytes = 0, data_in_tag = 0;
    enum matio_types packed_type = MAT_T_UNKNOWN;
    mat_uint32_t tag[2];

    if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {

        matvar->internal->z->avail_in = 0;
        InflateDataType(mat,matvar->internal->z,tag);
        if ( mat->byteswap )
            (void)Mat_uint32Swap(tag);

        packed_type = TYPE_FROM_TAG(tag[0]);
        if ( tag[0] & 0xffff0000 ) { 
            data_in_tag = 1;
            nBytes = (tag[0] & 0xffff0000) >> 16;
        } else {
            data_in_tag = 0;
            InflateDataType(mat,matvar->internal->z,tag+1);
            if ( mat->byteswap )
                (void)Mat_uint32Swap(tag+1);
            nBytes = tag[1];
        }

    } else {
        size_t bytesread = fread(tag,4,1,(FILE*)mat->fp);
        if ( mat->byteswap )
            (void)Mat_uint32Swap(tag);
        packed_type = TYPE_FROM_TAG(tag[0]);
        if ( tag[0] & 0xffff0000 ) { 
            data_in_tag = 1;
            nBytes = (tag[0] & 0xffff0000) >> 16;
        } else {
            data_in_tag = 0;
            bytesread += fread(tag+1,4,1,(FILE*)mat->fp);
            if ( mat->byteswap )
                (void)Mat_uint32Swap(tag+1);
            nBytes = tag[1];
        }
    }
    if ( nBytes == 0 ) {
        matvar->nbytes = 0;
        return;
    }

    if ( matvar->compression == MAT_COMPRESSION_NONE ) {
        switch ( matvar->class_type ) {
            case MAT_C_DOUBLE:
                nBytes = ReadDoubleData(mat,(double*)data,packed_type,N);
                break;
            case MAT_C_SINGLE:
                nBytes = ReadSingleData(mat,(float*)data,packed_type,N);
                break;
            case MAT_C_INT64:

                nBytes = ReadInt64Data(mat,(mat_int64_t*)data,packed_type,N);

                break;
            case MAT_C_UINT64:

                nBytes = ReadUInt64Data(mat,(mat_uint64_t*)data,packed_type,N);

                break;
            case MAT_C_INT32:
                nBytes = ReadInt32Data(mat,(mat_int32_t*)data,packed_type,N);
                break;
            case MAT_C_UINT32:
                nBytes = ReadUInt32Data(mat,(mat_uint32_t*)data,packed_type,N);
                break;
            case MAT_C_INT16:
                nBytes = ReadInt16Data(mat,(mat_int16_t*)data,packed_type,N);
                break;
            case MAT_C_UINT16:
                nBytes = ReadUInt16Data(mat,(mat_uint16_t*)data,packed_type,N);
                break;
            case MAT_C_INT8:
                nBytes = ReadInt8Data(mat,(mat_int8_t*)data,packed_type,N);
                break;
            case MAT_C_UINT8:
                nBytes = ReadUInt8Data(mat,(mat_uint8_t*)data,packed_type,N);
                break;
            default:
                break;
        }
        
        if ( data_in_tag )
            nBytes+=4;
        if ( (nBytes % 8) != 0 )
            (void)fseek((FILE*)mat->fp,8-(nBytes % 8),SEEK_CUR);

    } else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {
        switch ( matvar->class_type ) {
            case MAT_C_DOUBLE:
                nBytes = ReadCompressedDoubleData(mat,matvar->internal->z,(double*)data, packed_type,N);
                break;
            case MAT_C_SINGLE:
                nBytes = ReadCompressedSingleData(mat,matvar->internal->z,(float*)data, packed_type,N);
                break;
            case MAT_C_INT64:

                nBytes = ReadCompressedInt64Data(mat,matvar->internal->z,(mat_int64_t*)data, packed_type,N);

                break;
            case MAT_C_UINT64:

                nBytes = ReadCompressedUInt64Data(mat,matvar->internal->z,(mat_uint64_t*)data, packed_type,N);

                break;
            case MAT_C_INT32:
                nBytes = ReadCompressedInt32Data(mat,matvar->internal->z,(mat_int32_t*)data, packed_type,N);
                break;
            case MAT_C_UINT32:
                nBytes = ReadCompressedUInt32Data(mat,matvar->internal->z,(mat_uint32_t*)data, packed_type,N);
                break;
            case MAT_C_INT16:
                nBytes = ReadCompressedInt16Data(mat,matvar->internal->z,(mat_int16_t*)data, packed_type,N);
                break;
            case MAT_C_UINT16:
                nBytes = ReadCompressedUInt16Data(mat,matvar->internal->z,(mat_uint16_t*)data, packed_type,N);
                break;
            case MAT_C_INT8:
                nBytes = ReadCompressedInt8Data(mat,matvar->internal->z,(mat_int8_t*)data, packed_type,N);
                break;
            case MAT_C_UINT8:
                nBytes = ReadCompressedUInt8Data(mat,matvar->internal->z,(mat_uint8_t*)data, packed_type,N);
                break;
            default:
                break;
        }
        
        if ( data_in_tag )
            nBytes+=4;
        if ( (nBytes % 8) != 0 )
            InflateSkip(mat,matvar->internal->z,8-(nBytes % 8));

    }
}


void Mat_VarRead5(mat_t *mat, matvar_t *matvar)
{
    int nBytes = 0, byteswap, data_in_tag = 0, err;
    size_t nelems = 1;
    enum matio_types packed_type = MAT_T_UNKNOWN;
    long fpos;
    mat_uint32_t tag[2];
    size_t bytesread = 0;

    if ( matvar == NULL )
        return;
    else if ( matvar->rank == 0 )        
        return;

    else if ( NULL != matvar->internal->data ) {
        
        matvar->data = matvar->internal->data;
        matvar->internal->data = NULL;
        return;
    }

    fpos = ftell((FILE*)mat->fp);
    if ( fpos == -1L ) {
        Mat_Critical("Couldn't determine file position");
        return;
    }
    err = SafeMulDims(matvar, &nelems);
    if ( err ) {
        Mat_Critical("Integer multiplication overflow");
        return;
    }
    byteswap = mat->byteswap;
    switch ( matvar->class_type ) {
        case MAT_C_EMPTY:
            matvar->nbytes = 0;
            matvar->data_size = sizeof(double);
            matvar->data_type = MAT_T_DOUBLE;
            matvar->rank = 2;
            matvar->dims = (size_t*)malloc(matvar->rank*sizeof(*(matvar->dims)));
            matvar->dims[0] = 0;
            matvar->dims[1] = 0;
            break;
        case MAT_C_DOUBLE:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(double);
            matvar->data_type = MAT_T_DOUBLE;
            break;
        case MAT_C_SINGLE:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(float);
            matvar->data_type = MAT_T_SINGLE;
            break;
        case MAT_C_INT64:

            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(mat_int64_t);
            matvar->data_type = MAT_T_INT64;

            break;
        case MAT_C_UINT64:

            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(mat_uint64_t);
            matvar->data_type = MAT_T_UINT64;

            break;
        case MAT_C_INT32:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(mat_int32_t);
            matvar->data_type = MAT_T_INT32;
            break;
        case MAT_C_UINT32:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(mat_uint32_t);
            matvar->data_type = MAT_T_UINT32;
            break;
        case MAT_C_INT16:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(mat_int16_t);
            matvar->data_type = MAT_T_INT16;
            break;
        case MAT_C_UINT16:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(mat_uint16_t);
            matvar->data_type = MAT_T_UINT16;
            break;
        case MAT_C_INT8:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(mat_int8_t);
            matvar->data_type = MAT_T_INT8;
            break;
        case MAT_C_UINT8:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            matvar->data_size = sizeof(mat_uint8_t);
            matvar->data_type = MAT_T_UINT8;
            break;
        case MAT_C_CHAR:
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {

                matvar->internal->z->avail_in = 0;
                InflateDataType(mat,matvar->internal->z,tag);
                if ( byteswap )
                    (void)Mat_uint32Swap(tag);
                packed_type = TYPE_FROM_TAG(tag[0]);
                if ( tag[0] & 0xffff0000 ) { 
                    data_in_tag = 1;
                    nBytes = (tag[0] & 0xffff0000) >> 16;
                } else {
                    data_in_tag = 0;
                    InflateDataType(mat,matvar->internal->z,tag+1);
                    if ( byteswap )
                        (void)Mat_uint32Swap(tag+1);
                    nBytes = tag[1];
                }

                matvar->data_type = packed_type;
                matvar->data_size = Mat_SizeOf(matvar->data_type);
                matvar->nbytes = nBytes;
            } else {
                bytesread += fread(tag,4,1,(FILE*)mat->fp);
                if ( byteswap )
                    (void)Mat_uint32Swap(tag);
                packed_type = TYPE_FROM_TAG(tag[0]);
                if ( tag[0] & 0xffff0000 ) { 
                    data_in_tag = 1;
                    
                } else {
                    data_in_tag = 0;
                    bytesread += fread(tag+1,4,1,(FILE*)mat->fp);
                    if ( byteswap )
                        (void)Mat_uint32Swap(tag+1);
                    
                }
                matvar->data_type = MAT_T_UINT8;
                matvar->data_size = Mat_SizeOf(MAT_T_UINT8);
                err = SafeMul(&matvar->nbytes, nelems, matvar->data_size);
                if ( err ) {
                    Mat_Critical("Integer multiplication overflow");
                    break;
                }
            }
            if ( matvar->isComplex ) {
                break;
            }
            matvar->data = calloc(matvar->nbytes+1,1);
            if ( NULL == matvar->data ) {
                Mat_Critical("Couldn't allocate memory for the data");
                break;
            }
            if ( 0 == matvar->nbytes ) {
                break;
            }
            {
                size_t nbytes;
                err = SafeMul(&nbytes, nelems, matvar->data_size);
                if ( err || nbytes > matvar->nbytes ) {
                    break;
                }
            }
            if ( matvar->compression == MAT_COMPRESSION_NONE ) {
                nBytes = ReadCharData(mat,(char*)matvar->data,packed_type,(int)nelems);
                
                if ( data_in_tag )
                    nBytes+=4;
                if ( (nBytes % 8) != 0 )
                    (void)fseek((FILE*)mat->fp,8-(nBytes % 8),SEEK_CUR);

            } else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {
                nBytes = ReadCompressedCharData(mat,matvar->internal->z, (char*)matvar->data,packed_type,(int)nelems);
                
                if ( data_in_tag )
                    nBytes+=4;
                if ( (nBytes % 8) != 0 )
                    InflateSkip(mat,matvar->internal->z,8-(nBytes % 8));

            }
            break;
        case MAT_C_STRUCT:
        {
            matvar_t **fields;
            size_t i, nelems_x_nfields;

            matvar->data_type = MAT_T_STRUCT;
            err = SafeMul(&nelems_x_nfields, nelems, matvar->internal->num_fields);
            if ( err || !matvar->nbytes || !matvar->data_size || NULL == matvar->data )
                break;
            fields = (matvar_t **)matvar->data;
            for ( i = 0; i < nelems_x_nfields; i++ ) {
                if ( NULL != fields[i] ) {
                    Mat_VarRead5(mat,fields[i]);
                }
            }
            break;
        }
        case MAT_C_CELL:
        {
            matvar_t **cells;
            size_t i;

            if ( NULL == matvar->data ) {
                Mat_Critical("Data is NULL for cell array %s",matvar->name);
                break;
            }
            cells = (matvar_t **)matvar->data;
            for ( i = 0; i < nelems; i++ ) {
                if ( NULL != cells[i] ) {
                    Mat_VarRead5(mat, cells[i]);
                }
            }
            
            matvar->data_type = MAT_T_CELL;
            break;
        }
        case MAT_C_SPARSE:
        {
            mat_int32_t N = 0;
            mat_sparse_t *data;

            matvar->data_size = sizeof(mat_sparse_t);
            matvar->data      = malloc(matvar->data_size);
            if ( matvar->data == NULL ) {
                Mat_Critical("Mat_VarRead5: Allocation of data pointer failed");
                break;
            }
            data = (mat_sparse_t*)matvar->data;
            data->nzmax  = matvar->nbytes;
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
            
            bytesread += ReadSparse(mat, matvar, &data->nir, &data->ir);
            
            bytesread += ReadSparse(mat, matvar, &data->njc, &data->jc);
            
            if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {

                matvar->internal->z->avail_in = 0;
                InflateDataType(mat,matvar->internal->z,tag);
                if ( mat->byteswap )
                    (void)Mat_uint32Swap(tag);
                packed_type = TYPE_FROM_TAG(tag[0]);
                if ( tag[0] & 0xffff0000 ) { 
                    data_in_tag = 1;
                    N = (tag[0] & 0xffff0000) >> 16;
                } else {
                    data_in_tag = 0;
                    (void)ReadCompressedInt32Data(mat,matvar->internal->z, (mat_int32_t*)&N,MAT_T_INT32,1);
                }

            } else {
                bytesread += fread(tag,4,1,(FILE*)mat->fp);
                if ( mat->byteswap )
                    (void)Mat_uint32Swap(tag);
                packed_type = TYPE_FROM_TAG(tag[0]);
                if ( tag[0] & 0xffff0000 ) { 
                    data_in_tag = 1;
                    N = (tag[0] & 0xffff0000) >> 16;
                } else {
                    data_in_tag = 0;
                    bytesread += fread(&N,4,1,(FILE*)mat->fp);
                    if ( mat->byteswap )
                        (void)Mat_int32Swap(&N);
                }
            }
            if ( matvar->isLogical && packed_type == MAT_T_DOUBLE ) {
                
                packed_type = MAT_T_UINT8;
            }

            matvar->data_type = packed_type;

            matvar->data_type = MAT_T_DOUBLE;

            {
                size_t s_type = Mat_SizeOf(packed_type);
                if ( s_type == 0 )
                    break;
                data->ndata = N / s_type;
            }
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = ComplexMalloc(data->ndata*Mat_SizeOf(matvar->data_type));
                if ( NULL == complex_data ) {
                    Mat_Critical("Couldn't allocate memory for the complex sparse data");
                    break;
                }
                if ( matvar->compression == MAT_COMPRESSION_NONE ) {

                    switch ( matvar->data_type ) {
                        case MAT_T_DOUBLE:
                            nBytes = ReadDoubleData(mat,(double*)complex_data->Re, packed_type,data->ndata);
                            break;
                        case MAT_T_SINGLE:
                            nBytes = ReadSingleData(mat,(float*)complex_data->Re, packed_type,data->ndata);
                            break;
                        case MAT_T_INT64:

                            nBytes = ReadInt64Data(mat,(mat_int64_t*)complex_data->Re, packed_type,data->ndata);

                            break;
                        case MAT_T_UINT64:

                            nBytes = ReadUInt64Data(mat,(mat_uint64_t*)complex_data->Re, packed_type,data->ndata);

                            break;
                        case MAT_T_INT32:
                            nBytes = ReadInt32Data(mat,(mat_int32_t*)complex_data->Re, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT32:
                            nBytes = ReadUInt32Data(mat,(mat_uint32_t*)complex_data->Re, packed_type,data->ndata);
                            break;
                        case MAT_T_INT16:
                            nBytes = ReadInt16Data(mat,(mat_int16_t*)complex_data->Re, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT16:
                            nBytes = ReadUInt16Data(mat,(mat_uint16_t*)complex_data->Re, packed_type,data->ndata);
                            break;
                        case MAT_T_INT8:
                            nBytes = ReadInt8Data(mat,(mat_int8_t*)complex_data->Re, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT8:
                            nBytes = ReadUInt8Data(mat,(mat_uint8_t*)complex_data->Re, packed_type,data->ndata);
                            break;
                        default:
                            break;
                    }

                    nBytes = ReadDoubleData(mat,(double*)complex_data->Re, packed_type,data->ndata);

                    if ( data_in_tag )
                        nBytes+=4;
                    if ( (nBytes % 8) != 0 )
                        (void)fseek((FILE*)mat->fp,8-(nBytes % 8),SEEK_CUR);

                    
                    bytesread += fread(tag,4,1,(FILE*)mat->fp);
                    if ( byteswap )
                        (void)Mat_uint32Swap(tag);
                    packed_type = TYPE_FROM_TAG(tag[0]);
                    if ( tag[0] & 0xffff0000 ) { 
                        data_in_tag = 1;
                        nBytes = (tag[0] & 0xffff0000) >> 16;
                    } else {
                        data_in_tag = 0;
                        bytesread += fread(tag+1,4,1,(FILE*)mat->fp);
                        if ( byteswap )
                            (void)Mat_uint32Swap(tag+1);
                        nBytes = tag[1];
                    }

                    switch ( matvar->data_type ) {
                        case MAT_T_DOUBLE:
                            nBytes = ReadDoubleData(mat,(double*)complex_data->Im, packed_type,data->ndata);
                            break;
                        case MAT_T_SINGLE:
                            nBytes = ReadSingleData(mat,(float*)complex_data->Im, packed_type,data->ndata);
                            break;
                        case MAT_T_INT64:

                            nBytes = ReadInt64Data(mat,(mat_int64_t*)complex_data->Im, packed_type,data->ndata);

                            break;
                        case MAT_T_UINT64:

                            nBytes = ReadUInt64Data(mat,(mat_uint64_t*)complex_data->Im, packed_type,data->ndata);

                            break;
                        case MAT_T_INT32:
                            nBytes = ReadInt32Data(mat,(mat_int32_t*)complex_data->Im, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT32:
                            nBytes = ReadUInt32Data(mat,(mat_uint32_t*)complex_data->Im, packed_type,data->ndata);
                            break;
                        case MAT_T_INT16:
                            nBytes = ReadInt16Data(mat,(mat_int16_t*)complex_data->Im, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT16:
                            nBytes = ReadUInt16Data(mat,(mat_uint16_t*)complex_data->Im, packed_type,data->ndata);
                            break;
                        case MAT_T_INT8:
                            nBytes = ReadInt8Data(mat,(mat_int8_t*)complex_data->Im, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT8:
                            nBytes = ReadUInt8Data(mat,(mat_uint8_t*)complex_data->Im, packed_type,data->ndata);
                            break;
                        default:
                            break;
                    }

                    nBytes = ReadDoubleData(mat,(double*)complex_data->Im, packed_type,data->ndata);

                    if ( data_in_tag )
                        nBytes+=4;
                    if ( (nBytes % 8) != 0 )
                        (void)fseek((FILE*)mat->fp,8-(nBytes % 8),SEEK_CUR);

                } else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {

                    switch ( matvar->data_type ) {
                        case MAT_T_DOUBLE:
                            nBytes = ReadCompressedDoubleData(mat,matvar->internal->z, (double*)complex_data->Re,packed_type,data->ndata);
                            break;
                        case MAT_T_SINGLE:
                            nBytes = ReadCompressedSingleData(mat,matvar->internal->z, (float*)complex_data->Re,packed_type,data->ndata);
                            break;
                        case MAT_T_INT64:

                            nBytes = ReadCompressedInt64Data(mat, matvar->internal->z,(mat_int64_t*)complex_data->Re, packed_type,data->ndata);


                            break;
                        case MAT_T_UINT64:

                            nBytes = ReadCompressedUInt64Data(mat, matvar->internal->z,(mat_uint64_t*)complex_data->Re, packed_type,data->ndata);


                            break;
                        case MAT_T_INT32:
                            nBytes = ReadCompressedInt32Data(mat,matvar->internal->z, (mat_int32_t*)complex_data->Re,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT32:
                            nBytes = ReadCompressedUInt32Data(mat,matvar->internal->z, (mat_uint32_t*)complex_data->Re,packed_type,data->ndata);
                            break;
                        case MAT_T_INT16:
                            nBytes = ReadCompressedInt16Data(mat,matvar->internal->z, (mat_int16_t*)complex_data->Re,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT16:
                            nBytes = ReadCompressedUInt16Data(mat,matvar->internal->z, (mat_uint16_t*)complex_data->Re,packed_type,data->ndata);
                            break;
                        case MAT_T_INT8:
                            nBytes = ReadCompressedInt8Data(mat,matvar->internal->z, (mat_int8_t*)complex_data->Re,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT8:
                            nBytes = ReadCompressedUInt8Data(mat,matvar->internal->z, (mat_uint8_t*)complex_data->Re,packed_type,data->ndata);
                            break;
                        default:
                            break;
                    }

                    nBytes = ReadCompressedDoubleData(mat,matvar->internal->z, (double*)complex_data->Re,packed_type,data->ndata);

                    if ( data_in_tag )
                        nBytes+=4;
                    if ( (nBytes % 8) != 0 )
                        InflateSkip(mat,matvar->internal->z,8-(nBytes % 8));

                    
                    InflateDataType(mat,matvar->internal->z,tag);
                    if ( byteswap )
                        (void)Mat_uint32Swap(tag);

                    packed_type = TYPE_FROM_TAG(tag[0]);
                    if ( tag[0] & 0xffff0000 ) { 
                        data_in_tag = 1;
                        nBytes = (tag[0] & 0xffff0000) >> 16;
                    } else {
                        data_in_tag = 0;
                        InflateDataType(mat,matvar->internal->z,tag+1);
                        if ( byteswap )
                            (void)Mat_uint32Swap(tag+1);
                        nBytes = tag[1];
                    }

                    switch ( matvar->data_type ) {
                        case MAT_T_DOUBLE:
                            nBytes = ReadCompressedDoubleData(mat,matvar->internal->z, (double*)complex_data->Im,packed_type,data->ndata);
                            break;
                        case MAT_T_SINGLE:
                            nBytes = ReadCompressedSingleData(mat,matvar->internal->z, (float*)complex_data->Im,packed_type,data->ndata);
                            break;
                        case MAT_T_INT64:

                            nBytes = ReadCompressedInt64Data(mat, matvar->internal->z,(mat_int64_t*)complex_data->Im, packed_type,data->ndata);


                            break;
                        case MAT_T_UINT64:

                            nBytes = ReadCompressedUInt64Data(mat, matvar->internal->z,(mat_uint64_t*)complex_data->Im, packed_type,data->ndata);


                            break;
                        case MAT_T_INT32:
                            nBytes = ReadCompressedInt32Data(mat,matvar->internal->z, (mat_int32_t*)complex_data->Im,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT32:
                            nBytes = ReadCompressedUInt32Data(mat,matvar->internal->z, (mat_uint32_t*)complex_data->Im,packed_type,data->ndata);
                            break;
                        case MAT_T_INT16:
                            nBytes = ReadCompressedInt16Data(mat,matvar->internal->z, (mat_int16_t*)complex_data->Im,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT16:
                            nBytes = ReadCompressedUInt16Data(mat,matvar->internal->z, (mat_uint16_t*)complex_data->Im,packed_type,data->ndata);
                            break;
                        case MAT_T_INT8:
                            nBytes = ReadCompressedInt8Data(mat,matvar->internal->z, (mat_int8_t*)complex_data->Im,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT8:
                            nBytes = ReadCompressedUInt8Data(mat,matvar->internal->z, (mat_uint8_t*)complex_data->Im,packed_type,data->ndata);
                            break;
                        default:
                            break;
                    }

                    nBytes = ReadCompressedDoubleData(mat,matvar->internal->z, (double*)complex_data->Im,packed_type,data->ndata);

                    if ( data_in_tag )
                        nBytes+=4;
                    if ( (nBytes % 8) != 0 )
                        InflateSkip(mat,matvar->internal->z,8-(nBytes % 8));

                }
                data->data = complex_data;
            } else { 
                data->data = malloc(data->ndata*Mat_SizeOf(matvar->data_type));
                if ( data->data == NULL ) {
                    Mat_Critical("Couldn't allocate memory for the sparse data");
                    break;
                }
                if ( matvar->compression == MAT_COMPRESSION_NONE ) {

                    switch ( matvar->data_type ) {
                        case MAT_T_DOUBLE:
                            nBytes = ReadDoubleData(mat,(double*)data->data, packed_type,data->ndata);
                            break;
                        case MAT_T_SINGLE:
                            nBytes = ReadSingleData(mat,(float*)data->data, packed_type,data->ndata);
                            break;
                        case MAT_T_INT64:

                            nBytes = ReadInt64Data(mat,(mat_int64_t*)data->data, packed_type,data->ndata);

                            break;
                        case MAT_T_UINT64:

                            nBytes = ReadUInt64Data(mat,(mat_uint64_t*)data->data, packed_type,data->ndata);

                            break;
                        case MAT_T_INT32:
                            nBytes = ReadInt32Data(mat,(mat_int32_t*)data->data, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT32:
                            nBytes = ReadUInt32Data(mat,(mat_uint32_t*)data->data, packed_type,data->ndata);
                            break;
                        case MAT_T_INT16:
                            nBytes = ReadInt16Data(mat,(mat_int16_t*)data->data, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT16:
                            nBytes = ReadUInt16Data(mat,(mat_uint16_t*)data->data, packed_type,data->ndata);
                            break;
                        case MAT_T_INT8:
                            nBytes = ReadInt8Data(mat,(mat_int8_t*)data->data, packed_type,data->ndata);
                            break;
                        case MAT_T_UINT8:
                            nBytes = ReadUInt8Data(mat,(mat_uint8_t*)data->data, packed_type,data->ndata);
                            break;
                        default:
                            break;
                    }

                    nBytes = ReadDoubleData(mat,(double*)data->data,packed_type, data->ndata);

                    if ( data_in_tag )
                        nBytes+=4;
                    if ( (nBytes % 8) != 0 )
                        (void)fseek((FILE*)mat->fp,8-(nBytes % 8),SEEK_CUR);

                } else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {

                    switch ( matvar->data_type ) {
                        case MAT_T_DOUBLE:
                            nBytes = ReadCompressedDoubleData(mat,matvar->internal->z, (double*)data->data,packed_type,data->ndata);
                            break;
                        case MAT_T_SINGLE:
                            nBytes = ReadCompressedSingleData(mat,matvar->internal->z, (float*)data->data,packed_type,data->ndata);
                            break;
                        case MAT_T_INT64:

                            nBytes = ReadCompressedInt64Data(mat, matvar->internal->z,(mat_int64_t*)data->data,packed_type, data->ndata);


                            break;
                        case MAT_T_UINT64:

                            nBytes = ReadCompressedUInt64Data(mat, matvar->internal->z,(mat_uint64_t*)data->data,packed_type, data->ndata);


                            break;
                        case MAT_T_INT32:
                            nBytes = ReadCompressedInt32Data(mat,matvar->internal->z, (mat_int32_t*)data->data,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT32:
                            nBytes = ReadCompressedUInt32Data(mat,matvar->internal->z, (mat_uint32_t*)data->data,packed_type,data->ndata);
                            break;
                        case MAT_T_INT16:
                            nBytes = ReadCompressedInt16Data(mat,matvar->internal->z, (mat_int16_t*)data->data,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT16:
                            nBytes = ReadCompressedUInt16Data(mat,matvar->internal->z, (mat_uint16_t*)data->data,packed_type,data->ndata);
                            break;
                        case MAT_T_INT8:
                            nBytes = ReadCompressedInt8Data(mat,matvar->internal->z, (mat_int8_t*)data->data,packed_type,data->ndata);
                            break;
                        case MAT_T_UINT8:
                            nBytes = ReadCompressedUInt8Data(mat,matvar->internal->z, (mat_uint8_t*)data->data,packed_type,data->ndata);
                            break;
                        default:
                            break;
                    }

                    nBytes = ReadCompressedDoubleData(mat,matvar->internal->z, (double*)data->data,packed_type,data->ndata);

                    if ( data_in_tag )
                        nBytes+=4;
                    if ( (nBytes % 8) != 0 )
                        InflateSkip(mat,matvar->internal->z,8-(nBytes % 8));

                }
            }
            break;
        }
        case MAT_C_FUNCTION:
        {
            matvar_t **functions;
            size_t nfunctions = 0;

            if ( !matvar->nbytes || !matvar->data_size )
                break;
            nfunctions = matvar->nbytes / matvar->data_size;
            functions = (matvar_t **)matvar->data;
            if ( NULL != functions ) {
                size_t i;
                for ( i = 0; i < nfunctions; i++ ) {
                    Mat_VarRead5(mat,functions[i]);
                }
            }
            
            matvar->data_type = MAT_T_FUNCTION;
            break;
        }
        default:
            Mat_Critical("Mat_VarRead5: %d is not a supported class", matvar->class_type);
    }
    switch ( matvar->class_type ) {
        case MAT_C_DOUBLE:
        case MAT_C_SINGLE:

        case MAT_C_INT64:


        case MAT_C_UINT64:

        case MAT_C_INT32:
        case MAT_C_UINT32:
        case MAT_C_INT16:
        case MAT_C_UINT16:
        case MAT_C_INT8:
        case MAT_C_UINT8:
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data;

                err = SafeMul(&matvar->nbytes, nelems, matvar->data_size);
                if ( err ) {
                    Mat_Critical("Integer multiplication overflow");
                    break;
                }

                complex_data = ComplexMalloc(matvar->nbytes);
                if ( NULL == complex_data ) {
                    Mat_Critical("Couldn't allocate memory for the complex data");
                    break;
                }

                Mat_VarReadNumeric5(mat,matvar,complex_data->Re,nelems);
                Mat_VarReadNumeric5(mat,matvar,complex_data->Im,nelems);
                matvar->data = complex_data;
            } else {
                err = SafeMul(&matvar->nbytes, nelems, matvar->data_size);
                if ( err ) {
                    Mat_Critical("Integer multiplication overflow");
                    break;
                }

                matvar->data = malloc(matvar->nbytes);
                if ( NULL == matvar->data ) {
                    Mat_Critical("Couldn't allocate memory for the data");
                    break;
                }
                Mat_VarReadNumeric5(mat,matvar,matvar->data,nelems);
            }
        default:
            break;
    }
    (void)fseek((FILE*)mat->fp,fpos,SEEK_SET);

    return;
}





















































































































































































































































static int GetDataSlab(void *data_in, void *data_out, enum matio_classes class_type, enum matio_types data_type, size_t *dims, int *start, int *stride, int *edge, int rank, size_t nbytes)


{
    int err = 0;
    int same_type = 0;
    if (( class_type == MAT_C_DOUBLE && data_type == MAT_T_DOUBLE ) || ( class_type == MAT_C_SINGLE && data_type == MAT_T_SINGLE ) || ( class_type == MAT_C_INT16 && data_type == MAT_T_INT16 ) || ( class_type == MAT_C_INT32 && data_type == MAT_T_INT32 ) || ( class_type == MAT_C_INT64 && data_type == MAT_T_INT64 ) || ( class_type == MAT_C_INT8 && data_type == MAT_T_INT8 ) || ( class_type == MAT_C_UINT16 && data_type == MAT_T_UINT16 ) || ( class_type == MAT_C_UINT32 && data_type == MAT_T_UINT32 ) || ( class_type == MAT_C_UINT64 && data_type == MAT_T_UINT64 ) || ( class_type == MAT_C_UINT8 && data_type == MAT_T_UINT8 ))








        same_type = 1;

    if ( rank == 2 ) {
        if ( (size_t)stride[0]*(edge[0]-1)+start[0]+1 > dims[0] )
            err = 1;
        else if ( (size_t)stride[1]*(edge[1]-1)+start[1]+1 > dims[1] )
            err = 1;
        else if ( ( stride[0] == 1 && edge[0] == dims[0] ) && ( stride[1] == 1 ) && ( same_type == 1 ) )
            memcpy(data_out, data_in, nbytes);
        else {
            int i, j;

            switch ( class_type ) {
                case MAT_C_DOUBLE:
                {
                    double *ptr = (double *)data_out;
                    GET_DATA_SLAB2_TYPE(double);
                    break;
                }
                case MAT_C_SINGLE:
                {
                    float *ptr = (float *)data_out;
                    GET_DATA_SLAB2_TYPE(float);
                    break;
                }

                case MAT_C_INT64:
                {
                    mat_int64_t *ptr = (mat_int64_t *)data_out;
                    GET_DATA_SLAB2_TYPE(mat_int64_t);
                    break;
                }


                case MAT_C_UINT64:
                {
                    mat_uint64_t *ptr = (mat_uint64_t *)data_out;
                    GET_DATA_SLAB2_TYPE(mat_uint64_t);
                    break;
                }

                case MAT_C_INT32:
                {
                    mat_int32_t *ptr = (mat_int32_t *)data_out;
                    GET_DATA_SLAB2_TYPE(mat_int32_t);
                    break;
                }
                case MAT_C_UINT32:
                {
                    mat_uint32_t *ptr = (mat_uint32_t *)data_out;
                    GET_DATA_SLAB2_TYPE(mat_uint32_t);
                    break;
                }
                case MAT_C_INT16:
                {
                    mat_int16_t *ptr = (mat_int16_t *)data_out;
                    GET_DATA_SLAB2_TYPE(mat_int16_t);
                    break;
                }
                case MAT_C_UINT16:
                {
                    mat_uint16_t *ptr = (mat_uint16_t *)data_out;
                    GET_DATA_SLAB2_TYPE(mat_uint16_t);
                    break;
                }
                case MAT_C_INT8:
                {
                    mat_int8_t *ptr = (mat_int8_t *)data_out;
                    GET_DATA_SLAB2_TYPE(mat_int8_t);
                    break;
                }
                case MAT_C_UINT8:
                {
                    mat_uint8_t *ptr = (mat_uint8_t *)data_out;
                    GET_DATA_SLAB2_TYPE(mat_uint8_t);
                    break;
                }
                default:
                    err = 1;
                    break;
            }
        }
    } else {
        int i, j, N, I = 0;
        int inc[10] = {0,}, cnt[10] = {0,}, dimp[10] = {0,};

        switch ( class_type ) {
            case MAT_C_DOUBLE:
            {
                double *ptr = (double *)data_out;
                GET_DATA_SLABN_TYPE(double);
                break;
            }
            case MAT_C_SINGLE:
            {
                float *ptr = (float *)data_out;
                GET_DATA_SLABN_TYPE(float);
                break;
            }

            case MAT_C_INT64:
            {
                mat_int64_t *ptr = (mat_int64_t *)data_out;
                GET_DATA_SLABN_TYPE(mat_int64_t);
                break;
            }


            case MAT_C_UINT64:
            {
                mat_uint64_t *ptr = (mat_uint64_t *)data_out;
                GET_DATA_SLABN_TYPE(mat_uint64_t);
                break;
            }

            case MAT_C_INT32:
            {
                mat_int32_t *ptr = (mat_int32_t *)data_out;
                GET_DATA_SLABN_TYPE(mat_int32_t);
                break;
            }
            case MAT_C_UINT32:
            {
                mat_uint32_t *ptr = (mat_uint32_t *)data_out;
                GET_DATA_SLABN_TYPE(mat_uint32_t);
                break;
            }
            case MAT_C_INT16:
            {
                mat_int16_t *ptr = (mat_int16_t *)data_out;
                GET_DATA_SLABN_TYPE(mat_int16_t);
                break;
            }
            case MAT_C_UINT16:
            {
                mat_uint16_t *ptr = (mat_uint16_t *)data_out;
                GET_DATA_SLABN_TYPE(mat_uint16_t);
                break;
            }
            case MAT_C_INT8:
            {
                mat_int8_t *ptr = (mat_int8_t *)data_out;
                GET_DATA_SLABN_TYPE(mat_int8_t);
                break;
            }
            case MAT_C_UINT8:
            {
                mat_uint8_t *ptr = (mat_uint8_t *)data_out;
                GET_DATA_SLABN_TYPE(mat_uint8_t);
                break;
            }
            default:
                err = 1;
                break;
        }
    }

    return err;
}






















static int GetDataLinear(void *data_in, void *data_out, enum matio_classes class_type, enum matio_types data_type, int start, int stride, int edge)

{
    int err = 0;
    size_t data_size = Mat_SizeOf(data_type);

    switch ( class_type ) {
        case MAT_C_DOUBLE:
        {
            double *ptr = (double *)data_out;
            double *ptr_in = (double*)data_in;
            GET_DATA_LINEAR;
            break;
        }
        case MAT_C_SINGLE:
        {
            float *ptr = (float *)data_out;
            float *ptr_in = (float*)data_in;
            GET_DATA_LINEAR;
            break;
        }

        case MAT_C_INT64:
        {
            mat_int64_t *ptr = (mat_int64_t *)data_out;
            mat_int64_t *ptr_in = (mat_int64_t*)data_in;
            GET_DATA_LINEAR;
            break;
        }


        case MAT_C_UINT64:
        {
            mat_uint64_t *ptr = (mat_uint64_t *)data_out;
            mat_uint64_t *ptr_in = (mat_uint64_t*)data_in;
            GET_DATA_LINEAR;
            break;
        }

        case MAT_C_INT32:
        {
            mat_int32_t *ptr = (mat_int32_t *)data_out;
            mat_int32_t *ptr_in = (mat_int32_t*)data_in;
            GET_DATA_LINEAR;
            break;
        }
        case MAT_C_UINT32:
        {
            mat_uint32_t *ptr = (mat_uint32_t *)data_out;
            mat_uint32_t *ptr_in = (mat_uint32_t*)data_in;
            GET_DATA_LINEAR;
            break;
        }
        case MAT_C_INT16:
        {
            mat_int16_t *ptr = (mat_int16_t *)data_out;
            mat_int16_t *ptr_in = (mat_int16_t*)data_in;
            GET_DATA_LINEAR;
            break;
        }
        case MAT_C_UINT16:
        {
            mat_uint16_t *ptr = (mat_uint16_t *)data_out;
            mat_uint16_t *ptr_in = (mat_uint16_t*)data_in;
            GET_DATA_LINEAR;
            break;
        }
        case MAT_C_INT8:
        {
            mat_int8_t *ptr = (mat_int8_t *)data_out;
            mat_int8_t *ptr_in = (mat_int8_t*)data_in;
            GET_DATA_LINEAR;
            break;
        }
        case MAT_C_UINT8:
        {
            mat_uint8_t *ptr = (mat_uint8_t *)data_out;
            mat_uint8_t *ptr_in = (mat_uint8_t*)data_in;
            GET_DATA_LINEAR;
            break;
        }
        default:
            err = 1;
            break;
    }

    return err;
}





int Mat_VarReadData5(mat_t *mat,matvar_t *matvar,void *data, int *start,int *stride,int *edge)

{
    int err = 0,real_bytes = 0;
    mat_int32_t tag[2];

    z_stream z;

    size_t bytesread = 0;

    (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
    if ( matvar->compression == MAT_COMPRESSION_NONE ) {
        bytesread += fread(tag,4,2,(FILE*)mat->fp);
        if ( mat->byteswap ) {
            (void)Mat_int32Swap(tag);
            (void)Mat_int32Swap(tag+1);
        }
        matvar->data_type = TYPE_FROM_TAG(tag[0]);
        if ( tag[0] & 0xffff0000 ) { 
            (void)fseek((FILE*)mat->fp,-4,SEEK_CUR);
            real_bytes = 4+(tag[0] >> 16);
        } else {
            real_bytes = 8+tag[1];
        }

    } else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {
        if ( NULL != matvar->internal->data ) {
            
            if ( matvar->isComplex ) {
                mat_complex_split_t *ci, *co;

                co = (mat_complex_split_t*)data;
                ci = (mat_complex_split_t*)matvar->internal->data;
                err = GetDataSlab(ci->Re, co->Re, matvar->class_type, matvar->data_type, matvar->dims, start, stride, edge, matvar->rank, matvar->nbytes);

                if ( err == 0 )
                    err = GetDataSlab(ci->Im, co->Im, matvar->class_type, matvar->data_type, matvar->dims, start, stride, edge, matvar->rank, matvar->nbytes);

                return err;
            } else {
                return GetDataSlab(matvar->internal->data, data, matvar->class_type, matvar->data_type, matvar->dims, start, stride, edge, matvar->rank, matvar->nbytes);

            }
        }

        err = inflateCopy(&z,matvar->internal->z);
        if ( err != Z_OK ) {
            Mat_Critical("inflateCopy returned error %s",zError(err));
            return -1;
        }
        z.avail_in = 0;
        InflateDataType(mat,&z,tag);
        if ( mat->byteswap ) {
            (void)Mat_int32Swap(tag);
        }
        matvar->data_type = TYPE_FROM_TAG(tag[0]);
        if ( !(tag[0] & 0xffff0000) ) {
            
            InflateDataType(mat,&z,tag+1);
            if ( mat->byteswap ) {
                (void)Mat_int32Swap(tag+1);
            }
            real_bytes = 8+tag[1];
        } else {
            real_bytes = 4+(tag[0] >> 16);
        }

    }
    if ( real_bytes % 8 )
        real_bytes += (8-(real_bytes % 8));

    if ( matvar->rank == 2 ) {
        if ( (size_t)stride[0]*(edge[0]-1)+start[0]+1 > matvar->dims[0] )
            err = 1;
        else if ( (size_t)stride[1]*(edge[1]-1)+start[1]+1 > matvar->dims[1] )
            err = 1;
        else if ( matvar->compression == MAT_COMPRESSION_NONE ) {
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = (mat_complex_split_t*)data;

                ReadDataSlab2(mat,complex_data->Re,matvar->class_type, matvar->data_type,matvar->dims,start,stride,edge);
                (void)fseek((FILE*)mat->fp,matvar->internal->datapos+real_bytes,SEEK_SET);
                bytesread += fread(tag,4,2,(FILE*)mat->fp);
                if ( mat->byteswap ) {
                    (void)Mat_int32Swap(tag);
                    (void)Mat_int32Swap(tag+1);
                }
                matvar->data_type = TYPE_FROM_TAG(tag[0]);
                if ( tag[0] & 0xffff0000 ) { 
                    (void)fseek((FILE*)mat->fp,-4,SEEK_CUR);
                }
                ReadDataSlab2(mat,complex_data->Im,matvar->class_type, matvar->data_type,matvar->dims,start,stride,edge);
            } else {
                ReadDataSlab2(mat,data,matvar->class_type, matvar->data_type,matvar->dims,start,stride,edge);
            }
        }

        else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = (mat_complex_split_t*)data;

                ReadCompressedDataSlab2(mat,&z,complex_data->Re, matvar->class_type,matvar->data_type,matvar->dims, start,stride,edge);


                (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);

                
                inflateEnd(&z);
                err = inflateCopy(&z,matvar->internal->z);
                if ( err != Z_OK ) {
                    Mat_Critical("inflateCopy returned error %s",zError(err));
                }
                InflateSkip(mat,&z,real_bytes);
                z.avail_in = 0;
                InflateDataType(mat,&z,tag);
                if ( mat->byteswap ) {
                    (void)Mat_int32Swap(tag);
                }
                matvar->data_type = TYPE_FROM_TAG(tag[0]);
                if ( !(tag[0] & 0xffff0000) ) {
                    InflateSkip(mat,&z,4);
                }
                ReadCompressedDataSlab2(mat,&z,complex_data->Im, matvar->class_type,matvar->data_type,matvar->dims, start,stride,edge);

            } else {
                ReadCompressedDataSlab2(mat,&z,data,matvar->class_type, matvar->data_type,matvar->dims,start,stride,edge);
            }
            inflateEnd(&z);
        }

    } else {
        if ( matvar->compression == MAT_COMPRESSION_NONE ) {
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = (mat_complex_split_t*)data;

                ReadDataSlabN(mat,complex_data->Re,matvar->class_type, matvar->data_type,matvar->rank,matvar->dims, start,stride,edge);


                (void)fseek((FILE*)mat->fp,matvar->internal->datapos+real_bytes,SEEK_SET);
                bytesread += fread(tag,4,2,(FILE*)mat->fp);
                if ( mat->byteswap ) {
                    (void)Mat_int32Swap(tag);
                    (void)Mat_int32Swap(tag+1);
                }
                matvar->data_type = TYPE_FROM_TAG(tag[0]);
                if ( tag[0] & 0xffff0000 ) { 
                    (void)fseek((FILE*)mat->fp,-4,SEEK_CUR);
                }
                ReadDataSlabN(mat,complex_data->Im,matvar->class_type, matvar->data_type,matvar->rank,matvar->dims, start,stride,edge);

            } else {
                ReadDataSlabN(mat,data,matvar->class_type,matvar->data_type, matvar->rank,matvar->dims,start,stride,edge);
            }
        }

        else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {
            if ( matvar->isComplex ) {
                mat_complex_split_t *complex_data = (mat_complex_split_t*)data;

                ReadCompressedDataSlabN(mat,&z,complex_data->Re, matvar->class_type,matvar->data_type,matvar->rank, matvar->dims,start,stride,edge);


                (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
                
                inflateEnd(&z);
                err = inflateCopy(&z,matvar->internal->z);
                if ( err != Z_OK ) {
                    Mat_Critical("inflateCopy returned error %s",zError(err));
                }
                InflateSkip(mat,&z,real_bytes);
                z.avail_in = 0;
                InflateDataType(mat,&z,tag);
                if ( mat->byteswap ) {
                    (void)Mat_int32Swap(tag);
                }
                matvar->data_type = TYPE_FROM_TAG(tag[0]);
                if ( !(tag[0] & 0xffff0000) ) {
                    InflateSkip(mat,&z,4);
                }
                ReadCompressedDataSlabN(mat,&z,complex_data->Im, matvar->class_type,matvar->data_type,matvar->rank, matvar->dims,start,stride,edge);

            } else {
                ReadCompressedDataSlabN(mat,&z,data,matvar->class_type, matvar->data_type,matvar->rank,matvar->dims, start,stride,edge);

            }
            inflateEnd(&z);
        }

    }
    if ( err == 0 ) {
        matvar->data_type = ClassType2DataType(matvar->class_type);
        matvar->data_size = Mat_SizeOfClass(matvar->class_type);
    }
    return err;
}


int Mat_VarReadDataLinear5(mat_t *mat,matvar_t *matvar,void *data,int start, int stride,int edge)

{
    int err = 0, real_bytes = 0;
    mat_int32_t tag[2];

    z_stream z;

    size_t bytesread = 0, nelems = 1;

    if ( mat->version == MAT_FT_MAT4 )
        return -1;
    (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);
    if ( matvar->compression == MAT_COMPRESSION_NONE ) {
        bytesread += fread(tag,4,2,(FILE*)mat->fp);
        if ( mat->byteswap ) {
            (void)Mat_int32Swap(tag);
            (void)Mat_int32Swap(tag+1);
        }
        matvar->data_type = (enum matio_types)(tag[0] & 0x000000ff);
        if ( tag[0] & 0xffff0000 ) { 
            (void)fseek((FILE*)mat->fp,-4,SEEK_CUR);
            real_bytes = 4+(tag[0] >> 16);
        } else {
            real_bytes = 8+tag[1];
        }

    } else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {
        if ( NULL != matvar->internal->data ) {
            
            if ( matvar->isComplex ) {
                mat_complex_split_t *ci, *co;

                co = (mat_complex_split_t*)data;
                ci = (mat_complex_split_t*)matvar->internal->data;
                err = GetDataLinear(ci->Re, co->Re, matvar->class_type, matvar->data_type, start, stride, edge);
                if ( err == 0 )
                    err = GetDataLinear(ci->Im, co->Im, matvar->class_type, matvar->data_type, start, stride, edge);
                return err;
            } else {
                return GetDataLinear(matvar->internal->data, data, matvar->class_type, matvar->data_type, start, stride, edge);
            }
        }

        matvar->internal->z->avail_in = 0;
        err = inflateCopy(&z,matvar->internal->z);
        if ( err != Z_OK ) {
            Mat_Critical("inflateCopy returned error %s",zError(err));
            return -1;
        }
        InflateDataType(mat,&z,tag);
        if ( mat->byteswap ) {
            (void)Mat_int32Swap(tag);
            (void)Mat_int32Swap(tag+1);
        }
        matvar->data_type = (enum matio_types)(tag[0] & 0x000000ff);
        if ( !(tag[0] & 0xffff0000) ) {
            
            InflateDataType(mat,&z,tag+1);
            if ( mat->byteswap ) {
                (void)Mat_int32Swap(tag+1);
            }
            real_bytes = 8+tag[1];
        } else {
            real_bytes = 4+(tag[0] >> 16);
        }

    }
    if ( real_bytes % 8 )
        real_bytes += (8-(real_bytes % 8));

    err = SafeMulDims(matvar, &nelems);
    if ( err ) {
        Mat_Critical("Integer multiplication overflow");
        return -1;
    }

    if ( (size_t)stride*(edge-1)+start+1 > nelems ) {
        err = 1;
    } else if ( matvar->compression == MAT_COMPRESSION_NONE ) {
        if ( matvar->isComplex ) {
            mat_complex_split_t *complex_data = (mat_complex_split_t*)data;

            ReadDataSlab1(mat,complex_data->Re,matvar->class_type, matvar->data_type,start,stride,edge);
            (void)fseek((FILE*)mat->fp,matvar->internal->datapos+real_bytes,SEEK_SET);
            bytesread += fread(tag,4,2,(FILE*)mat->fp);
            if ( mat->byteswap ) {
                (void)Mat_int32Swap(tag);
                (void)Mat_int32Swap(tag+1);
            }
            matvar->data_type = (enum matio_types)(tag[0] & 0x000000ff);
            if ( tag[0] & 0xffff0000 ) { 
                (void)fseek((FILE*)mat->fp,-4,SEEK_CUR);
            }
            ReadDataSlab1(mat,complex_data->Im,matvar->class_type, matvar->data_type,start,stride,edge);
        } else {
            ReadDataSlab1(mat,data,matvar->class_type, matvar->data_type,start,stride,edge);
        }

    } else if ( matvar->compression == MAT_COMPRESSION_ZLIB ) {
        if ( matvar->isComplex ) {
            mat_complex_split_t *complex_data = (mat_complex_split_t*)data;

            ReadCompressedDataSlab1(mat,&z,complex_data->Re, matvar->class_type,matvar->data_type,start,stride,edge);

            (void)fseek((FILE*)mat->fp,matvar->internal->datapos,SEEK_SET);

            
            inflateEnd(&z);
            err = inflateCopy(&z,matvar->internal->z);
            if ( err != Z_OK ) {
                Mat_Critical("inflateCopy returned error %s",zError(err));
            }
            InflateSkip(mat,&z,real_bytes);
            z.avail_in = 0;
            InflateDataType(mat,&z,tag);
            if ( mat->byteswap ) {
                (void)Mat_int32Swap(tag);
            }
            matvar->data_type = (enum matio_types)(tag[0] & 0x000000ff);
            if ( !(tag[0] & 0xffff0000) ) {
                InflateSkip(mat,&z,4);
            }
            ReadCompressedDataSlab1(mat,&z,complex_data->Im, matvar->class_type,matvar->data_type,start,stride,edge);
        } else {
            ReadCompressedDataSlab1(mat,&z,data,matvar->class_type, matvar->data_type,start,stride,edge);
        }
        inflateEnd(&z);

    }

    matvar->data_type = ClassType2DataType(matvar->class_type);
    matvar->data_size = Mat_SizeOfClass(matvar->class_type);

    return err;
}


int Mat_VarWrite5(mat_t *mat,matvar_t *matvar,int compress)
{
    mat_uint32_t array_flags;
    int array_flags_type = MAT_T_UINT32, dims_array_type = MAT_T_INT32;
    int array_flags_size = 8, pad4 = 0, matrix_type = MAT_T_MATRIX;
    int nBytes, i, nzmax = 0;
    long start = 0, end = 0;

    if ( NULL == mat )
        return -1;

    
    (void)fseek((FILE*)mat->fp,0,SEEK_END);         

    if ( NULL == matvar || NULL == matvar->name )
        return -1;


    if ( compress == MAT_COMPRESSION_NONE ) {

    {

        fwrite(&matrix_type,4,1,(FILE*)mat->fp);
        fwrite(&pad4,4,1,(FILE*)mat->fp);
        start = ftell((FILE*)mat->fp);

        
        array_flags = matvar->class_type & CLASS_TYPE_MASK;
        if ( matvar->isComplex )
            array_flags |= MAT_F_COMPLEX;
        if ( matvar->isGlobal )
            array_flags |= MAT_F_GLOBAL;
        if ( matvar->isLogical )
            array_flags |= MAT_F_LOGICAL;
        if ( matvar->class_type == MAT_C_SPARSE )
            nzmax = ((mat_sparse_t *)matvar->data)->nzmax;

        fwrite(&array_flags_type,4,1,(FILE*)mat->fp);
        fwrite(&array_flags_size,4,1,(FILE*)mat->fp);
        fwrite(&array_flags,4,1,(FILE*)mat->fp);
        fwrite(&nzmax,4,1,(FILE*)mat->fp);
        
        nBytes = matvar->rank * 4;
        fwrite(&dims_array_type,4,1,(FILE*)mat->fp);
        fwrite(&nBytes,4,1,(FILE*)mat->fp);
        for ( i = 0; i < matvar->rank; i++ ) {
            mat_int32_t dim;
            dim = matvar->dims[i];
            fwrite(&dim,4,1,(FILE*)mat->fp);
        }
        if ( matvar->rank % 2 != 0 )
            fwrite(&pad4,4,1,(FILE*)mat->fp);
        
        if ( strlen(matvar->name) <= 4 ) {
            mat_int32_t  array_name_type = MAT_T_INT8;
            mat_int32_t array_name_len   = (mat_int32_t)strlen(matvar->name);
            mat_int8_t  pad1 = 0;

            fwrite(&array_name_type,2,1,(FILE*)mat->fp);
            fwrite(&array_name_len,2,1,(FILE*)mat->fp);

            array_name_type = (array_name_len << 16) | array_name_type;
            fwrite(&array_name_type,4,1,(FILE*)mat->fp);

            fwrite(matvar->name,1,array_name_len,(FILE*)mat->fp);
            for ( i = array_name_len; i < 4; i++ )
                fwrite(&pad1,1,1,(FILE*)mat->fp);
        } else {
            mat_int32_t array_name_type = MAT_T_INT8;
            mat_int32_t array_name_len  = (mat_int32_t)strlen(matvar->name);
            mat_int8_t  pad1 = 0;

            fwrite(&array_name_type,4,1,(FILE*)mat->fp);
            fwrite(&array_name_len,4,1,(FILE*)mat->fp);
            fwrite(matvar->name,1,array_name_len,(FILE*)mat->fp);
            if ( array_name_len % 8 )
                for ( i = array_name_len % 8; i < 8; i++ )
                    fwrite(&pad1,1,1,(FILE*)mat->fp);
        }

        if ( NULL != matvar->internal ) {
            matvar->internal->datapos = ftell((FILE*)mat->fp);
            if ( matvar->internal->datapos == -1L ) {
                Mat_Critical("Couldn't determine file position");
            }
        } else {
            
            matvar->class_type = MAT_C_EMPTY;
        }
        WriteType(mat,matvar);

    } else if ( compress == MAT_COMPRESSION_ZLIB ) {
        mat_uint32_t comp_buf[512];
        mat_uint32_t uncomp_buf[512] = {0,};
        int buf_size = 512, err;
        size_t byteswritten = 0, matrix_max_buf_size;
        z_streamp z;

        z = (z_streamp)calloc(1,sizeof(*z));
        if ( z == NULL )
            return -1;
        err = deflateInit(z,Z_DEFAULT_COMPRESSION);
        if ( err != Z_OK ) {
            free(z);
            Mat_Critical("deflateInit returned %s",zError(err));
            return -1;
        }

        matrix_type = MAT_T_COMPRESSED;
        fwrite(&matrix_type,4,1,(FILE*)mat->fp);
        fwrite(&pad4,4,1,(FILE*)mat->fp);
        start = ftell((FILE*)mat->fp);

        
        array_flags = matvar->class_type & CLASS_TYPE_MASK;
        if ( matvar->isComplex )
            array_flags |= MAT_F_COMPLEX;
        if ( matvar->isGlobal )
            array_flags |= MAT_F_GLOBAL;
        if ( matvar->isLogical )
            array_flags |= MAT_F_LOGICAL;
        if ( matvar->class_type == MAT_C_SPARSE )
            nzmax = ((mat_sparse_t *)matvar->data)->nzmax;

        uncomp_buf[0] = MAT_T_MATRIX;
        err = GetMatrixMaxBufSize(matvar, &matrix_max_buf_size);
        if (err || matrix_max_buf_size > UINT32_MAX)
            return -1;
        uncomp_buf[1] = matrix_max_buf_size;
        z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
        z->avail_in = 8;
        do {
            z->next_out  = ZLIB_BYTE_PTR(comp_buf);
            z->avail_out = buf_size*sizeof(*comp_buf);
            deflate(z,Z_NO_FLUSH);
            byteswritten += fwrite(comp_buf,1, buf_size*sizeof(*comp_buf)-z->avail_out,(FILE*)mat->fp);
        } while ( z->avail_out == 0 );
        uncomp_buf[0] = array_flags_type;
        uncomp_buf[1] = array_flags_size;
        uncomp_buf[2] = array_flags;
        uncomp_buf[3] = nzmax;
        
        nBytes = matvar->rank * 4;
        uncomp_buf[4] = dims_array_type;
        uncomp_buf[5] = nBytes;
        for ( i = 0; i < matvar->rank; i++ ) {
            mat_int32_t dim;
            dim = matvar->dims[i];
            uncomp_buf[6+i] = dim;
        }
        if ( matvar->rank % 2 != 0 ) {
            uncomp_buf[6+i] = pad4;
            i++;
        }

        z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
        z->avail_in = (6+i)*sizeof(*uncomp_buf);
        do {
            z->next_out  = ZLIB_BYTE_PTR(comp_buf);
            z->avail_out = buf_size*sizeof(*comp_buf);
            deflate(z,Z_NO_FLUSH);
            byteswritten += fwrite(comp_buf,1, buf_size*sizeof(*comp_buf)-z->avail_out,(FILE*)mat->fp);
        } while ( z->avail_out == 0 );
        
        if ( strlen(matvar->name) <= 4 ) {
            mat_int16_t array_name_len = (mat_int16_t)strlen(matvar->name);
            mat_int16_t array_name_type = MAT_T_INT8;

            memset(uncomp_buf,0,8);
            uncomp_buf[0] = (array_name_len << 16) | array_name_type;
            memcpy(uncomp_buf+1,matvar->name,array_name_len);
            if ( array_name_len % 4 )
                array_name_len += 4-(array_name_len % 4);

            z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
            z->avail_in = 8;
            do {
                z->next_out  = ZLIB_BYTE_PTR(comp_buf);
                z->avail_out = buf_size*sizeof(*comp_buf);
                deflate(z,Z_NO_FLUSH);
                byteswritten += fwrite(comp_buf,1, buf_size*sizeof(*comp_buf)-z->avail_out,(FILE*)mat->fp);
            } while ( z->avail_out == 0 );
        } else {
            mat_int32_t array_name_len = (mat_int32_t)strlen(matvar->name);
            mat_int32_t array_name_type = MAT_T_INT8;

            memset(uncomp_buf,0,buf_size*sizeof(*uncomp_buf));
            uncomp_buf[0] = array_name_type;
            uncomp_buf[1] = array_name_len;
            memcpy(uncomp_buf+2,matvar->name,array_name_len);
            if ( array_name_len % 8 )
                array_name_len += 8-(array_name_len % 8);
            z->next_in  = ZLIB_BYTE_PTR(uncomp_buf);
            z->avail_in = 8+array_name_len;
            do {
                z->next_out  = ZLIB_BYTE_PTR(comp_buf);
                z->avail_out = buf_size*sizeof(*comp_buf);
                deflate(z,Z_NO_FLUSH);
                byteswritten += fwrite(comp_buf,1, buf_size*sizeof(*comp_buf)-z->avail_out,(FILE*)mat->fp);
            } while ( z->avail_out == 0 );
        }
        if ( NULL != matvar->internal ) {
            matvar->internal->datapos = ftell((FILE*)mat->fp);
            if ( matvar->internal->datapos == -1L ) {
                Mat_Critical("Couldn't determine file position");
            }
        } else {
            
            matvar->class_type = MAT_C_EMPTY;
        }
        WriteCompressedType(mat,matvar,z);
        z->next_in  = NULL;
        z->avail_in = 0;
        do {
            z->next_out  = ZLIB_BYTE_PTR(comp_buf);
            z->avail_out = buf_size*sizeof(*comp_buf);
            err = deflate(z,Z_FINISH);
            byteswritten += fwrite(comp_buf,1, buf_size*sizeof(*comp_buf)-z->avail_out,(FILE*)mat->fp);
        } while ( err != Z_STREAM_END && z->avail_out == 0 );

        if ( byteswritten % 8 )
            for ( i = 0; i < 8-(byteswritten % 8); i++ )
                fwrite(&pad1,1,1,(FILE*)mat->fp);

        (void)deflateEnd(z);
        free(z);

    }
    end = ftell((FILE*)mat->fp);
    if ( start != -1L && end != -1L ) {
        nBytes = (int)(end-start);
        (void)fseek((FILE*)mat->fp,(long)-(nBytes+4),SEEK_CUR);
        fwrite(&nBytes,4,1,(FILE*)mat->fp);
        (void)fseek((FILE*)mat->fp,end,SEEK_SET);
    } else {
        Mat_Critical("Couldn't determine file position");
    }

    return 0;
}


matvar_t * Mat_VarReadNextInfo5( mat_t *mat )
{
    int err;
    mat_int32_t data_type, nBytes;
    long fpos;
    matvar_t *matvar = NULL;
    mat_uint32_t array_flags;

    if ( mat == NULL )
        return NULL;

    fpos = ftell((FILE*)mat->fp);
    if ( fpos == -1L ) {
        Mat_Critical("Couldn't determine file position");
        return NULL;
    }
    err = fread(&data_type,4,1,(FILE*)mat->fp);
    if ( err == 0 )
        return NULL;
    err = fread(&nBytes,4,1,(FILE*)mat->fp);
    if ( mat->byteswap ) {
        (void)Mat_int32Swap(&data_type);
        (void)Mat_int32Swap(&nBytes);
    }
    switch ( data_type ) {
        case MAT_T_COMPRESSED:
        {

            mat_uint32_t uncomp_buf[16] = {0,};
            int      nbytes;
            long     bytesread = 0;

            matvar = Mat_VarCalloc();
            if ( NULL == matvar ) {
                Mat_Critical("Couldn't allocate memory");
                break;
            }

            matvar->compression = MAT_COMPRESSION_ZLIB;
            matvar->internal->z = (z_streamp)calloc(1,sizeof(z_stream));
            err = inflateInit(matvar->internal->z);
            if ( err != Z_OK ) {
                Mat_VarFree(matvar);
                matvar = NULL;
                Mat_Critical("inflateInit returned %s",zError(err));
                break;
            }

            
            bytesread += InflateVarTag(mat,matvar,uncomp_buf);
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(uncomp_buf);
                (void)Mat_uint32Swap(uncomp_buf+1);
            }
            nbytes = uncomp_buf[1];
            if ( uncomp_buf[0] != MAT_T_MATRIX ) {
                (void)fseek((FILE*)mat->fp,nBytes-bytesread,SEEK_CUR);
                Mat_VarFree(matvar);
                matvar = NULL;
                Mat_Critical("Uncompressed type not MAT_T_MATRIX");
                break;
            }
            
            bytesread += InflateArrayFlags(mat,matvar,uncomp_buf);
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(uncomp_buf);
                (void)Mat_uint32Swap(uncomp_buf+2);
                (void)Mat_uint32Swap(uncomp_buf+3);
            }
            
            if ( uncomp_buf[0] == MAT_T_UINT32 ) {
                array_flags = uncomp_buf[2];
                matvar->class_type = CLASS_FROM_ARRAY_FLAGS(array_flags);
                matvar->isComplex  = (array_flags & MAT_F_COMPLEX);
                matvar->isGlobal   = (array_flags & MAT_F_GLOBAL);
                matvar->isLogical  = (array_flags & MAT_F_LOGICAL);
                if ( matvar->class_type == MAT_C_SPARSE ) {
                    
                    matvar->nbytes = uncomp_buf[3];
                }
            }
            if ( matvar->class_type != MAT_C_OPAQUE ) {
                mat_uint32_t* dims = NULL;
                int do_clean = 0;
                bytesread += InflateRankDims(mat,matvar,uncomp_buf,sizeof(uncomp_buf),&dims);
                if ( NULL == dims )
                    dims = uncomp_buf + 2;
                else do_clean = 1;
                if ( mat->byteswap ) {
                    (void)Mat_uint32Swap(uncomp_buf);
                    (void)Mat_uint32Swap(uncomp_buf+1);
                }
                
                if ( uncomp_buf[0] == MAT_T_INT32 ) {
                    int j;
                    nbytes = uncomp_buf[1];
                    matvar->rank = nbytes / 4;
                    matvar->dims = (size_t*)malloc(matvar->rank*sizeof(*matvar->dims));
                    if ( mat->byteswap ) {
                        for ( j = 0; j < matvar->rank; j++ )
                            matvar->dims[j] = Mat_uint32Swap(dims + j);
                    } else {
                        for ( j = 0; j < matvar->rank; j++ )
                            matvar->dims[j] = dims[j];
                    }
                }
                if ( do_clean )
                    free(dims);
                
                bytesread += InflateVarTag(mat,matvar,uncomp_buf);
                if ( mat->byteswap )
                    (void)Mat_uint32Swap(uncomp_buf);
                
                if ( uncomp_buf[0] == MAT_T_INT8 ) {    
                    mat_uint32_t len, len_pad;
                    if ( mat->byteswap )
                        len = Mat_uint32Swap(uncomp_buf+1);
                    else len = uncomp_buf[1];

                    if ( len % 8 == 0 )
                        len_pad = len;
                    else len_pad = len + 8 - (len % 8);
                    matvar->name = (char*)malloc(len_pad + 1);
                    if ( NULL != matvar->name ) {
                        
                        bytesread += InflateVarName(mat,matvar,matvar->name,len_pad);
                        matvar->name[len] = '\0';
                    }
                } else {
                    mat_uint32_t len = (uncomp_buf[0] & 0xffff0000) >> 16;
                    if ( ((uncomp_buf[0] & 0x0000ffff) == MAT_T_INT8) && len > 0 && len <= 4 ) {
                        
                        matvar->name = (char*)malloc(len+1);
                        if ( NULL != matvar->name ) {
                            memcpy(matvar->name,uncomp_buf+1,len);
                            matvar->name[len] = '\0';
                        }
                    }
                }
                if ( matvar->class_type == MAT_C_STRUCT )
                    (void)ReadNextStructField(mat,matvar);
                else if ( matvar->class_type == MAT_C_CELL )
                    (void)ReadNextCell(mat,matvar);
                (void)fseek((FILE*)mat->fp,-(int)matvar->internal->z->avail_in,SEEK_CUR);
                matvar->internal->datapos = ftell((FILE*)mat->fp);
                if ( matvar->internal->datapos == -1L ) {
                    Mat_Critical("Couldn't determine file position");
                }
            }
            (void)fseek((FILE*)mat->fp,nBytes+8+fpos,SEEK_SET);
            break;

            Mat_Critical("Compressed variable found in \"%s\", but matio was " "built without zlib support",mat->filename);
            (void)fseek((FILE*)mat->fp,nBytes+8+fpos,SEEK_SET);
            return NULL;

        }
        case MAT_T_MATRIX:
        {
            mat_uint32_t buf[6];
            size_t readresult;

            
            readresult = fread(buf, 4, 6, (FILE*)mat->fp);
            if ( 6 != readresult ) {
                (void)fseek((FILE*)mat->fp, fpos, SEEK_SET);
                break;
            }
            if ( mat->byteswap ) {
                (void)Mat_uint32Swap(buf);
                (void)Mat_uint32Swap(buf+1);
                (void)Mat_uint32Swap(buf+2);
                (void)Mat_uint32Swap(buf+3);
                (void)Mat_uint32Swap(buf+4);
                (void)Mat_uint32Swap(buf+5);
            }

            matvar = Mat_VarCalloc();
            if ( NULL == matvar ) {
                Mat_Critical("Couldn't allocate memory");
                break;
            }

            
            if ( buf[0] == MAT_T_UINT32 ) {
               array_flags = buf[2];
               matvar->class_type = CLASS_FROM_ARRAY_FLAGS(array_flags);
               matvar->isComplex  = (array_flags & MAT_F_COMPLEX);
               matvar->isGlobal   = (array_flags & MAT_F_GLOBAL);
               matvar->isLogical  = (array_flags & MAT_F_LOGICAL);
               if ( matvar->class_type == MAT_C_SPARSE ) {
                   
                   matvar->nbytes = buf[3];
               }
            }
            readresult = ReadRankDims(mat, matvar, (enum matio_types)buf[4], buf[5]);
            if ( 0 == readresult && 0 < matvar->rank ) {
                Mat_VarFree(matvar);
                matvar = NULL;
                (void)fseek((FILE*)mat->fp, fpos, SEEK_SET);
                break;
            }
            
            readresult = fread(buf, 4, 2, (FILE*)mat->fp);
            if ( 2 != readresult ) {
                Mat_VarFree(matvar);
                matvar = NULL;
                (void)fseek((FILE*)mat->fp, fpos, SEEK_SET);
                break;
            }
            if ( mat->byteswap )
                (void)Mat_uint32Swap(buf);
            
            if ( buf[0] == MAT_T_INT8 ) {    
                mat_uint32_t len, len_pad;
                if ( mat->byteswap )
                    len = Mat_uint32Swap(buf+1);
                else len = buf[1];
                if ( len % 8 == 0 )
                    len_pad = len;
                else len_pad = len + 8 - (len % 8);
                matvar->name = (char*)malloc(len_pad + 1);
                if ( NULL != matvar->name ) {
                    readresult = fread(matvar->name, 1, len_pad, (FILE*)mat->fp);
                    if ( readresult == len_pad ) {
                        matvar->name[len] = '\0';
                    } else {
                        Mat_VarFree(matvar);
                        matvar = NULL;
                        (void)fseek((FILE*)mat->fp, fpos, SEEK_SET);
                        break;
                    }
                }
            } else {
                mat_uint32_t len = (buf[0] & 0xffff0000) >> 16;
                if ( ((buf[0] & 0x0000ffff) == MAT_T_INT8) && len > 0 && len <= 4 ) {
                    
                    matvar->name = (char*)malloc(len+1);
                    if ( NULL != matvar->name ) {
                        memcpy(matvar->name, buf+1, len);
                        matvar->name[len] = '\0';
                    }
                }
            }
            if ( matvar->class_type == MAT_C_STRUCT )
                (void)ReadNextStructField(mat,matvar);
            else if ( matvar->class_type == MAT_C_CELL )
                (void)ReadNextCell(mat,matvar);
            else if ( matvar->class_type == MAT_C_FUNCTION )
                (void)ReadNextFunctionHandle(mat,matvar);
            matvar->internal->datapos = ftell((FILE*)mat->fp);
            if ( matvar->internal->datapos == -1L ) {
                Mat_Critical("Couldn't determine file position");
            }
            (void)fseek((FILE*)mat->fp,nBytes+8+fpos,SEEK_SET);
            break;
        }
        default:
            Mat_Critical("%d is not valid (MAT_T_MATRIX or MAT_T_COMPRESSED)", data_type);
            return NULL;
    }

    return matvar;
}
