
















strong_alias(create_buf,	slurm_create_buf);
strong_alias(free_buf,		slurm_free_buf);
strong_alias(grow_buf,		slurm_grow_buf);
strong_alias(init_buf,		slurm_init_buf);
strong_alias(xfer_buf_data,	slurm_xfer_buf_data);
strong_alias(pack_time,		slurm_pack_time);
strong_alias(unpack_time,	slurm_unpack_time);
strong_alias(packdouble,	slurm_packdouble);
strong_alias(unpackdouble,	slurm_unpackdouble);
strong_alias(packlongdouble,	slurm_packlongdouble);
strong_alias(unpacklongdouble,	slurm_unpacklongdouble);
strong_alias(pack64,		slurm_pack64);
strong_alias(unpack64,		slurm_unpack64);
strong_alias(pack32,		slurm_pack32);
strong_alias(unpack32,		slurm_unpack32);
strong_alias(pack16,		slurm_pack16);
strong_alias(unpack16,		slurm_unpack16);
strong_alias(pack8,		slurm_pack8);
strong_alias(unpack8,		slurm_unpack8);
strong_alias(pack16_array,      slurm_pack16_array);
strong_alias(unpack16_array,    slurm_unpack16_array);
strong_alias(pack32_array,	slurm_pack32_array);
strong_alias(unpack32_array,	slurm_unpack32_array);
strong_alias(packmem,		slurm_packmem);
strong_alias(unpackmem,		slurm_unpackmem);
strong_alias(unpackmem_ptr,	slurm_unpackmem_ptr);
strong_alias(unpackmem_xmalloc,	slurm_unpackmem_xmalloc);
strong_alias(unpackmem_malloc,	slurm_unpackmem_malloc);
strong_alias(packstr_array,	slurm_packstr_array);
strong_alias(unpackstr_array,	slurm_unpackstr_array);
strong_alias(packmem_array,	slurm_packmem_array);
strong_alias(unpackmem_array,	slurm_unpackmem_array);



Buf create_buf(char *data, uint32_t size)
{
	Buf my_buf;

	if (size > MAX_BUF_SIZE) {
		error("%s: Buffer size limit exceeded (%u > %u)", __func__, size, MAX_BUF_SIZE);
		return NULL;
	}

	my_buf = xmalloc_nz(sizeof(struct slurm_buf));
	my_buf->magic = BUF_MAGIC;
	my_buf->size = size;
	my_buf->processed = 0;
	my_buf->head = data;

	return my_buf;
}


void free_buf(Buf my_buf)
{
	if (!my_buf)
		return;
	assert(my_buf->magic == BUF_MAGIC);
	xfree(my_buf->head);
	xfree(my_buf);
}


void grow_buf (Buf buffer, uint32_t size)
{
	if ((buffer->size + size) > MAX_BUF_SIZE) {
		error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + size), MAX_BUF_SIZE);
		return;
	}

	buffer->size += size;
	xrealloc_nz(buffer->head, buffer->size);
}


Buf init_buf(uint32_t size)
{
	Buf my_buf;

	if (size > MAX_BUF_SIZE) {
		error("%s: Buffer size limit exceeded (%u > %u)", __func__, size, MAX_BUF_SIZE);
		return NULL;
	}
	if (size <= 0)
		size = BUF_SIZE;
	my_buf = xmalloc_nz(sizeof(struct slurm_buf));
	my_buf->magic = BUF_MAGIC;
	my_buf->size = size;
	my_buf->processed = 0;
	my_buf->head = xmalloc(sizeof(char)*size);
	return my_buf;
}


void *xfer_buf_data(Buf my_buf)
{
	void *data_ptr;

	assert(my_buf->magic == BUF_MAGIC);
	data_ptr = (void *) my_buf->head;
	xfree(my_buf);
	return data_ptr;
}


void pack_time(time_t val, Buf buffer)
{
	int64_t n64 = HTON_int64((int64_t) val);

	if (remaining_buf(buffer) < sizeof(n64)) {
		if ((buffer->size + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += BUF_SIZE;
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], &n64, sizeof(n64));
	buffer->processed += sizeof(n64);
}

int unpack_time(time_t * valp, Buf buffer)
{
	int64_t n64;

	if (remaining_buf(buffer) < sizeof(n64))
		return SLURM_ERROR;

	memcpy(&n64, &buffer->head[buffer->processed], sizeof(n64));
	buffer->processed += sizeof(n64);
	*valp = (time_t) NTOH_int64(n64);
	return SLURM_SUCCESS;
}



void 	packdouble(double val, Buf buffer)
{
	uint64_t nl;
	union {
		double d;
		uint64_t u;
	} uval;

	 
	uval.d =  (val * FLOAT_MULT);
	nl =  HTON_uint64(uval.u);
	if (remaining_buf(buffer) < sizeof(nl)) {
		if ((buffer->size + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += BUF_SIZE;
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], &nl, sizeof(nl));
	buffer->processed += sizeof(nl);
}


int	unpackdouble(double *valp, Buf buffer)
{
	uint64_t nl;
	union {
		double d;
		uint64_t u;
	} uval;

	if (remaining_buf(buffer) < sizeof(nl))
		return SLURM_ERROR;

	memcpy(&nl, &buffer->head[buffer->processed], sizeof(nl));
	buffer->processed += sizeof(nl);

	uval.u = NTOH_uint64(nl);
	*valp = uval.d / FLOAT_MULT;

	return SLURM_SUCCESS;
}


void 	packlongdouble(long double val, Buf buffer)
{
	char val_str[256];

	snprintf(val_str, sizeof(val_str), "%Lf", val);
	packstr(val_str, buffer);
}


int	unpacklongdouble(long double *valp, Buf buffer)
{
	long double nl;
	char *val_str = NULL;
	uint32_t size_val_str = 0;
	int rc;

	rc = unpackmem_ptr(&val_str, &size_val_str, buffer);
	if (rc != SLURM_SUCCESS)
		return rc;

	if (sscanf(val_str, "%Lf", &nl) != 1)
		return SLURM_ERROR;

	*valp = nl;
	return SLURM_SUCCESS;
}


void pack64(uint64_t val, Buf buffer)
{
	uint64_t nl =  HTON_uint64(val);

	if (remaining_buf(buffer) < sizeof(nl)) {
		if ((buffer->size + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += BUF_SIZE;
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], &nl, sizeof(nl));
	buffer->processed += sizeof(nl);
}


int unpack64(uint64_t * valp, Buf buffer)
{
	uint64_t nl;
	if (remaining_buf(buffer) < sizeof(nl))
		return SLURM_ERROR;

	memcpy(&nl, &buffer->head[buffer->processed], sizeof(nl));
	*valp = NTOH_uint64(nl);
	buffer->processed += sizeof(nl);
	return SLURM_SUCCESS;
}


void pack32(uint32_t val, Buf buffer)
{
	uint32_t nl = htonl(val);

	if (remaining_buf(buffer) < sizeof(nl)) {
		if ((buffer->size + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += BUF_SIZE;
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], &nl, sizeof(nl));
	buffer->processed += sizeof(nl);
}


int unpack32(uint32_t * valp, Buf buffer)
{
	uint32_t nl;
	if (remaining_buf(buffer) < sizeof(nl))
		return SLURM_ERROR;

	memcpy(&nl, &buffer->head[buffer->processed], sizeof(nl));
	*valp = ntohl(nl);
	buffer->processed += sizeof(nl);
	return SLURM_SUCCESS;
}


void pack16_array(uint16_t * valp, uint32_t size_val, Buf buffer)
{
	uint32_t i = 0;

	pack32(size_val, buffer);

	for (i = 0; i < size_val; i++) {
		pack16(*(valp + i), buffer);
	}
}


int unpack16_array(uint16_t ** valp, uint32_t * size_val, Buf buffer)
{
	uint32_t i = 0;

	if (unpack32(size_val, buffer))
		return SLURM_ERROR;

	*valp = xmalloc_nz((*size_val) * sizeof(uint16_t));
	for (i = 0; i < *size_val; i++) {
		if (unpack16((*valp) + i, buffer))
			return SLURM_ERROR;
	}
	return SLURM_SUCCESS;
}


void pack32_array(uint32_t * valp, uint32_t size_val, Buf buffer)
{
	uint32_t i = 0;

	pack32(size_val, buffer);

	for (i = 0; i < size_val; i++) {
		pack32(*(valp + i), buffer);
	}
}


int unpack32_array(uint32_t ** valp, uint32_t * size_val, Buf buffer)
{
	uint32_t i = 0;

	if (unpack32(size_val, buffer))
		return SLURM_ERROR;

	*valp = xmalloc_nz((*size_val) * sizeof(uint32_t));
	for (i = 0; i < *size_val; i++) {
		if (unpack32((*valp) + i, buffer))
			return SLURM_ERROR;
	}
	return SLURM_SUCCESS;
}


void pack64_array(uint64_t * valp, uint32_t size_val, Buf buffer)
{
	uint32_t i = 0;

	pack32(size_val, buffer);

	for (i = 0; i < size_val; i++) {
		pack64(*(valp + i), buffer);
	}
}


void pack64_array_as_32(uint64_t * valp, uint32_t size_val, Buf buffer)
{
	uint32_t i = 0;

	pack32(size_val, buffer);

	for (i = 0; i < size_val; i++) {
		pack32((uint32_t) *(valp + i), buffer);
	}
}


int unpack64_array(uint64_t ** valp, uint32_t * size_val, Buf buffer)
{
	uint32_t i = 0;

	if (unpack32(size_val, buffer))
		return SLURM_ERROR;

	*valp = xmalloc_nz((*size_val) * sizeof(uint64_t));
	for (i = 0; i < *size_val; i++) {
		if (unpack64((*valp) + i, buffer))
			return SLURM_ERROR;
	}
	return SLURM_SUCCESS;
}


int unpack64_array_from_32(uint64_t ** valp, uint32_t * size_val, Buf buffer)
{
	uint32_t i = 0, val32;

	if (unpack32(size_val, buffer))
		return SLURM_ERROR;

	*valp = xmalloc_nz((*size_val) * sizeof(uint64_t));
	for (i = 0; i < *size_val; i++) {
		if (unpack32(&val32, buffer))
			return SLURM_ERROR;
		*(*valp + i) = val32;
	}
	return SLURM_SUCCESS;
}

void packdouble_array(double *valp, uint32_t size_val, Buf buffer)
{
	uint32_t i = 0;

	pack32(size_val, buffer);

	for (i = 0; i < size_val; i++) {
		packdouble(*(valp + i), buffer);
	}
}

int unpackdouble_array(double **valp, uint32_t* size_val, Buf buffer)
{
	uint32_t i = 0;

	if (unpack32(size_val, buffer))
		return SLURM_ERROR;

	*valp = xmalloc_nz((*size_val) * sizeof(double));
	for (i = 0; i < *size_val; i++) {
		if (unpackdouble((*valp) + i, buffer))
			return SLURM_ERROR;
	}
	return SLURM_SUCCESS;
}

void packlongdouble_array(long double *valp, uint32_t size_val, Buf buffer)
{
	uint32_t i = 0;

	pack32(size_val, buffer);

	for (i = 0; i < size_val; i++) {
		packlongdouble(*(valp + i), buffer);
	}
}

int unpacklongdouble_array(long double **valp, uint32_t* size_val, Buf buffer)
{
	uint32_t i = 0;

	if (unpack32(size_val, buffer))
		return SLURM_ERROR;

	*valp = xmalloc_nz((*size_val) * sizeof(long double));
	for (i = 0; i < *size_val; i++) {
		if (unpacklongdouble((*valp) + i, buffer))
			return SLURM_ERROR;
	}
	return SLURM_SUCCESS;
}




void pack16(uint16_t val, Buf buffer)
{
	uint16_t ns = htons(val);

	if (remaining_buf(buffer) < sizeof(ns)) {
		if ((buffer->size + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += BUF_SIZE;
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], &ns, sizeof(ns));
	buffer->processed += sizeof(ns);
}


int unpack16(uint16_t * valp, Buf buffer)
{
	uint16_t ns;

	if (remaining_buf(buffer) < sizeof(ns))
		return SLURM_ERROR;

	memcpy(&ns, &buffer->head[buffer->processed], sizeof(ns));
	*valp = ntohs(ns);
	buffer->processed += sizeof(ns);
	return SLURM_SUCCESS;
}


void pack8(uint8_t val, Buf buffer)
{
	if (remaining_buf(buffer) < sizeof(uint8_t)) {
		if ((buffer->size + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += BUF_SIZE;
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], &val, sizeof(uint8_t));
	buffer->processed += sizeof(uint8_t);
}


int unpack8(uint8_t * valp, Buf buffer)
{
	if (remaining_buf(buffer) < sizeof(uint8_t))
		return SLURM_ERROR;

	memcpy(valp, &buffer->head[buffer->processed], sizeof(uint8_t));
	buffer->processed += sizeof(uint8_t);
	return SLURM_SUCCESS;
}


void packmem(char *valp, uint32_t size_val, Buf buffer)
{
	uint32_t ns = htonl(size_val);

	if (size_val > MAX_PACK_MEM_LEN) {
		error("%s: Buffer to be packed is too large (%u > %u)", __func__, size_val, MAX_PACK_MEM_LEN);
		return;
	}
	if (remaining_buf(buffer) < (sizeof(ns) + size_val)) {
		if ((buffer->size + size_val + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + size_val + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += (size_val + BUF_SIZE);
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], &ns, sizeof(ns));
	buffer->processed += sizeof(ns);

	if (size_val) {
		memcpy(&buffer->head[buffer->processed], valp, size_val);
		buffer->processed += size_val;
	}
}



int unpackmem_ptr(char **valp, uint32_t * size_valp, Buf buffer)
{
	uint32_t ns;

	if (remaining_buf(buffer) < sizeof(ns))
		return SLURM_ERROR;

	memcpy(&ns, &buffer->head[buffer->processed], sizeof(ns));
	*size_valp = ntohl(ns);
	buffer->processed += sizeof(ns);

	if (*size_valp > MAX_PACK_MEM_LEN) {
		error("%s: Buffer to be unpacked is too large (%u > %u)", __func__, *size_valp, MAX_PACK_MEM_LEN);
		return SLURM_ERROR;
	}
	else if (*size_valp > 0) {
		if (remaining_buf(buffer) < *size_valp)
			return SLURM_ERROR;
		*valp = &buffer->head[buffer->processed];
		buffer->processed += *size_valp;
	} else *valp = NULL;
	return SLURM_SUCCESS;
}



int unpackmem(char *valp, uint32_t * size_valp, Buf buffer)
{
	uint32_t ns;

	if (remaining_buf(buffer) < sizeof(ns))
		return SLURM_ERROR;

	memcpy(&ns, &buffer->head[buffer->processed], sizeof(ns));
	*size_valp = ntohl(ns);
	buffer->processed += sizeof(ns);

	if (*size_valp > MAX_PACK_MEM_LEN) {
		error("%s: Buffer to be unpacked is too large (%u > %u)", __func__, *size_valp, MAX_PACK_MEM_LEN);
		return SLURM_ERROR;
	}
	else if (*size_valp > 0) {
		if (remaining_buf(buffer) < *size_valp)
			return SLURM_ERROR;
		memcpy(valp, &buffer->head[buffer->processed], *size_valp);
		buffer->processed += *size_valp;
	} else *valp = 0;
	return SLURM_SUCCESS;
}


int unpackmem_xmalloc(char **valp, uint32_t * size_valp, Buf buffer)
{
	uint32_t ns;

	if (remaining_buf(buffer) < sizeof(ns))
		return SLURM_ERROR;

	memcpy(&ns, &buffer->head[buffer->processed], sizeof(ns));
	*size_valp = ntohl(ns);
	buffer->processed += sizeof(ns);

	if (*size_valp > MAX_PACK_MEM_LEN) {
		error("%s: Buffer to be unpacked is too large (%u > %u)", __func__, *size_valp, MAX_PACK_MEM_LEN);
		return SLURM_ERROR;
	}
	else if (*size_valp > 0) {
		if (remaining_buf(buffer) < *size_valp)
			return SLURM_ERROR;
		*valp = xmalloc_nz(*size_valp);
		memcpy(*valp, &buffer->head[buffer->processed], *size_valp);
		buffer->processed += *size_valp;
	} else *valp = NULL;
	return SLURM_SUCCESS;
}


int unpackmem_malloc(char **valp, uint32_t * size_valp, Buf buffer)
{
	uint32_t ns;

	if (remaining_buf(buffer) < sizeof(ns))
		return SLURM_ERROR;

	memcpy(&ns, &buffer->head[buffer->processed], sizeof(ns));
	*size_valp = ntohl(ns);
	buffer->processed += sizeof(ns);
	if (*size_valp > MAX_PACK_MEM_LEN) {
		error("%s: Buffer to be unpacked is too large (%u > %u)", __func__, *size_valp, MAX_PACK_MEM_LEN);
		return SLURM_ERROR;
	}
	else if (*size_valp > 0) {
		if (remaining_buf(buffer) < *size_valp)
			return SLURM_ERROR;
		*valp = malloc(*size_valp);
		if (*valp == NULL) {
			log_oom(__FILE__, __LINE__, __func__);
			abort();
		}
		memcpy(*valp, &buffer->head[buffer->processed], *size_valp);
		buffer->processed += *size_valp;
	} else *valp = NULL;
	return SLURM_SUCCESS;
}


void packstr_array(char **valp, uint32_t size_val, Buf buffer)
{
	int i;
	uint32_t ns = htonl(size_val);

	if (remaining_buf(buffer) < sizeof(ns)) {
		if ((buffer->size + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += BUF_SIZE;
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], &ns, sizeof(ns));
	buffer->processed += sizeof(ns);

	for (i = 0; i < size_val; i++) {
		packstr(valp[i], buffer);
	}

}


int unpackstr_array(char ***valp, uint32_t * size_valp, Buf buffer)
{
	int i;
	uint32_t ns;
	uint32_t uint32_tmp;

	if (remaining_buf(buffer) < sizeof(ns))
		return SLURM_ERROR;

	memcpy(&ns, &buffer->head[buffer->processed], sizeof(ns));
	*size_valp = ntohl(ns);
	buffer->processed += sizeof(ns);

	if (*size_valp > MAX_PACK_ARRAY_LEN) {
		error("%s: Buffer to be unpacked is too large (%u > %u)", __func__, *size_valp, MAX_PACK_ARRAY_LEN);
		return SLURM_ERROR;
	}
	else if (*size_valp > 0) {
		*valp = xmalloc_nz(sizeof(char *) * (*size_valp + 1));
		for (i = 0; i < *size_valp; i++) {
			if (unpackmem_xmalloc(&(*valp)[i], &uint32_tmp, buffer))
				return SLURM_ERROR;
		}
		(*valp)[i] = NULL;	
		
	} else *valp = NULL;
	return SLURM_SUCCESS;
}


void packmem_array(char *valp, uint32_t size_val, Buf buffer)
{
	if (remaining_buf(buffer) < size_val) {
		if ((buffer->size + size_val + BUF_SIZE) > MAX_BUF_SIZE) {
			error("%s: Buffer size limit exceeded (%u > %u)", __func__, (buffer->size + size_val + BUF_SIZE), MAX_BUF_SIZE);

			return;
		}
		buffer->size += (size_val + BUF_SIZE);
		xrealloc_nz(buffer->head, buffer->size);
	}

	memcpy(&buffer->head[buffer->processed], valp, size_val);
	buffer->processed += size_val;
}


int unpackmem_array(char *valp, uint32_t size_valp, Buf buffer)
{
	if (remaining_buf(buffer) >= size_valp) {
		memcpy(valp, &buffer->head[buffer->processed], size_valp);
		buffer->processed += size_valp;
		return SLURM_SUCCESS;
	} else {
		*valp = 0;
		return SLURM_ERROR;
	}
}
