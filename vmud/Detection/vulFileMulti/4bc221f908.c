
















static void malloc_assert_failed(char *, const char *, int, const char *, const char *);








void *slurm_xmalloc(size_t size, bool clear, const char *file, int line, const char *func)
{
	void *new;
	size_t *p;
	size_t total_size = size + 2 * sizeof(size_t);

	if (size <= 0)
		return NULL;

	if (clear)
		p = calloc(1, total_size);
	else p = malloc(total_size);
	if (!p) {
		
		log_oom(file, line, func);
		abort();
	}
	p[0] = XMALLOC_MAGIC;	
	p[1] = size;		

	new = &p[2];
	return new;
}


void *slurm_try_xmalloc(size_t size, const char *file, int line, const char *func)
{
	void *new;
	size_t *p;
	size_t total_size = size + 2 * sizeof(size_t);

	if (size <= 0)
		return NULL;

	p = calloc(1, total_size);
	if (!p) {
		return NULL;
	}
	p[0] = XMALLOC_MAGIC;	
	p[1] = size;		

	new = &p[2];
	return new;
}


extern void * slurm_xrealloc(void **item, size_t newsize, bool clear, const char *file, int line, const char *func)
{
	size_t *p = NULL;

	if (*item != NULL) {
		size_t old_size;
		p = (size_t *)*item - 2;

		
		xmalloc_assert(p[0] == XMALLOC_MAGIC);
		old_size = p[1];

		p = realloc(p, newsize + 2*sizeof(size_t));
		if (p == NULL)
			goto error;

		if (old_size < newsize) {
			char *p_new = (char *)(&p[2]) + old_size;
			if (clear)
				memset(p_new, 0, (newsize-old_size));
		}
		xmalloc_assert(p[0] == XMALLOC_MAGIC);

	} else {
		size_t total_size = newsize + 2 * sizeof(size_t);
		
		if (clear)
			p = calloc(1, total_size);
		else p = malloc(total_size);
		if (p == NULL)
			goto error;
		p[0] = XMALLOC_MAGIC;
	}

	p[1] = newsize;
	*item = &p[2];
	return *item;

  error:
	log_oom(file, line, func);
	abort();
}


int slurm_try_xrealloc(void **item, size_t newsize, const char *file, int line, const char *func)
{
	size_t *p = NULL;

	if (*item != NULL) {
		size_t old_size;
		p = (size_t *)*item - 2;

		
		xmalloc_assert(p[0] == XMALLOC_MAGIC);
		old_size = p[1];

		p = realloc(p, newsize + 2*sizeof(size_t));
		if (p == NULL)
			return 0;

		if (old_size < newsize) {
			char *p_new = (char *)(&p[2]) + old_size;
			memset(p_new, 0, (newsize-old_size));
		}
		xmalloc_assert(p[0] == XMALLOC_MAGIC);

	} else {
		size_t total_size = newsize + 2 * sizeof(size_t);
		
		p = calloc(1, total_size);
		if (p == NULL)
			return 0;
		p[0] = XMALLOC_MAGIC;
	}

	p[1] = newsize;
	*item = &p[2];
	return 1;
}



size_t slurm_xsize(void *item, const char *file, int line, const char *func)
{
	size_t *p = (size_t *)item - 2;
	xmalloc_assert(item != NULL);
	xmalloc_assert(p[0] == XMALLOC_MAGIC); 
	return p[1];
}


void slurm_xfree(void **item, const char *file, int line, const char *func)
{
	if (*item != NULL) {
		size_t *p = (size_t *)*item - 2;
		
		xmalloc_assert(p[0] == XMALLOC_MAGIC);
		p[0] = 0;	
		free(p);
		*item = NULL;
	}
}


static void malloc_assert_failed(char *expr, const char *file, int line, const char *caller, const char *func)
{
	error("%s() Error: from %s:%d: %s(): Assertion (%s) failed", func, file, line, caller, expr);
	abort();
}

