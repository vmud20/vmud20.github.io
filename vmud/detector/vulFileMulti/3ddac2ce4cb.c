





















extern PTR malloc (size_t);
extern void free (PTR);










struct objalloc_chunk {
  
  struct objalloc_chunk *next;
  
  char *current_ptr;
};
















struct objalloc * objalloc_create (void)
{
  struct objalloc *ret;
  struct objalloc_chunk *chunk;

  ret = (struct objalloc *) malloc (sizeof *ret);
  if (ret == NULL)
    return NULL;

  ret->chunks = (PTR) malloc (CHUNK_SIZE);
  if (ret->chunks == NULL)
    {
      free (ret);
      return NULL;
    }

  chunk = (struct objalloc_chunk *) ret->chunks;
  chunk->next = NULL;
  chunk->current_ptr = NULL;

  ret->current_ptr = (char *) chunk + CHUNK_HEADER_SIZE;
  ret->current_space = CHUNK_SIZE - CHUNK_HEADER_SIZE;

  return ret;
}



PTR _objalloc_alloc (struct objalloc *o, unsigned long len)
{
  
  if (len == 0)
    len = 1;

  len = (len + OBJALLOC_ALIGN - 1) &~ (OBJALLOC_ALIGN - 1);

  if (len <= o->current_space)
    {
      o->current_ptr += len;
      o->current_space -= len;
      return (PTR) (o->current_ptr - len);
    }

  if (len >= BIG_REQUEST)
    {
      char *ret;
      struct objalloc_chunk *chunk;

      ret = (char *) malloc (CHUNK_HEADER_SIZE + len);
      if (ret == NULL)
	return NULL;

      chunk = (struct objalloc_chunk *) ret;
      chunk->next = (struct objalloc_chunk *) o->chunks;
      chunk->current_ptr = o->current_ptr;

      o->chunks = (PTR) chunk;

      return (PTR) (ret + CHUNK_HEADER_SIZE);
    }
  else {
      struct objalloc_chunk *chunk;

      chunk = (struct objalloc_chunk *) malloc (CHUNK_SIZE);
      if (chunk == NULL)
	return NULL;
      chunk->next = (struct objalloc_chunk *) o->chunks;
      chunk->current_ptr = NULL;

      o->current_ptr = (char *) chunk + CHUNK_HEADER_SIZE;
      o->current_space = CHUNK_SIZE - CHUNK_HEADER_SIZE;

      o->chunks = (PTR) chunk;

      return objalloc_alloc (o, len);
    }
}



void objalloc_free (struct objalloc *o)
{
  struct objalloc_chunk *l;

  l = (struct objalloc_chunk *) o->chunks;
  while (l != NULL)
    {
      struct objalloc_chunk *next;

      next = l->next;
      free (l);
      l = next;
    }

  free (o);
}



void objalloc_free_block (struct objalloc *o, PTR block)
{
  struct objalloc_chunk *p, *small;
  char *b = (char *) block;

  
  small = NULL;
  for (p = (struct objalloc_chunk *) o->chunks; p != NULL; p = p->next)
    {
      if (p->current_ptr == NULL)
	{
	  if (b > (char *) p && b < (char *) p + CHUNK_SIZE)
	    break;
	  small = p;
	}
      else {
	  if (b == (char *) p + CHUNK_HEADER_SIZE)
	    break;
	}
    }

  
  if (p == NULL)
    abort ();

  if (p->current_ptr == NULL)
    {
      struct objalloc_chunk *q;
      struct objalloc_chunk *first;

      

      first = NULL;
      q = (struct objalloc_chunk *) o->chunks;
      while (q != p)
	{
	  struct objalloc_chunk *next;

	  next = q->next;
	  if (small != NULL)
	    {
	      if (small == q)
		small = NULL;
	      free (q);
	    }
	  else if (q->current_ptr > b)
	    free (q);
	  else if (first == NULL)
	    first = q;

	  q = next;
	}

      if (first == NULL)
	first = p;
      o->chunks = (PTR) first;

      
      o->current_ptr = b;
      o->current_space = ((char *) p + CHUNK_SIZE) - b;
    }
  else {
      struct objalloc_chunk *q;
      char *current_ptr;

      

      current_ptr = p->current_ptr;
      p = p->next;

      q = (struct objalloc_chunk *) o->chunks;
      while (q != p)
	{
	  struct objalloc_chunk *next;

	  next = q->next;
	  free (q);
	  q = next;
	}

      o->chunks = (PTR) p;

      while (p->current_ptr != NULL)
	p = p->next;

      o->current_ptr = current_ptr;
      o->current_space = ((char *) p + CHUNK_SIZE) - current_ptr;
    }
}
