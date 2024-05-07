













int __gconv_transliterate (struct __gconv_step *step, struct __gconv_step_data *step_data, void *trans_data __attribute__ ((unused)), const unsigned char *inbufstart, const unsigned char **inbufp, const unsigned char *inbufend, unsigned char **outbufstart, size_t *irreversible)






{
  
  uint_fast32_t size;
  const uint32_t *from_idx;
  const uint32_t *from_tbl;
  const uint32_t *to_idx;
  const uint32_t *to_tbl;
  const uint32_t *winbuf;
  const uint32_t *winbufend;
  uint_fast32_t low;
  uint_fast32_t high;

  
  winbuf = (const uint32_t *) *inbufp;
  winbufend = (const uint32_t *) inbufend;

  __gconv_fct fct = step->__fct;

  if (step->__shlib_handle != NULL)
    PTR_DEMANGLE (fct);


  
  size = _NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_TRANSLIT_TAB_SIZE);
  if (size == 0)
    goto no_rules;

  
  from_idx = (const uint32_t *) _NL_CURRENT (LC_CTYPE, _NL_CTYPE_TRANSLIT_FROM_IDX);
  from_tbl = (const uint32_t *) _NL_CURRENT (LC_CTYPE, _NL_CTYPE_TRANSLIT_FROM_TBL);
  to_idx = (const uint32_t *) _NL_CURRENT (LC_CTYPE, _NL_CTYPE_TRANSLIT_TO_IDX);
  to_tbl = (const uint32_t *) _NL_CURRENT (LC_CTYPE, _NL_CTYPE_TRANSLIT_TO_TBL);

  
  if (winbuf + 1 > winbufend)
    return (winbuf == winbufend ? __GCONV_EMPTY_INPUT : __GCONV_INCOMPLETE_INPUT);

  
  low = 0;
  high = size;
  while (low < high)
    {
      uint_fast32_t med = (low + high) / 2;
      uint32_t idx;
      int cnt;

      
      idx = from_idx[med];
      cnt = 0;
      do {
	  if (from_tbl[idx + cnt] != winbuf[cnt])
	    
	    break;
	  ++cnt;
	}
      while (from_tbl[idx + cnt] != L'\0' && winbuf + cnt < winbufend);

      if (cnt > 0 && from_tbl[idx + cnt] == L'\0')
	{
	  
	  uint32_t idx2 = to_idx[med];

	  do {
	      
	      uint_fast32_t len = 0;
	      int res;
	      const unsigned char *toinptr;
	      unsigned char *outptr;

	      while (to_tbl[idx2 + len] != L'\0')
		++len;

	      
	      toinptr = (const unsigned char *) &to_tbl[idx2];
	      outptr = *outbufstart;
	      res = DL_CALL_FCT (fct, (step, step_data, &toinptr, (const unsigned char *) &to_tbl[idx2 + len], &outptr, NULL, 0, 0));


	      if (res != __GCONV_ILLEGAL_INPUT)
		{
		  
		  if (res == __GCONV_EMPTY_INPUT)
		    {
		      *inbufp += cnt * sizeof (uint32_t);
		      ++*irreversible;
		      res = __GCONV_OK;
		    }
		  
		  if (res != __GCONV_FULL_OUTPUT)
		    *outbufstart = outptr;

		  return res;
		}

	      
	      idx2 += len + 1;
	    }
	  while (to_tbl[idx2] != L'\0');

	  
	}
      else if (cnt > 0)
	
	return __GCONV_INCOMPLETE_INPUT;

      if (winbuf + cnt >= winbufend || from_tbl[idx + cnt] < winbuf[cnt])
	low = med + 1;
      else high = med;
    }

 no_rules:
  
  if (_NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_TRANSLIT_IGNORE_LEN) != 0)
    {
      int n = _NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_TRANSLIT_IGNORE_LEN);
      const uint32_t *ranges = (const uint32_t *) _NL_CURRENT (LC_CTYPE, _NL_CTYPE_TRANSLIT_IGNORE);
      const uint32_t wc = *(const uint32_t *) (*inbufp);
      int i;

      
      if (winbuf + 1 > winbufend)
	return (winbuf == winbufend ? __GCONV_EMPTY_INPUT : __GCONV_INCOMPLETE_INPUT);

      for (i = 0; i < n; ranges += 3, ++i)
	if (ranges[0] <= wc && wc <= ranges[1] && (wc - ranges[0]) % ranges[2] == 0)
	  {
	    
	    *inbufp += 4;
	    ++*irreversible;
	    return __GCONV_OK;
	  }
	else if (wc < ranges[0])
	  
	  break;
    }

  
  if (_NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_TRANSLIT_DEFAULT_MISSING_LEN) != 0)
    {
      const uint32_t *default_missing = (const uint32_t *)
	_NL_CURRENT (LC_CTYPE, _NL_CTYPE_TRANSLIT_DEFAULT_MISSING);
      const unsigned char *toinptr = (const unsigned char *) default_missing;
      uint32_t len = _NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_TRANSLIT_DEFAULT_MISSING_LEN);
      unsigned char *outptr;
      int res;

      
      if (winbuf + 1 > winbufend)
	return (winbuf == winbufend ? __GCONV_EMPTY_INPUT : __GCONV_INCOMPLETE_INPUT);

      outptr = *outbufstart;
      res = DL_CALL_FCT (fct, (step, step_data, &toinptr, (const unsigned char *) (default_missing + len), &outptr, NULL, 0, 0));



      if (res != __GCONV_ILLEGAL_INPUT)
	{
	  
	  if (res == __GCONV_EMPTY_INPUT)
	    {
	      
	      ++*irreversible;
	      *inbufp += 4;
	      res = __GCONV_OK;
	    }
	  *outbufstart = outptr;

	  return res;
	}
    }

  
  return __GCONV_ILLEGAL_INPUT;
}



struct known_trans {
  
  struct trans_struct info;

  char *fname;
  void *handle;
  int open_count;
};



static void *search_tree;


__libc_lock_define_initialized (static, lock);



static int trans_compare (const void *p1, const void *p2)
{
  const struct known_trans *s1 = (const struct known_trans *) p1;
  const struct known_trans *s2 = (const struct known_trans *) p2;

  return strcmp (s1->info.name, s2->info.name);
}



static int open_translit (struct known_trans *trans)
{
  __gconv_trans_query_fct queryfct;

  trans->handle = __libc_dlopen (trans->fname);
  if (trans->handle == NULL)
    
    return 1;

  
  queryfct = __libc_dlsym (trans->handle, "gconv_trans_context");
  if (queryfct == NULL)
    {
      
    close_and_out:
      __libc_dlclose (trans->handle);
      trans->handle = NULL;
      return 1;
    }

  
  if (queryfct (trans->info.name, &trans->info.csnames, &trans->info.ncsnames)
      != 0)
    goto close_and_out;

  
  trans->info.trans_fct = __libc_dlsym (trans->handle, "gconv_trans");
  if (trans->info.trans_fct == NULL)
    goto close_and_out;

  
  trans->info.trans_init_fct = __libc_dlsym (trans->handle, "gconv_trans_init");
  trans->info.trans_context_fct = __libc_dlsym (trans->handle, "gconv_trans_context");
  trans->info.trans_end_fct = __libc_dlsym (trans->handle, "gconv_trans_end");

  trans->open_count = 1;

  return 0;
}


int internal_function __gconv_translit_find (struct trans_struct *trans)

{
  struct known_trans **found;
  const struct path_elem *runp;
  int res = 1;

  
  assert (trans->name != NULL);

  
  __libc_lock_lock (lock);

  
  found = __tfind (trans, &search_tree, trans_compare);
  if (found != NULL)
    {
      
      if ((*found)->handle != NULL)
	{
	  
	  if ((*found)->handle != (void *) -1)
	    
	    res = 0;
	  else if (open_translit (*found) == 0)
	    {
	      
	      *trans = (*found)->info;
	      (*found)->open_count++;
	      res = 0;
	    }
	}
    }
  else {
      size_t name_len = strlen (trans->name) + 1;
      int need_so = 0;
      struct known_trans *newp;

      
      if (__gconv_path_elem == NULL)
	__gconv_get_path ();

      
      if (name_len <= 4 || memcmp (&trans->name[name_len - 4], ".so", 3) != 0)
	need_so = 1;

      
      newp = (struct known_trans *) malloc (sizeof (struct known_trans)
					    + (__gconv_max_path_elem_len + name_len + 3)
					    + name_len);
      if (newp != NULL)
	{
	  char *cp;

	  
	  memset (newp, '\0', sizeof (struct known_trans));

	  
	  newp->info.name = cp = (char *) (newp + 1);
	  cp = __mempcpy (cp, trans->name, name_len);

	  newp->fname = cp;

	  
	  for (runp = __gconv_path_elem; runp->name != NULL; ++runp)
	    {
	      cp = __mempcpy (__stpcpy ((char *) newp->fname, runp->name), trans->name, name_len);
	      if (need_so)
		memcpy (cp, ".so", sizeof (".so"));

	      if (open_translit (newp) == 0)
		{
		  
		  res = 0;
		  break;
		}
	    }

	  if (res)
	    newp->fname = NULL;

	  
	  if (__tsearch (newp, &search_tree, trans_compare) == NULL)
	    {
	      
	      res = 1;
	      
	    }
	}
    }

  __libc_lock_unlock (lock);

  return res;
}
