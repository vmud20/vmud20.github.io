



























typedef struct {
  int len;			
  int val;			
  size_t idxnow;		
  size_t idxmax;		
  size_t idxcnt;		
  size_t backw;			
  size_t backw_stop;		
  const USTRING_TYPE *us;	
  int32_t *idxarr;		
  unsigned char *rulearr;	
} coll_seq;


static void get_next_seq_cached (coll_seq *seq, int nrules, int pass, const unsigned char *rulesets, const USTRING_TYPE *weights)


{
  int val = seq->val = 0;
  int len = seq->len;
  size_t backw_stop = seq->backw_stop;
  size_t backw = seq->backw;
  size_t idxcnt = seq->idxcnt;
  size_t idxmax = seq->idxmax;
  size_t idxnow = seq->idxnow;
  unsigned char *rulearr = seq->rulearr;
  int32_t *idxarr = seq->idxarr;

  while (len == 0)
    {
      ++val;
      if (backw_stop != ~0ul)
	{
	  
	  if (backw == backw_stop)
	    {
	      
	      if (idxcnt < idxmax)
		{
		  idxnow = idxcnt;
		  backw_stop = ~0ul;
		}
	      else {
		  
		  idxnow = ~0ul;
		  break;
		}
	    }
	  else idxnow = --backw;
	}
      else {
	  backw_stop = idxcnt;

	  while (idxcnt < idxmax)
	    {
	      if ((rulesets[rulearr[idxcnt] * nrules + pass] & sort_backward) == 0)
		
		break;
	      ++idxcnt;
	    }

	  if (backw_stop == idxcnt)
	    {
	      
	      if (idxcnt == idxmax)
		
		break;

	      backw_stop = ~0ul;
	      idxnow = idxcnt++;
	    }
	  else  idxnow = backw = idxcnt - 1;

	}
      len = weights[idxarr[idxnow]++];
    }

  
  seq->val = val;
  seq->len = len;
  seq->backw_stop = backw_stop;
  seq->backw = backw;
  seq->idxcnt = idxcnt;
  seq->idxnow = idxnow;
}


static void get_next_seq (coll_seq *seq, int nrules, const unsigned char *rulesets, const USTRING_TYPE *weights, const int32_t *table, const USTRING_TYPE *extra, const int32_t *indirect)


{

  int val = seq->val = 0;
  int len = seq->len;
  size_t backw_stop = seq->backw_stop;
  size_t backw = seq->backw;
  size_t idxcnt = seq->idxcnt;
  size_t idxmax = seq->idxmax;
  size_t idxnow = seq->idxnow;
  unsigned char *rulearr = seq->rulearr;
  int32_t *idxarr = seq->idxarr;
  const USTRING_TYPE *us = seq->us;

  while (len == 0)
    {
      ++val;
      if (backw_stop != ~0ul)
	{
	  
	  if (backw == backw_stop)
	    {
	      
	      if (idxcnt < idxmax)
		{
		  idxnow = idxcnt;
		  backw_stop = ~0ul;
		}
	      else  break;

	    }
	  else idxnow = --backw;
	}
      else {
	  backw_stop = idxmax;

	  while (*us != L('\0'))
	    {
	      int32_t tmp = findidx (&us, -1);
	      rulearr[idxmax] = tmp >> 24;
	      idxarr[idxmax] = tmp & 0xffffff;
	      idxcnt = idxmax++;

	      if ((rulesets[rulearr[idxcnt] * nrules] & sort_backward) == 0)
		
		break;
	      ++idxcnt;
	    }

	  if (backw_stop >= idxcnt)
	    {
	      
	      if (idxcnt == idxmax || backw_stop > idxcnt)
		
		break;

	      backw_stop = ~0ul;
	      idxnow = idxcnt;
	    }
	  else  idxnow = backw = idxcnt - 1;

	}
      len = weights[idxarr[idxnow]++];
    }

  
  seq->val = val;
  seq->len = len;
  seq->backw_stop = backw_stop;
  seq->backw = backw;
  seq->idxcnt = idxcnt;
  seq->idxmax = idxmax;
  seq->idxnow = idxnow;
  seq->us = us;
}


static int do_compare (coll_seq *seq1, coll_seq *seq2, int position, const USTRING_TYPE *weights)

{
  int seq1len = seq1->len;
  int seq2len = seq2->len;
  int val1 = seq1->val;
  int val2 = seq2->val;
  int32_t *idx1arr = seq1->idxarr;
  int32_t *idx2arr = seq2->idxarr;
  int idx1now = seq1->idxnow;
  int idx2now = seq2->idxnow;
  int result = 0;

  
  if (position && val1 != val2)
    {
      result = val1 - val2;
      goto out;
    }

  
  do {
      if (weights[idx1arr[idx1now]] != weights[idx2arr[idx2now]])
	{
	  
	  result = weights[idx1arr[idx1now]] - weights[idx2arr[idx2now]];
	  goto out;
	}

      
      ++idx1arr[idx1now];
      ++idx2arr[idx2now];

      --seq1len;
      --seq2len;
    }
  while (seq1len > 0 && seq2len > 0);

  if (position && seq1len != seq2len)
    result = seq1len - seq2len;

out:
  seq1->len = seq1len;
  seq2->len = seq2len;
  return result;
}

int STRCOLL (const STRING_TYPE *s1, const STRING_TYPE *s2, __locale_t l)
{
  struct __locale_data *current = l->__locales[LC_COLLATE];
  uint_fast32_t nrules = current->values[_NL_ITEM_INDEX (_NL_COLLATE_NRULES)].word;
  
  const unsigned char *rulesets;
  const int32_t *table;
  const USTRING_TYPE *weights;
  const USTRING_TYPE *extra;
  const int32_t *indirect;

  if (nrules == 0)
    return STRCMP (s1, s2);

  rulesets = (const unsigned char *)
    current->values[_NL_ITEM_INDEX (_NL_COLLATE_RULESETS)].string;
  table = (const int32_t *)
    current->values[_NL_ITEM_INDEX (CONCAT(_NL_COLLATE_TABLE,SUFFIX))].string;
  weights = (const USTRING_TYPE *)
    current->values[_NL_ITEM_INDEX (CONCAT(_NL_COLLATE_WEIGHT,SUFFIX))].string;
  extra = (const USTRING_TYPE *)
    current->values[_NL_ITEM_INDEX (CONCAT(_NL_COLLATE_EXTRA,SUFFIX))].string;
  indirect = (const int32_t *)
    current->values[_NL_ITEM_INDEX (CONCAT(_NL_COLLATE_INDIRECT,SUFFIX))].string;

  assert (((uintptr_t) table) % __alignof__ (table[0]) == 0);
  assert (((uintptr_t) weights) % __alignof__ (weights[0]) == 0);
  assert (((uintptr_t) extra) % __alignof__ (extra[0]) == 0);
  assert (((uintptr_t) indirect) % __alignof__ (indirect[0]) == 0);

  
  size_t s1len = STRLEN (s1);
  size_t s2len = STRLEN (s2);

  
  if (__glibc_unlikely (s1len == 0) || __glibc_unlikely (s2len == 0))
    return (s1len != 0) - (s2len != 0);

  

  coll_seq seq1, seq2;
  bool use_malloc = false;
  int result = 0;

  memset (&seq1, 0, sizeof (seq1));
  seq2 = seq1;

  
  seq1.us = (const USTRING_TYPE *) s1;
  seq2.us = (const USTRING_TYPE *) s2;

  if (! __libc_use_alloca ((s1len + s2len) * (sizeof (int32_t) + 1)))
    {
      seq1.idxarr = (int32_t *) malloc ((s1len + s2len) * (sizeof (int32_t) + 1));
      seq2.idxarr = &seq1.idxarr[s1len];
      seq1.rulearr = (unsigned char *) &seq2.idxarr[s2len];
      seq2.rulearr = &seq1.rulearr[s1len];

      if (seq1.idxarr == NULL)
	
	goto try_stack;
      use_malloc = true;
    }
  else {
    try_stack:
      seq1.idxarr = (int32_t *) alloca (s1len * sizeof (int32_t));
      seq2.idxarr = (int32_t *) alloca (s2len * sizeof (int32_t));
      seq1.rulearr = (unsigned char *) alloca (s1len);
      seq2.rulearr = (unsigned char *) alloca (s2len);
    }

  seq1.rulearr[0] = 0;

  
  for (int pass = 0; pass < nrules; ++pass)
    {
      seq1.idxcnt = 0;
      seq1.backw_stop = ~0ul;
      seq1.backw = ~0ul;
      seq2.idxcnt = 0;
      seq2.backw_stop = ~0ul;
      seq2.backw = ~0ul;

      
      int position = rulesets[seq1.rulearr[0] * nrules + pass] & sort_position;

      while (1)
	{
	  if (pass == 0)
	    {
	      get_next_seq (&seq1, nrules, rulesets, weights, table, extra, indirect);
	      get_next_seq (&seq2, nrules, rulesets, weights, table, extra, indirect);
	    }
	  else {
	      get_next_seq_cached (&seq1, nrules, pass, rulesets, weights);
	      get_next_seq_cached (&seq2, nrules, pass, rulesets, weights);
	    }

	  
	  if (seq1.len == 0 || seq2.len == 0)
	    {
	      if (seq1.len == seq2.len)
		
		break;

	      
	      result = seq1.len == 0 ? -1 : 1;
	      goto free_and_return;
	    }

	  result = do_compare (&seq1, &seq2, position, weights);
	  if (result != 0)
	    goto free_and_return;
	}
    }

  
 free_and_return:
  if (use_malloc)
    free (seq1.idxarr);

  return result;
}
libc_hidden_def (STRCOLL)


weak_alias (__strcoll_l, strcoll_l)

