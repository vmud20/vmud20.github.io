





























































































































































struct ptrs_to_free {
  size_t count;
  struct ptrs_to_free *next;
  char **ptrs[32];
};



int _IO_vfwscanf (_IO_FILE *s, const wchar_t *format, _IO_va_list argptr, int *errp)


int _IO_vfscanf_internal (_IO_FILE *s, const char *format, _IO_va_list argptr, int *errp)


{
  va_list arg;
  const CHAR_T *f = format;
  UCHAR_T fc;	
  WINT_T done = 0;	
  size_t read_in = 0;	
  WINT_T c = 0;	
  int width;		
  int flags;		
  int errval = 0;

  __locale_t loc = _NL_CURRENT_LOCALE;
  struct __locale_data *const curctype = loc->__locales[LC_CTYPE];


  
  int inchar_errno = 0;
  
  char got_digit, got_dot, got_e, negative;
  
  CHAR_T not_in;

  
  int base;
  

  wint_t decimal;

  const char *decimal;

  

  wint_t thousands;

  const char *thousands;

  struct ptrs_to_free *ptrs_to_free = NULL;
  
  mbstate_t state;
  
  union {
      long long int q;
      unsigned long long int uq;
      long int l;
      unsigned long int ul;
    } num;
  
  char *str = NULL;
  wchar_t *wstr = NULL;
  char **strptr = NULL;
  ssize_t strsize = 0;
  
  int skip_space = 0;
  
  CHAR_T *tw;			
  CHAR_T *wp = NULL;		
  size_t wpmax = 0;		
  size_t wpsize;		
  bool use_malloc = false;





































  __va_copy (arg, argptr);

  arg = (va_list) argptr;



  ORIENT;


  ARGCHECK (s, format);

 {

   struct __locale_data *const curnumeric = loc->__locales[LC_NUMERIC];


   

   decimal = _NL_CURRENT_WORD (LC_NUMERIC, _NL_NUMERIC_DECIMAL_POINT_WC);

   decimal = curnumeric->values[_NL_ITEM_INDEX (DECIMAL_POINT)].string;

   

   thousands = _NL_CURRENT_WORD (LC_NUMERIC, _NL_NUMERIC_THOUSANDS_SEP_WC);

   thousands = curnumeric->values[_NL_ITEM_INDEX (THOUSANDS_SEP)].string;
   if (*thousands == '\0')
     thousands = NULL;

 }

  
  LOCK_STREAM (s);



  
  memset (&state, '\0', sizeof (state));


  
  while (*f != '\0')
    {
      unsigned int argpos;
      










      

















      if (!isascii ((unsigned char) *f))
	{
	  
	  int len = __mbrlen (f, strlen (f), &state);
	  if (len > 0)
	    {
	      do {
		  c = inchar ();
		  if (__glibc_unlikely (c == EOF))
		    input_error ();
		  else if (c != (unsigned char) *f++)
		    {
		      ungetc_not_eof (c, s);
		      conv_error ();
		    }
		}
	      while (--len > 0);
	      continue;
	    }
	}


      fc = *f++;
      if (fc != '%')
	{
	  
	  if (ISSPACE (fc))
	    {
	      skip_space = 1;
	      continue;
	    }

	  
	  c = inchar ();

	  
	  if (__glibc_unlikely (c == EOF))
	    input_error ();

	  
	  if (skip_space)
	    {
	      while (ISSPACE (c))
		if (__glibc_unlikely (inchar () == EOF))
		  input_error ();
	      skip_space = 0;
	    }

	  if (__glibc_unlikely (c != fc))
	    {
	      ungetc (c, s);
	      conv_error ();
	    }

	  continue;
	}

      
      flags = 0;

      
      argpos = 0;

      
      wpsize = 0;

      
      if (ISDIGIT ((UCHAR_T) *f))
	{
	  argpos = (UCHAR_T) *f++ - L_('0');
	  while (ISDIGIT ((UCHAR_T) *f))
	    argpos = argpos * 10 + ((UCHAR_T) *f++ - L_('0'));
	  if (*f == L_('$'))
	    ++f;
	  else {
	      
	      width = argpos;
	      argpos = 0;
	      goto got_width;
	    }
	}

      
      while (*f == L_('*') || *f == L_('\'') || *f == L_('I'))
	switch (*f++)
	  {
	  case L_('*'):
	    flags |= SUPPRESS;
	    break;
	  case L_('\''):

	    if (thousands != L'\0')

	    if (thousands != NULL)

	      flags |= GROUP;
	    break;
	  case L_('I'):
	    flags |= I18N;
	    break;
	  }

      
      width = 0;
      while (ISDIGIT ((UCHAR_T) *f))
	{
	  width *= 10;
	  width += (UCHAR_T) *f++ - L_('0');
	}
    got_width:
      if (width == 0)
	width = -1;

      
      switch (*f++)
	{
	case L_('h'):
	  
	  if (*f == L_('h'))
	    {
	      ++f;
	      flags |= CHAR;
	    }
	  else flags |= SHORT;
	  break;
	case L_('l'):
	  if (*f == L_('l'))
	    {
	      
	      ++f;
	      flags |= LONGDBL | LONG;
	    }
	  else  flags |= LONG;

	  break;
	case L_('q'):
	case L_('L'):
	  
	  flags |= LONGDBL | LONG;
	  break;
	case L_('a'):
	  
	  if (*f != L_('s') && *f != L_('S') && *f != L_('['))
	    {
	      --f;
	      break;
	    }
	  
	  if (s->_flags2 & _IO_FLAGS2_SCANF_STD)
	    {
	      --f;
	      break;
	    }
	  
	  flags |= GNU_MALLOC;
	  break;
	case L_('m'):
	  flags |= POSIX_MALLOC;
	  if (*f == L_('l'))
	    {
	      ++f;
	      flags |= LONG;
	    }
	  break;
	case L_('z'):
	  if (need_longlong && sizeof (size_t) > sizeof (unsigned long int))
	    flags |= LONGDBL;
	  else if (sizeof (size_t) > sizeof (unsigned int))
	    flags |= LONG;
	  break;
	case L_('j'):
	  if (need_longlong && sizeof (uintmax_t) > sizeof (unsigned long int))
	    flags |= LONGDBL;
	  else if (sizeof (uintmax_t) > sizeof (unsigned int))
	    flags |= LONG;
	  break;
	case L_('t'):
	  if (need_longlong && sizeof (ptrdiff_t) > sizeof (long int))
	    flags |= LONGDBL;
	  else if (sizeof (ptrdiff_t) > sizeof (int))
	    flags |= LONG;
	  break;
	default:
	  
	  --f;
	  break;
	}

      
      if (__glibc_unlikely (*f == L_('\0')))
	conv_error ();

      
      fc = *f++;
      if (skip_space || (fc != L_('[') && fc != L_('c')
			 && fc != L_('C') && fc != L_('n')))
	{
	  
	  int save_errno = errno;
	  __set_errno (0);
	  do  if (__builtin_expect ((c == EOF || inchar () == EOF)

				  && errno == EINTR, 0))
	      input_error ();
	  while (ISSPACE (c));
	  __set_errno (save_errno);
	  ungetc (c, s);
	  skip_space = 0;
	}

      switch (fc)
	{
	case L_('%'):	
	  c = inchar ();
	  if (__glibc_unlikely (c == EOF))
	    input_error ();
	  if (__glibc_unlikely (c != fc))
	    {
	      ungetc_not_eof (c, s);
	      conv_error ();
	    }
	  break;

	case L_('n'):	
	  
	  if (!(flags & SUPPRESS))
	    {
	      
	      if (need_longlong && (flags & LONGDBL))
		*ARG (long long int *) = read_in;
	      else if (need_long && (flags & LONG))
		*ARG (long int *) = read_in;
	      else if (flags & SHORT)
		*ARG (short int *) = read_in;
	      else if (!(flags & CHAR))
		*ARG (int *) = read_in;
	      else *ARG (char *) = read_in;


	      
	      ++done;

	    }
	  break;

	case L_('c'):	
	  if ((flags & LONG) == 0)
	    {
	      if (width == -1)
		width = 1;




























	      STRING_ARG (str, char, 100);

	      STRING_ARG (str, char, (width > 1024 ? 1024 : width));


	      c = inchar ();
	      if (__glibc_unlikely (c == EOF))
		input_error ();


	      
	      memset (&state, '\0', sizeof (state));

	      do {
		  size_t n;

		  if (!(flags & SUPPRESS) && (flags & POSIX_MALLOC)
		      && str + MB_CUR_MAX >= *strptr + strsize)
		    {
		      
		      size_t strleng = str - *strptr;
		      char *newstr;

		      newstr = (char *) realloc (*strptr, strsize * 2);
		      if (newstr == NULL)
			{
			  
			  newstr = (char *) realloc (*strptr, strleng + MB_CUR_MAX);
			  if (newstr == NULL)
			    {
			      
			      done = EOF;
			      goto errout;
			    }
			  else {
			      *strptr = newstr;
			      str = newstr + strleng;
			      strsize = strleng + MB_CUR_MAX;
			    }
			}
		      else {
			  *strptr = newstr;
			  str = newstr + strleng;
			  strsize *= 2;
			}
		    }

		  n = __wcrtomb (!(flags & SUPPRESS) ? str : NULL, c, &state);
		  if (__glibc_unlikely (n == (size_t) -1))
		    
		    input_error ();

		  
		  str += n;
		}
	      while (--width > 0 && inchar () != EOF);

	      if (!(flags & SUPPRESS))
		{
		  do {
		      if ((flags & MALLOC)
			  && (char *) str == *strptr + strsize)
			{
			  
			  size_t newsize = strsize + (strsize >= width ? width - 1 : strsize);


			  str = (char *) realloc (*strptr, newsize);
			  if (str == NULL)
			    {
			      
			      str = (char *) realloc (*strptr, strsize + 1);
			      if (str == NULL)
				{
				  
				  done = EOF;
				  goto errout;
				}
			      else {
				  *strptr = (char *) str;
				  str += strsize;
				  ++strsize;
				}
			    }
			  else {
			      *strptr = (char *) str;
			      str += strsize;
			      strsize = newsize;
			    }
			}
		      *str++ = c;
		    }
		  while (--width > 0 && inchar () != EOF);
		}
	      else while (--width > 0 && inchar () != EOF);


	      if (!(flags & SUPPRESS))
		{
		  if ((flags & MALLOC) && str - *strptr != strsize)
		    {
		      char *cp = (char *) realloc (*strptr, str - *strptr);
		      if (cp != NULL)
			*strptr = cp;
		    }
		  strptr = NULL;
		  ++done;
		}

	      break;
	    }
	  
	case L_('C'):
	  if (width == -1)
	    width = 1;

	  STRING_ARG (wstr, wchar_t, (width > 1024 ? 1024 : width));

	  c = inchar ();
	  if (__glibc_unlikely (c == EOF))
	    input_error ();


	  
	  if (!(flags & SUPPRESS))
	    {
	      do {
		  if ((flags & MALLOC)
		      && wstr == (wchar_t *) *strptr + strsize)
		    {
		      size_t newsize = strsize + (strsize > width ? width - 1 : strsize);
		      
		      wstr = (wchar_t *) realloc (*strptr, newsize * sizeof (wchar_t));
		      if (wstr == NULL)
			{
			  
			  wstr = (wchar_t *) realloc (*strptr, (strsize + 1)
						      * sizeof (wchar_t));
			  if (wstr == NULL)
			    {
			      
			      done = EOF;
			      goto errout;
			    }
			  else {
			      *strptr = (char *) wstr;
			      wstr += strsize;
			      ++strsize;
			    }
			}
		      else {
			  *strptr = (char *) wstr;
			  wstr += strsize;
			  strsize = newsize;
			}
		    }
		  *wstr++ = c;
		}
	      while (--width > 0 && inchar () != EOF);
	    }
	  else while (--width > 0 && inchar () != EOF);

	  {
	    
	    char buf[1];
	    mbstate_t cstate;

	    memset (&cstate, '\0', sizeof (cstate));

	    do {
		
		buf[0] = c;

		if (!(flags & SUPPRESS) && (flags & MALLOC)
		    && wstr == (wchar_t *) *strptr + strsize)
		  {
		    size_t newsize = strsize + (strsize > width ? width - 1 : strsize);
		    
		    wstr = (wchar_t *) realloc (*strptr, newsize * sizeof (wchar_t));
		    if (wstr == NULL)
		      {
			
			wstr = (wchar_t *) realloc (*strptr, ((strsize + 1)
						     * sizeof (wchar_t)));
			if (wstr == NULL)
			  {
			    
			    done = EOF;
			    goto errout;
			  }
			else {
			    *strptr = (char *) wstr;
			    wstr += strsize;
			    ++strsize;
			  }
		      }
		    else {
			*strptr = (char *) wstr;
			wstr += strsize;
			strsize = newsize;
		      }
		  }

		while (1)
		  {
		    size_t n;

		    n = __mbrtowc (!(flags & SUPPRESS) ? wstr : NULL, buf, 1, &cstate);

		    if (n == (size_t) -2)
		      {
			
			if (__glibc_unlikely (inchar () == EOF))
			  encode_error ();

			buf[0] = c;
			continue;
		      }

		    if (__glibc_unlikely (n != 1))
		      encode_error ();

		    
		    break;
		  }

		
		++wstr;
	      }
	    while (--width > 0 && inchar () != EOF);
	  }


	  if (!(flags & SUPPRESS))
	    {
	      if ((flags & MALLOC) && wstr - (wchar_t *) *strptr != strsize)
		{
		  wchar_t *cp = (wchar_t *) realloc (*strptr, ((wstr - (wchar_t *) *strptr)

						      * sizeof (wchar_t)));
		  if (cp != NULL)
		    *strptr = (char *) cp;
		}
	      strptr = NULL;

	      ++done;
	    }

	  break;

	case L_('s'):		
	  if (!(flags & LONG))
	    {
	      STRING_ARG (str, char, 100);

	      c = inchar ();
	      if (__glibc_unlikely (c == EOF))
		input_error ();


	      memset (&state, '\0', sizeof (state));


	      do {
		  if (ISSPACE (c))
		    {
		      ungetc_not_eof (c, s);
		      break;
		    }


		  
		  {
		    size_t n;

		    if (!(flags & SUPPRESS) && (flags & MALLOC)
			&& str + MB_CUR_MAX >= *strptr + strsize)
		      {
			
			size_t strleng = str - *strptr;
			char *newstr;

			newstr = (char *) realloc (*strptr, strsize * 2);
			if (newstr == NULL)
			  {
			    
			    newstr = (char *) realloc (*strptr, strleng + MB_CUR_MAX);
			    if (newstr == NULL)
			      {
				if (flags & POSIX_MALLOC)
				  {
				    done = EOF;
				    goto errout;
				  }
				
				((char *) (*strptr))[strleng] = '\0';
				strptr = NULL;
				++done;
				conv_error ();
			      }
			    else {
				*strptr = newstr;
				str = newstr + strleng;
				strsize = strleng + MB_CUR_MAX;
			      }
			  }
			else {
			    *strptr = newstr;
			    str = newstr + strleng;
			    strsize *= 2;
			  }
		      }

		    n = __wcrtomb (!(flags & SUPPRESS) ? str : NULL, c, &state);
		    if (__glibc_unlikely (n == (size_t) -1))
		      encode_error ();

		    assert (n <= MB_CUR_MAX);
		    str += n;
		  }

		  
		  if (!(flags & SUPPRESS))
		    {
		      *str++ = c;
		      if ((flags & MALLOC)
			  && (char *) str == *strptr + strsize)
			{
			  
			  str = (char *) realloc (*strptr, 2 * strsize);
			  if (str == NULL)
			    {
			      
			      str = (char *) realloc (*strptr, strsize + 1);
			      if (str == NULL)
				{
				  if (flags & POSIX_MALLOC)
				    {
				      done = EOF;
				      goto errout;
				    }
				  
				  ((char *) (*strptr))[strsize - 1] = '\0';
				  strptr = NULL;
				  ++done;
				  conv_error ();
				}
			      else {
				  *strptr = (char *) str;
				  str += strsize;
				  ++strsize;
				}
			    }
			  else {
			      *strptr = (char *) str;
			      str += strsize;
			      strsize *= 2;
			    }
			}
		    }

		}
	      while ((width <= 0 || --width > 0) && inchar () != EOF);

	      if (!(flags & SUPPRESS))
		{

		  
		  char buf[MB_LEN_MAX];
		  size_t n = __wcrtomb (buf, L'\0', &state);
		  if (n > 0 && (flags & MALLOC)
		      && str + n >= *strptr + strsize)
		    {
		      
		      size_t strleng = str - *strptr;
		      char *newstr;

		      newstr = (char *) realloc (*strptr, strleng + n + 1);
		      if (newstr == NULL)
			{
			  if (flags & POSIX_MALLOC)
			    {
			      done = EOF;
			      goto errout;
			    }
			  
			  ((char *) (*strptr))[strleng] = '\0';
			  strptr = NULL;
			  ++done;
			  conv_error ();
			}
		      else {
			  *strptr = newstr;
			  str = newstr + strleng;
			  strsize = strleng + n + 1;
			}
		    }

		  str = __mempcpy (str, buf, n);

		  *str++ = '\0';

		  if ((flags & MALLOC) && str - *strptr != strsize)
		    {
		      char *cp = (char *) realloc (*strptr, str - *strptr);
		      if (cp != NULL)
			*strptr = cp;
		    }
		  strptr = NULL;

		  ++done;
		}
	      break;
	    }
	  

	case L_('S'):
	  {

	    mbstate_t cstate;


	    
	    STRING_ARG (wstr, wchar_t, 100);

	    c = inchar ();
	    if (__builtin_expect (c == EOF,  0))
	      input_error ();


	    memset (&cstate, '\0', sizeof (cstate));


	    do {
		if (ISSPACE (c))
		  {
		    ungetc_not_eof (c, s);
		    break;
		  }


		
		if (!(flags & SUPPRESS))
		  {
		    *wstr++ = c;
		    if ((flags & MALLOC)
			&& wstr == (wchar_t *) *strptr + strsize)
		      {
			
			wstr = (wchar_t *) realloc (*strptr, (2 * strsize)
						    * sizeof (wchar_t));
			if (wstr == NULL)
			  {
			    
			    wstr = (wchar_t *) realloc (*strptr, (strsize + 1)
							* sizeof (wchar_t));
			    if (wstr == NULL)
			      {
				if (flags & POSIX_MALLOC)
				  {
				    done = EOF;
				    goto errout;
				  }
				
				((wchar_t *) (*strptr))[strsize - 1] = L'\0';
				strptr = NULL;
				++done;
				conv_error ();
			      }
			    else {
				*strptr = (char *) wstr;
				wstr += strsize;
				++strsize;
			      }
			  }
			else {
			    *strptr = (char *) wstr;
			    wstr += strsize;
			    strsize *= 2;
			  }
		      }
		  }

		{
		  char buf[1];

		  buf[0] = c;

		  while (1)
		    {
		      size_t n;

		      n = __mbrtowc (!(flags & SUPPRESS) ? wstr : NULL, buf, 1, &cstate);

		      if (n == (size_t) -2)
			{
			  
			  if (__glibc_unlikely (inchar () == EOF))
			    encode_error ();

			  buf[0] = c;
			  continue;
			}

		      if (__glibc_unlikely (n != 1))
			encode_error ();

		      
		      ++wstr;
		      break;
		    }

		  if (!(flags & SUPPRESS) && (flags & MALLOC)
		      && wstr == (wchar_t *) *strptr + strsize)
		    {
		      
		      wstr = (wchar_t *) realloc (*strptr, (2 * strsize * sizeof (wchar_t)));

		      if (wstr == NULL)
			{
			  
			  wstr = (wchar_t *) realloc (*strptr, ((strsize + 1)
						       * sizeof (wchar_t)));
			  if (wstr == NULL)
			    {
			      if (flags & POSIX_MALLOC)
				{
				  done = EOF;
				  goto errout;
				}
			      
			      ((wchar_t *) (*strptr))[strsize - 1] = L'\0';
			      strptr = NULL;
			      ++done;
			      conv_error ();
			    }
			  else {
			      *strptr = (char *) wstr;
			      wstr += strsize;
			      ++strsize;
			    }
			}
		      else {
			  *strptr = (char *) wstr;
			  wstr += strsize;
			  strsize *= 2;
			}
		    }
		}

	      }
	    while ((width <= 0 || --width > 0) && inchar () != EOF);

	    if (!(flags & SUPPRESS))
	      {
		*wstr++ = L'\0';

		if ((flags & MALLOC) && wstr - (wchar_t *) *strptr != strsize)
		  {
		    wchar_t *cp = (wchar_t *) realloc (*strptr, ((wstr - (wchar_t *) *strptr)

							* sizeof(wchar_t)));
		    if (cp != NULL)
		      *strptr = (char *) cp;
		  }
		strptr = NULL;

		++done;
	      }
	  }
	  break;

	case L_('x'):	
	case L_('X'):	
	  base = 16;
	  goto number;

	case L_('o'):	
	  base = 8;
	  goto number;

	case L_('u'):	
	  base = 10;
	  goto number;

	case L_('d'):	
	  base = 10;
	  flags |= NUMBER_SIGNED;
	  goto number;

	case L_('i'):	
	  base = 0;
	  flags |= NUMBER_SIGNED;

	number:
	  c = inchar ();
	  if (__glibc_unlikely (c == EOF))
	    input_error ();

	  
	  if (c == L_('-') || c == L_('+'))
	    {
	      ADDW (c);
	      if (width > 0)
		--width;
	      c = inchar ();
	    }

	  
	  if (width != 0 && c == L_('0'))
	    {
	      if (width > 0)
		--width;

	      ADDW (c);
	      c = inchar ();

	      if (width != 0 && TOLOWER (c) == L_('x'))
		{
		  if (base == 0)
		    base = 16;
		  if (base == 16)
		    {
		      if (width > 0)
			--width;
		      c = inchar ();
		    }
		}
	      else if (base == 0)
		base = 8;
	    }

	  if (base == 0)
	    base = 10;

	  if (base == 10 && __builtin_expect ((flags & I18N) != 0, 0))
	    {
	      int from_level;
	      int to_level;
	      int level;

	      const wchar_t *wcdigits[10];
	      const wchar_t *wcdigits_extended[10];

	      const char *mbdigits[10];
	      const char *mbdigits_extended[10];

	      
	      wctrans_t map = __wctrans ("to_inpunct");
	      int n;

	      from_level = 0;

	      to_level = _NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_INDIGITS_WC_LEN) - 1;

	      to_level = (uint32_t) curctype->values[_NL_ITEM_INDEX (_NL_CTYPE_INDIGITS_MB_LEN)].word - 1;


	      
	      if (__glibc_unlikely (map != NULL))
		{
		  
		  ++to_level;

		  for (n = 0; n < 10; ++n)
		    {

		      wcdigits[n] = (const wchar_t *)
			_NL_CURRENT (LC_CTYPE, _NL_CTYPE_INDIGITS0_WC + n);

		      wchar_t *wc_extended = (wchar_t *)
			alloca ((to_level + 2) * sizeof (wchar_t));
		      __wmemcpy (wc_extended, wcdigits[n], to_level);
		      wc_extended[to_level] = __towctrans (L'0' + n, map);
		      wc_extended[to_level + 1] = '\0';
		      wcdigits_extended[n] = wc_extended;

		      mbdigits[n] = curctype->values[_NL_CTYPE_INDIGITS0_MB + n].string;

		      
		      wint_t extra_wcdigit = __towctrans (L'0' + n, map);

		      
		      mbstate_t state;
		      memset (&state, '\0', sizeof (state));

		      char extra_mbdigit[MB_LEN_MAX];
		      size_t mblen = __wcrtomb (extra_mbdigit, extra_wcdigit, &state);

		      if (mblen == (size_t) -1)
			{
			  
			  map = NULL;
			  break;
			}

		      
		      const char *last_char = mbdigits[n];
		      for (level = 0; level < to_level; ++level)
			last_char = strchr (last_char, '\0') + 1;

		      size_t mbdigits_len = last_char - mbdigits[n];

		      
		      char *mb_extended;
		      mb_extended = (char *) alloca (mbdigits_len + mblen + 1);

		      
		      *(char *) __mempcpy (__mempcpy (mb_extended, mbdigits[n], mbdigits_len), extra_mbdigit, mblen) = '\0';

		      mbdigits_extended[n] = mb_extended;

		    }
		}

	      
	      while (c != EOF && width != 0)
		{
		  
		  for (n = 0; n < 10; ++n)
		    {
		      

		      if (__glibc_unlikely (map != NULL))
			wcdigits[n] = wcdigits_extended[n];
		      else wcdigits[n] = (const wchar_t *)
			  _NL_CURRENT (LC_CTYPE, _NL_CTYPE_INDIGITS0_WC + n);
		      wcdigits[n] += from_level;

		      if (c == (wint_t) *wcdigits[n])
			{
			  to_level = from_level;
			  break;
			}

		      
		      ++wcdigits[n];

		      const char *cmpp;
		      int avail = width > 0 ? width : INT_MAX;

		      if (__glibc_unlikely (map != NULL))
			mbdigits[n] = mbdigits_extended[n];
		      else mbdigits[n] = curctype->values[_NL_CTYPE_INDIGITS0_MB + n].string;


		      for (level = 0; level < from_level; level++)
			mbdigits[n] = strchr (mbdigits[n], '\0') + 1;

		      cmpp = mbdigits[n];
		      while ((unsigned char) *cmpp == c && avail >= 0)
			{
			  if (*++cmpp == '\0')
			    break;
			  else {
			      if (avail == 0 || inchar () == EOF)
				break;
			      --avail;
			    }
			}

		      if (*cmpp == '\0')
			{
			  if (width > 0)
			    width = avail;
			  to_level = from_level;
			  break;
			}

		      
		      if (cmpp > mbdigits[n])
			{
			  ungetc (c, s);
			  while (--cmpp > mbdigits[n])
			    ungetc_not_eof ((unsigned char) *cmpp, s);
			  c = (unsigned char) *cmpp;
			}

		      
		      mbdigits[n] = strchr (mbdigits[n], '\0') + 1;

		    }

		  if (n == 10)
		    {
		      
		      for (level = from_level + 1; level <= to_level; ++level)
			{
			  
			  for (n = 0; n < 10; ++n)
			    {

			      if (c == (wint_t) *wcdigits[n])
				break;

			      
			      ++wcdigits[n];

			      const char *cmpp;
			      int avail = width > 0 ? width : INT_MAX;

			      cmpp = mbdigits[n];
			      while ((unsigned char) *cmpp == c && avail >= 0)
				{
				  if (*++cmpp == '\0')
				    break;
				  else {
				      if (avail == 0 || inchar () == EOF)
					break;
				      --avail;
				    }
				}

			      if (*cmpp == '\0')
				{
				  if (width > 0)
				    width = avail;
				  break;
				}

			      
			      if (cmpp > mbdigits[n])
				{
				  ungetc (c, s);
				  while (--cmpp > mbdigits[n])
				    ungetc_not_eof ((unsigned char) *cmpp, s);
				  c = (unsigned char) *cmpp;
				}

			      
			      mbdigits[n] = strchr (mbdigits[n], '\0') + 1;

			    }

			  if (n < 10)
			    {
			      
			      from_level = level;
			      to_level = level;
			      break;
			    }
			}
		    }

		  if (n < 10)
		    c = L_('0') + n;
		  else if (flags & GROUP)
		    {
		      

		      if (c != thousands)
			  break;

		      const char *cmpp = thousands;
		      int avail = width > 0 ? width : INT_MAX;

		      while ((unsigned char) *cmpp == c && avail >= 0)
			{
			  ADDW (c);
			  if (*++cmpp == '\0')
			    break;
			  else {
			      if (avail == 0 || inchar () == EOF)
				break;
			      --avail;
			    }
			}

		      if (*cmpp != '\0')
			{
			  
			  if (cmpp > thousands)
			    {
			      wpsize -= cmpp - thousands;
			      ungetc (c, s);
			      while (--cmpp > thousands)
				ungetc_not_eof ((unsigned char) *cmpp, s);
			      c = (unsigned char) *cmpp;
			    }
			  break;
			}

		      if (width > 0)
			width = avail;

		      
			--wpsize;

		    }
		  else break;

		  ADDW (c);
		  if (width > 0)
		    --width;

		  c = inchar ();
		}
	    }
	  else  while (c != EOF && width != 0)

	      {
		if (base == 16)
		  {
		    if (!ISXDIGIT (c))
		      break;
		  }
		else if (!ISDIGIT (c) || (int) (c - L_('0')) >= base)
		  {
		    if (base == 10 && (flags & GROUP))
		      {
			

			if (c != thousands)
			  break;

			const char *cmpp = thousands;
			int avail = width > 0 ? width : INT_MAX;

			while ((unsigned char) *cmpp == c && avail >= 0)
			  {
			    ADDW (c);
			    if (*++cmpp == '\0')
			      break;
			    else {
				if (avail == 0 || inchar () == EOF)
				  break;
				--avail;
			      }
			  }

			if (*cmpp != '\0')
			  {
			    
			    if (cmpp > thousands)
			      {
				wpsize -= cmpp - thousands;
				ungetc (c, s);
				while (--cmpp > thousands)
				  ungetc_not_eof ((unsigned char) *cmpp, s);
				c = (unsigned char) *cmpp;
			      }
			    break;
			  }

			if (width > 0)
			  width = avail;

			
			--wpsize;

		      }
		    else break;
		  }
		ADDW (c);
		if (width > 0)
		  --width;

		c = inchar ();
	      }

	  if (wpsize == 0 || (wpsize == 1 && (wp[0] == L_('+') || wp[0] == L_('-'))))
	    {
	      
	      if (__builtin_expect (wpsize == 0 && (flags & READ_POINTER)
				    && (width < 0 || width >= 5)
				    && c == '(' && TOLOWER (inchar ()) == L_('n')
				    && TOLOWER (inchar ()) == L_('i')
				    && TOLOWER (inchar ()) == L_('l')
				    && inchar () == L_(')'), 1))
		
		ADDW (L_('0'));
	      else {
		  
		  ungetc (c, s);

		  conv_error ();
		}
	    }
	  else  ungetc (c, s);


	  
	  ADDW (L_('\0'));
	  if (need_longlong && (flags & LONGDBL))
	    {
	      if (flags & NUMBER_SIGNED)
		num.q = __strtoll_internal (wp, &tw, base, flags & GROUP);
	      else num.uq = __strtoull_internal (wp, &tw, base, flags & GROUP);
	    }
	  else {
	      if (flags & NUMBER_SIGNED)
		num.l = __strtol_internal (wp, &tw, base, flags & GROUP);
	      else num.ul = __strtoul_internal (wp, &tw, base, flags & GROUP);
	    }
	  if (__glibc_unlikely (wp == tw))
	    conv_error ();

	  if (!(flags & SUPPRESS))
	    {
	      if (flags & NUMBER_SIGNED)
		{
		  if (need_longlong && (flags & LONGDBL))
		    *ARG (LONGLONG int *) = num.q;
		  else if (need_long && (flags & LONG))
		    *ARG (long int *) = num.l;
		  else if (flags & SHORT)
		    *ARG (short int *) = (short int) num.l;
		  else if (!(flags & CHAR))
		    *ARG (int *) = (int) num.l;
		  else *ARG (signed char *) = (signed char) num.ul;
		}
	      else {
		  if (need_longlong && (flags & LONGDBL))
		    *ARG (unsigned LONGLONG int *) = num.uq;
		  else if (need_long && (flags & LONG))
		    *ARG (unsigned long int *) = num.ul;
		  else if (flags & SHORT)
		    *ARG (unsigned short int *)
		      = (unsigned short int) num.ul;
		  else if (!(flags & CHAR))
		    *ARG (unsigned int *) = (unsigned int) num.ul;
		  else *ARG (unsigned char *) = (unsigned char) num.ul;
		}
	      ++done;
	    }
	  break;

	case L_('e'):	
	case L_('E'):
	case L_('f'):
	case L_('F'):
	case L_('g'):
	case L_('G'):
	case L_('a'):
	case L_('A'):
	  c = inchar ();
	  if (width > 0)
	    --width;
	  if (__glibc_unlikely (c == EOF))
	    input_error ();

	  got_digit = got_dot = got_e = 0;

	  
	  if (c == L_('-') || c == L_('+'))
	    {
	      negative = c == L_('-');
	      if (__glibc_unlikely (width == 0 || inchar () == EOF))
		
		conv_error ();
	      if (width > 0)
		--width;
	    }
	  else negative = 0;

	  
	  if (TOLOWER (c) == L_('n'))
	    {
	      
	      ADDW (c);
	      if (__builtin_expect (width == 0 || inchar () == EOF || TOLOWER (c) != L_('a'), 0))

		conv_error ();
	      if (width > 0)
		--width;
	      ADDW (c);
	      if (__builtin_expect (width == 0 || inchar () == EOF || TOLOWER (c) != L_('n'), 0))

		conv_error ();
	      if (width > 0)
		--width;
	      ADDW (c);
	      
	      goto scan_float;
	    }
	  else if (TOLOWER (c) == L_('i'))
	    {
	      
	      ADDW (c);
	      if (__builtin_expect (width == 0 || inchar () == EOF || TOLOWER (c) != L_('n'), 0))

		conv_error ();
	      if (width > 0)
		--width;
	      ADDW (c);
	      if (__builtin_expect (width == 0 || inchar () == EOF || TOLOWER (c) != L_('f'), 0))

		conv_error ();
	      if (width > 0)
		--width;
	      ADDW (c);
	      
	      if (width != 0 && inchar () != EOF)
		{
		  if (TOLOWER (c) == L_('i'))
		    {
		      if (width > 0)
			--width;
		      
		      ADDW (c);
		      if (__builtin_expect (width == 0 || inchar () == EOF || TOLOWER (c) != L_('n'), 0))

			conv_error ();
		      if (width > 0)
			--width;
		      ADDW (c);
		      if (__builtin_expect (width == 0 || inchar () == EOF || TOLOWER (c) != L_('i'), 0))

			conv_error ();
		      if (width > 0)
			--width;
		      ADDW (c);
		      if (__builtin_expect (width == 0 || inchar () == EOF || TOLOWER (c) != L_('t'), 0))

			conv_error ();
		      if (width > 0)
			--width;
		      ADDW (c);
		      if (__builtin_expect (width == 0 || inchar () == EOF || TOLOWER (c) != L_('y'), 0))

			conv_error ();
		      if (width > 0)
			--width;
		      ADDW (c);
		    }
		  else  ungetc (c, s);

		}
	      goto scan_float;
	    }

	  exp_char = L_('e');
	  if (width != 0 && c == L_('0'))
	    {
	      ADDW (c);
	      c = inchar ();
	      if (width > 0)
		--width;
	      if (width != 0 && TOLOWER (c) == L_('x'))
		{
		  
		  ADDW (c);

		  flags |= HEXA_FLOAT;
		  exp_char = L_('p');

		  
		  flags &= ~GROUP;
		  c = inchar ();
		  if (width > 0)
		    --width;
		}
	      else got_digit = 1;
	    }

	  while (1)
	    {
	      if (ISDIGIT (c))
		{
		  ADDW (c);
		  got_digit = 1;
		}
	      else if (!got_e && (flags & HEXA_FLOAT) && ISXDIGIT (c))
		{
		  ADDW (c);
		  got_digit = 1;
		}
	      else if (got_e && wp[wpsize - 1] == exp_char && (c == L_('-') || c == L_('+')))
		ADDW (c);
	      else if (got_digit && !got_e && (CHAR_T) TOLOWER (c) == exp_char)
		{
		  ADDW (exp_char);
		  got_e = got_dot = 1;
		}
	      else {

		  if (! got_dot && c == decimal)
		    {
		      ADDW (c);
		      got_dot = 1;
		    }
		  else if ((flags & GROUP) != 0 && ! got_dot && c == thousands)
		    ADDW (c);
		  else {
		      
		      ungetc (c, s);
		      break;
		    }

		  const char *cmpp = decimal;
		  int avail = width > 0 ? width : INT_MAX;

		  if (! got_dot)
		    {
		      while ((unsigned char) *cmpp == c && avail >= 0)
			if (*++cmpp == '\0')
			  break;
			else {
			    if (avail == 0 || inchar () == EOF)
			      break;
			    --avail;
			  }
		    }

		  if (*cmpp == '\0')
		    {
		      
		      for (cmpp = decimal; *cmpp != '\0'; ++cmpp)
			ADDW ((unsigned char) *cmpp);
		      if (width > 0)
			width = avail;
		      got_dot = 1;
		    }
		  else {
		      
		      const char *cmp2p = thousands;

		      if ((flags & GROUP) != 0 && ! got_dot)
			{
			  while (cmp2p - thousands < cmpp - decimal && *cmp2p == decimal[cmp2p - thousands])
			    ++cmp2p;
			  if (cmp2p - thousands == cmpp - decimal)
			    {
			      while ((unsigned char) *cmp2p == c && avail >= 0)
				if (*++cmp2p == '\0')
				  break;
				else {
				    if (avail == 0 || inchar () == EOF)
				      break;
				    --avail;
				  }
			    }
			}

		      if (cmp2p != NULL && *cmp2p == '\0')
			{
			  
			  for (cmpp = thousands; *cmpp != '\0'; ++cmpp)
			    ADDW ((unsigned char) *cmpp);
			  if (width > 0)
			    width = avail;
			}
		      else {
			  
			  ungetc (c, s);
			  break;
			}
		    }

		}

	      if (width == 0 || inchar () == EOF)
		break;

	      if (width > 0)
		--width;
	    }

	  wctrans_t map;
	  if (__builtin_expect ((flags & I18N) != 0, 0)
	      
	      && !(flags & HEXA_FLOAT)
	      
	      && (wpsize == 0 || got_dot)
	      && (map = __wctrans ("to_inpunct")) != NULL)
	    {
	      
	      inchar ();

	      
	      wint_t wcdigits[12];

	      
	      wcdigits[11] = __towctrans (L'.', map);

	      

	      if (wpsize == 0 || (wpsize == 1 && wcdigits[11] == decimal))

	      char mbdigits[12][MB_LEN_MAX + 1];

	      mbstate_t state;
	      memset (&state, '\0', sizeof (state));

	      bool match_so_far = wpsize == 0;
	      size_t mblen = __wcrtomb (mbdigits[11], wcdigits[11], &state);
	      if (mblen != (size_t) -1)
		{
		  mbdigits[11][mblen] = '\0';
		  match_so_far |= (wpsize == strlen (decimal)
				   && strcmp (decimal, mbdigits[11]) == 0);
		}
	      else {
		  size_t decimal_len = strlen (decimal);
		  
		  if (decimal_len <= MB_LEN_MAX)
		    {
		      match_so_far |= wpsize == decimal_len;
		      memcpy (mbdigits[11], decimal, decimal_len + 1);
		    }
		  else match_so_far = false;
		}

	      if (match_so_far)

		{
		  bool have_locthousands = (flags & GROUP) != 0;

		  
		  for (int n = 0; n < 11; ++n)
		    {
		      if (n < 10)
			wcdigits[n] = __towctrans (L'0' + n, map);
		      else if (n == 10)
			{
			  wcdigits[10] = __towctrans (L',', map);
			  have_locthousands &= wcdigits[10] != L'\0';
			}


		      memset (&state, '\0', sizeof (state));

		      size_t mblen = __wcrtomb (mbdigits[n], wcdigits[n], &state);
		      if (mblen == (size_t) -1)
			{
			  if (n == 10)
			    {
			      if (have_locthousands)
				{
				  size_t thousands_len = strlen (thousands);
				  if (thousands_len <= MB_LEN_MAX)
				    memcpy (mbdigits[10], thousands, thousands_len + 1);
				  else have_locthousands = false;
				}
			    }
			  else  goto no_i18nflt;

			}
		      else mbdigits[n][mblen] = '\0';

		    }

		  
		  while (1)
		    {
		      if (got_e && wp[wpsize - 1] == exp_char && (c == L_('-') || c == L_('+')))
			ADDW (c);
		      else if (wpsize > 0 && !got_e && (CHAR_T) TOLOWER (c) == exp_char)
			{
			  ADDW (exp_char);
			  got_e = got_dot = 1;
			}
		      else {
			  
			  int n;
			  for (n = 0; n < 12; ++n)
			    {

			      if (c == wcdigits[n])
				{
				  if (n < 10)
				    ADDW (L_('0') + n);
				  else if (n == 11 && !got_dot)
				    {
				      ADDW (decimal);
				      got_dot = 1;
				    }
				  else if (n == 10 && have_locthousands && ! got_dot)
				    ADDW (thousands);
				  else  n = 12;


				  break;
				}

			      const char *cmpp = mbdigits[n];
			      int avail = width > 0 ? width : INT_MAX;

			      while ((unsigned char) *cmpp == c && avail >= 0)
				if (*++cmpp == '\0')
				  break;
				else {
				    if (avail == 0 || inchar () == EOF)
				      break;
				    --avail;
				  }
			      if (*cmpp == '\0')
				{
				  if (width > 0)
				    width = avail;

				  if (n < 10)
				    ADDW (L_('0') + n);
				  else if (n == 11 && !got_dot)
				    {
				      
				      for (cmpp = decimal; *cmpp != '\0';
					   ++cmpp)
					ADDW ((unsigned char) *cmpp);

				      got_dot = 1;
				    }
				  else if (n == 10 && (flags & GROUP) != 0 && ! got_dot)
				    {
				      
				      for (cmpp = thousands; *cmpp != '\0';
					   ++cmpp)
					ADDW ((unsigned char) *cmpp);
				    }
				  else  n = 12;


				  break;
				}

			      
			      if (cmpp > mbdigits[n])
				{
				  ungetc (c, s);
				  while (--cmpp > mbdigits[n])
				    ungetc_not_eof ((unsigned char) *cmpp, s);
				  c = (unsigned char) *cmpp;
				}

			    }

			  if (n >= 12)
			    {
			      
			      ungetc (c, s);
			      break;
			    }
			}

		      if (width == 0 || inchar () == EOF)
			break;

		      if (width > 0)
			--width;
		    }
		}


	    no_i18nflt:
	      ;

	    }

	  
	  if (__builtin_expect (wpsize == 0 || ((flags & HEXA_FLOAT) && wpsize == 2), 0))
	    conv_error ();

	scan_float:
	  
	  ADDW (L_('\0'));
	  if ((flags & LONGDBL) && !__ldbl_is_dbl)
	    {
	      long double d = __strtold_internal (wp, &tw, flags & GROUP);
	      if (!(flags & SUPPRESS) && tw != wp)
		*ARG (long double *) = negative ? -d : d;
	    }
	  else if (flags & (LONG | LONGDBL))
	    {
	      double d = __strtod_internal (wp, &tw, flags & GROUP);
	      if (!(flags & SUPPRESS) && tw != wp)
		*ARG (double *) = negative ? -d : d;
	    }
	  else {
	      float d = __strtof_internal (wp, &tw, flags & GROUP);
	      if (!(flags & SUPPRESS) && tw != wp)
		*ARG (float *) = negative ? -d : d;
	    }

	  if (__glibc_unlikely (tw == wp))
	    conv_error ();

	  if (!(flags & SUPPRESS))
	    ++done;
	  break;

	case L_('['):	
	  if (flags & LONG)
	    STRING_ARG (wstr, wchar_t, 100);
	  else STRING_ARG (str, char, 100);

	  if (*f == L_('^'))
	    {
	      ++f;
	      not_in = 1;
	    }
	  else not_in = 0;

	  if (width < 0)
	    
	    width = INT_MAX;


	  
	  tw = (wchar_t *) f;	

	  if (*f == L']')
	    ++f;

	  while ((fc = *f++) != L'\0' && fc != L']');

	  if (__glibc_unlikely (fc == L'\0'))
	    conv_error ();
	  wchar_t *twend = (wchar_t *) f - 1;

	  
	  if (wpmax < UCHAR_MAX + 1)
	    {
	      wpmax = UCHAR_MAX + 1;
	      wp = (char *) alloca (wpmax);
	    }
	  memset (wp, '\0', UCHAR_MAX + 1);

	  fc = *f;
	  if (fc == ']' || fc == '-')
	    {
	      
	      wp[fc] = 1;
	      ++f;
	    }

	  while ((fc = *f++) != '\0' && fc != ']')
	    if (fc == '-' && *f != '\0' && *f != ']' && (unsigned char) f[-2] <= (unsigned char) *f)
	      {
		
		for (fc = (unsigned char) f[-2]; fc < (unsigned char) *f; ++fc)
		  wp[fc] = 1;
	      }
	    else  wp[fc] = 1;


	  if (__glibc_unlikely (fc == '\0'))
	    conv_error();


	  if (flags & LONG)
	    {
	      size_t now = read_in;

	      if (__glibc_unlikely (inchar () == WEOF))
		input_error ();

	      do {
		  wchar_t *runp;

		  
		  runp = tw;
		  while (runp < twend)
		    {
		      if (runp[0] == L'-' && runp[1] != '\0' && runp + 1 != twend && runp != tw && (unsigned int) runp[-1] <= (unsigned int) runp[1])


			{
			  
			  wchar_t wc;

			  for (wc = runp[-1] + 1; wc <= runp[1]; ++wc)
			    if ((wint_t) wc == c)
			      break;

			  if (wc <= runp[1] && !not_in)
			    break;
			  if (wc <= runp[1] && not_in)
			    {
			      
			      ungetc (c, s);
			      goto out;
			    }

			  runp += 2;
			}
		      else {
			  if ((wint_t) *runp == c && !not_in)
			    break;
			  if ((wint_t) *runp == c && not_in)
			    {
			      ungetc (c, s);
			      goto out;
			    }

			  ++runp;
			}
		    }

		  if (runp == twend && !not_in)
		    {
		      ungetc (c, s);
		      goto out;
		    }

		  if (!(flags & SUPPRESS))
		    {
		      *wstr++ = c;

		      if ((flags & MALLOC)
			  && wstr == (wchar_t *) *strptr + strsize)
			{
			  
			  wstr = (wchar_t *) realloc (*strptr, (2 * strsize)
						      * sizeof (wchar_t));
			  if (wstr == NULL)
			    {
			      
			      wstr = (wchar_t *)
				realloc (*strptr, (strsize + 1)
						  * sizeof (wchar_t));
			      if (wstr == NULL)
				{
				  if (flags & POSIX_MALLOC)
				    {
				      done = EOF;
				      goto errout;
				    }
				  
				  ((wchar_t *) (*strptr))[strsize - 1] = L'\0';
				  strptr = NULL;
				  ++done;
				  conv_error ();
				}
			      else {
				  *strptr = (char *) wstr;
				  wstr += strsize;
				  ++strsize;
				}
			    }
			  else {
			      *strptr = (char *) wstr;
			      wstr += strsize;
			      strsize *= 2;
			    }
			}
		    }
		}
	      while (--width > 0 && inchar () != WEOF);
	    out:

	      char buf[MB_LEN_MAX];
	      size_t cnt = 0;
	      mbstate_t cstate;

	      if (__glibc_unlikely (inchar () == EOF))
		input_error ();

	      memset (&cstate, '\0', sizeof (cstate));

	      do {
		  if (wp[c] == not_in)
		    {
		      ungetc_not_eof (c, s);
		      break;
		    }

		  
		  if (!(flags & SUPPRESS))
		    {
		      size_t n;

		      
		      buf[0] = c;
		      n = __mbrtowc (wstr, buf, 1, &cstate);

		      if (n == (size_t) -2)
			{
			  
			  ++cnt;
			  assert (cnt < MB_CUR_MAX);
			  continue;
			}
		      cnt = 0;

		      ++wstr;
		      if ((flags & MALLOC)
			  && wstr == (wchar_t *) *strptr + strsize)
			{
			  
			  wstr = (wchar_t *) realloc (*strptr, (2 * strsize * sizeof (wchar_t)));

			  if (wstr == NULL)
			    {
			      
			      wstr = (wchar_t *)
				realloc (*strptr, ((strsize + 1)
						   * sizeof (wchar_t)));
			      if (wstr == NULL)
				{
				  if (flags & POSIX_MALLOC)
				    {
				      done = EOF;
				      goto errout;
				    }
				  
				  ((wchar_t *) (*strptr))[strsize - 1] = L'\0';
				  strptr = NULL;
				  ++done;
				  conv_error ();
				}
			      else {
				  *strptr = (char *) wstr;
				  wstr += strsize;
				  ++strsize;
				}
			    }
			  else {
			      *strptr = (char *) wstr;
			      wstr += strsize;
			      strsize *= 2;
			    }
			}
		    }

		  if (--width <= 0)
		    break;
		}
	      while (inchar () != EOF);

	      if (__glibc_unlikely (cnt != 0))
		
		encode_error ();


	      if (__glibc_unlikely (now == read_in))
		
		conv_error ();

	      if (!(flags & SUPPRESS))
		{
		  *wstr++ = L'\0';

		  if ((flags & MALLOC)
		      && wstr - (wchar_t *) *strptr != strsize)
		    {
		      wchar_t *cp = (wchar_t *)
			realloc (*strptr, ((wstr - (wchar_t *) *strptr)
					   * sizeof(wchar_t)));
		      if (cp != NULL)
			*strptr = (char *) cp;
		    }
		  strptr = NULL;

		  ++done;
		}
	    }
	  else {
	      size_t now = read_in;

	      if (__glibc_unlikely (inchar () == EOF))
		input_error ();



	      memset (&state, '\0', sizeof (state));

	      do {
		  wchar_t *runp;
		  size_t n;

		  
		  runp = tw;
		  while (runp < twend)
		    {
		      if (runp[0] == L'-' && runp[1] != '\0' && runp + 1 != twend && runp != tw && (unsigned int) runp[-1] <= (unsigned int) runp[1])


			{
			  
			  wchar_t wc;

			  for (wc = runp[-1] + 1; wc <= runp[1]; ++wc)
			    if ((wint_t) wc == c)
			      break;

			  if (wc <= runp[1] && !not_in)
			    break;
			  if (wc <= runp[1] && not_in)
			    {
			      
			      ungetc (c, s);
			      goto out2;
			    }

			  runp += 2;
			}
		      else {
			  if ((wint_t) *runp == c && !not_in)
			    break;
			  if ((wint_t) *runp == c && not_in)
			    {
			      ungetc (c, s);
			      goto out2;
			    }

			  ++runp;
			}
		    }

		  if (runp == twend && !not_in)
		    {
		      ungetc (c, s);
		      goto out2;
		    }

		  if (!(flags & SUPPRESS))
		    {
		      if ((flags & MALLOC)
			  && str + MB_CUR_MAX >= *strptr + strsize)
			{
			  
			  size_t strleng = str - *strptr;
			  char *newstr;

			  newstr = (char *) realloc (*strptr, 2 * strsize);
			  if (newstr == NULL)
			    {
			      
			      newstr = (char *) realloc (*strptr, strleng + MB_CUR_MAX);
			      if (newstr == NULL)
				{
				  if (flags & POSIX_MALLOC)
				    {
				      done = EOF;
				      goto errout;
				    }
				  
				  ((char *) (*strptr))[strleng] = '\0';
				  strptr = NULL;
				  ++done;
				  conv_error ();
				}
			      else {
				  *strptr = newstr;
				  str = newstr + strleng;
				  strsize = strleng + MB_CUR_MAX;
				}
			    }
			  else {
			      *strptr = newstr;
			      str = newstr + strleng;
			      strsize *= 2;
			    }
			}
		    }

		  n = __wcrtomb (!(flags & SUPPRESS) ? str : NULL, c, &state);
		  if (__glibc_unlikely (n == (size_t) -1))
		    encode_error ();

		  assert (n <= MB_CUR_MAX);
		  str += n;
		}
	      while (--width > 0 && inchar () != WEOF);
	    out2:

	      do {
		  if (wp[c] == not_in)
		    {
		      ungetc_not_eof (c, s);
		      break;
		    }

		  
		  if (!(flags & SUPPRESS))
		    {
		      *str++ = c;
		      if ((flags & MALLOC)
			  && (char *) str == *strptr + strsize)
			{
			  
			  size_t newsize = 2 * strsize;

			allocagain:
			  str = (char *) realloc (*strptr, newsize);
			  if (str == NULL)
			    {
			      
			      if (newsize > strsize + 1)
				{
				  newsize = strsize + 1;
				  goto allocagain;
				}
			      if (flags & POSIX_MALLOC)
				{
				  done = EOF;
				  goto errout;
				}
			      
			      ((char *) (*strptr))[strsize - 1] = '\0';
			      strptr = NULL;
			      ++done;
			      conv_error ();
			    }
			  else {
			      *strptr = (char *) str;
			      str += strsize;
			      strsize = newsize;
			    }
			}
		    }
		}
	      while (--width > 0 && inchar () != EOF);


	      if (__glibc_unlikely (now == read_in))
		
		conv_error ();

	      if (!(flags & SUPPRESS))
		{

		  
		  char buf[MB_LEN_MAX];
		  size_t n = __wcrtomb (buf, L'\0', &state);
		  if (n > 0 && (flags & MALLOC)
		      && str + n >= *strptr + strsize)
		    {
		      
		      size_t strleng = str - *strptr;
		      char *newstr;

		      newstr = (char *) realloc (*strptr, strleng + n + 1);
		      if (newstr == NULL)
			{
			  if (flags & POSIX_MALLOC)
			    {
			      done = EOF;
			      goto errout;
			    }
			  
			  ((char *) (*strptr))[strleng] = '\0';
			  strptr = NULL;
			  ++done;
			  conv_error ();
			}
		      else {
			  *strptr = newstr;
			  str = newstr + strleng;
			  strsize = strleng + n + 1;
			}
		    }

		  str = __mempcpy (str, buf, n);

		  *str++ = '\0';

		  if ((flags & MALLOC) && str - *strptr != strsize)
		    {
		      char *cp = (char *) realloc (*strptr, str - *strptr);
		      if (cp != NULL)
			*strptr = cp;
		    }
		  strptr = NULL;

		  ++done;
		}
	    }
	  break;

	case L_('p'):	
	  base = 16;
	  
	  flags &= ~(SHORT|LONGDBL);
	  if (need_long)
	    flags |= LONG;
	  flags |= READ_POINTER;
	  goto number;

	default:
	  
	  conv_error ();
	}
    }

  
  if (skip_space)
    {
      do c = inchar ();
      while (ISSPACE (c));
      ungetc (c, s);
    }

 errout:
  
  UNLOCK_STREAM (s);

  if (use_malloc)
    free (wp);

  if (errp != NULL)
    *errp |= errval;

  if (__glibc_unlikely (done == EOF))
    {
      if (__glibc_unlikely (ptrs_to_free != NULL))
	{
	  struct ptrs_to_free *p = ptrs_to_free;
	  while (p != NULL)
	    {
	      for (size_t cnt = 0; cnt < p->count; ++cnt)
		{
		  free (*p->ptrs[cnt]);
		  *p->ptrs[cnt] = NULL;
		}
	      p = p->next;
	      ptrs_to_free = p;
	    }
	}
    }
  else if (__glibc_unlikely (strptr != NULL))
    {
      free (*strptr);
      *strptr = NULL;
    }
  return done;
}


int __vfwscanf (FILE *s, const wchar_t *format, va_list argptr)
{
  return _IO_vfwscanf (s, format, argptr, NULL);
}
ldbl_weak_alias (__vfwscanf, vfwscanf)

int ___vfscanf (FILE *s, const char *format, va_list argptr)
{
  return _IO_vfscanf_internal (s, format, argptr, NULL);
}
ldbl_strong_alias (_IO_vfscanf_internal, _IO_vfscanf)
ldbl_hidden_def (_IO_vfscanf_internal, _IO_vfscanf)
ldbl_strong_alias (___vfscanf, __vfscanf)
ldbl_hidden_def (___vfscanf, __vfscanf)
ldbl_weak_alias (___vfscanf, vfscanf)

