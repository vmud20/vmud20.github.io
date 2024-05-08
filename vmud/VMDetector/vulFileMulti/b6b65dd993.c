







































extern int __libc_argc attribute_hidden;
extern char **__libc_argv attribute_hidden;


static int parse_dollars (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white, int quoted)


     internal_function;
static int parse_backtick (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white)


     internal_function;
static int parse_dquote (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white)


     internal_function;
static int eval_expr (char *expr, long int *result) internal_function;






static inline char * w_newword (size_t *actlen, size_t *maxlen)
{
  *actlen = *maxlen = 0;
  return NULL;
}

static char * w_addchar (char *buffer, size_t *actlen, size_t *maxlen, char ch)
     
{
  

  if (*actlen == *maxlen)
    {
      char *old_buffer = buffer;
      assert (buffer == NULL || *maxlen != 0);
      *maxlen += W_CHUNK;
      buffer = (char *) realloc (buffer, 1 + *maxlen);

      if (buffer == NULL)
	free (old_buffer);
    }

  if (buffer != NULL)
    {
      buffer[*actlen] = ch;
      buffer[++(*actlen)] = '\0';
    }

  return buffer;
}

static char * internal_function w_addmem (char *buffer, size_t *actlen, size_t *maxlen, const char *str, size_t len)


{
  
  if (*actlen + len > *maxlen)
    {
      char *old_buffer = buffer;
      assert (buffer == NULL || *maxlen != 0);
      *maxlen += MAX (2 * len, W_CHUNK);
      buffer = realloc (old_buffer, 1 + *maxlen);

      if (buffer == NULL)
	free (old_buffer);
    }

  if (buffer != NULL)
    {
      *((char *) __mempcpy (&buffer[*actlen], str, len)) = '\0';
      *actlen += len;
    }

  return buffer;
}

static char * internal_function w_addstr (char *buffer, size_t *actlen, size_t *maxlen, const char *str)

     
{
  
  size_t len;

  assert (str != NULL); 
  len = strlen (str);

  return w_addmem (buffer, actlen, maxlen, str, len);
}

static int internal_function w_addword (wordexp_t *pwordexp, char *word)

{
  
  size_t num_p;
  char **new_wordv;
  bool allocated = false;

  
  if (word == NULL)
    {
      word = __strdup ("");
      if (word == NULL)
	goto no_space;
      allocated = true;
    }

  num_p = 2 + pwordexp->we_wordc + pwordexp->we_offs;
  new_wordv = realloc (pwordexp->we_wordv, sizeof (char *) * num_p);
  if (new_wordv != NULL)
    {
      pwordexp->we_wordv = new_wordv;
      pwordexp->we_wordv[pwordexp->we_offs + pwordexp->we_wordc++] = word;
      pwordexp->we_wordv[pwordexp->we_offs + pwordexp->we_wordc] = NULL;
      return 0;
    }

  if (allocated)
    free (word);

no_space:
  return WRDE_NOSPACE;
}



static int internal_function parse_backslash (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset)


{
  

  switch (words[1 + *offset])
    {
    case 0:
      
      return WRDE_SYNTAX;

    case '\n':
      ++(*offset);
      break;

    default:
      *word = w_addchar (*word, word_length, max_length, words[1 + *offset]);
      if (*word == NULL)
	return WRDE_NOSPACE;

      ++(*offset);
      break;
    }

  return 0;
}

static int internal_function parse_qtd_backslash (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset)


{
  

  switch (words[1 + *offset])
    {
    case 0:
      
      return WRDE_SYNTAX;

    case '\n':
      ++(*offset);
      break;

    case '$':
    case '`':
    case '"':
    case '\\':
      *word = w_addchar (*word, word_length, max_length, words[1 + *offset]);
      if (*word == NULL)
	return WRDE_NOSPACE;

      ++(*offset);
      break;

    default:
      *word = w_addchar (*word, word_length, max_length, words[*offset]);
      if (*word != NULL)
	*word = w_addchar (*word, word_length, max_length, words[1 + *offset]);

      if (*word == NULL)
	return WRDE_NOSPACE;

      ++(*offset);
      break;
    }

  return 0;
}

static int internal_function parse_tilde (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, size_t wordc)


{
  
  size_t i;

  if (*word_length != 0)
    {
      if (!((*word)[*word_length - 1] == '=' && wordc == 0))
	{
	  if (!((*word)[*word_length - 1] == ':' && strchr (*word, '=') && wordc == 0))
	    {
	      *word = w_addchar (*word, word_length, max_length, '~');
	      return *word ? 0 : WRDE_NOSPACE;
	    }
	}
    }

  for (i = 1 + *offset; words[i]; i++)
    {
      if (words[i] == ':' || words[i] == '/' || words[i] == ' ' || words[i] == '\t' || words[i] == 0 )
	break;

      if (words[i] == '\\')
	{
	  *word = w_addchar (*word, word_length, max_length, '~');
	  return *word ? 0 : WRDE_NOSPACE;
	}
    }

  if (i == 1 + *offset)
    {
      
      uid_t uid;
      struct passwd pwd, *tpwd;
      int buflen = 1000;
      char* home;
      char* buffer;
      int result;

      

      home = getenv ("HOME");
      if (home != NULL)
	{
	  *word = w_addstr (*word, word_length, max_length, home);
	  if (*word == NULL)
	    return WRDE_NOSPACE;
	}
      else {
	  uid = __getuid ();
	  buffer = __alloca (buflen);

	  while ((result = __getpwuid_r (uid, &pwd, buffer, buflen, &tpwd)) != 0 && errno == ERANGE)
	    buffer = extend_alloca (buffer, buflen, buflen + 1000);

	  if (result == 0 && tpwd != NULL && pwd.pw_dir != NULL)
	    {
	      *word = w_addstr (*word, word_length, max_length, pwd.pw_dir);
	      if (*word == NULL)
		return WRDE_NOSPACE;
	    }
	  else {
	      *word = w_addchar (*word, word_length, max_length, '~');
	      if (*word == NULL)
		return WRDE_NOSPACE;
	    }
	}
    }
  else {
      
      char *user = strndupa (&words[1 + *offset], i - (1 + *offset));
      struct passwd pwd, *tpwd;
      int buflen = 1000;
      char* buffer = __alloca (buflen);
      int result;

      while ((result = __getpwnam_r (user, &pwd, buffer, buflen, &tpwd)) != 0 && errno == ERANGE)
	buffer = extend_alloca (buffer, buflen, buflen + 1000);

      if (result == 0 && tpwd != NULL && pwd.pw_dir)
	*word = w_addstr (*word, word_length, max_length, pwd.pw_dir);
      else {
	  
	  *word = w_addchar (*word, word_length, max_length, '~');
	  if (*word != NULL)
	    *word = w_addstr (*word, word_length, max_length, user);
	}

      *offset = i - 1;
    }
  return *word ? 0 : WRDE_NOSPACE;
}


static int internal_function do_parse_glob (const char *glob_word, char **word, size_t *word_length, size_t *max_length, wordexp_t *pwordexp, const char *ifs, const char *ifs_white)



{
  int error;
  unsigned int match;
  glob_t globbuf;

  error = glob (glob_word, GLOB_NOCHECK, NULL, &globbuf);

  if (error != 0)
    {
      
      assert (error == GLOB_NOSPACE);
      return WRDE_NOSPACE;
    }

  if (ifs && !*ifs)
    {
      
      assert (globbuf.gl_pathv[0] != NULL);
      *word = w_addstr (*word, word_length, max_length, globbuf.gl_pathv[0]);
      for (match = 1; match < globbuf.gl_pathc && *word != NULL; ++match)
	{
	  *word = w_addchar (*word, word_length, max_length, ' ');
	  if (*word != NULL)
	    *word = w_addstr (*word, word_length, max_length, globbuf.gl_pathv[match]);
	}

      globfree (&globbuf);
      return *word ? 0 : WRDE_NOSPACE;
    }

  assert (ifs == NULL || *ifs != '\0');
  if (*word != NULL)
    {
      free (*word);
      *word = w_newword (word_length, max_length);
    }

  for (match = 0; match < globbuf.gl_pathc; ++match)
    {
      char *matching_word = __strdup (globbuf.gl_pathv[match]);
      if (matching_word == NULL || w_addword (pwordexp, matching_word))
	{
	  globfree (&globbuf);
	  return WRDE_NOSPACE;
	}
    }

  globfree (&globbuf);
  return 0;
}

static int internal_function parse_glob (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white)



{
  
  int error = WRDE_NOSPACE;
  int quoted = 0; 
  size_t i;
  wordexp_t glob_list; 

  glob_list.we_wordc = 0;
  glob_list.we_wordv = NULL;
  glob_list.we_offs = 0;
  for (; words[*offset] != '\0'; ++*offset)
    {
      if (strchr (ifs, words[*offset]) != NULL)
	
	break;

      
      if (words[*offset] == '\'')
	{
	  if (quoted == 0)
	    {
	      quoted = 1;
	      continue;
	    }
	  else if (quoted == 1)
	    {
	      quoted = 0;
	      continue;
	    }
	}
      else if (words[*offset] == '"')
	{
	  if (quoted == 0)
	    {
	      quoted = 2;
	      continue;
	    }
	  else if (quoted == 2)
	    {
	      quoted = 0;
	      continue;
	    }
	}

      
      if (quoted != 1 && words[*offset] == '$')
	{
	  error = parse_dollars (word, word_length, max_length, words, offset, flags, &glob_list, ifs, ifs_white, quoted == 2);

	  if (error)
	    goto tidy_up;

	  continue;
	}
      else if (words[*offset] == '\\')
	{
	  if (quoted)
	    error = parse_qtd_backslash (word, word_length, max_length, words, offset);
	  else error = parse_backslash (word, word_length, max_length, words, offset);


	  if (error)
	    goto tidy_up;

	  continue;
	}

      *word = w_addchar (*word, word_length, max_length, words[*offset]);
      if (*word == NULL)
	goto tidy_up;
    }

  
  --*offset;

  
  error = w_addword (&glob_list, *word);
  *word = w_newword (word_length, max_length);
  for (i = 0; error == 0 && i < glob_list.we_wordc; i++)
    error = do_parse_glob (glob_list.we_wordv[i], word, word_length, max_length, pwordexp, ifs, ifs_white);

  
tidy_up:
  wordfree (&glob_list);
  return error;
}

static int internal_function parse_squote (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset)


{
  
  for (; words[*offset]; ++(*offset))
    {
      if (words[*offset] != '\'')
	{
	  *word = w_addchar (*word, word_length, max_length, words[*offset]);
	  if (*word == NULL)
	    return WRDE_NOSPACE;
	}
      else return 0;
    }

  
  return WRDE_SYNTAX;
}


static int internal_function eval_expr_val (char **expr, long int *result)

{
  char *digit;

  
  for (digit = *expr; digit && *digit && isspace (*digit); ++digit);

  if (*digit == '(')
    {
      
      for (++digit; **expr && **expr != ')'; ++(*expr));

      
      if (!**expr)
	return WRDE_SYNTAX;

      *(*expr)++ = 0;

      if (eval_expr (digit, result))
	return WRDE_SYNTAX;

      return 0;
    }

  
  *result = strtol (digit, expr, 0);
  if (digit == *expr)
    return WRDE_SYNTAX;

  return 0;
}

static int internal_function eval_expr_multdiv (char **expr, long int *result)

{
  long int arg;

  
  if (eval_expr_val (expr, result) != 0)
    return WRDE_SYNTAX;

  while (**expr)
    {
      
      for (; *expr && **expr && isspace (**expr); ++(*expr));

      if (**expr == '*')
	{
	  ++(*expr);
	  if (eval_expr_val (expr, &arg) != 0)
	    return WRDE_SYNTAX;

	  *result *= arg;
	}
      else if (**expr == '/')
	{
	  ++(*expr);
	  if (eval_expr_val (expr, &arg) != 0)
	    return WRDE_SYNTAX;

	  *result /= arg;
	}
      else break;
    }

  return 0;
}

static int internal_function eval_expr (char *expr, long int *result)

{
  long int arg;

  
  if (eval_expr_multdiv (&expr, result) != 0)
    return WRDE_SYNTAX;

  while (*expr)
    {
      
      for (; expr && *expr && isspace (*expr); ++expr);

      if (*expr == '+')
	{
	  ++expr;
	  if (eval_expr_multdiv (&expr, &arg) != 0)
	    return WRDE_SYNTAX;

	  *result += arg;
	}
      else if (*expr == '-')
	{
	  ++expr;
	  if (eval_expr_multdiv (&expr, &arg) != 0)
	    return WRDE_SYNTAX;

	  *result -= arg;
	}
      else break;
    }

  return 0;
}

static int internal_function parse_arith (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, int bracket)


{
  
  int error;
  int paren_depth = 1;
  size_t expr_length;
  size_t expr_maxlen;
  char *expr;

  expr = w_newword (&expr_length, &expr_maxlen);
  for (; words[*offset]; ++(*offset))
    {
      switch (words[*offset])
	{
	case '$':
	  error = parse_dollars (&expr, &expr_length, &expr_maxlen, words, offset, flags, NULL, NULL, NULL, 1);
	  
	  if (error)
	    {
	      free (expr);
	      return error;
	    }
	  break;

	case '`':
	  (*offset)++;
	  error = parse_backtick (&expr, &expr_length, &expr_maxlen, words, offset, flags, NULL, NULL, NULL);
	  
	  if (error)
	    {
	      free (expr);
	      return error;
	    }
	  break;

	case '\\':
	  error = parse_qtd_backslash (&expr, &expr_length, &expr_maxlen, words, offset);
	  if (error)
	    {
	      free (expr);
	      return error;
	    }
	  
	  break;

	case ')':
	  if (--paren_depth == 0)
	    {
	      char result[21];	
	      long int numresult = 0;
	      long long int convertme;

	      if (bracket || words[1 + *offset] != ')')
		{
		  free (expr);
		  return WRDE_SYNTAX;
		}

	      ++(*offset);

	      
	      if (*expr && eval_expr (expr, &numresult) != 0)
		{
		  free (expr);
		  return WRDE_SYNTAX;
		}

	      if (numresult < 0)
		{
		  convertme = -numresult;
		  *word = w_addchar (*word, word_length, max_length, '-');
		  if (!*word)
		    {
		      free (expr);
		      return WRDE_NOSPACE;
		    }
		}
	      else convertme = numresult;

	      result[20] = '\0';
	      *word = w_addstr (*word, word_length, max_length, _itoa (convertme, &result[20], 10, 0));
	      free (expr);
	      return *word ? 0 : WRDE_NOSPACE;
	    }
	  expr = w_addchar (expr, &expr_length, &expr_maxlen, words[*offset]);
	  if (expr == NULL)
	    return WRDE_NOSPACE;

	  break;

	case ']':
	  if (bracket && paren_depth == 1)
	    {
	      char result[21];	
	      long int numresult = 0;

	      
	      if (*expr && eval_expr (expr, &numresult) != 0)
		{
		  free (expr);
		  return WRDE_SYNTAX;
		}

	      result[20] = '\0';
	      *word = w_addstr (*word, word_length, max_length, _itoa_word (numresult, &result[20], 10, 0));
	      free (expr);
	      return *word ? 0 : WRDE_NOSPACE;
	    }

	  free (expr);
	  return WRDE_SYNTAX;

	case '\n':
	case ';':
	case '{':
	case '}':
	  free (expr);
	  return WRDE_BADCHAR;

	case '(':
	  ++paren_depth;
	default:
	  expr = w_addchar (expr, &expr_length, &expr_maxlen, words[*offset]);
	  if (expr == NULL)
	    return WRDE_NOSPACE;
	}
    }

  
  free (expr);
  return WRDE_SYNTAX;
}


static inline void internal_function __attribute__ ((always_inline))
exec_comm_child (char *comm, int *fildes, int showerr, int noexec)
{
  const char *args[4] = { _PATH_BSHELL, "-c", comm, NULL };

  
  if (noexec)
    args[1] = "-nc";

  
  if (__glibc_likely (fildes[1] != STDOUT_FILENO))
    {
      __dup2 (fildes[1], STDOUT_FILENO);
      __close (fildes[1]);
    }
  else {

      

      if (__have_pipe2 > 0)

	__fcntl (fildes[1], F_SETFD, 0);

    }

  
  if (showerr == 0)
    {
      struct stat64 st;
      int fd;
      __close (STDERR_FILENO);
      fd = __open (_PATH_DEVNULL, O_WRONLY);
      if (fd >= 0 && fd != STDERR_FILENO)
	{
	  __dup2 (fd, STDERR_FILENO);
	  __close (fd);
	}
      
      if (__builtin_expect (__fxstat64 (_STAT_VER, STDERR_FILENO, &st), 0) != 0 || __builtin_expect (S_ISCHR (st.st_mode), 1) == 0  || st.st_rdev != makedev (DEV_NULL_MAJOR, DEV_NULL_MINOR)



	  )
	
	_exit (90);
    }

  
  __unsetenv ("IFS");

  __close (fildes[0]);
  __execve (_PATH_BSHELL, (char *const *) args, __environ);

  
  abort ();
}



static int internal_function exec_comm (char *comm, char **word, size_t *word_length, size_t *max_length, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white)



{
  int fildes[2];

  int buflen;
  int i;
  int status = 0;
  size_t maxnewlines = 0;
  char buffer[bufsize];
  pid_t pid;
  int noexec = 0;

  
  if (!comm || !*comm)
    return 0;



  if (__have_pipe2 >= 0)

    {
      int r = __pipe2 (fildes, O_CLOEXEC);

      if (__have_pipe2 == 0)
	__have_pipe2 = r != -1 || errno != ENOSYS ? 1 : -1;

      if (__have_pipe2 > 0)

	if (r < 0)
	  
	  return WRDE_NOSPACE;
    }



  if (__have_pipe2 < 0)

    if (__pipe (fildes) < 0)
      
      return WRDE_NOSPACE;


 again:
  if ((pid = __fork ()) < 0)
    {
      
      __close (fildes[0]);
      __close (fildes[1]);
      return WRDE_NOSPACE;
    }

  if (pid == 0)
    exec_comm_child (comm, fildes, noexec ? 0 : flags & WRDE_SHOWERR, noexec);

  

  
  if (noexec)
    return (TEMP_FAILURE_RETRY (__waitpid (pid, &status, 0)) == pid && status != 0) ? WRDE_SYNTAX : 0;

  __close (fildes[1]);
  fildes[1] = -1;

  if (!pwordexp)
    
    {
      while (1)
	{
	  if ((buflen = TEMP_FAILURE_RETRY (__read (fildes[0], buffer, bufsize))) < 1)
	    {
	      
	      if (TEMP_FAILURE_RETRY (__waitpid (pid, &status, buflen == 0 ? 0 : WNOHANG))
		  == 0)
		continue;
	      if ((buflen = TEMP_FAILURE_RETRY (__read (fildes[0], buffer, bufsize))) < 1)
		break;
	    }

	  maxnewlines += buflen;

	  *word = w_addmem (*word, word_length, max_length, buffer, buflen);
	  if (*word == NULL)
	    goto no_space;
	}
    }
  else  {

      int copying = 0;
      

      while (1)
	{
	  if ((buflen = TEMP_FAILURE_RETRY (__read (fildes[0], buffer, bufsize))) < 1)
	    {
	      
	      if (TEMP_FAILURE_RETRY (__waitpid (pid, &status, buflen == 0 ? 0 : WNOHANG))
		  == 0)
		continue;
	      if ((buflen = TEMP_FAILURE_RETRY (__read (fildes[0], buffer, bufsize))) < 1)
		break;
	    }

	  for (i = 0; i < buflen; ++i)
	    {
	      if (strchr (ifs, buffer[i]) != NULL)
		{
		  
		  if (strchr (ifs_white, buffer[i]) == NULL)
		    {
		      
		      if (copying == 2)
			{
			  
			  copying = 0;
			  continue;
			}

		      copying = 0;
		      
		    }
		  else {
		      if (buffer[i] == '\n')
			{
			  

			  
			  if (copying == 1)
			    copying = 3;

			  continue;
			}
		      else {
			  

			  
			  if (copying != 1 && copying != 3)
			    continue;

			  
			  copying = 2;
			}
		    }

		  
		  if (w_addword (pwordexp, *word) == WRDE_NOSPACE)
		    goto no_space;

		  *word = w_newword (word_length, max_length);

		  maxnewlines = 0;
		  
		}
	      else {
		  

		  if (copying == 3)
		    {
		      
		      if (w_addword (pwordexp, *word) == WRDE_NOSPACE)
			goto no_space;

		      *word = w_newword (word_length, max_length);
		    }

		  copying = 1;

		  if (buffer[i] == '\n') 
		    maxnewlines++;
		  else maxnewlines = 0;

		  *word = w_addchar (*word, word_length, max_length, buffer[i]);
		  if (*word == NULL)
		    goto no_space;
		}
	    }
	}
    }

  
  
  while (maxnewlines-- != 0 && *word_length > 0 && (*word)[*word_length - 1] == '\n')
    {
      (*word)[--*word_length] = '\0';

      
      if (*word_length == 0)
	{
	  free (*word);
	  *word = w_newword (word_length, max_length);
	  break;
	}
    }

  __close (fildes[0]);
  fildes[0] = -1;

  
  if (buflen < 1 && status != 0)
    {
      noexec = 1;
      goto again;
    }

  return 0;

no_space:
  __kill (pid, SIGKILL);
  TEMP_FAILURE_RETRY (__waitpid (pid, NULL, 0));
  __close (fildes[0]);
  return WRDE_NOSPACE;
}

static int internal_function parse_comm (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white)



{
  
  int paren_depth = 1;
  int error = 0;
  int quoted = 0; 
  size_t comm_length;
  size_t comm_maxlen;
  char *comm = w_newword (&comm_length, &comm_maxlen);

  for (; words[*offset]; ++(*offset))
    {
      switch (words[*offset])
	{
	case '\'':
	  if (quoted == 0)
	    quoted = 1;
	  else if (quoted == 1)
	    quoted = 0;

	  break;

	case '"':
	  if (quoted == 0)
	    quoted = 2;
	  else if (quoted == 2)
	    quoted = 0;

	  break;

	case ')':
	  if (!quoted && --paren_depth == 0)
	    {
	      
	      if (comm)
		{

		  
		  
		  
		  int state = PTHREAD_CANCEL_ENABLE;
		  __libc_ptf_call (pthread_setcancelstate, (PTHREAD_CANCEL_DISABLE, &state), 0);


		  error = exec_comm (comm, word, word_length, max_length, flags, pwordexp, ifs, ifs_white);


		  __libc_ptf_call (pthread_setcancelstate, (state, NULL), 0);


		  free (comm);
		}

	      return error;
	    }

	  
	  break;

	case '(':
	  if (!quoted)
	    ++paren_depth;
	}

      comm = w_addchar (comm, &comm_length, &comm_maxlen, words[*offset]);
      if (comm == NULL)
	return WRDE_NOSPACE;
    }

  
  free (comm);

  return WRDE_SYNTAX;
}

static int internal_function parse_param (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white, int quoted)



{
  
  enum action {
    ACT_NONE, ACT_RP_SHORT_LEFT = '#', ACT_RP_LONG_LEFT = 'L', ACT_RP_SHORT_RIGHT = '%', ACT_RP_LONG_RIGHT = 'R', ACT_NULL_ERROR = '?', ACT_NULL_SUBST = '-', ACT_NONNULL_SUBST = '+', ACT_NULL_ASSIGN = '=' };








  size_t env_length;
  size_t env_maxlen;
  size_t pat_length;
  size_t pat_maxlen;
  size_t start = *offset;
  char *env;
  char *pattern;
  char *value = NULL;
  enum action action = ACT_NONE;
  int depth = 0;
  int colon_seen = 0;
  int seen_hash = 0;
  int free_value = 0;
  int pattern_is_quoted = 0; 
  int error;
  int special = 0;
  char buffer[21];
  int brace = words[*offset] == '{';

  env = w_newword (&env_length, &env_maxlen);
  pattern = w_newword (&pat_length, &pat_maxlen);

  if (brace)
    ++*offset;

  

  if (words[*offset] == '#')
    {
      seen_hash = 1;
      if (!brace)
	goto envsubst;
      ++*offset;
    }

  if (isalpha (words[*offset]) || words[*offset] == '_')
    {
      
      do {
	  env = w_addchar (env, &env_length, &env_maxlen, words[*offset]);
	  if (env == NULL)
	    goto no_space;
	}
      while (isalnum (words[++*offset]) || words[*offset] == '_');
    }
  else if (isdigit (words[*offset]))
    {
      
      special = 1;
      do {
	  env = w_addchar (env, &env_length, &env_maxlen, words[*offset]);
	  if (env == NULL)
	    goto no_space;
	  if (!brace)
	    goto envsubst;
	}
      while (isdigit(words[++*offset]));
    }
  else if (strchr ("*@$", words[*offset]) != NULL)
    {
      
      special = 1;
      env = w_addchar (env, &env_length, &env_maxlen, words[*offset]);
      if (env == NULL)
	goto no_space;
      ++*offset;
    }
  else {
      if (brace)
	goto syntax;
    }

  if (brace)
    {
      
      switch (words[*offset])
	{
	case '}':
	  
	  goto envsubst;

	case '#':
	  action = ACT_RP_SHORT_LEFT;
	  if (words[1 + *offset] == '#')
	    {
	      ++*offset;
	      action = ACT_RP_LONG_LEFT;
	    }
	  break;

	case '%':
	  action = ACT_RP_SHORT_RIGHT;
	  if (words[1 + *offset] == '%')
	    {
	      ++*offset;
	      action = ACT_RP_LONG_RIGHT;
	    }
	  break;

	case ':':
	  if (strchr ("-=?+", words[1 + *offset]) == NULL)
	    goto syntax;

	  colon_seen = 1;
	  action = words[++*offset];
	  break;

	case '-':
	case '=':
	case '?':
	case '+':
	  action = words[*offset];
	  break;

	default:
	  goto syntax;
	}

      
      ++*offset;
      for (; words[*offset]; ++(*offset))
	{
	  switch (words[*offset])
	    {
	    case '{':
	      if (!pattern_is_quoted)
		++depth;
	      break;

	    case '}':
	      if (!pattern_is_quoted)
		{
		  if (depth == 0)
		    goto envsubst;
		  --depth;
		}
	      break;

	    case '\\':
	      if (pattern_is_quoted)
		
		break;

	      
	      if (words[++*offset] == '\0')
		goto syntax;

	      pattern = w_addchar (pattern, &pat_length, &pat_maxlen, '\\');
	      if (pattern == NULL)
		goto no_space;

	      break;

	    case '\'':
	      if (pattern_is_quoted == 0)
		pattern_is_quoted = 1;
	      else if (pattern_is_quoted == 1)
		pattern_is_quoted = 0;

	      break;

	    case '"':
	      if (pattern_is_quoted == 0)
		pattern_is_quoted = 2;
	      else if (pattern_is_quoted == 2)
		pattern_is_quoted = 0;

	      break;
	    }

	  pattern = w_addchar (pattern, &pat_length, &pat_maxlen, words[*offset]);
	  if (pattern == NULL)
	    goto no_space;
	}
    }

  
  --(*offset);

envsubst:
  if (words[start] == '{' && words[*offset] != '}')
    goto syntax;

  if (env == NULL)
    {
      if (seen_hash)
	{
	  
	  buffer[20] = '\0';
	  value = _itoa_word (__libc_argc - 1, &buffer[20], 10, 0);
	  seen_hash = 0;
	}
      else {
	  
	  *offset = start - 1;
	  *word = w_addchar (*word, word_length, max_length, '$');
	  return *word ? 0 : WRDE_NOSPACE;
	}
    }
  
  else if (isdigit (env[0]))
    {
      int n = atoi (env);

      if (n >= __libc_argc)
	
	value = NULL;
      else  value = __libc_argv[n];

    }
  
  else if (special)
    {
      
      if (*env == '$')
	{
	  buffer[20] = '\0';
	  value = _itoa_word (__getpid (), &buffer[20], 10, 0);
	}
      
      else if ((*env == '*' || *env == '@') && seen_hash)
	{
	  buffer[20] = '\0';
	  value = _itoa_word (__libc_argc > 0 ? __libc_argc - 1 : 0, &buffer[20], 10, 0);
	  *word = w_addstr (*word, word_length, max_length, value);
	  free (env);
	  free (pattern);
	  return *word ? 0 : WRDE_NOSPACE;
	}
      
      else if (*env == '*' || (*env == '@' && !quoted))
	{
	  size_t plist_len = 0;
	  int p;
	  char *end;

	  
	  for (p = 1; __libc_argv[p]; ++p)
	    plist_len += strlen (__libc_argv[p]) + 1; 
	  value = malloc (plist_len);
	  if (value == NULL)
	    goto no_space;
	  end = value;
	  *end = 0;
	  for (p = 1; __libc_argv[p]; ++p)
	    {
	      if (p > 1)
		*end++ = ' ';
	      end = __stpcpy (end, __libc_argv[p]);
	    }

	  free_value = 1;
	}
      else {
	  
	  assert (*env == '@' && quoted);

	  
	  if (__libc_argc == 2)
	    value = __libc_argv[1];
	  else if (__libc_argc > 2)
	    {
	      int p;

	      
	      value = w_addstr (*word, word_length, max_length, __libc_argv[1]);
	      if (value == NULL || w_addword (pwordexp, value))
		goto no_space;

	      for (p = 2; __libc_argv[p + 1]; p++)
		{
		  char *newword = __strdup (__libc_argv[p]);
		  if (newword == NULL || w_addword (pwordexp, newword))
		    goto no_space;
		}

	      
	      *word = w_newword (word_length, max_length);
	      value = __libc_argv[p];
	    }
	  else {
	      free (env);
	      free (pattern);
	      return 0;
	    }
	}
    }
  else value = getenv (env);

  if (value == NULL && (flags & WRDE_UNDEF))
    {
      
      error = WRDE_BADVAL;
      goto do_error;
    }

  if (action != ACT_NONE)
    {
      int expand_pattern = 0;

      
      switch (action)
	{
	case ACT_RP_SHORT_LEFT:
	case ACT_RP_LONG_LEFT:
	case ACT_RP_SHORT_RIGHT:
	case ACT_RP_LONG_RIGHT:
	  
	  expand_pattern = 1;
	  break;

	case ACT_NULL_ERROR:
	case ACT_NULL_SUBST:
	case ACT_NULL_ASSIGN:
	  if (!value || (!*value && colon_seen))
	    
	    expand_pattern = 1;

	  break;

	case ACT_NONNULL_SUBST:
	  
	  if (value && (*value || !colon_seen))
	    expand_pattern = 1;

	  break;

	default:
	  assert (! "Unrecognised action!");
	}

      if (expand_pattern)
	{
	  

	  char *expanded;
	  size_t exp_len;
	  size_t exp_maxl;
	  char *p;
	  int quoted = 0; 

	  expanded = w_newword (&exp_len, &exp_maxl);
	  for (p = pattern; p && *p; p++)
	    {
	      size_t offset;

	      switch (*p)
		{
		case '"':
		  if (quoted == 2)
		    quoted = 0;
		  else if (quoted == 0)
		    quoted = 2;
		  else break;

		  continue;

		case '\'':
		  if (quoted == 1)
		    quoted = 0;
		  else if (quoted == 0)
		    quoted = 1;
		  else break;

		  continue;

		case '*':
		case '?':
		  if (quoted)
		    {
		      
		      expanded = w_addchar (expanded, &exp_len, &exp_maxl, '\\');

		      if (expanded == NULL)
			goto no_space;
		    }
		  break;

		case '$':
		  offset = 0;
		  error = parse_dollars (&expanded, &exp_len, &exp_maxl, p, &offset, flags, NULL, NULL, NULL, 1);
		  if (error)
		    {
		      if (free_value)
			free (value);

		      free (expanded);

		      goto do_error;
		    }

		  p += offset;
		  continue;

		case '~':
		  if (quoted || exp_len)
		    break;

		  offset = 0;
		  error = parse_tilde (&expanded, &exp_len, &exp_maxl, p, &offset, 0);
		  if (error)
		    {
		      if (free_value)
			free (value);

		      free (expanded);

		      goto do_error;
		    }

		  p += offset;
		  continue;

		case '\\':
		  expanded = w_addchar (expanded, &exp_len, &exp_maxl, '\\');
		  ++p;
		  assert (*p); 
		  if (expanded == NULL)
		    goto no_space;
		}

	      expanded = w_addchar (expanded, &exp_len, &exp_maxl, *p);

	      if (expanded == NULL)
		goto no_space;
	    }

	  free (pattern);

	  pattern = expanded;
	}

      switch (action)
	{
	case ACT_RP_SHORT_LEFT:
	case ACT_RP_LONG_LEFT:
	case ACT_RP_SHORT_RIGHT:
	case ACT_RP_LONG_RIGHT:
	  {
	    char *p;
	    char c;
	    char *end;

	    if (value == NULL || pattern == NULL || *pattern == '\0')
	      break;

	    end = value + strlen (value);

	    switch (action)
	      {
	      case ACT_RP_SHORT_LEFT:
		for (p = value; p <= end; ++p)
		  {
		    c = *p;
		    *p = '\0';
		    if (fnmatch (pattern, value, 0) != FNM_NOMATCH)
		      {
			*p = c;
			if (free_value)
			  {
			    char *newval = __strdup (p);
			    if (newval == NULL)
			      {
				free (value);
				goto no_space;
			      }
			    free (value);
			    value = newval;
			  }
			else value = p;
			break;
		      }
		    *p = c;
		  }

		break;

	      case ACT_RP_LONG_LEFT:
		for (p = end; p >= value; --p)
		  {
		    c = *p;
		    *p = '\0';
		    if (fnmatch (pattern, value, 0) != FNM_NOMATCH)
		      {
			*p = c;
			if (free_value)
			  {
			    char *newval = __strdup (p);
			    if (newval == NULL)
			      {
				free (value);
				goto no_space;
			      }
			    free (value);
			    value = newval;
			  }
			else value = p;
			break;
		      }
		    *p = c;
		  }

		break;

	      case ACT_RP_SHORT_RIGHT:
		for (p = end; p >= value; --p)
		  {
		    if (fnmatch (pattern, p, 0) != FNM_NOMATCH)
		      {
			char *newval;
			newval = malloc (p - value + 1);

			if (newval == NULL)
			  {
			    if (free_value)
			      free (value);
			    goto no_space;
			  }

			*(char *) __mempcpy (newval, value, p - value) = '\0';
			if (free_value)
			  free (value);
			value = newval;
			free_value = 1;
			break;
		      }
		  }

		break;

	      case ACT_RP_LONG_RIGHT:
		for (p = value; p <= end; ++p)
		  {
		    if (fnmatch (pattern, p, 0) != FNM_NOMATCH)
		      {
			char *newval;
			newval = malloc (p - value + 1);

			if (newval == NULL)
			  {
			    if (free_value)
			      free (value);
			    goto no_space;
			  }

			*(char *) __mempcpy (newval, value, p - value) = '\0';
			if (free_value)
			  free (value);
			value = newval;
			free_value = 1;
			break;
		      }
		  }

		break;

	      default:
		break;
	      }

	    break;
	  }

	case ACT_NULL_ERROR:
	  if (value && *value)
	    
	    break;

	  error = 0;
	  if (!colon_seen && value)
	    
	    ;
	  else {
	      const char *str = pattern;

	      if (str[0] == '\0')
		str = _("parameter null or not set");

	      __fxprintf (NULL, "%s: %s\n", env, str);
	    }

	  if (free_value)
	    free (value);
	  goto do_error;

	case ACT_NULL_SUBST:
	  if (value && *value)
	    
	    break;

	  if (free_value)
	    free (value);

	  if (!colon_seen && value)
	    
	    goto success;

	  value = pattern ? __strdup (pattern) : pattern;
	  free_value = 1;

	  if (pattern && !value)
	    goto no_space;

	  break;

	case ACT_NONNULL_SUBST:
	  if (value && (*value || !colon_seen))
	    {
	      if (free_value)
		free (value);

	      value = pattern ? __strdup (pattern) : pattern;
	      free_value = 1;

	      if (pattern && !value)
		goto no_space;

	      break;
	    }

	  
	  if (free_value)
	    free (value);
	  goto success;

	case ACT_NULL_ASSIGN:
	  if (value && *value)
	    
	    break;

	  if (!colon_seen && value)
	    {
	      
	      if (free_value)
		free (value);
	      goto success;
	    }

	  if (free_value)
	    free (value);

	  value = pattern ? __strdup (pattern) : pattern;
	  free_value = 1;

	  if (pattern && !value)
	    goto no_space;

	  __setenv (env, value, 1);
	  break;

	default:
	  assert (! "Unrecognised action!");
	}
    }

  free (env);
  env = NULL;
  free (pattern);
  pattern = NULL;

  if (seen_hash)
    {
      char param_length[21];
      param_length[20] = '\0';
      *word = w_addstr (*word, word_length, max_length, _itoa_word (value ? strlen (value) : 0, &param_length[20], 10, 0));

      if (free_value)
	{
	  assert (value != NULL);
	  free (value);
	}

      return *word ? 0 : WRDE_NOSPACE;
    }

  if (value == NULL)
    return 0;

  if (quoted || !pwordexp)
    {
      
      *word = w_addstr (*word, word_length, max_length, value);
      if (free_value)
	free (value);

      return *word ? 0 : WRDE_NOSPACE;
    }
  else {
      
      char *value_copy = __strdup (value); 
      char *field_begin = value_copy;
      int seen_nonws_ifs = 0;

      if (free_value)
	free (value);

      if (value_copy == NULL)
	goto no_space;

      do {
	  char *field_end = field_begin;
	  char *next_field;

	  
	  if (field_begin != value_copy)
	    {
	      if (w_addword (pwordexp, *word) == WRDE_NOSPACE)
		{
		  free (value_copy);
		  goto no_space;
		}

	      *word = w_newword (word_length, max_length);
	    }

	  
	  field_begin += strspn (field_begin, ifs_white);

	  if (!seen_nonws_ifs && *field_begin == 0)
	    
	    break;

	  
	  field_end = field_begin + strcspn (field_begin, ifs);

	  
	  next_field = field_end + strspn (field_end, ifs_white);

	  
	  seen_nonws_ifs = 0;
	  if (*next_field && strchr (ifs, *next_field))
	    {
	      seen_nonws_ifs = 1;
	      next_field++;
	    }

	  
	  *field_end = 0;

	  
	  *word = w_addstr (*word, word_length, max_length, field_begin);

	  if (*word == NULL && *field_begin != '\0')
	    {
	      free (value_copy);
	      goto no_space;
	    }

	  field_begin = next_field;
	}
      while (seen_nonws_ifs || *field_begin);

      free (value_copy);
    }

  return 0;

success:
  error = 0;
  goto do_error;

no_space:
  error = WRDE_NOSPACE;
  goto do_error;

syntax:
  error = WRDE_SYNTAX;

do_error:
  free (env);

  free (pattern);

  return error;
}

static int internal_function parse_dollars (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white, int quoted)




{
  
  switch (words[1 + *offset])
    {
    case '"':
    case '\'':
    case 0:
      *word = w_addchar (*word, word_length, max_length, '$');
      return *word ? 0 : WRDE_NOSPACE;

    case '(':
      if (words[2 + *offset] == '(')
	{
	  
	  int i = 3 + *offset;
	  int depth = 0;
	  while (words[i] && !(depth == 0 && words[i] == ')'))
	    {
	      if (words[i] == '(')
		++depth;
	      else if (words[i] == ')')
		--depth;

	      ++i;
	    }

	  if (words[i] == ')' && words[i + 1] == ')')
	    {
	      (*offset) += 3;
	      
	      return parse_arith (word, word_length, max_length, words, offset, flags, 0);
	    }
	}

      if (flags & WRDE_NOCMD)
	return WRDE_CMDSUB;

      (*offset) += 2;
      return parse_comm (word, word_length, max_length, words, offset, flags, quoted? NULL : pwordexp, ifs, ifs_white);

    case '[':
      (*offset) += 2;
      
      return parse_arith (word, word_length, max_length, words, offset, flags, 1);

    case '{':
    default:
      ++(*offset);	
      return parse_param (word, word_length, max_length, words, offset, flags, pwordexp, ifs, ifs_white, quoted);
    }
}

static int internal_function parse_backtick (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char *ifs, const char *ifs_white)



{
  
  int error;
  int squoting = 0;
  size_t comm_length;
  size_t comm_maxlen;
  char *comm = w_newword (&comm_length, &comm_maxlen);

  for (; words[*offset]; ++(*offset))
    {
      switch (words[*offset])
	{
	case '`':
	  
	  error = exec_comm (comm, word, word_length, max_length, flags, pwordexp, ifs, ifs_white);
	  free (comm);
	  return error;

	case '\\':
	  if (squoting)
	    {
	      error = parse_qtd_backslash (&comm, &comm_length, &comm_maxlen, words, offset);

	      if (error)
		{
		  free (comm);
		  return error;
		}

	      break;
	    }

	  ++(*offset);
	  error = parse_backslash (&comm, &comm_length, &comm_maxlen, words, offset);

	  if (error)
	    {
	      free (comm);
	      return error;
	    }

	  break;

	case '\'':
	  squoting = 1 - squoting;
	default:
	  comm = w_addchar (comm, &comm_length, &comm_maxlen, words[*offset]);
	  if (comm == NULL)
	    return WRDE_NOSPACE;
	}
    }

  
  free (comm);
  return WRDE_SYNTAX;
}

static int internal_function parse_dquote (char **word, size_t *word_length, size_t *max_length, const char *words, size_t *offset, int flags, wordexp_t *pwordexp, const char * ifs, const char * ifs_white)



{
  
  int error;

  for (; words[*offset]; ++(*offset))
    {
      switch (words[*offset])
	{
	case '"':
	  return 0;

	case '$':
	  error = parse_dollars (word, word_length, max_length, words, offset, flags, pwordexp, ifs, ifs_white, 1);
	  
	  if (error)
	    return error;

	  break;

	case '`':
	  if (flags & WRDE_NOCMD)
	    return WRDE_CMDSUB;

	  ++(*offset);
	  error = parse_backtick (word, word_length, max_length, words, offset, flags, NULL, NULL, NULL);
	  
	  if (error)
	    return error;

	  break;

	case '\\':
	  error = parse_qtd_backslash (word, word_length, max_length, words, offset);

	  if (error)
	    return error;

	  break;

	default:
	  *word = w_addchar (*word, word_length, max_length, words[*offset]);
	  if (*word == NULL)
	    return WRDE_NOSPACE;
	}
    }

  
  return WRDE_SYNTAX;
}



void wordfree (wordexp_t *pwordexp)
{

  
  if (pwordexp && pwordexp->we_wordv)
    {
      char **wordv = pwordexp->we_wordv;

      for (wordv += pwordexp->we_offs; *wordv; ++wordv)
	free (*wordv);

      free (pwordexp->we_wordv);
      pwordexp->we_wordv = NULL;
    }
}
libc_hidden_def (wordfree)



int wordexp (const char *words, wordexp_t *pwordexp, int flags)
{
  size_t words_offset;
  size_t word_length;
  size_t max_length;
  char *word = w_newword (&word_length, &max_length);
  int error;
  char *ifs;
  char ifs_white[4];
  wordexp_t old_word = *pwordexp;

  if (flags & WRDE_REUSE)
    {
      
      wordfree (pwordexp);
      old_word.we_wordv = NULL;
    }

  if ((flags & WRDE_APPEND) == 0)
    {
      pwordexp->we_wordc = 0;

      if (flags & WRDE_DOOFFS)
	{
	  pwordexp->we_wordv = calloc (1 + pwordexp->we_offs, sizeof (char *));
	  if (pwordexp->we_wordv == NULL)
	    {
	      error = WRDE_NOSPACE;
	      goto do_error;
	    }
	}
      else {
	  pwordexp->we_wordv = calloc (1, sizeof (char *));
	  if (pwordexp->we_wordv == NULL)
	    {
	      error = WRDE_NOSPACE;
	      goto do_error;
	    }

	  pwordexp->we_offs = 0;
	}
    }

  
  ifs = getenv ("IFS");

  if (ifs == NULL)
    
    ifs = strcpy (ifs_white, " \t\n");
  else {
      char *ifsch = ifs;
      char *whch = ifs_white;

      while (*ifsch != '\0')
	{
	  if (*ifsch == ' ' || *ifsch == '\t' || *ifsch == '\n')
	    {
	      
	      char *runp = ifs_white;

	      while (runp < whch && *runp != *ifsch)
		++runp;

	      if (runp == whch)
		*whch++ = *ifsch;
	    }

	  ++ifsch;
	}
      *whch = '\0';
    }

  for (words_offset = 0 ; words[words_offset] ; ++words_offset)
    switch (words[words_offset])
      {
      case '\\':
	error = parse_backslash (&word, &word_length, &max_length, words, &words_offset);

	if (error)
	  goto do_error;

	break;

      case '$':
	error = parse_dollars (&word, &word_length, &max_length, words, &words_offset, flags, pwordexp, ifs, ifs_white, 0);


	if (error)
	  goto do_error;

	break;

      case '`':
	if (flags & WRDE_NOCMD)
	  {
	    error = WRDE_CMDSUB;
	    goto do_error;
	  }

	++words_offset;
	error = parse_backtick (&word, &word_length, &max_length, words, &words_offset, flags, pwordexp, ifs, ifs_white);


	if (error)
	  goto do_error;

	break;

      case '"':
	++words_offset;
	error = parse_dquote (&word, &word_length, &max_length, words, &words_offset, flags, pwordexp, ifs, ifs_white);

	if (error)
	  goto do_error;

	if (!word_length)
	  {
	    error = w_addword (pwordexp, NULL);

	    if (error)
	      return error;
	  }

	break;

      case '\'':
	++words_offset;
	error = parse_squote (&word, &word_length, &max_length, words, &words_offset);

	if (error)
	  goto do_error;

	if (!word_length)
	  {
	    error = w_addword (pwordexp, NULL);

	    if (error)
	      return error;
	  }

	break;

      case '~':
	error = parse_tilde (&word, &word_length, &max_length, words, &words_offset, pwordexp->we_wordc);

	if (error)
	  goto do_error;

	break;

      case '*':
      case '[':
      case '?':
	error = parse_glob (&word, &word_length, &max_length, words, &words_offset, flags, pwordexp, ifs, ifs_white);

	if (error)
	  goto do_error;

	break;

      default:
	
	if (strchr (" \t", words[words_offset]) == NULL)
	  {
	    char ch = words[words_offset];

	    
	    if (strchr ("\n|&;<>(){}", ch))
	      {
		
		error = WRDE_BADCHAR;
		goto do_error;
	      }

	    
	    word = w_addchar (word, &word_length, &max_length, ch);
	    if (word == NULL)
	      {
		error = WRDE_NOSPACE;
		goto do_error;
	      }

	    break;
	  }

	
	if (word != NULL)
	  {
	    error = w_addword (pwordexp, word);
	    if (error)
	      goto do_error;
	  }

	word = w_newword (&word_length, &max_length);
      }

  

  
  if (word == NULL) 
    return 0;

  
  return w_addword (pwordexp, word);

do_error:
  

  free (word);

  if (error == WRDE_NOSPACE)
    return WRDE_NOSPACE;

  if ((flags & WRDE_APPEND) == 0)
    wordfree (pwordexp);

  *pwordexp = old_word;
  return error;
}
