






















struct __locale_data *const _nl_C[] attribute_hidden = {



  };






struct loaded_l10nfile *_nl_locale_file_list[__LC_LAST];

const char _nl_default_locale_path[] attribute_hidden = LOCALEDIR;


struct __locale_data * internal_function _nl_find_locale (const char *locale_path, size_t locale_path_len, int category, const char **name)


{
  int mask;
  
  char *loc_name;
  const char *language;
  const char *modifier;
  const char *territory;
  const char *codeset;
  const char *normalized_codeset;
  struct loaded_l10nfile *locale_file;

  if ((*name)[0] == '\0')
    {
      
      *name = getenv ("LC_ALL");
      if (*name == NULL || (*name)[0] == '\0')
	*name = getenv (_nl_category_names.str + _nl_category_name_idxs[category]);
      if (*name == NULL || (*name)[0] == '\0')
	*name = getenv ("LANG");
    }

  if (*name == NULL || (*name)[0] == '\0' || (__builtin_expect (__libc_enable_secure, 0)
	  && strchr (*name, '/') != NULL))
    *name = (char *) _nl_C_name;

  if (__builtin_expect (strcmp (*name, _nl_C_name), 1) == 0 || __builtin_expect (strcmp (*name, _nl_POSIX_name), 1) == 0)
    {
      
      *name = (char *) _nl_C_name;
      return _nl_C[category];
    }

  
  if (__glibc_likely (locale_path == NULL))
    {
      struct __locale_data *data = _nl_load_locale_from_archive (category, name);
      if (__glibc_likely (data != NULL))
	return data;

      
      locale_path = _nl_default_locale_path;
      locale_path_len = sizeof _nl_default_locale_path;
    }

  
  loc_name = (char *) _nl_expand_alias (*name);
  if (loc_name == NULL)
    
    loc_name = (char *) *name;

  
  loc_name = strdupa (loc_name);

  
  mask = _nl_explode_name (loc_name, &language, &modifier, &territory, &codeset, &normalized_codeset);
  if (mask == -1)
    
    return NULL;

  
  locale_file = _nl_make_l10nflist (&_nl_locale_file_list[category], locale_path, locale_path_len, mask, language, territory, codeset, normalized_codeset, modifier, _nl_category_names.str + _nl_category_name_idxs[category], 0);





  if (locale_file == NULL)
    {
      
      locale_file = _nl_make_l10nflist (&_nl_locale_file_list[category], locale_path, locale_path_len, mask, language, territory, codeset, normalized_codeset, modifier, _nl_category_names.str + _nl_category_name_idxs[category], 1);




      if (locale_file == NULL)
	
	return NULL;
    }

  
  if (mask & XPG_NORM_CODESET)
    free ((void *) normalized_codeset);

  if (locale_file->decided == 0)
    _nl_load_locale (locale_file, category);

  if (locale_file->data == NULL)
    {
      int cnt;
      for (cnt = 0; locale_file->successor[cnt] != NULL; ++cnt)
	{
	  if (locale_file->successor[cnt]->decided == 0)
	    _nl_load_locale (locale_file->successor[cnt], category);
	  if (locale_file->successor[cnt]->data != NULL)
	    break;
	}
      
      locale_file->successor[0] = locale_file->successor[cnt];
      locale_file = locale_file->successor[cnt];

      if (locale_file == NULL)
	return NULL;
    }

  
  if (codeset != NULL)
    {
      
      static const int codeset_idx[] = {
	  [__LC_CTYPE] = _NL_ITEM_INDEX (CODESET), [__LC_NUMERIC] = _NL_ITEM_INDEX (_NL_NUMERIC_CODESET), [__LC_TIME] = _NL_ITEM_INDEX (_NL_TIME_CODESET), [__LC_COLLATE] = _NL_ITEM_INDEX (_NL_COLLATE_CODESET), [__LC_MONETARY] = _NL_ITEM_INDEX (_NL_MONETARY_CODESET), [__LC_MESSAGES] = _NL_ITEM_INDEX (_NL_MESSAGES_CODESET), [__LC_PAPER] = _NL_ITEM_INDEX (_NL_PAPER_CODESET), [__LC_NAME] = _NL_ITEM_INDEX (_NL_NAME_CODESET), [__LC_ADDRESS] = _NL_ITEM_INDEX (_NL_ADDRESS_CODESET), [__LC_TELEPHONE] = _NL_ITEM_INDEX (_NL_TELEPHONE_CODESET), [__LC_MEASUREMENT] = _NL_ITEM_INDEX (_NL_MEASUREMENT_CODESET), [__LC_IDENTIFICATION] = _NL_ITEM_INDEX (_NL_IDENTIFICATION_CODESET)










	};
      const struct __locale_data *data;
      const char *locale_codeset;
      char *clocale_codeset;
      char *ccodeset;

      data = (const struct __locale_data *) locale_file->data;
      locale_codeset = (const char *) data->values[codeset_idx[category]].string;
      assert (locale_codeset != NULL);
      
      clocale_codeset = (char *) alloca (strlen (locale_codeset) + 3);
      strip (clocale_codeset, locale_codeset);

      ccodeset = (char *) alloca (strlen (codeset) + 3);
      strip (ccodeset, codeset);

      if (__gconv_compare_alias (upstr (ccodeset, ccodeset), upstr (clocale_codeset, clocale_codeset)) != 0)

	
	return NULL;
    }

  
  if (((const struct __locale_data *) locale_file->data)->name == NULL)
    {
      char *cp, *endp;

      endp = strrchr (locale_file->filename, '/');
      cp = endp - 1;
      while (cp[-1] != '/')
	--cp;
      ((struct __locale_data *) locale_file->data)->name = __strndup (cp, endp - cp);
    }

  
  if (modifier != NULL && __strcasecmp_l (modifier, "TRANSLIT", _nl_C_locobj_ptr) == 0)
    ((struct __locale_data *) locale_file->data)->use_translit = 1;

  
  if (((const struct __locale_data *) locale_file->data)->usage_count < MAX_USAGE_COUNT)
    ++((struct __locale_data *) locale_file->data)->usage_count;

  return (struct __locale_data *) locale_file->data;
}



void internal_function _nl_remove_locale (int locale, struct __locale_data *data)

{
  if (--data->usage_count == 0)
    {
      if (data->alloc != ld_archive)
	{
	  
	  struct loaded_l10nfile *ptr = _nl_locale_file_list[locale];

	  
	  while ((struct __locale_data *) ptr->data != data)
	    ptr = ptr->next;

	  
	  ptr->decided = 0;
	  ptr->data = NULL;
	}

      
      _nl_unload_locale (data);
    }
}
