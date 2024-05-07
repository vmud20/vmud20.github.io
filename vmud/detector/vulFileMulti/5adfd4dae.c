















struct libmnt_optloc {
	char	*begin;
	char	*end;
	char	*value;
	size_t	valsz;
	size_t  namesz;
};






static int mnt_optstr_parse_next(char **optstr,	 char **name, size_t *namesz, char **value, size_t *valsz)
{
	int open_quote = 0;
	char *start = NULL, *stop = NULL, *p, *sep = NULL;
	char *optstr0;

	assert(optstr);
	assert(*optstr);

	optstr0 = *optstr;

	if (name)
		*name = NULL;
	if (namesz)
		*namesz = 0;
	if (value)
		*value = NULL;
	if (valsz)
		*valsz = 0;

	
	while (optstr0 && *optstr0 == ',')
		optstr0++;

	for (p = optstr0; p && *p; p++) {
		if (!start)
			start = p;		
		if (*p == '"')
			open_quote ^= 1;	
		if (open_quote)
			continue;		
		if (!sep && p > start && *p == '=')
			sep = p;		
		if (*p == ',')
			stop = p;		
		else if (*(p + 1) == '\0')
			stop = p + 1;		
		if (!start || !stop)
			continue;
		if (stop <= start)
			goto error;

		if (name)
			*name = start;
		if (namesz)
			*namesz = sep ? sep - start : stop - start;
		*optstr = *stop ? stop + 1 : stop;

		if (sep) {
			if (value)
				*value = sep + 1;
			if (valsz)
				*valsz = stop - sep - 1;
		}
		return 0;
	}

	return 1;				

error:
	DBG(OPTIONS, ul_debug("parse error: \"%s\"", optstr0));
	return -EINVAL;
}


static int mnt_optstr_locate_option(char *optstr, const char *name, struct libmnt_optloc *ol)
{
	char *n;
	size_t namesz, nsz;
	int rc;

	if (!optstr)
		return 1;

	assert(name);

	namesz = strlen(name);

	do {
		rc = mnt_optstr_parse_next(&optstr, &n, &nsz, &ol->value, &ol->valsz);
		if (rc)
			break;

		if (namesz == nsz && strncmp(n, name, nsz) == 0) {
			ol->begin = n;
			ol->end = *(optstr - 1) == ',' ? optstr - 1 : optstr;
			ol->namesz = nsz;
			return 0;
		}
	} while(1);

	return rc;
}


int mnt_optstr_next_option(char **optstr, char **name, size_t *namesz, char **value, size_t *valuesz)
{
	if (!optstr || !*optstr)
		return -EINVAL;
	return mnt_optstr_parse_next(optstr, name, namesz, value, valuesz);
}

static int __buffer_append_option(struct ul_buffer *buf, const char *name, size_t namesz, const char *val, size_t valsz)

{
	int rc = 0;

	if (!ul_buffer_is_empty(buf))
		rc = ul_buffer_append_data(buf, ",", 1);
	if (!rc)
		rc = ul_buffer_append_data(buf, name, namesz);
	if (val && !rc) {
		
		rc = ul_buffer_append_data(buf, "=", 1);
		if (!rc && valsz)
			rc = ul_buffer_append_data(buf, val, valsz);
	}
	return rc;
}


int mnt_optstr_append_option(char **optstr, const char *name, const char *value)
{
	struct ul_buffer buf = UL_INIT_BUFFER;
	int rc;
	size_t nsz, vsz, osz;

	if (!optstr)
		return -EINVAL;
	if (!name || !*name)
		return 0;

	nsz = strlen(name);
	osz = *optstr ? strlen(*optstr) : 0;
	vsz = value ? strlen(value) : 0;

	ul_buffer_refer_string(&buf, *optstr);
	ul_buffer_set_chunksize(&buf, osz + nsz + vsz + 3);	

	rc = __buffer_append_option(&buf, name, nsz, value, vsz);

	*optstr = ul_buffer_get_data(&buf, NULL, NULL);
	return rc;
}

int mnt_optstr_prepend_option(char **optstr, const char *name, const char *value)
{
	struct ul_buffer buf = UL_INIT_BUFFER;
	size_t nsz, vsz, osz;
	int rc;

	if (!optstr)
		return -EINVAL;
	if (!name || !*name)
		return 0;

	nsz = strlen(name);
	osz = *optstr ? strlen(*optstr) : 0;
	vsz = value ? strlen(value) : 0;

	ul_buffer_set_chunksize(&buf, osz + nsz + vsz + 3);   

	rc = __buffer_append_option(&buf, name, nsz, value, vsz);
	if (*optstr && !rc) {
		rc = ul_buffer_append_data(&buf, ",", 1);
		if (!rc)
			rc = ul_buffer_append_data(&buf, *optstr, osz);
		free(*optstr);
	}

	*optstr = ul_buffer_get_data(&buf, NULL, NULL);
	return rc;
}


int mnt_optstr_get_option(const char *optstr, const char *name, char **value, size_t *valsz)
{
	struct libmnt_optloc ol = MNT_INIT_OPTLOC;
	int rc;

	if (!optstr || !name)
		return -EINVAL;

	rc = mnt_optstr_locate_option((char *) optstr, name, &ol);
	if (!rc) {
		if (value)
			*value = ol.value;
		if (valsz)
			*valsz = ol.valsz;
	}
	return rc;
}


int mnt_optstr_deduplicate_option(char **optstr, const char *name)
{
	int rc;
	char *begin = NULL, *end = NULL, *opt;

	if (!optstr || !name)
		return -EINVAL;

	opt = *optstr;
	do {
		struct libmnt_optloc ol = MNT_INIT_OPTLOC;

		rc = mnt_optstr_locate_option(opt, name, &ol);
		if (!rc) {
			if (begin) {
				
				size_t shift = strlen(*optstr);

				mnt_optstr_remove_option_at(optstr, begin, end);

				
				shift -= strlen(*optstr);
				ol.begin -= shift;
				ol.end -= shift;
			}
			begin = ol.begin;
			end = ol.end;
			opt = end && *end ? end + 1 : NULL;
		}
		if (opt == NULL)
			break;
	} while (rc == 0 && *opt);

	return rc < 0 ? rc : begin ? 0 : 1;
}


int mnt_optstr_remove_option_at(char **optstr, char *begin, char *end)
{
	size_t sz;

	if (!optstr || !begin || !end)
		return -EINVAL;

	if ((begin == *optstr || *(begin - 1) == ',') && *end == ',')
		end++;

	sz = strlen(end);

	memmove(begin, end, sz + 1);
	if (!*begin && (begin > *optstr) && *(begin - 1) == ',')
		*(begin - 1) = '\0';

	return 0;
}


static int __attribute__((nonnull(1,2,3)))
insert_value(char **str, char *pos, const char *substr, char **next)
{
	size_t subsz = strlen(substr);			
	size_t strsz = strlen(*str);
	size_t possz = strlen(pos);
	size_t posoff;
	char *p;
	int sep;

	
	sep = !(pos > *str && *(pos - 1) == '=');

	
	posoff = pos - *str;

	p = realloc(*str, strsz + sep + subsz + 1);
	if (!p)
		return -ENOMEM;

	
	memset(p + strsz, 0, sep + subsz + 1);

	
	*str = p;
	pos = p + posoff;

	if (possz)
		
		memmove(pos + subsz + sep, pos, possz + 1);
	if (sep)
		*pos++ = '=';

	memcpy(pos, substr, subsz);

	if (next) {
		
		*next = pos + subsz;
		if (**next == ',')
			(*next)++;
	}
	return 0;
}


int mnt_optstr_set_option(char **optstr, const char *name, const char *value)
{
	struct libmnt_optloc ol = MNT_INIT_OPTLOC;
	char *nameend;
	int rc = 1;

	if (!optstr || !name)
		return -EINVAL;

	if (*optstr)
		rc = mnt_optstr_locate_option(*optstr, name, &ol);
	if (rc < 0)
		return rc;			
	if (rc == 1)
		return mnt_optstr_append_option(optstr, name, value);	

	nameend = ol.begin + ol.namesz;

	if (value == NULL && ol.value && ol.valsz)
		
		mnt_optstr_remove_option_at(optstr, nameend, ol.end);

	else if (value && ol.value == NULL)
		
		rc = insert_value(optstr, nameend, value, NULL);

	else if (value && ol.value && strlen(value) == ol.valsz)
		
		memcpy(ol.value, value, ol.valsz);

	else if (value && ol.value) {
		mnt_optstr_remove_option_at(optstr, nameend, ol.end);
		rc = insert_value(optstr, nameend, value, NULL);
	}
	return rc;
}


int mnt_optstr_remove_option(char **optstr, const char *name)
{
	struct libmnt_optloc ol = MNT_INIT_OPTLOC;
	int rc;

	if (!optstr || !name)
		return -EINVAL;

	rc = mnt_optstr_locate_option(*optstr, name, &ol);
	if (rc != 0)
		return rc;

	mnt_optstr_remove_option_at(optstr, ol.begin, ol.end);
	return 0;
}


int mnt_split_optstr(const char *optstr, char **user, char **vfs, char **fs, int ignore_user, int ignore_vfs)
{
	int rc = 0;
	char *name, *val, *str = (char *) optstr;
	size_t namesz, valsz, chunsz;
	struct libmnt_optmap const *maps[2];
	struct ul_buffer xvfs = UL_INIT_BUFFER, xfs = UL_INIT_BUFFER, xuser = UL_INIT_BUFFER;


	if (!optstr)
		return -EINVAL;

	maps[0] = mnt_get_builtin_optmap(MNT_LINUX_MAP);
	maps[1] = mnt_get_builtin_optmap(MNT_USERSPACE_MAP);

	chunsz = strlen(optstr) / 2;

	while (!mnt_optstr_next_option(&str, &name, &namesz, &val, &valsz)) {
		struct ul_buffer *buf = NULL;
		const struct libmnt_optmap *ent = NULL;
		const struct libmnt_optmap *m = mnt_optmap_get_entry(maps, 2, name, namesz, &ent);

		if (ent && !ent->id)
			continue;	

		
		if (valsz && mnt_optmap_entry_novalue(ent))
			m = NULL;

		if (ent && m && m == maps[0] && vfs) {
			if (ignore_vfs && (ent->mask & ignore_vfs))
				continue;
			if (vfs)
				buf = &xvfs;
		} else if (ent && m && m == maps[1] && user) {
			if (ignore_user && (ent->mask & ignore_user))
				continue;
			if (user)
				buf = &xuser;
		} else if (!m && fs) {
			if (fs)
				buf = &xfs;
		}

		if (buf) {
			if (ul_buffer_is_empty(buf))
				ul_buffer_set_chunksize(buf, chunsz);
			rc = __buffer_append_option(buf, name, namesz, val, valsz);
		}
		if (rc)
			break;
	}

	if (vfs)
		*vfs  = rc ? NULL : ul_buffer_get_data(&xvfs, NULL, NULL);
	if (fs)
		*fs   = rc ? NULL : ul_buffer_get_data(&xfs, NULL, NULL);
	if (user)
		*user = rc ? NULL : ul_buffer_get_data(&xuser, NULL, NULL);
	if (rc) {
		ul_buffer_free_data(&xvfs);
		ul_buffer_free_data(&xfs);
		ul_buffer_free_data(&xuser);
	}

	return rc;
}


int mnt_optstr_get_options(const char *optstr, char **subset, const struct libmnt_optmap *map, int ignore)
{
	struct libmnt_optmap const *maps[1];
	struct ul_buffer buf = UL_INIT_BUFFER;
	char *name, *val, *str = (char *) optstr;
	size_t namesz, valsz;
	int rc = 0;

	if (!optstr || !subset)
		return -EINVAL;

	maps[0] = map;

	ul_buffer_set_chunksize(&buf, strlen(optstr)/2);

	while (!mnt_optstr_next_option(&str, &name, &namesz, &val, &valsz)) {
		const struct libmnt_optmap *ent;

		mnt_optmap_get_entry(maps, 1, name, namesz, &ent);

		if (!ent || !ent->id)
			continue;	

		if (ignore && (ent->mask & ignore))
			continue;

		
		if (valsz && mnt_optmap_entry_novalue(ent))
			continue;

		rc = __buffer_append_option(&buf, name, namesz, val, valsz);
		if (rc)
			break;
	}

	*subset  = rc ? NULL : ul_buffer_get_data(&buf, NULL, NULL);
	if (rc)
		ul_buffer_free_data(&buf);
	return rc;
}



int mnt_optstr_get_flags(const char *optstr, unsigned long *flags, const struct libmnt_optmap *map)
{
	struct libmnt_optmap const *maps[2];
	char *name, *str = (char *) optstr;
	size_t namesz = 0, valsz = 0;
	int nmaps = 0;

	if (!optstr || !flags || !map)
		return -EINVAL;

	maps[nmaps++] = map;

	if (map == mnt_get_builtin_optmap(MNT_LINUX_MAP))
		
		maps[nmaps++] = mnt_get_builtin_optmap(MNT_USERSPACE_MAP);

	while(!mnt_optstr_next_option(&str, &name, &namesz, NULL, &valsz)) {
		const struct libmnt_optmap *ent;
		const struct libmnt_optmap *m;

		m = mnt_optmap_get_entry(maps, nmaps, name, namesz, &ent);
		if (!m || !ent || !ent->id)
			continue;

		
		if (valsz && mnt_optmap_entry_novalue(ent))
			continue;

		if (m == map) {				
			if (ent->mask & MNT_INVERT)
				*flags &= ~ent->id;
			else *flags |= ent->id;

		} else if (nmaps == 2 && m == maps[1] && valsz == 0) {
			
			if (ent->mask & MNT_INVERT)
				continue;
			if (ent->id & (MNT_MS_OWNER | MNT_MS_GROUP))
				*flags |= MS_OWNERSECURE;
			else if (ent->id & (MNT_MS_USER | MNT_MS_USERS))
				*flags |= MS_SECURE;
		}
	}

	return 0;
}


int mnt_optstr_apply_flags(char **optstr, unsigned long flags, const struct libmnt_optmap *map)
{
	struct libmnt_optmap const *maps[1];
	char *name, *next, *val;
	size_t namesz = 0, valsz = 0, multi = 0;
	unsigned long fl;
	int rc = 0;

	if (!optstr || !map)
		return -EINVAL;

	DBG(CXT, ul_debug("applying 0x%08lx flags to '%s'", flags, *optstr));

	maps[0] = map;
	next = *optstr;
	fl = flags;

	
	if (map == mnt_get_builtin_optmap(MNT_LINUX_MAP)) {
		const char *o = (fl & MS_RDONLY) ? "ro" : "rw";

		if (next && (!strncmp(next, "rw", 2) || !strncmp(next, "ro", 2)) && (*(next + 2) == '\0' || *(next + 2) == ',')) {


			
			memcpy(next, o, 2);
		} else {
			rc = mnt_optstr_prepend_option(optstr, o, NULL);
			if (rc)
				goto err;
			next = *optstr;		
		}
		fl &= ~MS_RDONLY;
		next += 2;
		if (*next == ',')
			next++;
	}

	if (next && *next) {
		
		while(!mnt_optstr_next_option(&next, &name, &namesz, &val, &valsz)) {
			const struct libmnt_optmap *ent;

			if (mnt_optmap_get_entry(maps, 1, name, namesz, &ent)) {
				
				if (!ent || !ent->id)
					continue;
				
				if (valsz && mnt_optmap_entry_novalue(ent))
					continue;

				if (ent->id == MS_RDONLY || (ent->mask & MNT_INVERT) || (fl & ent->id) != (unsigned long) ent->id) {


					char *end = val ? val + valsz :
							  name + namesz;
					next = name;
					rc = mnt_optstr_remove_option_at( optstr, name, end);
					if (rc)
						goto err;
				}
				if (!(ent->mask & MNT_INVERT)) {
					
					if (ent->mask & MNT_PREFIX)
						multi |= ent->id;
					else fl &= ~ent->id;
					if (ent->id & MS_REC)
						fl |= MS_REC;
				}
			}
		}
	}

	
	fl &= ~multi;

	
	if (fl && fl != MS_REC) {

		const struct libmnt_optmap *ent;
		struct ul_buffer buf = UL_INIT_BUFFER;
		size_t sz;
		char *p;

		ul_buffer_refer_string(&buf, *optstr);

		for (ent = map; ent && ent->name; ent++) {
			if ((ent->mask & MNT_INVERT)
			    || ent->id == 0 || (fl & ent->id) != (unsigned long) ent->id)
				continue;

			
			p = strchr(ent->name, '=');
			if (p) {
				if (p > ent->name && *(p - 1) == '[')
					p--;			
				else continue;
				sz = p - ent->name;
			} else sz = strlen(ent->name);

			rc = __buffer_append_option(&buf, ent->name, sz, NULL, 0);
			if (rc)
				goto err;
		}

		*optstr = ul_buffer_get_data(&buf, NULL, NULL);
	}

	DBG(CXT, ul_debug("new optstr '%s'", *optstr));
	return rc;
err:
	DBG(CXT, ul_debug("failed to apply flags [rc=%d]", rc));
	return rc;
}



int mnt_optstr_fix_secontext(char **optstr __attribute__ ((__unused__)), char *value   __attribute__ ((__unused__)), size_t valsz  __attribute__ ((__unused__)), char **next   __attribute__ ((__unused__)))


{
	return 0;
}

int mnt_optstr_fix_secontext(char **optstr, char *value, size_t valsz, char **next)


{
	int rc = 0;
	char *p, *val, *begin, *end, *raw = NULL;
	size_t sz;

	if (!optstr || !*optstr || !value || !valsz)
		return -EINVAL;

	DBG(CXT, ul_debug("fixing SELinux context"));

	begin = value;
	end = value + valsz;

	
	if (*value == '"') {
		if (valsz <= 2 || *(value + valsz - 1) != '"')
			return -EINVAL;		
		value++;
		valsz -= 2;
	}

	p = strndup(value, valsz);
	if (!p)
		return -ENOMEM;


	
	rc = selinux_trans_to_raw_context(p, &raw);

	DBG(CXT, ul_debug("SELinux context '%s' translated to '%s'", p, rc == -1 ? "FAILED" : (char *) raw));

	free(p);
	if (rc == -1 ||	!raw)
		return -EINVAL;


	
	sz = strlen((char *) raw);
	if (!sz)
		return -EINVAL;

	p = val = malloc(valsz + 3);
	if (!val)
		return -ENOMEM;

	*p++ = '"';
	memcpy(p, raw, sz);
	p += sz;
	*p++ = '"';
	*p = '\0';

	freecon(raw);

	
	mnt_optstr_remove_option_at(optstr, begin, end);
	rc = insert_value(optstr, begin, val, next);
	free(val);

	return rc;
}


static int set_uint_value(char **optstr, unsigned int num, char *begin, char *end, char **next)
{
	char buf[40];
	snprintf(buf, sizeof(buf), "%u", num);

	mnt_optstr_remove_option_at(optstr, begin, end);
	return insert_value(optstr, begin, buf, next);
}


int mnt_optstr_fix_uid(char **optstr, char *value, size_t valsz, char **next)
{
	char *end;

	if (!optstr || !*optstr || !value || !valsz)
		return -EINVAL;

	DBG(CXT, ul_debug("fixing uid"));

	end = value + valsz;

	if (valsz == 7 && !strncmp(value, "useruid", 7) && (*(value + 7) == ',' || !*(value + 7)))
		return set_uint_value(optstr, getuid(), value, end, next);

	if (!isdigit(*value)) {
		uid_t id;
		int rc;
		char *p = strndup(value, valsz);
		if (!p)
			return -ENOMEM;
		rc = mnt_get_uid(p, &id);
		free(p);

		if (!rc)
			return set_uint_value(optstr, id, value, end, next);
	}

	if (next) {
		
		*next = value + valsz;
		if (**next == ',')
			(*next)++;
	}

	return 0;
}


int mnt_optstr_fix_gid(char **optstr, char *value, size_t valsz, char **next)
{
	char *end;

	if (!optstr || !*optstr || !value || !valsz)
		return -EINVAL;

	DBG(CXT, ul_debug("fixing gid"));

	end = value + valsz;

	if (valsz == 7 && !strncmp(value, "usergid", 7) && (*(value + 7) == ',' || !*(value + 7)))
		return set_uint_value(optstr, getgid(), value, end, next);

	if (!isdigit(*value)) {
		int rc;
		gid_t id;
		char *p = strndup(value, valsz);
		if (!p)
			return -ENOMEM;
		rc = mnt_get_gid(p, &id);
		free(p);

		if (!rc)
			return set_uint_value(optstr, id, value, end, next);

	}

	if (next) {
		
		*next = value + valsz;
		if (**next == ',')
			(*next)++;
	}
	return 0;
}


int mnt_optstr_fix_user(char **optstr)
{
	char *username;
	struct libmnt_optloc ol = MNT_INIT_OPTLOC;
	int rc = 0;

	DBG(CXT, ul_debug("fixing user"));

	rc = mnt_optstr_locate_option(*optstr, "user", &ol);
	if (rc)
		return rc == 1 ? 0 : rc;	

	username = mnt_get_username(getuid());
	if (!username)
		return -ENOMEM;

	if (!ol.valsz || (ol.value && strncmp(ol.value, username, ol.valsz) != 0)) {
		if (ol.valsz)
			
			mnt_optstr_remove_option_at(optstr, ol.value, ol.end);

		rc = insert_value(optstr, ol.value ? ol.value : ol.end, username, NULL);
	}

	free(username);
	return rc;
}


int mnt_match_options(const char *optstr, const char *pattern)
{
	char *name, *pat = (char *) pattern;
	char *buf, *patval;
	size_t namesz = 0, patvalsz = 0;
	int match = 1;

	if (!pattern && !optstr)
		return 1;
	if (!pattern)
		return 0;

	buf = malloc(strlen(pattern) + 1);
	if (!buf)
		return 0;

	
	while (match && !mnt_optstr_next_option(&pat, &name, &namesz, &patval, &patvalsz)) {
		char *val;
		size_t sz;
		int no = 0, rc;

		if (*name == '+')
			name++, namesz--;
		else if ((no = (startswith(name, "no") != NULL)))
			name += 2, namesz -= 2;

		xstrncpy(buf, name, namesz + 1);

		rc = mnt_optstr_get_option(optstr, buf, &val, &sz);

		
		if (rc == 0 && patvalsz > 0 && (patvalsz != sz || strncmp(patval, val, sz) != 0))
			rc = 1;

		switch (rc) {
		case 0:		
			match = no == 0 ? 1 : 0;
			break;
		case 1:		
			match = no == 1 ? 1 : 0;
			break;
		default:	
			match = 0;
			break;
		}

	}

	free(buf);
	return match;
}




static int test_append(struct libmnt_test *ts, int argc, char *argv[])
{
	const char *value = NULL, *name;
	char *optstr;
	int rc;

	if (argc < 3)
		return -EINVAL;
	optstr = xstrdup(argv[1]);
	name = argv[2];

	if (argc == 4)
		value = argv[3];

	rc = mnt_optstr_append_option(&optstr, name, value);
	if (!rc)
		printf("result: >%s<\n", optstr);
	free(optstr);
	return rc;
}

static int test_prepend(struct libmnt_test *ts, int argc, char *argv[])
{
	const char *value = NULL, *name;
	char *optstr;
	int rc;

	if (argc < 3)
		return -EINVAL;
	optstr = xstrdup(argv[1]);
	name = argv[2];

	if (argc == 4)
		value = argv[3];

	rc = mnt_optstr_prepend_option(&optstr, name, value);
	if (!rc)
		printf("result: >%s<\n", optstr);
	free(optstr);
	return rc;
}

static int test_split(struct libmnt_test *ts, int argc, char *argv[])
{
	char *optstr, *user = NULL, *fs = NULL, *vfs = NULL;
	int rc;

	if (argc < 2)
		return -EINVAL;

	optstr = xstrdup(argv[1]);

	rc = mnt_split_optstr(optstr, &user, &vfs, &fs, 0, 0);
	if (!rc) {
		printf("user : %s\n", user);
		printf("vfs  : %s\n", vfs);
		printf("fs   : %s\n", fs);
	}

	free(user);
	free(vfs);
	free(fs);
	free(optstr);
	return rc;
}

static int test_flags(struct libmnt_test *ts, int argc, char *argv[])
{
	char *optstr;
	int rc;
	unsigned long fl = 0;

	if (argc < 2)
		return -EINVAL;

	optstr = xstrdup(argv[1]);

	rc = mnt_optstr_get_flags(optstr, &fl, mnt_get_builtin_optmap(MNT_LINUX_MAP));
	if (rc)
		return rc;
	printf("mountflags:           0x%08lx\n", fl);

	fl = 0;
	rc = mnt_optstr_get_flags(optstr, &fl, mnt_get_builtin_optmap(MNT_USERSPACE_MAP));
	if (rc)
		return rc;
	printf("userspace-mountflags: 0x%08lx\n", fl);

	free(optstr);
	return rc;
}

static int test_apply(struct libmnt_test *ts, int argc, char *argv[])
{
	char *optstr;
	int rc, map;
	unsigned long flags;

	if (argc < 4)
		return -EINVAL;

	if (!strcmp(argv[1], "--user"))
		map = MNT_USERSPACE_MAP;
	else if (!strcmp(argv[1], "--linux"))
		map = MNT_LINUX_MAP;
	else {
		fprintf(stderr, "unknown option '%s'\n", argv[1]);
		return -EINVAL;
	}

	optstr = xstrdup(argv[2]);
	flags = strtoul(argv[3], NULL, 16);

	printf("flags:  0x%08lx\n", flags);

	rc = mnt_optstr_apply_flags(&optstr, flags, mnt_get_builtin_optmap(map));
	printf("optstr: %s\n", optstr);

	free(optstr);
	return rc;
}

static int test_set(struct libmnt_test *ts, int argc, char *argv[])
{
	const char *value = NULL, *name;
	char *optstr;
	int rc;

	if (argc < 3)
		return -EINVAL;
	optstr = xstrdup(argv[1]);
	name = argv[2];

	if (argc == 4)
		value = argv[3];

	rc = mnt_optstr_set_option(&optstr, name, value);
	if (!rc)
		printf("result: >%s<\n", optstr);
	free(optstr);
	return rc;
}

static int test_get(struct libmnt_test *ts, int argc, char *argv[])
{
	char *optstr;
	const char *name;
	char *val = NULL;
	size_t sz = 0;
	int rc;

	if (argc < 2)
		return -EINVAL;
	optstr = argv[1];
	name = argv[2];

	rc = mnt_optstr_get_option(optstr, name, &val, &sz);
	if (rc == 0) {
		printf("found; name: %s", name);
		if (sz) {
			printf(", argument: size=%zd data=", sz);
			if (fwrite(val, 1, sz, stdout) != sz)
				return -1;
		}
		printf("\n");
	} else if (rc == 1)
		printf("%s: not found\n", name);
	else printf("parse error: %s\n", optstr);
	return rc;
}

static int test_remove(struct libmnt_test *ts, int argc, char *argv[])
{
	const char *name;
	char *optstr;
	int rc;

	if (argc < 3)
		return -EINVAL;
	optstr = xstrdup(argv[1]);
	name = argv[2];

	rc = mnt_optstr_remove_option(&optstr, name);
	if (!rc)
		printf("result: >%s<\n", optstr);
	free(optstr);
	return rc;
}

static int test_dedup(struct libmnt_test *ts, int argc, char *argv[])
{
	const char *name;
	char *optstr;
	int rc;

	if (argc < 3)
		return -EINVAL;
	optstr = xstrdup(argv[1]);
	name = argv[2];

	rc = mnt_optstr_deduplicate_option(&optstr, name);
	if (!rc)
		printf("result: >%s<\n", optstr);
	free(optstr);
	return rc;
}

static int test_fix(struct libmnt_test *ts, int argc, char *argv[])
{
	char *optstr;
	int rc = 0;
	char *name, *val, *next;
	size_t valsz, namesz;

	if (argc < 2)
		return -EINVAL;

	next = optstr = xstrdup(argv[1]);

	printf("optstr: %s\n", optstr);

	while (!mnt_optstr_next_option(&next, &name, &namesz, &val, &valsz)) {

		if (!strncmp(name, "uid", 3))
			rc = mnt_optstr_fix_uid(&optstr, val, valsz, &next);
		else if (!strncmp(name, "gid", 3))
			rc = mnt_optstr_fix_gid(&optstr, val, valsz, &next);
		else if (!strncmp(name, "context", 7))
			rc = mnt_optstr_fix_secontext(&optstr, val, valsz, &next);
		if (rc)
			break;
	}
	if (rc)
		rc = mnt_optstr_fix_user(&optstr);

	printf("fixed:  %s\n", optstr);

	free(optstr);
	return rc;

}

int main(int argc, char *argv[])
{
	struct libmnt_test tss[] = {
		{ "--append", test_append, "<optstr> <name> [<value>]  append value to optstr" }, { "--prepend",test_prepend,"<optstr> <name> [<value>]  prepend value to optstr" }, { "--set",    test_set,    "<optstr> <name> [<value>]  (un)set value" }, { "--get",    test_get,    "<optstr> <name>            search name in optstr" }, { "--remove", test_remove, "<optstr> <name>            remove name in optstr" }, { "--dedup",  test_dedup,  "<optstr> <name>            deduplicate name in optstr" }, { "--split",  test_split,  "<optstr>                   split into FS, VFS and userspace" }, { "--flags",  test_flags,  "<optstr>                   convert options to MS_* flags" }, { "--apply",  test_apply,  "--{linux,user} <optstr> <mask>    apply mask to optstr" }, { "--fix",    test_fix,    "<optstr>                   fix uid=, gid=, user, and context=" },  { NULL }










	};
	return  mnt_run_test(tss, argc, argv);
}
