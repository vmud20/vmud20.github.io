

















pg_encname	pg_encname_tbl[] = {
	{
		"abc", PG_WIN1258 }, {

		"alt", PG_WIN866 }, {

		"big5", PG_BIG5 }, {

		"euccn", PG_EUC_CN }, {

		"eucjp", PG_EUC_JP }, {

		"euckr", PG_EUC_KR }, {

		"euctw", PG_EUC_TW }, {

		"gb18030", PG_GB18030 }, {

		"gbk", PG_GBK }, {

		"iso88591", PG_LATIN1 }, {

		"iso885910", PG_LATIN6 }, {

		"iso885913", PG_LATIN7 }, {

		"iso885914", PG_LATIN8 }, {

		"iso885915", PG_LATIN9 }, {

		"iso885916", PG_LATIN10 }, {

		"iso88592", PG_LATIN2 }, {

		"iso88593", PG_LATIN3 }, {

		"iso88594", PG_LATIN4 }, {

		"iso88595", PG_ISO_8859_5 }, {

		"iso88596", PG_ISO_8859_6 }, {

		"iso88597", PG_ISO_8859_7 }, {

		"iso88598", PG_ISO_8859_8 }, {

		"iso88599", PG_LATIN5 }, {

		"johab", PG_JOHAB }, {

		"koi8", PG_KOI8R }, {

		"koi8r", PG_KOI8R }, {

		"latin1", PG_LATIN1 }, {

		"latin10", PG_LATIN10 }, {

		"latin2", PG_LATIN2 }, {

		"latin3", PG_LATIN3 }, {

		"latin4", PG_LATIN4 }, {

		"latin5", PG_LATIN5 }, {

		"latin6", PG_LATIN6 }, {

		"latin7", PG_LATIN7 }, {

		"latin8", PG_LATIN8 }, {

		"latin9", PG_LATIN9 }, {

		"mskanji", PG_SJIS }, {

		"muleinternal", PG_MULE_INTERNAL }, {

		"shiftjis", PG_SJIS }, {

		"sjis", PG_SJIS }, {

		"sqlascii", PG_SQL_ASCII }, {

		"tcvn", PG_WIN1258 }, {

		"tcvn5712", PG_WIN1258 }, {

		"uhc", PG_UHC }, {

		"unicode", PG_UTF8 }, {

		"utf8", PG_UTF8 }, {

		"vscii", PG_WIN1258 }, {

		"win", PG_WIN1251 }, {

		"win1250", PG_WIN1250 }, {

		"win1251", PG_WIN1251 }, {

		"win1252", PG_WIN1252 }, {

		"win1256", PG_WIN1256 }, {

		"win1258", PG_WIN1258 }, {

		"win866", PG_WIN866 }, {

		"win874", PG_WIN874 }, {

		"win932", PG_SJIS }, {

		"win936", PG_GBK }, {

		"win949", PG_UHC }, {

		"win950", PG_BIG5 }, {

		"windows1250", PG_WIN1250 }, {

		"windows1251", PG_WIN1251 }, {

		"windows1252", PG_WIN1252 }, {

		"windows1256", PG_WIN1256 }, {

		"windows1258", PG_WIN1258 }, {

		"windows866", PG_WIN866 }, {

		"windows874", PG_WIN874 }, {

		"windows932", PG_SJIS }, {

		"windows936", PG_GBK }, {

		"windows949", PG_UHC }, {

		"windows950", PG_BIG5 }, {

		NULL, 0 }
};

unsigned int pg_encname_tbl_sz =  sizeof(pg_encname_tbl) / sizeof(pg_encname_tbl[0]) - 1   pg_enc2name pg_enc2name_tbl[] = {



	{
		"SQL_ASCII", PG_SQL_ASCII }, {

		"EUC_JP", PG_EUC_JP }, {

		"EUC_CN", PG_EUC_CN }, {

		"EUC_KR", PG_EUC_KR }, {

		"EUC_TW", PG_EUC_TW }, {

		"JOHAB", PG_JOHAB }, {

		"UTF8", PG_UTF8 }, {

		"MULE_INTERNAL", PG_MULE_INTERNAL }, {

		"LATIN1", PG_LATIN1 }, {

		"LATIN2", PG_LATIN2 }, {

		"LATIN3", PG_LATIN3 }, {

		"LATIN4", PG_LATIN4 }, {

		"LATIN5", PG_LATIN5 }, {

		"LATIN6", PG_LATIN6 }, {

		"LATIN7", PG_LATIN7 }, {

		"LATIN8", PG_LATIN8 }, {

		"LATIN9", PG_LATIN9 }, {

		"LATIN10", PG_LATIN10 }, {

		"WIN1256", PG_WIN1256 }, {

		"WIN1258", PG_WIN1258 }, {

		"WIN866", PG_WIN866 }, {

		"WIN874", PG_WIN874 }, {

		"KOI8", PG_KOI8R }, {

		"WIN1251", PG_WIN1251 }, {

		"WIN1252", PG_WIN1252 }, {

		"ISO_8859_5", PG_ISO_8859_5 }, {

		"ISO_8859_6", PG_ISO_8859_6 }, {

		"ISO_8859_7", PG_ISO_8859_7 }, {

		"ISO_8859_8", PG_ISO_8859_8 }, {

		"WIN1250", PG_WIN1250 }, {

		"SJIS", PG_SJIS }, {

		"BIG5", PG_BIG5 }, {

		"GBK", PG_GBK }, {

		"UHC", PG_UHC }, {

		"GB18030", PG_GB18030 }
};


int pg_valid_client_encoding(const char *name)
{
	int			enc;

	if ((enc = pg_char_to_encoding(name)) < 0)
		return -1;

	if (!PG_VALID_FE_ENCODING(enc))
		return -1;

	return enc;
}

int pg_valid_server_encoding(const char *name)
{
	int			enc;

	if ((enc = pg_char_to_encoding(name)) < 0)
		return -1;

	if (!PG_VALID_BE_ENCODING(enc))
		return -1;

	return enc;
}


static char * clean_encoding_name(char *key, char *newkey)
{
	char	   *p, *np;

	for (p = key, np = newkey; *p != '\0'; p++)
	{
		if (isalnum((unsigned char) *p))
		{
			if (*p >= 'A' && *p <= 'Z')
				*np++ = *p + 'a' - 'A';
			else *np++ = *p;
		}
	}
	*np = '\0';
	return newkey;
}


pg_encname * pg_char_to_encname_struct(const char *name)
{
	unsigned int nel = pg_encname_tbl_sz;
	pg_encname *base = pg_encname_tbl, *last = base + nel - 1, *position;

	int			result;
	char		buff[NAMEDATALEN], *key;

	if (name == NULL || *name == '\0')
		return NULL;

	if (strlen(name) > NAMEDATALEN)
	{

		fprintf(stderr, "encoding name too long\n");
		return NULL;

		ereport(ERROR, (errcode(ERRCODE_NAME_TOO_LONG), errmsg("encoding name too long")));


	}
	key = clean_encoding_name((char *) name, buff);

	while (last >= base)
	{
		position = base + ((last - base) >> 1);
		result = key[0] - position->name[0];

		if (result == 0)
		{
			result = strcmp(key, position->name);
			if (result == 0)
				return position;
		}
		if (result < 0)
			last = position - 1;
		else base = position + 1;
	}
	return NULL;
}


int pg_char_to_encoding(const char *s)
{
	pg_encname *p = NULL;

	if (!s)
		return -1;

	p = pg_char_to_encname_struct(s);
	return p ? p->encoding : -1;
}


Datum PG_char_to_encoding(PG_FUNCTION_ARGS)
{
	Name		s = PG_GETARG_NAME(0);

	PG_RETURN_INT32(pg_char_to_encoding(NameStr(*s)));
}


const char * pg_encoding_to_char(int encoding)
{
	if (PG_VALID_ENCODING(encoding))
	{
		pg_enc2name *p = &pg_enc2name_tbl[encoding];

		Assert(encoding == p->encoding);
		return p->name;
	}
	return "";
}


Datum PG_encoding_to_char(PG_FUNCTION_ARGS)
{
	int32		encoding = PG_GETARG_INT32(0);
	const char *encoding_name = pg_encoding_to_char(encoding);

	return DirectFunctionCall1(namein, CStringGetDatum(encoding_name));
}


