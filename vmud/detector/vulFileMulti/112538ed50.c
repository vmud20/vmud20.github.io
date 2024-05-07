











int			day_tab[2][13] = {
	{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 0}, {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 0}};

typedef long AbsoluteTime;








static datetkn datetktbl[] = {

	{EARLY, RESERV, DTK_EARLY},  {"acsst", DTZ, POS(42)}, {"acst", DTZ, NEG(16)}, {"act", TZ, NEG(20)}, {DA_D, ADBC, AD}, {"adt", DTZ, NEG(12)}, {"aesst", DTZ, POS(44)}, {"aest", TZ, POS(40)}, {"aft", TZ, POS(18)}, {"ahst", TZ, NEG(40)}, {"akdt", DTZ, NEG(32)}, {"akst", DTZ, NEG(36)}, {"allballs", RESERV, DTK_ZULU}, {"almst", TZ, POS(28)}, {"almt", TZ, POS(24)}, {"am", AMPM, AM}, {"amst", DTZ, POS(20)},  {"amst", DTZ, NEG(12)},  {"amt", TZ, POS(16)}, {"anast", DTZ, POS(52)}, {"anat", TZ, POS(48)}, {"apr", MONTH, 4}, {"april", MONTH, 4},  aqtst aqtt arst  {"art", TZ, NEG(12)},  ashst ast  {"ast", TZ, NEG(16)}, {"at", IGNORE_DTF, 0}, {"aug", MONTH, 8}, {"august", MONTH, 8}, {"awsst", DTZ, POS(36)}, {"awst", TZ, POS(32)}, {"awt", DTZ, NEG(12)}, {"azost", DTZ, POS(0)}, {"azot", TZ, NEG(4)}, {"azst", DTZ, POS(20)}, {"azt", TZ, POS(16)}, {DB_C, ADBC, BC}, {"bdst", TZ, POS(8)}, {"bdt", TZ, POS(24)}, {"bnt", TZ, POS(32)}, {"bort", TZ, POS(32)},  bortst bost  {"bot", TZ, NEG(16)}, {"bra", TZ, NEG(12)},  brst brt  {"bst", DTZ, POS(4)},  {"bst", TZ, NEG(12)}, {"bst", DTZ, NEG(44)},  {"bt", TZ, POS(12)}, {"btt", TZ, POS(24)}, {"cadt", DTZ, POS(42)}, {"cast", TZ, POS(38)}, {"cat", TZ, NEG(40)}, {"cct", TZ, POS(32)},  {"cct", TZ, POS(26)},  {"cdt", DTZ, NEG(20)}, {"cest", DTZ, POS(8)}, {"cet", TZ, POS(4)}, {"cetdst", DTZ, POS(8)}, {"chadt", DTZ, POS(55)}, {"chast", TZ, POS(51)},  ckhst  {"ckt", TZ, POS(48)}, {"clst", DTZ, NEG(12)}, {"clt", TZ, NEG(16)},  cost  {"cot", TZ, NEG(20)}, {"cst", TZ, NEG(24)}, {DCURRENT, RESERV, DTK_CURRENT},  cvst  {"cvt", TZ, POS(28)}, {"cxt", TZ, POS(28)}, {"d", UNITS, DTK_DAY}, {"davt", TZ, POS(28)}, {"ddut", TZ, POS(40)}, {"dec", MONTH, 12}, {"december", MONTH, 12}, {"dnt", TZ, POS(4)}, {"dow", RESERV, DTK_DOW}, {"doy", RESERV, DTK_DOY}, {"dst", DTZMOD, 6},  {"dusst", DTZ, POS(24)},  {"easst", DTZ, NEG(20)}, {"east", TZ, NEG(24)}, {"eat", TZ, POS(12)},  {"east", DTZ, POS(16)}, {"eat", TZ, POS(12)}, {"ect", TZ, NEG(16)}, {"ect", TZ, NEG(20)},  {"edt", DTZ, NEG(16)}, {"eest", DTZ, POS(12)}, {"eet", TZ, POS(8)}, {"eetdst", DTZ, POS(12)}, {"egst", DTZ, POS(0)}, {"egt", TZ, NEG(4)},  ehdt  {EPOCH, RESERV, DTK_EPOCH}, {"est", TZ, NEG(20)}, {"feb", MONTH, 2}, {"february", MONTH, 2}, {"fjst", DTZ, NEG(52)}, {"fjt", TZ, NEG(48)}, {"fkst", DTZ, NEG(12)}, {"fkt", TZ, NEG(8)},  fnst fnt  {"fri", DOW, 5}, {"friday", DOW, 5}, {"fst", TZ, POS(4)}, {"fwt", DTZ, POS(8)}, {"galt", TZ, NEG(24)}, {"gamt", TZ, NEG(36)}, {"gest", DTZ, POS(20)}, {"get", TZ, POS(16)}, {"gft", TZ, NEG(12)},  ghst  {"gilt", TZ, POS(48)}, {"gmt", TZ, POS(0)}, {"gst", TZ, POS(40)}, {"gyt", TZ, NEG(16)}, {"h", UNITS, DTK_HOUR},  hadt hast  {"hdt", DTZ, NEG(36)},  hkst  {"hkt", TZ, POS(32)},  {"hmt", TZ, POS(12)}, hovst hovt  {"hst", TZ, NEG(40)},  hwt  {"ict", TZ, POS(28)}, {"idle", TZ, POS(48)}, {"idlw", TZ, NEG(48)},  idt  {LATE, RESERV, DTK_LATE}, {INVALID, RESERV, DTK_INVALID}, {"iot", TZ, POS(20)}, {"irkst", DTZ, POS(36)}, {"irkt", TZ, POS(32)}, {"irt", TZ, POS(14)}, {"isodow", RESERV, DTK_ISODOW},  isst  {"ist", TZ, POS(8)}, {"it", TZ, POS(14)}, {"j", UNITS, DTK_JULIAN}, {"jan", MONTH, 1}, {"january", MONTH, 1}, {"javt", TZ, POS(28)}, {"jayt", TZ, POS(36)}, {"jd", UNITS, DTK_JULIAN}, {"jst", TZ, POS(36)}, {"jt", TZ, POS(30)}, {"jul", MONTH, 7}, {"julian", UNITS, DTK_JULIAN}, {"july", MONTH, 7}, {"jun", MONTH, 6}, {"june", MONTH, 6}, {"kdt", DTZ, POS(40)}, {"kgst", DTZ, POS(24)}, {"kgt", TZ, POS(20)}, {"kost", TZ, POS(48)}, {"krast", DTZ, POS(28)}, {"krat", TZ, POS(32)}, {"kst", TZ, POS(36)}, {"lhdt", DTZ, POS(44)}, {"lhst", TZ, POS(42)}, {"ligt", TZ, POS(40)}, {"lint", TZ, POS(56)}, {"lkt", TZ, POS(24)}, {"m", UNITS, DTK_MONTH}, {"magst", DTZ, POS(48)}, {"magt", TZ, POS(44)}, {"mar", MONTH, 3}, {"march", MONTH, 3}, {"mart", TZ, NEG(38)}, {"mawt", TZ, POS(24)}, {"may", MONTH, 5}, {"mdt", DTZ, NEG(24)}, {"mest", DTZ, POS(8)}, {"met", TZ, POS(4)}, {"metdst", DTZ, POS(8)}, {"mewt", TZ, POS(4)}, {"mez", TZ, POS(4)}, {"mht", TZ, POS(48)}, {"mm", UNITS, DTK_MINUTE}, {"mmt", TZ, POS(26)}, {"mon", DOW, 1}, {"monday", DOW, 1},  most  {"mpt", TZ, POS(40)}, {"msd", DTZ, POS(16)}, {"msk", TZ, POS(12)}, {"mst", TZ, NEG(28)}, {"mt", TZ, POS(34)}, {"mut", TZ, POS(16)}, {"mvt", TZ, POS(20)}, {"myt", TZ, POS(32)},  ncst  {"nct", TZ, POS(44)}, {"ndt", DTZ, NEG(10)}, {"nft", TZ, NEG(14)}, {"nor", TZ, POS(4)}, {"nov", MONTH, 11}, {"november", MONTH, 11}, {"novst", DTZ, POS(28)}, {"novt", TZ, POS(24)}, {NOW, RESERV, DTK_NOW}, {"npt", TZ, POS(23)}, {"nst", TZ, NEG(14)}, {"nt", TZ, NEG(44)}, {"nut", TZ, NEG(44)}, {"nzdt", DTZ, POS(52)}, {"nzst", TZ, POS(48)}, {"nzt", TZ, POS(48)}, {"oct", MONTH, 10}, {"october", MONTH, 10}, {"omsst", DTZ, POS(28)}, {"omst", TZ, POS(24)}, {"on", IGNORE_DTF, 0}, {"pdt", DTZ, NEG(28)},  pest  {"pet", TZ, NEG(20)}, {"petst", DTZ, POS(52)}, {"pett", TZ, POS(48)}, {"pgt", TZ, POS(40)}, {"phot", TZ, POS(52)},  phst  {"pht", TZ, POS(32)}, {"pkt", TZ, POS(20)}, {"pm", AMPM, PM}, {"pmdt", DTZ, NEG(8)},  pmst  {"pont", TZ, POS(44)}, {"pst", TZ, NEG(32)}, {"pwt", TZ, POS(36)}, {"pyst", DTZ, NEG(12)}, {"pyt", TZ, NEG(16)}, {"ret", DTZ, POS(16)}, {"s", UNITS, DTK_SECOND}, {"sadt", DTZ, POS(42)},  samst samt  {"sast", TZ, POS(38)}, {"sat", DOW, 6}, {"saturday", DOW, 6},  sbt  {"sct", DTZ, POS(16)}, {"sep", MONTH, 9}, {"sept", MONTH, 9}, {"september", MONTH, 9}, {"set", TZ, NEG(4)},  sgt  {"sst", DTZ, POS(8)}, {"sun", DOW, 0}, {"sunday", DOW, 0}, {"swt", TZ, POS(4)},  syot  {"t", ISOTIME, DTK_TIME}, {"tft", TZ, POS(20)}, {"that", TZ, NEG(40)}, {"thu", DOW, 4}, {"thur", DOW, 4}, {"thurs", DOW, 4}, {"thursday", DOW, 4}, {"tjt", TZ, POS(20)}, {"tkt", TZ, NEG(40)}, {"tmt", TZ, POS(20)}, {TODAY, RESERV, DTK_TODAY}, {TOMORROW, RESERV, DTK_TOMORROW},  tost  {"tot", TZ, POS(52)},  tpt  {"truk", TZ, POS(40)}, {"tue", DOW, 2}, {"tues", DOW, 2}, {"tuesday", DOW, 2}, {"tvt", TZ, POS(48)},  uct  {"ulast", DTZ, POS(36)}, {"ulat", TZ, POS(32)}, {"undefined", RESERV, DTK_INVALID}, {"ut", TZ, POS(0)}, {"utc", TZ, POS(0)}, {"uyst", DTZ, NEG(8)}, {"uyt", TZ, NEG(12)}, {"uzst", DTZ, POS(24)}, {"uzt", TZ, POS(20)}, {"vet", TZ, NEG(16)}, {"vlast", DTZ, POS(44)}, {"vlat", TZ, POS(40)},  vust  {"vut", TZ, POS(44)}, {"wadt", DTZ, POS(32)}, {"wakt", TZ, POS(48)},  warst  {"wast", TZ, POS(28)}, {"wat", TZ, NEG(4)}, {"wdt", DTZ, POS(36)}, {"wed", DOW, 3}, {"wednesday", DOW, 3}, {"weds", DOW, 3}, {"west", DTZ, POS(4)}, {"wet", TZ, POS(0)}, {"wetdst", DTZ, POS(4)}, {"wft", TZ, POS(48)}, {"wgst", DTZ, NEG(8)}, {"wgt", TZ, NEG(12)}, {"wst", TZ, POS(32)}, {"y", UNITS, DTK_YEAR}, {"yakst", DTZ, POS(40)}, {"yakt", TZ, POS(36)}, {"yapt", TZ, POS(40)}, {"ydt", DTZ, NEG(32)}, {"yekst", DTZ, POS(24)}, {"yekt", TZ, POS(20)}, {YESTERDAY, RESERV, DTK_YESTERDAY}, {"yst", TZ, NEG(36)}, {"z", TZ, POS(0)}, {"zp4", TZ, NEG(16)}, {"zp5", TZ, NEG(20)}, {"zp6", TZ, NEG(24)}, {ZULU, TZ, POS(0)}, };















































































































































































































































































































































































































static datetkn deltatktbl[] = {
	
	{"@", IGNORE_DTF, 0},		 {DAGO, AGO, 0}, {"c", UNITS, DTK_CENTURY}, {"cent", UNITS, DTK_CENTURY}, {"centuries", UNITS, DTK_CENTURY}, {DCENTURY, UNITS, DTK_CENTURY}, {"d", UNITS, DTK_DAY}, {DDAY, UNITS, DTK_DAY}, {"days", UNITS, DTK_DAY}, {"dec", UNITS, DTK_DECADE}, {DDECADE, UNITS, DTK_DECADE}, {"decades", UNITS, DTK_DECADE}, {"decs", UNITS, DTK_DECADE}, {"h", UNITS, DTK_HOUR}, {DHOUR, UNITS, DTK_HOUR}, {"hours", UNITS, DTK_HOUR}, {"hr", UNITS, DTK_HOUR}, {"hrs", UNITS, DTK_HOUR}, {INVALID, RESERV, DTK_INVALID}, {"m", UNITS, DTK_MINUTE}, {"microsecon", UNITS, DTK_MICROSEC}, {"mil", UNITS, DTK_MILLENNIUM}, {"millennia", UNITS, DTK_MILLENNIUM}, {DMILLENNIUM, UNITS, DTK_MILLENNIUM}, {"millisecon", UNITS, DTK_MILLISEC}, {"mils", UNITS, DTK_MILLENNIUM}, {"min", UNITS, DTK_MINUTE}, {"mins", UNITS, DTK_MINUTE}, {DMINUTE, UNITS, DTK_MINUTE}, {"minutes", UNITS, DTK_MINUTE}, {"mon", UNITS, DTK_MONTH}, {"mons", UNITS, DTK_MONTH}, {DMONTH, UNITS, DTK_MONTH}, {"months", UNITS, DTK_MONTH}, {"ms", UNITS, DTK_MILLISEC}, {"msec", UNITS, DTK_MILLISEC}, {DMILLISEC, UNITS, DTK_MILLISEC}, {"mseconds", UNITS, DTK_MILLISEC}, {"msecs", UNITS, DTK_MILLISEC}, {"qtr", UNITS, DTK_QUARTER}, {DQUARTER, UNITS, DTK_QUARTER}, {"s", UNITS, DTK_SECOND}, {"sec", UNITS, DTK_SECOND}, {DSECOND, UNITS, DTK_SECOND}, {"seconds", UNITS, DTK_SECOND}, {"secs", UNITS, DTK_SECOND}, {DTIMEZONE, UNITS, DTK_TZ}, {"timezone_h", UNITS, DTK_TZ_HOUR}, {"timezone_m", UNITS, DTK_TZ_MINUTE}, {"undefined", RESERV, DTK_INVALID}, {"us", UNITS, DTK_MICROSEC}, {"usec", UNITS, DTK_MICROSEC}, {DMICROSEC, UNITS, DTK_MICROSEC}, {"useconds", UNITS, DTK_MICROSEC}, {"usecs", UNITS, DTK_MICROSEC}, {"w", UNITS, DTK_WEEK}, {DWEEK, UNITS, DTK_WEEK}, {"weeks", UNITS, DTK_WEEK}, {"y", UNITS, DTK_YEAR}, {DYEAR, UNITS, DTK_YEAR}, {"years", UNITS, DTK_YEAR}, {"yr", UNITS, DTK_YEAR}, {"yrs", UNITS, DTK_YEAR}, };































































static const unsigned int szdatetktbl = lengthof(datetktbl);
static const unsigned int szdeltatktbl = lengthof(deltatktbl);

static datetkn *datecache[MAXDATEFIELDS] = {NULL};

static datetkn *deltacache[MAXDATEFIELDS] = {NULL};

char	   *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", NULL};

char	   *days[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", NULL};

char	   *pgtypes_date_weekdays_short[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", NULL};

char	   *pgtypes_date_months[] = {"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December", NULL};

static datetkn * datebsearch(char *key, datetkn *base, unsigned int nel)
{
	if (nel > 0)
	{
		datetkn    *last = base + nel - 1, *position;
		int			result;

		while (last >= base)
		{
			position = base + ((last - base) >> 1);
			result = key[0] - position->token[0];
			if (result == 0)
			{
				result = strncmp(key, position->token, TOKMAXLEN);
				if (result == 0)
					return position;
			}
			if (result < 0)
				last = position - 1;
			else base = position + 1;
		}
	}
	return NULL;
}


int DecodeUnits(int field, char *lowtoken, int *val)
{
	int			type;
	datetkn    *tp;

	if (deltacache[field] != NULL && strncmp(lowtoken, deltacache[field]->token, TOKMAXLEN) == 0)
		tp = deltacache[field];
	else tp = datebsearch(lowtoken, deltatktbl, szdeltatktbl);
	deltacache[field] = tp;
	if (tp == NULL)
	{
		type = UNKNOWN_FIELD;
		*val = 0;
	}
	else {
		type = tp->type;
		if (type == TZ || type == DTZ)
			*val = FROMVAL(tp);
		else *val = tp->value;
	}

	return type;
}	



int date2j(int y, int m, int d)
{
	int			julian;
	int			century;

	if (m > 2)
	{
		m += 1;
		y += 4800;
	}
	else {
		m += 13;
		y += 4799;
	}

	century = y / 100;
	julian = y * 365 - 32167;
	julian += y / 4 - century + century / 4;
	julian += 7834 * m / 256 + d;

	return julian;
}	

void j2date(int jd, int *year, int *month, int *day)
{
	unsigned int julian;
	unsigned int quad;
	unsigned int extra;
	int			y;

	julian = jd;
	julian += 32044;
	quad = julian / 146097;
	extra = (julian - quad * 146097) * 4 + 3;
	julian += 60 + quad * 3 + extra / 146097;
	quad = julian / 1461;
	julian -= quad * 1461;
	y = julian * 4 / 1461;
	julian = ((y != 0) ? (julian + 305) % 365 : (julian + 306) % 366) + 123;
	y += quad * 4;
	*year = y - 4800;
	quad = julian * 2141 / 65536;
	*day = julian - 7834 * quad / 256;
	*month = (quad + 10) % 12 + 1;

	return;
}	


static int DecodeSpecial(int field, char *lowtoken, int *val)
{
	int			type;
	datetkn    *tp;

	if (datecache[field] != NULL && strncmp(lowtoken, datecache[field]->token, TOKMAXLEN) == 0)
		tp = datecache[field];
	else {
		tp = NULL;
		if (!tp)
			tp = datebsearch(lowtoken, datetktbl, szdatetktbl);
	}
	datecache[field] = tp;
	if (tp == NULL)
	{
		type = UNKNOWN_FIELD;
		*val = 0;
	}
	else {
		type = tp->type;
		switch (type)
		{
			case TZ:
			case DTZ:
			case DTZMOD:
				*val = FROMVAL(tp);
				break;

			default:
				*val = tp->value;
				break;
		}
	}

	return type;
}	


int EncodeDateOnly(struct tm * tm, int style, char *str, bool EuroDates)
{
	if (tm->tm_mon < 1 || tm->tm_mon > MONTHS_PER_YEAR)
		return -1;

	switch (style)
	{
		case USE_ISO_DATES:
			
			if (tm->tm_year > 0)
				sprintf(str, "%04d-%02d-%02d", tm->tm_year, tm->tm_mon, tm->tm_mday);
			else sprintf(str, "%04d-%02d-%02d %s", -(tm->tm_year - 1), tm->tm_mon, tm->tm_mday, "BC");

			break;

		case USE_SQL_DATES:
			
			if (EuroDates)
				sprintf(str, "%02d/%02d", tm->tm_mday, tm->tm_mon);
			else sprintf(str, "%02d/%02d", tm->tm_mon, tm->tm_mday);
			if (tm->tm_year > 0)
				sprintf(str + 5, "/%04d", tm->tm_year);
			else sprintf(str + 5, "/%04d %s", -(tm->tm_year - 1), "BC");
			break;

		case USE_GERMAN_DATES:
			
			sprintf(str, "%02d.%02d", tm->tm_mday, tm->tm_mon);
			if (tm->tm_year > 0)
				sprintf(str + 5, ".%04d", tm->tm_year);
			else sprintf(str + 5, ".%04d %s", -(tm->tm_year - 1), "BC");
			break;

		case USE_POSTGRES_DATES:
		default:
			
			if (EuroDates)
				sprintf(str, "%02d-%02d", tm->tm_mday, tm->tm_mon);
			else sprintf(str, "%02d-%02d", tm->tm_mon, tm->tm_mday);
			if (tm->tm_year > 0)
				sprintf(str + 5, "-%04d", tm->tm_year);
			else sprintf(str + 5, "-%04d %s", -(tm->tm_year - 1), "BC");
			break;
	}

	return TRUE;
}	

void TrimTrailingZeros(char *str)
{
	int			len = strlen(str);

	
	while (*(str + len - 1) == '0' && *(str + len - 3) != '.')
	{
		len--;
		*(str + len) = '\0';
	}
}


int EncodeDateTime(struct tm * tm, fsec_t fsec, bool print_tz, int tz, const char *tzn, int style, char *str, bool EuroDates)
{
	int			day, hour, min;


	
	if (tm->tm_isdst < 0)
		print_tz = false;

	switch (style)
	{
		case USE_ISO_DATES:
			

			sprintf(str, "%04d-%02d-%02d %02d:%02d", (tm->tm_year > 0) ? tm->tm_year : -(tm->tm_year - 1), tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min);


			

			if (fsec != 0)
			{
				sprintf(str + strlen(str), ":%02d.%06d", tm->tm_sec, fsec);

			if ((fsec != 0) && (tm->tm_year > 0))
			{
				sprintf(str + strlen(str), ":%09.6f", tm->tm_sec + fsec);

				TrimTrailingZeros(str);
			}
			else sprintf(str + strlen(str), ":%02d", tm->tm_sec);

			if (tm->tm_year <= 0)
				sprintf(str + strlen(str), " BC");

			if (print_tz)
			{
				hour = -(tz / SECS_PER_HOUR);
				min = (abs(tz) / MINS_PER_HOUR) % MINS_PER_HOUR;
				if (min != 0)
					sprintf(str + strlen(str), "%+03d:%02d", hour, min);
				else sprintf(str + strlen(str), "%+03d", hour);
			}
			break;

		case USE_SQL_DATES:
			

			if (EuroDates)
				sprintf(str, "%02d/%02d", tm->tm_mday, tm->tm_mon);
			else sprintf(str, "%02d/%02d", tm->tm_mon, tm->tm_mday);

			sprintf(str + 5, "/%04d %02d:%02d", (tm->tm_year > 0) ? tm->tm_year : -(tm->tm_year - 1), tm->tm_hour, tm->tm_min);


			

			if (fsec != 0)
			{
				sprintf(str + strlen(str), ":%02d.%06d", tm->tm_sec, fsec);

			if (fsec != 0 && tm->tm_year > 0)
			{
				sprintf(str + strlen(str), ":%09.6f", tm->tm_sec + fsec);

				TrimTrailingZeros(str);
			}
			else sprintf(str + strlen(str), ":%02d", tm->tm_sec);

			if (tm->tm_year <= 0)
				sprintf(str + strlen(str), " BC");

			

			if (print_tz)
			{
				if (tzn)
					sprintf(str + strlen(str), " %.*s", MAXTZLEN, tzn);
				else {
					hour = -(tz / SECS_PER_HOUR);
					min = (abs(tz) / MINS_PER_HOUR) % MINS_PER_HOUR;
					if (min != 0)
						sprintf(str + strlen(str), "%+03d:%02d", hour, min);
					else sprintf(str + strlen(str), "%+03d", hour);
				}
			}
			break;

		case USE_GERMAN_DATES:
			

			sprintf(str, "%02d.%02d", tm->tm_mday, tm->tm_mon);

			sprintf(str + 5, ".%04d %02d:%02d", (tm->tm_year > 0) ? tm->tm_year : -(tm->tm_year - 1), tm->tm_hour, tm->tm_min);


			

			if (fsec != 0)
			{
				sprintf(str + strlen(str), ":%02d.%06d", tm->tm_sec, fsec);

			if (fsec != 0 && tm->tm_year > 0)
			{
				sprintf(str + strlen(str), ":%09.6f", tm->tm_sec + fsec);

				TrimTrailingZeros(str);
			}
			else sprintf(str + strlen(str), ":%02d", tm->tm_sec);

			if (tm->tm_year <= 0)
				sprintf(str + strlen(str), " BC");

			if (print_tz)
			{
				if (tzn)
					sprintf(str + strlen(str), " %.*s", MAXTZLEN, tzn);
				else {
					hour = -(tz / SECS_PER_HOUR);
					min = (abs(tz) / MINS_PER_HOUR) % MINS_PER_HOUR;
					if (min != 0)
						sprintf(str + strlen(str), "%+03d:%02d", hour, min);
					else sprintf(str + strlen(str), "%+03d", hour);
				}
			}
			break;

		case USE_POSTGRES_DATES:
		default:
			

			day = date2j(tm->tm_year, tm->tm_mon, tm->tm_mday);
			tm->tm_wday = (int) ((day + date2j(2000, 1, 1) + 1) % 7);

			strncpy(str, days[tm->tm_wday], 3);
			strcpy(str + 3, " ");

			if (EuroDates)
				sprintf(str + 4, "%02d %3s", tm->tm_mday, months[tm->tm_mon - 1]);
			else sprintf(str + 4, "%3s %02d", months[tm->tm_mon - 1], tm->tm_mday);

			sprintf(str + 10, " %02d:%02d", tm->tm_hour, tm->tm_min);

			

			if (fsec != 0)
			{
				sprintf(str + strlen(str), ":%02d.%06d", tm->tm_sec, fsec);

			if (fsec != 0 && tm->tm_year > 0)
			{
				sprintf(str + strlen(str), ":%09.6f", tm->tm_sec + fsec);

				TrimTrailingZeros(str);
			}
			else sprintf(str + strlen(str), ":%02d", tm->tm_sec);

			sprintf(str + strlen(str), " %04d", (tm->tm_year > 0) ? tm->tm_year : -(tm->tm_year - 1));
			if (tm->tm_year <= 0)
				sprintf(str + strlen(str), " BC");

			if (print_tz)
			{
				if (tzn)
					sprintf(str + strlen(str), " %.*s", MAXTZLEN, tzn);
				else {
					
					hour = -(tz / SECS_PER_HOUR);
					min = (abs(tz) / MINS_PER_HOUR) % MINS_PER_HOUR;
					if (min != 0)
						sprintf(str + strlen(str), " %+03d:%02d", hour, min);
					else sprintf(str + strlen(str), " %+03d", hour);
				}
			}
			break;
	}

	return TRUE;
}	

int GetEpochTime(struct tm * tm)
{
	struct tm  *t0;
	time_t		epoch = 0;

	t0 = gmtime(&epoch);

	if (t0)
	{
		tm->tm_year = t0->tm_year + 1900;
		tm->tm_mon = t0->tm_mon + 1;
		tm->tm_mday = t0->tm_mday;
		tm->tm_hour = t0->tm_hour;
		tm->tm_min = t0->tm_min;
		tm->tm_sec = t0->tm_sec;

		return 0;
	}

	return -1;
}	

static void abstime2tm(AbsoluteTime _time, int *tzp, struct tm * tm, char **tzn)
{
	time_t		time = (time_t) _time;
	struct tm  *tx;

	errno = 0;
	if (tzp != NULL)
		tx = localtime((time_t *) &time);
	else tx = gmtime((time_t *) &time);

	if (!tx)
	{
		errno = PGTYPES_TS_BAD_TIMESTAMP;
		return;
	}

	tm->tm_year = tx->tm_year + 1900;
	tm->tm_mon = tx->tm_mon + 1;
	tm->tm_mday = tx->tm_mday;
	tm->tm_hour = tx->tm_hour;
	tm->tm_min = tx->tm_min;
	tm->tm_sec = tx->tm_sec;
	tm->tm_isdst = tx->tm_isdst;


	tm->tm_gmtoff = tx->tm_gmtoff;
	tm->tm_zone = tx->tm_zone;

	if (tzp != NULL)
	{
		
		*tzp = -tm->tm_gmtoff;	

		
		if (tzn != NULL)
		{
			
			StrNCpy(*tzn, tm->tm_zone, MAXTZLEN + 1);
			if (strlen(tm->tm_zone) > MAXTZLEN)
				tm->tm_isdst = -1;
		}
	}
	else tm->tm_isdst = -1;

	if (tzp != NULL)
	{
		*tzp = (tm->tm_isdst > 0) ? TIMEZONE_GLOBAL - SECS_PER_HOUR : TIMEZONE_GLOBAL;

		if (tzn != NULL)
		{
			
			StrNCpy(*tzn, TZNAME_GLOBAL[tm->tm_isdst], MAXTZLEN + 1);
			if (strlen(TZNAME_GLOBAL[tm->tm_isdst]) > MAXTZLEN)
				tm->tm_isdst = -1;
		}
	}
	else tm->tm_isdst = -1;

	if (tzp != NULL)
	{
		
		*tzp = 0;
		if (tzn != NULL)
			*tzn = NULL;
	}
	else tm->tm_isdst = -1;

}

void GetCurrentDateTime(struct tm * tm)
{
	int			tz;

	abstime2tm(time(NULL), &tz, tm, NULL);
}

void dt2time(double jd, int *hour, int *min, int *sec, fsec_t *fsec)
{

	int64		time;

	double		time;


	time = jd;

	*hour = time / USECS_PER_HOUR;
	time -= (*hour) * USECS_PER_HOUR;
	*min = time / USECS_PER_MINUTE;
	time -= (*min) * USECS_PER_MINUTE;
	*sec = time / USECS_PER_SEC;
	*fsec = time - (*sec * USECS_PER_SEC);

	*hour = time / SECS_PER_HOUR;
	time -= (*hour) * SECS_PER_HOUR;
	*min = time / SECS_PER_MINUTE;
	time -= (*min) * SECS_PER_MINUTE;
	*sec = time;
	*fsec = time - *sec;

}	




static int DecodeNumberField(int len, char *str, int fmask, int *tmask, struct tm * tm, fsec_t *fsec, int *is2digits)

{
	char	   *cp;

	
	if ((cp = strchr(str, '.')) != NULL)
	{

		char		fstr[MAXDATELEN + 1];

		
		strcpy(fstr, (cp + 1));
		strcpy(fstr + strlen(fstr), "000000");
		*(fstr + 6) = '\0';
		*fsec = strtol(fstr, NULL, 10);

		*fsec = strtod(cp, NULL);

		*cp = '\0';
		len = strlen(str);
	}
	
	else if ((fmask & DTK_DATE_M) != DTK_DATE_M)
	{
		
		if (len == 8)
		{
			*tmask = DTK_DATE_M;

			tm->tm_mday = atoi(str + 6);
			*(str + 6) = '\0';
			tm->tm_mon = atoi(str + 4);
			*(str + 4) = '\0';
			tm->tm_year = atoi(str + 0);

			return DTK_DATE;
		}
		
		else if (len == 6)
		{
			*tmask = DTK_DATE_M;
			tm->tm_mday = atoi(str + 4);
			*(str + 4) = '\0';
			tm->tm_mon = atoi(str + 2);
			*(str + 2) = '\0';
			tm->tm_year = atoi(str + 0);
			*is2digits = TRUE;

			return DTK_DATE;
		}
		
		else if (len == 5)
		{
			*tmask = DTK_DATE_M;
			tm->tm_mday = atoi(str + 2);
			*(str + 2) = '\0';
			tm->tm_mon = 1;
			tm->tm_year = atoi(str + 0);
			*is2digits = TRUE;

			return DTK_DATE;
		}
	}

	
	if ((fmask & DTK_TIME_M) != DTK_TIME_M)
	{
		
		if (len == 6)
		{
			*tmask = DTK_TIME_M;
			tm->tm_sec = atoi(str + 4);
			*(str + 4) = '\0';
			tm->tm_min = atoi(str + 2);
			*(str + 2) = '\0';
			tm->tm_hour = atoi(str + 0);

			return DTK_TIME;
		}
		
		else if (len == 4)
		{
			*tmask = DTK_TIME_M;
			tm->tm_sec = 0;
			tm->tm_min = atoi(str + 2);
			*(str + 2) = '\0';
			tm->tm_hour = atoi(str + 0);

			return DTK_TIME;
		}
	}

	return -1;
}	



static int DecodeNumber(int flen, char *str, int fmask, int *tmask, struct tm * tm, fsec_t *fsec, int *is2digits, bool EuroDates)

{
	int			val;
	char	   *cp;

	*tmask = 0;

	val = strtol(str, &cp, 10);
	if (cp == str)
		return -1;

	if (*cp == '.')
	{
		
		if (cp - str > 2)
			return DecodeNumberField(flen, str, (fmask | DTK_DATE_M), tmask, tm, fsec, is2digits);

		*fsec = strtod(cp, &cp);
		if (*cp != '\0')
			return -1;
	}
	else if (*cp != '\0')
		return -1;

	
	if (flen == 3 && (fmask & DTK_M(YEAR)) && val >= 1 && val <= 366)
	{
		*tmask = (DTK_M(DOY) | DTK_M(MONTH) | DTK_M(DAY));
		tm->tm_yday = val;
		j2date(date2j(tm->tm_year, 1, 1) + tm->tm_yday - 1, &tm->tm_year, &tm->tm_mon, &tm->tm_mday);
	}

	
	else if (flen >= 4)
	{
		*tmask = DTK_M(YEAR);

		
		if ((fmask & DTK_M(YEAR)) && !(fmask & DTK_M(DAY)) && tm->tm_year >= 1 && tm->tm_year <= 31)
		{
			tm->tm_mday = tm->tm_year;
			*tmask = DTK_M(DAY);
		}

		tm->tm_year = val;
	}

	
	else if ((fmask & DTK_M(YEAR)) && !(fmask & DTK_M(MONTH)) && val >= 1 && val <= MONTHS_PER_YEAR)
	{
		*tmask = DTK_M(MONTH);
		tm->tm_mon = val;
	}
	
	else if ((EuroDates || (fmask & DTK_M(MONTH))) && !(fmask & DTK_M(YEAR)) && !(fmask & DTK_M(DAY)) && val >= 1 && val <= 31)

	{
		*tmask = DTK_M(DAY);
		tm->tm_mday = val;
	}
	else if (!(fmask & DTK_M(MONTH)) && val >= 1 && val <= MONTHS_PER_YEAR)
	{
		*tmask = DTK_M(MONTH);
		tm->tm_mon = val;
	}
	else if (!(fmask & DTK_M(DAY)) && val >= 1 && val <= 31)
	{
		*tmask = DTK_M(DAY);
		tm->tm_mday = val;
	}

	
	else if (!(fmask & DTK_M(YEAR)) && (flen >= 4 || flen == 2))
	{
		*tmask = DTK_M(YEAR);
		tm->tm_year = val;

		
		*is2digits = (flen == 2);
	}
	else return -1;

	return 0;
}	


static int DecodeDate(char *str, int fmask, int *tmask, struct tm * tm, bool EuroDates)
{
	fsec_t		fsec;

	int			nf = 0;
	int			i, len;
	int			bc = FALSE;
	int			is2digits = FALSE;
	int			type, val, dmask = 0;

	char	   *field[MAXDATEFIELDS];

	
	while (*str != '\0' && nf < MAXDATEFIELDS)
	{
		
		while (!isalnum((unsigned char) *str))
			str++;

		field[nf] = str;
		if (isdigit((unsigned char) *str))
		{
			while (isdigit((unsigned char) *str))
				str++;
		}
		else if (isalpha((unsigned char) *str))
		{
			while (isalpha((unsigned char) *str))
				str++;
		}

		
		if (*str != '\0')
			*str++ = '\0';
		nf++;
	}


	
	if (nf > 3)
		return -1;


	*tmask = 0;

	
	for (i = 0; i < nf; i++)
	{
		if (isalpha((unsigned char) *field[i]))
		{
			type = DecodeSpecial(i, field[i], &val);
			if (type == IGNORE_DTF)
				continue;

			dmask = DTK_M(type);
			switch (type)
			{
				case MONTH:
					tm->tm_mon = val;
					break;

				case ADBC:
					bc = (val == BC);
					break;

				default:
					return -1;
			}
			if (fmask & dmask)
				return -1;

			fmask |= dmask;
			*tmask |= dmask;

			
			field[i] = NULL;
		}
	}

	
	for (i = 0; i < nf; i++)
	{
		if (field[i] == NULL)
			continue;

		if ((len = strlen(field[i])) <= 0)
			return -1;

		if (DecodeNumber(len, field[i], fmask, &dmask, tm, &fsec, &is2digits, EuroDates) != 0)
			return -1;

		if (fmask & dmask)
			return -1;

		fmask |= dmask;
		*tmask |= dmask;
	}

	if ((fmask & ~(DTK_M(DOY) | DTK_M(TZ))) != DTK_DATE_M)
		return -1;

	
	if (bc)
	{
		if (tm->tm_year > 0)
			tm->tm_year = -(tm->tm_year - 1);
		else return -1;
	}
	else if (is2digits)
	{
		if (tm->tm_year < 70)
			tm->tm_year += 2000;
		else if (tm->tm_year < 100)
			tm->tm_year += 1900;
	}

	return 0;
}	



int DecodeTime(char *str, int *tmask, struct tm * tm, fsec_t *fsec)
{
	char	   *cp;

	*tmask = DTK_TIME_M;

	tm->tm_hour = strtol(str, &cp, 10);
	if (*cp != ':')
		return -1;
	str = cp + 1;
	tm->tm_min = strtol(str, &cp, 10);
	if (*cp == '\0')
	{
		tm->tm_sec = 0;
		*fsec = 0;
	}
	else if (*cp != ':')
		return -1;
	else {
		str = cp + 1;
		tm->tm_sec = strtol(str, &cp, 10);
		if (*cp == '\0')
			*fsec = 0;
		else if (*cp == '.')
		{

			char		fstr[MAXDATELEN + 1];

			
			strncpy(fstr, (cp + 1), 7);
			strcpy(fstr + strlen(fstr), "000000");
			*(fstr + 6) = '\0';
			*fsec = strtol(fstr, &cp, 10);

			str = cp;
			*fsec = strtod(str, &cp);

			if (*cp != '\0')
				return -1;
		}
		else return -1;
	}

	

	if (tm->tm_hour < 0 || tm->tm_min < 0 || tm->tm_min > 59 || tm->tm_sec < 0 || tm->tm_sec > 59 || *fsec >= USECS_PER_SEC)
		return -1;

	if (tm->tm_hour < 0 || tm->tm_min < 0 || tm->tm_min > 59 || tm->tm_sec < 0 || tm->tm_sec > 59 || *fsec >= 1)
		return -1;


	return 0;
}	


static int DecodeTimezone(char *str, int *tzp)
{
	int			tz;
	int			hr, min;
	char	   *cp;
	int			len;

	
	hr = strtol(str + 1, &cp, 10);

	
	if (*cp == ':')
		min = strtol(cp + 1, &cp, 10);
	
	else if (*cp == '\0' && (len = strlen(str)) > 3)
	{
		min = strtol(str + len - 2, &cp, 10);
		if (min < 0 || min >= 60)
			return -1;

		*(str + len - 2) = '\0';
		hr = strtol(str + 1, &cp, 10);
		if (hr < 0 || hr > 13)
			return -1;
	}
	else min = 0;

	tz = (hr * MINS_PER_HOUR + min) * SECS_PER_MINUTE;
	if (*str == '-')
		tz = -tz;

	*tzp = -tz;
	return *cp != '\0';
}	



static int DecodePosixTimezone(char *str, int *tzp)
{
	int			val, tz;
	int			type;
	char	   *cp;
	char		delim;

	cp = str;
	while (*cp != '\0' && isalpha((unsigned char) *cp))
		cp++;

	if (DecodeTimezone(cp, &tz) != 0)
		return -1;

	delim = *cp;
	*cp = '\0';
	type = DecodeSpecial(MAXDATEFIELDS - 1, str, &val);
	*cp = delim;

	switch (type)
	{
		case DTZ:
		case TZ:
			*tzp = (val * MINS_PER_HOUR) - tz;
			break;

		default:
			return -1;
	}

	return 0;
}	


int ParseDateTime(char *timestr, char *lowstr, char **field, int *ftype, int *numfields, char **endstr)

{
	int			nf = 0;
	char	   *lp = lowstr;

	*endstr = timestr;
	
	while (*(*endstr) != '\0')
	{
		field[nf] = lp;

		
		if (isdigit((unsigned char) *(*endstr)))
		{
			*lp++ = *(*endstr)++;
			while (isdigit((unsigned char) *(*endstr)))
				*lp++ = *(*endstr)++;

			
			if (*(*endstr) == ':')
			{
				ftype[nf] = DTK_TIME;
				*lp++ = *(*endstr)++;
				while (isdigit((unsigned char) *(*endstr)) || (*(*endstr) == ':') || (*(*endstr) == '.'))
					*lp++ = *(*endstr)++;
			}
			
			else if (*(*endstr) == '-' || *(*endstr) == '/' || *(*endstr) == '.')
			{
				
				char	   *dp = (*endstr);

				*lp++ = *(*endstr)++;
				
				if (isdigit((unsigned char) *(*endstr)))
				{
					ftype[nf] = (*dp == '.') ? DTK_NUMBER : DTK_DATE;
					while (isdigit((unsigned char) *(*endstr)))
						*lp++ = *(*endstr)++;

					
					if (*(*endstr) == *dp)
					{
						ftype[nf] = DTK_DATE;
						*lp++ = *(*endstr)++;
						while (isdigit((unsigned char) *(*endstr)) || (*(*endstr) == *dp))
							*lp++ = *(*endstr)++;
					}
				}
				else {
					ftype[nf] = DTK_DATE;
					while (isalnum((unsigned char) *(*endstr)) || (*(*endstr) == *dp))
						*lp++ = pg_tolower((unsigned char) *(*endstr)++);
				}
			}

			
			else ftype[nf] = DTK_NUMBER;
		}
		
		else if (*(*endstr) == '.')
		{
			*lp++ = *(*endstr)++;
			while (isdigit((unsigned char) *(*endstr)))
				*lp++ = *(*endstr)++;

			ftype[nf] = DTK_NUMBER;
		}

		
		else if (isalpha((unsigned char) *(*endstr)))
		{
			ftype[nf] = DTK_STRING;
			*lp++ = pg_tolower((unsigned char) *(*endstr)++);
			while (isalpha((unsigned char) *(*endstr)))
				*lp++ = pg_tolower((unsigned char) *(*endstr)++);

			
			if (*(*endstr) == '-' || *(*endstr) == '/' || *(*endstr) == '.')
			{
				char	   *dp = (*endstr);

				ftype[nf] = DTK_DATE;
				*lp++ = *(*endstr)++;
				while (isdigit((unsigned char) *(*endstr)) || *(*endstr) == *dp)
					*lp++ = *(*endstr)++;
			}
		}
		
		else if (isspace((unsigned char) *(*endstr)))
		{
			(*endstr)++;
			continue;
		}
		
		else if (*(*endstr) == '+' || *(*endstr) == '-')
		{
			*lp++ = *(*endstr)++;
			
			while (isspace((unsigned char) *(*endstr)))
				(*endstr)++;
			
			if (isdigit((unsigned char) *(*endstr)))
			{
				ftype[nf] = DTK_TZ;
				*lp++ = *(*endstr)++;
				while (isdigit((unsigned char) *(*endstr)) || (*(*endstr) == ':') || (*(*endstr) == '.'))
					*lp++ = *(*endstr)++;
			}
			
			else if (isalpha((unsigned char) *(*endstr)))
			{
				ftype[nf] = DTK_SPECIAL;
				*lp++ = pg_tolower((unsigned char) *(*endstr)++);
				while (isalpha((unsigned char) *(*endstr)))
					*lp++ = pg_tolower((unsigned char) *(*endstr)++);
			}
			
			else return -1;
		}
		
		else if (ispunct((unsigned char) *(*endstr)))
		{
			(*endstr)++;
			continue;

		}
		
		else return -1;

		
		*lp++ = '\0';
		nf++;
		if (nf > MAXDATEFIELDS)
			return -1;
	}

	*numfields = nf;

	return 0;
}	



int DecodeDateTime(char **field, int *ftype, int nf, int *dtype, struct tm * tm, fsec_t *fsec, bool EuroDates)

{
	int			fmask = 0, tmask, type;

	int			ptype = 0;		
	int			i;
	int			val;
	int			mer = HR24;
	int			haveTextMonth = FALSE;
	int			is2digits = FALSE;
	int			bc = FALSE;
	int			t = 0;
	int		   *tzp = &t;

	
	*dtype = DTK_DATE;
	tm->tm_hour = 0;
	tm->tm_min = 0;
	tm->tm_sec = 0;
	*fsec = 0;
	
	tm->tm_isdst = -1;
	if (tzp != NULL)
		*tzp = 0;

	for (i = 0; i < nf; i++)
	{
		switch (ftype[i])
		{
			case DTK_DATE:
				
				if (ptype == DTK_JULIAN)
				{
					char	   *cp;
					int			val;

					if (tzp == NULL)
						return -1;

					val = strtol(field[i], &cp, 10);
					if (*cp != '-')
						return -1;

					j2date(val, &tm->tm_year, &tm->tm_mon, &tm->tm_mday);
					
					if (DecodeTimezone(cp, tzp) != 0)
						return -1;

					tmask = DTK_DATE_M | DTK_TIME_M | DTK_M(TZ);
					ptype = 0;
					break;
				}
				
				else if (((fmask & DTK_DATE_M) == DTK_DATE_M)
						 || (ptype != 0))
				{
					
					if (tzp == NULL)
						return -1;

					if (isdigit((unsigned char) *field[i]) || ptype != 0)
					{
						char	   *cp;

						if (ptype != 0)
						{
							
							if (ptype != DTK_TIME)
								return -1;
							ptype = 0;
						}

						
						if ((fmask & DTK_TIME_M) == DTK_TIME_M)
							return -1;

						if ((cp = strchr(field[i], '-')) == NULL)
							return -1;

						
						if (DecodeTimezone(cp, tzp) != 0)
							return -1;
						*cp = '\0';

						
						if ((ftype[i] = DecodeNumberField(strlen(field[i]), field[i], fmask, &tmask, tm, fsec, &is2digits)) < 0)
							return -1;

						
						tmask |= DTK_M(TZ);
					}
					else {
						if (DecodePosixTimezone(field[i], tzp) != 0)
							return -1;

						ftype[i] = DTK_TZ;
						tmask = DTK_M(TZ);
					}
				}
				else if (DecodeDate(field[i], fmask, &tmask, tm, EuroDates) != 0)
					return -1;
				break;

			case DTK_TIME:
				if (DecodeTime(field[i], &tmask, tm, fsec) != 0)
					return -1;

				
				
				if (tm->tm_hour > 24 || (tm->tm_hour == 24 && (tm->tm_min > 0 || tm->tm_sec > 0)))
					return -1;
				break;

			case DTK_TZ:
				{
					int			tz;

					if (tzp == NULL)
						return -1;

					if (DecodeTimezone(field[i], &tz) != 0)
						return -1;

					
					if (i > 0 && (fmask & DTK_M(TZ)) != 0 && ftype[i - 1] == DTK_TZ && isalpha((unsigned char) *field[i - 1]))

					{
						*tzp -= tz;
						tmask = 0;
					}
					else {
						*tzp = tz;
						tmask = DTK_M(TZ);
					}
				}
				break;

			case DTK_NUMBER:

				
				if (ptype != 0)
				{
					char	   *cp;
					int			val;

					val = strtol(field[i], &cp, 10);

					
					if (*cp == '.')
						switch (ptype)
						{
							case DTK_JULIAN:
							case DTK_TIME:
							case DTK_SECOND:
								break;
							default:
								return 1;
								break;
						}
					else if (*cp != '\0')
						return -1;

					switch (ptype)
					{
						case DTK_YEAR:
							tm->tm_year = val;
							tmask = DTK_M(YEAR);
							break;

						case DTK_MONTH:

							
							if ((fmask & DTK_M(MONTH)) != 0 && (fmask & DTK_M(HOUR)) != 0)
							{
								tm->tm_min = val;
								tmask = DTK_M(MINUTE);
							}
							else {
								tm->tm_mon = val;
								tmask = DTK_M(MONTH);
							}
							break;

						case DTK_DAY:
							tm->tm_mday = val;
							tmask = DTK_M(DAY);
							break;

						case DTK_HOUR:
							tm->tm_hour = val;
							tmask = DTK_M(HOUR);
							break;

						case DTK_MINUTE:
							tm->tm_min = val;
							tmask = DTK_M(MINUTE);
							break;

						case DTK_SECOND:
							tm->tm_sec = val;
							tmask = DTK_M(SECOND);
							if (*cp == '.')
							{
								double		frac;

								frac = strtod(cp, &cp);
								if (*cp != '\0')
									return -1;

								*fsec = frac * 1000000;

								*fsec = frac;

							}
							break;

						case DTK_TZ:
							tmask = DTK_M(TZ);
							if (DecodeTimezone(field[i], tzp) != 0)
								return -1;
							break;

						case DTK_JULIAN:
							
							tmask = DTK_DATE_M;
							j2date(val, &tm->tm_year, &tm->tm_mon, &tm->tm_mday);
							
							if (*cp == '.')
							{
								double		time;

								time = strtod(cp, &cp);
								if (*cp != '\0')
									return -1;

								tmask |= DTK_TIME_M;

								dt2time((time * USECS_PER_DAY), &tm->tm_hour, &tm->tm_min, &tm->tm_sec, fsec);

								dt2time((time * SECS_PER_DAY), &tm->tm_hour, &tm->tm_min, &tm->tm_sec, fsec);

							}
							break;

						case DTK_TIME:
							
							if ((ftype[i] = DecodeNumberField(strlen(field[i]), field[i], (fmask | DTK_DATE_M), &tmask, tm, fsec, &is2digits)) < 0)
								return -1;

							if (tmask != DTK_TIME_M)
								return -1;
							break;

						default:
							return -1;
							break;
					}

					ptype = 0;
					*dtype = DTK_DATE;
				}
				else {
					char	   *cp;
					int			flen;

					flen = strlen(field[i]);
					cp = strchr(field[i], '.');

					
					if (cp != NULL && !(fmask & DTK_DATE_M))
					{
						if (DecodeDate(field[i], fmask, &tmask, tm, EuroDates) != 0)
							return -1;
					}
					
					else if (cp != NULL && flen - strlen(cp) > 2)
					{
						
						if ((ftype[i] = DecodeNumberField(flen, field[i], fmask, &tmask, tm, fsec, &is2digits)) < 0)
							return -1;
					}
					else if (flen > 4)
					{
						if ((ftype[i] = DecodeNumberField(flen, field[i], fmask, &tmask, tm, fsec, &is2digits)) < 0)
							return -1;
					}
					
					else if (DecodeNumber(flen, field[i], fmask, &tmask, tm, fsec, &is2digits, EuroDates) != 0)
						return -1;
				}
				break;

			case DTK_STRING:
			case DTK_SPECIAL:
				type = DecodeSpecial(i, field[i], &val);
				if (type == IGNORE_DTF)
					continue;

				tmask = DTK_M(type);
				switch (type)
				{
					case RESERV:
						switch (val)
						{
							case DTK_NOW:
								tmask = (DTK_DATE_M | DTK_TIME_M | DTK_M(TZ));
								*dtype = DTK_DATE;
								GetCurrentDateTime(tm);
								break;

							case DTK_YESTERDAY:
								tmask = DTK_DATE_M;
								*dtype = DTK_DATE;
								GetCurrentDateTime(tm);
								j2date(date2j(tm->tm_year, tm->tm_mon, tm->tm_mday) - 1, &tm->tm_year, &tm->tm_mon, &tm->tm_mday);
								tm->tm_hour = 0;
								tm->tm_min = 0;
								tm->tm_sec = 0;
								break;

							case DTK_TODAY:
								tmask = DTK_DATE_M;
								*dtype = DTK_DATE;
								GetCurrentDateTime(tm);
								tm->tm_hour = 0;
								tm->tm_min = 0;
								tm->tm_sec = 0;
								break;

							case DTK_TOMORROW:
								tmask = DTK_DATE_M;
								*dtype = DTK_DATE;
								GetCurrentDateTime(tm);
								j2date(date2j(tm->tm_year, tm->tm_mon, tm->tm_mday) + 1, &tm->tm_year, &tm->tm_mon, &tm->tm_mday);
								tm->tm_hour = 0;
								tm->tm_min = 0;
								tm->tm_sec = 0;
								break;

							case DTK_ZULU:
								tmask = (DTK_TIME_M | DTK_M(TZ));
								*dtype = DTK_DATE;
								tm->tm_hour = 0;
								tm->tm_min = 0;
								tm->tm_sec = 0;
								if (tzp != NULL)
									*tzp = 0;
								break;

							default:
								*dtype = val;
						}

						break;

					case MONTH:

						
						if ((fmask & DTK_M(MONTH)) && !haveTextMonth && !(fmask & DTK_M(DAY)) && tm->tm_mon >= 1 && tm->tm_mon <= 31)
						{
							tm->tm_mday = tm->tm_mon;
							tmask = DTK_M(DAY);
						}
						haveTextMonth = TRUE;
						tm->tm_mon = val;
						break;

					case DTZMOD:

						
						tmask |= DTK_M(DTZ);
						tm->tm_isdst = 1;
						if (tzp == NULL)
							return -1;
						*tzp += val * MINS_PER_HOUR;
						break;

					case DTZ:

						
						tmask |= DTK_M(TZ);
						tm->tm_isdst = 1;
						if (tzp == NULL)
							return -1;
						*tzp = val * MINS_PER_HOUR;
						ftype[i] = DTK_TZ;
						break;

					case TZ:
						tm->tm_isdst = 0;
						if (tzp == NULL)
							return -1;
						*tzp = val * MINS_PER_HOUR;
						ftype[i] = DTK_TZ;
						break;

					case IGNORE_DTF:
						break;

					case AMPM:
						mer = val;
						break;

					case ADBC:
						bc = (val == BC);
						break;

					case DOW:
						tm->tm_wday = val;
						break;

					case UNITS:
						tmask = 0;
						ptype = val;
						break;

					case ISOTIME:

						
						tmask = 0;

						
						if ((fmask & DTK_DATE_M) != DTK_DATE_M)
							return -1;

						
						if (i >= nf - 1 || (ftype[i + 1] != DTK_NUMBER && ftype[i + 1] != DTK_TIME && ftype[i + 1] != DTK_DATE))


							return -1;

						ptype = val;
						break;

					default:
						return -1;
				}
				break;

			default:
				return -1;
		}

		if (tmask & fmask)
			return -1;
		fmask |= tmask;
	}

	
	if (bc)
	{
		if (tm->tm_year > 0)
			tm->tm_year = -(tm->tm_year - 1);
		else return -1;
	}
	else if (is2digits)
	{
		if (tm->tm_year < 70)
			tm->tm_year += 2000;
		else if (tm->tm_year < 100)
			tm->tm_year += 1900;
	}

	if (mer != HR24 && tm->tm_hour > 12)
		return -1;
	if (mer == AM && tm->tm_hour == 12)
		tm->tm_hour = 0;
	else if (mer == PM && tm->tm_hour != 12)
		tm->tm_hour += 12;

	
	if (*dtype == DTK_DATE)
	{
		if ((fmask & DTK_DATE_M) != DTK_DATE_M)
			return ((fmask & DTK_TIME_M) == DTK_TIME_M) ? 1 : -1;

		
		if (tm->tm_mday < 1 || tm->tm_mday > day_tab[isleap(tm->tm_year)][tm->tm_mon - 1])
			return -1;

		
		if ((fmask & DTK_DATE_M) == DTK_DATE_M && tzp != NULL && !(fmask & DTK_M(TZ)) && (fmask & DTK_M(DTZMOD)))
			return -1;
	}

	return 0;
}	



static char * find_end_token(char *str, char *fmt)
{
	
	char	   *end_position = NULL;
	char	   *next_percent, *subst_location = NULL;
	int			scan_offset = 0;
	char		last_char;

	
	if (!*fmt)
	{
		end_position = fmt;
		return end_position;
	}

	
	while (fmt[scan_offset] == '%' && fmt[scan_offset + 1])
	{
		
		scan_offset += 2;
	}
	next_percent = strchr(fmt + scan_offset, '%');
	if (next_percent)
	{
		

		subst_location = next_percent;
		while (*(subst_location - 1) == ' ' && subst_location - 1 > fmt + scan_offset)
			subst_location--;
		last_char = *subst_location;
		*subst_location = '\0';

		

		
		while (*str == ' ')
			str++;
		end_position = strstr(str, fmt + scan_offset);
		*subst_location = last_char;
	}
	else {
		
		end_position = str + strlen(str);
	}
	if (!end_position)
	{
		
		if ((fmt + scan_offset)[0] == ' ' && fmt + scan_offset + 1 == subst_location)
			end_position = str + strlen(str);
	}
	return end_position;
}

static int pgtypes_defmt_scan(union un_fmt_comb * scan_val, int scan_type, char **pstr, char *pfmt)
{
	

	char		last_char;
	int			err = 0;
	char	   *pstr_end;
	char	   *strtol_end = NULL;

	while (**pstr == ' ')
		pstr++;
	pstr_end = find_end_token(*pstr, pfmt);
	if (!pstr_end)
	{
		
		return 1;
	}
	last_char = *pstr_end;
	*pstr_end = '\0';

	switch (scan_type)
	{
		case PGTYPES_TYPE_UINT:

			
			while (**pstr == ' ')
				(*pstr)++;
			errno = 0;
			scan_val->uint_val = (unsigned int) strtol(*pstr, &strtol_end, 10);
			if (errno)
				err = 1;
			break;
		case PGTYPES_TYPE_UINT_LONG:
			while (**pstr == ' ')
				(*pstr)++;
			errno = 0;
			scan_val->luint_val = (unsigned long int) strtol(*pstr, &strtol_end, 10);
			if (errno)
				err = 1;
			break;
		case PGTYPES_TYPE_STRING_MALLOCED:
			scan_val->str_val = pgtypes_strdup(*pstr);
			if (scan_val->str_val == NULL)
				err = 1;
			break;
	}
	if (strtol_end && *strtol_end)
		*pstr = strtol_end;
	else *pstr = pstr_end;
	*pstr_end = last_char;
	return err;
}


int PGTYPEStimestamp_defmt_scan(char **str, char *fmt, timestamp * d, int *year, int *month, int *day, int *hour, int *minute, int *second, int *tz)



{
	union un_fmt_comb scan_val;
	int			scan_type;

	char	   *pstr, *pfmt, *tmp;

	int			err = 1;
	unsigned int j;
	struct tm	tm;

	pfmt = fmt;
	pstr = *str;

	while (*pfmt)
	{
		err = 0;
		while (*pfmt == ' ')
			pfmt++;
		while (*pstr == ' ')
			pstr++;
		if (*pfmt != '%')
		{
			if (*pfmt == *pstr)
			{
				pfmt++;
				pstr++;
			}
			else {
				
				err = 1;
				return err;
			}
			continue;
		}
		
		pfmt++;
		switch (*pfmt)
		{
			case 'a':
				pfmt++;

				
				err = 1;
				j = 0;
				while (pgtypes_date_weekdays_short[j])
				{
					if (strncmp(pgtypes_date_weekdays_short[j], pstr, strlen(pgtypes_date_weekdays_short[j])) == 0)
					{
						
						err = 0;
						pstr += strlen(pgtypes_date_weekdays_short[j]);
						break;
					}
					j++;
				}
				break;
			case 'A':
				
				pfmt++;
				err = 1;
				j = 0;
				while (days[j])
				{
					if (strncmp(days[j], pstr, strlen(days[j])) == 0)
					{
						
						err = 0;
						pstr += strlen(days[j]);
						break;
					}
					j++;
				}
				break;
			case 'b':
			case 'h':
				pfmt++;
				err = 1;
				j = 0;
				while (months[j])
				{
					if (strncmp(months[j], pstr, strlen(months[j])) == 0)
					{
						
						err = 0;
						pstr += strlen(months[j]);
						*month = j + 1;
						break;
					}
					j++;
				}
				break;
			case 'B':
				
				pfmt++;
				err = 1;
				j = 0;
				while (pgtypes_date_months[j])
				{
					if (strncmp(pgtypes_date_months[j], pstr, strlen(pgtypes_date_months[j])) == 0)
					{
						
						err = 0;
						pstr += strlen(pgtypes_date_months[j]);
						*month = j + 1;
						break;
					}
					j++;
				}
				break;
			case 'c':
				
				break;
			case 'C':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				*year = scan_val.uint_val * 100;
				break;
			case 'd':
			case 'e':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				*day = scan_val.uint_val;
				break;
			case 'D':

				
				pfmt++;
				tmp = pgtypes_alloc(strlen("%m/%d/%y") + strlen(pstr) + 1);
				strcpy(tmp, "%m/%d/%y");
				strcat(tmp, pfmt);
				err = PGTYPEStimestamp_defmt_scan(&pstr, tmp, d, year, month, day, hour, minute, second, tz);
				free(tmp);
				return err;
			case 'm':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				*month = scan_val.uint_val;
				break;
			case 'y':
			case 'g':			
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				if (*year < 0)
				{
					
					*year = scan_val.uint_val;
				}
				else *year += scan_val.uint_val;
				if (*year < 100)
					*year += 1900;
				break;
			case 'G':
				
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				*year = scan_val.uint_val;
				break;
			case 'H':
			case 'I':
			case 'k':
			case 'l':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				*hour += scan_val.uint_val;
				break;
			case 'j':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);

				
				break;
			case 'M':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				*minute = scan_val.uint_val;
				break;
			case 'n':
				pfmt++;
				if (*pstr == '\n')
					pstr++;
				else err = 1;
				break;
			case 'p':
				err = 1;
				pfmt++;
				if (strncmp(pstr, "am", 2) == 0)
				{
					*hour += 0;
					err = 0;
					pstr += 2;
				}
				if (strncmp(pstr, "a.m.", 4) == 0)
				{
					*hour += 0;
					err = 0;
					pstr += 4;
				}
				if (strncmp(pstr, "pm", 2) == 0)
				{
					*hour += 12;
					err = 0;
					pstr += 2;
				}
				if (strncmp(pstr, "p.m.", 4) == 0)
				{
					*hour += 12;
					err = 0;
					pstr += 4;
				}
				break;
			case 'P':
				err = 1;
				pfmt++;
				if (strncmp(pstr, "AM", 2) == 0)
				{
					*hour += 0;
					err = 0;
					pstr += 2;
				}
				if (strncmp(pstr, "A.M.", 4) == 0)
				{
					*hour += 0;
					err = 0;
					pstr += 4;
				}
				if (strncmp(pstr, "PM", 2) == 0)
				{
					*hour += 12;
					err = 0;
					pstr += 2;
				}
				if (strncmp(pstr, "P.M.", 4) == 0)
				{
					*hour += 12;
					err = 0;
					pstr += 4;
				}
				break;
			case 'r':
				pfmt++;
				tmp = pgtypes_alloc(strlen("%I:%M:%S %p") + strlen(pstr) + 1);
				strcpy(tmp, "%I:%M:%S %p");
				strcat(tmp, pfmt);
				err = PGTYPEStimestamp_defmt_scan(&pstr, tmp, d, year, month, day, hour, minute, second, tz);
				free(tmp);
				return err;
			case 'R':
				pfmt++;
				tmp = pgtypes_alloc(strlen("%H:%M") + strlen(pstr) + 1);
				strcpy(tmp, "%H:%M");
				strcat(tmp, pfmt);
				err = PGTYPEStimestamp_defmt_scan(&pstr, tmp, d, year, month, day, hour, minute, second, tz);
				free(tmp);
				return err;
			case 's':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT_LONG;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				
				{
					struct tm  *tms;
					time_t		et = (time_t) scan_val.luint_val;

					tms = gmtime(&et);

					if (tms)
					{
						*year = tms->tm_year + 1900;
						*month = tms->tm_mon + 1;
						*day = tms->tm_mday;
						*hour = tms->tm_hour;
						*minute = tms->tm_min;
						*second = tms->tm_sec;
					}
					else err = 1;
				}
				break;
			case 'S':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				*second = scan_val.uint_val;
				break;
			case 't':
				pfmt++;
				if (*pstr == '\t')
					pstr++;
				else err = 1;
				break;
			case 'T':
				pfmt++;
				tmp = pgtypes_alloc(strlen("%H:%M:%S") + strlen(pstr) + 1);
				strcpy(tmp, "%H:%M:%S");
				strcat(tmp, pfmt);
				err = PGTYPEStimestamp_defmt_scan(&pstr, tmp, d, year, month, day, hour, minute, second, tz);
				free(tmp);
				return err;
			case 'u':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				if (scan_val.uint_val < 1 || scan_val.uint_val > 7)
					err = 1;
				break;
			case 'U':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				if (scan_val.uint_val > 53)
					err = 1;
				break;
			case 'V':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				if (scan_val.uint_val < 1 || scan_val.uint_val > 53)
					err = 1;
				break;
			case 'w':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				if (scan_val.uint_val > 6)
					err = 1;
				break;
			case 'W':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				if (scan_val.uint_val > 53)
					err = 1;
				break;
			case 'x':
			case 'X':
				
				break;
			case 'Y':
				pfmt++;
				scan_type = PGTYPES_TYPE_UINT;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				*year = scan_val.uint_val;
				break;
			case 'z':
				pfmt++;
				scan_type = PGTYPES_TYPE_STRING_MALLOCED;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);
				if (!err)
				{
					err = DecodeTimezone(scan_val.str_val, tz);
					free(scan_val.str_val);
				}
				break;
			case 'Z':
				pfmt++;
				scan_type = PGTYPES_TYPE_STRING_MALLOCED;
				err = pgtypes_defmt_scan(&scan_val, scan_type, &pstr, pfmt);

				
				for (j = 0; !err && j < szdatetktbl; j++)
				{
					if (pg_strcasecmp(datetktbl[j].token, scan_val.str_val) == 0)
					{
						
						*tz = -15 * MINS_PER_HOUR * datetktbl[j].value;
						break;
					}
				}
				free(scan_val.str_val);
				break;
			case '+':
				
				break;
			case '%':
				pfmt++;
				if (*pstr == '%')
					pstr++;
				else err = 1;
				break;
			default:
				err = 1;
		}
	}
	if (!err)
	{
		if (*second < 0)
			*second = 0;
		if (*minute < 0)
			*minute = 0;
		if (*hour < 0)
			*hour = 0;
		if (*day < 0)
		{
			err = 1;
			*day = 1;
		}
		if (*month < 0)
		{
			err = 1;
			*month = 1;
		}
		if (*year < 0)
		{
			err = 1;
			*year = 1970;
		}

		if (*second > 59)
		{
			err = 1;
			*second = 0;
		}
		if (*minute > 59)
		{
			err = 1;
			*minute = 0;
		}
		if (*hour > 24 ||		 (*hour == 24 && (*minute > 0 || *second > 0)))
		{
			err = 1;
			*hour = 0;
		}
		if (*month > MONTHS_PER_YEAR)
		{
			err = 1;
			*month = 1;
		}
		if (*day > day_tab[isleap(*year)][*month - 1])
		{
			*day = day_tab[isleap(*year)][*month - 1];
			err = 1;
		}

		tm.tm_sec = *second;
		tm.tm_min = *minute;
		tm.tm_hour = *hour;
		tm.tm_mday = *day;
		tm.tm_mon = *month;
		tm.tm_year = *year;

		tm2timestamp(&tm, 0, tz, d);
	}
	return err;
}


