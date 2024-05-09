


















enum path_delim { PATH_NONE, PATH_OPEN, PATH_CLOSED };

static int	point_inside(Point *p, int npts, Point *plist);
static int	lseg_crossing(double x, double y, double px, double py);
static BOX *box_construct(double x1, double x2, double y1, double y2);
static BOX *box_copy(BOX *box);
static BOX *box_fill(BOX *result, double x1, double x2, double y1, double y2);
static bool box_ov(BOX *box1, BOX *box2);
static double box_ht(BOX *box);
static double box_wd(BOX *box);
static double circle_ar(CIRCLE *circle);
static CIRCLE *circle_copy(CIRCLE *circle);
static LINE *line_construct_pm(Point *pt, double m);
static void line_construct_pts(LINE *line, Point *pt1, Point *pt2);
static bool lseg_intersect_internal(LSEG *l1, LSEG *l2);
static double lseg_dt(LSEG *l1, LSEG *l2);
static bool on_ps_internal(Point *pt, LSEG *lseg);
static void make_bound_box(POLYGON *poly);
static bool plist_same(int npts, Point *p1, Point *p2);
static Point *point_construct(double x, double y);
static Point *point_copy(Point *pt);
static int	single_decode(char *str, float8 *x, char **ss);
static int	single_encode(float8 x, char *str);
static int	pair_decode(char *str, float8 *x, float8 *y, char **s);
static int	pair_encode(float8 x, float8 y, char *str);
static int	pair_count(char *s, char delim);
static int	path_decode(int opentype, int npts, char *str, int *isopen, char **ss, Point *p);
static char *path_encode(enum path_delim path_delim, int npts, Point *pt);
static void statlseg_construct(LSEG *lseg, Point *pt1, Point *pt2);
static double box_ar(BOX *box);
static void box_cn(Point *center, BOX *box);
static Point *interpt_sl(LSEG *lseg, LINE *line);
static bool has_interpt_sl(LSEG *lseg, LINE *line);
static double dist_pl_internal(Point *pt, LINE *line);
static double dist_ps_internal(Point *pt, LSEG *lseg);
static Point *line_interpt_internal(LINE *l1, LINE *l2);
static bool lseg_inside_poly(Point *a, Point *b, POLYGON *poly, int start);
static Point *lseg_interpt_internal(LSEG *l1, LSEG *l2);



















static int single_decode(char *str, float8 *x, char **s)
{
	char	   *cp;

	if (!PointerIsValid(str))
		return FALSE;

	while (isspace((unsigned char) *str))
		str++;
	*x = strtod(str, &cp);

	printf("single_decode- (%x) try decoding %s to %g\n", (cp - str), str, *x);

	if (cp <= str)
		return FALSE;
	while (isspace((unsigned char) *cp))
		cp++;

	if (s != NULL)
		*s = cp;

	return TRUE;
}	

static int single_encode(float8 x, char *str)
{
	int			ndig = DBL_DIG + extra_float_digits;

	if (ndig < 1)
		ndig = 1;

	sprintf(str, "%.*g", ndig, x);
	return TRUE;
}	

static int pair_decode(char *str, float8 *x, float8 *y, char **s)
{
	int			has_delim;
	char	   *cp;

	if (!PointerIsValid(str))
		return FALSE;

	while (isspace((unsigned char) *str))
		str++;
	if ((has_delim = (*str == LDELIM)))
		str++;

	while (isspace((unsigned char) *str))
		str++;
	*x = strtod(str, &cp);
	if (cp <= str)
		return FALSE;
	while (isspace((unsigned char) *cp))
		cp++;
	if (*cp++ != DELIM)
		return FALSE;
	while (isspace((unsigned char) *cp))
		cp++;
	*y = strtod(cp, &str);
	if (str <= cp)
		return FALSE;
	while (isspace((unsigned char) *str))
		str++;
	if (has_delim)
	{
		if (*str != RDELIM)
			return FALSE;
		str++;
		while (isspace((unsigned char) *str))
			str++;
	}
	if (s != NULL)
		*s = str;

	return TRUE;
}

static int pair_encode(float8 x, float8 y, char *str)
{
	int			ndig = DBL_DIG + extra_float_digits;

	if (ndig < 1)
		ndig = 1;

	sprintf(str, "%.*g,%.*g", ndig, x, ndig, y);
	return TRUE;
}

static int path_decode(int opentype, int npts, char *str, int *isopen, char **ss, Point *p)
{
	int			depth = 0;
	char	   *s, *cp;
	int			i;

	s = str;
	while (isspace((unsigned char) *s))
		s++;
	if ((*isopen = (*s == LDELIM_EP)))
	{
		
		if (!opentype)
			return FALSE;
		depth++;
		s++;
		while (isspace((unsigned char) *s))
			s++;

	}
	else if (*s == LDELIM)
	{
		cp = (s + 1);
		while (isspace((unsigned char) *cp))
			cp++;
		if (*cp == LDELIM)
		{

			
			if (npts <= 1)
				return FALSE;

			depth++;
			s = cp;
		}
		else if (strrchr(s, LDELIM) == s)
		{
			depth++;
			s = cp;
		}
	}

	for (i = 0; i < npts; i++)
	{
		if (!pair_decode(s, &(p->x), &(p->y), &s))
			return FALSE;

		if (*s == DELIM)
			s++;
		p++;
	}

	while (depth > 0)
	{
		if ((*s == RDELIM)
			|| ((*s == RDELIM_EP) && (*isopen) && (depth == 1)))
		{
			depth--;
			s++;
			while (isspace((unsigned char) *s))
				s++;
		}
		else return FALSE;
	}
	*ss = s;

	return TRUE;
}	

static char * path_encode(enum path_delim path_delim, int npts, Point *pt)
{
	int			size = npts * (P_MAXLEN + 3) + 2;
	char	   *result;
	char	   *cp;
	int			i;

	
	if ((size - 2) / npts != (P_MAXLEN + 3))
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("too many points requested")));


	result = palloc(size);

	cp = result;
	switch (path_delim)
	{
		case PATH_CLOSED:
			*cp++ = LDELIM;
			break;
		case PATH_OPEN:
			*cp++ = LDELIM_EP;
			break;
		case PATH_NONE:
			break;
	}

	for (i = 0; i < npts; i++)
	{
		*cp++ = LDELIM;
		if (!pair_encode(pt->x, pt->y, cp))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not format \"path\" value")));


		cp += strlen(cp);
		*cp++ = RDELIM;
		*cp++ = DELIM;
		pt++;
	}
	cp--;
	switch (path_delim)
	{
		case PATH_CLOSED:
			*cp++ = RDELIM;
			break;
		case PATH_OPEN:
			*cp++ = RDELIM_EP;
			break;
		case PATH_NONE:
			break;
	}
	*cp = '\0';

	return result;
}	


static int pair_count(char *s, char delim)
{
	int			ndelim = 0;

	while ((s = strchr(s, delim)) != NULL)
	{
		ndelim++;
		s++;
	}
	return (ndelim % 2) ? ((ndelim + 1) / 2) : -1;
}







Datum box_in(PG_FUNCTION_ARGS)
{
	char	   *str = PG_GETARG_CSTRING(0);
	BOX		   *box = (BOX *) palloc(sizeof(BOX));
	int			isopen;
	char	   *s;
	double		x, y;

	if ((!path_decode(FALSE, 2, str, &isopen, &s, &(box->high)))
		|| (*s != '\0'))
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type box: \"%s\"", str)));


	
	if (box->high.x < box->low.x)
	{
		x = box->high.x;
		box->high.x = box->low.x;
		box->low.x = x;
	}
	if (box->high.y < box->low.y)
	{
		y = box->high.y;
		box->high.y = box->low.y;
		box->low.y = y;
	}

	PG_RETURN_BOX_P(box);
}


Datum box_out(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);

	PG_RETURN_CSTRING(path_encode(PATH_NONE, 2, &(box->high)));
}


Datum box_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	BOX		   *box;
	double		x, y;

	box = (BOX *) palloc(sizeof(BOX));

	box->high.x = pq_getmsgfloat8(buf);
	box->high.y = pq_getmsgfloat8(buf);
	box->low.x = pq_getmsgfloat8(buf);
	box->low.y = pq_getmsgfloat8(buf);

	
	if (box->high.x < box->low.x)
	{
		x = box->high.x;
		box->high.x = box->low.x;
		box->low.x = x;
	}
	if (box->high.y < box->low.y)
	{
		y = box->high.y;
		box->high.y = box->low.y;
		box->low.y = y;
	}

	PG_RETURN_BOX_P(box);
}


Datum box_send(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	StringInfoData buf;

	pq_begintypsend(&buf);
	pq_sendfloat8(&buf, box->high.x);
	pq_sendfloat8(&buf, box->high.y);
	pq_sendfloat8(&buf, box->low.x);
	pq_sendfloat8(&buf, box->low.y);
	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}



static BOX * box_construct(double x1, double x2, double y1, double y2)
{
	BOX		   *result = (BOX *) palloc(sizeof(BOX));

	return box_fill(result, x1, x2, y1, y2);
}



static BOX * box_fill(BOX *result, double x1, double x2, double y1, double y2)
{
	if (x1 > x2)
	{
		result->high.x = x1;
		result->low.x = x2;
	}
	else {
		result->high.x = x2;
		result->low.x = x1;
	}
	if (y1 > y2)
	{
		result->high.y = y1;
		result->low.y = y2;
	}
	else {
		result->high.y = y2;
		result->low.y = y1;
	}

	return result;
}



static BOX * box_copy(BOX *box)
{
	BOX		   *result = (BOX *) palloc(sizeof(BOX));

	memcpy((char *) result, (char *) box, sizeof(BOX));

	return result;
}





Datum box_same(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPeq(box1->high.x, box2->high.x) && FPeq(box1->low.x, box2->low.x) && FPeq(box1->high.y, box2->high.y) && FPeq(box1->low.y, box2->low.y));


}


Datum box_overlap(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(box_ov(box1, box2));
}

static bool box_ov(BOX *box1, BOX *box2)
{
	return (FPle(box1->low.x, box2->high.x) && FPle(box2->low.x, box1->high.x) && FPle(box1->low.y, box2->high.y) && FPle(box2->low.y, box1->high.y));


}


Datum box_left(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPlt(box1->high.x, box2->low.x));
}


Datum box_overleft(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPle(box1->high.x, box2->high.x));
}


Datum box_right(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPgt(box1->low.x, box2->high.x));
}


Datum box_overright(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPge(box1->low.x, box2->low.x));
}


Datum box_below(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPlt(box1->high.y, box2->low.y));
}


Datum box_overbelow(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPle(box1->high.y, box2->high.y));
}


Datum box_above(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPgt(box1->low.y, box2->high.y));
}


Datum box_overabove(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPge(box1->low.y, box2->low.y));
}


Datum box_contained(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPle(box1->high.x, box2->high.x) && FPge(box1->low.x, box2->low.x) && FPle(box1->high.y, box2->high.y) && FPge(box1->low.y, box2->low.y));


}


Datum box_contain(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPge(box1->high.x, box2->high.x) && FPle(box1->low.x, box2->low.x) && FPge(box1->high.y, box2->high.y) && FPle(box1->low.y, box2->low.y));


}



Datum box_below_eq(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPle(box1->high.y, box2->low.y));
}

Datum box_above_eq(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPge(box1->low.y, box2->high.y));
}



Datum box_lt(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPlt(box_ar(box1), box_ar(box2)));
}

Datum box_gt(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPgt(box_ar(box1), box_ar(box2)));
}

Datum box_eq(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPeq(box_ar(box1), box_ar(box2)));
}

Datum box_le(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPle(box_ar(box1), box_ar(box2)));
}

Datum box_ge(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(FPge(box_ar(box1), box_ar(box2)));
}





Datum box_area(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);

	PG_RETURN_FLOAT8(box_ar(box));
}



Datum box_width(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);

	PG_RETURN_FLOAT8(box->high.x - box->low.x);
}



Datum box_height(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);

	PG_RETURN_FLOAT8(box->high.y - box->low.y);
}



Datum box_distance(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);
	Point		a, b;

	box_cn(&a, box1);
	box_cn(&b, box2);

	PG_RETURN_FLOAT8(HYPOT(a.x - b.x, a.y - b.y));
}



Datum box_center(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	Point	   *result = (Point *) palloc(sizeof(Point));

	box_cn(result, box);

	PG_RETURN_POINT_P(result);
}



static double box_ar(BOX *box)
{
	return box_wd(box) * box_ht(box);
}



static void box_cn(Point *center, BOX *box)
{
	center->x = (box->high.x + box->low.x) / 2.0;
	center->y = (box->high.y + box->low.y) / 2.0;
}



static double box_wd(BOX *box)
{
	return box->high.x - box->low.x;
}



static double box_ht(BOX *box)
{
	return box->high.y - box->low.y;
}





Datum box_intersect(PG_FUNCTION_ARGS)
{
	BOX		   *box1 = PG_GETARG_BOX_P(0);
	BOX		   *box2 = PG_GETARG_BOX_P(1);
	BOX		   *result;

	if (!box_ov(box1, box2))
		PG_RETURN_NULL();

	result = (BOX *) palloc(sizeof(BOX));

	result->high.x = Min(box1->high.x, box2->high.x);
	result->low.x = Max(box1->low.x, box2->low.x);
	result->high.y = Min(box1->high.y, box2->high.y);
	result->low.y = Max(box1->low.y, box2->low.y);

	PG_RETURN_BOX_P(result);
}



Datum box_diagonal(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	LSEG	   *result = (LSEG *) palloc(sizeof(LSEG));

	statlseg_construct(result, &box->high, &box->low);

	PG_RETURN_LSEG_P(result);
}



static bool line_decode(const char *str, LINE *line)
{
	char	   *tail;

	while (isspace((unsigned char) *str))
		str++;
	if (*str++ != '{')
		return false;
	line->A = strtod(str, &tail);
	if (tail <= str)
		return false;
	str = tail;
	while (isspace((unsigned char) *str))
		str++;
	if (*str++ != DELIM)
		return false;
	line->B = strtod(str, &tail);
	if (tail <= str)
		return false;
	str = tail;
	while (isspace((unsigned char) *str))
		str++;
	if (*str++ != DELIM)
		return false;
	line->C = strtod(str, &tail);
	if (tail <= str)
		return false;
	str = tail;
	while (isspace((unsigned char) *str))
		str++;
	if (*str++ != '}')
		return false;
	while (isspace((unsigned char) *str))
		str++;
	if (*str)
		return false;

	return true;
}

Datum line_in(PG_FUNCTION_ARGS)
{
	char	   *str = PG_GETARG_CSTRING(0);
	LINE	   *line;
	LSEG		lseg;
	int			isopen;
	char	   *s;

	line = (LINE *) palloc(sizeof(LINE));

	if (path_decode(TRUE, 2, str, &isopen, &s, &(lseg.p[0])) && *s == '\0')
	{
		if (FPeq(lseg.p[0].x, lseg.p[1].x) && FPeq(lseg.p[0].y, lseg.p[1].y))
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid line specification: must be two distinct points")));


		line_construct_pts(line, &lseg.p[0], &lseg.p[1]);
	}
	else if (line_decode(str, line))
	{
		if (FPzero(line->A) && FPzero(line->B))
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid line specification: A and B cannot both be zero")));

	}
	else ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type line: \"%s\"", str)));



	PG_RETURN_LINE_P(line);
}


Datum line_out(PG_FUNCTION_ARGS)
{
	LINE	   *line = PG_GETARG_LINE_P(0);
	int			ndig = DBL_DIG + extra_float_digits;

	if (ndig < 1)
		ndig = 1;

	PG_RETURN_CSTRING(psprintf("{%.*g,%.*g,%.*g}", ndig, line->A, ndig, line->B, ndig, line->C));
}


Datum line_recv(PG_FUNCTION_ARGS)
{
	StringInfo  buf = (StringInfo) PG_GETARG_POINTER(0);
	LINE	   *line;

	line = (LINE *) palloc(sizeof(LINE));

	line->A = pq_getmsgfloat8(buf);
	line->B = pq_getmsgfloat8(buf);
	line->C = pq_getmsgfloat8(buf);

	PG_RETURN_LINE_P(line);
}


Datum line_send(PG_FUNCTION_ARGS)
{
	LINE	   *line = PG_GETARG_LINE_P(0);
	StringInfoData buf;

	pq_begintypsend(&buf);
	pq_sendfloat8(&buf, line->A);
	pq_sendfloat8(&buf, line->B);
	pq_sendfloat8(&buf, line->C);
	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}





static LINE * line_construct_pm(Point *pt, double m)
{
	LINE	   *result = (LINE *) palloc(sizeof(LINE));

	if (m == DBL_MAX)
	{
		
		result->A = -1;
		result->B = 0;
		result->C = pt->x;
	}
	else {
		
		result->A = m;
		result->B = -1.0;
		result->C = pt->y - m * pt->x;
	}

	return result;
}


static void line_construct_pts(LINE *line, Point *pt1, Point *pt2)
{
	if (FPeq(pt1->x, pt2->x))
	{							
		
		line->A = -1;
		line->B = 0;
		line->C = pt1->x;

		printf("line_construct_pts- line is vertical\n");

	}
	else if (FPeq(pt1->y, pt2->y))
	{							
		
		line->A = 0;
		line->B = -1;
		line->C = pt1->y;

		printf("line_construct_pts- line is horizontal\n");

	}
	else {
		
		line->A = (pt2->y - pt1->y) / (pt2->x - pt1->x);
		line->B = -1.0;
		line->C = pt1->y - line->A * pt1->x;
		
		if (line->C == 0.0)
			line->C = 0.0;

		printf("line_construct_pts- line is neither vertical nor horizontal (diffs x=%.*g, y=%.*g\n", DBL_DIG, (pt2->x - pt1->x), DBL_DIG, (pt2->y - pt1->y));

	}
}


Datum line_construct_pp(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);
	LINE	   *result = (LINE *) palloc(sizeof(LINE));

	line_construct_pts(result, pt1, pt2);
	PG_RETURN_LINE_P(result);
}




Datum line_intersect(PG_FUNCTION_ARGS)
{
	LINE	   *l1 = PG_GETARG_LINE_P(0);
	LINE	   *l2 = PG_GETARG_LINE_P(1);

	PG_RETURN_BOOL(!DatumGetBool(DirectFunctionCall2(line_parallel, LinePGetDatum(l1), LinePGetDatum(l2))));

}

Datum line_parallel(PG_FUNCTION_ARGS)
{
	LINE	   *l1 = PG_GETARG_LINE_P(0);
	LINE	   *l2 = PG_GETARG_LINE_P(1);

	if (FPzero(l1->B))
		PG_RETURN_BOOL(FPzero(l2->B));

	PG_RETURN_BOOL(FPeq(l2->A, l1->A * (l2->B / l1->B)));
}

Datum line_perp(PG_FUNCTION_ARGS)
{
	LINE	   *l1 = PG_GETARG_LINE_P(0);
	LINE	   *l2 = PG_GETARG_LINE_P(1);

	if (FPzero(l1->A))
		PG_RETURN_BOOL(FPzero(l2->B));
	else if (FPzero(l1->B))
		PG_RETURN_BOOL(FPzero(l2->A));

	PG_RETURN_BOOL(FPeq(((l1->A * l2->B) / (l1->B * l2->A)), -1.0));
}

Datum line_vertical(PG_FUNCTION_ARGS)
{
	LINE	   *line = PG_GETARG_LINE_P(0);

	PG_RETURN_BOOL(FPzero(line->B));
}

Datum line_horizontal(PG_FUNCTION_ARGS)
{
	LINE	   *line = PG_GETARG_LINE_P(0);

	PG_RETURN_BOOL(FPzero(line->A));
}

Datum line_eq(PG_FUNCTION_ARGS)
{
	LINE	   *l1 = PG_GETARG_LINE_P(0);
	LINE	   *l2 = PG_GETARG_LINE_P(1);
	double		k;

	if (!FPzero(l2->A))
		k = l1->A / l2->A;
	else if (!FPzero(l2->B))
		k = l1->B / l2->B;
	else if (!FPzero(l2->C))
		k = l1->C / l2->C;
	else k = 1.0;

	PG_RETURN_BOOL(FPeq(l1->A, k * l2->A) && FPeq(l1->B, k * l2->B) && FPeq(l1->C, k * l2->C));

}





Datum line_distance(PG_FUNCTION_ARGS)
{
	LINE	   *l1 = PG_GETARG_LINE_P(0);
	LINE	   *l2 = PG_GETARG_LINE_P(1);
	float8		result;
	Point	   *tmp;

	if (!DatumGetBool(DirectFunctionCall2(line_parallel, LinePGetDatum(l1), LinePGetDatum(l2))))

		PG_RETURN_FLOAT8(0.0);
	if (FPzero(l1->B))			
		PG_RETURN_FLOAT8(fabs(l1->C - l2->C));
	tmp = point_construct(0.0, l1->C);
	result = dist_pl_internal(tmp, l2);
	PG_RETURN_FLOAT8(result);
}


Datum line_interpt(PG_FUNCTION_ARGS)
{
	LINE	   *l1 = PG_GETARG_LINE_P(0);
	LINE	   *l2 = PG_GETARG_LINE_P(1);
	Point	   *result;

	result = line_interpt_internal(l1, l2);

	if (result == NULL)
		PG_RETURN_NULL();
	PG_RETURN_POINT_P(result);
}


static Point * line_interpt_internal(LINE *l1, LINE *l2)
{
	Point	   *result;
	double		x, y;

	
	if (DatumGetBool(DirectFunctionCall2(line_parallel, LinePGetDatum(l1), LinePGetDatum(l2))))

		return NULL;

	if (FPzero(l1->B))			
	{
		x = l1->C;
		y = (l2->A * x + l2->C);
	}
	else if (FPzero(l2->B))		
	{
		x = l2->C;
		y = (l1->A * x + l1->C);
	}
	else {
		x = (l1->C - l2->C) / (l2->A - l1->A);
		y = (l1->A * x + l1->C);
	}
	result = point_construct(x, y);


	printf("line_interpt- lines are A=%.*g, B=%.*g, C=%.*g, A=%.*g, B=%.*g, C=%.*g\n", DBL_DIG, l1->A, DBL_DIG, l1->B, DBL_DIG, l1->C, DBL_DIG, l2->A, DBL_DIG, l2->B, DBL_DIG, l2->C);
	printf("line_interpt- lines intersect at (%.*g,%.*g)\n", DBL_DIG, x, DBL_DIG, y);


	return result;
}






Datum path_area(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P(0);
	double		area = 0.0;
	int			i, j;

	if (!path->closed)
		PG_RETURN_NULL();

	for (i = 0; i < path->npts; i++)
	{
		j = (i + 1) % path->npts;
		area += path->p[i].x * path->p[j].y;
		area -= path->p[i].y * path->p[j].x;
	}

	area *= 0.5;
	PG_RETURN_FLOAT8(area < 0.0 ? -area : area);
}


Datum path_in(PG_FUNCTION_ARGS)
{
	char	   *str = PG_GETARG_CSTRING(0);
	PATH	   *path;
	int			isopen;
	char	   *s;
	int			npts;
	int			size;
	int			depth = 0;

	if ((npts = pair_count(str, ',')) <= 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type path: \"%s\"", str)));


	s = str;
	while (isspace((unsigned char) *s))
		s++;

	
	if ((*s == LDELIM) && (strrchr(s, LDELIM) == s))
	{
		s++;
		depth++;
	}

	size = offsetof(PATH, p[0]) +sizeof(path->p[0]) * npts;
	path = (PATH *) palloc(size);

	SET_VARSIZE(path, size);
	path->npts = npts;

	if ((!path_decode(TRUE, npts, s, &isopen, &s, &(path->p[0])))
	&& (!((depth == 0) && (*s == '\0'))) && !((depth >= 1) && (*s == RDELIM)))
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type path: \"%s\"", str)));


	path->closed = (!isopen);
	
	path->dummy = 0;

	PG_RETURN_PATH_P(path);
}


Datum path_out(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P(0);

	PG_RETURN_CSTRING(path_encode(path->closed ? PATH_CLOSED : PATH_OPEN, path->npts, path->p));
}


Datum path_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	PATH	   *path;
	int			closed;
	int32		npts;
	int32		i;
	int			size;

	closed = pq_getmsgbyte(buf);
	npts = pq_getmsgint(buf, sizeof(int32));
	if (npts <= 0 || npts >= (int32) ((INT_MAX - offsetof(PATH, p[0])) / sizeof(Point)))
		ereport(ERROR, (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION), errmsg("invalid number of points in external \"path\" value")));


	size = offsetof(PATH, p[0]) +sizeof(path->p[0]) * npts;
	path = (PATH *) palloc(size);

	SET_VARSIZE(path, size);
	path->npts = npts;
	path->closed = (closed ? 1 : 0);
	
	path->dummy = 0;

	for (i = 0; i < npts; i++)
	{
		path->p[i].x = pq_getmsgfloat8(buf);
		path->p[i].y = pq_getmsgfloat8(buf);
	}

	PG_RETURN_PATH_P(path);
}


Datum path_send(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P(0);
	StringInfoData buf;
	int32		i;

	pq_begintypsend(&buf);
	pq_sendbyte(&buf, path->closed ? 1 : 0);
	pq_sendint(&buf, path->npts, sizeof(int32));
	for (i = 0; i < path->npts; i++)
	{
		pq_sendfloat8(&buf, path->p[i].x);
		pq_sendfloat8(&buf, path->p[i].y);
	}
	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}




Datum path_n_lt(PG_FUNCTION_ARGS)
{
	PATH	   *p1 = PG_GETARG_PATH_P(0);
	PATH	   *p2 = PG_GETARG_PATH_P(1);

	PG_RETURN_BOOL(p1->npts < p2->npts);
}

Datum path_n_gt(PG_FUNCTION_ARGS)
{
	PATH	   *p1 = PG_GETARG_PATH_P(0);
	PATH	   *p2 = PG_GETARG_PATH_P(1);

	PG_RETURN_BOOL(p1->npts > p2->npts);
}

Datum path_n_eq(PG_FUNCTION_ARGS)
{
	PATH	   *p1 = PG_GETARG_PATH_P(0);
	PATH	   *p2 = PG_GETARG_PATH_P(1);

	PG_RETURN_BOOL(p1->npts == p2->npts);
}

Datum path_n_le(PG_FUNCTION_ARGS)
{
	PATH	   *p1 = PG_GETARG_PATH_P(0);
	PATH	   *p2 = PG_GETARG_PATH_P(1);

	PG_RETURN_BOOL(p1->npts <= p2->npts);
}

Datum path_n_ge(PG_FUNCTION_ARGS)
{
	PATH	   *p1 = PG_GETARG_PATH_P(0);
	PATH	   *p2 = PG_GETARG_PATH_P(1);

	PG_RETURN_BOOL(p1->npts >= p2->npts);
}



Datum path_isclosed(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P(0);

	PG_RETURN_BOOL(path->closed);
}

Datum path_isopen(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P(0);

	PG_RETURN_BOOL(!path->closed);
}

Datum path_npoints(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P(0);

	PG_RETURN_INT32(path->npts);
}


Datum path_close(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P_COPY(0);

	path->closed = TRUE;

	PG_RETURN_PATH_P(path);
}

Datum path_open(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P_COPY(0);

	path->closed = FALSE;

	PG_RETURN_PATH_P(path);
}



Datum path_inter(PG_FUNCTION_ARGS)
{
	PATH	   *p1 = PG_GETARG_PATH_P(0);
	PATH	   *p2 = PG_GETARG_PATH_P(1);
	BOX			b1, b2;
	int			i, j;
	LSEG		seg1, seg2;

	if (p1->npts <= 0 || p2->npts <= 0)
		PG_RETURN_BOOL(false);

	b1.high.x = b1.low.x = p1->p[0].x;
	b1.high.y = b1.low.y = p1->p[0].y;
	for (i = 1; i < p1->npts; i++)
	{
		b1.high.x = Max(p1->p[i].x, b1.high.x);
		b1.high.y = Max(p1->p[i].y, b1.high.y);
		b1.low.x = Min(p1->p[i].x, b1.low.x);
		b1.low.y = Min(p1->p[i].y, b1.low.y);
	}
	b2.high.x = b2.low.x = p2->p[0].x;
	b2.high.y = b2.low.y = p2->p[0].y;
	for (i = 1; i < p2->npts; i++)
	{
		b2.high.x = Max(p2->p[i].x, b2.high.x);
		b2.high.y = Max(p2->p[i].y, b2.high.y);
		b2.low.x = Min(p2->p[i].x, b2.low.x);
		b2.low.y = Min(p2->p[i].y, b2.low.y);
	}
	if (!box_ov(&b1, &b2))
		PG_RETURN_BOOL(false);

	
	for (i = 0; i < p1->npts; i++)
	{
		int			iprev;

		if (i > 0)
			iprev = i - 1;
		else {
			if (!p1->closed)
				continue;
			iprev = p1->npts - 1;		
		}

		for (j = 0; j < p2->npts; j++)
		{
			int			jprev;

			if (j > 0)
				jprev = j - 1;
			else {
				if (!p2->closed)
					continue;
				jprev = p2->npts - 1;	
			}

			statlseg_construct(&seg1, &p1->p[iprev], &p1->p[i]);
			statlseg_construct(&seg2, &p2->p[jprev], &p2->p[j]);
			if (lseg_intersect_internal(&seg1, &seg2))
				PG_RETURN_BOOL(true);
		}
	}

	
	PG_RETURN_BOOL(false);
}


Datum path_distance(PG_FUNCTION_ARGS)
{
	PATH	   *p1 = PG_GETARG_PATH_P(0);
	PATH	   *p2 = PG_GETARG_PATH_P(1);
	float8		min = 0.0;		
	bool		have_min = false;
	float8		tmp;
	int			i, j;
	LSEG		seg1, seg2;

	for (i = 0; i < p1->npts; i++)
	{
		int			iprev;

		if (i > 0)
			iprev = i - 1;
		else {
			if (!p1->closed)
				continue;
			iprev = p1->npts - 1;		
		}

		for (j = 0; j < p2->npts; j++)
		{
			int			jprev;

			if (j > 0)
				jprev = j - 1;
			else {
				if (!p2->closed)
					continue;
				jprev = p2->npts - 1;	
			}

			statlseg_construct(&seg1, &p1->p[iprev], &p1->p[i]);
			statlseg_construct(&seg2, &p2->p[jprev], &p2->p[j]);

			tmp = DatumGetFloat8(DirectFunctionCall2(lseg_distance, LsegPGetDatum(&seg1), LsegPGetDatum(&seg2)));

			if (!have_min || tmp < min)
			{
				min = tmp;
				have_min = true;
			}
		}
	}

	if (!have_min)
		PG_RETURN_NULL();

	PG_RETURN_FLOAT8(min);
}




Datum path_length(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P(0);
	float8		result = 0.0;
	int			i;

	for (i = 0; i < path->npts; i++)
	{
		int			iprev;

		if (i > 0)
			iprev = i - 1;
		else {
			if (!path->closed)
				continue;
			iprev = path->npts - 1;		
		}

		result += point_dt(&path->p[iprev], &path->p[i]);
	}

	PG_RETURN_FLOAT8(result);
}





Datum point_in(PG_FUNCTION_ARGS)
{
	char	   *str = PG_GETARG_CSTRING(0);
	Point	   *point;
	double		x, y;
	char	   *s;

	if (!pair_decode(str, &x, &y, &s) || (*s != '\0'))
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type point: \"%s\"", str)));


	point = (Point *) palloc(sizeof(Point));

	point->x = x;
	point->y = y;

	PG_RETURN_POINT_P(point);
}

Datum point_out(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);

	PG_RETURN_CSTRING(path_encode(PATH_NONE, 1, pt));
}


Datum point_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	Point	   *point;

	point = (Point *) palloc(sizeof(Point));
	point->x = pq_getmsgfloat8(buf);
	point->y = pq_getmsgfloat8(buf);
	PG_RETURN_POINT_P(point);
}


Datum point_send(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	StringInfoData buf;

	pq_begintypsend(&buf);
	pq_sendfloat8(&buf, pt->x);
	pq_sendfloat8(&buf, pt->y);
	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}


static Point * point_construct(double x, double y)
{
	Point	   *result = (Point *) palloc(sizeof(Point));

	result->x = x;
	result->y = y;
	return result;
}


static Point * point_copy(Point *pt)
{
	Point	   *result;

	if (!PointerIsValid(pt))
		return NULL;

	result = (Point *) palloc(sizeof(Point));

	result->x = pt->x;
	result->y = pt->y;
	return result;
}




Datum point_left(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(FPlt(pt1->x, pt2->x));
}

Datum point_right(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(FPgt(pt1->x, pt2->x));
}

Datum point_above(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(FPgt(pt1->y, pt2->y));
}

Datum point_below(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(FPlt(pt1->y, pt2->y));
}

Datum point_vert(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(FPeq(pt1->x, pt2->x));
}

Datum point_horiz(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(FPeq(pt1->y, pt2->y));
}

Datum point_eq(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(FPeq(pt1->x, pt2->x) && FPeq(pt1->y, pt2->y));
}

Datum point_ne(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(FPne(pt1->x, pt2->x) || FPne(pt1->y, pt2->y));
}



Datum point_distance(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_FLOAT8(HYPOT(pt1->x - pt2->x, pt1->y - pt2->y));
}

double point_dt(Point *pt1, Point *pt2)
{

	printf("point_dt- segment (%f,%f),(%f,%f) length is %f\n", pt1->x, pt1->y, pt2->x, pt2->y, HYPOT(pt1->x - pt2->x, pt1->y - pt2->y));

	return HYPOT(pt1->x - pt2->x, pt1->y - pt2->y);
}

Datum point_slope(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);

	PG_RETURN_FLOAT8(point_sl(pt1, pt2));
}


double point_sl(Point *pt1, Point *pt2)
{
	return (FPeq(pt1->x, pt2->x)
			? (double) DBL_MAX : (pt1->y - pt2->y) / (pt1->x - pt2->x));
}






Datum lseg_in(PG_FUNCTION_ARGS)
{
	char	   *str = PG_GETARG_CSTRING(0);
	LSEG	   *lseg;
	int			isopen;
	char	   *s;

	lseg = (LSEG *) palloc(sizeof(LSEG));

	if ((!path_decode(TRUE, 2, str, &isopen, &s, &(lseg->p[0])))
		|| (*s != '\0'))
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type lseg: \"%s\"", str)));



	lseg->m = point_sl(&lseg->p[0], &lseg->p[1]);


	PG_RETURN_LSEG_P(lseg);
}


Datum lseg_out(PG_FUNCTION_ARGS)
{
	LSEG	   *ls = PG_GETARG_LSEG_P(0);

	PG_RETURN_CSTRING(path_encode(PATH_OPEN, 2, (Point *) &(ls->p[0])));
}


Datum lseg_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	LSEG	   *lseg;

	lseg = (LSEG *) palloc(sizeof(LSEG));

	lseg->p[0].x = pq_getmsgfloat8(buf);
	lseg->p[0].y = pq_getmsgfloat8(buf);
	lseg->p[1].x = pq_getmsgfloat8(buf);
	lseg->p[1].y = pq_getmsgfloat8(buf);


	lseg->m = point_sl(&lseg->p[0], &lseg->p[1]);


	PG_RETURN_LSEG_P(lseg);
}


Datum lseg_send(PG_FUNCTION_ARGS)
{
	LSEG	   *ls = PG_GETARG_LSEG_P(0);
	StringInfoData buf;

	pq_begintypsend(&buf);
	pq_sendfloat8(&buf, ls->p[0].x);
	pq_sendfloat8(&buf, ls->p[0].y);
	pq_sendfloat8(&buf, ls->p[1].x);
	pq_sendfloat8(&buf, ls->p[1].y);
	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}



Datum lseg_construct(PG_FUNCTION_ARGS)
{
	Point	   *pt1 = PG_GETARG_POINT_P(0);
	Point	   *pt2 = PG_GETARG_POINT_P(1);
	LSEG	   *result = (LSEG *) palloc(sizeof(LSEG));

	result->p[0].x = pt1->x;
	result->p[0].y = pt1->y;
	result->p[1].x = pt2->x;
	result->p[1].y = pt2->y;


	result->m = point_sl(pt1, pt2);


	PG_RETURN_LSEG_P(result);
}


static void statlseg_construct(LSEG *lseg, Point *pt1, Point *pt2)
{
	lseg->p[0].x = pt1->x;
	lseg->p[0].y = pt1->y;
	lseg->p[1].x = pt2->x;
	lseg->p[1].y = pt2->y;


	lseg->m = point_sl(pt1, pt2);

}

Datum lseg_length(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);

	PG_RETURN_FLOAT8(point_dt(&lseg->p[0], &lseg->p[1]));
}




Datum lseg_intersect(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);

	PG_RETURN_BOOL(lseg_intersect_internal(l1, l2));
}

static bool lseg_intersect_internal(LSEG *l1, LSEG *l2)
{
	LINE		ln;
	Point	   *interpt;
	bool		retval;

	line_construct_pts(&ln, &l2->p[0], &l2->p[1]);
	interpt = interpt_sl(l1, &ln);

	if (interpt != NULL && on_ps_internal(interpt, l2))
		retval = true;			
	else retval = false;
	return retval;
}

Datum lseg_parallel(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);


	PG_RETURN_BOOL(FPeq(l1->m, l2->m));

	PG_RETURN_BOOL(FPeq(point_sl(&l1->p[0], &l1->p[1]), point_sl(&l2->p[0], &l2->p[1])));
}


Datum lseg_perp(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);
	double		m1, m2;

	m1 = point_sl(&(l1->p[0]), &(l1->p[1]));
	m2 = point_sl(&(l2->p[0]), &(l2->p[1]));


	printf("lseg_perp- slopes are %g and %g\n", m1, m2);

	if (FPzero(m1))
		PG_RETURN_BOOL(FPeq(m2, DBL_MAX));
	else if (FPzero(m2))
		PG_RETURN_BOOL(FPeq(m1, DBL_MAX));

	PG_RETURN_BOOL(FPeq(m1 / m2, -1.0));
}

Datum lseg_vertical(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);

	PG_RETURN_BOOL(FPeq(lseg->p[0].x, lseg->p[1].x));
}

Datum lseg_horizontal(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);

	PG_RETURN_BOOL(FPeq(lseg->p[0].y, lseg->p[1].y));
}


Datum lseg_eq(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);

	PG_RETURN_BOOL(FPeq(l1->p[0].x, l2->p[0].x) && FPeq(l1->p[0].y, l2->p[0].y) && FPeq(l1->p[1].x, l2->p[1].x) && FPeq(l1->p[1].y, l2->p[1].y));


}

Datum lseg_ne(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);

	PG_RETURN_BOOL(!FPeq(l1->p[0].x, l2->p[0].x) || !FPeq(l1->p[0].y, l2->p[0].y) || !FPeq(l1->p[1].x, l2->p[1].x) || !FPeq(l1->p[1].y, l2->p[1].y));


}

Datum lseg_lt(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);

	PG_RETURN_BOOL(FPlt(point_dt(&l1->p[0], &l1->p[1]), point_dt(&l2->p[0], &l2->p[1])));
}

Datum lseg_le(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);

	PG_RETURN_BOOL(FPle(point_dt(&l1->p[0], &l1->p[1]), point_dt(&l2->p[0], &l2->p[1])));
}

Datum lseg_gt(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);

	PG_RETURN_BOOL(FPgt(point_dt(&l1->p[0], &l1->p[1]), point_dt(&l2->p[0], &l2->p[1])));
}

Datum lseg_ge(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);

	PG_RETURN_BOOL(FPge(point_dt(&l1->p[0], &l1->p[1]), point_dt(&l2->p[0], &l2->p[1])));
}





Datum lseg_distance(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);

	PG_RETURN_FLOAT8(lseg_dt(l1, l2));
}


static double lseg_dt(LSEG *l1, LSEG *l2)
{
	double		result, d;

	if (lseg_intersect_internal(l1, l2))
		return 0.0;

	d = dist_ps_internal(&l1->p[0], l2);
	result = d;
	d = dist_ps_internal(&l1->p[1], l2);
	result = Min(result, d);
	d = dist_ps_internal(&l2->p[0], l1);
	result = Min(result, d);
	d = dist_ps_internal(&l2->p[1], l1);
	result = Min(result, d);

	return result;
}


Datum lseg_center(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	Point	   *result;

	result = (Point *) palloc(sizeof(Point));

	result->x = (lseg->p[0].x + lseg->p[1].x) / 2.0;
	result->y = (lseg->p[0].y + lseg->p[1].y) / 2.0;

	PG_RETURN_POINT_P(result);
}

static Point * lseg_interpt_internal(LSEG *l1, LSEG *l2)
{
	Point	   *result;
	LINE		tmp1, tmp2;

	
	line_construct_pts(&tmp1, &l1->p[0], &l1->p[1]);
	line_construct_pts(&tmp2, &l2->p[0], &l2->p[1]);
	result = line_interpt_internal(&tmp1, &tmp2);
	if (!PointerIsValid(result))
		return NULL;

	
	if (!on_ps_internal(result, l1) || !on_ps_internal(result, l2))
	{
		pfree(result);
		return NULL;
	}

	
	if ((FPeq(l1->p[0].x, l2->p[0].x) && FPeq(l1->p[0].y, l2->p[0].y)) || (FPeq(l1->p[0].x, l2->p[1].x) && FPeq(l1->p[0].y, l2->p[1].y)))
	{
		result->x = l1->p[0].x;
		result->y = l1->p[0].y;
	}
	else if ((FPeq(l1->p[1].x, l2->p[0].x) && FPeq(l1->p[1].y, l2->p[0].y)) || (FPeq(l1->p[1].x, l2->p[1].x) && FPeq(l1->p[1].y, l2->p[1].y)))
	{
		result->x = l1->p[1].x;
		result->y = l1->p[1].y;
	}

	return result;
}


Datum lseg_interpt(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);
	Point	   *result;

	result = lseg_interpt_internal(l1, l2);
	if (!PointerIsValid(result))
		PG_RETURN_NULL();

	PG_RETURN_POINT_P(result);
}





Datum dist_pl(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	LINE	   *line = PG_GETARG_LINE_P(1);

	PG_RETURN_FLOAT8(dist_pl_internal(pt, line));
}

static double dist_pl_internal(Point *pt, LINE *line)
{
	return fabs((line->A * pt->x + line->B * pt->y + line->C) / HYPOT(line->A, line->B));
}

Datum dist_ps(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	LSEG	   *lseg = PG_GETARG_LSEG_P(1);

	PG_RETURN_FLOAT8(dist_ps_internal(pt, lseg));
}

static double dist_ps_internal(Point *pt, LSEG *lseg)
{
	double		m;				
	LINE	   *ln;
	double		result, tmpdist;
	Point	   *ip;

	
	if (lseg->p[1].x == lseg->p[0].x)
		m = 0;
	else if (lseg->p[1].y == lseg->p[0].y)
		m = (double) DBL_MAX;	
	else m = (lseg->p[0].x - lseg->p[1].x) / (lseg->p[1].y - lseg->p[0].y);
	ln = line_construct_pm(pt, m);


	printf("dist_ps- line is A=%g B=%g C=%g from (point) slope (%f,%f) %g\n", ln->A, ln->B, ln->C, pt->x, pt->y, m);


	

	
	if ((ip = interpt_sl(lseg, ln)) != NULL)
	{
		
		result = point_dt(pt, ip);

		printf("dist_ps- distance is %f to intersection point is (%f,%f)\n", result, ip->x, ip->y);

	}
	else {
		
		result = point_dt(pt, &lseg->p[0]);
		tmpdist = point_dt(pt, &lseg->p[1]);
		if (tmpdist < result)
			result = tmpdist;
	}

	return result;
}


Datum dist_ppath(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	PATH	   *path = PG_GETARG_PATH_P(1);
	float8		result = 0.0;	
	bool		have_min = false;
	float8		tmp;
	int			i;
	LSEG		lseg;

	switch (path->npts)
	{
		case 0:
			
			PG_RETURN_NULL();
		case 1:
			
			result = point_dt(pt, &path->p[0]);
			break;
		default:
			
			Assert(path->npts > 1);

			
			for (i = 0; i < path->npts; i++)
			{
				int			iprev;

				if (i > 0)
					iprev = i - 1;
				else {
					if (!path->closed)
						continue;
					iprev = path->npts - 1;		
				}

				statlseg_construct(&lseg, &path->p[iprev], &path->p[i]);
				tmp = dist_ps_internal(pt, &lseg);
				if (!have_min || tmp < result)
				{
					result = tmp;
					have_min = true;
				}
			}
			break;
	}
	PG_RETURN_FLOAT8(result);
}

Datum dist_pb(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);
	float8		result;
	Point	   *near;

	near = DatumGetPointP(DirectFunctionCall2(close_pb, PointPGetDatum(pt), BoxPGetDatum(box)));

	result = point_dt(near, pt);

	PG_RETURN_FLOAT8(result);
}


Datum dist_sl(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	LINE	   *line = PG_GETARG_LINE_P(1);
	float8		result, d2;

	if (has_interpt_sl(lseg, line))
		result = 0.0;
	else {
		result = dist_pl_internal(&lseg->p[0], line);
		d2 = dist_pl_internal(&lseg->p[1], line);
		
		if (d2 > result)
			result = d2;
	}

	PG_RETURN_FLOAT8(result);
}


Datum dist_sb(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);
	Point	   *tmp;
	Datum		result;

	tmp = DatumGetPointP(DirectFunctionCall2(close_sb, LsegPGetDatum(lseg), BoxPGetDatum(box)));

	result = DirectFunctionCall2(dist_pb, PointPGetDatum(tmp), BoxPGetDatum(box));


	PG_RETURN_DATUM(result);
}


Datum dist_lb(PG_FUNCTION_ARGS)
{

	LINE	   *line = PG_GETARG_LINE_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);


	
	ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("function \"dist_lb\" not implemented")));


	PG_RETURN_NULL();
}


Datum dist_cpoly(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	POLYGON    *poly = PG_GETARG_POLYGON_P(1);
	float8		result;
	float8		d;
	int			i;
	LSEG		seg;

	if (point_inside(&(circle->center), poly->npts, poly->p) != 0)
	{

		printf("dist_cpoly- center inside of polygon\n");

		PG_RETURN_FLOAT8(0.0);
	}

	
	seg.p[0].x = poly->p[0].x;
	seg.p[0].y = poly->p[0].y;
	seg.p[1].x = poly->p[poly->npts - 1].x;
	seg.p[1].y = poly->p[poly->npts - 1].y;
	result = dist_ps_internal(&circle->center, &seg);

	printf("dist_cpoly- segment 0/n distance is %f\n", result);


	
	for (i = 0; (i < poly->npts - 1); i++)
	{
		seg.p[0].x = poly->p[i].x;
		seg.p[0].y = poly->p[i].y;
		seg.p[1].x = poly->p[i + 1].x;
		seg.p[1].y = poly->p[i + 1].y;
		d = dist_ps_internal(&circle->center, &seg);

		printf("dist_cpoly- segment %d distance is %f\n", (i + 1), d);

		if (d < result)
			result = d;
	}

	result -= circle->radius;
	if (result < 0)
		result = 0;

	PG_RETURN_FLOAT8(result);
}





static Point * interpt_sl(LSEG *lseg, LINE *line)
{
	LINE		tmp;
	Point	   *p;

	line_construct_pts(&tmp, &lseg->p[0], &lseg->p[1]);
	p = line_interpt_internal(&tmp, line);

	printf("interpt_sl- segment is (%.*g %.*g) (%.*g %.*g)\n", DBL_DIG, lseg->p[0].x, DBL_DIG, lseg->p[0].y, DBL_DIG, lseg->p[1].x, DBL_DIG, lseg->p[1].y);
	printf("interpt_sl- segment becomes line A=%.*g B=%.*g C=%.*g\n", DBL_DIG, tmp.A, DBL_DIG, tmp.B, DBL_DIG, tmp.C);

	if (PointerIsValid(p))
	{

		printf("interpt_sl- intersection point is (%.*g %.*g)\n", DBL_DIG, p->x, DBL_DIG, p->y);

		if (on_ps_internal(p, lseg))
		{

			printf("interpt_sl- intersection point is on segment\n");

		}
		else p = NULL;
	}

	return p;
}


static bool has_interpt_sl(LSEG *lseg, LINE *line)
{
	Point	   *tmp;

	tmp = interpt_sl(lseg, line);
	if (tmp)
		return true;
	return false;
}




Datum close_pl(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	LINE	   *line = PG_GETARG_LINE_P(1);
	Point	   *result;
	LINE	   *tmp;
	double		invm;

	result = (Point *) palloc(sizeof(Point));

	if (FPzero(line->B))		
	{
		result->x = line->C;
		result->y = pt->y;
		PG_RETURN_POINT_P(result);
	}
	if (FPzero(line->A))		
	{
		result->x = pt->x;
		result->y = line->C;
		PG_RETURN_POINT_P(result);
	}
	

	
	invm = line->B / line->A;
	tmp = line_construct_pm(pt, invm);
	result = line_interpt_internal(tmp, line);
	Assert(result != NULL);
	PG_RETURN_POINT_P(result);
}



Datum close_ps(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	LSEG	   *lseg = PG_GETARG_LSEG_P(1);
	Point	   *result = NULL;
	LINE	   *tmp;
	double		invm;
	int			xh, yh;


	printf("close_sp:pt->x %f pt->y %f\nlseg(0).x %f lseg(0).y %f  lseg(1).x %f lseg(1).y %f\n", pt->x, pt->y, lseg->p[0].x, lseg->p[0].y, lseg->p[1].x, lseg->p[1].y);



	
	
	xh = lseg->p[0].x < lseg->p[1].x;
	yh = lseg->p[0].y < lseg->p[1].y;

	if (FPeq(lseg->p[0].x, lseg->p[1].x))		
	{

		printf("close_ps- segment is vertical\n");

		
		if (pt->y < lseg->p[!yh].y)
			result = point_copy(&lseg->p[!yh]); 
		else if (pt->y > lseg->p[yh].y)
			result = point_copy(&lseg->p[yh]);	
		if (result != NULL)
			PG_RETURN_POINT_P(result);

		

		result = (Point *) palloc(sizeof(Point));
		result->x = lseg->p[0].x;
		result->y = pt->y;
		PG_RETURN_POINT_P(result);
	}
	else if (FPeq(lseg->p[0].y, lseg->p[1].y))	
	{

		printf("close_ps- segment is horizontal\n");

		
		if (pt->x < lseg->p[!xh].x)
			result = point_copy(&lseg->p[!xh]); 
		else if (pt->x > lseg->p[xh].x)
			result = point_copy(&lseg->p[xh]);	
		if (result != NULL)
			PG_RETURN_POINT_P(result);

		
		result = (Point *) palloc(sizeof(Point));
		result->x = pt->x;
		result->y = lseg->p[0].y;
		PG_RETURN_POINT_P(result);
	}

	

	invm = -1.0 / point_sl(&(lseg->p[0]), &(lseg->p[1]));
	tmp = line_construct_pm(&lseg->p[!yh], invm);		
	if (pt->y < (tmp->A * pt->x + tmp->C))
	{							
		result = point_copy(&lseg->p[!yh]);		

		printf("close_ps below: tmp A %f  B %f   C %f    m %f\n", tmp->A, tmp->B, tmp->C, tmp->m);

		PG_RETURN_POINT_P(result);
	}
	tmp = line_construct_pm(&lseg->p[yh], invm);		
	if (pt->y > (tmp->A * pt->x + tmp->C))
	{							
		result = point_copy(&lseg->p[yh]);		

		printf("close_ps above: tmp A %f  B %f   C %f    m %f\n", tmp->A, tmp->B, tmp->C, tmp->m);

		PG_RETURN_POINT_P(result);
	}

	
	tmp = line_construct_pm(pt, invm);

	printf("close_ps- tmp A %f  B %f   C %f    m %f\n", tmp->A, tmp->B, tmp->C, tmp->m);

	result = interpt_sl(lseg, tmp);
	Assert(result != NULL);

	printf("close_ps- result.x %f  result.y %f\n", result->x, result->y);

	PG_RETURN_POINT_P(result);
}



Datum close_lseg(PG_FUNCTION_ARGS)
{
	LSEG	   *l1 = PG_GETARG_LSEG_P(0);
	LSEG	   *l2 = PG_GETARG_LSEG_P(1);
	Point	   *result = NULL;
	Point		point;
	double		dist;
	double		d;

	d = dist_ps_internal(&l1->p[0], l2);
	dist = d;
	memcpy(&point, &l1->p[0], sizeof(Point));

	if ((d = dist_ps_internal(&l1->p[1], l2)) < dist)
	{
		dist = d;
		memcpy(&point, &l1->p[1], sizeof(Point));
	}

	if (dist_ps_internal(&l2->p[0], l1) < dist)
	{
		result = DatumGetPointP(DirectFunctionCall2(close_ps, PointPGetDatum(&l2->p[0]), LsegPGetDatum(l1)));

		memcpy(&point, result, sizeof(Point));
		result = DatumGetPointP(DirectFunctionCall2(close_ps, PointPGetDatum(&point), LsegPGetDatum(l2)));

	}

	if (dist_ps_internal(&l2->p[1], l1) < dist)
	{
		result = DatumGetPointP(DirectFunctionCall2(close_ps, PointPGetDatum(&l2->p[1]), LsegPGetDatum(l1)));

		memcpy(&point, result, sizeof(Point));
		result = DatumGetPointP(DirectFunctionCall2(close_ps, PointPGetDatum(&point), LsegPGetDatum(l2)));

	}

	if (result == NULL)
		result = point_copy(&point);

	PG_RETURN_POINT_P(result);
}


Datum close_pb(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);
	LSEG		lseg, seg;
	Point		point;
	double		dist, d;

	if (DatumGetBool(DirectFunctionCall2(on_pb, PointPGetDatum(pt), BoxPGetDatum(box))))

		PG_RETURN_POINT_P(pt);

	
	point.x = box->low.x;
	point.y = box->high.y;
	statlseg_construct(&lseg, &box->low, &point);
	dist = dist_ps_internal(pt, &lseg);

	statlseg_construct(&seg, &box->high, &point);
	if ((d = dist_ps_internal(pt, &seg)) < dist)
	{
		dist = d;
		memcpy(&lseg, &seg, sizeof(lseg));
	}

	point.x = box->high.x;
	point.y = box->low.y;
	statlseg_construct(&seg, &box->low, &point);
	if ((d = dist_ps_internal(pt, &seg)) < dist)
	{
		dist = d;
		memcpy(&lseg, &seg, sizeof(lseg));
	}

	statlseg_construct(&seg, &box->high, &point);
	if ((d = dist_ps_internal(pt, &seg)) < dist)
	{
		dist = d;
		memcpy(&lseg, &seg, sizeof(lseg));
	}

	PG_RETURN_DATUM(DirectFunctionCall2(close_ps, PointPGetDatum(pt), LsegPGetDatum(&lseg)));

}


Datum close_sl(PG_FUNCTION_ARGS)
{

	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	LINE	   *line = PG_GETARG_LINE_P(1);
	Point	   *result;
	float8		d1, d2;

	result = interpt_sl(lseg, line);
	if (result)
		PG_RETURN_POINT_P(result);

	d1 = dist_pl_internal(&lseg->p[0], line);
	d2 = dist_pl_internal(&lseg->p[1], line);
	if (d1 < d2)
		result = point_copy(&lseg->p[0]);
	else result = point_copy(&lseg->p[1]);

	PG_RETURN_POINT_P(result);


	ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("function \"close_sl\" not implemented")));


	PG_RETURN_NULL();
}


Datum close_ls(PG_FUNCTION_ARGS)
{
	LINE	   *line = PG_GETARG_LINE_P(0);
	LSEG	   *lseg = PG_GETARG_LSEG_P(1);
	Point	   *result;
	float8		d1, d2;

	result = interpt_sl(lseg, line);
	if (result)
		PG_RETURN_POINT_P(result);

	d1 = dist_pl_internal(&lseg->p[0], line);
	d2 = dist_pl_internal(&lseg->p[1], line);
	if (d1 < d2)
		result = point_copy(&lseg->p[0]);
	else result = point_copy(&lseg->p[1]);

	PG_RETURN_POINT_P(result);
}


Datum close_sb(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);
	Point		point;
	LSEG		bseg, seg;
	double		dist, d;

	
	if (DatumGetBool(DirectFunctionCall2(inter_sb, LsegPGetDatum(lseg), BoxPGetDatum(box))))

	{
		box_cn(&point, box);
		PG_RETURN_DATUM(DirectFunctionCall2(close_ps, PointPGetDatum(&point), LsegPGetDatum(lseg)));

	}

	
	point.x = box->low.x;
	point.y = box->high.y;
	statlseg_construct(&bseg, &box->low, &point);
	dist = lseg_dt(lseg, &bseg);

	statlseg_construct(&seg, &box->high, &point);
	if ((d = lseg_dt(lseg, &seg)) < dist)
	{
		dist = d;
		memcpy(&bseg, &seg, sizeof(bseg));
	}

	point.x = box->high.x;
	point.y = box->low.y;
	statlseg_construct(&seg, &box->low, &point);
	if ((d = lseg_dt(lseg, &seg)) < dist)
	{
		dist = d;
		memcpy(&bseg, &seg, sizeof(bseg));
	}

	statlseg_construct(&seg, &box->high, &point);
	if ((d = lseg_dt(lseg, &seg)) < dist)
	{
		dist = d;
		memcpy(&bseg, &seg, sizeof(bseg));
	}

	
	PG_RETURN_DATUM(DirectFunctionCall2(close_lseg, LsegPGetDatum(lseg), LsegPGetDatum(&bseg)));

}

Datum close_lb(PG_FUNCTION_ARGS)
{

	LINE	   *line = PG_GETARG_LINE_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);


	
	ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("function \"close_lb\" not implemented")));


	PG_RETURN_NULL();
}




Datum on_pl(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	LINE	   *line = PG_GETARG_LINE_P(1);

	PG_RETURN_BOOL(FPzero(line->A * pt->x + line->B * pt->y + line->C));
}



Datum on_ps(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	LSEG	   *lseg = PG_GETARG_LSEG_P(1);

	PG_RETURN_BOOL(on_ps_internal(pt, lseg));
}

static bool on_ps_internal(Point *pt, LSEG *lseg)
{
	return FPeq(point_dt(pt, &lseg->p[0]) + point_dt(pt, &lseg->p[1]), point_dt(&lseg->p[0], &lseg->p[1]));
}

Datum on_pb(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(pt->x <= box->high.x && pt->x >= box->low.x && pt->y <= box->high.y && pt->y >= box->low.y);
}

Datum box_contain_pt(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	Point	   *pt = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(pt->x <= box->high.x && pt->x >= box->low.x && pt->y <= box->high.y && pt->y >= box->low.y);
}


Datum on_ppath(PG_FUNCTION_ARGS)
{
	Point	   *pt = PG_GETARG_POINT_P(0);
	PATH	   *path = PG_GETARG_PATH_P(1);
	int			i, n;
	double		a, b;

	
	if (!path->closed)
	{
		n = path->npts - 1;
		a = point_dt(pt, &path->p[0]);
		for (i = 0; i < n; i++)
		{
			b = point_dt(pt, &path->p[i + 1]);
			if (FPeq(a + b, point_dt(&path->p[i], &path->p[i + 1])))
				PG_RETURN_BOOL(true);
			a = b;
		}
		PG_RETURN_BOOL(false);
	}

	
	PG_RETURN_BOOL(point_inside(pt, path->npts, path->p) != 0);
}

Datum on_sl(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	LINE	   *line = PG_GETARG_LINE_P(1);

	PG_RETURN_BOOL(DatumGetBool(DirectFunctionCall2(on_pl, PointPGetDatum(&lseg->p[0]), LinePGetDatum(line))) && DatumGetBool(DirectFunctionCall2(on_pl, PointPGetDatum(&lseg->p[1]), LinePGetDatum(line))));




}

Datum on_sb(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);

	PG_RETURN_BOOL(DatumGetBool(DirectFunctionCall2(on_pb, PointPGetDatum(&lseg->p[0]), BoxPGetDatum(box))) && DatumGetBool(DirectFunctionCall2(on_pb, PointPGetDatum(&lseg->p[1]), BoxPGetDatum(box))));




}



Datum inter_sl(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	LINE	   *line = PG_GETARG_LINE_P(1);

	PG_RETURN_BOOL(has_interpt_sl(lseg, line));
}


Datum inter_sb(PG_FUNCTION_ARGS)
{
	LSEG	   *lseg = PG_GETARG_LSEG_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);
	BOX			lbox;
	LSEG		bseg;
	Point		point;

	lbox.low.x = Min(lseg->p[0].x, lseg->p[1].x);
	lbox.low.y = Min(lseg->p[0].y, lseg->p[1].y);
	lbox.high.x = Max(lseg->p[0].x, lseg->p[1].x);
	lbox.high.y = Max(lseg->p[0].y, lseg->p[1].y);

	
	if (!box_ov(&lbox, box))
		PG_RETURN_BOOL(false);

	
	if (DatumGetBool(DirectFunctionCall2(on_pb, PointPGetDatum(&lseg->p[0]), BoxPGetDatum(box))) || DatumGetBool(DirectFunctionCall2(on_pb, PointPGetDatum(&lseg->p[1]), BoxPGetDatum(box))))




		PG_RETURN_BOOL(true);

	
	point.x = box->low.x;
	point.y = box->high.y;
	statlseg_construct(&bseg, &box->low, &point);
	if (lseg_intersect_internal(&bseg, lseg))
		PG_RETURN_BOOL(true);

	statlseg_construct(&bseg, &box->high, &point);
	if (lseg_intersect_internal(&bseg, lseg))
		PG_RETURN_BOOL(true);

	point.x = box->high.x;
	point.y = box->low.y;
	statlseg_construct(&bseg, &box->low, &point);
	if (lseg_intersect_internal(&bseg, lseg))
		PG_RETURN_BOOL(true);

	statlseg_construct(&bseg, &box->high, &point);
	if (lseg_intersect_internal(&bseg, lseg))
		PG_RETURN_BOOL(true);

	
	PG_RETURN_BOOL(false);
}


Datum inter_lb(PG_FUNCTION_ARGS)
{
	LINE	   *line = PG_GETARG_LINE_P(0);
	BOX		   *box = PG_GETARG_BOX_P(1);
	LSEG		bseg;
	Point		p1, p2;

	
	p1.x = box->low.x;
	p1.y = box->low.y;
	p2.x = box->low.x;
	p2.y = box->high.y;
	statlseg_construct(&bseg, &p1, &p2);
	if (has_interpt_sl(&bseg, line))
		PG_RETURN_BOOL(true);
	p1.x = box->high.x;
	p1.y = box->high.y;
	statlseg_construct(&bseg, &p1, &p2);
	if (has_interpt_sl(&bseg, line))
		PG_RETURN_BOOL(true);
	p2.x = box->high.x;
	p2.y = box->low.y;
	statlseg_construct(&bseg, &p1, &p2);
	if (has_interpt_sl(&bseg, line))
		PG_RETURN_BOOL(true);
	p1.x = box->low.x;
	p1.y = box->low.y;
	statlseg_construct(&bseg, &p1, &p2);
	if (has_interpt_sl(&bseg, line))
		PG_RETURN_BOOL(true);

	
	PG_RETURN_BOOL(false);
}




static void make_bound_box(POLYGON *poly)
{
	int			i;
	double		x1, y1, x2, y2;



	if (poly->npts > 0)
	{
		x2 = x1 = poly->p[0].x;
		y2 = y1 = poly->p[0].y;
		for (i = 1; i < poly->npts; i++)
		{
			if (poly->p[i].x < x1)
				x1 = poly->p[i].x;
			if (poly->p[i].x > x2)
				x2 = poly->p[i].x;
			if (poly->p[i].y < y1)
				y1 = poly->p[i].y;
			if (poly->p[i].y > y2)
				y2 = poly->p[i].y;
		}

		box_fill(&(poly->boundbox), x1, x2, y1, y2);
	}
	else ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("cannot create bounding box for empty polygon")));


}


Datum poly_in(PG_FUNCTION_ARGS)
{
	char	   *str = PG_GETARG_CSTRING(0);
	POLYGON    *poly;
	int			npts;
	int			size;
	int			isopen;
	char	   *s;

	if ((npts = pair_count(str, ',')) <= 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type polygon: \"%s\"", str)));


	size = offsetof(POLYGON, p[0]) +sizeof(poly->p[0]) * npts;
	poly = (POLYGON *) palloc0(size);	

	SET_VARSIZE(poly, size);
	poly->npts = npts;

	if ((!path_decode(FALSE, npts, str, &isopen, &s, &(poly->p[0])))
		|| (*s != '\0'))
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type polygon: \"%s\"", str)));


	make_bound_box(poly);

	PG_RETURN_POLYGON_P(poly);
}


Datum poly_out(PG_FUNCTION_ARGS)
{
	POLYGON    *poly = PG_GETARG_POLYGON_P(0);

	PG_RETURN_CSTRING(path_encode(PATH_CLOSED, poly->npts, poly->p));
}


Datum poly_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	POLYGON    *poly;
	int32		npts;
	int32		i;
	int			size;

	npts = pq_getmsgint(buf, sizeof(int32));
	if (npts <= 0 || npts >= (int32) ((INT_MAX - offsetof(POLYGON, p[0])) / sizeof(Point)))
		ereport(ERROR, (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION), errmsg("invalid number of points in external \"polygon\" value")));


	size = offsetof(POLYGON, p[0]) +sizeof(poly->p[0]) * npts;
	poly = (POLYGON *) palloc0(size);	

	SET_VARSIZE(poly, size);
	poly->npts = npts;

	for (i = 0; i < npts; i++)
	{
		poly->p[i].x = pq_getmsgfloat8(buf);
		poly->p[i].y = pq_getmsgfloat8(buf);
	}

	make_bound_box(poly);

	PG_RETURN_POLYGON_P(poly);
}


Datum poly_send(PG_FUNCTION_ARGS)
{
	POLYGON    *poly = PG_GETARG_POLYGON_P(0);
	StringInfoData buf;
	int32		i;

	pq_begintypsend(&buf);
	pq_sendint(&buf, poly->npts, sizeof(int32));
	for (i = 0; i < poly->npts; i++)
	{
		pq_sendfloat8(&buf, poly->p[i].x);
		pq_sendfloat8(&buf, poly->p[i].y);
	}
	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}



Datum poly_left(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	result = polya->boundbox.high.x < polyb->boundbox.low.x;

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}


Datum poly_overleft(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	result = polya->boundbox.high.x <= polyb->boundbox.high.x;

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}


Datum poly_right(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	result = polya->boundbox.low.x > polyb->boundbox.high.x;

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}


Datum poly_overright(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	result = polya->boundbox.low.x >= polyb->boundbox.low.x;

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}


Datum poly_below(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	result = polya->boundbox.high.y < polyb->boundbox.low.y;

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}


Datum poly_overbelow(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	result = polya->boundbox.high.y <= polyb->boundbox.high.y;

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}


Datum poly_above(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	result = polya->boundbox.low.y > polyb->boundbox.high.y;

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}


Datum poly_overabove(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	result = polya->boundbox.low.y >= polyb->boundbox.low.y;

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}



Datum poly_same(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	if (polya->npts != polyb->npts)
		result = false;
	else result = plist_same(polya->npts, polya->p, polyb->p);

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}


Datum poly_overlap(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	
	result = (polya->npts > 0 && polyb->npts > 0 && box_ov(&polya->boundbox, &polyb->boundbox)) ? true : false;

	
	if (result)
	{
		int			ia, ib;
		LSEG		sa, sb;

		
		sa.p[0] = polya->p[polya->npts - 1];
		result = false;

		for (ia = 0; ia < polya->npts && result == false; ia++)
		{
			
			sa.p[1] = polya->p[ia];

			
			sb.p[0] = polyb->p[polyb->npts - 1];

			for (ib = 0; ib < polyb->npts && result == false; ib++)
			{
				sb.p[1] = polyb->p[ib];
				result = lseg_intersect_internal(&sa, &sb);
				sb.p[0] = sb.p[1];
			}

			
			sa.p[0] = sa.p[1];
		}

		if (result == false)
		{
			result = (point_inside(polya->p, polyb->npts, polyb->p)
					  || point_inside(polyb->p, polya->npts, polya->p));
		}
	}

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}



static bool touched_lseg_inside_poly(Point *a, Point *b, LSEG *s, POLYGON *poly, int start)
{
	
	LSEG		t;

	t.p[0] = *a;
	t.p[1] = *b;


	if (POINTEQ(a, s->p))
	{
		if (on_ps_internal(s->p + 1, &t))
			return lseg_inside_poly(b, s->p + 1, poly, start);
	}
	else if (POINTEQ(a, s->p + 1))
	{
		if (on_ps_internal(s->p, &t))
			return lseg_inside_poly(b, s->p, poly, start);
	}
	else if (on_ps_internal(s->p, &t))
	{
		return lseg_inside_poly(b, s->p, poly, start);
	}
	else if (on_ps_internal(s->p + 1, &t))
	{
		return lseg_inside_poly(b, s->p + 1, poly, start);
	}

	return true;				
}


static bool lseg_inside_poly(Point *a, Point *b, POLYGON *poly, int start)
{
	LSEG		s, t;
	int			i;
	bool		res = true, intersection = false;

	t.p[0] = *a;
	t.p[1] = *b;
	s.p[0] = poly->p[(start == 0) ? (poly->npts - 1) : (start - 1)];

	for (i = start; i < poly->npts && res; i++)
	{
		Point	   *interpt;

		s.p[1] = poly->p[i];

		if (on_ps_internal(t.p, &s))
		{
			if (on_ps_internal(t.p + 1, &s))
				return true;	

			
			res = touched_lseg_inside_poly(t.p, t.p + 1, &s, poly, i + 1);
		}
		else if (on_ps_internal(t.p + 1, &s))
		{
			
			res = touched_lseg_inside_poly(t.p + 1, t.p, &s, poly, i + 1);
		}
		else if ((interpt = lseg_interpt_internal(&t, &s)) != NULL)
		{
			

			intersection = true;
			res = lseg_inside_poly(t.p, interpt, poly, i + 1);
			if (res)
				res = lseg_inside_poly(t.p + 1, interpt, poly, i + 1);
			pfree(interpt);
		}

		s.p[0] = s.p[1];
	}

	if (res && !intersection)
	{
		Point		p;

		
		p.x = (t.p[0].x + t.p[1].x) / 2.0;
		p.y = (t.p[0].y + t.p[1].y) / 2.0;

		res = point_inside(&p, poly->npts, poly->p);
	}

	return res;
}


Datum poly_contain(PG_FUNCTION_ARGS)
{
	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);
	bool		result;

	
	if (polya->npts > 0 && polyb->npts > 0 && DatumGetBool(DirectFunctionCall2(box_contain, BoxPGetDatum(&polya->boundbox), BoxPGetDatum(&polyb->boundbox))))


	{
		int			i;
		LSEG		s;

		s.p[0] = polyb->p[polyb->npts - 1];
		result = true;

		for (i = 0; i < polyb->npts && result; i++)
		{
			s.p[1] = polyb->p[i];
			result = lseg_inside_poly(s.p, s.p + 1, polya, 0);
			s.p[0] = s.p[1];
		}
	}
	else {
		result = false;
	}

	
	PG_FREE_IF_COPY(polya, 0);
	PG_FREE_IF_COPY(polyb, 1);

	PG_RETURN_BOOL(result);
}



Datum poly_contained(PG_FUNCTION_ARGS)
{
	Datum		polya = PG_GETARG_DATUM(0);
	Datum		polyb = PG_GETARG_DATUM(1);

	
	PG_RETURN_DATUM(DirectFunctionCall2(poly_contain, polyb, polya));
}


Datum poly_contain_pt(PG_FUNCTION_ARGS)
{
	POLYGON    *poly = PG_GETARG_POLYGON_P(0);
	Point	   *p = PG_GETARG_POINT_P(1);

	PG_RETURN_BOOL(point_inside(p, poly->npts, poly->p) != 0);
}

Datum pt_contained_poly(PG_FUNCTION_ARGS)
{
	Point	   *p = PG_GETARG_POINT_P(0);
	POLYGON    *poly = PG_GETARG_POLYGON_P(1);

	PG_RETURN_BOOL(point_inside(p, poly->npts, poly->p) != 0);
}


Datum poly_distance(PG_FUNCTION_ARGS)
{

	POLYGON    *polya = PG_GETARG_POLYGON_P(0);
	POLYGON    *polyb = PG_GETARG_POLYGON_P(1);


	ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("function \"poly_distance\" not implemented")));


	PG_RETURN_NULL();
}




Datum construct_point(PG_FUNCTION_ARGS)
{
	float8		x = PG_GETARG_FLOAT8(0);
	float8		y = PG_GETARG_FLOAT8(1);

	PG_RETURN_POINT_P(point_construct(x, y));
}

Datum point_add(PG_FUNCTION_ARGS)
{
	Point	   *p1 = PG_GETARG_POINT_P(0);
	Point	   *p2 = PG_GETARG_POINT_P(1);
	Point	   *result;

	result = (Point *) palloc(sizeof(Point));

	result->x = (p1->x + p2->x);
	result->y = (p1->y + p2->y);

	PG_RETURN_POINT_P(result);
}

Datum point_sub(PG_FUNCTION_ARGS)
{
	Point	   *p1 = PG_GETARG_POINT_P(0);
	Point	   *p2 = PG_GETARG_POINT_P(1);
	Point	   *result;

	result = (Point *) palloc(sizeof(Point));

	result->x = (p1->x - p2->x);
	result->y = (p1->y - p2->y);

	PG_RETURN_POINT_P(result);
}

Datum point_mul(PG_FUNCTION_ARGS)
{
	Point	   *p1 = PG_GETARG_POINT_P(0);
	Point	   *p2 = PG_GETARG_POINT_P(1);
	Point	   *result;

	result = (Point *) palloc(sizeof(Point));

	result->x = (p1->x * p2->x) - (p1->y * p2->y);
	result->y = (p1->x * p2->y) + (p1->y * p2->x);

	PG_RETURN_POINT_P(result);
}

Datum point_div(PG_FUNCTION_ARGS)
{
	Point	   *p1 = PG_GETARG_POINT_P(0);
	Point	   *p2 = PG_GETARG_POINT_P(1);
	Point	   *result;
	double		div;

	result = (Point *) palloc(sizeof(Point));

	div = (p2->x * p2->x) + (p2->y * p2->y);

	if (div == 0.0)
		ereport(ERROR, (errcode(ERRCODE_DIVISION_BY_ZERO), errmsg("division by zero")));


	result->x = ((p1->x * p2->x) + (p1->y * p2->y)) / div;
	result->y = ((p2->x * p1->y) - (p2->y * p1->x)) / div;

	PG_RETURN_POINT_P(result);
}




Datum points_box(PG_FUNCTION_ARGS)
{
	Point	   *p1 = PG_GETARG_POINT_P(0);
	Point	   *p2 = PG_GETARG_POINT_P(1);

	PG_RETURN_BOX_P(box_construct(p1->x, p2->x, p1->y, p2->y));
}

Datum box_add(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	Point	   *p = PG_GETARG_POINT_P(1);

	PG_RETURN_BOX_P(box_construct((box->high.x + p->x), (box->low.x + p->x), (box->high.y + p->y), (box->low.y + p->y)));


}

Datum box_sub(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	Point	   *p = PG_GETARG_POINT_P(1);

	PG_RETURN_BOX_P(box_construct((box->high.x - p->x), (box->low.x - p->x), (box->high.y - p->y), (box->low.y - p->y)));


}

Datum box_mul(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	Point	   *p = PG_GETARG_POINT_P(1);
	BOX		   *result;
	Point	   *high, *low;

	high = DatumGetPointP(DirectFunctionCall2(point_mul, PointPGetDatum(&box->high), PointPGetDatum(p)));

	low = DatumGetPointP(DirectFunctionCall2(point_mul, PointPGetDatum(&box->low), PointPGetDatum(p)));


	result = box_construct(high->x, low->x, high->y, low->y);

	PG_RETURN_BOX_P(result);
}

Datum box_div(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	Point	   *p = PG_GETARG_POINT_P(1);
	BOX		   *result;
	Point	   *high, *low;

	high = DatumGetPointP(DirectFunctionCall2(point_div, PointPGetDatum(&box->high), PointPGetDatum(p)));

	low = DatumGetPointP(DirectFunctionCall2(point_div, PointPGetDatum(&box->low), PointPGetDatum(p)));


	result = box_construct(high->x, low->x, high->y, low->y);

	PG_RETURN_BOX_P(result);
}





Datum path_add(PG_FUNCTION_ARGS)
{
	PATH	   *p1 = PG_GETARG_PATH_P(0);
	PATH	   *p2 = PG_GETARG_PATH_P(1);
	PATH	   *result;
	int			size, base_size;
	int			i;

	if (p1->closed || p2->closed)
		PG_RETURN_NULL();

	base_size = sizeof(p1->p[0]) * (p1->npts + p2->npts);
	size = offsetof(PATH, p[0]) +base_size;

	
	if (base_size / sizeof(p1->p[0]) != (p1->npts + p2->npts) || size <= base_size)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("too many points requested")));


	result = (PATH *) palloc(size);

	SET_VARSIZE(result, size);
	result->npts = (p1->npts + p2->npts);
	result->closed = p1->closed;
	
	result->dummy = 0;

	for (i = 0; i < p1->npts; i++)
	{
		result->p[i].x = p1->p[i].x;
		result->p[i].y = p1->p[i].y;
	}
	for (i = 0; i < p2->npts; i++)
	{
		result->p[i + p1->npts].x = p2->p[i].x;
		result->p[i + p1->npts].y = p2->p[i].y;
	}

	PG_RETURN_PATH_P(result);
}


Datum path_add_pt(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P_COPY(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	int			i;

	for (i = 0; i < path->npts; i++)
	{
		path->p[i].x += point->x;
		path->p[i].y += point->y;
	}

	PG_RETURN_PATH_P(path);
}

Datum path_sub_pt(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P_COPY(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	int			i;

	for (i = 0; i < path->npts; i++)
	{
		path->p[i].x -= point->x;
		path->p[i].y -= point->y;
	}

	PG_RETURN_PATH_P(path);
}


Datum path_mul_pt(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P_COPY(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	Point	   *p;
	int			i;

	for (i = 0; i < path->npts; i++)
	{
		p = DatumGetPointP(DirectFunctionCall2(point_mul, PointPGetDatum(&path->p[i]), PointPGetDatum(point)));

		path->p[i].x = p->x;
		path->p[i].y = p->y;
	}

	PG_RETURN_PATH_P(path);
}

Datum path_div_pt(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P_COPY(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	Point	   *p;
	int			i;

	for (i = 0; i < path->npts; i++)
	{
		p = DatumGetPointP(DirectFunctionCall2(point_div, PointPGetDatum(&path->p[i]), PointPGetDatum(point)));

		path->p[i].x = p->x;
		path->p[i].y = p->y;
	}

	PG_RETURN_PATH_P(path);
}


Datum path_center(PG_FUNCTION_ARGS)
{

	PATH	   *path = PG_GETARG_PATH_P(0);


	ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("function \"path_center\" not implemented")));


	PG_RETURN_NULL();
}

Datum path_poly(PG_FUNCTION_ARGS)
{
	PATH	   *path = PG_GETARG_PATH_P(0);
	POLYGON    *poly;
	int			size;
	int			i;

	
	if (!path->closed)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("open path cannot be converted to polygon")));


	size = offsetof(POLYGON, p[0]) +sizeof(poly->p[0]) * path->npts;
	poly = (POLYGON *) palloc(size);

	SET_VARSIZE(poly, size);
	poly->npts = path->npts;

	for (i = 0; i < path->npts; i++)
	{
		poly->p[i].x = path->p[i].x;
		poly->p[i].y = path->p[i].y;
	}

	make_bound_box(poly);

	PG_RETURN_POLYGON_P(poly);
}




Datum poly_npoints(PG_FUNCTION_ARGS)
{
	POLYGON    *poly = PG_GETARG_POLYGON_P(0);

	PG_RETURN_INT32(poly->npts);
}


Datum poly_center(PG_FUNCTION_ARGS)
{
	POLYGON    *poly = PG_GETARG_POLYGON_P(0);
	Datum		result;
	CIRCLE	   *circle;

	circle = DatumGetCircleP(DirectFunctionCall1(poly_circle, PolygonPGetDatum(poly)));
	result = DirectFunctionCall1(circle_center, CirclePGetDatum(circle));

	PG_RETURN_DATUM(result);
}


Datum poly_box(PG_FUNCTION_ARGS)
{
	POLYGON    *poly = PG_GETARG_POLYGON_P(0);
	BOX		   *box;

	if (poly->npts < 1)
		PG_RETURN_NULL();

	box = box_copy(&poly->boundbox);

	PG_RETURN_BOX_P(box);
}



Datum box_poly(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	POLYGON    *poly;
	int			size;

	
	size = offsetof(POLYGON, p[0]) +sizeof(poly->p[0]) * 4;
	poly = (POLYGON *) palloc(size);

	SET_VARSIZE(poly, size);
	poly->npts = 4;

	poly->p[0].x = box->low.x;
	poly->p[0].y = box->low.y;
	poly->p[1].x = box->low.x;
	poly->p[1].y = box->high.y;
	poly->p[2].x = box->high.x;
	poly->p[2].y = box->high.y;
	poly->p[3].x = box->high.x;
	poly->p[3].y = box->low.y;

	box_fill(&poly->boundbox, box->high.x, box->low.x, box->high.y, box->low.y);

	PG_RETURN_POLYGON_P(poly);
}


Datum poly_path(PG_FUNCTION_ARGS)
{
	POLYGON    *poly = PG_GETARG_POLYGON_P(0);
	PATH	   *path;
	int			size;
	int			i;

	size = offsetof(PATH, p[0]) +sizeof(path->p[0]) * poly->npts;
	path = (PATH *) palloc(size);

	SET_VARSIZE(path, size);
	path->npts = poly->npts;
	path->closed = TRUE;
	
	path->dummy = 0;

	for (i = 0; i < poly->npts; i++)
	{
		path->p[i].x = poly->p[i].x;
		path->p[i].y = poly->p[i].y;
	}

	PG_RETURN_PATH_P(path);
}







Datum circle_in(PG_FUNCTION_ARGS)
{
	char	   *str = PG_GETARG_CSTRING(0);
	CIRCLE	   *circle;
	char	   *s, *cp;
	int			depth = 0;

	circle = (CIRCLE *) palloc(sizeof(CIRCLE));

	s = str;
	while (isspace((unsigned char) *s))
		s++;
	if ((*s == LDELIM_C) || (*s == LDELIM))
	{
		depth++;
		cp = (s + 1);
		while (isspace((unsigned char) *cp))
			cp++;
		if (*cp == LDELIM)
			s = cp;
	}

	if (!pair_decode(s, &circle->center.x, &circle->center.y, &s))
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type circle: \"%s\"", str)));


	if (*s == DELIM)
		s++;
	while (isspace((unsigned char) *s))
		s++;

	if ((!single_decode(s, &circle->radius, &s)) || (circle->radius < 0))
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type circle: \"%s\"", str)));


	while (depth > 0)
	{
		if ((*s == RDELIM)
			|| ((*s == RDELIM_C) && (depth == 1)))
		{
			depth--;
			s++;
			while (isspace((unsigned char) *s))
				s++;
		}
		else ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type circle: \"%s\"", str)));


	}

	if (*s != '\0')
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("invalid input syntax for type circle: \"%s\"", str)));


	PG_RETURN_CIRCLE_P(circle);
}


Datum circle_out(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	char	   *result;
	char	   *cp;

	result = palloc(2 * P_MAXLEN + 6);

	cp = result;
	*cp++ = LDELIM_C;
	*cp++ = LDELIM;
	if (!pair_encode(circle->center.x, circle->center.y, cp))
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not format \"circle\" value")));


	cp += strlen(cp);
	*cp++ = RDELIM;
	*cp++ = DELIM;
	if (!single_encode(circle->radius, cp))
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not format \"circle\" value")));


	cp += strlen(cp);
	*cp++ = RDELIM_C;
	*cp = '\0';

	PG_RETURN_CSTRING(result);
}


Datum circle_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	CIRCLE	   *circle;

	circle = (CIRCLE *) palloc(sizeof(CIRCLE));

	circle->center.x = pq_getmsgfloat8(buf);
	circle->center.y = pq_getmsgfloat8(buf);
	circle->radius = pq_getmsgfloat8(buf);

	if (circle->radius < 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION), errmsg("invalid radius in external \"circle\" value")));


	PG_RETURN_CIRCLE_P(circle);
}


Datum circle_send(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	StringInfoData buf;

	pq_begintypsend(&buf);
	pq_sendfloat8(&buf, circle->center.x);
	pq_sendfloat8(&buf, circle->center.y);
	pq_sendfloat8(&buf, circle->radius);
	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}





Datum circle_same(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPeq(circle1->radius, circle2->radius) && FPeq(circle1->center.x, circle2->center.x) && FPeq(circle1->center.y, circle2->center.y));

}


Datum circle_overlap(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPle(point_dt(&circle1->center, &circle2->center), circle1->radius + circle2->radius));
}


Datum circle_overleft(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPle((circle1->center.x + circle1->radius), (circle2->center.x + circle2->radius)));
}


Datum circle_left(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPlt((circle1->center.x + circle1->radius), (circle2->center.x - circle2->radius)));
}


Datum circle_right(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPgt((circle1->center.x - circle1->radius), (circle2->center.x + circle2->radius)));
}


Datum circle_overright(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPge((circle1->center.x - circle1->radius), (circle2->center.x - circle2->radius)));
}


Datum circle_contained(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPle((point_dt(&circle1->center, &circle2->center) + circle1->radius), circle2->radius));
}


Datum circle_contain(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPle((point_dt(&circle1->center, &circle2->center) + circle2->radius), circle1->radius));
}



Datum circle_below(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPlt((circle1->center.y + circle1->radius), (circle2->center.y - circle2->radius)));
}


Datum circle_above(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPgt((circle1->center.y - circle1->radius), (circle2->center.y + circle2->radius)));
}


Datum circle_overbelow(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPle((circle1->center.y + circle1->radius), (circle2->center.y + circle2->radius)));
}


Datum circle_overabove(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPge((circle1->center.y - circle1->radius), (circle2->center.y - circle2->radius)));
}



Datum circle_eq(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPeq(circle_ar(circle1), circle_ar(circle2)));
}

Datum circle_ne(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPne(circle_ar(circle1), circle_ar(circle2)));
}

Datum circle_lt(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPlt(circle_ar(circle1), circle_ar(circle2)));
}

Datum circle_gt(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPgt(circle_ar(circle1), circle_ar(circle2)));
}

Datum circle_le(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPle(circle_ar(circle1), circle_ar(circle2)));
}

Datum circle_ge(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);

	PG_RETURN_BOOL(FPge(circle_ar(circle1), circle_ar(circle2)));
}




static CIRCLE * circle_copy(CIRCLE *circle)
{
	CIRCLE	   *result;

	if (!PointerIsValid(circle))
		return NULL;

	result = (CIRCLE *) palloc(sizeof(CIRCLE));
	memcpy((char *) result, (char *) circle, sizeof(CIRCLE));
	return result;
}



Datum circle_add_pt(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	CIRCLE	   *result;

	result = circle_copy(circle);

	result->center.x += point->x;
	result->center.y += point->y;

	PG_RETURN_CIRCLE_P(result);
}

Datum circle_sub_pt(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	CIRCLE	   *result;

	result = circle_copy(circle);

	result->center.x -= point->x;
	result->center.y -= point->y;

	PG_RETURN_CIRCLE_P(result);
}



Datum circle_mul_pt(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	CIRCLE	   *result;
	Point	   *p;

	result = circle_copy(circle);

	p = DatumGetPointP(DirectFunctionCall2(point_mul, PointPGetDatum(&circle->center), PointPGetDatum(point)));

	result->center.x = p->x;
	result->center.y = p->y;
	result->radius *= HYPOT(point->x, point->y);

	PG_RETURN_CIRCLE_P(result);
}

Datum circle_div_pt(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	CIRCLE	   *result;
	Point	   *p;

	result = circle_copy(circle);

	p = DatumGetPointP(DirectFunctionCall2(point_div, PointPGetDatum(&circle->center), PointPGetDatum(point)));

	result->center.x = p->x;
	result->center.y = p->y;
	result->radius /= HYPOT(point->x, point->y);

	PG_RETURN_CIRCLE_P(result);
}



Datum circle_area(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);

	PG_RETURN_FLOAT8(circle_ar(circle));
}



Datum circle_diameter(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);

	PG_RETURN_FLOAT8(2 * circle->radius);
}



Datum circle_radius(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);

	PG_RETURN_FLOAT8(circle->radius);
}



Datum circle_distance(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle1 = PG_GETARG_CIRCLE_P(0);
	CIRCLE	   *circle2 = PG_GETARG_CIRCLE_P(1);
	float8		result;

	result = point_dt(&circle1->center, &circle2->center)
		- (circle1->radius + circle2->radius);
	if (result < 0)
		result = 0;
	PG_RETURN_FLOAT8(result);
}


Datum circle_contain_pt(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	Point	   *point = PG_GETARG_POINT_P(1);
	double		d;

	d = point_dt(&circle->center, point);
	PG_RETURN_BOOL(d <= circle->radius);
}


Datum pt_contained_circle(PG_FUNCTION_ARGS)
{
	Point	   *point = PG_GETARG_POINT_P(0);
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(1);
	double		d;

	d = point_dt(&circle->center, point);
	PG_RETURN_BOOL(d <= circle->radius);
}



Datum dist_pc(PG_FUNCTION_ARGS)
{
	Point	   *point = PG_GETARG_POINT_P(0);
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(1);
	float8		result;

	result = point_dt(point, &circle->center) - circle->radius;
	if (result < 0)
		result = 0;
	PG_RETURN_FLOAT8(result);
}



Datum circle_center(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	Point	   *result;

	result = (Point *) palloc(sizeof(Point));
	result->x = circle->center.x;
	result->y = circle->center.y;

	PG_RETURN_POINT_P(result);
}



static double circle_ar(CIRCLE *circle)
{
	return M_PI * (circle->radius * circle->radius);
}




Datum cr_circle(PG_FUNCTION_ARGS)
{
	Point	   *center = PG_GETARG_POINT_P(0);
	float8		radius = PG_GETARG_FLOAT8(1);
	CIRCLE	   *result;

	result = (CIRCLE *) palloc(sizeof(CIRCLE));

	result->center.x = center->x;
	result->center.y = center->y;
	result->radius = radius;

	PG_RETURN_CIRCLE_P(result);
}

Datum circle_box(PG_FUNCTION_ARGS)
{
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(0);
	BOX		   *box;
	double		delta;

	box = (BOX *) palloc(sizeof(BOX));

	delta = circle->radius / sqrt(2.0);

	box->high.x = circle->center.x + delta;
	box->low.x = circle->center.x - delta;
	box->high.y = circle->center.y + delta;
	box->low.y = circle->center.y - delta;

	PG_RETURN_BOX_P(box);
}


Datum box_circle(PG_FUNCTION_ARGS)
{
	BOX		   *box = PG_GETARG_BOX_P(0);
	CIRCLE	   *circle;

	circle = (CIRCLE *) palloc(sizeof(CIRCLE));

	circle->center.x = (box->high.x + box->low.x) / 2;
	circle->center.y = (box->high.y + box->low.y) / 2;

	circle->radius = point_dt(&circle->center, &box->high);

	PG_RETURN_CIRCLE_P(circle);
}


Datum circle_poly(PG_FUNCTION_ARGS)
{
	int32		npts = PG_GETARG_INT32(0);
	CIRCLE	   *circle = PG_GETARG_CIRCLE_P(1);
	POLYGON    *poly;
	int			base_size, size;
	int			i;
	double		angle;
	double		anglestep;

	if (FPzero(circle->radius))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert circle with radius zero to polygon")));


	if (npts < 2)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("must request at least 2 points")));


	base_size = sizeof(poly->p[0]) * npts;
	size = offsetof(POLYGON, p[0]) +base_size;

	
	if (base_size / npts != sizeof(poly->p[0]) || size <= base_size)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("too many points requested")));


	poly = (POLYGON *) palloc0(size);	
	SET_VARSIZE(poly, size);
	poly->npts = npts;

	anglestep = (2.0 * M_PI) / npts;

	for (i = 0; i < npts; i++)
	{
		angle = i * anglestep;
		poly->p[i].x = circle->center.x - (circle->radius * cos(angle));
		poly->p[i].y = circle->center.y + (circle->radius * sin(angle));
	}

	make_bound_box(poly);

	PG_RETURN_POLYGON_P(poly);
}


Datum poly_circle(PG_FUNCTION_ARGS)
{
	POLYGON    *poly = PG_GETARG_POLYGON_P(0);
	CIRCLE	   *circle;
	int			i;

	if (poly->npts < 2)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("cannot convert empty polygon to circle")));


	circle = (CIRCLE *) palloc(sizeof(CIRCLE));

	circle->center.x = 0;
	circle->center.y = 0;
	circle->radius = 0;

	for (i = 0; i < poly->npts; i++)
	{
		circle->center.x += poly->p[i].x;
		circle->center.y += poly->p[i].y;
	}
	circle->center.x /= poly->npts;
	circle->center.y /= poly->npts;

	for (i = 0; i < poly->npts; i++)
		circle->radius += point_dt(&poly->p[i], &circle->center);
	circle->radius /= poly->npts;

	if (FPzero(circle->radius))
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("cannot convert empty polygon to circle")));


	PG_RETURN_CIRCLE_P(circle);
}








static int point_inside(Point *p, int npts, Point *plist)
{
	double		x0, y0;
	double		prev_x, prev_y;
	int			i = 0;
	double		x, y;
	int			cross, total_cross = 0;

	if (npts <= 0)
		return 0;

	
	x0 = plist[0].x - p->x;
	y0 = plist[0].y - p->y;

	prev_x = x0;
	prev_y = y0;
	
	for (i = 1; i < npts; i++)
	{
		
		x = plist[i].x - p->x;
		y = plist[i].y - p->y;

		
		if ((cross = lseg_crossing(x, y, prev_x, prev_y)) == POINT_ON_POLYGON)
			return 2;
		total_cross += cross;

		prev_x = x;
		prev_y = y;
	}

	
	if ((cross = lseg_crossing(x0, y0, prev_x, prev_y)) == POINT_ON_POLYGON)
		return 2;
	total_cross += cross;

	if (total_cross != 0)
		return 1;
	return 0;
}




static int lseg_crossing(double x, double y, double prev_x, double prev_y)
{
	double		z;
	int			y_sign;

	if (FPzero(y))
	{							
		if (FPzero(x))			
			return POINT_ON_POLYGON;
		else if (FPgt(x, 0))
		{						
			if (FPzero(prev_y)) 
				
				return FPgt(prev_x, 0) ? 0 : POINT_ON_POLYGON;
			return FPlt(prev_y, 0) ? 1 : -1;
		}
		else {
			if (FPzero(prev_y))
				
				return FPlt(prev_x, 0) ? 0 : POINT_ON_POLYGON;
			return 0;
		}
	}
	else {
		
		y_sign = FPgt(y, 0) ? 1 : -1;

		if (FPzero(prev_y))
			
			return FPlt(prev_x, 0) ? 0 : y_sign;
		else if (FPgt(y_sign * prev_y, 0))
			
			return 0;			
		else {
			if (FPge(x, 0) && FPgt(prev_x, 0))
				
				return 2 * y_sign;
			if (FPlt(x, 0) && FPle(prev_x, 0))
				
				return 0;

			
			z = (x - prev_x) * y - (y - prev_y) * x;
			if (FPzero(z))
				return POINT_ON_POLYGON;
			return FPgt((y_sign * z), 0) ? 0 : 2 * y_sign;
		}
	}
}


static bool plist_same(int npts, Point *p1, Point *p2)
{
	int			i, ii, j;


	
	for (i = 0; i < npts; i++)
	{
		if ((FPeq(p2[i].x, p1[0].x))
			&& (FPeq(p2[i].y, p1[0].y)))
		{

			
			for (ii = 1, j = i + 1; ii < npts; ii++, j++)
			{
				if (j >= npts)
					j = 0;
				if ((!FPeq(p2[j].x, p1[ii].x))
					|| (!FPeq(p2[j].y, p1[ii].y)))
				{

					printf("plist_same- %d failed forward match with %d\n", j, ii);

					break;
				}
			}

			printf("plist_same- ii = %d/%d after forward match\n", ii, npts);

			if (ii == npts)
				return TRUE;

			
			for (ii = 1, j = i - 1; ii < npts; ii++, j--)
			{
				if (j < 0)
					j = (npts - 1);
				if ((!FPeq(p2[j].x, p1[ii].x))
					|| (!FPeq(p2[j].y, p1[ii].y)))
				{

					printf("plist_same- %d failed reverse match with %d\n", j, ii);

					break;
				}
			}

			printf("plist_same- ii = %d/%d after reverse match\n", ii, npts);

			if (ii == npts)
				return TRUE;
		}
	}

	return FALSE;
}



double pg_hypot(double x, double y)
{
	double		yx;

	
	if (isinf(x) || isinf(y))
		return get_float8_infinity();

	if (isnan(x) || isnan(y))
		return get_float8_nan();

	
	x = fabs(x);
	y = fabs(y);

	
	if (x < y)
	{
		double		temp = x;

		x = y;
		y = temp;
	}

	
	if (y == 0.0)
		return x;

	
	yx = y / x;
	return x * sqrt(1.0 + (yx * yx));
}
