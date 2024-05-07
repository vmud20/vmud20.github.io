




























int DNA_elem_array_size(const char *str)
{
	int a, mul = 1;
	const char *cp = NULL;

	for (a = 0; str[a]; a++) {
		if (str[a] == '[') {
			cp = &(str[a + 1]);
		}
		else if (str[a] == ']' && cp) {
			mul *= atoi(cp);
		}
	}

	return mul;
}





void DNA_sdna_free(SDNA *sdna)
{
	if (sdna->data_alloc) {
		MEM_freeN((void *)sdna->data);
	}

	MEM_freeN((void *)sdna->names);
	MEM_freeN((void *)sdna->types);
	MEM_freeN(sdna->structs);


	BLI_ghash_free(sdna->structs_map, NULL, NULL);


	MEM_freeN(sdna);
}


static bool ispointer(const char *name)
{
	
	return (name[0] == '*' || (name[0] == '(' && name[1] == '*'));
}


static int elementsize(const SDNA *sdna, short type, short name)
{
	int mul, namelen, len;
	const char *cp;
	
	cp = sdna->names[name];
	len = 0;
	
	namelen = strlen(cp);
	
	if (ispointer(cp)) {
		
		mul = 1;
		if (cp[namelen - 1] == ']') {
			mul = DNA_elem_array_size(cp);
		}
		
		len = sdna->pointerlen * mul;
	}
	else if (sdna->typelens[type]) {
		
		mul = 1;
		if (cp[namelen - 1] == ']') {
			mul = DNA_elem_array_size(cp);
		}
		
		len = mul * sdna->typelens[type];
		
	}
	
	return len;
}


static void printstruct(SDNA *sdna, short strnr)
{
	
	int b, nr;
	short *sp;
	
	sp = sdna->structs[strnr];
	
	printf("struct %s\n", sdna->types[sp[0]]);
	nr = sp[1];
	sp += 2;
	
	for (b = 0; b < nr; b++, sp += 2) {
		printf("   %s %s\n", sdna->types[sp[0]], sdna->names[sp[1]]);
	}
}



int DNA_struct_find_nr_ex(const SDNA *sdna, const char *str, unsigned int *index_last)
{
	const short *sp = NULL;

	if (*index_last < sdna->nr_structs) {
		sp = sdna->structs[*index_last];
		if (strcmp(sdna->types[sp[0]], str) == 0) {
			return *index_last;
		}
	}


	{
		void **index_p;
		int a;

		index_p = BLI_ghash_lookup_p(sdna->structs_map, str);

		if (index_p) {
			a = GET_INT_FROM_POINTER(*index_p);
			*index_last = a;
		}
		else {
			a = -1;
		}
		return a;
	}

	{
		int a;

		for (a = 0; a < sdna->nr_structs; a++) {

			sp = sdna->structs[a];

			if (strcmp(sdna->types[sp[0]], str) == 0) {
				*index_last = a;
				return a;
			}
		}
	}
	return -1;

}

int DNA_struct_find_nr(const SDNA *sdna, const char *str)
{
	unsigned int index_last_dummy = UINT_MAX;
	return DNA_struct_find_nr_ex(sdna, str, &index_last_dummy);
}





BLI_INLINE const char *pad_up_4(const char *ptr)
{
	return (const char *)((((uintptr_t)ptr) + 3) & ~3);
}


static bool init_structDNA( SDNA *sdna, bool do_endian_swap, const char **r_error_message)

{
	int *data, *verg, gravity_fix = -1;
	short *sp;
	char str[8];
	
	verg = (int *)str;
	data = (int *)sdna->data;

	
	sdna->names = NULL;
	sdna->types = NULL;
	sdna->structs = NULL;

	sdna->structs_map = NULL;


	strcpy(str, "SDNA");
	if (*data != *verg) {
		*r_error_message = "SDNA error in SDNA file";
		return false;
	}
	else {
		const char *cp;

		data++;
		
		
		strcpy(str, "NAME");
		if (*data == *verg) {
			data++;
			
			sdna->nr_names = *data;
			if (do_endian_swap) {
				BLI_endian_switch_int32(&sdna->nr_names);
			}
			
			data++;
			sdna->names = MEM_callocN(sizeof(void *) * sdna->nr_names, "sdnanames");
		}
		else {
			*r_error_message = "NAME error in SDNA file";
			return false;
		}
		
		cp = (char *)data;
		for (int nr = 0; nr < sdna->nr_names; nr++) {
			sdna->names[nr] = cp;

			
			if (*cp == '[' && strcmp(cp, "[3]") == 0) {
				if (nr && strcmp(sdna->names[nr - 1], "Cvi") == 0) {
					sdna->names[nr] = "gravity[3]";
					gravity_fix = nr;
				}
			}

			while (*cp) cp++;
			cp++;
		}

		cp = pad_up_4(cp);
		
		
		data = (int *)cp;
		strcpy(str, "TYPE");
		if (*data == *verg) {
			data++;

			sdna->nr_types = *data;
			if (do_endian_swap) {
				BLI_endian_switch_int32(&sdna->nr_types);
			}
			
			data++;
			sdna->types = MEM_callocN(sizeof(void *) * sdna->nr_types, "sdnatypes");
		}
		else {
			*r_error_message = "TYPE error in SDNA file";
			return false;
		}
		
		cp = (char *)data;
		for (int nr = 0; nr < sdna->nr_types; nr++) {
			sdna->types[nr] = cp;
			
			
			
			
			if (*cp == 'b') {
				
				if (strcmp("bScreen", cp) == 0) sdna->types[nr] = cp + 1;
			}
			
			while (*cp) cp++;
			cp++;
		}

		cp = pad_up_4(cp);
		
		
		data = (int *)cp;
		strcpy(str, "TLEN");
		if (*data == *verg) {
			data++;
			sp = (short *)data;
			sdna->typelens = sp;
			
			if (do_endian_swap) {
				BLI_endian_switch_int16_array(sp, sdna->nr_types);
			}
			
			sp += sdna->nr_types;
		}
		else {
			*r_error_message = "TLEN error in SDNA file";
			return false;
		}
		if (sdna->nr_types & 1) sp++;   

		
		data = (int *)sp;
		strcpy(str, "STRC");
		if (*data == *verg) {
			data++;
			
			sdna->nr_structs = *data;
			if (do_endian_swap) {
				BLI_endian_switch_int32(&sdna->nr_structs);
			}
			
			data++;
			sdna->structs = MEM_callocN(sizeof(void *) * sdna->nr_structs, "sdnastrcs");
		}
		else {
			*r_error_message = "STRC error in SDNA file";
			return false;
		}
		
		sp = (short *)data;
		for (int nr = 0; nr < sdna->nr_structs; nr++) {
			sdna->structs[nr] = sp;
			
			if (do_endian_swap) {
				short a;
				
				BLI_endian_switch_int16(&sp[0]);
				BLI_endian_switch_int16(&sp[1]);
				
				a = sp[1];
				sp += 2;
				while (a--) {
					BLI_endian_switch_int16(&sp[0]);
					BLI_endian_switch_int16(&sp[1]);
					sp += 2;
				}
			}
			else {
				sp += 2 * sp[1] + 2;
			}
		}
	}

	{
		
		if (gravity_fix > -1) {
			for (int nr = 0; nr < sdna->nr_structs; nr++) {
				sp = sdna->structs[nr];
				if (strcmp(sdna->types[sp[0]], "ClothSimSettings") == 0)
					sp[10] = SDNA_TYPE_VOID;
			}
		}
	}


	{
		
		sdna->structs_map = BLI_ghash_str_new_ex("init_structDNA gh", sdna->nr_structs);

		for (intptr_t nr = 0; nr < sdna->nr_structs; nr++) {
			sp = sdna->structs[nr];
			BLI_ghash_insert(sdna->structs_map, (void *)sdna->types[sp[0]], SET_INT_IN_POINTER(nr));
		}
	}


	
	{
		intptr_t nr = DNA_struct_find_nr(sdna, "ListBase");

		
		if (UNLIKELY(nr == -1)) {
			*r_error_message = "ListBase struct error! Not found.";
			return false;
		}

		
		sp = sdna->structs[nr];
		

		sdna->pointerlen = sdna->typelens[sp[0]] / 2;

		if (sp[1] != 2 || (sdna->pointerlen != 4 && sdna->pointerlen != 8)) {
			*r_error_message = "ListBase struct error! Needs it to calculate pointerize.";
			
			return false;
		}
	}

	return true;
}


SDNA *DNA_sdna_from_data( const void *data, const int datalen, bool do_endian_swap, bool data_alloc, const char **r_error_message)


{
	SDNA *sdna = MEM_mallocN(sizeof(*sdna), "sdna");
	const char *error_message = NULL;

	sdna->datalen = datalen;
	if (data_alloc) {
		char *data_copy = MEM_mallocN(datalen, "sdna_data");
		memcpy(data_copy, data, datalen);
		sdna->data = data_copy;
	}
	else {
		sdna->data = data;
	}
	sdna->data_alloc = data_alloc;
	

	if (init_structDNA(sdna, do_endian_swap, &error_message)) {
		return sdna;
	}
	else {
		if (r_error_message == NULL) {
			fprintf(stderr, "Error decoding blend file SDNA: %s\n", error_message);
		}
		else {
			*r_error_message = error_message;
		}
		DNA_sdna_free(sdna);
		return NULL;
	}
}


static SDNA *g_sdna = NULL;

void DNA_sdna_current_init(void)
{
	g_sdna = DNA_sdna_from_data(DNAstr, DNAlen, false, false, NULL);
}

const struct SDNA *DNA_sdna_current_get(void)
{
	BLI_assert(g_sdna != NULL);
	return g_sdna;
}

void DNA_sdna_current_free(void)
{
	DNA_sdna_free(g_sdna);
	g_sdna = NULL;
}






static void recurs_test_compflags(const SDNA *sdna, char *compflags, int structnr)
{
	int a, b, typenr, elems;
	const short *sp;
	const char *cp;
	
	
	sp = sdna->structs[structnr];
	typenr = sp[0];
	
	for (a = 0; a < sdna->nr_structs; a++) {
		if ((a != structnr) && (compflags[a] == SDNA_CMP_EQUAL)) {
			sp = sdna->structs[a];
			elems = sp[1];
			sp += 2;
			for (b = 0; b < elems; b++, sp += 2) {
				if (sp[0] == typenr) {
					cp = sdna->names[sp[1]];
					if (!ispointer(cp)) {
						compflags[a] = SDNA_CMP_NOT_EQUAL;
						recurs_test_compflags(sdna, compflags, a);
					}
				}
			}
		}
	}
	
}



const char *DNA_struct_get_compareflags(const SDNA *oldsdna, const SDNA *newsdna)
{
	int a, b;
	const short *sp_old, *sp_new;
	const char *str1, *str2;
	char *compflags;
	
	if (oldsdna->nr_structs == 0) {
		printf("error: file without SDNA\n");
		return NULL;
	}

	compflags = MEM_callocN(oldsdna->nr_structs, "compflags");

	
	unsigned int newsdna_index_last = 0;
	
	for (a = 0; a < oldsdna->nr_structs; a++) {
		sp_old = oldsdna->structs[a];
		
		
		int sp_new_index = DNA_struct_find_nr_ex(newsdna, oldsdna->types[sp_old[0]], &newsdna_index_last);

		
		newsdna_index_last++;

		if (sp_new_index != -1) {
			sp_new = newsdna->structs[sp_new_index];
			
			compflags[a] = SDNA_CMP_NOT_EQUAL;
			
			
			if (sp_new[1] == sp_old[1]) {
				if (newsdna->typelens[sp_new[0]] == oldsdna->typelens[sp_old[0]]) {

					
					b = sp_old[1];
					sp_old += 2;
					sp_new += 2;
					while (b > 0) {
						str1 = newsdna->types[sp_new[0]];
						str2 = oldsdna->types[sp_old[0]];
						if (strcmp(str1, str2) != 0) break;

						str1 = newsdna->names[sp_new[1]];
						str2 = oldsdna->names[sp_old[1]];
						if (strcmp(str1, str2) != 0) break;

						
						if (ispointer(str1)) {
							if (oldsdna->pointerlen != newsdna->pointerlen) break;
						}

						b--;
						sp_old += 2;
						sp_new += 2;
					}
					if (b == 0) {
						
						compflags[a] = SDNA_CMP_EQUAL;
					}

				}
			}
			
		}
	}

	
	compflags[0] = SDNA_CMP_EQUAL;

	
	for (a = 0; a < oldsdna->nr_structs; a++) {
		if (compflags[a] == SDNA_CMP_NOT_EQUAL) {
			recurs_test_compflags(oldsdna, compflags, a);
		}
	}
	

	for (a = 0; a < oldsdna->nr_structs; a++) {
		if (compflags[a] == SDNA_CMP_NOT_EQUAL) {
			spold = oldsdna->structs[a];
			printf("changed: %s\n", oldsdna->types[spold[0]]);
		}
	}


	return compflags;
}


static eSDNA_Type sdna_type_nr(const char *dna_type)
{
	if     ((strcmp(dna_type, "char") == 0) || (strcmp(dna_type, "const char") == 0))          return SDNA_TYPE_CHAR;
	else if ((strcmp(dna_type, "uchar") == 0) || (strcmp(dna_type, "unsigned char") == 0))     return SDNA_TYPE_UCHAR;
	else if ( strcmp(dna_type, "short") == 0)                                                  return SDNA_TYPE_SHORT;
	else if ((strcmp(dna_type, "ushort") == 0) || (strcmp(dna_type, "unsigned short") == 0))   return SDNA_TYPE_USHORT;
	else if ( strcmp(dna_type, "int") == 0)                                                    return SDNA_TYPE_INT;
	else if ( strcmp(dna_type, "float") == 0)                                                  return SDNA_TYPE_FLOAT;
	else if ( strcmp(dna_type, "double") == 0)                                                 return SDNA_TYPE_DOUBLE;
	else if ( strcmp(dna_type, "int64_t") == 0)                                                return SDNA_TYPE_INT64;
	else if ( strcmp(dna_type, "uint64_t") == 0)                                               return SDNA_TYPE_UINT64;
	else                                                                                       return -1; 
}


static void cast_elem( const char *ctype, const char *otype, const char *name, char *curdata, const char *olddata)

{
	double val = 0.0;
	int arrlen, curlen = 1, oldlen = 1;

	eSDNA_Type ctypenr, otypenr;

	arrlen = DNA_elem_array_size(name);

	if ( (otypenr = sdna_type_nr(otype)) == -1 || (ctypenr = sdna_type_nr(ctype)) == -1)
	{
		return;
	}

	
	oldlen = DNA_elem_type_size(otypenr);
	curlen = DNA_elem_type_size(ctypenr);

	while (arrlen > 0) {
		switch (otypenr) {
			case SDNA_TYPE_CHAR:
				val = *olddata; break;
			case SDNA_TYPE_UCHAR:
				val = *( (unsigned char *)olddata); break;
			case SDNA_TYPE_SHORT:
				val = *( (short *)olddata); break;
			case SDNA_TYPE_USHORT:
				val = *( (unsigned short *)olddata); break;
			case SDNA_TYPE_INT:
				val = *( (int *)olddata); break;
			case SDNA_TYPE_FLOAT:
				val = *( (float *)olddata); break;
			case SDNA_TYPE_DOUBLE:
				val = *( (double *)olddata); break;
			case SDNA_TYPE_INT64:
				val = *( (int64_t *)olddata); break;
			case SDNA_TYPE_UINT64:
				val = *( (uint64_t *)olddata); break;
		}
		
		switch (ctypenr) {
			case SDNA_TYPE_CHAR:
				*curdata = val; break;
			case SDNA_TYPE_UCHAR:
				*( (unsigned char *)curdata) = val; break;
			case SDNA_TYPE_SHORT:
				*( (short *)curdata) = val; break;
			case SDNA_TYPE_USHORT:
				*( (unsigned short *)curdata) = val; break;
			case SDNA_TYPE_INT:
				*( (int *)curdata) = val; break;
			case SDNA_TYPE_FLOAT:
				if (otypenr < 2) val /= 255;
				*( (float *)curdata) = val; break;
			case SDNA_TYPE_DOUBLE:
				if (otypenr < 2) val /= 255;
				*( (double *)curdata) = val; break;
			case SDNA_TYPE_INT64:
				*( (int64_t *)curdata) = val; break;
			case SDNA_TYPE_UINT64:
				*( (uint64_t *)curdata) = val; break;
		}

		olddata += oldlen;
		curdata += curlen;
		arrlen--;
	}
}


static void cast_pointer(int curlen, int oldlen, const char *name, char *curdata, const char *olddata)
{
	int64_t lval;
	int arrlen;
	
	arrlen = DNA_elem_array_size(name);
	
	while (arrlen > 0) {
	
		if (curlen == oldlen) {
			memcpy(curdata, olddata, curlen);
		}
		else if (curlen == 4 && oldlen == 8) {
			lval = *((int64_t *)olddata);

			
			*((int *)curdata) = lval >> 3;
		}
		else if (curlen == 8 && oldlen == 4) {
			*((int64_t *)curdata) = *((int *)olddata);
		}
		else {
			
			printf("errpr: illegal pointersize!\n");
		}
		
		olddata += oldlen;
		curdata += curlen;
		arrlen--;

	}
}


static int elem_strcmp(const char *name, const char *oname)
{
	int a = 0;
	
	while (1) {
		if (name[a] != oname[a]) return 1;
		if (name[a] == '[' || oname[a] == '[') break;
		if (name[a] == 0 || oname[a] == 0) break;
		a++;
	}
	return 0;
}


static const char *find_elem( const SDNA *sdna, const char *type, const char *name, const short *old, const char *olddata, const short **sppo)





{
	int a, elemcount, len;
	const char *otype, *oname;
	
	
	
	
	elemcount = old[1];
	old += 2;
	for (a = 0; a < elemcount; a++, old += 2) {

		otype = sdna->types[old[0]];
		oname = sdna->names[old[1]];

		len = elementsize(sdna, old[0], old[1]);

		if (elem_strcmp(name, oname) == 0) {  
			if (strcmp(type, otype) == 0) {   
				if (sppo) *sppo = old;
				return olddata;
			}
			
			return NULL;
		}
		
		olddata += len;
	}
	return NULL;
}


static void reconstruct_elem( const SDNA *newsdna, const SDNA *oldsdna, const char *type, const char *name, char *curdata, const short *old, const char *olddata)






{
	
	int a, elemcount, len, countpos, oldsize, cursize, mul;
	const char *otype, *oname, *cp;
	
	
	cp = name;
	countpos = 0;
	while (*cp && *cp != '[') {
		cp++; countpos++;
	}
	if (*cp != '[') countpos = 0;
	
	
	elemcount = old[1];
	old += 2;
	for (a = 0; a < elemcount; a++, old += 2) {
		otype = oldsdna->types[old[0]];
		oname = oldsdna->names[old[1]];
		len = elementsize(oldsdna, old[0], old[1]);
		
		if (strcmp(name, oname) == 0) { 
			
			if (ispointer(name)) {  
				cast_pointer(newsdna->pointerlen, oldsdna->pointerlen, name, curdata, olddata);
			}
			else if (strcmp(type, otype) == 0) {    
				memcpy(curdata, olddata, len);
			}
			else {
				cast_elem(type, otype, name, curdata, olddata);
			}

			return;
		}
		else if (countpos != 0) {  

			if (oname[countpos] == '[' && strncmp(name, oname, countpos) == 0) {  
				
				cursize = DNA_elem_array_size(name);
				oldsize = DNA_elem_array_size(oname);

				if (ispointer(name)) {  
					cast_pointer(newsdna->pointerlen, oldsdna->pointerlen, cursize > oldsize ? oname : name, curdata, olddata);

				}
				else if (strcmp(type, otype) == 0) {  
					mul = len / oldsize; 
					mul *= (cursize < oldsize) ? cursize : oldsize; 
					memcpy(curdata, olddata, mul);
					
					if (oldsize > cursize && strcmp(type, "char") == 0) {
						
						curdata[mul - 1] = '\0';
					}
				}
				else {
					cast_elem(type, otype, cursize > oldsize ? oname : name, curdata, olddata);

				}
				return;
			}
		}
		olddata += len;
	}
}


static void reconstruct_struct( const SDNA *newsdna, const SDNA *oldsdna, const char *compflags,  int oldSDNAnr, const char *data, int curSDNAnr, char *cur)







{
	
	int a, elemcount, elen, eleno, mul, mulo, firststructtypenr;
	const short *spo, *spc, *sppo;
	const char *type;
	const char *cpo;
	char *cpc;
	const char *name, *nameo;

	unsigned int oldsdna_index_last = UINT_MAX;
	unsigned int cursdna_index_last = UINT_MAX;


	if (oldSDNAnr == -1) return;
	if (curSDNAnr == -1) return;

	if (compflags[oldSDNAnr] == SDNA_CMP_EQUAL) {
		
		spo = oldsdna->structs[oldSDNAnr];
		elen = oldsdna->typelens[spo[0]];
		memcpy(cur, data, elen);
		
		return;
	}

	firststructtypenr = *(newsdna->structs[0]);

	spo = oldsdna->structs[oldSDNAnr];
	spc = newsdna->structs[curSDNAnr];

	elemcount = spc[1];

	spc += 2;
	cpc = cur;
	for (a = 0; a < elemcount; a++, spc += 2) {  
		type = newsdna->types[spc[0]];
		name = newsdna->names[spc[1]];
		
		elen = elementsize(newsdna, spc[0], spc[1]);

		
		if (spc[0] >= firststructtypenr && !ispointer(name)) {
			
			
			cpo = (char *)find_elem(oldsdna, type, name, spo, data, &sppo);
			
			if (cpo) {
				oldSDNAnr = DNA_struct_find_nr_ex(oldsdna, type, &oldsdna_index_last);
				curSDNAnr = DNA_struct_find_nr_ex(newsdna, type, &cursdna_index_last);
				
				
				mul = DNA_elem_array_size(name);
				nameo = oldsdna->names[sppo[1]];
				mulo = DNA_elem_array_size(nameo);
				
				eleno = elementsize(oldsdna, sppo[0], sppo[1]);
				
				elen /= mul;
				eleno /= mulo;
				
				while (mul--) {
					reconstruct_struct(newsdna, oldsdna, compflags, oldSDNAnr, cpo, curSDNAnr, cpc);
					cpo += eleno;
					cpc += elen;
					
					
					mulo--;
					if (mulo <= 0) break;
				}
			}
			else {
				cpc += elen;  
			}
		}
		else {
			
			reconstruct_elem(newsdna, oldsdna, type, name, cpc, spo, data);
			cpc += elen;
		}
	}
}


void DNA_struct_switch_endian(const SDNA *oldsdna, int oldSDNAnr, char *data)
{
	
	int a, mul, elemcount, elen, elena, firststructtypenr;
	const short *spo, *spc;
	char *cur;
	const char *type, *name;
	unsigned int oldsdna_index_last = UINT_MAX;

	if (oldSDNAnr == -1) return;
	firststructtypenr = *(oldsdna->structs[0]);
	
	spo = spc = oldsdna->structs[oldSDNAnr];

	elemcount = spo[1];

	spc += 2;
	cur = data;
	
	for (a = 0; a < elemcount; a++, spc += 2) {
		type = oldsdna->types[spc[0]];
		name = oldsdna->names[spc[1]];
		
		
		elen = elementsize(oldsdna, spc[0], spc[1]);

		
		if (spc[0] >= firststructtypenr && !ispointer(name)) {
			
			
			char *cpo = (char *)find_elem(oldsdna, type, name, spo, data, NULL);
			if (cpo) {
				oldSDNAnr = DNA_struct_find_nr_ex(oldsdna, type, &oldsdna_index_last);
				
				mul = DNA_elem_array_size(name);
				elena = elen / mul;

				while (mul--) {
					DNA_struct_switch_endian(oldsdna, oldSDNAnr, cpo);
					cpo += elena;
				}
			}
		}
		else {
			
			if (ispointer(name)) {
				if (oldsdna->pointerlen == 8) {
					BLI_endian_switch_int64_array((int64_t *)cur, DNA_elem_array_size(name));
				}
			}
			else {
				if (ELEM(spc[0], SDNA_TYPE_SHORT, SDNA_TYPE_USHORT)) {

					
					bool skip = false;
					if (name[0] == 'b' && name[1] == 'l') {
						if (strcmp(name, "blocktype") == 0) skip = true;
					}

					if (skip == false) {
						BLI_endian_switch_int16_array((int16_t *)cur, DNA_elem_array_size(name));
					}
				}
				else if (ELEM(spc[0], SDNA_TYPE_INT, SDNA_TYPE_FLOAT)) {
					

					BLI_endian_switch_int32_array((int32_t *)cur, DNA_elem_array_size(name));
				}
				else if (ELEM(spc[0], SDNA_TYPE_INT64, SDNA_TYPE_UINT64, SDNA_TYPE_DOUBLE)) {
					BLI_endian_switch_int64_array((int64_t *)cur, DNA_elem_array_size(name));
				}
			}
		}
		cur += elen;
	}
}


void *DNA_struct_reconstruct( const SDNA *newsdna, const SDNA *oldsdna, const char *compflags, int oldSDNAnr, int blocks, const void *data)

{
	int a, curSDNAnr, curlen = 0, oldlen;
	const short *spo, *spc;
	char *cur, *cpc;
	const char *cpo;
	const char *type;
	
	
	spo = oldsdna->structs[oldSDNAnr];
	type = oldsdna->types[spo[0]];
	oldlen = oldsdna->typelens[spo[0]];
	curSDNAnr = DNA_struct_find_nr(newsdna, type);

	
	if (curSDNAnr != -1) {
		spc = newsdna->structs[curSDNAnr];
		curlen = newsdna->typelens[spc[0]];
	}
	if (curlen == 0) {
		return NULL;
	}

	cur = MEM_callocN(blocks * curlen, "reconstruct");
	cpc = cur;
	cpo = data;
	for (a = 0; a < blocks; a++) {
		reconstruct_struct(newsdna, oldsdna, compflags, oldSDNAnr, cpo, curSDNAnr, cpc);
		cpc += curlen;
		cpo += oldlen;
	}

	return cur;
}


int DNA_elem_offset(SDNA *sdna, const char *stype, const char *vartype, const char *name)
{
	const int SDNAnr = DNA_struct_find_nr(sdna, stype);
	const short * const spo = sdna->structs[SDNAnr];
	const char * const cp = find_elem(sdna, vartype, name, spo, NULL, NULL);
	BLI_assert(SDNAnr != -1);
	return (int)((intptr_t)cp);
}

bool DNA_struct_find(const SDNA *sdna, const char *stype)
{
	return DNA_struct_find_nr(sdna, stype) != -1;
}

bool DNA_struct_elem_find(const SDNA *sdna, const char *stype, const char *vartype, const char *name)
{
	const int SDNAnr = DNA_struct_find_nr(sdna, stype);
	
	if (SDNAnr != -1) {
		const short * const spo = sdna->structs[SDNAnr];
		const char * const cp = find_elem(sdna, vartype, name, spo, NULL, NULL);
		
		if (cp) {
			return true;
		}
	}
	return false;
}



int DNA_elem_type_size(const eSDNA_Type elem_nr)
{
	
	switch (elem_nr) {
		case SDNA_TYPE_CHAR:
		case SDNA_TYPE_UCHAR:
			return 1;
		case SDNA_TYPE_SHORT:
		case SDNA_TYPE_USHORT:
			return 2;
		case SDNA_TYPE_INT:
		case SDNA_TYPE_FLOAT:
			return 4;
		case SDNA_TYPE_DOUBLE:
		case SDNA_TYPE_INT64:
		case SDNA_TYPE_UINT64:
			return 8;
	}

	
	return 8;
}
