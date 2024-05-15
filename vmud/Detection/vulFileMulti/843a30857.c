

















GF_Err stbl_AddDTS(GF_SampleTableBox *stbl, u64 DTS, u32 *sampleNumber, u32 LastAUDefDuration, u32 nb_packed_samples)
{
	u32 i, j, sampNum;
	u64 *DTSs, curDTS;
	Bool inserted;
	GF_SttsEntry *ent;

	GF_TimeToSampleBox *stts = stbl->TimeToSample;

	
	stts->r_FirstSampleInEntry = 0;

	*sampleNumber = 0;
	if (!nb_packed_samples)
		nb_packed_samples=1;

	
	if (!stts->nb_entries) {
		
		if (DTS) return GF_BAD_PARAM;
		stts->alloc_size = 1;
		stts->nb_entries = 1;
		stts->entries = gf_malloc(sizeof(GF_SttsEntry));
		if (!stts->entries) return GF_OUT_OF_MEM;
		stts->entries[0].sampleCount = nb_packed_samples;
		stts->entries[0].sampleDelta = (nb_packed_samples>1) ? 0 : LastAUDefDuration;
		(*sampleNumber) = 1;
		stts->w_currentSampleNum = nb_packed_samples;
		return GF_OK;
	}
	
	if (DTS >= stts->w_LastDTS) {
		u32 nb_extra = 0;
		ent = &stts->entries[stts->nb_entries-1];
		if (!ent->sampleDelta && (ent->sampleCount>1)) {
			ent->sampleDelta = (u32) ( DTS / ent->sampleCount);
			stts->w_LastDTS = DTS - ent->sampleDelta;
		}
		
		if ((DTS == stts->w_LastDTS + ent->sampleDelta)
			
			
			|| ((nb_packed_samples>1) && ((DTS == stts->w_LastDTS) || (DTS == stts->w_LastDTS + 2*ent->sampleDelta) ))
		) {
			(*sampleNumber) = stts->w_currentSampleNum + 1;
			ent->sampleCount += nb_packed_samples;
			stts->w_currentSampleNum += nb_packed_samples;
			stts->w_LastDTS = DTS + ent->sampleDelta * (nb_packed_samples-1);
			return GF_OK;
		}
		
		if (ent->sampleCount == 1) {
			

			if (stts->w_LastDTS)
				ent->sampleDelta += (u32) (DTS - stts->w_LastDTS);
			else ent->sampleDelta = (u32) DTS;

			
			ent->sampleDelta = (u32) (DTS - stts->w_LastDTS);


			ent->sampleCount ++;
			
			if ((stts->nb_entries>=2) && (ent->sampleDelta== stts->entries[stts->nb_entries-2].sampleDelta)) {
				stts->entries[stts->nb_entries-2].sampleCount += ent->sampleCount;
				stts->nb_entries--;
			}
			stts->w_currentSampleNum ++;
			stts->w_LastDTS = DTS;
			(*sampleNumber) = stts->w_currentSampleNum;
			return GF_OK;
		}
		
		ent->sampleCount --;

		if (nb_packed_samples>1)
			nb_extra = 1;

		if (stts->alloc_size <= stts->nb_entries + nb_extra) {
			ALLOC_INC(stts->alloc_size);
			stts->entries = gf_realloc(stts->entries, sizeof(GF_SttsEntry)*stts->alloc_size);
			if (!stts->entries) return GF_OUT_OF_MEM;
			memset(&stts->entries[stts->nb_entries], 0, sizeof(GF_SttsEntry)*(stts->alloc_size-stts->nb_entries) );
		}

		if (nb_extra)
			nb_extra = stts->entries[stts->nb_entries-1].sampleDelta;

		ent = &stts->entries[stts->nb_entries];
		stts->nb_entries++;

		if (nb_packed_samples==1) {
			ent->sampleCount = 2;
			ent->sampleDelta = (u32) (DTS - stts->w_LastDTS);
			stts->w_LastDTS = DTS;
			(*sampleNumber) = stts->w_currentSampleNum+1;
			stts->w_currentSampleNum += 1;
			return GF_OK;
		}

		ent->sampleCount = 1;
		ent->sampleDelta = (u32) (DTS - stts->w_LastDTS);

		ent = &stts->entries[stts->nb_entries];
		stts->nb_entries++;

		ent->sampleCount = nb_packed_samples;
		ent->sampleDelta = nb_extra;
		stts->w_LastDTS = DTS;
		(*sampleNumber) = stts->w_currentSampleNum + 1;
		stts->w_currentSampleNum += nb_packed_samples;
		return GF_OK;
	}


	
	DTSs = (u64*)gf_malloc(sizeof(u64) * (stbl->SampleSize->sampleCount+2) );
	if (!DTSs) return GF_OUT_OF_MEM;
	curDTS = 0;
	sampNum = 0;
	ent = NULL;
	inserted = 0;
	for (i=0; i<stts->nb_entries; i++) {
		ent = & stts->entries[i];
		for (j = 0; j<ent->sampleCount; j++) {
			if (!inserted && (curDTS > DTS)) {
				DTSs[sampNum] = DTS;
				sampNum++;
				*sampleNumber = sampNum;
				inserted = 1;
			}
			DTSs[sampNum] = curDTS;
			curDTS += ent->sampleDelta;
			sampNum ++;
		}
	}
	if (!inserted) {
		gf_free(DTSs);
		return GF_BAD_PARAM;
	}

	
	if (stts->nb_entries+3 >= stts->alloc_size) {
		stts->alloc_size += 3;
		stts->entries = gf_realloc(stts->entries, sizeof(GF_SttsEntry)*stts->alloc_size);
		if (!stts->entries) return GF_OUT_OF_MEM;
		memset(&stts->entries[stts->nb_entries], 0, sizeof(GF_SttsEntry)*(stts->alloc_size - stts->nb_entries) );
	}

	
	j=0;
	stts->nb_entries = 1;
	stts->entries[0].sampleCount = 1;
	stts->entries[0].sampleDelta = (u32) DTSs[1] ;
	for (i=1; i<stbl->SampleSize->sampleCount+1; i++) {
		if (i == stbl->SampleSize->sampleCount) {
			
			stts->entries[j].sampleCount++;
		} else if (stts->entries[j].sampleDelta == (u32) ( DTSs[i+1] - DTSs[i]) ) {
			stts->entries[j].sampleCount ++;
		} else {
			stts->nb_entries ++;
			j++;
			stts->entries[j].sampleCount = 1;
			stts->entries[j].sampleDelta = (u32) (DTSs[i+1] - DTSs[i]);
		}
	}
	gf_free(DTSs);

	
	stts->w_currentSampleNum = stbl->SampleSize->sampleCount + 1;
	return GF_OK;
}

GF_Err AddCompositionOffset(GF_CompositionOffsetBox *ctts, s32 offset)
{
	if (!ctts) return GF_BAD_PARAM;

	if (ctts->nb_entries && (ctts->entries[ctts->nb_entries-1].decodingOffset==offset)) {
		ctts->entries[ctts->nb_entries-1].sampleCount++;
	} else {
		if (ctts->alloc_size==ctts->nb_entries) {
			ALLOC_INC(ctts->alloc_size);
			ctts->entries = gf_realloc(ctts->entries, sizeof(GF_DttsEntry)*ctts->alloc_size);
			if (!ctts->entries) return GF_OUT_OF_MEM;
			memset(&ctts->entries[ctts->nb_entries], 0, sizeof(GF_DttsEntry)*(ctts->alloc_size-ctts->nb_entries) );
		}
		if (!ctts->entries) return GF_OUT_OF_MEM;

		ctts->entries[ctts->nb_entries].decodingOffset = offset;
		ctts->entries[ctts->nb_entries].sampleCount = 1;
		ctts->nb_entries++;
	}
	if (offset<0) ctts->version=1;
	ctts->w_LastSampleNumber++;
	return GF_OK;
}


GF_Err stbl_AddCTS(GF_SampleTableBox *stbl, u32 sampleNumber, s32 offset)
{
	u32 i, j, sampNum, *CTSs;

	GF_CompositionOffsetBox *ctts = stbl->CompositionOffset;

	
	if (ctts->unpack_mode) {
		if (ctts->nb_entries==ctts->alloc_size) {
			ALLOC_INC(ctts->alloc_size);
			ctts->entries = gf_realloc(ctts->entries, sizeof(GF_DttsEntry)*ctts->alloc_size);
			if (!ctts->entries) return GF_OUT_OF_MEM;
			memset(&ctts->entries[ctts->nb_entries], 0, sizeof(GF_DttsEntry)*(ctts->alloc_size - ctts->nb_entries) );
		}
		ctts->entries[ctts->nb_entries].decodingOffset = offset;
		ctts->entries[ctts->nb_entries].sampleCount = 1;
		ctts->nb_entries++;
		ctts->w_LastSampleNumber++;
		if (offset<0) ctts->version=1;
		return GF_OK;
	}
	
	if (ctts->w_LastSampleNumber < sampleNumber) {
		
		while (ctts->w_LastSampleNumber + 1 != sampleNumber) {
			GF_Err e = AddCompositionOffset(ctts, 0);
			if (e) return e;
		}
		return AddCompositionOffset(ctts, offset);
	}

	
	CTSs = (u32*)gf_malloc(sizeof(u32) * (stbl->SampleSize->sampleCount+1) );
	if (!CTSs) return GF_OUT_OF_MEM;
	sampNum = 0;
	for (i=0; i<ctts->nb_entries; i++) {
		for (j = 0; j<ctts->entries[i].sampleCount; j++) {
			if (sampNum > stbl->SampleSize->sampleCount) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[iso file] Too many CTS Offset entries for %d samples\n", stbl->SampleSize->sampleCount ));
				gf_free(CTSs);
				return GF_ISOM_INVALID_FILE;
			}
			if (sampNum+1==sampleNumber) {
				CTSs[sampNum] = offset;
				sampNum ++;
			}
			CTSs[sampNum] = ctts->entries[i].decodingOffset;
			sampNum ++;
		}
	}

	
	if (ctts->nb_entries+2>=ctts->alloc_size) {
		ctts->alloc_size += 2;
		ctts->entries = gf_realloc(ctts->entries, sizeof(GF_DttsEntry)*ctts->alloc_size);
		if (!ctts->entries) return GF_OUT_OF_MEM;
		memset(&ctts->entries[ctts->nb_entries], 0, sizeof(GF_DttsEntry)*(ctts->alloc_size-ctts->nb_entries) );
	}

	ctts->entries[0].sampleCount = 1;
	ctts->entries[0].decodingOffset = CTSs[0];
	ctts->nb_entries = 1;
	j=0;
	for (i=1; i<stbl->SampleSize->sampleCount + 1; i++) {
		if (CTSs[i]==ctts->entries[j].decodingOffset) {
			ctts->entries[j].sampleCount++;
		} else {
			j++;
			ctts->nb_entries++;
			ctts->entries[j].sampleCount = 1;
			ctts->entries[j].decodingOffset = CTSs[i];
		}
	}
	gf_free(CTSs);

	if (offset<0) ctts->version=1;

	
	ctts->w_LastSampleNumber += 1;
	return GF_OK;
}

GF_Err stbl_repackCTS(GF_CompositionOffsetBox *ctts)
{
	u32 i, j;

	if (!ctts->unpack_mode) return GF_OK;
	ctts->unpack_mode = 0;

	j=0;
	for (i=1; i<ctts->nb_entries; i++) {
		if (ctts->entries[i].decodingOffset==ctts->entries[j].decodingOffset) {
			ctts->entries[j].sampleCount++;
		} else {
			j++;
			ctts->entries[j].sampleCount = 1;
			ctts->entries[j].decodingOffset = ctts->entries[i].decodingOffset;
		}
	}
	ctts->nb_entries=j+1;
	
	return GF_OK;
}

GF_Err stbl_unpackCTS(GF_SampleTableBox *stbl)
{
	GF_DttsEntry *packed;
	u32 i, j, count;
	GF_CompositionOffsetBox *ctts;
	ctts = stbl->CompositionOffset;
	if (!ctts || ctts->unpack_mode) return GF_OK;
	ctts->unpack_mode = 1;

	packed = ctts->entries;
	count = ctts->nb_entries;
	ctts->entries = NULL;
	ctts->nb_entries = 0;
	ctts->alloc_size = 0;
	for (i=0; i<count; i++) {
		for (j=0; j<packed[i].sampleCount; j++) {
			if (ctts->nb_entries == ctts->alloc_size) {
				ALLOC_INC(ctts->alloc_size);
				ctts->entries = gf_realloc(ctts->entries, sizeof(GF_DttsEntry)*ctts->alloc_size);
				if (!ctts->entries) return GF_OUT_OF_MEM;

				memset(&ctts->entries[ctts->nb_entries], 0, sizeof(GF_DttsEntry)*(ctts->alloc_size-ctts->nb_entries) );
			}
			ctts->entries[ctts->nb_entries].decodingOffset = packed[i].decodingOffset;
			ctts->entries[ctts->nb_entries].sampleCount = 1;
			ctts->nb_entries++;
		}
	}
	gf_free(packed);

	while (stbl->SampleSize->sampleCount > ctts->nb_entries) {
		if (ctts->nb_entries == ctts->alloc_size) {
			ALLOC_INC(ctts->alloc_size);
			ctts->entries = gf_realloc(ctts->entries, sizeof(GF_DttsEntry)*ctts->alloc_size);
			if (!ctts->entries) return GF_OUT_OF_MEM;
			memset(&ctts->entries[ctts->nb_entries], 0, sizeof(GF_DttsEntry)*(ctts->alloc_size-ctts->nb_entries) );
		}
		ctts->entries[ctts->nb_entries].decodingOffset = 0;
		ctts->entries[ctts->nb_entries].sampleCount = 1;
		ctts->nb_entries++;
	}
	return GF_OK;
}


GF_Err stbl_AddSize(GF_SampleSizeBox *stsz, u32 sampleNumber, u32 size, u32 nb_pack_samples)
{
	u32 i, k;
	u32 *newSizes;
	if (!stsz  || !sampleNumber) return GF_BAD_PARAM;

	if (sampleNumber > stsz->sampleCount + 1) return GF_BAD_PARAM;

	if (!nb_pack_samples) nb_pack_samples = 1;
	else if (nb_pack_samples>1)
		size /= nb_pack_samples;

	
	if (stsz->sizes == NULL) {
		
		if (! stsz->sampleCount && (stsz->type != GF_ISOM_BOX_TYPE_STZ2) ) {
			stsz->sampleCount = nb_pack_samples;
			stsz->sampleSize = size;
			return GF_OK;
		}
		
		if (stsz->sampleSize == size) {
			stsz->sampleCount += nb_pack_samples;
			return GF_OK;
		}
		if (nb_pack_samples>1) {
			GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[iso file] Inserting packed samples with different sizes is not yet supported\n" ));
			return GF_NOT_SUPPORTED;
		}
		
		stsz->sizes = (u32*)gf_malloc(sizeof(u32) * (stsz->sampleCount + 1));
		if (!stsz->sizes) return GF_OUT_OF_MEM;
		stsz->alloc_size = stsz->sampleCount + 1;

		k = 0;
		for (i = 0 ; i < stsz->sampleCount; i++) {
			if (i + 1 == sampleNumber) {
				stsz->sizes[i + k] = size;
				k = 1;
			}
			stsz->sizes[i+k] = stsz->sampleSize;
		}
		
		if (stsz->sampleCount + 1 == sampleNumber) {
			stsz->sizes[stsz->sampleCount] = size;
		}
		stsz->sampleSize = 0;
		stsz->sampleCount++;
		return GF_OK;
	}


	
	if (stsz->sampleCount + 1 == sampleNumber) {
		if (!stsz->alloc_size) stsz->alloc_size = stsz->sampleCount;
		if (stsz->sampleCount == stsz->alloc_size) {
			ALLOC_INC(stsz->alloc_size);
			stsz->sizes = gf_realloc(stsz->sizes, sizeof(u32)*(stsz->alloc_size) );
			if (!stsz->sizes) return GF_OUT_OF_MEM;
			memset(&stsz->sizes[stsz->sampleCount], 0, sizeof(u32)*(stsz->alloc_size - stsz->sampleCount) );
		}
		stsz->sizes[stsz->sampleCount] = size;
	} else {
		newSizes = (u32*)gf_malloc(sizeof(u32)*(1 + stsz->sampleCount) );
		if (!newSizes) return GF_OUT_OF_MEM;
		k = 0;
		for (i = 0; i < stsz->sampleCount; i++) {
			if (i + 1 == sampleNumber) {
				newSizes[i + k] = size;
				k = 1;
			}
			newSizes[i + k] = stsz->sizes[i];
		}
		gf_free(stsz->sizes);
		stsz->sizes = newSizes;
		stsz->alloc_size = 1 + stsz->sampleCount;
	}
	stsz->sampleCount++;
	return GF_OK;
}


GF_Err stbl_AddRAP(GF_SyncSampleBox *stss, u32 sampleNumber)
{
	u32 i, k;
	u32 *newNumbers;

	if (!stss || !sampleNumber) return GF_BAD_PARAM;

	if (stss->sampleNumbers == NULL) {
		ALLOC_INC(stss->alloc_size);
		stss->sampleNumbers = (u32*)gf_malloc(sizeof(u32)*stss->alloc_size);
		if (!stss->sampleNumbers) return GF_OUT_OF_MEM;
		stss->sampleNumbers[0] = sampleNumber;
		stss->nb_entries = 1;
		return GF_OK;
	}

	if (stss->sampleNumbers[stss->nb_entries-1] == sampleNumber) return GF_OK;

	if (stss->sampleNumbers[stss->nb_entries-1] < sampleNumber) {
		if (stss->nb_entries==stss->alloc_size) {
			ALLOC_INC(stss->alloc_size);
			stss->sampleNumbers = gf_realloc(stss->sampleNumbers, sizeof(u32) * stss->alloc_size);
			if (!stss->sampleNumbers) return GF_OUT_OF_MEM;
			memset(&stss->sampleNumbers[stss->nb_entries], 0, sizeof(u32) * (stss->alloc_size-stss->nb_entries) );
		}
		stss->sampleNumbers[stss->nb_entries] = sampleNumber;
	} else {
		newNumbers = (u32*)gf_malloc(sizeof(u32) * (stss->nb_entries + 1));
		if (!newNumbers) return GF_OUT_OF_MEM;
		
		k = 0;
		for (i = 0; i < stss->nb_entries; i++) {
			if (stss->sampleNumbers[i] >= sampleNumber) {
				newNumbers[i + k] = sampleNumber;
				k = 1;
			}
			newNumbers[i + k] = stss->sampleNumbers[i] + k;
		}
		gf_free(stss->sampleNumbers);
		stss->sampleNumbers = newNumbers;
		stss->alloc_size = stss->nb_entries+1;
	}
	
	stss->nb_entries ++;
	return GF_OK;
}

GF_Err stbl_AddRedundant(GF_SampleTableBox *stbl, u32 sampleNumber)
{
	GF_SampleDependencyTypeBox *sdtp;

	if (stbl->SampleDep == NULL) {
		stbl->SampleDep = (GF_SampleDependencyTypeBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_SDTP);
		if (!stbl->SampleDep) return GF_OUT_OF_MEM;
	}
	sdtp = stbl->SampleDep;
	if (sdtp->sampleCount + 1 < sampleNumber) {
		u32 missed = sampleNumber-1 - sdtp->sampleCount;
		sdtp->sample_info = (u8*) gf_realloc(sdtp->sample_info, sizeof(u8) * (sdtp->sampleCount+missed) );
		if (!sdtp->sample_info) return GF_OUT_OF_MEM;
		sdtp->sample_alloc = sdtp->sampleCount+missed;
		memset(&sdtp->sample_info[sdtp->sampleCount], 0, sizeof(u8) * missed );
		while (missed) {
			GF_ISOSAPType isRAP;
			if (stbl->SyncSample) stbl_GetSampleRAP(stbl->SyncSample, sdtp->sampleCount+1, &isRAP, NULL, NULL);
			else isRAP = 1;
			sdtp->sample_info[sdtp->sampleCount] = isRAP ? 0x20 : 0;
			sdtp->sampleCount++;
			missed--;
		}
	}

	sdtp->sample_info = (u8*) gf_realloc(sdtp->sample_info, sizeof(u8) * (sdtp->sampleCount + 1));
	if (!sdtp->sample_info) return GF_OUT_OF_MEM;
	sdtp->sample_alloc = sdtp->sampleCount+1;
	if (sdtp->sampleCount < sampleNumber) {
		sdtp->sample_info[sdtp->sampleCount] = 0x29;
	} else {
		u32 snum = sampleNumber-1;
		memmove(sdtp->sample_info+snum+1, sdtp->sample_info+snum, sizeof(u8) * (sdtp->sampleCount - snum) );
		sdtp->sample_info[snum] = 0x29;
	}
	
	sdtp->sampleCount ++;
	return GF_OK;
}

GF_Err stbl_SetDependencyType(GF_SampleTableBox *stbl, u32 sampleNumber, u32 isLeading, u32 dependsOn, u32 dependedOn, u32 redundant)
{
	GF_SampleDependencyTypeBox *sdtp;
	u32 flags;
	if (stbl->SampleDep == NULL) {
		stbl->SampleDep = (GF_SampleDependencyTypeBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_SDTP);
		if (!stbl->SampleDep) return GF_OUT_OF_MEM;
	}
	sdtp = stbl->SampleDep;

	flags = 0;
	flags |= isLeading << 6;
	flags |= dependsOn << 4;
	flags |= dependedOn << 2;
	flags |= redundant;

	if (sdtp->sampleCount < sampleNumber) {
		u32 i;
		sdtp->sample_info = (u8*) gf_realloc(sdtp->sample_info, sizeof(u8) * sampleNumber);
		if (!sdtp->sample_info) return GF_OUT_OF_MEM;
		sdtp->sample_alloc = sampleNumber;

		for (i=sdtp->sampleCount; i<sampleNumber; i++) {
			sdtp->sample_info[i] = 0;
		}
		sdtp->sampleCount = sampleNumber;
	}
	sdtp->sample_info[sampleNumber-1] = flags;
	return GF_OK;
}


GF_Err stbl_AddDependencyType(GF_SampleTableBox *stbl, u32 sampleNumber, u32 isLeading, u32 dependsOn, u32 dependedOn, u32 redundant)
{
	u32 flags;
	GF_SampleDependencyTypeBox *sdtp;

	if (stbl->SampleDep == NULL) {
		stbl->SampleDep = (GF_SampleDependencyTypeBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_SDTP);
		if (!stbl->SampleDep) return GF_OUT_OF_MEM;
	}
	sdtp = stbl->SampleDep;
	if (sdtp->sampleCount + 1 < sampleNumber) {
		u32 missed = sampleNumber-1 - sdtp->sampleCount;
		sdtp->sample_info = (u8*) gf_realloc(sdtp->sample_info, sizeof(u8) * (sdtp->sampleCount+missed) );
		if (!sdtp->sample_info) return GF_OUT_OF_MEM;
		sdtp->sample_alloc = sdtp->sampleCount+missed;
		memset(&sdtp->sample_info[sdtp->sampleCount], 0, sizeof(u8) * missed );
		while (missed) {
			GF_ISOSAPType isRAP;
			if (stbl->SyncSample) stbl_GetSampleRAP(stbl->SyncSample, sdtp->sampleCount+1, &isRAP, NULL, NULL);
			else isRAP = 1;
			sdtp->sample_info[sdtp->sampleCount] = isRAP ? (2<<4) : 0;
			if (isRAP) {
				sdtp->sample_info[sdtp->sampleCount] = 0;

			}
			sdtp->sampleCount++;
			missed--;
		}
	}

	flags = 0;
	flags |= isLeading << 6;
	flags |= dependsOn << 4;
	flags |= dependedOn << 2;
	flags |= redundant;

	sdtp->sample_info = (u8*) gf_realloc(sdtp->sample_info, sizeof(u8) * (sdtp->sampleCount + 1));
	if (!sdtp->sample_info) return GF_OUT_OF_MEM;
	sdtp->sample_alloc = sdtp->sampleCount + 1;
	if (sdtp->sampleCount < sampleNumber) {
		sdtp->sample_info[sdtp->sampleCount] = flags;
	} else {
		u32 snum = sampleNumber-1;
		memmove(sdtp->sample_info+snum+1, sdtp->sample_info+snum, sizeof(u8) * (sdtp->sampleCount - snum) );
		sdtp->sample_info[snum] = flags;
	}
	
	sdtp->sampleCount ++;
	return GF_OK;
}


GF_Err stbl_AppendDependencyType(GF_SampleTableBox *stbl, u32 isLeading, u32 dependsOn, u32 dependedOn, u32 redundant)
{
	GF_SampleDependencyTypeBox *sdtp;
	u32 flags;
	if (stbl->SampleDep == NULL) {
		stbl->SampleDep = (GF_SampleDependencyTypeBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_SDTP);
		if (!stbl->SampleDep) return GF_OUT_OF_MEM;
	}
	sdtp = stbl->SampleDep;

	flags = 0;
	flags |= isLeading << 6;
	flags |= dependsOn << 4;
	flags |= dependedOn << 2;
	flags |= redundant;

	if (sdtp->sampleCount >= sdtp->sample_alloc) {
		ALLOC_INC(sdtp->sample_alloc);
		if (sdtp->sampleCount >= sdtp->sample_alloc) sdtp->sample_alloc = sdtp->sampleCount+1;
		sdtp->sample_info = (u8*) gf_realloc(sdtp->sample_info, sizeof(u8) * sdtp->sample_alloc);
		if (!sdtp->sample_info) return GF_OUT_OF_MEM;
	}
	sdtp->sample_info[sdtp->sampleCount] = flags;
	sdtp->sampleCount ++;
	return GF_OK;
}


GF_Err stbl_AddShadow(GF_ShadowSyncBox *stsh, u32 sampleNumber, u32 shadowNumber)
{
	GF_StshEntry *ent;
	u32 i, count;
	count = gf_list_count(stsh->entries);
	for (i=0; i<count; i++) {
		ent = (GF_StshEntry*)gf_list_get(stsh->entries, i);
		if (ent->shadowedSampleNumber == shadowNumber) {
			ent->syncSampleNumber = sampleNumber;
			return GF_OK;
		} else if (ent->shadowedSampleNumber > shadowNumber) break;
	}
	ent = (GF_StshEntry*)gf_malloc(sizeof(GF_StshEntry));
	if (!ent) return GF_OUT_OF_MEM;
	ent->shadowedSampleNumber = shadowNumber;
	ent->syncSampleNumber = sampleNumber;
	if (i == gf_list_count(stsh->entries)) {
		return gf_list_add(stsh->entries, ent);
	} else {
		return gf_list_insert(stsh->entries, ent, i ? i-1 : 0);
	}
}


GF_Err stbl_AddChunkOffset(GF_MediaBox *mdia, u32 sampleNumber, u32 StreamDescIndex, u64 offset, u32 nb_pack_samples)
{
	GF_SampleTableBox *stbl;
	GF_ChunkOffsetBox *stco;
	GF_SampleToChunkBox *stsc;
	GF_ChunkLargeOffsetBox *co64;
	GF_StscEntry *ent;
	u32 i, k, *newOff, new_chunk_idx=0;
	u64 *newLarge;
	s32 insert_idx = -1;

	stbl = mdia->information->sampleTable;
	stsc = stbl->SampleToChunk;


	if (!nb_pack_samples)
		nb_pack_samples = 1;

	if (!stsc->nb_entries || (stsc->nb_entries + 2 >= stsc->alloc_size)) {
		if (!stsc->alloc_size) stsc->alloc_size = 1;
		ALLOC_INC(stsc->alloc_size);
		stsc->entries = gf_realloc(stsc->entries, sizeof(GF_StscEntry)*stsc->alloc_size);
		if (!stsc->entries) return GF_OUT_OF_MEM;
		memset(&stsc->entries[stsc->nb_entries], 0, sizeof(GF_StscEntry)*(stsc->alloc_size-stsc->nb_entries) );
	}
	if (sampleNumber == stsc->w_lastSampleNumber + 1) {
		ent = &stsc->entries[stsc->nb_entries];
		stsc->w_lastChunkNumber ++;
		ent->firstChunk = stsc->w_lastChunkNumber;
		if (stsc->nb_entries) stsc->entries[stsc->nb_entries-1].nextChunk = stsc->w_lastChunkNumber;

		new_chunk_idx = stsc->w_lastChunkNumber;
		stsc->w_lastSampleNumber = sampleNumber + nb_pack_samples-1;
		stsc->nb_entries += 1;
	} else {
		u32 cur_samp = 1;
		u32 samples_in_next_entry = 0;
		u32 next_entry_first_chunk = 1;
		for (i=0; i<stsc->nb_entries; i++) {
			u32 nb_chunks = 1;
			ent = &stsc->entries[i];
			if (i+1<stsc->nb_entries) nb_chunks = stsc->entries[i+1].firstChunk - ent->firstChunk;
			for (k=0; k<nb_chunks; k++) {
				if ((cur_samp <= sampleNumber) && (ent->samplesPerChunk + cur_samp > sampleNumber)) {
					insert_idx = i;
					
					if (sampleNumber>cur_samp) {
						samples_in_next_entry = ent->samplesPerChunk - (sampleNumber-cur_samp);
						ent->samplesPerChunk = sampleNumber-cur_samp;
					}
					break;
				}
				cur_samp += ent->samplesPerChunk;
				next_entry_first_chunk++;
			}
			if (insert_idx>=0) break;
		}
		
		if (samples_in_next_entry) {
			memmove(&stsc->entries[insert_idx+3], &stsc->entries[insert_idx+1], sizeof(GF_StscEntry)*(stsc->nb_entries - insert_idx - 1));
			
			ent = &stsc->entries[insert_idx];
			stsc->entries[insert_idx+2] = *ent;
			stsc->entries[insert_idx+2].samplesPerChunk = samples_in_next_entry;
			stsc->entries[insert_idx+2].firstChunk = next_entry_first_chunk + 1;

			
			ent = &stsc->entries[insert_idx+1];
			ent->firstChunk = next_entry_first_chunk;

			stsc->nb_entries += 2;
		} else {
			if (insert_idx<0) {
				ent = &stsc->entries[stsc->nb_entries];
				insert_idx = stsc->nb_entries;
			} else {
				memmove(&stsc->entries[insert_idx+1], &stsc->entries[insert_idx], sizeof(GF_StscEntry)*(stsc->nb_entries+1-insert_idx));
				ent = &stsc->entries[insert_idx+1];
			}

			ent->firstChunk = next_entry_first_chunk;
			stsc->nb_entries += 1;
		}
		new_chunk_idx = next_entry_first_chunk;
	}
	ent->isEdited = (Media_IsSelfContained(mdia, StreamDescIndex)) ? 1 : 0;
	ent->sampleDescriptionIndex = StreamDescIndex;
	ent->samplesPerChunk = nb_pack_samples;
	ent->nextChunk = ent->firstChunk+1;

	
	if (sampleNumber + nb_pack_samples - 1 == stsc->w_lastSampleNumber) {
		if (stsc->nb_entries)
			stsc->entries[stsc->nb_entries-1].nextChunk = ent->firstChunk;

		stbl->SampleToChunk->currentIndex = stsc->nb_entries-1;
		stbl->SampleToChunk->firstSampleInCurrentChunk = sampleNumber;
		
		stbl->SampleToChunk->currentChunk = stsc->w_lastChunkNumber;
		stbl->SampleToChunk->ghostNumber = 1;
	} else {
		
		for (i = insert_idx+1; i<stsc->nb_entries+1; i++) {
			stsc->entries[i].firstChunk++;
			if (i+1<stsc->nb_entries)
				stsc->entries[i-1].nextChunk = stsc->entries[i].firstChunk;
		}
	}

	
	
	if (stbl->ChunkOffset->type == GF_ISOM_BOX_TYPE_STCO) {
		stco = (GF_ChunkOffsetBox *)stbl->ChunkOffset;
		
		if (offset > 0xFFFFFFFF) {
			co64 = (GF_ChunkLargeOffsetBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_CO64);
			if (!co64) return GF_OUT_OF_MEM;
			co64->nb_entries = stco->nb_entries + 1;
			co64->alloc_size = co64->nb_entries;
			co64->offsets = (u64*)gf_malloc(sizeof(u64) * co64->nb_entries);
			if (!co64->offsets) return GF_OUT_OF_MEM;
			k = 0;
			for (i=0; i<stco->nb_entries; i++) {
				if (i + 1 == new_chunk_idx) {
					co64->offsets[i] = offset;
					k = 1;
				}
				co64->offsets[i+k] = (u64) stco->offsets[i];
			}
			if (!k) co64->offsets[co64->nb_entries - 1] = offset;
			gf_isom_box_del_parent(&stbl->child_boxes, stbl->ChunkOffset);
			stbl->ChunkOffset = (GF_Box *) co64;
		} else {
			
			if (new_chunk_idx > stco->nb_entries) {
				if (!stco->alloc_size) stco->alloc_size = stco->nb_entries;
				if (stco->nb_entries == stco->alloc_size) {
					ALLOC_INC(stco->alloc_size);
					stco->offsets = (u32*)gf_realloc(stco->offsets, sizeof(u32) * stco->alloc_size);
					if (!stco->offsets) return GF_OUT_OF_MEM;
					memset(&stco->offsets[stco->nb_entries], 0, sizeof(u32) * (stco->alloc_size-stco->nb_entries) );
				}
				stco->offsets[stco->nb_entries] = (u32) offset;
				stco->nb_entries += 1;
			} else {
				
				newOff = (u32*)gf_malloc(sizeof(u32) * (stco->nb_entries + 1));
				if (!newOff) return GF_OUT_OF_MEM;
				k=0;
				for (i=0; i<stco->nb_entries; i++) {
					if (i+1 == new_chunk_idx) {
						newOff[i] = (u32) offset;
						k=1;
					}
					newOff[i+k] = stco->offsets[i];
				}
				gf_free(stco->offsets);
				stco->offsets = newOff;
				stco->nb_entries ++;
				stco->alloc_size = stco->nb_entries;
			}
		}
	} else {
		
		co64 = (GF_ChunkLargeOffsetBox *)stbl->ChunkOffset;
		if (sampleNumber > co64->nb_entries) {
			if (!co64->alloc_size) co64->alloc_size = co64->nb_entries;
			if (co64->nb_entries == co64->alloc_size) {
				ALLOC_INC(co64->alloc_size);
				co64->offsets = (u64*)gf_realloc(co64->offsets, sizeof(u64) * co64->alloc_size);
				if (!co64->offsets) return GF_OUT_OF_MEM;
				memset(&co64->offsets[co64->nb_entries], 0, sizeof(u64) * (co64->alloc_size - co64->nb_entries) );
			}
			co64->offsets[co64->nb_entries] = offset;
			co64->nb_entries += 1;
		} else {
			
			newLarge = (u64*)gf_malloc(sizeof(u64) * (co64->nb_entries + 1));
			if (!newLarge) return GF_OUT_OF_MEM;
			k=0;
			for (i=0; i<co64->nb_entries; i++) {
				if (i+1 == new_chunk_idx) {
					newLarge[i] = offset;
					k=1;
				}
				newLarge[i+k] = co64->offsets[i];
			}
			gf_free(co64->offsets);
			co64->offsets = newLarge;
			co64->nb_entries++;
			co64->alloc_size++;
		}
	}

	return GF_OK;
}




GF_Err stbl_SetChunkOffset(GF_MediaBox *mdia, u32 sampleNumber, u64 offset)
{
	GF_StscEntry *ent;
	u32 i;
	GF_ChunkLargeOffsetBox *co64;
	GF_SampleTableBox *stbl = mdia->information->sampleTable;

	if (!sampleNumber || !stbl) return GF_BAD_PARAM;

	ent = &stbl->SampleToChunk->entries[sampleNumber - 1];

	
	if (Media_IsSelfContained(mdia, ent->sampleDescriptionIndex))
		ent->isEdited = 1;

	
	if (stbl->ChunkOffset->type == GF_ISOM_BOX_TYPE_STCO) {
		
		if (offset > 0xFFFFFFFF) {
			co64 = (GF_ChunkLargeOffsetBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_CO64);
			if (!co64) return GF_OUT_OF_MEM;
			co64->nb_entries = ((GF_ChunkOffsetBox *)stbl->ChunkOffset)->nb_entries;
			co64->alloc_size = co64->nb_entries;
			co64->offsets = (u64*)gf_malloc(sizeof(u64)*co64->nb_entries);
			if (!co64->offsets) return GF_OUT_OF_MEM;
			for (i=0; i<co64->nb_entries; i++) {
				co64->offsets[i] = (u64) ((GF_ChunkOffsetBox *)stbl->ChunkOffset)->offsets[i];
			}
			co64->offsets[ent->firstChunk - 1] = offset;
			gf_isom_box_del_parent(&stbl->child_boxes, stbl->ChunkOffset);
			stbl->ChunkOffset = (GF_Box *) co64;
			return GF_OK;
		}
		((GF_ChunkOffsetBox *)stbl->ChunkOffset)->offsets[ent->firstChunk - 1] = (u32) offset;
	} else {
		((GF_ChunkLargeOffsetBox *)stbl->ChunkOffset)->offsets[ent->firstChunk - 1] = offset;
	}
	return GF_OK;
}


GF_Err stbl_SetSampleCTS(GF_SampleTableBox *stbl, u32 sampleNumber, s32 offset)
{
	GF_CompositionOffsetBox *ctts = stbl->CompositionOffset;

	assert(ctts->unpack_mode);

	
	if (ctts->w_LastSampleNumber < sampleNumber) {
		
		while (ctts->w_LastSampleNumber + 1 != sampleNumber) {
			GF_Err e = AddCompositionOffset(ctts, 0);
			if (e) return e;
		}
		return AddCompositionOffset(ctts, offset);
	}
	if (offset<0) ctts->version=1;
	ctts->entries[sampleNumber-1].decodingOffset = offset;
	return GF_OK;
}

GF_Err stbl_SetSampleSize(GF_SampleSizeBox *stsz, u32 SampleNumber, u32 size)
{
	u32 i;
	if (!SampleNumber || (stsz->sampleCount < SampleNumber)) return GF_BAD_PARAM;

	if (stsz->sampleSize) {
		if (stsz->sampleSize == size) return GF_OK;
		if (stsz->sampleCount == 1) {
			stsz->sampleSize = size;
			return GF_OK;
		}
		
		stsz->sizes = (u32*)gf_malloc(sizeof(u32)*stsz->sampleCount);
		if (!stsz->sizes) return GF_OUT_OF_MEM;
		for (i=0; i<stsz->sampleCount; i++) stsz->sizes[i] = stsz->sampleSize;
		stsz->sampleSize = 0;
	}
	stsz->sizes[SampleNumber - 1] = size;
	return GF_OK;
}


GF_Err stbl_SetSampleRAP(GF_SyncSampleBox *stss, u32 SampleNumber, u8 isRAP)
{
	u32 i;

	
	for (i = 0; i < stss->nb_entries; i++) {

		if (stss->sampleNumbers[i] < SampleNumber) continue;
		else if (stss->sampleNumbers[i] > SampleNumber) break;

		
		if (isRAP) return GF_OK;
		
		if (i+1 < stss->nb_entries)
			memmove(stss->sampleNumbers + i, stss->sampleNumbers + i + 1, sizeof(u32) * (stss->nb_entries - i - 1));
		stss->nb_entries--;
		return GF_OK;
	}
	
	if (!isRAP) return GF_OK;
	if (stss->nb_entries==stss->alloc_size) {
		ALLOC_INC(stss->alloc_size);
		stss->sampleNumbers = gf_realloc(stss->sampleNumbers, sizeof(u32)*stss->alloc_size);
		if (!stss->sampleNumbers) return GF_OUT_OF_MEM;
		memset(&stss->sampleNumbers[stss->nb_entries], 0, sizeof(u32)*(stss->alloc_size - stss->nb_entries) );
	}

	if (i+1 < stss->nb_entries)
		memmove(stss->sampleNumbers + i + 1, stss->sampleNumbers + i, sizeof(u32) * (stss->nb_entries - i - 1));
	stss->sampleNumbers[i] = SampleNumber;
	stss->nb_entries ++;
	return GF_OK;
}

GF_Err stbl_SetRedundant(GF_SampleTableBox *stbl, u32 sampleNumber)
{
	if (stbl->SampleDep->sampleCount < sampleNumber) {
		return stbl_AddRedundant(stbl, sampleNumber);
	} else {
		stbl->SampleDep->sample_info[sampleNumber-1] = 0x29;
		return GF_OK;
	}
}

GF_Err stbl_SetSyncShadow(GF_ShadowSyncBox *stsh, u32 sampleNumber, u32 syncSample)
{
	u32 i, count;
	GF_StshEntry *ent;

	count = gf_list_count(stsh->entries);
	for (i=0; i<count; i++) {
		ent = (GF_StshEntry*)gf_list_get(stsh->entries, i);
		if (ent->shadowedSampleNumber == sampleNumber) {
			ent->syncSampleNumber = syncSample;
			return GF_OK;
		}
		if (ent->shadowedSampleNumber > sampleNumber) break;
	}
	
	ent = (GF_StshEntry*)gf_malloc(sizeof(GF_StshEntry));
	if (!ent) return GF_OUT_OF_MEM;
	ent->shadowedSampleNumber = sampleNumber;
	ent->syncSampleNumber = syncSample;
	
	if (i == gf_list_count(stsh->entries)) {
		
		return gf_list_add(stsh->entries, ent);
	} else {
		
		stsh->r_LastEntryIndex = i;
		stsh->r_LastFoundSample = sampleNumber;
		return gf_list_insert(stsh->entries, ent, i);
	}
}



GF_Err stbl_RemoveDTS(GF_SampleTableBox *stbl, u32 sampleNumber, u32 nb_samples, u32 LastAUDefDuration)
{
	GF_SttsEntry *ent;
	GF_TimeToSampleBox *stts;

	if ((nb_samples>1) && (sampleNumber>1)) return GF_BAD_PARAM;

	stts = stbl->TimeToSample;

	
	if (stbl->SampleSize->sampleCount == 1) {
		stts->nb_entries = 0;
		stts->r_FirstSampleInEntry = stts->r_currentEntryIndex = 0;
		stts->r_CurrentDTS = 0;
		return GF_OK;
	}
	
	if ((nb_samples==1) && (sampleNumber == stbl->SampleSize->sampleCount)) {
		ent = &stts->entries[stts->nb_entries-1];
		ent->sampleCount--;
		if (!ent->sampleCount) stts->nb_entries--;
	} else {
		u64 *DTSs, curDTS;
		u32 i, j, k, sampNum;
		u32 tot_samples, nb_written=0;
		
		DTSs = (u64*)gf_malloc(sizeof(u64) * (stbl->SampleSize->sampleCount - 1));
		if (!DTSs) return GF_OUT_OF_MEM;
		memset(DTSs, 0, sizeof(u64) * (stbl->SampleSize->sampleCount - 1) );

		curDTS = 0;
		sampNum = 0;
		ent = NULL;
		k=0;

		for (i=0; i<stts->nb_entries; i++) {
			ent = & stts->entries[i];
			for (j=0; j<ent->sampleCount; j++) {
				if (nb_samples==1) {
					if (sampNum == sampleNumber - 1) {
						k=1;
					} else {
						DTSs[sampNum-k] = curDTS;
					}
				} else if (sampNum >= nb_samples) {
					DTSs[sampNum - nb_samples] = curDTS;
					nb_written++;
				}
				curDTS += ent->sampleDelta;
				sampNum ++;
			}
		}

		if (nb_samples>1) {
			assert(sampNum == stbl->SampleSize->sampleCount);
			assert(nb_written + nb_samples == stbl->SampleSize->sampleCount);
		}
		j=0;

		if (nb_samples==1) {
			tot_samples = stbl->SampleSize->sampleCount - 1;
		} else {
			tot_samples = stbl->SampleSize->sampleCount - nb_samples;
		}
		if (tot_samples) {
			sampNum = 1;
			stts->nb_entries = 1;
			stts->entries[0].sampleCount = 1;
			if (stbl->SampleSize->sampleCount == 2) {
				stts->entries[0].sampleDelta = LastAUDefDuration;
			} else {
				stts->entries[0].sampleDelta = (u32) DTSs[1] ;
			}
		} else {
			sampNum = 0;
			stts->nb_entries = 0;
		}

		for (i=1; i<tot_samples; i++) {
			if (i+1 == tot_samples) {
				
				stts->entries[j].sampleCount++;
				sampNum ++;
			} else if (DTSs[i+1] - DTSs[i] == stts->entries[j].sampleDelta) {
				stts->entries[j].sampleCount += 1;
				sampNum ++;
			} else {
				stts->nb_entries++;
				if (j+1==stts->alloc_size) {
					stts->alloc_size++;
					stts->entries = gf_realloc(stts->entries, sizeof(GF_SttsEntry) * stts->alloc_size);
					if (!stts->entries) return GF_OUT_OF_MEM;
				}
				j++;
				stts->entries[j].sampleCount = 1;
				stts->entries[j].sampleDelta = (u32) (DTSs[i+1] - DTSs[i]);
				assert(stts->entries[j].sampleDelta);
				sampNum ++;
			}
		}
		stts->w_LastDTS = tot_samples ? DTSs[tot_samples - 1] : 0;
		gf_free(DTSs);
		assert(sampNum == tot_samples);
		assert(sampNum + nb_samples == stbl->SampleSize->sampleCount);
	}

	
	stts->w_currentSampleNum = stbl->SampleSize->sampleCount - nb_samples;
	
	stts->r_FirstSampleInEntry = stts->r_currentEntryIndex = 0;
	stts->r_CurrentDTS = 0;
	return GF_OK;
}



GF_Err stbl_RemoveCTS(GF_SampleTableBox *stbl, u32 sampleNumber, u32 nb_samples)
{
	GF_CompositionOffsetBox *ctts = stbl->CompositionOffset;
	if (!ctts) return GF_OK;

	assert(ctts->unpack_mode);
	if ((nb_samples>1) && (sampleNumber>1)) return GF_BAD_PARAM;

	
	if (stbl->SampleSize->sampleCount == 1) {
		gf_isom_box_del_parent(&stbl->child_boxes, (GF_Box *) ctts);
		stbl->CompositionOffset = NULL;
		return GF_OK;
	}

	
	
	
	if (sampleNumber > ctts->w_LastSampleNumber) return GF_OK;

	if (nb_samples==1) {
		assert(ctts->nb_entries);
		memmove(&ctts->entries[sampleNumber-1], &ctts->entries[sampleNumber], sizeof(GF_DttsEntry)* (ctts->nb_entries-sampleNumber) );
		ctts->nb_entries--;
	} else {
		memmove(&ctts->entries[0], &ctts->entries[nb_samples], sizeof(GF_DttsEntry)* (ctts->nb_entries-nb_samples) );
		ctts->nb_entries -= nb_samples;
	}
	ctts->w_LastSampleNumber -= nb_samples;
	assert(ctts->w_LastSampleNumber >= ctts->nb_entries);

	return GF_OK;
}

GF_Err stbl_RemoveSize(GF_SampleTableBox *stbl, u32 sampleNumber, u32 nb_samples)
{
	GF_SampleSizeBox *stsz = stbl->SampleSize;

	if ((nb_samples>1) && (sampleNumber>1)) return GF_BAD_PARAM;
	
	if (stsz->sampleCount == 1) {
		if (stsz->sizes) gf_free(stsz->sizes);
		stsz->sizes = NULL;
		stsz->sampleCount = 0;
		return GF_OK;
	}
	
	if (stsz->sampleSize) {
		stsz->sampleCount -= nb_samples;
		return GF_OK;
	}
	if (nb_samples==1) {
		if (sampleNumber < stsz->sampleCount)
			memmove(stsz->sizes + sampleNumber - 1, stsz->sizes + sampleNumber, sizeof(u32) * (stsz->sampleCount - sampleNumber));
	} else {
		if (nb_samples < stsz->sampleCount)
			memmove(stsz->sizes, stsz->sizes + nb_samples, sizeof(u32) * (stsz->sampleCount - nb_samples));
	}
	stsz->sampleCount -= nb_samples;
	return GF_OK;
}


GF_Err stbl_RemoveChunk(GF_SampleTableBox *stbl, u32 sampleNumber, u32 nb_samples)
{
	u32 i;
	GF_SampleToChunkBox *stsc = stbl->SampleToChunk;

	if ((nb_samples>1) && (sampleNumber>1))
		return GF_BAD_PARAM;
	
	
	if (stsc->nb_entries < stbl->SampleSize->sampleCount) {
		if (sampleNumber==stbl->SampleSize->sampleCount+1) {
			GF_StscEntry *ent = &stsc->entries[stsc->nb_entries-1];
			if (ent->samplesPerChunk)
				ent->samplesPerChunk--;
			if (!ent->samplesPerChunk) {
				stsc->nb_entries--;

				if (stbl->ChunkOffset->type == GF_ISOM_BOX_TYPE_STCO) {
					((GF_ChunkOffsetBox *)stbl->ChunkOffset)->nb_entries --;
				} else {
					((GF_ChunkLargeOffsetBox *)stbl->ChunkOffset)->nb_entries --;
				}
				if (stsc->nb_entries) {
					ent = &stsc->entries[stsc->nb_entries-1];
					ent->nextChunk --;
				}
			}
			return GF_OK;
		}
		GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[iso file] removing sample in middle of track not supported for constant size and duration samples\n"));
		return GF_NOT_SUPPORTED;
	}

	
	if (nb_samples==1) {
		memmove(&stsc->entries[sampleNumber-1], &stsc->entries[sampleNumber], sizeof(GF_StscEntry)*(stsc->nb_entries-sampleNumber));
		stsc->nb_entries--;

		
		for (i=sampleNumber-1; i < stsc->nb_entries; i++) {
			assert(stsc->entries[i].firstChunk >= 1);
			stsc->entries[i].firstChunk -= 1;
			if (stsc->entries[i].nextChunk) {
				assert(stsc->entries[i].nextChunk >= 1);
				stsc->entries[i].nextChunk -= 1;
			}
		}
	} else {
		memmove(&stsc->entries[0], &stsc->entries[nb_samples], sizeof(GF_StscEntry)*(stsc->nb_entries-nb_samples));
		stsc->nb_entries -= nb_samples;

		
		for (i=0; i < stsc->nb_entries; i++) {
			stsc->entries[i].firstChunk = i+1;
			stsc->entries[i].nextChunk = (stsc->nb_entries==i+1) ? 0 : i+2;
		}
	}
	memset(&stsc->entries[stsc->nb_entries], 0, sizeof(GF_StscEntry)*(stsc->alloc_size - stsc->nb_entries) );

	
	stsc->firstSampleInCurrentChunk = 1;
	stsc->currentIndex = 0;
	stsc->currentChunk = 1;
	stsc->ghostNumber = 1;

	
	if (stbl->ChunkOffset->type == GF_ISOM_BOX_TYPE_STCO) {
		GF_ChunkOffsetBox *stco = (GF_ChunkOffsetBox *)stbl->ChunkOffset;
		if (!stbl->SampleSize->sampleCount) {
			gf_free(stco->offsets);
			stco->offsets = NULL;
			stco->nb_entries = 0;
			stco->alloc_size = 0;
			return GF_OK;
		}
		assert(stco->nb_entries - nb_samples == stbl->SampleSize->sampleCount);
		if (nb_samples==1) {
			memmove(&stco->offsets[sampleNumber-1], &stco->offsets[sampleNumber], sizeof(u32) * (stco->nb_entries - sampleNumber) );
		} else {
			memmove(&stco->offsets[0], &stco->offsets[nb_samples], sizeof(u32) * (stco->nb_entries - nb_samples) );
		}
		stco->nb_entries -= nb_samples;
	} else {
		GF_ChunkLargeOffsetBox *co64 = (GF_ChunkLargeOffsetBox *)stbl->ChunkOffset;
		if (!stbl->SampleSize->sampleCount) {
			gf_free(co64->offsets);
			co64->offsets = NULL;
			co64->nb_entries = 0;
			co64->alloc_size = 0;
			return GF_OK;
		}

		assert(co64->nb_entries - nb_samples == stbl->SampleSize->sampleCount);
		if (nb_samples==1) {
			memmove(&co64->offsets[sampleNumber-1], &co64->offsets[sampleNumber], sizeof(u64) * (co64->nb_entries - sampleNumber) );
		} else {
			memmove(&co64->offsets[0], &co64->offsets[nb_samples], sizeof(u64) * (co64->nb_entries - nb_samples) );
		}
		co64->nb_entries -= nb_samples;
	}
	return GF_OK;
}


GF_Err stbl_RemoveRAP(GF_SampleTableBox *stbl, u32 sampleNumber)
{
	u32 i;

	GF_SyncSampleBox *stss = stbl->SyncSample;
	if (!stss) return GF_OK;

	
	if (stss->nb_entries == 1) {
		if (stss->sampleNumbers[0] != sampleNumber) return GF_OK;
		
		gf_free(stss->sampleNumbers);
		stss->sampleNumbers = NULL;
		stss->r_LastSampleIndex = stss->r_LastSyncSample = 0;
		stss->alloc_size = stss->nb_entries = 0;
		return GF_OK;
	}

	for (i=0; i<stss->nb_entries; i++) {
		
		if (sampleNumber == stss->sampleNumbers[i]) {
			memmove(&stss->sampleNumbers[i], &stss->sampleNumbers[i+1], sizeof(u32)* (stss->nb_entries-i-1) );
			stss->nb_entries--;
		}

		if (sampleNumber < stss->sampleNumbers[i]) {
			assert(stss->sampleNumbers[i]);
			stss->sampleNumbers[i]--;
		}
	}
	return GF_OK;
}

GF_Err stbl_RemoveRedundant(GF_SampleTableBox *stbl, u32 SampleNumber, u32 nb_samples)
{
	u32 i;

	if (!stbl->SampleDep) return GF_OK;
	if (stbl->SampleDep->sampleCount < SampleNumber) return GF_BAD_PARAM;
	if ((nb_samples>1) && (SampleNumber>1)) return GF_BAD_PARAM;

	if (nb_samples==1) {
		i = stbl->SampleDep->sampleCount - SampleNumber;
		if (i) memmove(&stbl->SampleDep->sample_info[SampleNumber-1], & stbl->SampleDep->sample_info[SampleNumber], sizeof(u8)*i);
		stbl->SampleDep->sample_info = (u8*)gf_realloc(stbl->SampleDep->sample_info, sizeof(u8) * (stbl->SampleDep->sampleCount-1));
		if (!stbl->SampleDep->sample_info) return GF_OUT_OF_MEM;
		stbl->SampleDep->sample_alloc = stbl->SampleDep->sampleCount-1;
		stbl->SampleDep->sampleCount-=1;
	} else {
		memmove(&stbl->SampleDep->sample_info[0], &stbl->SampleDep->sample_info[nb_samples], sizeof(u8) * (stbl->SampleDep->sampleCount - nb_samples) );
		stbl->SampleDep->sampleCount -= nb_samples;
	}
	return GF_OK;
}

GF_Err stbl_RemoveShadow(GF_SampleTableBox *stbl, u32 sampleNumber)
{
	u32 i;
	GF_ShadowSyncBox *stsh;
	GF_StshEntry *ent;
	if (!stbl->ShadowSync) return GF_OK;
	stsh = stbl->ShadowSync;

	
	
	i=0;
	while ((ent = (GF_StshEntry *)gf_list_enum(stsh->entries, &i))) {
		if (ent->shadowedSampleNumber == sampleNumber) {
			i--;
			gf_list_rem(stsh->entries, i);
		}
	}
	
	stsh->r_LastEntryIndex = 0;
	stsh->r_LastFoundSample = 0;
	return GF_OK;
}


GF_Err stbl_SetPaddingBits(GF_SampleTableBox *stbl, u32 SampleNumber, u8 bits)
{
	u8 *p;
	
	if (SampleNumber > stbl->SampleSize->sampleCount) return GF_BAD_PARAM;

	
	if (!stbl->PaddingBits) {
		stbl->PaddingBits = (GF_PaddingBitsBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_PADB);
		if (!stbl->PaddingBits) return GF_OUT_OF_MEM;
	}

	
	if (!stbl->PaddingBits->padbits || !stbl->PaddingBits->SampleCount) {
		stbl->PaddingBits->SampleCount = stbl->SampleSize->sampleCount;
		stbl->PaddingBits->padbits = (u8*)gf_malloc(sizeof(u8)*stbl->PaddingBits->SampleCount);
		if (!stbl->PaddingBits->padbits) return GF_OUT_OF_MEM;
		memset(stbl->PaddingBits->padbits, 0, sizeof(u8)*stbl->PaddingBits->SampleCount);
	}
	
	if (stbl->PaddingBits->SampleCount < stbl->SampleSize->sampleCount) {
		p = (u8*)gf_malloc(sizeof(u8) * stbl->SampleSize->sampleCount);
		if (!p) return GF_OUT_OF_MEM;
		
		memset(p, 0, stbl->SampleSize->sampleCount);
		
		memcpy(p, stbl->PaddingBits->padbits, stbl->PaddingBits->SampleCount);
		gf_free(stbl->PaddingBits->padbits);
		stbl->PaddingBits->padbits = p;
		stbl->PaddingBits->SampleCount = stbl->SampleSize->sampleCount;
	}
	stbl->PaddingBits->padbits[SampleNumber-1] = bits;
	return GF_OK;
}

GF_Err stbl_RemovePaddingBits(GF_SampleTableBox *stbl, u32 SampleNumber)
{
	u8 *p;
	u32 i, k;

	if (!stbl->PaddingBits) return GF_OK;
	if (stbl->PaddingBits->SampleCount < SampleNumber) return GF_BAD_PARAM;

	
	if (stbl->PaddingBits->SampleCount == 1) {
		gf_isom_box_del_parent(&stbl->child_boxes, (GF_Box *) stbl->PaddingBits);
		stbl->PaddingBits = NULL;
		return GF_OK;
	}

	
	p = (u8 *)gf_malloc(sizeof(u8) * (stbl->PaddingBits->SampleCount - 1));
	if (!p) return GF_OUT_OF_MEM;

	k=0;
	for (i=0; i<stbl->PaddingBits->SampleCount; i++) {
		if (i+1 != SampleNumber) {
			p[k] = stbl->PaddingBits->padbits[i];
			k++;
		}
	}

	stbl->PaddingBits->SampleCount -= 1;
	gf_free(stbl->PaddingBits->padbits);
	stbl->PaddingBits->padbits = p;
	return GF_OK;
}

GF_Err stbl_RemoveSubSample(GF_SampleTableBox *stbl, u32 SampleNumber)
{
	u32 i, count, j, subs_count, prev_sample, delta=0;

	if (! stbl->sub_samples) return GF_OK;
	subs_count = gf_list_count(stbl->sub_samples);
	for (j=0; j<subs_count; j++) {
		GF_SubSampleInformationBox *subs = gf_list_get(stbl->sub_samples, j);
		if (! subs->Samples) continue;

		prev_sample = 0;
		count = gf_list_count(subs->Samples);
		for (i=0; i<count; i++) {
			GF_SubSampleInfoEntry *e = gf_list_get(subs->Samples, i);
			prev_sample += e->sample_delta;
			if (prev_sample==SampleNumber) {
				gf_list_rem(subs->Samples, i);
				while (gf_list_count(e->SubSamples)) {
					GF_SubSampleEntry *pSubSamp = (GF_SubSampleEntry*) gf_list_get(e->SubSamples, 0);
					gf_free(pSubSamp);
					gf_list_rem(e->SubSamples, 0);
				}
				gf_list_del(e->SubSamples);
				gf_free(e);
				i--;
				count--;
				delta=1;
				continue;
			}
			e->sample_delta+=delta;
		}
	}
	return GF_OK;
}


GF_Err stbl_RemoveSampleGroup(GF_SampleTableBox *stbl, u32 SampleNumber)
{
	u32 i, k, count, prev_sample;

	if (!stbl->sampleGroups) return GF_OK;

	count = gf_list_count(stbl->sampleGroups);
	prev_sample = 0;
	for (i=0; i<count; i++) {
		GF_SampleGroupBox *e = gf_list_get(stbl->sampleGroups, i);
		for (k=0; k<e->entry_count; k++) {
			if ((SampleNumber>prev_sample) && (SampleNumber <= prev_sample + e->sample_entries[k].sample_count) ) {
				e->sample_entries[k].sample_count--;
				if (!e->sample_entries[k].sample_count) {
					memmove(&e->sample_entries[k], &e->sample_entries[k+1], sizeof(GF_SampleGroupEntry) * (e->entry_count-k-1));
					e->entry_count--;
				}
				break;
			}
		}
		if (!e->entry_count) {
			gf_list_rem(stbl->sampleGroups, i);
			i--;
			count--;
			gf_isom_box_del_parent(&stbl->child_boxes, (GF_Box *) e);
		}
	}
	return GF_OK;
}

GF_Err stbl_SampleSizeAppend(GF_SampleSizeBox *stsz, u32 data_size)
{
	u32 i;
	if (!stsz || !stsz->sampleCount) return GF_BAD_PARAM;

	
	if (stsz->sampleSize) {
		stsz->sizes = (u32*)gf_malloc(sizeof(u32)*stsz->sampleCount);
		if (!stsz->sizes) return GF_OUT_OF_MEM;
		for (i=0; i<stsz->sampleCount; i++) stsz->sizes[i] = stsz->sampleSize;
		stsz->sampleSize = 0;
	}
	if (!stsz->sizes) {
		stsz->sampleSize = data_size;
	} else {
		u32 single_size;
		stsz->sizes[stsz->sampleCount-1] += data_size;

		single_size = stsz->sizes[0];
		for (i=1; i<stsz->sampleCount; i++) {
			if (stsz->sizes[i] != single_size) {
				single_size = 0;
				break;
			}
		}
		if (single_size) {
			stsz->sampleSize = single_size;
			gf_free(stsz->sizes);
			stsz->sizes = NULL;
		}
	}
	return GF_OK;
}





GF_Err stbl_AppendTime(GF_SampleTableBox *stbl, u32 duration, u32 nb_pack)
{
	GF_TimeToSampleBox *stts = stbl->TimeToSample;

	if (!nb_pack) nb_pack = 1;
	if (stts->nb_entries) {
		if (stts->entries[stts->nb_entries-1].sampleDelta == duration) {
			stts->entries[stts->nb_entries-1].sampleCount += nb_pack;
			return GF_OK;
		}
	}
	if (stts->nb_entries==stts->alloc_size) {
		ALLOC_INC(stts->alloc_size);
		stts->entries = gf_realloc(stts->entries, sizeof(GF_SttsEntry)*stts->alloc_size);
		if (!stts->entries) return GF_OUT_OF_MEM;
		memset(&stts->entries[stts->nb_entries], 0, sizeof(GF_SttsEntry)*(stts->alloc_size-stts->nb_entries) );
	}
	stts->entries[stts->nb_entries].sampleCount = nb_pack;
	stts->entries[stts->nb_entries].sampleDelta = duration;
	stts->nb_entries++;
	if (stts->max_ts_delta < duration ) stts->max_ts_delta = duration;
	return GF_OK;
}

GF_Err stbl_AppendSize(GF_SampleTableBox *stbl, u32 size, u32 nb_pack)
{
	u32 i;
	if (!nb_pack) nb_pack = 1;

	if (!stbl->SampleSize->sampleCount) {
		stbl->SampleSize->sampleSize = size;
		stbl->SampleSize->sampleCount += nb_pack;
		return GF_OK;
	}
	if (stbl->SampleSize->sampleSize && (stbl->SampleSize->sampleSize==size)) {
		stbl->SampleSize->sampleCount += nb_pack;
		return GF_OK;
	}
	if (!stbl->SampleSize->sizes || (stbl->SampleSize->sampleCount+nb_pack > stbl->SampleSize->alloc_size)) {
		Bool init_table = (stbl->SampleSize->sizes==NULL) ? 1 : 0;
		ALLOC_INC(stbl->SampleSize->alloc_size);
		if (stbl->SampleSize->sampleCount+nb_pack > stbl->SampleSize->alloc_size)
			stbl->SampleSize->alloc_size = stbl->SampleSize->sampleCount+nb_pack;

		stbl->SampleSize->sizes = (u32 *)gf_realloc(stbl->SampleSize->sizes, sizeof(u32)*stbl->SampleSize->alloc_size);
		if (!stbl->SampleSize->sizes) return GF_OUT_OF_MEM;
		memset(&stbl->SampleSize->sizes[stbl->SampleSize->sampleCount], 0, sizeof(u32) * (stbl->SampleSize->alloc_size - stbl->SampleSize->sampleCount) );

		if (init_table) {
			for (i=0; i<stbl->SampleSize->sampleCount; i++)
				stbl->SampleSize->sizes[i] = stbl->SampleSize->sampleSize;
		}
	}
	stbl->SampleSize->sampleSize = 0;
	for (i=0; i<nb_pack; i++) {
		stbl->SampleSize->sizes[stbl->SampleSize->sampleCount+i] = size;
	}
	stbl->SampleSize->sampleCount += nb_pack;
	if (size > stbl->SampleSize->max_size)
		stbl->SampleSize->max_size = size;
	stbl->SampleSize->total_size += size;
	stbl->SampleSize->total_samples += nb_pack;
	return GF_OK;
}



GF_Err stbl_AppendChunk(GF_SampleTableBox *stbl, u64 offset)
{
	GF_ChunkOffsetBox *stco;
	GF_ChunkLargeOffsetBox *co64;
	u32 i;
	
	
	if (stbl->ChunkOffset->type==GF_ISOM_BOX_TYPE_STCO) {
		stco = (GF_ChunkOffsetBox *)stbl->ChunkOffset;

		if (offset>0xFFFFFFFF) {
			co64 = (GF_ChunkLargeOffsetBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_CO64);
			if (!co64) return GF_OUT_OF_MEM;
			co64->nb_entries = stco->nb_entries + 1;
			if (co64->nb_entries<=stco->nb_entries) return GF_OUT_OF_MEM;
			co64->alloc_size = co64->nb_entries;
			co64->offsets = (u64*)gf_malloc(sizeof(u64) * co64->nb_entries);
			if (!co64->offsets) return GF_OUT_OF_MEM;
			for (i=0; i<stco->nb_entries; i++) co64->offsets[i] = stco->offsets[i];
			co64->offsets[i] = offset;
			gf_isom_box_del_parent(&stbl->child_boxes, stbl->ChunkOffset);
			stbl->ChunkOffset = (GF_Box *) co64;
			return GF_OK;
		}
		
		stco->alloc_size = stco->nb_entries + 1;
		if (stco->alloc_size < stco->nb_entries + 1) return GF_OUT_OF_MEM;
		stco->offsets = gf_realloc(stco->offsets, sizeof(u32)*stco->alloc_size);
		if (!stco->offsets) return GF_OUT_OF_MEM;
		stco->offsets[stco->nb_entries] = (u32) offset;
		stco->nb_entries += 1;
		return GF_OK;
	}

	co64 = (GF_ChunkLargeOffsetBox *)stbl->ChunkOffset;
	co64->alloc_size = co64->nb_entries+1;
	if (co64->alloc_size < co64->nb_entries + 1) return GF_OUT_OF_MEM;

	co64->offsets = gf_realloc(co64->offsets, sizeof(u64)*co64->alloc_size);
	if (!co64->offsets) return GF_OUT_OF_MEM;
	co64->offsets[co64->nb_entries] = offset;
	co64->alloc_size = co64->nb_entries;
	return GF_OK;
}

GF_Err stbl_AppendSampleToChunk(GF_SampleTableBox *stbl, u32 DescIndex, u32 samplesInChunk)
{
	u32 nextChunk;
	GF_SampleToChunkBox *stsc= stbl->SampleToChunk;
	GF_StscEntry *ent;

	nextChunk = ((GF_ChunkOffsetBox *) stbl->ChunkOffset)->nb_entries;

	if (stsc->nb_entries) {
		ent = &stsc->entries[stsc->nb_entries-1];
		
		if ( (ent->sampleDescriptionIndex == DescIndex) && (ent->samplesPerChunk==samplesInChunk))
			return GF_OK;

		
		ent->nextChunk = nextChunk;
	}
	if (stsc->nb_entries==stsc->alloc_size) {
		ALLOC_INC(stsc->alloc_size);
		stsc->entries = gf_realloc(stsc->entries, sizeof(GF_StscEntry)*stsc->alloc_size);
		if (!stsc->entries) return GF_OUT_OF_MEM;
		memset(&stsc->entries[stsc->nb_entries], 0, sizeof(GF_StscEntry)*(stsc->alloc_size - stsc->nb_entries) );
	}
	
	ent = &stsc->entries[stsc->nb_entries];
	ent->firstChunk = nextChunk;
	ent->sampleDescriptionIndex = DescIndex;
	ent->samplesPerChunk = samplesInChunk;
	ent->isEdited = 0;
	stsc->nb_entries++;
	return GF_OK;
}


GF_Err stbl_AppendRAP(GF_SampleTableBox *stbl, u8 isRap)
{
	u32 i;

	
	if (!stbl->SyncSample) {
		
		if (isRap) return GF_OK;

		
		stbl->SyncSample = (GF_SyncSampleBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_STSS);
		if (!stbl->SyncSample) return GF_OUT_OF_MEM;

		if (stbl->SampleSize->sampleCount > 1) {
			stbl->SyncSample->sampleNumbers = (u32*)gf_malloc(sizeof(u32) * (stbl->SampleSize->sampleCount-1));
			if (!stbl->SyncSample->sampleNumbers) return GF_OUT_OF_MEM;
			for (i=0; i<stbl->SampleSize->sampleCount-1; i++)
				stbl->SyncSample->sampleNumbers[i] = i+1;

		}
		stbl->SyncSample->nb_entries = stbl->SampleSize->sampleCount-1;
		stbl->SyncSample->alloc_size = stbl->SyncSample->nb_entries;
		return GF_OK;
	}
	if (!isRap) return GF_OK;

	if (stbl->SyncSample->alloc_size == stbl->SyncSample->nb_entries) {
		ALLOC_INC(stbl->SyncSample->alloc_size);
		stbl->SyncSample->sampleNumbers = (u32*) gf_realloc(stbl->SyncSample->sampleNumbers, sizeof(u32) * stbl->SyncSample->alloc_size);
		if (!stbl->SyncSample->sampleNumbers) return GF_OUT_OF_MEM;
		memset(&stbl->SyncSample->sampleNumbers[stbl->SyncSample->nb_entries], 0, sizeof(u32) * (stbl->SyncSample->alloc_size-stbl->SyncSample->nb_entries) );
	}
	stbl->SyncSample->sampleNumbers[stbl->SyncSample->nb_entries] = stbl->SampleSize->sampleCount;
	stbl->SyncSample->nb_entries += 1;
	return GF_OK;
}

GF_Err stbl_AppendTrafMap(GF_SampleTableBox *stbl, Bool is_seg_start, u64 seg_start_offset, u64 frag_start_offset, u8 *moof_template, u32 moof_template_size, u64 sidx_start, u64 sidx_end)
{
	GF_TrafToSampleMap *tmap;
	GF_TrafMapEntry *tmap_ent;
	if (!stbl->traf_map) {
		
		GF_SAFEALLOC(stbl->traf_map, GF_TrafToSampleMap);
		if (!stbl->traf_map) return GF_OUT_OF_MEM;
	}
	tmap = stbl->traf_map;
	if (tmap->nb_entries >= stbl->SampleSize->sampleCount) {
		u32 i;
		for (i=0; i<tmap->nb_entries; i++) {
			if (tmap->frag_starts[i].moof_template)
				gf_free(tmap->frag_starts[i].moof_template);
		}
		memset(tmap->frag_starts, 0, sizeof(GF_TrafMapEntry)*tmap->nb_alloc);
		tmap->nb_entries = 0;
	}

	if (tmap->nb_entries + 1 > tmap->nb_alloc) {
		tmap->nb_alloc++;
		tmap->frag_starts = gf_realloc(tmap->frag_starts, sizeof(GF_TrafMapEntry) * tmap->nb_alloc);
		if (!tmap->frag_starts) return GF_OUT_OF_MEM;
	}
	tmap_ent = &tmap->frag_starts[tmap->nb_entries];
	tmap->nb_entries += 1;

	memset(tmap_ent, 0, sizeof(GF_TrafMapEntry));
	tmap_ent->sample_num = stbl->SampleSize->sampleCount;
	tmap_ent->moof_template = moof_template;
	tmap_ent->moof_template_size = moof_template_size;
	tmap_ent->moof_start = frag_start_offset;
	tmap_ent->sidx_start = sidx_start;
	tmap_ent->sidx_end = sidx_end;
	if (is_seg_start)
		tmap_ent->seg_start_plus_one = 1 + seg_start_offset;

	return GF_OK;
}

GF_Err stbl_AppendPadding(GF_SampleTableBox *stbl, u8 padding)
{
	if (!stbl->PaddingBits) {
		stbl->PaddingBits = (GF_PaddingBitsBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_PADB);
		if (!stbl->PaddingBits) return GF_OUT_OF_MEM;
	}
	stbl->PaddingBits->padbits = (u8*)gf_realloc(stbl->PaddingBits->padbits, sizeof(u8) * stbl->SampleSize->sampleCount);
	if (!stbl->PaddingBits->padbits) return GF_OUT_OF_MEM;
	stbl->PaddingBits->padbits[stbl->SampleSize->sampleCount-1] = padding;
	stbl->PaddingBits->SampleCount = stbl->SampleSize->sampleCount;
	return GF_OK;
}

GF_Err stbl_AppendCTSOffset(GF_SampleTableBox *stbl, s32 offset)
{
	GF_CompositionOffsetBox *ctts;

	if (!stbl->CompositionOffset) {
		stbl->CompositionOffset = (GF_CompositionOffsetBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_CTTS);
		if (!stbl->CompositionOffset) return GF_OUT_OF_MEM;
	}
	ctts = stbl->CompositionOffset;
	ctts->w_LastSampleNumber ++;

	if (!ctts->unpack_mode && ctts->nb_entries && (ctts->entries[ctts->nb_entries-1].decodingOffset == offset) ) {
		ctts->entries[ctts->nb_entries-1].sampleCount++;
		return GF_OK;
	}
	if (ctts->nb_entries==ctts->alloc_size) {
		ALLOC_INC(ctts->alloc_size);
		ctts->entries = gf_realloc(ctts->entries, sizeof(GF_DttsEntry)*ctts->alloc_size);
		if (!ctts->entries) return GF_OUT_OF_MEM;
		memset(&ctts->entries[ctts->nb_entries], 0, sizeof(GF_DttsEntry)*(ctts->alloc_size-ctts->nb_entries) );
	}
	ctts->entries[ctts->nb_entries].decodingOffset = offset;
	ctts->entries[ctts->nb_entries].sampleCount = 1;
	ctts->nb_entries++;
	if (offset<0) ctts->version=1;

	if (ABS(offset) > ctts->max_ts_delta) ctts->max_ts_delta = ABS(offset);

	return GF_OK;
}

GF_Err stbl_AppendDegradation(GF_SampleTableBox *stbl, u16 DegradationPriority)
{
	if (!stbl->DegradationPriority) {
		stbl->DegradationPriority = (GF_DegradationPriorityBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_STDP);
		if (!stbl->DegradationPriority) return GF_OUT_OF_MEM;
	}

	stbl->DegradationPriority->priorities = (u16 *)gf_realloc(stbl->DegradationPriority->priorities, sizeof(u16) * stbl->SampleSize->sampleCount);
	if (!stbl->DegradationPriority->priorities) return GF_OUT_OF_MEM;
	stbl->DegradationPriority->priorities[stbl->SampleSize->sampleCount-1] = DegradationPriority;
	stbl->DegradationPriority->nb_entries = stbl->SampleSize->sampleCount;
	return GF_OK;
}


GF_Err stbl_AppendDepType(GF_SampleTableBox *stbl, u32 DepType)
{
	if (!stbl->SampleDep) {
		stbl->SampleDep = (GF_SampleDependencyTypeBox *) gf_isom_box_new_parent(&stbl->child_boxes, GF_ISOM_BOX_TYPE_SDTP);
		if (!stbl->SampleDep) return GF_OUT_OF_MEM;
	}
	stbl->SampleDep->sample_info = (u8*)gf_realloc(stbl->SampleDep->sample_info, sizeof(u8)*stbl->SampleSize->sampleCount );
	if (!stbl->SampleDep->sample_info) return GF_OUT_OF_MEM;
	stbl->SampleDep->sample_alloc = stbl->SampleSize->sampleCount;
	stbl->SampleDep->sample_info[stbl->SampleDep->sampleCount] = DepType;
	stbl->SampleDep->sampleCount = stbl->SampleSize->sampleCount;
	return GF_OK;
}







GF_Err stbl_UnpackOffsets(GF_SampleTableBox *stbl)
{
	GF_Err e;
	u32 i, chunkNumber, sampleDescIndex;
	u64 dataOffset;
	GF_StscEntry *ent;
	GF_ChunkOffsetBox *stco_tmp;
	GF_ChunkLargeOffsetBox *co64_tmp;
	GF_SampleToChunkBox *stsc_tmp;

	if (!stbl) return GF_ISOM_INVALID_FILE;

	
	if (!stbl->ChunkOffset && !stbl->SampleDescription && !stbl->SampleSize && !stbl->SampleToChunk && !stbl->TimeToSample)
		return GF_OK;
	
	if (!stbl->SampleToChunk && !stbl->TimeToSample) return GF_OK;

	
	if (!stbl->ChunkOffset || !stbl->SampleDescription || !stbl->SampleSize || !stbl->SampleToChunk || !stbl->TimeToSample)
		return GF_ISOM_INVALID_FILE;

	
	if (stbl->SampleSize->sampleCount == stbl->SampleToChunk->nb_entries) return GF_OK;

	
	if (stbl->ChunkOffset->type == GF_ISOM_BOX_TYPE_STCO) {
		co64_tmp = NULL;
		stco_tmp = (GF_ChunkOffsetBox *) gf_isom_box_new(GF_ISOM_BOX_TYPE_STCO);
		if (!stco_tmp) return GF_OUT_OF_MEM;
		stco_tmp->nb_entries = stbl->SampleSize->sampleCount;
		stco_tmp->offsets = (u32*)gf_malloc(stco_tmp->nb_entries * sizeof(u32));
		if (!stco_tmp->offsets) {
			gf_isom_box_del((GF_Box*)stco_tmp);
			return GF_OUT_OF_MEM;
		}
		stco_tmp->alloc_size = stco_tmp->nb_entries;
	} else if (stbl->ChunkOffset->type == GF_ISOM_BOX_TYPE_CO64) {
		stco_tmp = NULL;
		co64_tmp = (GF_ChunkLargeOffsetBox *) gf_isom_box_new(GF_ISOM_BOX_TYPE_CO64);
		if (!co64_tmp) return GF_OUT_OF_MEM;
		co64_tmp->nb_entries = stbl->SampleSize->sampleCount;
		co64_tmp->offsets = (u64*)gf_malloc(co64_tmp->nb_entries * sizeof(u64));
		if (!co64_tmp->offsets) {
			gf_isom_box_del((GF_Box*)co64_tmp);
			return GF_OUT_OF_MEM;
		}
		co64_tmp->alloc_size = co64_tmp->nb_entries;
	} else {
		return GF_ISOM_INVALID_FILE;
	}

	
	stsc_tmp = (GF_SampleToChunkBox *) gf_isom_box_new(GF_ISOM_BOX_TYPE_STSC);
	if (!stsc_tmp) return GF_OUT_OF_MEM;

	stsc_tmp->nb_entries = stsc_tmp->alloc_size = stbl->SampleSize->sampleCount;
	stsc_tmp->entries = gf_malloc(sizeof(GF_StscEntry)*stsc_tmp->nb_entries);
	if (!stsc_tmp->entries) return GF_OUT_OF_MEM;
	
	stsc_tmp->w_lastSampleNumber = stbl->SampleSize->sampleCount;
	stsc_tmp->w_lastChunkNumber = stbl->SampleSize->sampleCount;

	
	ent = NULL;
	for (i = 0; i < stbl->SampleSize->sampleCount; i++) {
		
		e = stbl_GetSampleInfos(stbl, i+1, &dataOffset, &chunkNumber, &sampleDescIndex, NULL);
		if (e) goto err_exit;
		ent = &stsc_tmp->entries[i];
		ent->isEdited = 0;
		ent->sampleDescriptionIndex = sampleDescIndex;
		
		ent->firstChunk = i+1;
		ent->nextChunk = i+2;
		ent->samplesPerChunk = 1;
		if (stco_tmp) {
			stco_tmp->offsets[i] = (u32) dataOffset;
		} else {
			co64_tmp->offsets[i] = dataOffset;
		}
	}
	
	if (ent) ent->nextChunk = 0;


	
	gf_list_del_item(stbl->child_boxes, stbl->ChunkOffset);
	gf_list_del_item(stbl->child_boxes, stbl->SampleToChunk);
	gf_isom_box_del(stbl->ChunkOffset);
	gf_isom_box_del((GF_Box *)stbl->SampleToChunk);
	
	if (stco_tmp) {
		stbl->ChunkOffset = (GF_Box *)stco_tmp;
	} else {
		stbl->ChunkOffset = (GF_Box *)co64_tmp;
	}
	stbl->SampleToChunk = stsc_tmp;
	gf_list_add(stbl->child_boxes, stbl->ChunkOffset);
	gf_list_add(stbl->child_boxes, stbl->SampleToChunk);

	stbl->SampleToChunk->currentIndex = 0;
	stbl->SampleToChunk->currentChunk = 0;
	stbl->SampleToChunk->firstSampleInCurrentChunk = 0;
	return GF_OK;

err_exit:
	if (stco_tmp) gf_isom_box_del((GF_Box *) stco_tmp);
	if (co64_tmp) gf_isom_box_del((GF_Box *) co64_tmp);
	if (stsc_tmp) gf_isom_box_del((GF_Box *) stsc_tmp);
	return e;
}



static GFINLINE GF_Err stbl_AddOffset(GF_SampleTableBox *stbl, GF_Box **old_stco, u64 offset)
{
	GF_ChunkOffsetBox *stco;
	GF_ChunkLargeOffsetBox *co64;
	u32 i;

	if ((*old_stco)->type == GF_ISOM_BOX_TYPE_STCO) {
		stco = (GF_ChunkOffsetBox *) *old_stco;
		
		if (offset > 0xFFFFFFFF) {
			s32 prev_pos = gf_list_find(stbl->child_boxes, *old_stco);
			co64 = (GF_ChunkLargeOffsetBox *) gf_isom_box_new(GF_ISOM_BOX_TYPE_CO64);
			if (!co64) return GF_OUT_OF_MEM;
			co64->nb_entries = stco->nb_entries + 1;
			co64->alloc_size = co64->nb_entries;
			co64->offsets = (u64*)gf_malloc(co64->nb_entries * sizeof(u64));
			if (!co64->offsets) {
				gf_isom_box_del((GF_Box *)co64);
				return GF_OUT_OF_MEM;
			}
			for (i = 0; i< co64->nb_entries - 1; i++) {
				co64->offsets[i] = (u64) stco->offsets[i];
			}
			co64->offsets[i] = offset;
			
			gf_isom_box_del_parent(&stbl->child_boxes, *old_stco);
			*old_stco = (GF_Box *)co64;

			assert (stbl->child_boxes);
			
			if (prev_pos>=0)
				gf_list_insert(stbl->child_boxes, *old_stco, prev_pos);
			return GF_OK;
		}
		
		if (stco->nb_entries==stco->alloc_size) {
			ALLOC_INC(stco->alloc_size);
			stco->offsets = (u32*)gf_realloc(stco->offsets, stco->alloc_size * sizeof(u32));
			if (!stco->offsets) return GF_OUT_OF_MEM;
			memset(&stco->offsets[stco->nb_entries], 0, (stco->alloc_size - stco->nb_entries) * sizeof(u32));
		}

		stco->offsets[stco->nb_entries] = (u32) offset;
		stco->nb_entries += 1;
	} else {
		
		co64 = (GF_ChunkLargeOffsetBox *) *old_stco;
		if (co64->nb_entries==co64->alloc_size) {
			ALLOC_INC(co64->alloc_size);
			co64->offsets = (u64*)gf_realloc(co64->offsets, co64->alloc_size * sizeof(u64));
			if (!co64->offsets) return GF_OUT_OF_MEM;
			memset(&co64->offsets[co64->nb_entries], 0, (co64->alloc_size - co64->nb_entries) * sizeof(u64) );
		}
		co64->offsets[co64->nb_entries] = offset;
		co64->nb_entries += 1;
	}
	return GF_OK;
}





GF_Err stbl_SetChunkAndOffset(GF_SampleTableBox *stbl, u32 sampleNumber, u32 StreamDescIndex, GF_SampleToChunkBox *the_stsc, GF_Box **the_stco, u64 data_offset, Bool forceNewChunk, u32 nb_samp)
{
	GF_Err e;
	u8 newChunk;
	GF_StscEntry *newEnt, *cur_ent;

	if (!stbl) return GF_ISOM_INVALID_FILE;

	newChunk = 0;
	
	

	
	
	
	if (forceNewChunk) newChunk = 1;

	cur_ent = NULL;
	
	if (! the_stsc->entries) {
		newChunk = 1;
	} else {
		cur_ent = &the_stsc->entries[the_stsc->nb_entries - 1];
		
		if (StreamDescIndex != cur_ent->sampleDescriptionIndex)
			newChunk = 1;
		if (stbl->MaxSamplePerChunk && cur_ent->samplesPerChunk >= stbl->MaxSamplePerChunk)
			newChunk = 1;
	}

	
	if (!newChunk) {
		cur_ent->samplesPerChunk += nb_samp;
		return GF_OK;
	}

	
	
	if (the_stsc->nb_entries > 1) {
		GF_StscEntry *ent = &the_stsc->entries[the_stsc->nb_entries - 2];
		if (!ent) return GF_OUT_OF_MEM;
		if ( (ent->sampleDescriptionIndex == cur_ent->sampleDescriptionIndex)
		        && (ent->samplesPerChunk == cur_ent->samplesPerChunk)
		   ) {
			
			ent->nextChunk = cur_ent->firstChunk;
			the_stsc->nb_entries--;
		}
	}

	
	e = stbl_AddOffset(stbl, the_stco, data_offset);
	if (e) return e;

	if (the_stsc->nb_entries==the_stsc->alloc_size) {
		ALLOC_INC(the_stsc->alloc_size);
		the_stsc->entries = gf_realloc(the_stsc->entries, sizeof(GF_StscEntry)*the_stsc->alloc_size);
		if (!the_stsc->entries) return GF_OUT_OF_MEM;
		memset(&the_stsc->entries[the_stsc->nb_entries], 0, sizeof(GF_StscEntry)*(the_stsc->alloc_size-the_stsc->nb_entries));
	}
	
	newEnt = &the_stsc->entries[the_stsc->nb_entries];
	if (!newEnt) return GF_OUT_OF_MEM;

	
	if ((*the_stco)->type == GF_ISOM_BOX_TYPE_STCO) {
		newEnt->firstChunk = ((GF_ChunkOffsetBox *) (*the_stco) )->nb_entries;
	} else {
		newEnt->firstChunk = ((GF_ChunkLargeOffsetBox *) (*the_stco) )->nb_entries;
	}
	newEnt->sampleDescriptionIndex = StreamDescIndex;
	newEnt->samplesPerChunk = nb_samp;
	newEnt->nextChunk = 0;
	
	if (the_stsc->nb_entries)
		the_stsc->entries[the_stsc->nb_entries-1].nextChunk = newEnt->firstChunk;
	the_stsc->nb_entries++;
	return GF_OK;
}

GF_EXPORT GF_Err gf_isom_refresh_size_info(GF_ISOFile *file, u32 trackNumber)
{
	u32 i, size;
	GF_TrackBox *trak;
	GF_SampleSizeBox *stsz;
	trak = gf_isom_get_track_from_file(file, trackNumber);
	if (!trak) return GF_BAD_PARAM;

	stsz = trak->Media->information->sampleTable->SampleSize;
	if (stsz->sampleSize || !stsz->sampleCount) return GF_OK;

	size = stsz->sizes[0];
	for (i=1; i<stsz->sampleCount; i++) {
		if (stsz->sizes[i] != size) {
			size = 0;
			break;
		}
	}
	if (size) {
		gf_free(stsz->sizes);
		stsz->sizes = NULL;
		stsz->sampleSize = size;
	}
	return GF_OK;
}



