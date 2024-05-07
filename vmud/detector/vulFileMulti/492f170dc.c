

















static BOOL nsc_context_initialize_encode(NSC_CONTEXT* context)
{
	int i;
	UINT32 length;
	UINT32 tempWidth;
	UINT32 tempHeight;
	tempWidth = ROUND_UP_TO(context->width, 8);
	tempHeight = ROUND_UP_TO(context->height, 2);
	
	length = tempWidth * tempHeight + 16;

	if (length > context->priv->PlaneBuffersLength)
	{
		for (i = 0; i < 5; i++)
		{
			BYTE* tmp = (BYTE*) realloc(context->priv->PlaneBuffers[i], length);
			if (!tmp)
				goto fail;

			context->priv->PlaneBuffers[i] = tmp;
		}

		context->priv->PlaneBuffersLength = length;
	}

	if (context->ChromaSubsamplingLevel)
	{
		context->OrgByteCount[0] = tempWidth * context->height;
		context->OrgByteCount[1] = tempWidth * tempHeight / 4;
		context->OrgByteCount[2] = tempWidth * tempHeight / 4;
		context->OrgByteCount[3] = context->width * context->height;
	}
	else {
		context->OrgByteCount[0] = context->width * context->height;
		context->OrgByteCount[1] = context->width * context->height;
		context->OrgByteCount[2] = context->width * context->height;
		context->OrgByteCount[3] = context->width * context->height;
	}

	return TRUE;
fail:

	if (length > context->priv->PlaneBuffersLength)
	{
		for (i = 0; i < 5; i++)
			free(context->priv->PlaneBuffers[i]);
	}

	return FALSE;
}

static void nsc_encode_argb_to_aycocg(NSC_CONTEXT* context, const BYTE* data, UINT32 scanline)
{
	UINT16 x;
	UINT16 y;
	UINT16 rw;
	BYTE ccl;
	const BYTE* src;
	BYTE* yplane = NULL;
	BYTE* coplane = NULL;
	BYTE* cgplane = NULL;
	BYTE* aplane = NULL;
	INT16 r_val;
	INT16 g_val;
	INT16 b_val;
	BYTE a_val;
	UINT32 tempWidth;
	tempWidth = ROUND_UP_TO(context->width, 8);
	rw = (context->ChromaSubsamplingLevel ? tempWidth : context->width);
	ccl = context->ColorLossLevel;

	for (y = 0; y < context->height; y++)
	{
		src = data + (context->height - 1 - y) * scanline;
		yplane = context->priv->PlaneBuffers[0] + y * rw;
		coplane = context->priv->PlaneBuffers[1] + y * rw;
		cgplane = context->priv->PlaneBuffers[2] + y * rw;
		aplane = context->priv->PlaneBuffers[3] + y * context->width;

		for (x = 0; x < context->width; x++)
		{
			switch (context->format)
			{
				case PIXEL_FORMAT_BGRX32:
					b_val = *src++;
					g_val = *src++;
					r_val = *src++;
					src++;
					a_val = 0xFF;
					break;

				case PIXEL_FORMAT_BGRA32:
					b_val = *src++;
					g_val = *src++;
					r_val = *src++;
					a_val = *src++;
					break;

				case PIXEL_FORMAT_RGBX32:
					r_val = *src++;
					g_val = *src++;
					b_val = *src++;
					src++;
					a_val = 0xFF;
					break;

				case PIXEL_FORMAT_RGBA32:
					r_val = *src++;
					g_val = *src++;
					b_val = *src++;
					a_val = *src++;
					break;

				case PIXEL_FORMAT_BGR24:
					b_val = *src++;
					g_val = *src++;
					r_val = *src++;
					a_val = 0xFF;
					break;

				case PIXEL_FORMAT_RGB24:
					r_val = *src++;
					g_val = *src++;
					b_val = *src++;
					a_val = 0xFF;
					break;

				case PIXEL_FORMAT_BGR16:
					b_val = (INT16)(((*(src + 1)) & 0xF8) | ((*(src + 1)) >> 5));
					g_val = (INT16)((((*(src + 1)) & 0x07) << 5) | (((*src) & 0xE0) >> 3));
					r_val = (INT16)((((*src) & 0x1F) << 3) | (((*src) >> 2) & 0x07));
					a_val = 0xFF;
					src += 2;
					break;

				case PIXEL_FORMAT_RGB16:
					r_val = (INT16)(((*(src + 1)) & 0xF8) | ((*(src + 1)) >> 5));
					g_val = (INT16)((((*(src + 1)) & 0x07) << 5) | (((*src) & 0xE0) >> 3));
					b_val = (INT16)((((*src) & 0x1F) << 3) | (((*src) >> 2) & 0x07));
					a_val = 0xFF;
					src += 2;
					break;

				case PIXEL_FORMAT_A4:
					{
						int shift;
						BYTE idx;
						shift = (7 - (x % 8));
						idx = ((*src) >> shift) & 1;
						idx |= (((*(src + 1)) >> shift) & 1) << 1;
						idx |= (((*(src + 2)) >> shift) & 1) << 2;
						idx |= (((*(src + 3)) >> shift) & 1) << 3;
						idx *= 3;
						r_val = (INT16) context->palette[idx];
						g_val = (INT16) context->palette[idx + 1];
						b_val = (INT16) context->palette[idx + 2];

						if (shift == 0)
							src += 4;
					}

					a_val = 0xFF;
					break;

				case PIXEL_FORMAT_RGB8:
					{
						int idx = (*src) * 3;
						r_val = (INT16) context->palette[idx];
						g_val = (INT16) context->palette[idx + 1];
						b_val = (INT16) context->palette[idx + 2];
						src++;
					}

					a_val = 0xFF;
					break;

				default:
					r_val = g_val = b_val = a_val = 0;
					break;
			}

			*yplane++ = (BYTE)((r_val >> 2) + (g_val >> 1) + (b_val >> 2));
			
			*coplane++ = (BYTE)((r_val - b_val) >> ccl);
			*cgplane++ = (BYTE)((-(r_val >> 1) + g_val - (b_val >> 1)) >> ccl);
			*aplane++ = a_val;
		}

		if (context->ChromaSubsamplingLevel && (x % 2) == 1)
		{
			*yplane = *(yplane - 1);
			*coplane = *(coplane - 1);
			*cgplane = *(cgplane - 1);
		}
	}

	if (context->ChromaSubsamplingLevel && (y % 2) == 1)
	{
		yplane = context->priv->PlaneBuffers[0] + y * rw;
		coplane = context->priv->PlaneBuffers[1] + y * rw;
		cgplane = context->priv->PlaneBuffers[2] + y * rw;
		CopyMemory(yplane, yplane - rw, rw);
		CopyMemory(coplane, coplane - rw, rw);
		CopyMemory(cgplane, cgplane - rw, rw);
	}
}

static void nsc_encode_subsampling(NSC_CONTEXT* context)
{
	UINT16 x;
	UINT16 y;
	BYTE* co_dst;
	BYTE* cg_dst;
	INT8* co_src0;
	INT8* co_src1;
	INT8* cg_src0;
	INT8* cg_src1;
	UINT32 tempWidth;
	UINT32 tempHeight;
	tempWidth = ROUND_UP_TO(context->width, 8);
	tempHeight = ROUND_UP_TO(context->height, 2);

	for (y = 0; y < tempHeight >> 1; y++)
	{
		co_dst = context->priv->PlaneBuffers[1] + y * (tempWidth >> 1);
		cg_dst = context->priv->PlaneBuffers[2] + y * (tempWidth >> 1);
		co_src0 = (INT8*) context->priv->PlaneBuffers[1] + (y << 1) * tempWidth;
		co_src1 = co_src0 + tempWidth;
		cg_src0 = (INT8*) context->priv->PlaneBuffers[2] + (y << 1) * tempWidth;
		cg_src1 = cg_src0 + tempWidth;

		for (x = 0; x < tempWidth >> 1; x++)
		{
			*co_dst++ = (BYTE)(((INT16) * co_src0 + (INT16) * (co_src0 + 1) + (INT16) * co_src1 + (INT16) * (co_src1 + 1)) >> 2);
			*cg_dst++ = (BYTE)(((INT16) * cg_src0 + (INT16) * (cg_src0 + 1) + (INT16) * cg_src1 + (INT16) * (cg_src1 + 1)) >> 2);
			co_src0 += 2;
			co_src1 += 2;
			cg_src0 += 2;
			cg_src1 += 2;
		}
	}
}

void nsc_encode(NSC_CONTEXT* context, const BYTE* bmpdata, UINT32 rowstride)
{
	nsc_encode_argb_to_aycocg(context, bmpdata, rowstride);

	if (context->ChromaSubsamplingLevel)
	{
		nsc_encode_subsampling(context);
	}
}

static UINT32 nsc_rle_encode(BYTE* in, BYTE* out, UINT32 originalSize)
{
	UINT32 left;
	UINT32 runlength = 1;
	UINT32 planeSize = 0;
	left = originalSize;

	
	while (left > 4 && planeSize < originalSize - 4)
	{
		if (left > 5 && *in == *(in + 1))
		{
			runlength++;
		}
		else if (runlength == 1)
		{
			*out++ = *in;
			planeSize++;
		}
		else if (runlength < 256)
		{
			*out++ = *in;
			*out++ = *in;
			*out++ = runlength - 2;
			runlength = 1;
			planeSize += 3;
		}
		else {
			*out++ = *in;
			*out++ = *in;
			*out++ = 0xFF;
			*out++ = (runlength & 0x000000FF);
			*out++ = (runlength & 0x0000FF00) >> 8;
			*out++ = (runlength & 0x00FF0000) >> 16;
			*out++ = (runlength & 0xFF000000) >> 24;
			runlength = 1;
			planeSize += 7;
		}

		in++;
		left--;
	}

	if (planeSize < originalSize - 4)
		CopyMemory(out, in, 4);

	planeSize += 4;
	return planeSize;
}

static void nsc_rle_compress_data(NSC_CONTEXT* context)
{
	UINT16 i;
	UINT32 planeSize;
	UINT32 originalSize;

	for (i = 0; i < 4; i++)
	{
		originalSize = context->OrgByteCount[i];

		if (originalSize == 0)
		{
			planeSize = 0;
		}
		else {
			planeSize = nsc_rle_encode(context->priv->PlaneBuffers[i], context->priv->PlaneBuffers[4], originalSize);

			if (planeSize < originalSize)
				CopyMemory(context->priv->PlaneBuffers[i], context->priv->PlaneBuffers[4], planeSize);
			else planeSize = originalSize;
		}

		context->PlaneByteCount[i] = planeSize;
	}
}

UINT32 nsc_compute_byte_count(NSC_CONTEXT* context, UINT32* ByteCount, UINT32 width, UINT32 height)
{
	UINT32 tempWidth;
	UINT32 tempHeight;
	UINT32 maxPlaneSize;
	tempWidth = ROUND_UP_TO(width, 8);
	tempHeight = ROUND_UP_TO(height, 2);
	maxPlaneSize = tempWidth * tempHeight + 16;

	if (context->ChromaSubsamplingLevel)
	{
		ByteCount[0] = tempWidth * height;
		ByteCount[1] = tempWidth * tempHeight / 4;
		ByteCount[2] = tempWidth * tempHeight / 4;
		ByteCount[3] = width * height;
	}
	else {
		ByteCount[0] = width * height;
		ByteCount[1] = width * height;
		ByteCount[2] = width * height;
		ByteCount[3] = width * height;
	}

	return maxPlaneSize;
}

NSC_MESSAGE* nsc_encode_messages(NSC_CONTEXT* context, const BYTE* data, UINT32 x, UINT32 y, UINT32 width, UINT32 height, UINT32 scanline, UINT32* numMessages, UINT32 maxDataSize)


{
	UINT32 i, j, k;
	UINT32 dataOffset;
	UINT32 rows, cols;
	UINT32 BytesPerPixel;
	UINT32 MaxRegionWidth;
	UINT32 MaxRegionHeight;
	UINT32 ByteCount[4];
	UINT32 MaxPlaneSize;
	UINT32 MaxMessageSize;
	NSC_MESSAGE* messages;
	UINT32 PaddedMaxPlaneSize;
	k = 0;
	MaxRegionWidth = 64 * 4;
	MaxRegionHeight = 64 * 2;
	BytesPerPixel = GetBytesPerPixel(context->format);
	rows = (width + (MaxRegionWidth - (width % MaxRegionWidth))) / MaxRegionWidth;
	cols = (height + (MaxRegionHeight - (height % MaxRegionHeight))) / MaxRegionHeight;
	*numMessages = rows * cols;
	MaxPlaneSize = nsc_compute_byte_count(context, (UINT32*) ByteCount, width, height);
	MaxMessageSize = ByteCount[0] + ByteCount[1] + ByteCount[2] + ByteCount[3] + 20;
	maxDataSize -= 1024; 
	messages = (NSC_MESSAGE*) calloc(*numMessages, sizeof(NSC_MESSAGE));

	if (!messages)
		return NULL;

	for (i = 0; i < rows; i++)
	{
		for (j = 0; j < cols; j++)
		{
			messages[k].x = x + (i * MaxRegionWidth);
			messages[k].y = y + (j * MaxRegionHeight);
			messages[k].width = (i < (rows - 1)) ? MaxRegionWidth : width - (i * MaxRegionWidth);
			messages[k].height = (j < (cols - 1)) ? MaxRegionHeight : height - (j * MaxRegionHeight);
			messages[k].data = data;
			messages[k].scanline = scanline;
			messages[k].MaxPlaneSize = nsc_compute_byte_count(context, (UINT32*) messages[k].OrgByteCount, messages[k].width, messages[k].height);
			k++;
		}
	}

	*numMessages = k;

	for (i = 0; i < *numMessages; i++)
	{
		PaddedMaxPlaneSize = messages[i].MaxPlaneSize + 32;
		messages[i].PlaneBuffer = (BYTE*) BufferPool_Take(context->priv->PlanePool, PaddedMaxPlaneSize * 5);

		if (!messages[i].PlaneBuffer)
			goto fail;

		messages[i].PlaneBuffers[0] = (BYTE*) & (messages[i].PlaneBuffer[(PaddedMaxPlaneSize * 0) + 16]);
		messages[i].PlaneBuffers[1] = (BYTE*) & (messages[i].PlaneBuffer[(PaddedMaxPlaneSize * 1) + 16]);
		messages[i].PlaneBuffers[2] = (BYTE*) & (messages[i].PlaneBuffer[(PaddedMaxPlaneSize * 2) + 16]);
		messages[i].PlaneBuffers[3] = (BYTE*) & (messages[i].PlaneBuffer[(PaddedMaxPlaneSize * 3) + 16]);
		messages[i].PlaneBuffers[4] = (BYTE*) & (messages[i].PlaneBuffer[(PaddedMaxPlaneSize * 4) + 16]);
	}

	for (i = 0; i < *numMessages; i++)
	{
		context->width = messages[i].width;
		context->height = messages[i].height;
		context->OrgByteCount[0] = messages[i].OrgByteCount[0];
		context->OrgByteCount[1] = messages[i].OrgByteCount[1];
		context->OrgByteCount[2] = messages[i].OrgByteCount[2];
		context->OrgByteCount[3] = messages[i].OrgByteCount[3];
		context->priv->PlaneBuffersLength = messages[i].MaxPlaneSize;
		context->priv->PlaneBuffers[0] = messages[i].PlaneBuffers[0];
		context->priv->PlaneBuffers[1] = messages[i].PlaneBuffers[1];
		context->priv->PlaneBuffers[2] = messages[i].PlaneBuffers[2];
		context->priv->PlaneBuffers[3] = messages[i].PlaneBuffers[3];
		context->priv->PlaneBuffers[4] = messages[i].PlaneBuffers[4];
		dataOffset = (messages[i].y * messages[i].scanline) + (messages[i].x * BytesPerPixel);
		PROFILER_ENTER(context->priv->prof_nsc_encode)
		context->encode(context, &data[dataOffset], scanline);
		PROFILER_EXIT(context->priv->prof_nsc_encode)
		PROFILER_ENTER(context->priv->prof_nsc_rle_compress_data)
		nsc_rle_compress_data(context);
		PROFILER_EXIT(context->priv->prof_nsc_rle_compress_data)
		messages[i].LumaPlaneByteCount = context->PlaneByteCount[0];
		messages[i].OrangeChromaPlaneByteCount = context->PlaneByteCount[1];
		messages[i].GreenChromaPlaneByteCount = context->PlaneByteCount[2];
		messages[i].AlphaPlaneByteCount = context->PlaneByteCount[3];
		messages[i].ColorLossLevel = context->ColorLossLevel;
		messages[i].ChromaSubsamplingLevel = context->ChromaSubsamplingLevel;
	}

	context->priv->PlaneBuffers[0] = NULL;
	context->priv->PlaneBuffers[1] = NULL;
	context->priv->PlaneBuffers[2] = NULL;
	context->priv->PlaneBuffers[3] = NULL;
	context->priv->PlaneBuffers[4] = NULL;
	return messages;
fail:

	for (i = 0; i < *numMessages; i++)
		BufferPool_Return(context->priv->PlanePool, messages[i].PlaneBuffer);

	free(messages);
	return NULL;
}

BOOL nsc_write_message(NSC_CONTEXT* context, wStream* s, NSC_MESSAGE* message)
{
	UINT32 totalPlaneByteCount;
	totalPlaneByteCount = message->LumaPlaneByteCount + message->OrangeChromaPlaneByteCount + message->GreenChromaPlaneByteCount + message->AlphaPlaneByteCount;


	if (!Stream_EnsureRemainingCapacity(s, 20 + totalPlaneByteCount))
		return -1;

	Stream_Write_UINT32(s, message->LumaPlaneByteCount);
	Stream_Write_UINT32(s, message->OrangeChromaPlaneByteCount);
	Stream_Write_UINT32(s, message->GreenChromaPlaneByteCount);
	Stream_Write_UINT32(s, message->AlphaPlaneByteCount);
	Stream_Write_UINT8(s, message->ColorLossLevel); 
	Stream_Write_UINT8(s, message->ChromaSubsamplingLevel);
	Stream_Write_UINT16(s, 0); 

	if (message->LumaPlaneByteCount)
		Stream_Write(s, message->PlaneBuffers[0], message->LumaPlaneByteCount);

	if (message->OrangeChromaPlaneByteCount)
		Stream_Write(s, message->PlaneBuffers[1], message->OrangeChromaPlaneByteCount);

	if (message->GreenChromaPlaneByteCount)
		Stream_Write(s, message->PlaneBuffers[2], message->GreenChromaPlaneByteCount);

	if (message->AlphaPlaneByteCount)
		Stream_Write(s, message->PlaneBuffers[3], message->AlphaPlaneByteCount);

	return TRUE;
}

void nsc_message_free(NSC_CONTEXT* context, NSC_MESSAGE* message)
{
	BufferPool_Return(context->priv->PlanePool, message->PlaneBuffer);
}

BOOL nsc_compose_message(NSC_CONTEXT* context, wStream* s, const BYTE* data, UINT32 width, UINT32 height, UINT32 scanline)
{
	NSC_MESSAGE s_message = { 0 };
	NSC_MESSAGE* message = &s_message;
	context->width = width;
	context->height = height;

	if (!nsc_context_initialize_encode(context))
		return FALSE;

	
	PROFILER_ENTER(context->priv->prof_nsc_encode)
	context->encode(context, data, scanline);
	PROFILER_EXIT(context->priv->prof_nsc_encode)
	
	PROFILER_ENTER(context->priv->prof_nsc_rle_compress_data)
	nsc_rle_compress_data(context);
	PROFILER_EXIT(context->priv->prof_nsc_rle_compress_data)
	message->PlaneBuffers[0] = context->priv->PlaneBuffers[0];
	message->PlaneBuffers[1] = context->priv->PlaneBuffers[1];
	message->PlaneBuffers[2] = context->priv->PlaneBuffers[2];
	message->PlaneBuffers[3] = context->priv->PlaneBuffers[3];
	message->LumaPlaneByteCount = context->PlaneByteCount[0];
	message->OrangeChromaPlaneByteCount = context->PlaneByteCount[1];
	message->GreenChromaPlaneByteCount = context->PlaneByteCount[2];
	message->AlphaPlaneByteCount = context->PlaneByteCount[3];
	message->ColorLossLevel = context->ColorLossLevel;
	message->ChromaSubsamplingLevel = context->ChromaSubsamplingLevel;
	return nsc_write_message(context, s, message);
}
