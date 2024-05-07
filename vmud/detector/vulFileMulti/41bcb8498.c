
















struct _ZGFX_TOKEN {
	int prefixLength;
	int prefixCode;
	int valueBits;
	int tokenType;
	UINT32 valueBase;
};
typedef struct _ZGFX_TOKEN ZGFX_TOKEN;

static const ZGFX_TOKEN ZGFX_TOKEN_TABLE[] = {
	
	{  1,    0,   8,   0,           0 },     {  5,   17,   5,   1,           0 }, {  5,   18,   7,   1,          32 }, {  5,   19,   9,   1,         160 }, {  5,   20,  10,   1,         672 }, {  5,   21,  12,   1,        1696 }, {  5,   24,   0,   0,  0x00       }, {  5,   25,   0,   0,  0x01       }, {  6,   44,  14,   1,        5792 }, {  6,   45,  15,   1,       22176 }, {  6,   52,   0,   0,  0x02       }, {  6,   53,   0,   0,  0x03       }, {  6,   54,   0,   0,  0xFF       }, {  7,   92,  18,   1,       54944 }, {  7,   93,  20,   1,      317088 }, {  7,  110,   0,   0,  0x04       }, {  7,  111,   0,   0,  0x05       }, {  7,  112,   0,   0,  0x06       }, {  7,  113,   0,   0,  0x07       }, {  7,  114,   0,   0,  0x08       }, {  7,  115,   0,   0,  0x09       }, {  7,  116,   0,   0,  0x0A       }, {  7,  117,   0,   0,  0x0B       }, {  7,  118,   0,   0,  0x3A       }, {  7,  119,   0,   0,  0x3B       }, {  7,  120,   0,   0,  0x3C       }, {  7,  121,   0,   0,  0x3D       }, {  7,  122,   0,   0,  0x3E       }, {  7,  123,   0,   0,  0x3F       }, {  7,  124,   0,   0,  0x40       }, {  7,  125,   0,   0,  0x80       }, {  8,  188,  20,   1,     1365664 }, {  8,  189,  21,   1,     2414240 }, {  8,  252,   0,   0,  0x0C       }, {  8,  253,   0,   0,  0x38       }, {  8,  254,   0,   0,  0x39       }, {  8,  255,   0,   0,  0x66       }, {  9,  380,  22,   1,     4511392 }, {  9,  381,  23,   1,     8705696 }, {  9,  382,  24,   1,    17094304 }, { 0 }







































};












static void zgfx_history_buffer_ring_write(ZGFX_CONTEXT* zgfx, const BYTE* src, size_t count)
{
	UINT32 front;

	if (count <= 0)
		return;

	if (count > zgfx->HistoryBufferSize)
	{
		const size_t residue = count - zgfx->HistoryBufferSize;
		count = zgfx->HistoryBufferSize;
		src += residue;
		zgfx->HistoryIndex = (zgfx->HistoryIndex + residue) % zgfx->HistoryBufferSize;
	}

	if (zgfx->HistoryIndex + count <= zgfx->HistoryBufferSize)
	{
		CopyMemory(&(zgfx->HistoryBuffer[zgfx->HistoryIndex]), src, count);

		if ((zgfx->HistoryIndex += count) == zgfx->HistoryBufferSize)
			zgfx->HistoryIndex = 0;
	}
	else {
		front = zgfx->HistoryBufferSize - zgfx->HistoryIndex;
		CopyMemory(&(zgfx->HistoryBuffer[zgfx->HistoryIndex]), src, front);
		CopyMemory(zgfx->HistoryBuffer, &src[front], count - front);
		zgfx->HistoryIndex = count - front;
	}
}

static void zgfx_history_buffer_ring_read(ZGFX_CONTEXT* zgfx, int offset, BYTE* dst, UINT32 count)
{
	UINT32 front;
	UINT32 index;
	UINT32 bytes;
	UINT32 valid;
	UINT32 bytesLeft;
	BYTE* dptr = dst;
	BYTE* origDst = dst;

	if (count <= 0)
		return;

	bytesLeft = count;
	index = (zgfx->HistoryIndex + zgfx->HistoryBufferSize - offset) % zgfx->HistoryBufferSize;
	bytes = MIN(bytesLeft, offset);

	if ((index + bytes) <= zgfx->HistoryBufferSize)
	{
		CopyMemory(dptr, &(zgfx->HistoryBuffer[index]), bytes);
	}
	else {
		front = zgfx->HistoryBufferSize - index;
		CopyMemory(dptr, &(zgfx->HistoryBuffer[index]), front);
		CopyMemory(&dptr[front], zgfx->HistoryBuffer, bytes - front);
	}

	if ((bytesLeft -= bytes) == 0)
		return;

	dptr += bytes;
	valid = bytes;

	do {
		bytes = valid;

		if (bytes > bytesLeft)
			bytes = bytesLeft;

		CopyMemory(dptr, origDst, bytes);
		dptr += bytes;
		valid <<= 1;
	}
	while ((bytesLeft -= bytes) > 0);
}

static BOOL zgfx_decompress_segment(ZGFX_CONTEXT* zgfx, wStream* stream, size_t segmentSize)
{
	BYTE c;
	BYTE flags;
	int extra;
	int opIndex;
	int haveBits;
	int inPrefix;
	UINT32 count;
	UINT32 distance;
	BYTE* pbSegment;
	size_t cbSegment = segmentSize - 1;

	if ((Stream_GetRemainingLength(stream) < segmentSize) || (segmentSize < 1))
		return FALSE;

	Stream_Read_UINT8(stream, flags); 
	zgfx->OutputCount = 0;
	pbSegment = Stream_Pointer(stream);
	Stream_Seek(stream, cbSegment);

	if (!(flags & PACKET_COMPRESSED))
	{
		zgfx_history_buffer_ring_write(zgfx, pbSegment, cbSegment);
		CopyMemory(zgfx->OutputBuffer, pbSegment, cbSegment);
		zgfx->OutputCount = cbSegment;
		return TRUE;
	}

	zgfx->pbInputCurrent = pbSegment;
	zgfx->pbInputEnd = &pbSegment[cbSegment - 1];
	
	zgfx->cBitsRemaining = 8 * (cbSegment - 1) - *zgfx->pbInputEnd;
	zgfx->cBitsCurrent = 0;
	zgfx->BitsCurrent = 0;

	while (zgfx->cBitsRemaining)
	{
		haveBits = 0;
		inPrefix = 0;

		for (opIndex = 0; ZGFX_TOKEN_TABLE[opIndex].prefixLength != 0; opIndex++)
		{
			while (haveBits < ZGFX_TOKEN_TABLE[opIndex].prefixLength)
			{
				zgfx_GetBits(zgfx, 1);
				inPrefix = (inPrefix << 1) + zgfx->bits;
				haveBits++;
			}

			if (inPrefix == ZGFX_TOKEN_TABLE[opIndex].prefixCode)
			{
				if (ZGFX_TOKEN_TABLE[opIndex].tokenType == 0)
				{
					
					zgfx_GetBits(zgfx, ZGFX_TOKEN_TABLE[opIndex].valueBits);
					c = (BYTE)(ZGFX_TOKEN_TABLE[opIndex].valueBase + zgfx->bits);
					zgfx->HistoryBuffer[zgfx->HistoryIndex] = c;

					if (++zgfx->HistoryIndex == zgfx->HistoryBufferSize)
						zgfx->HistoryIndex = 0;

					zgfx->OutputBuffer[zgfx->OutputCount++] = c;
				}
				else {
					zgfx_GetBits(zgfx, ZGFX_TOKEN_TABLE[opIndex].valueBits);
					distance = ZGFX_TOKEN_TABLE[opIndex].valueBase + zgfx->bits;

					if (distance != 0)
					{
						
						zgfx_GetBits(zgfx, 1);

						if (zgfx->bits == 0)
						{
							count = 3;
						}
						else {
							count = 4;
							extra = 2;
							zgfx_GetBits(zgfx, 1);

							while (zgfx->bits == 1)
							{
								count *= 2;
								extra++;
								zgfx_GetBits(zgfx, 1);
							}

							zgfx_GetBits(zgfx, extra);
							count += zgfx->bits;
						}

						zgfx_history_buffer_ring_read(zgfx, distance, &(zgfx->OutputBuffer[zgfx->OutputCount]), count);
						zgfx_history_buffer_ring_write(zgfx, &(zgfx->OutputBuffer[zgfx->OutputCount]), count);
						zgfx->OutputCount += count;
					}
					else {
						
						zgfx_GetBits(zgfx, 15);
						count = zgfx->bits;
						zgfx->cBitsRemaining -= zgfx->cBitsCurrent;
						zgfx->cBitsCurrent = 0;
						zgfx->BitsCurrent = 0;
						CopyMemory(&(zgfx->OutputBuffer[zgfx->OutputCount]), zgfx->pbInputCurrent, count);
						zgfx_history_buffer_ring_write(zgfx, zgfx->pbInputCurrent, count);
						zgfx->pbInputCurrent += count;
						zgfx->cBitsRemaining -= (8 * count);
						zgfx->OutputCount += count;
					}
				}

				break;
			}
		}
	}

	return TRUE;
}

int zgfx_decompress(ZGFX_CONTEXT* zgfx, const BYTE* pSrcData, UINT32 SrcSize, BYTE** ppDstData, UINT32* pDstSize, UINT32 flags)
{
	int status = -1;
	BYTE descriptor;

	wStream* stream = Stream_New((BYTE*)pSrcData, SrcSize);
	if (!stream)
		return -1;

	if (Stream_GetRemainingLength(stream) < 1)
		goto fail;

	Stream_Read_UINT8(stream, descriptor); 

	if (descriptor == ZGFX_SEGMENTED_SINGLE)
	{
		if (!zgfx_decompress_segment(zgfx, stream, Stream_GetRemainingLength(stream)))
			goto fail;

		*ppDstData = NULL;
		if (zgfx->OutputCount > 0)
			*ppDstData = (BYTE*) malloc(zgfx->OutputCount);

		if (!*ppDstData)
			goto fail;

		*pDstSize = zgfx->OutputCount;
		CopyMemory(*ppDstData, zgfx->OutputBuffer, zgfx->OutputCount);
	}
	else if (descriptor == ZGFX_SEGMENTED_MULTIPART)
	{
		UINT32 segmentSize;
		UINT16 segmentNumber;
		UINT16 segmentCount;
		UINT32 uncompressedSize;
		BYTE* pConcatenated;

		if (Stream_GetRemainingLength(stream) < 6)
			goto fail;

		Stream_Read_UINT16(stream, segmentCount); 
		Stream_Read_UINT32(stream, uncompressedSize); 

		if (Stream_GetRemainingLength(stream) < segmentCount * sizeof(UINT32))
			goto fail;

		pConcatenated = (BYTE*) malloc(uncompressedSize);

		if (!pConcatenated)
			goto fail;

		*ppDstData = pConcatenated;
		*pDstSize = uncompressedSize;

		for (segmentNumber = 0; segmentNumber < segmentCount; segmentNumber++)
		{
			if (Stream_GetRemainingLength(stream) < sizeof(UINT32))
				goto fail;

			Stream_Read_UINT32(stream, segmentSize); 

			if (!zgfx_decompress_segment(zgfx, stream, segmentSize))
				goto fail;

			CopyMemory(pConcatenated, zgfx->OutputBuffer, zgfx->OutputCount);
			pConcatenated += zgfx->OutputCount;
		}
	}
	else {
		goto fail;
	}

	status = 1;
fail:
	Stream_Free(stream, FALSE);
	return status;
}

static BOOL zgfx_compress_segment(ZGFX_CONTEXT* zgfx, wStream* s, const BYTE* pSrcData, UINT32 SrcSize, UINT32* pFlags)
{
	
	if (!Stream_EnsureRemainingCapacity(s, SrcSize + 1))
	{
		WLog_ERR(TAG, "Stream_EnsureRemainingCapacity failed!");
		return FALSE;
	}

	(*pFlags) |= ZGFX_PACKET_COMPR_TYPE_RDP8; 
	Stream_Write_UINT8(s, (*pFlags)); 
	Stream_Write(s, pSrcData, SrcSize);
	return TRUE;
}

int zgfx_compress_to_stream(ZGFX_CONTEXT* zgfx, wStream* sDst, const BYTE* pUncompressed, UINT32 uncompressedSize, UINT32* pFlags)
{
	int fragment;
	UINT16 maxLength;
	UINT32 totalLength;
	size_t posSegmentCount = 0;
	const BYTE* pSrcData;
	int status = 0;
	maxLength = ZGFX_SEGMENTED_MAXSIZE;
	totalLength = uncompressedSize;
	pSrcData = pUncompressed;

	for (fragment = 0; (totalLength > 0) || (fragment == 0); fragment++)
	{
		UINT32 SrcSize;
		size_t posDstSize;
		size_t posDataStart;
		UINT32 DstSize;
		SrcSize = (totalLength > maxLength) ? maxLength : totalLength;
		posDstSize = 0;
		totalLength -= SrcSize;

		
		if (!Stream_EnsureRemainingCapacity(sDst, 12))
		{
			WLog_ERR(TAG, "Stream_EnsureRemainingCapacity failed!");
			return -1;
		}

		if (fragment == 0)
		{
			
			
			Stream_Write_UINT8(sDst, (totalLength == 0) ? ZGFX_SEGMENTED_SINGLE : ZGFX_SEGMENTED_MULTIPART);

			if (totalLength > 0)
			{
				posSegmentCount = Stream_GetPosition(sDst); 
				Stream_Seek(sDst, 2);
				Stream_Write_UINT32(sDst, uncompressedSize); 
			}
		}

		if (fragment > 0 || totalLength > 0)
		{
			
			posDstSize = Stream_GetPosition(sDst); 
			Stream_Seek(sDst, 4);
		}

		posDataStart = Stream_GetPosition(sDst);

		if (!zgfx_compress_segment(zgfx, sDst, pSrcData, SrcSize, pFlags))
			return -1;

		if (posDstSize)
		{
			
			DstSize = Stream_GetPosition(sDst) - posDataStart;
			Stream_SetPosition(sDst, posDstSize);
			Stream_Write_UINT32(sDst, DstSize);
			Stream_SetPosition(sDst, posDataStart + DstSize);
		}

		pSrcData += SrcSize;
	}

	Stream_SealLength(sDst);

	
	if (posSegmentCount)
	{
		Stream_SetPosition(sDst, posSegmentCount);
		Stream_Write_UINT16(sDst, fragment);
		Stream_SetPosition(sDst, Stream_Length(sDst));
	}

	return status;
}

int zgfx_compress(ZGFX_CONTEXT* zgfx, const BYTE* pSrcData, UINT32 SrcSize, BYTE** ppDstData, UINT32* pDstSize, UINT32* pFlags)
{
	int status;
	wStream* s = Stream_New(NULL, SrcSize);
	status = zgfx_compress_to_stream(zgfx, s, pSrcData, SrcSize, pFlags);
	(*ppDstData) = Stream_Buffer(s);
	(*pDstSize) = Stream_GetPosition(s);
	Stream_Free(s, FALSE);
	return status;
}


void zgfx_context_reset(ZGFX_CONTEXT* zgfx, BOOL flush)
{
	zgfx->HistoryIndex = 0;
}

ZGFX_CONTEXT* zgfx_context_new(BOOL Compressor)
{
	ZGFX_CONTEXT* zgfx;
	zgfx = (ZGFX_CONTEXT*) calloc(1, sizeof(ZGFX_CONTEXT));

	if (zgfx)
	{
		zgfx->Compressor = Compressor;
		zgfx->HistoryBufferSize = sizeof(zgfx->HistoryBuffer);
		zgfx_context_reset(zgfx, FALSE);
	}

	return zgfx;
}

void zgfx_context_free(ZGFX_CONTEXT* zgfx)
{
	free(zgfx);
}

