





























































typedef UINT32 PIXEL;

static const BYTE g_MaskSpecialFgBg1 = 0x03;
static const BYTE g_MaskSpecialFgBg2 = 0x05;

static const BYTE g_MaskRegularRunLength = 0x1F;
static const BYTE g_MaskLiteRunLength = 0x0F;


static INLINE UINT32 ExtractCodeId(BYTE bOrderHdr)
{
	if ((bOrderHdr & 0xC0U) != 0xC0U)
	{
		
		return bOrderHdr >> 5;
	}
	else if ((bOrderHdr & 0xF0U) == 0xF0U)
	{
		
		return bOrderHdr;
	}
	else {
		
		return bOrderHdr >> 4;
	}
}


static INLINE UINT32 ExtractRunLength(UINT32 code, const BYTE* pbOrderHdr, UINT32* advance)
{
	UINT32 runLength;
	UINT32 ladvance;
	ladvance = 1;
	runLength = 0;

	switch (code)
	{
		case REGULAR_FGBG_IMAGE:
			runLength = (*pbOrderHdr) & g_MaskRegularRunLength;

			if (runLength == 0)
			{
				runLength = (*(pbOrderHdr + 1)) + 1;
				ladvance += 1;
			}
			else {
				runLength = runLength * 8;
			}

			break;

		case LITE_SET_FG_FGBG_IMAGE:
			runLength = (*pbOrderHdr) & g_MaskLiteRunLength;

			if (runLength == 0)
			{
				runLength = (*(pbOrderHdr + 1)) + 1;
				ladvance += 1;
			}
			else {
				runLength = runLength * 8;
			}

			break;

		case REGULAR_BG_RUN:
		case REGULAR_FG_RUN:
		case REGULAR_COLOR_RUN:
		case REGULAR_COLOR_IMAGE:
			runLength = (*pbOrderHdr) & g_MaskRegularRunLength;

			if (runLength == 0)
			{
				
				runLength = (*(pbOrderHdr + 1)) + 32;
				ladvance += 1;
			}

			break;

		case LITE_SET_FG_FG_RUN:
		case LITE_DITHERED_RUN:
			runLength = (*pbOrderHdr) & g_MaskLiteRunLength;

			if (runLength == 0)
			{
				
				runLength = (*(pbOrderHdr + 1)) + 16;
				ladvance += 1;
			}

			break;

		case MEGA_MEGA_BG_RUN:
		case MEGA_MEGA_FG_RUN:
		case MEGA_MEGA_SET_FG_RUN:
		case MEGA_MEGA_DITHERED_RUN:
		case MEGA_MEGA_COLOR_RUN:
		case MEGA_MEGA_FGBG_IMAGE:
		case MEGA_MEGA_SET_FGBG_IMAGE:
		case MEGA_MEGA_COLOR_IMAGE:
			runLength = ((UINT16)pbOrderHdr[1]) | ((UINT16)(pbOrderHdr[2] << 8));
			ladvance += 2;
			break;
	}

	*advance = ladvance;
	return runLength;
}

static INLINE BOOL ensure_capacity(const BYTE* start, const BYTE* end, size_t size, size_t base)
{
	const size_t available = (uintptr_t)end - (uintptr_t)start;
	const BOOL rc = available >= size * base;
	return rc;
}

static INLINE void write_pixel_8(BYTE* _buf, BYTE _pix)
{
	*_buf = _pix;
}

static INLINE void write_pixel_24(BYTE* _buf, UINT32 _pix)
{
	(_buf)[0] = (BYTE)(_pix);
	(_buf)[1] = (BYTE)((_pix) >> 8);
	(_buf)[2] = (BYTE)((_pix) >> 16);
}

static INLINE void write_pixel_16(BYTE* _buf, UINT16 _pix)
{
	*(UINT16*)_buf = _pix;
}













































































BOOL interleaved_decompress(BITMAP_INTERLEAVED_CONTEXT* interleaved, const BYTE* pSrcData, UINT32 SrcSize, UINT32 nSrcWidth, UINT32 nSrcHeight, UINT32 bpp, BYTE* pDstData, UINT32 DstFormat, UINT32 nDstStep, UINT32 nXDst, UINT32 nYDst, UINT32 nDstWidth, UINT32 nDstHeight, const gdiPalette* palette)



{
	UINT32 scanline;
	UINT32 SrcFormat;
	UINT32 BufferSize;

	if (!interleaved || !pSrcData || !pDstData)
		return FALSE;

	switch (bpp)
	{
		case 24:
			scanline = nSrcWidth * 3;
			SrcFormat = PIXEL_FORMAT_BGR24;
			break;

		case 16:
			scanline = nSrcWidth * 2;
			SrcFormat = PIXEL_FORMAT_RGB16;
			break;

		case 15:
			scanline = nSrcWidth * 2;
			SrcFormat = PIXEL_FORMAT_RGB15;
			break;

		case 8:
			scanline = nSrcWidth;
			SrcFormat = PIXEL_FORMAT_RGB8;
			break;

		default:
			WLog_ERR(TAG, "Invalid color depth %" PRIu32 "", bpp);
			return FALSE;
	}

	BufferSize = scanline * nSrcHeight;

	if (BufferSize > interleaved->TempSize)
	{
		interleaved->TempBuffer = _aligned_realloc(interleaved->TempBuffer, BufferSize, 16);
		interleaved->TempSize = BufferSize;
	}

	if (!interleaved->TempBuffer)
		return FALSE;

	switch (bpp)
	{
		case 24:
			if (!RleDecompress24to24(pSrcData, SrcSize, interleaved->TempBuffer, scanline, nSrcWidth, nSrcHeight))
				return FALSE;

			break;

		case 16:
		case 15:
			if (!RleDecompress16to16(pSrcData, SrcSize, interleaved->TempBuffer, scanline, nSrcWidth, nSrcHeight))
				return FALSE;

			break;

		case 8:
			if (!RleDecompress8to8(pSrcData, SrcSize, interleaved->TempBuffer, scanline, nSrcWidth, nSrcHeight))
				return FALSE;

			break;

		default:
			return FALSE;
	}

	return freerdp_image_copy(pDstData, DstFormat, nDstStep, nXDst, nYDst, nDstWidth, nDstHeight, interleaved->TempBuffer, SrcFormat, scanline, 0, 0, palette, FREERDP_FLIP_VERTICAL);

}

BOOL interleaved_compress(BITMAP_INTERLEAVED_CONTEXT* interleaved, BYTE* pDstData, UINT32* pDstSize, UINT32 nWidth, UINT32 nHeight, const BYTE* pSrcData, UINT32 SrcFormat, UINT32 nSrcStep, UINT32 nXSrc, UINT32 nYSrc, const gdiPalette* palette, UINT32 bpp)


{
	BOOL status;
	wStream* s;
	UINT32 DstFormat = 0;
	const size_t maxSize = 64 * 64 * 4;

	if (!interleaved || !pDstData || !pSrcData)
		return FALSE;

	if ((nWidth == 0) || (nHeight == 0))
		return FALSE;

	if (nWidth % 4)
	{
		WLog_ERR(TAG, "interleaved_compress: width is not a multiple of 4");
		return FALSE;
	}

	if ((nWidth > 64) || (nHeight > 64))
	{
		WLog_ERR(TAG, "interleaved_compress: width (%" PRIu32 ") or height (%" PRIu32 ") is greater than 64", nWidth, nHeight);


		return FALSE;
	}

	switch (bpp)
	{
		case 24:
			DstFormat = PIXEL_FORMAT_BGRX32;
			break;

		case 16:
			DstFormat = PIXEL_FORMAT_RGB16;
			break;

		case 15:
			DstFormat = PIXEL_FORMAT_RGB15;
			break;

		default:
			return FALSE;
	}

	if (!freerdp_image_copy(interleaved->TempBuffer, DstFormat, 0, 0, 0, nWidth, nHeight, pSrcData, SrcFormat, nSrcStep, nXSrc, nYSrc, palette, FREERDP_FLIP_NONE))
		return FALSE;

	s = Stream_New(pDstData, *pDstSize);

	if (!s)
		return FALSE;

	Stream_SetPosition(interleaved->bts, 0);

	if (freerdp_bitmap_compress(interleaved->TempBuffer, nWidth, nHeight, s, bpp, maxSize, nHeight - 1, interleaved->bts, 0) < 0)
		status = FALSE;
	else status = TRUE;

	Stream_SealLength(s);
	*pDstSize = (UINT32)Stream_Length(s);
	Stream_Free(s, FALSE);
	return status;
}

BOOL bitmap_interleaved_context_reset(BITMAP_INTERLEAVED_CONTEXT* interleaved)
{
	if (!interleaved)
		return FALSE;

	return TRUE;
}

BITMAP_INTERLEAVED_CONTEXT* bitmap_interleaved_context_new(BOOL Compressor)
{
	BITMAP_INTERLEAVED_CONTEXT* interleaved;
	interleaved = (BITMAP_INTERLEAVED_CONTEXT*)calloc(1, sizeof(BITMAP_INTERLEAVED_CONTEXT));

	if (interleaved)
	{
		interleaved->TempSize = 64 * 64 * 4;
		interleaved->TempBuffer = _aligned_malloc(interleaved->TempSize, 16);

		if (!interleaved->TempBuffer)
		{
			free(interleaved);
			WLog_ERR(TAG, "_aligned_malloc failed!");
			return NULL;
		}

		interleaved->bts = Stream_New(NULL, interleaved->TempSize);

		if (!interleaved->bts)
		{
			_aligned_free(interleaved->TempBuffer);
			free(interleaved);
			WLog_ERR(TAG, "Stream_New failed!");
			return NULL;
		}
	}

	return interleaved;
}

void bitmap_interleaved_context_free(BITMAP_INTERLEAVED_CONTEXT* interleaved)
{
	if (!interleaved)
		return;

	_aligned_free(interleaved->TempBuffer);
	Stream_Free(interleaved->bts, TRUE);
	free(interleaved);
}
