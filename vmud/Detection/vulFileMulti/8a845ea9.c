







static int subrectEncode8(rfbClientPtr cl, uint8_t *data, int w, int h);
static int subrectEncode16(rfbClientPtr cl, uint16_t *data, int w, int h);
static int subrectEncode32(rfbClientPtr cl, uint32_t *data, int w, int h);
static uint32_t getBgColour(char *data, int size, int bpp);
static rfbBool rfbSendSmallRectEncodingCoRRE(rfbClientPtr cl, int x, int y, int w, int h);




rfbBool rfbSendRectEncodingCoRRE(rfbClientPtr cl, int x, int y, int w, int h)




{
    if (h > cl->correMaxHeight) {
        return (rfbSendRectEncodingCoRRE(cl, x, y, w, cl->correMaxHeight) && rfbSendRectEncodingCoRRE(cl, x, y + cl->correMaxHeight, w, h - cl->correMaxHeight));

    }

    if (w > cl->correMaxWidth) {
        return (rfbSendRectEncodingCoRRE(cl, x, y, cl->correMaxWidth, h) && rfbSendRectEncodingCoRRE(cl, x + cl->correMaxWidth, y, w - cl->correMaxWidth, h));

    }

    rfbSendSmallRectEncodingCoRRE(cl, x, y, w, h);
    return TRUE;
}





static rfbBool rfbSendSmallRectEncodingCoRRE(rfbClientPtr cl, int x, int y, int w, int h)




{
    rfbFramebufferUpdateRectHeader rect;
    rfbRREHeader hdr;
    int nSubrects;
    int i;
    char *fbptr = (cl->scaledScreen->frameBuffer + (cl->scaledScreen->paddedWidthInBytes * y)
                   + (x * (cl->scaledScreen->bitsPerPixel / 8)));

    int maxRawSize = (cl->scaledScreen->width * cl->scaledScreen->height * (cl->format.bitsPerPixel / 8));

    if (cl->beforeEncBufSize < maxRawSize) {
        cl->beforeEncBufSize = maxRawSize;
        if (cl->beforeEncBuf == NULL)
            cl->beforeEncBuf = (char *)malloc(cl->beforeEncBufSize);
        else cl->beforeEncBuf = (char *)realloc(cl->beforeEncBuf, cl->beforeEncBufSize);
    }

    if (cl->afterEncBufSize < maxRawSize) {
        cl->afterEncBufSize = maxRawSize;
        if (cl->afterEncBuf == NULL)
            cl->afterEncBuf = (char *)malloc(cl->afterEncBufSize);
        else cl->afterEncBuf = (char *)realloc(cl->afterEncBuf, cl->afterEncBufSize);
    }

    (*cl->translateFn)(cl->translateLookupTable,&(cl->screen->serverFormat), &cl->format, fbptr, cl->beforeEncBuf, cl->scaledScreen->paddedWidthInBytes, w, h);


    switch (cl->format.bitsPerPixel) {
    case 8:
        nSubrects = subrectEncode8(cl, (uint8_t *)cl->beforeEncBuf, w, h);
        break;
    case 16:
        nSubrects = subrectEncode16(cl, (uint16_t *)cl->beforeEncBuf, w, h);
        break;
    case 32:
        nSubrects = subrectEncode32(cl, (uint32_t *)cl->beforeEncBuf, w, h);
        break;
    default:
        rfbLog("getBgColour: bpp %d?\n",cl->format.bitsPerPixel);
        return FALSE;
    }
        
    if (nSubrects < 0) {

        

        return rfbSendRectEncodingRaw(cl, x, y, w, h);
    }

    rfbStatRecordEncodingSent(cl,rfbEncodingCoRRE, sz_rfbFramebufferUpdateRectHeader + sz_rfbRREHeader + cl->afterEncBufLen, sz_rfbFramebufferUpdateRectHeader + w * h * (cl->format.bitsPerPixel / 8));


    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader + sz_rfbRREHeader > UPDATE_BUF_SIZE)
    {
        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }

    rect.r.x = Swap16IfLE(x);
    rect.r.y = Swap16IfLE(y);
    rect.r.w = Swap16IfLE(w);
    rect.r.h = Swap16IfLE(h);
    rect.encoding = Swap32IfLE(rfbEncodingCoRRE);

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;

    hdr.nSubrects = Swap32IfLE(nSubrects);

    memcpy(&cl->updateBuf[cl->ublen], (char *)&hdr, sz_rfbRREHeader);
    cl->ublen += sz_rfbRREHeader;

    for (i = 0; i < cl->afterEncBufLen;) {

        int bytesToCopy = UPDATE_BUF_SIZE - cl->ublen;

        if (i + bytesToCopy > cl->afterEncBufLen) {
            bytesToCopy = cl->afterEncBufLen - i;
        }

        memcpy(&cl->updateBuf[cl->ublen], &cl->afterEncBuf[i], bytesToCopy);

        cl->ublen += bytesToCopy;
        i += bytesToCopy;

        if (cl->ublen == UPDATE_BUF_SIZE) {
            if (!rfbSendUpdateBuf(cl))
                return FALSE;
        }
    }

    return TRUE;
}

























































































DEFINE_SUBRECT_ENCODE(8)
DEFINE_SUBRECT_ENCODE(16)
DEFINE_SUBRECT_ENCODE(32)



static uint32_t getBgColour(char *data, int size, int bpp)
{


  
  static int counts[NUMCLRS];
  int i,j,k;

  int maxcount = 0;
  uint8_t maxclr = 0;

  if (bpp != 8) {
    if (bpp == 16) {
      return ((uint16_t *)data)[0];
    } else if (bpp == 32) {
      return ((uint32_t *)data)[0];
    } else {
      rfbLog("getBgColour: bpp %d?\n",bpp);
      return 0;
    }
  }

  for (i=0; i<NUMCLRS; i++) {
    counts[i] = 0;
  }

  for (j=0; j<size; j++) {
    k = (int)(((uint8_t *)data)[j]);
    if (k >= NUMCLRS) {
      rfbLog("getBgColour: unusual colour = %d\n", k);
      return 0;
    }
    counts[k] += 1;
    if (counts[k] > maxcount) {
      maxcount = counts[k];
      maxclr = ((uint8_t *)data)[j];
    }
  }
  
  return maxclr;
}
