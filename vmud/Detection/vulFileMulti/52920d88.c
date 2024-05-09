





static rfbBool sendHextiles8(rfbClientPtr cl, int x, int y, int w, int h);
static rfbBool sendHextiles16(rfbClientPtr cl, int x, int y, int w, int h);
static rfbBool sendHextiles32(rfbClientPtr cl, int x, int y, int w, int h);




rfbBool rfbSendRectEncodingHextile(rfbClientPtr cl, int x, int y, int w, int h)




{
    rfbFramebufferUpdateRectHeader rect;
    
    if (cl->ublen + sz_rfbFramebufferUpdateRectHeader > UPDATE_BUF_SIZE) {
        if (!rfbSendUpdateBuf(cl))
            return FALSE;
    }

    rect.r.x = Swap16IfLE(x);
    rect.r.y = Swap16IfLE(y);
    rect.r.w = Swap16IfLE(w);
    rect.r.h = Swap16IfLE(h);
    rect.encoding = Swap32IfLE(rfbEncodingHextile);

    memcpy(&cl->updateBuf[cl->ublen], (char *)&rect, sz_rfbFramebufferUpdateRectHeader);
    cl->ublen += sz_rfbFramebufferUpdateRectHeader;

    rfbStatRecordEncodingSent(cl, rfbEncodingHextile, sz_rfbFramebufferUpdateRectHeader, sz_rfbFramebufferUpdateRectHeader + w * (cl->format.bitsPerPixel / 8) * h);


    switch (cl->format.bitsPerPixel) {
    case 8:
        return sendHextiles8(cl, x, y, w, h);
    case 16:
        return sendHextiles16(cl, x, y, w, h);
    case 32:
        return sendHextiles32(cl, x, y, w, h);
    }

    rfbLog("rfbSendRectEncodingHextile: bpp %d?\n", cl->format.bitsPerPixel);
    return FALSE;
}
























































































































































































































































DEFINE_SEND_HEXTILES(8)
DEFINE_SEND_HEXTILES(16)
DEFINE_SEND_HEXTILES(32)
