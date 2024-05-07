

































typedef struct FlicDecodeContext {
    AVCodecContext *avctx;
    AVFrame frame;

    unsigned int palette[256];
    int new_palette;
    int fli_type;  
} FlicDecodeContext;

static av_cold int flic_decode_init(AVCodecContext *avctx)
{
    FlicDecodeContext *s = avctx->priv_data;
    unsigned char *fli_header = (unsigned char *)avctx->extradata;
    int depth;

    s->avctx = avctx;

    s->fli_type = AV_RL16(&fli_header[4]); 

    depth = 0;
    if (s->avctx->extradata_size == 12) {
        
        s->fli_type = FLC_MAGIC_CARPET_SYNTHETIC_TYPE_CODE;
        depth = 8;
    } else if (s->avctx->extradata_size != 128) {
        av_log(avctx, AV_LOG_ERROR, "Expected extradata of 12 or 128 bytes\n");
        return -1;
    } else {
        depth = AV_RL16(&fli_header[12]);
    }

    if (depth == 0) {
        depth = 8; 
    }

    if ((s->fli_type == FLC_FLX_TYPE_CODE) && (depth == 16)) {
        depth = 15; 
    }

    switch (depth) {
        case 8  : avctx->pix_fmt = PIX_FMT_PAL8; break;
        case 15 : avctx->pix_fmt = PIX_FMT_RGB555; break;
        case 16 : avctx->pix_fmt = PIX_FMT_RGB565; break;
        case 24 : avctx->pix_fmt = PIX_FMT_BGR24; 
                  av_log(avctx, AV_LOG_ERROR, "24Bpp FLC/FLX is unsupported due to no test files.\n");
                  return -1;
                  break;
        default :
                  av_log(avctx, AV_LOG_ERROR, "Unknown FLC/FLX depth of %d Bpp is unsupported.\n",depth);
                  return -1;
    }

    s->frame.data[0] = NULL;
    s->new_palette = 0;

    return 0;
}

static int flic_decode_frame_8BPP(AVCodecContext *avctx, void *data, int *data_size, const uint8_t *buf, int buf_size)

{
    FlicDecodeContext *s = avctx->priv_data;

    int stream_ptr = 0;
    int stream_ptr_after_color_chunk;
    int pixel_ptr;
    int palette_ptr;
    unsigned char palette_idx1;
    unsigned char palette_idx2;

    unsigned int frame_size;
    int num_chunks;

    unsigned int chunk_size;
    int chunk_type;

    int i, j;

    int color_packets;
    int color_changes;
    int color_shift;
    unsigned char r, g, b;

    int lines;
    int compressed_lines;
    int starting_line;
    signed short line_packets;
    int y_ptr;
    int byte_run;
    int pixel_skip;
    int pixel_countdown;
    unsigned char *pixels;
    int pixel_limit;

    s->frame.reference = 1;
    s->frame.buffer_hints = FF_BUFFER_HINTS_VALID | FF_BUFFER_HINTS_PRESERVE | FF_BUFFER_HINTS_REUSABLE;
    if (avctx->reget_buffer(avctx, &s->frame) < 0) {
        av_log(avctx, AV_LOG_ERROR, "reget_buffer() failed\n");
        return -1;
    }

    pixels = s->frame.data[0];
    pixel_limit = s->avctx->height * s->frame.linesize[0];

    frame_size = AV_RL32(&buf[stream_ptr]);
    stream_ptr += 6;  
    num_chunks = AV_RL16(&buf[stream_ptr]);
    stream_ptr += 10;  

    frame_size -= 16;

    
    while ((frame_size > 0) && (num_chunks > 0)) {
        chunk_size = AV_RL32(&buf[stream_ptr]);
        stream_ptr += 4;
        chunk_type = AV_RL16(&buf[stream_ptr]);
        stream_ptr += 2;

        switch (chunk_type) {
        case FLI_256_COLOR:
        case FLI_COLOR:
            stream_ptr_after_color_chunk = stream_ptr + chunk_size - 6;

            
            if ((chunk_type == FLI_256_COLOR) && (s->fli_type != FLC_MAGIC_CARPET_SYNTHETIC_TYPE_CODE))
                color_shift = 0;
            else color_shift = 2;
            
            color_packets = AV_RL16(&buf[stream_ptr]);
            stream_ptr += 2;
            palette_ptr = 0;
            for (i = 0; i < color_packets; i++) {
                
                palette_ptr += buf[stream_ptr++];

                
                color_changes = buf[stream_ptr++];

                
                if (color_changes == 0)
                    color_changes = 256;

                for (j = 0; j < color_changes; j++) {
                    unsigned int entry;

                    
                    if ((unsigned)palette_ptr >= 256)
                        palette_ptr = 0;

                    r = buf[stream_ptr++] << color_shift;
                    g = buf[stream_ptr++] << color_shift;
                    b = buf[stream_ptr++] << color_shift;
                    entry = (r << 16) | (g << 8) | b;
                    if (s->palette[palette_ptr] != entry)
                        s->new_palette = 1;
                    s->palette[palette_ptr++] = entry;
                }
            }

            
            stream_ptr = stream_ptr_after_color_chunk;

            break;

        case FLI_DELTA:
            y_ptr = 0;
            compressed_lines = AV_RL16(&buf[stream_ptr]);
            stream_ptr += 2;
            while (compressed_lines > 0) {
                line_packets = AV_RL16(&buf[stream_ptr]);
                stream_ptr += 2;
                if ((line_packets & 0xC000) == 0xC000) {
                    
                    line_packets = -line_packets;
                    y_ptr += line_packets * s->frame.linesize[0];
                } else if ((line_packets & 0xC000) == 0x4000) {
                    av_log(avctx, AV_LOG_ERROR, "Undefined opcode (%x) in DELTA_FLI\n", line_packets);
                } else if ((line_packets & 0xC000) == 0x8000) {
                    
                    pixels[y_ptr + s->frame.linesize[0] - 1] = line_packets & 0xff;
                } else {
                    compressed_lines--;
                    pixel_ptr = y_ptr;
                    pixel_countdown = s->avctx->width;
                    for (i = 0; i < line_packets; i++) {
                        
                        pixel_skip = buf[stream_ptr++];
                        pixel_ptr += pixel_skip;
                        pixel_countdown -= pixel_skip;
                        byte_run = (signed char)(buf[stream_ptr++]);
                        if (byte_run < 0) {
                            byte_run = -byte_run;
                            palette_idx1 = buf[stream_ptr++];
                            palette_idx2 = buf[stream_ptr++];
                            CHECK_PIXEL_PTR(byte_run);
                            for (j = 0; j < byte_run; j++, pixel_countdown -= 2) {
                                pixels[pixel_ptr++] = palette_idx1;
                                pixels[pixel_ptr++] = palette_idx2;
                            }
                        } else {
                            CHECK_PIXEL_PTR(byte_run * 2);
                            for (j = 0; j < byte_run * 2; j++, pixel_countdown--) {
                                palette_idx1 = buf[stream_ptr++];
                                pixels[pixel_ptr++] = palette_idx1;
                            }
                        }
                    }

                    y_ptr += s->frame.linesize[0];
                }
            }
            break;

        case FLI_LC:
            
            starting_line = AV_RL16(&buf[stream_ptr]);
            stream_ptr += 2;
            y_ptr = 0;
            y_ptr += starting_line * s->frame.linesize[0];

            compressed_lines = AV_RL16(&buf[stream_ptr]);
            stream_ptr += 2;
            while (compressed_lines > 0) {
                pixel_ptr = y_ptr;
                pixel_countdown = s->avctx->width;
                line_packets = buf[stream_ptr++];
                if (line_packets > 0) {
                    for (i = 0; i < line_packets; i++) {
                        
                        pixel_skip = buf[stream_ptr++];
                        pixel_ptr += pixel_skip;
                        pixel_countdown -= pixel_skip;
                        byte_run = (signed char)(buf[stream_ptr++]);
                        if (byte_run > 0) {
                            CHECK_PIXEL_PTR(byte_run);
                            for (j = 0; j < byte_run; j++, pixel_countdown--) {
                                palette_idx1 = buf[stream_ptr++];
                                pixels[pixel_ptr++] = palette_idx1;
                            }
                        } else if (byte_run < 0) {
                            byte_run = -byte_run;
                            palette_idx1 = buf[stream_ptr++];
                            CHECK_PIXEL_PTR(byte_run);
                            for (j = 0; j < byte_run; j++, pixel_countdown--) {
                                pixels[pixel_ptr++] = palette_idx1;
                            }
                        }
                    }
                }

                y_ptr += s->frame.linesize[0];
                compressed_lines--;
            }
            break;

        case FLI_BLACK:
            
            memset(pixels, 0, s->frame.linesize[0] * s->avctx->height);
            break;

        case FLI_BRUN:
            
            y_ptr = 0;
            for (lines = 0; lines < s->avctx->height; lines++) {
                pixel_ptr = y_ptr;
                
                stream_ptr++;
                pixel_countdown = s->avctx->width;
                while (pixel_countdown > 0) {
                    byte_run = (signed char)(buf[stream_ptr++]);
                    if (byte_run > 0) {
                        palette_idx1 = buf[stream_ptr++];
                        CHECK_PIXEL_PTR(byte_run);
                        for (j = 0; j < byte_run; j++) {
                            pixels[pixel_ptr++] = palette_idx1;
                            pixel_countdown--;
                            if (pixel_countdown < 0)
                                av_log(avctx, AV_LOG_ERROR, "pixel_countdown < 0 (%d) at line %d\n", pixel_countdown, lines);
                        }
                    } else {  
                        byte_run = -byte_run;
                        CHECK_PIXEL_PTR(byte_run);
                        for (j = 0; j < byte_run; j++) {
                            palette_idx1 = buf[stream_ptr++];
                            pixels[pixel_ptr++] = palette_idx1;
                            pixel_countdown--;
                            if (pixel_countdown < 0)
                                av_log(avctx, AV_LOG_ERROR, "pixel_countdown < 0 (%d) at line %d\n", pixel_countdown, lines);
                        }
                    }
                }

                y_ptr += s->frame.linesize[0];
            }
            break;

        case FLI_COPY:
            
            if (chunk_size - 6 > s->avctx->width * s->avctx->height) {
                av_log(avctx, AV_LOG_ERROR, "In chunk FLI_COPY : source data (%d bytes) "  "bigger than image, skipping chunk\n", chunk_size - 6)
                stream_ptr += chunk_size - 6;
            } else {
                for (y_ptr = 0; y_ptr < s->frame.linesize[0] * s->avctx->height;
                     y_ptr += s->frame.linesize[0]) {
                    memcpy(&pixels[y_ptr], &buf[stream_ptr], s->avctx->width);
                    stream_ptr += s->avctx->width;
                }
            }
            break;

        case FLI_MINI:
            
            stream_ptr += chunk_size - 6;
            break;

        default:
            av_log(avctx, AV_LOG_ERROR, "Unrecognized chunk type: %d\n", chunk_type);
            break;
        }

        frame_size -= chunk_size;
        num_chunks--;
    }

    
    if ((stream_ptr != buf_size) && (stream_ptr != buf_size - 1))
        av_log(avctx, AV_LOG_ERROR, "Processed FLI chunk where chunk size = %d "  "and final chunk ptr = %d\n", buf_size, stream_ptr)

    
    memcpy(s->frame.data[1], s->palette, AVPALETTE_SIZE);
    if (s->new_palette) {
        s->frame.palette_has_changed = 1;
        s->new_palette = 0;
    }

    *data_size=sizeof(AVFrame);
    *(AVFrame*)data = s->frame;

    return buf_size;
}

static int flic_decode_frame_15_16BPP(AVCodecContext *avctx, void *data, int *data_size, const uint8_t *buf, int buf_size)

{
    
    
    FlicDecodeContext *s = avctx->priv_data;

    int stream_ptr = 0;
    int pixel_ptr;
    unsigned char palette_idx1;

    unsigned int frame_size;
    int num_chunks;

    unsigned int chunk_size;
    int chunk_type;

    int i, j;

    int lines;
    int compressed_lines;
    signed short line_packets;
    int y_ptr;
    int byte_run;
    int pixel_skip;
    int pixel_countdown;
    unsigned char *pixels;
    int pixel;
    int pixel_limit;

    s->frame.reference = 1;
    s->frame.buffer_hints = FF_BUFFER_HINTS_VALID | FF_BUFFER_HINTS_PRESERVE | FF_BUFFER_HINTS_REUSABLE;
    if (avctx->reget_buffer(avctx, &s->frame) < 0) {
        av_log(avctx, AV_LOG_ERROR, "reget_buffer() failed\n");
        return -1;
    }

    pixels = s->frame.data[0];
    pixel_limit = s->avctx->height * s->frame.linesize[0];

    frame_size = AV_RL32(&buf[stream_ptr]);
    stream_ptr += 6;  
    num_chunks = AV_RL16(&buf[stream_ptr]);
    stream_ptr += 10;  

    frame_size -= 16;

    
    while ((frame_size > 0) && (num_chunks > 0)) {
        chunk_size = AV_RL32(&buf[stream_ptr]);
        stream_ptr += 4;
        chunk_type = AV_RL16(&buf[stream_ptr]);
        stream_ptr += 2;

        switch (chunk_type) {
        case FLI_256_COLOR:
        case FLI_COLOR:
            

            stream_ptr = stream_ptr + chunk_size - 6;
            break;

        case FLI_DELTA:
        case FLI_DTA_LC:
            y_ptr = 0;
            compressed_lines = AV_RL16(&buf[stream_ptr]);
            stream_ptr += 2;
            while (compressed_lines > 0) {
                line_packets = AV_RL16(&buf[stream_ptr]);
                stream_ptr += 2;
                if (line_packets < 0) {
                    line_packets = -line_packets;
                    y_ptr += line_packets * s->frame.linesize[0];
                } else {
                    compressed_lines--;
                    pixel_ptr = y_ptr;
                    pixel_countdown = s->avctx->width;
                    for (i = 0; i < line_packets; i++) {
                        
                        pixel_skip = buf[stream_ptr++];
                        pixel_ptr += (pixel_skip*2); 
                        pixel_countdown -= pixel_skip;
                        byte_run = (signed char)(buf[stream_ptr++]);
                        if (byte_run < 0) {
                            byte_run = -byte_run;
                            pixel    = AV_RL16(&buf[stream_ptr]);
                            stream_ptr += 2;
                            CHECK_PIXEL_PTR(byte_run);
                            for (j = 0; j < byte_run; j++, pixel_countdown -= 2) {
                                *((signed short*)(&pixels[pixel_ptr])) = pixel;
                                pixel_ptr += 2;
                            }
                        } else {
                            CHECK_PIXEL_PTR(byte_run);
                            for (j = 0; j < byte_run; j++, pixel_countdown--) {
                                *((signed short*)(&pixels[pixel_ptr])) = AV_RL16(&buf[stream_ptr]);
                                stream_ptr += 2;
                                pixel_ptr += 2;
                            }
                        }
                    }

                    y_ptr += s->frame.linesize[0];
                }
            }
            break;

        case FLI_LC:
            av_log(avctx, AV_LOG_ERROR, "Unexpected FLI_LC chunk in non-paletised FLC\n");
            stream_ptr = stream_ptr + chunk_size - 6;
            break;

        case FLI_BLACK:
            
            memset(pixels, 0x0000, s->frame.linesize[0] * s->avctx->height);
            break;

        case FLI_BRUN:
            y_ptr = 0;
            for (lines = 0; lines < s->avctx->height; lines++) {
                pixel_ptr = y_ptr;
                
                stream_ptr++;
                pixel_countdown = (s->avctx->width * 2);

                while (pixel_countdown > 0) {
                    byte_run = (signed char)(buf[stream_ptr++]);
                    if (byte_run > 0) {
                        palette_idx1 = buf[stream_ptr++];
                        CHECK_PIXEL_PTR(byte_run);
                        for (j = 0; j < byte_run; j++) {
                            pixels[pixel_ptr++] = palette_idx1;
                            pixel_countdown--;
                            if (pixel_countdown < 0)
                                av_log(avctx, AV_LOG_ERROR, "pixel_countdown < 0 (%d) (linea%d)\n", pixel_countdown, lines);
                        }
                    } else {  
                        byte_run = -byte_run;
                        CHECK_PIXEL_PTR(byte_run);
                        for (j = 0; j < byte_run; j++) {
                            palette_idx1 = buf[stream_ptr++];
                            pixels[pixel_ptr++] = palette_idx1;
                            pixel_countdown--;
                            if (pixel_countdown < 0)
                                av_log(avctx, AV_LOG_ERROR, "pixel_countdown < 0 (%d) at line %d\n", pixel_countdown, lines);
                        }
                    }
                }

                

                pixel_ptr = y_ptr;
                pixel_countdown = s->avctx->width;
                while (pixel_countdown > 0) {
                    *((signed short*)(&pixels[pixel_ptr])) = AV_RL16(&buf[pixel_ptr]);
                    pixel_ptr += 2;
                }

                y_ptr += s->frame.linesize[0];
            }
            break;

        case FLI_DTA_BRUN:
            y_ptr = 0;
            for (lines = 0; lines < s->avctx->height; lines++) {
                pixel_ptr = y_ptr;
                
                stream_ptr++;
                pixel_countdown = s->avctx->width; 

                while (pixel_countdown > 0) {
                    byte_run = (signed char)(buf[stream_ptr++]);
                    if (byte_run > 0) {
                        pixel    = AV_RL16(&buf[stream_ptr]);
                        stream_ptr += 2;
                        CHECK_PIXEL_PTR(byte_run);
                        for (j = 0; j < byte_run; j++) {
                            *((signed short*)(&pixels[pixel_ptr])) = pixel;
                            pixel_ptr += 2;
                            pixel_countdown--;
                            if (pixel_countdown < 0)
                                av_log(avctx, AV_LOG_ERROR, "pixel_countdown < 0 (%d)\n", pixel_countdown);
                        }
                    } else {  
                        byte_run = -byte_run;
                        CHECK_PIXEL_PTR(byte_run);
                        for (j = 0; j < byte_run; j++) {
                            *((signed short*)(&pixels[pixel_ptr])) = AV_RL16(&buf[stream_ptr]);
                            stream_ptr += 2;
                            pixel_ptr  += 2;
                            pixel_countdown--;
                            if (pixel_countdown < 0)
                                av_log(avctx, AV_LOG_ERROR, "pixel_countdown < 0 (%d)\n", pixel_countdown);
                        }
                    }
                }

                y_ptr += s->frame.linesize[0];
            }
            break;

        case FLI_COPY:
        case FLI_DTA_COPY:
            
            if (chunk_size - 6 > (unsigned int)(s->avctx->width * s->avctx->height)*2) {
                av_log(avctx, AV_LOG_ERROR, "In chunk FLI_COPY : source data (%d bytes) "  "bigger than image, skipping chunk\n", chunk_size - 6)
                stream_ptr += chunk_size - 6;
            } else {

                for (y_ptr = 0; y_ptr < s->frame.linesize[0] * s->avctx->height;
                     y_ptr += s->frame.linesize[0]) {

                    pixel_countdown = s->avctx->width;
                    pixel_ptr = 0;
                    while (pixel_countdown > 0) {
                      *((signed short*)(&pixels[y_ptr + pixel_ptr])) = AV_RL16(&buf[stream_ptr+pixel_ptr]);
                      pixel_ptr += 2;
                      pixel_countdown--;
                    }
                    stream_ptr += s->avctx->width*2;
                }
            }
            break;

        case FLI_MINI:
            
            stream_ptr += chunk_size - 6;
            break;

        default:
            av_log(avctx, AV_LOG_ERROR, "Unrecognized chunk type: %d\n", chunk_type);
            break;
        }

        frame_size -= chunk_size;
        num_chunks--;
    }

    
    if ((stream_ptr != buf_size) && (stream_ptr != buf_size - 1))
        av_log(avctx, AV_LOG_ERROR, "Processed FLI chunk where chunk size = %d "  "and final chunk ptr = %d\n", buf_size, stream_ptr)


    *data_size=sizeof(AVFrame);
    *(AVFrame*)data = s->frame;

    return buf_size;
}

static int flic_decode_frame_24BPP(AVCodecContext *avctx, void *data, int *data_size, const uint8_t *buf, int buf_size)

{
  av_log(avctx, AV_LOG_ERROR, "24Bpp FLC Unsupported due to lack of test files.\n");
  return -1;
}

static int flic_decode_frame(AVCodecContext *avctx, void *data, int *data_size, AVPacket *avpkt)

{
    const uint8_t *buf = avpkt->data;
    int buf_size = avpkt->size;
    if (avctx->pix_fmt == PIX_FMT_PAL8) {
      return flic_decode_frame_8BPP(avctx, data, data_size, buf, buf_size);
    }
    else if ((avctx->pix_fmt == PIX_FMT_RGB555) || (avctx->pix_fmt == PIX_FMT_RGB565)) {
      return flic_decode_frame_15_16BPP(avctx, data, data_size, buf, buf_size);
    }
    else if (avctx->pix_fmt == PIX_FMT_BGR24) {
      return flic_decode_frame_24BPP(avctx, data, data_size, buf, buf_size);
    }

    
    
    
    
    av_log(avctx, AV_LOG_ERROR, "Unknown FLC format, my science cannot explain how this happened.\n");
    return -1;
}


static av_cold int flic_decode_end(AVCodecContext *avctx)
{
    FlicDecodeContext *s = avctx->priv_data;

    if (s->frame.data[0])
        avctx->release_buffer(avctx, &s->frame);

    return 0;
}

AVCodec flic_decoder = {
    "flic", AVMEDIA_TYPE_VIDEO, CODEC_ID_FLIC, sizeof(FlicDecodeContext), flic_decode_init, NULL, flic_decode_end, flic_decode_frame, CODEC_CAP_DR1, NULL, NULL, NULL, NULL, .long_name = NULL_IF_CONFIG_SMALL("Autodesk Animator Flic video"), };













