












enum {
    FRAMETYPE_INTRA       = 0, FRAMETYPE_INTER       = 1, FRAMETYPE_INTER_SCAL  = 2, FRAMETYPE_INTER_NOREF = 3, FRAMETYPE_NULL        = 4 };








static int decode_gop_header(IVI45DecContext *ctx, AVCodecContext *avctx)
{
    int             result, i, p, tile_size, pic_size_indx, mb_size, blk_size;
    int             quant_mat, blk_size_changed = 0;
    IVIBandDesc     *band, *band1, *band2;
    IVIPicConfig    pic_conf;

    ctx->gop_flags = get_bits(&ctx->gb, 8);

    ctx->gop_hdr_size = (ctx->gop_flags & 1) ? get_bits(&ctx->gb, 16) : 0;

    if (ctx->gop_flags & IVI5_IS_PROTECTED)
        ctx->lock_word = get_bits_long(&ctx->gb, 32);

    tile_size = (ctx->gop_flags & 0x40) ? 64 << get_bits(&ctx->gb, 2) : 0;
    if (tile_size > 256) {
        av_log(avctx, AV_LOG_ERROR, "Invalid tile size: %d\n", tile_size);
        return -1;
    }

    
    
    pic_conf.luma_bands   = get_bits(&ctx->gb, 2) * 3 + 1;
    pic_conf.chroma_bands = get_bits1(&ctx->gb)   * 3 + 1;
    ctx->is_scalable = pic_conf.luma_bands != 1 || pic_conf.chroma_bands != 1;
    if (ctx->is_scalable && (pic_conf.luma_bands != 4 || pic_conf.chroma_bands != 1)) {
        av_log(avctx, AV_LOG_ERROR, "Scalability: unsupported subdivision! Luma bands: %d, chroma bands: %d\n", pic_conf.luma_bands, pic_conf.chroma_bands);
        return -1;
    }

    pic_size_indx = get_bits(&ctx->gb, 4);
    if (pic_size_indx == IVI5_PIC_SIZE_ESC) {
        pic_conf.pic_height = get_bits(&ctx->gb, 13);
        pic_conf.pic_width  = get_bits(&ctx->gb, 13);
    } else {
        pic_conf.pic_height = ivi5_common_pic_sizes[pic_size_indx * 2 + 1] << 2;
        pic_conf.pic_width  = ivi5_common_pic_sizes[pic_size_indx * 2    ] << 2;
    }

    if (ctx->gop_flags & 2) {
        av_log(avctx, AV_LOG_ERROR, "YV12 picture format not supported!\n");
        return -1;
    }

    pic_conf.chroma_height = (pic_conf.pic_height + 3) >> 2;
    pic_conf.chroma_width  = (pic_conf.pic_width  + 3) >> 2;

    if (!tile_size) {
        pic_conf.tile_height = pic_conf.pic_height;
        pic_conf.tile_width  = pic_conf.pic_width;
    } else {
        pic_conf.tile_height = pic_conf.tile_width = tile_size;
    }

    
    if (ivi_pic_config_cmp(&pic_conf, &ctx->pic_conf)) {
        result = ff_ivi_init_planes(ctx->planes, &pic_conf);
        if (result) {
            av_log(avctx, AV_LOG_ERROR, "Couldn't reallocate color planes!\n");
            return -1;
        }
        ctx->pic_conf = pic_conf;
        blk_size_changed = 1; 
    }

    for (p = 0; p <= 1; p++) {
        for (i = 0; i < (!p ? pic_conf.luma_bands : pic_conf.chroma_bands); i++) {
            band = &ctx->planes[p].bands[i];

            band->is_halfpel = get_bits1(&ctx->gb);

            mb_size  = get_bits1(&ctx->gb);
            blk_size = 8 >> get_bits1(&ctx->gb);
            mb_size  = blk_size << !mb_size;

            blk_size_changed = mb_size != band->mb_size || blk_size != band->blk_size;
            if (blk_size_changed) {
                band->mb_size  = mb_size;
                band->blk_size = blk_size;
            }

            if (get_bits1(&ctx->gb)) {
                av_log(avctx, AV_LOG_ERROR, "Extended transform info encountered!\n");
                return -1;
            }

            
            switch ((p << 2) + i) {
            case 0:
                band->inv_transform = ff_ivi_inverse_slant_8x8;
                band->dc_transform  = ff_ivi_dc_slant_2d;
                band->scan          = ff_zigzag_direct;
                break;

            case 1:
                band->inv_transform = ff_ivi_row_slant8;
                band->dc_transform  = ff_ivi_dc_row_slant;
                band->scan          = ff_ivi_vertical_scan_8x8;
                break;

            case 2:
                band->inv_transform = ff_ivi_col_slant8;
                band->dc_transform  = ff_ivi_dc_col_slant;
                band->scan          = ff_ivi_horizontal_scan_8x8;
                break;

            case 3:
                band->inv_transform = ff_ivi_put_pixels_8x8;
                band->dc_transform  = ff_ivi_put_dc_pixel_8x8;
                band->scan          = ff_ivi_horizontal_scan_8x8;
                break;

            case 4:
                band->inv_transform = ff_ivi_inverse_slant_4x4;
                band->dc_transform  = ff_ivi_dc_slant_2d;
                band->scan          = ff_ivi_direct_scan_4x4;
                break;
            }

            band->is_2d_trans = band->inv_transform == ff_ivi_inverse_slant_8x8 || band->inv_transform == ff_ivi_inverse_slant_4x4;

            
            if (!p) {
                quant_mat = (pic_conf.luma_bands > 1) ? i+1 : 0;
            } else {
                quant_mat = 5;
            }

            if (band->blk_size == 8) {
                band->intra_base  = &ivi5_base_quant_8x8_intra[quant_mat][0];
                band->inter_base  = &ivi5_base_quant_8x8_inter[quant_mat][0];
                band->intra_scale = &ivi5_scale_quant_8x8_intra[quant_mat][0];
                band->inter_scale = &ivi5_scale_quant_8x8_inter[quant_mat][0];
            } else {
                band->intra_base  = ivi5_base_quant_4x4_intra;
                band->inter_base  = ivi5_base_quant_4x4_inter;
                band->intra_scale = ivi5_scale_quant_4x4_intra;
                band->inter_scale = ivi5_scale_quant_4x4_inter;
            }

            if (get_bits(&ctx->gb, 2)) {
                av_log(avctx, AV_LOG_ERROR, "End marker missing!\n");
                return -1;
            }
        }
    }

    
    for (i = 0; i < pic_conf.chroma_bands; i++) {
        band1 = &ctx->planes[1].bands[i];
        band2 = &ctx->planes[2].bands[i];

        band2->width         = band1->width;
        band2->height        = band1->height;
        band2->mb_size       = band1->mb_size;
        band2->blk_size      = band1->blk_size;
        band2->is_halfpel    = band1->is_halfpel;
        band2->intra_base    = band1->intra_base;
        band2->inter_base    = band1->inter_base;
        band2->intra_scale   = band1->intra_scale;
        band2->inter_scale   = band1->inter_scale;
        band2->scan          = band1->scan;
        band2->inv_transform = band1->inv_transform;
        band2->dc_transform  = band1->dc_transform;
        band2->is_2d_trans   = band1->is_2d_trans;
    }

    
    if (blk_size_changed) {
        result = ff_ivi_init_tiles(ctx->planes, pic_conf.tile_width, pic_conf.tile_height);
        if (result) {
            av_log(avctx, AV_LOG_ERROR, "Couldn't reallocate internal structures!\n");
            return -1;
        }
    }

    if (ctx->gop_flags & 8) {
        if (get_bits(&ctx->gb, 3)) {
            av_log(avctx, AV_LOG_ERROR, "Alignment bits are not zero!\n");
            return -1;
        }

        if (get_bits1(&ctx->gb))
            skip_bits_long(&ctx->gb, 24); 
    }

    align_get_bits(&ctx->gb);

    skip_bits(&ctx->gb, 23); 

    
    if (get_bits1(&ctx->gb)) {
        do {
            i = get_bits(&ctx->gb, 16);
        } while (i & 0x8000);
    }

    align_get_bits(&ctx->gb);

    return 0;
}



static inline void skip_hdr_extension(GetBitContext *gb)
{
    int i, len;

    do {
        len = get_bits(gb, 8);
        for (i = 0; i < len; i++) skip_bits(gb, 8);
    } while(len);
}



static int decode_pic_hdr(IVI45DecContext *ctx, AVCodecContext *avctx)
{
    if (get_bits(&ctx->gb, 5) != 0x1F) {
        av_log(avctx, AV_LOG_ERROR, "Invalid picture start code!\n");
        return -1;
    }

    ctx->prev_frame_type = ctx->frame_type;
    ctx->frame_type      = get_bits(&ctx->gb, 3);
    if (ctx->frame_type >= 5) {
        av_log(avctx, AV_LOG_ERROR, "Invalid frame type: %d \n", ctx->frame_type);
        return -1;
    }

    ctx->frame_num = get_bits(&ctx->gb, 8);

    if (ctx->frame_type == FRAMETYPE_INTRA) {
        if (decode_gop_header(ctx, avctx))
            return -1;
    }

    if (ctx->frame_type != FRAMETYPE_NULL) {
        ctx->frame_flags = get_bits(&ctx->gb, 8);

        ctx->pic_hdr_size = (ctx->frame_flags & 1) ? get_bits_long(&ctx->gb, 24) : 0;

        ctx->checksum = (ctx->frame_flags & 0x10) ? get_bits(&ctx->gb, 16) : 0;

        
        if (ctx->frame_flags & 0x20)
            skip_hdr_extension(&ctx->gb); 

        
        if (ff_ivi_dec_huff_desc(&ctx->gb, ctx->frame_flags & 0x40, IVI_MB_HUFF, &ctx->mb_vlc, avctx))
            return -1;

        skip_bits(&ctx->gb, 3); 
    }

    align_get_bits(&ctx->gb);

    return 0;
}



static int decode_band_hdr(IVI45DecContext *ctx, IVIBandDesc *band, AVCodecContext *avctx)
{
    int         i;
    uint8_t     band_flags;

    band_flags = get_bits(&ctx->gb, 8);

    if (band_flags & 1) {
        band->is_empty = 1;
        return 0;
    }

    band->data_size = (ctx->frame_flags & 0x80) ? get_bits_long(&ctx->gb, 24) : 0;

    band->inherit_mv     = band_flags & 2;
    band->inherit_qdelta = band_flags & 8;
    band->qdelta_present = band_flags & 4;
    if (!band->qdelta_present) band->inherit_qdelta = 1;

    
    band->num_corr = 0; 
    if (band_flags & 0x10) {
        band->num_corr = get_bits(&ctx->gb, 8); 
        if (band->num_corr > 61) {
            av_log(avctx, AV_LOG_ERROR, "Too many corrections: %d\n", band->num_corr);
            return -1;
        }

        
        for (i = 0; i < band->num_corr * 2; i++)
            band->corr[i] = get_bits(&ctx->gb, 8);
    }

    
    band->rvmap_sel = (band_flags & 0x40) ? get_bits(&ctx->gb, 3) : 8;

    
    if (ff_ivi_dec_huff_desc(&ctx->gb, band_flags & 0x80, IVI_BLK_HUFF, &band->blk_vlc, avctx))
        return -1;

    band->checksum_present = get_bits1(&ctx->gb);
    if (band->checksum_present)
        band->checksum = get_bits(&ctx->gb, 16);

    band->glob_quant = get_bits(&ctx->gb, 5);

    
    if (band_flags & 0x20) { 
        align_get_bits(&ctx->gb);
        skip_hdr_extension(&ctx->gb);
    }

    align_get_bits(&ctx->gb);

    return 0;
}



static int decode_mb_info(IVI45DecContext *ctx, IVIBandDesc *band, IVITile *tile, AVCodecContext *avctx)
{
    int         x, y, mv_x, mv_y, mv_delta, offs, mb_offset, mv_scale, blks_per_mb;
    IVIMbInfo   *mb, *ref_mb;
    int         row_offset = band->mb_size * band->pitch;

    mb     = tile->mbs;
    ref_mb = tile->ref_mbs;
    offs   = tile->ypos * band->pitch + tile->xpos;

    if (!ref_mb && ((band->qdelta_present && band->inherit_qdelta) || band->inherit_mv))
        return AVERROR_INVALIDDATA;

    
    mv_scale = (ctx->planes[0].bands[0].mb_size >> 3) - (band->mb_size >> 3);
    mv_x = mv_y = 0;

    for (y = tile->ypos; y < (tile->ypos + tile->height); y += band->mb_size) {
        mb_offset = offs;

        for (x = tile->xpos; x < (tile->xpos + tile->width); x += band->mb_size) {
            mb->xpos     = x;
            mb->ypos     = y;
            mb->buf_offs = mb_offset;

            if (get_bits1(&ctx->gb)) {
                if (ctx->frame_type == FRAMETYPE_INTRA) {
                    av_log(avctx, AV_LOG_ERROR, "Empty macroblock in an INTRA picture!\n");
                    return -1;
                }
                mb->type = 1; 
                mb->cbp  = 0; 

                mb->q_delta = 0;
                if (!band->plane && !band->band_num && (ctx->frame_flags & 8)) {
                    mb->q_delta = get_vlc2(&ctx->gb, ctx->mb_vlc.tab->table, IVI_VLC_BITS, 1);
                    mb->q_delta = IVI_TOSIGNED(mb->q_delta);
                }

                mb->mv_x = mb->mv_y = 0; 
                if (band->inherit_mv){
                    
                    if (mv_scale) {
                        mb->mv_x = ivi_scale_mv(ref_mb->mv_x, mv_scale);
                        mb->mv_y = ivi_scale_mv(ref_mb->mv_y, mv_scale);
                    } else {
                        mb->mv_x = ref_mb->mv_x;
                        mb->mv_y = ref_mb->mv_y;
                    }
                }
            } else {
                if (band->inherit_mv) {
                    mb->type = ref_mb->type; 
                } else if (ctx->frame_type == FRAMETYPE_INTRA) {
                    mb->type = 0; 
                } else {
                    mb->type = get_bits1(&ctx->gb);
                }

                blks_per_mb = band->mb_size != band->blk_size ? 4 : 1;
                mb->cbp = get_bits(&ctx->gb, blks_per_mb);

                mb->q_delta = 0;
                if (band->qdelta_present) {
                    if (band->inherit_qdelta) {
                        if (ref_mb) mb->q_delta = ref_mb->q_delta;
                    } else if (mb->cbp || (!band->plane && !band->band_num && (ctx->frame_flags & 8))) {
                        mb->q_delta = get_vlc2(&ctx->gb, ctx->mb_vlc.tab->table, IVI_VLC_BITS, 1);
                        mb->q_delta = IVI_TOSIGNED(mb->q_delta);
                    }
                }

                if (!mb->type) {
                    mb->mv_x = mb->mv_y = 0; 
                } else {
                    if (band->inherit_mv){
                        
                        if (mv_scale) {
                            mb->mv_x = ivi_scale_mv(ref_mb->mv_x, mv_scale);
                            mb->mv_y = ivi_scale_mv(ref_mb->mv_y, mv_scale);
                        } else {
                            mb->mv_x = ref_mb->mv_x;
                            mb->mv_y = ref_mb->mv_y;
                        }
                    } else {
                        
                        mv_delta = get_vlc2(&ctx->gb, ctx->mb_vlc.tab->table, IVI_VLC_BITS, 1);
                        mv_y += IVI_TOSIGNED(mv_delta);
                        mv_delta = get_vlc2(&ctx->gb, ctx->mb_vlc.tab->table, IVI_VLC_BITS, 1);
                        mv_x += IVI_TOSIGNED(mv_delta);
                        mb->mv_x = mv_x;
                        mb->mv_y = mv_y;
                    }
                }
            }

            mb++;
            if (ref_mb)
                ref_mb++;
            mb_offset += band->mb_size;
        }

        offs += row_offset;
    }

    align_get_bits(&ctx->gb);

    return 0;
}



static void switch_buffers(IVI45DecContext *ctx)
{
    switch (ctx->prev_frame_type) {
    case FRAMETYPE_INTRA:
    case FRAMETYPE_INTER:
        ctx->buf_switch ^= 1;
        ctx->dst_buf = ctx->buf_switch;
        ctx->ref_buf = ctx->buf_switch ^ 1;
        break;
    case FRAMETYPE_INTER_SCAL:
        if (!ctx->inter_scal) {
            ctx->ref2_buf   = 2;
            ctx->inter_scal = 1;
        }
        FFSWAP(int, ctx->dst_buf, ctx->ref2_buf);
        ctx->ref_buf = ctx->ref2_buf;
        break;
    case FRAMETYPE_INTER_NOREF:
        break;
    }

    switch (ctx->frame_type) {
    case FRAMETYPE_INTRA:
        ctx->buf_switch = 0;
        
    case FRAMETYPE_INTER:
        ctx->inter_scal = 0;
        ctx->dst_buf = ctx->buf_switch;
        ctx->ref_buf = ctx->buf_switch ^ 1;
        break;
    case FRAMETYPE_INTER_SCAL:
    case FRAMETYPE_INTER_NOREF:
    case FRAMETYPE_NULL:
        break;
    }
}


static int is_nonnull_frame(IVI45DecContext *ctx)
{
    return ctx->frame_type != FRAMETYPE_NULL;
}



static av_cold int decode_init(AVCodecContext *avctx)
{
    IVI45DecContext  *ctx = avctx->priv_data;
    int             result;

    ff_ivi_init_static_vlc();

    
    memcpy(ctx->rvmap_tabs, ff_ivi_rvmap_tabs, sizeof(ff_ivi_rvmap_tabs));

    
    ctx->pic_conf.pic_width     = avctx->width;
    ctx->pic_conf.pic_height    = avctx->height;
    ctx->pic_conf.chroma_width  = (avctx->width  + 3) >> 2;
    ctx->pic_conf.chroma_height = (avctx->height + 3) >> 2;
    ctx->pic_conf.tile_width    = avctx->width;
    ctx->pic_conf.tile_height   = avctx->height;
    ctx->pic_conf.luma_bands    = ctx->pic_conf.chroma_bands = 1;

    result = ff_ivi_init_planes(ctx->planes, &ctx->pic_conf);
    if (result) {
        av_log(avctx, AV_LOG_ERROR, "Couldn't allocate color planes!\n");
        return -1;
    }

    ctx->buf_switch = 0;
    ctx->inter_scal = 0;

    ctx->decode_pic_hdr   = decode_pic_hdr;
    ctx->decode_band_hdr  = decode_band_hdr;
    ctx->decode_mb_info   = decode_mb_info;
    ctx->switch_buffers   = switch_buffers;
    ctx->is_nonnull_frame = is_nonnull_frame;

    avctx->pix_fmt = PIX_FMT_YUV410P;

    return 0;
}


AVCodec ff_indeo5_decoder = {
    .name           = "indeo5", .type           = AVMEDIA_TYPE_VIDEO, .id             = AV_CODEC_ID_INDEO5, .priv_data_size = sizeof(IVI45DecContext), .init           = decode_init, .close          = ff_ivi_decode_close, .decode         = ff_ivi_decode_frame, .long_name      = NULL_IF_CONFIG_SMALL("Intel Indeo Video Interactive 5"), };







