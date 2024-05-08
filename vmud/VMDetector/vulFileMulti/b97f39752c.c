

























typedef struct {
    int16_t     prev_block_len;                         
    uint8_t     transmit_coefs;
    uint8_t     num_subframes;
    uint16_t    subframe_len[MAX_SUBFRAMES];            
    uint16_t    subframe_offsets[MAX_SUBFRAMES];        
    uint8_t     cur_subframe;                           
    uint16_t    decoded_samples;                        
    int         quant_step;                             
    int         transient_counter;                      
} WmallChannelCtx;


typedef struct WmallDecodeCtx {
    
    AVCodecContext  *avctx;
    AVFrame         frame;
    uint8_t         frame_data[MAX_FRAMESIZE + FF_INPUT_BUFFER_PADDING_SIZE];  
    PutBitContext   pb;                             

    
    uint32_t        decode_flags;                   
    int             len_prefix;                     
    int             dynamic_range_compression;      
    uint8_t         bits_per_sample;                
    uint16_t        samples_per_frame;              
    uint16_t        log2_frame_size;
    int8_t          num_channels;                   
    int8_t          lfe_channel;                    
    uint8_t         max_num_subframes;
    uint8_t         subframe_len_bits;              
    uint8_t         max_subframe_len_bit;           
    uint16_t        min_samples_per_subframe;

    
    GetBitContext   pgb;                            
    int             next_packet_start;              
    uint8_t         packet_offset;                  
    uint8_t         packet_sequence_number;         
    int             num_saved_bits;                 
    int             frame_offset;                   
    int             subframe_offset;                
    uint8_t         packet_loss;                    
    uint8_t         packet_done;                    

    
    uint32_t        frame_num;                      
    GetBitContext   gb;                             
    int             buf_bit_size;                   
    int16_t         *samples_16[WMALL_MAX_CHANNELS]; 
    int32_t         *samples_32[WMALL_MAX_CHANNELS]; 
    uint8_t         drc_gain;                       
    int8_t          skip_frame;                     
    int8_t          parsed_all_subframes;           

    
    int16_t         subframe_len;                   
    int8_t          channels_for_cur_subframe;      
    int8_t          channel_indexes_for_cur_subframe[WMALL_MAX_CHANNELS];

    WmallChannelCtx channel[WMALL_MAX_CHANNELS];    

    

    uint8_t do_arith_coding;
    uint8_t do_ac_filter;
    uint8_t do_inter_ch_decorr;
    uint8_t do_mclms;
    uint8_t do_lpc;

    int8_t  acfilter_order;
    int8_t  acfilter_scaling;
    int64_t acfilter_coeffs[16];
    int     acfilter_prevvalues[2][16];

    int8_t  mclms_order;
    int8_t  mclms_scaling;
    int16_t mclms_coeffs[128];
    int16_t mclms_coeffs_cur[4];
    int16_t mclms_prevvalues[WMALL_MAX_CHANNELS * 2 * 32];
    int16_t mclms_updates[WMALL_MAX_CHANNELS * 2 * 32];
    int     mclms_recent;

    int     movave_scaling;
    int     quant_stepsize;

    struct {
        int order;
        int scaling;
        int coefsend;
        int bitsend;
        int16_t coefs[MAX_ORDER];
        int16_t lms_prevvalues[MAX_ORDER * 2];
        int16_t lms_updates[MAX_ORDER * 2];
        int recent;
    } cdlms[2][9];

    int cdlms_ttl[2];

    int bV3RTM;

    int is_channel_coded[2];
    int update_speed[2];

    int transient[2];
    int transient_pos[2];
    int seekable_tile;

    int ave_sum[2];

    int channel_residues[2][WMALL_BLOCK_MAX_SIZE];

    int lpc_coefs[2][40];
    int lpc_order;
    int lpc_scaling;
    int lpc_intbits;

    int channel_coeffs[2][WMALL_BLOCK_MAX_SIZE];
} WmallDecodeCtx;


static av_cold int decode_init(AVCodecContext *avctx)
{
    WmallDecodeCtx *s  = avctx->priv_data;
    uint8_t *edata_ptr = avctx->extradata;
    unsigned int channel_mask;
    int i, log2_max_num_subframes;

    s->avctx = avctx;
    init_put_bits(&s->pb, s->frame_data, MAX_FRAMESIZE);

    if (avctx->extradata_size >= 18) {
        s->decode_flags    = AV_RL16(edata_ptr + 14);
        channel_mask       = AV_RL32(edata_ptr +  2);
        s->bits_per_sample = AV_RL16(edata_ptr);
        if (s->bits_per_sample == 16)
            avctx->sample_fmt = AV_SAMPLE_FMT_S16;
        else if (s->bits_per_sample == 24) {
            avctx->sample_fmt = AV_SAMPLE_FMT_S32;
            av_log_missing_feature(avctx, "bit-depth higher than 16", 0);
            return AVERROR_PATCHWELCOME;
        } else {
            av_log(avctx, AV_LOG_ERROR, "Unknown bit-depth: %d\n", s->bits_per_sample);
            return AVERROR_INVALIDDATA;
        }
        
        for (i = 0; i < avctx->extradata_size; i++)
            av_dlog(avctx, "[%x] ", avctx->extradata[i]);
        av_dlog(avctx, "\n");

    } else {
        av_log_ask_for_sample(avctx, "Unsupported extradata size\n");
        return AVERROR_INVALIDDATA;
    }

    
    s->log2_frame_size = av_log2(avctx->block_align) + 4;

    
    s->skip_frame  = 1; 
    s->packet_loss = 1;
    s->len_prefix  = s->decode_flags & 0x40;

    
    s->samples_per_frame = 1 << ff_wma_get_frame_len_bits(avctx->sample_rate, 3, s->decode_flags);
    av_assert0(s->samples_per_frame <= WMALL_BLOCK_MAX_SIZE);

    
    for (i = 0; i < avctx->channels; i++)
        s->channel[i].prev_block_len = s->samples_per_frame;

    
    log2_max_num_subframes  = (s->decode_flags & 0x38) >> 3;
    s->max_num_subframes    = 1 << log2_max_num_subframes;
    s->max_subframe_len_bit = 0;
    s->subframe_len_bits    = av_log2(log2_max_num_subframes) + 1;

    s->min_samples_per_subframe  = s->samples_per_frame / s->max_num_subframes;
    s->dynamic_range_compression = s->decode_flags & 0x80;
    s->bV3RTM                    = s->decode_flags & 0x100;

    if (s->max_num_subframes > MAX_SUBFRAMES) {
        av_log(avctx, AV_LOG_ERROR, "invalid number of subframes %i\n", s->max_num_subframes);
        return AVERROR_INVALIDDATA;
    }

    s->num_channels = avctx->channels;

    
    s->lfe_channel = -1;

    if (channel_mask & 8) {
        unsigned int mask;
        for (mask = 1; mask < 16; mask <<= 1)
            if (channel_mask & mask)
                ++s->lfe_channel;
    }

    if (s->num_channels < 0) {
        av_log(avctx, AV_LOG_ERROR, "invalid number of channels %d\n", s->num_channels);
        return AVERROR_INVALIDDATA;
    } else if (s->num_channels > WMALL_MAX_CHANNELS) {
        av_log_ask_for_sample(avctx, "unsupported number of channels\n");
        return AVERROR_PATCHWELCOME;
    }

    avcodec_get_frame_defaults(&s->frame);
    avctx->coded_frame    = &s->frame;
    avctx->channel_layout = channel_mask;
    return 0;
}


static int decode_subframe_length(WmallDecodeCtx *s, int offset)
{
    int frame_len_ratio, subframe_len, len;

    
    if (offset == s->samples_per_frame - s->min_samples_per_subframe)
        return s->min_samples_per_subframe;

    len             = av_log2(s->max_num_subframes - 1) + 1;
    frame_len_ratio = get_bits(&s->gb, len);
    subframe_len    = s->min_samples_per_subframe * (frame_len_ratio + 1);

    
    if (subframe_len < s->min_samples_per_subframe || subframe_len > s->samples_per_frame) {
        av_log(s->avctx, AV_LOG_ERROR, "broken frame: subframe_len %i\n", subframe_len);
        return AVERROR_INVALIDDATA;
    }
    return subframe_len;
}


static int decode_tilehdr(WmallDecodeCtx *s)
{
    uint16_t num_samples[WMALL_MAX_CHANNELS] = { 0 }; 
    uint8_t  contains_subframe[WMALL_MAX_CHANNELS];   
    int channels_for_cur_subframe = s->num_channels;  
    int fixed_channel_layout = 0;                     
    int min_channel_len = 0;                          
    int c, tile_aligned;

    
    for (c = 0; c < s->num_channels; c++)
        s->channel[c].num_subframes = 0;

    tile_aligned = get_bits1(&s->gb);
    if (s->max_num_subframes == 1 || tile_aligned)
        fixed_channel_layout = 1;

    
    do {
        int subframe_len, in_use = 0;

        
        for (c = 0; c < s->num_channels; c++) {
            if (num_samples[c] == min_channel_len) {
                if (fixed_channel_layout || channels_for_cur_subframe == 1 || (min_channel_len == s->samples_per_frame - s->min_samples_per_subframe)) {
                    contains_subframe[c] = in_use = 1;
                } else {
                    if (get_bits1(&s->gb))
                        contains_subframe[c] = in_use = 1;
                }
            } else contains_subframe[c] = 0;
        }

        if (!in_use) {
            av_log(s->avctx, AV_LOG_ERROR, "Found empty subframe\n");
            return AVERROR_INVALIDDATA;
        }

        
        if ((subframe_len = decode_subframe_length(s, min_channel_len)) <= 0)
            return AVERROR_INVALIDDATA;
        
        min_channel_len += subframe_len;
        for (c = 0; c < s->num_channels; c++) {
            WmallChannelCtx *chan = &s->channel[c];

            if (contains_subframe[c]) {
                if (chan->num_subframes >= MAX_SUBFRAMES) {
                    av_log(s->avctx, AV_LOG_ERROR, "broken frame: num subframes > 31\n");
                    return AVERROR_INVALIDDATA;
                }
                chan->subframe_len[chan->num_subframes] = subframe_len;
                num_samples[c] += subframe_len;
                ++chan->num_subframes;
                if (num_samples[c] > s->samples_per_frame) {
                    av_log(s->avctx, AV_LOG_ERROR, "broken frame: " "channel len(%d) > samples_per_frame(%d)\n", num_samples[c], s->samples_per_frame);

                    return AVERROR_INVALIDDATA;
                }
            } else if (num_samples[c] <= min_channel_len) {
                if (num_samples[c] < min_channel_len) {
                    channels_for_cur_subframe = 0;
                    min_channel_len = num_samples[c];
                }
                ++channels_for_cur_subframe;
            }
        }
    } while (min_channel_len < s->samples_per_frame);

    for (c = 0; c < s->num_channels; c++) {
        int i, offset = 0;
        for (i = 0; i < s->channel[c].num_subframes; i++) {
            s->channel[c].subframe_offsets[i] = offset;
            offset += s->channel[c].subframe_len[i];
        }
    }

    return 0;
}

static void decode_ac_filter(WmallDecodeCtx *s)
{
    int i;
    s->acfilter_order   = get_bits(&s->gb, 4) + 1;
    s->acfilter_scaling = get_bits(&s->gb, 4);

    for (i = 0; i < s->acfilter_order; i++)
        s->acfilter_coeffs[i] = (s->acfilter_scaling ? get_bits(&s->gb, s->acfilter_scaling) : 0) + 1;
}

static void decode_mclms(WmallDecodeCtx *s)
{
    s->mclms_order   = (get_bits(&s->gb, 4) + 1) * 2;
    s->mclms_scaling = get_bits(&s->gb, 4);
    if (get_bits1(&s->gb)) {
        int i, send_coef_bits;
        int cbits = av_log2(s->mclms_scaling + 1);
        if (1 << cbits < s->mclms_scaling + 1)
            cbits++;

        send_coef_bits = (cbits ? get_bits(&s->gb, cbits) : 0) + 2;

        for (i = 0; i < s->mclms_order * s->num_channels * s->num_channels; i++)
            s->mclms_coeffs[i] = get_bits(&s->gb, send_coef_bits);

        for (i = 0; i < s->num_channels; i++) {
            int c;
            for (c = 0; c < i; c++)
                s->mclms_coeffs_cur[i * s->num_channels + c] = get_bits(&s->gb, send_coef_bits);
        }
    }
}

static int decode_cdlms(WmallDecodeCtx *s)
{
    int c, i;
    int cdlms_send_coef = get_bits1(&s->gb);

    for (c = 0; c < s->num_channels; c++) {
        s->cdlms_ttl[c] = get_bits(&s->gb, 3) + 1;
        for (i = 0; i < s->cdlms_ttl[c]; i++) {
            s->cdlms[c][i].order = (get_bits(&s->gb, 7) + 1) * 8;
            if (s->cdlms[c][i].order > MAX_ORDER) {
                av_log(s->avctx, AV_LOG_ERROR, "Order[%d][%d] %d > max (%d), not supported\n", c, i, s->cdlms[c][i].order, MAX_ORDER);

                s->cdlms[0][0].order = 0;
                return AVERROR_INVALIDDATA;
            }
        }

        for (i = 0; i < s->cdlms_ttl[c]; i++)
            s->cdlms[c][i].scaling = get_bits(&s->gb, 4);

        if (cdlms_send_coef) {
            for (i = 0; i < s->cdlms_ttl[c]; i++) {
                int cbits, shift_l, shift_r, j;
                cbits = av_log2(s->cdlms[c][i].order);
                if ((1 << cbits) < s->cdlms[c][i].order)
                    cbits++;
                s->cdlms[c][i].coefsend = get_bits(&s->gb, cbits) + 1;

                cbits = av_log2(s->cdlms[c][i].scaling + 1);
                if ((1 << cbits) < s->cdlms[c][i].scaling + 1)
                    cbits++;

                s->cdlms[c][i].bitsend = get_bits(&s->gb, cbits) + 2;
                shift_l = 32 - s->cdlms[c][i].bitsend;
                shift_r = 32 - s->cdlms[c][i].scaling - 2;
                for (j = 0; j < s->cdlms[c][i].coefsend; j++)
                    s->cdlms[c][i].coefs[j] = (get_bits(&s->gb, s->cdlms[c][i].bitsend) << shift_l) >> shift_r;
            }
        }
    }

    return 0;
}

static int decode_channel_residues(WmallDecodeCtx *s, int ch, int tile_size)
{
    int i = 0;
    unsigned int ave_mean;
    s->transient[ch] = get_bits1(&s->gb);
    if (s->transient[ch]) {
        s->transient_pos[ch] = get_bits(&s->gb, av_log2(tile_size));
        if (s->transient_pos[ch])
            s->transient[ch] = 0;
        s->channel[ch].transient_counter = FFMAX(s->channel[ch].transient_counter, s->samples_per_frame / 2);
    } else if (s->channel[ch].transient_counter)
        s->transient[ch] = 1;

    if (s->seekable_tile) {
        ave_mean = get_bits(&s->gb, s->bits_per_sample);
        s->ave_sum[ch] = ave_mean << (s->movave_scaling + 1);
    }

    if (s->seekable_tile) {
        if (s->do_inter_ch_decorr)
            s->channel_residues[ch][0] = get_sbits(&s->gb, s->bits_per_sample + 1);
        else s->channel_residues[ch][0] = get_sbits(&s->gb, s->bits_per_sample);
        i++;
    }
    for (; i < tile_size; i++) {
        int quo = 0, rem, rem_bits, residue;
        while(get_bits1(&s->gb)) {
            quo++;
            if (get_bits_left(&s->gb) <= 0)
                return -1;
        }
        if (quo >= 32)
            quo += get_bits_long(&s->gb, get_bits(&s->gb, 5) + 1);

        ave_mean = (s->ave_sum[ch] + (1 << s->movave_scaling)) >> (s->movave_scaling + 1);
        if (ave_mean <= 1)
            residue = quo;
        else {
            rem_bits = av_ceil_log2(ave_mean);
            rem      = rem_bits ? get_bits_long(&s->gb, rem_bits) : 0;
            residue  = (quo << rem_bits) + rem;
        }

        s->ave_sum[ch] = residue + s->ave_sum[ch] - (s->ave_sum[ch] >> s->movave_scaling);

        if (residue & 1)
            residue = -(residue >> 1) - 1;
        else residue = residue >> 1;
        s->channel_residues[ch][i] = residue;
    }

    return 0;

}

static void decode_lpc(WmallDecodeCtx *s)
{
    int ch, i, cbits;
    s->lpc_order   = get_bits(&s->gb, 5) + 1;
    s->lpc_scaling = get_bits(&s->gb, 4);
    s->lpc_intbits = get_bits(&s->gb, 3) + 1;
    cbits = s->lpc_scaling + s->lpc_intbits;
    for (ch = 0; ch < s->num_channels; ch++)
        for (i = 0; i < s->lpc_order; i++)
            s->lpc_coefs[ch][i] = get_sbits(&s->gb, cbits);
}

static void clear_codec_buffers(WmallDecodeCtx *s)
{
    int ich, ilms;

    memset(s->acfilter_coeffs,     0, sizeof(s->acfilter_coeffs));
    memset(s->acfilter_prevvalues, 0, sizeof(s->acfilter_prevvalues));
    memset(s->lpc_coefs,           0, sizeof(s->lpc_coefs));

    memset(s->mclms_coeffs,     0, sizeof(s->mclms_coeffs));
    memset(s->mclms_coeffs_cur, 0, sizeof(s->mclms_coeffs_cur));
    memset(s->mclms_prevvalues, 0, sizeof(s->mclms_prevvalues));
    memset(s->mclms_updates,    0, sizeof(s->mclms_updates));

    for (ich = 0; ich < s->num_channels; ich++) {
        for (ilms = 0; ilms < s->cdlms_ttl[ich]; ilms++) {
            memset(s->cdlms[ich][ilms].coefs, 0, sizeof(s->cdlms[ich][ilms].coefs));
            memset(s->cdlms[ich][ilms].lms_prevvalues, 0, sizeof(s->cdlms[ich][ilms].lms_prevvalues));
            memset(s->cdlms[ich][ilms].lms_updates, 0, sizeof(s->cdlms[ich][ilms].lms_updates));
        }
        s->ave_sum[ich] = 0;
    }
}


static void reset_codec(WmallDecodeCtx *s)
{
    int ich, ilms;
    s->mclms_recent = s->mclms_order * s->num_channels;
    for (ich = 0; ich < s->num_channels; ich++) {
        for (ilms = 0; ilms < s->cdlms_ttl[ich]; ilms++)
            s->cdlms[ich][ilms].recent = s->cdlms[ich][ilms].order;
        
        s->channel[ich].transient_counter = s->samples_per_frame;
        s->transient[ich]     = 1;
        s->transient_pos[ich] = 0;
    }
}

static void mclms_update(WmallDecodeCtx *s, int icoef, int *pred)
{
    int i, j, ich, pred_error;
    int order        = s->mclms_order;
    int num_channels = s->num_channels;
    int range        = 1 << (s->bits_per_sample - 1);

    for (ich = 0; ich < num_channels; ich++) {
        pred_error = s->channel_residues[ich][icoef] - pred[ich];
        if (pred_error > 0) {
            for (i = 0; i < order * num_channels; i++)
                s->mclms_coeffs[i + ich * order * num_channels] += s->mclms_updates[s->mclms_recent + i];
            for (j = 0; j < ich; j++) {
                if (s->channel_residues[j][icoef] > 0)
                    s->mclms_coeffs_cur[ich * num_channels + j] += 1;
                else if (s->channel_residues[j][icoef] < 0)
                    s->mclms_coeffs_cur[ich * num_channels + j] -= 1;
            }
        } else if (pred_error < 0) {
            for (i = 0; i < order * num_channels; i++)
                s->mclms_coeffs[i + ich * order * num_channels] -= s->mclms_updates[s->mclms_recent + i];
            for (j = 0; j < ich; j++) {
                if (s->channel_residues[j][icoef] > 0)
                    s->mclms_coeffs_cur[ich * num_channels + j] -= 1;
                else if (s->channel_residues[j][icoef] < 0)
                    s->mclms_coeffs_cur[ich * num_channels + j] += 1;
            }
        }
    }

    for (ich = num_channels - 1; ich >= 0; ich--) {
        s->mclms_recent--;
        s->mclms_prevvalues[s->mclms_recent] = s->channel_residues[ich][icoef];
        if (s->channel_residues[ich][icoef] > range - 1)
            s->mclms_prevvalues[s->mclms_recent] = range - 1;
        else if (s->channel_residues[ich][icoef] < -range)
            s->mclms_prevvalues[s->mclms_recent] = -range;

        s->mclms_updates[s->mclms_recent] = 0;
        if (s->channel_residues[ich][icoef] > 0)
            s->mclms_updates[s->mclms_recent] = 1;
        else if (s->channel_residues[ich][icoef] < 0)
            s->mclms_updates[s->mclms_recent] = -1;
    }

    if (s->mclms_recent == 0) {
        memcpy(&s->mclms_prevvalues[order * num_channels], s->mclms_prevvalues, 2 * order * num_channels);

        memcpy(&s->mclms_updates[order * num_channels], s->mclms_updates, 2 * order * num_channels);

        s->mclms_recent = num_channels * order;
    }
}

static void mclms_predict(WmallDecodeCtx *s, int icoef, int *pred)
{
    int ich, i;
    int order        = s->mclms_order;
    int num_channels = s->num_channels;

    for (ich = 0; ich < num_channels; ich++) {
        pred[ich] = 0;
        if (!s->is_channel_coded[ich])
            continue;
        for (i = 0; i < order * num_channels; i++)
            pred[ich] += s->mclms_prevvalues[i + s->mclms_recent] * s->mclms_coeffs[i + order * num_channels * ich];
        for (i = 0; i < ich; i++)
            pred[ich] += s->channel_residues[i][icoef] * s->mclms_coeffs_cur[i + num_channels * ich];
        pred[ich] += 1 << s->mclms_scaling - 1;
        pred[ich] >>= s->mclms_scaling;
        s->channel_residues[ich][icoef] += pred[ich];
    }
}

static void revert_mclms(WmallDecodeCtx *s, int tile_size)
{
    int icoef, pred[WMALL_MAX_CHANNELS] = { 0 };
    for (icoef = 0; icoef < tile_size; icoef++) {
        mclms_predict(s, icoef, pred);
        mclms_update(s, icoef, pred);
    }
}

static int lms_predict(WmallDecodeCtx *s, int ich, int ilms)
{
    int pred = 0, icoef;
    int recent = s->cdlms[ich][ilms].recent;

    for (icoef = 0; icoef < s->cdlms[ich][ilms].order; icoef++)
        pred += s->cdlms[ich][ilms].coefs[icoef] * s->cdlms[ich][ilms].lms_prevvalues[icoef + recent];

    return pred;
}

static void lms_update(WmallDecodeCtx *s, int ich, int ilms, int input, int residue)
{
    int icoef;
    int recent = s->cdlms[ich][ilms].recent;
    int range  = 1 << s->bits_per_sample - 1;

    if (residue < 0) {
        for (icoef = 0; icoef < s->cdlms[ich][ilms].order; icoef++)
            s->cdlms[ich][ilms].coefs[icoef] -= s->cdlms[ich][ilms].lms_updates[icoef + recent];
    } else if (residue > 0) {
        for (icoef = 0; icoef < s->cdlms[ich][ilms].order; icoef++)
            s->cdlms[ich][ilms].coefs[icoef] += s->cdlms[ich][ilms].lms_updates[icoef + recent];
    }

    if (recent)
        recent--;
    else {
        memcpy(&s->cdlms[ich][ilms].lms_prevvalues[s->cdlms[ich][ilms].order], s->cdlms[ich][ilms].lms_prevvalues, 2 * s->cdlms[ich][ilms].order);

        memcpy(&s->cdlms[ich][ilms].lms_updates[s->cdlms[ich][ilms].order], s->cdlms[ich][ilms].lms_updates, 2 * s->cdlms[ich][ilms].order);

        recent = s->cdlms[ich][ilms].order - 1;
    }

    s->cdlms[ich][ilms].lms_prevvalues[recent] = av_clip(input, -range, range - 1);
    if (!input)
        s->cdlms[ich][ilms].lms_updates[recent] = 0;
    else if (input < 0)
        s->cdlms[ich][ilms].lms_updates[recent] = -s->update_speed[ich];
    else s->cdlms[ich][ilms].lms_updates[recent] = s->update_speed[ich];

    s->cdlms[ich][ilms].lms_updates[recent + (s->cdlms[ich][ilms].order >> 4)] >>= 2;
    s->cdlms[ich][ilms].lms_updates[recent + (s->cdlms[ich][ilms].order >> 3)] >>= 1;
    s->cdlms[ich][ilms].recent = recent;
}

static void use_high_update_speed(WmallDecodeCtx *s, int ich)
{
    int ilms, recent, icoef;
    for (ilms = s->cdlms_ttl[ich] - 1; ilms >= 0; ilms--) {
        recent = s->cdlms[ich][ilms].recent;
        if (s->update_speed[ich] == 16)
            continue;
        if (s->bV3RTM) {
            for (icoef = 0; icoef < s->cdlms[ich][ilms].order; icoef++)
                s->cdlms[ich][ilms].lms_updates[icoef + recent] *= 2;
        } else {
            for (icoef = 0; icoef < s->cdlms[ich][ilms].order; icoef++)
                s->cdlms[ich][ilms].lms_updates[icoef] *= 2;
        }
    }
    s->update_speed[ich] = 16;
}

static void use_normal_update_speed(WmallDecodeCtx *s, int ich)
{
    int ilms, recent, icoef;
    for (ilms = s->cdlms_ttl[ich] - 1; ilms >= 0; ilms--) {
        recent = s->cdlms[ich][ilms].recent;
        if (s->update_speed[ich] == 8)
            continue;
        if (s->bV3RTM)
            for (icoef = 0; icoef < s->cdlms[ich][ilms].order; icoef++)
                s->cdlms[ich][ilms].lms_updates[icoef + recent] /= 2;
        else for (icoef = 0; icoef < s->cdlms[ich][ilms].order; icoef++)
                s->cdlms[ich][ilms].lms_updates[icoef] /= 2;
    }
    s->update_speed[ich] = 8;
}

static void revert_cdlms(WmallDecodeCtx *s, int ch, int coef_begin, int coef_end)
{
    int icoef, pred, ilms, num_lms, residue, input;

    num_lms = s->cdlms_ttl[ch];
    for (ilms = num_lms - 1; ilms >= 0; ilms--) {
        for (icoef = coef_begin; icoef < coef_end; icoef++) {
            pred = 1 << (s->cdlms[ch][ilms].scaling - 1);
            residue = s->channel_residues[ch][icoef];
            pred += lms_predict(s, ch, ilms);
            input = residue + (pred >> s->cdlms[ch][ilms].scaling);
            lms_update(s, ch, ilms, input, residue);
            s->channel_residues[ch][icoef] = input;
        }
    }
}

static void revert_inter_ch_decorr(WmallDecodeCtx *s, int tile_size)
{
    if (s->num_channels != 2)
        return;
    else if (s->is_channel_coded[0] || s->is_channel_coded[1]) {
        int icoef;
        for (icoef = 0; icoef < tile_size; icoef++) {
            s->channel_residues[0][icoef] -= s->channel_residues[1][icoef] >> 1;
            s->channel_residues[1][icoef] += s->channel_residues[0][icoef];
        }
    }
}

static void revert_acfilter(WmallDecodeCtx *s, int tile_size)
{
    int ich, pred, i, j;
    int64_t *filter_coeffs = s->acfilter_coeffs;
    int scaling            = s->acfilter_scaling;
    int order              = s->acfilter_order;

    for (ich = 0; ich < s->num_channels; ich++) {
        int *prevvalues = s->acfilter_prevvalues[ich];
        for (i = 0; i < order; i++) {
            pred = 0;
            for (j = 0; j < order; j++) {
                if (i <= j)
                    pred += filter_coeffs[j] * prevvalues[j - i];
                else pred += s->channel_residues[ich][i - j - 1] * filter_coeffs[j];
            }
            pred >>= scaling;
            s->channel_residues[ich][i] += pred;
        }
        for (i = order; i < tile_size; i++) {
            pred = 0;
            for (j = 0; j < order; j++)
                pred += s->channel_residues[ich][i - j - 1] * filter_coeffs[j];
            pred >>= scaling;
            s->channel_residues[ich][i] += pred;
        }
        for (j = 0; j < order; j++)
            prevvalues[j] = s->channel_residues[ich][tile_size - j - 1];
    }
}

static int decode_subframe(WmallDecodeCtx *s)
{
    int offset        = s->samples_per_frame;
    int subframe_len  = s->samples_per_frame;
    int total_samples = s->samples_per_frame * s->num_channels;
    int i, j, rawpcm_tile, padding_zeroes, res;

    s->subframe_offset = get_bits_count(&s->gb);

    
    for (i = 0; i < s->num_channels; i++) {
        if (offset > s->channel[i].decoded_samples) {
            offset = s->channel[i].decoded_samples;
            subframe_len = s->channel[i].subframe_len[s->channel[i].cur_subframe];
        }
    }

    
    s->channels_for_cur_subframe = 0;
    for (i = 0; i < s->num_channels; i++) {
        const int cur_subframe = s->channel[i].cur_subframe;
        
        total_samples -= s->channel[i].decoded_samples;

        
        if (offset == s->channel[i].decoded_samples && subframe_len == s->channel[i].subframe_len[cur_subframe]) {
            total_samples -= s->channel[i].subframe_len[cur_subframe];
            s->channel[i].decoded_samples += s->channel[i].subframe_len[cur_subframe];
            s->channel_indexes_for_cur_subframe[s->channels_for_cur_subframe] = i;
            ++s->channels_for_cur_subframe;
        }
    }

    
    if (!total_samples)
        s->parsed_all_subframes = 1;


    s->seekable_tile = get_bits1(&s->gb);
    if (s->seekable_tile) {
        clear_codec_buffers(s);

        s->do_arith_coding    = get_bits1(&s->gb);
        if (s->do_arith_coding) {
            av_log_missing_feature(s->avctx, "arithmetic coding", 1);
            return AVERROR_PATCHWELCOME;
        }
        s->do_ac_filter       = get_bits1(&s->gb);
        s->do_inter_ch_decorr = get_bits1(&s->gb);
        s->do_mclms           = get_bits1(&s->gb);

        if (s->do_ac_filter)
            decode_ac_filter(s);

        if (s->do_mclms)
            decode_mclms(s);

        if ((res = decode_cdlms(s)) < 0)
            return res;
        s->movave_scaling = get_bits(&s->gb, 3);
        s->quant_stepsize = get_bits(&s->gb, 8) + 1;

        reset_codec(s);
    } else if (!s->cdlms[0][0].order) {
        av_log(s->avctx, AV_LOG_DEBUG, "Waiting for seekable tile\n");
        s->frame.nb_samples = 0;
        return -1;
    }

    rawpcm_tile = get_bits1(&s->gb);

    for (i = 0; i < s->num_channels; i++)
        s->is_channel_coded[i] = 1;

    if (!rawpcm_tile) {
        for (i = 0; i < s->num_channels; i++)
            s->is_channel_coded[i] = get_bits1(&s->gb);

        if (s->bV3RTM) {
            
            s->do_lpc = get_bits1(&s->gb);
            if (s->do_lpc) {
                decode_lpc(s);
                av_log_ask_for_sample(s->avctx, "Inverse LPC filter not " "implemented. Expect wrong output.\n");
            }
        } else s->do_lpc = 0;
    }


    if (get_bits1(&s->gb))
        padding_zeroes = get_bits(&s->gb, 5);
    else padding_zeroes = 0;

    if (rawpcm_tile) {
        int bits = s->bits_per_sample - padding_zeroes;
        if (bits <= 0) {
            av_log(s->avctx, AV_LOG_ERROR, "Invalid number of padding bits in raw PCM tile\n");
            return AVERROR_INVALIDDATA;
        }
        av_dlog(s->avctx, "RAWPCM %d bits per sample. " "total %d bits, remain=%d\n", bits, bits * s->num_channels * subframe_len, get_bits_count(&s->gb));

        for (i = 0; i < s->num_channels; i++)
            for (j = 0; j < subframe_len; j++)
                s->channel_coeffs[i][j] = get_sbits(&s->gb, bits);
    } else {
        for (i = 0; i < s->num_channels; i++)
            if (s->is_channel_coded[i]) {
                decode_channel_residues(s, i, subframe_len);
                if (s->seekable_tile)
                    use_high_update_speed(s, i);
                else use_normal_update_speed(s, i);
                revert_cdlms(s, i, 0, subframe_len);
            } else {
                memset(s->channel_residues[i], 0, sizeof(**s->channel_residues) * subframe_len);
            }
    }
    if (s->do_mclms)
        revert_mclms(s, subframe_len);
    if (s->do_inter_ch_decorr)
        revert_inter_ch_decorr(s, subframe_len);
    if (s->do_ac_filter)
        revert_acfilter(s, subframe_len);

    
    if (s->quant_stepsize != 1)
        for (i = 0; i < s->num_channels; i++)
            for (j = 0; j < subframe_len; j++)
                s->channel_residues[i][j] *= s->quant_stepsize;

    
    for (i = 0; i < s->channels_for_cur_subframe; i++) {
        int c = s->channel_indexes_for_cur_subframe[i];
        int subframe_len = s->channel[c].subframe_len[s->channel[c].cur_subframe];

        for (j = 0; j < subframe_len; j++) {
            if (s->bits_per_sample == 16) {
                *s->samples_16[c] = (int16_t) s->channel_residues[c][j] << padding_zeroes;
                s->samples_16[c] += s->num_channels;
            } else {
                *s->samples_32[c] = s->channel_residues[c][j] << padding_zeroes;
                s->samples_32[c] += s->num_channels;
            }
        }
    }

    
    for (i = 0; i < s->channels_for_cur_subframe; i++) {
        int c = s->channel_indexes_for_cur_subframe[i];
        if (s->channel[c].cur_subframe >= s->channel[c].num_subframes) {
            av_log(s->avctx, AV_LOG_ERROR, "broken subframe\n");
            return AVERROR_INVALIDDATA;
        }
        ++s->channel[c].cur_subframe;
    }
    return 0;
}


static int decode_frame(WmallDecodeCtx *s)
{
    GetBitContext* gb = &s->gb;
    int more_frames = 0, len = 0, i, ret;

    s->frame.nb_samples = s->samples_per_frame;
    if ((ret = s->avctx->get_buffer(s->avctx, &s->frame)) < 0) {
        
        av_log(s->avctx, AV_LOG_ERROR, "not enough space for the output samples\n");
        s->packet_loss = 1;
        return ret;
    }
    for (i = 0; i < s->num_channels; i++) {
        s->samples_16[i] = (int16_t *)s->frame.data[0] + i;
        s->samples_32[i] = (int32_t *)s->frame.data[0] + i;
    }

    
    if (s->len_prefix)
        len = get_bits(gb, s->log2_frame_size);

    
    if (decode_tilehdr(s)) {
        s->packet_loss = 1;
        return 0;
    }

    
    if (s->dynamic_range_compression)
        s->drc_gain = get_bits(gb, 8);

    
    if (get_bits1(gb)) {
        int av_unused skip;

        
        if (get_bits1(gb)) {
            skip = get_bits(gb, av_log2(s->samples_per_frame * 2));
            av_dlog(s->avctx, "start skip: %i\n", skip);
        }

        
        if (get_bits1(gb)) {
            skip = get_bits(gb, av_log2(s->samples_per_frame * 2));
            av_dlog(s->avctx, "end skip: %i\n", skip);
        }

    }

    
    s->parsed_all_subframes = 0;
    for (i = 0; i < s->num_channels; i++) {
        s->channel[i].decoded_samples = 0;
        s->channel[i].cur_subframe    = 0;
    }

    
    while (!s->parsed_all_subframes) {
        if (decode_subframe(s) < 0) {
            s->packet_loss = 1;
            return 0;
        }
    }

    av_dlog(s->avctx, "Frame done\n");

    if (s->skip_frame)
        s->skip_frame = 0;

    if (s->len_prefix) {
        if (len != (get_bits_count(gb) - s->frame_offset) + 2) {
            
            av_log(s->avctx, AV_LOG_ERROR, "frame[%i] would have to skip %i bits\n", s->frame_num, len - (get_bits_count(gb) - s->frame_offset) - 1);

            s->packet_loss = 1;
            return 0;
        }

        
        skip_bits_long(gb, len - (get_bits_count(gb) - s->frame_offset) - 1);
    }

    
    more_frames = get_bits1(gb);
    ++s->frame_num;
    return more_frames;
}


static int remaining_bits(WmallDecodeCtx *s, GetBitContext *gb)
{
    return s->buf_bit_size - get_bits_count(gb);
}


static void save_bits(WmallDecodeCtx *s, GetBitContext* gb, int len, int append)
{
    int buflen;
    PutBitContext tmp;

    

    if (!append) {
        s->frame_offset   = get_bits_count(gb) & 7;
        s->num_saved_bits = s->frame_offset;
        init_put_bits(&s->pb, s->frame_data, MAX_FRAMESIZE);
    }

    buflen = (s->num_saved_bits + len + 8) >> 3;

    if (len <= 0 || buflen > MAX_FRAMESIZE) {
        av_log_ask_for_sample(s->avctx, "input buffer too small\n");
        s->packet_loss = 1;
        return;
    }

    s->num_saved_bits += len;
    if (!append) {
        avpriv_copy_bits(&s->pb, gb->buffer + (get_bits_count(gb) >> 3), s->num_saved_bits);
    } else {
        int align = 8 - (get_bits_count(gb) & 7);
        align = FFMIN(align, len);
        put_bits(&s->pb, align, get_bits(gb, align));
        len -= align;
        avpriv_copy_bits(&s->pb, gb->buffer + (get_bits_count(gb) >> 3), len);
    }
    skip_bits_long(gb, len);

    tmp = s->pb;
    flush_put_bits(&tmp);

    init_get_bits(&s->gb, s->frame_data, s->num_saved_bits);
    skip_bits(&s->gb, s->frame_offset);
}

static int decode_packet(AVCodecContext *avctx, void *data, int *got_frame_ptr, AVPacket* avpkt)
{
    WmallDecodeCtx *s = avctx->priv_data;
    GetBitContext* gb  = &s->pgb;
    const uint8_t* buf = avpkt->data;
    int buf_size       = avpkt->size;
    int num_bits_prev_frame, packet_sequence_number, spliced_packet;

    s->frame.nb_samples = 0;

    if (s->packet_done || s->packet_loss) {
        s->packet_done = 0;

        
        if (buf_size < avctx->block_align)
            return 0;

        s->next_packet_start = buf_size - avctx->block_align;
        buf_size             = avctx->block_align;
        s->buf_bit_size      = buf_size << 3;

        
        init_get_bits(gb, buf, s->buf_bit_size);
        packet_sequence_number = get_bits(gb, 4);
        skip_bits(gb, 1);   
        spliced_packet = get_bits1(gb);
        if (spliced_packet)
            av_log_missing_feature(avctx, "Bitstream splicing", 1);

        
        num_bits_prev_frame = get_bits(gb, s->log2_frame_size);

        
        if (!s->packet_loss && ((s->packet_sequence_number + 1) & 0xF) != packet_sequence_number) {
            s->packet_loss = 1;
            av_log(avctx, AV_LOG_ERROR, "Packet loss detected! seq %x vs %x\n", s->packet_sequence_number, packet_sequence_number);
        }
        s->packet_sequence_number = packet_sequence_number;

        if (num_bits_prev_frame > 0) {
            int remaining_packet_bits = s->buf_bit_size - get_bits_count(gb);
            if (num_bits_prev_frame >= remaining_packet_bits) {
                num_bits_prev_frame = remaining_packet_bits;
                s->packet_done = 1;
            }

            
            save_bits(s, gb, num_bits_prev_frame, 1);

            
            if (num_bits_prev_frame < remaining_packet_bits && !s->packet_loss)
                decode_frame(s);
        } else if (s->num_saved_bits - s->frame_offset) {
            av_dlog(avctx, "ignoring %x previously saved bits\n", s->num_saved_bits - s->frame_offset);
        }

        if (s->packet_loss) {
            
            s->num_saved_bits = 0;
            s->packet_loss    = 0;
        }

    } else {
        int frame_size;

        s->buf_bit_size = (avpkt->size - s->next_packet_start) << 3;
        init_get_bits(gb, avpkt->data, s->buf_bit_size);
        skip_bits(gb, s->packet_offset);

        if (s->len_prefix && remaining_bits(s, gb) > s->log2_frame_size && (frame_size = show_bits(gb, s->log2_frame_size)) && frame_size <= remaining_bits(s, gb)) {

            save_bits(s, gb, frame_size, 0);
            s->packet_done = !decode_frame(s);
        } else if (!s->len_prefix && s->num_saved_bits > get_bits_count(&s->gb)) {
            
            s->packet_done = !decode_frame(s);
        } else {
            s->packet_done = 1;
        }
    }

    if (s->packet_done && !s->packet_loss && remaining_bits(s, gb) > 0) {
        
        save_bits(s, gb, remaining_bits(s, gb), 0);
    }

    *(AVFrame *)data = s->frame;
    *got_frame_ptr   = s->frame.nb_samples > 0;
    s->packet_offset = get_bits_count(gb) & 7;

    return (s->packet_loss) ? AVERROR_INVALIDDATA : get_bits_count(gb) >> 3;
}

static void flush(AVCodecContext *avctx)
{
    WmallDecodeCtx *s    = avctx->priv_data;
    s->packet_loss       = 1;
    s->packet_done       = 0;
    s->num_saved_bits    = 0;
    s->frame_offset      = 0;
    s->next_packet_start = 0;
    s->cdlms[0][0].order = 0;
    s->frame.nb_samples  = 0;
}

AVCodec ff_wmalossless_decoder = {
    .name           = "wmalossless", .type           = AVMEDIA_TYPE_AUDIO, .id             = AV_CODEC_ID_WMALOSSLESS, .priv_data_size = sizeof(WmallDecodeCtx), .init           = decode_init, .decode         = decode_packet, .flush          = flush, .capabilities   = CODEC_CAP_SUBFRAMES | CODEC_CAP_DR1 | CODEC_CAP_DELAY, .long_name      = NULL_IF_CONFIG_SMALL("Windows Media Audio Lossless"), };








