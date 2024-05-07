




















typedef struct Vp3Fragment {
    int16_t dc;
    uint8_t coding_method;
    uint8_t qpi;
} Vp3Fragment;
























static const int ModeAlphabet[6][CODING_MODE_COUNT] = {
    
    {    MODE_INTER_LAST_MV,    MODE_INTER_PRIOR_LAST, MODE_INTER_PLUS_MV,    MODE_INTER_NO_MV, MODE_INTRA,            MODE_USING_GOLDEN, MODE_GOLDEN_MV,        MODE_INTER_FOURMV },   {    MODE_INTER_LAST_MV,    MODE_INTER_PRIOR_LAST, MODE_INTER_NO_MV,      MODE_INTER_PLUS_MV, MODE_INTRA,            MODE_USING_GOLDEN, MODE_GOLDEN_MV,        MODE_INTER_FOURMV },   {    MODE_INTER_LAST_MV,    MODE_INTER_PLUS_MV, MODE_INTER_PRIOR_LAST, MODE_INTER_NO_MV, MODE_INTRA,            MODE_USING_GOLDEN, MODE_GOLDEN_MV,        MODE_INTER_FOURMV },   {    MODE_INTER_LAST_MV,    MODE_INTER_PLUS_MV, MODE_INTER_NO_MV,      MODE_INTER_PRIOR_LAST, MODE_INTRA,            MODE_USING_GOLDEN, MODE_GOLDEN_MV,        MODE_INTER_FOURMV },   {    MODE_INTER_NO_MV,      MODE_INTER_LAST_MV, MODE_INTER_PRIOR_LAST, MODE_INTER_PLUS_MV, MODE_INTRA,            MODE_USING_GOLDEN, MODE_GOLDEN_MV,        MODE_INTER_FOURMV },   {    MODE_INTER_NO_MV,      MODE_USING_GOLDEN, MODE_INTER_LAST_MV,    MODE_INTER_PRIOR_LAST, MODE_INTER_PLUS_MV,    MODE_INTRA, MODE_GOLDEN_MV,        MODE_INTER_FOURMV },  };



































static const uint8_t hilbert_offset[16][2] = {
    {0,0}, {1,0}, {1,1}, {0,1}, {0,2}, {0,3}, {1,3}, {1,2}, {2,2}, {2,3}, {3,3}, {3,2}, {3,1}, {2,1}, {2,0}, {3,0}


};



typedef struct Vp3DecodeContext {
    AVCodecContext *avctx;
    int theora, theora_tables;
    int version;
    int width, height;
    int chroma_x_shift, chroma_y_shift;
    AVFrame golden_frame;
    AVFrame last_frame;
    AVFrame current_frame;
    int keyframe;
    DSPContext dsp;
    int flipped_image;
    int last_slice_end;
    int skip_loop_filter;

    int qps[3];
    int nqps;
    int last_qps[3];

    int superblock_count;
    int y_superblock_width;
    int y_superblock_height;
    int y_superblock_count;
    int c_superblock_width;
    int c_superblock_height;
    int c_superblock_count;
    int u_superblock_start;
    int v_superblock_start;
    unsigned char *superblock_coding;

    int macroblock_count;
    int macroblock_width;
    int macroblock_height;

    int fragment_count;
    int fragment_width[2];
    int fragment_height[2];

    Vp3Fragment *all_fragments;
    int fragment_start[3];
    int data_offset[3];

    int8_t (*motion_val[2])[2];

    ScanTable scantable;

    
    uint16_t coded_dc_scale_factor[64];
    uint32_t coded_ac_scale_factor[64];
    uint8_t base_matrix[384][64];
    uint8_t qr_count[2][3];
    uint8_t qr_size [2][3][64];
    uint16_t qr_base[2][3][64];

    
    int16_t *dct_tokens[3][64];
    int16_t *dct_tokens_base;




    
    int num_coded_frags[3][64];
    int total_num_coded_frags;

    
    int *coded_fragment_list[3];

    VLC dc_vlc[16];
    VLC ac_vlc_1[16];
    VLC ac_vlc_2[16];
    VLC ac_vlc_3[16];
    VLC ac_vlc_4[16];

    VLC superblock_run_length_vlc;
    VLC fragment_run_length_vlc;
    VLC mode_code_vlc;
    VLC motion_vector_vlc;

    
    DECLARE_ALIGNED(16, int16_t, qmat)[3][2][3][64];     

    
    int *superblock_fragments;

    
    unsigned char *macroblock_coding;

    uint8_t *edge_emu_buffer;

    
    int hti;
    unsigned int hbits;
    int entries;
    int huff_code_size;
    uint32_t huffman_table[80][32][2];

    uint8_t filter_limit_values[64];
    DECLARE_ALIGNED(8, int, bounding_values_array)[256+2];
} Vp3DecodeContext;



static void vp3_decode_flush(AVCodecContext *avctx)
{
    Vp3DecodeContext *s = avctx->priv_data;

    if (s->golden_frame.data[0]) {
        if (s->golden_frame.data[0] == s->last_frame.data[0])
            memset(&s->last_frame, 0, sizeof(AVFrame));
        if (s->current_frame.data[0] == s->golden_frame.data[0])
            memset(&s->current_frame, 0, sizeof(AVFrame));
        ff_thread_release_buffer(avctx, &s->golden_frame);
    }
    if (s->last_frame.data[0]) {
        if (s->current_frame.data[0] == s->last_frame.data[0])
            memset(&s->current_frame, 0, sizeof(AVFrame));
        ff_thread_release_buffer(avctx, &s->last_frame);
    }
    if (s->current_frame.data[0])
        ff_thread_release_buffer(avctx, &s->current_frame);
}

static av_cold int vp3_decode_end(AVCodecContext *avctx)
{
    Vp3DecodeContext *s = avctx->priv_data;
    int i;

    av_free(s->superblock_coding);
    av_free(s->all_fragments);
    av_free(s->coded_fragment_list[0]);
    av_free(s->dct_tokens_base);
    av_free(s->superblock_fragments);
    av_free(s->macroblock_coding);
    av_free(s->motion_val[0]);
    av_free(s->motion_val[1]);
    av_free(s->edge_emu_buffer);

    if (avctx->internal->is_copy)
        return 0;

    for (i = 0; i < 16; i++) {
        free_vlc(&s->dc_vlc[i]);
        free_vlc(&s->ac_vlc_1[i]);
        free_vlc(&s->ac_vlc_2[i]);
        free_vlc(&s->ac_vlc_3[i]);
        free_vlc(&s->ac_vlc_4[i]);
    }

    free_vlc(&s->superblock_run_length_vlc);
    free_vlc(&s->fragment_run_length_vlc);
    free_vlc(&s->mode_code_vlc);
    free_vlc(&s->motion_vector_vlc);

    
    vp3_decode_flush(avctx);

    return 0;
}


static int init_block_mapping(Vp3DecodeContext *s)
{
    int sb_x, sb_y, plane;
    int x, y, i, j = 0;

    for (plane = 0; plane < 3; plane++) {
        int sb_width    = plane ? s->c_superblock_width  : s->y_superblock_width;
        int sb_height   = plane ? s->c_superblock_height : s->y_superblock_height;
        int frag_width  = s->fragment_width[!!plane];
        int frag_height = s->fragment_height[!!plane];

        for (sb_y = 0; sb_y < sb_height; sb_y++)
            for (sb_x = 0; sb_x < sb_width; sb_x++)
                for (i = 0; i < 16; i++) {
                    x = 4*sb_x + hilbert_offset[i][0];
                    y = 4*sb_y + hilbert_offset[i][1];

                    if (x < frag_width && y < frag_height)
                        s->superblock_fragments[j++] = s->fragment_start[plane] + y*frag_width + x;
                    else s->superblock_fragments[j++] = -1;
                }
    }

    return 0;  
}


static void init_dequantizer(Vp3DecodeContext *s, int qpi)
{
    int ac_scale_factor = s->coded_ac_scale_factor[s->qps[qpi]];
    int dc_scale_factor = s->coded_dc_scale_factor[s->qps[qpi]];
    int i, plane, inter, qri, bmi, bmj, qistart;

    for(inter=0; inter<2; inter++){
        for(plane=0; plane<3; plane++){
            int sum=0;
            for(qri=0; qri<s->qr_count[inter][plane]; qri++){
                sum+= s->qr_size[inter][plane][qri];
                if(s->qps[qpi] <= sum)
                    break;
            }
            qistart= sum - s->qr_size[inter][plane][qri];
            bmi= s->qr_base[inter][plane][qri  ];
            bmj= s->qr_base[inter][plane][qri+1];
            for(i=0; i<64; i++){
                int coeff= (  2*(sum    -s->qps[qpi])*s->base_matrix[bmi][i] - 2*(qistart-s->qps[qpi])*s->base_matrix[bmj][i] + s->qr_size[inter][plane][qri])

                           / (2*s->qr_size[inter][plane][qri]);

                int qmin= 8<<(inter + !i);
                int qscale= i ? ac_scale_factor : dc_scale_factor;

                s->qmat[qpi][inter][plane][s->dsp.idct_permutation[i]]= av_clip((qscale * coeff)/100 * 4, qmin, 4096);
            }
            
            s->qmat[qpi][inter][plane][0] = s->qmat[0][inter][plane][0];
        }
    }
}


static void init_loop_filter(Vp3DecodeContext *s)
{
    int *bounding_values= s->bounding_values_array+127;
    int filter_limit;
    int x;
    int value;

    filter_limit = s->filter_limit_values[s->qps[0]];

    
    memset(s->bounding_values_array, 0, 256 * sizeof(int));
    for (x = 0; x < filter_limit; x++) {
        bounding_values[-x] = -x;
        bounding_values[x] = x;
    }
    for (x = value = filter_limit; x < 128 && value; x++, value--) {
        bounding_values[ x] =  value;
        bounding_values[-x] = -value;
    }
    if (value)
        bounding_values[128] = value;
    bounding_values[129] = bounding_values[130] = filter_limit * 0x02020202;
}


static int unpack_superblocks(Vp3DecodeContext *s, GetBitContext *gb)
{
    int superblock_starts[3] = { 0, s->u_superblock_start, s->v_superblock_start };
    int bit = 0;
    int current_superblock = 0;
    int current_run = 0;
    int num_partial_superblocks = 0;

    int i, j;
    int current_fragment;
    int plane;

    if (s->keyframe) {
        memset(s->superblock_coding, SB_FULLY_CODED, s->superblock_count);

    } else {

        
        bit = get_bits1(gb) ^ 1;
        current_run = 0;

        while (current_superblock < s->superblock_count && get_bits_left(gb) > 0) {
            if (s->theora && current_run == MAXIMUM_LONG_BIT_RUN)
                bit = get_bits1(gb);
            else bit ^= 1;

                current_run = get_vlc2(gb, s->superblock_run_length_vlc.table, 6, 2) + 1;
                if (current_run == 34)
                    current_run += get_bits(gb, 12);

            if (current_superblock + current_run > s->superblock_count) {
                av_log(s->avctx, AV_LOG_ERROR, "Invalid partially coded superblock run length\n");
                return -1;
            }

            memset(s->superblock_coding + current_superblock, bit, current_run);

            current_superblock += current_run;
            if (bit)
                num_partial_superblocks += current_run;
        }

        
        if (num_partial_superblocks < s->superblock_count) {
            int superblocks_decoded = 0;

            current_superblock = 0;
            bit = get_bits1(gb) ^ 1;
            current_run = 0;

            while (superblocks_decoded < s->superblock_count - num_partial_superblocks && get_bits_left(gb) > 0) {

                if (s->theora && current_run == MAXIMUM_LONG_BIT_RUN)
                    bit = get_bits1(gb);
                else bit ^= 1;

                        current_run = get_vlc2(gb, s->superblock_run_length_vlc.table, 6, 2) + 1;
                        if (current_run == 34)
                            current_run += get_bits(gb, 12);

                for (j = 0; j < current_run; current_superblock++) {
                    if (current_superblock >= s->superblock_count) {
                        av_log(s->avctx, AV_LOG_ERROR, "Invalid fully coded superblock run length\n");
                        return -1;
                    }

                
                if (s->superblock_coding[current_superblock] == SB_NOT_CODED) {
                    s->superblock_coding[current_superblock] = 2*bit;
                    j++;
                }
                }
                superblocks_decoded += current_run;
            }
        }

        
        if (num_partial_superblocks) {

            current_run = 0;
            bit = get_bits1(gb);
            
            bit ^= 1;
        }
    }

    
    s->total_num_coded_frags = 0;
    memset(s->macroblock_coding, MODE_COPY, s->macroblock_count);

    for (plane = 0; plane < 3; plane++) {
        int sb_start = superblock_starts[plane];
        int sb_end = sb_start + (plane ? s->c_superblock_count : s->y_superblock_count);
        int num_coded_frags = 0;

    for (i = sb_start; i < sb_end && get_bits_left(gb) > 0; i++) {

        
        for (j = 0; j < 16; j++) {

            
            current_fragment = s->superblock_fragments[i * 16 + j];
            if (current_fragment != -1) {
                int coded = s->superblock_coding[i];

                if (s->superblock_coding[i] == SB_PARTIALLY_CODED) {

                    
                    if (current_run-- == 0) {
                        bit ^= 1;
                        current_run = get_vlc2(gb, s->fragment_run_length_vlc.table, 5, 2);
                    }
                    coded = bit;
                }

                    if (coded) {
                        
                        s->all_fragments[current_fragment].coding_method = MODE_INTER_NO_MV;
                        s->coded_fragment_list[plane][num_coded_frags++] = current_fragment;
                    } else {
                        
                        s->all_fragments[current_fragment].coding_method = MODE_COPY;
                    }
            }
        }
    }
        s->total_num_coded_frags += num_coded_frags;
        for (i = 0; i < 64; i++)
            s->num_coded_frags[plane][i] = num_coded_frags;
        if (plane < 2)
            s->coded_fragment_list[plane+1] = s->coded_fragment_list[plane] + num_coded_frags;
    }
    return 0;
}


static int unpack_modes(Vp3DecodeContext *s, GetBitContext *gb)
{
    int i, j, k, sb_x, sb_y;
    int scheme;
    int current_macroblock;
    int current_fragment;
    int coding_mode;
    int custom_mode_alphabet[CODING_MODE_COUNT];
    const int *alphabet;
    Vp3Fragment *frag;

    if (s->keyframe) {
        for (i = 0; i < s->fragment_count; i++)
            s->all_fragments[i].coding_method = MODE_INTRA;

    } else {

        
        scheme = get_bits(gb, 3);

        
        if (scheme == 0) {
            for (i = 0; i < 8; i++)
                custom_mode_alphabet[i] = MODE_INTER_NO_MV;
            for (i = 0; i < 8; i++)
                custom_mode_alphabet[get_bits(gb, 3)] = i;
            alphabet = custom_mode_alphabet;
        } else alphabet = ModeAlphabet[scheme-1];

        
        for (sb_y = 0; sb_y < s->y_superblock_height; sb_y++) {
            for (sb_x = 0; sb_x < s->y_superblock_width; sb_x++) {
                if (get_bits_left(gb) <= 0)
                    return -1;

            for (j = 0; j < 4; j++) {
                int mb_x = 2*sb_x +   (j>>1);
                int mb_y = 2*sb_y + (((j>>1)+j)&1);
                current_macroblock = mb_y * s->macroblock_width + mb_x;

                if (mb_x >= s->macroblock_width || mb_y >= s->macroblock_height)
                    continue;



                
                for (k = 0; k < 4; k++) {
                    current_fragment = BLOCK_Y*s->fragment_width[0] + BLOCK_X;
                    if (s->all_fragments[current_fragment].coding_method != MODE_COPY)
                        break;
                }
                if (k == 4) {
                    s->macroblock_coding[current_macroblock] = MODE_INTER_NO_MV;
                    continue;
                }

                
                if (scheme == 7)
                    coding_mode = get_bits(gb, 3);
                else coding_mode = alphabet [get_vlc2(gb, s->mode_code_vlc.table, 3, 3)];


                s->macroblock_coding[current_macroblock] = coding_mode;
                for (k = 0; k < 4; k++) {
                    frag = s->all_fragments + BLOCK_Y*s->fragment_width[0] + BLOCK_X;
                    if (frag->coding_method != MODE_COPY)
                        frag->coding_method = coding_mode;
                }






                if (s->chroma_y_shift) {
                    frag = s->all_fragments + mb_y*s->fragment_width[1] + mb_x;
                    SET_CHROMA_MODES } else if (s->chroma_x_shift) {
                    frag = s->all_fragments + 2*mb_y*s->fragment_width[1] + mb_x;
                    for (k = 0; k < 2; k++) {
                        SET_CHROMA_MODES frag += s->fragment_width[1];
                    }
                } else {
                    for (k = 0; k < 4; k++) {
                        frag = s->all_fragments + BLOCK_Y*s->fragment_width[1] + BLOCK_X;
                        SET_CHROMA_MODES }
                }
            }
            }
        }
    }

    return 0;
}


static int unpack_vectors(Vp3DecodeContext *s, GetBitContext *gb)
{
    int j, k, sb_x, sb_y;
    int coding_mode;
    int motion_x[4];
    int motion_y[4];
    int last_motion_x = 0;
    int last_motion_y = 0;
    int prior_last_motion_x = 0;
    int prior_last_motion_y = 0;
    int current_macroblock;
    int current_fragment;
    int frag;

    if (s->keyframe)
        return 0;

    
    coding_mode = get_bits1(gb);

    
    for (sb_y = 0; sb_y < s->y_superblock_height; sb_y++) {
        for (sb_x = 0; sb_x < s->y_superblock_width; sb_x++) {
            if (get_bits_left(gb) <= 0)
                return -1;

        for (j = 0; j < 4; j++) {
            int mb_x = 2*sb_x +   (j>>1);
            int mb_y = 2*sb_y + (((j>>1)+j)&1);
            current_macroblock = mb_y * s->macroblock_width + mb_x;

            if (mb_x >= s->macroblock_width || mb_y >= s->macroblock_height || (s->macroblock_coding[current_macroblock] == MODE_COPY))
                continue;

            switch (s->macroblock_coding[current_macroblock]) {

            case MODE_INTER_PLUS_MV:
            case MODE_GOLDEN_MV:
                
                if (coding_mode == 0) {
                    motion_x[0] = motion_vector_table[get_vlc2(gb, s->motion_vector_vlc.table, 6, 2)];
                    motion_y[0] = motion_vector_table[get_vlc2(gb, s->motion_vector_vlc.table, 6, 2)];
                } else {
                    motion_x[0] = fixed_motion_vector_table[get_bits(gb, 6)];
                    motion_y[0] = fixed_motion_vector_table[get_bits(gb, 6)];
                }

                
                if (s->macroblock_coding[current_macroblock] == MODE_INTER_PLUS_MV) {
                    prior_last_motion_x = last_motion_x;
                    prior_last_motion_y = last_motion_y;
                    last_motion_x = motion_x[0];
                    last_motion_y = motion_y[0];
                }
                break;

            case MODE_INTER_FOURMV:
                
                prior_last_motion_x = last_motion_x;
                prior_last_motion_y = last_motion_y;

                
                for (k = 0; k < 4; k++) {
                    current_fragment = BLOCK_Y*s->fragment_width[0] + BLOCK_X;
                    if (s->all_fragments[current_fragment].coding_method != MODE_COPY) {
                        if (coding_mode == 0) {
                            motion_x[k] = motion_vector_table[get_vlc2(gb, s->motion_vector_vlc.table, 6, 2)];
                            motion_y[k] = motion_vector_table[get_vlc2(gb, s->motion_vector_vlc.table, 6, 2)];
                        } else {
                            motion_x[k] = fixed_motion_vector_table[get_bits(gb, 6)];
                            motion_y[k] = fixed_motion_vector_table[get_bits(gb, 6)];
                        }
                        last_motion_x = motion_x[k];
                        last_motion_y = motion_y[k];
                    } else {
                        motion_x[k] = 0;
                        motion_y[k] = 0;
                    }
                }
                break;

            case MODE_INTER_LAST_MV:
                
                motion_x[0] = last_motion_x;
                motion_y[0] = last_motion_y;

                
                break;

            case MODE_INTER_PRIOR_LAST:
                
                motion_x[0] = prior_last_motion_x;
                motion_y[0] = prior_last_motion_y;

                
                prior_last_motion_x = last_motion_x;
                prior_last_motion_y = last_motion_y;
                last_motion_x = motion_x[0];
                last_motion_y = motion_y[0];
                break;

            default:
                
                motion_x[0] = 0;
                motion_y[0] = 0;

                
                break;
            }

            
            for (k = 0; k < 4; k++) {
                current_fragment = BLOCK_Y*s->fragment_width[0] + BLOCK_X;
                if (s->macroblock_coding[current_macroblock] == MODE_INTER_FOURMV) {
                    s->motion_val[0][current_fragment][0] = motion_x[k];
                    s->motion_val[0][current_fragment][1] = motion_y[k];
                } else {
                    s->motion_val[0][current_fragment][0] = motion_x[0];
                    s->motion_val[0][current_fragment][1] = motion_y[0];
                }
            }

            if (s->chroma_y_shift) {
                if (s->macroblock_coding[current_macroblock] == MODE_INTER_FOURMV) {
                    motion_x[0] = RSHIFT(motion_x[0] + motion_x[1] + motion_x[2] + motion_x[3], 2);
                    motion_y[0] = RSHIFT(motion_y[0] + motion_y[1] + motion_y[2] + motion_y[3], 2);
                }
                motion_x[0] = (motion_x[0]>>1) | (motion_x[0]&1);
                motion_y[0] = (motion_y[0]>>1) | (motion_y[0]&1);
                frag = mb_y*s->fragment_width[1] + mb_x;
                s->motion_val[1][frag][0] = motion_x[0];
                s->motion_val[1][frag][1] = motion_y[0];
            } else if (s->chroma_x_shift) {
                if (s->macroblock_coding[current_macroblock] == MODE_INTER_FOURMV) {
                    motion_x[0] = RSHIFT(motion_x[0] + motion_x[1], 1);
                    motion_y[0] = RSHIFT(motion_y[0] + motion_y[1], 1);
                    motion_x[1] = RSHIFT(motion_x[2] + motion_x[3], 1);
                    motion_y[1] = RSHIFT(motion_y[2] + motion_y[3], 1);
                } else {
                    motion_x[1] = motion_x[0];
                    motion_y[1] = motion_y[0];
                }
                motion_x[0] = (motion_x[0]>>1) | (motion_x[0]&1);
                motion_x[1] = (motion_x[1]>>1) | (motion_x[1]&1);

                frag = 2*mb_y*s->fragment_width[1] + mb_x;
                for (k = 0; k < 2; k++) {
                    s->motion_val[1][frag][0] = motion_x[k];
                    s->motion_val[1][frag][1] = motion_y[k];
                    frag += s->fragment_width[1];
                }
            } else {
                for (k = 0; k < 4; k++) {
                    frag = BLOCK_Y*s->fragment_width[1] + BLOCK_X;
                    if (s->macroblock_coding[current_macroblock] == MODE_INTER_FOURMV) {
                        s->motion_val[1][frag][0] = motion_x[k];
                        s->motion_val[1][frag][1] = motion_y[k];
                    } else {
                        s->motion_val[1][frag][0] = motion_x[0];
                        s->motion_val[1][frag][1] = motion_y[0];
                    }
                }
            }
        }
        }
    }

    return 0;
}

static int unpack_block_qpis(Vp3DecodeContext *s, GetBitContext *gb)
{
    int qpi, i, j, bit, run_length, blocks_decoded, num_blocks_at_qpi;
    int num_blocks = s->total_num_coded_frags;

    for (qpi = 0; qpi < s->nqps-1 && num_blocks > 0; qpi++) {
        i = blocks_decoded = num_blocks_at_qpi = 0;

        bit = get_bits1(gb) ^ 1;
        run_length = 0;

        do {
            if (run_length == MAXIMUM_LONG_BIT_RUN)
                bit = get_bits1(gb);
            else bit ^= 1;

            run_length = get_vlc2(gb, s->superblock_run_length_vlc.table, 6, 2) + 1;
            if (run_length == 34)
                run_length += get_bits(gb, 12);
            blocks_decoded += run_length;

            if (!bit)
                num_blocks_at_qpi += run_length;

            for (j = 0; j < run_length; i++) {
                if (i >= s->total_num_coded_frags)
                    return -1;

                if (s->all_fragments[s->coded_fragment_list[0][i]].qpi == qpi) {
                    s->all_fragments[s->coded_fragment_list[0][i]].qpi += bit;
                    j++;
                }
            }
        } while (blocks_decoded < num_blocks && get_bits_left(gb) > 0);

        num_blocks -= num_blocks_at_qpi;
    }

    return 0;
}


static int unpack_vlcs(Vp3DecodeContext *s, GetBitContext *gb, VLC *table, int coeff_index, int plane, int eob_run)


{
    int i, j = 0;
    int token;
    int zero_run = 0;
    DCTELEM coeff = 0;
    int bits_to_get;
    int blocks_ended;
    int coeff_i = 0;
    int num_coeffs = s->num_coded_frags[plane][coeff_index];
    int16_t *dct_tokens = s->dct_tokens[plane][coeff_index];

    
    int *coded_fragment_list = s->coded_fragment_list[plane];
    Vp3Fragment *all_fragments = s->all_fragments;
    VLC_TYPE (*vlc_table)[2] = table->table;

    if (num_coeffs < 0)
        av_log(s->avctx, AV_LOG_ERROR, "Invalid number of coefficents at level %d\n", coeff_index);

    if (eob_run > num_coeffs) {
        coeff_i = blocks_ended = num_coeffs;
        eob_run -= num_coeffs;
    } else {
        coeff_i = blocks_ended = eob_run;
        eob_run = 0;
    }

    
    if (blocks_ended)
        dct_tokens[j++] = blocks_ended << 2;

    while (coeff_i < num_coeffs && get_bits_left(gb) > 0) {
            
            token = get_vlc2(gb, vlc_table, 11, 3);
            
            if ((unsigned) token <= 6U) {
                eob_run = eob_run_base[token];
                if (eob_run_get_bits[token])
                    eob_run += get_bits(gb, eob_run_get_bits[token]);

                
                
                if (eob_run > num_coeffs - coeff_i) {
                    dct_tokens[j++] = TOKEN_EOB(num_coeffs - coeff_i);
                    blocks_ended   += num_coeffs - coeff_i;
                    eob_run        -= num_coeffs - coeff_i;
                    coeff_i         = num_coeffs;
                } else {
                    dct_tokens[j++] = TOKEN_EOB(eob_run);
                    blocks_ended   += eob_run;
                    coeff_i        += eob_run;
                    eob_run = 0;
                }
            } else if (token >= 0) {
                bits_to_get = coeff_get_bits[token];
                if (bits_to_get)
                    bits_to_get = get_bits(gb, bits_to_get);
                coeff = coeff_tables[token][bits_to_get];

                zero_run = zero_run_base[token];
                if (zero_run_get_bits[token])
                    zero_run += get_bits(gb, zero_run_get_bits[token]);

                if (zero_run) {
                    dct_tokens[j++] = TOKEN_ZERO_RUN(coeff, zero_run);
                } else {
                    
                    
                    
                    
                    if (!coeff_index)
                        all_fragments[coded_fragment_list[coeff_i]].dc = coeff;

                    dct_tokens[j++] = TOKEN_COEFF(coeff);
                }

                if (coeff_index + zero_run > 64) {
                    av_log(s->avctx, AV_LOG_DEBUG, "Invalid zero run of %d with" " %d coeffs left\n", zero_run, 64-coeff_index);
                    zero_run = 64 - coeff_index;
                }

                
                
                for (i = coeff_index+1; i <= coeff_index+zero_run; i++)
                    s->num_coded_frags[plane][i]--;
                coeff_i++;
            } else {
                av_log(s->avctx, AV_LOG_ERROR, "Invalid token %d\n", token);
                return -1;
            }
    }

    if (blocks_ended > s->num_coded_frags[plane][coeff_index])
        av_log(s->avctx, AV_LOG_ERROR, "More blocks ended than coded!\n");

    
    
    if (blocks_ended)
        for (i = coeff_index+1; i < 64; i++)
            s->num_coded_frags[plane][i] -= blocks_ended;

    
    if (plane < 2)
        s->dct_tokens[plane+1][coeff_index] = dct_tokens + j;
    else if (coeff_index < 63)
        s->dct_tokens[0][coeff_index+1] = dct_tokens + j;

    return eob_run;
}

static void reverse_dc_prediction(Vp3DecodeContext *s, int first_fragment, int fragment_width, int fragment_height);



static int unpack_dct_coeffs(Vp3DecodeContext *s, GetBitContext *gb)
{
    int i;
    int dc_y_table;
    int dc_c_table;
    int ac_y_table;
    int ac_c_table;
    int residual_eob_run = 0;
    VLC *y_tables[64];
    VLC *c_tables[64];

    s->dct_tokens[0][0] = s->dct_tokens_base;

    
    dc_y_table = get_bits(gb, 4);
    dc_c_table = get_bits(gb, 4);

    
    residual_eob_run = unpack_vlcs(s, gb, &s->dc_vlc[dc_y_table], 0, 0, residual_eob_run);
    if (residual_eob_run < 0)
        return residual_eob_run;

    
    reverse_dc_prediction(s, 0, s->fragment_width[0], s->fragment_height[0]);

    
    residual_eob_run = unpack_vlcs(s, gb, &s->dc_vlc[dc_c_table], 0, 1, residual_eob_run);
    if (residual_eob_run < 0)
        return residual_eob_run;
    residual_eob_run = unpack_vlcs(s, gb, &s->dc_vlc[dc_c_table], 0, 2, residual_eob_run);
    if (residual_eob_run < 0)
        return residual_eob_run;

    
    if (!(s->avctx->flags & CODEC_FLAG_GRAY))
    {
        reverse_dc_prediction(s, s->fragment_start[1], s->fragment_width[1], s->fragment_height[1]);
        reverse_dc_prediction(s, s->fragment_start[2], s->fragment_width[1], s->fragment_height[1]);
    }

    
    ac_y_table = get_bits(gb, 4);
    ac_c_table = get_bits(gb, 4);

    
    for (i = 1; i <= 5; i++) {
        y_tables[i] = &s->ac_vlc_1[ac_y_table];
        c_tables[i] = &s->ac_vlc_1[ac_c_table];
    }
    for (i = 6; i <= 14; i++) {
        y_tables[i] = &s->ac_vlc_2[ac_y_table];
        c_tables[i] = &s->ac_vlc_2[ac_c_table];
    }
    for (i = 15; i <= 27; i++) {
        y_tables[i] = &s->ac_vlc_3[ac_y_table];
        c_tables[i] = &s->ac_vlc_3[ac_c_table];
    }
    for (i = 28; i <= 63; i++) {
        y_tables[i] = &s->ac_vlc_4[ac_y_table];
        c_tables[i] = &s->ac_vlc_4[ac_c_table];
    }

    
    for (i = 1; i <= 63; i++) {
            residual_eob_run = unpack_vlcs(s, gb, y_tables[i], i, 0, residual_eob_run);
            if (residual_eob_run < 0)
                return residual_eob_run;

            residual_eob_run = unpack_vlcs(s, gb, c_tables[i], i, 1, residual_eob_run);
            if (residual_eob_run < 0)
                return residual_eob_run;
            residual_eob_run = unpack_vlcs(s, gb, c_tables[i], i, 2, residual_eob_run);
            if (residual_eob_run < 0)
                return residual_eob_run;
    }

    return 0;
}





static void reverse_dc_prediction(Vp3DecodeContext *s, int first_fragment, int fragment_width, int fragment_height)


{






    int x, y;
    int i = first_fragment;

    int predicted_dc;

    
    int vl, vul, vu, vur;

    
    int l, ul, u, ur;

    
    static const int predictor_transform[16][4] = {
        {  0,  0,  0,  0}, {  0,  0,  0,128}, {  0,  0,128,  0}, {  0,  0, 53, 75}, {  0,128,  0,  0}, {  0, 64,  0, 64}, {  0,128,  0,  0}, {  0,  0, 53, 75}, {128,  0,  0,  0}, {  0,  0,  0,128}, { 64,  0, 64,  0}, {  0,  0, 53, 75}, {  0,128,  0,  0}, {-104,116,  0,116}, { 24, 80, 24,  0}, {-104,116,  0,116}














    };

    
    static const unsigned char compatible_frame[9] = {
        1,     0, 1, 1, 1, 2, 2, 1, 3 };








    int current_frame_type;

    
    short last_dc[3];

    int transform = 0;

    vul = vu = vur = vl = 0;
    last_dc[0] = last_dc[1] = last_dc[2] = 0;

    
    for (y = 0; y < fragment_height; y++) {

        
        for (x = 0; x < fragment_width; x++, i++) {

            
            if (s->all_fragments[i].coding_method != MODE_COPY) {

                current_frame_type = compatible_frame[s->all_fragments[i].coding_method];

                transform= 0;
                if(x){
                    l= i-1;
                    vl = DC_COEFF(l);
                    if(COMPATIBLE_FRAME(l))
                        transform |= PL;
                }
                if(y){
                    u= i-fragment_width;
                    vu = DC_COEFF(u);
                    if(COMPATIBLE_FRAME(u))
                        transform |= PU;
                    if(x){
                        ul= i-fragment_width-1;
                        vul = DC_COEFF(ul);
                        if(COMPATIBLE_FRAME(ul))
                            transform |= PUL;
                    }
                    if(x + 1 < fragment_width){
                        ur= i-fragment_width+1;
                        vur = DC_COEFF(ur);
                        if(COMPATIBLE_FRAME(ur))
                            transform |= PUR;
                    }
                }

                if (transform == 0) {

                    
                    predicted_dc = last_dc[current_frame_type];
                } else {

                    
                    predicted_dc = (predictor_transform[transform][0] * vul) + (predictor_transform[transform][1] * vu) + (predictor_transform[transform][2] * vur) + (predictor_transform[transform][3] * vl);




                    predicted_dc /= 128;

                    
                    if ((transform == 15) || (transform == 13)) {
                        if (FFABS(predicted_dc - vu) > 128)
                            predicted_dc = vu;
                        else if (FFABS(predicted_dc - vl) > 128)
                            predicted_dc = vl;
                        else if (FFABS(predicted_dc - vul) > 128)
                            predicted_dc = vul;
                    }
                }

                
                DC_COEFF(i) += predicted_dc;
                
                last_dc[current_frame_type] = DC_COEFF(i);
            }
        }
    }
}

static void apply_loop_filter(Vp3DecodeContext *s, int plane, int ystart, int yend)
{
    int x, y;
    int *bounding_values= s->bounding_values_array+127;

    int width           = s->fragment_width[!!plane];
    int height          = s->fragment_height[!!plane];
    int fragment        = s->fragment_start        [plane] + ystart * width;
    int stride          = s->current_frame.linesize[plane];
    uint8_t *plane_data = s->current_frame.data    [plane];
    if (!s->flipped_image) stride = -stride;
    plane_data += s->data_offset[plane] + 8*ystart*stride;

    for (y = ystart; y < yend; y++) {

        for (x = 0; x < width; x++) {
            
            if( s->all_fragments[fragment].coding_method != MODE_COPY )
            {
                
                if (x > 0) {
                    s->dsp.vp3_h_loop_filter( plane_data + 8*x, stride, bounding_values);

                }

                
                if (y > 0) {
                    s->dsp.vp3_v_loop_filter( plane_data + 8*x, stride, bounding_values);

                }

                
                if ((x < width - 1) && (s->all_fragments[fragment + 1].coding_method == MODE_COPY)) {
                    s->dsp.vp3_h_loop_filter( plane_data + 8*x + 8, stride, bounding_values);

                }

                
                if ((y < height - 1) && (s->all_fragments[fragment + width].coding_method == MODE_COPY)) {
                    s->dsp.vp3_v_loop_filter( plane_data + 8*x + 8*stride, stride, bounding_values);

                }
            }

            fragment++;
        }
        plane_data += 8*stride;
    }
}


static inline int vp3_dequant(Vp3DecodeContext *s, Vp3Fragment *frag, int plane, int inter, DCTELEM block[64])
{
    int16_t *dequantizer = s->qmat[frag->qpi][inter][plane];
    uint8_t *perm = s->scantable.permutated;
    int i = 0;

    do {
        int token = *s->dct_tokens[plane][i];
        switch (token & 3) {
        case 0: 
            if (--token < 4) 
                s->dct_tokens[plane][i]++;
            else *s->dct_tokens[plane][i] = token & ~3;
            goto end;
        case 1: 
            s->dct_tokens[plane][i]++;
            i += (token >> 2) & 0x7f;
            block[perm[i]] = (token >> 9) * dequantizer[perm[i]];
            i++;
            break;
        case 2: 
            block[perm[i]] = (token >> 2) * dequantizer[perm[i]];
            s->dct_tokens[plane][i++]++;
            break;
        default: 
            return i;
        }
    } while (i < 64);
end:
    
    block[0] = frag->dc * s->qmat[0][inter][plane][0];
    return i;
}


static void vp3_draw_horiz_band(Vp3DecodeContext *s, int y)
{
    int h, cy, i;
    int offset[AV_NUM_DATA_POINTERS];

    if (HAVE_THREADS && s->avctx->active_thread_type&FF_THREAD_FRAME) {
        int y_flipped = s->flipped_image ? s->avctx->height-y : y;

        
        
        
        ff_thread_report_progress(&s->current_frame, y_flipped==s->avctx->height ? INT_MAX : y_flipped-1, 0);
    }

    if(s->avctx->draw_horiz_band==NULL)
        return;

    h= y - s->last_slice_end;
    s->last_slice_end= y;
    y -= h;

    if (!s->flipped_image) {
        y = s->avctx->height - y - h;
    }

    cy = y >> s->chroma_y_shift;
    offset[0] = s->current_frame.linesize[0]*y;
    offset[1] = s->current_frame.linesize[1]*cy;
    offset[2] = s->current_frame.linesize[2]*cy;
    for (i = 3; i < AV_NUM_DATA_POINTERS; i++)
        offset[i] = 0;

    emms_c();
    s->avctx->draw_horiz_band(s->avctx, &s->current_frame, offset, y, 3, h);
}


static void await_reference_row(Vp3DecodeContext *s, Vp3Fragment *fragment, int motion_y, int y)
{
    AVFrame *ref_frame;
    int ref_row;
    int border = motion_y&1;

    if (fragment->coding_method == MODE_USING_GOLDEN || fragment->coding_method == MODE_GOLDEN_MV)
        ref_frame = &s->golden_frame;
    else ref_frame = &s->last_frame;

    ref_row = y + (motion_y>>1);
    ref_row = FFMAX(FFABS(ref_row), ref_row + 8 + border);

    ff_thread_await_progress(ref_frame, ref_row, 0);
}


static void render_slice(Vp3DecodeContext *s, int slice)
{
    int x, y, i, j, fragment;
    LOCAL_ALIGNED_16(DCTELEM, block, [64]);
    int motion_x = 0xdeadbeef, motion_y = 0xdeadbeef;
    int motion_halfpel_index;
    uint8_t *motion_source;
    int plane, first_pixel;

    if (slice >= s->c_superblock_height)
        return;

    for (plane = 0; plane < 3; plane++) {
        uint8_t *output_plane = s->current_frame.data    [plane] + s->data_offset[plane];
        uint8_t *  last_plane = s->   last_frame.data    [plane] + s->data_offset[plane];
        uint8_t *golden_plane = s-> golden_frame.data    [plane] + s->data_offset[plane];
        int stride            = s->current_frame.linesize[plane];
        int plane_width       = s->width  >> (plane && s->chroma_x_shift);
        int plane_height      = s->height >> (plane && s->chroma_y_shift);
        int8_t (*motion_val)[2] = s->motion_val[!!plane];

        int sb_x, sb_y        = slice << (!plane && s->chroma_y_shift);
        int slice_height      = sb_y + 1 + (!plane && s->chroma_y_shift);
        int slice_width       = plane ? s->c_superblock_width : s->y_superblock_width;

        int fragment_width    = s->fragment_width[!!plane];
        int fragment_height   = s->fragment_height[!!plane];
        int fragment_start    = s->fragment_start[plane];
        int do_await          = !plane && HAVE_THREADS && (s->avctx->active_thread_type&FF_THREAD_FRAME);

        if (!s->flipped_image) stride = -stride;
        if (CONFIG_GRAY && plane && (s->avctx->flags & CODEC_FLAG_GRAY))
            continue;

        
        for (; sb_y < slice_height; sb_y++) {

            
            for (sb_x = 0; sb_x < slice_width; sb_x++) {

                
                for (j = 0; j < 16; j++) {
                    x = 4*sb_x + hilbert_offset[j][0];
                    y = 4*sb_y + hilbert_offset[j][1];
                    fragment = y*fragment_width + x;

                    i = fragment_start + fragment;

                    
                    if (x >= fragment_width || y >= fragment_height)
                        continue;

                first_pixel = 8*y*stride + 8*x;

                if (do_await && s->all_fragments[i].coding_method != MODE_INTRA)
                    await_reference_row(s, &s->all_fragments[i], motion_val[fragment][1], (16*y) >> s->chroma_y_shift);

                
                if (s->all_fragments[i].coding_method != MODE_COPY) {
                    if ((s->all_fragments[i].coding_method == MODE_USING_GOLDEN) || (s->all_fragments[i].coding_method == MODE_GOLDEN_MV))
                        motion_source= golden_plane;
                    else motion_source= last_plane;

                    motion_source += first_pixel;
                    motion_halfpel_index = 0;

                    
                    if ((s->all_fragments[i].coding_method > MODE_INTRA) && (s->all_fragments[i].coding_method != MODE_USING_GOLDEN)) {
                        int src_x, src_y;
                        motion_x = motion_val[fragment][0];
                        motion_y = motion_val[fragment][1];

                        src_x= (motion_x>>1) + 8*x;
                        src_y= (motion_y>>1) + 8*y;

                        motion_halfpel_index = motion_x & 0x01;
                        motion_source += (motion_x >> 1);

                        motion_halfpel_index |= (motion_y & 0x01) << 1;
                        motion_source += ((motion_y >> 1) * stride);

                        if(src_x<0 || src_y<0 || src_x + 9 >= plane_width || src_y + 9 >= plane_height){
                            uint8_t *temp= s->edge_emu_buffer;
                            if(stride<0) temp -= 8*stride;

                            s->dsp.emulated_edge_mc(temp, motion_source, stride, 9, 9, src_x, src_y, plane_width, plane_height);
                            motion_source= temp;
                        }
                    }


                    
                    if (s->all_fragments[i].coding_method != MODE_INTRA) {
                        
                        if(motion_halfpel_index != 3){
                            s->dsp.put_no_rnd_pixels_tab[1][motion_halfpel_index]( output_plane + first_pixel, motion_source, stride, 8);

                        }else{
                            int d= (motion_x ^ motion_y)>>31; 
                            s->dsp.put_no_rnd_pixels_l2[1]( output_plane + first_pixel, motion_source - d, motion_source + stride + 1 + d, stride, 8);



                        }
                    }

                        s->dsp.clear_block(block);

                    

                    if (s->all_fragments[i].coding_method == MODE_INTRA) {
                        vp3_dequant(s, s->all_fragments + i, plane, 0, block);
                        if(s->avctx->idct_algo!=FF_IDCT_VP3)
                            block[0] += 128<<3;
                        s->dsp.idct_put( output_plane + first_pixel, stride, block);


                    } else {
                        if (vp3_dequant(s, s->all_fragments + i, plane, 1, block)) {
                        s->dsp.idct_add( output_plane + first_pixel, stride, block);


                        } else {
                            s->dsp.vp3_idct_dc_add(output_plane + first_pixel, stride, block);
                        }
                    }
                } else {

                    
                    s->dsp.put_pixels_tab[1][0]( output_plane + first_pixel, last_plane + first_pixel, stride, 8);



                }
                }
            }

            
            if (!s->skip_loop_filter)
                apply_loop_filter(s, plane, 4*sb_y - !!sb_y, FFMIN(4*sb_y+3, fragment_height-1));
        }
    }

     
     

    vp3_draw_horiz_band(s, FFMIN((32 << s->chroma_y_shift) * (slice + 1) -16, s->height-16));
}


static av_cold int allocate_tables(AVCodecContext *avctx)
{
    Vp3DecodeContext *s = avctx->priv_data;
    int y_fragment_count, c_fragment_count;

    y_fragment_count = s->fragment_width[0] * s->fragment_height[0];
    c_fragment_count = s->fragment_width[1] * s->fragment_height[1];

    s->superblock_coding = av_malloc(s->superblock_count);
    s->all_fragments = av_malloc(s->fragment_count * sizeof(Vp3Fragment));
    s->coded_fragment_list[0] = av_malloc(s->fragment_count * sizeof(int));
    s->dct_tokens_base = av_malloc(64*s->fragment_count * sizeof(*s->dct_tokens_base));
    s->motion_val[0] = av_malloc(y_fragment_count * sizeof(*s->motion_val[0]));
    s->motion_val[1] = av_malloc(c_fragment_count * sizeof(*s->motion_val[1]));

    
    s->superblock_fragments = av_malloc(s->superblock_count * 16 * sizeof(int));
    s->macroblock_coding = av_malloc(s->macroblock_count + 1);

    if (!s->superblock_coding || !s->all_fragments || !s->dct_tokens_base || !s->coded_fragment_list[0] || !s->superblock_fragments || !s->macroblock_coding || !s->motion_val[0] || !s->motion_val[1]) {

        vp3_decode_end(avctx);
        return -1;
    }

    init_block_mapping(s);

    return 0;
}

static av_cold int vp3_decode_init(AVCodecContext *avctx)
{
    Vp3DecodeContext *s = avctx->priv_data;
    int i, inter, plane;
    int c_width;
    int c_height;
    int y_fragment_count, c_fragment_count;

    if (avctx->codec_tag == MKTAG('V','P','3','0'))
        s->version = 0;
    else s->version = 1;

    s->avctx = avctx;
    s->width = FFALIGN(avctx->width, 16);
    s->height = FFALIGN(avctx->height, 16);
    if (avctx->pix_fmt == PIX_FMT_NONE)
        avctx->pix_fmt = PIX_FMT_YUV420P;
    avctx->chroma_sample_location = AVCHROMA_LOC_CENTER;
    if(avctx->idct_algo==FF_IDCT_AUTO)
        avctx->idct_algo=FF_IDCT_VP3;
    dsputil_init(&s->dsp, avctx);

    ff_init_scantable(s->dsp.idct_permutation, &s->scantable, ff_zigzag_direct);

    
    for (i = 0; i < 3; i++)
        s->qps[i] = -1;

    avcodec_get_chroma_sub_sample(avctx->pix_fmt, &s->chroma_x_shift, &s->chroma_y_shift);

    s->y_superblock_width = (s->width + 31) / 32;
    s->y_superblock_height = (s->height + 31) / 32;
    s->y_superblock_count = s->y_superblock_width * s->y_superblock_height;

    
    c_width = s->width >> s->chroma_x_shift;
    c_height = s->height >> s->chroma_y_shift;
    s->c_superblock_width = (c_width + 31) / 32;
    s->c_superblock_height = (c_height + 31) / 32;
    s->c_superblock_count = s->c_superblock_width * s->c_superblock_height;

    s->superblock_count = s->y_superblock_count + (s->c_superblock_count * 2);
    s->u_superblock_start = s->y_superblock_count;
    s->v_superblock_start = s->u_superblock_start + s->c_superblock_count;

    s->macroblock_width = (s->width + 15) / 16;
    s->macroblock_height = (s->height + 15) / 16;
    s->macroblock_count = s->macroblock_width * s->macroblock_height;

    s->fragment_width[0] = s->width / FRAGMENT_PIXELS;
    s->fragment_height[0] = s->height / FRAGMENT_PIXELS;
    s->fragment_width[1]  = s->fragment_width[0]  >> s->chroma_x_shift;
    s->fragment_height[1] = s->fragment_height[0] >> s->chroma_y_shift;

    
    y_fragment_count     = s->fragment_width[0] * s->fragment_height[0];
    c_fragment_count     = s->fragment_width[1] * s->fragment_height[1];
    s->fragment_count    = y_fragment_count + 2*c_fragment_count;
    s->fragment_start[1] = y_fragment_count;
    s->fragment_start[2] = y_fragment_count + c_fragment_count;

    if (!s->theora_tables)
    {
        for (i = 0; i < 64; i++) {
            s->coded_dc_scale_factor[i] = vp31_dc_scale_factor[i];
            s->coded_ac_scale_factor[i] = vp31_ac_scale_factor[i];
            s->base_matrix[0][i] = vp31_intra_y_dequant[i];
            s->base_matrix[1][i] = vp31_intra_c_dequant[i];
            s->base_matrix[2][i] = vp31_inter_dequant[i];
            s->filter_limit_values[i] = vp31_filter_limit_values[i];
        }

        for(inter=0; inter<2; inter++){
            for(plane=0; plane<3; plane++){
                s->qr_count[inter][plane]= 1;
                s->qr_size [inter][plane][0]= 63;
                s->qr_base [inter][plane][0]= s->qr_base [inter][plane][1]= 2*inter + (!!plane)*!inter;
            }
        }

        
        for (i = 0; i < 16; i++) {

            
            init_vlc(&s->dc_vlc[i], 11, 32, &dc_bias[i][0][1], 4, 2, &dc_bias[i][0][0], 4, 2, 0);


            
            init_vlc(&s->ac_vlc_1[i], 11, 32, &ac_bias_0[i][0][1], 4, 2, &ac_bias_0[i][0][0], 4, 2, 0);


            
            init_vlc(&s->ac_vlc_2[i], 11, 32, &ac_bias_1[i][0][1], 4, 2, &ac_bias_1[i][0][0], 4, 2, 0);


            
            init_vlc(&s->ac_vlc_3[i], 11, 32, &ac_bias_2[i][0][1], 4, 2, &ac_bias_2[i][0][0], 4, 2, 0);


            
            init_vlc(&s->ac_vlc_4[i], 11, 32, &ac_bias_3[i][0][1], 4, 2, &ac_bias_3[i][0][0], 4, 2, 0);

        }
    } else {

        for (i = 0; i < 16; i++) {
            
            if (init_vlc(&s->dc_vlc[i], 11, 32, &s->huffman_table[i][0][1], 8, 4, &s->huffman_table[i][0][0], 8, 4, 0) < 0)

                goto vlc_fail;

            
            if (init_vlc(&s->ac_vlc_1[i], 11, 32, &s->huffman_table[i+16][0][1], 8, 4, &s->huffman_table[i+16][0][0], 8, 4, 0) < 0)

                goto vlc_fail;

            
            if (init_vlc(&s->ac_vlc_2[i], 11, 32, &s->huffman_table[i+16*2][0][1], 8, 4, &s->huffman_table[i+16*2][0][0], 8, 4, 0) < 0)

                goto vlc_fail;

            
            if (init_vlc(&s->ac_vlc_3[i], 11, 32, &s->huffman_table[i+16*3][0][1], 8, 4, &s->huffman_table[i+16*3][0][0], 8, 4, 0) < 0)

                goto vlc_fail;

            
            if (init_vlc(&s->ac_vlc_4[i], 11, 32, &s->huffman_table[i+16*4][0][1], 8, 4, &s->huffman_table[i+16*4][0][0], 8, 4, 0) < 0)

                goto vlc_fail;
        }
    }

    init_vlc(&s->superblock_run_length_vlc, 6, 34, &superblock_run_length_vlc_table[0][1], 4, 2, &superblock_run_length_vlc_table[0][0], 4, 2, 0);


    init_vlc(&s->fragment_run_length_vlc, 5, 30, &fragment_run_length_vlc_table[0][1], 4, 2, &fragment_run_length_vlc_table[0][0], 4, 2, 0);


    init_vlc(&s->mode_code_vlc, 3, 8, &mode_code_vlc_table[0][1], 2, 1, &mode_code_vlc_table[0][0], 2, 1, 0);


    init_vlc(&s->motion_vector_vlc, 6, 63, &motion_vector_vlc_table[0][1], 2, 1, &motion_vector_vlc_table[0][0], 2, 1, 0);


    for (i = 0; i < 3; i++) {
        s->current_frame.data[i] = NULL;
        s->last_frame.data[i] = NULL;
        s->golden_frame.data[i] = NULL;
    }

    return allocate_tables(avctx);

vlc_fail:
    av_log(avctx, AV_LOG_FATAL, "Invalid huffman table\n");
    return -1;
}


static void update_frames(AVCodecContext *avctx)
{
    Vp3DecodeContext *s = avctx->priv_data;

    
    if (s->last_frame.data[0] && s->last_frame.type != FF_BUFFER_TYPE_COPY)
        ff_thread_release_buffer(avctx, &s->last_frame);

    
    s->last_frame= s->current_frame;

    if (s->keyframe) {
        if (s->golden_frame.data[0])
            ff_thread_release_buffer(avctx, &s->golden_frame);
        s->golden_frame = s->current_frame;
        s->last_frame.type = FF_BUFFER_TYPE_COPY;
    }

    s->current_frame.data[0]= NULL; 
}

static int vp3_update_thread_context(AVCodecContext *dst, const AVCodecContext *src)
{
    Vp3DecodeContext *s = dst->priv_data, *s1 = src->priv_data;
    int qps_changed = 0, i, err;



    if (!s1->current_frame.data[0] ||s->width != s1->width ||s->height!= s1->height) {

        if (s != s1)
            copy_fields(s, s1, golden_frame, current_frame);
        return -1;
    }

    if (s != s1) {
        
        if (!s->current_frame.data[0]) {
            int y_fragment_count, c_fragment_count;
            s->avctx = dst;
            err = allocate_tables(dst);
            if (err)
                return err;
            y_fragment_count = s->fragment_width[0] * s->fragment_height[0];
            c_fragment_count = s->fragment_width[1] * s->fragment_height[1];
            memcpy(s->motion_val[0], s1->motion_val[0], y_fragment_count * sizeof(*s->motion_val[0]));
            memcpy(s->motion_val[1], s1->motion_val[1], c_fragment_count * sizeof(*s->motion_val[1]));
        }

        
        copy_fields(s, s1, golden_frame, dsp);

        
        for (i = 0; i < 3; i++) {
            if (s->qps[i] != s1->qps[1]) {
                qps_changed = 1;
                memcpy(&s->qmat[i], &s1->qmat[i], sizeof(s->qmat[i]));
            }
        }

        if (s->qps[0] != s1->qps[0])
            memcpy(&s->bounding_values_array, &s1->bounding_values_array, sizeof(s->bounding_values_array));

        if (qps_changed)
            copy_fields(s, s1, qps, superblock_count);

    }

    update_frames(dst);

    return 0;
}

static int vp3_decode_frame(AVCodecContext *avctx, void *data, int *data_size, AVPacket *avpkt)

{
    const uint8_t *buf = avpkt->data;
    int buf_size = avpkt->size;
    Vp3DecodeContext *s = avctx->priv_data;
    GetBitContext gb;
    int i;

    init_get_bits(&gb, buf, buf_size * 8);

    if (s->theora && get_bits1(&gb))
    {
        av_log(avctx, AV_LOG_ERROR, "Header packet passed to frame decoder, skipping\n");
        return -1;
    }

    s->keyframe = !get_bits1(&gb);
    if (!s->theora)
        skip_bits(&gb, 1);
    for (i = 0; i < 3; i++)
        s->last_qps[i] = s->qps[i];

    s->nqps=0;
    do{
        s->qps[s->nqps++]= get_bits(&gb, 6);
    } while(s->theora >= 0x030200 && s->nqps<3 && get_bits1(&gb));
    for (i = s->nqps; i < 3; i++)
        s->qps[i] = -1;

    if (s->avctx->debug & FF_DEBUG_PICT_INFO)
        av_log(s->avctx, AV_LOG_INFO, " VP3 %sframe #%d: Q index = %d\n", s->keyframe?"key":"", avctx->frame_number+1, s->qps[0]);

    s->skip_loop_filter = !s->filter_limit_values[s->qps[0]] || avctx->skip_loop_filter >= (s->keyframe ? AVDISCARD_ALL : AVDISCARD_NONKEY);

    if (s->qps[0] != s->last_qps[0])
        init_loop_filter(s);

    for (i = 0; i < s->nqps; i++)
        
        
        if (s->qps[i] != s->last_qps[i] || s->qps[0] != s->last_qps[0])
            init_dequantizer(s, i);

    if (avctx->skip_frame >= AVDISCARD_NONKEY && !s->keyframe)
        return buf_size;

    s->current_frame.reference = 3;
    s->current_frame.pict_type = s->keyframe ? AV_PICTURE_TYPE_I : AV_PICTURE_TYPE_P;
    if (ff_thread_get_buffer(avctx, &s->current_frame) < 0) {
        av_log(s->avctx, AV_LOG_ERROR, "get_buffer() failed\n");
        goto error;
    }

    if (!s->edge_emu_buffer)
        s->edge_emu_buffer = av_malloc(9*FFABS(s->current_frame.linesize[0]));

    if (s->keyframe) {
        if (!s->theora)
        {
            skip_bits(&gb, 4); 
            skip_bits(&gb, 4); 
            if (s->version)
            {
                s->version = get_bits(&gb, 5);
                if (avctx->frame_number == 0)
                    av_log(s->avctx, AV_LOG_DEBUG, "VP version: %d\n", s->version);
            }
        }
        if (s->version || s->theora)
        {
                if (get_bits1(&gb))
                    av_log(s->avctx, AV_LOG_ERROR, "Warning, unsupported keyframe coding type?!\n");
            skip_bits(&gb, 2); 
        }
    } else {
        if (!s->golden_frame.data[0]) {
            av_log(s->avctx, AV_LOG_WARNING, "vp3: first frame not a keyframe\n");

            s->golden_frame.reference = 3;
            s->golden_frame.pict_type = AV_PICTURE_TYPE_I;
            if (ff_thread_get_buffer(avctx, &s->golden_frame) < 0) {
                av_log(s->avctx, AV_LOG_ERROR, "get_buffer() failed\n");
                goto error;
            }
            s->last_frame = s->golden_frame;
            s->last_frame.type = FF_BUFFER_TYPE_COPY;
            ff_thread_report_progress(&s->last_frame, INT_MAX, 0);
        }
    }

    memset(s->all_fragments, 0, s->fragment_count * sizeof(Vp3Fragment));
    ff_thread_finish_setup(avctx);

    if (unpack_superblocks(s, &gb)){
        av_log(s->avctx, AV_LOG_ERROR, "error in unpack_superblocks\n");
        goto error;
    }
    if (unpack_modes(s, &gb)){
        av_log(s->avctx, AV_LOG_ERROR, "error in unpack_modes\n");
        goto error;
    }
    if (unpack_vectors(s, &gb)){
        av_log(s->avctx, AV_LOG_ERROR, "error in unpack_vectors\n");
        goto error;
    }
    if (unpack_block_qpis(s, &gb)){
        av_log(s->avctx, AV_LOG_ERROR, "error in unpack_block_qpis\n");
        goto error;
    }
    if (unpack_dct_coeffs(s, &gb)){
        av_log(s->avctx, AV_LOG_ERROR, "error in unpack_dct_coeffs\n");
        goto error;
    }

    for (i = 0; i < 3; i++) {
        int height = s->height >> (i && s->chroma_y_shift);
        if (s->flipped_image)
            s->data_offset[i] = 0;
        else s->data_offset[i] = (height-1) * s->current_frame.linesize[i];
    }

    s->last_slice_end = 0;
    for (i = 0; i < s->c_superblock_height; i++)
        render_slice(s, i);

    
    for (i = 0; i < 3; i++) {
        int row = (s->height >> (3+(i && s->chroma_y_shift))) - 1;
        apply_loop_filter(s, i, row, row+1);
    }
    vp3_draw_horiz_band(s, s->avctx->height);

    *data_size=sizeof(AVFrame);
    *(AVFrame*)data= s->current_frame;

    if (!HAVE_THREADS || !(s->avctx->active_thread_type&FF_THREAD_FRAME))
        update_frames(avctx);

    return buf_size;

error:
    ff_thread_report_progress(&s->current_frame, INT_MAX, 0);

    if (!HAVE_THREADS || !(s->avctx->active_thread_type&FF_THREAD_FRAME))
        avctx->release_buffer(avctx, &s->current_frame);

    return -1;
}

static int read_huffman_tree(AVCodecContext *avctx, GetBitContext *gb)
{
    Vp3DecodeContext *s = avctx->priv_data;

    if (get_bits1(gb)) {
        int token;
        if (s->entries >= 32) { 
            av_log(avctx, AV_LOG_ERROR, "huffman tree overflow\n");
            return -1;
        }
        token = get_bits(gb, 5);
        
        s->huffman_table[s->hti][token][0] = s->hbits;
        s->huffman_table[s->hti][token][1] = s->huff_code_size;
        s->entries++;
    }
    else {
        if (s->huff_code_size >= 32) {
            av_log(avctx, AV_LOG_ERROR, "huffman tree overflow\n");
            return -1;
        }
        s->huff_code_size++;
        s->hbits <<= 1;
        if (read_huffman_tree(avctx, gb))
            return -1;
        s->hbits |= 1;
        if (read_huffman_tree(avctx, gb))
            return -1;
        s->hbits >>= 1;
        s->huff_code_size--;
    }
    return 0;
}

static int vp3_init_thread_copy(AVCodecContext *avctx)
{
    Vp3DecodeContext *s = avctx->priv_data;

    s->superblock_coding      = NULL;
    s->all_fragments          = NULL;
    s->coded_fragment_list[0] = NULL;
    s->dct_tokens_base        = NULL;
    s->superblock_fragments   = NULL;
    s->macroblock_coding      = NULL;
    s->motion_val[0]          = NULL;
    s->motion_val[1]          = NULL;
    s->edge_emu_buffer        = NULL;

    return 0;
}


static const enum PixelFormat theora_pix_fmts[4] = {
    PIX_FMT_YUV420P, PIX_FMT_NONE, PIX_FMT_YUV422P, PIX_FMT_YUV444P };

static int theora_decode_header(AVCodecContext *avctx, GetBitContext *gb)
{
    Vp3DecodeContext *s = avctx->priv_data;
    int visible_width, visible_height, colorspace;
    int offset_x = 0, offset_y = 0;
    AVRational fps, aspect;

    s->theora = get_bits_long(gb, 24);
    av_log(avctx, AV_LOG_DEBUG, "Theora bitstream version %X\n", s->theora);

    
    
    if (s->theora < 0x030200)
    {
        s->flipped_image = 1;
        av_log(avctx, AV_LOG_DEBUG, "Old (<alpha3) Theora bitstream, flipped image\n");
    }

    visible_width  = s->width  = get_bits(gb, 16) << 4;
    visible_height = s->height = get_bits(gb, 16) << 4;

    if(av_image_check_size(s->width, s->height, 0, avctx)){
        av_log(avctx, AV_LOG_ERROR, "Invalid dimensions (%dx%d)\n", s->width, s->height);
        s->width= s->height= 0;
        return -1;
    }

    if (s->theora >= 0x030200) {
        visible_width  = get_bits_long(gb, 24);
        visible_height = get_bits_long(gb, 24);

        offset_x = get_bits(gb, 8); 
        offset_y = get_bits(gb, 8); 
    }

    fps.num = get_bits_long(gb, 32);
    fps.den = get_bits_long(gb, 32);
    if (fps.num && fps.den) {
        av_reduce(&avctx->time_base.num, &avctx->time_base.den, fps.den, fps.num, 1<<30);
    }

    aspect.num = get_bits_long(gb, 24);
    aspect.den = get_bits_long(gb, 24);
    if (aspect.num && aspect.den) {
        av_reduce(&avctx->sample_aspect_ratio.num, &avctx->sample_aspect_ratio.den, aspect.num, aspect.den, 1<<30);

    }

    if (s->theora < 0x030200)
        skip_bits(gb, 5); 
    colorspace = get_bits(gb, 8);
    skip_bits(gb, 24); 

    skip_bits(gb, 6); 

    if (s->theora >= 0x030200)
    {
        skip_bits(gb, 5); 
        avctx->pix_fmt = theora_pix_fmts[get_bits(gb, 2)];
        skip_bits(gb, 3); 
    }



    if (   visible_width  <= s->width  && visible_width  > s->width-16 && visible_height <= s->height && visible_height > s->height-16 && !offset_x && (offset_y == s->height - visible_height))

        avcodec_set_dimensions(avctx, visible_width, visible_height);
    else avcodec_set_dimensions(avctx, s->width, s->height);

    if (colorspace == 1) {
        avctx->color_primaries = AVCOL_PRI_BT470M;
    } else if (colorspace == 2) {
        avctx->color_primaries = AVCOL_PRI_BT470BG;
    }
    if (colorspace == 1 || colorspace == 2) {
        avctx->colorspace = AVCOL_SPC_BT470BG;
        avctx->color_trc  = AVCOL_TRC_BT709;
    }

    return 0;
}

static int theora_decode_tables(AVCodecContext *avctx, GetBitContext *gb)
{
    Vp3DecodeContext *s = avctx->priv_data;
    int i, n, matrices, inter, plane;

    if (s->theora >= 0x030200) {
        n = get_bits(gb, 3);
        
        if (n)
            for (i = 0; i < 64; i++)
                s->filter_limit_values[i] = get_bits(gb, n);
    }

    if (s->theora >= 0x030200)
        n = get_bits(gb, 4) + 1;
    else n = 16;
    
    for (i = 0; i < 64; i++)
        s->coded_ac_scale_factor[i] = get_bits(gb, n);

    if (s->theora >= 0x030200)
        n = get_bits(gb, 4) + 1;
    else n = 16;
    
    for (i = 0; i < 64; i++)
        s->coded_dc_scale_factor[i] = get_bits(gb, n);

    if (s->theora >= 0x030200)
        matrices = get_bits(gb, 9) + 1;
    else matrices = 3;

    if(matrices > 384){
        av_log(avctx, AV_LOG_ERROR, "invalid number of base matrixes\n");
        return -1;
    }

    for(n=0; n<matrices; n++){
        for (i = 0; i < 64; i++)
            s->base_matrix[n][i]= get_bits(gb, 8);
    }

    for (inter = 0; inter <= 1; inter++) {
        for (plane = 0; plane <= 2; plane++) {
            int newqr= 1;
            if (inter || plane > 0)
                newqr = get_bits1(gb);
            if (!newqr) {
                int qtj, plj;
                if(inter && get_bits1(gb)){
                    qtj = 0;
                    plj = plane;
                }else{
                    qtj= (3*inter + plane - 1) / 3;
                    plj= (plane + 2) % 3;
                }
                s->qr_count[inter][plane]= s->qr_count[qtj][plj];
                memcpy(s->qr_size[inter][plane], s->qr_size[qtj][plj], sizeof(s->qr_size[0][0]));
                memcpy(s->qr_base[inter][plane], s->qr_base[qtj][plj], sizeof(s->qr_base[0][0]));
            } else {
                int qri= 0;
                int qi = 0;

                for(;;){
                    i= get_bits(gb, av_log2(matrices-1)+1);
                    if(i>= matrices){
                        av_log(avctx, AV_LOG_ERROR, "invalid base matrix index\n");
                        return -1;
                    }
                    s->qr_base[inter][plane][qri]= i;
                    if(qi >= 63)
                        break;
                    i = get_bits(gb, av_log2(63-qi)+1) + 1;
                    s->qr_size[inter][plane][qri++]= i;
                    qi += i;
                }

                if (qi > 63) {
                    av_log(avctx, AV_LOG_ERROR, "invalid qi %d > 63\n", qi);
                    return -1;
                }
                s->qr_count[inter][plane]= qri;
            }
        }
    }

    
    for (s->hti = 0; s->hti < 80; s->hti++) {
        s->entries = 0;
        s->huff_code_size = 1;
        if (!get_bits1(gb)) {
            s->hbits = 0;
            if(read_huffman_tree(avctx, gb))
                return -1;
            s->hbits = 1;
            if(read_huffman_tree(avctx, gb))
                return -1;
        }
    }

    s->theora_tables = 1;

    return 0;
}

static av_cold int theora_decode_init(AVCodecContext *avctx)
{
    Vp3DecodeContext *s = avctx->priv_data;
    GetBitContext gb;
    int ptype;
    uint8_t *header_start[3];
    int header_len[3];
    int i;

    s->theora = 1;

    if (!avctx->extradata_size)
    {
        av_log(avctx, AV_LOG_ERROR, "Missing extradata!\n");
        return -1;
    }

    if (avpriv_split_xiph_headers(avctx->extradata, avctx->extradata_size, 42, header_start, header_len) < 0) {
        av_log(avctx, AV_LOG_ERROR, "Corrupt extradata\n");
        return -1;
    }

  for(i=0;i<3;i++) {
    init_get_bits(&gb, header_start[i], header_len[i] * 8);

    ptype = get_bits(&gb, 8);

     if (!(ptype & 0x80))
     {
        av_log(avctx, AV_LOG_ERROR, "Invalid extradata!\n");

     }

    
    skip_bits_long(&gb, 6*8); 

    switch(ptype)
    {
        case 0x80:
            theora_decode_header(avctx, &gb);
                break;
        case 0x81:


            break;
        case 0x82:
            if (theora_decode_tables(avctx, &gb))
                return -1;
            break;
        default:
            av_log(avctx, AV_LOG_ERROR, "Unknown Theora config packet: %d\n", ptype&~0x80);
            break;
    }
    if(ptype != 0x81 && 8*header_len[i] != get_bits_count(&gb))
        av_log(avctx, AV_LOG_WARNING, "%d bits left in packet %X\n", 8*header_len[i] - get_bits_count(&gb), ptype);
    if (s->theora < 0x030200)
        break;
  }

    return vp3_decode_init(avctx);
}

AVCodec ff_theora_decoder = {
    .name           = "theora", .type           = AVMEDIA_TYPE_VIDEO, .id             = CODEC_ID_THEORA, .priv_data_size = sizeof(Vp3DecodeContext), .init           = theora_decode_init, .close          = vp3_decode_end, .decode         = vp3_decode_frame, .capabilities   = CODEC_CAP_DR1 | CODEC_CAP_DRAW_HORIZ_BAND | CODEC_CAP_FRAME_THREADS, .flush = vp3_decode_flush, .long_name = NULL_IF_CONFIG_SMALL("Theora"), .init_thread_copy      = ONLY_IF_THREADS_ENABLED(vp3_init_thread_copy), .update_thread_context = ONLY_IF_THREADS_ENABLED(vp3_update_thread_context)










};


AVCodec ff_vp3_decoder = {
    .name           = "vp3", .type           = AVMEDIA_TYPE_VIDEO, .id             = CODEC_ID_VP3, .priv_data_size = sizeof(Vp3DecodeContext), .init           = vp3_decode_init, .close          = vp3_decode_end, .decode         = vp3_decode_frame, .capabilities   = CODEC_CAP_DR1 | CODEC_CAP_DRAW_HORIZ_BAND | CODEC_CAP_FRAME_THREADS, .flush = vp3_decode_flush, .long_name = NULL_IF_CONFIG_SMALL("On2 VP3"), .init_thread_copy      = ONLY_IF_THREADS_ENABLED(vp3_init_thread_copy), .update_thread_context = ONLY_IF_THREADS_ENABLED(vp3_update_thread_context)










};
