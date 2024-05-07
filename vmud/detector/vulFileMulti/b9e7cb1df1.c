














































































































































struct CirrusVGAState;
typedef void (*cirrus_bitblt_rop_t) (struct CirrusVGAState *s, uint8_t * dst, const uint8_t * src, int dstpitch, int srcpitch, int bltwidth, int bltheight);


typedef void (*cirrus_fill_t)(struct CirrusVGAState *s, uint8_t *dst, int dst_pitch, int width, int height);

typedef struct CirrusVGAState {
    VGACommonState vga;

    MemoryRegion cirrus_vga_io;
    MemoryRegion cirrus_linear_io;
    MemoryRegion cirrus_linear_bitblt_io;
    MemoryRegion cirrus_mmio_io;
    MemoryRegion pci_bar;
    bool linear_vram;  
    MemoryRegion low_mem_container; 
    MemoryRegion low_mem;           
    MemoryRegion cirrus_bank[2];    
    uint32_t cirrus_addr_mask;
    uint32_t linear_mmio_mask;
    uint8_t cirrus_shadow_gr0;
    uint8_t cirrus_shadow_gr1;
    uint8_t cirrus_hidden_dac_lockindex;
    uint8_t cirrus_hidden_dac_data;
    uint32_t cirrus_bank_base[2];
    uint32_t cirrus_bank_limit[2];
    uint8_t cirrus_hidden_palette[48];
    int cirrus_blt_pixelwidth;
    int cirrus_blt_width;
    int cirrus_blt_height;
    int cirrus_blt_dstpitch;
    int cirrus_blt_srcpitch;
    uint32_t cirrus_blt_fgcol;
    uint32_t cirrus_blt_bgcol;
    uint32_t cirrus_blt_dstaddr;
    uint32_t cirrus_blt_srcaddr;
    uint8_t cirrus_blt_mode;
    uint8_t cirrus_blt_modeext;
    cirrus_bitblt_rop_t cirrus_rop;

    uint8_t cirrus_bltbuf[CIRRUS_BLTBUFSIZE];
    uint8_t *cirrus_srcptr;
    uint8_t *cirrus_srcptr_end;
    uint32_t cirrus_srccounter;
    
    int last_hw_cursor_size;
    int last_hw_cursor_x;
    int last_hw_cursor_y;
    int last_hw_cursor_y_start;
    int last_hw_cursor_y_end;
    int real_vram_size; 
    int device_id;
    int bustype;
} CirrusVGAState;

typedef struct PCICirrusVGAState {
    PCIDevice dev;
    CirrusVGAState cirrus_vga;
} PCICirrusVGAState;







typedef struct ISACirrusVGAState {
    ISADevice parent_obj;

    CirrusVGAState cirrus_vga;
} ISACirrusVGAState;

static uint8_t rop_to_index[256];




static void cirrus_bitblt_reset(CirrusVGAState *s);
static void cirrus_update_memory_access(CirrusVGAState *s);



static bool blit_region_is_unsafe(struct CirrusVGAState *s, int32_t pitch, int32_t addr)
{
    if (!pitch) {
        return true;
    }
    if (pitch < 0) {
        int64_t min = addr + ((int64_t)s->cirrus_blt_height - 1) * pitch - s->cirrus_blt_width;

        if (min < -1 || addr >= s->vga.vram_size) {
            return true;
        }
    } else {
        int64_t max = addr + ((int64_t)s->cirrus_blt_height-1) * pitch + s->cirrus_blt_width;

        if (max > s->vga.vram_size) {
            return true;
        }
    }
    return false;
}

static bool blit_is_unsafe(struct CirrusVGAState *s, bool dst_only)
{
    
    assert(s->cirrus_blt_width > 0);
    assert(s->cirrus_blt_height > 0);

    if (s->cirrus_blt_width > CIRRUS_BLTBUFSIZE) {
        return true;
    }

    if (blit_region_is_unsafe(s, s->cirrus_blt_dstpitch, s->cirrus_blt_dstaddr)) {
        return true;
    }
    if (dst_only) {
        return false;
    }
    if (blit_region_is_unsafe(s, s->cirrus_blt_srcpitch, s->cirrus_blt_srcaddr)) {
        return true;
    }

    return false;
}

static void cirrus_bitblt_rop_nop(CirrusVGAState *s, uint8_t *dst,const uint8_t *src, int dstpitch,int srcpitch, int bltwidth,int bltheight)


{
}

static void cirrus_bitblt_fill_nop(CirrusVGAState *s, uint8_t *dst, int dstpitch, int bltwidth,int bltheight)

{
}





























































static const cirrus_bitblt_rop_t cirrus_fwd_rop[16] = {
    cirrus_bitblt_rop_fwd_0, cirrus_bitblt_rop_fwd_src_and_dst, cirrus_bitblt_rop_nop, cirrus_bitblt_rop_fwd_src_and_notdst, cirrus_bitblt_rop_fwd_notdst, cirrus_bitblt_rop_fwd_src, cirrus_bitblt_rop_fwd_1, cirrus_bitblt_rop_fwd_notsrc_and_dst, cirrus_bitblt_rop_fwd_src_xor_dst, cirrus_bitblt_rop_fwd_src_or_dst, cirrus_bitblt_rop_fwd_notsrc_or_notdst, cirrus_bitblt_rop_fwd_src_notxor_dst, cirrus_bitblt_rop_fwd_src_or_notdst, cirrus_bitblt_rop_fwd_notsrc, cirrus_bitblt_rop_fwd_notsrc_or_dst, cirrus_bitblt_rop_fwd_notsrc_and_notdst, };
















static const cirrus_bitblt_rop_t cirrus_bkwd_rop[16] = {
    cirrus_bitblt_rop_bkwd_0, cirrus_bitblt_rop_bkwd_src_and_dst, cirrus_bitblt_rop_nop, cirrus_bitblt_rop_bkwd_src_and_notdst, cirrus_bitblt_rop_bkwd_notdst, cirrus_bitblt_rop_bkwd_src, cirrus_bitblt_rop_bkwd_1, cirrus_bitblt_rop_bkwd_notsrc_and_dst, cirrus_bitblt_rop_bkwd_src_xor_dst, cirrus_bitblt_rop_bkwd_src_or_dst, cirrus_bitblt_rop_bkwd_notsrc_or_notdst, cirrus_bitblt_rop_bkwd_src_notxor_dst, cirrus_bitblt_rop_bkwd_src_or_notdst, cirrus_bitblt_rop_bkwd_notsrc, cirrus_bitblt_rop_bkwd_notsrc_or_dst, cirrus_bitblt_rop_bkwd_notsrc_and_notdst, };























static const cirrus_bitblt_rop_t cirrus_fwd_transp_rop[16][2] = {
    TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_0), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_src_and_dst), TRANSP_NOP(cirrus_bitblt_rop_nop), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_src_and_notdst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_notdst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_src), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_1), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_notsrc_and_dst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_src_xor_dst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_src_or_dst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_notsrc_or_notdst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_src_notxor_dst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_src_or_notdst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_notsrc), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_notsrc_or_dst), TRANSP_ROP(cirrus_bitblt_rop_fwd_transp_notsrc_and_notdst), };
















static const cirrus_bitblt_rop_t cirrus_bkwd_transp_rop[16][2] = {
    TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_0), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_src_and_dst), TRANSP_NOP(cirrus_bitblt_rop_nop), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_src_and_notdst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_notdst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_src), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_1), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_notsrc_and_dst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_src_xor_dst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_src_or_dst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_notsrc_or_notdst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_src_notxor_dst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_src_or_notdst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_notsrc), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_notsrc_or_dst), TRANSP_ROP(cirrus_bitblt_rop_bkwd_transp_notsrc_and_notdst), };




























static const cirrus_bitblt_rop_t cirrus_patternfill[16][4] = {
    ROP2(cirrus_patternfill_0), ROP2(cirrus_patternfill_src_and_dst), ROP_NOP2(cirrus_bitblt_rop_nop), ROP2(cirrus_patternfill_src_and_notdst), ROP2(cirrus_patternfill_notdst), ROP2(cirrus_patternfill_src), ROP2(cirrus_patternfill_1), ROP2(cirrus_patternfill_notsrc_and_dst), ROP2(cirrus_patternfill_src_xor_dst), ROP2(cirrus_patternfill_src_or_dst), ROP2(cirrus_patternfill_notsrc_or_notdst), ROP2(cirrus_patternfill_src_notxor_dst), ROP2(cirrus_patternfill_src_or_notdst), ROP2(cirrus_patternfill_notsrc), ROP2(cirrus_patternfill_notsrc_or_dst), ROP2(cirrus_patternfill_notsrc_and_notdst), };
















static const cirrus_bitblt_rop_t cirrus_colorexpand_transp[16][4] = {
    ROP2(cirrus_colorexpand_transp_0), ROP2(cirrus_colorexpand_transp_src_and_dst), ROP_NOP2(cirrus_bitblt_rop_nop), ROP2(cirrus_colorexpand_transp_src_and_notdst), ROP2(cirrus_colorexpand_transp_notdst), ROP2(cirrus_colorexpand_transp_src), ROP2(cirrus_colorexpand_transp_1), ROP2(cirrus_colorexpand_transp_notsrc_and_dst), ROP2(cirrus_colorexpand_transp_src_xor_dst), ROP2(cirrus_colorexpand_transp_src_or_dst), ROP2(cirrus_colorexpand_transp_notsrc_or_notdst), ROP2(cirrus_colorexpand_transp_src_notxor_dst), ROP2(cirrus_colorexpand_transp_src_or_notdst), ROP2(cirrus_colorexpand_transp_notsrc), ROP2(cirrus_colorexpand_transp_notsrc_or_dst), ROP2(cirrus_colorexpand_transp_notsrc_and_notdst), };
















static const cirrus_bitblt_rop_t cirrus_colorexpand[16][4] = {
    ROP2(cirrus_colorexpand_0), ROP2(cirrus_colorexpand_src_and_dst), ROP_NOP2(cirrus_bitblt_rop_nop), ROP2(cirrus_colorexpand_src_and_notdst), ROP2(cirrus_colorexpand_notdst), ROP2(cirrus_colorexpand_src), ROP2(cirrus_colorexpand_1), ROP2(cirrus_colorexpand_notsrc_and_dst), ROP2(cirrus_colorexpand_src_xor_dst), ROP2(cirrus_colorexpand_src_or_dst), ROP2(cirrus_colorexpand_notsrc_or_notdst), ROP2(cirrus_colorexpand_src_notxor_dst), ROP2(cirrus_colorexpand_src_or_notdst), ROP2(cirrus_colorexpand_notsrc), ROP2(cirrus_colorexpand_notsrc_or_dst), ROP2(cirrus_colorexpand_notsrc_and_notdst), };
















static const cirrus_bitblt_rop_t cirrus_colorexpand_pattern_transp[16][4] = {
    ROP2(cirrus_colorexpand_pattern_transp_0), ROP2(cirrus_colorexpand_pattern_transp_src_and_dst), ROP_NOP2(cirrus_bitblt_rop_nop), ROP2(cirrus_colorexpand_pattern_transp_src_and_notdst), ROP2(cirrus_colorexpand_pattern_transp_notdst), ROP2(cirrus_colorexpand_pattern_transp_src), ROP2(cirrus_colorexpand_pattern_transp_1), ROP2(cirrus_colorexpand_pattern_transp_notsrc_and_dst), ROP2(cirrus_colorexpand_pattern_transp_src_xor_dst), ROP2(cirrus_colorexpand_pattern_transp_src_or_dst), ROP2(cirrus_colorexpand_pattern_transp_notsrc_or_notdst), ROP2(cirrus_colorexpand_pattern_transp_src_notxor_dst), ROP2(cirrus_colorexpand_pattern_transp_src_or_notdst), ROP2(cirrus_colorexpand_pattern_transp_notsrc), ROP2(cirrus_colorexpand_pattern_transp_notsrc_or_dst), ROP2(cirrus_colorexpand_pattern_transp_notsrc_and_notdst), };
















static const cirrus_bitblt_rop_t cirrus_colorexpand_pattern[16][4] = {
    ROP2(cirrus_colorexpand_pattern_0), ROP2(cirrus_colorexpand_pattern_src_and_dst), ROP_NOP2(cirrus_bitblt_rop_nop), ROP2(cirrus_colorexpand_pattern_src_and_notdst), ROP2(cirrus_colorexpand_pattern_notdst), ROP2(cirrus_colorexpand_pattern_src), ROP2(cirrus_colorexpand_pattern_1), ROP2(cirrus_colorexpand_pattern_notsrc_and_dst), ROP2(cirrus_colorexpand_pattern_src_xor_dst), ROP2(cirrus_colorexpand_pattern_src_or_dst), ROP2(cirrus_colorexpand_pattern_notsrc_or_notdst), ROP2(cirrus_colorexpand_pattern_src_notxor_dst), ROP2(cirrus_colorexpand_pattern_src_or_notdst), ROP2(cirrus_colorexpand_pattern_notsrc), ROP2(cirrus_colorexpand_pattern_notsrc_or_dst), ROP2(cirrus_colorexpand_pattern_notsrc_and_notdst), };
















static const cirrus_fill_t cirrus_fill[16][4] = {
    ROP2(cirrus_fill_0), ROP2(cirrus_fill_src_and_dst), ROP_NOP2(cirrus_bitblt_fill_nop), ROP2(cirrus_fill_src_and_notdst), ROP2(cirrus_fill_notdst), ROP2(cirrus_fill_src), ROP2(cirrus_fill_1), ROP2(cirrus_fill_notsrc_and_dst), ROP2(cirrus_fill_src_xor_dst), ROP2(cirrus_fill_src_or_dst), ROP2(cirrus_fill_notsrc_or_notdst), ROP2(cirrus_fill_src_notxor_dst), ROP2(cirrus_fill_src_or_notdst), ROP2(cirrus_fill_notsrc), ROP2(cirrus_fill_notsrc_or_dst), ROP2(cirrus_fill_notsrc_and_notdst), };
















static inline void cirrus_bitblt_fgcol(CirrusVGAState *s)
{
    unsigned int color;
    switch (s->cirrus_blt_pixelwidth) {
    case 1:
        s->cirrus_blt_fgcol = s->cirrus_shadow_gr1;
        break;
    case 2:
        color = s->cirrus_shadow_gr1 | (s->vga.gr[0x11] << 8);
        s->cirrus_blt_fgcol = le16_to_cpu(color);
        break;
    case 3:
        s->cirrus_blt_fgcol = s->cirrus_shadow_gr1 | (s->vga.gr[0x11] << 8) | (s->vga.gr[0x13] << 16);
        break;
    default:
    case 4:
        color = s->cirrus_shadow_gr1 | (s->vga.gr[0x11] << 8) | (s->vga.gr[0x13] << 16) | (s->vga.gr[0x15] << 24);
        s->cirrus_blt_fgcol = le32_to_cpu(color);
        break;
    }
}

static inline void cirrus_bitblt_bgcol(CirrusVGAState *s)
{
    unsigned int color;
    switch (s->cirrus_blt_pixelwidth) {
    case 1:
        s->cirrus_blt_bgcol = s->cirrus_shadow_gr0;
        break;
    case 2:
        color = s->cirrus_shadow_gr0 | (s->vga.gr[0x10] << 8);
        s->cirrus_blt_bgcol = le16_to_cpu(color);
        break;
    case 3:
        s->cirrus_blt_bgcol = s->cirrus_shadow_gr0 | (s->vga.gr[0x10] << 8) | (s->vga.gr[0x12] << 16);
        break;
    default:
    case 4:
        color = s->cirrus_shadow_gr0 | (s->vga.gr[0x10] << 8) | (s->vga.gr[0x12] << 16) | (s->vga.gr[0x14] << 24);
        s->cirrus_blt_bgcol = le32_to_cpu(color);
        break;
    }
}

static void cirrus_invalidate_region(CirrusVGAState * s, int off_begin, int off_pitch, int bytesperline, int lines)

{
    int y;
    int off_cur;
    int off_cur_end;

    if (off_pitch < 0) {
        off_begin -= bytesperline - 1;
    }

    for (y = 0; y < lines; y++) {
	off_cur = off_begin;
	off_cur_end = (off_cur + bytesperline) & s->cirrus_addr_mask;
        assert(off_cur_end >= off_cur);
        memory_region_set_dirty(&s->vga.vram, off_cur, off_cur_end - off_cur);
	off_begin += off_pitch;
    }
}

static int cirrus_bitblt_common_patterncopy(CirrusVGAState *s, bool videosrc)
{
    uint32_t patternsize;
    uint8_t *dst;
    uint8_t *src;

    dst = s->vga.vram_ptr + s->cirrus_blt_dstaddr;

    if (videosrc) {
        switch (s->vga.get_bpp(&s->vga)) {
        case 8:
            patternsize = 64;
            break;
        case 15:
        case 16:
            patternsize = 128;
            break;
        case 24:
        case 32:
        default:
            patternsize = 256;
            break;
        }
        s->cirrus_blt_srcaddr &= ~(patternsize - 1);
        if (s->cirrus_blt_srcaddr + patternsize > s->vga.vram_size) {
            return 0;
        }
        src = s->vga.vram_ptr + s->cirrus_blt_srcaddr;
    } else {
        src = s->cirrus_bltbuf;
    }

    if (blit_is_unsafe(s, true)) {
        return 0;
    }

    (*s->cirrus_rop) (s, dst, src, s->cirrus_blt_dstpitch, 0, s->cirrus_blt_width, s->cirrus_blt_height);

    cirrus_invalidate_region(s, s->cirrus_blt_dstaddr, s->cirrus_blt_dstpitch, s->cirrus_blt_width, s->cirrus_blt_height);

    return 1;
}



static int cirrus_bitblt_solidfill(CirrusVGAState *s, int blt_rop)
{
    cirrus_fill_t rop_func;

    if (blit_is_unsafe(s, true)) {
        return 0;
    }
    rop_func = cirrus_fill[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
    rop_func(s, s->vga.vram_ptr + s->cirrus_blt_dstaddr, s->cirrus_blt_dstpitch, s->cirrus_blt_width, s->cirrus_blt_height);

    cirrus_invalidate_region(s, s->cirrus_blt_dstaddr, s->cirrus_blt_dstpitch, s->cirrus_blt_width, s->cirrus_blt_height);

    cirrus_bitblt_reset(s);
    return 1;
}



static int cirrus_bitblt_videotovideo_patterncopy(CirrusVGAState * s)
{
    return cirrus_bitblt_common_patterncopy(s, true);
}

static int cirrus_do_copy(CirrusVGAState *s, int dst, int src, int w, int h)
{
    int sx = 0, sy = 0;
    int dx = 0, dy = 0;
    int depth = 0;
    int notify = 0;

    
    if (*s->cirrus_rop == cirrus_bitblt_rop_fwd_src || *s->cirrus_rop == cirrus_bitblt_rop_bkwd_src) {

        int width, height;

        depth = s->vga.get_bpp(&s->vga) / 8;
        if (!depth) {
            return 0;
        }
        s->vga.get_resolution(&s->vga, &width, &height);

        
        sx = (src % ABS(s->cirrus_blt_srcpitch)) / depth;
        sy = (src / ABS(s->cirrus_blt_srcpitch));
        dx = (dst % ABS(s->cirrus_blt_dstpitch)) / depth;
        dy = (dst / ABS(s->cirrus_blt_dstpitch));

        
        w /= depth;

        
        if (s->cirrus_blt_dstpitch < 0) {
            sx -= (s->cirrus_blt_width / depth) - 1;
            dx -= (s->cirrus_blt_width / depth) - 1;
            sy -= s->cirrus_blt_height - 1;
            dy -= s->cirrus_blt_height - 1;
        }

        
        if (sx >= 0 && sy >= 0 && dx >= 0 && dy >= 0 && (sx + w) <= width && (sy + h) <= height && (dx + w) <= width && (dy + h) <= height) {

            notify = 1;
        }
    }

    
    if (notify)
        graphic_hw_update(s->vga.con);

    (*s->cirrus_rop) (s, s->vga.vram_ptr + s->cirrus_blt_dstaddr, s->vga.vram_ptr + s->cirrus_blt_srcaddr, s->cirrus_blt_dstpitch, s->cirrus_blt_srcpitch, s->cirrus_blt_width, s->cirrus_blt_height);



    if (notify) {
        qemu_console_copy(s->vga.con, sx, sy, dx, dy, s->cirrus_blt_width / depth, s->cirrus_blt_height);


    }

    

    cirrus_invalidate_region(s, s->cirrus_blt_dstaddr, s->cirrus_blt_dstpitch, s->cirrus_blt_width, s->cirrus_blt_height);


    return 1;
}

static int cirrus_bitblt_videotovideo_copy(CirrusVGAState * s)
{
    if (blit_is_unsafe(s, false))
        return 0;

    return cirrus_do_copy(s, s->cirrus_blt_dstaddr - s->vga.start_addr, s->cirrus_blt_srcaddr - s->vga.start_addr, s->cirrus_blt_width, s->cirrus_blt_height);

}



static void cirrus_bitblt_cputovideo_next(CirrusVGAState * s)
{
    int copy_count;
    uint8_t *end_ptr;

    if (s->cirrus_srccounter > 0) {
        if (s->cirrus_blt_mode & CIRRUS_BLTMODE_PATTERNCOPY) {
            cirrus_bitblt_common_patterncopy(s, false);
        the_end:
            s->cirrus_srccounter = 0;
            cirrus_bitblt_reset(s);
        } else {
            
            do {
                (*s->cirrus_rop)(s, s->vga.vram_ptr + s->cirrus_blt_dstaddr, s->cirrus_bltbuf, 0, 0, s->cirrus_blt_width, 1);
                cirrus_invalidate_region(s, s->cirrus_blt_dstaddr, 0, s->cirrus_blt_width, 1);
                s->cirrus_blt_dstaddr += s->cirrus_blt_dstpitch;
                s->cirrus_srccounter -= s->cirrus_blt_srcpitch;
                if (s->cirrus_srccounter <= 0)
                    goto the_end;
                
                
                end_ptr = s->cirrus_bltbuf + s->cirrus_blt_srcpitch;
                copy_count = s->cirrus_srcptr_end - end_ptr;
                memmove(s->cirrus_bltbuf, end_ptr, copy_count);
                s->cirrus_srcptr = s->cirrus_bltbuf + copy_count;
                s->cirrus_srcptr_end = s->cirrus_bltbuf + s->cirrus_blt_srcpitch;
            } while (s->cirrus_srcptr >= s->cirrus_srcptr_end);
        }
    }
}



static void cirrus_bitblt_reset(CirrusVGAState * s)
{
    int need_update;

    s->vga.gr[0x31] &= ~(CIRRUS_BLT_START | CIRRUS_BLT_BUSY | CIRRUS_BLT_FIFOUSED);
    need_update = s->cirrus_srcptr != &s->cirrus_bltbuf[0] || s->cirrus_srcptr_end != &s->cirrus_bltbuf[0];
    s->cirrus_srcptr = &s->cirrus_bltbuf[0];
    s->cirrus_srcptr_end = &s->cirrus_bltbuf[0];
    s->cirrus_srccounter = 0;
    if (!need_update)
        return;
    cirrus_update_memory_access(s);
}

static int cirrus_bitblt_cputovideo(CirrusVGAState * s)
{
    int w;

    if (blit_is_unsafe(s, true)) {
        return 0;
    }

    s->cirrus_blt_mode &= ~CIRRUS_BLTMODE_MEMSYSSRC;
    s->cirrus_srcptr = &s->cirrus_bltbuf[0];
    s->cirrus_srcptr_end = &s->cirrus_bltbuf[0];

    if (s->cirrus_blt_mode & CIRRUS_BLTMODE_PATTERNCOPY) {
	if (s->cirrus_blt_mode & CIRRUS_BLTMODE_COLOREXPAND) {
	    s->cirrus_blt_srcpitch = 8;
	} else {
            
	    s->cirrus_blt_srcpitch = 8 * 8 * s->cirrus_blt_pixelwidth;
	}
	s->cirrus_srccounter = s->cirrus_blt_srcpitch;
    } else {
	if (s->cirrus_blt_mode & CIRRUS_BLTMODE_COLOREXPAND) {
            w = s->cirrus_blt_width / s->cirrus_blt_pixelwidth;
            if (s->cirrus_blt_modeext & CIRRUS_BLTMODEEXT_DWORDGRANULARITY)
                s->cirrus_blt_srcpitch = ((w + 31) >> 5);
            else s->cirrus_blt_srcpitch = ((w + 7) >> 3);
	} else {
            
	    s->cirrus_blt_srcpitch = (s->cirrus_blt_width + 3) & ~3;
	}
        s->cirrus_srccounter = s->cirrus_blt_srcpitch * s->cirrus_blt_height;
    }

    
    assert(s->cirrus_blt_srcpitch <= CIRRUS_BLTBUFSIZE);

    s->cirrus_srcptr = s->cirrus_bltbuf;
    s->cirrus_srcptr_end = s->cirrus_bltbuf + s->cirrus_blt_srcpitch;
    cirrus_update_memory_access(s);
    return 1;
}

static int cirrus_bitblt_videotocpu(CirrusVGAState * s)
{
    

    printf("cirrus: bitblt (video to cpu) is not implemented yet\n");

    return 0;
}

static int cirrus_bitblt_videotovideo(CirrusVGAState * s)
{
    int ret;

    if (s->cirrus_blt_mode & CIRRUS_BLTMODE_PATTERNCOPY) {
	ret = cirrus_bitblt_videotovideo_patterncopy(s);
    } else {
	ret = cirrus_bitblt_videotovideo_copy(s);
    }
    if (ret)
	cirrus_bitblt_reset(s);
    return ret;
}

static void cirrus_bitblt_start(CirrusVGAState * s)
{
    uint8_t blt_rop;

    s->vga.gr[0x31] |= CIRRUS_BLT_BUSY;

    s->cirrus_blt_width = (s->vga.gr[0x20] | (s->vga.gr[0x21] << 8)) + 1;
    s->cirrus_blt_height = (s->vga.gr[0x22] | (s->vga.gr[0x23] << 8)) + 1;
    s->cirrus_blt_dstpitch = (s->vga.gr[0x24] | (s->vga.gr[0x25] << 8));
    s->cirrus_blt_srcpitch = (s->vga.gr[0x26] | (s->vga.gr[0x27] << 8));
    s->cirrus_blt_dstaddr = (s->vga.gr[0x28] | (s->vga.gr[0x29] << 8) | (s->vga.gr[0x2a] << 16));
    s->cirrus_blt_srcaddr = (s->vga.gr[0x2c] | (s->vga.gr[0x2d] << 8) | (s->vga.gr[0x2e] << 16));
    s->cirrus_blt_mode = s->vga.gr[0x30];
    s->cirrus_blt_modeext = s->vga.gr[0x33];
    blt_rop = s->vga.gr[0x32];

    s->cirrus_blt_dstaddr &= s->cirrus_addr_mask;
    s->cirrus_blt_srcaddr &= s->cirrus_addr_mask;


    printf("rop=0x%02x mode=0x%02x modeext=0x%02x w=%d h=%d dpitch=%d spitch=%d daddr=0x%08x saddr=0x%08x writemask=0x%02x\n", blt_rop, s->cirrus_blt_mode, s->cirrus_blt_modeext, s->cirrus_blt_width, s->cirrus_blt_height, s->cirrus_blt_dstpitch, s->cirrus_blt_srcpitch, s->cirrus_blt_dstaddr, s->cirrus_blt_srcaddr, s->vga.gr[0x2f]);











    switch (s->cirrus_blt_mode & CIRRUS_BLTMODE_PIXELWIDTHMASK) {
    case CIRRUS_BLTMODE_PIXELWIDTH8:
	s->cirrus_blt_pixelwidth = 1;
	break;
    case CIRRUS_BLTMODE_PIXELWIDTH16:
	s->cirrus_blt_pixelwidth = 2;
	break;
    case CIRRUS_BLTMODE_PIXELWIDTH24:
	s->cirrus_blt_pixelwidth = 3;
	break;
    case CIRRUS_BLTMODE_PIXELWIDTH32:
	s->cirrus_blt_pixelwidth = 4;
	break;
    default:

	printf("cirrus: bitblt - pixel width is unknown\n");

	goto bitblt_ignore;
    }
    s->cirrus_blt_mode &= ~CIRRUS_BLTMODE_PIXELWIDTHMASK;

    if ((s-> cirrus_blt_mode & (CIRRUS_BLTMODE_MEMSYSSRC | CIRRUS_BLTMODE_MEMSYSDEST))

	== (CIRRUS_BLTMODE_MEMSYSSRC | CIRRUS_BLTMODE_MEMSYSDEST)) {

	printf("cirrus: bitblt - memory-to-memory copy is requested\n");

	goto bitblt_ignore;
    }

    if ((s->cirrus_blt_modeext & CIRRUS_BLTMODEEXT_SOLIDFILL) && (s->cirrus_blt_mode & (CIRRUS_BLTMODE_MEMSYSDEST | CIRRUS_BLTMODE_TRANSPARENTCOMP | CIRRUS_BLTMODE_PATTERNCOPY | CIRRUS_BLTMODE_COLOREXPAND)) == (CIRRUS_BLTMODE_PATTERNCOPY | CIRRUS_BLTMODE_COLOREXPAND)) {




        cirrus_bitblt_fgcol(s);
        cirrus_bitblt_solidfill(s, blt_rop);
    } else {
        if ((s->cirrus_blt_mode & (CIRRUS_BLTMODE_COLOREXPAND | CIRRUS_BLTMODE_PATTERNCOPY)) == CIRRUS_BLTMODE_COLOREXPAND) {


            if (s->cirrus_blt_mode & CIRRUS_BLTMODE_TRANSPARENTCOMP) {
                if (s->cirrus_blt_modeext & CIRRUS_BLTMODEEXT_COLOREXPINV)
                    cirrus_bitblt_bgcol(s);
                else cirrus_bitblt_fgcol(s);
                s->cirrus_rop = cirrus_colorexpand_transp[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
            } else {
                cirrus_bitblt_fgcol(s);
                cirrus_bitblt_bgcol(s);
                s->cirrus_rop = cirrus_colorexpand[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
            }
        } else if (s->cirrus_blt_mode & CIRRUS_BLTMODE_PATTERNCOPY) {
            if (s->cirrus_blt_mode & CIRRUS_BLTMODE_COLOREXPAND) {
                if (s->cirrus_blt_mode & CIRRUS_BLTMODE_TRANSPARENTCOMP) {
                    if (s->cirrus_blt_modeext & CIRRUS_BLTMODEEXT_COLOREXPINV)
                        cirrus_bitblt_bgcol(s);
                    else cirrus_bitblt_fgcol(s);
                    s->cirrus_rop = cirrus_colorexpand_pattern_transp[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
                } else {
                    cirrus_bitblt_fgcol(s);
                    cirrus_bitblt_bgcol(s);
                    s->cirrus_rop = cirrus_colorexpand_pattern[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
                }
            } else {
                s->cirrus_rop = cirrus_patternfill[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
            }
        } else {
	    if (s->cirrus_blt_mode & CIRRUS_BLTMODE_TRANSPARENTCOMP) {
		if (s->cirrus_blt_pixelwidth > 2) {
		    printf("src transparent without colorexpand must be 8bpp or 16bpp\n");
		    goto bitblt_ignore;
		}
		if (s->cirrus_blt_mode & CIRRUS_BLTMODE_BACKWARDS) {
		    s->cirrus_blt_dstpitch = -s->cirrus_blt_dstpitch;
		    s->cirrus_blt_srcpitch = -s->cirrus_blt_srcpitch;
		    s->cirrus_rop = cirrus_bkwd_transp_rop[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
		} else {
		    s->cirrus_rop = cirrus_fwd_transp_rop[rop_to_index[blt_rop]][s->cirrus_blt_pixelwidth - 1];
		}
	    } else {
		if (s->cirrus_blt_mode & CIRRUS_BLTMODE_BACKWARDS) {
		    s->cirrus_blt_dstpitch = -s->cirrus_blt_dstpitch;
		    s->cirrus_blt_srcpitch = -s->cirrus_blt_srcpitch;
		    s->cirrus_rop = cirrus_bkwd_rop[rop_to_index[blt_rop]];
		} else {
		    s->cirrus_rop = cirrus_fwd_rop[rop_to_index[blt_rop]];
		}
	    }
	}
        
        if (s->cirrus_blt_mode & CIRRUS_BLTMODE_MEMSYSSRC) {
            if (!cirrus_bitblt_cputovideo(s))
                goto bitblt_ignore;
        } else if (s->cirrus_blt_mode & CIRRUS_BLTMODE_MEMSYSDEST) {
            if (!cirrus_bitblt_videotocpu(s))
                goto bitblt_ignore;
        } else {
            if (!cirrus_bitblt_videotovideo(s))
                goto bitblt_ignore;
        }
    }
    return;
  bitblt_ignore:;
    cirrus_bitblt_reset(s);
}

static void cirrus_write_bitblt(CirrusVGAState * s, unsigned reg_value)
{
    unsigned old_value;

    old_value = s->vga.gr[0x31];
    s->vga.gr[0x31] = reg_value;

    if (((old_value & CIRRUS_BLT_RESET) != 0) && ((reg_value & CIRRUS_BLT_RESET) == 0)) {
	cirrus_bitblt_reset(s);
    } else if (((old_value & CIRRUS_BLT_START) == 0) && ((reg_value & CIRRUS_BLT_START) != 0)) {
	cirrus_bitblt_start(s);
    }
}




static void cirrus_get_offsets(VGACommonState *s1, uint32_t *pline_offset, uint32_t *pstart_addr, uint32_t *pline_compare)


{
    CirrusVGAState * s = container_of(s1, CirrusVGAState, vga);
    uint32_t start_addr, line_offset, line_compare;

    line_offset = s->vga.cr[0x13] | ((s->vga.cr[0x1b] & 0x10) << 4);
    line_offset <<= 3;
    *pline_offset = line_offset;

    start_addr = (s->vga.cr[0x0c] << 8)
	| s->vga.cr[0x0d] | ((s->vga.cr[0x1b] & 0x01) << 16)
	| ((s->vga.cr[0x1b] & 0x0c) << 15)
	| ((s->vga.cr[0x1d] & 0x80) << 12);
    *pstart_addr = start_addr;

    line_compare = s->vga.cr[0x18] | ((s->vga.cr[0x07] & 0x10) << 4) | ((s->vga.cr[0x09] & 0x40) << 3);

    *pline_compare = line_compare;
}

static uint32_t cirrus_get_bpp16_depth(CirrusVGAState * s)
{
    uint32_t ret = 16;

    switch (s->cirrus_hidden_dac_data & 0xf) {
    case 0:
	ret = 15;
	break;			
    case 1:
	ret = 16;
	break;			
    default:

	printf("cirrus: invalid DAC value %x in 16bpp\n", (s->cirrus_hidden_dac_data & 0xf));

	ret = 15;		
	break;
    }
    return ret;
}

static int cirrus_get_bpp(VGACommonState *s1)
{
    CirrusVGAState * s = container_of(s1, CirrusVGAState, vga);
    uint32_t ret = 8;

    if ((s->vga.sr[0x07] & 0x01) != 0) {
	
	switch (s->vga.sr[0x07] & CIRRUS_SR7_BPP_MASK) {
	case CIRRUS_SR7_BPP_8:
	    ret = 8;
	    break;
	case CIRRUS_SR7_BPP_16_DOUBLEVCLK:
	    ret = cirrus_get_bpp16_depth(s);
	    break;
	case CIRRUS_SR7_BPP_24:
	    ret = 24;
	    break;
	case CIRRUS_SR7_BPP_16:
	    ret = cirrus_get_bpp16_depth(s);
	    break;
	case CIRRUS_SR7_BPP_32:
	    ret = 32;
	    break;
	default:

	    printf("cirrus: unknown bpp - sr7=%x\n", s->vga.sr[0x7]);

	    ret = 8;
	    break;
	}
    } else {
	
	ret = 0;
    }

    return ret;
}

static void cirrus_get_resolution(VGACommonState *s, int *pwidth, int *pheight)
{
    int width, height;

    width = (s->cr[0x01] + 1) * 8;
    height = s->cr[0x12] | ((s->cr[0x07] & 0x02) << 7) | ((s->cr[0x07] & 0x40) << 3);

    height = (height + 1);
    
    if (s->cr[0x1a] & 0x01)
        height = height * 2;
    *pwidth = width;
    *pheight = height;
}



static void cirrus_update_bank_ptr(CirrusVGAState * s, unsigned bank_index)
{
    unsigned offset;
    unsigned limit;

    if ((s->vga.gr[0x0b] & 0x01) != 0)	
	offset = s->vga.gr[0x09 + bank_index];
    else			 offset = s->vga.gr[0x09];

    if ((s->vga.gr[0x0b] & 0x20) != 0)
	offset <<= 14;
    else offset <<= 12;

    if (s->real_vram_size <= offset)
	limit = 0;
    else limit = s->real_vram_size - offset;

    if (((s->vga.gr[0x0b] & 0x01) == 0) && (bank_index != 0)) {
	if (limit > 0x8000) {
	    offset += 0x8000;
	    limit -= 0x8000;
	} else {
	    limit = 0;
	}
    }

    if (limit > 0) {
	s->cirrus_bank_base[bank_index] = offset;
	s->cirrus_bank_limit[bank_index] = limit;
    } else {
	s->cirrus_bank_base[bank_index] = 0;
	s->cirrus_bank_limit[bank_index] = 0;
    }
}



static int cirrus_vga_read_sr(CirrusVGAState * s)
{
    switch (s->vga.sr_index) {
    case 0x00:			
    case 0x01:			
    case 0x02:			
    case 0x03:			
    case 0x04:			
	return s->vga.sr[s->vga.sr_index];
    case 0x06:			
	return s->vga.sr[s->vga.sr_index];
    case 0x10:
    case 0x30:
    case 0x50:
    case 0x70:			
    case 0x90:
    case 0xb0:
    case 0xd0:
    case 0xf0:			
	return s->vga.sr[0x10];
    case 0x11:
    case 0x31:
    case 0x51:
    case 0x71:			
    case 0x91:
    case 0xb1:
    case 0xd1:
    case 0xf1:			
	return s->vga.sr[0x11];
    case 0x05:			
    case 0x07:			
    case 0x08:			
    case 0x09:			
    case 0x0a:			
    case 0x0b:			
    case 0x0c:			
    case 0x0d:			
    case 0x0e:			
    case 0x0f:			
    case 0x12:			
    case 0x13:			
    case 0x14:			
    case 0x15:			
    case 0x16:			
    case 0x17:			
    case 0x18:			
    case 0x19:			
    case 0x1a:			
    case 0x1b:			
    case 0x1c:			
    case 0x1d:			
    case 0x1e:			
    case 0x1f:			

	printf("cirrus: handled inport sr_index %02x\n", s->vga.sr_index);

	return s->vga.sr[s->vga.sr_index];
    default:

	printf("cirrus: inport sr_index %02x\n", s->vga.sr_index);

	return 0xff;
	break;
    }
}

static void cirrus_vga_write_sr(CirrusVGAState * s, uint32_t val)
{
    switch (s->vga.sr_index) {
    case 0x00:			
    case 0x01:			
    case 0x02:			
    case 0x03:			
    case 0x04:			
	s->vga.sr[s->vga.sr_index] = val & sr_mask[s->vga.sr_index];
	if (s->vga.sr_index == 1)
            s->vga.update_retrace_info(&s->vga);
        break;
    case 0x06:			
	val &= 0x17;
	if (val == 0x12) {
	    s->vga.sr[s->vga.sr_index] = 0x12;
	} else {
	    s->vga.sr[s->vga.sr_index] = 0x0f;
	}
	break;
    case 0x10:
    case 0x30:
    case 0x50:
    case 0x70:			
    case 0x90:
    case 0xb0:
    case 0xd0:
    case 0xf0:			
	s->vga.sr[0x10] = val;
        s->vga.hw_cursor_x = (val << 3) | (s->vga.sr_index >> 5);
	break;
    case 0x11:
    case 0x31:
    case 0x51:
    case 0x71:			
    case 0x91:
    case 0xb1:
    case 0xd1:
    case 0xf1:			
	s->vga.sr[0x11] = val;
        s->vga.hw_cursor_y = (val << 3) | (s->vga.sr_index >> 5);
	break;
    case 0x07:			
    cirrus_update_memory_access(s);
    case 0x08:			
    case 0x09:			
    case 0x0a:			
    case 0x0b:			
    case 0x0c:			
    case 0x0d:			
    case 0x0e:			
    case 0x0f:			
    case 0x13:			
    case 0x14:			
    case 0x15:			
    case 0x16:			
    case 0x18:			
    case 0x19:			
    case 0x1a:			
    case 0x1b:			
    case 0x1c:			
    case 0x1d:			
    case 0x1e:			
    case 0x1f:			
	s->vga.sr[s->vga.sr_index] = val;

	printf("cirrus: handled outport sr_index %02x, sr_value %02x\n", s->vga.sr_index, val);

	break;
    case 0x12:			
	s->vga.sr[0x12] = val;
        s->vga.force_shadow = !!(val & CIRRUS_CURSOR_SHOW);

        printf("cirrus: cursor ctl SR12=%02x (force shadow: %d)\n", val, s->vga.force_shadow);

        break;
    case 0x17:			
	s->vga.sr[s->vga.sr_index] = (s->vga.sr[s->vga.sr_index] & 0x38)
                                   | (val & 0xc7);
        cirrus_update_memory_access(s);
        break;
    default:

	printf("cirrus: outport sr_index %02x, sr_value %02x\n", s->vga.sr_index, val);

	break;
    }
}



static int cirrus_read_hidden_dac(CirrusVGAState * s)
{
    if (++s->cirrus_hidden_dac_lockindex == 5) {
        s->cirrus_hidden_dac_lockindex = 0;
        return s->cirrus_hidden_dac_data;
    }
    return 0xff;
}

static void cirrus_write_hidden_dac(CirrusVGAState * s, int reg_value)
{
    if (s->cirrus_hidden_dac_lockindex == 4) {
	s->cirrus_hidden_dac_data = reg_value;

	printf("cirrus: outport hidden DAC, value %02x\n", reg_value);

    }
    s->cirrus_hidden_dac_lockindex = 0;
}



static int cirrus_vga_read_palette(CirrusVGAState * s)
{
    int val;

    if ((s->vga.sr[0x12] & CIRRUS_CURSOR_HIDDENPEL)) {
        val = s->cirrus_hidden_palette[(s->vga.dac_read_index & 0x0f) * 3 + s->vga.dac_sub_index];
    } else {
        val = s->vga.palette[s->vga.dac_read_index * 3 + s->vga.dac_sub_index];
    }
    if (++s->vga.dac_sub_index == 3) {
	s->vga.dac_sub_index = 0;
	s->vga.dac_read_index++;
    }
    return val;
}

static void cirrus_vga_write_palette(CirrusVGAState * s, int reg_value)
{
    s->vga.dac_cache[s->vga.dac_sub_index] = reg_value;
    if (++s->vga.dac_sub_index == 3) {
        if ((s->vga.sr[0x12] & CIRRUS_CURSOR_HIDDENPEL)) {
            memcpy(&s->cirrus_hidden_palette[(s->vga.dac_write_index & 0x0f) * 3], s->vga.dac_cache, 3);
        } else {
            memcpy(&s->vga.palette[s->vga.dac_write_index * 3], s->vga.dac_cache, 3);
        }
        
	s->vga.dac_sub_index = 0;
	s->vga.dac_write_index++;
    }
}



static int cirrus_vga_read_gr(CirrusVGAState * s, unsigned reg_index)
{
    switch (reg_index) {
    case 0x00: 
        return s->cirrus_shadow_gr0;
    case 0x01: 
        return s->cirrus_shadow_gr1;
    case 0x02:			
    case 0x03:			
    case 0x04:			
    case 0x06:			
    case 0x07:			
    case 0x08:			
        return s->vga.gr[s->vga.gr_index];
    case 0x05:			
    default:
	break;
    }

    if (reg_index < 0x3a) {
	return s->vga.gr[reg_index];
    } else {

	printf("cirrus: inport gr_index %02x\n", reg_index);

	return 0xff;
    }
}

static void cirrus_vga_write_gr(CirrusVGAState * s, unsigned reg_index, int reg_value)
{

    printf("gr%02x: %02x\n", reg_index, reg_value);

    switch (reg_index) {
    case 0x00:			
	s->vga.gr[reg_index] = reg_value & gr_mask[reg_index];
	s->cirrus_shadow_gr0 = reg_value;
	break;
    case 0x01:			
	s->vga.gr[reg_index] = reg_value & gr_mask[reg_index];
	s->cirrus_shadow_gr1 = reg_value;
	break;
    case 0x02:			
    case 0x03:			
    case 0x04:			
    case 0x06:			
    case 0x07:			
    case 0x08:			
	s->vga.gr[reg_index] = reg_value & gr_mask[reg_index];
        break;
    case 0x05:			
	s->vga.gr[reg_index] = reg_value & 0x7f;
        cirrus_update_memory_access(s);
	break;
    case 0x09:			
    case 0x0A:			
	s->vga.gr[reg_index] = reg_value;
	cirrus_update_bank_ptr(s, 0);
	cirrus_update_bank_ptr(s, 1);
        cirrus_update_memory_access(s);
        break;
    case 0x0B:
	s->vga.gr[reg_index] = reg_value;
	cirrus_update_bank_ptr(s, 0);
	cirrus_update_bank_ptr(s, 1);
        cirrus_update_memory_access(s);
	break;
    case 0x10:			
    case 0x11:			
    case 0x12:			
    case 0x13:			
    case 0x14:			
    case 0x15:			
    case 0x20:			
    case 0x22:			
    case 0x24:			
    case 0x26:			
    case 0x28:			
    case 0x29:			
    case 0x2c:			
    case 0x2d:			
    case 0x2f:                  
    case 0x30:			
    case 0x32:			
    case 0x33:			
    case 0x34:			
    case 0x35:			
    case 0x38:			
    case 0x39:			
	s->vga.gr[reg_index] = reg_value;
	break;
    case 0x21:			
    case 0x23:			
    case 0x25:			
    case 0x27:			
	s->vga.gr[reg_index] = reg_value & 0x1f;
	break;
    case 0x2a:			
	s->vga.gr[reg_index] = reg_value & 0x3f;
        
        if (s->vga.gr[0x31] & CIRRUS_BLT_AUTOSTART) {
            cirrus_bitblt_start(s);
        }
	break;
    case 0x2e:			
	s->vga.gr[reg_index] = reg_value & 0x3f;
	break;
    case 0x31:			
	cirrus_write_bitblt(s, reg_value);
	break;
    default:

	printf("cirrus: outport gr_index %02x, gr_value %02x\n", reg_index, reg_value);

	break;
    }
}



static int cirrus_vga_read_cr(CirrusVGAState * s, unsigned reg_index)
{
    switch (reg_index) {
    case 0x00:			
    case 0x01:			
    case 0x02:			
    case 0x03:			
    case 0x04:			
    case 0x05:			
    case 0x06:			
    case 0x07:			
    case 0x08:			
    case 0x09:			
    case 0x0a:			
    case 0x0b:			
    case 0x0c:			
    case 0x0d:			
    case 0x0e:			
    case 0x0f:			
    case 0x10:			
    case 0x11:			
    case 0x12:			
    case 0x13:			
    case 0x14:			
    case 0x15:			
    case 0x16:			
    case 0x17:			
    case 0x18:			
	return s->vga.cr[s->vga.cr_index];
    case 0x24:			
        return (s->vga.ar_flip_flop << 7);
    case 0x19:			
    case 0x1a:			
    case 0x1b:			
    case 0x1c:			
    case 0x1d:			
    case 0x22:			
    case 0x25:			
    case 0x27:			
	return s->vga.cr[s->vga.cr_index];
    case 0x26:			
	return s->vga.ar_index & 0x3f;
	break;
    default:

	printf("cirrus: inport cr_index %02x\n", reg_index);

	return 0xff;
    }
}

static void cirrus_vga_write_cr(CirrusVGAState * s, int reg_value)
{
    switch (s->vga.cr_index) {
    case 0x00:			
    case 0x01:			
    case 0x02:			
    case 0x03:			
    case 0x04:			
    case 0x05:			
    case 0x06:			
    case 0x07:			
    case 0x08:			
    case 0x09:			
    case 0x0a:			
    case 0x0b:			
    case 0x0c:			
    case 0x0d:			
    case 0x0e:			
    case 0x0f:			
    case 0x10:			
    case 0x11:			
    case 0x12:			
    case 0x13:			
    case 0x14:			
    case 0x15:			
    case 0x16:			
    case 0x17:			
    case 0x18:			
	
	if ((s->vga.cr[0x11] & 0x80) && s->vga.cr_index <= 7) {
	    
	    if (s->vga.cr_index == 7)
		s->vga.cr[7] = (s->vga.cr[7] & ~0x10) | (reg_value & 0x10);
	    return;
	}
	s->vga.cr[s->vga.cr_index] = reg_value;
	switch(s->vga.cr_index) {
	case 0x00:
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
	case 0x11:
	case 0x17:
	    s->vga.update_retrace_info(&s->vga);
	    break;
	}
        break;
    case 0x19:			
    case 0x1a:			
    case 0x1b:			
    case 0x1c:			
    case 0x1d:			
	s->vga.cr[s->vga.cr_index] = reg_value;

	printf("cirrus: handled outport cr_index %02x, cr_value %02x\n", s->vga.cr_index, reg_value);

	break;
    case 0x22:			
    case 0x24:			
    case 0x26:			
    case 0x27:			
	break;
    case 0x25:			
    default:

	printf("cirrus: outport cr_index %02x, cr_value %02x\n", s->vga.cr_index, reg_value);

	break;
    }
}



static uint8_t cirrus_mmio_blt_read(CirrusVGAState * s, unsigned address)
{
    int value = 0xff;

    switch (address) {
    case (CIRRUS_MMIO_BLTBGCOLOR + 0):
	value = cirrus_vga_read_gr(s, 0x00);
	break;
    case (CIRRUS_MMIO_BLTBGCOLOR + 1):
	value = cirrus_vga_read_gr(s, 0x10);
	break;
    case (CIRRUS_MMIO_BLTBGCOLOR + 2):
	value = cirrus_vga_read_gr(s, 0x12);
	break;
    case (CIRRUS_MMIO_BLTBGCOLOR + 3):
	value = cirrus_vga_read_gr(s, 0x14);
	break;
    case (CIRRUS_MMIO_BLTFGCOLOR + 0):
	value = cirrus_vga_read_gr(s, 0x01);
	break;
    case (CIRRUS_MMIO_BLTFGCOLOR + 1):
	value = cirrus_vga_read_gr(s, 0x11);
	break;
    case (CIRRUS_MMIO_BLTFGCOLOR + 2):
	value = cirrus_vga_read_gr(s, 0x13);
	break;
    case (CIRRUS_MMIO_BLTFGCOLOR + 3):
	value = cirrus_vga_read_gr(s, 0x15);
	break;
    case (CIRRUS_MMIO_BLTWIDTH + 0):
	value = cirrus_vga_read_gr(s, 0x20);
	break;
    case (CIRRUS_MMIO_BLTWIDTH + 1):
	value = cirrus_vga_read_gr(s, 0x21);
	break;
    case (CIRRUS_MMIO_BLTHEIGHT + 0):
	value = cirrus_vga_read_gr(s, 0x22);
	break;
    case (CIRRUS_MMIO_BLTHEIGHT + 1):
	value = cirrus_vga_read_gr(s, 0x23);
	break;
    case (CIRRUS_MMIO_BLTDESTPITCH + 0):
	value = cirrus_vga_read_gr(s, 0x24);
	break;
    case (CIRRUS_MMIO_BLTDESTPITCH + 1):
	value = cirrus_vga_read_gr(s, 0x25);
	break;
    case (CIRRUS_MMIO_BLTSRCPITCH + 0):
	value = cirrus_vga_read_gr(s, 0x26);
	break;
    case (CIRRUS_MMIO_BLTSRCPITCH + 1):
	value = cirrus_vga_read_gr(s, 0x27);
	break;
    case (CIRRUS_MMIO_BLTDESTADDR + 0):
	value = cirrus_vga_read_gr(s, 0x28);
	break;
    case (CIRRUS_MMIO_BLTDESTADDR + 1):
	value = cirrus_vga_read_gr(s, 0x29);
	break;
    case (CIRRUS_MMIO_BLTDESTADDR + 2):
	value = cirrus_vga_read_gr(s, 0x2a);
	break;
    case (CIRRUS_MMIO_BLTSRCADDR + 0):
	value = cirrus_vga_read_gr(s, 0x2c);
	break;
    case (CIRRUS_MMIO_BLTSRCADDR + 1):
	value = cirrus_vga_read_gr(s, 0x2d);
	break;
    case (CIRRUS_MMIO_BLTSRCADDR + 2):
	value = cirrus_vga_read_gr(s, 0x2e);
	break;
    case CIRRUS_MMIO_BLTWRITEMASK:
	value = cirrus_vga_read_gr(s, 0x2f);
	break;
    case CIRRUS_MMIO_BLTMODE:
	value = cirrus_vga_read_gr(s, 0x30);
	break;
    case CIRRUS_MMIO_BLTROP:
	value = cirrus_vga_read_gr(s, 0x32);
	break;
    case CIRRUS_MMIO_BLTMODEEXT:
	value = cirrus_vga_read_gr(s, 0x33);
	break;
    case (CIRRUS_MMIO_BLTTRANSPARENTCOLOR + 0):
	value = cirrus_vga_read_gr(s, 0x34);
	break;
    case (CIRRUS_MMIO_BLTTRANSPARENTCOLOR + 1):
	value = cirrus_vga_read_gr(s, 0x35);
	break;
    case (CIRRUS_MMIO_BLTTRANSPARENTCOLORMASK + 0):
	value = cirrus_vga_read_gr(s, 0x38);
	break;
    case (CIRRUS_MMIO_BLTTRANSPARENTCOLORMASK + 1):
	value = cirrus_vga_read_gr(s, 0x39);
	break;
    case CIRRUS_MMIO_BLTSTATUS:
	value = cirrus_vga_read_gr(s, 0x31);
	break;
    default:

	printf("cirrus: mmio read - address 0x%04x\n", address);

	break;
    }

    trace_vga_cirrus_write_blt(address, value);
    return (uint8_t) value;
}

static void cirrus_mmio_blt_write(CirrusVGAState * s, unsigned address, uint8_t value)
{
    trace_vga_cirrus_write_blt(address, value);
    switch (address) {
    case (CIRRUS_MMIO_BLTBGCOLOR + 0):
	cirrus_vga_write_gr(s, 0x00, value);
	break;
    case (CIRRUS_MMIO_BLTBGCOLOR + 1):
	cirrus_vga_write_gr(s, 0x10, value);
	break;
    case (CIRRUS_MMIO_BLTBGCOLOR + 2):
	cirrus_vga_write_gr(s, 0x12, value);
	break;
    case (CIRRUS_MMIO_BLTBGCOLOR + 3):
	cirrus_vga_write_gr(s, 0x14, value);
	break;
    case (CIRRUS_MMIO_BLTFGCOLOR + 0):
	cirrus_vga_write_gr(s, 0x01, value);
	break;
    case (CIRRUS_MMIO_BLTFGCOLOR + 1):
	cirrus_vga_write_gr(s, 0x11, value);
	break;
    case (CIRRUS_MMIO_BLTFGCOLOR + 2):
	cirrus_vga_write_gr(s, 0x13, value);
	break;
    case (CIRRUS_MMIO_BLTFGCOLOR + 3):
	cirrus_vga_write_gr(s, 0x15, value);
	break;
    case (CIRRUS_MMIO_BLTWIDTH + 0):
	cirrus_vga_write_gr(s, 0x20, value);
	break;
    case (CIRRUS_MMIO_BLTWIDTH + 1):
	cirrus_vga_write_gr(s, 0x21, value);
	break;
    case (CIRRUS_MMIO_BLTHEIGHT + 0):
	cirrus_vga_write_gr(s, 0x22, value);
	break;
    case (CIRRUS_MMIO_BLTHEIGHT + 1):
	cirrus_vga_write_gr(s, 0x23, value);
	break;
    case (CIRRUS_MMIO_BLTDESTPITCH + 0):
	cirrus_vga_write_gr(s, 0x24, value);
	break;
    case (CIRRUS_MMIO_BLTDESTPITCH + 1):
	cirrus_vga_write_gr(s, 0x25, value);
	break;
    case (CIRRUS_MMIO_BLTSRCPITCH + 0):
	cirrus_vga_write_gr(s, 0x26, value);
	break;
    case (CIRRUS_MMIO_BLTSRCPITCH + 1):
	cirrus_vga_write_gr(s, 0x27, value);
	break;
    case (CIRRUS_MMIO_BLTDESTADDR + 0):
	cirrus_vga_write_gr(s, 0x28, value);
	break;
    case (CIRRUS_MMIO_BLTDESTADDR + 1):
	cirrus_vga_write_gr(s, 0x29, value);
	break;
    case (CIRRUS_MMIO_BLTDESTADDR + 2):
	cirrus_vga_write_gr(s, 0x2a, value);
	break;
    case (CIRRUS_MMIO_BLTDESTADDR + 3):
	
	break;
    case (CIRRUS_MMIO_BLTSRCADDR + 0):
	cirrus_vga_write_gr(s, 0x2c, value);
	break;
    case (CIRRUS_MMIO_BLTSRCADDR + 1):
	cirrus_vga_write_gr(s, 0x2d, value);
	break;
    case (CIRRUS_MMIO_BLTSRCADDR + 2):
	cirrus_vga_write_gr(s, 0x2e, value);
	break;
    case CIRRUS_MMIO_BLTWRITEMASK:
	cirrus_vga_write_gr(s, 0x2f, value);
	break;
    case CIRRUS_MMIO_BLTMODE:
	cirrus_vga_write_gr(s, 0x30, value);
	break;
    case CIRRUS_MMIO_BLTROP:
	cirrus_vga_write_gr(s, 0x32, value);
	break;
    case CIRRUS_MMIO_BLTMODEEXT:
	cirrus_vga_write_gr(s, 0x33, value);
	break;
    case (CIRRUS_MMIO_BLTTRANSPARENTCOLOR + 0):
	cirrus_vga_write_gr(s, 0x34, value);
	break;
    case (CIRRUS_MMIO_BLTTRANSPARENTCOLOR + 1):
	cirrus_vga_write_gr(s, 0x35, value);
	break;
    case (CIRRUS_MMIO_BLTTRANSPARENTCOLORMASK + 0):
	cirrus_vga_write_gr(s, 0x38, value);
	break;
    case (CIRRUS_MMIO_BLTTRANSPARENTCOLORMASK + 1):
	cirrus_vga_write_gr(s, 0x39, value);
	break;
    case CIRRUS_MMIO_BLTSTATUS:
	cirrus_vga_write_gr(s, 0x31, value);
	break;
    default:

	printf("cirrus: mmio write - addr 0x%04x val 0x%02x (ignored)\n", address, value);

	break;
    }
}



static void cirrus_mem_writeb_mode4and5_8bpp(CirrusVGAState * s, unsigned mode, unsigned offset, uint32_t mem_value)


{
    int x;
    unsigned val = mem_value;
    uint8_t *dst;

    dst = s->vga.vram_ptr + (offset &= s->cirrus_addr_mask);
    for (x = 0; x < 8; x++) {
	if (val & 0x80) {
	    *dst = s->cirrus_shadow_gr1;
	} else if (mode == 5) {
	    *dst = s->cirrus_shadow_gr0;
	}
	val <<= 1;
	dst++;
    }
    memory_region_set_dirty(&s->vga.vram, offset, 8);
}

static void cirrus_mem_writeb_mode4and5_16bpp(CirrusVGAState * s, unsigned mode, unsigned offset, uint32_t mem_value)


{
    int x;
    unsigned val = mem_value;
    uint8_t *dst;

    dst = s->vga.vram_ptr + (offset &= s->cirrus_addr_mask);
    for (x = 0; x < 8; x++) {
	if (val & 0x80) {
	    *dst = s->cirrus_shadow_gr1;
	    *(dst + 1) = s->vga.gr[0x11];
	} else if (mode == 5) {
	    *dst = s->cirrus_shadow_gr0;
	    *(dst + 1) = s->vga.gr[0x10];
	}
	val <<= 1;
	dst += 2;
    }
    memory_region_set_dirty(&s->vga.vram, offset, 16);
}



static uint64_t cirrus_vga_mem_read(void *opaque, hwaddr addr, uint32_t size)

{
    CirrusVGAState *s = opaque;
    unsigned bank_index;
    unsigned bank_offset;
    uint32_t val;

    if ((s->vga.sr[0x07] & 0x01) == 0) {
        return vga_mem_readb(&s->vga, addr);
    }

    if (addr < 0x10000) {
	
	
	bank_index = addr >> 15;
	bank_offset = addr & 0x7fff;
	if (bank_offset < s->cirrus_bank_limit[bank_index]) {
	    bank_offset += s->cirrus_bank_base[bank_index];
	    if ((s->vga.gr[0x0B] & 0x14) == 0x14) {
		bank_offset <<= 4;
	    } else if (s->vga.gr[0x0B] & 0x02) {
		bank_offset <<= 3;
	    }
	    bank_offset &= s->cirrus_addr_mask;
	    val = *(s->vga.vram_ptr + bank_offset);
	} else val = 0xff;
    } else if (addr >= 0x18000 && addr < 0x18100) {
	
	val = 0xff;
	if ((s->vga.sr[0x17] & 0x44) == 0x04) {
	    val = cirrus_mmio_blt_read(s, addr & 0xff);
	}
    } else {
	val = 0xff;

	printf("cirrus: mem_readb " TARGET_FMT_plx "\n", addr);

    }
    return val;
}

static void cirrus_vga_mem_write(void *opaque, hwaddr addr, uint64_t mem_value, uint32_t size)


{
    CirrusVGAState *s = opaque;
    unsigned bank_index;
    unsigned bank_offset;
    unsigned mode;

    if ((s->vga.sr[0x07] & 0x01) == 0) {
        vga_mem_writeb(&s->vga, addr, mem_value);
        return;
    }

    if (addr < 0x10000) {
	if (s->cirrus_srcptr != s->cirrus_srcptr_end) {
	    
	    *s->cirrus_srcptr++ = (uint8_t) mem_value;
	    if (s->cirrus_srcptr >= s->cirrus_srcptr_end) {
		cirrus_bitblt_cputovideo_next(s);
	    }
	} else {
	    
	    bank_index = addr >> 15;
	    bank_offset = addr & 0x7fff;
	    if (bank_offset < s->cirrus_bank_limit[bank_index]) {
		bank_offset += s->cirrus_bank_base[bank_index];
		if ((s->vga.gr[0x0B] & 0x14) == 0x14) {
		    bank_offset <<= 4;
		} else if (s->vga.gr[0x0B] & 0x02) {
		    bank_offset <<= 3;
		}
		bank_offset &= s->cirrus_addr_mask;
		mode = s->vga.gr[0x05] & 0x7;
		if (mode < 4 || mode > 5 || ((s->vga.gr[0x0B] & 0x4) == 0)) {
		    *(s->vga.vram_ptr + bank_offset) = mem_value;
                    memory_region_set_dirty(&s->vga.vram, bank_offset, sizeof(mem_value));
		} else {
		    if ((s->vga.gr[0x0B] & 0x14) != 0x14) {
			cirrus_mem_writeb_mode4and5_8bpp(s, mode, bank_offset, mem_value);

		    } else {
			cirrus_mem_writeb_mode4and5_16bpp(s, mode, bank_offset, mem_value);

		    }
		}
	    }
	}
    } else if (addr >= 0x18000 && addr < 0x18100) {
	
	if ((s->vga.sr[0x17] & 0x44) == 0x04) {
	    cirrus_mmio_blt_write(s, addr & 0xff, mem_value);
	}
    } else {

        printf("cirrus: mem_writeb " TARGET_FMT_plx " value 0x%02" PRIu64 "\n", addr, mem_value);

    }
}

static const MemoryRegionOps cirrus_vga_mem_ops = {
    .read = cirrus_vga_mem_read, .write = cirrus_vga_mem_write, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 1, .max_access_size = 1, }, };





static inline void invalidate_cursor1(CirrusVGAState *s)
{
    if (s->last_hw_cursor_size) {
        vga_invalidate_scanlines(&s->vga, s->last_hw_cursor_y + s->last_hw_cursor_y_start, s->last_hw_cursor_y + s->last_hw_cursor_y_end);

    }
}

static inline void cirrus_cursor_compute_yrange(CirrusVGAState *s)
{
    const uint8_t *src;
    uint32_t content;
    int y, y_min, y_max;

    src = s->vga.vram_ptr + s->real_vram_size - 16 * 1024;
    if (s->vga.sr[0x12] & CIRRUS_CURSOR_LARGE) {
        src += (s->vga.sr[0x13] & 0x3c) * 256;
        y_min = 64;
        y_max = -1;
        for(y = 0; y < 64; y++) {
            content = ((uint32_t *)src)[0] | ((uint32_t *)src)[1] | ((uint32_t *)src)[2] | ((uint32_t *)src)[3];


            if (content) {
                if (y < y_min)
                    y_min = y;
                if (y > y_max)
                    y_max = y;
            }
            src += 16;
        }
    } else {
        src += (s->vga.sr[0x13] & 0x3f) * 256;
        y_min = 32;
        y_max = -1;
        for(y = 0; y < 32; y++) {
            content = ((uint32_t *)src)[0] | ((uint32_t *)(src + 128))[0];
            if (content) {
                if (y < y_min)
                    y_min = y;
                if (y > y_max)
                    y_max = y;
            }
            src += 4;
        }
    }
    if (y_min > y_max) {
        s->last_hw_cursor_y_start = 0;
        s->last_hw_cursor_y_end = 0;
    } else {
        s->last_hw_cursor_y_start = y_min;
        s->last_hw_cursor_y_end = y_max + 1;
    }
}


static void cirrus_cursor_invalidate(VGACommonState *s1)
{
    CirrusVGAState *s = container_of(s1, CirrusVGAState, vga);
    int size;

    if (!(s->vga.sr[0x12] & CIRRUS_CURSOR_SHOW)) {
        size = 0;
    } else {
        if (s->vga.sr[0x12] & CIRRUS_CURSOR_LARGE)
            size = 64;
        else size = 32;
    }
    
    if (s->last_hw_cursor_size != size || s->last_hw_cursor_x != s->vga.hw_cursor_x || s->last_hw_cursor_y != s->vga.hw_cursor_y) {


        invalidate_cursor1(s);

        s->last_hw_cursor_size = size;
        s->last_hw_cursor_x = s->vga.hw_cursor_x;
        s->last_hw_cursor_y = s->vga.hw_cursor_y;
        
        cirrus_cursor_compute_yrange(s);
        invalidate_cursor1(s);
    }
}

static void vga_draw_cursor_line(uint8_t *d1, const uint8_t *src1, int poffset, int w, unsigned int color0, unsigned int color1, unsigned int color_xor)




{
    const uint8_t *plane0, *plane1;
    int x, b0, b1;
    uint8_t *d;

    d = d1;
    plane0 = src1;
    plane1 = src1 + poffset;
    for (x = 0; x < w; x++) {
        b0 = (plane0[x >> 3] >> (7 - (x & 7))) & 1;
        b1 = (plane1[x >> 3] >> (7 - (x & 7))) & 1;
        switch (b0 | (b1 << 1)) {
        case 0:
            break;
        case 1:
            ((uint32_t *)d)[0] ^= color_xor;
            break;
        case 2:
            ((uint32_t *)d)[0] = color0;
            break;
        case 3:
            ((uint32_t *)d)[0] = color1;
            break;
        }
        d += 4;
    }
}

static void cirrus_cursor_draw_line(VGACommonState *s1, uint8_t *d1, int scr_y)
{
    CirrusVGAState *s = container_of(s1, CirrusVGAState, vga);
    int w, h, x1, x2, poffset;
    unsigned int color0, color1;
    const uint8_t *palette, *src;
    uint32_t content;

    if (!(s->vga.sr[0x12] & CIRRUS_CURSOR_SHOW))
        return;
    
    if (s->vga.sr[0x12] & CIRRUS_CURSOR_LARGE) {
        h = 64;
    } else {
        h = 32;
    }
    if (scr_y < s->vga.hw_cursor_y || scr_y >= (s->vga.hw_cursor_y + h)) {
        return;
    }

    src = s->vga.vram_ptr + s->real_vram_size - 16 * 1024;
    if (s->vga.sr[0x12] & CIRRUS_CURSOR_LARGE) {
        src += (s->vga.sr[0x13] & 0x3c) * 256;
        src += (scr_y - s->vga.hw_cursor_y) * 16;
        poffset = 8;
        content = ((uint32_t *)src)[0] | ((uint32_t *)src)[1] | ((uint32_t *)src)[2] | ((uint32_t *)src)[3];


    } else {
        src += (s->vga.sr[0x13] & 0x3f) * 256;
        src += (scr_y - s->vga.hw_cursor_y) * 4;


        poffset = 128;
        content = ((uint32_t *)src)[0] | ((uint32_t *)(src + 128))[0];
    }
    
    if (!content)
        return;
    w = h;

    x1 = s->vga.hw_cursor_x;
    if (x1 >= s->vga.last_scr_width)
        return;
    x2 = s->vga.hw_cursor_x + w;
    if (x2 > s->vga.last_scr_width)
        x2 = s->vga.last_scr_width;
    w = x2 - x1;
    palette = s->cirrus_hidden_palette;
    color0 = rgb_to_pixel32(c6_to_8(palette[0x0 * 3]), c6_to_8(palette[0x0 * 3 + 1]), c6_to_8(palette[0x0 * 3 + 2]));

    color1 = rgb_to_pixel32(c6_to_8(palette[0xf * 3]), c6_to_8(palette[0xf * 3 + 1]), c6_to_8(palette[0xf * 3 + 2]));

    d1 += x1 * 4;
    vga_draw_cursor_line(d1, src, poffset, w, color0, color1, 0xffffff);
}



static uint64_t cirrus_linear_read(void *opaque, hwaddr addr, unsigned size)
{
    CirrusVGAState *s = opaque;
    uint32_t ret;

    addr &= s->cirrus_addr_mask;

    if (((s->vga.sr[0x17] & 0x44) == 0x44) && ((addr & s->linear_mmio_mask) == s->linear_mmio_mask)) {
	
	ret = cirrus_mmio_blt_read(s, addr & 0xff);
    } else if (0) {
	
	ret = 0xff;
    } else {
	
	if ((s->vga.gr[0x0B] & 0x14) == 0x14) {
	    addr <<= 4;
	} else if (s->vga.gr[0x0B] & 0x02) {
	    addr <<= 3;
	}
	addr &= s->cirrus_addr_mask;
	ret = *(s->vga.vram_ptr + addr);
    }

    return ret;
}

static void cirrus_linear_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    CirrusVGAState *s = opaque;
    unsigned mode;

    addr &= s->cirrus_addr_mask;

    if (((s->vga.sr[0x17] & 0x44) == 0x44) && ((addr & s->linear_mmio_mask) ==  s->linear_mmio_mask)) {
	
	cirrus_mmio_blt_write(s, addr & 0xff, val);
    } else if (s->cirrus_srcptr != s->cirrus_srcptr_end) {
	
	*s->cirrus_srcptr++ = (uint8_t) val;
	if (s->cirrus_srcptr >= s->cirrus_srcptr_end) {
	    cirrus_bitblt_cputovideo_next(s);
	}
    } else {
	
	if ((s->vga.gr[0x0B] & 0x14) == 0x14) {
	    addr <<= 4;
	} else if (s->vga.gr[0x0B] & 0x02) {
	    addr <<= 3;
	}
	addr &= s->cirrus_addr_mask;

	mode = s->vga.gr[0x05] & 0x7;
	if (mode < 4 || mode > 5 || ((s->vga.gr[0x0B] & 0x4) == 0)) {
	    *(s->vga.vram_ptr + addr) = (uint8_t) val;
            memory_region_set_dirty(&s->vga.vram, addr, 1);
	} else {
	    if ((s->vga.gr[0x0B] & 0x14) != 0x14) {
		cirrus_mem_writeb_mode4and5_8bpp(s, mode, addr, val);
	    } else {
		cirrus_mem_writeb_mode4and5_16bpp(s, mode, addr, val);
	    }
	}
    }
}




static uint64_t cirrus_linear_bitblt_read(void *opaque, hwaddr addr, unsigned size)

{
    CirrusVGAState *s = opaque;
    uint32_t ret;

    
    (void)s;
    ret = 0xff;
    return ret;
}

static void cirrus_linear_bitblt_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)


{
    CirrusVGAState *s = opaque;

    if (s->cirrus_srcptr != s->cirrus_srcptr_end) {
	
	*s->cirrus_srcptr++ = (uint8_t) val;
	if (s->cirrus_srcptr >= s->cirrus_srcptr_end) {
	    cirrus_bitblt_cputovideo_next(s);
	}
    }
}

static const MemoryRegionOps cirrus_linear_bitblt_io_ops = {
    .read = cirrus_linear_bitblt_read, .write = cirrus_linear_bitblt_write, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 1, .max_access_size = 1, }, };



static void map_linear_vram_bank(CirrusVGAState *s, unsigned bank)
{
    MemoryRegion *mr = &s->cirrus_bank[bank];
    bool enabled = !(s->cirrus_srcptr != s->cirrus_srcptr_end)
        && !((s->vga.sr[0x07] & 0x01) == 0)
        && !((s->vga.gr[0x0B] & 0x14) == 0x14)
        && !(s->vga.gr[0x0B] & 0x02);

    memory_region_set_enabled(mr, enabled);
    memory_region_set_alias_offset(mr, s->cirrus_bank_base[bank]);
}

static void map_linear_vram(CirrusVGAState *s)
{
    if (s->bustype == CIRRUS_BUSTYPE_PCI && !s->linear_vram) {
        s->linear_vram = true;
        memory_region_add_subregion_overlap(&s->pci_bar, 0, &s->vga.vram, 1);
    }
    map_linear_vram_bank(s, 0);
    map_linear_vram_bank(s, 1);
}

static void unmap_linear_vram(CirrusVGAState *s)
{
    if (s->bustype == CIRRUS_BUSTYPE_PCI && s->linear_vram) {
        s->linear_vram = false;
        memory_region_del_subregion(&s->pci_bar, &s->vga.vram);
    }
    memory_region_set_enabled(&s->cirrus_bank[0], false);
    memory_region_set_enabled(&s->cirrus_bank[1], false);
}


static void cirrus_update_memory_access(CirrusVGAState *s)
{
    unsigned mode;

    memory_region_transaction_begin();
    if ((s->vga.sr[0x17] & 0x44) == 0x44) {
        goto generic_io;
    } else if (s->cirrus_srcptr != s->cirrus_srcptr_end) {
        goto generic_io;
    } else {
	if ((s->vga.gr[0x0B] & 0x14) == 0x14) {
            goto generic_io;
	} else if (s->vga.gr[0x0B] & 0x02) {
            goto generic_io;
        }

	mode = s->vga.gr[0x05] & 0x7;
	if (mode < 4 || mode > 5 || ((s->vga.gr[0x0B] & 0x4) == 0)) {
            map_linear_vram(s);
        } else {
        generic_io:
            unmap_linear_vram(s);
        }
    }
    memory_region_transaction_commit();
}




static uint64_t cirrus_vga_ioport_read(void *opaque, hwaddr addr, unsigned size)
{
    CirrusVGAState *c = opaque;
    VGACommonState *s = &c->vga;
    int val, index;

    addr += 0x3b0;

    if (vga_ioport_invalid(s, addr)) {
	val = 0xff;
    } else {
	switch (addr) {
	case 0x3c0:
	    if (s->ar_flip_flop == 0) {
		val = s->ar_index;
	    } else {
		val = 0;
	    }
	    break;
	case 0x3c1:
	    index = s->ar_index & 0x1f;
	    if (index < 21)
		val = s->ar[index];
	    else val = 0;
	    break;
	case 0x3c2:
	    val = s->st00;
	    break;
	case 0x3c4:
	    val = s->sr_index;
	    break;
	case 0x3c5:
	    val = cirrus_vga_read_sr(c);
            break;

	    printf("vga: read SR%x = 0x%02x\n", s->sr_index, val);

	    break;
	case 0x3c6:
	    val = cirrus_read_hidden_dac(c);
	    break;
	case 0x3c7:
	    val = s->dac_state;
	    break;
	case 0x3c8:
	    val = s->dac_write_index;
	    c->cirrus_hidden_dac_lockindex = 0;
	    break;
        case 0x3c9:
            val = cirrus_vga_read_palette(c);
            break;
	case 0x3ca:
	    val = s->fcr;
	    break;
	case 0x3cc:
	    val = s->msr;
	    break;
	case 0x3ce:
	    val = s->gr_index;
	    break;
	case 0x3cf:
	    val = cirrus_vga_read_gr(c, s->gr_index);

	    printf("vga: read GR%x = 0x%02x\n", s->gr_index, val);

	    break;
	case 0x3b4:
	case 0x3d4:
	    val = s->cr_index;
	    break;
	case 0x3b5:
	case 0x3d5:
            val = cirrus_vga_read_cr(c, s->cr_index);

	    printf("vga: read CR%x = 0x%02x\n", s->cr_index, val);

	    break;
	case 0x3ba:
	case 0x3da:
	    
	    val = s->st01 = s->retrace(s);
	    s->ar_flip_flop = 0;
	    break;
	default:
	    val = 0x00;
	    break;
	}
    }
    trace_vga_cirrus_read_io(addr, val);
    return val;
}

static void cirrus_vga_ioport_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    CirrusVGAState *c = opaque;
    VGACommonState *s = &c->vga;
    int index;

    addr += 0x3b0;

    
    if (vga_ioport_invalid(s, addr)) {
	return;
    }
    trace_vga_cirrus_write_io(addr, val);

    switch (addr) {
    case 0x3c0:
	if (s->ar_flip_flop == 0) {
	    val &= 0x3f;
	    s->ar_index = val;
	} else {
	    index = s->ar_index & 0x1f;
	    switch (index) {
	    case 0x00 ... 0x0f:
		s->ar[index] = val & 0x3f;
		break;
	    case 0x10:
		s->ar[index] = val & ~0x10;
		break;
	    case 0x11:
		s->ar[index] = val;
		break;
	    case 0x12:
		s->ar[index] = val & ~0xc0;
		break;
	    case 0x13:
		s->ar[index] = val & ~0xf0;
		break;
	    case 0x14:
		s->ar[index] = val & ~0xf0;
		break;
	    default:
		break;
	    }
	}
	s->ar_flip_flop ^= 1;
	break;
    case 0x3c2:
	s->msr = val & ~0x10;
	s->update_retrace_info(s);
	break;
    case 0x3c4:
	s->sr_index = val;
	break;
    case 0x3c5:

	printf("vga: write SR%x = 0x%02" PRIu64 "\n", s->sr_index, val);

	cirrus_vga_write_sr(c, val);
        break;
    case 0x3c6:
	cirrus_write_hidden_dac(c, val);
	break;
    case 0x3c7:
	s->dac_read_index = val;
	s->dac_sub_index = 0;
	s->dac_state = 3;
	break;
    case 0x3c8:
	s->dac_write_index = val;
	s->dac_sub_index = 0;
	s->dac_state = 0;
	break;
    case 0x3c9:
        cirrus_vga_write_palette(c, val);
        break;
    case 0x3ce:
	s->gr_index = val;
	break;
    case 0x3cf:

	printf("vga: write GR%x = 0x%02" PRIu64 "\n", s->gr_index, val);

	cirrus_vga_write_gr(c, s->gr_index, val);
	break;
    case 0x3b4:
    case 0x3d4:
	s->cr_index = val;
	break;
    case 0x3b5:
    case 0x3d5:

	printf("vga: write CR%x = 0x%02"PRIu64"\n", s->cr_index, val);

	cirrus_vga_write_cr(c, val);
	break;
    case 0x3ba:
    case 0x3da:
	s->fcr = val & 0x10;
	break;
    }
}



static uint64_t cirrus_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    CirrusVGAState *s = opaque;

    if (addr >= 0x100) {
        return cirrus_mmio_blt_read(s, addr - 0x100);
    } else {
        return cirrus_vga_ioport_read(s, addr + 0x10, size);
    }
}

static void cirrus_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    CirrusVGAState *s = opaque;

    if (addr >= 0x100) {
	cirrus_mmio_blt_write(s, addr - 0x100, val);
    } else {
        cirrus_vga_ioport_write(s, addr + 0x10, val, size);
    }
}

static const MemoryRegionOps cirrus_mmio_io_ops = {
    .read = cirrus_mmio_read, .write = cirrus_mmio_write, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 1, .max_access_size = 1, }, };





static int cirrus_post_load(void *opaque, int version_id)
{
    CirrusVGAState *s = opaque;

    s->vga.gr[0x00] = s->cirrus_shadow_gr0 & 0x0f;
    s->vga.gr[0x01] = s->cirrus_shadow_gr1 & 0x0f;

    cirrus_update_memory_access(s);
    
    s->vga.graphic_mode = -1;
    cirrus_update_bank_ptr(s, 0);
    cirrus_update_bank_ptr(s, 1);
    return 0;
}

static const VMStateDescription vmstate_cirrus_vga = {
    .name = "cirrus_vga", .version_id = 2, .minimum_version_id = 1, .post_load = cirrus_post_load, .fields = (VMStateField[]) {



        VMSTATE_UINT32(vga.latch, CirrusVGAState), VMSTATE_UINT8(vga.sr_index, CirrusVGAState), VMSTATE_BUFFER(vga.sr, CirrusVGAState), VMSTATE_UINT8(vga.gr_index, CirrusVGAState), VMSTATE_UINT8(cirrus_shadow_gr0, CirrusVGAState), VMSTATE_UINT8(cirrus_shadow_gr1, CirrusVGAState), VMSTATE_BUFFER_START_MIDDLE(vga.gr, CirrusVGAState, 2), VMSTATE_UINT8(vga.ar_index, CirrusVGAState), VMSTATE_BUFFER(vga.ar, CirrusVGAState), VMSTATE_INT32(vga.ar_flip_flop, CirrusVGAState), VMSTATE_UINT8(vga.cr_index, CirrusVGAState), VMSTATE_BUFFER(vga.cr, CirrusVGAState), VMSTATE_UINT8(vga.msr, CirrusVGAState), VMSTATE_UINT8(vga.fcr, CirrusVGAState), VMSTATE_UINT8(vga.st00, CirrusVGAState), VMSTATE_UINT8(vga.st01, CirrusVGAState), VMSTATE_UINT8(vga.dac_state, CirrusVGAState), VMSTATE_UINT8(vga.dac_sub_index, CirrusVGAState), VMSTATE_UINT8(vga.dac_read_index, CirrusVGAState), VMSTATE_UINT8(vga.dac_write_index, CirrusVGAState), VMSTATE_BUFFER(vga.dac_cache, CirrusVGAState), VMSTATE_BUFFER(vga.palette, CirrusVGAState), VMSTATE_INT32(vga.bank_offset, CirrusVGAState), VMSTATE_UINT8(cirrus_hidden_dac_lockindex, CirrusVGAState), VMSTATE_UINT8(cirrus_hidden_dac_data, CirrusVGAState), VMSTATE_UINT32(vga.hw_cursor_x, CirrusVGAState), VMSTATE_UINT32(vga.hw_cursor_y, CirrusVGAState),  VMSTATE_END_OF_LIST()



























    }
};

static const VMStateDescription vmstate_pci_cirrus_vga = {
    .name = "cirrus_vga", .version_id = 2, .minimum_version_id = 2, .fields = (VMStateField[]) {


        VMSTATE_PCI_DEVICE(dev, PCICirrusVGAState), VMSTATE_STRUCT(cirrus_vga, PCICirrusVGAState, 0, vmstate_cirrus_vga, CirrusVGAState), VMSTATE_END_OF_LIST()


    }
};



static void cirrus_reset(void *opaque)
{
    CirrusVGAState *s = opaque;

    vga_common_reset(&s->vga);
    unmap_linear_vram(s);
    s->vga.sr[0x06] = 0x0f;
    if (s->device_id == CIRRUS_ID_CLGD5446) {
        
        s->vga.sr[0x1F] = 0x2d;		
        s->vga.gr[0x18] = 0x0f;             
        s->vga.sr[0x0f] = 0x98;
        s->vga.sr[0x17] = 0x20;
        s->vga.sr[0x15] = 0x04; 
    } else {
        s->vga.sr[0x1F] = 0x22;		
        s->vga.sr[0x0F] = CIRRUS_MEMSIZE_2M;
        s->vga.sr[0x17] = s->bustype;
        s->vga.sr[0x15] = 0x03; 
    }
    s->vga.cr[0x27] = s->device_id;

    s->cirrus_hidden_dac_lockindex = 5;
    s->cirrus_hidden_dac_data = 0;
}

static const MemoryRegionOps cirrus_linear_io_ops = {
    .read = cirrus_linear_read, .write = cirrus_linear_write, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 1, .max_access_size = 1, }, };



static const MemoryRegionOps cirrus_vga_io_ops = {
    .read = cirrus_vga_ioport_read, .write = cirrus_vga_ioport_write, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 1, .max_access_size = 1, }, };



static void cirrus_init_common(CirrusVGAState *s, Object *owner, int device_id, int is_pci, MemoryRegion *system_memory, MemoryRegion *system_io)


{
    int i;
    static int inited;

    if (!inited) {
        inited = 1;
        for(i = 0;i < 256; i++)
            rop_to_index[i] = CIRRUS_ROP_NOP_INDEX; 
        rop_to_index[CIRRUS_ROP_0] = 0;
        rop_to_index[CIRRUS_ROP_SRC_AND_DST] = 1;
        rop_to_index[CIRRUS_ROP_NOP] = 2;
        rop_to_index[CIRRUS_ROP_SRC_AND_NOTDST] = 3;
        rop_to_index[CIRRUS_ROP_NOTDST] = 4;
        rop_to_index[CIRRUS_ROP_SRC] = 5;
        rop_to_index[CIRRUS_ROP_1] = 6;
        rop_to_index[CIRRUS_ROP_NOTSRC_AND_DST] = 7;
        rop_to_index[CIRRUS_ROP_SRC_XOR_DST] = 8;
        rop_to_index[CIRRUS_ROP_SRC_OR_DST] = 9;
        rop_to_index[CIRRUS_ROP_NOTSRC_OR_NOTDST] = 10;
        rop_to_index[CIRRUS_ROP_SRC_NOTXOR_DST] = 11;
        rop_to_index[CIRRUS_ROP_SRC_OR_NOTDST] = 12;
        rop_to_index[CIRRUS_ROP_NOTSRC] = 13;
        rop_to_index[CIRRUS_ROP_NOTSRC_OR_DST] = 14;
        rop_to_index[CIRRUS_ROP_NOTSRC_AND_NOTDST] = 15;
        s->device_id = device_id;
        if (is_pci)
            s->bustype = CIRRUS_BUSTYPE_PCI;
        else s->bustype = CIRRUS_BUSTYPE_ISA;
    }

    
    memory_region_init_io(&s->cirrus_vga_io, owner, &cirrus_vga_io_ops, s, "cirrus-io", 0x30);
    memory_region_set_flush_coalesced(&s->cirrus_vga_io);
    memory_region_add_subregion(system_io, 0x3b0, &s->cirrus_vga_io);

    memory_region_init(&s->low_mem_container, owner, "cirrus-lowmem-container", 0x20000);


    memory_region_init_io(&s->low_mem, owner, &cirrus_vga_mem_ops, s, "cirrus-low-memory", 0x20000);
    memory_region_add_subregion(&s->low_mem_container, 0, &s->low_mem);
    for (i = 0; i < 2; ++i) {
        static const char *names[] = { "vga.bank0", "vga.bank1" };
        MemoryRegion *bank = &s->cirrus_bank[i];
        memory_region_init_alias(bank, owner, names[i], &s->vga.vram, 0, 0x8000);
        memory_region_set_enabled(bank, false);
        memory_region_add_subregion_overlap(&s->low_mem_container, i * 0x8000, bank, 1);
    }
    memory_region_add_subregion_overlap(system_memory, 0x000a0000, &s->low_mem_container, 1);


    memory_region_set_coalescing(&s->low_mem);

    
    memory_region_init_io(&s->cirrus_linear_io, owner, &cirrus_linear_io_ops, s, "cirrus-linear-io", s->vga.vram_size_mb * 1024 * 1024);

    memory_region_set_flush_coalesced(&s->cirrus_linear_io);

    
    memory_region_init_io(&s->cirrus_linear_bitblt_io, owner, &cirrus_linear_bitblt_io_ops, s, "cirrus-bitblt-mmio", 0x400000);



    memory_region_set_flush_coalesced(&s->cirrus_linear_bitblt_io);

    
    memory_region_init_io(&s->cirrus_mmio_io, owner, &cirrus_mmio_io_ops, s, "cirrus-mmio", CIRRUS_PNPMMIO_SIZE);
    memory_region_set_flush_coalesced(&s->cirrus_mmio_io);

    s->real_vram_size = (s->device_id == CIRRUS_ID_CLGD5446) ? 4096 * 1024 : 2048 * 1024;

    
    s->cirrus_addr_mask = s->real_vram_size - 1;
    s->linear_mmio_mask = s->real_vram_size - 256;

    s->vga.get_bpp = cirrus_get_bpp;
    s->vga.get_offsets = cirrus_get_offsets;
    s->vga.get_resolution = cirrus_get_resolution;
    s->vga.cursor_invalidate = cirrus_cursor_invalidate;
    s->vga.cursor_draw_line = cirrus_cursor_draw_line;

    qemu_register_reset(cirrus_reset, s);
}



static void isa_cirrus_vga_realizefn(DeviceState *dev, Error **errp)
{
    ISADevice *isadev = ISA_DEVICE(dev);
    ISACirrusVGAState *d = ISA_CIRRUS_VGA(dev);
    VGACommonState *s = &d->cirrus_vga.vga;

    
    if (s->vram_size_mb != 4 && s->vram_size_mb != 8 && s->vram_size_mb != 16) {
        error_setg(errp, "Invalid cirrus_vga ram size '%u'", s->vram_size_mb);
        return;
    }
    vga_common_init(s, OBJECT(dev), true);
    cirrus_init_common(&d->cirrus_vga, OBJECT(dev), CIRRUS_ID_CLGD5430, 0, isa_address_space(isadev), isa_address_space_io(isadev));

    s->con = graphic_console_init(dev, 0, s->hw_ops, s);
    rom_add_vga(VGABIOS_CIRRUS_FILENAME);
    
    
}

static Property isa_cirrus_vga_properties[] = {
    DEFINE_PROP_UINT32("vgamem_mb", struct ISACirrusVGAState, cirrus_vga.vga.vram_size_mb, 8), DEFINE_PROP_END_OF_LIST(), };



static void isa_cirrus_vga_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->vmsd  = &vmstate_cirrus_vga;
    dc->realize = isa_cirrus_vga_realizefn;
    dc->props = isa_cirrus_vga_properties;
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
}

static const TypeInfo isa_cirrus_vga_info = {
    .name          = TYPE_ISA_CIRRUS_VGA, .parent        = TYPE_ISA_DEVICE, .instance_size = sizeof(ISACirrusVGAState), .class_init = isa_cirrus_vga_class_init, };






static void pci_cirrus_vga_realize(PCIDevice *dev, Error **errp)
{
     PCICirrusVGAState *d = PCI_CIRRUS_VGA(dev);
     CirrusVGAState *s = &d->cirrus_vga;
     PCIDeviceClass *pc = PCI_DEVICE_GET_CLASS(dev);
     int16_t device_id = pc->device_id;

     
     if (s->vga.vram_size_mb != 4 && s->vga.vram_size_mb != 8 && s->vga.vram_size_mb != 16) {
         error_setg(errp, "Invalid cirrus_vga ram size '%u'", s->vga.vram_size_mb);
         return;
     }
     
     vga_common_init(&s->vga, OBJECT(dev), true);
     cirrus_init_common(s, OBJECT(dev), device_id, 1, pci_address_space(dev), pci_address_space_io(dev));
     s->vga.con = graphic_console_init(DEVICE(dev), 0, s->vga.hw_ops, &s->vga);

     

    memory_region_init(&s->pci_bar, OBJECT(dev), "cirrus-pci-bar0", 0x2000000);

    
    memory_region_add_subregion(&s->pci_bar, 0, &s->cirrus_linear_io);
    memory_region_add_subregion(&s->pci_bar, 0x1000000, &s->cirrus_linear_bitblt_io);

     
     
     
     
     pci_register_bar(&d->dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH, &s->pci_bar);
     if (device_id == CIRRUS_ID_CLGD5446) {
         pci_register_bar(&d->dev, 1, 0, &s->cirrus_mmio_io);
     }
}

static Property pci_vga_cirrus_properties[] = {
    DEFINE_PROP_UINT32("vgamem_mb", struct PCICirrusVGAState, cirrus_vga.vga.vram_size_mb, 8), DEFINE_PROP_END_OF_LIST(), };



static void cirrus_vga_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_cirrus_vga_realize;
    k->romfile = VGABIOS_CIRRUS_FILENAME;
    k->vendor_id = PCI_VENDOR_ID_CIRRUS;
    k->device_id = CIRRUS_ID_CLGD5446;
    k->class_id = PCI_CLASS_DISPLAY_VGA;
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    dc->desc = "Cirrus CLGD 54xx VGA";
    dc->vmsd = &vmstate_pci_cirrus_vga;
    dc->props = pci_vga_cirrus_properties;
    dc->hotpluggable = false;
}

static const TypeInfo cirrus_vga_info = {
    .name          = TYPE_PCI_CIRRUS_VGA, .parent        = TYPE_PCI_DEVICE, .instance_size = sizeof(PCICirrusVGAState), .class_init    = cirrus_vga_class_init, };




static void cirrus_vga_register_types(void)
{
    type_register_static(&isa_cirrus_vga_info);
    type_register_static(&cirrus_vga_info);
}

type_init(cirrus_vga_register_types)
