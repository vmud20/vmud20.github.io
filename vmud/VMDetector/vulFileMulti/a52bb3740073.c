



















static DEFINE_RAW_SPINLOCK(vga_lock);
static int cursor_size_lastfrom;
static int cursor_size_lastto;
static u32 vgacon_xres;
static u32 vgacon_yres;
static struct vgastate vgastate;






static const char *vgacon_startup(void);
static void vgacon_init(struct vc_data *c, int init);
static void vgacon_deinit(struct vc_data *c);
static void vgacon_cursor(struct vc_data *c, int mode);
static int vgacon_switch(struct vc_data *c);
static int vgacon_blank(struct vc_data *c, int blank, int mode_switch);
static void vgacon_scrolldelta(struct vc_data *c, int lines);
static int vgacon_set_origin(struct vc_data *c);
static void vgacon_save_screen(struct vc_data *c);
static void vgacon_invert_region(struct vc_data *c, u16 * p, int count);
static struct uni_pagedir *vgacon_uni_pagedir;
static int vgacon_refcount;


static bool		vga_init_done;
static unsigned long	vga_vram_base		__read_mostly;	
static unsigned long	vga_vram_end		__read_mostly;	
static unsigned int	vga_vram_size		__read_mostly;	
static u16		vga_video_port_reg	__read_mostly;	
static u16		vga_video_port_val	__read_mostly;	
static unsigned int	vga_video_num_columns;			
static unsigned int	vga_video_num_lines;			
static bool		vga_can_do_color;			
static unsigned int	vga_default_font_height __read_mostly;	
static unsigned char	vga_video_type		__read_mostly;	
static bool		vga_font_is_default = true;
static int		vga_vesa_blanked;
static bool 		vga_palette_blanked;
static bool 		vga_is_gfx;
static bool 		vga_512_chars;
static int 		vga_video_font_height;
static int 		vga_scan_lines		__read_mostly;
static unsigned int 	vga_rolled_over;

static bool vgacon_text_mode_force;
static bool vga_hardscroll_enabled;
static bool vga_hardscroll_user_enable = true;

bool vgacon_text_force(void)
{
	return vgacon_text_mode_force;
}
EXPORT_SYMBOL(vgacon_text_force);

static int __init text_mode(char *str)
{
	vgacon_text_mode_force = true;

	pr_warn("You have booted with nomodeset. This means your GPU drivers are DISABLED\n");
	pr_warn("Any video related functionality will be severely degraded, and you may not even be able to suspend the system properly\n");
	pr_warn("Unless you actually understand what nomodeset does, you should reboot without enabling it\n");

	return 1;
}


__setup("nomodeset", text_mode);

static int __init no_scroll(char *str)
{
	
	vga_hardscroll_user_enable = vga_hardscroll_enabled = false;
	return 1;
}

__setup("no-scroll", no_scroll);


static inline void write_vga(unsigned char reg, unsigned int val)
{
	unsigned int v1, v2;
	unsigned long flags;

	
	raw_spin_lock_irqsave(&vga_lock, flags);
	v1 = reg + (val & 0xff00);
	v2 = reg + 1 + ((val << 8) & 0xff00);
	outw(v1, vga_video_port_reg);
	outw(v2, vga_video_port_reg);
	raw_spin_unlock_irqrestore(&vga_lock, flags);
}

static inline void vga_set_mem_top(struct vc_data *c)
{
	write_vga(12, (c->vc_visible_origin - vga_vram_base) / 2);
}



struct vgacon_scrollback_info {
	void *data;
	int tail;
	int size;
	int rows;
	int cnt;
	int cur;
	int save;
	int restore;
};

static struct vgacon_scrollback_info *vgacon_scrollback_cur;
static struct vgacon_scrollback_info vgacon_scrollbacks[MAX_NR_CONSOLES];
static bool scrollback_persistent =  IS_ENABLED(CONFIG_VGACON_SOFT_SCROLLBACK_PERSISTENT_ENABLE_BY_DEFAULT)
module_param_named(scrollback_persistent, scrollback_persistent, bool, 0000);
MODULE_PARM_DESC(scrollback_persistent, "Enable persistent scrollback for all vga consoles");

static void vgacon_scrollback_reset(int vc_num, size_t reset_size)
{
	struct vgacon_scrollback_info *scrollback = &vgacon_scrollbacks[vc_num];

	if (scrollback->data && reset_size > 0)
		memset(scrollback->data, 0, reset_size);

	scrollback->cnt  = 0;
	scrollback->tail = 0;
	scrollback->cur  = 0;
}

static void vgacon_scrollback_init(int vc_num)
{
	int pitch = vga_video_num_columns * 2;
	size_t size = CONFIG_VGACON_SOFT_SCROLLBACK_SIZE * 1024;
	int rows = size / pitch;
	void *data;

	data = kmalloc_array(CONFIG_VGACON_SOFT_SCROLLBACK_SIZE, 1024, GFP_NOWAIT);

	vgacon_scrollbacks[vc_num].data = data;
	vgacon_scrollback_cur = &vgacon_scrollbacks[vc_num];

	vgacon_scrollback_cur->rows = rows - 1;
	vgacon_scrollback_cur->size = rows * pitch;

	vgacon_scrollback_reset(vc_num, size);
}

static void vgacon_scrollback_switch(int vc_num)
{
	if (!scrollback_persistent)
		vc_num = 0;

	if (!vgacon_scrollbacks[vc_num].data) {
		vgacon_scrollback_init(vc_num);
	} else {
		if (scrollback_persistent) {
			vgacon_scrollback_cur = &vgacon_scrollbacks[vc_num];
		} else {
			size_t size = CONFIG_VGACON_SOFT_SCROLLBACK_SIZE * 1024;

			vgacon_scrollback_reset(vc_num, size);
		}
	}
}

static void vgacon_scrollback_startup(void)
{
	vgacon_scrollback_cur = &vgacon_scrollbacks[0];
	vgacon_scrollback_init(0);
}

static void vgacon_scrollback_update(struct vc_data *c, int t, int count)
{
	void *p;

	if (!vgacon_scrollback_cur->data || !vgacon_scrollback_cur->size || c->vc_num != fg_console)
		return;

	p = (void *) (c->vc_origin + t * c->vc_size_row);

	while (count--) {
		if ((vgacon_scrollback_cur->tail + c->vc_size_row) > vgacon_scrollback_cur->size)
			vgacon_scrollback_cur->tail = 0;

		scr_memcpyw(vgacon_scrollback_cur->data + vgacon_scrollback_cur->tail, p, c->vc_size_row);


		vgacon_scrollback_cur->cnt++;
		p += c->vc_size_row;
		vgacon_scrollback_cur->tail += c->vc_size_row;

		if (vgacon_scrollback_cur->tail >= vgacon_scrollback_cur->size)
			vgacon_scrollback_cur->tail = 0;

		if (vgacon_scrollback_cur->cnt > vgacon_scrollback_cur->rows)
			vgacon_scrollback_cur->cnt = vgacon_scrollback_cur->rows;

		vgacon_scrollback_cur->cur = vgacon_scrollback_cur->cnt;
	}
}

static void vgacon_restore_screen(struct vc_data *c)
{
	c->vc_origin = c->vc_visible_origin;
	vgacon_scrollback_cur->save = 0;

	if (!vga_is_gfx && !vgacon_scrollback_cur->restore) {
		scr_memcpyw((u16 *) c->vc_origin, (u16 *) c->vc_screenbuf, c->vc_screenbuf_size > vga_vram_size ? vga_vram_size : c->vc_screenbuf_size);

		vgacon_scrollback_cur->restore = 1;
		vgacon_scrollback_cur->cur = vgacon_scrollback_cur->cnt;
	}
}

static void vgacon_scrolldelta(struct vc_data *c, int lines)
{
	int start, end, count, soff;

	if (!lines) {
		vgacon_restore_screen(c);
		return;
	}

	if (!vgacon_scrollback_cur->data)
		return;

	if (!vgacon_scrollback_cur->save) {
		vgacon_cursor(c, CM_ERASE);
		vgacon_save_screen(c);
		c->vc_origin = (unsigned long)c->vc_screenbuf;
		vgacon_scrollback_cur->save = 1;
	}

	vgacon_scrollback_cur->restore = 0;
	start = vgacon_scrollback_cur->cur + lines;
	end = start + abs(lines);

	if (start < 0)
		start = 0;

	if (start > vgacon_scrollback_cur->cnt)
		start = vgacon_scrollback_cur->cnt;

	if (end < 0)
		end = 0;

	if (end > vgacon_scrollback_cur->cnt)
		end = vgacon_scrollback_cur->cnt;

	vgacon_scrollback_cur->cur = start;
	count = end - start;
	soff = vgacon_scrollback_cur->tail - ((vgacon_scrollback_cur->cnt - end) * c->vc_size_row);
	soff -= count * c->vc_size_row;

	if (soff < 0)
		soff += vgacon_scrollback_cur->size;

	count = vgacon_scrollback_cur->cnt - start;

	if (count > c->vc_rows)
		count = c->vc_rows;

	if (count) {
		int copysize;

		int diff = c->vc_rows - count;
		void *d = (void *) c->vc_visible_origin;
		void *s = (void *) c->vc_screenbuf;

		count *= c->vc_size_row;
		
		copysize = min(count, vgacon_scrollback_cur->size - soff);
		scr_memcpyw(d, vgacon_scrollback_cur->data + soff, copysize);
		d += copysize;
		count -= copysize;

		if (count) {
			scr_memcpyw(d, vgacon_scrollback_cur->data, count);
			d += count;
		}

		if (diff)
			scr_memcpyw(d, s, diff * c->vc_size_row);
	} else vgacon_cursor(c, CM_MOVE);
}

static void vgacon_flush_scrollback(struct vc_data *c)
{
	size_t size = CONFIG_VGACON_SOFT_SCROLLBACK_SIZE * 1024;

	vgacon_scrollback_reset(c->vc_num, size);
}






static void vgacon_restore_screen(struct vc_data *c)
{
	if (c->vc_origin != c->vc_visible_origin)
		vgacon_scrolldelta(c, 0);
}

static void vgacon_scrolldelta(struct vc_data *c, int lines)
{
	vc_scrolldelta_helper(c, lines, vga_rolled_over, (void *)vga_vram_base, vga_vram_size);
	vga_set_mem_top(c);
}

static void vgacon_flush_scrollback(struct vc_data *c)
{
}


static const char *vgacon_startup(void)
{
	const char *display_desc = NULL;
	u16 saved1, saved2;
	volatile u16 *p;

	if (screen_info.orig_video_isVGA == VIDEO_TYPE_VLFB || screen_info.orig_video_isVGA == VIDEO_TYPE_EFI) {
	      no_vga:

		conswitchp = &dummy_con;
		return conswitchp->con_startup();

		return NULL;

	}

	
	if ((screen_info.orig_video_lines == 0) || (screen_info.orig_video_cols  == 0))
		goto no_vga;

	
	if ((screen_info.orig_video_mode == 0x0D) ||	 (screen_info.orig_video_mode == 0x0E) || (screen_info.orig_video_mode == 0x10) || (screen_info.orig_video_mode == 0x12) || (screen_info.orig_video_mode == 0x6A))



		goto no_vga;

	vga_video_num_lines = screen_info.orig_video_lines;
	vga_video_num_columns = screen_info.orig_video_cols;
	vgastate.vgabase = NULL;

	if (screen_info.orig_video_mode == 7) {
		
		vga_vram_base = 0xb0000;
		vga_video_port_reg = VGA_CRT_IM;
		vga_video_port_val = VGA_CRT_DM;
		if ((screen_info.orig_video_ega_bx & 0xff) != 0x10) {
			static struct resource ega_console_resource = { .name	= "ega", .flags	= IORESOURCE_IO, .start	= 0x3B0, .end	= 0x3BF };



			vga_video_type = VIDEO_TYPE_EGAM;
			vga_vram_size = 0x8000;
			display_desc = "EGA+";
			request_resource(&ioport_resource, &ega_console_resource);
		} else {
			static struct resource mda1_console_resource = { .name	= "mda", .flags	= IORESOURCE_IO, .start	= 0x3B0, .end	= 0x3BB };



			static struct resource mda2_console_resource = { .name	= "mda", .flags	= IORESOURCE_IO, .start	= 0x3BF, .end	= 0x3BF };



			vga_video_type = VIDEO_TYPE_MDA;
			vga_vram_size = 0x2000;
			display_desc = "*MDA";
			request_resource(&ioport_resource, &mda1_console_resource);
			request_resource(&ioport_resource, &mda2_console_resource);
			vga_video_font_height = 14;
		}
	} else {
		
		vga_can_do_color = true;
		vga_vram_base = 0xb8000;
		vga_video_port_reg = VGA_CRT_IC;
		vga_video_port_val = VGA_CRT_DC;
		if ((screen_info.orig_video_ega_bx & 0xff) != 0x10) {
			int i;

			vga_vram_size = 0x8000;

			if (!screen_info.orig_video_isVGA) {
				static struct resource ega_console_resource = { .name	= "ega", .flags	= IORESOURCE_IO, .start	= 0x3C0, .end	= 0x3DF };



				vga_video_type = VIDEO_TYPE_EGAC;
				display_desc = "EGA";
				request_resource(&ioport_resource, &ega_console_resource);
			} else {
				static struct resource vga_console_resource = { .name	= "vga+", .flags	= IORESOURCE_IO, .start	= 0x3C0, .end	= 0x3DF };



				vga_video_type = VIDEO_TYPE_VGAC;
				display_desc = "VGA+";
				request_resource(&ioport_resource, &vga_console_resource);

				

				for (i = 0; i < 16; i++) {
					inb_p(VGA_IS1_RC);
					outb_p(i, VGA_ATT_W);
					outb_p(i, VGA_ATT_W);
				}
				outb_p(0x20, VGA_ATT_W);

				
				for (i = 0; i < 16; i++) {
					outb_p(color_table[i], VGA_PEL_IW);
					outb_p(default_red[i], VGA_PEL_D);
					outb_p(default_grn[i], VGA_PEL_D);
					outb_p(default_blu[i], VGA_PEL_D);
				}
			}
		} else {
			static struct resource cga_console_resource = { .name	= "cga", .flags	= IORESOURCE_IO, .start	= 0x3D4, .end	= 0x3D5 };



			vga_video_type = VIDEO_TYPE_CGA;
			vga_vram_size = 0x2000;
			display_desc = "*CGA";
			request_resource(&ioport_resource, &cga_console_resource);
			vga_video_font_height = 8;
		}
	}

	vga_vram_base = VGA_MAP_MEM(vga_vram_base, vga_vram_size);
	vga_vram_end = vga_vram_base + vga_vram_size;

	
	p = (volatile u16 *) vga_vram_base;
	saved1 = scr_readw(p);
	saved2 = scr_readw(p + 1);
	scr_writew(0xAA55, p);
	scr_writew(0x55AA, p + 1);
	if (scr_readw(p) != 0xAA55 || scr_readw(p + 1) != 0x55AA) {
		scr_writew(saved1, p);
		scr_writew(saved2, p + 1);
		goto no_vga;
	}
	scr_writew(0x55AA, p);
	scr_writew(0xAA55, p + 1);
	if (scr_readw(p) != 0x55AA || scr_readw(p + 1) != 0xAA55) {
		scr_writew(saved1, p);
		scr_writew(saved2, p + 1);
		goto no_vga;
	}
	scr_writew(saved1, p);
	scr_writew(saved2, p + 1);

	if (vga_video_type == VIDEO_TYPE_EGAC || vga_video_type == VIDEO_TYPE_VGAC || vga_video_type == VIDEO_TYPE_EGAM) {

		vga_hardscroll_enabled = vga_hardscroll_user_enable;
		vga_default_font_height = screen_info.orig_video_points;
		vga_video_font_height = screen_info.orig_video_points;
		
		vga_scan_lines = vga_video_font_height * vga_video_num_lines;
	}

	vgacon_xres = screen_info.orig_video_cols * VGA_FONTWIDTH;
	vgacon_yres = vga_scan_lines;

	if (!vga_init_done) {
		vgacon_scrollback_startup();
		vga_init_done = true;
	}

	return display_desc;
}

static void vgacon_init(struct vc_data *c, int init)
{
	struct uni_pagedir *p;

	
	c->vc_can_do_color = vga_can_do_color;

	
	if (init) {
		c->vc_cols = vga_video_num_columns;
		c->vc_rows = vga_video_num_lines;
	} else vc_resize(c, vga_video_num_columns, vga_video_num_lines);

	c->vc_scan_lines = vga_scan_lines;
	c->vc_font.height = vga_video_font_height;
	c->vc_complement_mask = 0x7700;
	if (vga_512_chars)
		c->vc_hi_font_mask = 0x0800;
	p = *c->vc_uni_pagedir_loc;
	if (c->vc_uni_pagedir_loc != &vgacon_uni_pagedir) {
		con_free_unimap(c);
		c->vc_uni_pagedir_loc = &vgacon_uni_pagedir;
		vgacon_refcount++;
	}
	if (!vgacon_uni_pagedir && p)
		con_set_default_unimap(c);

	
	if (global_cursor_default == -1)
		global_cursor_default = !(screen_info.flags & VIDEO_FLAGS_NOCURSOR);
}

static void vgacon_deinit(struct vc_data *c)
{
	
	if (con_is_visible(c)) {
		c->vc_visible_origin = vga_vram_base;
		vga_set_mem_top(c);
	}

	if (!--vgacon_refcount)
		con_free_unimap(c);
	c->vc_uni_pagedir_loc = &c->vc_uni_pagedir;
	con_set_default_unimap(c);
}

static u8 vgacon_build_attr(struct vc_data *c, u8 color, enum vc_intensity intensity, bool blink, bool underline, bool reverse, bool italic)


{
	u8 attr = color;

	if (vga_can_do_color) {
		if (italic)
			attr = (attr & 0xF0) | c->vc_itcolor;
		else if (underline)
			attr = (attr & 0xf0) | c->vc_ulcolor;
		else if (intensity == VCI_HALF_BRIGHT)
			attr = (attr & 0xf0) | c->vc_halfcolor;
	}
	if (reverse)
		attr = ((attr) & 0x88) | ((((attr) >> 4) | ((attr) << 4)) & 0x77);

	if (blink)
		attr ^= 0x80;
	if (intensity == VCI_BOLD)
		attr ^= 0x08;
	if (!vga_can_do_color) {
		if (italic)
			attr = (attr & 0xF8) | 0x02;
		else if (underline)
			attr = (attr & 0xf8) | 0x01;
		else if (intensity == VCI_HALF_BRIGHT)
			attr = (attr & 0xf0) | 0x08;
	}
	return attr;
}

static void vgacon_invert_region(struct vc_data *c, u16 * p, int count)
{
	const bool col = vga_can_do_color;

	while (count--) {
		u16 a = scr_readw(p);
		if (col)
			a = ((a) & 0x88ff) | (((a) & 0x7000) >> 4) | (((a) & 0x0700) << 4);
		else a ^= ((a & 0x0700) == 0x0100) ? 0x7000 : 0x7700;
		scr_writew(a, p++);
	}
}

static void vgacon_set_cursor_size(int xpos, int from, int to)
{
	unsigned long flags;
	int curs, cure;

	if ((from == cursor_size_lastfrom) && (to == cursor_size_lastto))
		return;
	cursor_size_lastfrom = from;
	cursor_size_lastto = to;

	raw_spin_lock_irqsave(&vga_lock, flags);
	if (vga_video_type >= VIDEO_TYPE_VGAC) {
		outb_p(VGA_CRTC_CURSOR_START, vga_video_port_reg);
		curs = inb_p(vga_video_port_val);
		outb_p(VGA_CRTC_CURSOR_END, vga_video_port_reg);
		cure = inb_p(vga_video_port_val);
	} else {
		curs = 0;
		cure = 0;
	}

	curs = (curs & 0xc0) | from;
	cure = (cure & 0xe0) | to;

	outb_p(VGA_CRTC_CURSOR_START, vga_video_port_reg);
	outb_p(curs, vga_video_port_val);
	outb_p(VGA_CRTC_CURSOR_END, vga_video_port_reg);
	outb_p(cure, vga_video_port_val);
	raw_spin_unlock_irqrestore(&vga_lock, flags);
}

static void vgacon_cursor(struct vc_data *c, int mode)
{
	if (c->vc_mode != KD_TEXT)
		return;

	vgacon_restore_screen(c);

	switch (mode) {
	case CM_ERASE:
		write_vga(14, (c->vc_pos - vga_vram_base) / 2);
	        if (vga_video_type >= VIDEO_TYPE_VGAC)
			vgacon_set_cursor_size(c->state.x, 31, 30);
		else vgacon_set_cursor_size(c->state.x, 31, 31);
		break;

	case CM_MOVE:
	case CM_DRAW:
		write_vga(14, (c->vc_pos - vga_vram_base) / 2);
		switch (CUR_SIZE(c->vc_cursor_type)) {
		case CUR_UNDERLINE:
			vgacon_set_cursor_size(c->state.x, c->vc_font.height - (c->vc_font.height < 10 ? 2 : 3), c->vc_font.height - (c->vc_font.height < 10 ? 1 : 2));





			break;
		case CUR_TWO_THIRDS:
			vgacon_set_cursor_size(c->state.x, c->vc_font.height / 3, c->vc_font.height - (c->vc_font.height < 10 ? 1 : 2));



			break;
		case CUR_LOWER_THIRD:
			vgacon_set_cursor_size(c->state.x, (c->vc_font.height * 2) / 3, c->vc_font.height - (c->vc_font.height < 10 ? 1 : 2));



			break;
		case CUR_LOWER_HALF:
			vgacon_set_cursor_size(c->state.x, c->vc_font.height / 2, c->vc_font.height - (c->vc_font.height < 10 ? 1 : 2));



			break;
		case CUR_NONE:
			if (vga_video_type >= VIDEO_TYPE_VGAC)
				vgacon_set_cursor_size(c->state.x, 31, 30);
			else vgacon_set_cursor_size(c->state.x, 31, 31);
			break;
		default:
			vgacon_set_cursor_size(c->state.x, 1, c->vc_font.height);
			break;
		}
		break;
	}
}

static int vgacon_doresize(struct vc_data *c, unsigned int width, unsigned int height)
{
	unsigned long flags;
	unsigned int scanlines = height * c->vc_font.height;
	u8 scanlines_lo = 0, r7 = 0, vsync_end = 0, mode, max_scan;

	raw_spin_lock_irqsave(&vga_lock, flags);

	vgacon_xres = width * VGA_FONTWIDTH;
	vgacon_yres = height * c->vc_font.height;
	if (vga_video_type >= VIDEO_TYPE_VGAC) {
		outb_p(VGA_CRTC_MAX_SCAN, vga_video_port_reg);
		max_scan = inb_p(vga_video_port_val);

		if (max_scan & 0x80)
			scanlines <<= 1;

		outb_p(VGA_CRTC_MODE, vga_video_port_reg);
		mode = inb_p(vga_video_port_val);

		if (mode & 0x04)
			scanlines >>= 1;

		scanlines -= 1;
		scanlines_lo = scanlines & 0xff;

		outb_p(VGA_CRTC_OVERFLOW, vga_video_port_reg);
		r7 = inb_p(vga_video_port_val) & ~0x42;

		if (scanlines & 0x100)
			r7 |= 0x02;
		if (scanlines & 0x200)
			r7 |= 0x40;

		
		outb_p(VGA_CRTC_V_SYNC_END, vga_video_port_reg);
		vsync_end = inb_p(vga_video_port_val);
		outb_p(VGA_CRTC_V_SYNC_END, vga_video_port_reg);
		outb_p(vsync_end & ~0x80, vga_video_port_val);
	}

	outb_p(VGA_CRTC_H_DISP, vga_video_port_reg);
	outb_p(width - 1, vga_video_port_val);
	outb_p(VGA_CRTC_OFFSET, vga_video_port_reg);
	outb_p(width >> 1, vga_video_port_val);

	if (vga_video_type >= VIDEO_TYPE_VGAC) {
		outb_p(VGA_CRTC_V_DISP_END, vga_video_port_reg);
		outb_p(scanlines_lo, vga_video_port_val);
		outb_p(VGA_CRTC_OVERFLOW, vga_video_port_reg);
		outb_p(r7,vga_video_port_val);

		
		outb_p(VGA_CRTC_V_SYNC_END, vga_video_port_reg);
		outb_p(vsync_end, vga_video_port_val);
	}

	raw_spin_unlock_irqrestore(&vga_lock, flags);
	return 0;
}

static int vgacon_switch(struct vc_data *c)
{
	int x = c->vc_cols * VGA_FONTWIDTH;
	int y = c->vc_rows * c->vc_font.height;
	int rows = screen_info.orig_video_lines * vga_default_font_height/ c->vc_font.height;
	
	vga_video_num_columns = c->vc_cols;
	vga_video_num_lines = c->vc_rows;

	

	if (!vga_is_gfx) {
		scr_memcpyw((u16 *) c->vc_origin, (u16 *) c->vc_screenbuf, c->vc_screenbuf_size > vga_vram_size ? vga_vram_size : c->vc_screenbuf_size);


		if ((vgacon_xres != x || vgacon_yres != y) && (!(vga_video_num_columns % 2) && vga_video_num_columns <= screen_info.orig_video_cols && vga_video_num_lines <= rows))


			vgacon_doresize(c, c->vc_cols, c->vc_rows);
	}

	vgacon_scrollback_switch(c->vc_num);
	return 0;		
}

static void vga_set_palette(struct vc_data *vc, const unsigned char *table)
{
	int i, j;

	vga_w(vgastate.vgabase, VGA_PEL_MSK, 0xff);
	for (i = j = 0; i < 16; i++) {
		vga_w(vgastate.vgabase, VGA_PEL_IW, table[i]);
		vga_w(vgastate.vgabase, VGA_PEL_D, vc->vc_palette[j++] >> 2);
		vga_w(vgastate.vgabase, VGA_PEL_D, vc->vc_palette[j++] >> 2);
		vga_w(vgastate.vgabase, VGA_PEL_D, vc->vc_palette[j++] >> 2);
	}
}

static void vgacon_set_palette(struct vc_data *vc, const unsigned char *table)
{
	if (vga_video_type != VIDEO_TYPE_VGAC || vga_palette_blanked || !con_is_visible(vc))
		return;
	vga_set_palette(vc, table);
}


static struct {
	unsigned char SeqCtrlIndex;	
	unsigned char CrtCtrlIndex;	
	unsigned char CrtMiscIO;	
	unsigned char HorizontalTotal;	
	unsigned char HorizDisplayEnd;	
	unsigned char StartHorizRetrace;	
	unsigned char EndHorizRetrace;	
	unsigned char Overflow;	
	unsigned char StartVertRetrace;	
	unsigned char EndVertRetrace;	
	unsigned char ModeControl;	
	unsigned char ClockingMode;	
} vga_state;

static void vga_vesa_blank(struct vgastate *state, int mode)
{
	
	if (!vga_vesa_blanked) {
		raw_spin_lock_irq(&vga_lock);
		vga_state.SeqCtrlIndex = vga_r(state->vgabase, VGA_SEQ_I);
		vga_state.CrtCtrlIndex = inb_p(vga_video_port_reg);
		vga_state.CrtMiscIO = vga_r(state->vgabase, VGA_MIS_R);
		raw_spin_unlock_irq(&vga_lock);

		outb_p(0x00, vga_video_port_reg);	
		vga_state.HorizontalTotal = inb_p(vga_video_port_val);
		outb_p(0x01, vga_video_port_reg);	
		vga_state.HorizDisplayEnd = inb_p(vga_video_port_val);
		outb_p(0x04, vga_video_port_reg);	
		vga_state.StartHorizRetrace = inb_p(vga_video_port_val);
		outb_p(0x05, vga_video_port_reg);	
		vga_state.EndHorizRetrace = inb_p(vga_video_port_val);
		outb_p(0x07, vga_video_port_reg);	
		vga_state.Overflow = inb_p(vga_video_port_val);
		outb_p(0x10, vga_video_port_reg);	
		vga_state.StartVertRetrace = inb_p(vga_video_port_val);
		outb_p(0x11, vga_video_port_reg);	
		vga_state.EndVertRetrace = inb_p(vga_video_port_val);
		outb_p(0x17, vga_video_port_reg);	
		vga_state.ModeControl = inb_p(vga_video_port_val);
		vga_state.ClockingMode = vga_rseq(state->vgabase, VGA_SEQ_CLOCK_MODE);
	}

	
	
	raw_spin_lock_irq(&vga_lock);
	vga_wseq(state->vgabase, VGA_SEQ_CLOCK_MODE, vga_state.ClockingMode | 0x20);

	
	if ((vga_state.CrtMiscIO & 0x80) == 0x80)
		vga_w(state->vgabase, VGA_MIS_W, vga_state.CrtMiscIO & 0xEF);

	
	if (mode & VESA_VSYNC_SUSPEND) {
		outb_p(0x10, vga_video_port_reg);	
		outb_p(0xff, vga_video_port_val);	
		outb_p(0x11, vga_video_port_reg);	
		outb_p(0x40, vga_video_port_val);	
		outb_p(0x07, vga_video_port_reg);	
		outb_p(vga_state.Overflow | 0x84, vga_video_port_val);	
	}

	if (mode & VESA_HSYNC_SUSPEND) {
		
		outb_p(0x04, vga_video_port_reg);	
		outb_p(0xff, vga_video_port_val);	
		outb_p(0x05, vga_video_port_reg);	
		outb_p(0x00, vga_video_port_val);	
	}

	
	vga_w(state->vgabase, VGA_SEQ_I, vga_state.SeqCtrlIndex);
	outb_p(vga_state.CrtCtrlIndex, vga_video_port_reg);
	raw_spin_unlock_irq(&vga_lock);
}

static void vga_vesa_unblank(struct vgastate *state)
{
	
	raw_spin_lock_irq(&vga_lock);
	vga_w(state->vgabase, VGA_MIS_W, vga_state.CrtMiscIO);

	outb_p(0x00, vga_video_port_reg);	
	outb_p(vga_state.HorizontalTotal, vga_video_port_val);
	outb_p(0x01, vga_video_port_reg);	
	outb_p(vga_state.HorizDisplayEnd, vga_video_port_val);
	outb_p(0x04, vga_video_port_reg);	
	outb_p(vga_state.StartHorizRetrace, vga_video_port_val);
	outb_p(0x05, vga_video_port_reg);	
	outb_p(vga_state.EndHorizRetrace, vga_video_port_val);
	outb_p(0x07, vga_video_port_reg);	
	outb_p(vga_state.Overflow, vga_video_port_val);
	outb_p(0x10, vga_video_port_reg);	
	outb_p(vga_state.StartVertRetrace, vga_video_port_val);
	outb_p(0x11, vga_video_port_reg);	
	outb_p(vga_state.EndVertRetrace, vga_video_port_val);
	outb_p(0x17, vga_video_port_reg);	
	outb_p(vga_state.ModeControl, vga_video_port_val);
	
	vga_wseq(state->vgabase, VGA_SEQ_CLOCK_MODE, vga_state.ClockingMode);

	
	vga_w(state->vgabase, VGA_SEQ_I, vga_state.SeqCtrlIndex);
	outb_p(vga_state.CrtCtrlIndex, vga_video_port_reg);
	raw_spin_unlock_irq(&vga_lock);
}

static void vga_pal_blank(struct vgastate *state)
{
	int i;

	vga_w(state->vgabase, VGA_PEL_MSK, 0xff);
	for (i = 0; i < 16; i++) {
		vga_w(state->vgabase, VGA_PEL_IW, i);
		vga_w(state->vgabase, VGA_PEL_D, 0);
		vga_w(state->vgabase, VGA_PEL_D, 0);
		vga_w(state->vgabase, VGA_PEL_D, 0);
	}
}

static int vgacon_blank(struct vc_data *c, int blank, int mode_switch)
{
	switch (blank) {
	case 0:		
		if (vga_vesa_blanked) {
			vga_vesa_unblank(&vgastate);
			vga_vesa_blanked = 0;
		}
		if (vga_palette_blanked) {
			vga_set_palette(c, color_table);
			vga_palette_blanked = false;
			return 0;
		}
		vga_is_gfx = false;
		
		return 1;
	case 1:		
	case -1:	
		if (!mode_switch && vga_video_type == VIDEO_TYPE_VGAC) {
			vga_pal_blank(&vgastate);
			vga_palette_blanked = true;
			return 0;
		}
		vgacon_set_origin(c);
		scr_memsetw((void *) vga_vram_base, BLANK, c->vc_screenbuf_size);
		if (mode_switch)
			vga_is_gfx = true;
		return 1;
	default:		
		if (vga_video_type == VIDEO_TYPE_VGAC) {
			vga_vesa_blank(&vgastate, blank - 1);
			vga_vesa_blanked = blank;
		}
		return 0;
	}
}








static int vgacon_do_font_op(struct vgastate *state, char *arg, int set, bool ch512)
{
	unsigned short video_port_status = vga_video_port_reg + 6;
	int font_select = 0x00, beg, i;
	char *charmap;
	bool clear_attribs = false;
	if (vga_video_type != VIDEO_TYPE_EGAM) {
		charmap = (char *) VGA_MAP_MEM(colourmap, 0);
		beg = 0x0e;
	} else {
		charmap = (char *) VGA_MAP_MEM(blackwmap, 0);
		beg = 0x0a;
	}


	

	if (!arg)
		return -EINVAL;	

	vga_font_is_default = false;
	font_select = ch512 ? 0x04 : 0x00;

	

	if (set) {
		vga_font_is_default = !arg;
		if (!arg)
			ch512 = false;	
		font_select = arg ? (ch512 ? 0x0e : 0x0a) : 0x00;
	}

	if (!vga_font_is_default)
		charmap += 4 * cmapsz;


	raw_spin_lock_irq(&vga_lock);
	
	vga_wseq(state->vgabase, VGA_SEQ_RESET, 0x1);
	
	vga_wseq(state->vgabase, VGA_SEQ_PLANE_WRITE, 0x04);	
	
	vga_wseq(state->vgabase, VGA_SEQ_MEMORY_MODE, 0x07);	
	
	vga_wseq(state->vgabase, VGA_SEQ_RESET, 0x03);

	
	vga_wgfx(state->vgabase, VGA_GFX_PLANE_READ, 0x02);		
	
	vga_wgfx(state->vgabase, VGA_GFX_MODE, 0x00);
	
	vga_wgfx(state->vgabase, VGA_GFX_MISC, 0x00);
	raw_spin_unlock_irq(&vga_lock);

	if (arg) {
		if (set)
			for (i = 0; i < cmapsz; i++) {
				vga_writeb(arg[i], charmap + i);
				cond_resched();
			}
		else for (i = 0; i < cmapsz; i++) {
				arg[i] = vga_readb(charmap + i);
				cond_resched();
			}

		

		if (ch512) {
			charmap += 2 * cmapsz;
			arg += cmapsz;
			if (set)
				for (i = 0; i < cmapsz; i++) {
					vga_writeb(arg[i], charmap + i);
					cond_resched();
				}
			else for (i = 0; i < cmapsz; i++) {
					arg[i] = vga_readb(charmap + i);
					cond_resched();
				}
		}
	}

	raw_spin_lock_irq(&vga_lock);
	
	vga_wseq(state->vgabase, VGA_SEQ_RESET, 0x01);	
	
	vga_wseq(state->vgabase, VGA_SEQ_PLANE_WRITE, 0x03);
	
	vga_wseq(state->vgabase, VGA_SEQ_MEMORY_MODE, 0x03);
	
	if (set)
		vga_wseq(state->vgabase, VGA_SEQ_CHARACTER_MAP, font_select);
	
	vga_wseq(state->vgabase, VGA_SEQ_RESET, 0x03);

	
	vga_wgfx(state->vgabase, VGA_GFX_PLANE_READ, 0x00);
	
	vga_wgfx(state->vgabase, VGA_GFX_MODE, 0x10);
	
	vga_wgfx(state->vgabase, VGA_GFX_MISC, beg);

	
	if ((set) && (ch512 != vga_512_chars)) {
		vga_512_chars = ch512;
		
		inb_p(video_port_status);	
		
		vga_wattr(state->vgabase, VGA_ATC_PLANE_ENABLE, ch512 ? 0x07 : 0x0f);
		
		inb_p(video_port_status);
		vga_wattr(state->vgabase, VGA_AR_ENABLE_DISPLAY, 0);	
		clear_attribs = true;
	}
	raw_spin_unlock_irq(&vga_lock);

	if (clear_attribs) {
		for (i = 0; i < MAX_NR_CONSOLES; i++) {
			struct vc_data *c = vc_cons[i].d;
			if (c && c->vc_sw == &vga_con) {
				
				c->vc_hi_font_mask = 0x00;
				clear_buffer_attributes(c);
				c->vc_hi_font_mask = ch512 ? 0x0800 : 0;
			}
		}
	}
	return 0;
}


static int vgacon_adjust_height(struct vc_data *vc, unsigned fontheight)
{
	unsigned char ovr, vde, fsr;
	int rows, maxscan, i;

	rows = vc->vc_scan_lines / fontheight;	
	maxscan = rows * fontheight - 1;	

	

	raw_spin_lock_irq(&vga_lock);
	outb_p(0x07, vga_video_port_reg);	
	ovr = inb_p(vga_video_port_val);
	outb_p(0x09, vga_video_port_reg);	
	fsr = inb_p(vga_video_port_val);
	raw_spin_unlock_irq(&vga_lock);

	vde = maxscan & 0xff;	
	ovr = (ovr & 0xbd) +	 ((maxscan & 0x100) >> 7) + ((maxscan & 0x200) >> 3);
	fsr = (fsr & 0xe0) + (fontheight - 1);	

	raw_spin_lock_irq(&vga_lock);
	outb_p(0x07, vga_video_port_reg);	
	outb_p(ovr, vga_video_port_val);
	outb_p(0x09, vga_video_port_reg);	
	outb_p(fsr, vga_video_port_val);
	outb_p(0x12, vga_video_port_reg);	
	outb_p(vde, vga_video_port_val);
	raw_spin_unlock_irq(&vga_lock);
	vga_video_font_height = fontheight;

	for (i = 0; i < MAX_NR_CONSOLES; i++) {
		struct vc_data *c = vc_cons[i].d;

		if (c && c->vc_sw == &vga_con) {
			if (con_is_visible(c)) {
			        
				cursor_size_lastfrom = 0;
				cursor_size_lastto = 0;
				c->vc_sw->con_cursor(c, CM_DRAW);
			}
			c->vc_font.height = fontheight;
			vc_resize(c, 0, rows);	
		}
	}
	return 0;
}

static int vgacon_font_set(struct vc_data *c, struct console_font *font, unsigned int flags)
{
	unsigned charcount = font->charcount;
	int rc;

	if (vga_video_type < VIDEO_TYPE_EGAM)
		return -EINVAL;

	if (font->width != VGA_FONTWIDTH || (charcount != 256 && charcount != 512))
		return -EINVAL;

	rc = vgacon_do_font_op(&vgastate, font->data, 1, charcount == 512);
	if (rc)
		return rc;

	if (!(flags & KD_FONT_FLAG_DONT_RECALC))
		rc = vgacon_adjust_height(c, font->height);
	return rc;
}

static int vgacon_font_get(struct vc_data *c, struct console_font *font)
{
	if (vga_video_type < VIDEO_TYPE_EGAM)
		return -EINVAL;

	font->width = VGA_FONTWIDTH;
	font->height = c->vc_font.height;
	font->charcount = vga_512_chars ? 512 : 256;
	if (!font->data)
		return 0;
	return vgacon_do_font_op(&vgastate, font->data, 0, vga_512_chars);
}

static int vgacon_resize(struct vc_data *c, unsigned int width, unsigned int height, unsigned int user)
{
	if ((width << 1) * height > vga_vram_size)
		return -EINVAL;

	if (width % 2 || width > screen_info.orig_video_cols || height > (screen_info.orig_video_lines * vga_default_font_height)/ c->vc_font.height)

		
		return (user) ? 0 : -EINVAL;

	if (con_is_visible(c) && !vga_is_gfx) 
		vgacon_doresize(c, width, height);
	return 0;
}

static int vgacon_set_origin(struct vc_data *c)
{
	if (vga_is_gfx ||	 (console_blanked && !vga_palette_blanked))
		return 0;
	c->vc_origin = c->vc_visible_origin = vga_vram_base;
	vga_set_mem_top(c);
	vga_rolled_over = 0;
	return 1;
}

static void vgacon_save_screen(struct vc_data *c)
{
	static int vga_bootup_console = 0;

	if (!vga_bootup_console) {
		
		vga_bootup_console = 1;
		c->state.x = screen_info.orig_x;
		c->state.y = screen_info.orig_y;
	}

	

	if (!vga_is_gfx)
		scr_memcpyw((u16 *) c->vc_screenbuf, (u16 *) c->vc_origin, c->vc_screenbuf_size > vga_vram_size ? vga_vram_size : c->vc_screenbuf_size);
}

static bool vgacon_scroll(struct vc_data *c, unsigned int t, unsigned int b, enum con_scroll dir, unsigned int lines)
{
	unsigned long oldo;
	unsigned int delta;

	if (t || b != c->vc_rows || vga_is_gfx || c->vc_mode != KD_TEXT)
		return false;

	if (!vga_hardscroll_enabled || lines >= c->vc_rows / 2)
		return false;

	vgacon_restore_screen(c);
	oldo = c->vc_origin;
	delta = lines * c->vc_size_row;
	if (dir == SM_UP) {
		vgacon_scrollback_update(c, t, lines);
		if (c->vc_scr_end + delta >= vga_vram_end) {
			scr_memcpyw((u16 *) vga_vram_base, (u16 *) (oldo + delta), c->vc_screenbuf_size - delta);

			c->vc_origin = vga_vram_base;
			vga_rolled_over = oldo - vga_vram_base;
		} else c->vc_origin += delta;
		scr_memsetw((u16 *) (c->vc_origin + c->vc_screenbuf_size - delta), c->vc_video_erase_char, delta);

	} else {
		if (oldo - delta < vga_vram_base) {
			scr_memmovew((u16 *) (vga_vram_end - c->vc_screenbuf_size + delta), (u16 *) oldo, c->vc_screenbuf_size - delta);


			c->vc_origin = vga_vram_end - c->vc_screenbuf_size;
			vga_rolled_over = 0;
		} else c->vc_origin -= delta;
		c->vc_scr_end = c->vc_origin + c->vc_screenbuf_size;
		scr_memsetw((u16 *) (c->vc_origin), c->vc_video_erase_char, delta);
	}
	c->vc_scr_end = c->vc_origin + c->vc_screenbuf_size;
	c->vc_visible_origin = c->vc_origin;
	vga_set_mem_top(c);
	c->vc_pos = (c->vc_pos - oldo) + c->vc_origin;
	return true;
}



static void vgacon_clear(struct vc_data *vc, int sy, int sx, int height, int width) { }
static void vgacon_putc(struct vc_data *vc, int c, int ypos, int xpos) { }
static void vgacon_putcs(struct vc_data *vc, const unsigned short *s, int count, int ypos, int xpos) { }

const struct consw vga_con = {
	.owner = THIS_MODULE, .con_startup = vgacon_startup, .con_init = vgacon_init, .con_deinit = vgacon_deinit, .con_clear = vgacon_clear, .con_putc = vgacon_putc, .con_putcs = vgacon_putcs, .con_cursor = vgacon_cursor, .con_scroll = vgacon_scroll, .con_switch = vgacon_switch, .con_blank = vgacon_blank, .con_font_set = vgacon_font_set, .con_font_get = vgacon_font_get, .con_resize = vgacon_resize, .con_set_palette = vgacon_set_palette, .con_scrolldelta = vgacon_scrolldelta, .con_set_origin = vgacon_set_origin, .con_save_screen = vgacon_save_screen, .con_build_attr = vgacon_build_attr, .con_invert_region = vgacon_invert_region, .con_flush_scrollback = vgacon_flush_scrollback, };




















EXPORT_SYMBOL(vga_con);

MODULE_LICENSE("GPL");
