











static int xen_pt_ptr_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data);





static int xen_pt_hide_dev_cap(const XenHostPCIDevice *d, uint8_t grp_id)
{
    switch (grp_id) {
    case PCI_CAP_ID_EXP:
        
        if (d->vendor_id == PCI_VENDOR_ID_INTEL && d->device_id == PCI_DEVICE_ID_INTEL_82599_SFP_VF) {
            return 1;
        }
        break;
    }
    return 0;
}


XenPTRegGroup *xen_pt_find_reg_grp(XenPCIPassthroughState *s, uint32_t address)
{
    XenPTRegGroup *entry = NULL;

    
    QLIST_FOREACH(entry, &s->reg_grps, entries) {
        
        if ((entry->base_offset <= address)
            && ((entry->base_offset + entry->size) > address)) {
            return entry;
        }
    }

    
    return NULL;
}


XenPTReg *xen_pt_find_reg(XenPTRegGroup *reg_grp, uint32_t address)
{
    XenPTReg *reg_entry = NULL;
    XenPTRegInfo *reg = NULL;
    uint32_t real_offset = 0;

    
    QLIST_FOREACH(reg_entry, &reg_grp->reg_tbl_list, entries) {
        reg = reg_entry->reg;
        real_offset = reg_grp->base_offset + reg->offset;
        
        if ((real_offset <= address)
            && ((real_offset + reg->size) > address)) {
            return reg_entry;
        }
    }

    return NULL;
}






static int xen_pt_common_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    *data = reg->init_val;
    return 0;
}



static int xen_pt_byte_reg_read(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint8_t *value, uint8_t valid_mask)
{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint8_t valid_emu_mask = 0;

    
    valid_emu_mask = reg->emu_mask & valid_mask;
    *value = XEN_PT_MERGE_VALUE(*value, cfg_entry->data, ~valid_emu_mask);

    return 0;
}
static int xen_pt_word_reg_read(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *value, uint16_t valid_mask)
{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint16_t valid_emu_mask = 0;

    
    valid_emu_mask = reg->emu_mask & valid_mask;
    *value = XEN_PT_MERGE_VALUE(*value, cfg_entry->data, ~valid_emu_mask);

    return 0;
}
static int xen_pt_long_reg_read(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint32_t *value, uint32_t valid_mask)
{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint32_t valid_emu_mask = 0;

    
    valid_emu_mask = reg->emu_mask & valid_mask;
    *value = XEN_PT_MERGE_VALUE(*value, cfg_entry->data, ~valid_emu_mask);

    return 0;
}



static int xen_pt_byte_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint8_t *val, uint8_t dev_value, uint8_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint8_t writable_mask = 0;
    uint8_t throughable_mask = 0;

    
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);

    
    throughable_mask = ~reg->emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    return 0;
}
static int xen_pt_word_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *val, uint16_t dev_value, uint16_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;

    
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);

    
    throughable_mask = ~reg->emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    return 0;
}
static int xen_pt_long_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint32_t *val, uint32_t dev_value, uint32_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;

    
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);

    
    throughable_mask = ~reg->emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    return 0;
}






static int xen_pt_vendor_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    *data = s->real_device.vendor_id;
    return 0;
}
static int xen_pt_device_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    *data = s->real_device.device_id;
    return 0;
}
static int xen_pt_status_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    XenPTRegGroup *reg_grp_entry = NULL;
    XenPTReg *reg_entry = NULL;
    uint32_t reg_field = 0;

    
    reg_grp_entry = xen_pt_find_reg_grp(s, PCI_CAPABILITY_LIST);
    if (reg_grp_entry) {
        
        reg_entry = xen_pt_find_reg(reg_grp_entry, PCI_CAPABILITY_LIST);
        if (reg_entry) {
            
            if (reg_entry->data) {
                reg_field |= PCI_STATUS_CAP_LIST;
            } else {
                reg_field &= ~PCI_STATUS_CAP_LIST;
            }
        } else {
            xen_shutdown_fatal_error("Internal error: Couldn't find XenPTReg*" " for Capabilities Pointer register." " (%s)\n", __func__);

            return -1;
        }
    } else {
        xen_shutdown_fatal_error("Internal error: Couldn't find XenPTRegGroup" " for Header. (%s)\n", __func__);
        return -1;
    }

    *data = reg_field;
    return 0;
}
static int xen_pt_header_type_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    
    *data = reg->init_val | 0x80;
    return 0;
}


static int xen_pt_irqpin_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    *data = xen_pt_pci_read_intx(s);
    return 0;
}


static int xen_pt_cmd_reg_read(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *value, uint16_t valid_mask)
{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint16_t valid_emu_mask = 0;
    uint16_t emu_mask = reg->emu_mask;

    if (s->is_virtfn) {
        emu_mask |= PCI_COMMAND_MEMORY;
    }

    
    valid_emu_mask = emu_mask & valid_mask;
    *value = XEN_PT_MERGE_VALUE(*value, cfg_entry->data, ~valid_emu_mask);

    return 0;
}
static int xen_pt_cmd_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *val, uint16_t dev_value, uint16_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t emu_mask = reg->emu_mask;

    if (s->is_virtfn) {
        emu_mask |= PCI_COMMAND_MEMORY;
    }

    
    writable_mask = ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);

    
    throughable_mask = ~emu_mask & valid_mask;

    if (*val & PCI_COMMAND_INTX_DISABLE) {
        throughable_mask |= PCI_COMMAND_INTX_DISABLE;
    } else {
        if (s->machine_irq) {
            throughable_mask |= PCI_COMMAND_INTX_DISABLE;
        }
    }

    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    return 0;
}







static bool is_64bit_bar(PCIIORegion *r)
{
    return !!(r->type & PCI_BASE_ADDRESS_MEM_TYPE_64);
}

static uint64_t xen_pt_get_bar_size(PCIIORegion *r)
{
    if (is_64bit_bar(r)) {
        uint64_t size64;
        size64 = (r + 1)->size;
        size64 <<= 32;
        size64 += r->size;
        return size64;
    }
    return r->size;
}

static XenPTBarFlag xen_pt_bar_reg_parse(XenPCIPassthroughState *s, int index)
{
    PCIDevice *d = &s->dev;
    XenPTRegion *region = NULL;
    PCIIORegion *r;

    
    if ((0 < index) && (index < PCI_ROM_SLOT)) {
        int type = s->real_device.io_regions[index - 1].type;

        if ((type & XEN_HOST_PCI_REGION_TYPE_MEM)
            && (type & XEN_HOST_PCI_REGION_TYPE_MEM_64)) {
            region = &s->bases[index - 1];
            if (region->bar_flag != XEN_PT_BAR_FLAG_UPPER) {
                return XEN_PT_BAR_FLAG_UPPER;
            }
        }
    }

    
    r = &d->io_regions[index];
    if (!xen_pt_get_bar_size(r)) {
        return XEN_PT_BAR_FLAG_UNUSED;
    }

    
    if (index == PCI_ROM_SLOT) {
        return XEN_PT_BAR_FLAG_MEM;
    }

    
    if (s->real_device.io_regions[index].type & XEN_HOST_PCI_REGION_TYPE_IO) {
        return XEN_PT_BAR_FLAG_IO;
    } else {
        return XEN_PT_BAR_FLAG_MEM;
    }
}

static inline uint32_t base_address_with_flags(XenHostPCIIORegion *hr)
{
    if (hr->type & XEN_HOST_PCI_REGION_TYPE_IO) {
        return hr->base_addr | (hr->bus_flags & ~PCI_BASE_ADDRESS_IO_MASK);
    } else {
        return hr->base_addr | (hr->bus_flags & ~PCI_BASE_ADDRESS_MEM_MASK);
    }
}

static int xen_pt_bar_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)
{
    uint32_t reg_field = 0;
    int index;

    index = xen_pt_bar_offset_to_index(reg->offset);
    if (index < 0 || index >= PCI_NUM_REGIONS) {
        XEN_PT_ERR(&s->dev, "Internal error: Invalid BAR index [%d].\n", index);
        return -1;
    }

    
    s->bases[index].bar_flag = xen_pt_bar_reg_parse(s, index);
    if (s->bases[index].bar_flag == XEN_PT_BAR_FLAG_UNUSED) {
        reg_field = XEN_PT_INVALID_REG;
    }

    *data = reg_field;
    return 0;
}
static int xen_pt_bar_reg_read(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint32_t *value, uint32_t valid_mask)
{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint32_t valid_emu_mask = 0;
    uint32_t bar_emu_mask = 0;
    int index;

    
    index = xen_pt_bar_offset_to_index(reg->offset);
    if (index < 0 || index >= PCI_NUM_REGIONS - 1) {
        XEN_PT_ERR(&s->dev, "Internal error: Invalid BAR index [%d].\n", index);
        return -1;
    }

    
    *value = base_address_with_flags(&s->real_device.io_regions[index]);

    
    switch (s->bases[index].bar_flag) {
    case XEN_PT_BAR_FLAG_MEM:
        bar_emu_mask = XEN_PT_BAR_MEM_EMU_MASK;
        break;
    case XEN_PT_BAR_FLAG_IO:
        bar_emu_mask = XEN_PT_BAR_IO_EMU_MASK;
        break;
    case XEN_PT_BAR_FLAG_UPPER:
        bar_emu_mask = XEN_PT_BAR_ALLF;
        break;
    default:
        break;
    }

    
    valid_emu_mask = bar_emu_mask & valid_mask;
    *value = XEN_PT_MERGE_VALUE(*value, cfg_entry->data, ~valid_emu_mask);

    return 0;
}
static int xen_pt_bar_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint32_t *val, uint32_t dev_value, uint32_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    XenPTRegion *base = NULL;
    PCIDevice *d = &s->dev;
    const PCIIORegion *r;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;
    uint32_t bar_emu_mask = 0;
    uint32_t bar_ro_mask = 0;
    uint32_t r_size = 0;
    int index = 0;

    index = xen_pt_bar_offset_to_index(reg->offset);
    if (index < 0 || index >= PCI_NUM_REGIONS) {
        XEN_PT_ERR(d, "Internal error: Invalid BAR index [%d].\n", index);
        return -1;
    }

    r = &d->io_regions[index];
    base = &s->bases[index];
    r_size = xen_pt_get_emul_size(base->bar_flag, r->size);

    
    switch (s->bases[index].bar_flag) {
    case XEN_PT_BAR_FLAG_MEM:
        bar_emu_mask = XEN_PT_BAR_MEM_EMU_MASK;
        if (!r_size) {
            
            bar_ro_mask = XEN_PT_BAR_ALLF;
        } else {
            bar_ro_mask = XEN_PT_BAR_MEM_RO_MASK | (r_size - 1);
        }
        break;
    case XEN_PT_BAR_FLAG_IO:
        bar_emu_mask = XEN_PT_BAR_IO_EMU_MASK;
        bar_ro_mask = XEN_PT_BAR_IO_RO_MASK | (r_size - 1);
        break;
    case XEN_PT_BAR_FLAG_UPPER:
        bar_emu_mask = XEN_PT_BAR_ALLF;
        bar_ro_mask = r_size ? r_size - 1 : 0;
        break;
    default:
        break;
    }

    
    writable_mask = bar_emu_mask & ~bar_ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);

    
    switch (s->bases[index].bar_flag) {
    case XEN_PT_BAR_FLAG_UPPER:
    case XEN_PT_BAR_FLAG_MEM:
        
        break;
    case XEN_PT_BAR_FLAG_IO:
        
        break;
    default:
        break;
    }

    
    throughable_mask = ~bar_emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    return 0;
}


static int xen_pt_exp_rom_bar_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint32_t *val, uint32_t dev_value, uint32_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    XenPTRegion *base = NULL;
    PCIDevice *d = (PCIDevice *)&s->dev;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;
    pcibus_t r_size = 0;
    uint32_t bar_emu_mask = 0;
    uint32_t bar_ro_mask = 0;

    r_size = d->io_regions[PCI_ROM_SLOT].size;
    base = &s->bases[PCI_ROM_SLOT];
    
    r_size = xen_pt_get_emul_size(base->bar_flag, r_size);

    
    bar_emu_mask = reg->emu_mask;
    bar_ro_mask = (reg->ro_mask | (r_size - 1)) & ~PCI_ROM_ADDRESS_ENABLE;

    
    writable_mask = ~bar_ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);

    
    throughable_mask = ~bar_emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    return 0;
}


static XenPTRegInfo xen_pt_emu_reg_header0[] = {
    
    {
        .offset     = PCI_VENDOR_ID, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0xFFFF, .emu_mask   = 0xFFFF, .init       = xen_pt_vendor_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_word_reg_write, },  {









        .offset     = PCI_DEVICE_ID, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0xFFFF, .emu_mask   = 0xFFFF, .init       = xen_pt_device_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_word_reg_write, },  {









        .offset     = PCI_COMMAND, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0xF880, .emu_mask   = 0x0740, .init       = xen_pt_common_reg_init, .u.w.read   = xen_pt_cmd_reg_read, .u.w.write  = xen_pt_cmd_reg_write, },  {









        .offset     = PCI_CAPABILITY_LIST, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0xFF, .init       = xen_pt_ptr_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },   {










        .offset     = PCI_STATUS, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0x06FF, .emu_mask   = 0x0010, .init       = xen_pt_status_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_word_reg_write, },  {









        .offset     = PCI_CACHE_LINE_SIZE, .size       = 1, .init_val   = 0x00, .ro_mask    = 0x00, .emu_mask   = 0xFF, .init       = xen_pt_common_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },  {









        .offset     = PCI_LATENCY_TIMER, .size       = 1, .init_val   = 0x00, .ro_mask    = 0x00, .emu_mask   = 0xFF, .init       = xen_pt_common_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },  {









        .offset     = PCI_HEADER_TYPE, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0x00, .init       = xen_pt_header_type_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },  {









        .offset     = PCI_INTERRUPT_LINE, .size       = 1, .init_val   = 0x00, .ro_mask    = 0x00, .emu_mask   = 0xFF, .init       = xen_pt_common_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },  {









        .offset     = PCI_INTERRUPT_PIN, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0xFF, .init       = xen_pt_irqpin_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },   {










        .offset     = PCI_BASE_ADDRESS_0, .size       = 4, .init_val   = 0x00000000, .init       = xen_pt_bar_reg_init, .u.dw.read  = xen_pt_bar_reg_read, .u.dw.write = xen_pt_bar_reg_write, },  {







        .offset     = PCI_BASE_ADDRESS_1, .size       = 4, .init_val   = 0x00000000, .init       = xen_pt_bar_reg_init, .u.dw.read  = xen_pt_bar_reg_read, .u.dw.write = xen_pt_bar_reg_write, },  {







        .offset     = PCI_BASE_ADDRESS_2, .size       = 4, .init_val   = 0x00000000, .init       = xen_pt_bar_reg_init, .u.dw.read  = xen_pt_bar_reg_read, .u.dw.write = xen_pt_bar_reg_write, },  {







        .offset     = PCI_BASE_ADDRESS_3, .size       = 4, .init_val   = 0x00000000, .init       = xen_pt_bar_reg_init, .u.dw.read  = xen_pt_bar_reg_read, .u.dw.write = xen_pt_bar_reg_write, },  {







        .offset     = PCI_BASE_ADDRESS_4, .size       = 4, .init_val   = 0x00000000, .init       = xen_pt_bar_reg_init, .u.dw.read  = xen_pt_bar_reg_read, .u.dw.write = xen_pt_bar_reg_write, },  {







        .offset     = PCI_BASE_ADDRESS_5, .size       = 4, .init_val   = 0x00000000, .init       = xen_pt_bar_reg_init, .u.dw.read  = xen_pt_bar_reg_read, .u.dw.write = xen_pt_bar_reg_write, },  {







        .offset     = PCI_ROM_ADDRESS, .size       = 4, .init_val   = 0x00000000, .ro_mask    = 0x000007FE, .emu_mask   = 0xFFFFF800, .init       = xen_pt_bar_reg_init, .u.dw.read  = xen_pt_long_reg_read, .u.dw.write = xen_pt_exp_rom_bar_reg_write, }, {








        .size = 0, }, };






static XenPTRegInfo xen_pt_emu_reg_vpd[] = {
    {
        .offset     = PCI_CAP_LIST_NEXT, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0xFF, .init       = xen_pt_ptr_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, }, {








        .size = 0, }, };






static XenPTRegInfo xen_pt_emu_reg_vendor[] = {
    {
        .offset     = PCI_CAP_LIST_NEXT, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0xFF, .init       = xen_pt_ptr_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, }, {








        .size = 0, }, };





static inline uint8_t get_capability_version(XenPCIPassthroughState *s, uint32_t offset)
{
    uint8_t flags = pci_get_byte(s->dev.config + offset + PCI_EXP_FLAGS);
    return flags & PCI_EXP_FLAGS_VERS;
}

static inline uint8_t get_device_type(XenPCIPassthroughState *s, uint32_t offset)
{
    uint8_t flags = pci_get_byte(s->dev.config + offset + PCI_EXP_FLAGS);
    return (flags & PCI_EXP_FLAGS_TYPE) >> 4;
}


static int xen_pt_linkctrl_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    uint8_t cap_ver = get_capability_version(s, real_offset - reg->offset);
    uint8_t dev_type = get_device_type(s, real_offset - reg->offset);

    
    if ((dev_type == PCI_EXP_TYPE_RC_END) && (cap_ver == 1)) {
        *data = XEN_PT_INVALID_REG;
    }

    *data = reg->init_val;
    return 0;
}

static int xen_pt_devctrl2_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    uint8_t cap_ver = get_capability_version(s, real_offset - reg->offset);

    
    if (cap_ver == 1) {
        *data = XEN_PT_INVALID_REG;
    }

    *data = reg->init_val;
    return 0;
}

static int xen_pt_linkctrl2_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    uint8_t cap_ver = get_capability_version(s, real_offset - reg->offset);
    uint32_t reg_field = 0;

    
    if (cap_ver == 1) {
        reg_field = XEN_PT_INVALID_REG;
    } else {
        
        uint8_t lnkcap = pci_get_byte(s->dev.config + real_offset - reg->offset + PCI_EXP_LNKCAP);
        reg_field |= PCI_EXP_LNKCAP_SLS & lnkcap;
    }

    *data = reg_field;
    return 0;
}


static XenPTRegInfo xen_pt_emu_reg_pcie[] = {
    
    {
        .offset     = PCI_CAP_LIST_NEXT, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0xFF, .init       = xen_pt_ptr_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },  {









        .offset     = PCI_EXP_DEVCAP, .size       = 4, .init_val   = 0x00000000, .ro_mask    = 0x1FFCFFFF, .emu_mask   = 0x10000000, .init       = xen_pt_common_reg_init, .u.dw.read  = xen_pt_long_reg_read, .u.dw.write = xen_pt_long_reg_write, },  {









        .offset     = PCI_EXP_DEVCTL, .size       = 2, .init_val   = 0x2810, .ro_mask    = 0x8400, .emu_mask   = 0xFFFF, .init       = xen_pt_common_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_word_reg_write, },  {









        .offset     = PCI_EXP_LNKCTL, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0xFC34, .emu_mask   = 0xFFFF, .init       = xen_pt_linkctrl_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_word_reg_write, },  {









        .offset     = 0x28, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0xFFE0, .emu_mask   = 0xFFFF, .init       = xen_pt_devctrl2_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_word_reg_write, },  {









        .offset     = 0x30, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0xE040, .emu_mask   = 0xFFFF, .init       = xen_pt_linkctrl2_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_word_reg_write, }, {








        .size = 0, }, };






static int xen_pt_pmcsr_reg_read(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *value, uint16_t valid_mask)
{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint16_t valid_emu_mask = reg->emu_mask;

    valid_emu_mask |= PCI_PM_CTRL_STATE_MASK | PCI_PM_CTRL_NO_SOFT_RESET;

    valid_emu_mask = valid_emu_mask & valid_mask;
    *value = XEN_PT_MERGE_VALUE(*value, cfg_entry->data, ~valid_emu_mask);

    return 0;
}

static int xen_pt_pmcsr_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *val, uint16_t dev_value, uint16_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint16_t emu_mask = reg->emu_mask;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;

    emu_mask |= PCI_PM_CTRL_STATE_MASK | PCI_PM_CTRL_NO_SOFT_RESET;

    
    writable_mask = emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);

    
    throughable_mask = ~emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    return 0;
}


static XenPTRegInfo xen_pt_emu_reg_pm[] = {
    
    {
        .offset     = PCI_CAP_LIST_NEXT, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0xFF, .init       = xen_pt_ptr_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },  {









        .offset     = PCI_CAP_FLAGS, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0xFFFF, .emu_mask   = 0xF9C8, .init       = xen_pt_common_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_word_reg_write, },  {









        .offset     = PCI_PM_CTRL, .size       = 2, .init_val   = 0x0008, .ro_mask    = 0xE1FC, .emu_mask   = 0x8100, .init       = xen_pt_common_reg_init, .u.w.read   = xen_pt_pmcsr_reg_read, .u.w.write  = xen_pt_pmcsr_reg_write, }, {








        .size = 0, }, };






static bool xen_pt_msgdata_check_type(uint32_t offset, uint16_t flags)
{
    
    bool is_32 = (offset == PCI_MSI_DATA_32) && !(flags & PCI_MSI_FLAGS_64BIT);
    bool is_64 = (offset == PCI_MSI_DATA_64) &&  (flags & PCI_MSI_FLAGS_64BIT);
    return is_32 || is_64;
}


static int xen_pt_msgctrl_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    PCIDevice *d = &s->dev;
    XenPTMSI *msi = s->msi;
    uint16_t reg_field = 0;

    
    reg_field = pci_get_word(d->config + real_offset);

    if (reg_field & PCI_MSI_FLAGS_ENABLE) {
        XEN_PT_LOG(&s->dev, "MSI already enabled, disabling it first\n");
        xen_host_pci_set_word(&s->real_device, real_offset, reg_field & ~PCI_MSI_FLAGS_ENABLE);
    }
    msi->flags |= reg_field;
    msi->ctrl_offset = real_offset;
    msi->initialized = false;
    msi->mapped = false;

    *data = reg->init_val;
    return 0;
}
static int xen_pt_msgctrl_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *val, uint16_t dev_value, uint16_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    XenPTMSI *msi = s->msi;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t raw_val;

    
    if (*val & PCI_MSI_FLAGS_QSIZE) {
        XEN_PT_WARN(&s->dev, "Tries to set more than 1 vector ctrl %x\n", *val);
    }

    
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);
    msi->flags |= cfg_entry->data & ~PCI_MSI_FLAGS_ENABLE;

    
    raw_val = *val;
    throughable_mask = ~reg->emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    
    if (raw_val & PCI_MSI_FLAGS_ENABLE) {
        
        if (!msi->initialized) {
            
            XEN_PT_LOG(&s->dev, "setup MSI\n");
            if (xen_pt_msi_setup(s)) {
                
                *val &= ~PCI_MSI_FLAGS_ENABLE;
                XEN_PT_WARN(&s->dev, "Can not map MSI.\n");
                return 0;
            }
            if (xen_pt_msi_update(s)) {
                *val &= ~PCI_MSI_FLAGS_ENABLE;
                XEN_PT_WARN(&s->dev, "Can not bind MSI\n");
                return 0;
            }
            msi->initialized = true;
            msi->mapped = true;
        }
        msi->flags |= PCI_MSI_FLAGS_ENABLE;
    } else if (msi->mapped) {
        xen_pt_msi_disable(s);
    }

    
    *val &= ~PCI_MSI_FLAGS_ENABLE;
    *val |= raw_val & PCI_MSI_FLAGS_ENABLE;

    return 0;
}


static int xen_pt_msgaddr64_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    
    if (!(s->msi->flags & PCI_MSI_FLAGS_64BIT)) {
        *data = XEN_PT_INVALID_REG;
    } else {
        *data = reg->init_val;
    }

    return 0;
}


static int xen_pt_msgdata_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    uint32_t flags = s->msi->flags;
    uint32_t offset = reg->offset;

    
    if (xen_pt_msgdata_check_type(offset, flags)) {
        *data = reg->init_val;
    } else {
        *data = XEN_PT_INVALID_REG;
    }
    return 0;
}


static int xen_pt_msgaddr32_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint32_t *val, uint32_t dev_value, uint32_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;
    uint32_t old_addr = cfg_entry->data;

    
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);
    s->msi->addr_lo = cfg_entry->data;

    
    throughable_mask = ~reg->emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    
    if (cfg_entry->data != old_addr) {
        if (s->msi->mapped) {
            xen_pt_msi_update(s);
        }
    }

    return 0;
}

static int xen_pt_msgaddr64_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint32_t *val, uint32_t dev_value, uint32_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint32_t writable_mask = 0;
    uint32_t throughable_mask = 0;
    uint32_t old_addr = cfg_entry->data;

    
    if (!(s->msi->flags & PCI_MSI_FLAGS_64BIT)) {
        XEN_PT_ERR(&s->dev, "Can't write to the upper address without 64 bit support\n");
        return -1;
    }

    
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);
    
    s->msi->addr_hi = cfg_entry->data;

    
    throughable_mask = ~reg->emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    
    if (cfg_entry->data != old_addr) {
        if (s->msi->mapped) {
            xen_pt_msi_update(s);
        }
    }

    return 0;
}




static int xen_pt_msgdata_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *val, uint16_t dev_value, uint16_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    XenPTMSI *msi = s->msi;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    uint16_t old_data = cfg_entry->data;
    uint32_t offset = reg->offset;

    
    if (!xen_pt_msgdata_check_type(offset, msi->flags)) {
        
        XEN_PT_ERR(&s->dev, "the offset does not match the 32/64 bit type!\n");
        return -1;
    }

    
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);
    
    msi->data = cfg_entry->data;

    
    throughable_mask = ~reg->emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    
    if (cfg_entry->data != old_data) {
        if (msi->mapped) {
            xen_pt_msi_update(s);
        }
    }

    return 0;
}


static XenPTRegInfo xen_pt_emu_reg_msi[] = {
    
    {
        .offset     = PCI_CAP_LIST_NEXT, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0xFF, .init       = xen_pt_ptr_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },  {









        .offset     = PCI_MSI_FLAGS, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0xFF8E, .emu_mask   = 0x007F, .init       = xen_pt_msgctrl_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_msgctrl_reg_write, },  {









        .offset     = PCI_MSI_ADDRESS_LO, .size       = 4, .init_val   = 0x00000000, .ro_mask    = 0x00000003, .emu_mask   = 0xFFFFFFFF, .no_wb      = 1, .init       = xen_pt_common_reg_init, .u.dw.read  = xen_pt_long_reg_read, .u.dw.write = xen_pt_msgaddr32_reg_write, },  {










        .offset     = PCI_MSI_ADDRESS_HI, .size       = 4, .init_val   = 0x00000000, .ro_mask    = 0x00000000, .emu_mask   = 0xFFFFFFFF, .no_wb      = 1, .init       = xen_pt_msgaddr64_reg_init, .u.dw.read  = xen_pt_long_reg_read, .u.dw.write = xen_pt_msgaddr64_reg_write, },  {










        .offset     = PCI_MSI_DATA_32, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0x0000, .emu_mask   = 0xFFFF, .no_wb      = 1, .init       = xen_pt_msgdata_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_msgdata_reg_write, },  {










        .offset     = PCI_MSI_DATA_64, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0x0000, .emu_mask   = 0xFFFF, .no_wb      = 1, .init       = xen_pt_msgdata_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_msgdata_reg_write, }, {









        .size = 0, }, };






static int xen_pt_msixctrl_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    PCIDevice *d = &s->dev;
    uint16_t reg_field = 0;

    
    reg_field = pci_get_word(d->config + real_offset);

    if (reg_field & PCI_MSIX_FLAGS_ENABLE) {
        XEN_PT_LOG(d, "MSIX already enabled, disabling it first\n");
        xen_host_pci_set_word(&s->real_device, real_offset, reg_field & ~PCI_MSIX_FLAGS_ENABLE);
    }

    s->msix->ctrl_offset = real_offset;

    *data = reg->init_val;
    return 0;
}
static int xen_pt_msixctrl_reg_write(XenPCIPassthroughState *s, XenPTReg *cfg_entry, uint16_t *val, uint16_t dev_value, uint16_t valid_mask)

{
    XenPTRegInfo *reg = cfg_entry->reg;
    uint16_t writable_mask = 0;
    uint16_t throughable_mask = 0;
    int debug_msix_enabled_old;

    
    writable_mask = reg->emu_mask & ~reg->ro_mask & valid_mask;
    cfg_entry->data = XEN_PT_MERGE_VALUE(*val, cfg_entry->data, writable_mask);

    
    throughable_mask = ~reg->emu_mask & valid_mask;
    *val = XEN_PT_MERGE_VALUE(*val, dev_value, throughable_mask);

    
    if ((*val & PCI_MSIX_FLAGS_ENABLE)
        && !(*val & PCI_MSIX_FLAGS_MASKALL)) {
        xen_pt_msix_update(s);
    } else if (!(*val & PCI_MSIX_FLAGS_ENABLE) && s->msix->enabled) {
        xen_pt_msix_disable(s);
    }

    debug_msix_enabled_old = s->msix->enabled;
    s->msix->enabled = !!(*val & PCI_MSIX_FLAGS_ENABLE);
    if (s->msix->enabled != debug_msix_enabled_old) {
        XEN_PT_LOG(&s->dev, "%s MSI-X\n", s->msix->enabled ? "enable" : "disable");
    }

    return 0;
}


static XenPTRegInfo xen_pt_emu_reg_msix[] = {
    
    {
        .offset     = PCI_CAP_LIST_NEXT, .size       = 1, .init_val   = 0x00, .ro_mask    = 0xFF, .emu_mask   = 0xFF, .init       = xen_pt_ptr_reg_init, .u.b.read   = xen_pt_byte_reg_read, .u.b.write  = xen_pt_byte_reg_write, },  {









        .offset     = PCI_MSI_FLAGS, .size       = 2, .init_val   = 0x0000, .ro_mask    = 0x3FFF, .emu_mask   = 0x0000, .init       = xen_pt_msixctrl_reg_init, .u.w.read   = xen_pt_word_reg_read, .u.w.write  = xen_pt_msixctrl_reg_write, }, {








        .size = 0, }, };







static int xen_pt_reg_grp_size_init(XenPCIPassthroughState *s, const XenPTRegGroupInfo *grp_reg, uint32_t base_offset, uint8_t *size)

{
    *size = grp_reg->grp_size;
    return 0;
}

static int xen_pt_vendor_size_init(XenPCIPassthroughState *s, const XenPTRegGroupInfo *grp_reg, uint32_t base_offset, uint8_t *size)

{
    *size = pci_get_byte(s->dev.config + base_offset + 0x02);
    return 0;
}

static int xen_pt_pcie_size_init(XenPCIPassthroughState *s, const XenPTRegGroupInfo *grp_reg, uint32_t base_offset, uint8_t *size)

{
    PCIDevice *d = &s->dev;
    uint8_t version = get_capability_version(s, base_offset);
    uint8_t type = get_device_type(s, base_offset);
    uint8_t pcie_size = 0;


    
    
    if (version == 1) {
        
        switch (type) {
        case PCI_EXP_TYPE_ENDPOINT:
        case PCI_EXP_TYPE_LEG_END:
            pcie_size = 0x14;
            break;
        case PCI_EXP_TYPE_RC_END:
            
            pcie_size = 0x0C;
            break;
            
        case PCI_EXP_TYPE_ROOT_PORT:
        case PCI_EXP_TYPE_UPSTREAM:
        case PCI_EXP_TYPE_DOWNSTREAM:
        case PCI_EXP_TYPE_PCI_BRIDGE:
        case PCI_EXP_TYPE_PCIE_BRIDGE:
        case PCI_EXP_TYPE_RC_EC:
        default:
            XEN_PT_ERR(d, "Unsupported device/port type %#x.\n", type);
            return -1;
        }
    }
    
    else if (version == 2) {
        switch (type) {
        case PCI_EXP_TYPE_ENDPOINT:
        case PCI_EXP_TYPE_LEG_END:
        case PCI_EXP_TYPE_RC_END:
            
            pcie_size = 0x3C;
            break;
            
        case PCI_EXP_TYPE_ROOT_PORT:
        case PCI_EXP_TYPE_UPSTREAM:
        case PCI_EXP_TYPE_DOWNSTREAM:
        case PCI_EXP_TYPE_PCI_BRIDGE:
        case PCI_EXP_TYPE_PCIE_BRIDGE:
        case PCI_EXP_TYPE_RC_EC:
        default:
            XEN_PT_ERR(d, "Unsupported device/port type %#x.\n", type);
            return -1;
        }
    } else {
        XEN_PT_ERR(d, "Unsupported capability version %#x.\n", version);
        return -1;
    }

    *size = pcie_size;
    return 0;
}

static int xen_pt_msi_size_init(XenPCIPassthroughState *s, const XenPTRegGroupInfo *grp_reg, uint32_t base_offset, uint8_t *size)

{
    PCIDevice *d = &s->dev;
    uint16_t msg_ctrl = 0;
    uint8_t msi_size = 0xa;

    msg_ctrl = pci_get_word(d->config + (base_offset + PCI_MSI_FLAGS));

    
    if (msg_ctrl & PCI_MSI_FLAGS_64BIT) {
        msi_size += 4;
    }
    if (msg_ctrl & PCI_MSI_FLAGS_MASKBIT) {
        msi_size += 10;
    }

    s->msi = g_new0(XenPTMSI, 1);
    s->msi->pirq = XEN_PT_UNASSIGNED_PIRQ;

    *size = msi_size;
    return 0;
}

static int xen_pt_msix_size_init(XenPCIPassthroughState *s, const XenPTRegGroupInfo *grp_reg, uint32_t base_offset, uint8_t *size)

{
    int rc = 0;

    rc = xen_pt_msix_init(s, base_offset);

    if (rc < 0) {
        XEN_PT_ERR(&s->dev, "Internal error: Invalid xen_pt_msix_init.\n");
        return rc;
    }

    *size = grp_reg->grp_size;
    return 0;
}


static const XenPTRegGroupInfo xen_pt_emu_reg_grps[] = {
    
    {
        .grp_id      = 0xFF, .grp_type    = XEN_PT_GRP_TYPE_EMU, .grp_size    = 0x40, .size_init   = xen_pt_reg_grp_size_init, .emu_regs = xen_pt_emu_reg_header0, },  {






        .grp_id      = PCI_CAP_ID_PM, .grp_type    = XEN_PT_GRP_TYPE_EMU, .grp_size    = PCI_PM_SIZEOF, .size_init   = xen_pt_reg_grp_size_init, .emu_regs = xen_pt_emu_reg_pm, },  {






        .grp_id     = PCI_CAP_ID_AGP, .grp_type   = XEN_PT_GRP_TYPE_HARDWIRED, .grp_size   = 0x30, .size_init  = xen_pt_reg_grp_size_init, },  {





        .grp_id      = PCI_CAP_ID_VPD, .grp_type    = XEN_PT_GRP_TYPE_EMU, .grp_size    = 0x08, .size_init   = xen_pt_reg_grp_size_init, .emu_regs = xen_pt_emu_reg_vpd, },  {






        .grp_id     = PCI_CAP_ID_SLOTID, .grp_type   = XEN_PT_GRP_TYPE_HARDWIRED, .grp_size   = 0x04, .size_init  = xen_pt_reg_grp_size_init, },  {





        .grp_id      = PCI_CAP_ID_MSI, .grp_type    = XEN_PT_GRP_TYPE_EMU, .grp_size    = 0xFF, .size_init   = xen_pt_msi_size_init, .emu_regs = xen_pt_emu_reg_msi, },  {






        .grp_id     = PCI_CAP_ID_PCIX, .grp_type   = XEN_PT_GRP_TYPE_HARDWIRED, .grp_size   = 0x18, .size_init  = xen_pt_reg_grp_size_init, },  {





        .grp_id      = PCI_CAP_ID_VNDR, .grp_type    = XEN_PT_GRP_TYPE_EMU, .grp_size    = 0xFF, .size_init   = xen_pt_vendor_size_init, .emu_regs = xen_pt_emu_reg_vendor, },  {






        .grp_id     = PCI_CAP_ID_SHPC, .grp_type   = XEN_PT_GRP_TYPE_HARDWIRED, .grp_size   = 0x08, .size_init  = xen_pt_reg_grp_size_init, },  {





        .grp_id     = PCI_CAP_ID_SSVID, .grp_type   = XEN_PT_GRP_TYPE_HARDWIRED, .grp_size   = 0x08, .size_init  = xen_pt_reg_grp_size_init, },  {





        .grp_id     = PCI_CAP_ID_AGP3, .grp_type   = XEN_PT_GRP_TYPE_HARDWIRED, .grp_size   = 0x30, .size_init  = xen_pt_reg_grp_size_init, },  {





        .grp_id      = PCI_CAP_ID_EXP, .grp_type    = XEN_PT_GRP_TYPE_EMU, .grp_size    = 0xFF, .size_init   = xen_pt_pcie_size_init, .emu_regs = xen_pt_emu_reg_pcie, },  {






        .grp_id      = PCI_CAP_ID_MSIX, .grp_type    = XEN_PT_GRP_TYPE_EMU, .grp_size    = 0x0C, .size_init   = xen_pt_msix_size_init, .emu_regs = xen_pt_emu_reg_msix, }, {





        .grp_size = 0, }, };



static int xen_pt_ptr_reg_init(XenPCIPassthroughState *s, XenPTRegInfo *reg, uint32_t real_offset, uint32_t *data)

{
    int i;
    uint8_t *config = s->dev.config;
    uint32_t reg_field = pci_get_byte(config + real_offset);
    uint8_t cap_id = 0;

    
    while (reg_field) {
        for (i = 0; xen_pt_emu_reg_grps[i].grp_size != 0; i++) {
            if (xen_pt_hide_dev_cap(&s->real_device, xen_pt_emu_reg_grps[i].grp_id)) {
                continue;
            }

            cap_id = pci_get_byte(config + reg_field + PCI_CAP_LIST_ID);
            if (xen_pt_emu_reg_grps[i].grp_id == cap_id) {
                if (xen_pt_emu_reg_grps[i].grp_type == XEN_PT_GRP_TYPE_EMU) {
                    goto out;
                }
                
                break;
            }
        }

        
        reg_field = pci_get_byte(config + reg_field + PCI_CAP_LIST_NEXT);
    }

out:
    *data = reg_field;
    return 0;
}




static uint8_t find_cap_offset(XenPCIPassthroughState *s, uint8_t cap)
{
    uint8_t id;
    unsigned max_cap = PCI_CAP_MAX;
    uint8_t pos = PCI_CAPABILITY_LIST;
    uint8_t status = 0;

    if (xen_host_pci_get_byte(&s->real_device, PCI_STATUS, &status)) {
        return 0;
    }
    if ((status & PCI_STATUS_CAP_LIST) == 0) {
        return 0;
    }

    while (max_cap--) {
        if (xen_host_pci_get_byte(&s->real_device, pos, &pos)) {
            break;
        }
        if (pos < PCI_CONFIG_HEADER_SIZE) {
            break;
        }

        pos &= ~3;
        if (xen_host_pci_get_byte(&s->real_device, pos + PCI_CAP_LIST_ID, &id)) {
            break;
        }

        if (id == 0xff) {
            break;
        }
        if (id == cap) {
            return pos;
        }

        pos += PCI_CAP_LIST_NEXT;
    }
    return 0;
}

static int xen_pt_config_reg_init(XenPCIPassthroughState *s, XenPTRegGroup *reg_grp, XenPTRegInfo *reg)
{
    XenPTReg *reg_entry;
    uint32_t data = 0;
    int rc = 0;

    reg_entry = g_new0(XenPTReg, 1);
    reg_entry->reg = reg;

    if (reg->init) {
        
        rc = reg->init(s, reg_entry->reg, reg_grp->base_offset + reg->offset, &data);
        if (rc < 0) {
            g_free(reg_entry);
            return rc;
        }
        if (data == XEN_PT_INVALID_REG) {
            
            g_free(reg_entry);
            return 0;
        }
        
        reg_entry->data = data;
    }
    
    QLIST_INSERT_HEAD(&reg_grp->reg_tbl_list, reg_entry, entries);

    return 0;
}

int xen_pt_config_init(XenPCIPassthroughState *s)
{
    int i, rc;

    QLIST_INIT(&s->reg_grps);

    for (i = 0; xen_pt_emu_reg_grps[i].grp_size != 0; i++) {
        uint32_t reg_grp_offset = 0;
        XenPTRegGroup *reg_grp_entry = NULL;

        if (xen_pt_emu_reg_grps[i].grp_id != 0xFF) {
            if (xen_pt_hide_dev_cap(&s->real_device, xen_pt_emu_reg_grps[i].grp_id)) {
                continue;
            }

            reg_grp_offset = find_cap_offset(s, xen_pt_emu_reg_grps[i].grp_id);

            if (!reg_grp_offset) {
                continue;
            }
        }

        reg_grp_entry = g_new0(XenPTRegGroup, 1);
        QLIST_INIT(&reg_grp_entry->reg_tbl_list);
        QLIST_INSERT_HEAD(&s->reg_grps, reg_grp_entry, entries);

        reg_grp_entry->base_offset = reg_grp_offset;
        reg_grp_entry->reg_grp = xen_pt_emu_reg_grps + i;
        if (xen_pt_emu_reg_grps[i].size_init) {
            
            rc = xen_pt_emu_reg_grps[i].size_init(s, reg_grp_entry->reg_grp, reg_grp_offset, &reg_grp_entry->size);

            if (rc < 0) {
                xen_pt_config_delete(s);
                return rc;
            }
        }

        if (xen_pt_emu_reg_grps[i].grp_type == XEN_PT_GRP_TYPE_EMU) {
            if (xen_pt_emu_reg_grps[i].emu_regs) {
                int j = 0;
                XenPTRegInfo *regs = xen_pt_emu_reg_grps[i].emu_regs;
                
                for (j = 0; regs->size != 0; j++, regs++) {
                    
                    rc = xen_pt_config_reg_init(s, reg_grp_entry, regs);
                    if (rc < 0) {
                        xen_pt_config_delete(s);
                        return rc;
                    }
                }
            }
        }
    }

    return 0;
}


void xen_pt_config_delete(XenPCIPassthroughState *s)
{
    struct XenPTRegGroup *reg_group, *next_grp;
    struct XenPTReg *reg, *next_reg;

    
    if (s->msix) {
        xen_pt_msix_delete(s);
    }
    if (s->msi) {
        g_free(s->msi);
    }

    
    QLIST_FOREACH_SAFE(reg_group, &s->reg_grps, entries, next_grp) {
        
        QLIST_FOREACH_SAFE(reg, &reg_group->reg_tbl_list, entries, next_reg) {
            QLIST_REMOVE(reg, entries);
            g_free(reg);
        }

        QLIST_REMOVE(reg_group, entries);
        g_free(reg_group);
    }
}
