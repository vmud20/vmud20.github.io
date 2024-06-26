













static uint8_t xen_pt_mapped_machine_irq[XEN_PT_NR_IRQS] = {0};

void xen_pt_log(const PCIDevice *d, const char *f, ...)
{
    va_list ap;

    va_start(ap, f);
    if (d) {
        fprintf(stderr, "[%02x:%02x.%d] ", pci_bus_num(d->bus), PCI_SLOT(d->devfn), PCI_FUNC(d->devfn));
    }
    vfprintf(stderr, f, ap);
    va_end(ap);
}



static int xen_pt_pci_config_access_check(PCIDevice *d, uint32_t addr, int len)
{
    
    if (addr >= 0xFF) {
        XEN_PT_ERR(d, "Failed to access register with offset exceeding 0xFF. " "(addr: 0x%02x, len: %d)\n", addr, len);
        return -1;
    }

    
    if ((len != 1) && (len != 2) && (len != 4)) {
        XEN_PT_ERR(d, "Failed to access register with invalid access length. " "(addr: 0x%02x, len: %d)\n", addr, len);
        return -1;
    }

    
    if (addr & (len - 1)) {
        XEN_PT_ERR(d, "Failed to access register with invalid access size " "alignment. (addr: 0x%02x, len: %d)\n", addr, len);
        return -1;
    }

    return 0;
}

int xen_pt_bar_offset_to_index(uint32_t offset)
{
    int index = 0;

    
    if (offset == PCI_ROM_ADDRESS) {
        return PCI_ROM_SLOT;
    }

    
    index = (offset - PCI_BASE_ADDRESS_0) >> 2;
    if (index >= PCI_NUM_REGIONS) {
        return -1;
    }

    return index;
}

static uint32_t xen_pt_pci_read_config(PCIDevice *d, uint32_t addr, int len)
{
    XenPCIPassthroughState *s = DO_UPCAST(XenPCIPassthroughState, dev, d);
    uint32_t val = 0;
    XenPTRegGroup *reg_grp_entry = NULL;
    XenPTReg *reg_entry = NULL;
    int rc = 0;
    int emul_len = 0;
    uint32_t find_addr = addr;

    if (xen_pt_pci_config_access_check(d, addr, len)) {
        goto exit;
    }

    
    reg_grp_entry = xen_pt_find_reg_grp(s, addr);
    if (reg_grp_entry) {
        
        if (reg_grp_entry->reg_grp->grp_type == XEN_PT_GRP_TYPE_HARDWIRED) {
            
            val = 0;
            goto exit;
        }
    }

    
    rc = xen_host_pci_get_block(&s->real_device, addr, (uint8_t *)&val, len);
    if (rc < 0) {
        XEN_PT_ERR(d, "pci_read_block failed. return value: %d.\n", rc);
        memset(&val, 0xff, len);
    }

    
    if (reg_grp_entry == NULL) {
        goto exit;
    }

    
    val <<= (addr & 3) << 3;
    emul_len = len;

    
    while (emul_len > 0) {
        
        reg_entry = xen_pt_find_reg(reg_grp_entry, find_addr);
        if (reg_entry) {
            XenPTRegInfo *reg = reg_entry->reg;
            uint32_t real_offset = reg_grp_entry->base_offset + reg->offset;
            uint32_t valid_mask = 0xFFFFFFFF >> ((4 - emul_len) << 3);
            uint8_t *ptr_val = NULL;

            valid_mask <<= (find_addr - real_offset) << 3;
            ptr_val = (uint8_t *)&val + (real_offset & 3);

            
            switch (reg->size) {
            case 1:
                if (reg->u.b.read) {
                    rc = reg->u.b.read(s, reg_entry, ptr_val, valid_mask);
                }
                break;
            case 2:
                if (reg->u.w.read) {
                    rc = reg->u.w.read(s, reg_entry, (uint16_t *)ptr_val, valid_mask);
                }
                break;
            case 4:
                if (reg->u.dw.read) {
                    rc = reg->u.dw.read(s, reg_entry, (uint32_t *)ptr_val, valid_mask);
                }
                break;
            }

            if (rc < 0) {
                xen_shutdown_fatal_error("Internal error: Invalid read " "emulation. (%s, rc: %d)\n", __func__, rc);

                return 0;
            }

            
            emul_len -= reg->size;
            if (emul_len > 0) {
                find_addr = real_offset + reg->size;
            }
        } else {
            
            emul_len--;
            find_addr++;
        }
    }

    
    val >>= ((addr & 3) << 3);

exit:
    XEN_PT_LOG_CONFIG(d, addr, val, len);
    return val;
}

static void xen_pt_pci_write_config(PCIDevice *d, uint32_t addr, uint32_t val, int len)
{
    XenPCIPassthroughState *s = DO_UPCAST(XenPCIPassthroughState, dev, d);
    int index = 0;
    XenPTRegGroup *reg_grp_entry = NULL;
    int rc = 0;
    uint32_t read_val = 0;
    int emul_len = 0;
    XenPTReg *reg_entry = NULL;
    uint32_t find_addr = addr;
    XenPTRegInfo *reg = NULL;

    if (xen_pt_pci_config_access_check(d, addr, len)) {
        return;
    }

    XEN_PT_LOG_CONFIG(d, addr, val, len);

    
    index = xen_pt_bar_offset_to_index(addr);
    if ((index >= 0) && (val > 0 && val < XEN_PT_BAR_ALLF) && (s->bases[index].bar_flag == XEN_PT_BAR_FLAG_UNUSED)) {
        XEN_PT_WARN(d, "Guest attempt to set address to unused Base Address " "Register. (addr: 0x%02x, len: %d)\n", addr, len);
    }

    
    reg_grp_entry = xen_pt_find_reg_grp(s, addr);
    if (reg_grp_entry) {
        
        if (reg_grp_entry->reg_grp->grp_type == XEN_PT_GRP_TYPE_HARDWIRED) {
            
            XEN_PT_WARN(d, "Access to 0-Hardwired register. " "(addr: 0x%02x, len: %d)\n", addr, len);
            return;
        }
    }

    rc = xen_host_pci_get_block(&s->real_device, addr, (uint8_t *)&read_val, len);
    if (rc < 0) {
        XEN_PT_ERR(d, "pci_read_block failed. return value: %d.\n", rc);
        memset(&read_val, 0xff, len);
    }

    
    if (reg_grp_entry == NULL) {
        goto out;
    }

    memory_region_transaction_begin();
    pci_default_write_config(d, addr, val, len);

    
    read_val <<= (addr & 3) << 3;
    val <<= (addr & 3) << 3;
    emul_len = len;

    
    while (emul_len > 0) {
        
        reg_entry = xen_pt_find_reg(reg_grp_entry, find_addr);
        if (reg_entry) {
            reg = reg_entry->reg;
            uint32_t real_offset = reg_grp_entry->base_offset + reg->offset;
            uint32_t valid_mask = 0xFFFFFFFF >> ((4 - emul_len) << 3);
            uint8_t *ptr_val = NULL;

            valid_mask <<= (find_addr - real_offset) << 3;
            ptr_val = (uint8_t *)&val + (real_offset & 3);

            
            switch (reg->size) {
            case 1:
                if (reg->u.b.write) {
                    rc = reg->u.b.write(s, reg_entry, ptr_val, read_val >> ((real_offset & 3) << 3), valid_mask);

                }
                break;
            case 2:
                if (reg->u.w.write) {
                    rc = reg->u.w.write(s, reg_entry, (uint16_t *)ptr_val, (read_val >> ((real_offset & 3) << 3)), valid_mask);

                }
                break;
            case 4:
                if (reg->u.dw.write) {
                    rc = reg->u.dw.write(s, reg_entry, (uint32_t *)ptr_val, (read_val >> ((real_offset & 3) << 3)), valid_mask);

                }
                break;
            }

            if (rc < 0) {
                xen_shutdown_fatal_error("Internal error: Invalid write" " emulation. (%s, rc: %d)\n", __func__, rc);

                return;
            }

            
            emul_len -= reg->size;
            if (emul_len > 0) {
                find_addr = real_offset + reg->size;
            }
        } else {
            
            emul_len--;
            find_addr++;
        }
    }

    
    val >>= (addr & 3) << 3;

    memory_region_transaction_commit();

out:
    if (!(reg && reg->no_wb)) {
        
        rc = xen_host_pci_set_block(&s->real_device, addr, (uint8_t *)&val, len);

        if (rc < 0) {
            XEN_PT_ERR(d, "pci_write_block failed. return value: %d.\n", rc);
        }
    }
}



static uint64_t xen_pt_bar_read(void *o, hwaddr addr, unsigned size)
{
    PCIDevice *d = o;
    
    XEN_PT_ERR(d, "Should not read BAR through QEMU. @0x"TARGET_FMT_plx"\n", addr);
    return 0;
}
static void xen_pt_bar_write(void *o, hwaddr addr, uint64_t val, unsigned size)
{
    PCIDevice *d = o;
    
    XEN_PT_ERR(d, "Should not write BAR through QEMU. @0x"TARGET_FMT_plx"\n", addr);
}

static const MemoryRegionOps ops = {
    .endianness = DEVICE_NATIVE_ENDIAN, .read = xen_pt_bar_read, .write = xen_pt_bar_write, };



static int xen_pt_register_regions(XenPCIPassthroughState *s)
{
    int i = 0;
    XenHostPCIDevice *d = &s->real_device;

    
    for (i = 0; i < PCI_ROM_SLOT; i++) {
        XenHostPCIIORegion *r = &d->io_regions[i];
        uint8_t type;

        if (r->base_addr == 0 || r->size == 0) {
            continue;
        }

        s->bases[i].access.u = r->base_addr;

        if (r->type & XEN_HOST_PCI_REGION_TYPE_IO) {
            type = PCI_BASE_ADDRESS_SPACE_IO;
        } else {
            type = PCI_BASE_ADDRESS_SPACE_MEMORY;
            if (r->type & XEN_HOST_PCI_REGION_TYPE_PREFETCH) {
                type |= PCI_BASE_ADDRESS_MEM_PREFETCH;
            }
            if (r->type & XEN_HOST_PCI_REGION_TYPE_MEM_64) {
                type |= PCI_BASE_ADDRESS_MEM_TYPE_64;
            }
        }

        memory_region_init_io(&s->bar[i], OBJECT(s), &ops, &s->dev, "xen-pci-pt-bar", r->size);
        pci_register_bar(&s->dev, i, type, &s->bar[i]);

        XEN_PT_LOG(&s->dev, "IO region %i registered (size=0x%08"PRIx64 " base_addr=0x%08"PRIx64" type: %#x)\n", i, r->size, r->base_addr, type);

    }

    
    if (d->rom.base_addr && d->rom.size) {
        uint32_t bar_data = 0;

        
        if (xen_host_pci_get_long(d, PCI_ROM_ADDRESS, &bar_data)) {
            return 0;
        }
        if ((bar_data & PCI_ROM_ADDRESS_MASK) == 0) {
            bar_data |= d->rom.base_addr & PCI_ROM_ADDRESS_MASK;
            xen_host_pci_set_long(d, PCI_ROM_ADDRESS, bar_data);
        }

        s->bases[PCI_ROM_SLOT].access.maddr = d->rom.base_addr;

        memory_region_init_io(&s->rom, OBJECT(s), &ops, &s->dev, "xen-pci-pt-rom", d->rom.size);
        pci_register_bar(&s->dev, PCI_ROM_SLOT, PCI_BASE_ADDRESS_MEM_PREFETCH, &s->rom);

        XEN_PT_LOG(&s->dev, "Expansion ROM registered (size=0x%08"PRIx64 " base_addr=0x%08"PRIx64")\n", d->rom.size, d->rom.base_addr);

    }

    return 0;
}



static int xen_pt_bar_from_region(XenPCIPassthroughState *s, MemoryRegion *mr)
{
    int i = 0;

    for (i = 0; i < PCI_NUM_REGIONS - 1; i++) {
        if (mr == &s->bar[i]) {
            return i;
        }
    }
    if (mr == &s->rom) {
        return PCI_ROM_SLOT;
    }
    return -1;
}


struct CheckBarArgs {
    XenPCIPassthroughState *s;
    pcibus_t addr;
    pcibus_t size;
    uint8_t type;
    bool rc;
};
static void xen_pt_check_bar_overlap(PCIBus *bus, PCIDevice *d, void *opaque)
{
    struct CheckBarArgs *arg = opaque;
    XenPCIPassthroughState *s = arg->s;
    uint8_t type = arg->type;
    int i;

    if (d->devfn == s->dev.devfn) {
        return;
    }

    
    for (i = 0; i < PCI_NUM_REGIONS; i++) {
        const PCIIORegion *r = &d->io_regions[i];

        if (!r->size) {
            continue;
        }
        if ((type & PCI_BASE_ADDRESS_SPACE_IO)
            != (r->type & PCI_BASE_ADDRESS_SPACE_IO)) {
            continue;
        }

        if (ranges_overlap(arg->addr, arg->size, r->addr, r->size)) {
            XEN_PT_WARN(&s->dev, "Overlapped to device [%02x:%02x.%d] Region: %i" " (addr: %#"FMT_PCIBUS", len: %#"FMT_PCIBUS")\n", pci_bus_num(bus), PCI_SLOT(d->devfn), PCI_FUNC(d->devfn), i, r->addr, r->size);



            arg->rc = true;
        }
    }
}

static void xen_pt_region_update(XenPCIPassthroughState *s, MemoryRegionSection *sec, bool adding)
{
    PCIDevice *d = &s->dev;
    MemoryRegion *mr = sec->mr;
    int bar = -1;
    int rc;
    int op = adding ? DPCI_ADD_MAPPING : DPCI_REMOVE_MAPPING;
    struct CheckBarArgs args = {
        .s = s, .addr = sec->offset_within_address_space, .size = int128_get64(sec->size), .rc = false, };




    bar = xen_pt_bar_from_region(s, mr);
    if (bar == -1 && (!s->msix || &s->msix->mmio != mr)) {
        return;
    }

    if (s->msix && &s->msix->mmio == mr) {
        if (adding) {
            s->msix->mmio_base_addr = sec->offset_within_address_space;
            rc = xen_pt_msix_update_remap(s, s->msix->bar_index);
        }
        return;
    }

    args.type = d->io_regions[bar].type;
    pci_for_each_device(d->bus, pci_bus_num(d->bus), xen_pt_check_bar_overlap, &args);
    if (args.rc) {
        XEN_PT_WARN(d, "Region: %d (addr: %#"FMT_PCIBUS ", len: %#"FMT_PCIBUS") is overlapped.\n", bar, sec->offset_within_address_space, int128_get64(sec->size));


    }

    if (d->io_regions[bar].type & PCI_BASE_ADDRESS_SPACE_IO) {
        uint32_t guest_port = sec->offset_within_address_space;
        uint32_t machine_port = s->bases[bar].access.pio_base;
        uint32_t size = int128_get64(sec->size);
        rc = xc_domain_ioport_mapping(xen_xc, xen_domid, guest_port, machine_port, size, op);

        if (rc) {
            XEN_PT_ERR(d, "%s ioport mapping failed! (rc: %i)\n", adding ? "create new" : "remove old", rc);
        }
    } else {
        pcibus_t guest_addr = sec->offset_within_address_space;
        pcibus_t machine_addr = s->bases[bar].access.maddr + sec->offset_within_region;
        pcibus_t size = int128_get64(sec->size);
        rc = xc_domain_memory_mapping(xen_xc, xen_domid, XEN_PFN(guest_addr + XC_PAGE_SIZE - 1), XEN_PFN(machine_addr + XC_PAGE_SIZE - 1), XEN_PFN(size + XC_PAGE_SIZE - 1), op);



        if (rc) {
            XEN_PT_ERR(d, "%s mem mapping failed! (rc: %i)\n", adding ? "create new" : "remove old", rc);
        }
    }
}

static void xen_pt_region_add(MemoryListener *l, MemoryRegionSection *sec)
{
    XenPCIPassthroughState *s = container_of(l, XenPCIPassthroughState, memory_listener);

    memory_region_ref(sec->mr);
    xen_pt_region_update(s, sec, true);
}

static void xen_pt_region_del(MemoryListener *l, MemoryRegionSection *sec)
{
    XenPCIPassthroughState *s = container_of(l, XenPCIPassthroughState, memory_listener);

    xen_pt_region_update(s, sec, false);
    memory_region_unref(sec->mr);
}

static void xen_pt_io_region_add(MemoryListener *l, MemoryRegionSection *sec)
{
    XenPCIPassthroughState *s = container_of(l, XenPCIPassthroughState, io_listener);

    memory_region_ref(sec->mr);
    xen_pt_region_update(s, sec, true);
}

static void xen_pt_io_region_del(MemoryListener *l, MemoryRegionSection *sec)
{
    XenPCIPassthroughState *s = container_of(l, XenPCIPassthroughState, io_listener);

    xen_pt_region_update(s, sec, false);
    memory_region_unref(sec->mr);
}

static const MemoryListener xen_pt_memory_listener = {
    .region_add = xen_pt_region_add, .region_del = xen_pt_region_del, .priority = 10, };



static const MemoryListener xen_pt_io_listener = {
    .region_add = xen_pt_io_region_add, .region_del = xen_pt_io_region_del, .priority = 10, };





static int xen_pt_initfn(PCIDevice *d)
{
    XenPCIPassthroughState *s = DO_UPCAST(XenPCIPassthroughState, dev, d);
    int rc = 0;
    uint8_t machine_irq = 0;
    int pirq = XEN_PT_UNASSIGNED_PIRQ;

    
    XEN_PT_LOG(d, "Assigning real physical device %02x:%02x.%d" " to devfn %#x\n", s->hostaddr.bus, s->hostaddr.slot, s->hostaddr.function, s->dev.devfn);



    rc = xen_host_pci_device_get(&s->real_device, s->hostaddr.domain, s->hostaddr.bus, s->hostaddr.slot, s->hostaddr.function);

    if (rc) {
        XEN_PT_ERR(d, "Failed to \"open\" the real pci device. rc: %i\n", rc);
        return -1;
    }

    s->is_virtfn = s->real_device.is_virtfn;
    if (s->is_virtfn) {
        XEN_PT_LOG(d, "%04x:%02x:%02x.%d is a SR-IOV Virtual Function\n", s->real_device.domain, s->real_device.bus, s->real_device.dev, s->real_device.func);

    }

    
    if (xen_host_pci_get_block(&s->real_device, 0, d->config, PCI_CONFIG_SPACE_SIZE) == -1) {
        xen_host_pci_device_put(&s->real_device);
        return -1;
    }

    s->memory_listener = xen_pt_memory_listener;
    s->io_listener = xen_pt_io_listener;

    
    xen_pt_register_regions(s);

    
    if (xen_pt_config_init(s)) {
        XEN_PT_ERR(d, "PCI Config space initialisation failed.\n");
        xen_host_pci_device_put(&s->real_device);
        return -1;
    }

    
    if (!s->dev.config[PCI_INTERRUPT_PIN]) {
        XEN_PT_LOG(d, "no pin interrupt\n");
        goto out;
    }

    machine_irq = s->real_device.irq;
    rc = xc_physdev_map_pirq(xen_xc, xen_domid, machine_irq, &pirq);

    if (rc < 0) {
        XEN_PT_ERR(d, "Mapping machine irq %u to pirq %i failed, (rc: %d)\n", machine_irq, pirq, rc);

        
        xen_host_pci_set_word(&s->real_device, PCI_COMMAND, pci_get_word(s->dev.config + PCI_COMMAND)

                              | PCI_COMMAND_INTX_DISABLE);
        machine_irq = 0;
        s->machine_irq = 0;
    } else {
        machine_irq = pirq;
        s->machine_irq = pirq;
        xen_pt_mapped_machine_irq[machine_irq]++;
    }

    
    if (machine_irq != 0) {
        uint8_t e_intx = xen_pt_pci_intx(s);

        rc = xc_domain_bind_pt_pci_irq(xen_xc, xen_domid, machine_irq, pci_bus_num(d->bus), PCI_SLOT(d->devfn), e_intx);


        if (rc < 0) {
            XEN_PT_ERR(d, "Binding of interrupt %i failed! (rc: %d)\n", e_intx, rc);

            
            xen_host_pci_set_word(&s->real_device, PCI_COMMAND, *(uint16_t *)(&s->dev.config[PCI_COMMAND])
                                  | PCI_COMMAND_INTX_DISABLE);
            xen_pt_mapped_machine_irq[machine_irq]--;

            if (xen_pt_mapped_machine_irq[machine_irq] == 0) {
                if (xc_physdev_unmap_pirq(xen_xc, xen_domid, machine_irq)) {
                    XEN_PT_ERR(d, "Unmapping of machine interrupt %i failed!" " (rc: %d)\n", machine_irq, rc);
                }
            }
            s->machine_irq = 0;
        }
    }

out:
    memory_listener_register(&s->memory_listener, &s->dev.bus_master_as);
    memory_listener_register(&s->io_listener, &address_space_io);
    XEN_PT_LOG(d, "Real physical device %02x:%02x.%d registered successfully!\n", s->hostaddr.bus, s->hostaddr.slot, s->hostaddr.function);


    return 0;
}

static void xen_pt_unregister_device(PCIDevice *d)
{
    XenPCIPassthroughState *s = DO_UPCAST(XenPCIPassthroughState, dev, d);
    uint8_t machine_irq = s->machine_irq;
    uint8_t intx = xen_pt_pci_intx(s);
    int rc;

    if (machine_irq) {
        rc = xc_domain_unbind_pt_irq(xen_xc, xen_domid, machine_irq, PT_IRQ_TYPE_PCI, pci_bus_num(d->bus), PCI_SLOT(s->dev.devfn), intx, 0 );




        if (rc < 0) {
            XEN_PT_ERR(d, "unbinding of interrupt INT%c failed." " (machine irq: %i, rc: %d)" " But bravely continuing on..\n", 'a' + intx, machine_irq, rc);


        }
    }

    if (s->msi) {
        xen_pt_msi_disable(s);
    }
    if (s->msix) {
        xen_pt_msix_disable(s);
    }

    if (machine_irq) {
        xen_pt_mapped_machine_irq[machine_irq]--;

        if (xen_pt_mapped_machine_irq[machine_irq] == 0) {
            rc = xc_physdev_unmap_pirq(xen_xc, xen_domid, machine_irq);

            if (rc < 0) {
                XEN_PT_ERR(d, "unmapping of interrupt %i failed. (rc: %d)" " But bravely continuing on..\n", machine_irq, rc);

            }
        }
    }

    
    xen_pt_config_delete(s);

    memory_listener_unregister(&s->memory_listener);
    memory_listener_unregister(&s->io_listener);

    xen_host_pci_device_put(&s->real_device);
}

static Property xen_pci_passthrough_properties[] = {
    DEFINE_PROP_PCI_HOST_DEVADDR("hostaddr", XenPCIPassthroughState, hostaddr), DEFINE_PROP_END_OF_LIST(), };


static void xen_pci_passthrough_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = xen_pt_initfn;
    k->exit = xen_pt_unregister_device;
    k->config_read = xen_pt_pci_read_config;
    k->config_write = xen_pt_pci_write_config;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "Assign an host PCI device with Xen";
    dc->props = xen_pci_passthrough_properties;
};

static const TypeInfo xen_pci_passthrough_info = {
    .name = "xen-pci-passthrough", .parent = TYPE_PCI_DEVICE, .instance_size = sizeof(XenPCIPassthroughState), .class_init = xen_pci_passthrough_class_init, };




static void xen_pci_passthrough_register_types(void)
{
    type_register_static(&xen_pci_passthrough_info);
}

type_init(xen_pci_passthrough_register_types)
