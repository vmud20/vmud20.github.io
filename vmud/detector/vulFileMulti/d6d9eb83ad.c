





















int pcie_cap_init(PCIDevice *dev, uint8_t offset, uint8_t type, uint8_t port)
{
    int pos;
    uint8_t *exp_cap;

    assert(pci_is_express(dev));

    pos = pci_add_capability(dev, PCI_CAP_ID_EXP, offset, PCI_EXP_VER2_SIZEOF);
    if (pos < 0) {
        return pos;
    }
    dev->exp.exp_cap = pos;
    exp_cap = dev->config + pos;

    
    pci_set_word(exp_cap + PCI_EXP_FLAGS, ((type << PCI_EXP_FLAGS_TYPE_SHIFT) & PCI_EXP_FLAGS_TYPE) | PCI_EXP_FLAGS_VER2);


    
    pci_set_long(exp_cap + PCI_EXP_DEVCAP, PCI_EXP_DEVCAP_RBER);

    pci_set_long(exp_cap + PCI_EXP_LNKCAP, (port << PCI_EXP_LNKCAP_PN_SHIFT) | PCI_EXP_LNKCAP_ASPMS_0S | PCI_EXP_LNK_MLW_1 | PCI_EXP_LNK_LS_25);




    pci_set_word(exp_cap + PCI_EXP_LNKSTA, PCI_EXP_LNK_MLW_1 | PCI_EXP_LNK_LS_25);

    pci_set_long(exp_cap + PCI_EXP_DEVCAP2, PCI_EXP_DEVCAP2_EFF | PCI_EXP_DEVCAP2_EETLPP);

    pci_set_word(dev->wmask + pos, PCI_EXP_DEVCTL2_EETLPPB);
    return pos;
}

int pcie_endpoint_cap_init(PCIDevice *dev, uint8_t offset)
{
    uint8_t type = PCI_EXP_TYPE_ENDPOINT;

    
    if (pci_bus_is_express(dev->bus) && pci_bus_is_root(dev->bus)) {
        type = PCI_EXP_TYPE_RC_END;
    }

    return pcie_cap_init(dev, offset, type, 0);
}

void pcie_cap_exit(PCIDevice *dev)
{
    pci_del_capability(dev, PCI_CAP_ID_EXP, PCI_EXP_VER2_SIZEOF);
}

uint8_t pcie_cap_get_type(const PCIDevice *dev)
{
    uint32_t pos = dev->exp.exp_cap;
    assert(pos > 0);
    return (pci_get_word(dev->config + pos + PCI_EXP_FLAGS) & PCI_EXP_FLAGS_TYPE) >> PCI_EXP_FLAGS_TYPE_SHIFT;
}




void pcie_cap_flags_set_vector(PCIDevice *dev, uint8_t vector)
{
    uint8_t *exp_cap = dev->config + dev->exp.exp_cap;
    assert(vector < 32);
    pci_word_test_and_clear_mask(exp_cap + PCI_EXP_FLAGS, PCI_EXP_FLAGS_IRQ);
    pci_word_test_and_set_mask(exp_cap + PCI_EXP_FLAGS, vector << PCI_EXP_FLAGS_IRQ_SHIFT);
}

uint8_t pcie_cap_flags_get_vector(PCIDevice *dev)
{
    return (pci_get_word(dev->config + dev->exp.exp_cap + PCI_EXP_FLAGS) & PCI_EXP_FLAGS_IRQ) >> PCI_EXP_FLAGS_IRQ_SHIFT;
}

void pcie_cap_deverr_init(PCIDevice *dev)
{
    uint32_t pos = dev->exp.exp_cap;
    pci_long_test_and_set_mask(dev->config + pos + PCI_EXP_DEVCAP, PCI_EXP_DEVCAP_RBER);
    pci_long_test_and_set_mask(dev->wmask + pos + PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_CERE | PCI_EXP_DEVCTL_NFERE | PCI_EXP_DEVCTL_FERE | PCI_EXP_DEVCTL_URRE);

    pci_long_test_and_set_mask(dev->w1cmask + pos + PCI_EXP_DEVSTA, PCI_EXP_DEVSTA_CED | PCI_EXP_DEVSTA_NFED | PCI_EXP_DEVSTA_URD | PCI_EXP_DEVSTA_URD);

}

void pcie_cap_deverr_reset(PCIDevice *dev)
{
    uint8_t *devctl = dev->config + dev->exp.exp_cap + PCI_EXP_DEVCTL;
    pci_long_test_and_clear_mask(devctl, PCI_EXP_DEVCTL_CERE | PCI_EXP_DEVCTL_NFERE | PCI_EXP_DEVCTL_FERE | PCI_EXP_DEVCTL_URRE);

}

static void hotplug_event_update_event_status(PCIDevice *dev)
{
    uint32_t pos = dev->exp.exp_cap;
    uint8_t *exp_cap = dev->config + pos;
    uint16_t sltctl = pci_get_word(exp_cap + PCI_EXP_SLTCTL);
    uint16_t sltsta = pci_get_word(exp_cap + PCI_EXP_SLTSTA);

    dev->exp.hpev_notified = (sltctl & PCI_EXP_SLTCTL_HPIE) && (sltsta & sltctl & PCI_EXP_HP_EV_SUPPORTED);
}

static void hotplug_event_notify(PCIDevice *dev)
{
    bool prev = dev->exp.hpev_notified;

    hotplug_event_update_event_status(dev);

    if (prev == dev->exp.hpev_notified) {
        return;
    }

    
    if (msix_enabled(dev)) {
        msix_notify(dev, pcie_cap_flags_get_vector(dev));
    } else if (msi_enabled(dev)) {
        msi_notify(dev, pcie_cap_flags_get_vector(dev));
    } else {
        pci_set_irq(dev, dev->exp.hpev_notified);
    }
}

static void hotplug_event_clear(PCIDevice *dev)
{
    hotplug_event_update_event_status(dev);
    if (!msix_enabled(dev) && !msi_enabled(dev) && !dev->exp.hpev_notified) {
        pci_irq_deassert(dev);
    }
}


static void pcie_cap_slot_event(PCIDevice *dev, PCIExpressHotPlugEvent event)
{
    
    if (pci_word_test_and_set_mask(dev->config + dev->exp.exp_cap + PCI_EXP_SLTSTA, event)) {
        return;
    }
    hotplug_event_notify(dev);
}

static void pcie_cap_slot_hotplug_common(PCIDevice *hotplug_dev, DeviceState *dev, uint8_t **exp_cap, Error **errp)

{
    *exp_cap = hotplug_dev->config + hotplug_dev->exp.exp_cap;
    uint16_t sltsta = pci_get_word(*exp_cap + PCI_EXP_SLTSTA);

    PCIE_DEV_PRINTF(PCI_DEVICE(dev), "hotplug state: 0x%x\n", sltsta);
    if (sltsta & PCI_EXP_SLTSTA_EIS) {
        
        error_setg_errno(errp, -EBUSY, "slot is electromechanically locked");
    }
}

void pcie_cap_slot_hotplug_cb(HotplugHandler *hotplug_dev, DeviceState *dev, Error **errp)
{
    uint8_t *exp_cap;
    PCIDevice *pci_dev = PCI_DEVICE(dev);

    pcie_cap_slot_hotplug_common(PCI_DEVICE(hotplug_dev), dev, &exp_cap, errp);

    
    if (!dev->hotplugged) {
        pci_word_test_and_set_mask(exp_cap + PCI_EXP_SLTSTA, PCI_EXP_SLTSTA_PDS);
        return;
    }

    
    assert(PCI_FUNC(pci_dev->devfn) == 0);

    pci_word_test_and_set_mask(exp_cap + PCI_EXP_SLTSTA, PCI_EXP_SLTSTA_PDS);
    pcie_cap_slot_event(PCI_DEVICE(hotplug_dev), PCI_EXP_HP_EV_PDC);
}

void pcie_cap_slot_hot_unplug_cb(HotplugHandler *hotplug_dev, DeviceState *dev, Error **errp)
{
    uint8_t *exp_cap;

    pcie_cap_slot_hotplug_common(PCI_DEVICE(hotplug_dev), dev, &exp_cap, errp);

    object_unparent(OBJECT(dev));
    pci_word_test_and_clear_mask(exp_cap + PCI_EXP_SLTSTA, PCI_EXP_SLTSTA_PDS);
    pcie_cap_slot_event(PCI_DEVICE(hotplug_dev), PCI_EXP_HP_EV_PDC);
}


void pcie_cap_slot_init(PCIDevice *dev, uint16_t slot)
{
    uint32_t pos = dev->exp.exp_cap;

    pci_word_test_and_set_mask(dev->config + pos + PCI_EXP_FLAGS, PCI_EXP_FLAGS_SLOT);

    pci_long_test_and_clear_mask(dev->config + pos + PCI_EXP_SLTCAP, ~PCI_EXP_SLTCAP_PSN);
    pci_long_test_and_set_mask(dev->config + pos + PCI_EXP_SLTCAP, (slot << PCI_EXP_SLTCAP_PSN_SHIFT) | PCI_EXP_SLTCAP_EIP | PCI_EXP_SLTCAP_HPS | PCI_EXP_SLTCAP_HPC | PCI_EXP_SLTCAP_PIP | PCI_EXP_SLTCAP_AIP | PCI_EXP_SLTCAP_ABP);







    if (dev->cap_present & QEMU_PCIE_SLTCAP_PCP) {
        pci_long_test_and_set_mask(dev->config + pos + PCI_EXP_SLTCAP, PCI_EXP_SLTCAP_PCP);
        pci_word_test_and_clear_mask(dev->config + pos + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_PCC);
        pci_word_test_and_set_mask(dev->wmask + pos + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_PCC);
    }

    pci_word_test_and_clear_mask(dev->config + pos + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_PIC | PCI_EXP_SLTCTL_AIC);

    pci_word_test_and_set_mask(dev->config + pos + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_PIC_OFF | PCI_EXP_SLTCTL_AIC_OFF);

    pci_word_test_and_set_mask(dev->wmask + pos + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_PIC | PCI_EXP_SLTCTL_AIC | PCI_EXP_SLTCTL_HPIE | PCI_EXP_SLTCTL_CCIE | PCI_EXP_SLTCTL_PDCE | PCI_EXP_SLTCTL_ABPE);





    
    pci_word_test_and_set_mask(dev->wmask + pos + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_EIC);

    pci_word_test_and_set_mask(dev->w1cmask + pos + PCI_EXP_SLTSTA, PCI_EXP_HP_EV_SUPPORTED);

    dev->exp.hpev_notified = false;

    qbus_set_hotplug_handler(BUS(pci_bridge_get_sec_bus(PCI_BRIDGE(dev))), DEVICE(dev), NULL);
}

void pcie_cap_slot_reset(PCIDevice *dev)
{
    uint8_t *exp_cap = dev->config + dev->exp.exp_cap;
    uint8_t port_type = pcie_cap_get_type(dev);

    assert(port_type == PCI_EXP_TYPE_DOWNSTREAM || port_type == PCI_EXP_TYPE_ROOT_PORT);

    PCIE_DEV_PRINTF(dev, "reset\n");

    pci_word_test_and_clear_mask(exp_cap + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_EIC | PCI_EXP_SLTCTL_PIC | PCI_EXP_SLTCTL_AIC | PCI_EXP_SLTCTL_HPIE | PCI_EXP_SLTCTL_CCIE | PCI_EXP_SLTCTL_PDCE | PCI_EXP_SLTCTL_ABPE);






    pci_word_test_and_set_mask(exp_cap + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_AIC_OFF);

    if (dev->cap_present & QEMU_PCIE_SLTCAP_PCP) {
        bool populated;
        uint16_t pic;

        
        populated = (pci_bridge_get_sec_bus(PCI_BRIDGE(dev))->devices[0] != NULL);

        if (populated) {
            pci_word_test_and_clear_mask(exp_cap + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_PCC);
        } else {
            pci_word_test_and_set_mask(exp_cap + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_PCC);
        }

        pic = populated ? PCI_EXP_SLTCTL_PIC_ON : PCI_EXP_SLTCTL_PIC_OFF;
        pci_word_test_and_set_mask(exp_cap + PCI_EXP_SLTCTL, pic);
     }

    pci_word_test_and_clear_mask(exp_cap + PCI_EXP_SLTSTA, PCI_EXP_SLTSTA_EIS | PCI_EXP_SLTSTA_CC | PCI_EXP_SLTSTA_PDC | PCI_EXP_SLTSTA_ABP);




    hotplug_event_update_event_status(dev);
}

void pcie_cap_slot_write_config(PCIDevice *dev, uint32_t addr, uint32_t val, int len)
{
    uint32_t pos = dev->exp.exp_cap;
    uint8_t *exp_cap = dev->config + pos;
    uint16_t sltsta = pci_get_word(exp_cap + PCI_EXP_SLTSTA);

    if (ranges_overlap(addr, len, pos + PCI_EXP_SLTSTA, 2)) {
        hotplug_event_clear(dev);
    }

    if (!ranges_overlap(addr, len, pos + PCI_EXP_SLTCTL, 2)) {
        return;
    }

    if (pci_word_test_and_clear_mask(exp_cap + PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_EIC)) {
        sltsta ^= PCI_EXP_SLTSTA_EIS; 
        pci_set_word(exp_cap + PCI_EXP_SLTSTA, sltsta);
        PCIE_DEV_PRINTF(dev, "PCI_EXP_SLTCTL_EIC: " "sltsta -> 0x%02"PRIx16"\n", sltsta);

    }

    hotplug_event_notify(dev);

    

    
    pcie_cap_slot_event(dev, PCI_EXP_HP_EV_CCI);
}

int pcie_cap_slot_post_load(void *opaque, int version_id)
{
    PCIDevice *dev = opaque;
    hotplug_event_update_event_status(dev);
    return 0;
}

void pcie_cap_slot_push_attention_button(PCIDevice *dev)
{
    pcie_cap_slot_event(dev, PCI_EXP_HP_EV_ABP);
}


void pcie_cap_root_init(PCIDevice *dev)
{
    pci_set_word(dev->wmask + dev->exp.exp_cap + PCI_EXP_RTCTL, PCI_EXP_RTCTL_SECEE | PCI_EXP_RTCTL_SENFEE | PCI_EXP_RTCTL_SEFEE);

}

void pcie_cap_root_reset(PCIDevice *dev)
{
    pci_set_word(dev->config + dev->exp.exp_cap + PCI_EXP_RTCTL, 0);
}


void pcie_cap_flr_init(PCIDevice *dev)
{
    pci_long_test_and_set_mask(dev->config + dev->exp.exp_cap + PCI_EXP_DEVCAP, PCI_EXP_DEVCAP_FLR);

    
    pci_word_test_and_set_mask(dev->wmask + dev->exp.exp_cap + PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_BCR_FLR);
}

void pcie_cap_flr_write_config(PCIDevice *dev, uint32_t addr, uint32_t val, int len)
{
    uint8_t *devctl = dev->config + dev->exp.exp_cap + PCI_EXP_DEVCTL;
    if (pci_get_word(devctl) & PCI_EXP_DEVCTL_BCR_FLR) {
        
        pci_device_reset(dev);
        pci_word_test_and_clear_mask(devctl, PCI_EXP_DEVCTL_BCR_FLR);
    }
}



void pcie_cap_ari_init(PCIDevice *dev)
{
    uint32_t pos = dev->exp.exp_cap;
    pci_long_test_and_set_mask(dev->config + pos + PCI_EXP_DEVCAP2, PCI_EXP_DEVCAP2_ARI);
    pci_long_test_and_set_mask(dev->wmask + pos + PCI_EXP_DEVCTL2, PCI_EXP_DEVCTL2_ARI);
}

void pcie_cap_ari_reset(PCIDevice *dev)
{
    uint8_t *devctl2 = dev->config + dev->exp.exp_cap + PCI_EXP_DEVCTL2;
    pci_long_test_and_clear_mask(devctl2, PCI_EXP_DEVCTL2_ARI);
}

bool pcie_cap_is_ari_enabled(const PCIDevice *dev)
{
    if (!pci_is_express(dev)) {
        return false;
    }
    if (!dev->exp.exp_cap) {
        return false;
    }

    return pci_get_long(dev->config + dev->exp.exp_cap + PCI_EXP_DEVCTL2) & PCI_EXP_DEVCTL2_ARI;
}



static uint16_t pcie_find_capability_list(PCIDevice *dev, uint16_t cap_id, uint16_t *prev_p)
{
    uint16_t prev = 0;
    uint16_t next;
    uint32_t header = pci_get_long(dev->config + PCI_CONFIG_SPACE_SIZE);

    if (!header) {
        
        next = 0;
        goto out;
    }
    for (next = PCI_CONFIG_SPACE_SIZE; next;
         prev = next, next = PCI_EXT_CAP_NEXT(header)) {

        assert(next >= PCI_CONFIG_SPACE_SIZE);
        assert(next <= PCIE_CONFIG_SPACE_SIZE - 8);

        header = pci_get_long(dev->config + next);
        if (PCI_EXT_CAP_ID(header) == cap_id) {
            break;
        }
    }

out:
    if (prev_p) {
        *prev_p = prev;
    }
    return next;
}

uint16_t pcie_find_capability(PCIDevice *dev, uint16_t cap_id)
{
    return pcie_find_capability_list(dev, cap_id, NULL);
}

static void pcie_ext_cap_set_next(PCIDevice *dev, uint16_t pos, uint16_t next)
{
    uint32_t header = pci_get_long(dev->config + pos);
    assert(!(next & (PCI_EXT_CAP_ALIGN - 1)));
    header = (header & ~PCI_EXT_CAP_NEXT_MASK) | ((next << PCI_EXT_CAP_NEXT_SHIFT) & PCI_EXT_CAP_NEXT_MASK);
    pci_set_long(dev->config + pos, header);
}


void pcie_add_capability(PCIDevice *dev, uint16_t cap_id, uint8_t cap_ver, uint16_t offset, uint16_t size)

{
    uint32_t header;
    uint16_t next;

    assert(offset >= PCI_CONFIG_SPACE_SIZE);
    assert(offset < offset + size);
    assert(offset + size < PCIE_CONFIG_SPACE_SIZE);
    assert(size >= 8);
    assert(pci_is_express(dev));

    if (offset == PCI_CONFIG_SPACE_SIZE) {
        header = pci_get_long(dev->config + offset);
        next = PCI_EXT_CAP_NEXT(header);
    } else {
        uint16_t prev;

        
        next = pcie_find_capability_list(dev, 0, &prev);

        assert(prev >= PCI_CONFIG_SPACE_SIZE);
        assert(next == 0);
        pcie_ext_cap_set_next(dev, prev, offset);
    }
    pci_set_long(dev->config + offset, PCI_EXT_CAP(cap_id, cap_ver, next));

    
    memset(dev->wmask + offset, 0, size);
    memset(dev->w1cmask + offset, 0, size);
    
    memset(dev->cmask + offset, 0xFF, size);
}




void pcie_ari_init(PCIDevice *dev, uint16_t offset, uint16_t nextfn)
{
    pcie_add_capability(dev, PCI_EXT_CAP_ID_ARI, PCI_ARI_VER, offset, PCI_ARI_SIZEOF);
    pci_set_long(dev->config + offset + PCI_ARI_CAP, PCI_ARI_CAP_NFN(nextfn));
}
