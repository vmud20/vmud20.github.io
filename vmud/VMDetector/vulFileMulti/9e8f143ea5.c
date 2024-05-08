




































typedef struct {
    SysBusDevice parent_obj;

    uint32_t ris;
    uint32_t im;
    uint32_t rctl;
    uint32_t tctl;
    uint32_t thr;
    uint32_t mctl;
    uint32_t mdv;
    uint32_t mtxd;
    uint32_t mrxd;
    uint32_t np;
    int tx_fifo_len;
    uint8_t tx_fifo[2048];
    
    struct {
        uint8_t data[2048];
        int len;
    } rx[31];
    int rx_fifo_offset;
    int next_packet;
    NICState *nic;
    NICConf conf;
    qemu_irq irq;
    MemoryRegion mmio;
} stellaris_enet_state;

static void stellaris_enet_update(stellaris_enet_state *s)
{
    qemu_set_irq(s->irq, (s->ris & s->im) != 0);
}


static inline int stellaris_txpacket_datalen(stellaris_enet_state *s)
{
    return s->tx_fifo[0] | (s->tx_fifo[1] << 8);
}


static inline bool stellaris_txpacket_complete(stellaris_enet_state *s)
{
    int framelen = stellaris_txpacket_datalen(s);
    framelen += 16;
    if (!(s->tctl & SE_TCTL_CRC)) {
        framelen += 4;
    }
    
    framelen = MIN(framelen, ARRAY_SIZE(s->tx_fifo));
    return s->tx_fifo_len >= framelen;
}


static inline bool stellaris_tx_thr_reached(stellaris_enet_state *s)
{
    return (s->thr < 0x3f && (s->tx_fifo_len >= 4 * (s->thr * 8 + 1)));
}


static void stellaris_enet_send(stellaris_enet_state *s)
{
    int framelen = stellaris_txpacket_datalen(s);

    
    framelen += 14;
    if ((s->tctl & SE_TCTL_PADEN) && framelen < 60) {
        memset(&s->tx_fifo[framelen + 2], 0, 60 - framelen);
        framelen = 60;
    }
    
    framelen = MIN(framelen, ARRAY_SIZE(s->tx_fifo) - 2);
    qemu_send_packet(qemu_get_queue(s->nic), s->tx_fifo + 2, framelen);
    s->tx_fifo_len = 0;
    s->ris |= SE_INT_TXEMP;
    stellaris_enet_update(s);
    DPRINTF("Done TX\n");
}


static ssize_t stellaris_enet_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    stellaris_enet_state *s = qemu_get_nic_opaque(nc);
    int n;
    uint8_t *p;
    uint32_t crc;

    if ((s->rctl & SE_RCTL_RXEN) == 0)
        return -1;
    if (s->np >= 31) {
        DPRINTF("Packet dropped\n");
        return -1;
    }

    DPRINTF("Received packet len=%zu\n", size);
    n = s->next_packet + s->np;
    if (n >= 31)
        n -= 31;
    s->np++;

    s->rx[n].len = size + 6;
    p = s->rx[n].data;
    *(p++) = (size + 6);
    *(p++) = (size + 6) >> 8;
    memcpy (p, buf, size);
    p += size;
    crc = crc32(~0, buf, size);
    *(p++) = crc;
    *(p++) = crc >> 8;
    *(p++) = crc >> 16;
    *(p++) = crc >> 24;
    
    if ((size & 3) != 2) {
        memset(p, 0, (6 - size) & 3);
    }

    s->ris |= SE_INT_RX;
    stellaris_enet_update(s);

    return size;
}

static int stellaris_enet_can_receive(NetClientState *nc)
{
    stellaris_enet_state *s = qemu_get_nic_opaque(nc);

    if ((s->rctl & SE_RCTL_RXEN) == 0)
        return 1;

    return (s->np < 31);
}

static uint64_t stellaris_enet_read(void *opaque, hwaddr offset, unsigned size)
{
    stellaris_enet_state *s = (stellaris_enet_state *)opaque;
    uint32_t val;

    switch (offset) {
    case 0x00: 
        DPRINTF("IRQ status %02x\n", s->ris);
        return s->ris;
    case 0x04: 
        return s->im;
    case 0x08: 
        return s->rctl;
    case 0x0c: 
        return s->tctl;
    case 0x10: 
    {
        uint8_t *rx_fifo;

        if (s->np == 0) {
            BADF("RX underflow\n");
            return 0;
        }

        rx_fifo = s->rx[s->next_packet].data + s->rx_fifo_offset;

        val = rx_fifo[0] | (rx_fifo[1] << 8) | (rx_fifo[2] << 16)
              | (rx_fifo[3] << 24);
        s->rx_fifo_offset += 4;
        if (s->rx_fifo_offset >= s->rx[s->next_packet].len) {
            s->rx_fifo_offset = 0;
            s->next_packet++;
            if (s->next_packet >= 31)
                s->next_packet = 0;
            s->np--;
            DPRINTF("RX done np=%d\n", s->np);
        }
        return val;
    }
    case 0x14: 
        return s->conf.macaddr.a[0] | (s->conf.macaddr.a[1] << 8)
            | (s->conf.macaddr.a[2] << 16)
            | ((uint32_t)s->conf.macaddr.a[3] << 24);
    case 0x18: 
        return s->conf.macaddr.a[4] | (s->conf.macaddr.a[5] << 8);
    case 0x1c: 
        return s->thr;
    case 0x20: 
        return s->mctl;
    case 0x24: 
        return s->mdv;
    case 0x28: 
        return 0;
    case 0x2c: 
        return s->mtxd;
    case 0x30: 
        return s->mrxd;
    case 0x34: 
        return s->np;
    case 0x38: 
        return 0;
    case 0x3c: 
        return 0;
    default:
        hw_error("stellaris_enet_read: Bad offset %x\n", (int)offset);
        return 0;
    }
}

static void stellaris_enet_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
    stellaris_enet_state *s = (stellaris_enet_state *)opaque;

    switch (offset) {
    case 0x00: 
        s->ris &= ~value;
        DPRINTF("IRQ ack %02" PRIx64 "/%02x\n", value, s->ris);
        stellaris_enet_update(s);
        
        if (value & SE_INT_TXER) {
            s->tx_fifo_len = 0;
        }
        break;
    case 0x04: 
        DPRINTF("IRQ mask %02" PRIx64 "/%02x\n", value, s->ris);
        s->im = value;
        stellaris_enet_update(s);
        break;
    case 0x08: 
        s->rctl = value;
        if (value & SE_RCTL_RSTFIFO) {
            s->np = 0;
            s->rx_fifo_offset = 0;
            stellaris_enet_update(s);
        }
        break;
    case 0x0c: 
        s->tctl = value;
        break;
    case 0x10: 
        if (s->tx_fifo_len == 0) {
            
            int framelen = value & 0xffff;
            if (framelen > 2032) {
                DPRINTF("TX frame too long (%d)\n", framelen);
                s->ris |= SE_INT_TXER;
                stellaris_enet_update(s);
                break;
            }
        }

        if (s->tx_fifo_len + 4 <= ARRAY_SIZE(s->tx_fifo)) {
            s->tx_fifo[s->tx_fifo_len++] = value;
            s->tx_fifo[s->tx_fifo_len++] = value >> 8;
            s->tx_fifo[s->tx_fifo_len++] = value >> 16;
            s->tx_fifo[s->tx_fifo_len++] = value >> 24;
        }

        if (stellaris_tx_thr_reached(s) && stellaris_txpacket_complete(s)) {
            stellaris_enet_send(s);
        }
        break;
    case 0x14: 
        s->conf.macaddr.a[0] = value;
        s->conf.macaddr.a[1] = value >> 8;
        s->conf.macaddr.a[2] = value >> 16;
        s->conf.macaddr.a[3] = value >> 24;
        break;
    case 0x18: 
        s->conf.macaddr.a[4] = value;
        s->conf.macaddr.a[5] = value >> 8;
        break;
    case 0x1c: 
        s->thr = value;
        break;
    case 0x20: 
        s->mctl = value;
        break;
    case 0x24: 
        s->mdv = value;
        break;
    case 0x28: 
        
        break;
    case 0x2c: 
        s->mtxd = value & 0xff;
        break;
    case 0x38: 
        if (value & 1) {
            stellaris_enet_send(s);
        }
        break;
    case 0x30: 
    case 0x34: 
        
    case 0x3c: 
        
        break;
    default:
        hw_error("stellaris_enet_write: Bad offset %x\n", (int)offset);
    }
}

static const MemoryRegionOps stellaris_enet_ops = {
    .read = stellaris_enet_read, .write = stellaris_enet_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static void stellaris_enet_reset(stellaris_enet_state *s)
{
    s->mdv = 0x80;
    s->rctl = SE_RCTL_BADCRC;
    s->im = SE_INT_PHY | SE_INT_MD | SE_INT_RXER | SE_INT_FOV | SE_INT_TXEMP | SE_INT_TXER | SE_INT_RX;
    s->thr = 0x3f;
    s->tx_fifo_len = 0;
}

static void stellaris_enet_save(QEMUFile *f, void *opaque)
{
    stellaris_enet_state *s = (stellaris_enet_state *)opaque;
    int i;

    qemu_put_be32(f, s->ris);
    qemu_put_be32(f, s->im);
    qemu_put_be32(f, s->rctl);
    qemu_put_be32(f, s->tctl);
    qemu_put_be32(f, s->thr);
    qemu_put_be32(f, s->mctl);
    qemu_put_be32(f, s->mdv);
    qemu_put_be32(f, s->mtxd);
    qemu_put_be32(f, s->mrxd);
    qemu_put_be32(f, s->np);
    qemu_put_be32(f, s->tx_fifo_len);
    qemu_put_buffer(f, s->tx_fifo, sizeof(s->tx_fifo));
    for (i = 0; i < 31; i++) {
        qemu_put_be32(f, s->rx[i].len);
        qemu_put_buffer(f, s->rx[i].data, sizeof(s->rx[i].data));

    }
    qemu_put_be32(f, s->next_packet);
    qemu_put_be32(f, s->rx_fifo_offset);
}

static int stellaris_enet_load(QEMUFile *f, void *opaque, int version_id)
{
    stellaris_enet_state *s = (stellaris_enet_state *)opaque;
    int i;

    if (version_id != 1)
        return -EINVAL;

    s->ris = qemu_get_be32(f);
    s->im = qemu_get_be32(f);
    s->rctl = qemu_get_be32(f);
    s->tctl = qemu_get_be32(f);
    s->thr = qemu_get_be32(f);
    s->mctl = qemu_get_be32(f);
    s->mdv = qemu_get_be32(f);
    s->mtxd = qemu_get_be32(f);
    s->mrxd = qemu_get_be32(f);
    s->np = qemu_get_be32(f);
    s->tx_fifo_len = qemu_get_be32(f);
    qemu_get_buffer(f, s->tx_fifo, sizeof(s->tx_fifo));
    for (i = 0; i < 31; i++) {
        s->rx[i].len = qemu_get_be32(f);
        qemu_get_buffer(f, s->rx[i].data, sizeof(s->rx[i].data));

    }
    s->next_packet = qemu_get_be32(f);
    s->rx_fifo_offset = qemu_get_be32(f);

    return 0;
}

static void stellaris_enet_cleanup(NetClientState *nc)
{
    stellaris_enet_state *s = qemu_get_nic_opaque(nc);

    s->nic = NULL;
}

static NetClientInfo net_stellaris_enet_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC, .size = sizeof(NICState), .can_receive = stellaris_enet_can_receive, .receive = stellaris_enet_receive, .cleanup = stellaris_enet_cleanup, };





static int stellaris_enet_init(SysBusDevice *sbd)
{
    DeviceState *dev = DEVICE(sbd);
    stellaris_enet_state *s = STELLARIS_ENET(dev);

    memory_region_init_io(&s->mmio, OBJECT(s), &stellaris_enet_ops, s, "stellaris_enet", 0x1000);
    sysbus_init_mmio(sbd, &s->mmio);
    sysbus_init_irq(sbd, &s->irq);
    qemu_macaddr_default_if_unset(&s->conf.macaddr);

    s->nic = qemu_new_nic(&net_stellaris_enet_info, &s->conf, object_get_typename(OBJECT(dev)), dev->id, s);
    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);

    stellaris_enet_reset(s);
    register_savevm(dev, "stellaris_enet", -1, 1, stellaris_enet_save, stellaris_enet_load, s);
    return 0;
}

static void stellaris_enet_unrealize(DeviceState *dev, Error **errp)
{
    stellaris_enet_state *s = STELLARIS_ENET(dev);

    unregister_savevm(DEVICE(s), "stellaris_enet", s);

    memory_region_destroy(&s->mmio);
}

static Property stellaris_enet_properties[] = {
    DEFINE_NIC_PROPERTIES(stellaris_enet_state, conf), DEFINE_PROP_END_OF_LIST(), };


static void stellaris_enet_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = stellaris_enet_init;
    dc->unrealize = stellaris_enet_unrealize;
    dc->props = stellaris_enet_properties;
}

static const TypeInfo stellaris_enet_info = {
    .name          = TYPE_STELLARIS_ENET, .parent        = TYPE_SYS_BUS_DEVICE, .instance_size = sizeof(stellaris_enet_state), .class_init    = stellaris_enet_class_init, };




static void stellaris_enet_register_types(void)
{
    type_register_static(&stellaris_enet_info);
}

type_init(stellaris_enet_register_types)