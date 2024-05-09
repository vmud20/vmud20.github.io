










static struct {
    hwaddr io_base;
    int irqn;
} pxa255_serial[] = {
    { 0x40100000, PXA2XX_PIC_FFUART }, { 0x40200000, PXA2XX_PIC_BTUART }, { 0x40700000, PXA2XX_PIC_STUART }, { 0x41600000, PXA25X_PIC_HWUART }, { 0, 0 }



}, pxa270_serial[] = {
    { 0x40100000, PXA2XX_PIC_FFUART }, { 0x40200000, PXA2XX_PIC_BTUART }, { 0x40700000, PXA2XX_PIC_STUART }, { 0, 0 }


};

typedef struct PXASSPDef {
    hwaddr io_base;
    int irqn;
} PXASSPDef;


static PXASSPDef pxa250_ssp[] = {
    { 0x41000000, PXA2XX_PIC_SSP }, { 0, 0 }
};


static PXASSPDef pxa255_ssp[] = {
    { 0x41000000, PXA2XX_PIC_SSP }, { 0x41400000, PXA25X_PIC_NSSP }, { 0, 0 }

};


static PXASSPDef pxa26x_ssp[] = {
    { 0x41000000, PXA2XX_PIC_SSP }, { 0x41400000, PXA25X_PIC_NSSP }, { 0x41500000, PXA26X_PIC_ASSP }, { 0, 0 }


};


static PXASSPDef pxa27x_ssp[] = {
    { 0x41000000, PXA2XX_PIC_SSP }, { 0x41700000, PXA27X_PIC_SSP2 }, { 0x41900000, PXA2XX_PIC_SSP3 }, { 0, 0 }


};























static uint64_t pxa2xx_pm_read(void *opaque, hwaddr addr, unsigned size)
{
    PXA2xxState *s = (PXA2xxState *) opaque;

    switch (addr) {
    case PMCR ... PCMD31:
        if (addr & 3)
            goto fail;

        return s->pm_regs[addr >> 2];
    default:
    fail:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
    return 0;
}

static void pxa2xx_pm_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    PXA2xxState *s = (PXA2xxState *) opaque;

    switch (addr) {
    case PMCR:
        
        s->pm_regs[addr >> 2] &= ~(value & 0x2a);
        
        s->pm_regs[addr >> 2] &= ~0x15;
        s->pm_regs[addr >> 2] |= value & 0x15;
        break;

    case PSSR:	
    case RCSR:
    case PKSR:
        s->pm_regs[addr >> 2] &= ~value;
        break;

    default:	
        if (!(addr & 3)) {
            s->pm_regs[addr >> 2] = value;
            break;
        }

        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
}

static const MemoryRegionOps pxa2xx_pm_ops = {
    .read = pxa2xx_pm_read, .write = pxa2xx_pm_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static const VMStateDescription vmstate_pxa2xx_pm = {
    .name = "pxa2xx_pm", .version_id = 0, .minimum_version_id = 0, .minimum_version_id_old = 0, .fields      = (VMStateField[]) {



        VMSTATE_UINT32_ARRAY(pm_regs, PXA2xxState, 0x40), VMSTATE_END_OF_LIST()
    }
};






static uint64_t pxa2xx_cm_read(void *opaque, hwaddr addr, unsigned size)
{
    PXA2xxState *s = (PXA2xxState *) opaque;

    switch (addr) {
    case CCCR:
    case CKEN:
    case OSCC:
        return s->cm_regs[addr >> 2];

    case CCSR:
        return s->cm_regs[CCCR >> 2] | (3 << 28);

    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
    return 0;
}

static void pxa2xx_cm_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    PXA2xxState *s = (PXA2xxState *) opaque;

    switch (addr) {
    case CCCR:
    case CKEN:
        s->cm_regs[addr >> 2] = value;
        break;

    case OSCC:
        s->cm_regs[addr >> 2] &= ~0x6c;
        s->cm_regs[addr >> 2] |= value & 0x6e;
        if ((value >> 1) & 1)			
            s->cm_regs[addr >> 2] |= 1 << 0;	
        break;

    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
}

static const MemoryRegionOps pxa2xx_cm_ops = {
    .read = pxa2xx_cm_read, .write = pxa2xx_cm_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static const VMStateDescription vmstate_pxa2xx_cm = {
    .name = "pxa2xx_cm", .version_id = 0, .minimum_version_id = 0, .minimum_version_id_old = 0, .fields      = (VMStateField[]) {



        VMSTATE_UINT32_ARRAY(cm_regs, PXA2xxState, 4), VMSTATE_UINT32(clkcfg, PXA2xxState), VMSTATE_UINT32(pmnc, PXA2xxState), VMSTATE_END_OF_LIST()


    }
};

static uint64_t pxa2xx_clkcfg_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    PXA2xxState *s = (PXA2xxState *)ri->opaque;
    return s->clkcfg;
}

static void pxa2xx_clkcfg_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    PXA2xxState *s = (PXA2xxState *)ri->opaque;
    s->clkcfg = value & 0xf;
    if (value & 2) {
        printf("%s: CPU frequency change attempt\n", __func__);
    }
}

static void pxa2xx_pwrmode_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    PXA2xxState *s = (PXA2xxState *)ri->opaque;
    static const char *pwrmode[8] = {
        "Normal", "Idle", "Deep-idle", "Standby", "Sleep", "reserved (!)", "reserved (!)", "Deep-sleep", };


    if (value & 8) {
        printf("%s: CPU voltage change attempt\n", __func__);
    }
    switch (value & 7) {
    case 0:
        
        break;

    case 1:
        
        if (!(s->cm_regs[CCCR >> 2] & (1U << 31))) { 
            cpu_interrupt(CPU(s->cpu), CPU_INTERRUPT_HALT);
            break;
        }
        

    case 2:
        
        cpu_interrupt(CPU(s->cpu), CPU_INTERRUPT_HALT);
        s->pm_regs[RCSR >> 2] |= 0x8; 
        goto message;

    case 3:
        s->cpu->env.uncached_cpsr = ARM_CPU_MODE_SVC;
        s->cpu->env.daif = PSTATE_A | PSTATE_F | PSTATE_I;
        s->cpu->env.cp15.c1_sys = 0;
        s->cpu->env.cp15.c1_coproc = 0;
        s->cpu->env.cp15.ttbr0_el1 = 0;
        s->cpu->env.cp15.c3 = 0;
        s->pm_regs[PSSR >> 2] |= 0x8; 
        s->pm_regs[RCSR >> 2] |= 0x8; 

        
        memset(s->cpu->env.regs, 0, 4 * 15);
        s->cpu->env.regs[15] = s->pm_regs[PSPR >> 2];


        buffer = 0xe59ff000; 
        cpu_physical_memory_write(0, &buffer, 4);
        buffer = s->pm_regs[PSPR >> 2];
        cpu_physical_memory_write(8, &buffer, 4);


        
        cpu_interrupt(current_cpu, CPU_INTERRUPT_HALT);

        goto message;

    default:
    message:
        printf("%s: machine entered %s mode\n", __func__, pwrmode[value & 7]);
    }
}

static uint64_t pxa2xx_cppmnc_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    PXA2xxState *s = (PXA2xxState *)ri->opaque;
    return s->pmnc;
}

static void pxa2xx_cppmnc_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    PXA2xxState *s = (PXA2xxState *)ri->opaque;
    s->pmnc = value;
}

static uint64_t pxa2xx_cpccnt_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    PXA2xxState *s = (PXA2xxState *)ri->opaque;
    if (s->pmnc & 1) {
        return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    } else {
        return 0;
    }
}

static const ARMCPRegInfo pxa_cp_reginfo[] = {
    
    { .name = "CPPMNC", .cp = 14, .crn = 0, .crm = 1, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .readfn = pxa2xx_cppmnc_read, .writefn = pxa2xx_cppmnc_write }, { .name = "CPCCNT", .cp = 14, .crn = 1, .crm = 1, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .readfn = pxa2xx_cpccnt_read, .writefn = arm_cp_write_ignore }, { .name = "CPINTEN", .cp = 14, .crn = 4, .crm = 1, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 }, { .name = "CPFLAG", .cp = 14, .crn = 5, .crm = 1, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 }, { .name = "CPEVTSEL", .cp = 14, .crn = 8, .crm = 1, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 },  { .name = "CPPMN0", .cp = 14, .crn = 0, .crm = 2, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 }, { .name = "CPPMN1", .cp = 14, .crn = 1, .crm = 2, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 }, { .name = "CPPMN2", .cp = 14, .crn = 2, .crm = 2, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 }, { .name = "CPPMN3", .cp = 14, .crn = 2, .crm = 3, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 },  { .name = "CLKCFG", .cp = 14, .crn = 6, .crm = 0, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .readfn = pxa2xx_clkcfg_read, .writefn = pxa2xx_clkcfg_write },  { .name = "PWRMODE", .cp = 14, .crn = 7, .crm = 0, .opc1 = 0, .opc2 = 0, .access = PL1_RW, .readfn = arm_cp_read_zero, .writefn = pxa2xx_pwrmode_write }, REGINFO_SENTINEL };






























static void pxa2xx_setup_cp14(PXA2xxState *s)
{
    define_arm_cp_regs_with_opaque(s->cpu, pxa_cp_reginfo, s);
}

























static uint64_t pxa2xx_mm_read(void *opaque, hwaddr addr, unsigned size)
{
    PXA2xxState *s = (PXA2xxState *) opaque;

    switch (addr) {
    case MDCNFG ... SA1110:
        if ((addr & 3) == 0)
            return s->mm_regs[addr >> 2];

    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
    return 0;
}

static void pxa2xx_mm_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    PXA2xxState *s = (PXA2xxState *) opaque;

    switch (addr) {
    case MDCNFG ... SA1110:
        if ((addr & 3) == 0) {
            s->mm_regs[addr >> 2] = value;
            break;
        }

    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
}

static const MemoryRegionOps pxa2xx_mm_ops = {
    .read = pxa2xx_mm_read, .write = pxa2xx_mm_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static const VMStateDescription vmstate_pxa2xx_mm = {
    .name = "pxa2xx_mm", .version_id = 0, .minimum_version_id = 0, .minimum_version_id_old = 0, .fields      = (VMStateField[]) {



        VMSTATE_UINT32_ARRAY(mm_regs, PXA2xxState, 0x1a), VMSTATE_END_OF_LIST()
    }
};





typedef struct {
    
    SysBusDevice parent_obj;
    

    MemoryRegion iomem;
    qemu_irq irq;
    int enable;
    SSIBus *bus;

    uint32_t sscr[2];
    uint32_t sspsp;
    uint32_t ssto;
    uint32_t ssitr;
    uint32_t sssr;
    uint8_t sstsa;
    uint8_t ssrsa;
    uint8_t ssacd;

    uint32_t rx_fifo[16];
    int rx_level;
    int rx_start;
} PXA2xxSSPState;
















































static void pxa2xx_ssp_int_update(PXA2xxSSPState *s)
{
    int level = 0;

    level |= s->ssitr & SSITR_INT;
    level |= (s->sssr & SSSR_BCE)  &&  (s->sscr[1] & SSCR1_EBCEI);
    level |= (s->sssr & SSSR_TUR)  && !(s->sscr[0] & SSCR0_TIM);
    level |= (s->sssr & SSSR_EOC)  &&  (s->sssr & (SSSR_TINT | SSSR_PINT));
    level |= (s->sssr & SSSR_TINT) &&  (s->sscr[1] & SSCR1_TINTE);
    level |= (s->sssr & SSSR_PINT) &&  (s->sscr[1] & SSCR1_PINTE);
    level |= (s->sssr & SSSR_ROR)  && !(s->sscr[0] & SSCR0_RIM);
    level |= (s->sssr & SSSR_RFS)  &&  (s->sscr[1] & SSCR1_RIE);
    level |= (s->sssr & SSSR_TFS)  &&  (s->sscr[1] & SSCR1_TIE);
    qemu_set_irq(s->irq, !!level);
}

static void pxa2xx_ssp_fifo_update(PXA2xxSSPState *s)
{
    s->sssr &= ~(0xf << 12);	
    s->sssr &= ~(0xf << 8);	
    s->sssr &= ~SSSR_TFS;
    s->sssr &= ~SSSR_TNF;
    if (s->enable) {
        s->sssr |= ((s->rx_level - 1) & 0xf) << 12;
        if (s->rx_level >= SSCR1_RFT(s->sscr[1]))
            s->sssr |= SSSR_RFS;
        else s->sssr &= ~SSSR_RFS;
        if (s->rx_level)
            s->sssr |= SSSR_RNE;
        else s->sssr &= ~SSSR_RNE;
        
        s->sssr |= SSSR_TFS;
        s->sssr |= SSSR_TNF;
    }

    pxa2xx_ssp_int_update(s);
}

static uint64_t pxa2xx_ssp_read(void *opaque, hwaddr addr, unsigned size)
{
    PXA2xxSSPState *s = (PXA2xxSSPState *) opaque;
    uint32_t retval;

    switch (addr) {
    case SSCR0:
        return s->sscr[0];
    case SSCR1:
        return s->sscr[1];
    case SSPSP:
        return s->sspsp;
    case SSTO:
        return s->ssto;
    case SSITR:
        return s->ssitr;
    case SSSR:
        return s->sssr | s->ssitr;
    case SSDR:
        if (!s->enable)
            return 0xffffffff;
        if (s->rx_level < 1) {
            printf("%s: SSP Rx Underrun\n", __FUNCTION__);
            return 0xffffffff;
        }
        s->rx_level --;
        retval = s->rx_fifo[s->rx_start ++];
        s->rx_start &= 0xf;
        pxa2xx_ssp_fifo_update(s);
        return retval;
    case SSTSA:
        return s->sstsa;
    case SSRSA:
        return s->ssrsa;
    case SSTSS:
        return 0;
    case SSACD:
        return s->ssacd;
    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
    return 0;
}

static void pxa2xx_ssp_write(void *opaque, hwaddr addr, uint64_t value64, unsigned size)
{
    PXA2xxSSPState *s = (PXA2xxSSPState *) opaque;
    uint32_t value = value64;

    switch (addr) {
    case SSCR0:
        s->sscr[0] = value & 0xc7ffffff;
        s->enable = value & SSCR0_SSE;
        if (value & SSCR0_MOD)
            printf("%s: Attempt to use network mode\n", __FUNCTION__);
        if (s->enable && SSCR0_DSS(value) < 4)
            printf("%s: Wrong data size: %i bits\n", __FUNCTION__, SSCR0_DSS(value));
        if (!(value & SSCR0_SSE)) {
            s->sssr = 0;
            s->ssitr = 0;
            s->rx_level = 0;
        }
        pxa2xx_ssp_fifo_update(s);
        break;

    case SSCR1:
        s->sscr[1] = value;
        if (value & (SSCR1_LBM | SSCR1_EFWR))
            printf("%s: Attempt to use SSP test mode\n", __FUNCTION__);
        pxa2xx_ssp_fifo_update(s);
        break;

    case SSPSP:
        s->sspsp = value;
        break;

    case SSTO:
        s->ssto = value;
        break;

    case SSITR:
        s->ssitr = value & SSITR_INT;
        pxa2xx_ssp_int_update(s);
        break;

    case SSSR:
        s->sssr &= ~(value & SSSR_RW);
        pxa2xx_ssp_int_update(s);
        break;

    case SSDR:
        if (SSCR0_UWIRE(s->sscr[0])) {
            if (s->sscr[1] & SSCR1_MWDS)
                value &= 0xffff;
            else value &= 0xff;
        } else  value &= (1 << SSCR0_DSS(s->sscr[0])) - 1;


        
        if (s->enable) {
            uint32_t readval;
            readval = ssi_transfer(s->bus, value);
            if (s->rx_level < 0x10) {
                s->rx_fifo[(s->rx_start + s->rx_level ++) & 0xf] = readval;
            } else {
                s->sssr |= SSSR_ROR;
            }
        }
        pxa2xx_ssp_fifo_update(s);
        break;

    case SSTSA:
        s->sstsa = value;
        break;

    case SSRSA:
        s->ssrsa = value;
        break;

    case SSACD:
        s->ssacd = value;
        break;

    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
}

static const MemoryRegionOps pxa2xx_ssp_ops = {
    .read = pxa2xx_ssp_read, .write = pxa2xx_ssp_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static void pxa2xx_ssp_save(QEMUFile *f, void *opaque)
{
    PXA2xxSSPState *s = (PXA2xxSSPState *) opaque;
    int i;

    qemu_put_be32(f, s->enable);

    qemu_put_be32s(f, &s->sscr[0]);
    qemu_put_be32s(f, &s->sscr[1]);
    qemu_put_be32s(f, &s->sspsp);
    qemu_put_be32s(f, &s->ssto);
    qemu_put_be32s(f, &s->ssitr);
    qemu_put_be32s(f, &s->sssr);
    qemu_put_8s(f, &s->sstsa);
    qemu_put_8s(f, &s->ssrsa);
    qemu_put_8s(f, &s->ssacd);

    qemu_put_byte(f, s->rx_level);
    for (i = 0; i < s->rx_level; i ++)
        qemu_put_byte(f, s->rx_fifo[(s->rx_start + i) & 0xf]);
}

static int pxa2xx_ssp_load(QEMUFile *f, void *opaque, int version_id)
{
    PXA2xxSSPState *s = (PXA2xxSSPState *) opaque;
    int i;

    s->enable = qemu_get_be32(f);

    qemu_get_be32s(f, &s->sscr[0]);
    qemu_get_be32s(f, &s->sscr[1]);
    qemu_get_be32s(f, &s->sspsp);
    qemu_get_be32s(f, &s->ssto);
    qemu_get_be32s(f, &s->ssitr);
    qemu_get_be32s(f, &s->sssr);
    qemu_get_8s(f, &s->sstsa);
    qemu_get_8s(f, &s->ssrsa);
    qemu_get_8s(f, &s->ssacd);

    s->rx_level = qemu_get_byte(f);
    s->rx_start = 0;
    for (i = 0; i < s->rx_level; i ++)
        s->rx_fifo[i] = qemu_get_byte(f);

    return 0;
}

static int pxa2xx_ssp_init(SysBusDevice *sbd)
{
    DeviceState *dev = DEVICE(sbd);
    PXA2xxSSPState *s = PXA2XX_SSP(dev);

    sysbus_init_irq(sbd, &s->irq);

    memory_region_init_io(&s->iomem, OBJECT(s), &pxa2xx_ssp_ops, s, "pxa2xx-ssp", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    register_savevm(dev, "pxa2xx_ssp", -1, 0, pxa2xx_ssp_save, pxa2xx_ssp_load, s);

    s->bus = ssi_create_bus(dev, "ssi");
    return 0;
}





















typedef struct {
    
    SysBusDevice parent_obj;
    

    MemoryRegion iomem;
    uint32_t rttr;
    uint32_t rtsr;
    uint32_t rtar;
    uint32_t rdar1;
    uint32_t rdar2;
    uint32_t ryar1;
    uint32_t ryar2;
    uint32_t swar1;
    uint32_t swar2;
    uint32_t piar;
    uint32_t last_rcnr;
    uint32_t last_rdcr;
    uint32_t last_rycr;
    uint32_t last_swcr;
    uint32_t last_rtcpicr;
    int64_t last_hz;
    int64_t last_sw;
    int64_t last_pi;
    QEMUTimer *rtc_hz;
    QEMUTimer *rtc_rdal1;
    QEMUTimer *rtc_rdal2;
    QEMUTimer *rtc_swal1;
    QEMUTimer *rtc_swal2;
    QEMUTimer *rtc_pi;
    qemu_irq rtc_irq;
} PXA2xxRTCState;

static inline void pxa2xx_rtc_int_update(PXA2xxRTCState *s)
{
    qemu_set_irq(s->rtc_irq, !!(s->rtsr & 0x2553));
}

static void pxa2xx_rtc_hzupdate(PXA2xxRTCState *s)
{
    int64_t rt = qemu_clock_get_ms(rtc_clock);
    s->last_rcnr += ((rt - s->last_hz) << 15) / (1000 * ((s->rttr & 0xffff) + 1));
    s->last_rdcr += ((rt - s->last_hz) << 15) / (1000 * ((s->rttr & 0xffff) + 1));
    s->last_hz = rt;
}

static void pxa2xx_rtc_swupdate(PXA2xxRTCState *s)
{
    int64_t rt = qemu_clock_get_ms(rtc_clock);
    if (s->rtsr & (1 << 12))
        s->last_swcr += (rt - s->last_sw) / 10;
    s->last_sw = rt;
}

static void pxa2xx_rtc_piupdate(PXA2xxRTCState *s)
{
    int64_t rt = qemu_clock_get_ms(rtc_clock);
    if (s->rtsr & (1 << 15))
        s->last_swcr += rt - s->last_pi;
    s->last_pi = rt;
}

static inline void pxa2xx_rtc_alarm_update(PXA2xxRTCState *s, uint32_t rtsr)
{
    if ((rtsr & (1 << 2)) && !(rtsr & (1 << 0)))
        timer_mod(s->rtc_hz, s->last_hz + (((s->rtar - s->last_rcnr) * 1000 * ((s->rttr & 0xffff) + 1)) >> 15));

    else timer_del(s->rtc_hz);

    if ((rtsr & (1 << 5)) && !(rtsr & (1 << 4)))
        timer_mod(s->rtc_rdal1, s->last_hz + (((s->rdar1 - s->last_rdcr) * 1000 * ((s->rttr & 0xffff) + 1)) >> 15));

    else timer_del(s->rtc_rdal1);

    if ((rtsr & (1 << 7)) && !(rtsr & (1 << 6)))
        timer_mod(s->rtc_rdal2, s->last_hz + (((s->rdar2 - s->last_rdcr) * 1000 * ((s->rttr & 0xffff) + 1)) >> 15));

    else timer_del(s->rtc_rdal2);

    if ((rtsr & 0x1200) == 0x1200 && !(rtsr & (1 << 8)))
        timer_mod(s->rtc_swal1, s->last_sw + (s->swar1 - s->last_swcr) * 10);
    else timer_del(s->rtc_swal1);

    if ((rtsr & 0x1800) == 0x1800 && !(rtsr & (1 << 10)))
        timer_mod(s->rtc_swal2, s->last_sw + (s->swar2 - s->last_swcr) * 10);
    else timer_del(s->rtc_swal2);

    if ((rtsr & 0xc000) == 0xc000 && !(rtsr & (1 << 13)))
        timer_mod(s->rtc_pi, s->last_pi + (s->piar & 0xffff) - s->last_rtcpicr);
    else timer_del(s->rtc_pi);
}

static inline void pxa2xx_rtc_hz_tick(void *opaque)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;
    s->rtsr |= (1 << 0);
    pxa2xx_rtc_alarm_update(s, s->rtsr);
    pxa2xx_rtc_int_update(s);
}

static inline void pxa2xx_rtc_rdal1_tick(void *opaque)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;
    s->rtsr |= (1 << 4);
    pxa2xx_rtc_alarm_update(s, s->rtsr);
    pxa2xx_rtc_int_update(s);
}

static inline void pxa2xx_rtc_rdal2_tick(void *opaque)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;
    s->rtsr |= (1 << 6);
    pxa2xx_rtc_alarm_update(s, s->rtsr);
    pxa2xx_rtc_int_update(s);
}

static inline void pxa2xx_rtc_swal1_tick(void *opaque)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;
    s->rtsr |= (1 << 8);
    pxa2xx_rtc_alarm_update(s, s->rtsr);
    pxa2xx_rtc_int_update(s);
}

static inline void pxa2xx_rtc_swal2_tick(void *opaque)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;
    s->rtsr |= (1 << 10);
    pxa2xx_rtc_alarm_update(s, s->rtsr);
    pxa2xx_rtc_int_update(s);
}

static inline void pxa2xx_rtc_pi_tick(void *opaque)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;
    s->rtsr |= (1 << 13);
    pxa2xx_rtc_piupdate(s);
    s->last_rtcpicr = 0;
    pxa2xx_rtc_alarm_update(s, s->rtsr);
    pxa2xx_rtc_int_update(s);
}

static uint64_t pxa2xx_rtc_read(void *opaque, hwaddr addr, unsigned size)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;

    switch (addr) {
    case RTTR:
        return s->rttr;
    case RTSR:
        return s->rtsr;
    case RTAR:
        return s->rtar;
    case RDAR1:
        return s->rdar1;
    case RDAR2:
        return s->rdar2;
    case RYAR1:
        return s->ryar1;
    case RYAR2:
        return s->ryar2;
    case SWAR1:
        return s->swar1;
    case SWAR2:
        return s->swar2;
    case PIAR:
        return s->piar;
    case RCNR:
        return s->last_rcnr + ((qemu_clock_get_ms(rtc_clock) - s->last_hz) << 15) / (1000 * ((s->rttr & 0xffff) + 1));

    case RDCR:
        return s->last_rdcr + ((qemu_clock_get_ms(rtc_clock) - s->last_hz) << 15) / (1000 * ((s->rttr & 0xffff) + 1));

    case RYCR:
        return s->last_rycr;
    case SWCR:
        if (s->rtsr & (1 << 12))
            return s->last_swcr + (qemu_clock_get_ms(rtc_clock) - s->last_sw) / 10;
        else return s->last_swcr;
    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
    return 0;
}

static void pxa2xx_rtc_write(void *opaque, hwaddr addr, uint64_t value64, unsigned size)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;
    uint32_t value = value64;

    switch (addr) {
    case RTTR:
        if (!(s->rttr & (1U << 31))) {
            pxa2xx_rtc_hzupdate(s);
            s->rttr = value;
            pxa2xx_rtc_alarm_update(s, s->rtsr);
        }
        break;

    case RTSR:
        if ((s->rtsr ^ value) & (1 << 15))
            pxa2xx_rtc_piupdate(s);

        if ((s->rtsr ^ value) & (1 << 12))
            pxa2xx_rtc_swupdate(s);

        if (((s->rtsr ^ value) & 0x4aac) | (value & ~0xdaac))
            pxa2xx_rtc_alarm_update(s, value);

        s->rtsr = (value & 0xdaac) | (s->rtsr & ~(value & ~0xdaac));
        pxa2xx_rtc_int_update(s);
        break;

    case RTAR:
        s->rtar = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case RDAR1:
        s->rdar1 = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case RDAR2:
        s->rdar2 = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case RYAR1:
        s->ryar1 = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case RYAR2:
        s->ryar2 = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case SWAR1:
        pxa2xx_rtc_swupdate(s);
        s->swar1 = value;
        s->last_swcr = 0;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case SWAR2:
        s->swar2 = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case PIAR:
        s->piar = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case RCNR:
        pxa2xx_rtc_hzupdate(s);
        s->last_rcnr = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case RDCR:
        pxa2xx_rtc_hzupdate(s);
        s->last_rdcr = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case RYCR:
        s->last_rycr = value;
        break;

    case SWCR:
        pxa2xx_rtc_swupdate(s);
        s->last_swcr = value;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    case RTCPICR:
        pxa2xx_rtc_piupdate(s);
        s->last_rtcpicr = value & 0xffff;
        pxa2xx_rtc_alarm_update(s, s->rtsr);
        break;

    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
    }
}

static const MemoryRegionOps pxa2xx_rtc_ops = {
    .read = pxa2xx_rtc_read, .write = pxa2xx_rtc_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static int pxa2xx_rtc_init(SysBusDevice *dev)
{
    PXA2xxRTCState *s = PXA2XX_RTC(dev);
    struct tm tm;
    int wom;

    s->rttr = 0x7fff;
    s->rtsr = 0;

    qemu_get_timedate(&tm, 0);
    wom = ((tm.tm_mday - 1) / 7) + 1;

    s->last_rcnr = (uint32_t) mktimegm(&tm);
    s->last_rdcr = (wom << 20) | ((tm.tm_wday + 1) << 17) | (tm.tm_hour << 12) | (tm.tm_min << 6) | tm.tm_sec;
    s->last_rycr = ((tm.tm_year + 1900) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday;
    s->last_swcr = (tm.tm_hour << 19) | (tm.tm_min << 13) | (tm.tm_sec << 7);
    s->last_rtcpicr = 0;
    s->last_hz = s->last_sw = s->last_pi = qemu_clock_get_ms(rtc_clock);

    s->rtc_hz    = timer_new_ms(rtc_clock, pxa2xx_rtc_hz_tick,    s);
    s->rtc_rdal1 = timer_new_ms(rtc_clock, pxa2xx_rtc_rdal1_tick, s);
    s->rtc_rdal2 = timer_new_ms(rtc_clock, pxa2xx_rtc_rdal2_tick, s);
    s->rtc_swal1 = timer_new_ms(rtc_clock, pxa2xx_rtc_swal1_tick, s);
    s->rtc_swal2 = timer_new_ms(rtc_clock, pxa2xx_rtc_swal2_tick, s);
    s->rtc_pi    = timer_new_ms(rtc_clock, pxa2xx_rtc_pi_tick,    s);

    sysbus_init_irq(dev, &s->rtc_irq);

    memory_region_init_io(&s->iomem, OBJECT(s), &pxa2xx_rtc_ops, s, "pxa2xx-rtc", 0x10000);
    sysbus_init_mmio(dev, &s->iomem);

    return 0;
}

static void pxa2xx_rtc_pre_save(void *opaque)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;

    pxa2xx_rtc_hzupdate(s);
    pxa2xx_rtc_piupdate(s);
    pxa2xx_rtc_swupdate(s);
}

static int pxa2xx_rtc_post_load(void *opaque, int version_id)
{
    PXA2xxRTCState *s = (PXA2xxRTCState *) opaque;

    pxa2xx_rtc_alarm_update(s, s->rtsr);

    return 0;
}

static const VMStateDescription vmstate_pxa2xx_rtc_regs = {
    .name = "pxa2xx_rtc", .version_id = 0, .minimum_version_id = 0, .minimum_version_id_old = 0, .pre_save = pxa2xx_rtc_pre_save, .post_load = pxa2xx_rtc_post_load, .fields = (VMStateField[]) {





        VMSTATE_UINT32(rttr, PXA2xxRTCState), VMSTATE_UINT32(rtsr, PXA2xxRTCState), VMSTATE_UINT32(rtar, PXA2xxRTCState), VMSTATE_UINT32(rdar1, PXA2xxRTCState), VMSTATE_UINT32(rdar2, PXA2xxRTCState), VMSTATE_UINT32(ryar1, PXA2xxRTCState), VMSTATE_UINT32(ryar2, PXA2xxRTCState), VMSTATE_UINT32(swar1, PXA2xxRTCState), VMSTATE_UINT32(swar2, PXA2xxRTCState), VMSTATE_UINT32(piar, PXA2xxRTCState), VMSTATE_UINT32(last_rcnr, PXA2xxRTCState), VMSTATE_UINT32(last_rdcr, PXA2xxRTCState), VMSTATE_UINT32(last_rycr, PXA2xxRTCState), VMSTATE_UINT32(last_swcr, PXA2xxRTCState), VMSTATE_UINT32(last_rtcpicr, PXA2xxRTCState), VMSTATE_INT64(last_hz, PXA2xxRTCState), VMSTATE_INT64(last_sw, PXA2xxRTCState), VMSTATE_INT64(last_pi, PXA2xxRTCState), VMSTATE_END_OF_LIST(), }, };




















static void pxa2xx_rtc_sysbus_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = pxa2xx_rtc_init;
    dc->desc = "PXA2xx RTC Controller";
    dc->vmsd = &vmstate_pxa2xx_rtc_regs;
}

static const TypeInfo pxa2xx_rtc_sysbus_info = {
    .name          = TYPE_PXA2XX_RTC, .parent        = TYPE_SYS_BUS_DEVICE, .instance_size = sizeof(PXA2xxRTCState), .class_init    = pxa2xx_rtc_sysbus_class_init, };









typedef struct PXA2xxI2CSlaveState {
    I2CSlave parent_obj;

    PXA2xxI2CState *host;
} PXA2xxI2CSlaveState;




struct PXA2xxI2CState {
    
    SysBusDevice parent_obj;
    

    MemoryRegion iomem;
    PXA2xxI2CSlaveState *slave;
    I2CBus *bus;
    qemu_irq irq;
    uint32_t offset;
    uint32_t region_size;

    uint16_t control;
    uint16_t status;
    uint8_t ibmr;
    uint8_t data;
};







static void pxa2xx_i2c_update(PXA2xxI2CState *s)
{
    uint16_t level = 0;
    level |= s->status & s->control & (1 << 10);		
    level |= (s->status & (1 << 7)) && (s->control & (1 << 9));	
    level |= (s->status & (1 << 6)) && (s->control & (1 << 8));	
    level |= s->status & (1 << 9);				
    qemu_set_irq(s->irq, !!level);
}


static void pxa2xx_i2c_event(I2CSlave *i2c, enum i2c_event event)
{
    PXA2xxI2CSlaveState *slave = PXA2XX_I2C_SLAVE(i2c);
    PXA2xxI2CState *s = slave->host;

    switch (event) {
    case I2C_START_SEND:
        s->status |= (1 << 9);				
        s->status &= ~(1 << 0);				
        break;
    case I2C_START_RECV:
        s->status |= (1 << 9);				
        s->status |= 1 << 0;				
        break;
    case I2C_FINISH:
        s->status |= (1 << 4);				
        break;
    case I2C_NACK:
        s->status |= 1 << 1;				
        break;
    }
    pxa2xx_i2c_update(s);
}

static int pxa2xx_i2c_rx(I2CSlave *i2c)
{
    PXA2xxI2CSlaveState *slave = PXA2XX_I2C_SLAVE(i2c);
    PXA2xxI2CState *s = slave->host;

    if ((s->control & (1 << 14)) || !(s->control & (1 << 6))) {
        return 0;
    }

    if (s->status & (1 << 0)) {			
        s->status |= 1 << 6;			
    }
    pxa2xx_i2c_update(s);

    return s->data;
}

static int pxa2xx_i2c_tx(I2CSlave *i2c, uint8_t data)
{
    PXA2xxI2CSlaveState *slave = PXA2XX_I2C_SLAVE(i2c);
    PXA2xxI2CState *s = slave->host;

    if ((s->control & (1 << 14)) || !(s->control & (1 << 6))) {
        return 1;
    }

    if (!(s->status & (1 << 0))) {		
        s->status |= 1 << 7;			
        s->data = data;
    }
    pxa2xx_i2c_update(s);

    return 1;
}

static uint64_t pxa2xx_i2c_read(void *opaque, hwaddr addr, unsigned size)
{
    PXA2xxI2CState *s = (PXA2xxI2CState *) opaque;
    I2CSlave *slave;

    addr -= s->offset;
    switch (addr) {
    case ICR:
        return s->control;
    case ISR:
        return s->status | (i2c_bus_busy(s->bus) << 2);
    case ISAR:
        slave = I2C_SLAVE(s->slave);
        return slave->address;
    case IDBR:
        return s->data;
    case IBMR:
        if (s->status & (1 << 2))
            s->ibmr ^= 3;	
        else s->ibmr = 0;
        return s->ibmr;
    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
    return 0;
}

static void pxa2xx_i2c_write(void *opaque, hwaddr addr, uint64_t value64, unsigned size)
{
    PXA2xxI2CState *s = (PXA2xxI2CState *) opaque;
    uint32_t value = value64;
    int ack;

    addr -= s->offset;
    switch (addr) {
    case ICR:
        s->control = value & 0xfff7;
        if ((value & (1 << 3)) && (value & (1 << 6))) {	
            
            if (value & (1 << 0)) {			
                if (s->data & 1)
                    s->status |= 1 << 0;		
                else s->status &= ~(1 << 0);
                ack = !i2c_start_transfer(s->bus, s->data >> 1, s->data & 1);
            } else {
                if (s->status & (1 << 0)) {		
                    s->data = i2c_recv(s->bus);
                    if (value & (1 << 2))		
                        i2c_nack(s->bus);
                    ack = 1;
                } else ack = !i2c_send(s->bus, s->data);
            }

            if (value & (1 << 1))			
                i2c_end_transfer(s->bus);

            if (ack) {
                if (value & (1 << 0))			
                    s->status |= 1 << 6;		
                else if (s->status & (1 << 0))
                        s->status |= 1 << 7;		
                    else s->status |= 1 << 6;
                s->status &= ~(1 << 1);			
            } else {
                s->status |= 1 << 6;			
                s->status |= 1 << 10;			
                s->status |= 1 << 1;			
            }
        }
        if (!(value & (1 << 3)) && (value & (1 << 6)))	
            if (value & (1 << 4))			
                i2c_end_transfer(s->bus);
        pxa2xx_i2c_update(s);
        break;

    case ISR:
        s->status &= ~(value & 0x07f0);
        pxa2xx_i2c_update(s);
        break;

    case ISAR:
        i2c_set_slave_address(I2C_SLAVE(s->slave), value & 0x7f);
        break;

    case IDBR:
        s->data = value & 0xff;
        break;

    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
    }
}

static const MemoryRegionOps pxa2xx_i2c_ops = {
    .read = pxa2xx_i2c_read, .write = pxa2xx_i2c_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static const VMStateDescription vmstate_pxa2xx_i2c_slave = {
    .name = "pxa2xx_i2c_slave", .version_id = 1, .minimum_version_id = 1, .minimum_version_id_old = 1, .fields      = (VMStateField []) {



        VMSTATE_I2C_SLAVE(parent_obj, PXA2xxI2CSlaveState), VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_pxa2xx_i2c = {
    .name = "pxa2xx_i2c", .version_id = 1, .minimum_version_id = 1, .minimum_version_id_old = 1, .fields      = (VMStateField []) {



        VMSTATE_UINT16(control, PXA2xxI2CState), VMSTATE_UINT16(status, PXA2xxI2CState), VMSTATE_UINT8(ibmr, PXA2xxI2CState), VMSTATE_UINT8(data, PXA2xxI2CState), VMSTATE_STRUCT_POINTER(slave, PXA2xxI2CState, vmstate_pxa2xx_i2c_slave, PXA2xxI2CSlaveState), VMSTATE_END_OF_LIST()





    }
};

static int pxa2xx_i2c_slave_init(I2CSlave *i2c)
{
    
    return 0;
}

static void pxa2xx_i2c_slave_class_init(ObjectClass *klass, void *data)
{
    I2CSlaveClass *k = I2C_SLAVE_CLASS(klass);

    k->init = pxa2xx_i2c_slave_init;
    k->event = pxa2xx_i2c_event;
    k->recv = pxa2xx_i2c_rx;
    k->send = pxa2xx_i2c_tx;
}

static const TypeInfo pxa2xx_i2c_slave_info = {
    .name          = TYPE_PXA2XX_I2C_SLAVE, .parent        = TYPE_I2C_SLAVE, .instance_size = sizeof(PXA2xxI2CSlaveState), .class_init    = pxa2xx_i2c_slave_class_init, };




PXA2xxI2CState *pxa2xx_i2c_init(hwaddr base, qemu_irq irq, uint32_t region_size)
{
    DeviceState *dev;
    SysBusDevice *i2c_dev;
    PXA2xxI2CState *s;
    I2CBus *i2cbus;

    dev = qdev_create(NULL, TYPE_PXA2XX_I2C);
    qdev_prop_set_uint32(dev, "size", region_size + 1);
    qdev_prop_set_uint32(dev, "offset", base & region_size);
    qdev_init_nofail(dev);

    i2c_dev = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(i2c_dev, 0, base & ~region_size);
    sysbus_connect_irq(i2c_dev, 0, irq);

    s = PXA2XX_I2C(i2c_dev);
    
    i2cbus = i2c_init_bus(dev, "dummy");
    dev = i2c_create_slave(i2cbus, TYPE_PXA2XX_I2C_SLAVE, 0);
    s->slave = PXA2XX_I2C_SLAVE(dev);
    s->slave->host = s;

    return s;
}

static int pxa2xx_i2c_initfn(SysBusDevice *sbd)
{
    DeviceState *dev = DEVICE(sbd);
    PXA2xxI2CState *s = PXA2XX_I2C(dev);

    s->bus = i2c_init_bus(dev, "i2c");

    memory_region_init_io(&s->iomem, OBJECT(s), &pxa2xx_i2c_ops, s, "pxa2xx-i2c", s->region_size);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    return 0;
}

I2CBus *pxa2xx_i2c_bus(PXA2xxI2CState *s)
{
    return s->bus;
}

static Property pxa2xx_i2c_properties[] = {
    DEFINE_PROP_UINT32("size", PXA2xxI2CState, region_size, 0x10000), DEFINE_PROP_UINT32("offset", PXA2xxI2CState, offset, 0), DEFINE_PROP_END_OF_LIST(), };



static void pxa2xx_i2c_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = pxa2xx_i2c_initfn;
    dc->desc = "PXA2xx I2C Bus Controller";
    dc->vmsd = &vmstate_pxa2xx_i2c;
    dc->props = pxa2xx_i2c_properties;
}

static const TypeInfo pxa2xx_i2c_info = {
    .name          = TYPE_PXA2XX_I2C, .parent        = TYPE_SYS_BUS_DEVICE, .instance_size = sizeof(PXA2xxI2CState), .class_init    = pxa2xx_i2c_class_init, };





static void pxa2xx_i2s_reset(PXA2xxI2SState *i2s)
{
    i2s->rx_len = 0;
    i2s->tx_len = 0;
    i2s->fifo_len = 0;
    i2s->clk = 0x1a;
    i2s->control[0] = 0x00;
    i2s->control[1] = 0x00;
    i2s->status = 0x00;
    i2s->mask = 0x00;
}






static inline void pxa2xx_i2s_update(PXA2xxI2SState *i2s)
{
    int rfs, tfs;
    rfs = SACR_RFTH(i2s->control[0]) < i2s->rx_len && !SACR_DREC(i2s->control[1]);
    tfs = (i2s->tx_len || i2s->fifo_len < SACR_TFTH(i2s->control[0])) && i2s->enable && !SACR_DPRL(i2s->control[1]);

    qemu_set_irq(i2s->rx_dma, rfs);
    qemu_set_irq(i2s->tx_dma, tfs);

    i2s->status &= 0xe0;
    if (i2s->fifo_len < 16 || !i2s->enable)
        i2s->status |= 1 << 0;			
    if (i2s->rx_len)
        i2s->status |= 1 << 1;			
    if (i2s->enable)
        i2s->status |= 1 << 2;			
    if (tfs)
        i2s->status |= 1 << 3;			
    if (rfs)
        i2s->status |= 1 << 4;			
    if (!(i2s->tx_len && i2s->enable))
        i2s->status |= i2s->fifo_len << 8;	
    i2s->status |= MAX(i2s->rx_len, 0xf) << 12;	

    qemu_set_irq(i2s->irq, i2s->status & i2s->mask);
}









static uint64_t pxa2xx_i2s_read(void *opaque, hwaddr addr, unsigned size)
{
    PXA2xxI2SState *s = (PXA2xxI2SState *) opaque;

    switch (addr) {
    case SACR0:
        return s->control[0];
    case SACR1:
        return s->control[1];
    case SASR0:
        return s->status;
    case SAIMR:
        return s->mask;
    case SAICR:
        return 0;
    case SADIV:
        return s->clk;
    case SADR:
        if (s->rx_len > 0) {
            s->rx_len --;
            pxa2xx_i2s_update(s);
            return s->codec_in(s->opaque);
        }
        return 0;
    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
    return 0;
}

static void pxa2xx_i2s_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    PXA2xxI2SState *s = (PXA2xxI2SState *) opaque;
    uint32_t *sample;

    switch (addr) {
    case SACR0:
        if (value & (1 << 3))				
            pxa2xx_i2s_reset(s);
        s->control[0] = value & 0xff3d;
        if (!s->enable && (value & 1) && s->tx_len) {	
            for (sample = s->fifo; s->fifo_len > 0; s->fifo_len --, sample ++)
                s->codec_out(s->opaque, *sample);
            s->status &= ~(1 << 7);			
        }
        if (value & (1 << 4))				
            printf("%s: Attempt to use special function\n", __FUNCTION__);
        s->enable = (value & 9) == 1;			
        pxa2xx_i2s_update(s);
        break;
    case SACR1:
        s->control[1] = value & 0x0039;
        if (value & (1 << 5))				
            printf("%s: Attempt to use loopback function\n", __FUNCTION__);
        if (value & (1 << 4))				
            s->fifo_len = 0;
        pxa2xx_i2s_update(s);
        break;
    case SAIMR:
        s->mask = value & 0x0078;
        pxa2xx_i2s_update(s);
        break;
    case SAICR:
        s->status &= ~(value & (3 << 5));
        pxa2xx_i2s_update(s);
        break;
    case SADIV:
        s->clk = value & 0x007f;
        break;
    case SADR:
        if (s->tx_len && s->enable) {
            s->tx_len --;
            pxa2xx_i2s_update(s);
            s->codec_out(s->opaque, value);
        } else if (s->fifo_len < 16) {
            s->fifo[s->fifo_len ++] = value;
            pxa2xx_i2s_update(s);
        }
        break;
    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
    }
}

static const MemoryRegionOps pxa2xx_i2s_ops = {
    .read = pxa2xx_i2s_read, .write = pxa2xx_i2s_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static const VMStateDescription vmstate_pxa2xx_i2s = {
    .name = "pxa2xx_i2s", .version_id = 0, .minimum_version_id = 0, .minimum_version_id_old = 0, .fields      = (VMStateField[]) {



        VMSTATE_UINT32_ARRAY(control, PXA2xxI2SState, 2), VMSTATE_UINT32(status, PXA2xxI2SState), VMSTATE_UINT32(mask, PXA2xxI2SState), VMSTATE_UINT32(clk, PXA2xxI2SState), VMSTATE_INT32(enable, PXA2xxI2SState), VMSTATE_INT32(rx_len, PXA2xxI2SState), VMSTATE_INT32(tx_len, PXA2xxI2SState), VMSTATE_INT32(fifo_len, PXA2xxI2SState), VMSTATE_END_OF_LIST()







    }
};

static void pxa2xx_i2s_data_req(void *opaque, int tx, int rx)
{
    PXA2xxI2SState *s = (PXA2xxI2SState *) opaque;
    uint32_t *sample;

    
    if (s->enable && s->tx_len)
        s->status |= 1 << 5;		
    if (s->enable && s->rx_len)
        s->status |= 1 << 6;		

    
    s->tx_len = tx - s->fifo_len;
    s->rx_len = rx;
    
    if (s->enable)
        for (sample = s->fifo; s->fifo_len; s->fifo_len --, sample ++)
            s->codec_out(s->opaque, *sample);
    pxa2xx_i2s_update(s);
}

static PXA2xxI2SState *pxa2xx_i2s_init(MemoryRegion *sysmem, hwaddr base, qemu_irq irq, qemu_irq rx_dma, qemu_irq tx_dma)

{
    PXA2xxI2SState *s = (PXA2xxI2SState *)
            g_malloc0(sizeof(PXA2xxI2SState));

    s->irq = irq;
    s->rx_dma = rx_dma;
    s->tx_dma = tx_dma;
    s->data_req = pxa2xx_i2s_data_req;

    pxa2xx_i2s_reset(s);

    memory_region_init_io(&s->iomem, NULL, &pxa2xx_i2s_ops, s, "pxa2xx-i2s", 0x100000);
    memory_region_add_subregion(sysmem, base, &s->iomem);

    vmstate_register(NULL, base, &vmstate_pxa2xx_i2s, s);

    return s;
}


struct PXA2xxFIrState {
    MemoryRegion iomem;
    qemu_irq irq;
    qemu_irq rx_dma;
    qemu_irq tx_dma;
    int enable;
    CharDriverState *chr;

    uint8_t control[3];
    uint8_t status[2];

    int rx_len;
    int rx_start;
    uint8_t rx_fifo[64];
};

static void pxa2xx_fir_reset(PXA2xxFIrState *s)
{
    s->control[0] = 0x00;
    s->control[1] = 0x00;
    s->control[2] = 0x00;
    s->status[0] = 0x00;
    s->status[1] = 0x00;
    s->enable = 0;
}

static inline void pxa2xx_fir_update(PXA2xxFIrState *s)
{
    static const int tresh[4] = { 8, 16, 32, 0 };
    int intr = 0;
    if ((s->control[0] & (1 << 4)) &&			 s->rx_len >= tresh[s->control[2] & 3])
        s->status[0] |= 1 << 4;				
    else s->status[0] &= ~(1 << 4);
    if (s->control[0] & (1 << 3))			
        s->status[0] |= 1 << 3;				
    else s->status[0] &= ~(1 << 3);
    if (s->rx_len)
        s->status[1] |= 1 << 2;				
    else s->status[1] &= ~(1 << 2);
    if (s->control[0] & (1 << 4))			
        s->status[1] |= 1 << 0;				
    else s->status[1] &= ~(1 << 0);

    intr |= (s->control[0] & (1 << 5)) &&		 (s->status[0] & (1 << 4));
    intr |= (s->control[0] & (1 << 6)) &&		 (s->status[0] & (1 << 3));
    intr |= (s->control[2] & (1 << 4)) &&		 (s->status[0] & (1 << 6));
    intr |= (s->control[0] & (1 << 2)) &&		 (s->status[0] & (1 << 1));
    intr |= s->status[0] & 0x25;			

    qemu_set_irq(s->rx_dma, (s->status[0] >> 4) & 1);
    qemu_set_irq(s->tx_dma, (s->status[0] >> 3) & 1);

    qemu_set_irq(s->irq, intr && s->enable);
}









static uint64_t pxa2xx_fir_read(void *opaque, hwaddr addr, unsigned size)
{
    PXA2xxFIrState *s = (PXA2xxFIrState *) opaque;
    uint8_t ret;

    switch (addr) {
    case ICCR0:
        return s->control[0];
    case ICCR1:
        return s->control[1];
    case ICCR2:
        return s->control[2];
    case ICDR:
        s->status[0] &= ~0x01;
        s->status[1] &= ~0x72;
        if (s->rx_len) {
            s->rx_len --;
            ret = s->rx_fifo[s->rx_start ++];
            s->rx_start &= 63;
            pxa2xx_fir_update(s);
            return ret;
        }
        printf("%s: Rx FIFO underrun.\n", __FUNCTION__);
        break;
    case ICSR0:
        return s->status[0];
    case ICSR1:
        return s->status[1] | (1 << 3);			
    case ICFOR:
        return s->rx_len;
    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
        break;
    }
    return 0;
}

static void pxa2xx_fir_write(void *opaque, hwaddr addr, uint64_t value64, unsigned size)
{
    PXA2xxFIrState *s = (PXA2xxFIrState *) opaque;
    uint32_t value = value64;
    uint8_t ch;

    switch (addr) {
    case ICCR0:
        s->control[0] = value;
        if (!(value & (1 << 4)))			
            s->rx_len = s->rx_start = 0;
        if (!(value & (1 << 3))) {                      
            
        }
        s->enable = value & 1;				
        if (!s->enable)
            s->status[0] = 0;
        pxa2xx_fir_update(s);
        break;
    case ICCR1:
        s->control[1] = value;
        break;
    case ICCR2:
        s->control[2] = value & 0x3f;
        pxa2xx_fir_update(s);
        break;
    case ICDR:
        if (s->control[2] & (1 << 2))			
            ch = value;
        else ch = ~value;
        if (s->chr && s->enable && (s->control[0] & (1 << 3)))	
            qemu_chr_fe_write(s->chr, &ch, 1);
        break;
    case ICSR0:
        s->status[0] &= ~(value & 0x66);
        pxa2xx_fir_update(s);
        break;
    case ICFOR:
        break;
    default:
        printf("%s: Bad register " REG_FMT "\n", __FUNCTION__, addr);
    }
}

static const MemoryRegionOps pxa2xx_fir_ops = {
    .read = pxa2xx_fir_read, .write = pxa2xx_fir_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static int pxa2xx_fir_is_empty(void *opaque)
{
    PXA2xxFIrState *s = (PXA2xxFIrState *) opaque;
    return (s->rx_len < 64);
}

static void pxa2xx_fir_rx(void *opaque, const uint8_t *buf, int size)
{
    PXA2xxFIrState *s = (PXA2xxFIrState *) opaque;
    if (!(s->control[0] & (1 << 4)))			
        return;

    while (size --) {
        s->status[1] |= 1 << 4;				
        if (s->rx_len >= 64) {
            s->status[1] |= 1 << 6;			
            break;
        }

        if (s->control[2] & (1 << 3))			
            s->rx_fifo[(s->rx_start + s->rx_len ++) & 63] = *(buf ++);
        else s->rx_fifo[(s->rx_start + s->rx_len ++) & 63] = ~*(buf ++);
    }

    pxa2xx_fir_update(s);
}

static void pxa2xx_fir_event(void *opaque, int event)
{
}

static void pxa2xx_fir_save(QEMUFile *f, void *opaque)
{
    PXA2xxFIrState *s = (PXA2xxFIrState *) opaque;
    int i;

    qemu_put_be32(f, s->enable);

    qemu_put_8s(f, &s->control[0]);
    qemu_put_8s(f, &s->control[1]);
    qemu_put_8s(f, &s->control[2]);
    qemu_put_8s(f, &s->status[0]);
    qemu_put_8s(f, &s->status[1]);

    qemu_put_byte(f, s->rx_len);
    for (i = 0; i < s->rx_len; i ++)
        qemu_put_byte(f, s->rx_fifo[(s->rx_start + i) & 63]);
}

static int pxa2xx_fir_load(QEMUFile *f, void *opaque, int version_id)
{
    PXA2xxFIrState *s = (PXA2xxFIrState *) opaque;
    int i;

    s->enable = qemu_get_be32(f);

    qemu_get_8s(f, &s->control[0]);
    qemu_get_8s(f, &s->control[1]);
    qemu_get_8s(f, &s->control[2]);
    qemu_get_8s(f, &s->status[0]);
    qemu_get_8s(f, &s->status[1]);

    s->rx_len = qemu_get_byte(f);
    s->rx_start = 0;
    for (i = 0; i < s->rx_len; i ++)
        s->rx_fifo[i] = qemu_get_byte(f);

    return 0;
}

static PXA2xxFIrState *pxa2xx_fir_init(MemoryRegion *sysmem, hwaddr base, qemu_irq irq, qemu_irq rx_dma, qemu_irq tx_dma, CharDriverState *chr)


{
    PXA2xxFIrState *s = (PXA2xxFIrState *)
            g_malloc0(sizeof(PXA2xxFIrState));

    s->irq = irq;
    s->rx_dma = rx_dma;
    s->tx_dma = tx_dma;
    s->chr = chr;

    pxa2xx_fir_reset(s);

    memory_region_init_io(&s->iomem, NULL, &pxa2xx_fir_ops, s, "pxa2xx-fir", 0x1000);
    memory_region_add_subregion(sysmem, base, &s->iomem);

    if (chr) {
        qemu_chr_fe_claim_no_fail(chr);
        qemu_chr_add_handlers(chr, pxa2xx_fir_is_empty, pxa2xx_fir_rx, pxa2xx_fir_event, s);
    }

    register_savevm(NULL, "pxa2xx_fir", 0, 0, pxa2xx_fir_save, pxa2xx_fir_load, s);

    return s;
}

static void pxa2xx_reset(void *opaque, int line, int level)
{
    PXA2xxState *s = (PXA2xxState *) opaque;

    if (level && (s->pm_regs[PCFR >> 2] & 0x10)) {	
        cpu_reset(CPU(s->cpu));
        
    }
}


PXA2xxState *pxa270_init(MemoryRegion *address_space, unsigned int sdram_size, const char *revision)
{
    PXA2xxState *s;
    int i;
    DriveInfo *dinfo;
    s = (PXA2xxState *) g_malloc0(sizeof(PXA2xxState));

    if (revision && strncmp(revision, "pxa27", 5)) {
        fprintf(stderr, "Machine requires a PXA27x processor.\n");
        exit(1);
    }
    if (!revision)
        revision = "pxa270";
    
    s->cpu = cpu_arm_init(revision);
    if (s->cpu == NULL) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    s->reset = qemu_allocate_irqs(pxa2xx_reset, s, 1)[0];

    
    memory_region_init_ram(&s->sdram, NULL, "pxa270.sdram", sdram_size);
    vmstate_register_ram_global(&s->sdram);
    memory_region_add_subregion(address_space, PXA2XX_SDRAM_BASE, &s->sdram);
    memory_region_init_ram(&s->internal, NULL, "pxa270.internal", 0x40000);
    vmstate_register_ram_global(&s->internal);
    memory_region_add_subregion(address_space, PXA2XX_INTERNAL_BASE, &s->internal);

    s->pic = pxa2xx_pic_init(0x40d00000, s->cpu);

    s->dma = pxa27x_dma_init(0x40000000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_DMA));

    sysbus_create_varargs("pxa27x-timer", 0x40a00000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_OST_0 + 0), qdev_get_gpio_in(s->pic, PXA2XX_PIC_OST_0 + 1), qdev_get_gpio_in(s->pic, PXA2XX_PIC_OST_0 + 2), qdev_get_gpio_in(s->pic, PXA2XX_PIC_OST_0 + 3), qdev_get_gpio_in(s->pic, PXA27X_PIC_OST_4_11), NULL);






    s->gpio = pxa2xx_gpio_init(0x40e00000, s->cpu, s->pic, 121);

    dinfo = drive_get(IF_SD, 0, 0);
    if (!dinfo) {
        fprintf(stderr, "qemu: missing SecureDigital device\n");
        exit(1);
    }
    s->mmc = pxa2xx_mmci_init(address_space, 0x41100000, dinfo->bdrv, qdev_get_gpio_in(s->pic, PXA2XX_PIC_MMC), qdev_get_gpio_in(s->dma, PXA2XX_RX_RQ_MMCI), qdev_get_gpio_in(s->dma, PXA2XX_TX_RQ_MMCI));



    for (i = 0; pxa270_serial[i].io_base; i++) {
        if (serial_hds[i]) {
            serial_mm_init(address_space, pxa270_serial[i].io_base, 2, qdev_get_gpio_in(s->pic, pxa270_serial[i].irqn), 14857000 / 16, serial_hds[i], DEVICE_NATIVE_ENDIAN);


        } else {
            break;
        }
    }
    if (serial_hds[i])
        s->fir = pxa2xx_fir_init(address_space, 0x40800000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_ICP), qdev_get_gpio_in(s->dma, PXA2XX_RX_RQ_ICP), qdev_get_gpio_in(s->dma, PXA2XX_TX_RQ_ICP), serial_hds[i]);




    s->lcd = pxa2xx_lcdc_init(address_space, 0x44000000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_LCD));

    s->cm_base = 0x41300000;
    s->cm_regs[CCCR >> 2] = 0x02000210;	
    s->clkcfg = 0x00000009;		
    memory_region_init_io(&s->cm_iomem, NULL, &pxa2xx_cm_ops, s, "pxa2xx-cm", 0x1000);
    memory_region_add_subregion(address_space, s->cm_base, &s->cm_iomem);
    vmstate_register(NULL, 0, &vmstate_pxa2xx_cm, s);

    pxa2xx_setup_cp14(s);

    s->mm_base = 0x48000000;
    s->mm_regs[MDMRS >> 2] = 0x00020002;
    s->mm_regs[MDREFR >> 2] = 0x03ca4000;
    s->mm_regs[MECR >> 2] = 0x00000001;	
    memory_region_init_io(&s->mm_iomem, NULL, &pxa2xx_mm_ops, s, "pxa2xx-mm", 0x1000);
    memory_region_add_subregion(address_space, s->mm_base, &s->mm_iomem);
    vmstate_register(NULL, 0, &vmstate_pxa2xx_mm, s);

    s->pm_base = 0x40f00000;
    memory_region_init_io(&s->pm_iomem, NULL, &pxa2xx_pm_ops, s, "pxa2xx-pm", 0x100);
    memory_region_add_subregion(address_space, s->pm_base, &s->pm_iomem);
    vmstate_register(NULL, 0, &vmstate_pxa2xx_pm, s);

    for (i = 0; pxa27x_ssp[i].io_base; i ++);
    s->ssp = (SSIBus **)g_malloc0(sizeof(SSIBus *) * i);
    for (i = 0; pxa27x_ssp[i].io_base; i ++) {
        DeviceState *dev;
        dev = sysbus_create_simple(TYPE_PXA2XX_SSP, pxa27x_ssp[i].io_base, qdev_get_gpio_in(s->pic, pxa27x_ssp[i].irqn));
        s->ssp[i] = (SSIBus *)qdev_get_child_bus(dev, "ssi");
    }

    if (usb_enabled(false)) {
        sysbus_create_simple("sysbus-ohci", 0x4c000000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_USBH1));
    }

    s->pcmcia[0] = pxa2xx_pcmcia_init(address_space, 0x20000000);
    s->pcmcia[1] = pxa2xx_pcmcia_init(address_space, 0x30000000);

    sysbus_create_simple(TYPE_PXA2XX_RTC, 0x40900000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_RTCALARM));

    s->i2c[0] = pxa2xx_i2c_init(0x40301600, qdev_get_gpio_in(s->pic, PXA2XX_PIC_I2C), 0xffff);
    s->i2c[1] = pxa2xx_i2c_init(0x40f00100, qdev_get_gpio_in(s->pic, PXA2XX_PIC_PWRI2C), 0xff);

    s->i2s = pxa2xx_i2s_init(address_space, 0x40400000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_I2S), qdev_get_gpio_in(s->dma, PXA2XX_RX_RQ_I2S), qdev_get_gpio_in(s->dma, PXA2XX_TX_RQ_I2S));



    s->kp = pxa27x_keypad_init(address_space, 0x41500000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_KEYPAD));

    
    
    qdev_connect_gpio_out(s->gpio, 1, s->reset);
    return s;
}


PXA2xxState *pxa255_init(MemoryRegion *address_space, unsigned int sdram_size)
{
    PXA2xxState *s;
    int i;
    DriveInfo *dinfo;

    s = (PXA2xxState *) g_malloc0(sizeof(PXA2xxState));

    s->cpu = cpu_arm_init("pxa255");
    if (s->cpu == NULL) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    s->reset = qemu_allocate_irqs(pxa2xx_reset, s, 1)[0];

    
    memory_region_init_ram(&s->sdram, NULL, "pxa255.sdram", sdram_size);
    vmstate_register_ram_global(&s->sdram);
    memory_region_add_subregion(address_space, PXA2XX_SDRAM_BASE, &s->sdram);
    memory_region_init_ram(&s->internal, NULL, "pxa255.internal", PXA2XX_INTERNAL_SIZE);
    vmstate_register_ram_global(&s->internal);
    memory_region_add_subregion(address_space, PXA2XX_INTERNAL_BASE, &s->internal);

    s->pic = pxa2xx_pic_init(0x40d00000, s->cpu);

    s->dma = pxa255_dma_init(0x40000000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_DMA));

    sysbus_create_varargs("pxa25x-timer", 0x40a00000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_OST_0 + 0), qdev_get_gpio_in(s->pic, PXA2XX_PIC_OST_0 + 1), qdev_get_gpio_in(s->pic, PXA2XX_PIC_OST_0 + 2), qdev_get_gpio_in(s->pic, PXA2XX_PIC_OST_0 + 3), NULL);





    s->gpio = pxa2xx_gpio_init(0x40e00000, s->cpu, s->pic, 85);

    dinfo = drive_get(IF_SD, 0, 0);
    if (!dinfo) {
        fprintf(stderr, "qemu: missing SecureDigital device\n");
        exit(1);
    }
    s->mmc = pxa2xx_mmci_init(address_space, 0x41100000, dinfo->bdrv, qdev_get_gpio_in(s->pic, PXA2XX_PIC_MMC), qdev_get_gpio_in(s->dma, PXA2XX_RX_RQ_MMCI), qdev_get_gpio_in(s->dma, PXA2XX_TX_RQ_MMCI));



    for (i = 0; pxa255_serial[i].io_base; i++) {
        if (serial_hds[i]) {
            serial_mm_init(address_space, pxa255_serial[i].io_base, 2, qdev_get_gpio_in(s->pic, pxa255_serial[i].irqn), 14745600 / 16, serial_hds[i], DEVICE_NATIVE_ENDIAN);


        } else {
            break;
        }
    }
    if (serial_hds[i])
        s->fir = pxa2xx_fir_init(address_space, 0x40800000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_ICP), qdev_get_gpio_in(s->dma, PXA2XX_RX_RQ_ICP), qdev_get_gpio_in(s->dma, PXA2XX_TX_RQ_ICP), serial_hds[i]);




    s->lcd = pxa2xx_lcdc_init(address_space, 0x44000000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_LCD));

    s->cm_base = 0x41300000;
    s->cm_regs[CCCR >> 2] = 0x02000210;	
    s->clkcfg = 0x00000009;		
    memory_region_init_io(&s->cm_iomem, NULL, &pxa2xx_cm_ops, s, "pxa2xx-cm", 0x1000);
    memory_region_add_subregion(address_space, s->cm_base, &s->cm_iomem);
    vmstate_register(NULL, 0, &vmstate_pxa2xx_cm, s);

    pxa2xx_setup_cp14(s);

    s->mm_base = 0x48000000;
    s->mm_regs[MDMRS >> 2] = 0x00020002;
    s->mm_regs[MDREFR >> 2] = 0x03ca4000;
    s->mm_regs[MECR >> 2] = 0x00000001;	
    memory_region_init_io(&s->mm_iomem, NULL, &pxa2xx_mm_ops, s, "pxa2xx-mm", 0x1000);
    memory_region_add_subregion(address_space, s->mm_base, &s->mm_iomem);
    vmstate_register(NULL, 0, &vmstate_pxa2xx_mm, s);

    s->pm_base = 0x40f00000;
    memory_region_init_io(&s->pm_iomem, NULL, &pxa2xx_pm_ops, s, "pxa2xx-pm", 0x100);
    memory_region_add_subregion(address_space, s->pm_base, &s->pm_iomem);
    vmstate_register(NULL, 0, &vmstate_pxa2xx_pm, s);

    for (i = 0; pxa255_ssp[i].io_base; i ++);
    s->ssp = (SSIBus **)g_malloc0(sizeof(SSIBus *) * i);
    for (i = 0; pxa255_ssp[i].io_base; i ++) {
        DeviceState *dev;
        dev = sysbus_create_simple(TYPE_PXA2XX_SSP, pxa255_ssp[i].io_base, qdev_get_gpio_in(s->pic, pxa255_ssp[i].irqn));
        s->ssp[i] = (SSIBus *)qdev_get_child_bus(dev, "ssi");
    }

    if (usb_enabled(false)) {
        sysbus_create_simple("sysbus-ohci", 0x4c000000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_USBH1));
    }

    s->pcmcia[0] = pxa2xx_pcmcia_init(address_space, 0x20000000);
    s->pcmcia[1] = pxa2xx_pcmcia_init(address_space, 0x30000000);

    sysbus_create_simple(TYPE_PXA2XX_RTC, 0x40900000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_RTCALARM));

    s->i2c[0] = pxa2xx_i2c_init(0x40301600, qdev_get_gpio_in(s->pic, PXA2XX_PIC_I2C), 0xffff);
    s->i2c[1] = pxa2xx_i2c_init(0x40f00100, qdev_get_gpio_in(s->pic, PXA2XX_PIC_PWRI2C), 0xff);

    s->i2s = pxa2xx_i2s_init(address_space, 0x40400000, qdev_get_gpio_in(s->pic, PXA2XX_PIC_I2S), qdev_get_gpio_in(s->dma, PXA2XX_RX_RQ_I2S), qdev_get_gpio_in(s->dma, PXA2XX_TX_RQ_I2S));



    
    
    qdev_connect_gpio_out(s->gpio, 1, s->reset);
    return s;
}

static void pxa2xx_ssp_class_init(ObjectClass *klass, void *data)
{
    SysBusDeviceClass *sdc = SYS_BUS_DEVICE_CLASS(klass);

    sdc->init = pxa2xx_ssp_init;
}

static const TypeInfo pxa2xx_ssp_info = {
    .name          = TYPE_PXA2XX_SSP, .parent        = TYPE_SYS_BUS_DEVICE, .instance_size = sizeof(PXA2xxSSPState), .class_init    = pxa2xx_ssp_class_init, };




static void pxa2xx_register_types(void)
{
    type_register_static(&pxa2xx_i2c_slave_info);
    type_register_static(&pxa2xx_ssp_info);
    type_register_static(&pxa2xx_i2c_info);
    type_register_static(&pxa2xx_rtc_sysbus_info);
}

type_init(pxa2xx_register_types)
