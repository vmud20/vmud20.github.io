













static const int debug_openpic = 1;

static const int debug_openpic = 0;












































typedef struct FslMpicInfo {
    int max_ext;
} FslMpicInfo;

static FslMpicInfo fsl_mpic_20 = {
    .max_ext = 12, };

static FslMpicInfo fsl_mpic_42 = {
    .max_ext = 12, };































static const int inttgt_output[][2] = {
    { ILR_INTTGT_INT, OPENPIC_OUTPUT_INT }, { ILR_INTTGT_CINT, OPENPIC_OUTPUT_CINT }, { ILR_INTTGT_MCP, OPENPIC_OUTPUT_MCK }, };



static int inttgt_to_output(int inttgt)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(inttgt_output); i++) {
        if (inttgt_output[i][0] == inttgt) {
            return inttgt_output[i][1];
        }
    }

    fprintf(stderr, "%s: unsupported inttgt %d\n", __func__, inttgt);
    return OPENPIC_OUTPUT_INT;
}

static int output_to_inttgt(int output)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(inttgt_output); i++) {
        if (inttgt_output[i][1] == output) {
            return inttgt_output[i][0];
        }
    }

    abort();
}







static int get_current_cpu(void)
{
    if (!current_cpu) {
        return -1;
    }

    return current_cpu->cpu_index;
}

static uint32_t openpic_cpu_read_internal(void *opaque, hwaddr addr, int idx);
static void openpic_cpu_write_internal(void *opaque, hwaddr addr, uint32_t val, int idx);

typedef enum IRQType {
    IRQ_TYPE_NORMAL = 0, IRQ_TYPE_FSLINT, IRQ_TYPE_FSLSPECIAL, } IRQType;



typedef struct IRQQueue {
    
    unsigned long queue[BITS_TO_LONGS((OPENPIC_MAX_IRQ + 63) & ~63)];
    int next;
    int priority;
} IRQQueue;

typedef struct IRQSource {
    uint32_t ivpr;  
    uint32_t idr;   
    uint32_t destmask; 
    int last_cpu;
    int output;     
    int pending;    
    IRQType type;
    bool level:1;   
    bool nomask:1;  
} IRQSource;




















typedef struct IRQDest {
    int32_t ctpr; 
    IRQQueue raised;
    IRQQueue servicing;
    qemu_irq *irqs;

    
    uint32_t outputs_active[OPENPIC_OUTPUT_NB];
} IRQDest;



typedef struct OpenPICState {
    
    SysBusDevice parent_obj;
    

    MemoryRegion mem;

    
    FslMpicInfo *fsl;
    uint32_t model;
    uint32_t flags;
    uint32_t nb_irqs;
    uint32_t vid;
    uint32_t vir; 
    uint32_t vector_mask;
    uint32_t tfrr_reset;
    uint32_t ivpr_reset;
    uint32_t idr_reset;
    uint32_t brr1;
    uint32_t mpic_mode_mask;

    
    MemoryRegion sub_io_mem[6];

    
    uint32_t frr; 
    uint32_t gcr; 
    uint32_t pir; 
    uint32_t spve; 
    uint32_t tfrr; 
    
    IRQSource src[OPENPIC_MAX_IRQ];
    
    IRQDest dst[MAX_CPU];
    uint32_t nb_cpus;
    
    struct {
        uint32_t tccr;  
        uint32_t tbcr;  
    } timers[OPENPIC_MAX_TMR];
    
    struct {
        uint32_t msir;   
    } msi[MAX_MSI];
    uint32_t max_irq;
    uint32_t irq_ipi0;
    uint32_t irq_tim0;
    uint32_t irq_msi;
} OpenPICState;

static inline void IRQ_setbit(IRQQueue *q, int n_IRQ)
{
    set_bit(n_IRQ, q->queue);
}

static inline void IRQ_resetbit(IRQQueue *q, int n_IRQ)
{
    clear_bit(n_IRQ, q->queue);
}

static inline int IRQ_testbit(IRQQueue *q, int n_IRQ)
{
    return test_bit(n_IRQ, q->queue);
}

static void IRQ_check(OpenPICState *opp, IRQQueue *q)
{
    int irq = -1;
    int next = -1;
    int priority = -1;

    for (;;) {
        irq = find_next_bit(q->queue, opp->max_irq, irq + 1);
        if (irq == opp->max_irq) {
            break;
        }

        DPRINTF("IRQ_check: irq %d set ivpr_pr=%d pr=%d\n", irq, IVPR_PRIORITY(opp->src[irq].ivpr), priority);

        if (IVPR_PRIORITY(opp->src[irq].ivpr) > priority) {
            next = irq;
            priority = IVPR_PRIORITY(opp->src[irq].ivpr);
        }
    }

    q->next = next;
    q->priority = priority;
}

static int IRQ_get_next(OpenPICState *opp, IRQQueue *q)
{
    
    IRQ_check(opp, q);

    return q->next;
}

static void IRQ_local_pipe(OpenPICState *opp, int n_CPU, int n_IRQ, bool active, bool was_active)
{
    IRQDest *dst;
    IRQSource *src;
    int priority;

    dst = &opp->dst[n_CPU];
    src = &opp->src[n_IRQ];

    DPRINTF("%s: IRQ %d active %d was %d\n", __func__, n_IRQ, active, was_active);

    if (src->output != OPENPIC_OUTPUT_INT) {
        DPRINTF("%s: output %d irq %d active %d was %d count %d\n", __func__, src->output, n_IRQ, active, was_active, dst->outputs_active[src->output]);


        
        if (active) {
            if (!was_active && dst->outputs_active[src->output]++ == 0) {
                DPRINTF("%s: Raise OpenPIC output %d cpu %d irq %d\n", __func__, src->output, n_CPU, n_IRQ);
                qemu_irq_raise(dst->irqs[src->output]);
            }
        } else {
            if (was_active && --dst->outputs_active[src->output] == 0) {
                DPRINTF("%s: Lower OpenPIC output %d cpu %d irq %d\n", __func__, src->output, n_CPU, n_IRQ);
                qemu_irq_lower(dst->irqs[src->output]);
            }
        }

        return;
    }

    priority = IVPR_PRIORITY(src->ivpr);

    
    if (active) {
        IRQ_setbit(&dst->raised, n_IRQ);
    } else {
        IRQ_resetbit(&dst->raised, n_IRQ);
    }

    IRQ_check(opp, &dst->raised);

    if (active && priority <= dst->ctpr) {
        DPRINTF("%s: IRQ %d priority %d too low for ctpr %d on CPU %d\n", __func__, n_IRQ, priority, dst->ctpr, n_CPU);
        active = 0;
    }

    if (active) {
        if (IRQ_get_next(opp, &dst->servicing) >= 0 && priority <= dst->servicing.priority) {
            DPRINTF("%s: IRQ %d is hidden by servicing IRQ %d on CPU %d\n", __func__, n_IRQ, dst->servicing.next, n_CPU);
        } else {
            DPRINTF("%s: Raise OpenPIC INT output cpu %d irq %d/%d\n", __func__, n_CPU, n_IRQ, dst->raised.next);
            qemu_irq_raise(opp->dst[n_CPU].irqs[OPENPIC_OUTPUT_INT]);
        }
    } else {
        IRQ_get_next(opp, &dst->servicing);
        if (dst->raised.priority > dst->ctpr && dst->raised.priority > dst->servicing.priority) {
            DPRINTF("%s: IRQ %d inactive, IRQ %d prio %d above %d/%d, CPU %d\n", __func__, n_IRQ, dst->raised.next, dst->raised.priority, dst->ctpr, dst->servicing.priority, n_CPU);

            
        } else {
            DPRINTF("%s: IRQ %d inactive, current prio %d/%d, CPU %d\n", __func__, n_IRQ, dst->ctpr, dst->servicing.priority, n_CPU);
            qemu_irq_lower(opp->dst[n_CPU].irqs[OPENPIC_OUTPUT_INT]);
        }
    }
}


static void openpic_update_irq(OpenPICState *opp, int n_IRQ)
{
    IRQSource *src;
    bool active, was_active;
    int i;

    src = &opp->src[n_IRQ];
    active = src->pending;

    if ((src->ivpr & IVPR_MASK_MASK) && !src->nomask) {
        
        DPRINTF("%s: IRQ %d is disabled\n", __func__, n_IRQ);
        active = false;
    }

    was_active = !!(src->ivpr & IVPR_ACTIVITY_MASK);

    
    if (!active && !was_active) {
        DPRINTF("%s: IRQ %d is already inactive\n", __func__, n_IRQ);
        return;
    }

    if (active) {
        src->ivpr |= IVPR_ACTIVITY_MASK;
    } else {
        src->ivpr &= ~IVPR_ACTIVITY_MASK;
    }

    if (src->destmask == 0) {
        
        DPRINTF("%s: IRQ %d has no target\n", __func__, n_IRQ);
        return;
    }

    if (src->destmask == (1 << src->last_cpu)) {
        
        IRQ_local_pipe(opp, src->last_cpu, n_IRQ, active, was_active);
    } else if (!(src->ivpr & IVPR_MODE_MASK)) {
        
        for (i = 0; i < opp->nb_cpus; i++) {
            if (src->destmask & (1 << i)) {
                IRQ_local_pipe(opp, i, n_IRQ, active, was_active);
            }
        }
    } else {
        
        for (i = src->last_cpu + 1; i != src->last_cpu; i++) {
            if (i == opp->nb_cpus) {
                i = 0;
            }
            if (src->destmask & (1 << i)) {
                IRQ_local_pipe(opp, i, n_IRQ, active, was_active);
                src->last_cpu = i;
                break;
            }
        }
    }
}

static void openpic_set_irq(void *opaque, int n_IRQ, int level)
{
    OpenPICState *opp = opaque;
    IRQSource *src;

    if (n_IRQ >= OPENPIC_MAX_IRQ) {
        fprintf(stderr, "%s: IRQ %d out of range\n", __func__, n_IRQ);
        abort();
    }

    src = &opp->src[n_IRQ];
    DPRINTF("openpic: set irq %d = %d ivpr=0x%08x\n", n_IRQ, level, src->ivpr);
    if (src->level) {
        
        src->pending = level;
        openpic_update_irq(opp, n_IRQ);
    } else {
        
        if (level) {
            src->pending = 1;
            openpic_update_irq(opp, n_IRQ);
        }

        if (src->output != OPENPIC_OUTPUT_INT) {
            
            src->pending = 0;
            openpic_update_irq(opp, n_IRQ);
        }
    }
}

static void openpic_reset(DeviceState *d)
{
    OpenPICState *opp = OPENPIC(d);
    int i;

    opp->gcr = GCR_RESET;
    
    opp->frr = ((opp->nb_irqs - 1) << FRR_NIRQ_SHIFT) | ((opp->nb_cpus - 1) << FRR_NCPU_SHIFT) | (opp->vid << FRR_VID_SHIFT);


    opp->pir = 0;
    opp->spve = -1 & opp->vector_mask;
    opp->tfrr = opp->tfrr_reset;
    
    for (i = 0; i < opp->max_irq; i++) {
        opp->src[i].ivpr = opp->ivpr_reset;
        opp->src[i].idr  = opp->idr_reset;

        switch (opp->src[i].type) {
        case IRQ_TYPE_NORMAL:
            opp->src[i].level = !!(opp->ivpr_reset & IVPR_SENSE_MASK);
            break;

        case IRQ_TYPE_FSLINT:
            opp->src[i].ivpr |= IVPR_POLARITY_MASK;
            break;

        case IRQ_TYPE_FSLSPECIAL:
            break;
        }
    }
    
    for (i = 0; i < MAX_CPU; i++) {
        opp->dst[i].ctpr      = 15;
        memset(&opp->dst[i].raised, 0, sizeof(IRQQueue));
        opp->dst[i].raised.next = -1;
        memset(&opp->dst[i].servicing, 0, sizeof(IRQQueue));
        opp->dst[i].servicing.next = -1;
    }
    
    for (i = 0; i < OPENPIC_MAX_TMR; i++) {
        opp->timers[i].tccr = 0;
        opp->timers[i].tbcr = TBCR_CI;
    }
    
    opp->gcr = 0;
}

static inline uint32_t read_IRQreg_idr(OpenPICState *opp, int n_IRQ)
{
    return opp->src[n_IRQ].idr;
}

static inline uint32_t read_IRQreg_ilr(OpenPICState *opp, int n_IRQ)
{
    if (opp->flags & OPENPIC_FLAG_ILR) {
        return output_to_inttgt(opp->src[n_IRQ].output);
    }

    return 0xffffffff;
}

static inline uint32_t read_IRQreg_ivpr(OpenPICState *opp, int n_IRQ)
{
    return opp->src[n_IRQ].ivpr;
}

static inline void write_IRQreg_idr(OpenPICState *opp, int n_IRQ, uint32_t val)
{
    IRQSource *src = &opp->src[n_IRQ];
    uint32_t normal_mask = (1UL << opp->nb_cpus) - 1;
    uint32_t crit_mask = 0;
    uint32_t mask = normal_mask;
    int crit_shift = IDR_EP_SHIFT - opp->nb_cpus;
    int i;

    if (opp->flags & OPENPIC_FLAG_IDR_CRIT) {
        crit_mask = mask << crit_shift;
        mask |= crit_mask | IDR_EP;
    }

    src->idr = val & mask;
    DPRINTF("Set IDR %d to 0x%08x\n", n_IRQ, src->idr);

    if (opp->flags & OPENPIC_FLAG_IDR_CRIT) {
        if (src->idr & crit_mask) {
            if (src->idr & normal_mask) {
                DPRINTF("%s: IRQ configured for multiple output types, using " "critical\n", __func__);
            }

            src->output = OPENPIC_OUTPUT_CINT;
            src->nomask = true;
            src->destmask = 0;

            for (i = 0; i < opp->nb_cpus; i++) {
                int n_ci = IDR_CI0_SHIFT - i;

                if (src->idr & (1UL << n_ci)) {
                    src->destmask |= 1UL << i;
                }
            }
        } else {
            src->output = OPENPIC_OUTPUT_INT;
            src->nomask = false;
            src->destmask = src->idr & normal_mask;
        }
    } else {
        src->destmask = src->idr;
    }
}

static inline void write_IRQreg_ilr(OpenPICState *opp, int n_IRQ, uint32_t val)
{
    if (opp->flags & OPENPIC_FLAG_ILR) {
        IRQSource *src = &opp->src[n_IRQ];

        src->output = inttgt_to_output(val & ILR_INTTGT_MASK);
        DPRINTF("Set ILR %d to 0x%08x, output %d\n", n_IRQ, src->idr, src->output);

        
    }
}

static inline void write_IRQreg_ivpr(OpenPICState *opp, int n_IRQ, uint32_t val)
{
    uint32_t mask;

    
    mask = IVPR_MASK_MASK | IVPR_PRIORITY_MASK | IVPR_SENSE_MASK | IVPR_POLARITY_MASK | opp->vector_mask;

    
    opp->src[n_IRQ].ivpr = (opp->src[n_IRQ].ivpr & IVPR_ACTIVITY_MASK) | (val & mask);

    
    switch (opp->src[n_IRQ].type) {
    case IRQ_TYPE_NORMAL:
        opp->src[n_IRQ].level = !!(opp->src[n_IRQ].ivpr & IVPR_SENSE_MASK);
        break;

    case IRQ_TYPE_FSLINT:
        opp->src[n_IRQ].ivpr &= ~IVPR_SENSE_MASK;
        break;

    case IRQ_TYPE_FSLSPECIAL:
        opp->src[n_IRQ].ivpr &= ~(IVPR_POLARITY_MASK | IVPR_SENSE_MASK);
        break;
    }

    openpic_update_irq(opp, n_IRQ);
    DPRINTF("Set IVPR %d to 0x%08x -> 0x%08x\n", n_IRQ, val, opp->src[n_IRQ].ivpr);
}

static void openpic_gcr_write(OpenPICState *opp, uint64_t val)
{
    bool mpic_proxy = false;

    if (val & GCR_RESET) {
        openpic_reset(DEVICE(opp));
        return;
    }

    opp->gcr &= ~opp->mpic_mode_mask;
    opp->gcr |= val & opp->mpic_mode_mask;

    
    if ((val & opp->mpic_mode_mask) == GCR_MODE_PROXY) {
        mpic_proxy = true;
    }

    ppce500_set_mpic_proxy(mpic_proxy);
}

static void openpic_gbl_write(void *opaque, hwaddr addr, uint64_t val, unsigned len)
{
    OpenPICState *opp = opaque;
    IRQDest *dst;
    int idx;

    DPRINTF("%s: addr %#" HWADDR_PRIx " <= %08" PRIx64 "\n", __func__, addr, val);
    if (addr & 0xF) {
        return;
    }
    switch (addr) {
    case 0x00: 
        break;
    case 0x40:
    case 0x50:
    case 0x60:
    case 0x70:
    case 0x80:
    case 0x90:
    case 0xA0:
    case 0xB0:
        openpic_cpu_write_internal(opp, addr, val, get_current_cpu());
        break;
    case 0x1000: 
        break;
    case 0x1020: 
        openpic_gcr_write(opp, val);
        break;
    case 0x1080: 
        break;
    case 0x1090: 
        for (idx = 0; idx < opp->nb_cpus; idx++) {
            if ((val & (1 << idx)) && !(opp->pir & (1 << idx))) {
                DPRINTF("Raise OpenPIC RESET output for CPU %d\n", idx);
                dst = &opp->dst[idx];
                qemu_irq_raise(dst->irqs[OPENPIC_OUTPUT_RESET]);
            } else if (!(val & (1 << idx)) && (opp->pir & (1 << idx))) {
                DPRINTF("Lower OpenPIC RESET output for CPU %d\n", idx);
                dst = &opp->dst[idx];
                qemu_irq_lower(dst->irqs[OPENPIC_OUTPUT_RESET]);
            }
        }
        opp->pir = val;
        break;
    case 0x10A0: 
    case 0x10B0:
    case 0x10C0:
    case 0x10D0:
        {
            int idx;
            idx = (addr - 0x10A0) >> 4;
            write_IRQreg_ivpr(opp, opp->irq_ipi0 + idx, val);
        }
        break;
    case 0x10E0: 
        opp->spve = val & opp->vector_mask;
        break;
    default:
        break;
    }
}

static uint64_t openpic_gbl_read(void *opaque, hwaddr addr, unsigned len)
{
    OpenPICState *opp = opaque;
    uint32_t retval;

    DPRINTF("%s: addr %#" HWADDR_PRIx "\n", __func__, addr);
    retval = 0xFFFFFFFF;
    if (addr & 0xF) {
        return retval;
    }
    switch (addr) {
    case 0x1000: 
        retval = opp->frr;
        break;
    case 0x1020: 
        retval = opp->gcr;
        break;
    case 0x1080: 
        retval = opp->vir;
        break;
    case 0x1090: 
        retval = 0x00000000;
        break;
    case 0x00: 
        retval = opp->brr1;
        break;
    case 0x40:
    case 0x50:
    case 0x60:
    case 0x70:
    case 0x80:
    case 0x90:
    case 0xA0:
    case 0xB0:
        retval = openpic_cpu_read_internal(opp, addr, get_current_cpu());
        break;
    case 0x10A0: 
    case 0x10B0:
    case 0x10C0:
    case 0x10D0:
        {
            int idx;
            idx = (addr - 0x10A0) >> 4;
            retval = read_IRQreg_ivpr(opp, opp->irq_ipi0 + idx);
        }
        break;
    case 0x10E0: 
        retval = opp->spve;
        break;
    default:
        break;
    }
    DPRINTF("%s: => 0x%08x\n", __func__, retval);

    return retval;
}

static void openpic_tmr_write(void *opaque, hwaddr addr, uint64_t val, unsigned len)
{
    OpenPICState *opp = opaque;
    int idx;

    addr += 0x10f0;

    DPRINTF("%s: addr %#" HWADDR_PRIx " <= %08" PRIx64 "\n", __func__, addr, val);
    if (addr & 0xF) {
        return;
    }

    if (addr == 0x10f0) {
        
        opp->tfrr = val;
        return;
    }

    idx = (addr >> 6) & 0x3;
    addr = addr & 0x30;

    switch (addr & 0x30) {
    case 0x00: 
        break;
    case 0x10: 
        if ((opp->timers[idx].tccr & TCCR_TOG) != 0 && (val & TBCR_CI) == 0 && (opp->timers[idx].tbcr & TBCR_CI) != 0) {

            opp->timers[idx].tccr &= ~TCCR_TOG;
        }
        opp->timers[idx].tbcr = val;
        break;
    case 0x20: 
        write_IRQreg_ivpr(opp, opp->irq_tim0 + idx, val);
        break;
    case 0x30: 
        write_IRQreg_idr(opp, opp->irq_tim0 + idx, val);
        break;
    }
}

static uint64_t openpic_tmr_read(void *opaque, hwaddr addr, unsigned len)
{
    OpenPICState *opp = opaque;
    uint32_t retval = -1;
    int idx;

    DPRINTF("%s: addr %#" HWADDR_PRIx "\n", __func__, addr);
    if (addr & 0xF) {
        goto out;
    }
    idx = (addr >> 6) & 0x3;
    if (addr == 0x0) {
        
        retval = opp->tfrr;
        goto out;
    }
    switch (addr & 0x30) {
    case 0x00: 
        retval = opp->timers[idx].tccr;
        break;
    case 0x10: 
        retval = opp->timers[idx].tbcr;
        break;
    case 0x20: 
        retval = read_IRQreg_ivpr(opp, opp->irq_tim0 + idx);
        break;
    case 0x30: 
        retval = read_IRQreg_idr(opp, opp->irq_tim0 + idx);
        break;
    }

out:
    DPRINTF("%s: => 0x%08x\n", __func__, retval);

    return retval;
}

static void openpic_src_write(void *opaque, hwaddr addr, uint64_t val, unsigned len)
{
    OpenPICState *opp = opaque;
    int idx;

    DPRINTF("%s: addr %#" HWADDR_PRIx " <= %08" PRIx64 "\n", __func__, addr, val);

    addr = addr & 0xffff;
    idx = addr >> 5;

    switch (addr & 0x1f) {
    case 0x00:
        write_IRQreg_ivpr(opp, idx, val);
        break;
    case 0x10:
        write_IRQreg_idr(opp, idx, val);
        break;
    case 0x18:
        write_IRQreg_ilr(opp, idx, val);
        break;
    }
}

static uint64_t openpic_src_read(void *opaque, uint64_t addr, unsigned len)
{
    OpenPICState *opp = opaque;
    uint32_t retval;
    int idx;

    DPRINTF("%s: addr %#" HWADDR_PRIx "\n", __func__, addr);
    retval = 0xFFFFFFFF;

    addr = addr & 0xffff;
    idx = addr >> 5;

    switch (addr & 0x1f) {
    case 0x00:
        retval = read_IRQreg_ivpr(opp, idx);
        break;
    case 0x10:
        retval = read_IRQreg_idr(opp, idx);
        break;
    case 0x18:
        retval = read_IRQreg_ilr(opp, idx);
        break;
    }

    DPRINTF("%s: => 0x%08x\n", __func__, retval);
    return retval;
}

static void openpic_msi_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    OpenPICState *opp = opaque;
    int idx = opp->irq_msi;
    int srs, ibs;

    DPRINTF("%s: addr %#" HWADDR_PRIx " <= 0x%08" PRIx64 "\n", __func__, addr, val);
    if (addr & 0xF) {
        return;
    }

    switch (addr) {
    case MSIIR_OFFSET:
        srs = val >> MSIIR_SRS_SHIFT;
        idx += srs;
        ibs = (val & MSIIR_IBS_MASK) >> MSIIR_IBS_SHIFT;
        opp->msi[srs].msir |= 1 << ibs;
        openpic_set_irq(opp, idx, 1);
        break;
    default:
        
        break;
    }
}

static uint64_t openpic_msi_read(void *opaque, hwaddr addr, unsigned size)
{
    OpenPICState *opp = opaque;
    uint64_t r = 0;
    int i, srs;

    DPRINTF("%s: addr %#" HWADDR_PRIx "\n", __func__, addr);
    if (addr & 0xF) {
        return -1;
    }

    srs = addr >> 4;

    switch (addr) {
    case 0x00:
    case 0x10:
    case 0x20:
    case 0x30:
    case 0x40:
    case 0x50:
    case 0x60:
    case 0x70: 
        r = opp->msi[srs].msir;
        
        opp->msi[srs].msir = 0;
        openpic_set_irq(opp, opp->irq_msi + srs, 0);
        break;
    case 0x120: 
        for (i = 0; i < MAX_MSI; i++) {
            r |= (opp->msi[i].msir ? 1 : 0) << i;
        }
        break;
    }

    return r;
}

static uint64_t openpic_summary_read(void *opaque, hwaddr addr, unsigned size)
{
    uint64_t r = 0;

    DPRINTF("%s: addr %#" HWADDR_PRIx "\n", __func__, addr);

    

    return r;
}

static void openpic_summary_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    DPRINTF("%s: addr %#" HWADDR_PRIx " <= 0x%08" PRIx64 "\n", __func__, addr, val);

    
}

static void openpic_cpu_write_internal(void *opaque, hwaddr addr, uint32_t val, int idx)
{
    OpenPICState *opp = opaque;
    IRQSource *src;
    IRQDest *dst;
    int s_IRQ, n_IRQ;

    DPRINTF("%s: cpu %d addr %#" HWADDR_PRIx " <= 0x%08x\n", __func__, idx, addr, val);

    if (idx < 0) {
        return;
    }

    if (addr & 0xF) {
        return;
    }
    dst = &opp->dst[idx];
    addr &= 0xFF0;
    switch (addr) {
    case 0x40: 
    case 0x50:
    case 0x60:
    case 0x70:
        idx = (addr - 0x40) >> 4;
        
        opp->src[opp->irq_ipi0 + idx].destmask |= val;
        openpic_set_irq(opp, opp->irq_ipi0 + idx, 1);
        openpic_set_irq(opp, opp->irq_ipi0 + idx, 0);
        break;
    case 0x80: 
        dst->ctpr = val & 0x0000000F;

        DPRINTF("%s: set CPU %d ctpr to %d, raised %d servicing %d\n", __func__, idx, dst->ctpr, dst->raised.priority, dst->servicing.priority);


        if (dst->raised.priority <= dst->ctpr) {
            DPRINTF("%s: Lower OpenPIC INT output cpu %d due to ctpr\n", __func__, idx);
            qemu_irq_lower(dst->irqs[OPENPIC_OUTPUT_INT]);
        } else if (dst->raised.priority > dst->servicing.priority) {
            DPRINTF("%s: Raise OpenPIC INT output cpu %d irq %d\n", __func__, idx, dst->raised.next);
            qemu_irq_raise(dst->irqs[OPENPIC_OUTPUT_INT]);
        }

        break;
    case 0x90: 
        
        break;
    case 0xA0: 
        
        break;
    case 0xB0: 
        DPRINTF("EOI\n");
        s_IRQ = IRQ_get_next(opp, &dst->servicing);

        if (s_IRQ < 0) {
            DPRINTF("%s: EOI with no interrupt in service\n", __func__);
            break;
        }

        IRQ_resetbit(&dst->servicing, s_IRQ);
        
        s_IRQ = IRQ_get_next(opp, &dst->servicing);
        
        n_IRQ = IRQ_get_next(opp, &dst->raised);
        src = &opp->src[n_IRQ];
        if (n_IRQ != -1 && (s_IRQ == -1 || IVPR_PRIORITY(src->ivpr) > dst->servicing.priority)) {

            DPRINTF("Raise OpenPIC INT output cpu %d irq %d\n", idx, n_IRQ);
            qemu_irq_raise(opp->dst[idx].irqs[OPENPIC_OUTPUT_INT]);
        }
        break;
    default:
        break;
    }
}

static void openpic_cpu_write(void *opaque, hwaddr addr, uint64_t val, unsigned len)
{
    openpic_cpu_write_internal(opaque, addr, val, (addr & 0x1f000) >> 12);
}


static uint32_t openpic_iack(OpenPICState *opp, IRQDest *dst, int cpu)
{
    IRQSource *src;
    int retval, irq;

    DPRINTF("Lower OpenPIC INT output\n");
    qemu_irq_lower(dst->irqs[OPENPIC_OUTPUT_INT]);

    irq = IRQ_get_next(opp, &dst->raised);
    DPRINTF("IACK: irq=%d\n", irq);

    if (irq == -1) {
        
        return opp->spve;
    }

    src = &opp->src[irq];
    if (!(src->ivpr & IVPR_ACTIVITY_MASK) || !(IVPR_PRIORITY(src->ivpr) > dst->ctpr)) {
        fprintf(stderr, "%s: bad raised IRQ %d ctpr %d ivpr 0x%08x\n", __func__, irq, dst->ctpr, src->ivpr);
        openpic_update_irq(opp, irq);
        retval = opp->spve;
    } else {
        
        IRQ_setbit(&dst->servicing, irq);
        retval = IVPR_VECTOR(opp, src->ivpr);
    }

    if (!src->level) {
        
        src->ivpr &= ~IVPR_ACTIVITY_MASK;
        src->pending = 0;
        IRQ_resetbit(&dst->raised, irq);
    }

    if ((irq >= opp->irq_ipi0) &&  (irq < (opp->irq_ipi0 + OPENPIC_MAX_IPI))) {
        src->destmask &= ~(1 << cpu);
        if (src->destmask && !src->level) {
            
            openpic_set_irq(opp, irq, 1);
            openpic_set_irq(opp, irq, 0);
            
            src->ivpr |= IVPR_ACTIVITY_MASK;
        }
    }

    return retval;
}

static uint32_t openpic_cpu_read_internal(void *opaque, hwaddr addr, int idx)
{
    OpenPICState *opp = opaque;
    IRQDest *dst;
    uint32_t retval;

    DPRINTF("%s: cpu %d addr %#" HWADDR_PRIx "\n", __func__, idx, addr);
    retval = 0xFFFFFFFF;

    if (idx < 0) {
        return retval;
    }

    if (addr & 0xF) {
        return retval;
    }
    dst = &opp->dst[idx];
    addr &= 0xFF0;
    switch (addr) {
    case 0x80: 
        retval = dst->ctpr;
        break;
    case 0x90: 
        retval = idx;
        break;
    case 0xA0: 
        retval = openpic_iack(opp, dst, idx);
        break;
    case 0xB0: 
        retval = 0;
        break;
    default:
        break;
    }
    DPRINTF("%s: => 0x%08x\n", __func__, retval);

    return retval;
}

static uint64_t openpic_cpu_read(void *opaque, hwaddr addr, unsigned len)
{
    return openpic_cpu_read_internal(opaque, addr, (addr & 0x1f000) >> 12);
}

static const MemoryRegionOps openpic_glb_ops_le = {
    .write = openpic_gbl_write, .read  = openpic_gbl_read, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_glb_ops_be = {
    .write = openpic_gbl_write, .read  = openpic_gbl_read, .endianness = DEVICE_BIG_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_tmr_ops_le = {
    .write = openpic_tmr_write, .read  = openpic_tmr_read, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_tmr_ops_be = {
    .write = openpic_tmr_write, .read  = openpic_tmr_read, .endianness = DEVICE_BIG_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_cpu_ops_le = {
    .write = openpic_cpu_write, .read  = openpic_cpu_read, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_cpu_ops_be = {
    .write = openpic_cpu_write, .read  = openpic_cpu_read, .endianness = DEVICE_BIG_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_src_ops_le = {
    .write = openpic_src_write, .read  = openpic_src_read, .endianness = DEVICE_LITTLE_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_src_ops_be = {
    .write = openpic_src_write, .read  = openpic_src_read, .endianness = DEVICE_BIG_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_msi_ops_be = {
    .read = openpic_msi_read, .write = openpic_msi_write, .endianness = DEVICE_BIG_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static const MemoryRegionOps openpic_summary_ops_be = {
    .read = openpic_summary_read, .write = openpic_summary_write, .endianness = DEVICE_BIG_ENDIAN, .impl = {


        .min_access_size = 4, .max_access_size = 4, }, };



static void openpic_save_IRQ_queue(QEMUFile* f, IRQQueue *q)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(q->queue); i++) {
        
        qemu_put_be32(f, (uint32_t)q->queue[i]);

        qemu_put_be32(f, (uint32_t)(q->queue[i] >> 32));

    }

    qemu_put_sbe32s(f, &q->next);
    qemu_put_sbe32s(f, &q->priority);
}

static void openpic_save(QEMUFile* f, void *opaque)
{
    OpenPICState *opp = (OpenPICState *)opaque;
    unsigned int i;

    qemu_put_be32s(f, &opp->gcr);
    qemu_put_be32s(f, &opp->vir);
    qemu_put_be32s(f, &opp->pir);
    qemu_put_be32s(f, &opp->spve);
    qemu_put_be32s(f, &opp->tfrr);

    qemu_put_be32s(f, &opp->nb_cpus);

    for (i = 0; i < opp->nb_cpus; i++) {
        qemu_put_sbe32s(f, &opp->dst[i].ctpr);
        openpic_save_IRQ_queue(f, &opp->dst[i].raised);
        openpic_save_IRQ_queue(f, &opp->dst[i].servicing);
        qemu_put_buffer(f, (uint8_t *)&opp->dst[i].outputs_active, sizeof(opp->dst[i].outputs_active));
    }

    for (i = 0; i < OPENPIC_MAX_TMR; i++) {
        qemu_put_be32s(f, &opp->timers[i].tccr);
        qemu_put_be32s(f, &opp->timers[i].tbcr);
    }

    for (i = 0; i < opp->max_irq; i++) {
        qemu_put_be32s(f, &opp->src[i].ivpr);
        qemu_put_be32s(f, &opp->src[i].idr);
        qemu_get_be32s(f, &opp->src[i].destmask);
        qemu_put_sbe32s(f, &opp->src[i].last_cpu);
        qemu_put_sbe32s(f, &opp->src[i].pending);
    }
}

static void openpic_load_IRQ_queue(QEMUFile* f, IRQQueue *q)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(q->queue); i++) {
        unsigned long val;

        val = qemu_get_be32(f);

        val <<= 32;
        val |= qemu_get_be32(f);


        q->queue[i] = val;
    }

    qemu_get_sbe32s(f, &q->next);
    qemu_get_sbe32s(f, &q->priority);
}

static int openpic_load(QEMUFile* f, void *opaque, int version_id)
{
    OpenPICState *opp = (OpenPICState *)opaque;
    unsigned int i;

    if (version_id != 1) {
        return -EINVAL;
    }

    qemu_get_be32s(f, &opp->gcr);
    qemu_get_be32s(f, &opp->vir);
    qemu_get_be32s(f, &opp->pir);
    qemu_get_be32s(f, &opp->spve);
    qemu_get_be32s(f, &opp->tfrr);

    qemu_get_be32s(f, &opp->nb_cpus);

    for (i = 0; i < opp->nb_cpus; i++) {
        qemu_get_sbe32s(f, &opp->dst[i].ctpr);
        openpic_load_IRQ_queue(f, &opp->dst[i].raised);
        openpic_load_IRQ_queue(f, &opp->dst[i].servicing);
        qemu_get_buffer(f, (uint8_t *)&opp->dst[i].outputs_active, sizeof(opp->dst[i].outputs_active));
    }

    for (i = 0; i < OPENPIC_MAX_TMR; i++) {
        qemu_get_be32s(f, &opp->timers[i].tccr);
        qemu_get_be32s(f, &opp->timers[i].tbcr);
    }

    for (i = 0; i < opp->max_irq; i++) {
        uint32_t val;

        val = qemu_get_be32(f);
        write_IRQreg_idr(opp, i, val);
        val = qemu_get_be32(f);
        write_IRQreg_ivpr(opp, i, val);

        qemu_get_be32s(f, &opp->src[i].ivpr);
        qemu_get_be32s(f, &opp->src[i].idr);
        qemu_get_be32s(f, &opp->src[i].destmask);
        qemu_get_sbe32s(f, &opp->src[i].last_cpu);
        qemu_get_sbe32s(f, &opp->src[i].pending);
    }

    return 0;
}

typedef struct MemReg {
    const char             *name;
    MemoryRegionOps const  *ops;
    hwaddr      start_addr;
    ram_addr_t              size;
} MemReg;

static void fsl_common_init(OpenPICState *opp)
{
    int i;
    int virq = OPENPIC_MAX_SRC;

    opp->vid = VID_REVISION_1_2;
    opp->vir = VIR_GENERIC;
    opp->vector_mask = 0xFFFF;
    opp->tfrr_reset = 0;
    opp->ivpr_reset = IVPR_MASK_MASK;
    opp->idr_reset = 1 << 0;
    opp->max_irq = OPENPIC_MAX_IRQ;

    opp->irq_ipi0 = virq;
    virq += OPENPIC_MAX_IPI;
    opp->irq_tim0 = virq;
    virq += OPENPIC_MAX_TMR;

    assert(virq <= OPENPIC_MAX_IRQ);

    opp->irq_msi = 224;

    msi_supported = true;
    for (i = 0; i < opp->fsl->max_ext; i++) {
        opp->src[i].level = false;
    }

    
    for (i = 16; i < OPENPIC_MAX_SRC; i++) {
        opp->src[i].type = IRQ_TYPE_FSLINT;
        opp->src[i].level = true;
    }

    
    for (i = OPENPIC_MAX_SRC; i < virq; i++) {
        opp->src[i].type = IRQ_TYPE_FSLSPECIAL;
        opp->src[i].level = false;
    }
}

static void map_list(OpenPICState *opp, const MemReg *list, int *count)
{
    while (list->name) {
        assert(*count < ARRAY_SIZE(opp->sub_io_mem));

        memory_region_init_io(&opp->sub_io_mem[*count], OBJECT(opp), list->ops, opp, list->name, list->size);

        memory_region_add_subregion(&opp->mem, list->start_addr, &opp->sub_io_mem[*count]);

        (*count)++;
        list++;
    }
}

static void openpic_init(Object *obj)
{
    OpenPICState *opp = OPENPIC(obj);

    memory_region_init(&opp->mem, obj, "openpic", 0x40000);
}

static void openpic_realize(DeviceState *dev, Error **errp)
{
    SysBusDevice *d = SYS_BUS_DEVICE(dev);
    OpenPICState *opp = OPENPIC(dev);
    int i, j;
    int list_count = 0;
    static const MemReg list_le[] = {
        {"glb", &openpic_glb_ops_le, OPENPIC_GLB_REG_START, OPENPIC_GLB_REG_SIZE}, {"tmr", &openpic_tmr_ops_le, OPENPIC_TMR_REG_START, OPENPIC_TMR_REG_SIZE}, {"src", &openpic_src_ops_le, OPENPIC_SRC_REG_START, OPENPIC_SRC_REG_SIZE}, {"cpu", &openpic_cpu_ops_le, OPENPIC_CPU_REG_START, OPENPIC_CPU_REG_SIZE}, {NULL}







    };
    static const MemReg list_be[] = {
        {"glb", &openpic_glb_ops_be, OPENPIC_GLB_REG_START, OPENPIC_GLB_REG_SIZE}, {"tmr", &openpic_tmr_ops_be, OPENPIC_TMR_REG_START, OPENPIC_TMR_REG_SIZE}, {"src", &openpic_src_ops_be, OPENPIC_SRC_REG_START, OPENPIC_SRC_REG_SIZE}, {"cpu", &openpic_cpu_ops_be, OPENPIC_CPU_REG_START, OPENPIC_CPU_REG_SIZE}, {NULL}







    };
    static const MemReg list_fsl[] = {
        {"msi", &openpic_msi_ops_be, OPENPIC_MSI_REG_START, OPENPIC_MSI_REG_SIZE}, {"summary", &openpic_summary_ops_be, OPENPIC_SUMMARY_REG_START, OPENPIC_SUMMARY_REG_SIZE}, {NULL}



    };

    switch (opp->model) {
    case OPENPIC_MODEL_FSL_MPIC_20:
    default:
        opp->fsl = &fsl_mpic_20;
        opp->brr1 = 0x00400200;
        opp->flags |= OPENPIC_FLAG_IDR_CRIT;
        opp->nb_irqs = 80;
        opp->mpic_mode_mask = GCR_MODE_MIXED;

        fsl_common_init(opp);
        map_list(opp, list_be, &list_count);
        map_list(opp, list_fsl, &list_count);

        break;

    case OPENPIC_MODEL_FSL_MPIC_42:
        opp->fsl = &fsl_mpic_42;
        opp->brr1 = 0x00400402;
        opp->flags |= OPENPIC_FLAG_ILR;
        opp->nb_irqs = 196;
        opp->mpic_mode_mask = GCR_MODE_PROXY;

        fsl_common_init(opp);
        map_list(opp, list_be, &list_count);
        map_list(opp, list_fsl, &list_count);

        break;

    case OPENPIC_MODEL_RAVEN:
        opp->nb_irqs = RAVEN_MAX_EXT;
        opp->vid = VID_REVISION_1_3;
        opp->vir = VIR_GENERIC;
        opp->vector_mask = 0xFF;
        opp->tfrr_reset = 4160000;
        opp->ivpr_reset = IVPR_MASK_MASK | IVPR_MODE_MASK;
        opp->idr_reset = 0;
        opp->max_irq = RAVEN_MAX_IRQ;
        opp->irq_ipi0 = RAVEN_IPI_IRQ;
        opp->irq_tim0 = RAVEN_TMR_IRQ;
        opp->brr1 = -1;
        opp->mpic_mode_mask = GCR_MODE_MIXED;

        if (opp->nb_cpus != 1) {
            error_setg(errp, "Only UP supported today");
            return;
        }

        map_list(opp, list_le, &list_count);
        break;
    }

    for (i = 0; i < opp->nb_cpus; i++) {
        opp->dst[i].irqs = g_new(qemu_irq, OPENPIC_OUTPUT_NB);
        for (j = 0; j < OPENPIC_OUTPUT_NB; j++) {
            sysbus_init_irq(d, &opp->dst[i].irqs[j]);
        }
    }

    register_savevm(dev, "openpic", 0, 2, openpic_save, openpic_load, opp);

    sysbus_init_mmio(d, &opp->mem);
    qdev_init_gpio_in(dev, openpic_set_irq, opp->max_irq);
}

static Property openpic_properties[] = {
    DEFINE_PROP_UINT32("model", OpenPICState, model, OPENPIC_MODEL_FSL_MPIC_20), DEFINE_PROP_UINT32("nb_cpus", OpenPICState, nb_cpus, 1), DEFINE_PROP_END_OF_LIST(), };



static void openpic_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = openpic_realize;
    dc->props = openpic_properties;
    dc->reset = openpic_reset;
}

static const TypeInfo openpic_info = {
    .name          = TYPE_OPENPIC, .parent        = TYPE_SYS_BUS_DEVICE, .instance_size = sizeof(OpenPICState), .instance_init = openpic_init, .class_init    = openpic_class_init, };





static void openpic_register_types(void)
{
    type_register_static(&openpic_info);
}

type_init(openpic_register_types)
