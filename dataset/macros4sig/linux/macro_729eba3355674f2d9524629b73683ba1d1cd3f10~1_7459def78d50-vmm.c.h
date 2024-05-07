


#define NVKM_VMM_PAGE_COMP                                                 0x08
#define NVKM_VMM_PAGE_HOST                                                 0x04
#define NVKM_VMM_PAGE_SPARSE                                               0x01
#define NVKM_VMM_PAGE_SVHx             (NVKM_VMM_PAGE_SVxx | NVKM_VMM_PAGE_HOST)
#define NVKM_VMM_PAGE_SVxC             (NVKM_VMM_PAGE_SVxx | NVKM_VMM_PAGE_COMP)
#define NVKM_VMM_PAGE_SVxx             (NVKM_VMM_PAGE_Sxxx | NVKM_VMM_PAGE_VRAM)
#define NVKM_VMM_PAGE_SxHC             (NVKM_VMM_PAGE_SxHx | NVKM_VMM_PAGE_COMP)
#define NVKM_VMM_PAGE_SxHx             (NVKM_VMM_PAGE_Sxxx | NVKM_VMM_PAGE_HOST)
#define NVKM_VMM_PAGE_Sxxx                                (NVKM_VMM_PAGE_SPARSE)
#define NVKM_VMM_PAGE_VRAM                                                 0x02
#define NVKM_VMM_PAGE_xVHx             (NVKM_VMM_PAGE_xVxx | NVKM_VMM_PAGE_HOST)
#define NVKM_VMM_PAGE_xVxC             (NVKM_VMM_PAGE_xVxx | NVKM_VMM_PAGE_COMP)
#define NVKM_VMM_PAGE_xVxx                                  (NVKM_VMM_PAGE_VRAM)
#define NVKM_VMM_PAGE_xxHC             (NVKM_VMM_PAGE_xxHx | NVKM_VMM_PAGE_COMP)
#define NVKM_VMM_PAGE_xxHx                                  (NVKM_VMM_PAGE_HOST)
#define NVKM_VMM_PDE_INVALID(pde) IS_ERR_OR_NULL(pde)
#define NVKM_VMM_PDE_SPARSE       ERR_PTR(-EBUSY)
#define NVKM_VMM_PDE_SPARSED(pde) IS_ERR(pde)
#define NVKM_VMM_PTE_SPARSE 0x80
#define NVKM_VMM_PTE_SPTES  0x3f
#define NVKM_VMM_PTE_VALID  0x40
#define VMM_DEBUG(v,f,a...) VMM_PRINT(NV_DBG_DEBUG, (v), info, f, ##a)
#define VMM_FO(m,o,d,c,b) nvkm_fo##b((m)->memory, (o), (d), (c))
#define VMM_FO032(m,v,o,d,c)                                                   \
	VMM_XO((m),(v),(o),(d),(c), 32, FO, "%08x %08x", (c))
#define VMM_FO064(m,v,o,d,c)                                                   \
	VMM_XO((m),(v),(o),(d),(c), 64, FO, "%016llx %08x", (c))
#define VMM_FO128(m,v,o,lo,hi,c) do {                                          \
	nvkm_kmap((m)->memory);                                                \
	VMM_XO128((m),(v),(o),(lo),(hi),(c), " %08x", (c));                    \
	nvkm_done((m)->memory);                                                \
} while(0)
#define VMM_MAP_ITER(VMM,PT,PTEI,PTEN,MAP,FILL,BASE,SIZE,NEXT) do {            \
	nvkm_kmap((PT)->memory);                                               \
	while (PTEN) {                                                         \
		u64 _ptes = ((SIZE) - MAP->off) >> MAP->page->shift;           \
		u64 _addr = ((BASE) + MAP->off);                               \
                                                                               \
		if (_ptes > PTEN) {                                            \
			MAP->off += PTEN << MAP->page->shift;                  \
			_ptes = PTEN;                                          \
		} else {                                                       \
			MAP->off = 0;                                          \
			NEXT;                                                  \
		}                                                              \
                                                                               \
		VMM_SPAM(VMM, "ITER %08x %08x PTE(s)", PTEI, (u32)_ptes);      \
                                                                               \
		FILL(VMM, PT, PTEI, _ptes, MAP, _addr);                        \
		PTEI += _ptes;                                                 \
		PTEN -= _ptes;                                                 \
	};                                                                     \
	nvkm_done((PT)->memory);                                               \
} while(0)
#define VMM_MAP_ITER_DMA(VMM,PT,PTEI,PTEN,MAP,FILL)                            \
	VMM_MAP_ITER(VMM,PT,PTEI,PTEN,MAP,FILL,                                \
		     *MAP->dma, PAGE_SIZE, MAP->dma++)
#define VMM_MAP_ITER_MEM(VMM,PT,PTEI,PTEN,MAP,FILL)                            \
	VMM_MAP_ITER(VMM,PT,PTEI,PTEN,MAP,FILL,                                \
		     ((u64)MAP->mem->offset << NVKM_RAM_MM_SHIFT),             \
		     ((u64)MAP->mem->length << NVKM_RAM_MM_SHIFT),             \
		     (MAP->mem = MAP->mem->next))
#define VMM_MAP_ITER_SGL(VMM,PT,PTEI,PTEN,MAP,FILL)                            \
	VMM_MAP_ITER(VMM,PT,PTEI,PTEN,MAP,FILL,                                \
		     sg_dma_address(MAP->sgl), sg_dma_len(MAP->sgl),           \
		     (MAP->sgl = sg_next(MAP->sgl)))
#define VMM_PRINT(l,v,p,f,a...) do {                                           \
	struct nvkm_vmm *_vmm = (v);                                           \
	if (CONFIG_NOUVEAU_DEBUG >= (l) && _vmm->debug >= (l)) {               \
		nvkm_printk_(&_vmm->mmu->subdev, 0, p, "%s: "f"\n",            \
			     _vmm->name, ##a);                                 \
	}                                                                      \
} while(0)
#define VMM_SPAM(v,f,a...)  VMM_PRINT(NV_DBG_SPAM , (v),  dbg, f, ##a)
#define VMM_TRACE(v,f,a...) VMM_PRINT(NV_DBG_TRACE, (v), info, f, ##a)
#define VMM_WO(m,o,d,c,b) nvkm_wo##b((m)->memory, (o), (d))
#define VMM_WO032(m,v,o,d) VMM_XO((m),(v),(o),(d),  1, 32, WO, "%08x")
#define VMM_WO064(m,v,o,d) VMM_XO((m),(v),(o),(d),  1, 64, WO, "%016llx")
#define VMM_WO128(m,v,o,lo,hi) VMM_XO128((m),(v),(o),(lo),(hi), 1, "")
#define VMM_XO(m,v,o,d,c,b,fn,f,a...) do {                                     \
	const u32 _pteo = (o); u##b _data = (d);                               \
	VMM_SPAM((v), "   %010llx "f, (m)->addr + _pteo, _data, ##a);          \
	VMM_##fn((m), (m)->base + _pteo, _data, (c), b);                       \
} while(0)
#define VMM_XO128(m,v,o,lo,hi,c,f,a...) do {                                   \
	u32 _pteo = (o), _ptes = (c);                                          \
	const u64 _addr = (m)->addr + _pteo;                                   \
	VMM_SPAM((v), "   %010llx %016llx%016llx"f, _addr, (hi), (lo), ##a);   \
	while (_ptes--) {                                                      \
		nvkm_wo64((m)->memory, (m)->base + _pteo + 0, (lo));           \
		nvkm_wo64((m)->memory, (m)->base + _pteo + 8, (hi));           \
		_pteo += 0x10;                                                 \
	}                                                                      \
} while(0)


#define nvkm_mmu(p) container_of((p), struct nvkm_mmu, subdev)
