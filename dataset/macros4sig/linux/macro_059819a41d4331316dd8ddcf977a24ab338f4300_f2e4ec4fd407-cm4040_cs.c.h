
#include<linux/wait.h>
#include<linux/errno.h>




#include<linux/kernel.h>


#include<sys/types.h>



#include<linux/fs.h>

#include<linux/time.h>

#include<asm/ptrace.h>
#include<asm/siginfo.h>

#include<asm/types.h>




#include<linux/auxvec.h>


#include<linux/sched.h>






#include<linux/module.h>
#include<linux/aio_abi.h>




#include<linux/timex.h>

#include<asm/resource.h>

#include<asm/param.h>



#include<asm/signal.h>



#include<asm/fcntl.h>

#include<asm/poll.h>






#include<linux/uio.h>





#include<linux/types.h>
#include<asm/posix_types.h>
#include<asm/auxvec.h>












#include<linux/string.h>
#include<asm/sembuf.h>

#include<asm/ipcbuf.h>



#include<linux/stddef.h>
#include<asm/stat.h>




#include<linux/stat.h>



#include<asm/byteorder.h>
#include<asm/ioctl.h>

#include<stdarg.h>
#include<asm/errno.h>


#define BSR_BULK_IN_FULL  0x02
#define BSR_BULK_OUT_FULL 0x01
#define  CMD_PC_TO_RDR_ESCAPE           0x6B
#define  CMD_PC_TO_RDR_GETPARAMETERS    0x6C
#define  CMD_PC_TO_RDR_GETSLOTSTATUS    0x65
#define  CMD_PC_TO_RDR_ICCCLOCK         0x6E
#define  CMD_PC_TO_RDR_ICCPOWEROFF      0x63
#define  CMD_PC_TO_RDR_ICCPOWERON       0x62
#define  CMD_PC_TO_RDR_OK_SECURE        0x89
#define  CMD_PC_TO_RDR_RESETPARAMETERS  0x6D
#define  CMD_PC_TO_RDR_SECURE           0x69
#define  CMD_PC_TO_RDR_SETPARAMETERS    0x61
#define  CMD_PC_TO_RDR_TEST_SECURE      0x74
#define  CMD_PC_TO_RDR_XFRBLOCK         0x6F
#define  CMD_RDR_TO_PC_DATABLOCK          0x80
#define  CMD_RDR_TO_PC_ESCAPE             0x83
#define  CMD_RDR_TO_PC_OK_SECURE          0x89
#define  CMD_RDR_TO_PC_PARAMETERS         0x82
#define  CMD_RDR_TO_PC_SLOTSTATUS         0x81
#define REG_OFFSET_BUFFER_STATUS 1
#define REG_OFFSET_BULK_IN       0
#define REG_OFFSET_BULK_OUT      0
#define REG_OFFSET_SYNC_CONTROL  2
#define SCR_ABORT                0x40
#define SCR_ACK_NOTIFY           0x10
#define SCR_EN_NOTIFY            0x20
#define SCR_HOST_TO_READER_DONE  0x04
#define SCR_HOST_TO_READER_START 0x80
#define SCR_POWER_DOWN           0x01
#define SCR_PULSE_INTERRUPT      0x02
#define SCR_READER_TO_HOST_DONE  0x08
#define DS_ACCESS_CONFIGURATION_REGISTER _IOWR('d', 10, conf_reg_t)

#define handle_to_dev(handle) (handle->dev)
#define to_pcmcia_dev(n) container_of(n, struct pcmcia_device, dev)
#define to_pcmcia_drv(n) container_of(n, struct pcmcia_driver, drv)
#define MAX_IO_WIN 2
#define MAX_WIN 4

#define DECLARE_PCI_FIXUP_EARLY(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_early,			\
			vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_ENABLE(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_enable,			\
			vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_FINAL(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_final,			\
			vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_HEADER(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_header,			\
			vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_RESUME(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume,			\
			resume##vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_SECTION(section, name, vendor, device, hook)	\
	static const struct pci_fixup __pci_fixup_##name __attribute_used__ \
	__attribute__((__section__(#section))) = { vendor, device, hook };


#define PCI_DEVFN(slot,func)	((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define PCI_DEVICE_CLASS(dev_class,dev_class_mask) \
	.class = (dev_class), .class_mask = (dev_class_mask), \
	.vendor = PCI_ANY_ID, .device = PCI_ANY_ID, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define PCI_FUNC(devfn)		((devfn) & 0x07)
#define PCI_SLOT(devfn)		(((devfn) >> 3) & 0x1f)
#define PCI_VDEVICE(vendor, device)		\
	PCI_VENDOR_ID_##vendor, (device),	\
	PCI_ANY_ID, PCI_ANY_ID, 0, 0
#define _PCI_NOP(o,s,t) \
	static inline int pci_##o##_config_##s (struct pci_dev *dev, int where, t val) \
		{ return PCIBIOS_FUNC_NOT_SUPPORTED; }
#define _PCI_NOP_ALL(o,x)	_PCI_NOP(o,byte,u8 x) \
				_PCI_NOP(o,word,u16 x) \
				_PCI_NOP(o,dword,u32 x)
#define for_each_pci_dev(d) while ((d = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, d)) != NULL)
#define pci_bus_b(n)	list_entry(n, struct pci_bus, node)
#define pci_dev_b(n) list_entry(n, struct pci_dev, bus_list)
#define pci_dev_g(n) list_entry(n, struct pci_dev, global_list)
#define pci_dev_present(ids)	(0)
#define pci_dev_put(dev)	do { } while (0)
#define pci_dma_burst_advice(pdev, strat, strategy_parameter) do { } while (0)
#define pci_find_present(ids)	(NULL)
#define pci_pool_create(name, pdev, size, align, allocation) \
		dma_pool_create(name, &pdev->dev, size, align, allocation)
#define pci_resource_end(dev,bar)     ((dev)->resource[(bar)].end)
#define pci_resource_flags(dev,bar)   ((dev)->resource[(bar)].flags)
#define pci_resource_len(dev,bar) \
	((pci_resource_start((dev),(bar)) == 0 &&	\
	  pci_resource_end((dev),(bar)) ==		\
	  pci_resource_start((dev),(bar))) ? 0 :	\
	  						\
	 (pci_resource_end((dev),(bar)) -		\
	  pci_resource_start((dev),(bar)) + 1))
#define pci_resource_start(dev,bar)   ((dev)->resource[(bar)].start)
#define to_pci_bus(n)	container_of(n, struct pci_bus, class_dev)
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6200_ALT1 0x00f3
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6600_ALT1 0x00f1
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6600_ALT2 0x00f2
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6800_ALT1 0x00f0
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6800_GT   0x00f9
#define PCI_BASE_CLASS_SIGNAL_PROCESSING 0x11
#define PCI_CLASS_COMMUNICATION_MULTISERIAL 0x0702
#define PCI_CLASS_COMMUNICATION_PARALLEL 0x0701
#define PCI_DEVICE_ID_ABOCOM_2BD1       0x2BD1
#define PCI_DEVICE_ID_ADAPTEC2_OBSIDIAN   0x0500
#define PCI_DEVICE_ID_AL_M1535 		0x1535
#define PCI_DEVICE_ID_AMD_CS5536_AUDIO  0x2093
#define PCI_DEVICE_ID_AMD_CS5536_EHC    0x2095
#define PCI_DEVICE_ID_AMD_CS5536_FLASH  0x2091
#define PCI_DEVICE_ID_AMD_CS5536_IDE    0x209A
#define PCI_DEVICE_ID_AMD_CS5536_ISA    0x2090
#define PCI_DEVICE_ID_AMD_CS5536_OHC    0x2094
#define PCI_DEVICE_ID_AMD_CS5536_UDC    0x2096
#define PCI_DEVICE_ID_AMD_CS5536_UOC    0x2097
#define PCI_DEVICE_ID_AMD_LX_AES    0x2082
#define PCI_DEVICE_ID_AMD_LX_VIDEO  0x2081
#define PCI_DEVICE_ID_APPLE_SH_ATA      0x0050
#define PCI_DEVICE_ID_APPLE_SH_SUNGEM   0x0051
#define PCI_DEVICE_ID_APPLICOM_PCI2000IBS_CAN 0x0002
#define PCI_DEVICE_ID_APPLICOM_PCI2000PFB 0x0003
#define PCI_DEVICE_ID_APPLICOM_PCIGENERIC 0x0001
#define PCI_DEVICE_ID_ATI_IXP300_SATA   0x436e
#define PCI_DEVICE_ID_ATI_IXP400_SATA   0x4379
#define PCI_DEVICE_ID_ATI_RAGE128_MF    0x4d46
#define PCI_DEVICE_ID_ATI_RAGE128_ML    0x4d4c
#define PCI_DEVICE_ID_ATI_RS350_100     0x7830
#define PCI_DEVICE_ID_ATI_RS350_133     0x7831
#define PCI_DEVICE_ID_ATI_RS350_166     0x7832
#define PCI_DEVICE_ID_ATI_RS350_200     0x7833
#define PCI_DEVICE_ID_ATI_RS400_100     0x5a30
#define PCI_DEVICE_ID_ATI_RS400_133     0x5a31
#define PCI_DEVICE_ID_ATI_RS400_166     0x5a32
#define PCI_DEVICE_ID_ATI_RS400_200     0x5a33
#define PCI_DEVICE_ID_ATI_RS480         0x5950
#define PCI_DEVICE_ID_BUSLOGIC_FLASHPOINT     0x8130
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER    0x1040
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER_NC 0x0140
#define PCI_DEVICE_ID_COMPAQ_TRIFLEX_IDE 0xae33
#define PCI_DEVICE_ID_ESDGMBH_CPCIASIO4 0x0111
#define PCI_DEVICE_ID_FARSITE_T1U       0x0610
#define PCI_DEVICE_ID_FARSITE_T2P       0x0400
#define PCI_DEVICE_ID_FARSITE_T2U       0x0620
#define PCI_DEVICE_ID_FARSITE_T4P       0x0440
#define PCI_DEVICE_ID_FARSITE_T4U       0x0640
#define PCI_DEVICE_ID_FARSITE_TE1       0x1610
#define PCI_DEVICE_ID_FARSITE_TE1C      0x1612
#define PCI_DEVICE_ID_GEFORCE_6800A             0x00c1
#define PCI_DEVICE_ID_GEFORCE_6800A_LE          0x00c2
#define PCI_DEVICE_ID_GEFORCE_GO_6800           0x00c8
#define PCI_DEVICE_ID_GEFORCE_GO_6800_ULTRA     0x00c9
#define PCI_DEVICE_ID_HINT_VXPROII_IDE 0x8013
#define PCI_DEVICE_ID_INTEL_82454NX     0x84cb
#define PCI_DEVICE_ID_INTEL_82801DB_12  0x24cc
#define PCI_DEVICE_ID_MELLANOX_ARBEL_COMPAT 0x6278
#define PCI_DEVICE_ID_MELLANOX_SINAI_OLD 0x5e8c
#define PCI_DEVICE_ID_NEC_PC9821CS01    0x800c 
#define PCI_DEVICE_ID_NEC_PC9821NRB06   0x800d 
#define PCI_DEVICE_ID_NEC_VRC5476       0x009b
#define PCI_DEVICE_ID_NEC_VRC5477_AC97  0x00a6
#define PCI_DEVICE_ID_NEOMAGIC_NM256AV_AUDIO 0x8005
#define PCI_DEVICE_ID_NEOMAGIC_NM256XL_PLUS_AUDIO 0x8016
#define PCI_DEVICE_ID_NEOMAGIC_NM256ZX_AUDIO 0x8006
#define PCI_DEVICE_ID_NEO_2DB9          0x00C8
#define PCI_DEVICE_ID_NEO_2DB9PRI       0x00C9
#define PCI_DEVICE_ID_NEO_2RJ45         0x00CA
#define PCI_DEVICE_ID_NEO_2RJ45PRI      0x00CB
#define PCI_DEVICE_ID_NS_GX_HOST_BRIDGE  0x0028
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_410_GO_M16 0x017D
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_4200_GO       0x0286
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_420_GO_M32 0x0176
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_440_GO_M64 0x0179
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_448_GO    0x0186
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_460_GO    0x0177
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_488_GO    0x0187
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_4000   0x0185
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_420_8X 0x0183
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_440SE_8X 0x0182
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_440_8X 0x0181
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_MAC    0x0189
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_TI_4800SE     0x0282
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_TI_4800_8X    0x0281
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6200_TURBOCACHE 0x0161
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800       0x0041
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B      0x0211
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B_GT   0x0215
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B_LE   0x0212
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_GT    0x0045
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_LE    0x0042
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_ULTRA 0x0040
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_7800_GT   0x0090
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5100        0x0327
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200        0x0320
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200SE      0x0323
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200_1      0x0322
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200_ULTRA  0x0321
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5500        0x0326
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600        0x0312
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600SE      0x0314
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600_ULTRA  0x0311
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700        0x0342
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700LE      0x0343
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700VE      0x0344
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700_ULTRA  0x0341
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5800        0x0302
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5800_ULTRA  0x0301
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900        0x0331
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900XT      0x0332
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900ZT      0x0334
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900_ULTRA  0x0330
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5950_ULTRA  0x0333
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5100      0x032D
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5200      0x0324
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5250      0x0325
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5250_32   0x0328
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5300      0x032C
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5600      0x031A
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5650      0x031B
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5700_1    0x0347
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5700_2    0x0348
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6200    0x0164
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6200_1  0x0167
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6250    0x0166
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6250_1  0x0168
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_7800   0x0098
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_7800_GTX 0x0099
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_IDE       0x03EC
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA      0x03E7
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA2     0x03F6
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA3     0x03F7
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP67_IDE       0x0560
#define PCI_DEVICE_ID_NVIDIA_NVENET_14              0x0372
#define PCI_DEVICE_ID_NVIDIA_NVENET_15              0x0373
#define PCI_DEVICE_ID_NVIDIA_NVENET_16              0x03E5
#define PCI_DEVICE_ID_NVIDIA_NVENET_17              0x03E6
#define PCI_DEVICE_ID_NVIDIA_NVENET_18              0x03EE
#define PCI_DEVICE_ID_NVIDIA_NVENET_19              0x03EF
#define PCI_DEVICE_ID_NVIDIA_NVENET_20              0x0450
#define PCI_DEVICE_ID_NVIDIA_NVENET_21              0x0451
#define PCI_DEVICE_ID_NVIDIA_NVENET_22              0x0452
#define PCI_DEVICE_ID_NVIDIA_NVENET_23              0x0453
#define PCI_DEVICE_ID_NVIDIA_NVENET_24              0x054C
#define PCI_DEVICE_ID_NVIDIA_NVENET_25              0x054D
#define PCI_DEVICE_ID_NVIDIA_NVENET_26              0x054E
#define PCI_DEVICE_ID_NVIDIA_NVENET_27              0x054F
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_280_NVS    0x018A
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_380_XGL    0x018B
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_580_XGL    0x0188
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_700_GOGL       0x028C
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_780_XGL        0x0289
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_980_XGL        0x0288
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_1000         0x0309
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_1100         0x034E
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_2000         0x0308
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_3000         0x0338
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_4000     0x004E
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_500          0x032B
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_700          0x033F
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_GO1000       0x034C
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_GO700        0x031C
#define PCI_DEVICE_ID_NVIDIA_QUADRO_NVS_280_PCI     0x032A
#define PCI_DEVICE_ID_NVIDIA_SGS_RIVA128 0x0018
#define PCI_DEVICE_ID_NVIDIA_TNT_UNKNOWN        0x002a
#define PCI_DEVICE_ID_PCTECH_SAMURAI_IDE 0x3020
#define PCI_DEVICE_ID_PLX_9030          0x9030
#define PCI_DEVICE_ID_QUADRO_FX_1400            0x00ce
#define PCI_DEVICE_ID_QUADRO_FX_GO1400          0x00cc
#define PCI_DEVICE_ID_RME_DIGI96_8_PAD_OR_PST 0x3fc3
#define PCI_DEVICE_ID_SERVERWORKS_CSB5IDE 0x0212
#define PCI_DEVICE_ID_SERVERWORKS_CSB6    0x0203
#define PCI_DEVICE_ID_SERVERWORKS_CSB6IDE 0x0213
#define PCI_DEVICE_ID_SERVERWORKS_CSB6IDE2 0x0217
#define PCI_DEVICE_ID_SERVERWORKS_CSB6LPC 0x0227
#define PCI_DEVICE_ID_SERVERWORKS_GCNB_LE 0x0017
#define PCI_DEVICE_ID_SERVERWORKS_HT1000IDE 0x0214
#define PCI_DEVICE_ID_SERVERWORKS_HT1000SB 0x0205
#define PCI_DEVICE_ID_SERVERWORKS_OSB4IDE 0x0211
#define PCI_DEVICE_ID_SIEMENS_DSCC4     0x2102
#define PCI_DEVICE_ID_TDI_EHCI          0x0101
#define PCI_DEVICE_ID_TOSHIBA_SPIDER_NET 0x01b3
#define PCI_DEVICE_ID_XILINX_HAMMERFALL_DSP 0x3fc5
#define PCI_DEVICE_ID_XILINX_HAMMERFALL_DSP_MADI 0x3fc6
#define PCI_SUBDEVICE_ID_PCI_RAS4       0xf001
#define PCI_SUBDEVICE_ID_PCI_RAS8       0xf010
#define PCI_SUBDEVICE_ID_SPECIALIX_SPEED4 0xa004
#define PCI_SUBVENDOR_ID_PERLE          0x155f
#define PCI_VENDOR_ID_AT    		0x1259
#define PCI_VENDOR_ID_ELECTRONICDESIGNGMBH 0x12f8
#define PCI_VENDOR_ID_FARSITE           0x1619
#define PCI_VENDOR_ID_HINT             0x3388
#define PCI_VENDOR_ID_SIEMENS           0x110A
#define PCI_VENDOR_ID_TDI               0x192E
#define BUS_ATTR(_name,_mode,_show,_store)	\
struct bus_attribute bus_attr_##_name = __ATTR(_name,_mode,_show,_store)
#define CLASS_ATTR(_name,_mode,_show,_store)			\
struct class_attribute class_attr_##_name = __ATTR(_name,_mode,_show,_store) 
#define CLASS_DEVICE_ATTR(_name,_mode,_show,_store)		\
struct class_device_attribute class_device_attr_##_name = 	\
	__ATTR(_name,_mode,_show,_store)
#define DEVICE_ATTR(_name,_mode,_show,_store) \
struct device_attribute dev_attr_##_name = __ATTR(_name,_mode,_show,_store)
#define DRIVER_ATTR(_name,_mode,_show,_store)	\
struct driver_attribute driver_attr_##_name = __ATTR(_name,_mode,_show,_store)
#define MODULE_ALIAS_CHARDEV(major,minor) \
	MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major) \
	MODULE_ALIAS("char-major-" __stringify(major) "-*")

#define dev_dbg(dev, format, arg...)		\
	dev_printk(KERN_DEBUG , dev , format , ## arg)
#define dev_err(dev, format, arg...)		\
	dev_printk(KERN_ERR , dev , format , ## arg)
#define dev_info(dev, format, arg...)		\
	dev_printk(KERN_INFO , dev , format , ## arg)
#define dev_notice(dev, format, arg...)		\
	dev_printk(KERN_NOTICE , dev , format , ## arg)
#define dev_printk(level, dev, format, arg...)	\
	printk(level "%s %s: " format , dev_driver_string(dev) , (dev)->bus_id , ## arg)
#define dev_warn(dev, format, arg...)		\
	dev_printk(KERN_WARNING , dev , format , ## arg)
#define devres_alloc(release, size, gfp) \
	__devres_alloc(release, size, gfp, #release)
#define PM_EVENT_FREEZE 1
#define PM_EVENT_ON 0
#define PM_EVENT_PRETHAW 3
#define PM_EVENT_SUSPEND 2
#define PM_PCI_ID(dev) ((dev)->bus->number << 16 | (dev)->devfn)

#define device_can_wakeup(dev) \
	((dev)->power.can_wakeup)
#define device_init_wakeup(dev,val) \
	do { \
		device_can_wakeup(dev) = !!(val); \
		device_set_wakeup_enable(dev,val); \
	} while(0)
#define device_may_wakeup(dev) \
	(device_can_wakeup(dev) && (dev)->power.should_wakeup)
#define device_set_wakeup_enable(dev,val) \
	((dev)->power.should_wakeup = !!(val))
#define suspend_report_result(fn, ret)					\
	do {								\
		__suspend_report_result(__FUNCTION__, fn, ret);		\
	} while (0)
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define HLIST_HEAD_INIT { .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define __list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define __list_for_each_rcu(pos, head) \
	for (pos = (head)->next; \
		rcu_dereference(pos) != (head); \
        	pos = pos->next)
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos && ({ prefetch(pos->next); 1; }); \
	     pos = pos->next)
#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_continue(tpos, pos, member)		 \
	for (pos = (pos)->next;						 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_from(tpos, pos, member)			 \
	for (; pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_rcu(tpos, pos, head, member)		 \
	for (pos = (head)->first;					 \
	     rcu_dereference(pos) && ({ prefetch(pos->next); 1;}) &&	 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)
#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_for_each(pos, head) \
	for (pos = (head)->next; prefetch(pos->next), pos != (head); \
        	pos = pos->next)
#define list_for_each_continue_rcu(pos, head) \
	for ((pos) = (pos)->next; \
		prefetch(rcu_dereference((pos))->next), (pos) != (head); \
        	(pos) = (pos)->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_entry(pos->member.next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_from(pos, head, member) 			\
	for (; prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member); \
		prefetch(rcu_dereference(pos)->member.next), \
			&pos->member != (head); \
		pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     prefetch(pos->member.prev), &pos->member != (head); 	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_entry(pos->member.next, typeof(*pos), member), 		\
		n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, typeof(*pos), member),	\
		n = list_entry(pos->member.prev, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.prev, typeof(*n), member))
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; prefetch(pos->prev), pos != (head); \
        	pos = pos->prev)
#define list_for_each_rcu(pos, head) \
	for (pos = (head)->next; \
		prefetch(rcu_dereference(pos)->next), pos != (head); \
        	pos = pos->next)
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#define list_for_each_safe_rcu(pos, n, head) \
	for (pos = (head)->next; \
		n = rcu_dereference(pos)->next, pos != (head); \
		pos = n)
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)

#define spin_lock_prefetch(x) prefetchw(x)
#define BITS_PER_BYTE 8
#define BITS_TO_LONGS(bits) \
	(((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]








#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
#define aligned_be64 __be64 __attribute__((aligned(8)))
#define aligned_le64 __le64 __attribute__((aligned(8)))
#define aligned_u64 unsigned long long __attribute__((aligned(8)))
#define pgoff_t unsigned long

#define NULL ((void *)0)

#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })

# define __acquire(x)	__context__(x,1)
# define __acquires(x)	__attribute__((context(x,0,1)))
#define __always_inline inline
# define __builtin_warning(x, y...) (1)
# define __chk_io_ptr(x) (void)0
# define __chk_user_ptr(x) (void)0
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
#define __deprecated_for_modules __deprecated
# define __force
# define __iomem
# define __kernel

# define __nocast
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
# define __user
# define barrier() __memory_barrier()
#define likely(x)	__builtin_expect(!!(x), 1)

#define unlikely(x)	__builtin_expect(!!(x), 0)
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

#define EXPORT_SYMBOL(sym)					\
	__EXPORT_SYMBOL(sym, "")
#define EXPORT_SYMBOL_GPL(sym)					\
	__EXPORT_SYMBOL(sym, "_gpl")
#define EXPORT_SYMBOL_GPL_FUTURE(sym)				\
	__EXPORT_SYMBOL(sym, "_gpl_future")
#define EXPORT_UNUSED_SYMBOL(sym) __EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym, "_unused_gpl")
#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_DEVICE_TABLE(type,name)		\
  MODULE_GENERIC_TABLE(type##_device,name)
#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)
#define MODULE_GENERIC_TABLE(gtype,name)			\
extern const struct gtype##_id __mod_##gtype##_table		\
  __attribute__ ((unused, alias(__stringify(name))))
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)
#define MODULE_NAME_LEN (64 - sizeof(unsigned long))
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)

#define MODULE_SYMBOL_PREFIX ""
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)
#define THIS_MODULE (&__this_module)

#define __CRC_SYMBOL(sym, sec)					\
	extern void *__crc_##sym __attribute__((weak));		\
	static const unsigned long __kcrctab_##sym		\
	__attribute_used__					\
	__attribute__((section("__kcrctab" sec), unused))	\
	= (unsigned long) &__crc_##sym;
#define __EXPORT_SYMBOL(sym, sec)				\
	extern typeof(sym) sym;					\
	__CRC_SYMBOL(sym, sec)					\
	static const char __kstrtab_##sym[]			\
	__attribute__((section("__ksymtab_strings")))		\
	= MODULE_SYMBOL_PREFIX #sym;                    	\
	static const struct kernel_symbol __ksymtab_##sym	\
	__attribute_used__					\
	__attribute__((section("__ksymtab" sec), unused))	\
	= { (unsigned long)&sym, __kstrtab_##sym }
#define __MODULE_STRING(x) __stringify(x)
#define __unsafe(mod)							     \
do {									     \
	if (mod && !(mod)->unsafe) {					     \
		printk(KERN_WARNING					     \
		       "Module %s cannot be unloaded due to unsafe usage in" \
		       " %s:%u\n", (mod)->name, "__FILE__", "__LINE__");	     \
		(mod)->unsafe = 1;					     \
	}								     \
} while(0)
#define module_name(mod)			\
({						\
	struct module *__mod = (mod);		\
	__mod ? __mod->name : "kernel";		\
})
#define module_put_and_exit(code) __module_put_and_exit(THIS_MODULE, code);
#define symbol_get(x) ((typeof(&x))(__symbol_get(MODULE_SYMBOL_PREFIX #x)))
#define symbol_put(x) __symbol_put(MODULE_SYMBOL_PREFIX #x)
#define symbol_put_addr(p) do { } while(0)
#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)
#define MODULE_PARAM_PREFIX 

#define __MODULE_INFO(tag, name, info)					  \
static const char __module_cat(name,"__LINE__")[]				  \
  __attribute_used__							  \
  __attribute__((section(".modinfo"),unused)) = __stringify(tag) "=" info
#define __MODULE_PARM_TYPE(name, _type)					  \
  __MODULE_INFO(parmtype, name##type, #name ":" _type)

#define __module_cat(a,b) ___module_cat(a,b)
#define __module_param_call(prefix, name, set, get, arg, perm)		\
				\
	static int __param_perm_check_##name __attribute__((unused)) =	\
	BUILD_BUG_ON_ZERO((perm) < 0 || (perm) > 0777 || ((perm) & 2));	\
	static char __param_str_##name[] = prefix #name;		\
	static struct kernel_param const __param_##name			\
	__attribute_used__						\
    __attribute__ ((unused,__section__ ("__param"),aligned(sizeof(void *)))) \
	= { __param_str_##name, perm, set, get, arg }
#define __param_check(name, p, type) \
	static inline type *__check_##name(void) { return(p); }
#define module_param(name, type, perm)				\
	module_param_named(name, name, type, perm)
#define module_param_array(name, type, nump, perm)		\
	module_param_array_named(name, name, type, nump, perm)
#define module_param_array_named(name, array, type, nump, perm)		\
	static struct kparam_array __param_arr_##name			\
	= { ARRAY_SIZE(array), nump, param_set_##type, param_get_##type,\
	    sizeof(array[0]), array };					\
	module_param_call(name, param_array_set, param_array_get, 	\
			  &__param_arr_##name, perm);			\
	__MODULE_PARM_TYPE(name, "array of " #type)
#define module_param_call(name, set, get, arg, perm)			      \
	__module_param_call(MODULE_PARAM_PREFIX, name, set, get, arg, perm)
#define module_param_named(name, value, type, perm)			   \
	param_check_##type(name, &(value));				   \
	module_param_call(name, param_set_##type, param_get_##type, &value, perm); \
	__MODULE_PARM_TYPE(name, #type)
#define module_param_string(name, string, len, perm)			\
	static struct kparam_string __param_string_##name		\
		= { len, string };					\
	module_param_call(name, param_set_copystring, param_get_string,	\
		   &__param_string_##name, perm);			\
	__MODULE_PARM_TYPE(name, "string")
#define param_check_bool(name, p) __param_check(name, p, int)
#define param_check_byte(name, p) __param_check(name, p, unsigned char)
#define param_check_charp(name, p) __param_check(name, p, char *)
#define param_check_int(name, p) __param_check(name, p, int)
#define param_check_invbool(name, p) __param_check(name, p, int)
#define param_check_long(name, p) __param_check(name, p, long)
#define param_check_short(name, p) __param_check(name, p, short)
#define param_check_uint(name, p) __param_check(name, p, unsigned int)
#define param_check_ulong(name, p) __param_check(name, p, unsigned long)
#define param_check_ushort(name, p) __param_check(name, p, unsigned short)
#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#define NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define NIP6_SEQFMT "%04x%04x%04x%04x%04x%04x%04x%04x"
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NUMA_BUILD 1

#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#define __FUNCTION__ (__func__)
#define abs(x) ({				\
		int __x = (x);			\
		(__x < 0) ? -__x : __x;		\
	})
#define console_loglevel (console_printk[0])
#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})
#define default_console_loglevel (console_printk[3])
#define default_message_loglevel (console_printk[1])
#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
# define might_resched() cond_resched()
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__"); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define minimum_console_loglevel (console_printk[2])
#define pr_debug(fmt,arg...) \
	printk(KERN_DEBUG fmt,##arg)
#define pr_info(fmt,arg...) \
	printk(KERN_INFO fmt,##arg)
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})
#define typecheck_fn(type,function) \
({	typeof(type) __tmp = function; \
	(void)__tmp; \
})

#define ilog2(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		(n) < 1 ? ____ilog2_NaN() :	\
		(n) & (1ULL << 63) ? 63 :	\
		(n) & (1ULL << 62) ? 62 :	\
		(n) & (1ULL << 61) ? 61 :	\
		(n) & (1ULL << 60) ? 60 :	\
		(n) & (1ULL << 59) ? 59 :	\
		(n) & (1ULL << 58) ? 58 :	\
		(n) & (1ULL << 57) ? 57 :	\
		(n) & (1ULL << 56) ? 56 :	\
		(n) & (1ULL << 55) ? 55 :	\
		(n) & (1ULL << 54) ? 54 :	\
		(n) & (1ULL << 53) ? 53 :	\
		(n) & (1ULL << 52) ? 52 :	\
		(n) & (1ULL << 51) ? 51 :	\
		(n) & (1ULL << 50) ? 50 :	\
		(n) & (1ULL << 49) ? 49 :	\
		(n) & (1ULL << 48) ? 48 :	\
		(n) & (1ULL << 47) ? 47 :	\
		(n) & (1ULL << 46) ? 46 :	\
		(n) & (1ULL << 45) ? 45 :	\
		(n) & (1ULL << 44) ? 44 :	\
		(n) & (1ULL << 43) ? 43 :	\
		(n) & (1ULL << 42) ? 42 :	\
		(n) & (1ULL << 41) ? 41 :	\
		(n) & (1ULL << 40) ? 40 :	\
		(n) & (1ULL << 39) ? 39 :	\
		(n) & (1ULL << 38) ? 38 :	\
		(n) & (1ULL << 37) ? 37 :	\
		(n) & (1ULL << 36) ? 36 :	\
		(n) & (1ULL << 35) ? 35 :	\
		(n) & (1ULL << 34) ? 34 :	\
		(n) & (1ULL << 33) ? 33 :	\
		(n) & (1ULL << 32) ? 32 :	\
		(n) & (1ULL << 31) ? 31 :	\
		(n) & (1ULL << 30) ? 30 :	\
		(n) & (1ULL << 29) ? 29 :	\
		(n) & (1ULL << 28) ? 28 :	\
		(n) & (1ULL << 27) ? 27 :	\
		(n) & (1ULL << 26) ? 26 :	\
		(n) & (1ULL << 25) ? 25 :	\
		(n) & (1ULL << 24) ? 24 :	\
		(n) & (1ULL << 23) ? 23 :	\
		(n) & (1ULL << 22) ? 22 :	\
		(n) & (1ULL << 21) ? 21 :	\
		(n) & (1ULL << 20) ? 20 :	\
		(n) & (1ULL << 19) ? 19 :	\
		(n) & (1ULL << 18) ? 18 :	\
		(n) & (1ULL << 17) ? 17 :	\
		(n) & (1ULL << 16) ? 16 :	\
		(n) & (1ULL << 15) ? 15 :	\
		(n) & (1ULL << 14) ? 14 :	\
		(n) & (1ULL << 13) ? 13 :	\
		(n) & (1ULL << 12) ? 12 :	\
		(n) & (1ULL << 11) ? 11 :	\
		(n) & (1ULL << 10) ? 10 :	\
		(n) & (1ULL <<  9) ?  9 :	\
		(n) & (1ULL <<  8) ?  8 :	\
		(n) & (1ULL <<  7) ?  7 :	\
		(n) & (1ULL <<  6) ?  6 :	\
		(n) & (1ULL <<  5) ?  5 :	\
		(n) & (1ULL <<  4) ?  4 :	\
		(n) & (1ULL <<  3) ?  3 :	\
		(n) & (1ULL <<  2) ?  2 :	\
		(n) & (1ULL <<  1) ?  1 :	\
		(n) & (1ULL <<  0) ?  0 :	\
		____ilog2_NaN()			\
				   ) :		\
	(sizeof(n) <= 4) ?			\
	__ilog2_u32(n) :			\
	__ilog2_u64(n)				\
 )
#define roundup_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		(n == 1) ? 0 :			\
		(1UL << (ilog2((n) - 1) + 1))	\
				   ) :		\
	__roundup_pow_of_two(n)			\
 )

#define ALIGN_STR __ALIGN_STR
#define ATTRIB_NORET  __attribute__((noreturn))
#define CPP_ASMLINKAGE extern "C"
#define END(name) \
  .size name, .-name
#define ENDPROC(name) \
  .type name, @function; \
  END(name)
#define ENTRY(name) \
  .globl name; \
  ALIGN; \
  name:
#define FASTCALL(x)	x
#define KPROBE_END(name) \
  END(name);		 \
  .popsection
#define KPROBE_ENTRY(name) \
  .pushsection .kprobes.text, "ax"; \
  ENTRY(name)
#define NORET_AND     noreturn,
#define NORET_TYPE    

#define asmlinkage CPP_ASMLINKAGE

# define prevent_tail_call(ret) do { } while (0)

#define __stringify(x)		__stringify_1(x)
#define __stringify_1(x)	#x

#define __cpuexit __exit


#define __cpuinitdata __initdata
#define __define_initcall(level,fn,id) \
	static initcall_t __initcall_##fn##id __attribute_used__ \
	__attribute__((__section__(".initcall" level ".init"))) = fn
#define __devexit __exit
#define __devexit_p(x) x
#define __devexitdata __exitdata
#define __devinit __init
#define __devinitdata __initdata
#define __exit_p(x) x
#define __exitcall(fn) \
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __init_or_module __init
#define __initcall(fn) device_initcall(fn)
#define __initdata_or_module __initdata
#define __memexit __exit


#define __meminitdata __initdata
#define __nosavedata __attribute__ ((__section__ (".data.nosave")))
#define __obsolete_setup(str)					\
	__setup_null_param(str, "__LINE__")
#define __setup(str, fn)					\
	__setup_param(str, fn, fn, 0)
#define __setup_null_param(str, unique_id)			\
	__setup_param(str, unique_id, NULL, 0)
#define __setup_param(str, unique_id, fn, early)			\
	static char __setup_str_##unique_id[] __initdata = str;	\
	static struct obs_kernel_param __setup_##unique_id	\
		__attribute_used__				\
		__attribute__((__section__(".init.setup")))	\
		__attribute__((aligned((sizeof(long)))))	\
		= { __setup_str_##unique_id, fn, early }
#define arch_initcall(fn)		__define_initcall("3",fn,3)
#define arch_initcall_sync(fn)		__define_initcall("3s",fn,3s)
#define console_initcall(fn) \
	static initcall_t __initcall_##fn \
	__attribute_used__ __attribute__((__section__(".con_initcall.init")))=fn
#define core_initcall(fn)		__define_initcall("1",fn,1)
#define core_initcall_sync(fn)		__define_initcall("1s",fn,1s)
#define device_initcall(fn)		__define_initcall("6",fn,6)
#define device_initcall_sync(fn)	__define_initcall("6s",fn,6s)
#define early_param(str, fn)					\
	__setup_param(str, fn, fn, 1)
#define fs_initcall(fn)			__define_initcall("5",fn,5)
#define fs_initcall_sync(fn)		__define_initcall("5s",fn,5s)
#define late_initcall(fn)		__define_initcall("7",fn,7)
#define late_initcall_sync(fn)		__define_initcall("7s",fn,7s)
#define module_exit(x)	__exitcall(x);
#define module_init(x)	__initcall(x);
#define postcore_initcall(fn)		__define_initcall("2",fn,2)
#define postcore_initcall_sync(fn)	__define_initcall("2s",fn,2s)
#define pure_initcall(fn)		__define_initcall("0",fn,1)
#define rootfs_initcall(fn)		__define_initcall("rootfs",fn,rootfs)
#define security_initcall(fn) \
	static initcall_t __initcall_##fn \
	__attribute_used__ __attribute__((__section__(".security_initcall.init"))) = fn
#define subsys_initcall(fn)		__define_initcall("4",fn,4)
#define subsys_initcall_sync(fn)	__define_initcall("4s",fn,4s)

#define decl_subsys(_name,_type,_uevent_ops) \
struct subsystem _name##_subsys = { \
	.kset = { \
		.kobj = { .name = __stringify(_name) }, \
		.ktype = _type, \
		.uevent_ops =_uevent_ops, \
	} \
}
#define decl_subsys_name(_varname,_name,_type,_uevent_ops) \
struct subsystem _varname##_subsys = { \
	.kset = { \
		.kobj = { .name = __stringify(_name) }, \
		.ktype = _type, \
		.uevent_ops =_uevent_ops, \
	} \
}
#define kobj_set_kset_s(obj,subsys) \
	(obj)->kobj.kset = &(subsys).kset
#define kset_set_kset_s(obj,subsys) \
	(obj)->kset.kobj.kset = &(subsys).kset
#define set_kset_name(str)	.kset = { .kobj = { .name = str } }
#define subsys_set_kset(obj,_subsys) \
	(obj)->subsys.kset.kobj.kset = &(_subsys).kset
#define DECLARE_WAITQUEUE(name, tsk)					\
	wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk)
#define DECLARE_WAIT_QUEUE_HEAD(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INITIALIZER(name)
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INIT_ONSTACK(name)
#define DEFINE_WAIT(name)						\
	wait_queue_t name = {						\
		.private	= current,				\
		.func		= autoremove_wake_function,		\
		.task_list	= LIST_HEAD_INIT((name).task_list),	\
	}
#define DEFINE_WAIT_BIT(name, word, bit)				\
	struct wait_bit_queue name = {					\
		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),		\
		.wait	= {						\
			.private	= current,			\
			.func		= wake_bit_function,		\
			.task_list	=				\
				LIST_HEAD_INIT((name).wait.task_list),	\
		},							\
	}

#define __WAITQUEUE_INITIALIZER(name, tsk) {				\
	.private	= tsk,						\
	.func		= default_wake_function,			\
	.task_list	= { NULL, NULL } }
#define __WAIT_BIT_KEY_INITIALIZER(word, bit)				\
	{ .flags = word, .bit_nr = bit, }
#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),		\
	.task_list	= { &(name).task_list, &(name).task_list } }
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
#define __wait_event(wq, condition) 					\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		schedule();						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_interruptible(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_interruptible_exclusive(wq, condition, ret)	\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait_exclusive(&wq, &__wait,			\
					TASK_INTERRUPTIBLE);		\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_timeout(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		ret = schedule_timeout(ret);				\
		if (!ret)						\
			break;						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define init_wait(wait)							\
	do {								\
		(wait)->private = current;				\
		(wait)->func = autoremove_wake_function;		\
		INIT_LIST_HEAD(&(wait)->task_list);			\
	} while (0)
#define is_sync_wait(wait)	(!(wait) || ((wait)->private))
#define wait_event(wq, condition) 					\
do {									\
	if (condition)	 						\
		break;							\
	__wait_event(wq, condition);					\
} while (0)
#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible(wq, condition, __ret);	\
	__ret;								\
})
#define wait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible_exclusive(wq, condition, __ret);\
	__ret;								\
})
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout(wq, condition, __ret);		\
	__ret;								\
})
#define wake_up(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_sync(x)   __wake_up_sync((x),TASK_INTERRUPTIBLE, 1)
#define wake_up_nr(x, nr)		__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, nr, NULL)
#define LOCK_SECTION_END                        \
        ".previous\n\t"
#define LOCK_SECTION_NAME ".text.lock."KBUILD_BASENAME
#define LOCK_SECTION_START(extra)               \
        ".subsection 1\n\t"                     \
        extra                                   \
        ".ifndef " LOCK_SECTION_NAME "\n\t"     \
        LOCK_SECTION_NAME ":\n\t"               \
        ".endif\n"

#define __lockfunc fastcall __attribute__((section(".spinlock.text")))
# define _raw_read_lock(rwlock)		__raw_read_lock(&(rwlock)->raw_lock)
# define _raw_read_trylock(rwlock)	__raw_read_trylock(&(rwlock)->raw_lock)
# define _raw_read_unlock(rwlock)	__raw_read_unlock(&(rwlock)->raw_lock)
# define _raw_spin_lock(lock)		__raw_spin_lock(&(lock)->raw_lock)
# define _raw_spin_lock_flags(lock, flags) \
		__raw_spin_lock_flags(&(lock)->raw_lock, *(flags))
# define _raw_spin_trylock(lock)	__raw_spin_trylock(&(lock)->raw_lock)
# define _raw_spin_unlock(lock)		__raw_spin_unlock(&(lock)->raw_lock)
# define _raw_write_lock(rwlock)	__raw_write_lock(&(rwlock)->raw_lock)
# define _raw_write_trylock(rwlock)	__raw_write_trylock(&(rwlock)->raw_lock)
# define _raw_write_unlock(rwlock)	__raw_write_unlock(&(rwlock)->raw_lock)
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
#define read_can_lock(rwlock)		__raw_read_can_lock(&(rwlock)->raw_lock)
#define read_lock(lock)			_read_lock(lock)
#define read_lock_bh(lock)		_read_lock_bh(lock)
#define read_lock_irq(lock)		_read_lock_irq(lock)
#define read_lock_irqsave(lock, flags)	flags = _read_lock_irqsave(lock)
#define read_trylock(lock)		__cond_lock(lock, _read_trylock(lock))
# define read_unlock(lock)		_read_unlock(lock)
#define read_unlock_bh(lock)		_read_unlock_bh(lock)
# define read_unlock_irq(lock)		_read_unlock_irq(lock)
#define read_unlock_irqrestore(lock, flags) \
					_read_unlock_irqrestore(lock, flags)
# define rwlock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__rwlock_init((lock), #lock, &__key);			\
} while (0)
#define spin_can_lock(lock)	(!spin_is_locked(lock))
#define spin_is_locked(lock)	__raw_spin_is_locked(&(lock)->raw_lock)
#define spin_lock(lock)			_spin_lock(lock)
#define spin_lock_bh(lock)		_spin_lock_bh(lock)
# define spin_lock_init(lock)					\
	do { *(lock) = SPIN_LOCK_UNLOCKED; } while (0)
#define spin_lock_irq(lock)		_spin_lock_irq(lock)
#define spin_lock_irqsave(lock, flags)	flags = _spin_lock_irqsave(lock)
#define spin_lock_irqsave_nested(lock, flags, subclass) \
	flags = _spin_lock_irqsave_nested(lock, subclass)
# define spin_lock_nested(lock, subclass) _spin_lock_nested(lock, subclass)
#define spin_trylock(lock)		__cond_lock(lock, _spin_trylock(lock))
#define spin_trylock_bh(lock)	__cond_lock(lock, _spin_trylock_bh(lock))
#define spin_trylock_irq(lock) \
({ \
	local_irq_disable(); \
	spin_trylock(lock) ? \
	1 : ({ local_irq_enable(); 0;  }); \
})
#define spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	spin_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
# define spin_unlock(lock)		_spin_unlock(lock)
#define spin_unlock_bh(lock)		_spin_unlock_bh(lock)
# define spin_unlock_irq(lock)		_spin_unlock_irq(lock)
#define spin_unlock_irqrestore(lock, flags) \
					_spin_unlock_irqrestore(lock, flags)
#define spin_unlock_wait(lock)	__raw_spin_unlock_wait(&(lock)->raw_lock)
#define write_can_lock(rwlock)		__raw_write_can_lock(&(rwlock)->raw_lock)
#define write_lock(lock)		_write_lock(lock)
#define write_lock_bh(lock)		_write_lock_bh(lock)
#define write_lock_irq(lock)		_write_lock_irq(lock)
#define write_lock_irqsave(lock, flags)	flags = _write_lock_irqsave(lock)
#define write_trylock(lock)		__cond_lock(lock, _write_trylock(lock))
# define write_unlock(lock)		_write_unlock(lock)
#define write_unlock_bh(lock)		_write_unlock_bh(lock)
# define write_unlock_irq(lock)		_write_unlock_irq(lock)
#define write_unlock_irqrestore(lock, flags) \
					_write_unlock_irqrestore(lock, flags)
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
# define RW_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }
# define SPIN_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }

#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __RAW_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }
# define __SPIN_LOCK_UNLOCKED(lockname)					\
	(spinlock_t)	{	.raw_lock = __RAW_SPIN_LOCK_UNLOCKED,	\
				.magic = SPINLOCK_MAGIC,		\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				SPIN_DEP_MAP_INIT(lockname) }
# define INIT_LOCKDEP
#define LOCKF_ENABLED_IRQS (LOCKF_ENABLED_HARDIRQS | LOCKF_ENABLED_SOFTIRQS)
#define LOCKF_ENABLED_IRQS_READ \
		(LOCKF_ENABLED_HARDIRQS_READ | LOCKF_ENABLED_SOFTIRQS_READ)
#define LOCKF_USED_IN_IRQ (LOCKF_USED_IN_HARDIRQ | LOCKF_USED_IN_SOFTIRQ)
#define LOCKF_USED_IN_IRQ_READ \
		(LOCKF_USED_IN_HARDIRQ_READ | LOCKF_USED_IN_SOFTIRQ_READ)

# define lock_acquire(l, s, t, r, c, i)		do { } while (0)
# define lock_release(l, n, i)			do { } while (0)
#define lockdep_depth(tsk)	((tsk)->lockdep_depth)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_info()				do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key, sub)	do { (void)(key); } while (0)
# define lockdep_reset()		do { debug_locks = 1; } while (0)
# define lockdep_set_class(lock, key)		do { (void)(key); } while (0)
# define lockdep_set_class_and_name(lock, key, name) \
		do { (void)(key); } while (0)
#define lockdep_set_class_and_subclass(lock, key, sub) \
		lockdep_init_map(&(lock)->dep_map, #key, key, sub)
#define lockdep_set_subclass(lock, sub)	\
		lockdep_init_map(&(lock)->dep_map, #lock, \
				 (lock)->dep_map.key, sub)
#  define mutex_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, i)
# define mutex_release(l, n, i)			lock_release(l, n, i)
#  define rwlock_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, i)
#  define rwlock_acquire_read(l, s, t, i)	lock_acquire(l, s, t, 2, 2, i)
# define rwlock_release(l, n, i)		lock_release(l, n, i)
#  define rwsem_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, i)
#  define rwsem_acquire_read(l, s, t, i)	lock_acquire(l, s, t, 1, 2, i)
# define rwsem_release(l, n, i)			lock_release(l, n, i)
#  define spin_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, i)
# define spin_release(l, n, i)			lock_release(l, n, i)

# define print_stack_trace(trace)			do { } while (0)
# define save_stack_trace(trace, task)			do { } while (0)
#define DEBUG_LOCKS_WARN_ON(c)						\
({									\
	int __ret = 0;							\
									\
	if (unlikely(c)) {						\
		if (debug_locks_off() && !debug_locks_silent)		\
			WARN_ON(1);					\
		__ret = 1;						\
	}								\
	__ret;								\
})
# define SMP_DEBUG_LOCKS_WARN_ON(c)			DEBUG_LOCKS_WARN_ON(c)
#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })

# define locking_selftest()	do { } while (0)


#define clear_need_resched()	clear_thread_flag(TIF_NEED_RESCHED)
#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define set_need_resched()	set_thread_flag(TIF_NEED_RESCHED)
#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)

# define add_preempt_count(val)	do { preempt_count() += (val); } while (0)
#define dec_preempt_count() sub_preempt_count(1)
#define inc_preempt_count() add_preempt_count(1)
#define preempt_check_resched() \
do { \
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED))) \
		preempt_schedule(); \
} while (0)
#define preempt_count()	(current_thread_info()->preempt_count)
#define preempt_disable() \
do { \
	inc_preempt_count(); \
	barrier(); \
} while (0)
#define preempt_enable() \
do { \
	preempt_enable_no_resched(); \
	barrier(); \
	preempt_check_resched(); \
} while (0)
#define preempt_enable_no_resched() \
do { \
	barrier(); \
	dec_preempt_count(); \
} while (0)
# define sub_preempt_count(val)	do { preempt_count() -= (val); } while (0)


# define down_read_nested(sem, subclass)		down_read(sem)
# define down_read_non_owner(sem)		down_read(sem)
# define down_write_nested(sem, subclass)	down_write(sem)
# define up_read_non_owner(sem)			up_read(sem)
#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

# define __RWSEM_DEP_MAP_INIT(lockname) , .dep_map = { .name = #lockname }
#define __RWSEM_INITIALIZER(name) \
{ 0, __SPIN_LOCK_UNLOCKED(name.wait_lock), LIST_HEAD_INIT((name).wait_list) \
  __RWSEM_DEP_MAP_INIT(name) }
#define init_rwsem(sem)						\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_rwsem((sem), #sem, &__key);			\
} while (0)
#define SYSFS_KOBJ_ATTR 	0x0004
#define SYSFS_KOBJ_LINK 	0x0020

#define __ATTR(_name,_mode,_show,_store) { \
	.attr = {.name = __stringify(_name), .mode = _mode, .owner = THIS_MODULE },	\
	.show	= _show,					\
	.store	= _store,					\
}
#define __ATTR_NULL { .attr = { .name = NULL } }
#define __ATTR_RO(_name) { \
	.attr	= { .name = __stringify(_name), .mode = 0444, .owner = THIS_MODULE },	\
	.show	= _name##_show,	\
}
#define attr_name(_attr) (_attr).attr.name
#define DT_RPATH 	15
#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)
#define ELF32_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x)	ELF_ST_TYPE(x)
#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x)	ELF_ST_TYPE(x)
#define ELF_CORE_EXTRA_NOTES_SIZE arch_notes_size()
#define ELF_CORE_WRITE_EXTRA_NOTES arch_write_notes(file)
#define ELF_OSABI ELFOSABI_NONE
#define ELF_ST_BIND(x)		((x) >> 4)
#define ELF_ST_TYPE(x)		(((unsigned int) x) & 0xf)
#define ET_CORE   4
#define ET_DYN    3
#define ET_EXEC   2
#define ET_HIPROC 0xffff
#define ET_LOPROC 0xff00
#define ET_NONE   0
#define ET_REL    1
#define NT_PRXFPREG     0x46e62b7f      
#define PT_DYNAMIC 2
#define PT_HIOS    0x6fffffff      
#define PT_HIPROC  0x7fffffff
#define PT_INTERP  3
#define PT_LOAD    1
#define PT_LOOS    0x60000000      
#define PT_LOPROC  0x70000000
#define PT_NOTE    4
#define PT_NULL    0
#define PT_PHDR    6
#define PT_SHLIB   5
#define PT_TLS     7               
#define STB_GLOBAL 1
#define STB_LOCAL  0
#define STB_WEAK   2
#define STT_COMMON  5
#define STT_FILE    4
#define STT_FUNC    2
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_SECTION 3
#define STT_TLS     6

# define elf_read_implies_exec(ex, have_pt_gnu_stack)	0

#define AT_BASE   7	
#define AT_CLKTCK 17	
#define AT_EGID   14	
#define AT_ENTRY  9	
#define AT_EUID   12	
#define AT_EXECFD 2	
#define AT_FLAGS  8	
#define AT_GID    13	
#define AT_HWCAP  16    
#define AT_IGNORE 1	
#define AT_NOTELF 10	
#define AT_NULL   0	
#define AT_PAGESZ 6	
#define AT_PHDR   3	
#define AT_PHENT  4	
#define AT_PHNUM  5	
#define AT_PLATFORM 15  
#define AT_SECURE 23   
#define AT_UID    11	
#define AT_VECTOR_SIZE  44 

#define KMOD_PATH_LEN 256

#define try_then_request_module(x, mod...) ((x) ?: (request_module(mod), (x)))
#define ERESTART_RESTARTBLOCK 516 

#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) ALIGN(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

#define S_IFBLK  0060000
#define S_IFCHR  0020000
#define S_IFDIR  0040000
#define S_IFIFO  0010000
#define S_IFMT  00170000
#define S_IFREG  0100000
#define S_IFSOCK 0140000
#define S_IRGRP 00040
#define S_IROTH 00004
#define S_IRUSR 00400
#define S_IRWXG 00070
#define S_IRWXO 00007
#define S_IRWXU 00700
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISGID  0002000
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)
#define S_ISUID  0004000
#define S_ISVTX  0001000
#define S_IWGRP 00020
#define S_IWOTH 00002
#define S_IWUSR 00200
#define S_IXGRP 00010
#define S_IXOTH 00001
#define S_IXUSR 00100

#define FD_CLR(fd,fdsetp)	__FD_CLR(fd,fdsetp)
#define FD_ISSET(fd,fdsetp)	__FD_ISSET(fd,fdsetp)
#define FD_SET(fd,fdsetp)	__FD_SET(fd,fdsetp)
#define FD_ZERO(fdsetp)		__FD_ZERO(fdsetp)


#define do_posix_clock_monotonic_gettime(ts) ktime_get_ts(ts)
#define timespec_valid(ts) \
	(((ts)->tv_sec >= 0) && (((unsigned long) (ts)->tv_nsec) < NSEC_PER_SEC))

#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }
#define COMPLETION_INITIALIZER_ONSTACK(work) \
	({ init_completion(&work); work; })
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
# define DECLARE_COMPLETION_ONSTACK(work) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK(work)
#define INIT_COMPLETION(x)	((x).done = 0)


#define check_mem_region(start,n)	__check_region(&iomem_resource, (start), (n))
#define devm_release_mem_region(start,n) \
	__devm_release_region(dev, &iomem_resource, (start), (n))
#define devm_release_region(start,n) \
	__devm_release_region(dev, &ioport_resource, (start), (n))
#define devm_request_mem_region(dev,start,n,name) \
	__devm_request_region(dev, &iomem_resource, (start), (n), (name))
#define devm_request_region(dev,start,n,name) \
	__devm_request_region(dev, &ioport_resource, (start), (n), (name))
#define release_mem_region(start,n)	__release_region(&iomem_resource, (start), (n))
#define release_region(start,n)	__release_region(&ioport_resource, (start), (n))
#define rename_region(region, newname) do { (region)->name = (newname); } while (0)
#define request_mem_region(start,n,name) __request_region(&iomem_resource, (start), (n), (name))
#define request_region(start,n,name)	__request_region(&ioport_resource, (start), (n), (name))
#define EISA_DEVICE_MODALIAS_FMT "eisa:s%s"
#define EISA_SIG_LEN   8

#define PCI_ANY_ID (~0)
#define HT_CAPTYPE_REMAPPING_64 0xA2	

#define  PCI_AGP_COMMAND_RQ_MASK 0xff000000  
#define  PCI_CAP_ID_EXP 	0x10	
#define  PCI_CAP_ID_SHPC 	0x0C	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 0x100	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM1 0x200
#define  PCI_COMMAND_INTX_DISABLE 0x400 
#define  PCI_COMMAND_VGA_PALETTE 0x20	
#define  PCI_COMMAND_WAIT 	0x80	
#define  PCI_ERR_CAP_FEP(x)	((x) & 31)	
#define  PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800  
#define  PCI_EXP_DEVCTL_RELAX_EN 0x0010 
#define  PCI_EXP_LNKCTL_CLKREQ_EN 0x100	
#define  PCI_EXP_TYPE_DOWNSTREAM 0x6	
#define  PCI_EXP_TYPE_PCI_BRIDGE 0x7	
#define  PCI_EXP_TYPE_ROOT_PORT 0x4	
#define PCI_EXT_CAP_ID(header)		(header & 0x0000ffff)
#define PCI_EXT_CAP_NEXT(header)	((header >> 20) & 0xffc)
#define PCI_EXT_CAP_VER(header)		((header >> 16) & 0xf)
#define  PCI_MEMORY_RANGE_TYPE_MASK 0x0fUL
#define  PCI_PM_CAP_RESERVED    0x0010  
#define  PCI_PREF_RANGE_TYPE_MASK 0x0fUL
#define  PCI_PWR_CAP_BUDGET(x)	((x) & 1)	
#define  PCI_PWR_DATA_BASE(x)	((x) & 0xff)	    
#define  PCI_PWR_DATA_PM_STATE(x) (((x) >> 13) & 3) 
#define  PCI_PWR_DATA_PM_SUB(x)	(((x) >> 10) & 7)   
#define  PCI_PWR_DATA_RAIL(x)	(((x) >> 18) & 7)   
#define  PCI_PWR_DATA_SCALE(x)	(((x) >> 8) & 3)    
#define  PCI_PWR_DATA_TYPE(x)	(((x) >> 15) & 7)   
#define  PCI_X_CMD_VERSION(x) 	(((x) >> 12) & 3) 


#define pcmcia_reset_card(p_dev, req) \
		pccard_reset_card(p_dev->socket)
#define DEV_NAME_LEN 32

#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
# define __DEBUG_MUTEX_INITIALIZER(lockname)
# define __DEP_MAP_MUTEX_INITIALIZER(lockname) \
		, .dep_map = { .name = #lockname }

#define __MUTEX_INITIALIZER(lockname) \
		{ .count = ATOMIC_INIT(1) \
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
# define mutex_destroy(mutex)				do { } while (0)
# define mutex_init(mutex) \
do {							\
	static struct lock_class_key __key;		\
							\
	__mutex_init((mutex), #mutex, &__key);		\
} while (0)
# define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)
#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;
#define GROUP_AT(gi, i) \
    ((gi)->blocks[(i)/NGROUPS_PER_BLOCK][(i)%NGROUPS_PER_BLOCK])
#define INIT_USER (&root_user)
# define MAX_LOCK_DEPTH 30UL
#define PF_LESS_THROTTLE 0x00100000	
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define TASK_COMM_LEN 16

# define __ARCH_WANT_UNLOCKED_CTXSW
#define __set_current_state(state_value)			\
	do { current->state = (state_value); } while (0)
#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define add_mm_counter(mm, member, value) atomic_long_add(value, &(mm)->_##member)
#define add_parent(p)		list_add_tail(&(p)->sibling,&(p)->parent->children)
#define batch_task(p)		(unlikely((p)->policy == SCHED_BATCH))
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define dec_mm_counter(mm, member) atomic_long_dec(&(mm)->_##member)
#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do
#define find_task_by_pid(nr)	find_task_by_pid_type(PIDTYPE_PID, nr)
#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )
#define get_group_info(group_info) do { \
	atomic_inc(&(group_info)->usage); \
} while (0)
#define get_mm_counter(mm, member) ((unsigned long)atomic_long_read(&(mm)->_##member))
#define get_mm_rss(mm)					\
	(get_mm_counter(mm, file_rss) + get_mm_counter(mm, anon_rss))
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)
#define has_rt_policy(p)	unlikely(is_rt_policy((p)->policy))
#define inc_mm_counter(mm, member) atomic_long_inc(&(mm)->_##member)
#define is_rt_policy(p)		((p) != SCHED_NORMAL && (p) != SCHED_BATCH)
# define need_lockbreak(lock) ((lock)->break_lock)
#define next_task(p)	list_entry(rcu_dereference((p)->tasks.next), struct task_struct, tasks)
#define put_group_info(group_info) do { \
	if (atomic_dec_and_test(&(group_info)->usage)) \
		groups_free(group_info); \
} while (0)
#define remove_parent(p)	list_del_init(&(p)->sibling)
# define rt_mutex_adjust_pi(p)		do { } while (0)
#define rt_prio(prio)		unlikely((prio) < MAX_RT_PRIO)
#define rt_task(p)		rt_prio((p)->prio)
#define sched_exec()   {}
#define set_current_state(state_value)		\
	set_mb(current->state, (state_value))
#define set_mm_counter(mm, member, value) atomic_long_set(&(mm)->_##member, value)
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_task_state(tsk, state_value)		\
	set_mb((tsk)->state, (state_value))
#define set_used_math() set_stopped_child_used_math(current)
#define task_stack_page(task) ((void*)((task)->thread_info))
#define task_thread_info(task) (task)->thread_info
#define test_sd_parent(sd, flag)	((sd->parent &&		\
					 (sd->parent->flags & flag)) ? 1 : 0)
#define thread_group_leader(p)	(p == p->group_leader)
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define update_hiwater_rss(mm)	do {			\
	unsigned long _rss = get_mm_rss(mm);		\
	if ((mm)->hiwater_rss < _rss)			\
		(mm)->hiwater_rss = _rss;		\
} while (0)
#define update_hiwater_vm(mm)	do {			\
	if ((mm)->hiwater_vm < (mm)->total_vm)		\
		(mm)->hiwater_vm = (mm)->total_vm;	\
} while (0)
#define used_math() tsk_used_math(current)
#define wait_task_inactive(p)	do { } while (0)
#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)
#define SYSDEV_ATTR(_name,_mode,_show,_store)		\
struct sysdev_attribute attr_##_name = _SYSDEV_ATTR(_name,_mode,_show,_store);
#define SYSDEV_CLASS_ATTR(_name,_mode,_show,_store) 		\
struct sysdev_class_attribute attr_##_name = { 			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
};
#define _SYSDEV_ATTR(_name,_mode,_show,_store)			\
{								\
	.attr = { .name = __stringify(_name), .mode = _mode,	\
		 .owner = THIS_MODULE },			\
	.show	= _show,					\
	.store	= _store,					\
}


#define aio_ring_avail(info, ring)	(((ring)->head + (info)->nr - 1 - (ring)->tail) % (info)->nr)
#define get_ioctx(kioctx) do {						\
	BUG_ON(atomic_read(&(kioctx)->users) <= 0);			\
	atomic_inc(&(kioctx)->users);					\
} while (0)
#define in_aio() !is_sync_wait(current->io_wait)
#define init_sync_kiocb(x, filp)			\
	do {						\
		struct task_struct *tsk = current;	\
		(x)->ki_flags = 0;			\
		(x)->ki_users = 1;			\
		(x)->ki_key = KIOCB_SYNC_KEY;		\
		(x)->ki_filp = (filp);			\
		(x)->ki_ctx = NULL;			\
		(x)->ki_cancel = NULL;			\
		(x)->ki_retry = NULL;			\
		(x)->ki_dtor = NULL;			\
		(x)->ki_obj.tsk = tsk;			\
		(x)->ki_user_data = 0;                  \
		init_wait((&(x)->ki_wait));             \
	} while (0)
#define io_wait_to_kiocb(wait) container_of(wait, struct kiocb, ki_wait)
#define is_sync_kiocb(iocb)	((iocb)->ki_key == KIOCB_SYNC_KEY)
#define kiocbClearCancelled(iocb)	clear_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbClearKicked(iocb)	clear_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbClearLocked(iocb)	clear_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbIsCancelled(iocb)	test_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbIsKicked(iocb)	test_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbIsLocked(iocb)	test_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbSetCancelled(iocb)	set_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbSetKicked(iocb)	set_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbSetLocked(iocb)	set_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbTryKick(iocb)	test_and_set_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbTryLock(iocb)	test_and_set_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define put_ioctx(kioctx) do {						\
	BUG_ON(atomic_read(&(kioctx)->users) <= 0);			\
	if (unlikely(atomic_dec_and_test(&(kioctx)->users))) 		\
		__put_ioctx(kioctx);					\
} while (0)
#define warn_if_async()							\
do {									\
	if (in_aio()) {							\
		printk(KERN_ERR "%s(%s:%d) called in async context!\n",	\
			__FUNCTION__, "__FILE__", "__LINE__");		\
		dump_stack();						\
	}								\
} while (0)
#define PADDED(x,y)	x, y


#define DECLARE_DELAYED_WORK(n, f)				\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f)
#define DECLARE_DELAYED_WORK_NAR(n, f)			\
	struct dwork_struct n = __DELAYED_WORK_INITIALIZER_NAR(n, f)
#define DECLARE_WORK(n, f)					\
	struct work_struct n = __WORK_INITIALIZER(n, f)
#define DECLARE_WORK_NAR(n, f)					\
	struct work_struct n = __WORK_INITIALIZER_NAR(n, f)
#define INIT_DELAYED_WORK(_work, _func)				\
	do {							\
		INIT_WORK(&(_work)->work, (_func));		\
		init_timer(&(_work)->timer);			\
	} while (0)
#define INIT_DELAYED_WORK_NAR(_work, _func)			\
	do {							\
		INIT_WORK_NAR(&(_work)->work, (_func));		\
		init_timer(&(_work)->timer);			\
	} while (0)
#define INIT_WORK(_work, _func)					\
	do {							\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT(0);	\
		INIT_LIST_HEAD(&(_work)->entry);		\
		PREPARE_WORK((_work), (_func));			\
	} while (0)
#define INIT_WORK_NAR(_work, _func)					\
	do {								\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT(1);	\
		INIT_LIST_HEAD(&(_work)->entry);			\
		PREPARE_WORK((_work), (_func));				\
	} while (0)
#define PREPARE_DELAYED_WORK(_work, _func)			\
	PREPARE_WORK(&(_work)->work, (_func))
#define PREPARE_WORK(_work, _func)				\
	do {							\
		(_work)->func = (_func);			\
	} while (0)
#define WORK_DATA_INIT(autorelease) \
	ATOMIC_LONG_INIT((autorelease) << WORK_STRUCT_NOAUTOREL)
#define WORK_STRUCT_FLAG_MASK (3UL)
#define WORK_STRUCT_NOAUTOREL 1		
#define WORK_STRUCT_PENDING 0		
#define WORK_STRUCT_WQ_DATA_MASK (~WORK_STRUCT_FLAG_MASK)

#define __DELAYED_WORK_INITIALIZER(n, f) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),		\
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
	}
#define __DELAYED_WORK_INITIALIZER_NAR(n, f) {			\
	.work = __WORK_INITIALIZER_NAR((n).work, (f)),		\
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
	}
#define __WORK_INITIALIZER(n, f) {				\
	.data = WORK_DATA_INIT(0),				\
        .entry	= { &(n).entry, &(n).entry },			\
	.func = (f),						\
	}
#define __WORK_INITIALIZER_NAR(n, f) {				\
	.data = WORK_DATA_INIT(1),				\
        .entry	= { &(n).entry, &(n).entry },			\
	.func = (f),						\
	}
#define create_freezeable_workqueue(name) __create_workqueue((name), 0, 1)
#define create_singlethread_workqueue(name) __create_workqueue((name), 1, 0)
#define create_workqueue(name) __create_workqueue((name), 0, 0)
#define delayed_work_pending(w) \
	work_pending(&(w)->work)
#define work_data_bits(work) ((unsigned long *)(&(work)->data))
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING, work_data_bits(work))
#define work_release(work) \
	clear_bit(WORK_STRUCT_PENDING, work_data_bits(work))
#define DEFINE_TIMER(_name, _function, _expires, _data)		\
	struct timer_list _name =				\
		TIMER_INITIALIZER(_function, _expires, _data)
#define TIMER_INITIALIZER(_function, _expires, _data) {		\
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
		.base = &boot_tvec_bases,			\
	}

#define del_singleshot_timer_sync(t) del_timer_sync(t)
# define del_timer_sync(t)		del_timer(t)
# define try_to_del_timer_sync(t)	del_timer(t)

#define ktime_add(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })
#define ktime_add_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 + (nsval) }; })
#define ktime_get_real_ts(ts)	getnstimeofday(ts)
#define ktime_sub(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })
#define ktime_to_ns(kt)			((kt).tv64)
#define ktime_to_timespec(kt)		ns_to_timespec((kt).tv64)
#define ktime_to_timeval(kt)		ns_to_timeval((kt).tv64)
#define ACTHZ (SH_DIV (CLOCK_TICK_RATE, LATCH, 8))
#define ACTHZ_HPET (SH_DIV (HPET_TICK_RATE, LATCH_HPET, 8))
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)	
#define LATCH_HPET ((HPET_TICK_RATE + HZ/2) / HZ)
#define MAX_JIFFY_OFFSET ((LONG_MAX >> 1)-1)
# define MAX_SEC_IN_JIFFIES \
	(long)((u64)((u64)MAX_JIFFY_OFFSET * TICK_NSEC) / NSEC_PER_SEC)
#define NSEC_CONVERSION ((unsigned long)((((u64)1 << NSEC_JIFFIE_SC) +\
                                        TICK_NSEC -1) / (u64)TICK_NSEC))
#define NSEC_JIFFIE_SC (SEC_JIFFIE_SC + 29)
#define SEC_CONVERSION ((unsigned long)((((u64)NSEC_PER_SEC << SEC_JIFFIE_SC) +\
                                TICK_NSEC -1) / (u64)TICK_NSEC))
#define SEC_JIFFIE_SC (31 - SHIFT_HZ)
#define SH_DIV(NOM,DEN,LSH) (   (((NOM) / (DEN)) << (LSH))              \
                             + ((((NOM) % (DEN)) << (LSH)) + (DEN) / 2) / (DEN))
#define TICK_NSEC (SH_DIV (1000000UL * 1000, ACTHZ, 8))
#define TICK_NSEC_HPET (SH_DIV(1000000UL * 1000, ACTHZ_HPET, 8))
#define TICK_USEC ((1000000UL + USER_HZ/2) / USER_HZ)
#define TICK_USEC_TO_NSEC(TUSEC) (SH_DIV (TUSEC * USER_HZ * 1000, ACTHZ, 8))
#define USEC_CONVERSION  \
                    ((unsigned long)((((u64)NSEC_PER_USEC << USEC_JIFFIE_SC) +\
                                        TICK_NSEC -1) / (u64)TICK_NSEC))
#define USEC_JIFFIE_SC (SEC_JIFFIE_SC + 19)
#define USEC_ROUND (u64)(((u64)1 << USEC_JIFFIE_SC) - 1)

#define __jiffy_data  __attribute__((section(".data")))
#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(b) - (long)(a) < 0))
#define time_after64(a,b)	\
	(typecheck(__u64, a) &&	\
	 typecheck(__u64, b) && \
	 ((__s64)(b) - (__s64)(a) < 0))
#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(a) - (long)(b) >= 0))
#define time_after_eq64(a,b)	\
	(typecheck(__u64, a) && \
	 typecheck(__u64, b) && \
	 ((__s64)(a) - (__s64)(b) >= 0))
#define time_before(a,b)	time_after(b,a)
#define time_before64(a,b)	time_after64(b,a)
#define time_before_eq(a,b)	time_after_eq(b,a)
#define time_before_eq64(a,b)	time_after_eq64(b,a)
#define MAXFREQ (512L << SHIFT_USEC)  
#define MAXFREQ_NSEC (512000L << SHIFT_NSEC) 
#define MAXPHASE 512000L        
#define MAXSEC 2048		
#define MINSEC 256		
#define NTP_INTERVAL_FREQ  (2)
#define NTP_INTERVAL_LENGTH (NSEC_PER_SEC/NTP_INTERVAL_FREQ)
#define SHIFT_NSEC 12		
#define SHIFT_UPDATE (SHIFT_HZ + 1) 
#define SHIFT_USEC 16		
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
    STA_PPSERROR | STA_CLOCKERR) 
#define TIME_SOURCE_CPU 0
#define TIME_SOURCE_FUNCTION 3
#define TIME_SOURCE_MMIO32 2
#define TIME_SOURCE_MMIO64 1

#define shift_right(x, s) ({	\
	__typeof__(x) __x = (x);	\
	__typeof__(s) __s = (s);	\
	__x < 0 ? -(-__x >> __s) : __x >> __s;	\
})

#define div_long_long_rem(dividend, divisor, remainder)	\
	do_div_llr((dividend), divisor, remainder)
#define HRTIMER_MAX_CLOCK_BASES 2

# define ktime_divns(kt, div)		(unsigned long)((kt).tv64 / (div))
#define RB_CLEAR_NODE(node)	(rb_set_parent(node, node))
#define RB_EMPTY_NODE(node)	(rb_parent(node) == node)
#define RB_EMPTY_ROOT(root)	((root)->rb_node == NULL)
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_black(r) rb_color(r)
#define rb_is_red(r)   (!rb_color(r))
#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)


#define DEFINE_RT_MUTEX(mutexname) \
	struct rt_mutex mutexname = __RT_MUTEX_INITIALIZER(mutexname)
# define INIT_RT_MUTEXES(tsk)						\
	.pi_waiters	= PLIST_HEAD_INIT(tsk.pi_waiters, tsk.pi_lock),	\
	INIT_RT_MUTEX_DEBUG(tsk)
# define __DEBUG_RT_MUTEX_INITIALIZER(mutexname) \
	, .name = #mutexname, .file = "__FILE__", .line = "__LINE__"

#define __RT_MUTEX_INITIALIZER(mutexname) \
	{ .wait_lock = __SPIN_LOCK_UNLOCKED(mutexname.wait_lock) \
	, .wait_list = PLIST_HEAD_INIT(mutexname.wait_list, mutexname.wait_lock) \
	, .owner = NULL \
	__DEBUG_RT_MUTEX_INITIALIZER(mutexname)}
# define rt_mutex_debug_check_no_locks_held(task)	do { } while (0)
# define rt_mutex_debug_task_free(t)			do { } while (0)
# define rt_mutex_init(mutex)			__rt_mutex_init(mutex, __FUNCTION__)
#define PLIST_HEAD_INIT(head, _lock)			\
{							\
	.prio_list = LIST_HEAD_INIT((head).prio_list),	\
	.node_list = LIST_HEAD_INIT((head).node_list),	\
	PLIST_HEAD_LOCK_INIT(&(_lock))			\
}
# define PLIST_HEAD_LOCK_INIT(_lock)	.lock = _lock
#define PLIST_NODE_INIT(node, __prio)			\
{							\
	.prio  = (__prio),				\
	.plist = PLIST_HEAD_INIT((node).plist, NULL),	\
}

# define plist_first_entry(head, type, member)	\
({ \
	WARN_ON(plist_head_empty(head)); \
	container_of(plist_first(head), type, member); \
})
#define plist_for_each(pos, head)	\
	 list_for_each_entry(pos, &(head)->node_list, plist.node_list)
#define plist_for_each_entry(pos, head, mem)	\
	 list_for_each_entry(pos, &(head)->node_list, mem.plist.node_list)
#define plist_for_each_entry_safe(pos, n, head, m)	\
	list_for_each_entry_safe(pos, n, &(head)->node_list, m.plist.node_list)
#define plist_for_each_safe(pos, n, head)	\
	 list_for_each_entry_safe(pos, n, &(head)->node_list, plist.node_list)
#define FUTEX_OP(op, oparg, cmp, cmparg) \
  (((op & 0xf) << 28) | ((cmp & 0xf) << 24)		\
   | ((oparg & 0xfff) << 12) | (cmparg & 0xfff))

#define INIT_RCU_HEAD(ptr) do { \
       (ptr)->next = NULL; (ptr)->func = NULL; \
} while (0)
#define RCU_HEAD(head) struct rcu_head head = RCU_HEAD_INIT
#define RCU_HEAD_INIT 	{ .next = NULL, .func = NULL }

#define rcu_assign_pointer(p, v)	({ \
						smp_wmb(); \
						(p) = (v); \
					})
#define rcu_dereference(p)     ({ \
				typeof(p) _________p1 = p; \
				smp_read_barrier_depends(); \
				(_________p1); \
				})
#define rcu_read_lock() \
	do { \
		preempt_disable(); \
		__acquire(RCU); \
	} while(0)
#define rcu_read_lock_bh() \
	do { \
		local_bh_disable(); \
		__acquire(RCU_BH); \
	} while(0)
#define rcu_read_unlock() \
	do { \
		__release(RCU); \
		preempt_enable(); \
	} while(0)
#define rcu_read_unlock_bh() \
	do { \
		__release(RCU_BH); \
		local_bh_enable(); \
	} while(0)
#define synchronize_sched() synchronize_rcu()
#define DEFINE_SEQLOCK(x) \
		seqlock_t x = __SEQLOCK_UNLOCKED(x)
#define SEQCNT_ZERO { 0 }
#define SEQLOCK_UNLOCKED \
		 __SEQLOCK_UNLOCKED(old_style_seqlock_init)

#define __SEQLOCK_UNLOCKED(lockname) \
		 { 0, __SPIN_LOCK_UNLOCKED(lockname) }
#define read_seqbegin_irqsave(lock, flags)				\
	({ local_irq_save(flags);   read_seqbegin(lock); })
#define read_seqretry_irqrestore(lock, iv, flags)			\
	({								\
		int ret = read_seqretry(lock, iv);			\
		local_irq_restore(flags);				\
		ret;							\
	})
#define seqcount_init(x)	do { *(x) = (seqcount_t) SEQCNT_ZERO; } while (0)
#define seqlock_init(x)					\
	do {						\
		(x)->sequence = 0;			\
		spin_lock_init(&(x)->lock);		\
	} while (0)
#define write_seqlock_bh(lock)						\
        do { local_bh_disable();    write_seqlock(lock); } while (0)
#define write_seqlock_irq(lock)						\
	do { local_irq_disable();   write_seqlock(lock); } while (0)
#define write_seqlock_irqsave(lock, flags)				\
	do { local_irq_save(flags); write_seqlock(lock); } while (0)
#define write_sequnlock_bh(lock)					\
	do { write_sequnlock(lock); local_bh_enable(); } while(0)
#define write_sequnlock_irq(lock)					\
	do { write_sequnlock(lock); local_irq_enable(); } while(0)
#define write_sequnlock_irqrestore(lock, flags)				\
	do { write_sequnlock(lock); local_irq_restore(flags); } while(0)
#define CPU_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(NR_CPUS)

#define any_online_cpu(mask) __any_online_cpu(&(mask))
#define cpu_clear(cpu, dst) __cpu_clear((cpu), &(dst))
#define cpu_isset(cpu, cpumask) test_bit((cpu), (cpumask).bits)
#define cpu_online(cpu)		cpu_isset((cpu), cpu_online_map)
#define cpu_possible(cpu)	cpu_isset((cpu), cpu_possible_map)
#define cpu_present(cpu)	cpu_isset((cpu), cpu_present_map)
#define cpu_remap(oldbit, old, new) \
		__cpu_remap((oldbit), &(old), &(new), NR_CPUS)
#define cpu_set(cpu, dst) __cpu_set((cpu), &(dst))
#define cpu_test_and_set(cpu, cpumask) __cpu_test_and_set((cpu), &(cpumask))
#define cpulist_parse(buf, dst) __cpulist_parse((buf), &(dst), NR_CPUS)
#define cpulist_scnprintf(buf, len, src) \
			__cpulist_scnprintf((buf), (len), &(src), NR_CPUS)
#define cpumask_of_cpu(cpu)						\
({									\
	typeof(_unused_cpumask_arg_) m;					\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL<<(cpu);					\
	} else {							\
		cpus_clear(m);						\
		cpu_set((cpu), m);					\
	}								\
	m;								\
})
#define cpumask_parse_user(ubuf, ulen, dst) \
			__cpumask_parse_user((ubuf), (ulen), &(dst), NR_CPUS)
#define cpumask_scnprintf(buf, len, src) \
			__cpumask_scnprintf((buf), (len), &(src), NR_CPUS)
#define cpus_addr(src) ((src).bits)
#define cpus_and(dst, src1, src2) __cpus_and(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_andnot(dst, src1, src2) \
				__cpus_andnot(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_clear(dst) __cpus_clear(&(dst), NR_CPUS)
#define cpus_complement(dst, src) __cpus_complement(&(dst), &(src), NR_CPUS)
#define cpus_empty(src) __cpus_empty(&(src), NR_CPUS)
#define cpus_equal(src1, src2) __cpus_equal(&(src1), &(src2), NR_CPUS)
#define cpus_full(cpumask) __cpus_full(&(cpumask), NR_CPUS)
#define cpus_intersects(src1, src2) __cpus_intersects(&(src1), &(src2), NR_CPUS)
#define cpus_or(dst, src1, src2) __cpus_or(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_remap(dst, src, old, new) \
		__cpus_remap(&(dst), &(src), &(old), &(new), NR_CPUS)
#define cpus_setall(dst) __cpus_setall(&(dst), NR_CPUS)
#define cpus_shift_left(dst, src, n) \
			__cpus_shift_left(&(dst), &(src), (n), NR_CPUS)
#define cpus_shift_right(dst, src, n) \
			__cpus_shift_right(&(dst), &(src), (n), NR_CPUS)
#define cpus_subset(src1, src2) __cpus_subset(&(src1), &(src2), NR_CPUS)
#define cpus_weight(cpumask) __cpus_weight(&(cpumask), NR_CPUS)
#define cpus_xor(dst, src1, src2) __cpus_xor(&(dst), &(src1), &(src2), NR_CPUS)
#define first_cpu(src) __first_cpu(&(src))
#define for_each_cpu_mask(cpu, mask)		\
	for ((cpu) = first_cpu(mask);		\
		(cpu) < NR_CPUS;		\
		(cpu) = next_cpu((cpu), (mask)))
#define for_each_online_cpu(cpu)  for_each_cpu_mask((cpu), cpu_online_map)
#define for_each_possible_cpu(cpu)  for_each_cpu_mask((cpu), cpu_possible_map)
#define for_each_present_cpu(cpu) for_each_cpu_mask((cpu), cpu_present_map)
#define next_cpu(n, src) __next_cpu((n), &(src))
#define num_online_cpus()	cpus_weight(cpu_online_map)
#define num_possible_cpus()	cpus_weight(cpu_possible_map)
#define num_present_cpus()	cpus_weight(cpu_present_map)
#define BITMAP_LAST_WORD_MASK(nbits)					\
(									\
	((nbits) % BITS_PER_LONG) ?					\
		(1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL		\
)


#define MIN_THREADS_LEFT_FOR_ROOT 4
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

#define PERCPU_ENOUGH_ROOM 32768

#define __alloc_percpu(size)	percpu_alloc_mask((size), GFP_KERNEL, \
						  cpu_possible_map)
#define __percpu_disguise(pdata) (struct percpu_data *)~(unsigned long)(pdata)
#define alloc_percpu(type)	(type *)__alloc_percpu(sizeof(type))
#define free_percpu(ptr)	percpu_free((ptr))
#define get_cpu_var(var) (*({				\
	extern int simple_identifier_##var(void);	\
	preempt_disable();				\
	&__get_cpu_var(var); }))
#define per_cpu_ptr(ptr, cpu)	percpu_ptr((ptr), (cpu))
#define percpu_alloc(size, gfp) percpu_alloc_mask((size), (gfp), cpu_online_map)
#define percpu_alloc_mask(size, gfp, mask) \
	__percpu_alloc_mask((size), (gfp), &(mask))
#define percpu_depopulate_mask(__pdata, mask) \
	__percpu_depopulate_mask((__pdata), &(mask))
#define percpu_populate_mask(__pdata, size, gfp, mask) \
	__percpu_populate_mask((__pdata), (size), (gfp), &(mask))
#define percpu_ptr(ptr, cpu)                              \
({                                                        \
        struct percpu_data *__p = __percpu_disguise(ptr); \
        (__typeof__(ptr))__p->ptrs[(cpu)];	          \
})
#define put_cpu_var(var) preempt_enable()
#define MSG_CALL_FUNCTION       0x0004  

#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define hard_smp_processor_id()			0
#define num_booting_cpus()			1
#define on_each_cpu(func,info,retry,wait)	\
	({					\
		local_irq_disable();		\
		func(info);			\
		local_irq_enable();		\
		0;				\
	})
#define put_cpu()		preempt_enable()
#define put_cpu_no_resched()	preempt_enable_no_resched()
#define raw_smp_processor_id()			0
#define smp_call_function(func,info,retry,wait)	(up_smp_call_function())
#define smp_prepare_boot_cpu()			do {} while (0)
# define smp_processor_id() debug_smp_processor_id()
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
			__builtin_return_address(0))
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, __builtin_return_address(0))
#define CACHE(x) \
		if (size <= x) \
			goto found; \
		else \
			i++;
#define GFP_LEVEL_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS| \
			__GFP_COLD|__GFP_NOWARN|__GFP_REPEAT| \
			__GFP_NOFAIL|__GFP_NORETRY|__GFP_NO_GROW|__GFP_COMP| \
			__GFP_NOMEMALLOC|__GFP_HARDWALL|__GFP_THISNODE)
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define __GFP_BITS_SHIFT 20	
#define __GFP_HARDWALL   ((__force gfp_t)0x20000u) 
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) 

#define __free_page(page) __free_pages((page), 0)
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA,(order))
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask),0)
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define free_page(addr) free_pages((addr),0)
#define DEF_PRIORITY 12
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define ZONES_SHIFT 0
#define ZONE_PADDING(name)	struct zone_padding name;

#define __ZONE_COUNT (			\
	  defined(CONFIG_ZONE_DMA)	\
	+ defined(CONFIG_ZONE_DMA32)	\
	+ 1				\
	+ defined(CONFIG_HIGHMEM)	\
)
#define early_pfn_in_nid(pfn, nid)	(early_pfn_to_nid(pfn) == (nid))
#define early_pfn_to_nid(nid)  (0UL)
#define early_pfn_valid(pfn)	pfn_valid(pfn)
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define numa_node_id()		(cpu_to_node(raw_smp_processor_id()))
#define pfn_to_nid(pfn)		(0)
#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)
#define zone_pcp(__z, __cpu) ((__z)->pageset[(__cpu)])

#define RECLAIM_DISTANCE 20
#define SD_ALLNODES_INIT (struct sched_domain) {	\
	.span			= CPU_MASK_NONE,	\
	.parent			= NULL,			\
	.child			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 64,			\
	.max_interval		= 64*num_online_cpus(),	\
	.busy_factor		= 128,			\
	.imbalance_pct		= 133,			\
	.cache_hot_time		= (10*1000000),		\
	.cache_nice_tries	= 1,			\
	.busy_idx		= 3,			\
	.idle_idx		= 3,			\
	.newidle_idx		= 0, 	\
	.wake_idx		= 0, 	\
	.forkexec_idx		= 0, 	\
	.flags			= SD_LOAD_BALANCE	\
				| SD_SERIALIZE,	\
	.last_balance		= jiffies,		\
	.balance_interval	= 64,			\
	.nr_balance_failed	= 0,			\
}
#define SD_CPU_INIT (struct sched_domain) {		\
	.span			= CPU_MASK_NONE,	\
	.parent			= NULL,			\
	.child			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 1,			\
	.max_interval		= 4,			\
	.busy_factor		= 64,			\
	.imbalance_pct		= 125,			\
	.cache_nice_tries	= 1,			\
	.busy_idx		= 2,			\
	.idle_idx		= 1,			\
	.newidle_idx		= 2,			\
	.wake_idx		= 1,			\
	.forkexec_idx		= 1,			\
	.flags			= SD_LOAD_BALANCE	\
				| SD_BALANCE_NEWIDLE	\
				| SD_BALANCE_EXEC	\
				| SD_WAKE_AFFINE	\
				| BALANCE_FOR_PKG_POWER,\
	.last_balance		= jiffies,		\
	.balance_interval	= 1,			\
	.nr_balance_failed	= 0,			\
}
#define SD_MC_INIT (struct sched_domain) {		\
	.span			= CPU_MASK_NONE,	\
	.parent			= NULL,			\
	.child			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 1,			\
	.max_interval		= 4,			\
	.busy_factor		= 64,			\
	.imbalance_pct		= 125,			\
	.cache_nice_tries	= 1,			\
	.busy_idx		= 2,			\
	.idle_idx		= 1,			\
	.newidle_idx		= 2,			\
	.wake_idx		= 1,			\
	.forkexec_idx		= 1,			\
	.flags			= SD_LOAD_BALANCE	\
				| SD_BALANCE_NEWIDLE	\
				| SD_BALANCE_EXEC	\
				| SD_WAKE_AFFINE	\
				| SD_SHARE_PKG_RESOURCES\
				| BALANCE_FOR_MC_POWER,	\
	.last_balance		= jiffies,		\
	.balance_interval	= 1,			\
	.nr_balance_failed	= 0,			\
}
#define SD_SIBLING_INIT (struct sched_domain) {		\
	.span			= CPU_MASK_NONE,	\
	.parent			= NULL,			\
	.child			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 1,			\
	.max_interval		= 2,			\
	.busy_factor		= 64,			\
	.imbalance_pct		= 110,			\
	.cache_nice_tries	= 0,			\
	.busy_idx		= 0,			\
	.idle_idx		= 0,			\
	.newidle_idx		= 1,			\
	.wake_idx		= 0,			\
	.forkexec_idx		= 0,			\
	.flags			= SD_LOAD_BALANCE	\
				| SD_BALANCE_NEWIDLE	\
				| SD_BALANCE_EXEC	\
				| SD_WAKE_AFFINE	\
				| SD_WAKE_IDLE		\
				| SD_SHARE_CPUPOWER,	\
	.last_balance		= jiffies,		\
	.balance_interval	= 1,			\
	.nr_balance_failed	= 0,			\
}

#define for_each_node_with_cpus(node)						\
	for_each_online_node(node)						\
		if (nr_cpus_node(node))
#define node_distance(from,to)	((from) == (to) ? LOCAL_DISTANCE : REMOTE_DISTANCE)
#define node_has_online_mem(nid) (1)
#define nr_cpus_node(node)							\
	({									\
		cpumask_t __tmp__;						\
		__tmp__ = node_to_cpumask(node);				\
		cpus_weight(__tmp__);						\
	})

#define arch_alloc_nodedata(nid)	generic_alloc_nodedata(nid)
#define arch_free_nodedata(pgdat)	generic_free_nodedata(pgdat)
#define generic_alloc_nodedata(nid)				\
({								\
	kzalloc(sizeof(pg_data_t), GFP_KERNEL);			\
})
#define generic_free_nodedata(pgdat)	kfree(pgdat)
#define ATOMIC_INIT_NOTIFIER_HEAD(name) do {	\
		spin_lock_init(&(name)->lock);	\
		(name)->head = NULL;		\
	} while (0)
#define ATOMIC_NOTIFIER_HEAD(name)				\
	struct atomic_notifier_head name =			\
		ATOMIC_NOTIFIER_INIT(name)
#define ATOMIC_NOTIFIER_INIT(name) {				\
		.lock = __SPIN_LOCK_UNLOCKED(name.lock),	\
		.head = NULL }
#define BLOCKING_INIT_NOTIFIER_HEAD(name) do {	\
		init_rwsem(&(name)->rwsem);	\
		(name)->head = NULL;		\
	} while (0)
#define BLOCKING_NOTIFIER_HEAD(name)				\
	struct blocking_notifier_head name =			\
		BLOCKING_NOTIFIER_INIT(name)
#define BLOCKING_NOTIFIER_INIT(name) {				\
		.rwsem = __RWSEM_INITIALIZER((name).rwsem),	\
		.head = NULL }
#define NETDEV_REGISTER 0x0005
#define RAW_INIT_NOTIFIER_HEAD(name) do {	\
		(name)->head = NULL;		\
	} while (0)
#define RAW_NOTIFIER_HEAD(name)					\
	struct raw_notifier_head name =				\
		RAW_NOTIFIER_INIT(name)
#define RAW_NOTIFIER_INIT(name)	{				\
		.head = NULL }

#define srcu_cleanup_notifier_head(name)	\
		cleanup_srcu_struct(&(name)->srcu);

#define srcu_barrier() barrier()
#define NODE_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(MAX_NUMNODES)

#define any_online_node(mask)			\
({						\
	int node;				\
	for_each_node_mask(node, (mask))	\
		if (node_online(node))		\
			break;			\
	node;					\
})
#define first_node(src) __first_node(&(src))
#define first_unset_node(mask) __first_unset_node(&(mask))
#define for_each_node(node)	   for_each_node_mask((node), node_possible_map)
#define for_each_node_mask(node, mask)			\
	for ((node) = first_node(mask);			\
		(node) < MAX_NUMNODES;			\
		(node) = next_node((node), (mask)))
#define for_each_online_node(node) for_each_node_mask((node), node_online_map)
#define next_node(n, src) __next_node((n), &(src))
#define next_online_node(nid)	next_node((nid), node_online_map)
#define node_clear(node, dst) __node_clear((node), &(dst))
#define node_isset(node, nodemask) test_bit((node), (nodemask).bits)
#define node_online(node)	node_isset((node), node_online_map)
#define node_possible(node)	node_isset((node), node_possible_map)
#define node_remap(oldbit, old, new) \
		__node_remap((oldbit), &(old), &(new), MAX_NUMNODES)
#define node_set(node, dst) __node_set((node), &(dst))
#define node_set_offline(node)	   clear_bit((node), node_online_map.bits)
#define node_set_online(node)	   set_bit((node), node_online_map.bits)
#define node_test_and_set(node, nodemask) \
			__node_test_and_set((node), &(nodemask))
#define nodelist_parse(buf, dst) __nodelist_parse((buf), &(dst), MAX_NUMNODES)
#define nodelist_scnprintf(buf, len, src) \
			__nodelist_scnprintf((buf), (len), &(src), MAX_NUMNODES)
#define nodemask_of_node(node)						\
({									\
	typeof(_unused_nodemask_arg_) m;				\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL<<(node);				\
	} else {							\
		nodes_clear(m);						\
		node_set((node), m);					\
	}								\
	m;								\
})
#define nodemask_parse_user(ubuf, ulen, dst) \
		__nodemask_parse_user((ubuf), (ulen), &(dst), MAX_NUMNODES)
#define nodemask_scnprintf(buf, len, src) \
			__nodemask_scnprintf((buf), (len), &(src), MAX_NUMNODES)
#define nodes_addr(src) ((src).bits)
#define nodes_and(dst, src1, src2) \
			__nodes_and(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_andnot(dst, src1, src2) \
			__nodes_andnot(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_clear(dst) __nodes_clear(&(dst), MAX_NUMNODES)
#define nodes_complement(dst, src) \
			__nodes_complement(&(dst), &(src), MAX_NUMNODES)
#define nodes_empty(src) __nodes_empty(&(src), MAX_NUMNODES)
#define nodes_equal(src1, src2) \
			__nodes_equal(&(src1), &(src2), MAX_NUMNODES)
#define nodes_full(nodemask) __nodes_full(&(nodemask), MAX_NUMNODES)
#define nodes_intersects(src1, src2) \
			__nodes_intersects(&(src1), &(src2), MAX_NUMNODES)
#define nodes_or(dst, src1, src2) \
			__nodes_or(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_remap(dst, src, old, new) \
		__nodes_remap(&(dst), &(src), &(old), &(new), MAX_NUMNODES)
#define nodes_setall(dst) __nodes_setall(&(dst), MAX_NUMNODES)
#define nodes_shift_left(dst, src, n) \
			__nodes_shift_left(&(dst), &(src), (n), MAX_NUMNODES)
#define nodes_shift_right(dst, src, n) \
			__nodes_shift_right(&(dst), &(src), (n), MAX_NUMNODES)
#define nodes_subset(src1, src2) \
			__nodes_subset(&(src1), &(src2), MAX_NUMNODES)
#define nodes_weight(nodemask) __nodes_weight(&(nodemask), MAX_NUMNODES)
#define nodes_xor(dst, src1, src2) \
			__nodes_xor(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define num_online_nodes()	nodes_weight(node_online_map)
#define num_possible_nodes()	nodes_weight(node_possible_map)
#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NODES_SHIFT     CONFIG_NODES_SHIFT

#define NR_SECCOMP_MODES 1

#define secure_computing(x) do { } while (0)

#define do_each_pid_task(pid, type, task)				\
	do {								\
		struct hlist_node *pos___;				\
		if (pid != NULL)					\
			hlist_for_each_entry_rcu((task), pos___,	\
				&pid->tasks[type], pids[type].node) {
#define while_each_pid_task(pid, type, task)				\
			}						\
	} while (0)
#define INIT_FS {				\
	.count		= ATOMIC_INIT(1),	\
	.lock		= RW_LOCK_UNLOCKED,	\
	.umask		= 0022, \
}

#define SECUREBITS_DEFAULT 0x00000000
#define SECURE_NOROOT            0
#define SECURE_NO_SETUID_FIXUP   2
#define _LINUX_SECUREBITS_H 1
#define issecure(X) ( (1 << (X+1)) & SECUREBITS_DEFAULT ? 	\
		      (1 << (X)) & SECUREBITS_DEFAULT :		\
		      (1 << (X)) & securebits )

#define _SIG_SET_BINOP(name, op)					\
static inline void name(sigset_t *r, const sigset_t *a, const sigset_t *b) \
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
	unsigned long a0, a1, a2, a3, b0, b1, b2, b3;			\
									\
	switch (_NSIG_WORDS) {						\
	    case 4:							\
		a3 = a->sig[3]; a2 = a->sig[2];				\
		b3 = b->sig[3]; b2 = b->sig[2];				\
		r->sig[3] = op(a3, b3);					\
		r->sig[2] = op(a2, b2);					\
	    case 2:							\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
	    case 1:							\
		a0 = a->sig[0]; b0 = b->sig[0];				\
		r->sig[0] = op(a0, b0);					\
		break;							\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}
#define _SIG_SET_OP(name, op)						\
static inline void name(sigset_t *set)					\
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
									\
	switch (_NSIG_WORDS) {						\
	    case 4: set->sig[3] = op(set->sig[3]);			\
		    set->sig[2] = op(set->sig[2]);			\
	    case 2: set->sig[1] = op(set->sig[1]);			\
	    case 1: set->sig[0] = op(set->sig[0]);			\
		    break;						\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}
#define _sig_and(x,y)	((x) & (y))
#define _sig_nand(x,y)	((x) & ~(y))
#define _sig_not(x)	(~(x))
#define _sig_or(x,y)	((x) | (y))
#define sigmask(sig)	(1UL << ((sig) - 1))
#define GETALL  13       
#define GETNCNT 14       
#define GETPID  11       
#define GETVAL  12       
#define GETZCNT 15       
#define SEMAEM  SEMVMX          
#define SEMMAP  SEMMNS          
#define SEMMNI  128             
#define SEMMNS  (SEMMNI*SEMMSL) 
#define SEMMNU  SEMMNS          
#define SEMMSL  250             
#define SEMOPM  32	        
#define SEMUME  SEMOPM          
#define SEMUSZ  20		
#define SEMVMX  32767           
#define SEM_INFO 19
#define SEM_STAT 18
#define SEM_UNDO        0x1000  
#define SETALL  17       
#define SETVAL  16       

#define INIT_IPC_NS(ns)		.ns		= &init_ipc_ns,
#define IPCMNI 32768  
#define IPC_64  0x0100  
#define IPC_CREAT  00001000   
#define IPC_DIPC 00010000  
#define IPC_EXCL   00002000   
#define IPC_INFO 3     
#define IPC_NOWAIT 00004000   
#define IPC_OLD 0	
#define IPC_OWN  00020000  
#define IPC_PRIVATE ((__kernel_key_t) 0)  
#define IPC_RMID 0     
#define IPC_SET  1     
#define IPC_STAT 2     

#define CAP_AUDIT_CONTROL    30
#define CAP_AUDIT_WRITE      29
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
#define CAP_EMPTY_SET       to_cap_t(0)
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_FS_MASK          0x1f
#define CAP_FULL_SET        to_cap_t(~0)
#define CAP_INIT_EFF_SET    to_cap_t(~0 & ~CAP_TO_MASK(CAP_SETPCAP))
#define CAP_INIT_INH_SET    to_cap_t(0)
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_KILL             5
#define CAP_LEASE            28
#define CAP_LINUX_IMMUTABLE  9
#define CAP_MKNOD            27
#define CAP_NET_ADMIN        12
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_RAW          13
#define CAP_SETGID           6
#define CAP_SETPCAP          8
#define CAP_SETUID           7
#define CAP_SYS_ADMIN        21
#define CAP_SYS_BOOT         22
#define CAP_SYS_CHROOT       18
#define CAP_SYS_MODULE       16
#define CAP_SYS_NICE         23
#define CAP_SYS_PACCT        20
#define CAP_SYS_PTRACE       19
#define CAP_SYS_RAWIO        17
#define CAP_SYS_RESOURCE     24
#define CAP_SYS_TIME         25
#define CAP_SYS_TTY_CONFIG   26
#define CAP_TO_MASK(x) (1 << (x))
#define _KERNEL_CAP_T_SIZE     (sizeof(kernel_cap_t))

#define _LINUX_CAPABILITY_VERSION  0x19980330
#define _USER_CAP_HEADER_SIZE  (2*sizeof(__u32))
#define cap_clear(c)         do { cap_t(c) =  0; } while(0)
#define cap_is_fs_cap(c)     (CAP_TO_MASK(c) & CAP_FS_MASK)
#define cap_isclear(c)       (!cap_t(c))
#define cap_issubset(a,set)  (!(cap_t(a) & ~cap_t(set)))
#define cap_lower(c, flag)   (cap_t(c) &= ~CAP_TO_MASK(flag))
#define cap_mask(c,mask)     do { cap_t(c) &= cap_t(mask); } while(0)
#define cap_raise(c, flag)   (cap_t(c) |=  CAP_TO_MASK(flag))
#define cap_raised(c, flag)  (cap_t(c) & CAP_TO_MASK(flag))
#define cap_set_full(c)      do { cap_t(c) = ~0; } while(0)
#define cap_t(x) (x).cap
#define to_cap_t(x) { x }
#define PCMCIA_DEVICE_CIS_MANF_CARD(manf, card, _cisfile) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_FAKE_CIS | \
			PCMCIA_DEV_ID_MATCH_MANF_ID| \
			PCMCIA_DEV_ID_MATCH_CARD_ID, \
	.manf_id = (manf), \
	.card_id = (card), \
	.cisfile = (_cisfile)}
#define PCMCIA_DEVICE_CIS_PROD_ID12(v1, v2, vh1, vh2, _cisfile) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_FAKE_CIS | \
			PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2, \
	.prod_id = { (v1), (v2), NULL, NULL }, \
	.prod_id_hash = { (vh1), (vh2), 0, 0 }, \
	.cisfile = (_cisfile)}
#define PCMCIA_DEVICE_CIS_PROD_ID123(v1, v2, v3, vh1, vh2, vh3, _cisfile) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_FAKE_CIS | \
			PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3, \
	.prod_id = { (v1), (v2), (v3), NULL },\
	.prod_id_hash = { (vh1), (vh2), (vh3), 0 }, \
	.cisfile = (_cisfile)}
#define PCMCIA_DEVICE_CIS_PROD_ID2(v2, vh2, _cisfile) { \
	.match_flags =  PCMCIA_DEV_ID_MATCH_FAKE_CIS | \
			PCMCIA_DEV_ID_MATCH_PROD_ID2, \
	.prod_id = { NULL, (v2), NULL, NULL },  \
	.prod_id_hash = { 0, (vh2), 0, 0 }, \
	.cisfile = (_cisfile)}
#define PCMCIA_DEVICE_FUNC_ID(func) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_FUNC_ID, \
	.func_id = (func), }
#define PCMCIA_DEVICE_MANF_CARD(manf, card) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_MANF_ID| \
			PCMCIA_DEV_ID_MATCH_CARD_ID, \
	.manf_id = (manf), \
	.card_id = (card), }
#define PCMCIA_DEVICE_MANF_CARD_PROD_ID1(manf, card, v1, vh1) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_MANF_ID| \
			PCMCIA_DEV_ID_MATCH_CARD_ID| \
			PCMCIA_DEV_ID_MATCH_PROD_ID1, \
	.manf_id = (manf), \
	.card_id = (card), \
	.prod_id = { (v1), NULL, NULL, NULL }, \
	.prod_id_hash = { (vh1), 0, 0, 0 }, }
#define PCMCIA_DEVICE_NULL { .match_flags = 0, }
#define PCMCIA_DEVICE_PROD_ID1(v1, vh1) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1, \
	.prod_id = { (v1), NULL, NULL, NULL }, \
	.prod_id_hash = { (vh1), 0, 0, 0 }, }
#define PCMCIA_DEVICE_PROD_ID12(v1, v2, vh1, vh2) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2, \
	.prod_id = { (v1), (v2), NULL, NULL }, \
	.prod_id_hash = { (vh1), (vh2), 0, 0 }, }
#define PCMCIA_DEVICE_PROD_ID123(v1, v2, v3, vh1, vh2, vh3) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3, \
	.prod_id = { (v1), (v2), (v3), NULL },\
	.prod_id_hash = { (vh1), (vh2), (vh3), 0 }, }
#define PCMCIA_DEVICE_PROD_ID1234(v1, v2, v3, v4, vh1, vh2, vh3, vh4) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3| \
			PCMCIA_DEV_ID_MATCH_PROD_ID4, \
	.prod_id = { (v1), (v2), (v3), (v4) }, \
	.prod_id_hash = { (vh1), (vh2), (vh3), (vh4) }, }
#define PCMCIA_DEVICE_PROD_ID124(v1, v2, v4, vh1, vh2, vh4) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_PROD_ID4, \
	.prod_id = { (v1), (v2), NULL, (v4) }, \
	.prod_id_hash = { (vh1), (vh2), 0, (vh4) }, }
#define PCMCIA_DEVICE_PROD_ID13(v1, v3, vh1, vh3) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3, \
	.prod_id = { (v1), NULL, (v3), NULL }, \
	.prod_id_hash = { (vh1), 0, (vh3), 0 }, }
#define PCMCIA_DEVICE_PROD_ID134(v1, v3, v4, vh1, vh3, vh4) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3| \
			PCMCIA_DEV_ID_MATCH_PROD_ID4, \
	.prod_id = { (v1), NULL, (v3), (v4) }, \
	.prod_id_hash = { (vh1), 0, (vh3), (vh4) }, }
#define PCMCIA_DEVICE_PROD_ID14(v1, v4, vh1, vh4) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID4, \
	.prod_id = { (v1), NULL, NULL, (v4) }, \
	.prod_id_hash = { (vh1), 0, 0, (vh4) }, }
#define PCMCIA_DEVICE_PROD_ID2(v2, vh2) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID2, \
	.prod_id = { NULL, (v2), NULL, NULL },  \
	.prod_id_hash = { 0, (vh2), 0, 0 }, }
#define PCMCIA_MFC_DEVICE_CIS_MANF_CARD(mfc, manf, card, _cisfile) { \
	.match_flags =  PCMCIA_DEV_ID_MATCH_FAKE_CIS | \
			PCMCIA_DEV_ID_MATCH_MANF_ID| \
			PCMCIA_DEV_ID_MATCH_CARD_ID| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.manf_id = (manf), \
	.card_id = (card), \
	.function = (mfc), \
	.cisfile = (_cisfile)}
#define PCMCIA_MFC_DEVICE_CIS_PROD_ID12(mfc, v1, v2, vh1, vh2, _cisfile) { \
	.match_flags =  PCMCIA_DEV_ID_MATCH_FAKE_CIS | \
			PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.prod_id = { (v1), (v2), NULL, NULL }, \
	.prod_id_hash = { (vh1), (vh2), 0, 0 }, \
	.function = (mfc), \
	.cisfile = (_cisfile)}
#define PCMCIA_MFC_DEVICE_CIS_PROD_ID4(mfc, v4, vh4, _cisfile) { \
	.match_flags =  PCMCIA_DEV_ID_MATCH_FAKE_CIS | \
			PCMCIA_DEV_ID_MATCH_PROD_ID4| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.prod_id = { NULL, NULL, NULL, (v4) }, \
	.prod_id_hash = { 0, 0, 0, (vh4) }, \
	.function = (mfc), \
	.cisfile = (_cisfile)}
#define PCMCIA_MFC_DEVICE_MANF_CARD(mfc, manf, card) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_MANF_ID| \
			PCMCIA_DEV_ID_MATCH_CARD_ID| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.manf_id = (manf), \
	.card_id = (card), \
	.function = (mfc), }
#define PCMCIA_MFC_DEVICE_PROD_ID1(mfc, v1, vh1) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.prod_id = { (v1), NULL, NULL, NULL }, \
	.prod_id_hash = { (vh1), 0, 0, 0 }, \
	.function = (mfc), }
#define PCMCIA_MFC_DEVICE_PROD_ID12(mfc, v1, v2, vh1, vh2) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.prod_id = { (v1), (v2), NULL, NULL }, \
	.prod_id_hash = { (vh1), (vh2), 0, 0 }, \
	.function = (mfc), }
#define PCMCIA_MFC_DEVICE_PROD_ID123(mfc, v1, v2, v3, vh1, vh2, vh3) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.prod_id = { (v1), (v2), (v3), NULL },\
	.prod_id_hash = { (vh1), (vh2), (vh3), 0 }, \
	.function = (mfc), }
#define PCMCIA_MFC_DEVICE_PROD_ID13(mfc, v1, v3, vh1, vh3) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.prod_id = { (v1), NULL, (v3), NULL }, \
	.prod_id_hash = { (vh1), 0, (vh3), 0 }, \
	.function = (mfc), }
#define PCMCIA_MFC_DEVICE_PROD_ID2(mfc, v2, vh2) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_FUNCTION, \
	.prod_id = { NULL, (v2), NULL, NULL },  \
	.prod_id_hash = { 0, (vh2), 0, 0 }, \
	.function = (mfc), }
#define PCMCIA_PFC_DEVICE_CIS_PROD_ID12(mfc, v1, v2, vh1, vh2, _cisfile) { \
	.match_flags =  PCMCIA_DEV_ID_MATCH_FAKE_CIS | \
			PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_DEVICE_NO, \
	.prod_id = { (v1), (v2), NULL, NULL }, \
	.prod_id_hash = { (vh1), (vh2), 0, 0 },\
	.device_no = (mfc), \
	.cisfile = (_cisfile)}
#define PCMCIA_PFC_DEVICE_MANF_CARD(mfc, manf, card) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_MANF_ID| \
			PCMCIA_DEV_ID_MATCH_CARD_ID| \
			PCMCIA_DEV_ID_MATCH_DEVICE_NO, \
	.manf_id = (manf), \
	.card_id = (card), \
	.device_no = (mfc), }
#define PCMCIA_PFC_DEVICE_PROD_ID1(mfc, v1, vh1) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_DEVICE_NO, \
	.prod_id = { (v1), NULL, NULL, NULL }, \
	.prod_id_hash = { (vh1), 0, 0, 0 }, \
	.device_no = (mfc), }
#define PCMCIA_PFC_DEVICE_PROD_ID12(mfc, v1, v2, vh1, vh2) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_DEVICE_NO, \
	.prod_id = { (v1), (v2), NULL, NULL }, \
	.prod_id_hash = { (vh1), (vh2), 0, 0 }, \
	.device_no = (mfc), }
#define PCMCIA_PFC_DEVICE_PROD_ID123(mfc, v1, v2, v3, vh1, vh2, vh3) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3| \
			PCMCIA_DEV_ID_MATCH_DEVICE_NO, \
	.prod_id = { (v1), (v2), (v3), NULL },\
	.prod_id_hash = { (vh1), (vh2), (vh3), 0 }, \
	.device_no = (mfc), }
#define PCMCIA_PFC_DEVICE_PROD_ID13(mfc, v1, v3, vh1, vh3) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID1| \
			PCMCIA_DEV_ID_MATCH_PROD_ID3| \
			PCMCIA_DEV_ID_MATCH_DEVICE_NO, \
	.prod_id = { (v1), NULL, (v3), NULL }, \
	.prod_id_hash = { (vh1), 0, (vh3), 0 }, \
	.device_no = (mfc), }
#define PCMCIA_PFC_DEVICE_PROD_ID2(mfc, v2, vh2) { \
	.match_flags = PCMCIA_DEV_ID_MATCH_PROD_ID2| \
			PCMCIA_DEV_ID_MATCH_DEVICE_NO, \
	.prod_id = { NULL, (v2), NULL, NULL },  \
	.prod_id_hash = { 0, (vh2), 0, 0 }, \
	.device_no = (mfc), }
#define MANFID_UNGERMANN 0x02c0



#define pcmcia_get_first_tuple(p_dev, tuple) \
		pccard_get_first_tuple(p_dev->socket, p_dev->func, tuple)
#define pcmcia_get_next_tuple(p_dev, tuple) \
		pccard_get_next_tuple(p_dev->socket, p_dev->func, tuple)
#define pcmcia_get_tuple_data(p_dev, tuple) \
		pccard_get_tuple_data(p_dev->socket, tuple)
#define pcmcia_parse_tuple(p_dev, tuple, parse) \
		pccard_parse_tuple(tuple, parse)
#define pcmcia_validate_cis(p_dev, info) \
		pccard_validate_cis(p_dev->socket, p_dev->func, info)
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)
#define MAX_STACK_ALLOC 832

#define BLKBSZGET  _IOR(0x12,112,size_t)
#define BLKBSZSET  _IOW(0x12,113,size_t)
#define BLKFLSBUF  _IO(0x12,97)	
#define BLKFRAGET  _IO(0x12,101)
#define BLKFRASET  _IO(0x12,100)
#define BLKGETSIZE _IO(0x12,96)	
#define BLKGETSIZE64 _IOR(0x12,114,size_t)	
#define BLKRAGET   _IO(0x12,99)	
#define BLKRASET   _IO(0x12,98)	
#define BLKROGET   _IO(0x12,94)	
#define BLKROSET   _IO(0x12,93)	
#define BLKRRPART  _IO(0x12,95)	
#define BLKSECTGET _IO(0x12,103)
#define BLKSECTSET _IO(0x12,102)
#define BLKSSZGET  _IO(0x12,104)
#define BLKTRACESETUP _IOWR(0x12,115,struct blk_user_trace_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)
#define BLOCK_SIZE_BITS 10
#define BMAP_IOCTL 1		
#define DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_close,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
};
#define FASYNC_MAGIC 0x4601
#define FIGETBSZ   _IO(0x00,2)	
#define FLOCK_VERIFY_READ  1
#define FLOCK_VERIFY_WRITE 2
#define FMODE_READ 1
#define FMODE_WRITE 2
#define FS_BINARY_MOUNTDATA 2
#define FS_REQUIRES_DEV 1 
#define HAVE_COMPAT_IOCTL 1
#define HAVE_UNLOCKED_IOCTL 1
#define INR_OPEN 1024		
#define INT_LIMIT(x)	(~((x)1 << (sizeof(x)*8 - 1)))
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)
#define IS_DEADDIR(inode)	((inode)->i_flags & S_DEAD)
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, MS_SYNCHRONOUS|MS_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_MANDLOCK(inode)	__IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode)   __IS_FLG(inode, MS_RDONLY|MS_NOATIME)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_POSIXACL(inode)	__IS_FLG(inode, MS_POSIXACL)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)
#define IS_RDONLY(inode) ((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_SYNC(inode)		(__IS_FLG(inode, MS_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)
#define MANDATORY_LOCK(inode) \
	(IS_MANDLOCK(inode) && ((inode)->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID)
#define MAX_LFS_FILESIZE 	0x7fffffffffffffffUL
#define MAY_APPEND 8
#define MAY_EXEC 1
#define MAY_READ 4
#define MAY_WRITE 2
#define MS_MGC_MSK 0xffff0000
#define MS_MGC_VAL 0xC0ED0000
#define NR_FILE  8192	
#define NR_OPEN (1024*1024)	
#define RA_FLAG_INCACHE 0x02	
#define RA_FLAG_MISS 0x01	
#define READ 0
#define READA 2		
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))
#define SWRITE 3	
#define S_BIAS (1<<30)
#define WRITE 1

#define __IS_FLG(inode,flg) ((inode)->i_sb->s_flags & (flg))

#define __getname()	kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define __putname(name) kmem_cache_free(names_cachep, (void *)(name))
#define bd_claim_by_disk(bdev, holder, disk)	bd_claim(bdev, holder)
#define bd_release_from_disk(bdev, disk)	bd_release(bdev)
#define bio_data_dir(bio)	((bio)->bi_rw & 1)
#define bio_rw(bio)		((bio)->bi_rw & (RW_MASK | RWA_MASK))
#define buffer_migrate_page NULL
#define file_count(x)	atomic_read(&(x)->f_count)
#define file_list_lock() spin_lock(&files_lock);
#define file_list_unlock() spin_unlock(&files_lock);
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
#define get_file(x)	atomic_inc(&(x)->f_count)
#define get_fs_excl() atomic_inc(&current->fs_excl)
#define has_fs_excl() atomic_read(&current->fs_excl)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define put_fs_excl() atomic_dec(&current->fs_excl)
#define putname(name)   __putname(name)
#define sb_entry(list)	list_entry((list), struct super_block, s_list)
#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))
#define vfs_check_frozen(sb, level) \
	wait_event((sb)->s_wait_unfrozen, ((sb)->s_frozen < (level)))
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

#define IS_GETLK(cmd)	(IS_GETLK32(cmd)  || IS_GETLK64(cmd))
#define IS_GETLK32(cmd)		((cmd) == F_GETLK)
#define IS_GETLK64(cmd)		((cmd) == F_GETLK64)
#define IS_SETLK(cmd)	(IS_SETLK32(cmd)  || IS_SETLK64(cmd))
#define IS_SETLK32(cmd)		((cmd) == F_SETLK)
#define IS_SETLK64(cmd)		((cmd) == F_SETLK64)
#define IS_SETLKW(cmd)	(IS_SETLKW32(cmd) || IS_SETLKW64(cmd))
#define IS_SETLKW32(cmd)	((cmd) == F_SETLKW)
#define IS_SETLKW64(cmd)	((cmd) == F_SETLKW64)

#define force_o_largefile() (BITS_PER_LONG != 32)


#define RPC_MAX_AUTH_SIZE (400)
#define RPC_MAX_HEADER_WITH_AUTH \
	(RPC_CALLHDRSIZE + 2*(2+RPC_MAX_AUTH_SIZE/4))
#define RPC_VERSION 2

#define DQF_INFO_DIRTY (1 << DQF_INFO_DIRTY_B)	
#define DQF_INFO_DIRTY_B 16
#define DQF_MASK 0xffff		
#define DQUOT_DEL_ALLOC max(V1_DEL_ALLOC, V2_DEL_ALLOC)
#define DQUOT_DEL_REWRITE max(V1_DEL_REWRITE, V2_DEL_REWRITE)
#define DQUOT_INIT_ALLOC max(V1_INIT_ALLOC, V2_INIT_ALLOC)
#define DQUOT_INIT_REWRITE max(V1_INIT_REWRITE, V2_INIT_REWRITE)
#define GRPQUOTA  1		
#define INITQFNAMES { \
	"user",     \
	"group",    \
	"undefined", \
};
#define INIT_QUOTA_MODULE_NAMES {\
	{QFMT_VFS_OLD, "quota_v1",\
	{QFMT_VFS_V0, "quota_v2",\
	{0, NULL}}
#define MAXQUOTAS 2
#define NODQUOT (struct dquot *)NULL
#define NO_QUOTA          1
#define QCMD(cmd, type)  (((cmd) << SUBCMDSHIFT) | ((type) & SUBCMDMASK))
#define QUOTABLOCK_BITS 10
#define QUOTABLOCK_SIZE (1 << QUOTABLOCK_BITS)
#define QUOTA_OK          0
#define Q_GETFMT   0x800004	
#define Q_GETINFO  0x800005	
#define Q_GETQUOTA 0x800007	
#define Q_QUOTAOFF 0x800003	
#define Q_QUOTAON  0x800002	
#define Q_SETINFO  0x800006	
#define Q_SETQUOTA 0x800008	
#define Q_SYNC     0x800001	
#define SUBCMDMASK  0x00ff
#define SUBCMDSHIFT 8
#define USRQUOTA  0		

#define dquot_dirty(dquot) test_bit(DQ_MOD_B, &(dquot)->dq_flags)
#define info_any_dirty(info) (info_dirty(info) || info_any_dquot_dirty(info))
#define info_any_dquot_dirty(info) (!list_empty(&(info)->dqi_dirty_list))
#define info_dirty(info) test_bit(DQF_INFO_DIRTY_B, &(info)->dqi_flags)
#define kb2qb(x) ((x) >> (QUOTABLOCK_BITS-10))
#define qb2kb(x) ((x) << (QUOTABLOCK_BITS-10))
#define sb_any_quota_enabled(sb) (sb_has_quota_enabled(sb, USRQUOTA) | \
				  sb_has_quota_enabled(sb, GRPQUOTA))
#define sb_dqinfo(sb, type) (sb_dqopt(sb)->info+(type))
#define sb_dqopt(sb) (&(sb)->s_dquot)
#define sb_has_quota_enabled(sb, type) ((type)==USRQUOTA ? \
	(sb_dqopt(sb)->flags & DQUOT_USR_ENABLED) : (sb_dqopt(sb)->flags & DQUOT_GRP_ENABLED))
#define toqb(x) (((x) + QUOTABLOCK_SIZE - 1) >> QUOTABLOCK_BITS)
#define QFMT_VFS_V0 2
#define V2_DEL_ALLOC 0
#define V2_DEL_REWRITE 6
#define V2_INIT_ALLOC 4
#define V2_INIT_REWRITE 2

#define QFMT_VFS_OLD 1
#define V1_DEL_ALLOC 0
#define V1_DEL_REWRITE 2
#define V1_DQF_RSQUASH 1
#define V1_INIT_ALLOC 1
#define V1_INIT_REWRITE 1

#define FS_DQ_BHARD 	(1<<3)
#define FS_DQ_RTBTIMER 	(1<<8)
#define XQM_CMD(x)	(('X'<<8)+(x))	
#define XQM_COMMAND(x)	(((x) & (0xff<<8)) == ('X'<<8))	

#define INIT_PRIO_TREE_ITER(ptr)	\
do {					\
	(ptr)->cur = NULL;		\
	(ptr)->mask = 0UL;		\
	(ptr)->value = 0UL;		\
	(ptr)->size_level = 0;		\
} while (0)
#define INIT_PRIO_TREE_NODE(ptr)				\
do {								\
	(ptr)->left = (ptr)->right = (ptr)->parent = (ptr);	\
} while (0)
#define INIT_PRIO_TREE_ROOT(ptr)	__INIT_PRIO_TREE_ROOT(ptr, 0)
#define INIT_RAW_PRIO_TREE_ROOT(ptr)	__INIT_PRIO_TREE_ROOT(ptr, 1)

#define __INIT_PRIO_TREE_ROOT(ptr, _raw)	\
do {					\
	(ptr)->prio_tree_node = NULL;	\
	(ptr)->index_bits = 1;		\
	(ptr)->raw = (_raw);		\
} while (0)
#define prio_tree_entry(ptr, type, member) \
       ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))
#define raw_prio_tree_insert(root, node) \
	prio_tree_insert(root, (struct prio_tree_node *) (node))
#define raw_prio_tree_remove(root, node) \
	prio_tree_remove(root, (struct prio_tree_node *) (node))
#define raw_prio_tree_replace(root, old, node) \
	prio_tree_replace(root, (struct prio_tree_node *) (old), \
	    (struct prio_tree_node *) (node))
#define INIT_RADIX_TREE(root, mask)					\
do {									\
	(root)->height = 0;						\
	(root)->gfp_mask = (mask);					\
	(root)->rnode = NULL;						\
} while (0)
#define RADIX_TREE(name, mask) \
	struct radix_tree_root name = RADIX_TREE_INIT(mask)
#define RADIX_TREE_INIT(mask)	{					\
	.height = 0,							\
	.gfp_mask = (mask),						\
	.rnode = NULL,							\
}
#define RADIX_TREE_MAX_TAGS 2


#define user_path_walk(name,nd) \
	__user_walk_fd(AT_FDCWD, name, LOOKUP_FOLLOW, nd)
#define user_path_walk_link(name,nd) \
	__user_walk_fd(AT_FDCWD, name, 0, nd)
#define DCACHE_AUTOFS_PENDING 0x0001    
#define DCACHE_NFSFS_RENAMED  0x0002    
#define DNAME_INLINE_LEN_MIN 36
#define IS_ROOT(x) ((x) == (x)->d_parent)

#define init_name_hash()		0
#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)	((ma)<<8 | (mi))

#define format_dev_t(buffer, dev)					\
	({								\
		sprintf(buffer, "%u:%u", MAJOR(dev), MINOR(dev));	\
		buffer;							\
	})
#define print_dev_t(buffer, dev)					\
	sprintf((buffer), "%u:%u\n", MAJOR(dev), MINOR(dev))

#define ARG_MAX       131072	
#define CHILD_MAX        999    
#define LINK_MAX         127	
#define MAX_CANON        255	
#define MAX_INPUT        255	
#define NAME_MAX         255	
#define NGROUPS_MAX    65536	
#define OPEN_MAX         256	
#define PATH_MAX        4096	
#define PIPE_BUF        4096	
#define XATTR_LIST_MAX 65536	
#define XATTR_NAME_MAX   255	
#define XATTR_SIZE_MAX 65536	


#define mdelay(n) (\
	(__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) : \
	({unsigned long __ms=(n); while (__ms--) udelay(1000);}))
#define ndelay(x)	udelay(((x)+999)/1000)
