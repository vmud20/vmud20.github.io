





#include<sys/types.h>














#include<time.h>

































#include<sys/queue.h>
#include<ctype.h>





#include<sys/select.h>



#include<sys/time.h>














#include<sys/cdefs.h>

#include<sys/signal.h>




#include<fcntl.h>






#include<errno.h>








#include<sys/param.h>


#include<sys/resource.h>


#include<stdarg.h>





#define ACPI_APP_DEPENDENT_RETURN_VOID(Prototype) \
    Prototype;
#define ACPI_CA_VERSION                 0x20191018
#define ACPI_DBG_DEPENDENT_RETURN_VOID(Prototype) \
    Prototype;
#define ACPI_DBR_DEPENDENT_RETURN_OK(Prototype) \
    ACPI_EXTERNAL_RETURN_OK(Prototype)
#define ACPI_DBR_DEPENDENT_RETURN_VOID(Prototype) \
    ACPI_EXTERNAL_RETURN_VOID(Prototype)
#define ACPI_EXTERNAL_RETURN_OK(Prototype) \
    Prototype;
#define ACPI_EXTERNAL_RETURN_PTR(Prototype) \
    Prototype;
#define ACPI_EXTERNAL_RETURN_STATUS(Prototype) \
    Prototype;
#define ACPI_EXTERNAL_RETURN_UINT32(Prototype) \
    Prototype;
#define ACPI_EXTERNAL_RETURN_VOID(Prototype) \
    Prototype;
#define ACPI_GLOBAL(type,name) \
    extern type name; \
    type name
#define ACPI_HW_DEPENDENT_RETURN_OK(Prototype) \
    ACPI_EXTERNAL_RETURN_OK(Prototype)
#define ACPI_HW_DEPENDENT_RETURN_STATUS(Prototype) \
    ACPI_EXTERNAL_RETURN_STATUS(Prototype)
#define ACPI_HW_DEPENDENT_RETURN_UINT32(prototype) \
    ACPI_EXTERNAL_RETURN_UINT32(prototype)
#define ACPI_HW_DEPENDENT_RETURN_VOID(Prototype) \
    ACPI_EXTERNAL_RETURN_VOID(Prototype)
#define ACPI_INIT_GLOBAL(type,name,value) \
    type name=value
#define ACPI_MSG_DEPENDENT_RETURN_VOID(Prototype) \
    Prototype;

#define ACPI_PLD_BUFFER_SIZE                    20 
#define ACPI_PLD_GET_BAY(dword)                 ACPI_GET_BITS (dword, 31, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_BLUE(dword)                ACPI_GET_BITS (dword, 24, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_CABINET(dword)             ACPI_GET_BITS (dword, 2, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_CARD_CAGE(dword)           ACPI_GET_BITS (dword, 10, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_DOCK(dword)                ACPI_GET_BITS (dword, 1, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_EJECTABLE(dword)           ACPI_GET_BITS (dword, 0, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_GREEN(dword)               ACPI_GET_BITS (dword, 16, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_HEIGHT(dword)              ACPI_GET_BITS (dword, 16, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_HORIZONTAL(dword)          ACPI_GET_BITS (dword, 8, ACPI_2BIT_MASK)
#define ACPI_PLD_GET_HORIZ_OFFSET(dword)        ACPI_GET_BITS (dword, 16, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_IGNORE_COLOR(dword)        ACPI_GET_BITS (dword, 7, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_LID(dword)                 ACPI_GET_BITS (dword, 2, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_ORDER(dword)               ACPI_GET_BITS (dword, 23, ACPI_5BIT_MASK)
#define ACPI_PLD_GET_ORIENTATION(dword)         ACPI_GET_BITS (dword, 14, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_OSPM_EJECT(dword)          ACPI_GET_BITS (dword, 1, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_PANEL(dword)               ACPI_GET_BITS (dword, 3, ACPI_3BIT_MASK)
#define ACPI_PLD_GET_POSITION(dword)            ACPI_GET_BITS (dword, 23, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_RED(dword)                 ACPI_GET_BITS (dword, 8, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_REFERENCE(dword)           ACPI_GET_BITS (dword, 18, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_REVISION(dword)            ACPI_GET_BITS (dword, 0, ACPI_7BIT_MASK)
#define ACPI_PLD_GET_ROTATION(dword)            ACPI_GET_BITS (dword, 19, ACPI_4BIT_MASK)
#define ACPI_PLD_GET_SHAPE(dword)               ACPI_GET_BITS (dword, 10, ACPI_4BIT_MASK)
#define ACPI_PLD_GET_TOKEN(dword)               ACPI_GET_BITS (dword, 15, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_USER_VISIBLE(dword)        ACPI_GET_BITS (dword, 0, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_VERTICAL(dword)            ACPI_GET_BITS (dword, 6, ACPI_2BIT_MASK)
#define ACPI_PLD_GET_VERT_OFFSET(dword)         ACPI_GET_BITS (dword, 0, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_WIDTH(dword)               ACPI_GET_BITS (dword, 0, ACPI_16BIT_MASK)
#define ACPI_PLD_REV1_BUFFER_SIZE               16 
#define ACPI_PLD_REV2_BUFFER_SIZE               20 
#define ACPI_PLD_SET_BAY(dword,value)           ACPI_SET_BITS (dword, 31, ACPI_1BIT_MASK, value)    
#define ACPI_PLD_SET_BLUE(dword,value)          ACPI_SET_BITS (dword, 24, ACPI_8BIT_MASK, value)    
#define ACPI_PLD_SET_CABINET(dword,value)       ACPI_SET_BITS (dword, 2, ACPI_8BIT_MASK, value)     
#define ACPI_PLD_SET_CARD_CAGE(dword,value)     ACPI_SET_BITS (dword, 10, ACPI_8BIT_MASK, value)    
#define ACPI_PLD_SET_DOCK(dword,value)          ACPI_SET_BITS (dword, 1, ACPI_1BIT_MASK, value)     
#define ACPI_PLD_SET_EJECTABLE(dword,value)     ACPI_SET_BITS (dword, 0, ACPI_1BIT_MASK, value)     
#define ACPI_PLD_SET_GREEN(dword,value)         ACPI_SET_BITS (dword, 16, ACPI_8BIT_MASK, value)    
#define ACPI_PLD_SET_HEIGHT(dword,value)        ACPI_SET_BITS (dword, 16, ACPI_16BIT_MASK, value)   
#define ACPI_PLD_SET_HORIZONTAL(dword,value)    ACPI_SET_BITS (dword, 8, ACPI_2BIT_MASK, value)     
#define ACPI_PLD_SET_HORIZ_OFFSET(dword,value)  ACPI_SET_BITS (dword, 16, ACPI_16BIT_MASK, value)   
#define ACPI_PLD_SET_IGNORE_COLOR(dword,value)  ACPI_SET_BITS (dword, 7, ACPI_1BIT_MASK, value)     
#define ACPI_PLD_SET_LID(dword,value)           ACPI_SET_BITS (dword, 2, ACPI_1BIT_MASK, value)     
#define ACPI_PLD_SET_ORDER(dword,value)         ACPI_SET_BITS (dword, 23, ACPI_5BIT_MASK, value)    
#define ACPI_PLD_SET_ORIENTATION(dword,value)   ACPI_SET_BITS (dword, 14, ACPI_1BIT_MASK, value)    
#define ACPI_PLD_SET_OSPM_EJECT(dword,value)    ACPI_SET_BITS (dword, 1, ACPI_1BIT_MASK, value)     
#define ACPI_PLD_SET_PANEL(dword,value)         ACPI_SET_BITS (dword, 3, ACPI_3BIT_MASK, value)     
#define ACPI_PLD_SET_POSITION(dword,value)      ACPI_SET_BITS (dword, 23, ACPI_8BIT_MASK, value)    
#define ACPI_PLD_SET_RED(dword,value)           ACPI_SET_BITS (dword, 8, ACPI_8BIT_MASK, value)    
#define ACPI_PLD_SET_REFERENCE(dword,value)     ACPI_SET_BITS (dword, 18, ACPI_1BIT_MASK, value)    
#define ACPI_PLD_SET_REVISION(dword,value)      ACPI_SET_BITS (dword, 0, ACPI_7BIT_MASK, value)     
#define ACPI_PLD_SET_ROTATION(dword,value)      ACPI_SET_BITS (dword, 19, ACPI_4BIT_MASK, value)    
#define ACPI_PLD_SET_SHAPE(dword,value)         ACPI_SET_BITS (dword, 10, ACPI_4BIT_MASK, value)    
#define ACPI_PLD_SET_TOKEN(dword,value)         ACPI_SET_BITS (dword, 15, ACPI_8BIT_MASK, value)    
#define ACPI_PLD_SET_USER_VISIBLE(dword,value)  ACPI_SET_BITS (dword, 0, ACPI_1BIT_MASK, value)     
#define ACPI_PLD_SET_VERTICAL(dword,value)      ACPI_SET_BITS (dword, 6, ACPI_2BIT_MASK, value)     
#define ACPI_PLD_SET_VERT_OFFSET(dword,value)   ACPI_SET_BITS (dword, 0, ACPI_16BIT_MASK, value)    
#define ACPI_PLD_SET_WIDTH(dword,value)         ACPI_SET_BITS (dword, 0, ACPI_16BIT_MASK, value)    

#define ACPI_FACS_64BIT_ENVIRONMENT (1)             
#define ACPI_FACS_64BIT_WAKE        (1<<1)          
#define ACPI_FACS_S4_BIOS_PRESENT   (1)             
#define ACPI_FADT_32BIT_TIMER       (1<<8)      
#define ACPI_FADT_8042              (1<<1)      
#define ACPI_FADT_APIC_CLUSTER      (1<<18)     
#define ACPI_FADT_APIC_PHYSICAL     (1<<19)     
#define ACPI_FADT_C1_SUPPORTED      (1<<2)      
#define ACPI_FADT_C2_MP_SUPPORTED   (1<<3)      
#define ACPI_FADT_CONFORMANCE   "ACPI 6.1 (FADT version 6)"
#define ACPI_FADT_DOCKING_SUPPORTED (1<<9)      
#define ACPI_FADT_FIXED_RTC         (1<<6)      
#define ACPI_FADT_HEADLESS          (1<<12)     
#define ACPI_FADT_HW_REDUCED        (1<<20)     
#define ACPI_FADT_LEGACY_DEVICES    (1)         
#define ACPI_FADT_LOW_POWER_S0      (1<<21)     
#define ACPI_FADT_NO_ASPM           (1<<4)      
#define ACPI_FADT_NO_CMOS_RTC       (1<<5)      
#define ACPI_FADT_NO_MSI            (1<<3)      
#define ACPI_FADT_NO_VGA            (1<<2)      
#define ACPI_FADT_OFFSET(f)             (UINT16) ACPI_OFFSET (ACPI_TABLE_FADT, f)
#define ACPI_FADT_PCI_EXPRESS_WAKE  (1<<14)     
#define ACPI_FADT_PLATFORM_CLOCK    (1<<15)     
#define ACPI_FADT_POWER_BUTTON      (1<<4)      
#define ACPI_FADT_PSCI_COMPLIANT    (1)         
#define ACPI_FADT_PSCI_USE_HVC      (1<<1)      
#define ACPI_FADT_REMOTE_POWER_ON   (1<<17)     
#define ACPI_FADT_RESET_REGISTER    (1<<10)     
#define ACPI_FADT_S4_RTC_VALID      (1<<16)     
#define ACPI_FADT_S4_RTC_WAKE       (1<<7)      
#define ACPI_FADT_SEALED_CASE       (1<<11)     
#define ACPI_FADT_SLEEP_BUTTON      (1<<5)      
#define ACPI_FADT_SLEEP_TYPE        (1<<13)     
#define ACPI_FADT_V1_SIZE       (UINT32) (ACPI_FADT_OFFSET (Flags) + 4)
#define ACPI_FADT_V2_SIZE       (UINT32) (ACPI_FADT_OFFSET (MinorRevision) + 1)
#define ACPI_FADT_V3_SIZE       (UINT32) (ACPI_FADT_OFFSET (SleepControl))
#define ACPI_FADT_V5_SIZE       (UINT32) (ACPI_FADT_OFFSET (HypervisorId))
#define ACPI_FADT_V6_SIZE       (UINT32) (sizeof (ACPI_TABLE_FADT))
#define ACPI_FADT_WBINVD            (1)         
#define ACPI_FADT_WBINVD_FLUSH      (1<<1)      
#define ACPI_GLOCK_OWNED            (1<<1)          
#define ACPI_GLOCK_PENDING          (1)             
#define ACPI_MAX_TABLE_VALIDATIONS          ACPI_UINT16_MAX
#define ACPI_OEM_NAME           "OEM"       
#define ACPI_RSDP_NAME          "RSDP"      
#define ACPI_RSDT_ENTRY_SIZE        (sizeof (UINT32))
#define ACPI_SIG_DSDT           "DSDT"      
#define ACPI_SIG_FACS           "FACS"      
#define ACPI_SIG_FADT           "FACP"      
#define ACPI_SIG_OSDT           "OSDT"      
#define ACPI_SIG_PSDT           "PSDT"      
#define ACPI_SIG_RSDP           "RSD PTR "  
#define ACPI_SIG_RSDT           "RSDT"      
#define ACPI_SIG_SSDT           "SSDT"      
#define ACPI_SIG_XSDT           "XSDT"      
#define ACPI_TABLE_IS_LOADED                (8)
#define ACPI_TABLE_IS_VERIFIED              (4)
#define ACPI_TABLE_ORIGIN_EXTERNAL_VIRTUAL  (0) 
#define ACPI_TABLE_ORIGIN_INTERNAL_PHYSICAL (1) 
#define ACPI_TABLE_ORIGIN_INTERNAL_VIRTUAL  (2) 
#define ACPI_TABLE_ORIGIN_MASK              (3)
#define ACPI_XSDT_ENTRY_SIZE        (sizeof (UINT64))
#define ACPI_X_SLEEP_ENABLE         0x20
#define ACPI_X_SLEEP_TYPE_MASK      0x1C
#define ACPI_X_SLEEP_TYPE_POSITION  0x02
#define ACPI_X_WAKE_STATUS          0x80

#define ACPI_SIG_SLIC           "SLIC"      
#define ACPI_SIG_SLIT           "SLIT"      
#define ACPI_SIG_SPCR           "SPCR"      
#define ACPI_SIG_SPMI           "SPMI"      
#define ACPI_SIG_SRAT           "SRAT"      
#define ACPI_SIG_STAO           "STAO"      
#define ACPI_SIG_TCPA           "TCPA"      
#define ACPI_SIG_TPM2           "TPM2"      
#define ACPI_SIG_UEFI           "UEFI"      
#define ACPI_SIG_VRTC           "VRTC"      
#define ACPI_SIG_WAET           "WAET"      
#define ACPI_SIG_WDAT           "WDAT"      
#define ACPI_SIG_WDDT           "WDDT"      
#define ACPI_SIG_WDRT           "WDRT"      
#define ACPI_SIG_WPBT           "WPBT"      
#define ACPI_SIG_WSMT           "WSMT"      
#define ACPI_SIG_XENV           "XENV"      
#define ACPI_SIG_XXXX           "XXXX"      
#define ACPI_SPCR_DO_NOT_DISABLE    (1)
#define ACPI_SRAT_CPU_ENABLED       (1)         
#define ACPI_SRAT_CPU_USE_AFFINITY  (1)         
#define ACPI_SRAT_GENERIC_AFFINITY_ENABLED (1) 
#define ACPI_SRAT_GICC_ENABLED     (1)         
#define ACPI_SRAT_MEM_ENABLED       (1)         
#define ACPI_SRAT_MEM_HOT_PLUGGABLE (1<<1)      
#define ACPI_SRAT_MEM_NON_VOLATILE  (1<<2)      
#define ACPI_TCPA_ADDRESS_VALID         (1<<2)
#define ACPI_TCPA_BUS_PNP               (1<<1)
#define ACPI_TCPA_CLIENT_TABLE          0
#define ACPI_TCPA_GLOBAL_INTERRUPT      (1<<3)
#define ACPI_TCPA_INTERRUPT_MODE        (1)
#define ACPI_TCPA_INTERRUPT_POLARITY    (1<<1)
#define ACPI_TCPA_PCI_DEVICE            (1)
#define ACPI_TCPA_SCI_VIA_GPE           (1<<2)
#define ACPI_TCPA_SERVER_TABLE          1
#define ACPI_TPM23_ACPI_START_METHOD                 2
#define ACPI_TPM2_COMMAND_BUFFER                    7
#define ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC       11  
#define ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD  8
#define ACPI_TPM2_IDLE_SUPPORT          (1)
#define ACPI_TPM2_INTERRUPT_SUPPORT     (1)
#define ACPI_TPM2_MEMORY_MAPPED                     6
#define ACPI_TPM2_NOT_ALLOWED                       0
#define ACPI_TPM2_RESERVED                          12
#define ACPI_TPM2_RESERVED1                         1
#define ACPI_TPM2_RESERVED10                        10
#define ACPI_TPM2_RESERVED3                         3
#define ACPI_TPM2_RESERVED4                         4
#define ACPI_TPM2_RESERVED5                         5
#define ACPI_TPM2_RESERVED9                         9
#define ACPI_TPM2_START_METHOD                      2
#define ACPI_WAET_RTC_NO_ACK        (1)         
#define ACPI_WAET_TIMER_ONE_READ    (1<<1)      
#define ACPI_WDAT_ENABLED           (1)
#define ACPI_WDAT_STOPPED           0x80
#define ACPI_WDDT_ACTIVE        (1<<1)
#define ACPI_WDDT_ALERT_SUPPORT (1<<1)
#define ACPI_WDDT_AUTO_RESET    (1)
#define ACPI_WDDT_AVAILABLE     (1)
#define ACPI_WDDT_POWER_FAIL    (1<<13)
#define ACPI_WDDT_TCO_OS_OWNED  (1<<2)
#define ACPI_WDDT_UNKNOWN_RESET (1<<14)
#define ACPI_WDDT_USER_RESET    (1<<11)
#define ACPI_WDDT_WDT_RESET     (1<<12)
#define ACPI_WSMT_COMM_BUFFER_NESTED_PTR_PROTECTION (2)
#define ACPI_WSMT_FIXED_COMM_BUFFERS                (1)
#define ACPI_WSMT_SYSTEM_RESOURCE_PROTECTION        (4)

#define ACPI_IORT_ATS_SUPPORTED         0x00000001  
#define ACPI_IORT_ATS_UNSUPPORTED       0x00000000  
#define ACPI_IORT_HT_OVERRIDE           (1<<3)
#define ACPI_IORT_HT_READ               (1<<2)
#define ACPI_IORT_HT_TRANSIENT          (1)
#define ACPI_IORT_HT_WRITE              (1<<1)
#define ACPI_IORT_ID_SINGLE_MAPPING (1)
#define ACPI_IORT_MF_ATTRIBUTES         (1<<1)
#define ACPI_IORT_MF_COHERENCY          (1)
#define ACPI_IORT_NC_PASID_BITS         (31<<1)
#define ACPI_IORT_NC_STALL_SUPPORTED    (1)
#define ACPI_IORT_NODE_COHERENT         0x00000001  
#define ACPI_IORT_NODE_NOT_COHERENT     0x00000000  
#define ACPI_IORT_SMMU_CAVIUM_THUNDERX  0x00000005  
#define ACPI_IORT_SMMU_COHERENT_WALK    (1<<1)
#define ACPI_IORT_SMMU_CORELINK_MMU400  0x00000002  
#define ACPI_IORT_SMMU_CORELINK_MMU401  0x00000004  
#define ACPI_IORT_SMMU_CORELINK_MMU500  0x00000003  
#define ACPI_IORT_SMMU_DVM_SUPPORTED    (1)
#define ACPI_IORT_SMMU_V1               0x00000000  
#define ACPI_IORT_SMMU_V2               0x00000001  
#define ACPI_IORT_SMMU_V3_CAVIUM_CN99XX     0x00000002  
#define ACPI_IORT_SMMU_V3_COHACC_OVERRIDE   (1)
#define ACPI_IORT_SMMU_V3_GENERIC           0x00000000  
#define ACPI_IORT_SMMU_V3_HISILICON_HI161X  0x00000001  
#define ACPI_IORT_SMMU_V3_HTTU_OVERRIDE     (3<<1)
#define ACPI_IORT_SMMU_V3_PXM_VALID         (1<<3)
#define ACPI_IVHD_ATS_DISABLED      (1<<31)
#define ACPI_IVHD_EINT_PASS         (1<<1)
#define ACPI_IVHD_ENTRY_LENGTH      0xC0
#define ACPI_IVHD_HPET              2
#define ACPI_IVHD_INIT_PASS         (1)
#define ACPI_IVHD_IOAPIC            1
#define ACPI_IVHD_IOTLB             (1<<4)
#define ACPI_IVHD_ISOC              (1<<3)
#define ACPI_IVHD_LINT0_PASS        (1<<6)
#define ACPI_IVHD_LINT1_PASS        (1<<7)
#define ACPI_IVHD_MSI_NUMBER_MASK   0x001F      
#define ACPI_IVHD_NMI_PASS          (1<<2)
#define ACPI_IVHD_PASS_PW           (1<<1)
#define ACPI_IVHD_RES_PASS_PW       (1<<2)
#define ACPI_IVHD_SYSTEM_MGMT       (3<<4)
#define ACPI_IVHD_TT_ENABLE         (1)
#define ACPI_IVHD_UNIT_ID_MASK      0x1F00      
#define ACPI_IVMD_EXCLUSION_RANGE   (1<<3)
#define ACPI_IVMD_READ              (1<<1)
#define ACPI_IVMD_UNITY             (1)
#define ACPI_IVMD_WRITE             (1<<2)
#define ACPI_IVRS_ATS_RESERVED      0x00400000  
#define ACPI_IVRS_PHYSICAL_SIZE     0x00007F00  
#define ACPI_IVRS_VIRTUAL_SIZE      0x003F8000  
#define ACPI_LPIT_NO_COUNTER        (1<<1)
#define ACPI_LPIT_STATE_DISABLED    (1)
#define ACPI_MADT_CPEI_OVERRIDE     (1)
#define ACPI_MADT_DUAL_PIC          1
#define ACPI_MADT_ENABLED           (1)         
#define ACPI_MADT_MULTIPLE_APIC     0
#define ACPI_MADT_OVERRIDE_SPI_VALUES   (1)
#define ACPI_MADT_PCAT_COMPAT       (1)         
#define ACPI_MADT_PERFORMANCE_IRQ_MODE  (1<<1)  
#define ACPI_MADT_POLARITY_ACTIVE_HIGH    1
#define ACPI_MADT_POLARITY_ACTIVE_LOW     3
#define ACPI_MADT_POLARITY_CONFORMS       0
#define ACPI_MADT_POLARITY_MASK     (3)         
#define ACPI_MADT_POLARITY_RESERVED       2
#define ACPI_MADT_TRIGGER_CONFORMS        (0)
#define ACPI_MADT_TRIGGER_EDGE            (1<<2)
#define ACPI_MADT_TRIGGER_LEVEL           (3<<2)
#define ACPI_MADT_TRIGGER_MASK      (3<<2)      
#define ACPI_MADT_TRIGGER_RESERVED        (2<<2)
#define ACPI_MADT_VGIC_IRQ_MODE         (1<<2)  
#define ACPI_MPST_AUTOENTRY             2
#define ACPI_MPST_AUTOEXIT              4
#define ACPI_MPST_CHANNEL_INFO \
    UINT8                   ChannelId; \
    UINT8                   Reserved1[3]; \
    UINT16                  PowerNodeCount; \
    UINT16                  Reserved2;
#define ACPI_MPST_ENABLED               1
#define ACPI_MPST_HOT_PLUG_CAPABLE      4
#define ACPI_MPST_POWER_MANAGED         2
#define ACPI_MPST_PRESERVE              1
#define ACPI_NFIT_ADD_ONLINE_ONLY       (1)     
#define ACPI_NFIT_BUILD_DEVICE_HANDLE(dimm, channel, memory, socket, node) \
    ((dimm)                                         | \
    ((channel) << ACPI_NFIT_CHANNEL_NUMBER_OFFSET)  | \
    ((memory)  << ACPI_NFIT_MEMORY_ID_OFFSET)       | \
    ((socket)  << ACPI_NFIT_SOCKET_ID_OFFSET)       | \
    ((node)    << ACPI_NFIT_NODE_ID_OFFSET))
#define ACPI_NFIT_CAPABILITY_CACHE_FLUSH       (1)     
#define ACPI_NFIT_CAPABILITY_MEM_FLUSH         (1<<1)  
#define ACPI_NFIT_CAPABILITY_MEM_MIRRORING     (1<<2)  
#define ACPI_NFIT_CHANNEL_NUMBER_MASK           0x000000F0
#define ACPI_NFIT_CHANNEL_NUMBER_OFFSET         4
#define ACPI_NFIT_CONTROL_BUFFERED          (1)     
#define ACPI_NFIT_CONTROL_MFG_INFO_VALID    (1)     
#define ACPI_NFIT_DIMM_NUMBER_MASK              0x0000000F
#define ACPI_NFIT_DIMM_NUMBER_OFFSET            0
#define ACPI_NFIT_GET_CHANNEL_NUMBER(handle) \
    (((handle) & ACPI_NFIT_CHANNEL_NUMBER_MASK) >> ACPI_NFIT_CHANNEL_NUMBER_OFFSET)
#define ACPI_NFIT_GET_DIMM_NUMBER(handle) \
    ((handle) & ACPI_NFIT_DIMM_NUMBER_MASK)
#define ACPI_NFIT_GET_MEMORY_ID(handle) \
    (((handle) & ACPI_NFIT_MEMORY_ID_MASK)      >> ACPI_NFIT_MEMORY_ID_OFFSET)
#define ACPI_NFIT_GET_NODE_ID(handle) \
    (((handle) & ACPI_NFIT_NODE_ID_MASK)        >> ACPI_NFIT_NODE_ID_OFFSET)
#define ACPI_NFIT_GET_SOCKET_ID(handle) \
    (((handle) & ACPI_NFIT_SOCKET_ID_MASK)      >> ACPI_NFIT_SOCKET_ID_OFFSET)
#define ACPI_NFIT_MEMORY_ID_MASK                0x00000F00
#define ACPI_NFIT_MEMORY_ID_OFFSET              8
#define ACPI_NFIT_MEM_FLUSH_FAILED      (1<<2)  
#define ACPI_NFIT_MEM_HEALTH_ENABLED    (1<<5)  
#define ACPI_NFIT_MEM_HEALTH_OBSERVED   (1<<4)  
#define ACPI_NFIT_MEM_MAP_FAILED        (1<<6)  
#define ACPI_NFIT_MEM_NOT_ARMED         (1<<3)  
#define ACPI_NFIT_MEM_RESTORE_FAILED    (1<<1)  
#define ACPI_NFIT_MEM_SAVE_FAILED       (1)     
#define ACPI_NFIT_NODE_ID_MASK                  0x0FFF0000
#define ACPI_NFIT_NODE_ID_OFFSET                16
#define ACPI_NFIT_PROXIMITY_VALID       (1<<1)  
#define ACPI_NFIT_SOCKET_ID_MASK                0x0000F000
#define ACPI_NFIT_SOCKET_ID_OFFSET              12
#define ACPI_PCCT_DOORBELL              1
#define ACPI_PCCT_INTERRUPT_MODE        (1<<1)
#define ACPI_PCCT_INTERRUPT_POLARITY    (1)
#define ACPI_PDTT_RUNTIME_TRIGGER           (1)
#define ACPI_PDTT_TRIGGER_ORDER             (1<<2)
#define ACPI_PDTT_WAIT_COMPLETION           (1<<1)
#define ACPI_PMTT_MEMORY_TYPE           0x000C
#define ACPI_PMTT_PHYSICAL              0x0002
#define ACPI_PMTT_TOP_LEVEL             0x0001
#define ACPI_PMTT_TYPE_CONTROLLER       1
#define ACPI_PMTT_TYPE_DIMM             2
#define ACPI_PMTT_TYPE_RESERVED         3 
#define ACPI_PMTT_TYPE_SOCKET           0
#define ACPI_PPTT_ACPI_IDENTICAL            (1<<4)  
#define ACPI_PPTT_ACPI_LEAF_NODE            (1<<3)  
#define ACPI_PPTT_ACPI_PROCESSOR_ID_VALID   (1<<1)
#define ACPI_PPTT_ACPI_PROCESSOR_IS_THREAD  (1<<2)  
#define ACPI_PPTT_ALLOCATION_TYPE_VALID     (1<<3)  
#define ACPI_PPTT_ASSOCIATIVITY_VALID       (1<<2)  
#define ACPI_PPTT_CACHE_POLICY_WB           (0x0)   
#define ACPI_PPTT_CACHE_POLICY_WT           (1<<4)  
#define ACPI_PPTT_CACHE_READ_ALLOCATE       (0x0)   
#define ACPI_PPTT_CACHE_RW_ALLOCATE         (0x02)  
#define ACPI_PPTT_CACHE_RW_ALLOCATE_ALT     (0x03)  
#define ACPI_PPTT_CACHE_TYPE_DATA           (0x0)   
#define ACPI_PPTT_CACHE_TYPE_INSTR          (1<<2)  
#define ACPI_PPTT_CACHE_TYPE_UNIFIED        (2<<2)  
#define ACPI_PPTT_CACHE_TYPE_UNIFIED_ALT    (3<<2)  
#define ACPI_PPTT_CACHE_TYPE_VALID          (1<<4)  
#define ACPI_PPTT_CACHE_WRITE_ALLOCATE      (0x01)  
#define ACPI_PPTT_LINE_SIZE_VALID           (1<<6)  
#define ACPI_PPTT_MASK_ALLOCATION_TYPE      (0x03)  
#define ACPI_PPTT_MASK_CACHE_TYPE           (0x0C)  
#define ACPI_PPTT_MASK_WRITE_POLICY         (0x10)  
#define ACPI_PPTT_NUMBER_OF_SETS_VALID      (1<<1)  
#define ACPI_PPTT_PHYSICAL_PACKAGE          (1)
#define ACPI_PPTT_SIZE_PROPERTY_VALID       (1)     
#define ACPI_PPTT_WRITE_POLICY_VALID        (1<<5)  
#define ACPI_RASF_COMMAND_COMPLETE      (1)
#define ACPI_RASF_ERROR                 (1<<2)
#define ACPI_RASF_GENERATE_SCI          (1<<15)
#define ACPI_RASF_SCI_DOORBELL          (1<<1)
#define ACPI_RASF_SCRUBBER_RUNNING      1
#define ACPI_RASF_SPEED                 (7<<1)
#define ACPI_RASF_SPEED_FAST            (7<<1)
#define ACPI_RASF_SPEED_MEDIUM          (4<<1)
#define ACPI_RASF_SPEED_SLOW            (0<<1)
#define ACPI_RASF_STATUS                (0x1F<<3)
#define ACPI_SDEV_HANDOFF_TO_UNSECURE_OS    (1)
#define ACPI_SIG_IORT           "IORT"      
#define ACPI_SIG_IVRS           "IVRS"      
#define ACPI_SIG_LPIT           "LPIT"      
#define ACPI_SIG_MADT           "APIC"      
#define ACPI_SIG_MCFG           "MCFG"      
#define ACPI_SIG_MCHI           "MCHI"      
#define ACPI_SIG_MPST           "MPST"      
#define ACPI_SIG_MSCT           "MSCT"      
#define ACPI_SIG_MSDM           "MSDM"      
#define ACPI_SIG_MTMR           "MTMR"      
#define ACPI_SIG_NFIT           "NFIT"      
#define ACPI_SIG_PCCT           "PCCT"      
#define ACPI_SIG_PDTT           "PDTT"      
#define ACPI_SIG_PMTT           "PMTT"      
#define ACPI_SIG_PPTT           "PPTT"      
#define ACPI_SIG_RASF           "RASF"      
#define ACPI_SIG_SBST           "SBST"      
#define ACPI_SIG_SDEI           "SDEI"      
#define ACPI_SIG_SDEV           "SDEV"      

#define ACPI_ASF_SMBUS_PROTOCOLS    (1)
#define ACPI_BERT_CORRECTABLE               (1<<1)
#define ACPI_BERT_ERROR_ENTRY_COUNT         (0xFF<<4) 
#define ACPI_BERT_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_BERT_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_BERT_UNCORRECTABLE             (1)
#define ACPI_BGRT_DISPLAYED                 (1)
#define ACPI_BGRT_ORIENTATION_OFFSET        (3 << 1)
#define ACPI_CSRT_DMA_CHANNEL       0x0000
#define ACPI_CSRT_DMA_CONTROLLER    0x0001
#define ACPI_CSRT_TIMER             0x0000
#define ACPI_CSRT_TYPE_DMA          0x0003
#define ACPI_CSRT_TYPE_INTERRUPT    0x0001
#define ACPI_CSRT_TYPE_TIMER        0x0002
#define ACPI_CSRT_XRUPT_CONTROLLER  0x0001
#define ACPI_CSRT_XRUPT_LINE        0x0000
#define ACPI_DBG2_1394_PORT         0x8001
#define ACPI_DBG2_1394_STANDARD     0x0000
#define ACPI_DBG2_16550_COMPATIBLE  0x0000
#define ACPI_DBG2_16550_SUBSET      0x0001
#define ACPI_DBG2_ARM_DCC           0x000F
#define ACPI_DBG2_ARM_PL011         0x0003
#define ACPI_DBG2_ARM_SBSA_32BIT    0x000D
#define ACPI_DBG2_ARM_SBSA_GENERIC  0x000E
#define ACPI_DBG2_BCM2835           0x0010
#define ACPI_DBG2_NET_PORT          0x8003
#define ACPI_DBG2_SERIAL_PORT       0x8000
#define ACPI_DBG2_USB_EHCI          0x0001
#define ACPI_DBG2_USB_PORT          0x8002
#define ACPI_DBG2_USB_XHCI          0x0000
#define ACPI_DMAR_ALLOW_ALL         (1)
#define ACPI_DMAR_ALL_PORTS         (1)
#define ACPI_DMAR_INCLUDE_ALL       (1)
#define ACPI_DMAR_INTR_REMAP        (1)
#define ACPI_DMAR_X2APIC_MODE       (1<<2)
#define ACPI_DMAR_X2APIC_OPT_OUT    (1<<1)
#define ACPI_DRTM_ACCESS_ALLOWED            (1)
#define ACPI_DRTM_AUTHORITY_ORDER           (1<<3)
#define ACPI_DRTM_ENABLE_GAP_CODE           (1<<1)
#define ACPI_DRTM_INCOMPLETE_MEASUREMENTS   (1<<2)
#define ACPI_EINJ_MEMORY_CORRECTABLE        (1<<3)
#define ACPI_EINJ_MEMORY_FATAL              (1<<5)
#define ACPI_EINJ_MEMORY_UNCORRECTABLE      (1<<4)
#define ACPI_EINJ_PCIX_CORRECTABLE          (1<<6)
#define ACPI_EINJ_PCIX_FATAL                (1<<8)
#define ACPI_EINJ_PCIX_UNCORRECTABLE        (1<<7)
#define ACPI_EINJ_PLATFORM_CORRECTABLE      (1<<9)
#define ACPI_EINJ_PLATFORM_FATAL            (1<<11)
#define ACPI_EINJ_PLATFORM_UNCORRECTABLE    (1<<10)
#define ACPI_EINJ_PRESERVE          (1)
#define ACPI_EINJ_PROCESSOR_CORRECTABLE     (1)
#define ACPI_EINJ_PROCESSOR_FATAL           (1<<2)
#define ACPI_EINJ_PROCESSOR_UNCORRECTABLE   (1<<1)
#define ACPI_EINJ_VENDOR_DEFINED            (1<<31)
#define ACPI_ERST_PRESERVE          (1)
#define ACPI_GTDT_ALWAYS_ON             (1<<2)
#define ACPI_GTDT_GT_ALWAYS_ON              (1<<1)
#define ACPI_GTDT_GT_IRQ_MODE               (1)
#define ACPI_GTDT_GT_IRQ_POLARITY           (1<<1)
#define ACPI_GTDT_GT_IS_SECURE_TIMER        (1)
#define ACPI_GTDT_INTERRUPT_MODE        (1)
#define ACPI_GTDT_INTERRUPT_POLARITY    (1<<1)
#define ACPI_GTDT_WATCHDOG_IRQ_MODE         (1)
#define ACPI_GTDT_WATCHDOG_IRQ_POLARITY     (1<<1)
#define ACPI_GTDT_WATCHDOG_SECURE           (1<<2)
#define ACPI_HEST_BUS(Bus)              ((Bus) & 0xFF)
#define ACPI_HEST_CORRECTABLE               (1<<1)
#define ACPI_HEST_ERROR_ENTRY_COUNT         (0xFF<<4) 
#define ACPI_HEST_ERR_THRESHOLD_VALUE   (1<<4)
#define ACPI_HEST_ERR_THRESHOLD_WINDOW  (1<<5)
#define ACPI_HEST_FIRMWARE_FIRST        (1)
#define ACPI_HEST_GEN_ERROR_CORRECTED       2
#define ACPI_HEST_GEN_ERROR_FATAL           1
#define ACPI_HEST_GEN_ERROR_NONE            3
#define ACPI_HEST_GEN_ERROR_RECOVERABLE     0
#define ACPI_HEST_GEN_VALID_FRU_ID          (1)
#define ACPI_HEST_GEN_VALID_FRU_STRING      (1<<1)
#define ACPI_HEST_GEN_VALID_TIMESTAMP       (1<<2)
#define ACPI_HEST_GHES_ASSIST           (1<<2)
#define ACPI_HEST_GLOBAL                (1<<1)
#define ACPI_HEST_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_HEST_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_HEST_POLL_INTERVAL         (1<<1)
#define ACPI_HEST_POLL_THRESHOLD_VALUE  (1<<2)
#define ACPI_HEST_POLL_THRESHOLD_WINDOW (1<<3)
#define ACPI_HEST_SEGMENT(Bus)          (((Bus) >> 8) & 0xFFFF)
#define ACPI_HEST_TYPE                  (1)
#define ACPI_HEST_UNCORRECTABLE             (1)
#define ACPI_HMAT_1ST_LEVEL_CACHE   2
#define ACPI_HMAT_2ND_LEVEL_CACHE   3
#define ACPI_HMAT_3RD_LEVEL_CACHE   4
#define ACPI_HMAT_ACCESS_BANDWIDTH  3
#define ACPI_HMAT_ACCESS_LATENCY    0
#define ACPI_HMAT_CACHE_ASSOCIATIVITY   (0x00000F00)
#define ACPI_HMAT_CACHE_LEVEL           (0x000000F0)
#define ACPI_HMAT_CACHE_LINE_SIZE       (0xFFFF0000)
#define ACPI_HMAT_CA_COMPLEX_CACHE_INDEXING   (2)
#define ACPI_HMAT_CA_DIRECT_MAPPED            (1)
#define ACPI_HMAT_CA_NONE                     (0)
#define ACPI_HMAT_CP_NONE   (0)
#define ACPI_HMAT_CP_WB     (1)
#define ACPI_HMAT_CP_WT     (2)
#define ACPI_HMAT_LAST_LEVEL_CACHE  1
#define ACPI_HMAT_MEMORY            0
#define ACPI_HMAT_MEMORY_HIERARCHY  (0x0F)
#define ACPI_HMAT_MEMORY_PD_VALID       (1<<1)  
#define ACPI_HMAT_PROCESSOR_PD_VALID    (1)     
#define ACPI_HMAT_READ_BANDWIDTH    4
#define ACPI_HMAT_READ_LATENCY      1
#define ACPI_HMAT_RESERVATION_HINT      (1<<2)  
#define ACPI_HMAT_TOTAL_CACHE_LEVEL     (0x0000000F)
#define ACPI_HMAT_WRITE_BANDWIDTH   5
#define ACPI_HMAT_WRITE_LATENCY     2
#define ACPI_HMAT_WRITE_POLICY          (0x0000F000)
#define ACPI_HPET_PAGE_PROTECT_MASK (3)
#define ACPI_SIG_ASF            "ASF!"      
#define ACPI_SIG_ATKG           "ATKG"
#define ACPI_SIG_BERT           "BERT"      
#define ACPI_SIG_BGRT           "BGRT"      
#define ACPI_SIG_BOOT           "BOOT"      
#define ACPI_SIG_CPEP           "CPEP"      
#define ACPI_SIG_CSRT           "CSRT"      
#define ACPI_SIG_DBG2           "DBG2"      
#define ACPI_SIG_DBGP           "DBGP"      
#define ACPI_SIG_DMAR           "DMAR"      
#define ACPI_SIG_DRTM           "DRTM"      
#define ACPI_SIG_ECDT           "ECDT"      
#define ACPI_SIG_EINJ           "EINJ"      
#define ACPI_SIG_ERST           "ERST"      
#define ACPI_SIG_FPDT           "FPDT"      
#define ACPI_SIG_GSCI           "GSCI"      
#define ACPI_SIG_GTDT           "GTDT"      
#define ACPI_SIG_HEST           "HEST"      
#define ACPI_SIG_HMAT           "HMAT"      
#define ACPI_SIG_HPET           "HPET"      
#define ACPI_SIG_IBFT           "IBFT"      
#define ACPI_SIG_IEIT           "IEIT"
#define ACPI_SIG_MATR           "MATR"      
#define ACPI_SIG_PCCS           "PCC"       
#define ACPI_SIG_S3PT           "S3PT"      

#define ACPI_100NSEC_PER_MSEC           10000L
#define ACPI_100NSEC_PER_SEC            10000000L
#define ACPI_100NSEC_PER_USEC           10L
#define ACPI_ACCESS_BIT_WIDTH(size)     (1 << ((size) + 2))
#define ACPI_ADD_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (UINT8, (a)) + (ACPI_SIZE)(b)))
#define ACPI_ADR_SPACE_CMOS             (ACPI_ADR_SPACE_TYPE) 5
#define ACPI_ADR_SPACE_DATA_TABLE       (ACPI_ADR_SPACE_TYPE) 0x7E 
#define ACPI_ADR_SPACE_EC               (ACPI_ADR_SPACE_TYPE) 3
#define ACPI_ADR_SPACE_FIXED_HARDWARE   (ACPI_ADR_SPACE_TYPE) 0x7F
#define ACPI_ADR_SPACE_GPIO             (ACPI_ADR_SPACE_TYPE) 8
#define ACPI_ADR_SPACE_GSBUS            (ACPI_ADR_SPACE_TYPE) 9
#define ACPI_ADR_SPACE_IPMI             (ACPI_ADR_SPACE_TYPE) 7
#define ACPI_ADR_SPACE_PCI_BAR_TARGET   (ACPI_ADR_SPACE_TYPE) 6
#define ACPI_ADR_SPACE_PCI_CONFIG       (ACPI_ADR_SPACE_TYPE) 2
#define ACPI_ADR_SPACE_PLATFORM_COMM    (ACPI_ADR_SPACE_TYPE) 10
#define ACPI_ADR_SPACE_SMBUS            (ACPI_ADR_SPACE_TYPE) 4
#define ACPI_ADR_SPACE_SYSTEM_IO        (ACPI_ADR_SPACE_TYPE) 1
#define ACPI_ADR_SPACE_SYSTEM_MEMORY    (ACPI_ADR_SPACE_TYPE) 0
#define ACPI_ALLOCATE(a)                NULL
#define ACPI_ALLOCATE_BUFFER        (ACPI_SIZE) (0)
#define ACPI_ALLOCATE_LOCAL_BUFFER  (ACPI_SIZE) (0)
#define ACPI_ALLOCATE_ZEROED(a)         NULL
#define ACPI_ALL_NOTIFY                 (ACPI_SYSTEM_NOTIFY | ACPI_DEVICE_NOTIFY)
#define ACPI_ARRAY_LENGTH(x)            (sizeof(x) / sizeof((x)[0]))
#define ACPI_ASCII_MAX                  0x7F
#define ACPI_BITREG_ARB_DISABLE                 0x13
#define ACPI_BITREG_BUS_MASTER_RLD              0x0F
#define ACPI_BITREG_BUS_MASTER_STATUS           0x01
#define ACPI_BITREG_GLOBAL_LOCK_ENABLE          0x09
#define ACPI_BITREG_GLOBAL_LOCK_RELEASE         0x10
#define ACPI_BITREG_GLOBAL_LOCK_STATUS          0x02
#define ACPI_BITREG_MAX                         0x13
#define ACPI_BITREG_PCIEXP_WAKE_DISABLE         0x0D
#define ACPI_BITREG_PCIEXP_WAKE_STATUS          0x07
#define ACPI_BITREG_POWER_BUTTON_ENABLE         0x0A
#define ACPI_BITREG_POWER_BUTTON_STATUS         0x03
#define ACPI_BITREG_RT_CLOCK_ENABLE             0x0C
#define ACPI_BITREG_RT_CLOCK_STATUS             0x05
#define ACPI_BITREG_SCI_ENABLE                  0x0E
#define ACPI_BITREG_SLEEP_BUTTON_ENABLE         0x0B
#define ACPI_BITREG_SLEEP_BUTTON_STATUS         0x04
#define ACPI_BITREG_SLEEP_ENABLE                0x12
#define ACPI_BITREG_SLEEP_TYPE                  0x11
#define ACPI_BITREG_TIMER_ENABLE                0x08
#define ACPI_BITREG_TIMER_STATUS                0x00
#define ACPI_BITREG_WAKE_STATUS                 0x06
#define ACPI_CACHE_T                    ACPI_MEMORY_LIST
#define ACPI_CAST_INDIRECT_PTR(t, p)    ((t **) (ACPI_UINTPTR_T) (p))
#define ACPI_CAST_PTR(t, p)             ((t *) (ACPI_UINTPTR_T) (p))
#define ACPI_CLEAR_BIT(target,bit)      ((target) &= ~(bit))
#define ACPI_CLEAR_STATUS                       1
#define ACPI_COMPARE_NAMESEG(a,b)       (*ACPI_CAST_PTR (UINT32, (a)) == *ACPI_CAST_PTR (UINT32, (b)))
#define ACPI_COPY_NAMESEG(dest,src)     (*ACPI_CAST_PTR (UINT32, (dest)) = *ACPI_CAST_PTR (UINT32, (src)))
#define ACPI_CPU_FLAGS                  ACPI_SIZE
#define ACPI_C_STATES_MAX               ACPI_STATE_C3
#define ACPI_C_STATE_COUNT              4

#define ACPI_DEFAULT_HANDLER            NULL
#define ACPI_DEVICE_HANDLER_LIST        1 
#define ACPI_DEVICE_NOTIFY              0x2
#define ACPI_DISABLE_ALL_FEATURE_STRINGS    (ACPI_DISABLE_INTERFACES | ACPI_FEATURE_STRINGS)
#define ACPI_DISABLE_ALL_STRINGS            (ACPI_DISABLE_INTERFACES | ACPI_VENDOR_STRINGS | ACPI_FEATURE_STRINGS)
#define ACPI_DISABLE_ALL_VENDOR_STRINGS     (ACPI_DISABLE_INTERFACES | ACPI_VENDOR_STRINGS)
#define ACPI_DISABLE_EVENT                      0
#define ACPI_DISABLE_INTERFACES             0x04
#define ACPI_DO_NOT_WAIT                0
#define ACPI_D_STATES_MAX               ACPI_STATE_D3
#define ACPI_D_STATE_COUNT              4
#define ACPI_EISAID_STRING_SIZE         8   
#define ACPI_ENABLE_ALL_FEATURE_STRINGS     (ACPI_ENABLE_INTERFACES | ACPI_FEATURE_STRINGS)
#define ACPI_ENABLE_ALL_STRINGS             (ACPI_ENABLE_INTERFACES | ACPI_VENDOR_STRINGS | ACPI_FEATURE_STRINGS)
#define ACPI_ENABLE_ALL_VENDOR_STRINGS      (ACPI_ENABLE_INTERFACES | ACPI_VENDOR_STRINGS)
#define ACPI_ENABLE_EVENT                       1
#define ACPI_ENABLE_INTERFACES              0x00
#define ACPI_EVENT_FLAG_DISABLED        (ACPI_EVENT_STATUS) 0x00
#define ACPI_EVENT_FLAG_ENABLED         (ACPI_EVENT_STATUS) 0x01
#define ACPI_EVENT_FLAG_ENABLE_SET      (ACPI_EVENT_STATUS) 0x08
#define ACPI_EVENT_FLAG_HAS_HANDLER     (ACPI_EVENT_STATUS) 0x10
#define ACPI_EVENT_FLAG_MASKED          (ACPI_EVENT_STATUS) 0x20
#define ACPI_EVENT_FLAG_SET             ACPI_EVENT_FLAG_STATUS_SET
#define ACPI_EVENT_FLAG_STATUS_SET      (ACPI_EVENT_STATUS) 0x04
#define ACPI_EVENT_FLAG_WAKE_ENABLED    (ACPI_EVENT_STATUS) 0x02
#define ACPI_EVENT_GLOBAL               1
#define ACPI_EVENT_MAX                  4
#define ACPI_EVENT_PMTIMER              0
#define ACPI_EVENT_POWER_BUTTON         2
#define ACPI_EVENT_RTC                  4
#define ACPI_EVENT_SLEEP_BUTTON         3
#define ACPI_EVENT_TYPE_FIXED       1
#define ACPI_EVENT_TYPE_GPE         0


#define ACPI_FEATURE_STRINGS                0x02

#define ACPI_FULL_INITIALIZATION        0x0000
#define ACPI_FULL_PATHNAME              0
#define ACPI_FULL_PATHNAME_NO_TRAILING  2
#define ACPI_GENERIC_NOTIFY_MAX         0x0F
#define ACPI_GPE_AUTO_ENABLED           (UINT8) 0x20
#define ACPI_GPE_CAN_WAKE               (UINT8) 0x10
#define ACPI_GPE_CONDITIONAL_ENABLE     2
#define ACPI_GPE_DISABLE                1
#define ACPI_GPE_DISPATCH_HANDLER       (UINT8) 0x02
#define ACPI_GPE_DISPATCH_MASK          (UINT8) 0x07
#define ACPI_GPE_DISPATCH_METHOD        (UINT8) 0x01
#define ACPI_GPE_DISPATCH_NONE          (UINT8) 0x00
#define ACPI_GPE_DISPATCH_NOTIFY        (UINT8) 0x03
#define ACPI_GPE_DISPATCH_RAW_HANDLER   (UINT8) 0x04
#define ACPI_GPE_DISPATCH_TYPE(flags)   ((UINT8) ((flags) & ACPI_GPE_DISPATCH_MASK))
#define ACPI_GPE_EDGE_TRIGGERED         (UINT8) 0x00
#define ACPI_GPE_ENABLE                 0
#define ACPI_GPE_INITIALIZED            (UINT8) 0x40
#define ACPI_GPE_LEVEL_TRIGGERED        (UINT8) 0x08
#define ACPI_GPE_REGISTER_WIDTH         8
#define ACPI_GPE_XRUPT_TYPE_MASK        (UINT8) 0x08
#define ACPI_HIBYTE(Integer)            ((UINT8) (((UINT16)(Integer)) >> 8))
#define ACPI_HIDWORD(Integer64)         ((UINT32)(((UINT64)(Integer64)) >> 32))
#define ACPI_HIWORD(Integer)            ((UINT16)(((UINT32)(Integer)) >> 16))
#define ACPI_INITIALIZED_OK             0x02
#define ACPI_INIT_DEVICE_INI        1
#define ACPI_INTEGER_BIT_SIZE           64
#define ACPI_INTEGER_MAX                ACPI_UINT64_MAX
#define ACPI_INTERRUPT_HANDLED          0x01
#define ACPI_INTERRUPT_NOT_HANDLED      0x00
#define ACPI_IO_MASK                    1
#define ACPI_ISR                        0x0
#define ACPI_IS_OEM_SIG(a)        (!strncmp (ACPI_CAST_PTR (char, (a)), ACPI_OEM_NAME, 3) &&\
                                      strnlen (a, ACPI_NAMESEG_SIZE) == ACPI_NAMESEG_SIZE)
#define ACPI_LOBYTE(Integer)            ((UINT8)   (UINT16)(Integer))
#define ACPI_LODWORD(Integer64)         ((UINT32)  (UINT64)(Integer64))
#define ACPI_LOWORD(Integer)            ((UINT16)  (UINT32)(Integer))
#define ACPI_MAKE_RSDP_SIG(dest)        (memcpy (ACPI_CAST_PTR (char, (dest)), ACPI_SIG_RSDP, 8))
#define ACPI_MAX(a,b)                   (((a)>(b))?(a):(b))
#define ACPI_MAX16_DECIMAL_DIGITS        5
#define ACPI_MAX32_DECIMAL_DIGITS       10
#define ACPI_MAX64_DECIMAL_DIGITS       20
#define ACPI_MAX8_DECIMAL_DIGITS         3
#define ACPI_MAX_DECIMAL_DIGITS         20  
#define ACPI_MAX_DEVICE_SPECIFIC_NOTIFY 0xBF
#define ACPI_MAX_GPE_BLOCKS             2
#define ACPI_MAX_NOTIFY_HANDLER_TYPE    0x3
#define ACPI_MAX_PTR                    ACPI_UINT64_MAX
#define ACPI_MAX_SYS_NOTIFY             0x7F
#define ACPI_MEM_PARAMETERS             _COMPONENT, _AcpiModuleName, "__LINE__"

#define ACPI_MIN(a,b)                   (((a)<(b))?(a):(b))

#define ACPI_MSEC_PER_SEC               1000L
#define ACPI_MUTEX                      ACPI_SEMAPHORE
#define ACPI_NAMESEG_SIZE               4           
#define ACPI_NAME_TYPE_MAX              2
#define ACPI_NOTIFY_AFFINITY_UPDATE     (UINT8) 0x0D
#define ACPI_NOTIFY_BUS_CHECK           (UINT8) 0x00
#define ACPI_NOTIFY_BUS_MODE_MISMATCH   (UINT8) 0x06
#define ACPI_NOTIFY_CAPABILITIES_CHECK  (UINT8) 0x08
#define ACPI_NOTIFY_DEVICE_CHECK        (UINT8) 0x01
#define ACPI_NOTIFY_DEVICE_CHECK_LIGHT  (UINT8) 0x04
#define ACPI_NOTIFY_DEVICE_PLD_CHECK    (UINT8) 0x09
#define ACPI_NOTIFY_DEVICE_WAKE         (UINT8) 0x02
#define ACPI_NOTIFY_DISCONNECT_RECOVER  (UINT8) 0x0F
#define ACPI_NOTIFY_EJECT_REQUEST       (UINT8) 0x03
#define ACPI_NOTIFY_FREQUENCY_MISMATCH  (UINT8) 0x05
#define ACPI_NOTIFY_LOCALITY_UPDATE     (UINT8) 0x0B
#define ACPI_NOTIFY_MEMORY_UPDATE       (UINT8) 0x0E
#define ACPI_NOTIFY_POWER_FAULT         (UINT8) 0x07
#define ACPI_NOTIFY_RESERVED            (UINT8) 0x0A
#define ACPI_NOTIFY_SHUTDOWN_REQUEST    (UINT8) 0x0C
#define ACPI_NOT_ISR                    0x1
#define ACPI_NO_ACPI_ENABLE             0x0002
#define ACPI_NO_ADDRESS_SPACE_INIT      0x0080
#define ACPI_NO_BUFFER              0
#define ACPI_NO_DEVICE_INIT             0x0040
#define ACPI_NO_EVENT_INIT              0x0008
#define ACPI_NO_FACS_INIT               0x0001
#define ACPI_NO_HANDLER_INIT            0x0010
#define ACPI_NO_HARDWARE_INIT           0x0004
#define ACPI_NO_OBJECT_INIT             0x0020
#define ACPI_NSEC_PER_MSEC              1000000L
#define ACPI_NSEC_PER_SEC               1000000000L
#define ACPI_NSEC_PER_USEC              1000L
#define ACPI_NUM_BITREG                         ACPI_BITREG_MAX + 1
#define ACPI_NUM_FIXED_EVENTS           ACPI_EVENT_MAX + 1
#define ACPI_NUM_NOTIFY_TYPES           2
#define ACPI_NUM_NS_TYPES               (ACPI_TYPE_INVALID + 1)
#define ACPI_NUM_PREDEFINED_REGIONS     11
#define ACPI_NUM_TABLE_EVENTS           4
#define ACPI_NUM_TYPES                  (ACPI_TYPE_EXTERNAL_MAX + 1)
#define ACPI_OEM_ID_SIZE                6
#define ACPI_OEM_TABLE_ID_SIZE          8
#define ACPI_OFFSET(d, f)               ACPI_PTR_DIFF (&(((d *) 0)->f), (void *) 0)
#define ACPI_OPT_END                    -1
#define ACPI_OSI_WINSRV_2003            0x04
#define ACPI_OSI_WINSRV_2003_SP1        0x06
#define ACPI_OSI_WINSRV_2008            0x08
#define ACPI_OSI_WIN_10                 0x0E
#define ACPI_OSI_WIN_10_19H1            0x14
#define ACPI_OSI_WIN_10_RS1             0x0F
#define ACPI_OSI_WIN_10_RS2             0x10
#define ACPI_OSI_WIN_10_RS3             0x11
#define ACPI_OSI_WIN_10_RS4             0x12
#define ACPI_OSI_WIN_10_RS5             0x13
#define ACPI_OSI_WIN_2000               0x01
#define ACPI_OSI_WIN_7                  0x0B
#define ACPI_OSI_WIN_8                  0x0C
#define ACPI_OSI_WIN_8_1                0x0D
#define ACPI_OSI_WIN_VISTA              0x07
#define ACPI_OSI_WIN_VISTA_SP1          0x09
#define ACPI_OSI_WIN_VISTA_SP2          0x0A
#define ACPI_OSI_WIN_XP                 0x02
#define ACPI_OSI_WIN_XP_SP1             0x03
#define ACPI_OSI_WIN_XP_SP2             0x05
#define ACPI_OWNER_ID_MAX               0xFFF   
#define ACPI_PATH_SEGMENT_LENGTH        5           
#define ACPI_PATH_SEPARATOR             '.'
#define ACPI_PCICLS_STRING_SIZE         7   
#define ACPI_PCI_ROOT_BRIDGE            0x01
#define ACPI_PHYSADDR_TO_PTR(i)         ACPI_TO_POINTER(i)
#define ACPI_PM1_REGISTER_WIDTH         16
#define ACPI_PM2_REGISTER_WIDTH         8
#define ACPI_PM_TIMER_FREQUENCY         3579545
#define ACPI_PM_TIMER_WIDTH             32

#define ACPI_PTR_DIFF(a, b)             ((ACPI_SIZE) (ACPI_CAST_PTR (UINT8, (a)) - ACPI_CAST_PTR (UINT8, (b))))
#define ACPI_PTR_TO_PHYSADDR(i)         ACPI_TO_INTEGER(i)
#define ACPI_READ                       0
#define ACPI_REENABLE_GPE               0x80
#define ACPI_REGION_ACTIVATE    0
#define ACPI_REGION_DEACTIVATE  1
#define ACPI_REG_CONNECT                1
#define ACPI_REG_DISCONNECT             0
#define ACPI_RESET_REGISTER_WIDTH       8
#define ACPI_ROOT_OBJECT                ((ACPI_HANDLE) ACPI_TO_POINTER (ACPI_MAX_PTR))
#define ACPI_SEMAPHORE                  void *
#define ACPI_SET_BIT(target,bit)        ((target) |= (bit))
#define ACPI_SINGLE_NAME                1
#define ACPI_SIZE_MAX                   ACPI_UINT64_MAX
#define ACPI_SLEEP_TYPE_INVALID         0xFF
#define ACPI_SLEEP_TYPE_MAX             0x7
#define ACPI_SPECIFIC_NOTIFY_MAX        0x84
#define ACPI_SPINLOCK                   void *
#define ACPI_STATE_C0                   (UINT8) 0
#define ACPI_STATE_C1                   (UINT8) 1
#define ACPI_STATE_C2                   (UINT8) 2
#define ACPI_STATE_C3                   (UINT8) 3
#define ACPI_STATE_D0                   (UINT8) 0
#define ACPI_STATE_D1                   (UINT8) 1
#define ACPI_STATE_D2                   (UINT8) 2
#define ACPI_STATE_D3                   (UINT8) 3
#define ACPI_STATE_S0                   (UINT8) 0
#define ACPI_STATE_S1                   (UINT8) 1
#define ACPI_STATE_S2                   (UINT8) 2
#define ACPI_STATE_S3                   (UINT8) 3
#define ACPI_STATE_S4                   (UINT8) 4
#define ACPI_STATE_S5                   (UINT8) 5
#define ACPI_STATE_UNKNOWN              (UINT8) 0xFF
#define ACPI_STA_BATTERY_PRESENT        0x10
#define ACPI_STA_DEVICE_ENABLED         0x02
#define ACPI_STA_DEVICE_FUNCTIONING     0x08
#define ACPI_STA_DEVICE_OK              0x08 
#define ACPI_STA_DEVICE_PRESENT         0x01
#define ACPI_STA_DEVICE_UI              0x04
#define ACPI_SUBSYSTEM_INITIALIZE       0x01
#define ACPI_SUB_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (UINT8, (a)) - (ACPI_SIZE)(b)))
#define ACPI_SYSTEM_HANDLER_LIST        0 
#define ACPI_SYSTEM_NOTIFY              0x1
#define ACPI_SYS_MODES_MASK             0x0003
#define ACPI_SYS_MODE_ACPI              0x0001
#define ACPI_SYS_MODE_LEGACY            0x0002
#define ACPI_SYS_MODE_UNKNOWN           0x0000
#define ACPI_S_STATES_MAX               ACPI_STATE_S5
#define ACPI_S_STATE_COUNT              6
#define ACPI_TABLE_EVENT_INSTALL        0x2
#define ACPI_TABLE_EVENT_LOAD           0x0
#define ACPI_TABLE_EVENT_UNINSTALL      0x3
#define ACPI_TABLE_EVENT_UNLOAD         0x1
#define ACPI_THREAD_ID                  UINT64
#define ACPI_TIME_AFTER(a, b)           ((INT64)((b) - (a)) < 0)
#define ACPI_TOTAL_TYPES                (ACPI_TYPE_NS_NODE_MAX + 1)
#define ACPI_TO_INTEGER(p)              ACPI_PTR_DIFF (p, (void *) 0)
#define ACPI_TO_POINTER(i)              ACPI_CAST_PTR (void, (ACPI_SIZE) (i))
#define ACPI_TYPE_ANY                   0x00
#define ACPI_TYPE_BUFFER                0x03
#define ACPI_TYPE_BUFFER_FIELD          0x0E
#define ACPI_TYPE_DDB_HANDLE            0x0F
#define ACPI_TYPE_DEBUG_OBJECT          0x10
#define ACPI_TYPE_DEVICE                0x06  
#define ACPI_TYPE_EVENT                 0x07
#define ACPI_TYPE_EXTERNAL_MAX          0x10
#define ACPI_TYPE_FIELD_UNIT            0x05
#define ACPI_TYPE_INTEGER               0x01  
#define ACPI_TYPE_INVALID               0x1E
#define ACPI_TYPE_LOCAL_ADDRESS_HANDLER 0x18
#define ACPI_TYPE_LOCAL_ALIAS           0x15
#define ACPI_TYPE_LOCAL_BANK_FIELD      0x12
#define ACPI_TYPE_LOCAL_DATA            0x1D
#define ACPI_TYPE_LOCAL_EXTRA           0x1C
#define ACPI_TYPE_LOCAL_INDEX_FIELD     0x13
#define ACPI_TYPE_LOCAL_MAX             0x1D
#define ACPI_TYPE_LOCAL_METHOD_ALIAS    0x16
#define ACPI_TYPE_LOCAL_NOTIFY          0x17
#define ACPI_TYPE_LOCAL_REFERENCE       0x14  
#define ACPI_TYPE_LOCAL_REGION_FIELD    0x11
#define ACPI_TYPE_LOCAL_RESOURCE        0x19
#define ACPI_TYPE_LOCAL_RESOURCE_FIELD  0x1A
#define ACPI_TYPE_LOCAL_SCOPE           0x1B  
#define ACPI_TYPE_METHOD                0x08  
#define ACPI_TYPE_MUTEX                 0x09
#define ACPI_TYPE_NOT_FOUND             0xFF
#define ACPI_TYPE_NS_NODE_MAX           0x1B  
#define ACPI_TYPE_PACKAGE               0x04  
#define ACPI_TYPE_POWER                 0x0B  
#define ACPI_TYPE_PROCESSOR             0x0C  
#define ACPI_TYPE_REGION                0x0A
#define ACPI_TYPE_STRING                0x02
#define ACPI_TYPE_THERMAL               0x0D  
#define ACPI_UINT16_MAX                 (UINT16)(~((UINT16) 0)) 
#define ACPI_UINT32_MAX                 (UINT32)(~((UINT32) 0)) 
#define ACPI_UINT64_MAX                 (UINT64)(~((UINT64) 0)) 
#define ACPI_UINT8_MAX                  (UINT8) (~((UINT8)  0)) 
#define ACPI_UINTPTR_T                  void *

#define ACPI_USEC_PER_MSEC              1000L
#define ACPI_USEC_PER_SEC               1000000L
#define ACPI_USE_NATIVE_DIVIDE          
#define ACPI_USE_NATIVE_MATH64          
#define ACPI_UUID_LENGTH                16
#define ACPI_VALIDATE_RSDP_SIG(a)       (!strncmp (ACPI_CAST_PTR (char, (a)), ACPI_SIG_RSDP, 8))
#define ACPI_VALID_ADR                  0x0002
#define ACPI_VALID_CID                  0x0020
#define ACPI_VALID_CLS                  0x0040
#define ACPI_VALID_HID                  0x0004
#define ACPI_VALID_SXDS                 0x0100
#define ACPI_VALID_SXWS                 0x0200
#define ACPI_VALID_UID                  0x0008
#define ACPI_VENDOR_STRINGS                 0x01
#define ACPI_WAIT_FOREVER               0xFFFF  
#define ACPI_WRITE                      1
#define AcpiOsAcquireMutex(Handle,Time) AcpiOsWaitSemaphore (Handle, 1, Time)
#define AcpiOsCreateMutex(OutHandle)    AcpiOsCreateSemaphore (1, 1, OutHandle)
#define AcpiOsDeleteMutex(Handle)       (void) AcpiOsDeleteSemaphore (Handle)
#define AcpiOsReleaseMutex(Handle)      (void) AcpiOsSignalSemaphore (Handle, 1)
#define FALSE                           (1 == 0)
#define NULL                            (void *) 0
#define PCI_EXPRESS_ROOT_HID_STRING     "PNP0A08"
#define PCI_ROOT_HID_STRING             "PNP0A03"
#define TRUE                            (1 == 1)

#define ACPI_ADDRESS_RANGE_MAX          2
#define ACPI_CA_SUPPORT_LEVEL           5
#define ACPI_CHECKSUM_ABORT             FALSE
#define ACPI_DB_LINE_BUFFER_SIZE        512
#define ACPI_DEBUGGER_COMMAND_PROMPT    '-'
#define ACPI_DEBUGGER_EXECUTE_PROMPT    '%'
#define ACPI_DEBUGGER_MAX_ARGS          ACPI_METHOD_NUM_ARGS + 4 
#define ACPI_DEFAULT_PAGE_SIZE          4096    
#define ACPI_EBDA_PTR_LENGTH            2
#define ACPI_EBDA_PTR_LOCATION          0x0000040E     
#define ACPI_EBDA_WINDOW_SIZE           1024
#define ACPI_HI_RSDP_WINDOW_BASE        0x000E0000     
#define ACPI_HI_RSDP_WINDOW_SIZE        0x00020000
#define ACPI_IPMI_BUFFER_SIZE           ACPI_SERIAL_HEADER_SIZE + ACPI_IPMI_DATA_SIZE
#define ACPI_IPMI_DATA_SIZE             64
#define ACPI_MAX_ADDRESS_SPACE          255
#define ACPI_MAX_COMMENT_CACHE_DEPTH    96          
#define ACPI_MAX_EXTPARSE_CACHE_DEPTH   96          
#define ACPI_MAX_GSBUS_BUFFER_SIZE      ACPI_SERIAL_HEADER_SIZE + ACPI_MAX_GSBUS_DATA_SIZE
#define ACPI_MAX_GSBUS_DATA_SIZE        255
#define ACPI_MAX_LOOP_TIMEOUT           30
#define ACPI_MAX_MATCH_OPCODE           5
#define ACPI_MAX_NAMESPACE_CACHE_DEPTH  96          
#define ACPI_MAX_OBJECT_CACHE_DEPTH     96          
#define ACPI_MAX_PARSE_CACHE_DEPTH      96          
#define ACPI_MAX_REFERENCE_COUNT        0x4000
#define ACPI_MAX_SEMAPHORE_COUNT        256
#define ACPI_MAX_SLEEP                  2000    
#define ACPI_MAX_STATE_CACHE_DEPTH      96          
#define ACPI_METHOD_MAX_ARG             6
#define ACPI_METHOD_MAX_LOCAL           7
#define ACPI_METHOD_NUM_ARGS            7
#define ACPI_METHOD_NUM_LOCALS          8
#define ACPI_NUM_DEFAULT_SPACES         4
#define ACPI_NUM_OWNERID_MASKS          128
#define ACPI_NUM_SxD_METHODS            4
#define ACPI_NUM_SxW_METHODS            5
#define ACPI_OBJ_MAX_OPERAND            7
#define ACPI_OBJ_NUM_OPERANDS           8
#define ACPI_OS_NAME                    "Microsoft Windows NT"
#define ACPI_REDUCED_HARDWARE           FALSE
#define ACPI_RESULTS_FRAME_OBJ_NUM      8
#define ACPI_RESULTS_OBJ_NUM_MAX        255
#define ACPI_ROOT_TABLE_SIZE_INCREMENT  4
#define ACPI_RSDP_CHECKSUM_LENGTH       20
#define ACPI_RSDP_SCAN_STEP             16
#define ACPI_RSDP_XCHECKSUM_LENGTH      36
#define ACPI_SERIAL_HEADER_SIZE         2   
#define ACPI_SMBUS_BUFFER_SIZE          ACPI_SERIAL_HEADER_SIZE + ACPI_SMBUS_DATA_SIZE
#define ACPI_SMBUS_DATA_SIZE            32
#define ACPI_USER_REGION_BEGIN          0x80
#define UUID_BUFFER_LENGTH          16 
#define UUID_HYPHEN1_OFFSET         8
#define UUID_HYPHEN2_OFFSET         13
#define UUID_HYPHEN3_OFFSET         18
#define UUID_HYPHEN4_OFFSET         23
#define UUID_STRING_LENGTH          36 

#define ACPI_MUTEX_SEM              1
#define ACPI_NO_UNIT_LIMIT          ((UINT32) -1)
#define ACPI_SIGNAL_BREAKPOINT      1
#define ACPI_SIGNAL_FATAL           0
#define REQUEST_DIR_ONLY                    1
#define REQUEST_FILE_ONLY                   0


#define ACPI_ACQUIRE_GLOBAL_LOCK(GLptr, Acquired) Acquired = 1

#define ACPI_BINARY_SEMAPHORE       0



#define ACPI_DEBUGGER 1

#define ACPI_DISASSEMBLER 1

#define ACPI_FILE              FILE *
#define ACPI_FILE_ERR          stderr
#define ACPI_FILE_OUT          stdout








#define ACPI_MUTEX_TYPE             ACPI_BINARY_SEMAPHORE

#define ACPI_OSL_MUTEX              1
#define ACPI_RELEASE_GLOBAL_LOCK(GLptr, Pending) Pending = 0

#define ACPI_STRUCT_INIT(field, value)  value




#define COMPILER_DEPENDENT_INT64   long long
#define COMPILER_DEPENDENT_UINT64  unsigned long long
#define DEBUGGER_MULTI_THREADED     1
#define DEBUGGER_SINGLE_THREADED    0
#define DEBUGGER_THREADING          DEBUGGER_MULTI_THREADED








#define XLOCALE_ISCTYPE(__fname, __cat) \
		_XLOCALE_INLINE int is##__fname##_l(int, locale_t); \
		_XLOCALE_INLINE int is##__fname##_l(int __c, locale_t __l)\
		{ return __sbistype_l(__c, __cat, __l); }

#define _XLOCALE_INLINE extern __inline
#define _XLOCALE_RUN_FUNCTIONS_DEFINED 1

#define _CurrentRuneLocale (__getCurrentRuneLocale())





#define alloca(sz) __builtin_alloca(sz)
#define MB_CUR_MAX_L(x) ((size_t)___mb_cur_max_l(x))
#define ACPI_CAST_PTHREAD_T(pthread)    ((ACPI_THREAD_ID) ACPI_TO_INTEGER (pthread))
#define ACPI_MACHINE_WIDTH      64





#define CALLOUT_HANDLE_INITIALIZER(handle)	\
	{ NULL }

#define __gone_ok(m, msg)					 \
	_Static_assert(m < P_OSREL_MAJOR(__FreeBSD_version)),	 \
	    "Obsolete code" msg);
#define bcmp(b1, b2, len) __builtin_memcmp((b1), (b2), (len))
#define bcopy(from, to, len) __builtin_memmove((to), (from), (len))
#define bcopy_early(from, to, len) memmove_early((to), (from), (len))
#define bzero(buf, len) __builtin_memset((buf), 0, (len))
#define bzero_early(buf, len) memset_early((buf), 0, (len))
#define critical_enter() critical_enter_KBI()
#define critical_exit() critical_exit_KBI()
#define gone_in(major, msg)		__gone_ok(major, msg) _gone_in(major, msg)
#define gone_in_dev(dev, major, msg)	__gone_ok(major, msg) _gone_in_dev(dev, major, msg)
#define memcmp(b1, b2, len) __builtin_memcmp((b1), (b2), (len))
#define memcpy(to, from, len) __builtin_memcpy((to), (from), (len))
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#define memset(buf, c, len) __builtin_memset((buf), (c), (len))
#define ovbcopy(f, t, l) bcopy((f), (t), (l))

#define zpcpu_replace_cpu(base, val, cpu) ({				\
	__typeof(val) _old = *(__typeof(val) *)zpcpu_get_cpu(base, cpu);\
	*(__typeof(val) *)zpcpu_get_cpu(base, cpu) = val;		\
	_old;								\
})


#define __min_size(x)	static (x)

#define LIST_CONCAT(head1, head2, type, field) do {			      \
	QUEUE_TYPEOF(type) *curelm = LIST_FIRST(head1);			      \
	if (curelm == NULL) {						      \
		if ((LIST_FIRST(head1) = LIST_FIRST(head2)) != NULL) {	      \
			LIST_FIRST(head2)->field.le_prev =		      \
			    &LIST_FIRST((head1));			      \
			LIST_INIT(head2);				      \
		}							      \
	} else if (LIST_FIRST(head2) != NULL) {				      \
		while (LIST_NEXT(curelm, field) != NULL)		      \
			curelm = LIST_NEXT(curelm, field);		      \
		LIST_NEXT(curelm, field) = LIST_FIRST(head2);		      \
		LIST_FIRST(head2)->field.le_prev = &LIST_NEXT(curelm, field); \
		LIST_INIT(head2);					      \
	}								      \
} while (0)
#define LIST_SWAP(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *swap_tmp = LIST_FIRST(head1);		\
	LIST_FIRST((head1)) = LIST_FIRST((head2));			\
	LIST_FIRST((head2)) = swap_tmp;					\
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head1));		\
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head2));		\
} while (0)
#define SLIST_CONCAT(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *curelm = SLIST_FIRST(head1);		\
	if (curelm == NULL) {						\
		if ((SLIST_FIRST(head1) = SLIST_FIRST(head2)) != NULL)	\
			SLIST_INIT(head2);				\
	} else if (SLIST_FIRST(head2) != NULL) {			\
		while (SLIST_NEXT(curelm, field) != NULL)		\
			curelm = SLIST_NEXT(curelm, field);		\
		SLIST_NEXT(curelm, field) = SLIST_FIRST(head2);		\
		SLIST_INIT(head2);					\
	}								\
} while (0)
#define SLIST_REMOVE_AFTER(elm, field) do {				\
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
} while (0)
#define SLIST_SWAP(head1, head2, type) do {				\
	QUEUE_TYPEOF(type) *swap_first = SLIST_FIRST(head1);		\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)
#define STAILQ_SWAP(head1, head2, type) do {				\
	QUEUE_TYPEOF(type) *swap_first = STAILQ_FIRST(head1);		\
	QUEUE_TYPEOF(type) **swap_last = (head1)->stqh_last;		\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
} while (0)
#define TAILQ_SWAP(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *swap_first = (head1)->tqh_first;		\
	QUEUE_TYPEOF(type) **swap_last = (head1)->tqh_last;		\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)


#define BITSET_DEFINE_VAR(t)	BITSET_DEFINE(t, 1)
#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1300057	
#define __PAST_END(array, offset) (((__typeof__(*(array)) *)(array))[offset])
#define btoc(x)	(((vm_offset_t)(x)+PAGE_MASK)>>PAGE_SHIFT)
#define btodb(bytes)	 		 \
	(sizeof (bytes) > sizeof(long) \
	 ? (daddr_t)((unsigned long long)(bytes) >> DEV_BSHIFT) \
	 : (daddr_t)((unsigned long)(bytes) >> DEV_BSHIFT))
#define ctob(x)	((x)<<PAGE_SHIFT)
#define ctodb(db)			 \
	((db) << (PAGE_SHIFT - DEV_BSHIFT))
#define dbtob(db)			 \
	((off_t)(db) << DEV_BSHIFT)
#define dbtoc(db)			 \
	((db + (ctodb(1) - 1)) >> (PAGE_SHIFT - DEV_BSHIFT))
#define powerof2(x)	((((x)-1)&(x))==0)
#define ILL_BADSTK 	8	
#define ILL_COPROC 	7	
#define ILL_ILLADR 	3	
#define ILL_ILLOPC 	1	
#define ILL_ILLOPN 	2	
#define ILL_ILLTRP 	4	
#define ILL_PRVOPC 	5	
#define ILL_PRVREG 	6	
#define SIG_HOLD        ((__sighandler_t *)3)


#define MSEC_2_TICKS(m) max(1, (uint32_t)((hz == 1000) ? \
	  (m) : ((uint64_t)(m) * (uint64_t)hz)/(uint64_t)1000))
#define TICKS_2_MSEC(t) max(1, (uint32_t)(hz == 1000) ? \
	  (t) : (((uint64_t)(t) * (uint64_t)1000)/(uint64_t)hz))
#define TICKS_2_USEC(t) max(1, (uint32_t)(hz == 1000) ? \
	  ((t) * 1000) : (((uint64_t)(t) * (uint64_t)1000000)/(uint64_t)hz))
#define USEC_2_TICKS(u) max(1, (uint32_t)((hz == 1000) ? \
	 ((u) / 1000) : ((uint64_t)(u) * (uint64_t)hz)/(uint64_t)1000000))

#define offsetof(type, field) __offsetof(type, field)



#define RSIZE_MAX (SIZE_MAX >> 1)


#define callout_async_drain(c, d)					\
    _callout_stop_safe(c, 0, d)
#define ACPI_GET_FUNCTION_NAME          __func__
#define COMPILER_VA_MACRO               1

#define va_arg(v, l)            __builtin_va_arg(v, l)
#define va_copy(d, s)           __builtin_va_copy(d, s)
#define va_end(v)               __builtin_va_end(v)
#define va_start(v, l)          __builtin_va_start(v, l)
#define ACPI_ACCEPTABLE_CONFIGURATION   (UINT8) 0x01
#define ACPI_ACTIVE_BOTH                (UINT8) 0x02
#define ACPI_ACTIVE_HIGH                (UINT8) 0x00
#define ACPI_ACTIVE_LOW                 (UINT8) 0x01
#define ACPI_ADDRESS_FIXED              (UINT8) 0x01
#define ACPI_ADDRESS_NOT_FIXED          (UINT8) 0x00
#define ACPI_BUS_MASTER                 (UINT8) 0x01
#define ACPI_BUS_NUMBER_RANGE           (UINT8) 0x02
#define ACPI_CACHABLE_MEMORY            (UINT8) 0x01
#define ACPI_COMPATIBILITY              (UINT8) 0x00
#define ACPI_CONSUMER                   (UINT8) 0x01
#define ACPI_CONTROLLER_INITIATED               0
#define ACPI_DECODE_10                  (UINT8) 0x00    
#define ACPI_DECODE_16                  (UINT8) 0x01    
#define ACPI_DEVICE_INITIATED                   1
#define ACPI_DMA_WIDTH128                       4
#define ACPI_DMA_WIDTH16                        1
#define ACPI_DMA_WIDTH256                       5
#define ACPI_DMA_WIDTH32                        2
#define ACPI_DMA_WIDTH64                        3
#define ACPI_DMA_WIDTH8                         0
#define ACPI_EDGE_SENSITIVE             (UINT8) 0x01
#define ACPI_ENTIRE_RANGE               (ACPI_NON_ISA_ONLY_RANGES | ACPI_ISA_ONLY_RANGES)
#define ACPI_EXCLUSIVE                  (UINT8) 0x00
#define ACPI_GOOD_CONFIGURATION         (UINT8) 0x00
#define ACPI_I2C_10BIT_MODE                     1
#define ACPI_I2C_7BIT_MODE                      0
#define ACPI_IO_RANGE                   (UINT8) 0x01
#define ACPI_IO_RESTRICT_INPUT                  1
#define ACPI_IO_RESTRICT_NONE                   0
#define ACPI_IO_RESTRICT_NONE_PRESERVE          3
#define ACPI_IO_RESTRICT_OUTPUT                 2
#define ACPI_ISA_ONLY_RANGES            (UINT8) 0x02
#define ACPI_LEVEL_SENSITIVE            (UINT8) 0x00
#define ACPI_MEMORY_RANGE               (UINT8) 0x00
#define ACPI_NEXT_RESOURCE(Res) \
    ACPI_ADD_PTR (ACPI_RESOURCE, (Res), (Res)->Length)
#define ACPI_NON_CACHEABLE_MEMORY       (UINT8) 0x00
#define ACPI_NON_ISA_ONLY_RANGES        (UINT8) 0x01
#define ACPI_NOT_BUS_MASTER             (UINT8) 0x00
#define ACPI_NOT_WAKE_CAPABLE           (UINT8) 0x00
#define ACPI_PIN_CONFIG_BIAS_BUS_HOLD           6
#define ACPI_PIN_CONFIG_BIAS_DEFAULT            3
#define ACPI_PIN_CONFIG_BIAS_DISABLE            4
#define ACPI_PIN_CONFIG_BIAS_HIGH_IMPEDANCE     5
#define ACPI_PIN_CONFIG_BIAS_PULL_DOWN          2
#define ACPI_PIN_CONFIG_BIAS_PULL_UP            1
#define ACPI_PIN_CONFIG_DEFAULT                 0
#define ACPI_PIN_CONFIG_DRIVE_OPEN_DRAIN        7
#define ACPI_PIN_CONFIG_DRIVE_OPEN_SOURCE       8
#define ACPI_PIN_CONFIG_DRIVE_PUSH_PULL         9
#define ACPI_PIN_CONFIG_DRIVE_STRENGTH          10
#define ACPI_PIN_CONFIG_INPUT_DEBOUNCE          12
#define ACPI_PIN_CONFIG_INPUT_SCHMITT_TRIGGER   13
#define ACPI_PIN_CONFIG_NOPULL                  3
#define ACPI_PIN_CONFIG_PULLDOWN                2
#define ACPI_PIN_CONFIG_PULLUP                  1
#define ACPI_PIN_CONFIG_SLEW_RATE               11
#define ACPI_POS_DECODE                 (UINT8) 0x00
#define ACPI_PREFETCHABLE_MEMORY        (UINT8) 0x03
#define ACPI_PRODUCER                   (UINT8) 0x00
#define ACPI_READ_ONLY_MEMORY           (UINT8) 0x00
#define ACPI_READ_WRITE_MEMORY          (UINT8) 0x01
#define ACPI_RESOURCE_ADDRESS_COMMON \
    UINT8                           ResourceType; \
    UINT8                           ProducerConsumer; \
    UINT8                           Decode; \
    UINT8                           MinAddressFixed; \
    UINT8                           MaxAddressFixed; \
    ACPI_RESOURCE_ATTRIBUTE         Info;
#define ACPI_RESOURCE_GPIO_TYPE_INT             0
#define ACPI_RESOURCE_GPIO_TYPE_IO              1
#define ACPI_RESOURCE_SERIAL_COMMON \
    UINT8                           RevisionId; \
    UINT8                           Type; \
    UINT8                           ProducerConsumer;    \
    UINT8                           SlaveMode; \
    UINT8                           ConnectionSharing; \
    UINT8                           TypeRevisionId; \
    UINT16                          TypeDataLength; \
    UINT16                          VendorLength; \
    ACPI_RESOURCE_SOURCE            ResourceSource; \
    UINT8                           *VendorData;
#define ACPI_RESOURCE_SERIAL_TYPE_I2C           1
#define ACPI_RESOURCE_SERIAL_TYPE_SPI           2
#define ACPI_RESOURCE_SERIAL_TYPE_UART          3
#define ACPI_RESOURCE_TYPE_ADDRESS16            11
#define ACPI_RESOURCE_TYPE_ADDRESS32            12
#define ACPI_RESOURCE_TYPE_ADDRESS64            13
#define ACPI_RESOURCE_TYPE_DMA                  1
#define ACPI_RESOURCE_TYPE_END_DEPENDENT        3
#define ACPI_RESOURCE_TYPE_END_TAG              7
#define ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64   14  
#define ACPI_RESOURCE_TYPE_EXTENDED_IRQ         15
#define ACPI_RESOURCE_TYPE_FIXED_DMA            18  
#define ACPI_RESOURCE_TYPE_FIXED_IO             5
#define ACPI_RESOURCE_TYPE_FIXED_MEMORY32       10
#define ACPI_RESOURCE_TYPE_GENERIC_REGISTER     16
#define ACPI_RESOURCE_TYPE_GPIO                 17  
#define ACPI_RESOURCE_TYPE_IO                   4
#define ACPI_RESOURCE_TYPE_IRQ                  0
#define ACPI_RESOURCE_TYPE_MAX                  24
#define ACPI_RESOURCE_TYPE_MEMORY24             8
#define ACPI_RESOURCE_TYPE_MEMORY32             9
#define ACPI_RESOURCE_TYPE_PIN_CONFIG           21  
#define ACPI_RESOURCE_TYPE_PIN_FUNCTION         20  
#define ACPI_RESOURCE_TYPE_PIN_GROUP            22  
#define ACPI_RESOURCE_TYPE_PIN_GROUP_CONFIG     24  
#define ACPI_RESOURCE_TYPE_PIN_GROUP_FUNCTION   23  
#define ACPI_RESOURCE_TYPE_SERIAL_BUS           19  
#define ACPI_RESOURCE_TYPE_START_DEPENDENT      2
#define ACPI_RESOURCE_TYPE_VENDOR               6
#define ACPI_RS_SIZE(Type)                  (UINT32) (ACPI_RS_SIZE_NO_DATA + sizeof (Type))
#define ACPI_RS_SIZE_MIN                    (UINT32) ACPI_ROUND_UP_TO_NATIVE_WORD (12)
#define ACPI_RS_SIZE_NO_DATA                8       
#define ACPI_SHARED                     (UINT8) 0x01
#define ACPI_SPARSE_TRANSLATION         (UINT8) 0x01
#define ACPI_SPI_3WIRE_MODE                     1
#define ACPI_SPI_4WIRE_MODE                     0
#define ACPI_SPI_ACTIVE_HIGH                    1
#define ACPI_SPI_ACTIVE_LOW                     0
#define ACPI_SPI_FIRST_PHASE                    0
#define ACPI_SPI_SECOND_PHASE                   1
#define ACPI_SPI_START_HIGH                     1
#define ACPI_SPI_START_LOW                      0
#define ACPI_SUB_DECODE                 (UINT8) 0x01
#define ACPI_SUB_OPTIMAL_CONFIGURATION  (UINT8) 0x02
#define ACPI_TRANSFER_16                (UINT8) 0x02
#define ACPI_TRANSFER_8                 (UINT8) 0x00
#define ACPI_TRANSFER_8_16              (UINT8) 0x01
#define ACPI_TYPE_A                     (UINT8) 0x01
#define ACPI_TYPE_B                     (UINT8) 0x02
#define ACPI_TYPE_F                     (UINT8) 0x03
#define ACPI_UART_1P5_STOP_BITS                 2
#define ACPI_UART_1_STOP_BIT                    1
#define ACPI_UART_2_STOP_BITS                   3
#define ACPI_UART_5_DATA_BITS                   0
#define ACPI_UART_6_DATA_BITS                   1
#define ACPI_UART_7_DATA_BITS                   2
#define ACPI_UART_8_DATA_BITS                   3
#define ACPI_UART_9_DATA_BITS                   4
#define ACPI_UART_BIG_ENDIAN                    1
#define ACPI_UART_CARRIER_DETECT                (1<<2)
#define ACPI_UART_CLEAR_TO_SEND                 (1<<6)
#define ACPI_UART_DATA_SET_READY                (1<<4)
#define ACPI_UART_DATA_TERMINAL_READY           (1<<5)
#define ACPI_UART_FLOW_CONTROL_HW               1
#define ACPI_UART_FLOW_CONTROL_NONE             0
#define ACPI_UART_FLOW_CONTROL_XON_XOFF         2
#define ACPI_UART_LITTLE_ENDIAN                 0
#define ACPI_UART_NO_STOP_BITS                  0
#define ACPI_UART_PARITY_EVEN                   1
#define ACPI_UART_PARITY_MARK                   3
#define ACPI_UART_PARITY_NONE                   0
#define ACPI_UART_PARITY_ODD                    2
#define ACPI_UART_PARITY_SPACE                  4
#define ACPI_UART_REQUEST_TO_SEND               (1<<7)
#define ACPI_UART_RING_INDICATOR                (1<<3)
#define ACPI_WAKE_CAPABLE               (UINT8) 0x01
#define ACPI_WRITE_COMBINING_MEMORY     (UINT8) 0x02

#define ACPI_ACTUAL_DEBUG(Level, Line, Filename, Modulename, Component, ...) \
    ACPI_DO_DEBUG_PRINT (AcpiDebugPrint, Level, Line, \
        Filename, Modulename, Component, __VA_ARGS__)
#define ACPI_ACTUAL_DEBUG_RAW(Level, Line, Filename, Modulename, Component, ...) \
    ACPI_DO_DEBUG_PRINT (AcpiDebugPrintRaw, Level, Line, \
        Filename, Modulename, Component, __VA_ARGS__)
#define ACPI_ALL_COMPONENTS         0x0001FFFF
#define ACPI_ALL_DRIVERS            0xFFFF0000
#define ACPI_BIOS_ERROR(plist)          AcpiBiosError plist
#define ACPI_BIOS_EXCEPTION(plist)      AcpiBiosException plist
#define ACPI_BIOS_WARNING(plist)        AcpiBiosWarning plist
#define ACPI_CA_DEBUGGER            0x00000200
#define ACPI_CA_DISASSEMBLER        0x00000800
#define ACPI_COMPILER               0x00001000
#define ACPI_COMPONENT_DEFAULT      (ACPI_ALL_COMPONENTS)
#define ACPI_DB_ALL                 ACPI_DEBUG_LEVEL (ACPI_LV_ALL)
#define ACPI_DB_ALLOCATIONS         ACPI_DEBUG_LEVEL (ACPI_LV_ALLOCATIONS)
#define ACPI_DB_ALL_EXCEPTIONS      ACPI_DEBUG_LEVEL (ACPI_LV_ALL_EXCEPTIONS)
#define ACPI_DB_BFIELD              ACPI_DEBUG_LEVEL (ACPI_LV_BFIELD)
#define ACPI_DB_DEBUG_OBJECT        ACPI_DEBUG_LEVEL (ACPI_LV_DEBUG_OBJECT)
#define ACPI_DB_DISPATCH            ACPI_DEBUG_LEVEL (ACPI_LV_DISPATCH)
#define ACPI_DB_EVALUATION          ACPI_DEBUG_LEVEL (ACPI_LV_EVALUATION)
#define ACPI_DB_EVENTS              ACPI_DEBUG_LEVEL (ACPI_LV_EVENTS)
#define ACPI_DB_EXEC                ACPI_DEBUG_LEVEL (ACPI_LV_EXEC)
#define ACPI_DB_FUNCTIONS           ACPI_DEBUG_LEVEL (ACPI_LV_FUNCTIONS)
#define ACPI_DB_INFO                ACPI_DEBUG_LEVEL (ACPI_LV_INFO)
#define ACPI_DB_INIT                ACPI_DEBUG_LEVEL (ACPI_LV_INIT)
#define ACPI_DB_INIT_NAMES          ACPI_DEBUG_LEVEL (ACPI_LV_INIT_NAMES)
#define ACPI_DB_INTERRUPTS          ACPI_DEBUG_LEVEL (ACPI_LV_INTERRUPTS)
#define ACPI_DB_IO                  ACPI_DEBUG_LEVEL (ACPI_LV_IO)
#define ACPI_DB_LOAD                ACPI_DEBUG_LEVEL (ACPI_LV_LOAD)
#define ACPI_DB_MUTEX               ACPI_DEBUG_LEVEL (ACPI_LV_MUTEX)
#define ACPI_DB_NAMES               ACPI_DEBUG_LEVEL (ACPI_LV_NAMES)
#define ACPI_DB_OBJECTS             ACPI_DEBUG_LEVEL (ACPI_LV_OBJECTS)
#define ACPI_DB_OPREGION            ACPI_DEBUG_LEVEL (ACPI_LV_OPREGION)
#define ACPI_DB_OPTIMIZATIONS       ACPI_DEBUG_LEVEL (ACPI_LV_OPTIMIZATIONS)
#define ACPI_DB_PACKAGE             ACPI_DEBUG_LEVEL (ACPI_LV_PACKAGE)
#define ACPI_DB_PARSE               ACPI_DEBUG_LEVEL (ACPI_LV_PARSE)
#define ACPI_DB_PARSE_TREES         ACPI_DEBUG_LEVEL (ACPI_LV_PARSE_TREES)
#define ACPI_DB_REPAIR              ACPI_DEBUG_LEVEL (ACPI_LV_REPAIR)
#define ACPI_DB_RESOURCES           ACPI_DEBUG_LEVEL (ACPI_LV_RESOURCES)
#define ACPI_DB_TABLES              ACPI_DEBUG_LEVEL (ACPI_LV_TABLES)
#define ACPI_DB_THREADS             ACPI_DEBUG_LEVEL (ACPI_LV_THREADS)
#define ACPI_DB_TRACE_POINT         ACPI_DEBUG_LEVEL (ACPI_LV_TRACE_POINT)
#define ACPI_DB_USER_REQUESTS       ACPI_DEBUG_LEVEL (ACPI_LV_USER_REQUESTS)
#define ACPI_DB_VALUES              ACPI_DEBUG_LEVEL (ACPI_LV_VALUES)
#define ACPI_DEBUG_ALL              (ACPI_LV_AML_DISASSEMBLE | ACPI_LV_ALL_EXCEPTIONS | ACPI_LV_ALL)
#define ACPI_DEBUG_DEFAULT          (ACPI_LV_INIT | ACPI_LV_DEBUG_OBJECT | ACPI_LV_EVALUATION | ACPI_LV_REPAIR)
#define ACPI_DEBUG_EXEC(a)              a
#define ACPI_DEBUG_LEVEL(dl)        (UINT32) dl,ACPI_DEBUG_PARAMETERS
#define ACPI_DEBUG_OBJECT(obj,l,i)      AcpiExDoDebugObject(obj,l,i)
#define ACPI_DEBUG_ONLY_MEMBERS(a)      a;
#define ACPI_DEBUG_PARAMETERS \
    "__LINE__", ACPI_GET_FUNCTION_NAME, _AcpiModuleName, _COMPONENT
#define ACPI_DEBUG_PRINT(plist)         AcpiDebugPrint plist
#define ACPI_DEBUG_PRINT_RAW(plist)     AcpiDebugPrintRaw plist
#define ACPI_DISPATCHER             0x00000040
#define ACPI_DO_DEBUG_PRINT(Function, Level, Line, Filename, Modulename, Component, ...) \
    ACPI_DO_WHILE0 ({ \
        if (ACPI_IS_DEBUG_ENABLED (Level, Component)) \
        { \
            Function (Level, Line, Filename, Modulename, Component, __VA_ARGS__); \
        } \
    })
#define ACPI_DO_WHILE0(a)               do a while(0)
#define ACPI_DRIVER                 0x00008000
#define ACPI_DUMP_BUFFER(a, b)          AcpiUtDebugDumpBuffer((UINT8 *) a, b, DB_BYTE_DISPLAY, _COMPONENT)
#define ACPI_DUMP_ENTRY(a, b)           AcpiNsDumpEntry (a, b)
#define ACPI_DUMP_OPERANDS(a, b ,c)     AcpiExDumpOperands(a, b, c)
#define ACPI_DUMP_PATHNAME(a, b, c, d)  AcpiNsDumpPathname(a, b, c, d)
#define ACPI_DUMP_STACK_ENTRY(a)        AcpiExDumpOperand((a), 0)
#define ACPI_ERROR(plist)               AcpiError plist
#define ACPI_EVENTS                 0x00000004
#define ACPI_EXAMPLE                0x00004000
#define ACPI_EXCEPTION(plist)           AcpiException plist
#define ACPI_EXECUTER               0x00000080
#define ACPI_FUNCTION_ENTRY() \
    AcpiUtTrackStackPtr()
#define ACPI_FUNCTION_NAME(Name)        static const char _AcpiFunctionName[] = #Name;
#define ACPI_FUNCTION_TRACE(Name) \
    ACPI_FUNCTION_NAME(Name) \
    AcpiUtTrace (ACPI_DEBUG_PARAMETERS)
#define ACPI_FUNCTION_TRACE_PTR(Name, Pointer) \
    ACPI_TRACE_ENTRY (Name, AcpiUtTracePtr, void *, Pointer)
#define ACPI_FUNCTION_TRACE_STR(Name, String) \
    ACPI_TRACE_ENTRY (Name, AcpiUtTraceStr, const char *, String)
#define ACPI_FUNCTION_TRACE_U32(Name, Value) \
    ACPI_TRACE_ENTRY (Name, AcpiUtTraceU32, UINT32, Value)
#define ACPI_GET_FUNCTION_NAME          _AcpiFunctionName
#define ACPI_HARDWARE               0x00000002
#define ACPI_INFO(plist)                AcpiInfo plist
#define ACPI_IS_DEBUG_ENABLED(Level, Component) \
    ((Level & AcpiDbgLevel) && (Component & AcpiDbgLayer))
#define ACPI_LV_ALL                 ACPI_LV_VERBOSITY2
#define ACPI_LV_ALLOCATIONS         0x00100000
#define ACPI_LV_ALL_EXCEPTIONS      0x0000001F
#define ACPI_LV_AML_DISASSEMBLE     0x10000000
#define ACPI_LV_BFIELD              0x00001000
#define ACPI_LV_DEBUG_OBJECT        0x00000002
#define ACPI_LV_DISPATCH            0x00000100
#define ACPI_LV_EVALUATION          0x00080000
#define ACPI_LV_EVENTS              0x80000000
#define ACPI_LV_EXEC                0x00000200
#define ACPI_LV_FULL_TABLES         0x40000000
#define ACPI_LV_FUNCTIONS           0x00200000
#define ACPI_LV_INFO                0x00000004
#define ACPI_LV_INIT                0x00000001
#define ACPI_LV_INIT_NAMES          0x00000020
#define ACPI_LV_INTERRUPTS          0x08000000
#define ACPI_LV_IO                  0x04000000
#define ACPI_LV_LOAD                0x00000080
#define ACPI_LV_MUTEX               0x01000000
#define ACPI_LV_NAMES               0x00000400
#define ACPI_LV_OBJECTS             0x00008000
#define ACPI_LV_OPREGION            0x00000800
#define ACPI_LV_OPTIMIZATIONS       0x00400000
#define ACPI_LV_PACKAGE             0x00040000
#define ACPI_LV_PARSE               0x00000040
#define ACPI_LV_PARSE_TREES         0x00800000
#define ACPI_LV_REPAIR              0x00000008
#define ACPI_LV_RESOURCES           0x00010000
#define ACPI_LV_TABLES              0x00002000
#define ACPI_LV_THREADS             0x02000000
#define ACPI_LV_TRACE_POINT         0x00000010
#define ACPI_LV_USER_REQUESTS       0x00020000
#define ACPI_LV_VALUES              0x00004000
#define ACPI_LV_VERBOSE             0xF0000000
#define ACPI_LV_VERBOSE_INFO        0x20000000
#define ACPI_LV_VERBOSITY1          0x000FFF40 | ACPI_LV_ALL_EXCEPTIONS
#define ACPI_LV_VERBOSITY2          0x00F00000 | ACPI_LV_VERBOSITY1
#define ACPI_LV_VERBOSITY3          0x0F000000 | ACPI_LV_VERBOSITY2
#define ACPI_MODULE_NAME(Name)          static const char ACPI_UNUSED_VAR _AcpiModuleName[] = Name;
#define ACPI_NAMESPACE              0x00000010
#define ACPI_NORMAL_DEFAULT         (ACPI_LV_INIT | ACPI_LV_DEBUG_OBJECT | ACPI_LV_REPAIR)
#define ACPI_OS_SERVICES            0x00000400
#define ACPI_PARSER                 0x00000020
#define ACPI_RESOURCES              0x00000100
#define ACPI_TABLES                 0x00000008
#define ACPI_TOOLS                  0x00002000
#define ACPI_TRACE_ENABLED          ((UINT32) 4)
#define ACPI_TRACE_ENTRY(Name, Function, Type, Param) \
    ACPI_FUNCTION_NAME (Name) \
    Function (ACPI_DEBUG_PARAMETERS, (Type) (Param))
#define ACPI_TRACE_EXIT(Function, Type, Param) \
    ACPI_DO_WHILE0 ({ \
        register Type _Param = (Type) (Param); \
        Function (ACPI_DEBUG_PARAMETERS, _Param); \
        return (_Param); \
    })
#define ACPI_TRACE_LAYER_ALL        0x000001FF
#define ACPI_TRACE_LAYER_DEFAULT    ACPI_EXECUTER
#define ACPI_TRACE_LEVEL_ALL        ACPI_LV_ALL
#define ACPI_TRACE_LEVEL_DEFAULT    ACPI_LV_TRACE_POINT
#define ACPI_TRACE_ONESHOT          ((UINT32) 2)
#define ACPI_TRACE_OPCODE           ((UINT32) 1)
#define ACPI_TRACE_POINT(a, b, c, d)    AcpiTracePoint (a, b, c, d)
#define ACPI_UTILITIES              0x00000001
#define ACPI_WARNING(plist)             AcpiWarning plist
#define AE_INFO                         _AcpiModuleName, "__LINE__"
#define ASL_PREPROCESSOR            0x00020000
#define DT_COMPILER                 0x00010000
#define _AcpiModuleName ""


#define return_ACPI_STATUS(Status) \
    ACPI_TRACE_EXIT (AcpiUtStatusExit, ACPI_STATUS, Status)
#define return_PTR(Pointer) \
    ACPI_TRACE_EXIT (AcpiUtPtrExit, void *, Pointer)
#define return_STR(String) \
    ACPI_TRACE_EXIT (AcpiUtStrExit, const char *, String)
#define return_UINT32(Value) \
    ACPI_TRACE_EXIT (AcpiUtValueExit, UINT32, Value)
#define return_UINT8(Value) \
    ACPI_TRACE_EXIT (AcpiUtValueExit, UINT8, Value)
#define return_VALUE(Value) \
    ACPI_TRACE_EXIT (AcpiUtValueExit, UINT64, Value)
#define return_VOID \
    ACPI_DO_WHILE0 ({ \
        AcpiUtExit (ACPI_DEBUG_PARAMETERS); \
        return; \
    })
#define ACPI_AML_EXCEPTION(Status)      (Status & AE_CODE_AML)
#define ACPI_CNTL_EXCEPTION(Status)     (Status & AE_CODE_CONTROL)
#define ACPI_ENV_EXCEPTION(Status)      (Status & AE_CODE_ENVIRONMENTAL)
#define ACPI_FAILURE(a)                 (a)
#define ACPI_PROG_EXCEPTION(Status)     (Status & AE_CODE_PROGRAMMER)
#define ACPI_SUCCESS(a)                 (!(a))
#define ACPI_TABLE_EXCEPTION(Status)    (Status & AE_CODE_ACPI_TABLES)
#define AE_ABORT_METHOD                 EXCEP_ENV (0x0018)
#define AE_ACCESS                       EXCEP_ENV (0x001D)
#define AE_ACQUIRE_DEADLOCK             EXCEP_ENV (0x0012)
#define AE_ALREADY_ACQUIRED             EXCEP_ENV (0x0015)
#define AE_ALREADY_EXISTS               EXCEP_ENV (0x0007)
#define AE_AML_ALIGNMENT                EXCEP_AML (0x001B)
#define AE_AML_BAD_NAME                 EXCEP_AML (0x000D)
#define AE_AML_BAD_OPCODE               EXCEP_AML (0x0001)
#define AE_AML_BAD_RESOURCE_LENGTH      EXCEP_AML (0x001F)
#define AE_AML_BAD_RESOURCE_VALUE       EXCEP_AML (0x001D)
#define AE_AML_BUFFER_LENGTH            EXCEP_AML (0x0025)
#define AE_AML_BUFFER_LIMIT             EXCEP_AML (0x000A)
#define AE_AML_CIRCULAR_REFERENCE       EXCEP_AML (0x001E)
#define AE_AML_DIVIDE_BY_ZERO           EXCEP_AML (0x000C)
#define AE_AML_ILLEGAL_ADDRESS          EXCEP_AML (0x0020)
#define AE_AML_INTERNAL                 EXCEP_AML (0x000F)
#define AE_AML_INVALID_INDEX            EXCEP_AML (0x0018)
#define AE_AML_INVALID_RESOURCE_TYPE    EXCEP_AML (0x0017)
#define AE_AML_INVALID_SPACE_ID         EXCEP_AML (0x0010)
#define AE_AML_LOOP_TIMEOUT             EXCEP_AML (0x0021)
#define AE_AML_METHOD_LIMIT             EXCEP_AML (0x0013)
#define AE_AML_MUTEX_NOT_ACQUIRED       EXCEP_AML (0x0016)
#define AE_AML_MUTEX_ORDER              EXCEP_AML (0x0015)
#define AE_AML_NAME_NOT_FOUND           EXCEP_AML (0x000E)
#define AE_AML_NOT_OWNER                EXCEP_AML (0x0014)
#define AE_AML_NO_OPERAND               EXCEP_AML (0x0002)
#define AE_AML_NO_RESOURCE_END_TAG      EXCEP_AML (0x001C)
#define AE_AML_NO_RETURN_VALUE          EXCEP_AML (0x0012)
#define AE_AML_NO_WHILE                 EXCEP_AML (0x001A)
#define AE_AML_NUMERIC_OVERFLOW         EXCEP_AML (0x0008)
#define AE_AML_OPERAND_TYPE             EXCEP_AML (0x0003)
#define AE_AML_OPERAND_VALUE            EXCEP_AML (0x0004)
#define AE_AML_PACKAGE_LIMIT            EXCEP_AML (0x000B)
#define AE_AML_PROTOCOL                 EXCEP_AML (0x0024)
#define AE_AML_REGION_LIMIT             EXCEP_AML (0x0009)
#define AE_AML_REGISTER_LIMIT           EXCEP_AML (0x0019)
#define AE_AML_STRING_LIMIT             EXCEP_AML (0x0011)
#define AE_AML_TARGET_TYPE              EXCEP_AML (0x0023)
#define AE_AML_UNINITIALIZED_ARG        EXCEP_AML (0x0006)
#define AE_AML_UNINITIALIZED_ELEMENT    EXCEP_AML (0x0007)
#define AE_AML_UNINITIALIZED_LOCAL      EXCEP_AML (0x0005)
#define AE_AML_UNINITIALIZED_NODE       EXCEP_AML (0x0022)
#define AE_BAD_ADDRESS                  EXCEP_PGM (0x0009)
#define AE_BAD_CHARACTER                EXCEP_PGM (0x0002)
#define AE_BAD_CHECKSUM                 EXCEP_TBL (0x0003)
#define AE_BAD_DATA                     EXCEP_PGM (0x0004)
#define AE_BAD_DECIMAL_CONSTANT         EXCEP_PGM (0x0007)
#define AE_BAD_HEADER                   EXCEP_TBL (0x0002)
#define AE_BAD_HEX_CONSTANT             EXCEP_PGM (0x0005)
#define AE_BAD_OCTAL_CONSTANT           EXCEP_PGM (0x0006)
#define AE_BAD_PARAMETER                EXCEP_PGM (0x0001)
#define AE_BAD_PATHNAME                 EXCEP_PGM (0x0003)
#define AE_BAD_SIGNATURE                EXCEP_TBL (0x0001)
#define AE_BAD_VALUE                    EXCEP_TBL (0x0004)
#define AE_BUFFER_OVERFLOW              EXCEP_ENV (0x000B)
#define AE_CODE_ACPI_TABLES             0x2000 
#define AE_CODE_AML                     0x3000 
#define AE_CODE_AML_MAX                 0x0025
#define AE_CODE_CONTROL                 0x4000 
#define AE_CODE_CTRL_MAX                0x000C
#define AE_CODE_ENVIRONMENTAL           0x0000 
#define AE_CODE_ENV_MAX                 0x0023
#define AE_CODE_MASK                    0xF000
#define AE_CODE_MAX                     0x4000
#define AE_CODE_PGM_MAX                 0x0009
#define AE_CODE_PROGRAMMER              0x1000 
#define AE_CODE_TBL_MAX                 0x0005
#define AE_CTRL_BREAK                   EXCEP_CTL (0x0009)
#define AE_CTRL_CONTINUE                EXCEP_CTL (0x000A)
#define AE_CTRL_DEPTH                   EXCEP_CTL (0x0006)
#define AE_CTRL_END                     EXCEP_CTL (0x0007)
#define AE_CTRL_FALSE                   EXCEP_CTL (0x0005)
#define AE_CTRL_PARSE_CONTINUE          EXCEP_CTL (0x000B)
#define AE_CTRL_PARSE_PENDING           EXCEP_CTL (0x000C)
#define AE_CTRL_PENDING                 EXCEP_CTL (0x0002)
#define AE_CTRL_RETURN_VALUE            EXCEP_CTL (0x0001)
#define AE_CTRL_TERMINATE               EXCEP_CTL (0x0003)
#define AE_CTRL_TRANSFER                EXCEP_CTL (0x0008)
#define AE_CTRL_TRUE                    EXCEP_CTL (0x0004)
#define AE_DECIMAL_OVERFLOW             EXCEP_ENV (0x0021)
#define AE_END_OF_TABLE                 EXCEP_ENV (0x0023)
#define AE_ERROR                        EXCEP_ENV (0x0001)
#define AE_HEX_OVERFLOW                 EXCEP_ENV (0x0020)
#define AE_INVALID_TABLE_LENGTH         EXCEP_TBL (0x0005)
#define AE_IO_ERROR                     EXCEP_ENV (0x001E)
#define AE_LIMIT                        EXCEP_ENV (0x0010)
#define AE_MISSING_ARGUMENTS            EXCEP_PGM (0x0008)
#define AE_NOT_ACQUIRED                 EXCEP_ENV (0x0014)
#define AE_NOT_CONFIGURED               EXCEP_ENV (0x001C)
#define AE_NOT_EXIST                    EXCEP_ENV (0x0006)
#define AE_NOT_FOUND                    EXCEP_ENV (0x0005)
#define AE_NOT_IMPLEMENTED              EXCEP_ENV (0x000E)
#define AE_NO_ACPI_TABLES               EXCEP_ENV (0x0002)
#define AE_NO_GLOBAL_LOCK               EXCEP_ENV (0x0017)
#define AE_NO_HANDLER                   EXCEP_ENV (0x001A)
#define AE_NO_HARDWARE_RESPONSE         EXCEP_ENV (0x0016)
#define AE_NO_MEMORY                    EXCEP_ENV (0x0004)
#define AE_NO_NAMESPACE                 EXCEP_ENV (0x0003)
#define AE_NULL_ENTRY                   EXCEP_ENV (0x000A)
#define AE_NULL_OBJECT                  EXCEP_ENV (0x0009)
#define AE_NUMERIC_OVERFLOW             EXCEP_ENV (0x001F)
#define AE_OCTAL_OVERFLOW               EXCEP_ENV (0x0022)
#define AE_OK                           (ACPI_STATUS) 0x0000
#define AE_OWNER_ID_LIMIT               EXCEP_ENV (0x001B)
#define AE_RELEASE_DEADLOCK             EXCEP_ENV (0x0013)
#define AE_SAME_HANDLER                 EXCEP_ENV (0x0019)
#define AE_STACK_OVERFLOW               EXCEP_ENV (0x000C)
#define AE_STACK_UNDERFLOW              EXCEP_ENV (0x000D)
#define AE_SUPPORT                      EXCEP_ENV (0x000F)
#define AE_TIME                         EXCEP_ENV (0x0011)
#define AE_TYPE                         EXCEP_ENV (0x0008)
#define EXCEP_AML(code)                 ((ACPI_STATUS) (code | AE_CODE_AML))
#define EXCEP_CTL(code)                 ((ACPI_STATUS) (code | AE_CODE_CONTROL))
#define EXCEP_ENV(code)                 ((ACPI_STATUS) (code | AE_CODE_ENVIRONMENTAL))
#define EXCEP_PGM(code)                 ((ACPI_STATUS) (code | AE_CODE_PROGRAMMER))
#define EXCEP_TBL(code)                 ((ACPI_STATUS) (code | AE_CODE_ACPI_TABLES))
#define EXCEP_TXT(Name,Description)     {Name, Description}

#define ACPI_NAMESPACE_ROOT     "Namespace Root"
#define ACPI_NS_ROOT_PATH       "\\"
#define ACPI_PREFIX_LOWER       (UINT32) 0x69706361     
#define ACPI_PREFIX_MIXED       (UINT32) 0x69706341     
#define ACPI_ROOT_NAME          (UINT32) 0x5F5F5F5C     
#define ACPI_ROOT_PATHNAME      "\\___"
#define ACPI_UNKNOWN_NAME       (UINT32) 0x3F3F3F3F     
#define METHOD_NAME__ADR        "_ADR"
#define METHOD_NAME__AEI        "_AEI"
#define METHOD_NAME__BBN        "_BBN"
#define METHOD_NAME__CBA        "_CBA"
#define METHOD_NAME__CID        "_CID"
#define METHOD_NAME__CLS        "_CLS"
#define METHOD_NAME__CRS        "_CRS"
#define METHOD_NAME__DDN        "_DDN"
#define METHOD_NAME__DMA        "_DMA"
#define METHOD_NAME__DSD        "_DSD"
#define METHOD_NAME__HID        "_HID"
#define METHOD_NAME__INI        "_INI"
#define METHOD_NAME__PLD        "_PLD"
#define METHOD_NAME__PRS        "_PRS"
#define METHOD_NAME__PRT        "_PRT"
#define METHOD_NAME__PRW        "_PRW"
#define METHOD_NAME__PS0        "_PS0"
#define METHOD_NAME__PS1        "_PS1"
#define METHOD_NAME__PS2        "_PS2"
#define METHOD_NAME__PS3        "_PS3"
#define METHOD_NAME__REG        "_REG"
#define METHOD_NAME__SB_        "_SB_"
#define METHOD_NAME__SEG        "_SEG"
#define METHOD_NAME__SRS        "_SRS"
#define METHOD_NAME__STA        "_STA"
#define METHOD_NAME__SUB        "_SUB"
#define METHOD_NAME__UID        "_UID"
#define METHOD_PATHNAME__PTS    "\\_PTS"
#define METHOD_PATHNAME__SST    "\\_SI._SST"
#define METHOD_PATHNAME__WAK    "\\_WAK"


#define KSTACK_MAX_PAGES 32
#define PHYS_AVAIL_COUNT        (PHYS_AVAIL_ENTRIES + 2)
#define PHYS_AVAIL_ENTRIES      (VM_PHYSSEG_MAX * 2)
#define num_pages(x) \
	((vm_offset_t)((((vm_offset_t)(x)) + PAGE_MASK) >> PAGE_SHIFT))



#define VM_MAP_ENTRY_FOREACH(it, map)			\
	for ((it) = (map)->header.next;		\
	    (it) != &(map)->header;		\
	    (it) = vm_map_entry_succ(it))
#define DTRACE_PROBE(name)						\
	DTRACE_PROBE_IMPL_START(name, 0, 0, 0, 0, 0)			\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE1(name, type0, arg0)				\
	DTRACE_PROBE_IMPL_START(name, arg0, 0, 0, 0, 0) 		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE2(name, type0, arg0, type1, arg1)			\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, 0, 0, 0) 		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE3(name, type0, arg0, type1, arg1, type2, arg2)	\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, 0, 0)	 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE4(name, type0, arg0, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, arg3, 0) 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 3, #type3, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE5(name, type0, arg0, type1, arg1, type2, arg2, type3, arg3,	\
    type4, arg4)								\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, arg3, arg4) 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 3, #type3, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 4, #type4, NULL);		\
	DTRACE_PROBE_IMPL_END
#define SDT_PROBE(prov, mod, func, name, arg0, arg1, arg2, arg3, arg4)	do {	\
	if (SDT_PROBES_ENABLED()) {						\
		if (__predict_false(sdt_##prov##_##mod##_##func##_##name->id))	\
		(*sdt_probe_func)(sdt_##prov##_##mod##_##func##_##name->id,	\
		    (uintptr_t) arg0, (uintptr_t) arg1, (uintptr_t) arg2,	\
		    (uintptr_t) arg3, (uintptr_t) arg4);			\
	} \
} while (0)
#define SDT_PROBES_ENABLED()	0
#define SDT_PROBE_ARGTYPE(prov, mod, func, name, num, type, xtype)		\
	static struct sdt_argtype sdta_##prov##_##mod##_##func##_##name##num[1]	\
	    = { { num, type, xtype, { NULL, NULL },				\
	    sdt_##prov##_##mod##_##func##_##name }				\
	};									\
	DATA_SET(sdt_argtypes_set, sdta_##prov##_##mod##_##func##_##name##num);
#define SDT_PROBE_DECLARE(prov, mod, func, name)				\
	extern struct sdt_probe sdt_##prov##_##mod##_##func##_##name[1]
#define SDT_PROBE_DEFINE(prov, mod, func, name)					\
	struct sdt_probe sdt_##prov##_##mod##_##func##_##name[1] = {		\
		{ sizeof(struct sdt_probe), sdt_provider_##prov,		\
		    { NULL, NULL }, { NULL, NULL }, #mod, #func, #name, 0, 0,	\
		    NULL }							\
	};									\
	DATA_SET(sdt_probes_set, sdt_##prov##_##mod##_##func##_##name);
#define SDT_PROBE_DEFINE4_XLATE(prov, mod, func, name, arg0, xarg0,     \
    arg1, xarg1, arg2, xarg2, arg3, xarg3)
#define SDT_PROVIDER_DECLARE(prov)						\
	extern struct sdt_provider sdt_provider_##prov[1]
#define SDT_PROVIDER_DEFINE(prov)						\
	struct sdt_provider sdt_provider_##prov[1] = {				\
		{ #prov, { NULL, NULL }, 0, 0 }					\
	};									\
	DATA_SET(sdt_providers_set, sdt_provider_##prov);
#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_WSET(set, sym)	__MAKE_SET_QV(set, sym, )
#define SET_BEGIN(set)							\
	(&__CONCAT(__start_set_,set))
#define SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))
#define SET_DECLARE(set, ptype)					\
	extern ptype __weak_symbol *__CONCAT(__start_set_,set);	\
	extern ptype __weak_symbol *__CONCAT(__stop_set_,set)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)
#define SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])
#define SET_LIMIT(set)							\
	(&__CONCAT(__stop_set_,set))
#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)

#define __MAKE_SET(set, sym)	__MAKE_SET_QV(set, sym, __MAKE_SET_CONST)
#define __MAKE_SET_QV(set, sym, qv)			\
	__GLOBL(__CONCAT(__start_set_,set));		\
	__GLOBL(__CONCAT(__stop_set_,set));		\
	static void const * qv				\
	__set_##set##_sym_##sym __section("set_" #set)	\
	__used = &(sym)

#define lock_profile_obtain_lock_failed(lo, contested, waittime)	(void)0
#define lock_profile_obtain_lock_success(lo, contested, waittime, file, line)	(void)0
#define LO_NOPROFILE    0x10000000      
#define MPASS(ex)		MPASS4(ex, #ex, "__FILE__", "__LINE__")
#define MPASS2(ex, what)	MPASS4(ex, what, "__FILE__", "__LINE__")
#define MPASS3(ex, file, line)	MPASS4(ex, #ex, file, line)
#define MPASS4(ex, what, file, line)					\
	KASSERT((ex), ("Assertion %s failed at %s:%d", what, file, line))
#define WITNESS_DESTROY(lock)						\
	witness_destroy(lock)

#define lock_delay_spin(n)	do {	\
	u_int _i;			\
					\
	for (_i = (n); _i > 0; _i--)	\
		cpu_spinwait();		\
} while (0)
#define KTR_COMPILE 0

#define VM_PAGE_BITS_ALL 0xffu
#define VM_PAGE_TO_PHYS(entry)	((entry)->phys_addr)


#define CPU_SET_RDONLY  0x0002  
#define CPU_SET_ROOT    0x0001  
#define BITSET_ALLOC(_s, mt, mf)					\
	malloc(__bitset_words(_s) * sizeof(long), mt, (mf))
#define SCHED_FIFO      1
#define SCHED_OTHER     2
#define SCHED_RR        3
#define SCHED_STAT_INC(var)     DPCPU_GET(var)++;


#define DROP_GIANT()							\
do {									\
	int _giantcnt = 0;						\
	WITNESS_SAVE_DECL(Giant);					\
									\
	if (__predict_false(mtx_owned(&Giant))) {			\
		WITNESS_SAVE(&Giant.lock_object, Giant);		\
		for (_giantcnt = 0; mtx_owned(&Giant) &&		\
		    !SCHEDULER_STOPPED(); _giantcnt++)			\
			mtx_unlock(&Giant);				\
	}

#define MTX_NOPROFILE   0x00000020	
#define PARTIAL_PICKUP_GIANT()						\
	mtx_assert(&Giant, MA_NOTOWNED);				\
	if (__predict_false(_giantcnt > 0)) {				\
		while (_giantcnt--)					\
			mtx_lock(&Giant);				\
		WITNESS_RESTORE(&Giant.lock_object, Giant);		\
	}
#define PICKUP_GIANT()							\
	PARTIAL_PICKUP_GIANT();						\
} while (0)

#define __mtx_lock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
	uintptr_t _v = MTX_UNOWNED;					\
									\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(adaptive__acquire) ||\
	    !_mtx_obtain_lock_fetch((mp), &_v, _tid)))			\
		_mtx_lock_sleep((mp), _v, (opts), (file), (line));	\
} while (0)
#define __mtx_lock_spin(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
	uintptr_t _v = MTX_UNOWNED;					\
									\
	spinlock_enter();						\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(spin__acquire) ||	\
	    !_mtx_obtain_lock_fetch((mp), &_v, _tid))) 			\
		_mtx_lock_spin((mp), _v, (opts), (file), (line)); 	\
} while (0)
#define __mtx_trylock_spin(mp, tid, opts, file, line) __extension__  ({	\
	uintptr_t _tid = (uintptr_t)(tid);				\
	int _ret;							\
									\
	spinlock_enter();						\
	if (((mp)->mtx_lock != MTX_UNOWNED || !_mtx_obtain_lock((mp), _tid))) {\
		spinlock_exit();					\
		_ret = 0;						\
	} else {							\
		LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(spin__acquire,	\
		    mp, 0, 0, file, line);				\
		_ret = 1;						\
	}								\
	_ret;								\
})
#define __mtx_unlock(mp, tid, opts, file, line) do {			\
	uintptr_t _v = (uintptr_t)(tid);				\
									\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(adaptive__release) ||\
	    !_mtx_release_lock_fetch((mp), &_v)))			\
		_mtx_unlock_sleep((mp), _v, (opts), (file), (line));	\
} while (0)
#define __mtx_unlock_spin(mp) do {					\
	if (mtx_recursed((mp)))						\
		(mp)->mtx_recurse--;					\
	else {								\
		LOCKSTAT_PROFILE_RELEASE_LOCK(spin__release, mp);	\
		_mtx_release_lock_quick((mp));				\
	}								\
	spinlock_exit();						\
} while (0)
#define _mtx_obtain_lock(mp, tid)					\
	atomic_cmpset_acq_ptr(&(mp)->mtx_lock, MTX_UNOWNED, (tid))
#define _mtx_obtain_lock_fetch(mp, vp, tid)				\
	atomic_fcmpset_acq_ptr(&(mp)->mtx_lock, vp, (tid))
#define _mtx_release_lock(mp, tid)					\
	atomic_cmpset_rel_ptr(&(mp)->mtx_lock, (tid), MTX_UNOWNED)
#define _mtx_release_lock_quick(mp)					\
	atomic_store_rel_ptr(&(mp)->mtx_lock, MTX_UNOWNED)
#define lv_mtx_owner(v)	((struct thread *)((v) & ~MTX_FLAGMASK))
#define mtx_assert_(m, what, file, line)	(void)0
#define mtx_lock(m)		mtx_lock_flags((m), 0)
#define mtx_lock_spin(m)	mtx_lock_spin_flags((m), 0)
#define mtx_name(m)	((m)->lock_object.lo_name)
#define mtx_owned(m)	(mtx_owner(m) == curthread)
#define mtx_owner(m)	lv_mtx_owner(MTX_READ_VALUE(m))
#define mtx_pool_lock(pool, ptr)					\
	mtx_lock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_lock_spin(pool, ptr)					\
	mtx_lock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock(pool, ptr)					\
	mtx_unlock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock_spin(pool, ptr)					\
	mtx_unlock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_recursed(m)	((m)->mtx_recurse != 0)
#define mtx_trylock(m)		mtx_trylock_flags((m), 0)
#define mtx_trylock_flags(m, opts)					\
	mtx_trylock_flags_((m), (opts), LOCK_FILE, LOCK_LINE)
#define mtx_trylock_spin(m)	mtx_trylock_spin_flags((m), 0)
#define mtx_trylock_spin_flags(m, opts)					\
	mtx_trylock_spin_flags_((m), (opts), LOCK_FILE, LOCK_LINE)
#define mtx_unlock(m)		mtx_unlock_flags((m), 0)
#define mtx_unlock_spin(m)	mtx_unlock_spin_flags((m), 0)
#define CTR0(m, format)			CTR6(m, format, 0, 0, 0, 0, 0, 0)
#define CTR1(m, format, p1)		CTR6(m, format, p1, 0, 0, 0, 0, 0)
#define CTR6(m, format, p1, p2, p3, p4, p5, p6) do {			\
	if (KTR_COMPILE & (m))						\
		ktr_tracepoint((m), "__FILE__", "__LINE__", format,		\
		    (u_long)(p1), (u_long)(p2), (u_long)(p3),		\
		    (u_long)(p4), (u_long)(p5), (u_long)(p6));		\
	} while(0)
#define KTR_STATE0(m, egroup, ident, state)				\
	KTR_EVENT0(m, egroup, ident, "state:\"%s\"", state)
#define KTR_STATE1(m, egroup, ident, state, a0, v0)			\
	KTR_EVENT1(m, egroup, ident, "state:\"%s\"", state, a0, (v0))
#define KTR_STATE2(m, egroup, ident, state, a0, v0, a1, v1)		\
	KTR_EVENT2(m, egroup, ident, "state:\"%s\"", state, a0, (v0), a1, (v1))
#define KTR_STATE3(m, egroup, ident, state, a0, v0, a1, v1, a2, v2)	\
	KTR_EVENT3(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2))
#define KTR_STATE4(m, egroup, ident, state, a0, v0, a1, v1, a2, v2, a3, v3)\
	KTR_EVENT4(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2), a3, (v3))

#define TSENTER() TSRAW(curthread, TS_ENTER, __func__, NULL)
#define TSENTER2(x) TSRAW(curthread, TS_ENTER, __func__, x)
#define TSEVENT(x) TSRAW(curthread, TS_EVENT, x, NULL)
#define TSEVENT2(x, y) TSRAW(curthread, TS_EVENT, x, y)
#define TSEXIT() TSRAW(curthread, TS_EXIT, __func__, NULL)
#define TSEXIT2(x) TSRAW(curthread, TS_EXIT, __func__, x)
#define TSHOLD(x) TSEVENT2("HOLD", x);
#define TSLINE() TSEVENT2("__FILE__", __XSTRING("__LINE__"))
#define TSRAW(a, b, c, d) tslog(a, b, c, d)
#define TSRELEASE(x) TSEVENT2("RELEASE", x);
#define TSTHREAD(td, x) TSRAW(td, TS_THREAD, x, NULL)
#define TSUNWAIT(x) TSEVENT2("UNWAIT", x);
#define TSWAIT(x) TSEVENT2("WAIT", x);
#define CPUFREQ_CMP(x, y)	(abs((x) - (y)) < 25)

#define EVENTHANDLER_DECLARE(name, type)				\
struct eventhandler_entry_ ## name 					\
{									\
	struct eventhandler_entry	ee;				\
	type				eh_func;			\
};									\
struct __hack


#define __BUS_ACCESSOR(varp, var, ivarp, ivar, type)			\
									\
static __inline type varp ## _get_ ## var(device_t dev)			\
{									\
	uintptr_t v;							\
	int e;								\
	e = BUS_READ_IVAR(device_get_parent(dev), dev,			\
	    ivarp ## _IVAR_ ## ivar, &v);				\
	KASSERT(e == 0, ("%s failed for %s on bus %s, error = %d",	\
	    __func__, device_get_nameunit(dev),				\
	    device_get_nameunit(device_get_parent(dev)), e));		\
	return ((type) v);						\
}									\
									\
static __inline void varp ## _set_ ## var(device_t dev, type t)		\
{									\
	uintptr_t v = (uintptr_t) t;					\
	int e;								\
	e = BUS_WRITE_IVAR(device_get_parent(dev), dev,			\
	    ivarp ## _IVAR_ ## ivar, v);				\
	KASSERT(e == 0, ("%s failed for %s on bus %s, error = %d",	\
	    __func__, device_get_nameunit(dev),				\
	    device_get_nameunit(device_get_parent(dev)), e));		\
}
#define bus_barrier(r, o, l, f) \
	bus_space_barrier((r)->r_bustag, (r)->r_bushandle, (o), (l), (f))
#define bus_read_1(r, o) \
	bus_space_read_1((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_2(r, o) \
	bus_space_read_2((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_4(r, o) \
	bus_space_read_4((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_8(r, o) \
	bus_space_read_8((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_multi_1(r, o, d, c) \
	bus_space_read_multi_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_2(r, o, d, c) \
	bus_space_read_multi_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_4(r, o, d, c) \
	bus_space_read_multi_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_8(r, o, d, c) \
	bus_space_read_multi_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_stream_1(r, o, d, c) \
	bus_space_read_multi_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_stream_2(r, o, d, c) \
	bus_space_read_multi_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_stream_4(r, o, d, c) \
	bus_space_read_multi_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_multi_stream_8(r, o, d, c) \
	bus_space_read_multi_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_1(r, o, d, c) \
	bus_space_read_region_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_2(r, o, d, c) \
	bus_space_read_region_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_4(r, o, d, c) \
	bus_space_read_region_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_8(r, o, d, c) \
	bus_space_read_region_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_stream_1(r, o, d, c) \
	bus_space_read_region_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_stream_2(r, o, d, c) \
	bus_space_read_region_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_stream_4(r, o, d, c) \
	bus_space_read_region_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_region_stream_8(r, o, d, c) \
	bus_space_read_region_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_read_stream_1(r, o) \
	bus_space_read_stream_1((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_stream_2(r, o) \
	bus_space_read_stream_2((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_stream_4(r, o) \
	bus_space_read_stream_4((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_read_stream_8(r, o) \
	bus_space_read_stream_8((r)->r_bustag, (r)->r_bushandle, (o))
#define bus_set_multi_1(r, o, v, c) \
	bus_space_set_multi_1((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_2(r, o, v, c) \
	bus_space_set_multi_2((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_4(r, o, v, c) \
	bus_space_set_multi_4((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_8(r, o, v, c) \
	bus_space_set_multi_8((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_stream_1(r, o, v, c) \
	bus_space_set_multi_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_stream_2(r, o, v, c) \
	bus_space_set_multi_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_stream_4(r, o, v, c) \
	bus_space_set_multi_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_multi_stream_8(r, o, v, c) \
	bus_space_set_multi_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_1(r, o, v, c) \
	bus_space_set_region_1((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_2(r, o, v, c) \
	bus_space_set_region_2((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_4(r, o, v, c) \
	bus_space_set_region_4((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_8(r, o, v, c) \
	bus_space_set_region_8((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_stream_1(r, o, v, c) \
	bus_space_set_region_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_stream_2(r, o, v, c) \
	bus_space_set_region_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_stream_4(r, o, v, c) \
	bus_space_set_region_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_set_region_stream_8(r, o, v, c) \
	bus_space_set_region_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (v), (c))
#define bus_write_1(r, o, v) \
	bus_space_write_1((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_2(r, o, v) \
	bus_space_write_2((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_4(r, o, v) \
	bus_space_write_4((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_8(r, o, v) \
	bus_space_write_8((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_multi_1(r, o, d, c) \
	bus_space_write_multi_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_2(r, o, d, c) \
	bus_space_write_multi_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_4(r, o, d, c) \
	bus_space_write_multi_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_8(r, o, d, c) \
	bus_space_write_multi_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_stream_1(r, o, d, c) \
	bus_space_write_multi_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_stream_2(r, o, d, c) \
	bus_space_write_multi_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_stream_4(r, o, d, c) \
	bus_space_write_multi_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_multi_stream_8(r, o, d, c) \
	bus_space_write_multi_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_1(r, o, d, c) \
	bus_space_write_region_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_2(r, o, d, c) \
	bus_space_write_region_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_4(r, o, d, c) \
	bus_space_write_region_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_8(r, o, d, c) \
	bus_space_write_region_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_stream_1(r, o, d, c) \
	bus_space_write_region_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_stream_2(r, o, d, c) \
	bus_space_write_region_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_stream_4(r, o, d, c) \
	bus_space_write_region_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_region_stream_8(r, o, d, c) \
	bus_space_write_region_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (d), (c))
#define bus_write_stream_1(r, o, v) \
	bus_space_write_stream_1((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_stream_2(r, o, v) \
	bus_space_write_stream_2((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_stream_4(r, o, v) \
	bus_space_write_stream_4((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define bus_write_stream_8(r, o, v) \
	bus_space_write_stream_8((r)->r_bustag, (r)->r_bushandle, (o), (v))
#define DECLARE_CLASS(name) extern struct kobj_class name
#define DEFINE_CLASS(name, methods, size)     		\
DEFINE_CLASS_0(name, name ## _class, methods, size)
#define DEFINE_CLASS_0(name, classvar, methods, size)	\
							\
struct kobj_class classvar = {				\
	#name, methods, size, NULL			\
}
#define DEFINE_CLASS_1(name, classvar, methods, size,	\
		       base1)				\
							\
static kobj_class_t name ## _baseclasses[] =		\
	{ &base1, NULL };				\
struct kobj_class classvar = {				\
	#name, methods, size, name ## _baseclasses	\
}
#define DEFINE_CLASS_2(name, classvar, methods, size,	\
	               base1, base2)			\
							\
static kobj_class_t name ## _baseclasses[] =		\
	{ &base1,					\
	  &base2, NULL };				\
struct kobj_class classvar = {				\
	#name, methods, size, name ## _baseclasses	\
}
#define DEFINE_CLASS_3(name, classvar, methods, size,	\
		       base1, base2, base3)		\
							\
static kobj_class_t name ## _baseclasses[] =		\
	{ &base1,					\
	  &base2,					\
	  &base3, NULL };				\
struct kobj_class classvar = {				\
	#name, methods, size, name ## _baseclasses	\
}
#define KOBJMETHOD(NAME, FUNC) \
	{ &NAME##_desc, (kobjop_t) (1 ? FUNC : (NAME##_t *)NULL) }
#define KOBJOPLOOKUP(OPS,OP) do {				\
	kobjop_desc_t _desc = &OP##_##desc;			\
	kobj_method_t **_cep =					\
	    &OPS->cache[_desc->id & (KOBJ_CACHE_SIZE-1)];	\
	kobj_method_t *_ce = *_cep;				\
	if (_ce->desc != _desc) {				\
		_ce = kobj_lookup_method(OPS->cls,		\
					 _cep, _desc);		\
		kobj_lookup_misses++;				\
	} else							\
		kobj_lookup_hits++;				\
	_m = _ce->func;						\
} while(0)


#define TD_IS_IDLETHREAD(td)	((td)->td_flags & TDF_IDLETD)
#define ucontext4 ucontext

#define RTP_PRIO_BASE(P)	PRI_BASE(P)
#define RTP_PRIO_IS_REALTIME(P) PRI_IS_REALTIME(P)
#define RTP_PRIO_NEED_RR(P)	PRI_NEED_RR(P)



#define EV_SET(kevp_, a, b, c, d, e, f) do {	\
	struct kevent *kevp = (kevp_);		\
	(kevp)->ident = (a);			\
	(kevp)->filter = (b);			\
	(kevp)->flags = (c);			\
	(kevp)->fflags = (d);			\
	(kevp)->data = (e);			\
	(kevp)->udata = (f);			\
	(kevp)->ext[0] = 0;			\
	(kevp)->ext[1] = 0;			\
	(kevp)->ext[2] = 0;			\
	(kevp)->ext[3] = 0;			\
} while(0)
#define KNOTE(list, hint, flags)	knote(list, hint, flags)
#define KNOTE_LOCKED(list, hint)	knote(list, hint, KNF_LISTLOCKED)
#define KNOTE_UNLOCKED(list, hint)	knote(list, hint, 0)

#define knlist_clear(knl, islocked)				\
	knlist_cleardel((knl), NULL, (islocked), 0)
#define knlist_delete(knl, td, islocked)			\
	knlist_cleardel((knl), (td), (islocked), 1)
#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
