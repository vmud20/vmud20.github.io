

















#define SD_MMC_HC_ASYNC_TIMER   EFI_TIMER_PERIOD_MILLISECONDS(1)
#define SD_MMC_HC_ENUM_TIMER    EFI_TIMER_PERIOD_MILLISECONDS(100)
#define SD_MMC_HC_GENERIC_TIMEOUT     1 * 1000 * 1000
#define SD_MMC_HC_PRIVATE_FROM_THIS(a) \
    CR(a, SD_MMC_HC_PRIVATE_DATA, PassThru, SD_MMC_HC_PRIVATE_SIGNATURE)
#define SD_MMC_HC_PRIVATE_SIGNATURE  SIGNATURE_32 ('s', 'd', 't', 'f')
#define SD_MMC_HC_TRB_FROM_THIS(a) \
    CR(a, SD_MMC_HC_TRB, TrbList, SD_MMC_HC_TRB_SIG)
#define SD_MMC_HC_TRB_SIG             SIGNATURE_32 ('T', 'R', 'B', 'T')
#define SD_MMC_TRB_RETRIES            5

#define ADMA_MAX_DATA_PER_LINE_16B     SIZE_64KB
#define ADMA_MAX_DATA_PER_LINE_26B     SIZE_64MB
#define SD_MMC_HC_26_DATA_LEN_ADMA_EN BIT10
#define SD_MMC_HC_64_ADDR_EN          BIT13
#define SD_MMC_HC_ADMA_ERR_STS        0x54
#define SD_MMC_HC_ADMA_SYS_ADDR       0x58
#define SD_MMC_HC_ARG1                0x08
#define SD_MMC_HC_ARG2                0x00
#define SD_MMC_HC_AUTO_CMD_ERR_STS    0x3C
#define SD_MMC_HC_BLK_COUNT           0x06
#define SD_MMC_HC_BLK_GAP_CTRL        0x2A
#define SD_MMC_HC_BLK_SIZE            0x04
#define SD_MMC_HC_BUF_DAT_PORT        0x20
#define SD_MMC_HC_CAP                 0x40
#define SD_MMC_HC_CLOCK_CTRL          0x2C
#define SD_MMC_HC_COMMAND             0x0E
#define SD_MMC_HC_CTRL_DRIVER_STRENGTH_MASK  0x0030
#define SD_MMC_HC_CTRL_MMC_HS200      0x0003
#define SD_MMC_HC_CTRL_MMC_HS400      0x0005
#define SD_MMC_HC_CTRL_MMC_HS_DDR     0x0004
#define SD_MMC_HC_CTRL_MMC_HS_SDR     0x0001
#define SD_MMC_HC_CTRL_MMC_LEGACY     0x0000
#define SD_MMC_HC_CTRL_UHS_DDR50      0x0004
#define SD_MMC_HC_CTRL_UHS_MASK       0x0007
#define SD_MMC_HC_CTRL_UHS_SDR104     0x0003
#define SD_MMC_HC_CTRL_UHS_SDR12      0x0000
#define SD_MMC_HC_CTRL_UHS_SDR25      0x0001
#define SD_MMC_HC_CTRL_UHS_SDR50      0x0002
#define SD_MMC_HC_CTRL_VER            0xFE
#define SD_MMC_HC_CTRL_VER_100        0x00
#define SD_MMC_HC_CTRL_VER_200        0x01
#define SD_MMC_HC_CTRL_VER_300        0x02
#define SD_MMC_HC_CTRL_VER_400        0x03
#define SD_MMC_HC_CTRL_VER_410        0x04
#define SD_MMC_HC_CTRL_VER_420        0x05
#define SD_MMC_HC_ERR_INT_SIG_EN      0x3A
#define SD_MMC_HC_ERR_INT_STS         0x32
#define SD_MMC_HC_ERR_INT_STS_EN      0x36
#define SD_MMC_HC_FORCE_EVT_AUTO_CMD  0x50
#define SD_MMC_HC_FORCE_EVT_ERR_INT   0x52
#define SD_MMC_HC_HOST_CTRL1          0x28
#define SD_MMC_HC_HOST_CTRL2          0x3E
#define SD_MMC_HC_MAX_CURRENT_CAP     0x48
#define SD_MMC_HC_MAX_SLOT            6
#define SD_MMC_HC_NOR_INT_SIG_EN      0x38
#define SD_MMC_HC_NOR_INT_STS         0x30
#define SD_MMC_HC_NOR_INT_STS_EN      0x34
#define SD_MMC_HC_POWER_CTRL          0x29
#define SD_MMC_HC_PRESENT_STATE       0x24
#define SD_MMC_HC_PRESET_VAL          0x60
#define SD_MMC_HC_RESPONSE            0x10
#define SD_MMC_HC_SDMA_ADDR           0x00
#define SD_MMC_HC_SHARED_BUS_CTRL     0xE0
#define SD_MMC_HC_SLOT_INT_STS        0xFC
#define SD_MMC_HC_SLOT_OFFSET         0x40
#define SD_MMC_HC_SW_RST              0x2F
#define SD_MMC_HC_TIMEOUT_CTRL        0x2E
#define SD_MMC_HC_TRANS_MOD           0x0C
#define SD_MMC_HC_V4_EN               BIT12
#define SD_MMC_HC_WAKEUP_CTRL         0x2B
#define SD_MMC_SDMA_BOUNDARY          512 * 1024
#define SD_MMC_SDMA_ROUND_UP(x, n)    (((x) + n) & ~(n - 1))

