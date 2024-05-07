#include<signal.h>


#include<stdarg.h>
#include<unistd.h>
#include<linux/kvm.h>
#include<string.h>
#include<stdlib.h>

#include<stdbool.h>


#include<sys/signal.h>
#include<sys/time.h>








#include<sys/uio.h>

#include<limits.h>
#include<errno.h>
#include<time.h>



#include<emmintrin.h>






#include<fcntl.h>
#include<sys/mman.h>
#include<stddef.h>

#include<sys/types.h>

#include<sys/wait.h>


#include<assert.h>
#include<stdio.h>
#include<stdint.h>
#include<pthread.h>
#include<inttypes.h>
#include<strings.h>






#include<ctype.h>



#include<linux/kvm_para.h>

#include<setjmp.h>
#include<semaphore.h>


#include<sys/stat.h>





#define E1000_AIT      0x00458  
#define E1000_ALGNERRC 0x04004  
#define E1000_BPRC     0x04078  
#define E1000_BPTC     0x040F4  
#define E1000_CEXTERR  0x0403C  
#define E1000_COLC     0x04028  
#define E1000_CPUVEC    0x02C10 
#define E1000_CRCERRS  0x04000  
#define E1000_CTRL     0x00000  
#define E1000_CTRL_ASDE     0x00000020  
#define E1000_CTRL_BEM      0x00000002  
#define E1000_CTRL_BEM32    0x00000400  
#define E1000_CTRL_DUP 0x00004  
#define E1000_CTRL_D_UD_EN  0x00002000  
#define E1000_CTRL_D_UD_POLARITY 0x00004000 
#define E1000_CTRL_EXT 0x00018  
#define E1000_CTRL_EXT_LINK_EN 0x00010000 
#define E1000_CTRL_FD       0x00000001  
#define E1000_CTRL_FORCE_PHY_RESET 0x00008000 
#define E1000_CTRL_FRCDPX   0x00001000  
#define E1000_CTRL_FRCSPD   0x00000800  
#define E1000_CTRL_GIO_MASTER_DISABLE 0x00000004 
#define E1000_CTRL_ILOS     0x00000080  
#define E1000_CTRL_LRST     0x00000008  
#define E1000_CTRL_PHY_RST  0x80000000  
#define E1000_CTRL_PRIOR    0x00000004  
#define E1000_CTRL_RFCE     0x08000000  
#define E1000_CTRL_RST      0x04000000  
#define E1000_CTRL_RTE      0x20000000  
#define E1000_CTRL_SLE      0x00000020  
#define E1000_CTRL_SLU      0x00000040  
#define E1000_CTRL_SPD_10   0x00000000  
#define E1000_CTRL_SPD_100  0x00000100  
#define E1000_CTRL_SPD_1000 0x00000200  
#define E1000_CTRL_SPD_SEL  0x00000300  
#define E1000_CTRL_SW2FW_INT 0x02000000  
#define E1000_CTRL_SWDPIN0  0x00040000  
#define E1000_CTRL_SWDPIN1  0x00080000  
#define E1000_CTRL_SWDPIN2  0x00100000  
#define E1000_CTRL_SWDPIN3  0x00200000  
#define E1000_CTRL_SWDPIO0  0x00400000  
#define E1000_CTRL_SWDPIO1  0x00800000  
#define E1000_CTRL_SWDPIO2  0x01000000  
#define E1000_CTRL_SWDPIO3  0x02000000  
#define E1000_CTRL_TFCE     0x10000000  
#define E1000_CTRL_TME      0x00000010  
#define E1000_CTRL_VME      0x40000000  
#define E1000_DC       0x04030  
#define E1000_DEV_ID_80003ES2LAN_COPPER_DPT     0x1096
#define E1000_DEV_ID_80003ES2LAN_COPPER_SPT     0x10BA
#define E1000_DEV_ID_80003ES2LAN_SERDES_DPT     0x1098
#define E1000_DEV_ID_80003ES2LAN_SERDES_SPT     0x10BB
#define E1000_DEV_ID_82540EM             0x100E
#define E1000_DEV_ID_82540EM_LOM         0x1015
#define E1000_DEV_ID_82540EP             0x1017
#define E1000_DEV_ID_82540EP_LOM         0x1016
#define E1000_DEV_ID_82540EP_LP          0x101E
#define E1000_DEV_ID_82541EI             0x1013
#define E1000_DEV_ID_82541EI_MOBILE      0x1018
#define E1000_DEV_ID_82541ER             0x1078
#define E1000_DEV_ID_82541ER_LOM         0x1014
#define E1000_DEV_ID_82541GI             0x1076
#define E1000_DEV_ID_82541GI_LF          0x107C
#define E1000_DEV_ID_82541GI_MOBILE      0x1077
#define E1000_DEV_ID_82542               0x1000
#define E1000_DEV_ID_82543GC_COPPER      0x1004
#define E1000_DEV_ID_82543GC_FIBER       0x1001
#define E1000_DEV_ID_82544EI_COPPER      0x1008
#define E1000_DEV_ID_82544EI_FIBER       0x1009
#define E1000_DEV_ID_82544GC_COPPER      0x100C
#define E1000_DEV_ID_82544GC_LOM         0x100D
#define E1000_DEV_ID_82545EM_COPPER      0x100F
#define E1000_DEV_ID_82545EM_FIBER       0x1011
#define E1000_DEV_ID_82545GM_COPPER      0x1026
#define E1000_DEV_ID_82545GM_FIBER       0x1027
#define E1000_DEV_ID_82545GM_SERDES      0x1028
#define E1000_DEV_ID_82546EB_COPPER      0x1010
#define E1000_DEV_ID_82546EB_FIBER       0x1012
#define E1000_DEV_ID_82546EB_QUAD_COPPER 0x101D
#define E1000_DEV_ID_82546GB_COPPER      0x1079
#define E1000_DEV_ID_82546GB_FIBER       0x107A
#define E1000_DEV_ID_82546GB_PCIE        0x108A
#define E1000_DEV_ID_82546GB_QUAD_COPPER 0x1099
#define E1000_DEV_ID_82546GB_QUAD_COPPER_KSP3 0x10B5
#define E1000_DEV_ID_82546GB_SERDES      0x107B
#define E1000_DEV_ID_82547EI             0x1019
#define E1000_DEV_ID_82547EI_MOBILE      0x101A
#define E1000_DEV_ID_82547GI             0x1075
#define E1000_DEV_ID_82571EB_COPPER      0x105E
#define E1000_DEV_ID_82571EB_FIBER       0x105F
#define E1000_DEV_ID_82571EB_QUAD_COPPER 0x10A4
#define E1000_DEV_ID_82571EB_QUAD_COPPER_LOWPROFILE  0x10BC
#define E1000_DEV_ID_82571EB_QUAD_FIBER  0x10A5
#define E1000_DEV_ID_82571EB_SERDES      0x1060
#define E1000_DEV_ID_82571EB_SERDES_DUAL 0x10D9
#define E1000_DEV_ID_82571EB_SERDES_QUAD 0x10DA
#define E1000_DEV_ID_82571PT_QUAD_COPPER 0x10D5
#define E1000_DEV_ID_82572EI             0x10B9
#define E1000_DEV_ID_82572EI_COPPER      0x107D
#define E1000_DEV_ID_82572EI_FIBER       0x107E
#define E1000_DEV_ID_82572EI_SERDES      0x107F
#define E1000_DEV_ID_82573E              0x108B
#define E1000_DEV_ID_82573E_IAMT         0x108C
#define E1000_DEV_ID_82573L              0x109A
#define E1000_DEV_ID_ICH8_IFE            0x104C
#define E1000_DEV_ID_ICH8_IFE_G          0x10C5
#define E1000_DEV_ID_ICH8_IFE_GT         0x10C4
#define E1000_DEV_ID_ICH8_IGP_AMT        0x104A
#define E1000_DEV_ID_ICH8_IGP_C          0x104B
#define E1000_DEV_ID_ICH8_IGP_M          0x104D
#define E1000_DEV_ID_ICH8_IGP_M_AMT      0x1049
#define E1000_ECOL     0x04018  
#define E1000_EEARBC   0x01024  
#define E1000_EECD     0x00010  
#define E1000_EECD_ADDR_BITS 0x00000400 
#define E1000_EECD_AUPDEN    0x00100000 
#define E1000_EECD_AUTO_RD          0x00000200  
#define E1000_EECD_CS        0x00000002 
#define E1000_EECD_DI        0x00000004 
#define E1000_EECD_DO        0x00000008 
#define E1000_EECD_FLUPD     0x00080000 
#define E1000_EECD_FWE_DIS   0x00000010 
#define E1000_EECD_FWE_EN    0x00000020 
#define E1000_EECD_FWE_MASK  0x00000030
#define E1000_EECD_FWE_SHIFT 4
#define E1000_EECD_GNT       0x00000080 
#define E1000_EECD_INITSRAM  0x00040000 
#define E1000_EECD_NVADDS    0x00018000 
#define E1000_EECD_PRES      0x00000100 
#define E1000_EECD_REQ       0x00000040 
#define E1000_EECD_SEC1VAL   0x00400000 
#define E1000_EECD_SECVAL_SHIFT      22
#define E1000_EECD_SELSHAD   0x00020000 
#define E1000_EECD_SHADV     0x00200000 
#define E1000_EECD_SIZE      0x00000200 
#define E1000_EECD_SIZE_EX_MASK     0x00007800  
#define E1000_EECD_SIZE_EX_SHIFT    11
#define E1000_EECD_SK        0x00000001 
#define E1000_EECD_TYPE      0x00002000 
#define E1000_EEMNGCTL 0x01010  
#define E1000_EEPROM_CFG_DONE         0x00040000   
#define E1000_EEPROM_CFG_DONE_PORT_1  0x00080000   
#define E1000_EEPROM_GRANT_ATTEMPTS 1000 
#define E1000_EEPROM_LED_LOGIC 0x0020   
#define E1000_EEPROM_POLL_READ     0    
#define E1000_EEPROM_POLL_WRITE    1    
#define E1000_EEPROM_RW_ADDR_SHIFT 8    
#define E1000_EEPROM_RW_REG_DATA   16   
#define E1000_EEPROM_RW_REG_DONE   0x10 
#define E1000_EEPROM_RW_REG_START  1    
#define E1000_EEPROM_SWDPIN0   0x0001   
#define E1000_EERD     0x00014  
#define E1000_EEWR     0x0102C  
#define E1000_ERT      0x02008  
#define E1000_EXTCNF_CTRL  0x00F00  
#define E1000_EXTCNF_SIZE  0x00F08  
#define E1000_FACTPS    0x05B30 
#define E1000_FCAH     0x0002C  
#define E1000_FCAL     0x00028  
#define E1000_FCRTH    0x02168  
#define E1000_FCRTL    0x02160  
#define E1000_FCRUC    0x04058  
#define E1000_FCT      0x00030  
#define E1000_FCTTV    0x00170  
#define E1000_FEXTNVM  0x00028  
#define E1000_FFLT     0x05F00  
#define E1000_FFLT_DBG  0x05F04 
#define E1000_FFMT     0x09000  
#define E1000_FFVT     0x09800  
#define E1000_FLA      0x0001C  
#define E1000_FLASHT   0x01028  
#define E1000_FLASH_UPDATES 1000
#define E1000_FLOP     0x0103C  
#define E1000_FLSWCNT  0x01038  
#define E1000_FLSWCTL  0x01030  
#define E1000_FLSWDATA 0x01034  
#define E1000_FWSM      0x05B54 
#define E1000_GCR       0x05B00 
#define E1000_GORCH    0x0408C  
#define E1000_GORCL    0x04088  
#define E1000_GOTCH    0x04094  
#define E1000_GOTCL    0x04090  
#define E1000_GPRC     0x04074  
#define E1000_GPTC     0x04080  
#define E1000_GSCL_1    0x05B10 
#define E1000_GSCL_2    0x05B14 
#define E1000_GSCL_3    0x05B18 
#define E1000_GSCL_4    0x05B1C 
#define E1000_HICR      0x08F00 
#define E1000_HICR_FW_RESET  0xC0
#define E1000_HOST_IF  0x08800  
#define E1000_IAC      0x04100  
#define E1000_IAM      0x000E0  
#define E1000_ICH_NVM_SIG_MASK     0xC0
#define E1000_ICH_NVM_SIG_WORD     0x13
#define E1000_ICR      0x000C0  
#define E1000_ICRXATC  0x04108  
#define E1000_ICRXDMTC 0x04120  
#define E1000_ICRXOC   0x04124  
#define E1000_ICRXPTC  0x04104  
#define E1000_ICR_ACK           0x00020000 
#define E1000_ICR_ALL_PARITY    0x03F00000 
#define E1000_ICR_DOCK          0x00080000 
#define E1000_ICR_DSW           0x00000020 
#define E1000_ICR_EPRST         0x00100000 
#define E1000_ICR_GPI_EN0       0x00000800 
#define E1000_ICR_GPI_EN1       0x00001000 
#define E1000_ICR_GPI_EN2       0x00002000 
#define E1000_ICR_GPI_EN3       0x00004000 
#define E1000_ICR_HOST_ARB_PAR  0x00400000 
#define E1000_ICR_INT_ASSERTED  0x80000000 
#define E1000_ICR_LSC           0x00000004 
#define E1000_ICR_MDAC          0x00000200 
#define E1000_ICR_MNG           0x00040000 
#define E1000_ICR_PB_PAR        0x00800000 
#define E1000_ICR_PHYINT        0x00001000 
#define E1000_ICR_RXCFG         0x00000400 
#define E1000_ICR_RXDMT0        0x00000010 
#define E1000_ICR_RXD_FIFO_PAR0 0x00100000 
#define E1000_ICR_RXD_FIFO_PAR1 0x01000000 
#define E1000_ICR_RXO           0x00000040 
#define E1000_ICR_RXSEQ         0x00000008 
#define E1000_ICR_RXT0          0x00000080 
#define E1000_ICR_SRPD          0x00010000
#define E1000_ICR_TXDW          0x00000001 
#define E1000_ICR_TXD_FIFO_PAR0 0x00200000 
#define E1000_ICR_TXD_FIFO_PAR1 0x02000000 
#define E1000_ICR_TXD_LOW       0x00008000
#define E1000_ICR_TXQE          0x00000002 
#define E1000_ICS      0x000C8  
#define E1000_ICS_ACK       E1000_ICR_ACK       
#define E1000_ICS_DOCK      E1000_ICR_DOCK      
#define E1000_ICS_DSW       E1000_ICR_DSW
#define E1000_ICS_EPRST     E1000_ICR_EPRST
#define E1000_ICS_GPI_EN0   E1000_ICR_GPI_EN0   
#define E1000_ICS_GPI_EN1   E1000_ICR_GPI_EN1   
#define E1000_ICS_GPI_EN2   E1000_ICR_GPI_EN2   
#define E1000_ICS_GPI_EN3   E1000_ICR_GPI_EN3   
#define E1000_ICS_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  
#define E1000_ICS_LSC       E1000_ICR_LSC       
#define E1000_ICS_MDAC      E1000_ICR_MDAC      
#define E1000_ICS_MNG       E1000_ICR_MNG       
#define E1000_ICS_PB_PAR        E1000_ICR_PB_PAR        
#define E1000_ICS_PHYINT    E1000_ICR_PHYINT
#define E1000_ICS_RXCFG     E1000_ICR_RXCFG     
#define E1000_ICS_RXDMT0    E1000_ICR_RXDMT0    
#define E1000_ICS_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 
#define E1000_ICS_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 
#define E1000_ICS_RXO       E1000_ICR_RXO       
#define E1000_ICS_RXSEQ     E1000_ICR_RXSEQ     
#define E1000_ICS_RXT0      E1000_ICR_RXT0      
#define E1000_ICS_SRPD      E1000_ICR_SRPD
#define E1000_ICS_TXDW      E1000_ICR_TXDW      
#define E1000_ICS_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 
#define E1000_ICS_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 
#define E1000_ICS_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_ICS_TXQE      E1000_ICR_TXQE      
#define E1000_ICTXATC  0x04110  
#define E1000_ICTXPTC  0x0410C  
#define E1000_ICTXQEC  0x04118  
#define E1000_ICTXQMTC 0x0411C  
#define E1000_IMC      0x000D8  
#define E1000_IMC_ACK       E1000_ICR_ACK       
#define E1000_IMC_DOCK      E1000_ICR_DOCK      
#define E1000_IMC_DSW       E1000_ICR_DSW
#define E1000_IMC_EPRST     E1000_ICR_EPRST
#define E1000_IMC_GPI_EN0   E1000_ICR_GPI_EN0   
#define E1000_IMC_GPI_EN1   E1000_ICR_GPI_EN1   
#define E1000_IMC_GPI_EN2   E1000_ICR_GPI_EN2   
#define E1000_IMC_GPI_EN3   E1000_ICR_GPI_EN3   
#define E1000_IMC_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  
#define E1000_IMC_LSC       E1000_ICR_LSC       
#define E1000_IMC_MDAC      E1000_ICR_MDAC      
#define E1000_IMC_MNG       E1000_ICR_MNG       
#define E1000_IMC_PB_PAR        E1000_ICR_PB_PAR        
#define E1000_IMC_PHYINT    E1000_ICR_PHYINT
#define E1000_IMC_RXCFG     E1000_ICR_RXCFG     
#define E1000_IMC_RXDMT0    E1000_ICR_RXDMT0    
#define E1000_IMC_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 
#define E1000_IMC_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 
#define E1000_IMC_RXO       E1000_ICR_RXO       
#define E1000_IMC_RXSEQ     E1000_ICR_RXSEQ     
#define E1000_IMC_RXT0      E1000_ICR_RXT0      
#define E1000_IMC_SRPD      E1000_ICR_SRPD
#define E1000_IMC_TXDW      E1000_ICR_TXDW      
#define E1000_IMC_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 
#define E1000_IMC_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 
#define E1000_IMC_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_IMC_TXQE      E1000_ICR_TXQE      
#define E1000_IMS      0x000D0  
#define E1000_IMS_ACK       E1000_ICR_ACK       
#define E1000_IMS_DOCK      E1000_ICR_DOCK      
#define E1000_IMS_DSW       E1000_ICR_DSW
#define E1000_IMS_EPRST     E1000_ICR_EPRST
#define E1000_IMS_GPI_EN0   E1000_ICR_GPI_EN0   
#define E1000_IMS_GPI_EN1   E1000_ICR_GPI_EN1   
#define E1000_IMS_GPI_EN2   E1000_ICR_GPI_EN2   
#define E1000_IMS_GPI_EN3   E1000_ICR_GPI_EN3   
#define E1000_IMS_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  
#define E1000_IMS_LSC       E1000_ICR_LSC       
#define E1000_IMS_MDAC      E1000_ICR_MDAC      
#define E1000_IMS_MNG       E1000_ICR_MNG       
#define E1000_IMS_PB_PAR        E1000_ICR_PB_PAR        
#define E1000_IMS_PHYINT    E1000_ICR_PHYINT
#define E1000_IMS_RXCFG     E1000_ICR_RXCFG     
#define E1000_IMS_RXDMT0    E1000_ICR_RXDMT0    
#define E1000_IMS_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 
#define E1000_IMS_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 
#define E1000_IMS_RXO       E1000_ICR_RXO       
#define E1000_IMS_RXSEQ     E1000_ICR_RXSEQ     
#define E1000_IMS_RXT0      E1000_ICR_RXT0      
#define E1000_IMS_SRPD      E1000_ICR_SRPD
#define E1000_IMS_TXDW      E1000_ICR_TXDW      
#define E1000_IMS_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 
#define E1000_IMS_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 
#define E1000_IMS_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_IMS_TXQE      E1000_ICR_TXQE      
#define E1000_IP4AT    0x05840  
#define E1000_IP6AT    0x05880  
#define E1000_IPAV     0x05838  
#define E1000_ITR      0x000C4  
#define E1000_KABGTXD  0x03004  
#define E1000_KUMCTRLSTA 0x00034 
#define E1000_LATECOL  0x04020  
#define E1000_LEDCTL   0x00E00  
#define E1000_MANC     0x05820  
#define E1000_MANC2H     0x05860  
#define E1000_MANC_0298_EN       0x00000200 
#define E1000_MANC_ARP_EN        0x00002000 
#define E1000_MANC_ARP_RES_EN    0x00008000 
#define E1000_MANC_ASF_EN        0x00000002 
#define E1000_MANC_BLK_PHY_RST_ON_IDE   0x00040000 
#define E1000_MANC_BR_EN         0x01000000 
#define E1000_MANC_EN_IP_ADDR_FILTER    0x00400000 
#define E1000_MANC_EN_MAC_ADDR_FILTER   0x00100000 
#define E1000_MANC_EN_MNG2HOST   0x00200000 
#define E1000_MANC_EN_XSUM_FILTER   0x00800000 
#define E1000_MANC_IPV4_EN       0x00000400 
#define E1000_MANC_IPV6_EN       0x00000800 
#define E1000_MANC_NEIGHBOR_EN   0x00004000 
#define E1000_MANC_RCV_ALL       0x00080000 
#define E1000_MANC_RCV_TCO_EN    0x00020000 
#define E1000_MANC_REPORT_STATUS 0x00040000 
#define E1000_MANC_RMCP_EN       0x00000100 
#define E1000_MANC_R_ON_FORCE    0x00000004 
#define E1000_MANC_SMBUS_EN      0x00000001 
#define E1000_MANC_SMB_CLK_IN    0x04000000 
#define E1000_MANC_SMB_CLK_OUT   0x20000000 
#define E1000_MANC_SMB_CLK_OUT_SHIFT   29 
#define E1000_MANC_SMB_DATA_IN   0x08000000 
#define E1000_MANC_SMB_DATA_OUT  0x10000000 
#define E1000_MANC_SMB_DATA_OUT_SHIFT  28 
#define E1000_MANC_SMB_GNT       0x02000000 
#define E1000_MANC_SMB_REQ       0x01000000 
#define E1000_MANC_SNAP_EN       0x00001000 
#define E1000_MANC_TCO_RESET     0x00010000 
#define E1000_MCC      0x0401C  
#define E1000_MDIC     0x00020  
#define E1000_MDIC_DATA_MASK 0x0000FFFF
#define E1000_MDIC_ERROR     0x40000000
#define E1000_MDIC_INT_EN    0x20000000
#define E1000_MDIC_OP_READ   0x08000000
#define E1000_MDIC_OP_WRITE  0x04000000
#define E1000_MDIC_PHY_MASK  0x03E00000
#define E1000_MDIC_PHY_SHIFT 21
#define E1000_MDIC_READY     0x10000000
#define E1000_MDIC_REG_MASK  0x001F0000
#define E1000_MDIC_REG_SHIFT 16
#define E1000_MDPHYA     0x0003C  
#define E1000_MGTPDC   0x040B8  
#define E1000_MGTPRC   0x040B4  
#define E1000_MGTPTC   0x040BC  
#define E1000_MPC      0x04010  
#define E1000_MPRC     0x0407C  
#define E1000_MPTC     0x040F0  
#define E1000_MRQC      0x05818 
#define E1000_MTA      0x05200  
#define E1000_PBA      0x01000  
#define E1000_PBM      0x10000  
#define E1000_PBS      0x01008  
#define E1000_PHY_CTRL     0x00F10  
#define E1000_PHY_ID2_82541x 0x380
#define E1000_PHY_ID2_82544x 0xC30
#define E1000_PHY_ID2_8254xx_DEFAULT 0xC20 
#define E1000_PHY_ID2_82573x 0xCC0
#define E1000_PRC1023  0x0406C  
#define E1000_PRC127   0x04060  
#define E1000_PRC1522  0x04070  
#define E1000_PRC255   0x04064  
#define E1000_PRC511   0x04068  
#define E1000_PRC64    0x0405C  
#define E1000_PSRCTL   0x02170  
#define E1000_PTC1023  0x040E8  
#define E1000_PTC127   0x040DC  
#define E1000_PTC1522  0x040EC  
#define E1000_PTC255   0x040E0  
#define E1000_PTC511   0x040E4  
#define E1000_PTC64    0x040D8  
#define E1000_RA       0x05400  
#define E1000_RADV     0x0282C  
#define E1000_RAH_AV  0x80000000        
#define E1000_RAID     0x02C08  
#define E1000_RCTL     0x00100  
#define E1000_RCTL_BAM            0x00008000    
#define E1000_RCTL_BSEX           0x02000000    
#define E1000_RCTL_CFI            0x00100000    
#define E1000_RCTL_CFIEN          0x00080000    
#define E1000_RCTL_DPF            0x00400000    
#define E1000_RCTL_DTYP_MASK      0x00000C00    
#define E1000_RCTL_DTYP_PS        0x00000400    
#define E1000_RCTL_EN             0x00000002    
#define E1000_RCTL_FLXBUF_MASK    0x78000000    
#define E1000_RCTL_FLXBUF_SHIFT   27            
#define E1000_RCTL_LBM_MAC        0x00000040    
#define E1000_RCTL_LBM_NO         0x00000000    
#define E1000_RCTL_LBM_SLP        0x00000080    
#define E1000_RCTL_LBM_TCVR       0x000000C0    
#define E1000_RCTL_LPE            0x00000020    
#define E1000_RCTL_MDR            0x00004000    
#define E1000_RCTL_MO_0           0x00000000    
#define E1000_RCTL_MO_1           0x00001000    
#define E1000_RCTL_MO_2           0x00002000    
#define E1000_RCTL_MO_3           0x00003000    
#define E1000_RCTL_MO_SHIFT       12            
#define E1000_RCTL_MPE            0x00000010    
#define E1000_RCTL_PMCF           0x00800000    
#define E1000_RCTL_RDMTS_EIGTH    0x00000200    
#define E1000_RCTL_RDMTS_HALF     0x00000000    
#define E1000_RCTL_RDMTS_QUAT     0x00000100    
#define E1000_RCTL_RST            0x00000001    
#define E1000_RCTL_SBP            0x00000004    
#define E1000_RCTL_SECRC          0x04000000    
#define E1000_RCTL_SZ_1024        0x00010000    
#define E1000_RCTL_SZ_16384       0x00010000    
#define E1000_RCTL_SZ_2048        0x00000000    
#define E1000_RCTL_SZ_256         0x00030000    
#define E1000_RCTL_SZ_4096        0x00030000    
#define E1000_RCTL_SZ_512         0x00020000    
#define E1000_RCTL_SZ_8192        0x00020000    
#define E1000_RCTL_UPE            0x00000008    
#define E1000_RCTL_VFE            0x00040000    
#define E1000_RDBAH    0x02804  
#define E1000_RDBAH0   E1000_RDBAH 
#define E1000_RDBAH1   0x02904  
#define E1000_RDBAL    0x02800  
#define E1000_RDBAL0   E1000_RDBAL 
#define E1000_RDBAL1   0x02900  
#define E1000_RDFH     0x02410  
#define E1000_RDFHS    0x02420  
#define E1000_RDFPC    0x02430  
#define E1000_RDFT     0x02418  
#define E1000_RDFTS    0x02428  
#define E1000_RDH      0x02810  
#define E1000_RDH0     E1000_RDH   
#define E1000_RDH1     0x02910  
#define E1000_RDLEN    0x02808  
#define E1000_RDLEN0   E1000_RDLEN 
#define E1000_RDLEN1   0x02908  
#define E1000_RDT      0x02818  
#define E1000_RDT0     E1000_RDT   
#define E1000_RDT1     0x02918  
#define E1000_RDTR     0x02820  
#define E1000_RDTR0    E1000_RDTR  
#define E1000_RDTR1    0x02820  
#define E1000_RETA      0x05C00 
#define E1000_RFC      0x040A8  
#define E1000_RFCTL    0x05008  
#define E1000_RJC      0x040B0  
#define E1000_RLEC     0x04040  
#define E1000_RNBC     0x040A0  
#define E1000_ROC      0x040AC  
#define E1000_RSRPD    0x02C00  
#define E1000_RSSIM     0x05864 
#define E1000_RSSIR     0x05868 
#define E1000_RSSRK     0x05C80 
#define E1000_RUC      0x040A4  
#define E1000_RXCSUM   0x05000  
#define E1000_RXCW     0x00180  
#define E1000_RXDCTL   0x02828  
#define E1000_RXDCTL1  0x02928  
#define E1000_RXDEXT_STATERR_CE    0x01000000
#define E1000_RXDEXT_STATERR_CXE   0x10000000
#define E1000_RXDEXT_STATERR_IPE   0x40000000
#define E1000_RXDEXT_STATERR_RXE   0x80000000
#define E1000_RXDEXT_STATERR_SE    0x02000000
#define E1000_RXDEXT_STATERR_SEQ   0x04000000
#define E1000_RXDEXT_STATERR_TCPE  0x20000000
#define E1000_RXDPS_HDRSTAT_HDRLEN_MASK  0x000003FF
#define E1000_RXDPS_HDRSTAT_HDRSP        0x00008000
#define E1000_RXD_ERR_CE        0x01    
#define E1000_RXD_ERR_CXE       0x10    
#define E1000_RXD_ERR_IPE       0x40    
#define E1000_RXD_ERR_RXE       0x80    
#define E1000_RXD_ERR_SE        0x02    
#define E1000_RXD_ERR_SEQ       0x04    
#define E1000_RXD_ERR_TCPE      0x20    
#define E1000_RXD_SPC_CFI_MASK  0x1000  
#define E1000_RXD_SPC_CFI_SHIFT 12
#define E1000_RXD_SPC_PRI_MASK  0xE000  
#define E1000_RXD_SPC_PRI_SHIFT 13
#define E1000_RXD_SPC_VLAN_MASK 0x0FFF  
#define E1000_RXD_STAT_ACK      0x8000  
#define E1000_RXD_STAT_DD       0x01    
#define E1000_RXD_STAT_EOP      0x02    
#define E1000_RXD_STAT_IPCS     0x40    
#define E1000_RXD_STAT_IPIDV    0x200   
#define E1000_RXD_STAT_IXSM     0x04    
#define E1000_RXD_STAT_PIF      0x80    
#define E1000_RXD_STAT_TCPCS    0x20    
#define E1000_RXD_STAT_UDPCS    0x10    
#define E1000_RXD_STAT_UDPV     0x400   
#define E1000_RXD_STAT_VP       0x08    
#define E1000_RXERRC   0x0400C  
#define E1000_SCC      0x04014  
#define E1000_SCTL     0x00024  
#define E1000_SEC      0x04038  
#define E1000_SHADOW_RAM_WORDS     2048
#define E1000_STATUS   0x00008  
#define E1000_STATUS_ASDV       0x00000300      
#define E1000_STATUS_BMC_CRYPTO 0x00800000 
#define E1000_STATUS_BMC_LITE   0x01000000 
#define E1000_STATUS_BMC_SKU_0  0x00100000 
#define E1000_STATUS_BMC_SKU_1  0x00200000 
#define E1000_STATUS_BMC_SKU_2  0x00400000 
#define E1000_STATUS_BUS64      0x00001000      
#define E1000_STATUS_DOCK_CI    0x00000800      
#define E1000_STATUS_FD         0x00000001      
#define E1000_STATUS_FUNC_0     0x00000000      
#define E1000_STATUS_FUNC_1     0x00000004      
#define E1000_STATUS_FUNC_MASK  0x0000000C      
#define E1000_STATUS_FUNC_SHIFT 2
#define E1000_STATUS_FUSE_8       0x04000000
#define E1000_STATUS_FUSE_9       0x08000000
#define E1000_STATUS_GIO_MASTER_ENABLE 0x00080000 
#define E1000_STATUS_LAN_INIT_DONE 0x00000200   
#define E1000_STATUS_LU         0x00000002      
#define E1000_STATUS_MTXCKOK    0x00000400      
#define E1000_STATUS_PCI66      0x00000800      
#define E1000_STATUS_PCIX_MODE  0x00002000      
#define E1000_STATUS_PCIX_SPEED 0x0000C000      
#define E1000_STATUS_RGMII_ENABLE 0x02000000 
#define E1000_STATUS_SERDES0_DIS  0x10000000 
#define E1000_STATUS_SERDES1_DIS  0x20000000 
#define E1000_STATUS_SPEED_10   0x00000000      
#define E1000_STATUS_SPEED_100  0x00000040      
#define E1000_STATUS_SPEED_1000 0x00000080      
#define E1000_STATUS_SPEED_MASK 0x000000C0
#define E1000_STATUS_TBIMODE    0x00000020      
#define E1000_STATUS_TXOFF      0x00000010      
#define E1000_STM_OPCODE     0xDB00
#define E1000_SWSM      0x05B50 
#define E1000_SW_FW_SYNC 0x05B5C 
#define E1000_SYMERRS  0x04008  
#define E1000_TADV     0x0382C  
#define E1000_TARC0    0x03840  
#define E1000_TARC1    0x03940  
#define E1000_TBT      0x00448  
#define E1000_TCTL     0x00400  
#define E1000_TCTL_BCE    0x00000004    
#define E1000_TCTL_COLD   0x003ff000    
#define E1000_TCTL_CT     0x00000ff0    
#define E1000_TCTL_EN     0x00000002    
#define E1000_TCTL_EXT 0x00404  
#define E1000_TCTL_MULR   0x10000000    
#define E1000_TCTL_NRTU   0x02000000    
#define E1000_TCTL_PBE    0x00800000    
#define E1000_TCTL_PSP    0x00000008    
#define E1000_TCTL_RST    0x00000001    
#define E1000_TCTL_RTLC   0x01000000    
#define E1000_TCTL_SWXOFF 0x00400000    
#define E1000_TDBAH    0x03804  
#define E1000_TDBAH1   0x03904  
#define E1000_TDBAL    0x03800  
#define E1000_TDBAL1   0x03900  
#define E1000_TDFH     0x03410  
#define E1000_TDFHS    0x03420  
#define E1000_TDFPC    0x03430  
#define E1000_TDFT     0x03418  
#define E1000_TDFTS    0x03428  
#define E1000_TDH      0x03810  
#define E1000_TDH1     0x03910  
#define E1000_TDLEN    0x03808  
#define E1000_TDLEN1   0x03908  
#define E1000_TDT      0x03818  
#define E1000_TDT1     0x03918  
#define E1000_TIDV     0x03820  
#define E1000_TIPG     0x00410  
#define E1000_TNCRS    0x04034  
#define E1000_TORH     0x040C4  
#define E1000_TORL     0x040C0  
#define E1000_TOTH     0x040CC  
#define E1000_TOTL     0x040C8  
#define E1000_TPR      0x040D0  
#define E1000_TPT      0x040D4  
#define E1000_TSCTC    0x040F8  
#define E1000_TSCTFC   0x040FC  
#define E1000_TSPMT    0x03830  
#define E1000_TXCW     0x00178  
#define E1000_TXDCTL   0x03828  
#define E1000_TXDCTL1  0x03928  
#define E1000_TXDMAC   0x03000  
#define E1000_TXD_CMD_DEXT   0x20000000 
#define E1000_TXD_CMD_EOP    0x01000000 
#define E1000_TXD_CMD_IC     0x04000000 
#define E1000_TXD_CMD_IDE    0x80000000 
#define E1000_TXD_CMD_IFCS   0x02000000 
#define E1000_TXD_CMD_IP     0x02000000 
#define E1000_TXD_CMD_RPS    0x10000000 
#define E1000_TXD_CMD_RS     0x08000000 
#define E1000_TXD_CMD_TCP    0x01000000 
#define E1000_TXD_CMD_TSE    0x04000000 
#define E1000_TXD_CMD_VLE    0x40000000 
#define E1000_TXD_DTYP_C     0x00000000 
#define E1000_TXD_DTYP_D     0x00100000 
#define E1000_TXD_POPTS_IXSM 0x01       
#define E1000_TXD_POPTS_TXSM 0x02       
#define E1000_TXD_STAT_DD    0x00000001 
#define E1000_TXD_STAT_EC    0x00000002 
#define E1000_TXD_STAT_LC    0x00000004 
#define E1000_TXD_STAT_TC    0x00000004 
#define E1000_TXD_STAT_TU    0x00000008 
#define E1000_VET      0x00038  
#define E1000_VFTA     0x05600  
#define E1000_WUC      0x05800  
#define E1000_WUFC     0x05808  
#define E1000_WUPL     0x05900  
#define E1000_WUPM     0x05A00  
#define E1000_WUS      0x05810  
#define E1000_XOFFRXC  0x04050  
#define E1000_XOFFTXC  0x04054  
#define E1000_XONRXC   0x04048  
#define E1000_XONTXC   0x0404C  
#define EEPROM_CFG                    0x0012
#define EEPROM_CHECKSUM_REG           0x003F
#define EEPROM_COMPAT                 0x0003
#define EEPROM_ERASE_OPCODE_MICROWIRE 0x7  
#define EEPROM_EWDS_OPCODE_MICROWIRE  0x10 
#define EEPROM_EWEN_OPCODE_MICROWIRE  0x13 
#define EEPROM_FLASH_VERSION          0x0032
#define EEPROM_ID_LED_SETTINGS        0x0004
#define EEPROM_INIT_3GIO_3            0x001A
#define EEPROM_INIT_CONTROL1_REG      0x000A
#define EEPROM_INIT_CONTROL2_REG      0x000F
#define EEPROM_INIT_CONTROL3_PORT_A   0x0024
#define EEPROM_INIT_CONTROL3_PORT_B   0x0014
#define EEPROM_PHY_CLASS_WORD         0x0007
#define EEPROM_READ_OPCODE_MICROWIRE  0x6  
#define EEPROM_SERDES_AMPLITUDE       0x0006 
#define EEPROM_SUM 0xBABA
#define EEPROM_SWDEF_PINS_CTRL_PORT_0 0x0020
#define EEPROM_SWDEF_PINS_CTRL_PORT_1 0x0010
#define EEPROM_VERSION                0x0005
#define EEPROM_WRITE_OPCODE_MICROWIRE 0x5  
#define FEXTNVM_SW_CONFIG  0x0001
#define M88E1000_EXT_PHY_SPEC_CTRL 0x14  
#define M88E1000_INT_ENABLE        0x12  
#define M88E1000_INT_STATUS        0x13  
#define M88E1000_PHY_EXT_CTRL      0x1A  
#define M88E1000_PHY_GEN_CONTROL   0x1E  
#define M88E1000_PHY_PAGE_SELECT   0x1D  
#define M88E1000_PHY_SPEC_CTRL     0x10  
#define M88E1000_PHY_SPEC_STATUS   0x11  
#define M88E1000_PHY_VCO_REG_BIT11 0x800    
#define M88E1000_PHY_VCO_REG_BIT8  0x100 
#define M88E1000_RX_ERR_CNTR       0x15  
#define MAX_PHY_MULTI_PAGE_REG     0xF   
#define MAX_PHY_REG_ADDRESS        0x1F  
#define MII_CR_AUTO_NEG_EN      0x1000 
#define MII_CR_COLL_TEST_ENABLE 0x0080 
#define MII_CR_FULL_DUPLEX      0x0100 
#define MII_CR_ISOLATE          0x0400 
#define MII_CR_LOOPBACK         0x4000 
#define MII_CR_POWER_DOWN       0x0800 
#define MII_CR_RESET            0x8000 
#define MII_CR_RESTART_AUTO_NEG 0x0200 
#define MII_CR_SPEED_SELECT_LSB 0x2000 
#define MII_CR_SPEED_SELECT_MSB 0x0040 
#define MII_LPAR_LPACK           0x4000 
#define MII_SR_100T2_FD_CAPS     0x0400	
#define MII_SR_100T2_HD_CAPS     0x0200	
#define MII_SR_100T4_CAPS        0x8000	
#define MII_SR_100X_FD_CAPS      0x4000	
#define MII_SR_100X_HD_CAPS      0x2000	
#define MII_SR_10T_FD_CAPS       0x1000	
#define MII_SR_10T_HD_CAPS       0x0800	
#define MII_SR_AUTONEG_CAPS      0x0008	
#define MII_SR_AUTONEG_COMPLETE  0x0020	
#define MII_SR_EXTENDED_CAPS     0x0001	
#define MII_SR_EXTENDED_STATUS   0x0100	
#define MII_SR_JABBER_DETECT     0x0002	
#define MII_SR_LINK_STATUS       0x0004	
#define MII_SR_PREAMBLE_SUPPRESS 0x0040	
#define MII_SR_REMOTE_FAULT      0x0010	
#define PHY_1000T_CTRL   0x09 
#define PHY_1000T_STATUS 0x0A 
#define PHY_AUTONEG_ADV  0x04 
#define PHY_AUTONEG_EXP  0x06 
#define PHY_CTRL         0x00 
#define PHY_EXT_STATUS   0x0F 
#define PHY_ID1          0x02 
#define PHY_ID2          0x03 
#define PHY_LP_ABILITY   0x05 
#define PHY_LP_NEXT_PAGE 0x08 
#define PHY_NEXT_PAGE_TX 0x07 
#define PHY_STATUS       0x01 



#define QLIST_EMPTY(head)                ((head)->lh_first == NULL)
#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;                         \
        struct type **le_prev;    \
}
#define QLIST_FIRST(head)                ((head)->lh_first)
#define QLIST_FOREACH(var, head, field)                                 \
        for ((var) = ((head)->lh_first);                                \
                (var);                                                  \
                (var) = ((var)->field.le_next))
#define QLIST_FOREACH_SAFE(var, head, field, next_var)                  \
        for ((var) = ((head)->lh_first);                                \
                (var) && ((next_var) = ((var)->field.le_next), 1);      \
                (var) = (next_var))
#define QLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;                       \
}
#define QLIST_HEAD_INITIALIZER(head)                                    \
        { NULL }
#define QLIST_INIT(head) do {                                           \
        (head)->lh_first = NULL;                                        \
} while (0)
#define QLIST_INSERT_AFTER(listelm, elm, field) do {                    \
        if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)  \
                (listelm)->field.le_next->field.le_prev =               \
                    &(elm)->field.le_next;                              \
        (listelm)->field.le_next = (elm);                               \
        (elm)->field.le_prev = &(listelm)->field.le_next;               \
} while (0)
#define QLIST_INSERT_BEFORE(listelm, elm, field) do {                   \
        (elm)->field.le_prev = (listelm)->field.le_prev;                \
        (elm)->field.le_next = (listelm);                               \
        *(listelm)->field.le_prev = (elm);                              \
        (listelm)->field.le_prev = &(elm)->field.le_next;               \
} while (0)
#define QLIST_INSERT_HEAD(head, elm, field) do {                        \
        if (((elm)->field.le_next = (head)->lh_first) != NULL)          \
                (head)->lh_first->field.le_prev = &(elm)->field.le_next;\
        (head)->lh_first = (elm);                                       \
        (elm)->field.le_prev = &(head)->lh_first;                       \
} while (0)
#define QLIST_NEXT(elm, field)           ((elm)->field.le_next)
#define QLIST_REMOVE(elm, field) do {                                   \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
} while (0)
#define QLIST_SWAP(dstlist, srclist, field) do {                        \
        void *tmplist;                                                  \
        tmplist = (srclist)->lh_first;                                  \
        (srclist)->lh_first = (dstlist)->lh_first;                      \
        if ((srclist)->lh_first != NULL) {                              \
            (srclist)->lh_first->field.le_prev = &(srclist)->lh_first;  \
        }                                                               \
        (dstlist)->lh_first = tmplist;                                  \
        if ((dstlist)->lh_first != NULL) {                              \
            (dstlist)->lh_first->field.le_prev = &(dstlist)->lh_first;  \
        }                                                               \
} while (0)
#define QSIMPLEQ_CONCAT(head1, head2) do {                              \
    if (!QSIMPLEQ_EMPTY((head2))) {                                     \
        *(head1)->sqh_last = (head2)->sqh_first;                        \
        (head1)->sqh_last = (head2)->sqh_last;                          \
        QSIMPLEQ_INIT((head2));                                         \
    }                                                                   \
} while (0)
#define QSIMPLEQ_EMPTY(head)        ((head)->sqh_first == NULL)
#define QSIMPLEQ_ENTRY(type)                                            \
struct {                                                                \
    struct type *sqe_next;                            \
}
#define QSIMPLEQ_FIRST(head)        ((head)->sqh_first)
#define QSIMPLEQ_FOREACH(var, head, field)                              \
    for ((var) = ((head)->sqh_first);                                   \
        (var);                                                          \
        (var) = ((var)->field.sqe_next))
#define QSIMPLEQ_FOREACH_SAFE(var, head, field, next)                   \
    for ((var) = ((head)->sqh_first);                                   \
        (var) && ((next = ((var)->field.sqe_next)), 1);                 \
        (var) = (next))
#define QSIMPLEQ_HEAD(name, type)                                       \
struct name {                                                           \
    struct type *sqh_first;                          \
    struct type **sqh_last;              \
}
#define QSIMPLEQ_HEAD_INITIALIZER(head)                                 \
    { NULL, &(head).sqh_first }
#define QSIMPLEQ_INIT(head) do {                                        \
    (head)->sqh_first = NULL;                                           \
    (head)->sqh_last = &(head)->sqh_first;                              \
} while (0)
#define QSIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {           \
    if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)    \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    (listelm)->field.sqe_next = (elm);                                  \
} while (0)
#define QSIMPLEQ_INSERT_HEAD(head, elm, field) do {                     \
    if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)            \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    (head)->sqh_first = (elm);                                          \
} while (0)
#define QSIMPLEQ_INSERT_TAIL(head, elm, field) do {                     \
    (elm)->field.sqe_next = NULL;                                       \
    *(head)->sqh_last = (elm);                                          \
    (head)->sqh_last = &(elm)->field.sqe_next;                          \
} while (0)
#define QSIMPLEQ_LAST(head, type, field)                                \
    (QSIMPLEQ_EMPTY((head)) ?                                           \
        NULL :                                                          \
            ((struct type *)(void *)                                    \
        ((char *)((head)->sqh_last) - offsetof(struct type, field))))
#define QSIMPLEQ_NEXT(elm, field)   ((elm)->field.sqe_next)
#define QSIMPLEQ_REMOVE(head, elm, type, field) do {                    \
    if ((head)->sqh_first == (elm)) {                                   \
        QSIMPLEQ_REMOVE_HEAD((head), field);                            \
    } else {                                                            \
        struct type *curelm = (head)->sqh_first;                        \
        while (curelm->field.sqe_next != (elm))                         \
            curelm = curelm->field.sqe_next;                            \
        if ((curelm->field.sqe_next =                                   \
            curelm->field.sqe_next->field.sqe_next) == NULL)            \
                (head)->sqh_last = &(curelm)->field.sqe_next;           \
    }                                                                   \
} while (0)
#define QSIMPLEQ_REMOVE_HEAD(head, field) do {                          \
    if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL)\
        (head)->sqh_last = &(head)->sqh_first;                          \
} while (0)
#define QSIMPLEQ_SPLIT_AFTER(head, elm, field, removed) do {            \
    QSIMPLEQ_INIT(removed);                                             \
    if (((removed)->sqh_first = (head)->sqh_first) != NULL) {           \
        if (((head)->sqh_first = (elm)->field.sqe_next) == NULL) {      \
            (head)->sqh_last = &(head)->sqh_first;                      \
        }                                                               \
        (removed)->sqh_last = &(elm)->field.sqe_next;                   \
        (elm)->field.sqe_next = NULL;                                   \
    }                                                                   \
} while (0)
#define QSLIST_EMPTY(head)       ((head)->slh_first == NULL)
#define QSLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *sle_next;                        \
}
#define QSLIST_FIRST(head)       ((head)->slh_first)
#define QSLIST_FOREACH(var, head, field)                                 \
        for((var) = (head)->slh_first; (var); (var) = (var)->field.sle_next)
#define QSLIST_FOREACH_SAFE(var, head, field, tvar)                      \
        for ((var) = QSLIST_FIRST((head));                               \
            (var) && ((tvar) = QSLIST_NEXT((var), field), 1);            \
            (var) = (tvar))
#define QSLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *slh_first;                      \
}
#define QSLIST_HEAD_INITIALIZER(head)                                    \
        { NULL }
#define QSLIST_INIT(head) do {                                           \
        (head)->slh_first = NULL;                                       \
} while (0)
#define QSLIST_INSERT_AFTER(slistelm, elm, field) do {                   \
        (elm)->field.sle_next = (slistelm)->field.sle_next;             \
        (slistelm)->field.sle_next = (elm);                             \
} while (0)
#define QSLIST_INSERT_HEAD(head, elm, field) do {                        \
        (elm)->field.sle_next = (head)->slh_first;                       \
        (head)->slh_first = (elm);                                       \
} while (0)
#define QSLIST_INSERT_HEAD_ATOMIC(head, elm, field) do {                     \
        typeof(elm) save_sle_next;                                           \
        do {                                                                 \
            save_sle_next = (elm)->field.sle_next = (head)->slh_first;       \
        } while (atomic_cmpxchg(&(head)->slh_first, save_sle_next, (elm)) != \
                 save_sle_next);                                             \
} while (0)
#define QSLIST_MOVE_ATOMIC(dest, src) do {                               \
        (dest)->slh_first = atomic_xchg(&(src)->slh_first, NULL);        \
} while (0)
#define QSLIST_NEXT(elm, field)  ((elm)->field.sle_next)
#define QSLIST_REMOVE_AFTER(slistelm, field) do {                        \
        (slistelm)->field.sle_next =                                    \
            QSLIST_NEXT(QSLIST_NEXT((slistelm), field), field);           \
} while (0)
#define QSLIST_REMOVE_HEAD(head, field) do {                             \
        (head)->slh_first = (head)->slh_first->field.sle_next;          \
} while (0)
#define QTAILQ_EMPTY(head)               ((head)->tqh_first == NULL)
#define QTAILQ_ENTRY(type)       Q_TAILQ_ENTRY(struct type,)
#define QTAILQ_FIRST(head)               ((head)->tqh_first)
#define QTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))
#define QTAILQ_FOREACH_REVERSE(var, head, headname, field)              \
        for ((var) = (*(((struct headname *)((head)->tqh_last))->tqh_last));    \
                (var);                                                  \
                (var) = (*(((struct headname *)((var)->field.tqe_prev))->tqh_last)))
#define QTAILQ_FOREACH_SAFE(var, head, field, next_var)                 \
        for ((var) = ((head)->tqh_first);                               \
                (var) && ((next_var) = ((var)->field.tqe_next), 1);     \
                (var) = (next_var))
#define QTAILQ_HEAD(name, type)  Q_TAILQ_HEAD(name, struct type,)
#define QTAILQ_HEAD_INITIALIZER(head)                                   \
        { NULL, &(head).tqh_first }
#define QTAILQ_INIT(head) do {                                          \
        (head)->tqh_first = NULL;                                       \
        (head)->tqh_last = &(head)->tqh_first;                          \
} while (0)
#define QTAILQ_INSERT_AFTER(head, listelm, elm, field) do {             \
        if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    &(elm)->field.tqe_next;                             \
        else                                                            \
                (head)->tqh_last = &(elm)->field.tqe_next;              \
        (listelm)->field.tqe_next = (elm);                              \
        (elm)->field.tqe_prev = &(listelm)->field.tqe_next;             \
} while (0)
#define QTAILQ_INSERT_BEFORE(listelm, elm, field) do {                  \
        (elm)->field.tqe_prev = (listelm)->field.tqe_prev;              \
        (elm)->field.tqe_next = (listelm);                              \
        *(listelm)->field.tqe_prev = (elm);                             \
        (listelm)->field.tqe_prev = &(elm)->field.tqe_next;             \
} while (0)
#define QTAILQ_INSERT_HEAD(head, elm, field) do {                       \
        if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)        \
                (head)->tqh_first->field.tqe_prev =                     \
                    &(elm)->field.tqe_next;                             \
        else                                                            \
                (head)->tqh_last = &(elm)->field.tqe_next;              \
        (head)->tqh_first = (elm);                                      \
        (elm)->field.tqe_prev = &(head)->tqh_first;                     \
} while (0)
#define QTAILQ_INSERT_TAIL(head, elm, field) do {                       \
        (elm)->field.tqe_next = NULL;                                   \
        (elm)->field.tqe_prev = (head)->tqh_last;                       \
        *(head)->tqh_last = (elm);                                      \
        (head)->tqh_last = &(elm)->field.tqe_next;                      \
} while (0)
#define QTAILQ_LAST(head, headname) \
        (*(((struct headname *)((head)->tqh_last))->tqh_last))
#define QTAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)
#define QTAILQ_PREV(elm, headname, field) \
        (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#define QTAILQ_REMOVE(head, elm, field) do {                            \
        if (((elm)->field.tqe_next) != NULL)                            \
                (elm)->field.tqe_next->field.tqe_prev =                 \
                    (elm)->field.tqe_prev;                              \
        else                                                            \
                (head)->tqh_last = (elm)->field.tqe_prev;               \
        *(elm)->field.tqe_prev = (elm)->field.tqe_next;                 \
} while (0)
#define Q_TAILQ_ENTRY(type, qual)                                       \
struct {                                                                \
        qual type *tqe_next;                          \
        qual type *qual *tqe_prev;      \
}
#define Q_TAILQ_HEAD(name, type, qual)                                  \
struct name {                                                           \
        qual type *tqh_first;                        \
        qual type *qual *tqh_last;       \
}
#define __QEMU_ATOMIC_H 1
#define atomic_add(ptr, n)     ((void) __sync_fetch_and_add(ptr, n))
#define atomic_and(ptr, n)     ((void) __sync_fetch_and_and(ptr, n))
#define atomic_cmpxchg         __sync_val_compare_and_swap
#define atomic_dec(ptr)        ((void) __sync_fetch_and_add(ptr, -1))
#define atomic_fetch_add       __sync_fetch_and_add
#define atomic_fetch_and       __sync_fetch_and_and
#define atomic_fetch_dec(ptr)  __sync_fetch_and_add(ptr, -1)
#define atomic_fetch_inc(ptr)  __sync_fetch_and_add(ptr, 1)
#define atomic_fetch_or        __sync_fetch_and_or
#define atomic_fetch_sub       __sync_fetch_and_sub
#define atomic_inc(ptr)        ((void) __sync_fetch_and_add(ptr, 1))
#define atomic_mb_read(ptr)    ({           \
    typeof(*ptr) _val = atomic_read(ptr);   \
    smp_rmb();                              \
    _val;                                   \
})
#define atomic_mb_set(ptr, i)  do {         \
    smp_wmb();                              \
    atomic_set(ptr, i);                     \
    smp_mb();                               \
} while (0)
#define atomic_or(ptr, n)      ((void) __sync_fetch_and_or(ptr, n))
#define atomic_rcu_read(ptr)    ({                \
    typeof(*ptr) _val;                            \
     __atomic_load(ptr, &_val, __ATOMIC_CONSUME); \
    _val;                                         \
})
#define atomic_rcu_set(ptr, i)  do {              \
    typeof(*ptr) _val = (i);                      \
    __atomic_store(ptr, &_val, __ATOMIC_RELEASE); \
} while(0)
#define atomic_read(ptr)       (*(__typeof__(*ptr) volatile*) (ptr))
#define atomic_set(ptr, i)     ((*(__typeof__(*ptr) volatile*) (ptr)) = (i))
#define atomic_sub(ptr, n)     ((void) __sync_fetch_and_sub(ptr, n))
#define atomic_xchg(ptr, i)    __sync_swap(ptr, i)
#define barrier()   ({ asm volatile("" ::: "memory"); (void)0; })
#define smp_mb()    ({ asm volatile("mfence" ::: "memory"); (void)0; })
#define smp_read_barrier_depends()   ({ barrier(); __atomic_thread_fence(__ATOMIC_CONSUME); barrier(); })
#define smp_rmb()   ({ barrier(); __atomic_thread_fence(__ATOMIC_ACQUIRE); barrier(); })
#define smp_wmb()   ({ barrier(); __atomic_thread_fence(__ATOMIC_RELEASE); barrier(); })

#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
#  define GCC_FMT_ATTR(n, m) __attribute__((format(gnu_printf, n, m)))
#define QEMU_ARTIFICIAL __attribute__((always_inline, artificial))
#define QEMU_BUILD_BUG_ON(x) \
    typedef char glue(qemu_build_bug_on__,"__LINE__")[(x)?-1:1] __attribute__((unused));
# define QEMU_GNUC_PREREQ(maj, min) \
         (("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
#define QEMU_NORETURN __attribute__ ((__noreturn__))
# define QEMU_PACKED __attribute__((gcc_struct, packed))
#define QEMU_SENTINEL __attribute__((sentinel))
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define __builtin_expect(x, n) (x)
#   define __printf__ __gnu_printf__
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#define glue(x, y) xglue(x, y)
#define inline __attribute__ (( always_inline )) __inline__
#define likely(x)   __builtin_expect(!!(x), 1)
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#define type_check(t1,t2) ((t1*)0 - (t2*)0)
#define typeof_field(type, field) typeof(((type *)0)->field)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#define xglue(x, y) x ## y


#define iov_recv(sockfd, iov, iov_cnt, offset, bytes) \
  iov_send_recv(sockfd, iov, iov_cnt, offset, bytes, false)
#define iov_send(sockfd, iov, iov_cnt, offset, bytes) \
  iov_send_recv(sockfd, iov, iov_cnt, offset, bytes, true)
#define ALL_EQ(v1, v2) vec_all_eq(v1, v2)
#define BUFFER_FIND_NONZERO_OFFSET_UNROLL_FACTOR 8
#define E_BYTE     (1ULL << 60)
#define G_BYTE     (1ULL << 30)
# define HOST_LONG_BITS 32
#define K_BYTE     (1ULL << 10)
#define M_BYTE     (1ULL << 20)
#define P_BYTE     (1ULL << 50)
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

#define QEMU_FILE_TYPE_BIOS   0
#define QEMU_FILE_TYPE_KEYMAP 1
#define QEMU_STRTOSZ_DEFSUFFIX_B 'B'
#define QEMU_STRTOSZ_DEFSUFFIX_EB 'E'
#define QEMU_STRTOSZ_DEFSUFFIX_GB 'G'
#define QEMU_STRTOSZ_DEFSUFFIX_KB 'K'
#define QEMU_STRTOSZ_DEFSUFFIX_MB 'M'
#define QEMU_STRTOSZ_DEFSUFFIX_PB 'P'
#define QEMU_STRTOSZ_DEFSUFFIX_TB 'T'
#define SPLAT(p)       vec_splat(vec_ld(0, p), 0)
#define STR_OR_NULL(str) ((str) ? (str) : "null")
#define TFR(expr) do { if ((expr) != -1) break; } while (errno == EINTR)
#define T_BYTE     (1ULL << 40)
#define VECTYPE        __vector unsigned char
#define VEC_OR(v1, v2) ((v1) | (v2))

#define bool _Bool
#define qemu_co_recv(sockfd, buf, bytes) \
  qemu_co_send_recv(sockfd, buf, bytes, false)
#define qemu_co_recvv(sockfd, iov, iov_cnt, offset, bytes) \
  qemu_co_sendv_recvv(sockfd, iov, iov_cnt, offset, bytes, false)
#define qemu_co_send(sockfd, buf, bytes) \
  qemu_co_send_recv(sockfd, buf, bytes, true)
#define qemu_co_sendv(sockfd, iov, iov_cnt, offset, bytes) \
  qemu_co_sendv_recvv(sockfd, iov, iov_cnt, offset, bytes, true)
#define qemu_getsockopt(sockfd, level, optname, optval, optlen) \
    getsockopt(sockfd, level, optname, (void *)optval, optlen)
#define qemu_isalnum(c)		isalnum((unsigned char)(c))
#define qemu_isalpha(c)		isalpha((unsigned char)(c))
#define qemu_isascii(c)		isascii((unsigned char)(c))
#define qemu_iscntrl(c)		iscntrl((unsigned char)(c))
#define qemu_isdigit(c)		isdigit((unsigned char)(c))
#define qemu_isgraph(c)		isgraph((unsigned char)(c))
#define qemu_islower(c)		islower((unsigned char)(c))
#define qemu_isprint(c)		isprint((unsigned char)(c))
#define qemu_ispunct(c)		ispunct((unsigned char)(c))
#define qemu_isspace(c)		isspace((unsigned char)(c))
#define qemu_isupper(c)		isupper((unsigned char)(c))
#define qemu_isxdigit(c)	isxdigit((unsigned char)(c))
#define qemu_recv(sockfd, buf, len, flags) recv(sockfd, (void *)buf, len, flags)
#define qemu_sendto(sockfd, buf, len, flags, destaddr, addrlen) \
    sendto(sockfd, (const void *)buf, len, flags, destaddr, addrlen)
#define qemu_setsockopt(sockfd, level, optname, optval, optlen) \
    setsockopt(sockfd, level, optname, (const void *)optval, optlen)
#define qemu_toascii(c)		toascii((unsigned char)(c))
#define qemu_tolower(c)		tolower((unsigned char)(c))
#define qemu_toupper(c)		toupper((unsigned char)(c))
#define DSO_STAMP_FUN         glue(qemu_stamp, CONFIG_STAMP)
#define DSO_STAMP_FUN_STR     stringify(DSO_STAMP_FUN)

#define block_init(function) module_init(function, MODULE_INIT_BLOCK)
#define machine_init(function) module_init(function, MODULE_INIT_MACHINE)
#define module_init(function, type)                                         \
static void __attribute__((constructor)) do_qemu_init_ ## function(void)    \
{                                                                           \
    register_dso_module_init(function, type);                               \
}
#define qapi_init(function) module_init(function, MODULE_INIT_QAPI)
#define type_init(function) module_init(function, MODULE_INIT_QOM)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define ECANCELED 4097
#define EMEDIUMTYPE 4098
#define ENOMEDIUM ENODEV
#define ENOTSUP 4096
#define FMT_pid "%ld"
#define IOV_MAX 1024
#define MAP_ANONYMOUS MAP_ANON
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MIN_NON_ZERO(a, b) (((a) != 0 && (a) < (b)) ? (a) : (b))
#define O_BINARY 0
#define O_LARGEFILE 0
#define QEMU_MADV_DODUMP MADV_DODUMP
#define QEMU_MADV_DONTDUMP MADV_DONTDUMP
#define QEMU_MADV_DONTFORK  MADV_DONTFORK
#define QEMU_MADV_DONTNEED  MADV_DONTNEED
#define QEMU_MADV_HUGEPAGE MADV_HUGEPAGE
#define QEMU_MADV_INVALID -1
#define QEMU_MADV_MERGEABLE MADV_MERGEABLE
#define QEMU_MADV_NOHUGEPAGE MADV_NOHUGEPAGE
#define QEMU_MADV_UNMERGEABLE MADV_UNMERGEABLE
#define QEMU_MADV_WILLNEED  MADV_WILLNEED

#define ROUND_UP(n,d) (((n) + (d) - 1) & -(d))
#define TIME_MAX LONG_MAX
#define WEXITSTATUS(x) (x)
#define WIFEXITED(x)   1
#define qemu_timersub timersub

#define error_set(errp, err_class, fmt, ...)                    \
    error_set_internal((errp), "__FILE__", "__LINE__", __func__,    \
                       (err_class), (fmt), ## __VA_ARGS__)
#define error_setg(errp, fmt, ...)                              \
    error_setg_internal((errp), "__FILE__", "__LINE__", __func__,   \
                        (fmt), ## __VA_ARGS__)
#define error_setg_errno(errp, os_error, fmt, ...)                      \
    error_setg_errno_internal((errp), "__FILE__", "__LINE__", __func__,     \
                              (os_error), (fmt), ## __VA_ARGS__)
#define error_setg_file_open(errp, os_errno, filename)                  \
    error_setg_file_open_internal((errp), "__FILE__", "__LINE__", __func__, \
                                  (os_errno), (filename))
#define error_setg_win32(errp, win32_err, fmt, ...)                     \
    error_setg_win32_internal((errp), "__FILE__", "__LINE__", __func__,     \
                              (win32_err), (fmt), ## __VA_ARGS__)
#define CompatGCond GCond
#define CompatGMutex GMutex
#define G_TIME_SPAN_SECOND              (G_GINT64_CONSTANT(1000000))

#define g_assert_cmpmem(m1, l1, m2, l2)                                        \
    do {                                                                       \
        gconstpointer __m1 = m1, __m2 = m2;                                    \
        int __l1 = l1, __l2 = l2;                                              \
        if (__l1 != __l2) {                                                    \
            g_assertion_message_cmpnum(                                        \
                G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,                   \
                #l1 " (len(" #m1 ")) == " #l2 " (len(" #m2 "))", __l1, "==",   \
                __l2, 'i');                                                    \
        } else if (memcmp(__m1, __m2, __l1) != 0) {                            \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "assertion failed (" #m1 " == " #m2 ")");      \
        }                                                                      \
    } while (0)
#define g_assert_false(expr)                                                   \
    do {                                                                       \
        if (G_LIKELY(!(expr))) {                                               \
        } else {                                                               \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "'" #expr "' should be FALSE");                \
        }                                                                      \
    } while (0)
#define g_assert_nonnull(expr)                                                 \
    do {                                                                       \
        if (G_LIKELY((expr) != NULL)) {                                        \
        } else {                                                               \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "'" #expr "' should not be NULL");             \
        }                                                                      \
    } while (0)
#define g_assert_null(expr)                                                    \
    do {                                                                       \
        if (G_LIKELY((expr) == NULL)) {                                        \
        } else {                                                               \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "'" #expr "' should be NULL");                 \
        }                                                                      \
    } while (0)
#define g_assert_true(expr)                                                    \
    do {                                                                       \
        if (G_LIKELY(expr)) {                                                  \
        } else {                                                               \
            g_assertion_message(G_LOG_DOMAIN, "__FILE__", "__LINE__", G_STRFUNC,   \
                                "'" #expr "' should be TRUE");                 \
        }                                                                      \
    } while (0)
#define g_get_monotonic_time() qemu_g_get_monotonic_time()
#define g_poll(fds, nfds, timeout) g_poll_fixed(fds, nfds, timeout)

# define UTIME_NOW     ((1l << 30) - 1l)
# define UTIME_OMIT    ((1l << 30) - 2l)
#define qemu_gettimeofday(tp) gettimeofday(tp, NULL)
# define ECONNREFUSED WSAECONNREFUSED
# define EHOSTUNREACH WSAEHOSTUNREACH
# define EINPROGRESS  WSAEINPROGRESS
# define EINTR        WSAEINTR
# define ENETUNREACH  WSAENETUNREACH
# define ENOTCONN     WSAENOTCONN
# define EPROTONOSUPPORT EINVAL
# define EWOULDBLOCK  WSAEWOULDBLOCK

#define fsync _commit
# define ftruncate qemu_ftruncate64
# define lseek _lseeki64
# define setjmp(env) _setjmp(env, NULL)
#define sigjmp_buf jmp_buf
#define siglongjmp(env, val) longjmp(env, val)
#define sigsetjmp(env, savemask) setjmp(env)

#define CPU_CONVERT(endian, size, type)\
static inline type endian ## size ## _to_cpu(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline type cpu_to_ ## endian ## size(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline void endian ## size ## _to_cpus(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}\
\
static inline void cpu_to_ ## endian ## size ## s(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}\
\
static inline type endian ## size ## _to_cpup(const type *p)\
{\
    return glue(glue(endian, size), _to_cpu)(*p);\
}\
\
static inline void cpu_to_ ## endian ## size ## w(type *p, type v)\
{\
    *p = glue(glue(cpu_to_, endian), size)(v);\
}
#define be_bswap(v, size) (v)
#define be_bswaps(v, size)
#define le_bswap(v, size) glue(bswap, size)(v)
#define le_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)
#define LIT64( a ) a##LL

#define const_float16(x) { x }
#define const_float32(x) { x }
#define const_float64(x) { x }
#define float128_zero make_float128(0, 0)
#define float16_val(x) (((float16)(x)).v)
#define float32_half make_float32(0x3f000000)
#define float32_infinity make_float32(0x7f800000)
#define float32_ln2 make_float32(0x3f317218)
#define float32_one make_float32(0x3f800000)
#define float32_pi make_float32(0x40490fdb)
#define float32_val(x) (((float32)(x)).v)
#define float32_zero make_float32(0)
#define float64_half make_float64(0x3fe0000000000000LL)
#define float64_infinity make_float64(0x7ff0000000000000LL)
#define float64_ln2 make_float64(0x3fe62e42fefa39efLL)
#define float64_one make_float64(0x3ff0000000000000LL)
#define float64_pi make_float64(0x400921fb54442d18LL)
#define float64_val(x) (((float64)(x)).v)
#define float64_zero make_float64(0)
#define floatx80_half make_floatx80(0x3ffe, 0x8000000000000000LL)
#define floatx80_infinity make_floatx80(0x7fff, 0x8000000000000000LL)
#define floatx80_ln2 make_floatx80(0x3ffe, 0xb17217f7d1cf79acLL)
#define floatx80_one make_floatx80(0x3fff, 0x8000000000000000LL)
#define floatx80_pi make_floatx80(0x4000, 0xc90fdaa22168c235LL)
#define floatx80_zero make_floatx80(0x0000, 0x0000000000000000LL)
#define make_float128(high_, low_) ((float128) { .high = high_, .low = low_ })
#define make_float128_init(high_, low_) { .high = high_, .low = low_ }
#define make_float16(x) __extension__ ({ float16 f16_val = {x}; f16_val; })
#define make_float32(x) __extension__ ({ float32 f32_val = {x}; f32_val; })
#define make_float64(x) __extension__ ({ float64 f64_val = {x}; f64_val; })
#define make_floatx80(exp, mant) ((floatx80) { mant, exp })
#define make_floatx80_init(exp, mant) { .low = mant, .high = exp }
#define HOST_UTILS_H 1
# define clol   clo32
# define clzl   clz32
# define ctol   cto32
# define ctpopl ctpop32
# define ctzl   ctz32
# define revbitl revbit32

#define QDICT_BUCKET_MAX 512

#define qdict_put(qdict, key, obj) \
        qdict_put_obj(qdict, key, QOBJECT(obj))
#define QLIST_FOREACH_ENTRY(qlist, var)             \
        for ((var) = ((qlist)->head.tqh_first);     \
            (var);                                  \
            (var) = ((var)->next.tqe_next))

#define qlist_append(qlist, obj) \
        qlist_append_obj(qlist, QOBJECT(obj))
#define QDECREF(obj)              \
    qobject_decref(obj ? QOBJECT(obj) : NULL)
#define QINCREF(obj)      \
    qobject_incref(QOBJECT(obj))
#define QOBJECT(obj) (&(obj)->base)

#define QEMU_FPRINTF_FN_H 1
#define DEFINE_LDST_DMA(_lname, _sname, _bits, _end) \
    static inline uint##_bits##_t ld##_lname##_##_end##_dma(AddressSpace *as, \
                                                            dma_addr_t addr) \
    {                                                                   \
        uint##_bits##_t val;                                            \
        dma_memory_read(as, addr, &val, (_bits) / 8);                   \
        return _end##_bits##_to_cpu(val);                               \
    }                                                                   \
    static inline void st##_sname##_##_end##_dma(AddressSpace *as,      \
                                                 dma_addr_t addr,       \
                                                 uint##_bits##_t val)   \
    {                                                                   \
        val = cpu_to_##_end##_bits(val);                                \
        dma_memory_write(as, addr, &val, (_bits) / 8);                  \
    }
#define DMA_ADDR_BITS 64
#define DMA_ADDR_FMT "%" PRIx64

#define KVM_CAP_INFO(CAP) { "KVM_CAP_" stringify(CAP), KVM_CAP_##CAP }
#define KVM_CAP_LAST_INFO { NULL, 0 }
#define KVM_CPUID_FEATURES       0
#define KVM_CPUID_SIGNATURE      0
#define KVM_FEATURE_ASYNC_PF     0
#define KVM_FEATURE_CLOCKSOURCE  0
#define KVM_FEATURE_CLOCKSOURCE2 0
#define KVM_FEATURE_CLOCKSOURCE_STABLE_BIT 0
#define KVM_FEATURE_MMU_OP       0
#define KVM_FEATURE_NOP_IO_DELAY 0
#define KVM_FEATURE_PV_EOI       0
#define KVM_FEATURE_STEAL_TIME   0
#define KVM_PUT_FULL_STATE      3
#define KVM_PUT_RESET_STATE     2
#define KVM_PUT_RUNTIME_STATE   1

#define kvm_async_interrupts_enabled() (false)
#define kvm_direct_msi_enabled() (kvm_direct_msi_allowed)
#define kvm_enabled()           (0)
#define kvm_eventfds_enabled() (kvm_eventfds_allowed)
#define kvm_gsi_direct_mapping() (kvm_gsi_direct_mapping)
#define kvm_gsi_routing_allowed() (false)
#define kvm_gsi_routing_enabled() (kvm_gsi_routing_allowed)
#define kvm_halt_in_kernel() (kvm_halt_in_kernel_allowed)
#define kvm_ioeventfd_any_length_enabled() (kvm_ioeventfd_any_length_allowed)
#define kvm_irqchip_in_kernel() (false)
#define kvm_irqchip_is_split() (false)
#define kvm_irqfds_enabled() (kvm_irqfds_allowed)
#define kvm_msi_via_irqfd_enabled() (kvm_msi_via_irqfd_allowed)
#define kvm_readonly_mem_enabled() (kvm_readonly_mem_allowed)
#define kvm_resamplefds_enabled() (kvm_resamplefds_allowed)
#define kvm_vcpu_enable_cap(cpu, capability, cap_flags, ...)         \
    ({                                                               \
        struct kvm_enable_cap cap = {                                \
            .cap = capability,                                       \
            .flags = cap_flags,                                      \
        };                                                           \
        uint64_t args_tmp[] = { __VA_ARGS__ };                       \
        int i;                                                       \
        for (i = 0; i < (int)ARRAY_SIZE(args_tmp) &&                 \
                     i < ARRAY_SIZE(cap.args); i++) {                \
            cap.args[i] = args_tmp[i];                               \
        }                                                            \
        kvm_vcpu_ioctl(cpu, KVM_ENABLE_CAP, &cap);                   \
    })
#define kvm_vm_enable_cap(s, capability, cap_flags, ...)             \
    ({                                                               \
        struct kvm_enable_cap cap = {                                \
            .cap = capability,                                       \
            .flags = cap_flags,                                      \
        };                                                           \
        uint64_t args_tmp[] = { __VA_ARGS__ };                       \
        int i;                                                       \
        for (i = 0; i < (int)ARRAY_SIZE(args_tmp) &&                 \
                     i < ARRAY_SIZE(cap.args); i++) {                \
            cap.args[i] = args_tmp[i];                               \
        }                                                            \
        kvm_vm_ioctl(s, KVM_ENABLE_CAP, &cap);                       \
    })

#define TYPE_IRQ "irq"

#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs) { .unspecified = 1 })
#define BP_ANY                (BP_GDB | BP_CPU)
#define BP_CPU                0x20
#define BP_GDB                0x10
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_STOP_BEFORE_ACCESS 0x04
#define BP_WATCHPOINT_HIT (BP_WATCHPOINT_HIT_READ | BP_WATCHPOINT_HIT_WRITE)
#define BP_WATCHPOINT_HIT_READ 0x40
#define BP_WATCHPOINT_HIT_WRITE 0x80
#define CPU(obj) ((CPUState *)(obj))
#define CPU_CLASS(class) OBJECT_CLASS_CHECK(CPUClass, (class), TYPE_CPU)
#define CPU_FOREACH(cpu) QTAILQ_FOREACH(cpu, &cpus, node)
#define CPU_FOREACH_REVERSE(cpu) \
    QTAILQ_FOREACH_REVERSE(cpu, &cpus, CPUTailQ, node)
#define CPU_FOREACH_SAFE(cpu, next_cpu) \
    QTAILQ_FOREACH_SAFE(cpu, &cpus, node, next_cpu)
#define CPU_GET_CLASS(obj) OBJECT_GET_CLASS(CPUClass, (obj), TYPE_CPU)
#define CPU_NEXT(cpu) QTAILQ_NEXT(cpu, node)

#define SSTEP_ENABLE  0x1  
#define SSTEP_NOIRQ   0x2  
#define SSTEP_NOTIMER 0x4  
#define TB_JMP_CACHE_BITS 12
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)
#define TYPE_CPU "cpu"
#define VADDR_MAX UINT64_MAX
#define VADDR_PRIX PRIX64
#define VADDR_PRId PRId64
#define VADDR_PRIo PRIo64
#define VADDR_PRIu PRIu64
#define VADDR_PRIx PRIx64
#define VMSTATE_CPU() {                                                     \
    .name = "parent_obj",                                                   \
    .size = sizeof(CPUState),                                               \
    .vmsd = &vmstate_cpu_common,                                            \
    .flags = VMS_STRUCT,                                                    \
    .offset = 0,                                                            \
}
#define first_cpu QTAILQ_FIRST(&cpus)
#define vmstate_cpu_common vmstate_dummy
#define QEMU_THREAD_DETACHED 1
#define QEMU_THREAD_JOINABLE 0
#define __QEMU_THREAD_H 1
#define __QEMU_THREAD_POSIX_H 1
#define __QEMU_THREAD_WIN32_H 1
#define HWADDR_BITS 64

#define HWADDR_MAX UINT64_MAX
#define HWADDR_PRIX PRIX64
#define HWADDR_PRId PRId64
#define HWADDR_PRIi PRIi64
#define HWADDR_PRIo PRIo64
#define HWADDR_PRIu PRIu64
#define HWADDR_PRIx PRIx64
#define TARGET_FMT_plx "%016" PRIx64
#define ATTRIBUTE_UNUSED __attribute__((unused))


#define INIT_DISASSEMBLE_INFO(INFO, STREAM, FPRINTF_FUNC) \
  (INFO).flavour = bfd_target_unknown_flavour, \
  (INFO).arch = bfd_arch_unknown, \
  (INFO).mach = 0, \
  (INFO).endian = BFD_ENDIAN_UNKNOWN, \
  INIT_DISASSEMBLE_INFO_NO_ARCH(INFO, STREAM, FPRINTF_FUNC)
#define INIT_DISASSEMBLE_INFO_NO_ARCH(INFO, STREAM, FPRINTF_FUNC) \
  (INFO).fprintf_func = (FPRINTF_FUNC), \
  (INFO).stream = (STREAM), \
  (INFO).symbols = NULL, \
  (INFO).num_symbols = 0, \
  (INFO).private_data = NULL, \
  (INFO).buffer = NULL, \
  (INFO).buffer_vma = 0, \
  (INFO).buffer_length = 0, \
  (INFO).read_memory_func = buffer_read_memory, \
  (INFO).memory_error_func = perror_memory, \
  (INFO).print_address_func = generic_print_address, \
  (INFO).print_insn = NULL, \
  (INFO).symbol_at_address_func = generic_symbol_at_address, \
  (INFO).flags = 0, \
  (INFO).bytes_per_line = 0, \
  (INFO).bytes_per_chunk = 0, \
  (INFO).display_endian = BFD_ENDIAN_UNKNOWN, \
  (INFO).disassembler_options = NULL, \
  (INFO).insn_info_valid = 0
#define _(x) x
#define bfd_mach_alpha 1
#define bfd_mach_alpha_ev4  0x10
#define bfd_mach_alpha_ev5  0x20
#define bfd_mach_alpha_ev6  0x30
#define bfd_mach_arc_base 0
#define bfd_mach_arm_3M 	4
#define bfd_mach_arm_4 		5
#define bfd_mach_arm_4T 	6
#define bfd_mach_arm_5 		7
#define bfd_mach_cpu32  8
#define bfd_mach_cris_v0_v10   255
#define bfd_mach_cris_v10_v32  1032
#define bfd_mach_cris_v32      32
#define bfd_mach_h8300   1
#define bfd_mach_h8300h  2
#define bfd_mach_h8300s  3
#define bfd_mach_hppa10        10
#define bfd_mach_hppa11        11
#define bfd_mach_hppa20        20
#define bfd_mach_hppa20w       25
#define bfd_mach_i386_i386 0
#define bfd_mach_i386_i386_intel_syntax 2
#define bfd_mach_i386_i8086 1
#define bfd_mach_i960_ca        6
#define bfd_mach_i960_core      1
#define bfd_mach_i960_hx        8
#define bfd_mach_i960_jx        7
#define bfd_mach_i960_ka_sa     2
#define bfd_mach_i960_kb_sb     3
#define bfd_mach_i960_mc        4
#define bfd_mach_i960_xa        5
#define bfd_mach_ia64_elf32    32
#define bfd_mach_ia64_elf64    64
#define bfd_mach_lm32 1
#define bfd_mach_m32r          0  
#define bfd_mach_m68000 1
#define bfd_mach_m68008 2
#define bfd_mach_m68010 3
#define bfd_mach_m68020 4
#define bfd_mach_m68030 5
#define bfd_mach_m68040 6
#define bfd_mach_m68060 7
#define bfd_mach_mcf5200  9
#define bfd_mach_mcf5206e 10
#define bfd_mach_mcf521x   15
#define bfd_mach_mcf5249   16
#define bfd_mach_mcf528x  13
#define bfd_mach_mcf5307  11
#define bfd_mach_mcf5407  12
#define bfd_mach_mcf547x   17
#define bfd_mach_mcf548x   18
#define bfd_mach_mcfv4e   14
#define bfd_mach_mips10000             10000
#define bfd_mach_mips16                16
#define bfd_mach_mips3000              3000
#define bfd_mach_mips3900              3900
#define bfd_mach_mips4000              4000
#define bfd_mach_mips4010              4010
#define bfd_mach_mips4100              4100
#define bfd_mach_mips4300              4300
#define bfd_mach_mips4400              4400
#define bfd_mach_mips4600              4600
#define bfd_mach_mips4650              4650
#define bfd_mach_mips5000              5000
#define bfd_mach_mips6000              6000
#define bfd_mach_mips8000              8000
#define bfd_mach_ppc           0
#define bfd_mach_ppc64         1
#define bfd_mach_ppc_403       403
#define bfd_mach_ppc_403gc     4030
#define bfd_mach_ppc_505       505
#define bfd_mach_ppc_601       601
#define bfd_mach_ppc_602       602
#define bfd_mach_ppc_603       603
#define bfd_mach_ppc_604       604
#define bfd_mach_ppc_620       620
#define bfd_mach_ppc_630       630
#define bfd_mach_ppc_7400      7400
#define bfd_mach_ppc_750       750
#define bfd_mach_ppc_860       860
#define bfd_mach_ppc_a35       35
#define bfd_mach_ppc_e500      500
#define bfd_mach_ppc_ec603e    6031
#define bfd_mach_ppc_rs64ii    642
#define bfd_mach_ppc_rs64iii   643
#define bfd_mach_s390_31 31
#define bfd_mach_s390_64 64
#define bfd_mach_sh            1
#define bfd_mach_sh2        0x20
#define bfd_mach_sh2a       0x2a
#define bfd_mach_sh2a_nofpu 0x2b
#define bfd_mach_sh2e       0x2e
#define bfd_mach_sh3        0x30
#define bfd_mach_sh3_dsp    0x3d
#define bfd_mach_sh3_nommu  0x31
#define bfd_mach_sh3e       0x3e
#define bfd_mach_sh4        0x40
#define bfd_mach_sh4_nofpu  0x41
#define bfd_mach_sh4_nommu_nofpu  0x42
#define bfd_mach_sh4a       0x4a
#define bfd_mach_sh4a_nofpu 0x4b
#define bfd_mach_sh4al_dsp  0x4d
#define bfd_mach_sh5        0x50
#define bfd_mach_sh_dsp     0x2d
#define bfd_mach_sparc                 1
#define bfd_mach_sparc_sparclet        2
#define bfd_mach_sparc_sparclite       3
#define bfd_mach_sparc_sparclite_le    6
#define bfd_mach_sparc_v8plus          4
#define bfd_mach_sparc_v8plusa         5 
#define bfd_mach_sparc_v8plusb         9 
#define bfd_mach_sparc_v9              7
#define bfd_mach_sparc_v9_p(mach) \
  ((mach) >= bfd_mach_sparc_v8plus && (mach) <= bfd_mach_sparc_v9b \
   && (mach) != bfd_mach_sparc_sparclite_le)
#define bfd_mach_sparc_v9a             8 
#define bfd_mach_sparc_v9b             10 
#define bfd_mach_v850          0
#define bfd_mach_x86_64 3
#define bfd_mach_x86_64_intel_syntax 4
#define bfd_mach_z8001         1
#define bfd_mach_z8002         2
#define snprintf_vma(s,ss,x) snprintf (s, ss, "%0" PRIx64, x)
#define sprintf_vma(s,x) sprintf (s, "%0" PRIx64, x)
#define BUS(obj) OBJECT_CHECK(BusState, (obj), TYPE_BUS)
#define BUS_CLASS(klass) OBJECT_CLASS_CHECK(BusClass, (klass), TYPE_BUS)
#define BUS_GET_CLASS(obj) OBJECT_GET_CLASS(BusClass, (obj), TYPE_BUS)
#define DEVICE(obj) OBJECT_CHECK(DeviceState, (obj), TYPE_DEVICE)
#define DEVICE_CLASS(klass) OBJECT_CLASS_CHECK(DeviceClass, (klass), TYPE_DEVICE)
#define DEVICE_GET_CLASS(obj) OBJECT_GET_CLASS(DeviceClass, (obj), TYPE_DEVICE)

#define QDEV_HOTPLUG_HANDLER_PROPERTY "hotplug-handler"
#define TYPE_BUS "bus"
#define TYPE_DEVICE "device"

#define HOTPLUG_HANDLER(obj) \
     INTERFACE_CHECK(HotplugHandler, (obj), TYPE_HOTPLUG_HANDLER)
#define HOTPLUG_HANDLER_CLASS(klass) \
     OBJECT_CLASS_CHECK(HotplugHandlerClass, (klass), TYPE_HOTPLUG_HANDLER)
#define HOTPLUG_HANDLER_GET_CLASS(obj) \
     OBJECT_GET_CLASS(HotplugHandlerClass, (obj), TYPE_HOTPLUG_HANDLER)
#define TYPE_HOTPLUG_HANDLER "hotplug-handler"
#define INTERFACE_CHECK(interface, obj, name) \
    ((interface *)object_dynamic_cast_assert(OBJECT((obj)), (name), \
                                             "__FILE__", "__LINE__", __func__))
#define INTERFACE_CLASS(klass) \
    OBJECT_CLASS_CHECK(InterfaceClass, klass, TYPE_INTERFACE)
#define OBJECT(obj) \
    ((Object *)(obj))
#define OBJECT_CHECK(type, obj, name) \
    ((type *)object_dynamic_cast_assert(OBJECT(obj), (name), \
                                        "__FILE__", "__LINE__", __func__))
#define OBJECT_CLASS(class) \
    ((ObjectClass *)(class))
#define OBJECT_CLASS_CAST_CACHE 4
#define OBJECT_CLASS_CHECK(class_type, class, name) \
    ((class_type *)object_class_dynamic_cast_assert(OBJECT_CLASS(class), (name), \
                                               "__FILE__", "__LINE__", __func__))
#define OBJECT_GET_CLASS(class, obj, name) \
    OBJECT_CLASS_CHECK(class, object_get_class(OBJECT(obj)), name)

#define TYPE_INTERFACE "interface"
#define TYPE_OBJECT "object"

#define BITMAP_LAST_WORD_MASK(nbits)                                    \
    (                                                                   \
        ((nbits) % BITS_PER_LONG) ?                                     \
        (1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL                       \
        )
#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]
#define small_nbits(nbits)                      \
        ((nbits) <= BITS_PER_LONG)
#define BIT(nr)                 (1UL << (nr))

#define BITS_PER_BYTE           CHAR_BIT
#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)


#define MIPS_RDHWR(rd, value) {                         \
        __asm__ __volatile__ (".set   push\n\t"         \
                              ".set mips32r2\n\t"       \
                              "rdhwr  %0, "rd"\n\t"     \
                              ".set   pop"              \
                              : "=r" (value));          \
    }
#define NANOSECONDS_PER_SECOND 1000000000LL

#define SCALE_MS 1000000
#define SCALE_NS 1
#define SCALE_US 1000
#define NOTIFIER_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }
#define NOTIFIER_WITH_RETURN_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }

#define BDRV_BLOCK_ALLOCATED    0x10
#define BDRV_BLOCK_DATA         0x01
#define BDRV_BLOCK_OFFSET_MASK  BDRV_SECTOR_MASK
#define BDRV_BLOCK_OFFSET_VALID 0x04
#define BDRV_BLOCK_RAW          0x08
#define BDRV_BLOCK_ZERO         0x02
#define BDRV_OPT_CACHE_DIRECT   "cache.direct"
#define BDRV_OPT_CACHE_NO_FLUSH "cache.no-flush"
#define BDRV_OPT_CACHE_WB       "cache.writeback"
#define BDRV_O_ALLOW_RDWR  0x2000  
#define BDRV_O_CACHE_MASK  (BDRV_O_NOCACHE | BDRV_O_CACHE_WB | BDRV_O_NO_FLUSH)
#define BDRV_O_CACHE_WB    0x0040 
#define BDRV_O_CHECK       0x1000  
#define BDRV_O_COPY_ON_READ 0x0400 
#define BDRV_O_INACTIVE    0x0800  
#define BDRV_O_NATIVE_AIO  0x0080 
#define BDRV_O_NOCACHE     0x0020 
#define BDRV_O_NO_BACKING  0x0100 
#define BDRV_O_NO_FLUSH    0x0200 
#define BDRV_O_PROTOCOL    0x8000  
#define BDRV_O_RDWR        0x0002
#define BDRV_O_SNAPSHOT    0x0008 
#define BDRV_O_TEMPORARY   0x0010 
#define BDRV_O_UNMAP       0x4000  
#define BDRV_REQUEST_MAX_SECTORS MIN(SIZE_MAX >> BDRV_SECTOR_BITS, \
                                     INT_MAX >> BDRV_SECTOR_BITS)
#define BDRV_SECTOR_BITS   9
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1)
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BLKDBG_EVENT(child, evt) \
    do { \
        if (child) { \
            bdrv_debug_event(child->bs, evt); \
        } \
    } while (0)







#define VMSTATE_UINTTL(_f, _s)                                        \
    VMSTATE_UINTTL_V(_f, _s, 0)
#define VMSTATE_UINTTL_ARRAY(_f, _s, _n)                              \
    VMSTATE_UINTTL_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINTTL_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_UINT64_ARRAY_V(_f, _s, _n, _v)
#define VMSTATE_UINTTL_EQUAL(_f, _s)                                  \
    VMSTATE_UINTTL_EQUAL_V(_f, _s, 0)
#define VMSTATE_UINTTL_EQUAL_V(_f, _s, _v)                            \
    VMSTATE_UINT64_EQUAL_V(_f, _s, _v)
#define VMSTATE_UINTTL_V(_f, _s, _v)                                  \
    VMSTATE_UINT64_V(_f, _s, _v)
#define qemu_get_betl qemu_get_be64
#define qemu_get_betls qemu_get_be64s
#define qemu_get_sbetl qemu_get_sbe64
#define qemu_get_sbetls qemu_get_sbe64s
#define qemu_put_betl qemu_put_be64
#define qemu_put_betls qemu_put_be64s
#define qemu_put_sbetl qemu_put_sbe64
#define qemu_put_sbetls qemu_put_sbe64s
#define vmstate_info_uinttl vmstate_info_uint64
#define CPU_LOG_EXEC       (1 << 5)
#define CPU_LOG_INT        (1 << 4)
#define CPU_LOG_MMU        (1 << 12)
#define CPU_LOG_PAGE       (1 << 14)
#define CPU_LOG_PCALL      (1 << 6)
#define CPU_LOG_RESET      (1 << 9)
#define CPU_LOG_TB_CPU     (1 << 8)
#define CPU_LOG_TB_IN_ASM  (1 << 1)
#define CPU_LOG_TB_NOCHAIN (1 << 13)
#define CPU_LOG_TB_OP      (1 << 2)
#define CPU_LOG_TB_OP_OPT  (1 << 3)
#define CPU_LOG_TB_OUT_ASM (1 << 0)
#define LOG_GUEST_ERROR    (1 << 11)
#define LOG_UNIMP          (1 << 10)


#define QEMU_VMSTATE_H 1
#define SELF_ANNOUNCE_ROUNDS 5
#define VMSTATE_2DARRAY(_field, _state, _n1, _n2, _version, _info, _type) { \
    .name       = (stringify(_field)),                                      \
    .version_id = (_version),                                               \
    .num        = (_n1) * (_n2),                                            \
    .info       = &(_info),                                                 \
    .size       = sizeof(_type),                                            \
    .flags      = VMS_ARRAY,                                                \
    .offset     = vmstate_offset_2darray(_state, _field, _type, _n1, _n2),  \
}
#define VMSTATE_ARRAY(_field, _state, _num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY,                                         \
    .offset     = vmstate_offset_array(_state, _field, _type, _num), \
}
#define VMSTATE_ARRAY_INT32_UNSAFE(_field, _state, _field_num, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_INT32,                                  \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_ARRAY_OF_POINTER(_field, _state, _num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY|VMS_ARRAY_OF_POINTER,                    \
    .offset     = vmstate_offset_array(_state, _field, _type, _num), \
}
#define VMSTATE_ARRAY_OF_POINTER_TO_STRUCT(_f, _s, _n, _v, _vmsd, _type) { \
    .name       = (stringify(_f)),                                   \
    .version_id = (_v),                                              \
    .num        = (_n),                                              \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type *),                                    \
    .flags      = VMS_ARRAY|VMS_STRUCT|VMS_ARRAY_OF_POINTER,         \
    .offset     = vmstate_offset_array(_s, _f, _type*, _n),          \
}
#define VMSTATE_ARRAY_TEST(_field, _state, _num, _test, _info, _type) {\
    .name         = (stringify(_field)),                              \
    .field_exists = (_test),                                          \
    .num          = (_num),                                           \
    .info         = &(_info),                                         \
    .size         = sizeof(_type),                                    \
    .flags        = VMS_ARRAY,                                        \
    .offset       = vmstate_offset_array(_state, _field, _type, _num),\
}
#define VMSTATE_BITMAP(_field, _state, _version, _field_size) {      \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .size_offset  = vmstate_offset_value(_state, _field_size, int32_t),\
    .info         = &vmstate_info_bitmap,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_BOOL(_f, _s)                                          \
    VMSTATE_BOOL_V(_f, _s, 0)
#define VMSTATE_BOOL_ARRAY(_f, _s, _n)                               \
    VMSTATE_BOOL_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_BOOL_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_bool, bool)
#define VMSTATE_BOOL_V(_f, _s, _v)                                    \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_bool, bool)
#define VMSTATE_BUFFER(_f, _s)                                        \
    VMSTATE_BUFFER_V(_f, _s, 0)
#define VMSTATE_BUFFER_POINTER_UNSAFE(_field, _state, _version, _size) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .size       = (_size),                                           \
    .info       = &vmstate_info_buffer,                              \
    .flags      = VMS_BUFFER|VMS_POINTER,                            \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_BUFFER_START_MIDDLE(_f, _s, _start) \
    VMSTATE_STATIC_BUFFER(_f, _s, 0, NULL, _start, sizeof(typeof_field(_s, _f)))
#define VMSTATE_BUFFER_TEST(_f, _s, _test)                            \
    VMSTATE_STATIC_BUFFER(_f, _s, 0, _test, 0, sizeof(typeof_field(_s, _f)))
#define VMSTATE_BUFFER_UNSAFE(_field, _state, _version, _size)        \
    VMSTATE_BUFFER_UNSAFE_INFO(_field, _state, _version, vmstate_info_buffer, _size)
#define VMSTATE_BUFFER_UNSAFE_INFO(_field, _state, _version, _info, _size) \
    VMSTATE_BUFFER_UNSAFE_INFO_TEST(_field, _state, NULL, _version, _info, \
            _size)
#define VMSTATE_BUFFER_UNSAFE_INFO_TEST(_field, _state, _test, _version, _info, _size) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .field_exists = (_test),                                         \
    .size       = (_size),                                           \
    .info       = &(_info),                                          \
    .flags      = VMS_BUFFER,                                        \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_BUFFER_V(_f, _s, _v)                                  \
    VMSTATE_STATIC_BUFFER(_f, _s, _v, NULL, 0, sizeof(typeof_field(_s, _f)))
#define VMSTATE_CPUDOUBLE_ARRAY(_f, _s, _n)                           \
    VMSTATE_CPUDOUBLE_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_CPUDOUBLE_ARRAY_V(_f, _s, _n, _v)                     \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_cpudouble, CPU_DoubleU)
#define VMSTATE_END_OF_LIST()                                         \
    {}
#define VMSTATE_FLOAT64(_f, _s)                                       \
    VMSTATE_FLOAT64_V(_f, _s, 0)
#define VMSTATE_FLOAT64_ARRAY(_f, _s, _n)                             \
    VMSTATE_FLOAT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_FLOAT64_ARRAY_V(_f, _s, _n, _v)                       \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_float64, float64)
#define VMSTATE_FLOAT64_V(_f, _s, _v)                                 \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_float64, float64)
#define VMSTATE_INT16(_f, _s)                                         \
    VMSTATE_INT16_V(_f, _s, 0)
#define VMSTATE_INT16_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT16_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT16_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int16, int16_t)
#define VMSTATE_INT16_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int16, int16_t)
#define VMSTATE_INT16_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int16, int16_t)
#define VMSTATE_INT32(_f, _s)                                         \
    VMSTATE_INT32_V(_f, _s, 0)
#define VMSTATE_INT32_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT32_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT32_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int32, int32_t)
#define VMSTATE_INT32_EQUAL(_f, _s)                                   \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_int32_equal, int32_t)
#define VMSTATE_INT32_POSITIVE_LE(_f, _s)                             \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_int32_le, int32_t)
#define VMSTATE_INT32_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int32, int32_t)
#define VMSTATE_INT32_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int32, int32_t)
#define VMSTATE_INT64(_f, _s)                                         \
    VMSTATE_INT64_V(_f, _s, 0)
#define VMSTATE_INT64_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT64_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int64, int64_t)
#define VMSTATE_INT64_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int64, int64_t)
#define VMSTATE_INT64_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int64, int64_t)
#define VMSTATE_INT8(_f, _s)                                          \
    VMSTATE_INT8_V(_f, _s, 0)
#define VMSTATE_INT8_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int8, int8_t)
#define VMSTATE_INT8_V(_f, _s, _v)                                    \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int8, int8_t)
#define VMSTATE_PARTIAL_BUFFER(_f, _s, _size)                         \
    VMSTATE_STATIC_BUFFER(_f, _s, 0, NULL, 0, _size)
#define VMSTATE_PARTIAL_VBUFFER(_f, _s, _size)                        \
    VMSTATE_VBUFFER(_f, _s, 0, NULL, 0, _size)
#define VMSTATE_PARTIAL_VBUFFER_UINT32(_f, _s, _size)                        \
    VMSTATE_VBUFFER_UINT32(_f, _s, 0, NULL, 0, _size)
#define VMSTATE_POINTER(_field, _state, _version, _info, _type) {    \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_SINGLE|VMS_POINTER,                            \
    .offset     = vmstate_offset_value(_state, _field, _type),       \
}
#define VMSTATE_POINTER_TEST(_field, _state, _test, _info, _type) {  \
    .name       = (stringify(_field)),                               \
    .info       = &(_info),                                          \
    .field_exists = (_test),                                         \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_SINGLE|VMS_POINTER,                            \
    .offset     = vmstate_offset_value(_state, _field, _type),       \
}
#define VMSTATE_SINGLE(_field, _state, _version, _info, _type)        \
    VMSTATE_SINGLE_TEST(_field, _state, NULL, _version, _info, _type)
#define VMSTATE_SINGLE_TEST(_field, _state, _test, _version, _info, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size         = sizeof(_type),                                   \
    .info         = &(_info),                                        \
    .flags        = VMS_SINGLE,                                      \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
}
#define VMSTATE_STATIC_BUFFER(_field, _state, _version, _test, _start, _size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size         = (_size - _start),                                \
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_BUFFER,                                      \
    .offset       = vmstate_offset_buffer(_state, _field) + _start,  \
}
#define VMSTATE_STRUCT(_field, _state, _version, _vmsd, _type)        \
    VMSTATE_STRUCT_TEST(_field, _state, NULL, _version, _vmsd, _type)
#define VMSTATE_STRUCT_ARRAY(_field, _state, _num, _version, _vmsd, _type) \
    VMSTATE_STRUCT_ARRAY_TEST(_field, _state, _num, NULL, _version,   \
            _vmsd, _type)
#define VMSTATE_STRUCT_ARRAY_TEST(_field, _state, _num, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .num          = (_num),                                          \
    .field_exists = (_test),                                         \
    .version_id   = (_version),                                      \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_STRUCT|VMS_ARRAY,                            \
    .offset       = vmstate_offset_array(_state, _field, _type, _num),\
}
#define VMSTATE_STRUCT_POINTER(_field, _state, _vmsd, _type)          \
    VMSTATE_STRUCT_POINTER_V(_field, _state, 0, _vmsd, _type)
#define VMSTATE_STRUCT_POINTER_TEST(_field, _state, _test, _vmsd, _type)     \
    VMSTATE_STRUCT_POINTER_TEST_V(_field, _state, _test, 0, _vmsd, _type)
#define VMSTATE_STRUCT_POINTER_TEST_V(_field, _state, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                        \
    .field_exists = (_test),                                         \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type *),                                 \
    .flags        = VMS_STRUCT|VMS_POINTER,                          \
    .offset       = vmstate_offset_pointer(_state, _field, _type),   \
}
#define VMSTATE_STRUCT_POINTER_V(_field, _state, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                        \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type *),                                 \
    .flags        = VMS_STRUCT|VMS_POINTER,                          \
    .offset       = vmstate_offset_pointer(_state, _field, _type),   \
}
#define VMSTATE_STRUCT_SUB_ARRAY(_field, _state, _start, _num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                                     \
    .version_id = (_version),                                              \
    .num        = (_num),                                                  \
    .vmsd       = &(_vmsd),                                                \
    .size       = sizeof(_type),                                           \
    .flags      = VMS_STRUCT|VMS_ARRAY,                                    \
    .offset     = vmstate_offset_sub_array(_state, _field, _type, _start), \
}
#define VMSTATE_STRUCT_TEST(_field, _state, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_STRUCT,                                      \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_ALLOC(_field, _state, _field_num, _version, _vmsd, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_INT32|VMS_ALLOC|VMS_POINTER, \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_INT32(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_INT32,                       \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_STRUCT_VARRAY_KNOWN(_field, _state, _num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num          = (_num),                                          \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_ARRAY,                              \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_INT32(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_INT32 | VMS_STRUCT,       \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT16(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, uint16_t),\
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_UINT16 | VMS_STRUCT,      \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT32(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_INT32 | VMS_STRUCT,       \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_UINT32(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_UINT32,                      \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_STRUCT_VARRAY_UINT8(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint8_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_UINT8,                       \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_SUB_ARRAY(_field, _state, _start, _num, _version, _info, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY,                                         \
    .offset     = vmstate_offset_sub_array(_state, _field, _type, _start), \
}
#define VMSTATE_SUB_VBUFFER(_f, _s, _start, _size)                    \
    VMSTATE_VBUFFER(_f, _s, 0, NULL, _start, _size)
#define VMSTATE_TIMER(_f, _s)                                         \
    VMSTATE_TIMER_V(_f, _s, 0)
#define VMSTATE_TIMER_ARRAY(_f, _s, _n)                              \
    VMSTATE_ARRAY(_f, _s, _n, 0, vmstate_info_timer, QEMUTimer)
#define VMSTATE_TIMER_PTR(_f, _s)                                         \
    VMSTATE_TIMER_PTR_V(_f, _s, 0)
#define VMSTATE_TIMER_PTR_ARRAY(_f, _s, _n)                              \
    VMSTATE_ARRAY_OF_POINTER(_f, _s, _n, 0, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_PTR_TEST(_f, _s, _test)                             \
    VMSTATE_POINTER_TEST(_f, _s, _test, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_PTR_V(_f, _s, _v)                                   \
    VMSTATE_POINTER(_f, _s, _v, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_TEST(_f, _s, _test)                             \
    VMSTATE_SINGLE_TEST(_f, _s, _test, 0, vmstate_info_timer, QEMUTimer)
#define VMSTATE_TIMER_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_timer, QEMUTimer)
#define VMSTATE_UINT16(_f, _s)                                        \
    VMSTATE_UINT16_V(_f, _s, 0)
#define VMSTATE_UINT16_2DARRAY(_f, _s, _n1, _n2)                      \
    VMSTATE_UINT16_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT16_2DARRAY_V(_f, _s, _n1, _n2, _v)                \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_ARRAY(_f, _s, _n)                               \
    VMSTATE_UINT16_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT16_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_EQUAL(_f, _s)                                  \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_uint16_equal, uint16_t)
#define VMSTATE_UINT16_EQUAL_V(_f, _s, _v)                            \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint16_equal, uint16_t)
#define VMSTATE_UINT16_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT32(_f, _s)                                        \
    VMSTATE_UINT32_V(_f, _s, 0)
#define VMSTATE_UINT32_2DARRAY(_f, _s, _n1, _n2)                      \
    VMSTATE_UINT32_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT32_2DARRAY_V(_f, _s, _n1, _n2, _v)                \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_ARRAY(_f, _s, _n)                              \
    VMSTATE_UINT32_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT32_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_EQUAL(_f, _s)                                  \
    VMSTATE_UINT32_EQUAL_V(_f, _s, 0)
#define VMSTATE_UINT32_EQUAL_V(_f, _s, _v)                            \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint32_equal, uint32_t)
#define VMSTATE_UINT32_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT64(_f, _s)                                        \
    VMSTATE_UINT64_V(_f, _s, 0)
#define VMSTATE_UINT64_ARRAY(_f, _s, _n)                              \
    VMSTATE_UINT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT64_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_EQUAL(_f, _s)                                  \
    VMSTATE_UINT64_EQUAL_V(_f, _s, 0)
#define VMSTATE_UINT64_EQUAL_V(_f, _s, _v)                            \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint64_equal, uint64_t)
#define VMSTATE_UINT64_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT8(_f, _s)                                         \
    VMSTATE_UINT8_V(_f, _s, 0)
#define VMSTATE_UINT8_2DARRAY(_f, _s, _n1, _n2)                       \
    VMSTATE_UINT8_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT8_2DARRAY_V(_f, _s, _n1, _n2, _v)                 \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_ARRAY(_f, _s, _n)                               \
    VMSTATE_UINT8_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT8_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_EQUAL(_f, _s)                                   \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_uint8_equal, uint8_t)
#define VMSTATE_UINT8_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UNUSED(_size)                                         \
    VMSTATE_UNUSED_V(0, _size)
#define VMSTATE_UNUSED_BUFFER(_test, _version, _size) {              \
    .name         = "unused",                                        \
    .field_exists = (_test),                                         \
    .version_id   = (_version),                                      \
    .size         = (_size),                                         \
    .info         = &vmstate_info_unused_buffer,                     \
    .flags        = VMS_BUFFER,                                      \
}
#define VMSTATE_UNUSED_TEST(_test, _size)                             \
    VMSTATE_UNUSED_BUFFER(_test, 0, _size)
#define VMSTATE_UNUSED_V(_v, _size)                                   \
    VMSTATE_UNUSED_BUFFER(NULL, _v, _size)
#define VMSTATE_VALIDATE(_name, _test) { \
    .name         = (_name),                                         \
    .field_exists = (_test),                                         \
    .flags        = VMS_ARRAY | VMS_MUST_EXIST,                      \
    .num          = 0,      \
}
#define VMSTATE_VARRAY_INT32(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_INT32|VMS_POINTER,                      \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VARRAY_MULTIPLY(_field, _state, _field_num, _multiply, _info, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .num        = (_multiply),                                       \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT32|VMS_MULTIPLY_ELEMENTS,           \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_VARRAY_UINT16_UNSAFE(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint16_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT16,                                 \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_VARRAY_UINT32(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT32|VMS_POINTER,                     \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VBUFFER(_field, _state, _version, _test, _start, _field_size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, int32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
    .start        = (_start),                                        \
}
#define VMSTATE_VBUFFER_ALLOC_UINT32(_field, _state, _version, _test, _start, _field_size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER|VMS_ALLOC,               \
    .offset       = offsetof(_state, _field),                        \
    .start        = (_start),                                        \
}
#define VMSTATE_VBUFFER_MULTIPLY(_field, _state, _version, _test, _start, _field_size, _multiply) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .size         = (_multiply),                                      \
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER|VMS_MULTIPLY,            \
    .offset       = offsetof(_state, _field),                        \
    .start        = (_start),                                        \
}
#define VMSTATE_VBUFFER_UINT32(_field, _state, _version, _test, _start, _field_size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
    .start        = (_start),                                        \
}
#define type_check_2darray(t1,t2,n,m) ((t1(*)[n][m])0 - (t2*)0)
#define type_check_array(t1,t2,n) ((t1(*)[n])0 - (t2*)0)
#define type_check_pointer(t1,t2) ((t1**)0 - (t2*)0)
#define vmstate_offset_2darray(_state, _field, _type, _n1, _n2)      \
    (offsetof(_state, _field) +                                      \
     type_check_2darray(_type, typeof_field(_state, _field), _n1, _n2))
#define vmstate_offset_array(_state, _field, _type, _num)            \
    (offsetof(_state, _field) +                                      \
     type_check_array(_type, typeof_field(_state, _field), _num))
#define vmstate_offset_buffer(_state, _field)                        \
    vmstate_offset_array(_state, _field, uint8_t,                    \
                         sizeof(typeof_field(_state, _field)))
#define vmstate_offset_pointer(_state, _field, _type)                \
    (offsetof(_state, _field) +                                      \
     type_check_pointer(_type, typeof_field(_state, _field)))
#define vmstate_offset_sub_array(_state, _field, _type, _start)      \
    vmstate_offset_value(_state, _field[_start], _type)
#define vmstate_offset_value(_state, _field, _type)                  \
    (offsetof(_state, _field) +                                      \
     type_check(_type, typeof_field(_state, _field)))

#define TYPE_QJSON "QJSON"
#define QEMU_FILE_H 1
#define RAM_CONTROL_BLOCK_REG 4
#define RAM_CONTROL_FINISH    3
#define RAM_CONTROL_HOOK      2
#define RAM_CONTROL_ROUND     1
#define RAM_CONTROL_SETUP     0
#define qemu_get_sbyte qemu_get_byte
#define qemu_put_sbyte qemu_put_byte
#define CPU_COMMON_H 1
#  define RAM_ADDR_FMT "%" PRIx64
#  define RAM_ADDR_MAX UINT64_MAX

#define FMT_pioaddr     PRIx32
#define IOPORTS_MASK    (MAX_IOPORTS - 1)

#define MAX_IOPORTS     (64 * 1024)
#define PORTIO_END_OF_LIST() { }
#define DIRTY_MEMORY_CODE      1
#define DIRTY_MEMORY_MIGRATION 2
#define DIRTY_MEMORY_NUM       3        
#define DIRTY_MEMORY_VGA       0
#define MAX_PHYS_ADDR            (((hwaddr)1 << MAX_PHYS_ADDR_SPACE_BITS) - 1)
#define MAX_PHYS_ADDR_SPACE_BITS 62

#define MEMORY_REGION(obj) \
        OBJECT_CHECK(MemoryRegion, (obj), TYPE_MEMORY_REGION)
#define MEMTX_DECODE_ERROR      (1U << 1) 
#define MEMTX_ERROR             (1U << 0) 
#define MEMTX_OK 0
#define TYPE_MEMORY_REGION "qemu:memory-region"

#define call_rcu(head, func, field)                                      \
    call_rcu1(({                                                         \
         char __attribute__((unused))                                    \
            offset_must_be_zero[-offsetof(typeof(*(head)), field)],      \
            func_type_invalid = (func) - (void (*)(typeof(head)))(func); \
         &(head)->field;                                                 \
      }),                                                                \
      (RCUCBFunc *)(func))
#define g_free_rcu(obj, field) \
    call_rcu1(({                                                         \
        char __attribute__((unused))                                     \
            offset_must_be_zero[-offsetof(typeof(*(obj)), field)];       \
        &(obj)->field;                                                   \
      }),                                                                \
      (RCUCBFunc *)g_free);
#define rcu_assert(args...)    assert(args)


#define MAX_CPUMASK_BITS 255
#define MAX_NODES 128
#define MAX_OPTION_ROMS 16
#define MAX_PARALLEL_PORTS 3
#define MAX_PROM_ENVS 128
#define MAX_SERIAL_PORTS 4
#define MAX_VM_CMD_PACKAGED_SIZE (1ul << 24)
#define NUMA_NODE_UNASSIGNED MAX_NODES

#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
#define UUID_NONE "00000000-0000-0000-0000-000000000000"
#define VMRESET_REPORT   true
#define VMRESET_SILENT   false
#define xenfb_enabled (vga_interface_type == VGA_XENFB)
#define QEMU_MAIN_LOOP_H 1
#define SIG_IPI SIGUSR1
#define ELF_LOAD_FAILED       -1
#define ELF_LOAD_NOT_ELF      -2
#define ELF_LOAD_WRONG_ARCH   -3
#define ELF_LOAD_WRONG_ENDIAN -4

#define LOAD_IMAGE_MAX_GUNZIP_BYTES (256 << 20)
#define PC_ROM_ALIGN       0x800
#define PC_ROM_MAX         0xe0000
#define PC_ROM_MIN_OPTION  0xc8000
#define PC_ROM_MIN_VGA     0xc0000
#define PC_ROM_SIZE        (PC_ROM_MAX - PC_ROM_MIN_VGA)
#define rom_add_blob_fixed(_f, _b, _l, _a)      \
    rom_add_blob(_f, _b, _l, _l, _a, NULL, NULL, NULL)
#define rom_add_file_fixed(_f, _a, _i)          \
    rom_add_file(_f, NULL, _a, _i, false)
#define FW_CFG_ARCH_LOCAL       0x8000
#define FW_CFG_BOOT_DEVICE      0x0c
#define FW_CFG_BOOT_MENU        0x0e
#define FW_CFG_CMDLINE_ADDR     0x13
#define FW_CFG_CMDLINE_DATA     0x15
#define FW_CFG_CMDLINE_SIZE     0x14
#define FW_CFG_ENTRY_MASK       ~(FW_CFG_WRITE_CHANNEL | FW_CFG_ARCH_LOCAL)
#define FW_CFG_FILE_DIR         0x19
#define FW_CFG_FILE_FIRST       0x20
#define FW_CFG_FILE_SLOTS       0x10

#define FW_CFG_ID               0x01
#define FW_CFG_INITRD_ADDR      0x0a
#define FW_CFG_INITRD_DATA      0x12
#define FW_CFG_INITRD_SIZE      0x0b
#define FW_CFG_INVALID          0xffff
#define FW_CFG_KERNEL_ADDR      0x07
#define FW_CFG_KERNEL_CMDLINE   0x09
#define FW_CFG_KERNEL_DATA      0x11
#define FW_CFG_KERNEL_ENTRY     0x10
#define FW_CFG_KERNEL_SIZE      0x08
#define FW_CFG_MACHINE_ID       0x06
#define FW_CFG_MAX_CPUS         0x0f
#define FW_CFG_MAX_ENTRY        (FW_CFG_FILE_FIRST+FW_CFG_FILE_SLOTS)
#define FW_CFG_MAX_FILE_PATH    56
#define FW_CFG_NB_CPUS          0x05
#define FW_CFG_NOGRAPHIC        0x04
#define FW_CFG_NUMA             0x0d
#define FW_CFG_RAM_SIZE         0x03
#define FW_CFG_SETUP_ADDR       0x16
#define FW_CFG_SETUP_DATA       0x18
#define FW_CFG_SETUP_SIZE       0x17
#define FW_CFG_SIGNATURE        0x00
#define FW_CFG_UUID             0x02
#define FW_CFG_WRITE_CHANNEL    0x4000

#define DEFAULT_BRIDGE_HELPER CONFIG_QEMU_HELPERDIR "/qemu-bridge-helper"
#define DEFAULT_BRIDGE_INTERFACE "br0"
#define DEFAULT_NETWORK_DOWN_SCRIPT "/etc/qemu-ifdown"
#define DEFAULT_NETWORK_SCRIPT "/etc/qemu-ifup"
#define DEFINE_NIC_PROPERTIES(_state, _conf)                            \
    DEFINE_PROP_MACADDR("mac",   _state, _conf.macaddr),                \
    DEFINE_PROP_VLAN("vlan",     _state, _conf.peers),                   \
    DEFINE_PROP_NETDEV("netdev", _state, _conf.peers)
#define MAX_NICS 8
#define MAX_QUEUE_NUM 1024
#define NET_BUFSIZE (4096 + 65536)
#define POLYNOMIAL 0x04c11db6

#define VMSTATE_MACADDR(_field, _state) {                            \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(MACAddr),                                   \
    .info       = &vmstate_info_buffer,                              \
    .flags      = VMS_BUFFER,                                        \
    .offset     = vmstate_offset_macaddr(_state, _field),            \
}
#define vmstate_offset_macaddr(_state, _field)                       \
    vmstate_offset_array(_state, _field.a, uint8_t,                \
                         sizeof(typeof_field(_state, _field)))
#define QEMU_NET_PACKET_FLAG_NONE  0
#define QEMU_NET_PACKET_FLAG_RAW  (1<<0)

#define FMT_PCIBUS                      PRIx64
#define PCIE_CONFIG_SPACE_SIZE  0x1000
#define PCI_BAR_UNMAPPED (~(pcibus_t)0)
#define PCI_BUS(obj) OBJECT_CHECK(PCIBus, (obj), TYPE_PCI_BUS)
#define PCI_BUS_CLASS(klass) OBJECT_CLASS_CHECK(PCIBusClass, (klass), TYPE_PCI_BUS)
#define PCI_BUS_GET_CLASS(obj) OBJECT_GET_CLASS(PCIBusClass, (obj), TYPE_PCI_BUS)
#define PCI_CONFIG_HEADER_SIZE 0x40
#define PCI_CONFIG_SPACE_SIZE 0x100
#define PCI_DEVFN(slot, func)   ((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_DEVICE(obj) \
     OBJECT_CHECK(PCIDevice, (obj), TYPE_PCI_DEVICE)
#define PCI_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(PCIDeviceClass, (klass), TYPE_PCI_DEVICE)
#define PCI_DEVICE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(PCIDeviceClass, (obj), TYPE_PCI_DEVICE)
#define PCI_DEVICE_ID_APPLE_343S1201     0x0010
#define PCI_DEVICE_ID_APPLE_IPID_USB     0x003f
#define PCI_DEVICE_ID_APPLE_UNI_N_I_PCI  0x001e
#define PCI_DEVICE_ID_APPLE_UNI_N_KEYL   0x0022
#define PCI_DEVICE_ID_APPLE_UNI_N_PCI    0x001f
#define PCI_DEVICE_ID_HITACHI_SH7751R    0x350e
#define PCI_DEVICE_ID_IBM_440GX          0x027f
#define PCI_DEVICE_ID_IBM_OPENPIC2       0xffff
#define PCI_DEVICE_ID_INTEL_82551IT      0x1209
#define PCI_DEVICE_ID_INTEL_82557        0x1229
#define PCI_DEVICE_ID_INTEL_82801IR      0x2922
#define PCI_DEVICE_ID_MARVELL_GT6412X    0x4620
#define PCI_DEVICE_ID_QEMU_VGA           0x1111
#define PCI_DEVICE_ID_REALTEK_8029       0x8029
#define PCI_DEVICE_ID_REDHAT_BRIDGE      0x0001
#define PCI_DEVICE_ID_REDHAT_BRIDGE_SEAT 0x000a
#define PCI_DEVICE_ID_REDHAT_PCIE_HOST   0x0008
#define PCI_DEVICE_ID_REDHAT_PXB         0x0009
#define PCI_DEVICE_ID_REDHAT_PXB_PCIE    0x000b
#define PCI_DEVICE_ID_REDHAT_QXL         0x0100
#define PCI_DEVICE_ID_REDHAT_ROCKER      0x0006
#define PCI_DEVICE_ID_REDHAT_SDHCI       0x0007
#define PCI_DEVICE_ID_REDHAT_SERIAL      0x0002
#define PCI_DEVICE_ID_REDHAT_SERIAL2     0x0003
#define PCI_DEVICE_ID_REDHAT_SERIAL4     0x0004
#define PCI_DEVICE_ID_REDHAT_TEST        0x0005
#define PCI_DEVICE_ID_VIRTIO_9P          0x1009
#define PCI_DEVICE_ID_VIRTIO_BALLOON     0x1002
#define PCI_DEVICE_ID_VIRTIO_BLOCK       0x1001
#define PCI_DEVICE_ID_VIRTIO_CONSOLE     0x1003
#define PCI_DEVICE_ID_VIRTIO_NET         0x1000
#define PCI_DEVICE_ID_VIRTIO_RNG         0x1005
#define PCI_DEVICE_ID_VIRTIO_SCSI        0x1004
#define PCI_DEVICE_ID_VMWARE_IDE         0x1729
#define PCI_DEVICE_ID_VMWARE_NET         0x0720
#define PCI_DEVICE_ID_VMWARE_PVSCSI      0x07C0
#define PCI_DEVICE_ID_VMWARE_SCSI        0x0730
#define PCI_DEVICE_ID_VMWARE_SVGA        0x0710
#define PCI_DEVICE_ID_VMWARE_SVGA2       0x0405
#define PCI_DEVICE_ID_VMWARE_VMXNET3     0x07B0
#define PCI_DEVICE_ID_XILINX_XC2VP30     0x0300
#define PCI_DMA_DEFINE_LDST(_l, _s, _bits)                              \
    static inline uint##_bits##_t ld##_l##_pci_dma(PCIDevice *dev,      \
                                                   dma_addr_t addr)     \
    {                                                                   \
        return ld##_l##_dma(pci_get_address_space(dev), addr);          \
    }                                                                   \
    static inline void st##_s##_pci_dma(PCIDevice *dev,                 \
                                        dma_addr_t addr, uint##_bits##_t val) \
    {                                                                   \
        st##_s##_dma(pci_get_address_space(dev), addr, val);            \
    }
#define PCI_FUNC(devfn)         ((devfn) & 0x07)
#define PCI_FUNC_MAX            8
#define  PCI_HEADER_TYPE_MULTI_FUNCTION 0x80
#define PCI_NUM_PINS 4 
#define PCI_NUM_REGIONS 7
#define PCI_ROM_SLOT 6
#define PCI_SLOT(devfn)         (((devfn) >> 3) & 0x1f)
#define PCI_SLOT_MAX            32
#define PCI_SUBDEVICE_ID_QEMU            0x1100
#define PCI_SUBVENDOR_ID_REDHAT_QUMRANET 0x1af4
#define PCI_VENDOR_ID_HITACHI            0x1054
#define PCI_VENDOR_ID_QEMU               0x1234
#define PCI_VENDOR_ID_REDHAT             0x1b36
#define PCI_VENDOR_ID_REDHAT_QUMRANET    0x1af4
#define PCI_VENDOR_ID_VMWARE             0x15ad
#define QEMU_PCIE_SLTCAP_PCP_BITNR 7
#define QEMU_PCI_CAP_MULTIFUNCTION_BITNR        3
#define QEMU_PCI_CAP_SERR_BITNR 4

#define QEMU_PCI_SHPC_BITNR 5
#define QEMU_PCI_SLOTID_BITNR 6
#define QEMU_PCI_VGA_IO_HI_BASE 0x3c0
#define QEMU_PCI_VGA_IO_HI_SIZE 0x20
#define QEMU_PCI_VGA_IO_LO_BASE 0x3b0
#define QEMU_PCI_VGA_IO_LO_SIZE 0xc
#define QEMU_PCI_VGA_MEM_BASE 0xa0000
#define QEMU_PCI_VGA_MEM_SIZE 0x20000
#define TYPE_PCIE_BUS "PCIE"
#define TYPE_PCI_BUS "PCI"
#define TYPE_PCI_DEVICE "pci-device"
#define VMSTATE_PCI_DEVICE(_field, _state) {                         \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(PCIDevice),                                 \
    .vmsd       = &vmstate_pci_device,                               \
    .flags      = VMS_STRUCT,                                        \
    .offset     = vmstate_offset_value(_state, _field, PCIDevice),   \
}
#define VMSTATE_PCI_DEVICE_POINTER(_field, _state) {                 \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(PCIDevice),                                 \
    .vmsd       = &vmstate_pci_device,                               \
    .flags      = VMS_STRUCT|VMS_POINTER,                            \
    .offset     = vmstate_offset_pointer(_state, _field, PCIDevice), \
}
#define HT_CAPTYPE_REMAPPING_64 0xA2	

#define  PCI_AGP_COMMAND_RQ_MASK 0xff000000  
#define  PCI_ARI_CAP_NFN(x)	(((x) >> 8) & 0xff) 
#define  PCI_ARI_CTRL_FG(x)	(((x) >> 4) & 7) 
#define  PCI_ATS_CAP_QDEP(x)	((x) & 0x1f)	
#define  PCI_ATS_CTRL_STU(x)	((x) & 0x1f)	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 0x100	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM1 0x200
#define  PCI_COMMAND_INTX_DISABLE 0x400 
#define  PCI_COMMAND_VGA_PALETTE 0x20	
#define  PCI_ERR_CAP_FEP(x)	((x) & 31)	
#define  PCI_EXP_DEVCAP_FLR     0x10000000 
#define  PCI_EXP_DEVCTL_BCR_FLR 0x8000  
#define  PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800  
#define  PCI_EXP_DEVCTL_READRQ_1024B 0x3000 
#define  PCI_EXP_DEVCTL_READRQ_128B  0x0000 
#define  PCI_EXP_DEVCTL_READRQ_256B  0x1000 
#define  PCI_EXP_DEVCTL_READRQ_512B  0x2000 
#define  PCI_EXP_DEVCTL_RELAX_EN 0x0010 
#define  PCI_EXP_LNKCAP_SLS_2_5GB 0x00000001 
#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x00000002 
#define  PCI_EXP_LNKCTL_ASPM_L0S 0x0001	
#define  PCI_EXP_LNKCTL_ASPM_L1  0x0002	
#define  PCI_EXP_LNKCTL_CLKREQ_EN 0x0100 
#define  PCI_EXP_LNKSTA_CLS_2_5GB 0x0001 
#define  PCI_EXP_LNKSTA_CLS_5_0GB 0x0002 
#define  PCI_EXP_LNKSTA_CLS_8_0GB 0x0003 
#define  PCI_EXP_LNKSTA_NLW_SHIFT 4	
#define  PCI_EXP_SLTCTL_ATTN_IND_BLINK 0x0080 
#define  PCI_EXP_SLTCTL_ATTN_IND_OFF   0x00c0 
#define  PCI_EXP_SLTCTL_ATTN_IND_ON    0x0040 
#define  PCI_EXP_SLTCTL_PWR_IND_BLINK  0x0200 
#define  PCI_EXP_SLTCTL_PWR_IND_OFF    0x0300 
#define  PCI_EXP_SLTCTL_PWR_IND_ON     0x0100 
#define  PCI_EXP_SLTCTL_PWR_OFF        0x0400 
#define  PCI_EXP_SLTCTL_PWR_ON         0x0000 
#define  PCI_EXP_TYPE_DOWNSTREAM 0x6	
#define  PCI_EXP_TYPE_PCIE_BRIDGE 0x8	
#define  PCI_EXP_TYPE_PCI_BRIDGE 0x7	
#define  PCI_EXP_TYPE_ROOT_PORT 0x4	
#define PCI_EXT_CAP_ID(header)		(header & 0x0000ffff)
#define PCI_EXT_CAP_MCAST_ENDPOINT_SIZEOF 40
#define PCI_EXT_CAP_NEXT(header)	((header >> 20) & 0xffc)
#define PCI_EXT_CAP_SRIOV_SIZEOF 64
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
#define  PCI_SRIOV_CAP_INTR(x)	((x) >> 21) 
#define  PCI_SRIOV_VFM_BIR(x)	((x) & 7)	
#define  PCI_SRIOV_VFM_OFFSET(x) ((x) & ~7)	
#define PCI_SSVID_DEVICE_ID     6	
#define PCI_SSVID_VENDOR_ID     4	
#define  PCI_VNDR_HEADER_ID(x)	((x) & 0xffff)
#define  PCI_VNDR_HEADER_LEN(x)	(((x) >> 20) & 0xfff)
#define  PCI_VNDR_HEADER_REV(x)	(((x) >> 16) & 0xf)
#define  PCI_X_CMD_VERSION(x)	(((x) >> 12) & 3) 
#define HW_PCI_IDS_H 1
#define PCI_BASE_CLASS_NETWORK           0x02
#define PCI_BASE_CLASS_STORAGE           0x01
#define PCI_CLASS_BRIDGE_HOST            0x0600
#define PCI_CLASS_BRIDGE_ISA             0x0601
#define PCI_CLASS_BRIDGE_OTHER           0x0680
#define PCI_CLASS_BRIDGE_PCI             0x0604
#define PCI_CLASS_BRIDGE_PCI_INF_SUB     0x01
#define PCI_CLASS_COMMUNICATION_OTHER    0x0780
#define PCI_CLASS_COMMUNICATION_SERIAL   0x0700
#define PCI_CLASS_DISPLAY_OTHER          0x0380
#define PCI_CLASS_DISPLAY_VGA            0x0300
#define PCI_CLASS_INPUT_GAMEPORT         0x0904
#define PCI_CLASS_INPUT_KEYBOARD         0x0900
#define PCI_CLASS_INPUT_MOUSE            0x0902
#define PCI_CLASS_INPUT_OTHER            0x0980
#define PCI_CLASS_INPUT_PEN              0x0901
#define PCI_CLASS_INPUT_SCANNER          0x0903
#define PCI_CLASS_MEMORY_RAM             0x0500
#define PCI_CLASS_MULTIMEDIA_AUDIO       0x0401
#define PCI_CLASS_NETWORK_ETHERNET       0x0200
#define PCI_CLASS_NETWORK_OTHER          0x0280
#define PCI_CLASS_OTHERS                 0xff
#define PCI_CLASS_PROCESSOR_CO           0x0b40
#define PCI_CLASS_PROCESSOR_POWERPC      0x0b20
#define PCI_CLASS_SERIAL_SMBUS           0x0c05
#define PCI_CLASS_SERIAL_USB             0x0c03
#define PCI_CLASS_STORAGE_EXPRESS        0x0108
#define PCI_CLASS_STORAGE_IDE            0x0101
#define PCI_CLASS_STORAGE_OTHER          0x0180
#define PCI_CLASS_STORAGE_RAID           0x0104
#define PCI_CLASS_STORAGE_SATA           0x0106
#define PCI_CLASS_STORAGE_SCSI           0x0100
#define PCI_CLASS_SYSTEM_OTHER           0x0880
#define PCI_CLASS_SYSTEM_SDHCI           0x0805
#define PCI_DEVICE_ID_AMD_LANCE          0x2000
#define PCI_DEVICE_ID_AMD_SCSI           0x2020
#define PCI_DEVICE_ID_APPLE_U3_AGP       0x004b
#define PCI_DEVICE_ID_APPLE_UNI_N_AGP    0x0020
#define PCI_DEVICE_ID_CMD_646            0x0646
#define PCI_DEVICE_ID_DEC_21154          0x0026
#define PCI_DEVICE_ID_ENSONIQ_ES1370     0x5000
#define PCI_DEVICE_ID_INTEL_82371AB      0x7111
#define PCI_DEVICE_ID_INTEL_82371AB_0    0x7110
#define PCI_DEVICE_ID_INTEL_82371AB_2    0x7112
#define PCI_DEVICE_ID_INTEL_82371AB_3    0x7113
#define PCI_DEVICE_ID_INTEL_82371SB_0    0x7000
#define PCI_DEVICE_ID_INTEL_82371SB_1    0x7010
#define PCI_DEVICE_ID_INTEL_82371SB_2    0x7020
#define PCI_DEVICE_ID_INTEL_82378        0x0484
#define PCI_DEVICE_ID_INTEL_82441        0x1237
#define PCI_DEVICE_ID_INTEL_82599_SFP_VF 0x10ed
#define PCI_DEVICE_ID_INTEL_82801AA_5    0x2415
#define PCI_DEVICE_ID_INTEL_82801BA_11   0x244e
#define PCI_DEVICE_ID_INTEL_82801D       0x24CD
#define PCI_DEVICE_ID_INTEL_82801I_EHCI1 0x293a
#define PCI_DEVICE_ID_INTEL_82801I_EHCI2 0x293c
#define PCI_DEVICE_ID_INTEL_82801I_UHCI1 0x2934
#define PCI_DEVICE_ID_INTEL_82801I_UHCI2 0x2935
#define PCI_DEVICE_ID_INTEL_82801I_UHCI3 0x2936
#define PCI_DEVICE_ID_INTEL_82801I_UHCI4 0x2937
#define PCI_DEVICE_ID_INTEL_82801I_UHCI5 0x2938
#define PCI_DEVICE_ID_INTEL_82801I_UHCI6 0x2939
#define PCI_DEVICE_ID_INTEL_ESB_9        0x25ab
#define PCI_DEVICE_ID_INTEL_ICH9_0       0x2910
#define PCI_DEVICE_ID_INTEL_ICH9_1       0x2917
#define PCI_DEVICE_ID_INTEL_ICH9_2       0x2912
#define PCI_DEVICE_ID_INTEL_ICH9_3       0x2913
#define PCI_DEVICE_ID_INTEL_ICH9_4       0x2914
#define PCI_DEVICE_ID_INTEL_ICH9_5       0x2919
#define PCI_DEVICE_ID_INTEL_ICH9_6       0x2930
#define PCI_DEVICE_ID_INTEL_ICH9_7       0x2916
#define PCI_DEVICE_ID_INTEL_ICH9_8       0x2918
#define PCI_DEVICE_ID_INTEL_Q35_MCH      0x29c0
#define PCI_DEVICE_ID_LSI_53C810         0x0001
#define PCI_DEVICE_ID_LSI_53C895A        0x0012
#define PCI_DEVICE_ID_LSI_SAS0079        0x0079
#define PCI_DEVICE_ID_LSI_SAS1078        0x0060
#define PCI_DEVICE_ID_MOTOROLA_MPC106    0x0002
#define PCI_DEVICE_ID_MOTOROLA_RAVEN     0x4801
#define PCI_DEVICE_ID_MPC8533E           0x0030
#define PCI_DEVICE_ID_NEC_UPD720200      0x0194
#define PCI_DEVICE_ID_REALTEK_8139       0x8139
#define PCI_DEVICE_ID_SUN_EBUS           0x1000
#define PCI_DEVICE_ID_SUN_SABRE          0xa000
#define PCI_DEVICE_ID_SUN_SIMBA          0x5000
#define PCI_DEVICE_ID_TEWS_TPCI200       0x30C8
#define PCI_DEVICE_ID_VIA_AC97           0x3058
#define PCI_DEVICE_ID_VIA_ACPI           0x3057
#define PCI_DEVICE_ID_VIA_IDE            0x0571
#define PCI_DEVICE_ID_VIA_ISA_BRIDGE     0x0686
#define PCI_DEVICE_ID_VIA_MC97           0x3068
#define PCI_DEVICE_ID_VIA_UHCI           0x3038
#define PCI_DEVICE_ID_XEN_PLATFORM       0x0001
#define PCI_VENDOR_ID_AMD                0x1022
#define PCI_VENDOR_ID_APPLE              0x106b
#define PCI_VENDOR_ID_CHELSIO            0x1425
#define PCI_VENDOR_ID_CIRRUS             0x1013
#define PCI_VENDOR_ID_CMD                0x1095
#define PCI_VENDOR_ID_DEC                0x1011
#define PCI_VENDOR_ID_ENSONIQ            0x1274
#define PCI_VENDOR_ID_FREESCALE          0x1957
#define PCI_VENDOR_ID_IBM                0x1014
#define PCI_VENDOR_ID_INTEL              0x8086
#define PCI_VENDOR_ID_LSI_LOGIC          0x1000
#define PCI_VENDOR_ID_MARVELL            0x11ab
#define PCI_VENDOR_ID_MOTOROLA           0x1057
#define PCI_VENDOR_ID_NEC                0x1033
#define PCI_VENDOR_ID_REALTEK            0x10ec
#define PCI_VENDOR_ID_SUN                0x108e
#define PCI_VENDOR_ID_TEWS               0x1498
#define PCI_VENDOR_ID_TI                 0x104c
#define PCI_VENDOR_ID_VIA                0x1106
#define PCI_VENDOR_ID_XEN                0x5853
#define PCI_VENDOR_ID_XILINX             0x10ee
#define COMPAT_PROP_PCP "power_controller_present"

#define VMSTATE_PCIE_DEVICE(_field, _state) {                        \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(PCIDevice),                                 \
    .vmsd       = &vmstate_pcie_device,                              \
    .flags      = VMS_STRUCT,                                        \
    .offset     = vmstate_offset_value(_state, _field, PCIDevice),   \
}
#define PCIE_AER_ERR_HEADER_VALID       0x4     
#define PCIE_AER_ERR_IS_CORRECTABLE     0x1     
#define PCIE_AER_ERR_MAYBE_ADVISORY     0x2     
#define PCIE_AER_ERR_TLP_PREFIX_PRESENT 0x8     
#define PCIE_AER_LOG_MAX_DEFAULT        8
#define PCIE_AER_LOG_MAX_LIMIT          128
#define PCIE_AER_LOG_MAX_UNSET          0xffff

#define PCI_ARI_SIZEOF                  8
#define PCI_ARI_VER                     1
#define PCI_ERR_CAP_FEP_MASK            0x0000001f
#define PCI_ERR_CAP_MHRC                0x00000200
#define PCI_ERR_CAP_MHRE                0x00000400
#define PCI_ERR_CAP_TLP                 0x00000800
#define PCI_ERR_COR_ADV_NONFATAL        0x00002000      
#define PCI_ERR_COR_HL_OVERFLOW         0x00008000      
#define PCI_ERR_COR_INTERNAL            0x00004000      
#define PCI_ERR_COR_MASK_DEFAULT        (PCI_ERR_COR_ADV_NONFATAL |     \
                                         PCI_ERR_COR_INTERNAL |         \
                                         PCI_ERR_COR_HL_OVERFLOW)
#define PCI_ERR_COR_SUPPORTED           (PCI_ERR_COR_RCVR |             \
                                         PCI_ERR_COR_BAD_TLP |          \
                                         PCI_ERR_COR_BAD_DLLP |         \
                                         PCI_ERR_COR_REP_ROLL |         \
                                         PCI_ERR_COR_REP_TIMER |        \
                                         PCI_ERR_COR_ADV_NONFATAL |     \
                                         PCI_ERR_COR_INTERNAL |         \
                                         PCI_ERR_COR_HL_OVERFLOW)
#define PCI_ERR_HEADER_LOG_SIZE         16
#define PCI_ERR_ROOT_CMD_EN_MASK        (PCI_ERR_ROOT_CMD_COR_EN |      \
                                         PCI_ERR_ROOT_CMD_NONFATAL_EN | \
                                         PCI_ERR_ROOT_CMD_FATAL_EN)
#define PCI_ERR_ROOT_IRQ                0xf8000000
#define PCI_ERR_ROOT_IRQ_MAX            32
#define PCI_ERR_ROOT_IRQ_SHIFT          ctz32(PCI_ERR_ROOT_IRQ)
#define PCI_ERR_ROOT_STATUS_REPORT_MASK (PCI_ERR_ROOT_COR_RCV |         \
                                         PCI_ERR_ROOT_MULTI_COR_RCV |   \
                                         PCI_ERR_ROOT_UNCOR_RCV |       \
                                         PCI_ERR_ROOT_MULTI_UNCOR_RCV | \
                                         PCI_ERR_ROOT_FIRST_FATAL |     \
                                         PCI_ERR_ROOT_NONFATAL_RCV |    \
                                         PCI_ERR_ROOT_FATAL_RCV)
#define PCI_ERR_SIZEOF                  0x48
#define PCI_ERR_TLP_PREFIX_LOG          0x38
#define PCI_ERR_TLP_PREFIX_LOG_SIZE     16
#define PCI_ERR_UNC_ACSV                0x00200000      
#define PCI_ERR_UNC_ATOP_EBLOCKED       0x01000000      
#define PCI_ERR_UNC_INTN                0x00400000      
#define PCI_ERR_UNC_MCBTLP              0x00800000      
#define PCI_ERR_UNC_SDN                 0x00000020      
#define PCI_ERR_UNC_SEVERITY_DEFAULT    (PCI_ERR_UNC_DLP |              \
                                         PCI_ERR_UNC_SDN |              \
                                         PCI_ERR_UNC_FCP |              \
                                         PCI_ERR_UNC_RX_OVER |          \
                                         PCI_ERR_UNC_MALF_TLP |         \
                                         PCI_ERR_UNC_INTN)
#define PCI_ERR_UNC_SUPPORTED           (PCI_ERR_UNC_DLP |              \
                                         PCI_ERR_UNC_SDN |              \
                                         PCI_ERR_UNC_POISON_TLP |       \
                                         PCI_ERR_UNC_FCP |              \
                                         PCI_ERR_UNC_COMP_TIME |        \
                                         PCI_ERR_UNC_COMP_ABORT |       \
                                         PCI_ERR_UNC_UNX_COMP |         \
                                         PCI_ERR_UNC_RX_OVER |          \
                                         PCI_ERR_UNC_MALF_TLP |         \
                                         PCI_ERR_UNC_ECRC |             \
                                         PCI_ERR_UNC_UNSUP |            \
                                         PCI_ERR_UNC_ACSV |             \
                                         PCI_ERR_UNC_INTN |             \
                                         PCI_ERR_UNC_MCBTLP |           \
                                         PCI_ERR_UNC_ATOP_EBLOCKED |    \
                                         PCI_ERR_UNC_TLP_PRF_BLOCKED)
#define PCI_ERR_UNC_TLP_PRF_BLOCKED     0x02000000      
#define PCI_ERR_VER                     2
#define PCI_EXP_DEVCAP2_EETLPP          0x200000
#define PCI_EXP_DEVCAP2_EFF             0x100000
#define PCI_EXP_DEVCTL2_EETLPPB         0x8000
#define PCI_EXP_FLAGS_IRQ_SHIFT         ctz32(PCI_EXP_FLAGS_IRQ)
#define PCI_EXP_FLAGS_TYPE_SHIFT        ctz32(PCI_EXP_FLAGS_TYPE)
#define PCI_EXP_FLAGS_VER2              2 
#define PCI_EXP_LNKCAP_ASPMS_0S         (1 << PCI_EXP_LNKCAP_ASPMS_SHIFT)
#define PCI_EXP_LNKCAP_ASPMS_SHIFT      ctz32(PCI_EXP_LNKCAP_ASPMS)
#define PCI_EXP_LNKCAP_PN_SHIFT         ctz32(PCI_EXP_LNKCAP_PN)
#define PCI_EXP_LNK_LS_25               1
#define PCI_EXP_LNK_MLW_1               (1 << PCI_EXP_LNK_MLW_SHIFT)
#define PCI_EXP_LNK_MLW_SHIFT           ctz32(PCI_EXP_LNKCAP_MLW)
#define PCI_EXP_SLTCAP_PSN_SHIFT        ctz32(PCI_EXP_SLTCAP_PSN)
#define PCI_EXP_SLTCTL_AIC_OFF                          \
    (PCI_EXP_SLTCTL_IND_OFF << PCI_EXP_SLTCTL_AIC_SHIFT)
#define PCI_EXP_SLTCTL_AIC_SHIFT        ctz32(PCI_EXP_SLTCTL_AIC)
#define PCI_EXP_SLTCTL_IND_BLINK        0x2
#define PCI_EXP_SLTCTL_IND_OFF          0x3
#define PCI_EXP_SLTCTL_IND_ON           0x1
#define PCI_EXP_SLTCTL_IND_RESERVED     0x0
#define PCI_EXP_SLTCTL_PIC_OFF                          \
    (PCI_EXP_SLTCTL_IND_OFF << PCI_EXP_SLTCTL_PIC_SHIFT)
#define PCI_EXP_SLTCTL_PIC_ON                          \
    (PCI_EXP_SLTCTL_IND_ON << PCI_EXP_SLTCTL_PIC_SHIFT)
#define PCI_EXP_SLTCTL_PIC_SHIFT        ctz32(PCI_EXP_SLTCTL_PIC)
#define PCI_EXP_SLTCTL_SUPPORTED        \
            (PCI_EXP_SLTCTL_ABPE |      \
             PCI_EXP_SLTCTL_PDCE |      \
             PCI_EXP_SLTCTL_CCIE |      \
             PCI_EXP_SLTCTL_HPIE |      \
             PCI_EXP_SLTCTL_AIC |       \
             PCI_EXP_SLTCTL_PCC |       \
             PCI_EXP_SLTCTL_EIC)
#define PCI_EXP_VER2_SIZEOF             0x3c 
#define PCI_EXT_CAP(id, ver, next)                                      \
    ((id) |                                                             \
     ((ver) << PCI_EXT_CAP_VER_SHIFT) |                                 \
     ((next) << PCI_EXT_CAP_NEXT_SHIFT))
#define PCI_EXT_CAP_ALIGN               4
#define PCI_EXT_CAP_ALIGNUP(x)                                  \
    (((x) + PCI_EXT_CAP_ALIGN - 1) & ~(PCI_EXT_CAP_ALIGN - 1))
#define PCI_EXT_CAP_NEXT_MASK           (0xffc << PCI_EXT_CAP_NEXT_SHIFT)
#define PCI_EXT_CAP_NEXT_SHIFT          20
#define PCI_EXT_CAP_VER_SHIFT           16
#define PCI_SEC_STATUS_RCV_SYSTEM_ERROR         0x4000

#define APPLESMC_MAX_DATA_LENGTH       32
#define APPLESMC_PROP_IO_BASE "iobase"

#define ISA_BUS(obj) OBJECT_CHECK(ISABus, (obj), TYPE_ISA_BUS)
#define ISA_DEVICE(obj) \
     OBJECT_CHECK(ISADevice, (obj), TYPE_ISA_DEVICE)
#define ISA_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(ISADeviceClass, (klass), TYPE_ISA_DEVICE)
#define ISA_DEVICE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(ISADeviceClass, (obj), TYPE_ISA_DEVICE)
#define ISA_NUM_IRQS 16
#define TYPE_APPLE_SMC "isa-applesmc"
#define TYPE_ISA_BUS "ISA"
#define TYPE_ISA_DEVICE "isa-device"

#define DEFINE_PROP(_name, _state, _field, _prop, _type) { \
        .name      = (_name),                                    \
        .info      = &(_prop),                                   \
        .offset    = offsetof(_state, _field)                    \
            + type_check(_type, typeof_field(_state, _field)),   \
        }
#define DEFINE_PROP_ARRAY(_name, _state, _field,                        \
                          _arrayfield, _arrayprop, _arraytype) {        \
        .name = (PROP_ARRAY_LEN_PREFIX _name),                          \
        .info = &(qdev_prop_arraylen),                                  \
        .offset = offsetof(_state, _field)                              \
            + type_check(uint32_t, typeof_field(_state, _field)),       \
        .qtype = QTYPE_QINT,                                            \
        .arrayinfo = &(_arrayprop),                                     \
        .arrayfieldsize = sizeof(_arraytype),                           \
        .arrayoffset = offsetof(_state, _arrayfield),                   \
        }
#define DEFINE_PROP_BIOS_CHS_TRANS(_n, _s, _f, _d) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_bios_chs_trans, int)
#define DEFINE_PROP_BIT(_name, _state, _field, _bit, _defval) {  \
        .name      = (_name),                                    \
        .info      = &(qdev_prop_bit),                           \
        .bitnr    = (_bit),                                      \
        .offset    = offsetof(_state, _field)                    \
            + type_check(uint32_t,typeof_field(_state, _field)), \
        .qtype     = QTYPE_QBOOL,                                \
        .defval    = (bool)_defval,                              \
        }
#define DEFINE_PROP_BIT64(_name, _state, _field, _bit, _defval) {       \
        .name      = (_name),                                           \
        .info      = &(qdev_prop_bit64),                                \
        .bitnr    = (_bit),                                             \
        .offset    = offsetof(_state, _field)                           \
            + type_check(uint64_t, typeof_field(_state, _field)),       \
        .qtype     = QTYPE_QBOOL,                                       \
        .defval    = (bool)_defval,                                     \
        }
#define DEFINE_PROP_BLOCKSIZE(_n, _s, _f) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, 0, qdev_prop_blocksize, uint16_t)
#define DEFINE_PROP_BOOL(_name, _state, _field, _defval) {       \
        .name      = (_name),                                    \
        .info      = &(qdev_prop_bool),                          \
        .offset    = offsetof(_state, _field)                    \
            + type_check(bool, typeof_field(_state, _field)),    \
        .qtype     = QTYPE_QBOOL,                                \
        .defval    = (bool)_defval,                              \
        }
#define DEFINE_PROP_CHR(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_chr, CharDriverState*)
#define DEFINE_PROP_DEFAULT(_name, _state, _field, _defval, _prop, _type) { \
        .name      = (_name),                                           \
        .info      = &(_prop),                                          \
        .offset    = offsetof(_state, _field)                           \
            + type_check(_type,typeof_field(_state, _field)),           \
        .qtype     = QTYPE_QINT,                                        \
        .defval    = (_type)_defval,                                    \
        }
#define DEFINE_PROP_DRIVE(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_drive, BlockBackend *)
#define DEFINE_PROP_END_OF_LIST()               \
    {}
#define DEFINE_PROP_INT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_int32, int32_t)
#define DEFINE_PROP_LOSTTICKPOLICY(_n, _s, _f, _d) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_losttickpolicy, \
                        LostTickPolicy)
#define DEFINE_PROP_MACADDR(_n, _s, _f)         \
    DEFINE_PROP(_n, _s, _f, qdev_prop_macaddr, MACAddr)
#define DEFINE_PROP_NETDEV(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_netdev, NICPeers)
#define DEFINE_PROP_PCI_DEVFN(_n, _s, _f, _d)                   \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_pci_devfn, int32_t)
#define DEFINE_PROP_PCI_HOST_DEVADDR(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_pci_host_devaddr, PCIHostDeviceAddress)
#define DEFINE_PROP_PTR(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_ptr, void*)
#define DEFINE_PROP_SIZE(_n, _s, _f, _d)                       \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_size, uint64_t)
#define DEFINE_PROP_STRING(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_string, char*)
#define DEFINE_PROP_UINT16(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint16, uint16_t)
#define DEFINE_PROP_UINT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint32, uint32_t)
#define DEFINE_PROP_UINT64(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint64, uint64_t)
#define DEFINE_PROP_UINT8(_n, _s, _f, _d)                       \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_uint8, uint8_t)
#define DEFINE_PROP_VLAN(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_vlan, NICPeers)
#define PROP_ARRAY_LEN_PREFIX "len-"

