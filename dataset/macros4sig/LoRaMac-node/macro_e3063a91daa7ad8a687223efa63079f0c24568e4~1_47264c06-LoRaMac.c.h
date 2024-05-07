

#include<stdbool.h>

#include<stdint.h>





#include<stddef.h>



#include<stdlib.h>
#define DOWN_LINK                                   1
#define LORAMAC_CRYPTO_MULTICAST_KEYS   127
#define   LORAMAC_MAX_MC_CTX       4
#define LORA_MAC_MLME_CONFIRM_QUEUE_LEN             5
#define MAX_ACK_RETRIES                             8
#define UP_LINK                                     0

#define DR_0                                        0
#define DR_1                                        1
#define DR_10                                       10
#define DR_11                                       11
#define DR_12                                       12
#define DR_13                                       13
#define DR_14                                       14
#define DR_15                                       15
#define DR_2                                        2
#define DR_3                                        3
#define DR_4                                        4
#define DR_5                                        5
#define DR_6                                        6
#define DR_7                                        7
#define DR_8                                        8
#define DR_9                                        9
#define LC( channelIndex )                          ( uint16_t )( 1 << ( channelIndex - 1 ) )
#define REGION_VERSION                              0x00010003
#define TX_POWER_0                                  0
#define TX_POWER_1                                  1
#define TX_POWER_10                                 10
#define TX_POWER_11                                 11
#define TX_POWER_12                                 12
#define TX_POWER_13                                 13
#define TX_POWER_14                                 14
#define TX_POWER_15                                 15
#define TX_POWER_2                                  2
#define TX_POWER_3                                  3
#define TX_POWER_4                                  4
#define TX_POWER_5                                  5
#define TX_POWER_6                                  6
#define TX_POWER_7                                  7
#define TX_POWER_8                                  8
#define TX_POWER_9                                  9

#define LORAMAC_CRYPTO_UNICAST_KEYS     0


#define LORAMAC_COMMADS_MAX_NUM_OF_PARAMS   2



#define JOIN_ACCEPT_MIC_COMPUTATION_OFFSET                                                   \
    ( LORAMAC_MHDR_FIELD_SIZE + LORAMAC_JOIN_TYPE_FIELD_SIZE + LORAMAC_JOIN_EUI_FIELD_SIZE + \
      LORAMAC_DEV_NONCE_FIELD_SIZE )
#define LORAMAC_CF_LIST_FIELD_SIZE          16
#define LORAMAC_DEV_ADDR_FIELD_SIZE         4
#define LORAMAC_DEV_EUI_FIELD_SIZE          8
#define LORAMAC_DEV_NONCE_FIELD_SIZE        2
#define LORAMAC_DL_SETTINGS_FIELD_SIZE      1
#define LORAMAC_FHDR_DEV_ADDR_FIELD_SIZE    LORAMAC_DEV_ADDR_FIELD_SIZE
#define LORAMAC_FHDR_F_CNT_FIELD_SIZE       2
#define LORAMAC_FHDR_F_CTRL_FIELD_SIZE      1
#define LORAMAC_FHDR_F_OPTS_MAX_FIELD_SIZE  15
#define LORAMAC_FRAME_PAYLOAD_MAX_SIZE      ( LORAMAC_MHDR_FIELD_SIZE + ( LORAMAC_FHDR_DEV_ADDR_FIELD_SIZE + \
                                              LORAMAC_FHDR_F_CTRL_FIELD_SIZE + LORAMAC_FHDR_F_CNT_FIELD_SIZE ) + \
                                              LORAMAC_F_PORT_FIELD_SIZE + LORAMAC_MAC_PAYLOAD_FIELD_MAX_SIZE + \
                                              LORAMAC_MIC_FIELD_SIZE )
#define LORAMAC_FRAME_PAYLOAD_MIN_SIZE      ( LORAMAC_MHDR_FIELD_SIZE + ( LORAMAC_FHDR_DEV_ADDR_FIELD_SIZE + \
                                              LORAMAC_FHDR_F_CTRL_FIELD_SIZE + LORAMAC_FHDR_F_CNT_FIELD_SIZE ) + \
                                              LORAMAC_MIC_FIELD_SIZE )
#define LORAMAC_FRAME_PAYLOAD_OVERHEAD_SIZE ( LORAMAC_MHDR_FIELD_SIZE + ( LORAMAC_FHDR_DEV_ADDR_FIELD_SIZE + \
                                              LORAMAC_FHDR_F_CTRL_FIELD_SIZE + LORAMAC_FHDR_F_CNT_FIELD_SIZE ) + \
                                              LORAMAC_F_PORT_FIELD_SIZE + LORAMAC_MIC_FIELD_SIZE )
#define LORAMAC_F_PORT_FIELD_SIZE           1
#define LORAMAC_JOIN_ACCEPT_FRAME_MAX_SIZE  ( LORAMAC_MHDR_FIELD_SIZE + LORAMAC_JOIN_NONCE_FIELD_SIZE + \
                                              LORAMAC_NET_ID_FIELD_SIZE + LORAMAC_DEV_ADDR_FIELD_SIZE + \
                                              LORAMAC_DL_SETTINGS_FIELD_SIZE + LORAMAC_RX_DELAY_FIELD_SIZE + \
                                              LORAMAC_CF_LIST_FIELD_SIZE + LORAMAC_MIC_FIELD_SIZE )
#define LORAMAC_JOIN_ACCEPT_FRAME_MIN_SIZE  ( LORAMAC_MHDR_FIELD_SIZE + LORAMAC_JOIN_NONCE_FIELD_SIZE + \
                                              LORAMAC_NET_ID_FIELD_SIZE + LORAMAC_DEV_ADDR_FIELD_SIZE + \
                                              LORAMAC_DL_SETTINGS_FIELD_SIZE + LORAMAC_RX_DELAY_FIELD_SIZE + \
                                              LORAMAC_MIC_FIELD_SIZE )
#define LORAMAC_JOIN_EUI_FIELD_SIZE         8
#define LORAMAC_JOIN_NONCE_FIELD_SIZE       3
#define LORAMAC_JOIN_REQ_MSG_SIZE           ( LORAMAC_MHDR_FIELD_SIZE + LORAMAC_JOIN_EUI_FIELD_SIZE + \
                                              LORAMAC_DEV_EUI_FIELD_SIZE + LORAMAC_DEV_NONCE_FIELD_SIZE + \
                                              LORAMAC_MIC_FIELD_SIZE )
#define LORAMAC_JOIN_TYPE_FIELD_SIZE        1
#define LORAMAC_MAC_PAYLOAD_FIELD_MAX_SIZE  242
#define LORAMAC_MHDR_FIELD_SIZE             1
#define LORAMAC_MIC_FIELD_SIZE              4
#define LORAMAC_NET_ID_FIELD_SIZE           3
#define LORAMAC_RE_JOIN_0_2_MSG_SIZE        ( LORAMAC_MHDR_FIELD_SIZE + LORAMAC_JOIN_TYPE_FIELD_SIZE + \
                                              LORAMAC_NET_ID_FIELD_SIZE + LORAMAC_DEV_EUI_FIELD_SIZE + \
                                              LORAMAC_RJCOUNT_0_FIELD_SIZE + \
                                              LORAMAC_MIC_FIELD_SIZE )
#define LORAMAC_RE_JOIN_1_MSG_SIZE          ( LORAMAC_MHDR_FIELD_SIZE + LORAMAC_JOIN_TYPE_FIELD_SIZE + \
                                              LORAMAC_JOIN_EUI_FIELD_SIZE + LORAMAC_DEV_EUI_FIELD_SIZE + \
                                              LORAMAC_RJCOUNT_1_FIELD_SIZE + \
                                              LORAMAC_MIC_FIELD_SIZE )
#define LORAMAC_RJCOUNT_0_FIELD_SIZE        2
#define LORAMAC_RJCOUNT_1_FIELD_SIZE        2
#define LORAMAC_RX_DELAY_FIELD_SIZE         1



#define SE_EUI_SIZE             8
#define SE_KEY_SIZE             16
#define SE_PIN_SIZE             4

#define FCNT_DOWN_INITAL_VALUE          0xFFFFFFFF
#define USE_JOIN_NONCE_COUNTER_CHECK                0
#define USE_LRWAN_1_1_X_CRYPTO                      0
#define USE_RANDOM_DEV_NONCE                        1


