
#include<stdbool.h>

#include<stdint.h>



#define ATECC608A_SE_KEY_LIST                                                                                          \
    {                                                                                                                  \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = APP_KEY,                                                                                  \
            .KeySlotNumber = TNGLORA_APP_KEY_SLOT,                                                                     \
            .KeyBlockIndex = TNGLORA_APP_KEY_BLOCK_INDEX,                                                              \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = NWK_KEY,                                                                                  \
            .KeySlotNumber = TNGLORA_APP_KEY_SLOT,                                                                     \
            .KeyBlockIndex = TNGLORA_APP_KEY_BLOCK_INDEX,                                                              \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = J_S_INT_KEY,                                                                              \
            .KeySlotNumber = TNGLORA_J_S_INT_KEY_SLOT,                                                                 \
            .KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX,                                                       \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = J_S_ENC_KEY,                                                                              \
            .KeySlotNumber = TNGLORA_J_S_ENC_KEY_SLOT,                                                                 \
            .KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX,                                                       \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = F_NWK_S_INT_KEY,                                                                          \
            .KeySlotNumber = TNGLORA_F_NWK_S_INT_KEY_SLOT,                                                             \
            .KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX,                                                       \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = S_NWK_S_INT_KEY,                                                                          \
            .KeySlotNumber = TNGLORA_S_NWK_S_INT_KEY_SLOT,                                                             \
            .KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX,                                                       \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = NWK_S_ENC_KEY,                                                                            \
            .KeySlotNumber = TNGLORA_NWK_S_ENC_KEY_SLOT,                                                               \
            .KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX,                                                       \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = APP_S_KEY,                                                                                \
            .KeySlotNumber = TNGLORA_APP_S_KEY_SLOT,                                                                   \
            .KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX,                                                       \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = MC_ROOT_KEY,                                                                              \
            .KeySlotNumber = 0,                                                                                        \
            .KeyBlockIndex = 0,                                                                                        \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = MC_KE_KEY,                                                                                \
            .KeySlotNumber = 0,                                                                                        \
            .KeyBlockIndex = 0,                                                                                        \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = MC_KEY_0,                                                                                 \
            .KeySlotNumber = 0,                                                                                        \
            .KeyBlockIndex = 0,                                                                                        \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = MC_APP_S_KEY_0,                                                                           \
            .KeySlotNumber = TNGLORA_MC_APP_S_KEY_0_SLOT,                                                              \
            .KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX,                                                       \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = MC_NWK_S_KEY_0,                                                                           \
            .KeySlotNumber = TNGLORA_MC_NWK_S_KEY_0_SLOT,                                                              \
            .KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX,                                                       \
        },                                                                                                             \
        {                                                                                                              \
                                                                                                                    \
            .KeyID         = SLOT_RAND_ZERO_KEY,                                                                       \
            .KeySlotNumber = 0,                                                                                        \
            .KeyBlockIndex = 0,                                                                                        \
        },                                                                                                             \
    },
#define LORAWAN_DEVICE_ADDRESS ( uint32_t ) 0x00000000
#define SECURE_ELEMENT_PIN     \
    {                          \
        0x00, 0x00, 0x00, 0x00 \
    }
#define STATIC_DEVICE_ADDRESS 0
#define TNGLORA_APP_KEY_BLOCK_INDEX 1U
#define TNGLORA_APP_KEY_SLOT 0U
#define TNGLORA_APP_S_KEY_SLOT 2U
#define TNGLORA_DEV_EUI_SLOT 10U
#define TNGLORA_F_NWK_S_INT_KEY_SLOT 5U
#define TNGLORA_JOIN_EUI_SLOT 9U
#define TNGLORA_J_S_ENC_KEY_SLOT 7U
#define TNGLORA_J_S_INT_KEY_SLOT 6U
#define TNGLORA_MC_APP_S_KEY_0_SLOT 11U
#define TNGLORA_MC_NWK_S_KEY_0_SLOT 12U
#define TNGLORA_NWK_KEY_SLOT 0U
#define TNGLORA_NWK_S_ENC_KEY_SLOT 3U
#define TNGLORA_REMAINING_KEYS_BLOCK_INDEX 0U
#define TNGLORA_S_NWK_S_INT_KEY_SLOT 4U

