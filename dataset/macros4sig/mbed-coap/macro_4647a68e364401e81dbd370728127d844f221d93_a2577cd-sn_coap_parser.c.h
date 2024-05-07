



#include<stdio.h>
#include<string.h>




#define COAP_OPTION_BLOCK_NONE                      (-1) 
#define COAP_OPTION_MAX_AGE_DEFAULT                 60 
#define COAP_OPTION_URI_PORT_NONE                   (-1) 
#define RESPONSE_RANDOM_FACTOR                      1.5   

#define DEFAULT_RESPONSE_TIMEOUT                        10  
#define ENABLE_RESENDINGS                               0   
#define SN_COAP_BLOCKWISE_ENABLED                       0  
#define SN_COAP_BLOCKWISE_INTERNAL_BLOCK_2_HANDLING_ENABLED  1
#define SN_COAP_BLOCKWISE_MAX_TIME_DATA_STORED      300 
#define SN_COAP_DUPLICATION_MAX_MSGS_COUNT              0
#define SN_COAP_DUPLICATION_MAX_TIME_MSGS_STORED    300 
#define SN_COAP_MAX_ALLOWED_DUPLICATION_MESSAGE_COUNT   6
#define SN_COAP_MAX_ALLOWED_RESENDING_BUFF_SIZE_BYTES   512 
#define SN_COAP_MAX_ALLOWED_RESENDING_BUFF_SIZE_MSGS    6   
#define SN_COAP_MAX_ALLOWED_RESENDING_COUNT             6   
#define SN_COAP_MAX_ALLOWED_RESPONSE_TIMEOUT            40  
#define SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE              0  
#define SN_COAP_MAX_INCOMING_BLOCK_MESSAGE_SIZE MBED_CONF_MBED_CLIENT_SN_COAP_MAX_INCOMING_MESSAGE_SIZE
#define SN_COAP_MAX_INCOMING_MESSAGE_SIZE               UINT16_MAX
#define SN_COAP_MAX_NONBLOCKWISE_PAYLOAD_SIZE           0
#define SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT              0   
#define SN_COAP_RESENDING_MAX_COUNT                     3
#define SN_COAP_RESENDING_QUEUE_SIZE_BYTES              0   
#define SN_COAP_RESENDING_QUEUE_SIZE_MSGS               2   

#define COAP_HEADER_LENGTH                          4   
#define COAP_HEADER_MSG_ID_MSB_SHIFT                8
#define COAP_HEADER_MSG_TYPE_MASK                   0x30
#define COAP_HEADER_TOKEN_LENGTH_MASK               0x0F
#define COAP_HEADER_VERSION_MASK                    0xC0
#define COAP_OPTIONS_OPTION_NUMBER_SHIFT            4
#define COAP_VERSION                                COAP_VERSION_1 



