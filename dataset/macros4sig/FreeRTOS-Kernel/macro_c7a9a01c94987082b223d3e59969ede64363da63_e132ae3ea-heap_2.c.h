#include<stddef.h>
































#include<stdlib.h>









#include<stdint.h>




#define taskDISABLE_INTERRUPTS()           portDISABLE_INTERRUPTS()
#define taskENABLE_INTERRUPTS()            portENABLE_INTERRUPTS()
#define taskENTER_CRITICAL()               portENTER_CRITICAL()
#define taskENTER_CRITICAL_FROM_ISR()      portSET_INTERRUPT_MASK_FROM_ISR()
#define taskEXIT_CRITICAL()                portEXIT_CRITICAL()
#define taskEXIT_CRITICAL_FROM_ISR( x )    portCLEAR_INTERRUPT_MASK_FROM_ISR( x )
#define taskSCHEDULER_NOT_STARTED    ( ( BaseType_t ) 1 )
#define taskSCHEDULER_RUNNING        ( ( BaseType_t ) 2 )
#define taskSCHEDULER_SUSPENDED      ( ( BaseType_t ) 0 )
#define taskYIELD()                        portYIELD()
#define tskDEFAULT_INDEX_TO_NOTIFY     ( 0 )
#define tskIDLE_PRIORITY    ( ( UBaseType_t ) 0U )
#define tskKERNEL_VERSION_BUILD        2
#define tskKERNEL_VERSION_MAJOR        10
#define tskKERNEL_VERSION_MINOR        4
#define tskKERNEL_VERSION_NUMBER       "V10.4.2"
#define tskMPU_REGION_DEVICE_MEMORY    ( 1UL << 4UL )
#define tskMPU_REGION_EXECUTE_NEVER    ( 1UL << 2UL )
#define tskMPU_REGION_NORMAL_MEMORY    ( 1UL << 3UL )
#define tskMPU_REGION_READ_ONLY        ( 1UL << 0UL )
#define tskMPU_REGION_READ_WRITE       ( 1UL << 1UL )
#define ulTaskNotifyTake( xClearCountOnExit, xTicksToWait ) \
    ulTaskGenericNotifyTake( ( tskDEFAULT_INDEX_TO_NOTIFY ), ( xClearCountOnExit ), ( xTicksToWait ) )
#define ulTaskNotifyTakeIndexed( uxIndexToWaitOn, xClearCountOnExit, xTicksToWait ) \
    ulTaskGenericNotifyTake( ( uxIndexToWaitOn ), ( xClearCountOnExit ), ( xTicksToWait ) )
#define ulTaskNotifyValueClear( xTask, ulBitsToClear ) \
    ulTaskGenericNotifyValueClear( ( xTask ), ( tskDEFAULT_INDEX_TO_NOTIFY ), ( ulBitsToClear ) )
#define ulTaskNotifyValueClearIndexed( xTask, uxIndexToClear, ulBitsToClear ) \
    ulTaskGenericNotifyValueClear( ( xTask ), ( uxIndexToClear ), ( ulBitsToClear ) )
#define vTaskDelayUntil( pxPreviousWakeTime, xTimeIncrement )       \
{                                                                   \
    ( void ) xTaskDelayUntil( pxPreviousWakeTime, xTimeIncrement ); \
}
#define vTaskNotifyGiveFromISR( xTaskToNotify, pxHigherPriorityTaskWoken ) \
    vTaskGenericNotifyGiveFromISR( ( xTaskToNotify ), ( tskDEFAULT_INDEX_TO_NOTIFY ), ( pxHigherPriorityTaskWoken ) );
#define vTaskNotifyGiveIndexedFromISR( xTaskToNotify, uxIndexToNotify, pxHigherPriorityTaskWoken ) \
    vTaskGenericNotifyGiveFromISR( ( xTaskToNotify ), ( uxIndexToNotify ), ( pxHigherPriorityTaskWoken ) );
#define xTaskNotify( xTaskToNotify, ulValue, eAction ) \
    xTaskGenericNotify( ( xTaskToNotify ), ( tskDEFAULT_INDEX_TO_NOTIFY ), ( ulValue ), ( eAction ), NULL )
#define xTaskNotifyAndQuery( xTaskToNotify, ulValue, eAction, pulPreviousNotifyValue ) \
    xTaskGenericNotify( ( xTaskToNotify ), ( tskDEFAULT_INDEX_TO_NOTIFY ), ( ulValue ), ( eAction ), ( pulPreviousNotifyValue ) )
#define xTaskNotifyAndQueryFromISR( xTaskToNotify, ulValue, eAction, pulPreviousNotificationValue, pxHigherPriorityTaskWoken ) \
    xTaskGenericNotifyFromISR( ( xTaskToNotify ), ( tskDEFAULT_INDEX_TO_NOTIFY ), ( ulValue ), ( eAction ), ( pulPreviousNotificationValue ), ( pxHigherPriorityTaskWoken ) )
#define xTaskNotifyAndQueryIndexed( xTaskToNotify, uxIndexToNotify, ulValue, eAction, pulPreviousNotifyValue ) \
    xTaskGenericNotify( ( xTaskToNotify ), ( uxIndexToNotify ), ( ulValue ), ( eAction ), ( pulPreviousNotifyValue ) )
#define xTaskNotifyAndQueryIndexedFromISR( xTaskToNotify, uxIndexToNotify, ulValue, eAction, pulPreviousNotificationValue, pxHigherPriorityTaskWoken ) \
    xTaskGenericNotifyFromISR( ( xTaskToNotify ), ( uxIndexToNotify ), ( ulValue ), ( eAction ), ( pulPreviousNotificationValue ), ( pxHigherPriorityTaskWoken ) )
#define xTaskNotifyFromISR( xTaskToNotify, ulValue, eAction, pxHigherPriorityTaskWoken ) \
    xTaskGenericNotifyFromISR( ( xTaskToNotify ), ( tskDEFAULT_INDEX_TO_NOTIFY ), ( ulValue ), ( eAction ), NULL, ( pxHigherPriorityTaskWoken ) )
#define xTaskNotifyGive( xTaskToNotify ) \
    xTaskGenericNotify( ( xTaskToNotify ), ( tskDEFAULT_INDEX_TO_NOTIFY ), ( 0 ), eIncrement, NULL )
#define xTaskNotifyGiveIndexed( xTaskToNotify, uxIndexToNotify ) \
    xTaskGenericNotify( ( xTaskToNotify ), ( uxIndexToNotify ), ( 0 ), eIncrement, NULL )
#define xTaskNotifyIndexed( xTaskToNotify, uxIndexToNotify, ulValue, eAction ) \
    xTaskGenericNotify( ( xTaskToNotify ), ( uxIndexToNotify ), ( ulValue ), ( eAction ), NULL )
#define xTaskNotifyIndexedFromISR( xTaskToNotify, uxIndexToNotify, ulValue, eAction, pxHigherPriorityTaskWoken ) \
    xTaskGenericNotifyFromISR( ( xTaskToNotify ), ( uxIndexToNotify ), ( ulValue ), ( eAction ), NULL, ( pxHigherPriorityTaskWoken ) )
#define xTaskNotifyStateClear( xTask ) \
    xTaskGenericNotifyStateClear( ( xTask ), ( tskDEFAULT_INDEX_TO_NOTIFY ) )
#define xTaskNotifyStateClearIndexed( xTask, uxIndexToClear ) \
    xTaskGenericNotifyStateClear( ( xTask ), ( uxIndexToClear ) )
#define xTaskNotifyWait( ulBitsToClearOnEntry, ulBitsToClearOnExit, pulNotificationValue, xTicksToWait ) \
    xTaskGenericNotifyWait( tskDEFAULT_INDEX_TO_NOTIFY, ( ulBitsToClearOnEntry ), ( ulBitsToClearOnExit ), ( pulNotificationValue ), ( xTicksToWait ) )
#define xTaskNotifyWaitIndexed( uxIndexToWaitOn, ulBitsToClearOnEntry, ulBitsToClearOnExit, pulNotificationValue, xTicksToWait ) \
    xTaskGenericNotifyWait( ( uxIndexToWaitOn ), ( ulBitsToClearOnEntry ), ( ulBitsToClearOnExit ), ( pulNotificationValue ), ( xTicksToWait ) )


#define listCURRENT_LIST_LENGTH( pxList )                 ( ( pxList )->uxNumberOfItems )


#define listGET_END_MARKER( pxList )                      ( ( ListItem_t const * ) ( &( ( pxList )->xListEnd ) ) )
#define listGET_HEAD_ENTRY( pxList )                      ( ( ( pxList )->xListEnd ).pxNext )
#define listGET_ITEM_VALUE_OF_HEAD_ENTRY( pxList )        ( ( ( pxList )->xListEnd ).pxNext->xItemValue )
#define listGET_LIST_ITEM_OWNER( pxListItem )             ( ( pxListItem )->pvOwner )
#define listGET_LIST_ITEM_VALUE( pxListItem )             ( ( pxListItem )->xItemValue )
#define listGET_NEXT( pxListItem )                        ( ( pxListItem )->pxNext )
#define listGET_OWNER_OF_HEAD_ENTRY( pxList )            ( ( &( ( pxList )->xListEnd ) )->pxNext->pvOwner )
#define listGET_OWNER_OF_NEXT_ENTRY( pxTCB, pxList )                                           \
    {                                                                                          \
        List_t * const pxConstList = ( pxList );                                               \
                       \
                                 \
        ( pxConstList )->pxIndex = ( pxConstList )->pxIndex->pxNext;                           \
        if( ( void * ) ( pxConstList )->pxIndex == ( void * ) &( ( pxConstList )->xListEnd ) ) \
        {                                                                                      \
            ( pxConstList )->pxIndex = ( pxConstList )->pxIndex->pxNext;                       \
        }                                                                                      \
        ( pxTCB ) = ( pxConstList )->pxIndex->pvOwner;                                         \
    }
#define listIS_CONTAINED_WITHIN( pxList, pxListItem )    ( ( ( pxListItem )->pxContainer == ( pxList ) ) ? ( pdTRUE ) : ( pdFALSE ) )
#define listLIST_IS_EMPTY( pxList )                       ( ( ( pxList )->uxNumberOfItems == ( UBaseType_t ) 0 ) ? pdTRUE : pdFALSE )
#define listLIST_IS_INITIALISED( pxList )                ( ( pxList )->xListEnd.xItemValue == portMAX_DELAY )
#define listLIST_ITEM_CONTAINER( pxListItem )            ( ( pxListItem )->pxContainer )


    #define listSET_FIRST_LIST_ITEM_INTEGRITY_CHECK_VALUE( pxItem )
    #define listSET_LIST_INTEGRITY_CHECK_1_VALUE( pxList )
    #define listSET_LIST_INTEGRITY_CHECK_2_VALUE( pxList )
#define listSET_LIST_ITEM_OWNER( pxListItem, pxOwner )    ( ( pxListItem )->pvOwner = ( void * ) ( pxOwner ) )
#define listSET_LIST_ITEM_VALUE( pxListItem, xValue )     ( ( pxListItem )->xItemValue = ( xValue ) )
    #define listSET_SECOND_LIST_ITEM_INTEGRITY_CHECK_VALUE( pxItem )
    #define listTEST_LIST_INTEGRITY( pxList )
    #define listTEST_LIST_ITEM_INTEGRITY( pxItem )
    #define INCLUDE_eTaskGetState    0
    #define INCLUDE_uxTaskGetStackHighWaterMark    0
    #define INCLUDE_uxTaskGetStackHighWaterMark2    0
    #define INCLUDE_uxTaskPriorityGet    0
    #define INCLUDE_vTaskDelay    0
    #define INCLUDE_vTaskDelete    0
    #define INCLUDE_vTaskPrioritySet    0
    #define INCLUDE_vTaskSuspend    0
    #define INCLUDE_xQueueGetMutexHolder    0
    #define INCLUDE_xSemaphoreGetMutexHolder    INCLUDE_xQueueGetMutexHolder
    #define INCLUDE_xTaskAbortDelay    0
        #define INCLUDE_xTaskDelayUntil INCLUDE_vTaskDelayUntil
    #define INCLUDE_xTaskGetCurrentTaskHandle    0
    #define INCLUDE_xTaskGetHandle    0
    #define INCLUDE_xTaskGetIdleTaskHandle    0
    #define INCLUDE_xTaskGetSchedulerState    0
    #define INCLUDE_xTaskResumeFromISR    1
    #define INCLUDE_xTimerPendFunctionCall    0

    #define configAPPLICATION_ALLOCATED_HEAP    0
    #define configASSERT_DEFINED    0
    #define configCHECK_FOR_STACK_OVERFLOW    0
    #define configENABLE_BACKWARD_COMPATIBILITY    1
    #define configENABLE_FPU    1
    #define configENABLE_MPU    0
    #define configENABLE_TRUSTZONE    1
    #define configEXPECTED_IDLE_TIME_BEFORE_SLEEP    2
    #define configGENERATE_RUN_TIME_STATS    0
    #define configIDLE_SHOULD_YIELD    1
    #define configINCLUDE_APPLICATION_DEFINED_PRIVILEGED_FUNCTIONS    0
    #define configINCLUDE_FREERTOS_TASK_C_ADDITIONS_H    0
    #define configINITIAL_TICK_COUNT    0
    #define configMAX( a, b )    ( ( ( a ) > ( b ) ) ? ( a ) : ( b ) )
    #define configMAX_TASK_NAME_LEN    16
    #define configMESSAGE_BUFFER_LENGTH_TYPE    size_t
    #define configMIN( a, b )    ( ( ( a ) < ( b ) ) ? ( a ) : ( b ) )
    #define configNUM_THREAD_LOCAL_STORAGE_POINTERS    0
    #define configPOST_SLEEP_PROCESSING( x )
    #define configPRECONDITION( X )    configASSERT( X )
    #define configPRECONDITION_DEFINED    0
    #define configPRE_SLEEP_PROCESSING( x )
    #define configPRE_SUPPRESS_TICKS_AND_SLEEP_PROCESSING( x )
    #define configPRINTF( X )
    #define configQUEUE_REGISTRY_SIZE    0U
    #define configRECORD_STACK_HIGH_ADDRESS    0
    #define configRUN_FREERTOS_SECURE_ONLY    0
    #define configSTACK_DEPTH_TYPE    uint16_t
    #define configSUPPORT_DYNAMIC_ALLOCATION    1
    #define configSUPPORT_STATIC_ALLOCATION    0
    #define configTASK_NOTIFICATION_ARRAY_ENTRIES    1
    #define configUSE_ALTERNATIVE_API    0
    #define configUSE_APPLICATION_TASK_TAG    0
    #define configUSE_COUNTING_SEMAPHORES    0
    #define configUSE_CO_ROUTINES    0
    #define configUSE_DAEMON_TASK_STARTUP_HOOK    0
    #define configUSE_MALLOC_FAILED_HOOK    0
    #define configUSE_MUTEXES    0
    #define configUSE_NEWLIB_REENTRANT    0
    #define configUSE_PORT_OPTIMISED_TASK_SELECTION    0
    #define configUSE_POSIX_ERRNO    0
    #define configUSE_QUEUE_SETS    0
    #define configUSE_RECURSIVE_MUTEXES    0
    #define configUSE_STATS_FORMATTING_FUNCTIONS    0
    #define configUSE_TASK_FPU_SUPPORT    1
    #define configUSE_TASK_NOTIFICATIONS    1
    #define configUSE_TICKLESS_IDLE    0
    #define configUSE_TIMERS    0
    #define configUSE_TIME_SLICING    1
    #define configUSE_TRACE_FACILITY    0
    #define eTaskStateGet                 eTaskGetState


    #define pcQueueGetName( xQueue )
    #define pcQueueGetQueueName           pcQueueGetName
    #define pcTaskGetTaskName             pcTaskGetName
    #define pcTimerGetTimerName           pcTimerGetName
    #define pdTASK_CODE                   TaskFunction_t
    #define pdTASK_HOOK_CODE              TaskHookFunction_t
    #define portALLOCATE_SECURE_CONTEXT( ulSecureStackSize )


    #define portCLEAN_UP_TCB( pxTCB )    ( void ) pxTCB
    #define portCLEAR_INTERRUPT_MASK_FROM_ISR( uxSavedStatusValue )    ( void ) uxSavedStatusValue

    #define portCRITICAL_NESTING_IN_TCB    0


    #define portPOINTER_SIZE_TYPE    uint32_t
    #define portPRE_TASK_DELETE_HOOK( pvTaskToDelete, pxYieldPending )
    #define portPRIVILEGE_BIT    ( ( UBaseType_t ) 0x00 )
    #define portSETUP_TCB( pxTCB )    ( void ) pxTCB
    #define portSET_INTERRUPT_MASK_FROM_ISR()    0

    #define portSUPPRESS_TICKS_AND_SLEEP( xExpectedIdleTime )

    #define portTICK_RATE_MS              portTICK_PERIOD_MS
    #define portTICK_TYPE_CLEAR_INTERRUPT_MASK_FROM_ISR( x )    portCLEAR_INTERRUPT_MASK_FROM_ISR( ( x ) )
    #define portTICK_TYPE_ENTER_CRITICAL()                      portENTER_CRITICAL()
    #define portTICK_TYPE_EXIT_CRITICAL()                       portEXIT_CRITICAL()
    #define portTICK_TYPE_IS_ATOMIC    0
    #define portTICK_TYPE_SET_INTERRUPT_MASK_FROM_ISR()         portSET_INTERRUPT_MASK_FROM_ISR()
    #define portTickType                  TickType_t
    #define portYIELD_WITHIN_API    portYIELD
    #define pxContainer                   pvContainer
    #define tmrTIMER_CALLBACK             TimerCallbackFunction_t
    #define traceBLOCKING_ON_QUEUE_PEEK( pxQueue )
    #define traceBLOCKING_ON_QUEUE_RECEIVE( pxQueue )
    #define traceBLOCKING_ON_QUEUE_SEND( pxQueue )
    #define traceBLOCKING_ON_STREAM_BUFFER_RECEIVE( xStreamBuffer )
    #define traceBLOCKING_ON_STREAM_BUFFER_SEND( xStreamBuffer )


    #define traceCREATE_MUTEX( pxNewQueue )


    #define traceEVENT_GROUP_CLEAR_BITS( xEventGroup, uxBitsToClear )
    #define traceEVENT_GROUP_CLEAR_BITS_FROM_ISR( xEventGroup, uxBitsToClear )
    #define traceEVENT_GROUP_CREATE( xEventGroup )

    #define traceEVENT_GROUP_DELETE( xEventGroup )
    #define traceEVENT_GROUP_SET_BITS( xEventGroup, uxBitsToSet )
    #define traceEVENT_GROUP_SET_BITS_FROM_ISR( xEventGroup, uxBitsToSet )
    #define traceEVENT_GROUP_SYNC_BLOCK( xEventGroup, uxBitsToSet, uxBitsToWaitFor )
    #define traceEVENT_GROUP_SYNC_END( xEventGroup, uxBitsToSet, uxBitsToWaitFor, xTimeoutOccurred )    ( void ) xTimeoutOccurred
    #define traceEVENT_GROUP_WAIT_BITS_BLOCK( xEventGroup, uxBitsToWaitFor )
    #define traceEVENT_GROUP_WAIT_BITS_END( xEventGroup, uxBitsToWaitFor, xTimeoutOccurred )    ( void ) xTimeoutOccurred
    #define traceFREE( pvAddress, uiSize )
    #define traceGIVE_MUTEX_RECURSIVE( pxMutex )
    #define traceGIVE_MUTEX_RECURSIVE_FAILED( pxMutex )
    #define traceINCREASE_TICK_COUNT( x )


    #define traceMALLOC( pvAddress, uiSize )
    #define traceMOVED_TASK_TO_READY_STATE( pxTCB )
    #define tracePEND_FUNC_CALL( xFunctionToPend, pvParameter1, ulParameter2, ret )
    #define tracePEND_FUNC_CALL_FROM_ISR( xFunctionToPend, pvParameter1, ulParameter2, ret )
    #define tracePOST_MOVED_TASK_TO_READY_STATE( pxTCB )
    #define traceQUEUE_CREATE( pxNewQueue )
    #define traceQUEUE_CREATE_FAILED( ucQueueType )
    #define traceQUEUE_DELETE( pxQueue )
    #define traceQUEUE_PEEK( pxQueue )
    #define traceQUEUE_PEEK_FAILED( pxQueue )
    #define traceQUEUE_PEEK_FROM_ISR( pxQueue )
    #define traceQUEUE_PEEK_FROM_ISR_FAILED( pxQueue )
    #define traceQUEUE_RECEIVE( pxQueue )
    #define traceQUEUE_RECEIVE_FAILED( pxQueue )
    #define traceQUEUE_RECEIVE_FROM_ISR( pxQueue )
    #define traceQUEUE_RECEIVE_FROM_ISR_FAILED( pxQueue )
    #define traceQUEUE_REGISTRY_ADD( xQueue, pcQueueName )
    #define traceQUEUE_SEND( pxQueue )
    #define traceQUEUE_SEND_FAILED( pxQueue )
    #define traceQUEUE_SEND_FROM_ISR( pxQueue )
    #define traceQUEUE_SEND_FROM_ISR_FAILED( pxQueue )
    #define traceQUEUE_SET_SEND    traceQUEUE_SEND

    #define traceSTREAM_BUFFER_CREATE( pxStreamBuffer, xIsMessageBuffer )
    #define traceSTREAM_BUFFER_CREATE_FAILED( xIsMessageBuffer )
    #define traceSTREAM_BUFFER_CREATE_STATIC_FAILED( xReturn, xIsMessageBuffer )
    #define traceSTREAM_BUFFER_DELETE( xStreamBuffer )
    #define traceSTREAM_BUFFER_RECEIVE( xStreamBuffer, xReceivedLength )
    #define traceSTREAM_BUFFER_RECEIVE_FAILED( xStreamBuffer )
    #define traceSTREAM_BUFFER_RECEIVE_FROM_ISR( xStreamBuffer, xReceivedLength )
    #define traceSTREAM_BUFFER_RESET( xStreamBuffer )
    #define traceSTREAM_BUFFER_SEND( xStreamBuffer, xBytesSent )
    #define traceSTREAM_BUFFER_SEND_FAILED( xStreamBuffer )
    #define traceSTREAM_BUFFER_SEND_FROM_ISR( xStreamBuffer, xBytesSent )
    #define traceTAKE_MUTEX_RECURSIVE( pxMutex )
    #define traceTAKE_MUTEX_RECURSIVE_FAILED( pxMutex )
    #define traceTASK_CREATE( pxNewTCB )


    #define traceTASK_DELAY_UNTIL( x )
    #define traceTASK_DELETE( pxTaskToDelete )
    #define traceTASK_INCREMENT_TICK( xTickCount )
    #define traceTASK_NOTIFY( uxIndexToNotify )
    #define traceTASK_NOTIFY_FROM_ISR( uxIndexToNotify )
    #define traceTASK_NOTIFY_GIVE_FROM_ISR( uxIndexToNotify )
    #define traceTASK_NOTIFY_TAKE( uxIndexToWait )
    #define traceTASK_NOTIFY_TAKE_BLOCK( uxIndexToWait )
    #define traceTASK_NOTIFY_WAIT( uxIndexToWait )
    #define traceTASK_NOTIFY_WAIT_BLOCK( uxIndexToWait )
    #define traceTASK_PRIORITY_DISINHERIT( pxTCBOfMutexHolder, uxOriginalPriority )
    #define traceTASK_PRIORITY_INHERIT( pxTCBOfMutexHolder, uxInheritedPriority )
    #define traceTASK_PRIORITY_SET( pxTask, uxNewPriority )
    #define traceTASK_RESUME( pxTaskToResume )
    #define traceTASK_RESUME_FROM_ISR( pxTaskToResume )
    #define traceTASK_SUSPEND( pxTaskToSuspend )


    #define traceTIMER_COMMAND_RECEIVED( pxTimer, xMessageID, xMessageValue )
    #define traceTIMER_COMMAND_SEND( xTimer, xMessageID, xMessageValueValue, xReturn )
    #define traceTIMER_CREATE( pxNewTimer )

    #define traceTIMER_EXPIRED( pxTimer )
#define tskSTATIC_AND_DYNAMIC_ALLOCATION_POSSIBLE                                                                                     \
    ( ( ( portUSING_MPU_WRAPPERS == 0 ) && ( configSUPPORT_DYNAMIC_ALLOCATION == 1 ) && ( configSUPPORT_STATIC_ALLOCATION == 1 ) ) || \
      ( ( portUSING_MPU_WRAPPERS == 1 ) && ( configSUPPORT_DYNAMIC_ALLOCATION == 1 ) ) )
    #define vQueueAddToRegistry( xQueue, pcName )
    #define vQueueUnregisterQueue( xQueue )
    #define vTaskGetTaskInfo              vTaskGetInfo
    #define xCoRoutineHandle              CoRoutineHandle_t
    #define xList                         List_t
    #define xListItem                     ListItem_t
    #define xMemoryRegion                 MemoryRegion_t
    #define xQueueHandle                  QueueHandle_t
    #define xQueueSetHandle               QueueSetHandle_t
    #define xQueueSetMemberHandle         QueueSetMemberHandle_t
    #define xSemaphoreHandle              SemaphoreHandle_t
    #define xTaskGetIdleRunTimeCounter    ulTaskGetIdleRunTimeCounter
    #define xTaskHandle                   TaskHandle_t
    #define xTaskParameters               TaskParameters_t
    #define xTaskStatusType               TaskStatus_t
    #define xTimeOutType                  TimeOut_t
    #define xTimerHandle                  TimerHandle_t

    #define portARCH_NAME    NULL
    #define portBYTE_ALIGNMENT_MASK    ( 0x001f )
    #define portHAS_STACK_OVERFLOW_CHECKING    0
    #define portNUM_CONFIGURABLE_REGIONS    1
        #define FREERTOS_SYSTEM_CALL    __attribute__( ( section( "freertos_system_calls" ) ) )

        #define PRIVILEGED_DATA    __attribute__( ( section( "privileged_data" ) ) )
        #define PRIVILEGED_FUNCTION     __attribute__( ( section( "privileged_functions" ) ) )
        #define eTaskGetState                          MPU_eTaskGetState
        #define pcTaskGetName                          MPU_pcTaskGetName
        #define pcTimerGetName                         MPU_pcTimerGetName
    #define portUSING_MPU_WRAPPERS    0
        #define pvTaskGetThreadLocalStoragePointer     MPU_pvTaskGetThreadLocalStoragePointer
        #define pvTimerGetTimerID                      MPU_pvTimerGetTimerID
        #define ulTaskGenericNotifyTake                MPU_ulTaskGenericNotifyTake
        #define ulTaskGenericNotifyValueClear          MPU_ulTaskGenericNotifyValueClear
        #define ulTaskGetIdleRunTimeCounter            MPU_ulTaskGetIdleRunTimeCounter
        #define uxQueueMessagesWaiting                 MPU_uxQueueMessagesWaiting
        #define uxQueueSpacesAvailable                 MPU_uxQueueSpacesAvailable
        #define uxTaskGetNumberOfTasks                 MPU_uxTaskGetNumberOfTasks
        #define uxTaskGetStackHighWaterMark            MPU_uxTaskGetStackHighWaterMark
        #define uxTaskGetStackHighWaterMark2           MPU_uxTaskGetStackHighWaterMark2
        #define uxTaskGetSystemState                   MPU_uxTaskGetSystemState
        #define uxTaskPriorityGet                      MPU_uxTaskPriorityGet
        #define uxTimerGetReloadMode                   MPU_uxTimerGetReloadMode
        #define vEventGroupDelete                      MPU_vEventGroupDelete
        #define vQueueDelete                           MPU_vQueueDelete
        #define vStreamBufferDelete                    MPU_vStreamBufferDelete
        #define vTaskDelay                             MPU_vTaskDelay
        #define vTaskDelete                            MPU_vTaskDelete
        #define vTaskGetInfo                           MPU_vTaskGetInfo
        #define vTaskGetRunTimeStats                   MPU_vTaskGetRunTimeStats
        #define vTaskList                              MPU_vTaskList
        #define vTaskPrioritySet                       MPU_vTaskPrioritySet
        #define vTaskResume                            MPU_vTaskResume
        #define vTaskSetApplicationTaskTag             MPU_vTaskSetApplicationTaskTag
        #define vTaskSetThreadLocalStoragePointer      MPU_vTaskSetThreadLocalStoragePointer
        #define vTaskSetTimeOutState                   MPU_vTaskSetTimeOutState
        #define vTaskSuspend                           MPU_vTaskSuspend
        #define vTaskSuspendAll                        MPU_vTaskSuspendAll
        #define vTimerSetReloadMode                    MPU_vTimerSetReloadMode
        #define vTimerSetTimerID                       MPU_vTimerSetTimerID
        #define xEventGroupClearBits                   MPU_xEventGroupClearBits
        #define xEventGroupCreate                      MPU_xEventGroupCreate
        #define xEventGroupCreateStatic                MPU_xEventGroupCreateStatic
        #define xEventGroupSetBits                     MPU_xEventGroupSetBits
        #define xEventGroupSync                        MPU_xEventGroupSync
        #define xEventGroupWaitBits                    MPU_xEventGroupWaitBits
        #define xQueueAddToSet                         MPU_xQueueAddToSet
        #define xQueueCreateCountingSemaphore          MPU_xQueueCreateCountingSemaphore
        #define xQueueCreateCountingSemaphoreStatic    MPU_xQueueCreateCountingSemaphoreStatic
        #define xQueueCreateMutex                      MPU_xQueueCreateMutex
        #define xQueueCreateMutexStatic                MPU_xQueueCreateMutexStatic
        #define xQueueCreateSet                        MPU_xQueueCreateSet
        #define xQueueGenericCreate                    MPU_xQueueGenericCreate
        #define xQueueGenericCreateStatic              MPU_xQueueGenericCreateStatic
        #define xQueueGenericReset                     MPU_xQueueGenericReset
        #define xQueueGenericSend                      MPU_xQueueGenericSend
        #define xQueueGetMutexHolder                   MPU_xQueueGetMutexHolder
        #define xQueueGiveMutexRecursive               MPU_xQueueGiveMutexRecursive
        #define xQueuePeek                             MPU_xQueuePeek
        #define xQueueReceive                          MPU_xQueueReceive
        #define xQueueRemoveFromSet                    MPU_xQueueRemoveFromSet
        #define xQueueSelectFromSet                    MPU_xQueueSelectFromSet
        #define xQueueSemaphoreTake                    MPU_xQueueSemaphoreTake
        #define xQueueTakeMutexRecursive               MPU_xQueueTakeMutexRecursive
        #define xStreamBufferBytesAvailable            MPU_xStreamBufferBytesAvailable
        #define xStreamBufferGenericCreate             MPU_xStreamBufferGenericCreate
        #define xStreamBufferGenericCreateStatic       MPU_xStreamBufferGenericCreateStatic
        #define xStreamBufferIsEmpty                   MPU_xStreamBufferIsEmpty
        #define xStreamBufferIsFull                    MPU_xStreamBufferIsFull
        #define xStreamBufferNextMessageLengthBytes    MPU_xStreamBufferNextMessageLengthBytes
        #define xStreamBufferReceive                   MPU_xStreamBufferReceive
        #define xStreamBufferReset                     MPU_xStreamBufferReset
        #define xStreamBufferSend                      MPU_xStreamBufferSend
        #define xStreamBufferSetTriggerLevel           MPU_xStreamBufferSetTriggerLevel
        #define xStreamBufferSpacesAvailable           MPU_xStreamBufferSpacesAvailable
        #define xTaskAbortDelay                        MPU_xTaskAbortDelay
        #define xTaskCallApplicationTaskHook           MPU_xTaskCallApplicationTaskHook
        #define xTaskCatchUpTicks                      MPU_xTaskCatchUpTicks
        #define xTaskCheckForTimeOut                   MPU_xTaskCheckForTimeOut
        #define xTaskCreate                            MPU_xTaskCreate
        #define xTaskCreateStatic                      MPU_xTaskCreateStatic
        #define xTaskDelayUntil                        MPU_xTaskDelayUntil
        #define xTaskGenericNotify                     MPU_xTaskGenericNotify
        #define xTaskGenericNotifyStateClear           MPU_xTaskGenericNotifyStateClear
        #define xTaskGenericNotifyWait                 MPU_xTaskGenericNotifyWait
        #define xTaskGetApplicationTaskTag             MPU_xTaskGetApplicationTaskTag
        #define xTaskGetCurrentTaskHandle              MPU_xTaskGetCurrentTaskHandle
        #define xTaskGetHandle                         MPU_xTaskGetHandle
        #define xTaskGetIdleTaskHandle                 MPU_xTaskGetIdleTaskHandle
        #define xTaskGetSchedulerState                 MPU_xTaskGetSchedulerState
        #define xTaskGetTickCount                      MPU_xTaskGetTickCount
        #define xTaskResumeAll                         MPU_xTaskResumeAll
        #define xTimerCreate                           MPU_xTimerCreate
        #define xTimerCreateStatic                     MPU_xTimerCreateStatic
        #define xTimerGenericCommand                   MPU_xTimerGenericCommand
        #define xTimerGetExpiryTime                    MPU_xTimerGetExpiryTime
        #define xTimerGetPeriod                        MPU_xTimerGetPeriod
        #define xTimerGetTimerDaemonTaskHandle         MPU_xTimerGetTimerDaemonTaskHandle
        #define xTimerIsTimerActive                    MPU_xTimerIsTimerActive
        #define xTimerPendFunctionCall                 MPU_xTimerPendFunctionCall


#define portDISABLE_INTERRUPTS()	asm( "cli" )
#define portENABLE_INTERRUPTS()		asm( "sei" )
#define portENTER_CRITICAL()	vPortEnterCritical()
#define portEXIT_CRITICAL()		vPortExitCritical()
#define portNOP()					asm( "nop" )
#define portTASK_FUNCTION( vFunction, pvParameters ) void vFunction( void *pvParameters )
#define portTASK_FUNCTION_PROTO( vFunction, pvParameters ) void vFunction( void *pvParameters )
#define portYIELD()	vPortYield()

    #define configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES    0
#define errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY    ( -1 )
#define errQUEUE_BLOCKED                         ( -4 )
#define errQUEUE_EMPTY                           ( ( BaseType_t ) 0 )
#define errQUEUE_FULL                            ( ( BaseType_t ) 0 )
#define errQUEUE_YIELD                           ( -5 )
#define pdBIG_ENDIAN                      pdFREERTOS_BIG_ENDIAN
#define pdFAIL                                   ( pdFALSE )
#define pdFALSE                                  ( ( BaseType_t ) 0 )
#define pdFREERTOS_BIG_ENDIAN             1
#define pdFREERTOS_ERRNO_EACCES           13  
#define pdFREERTOS_ERRNO_EADDRINUSE       112 
#define pdFREERTOS_ERRNO_EADDRNOTAVAIL    125 
#define pdFREERTOS_ERRNO_EAGAIN           11  
#define pdFREERTOS_ERRNO_EALREADY         120 
#define pdFREERTOS_ERRNO_EBADE            50  
#define pdFREERTOS_ERRNO_EBADF            9   
#define pdFREERTOS_ERRNO_EBUSY            16  
#define pdFREERTOS_ERRNO_ECANCELED        140 
#define pdFREERTOS_ERRNO_EEXIST           17  
#define pdFREERTOS_ERRNO_EFAULT           14  
#define pdFREERTOS_ERRNO_EFTYPE           79  
#define pdFREERTOS_ERRNO_EILSEQ           138 
#define pdFREERTOS_ERRNO_EINPROGRESS      119 
#define pdFREERTOS_ERRNO_EINTR            4   
#define pdFREERTOS_ERRNO_EINVAL           22  
#define pdFREERTOS_ERRNO_EIO              5   
#define pdFREERTOS_ERRNO_EISCONN          127 
#define pdFREERTOS_ERRNO_EISDIR           21  
#define pdFREERTOS_ERRNO_ENAMETOOLONG     91  
#define pdFREERTOS_ERRNO_ENMFILE          89  
#define pdFREERTOS_ERRNO_ENOBUFS          105 
#define pdFREERTOS_ERRNO_ENODEV           19  
#define pdFREERTOS_ERRNO_ENOENT           2   
#define pdFREERTOS_ERRNO_ENOMEDIUM        135 
#define pdFREERTOS_ERRNO_ENOMEM           12  
#define pdFREERTOS_ERRNO_ENOPROTOOPT      109 
#define pdFREERTOS_ERRNO_ENOSPC           28  
#define pdFREERTOS_ERRNO_ENOTCONN         128 
#define pdFREERTOS_ERRNO_ENOTDIR          20  
#define pdFREERTOS_ERRNO_ENOTEMPTY        90  
#define pdFREERTOS_ERRNO_ENXIO            6   
#define pdFREERTOS_ERRNO_EOPNOTSUPP       95  
#define pdFREERTOS_ERRNO_EROFS            30  
#define pdFREERTOS_ERRNO_ESPIPE           29  
#define pdFREERTOS_ERRNO_ETIMEDOUT        116 
#define pdFREERTOS_ERRNO_EUNATCH          42  
#define pdFREERTOS_ERRNO_EWOULDBLOCK      11  
#define pdFREERTOS_ERRNO_EXDEV            18  
#define pdFREERTOS_ERRNO_NONE             0   
#define pdFREERTOS_LITTLE_ENDIAN          0
    #define pdINTEGRITY_CHECK_VALUE    0x5a5a
#define pdLITTLE_ENDIAN                   pdFREERTOS_LITTLE_ENDIAN
    #define pdMS_TO_TICKS( xTimeInMs )    ( ( TickType_t ) ( ( ( TickType_t ) ( xTimeInMs ) * ( TickType_t ) configTICK_RATE_HZ ) / ( TickType_t ) 1000U ) )
#define pdPASS                                   ( pdTRUE )
#define pdTRUE                                   ( ( BaseType_t ) 1 )
