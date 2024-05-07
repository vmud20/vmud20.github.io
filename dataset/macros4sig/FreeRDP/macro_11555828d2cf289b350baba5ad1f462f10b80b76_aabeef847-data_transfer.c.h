
#include<string.h>
#include<stdlib.h>




#include<stdio.h>
#define DEVICE_CTX(dev) ((dev)->ctx)

#define HANDLE_CTX(handle) (DEVICE_CTX((handle)->dev))
#define ITRANSFER_CTX(transfer) (TRANSFER_CTX(__USBI_TRANSFER_TO_LIBUSB_TRANSFER(transfer)))
#define TRANSFER_CTX(transfer) (HANDLE_CTX((transfer)->dev_handle))
#define BASIC_DEVMAN_STATE_DEFINED(_arg, _type) \
	_type (*get_##_arg)(IUDEVMAN * udevman);    \
	void (*set_##_arg)(IUDEVMAN * udevman, _type _arg)
#define BASIC_DEV_STATE_DEFINED(_arg, _type) \
	_type (*get_##_arg)(IUDEVICE * pdev);    \
	void (*set_##_arg)(IUDEVICE * pdev, _type _arg)
#define DEBUG_DVC(...) WLog_DBG(TAG, __VA_ARGS__)
#define DEVICE_ADD_FLAG_ALL                                               \
	(DEVICE_ADD_FLAG_BUS | DEVICE_ADD_FLAG_DEV | DEVICE_ADD_FLAG_VENDOR | \
	 DEVICE_ADD_FLAG_PRODUCT | DEVICE_ADD_FLAG_REGISTER)
#define DEVICE_ADD_FLAG_BUS 0x01
#define DEVICE_ADD_FLAG_DEV 0x02
#define DEVICE_ADD_FLAG_PRODUCT 0x08
#define DEVICE_ADD_FLAG_REGISTER 0x10
#define DEVICE_ADD_FLAG_VENDOR 0x04
#define DEVICE_COMPATIBILITY_ID_SIZE 36
#define DEVICE_CONTAINER_STR_SIZE 39
#define DEVICE_HARDWARE_ID_SIZE 32
#define DEVICE_INSTANCE_STR_SIZE 37

#define TAG CHANNELS_TAG("urbdrc.client")
#define CHANNELS_TAG(tag) FREERDP_TAG("channels.") tag

#define CLIENT_TAG(tag) FREERDP_TAG("client.") tag

#define FREERDP_TAG(tag) "com.freerdp." tag
#define SERVER_TAG(tag) FREERDP_TAG("server.") tag
