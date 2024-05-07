#include<alloca.h>
#include<endian.h>
#include<stdint.h>
#include<errno.h>
#include<string.h>
#include<stdlib.h>
#include<sys/time.h>
#include<stddef.h>
#include<iconv.h>
#include<stdbool.h>

#define AUTHENTICATE_MESSAGE    0x00000003
#define CHALLENGE_MESSAGE       0x00000002
#define MSVAVFLAGS_AUTH_CONSTRAINED 0x01
#define MSVAVFLAGS_MIC_PRESENT      0x02
#define MSVAVFLAGS_UNVERIFIED_SPN   0x04
#define NEGOTIATE_MESSAGE       0x00000001
#define NTLMSSP_ANONYMOUS                           (1 << 11)
#define NTLMSSP_MESSAGE_SIGNATURE_VERSION 0x00000001
#define NTLMSSP_NEGOTIATE_128                       (1 << 29)
#define NTLMSSP_NEGOTIATE_56                        (1 << 31)
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN               (1 << 15)
#define NTLMSSP_NEGOTIATE_DATAGRAM                  (1 << 6)
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY  (1 << 19)
#define NTLMSSP_NEGOTIATE_IDENTIFY                  (1 << 20)
#define NTLMSSP_NEGOTIATE_KEY_EXCH                  (1 << 30)
#define NTLMSSP_NEGOTIATE_LM_KEY                    (1 << 7)
#define NTLMSSP_NEGOTIATE_NTLM                      (1 << 9)
#define NTLMSSP_NEGOTIATE_OEM                       (1 << 1)
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED       (1 << 12)
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED  (1 << 13)
#define NTLMSSP_NEGOTIATE_SEAL                      (1 << 5)
#define NTLMSSP_NEGOTIATE_SIGN                      (1 << 4)
#define NTLMSSP_NEGOTIATE_TARGET_INFO               (1 << 23)
#define NTLMSSP_NEGOTIATE_UNICODE                   (1 << 0)
#define NTLMSSP_NEGOTIATE_VERSION                   (1 << 25)
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY          (1 << 22)
#define NTLMSSP_REQUEST_TARGET                      (1 << 2)
#define NTLMSSP_REVISION_W2K3 0x0F
#define NTLMSSP_TARGET_TYPE_DOMAIN                  (1 << 16)
#define NTLMSSP_TARGET_TYPE_SERVER                  (1 << 17)
#define NTLMSSP_VERSION_BUILD 0
#define NTLMSSP_VERSION_MAJOR WINDOWS_MAJOR_VERSION_6
#define NTLMSSP_VERSION_MINOR WINDOWS_MINOR_VERSION_2
#define NTLMSSP_VERSION_REV NTLMSSP_REVISION_W2K3
#define NTLM_RECV 2
#define NTLM_SEND 1
#define NTLM_SIGNATURE_SIZE 16
#define UNUSED_R1                                   (1 << 28)
#define UNUSED_R10                                  (1 << 3)
#define UNUSED_R2                                   (1 << 27)
#define UNUSED_R3                                   (1 << 26)
#define UNUSED_R4                                   (1 << 24)
#define UNUSED_R5  (1 << 21)
#define UNUSED_R6  (1 << 18)
#define UNUSED_R7         (1 << 14)
#define UNUSED_R8                                   (1 << 10)
#define UNUSED_R9                                   (1 << 8)
#define WINDOWS_MAJOR_VERSION_10 0x0A
#define WINDOWS_MAJOR_VERSION_5 0x05
#define WINDOWS_MAJOR_VERSION_6 0x06
#define WINDOWS_MINOR_VERSION_0 0x00
#define WINDOWS_MINOR_VERSION_1 0x01
#define WINDOWS_MINOR_VERSION_2 0x02
#define WINDOWS_MINOR_VERSION_3 0x03

#define IS_NTLM_ERR_CODE(x) (((x) & NTLM_ERR_MASK) ? true : false)
#define NTLM_ERR_MASK 0x4E54FFFF

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#define safefree(x) do { free(x); x = NULL; } while(0)
#define safezero(x, s) do { \
    volatile uint8_t *p = (x); \
    size_t size = (s); \
    while (size--) { *p++ = 0; } \
} while(0)
