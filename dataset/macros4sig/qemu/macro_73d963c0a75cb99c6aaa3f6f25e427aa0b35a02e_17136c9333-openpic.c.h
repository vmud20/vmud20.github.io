#include<limits.h>
#include<fcntl.h>

#include<sys/signal.h>

#include<stdlib.h>



#include<stdio.h>
#include<pthread.h>





#include<linux/kvm_para.h>



#include<emmintrin.h>
#include<sys/uio.h>

#include<signal.h>

#include<strings.h>

#include<semaphore.h>

#include<stdarg.h>

#include<errno.h>

#include<stdint.h>




#include<string.h>


#include<stddef.h>

#include<inttypes.h>
#include<ctype.h>
#include<sys/wait.h>


#include<assert.h>


#include<time.h>


#include<stdbool.h>




#include<setjmp.h>
#include<sys/time.h>
#include<sys/stat.h>


#include<unistd.h>

#include<sys/types.h>
#include<linux/kvm.h>

#define QERR_BASE_NOT_FOUND \
    ERROR_CLASS_GENERIC_ERROR, "Base '%s' not found"
#define QERR_BLOCK_FORMAT_FEATURE_NOT_SUPPORTED \
    ERROR_CLASS_GENERIC_ERROR, "Block format '%s' used by device '%s' does not support feature '%s'"
#define QERR_BLOCK_JOB_NOT_ACTIVE \
    ERROR_CLASS_DEVICE_NOT_ACTIVE, "No active block job on device '%s'"
#define QERR_BLOCK_JOB_NOT_READY \
    ERROR_CLASS_GENERIC_ERROR, "The active block job for device '%s' cannot be completed"
#define QERR_BUS_NOT_FOUND \
    ERROR_CLASS_GENERIC_ERROR, "Bus '%s' not found"
#define QERR_BUS_NO_HOTPLUG \
    ERROR_CLASS_GENERIC_ERROR, "Bus '%s' does not support hotplugging"
#define QERR_COMMAND_NOT_FOUND \
    ERROR_CLASS_COMMAND_NOT_FOUND, "The command %s has not been found"
#define QERR_DEVICE_ENCRYPTED \
    ERROR_CLASS_DEVICE_ENCRYPTED, "'%s' (%s) is encrypted"
#define QERR_DEVICE_HAS_NO_MEDIUM \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' has no medium"
#define QERR_DEVICE_INIT_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' could not be initialized"
#define QERR_DEVICE_IN_USE \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' is in use"
#define QERR_DEVICE_IS_READ_ONLY \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' is read only"
#define QERR_DEVICE_NOT_ACTIVE \
    ERROR_CLASS_DEVICE_NOT_ACTIVE, "No %s device has been activated"
#define QERR_DEVICE_NOT_ENCRYPTED \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' is not encrypted"
#define QERR_DEVICE_NOT_FOUND \
    ERROR_CLASS_DEVICE_NOT_FOUND, "Device '%s' not found"
#define QERR_DEVICE_NO_HOTPLUG \
    ERROR_CLASS_GENERIC_ERROR, "Device '%s' does not support hotplugging"
#define QERR_FD_NOT_FOUND \
    ERROR_CLASS_GENERIC_ERROR, "File descriptor named '%s' not found"
#define QERR_FD_NOT_SUPPLIED \
    ERROR_CLASS_GENERIC_ERROR, "No file descriptor supplied via SCM_RIGHTS"
#define QERR_FEATURE_DISABLED \
    ERROR_CLASS_GENERIC_ERROR, "The feature '%s' is not enabled"
#define QERR_INVALID_BLOCK_FORMAT \
    ERROR_CLASS_GENERIC_ERROR, "Invalid block format '%s'"
#define QERR_INVALID_PARAMETER \
    ERROR_CLASS_GENERIC_ERROR, "Invalid parameter '%s'"
#define QERR_INVALID_PARAMETER_TYPE \
    ERROR_CLASS_GENERIC_ERROR, "Invalid parameter type for '%s', expected: %s"
#define QERR_INVALID_PARAMETER_VALUE \
    ERROR_CLASS_GENERIC_ERROR, "Parameter '%s' expects %s"
#define QERR_INVALID_PASSWORD \
    ERROR_CLASS_GENERIC_ERROR, "Password incorrect"
#define QERR_IO_ERROR \
    ERROR_CLASS_GENERIC_ERROR, "An IO error has occurred"
#define QERR_JSON_PARSING \
    ERROR_CLASS_GENERIC_ERROR, "Invalid JSON syntax"
#define QERR_KVM_MISSING_CAP \
    ERROR_CLASS_KVM_MISSING_CAP, "Using KVM without %s, %s unavailable"
#define QERR_MIGRATION_ACTIVE \
    ERROR_CLASS_GENERIC_ERROR, "There's a migration process in progress"
#define QERR_MISSING_PARAMETER \
    ERROR_CLASS_GENERIC_ERROR, "Parameter '%s' is missing"
#define QERR_PERMISSION_DENIED \
    ERROR_CLASS_GENERIC_ERROR, "Insufficient permission to perform this operation"
#define QERR_PROPERTY_VALUE_BAD \
    ERROR_CLASS_GENERIC_ERROR, "Property '%s.%s' doesn't take value '%s'"
#define QERR_PROPERTY_VALUE_OUT_OF_RANGE \
    ERROR_CLASS_GENERIC_ERROR, "Property %s.%s doesn't take value %" PRId64 " (minimum: %" PRId64 ", maximum: %" PRId64 ")"
#define QERR_QGA_COMMAND_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Guest agent command failed, error was '%s'"
#define QERR_QMP_BAD_INPUT_OBJECT \
    ERROR_CLASS_GENERIC_ERROR, "Expected '%s' in QMP input"
#define QERR_QMP_BAD_INPUT_OBJECT_MEMBER \
    ERROR_CLASS_GENERIC_ERROR, "QMP input object member '%s' expects '%s'"
#define QERR_QMP_EXTRA_MEMBER \
    ERROR_CLASS_GENERIC_ERROR, "QMP input object member '%s' is unexpected"
#define QERR_SET_PASSWD_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Could not set password"
#define QERR_SOCKET_BIND_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Failed to bind socket"
#define QERR_SOCKET_CONNECT_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Failed to connect to socket"
#define QERR_SOCKET_CREATE_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Failed to create socket"
#define QERR_SOCKET_LISTEN_FAILED \
    ERROR_CLASS_GENERIC_ERROR, "Failed to set socket to listening mode"
#define QERR_UNDEFINED_ERROR \
    ERROR_CLASS_GENERIC_ERROR, "An undefined error has occurred"
#define QERR_UNKNOWN_BLOCK_FORMAT_FEATURE \
    ERROR_CLASS_GENERIC_ERROR, "'%s' uses a %s feature which is not supported by this qemu version: %s"
#define QERR_UNSUPPORTED \
    ERROR_CLASS_GENERIC_ERROR, "this feature or command is not currently supported"

#define error_setg(err, fmt, ...) \
    error_set(err, ERROR_CLASS_GENERIC_ERROR, fmt, ## __VA_ARGS__)
#define error_setg_errno(err, os_error, fmt, ...) \
    error_set_errno(err, os_error, ERROR_CLASS_GENERIC_ERROR, fmt, ## __VA_ARGS__)
#define error_setg_win32(err, win32_err, fmt, ...) \
    error_set_win32(err, win32_err, ERROR_CLASS_GENERIC_ERROR, fmt, ## __VA_ARGS__)

#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))
#define QEMU_BUILD_BUG_ON(x) \
    typedef char cat2(qemu_build_bug_on__,"__LINE__")[(x)?-1:1] __attribute__((unused));
# define QEMU_GNUC_PREREQ(maj, min) \
         (("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
#define QEMU_NORETURN __attribute__ ((__noreturn__))
# define QEMU_PACKED __attribute__((gcc_struct, packed))
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#   define __printf__ __gnu_printf__
#define cat(x,y) x ## y
#define cat2(x,y) cat(x,y)


#define QDECREF(obj)              \
    qobject_decref(obj ? QOBJECT(obj) : NULL)
#define QINCREF(obj)      \
    qobject_incref(QOBJECT(obj))
#define QOBJECT(obj) (&(obj)->base)

#define QOBJECT_INIT(obj, qtype_type)   \
    obj->base.refcnt = 1;               \
    obj->base.type   = qtype_type
#define QObject_HEAD  \
    QObject base
#define BIT(nr)			(1UL << (nr))

#define BITS_PER_BYTE           CHAR_BIT
#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define ALL_EQ(v1, v2) vec_all_eq(v1, v2)
#define BUFFER_FIND_NONZERO_OFFSET_UNROLL_FACTOR 8
#define ECANCELED 4097
#define EMEDIUMTYPE 4098
#define ENOMEDIUM ENODEV
#define ENOTSUP 4096
# define HOST_LONG_BITS 32
#define MAP_ANONYMOUS MAP_ANON
#define O_BINARY 0
#define O_LARGEFILE 0
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

#define QEMU_FILE_TYPE_BIOS   0
#define QEMU_FILE_TYPE_KEYMAP 1
#define SPLAT(p)       vec_splat(vec_ld(0, p), 0)
#define STR_OR_NULL(str) ((str) ? (str) : "null")
#define TFR(expr) do { if ((expr) != -1) break; } while (errno == EINTR)
#define TIME_MAX LONG_MAX
#define VECTYPE        __vector unsigned char

#define bool _Bool
#define fsync _commit
# define ftruncate qemu_ftruncate64
# define lseek _lseeki64
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
#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
#define FMT_pid "%ld"
#define IOV_MAX 1024
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define QEMU_MADV_DONTDUMP MADV_DONTDUMP
#define QEMU_MADV_DONTFORK  MADV_DONTFORK
#define QEMU_MADV_DONTNEED  MADV_DONTNEED
#define QEMU_MADV_HUGEPAGE MADV_HUGEPAGE
#define QEMU_MADV_INVALID -1
#define QEMU_MADV_MERGEABLE MADV_MERGEABLE
#define QEMU_MADV_WILLNEED  MADV_WILLNEED

#define ROUND_UP(n,d) (((n) + (d) - 1) & -(d))
#define WEXITSTATUS(x) (x)
#define WIFEXITED(x)   1
#define __builtin_expect(x, n) (x)
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#define glue(x, y) xglue(x, y)
#define inline __attribute__ (( always_inline )) __inline__
#define likely(x)   __builtin_expect(!!(x), 1)
#define qemu_printf printf
#define qemu_timersub timersub
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#define type_check(t1,t2) ((t1*)0 - (t2*)0)
#define typeof_field(type, field) typeof(((type *)0)->field)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#define xglue(x, y) x ## y

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
#define INLINE static inline
#define LIT64( a ) a##LL

#define STATUS(field) status->field
#define STATUS_PARAM , float_status *status
#define STATUS_VAR , status
#define const_float16(x) (x)
#define const_float32(x) { x }
#define const_float64(x) { x }
#define float128_zero make_float128(0, 0)
#define float16_val(x) (x)
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
#define make_float16(x) (x)
#define make_float32(x) __extension__ ({ float32 f32_val = {x}; f32_val; })
#define make_float64(x) __extension__ ({ float64 f64_val = {x}; f64_val; })
#define make_floatx80(exp, mant) ((floatx80) { mant, exp })
#define make_floatx80_init(exp, mant) { .low = mant, .high = exp }

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

# define setjmp(env) _setjmp(env, NULL)
#define sigjmp_buf jmp_buf
#define siglongjmp(env, val) longjmp(env, val)
#define sigsetjmp(env, savemask) setjmp(env)



#define FMT_PCIBUS                      PRIx64
#define PCIE_CONFIG_SPACE_SIZE  0x1000
#define PCI_BAR_UNMAPPED (~(pcibus_t)0)
#define PCI_BUS(obj) OBJECT_CHECK(PCIBus, (obj), TYPE_PCI_BUS)
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
#define PCI_DEVICE_ID_REDHAT_QXL         0x0100
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
#define  PCI_CAP_ID_EXP 	0x10	
#define  PCI_CAP_ID_SHPC 	0x0C	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 0x100	
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM1 0x200
#define  PCI_COMMAND_INTX_DISABLE 0x400 
#define  PCI_COMMAND_VGA_PALETTE 0x20	
#define  PCI_COMMAND_WAIT 	0x80	
#define  PCI_ERR_CAP_FEP(x)	((x) & 31)	
#define  PCI_EXP_DEVCAP_FLR     0x10000000 
#define  PCI_EXP_DEVCTL_BCR_FLR 0x8000  
#define  PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800  
#define  PCI_EXP_DEVCTL_RELAX_EN 0x0010 
#define  PCI_EXP_LNKCTL_CLKREQ_EN 0x100	
#define  PCI_EXP_LNKSTA_CLS_2_5GB 0x01	
#define  PCI_EXP_LNKSTA_CLS_5_0GB 0x02	
#define  PCI_EXP_LNKSTA_NLW_SHIFT 4	
#define  PCI_EXP_TYPE_DOWNSTREAM 0x6	
#define  PCI_EXP_TYPE_PCIE_BRIDGE 0x8   
#define  PCI_EXP_TYPE_PCI_BRIDGE 0x7	
#define  PCI_EXP_TYPE_RC_EC     0xa     
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
#define  PCI_SRIOV_CAP_INTR(x)	((x) >> 21) 
#define  PCI_SRIOV_VFM_BIR(x)	((x) & 7)	
#define  PCI_SRIOV_VFM_OFFSET(x) ((x) & ~7)	
#define PCI_SSVID_DEVICE_ID     6	
#define PCI_SSVID_VENDOR_ID     4	
#define  PCI_X_CMD_VERSION(x) 	(((x) >> 12) & 3) 
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
#define PCI_CLASS_MEMORY_RAM             0x0500
#define PCI_CLASS_MULTIMEDIA_AUDIO       0x0401
#define PCI_CLASS_NETWORK_ETHERNET       0x0200
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

#define VMSTATE_PCIE_DEVICE(_field, _state) {                        \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(PCIDevice),                                 \
    .vmsd       = &vmstate_pcie_device,                              \
    .flags      = VMS_STRUCT,                                        \
    .offset     = vmstate_offset_value(_state, _field, PCIDevice),   \
}

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
#define OBJECT_CLASS_CHECK(class, obj, name) \
    ((class *)object_class_dynamic_cast_assert(OBJECT_CLASS(obj), (name), \
                                               "__FILE__", "__LINE__", __func__))
#define OBJECT_GET_CLASS(class, obj, name) \
    OBJECT_CLASS_CHECK(class, object_get_class(OBJECT(obj)), name)

#define TYPE_INTERFACE "interface"
#define TYPE_OBJECT "object"

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
#define QLIST_INSERT_HEAD_RCU(head, elm, field) do {                    \
        (elm)->field.le_prev = &(head)->lh_first;                       \
        (elm)->field.le_next = (head)->lh_first;                        \
        smp_wmb();                      \
        if ((head)->lh_first != NULL)  {                                \
            (head)->lh_first->field.le_prev = &(elm)->field.le_next;    \
        }                                                               \
        (head)->lh_first = (elm);                                       \
        smp_wmb();                                                      \
} while (0)
#define QLIST_NEXT(elm, field)           ((elm)->field.le_next)
#define QLIST_REMOVE(elm, field) do {                                   \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
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
        (elm)->field.sle_next = (head)->slh_first;                      \
        (head)->slh_first = (elm);                                      \
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
#define atomic_read(ptr)       (*(__typeof__(*ptr) *volatile) (ptr))
#define atomic_set(ptr, i)     ((*(__typeof__(*ptr) *volatile) (ptr)) = (i))
#define atomic_sub(ptr, n)     ((void) __sync_fetch_and_sub(ptr, n))
#define atomic_xchg(ptr, i)    __sync_swap(ptr, i)
#define barrier()   ({ asm volatile("" ::: "memory"); (void)0; })
#define smp_mb()    ({ asm volatile("mfence" ::: "memory"); (void)0; })
#define smp_read_barrier_depends()   __atomic_thread_fence(__ATOMIC_CONSUME)
#define smp_rmb()   __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define smp_wmb()   __atomic_thread_fence(__ATOMIC_RELEASE)
#define PCIE_AER_ERR_HEADER_VALID       0x4     
#define PCIE_AER_ERR_IS_CORRECTABLE     0x1     
#define PCIE_AER_ERR_MAYBE_ADVISORY     0x2     
#define PCIE_AER_ERR_TLP_PREFIX_PRESENT 0x8     
#define PCIE_AER_LOG_MAX_DEFAULT        8
#define PCIE_AER_LOG_MAX_LIMIT          128
#define PCIE_AER_LOG_MAX_UNSET          0xffff


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
#define CPU_LOG_EXEC       (1 << 5)
#define CPU_LOG_INT        (1 << 4)
#define CPU_LOG_IOPORT     (1 << 7)
#define CPU_LOG_PCALL      (1 << 6)
#define CPU_LOG_RESET      (1 << 9)
#define CPU_LOG_TB_CPU     (1 << 8)
#define CPU_LOG_TB_IN_ASM  (1 << 1)
#define CPU_LOG_TB_OP      (1 << 2)
#define CPU_LOG_TB_OP_OPT  (1 << 3)
#define CPU_LOG_TB_OUT_ASM (1 << 0)
#define LOG_GUEST_ERROR    (1 << 11)
#define LOG_UNIMP          (1 << 10)


#define BP_CPU                0x20
#define BP_GDB                0x10
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_STOP_BEFORE_ACCESS 0x04
#define BP_WATCHPOINT_HIT     0x08
#define CPU(obj) ((CPUState *)(obj))
#define CPU_CLASS(class) OBJECT_CLASS_CHECK(CPUClass, (class), TYPE_CPU)
#define CPU_FOREACH(cpu) QTAILQ_FOREACH(cpu, &cpus, node)
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
#define current_cpu tls_var(current_cpu)
#define first_cpu QTAILQ_FIRST(&cpus)
#define vmstate_cpu_common vmstate_dummy
#define DECLARE_TLS(type, x) extern DEFINE_TLS(type, x)
#define DEFINE_TLS(type, x)  __thread __typeof__(type) tls__##x

#define tls_var(x)           tls__##x
#define QEMU_THREAD_DETACHED 1
#define QEMU_THREAD_JOINABLE 0
#define __QEMU_THREAD_H 1
#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)
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
#define BUS(obj) OBJECT_CHECK(BusState, (obj), TYPE_BUS)
#define BUS_CLASS(klass) OBJECT_CLASS_CHECK(BusClass, (klass), TYPE_BUS)
#define BUS_GET_CLASS(obj) OBJECT_GET_CLASS(BusClass, (obj), TYPE_BUS)
#define DEVICE(obj) OBJECT_CHECK(DeviceState, (obj), TYPE_DEVICE)
#define DEVICE_CLASS(klass) OBJECT_CLASS_CHECK(DeviceClass, (klass), TYPE_DEVICE)
#define DEVICE_GET_CLASS(obj) OBJECT_GET_CLASS(DeviceClass, (obj), TYPE_DEVICE)

#define QDEV_HOTPLUG_HANDLER_PROPERTY "hotplug-handler"
#define TYPE_BUS "bus"
#define TYPE_DEVICE "device"


#define BITMAP_LAST_WORD_MASK(nbits)                                    \
    (                                                                   \
        ((nbits) % BITS_PER_LONG) ?                                     \
        (1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL                       \
        )
#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]
#define small_nbits(nbits)                      \
        ((nbits) <= BITS_PER_LONG)

#define QDICT_BUCKET_MAX 512

#define qdict_put(qdict, key, obj) \
        qdict_put_obj(qdict, key, QOBJECT(obj))
#define QLIST_FOREACH_ENTRY(qlist, var)             \
        for ((var) = ((qlist)->head.tqh_first);     \
            (var);                                  \
            (var) = ((var)->next.tqe_next))

#define qlist_append(qlist, obj) \
        qlist_append_obj(qlist, QOBJECT(obj))
#define QEMU_VMSTATE_H 1
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
#define VMSTATE_BUFFER_UNSAFE_INFO(_field, _state, _version, _info, _size) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .size       = (_size),                                           \
    .info       = &(_info),                                          \
    .flags      = VMS_BUFFER,                                        \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_BUFFER_V(_f, _s, _v)                                  \
    VMSTATE_STATIC_BUFFER(_f, _s, _v, NULL, 0, sizeof(typeof_field(_s, _f)))
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
#define VMSTATE_INT32_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int32, int32_t)
#define VMSTATE_INT64(_f, _s)                                         \
    VMSTATE_INT64_V(_f, _s, 0)
#define VMSTATE_INT64_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT64_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int64, int64_t)
#define VMSTATE_INT64_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int64, int64_t)
#define VMSTATE_INT8(_f, _s)                                          \
    VMSTATE_INT8_V(_f, _s, 0)
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
#define VMSTATE_STRUCT_TEST(_field, _state, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_STRUCT,                                      \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
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
    VMSTATE_ARRAY_OF_POINTER(_f, _s, _n, 0, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_TEST(_f, _s, _test)                             \
    VMSTATE_POINTER_TEST(_f, _s, _test, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_V(_f, _s, _v)                                   \
    VMSTATE_POINTER(_f, _s, _v, vmstate_info_timer, QEMUTimer *)
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
    (offsetof(_state, _field[_start]))
#define vmstate_offset_value(_state, _field, _type)                  \
    (offsetof(_state, _field) +                                      \
     type_check(_type, typeof_field(_state, _field)))
#define QEMU_FILE_H 1
#define RAM_CONTROL_FINISH   3
#define RAM_CONTROL_HOOK     2
#define RAM_CONTROL_ROUND    1
#define RAM_CONTROL_SETUP    0
#define qemu_get_sbyte qemu_get_byte
#define qemu_put_sbyte qemu_put_byte
#define CPU_COMMON_H 1
#  define RAM_ADDR_FMT "%" PRIx64
#  define RAM_ADDR_MAX UINT64_MAX


#define MIPS_RDHWR(rd, value) {                         \
        __asm__ __volatile__ (".set   push\n\t"         \
                              ".set mips32r2\n\t"       \
                              "rdhwr  %0, "rd"\n\t"     \
                              ".set   pop"              \
                              : "=r" (value));          \
    }

#define SCALE_MS 1000000
#define SCALE_NS 1
#define SCALE_US 1000
#define NOTIFIER_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }
#define NOTIFIER_WITH_RETURN_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }



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
#define PCI_ERR_ROOT_IRQ_SHIFT          (ffs(PCI_ERR_ROOT_IRQ) - 1)
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
#define PCI_EXP_DEVCTL2_EETLPPB         0x80
#define PCI_EXP_FLAGS_IRQ_SHIFT         (ffs(PCI_EXP_FLAGS_IRQ) - 1)
#define PCI_EXP_FLAGS_TYPE_SHIFT        (ffs(PCI_EXP_FLAGS_TYPE) - 1)
#define PCI_EXP_FLAGS_VER2              2 
#define PCI_EXP_LNKCAP_ASPMS_0S         (1 << PCI_EXP_LNKCAP_ASPMS_SHIFT)
#define PCI_EXP_LNKCAP_ASPMS_SHIFT      (ffs(PCI_EXP_LNKCAP_ASPMS) - 1)
#define PCI_EXP_LNKCAP_PN_SHIFT         (ffs(PCI_EXP_LNKCAP_PN) - 1)
#define PCI_EXP_LNK_LS_25               1
#define PCI_EXP_LNK_MLW_1               (1 << PCI_EXP_LNK_MLW_SHIFT)
#define PCI_EXP_LNK_MLW_SHIFT           (ffs(PCI_EXP_LNKCAP_MLW) - 1)
#define PCI_EXP_SLTCAP_PSN_SHIFT        (ffs(PCI_EXP_SLTCAP_PSN) - 1)
#define PCI_EXP_SLTCTL_AIC_OFF                          \
    (PCI_EXP_SLTCTL_IND_OFF << PCI_EXP_SLTCTL_AIC_SHIFT)
#define PCI_EXP_SLTCTL_AIC_SHIFT        (ffs(PCI_EXP_SLTCTL_AIC) - 1)
#define PCI_EXP_SLTCTL_IND_BLINK        0x2
#define PCI_EXP_SLTCTL_IND_OFF          0x3
#define PCI_EXP_SLTCTL_IND_ON           0x1
#define PCI_EXP_SLTCTL_IND_RESERVED     0x0
#define PCI_EXP_SLTCTL_PIC_OFF                          \
    (PCI_EXP_SLTCTL_IND_OFF << PCI_EXP_SLTCTL_PIC_SHIFT)
#define PCI_EXP_SLTCTL_PIC_SHIFT        (ffs(PCI_EXP_SLTCTL_PIC) - 1)
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
#define DEFINE_PROP_BLOCKSIZE(_n, _s, _f, _d) \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_blocksize, uint16_t)
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
    DEFINE_PROP(_n, _s, _f, qdev_prop_drive, BlockDriverState *)
#define DEFINE_PROP_END_OF_LIST()               \
    {}
#define DEFINE_PROP_INT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_DEFAULT(_n, _s, _f, _d, qdev_prop_int32, int32_t)
#define DEFINE_PROP_IOTHREAD(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_iothread, IOThread *)
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
#define kvm_enabled()           (0)
#define kvm_gsi_direct_mapping() (kvm_gsi_direct_mapping)
#define kvm_gsi_routing_allowed() (false)
#define kvm_gsi_routing_enabled() (kvm_gsi_routing_allowed)
#define kvm_halt_in_kernel() (false)
#define kvm_irqchip_in_kernel() (false)
#define kvm_irqfds_enabled() (false)
#define kvm_msi_via_irqfd_enabled() (kvm_msi_via_irqfd_allowed)
#define kvm_readonly_mem_enabled() (kvm_readonly_mem_allowed)
#define kvm_vcpu_enable_cap(cpu, capability, cap_flags, ...)         \
    ({                                                               \
        struct kvm_enable_cap cap = {                                \
            .cap = capability,                                       \
            .flags = cap_flags,                                      \
        };                                                           \
        uint64_t args_tmp[] = { __VA_ARGS__ };                       \
        int i;                                                       \
        for (i = 0; i < ARRAY_SIZE(args_tmp) &&                      \
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
        for (i = 0; i < ARRAY_SIZE(args_tmp) &&                      \
                     i < ARRAY_SIZE(cap.args); i++) {                \
            cap.args[i] = args_tmp[i];                               \
        }                                                            \
        kvm_vm_ioctl(s, KVM_ENABLE_CAP, &cap);                       \
    })
#define BDRV_BLOCK_DATA         1
#define BDRV_BLOCK_OFFSET_MASK  BDRV_SECTOR_MASK
#define BDRV_BLOCK_OFFSET_VALID 4
#define BDRV_BLOCK_RAW          8
#define BDRV_BLOCK_ZERO         2
#define BDRV_O_ALLOW_RDWR  0x2000  
#define BDRV_O_CACHE_MASK  (BDRV_O_NOCACHE | BDRV_O_CACHE_WB | BDRV_O_NO_FLUSH)
#define BDRV_O_CACHE_WB    0x0040 
#define BDRV_O_CHECK       0x1000  
#define BDRV_O_COPY_ON_READ 0x0400 
#define BDRV_O_INCOMING    0x0800  
#define BDRV_O_NATIVE_AIO  0x0080 
#define BDRV_O_NOCACHE     0x0020 
#define BDRV_O_NO_BACKING  0x0100 
#define BDRV_O_NO_FLUSH    0x0200 
#define BDRV_O_PROTOCOL    0x8000  
#define BDRV_O_RDWR        0x0002
#define BDRV_O_SNAPSHOT    0x0008 
#define BDRV_O_TEMPORARY   0x0010 
#define BDRV_O_UNMAP       0x4000  
#define BDRV_SECTOR_BITS   9
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1)
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BLKDBG_EVENT(bs, evt) bdrv_debug_event(bs, evt)




#define HW_SYSBUS_H 1
#define QDEV_MAX_IRQ 512
#define QDEV_MAX_MMIO 32
#define QDEV_MAX_PIO 32
#define SYSTEM_BUS(obj) OBJECT_CHECK(IDEBus, (obj), TYPE_IDE_BUS)
#define SYS_BUS_DEVICE(obj) \
     OBJECT_CHECK(SysBusDevice, (obj), TYPE_SYS_BUS_DEVICE)
#define SYS_BUS_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(SysBusDeviceClass, (klass), TYPE_SYS_BUS_DEVICE)
#define SYS_BUS_DEVICE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(SysBusDeviceClass, (obj), TYPE_SYS_BUS_DEVICE)
#define TYPE_SYSTEM_BUS "System"
#define TYPE_SYS_BUS_DEVICE "sys-bus-device"

#define OPENPIC_MAX_IPI     4
#define OPENPIC_MAX_IRQ     (OPENPIC_MAX_SRC + OPENPIC_MAX_IPI + \
                             OPENPIC_MAX_TMR)
#define OPENPIC_MAX_SRC     256
#define OPENPIC_MAX_TMR     4
#define OPENPIC_MODEL_FSL_MPIC_20 1
#define OPENPIC_MODEL_FSL_MPIC_42 2
#define OPENPIC_MODEL_RAVEN       0
#define TYPE_KVM_OPENPIC "kvm-openpic"
#define TYPE_OPENPIC "openpic"

#define BIOS_SIZE     (1024 * 1024)
#define CUDA(obj) OBJECT_CHECK(CUDAState, (obj), TYPE_CUDA)
#define ESCC_CLOCK 3686400
#define KERNEL_GAP       0x00100000
#define KERNEL_LOAD_ADDR 0x01000000
#define MACIO_IDE(obj) OBJECT_CHECK(MACIOIDEState, (obj), TYPE_MACIO_IDE)
#define MACIO_NVRAM(obj) \
    OBJECT_CHECK(MacIONVRAMState, (obj), TYPE_MACIO_NVRAM)
#define MAX_CPUS 1
#define NVRAM_SIZE        0x2000
#define PROM_ADDR         0xfff00000
#define PROM_FILENAME    "openbios-ppc"
#define TYPE_CUDA "cuda"
#define TYPE_GRACKLE_PCI_HOST_BRIDGE "grackle-pcihost"
#define TYPE_MACIO_IDE "macio-ide"
#define TYPE_MACIO_NVRAM "macio-nvram"
#define TYPE_NEWWORLD_MACIO "macio-newworld"
#define TYPE_OLDWORLD_MACIO "macio-oldworld"

#define ADB_BUS(obj) OBJECT_CHECK(ADBBusState, (obj), TYPE_ADB_BUS)
#define ADB_DEVICE(obj) OBJECT_CHECK(ADBDevice, (obj), TYPE_ADB_DEVICE)
#define ADB_DEVICE_CLASS(cls) \
    OBJECT_CLASS_CHECK(ADBDeviceClass, (cls), TYPE_ADB_DEVICE)
#define ADB_DEVICE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(ADBDeviceClass, (obj), TYPE_ADB_DEVICE)
#define ADB_MAX_OUT_LEN 16
#define MAX_ADB_DEVICES 16
#define TYPE_ADB_BUS "apple-desktop-bus"
#define TYPE_ADB_DEVICE "adb-device"
#define TYPE_ADB_KEYBOARD "adb-keyboard"
#define TYPE_ADB_MOUSE "adb-mouse"

#define ASC_ILLEGAL_OPCODE                   0x20
#define ASC_INCOMPATIBLE_FORMAT              0x30
#define ASC_INV_FIELD_IN_CMD_PACKET          0x24
#define ASC_LOGICAL_BLOCK_OOR                0x21
#define ASC_MEDIA_REMOVAL_PREVENTED          0x53
#define ASC_MEDIUM_MAY_HAVE_CHANGED          0x28
#define ASC_MEDIUM_NOT_PRESENT               0x3a
#define ASC_SAVING_PARAMETERS_NOT_SUPPORTED  0x39
#define ATAPI_INT_REASON_CD             0x01 
#define ATAPI_INT_REASON_IO             0x02 
#define ATAPI_INT_REASON_REL            0x04
#define ATAPI_INT_REASON_TAG            0xf8
#define ATAPI_PACKET_SIZE 12
#define BM_CMD_READ      0x08
#define BM_CMD_START     0x01
#define BM_MIGRATION_COMPAT_STATUS_BITS \
        (BM_STATUS_DMA_RETRY | BM_STATUS_PIO_RETRY | \
        BM_STATUS_RETRY_READ | BM_STATUS_RETRY_FLUSH)
#define BM_STATUS_DMAING 0x01
#define BM_STATUS_DMA_RETRY  0x08
#define BM_STATUS_ERROR  0x02
#define BM_STATUS_INT    0x04
#define BM_STATUS_PIO_RETRY  0x10
#define BM_STATUS_RETRY_FLUSH 0x40
#define BM_STATUS_RETRY_READ  0x20
#define BM_STATUS_RETRY_TRIM 0x80
#define CFA_ADDRESS_OVERFLOW    0x2f
#define CFA_ERASE_SECTORS       	0xC0 
#define CFA_INVALID_ADDRESS     0x21
#define CFA_INVALID_COMMAND     0x20
#define CFA_MISC_ERROR          0x09
#define CFA_NO_ERROR            0x00
#define CFA_WEAR_LEVEL                  0xF5 
#define DSM_TRIM                        0x01
#define GPCMD_GET_EVENT_STATUS_NOTIFICATION 0x4a
#define GPCMD_PREVENT_ALLOW_MEDIUM_REMOVAL  0x1e

#define IBM_SENSE_CONDITION             0xF0 
#define IDE_BUS(obj) OBJECT_CHECK(IDEBus, (obj), TYPE_IDE_BUS)
#define IDE_CMD_DISABLE_IRQ     0x02
#define IDE_CMD_RESET           0x04
#define IDE_DEVICE(obj) \
     OBJECT_CHECK(IDEDevice, (obj), TYPE_IDE_DEVICE)
#define IDE_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(IDEDeviceClass, (klass), TYPE_IDE_DEVICE)
#define IDE_DEVICE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(IDEDeviceClass, (obj), TYPE_IDE_DEVICE)
#define IDE_DMA_BUF_SECTORS 256
#define MAX_MULT_SECTORS 16
#define SMART_ATTR_AUTOSAVE   0xd2
#define SMART_DISABLE         0xd9
#define SMART_ENABLE          0xd8
#define SMART_EXECUTE_OFFLINE 0xd4
#define SMART_READ_DATA       0xd0
#define SMART_READ_LOG        0xd5
#define SMART_READ_THRESH     0xd1
#define SMART_SAVE_ATTR       0xd3
#define SMART_STATUS          0xda
#define SMART_WRITE_LOG       0xd6
#define TYPE_IDE_BUS "IDE"
#define TYPE_IDE_DEVICE "ide-device"

#define VMSTATE_IDE_BUS(_field, _state)                          \
    VMSTATE_STRUCT(_field, _state, 1, vmstate_ide_bus, IDEBus)
#define VMSTATE_IDE_BUS_ARRAY(_field, _state, _num)              \
    VMSTATE_STRUCT_ARRAY(_field, _state, _num, 1, vmstate_ide_bus, IDEBus)
#define VMSTATE_IDE_DRIVES(_field, _state) \
    VMSTATE_STRUCT_ARRAY(_field, _state, 2, 3, vmstate_ide_drive, IDEState)
#define WIN_CHECKPOWERMODE2             0x98 
#define WIN_DOORLOCK                    0xDE 
#define WIN_DOORUNLOCK                  0xDF 
#define WIN_DSM                         0x06
#define WIN_GETMEDIASTATUS              0xDA 
#define WIN_IDLEIMMEDIATE2              0x95 
#define WIN_MEDIAEJECT                  0xED 
#define WIN_QUEUED_SERVICE              0xA2 
#define WIN_READDMA_ONCE                0xC9 
#define WIN_READDMA_QUEUED              0xC7 
#define WIN_READDMA_QUEUED_EXT          0x26 
#define WIN_READ_ONCE                   0x21 
#define WIN_RECAL                       0x10 
#define WIN_SEEK                        0x70 
#define WIN_SETIDLE2                    0x97 
#define WIN_SET_MAX_EXT                 0x37 
#define WIN_SLEEPNOW2                   0x99 
#define WIN_SPECIFY                     0x91 
#define WIN_STANDBY             	0xE2 
#define WIN_STANDBY2                    0x96 
#define WIN_STANDBYNOW2                 0x94 
#define WIN_VERIFY_ONCE                 0x41 
#define WIN_WRITEDMA_ONCE               0xCB 
#define WIN_WRITE_ONCE                  0x31 
#define WIN_WRITE_VERIFY                0x3C 
#define ide_cmd_is_read(s) \
	((s)->dma_cmd == IDE_DMA_READ)
#define ABORTED_COMMAND     0x0b
#define ACA_ACTIVE           0x30
#define ACCESS_CONTROL_IN     0x86
#define ACCESS_CONTROL_OUT    0x87
#define ALLOW_MEDIUM_REMOVAL  0x1e
#define ALLOW_OVERWRITE       0x82
#define ATA_PASSTHROUGH_12    0xa1
#define ATA_PASSTHROUGH_16    0x85
#define BLANK_CHECK         0x08
#define BUSY                 0x08
#define CD_FRAMES                     75 
#define CD_FRAMESIZE                2048 
#define CD_MAX_BYTES       (CD_MINS * CD_SECS * CD_FRAMES * CD_FRAMESIZE)
#define CD_MAX_SECTORS     (CD_MAX_BYTES / 512)
#define CD_MINS                       80 
#define CD_SECS                       60 
#define CHANGE_DEFINITION     0x40
#define CHECK_CONDITION      0x02
#define COMMAND_TERMINATED   0x22
#define COMPARE               0x39
#define COMPARE_AND_WRITE     0x89
#define CONDITION_GOOD       0x04
#define COPY                  0x18
#define COPY_ABORTED        0x0a
#define COPY_VERIFY           0x3a
#define DATA_PROTECT        0x07
#define ERASE                 0x19
#define ERASE_12              0xac
#define ERASE_16              0x93
#define EXCHANGE_MEDIUM       0xa6
#define EXTENDED_COPY         0x83
#define EXTENDED_FORM        0x08
#define FORMAT_UNIT           0x04
#define GESN_DEVICE_BUSY              6
#define GESN_EXTERNAL_REQUEST         3
#define GESN_MEDIA                    4
#define GESN_MULTIPLE_HOSTS           5
#define GESN_NO_EVENTS                0
#define GESN_OPERATIONAL_CHANGE       1
#define GESN_POWER_MANAGEMENT         2
#define GET_CONFIGURATION     0x46
#define GET_EVENT_STATUS_NOTIFICATION 0x4a
#define GOOD                 0x00
#define HARDWARE_ERROR      0x04
#define HW_SCSI_DEFS_H 1
#define ILLEGAL_REQUEST     0x05
#define INITIALIZE_ELEMENT_STATUS 0x07
#define INITIALIZE_ELEMENT_STATUS_WITH_RANGE 0x37
#define INQUIRY               0x12
#define INTERMEDIATE_C_GOOD  0x14
#define INTERMEDIATE_GOOD    0x10
#define LOAD_UNLOAD           0x1b
#define LOCATE_10             0x2b
#define LOCATE_16             0x92
#define LOCK_UNLOCK_CACHE     0x36
#define LOG_SELECT            0x4c
#define LOG_SENSE             0x4d
#define LONG_FORM            0x06
#define MAINTENANCE_IN        0xa3
#define MAINTENANCE_OUT       0xa4
#define MECHANISM_STATUS      0xbd
#define MEC_BG_FORMAT_COMPLETED       5 
#define MEC_BG_FORMAT_RESTARTED       6 
#define MEC_EJECT_REQUESTED           1
#define MEC_MEDIA_CHANGED             4 
#define MEC_MEDIA_REMOVAL             3 
#define MEC_NEW_MEDIA                 2
#define MEC_NO_CHANGE                 0
#define MEDIUM_ERROR        0x03
#define MEDIUM_SCAN           0x38
#define MISCOMPARE          0x0e
#define MMC_PROFILE_BD_RE               0x0043
#define MMC_PROFILE_BD_ROM              0x0040
#define MMC_PROFILE_BD_R_RRM            0x0042
#define MMC_PROFILE_BD_R_SRM            0x0041
#define MMC_PROFILE_CD_R                0x0009
#define MMC_PROFILE_CD_ROM              0x0008
#define MMC_PROFILE_CD_RW               0x000A
#define MMC_PROFILE_DVD_DDR             0x0018
#define MMC_PROFILE_DVD_PLUS_R          0x001B
#define MMC_PROFILE_DVD_PLUS_RW         0x001A
#define MMC_PROFILE_DVD_PLUS_RW_DL      0x002A
#define MMC_PROFILE_DVD_PLUS_R_DL       0x002B
#define MMC_PROFILE_DVD_RAM             0x0012
#define MMC_PROFILE_DVD_ROM             0x0010
#define MMC_PROFILE_DVD_RW_DL           0x0017
#define MMC_PROFILE_DVD_RW_RO           0x0013
#define MMC_PROFILE_DVD_RW_SR           0x0014
#define MMC_PROFILE_DVD_R_DL_JR         0x0016
#define MMC_PROFILE_DVD_R_DL_SR         0x0015
#define MMC_PROFILE_DVD_R_SR            0x0011
#define MMC_PROFILE_HDDVD_R             0x0051
#define MMC_PROFILE_HDDVD_RAM           0x0052
#define MMC_PROFILE_HDDVD_ROM           0x0050
#define MMC_PROFILE_HDDVD_RW            0x0053
#define MMC_PROFILE_HDDVD_RW_DL         0x005A
#define MMC_PROFILE_HDDVD_R_DL          0x0058
#define MMC_PROFILE_INVALID             0xFFFF
#define MMC_PROFILE_NONE                0x0000
#define MODE_PAGE_ALLS                        0x3f
#define MODE_PAGE_AUDIO_CTL                   0x0e
#define MODE_PAGE_CACHING                     0x08
#define MODE_PAGE_CAPABILITIES                0x2a
#define MODE_PAGE_CDROM                       0x0d
#define MODE_PAGE_FAULT_FAIL                  0x1c
#define MODE_PAGE_FLEXIBLE_DISK_GEOMETRY      0x05
#define MODE_PAGE_HD_GEOMETRY                 0x04
#define MODE_PAGE_POWER                       0x1a
#define MODE_PAGE_R_W_ERROR                   0x01
#define MODE_PAGE_TO_PROTECT                  0x1d
#define MODE_SELECT           0x15
#define MODE_SELECT_10        0x55
#define MODE_SENSE            0x1a
#define MODE_SENSE_10         0x5a
#define MOVE_MEDIUM           0xa5
#define MS_MEDIA_PRESENT              2
#define MS_TRAY_OPEN                  1
#define NOT_READY           0x02
#define NO_SENSE            0x00
#define PERSISTENT_RESERVE_IN 0x5e
#define PERSISTENT_RESERVE_OUT 0x5f
#define POSITION_TO_ELEMENT   0x2b
#define PRE_FETCH             0x34
#define PRE_FETCH_16          0x90
#define READ_10               0x28
#define READ_12               0xa8
#define READ_16               0x88
#define READ_6                0x08
#define READ_BLOCK_LIMITS     0x05
#define READ_BUFFER           0x3c
#define READ_CAPACITY_10      0x25
#define READ_CD               0xbe
#define READ_DEFECT_DATA      0x37
#define READ_DEFECT_DATA_12   0xb7
#define READ_DISC_INFORMATION 0x51
#define READ_DVD_STRUCTURE    0xad
#define READ_ELEMENT_STATUS   0xb8
#define READ_LONG_10          0x3e
#define READ_POSITION         0x34
#define READ_REVERSE          0x0f
#define READ_REVERSE_16       0x81
#define READ_TOC              0x43
#define REASSIGN_BLOCKS       0x07
#define RECEIVE_DIAGNOSTIC    0x1c
#define RECOVERED_ERROR     0x01
#define RECOVER_BUFFERED_DATA 0x14
#define RELEASE               0x17
#define RELEASE_10            0x57
#define REPORT_DENSITY_SUPPORT 0x44
#define REPORT_LUNS           0xa0
#define REQUEST_SENSE         0x03
#define RESERVATION_CONFLICT 0x18
#define RESERVE               0x16
#define RESERVE_10            0x56
#define RESERVE_TRACK         0x53
#define REWIND                0x01
#define SAI_READ_CAPACITY_16  0x10
#define SANITIZE              0x48
#define SEARCH_EQUAL          0x31
#define SEARCH_EQUAL_12       0xb1
#define SEARCH_HIGH           0x30
#define SEARCH_HIGH_12        0xb0
#define SEARCH_LOW            0x32
#define SEARCH_LOW_12         0xb2
#define SEEK_10               0x2b
#define SEND_CUE_SHEET        0x5d
#define SEND_DIAGNOSTIC       0x1d
#define SEND_DVD_STRUCTURE    0xbf
#define SEND_VOLUME_TAG       0xb6
#define SERVICE_ACTION_IN_12  0xab
#define SERVICE_ACTION_IN_16  0x9e
#define SET_CAPACITY          0x0b
#define SET_CD_SPEED          0xbb
#define SET_LIMITS            0x33
#define SET_READ_AHEAD        0xa7
#define SHORT_FORM_BLOCK_ID  0x00
#define SHORT_FORM_VENDOR_SPECIFIC 0x01
#define SPACE                 0x11
#define SPACE_16              0x91
#define START_STOP            0x1b
#define STATUS_MASK          0x3e
#define SYNCHRONIZE_CACHE     0x35
#define SYNCHRONIZE_CACHE_16  0x91
#define TASK_ABORTED         0x40
#define TASK_SET_FULL        0x28
#define TEST_UNIT_READY       0x00
#define TYPE_DISK           0x00
#define TYPE_ENCLOSURE      0x0d    
#define TYPE_INACTIVE       0x20
#define TYPE_MEDIUM_CHANGER 0x08
#define TYPE_MOD            0x07    
#define TYPE_NOT_PRESENT    0x1f
#define TYPE_NO_LUN         0x7f
#define TYPE_OSD            0x11    
#define TYPE_PRINTER        0x02
#define TYPE_PROCESSOR      0x03    
#define TYPE_RBC            0x0e    
#define TYPE_ROM            0x05
#define TYPE_SCANNER        0x06
#define TYPE_STORAGE_ARRAY  0x0c    
#define TYPE_TAPE           0x01
#define TYPE_WLUN           0x1e    
#define TYPE_WORM           0x04    
#define UNIT_ATTENTION      0x06
#define UNMAP                 0x42
#define UPDATE_BLOCK          0x3d
#define VARLENGTH_CDB         0x7f
#define VERIFY_10             0x2f
#define VERIFY_12             0xaf
#define VERIFY_16             0x8f
#define VOLUME_OVERFLOW     0x0d
#define WRITE_10              0x2a
#define WRITE_12              0xaa
#define WRITE_16              0x8a
#define WRITE_6               0x0a
#define WRITE_BUFFER          0x3b
#define WRITE_FILEMARKS       0x10
#define WRITE_FILEMARKS_16    0x80
#define WRITE_LONG_10         0x3f
#define WRITE_LONG_16         0x9f
#define WRITE_SAME_10         0x41
#define WRITE_SAME_16         0x93
#define WRITE_VERIFY_10       0x2e
#define WRITE_VERIFY_12       0xae
#define WRITE_VERIFY_16       0x8e
#define DEFINE_BLOCK_CHS_PROPERTIES(_state, _conf)      \
    DEFINE_PROP_UINT32("cyls", _state, _conf.cyls, 0),  \
    DEFINE_PROP_UINT32("heads", _state, _conf.heads, 0), \
    DEFINE_PROP_UINT32("secs", _state, _conf.secs, 0)
#define DEFINE_BLOCK_PROPERTIES(_state, _conf)                          \
    DEFINE_PROP_DRIVE("drive", _state, _conf.bs),                       \
    DEFINE_PROP_BLOCKSIZE("logical_block_size", _state,                 \
                          _conf.logical_block_size, 512),               \
    DEFINE_PROP_BLOCKSIZE("physical_block_size", _state,                \
                          _conf.physical_block_size, 512),              \
    DEFINE_PROP_UINT16("min_io_size", _state, _conf.min_io_size, 0),  \
    DEFINE_PROP_UINT32("opt_io_size", _state, _conf.opt_io_size, 0),    \
    DEFINE_PROP_INT32("bootindex", _state, _conf.bootindex, -1),        \
    DEFINE_PROP_UINT32("discard_granularity", _state, \
                       _conf.discard_granularity, -1)

#define MAX_CPUMASK_BITS 255
#define MAX_NODES 64
#define MAX_OPTION_ROMS 16
#define MAX_PARALLEL_PORTS 3
#define MAX_PROM_ENVS 128
#define MAX_SERIAL_PORTS 4

#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
#define UUID_NONE "00000000-0000-0000-0000-000000000000"
#define VMRESET_REPORT   true
#define VMRESET_SILENT   false
#define xenfb_enabled (vga_interface_type == VGA_XENFB)
#define QEMU_MAIN_LOOP_H 1
#define SIG_IPI SIGUSR1

