#include<stdio.h>
#include<string.h>
#include<errno.h>
#include<stddef.h>

#define UV_ERRNO_MAP(XX)                                                      \
  XX(E2BIG, "argument list too long")                                         \
  XX(EACCES, "permission denied")                                             \
  XX(EADDRINUSE, "address already in use")                                    \
  XX(EADDRNOTAVAIL, "address not available")                                  \
  XX(EAFNOSUPPORT, "address family not supported")                            \
  XX(EAGAIN, "resource temporarily unavailable")                              \
  XX(EAI_ADDRFAMILY, "address family not supported")                          \
  XX(EAI_AGAIN, "temporary failure")                                          \
  XX(EAI_BADFLAGS, "bad ai_flags value")                                      \
  XX(EAI_BADHINTS, "invalid value for hints")                                 \
  XX(EAI_CANCELED, "request canceled")                                        \
  XX(EAI_FAIL, "permanent failure")                                           \
  XX(EAI_FAMILY, "ai_family not supported")                                   \
  XX(EAI_MEMORY, "out of memory")                                             \
  XX(EAI_NODATA, "no address")                                                \
  XX(EAI_NONAME, "unknown node or service")                                   \
  XX(EAI_OVERFLOW, "argument buffer overflow")                                \
  XX(EAI_PROTOCOL, "resolved protocol is unknown")                            \
  XX(EAI_SERVICE, "service not available for socket type")                    \
  XX(EAI_SOCKTYPE, "socket type not supported")                               \
  XX(EALREADY, "connection already in progress")                              \
  XX(EBADF, "bad file descriptor")                                            \
  XX(EBUSY, "resource busy or locked")                                        \
  XX(ECANCELED, "operation canceled")                                         \
  XX(ECHARSET, "invalid Unicode character")                                   \
  XX(ECONNABORTED, "software caused connection abort")                        \
  XX(ECONNREFUSED, "connection refused")                                      \
  XX(ECONNRESET, "connection reset by peer")                                  \
  XX(EDESTADDRREQ, "destination address required")                            \
  XX(EEXIST, "file already exists")                                           \
  XX(EFAULT, "bad address in system call argument")                           \
  XX(EFBIG, "file too large")                                                 \
  XX(EHOSTUNREACH, "host is unreachable")                                     \
  XX(EINTR, "interrupted system call")                                        \
  XX(EINVAL, "invalid argument")                                              \
  XX(EIO, "i/o error")                                                        \
  XX(EISCONN, "socket is already connected")                                  \
  XX(EISDIR, "illegal operation on a directory")                              \
  XX(ELOOP, "too many symbolic links encountered")                            \
  XX(EMFILE, "too many open files")                                           \
  XX(EMSGSIZE, "message too long")                                            \
  XX(ENAMETOOLONG, "name too long")                                           \
  XX(ENETDOWN, "network is down")                                             \
  XX(ENETUNREACH, "network is unreachable")                                   \
  XX(ENFILE, "file table overflow")                                           \
  XX(ENOBUFS, "no buffer space available")                                    \
  XX(ENODEV, "no such device")                                                \
  XX(ENOENT, "no such file or directory")                                     \
  XX(ENOMEM, "not enough memory")                                             \
  XX(ENONET, "machine is not on the network")                                 \
  XX(ENOPROTOOPT, "protocol not available")                                   \
  XX(ENOSPC, "no space left on device")                                       \
  XX(ENOSYS, "function not implemented")                                      \
  XX(ENOTCONN, "socket is not connected")                                     \
  XX(ENOTDIR, "not a directory")                                              \
  XX(ENOTEMPTY, "directory not empty")                                        \
  XX(ENOTSOCK, "socket operation on non-socket")                              \
  XX(ENOTSUP, "operation not supported on socket")                            \
  XX(EOVERFLOW, "value too large for defined data type")                      \
  XX(EPERM, "operation not permitted")                                        \
  XX(EPIPE, "broken pipe")                                                    \
  XX(EPROTO, "protocol error")                                                \
  XX(EPROTONOSUPPORT, "protocol not supported")                               \
  XX(EPROTOTYPE, "protocol wrong type for socket")                            \
  XX(ERANGE, "result too large")                                              \
  XX(EROFS, "read-only file system")                                          \
  XX(ESHUTDOWN, "cannot send after transport endpoint shutdown")              \
  XX(ESPIPE, "invalid seek")                                                  \
  XX(ESRCH, "no such process")                                                \
  XX(ETIMEDOUT, "connection timed out")                                       \
  XX(ETXTBSY, "text file is busy")                                            \
  XX(EXDEV, "cross-device link not permitted")                                \
  XX(UNKNOWN, "unknown error")                                                \
  XX(EOF, "end of file")                                                      \
  XX(ENXIO, "no such device or address")                                      \
  XX(EMLINK, "too many links")                                                \
  XX(EHOSTDOWN, "host is down")                                               \
  XX(EREMOTEIO, "remote I/O error")                                           \
  XX(ENOTTY, "inappropriate ioctl for device")                                \
  XX(EFTYPE, "inappropriate file type or format")                             \
  XX(EILSEQ, "illegal byte sequence")                                         \
  XX(ESOCKTNOSUPPORT, "socket type not supported")                            \

#   define UV_EXTERN __declspec(dllexport)
#define UV_FS_COPYFILE_EXCL   0x0001
#define UV_FS_COPYFILE_FICLONE 0x0002
#define UV_FS_COPYFILE_FICLONE_FORCE 0x0004
#define UV_FS_SYMLINK_DIR          0x0001
#define UV_FS_SYMLINK_JUNCTION     0x0002

#define UV_HANDLE_FIELDS                                                      \
                                                                  \
  void* data;                                                                 \
                                                               \
  uv_loop_t* loop;                                                            \
  uv_handle_type type;                                                        \
                                                                 \
  uv_close_cb close_cb;                                                       \
  void* handle_queue[2];                                                      \
  union {                                                                     \
    int fd;                                                                   \
    void* reserved[4];                                                        \
  } u;                                                                        \
  UV_HANDLE_PRIVATE_FIELDS                                                    \

#define UV_HANDLE_TYPE_MAP(XX)                                                \
  XX(ASYNC, async)                                                            \
  XX(CHECK, check)                                                            \
  XX(FS_EVENT, fs_event)                                                      \
  XX(FS_POLL, fs_poll)                                                        \
  XX(HANDLE, handle)                                                          \
  XX(IDLE, idle)                                                              \
  XX(NAMED_PIPE, pipe)                                                        \
  XX(POLL, poll)                                                              \
  XX(PREPARE, prepare)                                                        \
  XX(PROCESS, process)                                                        \
  XX(STREAM, stream)                                                          \
  XX(TCP, tcp)                                                                \
  XX(TIMER, timer)                                                            \
  XX(TTY, tty)                                                                \
  XX(UDP, udp)                                                                \
  XX(SIGNAL, signal)                                                          \

# define UV_IF_NAMESIZE (IF_NAMESIZE + 1)
# define UV_MAXHOSTNAMESIZE (MAXHOSTNAMELEN + 1)
# define UV_PRIORITY_ABOVE_NORMAL -4 
# define UV_PRIORITY_BELOW_NORMAL 15 
# define UV_PRIORITY_HIGH -7         
# define UV_PRIORITY_HIGHEST -10     
# define UV_PRIORITY_LOW 39          
# define UV_PRIORITY_NORMAL 0        
#define UV_REQ_FIELDS                                                         \
                                                                  \
  void* data;                                                                 \
                                                               \
  uv_req_type type;                                                           \
                                                                 \
  void* reserved[6];                                                          \
  UV_REQ_PRIVATE_FIELDS                                                       \

#define UV_REQ_TYPE_MAP(XX)                                                   \
  XX(REQ, req)                                                                \
  XX(CONNECT, connect)                                                        \
  XX(WRITE, write)                                                            \
  XX(SHUTDOWN, shutdown)                                                      \
  XX(UDP_SEND, udp_send)                                                      \
  XX(FS, fs)                                                                  \
  XX(WORK, work)                                                              \
  XX(GETADDRINFO, getaddrinfo)                                                \
  XX(GETNAMEINFO, getnameinfo)                                                \
  XX(RANDOM, random)                                                          \

#define UV_STREAM_FIELDS                                                      \
                                      \
  size_t write_queue_size;                                                    \
  uv_alloc_cb alloc_cb;                                                       \
  uv_read_cb read_cb;                                                         \
                                                                 \
  UV_STREAM_PRIVATE_FIELDS
#define XX(_, name) uv_ ## name ## _t name;

#define UV_VERSION_HEX  ((UV_VERSION_MAJOR << 16) | \
                         (UV_VERSION_MINOR <<  8) | \
                         (UV_VERSION_PATCH))
#define UV_VERSION_IS_RELEASE 0
#define UV_VERSION_MAJOR 1
#define UV_VERSION_MINOR 41
#define UV_VERSION_PATCH 1
#define UV_VERSION_SUFFIX "dev"

# define UV__E2BIG UV__ERR(E2BIG)
# define UV__EACCES UV__ERR(EACCES)
# define UV__EADDRINUSE UV__ERR(EADDRINUSE)
# define UV__EADDRNOTAVAIL UV__ERR(EADDRNOTAVAIL)
# define UV__EAFNOSUPPORT UV__ERR(EAFNOSUPPORT)
# define UV__EAGAIN UV__ERR(EAGAIN)
#define UV__EAI_ADDRFAMILY  (-3000)
#define UV__EAI_AGAIN       (-3001)
#define UV__EAI_BADFLAGS    (-3002)
#define UV__EAI_BADHINTS    (-3013)
#define UV__EAI_CANCELED    (-3003)
#define UV__EAI_FAIL        (-3004)
#define UV__EAI_FAMILY      (-3005)
#define UV__EAI_MEMORY      (-3006)
#define UV__EAI_NODATA      (-3007)
#define UV__EAI_NONAME      (-3008)
#define UV__EAI_OVERFLOW    (-3009)
#define UV__EAI_PROTOCOL    (-3014)
#define UV__EAI_SERVICE     (-3010)
#define UV__EAI_SOCKTYPE    (-3011)
# define UV__EALREADY UV__ERR(EALREADY)
# define UV__EBADF UV__ERR(EBADF)
# define UV__EBUSY UV__ERR(EBUSY)
# define UV__ECANCELED UV__ERR(ECANCELED)
# define UV__ECHARSET UV__ERR(ECHARSET)
# define UV__ECONNABORTED UV__ERR(ECONNABORTED)
# define UV__ECONNREFUSED UV__ERR(ECONNREFUSED)
# define UV__ECONNRESET UV__ERR(ECONNRESET)
# define UV__EDESTADDRREQ UV__ERR(EDESTADDRREQ)
# define UV__EEXIST UV__ERR(EEXIST)
# define UV__EFAULT UV__ERR(EFAULT)
# define UV__EFBIG UV__ERR(EFBIG)
# define UV__EFTYPE UV__ERR(EFTYPE)
# define UV__EHOSTDOWN UV__ERR(EHOSTDOWN)
# define UV__EHOSTUNREACH UV__ERR(EHOSTUNREACH)
# define UV__EILSEQ UV__ERR(EILSEQ)
# define UV__EINTR UV__ERR(EINTR)
# define UV__EINVAL UV__ERR(EINVAL)
# define UV__EIO UV__ERR(EIO)
# define UV__EISCONN UV__ERR(EISCONN)
# define UV__EISDIR UV__ERR(EISDIR)
# define UV__ELOOP UV__ERR(ELOOP)
# define UV__EMFILE UV__ERR(EMFILE)
# define UV__EMLINK UV__ERR(EMLINK)
# define UV__EMSGSIZE UV__ERR(EMSGSIZE)
# define UV__ENAMETOOLONG UV__ERR(ENAMETOOLONG)
# define UV__ENETDOWN UV__ERR(ENETDOWN)
# define UV__ENETUNREACH UV__ERR(ENETUNREACH)
# define UV__ENFILE UV__ERR(ENFILE)
# define UV__ENOBUFS UV__ERR(ENOBUFS)
# define UV__ENODEV UV__ERR(ENODEV)
# define UV__ENOENT UV__ERR(ENOENT)
# define UV__ENOMEM UV__ERR(ENOMEM)
# define UV__ENONET UV__ERR(ENONET)
# define UV__ENOPROTOOPT UV__ERR(ENOPROTOOPT)
# define UV__ENOSPC UV__ERR(ENOSPC)
# define UV__ENOSYS UV__ERR(ENOSYS)
# define UV__ENOTCONN UV__ERR(ENOTCONN)
# define UV__ENOTDIR UV__ERR(ENOTDIR)
# define UV__ENOTEMPTY UV__ERR(ENOTEMPTY)
# define UV__ENOTSOCK UV__ERR(ENOTSOCK)
# define UV__ENOTSUP UV__ERR(ENOTSUP)
# define UV__ENOTTY UV__ERR(ENOTTY)
# define UV__ENXIO UV__ERR(ENXIO)
#define UV__EOF     (-4095)
# define UV__EOVERFLOW UV__ERR(EOVERFLOW)
# define UV__EPERM UV__ERR(EPERM)
# define UV__EPIPE UV__ERR(EPIPE)
# define UV__EPROTO UV__ERR(EPROTO)
# define UV__EPROTONOSUPPORT UV__ERR(EPROTONOSUPPORT)
# define UV__EPROTOTYPE UV__ERR(EPROTOTYPE)
# define UV__ERANGE UV__ERR(ERANGE)
# define UV__EREMOTEIO UV__ERR(EREMOTEIO)
# define UV__EROFS UV__ERR(EROFS)
# define UV__ERR(x) (-(x))
# define UV__ESHUTDOWN UV__ERR(ESHUTDOWN)
# define UV__ESOCKTNOSUPPORT UV__ERR(ESOCKTNOSUPPORT)
# define UV__ESPIPE UV__ERR(ESPIPE)
# define UV__ESRCH UV__ERR(ESRCH)
# define UV__ETIMEDOUT UV__ERR(ETIMEDOUT)
# define UV__ETXTBSY UV__ERR(ETXTBSY)
# define UV__EXDEV UV__ERR(EXDEV)
#define UV__UNKNOWN (-4094)
