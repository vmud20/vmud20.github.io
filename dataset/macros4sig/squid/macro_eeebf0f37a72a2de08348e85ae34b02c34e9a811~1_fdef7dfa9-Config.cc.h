


#include<cstring>
#include<csignal>
#include<sstream>
#include<unordered_map>


#include<climits>









#include<strings.h>


#include<vector>

#include<iosfwd>


#include<stdio.h>
#include<random>


#include<sys/select.h>

#include<stack>

#include<sys/resource.h>
#include<arpa/inet.h>





#include<functional>


#include<string>






#include<sys/vfs.h>









#include<ostream>
#include<memory>


#include<netdb.h>


#include<algorithm>
#include<cstdarg>


#include<iostream>
#include<queue>



#include<regex.h>
#include<sys/time.h>
#include<paths.h>







#include<sys/bitypes.h>
#include<sys/socket.h>




#include<malloc.h>


#include<stdexcept>

#include<inttypes.h>



#include<dirent.h>
#include<netinet/in.h>


#include<signal.h>
#include<features.h>
#include<sys/un.h>
#include<fcntl.h>
#include<numeric>
#include<list>

#include<bits/types.h>
#include<errno.h>
#include<stdint.h>
#include<time.h>

#include<sys/dir.h>
#include<cstdio>


#include<sys/statfs.h>
#include<string.h>
#include<sys/stat.h>
#include<cstdint>



#include<iterator>

#include<sys/mount.h>
#include<ctype.h>


#include<unistd.h>

#include<linux/types.h>

#include<stdarg.h>







#include<map>



#include<varargs.h>
#include<sys/statvfs.h>
#include<netinet/ip.h>

#include<syslog.h>


#include<tr1/random>



#include<ctime>
#include<stdlib.h>





#include<initializer_list>
#include<stddef.h>
#include<iomanip>
#include<sys/types.h>

#include<linux/posix_types.h>

#include<unordered_set>
#include<sys/param.h>
#include<wchar.h>
#include<netinet/in_systm.h>





#include<memory.h>




#define MEM_MAX_FREE  65535 
#define MEM_MIN_FREE  32
#define MEM_PAGE_SIZE 4096
#define M_MMAP_MAX -4

#define memPoolCreate MemPools::GetInstance().create
#define toKB(size) ( (size + 1024 - 1) / 1024 )
#define toMB(size) ( ((double) size) / ((double)(1024*1024)) )

#define gb_flush_limit (0x3FFFFFFF)
#define gb_inc(gb, delta) { if ((gb)->bytes > gb_flush_limit || delta > gb_flush_limit) gb_flush(gb); (gb)->bytes += delta; (gb)->count++; }
#define gb_incb(gb, delta) { if ((gb)->bytes > gb_flush_limit || delta > gb_flush_limit) gb_flush(gb); (gb)->bytes += delta; }
#define gb_incc(gb, delta) { if ((gb)->bytes > gb_flush_limit || delta > gb_flush_limit) gb_flush(gb); (gb)->count+= delta; }


#define   SQUID_TIME_H



#define SQUIDSBUFPH "%.*s"
#define SQUIDSBUFPRINT(s) (s).plength(),(s).rawContent()


#define MEMBLOB_DEBUGSECTION 24


#define MEMPROXY_CLASS(CLASS) \
    private: \
    static inline Mem::AllocatorProxy &Pool() { \
        static Mem::AllocatorProxy thePool(#CLASS, sizeof(CLASS), false); \
        return thePool; \
    } \
    public: \
    void *operator new(size_t byteCount) { \
         \
        assert(byteCount == sizeof(CLASS)); \
        return Pool().alloc(); \
    } \
    void operator delete(void *address) { \
        if (address) \
            Pool().freeOne(address); \
    } \
    static int UseCount() { return Pool().inUseCount(); } \
    private:


#define RefCountable virtual Lock

#define InstanceIdDefinitions(Class, pfx) \
    template<> const char * const \
    InstanceId<Class>::prefix() const { \
        return pfx; \
    } \
    template<> std::ostream & \
    InstanceId<Class>::print(std::ostream &os) const { \
        return os << pfx << value; \
    } \
    template<> void \
    InstanceId<Class>::change() { \
        static InstanceId<Class>::Value Last = 0; \
        value = ++Last ? Last : ++Last; \
    }



#define RFC2181_MAXHOSTNAMELEN  256
#define SQUIDHOSTNAMELEN    RFC2181_MAXHOSTNAMELEN


#define  DEFAULT_HASH_SIZE 7951 

#define ACL_ALLWEEK 0x7F
#define ACL_FRIDAY  0x20
#define ACL_MONDAY  0x02
#define ACL_SATURDAY    0x40
#define ACL_SUNDAY  0x01
#define ACL_THURSDAY    0x10
#define ACL_TUESDAY 0x04
#define ACL_WEDNESDAY   0x08
#define ACL_WEEKDAYS    0x3E
#define ANONYMIZER_NONE     0
#define ANONYMIZER_PARANOID 2
#define ANONYMIZER_STANDARD 1
#define AUTHENTICATE_AV_FACTOR 1000
#define AUTH_MSG_SZ 4096
#define BROWSERNAMELEN 128
#define BUFSIZ  4096            
#define BUF_TYPE_8K     1
#define BUF_TYPE_MALLOC 2
#define CBIT_BIN(mask, bit)     (mask)[(bit)>>3]
#define CBIT_BIT(bit)           (1<<((bit)%8))
#define CBIT_CLR(mask, bit)     ((void)(CBIT_BIN(mask, bit) &= ~CBIT_BIT(bit)))
#define CBIT_SET(mask, bit)     ((void)(CBIT_BIN(mask, bit) |= CBIT_BIT(bit)))
#define CBIT_TEST(mask, bit)    (CBIT_BIN(mask, bit) & CBIT_BIT(bit))
#define CLIENT_REQ_BUF_SZ 4096
#define COMM_SELECT_READ   (0x1)
#define COMM_SELECT_WRITE  (0x2)
#define COUNT_INTERVAL 60
#define DIRECT_MAYBE 2
#define DIRECT_NO    1
#define DIRECT_UNKNOWN 0
#define DIRECT_YES   3
#define DISK_EOF                 (-2)
#define DISK_ERROR               (-1)
#define DISK_NO_SPACE_LEFT       (-6)
#define DISK_OK                   (0)
#define DNS_INBUF_SZ 4096
#define EBIT_CLR(flag, bit)     ((void)((flag) &= ~((1L<<(bit)))))
#define EBIT_SET(flag, bit)     ((void)((flag) |= ((1L<<(bit)))))
#define EBIT_TEST(flag, bit)    ((flag) & ((1L<<(bit))))
#define ERROR_BUF_SZ (MAX_URL << 2)
#define FALSE 0
#define FD_DESC_SZ      64
#define FILE_MODE(x) ((x)&O_ACCMODE)
#define FQDN_LOOKUP_IF_MISS 0x01
#define FQDN_MAX_NAMES 5
#define HIER_MAX_DEFICIT  20
#define HTTP_REPLY_BUF_SZ 4096
#define HTTP_REPLY_FIELD_SZ 128
#define HTTP_REQBUF_SZ  4096
#define ICP_FLAG_HIT_OBJ     0x80000000ul
#define ICP_FLAG_SRC_RTT     0x40000000ul
#define ICP_VERSION_2       2
#define ICP_VERSION_3       3
#define ICP_VERSION_CURRENT ICP_VERSION_2
#define IDENT_DONE 2
#define IDENT_NONE 0
#define IDENT_PENDING 1
#define IPC_DGRAM IPC_UNIX_DGRAM
#define IPC_FIFO 3
#define IPC_NONE 0
#define IPC_STREAM IPC_UNIX_STREAM
#define IPC_TCP_SOCKET 1
#define IPC_UDP_SOCKET 2
#define IPC_UNIX_DGRAM 5
#define IPC_UNIX_STREAM 4
#define IP_LOOKUP_IF_MISS   0x01
#define LOG_DISABLE 0
#define LOG_ENABLE  1
#define MAX_CLIENT_BUF_SZ 4096
#define MAX_FILES_PER_DIR (1<<20)
#define MAX_LOGIN_SZ  128
#define MAX_MIME 4096
#define MAX_URL  8192
#define NTLM_CHALLENGE_SZ 300
#define N_COUNT_HIST (3600 / COUNT_INTERVAL) + 1
#define N_COUNT_HOUR_HIST (86400 * 3) / (60 * COUNT_INTERVAL)
#define O_BINARY 0
#define O_TEXT 0
#define PEER_ALIVE 1
#define PEER_DEAD 0
#define PEER_MAX_ADDRESSES 10
#define PEER_TCP_MAGIC_COUNT 10
#define REDIRECT_AV_FACTOR 1000
#define REDIRECT_DONE 2
#define REDIRECT_NONE 0
#define REDIRECT_PENDING 1
#define RTT_AV_FACTOR      50
#define RTT_BACKGROUND_AV_FACTOR      25    
#define SM_PAGE_SIZE 4096

#define STORE_HDR_METASIZE (4*sizeof(time_t)+2*sizeof(uint16_t)+sizeof(uint64_t))
#define STORE_HDR_METASIZE_OLD (4*sizeof(time_t)+2*sizeof(uint16_t)+sizeof(size_t))
#define STORE_META_BAD    0x05
#define STORE_META_DIRTY  0x04
#define STORE_META_KEY STORE_META_KEY_MD5
#define STORE_META_OK     0x03
#define STORE_META_TLD_SIZE STORE_META_TLD_START
#define STORE_META_TLD_START sizeof(int)+sizeof(char)
#define SwapMetaData(x) &x[STORE_META_TLD_START]
#define SwapMetaSize(x) &x[sizeof(char)]
#define SwapMetaType(x) (char)x[0]
#define TRUE 1
#define URI_WHITESPACE_ALLOW 1
#define URI_WHITESPACE_CHOP 3
#define URI_WHITESPACE_DENY 4
#define URI_WHITESPACE_ENCODE 2
#define URI_WHITESPACE_STRIP 0
#define USER_IDENT_SZ 64
#define VIEWEXCLUDED    2
#define VIEWINCLUDED    1
#define _WIN_SQUID_RUN_MODE_INTERACTIVE     0
#define _WIN_SQUID_RUN_MODE_SERVICE     1
#define _WIN_SQUID_SERVICE_CONTROL_DEBUG    130
#define _WIN_SQUID_SERVICE_CONTROL_INTERROGATE SERVICE_CONTROL_INTERROGATE
#define _WIN_SQUID_SERVICE_CONTROL_INTERRUPT    131
#define _WIN_SQUID_SERVICE_CONTROL_RECONFIGURE  129
#define _WIN_SQUID_SERVICE_CONTROL_ROTATE   128
#define _WIN_SQUID_SERVICE_CONTROL_SHUTDOWN SERVICE_CONTROL_SHUTDOWN
#define _WIN_SQUID_SERVICE_CONTROL_STOP SERVICE_CONTROL_STOP
#define _WIN_SQUID_SERVICE_OPTION       "--ntservice"
#define countof(arr) (sizeof(arr)/sizeof(*arr))
#define current_stacksize(stack) ((stack)->top - (stack)->base)



#define DBG_CRITICAL    0   
#define DBG_DATA    9   
#define DBG_IMPORTANT   1   
#define DBG_PARSE_NOTE(x) (opt_parse_cfg_only?0:(x)) 
#define MAX_DEBUG_SECTIONS 100
#define MYNAME __PRETTY_FUNCTION__ << " "

#define assert(EX) ((void)0)
#define debug_log DebugStream()
#define debugs(SECTION, LEVEL, CONTENT) \
   do { \
        const int _dbg_level = (LEVEL); \
        if (Debug::Enabled((SECTION), _dbg_level)) { \
            std::ostream &_dbo = Debug::Start((SECTION), _dbg_level); \
            if (_dbg_level > DBG_IMPORTANT) { \
                _dbo << (SECTION) << ',' << _dbg_level << "| " \
                     << Here() << ": "; \
            } \
            _dbo << CONTENT; \
            Debug::Finish(); \
        } \
   } while ( 0)
#define Here() SourceLocation(__FUNCTION__, "__FILE__", "__LINE__")

#define Must(condition) Must2((condition), "check failed: " #condition)
#define Must2(condition, message) \
    do { \
        if (!(condition)) { \
            const TextException Must_ex_((message), Here()); \
            debugs(0, 3, Must_ex_.what()); \
            throw Must_ex_; \
        } \
    } while ( false)

#define SWALLOW_EXCEPTIONS(code) \
    try { \
        code \
    } catch (...) { \
        debugs(0, DBG_IMPORTANT, "BUG: ignoring exception;\n" << \
               "    bug location: " << Here() << "\n" << \
               "    ignored exception: " << CurrentException); \
    }
#define TexcHere(msg) TextException((msg), Here())




#define SQUIDSTRINGPH "%.*s"
#define SQUIDSTRINGPRINT(s) (s).psize(),(s).rawBuf()

#define CBDATA_CHILD(type) CBDATA_DECL_(type, override final)
#define CBDATA_CLASS(type) CBDATA_DECL_(type, noexcept)
#define CBDATA_CLASS_INIT(type) cbdata_type type::CBDATA_##type = CBDATA_UNKNOWN
#define CBDATA_DECL_(type, methodSpecifiers) \
    public: \
        void *operator new(size_t size) { \
          assert(size == sizeof(type)); \
          if (!CBDATA_##type) CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type)); \
          return (type *)cbdataInternalAlloc(CBDATA_##type,"__FILE__","__LINE__"); \
        } \
        void operator delete (void *address) { \
          if (address) cbdataInternalFree(address,"__FILE__","__LINE__"); \
        } \
        void *toCbdata() methodSpecifiers { return this; } \
    private: \
       static cbdata_type CBDATA_##type;
#define CBDATA_NAMESPACED_CLASS_INIT(namespace, type) cbdata_type namespace::type::CBDATA_##type = CBDATA_UNKNOWN

#define cbdataInternalLock(a) cbdataInternalLockDbg(a,"__FILE__","__LINE__")
#define cbdataInternalUnlock(a) cbdataInternalUnlockDbg(a,"__FILE__","__LINE__")
#define cbdataReference(var)    (cbdataInternalLock(var), var)
#define cbdataReferenceDone(var) do {if (var) {cbdataInternalUnlock(var); var = NULL;}} while(0)
#define cbdataReferenceValidDone(var, ptr) cbdataInternalReferenceDoneValidDbg((void **)&(var), (ptr), "__FILE__","__LINE__")











#define   SQUID_REMOVALPOLICY_H















#define MAXTCPLISTENPORTS 128



#define OPENSSL_LH_delete lh_delete
#define OPENSSL_LH_strhash lh_strhash
#define OPENSSL_VERSION SSLEAY_VERSION
#define OpenSSL_version SSLeay_version
#define TLS_client_method SSLv23_client_method
#define TLS_server_method SSLv23_server_method
#define X509_STORE_CTX_set0_untrusted X509_STORE_CTX_set_chain
#define X509_getm_notAfter X509_get_notAfter
#define X509_getm_notBefore X509_get_notBefore
#define X509_set1_notAfter X509_set_notAfter
#define X509_set1_notBefore X509_set_notBefore

#define dump_securePeerOptions(e,n,x) do { (e)->appendf(n); (x).dumpCfg((e),""); (e)->append("\n",1); } while(false)
#define free_securePeerOptions(x) Security::ProxyOutgoingConfig.clear()


#define SSL_FLAG_DELAYED_AUTH       (1<<1)
#define SSL_FLAG_DONT_VERIFY_DOMAIN (1<<3)
#define SSL_FLAG_DONT_VERIFY_PEER   (1<<2)
#define SSL_FLAG_NO_DEFAULT_CA      (1<<0)
#define SSL_FLAG_NO_SESSION_REUSE   (1<<4)
#define SSL_FLAG_VERIFY_CRL         (1<<5)
#define SSL_FLAG_VERIFY_CRL_ALL     (1<<6)
#define sk_dtor_wrapper(sk_object, argument_type, freefunction) \
        struct sk_object ## _free_wrapper { \
            void operator()(argument_type a) { sk_object ## _pop_free(a, freefunction); } \
        }

#define CtoCpp1(function, argument) \
        extern "C++" inline void function ## _cpp(argument a) { \
            function(a); \
        }

#define sk_free_wrapper(sk_object, argument, freefunction) \
        extern "C++" inline void sk_object ## _free_wrapper(argument a) { \
            sk_object ## _pop_free(a, freefunction); \
        }




#define CONFIG_LINE_LIMIT   2048


#define COMM_DOBIND             0x08  
#define COMM_INTERCEPTION       0x20  
#define COMM_NOCLOEXEC          0x02
#define COMM_NONBLOCKING        0x01  
#define COMM_REUSEADDR          0x04  
#define COMM_TRANSPARENT        0x10  
#define COMM_UNSET              0x00

#define MAX_IPSTRLEN  75



#define SZ_EUI64_BUF EUI64_LEN

#define SZ_EUI48_BUF 6




#define CallJobHere(debugSection, debugLevel, job, Class, method) \
    CallJob((debugSection), (debugLevel), "__FILE__", "__LINE__", \
        (#Class "::" #method), \
        JobMemFun<Class>((job), &Class::method))
#define CallJobHere1(debugSection, debugLevel, job, Class, method, arg1) \
    CallJob((debugSection), (debugLevel), "__FILE__", "__LINE__", \
        (#Class "::" #method), \
        JobMemFun((job), &Class::method, (arg1)))
#define JobCallback(dbgSection, dbgLevel, Dialer, job, method) \
    asyncCall((dbgSection), (dbgLevel), #method, \
        Dialer(CbcPointer<Dialer::DestClass>(job), &method))




#define ScheduleCallHere(call) ScheduleCall("__FILE__", "__LINE__", (call))



#define comm_close(x) (_comm_close((x), "__FILE__", "__LINE__"))
#define COMMIO_FD_READCB(fd)    (&Comm::iocb_table[(fd)].readcb)
#define COMMIO_FD_WRITECB(fd)   (&Comm::iocb_table[(fd)].writecb)








#define ACLList Acl::Tree
#define ACL_NAME_SZ 64

#define acl_access Acl::Tree
#define HttpHeaderInitPos (-1)






#define MAX_AUTHTOKEN_LEN   65535









#define SQUID_SSL_SIGN_HASH_IF_NONE "sha256"











#define HTTPMSGLOCK(a) if (a) { (a)->lock(); }
#define HTTPMSGUNLOCK(a) if (a) { if ((a)->unlock() == 0) delete (a); (a)=NULL; }










#define HASHHEXLEN 32
#define HASHLEN 16



#define SQUID_MD5_DIGEST_LENGTH MD5_DIGEST_SIZE

#define SquidMD5Final(d,c)    md5_digest((c), MD5_DIGEST_SIZE, (uint8_t *)(d))
#define SquidMD5Init(c)       md5_init((c))
#define SquidMD5Update(c,b,l) md5_update((c), (l), (const uint8_t *)(b))






#define dump_HelperChildConfig(e,n,c)  storeAppendPrintf((e), "\n%s %d startup=%d idle=%d concurrency=%d\n", (n), (c).n_max, (c).n_startup, (c).n_idle, (c).concurrency)
#define free_HelperChildConfig(dummy)  
#define parse_HelperChildConfig(c)     (c)->parseConfig()






#define QOP_AUTH "auth"



#define CACHEMGR_HOSTNAME ""
#define CACHEMGR_HOSTNAME_DEFINED 1
#define CACHE_HTTP_PORT 3128
#define CACHE_ICP_PORT 3130
#define LEAK_CHECK_MODE 1
#define SQUIDCEXTERN extern "C"

#define SQUID_MAXPATHLEN 256
#define SQUID_UDP_SO_RCVBUF 16384
#define SQUID_UDP_SO_SNDBUF 16384
#define USE_RE_SYNTAX   REG_EXTENDED    
#define _SQUID_INLINE_ inline
#define LOCAL_ARRAY(type,name,size) \
        static type *local_##name=NULL; \
        type *name = local_##name ? local_##name : \
                ( local_##name = (type *)xcalloc(size, sizeof(type)) )



#define minor_t solaris_minor_t_fubar
#define CPPUNIT_TEST_SUITE_END()                                               \
    }                                                                          \
                                                                               \
    static CPPUNIT_NS::TestSuite *suite()                                      \
    {                                                                          \
      const CPPUNIT_NS::TestNamer &namer = getTestNamer__();                   \
      std::unique_ptr<CPPUNIT_NS::TestSuite> suite(                            \
             new CPPUNIT_NS::TestSuite( namer.getFixtureName() ));             \
      CPPUNIT_NS::ConcretTestFixtureFactory<TestFixtureType> factory;          \
      CPPUNIT_NS::TestSuiteBuilderContextBase context( *suite.get(),           \
                                                       namer,                  \
                                                       factory );              \
      TestFixtureType::addTestsToSuite( context );                             \
      return suite.release();                                                  \
    }                                                                          \
  private:          \
    typedef int CppUnitDummyTypedefForSemiColonEnding__

#define REGS_FIXED 2
#define REGS_REALLOCATE 1
#define REGS_UNALLOCATED 0
#define REG_EXTENDED 1
#define REG_ICASE (REG_EXTENDED << 1)
#define REG_NEWLINE (REG_ICASE << 1)
#define REG_NOSUB (REG_NEWLINE << 1)
#define REG_NOTBOL 1
#define REG_NOTEOL (1 << 1)
#define RE_BACKSLASH_ESCAPE_IN_LISTS (1)
#define RE_BK_PLUS_QM (RE_BACKSLASH_ESCAPE_IN_LISTS << 1)
#define RE_CHAR_CLASSES (RE_BK_PLUS_QM << 1)
#define RE_CONTEXT_INDEP_ANCHORS (RE_CHAR_CLASSES << 1)
#define RE_CONTEXT_INDEP_OPS (RE_CONTEXT_INDEP_ANCHORS << 1)
#define RE_CONTEXT_INVALID_OPS (RE_CONTEXT_INDEP_OPS << 1)
#define RE_DOT_NEWLINE (RE_CONTEXT_INVALID_OPS << 1)
#define RE_DOT_NOT_NULL (RE_DOT_NEWLINE << 1)
#define RE_DUP_MAX ((1 << 15) - 1)
#define RE_EXACTN_VALUE 1
#define RE_HAT_LISTS_NOT_NEWLINE (RE_DOT_NOT_NULL << 1)
#define RE_INTERVALS (RE_HAT_LISTS_NOT_NEWLINE << 1)
#define RE_LIMITED_OPS (RE_INTERVALS << 1)
#define RE_NEWLINE_ALT (RE_LIMITED_OPS << 1)
#define RE_NO_BK_BRACES (RE_NEWLINE_ALT << 1)
#define RE_NO_BK_PARENS (RE_NO_BK_BRACES << 1)
#define RE_NO_BK_REFS (RE_NO_BK_PARENS << 1)
#define RE_NO_BK_VBAR (RE_NO_BK_REFS << 1)
#define RE_NO_EMPTY_RANGES (RE_NO_BK_VBAR << 1)
#define RE_NREGS 30
#define RE_SYNTAX_AWK                           \
  (RE_BACKSLASH_ESCAPE_IN_LISTS | RE_DOT_NOT_NULL           \
   | RE_NO_BK_PARENS            | RE_NO_BK_REFS             \
   | RE_NO_BK_VBAR               | RE_NO_EMPTY_RANGES           \
   | RE_UNMATCHED_RIGHT_PAREN_ORD)
#define RE_SYNTAX_ED RE_SYNTAX_POSIX_BASIC
#define RE_SYNTAX_EGREP                         \
  (RE_CHAR_CLASSES        | RE_CONTEXT_INDEP_ANCHORS            \
   | RE_CONTEXT_INDEP_OPS | RE_HAT_LISTS_NOT_NEWLINE            \
   | RE_NEWLINE_ALT       | RE_NO_BK_PARENS             \
   | RE_NO_BK_VBAR)
#define RE_SYNTAX_EMACS 0
#define RE_SYNTAX_GREP                          \
  (RE_BK_PLUS_QM              | RE_CHAR_CLASSES             \
   | RE_HAT_LISTS_NOT_NEWLINE | RE_INTERVALS                \
   | RE_NEWLINE_ALT)
#define RE_SYNTAX_POSIX_AWK                         \
  (RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS)
#define RE_SYNTAX_POSIX_BASIC                       \
  (_RE_SYNTAX_POSIX_COMMON | RE_BK_PLUS_QM)
#define RE_SYNTAX_POSIX_EGREP                       \
  (RE_SYNTAX_EGREP | RE_INTERVALS | RE_NO_BK_BRACES)
#define RE_SYNTAX_POSIX_EXTENDED                    \
  (_RE_SYNTAX_POSIX_COMMON | RE_CONTEXT_INDEP_ANCHORS           \
   | RE_CONTEXT_INDEP_OPS  | RE_NO_BK_BRACES                \
   | RE_NO_BK_PARENS       | RE_NO_BK_VBAR              \
   | RE_UNMATCHED_RIGHT_PAREN_ORD)
#define RE_SYNTAX_POSIX_MINIMAL_BASIC                   \
  (_RE_SYNTAX_POSIX_COMMON | RE_LIMITED_OPS)
#define RE_SYNTAX_POSIX_MINIMAL_EXTENDED                \
  (_RE_SYNTAX_POSIX_COMMON  | RE_CONTEXT_INDEP_ANCHORS          \
   | RE_CONTEXT_INVALID_OPS | RE_NO_BK_BRACES               \
   | RE_NO_BK_PARENS        | RE_NO_BK_REFS             \
   | RE_NO_BK_VBAR      | RE_UNMATCHED_RIGHT_PAREN_ORD)
#define RE_SYNTAX_SED RE_SYNTAX_POSIX_BASIC
#define RE_UNMATCHED_RIGHT_PAREN_ORD (RE_NO_EMPTY_RANGES << 1)

#define _RE_SYNTAX_POSIX_COMMON                     \
  (RE_CHAR_CLASSES | RE_DOT_NEWLINE      | RE_DOT_NOT_NULL      \
   | RE_INTERVALS  | RE_NO_EMPTY_RANGES)
# define RUNNING_ON_VALGRIND 0

#  define VALGRIND_CHECK_MEM_IS_ADDRESSABLE VALGRIND_CHECK_WRITABLE
# define VALGRIND_CHECK_MEM_IS_DEFINED(a,b) (0)
# define VALGRIND_FREELIKE_BLOCK(a,b)
#  define VALGRIND_MAKE_MEM_DEFINED VALGRIND_MAKE_READABLE
#  define VALGRIND_MAKE_MEM_NOACCESS VALGRIND_MAKE_NOACCESS
#  define VALGRIND_MAKE_MEM_UNDEFINED VALGRIND_MAKE_WRITABLE
# define VALGRIND_MALLOCLIKE_BLOCK(a,b,c,d)

#define debug(X...) \
                     if (debug_enabled) { \
                         fprintf(stderr, "%s(%d): pid=%ld :", "__FILE__", "__LINE__", static_cast<long>(getpid())); \
                         fprintf(stderr,X); \
                     } else (void)0
#define ndebug(content) ndebug_("__FILE__", "__LINE__", content)
#define ndebug_(file, line, content) if (debug_enabled) { \
    std::cerr << file << '(' << line << ')' << ": pid=" << getpid() << ':' \
        << content << std::endl; \
    } else (void)0

#define xstatvfs statvfs
#define MAXPATHLEN SQUID_MAXPATHLEN

#define HAVE_STDARGS            
#define VA_END va_end(ap)
#define VA_LOCAL_DECL va_list ap;
#define VA_SHIFT(v,t) ;         
#define VA_START(f) va_start(ap, f)


#define inet_pton xinet_pton

#define inet_ntop xinet_ntop

#define getnameinfo xgetnameinfo
#define EAI_OVERFLOW   12 
#define EAI_SYSTEM     11  
#define IN_EXPERIMENTAL(a)  \
     ((((long int) (a)) & 0xf0000000) == 0xf0000000)

#define freeaddrinfo    xfreeaddrinfo
#define gai_strerror    xgai_strerror
#define getaddrinfo xgetaddrinfo
#define NAMLEN(dirent) strlen((dirent)->d_name)
#define PRINTF_FORMAT_ARG1 __attribute__ ((format (printf, 1, 2)))
#define PRINTF_FORMAT_ARG2 __attribute__ ((format (printf, 2, 3)))
#define PRINTF_FORMAT_ARG3 __attribute__ ((format (printf, 3, 4)))
#define SA_NODEFER 0
#define SA_RESETHAND 0
#define SA_RESTART 0
# define SQUID_FDSET_NOUSE 1
# define SQUID_MAXFD_LIMIT    ((signed int)FD_SETSIZE)
#define SQUID_NONBLOCK O_NONBLOCK

#define dirent direct
#define dirent_t struct dirent64
#define max(a,b) ((a) < (b) ? (b) : (a))
#define memcpy(d,s,n) bcopy((s),(d),(n))
#define memmove(d,s,n) bcopy((s),(d),(n))
#define min(a,b) ((a) < (b) ? (a) : (b))
#define squid_strnstr(a,b,c)    strnstr(a,b,c)
#define w_space     " \t\n\r"




#define strdup(X) xstrdup((X))
#define strndup(X) xstrndup((X))


#define xisalnum(x) isalnum(static_cast<unsigned char>(x))
#define xisalpha(x) isalpha(static_cast<unsigned char>(x))
#define xisascii(x) isascii(static_cast<unsigned char>(x))
#define xiscntrl(x) iscntrl(static_cast<unsigned char>(x))
#define xisdigit(x) isdigit(static_cast<unsigned char>(x))
#define xisgraph(x) isgraph(static_cast<unsigned char>(x))
#define xislower(x) islower(static_cast<unsigned char>(x))
#define xisprint(x) isprint(static_cast<unsigned char>(x))
#define xispunct(x) ispunct(static_cast<unsigned char>(x))
#define xisspace(x) isspace(static_cast<unsigned char>(x))
#define xisupper(x) isupper(static_cast<unsigned char>(x))
#define xisxdigit(x) isxdigit(static_cast<unsigned char>(x))
#define xtolower(x) tolower(static_cast<unsigned char>(x))
#define xtoupper(x) toupper(static_cast<unsigned char>(x))

#define safe_free(x)    while ((x)) { free_const((x)); (x) = NULL; }

#define assert(EX) ((void)0)

#define AF_LOCAL AF_UNIX

#define SUN_LEN(su) (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#define _PATH_DEVNULL "/dev/null"
#define _XPG4_2 1
#define __FUNCTION__ ""
#define s6_addr32  _S6_un._S6_u32
#define wcsstr wcswcs
#define AI_ADDRCONFIG   0x0004  
#define AI_ALL      0x0002  
#define AI_CANONNAME    0x0010  
#define AI_DEFAULT  (AI_V4MAPPED | AI_ADDRCONFIG)
#define AI_NUMERICHOST  0x0020  
#define AI_NUMERICSERV  0x0040  
#define AI_PASSIVE  0x0008  
#define AI_V4MAPPED 0x0001  
#define EAI_ADDRFAMILY  1   
#define EAI_AGAIN   2   
#define EAI_BADFLAGS    3   
#define EAI_FAIL    4   
#define EAI_FAMILY  5   
#define EAI_MAX     14
#define EAI_MEMORY  6   
#define EAI_NODATA  7   
#define EAI_NONAME  8   
#define EAI_PROTOCOL    13
#define EAI_SERVICE 9   
#define EAI_SOCKTYPE    10  
#define HOST_NOT_FOUND  1 
#define IPSEC_PROTO_AH      2
#define IPSEC_PROTO_ESP     3
#define MAXADDRS    35
#define MAXALIASES  35
#define MAXHOSTNAMELEN  256
#define NETDB_INTERNAL  -1  
#define NETDB_SUCCESS   0   
#define NI_DGRAM    0x0010
#define NI_MAXHOST  1025
#define NI_MAXSERV  32
#define NI_NAMEREQD 0x0004  
#define NI_NOFQDN   0x0001
#define NI_NUMERICHOST  0x0002  
#define NI_NUMERICSCOPE 0x0040
#define NI_NUMERICSERV  0x0008
#define NI_WITHSCOPEID  0x0020
#define NO_ADDRESS  NO_DATA     
#define NO_DATA     4 
#define NO_RECOVERY 3 
#define SCOPE_DELIMITER '%'
#define TRY_AGAIN   2 

#define _PATH_HEQUIV    "/etc/hosts.equiv"
#define _PATH_HOSTS "/etc/hosts"
#define _PATH_IPNODES   "/etc/inet/ipnodes"
#define _PATH_IPSECALGS "/etc/inet/ipsecalgs"
#define _PATH_NETMASKS  "/etc/netmasks"
#define _PATH_NETWORKS  "/etc/networks"
#define _PATH_PROTOCOLS "/etc/protocols"
#define _PATH_SERVICES  "/etc/services"
#define h_addr  h_addr_list[0]  
#define h_errno (*__h_errno())


#define _SVR4_SOURCE        


#define IPV6_V6ONLY             27 

#define HAVE_NETDB_H 0

#define S_ISDIR(mode) (((mode) & (_S_IFMT)) == (_S_IFDIR))
#define NEED_SYS_ERRLIST 1

#define ACL WindowsACL
#define CHANGE_FD_SETSIZE 1
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define EAI_NODATA WSANO_DATA
#define EALREADY WSAEALREADY
#define ECONNABORTED WSAECONNABORTED
#define ECONNREFUSED WSAECONNREFUSED
#define ECONNRESET WSAECONNRESET
#define EINPROGRESS WSAEINPROGRESS
#define EISCONN WSAEISCONN
#define ENETUNREACH WSAENETUNREACH
#define ENOTCONN WSAENOTCONN
#define ENOTSUP WSAEOPNOTSUPP
#define ERESTART WSATRY_AGAIN
#define ETIMEDOUT WSAETIMEDOUT
#define EWOULDBLOCK WSAEWOULDBLOCK
#define FD_CLR(fd, set) do { \
    u_int __i; \
    SOCKET __sock = _get_osfhandle(fd); \
    for (__i = 0; __i < ((fd_set FAR *)(set))->fd_count ; __i++) { \
        if (((fd_set FAR *)(set))->fd_array[__i] == __sock) { \
            while (__i < ((fd_set FAR *)(set))->fd_count-1) { \
                ((fd_set FAR *)(set))->fd_array[__i] = \
                    ((fd_set FAR *)(set))->fd_array[__i+1]; \
                __i++; \
            } \
            ((fd_set FAR *)(set))->fd_count--; \
            break; \
        } \
    } \
} while(0)
#define FD_ISSET(fd, set) Win32__WSAFDIsSet(fd, (fd_set FAR *)(set))
#define FD_SET(fd, set) do { \
    u_int __i; \
    SOCKET __sock = _get_osfhandle(fd); \
    for (__i = 0; __i < ((fd_set FAR *)(set))->fd_count; __i++) { \
        if (((fd_set FAR *)(set))->fd_array[__i] == (__sock)) { \
            break; \
        } \
    } \
    if (__i == ((fd_set FAR *)(set))->fd_count) { \
        if (((fd_set FAR *)(set))->fd_count < FD_SETSIZE) { \
            ((fd_set FAR *)(set))->fd_array[__i] = (__sock); \
            ((fd_set FAR *)(set))->fd_count++; \
        } \
    } \
} while(0)
#define FD_SETSIZE SQUID_MAXFD
#define FOPEN           0x01    
#define HAVE_GETPAGESIZE 2
#define INT64_MAX _I64_MAX
#define INT64_MIN _I64_MIN
#define IOINFO_ARRAY_ELTS   (1 << IOINFO_L2E)
#define IOINFO_L2E          5
#define LOG_ALERT   1
#define LOG_CRIT    2
#define LOG_DAEMON  (3<<3)
#define LOG_DEBUG   7
#define LOG_EMERG   0
#define LOG_ERR     3
#define LOG_INFO    6
#define LOG_NOTICE  5
#define LOG_PID     0x01
#define LOG_WARNING 4


#define O_APPEND        _O_APPEND
#define O_BINARY        _O_BINARY
#define O_CREAT         _O_CREAT
#define O_EXCL          _O_EXCL
#define O_NDELAY    0
#define O_NOINHERIT     _O_NOINHERIT
#define O_RANDOM        _O_RANDOM
#define O_RAW           _O_BINARY
#define O_RDONLY        _O_RDONLY
#define O_RDWR          _O_RDWR
#define O_SEQUENTIAL    _O_SEQUENTIAL
#define O_TEMPORARY     _O_TEMPORARY
#define O_TEXT          _O_TEXT
#define O_TRUNC         _O_TRUNC
#define O_WRONLY        _O_WRONLY
#define RUSAGE_CHILDREN -1      
#define RUSAGE_SELF 0       
#define SIGBUS  10  
#define SIGCHLD 20  
#define SIGHUP  1   
#define SIGKILL 9   
#define SIGPIPE 13  
#define SIGUSR1 30  
#define SIGUSR2 31  

#define S_IEXEC  _S_IEXEC
#define S_IFCHR  _S_IFCHR
#define S_IFDIR  _S_IFDIR
#define S_IFMT   _S_IFMT
#define S_IFREG  _S_IFREG
#define S_IREAD  _S_IREAD
#define S_IRWXO 007
#define S_IWGRP 0
#define S_IWOTH 0
#define S_IWRITE _S_IWRITE
#define S_IXGRP 0
#define S_IXOTH 0
#define THREADLOCAL __declspec(thread)
#define WEXITSTATUS(w)  (((w) >> 8) & 0xff)
#define WIFEXITED(w)    (((w) & 0xff) == 0)
#define WIFSIGNALED(w)  (((w) & 0x7f) > 0 && (((w) & 0x7f) < 0x7f))
#define WIFSTOPPED(w)   (((w) & 0xff) == 0x7f)
#define WINVER 0x0501
#define WSAAsyncSelect(s,h,w,e) Squid::WSAAsyncSelect(s,h,w,e)
#define WSADuplicateSocket(s,n,l) Squid::WSADuplicateSocket(s,n,l)
#define WSASocket(a,t,p,i,g,f) Squid::WSASocket(a,t,p,i,g,f)
#define WSTOPSIG    WEXITSTATUS
#define WTERMSIG(w) ((w) & 0x7f)

#define _MSWIN_ACL_WAS_NOT_DEFINED 1
#define _S_IREAD 0x0100
#define _S_IWRITE 0x0080
#define _WIN32_WINNT WINVER

# define __USE_FILE_OFFSET64    1
#define _osfhnd(i)  ( _pioinfo(i)->osfhnd )
#define _osfile(i)  ( _pioinfo(i)->osfile )
#define _pioinfo(i) ( __pioinfo[(i) >> IOINFO_L2E] + ((i) & (IOINFO_ARRAY_ELTS - 1)) )
#define accept(s,a,l) Squid::accept(s,a,reinterpret_cast<socklen_t*>(l))
#define alloca _alloca
#define bind(s,n,l) Squid::bind(s,n,l)
#define chdir _chdir
#define connect(s,n,l) \
    (SOCKET_ERROR == connect(_get_osfhandle(s),n,l) ? \
    (WSAEMFILE == (errno = WSAGetLastError()) ? errno = EMFILE : -1, -1) : 0)
#define dup _dup
#define dup2 _dup2
#define fdopen _fdopen
#define fileno _fileno
#define fstat _fstati64
#define ftruncate WIN32_ftruncate
#define getcwd _getcwd
#define gethostbyaddr(a,l,t) Squid::gethostbyaddr(a,l,t)
#define gethostbyname(n) \
    (NULL == ((HOSTENT FAR*)(ws32_result = (int)gethostbyname(n))) ? \
    (errno = WSAGetLastError()), (HOSTENT FAR*)NULL : (HOSTENT FAR*)ws32_result)
#define gethostname(n,l) \
    (SOCKET_ERROR == gethostname(n,l) ? \
    (errno = WSAGetLastError()), -1 : 0)
#define getpid _getpid
#define getservbyname(n,p) Squid::getservbyname(n,p)
#define getsockname(s,a,l) Squid::getsockname(s,a,reinterpret_cast<socklen_t*>(l))
#define getsockopt(s,l,o,v,n) Squid::getsockopt(s,l,o,v,n)
#define h_errno errno 
#define ioctl(s,c,a) Squid::ioctl(s,c,a)
#define ioctlsocket(s,c,a) Squid::ioctlsocket(s,c,a)
#define listen(s,b) Squid::listen(s,b)
#define lseek _lseeki64
#define memccpy _memccpy
#define mkdir(p,F) mkdir((p))
#define mktemp _mktemp
#define open       _open 
#define pclose _pclose
#define pipe(a) Squid::pipe(a)
#define popen _popen
#define putenv _putenv
#define recv(s,b,l,f) \
    (SOCKET_ERROR == (ws32_result = recv(_get_osfhandle(s),b,l,f)) ? \
    (errno = WSAGetLastError()), -1 : ws32_result)
#define recvfrom(s,b,l,f,r,n) Squid::recvfrom(s,b,l,f,r,reinterpret_cast<socklen_t*>(n))
#define select(n,r,w,e,t) \
    (SOCKET_ERROR == (ws32_result = select(n,r,w,e,t)) ? \
    (errno = WSAGetLastError()), -1 : ws32_result)
#define send(s,b,l,f) Squid::send(s,reinterpret_cast<const char*>(b),l,f)
#define sendto(s,b,l,f,t,tl) \
    (SOCKET_ERROR == (ws32_result = sendto(_get_osfhandle(s),b,l,f,t,tl)) ? \
    (errno = WSAGetLastError()), -1 : ws32_result)
#define setmode _setmode
#define setsockopt(s,l,o,v,n) Squid::setsockopt(s,l,o,v,n)
#define shutdown(s,h) Squid::shutdown(s,h)
#define sleep(t) Sleep((t)*1000)
#define snprintf _snprintf
#define socket(f,t,p) \
    (INVALID_SOCKET == ((SOCKET)(ws32_result = (int)socket(f,t,p))) ? \
    ((WSAEMFILE == (errno = WSAGetLastError()) ? errno = EMFILE : -1), -1) : \
    (SOCKET)_open_osfhandle(ws32_result,0))
#define stat _stati64
#define strcasecmp _stricmp
#define strlwr _strlwr
#define strncasecmp _strnicmp
#define tempnam _tempnam
#define truncate WIN32_truncate
#define umask _umask
#define unlink _unlink
#define vsnprintf _vsnprintf
#define write      _write 


# define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
             & ~(sizeof (size_t) - 1))
# define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr)        \
   ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) NULL)
# define CMSG_LEN(len)   (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))
# define CMSG_NXTHDR(mhdr, X) __cmsg_nxthdr (mhdr, X)
# define CMSG_SPACE(len) (CMSG_ALIGN (len) \
             + CMSG_ALIGN (sizeof (struct cmsghdr)))
#define HAVE_CONSTANT_CMSG_SPACE 1
#define SCM_CREDENTIALS 2
#define SCM_RIGHTS 1
#define SCM_SECURITY 3
# define SQUID_CMSG_DATA(cmsg) WSA_CMSG_DATA(cmsg)
#define SQUID_CMSG_SPACE CMSG_SPACE

#define HAVE_RES_INIT  HAVE___RES_INIT




#define res_init  __res_init
#define HAVE_GETRUSAGE 1

#define getpagesize( )   sysconf(_SC_PAGE_SIZE)
#define getrusage(a, b)  syscall(SYS_GETRUSAGE, a, b)

#define _etext etext


#define _SQUID_ANDROID_ 1
#define MSG_DONTWAIT 0


#define _XOPEN_SOURCE_EXTENDED 1
#define INT_MAX    0x7FFFFFFFL 
#define NULL 0
#define PRIX64 "I64X"
#define PRId64 "I64d"
#define PRIu64 "I64u"
#define PRIuSIZE "I32u"

#define UINT32_MAX    0xFFFFFFFFL
#define UINT32_MIN    0x00000000L
#define xuniform_int_distribution std::uniform_int_distribution
#define xuniform_real_distribution std::uniform_real_distribution

#define __FD_SETSIZE SQUID_MAXFD
#  define fd_set ERROR_FD_SET_USED

#define _SQUID_AIX_ 1
#define _SQUID_APPLE_ 1
#define _SQUID_CYGWIN_ 1
#define _SQUID_DRAGONFLY_ 1
#define _SQUID_FREEBSD_ 1
#define _SQUID_HPUX_ 1
#define _SQUID_KFREEBSD_ 1
#define _SQUID_LINUX_ 1
#define _SQUID_MINGW_ 1
#define _SQUID_NETBSD_ 1
#define _SQUID_NEWSOS6_ 1
#define _SQUID_NEXT_ 1
#define _SQUID_OPENBSD_ 1
#define _SQUID_OS2_ 1
#define _SQUID_OSF_ 1
#define _SQUID_QNX_ 1
#define _SQUID_SGI_ 1
#define _SQUID_SOLARIS_ 1
#define _SQUID_SUNOS_ 1
#define _SQUID_WINDOWS_ 1
#define APP_FULLNAME  PACKAGE "/" VERSION
#define APP_SHORTNAME "squid"
#define SQUID_RELEASE_TIME squid_curtime
