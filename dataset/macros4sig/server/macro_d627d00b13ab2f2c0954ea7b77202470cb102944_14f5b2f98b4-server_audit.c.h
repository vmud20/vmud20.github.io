

#include<time.h>
#include<signal.h>
#include<limits.h>
#include<unistd.h>

#include<alloca.h>
#include<stdio.h>
#include<malloc.h>




#include<sys/resource.h>
#include<math.h>
#include<sys/mman.h>

#include<stdarg.h>


#include<pthread.h>
#include<assert.h>

#include<sys/types.h>

#include<float.h>


#include<syslog.h>



#include<stdlib.h>

#include<fcntl.h>

#include<dlfcn.h>
#include<errno.h>

#include<string.h>



#include<sched.h>
#include<fenv.h>


#include<memory.h>

#include<crypt.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<stddef.h>
#include<strings.h>




#define LOG_FLAGS (O_APPEND | O_CREAT | O_WRONLY)
#define flogger_mutex_destroy(A) mysql_mutex_destroy(A)
#define flogger_mutex_init(A,B,C) mysql_mutex_init(A,B,C)
#define flogger_mutex_lock(A) mysql_mutex_lock(A)
#define flogger_mutex_unlock(A) mysql_mutex_unlock(A)
#define ESRCH 1
#define ETIME ETIMEDOUT				
#define ETIMEDOUT 145		    
#define EXTERNC extern "C"
#define GETHOSTBYADDR_BUFF_SIZE 2048
#define INSTRUMENT_ME 0
#define MYF_NO_DEADLOCK_DETECTION 2
#define MYF_TRY_LOCK              1
#define MY_MUTEX_INIT_ERRCHK &my_errorcheck_mutexattr
#define MY_MUTEX_INIT_FAST &my_fast_mutexattr
#define MY_MUTEX_INIT_SLOW   NULL
#define MY_PTHREAD_LOCK_READ 0
#define MY_PTHREAD_LOCK_WRITE 1
#define MY_PTHREAD_ONCE_INIT INIT_ONCE_STATIC_INIT;
#define MY_tv_nsec ts_nsec
#define MY_tv_sec  ts_sec
#define NEED_MY_RW_LOCK 1
#define PTHREAD_STACK_MIN 65536
#define THD_LIB_LT    4
#define THD_LIB_NPTL  2
#define THD_LIB_OTHER 1
#define THREAD_NAME_SIZE 10
#define _current_thd() _current_thd_noinline()

#define cmp_timespec(TS1, TS2) \
  ((TS1.MY_tv_sec > TS2.MY_tv_sec || \
    (TS1.MY_tv_sec == TS2.MY_tv_sec && TS1.MY_tv_nsec > TS2.MY_tv_nsec)) ? 1 : \
   ((TS1.MY_tv_sec < TS2.MY_tv_sec || \
     (TS1.MY_tv_sec == TS2.MY_tv_sec && TS1.MY_tv_nsec < TS2.MY_tv_nsec)) ? -1 : 0))
#define getpid() GetCurrentThreadId()
#define my_cond_timedwait(A,B,C) safe_cond_timedwait((A),(B),(C),"__FILE__","__LINE__")
#define my_cond_wait(A,B) safe_cond_wait((A), (B), "__FILE__", "__LINE__")
#define my_errno my_thread_var->thr_errno
#define my_pthread_getspecific(T,A) ((T) TlsGetValue(A))
#define my_pthread_getspecific_ptr(T,V) ((T) TlsGetValue(V))
#define my_pthread_setspecific_ptr(T,V) (!TlsSetValue((T),(V)))
#define my_rw_lock_assert_not_write_owner(A) \
  DBUG_ASSERT((A)->state >= 0 || ! pthread_equal(pthread_self(), \
                                                 (A)->write_thread))
#define my_rw_lock_assert_write_owner(A) \
  DBUG_ASSERT((A)->state == -1 && pthread_equal(pthread_self(), \
                                                (A)->write_thread))
#define my_rwlock_init(A,B) pthread_mutex_init((A),(B))
#define my_sigset(A,B) signal(A,B)
#define my_thread_var (_my_thread_var())
#define mysql_mutex_record_order(A,B)                   \
  do {                                                  \
    mysql_mutex_lock(A); mysql_mutex_lock(B);           \
    mysql_mutex_unlock(B); mysql_mutex_unlock(A);       \
  }  while(0)
#define pthread_attr_getstacksize(A,B) my_pthread_attr_getstacksize(A,B)
#define pthread_attr_setdetachstate(A,B) pthread_dummy(0)

#define pthread_attr_setstacksize(A,B) pthread_dummy(0)
#define pthread_cond_timedwait(a,b,c) my_pthread_cond_timedwait((a),(b),(c))



#define pthread_equal(A,B) ((A) == (B))
#define pthread_getspecific(A) (TlsGetValue(A))
#define pthread_handler_t EXTERNC void * __cdecl
#define pthread_key(T,V)  DWORD V
#define pthread_key_create(A,B) ((*A=TlsAlloc())==0xFFFFFFFF)
#define pthread_key_delete(A) TlsFree(A)
#define pthread_kill(A,B) pthread_dummy((A) ? 0 : ESRCH)
#define pthread_mutex_destroy(A) (DeleteCriticalSection(A), 0)
#define pthread_mutex_init(A,B)  (InitializeCriticalSection(A),0)
#define pthread_mutex_lock(A)	 (EnterCriticalSection(A),0)
#define pthread_mutex_trylock(A) win_pthread_mutex_trylock((A))
#define pthread_mutex_unlock(A)  (LeaveCriticalSection(A), 0)
#define pthread_self() GetCurrentThreadId()
#define pthread_setspecific(A,B) (!TlsSetValue((A),(B)))
#define pthread_yield() pthread_yield_np()
#define rw_lock_assert_not_write_owner(A) my_rw_lock_assert_not_write_owner((A))
#define rw_lock_assert_write_owner(A) my_rw_lock_assert_write_owner((A))
#define rw_lock_t pthread_mutex_t
#define rw_pr_lock_assert_not_write_owner(A) \
  DBUG_ASSERT(! (A)->active_writer || ! pthread_equal(pthread_self(), \
                                                      (A)->writer_thread))
#define rw_pr_lock_assert_write_owner(A) \
  DBUG_ASSERT((A)->active_writer && pthread_equal(pthread_self(), \
                                                  (A)->writer_thread))
#define rw_rdlock(A) pthread_mutex_lock((A))
#define rw_tryrdlock(A) pthread_mutex_trylock((A))
#define rw_trywrlock(A) pthread_mutex_trylock((A))
#define rw_unlock(A) pthread_mutex_unlock((A))
#define rw_wrlock(A) pthread_mutex_lock((A))
#define rwlock_destroy(A) pthread_mutex_destroy((A))
#define safe_mutex_assert_not_owner(mp) \
          DBUG_ASSERT(! (mp)->count || \
                      ! pthread_equal(pthread_self(), (mp)->thread))
#define safe_mutex_assert_owner(mp) \
          DBUG_ASSERT((mp)->count > 0 && \
                      pthread_equal(pthread_self(), (mp)->thread))
#define safe_mutex_setflags(mp, F)      do { (mp)->create_flags|= (F); } while (0)
#define set_timespec(ABSTIME,SEC) set_timespec_nsec((ABSTIME),(SEC)*1000000000ULL)
#define set_timespec_nsec(ABSTIME,NSEC)                                 \
  set_timespec_time_nsec((ABSTIME), my_hrtime().val*1000 + (NSEC))
#define set_timespec_time_nsec(ABSTIME,NSEC) do {    \
  ulonglong _now_= (NSEC);                             \
  (ABSTIME).MY_tv_sec=  (_now_ / 1000000000ULL);       \
  (ABSTIME).MY_tv_nsec= (_now_ % 1000000000ULL);       \
} while(0)
#define statistic_add(V,C,L)     thread_safe_add((V),(C),(L))
#define statistic_decrement(V,L) thread_safe_decrement((V),(L))
#define statistic_increment(V,L) thread_safe_increment((V),(L))
#define statistic_sub(V,C,L)     thread_safe_sub((V),(C),(L))
#define status_var_add(V,C)     (V)+=(C)
#define status_var_decrement(V) (V)--
#define status_var_increment(V) (V)++
#define status_var_sub(V,C)     (V)-=(C)
#define thr_setconcurrency(A) pthread_dummy(0)
#define thread_safe_add(V,C,L) InterlockedExchangeAdd((long*) &(V),(C))
#define thread_safe_decrement(V,L) InterlockedDecrement((long*) &(V))
#define thread_safe_increment(V,L) InterlockedIncrement((long*) &(V))
#define thread_safe_sub(V,C,L) InterlockedExchangeAdd((long*) &(V),-(long) (C))

#define mysql_cond_broadcast(C) inline_mysql_cond_broadcast(C)
#define mysql_cond_destroy(C) inline_mysql_cond_destroy(C)
  #define mysql_cond_init(K, C, A) inline_mysql_cond_init(K, C, A)
#define mysql_cond_register(P1, P2, P3) \
  inline_mysql_cond_register(P1, P2, P3)
#define mysql_cond_signal(C) inline_mysql_cond_signal(C)
  #define mysql_cond_timedwait(C, M, W) \
    inline_mysql_cond_timedwait(C, M, W, "__FILE__", "__LINE__")
  #define mysql_cond_wait(C, M) \
    inline_mysql_cond_wait(C, M, "__FILE__", "__LINE__")
#define mysql_mutex_assert_not_owner(M) \
  safe_mutex_assert_not_owner(&(M)->m_mutex)
#define mysql_mutex_assert_owner(M) \
  safe_mutex_assert_owner(&(M)->m_mutex)
  #define mysql_mutex_destroy(M) \
    inline_mysql_mutex_destroy(M, "__FILE__", "__LINE__")
    #define mysql_mutex_init(K, M, A) \
      inline_mysql_mutex_init(K, M, A, #M, "__FILE__", "__LINE__")
  #define mysql_mutex_lock(M) \
    inline_mysql_mutex_lock(M, "__FILE__", "__LINE__")
#define mysql_mutex_register(P1, P2, P3) \
  inline_mysql_mutex_register(P1, P2, P3)
#define mysql_mutex_setflags(M, F) \
  safe_mutex_setflags(&(M)->m_mutex, (F))
  #define mysql_mutex_trylock(M) \
    inline_mysql_mutex_trylock(M, "__FILE__", "__LINE__")
  #define mysql_mutex_unlock(M) \
    inline_mysql_mutex_unlock(M, "__FILE__", "__LINE__")
#define mysql_prlock_assert_not_write_owner(M) \
  rw_pr_lock_assert_not_write_owner(&(M)->m_prlock)
#define mysql_prlock_assert_write_owner(M) \
  rw_pr_lock_assert_write_owner(&(M)->m_prlock)
#define mysql_prlock_destroy(RW) inline_mysql_prlock_destroy(RW)
  #define mysql_prlock_init(K, RW) inline_mysql_prlock_init(K, RW)
  #define mysql_prlock_rdlock(RW) \
    inline_mysql_prlock_rdlock(RW, "__FILE__", "__LINE__")
#define mysql_prlock_unlock(RW) inline_mysql_prlock_unlock(RW)
  #define mysql_prlock_wrlock(RW) \
    inline_mysql_prlock_wrlock(RW, "__FILE__", "__LINE__")
#define mysql_rwlock_destroy(RW) inline_mysql_rwlock_destroy(RW)
  #define mysql_rwlock_init(K, RW) inline_mysql_rwlock_init(K, RW)
  #define mysql_rwlock_rdlock(RW) \
    inline_mysql_rwlock_rdlock(RW, "__FILE__", "__LINE__")
#define mysql_rwlock_register(P1, P2, P3) \
  inline_mysql_rwlock_register(P1, P2, P3)
  #define mysql_rwlock_tryrdlock(RW) \
    inline_mysql_rwlock_tryrdlock(RW, "__FILE__", "__LINE__")
  #define mysql_rwlock_trywrlock(RW) \
    inline_mysql_rwlock_trywrlock(RW, "__FILE__", "__LINE__")
#define mysql_rwlock_unlock(RW) inline_mysql_rwlock_unlock(RW)
  #define mysql_rwlock_wrlock(RW) \
    inline_mysql_rwlock_wrlock(RW, "__FILE__", "__LINE__")
  #define mysql_thread_create(K, P1, P2, P3, P4) \
    inline_mysql_thread_create(K, P1, P2, P3, P4)
#define mysql_thread_register(P1, P2, P3) \
  inline_mysql_thread_register(P1, P2, P3)
  #define mysql_thread_set_psi_id(I) do {} while (0)
























#define PSI_COND_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_CURRENT_VERSION 1
#define PSI_DIGEST_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_DYNAMIC_CALL(M) PSI_server->M
#define PSI_FILE_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_FLAG_GLOBAL (1 << 0)
#define PSI_FLAG_MUTABLE (1 << 1)
#define PSI_IDLE_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_MUTEX_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_RWLOCK_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_SCHEMA_NAME_LEN (64 * 3)
#define PSI_SOCKET_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_STAGE_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_STATEMENT_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_TABLE_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_THREAD_CALL(M) PSI_DYNAMIC_CALL(M)
#define PSI_VERSION_1 1
#define PSI_VERSION_2 2

#define ADD_TO_PTR(ptr,size,type) (type) ((uchar*) (ptr)+size)
#define ALIGN_MAX_UNIT  (sizeof(double))
#define ALIGN_PTR(A, t) ((t*) MY_ALIGN((A), sizeof(double)))
#define ALIGN_SIZE(A)	MY_ALIGN((A),sizeof(double))
#define CMP_NUM(a,b)    (((a) < (b)) ? -1 : ((a) == (b)) ? 0 : 1)
#define CPP_UNNAMED_NS_END    }
#define CPP_UNNAMED_NS_START  namespace {
    #define CPU_LEVEL1_DCACHE_LINESIZE 256

#define C_MODE_START    extern "C" {
#  define DBUG_OFF
#define DONT_ALLOW_USER_CHANGE 1
#define DONT_USE_MYSQL_PWD 1
#define FLOATING_POINT_DECIMALS 31
#define FN_DIRSEP       "/\\"               
#define FN_EXEEXT   ".exe"
#define FN_SOEXT    ".dll"
#define F_OK 0
#define F_RDLCK 1
#define F_TO_EOF 0x3FFFFFFF
#define F_UNLCK 3
#define F_WRLCK 2
#define HAVE_DLERROR 1
#define HAVE_DLOPEN 1



#define HAVE_LONG_LONG 1
#define HAVE_NAMED_PIPE 1


#define HAVE_SMEM 1



#define IF_EMBEDDED(A,B) A
#define IF_PARTITIONING(A,B) A
#define IF_WIN(A,B) A

#define INT_MAX16       0x7FFF
#define INT_MAX24       0x007FFFFF
#define INT_MAX32       0x7FFFFFFFL
#define INT_MAX64       0x7FFFFFFFFFFFFFFFLL
#define INT_MAX8        0x7F
#define INT_MIN16       (~0x7FFF)
#define INT_MIN24       (~0x007FFFFF)
#define INT_MIN32       (~0x7FFFFFFFL)
#define INT_MIN64       (~0x7FFFFFFFFFFFFFFFLL)
#define INT_MIN8        (~0x7F)
#define INVALID_SOCKET -1
#define LINT_INIT(x) x= 0
#define MALLOC_OVERHEAD 8
#define MAX_EXACT_INTEGER ((1LL << DBL_MANT_DIG) - 1)
#define MYF(v)		(myf) (v)
#define MYSQL_PLUGIN_IMPORT __declspec(dllimport)
#define MYSQL_UNIVERSAL_CLIENT_CHARSET "utf8"
#define MY_ALIGN(A,L)	   (((A) + (L) - 1) & ~((L) - 1))
#define MY_ALIGN_DOWN(A,L) ((A) & ~((L) - 1))
#define MY_ERRPTR ((void*)(intptr)1)
#define MY_FILE_MIN  2048

#define MY_INT32_NUM_DECIMAL_DIGITS 11
#define MY_INT64_NUM_DECIMAL_DIGITS 21
#define MY_MAX(a, b)	((a) > (b) ? (a) : (b))
#define MY_MIN(a, b)	((a) < (b) ? (a) : (b))
#define MY_NFILE (16384 + MY_FILE_MIN)
#define MY_TEST(a) ((a) ? 1 : 0)
#define M_E 2.7182818284590452354
#define M_LN2 0.69314718055994530942
#define M_PI 3.14159265358979323846
#define NEED_EXPLICIT_SYNC_DIR 1

#define NOT_FIXED_DEC           DECIMAL_NOT_SPECIFIED

#define O_CLOEXEC       0
#define O_NOFOLLOW      0
#define PREV_BITS(type,A)	((type) (((type) 1 << (A)) -1))
#define PTR_BYTE_DIFF(A,B) (my_ptrdiff_t) ((uchar*) (A) - (uchar*) (B))
#define QUOTE_ARG(x)		#x	
#define RTLD_DEFAULT GetModuleHandle(NULL)
#define R_OK 4                        

#    define SIZEOF_CHARP 4
#  define SIZEOF_INT 4
#    define SIZEOF_LONG 4
#  define SIZEOF_LONG_LONG 8
#  define SIZEOF_OFF_T 8
#define SIZE_T_MAX      (~((size_t) 0))
#define SOCKET_EADDRINUSE WSAEADDRINUSE
#define SOCKET_ECONNRESET ECONNRESET
#define SOCKET_ETIMEDOUT WSAETIMEDOUT
#define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
#define SOCKOPT_OPTLEN_TYPE size_socket
#define SOCK_CLOEXEC    0
#define SO_EXT ".dll"
#define STDCALL __stdcall
#define STRINGIFY_ARG(x) QUOTE_ARG(x)	
#define STR_O_CLOEXEC "e"
#define UINT_MAX16      0xFFFF
#define UINT_MAX24      0x00FFFFFF
#define UINT_MAX32      0xFFFFFFFFL
#define UINT_MAX8       0xFF
#define ULONGLONG_MAX  ULLONG_MAX
#define UNINIT_VAR(x) x= x
#    define WORDS_BIGENDIAN
#define WT_RWLOCKS_USE_MUTEXES 1
#define W_OK 2
#define YESNO(X) ((X) ? "yes" : "no")
#define _GNU_SOURCE 1


#define _LONG_LONG 1		

#define _POSIX_PTHREAD_SEMANTICS 

#define _SH_DENYDEL     0x140    
#define _SH_DENYRDD     0x130    
#define _SH_DENYRWD     0x110    
#define _SH_DENYWRD     0x120    

#define _THREAD_SAFE            
#define _XOPEN_SOURCE 600
#define __EXTENSIONS__ 1	
#define __STDC_EXT__ 1          


#define __builtin_expect(x, expected_value) (x)
#    define __func__ __FUNCTION__

#define array_elements(A) ((uint) (sizeof(A)/sizeof(A[0])))
#define bool In_C_you_should_use_my_bool_instead()
#define closesocket(A)	close(A)
#define compile_time_assert(X)  do { } while(0)
#define default_shared_memory_base_name "MYSQL"
#define dladdr(A, B) 0
#define dlclose(lib) FreeLibrary((HMODULE)lib)
#define dlerror() ""
#define dlopen(libname, unused) LoadLibraryEx(libname, NULL, 0)
#define dlsym(lib, name) (void*)GetProcAddress((HMODULE)lib, name)
#define double2ulonglong my_double2ulonglong
#define likely(x)	__builtin_expect(((x) != 0),1)

#define my_off_t2double  my_ulonglong2double
#define my_offsetof(TYPE, MEMBER) PTR_BYTE_DIFF(&((TYPE *)0x10)->MEMBER, 0x10)
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define qsort_t RETQSORTTYPE	
#define reg1 register
#define reg10 register
#define reg11 register
#define reg12 register
#define reg13 register
#define reg14 register
#define reg15 register
#define reg16 register
#define reg2 register
#define reg3 register
#define reg4 register
#define reg5 register
#define reg6 register
#define reg7 register
#define reg8 register
#define reg9 register
#define set_bits(type, bit_count) (sizeof(type)*8 <= (bit_count) ? ~(type) 0 : ((((type) 1) << (bit_count)) - (type) 1))
#define set_if_bigger(a,b)  do { if ((a) < (b)) (a)=(b); } while(0)
#define set_if_smaller(a,b) do { if ((a) > (b)) (a)=(b); } while(0)
#define setrlimit cma_setrlimit64
#define shared_memory_buffer_length 16000
#define sig_handler RETSIGTYPE
#define sleep(a) Sleep((a)*1000)
#define strtok_r(A,B,C) strtok((A),(B))
#define swap_variables(t, a, b) do { t dummy; dummy= a; a= b; b= dummy; } while(0)
#define test_all_bits(a,b) (((a) & (b)) == (b))
#define ulong_to_double(X) ((double) (ulong) (X))
#define ulonglong2double my_ulonglong2double
#define unlikely(x)	__builtin_expect(((x) != 0),0)


#define int4net(A)        (int32) (((uint32) ((uchar) (A)[3]))        | \
                                  (((uint32) ((uchar) (A)[2])) << 8)  | \
                                  (((uint32) ((uchar) (A)[1])) << 16) | \
                                  (((uint32) ((uchar) (A)[0])) << 24))
#define doubleget(V,M)   do { double def_temp;\
                              ((uchar*) &def_temp)[0]=(M)[4];\
                              ((uchar*) &def_temp)[1]=(M)[5];\
                              ((uchar*) &def_temp)[2]=(M)[6];\
                              ((uchar*) &def_temp)[3]=(M)[7];\
                              ((uchar*) &def_temp)[4]=(M)[0];\
                              ((uchar*) &def_temp)[5]=(M)[1];\
                              ((uchar*) &def_temp)[6]=(M)[2];\
                              ((uchar*) &def_temp)[7]=(M)[3];\
                              (V) = def_temp; } while(0)
#define doublestore(T,V) do { *(((char*)T)+0)=(char) ((uchar *) &V)[4];\
                              *(((char*)T)+1)=(char) ((uchar *) &V)[5];\
                              *(((char*)T)+2)=(char) ((uchar *) &V)[6];\
                              *(((char*)T)+3)=(char) ((uchar *) &V)[7];\
                              *(((char*)T)+4)=(char) ((uchar *) &V)[0];\
                              *(((char*)T)+5)=(char) ((uchar *) &V)[1];\
                              *(((char*)T)+6)=(char) ((uchar *) &V)[2];\
                              *(((char*)T)+7)=(char) ((uchar *) &V)[3]; }\
                         while(0)
#define float4get(V,M)   memcpy(&V, (M), sizeof(float))
#define float4store(V,M) memcpy(V, (&M), sizeof(float))
#define float8get(V,M)   doubleget((V),(M))
#define float8store(V,M) doublestore((V),(M))
#define floatget(V,M)    memcpy(&V, (M), sizeof(float))
#define floatstore(T,V)  memcpy((T), (void*) (&V), sizeof(float))
#define longget(V,M)	do { uchar *pM= (uchar*)(M);V = sint4korr(pM);} while(0)
#define longlongget(V,M) memcpy(&V, (M), sizeof(ulonglong))
#define longlongstore(T,V) memcpy((T), &V, sizeof(ulonglong))
#define longstore(T,V)	int4store(T,V)
#define shortget(V,M)	do { uchar *pM= (uchar*)(M);V = sint2korr(pM);} while(0)
#define shortstore(T,V) int2store(T,V)
#define ulongget(V,M)   do { uchar *pM= (uchar*)(M);V = uint4korr(pM);} while(0)
#define ushortget(V,M)	do { uchar *pM= (uchar*)(M);V = uint2korr(pM);} while(0)
#define int2store(T,A)       do { uint def_temp= (uint) (A) ;\
                                  *((uchar*) (T))=  (uchar)(def_temp); \
                                   *((uchar*) (T)+1)=(uchar)((def_temp >> 8)); \
                             } while(0)
#define int3store(T,A)       do { \
                                  *((uchar*)(T))=(uchar) ((A));\
                                  *((uchar*) (T)+1)=(uchar) (((A) >> 8));\
                                  *((uchar*)(T)+2)=(uchar) (((A) >> 16)); \
                                   while(0)
#define int4store(T,A)       do { *((char *)(T))=(char) ((A));\
                                  *(((char *)(T))+1)=(char) (((A) >> 8));\
                                  *(((char *)(T))+2)=(char) (((A) >> 16));\
                                  *(((char *)(T))+3)=(char) (((A) >> 24));\
                             } while(0)
#define int5store(T,A)       do { *((char *)(T))=     (char)((A));  \
                                  *(((char *)(T))+1)= (char)(((A) >> 8)); \
                                  *(((char *)(T))+2)= (char)(((A) >> 16)); \
                                  *(((char *)(T))+3)= (char)(((A) >> 24)); \
                                  *(((char *)(T))+4)= (char)(((A) >> 32)); \
		             } while(0)
#define int6store(T,A)       do { *((char *)(T))=     (char)((A)); \
                                  *(((char *)(T))+1)= (char)(((A) >> 8)); \
                                  *(((char *)(T))+2)= (char)(((A) >> 16)); \
                                  *(((char *)(T))+3)= (char)(((A) >> 24)); \
                                  *(((char *)(T))+4)= (char)(((A) >> 32)); \
                                  *(((char *)(T))+5)= (char)(((A) >> 40)); \
                             } while(0)
#define int8store(T,A)       do { uint def_temp= (uint) (A), \
                                       def_temp2= (uint) ((A) >> 32); \
                                  int4store((T),def_temp); \
                                  int4store((T+4),def_temp2);\
                             } while(0)
#define sint2korr(A)	(int16) (((int16) ((uchar) (A)[0])) |\
				 ((int16) ((int16) (A)[1]) << 8))
#define sint3korr(A)	((int32) ((((uchar) (A)[2]) & 128) ? \
				  (((uint32) 255L << 24) | \
				   (((uint32) (uchar) (A)[2]) << 16) |\
				   (((uint32) (uchar) (A)[1]) << 8) | \
				   ((uint32) (uchar) (A)[0])) : \
				  (((uint32) (uchar) (A)[2]) << 16) |\
				  (((uint32) (uchar) (A)[1]) << 8) | \
				  ((uint32) (uchar) (A)[0])))
#define sint4korr(A)	(int32) (((int32) ((uchar) (A)[0])) |\
				(((int32) ((uchar) (A)[1]) << 8)) |\
				(((int32) ((uchar) (A)[2]) << 16)) |\
				(((int32) ((int16) (A)[3]) << 24)))
#define sint8korr(A)	(longlong) uint8korr(A)
#define uint2korr(A)	(uint16) (((uint16) ((uchar) (A)[0])) |\
				  ((uint16) ((uchar) (A)[1]) << 8))
#define uint3korr(A)	(uint32) (((uint32) ((uchar) (A)[0])) |\
				  (((uint32) ((uchar) (A)[1])) << 8) |\
				  (((uint32) ((uchar) (A)[2])) << 16))
#define uint4korr(A)	(uint32) (((uint32) ((uchar) (A)[0])) |\
				  (((uint32) ((uchar) (A)[1])) << 8) |\
				  (((uint32) ((uchar) (A)[2])) << 16) |\
				  (((uint32) ((uchar) (A)[3])) << 24))
#define uint5korr(A)	((ulonglong)(((uint32) ((uchar) (A)[0])) |\
				    (((uint32) ((uchar) (A)[1])) << 8) |\
				    (((uint32) ((uchar) (A)[2])) << 16) |\
				    (((uint32) ((uchar) (A)[3])) << 24)) |\
				    (((ulonglong) ((uchar) (A)[4])) << 32))
#define uint6korr(A)	((ulonglong)(((uint32)    ((uchar) (A)[0]))          | \
                                     (((uint32)    ((uchar) (A)[1])) << 8)   | \
                                     (((uint32)    ((uchar) (A)[2])) << 16)  | \
                                     (((uint32)    ((uchar) (A)[3])) << 24)) | \
                         (((ulonglong) ((uchar) (A)[4])) << 32) |       \
                         (((ulonglong) ((uchar) (A)[5])) << 40))
#define uint8korr(A)	((ulonglong)(((uint32) ((uchar) (A)[0])) |\
				    (((uint32) ((uchar) (A)[1])) << 8) |\
				    (((uint32) ((uchar) (A)[2])) << 16) |\
				    (((uint32) ((uchar) (A)[3])) << 24)) |\
			(((ulonglong) (((uint32) ((uchar) (A)[4])) |\
				    (((uint32) ((uchar) (A)[5])) << 8) |\
				    (((uint32) ((uchar) (A)[6])) << 16) |\
				    (((uint32) ((uchar) (A)[7])) << 24))) <<\
				    32))




#define DBUG_ABORT()                    (_db_flush_(), abort())
#define DBUG_ASSERT(A) assert(A)
#define DBUG_DUMP(keyword,a1,a2) _db_dump_("__LINE__",keyword,a1,a2)
#define DBUG_END()  _db_end_ ()
#define DBUG_ENTER(a) struct _db_stack_frame_ _db_stack_frame_  __attribute__((cleanup(_db_return_))); \
        _db_enter_ (a,"__FILE__","__LINE__",&_db_stack_frame_)
#define DBUG_EVALUATE(keyword,a1,a2) \
        (_db_keyword_(0,(keyword), 0) ? (a1) : (a2))
#define DBUG_EVALUATE_IF(keyword,a1,a2) \
        (_db_keyword_(0,(keyword), 1) ? (a1) : (a2))
#define DBUG_EXECUTE(keyword,a1) \
        do {if (_db_keyword_(0, (keyword), 0)) { a1 }} while(0)
#define DBUG_EXECUTE_IF(keyword,a1) \
        do {if (_db_keyword_(0, (keyword), 1)) { a1 }} while(0)
#define DBUG_EXPLAIN(buf,len) _db_explain_(0, (buf),(len))
#define DBUG_EXPLAIN_INITIAL(buf,len) _db_explain_init_((buf),(len))
#define DBUG_FILE _db_fp_()
#define DBUG_FREE_CODE_STATE(arg) dbug_free_code_state(arg)
#define DBUG_LEAVE do { \
    _db_stack_frame_.line= "__LINE__"; \
    _db_return_ (&_db_stack_frame_); \
    _db_stack_frame_.line= 0; \
  } while(0)
#define DBUG_LOCK_FILE _db_lock_file_()
#  define DBUG_LOG(keyword, v) do {} while (0)
#define DBUG_POP() _db_pop_ ()
#define DBUG_PRINT(keyword,arglist) \
        do if (_db_pargs_("__LINE__",keyword)) _db_doprnt_ arglist; while(0)
#define DBUG_PROCESS(a1) _db_process_(a1)
#define DBUG_PUSH(a1) _db_push_ (a1)
#define DBUG_RETURN(a1) do { _db_stack_frame_.line="__LINE__"; return(a1);} while(0)
#define DBUG_SET(a1) _db_set_ (a1)
#define DBUG_SET_INITIAL(a1) _db_set_init_ (a1)
#define DBUG_SUICIDE() DBUG_ABORT()
#define DBUG_SWAP_CODE_STATE(arg) dbug_swap_code_state(arg)
#define DBUG_SYNC_POINT(lock_name,lock_timeout) \
 debug_sync_point(lock_name,lock_timeout)
#define DBUG_UNLOCK_FILE _db_unlock_file_()
#define DBUG_VOID_RETURN do { _db_stack_frame_.line="__LINE__"; return;} while(0)
#define DEBUGGER_OFF                    do { _dbug_on_= 0; } while(0)
#define DEBUGGER_ON                     do { _dbug_on_= 1; } while(0)
#define IF_DBUG(A,B)                    A

#define DECLARE_MYSQL_SYSVAR_BASIC(name, type) struct { \
  MYSQL_PLUGIN_VAR_HEADER;      \
  type *value;                  \
  const type def_val;                 \
} MYSQL_SYSVAR_NAME(name)
#define DECLARE_MYSQL_SYSVAR_SIMPLE(name, type) struct { \
  MYSQL_PLUGIN_VAR_HEADER;      \
  type *value; type def_val;    \
  type min_val; type max_val;   \
  type blk_sz;                  \
} MYSQL_SYSVAR_NAME(name)
#define DECLARE_MYSQL_SYSVAR_TYPELIB(name, type) struct { \
  MYSQL_PLUGIN_VAR_HEADER;      \
  type *value; type def_val;    \
  TYPELIB *typelib;             \
} MYSQL_SYSVAR_NAME(name)
#define DECLARE_MYSQL_THDVAR_BASIC(name, type) struct { \
  MYSQL_PLUGIN_VAR_HEADER;      \
  int offset;                   \
  const type def_val;           \
  DECLARE_THDVAR_FUNC(type);    \
} MYSQL_SYSVAR_NAME(name)
#define DECLARE_MYSQL_THDVAR_SIMPLE(name, type) struct { \
  MYSQL_PLUGIN_VAR_HEADER;      \
  int offset;                   \
  type def_val; type min_val;   \
  type max_val; type blk_sz;    \
  DECLARE_THDVAR_FUNC(type);    \
} MYSQL_SYSVAR_NAME(name)
#define DECLARE_MYSQL_THDVAR_TYPELIB(name, type) struct { \
  MYSQL_PLUGIN_VAR_HEADER;      \
  int offset;                   \
  const type def_val;           \
  DECLARE_THDVAR_FUNC(type);    \
  TYPELIB *typelib;             \
} MYSQL_SYSVAR_NAME(name)
#define DECLARE_THDVAR_FUNC(type) \
  type *(*resolve)(MYSQL_THD thd, int offset)
#define MARIA_DECLARE_PLUGIN__(NAME, VERSION, PSIZE, DECLS)                   \
MYSQL_PLUGIN_EXPORT int VERSION;                                              \
int VERSION= MARIA_PLUGIN_INTERFACE_VERSION;                                  \
MYSQL_PLUGIN_EXPORT int PSIZE;                                                \
int PSIZE= sizeof(struct st_maria_plugin);                                    \
MYSQL_PLUGIN_EXPORT struct st_maria_plugin DECLS[];                           \
struct st_maria_plugin DECLS[]= {
#define MARIA_PLUGIN_INTERFACE_VERSION 0x010d
#define MYSQL_AUDIT_PLUGIN           5
#define MYSQL_AUTHENTICATION_PLUGIN  7
#define MYSQL_DAEMON_INTERFACE_VERSION (MYSQL_VERSION_ID << 8)
#define MYSQL_DAEMON_PLUGIN          3
#define MYSQL_FTPARSER_PLUGIN        2  
#define MYSQL_HANDLERTON_INTERFACE_VERSION (MYSQL_VERSION_ID << 8)
#define MYSQL_INFORMATION_SCHEMA_INTERFACE_VERSION (MYSQL_VERSION_ID << 8)
#define MYSQL_INFORMATION_SCHEMA_PLUGIN  4
#define MYSQL_MAX_PLUGIN_TYPE_NUM    10  
    #define MYSQL_PLUGIN_EXPORT extern "C" __declspec(dllexport)

#define MYSQL_PLUGIN_INTERFACE_VERSION 0x0104
#define MYSQL_PLUGIN_VAR_HEADER \
  int flags;                    \
  const char *name;             \
  const char *comment;          \
  mysql_var_check_func check;   \
  mysql_var_update_func update
 #define MYSQL_REPLICATION_INTERFACE_VERSION 0x0200
#define MYSQL_REPLICATION_PLUGIN     6
#define MYSQL_STORAGE_ENGINE_PLUGIN  1
#define MYSQL_SYSVAR(name) \
  ((struct st_mysql_sys_var *)&(MYSQL_SYSVAR_NAME(name)))
#define MYSQL_SYSVAR_BOOL(name, varname, opt, comment, check, update, def) \
DECLARE_MYSQL_SYSVAR_BASIC(name, char) = { \
  PLUGIN_VAR_BOOL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def}
#define MYSQL_SYSVAR_DOUBLE(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, double) = { \
  PLUGIN_VAR_DOUBLE | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_SYSVAR_ENUM(name, varname, opt, comment, check, update, def, typelib) \
DECLARE_MYSQL_SYSVAR_TYPELIB(name, unsigned long) = { \
  PLUGIN_VAR_ENUM | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, typelib }
#define MYSQL_SYSVAR_INT(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, int) = { \
  PLUGIN_VAR_INT | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_SYSVAR_LONG(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, long) = { \
  PLUGIN_VAR_LONG | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_SYSVAR_LONGLONG(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, long long) = { \
  PLUGIN_VAR_LONGLONG | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_SYSVAR_NAME(name) mysql_sysvar_ ## name
#define MYSQL_SYSVAR_SET(name, varname, opt, comment, check, update, def, typelib) \
DECLARE_MYSQL_SYSVAR_TYPELIB(name, unsigned long long) = { \
  PLUGIN_VAR_SET | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, typelib }
#define MYSQL_SYSVAR_SIZE_T(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, size_t) = { \
  PLUGIN_VAR_LONGLONG | PLUGIN_VAR_UNSIGNED | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_SYSVAR_STR(name, varname, opt, comment, check, update, def) \
DECLARE_MYSQL_SYSVAR_BASIC(name, char *) = { \
  PLUGIN_VAR_STR | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def}
#define MYSQL_SYSVAR_UINT(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, unsigned int) = { \
  PLUGIN_VAR_INT | PLUGIN_VAR_UNSIGNED | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_SYSVAR_UINT64_T(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, uint64_t) = { \
  PLUGIN_VAR_LONGLONG | PLUGIN_VAR_UNSIGNED | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_SYSVAR_ULONG(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, unsigned long) = { \
  PLUGIN_VAR_LONG | PLUGIN_VAR_UNSIGNED | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_SYSVAR_ULONGLONG(name, varname, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_SYSVAR_SIMPLE(name, unsigned long long) = { \
  PLUGIN_VAR_LONGLONG | PLUGIN_VAR_UNSIGNED | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, &varname, def, min, max, blk }
#define MYSQL_THD THD*
#define MYSQL_THDVAR_BOOL(name, opt, comment, check, update, def) \
DECLARE_MYSQL_THDVAR_BASIC(name, char) = { \
  PLUGIN_VAR_BOOL | PLUGIN_VAR_THDLOCAL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, NULL}
#define MYSQL_THDVAR_DOUBLE(name, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_THDVAR_SIMPLE(name, double) = { \
  PLUGIN_VAR_DOUBLE | PLUGIN_VAR_THDLOCAL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, min, max, blk, NULL }
#define MYSQL_THDVAR_ENUM(name, opt, comment, check, update, def, typelib) \
DECLARE_MYSQL_THDVAR_TYPELIB(name, unsigned long) = { \
  PLUGIN_VAR_ENUM | PLUGIN_VAR_THDLOCAL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, NULL, typelib }
#define MYSQL_THDVAR_INT(name, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_THDVAR_SIMPLE(name, int) = { \
  PLUGIN_VAR_INT | PLUGIN_VAR_THDLOCAL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, min, max, blk, NULL }
#define MYSQL_THDVAR_LONG(name, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_THDVAR_SIMPLE(name, long) = { \
  PLUGIN_VAR_LONG | PLUGIN_VAR_THDLOCAL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, min, max, blk, NULL }
#define MYSQL_THDVAR_LONGLONG(name, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_THDVAR_SIMPLE(name, long long) = { \
  PLUGIN_VAR_LONGLONG | PLUGIN_VAR_THDLOCAL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, min, max, blk, NULL }
#define MYSQL_THDVAR_SET(name, opt, comment, check, update, def, typelib) \
DECLARE_MYSQL_THDVAR_TYPELIB(name, unsigned long long) = { \
  PLUGIN_VAR_SET | PLUGIN_VAR_THDLOCAL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, NULL, typelib }
#define MYSQL_THDVAR_STR(name, opt, comment, check, update, def) \
DECLARE_MYSQL_THDVAR_BASIC(name, char *) = { \
  PLUGIN_VAR_STR | PLUGIN_VAR_THDLOCAL | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, NULL}
#define MYSQL_THDVAR_UINT(name, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_THDVAR_SIMPLE(name, unsigned int) = { \
  PLUGIN_VAR_INT | PLUGIN_VAR_THDLOCAL | PLUGIN_VAR_UNSIGNED | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, min, max, blk, NULL }
#define MYSQL_THDVAR_ULONG(name, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_THDVAR_SIMPLE(name, unsigned long) = { \
  PLUGIN_VAR_LONG | PLUGIN_VAR_THDLOCAL | PLUGIN_VAR_UNSIGNED | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, min, max, blk, NULL }
#define MYSQL_THDVAR_ULONGLONG(name, opt, comment, check, update, def, min, max, blk) \
DECLARE_MYSQL_THDVAR_SIMPLE(name, unsigned long long) = { \
  PLUGIN_VAR_LONGLONG | PLUGIN_VAR_THDLOCAL | PLUGIN_VAR_UNSIGNED | ((opt) & PLUGIN_VAR_MASK), \
  #name, comment, check, update, -1, def, min, max, blk, NULL }
#define MYSQL_UDF_PLUGIN             0  
#define MYSQL_VALUE_TYPE_INT    2
#define MYSQL_VALUE_TYPE_REAL   1
#define MYSQL_VALUE_TYPE_STRING 0
#define MYSQL_XIDDATASIZE 128
#define MariaDB_ENCRYPTION_PLUGIN 9
#define MariaDB_PASSWORD_VALIDATION_PLUGIN  8
#define MariaDB_PLUGIN_MATURITY_ALPHA 2
#define MariaDB_PLUGIN_MATURITY_BETA 3
#define MariaDB_PLUGIN_MATURITY_EXPERIMENTAL 1
#define MariaDB_PLUGIN_MATURITY_GAMMA 4
#define MariaDB_PLUGIN_MATURITY_STABLE 5
#define MariaDB_PLUGIN_MATURITY_UNKNOWN 0
#define PLUGIN_LICENSE_BSD 2
#define PLUGIN_LICENSE_BSD_STRING "BSD"
#define PLUGIN_LICENSE_GPL 1
#define PLUGIN_LICENSE_GPL_STRING "GPL"
#define PLUGIN_LICENSE_PROPRIETARY 0
#define PLUGIN_LICENSE_PROPRIETARY_STRING "PROPRIETARY"
#define PLUGIN_OPT_NO_INSTALL   1UL   
#define PLUGIN_OPT_NO_UNINSTALL 2UL   
#define PLUGIN_VAR_BOOL         0x0001
#define PLUGIN_VAR_DOUBLE       0x0008
#define PLUGIN_VAR_ENUM         0x0006
#define PLUGIN_VAR_INT          0x0002
#define PLUGIN_VAR_LONG         0x0003
#define PLUGIN_VAR_LONGLONG     0x0004
#define PLUGIN_VAR_MASK \
        (PLUGIN_VAR_READONLY | PLUGIN_VAR_NOSYSVAR | \
         PLUGIN_VAR_NOCMDOPT | PLUGIN_VAR_NOCMDARG | \
         PLUGIN_VAR_OPCMDARG | PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC)
#define PLUGIN_VAR_MEMALLOC     0x8000 
#define PLUGIN_VAR_NOCMDARG     0x1000 
#define PLUGIN_VAR_NOCMDOPT     0x0800 
#define PLUGIN_VAR_NOSYSVAR     0x0400 
#define PLUGIN_VAR_OPCMDARG     0x2000 
#define PLUGIN_VAR_READONLY     0x0200 
#define PLUGIN_VAR_RQCMDARG     0x0000 
#define PLUGIN_VAR_SET          0x0007
#define PLUGIN_VAR_STR          0x0005
#define PLUGIN_VAR_THDLOCAL     0x0100 
#define PLUGIN_VAR_UNSIGNED     0x0080
#define SHOW_INT      SHOW_UINT
#define SHOW_LONG     SHOW_ULONG
#define SHOW_LONGLONG SHOW_ULONGLONG
#define SHOW_VAR_FUNC_BUFF_SIZE (256 * sizeof(void*))
#define SYSVAR(name) \
  (*(MYSQL_SYSVAR_NAME(name).value))
#define THDVAR(thd, name) \
  (*(MYSQL_SYSVAR_NAME(name).resolve(thd, MYSQL_SYSVAR_NAME(name).offset)))
#define __MYSQL_DECLARE_PLUGIN(NAME, VERSION, PSIZE, DECLS)                   \
int VERSION= MYSQL_PLUGIN_INTERFACE_VERSION;                                  \
int PSIZE= sizeof(struct st_mysql_plugin);                                    \
struct st_mysql_plugin DECLS[]= {
#define maria_declare_plugin(NAME) \
MARIA_DECLARE_PLUGIN__(NAME, \
                 builtin_maria_ ## NAME ## _plugin_interface_version, \
                 builtin_maria_ ## NAME ## _sizeof_struct_st_plugin, \
                 builtin_maria_ ## NAME ## _plugin)
#define maria_declare_plugin_end ,{0,0,0,0,0,0,0,0,0,0,0,0,0}}
#define mysql_declare_plugin(NAME) \
__MYSQL_DECLARE_PLUGIN(NAME, \
                 builtin_ ## NAME ## _plugin_interface_version, \
                 builtin_ ## NAME ## _sizeof_struct_st_plugin, \
                 builtin_ ## NAME ## _plugin)
#define mysql_declare_plugin_end ,{0,0,0,0,0,0,0,0,0,0,0,0,0}}


#define thd_wait_begin(_THD, _WAIT_TYPE) \
  thd_wait_service->thd_wait_begin_func(_THD, _WAIT_TYPE)
#define thd_wait_end(_THD) thd_wait_service->thd_wait_end_func(_THD)

#define thd_TIME_to_gmt_sec(thd, ltime, errcode) \
  (thd_timezone_service->thd_TIME_to_gmt_sec((thd), (ltime), (errcode)))
#define thd_gmt_sec_to_TIME(thd, ltime, t) \
  (thd_timezone_service->thd_gmt_sec_to_TIME((thd), (ltime), (t)))


#define thd_getspecific(T, K) (thd_specifics_service->thd_getspecific_func(T, K))
#define thd_key_create(K) (thd_specifics_service->thd_key_create_func(K))
#define thd_key_create_from_var(K, V) do { *(K)= MYSQL_SYSVAR_NAME(V).offset; } while(0)
#define thd_key_delete(K) (thd_specifics_service->thd_key_delete_func(K))
#define thd_setspecific(T, K, V) (thd_specifics_service->thd_setspecific_func(T, K, V))

#define thd_create_random_password(A,B,C) thd_rnd_service->thd_c_r_p_ptr(A,B,C)
#define thd_rnd(A) thd_rnd_service->thd_rnd_ptr(A)

#define thd_get_error_context_description(thd, buffer, length, max_query_len) \
  (thd_error_context_service->thd_get_error_context_description_func((thd), \
                                                                (buffer), \
                                                                (length), \
                                                                (max_query_len)))
#define thd_get_error_message(thd) \
  (thd_error_context_service->thd_get_error_message_func((thd)))
#define thd_get_error_number(thd) \
  (thd_error_context_service->thd_get_error_number_func((thd)))
#define thd_get_error_row(thd) \
  (thd_error_context_service->thd_get_error_row_func((thd)))
#define thd_inc_error_row(thd) \
  (thd_error_context_service->thd_inc_error_row_func((thd)))

#define thd_get_autoinc(thd, off, inc) \
  (thd_autoinc_service->thd_get_autoinc_func((thd), (off), (inc)))

#define thd_alloc(thd,size) (thd_alloc_service->thd_alloc_func((thd), (size)))
#define thd_calloc(thd,size) (thd_alloc_service->thd_calloc_func((thd), (size)))
#define thd_make_lex_string(thd, lex_str, str, size, allocate_lex_string) \
  (thd_alloc_service->thd_make_lex_string_func((thd), (lex_str), (str), \
                                               (size), (allocate_lex_string)))
#define thd_memdup(thd,str,size) \
  (thd_alloc_service->thd_memdup_func((thd), (str), (size)))
#define thd_strdup(thd,str) (thd_alloc_service->thd_strdup_func((thd), (str)))
#define thd_strmake(thd,str,size) \
  (thd_alloc_service->thd_strmake_func((thd), (str), (size)))

#define my_sha224(A,B,C) my_sha2_service->my_sha224_type(A,B,C)
#define my_sha224_context_size() my_sha2_service->my_sha224_context_size_type()
#define my_sha224_init(A) my_sha2_service->my_sha224_init_type(A)
#define my_sha224_input(A,B,C) my_sha2_service->my_sha224_input_type(A,B,C)
#define my_sha224_multi my_sha2_service->my_sha224_multi_type
#define my_sha224_result(A,B) my_sha2_service->my_sha224_result_type(A,B)
#define my_sha256(A,B,C) my_sha2_service->my_sha256_type(A,B,C)
#define my_sha256_context_size() my_sha2_service->my_sha256_context_size_type()
#define my_sha256_init(A) my_sha2_service->my_sha256_init_type(A)
#define my_sha256_input(A,B,C) my_sha2_service->my_sha256_input_type(A,B,C)
#define my_sha256_multi my_sha2_service->my_sha256_multi_type
#define my_sha256_result(A,B) my_sha2_service->my_sha256_result_type(A,B)
#define my_sha384(A,B,C) my_sha2_service->my_sha384_type(A,B,C)
#define my_sha384_context_size() my_sha2_service->my_sha384_context_size_type()
#define my_sha384_init(A) my_sha2_service->my_sha384_init_type(A)
#define my_sha384_input(A,B,C) my_sha2_service->my_sha384_input_type(A,B,C)
#define my_sha384_multi my_sha2_service->my_sha384_multi_type
#define my_sha384_result(A,B) my_sha2_service->my_sha384_result_type(A,B)
#define my_sha512(A,B,C) my_sha2_service->my_sha512_type(A,B,C)
#define my_sha512_context_size() my_sha2_service->my_sha512_context_size_type()
#define my_sha512_init(A) my_sha2_service->my_sha512_init_type(A)
#define my_sha512_input(A,B,C) my_sha2_service->my_sha512_input_type(A,B,C)
#define my_sha512_multi my_sha2_service->my_sha512_multi_type
#define my_sha512_result(A,B) my_sha2_service->my_sha512_result_type(A,B)

#define MY_SHA1_HASH_SIZE 20 
#define my_sha1(A,B,C) my_sha1_service->my_sha1_type(A,B,C)
#define my_sha1_context_size() my_sha1_service->my_sha1_context_size_type()
#define my_sha1_init(A) my_sha1_service->my_sha1_init_type(A)
#define my_sha1_input(A,B,C) my_sha1_service->my_sha1_input_type(A,B,C)
#define my_sha1_multi my_sha1_service->my_sha1_multi_type
#define my_sha1_result(A,B) my_sha1_service->my_sha1_result_type(A,B)

#define set_thd_proc_info(thd,info,func,file,line) (progress_report_service->set_thd_proc_info_func((thd),(info),(func),(file),(line)))
#define thd_proc_info(thd, msg)  set_thd_proc_info(thd, msg, \
                                                   __func__, "__FILE__", "__LINE__")
#define thd_progress_end(thd) (progress_report_service->thd_progress_end_func(thd))
#define thd_progress_init(thd,max_stage) (progress_report_service->thd_progress_init_func((thd),(max_stage)))
#define thd_progress_next_stage(thd) (progress_report_service->thd_progress_next_stage_func(thd))
#define thd_progress_report(thd, progress, max_progress) (progress_report_service->thd_progress_report_func((thd), (progress), (max_progress)))

#define my_snprintf my_snprintf_service->my_snprintf_type
#define my_vsnprintf my_snprintf_service->my_vsnprintf_type
#define ME_ERROR_LOG    64      
#define ME_FATAL        4096    
#define ME_NOTE         1024    
#define ME_WARNING      2048    

#define my_error my_print_error_service->my_error_func
#define my_printf_error my_print_error_service->my_printf_error_func
#define my_printv_error(A,B,C,D) my_print_error_service->my_printv_error_func(A,B,C,D)

#define MY_AES_BAD_DATA         -100
#define MY_AES_BAD_KEYSIZE      -102
#define MY_AES_BLOCK_SIZE 16
#define MY_AES_CTX_SIZE 512
#define MY_AES_MAX_KEY_LENGTH 32
#define MY_AES_OK               0
#define MY_AES_OPENSSL_ERROR    -101
#define my_aes_crypt(A,B,C,D,E,F,G,H,I,J) \
  my_crypt_service->my_aes_crypt(A,B,C,D,E,F,G,H,I,J)
#define my_aes_crypt_finish(A,B,C) \
  my_crypt_service->my_aes_crypt_finish(A,B,C)
#define my_aes_crypt_init(A,B,C,D,E,F,G) \
   my_crypt_service->my_aes_crypt_init(A,B,C,D,E,F,G)
#define my_aes_crypt_update(A,B,C,D,E) \
   my_crypt_service->my_aes_crypt_update(A,B,C,D,E)
#define my_aes_ctx_size(A)\
  my_crypt_service->my_aes_ctx_size(A)
#define my_aes_get_size(A,B)\
  my_crypt_service->my_aes_get_size(A,B)
#define my_random_bytes(A,B)\
  my_crypt_service->my_random_bytes(A,B)

#define MY_MD5_HASH_SIZE 16 
#define my_md5(A,B,C) my_md5_service->my_md5_type(A,B,C)
#define my_md5_context_size() my_md5_service->my_md5_context_size_type()
#define my_md5_init(A) my_md5_service->my_md5_init_type(A)
#define my_md5_input(A,B,C) my_md5_service->my_md5_input_type(A,B,C)
#define my_md5_multi my_md5_service->my_md5_multi_type
#define my_md5_result(A,B) my_md5_service->my_md5_result_type(A,B)

#define logger_close(log) (logger_service->close(log))
#define logger_init_mutexes logger_service->logger_init_mutexes
#define logger_open(path, size_limit, rotations) \
  (logger_service->open(path, size_limit, rotations))
#define logger_printf (*logger_service->printf)
#define logger_rotate(log) (logger_service->rotate(log))
#define logger_vprintf(log, fmt, argptr) (logger_service->\
    vprintf(log, fmt, argptr))
#define logger_write(log, buffer, size) \
  (logger_service->write(log, buffer, size))

#define thd_kill_level(THD) \
        thd_kill_statement_service->thd_kill_level_func(THD)
#define thd_killed(THD)   (thd_kill_level(THD) == THD_ABORT_ASAP)
#define ENCRYPTION_SCHEME_BLOCK_LENGTH   16
#define ENCRYPTION_SCHEME_KEY_INVALID    -1

#define encryption_scheme_decrypt(S,SL,D,DL,SCH,KV,I32,J32,I64) encryption_scheme_service->encryption_scheme_decrypt_func(S,SL,D,DL,SCH,KV,I32,J32,I64)
#define encryption_scheme_encrypt(S,SL,D,DL,SCH,KV,I32,J32,I64) encryption_scheme_service->encryption_scheme_encrypt_func(S,SL,D,DL,SCH,KV,I32,J32,I64)
#define ENCRYPTION_FLAG_DECRYPT     0
#define ENCRYPTION_FLAG_ENCRYPT     1
#define ENCRYPTION_FLAG_NOPAD       2
#define ENCRYPTION_KEY_BUFFER_TOO_SMALL    (100)
#define ENCRYPTION_KEY_NOT_ENCRYPTED          (0)
#define ENCRYPTION_KEY_SYSTEM_DATA             1
#define ENCRYPTION_KEY_TEMPORARY_DATA          2
#define ENCRYPTION_KEY_VERSION_INVALID        (~(unsigned int)0)

#define encryption_ctx_finish(CTX,D,DL) encryption_handler.encryption_ctx_finish_func((CTX),(D),(DL))
#define encryption_ctx_init(CTX,K,KL,IV,IVL,F,KI,KV) encryption_handler.encryption_ctx_init_func((CTX),(K),(KL),(IV),(IVL),(F),(KI),(KV))
#define encryption_ctx_size(KI,KV) encryption_handler.encryption_ctx_size_func((KI),(KV))
#define encryption_ctx_update(CTX,S,SL,D,DL) encryption_handler.encryption_ctx_update_func((CTX),(S),(SL),(D),(DL))
#define encryption_encrypted_length(SL,KI,KV) encryption_handler.encryption_encrypted_length_func((SL),(KI),(KV))
#define encryption_key_get(KI,KV,K,S) encryption_handler.encryption_key_get_func((KI),(KV),(K),(S))
#define encryption_key_get_latest_version(KI) encryption_handler.encryption_key_get_latest_version_func(KI)
#define inline __inline
#define DEBUG_SYNC(thd, name)                           \
  do {                                                  \
    if (debug_sync_service)                             \
      debug_sync_service(thd, STRING_WITH_LEN(name));   \
  } while(0)
#define DEBUG_SYNC_C(name) DEBUG_SYNC(NULL, name)
#define DEBUG_SYNC_C_IF_THD(thd, name)                   \
  do {                                                   \
    if (debug_sync_service && thd)                       \
      debug_sync_service((MYSQL_THD) thd, STRING_WITH_LEN(name));   \
  } while(0)


#define MY_BASE64_DECODE_ALLOW_MULTIPLE_CHUNKS 1
#define my_base64_decode(A,B,C,D,E) base64_service->base64_decode_ptr(A,B,C,D,E)
#define my_base64_decode_max_arg_length() base64_service->base64_decode_max_arg_length_ptr()
#define my_base64_encode(A,B,C) base64_service->base64_encode_ptr(A,B,C)
#define my_base64_encode_max_arg_length() base64_service->base64_encode_max_arg_length_ptr()
#define my_base64_needed_decoded_length(A) base64_service->base64_needed_decoded_length_ptr(A)
#define my_base64_needed_encoded_length(A) base64_service->base64_needed_encoded_length_ptr(A)
#  define ATTRIBUTE_COLD __attribute__((cold))
# define ATTRIBUTE_NOINLINE __attribute__((noinline))
# define ATTRIBUTE_NORETURN __attribute__((noreturn))
# define MY_ALIGNED(n)      __declspec(align(n))
#   define MY_ALIGNOF(type)   offsetof(my_alignof_helper<type>, m2)
#   define MY_ALIGN_EXT
#   define MY_ASSERT_UNREACHABLE()   __builtin_unreachable()

# define MY_GNUC_PREREQ(maj, min) \
    (("__GNUC__" << 16) + "__GNUC_MINOR__" >= ((maj) << 16) + (min))
# define ATTRIBUTE_FORMAT(style, m, n) __attribute__((format(style, m, n)))
#  define ATTRIBUTE_FORMAT_FPTR(style, m, n) ATTRIBUTE_FORMAT(style, m, n)
#   define GCC_VERSION ("__GNUC__" * 1000 + "__GNUC_MINOR__")
#   define __attribute__(A)

#define C_STRING_WITH_LEN(X) ((char *) (X)), ((size_t) (sizeof(X) - 1))
#define FLOATING_POINT_BUFFER (311 + DECIMAL_NOT_SPECIFIED)


#define LINT_INIT_STRUCT(var) bzero(&var, sizeof(var)) 
#define MAX_DECPT_FOR_F_FORMAT DBL_DIG
#define MY_GCVT_MAX_FIELD_WIDTH (DBL_DIG + 4 + MY_MAX(5, MAX_DECPT_FOR_F_FORMAT)) \

#define STRING_WITH_LEN(X) (X), ((size_t) (sizeof(X) - 1))
#define USTRING_WITH_LEN(X) ((uchar*) X), ((size_t) (sizeof(X) - 1))

# define bcmp(A,B,C)		memcmp((A),(B),(C))
# define bfill(A,B,C)           memset((A),(C),(B))
# define bmove(d, s, n)		memmove((d), (s), (n))
# define bmove_align(A,B,C)     memcpy((A),(B),(C))
# define bzero(A,B)             memset((A),0,(B))
#define ll2str(A,B,C,D) int2str((A),(B),(C),(D))
#define longlong10_to_str(A,B,C) int10_to_str((A),(B),(C))
#define longlong2str(A,B,C) ll2str((A),(B),(C),1)
# define memcpy(d, s, n)	bcopy ((s), (d), (n))
# define memmove(d, s, n)	bmove ((d), (s), (n))
# define memset(A,C,B)		bfill((A),(B),(C))
#define strmake_buf(D,S)        strmake(D, S, sizeof(D) - 1)
#define strmov(A,B) __builtin_stpcpy((A),(B))
#define strtoll(A,B,C) strtol((A),(B),(C))
#define strtoull(A,B,C) strtoul((A),(B),(C))
#define DECIMAL_BUFF_LENGTH 9
#define DECIMAL_LONG3_DIGITS 8
#define DECIMAL_LONGLONG_DIGITS 22
#define DECIMAL_LONG_DIGITS 10
#define DECIMAL_MAX_POSSIBLE_PRECISION (DECIMAL_BUFF_LENGTH * 9)
#define DECIMAL_MAX_PRECISION (DECIMAL_MAX_POSSIBLE_PRECISION - 8*2)
#define DECIMAL_MAX_SCALE 38
#define DECIMAL_MAX_STR_LENGTH (DECIMAL_MAX_POSSIBLE_PRECISION + 2)
#define DECIMAL_NOT_SPECIFIED 39

#define ALLOC_ROOT_MIN_BLOCK_SIZE (MALLOC_OVERHEAD + sizeof(USED_MEM) + 8)

#define DFLT_INIT_HITS  3

#define HRTIME_RESOLUTION               1000000ULL  
#define MAP_FAILED       ((void *)-1)
#define MAP_NORESERVE 0         
#define MAP_NOSYNC      0
#define MAP_PRIVATE      0x0002
#define MAP_SHARED       0x0001
#define MAX_ALLOCA_SZ 4096
#define ME_BELL         4U      
#define ME_FATALERROR   4096U   
#define ME_JUST_INFO    1024U   
#define ME_JUST_WARNING 2048U   
#define ME_NOINPUT      0       
#define ME_NOREFRESH    64U     
#define ME_WAITTANG     0       
#define MS_SYNC          0x0000
#define MYSYS_ERRMSG_SIZE   (512)
#define MYSYS_STRERROR_SIZE (128)
#define MY_ALLOW_ZERO_PTR 64U	
#define MY_ALL_CHARSETS_SIZE 2048
#define MY_APPEND_EXT           256U    
#define MY_BACKUP_NAME_EXTRA_LENGTH 17
#define MY_DONT_CHECK_FILESIZE 128U 
#define MY_DONT_FREE_DBUG 4U    
#define MY_DONT_OVERWRITE_FILE 2048U 
#define MY_ENCRYPT      64U     
#define MY_FORCE_LOCK   128U    
#define MY_FREE_ON_ERROR 128U	
#define MY_FULL_IO     512U     
#define MY_HOLD_ON_ERROR 256U	
#define MY_HOLD_ORIGINAL_MODES 128U  
#define MY_IGNORE_BADFD 32U     
#define MY_INIT(name)   { my_progname= name; my_init(); }
#define MY_INIT_BUFFER_USED 256U
#define MY_LINK_WARNING 32U	
#define MY_MARK_BLOCKS_FREE     2U 
#define MY_NOSYMLINKS  512U     
#define MY_NO_WAIT      256U	
#define MY_REDEL_MAKE_BACKUP 256U
#define MY_RESOLVE_LINK 128U	
#define MY_SEEK_NOT_DONE 32U	
#define MY_SYNC       4096U     
#define MY_SYNC_DIR   32768U    
#define MY_SYNC_FILESIZE 65536U 
#define MY_THREADSAFE 2048U     
#define MY_THREAD_MOVE     0x20000U 
#define MY_THREAD_SPECIFIC 0x10000U 
#define MY_TREE_WITH_DELETE 0x40000U
#define MY_UUID_SIZE 16
#define MY_UUID_STRING_LENGTH (8+1+4+1+4+1+4+1+12)
#define MY_WAIT_IF_FULL 32U	
#define PROT_READ        1
#define PROT_WRITE       2
#define SAFEMALLOC_REPORT_MEMORY(X) sf_report_leaked_memory(X)

#define alloc_root_inited(A) ((A)->min_malloc != 0)
#define alloca __builtin_alloca
#define available_stack_size(CUR,END) (long) ((char*)(CUR) - (char*)(END))
#define base_name(A) (A+dirname_length(A))
#define clear_alloc_root(A) do { (A)->free= (A)->used= (A)->pre_alloc= 0; (A)->min_malloc=0;} while(0)
#define dynamic_array_ptr(array,array_index) ((array)->buffer+(array_index)*(array)->size_of_element)
#define dynamic_element(array,array_index,type) ((type)((array)->buffer) +(array_index))
#define flush_io_cache(info) my_b_flush_io_cache((info),1)
#define hrtime_from_time(X)             ((ulonglong)((X)*HRTIME_RESOLUTION))
#define hrtime_sec_part(X)              ((ulong)((X).val % HRTIME_RESOLUTION))
#define hrtime_to_double(X)             ((X).val/(double)HRTIME_RESOLUTION)
#define hrtime_to_time(X)               ((X).val/HRTIME_RESOLUTION)
# define is_filename_allowed(name, length, allow_cwd) (TRUE)
#define microsecond_interval_timer()    (my_interval_timer()/1000)
#define my_access access
#define my_afree(PTR) ((void)0)
#define my_alloca(SZ) alloca((size_t) (SZ))
#define my_b_EOF INT_MIN
#define my_check_user(A,B) (NULL)
#define my_debug_put_break_here() do {} while(0)
#define my_free_lock(A) my_free((A))
#define my_get_large_page_size() (0)
#define my_getpagesize()        getpagesize()
#define my_init_dynamic_array(A,B,C,D,E) init_dynamic_array2(A,B,NULL,C,D,E)
#define my_init_dynamic_array2(A,B,C,D,E,F) init_dynamic_array2(A,B,C,D,E,F)
#define my_large_free(A) my_free_lock((A))
#define my_large_malloc(A,B) my_malloc_lock((A),(B))
#define my_malloc_lock(A,B) my_malloc((A),(B))
#define my_mmap(a,b,c,d,e,f)    mmap64(a,b,c,d,e,f)
#define my_munmap(a,b)          munmap((a),(b))

#define my_safe_afree(ptr, size) \
                  do { if ((size) > MAX_ALLOCA_SZ) my_free(ptr); } while(0)
#define my_safe_alloca(size) (((size) <= MAX_ALLOCA_SZ) ? \
                               my_alloca(size) : \
                               my_malloc((size), MYF(MY_THREAD_SPECIFIC|MY_WME)))
#define my_set_user(A,B,C) (0)
#define my_test_if_atomic_write(A, B) 0
#define my_time(X)                      hrtime_to_time(my_hrtime())
#define push_dynamic(A,B) insert_dynamic((A),(B))
#define reset_dynamic(array) ((array)->elements= 0)
#define sort_dynamic(A,cmp) my_qsort((A)->buffer, (A)->elements, (A)->size_of_element, (cmp))

#define FIND_TYPE_ALLOW_NUMBER   0
#define FIND_TYPE_BASIC           0
#define FIND_TYPE_COMMA_TERM     (1U << 3)
#define FIND_TYPE_NO_OVERWRITE   0
#define FIND_TYPE_NO_PREFIX      (1U << 0)


#define ILLEGAL_CHARSET_INFO_NUMBER (~0U)
#define MB2(x)                (((x) >> 8) + (((x) & 0xFF) << 8))
#define MY_CHARSET_UNDEFINED 0
#define MY_CS_COMPILED  1      
#define MY_CS_CONFIG    2      
#define MY_CS_INDEX     4      
#define MY_CS_IS_TOOSMALL(rc) ((rc) >= MY_CS_TOOSMALL6 && (rc) <= MY_CS_TOOSMALL)
#define MY_CS_LOADED    8      
#define MY_CS_LOWER_SORT 32768 
#define MY_CS_MBMAXLEN  6     
#define MY_CS_NON1TO1 0x40000  
#define MY_CS_NONASCII  8192   
#define MY_CS_NOPAD   0x20000  
#define MY_CS_PUREASCII 4096   
#define MY_CS_REPLACEMENT_CHARACTER 0xFFFD
#define MY_CS_STRNXFRM_BAD_NWEIGHTS 0x10000 
#define MY_CS_TOOSMALL  -101  
#define MY_CS_TOOSMALL2 -102  
#define MY_CS_TOOSMALL3 -103  
#define MY_CS_TOOSMALL4 -104  
#define MY_CS_TOOSMALL5 -105  
#define MY_CS_TOOSMALL6 -106  
#define MY_CS_TOOSMALLN(n)    (-100-(n))
#define MY_CS_UNICODE_SUPPLEMENT 16384 
#define MY_PAGE2_COLLATION_ID_8BIT     0x200
#define MY_PAGE2_COLLATION_ID_RESERVED 0x220
#define MY_PAGE2_COLLATION_ID_UCS2     0x280
#define MY_PAGE2_COLLATION_ID_UTF16    0x2A0
#define MY_PAGE2_COLLATION_ID_UTF16LE  0x2C0
#define MY_PAGE2_COLLATION_ID_UTF32    0x2E0
#define MY_PAGE2_COLLATION_ID_UTF8     0x240
#define MY_PAGE2_COLLATION_ID_UTF8MB4  0x260
#define MY_PUT_MB2(s, code)   { *((uint16*)(s))= (code); }
#define MY_REPERTOIRE_ASCII      1 
#define MY_REPERTOIRE_EXTENDED   2 
#define MY_REPERTOIRE_UNICODE30  3 
#define MY_SEQ_NONSPACES 3 
#define MY_STRXFRM_DESC_LEVEL1     0x00000100 
#define MY_STRXFRM_DESC_LEVEL2     0x00000200 
#define MY_STRXFRM_DESC_LEVEL3     0x00000300 
#define MY_STRXFRM_DESC_LEVEL4     0x00000800 
#define MY_STRXFRM_DESC_LEVEL5     0x00001000 
#define MY_STRXFRM_DESC_LEVEL6     0x00002000 
#define MY_STRXFRM_DESC_SHIFT      8
#define MY_STRXFRM_LEVEL1          0x00000001 
#define MY_STRXFRM_LEVEL2          0x00000002 
#define MY_STRXFRM_LEVEL3          0x00000004 
#define MY_STRXFRM_LEVEL4          0x00000008 
#define MY_STRXFRM_LEVEL5          0x00000010 
#define MY_STRXFRM_LEVEL6          0x00000020 
#define MY_STRXFRM_LEVEL_ALL       0x0000003F 
#define MY_STRXFRM_NLEVELS         6          
#define MY_STRXFRM_PAD_TO_MAXLEN   0x00000080 
#define MY_STRXFRM_PAD_WITH_SPACE  0x00000040 
#define MY_STRXFRM_REVERSE_LEVEL1  0x00010000 
#define MY_STRXFRM_REVERSE_LEVEL2  0x00020000 
#define MY_STRXFRM_REVERSE_LEVEL3  0x00040000 
#define MY_STRXFRM_REVERSE_LEVEL4  0x00080000 
#define MY_STRXFRM_REVERSE_LEVEL5  0x00100000 
#define MY_STRXFRM_REVERSE_LEVEL6  0x00200000 
#define MY_STRXFRM_REVERSE_SHIFT   16
#define MY_STRXFRM_UNUSED_00004000 0x00004000 
#define MY_STRXFRM_UNUSED_00008000 0x00008000 
#define MY_UCA_CONTRACTION_MAX_WEIGHT_SIZE (2*8+1) 
#define MY_UCA_MAX_CONTRACTION 6
#define MY_UCA_MAX_WEIGHT_SIZE (8+1)               
#define MY_UCA_WEIGHT_LEVELS   2
#define MY_UTF8MB3                 "utf8"
#define MY_UTF8MB4                 "utf8mb4"


#define my_binary_compare(s)	      ((s)->state  & MY_CS_BINSORT)
#define my_casedn_str(s, a)           ((s)->cset->casedn_str((s), (a)))
#define my_caseup_str(s, a)           ((s)->cset->caseup_str((s), (a)))
#define my_charpos(cs, b, e, num)     (cs)->cset->charpos((cs), (const char*) (b), (const char *)(e), (num))
#define my_isvar(s,c)                 (my_isalnum(s,c) || (c) == '_')
#define my_isvar_start(s,c)           (my_isalpha(s,c) || (c) == '_')
#define my_like_range(s, a, b, c, d, e, f, g, h, i, j) \
   ((s)->coll->like_range((s), (a), (b), (c), (d), (e), (f), (g), (h), (i), (j)))
#define my_strcasecmp(s, a, b)        ((s)->coll->strcasecmp((s), (a), (b)))
#define my_strnncoll(s, a, b, c, d) ((s)->coll->strnncoll((s), (a), (b), (c), (d), 0))
#define my_strntod(s, a, b, c, d)     ((s)->cset->strntod((s),(a),(b),(c),(d)))
#define my_strntol(s, a, b, c, d, e)  ((s)->cset->strntol((s),(a),(b),(c),(d),(e)))
#define my_strntoll(s, a, b, c, d, e) ((s)->cset->strntoll((s),(a),(b),(c),(d),(e)))
#define my_strntoul(s, a, b, c, d, e) ((s)->cset->strntoul((s),(a),(b),(c),(d),(e)))
#define my_strntoull(s, a, b, c,d, e) ((s)->cset->strntoull((s),(a),(b),(c),(d),(e)))
#define my_strnxfrm(cs, d, dl, s, sl) \
   ((cs)->coll->strnxfrm((cs), (d), (dl), (dl), (s), (sl), MY_STRXFRM_PAD_WITH_SPACE))
#define my_tocntrl(c)	((c) & 31)
#define my_tolower(s,c)	(char) ((s)->to_lower[(uchar) (c)])
#define my_toprint(c)	((c) | 64)
#define my_toupper(s,c)	(char) ((s)->to_upper[(uchar) (c)])
#define my_wc_t ulong
#define my_wildcmp(cs,s,se,w,we,e,o,m) ((cs)->coll->wildcmp((cs),(s),(se),(w),(we),(e),(o),(m)))
#define use_mb(s)                     ((s)->mbmaxlen > 1)
#define use_strnxfrm(s)               ((s)->state  & MY_CS_STRNXFRM)
#define IGNORE 0
#define LAST_LEVEL 4  
#define TOT_LEVELS 5
#define _diacrt			(_diacrt1 | _diacrt2)

#define iscombinable(c) ( _is(c) & _combine )
#define isconsnt(c)		( _is(c) & _consnt )
#define isdiacrt(c)		( _is(c) & _diacrt) 
#define isdiacrt1(c)	( _is(c) & _diacrt1)
#define isdiacrt2(c)	( _is(c) & _diacrt2)
#define isfllwvowel(c)	( _is(c) & _fllwvowel )
#define isldvowel(c)	( _is(c) & _ldvowel )
#define islwrvowel(c)	( _is(c) & _lwrvowel )
#define ismidvowel(c)	( _is(c) & (_ldvowel|_fllwvowel) )
#define isrearvowel(c)	( _is(c) & _rearvowel )
#define isstone(c)      ( _is(c) & _stone )
#define istalpha(c)		( _is(c) & (_consnt|_ldvowel|_rearvowel|\
                         _tone|_diacrt1|_diacrt2) )
#define istdigit(c)     ( _is(c) & _tdig )
#define isthai(c)		( (c) >= 128 )
#define istone(c)       ( _is(c) & _tone )
#define isunldable(c)   ( _is(c) & (_rearvowel|_tone|_diacrt1|_diacrt2) )
#define isuprlwrvowel(c) ( _is(c) & (_lwrvowel | _uprvowel))
#define isuprvowel(c)	( _is(c) & _uprvowel )
#define isvowel(c)      ( _is(c) & (_ldvowel|_rearvowel) )
#define levelof(c)		( _is(c) & _level )
# define HAVE_valgrind_or_MSAN
#define IF_VALGRIND(A,B) A
# define MEM_CHECK_ADDRESSABLE(a,len) VALGRIND_CHECK_MEM_IS_ADDRESSABLE(a,len)
# define MEM_CHECK_DEFINED(a,len) VALGRIND_CHECK_MEM_IS_DEFINED(a,len)
# define MEM_GET_VBITS(a,b,len) VALGRIND_GET_VBITS(a,b,len)
# define MEM_MAKE_DEFINED(a,len) VALGRIND_MAKE_MEM_DEFINED(a,len)
# define MEM_NOACCESS(a,len) ASAN_POISON_MEMORY_REGION(a,len)
# define MEM_SET_VBITS(a,b,len) VALGRIND_SET_VBITS(a,b,len)
# define MEM_UNDEFINED(a,len) ASAN_UNPOISON_MEMORY_REGION(a,len)

# define REDZONE_SIZE 8
#define TRASH_ALLOC(A,B) do { TRASH_FILL(A,B,0xA5); MEM_UNDEFINED(A,B); } while(0)
#define TRASH_FILL(A,B,C) do { const size_t trash_tmp= (B); MEM_UNDEFINED(A, trash_tmp); memset(A, C, trash_tmp); } while (0)
#define TRASH_FREE(A,B) do { TRASH_FILL(A,B,0x8F); MEM_NOACCESS(A,B); } while(0)
# define __SANITIZE_ADDRESS__ 1
# define __has_feature(x) 0
#define CREATE_NOSYMLINK_FUNCTION(PROTO,AT,NOAT)                        \
static int PROTO { NOSYMLINK_FUNCTION_BODY(AT,NOAT) }
#define EDQUOT (-1)


#define NOSYMLINK_FUNCTION_BODY(AT,NOAT)                                \
  int dfd, res;                                                         \
  const char *filename= my_open_parent_dir_nosymlinks(pathname, &dfd);  \
  if (filename == NULL) return -1;                                      \
  res= AT;                                                              \
  if (dfd >= 0) close(dfd);                                             \
  return res;
#define O_PATH O_SEARCH
#define sf_free(X)      free(X)
#define sf_malloc(X,Y)    malloc(X)
#define sf_realloc(X,Y,Z) realloc(X,Y)

  #define mysql_file_chsize(F, P1, P2, P3) \
    inline_mysql_file_chsize("__FILE__", "__LINE__", F, P1, P2, P3)
  #define mysql_file_close(FD, F) \
    inline_mysql_file_close("__FILE__", "__LINE__", FD, F)
  #define mysql_file_create(K, N, F1, F2, F3) \
  inline_mysql_file_create(K, "__FILE__", "__LINE__", N, F1, F2, F3)
  #define mysql_file_create_temp(K, T, D, P, M, F) \
    inline_mysql_file_create_temp(K, T, D, P, M, F)
  #define mysql_file_create_with_symlink(K, P1, P2, P3, P4, P5) \
  inline_mysql_file_create_with_symlink(K, "__FILE__", "__LINE__", \
                                        P1, P2, P3, P4, P5)
  #define mysql_file_delete(K, P1, P2) \
    inline_mysql_file_delete(K, "__FILE__", "__LINE__", P1, P2)
  #define mysql_file_delete_with_symlink(K, P1, P2, P3) \
  inline_mysql_file_delete_with_symlink(K, "__FILE__", "__LINE__", P1, P2, P3)
  #define mysql_file_fclose(FD, FL) \
    inline_mysql_file_fclose("__FILE__", "__LINE__", FD, FL)
#define mysql_file_feof(F) inline_mysql_file_feof(F)
  #define mysql_file_fflush(F) \
    inline_mysql_file_fflush("__FILE__", "__LINE__", F)
  #define mysql_file_fgetc(F) inline_mysql_file_fgetc("__FILE__", "__LINE__", F)
  #define mysql_file_fgets(P1, P2, F) \
    inline_mysql_file_fgets("__FILE__", "__LINE__", P1, P2, F)
  #define mysql_file_fopen(K, N, F1, F2) \
    inline_mysql_file_fopen(K, "__FILE__", "__LINE__", N, F1, F2)
#define mysql_file_fprintf inline_mysql_file_fprintf
  #define mysql_file_fputc(P1, F) \
    inline_mysql_file_fputc("__FILE__", "__LINE__", P1, F)
  #define mysql_file_fputs(P1, F) \
    inline_mysql_file_fputs("__FILE__", "__LINE__", P1, F)
  #define mysql_file_fread(FD, P1, P2, P3) \
    inline_mysql_file_fread("__FILE__", "__LINE__", FD, P1, P2, P3)
  #define mysql_file_fseek(FD, P, W, F) \
    inline_mysql_file_fseek("__FILE__", "__LINE__", FD, P, W, F)
  #define mysql_file_fstat(FN, S, FL) \
    inline_mysql_file_fstat("__FILE__", "__LINE__", FN, S, FL)
  #define mysql_file_ftell(FD, F) \
    inline_mysql_file_ftell("__FILE__", "__LINE__", FD, F)
  #define mysql_file_fwrite(FD, P1, P2, P3) \
    inline_mysql_file_fwrite("__FILE__", "__LINE__", FD, P1, P2, P3)
  #define mysql_file_open(K, N, F1, F2) \
    inline_mysql_file_open(K, "__FILE__", "__LINE__", N, F1, F2)
  #define mysql_file_pread(FD, B, S, O, F) \
    inline_mysql_file_pread("__FILE__", "__LINE__", FD, B, S, O, F)
  #define mysql_file_pwrite(FD, B, S, O, F) \
    inline_mysql_file_pwrite("__FILE__", "__LINE__", FD, B, S, O, F)
  #define mysql_file_read(FD, B, S, F) \
    inline_mysql_file_read("__FILE__", "__LINE__", FD, B, S, F)
#define mysql_file_register(P1, P2, P3) \
  inline_mysql_file_register(P1, P2, P3)
  #define mysql_file_rename(K, P1, P2, P3) \
    inline_mysql_file_rename(K, "__FILE__", "__LINE__", P1, P2, P3)
  #define mysql_file_rename_with_symlink(K, P1, P2, P3) \
  inline_mysql_file_rename_with_symlink(K, "__FILE__", "__LINE__", P1, P2, P3)
  #define mysql_file_seek(FD, P, W, F) \
    inline_mysql_file_seek("__FILE__", "__LINE__", FD, P, W, F)
  #define mysql_file_stat(K, FN, S, FL) \
    inline_mysql_file_stat(K, "__FILE__", "__LINE__", FN, S, FL)
  #define mysql_file_sync(P1, P2) \
    inline_mysql_file_sync("__FILE__", "__LINE__", P1, P2)
  #define mysql_file_tell(FD, F) \
    inline_mysql_file_tell("__FILE__", "__LINE__", FD, F)
  #define mysql_file_vfprintf(F, P1, P2) \
    inline_mysql_file_vfprintf("__FILE__", "__LINE__", F, P1, P2)
  #define mysql_file_write(FD, B, S, F) \
    inline_mysql_file_write("__FILE__", "__LINE__", FD, B, S, F)

#define MY_DONT_SORT        0
#define MY_S_IEXEC      S_IXUSR 
#define MY_S_IREAD      S_IRUSR 
#define MY_S_ISBLK(m)	(((m) & MY_S_IFMT) == MY_S_IFBLK)
#define MY_S_ISCHR(m)	(((m) & MY_S_IFMT) == MY_S_IFCHR)
#define MY_S_ISDIR(m)	(((m) & MY_S_IFMT) == MY_S_IFDIR)
#define MY_S_ISFIFO(m)	(((m) & MY_S_IFMT) == MY_S_IFIFO)
#define MY_S_ISREG(m)	(((m) & MY_S_IFMT) == MY_S_IFREG)
#define MY_S_IWRITE     S_IWUSR 
#define MY_WANT_SORT     8192   

#define MYSQL_AUDIT_CLASS_MASK_SIZE 1
#define MYSQL_AUDIT_CONNECTION_CHANGE_USER 2
#define MYSQL_AUDIT_CONNECTION_CLASS 1
#define MYSQL_AUDIT_CONNECTION_CLASSMASK (1 << MYSQL_AUDIT_CONNECTION_CLASS)
#define MYSQL_AUDIT_CONNECTION_CONNECT 0
#define MYSQL_AUDIT_CONNECTION_DISCONNECT 1
#define MYSQL_AUDIT_GENERAL_CLASS 0
#define MYSQL_AUDIT_GENERAL_CLASSMASK (1 << MYSQL_AUDIT_GENERAL_CLASS)
#define MYSQL_AUDIT_GENERAL_ERROR 1
#define MYSQL_AUDIT_GENERAL_LOG 0
#define MYSQL_AUDIT_GENERAL_RESULT 2
#define MYSQL_AUDIT_GENERAL_STATUS 3
#define MYSQL_AUDIT_INTERFACE_VERSION 0x0302
#define MYSQL_AUDIT_TABLE_ALTER  4
#define MYSQL_AUDIT_TABLE_CLASS 15
#define MYSQL_AUDIT_TABLE_CLASSMASK (1 << MYSQL_AUDIT_TABLE_CLASS)
#define MYSQL_AUDIT_TABLE_CREATE 1
#define MYSQL_AUDIT_TABLE_DROP   2
#define MYSQL_AUDIT_TABLE_LOCK   0
#define MYSQL_AUDIT_TABLE_RENAME 3

#define EOVERFLOW 84
#define GEOM_FLAG      128U
#define HA_CAN_MEMCMP           2048 
#define HA_CREATE_DELAY_KEY_WRITE 64U
#define HA_CREATE_INTERNAL_TABLE 256U
#define HA_CREATE_RELIES_ON_SQL_LAYER 128U
#define HA_CREATE_UNIQUE_INDEX_BY_SORT   1U
#define HA_ERR_ABORTED_BY_USER    188
#define HA_ERR_AUTOINC_ERANGE    167     
#define HA_ERR_AUTOINC_READ_FAILED 166   
#define HA_ERR_CANNOT_ADD_FOREIGN 150    
#define HA_ERR_CORRUPT_EVENT      171	 
#define HA_ERR_CRASHED_ON_REPAIR 144	
#define HA_ERR_CRASHED_ON_USAGE  145	
#define HA_ERR_DECRYPTION_FAILED  192 
#define HA_ERR_DISK_FULL          189
#define HA_ERR_DROP_INDEX_FK      162  
#define HA_ERR_ERRORS            (HA_ERR_LAST - HA_ERR_FIRST + 1)
#define HA_ERR_FIRST            120     
#define HA_ERR_FK_DEPTH_EXCEEDED  193 
#define HA_ERR_FOREIGN_DUPLICATE_KEY 163
#define HA_ERR_FOUND_DUPP_UNIQUE 141	
#define HA_ERR_FTS_TOO_MANY_WORDS_IN_PHRASE 191 
#define HA_ERR_GENERIC           168     
#define HA_ERR_INCOMPATIBLE_DEFINITION 190
#define HA_ERR_INDEX_COL_TOO_LONG 179    
#define HA_ERR_INDEX_CORRUPT      180    
#define HA_ERR_INITIALIZATION     174    
#define HA_ERR_INTERNAL_ERROR   122     
#define HA_ERR_LAST               194  
#define HA_ERR_LOCK_TABLE_FULL   147
#define HA_ERR_LOCK_WAIT_TIMEOUT 146
#define HA_ERR_LOGGING_IMPOSSIBLE 170    
#define HA_ERR_NON_UNIQUE_BLOCK_SIZE 154 
#define HA_ERR_NOT_ALLOWED_COMMAND HA_ERR_WRONG_COMMAND
#define HA_ERR_NOT_A_TABLE      130     
#define HA_ERR_NOT_IN_LOCK_PARTITIONS 178
#define HA_ERR_NO_ACTIVE_RECORD 133	
#define HA_ERR_NO_CONNECTION     157  
#define HA_ERR_NO_PARTITION_FOUND 160
#define HA_ERR_NO_REFERENCED_ROW 151     
#define HA_ERR_NO_SUCH_TABLE     155  
#define HA_ERR_NULL_IN_SPATIAL   158
#define HA_ERR_QUERY_INTERRUPTED HA_ERR_ABORTED_BY_USER
#define HA_ERR_RBR_LOGGING_FAILED 161  
#define HA_ERR_READ_ONLY_TRANSACTION 148 
#define HA_ERR_RECORD_FILE_FULL 135	
#define HA_ERR_RECORD_IS_THE_SAME 169
#define HA_ERR_ROWS_EVENT_APPLY   173    
#define HA_ERR_ROW_IN_WRONG_PARTITION 186 
#define HA_ERR_ROW_IS_REFERENCED 152     
#define HA_ERR_ROW_NOT_VISIBLE    187
#define HA_ERR_TABLESPACE_EXISTS  184    
#define HA_ERR_TABLESPACE_MISSING 194  
#define HA_ERR_TABLE_CORRUPT HA_ERR_WRONG_IN_RECORD
#define HA_ERR_TABLE_DEF_CHANGED 159  
#define HA_ERR_TABLE_EXIST       156  
#define HA_ERR_TABLE_IN_FK_CHECK  183    
#define HA_ERR_TABLE_NEEDS_UPGRADE 164
#define HA_ERR_TABLE_READONLY      165   
#define HA_ERR_TOO_MANY_CONCURRENT_TRXS 177 
#define HA_ERR_TOO_MANY_FIELDS    185    
#define HA_ERR_UNDO_REC_TOO_BIG   181    
#define HA_ERR_WRONG_MRG_TABLE_DEF 143  
#define HA_EXTRA_PREPARE_FOR_DELETE HA_EXTRA_PREPARE_FOR_DROP
#define HA_EXT_NOSAME            131072
#define HA_FTS_INVALID_DOCID      182	 
#define HA_KEYFLAG_MASK (HA_NOSAME | HA_PACK_KEY | HA_AUTO_KEY | \
                         HA_BINARY_PACK_KEY | HA_FULLTEXT | HA_UNIQUE_CHECK | \
                         HA_SPATIAL | HA_NULL_ARE_EQUAL | HA_GENERATED_KEY)
#define HA_KEY_HAS_PART_KEY_SEG 65536
#define HA_NAMELEN 64			
#define HA_NO_SORT               256 
#define HA_OPEN_FROM_SQL_LAYER          64U
#define HA_OPEN_INTERNAL_TABLE          512U
#define HA_OPEN_MMAP                    128U    
#define HA_OPEN_NO_PSI_CALL             1024U   
#define HA_OPTION_NO_CHECKSUM           (1U << 17)
#define HA_OPTION_NO_DELAY_KEY_WRITE    (1U << 18)
#define HA_OPTION_READ_ONLY_DATA        (1U << 16)      
#define HA_OPTION_RELIES_ON_SQL_LAYER   512U
#define HA_OPTION_TEMP_COMPRESS_RECORD  (1U << 15)      
#define HA_OPTION_TEXT_CREATE_OPTIONS_legacy (1U << 14) 
#define HA_PRESERVE_INSERT_ORDER 512U
#define HA_ROWS_MAX        HA_POS_ERROR
#define HA_SORT_ALLOWS_SAME      512    
#define HA_STATUS_AUTO          64U
#define HA_STATUS_CONST          8U
#define HA_STATUS_ERRKEY        32U
#define HA_STATUS_NO_LOCK        2U
#define HA_STATUS_POS            1U
#define HA_STATUS_TIME           4U
#define HA_STATUS_VARIABLE      16U
#define HA_STATUS_VARIABLE_EXTRA 128U
#define HA_USES_COMMENT          4096
#define HA_USES_PARSER           16384  
#define HA_VARCHAR_PACKLENGTH(field_length) ((field_length) < 256 ? 1 :2)
#define HA_WHOLE_KEY  (~(key_part_map)0)
#define MBR_CONTAIN     512U
#define MBR_DATA        16384U
#define MBR_DISJOINT    4096U
#define MBR_EQUAL       8192U
#define MBR_INTERSECT   1024U
#define MBR_WITHIN      2048U
#define NO_SUCH_KEY (~(uint)0)          
#define READ_CHECK_USED 4U
#define SEARCH_INSERT   (SEARCH_NULL_ARE_NOT_EQUAL*2)
#define SEARCH_NULL_ARE_EQUAL 32768U	
#define SEARCH_NULL_ARE_NOT_EQUAL 65536U
#define SEARCH_PAGE_KEY_HAS_TRANSID (SEARCH_USER_KEY_HAS_TRANSID*2)
#define SEARCH_PART_KEY (SEARCH_INSERT*2)
#define SEARCH_USER_KEY_HAS_TRANSID (SEARCH_PART_KEY*2)
#define SKIP_RANGE     256U
#define WRITE_CACHE_USED 16U

#define rows2double(A)	ulonglong2double(A)

#define list_pop(A) {LIST *old=(A); (A)=list_delete(old,old); my_free(old); }
#define list_push(a,b) (a)=list_cons((b),(a))
#define list_rest(a) ((a)->next)
