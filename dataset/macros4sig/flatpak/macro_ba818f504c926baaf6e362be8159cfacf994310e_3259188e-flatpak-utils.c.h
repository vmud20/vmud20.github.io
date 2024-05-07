
#include<sys/file.h>




#include<fcntl.h>



#include<string.h>
#include<termios.h>
#include<stdlib.h>



#include<sys/mman.h>


#include<sys/ioctl.h>
#include<errno.h>

#include<sys/utsname.h>

#include<sys/stat.h>






#include<ctype.h>



#include<stdio.h>
#include<sys/types.h>

#include<stdarg.h>

#include<unistd.h>

#define CALL_FN_W_10W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,  \
                                  arg7,arg8,arg9,arg10)           \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[11];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      _argvec[9] = (unsigned long)(arg9);                         \
      _argvec[10] = (unsigned long)(arg10);                       \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $8, %%esp\n\t"                                     \
         "pushl 40(%%eax)\n\t"                                    \
         "pushl 36(%%eax)\n\t"                                    \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_11W(lval, orig, arg1,arg2,arg3,arg4,arg5,       \
                                  arg6,arg7,arg8,arg9,arg10,      \
                                  arg11)                          \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[12];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      _argvec[9] = (unsigned long)(arg9);                         \
      _argvec[10] = (unsigned long)(arg10);                       \
      _argvec[11] = (unsigned long)(arg11);                       \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $4, %%esp\n\t"                                     \
         "pushl 44(%%eax)\n\t"                                    \
         "pushl 40(%%eax)\n\t"                                    \
         "pushl 36(%%eax)\n\t"                                    \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_12W(lval, orig, arg1,arg2,arg3,arg4,arg5,       \
                                  arg6,arg7,arg8,arg9,arg10,      \
                                  arg11,arg12)                    \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[13];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      _argvec[9] = (unsigned long)(arg9);                         \
      _argvec[10] = (unsigned long)(arg10);                       \
      _argvec[11] = (unsigned long)(arg11);                       \
      _argvec[12] = (unsigned long)(arg12);                       \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "pushl 48(%%eax)\n\t"                                    \
         "pushl 44(%%eax)\n\t"                                    \
         "pushl 40(%%eax)\n\t"                                    \
         "pushl 36(%%eax)\n\t"                                    \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_5W(lval, orig, arg1,arg2,arg3,arg4,arg5)        \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[6];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $12, %%esp\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_6W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6)   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[7];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $8, %%esp\n\t"                                     \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_7W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7)                            \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[8];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $4, %%esp\n\t"                                     \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_8W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7,arg8)                       \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[9];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_9W(lval, orig, arg1,arg2,arg3,arg4,arg5,arg6,   \
                                 arg7,arg8,arg9)                  \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[10];                         \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      _argvec[5] = (unsigned long)(arg5);                         \
      _argvec[6] = (unsigned long)(arg6);                         \
      _argvec[7] = (unsigned long)(arg7);                         \
      _argvec[8] = (unsigned long)(arg8);                         \
      _argvec[9] = (unsigned long)(arg9);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $12, %%esp\n\t"                                    \
         "pushl 36(%%eax)\n\t"                                    \
         "pushl 32(%%eax)\n\t"                                    \
         "pushl 28(%%eax)\n\t"                                    \
         "pushl 24(%%eax)\n\t"                                    \
         "pushl 20(%%eax)\n\t"                                    \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_W(lval, orig, arg1)                             \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[2];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $12, %%esp\n\t"                                    \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_WW(lval, orig, arg1,arg2)                       \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[3];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $8, %%esp\n\t"                                     \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_WWW(lval, orig, arg1,arg2,arg3)                 \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[4];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "subl $4, %%esp\n\t"                                     \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_WWWW(lval, orig, arg1,arg2,arg3,arg4)           \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[5];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      _argvec[1] = (unsigned long)(arg1);                         \
      _argvec[2] = (unsigned long)(arg2);                         \
      _argvec[3] = (unsigned long)(arg3);                         \
      _argvec[4] = (unsigned long)(arg4);                         \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "pushl 16(%%eax)\n\t"                                    \
         "pushl 12(%%eax)\n\t"                                    \
         "pushl 8(%%eax)\n\t"                                     \
         "pushl 4(%%eax)\n\t"                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_W_v(lval, orig)                                   \
   do {                                                           \
      volatile OrigFn        _orig = (orig);                      \
      volatile unsigned long _argvec[1];                          \
      volatile unsigned long _res;                                \
      _argvec[0] = (unsigned long)_orig.nraddr;                   \
      __asm__ volatile(                                           \
         VALGRIND_ALIGN_STACK                                     \
         "movl (%%eax), %%eax\n\t"              \
         VALGRIND_CALL_NOREDIR_EAX                                \
         VALGRIND_RESTORE_STACK                                   \
         :    "=a" (_res)                                  \
         :     "a" (&_argvec[0])                            \
         :  "cc", "memory", __CALLER_SAVED_REGS, "edi"   \
      );                                                          \
      lval = (__typeof__(lval)) _res;                             \
   } while (0)
#define CALL_FN_v_5W(fnptr, arg1,arg2,arg3,arg4,arg5)             \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_5W(_junk,fnptr,arg1,arg2,arg3,arg4,arg5); } while (0)
#define CALL_FN_v_6W(fnptr, arg1,arg2,arg3,arg4,arg5,arg6)        \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_6W(_junk,fnptr,arg1,arg2,arg3,arg4,arg5,arg6); } while (0)
#define CALL_FN_v_7W(fnptr, arg1,arg2,arg3,arg4,arg5,arg6,arg7)   \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_7W(_junk,fnptr,arg1,arg2,arg3,arg4,arg5,arg6,arg7); } while (0)
#define CALL_FN_v_W(fnptr, arg1)                                  \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_W(_junk,fnptr,arg1); } while (0)
#define CALL_FN_v_WW(fnptr, arg1,arg2)                            \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_WW(_junk,fnptr,arg1,arg2); } while (0)
#define CALL_FN_v_WWW(fnptr, arg1,arg2,arg3)                      \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_WWW(_junk,fnptr,arg1,arg2,arg3); } while (0)
#define CALL_FN_v_WWWW(fnptr, arg1,arg2,arg3,arg4)                \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_WWWW(_junk,fnptr,arg1,arg2,arg3,arg4); } while (0)
#define CALL_FN_v_v(fnptr)                                        \
   do { volatile unsigned long _junk;                             \
        CALL_FN_W_v(_junk,fnptr); } while (0)
#define I_REPLACE_SONAME_FNNAME_ZU(soname,fnname)                 \
   VG_CONCAT4(_vgr00000ZU_,soname,_,fnname)
#define I_REPLACE_SONAME_FNNAME_ZZ(soname,fnname)                 \
   VG_CONCAT4(_vgr00000ZZ_,soname,_,fnname)
#define I_WRAP_SONAME_FNNAME_ZU(soname,fnname)                    \
   VG_CONCAT4(_vgw00000ZU_,soname,_,fnname)
#define I_WRAP_SONAME_FNNAME_ZZ(soname,fnname)                    \
   VG_CONCAT4(_vgw00000ZZ_,soname,_,fnname)
#    define NVALGRIND 1
#  define PLAT_amd64_darwin 1
#  define PLAT_amd64_linux 1
#  define PLAT_amd64_solaris 1
#  define PLAT_amd64_win64 1
#  define PLAT_arm64_linux 1
#  define PLAT_arm_linux 1
#  define PLAT_mips32_linux 1
#  define PLAT_mips64_linux 1
#  define PLAT_ppc32_linux 1
#  define PLAT_ppc64be_linux 1
#  define PLAT_ppc64le_linux 1
#  define PLAT_s390x_linux 1
#  define PLAT_x86_darwin 1
#  define PLAT_x86_linux 1
#  define PLAT_x86_solaris 1
#  define PLAT_x86_win32 1
#define RUNNING_ON_VALGRIND                                           \
    (unsigned)VALGRIND_DO_CLIENT_REQUEST_EXPR(0 ,         \
                                    VG_USERREQ__RUNNING_ON_VALGRIND,  \
                                    0, 0, 0, 0, 0)                    \

#define VALGRIND_ALIGN_STACK               \
      "movl %%esp,%%edi\n\t"               \
      "andl $0xfffffff0,%%esp\n\t"
#define VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R11                   \
                     __SPECIAL_INSTRUCTION_PREAMBLE               \
                            \
                     "or 3,3,3\n\t"
#define VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R12                   \
                     __SPECIAL_INSTRUCTION_PREAMBLE               \
                            \
                     "or 3,3,3\n\t"
#define VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_R4                    \
                     __SPECIAL_INSTRUCTION_PREAMBLE               \
                             \
                     "orr r12, r12, r12\n\t"
#define VALGRIND_BRANCH_AND_LINK_TO_NOREDIR_X8                    \
                     __SPECIAL_INSTRUCTION_PREAMBLE               \
                               \
                     "orr x12, x12, x12\n\t"
#define VALGRIND_CALL_NOREDIR_EAX                                 \
                     __SPECIAL_INSTRUCTION_PREAMBLE               \
                                          \
                     "xchgl %%edx,%%edx\n\t"
#define VALGRIND_CALL_NOREDIR_R1                                 \
                    __SPECIAL_INSTRUCTION_PREAMBLE               \
                    __CALL_NO_REDIR_CODE
#define VALGRIND_CALL_NOREDIR_RAX                                 \
                     __SPECIAL_INSTRUCTION_PREAMBLE               \
                                          \
                     "xchgq %%rdx,%%rdx\n\t"
#define VALGRIND_CALL_NOREDIR_T9                                    \
                     __SPECIAL_INSTRUCTION_PREAMBLE                 \
                                              \
                     "or $15, $15, $15\n\t"
#  define VALGRIND_CFI_EPILOGUE                                   \
      "movq %%r15, %%rbp\n\t"                                     \
      ".cfi_restore_state\n\t"
#  define VALGRIND_CFI_PROLOGUE                                   \
      "movq %%rbp, %%r15\n\t"                                     \
      "movq %2, %%rbp\n\t"                                        \
      ".cfi_remember_state\n\t"                                   \
      ".cfi_def_cfa rbp, 0\n\t"
#define VALGRIND_COUNT_ERRORS                                     \
    (unsigned)VALGRIND_DO_CLIENT_REQUEST_EXPR(                    \
                               0 ,            \
                               VG_USERREQ__COUNT_ERRORS,          \
                               0, 0, 0, 0, 0)
#define VALGRIND_CREATE_MEMPOOL(pool, rzB, is_zeroed)             \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__CREATE_MEMPOOL,   \
                                    pool, rzB, is_zeroed, 0, 0)
#define VALGRIND_CREATE_MEMPOOL_EXT(pool, rzB, is_zeroed, flags)        \
   VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__CREATE_MEMPOOL,          \
                                   pool, rzB, is_zeroed, flags, 0)
#define VALGRIND_DESTROY_MEMPOOL(pool)                            \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__DESTROY_MEMPOOL,  \
                                    pool, 0, 0, 0, 0)
#define VALGRIND_DISABLE_ERROR_REPORTING                                \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__CHANGE_ERR_DISABLEMENT, \
                                    1, 0, 0, 0, 0)
#define VALGRIND_DISCARD_TRANSLATIONS(_qzz_addr,_qzz_len)              \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__DISCARD_TRANSLATIONS,  \
                                    _qzz_addr, _qzz_len, 0, 0, 0)
#define VALGRIND_DO_CLIENT_REQUEST(_zzq_rlval, _zzq_default,            \
                                   _zzq_request, _zzq_arg1, _zzq_arg2,  \
                                   _zzq_arg3, _zzq_arg4, _zzq_arg5)     \
  do { (_zzq_rlval) = VALGRIND_DO_CLIENT_REQUEST_EXPR((_zzq_default),   \
                        (_zzq_request), (_zzq_arg1), (_zzq_arg2),       \
                        (_zzq_arg3), (_zzq_arg4), (_zzq_arg5)); } while (0)
#define VALGRIND_DO_CLIENT_REQUEST_EXPR(                          \
        _zzq_default, _zzq_request,                               \
        _zzq_arg1, _zzq_arg2, _zzq_arg3, _zzq_arg4, _zzq_arg5)    \
      (_zzq_default)
#define VALGRIND_DO_CLIENT_REQUEST_STMT(_zzq_request, _zzq_arg1,        \
                           _zzq_arg2,  _zzq_arg3, _zzq_arg4, _zzq_arg5) \
  do { (void) VALGRIND_DO_CLIENT_REQUEST_EXPR(0,                        \
                    (_zzq_request), (_zzq_arg1), (_zzq_arg2),           \
                    (_zzq_arg3), (_zzq_arg4), (_zzq_arg5)); } while (0)
#define VALGRIND_ENABLE_ERROR_REPORTING                                 \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__CHANGE_ERR_DISABLEMENT, \
                                    -1, 0, 0, 0, 0)
#define VALGRIND_FREELIKE_BLOCK(addr, rzB)                              \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__FREELIKE_BLOCK,         \
                                    addr, rzB, 0, 0, 0)
#define VALGRIND_GET_NR_CONTEXT(_zzq_rlval)                         \
  { volatile OrigFn* _zzq_orig = &(_zzq_rlval);                     \
    volatile unsigned long int __addr;                              \
    __asm__ volatile(__SPECIAL_INSTRUCTION_PREAMBLE                 \
                                            \
                     "or $14, $14, $14\n\t"                         \
                     "move %0, $11"                       \
                     : "=r" (__addr)                                \
                     :                                              \
                     : "$11");                                      \
    _zzq_orig->nraddr = __addr;                                     \
  }
#define VALGRIND_GET_ORIG_FN(_lval)  VALGRIND_GET_NR_CONTEXT(_lval)
#define VALGRIND_INNER_THREADS(_qzz_addr)                               \
   VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__INNER_THREADS,           \
                                   _qzz_addr, 0, 0, 0, 0)
#define VALGRIND_LOAD_PDB_DEBUGINFO(fd, ptr, total_size, delta)     \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__LOAD_PDB_DEBUGINFO, \
                                    fd, ptr, total_size, delta, 0)
#define VALGRIND_MALLOCLIKE_BLOCK(addr, sizeB, rzB, is_zeroed)          \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__MALLOCLIKE_BLOCK,       \
                                    addr, sizeB, rzB, is_zeroed, 0)
#define VALGRIND_MAP_IP_TO_SRCLOC(addr, buf64)                    \
    (unsigned)VALGRIND_DO_CLIENT_REQUEST_EXPR(0,                  \
                               VG_USERREQ__MAP_IP_TO_SRCLOC,      \
                               addr, buf64, 0, 0, 0)
#define VALGRIND_MEMPOOL_ALLOC(pool, addr, size)                  \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__MEMPOOL_ALLOC,    \
                                    pool, addr, size, 0, 0)
#define VALGRIND_MEMPOOL_AUTO_FREE  1
#define VALGRIND_MEMPOOL_CHANGE(pool, addrA, addrB, size)         \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__MEMPOOL_CHANGE,   \
                                    pool, addrA, addrB, size, 0)
#define VALGRIND_MEMPOOL_EXISTS(pool)                             \
    (unsigned)VALGRIND_DO_CLIENT_REQUEST_EXPR(0,                  \
                               VG_USERREQ__MEMPOOL_EXISTS,        \
                               pool, 0, 0, 0, 0)
#define VALGRIND_MEMPOOL_FREE(pool, addr)                         \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__MEMPOOL_FREE,     \
                                    pool, addr, 0, 0, 0)
#define VALGRIND_MEMPOOL_METAPOOL   2
#define VALGRIND_MEMPOOL_TRIM(pool, addr, size)                   \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__MEMPOOL_TRIM,     \
                                    pool, addr, size, 0, 0)
#define VALGRIND_MONITOR_COMMAND(command)                               \
   VALGRIND_DO_CLIENT_REQUEST_EXPR(0, VG_USERREQ__GDB_MONITOR_COMMAND, \
                                   command, 0, 0, 0, 0)
#define VALGRIND_MOVE_MEMPOOL(poolA, poolB)                       \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__MOVE_MEMPOOL,     \
                                    poolA, poolB, 0, 0, 0)
#define VALGRIND_NON_SIMD_CALL0(_qyy_fn)                          \
    VALGRIND_DO_CLIENT_REQUEST_EXPR(0 ,       \
                                    VG_USERREQ__CLIENT_CALL0,     \
                                    _qyy_fn,                      \
                                    0, 0, 0, 0)
#define VALGRIND_NON_SIMD_CALL1(_qyy_fn, _qyy_arg1)                    \
    VALGRIND_DO_CLIENT_REQUEST_EXPR(0 ,            \
                                    VG_USERREQ__CLIENT_CALL1,          \
                                    _qyy_fn,                           \
                                    _qyy_arg1, 0, 0, 0)
#define VALGRIND_NON_SIMD_CALL2(_qyy_fn, _qyy_arg1, _qyy_arg2)         \
    VALGRIND_DO_CLIENT_REQUEST_EXPR(0 ,            \
                                    VG_USERREQ__CLIENT_CALL2,          \
                                    _qyy_fn,                           \
                                    _qyy_arg1, _qyy_arg2, 0, 0)
#define VALGRIND_NON_SIMD_CALL3(_qyy_fn, _qyy_arg1, _qyy_arg2, _qyy_arg3) \
    VALGRIND_DO_CLIENT_REQUEST_EXPR(0 ,             \
                                    VG_USERREQ__CLIENT_CALL3,           \
                                    _qyy_fn,                            \
                                    _qyy_arg1, _qyy_arg2,               \
                                    _qyy_arg3, 0)
#define VALGRIND_RESIZEINPLACE_BLOCK(addr, oldSizeB, newSizeB, rzB)     \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__RESIZEINPLACE_BLOCK,    \
                                    addr, oldSizeB, newSizeB, rzB, 0)
#define VALGRIND_RESTORE_STACK             \
      "movl %%edi,%%esp\n\t"
#define VALGRIND_STACK_CHANGE(id, start, end)                     \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__STACK_CHANGE,     \
                                    id, start, end, 0, 0)
#define VALGRIND_STACK_DEREGISTER(id)                             \
    VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__STACK_DEREGISTER, \
                                    id, 0, 0, 0, 0)
#define VALGRIND_STACK_REGISTER(start, end)                       \
    (unsigned)VALGRIND_DO_CLIENT_REQUEST_EXPR(0,                  \
                               VG_USERREQ__STACK_REGISTER,        \
                               start, end, 0, 0, 0)
#define VALGRIND_VEX_INJECT_IR()                                    \
 do {                                                               \
    __asm__ volatile(__SPECIAL_INSTRUCTION_PREAMBLE                 \
                     "or $11, $11, $11\n\t"                         \
                    );                                              \
 } while (0)
#define VG_CONCAT4(_aa,_bb,_cc,_dd) _aa##_bb##_cc##_dd
#define VG_IS_TOOL_USERREQ(a, b, v) \
   (VG_USERREQ_TOOL_BASE(a,b) == ((v) & 0xffff0000))
#define VG_USERREQ_TOOL_BASE(a,b) \
   ((unsigned int)(((a)&0xff) << 24 | ((b)&0xff) << 16))
#define __CALLER_SAVED_REGS  "ecx", "edx"
#define __CALL_NO_REDIR_CODE  "lr 4,4\n\t"
#define __CLIENT_REQUEST_CODE "lr 2,2\n\t"
#  define __FRAME_POINTER                                         \
      ,"r"(__builtin_dwarf_cfa())
#define __GET_NR_CONTEXT_CODE "lr 3,3\n\t"
#define __SPECIAL_INSTRUCTION_PREAMBLE                            \
                     "roll $3,  %%edi ; roll $13, %%edi\n\t"      \
                     "roll $29, %%edi ; roll $19, %%edi\n\t"

#define __VALGRIND_MAJOR__    3
#define __VALGRIND_MINOR__    13
#define __VEX_INJECT_IR_CODE  "lr 5,5\n\t"
#  define __extension__ 
#define AUTOFS_SUPER_MAGIC 0x0187
#define AUTOLOCK(name) G_GNUC_UNUSED __attribute__((cleanup (flatpak_auto_unlock_helper))) GMutex * G_PASTE (auto_unlock, "__LINE__") = flatpak_auto_lock_helper (&G_LOCK_NAME (name))
#define FLATPAK_ANSI_ALT_SCREEN_OFF "\x1b[?1049l"
#define FLATPAK_ANSI_ALT_SCREEN_ON "\x1b[?1049h"
#define FLATPAK_ANSI_BOLD_OFF "\x1b[22m"
#define FLATPAK_ANSI_BOLD_ON "\x1b[1m"
#define FLATPAK_ANSI_CLEAR "\x1b[0J"
#define FLATPAK_ANSI_COLOR_RESET "\x1b[0m"
#define FLATPAK_ANSI_FAINT_OFF "\x1b[22m"
#define FLATPAK_ANSI_FAINT_ON "\x1b[2m"
#define FLATPAK_ANSI_GREEN "\x1b[32m"
#define FLATPAK_ANSI_HIDE_CURSOR "\x1b[?25l"
#define FLATPAK_ANSI_RED "\x1b[31m"
#define FLATPAK_ANSI_ROW_N "\x1b[%d;1H"
#define FLATPAK_ANSI_SHOW_CURSOR "\x1b[?25h"
#define FLATPAK_MESSAGE_ID "c7b39b1e006b464599465e105b361485"
#define FLATPAK_SUMMARY_DIFF_HEADER "xadf"
#define FLATPAK_SUMMARY_HISTORY_LENGTH_DEFAULT 16
#define FLATPAK_VARIANT_BUILDER_INITIALIZER {{0, }}
#define FLATPAK_VARIANT_DICT_INITIALIZER {{0, }}
#define FLATPAK_XA_CACHE_VERSION 2
#define FLATPAK_XA_SUMMARY_VERSION 1
#define OSTREE_COMMIT_TIMESTAMP "ostree.commit.timestamp"
#define OSTREE_COMMIT_TIMESTAMP2 "ot.ts" 

#define flatpak_fail glnx_throw
#define FLATPAK_CLI_UPDATE_INTERVAL_MS 300
#define FLATPAK_DEPLOY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_DEPLOY, FlatpakDeploy))
#define FLATPAK_DEPLOY_DATA_GVARIANT_FORMAT G_VARIANT_TYPE (FLATPAK_DEPLOY_DATA_GVARIANT_STRING)
#define FLATPAK_DEPLOY_DATA_GVARIANT_STRING "(ssasta{sv})"
#define FLATPAK_DEPLOY_VERSION_ANY 0
#define FLATPAK_DEPLOY_VERSION_CURRENT 4
#define FLATPAK_DIR(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_DIR, FlatpakDir))
#define FLATPAK_HELPER_CANCEL_PULL_FLAGS_ALL (FLATPAK_HELPER_CANCEL_PULL_FLAGS_PRESERVE_PULL |\
                                              FLATPAK_HELPER_CANCEL_PULL_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_CONFIGURE_FLAGS_ALL (FLATPAK_HELPER_CONFIGURE_FLAGS_UNSET | \
                                            FLATPAK_HELPER_CONFIGURE_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_CONFIGURE_REMOTE_FLAGS_ALL (FLATPAK_HELPER_CONFIGURE_REMOTE_FLAGS_FORCE_REMOVE | \
                                                   FLATPAK_HELPER_CONFIGURE_REMOTE_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_DEPLOY_APPSTREAM_FLAGS_ALL (FLATPAK_HELPER_DEPLOY_APPSTREAM_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_DEPLOY_FLAGS_ALL (FLATPAK_HELPER_DEPLOY_FLAGS_UPDATE | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_NO_DEPLOY | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_LOCAL_PULL | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_REINSTALL | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_NO_INTERACTION | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_APP_HINT | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_INSTALL_HINT | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_UPDATE_PINNED)
#define FLATPAK_HELPER_ENSURE_REPO_FLAGS_ALL (FLATPAK_HELPER_ENSURE_REPO_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_GENERATE_OCI_SUMMARY_FLAGS_ALL (FLATPAK_HELPER_GENERATE_OCI_SUMMARY_FLAGS_NO_INTERACTION |\
                                                       FLATPAK_HELPER_GENERATE_OCI_SUMMARY_FLAGS_ONLY_CACHED)
#define FLATPAK_HELPER_GET_REVOKEFS_FD_FLAGS_ALL (FLATPAK_HELPER_GET_REVOKEFS_FD_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_INSTALL_BUNDLE_FLAGS_ALL (FLATPAK_HELPER_INSTALL_BUNDLE_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_PRUNE_LOCAL_REPO_FLAGS_ALL (FLATPAK_HELPER_PRUNE_LOCAL_REPO_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_REMOVE_LOCAL_REF_FLAGS_ALL (FLATPAK_HELPER_REMOVE_LOCAL_REF_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_RUN_TRIGGERS_FLAGS_ALL (FLATPAK_HELPER_RUN_TRIGGERS_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_UNINSTALL_FLAGS_ALL (FLATPAK_HELPER_UNINSTALL_FLAGS_KEEP_REF | \
                                            FLATPAK_HELPER_UNINSTALL_FLAGS_FORCE_REMOVE | \
                                            FLATPAK_HELPER_UNINSTALL_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_UPDATE_REMOTE_FLAGS_ALL (FLATPAK_HELPER_UPDATE_REMOTE_FLAGS_NO_INTERACTION | \
                                                FLATPAK_HELPER_UPDATE_REMOTE_FLAGS_SUMMARY_IS_INDEX)
#define FLATPAK_HELPER_UPDATE_SUMMARY_FLAGS_ALL (FLATPAK_HELPER_UPDATE_SUMMARY_FLAGS_NO_INTERACTION |\
                                                 FLATPAK_HELPER_UPDATE_SUMMARY_FLAGS_DELETE)
#define FLATPAK_IS_DEPLOY(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_DEPLOY))
#define FLATPAK_IS_DIR(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_DIR))
#define FLATPAK_REF_BRANCH_KEY "Branch"
#define FLATPAK_REF_COLLECTION_ID_KEY "CollectionID"
#define FLATPAK_REF_DEPLOY_COLLECTION_ID_KEY "DeployCollectionID"
#define FLATPAK_REF_GPGKEY_KEY "GPGKey"
#define FLATPAK_REF_GROUP "Flatpak Ref"
#define FLATPAK_REF_IS_RUNTIME_KEY "IsRuntime"
#define FLATPAK_REF_NAME_KEY "Name"
#define FLATPAK_REF_RUNTIME_REPO_KEY "RuntimeRepo"
#define FLATPAK_REF_SUGGEST_REMOTE_NAME_KEY "SuggestRemoteName"
#define FLATPAK_REF_TITLE_KEY "Title"
#define FLATPAK_REF_URL_KEY "Url"
#define FLATPAK_REF_VERSION_KEY "Version"
#define FLATPAK_REPO_AUTHENTICATOR_INSTALL_KEY "AuthenticatorInstall"
#define FLATPAK_REPO_AUTHENTICATOR_NAME_KEY "AuthenticatorName"
#define FLATPAK_REPO_COLLECTION_ID_KEY "CollectionID"
#define FLATPAK_REPO_COMMENT_KEY "Comment"
#define FLATPAK_REPO_DEFAULT_BRANCH_KEY "DefaultBranch"
#define FLATPAK_REPO_DEPLOY_COLLECTION_ID_KEY "DeployCollectionID"
#define FLATPAK_REPO_DESCRIPTION_KEY "Description"
#define FLATPAK_REPO_FILTER_KEY "Filter"
#define FLATPAK_REPO_GPGKEY_KEY "GPGKey"
#define FLATPAK_REPO_GROUP "Flatpak Repo"
#define FLATPAK_REPO_HOMEPAGE_KEY "Homepage"
#define FLATPAK_REPO_ICON_KEY "Icon"
#define FLATPAK_REPO_NODEPS_KEY "NoDeps"
#define FLATPAK_REPO_SUBSET_KEY "Subset"
#define FLATPAK_REPO_TITLE_KEY "Title"
#define FLATPAK_REPO_URL_KEY "Url"
#define FLATPAK_REPO_VERSION_KEY "Version"
#define FLATPAK_SPARSE_CACHE_KEY_ENDOFLINE "eol"
#define FLATPAK_SPARSE_CACHE_KEY_ENDOFLINE_REBASE "eolr"
#define FLATPAK_SPARSE_CACHE_KEY_EXTRA_DATA_SIZE "eds"
#define FLATPAK_SPARSE_CACHE_KEY_TOKEN_TYPE "tokt"
#define FLATPAK_SUMMARY_INDEX_GVARIANT_FORMAT G_VARIANT_TYPE (FLATPAK_SUMMARY_INDEX_GVARIANT_STRING)
#define FLATPAK_SUMMARY_INDEX_GVARIANT_STRING "(a{s(ayaaya{sv})}a{sv})"
#define FLATPAK_TYPE_DEPLOY flatpak_deploy_get_type ()
#define FLATPAK_TYPE_DIR flatpak_dir_get_type ()
#define SYSTEM_DIR_DEFAULT_DISPLAY_NAME _("Default system installation")
#define SYSTEM_DIR_DEFAULT_ID "default"
#define SYSTEM_DIR_DEFAULT_PRIORITY 0
#define SYSTEM_DIR_DEFAULT_STORAGE_TYPE FLATPAK_DIR_STORAGE_TYPE_DEFAULT


#define FLATPAK_IS_REF(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_REF))
#define FLATPAK_REF(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_REF, FlatpakRef))
#define FLATPAK_TYPE_REF flatpak_ref_get_type ()


#define FLATKPAK_MAIN_CONTEXT_INIT {NULL}
#define FLATPAK_DEFAULT_UPDATE_INTERVAL_MS 100

#define FLATPAK_TYPE_PROGRESS flatpak_progress_get_type ()
#define FLATPAK_INSTALLATION(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_INSTALLATION, FlatpakInstallation))
#define FLATPAK_IS_INSTALLATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_INSTALLATION))
#define FLATPAK_TYPE_INSTALLATION flatpak_installation_get_type ()

#define FLATPAK_IS_REMOTE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_REMOTE))
#define FLATPAK_REMOTE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_REMOTE, FlatpakRemote))
#define FLATPAK_TYPE_REMOTE flatpak_remote_get_type ()

#define FLATPAK_IS_REMOTE_REF(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_REMOTE_REF))
#define FLATPAK_REMOTE_REF(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_REMOTE_REF, FlatpakRemoteRef))
#define FLATPAK_TYPE_REMOTE_REF flatpak_remote_ref_get_type ()

#define FLATPAK_INSTANCE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_INSTANCE, FlatpakInstance))
#define FLATPAK_IS_INSTANCE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_INSTANCE))
#define FLATPAK_TYPE_INSTANCE flatpak_instance_get_type ()

#define FLATPAK_INSTALLED_REF(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_INSTALLED_REF, FlatpakInstalledRef))
#define FLATPAK_IS_INSTALLED_REF(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_INSTALLED_REF))
#define FLATPAK_TYPE_INSTALLED_REF flatpak_installed_ref_get_type ()




#define FLATPAK_HTTP_ERROR flatpak_http_error_quark ()

#define FLATPAK_ERROR flatpak_error_quark ()

# define G_DBUS_METHOD_INVOCATION_HANDLED TRUE
# define G_DBUS_METHOD_INVOCATION_UNHANDLED FALSE

#define FLATPAK_METADATA_GROUP_APPLICATION "Application"
#define FLATPAK_METADATA_GROUP_CONTEXT "Context"
#define FLATPAK_METADATA_GROUP_DCONF "X-DConf"
#define FLATPAK_METADATA_GROUP_ENVIRONMENT "Environment"
#define FLATPAK_METADATA_GROUP_EXTENSION_OF "ExtensionOf"
#define FLATPAK_METADATA_GROUP_EXTRA_DATA "Extra Data"
#define FLATPAK_METADATA_GROUP_INSTANCE "Instance"
#define FLATPAK_METADATA_GROUP_PREFIX_EXTENSION "Extension "
#define FLATPAK_METADATA_GROUP_PREFIX_POLICY "Policy "
#define FLATPAK_METADATA_GROUP_RUNTIME "Runtime"
#define FLATPAK_METADATA_GROUP_SESSION_BUS_POLICY "Session Bus Policy"
#define FLATPAK_METADATA_GROUP_SYSTEM_BUS_POLICY "System Bus Policy"
#define FLATPAK_METADATA_KEY_ADD_LD_PATH "add-ld-path"
#define FLATPAK_METADATA_KEY_APP_COMMIT "app-commit"
#define FLATPAK_METADATA_KEY_APP_EXTENSIONS "app-extensions"
#define FLATPAK_METADATA_KEY_APP_PATH "app-path"
#define FLATPAK_METADATA_KEY_ARCH "arch"
#define FLATPAK_METADATA_KEY_AUTODELETE "autodelete"
#define FLATPAK_METADATA_KEY_AUTOPRUNE_UNLESS "autoprune-unless"
#define FLATPAK_METADATA_KEY_BRANCH "branch"
#define FLATPAK_METADATA_KEY_BUILD "build"
#define FLATPAK_METADATA_KEY_COLLECTION_ID "collection-id"
#define FLATPAK_METADATA_KEY_COMMAND "command"
#define FLATPAK_METADATA_KEY_DCONF_MIGRATE_PATH "migrate-path"
#define FLATPAK_METADATA_KEY_DCONF_PATHS "paths"
#define FLATPAK_METADATA_KEY_DEVEL "devel"
#define FLATPAK_METADATA_KEY_DEVICES "devices"
#define FLATPAK_METADATA_KEY_DIRECTORY "directory"
#define FLATPAK_METADATA_KEY_DOWNLOAD_IF "download-if"
#define FLATPAK_METADATA_KEY_ENABLE_IF "enable-if"
#define FLATPAK_METADATA_KEY_EXTRA_ARGS "extra-args"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_CHECKSUM "checksum"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_INSTALLED_SIZE "installed-size"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_NAME "name"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_SIZE "size"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_URI "uri"
#define FLATPAK_METADATA_KEY_FEATURES "features"
#define FLATPAK_METADATA_KEY_FILESYSTEMS "filesystems"
#define FLATPAK_METADATA_KEY_FLATPAK_VERSION "flatpak-version"
#define FLATPAK_METADATA_KEY_INSTANCE_ID "instance-id"
#define FLATPAK_METADATA_KEY_INSTANCE_PATH "instance-path"
#define FLATPAK_METADATA_KEY_LOCALE_SUBSET "locale-subset"
#define FLATPAK_METADATA_KEY_MERGE_DIRS "merge-dirs"
#define FLATPAK_METADATA_KEY_NAME "name"
#define FLATPAK_METADATA_KEY_NO_AUTODOWNLOAD "no-autodownload"
#define FLATPAK_METADATA_KEY_NO_RUNTIME "NoRuntime"
#define FLATPAK_METADATA_KEY_ORIGINAL_APP_PATH "original-app-path"
#define FLATPAK_METADATA_KEY_ORIGINAL_RUNTIME_PATH "original-runtime-path"
#define FLATPAK_METADATA_KEY_PERSISTENT "persistent"
#define FLATPAK_METADATA_KEY_PRIORITY "priority"
#define FLATPAK_METADATA_KEY_REF "ref"
#define FLATPAK_METADATA_KEY_REQUIRED_FLATPAK "required-flatpak"
#define FLATPAK_METADATA_KEY_RUNTIME "runtime"
#define FLATPAK_METADATA_KEY_RUNTIME_COMMIT "runtime-commit"
#define FLATPAK_METADATA_KEY_RUNTIME_EXTENSIONS "runtime-extensions"
#define FLATPAK_METADATA_KEY_RUNTIME_PATH "runtime-path"
#define FLATPAK_METADATA_KEY_SANDBOX "sandbox"
#define FLATPAK_METADATA_KEY_SDK "sdk"
#define FLATPAK_METADATA_KEY_SESSION_BUS_PROXY "session-bus-proxy"
#define FLATPAK_METADATA_KEY_SHARED "shared"
#define FLATPAK_METADATA_KEY_SOCKETS "sockets"
#define FLATPAK_METADATA_KEY_SUBDIRECTORIES "subdirectories"
#define FLATPAK_METADATA_KEY_SUBDIRECTORY_SUFFIX "subdirectory-suffix"
#define FLATPAK_METADATA_KEY_SYSTEM_BUS_PROXY "system-bus-proxy"
#define FLATPAK_METADATA_KEY_TAG "tag"
#define FLATPAK_METADATA_KEY_TAGS "tags"
#define FLATPAK_METADATA_KEY_UNSET_ENVIRONMENT "unset-environment"
#define FLATPAK_METADATA_KEY_VERSION "version"
#define FLATPAK_METADATA_KEY_VERSIONS "versions"

#define FLATPAK_IS_OCI_LAYER_WRITER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_OCI_LAYER_WRITER))
#define FLATPAK_IS_OCI_REGISTRY(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_OCI_REGISTRY))
#define FLATPAK_OCI_LAYER_WRITER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_OCI_LAYER_WRITER, FlatpakOciLayerWriter))
#define FLATPAK_OCI_REGISTRY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_OCI_REGISTRY, FlatpakOciRegistry))
#define FLATPAK_TYPE_OCI_LAYER_WRITER flatpak_oci_layer_writer_get_type ()
#define FLATPAK_TYPE_OCI_REGISTRY flatpak_oci_registry_get_type ()

#define FLATPAK_DOCKER_MEDIA_TYPE_IMAGE_IMAGE_CONFIG "application/vnd.docker.container.image.v1+json"
#define FLATPAK_DOCKER_MEDIA_TYPE_IMAGE_MANIFEST2 "application/vnd.docker.distribution.manifest.v2+json"
#define FLATPAK_OCI_MEDIA_TYPE_DESCRIPTOR "application/vnd.oci.descriptor.v1+json"
#define FLATPAK_OCI_MEDIA_TYPE_IMAGE_CONFIG "application/vnd.oci.image.config.v1+json"
#define FLATPAK_OCI_MEDIA_TYPE_IMAGE_INDEX "application/vnd.oci.image.index.v1+json"
#define FLATPAK_OCI_MEDIA_TYPE_IMAGE_LAYER "application/vnd.oci.image.layer.v1.tar+gzip"
#define FLATPAK_OCI_MEDIA_TYPE_IMAGE_LAYER_NONDISTRIBUTABLE "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
#define FLATPAK_OCI_MEDIA_TYPE_IMAGE_MANIFEST "application/vnd.oci.image.manifest.v1+json"
#define FLATPAK_OCI_SIGNATURE_TYPE_FLATPAK "flatpak oci image signature"
#define FLATPAK_TYPE_OCI_IMAGE flatpak_oci_image_get_type ()
#define FLATPAK_TYPE_OCI_INDEX flatpak_oci_index_get_type ()
#define FLATPAK_TYPE_OCI_INDEX_RESPONSE flatpak_oci_index_response_get_type ()
#define FLATPAK_TYPE_OCI_MANIFEST flatpak_oci_manifest_get_type ()
#define FLATPAK_TYPE_OCI_SIGNATURE flatpak_oci_signature_get_type ()
#define FLATPAK_TYPE_OCI_VERSIONED flatpak_oci_versioned_get_type ()

#define FLATPAK_JSON_BOOLMAP_PROP(_struct, _field, _name) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_BOOLMAP }
#define FLATPAK_JSON_BOOL_PROP(_struct, _field, _name) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_BOOL }
#define FLATPAK_JSON_INT64_PROP(_struct, _field, _name) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_INT64 }
#define FLATPAK_JSON_LAST_PROP { NULL }
#define FLATPAK_JSON_MANDATORY_STRICT_STRUCT_PROP(_struct, _field, _name, _props) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRUCT, (gpointer) _props, 0, FLATPAK_JSON_PROP_FLAGS_STRICT | FLATPAK_JSON_PROP_FLAGS_MANDATORY}
#define FLATPAK_JSON_MANDATORY_STRING_PROP(_struct, _field, _name) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRING, 0, 0, FLATPAK_JSON_PROP_FLAGS_MANDATORY }
#define FLATPAK_JSON_OPT_STRUCT_PROP(_struct, _field, _name, _props) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRUCT, (gpointer) _props, 0, FLATPAK_JSON_PROP_FLAGS_OPTIONAL}
#define FLATPAK_JSON_PARENT_PROP(_struct, _field, _props) \
  { "parent", G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_PARENT, (gpointer) _props}
#define FLATPAK_JSON_STRICT_STRUCT_PROP(_struct, _field, _name, _props) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRUCT, (gpointer) _props, 0, FLATPAK_JSON_PROP_FLAGS_STRICT}
#define FLATPAK_JSON_STRING_PROP(_struct, _field, _name) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRING }
#define FLATPAK_JSON_STRMAP_PROP(_struct, _field, _name) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRMAP }
#define FLATPAK_JSON_STRUCTV_PROP(_struct, _field, _name, _props) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRUCTV, (gpointer) _props, (gpointer) sizeof (**((_struct *) 0)->_field) }
#define FLATPAK_JSON_STRUCT_PROP(_struct, _field, _name, _props) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRUCT, (gpointer) _props}
#define FLATPAK_JSON_STRV_PROP(_struct, _field, _name) \
  { _name, G_STRUCT_OFFSET (_struct, _field), FLATPAK_JSON_PROP_TYPE_STRV }
#define FLATPAK_TYPE_JSON flatpak_json_get_type ()

