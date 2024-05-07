























libc_hidden_def (globfree64)

versioned_symbol (libc, __glob64, glob64, GLIBC_2_2);
libc_hidden_ver (__glob64, glob64)





int __old_glob64 (const char *__pattern, int __flags, int (*__errfunc) (const char *, int), glob64_t *__pglob);















compat_symbol (libc, __old_glob64, glob64, GLIBC_2_1);

