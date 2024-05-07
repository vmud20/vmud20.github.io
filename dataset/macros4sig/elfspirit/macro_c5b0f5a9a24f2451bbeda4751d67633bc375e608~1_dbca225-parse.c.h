#include<sys/stat.h>
#include<elf.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<stdio.h>
#include<fcntl.h>
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a) - 1)
#define ERROR(format, ...) printf (""L_RED" [-] "format""NONE"", ##__VA_ARGS__)
#define INFO(format, ...) printf (""L_GREEN" [+] "format""NONE"", ##__VA_ARGS__)
#define LENGTH 64
#define L_GREEN   "\e[1;32m"           
#define L_RED     "\e[1;31m"           
#define NONE      "\e[0m"              
#define PATH_LENGTH LENGTH
#define PATH_LENGTH_NEW LENGTH + 4
#define PTR_ALIGN(p, a) ((typeof(p))ALIGN((unsigned long)(p), (a)))
#define WARNING(format, ...) printf (""YELLOW" [!] "format""NONE"", ##__VA_ARGS__)
#define YELLOW    "\e[1;33m"           
#define __ALIGN_MASK(x, mask) (((x) + (mask))&~(mask))
