#include<string.h>
#include<stdlib.h>


#include<pwd.h>
#include<sys/types.h>
#include<fcntl.h>
#include<getopt.h>
#include<stdio.h>
#include<libgen.h>

#include<errno.h>
#include<grp.h>
#include<sys/stat.h>
#include<unistd.h>
#define case_RC_COMMON_getopt_case_C  setenv ("EINFO_COLOR", "NO", 1);
#define case_RC_COMMON_getopt_case_V  if (argc == 2) show_version();
#define case_RC_COMMON_getopt_case_h  usage (EXIT_SUCCESS);
#define case_RC_COMMON_getopt_case_q  set_quiet_options();
#define case_RC_COMMON_getopt_case_v  setenv ("EINFO_VERBOSE", "YES", 1);
#define case_RC_COMMON_getopt_default usage (EXIT_FAILURE);
#define getoptstring_COMMON "ChqVv"

#define selinux_setup(x) do { } while (0)
#define selinux_util_close() do { } while (0)
#define selinux_util_label(x) do { } while (0)
#define selinux_util_open() (0)
