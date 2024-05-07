#include<limits.h>
#include<fcntl.h>
#include<time.h>
#include<sys/types.h>
#include<stdlib.h>
#include<stdarg.h>

#include<signal.h>
#include<sys/stat.h>
#include<string.h>
#include<sys/time.h>
#include<mntent.h>
#include<errno.h>
#include<stdio.h>
#include<rpc/types.h>
#include<unistd.h>
#define LOCALEDIR "/usr/share/locale"
#  define N_(String) gettext_noop (String)
# define _(Text) (Text)
# define bindtextdomain(Domain, Directory) 
# define textdomain(Domain) 


#define EX_BG         256       
#define EX_FILEIO      16	
#define EX_SOMEOK      64	

#define streq(s, t)	(strcmp ((s), (t)) == 0)
#define ERR_MAX 5

