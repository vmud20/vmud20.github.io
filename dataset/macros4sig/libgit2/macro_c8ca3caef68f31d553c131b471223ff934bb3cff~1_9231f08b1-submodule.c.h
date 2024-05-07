










#include<sys/types.h>
#include<stdint.h>
#include<stdlib.h>
#include<netinet/in.h>





#include<time.h>




#define GIT_IDXENTRY_NAMEMASK  (0x0fff)
#define GIT_IDXENTRY_STAGE(E) \
	(((E)->flags & GIT_IDXENTRY_STAGEMASK) >> GIT_IDXENTRY_STAGESHIFT)
#define GIT_IDXENTRY_STAGEMASK (0x3000)
#define GIT_IDXENTRY_STAGESHIFT 12
#define GIT_IDXENTRY_STAGE_SET(E,S) do { \
	(E)->flags = ((E)->flags & ~GIT_IDXENTRY_STAGEMASK) | \
		(((S) & 0x03) << GIT_IDXENTRY_STAGESHIFT); } while (0)


#define GIT_CONFIG_BACKEND_INIT {GIT_CONFIG_BACKEND_VERSION}
#define GIT_CONFIG_BACKEND_VERSION 1


# define GIT_BEGIN_DECL extern "C" {
# define GIT_DEPRECATED(func) \
			 __attribute__((deprecated)) \
			 func
# define GIT_EXTERN(type) extern \
			 __attribute__((visibility("default"))) \
			 type
# define GIT_FORMAT_PRINTF(a,b) __attribute__((format (printf, a, b)))
#define GIT_OID_HEX_ZERO "0000000000000000000000000000000000000000"
#define GIT_PATH_LIST_SEPARATOR ';'
#define GIT_PATH_MAX 4096
#define GIT_WIN32 1

