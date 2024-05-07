


#include<unistd.h>

#include<fcntl.h>
#include<pthread.h>






#include<limits.h>










#define BLKD_AT "blocked at %s"
#define CONN_ID "connection-id=%s"
#define DUMP_BLKD_FMT DUMP_GEN_FMT ", " CONN_ID ", " BLKD_AT
#define DUMP_BLKD_GRNTD_FMT DUMP_GEN_FMT ", " CONN_ID ", " BLKD_AT ", " GRNTD_AT
#define DUMP_GEN_FMT "pid = %llu, owner=%s, client=%p"
#define DUMP_GRNTD_FMT DUMP_GEN_FMT ", " CONN_ID ", " GRNTD_AT
#define ENTRY_BLKD_FMT ENTRY_FMT ", " DUMP_BLKD_FMT
#define ENTRY_BLKD_GRNTD_FMT ENTRY_FMT ", " DUMP_BLKD_GRNTD_FMT
#define ENTRY_FMT "type=%s on basename=%s"
#define ENTRY_GRNTD_FMT ENTRY_FMT ", " DUMP_GRNTD_FMT
#define GRNTD_AT "granted at %s"
#define RANGE_BLKD_FMT RANGE_FMT ", " DUMP_BLKD_FMT
#define RANGE_BLKD_GRNTD_FMT RANGE_FMT ", " DUMP_BLKD_GRNTD_FMT
#define RANGE_FMT "type=%s, whence=%hd, start=%llu, len=%llu"
#define RANGE_GRNTD_FMT RANGE_FMT ", " DUMP_GRNTD_FMT
#define SET_FLOCK_PID(flock, lock) ((flock)->l_pid = lock->client_pid)

