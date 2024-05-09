







































struct sharedObjectsStruct shared;



double R_Zero, R_PosInf, R_NegInf, R_Nan;




struct redisServer server; 




struct redisCommand redisCommandTable[] = {
    {"module",moduleCommand,-2, "admin no-script",  {"get",getCommand,2, "read-only fast @string", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"getex",getexCommand,-2, "write fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"getdel",getdelCommand,2, "write fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},   {"set",setCommand,-3, "write use-memory @string", {{"read write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"setnx",setnxCommand,3, "write use-memory fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"setex",setexCommand,4, "write use-memory @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"psetex",psetexCommand,4, "write use-memory @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"append",appendCommand,3, "write use-memory fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"strlen",strlenCommand,2, "read-only fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"del",delCommand,-2, "write @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"unlink",unlinkCommand,-2, "write fast @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"exists",existsCommand,-2, "read-only fast @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"setbit",setbitCommand,4, "write use-memory @bitmap", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"getbit",getbitCommand,3, "read-only fast @bitmap", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"bitfield",bitfieldCommand,-2, "write use-memory @bitmap", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"bitfield_ro",bitfieldroCommand,-2, "read-only fast @bitmap", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"setrange",setrangeCommand,4, "write use-memory @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"getrange",getrangeCommand,4, "read-only @string", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"substr",getrangeCommand,4, "read-only @string", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"incr",incrCommand,2, "write use-memory fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"decr",decrCommand,2, "write use-memory fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"mget",mgetCommand,-2, "read-only fast @string", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"rpush",rpushCommand,-3, "write use-memory fast @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lpush",lpushCommand,-3, "write use-memory fast @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"rpushx",rpushxCommand,-3, "write use-memory fast @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lpushx",lpushxCommand,-3, "write use-memory fast @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"linsert",linsertCommand,5, "write use-memory @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"rpop",rpopCommand,-2, "write fast @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lpop",lpopCommand,-2, "write fast @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lmpop",lmpopCommand,-4, "write @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, lmpopGetKeys},  {"brpop",brpopCommand,-3, "write no-script @list @blocking", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-2,1,0}}}},  {"brpoplpush",brpoplpushCommand,4, "write use-memory no-script @list @blocking", {{"read write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"blmove",blmoveCommand,6, "write use-memory no-script @list @blocking", {{"read write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"blpop",blpopCommand,-3, "write no-script @list @blocking", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-2,1,0}}}},  {"blmpop",blmpopCommand,-5, "write @list @blocking", {{"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, blmpopGetKeys},  {"llen",llenCommand,2, "read-only fast @list", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lindex",lindexCommand,3, "read-only @list", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lset",lsetCommand,4, "write use-memory @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lrange",lrangeCommand,4, "read-only @list", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"ltrim",ltrimCommand,4, "write @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lpos",lposCommand,-3, "read-only @list", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lrem",lremCommand,4, "write @list", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"rpoplpush",rpoplpushCommand,3, "write use-memory @list", {{"read write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"lmove",lmoveCommand,5, "write use-memory @list", {{"read write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"sadd",saddCommand,-3, "write use-memory fast @set", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"srem",sremCommand,-3, "write fast @set", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"smove",smoveCommand,4, "write fast @set", {{"read write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"sismember",sismemberCommand,3, "read-only fast @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"smismember",smismemberCommand,-3, "read-only fast @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"scard",scardCommand,2, "read-only fast @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"spop",spopCommand,-2, "write random fast @set", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"srandmember",srandmemberCommand,-2, "read-only random @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"sinter",sinterCommand,-2, "read-only to-sort @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"sintercard",sinterCardCommand,-3, "read-only @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_KEYNUM,.fk.range={0,1,1}}}, sintercardGetKeys},  {"sinterstore",sinterstoreCommand,-3, "write use-memory @set", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"sunion",sunionCommand,-2, "read-only to-sort @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"sunionstore",sunionstoreCommand,-3, "write use-memory @set", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"sdiff",sdiffCommand,-2, "read-only to-sort @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"sdiffstore",sdiffstoreCommand,-3, "write use-memory @set", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"smembers",sinterCommand,2, "read-only to-sort @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"sscan",sscanCommand,-3, "read-only random @set", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zadd",zaddCommand,-4, "write use-memory fast @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zincrby",zincrbyCommand,4, "write use-memory fast @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrem",zremCommand,-3, "write fast @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zremrangebyscore",zremrangebyscoreCommand,4, "write @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zremrangebyrank",zremrangebyrankCommand,4, "write @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zremrangebylex",zremrangebylexCommand,4, "write @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zunionstore",zunionstoreCommand,-4, "write use-memory @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, zunionInterDiffStoreGetKeys},  {"zinterstore",zinterstoreCommand,-4, "write use-memory @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, zunionInterDiffStoreGetKeys},  {"zdiffstore",zdiffstoreCommand,-4, "write use-memory @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, zunionInterDiffStoreGetKeys},  {"zunion",zunionCommand,-3, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, zunionInterDiffGetKeys},  {"zinter",zinterCommand,-3, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, zunionInterDiffGetKeys},  {"zintercard",zinterCardCommand,-3, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, zunionInterDiffGetKeys},  {"zdiff",zdiffCommand,-3, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, zunionInterDiffGetKeys},  {"zrange",zrangeCommand,-4, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrangestore",zrangestoreCommand,-5, "write use-memory @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrangebyscore",zrangebyscoreCommand,-4, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrevrangebyscore",zrevrangebyscoreCommand,-4, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrangebylex",zrangebylexCommand,-4, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrevrangebylex",zrevrangebylexCommand,-4, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zcount",zcountCommand,4, "read-only fast @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zlexcount",zlexcountCommand,4, "read-only fast @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrevrange",zrevrangeCommand,-4, "read-only @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zcard",zcardCommand,2, "read-only fast @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zscore",zscoreCommand,3, "read-only fast @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zmscore",zmscoreCommand,-3, "read-only fast @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrank",zrankCommand,3, "read-only fast @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zrevrank",zrevrankCommand,3, "read-only fast @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zscan",zscanCommand,-3, "read-only random @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zpopmin",zpopminCommand,-2, "write fast @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zpopmax",zpopmaxCommand,-2, "write fast @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"zmpop", zmpopCommand,-4, "write @sortedset", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, zmpopGetKeys},  {"bzpopmin",bzpopminCommand,-3, "write no-script fast @sortedset @blocking", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-2,1,0}}}},  {"bzpopmax",bzpopmaxCommand,-3, "write no-script fast @sortedset @blocking", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-2,1,0}}}},  {"bzmpop",bzmpopCommand,-5, "write @sortedset @blocking", {{"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, blmpopGetKeys},  {"zrandmember",zrandmemberCommand,-2, "read-only random @sortedset", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hset",hsetCommand,-4, "write use-memory fast @hash", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hsetnx",hsetnxCommand,4, "write use-memory fast @hash", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hget",hgetCommand,3, "read-only fast @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hmset",hsetCommand,-4, "write use-memory fast @hash", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hmget",hmgetCommand,-3, "read-only fast @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hincrby",hincrbyCommand,4, "write use-memory fast @hash", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hincrbyfloat",hincrbyfloatCommand,4, "write use-memory fast @hash", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hdel",hdelCommand,-3, "write fast @hash", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hlen",hlenCommand,2, "read-only fast @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hstrlen",hstrlenCommand,3, "read-only fast @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hkeys",hkeysCommand,2, "read-only to-sort @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hvals",hvalsCommand,2, "read-only to-sort @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hgetall",hgetallCommand,2, "read-only random @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hexists",hexistsCommand,3, "read-only fast @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hrandfield",hrandfieldCommand,-2, "read-only random @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"hscan",hscanCommand,-3, "read-only random @hash", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"incrby",incrbyCommand,3, "write use-memory fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"decrby",decrbyCommand,3, "write use-memory fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"incrbyfloat",incrbyfloatCommand,3, "write use-memory fast @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"getset",getsetCommand,3, "write use-memory fast @string", {{"read write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"mset",msetCommand,-3, "write use-memory @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,2,0}}}},  {"msetnx",msetnxCommand,-3, "write use-memory @string", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,2,0}}}},  {"randomkey",randomkeyCommand,1, "read-only random @keyspace",  {"select",selectCommand,2, "ok-loading fast ok-stale @connection",  {"swapdb",swapdbCommand,3, "write fast @keyspace @dangerous",  {"move",moveCommand,3, "write fast @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"copy",copyCommand,-3, "write use-memory @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},   {"rename",renameCommand,3, "write @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={1,1,0}}}},  {"renamenx",renamenxCommand,3, "write fast @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={1,1,0}}}},  {"expire",expireCommand,-3, "write fast @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"expireat",expireatCommand,-3, "write fast @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"pexpire",pexpireCommand,-3, "write fast @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"pexpireat",pexpireatCommand,-3, "write fast @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"keys",keysCommand,2, "read-only to-sort @keyspace @dangerous",  {"scan",scanCommand,-2, "read-only random @keyspace",  {"dbsize",dbsizeCommand,1, "read-only fast @keyspace",  {"auth",authCommand,-2, "no-auth no-script ok-loading ok-stale fast @connection",   {"ping",pingCommand,-1, "ok-stale fast @connection",  {"echo",echoCommand,2, "fast @connection",  {"save",saveCommand,1, "admin no-script",  {"bgsave",bgsaveCommand,-1, "admin no-script",  {"bgrewriteaof",bgrewriteaofCommand,1, "admin no-script",  {"shutdown",shutdownCommand,-1, "admin no-script ok-loading ok-stale",  {"lastsave",lastsaveCommand,1, "random fast ok-loading ok-stale @admin @dangerous",  {"type",typeCommand,2, "read-only fast @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"multi",multiCommand,1, "no-script fast ok-loading ok-stale @transaction",  {"exec",execCommand,1, "no-script no-slowlog ok-loading ok-stale @transaction",  {"discard",discardCommand,1, "no-script fast ok-loading ok-stale @transaction",  {"sync",syncCommand,1, "admin no-script",  {"psync",syncCommand,-3, "admin no-script",  {"replconf",replconfCommand,-1, "admin no-script ok-loading ok-stale",  {"flushdb",flushdbCommand,-1, "write @keyspace @dangerous",  {"flushall",flushallCommand,-1, "write @keyspace @dangerous",  {"sort",sortCommand,-2, "write use-memory @list @set @sortedset @dangerous", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write incomplete", KSPEC_BS_UNKNOWN,{{0}}, KSPEC_FK_UNKNOWN,{{0}}}}, sortGetKeys},  {"sort_ro",sortroCommand,-2, "read-only @list @set @sortedset @dangerous", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"info",infoCommand,-1, "ok-loading ok-stale random @dangerous",  {"monitor",monitorCommand,1, "admin no-script ok-loading ok-stale",  {"ttl",ttlCommand,2, "read-only fast random @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"touch",touchCommand,-2, "read-only fast @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"pttl",pttlCommand,2, "read-only fast random @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"expiretime",expiretimeCommand,2, "read-only fast random @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"pexpiretime",pexpiretimeCommand,2, "read-only fast random @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"persist",persistCommand,2, "write fast @keyspace", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"slaveof",replicaofCommand,3, "admin no-script ok-stale",  {"replicaof",replicaofCommand,3, "admin no-script ok-stale",  {"role",roleCommand,1, "ok-loading ok-stale no-script fast @admin @dangerous",  {"debug",debugCommand,-2, "admin no-script ok-loading ok-stale",  {"config",configCommand,-2, "admin ok-loading ok-stale no-script",  {"subscribe",subscribeCommand,-2, "pub-sub no-script ok-loading ok-stale",  {"unsubscribe",unsubscribeCommand,-1, "pub-sub no-script ok-loading ok-stale",  {"psubscribe",psubscribeCommand,-2, "pub-sub no-script ok-loading ok-stale",  {"punsubscribe",punsubscribeCommand,-1, "pub-sub no-script ok-loading ok-stale",  {"publish",publishCommand,3, "pub-sub ok-loading ok-stale fast may-replicate",  {"pubsub",pubsubCommand,-2, "pub-sub ok-loading ok-stale random",  {"watch",watchCommand,-2, "no-script fast ok-loading ok-stale @transaction", {{"", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"unwatch",unwatchCommand,1, "no-script fast ok-loading ok-stale @transaction",  {"cluster",clusterCommand,-2, "admin ok-stale random",  {"restore",restoreCommand,-4, "write use-memory @keyspace @dangerous", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"restore-asking",restoreCommand,-4, "write use-memory cluster-asking @keyspace @dangerous", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"migrate",migrateCommand,-6, "write random @keyspace @dangerous", {{"write", KSPEC_BS_INDEX,.bs.index={3}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write incomplete", KSPEC_BS_KEYWORD,.bs.keyword={"KEYS",-2}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}, migrateGetKeys},  {"asking",askingCommand,1, "fast @connection",  {"readonly",readonlyCommand,1, "fast @connection",  {"readwrite",readwriteCommand,1, "fast @connection",  {"dump",dumpCommand,2, "read-only random @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"object",objectCommand,-2, "read-only random @keyspace", {{"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"memory",memoryCommand,-2, "random read-only", {{"read", KSPEC_BS_KEYWORD,.bs.keyword={"USAGE",1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}, memoryGetKeys},  {"client",clientCommand,-2, "admin no-script random ok-loading ok-stale @connection",  {"hello",helloCommand,-1, "no-auth no-script fast ok-loading ok-stale @connection",   {"eval",evalCommand,-3, "no-script no-monitor may-replicate @scripting", {{"read write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, evalGetKeys},  {"eval_ro",evalRoCommand,-3, "no-script no-monitor @scripting", {{"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, evalGetKeys},  {"evalsha",evalShaCommand,-3, "no-script no-monitor may-replicate @scripting", {{"read write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, evalGetKeys},  {"evalsha_ro",evalShaRoCommand,-3, "no-script no-monitor @scripting", {{"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_KEYNUM,.fk.keynum={0,1,1}}}, evalGetKeys},  {"slowlog",slowlogCommand,-2, "admin random ok-loading ok-stale",  {"script",scriptCommand,-2, "no-script may-replicate @scripting",  {"time",timeCommand,1, "random fast ok-loading ok-stale",  {"bitop",bitopCommand,-4, "write use-memory @bitmap", {{"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={3}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"bitcount",bitcountCommand,-2, "read-only @bitmap", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"bitpos",bitposCommand,-3, "read-only @bitmap", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"wait",waitCommand,3, "no-script @connection",  {"command",commandCommand,-1, "ok-loading ok-stale random @connection",  {"geoadd",geoaddCommand,-5, "write use-memory @geo", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},   {"georadius",georadiusCommand,-6, "write use-memory @geo", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_KEYWORD,.bs.keyword={"STORE",6}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_KEYWORD,.bs.keyword={"STOREDIST",6}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}, georadiusGetKeys},  {"georadius_ro",georadiusroCommand,-6, "read-only @geo", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"georadiusbymember",georadiusbymemberCommand,-5,"write use-memory @geo", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_KEYWORD,.bs.keyword={"STORE",5}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"write", KSPEC_BS_KEYWORD,.bs.keyword={"STOREDIST",5}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}, georadiusGetKeys},  {"georadiusbymember_ro",georadiusbymemberroCommand,-5, "read-only @geo", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"geohash",geohashCommand,-2, "read-only @geo", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"geopos",geoposCommand,-2, "read-only @geo", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"geodist",geodistCommand,-4, "read-only @geo", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"geosearch",geosearchCommand,-7, "read-only @geo", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"geosearchstore",geosearchstoreCommand,-8, "write use-memory @geo", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"pfselftest",pfselftestCommand,1, "admin @hyperloglog",  {"pfadd",pfaddCommand,-2, "write use-memory fast @hyperloglog", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},   {"pfcount",pfcountCommand,-2, "read-only may-replicate @hyperloglog", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},  {"pfmerge",pfmergeCommand,-2, "write use-memory @hyperloglog", {{"read write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}, {"read", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={-1,1,0}}}},   {"pfdebug",pfdebugCommand,-3, "admin write use-memory @hyperloglog", {{"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xadd",xaddCommand,-5, "write use-memory fast random @stream", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xrange",xrangeCommand,-4, "read-only @stream", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xrevrange",xrevrangeCommand,-4, "read-only @stream", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xlen",xlenCommand,2, "read-only fast @stream", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xread",xreadCommand,-4, "read-only @stream @blocking", {{"read", KSPEC_BS_KEYWORD,.bs.keyword={"STREAMS",1}, KSPEC_FK_RANGE,.fk.range={-1,1,2}}}, xreadGetKeys},  {"xreadgroup",xreadCommand,-7, "write @stream @blocking", {{"read", KSPEC_BS_KEYWORD,.bs.keyword={"STREAMS",4}, KSPEC_FK_RANGE,.fk.range={-1,1,2}}}, xreadGetKeys},  {"xgroup",xgroupCommand,-2, "write use-memory @stream", {{"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xsetid",xsetidCommand,3, "write use-memory fast @stream", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xack",xackCommand,-4, "write fast random @stream", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xpending",xpendingCommand,-3, "read-only random @stream", {{"read", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xclaim",xclaimCommand,-6, "write random fast @stream", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xautoclaim",xautoclaimCommand,-6, "write random fast @stream", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xinfo",xinfoCommand,-2, "read-only random @stream", {{"write", KSPEC_BS_INDEX,.bs.index={2}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xdel",xdelCommand,-3, "write fast @stream", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"xtrim",xtrimCommand,-4, "write random @stream", {{"write", KSPEC_BS_INDEX,.bs.index={1}, KSPEC_FK_RANGE,.fk.range={0,1,0}}}},  {"post",securityWarningCommand,-1, "ok-loading ok-stale read-only",  {"host:",securityWarningCommand,-1, "ok-loading ok-stale read-only",  {"latency",latencyCommand,-2, "admin no-script ok-loading ok-stale",  {"lolwut",lolwutCommand,-1, "read-only fast",  {"acl",aclCommand,-2, "admin no-script ok-loading ok-stale",  {"stralgo",stralgoCommand,-2, "read-only @string", {{"read incomplete", KSPEC_BS_UNKNOWN,{{0}}, KSPEC_FK_UNKNOWN,{{0}}}}, lcsGetKeys},  {"reset",resetCommand,1, "no-script ok-stale ok-loading fast @connection",  {"failover",failoverCommand,-1, "admin no-script ok-stale" };




























































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































void nolocks_localtime(struct tm *tmp, time_t t, time_t tz, int dst);


void serverLogRaw(int level, const char *msg) {
    const int syslogLevelMap[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING };
    const char *c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & LL_RAW);
    int log_to_stdout = server.logfile[0] == '\0';

    level &= 0xff; 
    if (level < server.verbosity) return;

    fp = log_to_stdout ? stdout : fopen(server.logfile,"a");
    if (!fp) return;

    if (rawmode) {
        fprintf(fp,"%s",msg);
    } else {
        int off;
        struct timeval tv;
        int role_char;
        pid_t pid = getpid();

        gettimeofday(&tv,NULL);
        struct tm tm;
        nolocks_localtime(&tm,tv.tv_sec,server.timezone,server.daylight_active);
        off = strftime(buf,sizeof(buf),"%d %b %Y %H:%M:%S.",&tm);
        snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);
        if (server.sentinel_mode) {
            role_char = 'X'; 
        } else if (pid != server.pid) {
            role_char = 'C'; 
        } else {
            role_char = (server.masterhost ? 'S':'M'); 
        }
        fprintf(fp,"%d:%c %s %c %s\n", (int)getpid(),role_char, buf,c[level],msg);
    }
    fflush(fp);

    if (!log_to_stdout) fclose(fp);
    if (server.syslog_enabled) syslog(syslogLevelMap[level], "%s", msg);
}


void _serverLog(int level, const char *fmt, ...) {
    va_list ap;
    char msg[LOG_MAX_LEN];

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    serverLogRaw(level,msg);
}


void serverLogFromHandler(int level, const char *msg) {
    int fd;
    int log_to_stdout = server.logfile[0] == '\0';
    char buf[64];

    if ((level&0xff) < server.verbosity || (log_to_stdout && server.daemonize))
        return;
    fd = log_to_stdout ? STDOUT_FILENO :
                         open(server.logfile, O_APPEND|O_CREAT|O_WRONLY, 0644);
    if (fd == -1) return;
    ll2string(buf,sizeof(buf),getpid());
    if (write(fd,buf,strlen(buf)) == -1) goto err;
    if (write(fd,":signal-handler (",17) == -1) goto err;
    ll2string(buf,sizeof(buf),time(NULL));
    if (write(fd,buf,strlen(buf)) == -1) goto err;
    if (write(fd,") ",2) == -1) goto err;
    if (write(fd,msg,strlen(msg)) == -1) goto err;
    if (write(fd,"\n",1) == -1) goto err;
err:
    if (!log_to_stdout) close(fd);
}


long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}


mstime_t mstime(void) {
    return ustime()/1000;
}


void exitFromChild(int retcode) {

    exit(retcode);

    _exit(retcode);

}





void dictVanillaFree(dict *d, void *val)
{
    UNUSED(d);
    zfree(val);
}

void dictListDestructor(dict *d, void *val)
{
    UNUSED(d);
    listRelease((list*)val);
}

int dictSdsKeyCompare(dict *d, const void *key1, const void *key2)
{
    int l1,l2;
    UNUSED(d);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}


int dictSdsKeyCaseCompare(dict *d, const void *key1, const void *key2)
{
    UNUSED(d);
    return strcasecmp(key1, key2) == 0;
}

void dictObjectDestructor(dict *d, void *val)
{
    UNUSED(d);
    if (val == NULL) return; 
    decrRefCount(val);
}

void dictSdsDestructor(dict *d, void *val)
{
    UNUSED(d);
    sdsfree(val);
}

int dictObjKeyCompare(dict *d, const void *key1, const void *key2)
{
    const robj *o1 = key1, *o2 = key2;
    return dictSdsKeyCompare(d, o1->ptr,o2->ptr);
}

uint64_t dictObjHash(const void *key) {
    const robj *o = key;
    return dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
}

uint64_t dictSdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}

uint64_t dictSdsCaseHash(const void *key) {
    return dictGenCaseHashFunction((unsigned char*)key, sdslen((char*)key));
}

int dictEncObjKeyCompare(dict *d, const void *key1, const void *key2)
{
    robj *o1 = (robj*) key1, *o2 = (robj*) key2;
    int cmp;

    if (o1->encoding == OBJ_ENCODING_INT && o2->encoding == OBJ_ENCODING_INT)
            return o1->ptr == o2->ptr;

    
    if (o1->refcount != OBJ_STATIC_REFCOUNT) o1 = getDecodedObject(o1);
    if (o2->refcount != OBJ_STATIC_REFCOUNT) o2 = getDecodedObject(o2);
    cmp = dictSdsKeyCompare(d,o1->ptr,o2->ptr);
    if (o1->refcount != OBJ_STATIC_REFCOUNT) decrRefCount(o1);
    if (o2->refcount != OBJ_STATIC_REFCOUNT) decrRefCount(o2);
    return cmp;
}

uint64_t dictEncObjHash(const void *key) {
    robj *o = (robj*) key;

    if (sdsEncodedObject(o)) {
        return dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
    } else if (o->encoding == OBJ_ENCODING_INT) {
        char buf[32];
        int len;

        len = ll2string(buf,32,(long)o->ptr);
        return dictGenHashFunction((unsigned char*)buf, len);
    } else {
        serverPanic("Unknown string encoding");
    }
}


int dictExpandAllowed(size_t moreMem, double usedRatio) {
    if (usedRatio <= HASHTABLE_MAX_LOAD_FACTOR) {
        return !overMaxmemoryAfterAlloc(moreMem);
    } else {
        return 1;
    }
}


size_t dictEntryMetadataSize(dict *d) {
    UNUSED(d);
    return server.cluster_enabled ? sizeof(clusterDictEntryMetadata) : 0;
}


dictType objectKeyPointerValueDictType = {
    dictEncObjHash,             NULL, NULL, dictEncObjKeyCompare, dictObjectDestructor, NULL, NULL };








dictType objectKeyHeapPointerValueDictType = {
    dictEncObjHash,             NULL, NULL, dictEncObjKeyCompare, dictObjectDestructor, dictVanillaFree, NULL };








dictType setDictType = {
    dictSdsHash,                NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, NULL };







dictType zsetDictType = {
    dictSdsHash,                NULL, NULL, dictSdsKeyCompare, NULL, NULL, NULL };








dictType dbDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, dictObjectDestructor, dictExpandAllowed, dictEntryMetadataSize };









dictType shaScriptObjectDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, dictObjectDestructor, NULL };








dictType dbExpiresDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, NULL, NULL, dictExpandAllowed };








dictType commandTableDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, NULL, NULL };








dictType hashDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, dictSdsDestructor, NULL };








dictType sdsReplyDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, NULL, NULL, NULL };








dictType keylistDictType = {
    dictObjHash,                 NULL, NULL, dictObjKeyCompare, dictObjectDestructor, dictListDestructor, NULL };








dictType modulesDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, NULL, NULL };








dictType migrateCacheDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, NULL, NULL };








dictType replScriptCacheDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, NULL, NULL };







int htNeedsResize(dict *dict) {
    long long size, used;

    size = dictSlots(dict);
    used = dictSize(dict);
    return (size > DICT_HT_INITIAL_SIZE && (used*100/size < HASHTABLE_MIN_FILL));
}


void tryResizeHashTables(int dbid) {
    if (htNeedsResize(server.db[dbid].dict))
        dictResize(server.db[dbid].dict);
    if (htNeedsResize(server.db[dbid].expires))
        dictResize(server.db[dbid].expires);
}


int incrementallyRehash(int dbid) {
    
    if (dictIsRehashing(server.db[dbid].dict)) {
        dictRehashMilliseconds(server.db[dbid].dict,1);
        return 1; 
    }
    
    if (dictIsRehashing(server.db[dbid].expires)) {
        dictRehashMilliseconds(server.db[dbid].expires,1);
        return 1; 
    }
    return 0;
}


void updateDictResizePolicy(void) {
    if (!hasActiveChildProcess())
        dictEnableResize();
    else dictDisableResize();
}

const char *strChildType(int type) {
    switch(type) {
        case CHILD_TYPE_RDB: return "RDB";
        case CHILD_TYPE_AOF: return "AOF";
        case CHILD_TYPE_LDB: return "LDB";
        case CHILD_TYPE_MODULE: return "MODULE";
        default: return "Unknown";
    }
}


int hasActiveChildProcess() {
    return server.child_pid != -1;
}

void resetChildState() {
    server.child_type = CHILD_TYPE_NONE;
    server.child_pid = -1;
    server.stat_current_cow_peak = 0;
    server.stat_current_cow_bytes = 0;
    server.stat_current_cow_updated = 0;
    server.stat_current_save_keys_processed = 0;
    server.stat_module_progress = 0;
    server.stat_current_save_keys_total = 0;
    updateDictResizePolicy();
    closeChildInfoPipe();
    moduleFireServerEvent(REDISMODULE_EVENT_FORK_CHILD, REDISMODULE_SUBEVENT_FORK_CHILD_DIED, NULL);

}


int isMutuallyExclusiveChildType(int type) {
    return type == CHILD_TYPE_RDB || type == CHILD_TYPE_AOF || type == CHILD_TYPE_MODULE;
}


int allPersistenceDisabled(void) {
    return server.saveparamslen == 0 && server.aof_state == AOF_OFF;
}




void trackInstantaneousMetric(int metric, long long current_reading) {
    long long now = mstime();
    long long t = now - server.inst_metric[metric].last_sample_time;
    long long ops = current_reading - server.inst_metric[metric].last_sample_count;
    long long ops_sec;

    ops_sec = t > 0 ? (ops*1000/t) : 0;

    server.inst_metric[metric].samples[server.inst_metric[metric].idx] = ops_sec;
    server.inst_metric[metric].idx++;
    server.inst_metric[metric].idx %= STATS_METRIC_SAMPLES;
    server.inst_metric[metric].last_sample_time = now;
    server.inst_metric[metric].last_sample_count = current_reading;
}


long long getInstantaneousMetric(int metric) {
    int j;
    long long sum = 0;

    for (j = 0; j < STATS_METRIC_SAMPLES; j++)
        sum += server.inst_metric[metric].samples[j];
    return sum / STATS_METRIC_SAMPLES;
}


int clientsCronResizeQueryBuffer(client *c) {
    size_t querybuf_size = sdsalloc(c->querybuf);
    time_t idletime = server.unixtime - c->lastinteraction;

    
    if (sdsavail(c->querybuf) > 1024*4) {
        
        if (idletime > 2) {
            
            c->querybuf = sdsRemoveFreeSpace(c->querybuf);
        } else if (querybuf_size > PROTO_RESIZE_THRESHOLD && querybuf_size/2 > c->querybuf_peak) {
            
            size_t resize = sdslen(c->querybuf);
            if (resize < c->querybuf_peak) resize = c->querybuf_peak;
            if (c->bulklen != -1 && resize < (size_t)c->bulklen) resize = c->bulklen;
            c->querybuf = sdsResize(c->querybuf, resize);
        }
    }

    
    c->querybuf_peak = sdslen(c->querybuf);
    
    if (c->bulklen != -1 && (size_t)c->bulklen > c->querybuf_peak)
        c->querybuf_peak = c->bulklen;

    
    if (c->flags & CLIENT_MASTER) {
        
        size_t pending_querybuf_size = sdsAllocSize(c->pending_querybuf);
        if(pending_querybuf_size > LIMIT_PENDING_QUERYBUF && sdslen(c->pending_querybuf) < (pending_querybuf_size/2))
        {
            c->pending_querybuf = sdsRemoveFreeSpace(c->pending_querybuf);
        }
    }
    return 0;
}



size_t ClientsPeakMemInput[CLIENTS_PEAK_MEM_USAGE_SLOTS] = {0};
size_t ClientsPeakMemOutput[CLIENTS_PEAK_MEM_USAGE_SLOTS] = {0};

int clientsCronTrackExpansiveClients(client *c, int time_idx) {
    size_t in_usage = sdsZmallocSize(c->querybuf) + c->argv_len_sum + (c->argv ? zmalloc_size(c->argv) : 0);
    size_t out_usage = getClientOutputBufferMemoryUsage(c);

    
    if (in_usage > ClientsPeakMemInput[time_idx]) ClientsPeakMemInput[time_idx] = in_usage;
    if (out_usage > ClientsPeakMemOutput[time_idx]) ClientsPeakMemOutput[time_idx] = out_usage;

    return 0; 
}


clientMemUsageBucket *getMemUsageBucket(size_t mem) {
    int size_in_bits = 8*(int)sizeof(mem);
    int clz = mem > 0 ? __builtin_clzl(mem) : size_in_bits;
    int bucket_idx = size_in_bits - clz;
    if (bucket_idx > CLIENT_MEM_USAGE_BUCKET_MAX_LOG)
        bucket_idx = CLIENT_MEM_USAGE_BUCKET_MAX_LOG;
    else if (bucket_idx < CLIENT_MEM_USAGE_BUCKET_MIN_LOG)
        bucket_idx = CLIENT_MEM_USAGE_BUCKET_MIN_LOG;
    bucket_idx -= CLIENT_MEM_USAGE_BUCKET_MIN_LOG;
    return &server.client_mem_usage_buckets[bucket_idx];
}


int updateClientMemUsage(client *c) {
    size_t mem = getClientMemoryUsage(c, NULL);
    int type = getClientType(c);

    
    atomicDecr(server.stat_clients_type_memory[c->last_memory_type], c->last_memory_usage);
    atomicIncr(server.stat_clients_type_memory[type], mem);

    
    c->last_memory_usage = mem;
    c->last_memory_type = type;

    
    if (io_threads_op == IO_THREADS_OP_IDLE)
        updateClientMemUsageBucket(c);

    return 0;
}


void updateClientMemUsageBucket(client *c) {
    serverAssert(io_threads_op == IO_THREADS_OP_IDLE);
    int allow_eviction = (c->last_memory_type == CLIENT_TYPE_NORMAL || c->last_memory_type == CLIENT_TYPE_PUBSUB) && !(c->flags & CLIENT_NO_EVICT);


    
    if (c->mem_usage_bucket) {
        c->mem_usage_bucket->mem_usage_sum -= c->last_memory_usage_on_bucket_update;
        
        if (!allow_eviction) {
            listDelNode(c->mem_usage_bucket->clients, c->mem_usage_bucket_node);
            c->mem_usage_bucket = NULL;
            c->mem_usage_bucket_node = NULL;
        }
    }
    if (allow_eviction) {
        clientMemUsageBucket *bucket = getMemUsageBucket(c->last_memory_usage);
        bucket->mem_usage_sum += c->last_memory_usage;
        if (bucket != c->mem_usage_bucket) {
            if (c->mem_usage_bucket)
                listDelNode(c->mem_usage_bucket->clients, c->mem_usage_bucket_node);
            c->mem_usage_bucket = bucket;
            listAddNodeTail(bucket->clients, c);
            c->mem_usage_bucket_node = listLast(bucket->clients);
        }
    }

    c->last_memory_usage_on_bucket_update = c->last_memory_usage;
}


void getExpansiveClientsInfo(size_t *in_usage, size_t *out_usage) {
    size_t i = 0, o = 0;
    for (int j = 0; j < CLIENTS_PEAK_MEM_USAGE_SLOTS; j++) {
        if (ClientsPeakMemInput[j] > i) i = ClientsPeakMemInput[j];
        if (ClientsPeakMemOutput[j] > o) o = ClientsPeakMemOutput[j];
    }
    *in_usage = i;
    *out_usage = o;
}



void clientsCron(void) {
    
    int numclients = listLength(server.clients);
    int iterations = numclients/server.hz;
    mstime_t now = mstime();

    
    if (iterations < CLIENTS_CRON_MIN_ITERATIONS)
        iterations = (numclients < CLIENTS_CRON_MIN_ITERATIONS) ? numclients : CLIENTS_CRON_MIN_ITERATIONS;


    int curr_peak_mem_usage_slot = server.unixtime % CLIENTS_PEAK_MEM_USAGE_SLOTS;
    
    int zeroidx = (curr_peak_mem_usage_slot+1) % CLIENTS_PEAK_MEM_USAGE_SLOTS;
    ClientsPeakMemInput[zeroidx] = 0;
    ClientsPeakMemOutput[zeroidx] = 0;


    while(listLength(server.clients) && iterations--) {
        client *c;
        listNode *head;

        
        listRotateTailToHead(server.clients);
        head = listFirst(server.clients);
        c = listNodeValue(head);
        
        if (clientsCronHandleTimeout(c,now)) continue;
        if (clientsCronResizeQueryBuffer(c)) continue;
        if (clientsCronTrackExpansiveClients(c, curr_peak_mem_usage_slot)) continue;

        
        if (updateClientMemUsage(c)) continue;
        if (closeClientOnOutputBufferLimitReached(c, 0)) continue;
    }
}


void databasesCron(void) {
    
    if (server.active_expire_enabled) {
        if (iAmMaster()) {
            activeExpireCycle(ACTIVE_EXPIRE_CYCLE_SLOW);
        } else {
            expireSlaveKeys();
        }
    }

    
    activeDefragCycle();

    
    if (!hasActiveChildProcess()) {
        
        static unsigned int resize_db = 0;
        static unsigned int rehash_db = 0;
        int dbs_per_call = CRON_DBS_PER_CALL;
        int j;

        
        if (dbs_per_call > server.dbnum) dbs_per_call = server.dbnum;

        
        for (j = 0; j < dbs_per_call; j++) {
            tryResizeHashTables(resize_db % server.dbnum);
            resize_db++;
        }

        
        if (server.activerehashing) {
            for (j = 0; j < dbs_per_call; j++) {
                int work_done = incrementallyRehash(rehash_db);
                if (work_done) {
                    
                    break;
                } else {
                    
                    rehash_db++;
                    rehash_db %= server.dbnum;
                }
            }
        }
    }
}


void updateCachedTime(int update_daylight_info) {
    server.ustime = ustime();
    server.mstime = server.ustime / 1000;
    time_t unixtime = server.mstime / 1000;
    atomicSet(server.unixtime, unixtime);

    
    if (update_daylight_info) {
        struct tm tm;
        time_t ut = server.unixtime;
        localtime_r(&ut,&tm);
        server.daylight_active = tm.tm_isdst;
    }
}

void checkChildrenDone(void) {
    int statloc = 0;
    pid_t pid;

    if ((pid = waitpid(-1, &statloc, WNOHANG)) != 0) {
        int exitcode = WIFEXITED(statloc) ? WEXITSTATUS(statloc) : -1;
        int bysignal = 0;

        if (WIFSIGNALED(statloc)) bysignal = WTERMSIG(statloc);

        
        if (exitcode == SERVER_CHILD_NOERROR_RETVAL) {
            bysignal = SIGUSR1;
            exitcode = 1;
        }

        if (pid == -1) {
            serverLog(LL_WARNING,"waitpid() returned an error: %s. " "child_type: %s, child_pid = %d", strerror(errno), strChildType(server.child_type), (int) server.child_pid);



        } else if (pid == server.child_pid) {
            if (server.child_type == CHILD_TYPE_RDB) {
                backgroundSaveDoneHandler(exitcode, bysignal);
            } else if (server.child_type == CHILD_TYPE_AOF) {
                backgroundRewriteDoneHandler(exitcode, bysignal);
            } else if (server.child_type == CHILD_TYPE_MODULE) {
                ModuleForkDoneHandler(exitcode, bysignal);
            } else {
                serverPanic("Unknown child type %d for child pid %d", server.child_type, server.child_pid);
                exit(1);
            }
            if (!bysignal && exitcode == 0) receiveChildInfo();
            resetChildState();
        } else {
            if (!ldbRemoveChild(pid)) {
                serverLog(LL_WARNING, "Warning, detected child with unmatched pid: %ld", (long) pid);

            }
        }

        
        replicationStartPendingFork();
    }
}


void cronUpdateMemoryStats() {
    
    if (zmalloc_used_memory() > server.stat_peak_memory)
        server.stat_peak_memory = zmalloc_used_memory();

    run_with_period(100) {
        
        server.cron_malloc_stats.process_rss = zmalloc_get_rss();
        server.cron_malloc_stats.zmalloc_used = zmalloc_used_memory();
        
        zmalloc_get_allocator_info(&server.cron_malloc_stats.allocator_allocated, &server.cron_malloc_stats.allocator_active, &server.cron_malloc_stats.allocator_resident);

        
        if (!server.cron_malloc_stats.allocator_resident) {
            
            size_t lua_memory = lua_gc(server.lua,LUA_GCCOUNT,0)*1024LL;
            server.cron_malloc_stats.allocator_resident = server.cron_malloc_stats.process_rss - lua_memory;
        }
        if (!server.cron_malloc_stats.allocator_active)
            server.cron_malloc_stats.allocator_active = server.cron_malloc_stats.allocator_resident;
        if (!server.cron_malloc_stats.allocator_allocated)
            server.cron_malloc_stats.allocator_allocated = server.cron_malloc_stats.zmalloc_used;
    }
}



int serverCron(struct aeEventLoop *eventLoop, long long id, void *clientData) {
    int j;
    UNUSED(eventLoop);
    UNUSED(id);
    UNUSED(clientData);

    
    if (server.watchdog_period) watchdogScheduleSignal(server.watchdog_period);

    
    updateCachedTime(1);

    server.hz = server.config_hz;
    
    if (server.dynamic_hz) {
        while (listLength(server.clients) / server.hz > MAX_CLIENTS_PER_CLOCK_TICK)
        {
            server.hz *= 2;
            if (server.hz > CONFIG_MAX_HZ) {
                server.hz = CONFIG_MAX_HZ;
                break;
            }
        }
    }

    
    if (server.pause_cron) return 1000/server.hz;

    run_with_period(100) {
        long long stat_net_input_bytes, stat_net_output_bytes;
        atomicGet(server.stat_net_input_bytes, stat_net_input_bytes);
        atomicGet(server.stat_net_output_bytes, stat_net_output_bytes);

        trackInstantaneousMetric(STATS_METRIC_COMMAND,server.stat_numcommands);
        trackInstantaneousMetric(STATS_METRIC_NET_INPUT, stat_net_input_bytes);
        trackInstantaneousMetric(STATS_METRIC_NET_OUTPUT, stat_net_output_bytes);
    }

    
    unsigned int lruclock = getLRUClock();
    atomicSet(server.lruclock,lruclock);

    cronUpdateMemoryStats();

    
    if (server.shutdown_asap) {
        if (prepareForShutdown(SHUTDOWN_NOFLAGS) == C_OK) exit(0);
        serverLog(LL_WARNING,"SIGTERM received but errors trying to shut down the server, check the logs for more information");
        server.shutdown_asap = 0;
    }

    
    if (server.verbosity <= LL_VERBOSE) {
        run_with_period(5000) {
            for (j = 0; j < server.dbnum; j++) {
                long long size, used, vkeys;

                size = dictSlots(server.db[j].dict);
                used = dictSize(server.db[j].dict);
                vkeys = dictSize(server.db[j].expires);
                if (used || vkeys) {
                    serverLog(LL_VERBOSE,"DB %d: %lld keys (%lld volatile) in %lld slots HT.",j,used,vkeys,size);
                }
            }
        }
    }

    
    if (!server.sentinel_mode) {
        run_with_period(5000) {
            serverLog(LL_DEBUG, "%lu clients connected (%lu replicas), %zu bytes in use", listLength(server.clients)-listLength(server.slaves), listLength(server.slaves), zmalloc_used_memory());



        }
    }

    
    clientsCron();

    
    databasesCron();

    
    if (!hasActiveChildProcess() && server.aof_rewrite_scheduled)
    {
        rewriteAppendOnlyFileBackground();
    }

    
    if (hasActiveChildProcess() || ldbPendingChildren())
    {
        run_with_period(1000) receiveChildInfo();
        checkChildrenDone();
    } else {
        
        for (j = 0; j < server.saveparamslen; j++) {
            struct saveparam *sp = server.saveparams+j;

            
            if (server.dirty >= sp->changes && server.unixtime-server.lastsave > sp->seconds && (server.unixtime-server.lastbgsave_try > CONFIG_BGSAVE_RETRY_DELAY || server.lastbgsave_status == C_OK))



            {
                serverLog(LL_NOTICE,"%d changes in %d seconds. Saving...", sp->changes, (int)sp->seconds);
                rdbSaveInfo rsi, *rsiptr;
                rsiptr = rdbPopulateSaveInfo(&rsi);
                rdbSaveBackground(server.rdb_filename,rsiptr);
                break;
            }
        }

        
        if (server.aof_state == AOF_ON && !hasActiveChildProcess() && server.aof_rewrite_perc && server.aof_current_size > server.aof_rewrite_min_size)


        {
            long long base = server.aof_rewrite_base_size ? server.aof_rewrite_base_size : 1;
            long long growth = (server.aof_current_size*100/base) - 100;
            if (growth >= server.aof_rewrite_perc) {
                serverLog(LL_NOTICE,"Starting automatic rewriting of AOF on %lld%% growth",growth);
                rewriteAppendOnlyFileBackground();
            }
        }
    }
    
    updateDictResizePolicy();


    
    if (server.aof_state == AOF_ON && server.aof_flush_postponed_start)
        flushAppendOnlyFile(0);

    
    run_with_period(1000) {
        if (server.aof_state == AOF_ON && server.aof_last_write_status == C_ERR)
            flushAppendOnlyFile(0);
    }

    
    checkClientPauseTimeoutAndReturnIfPaused();

    
    if (server.failover_state != NO_FAILOVER) {
        run_with_period(100) replicationCron();
    } else {
        run_with_period(1000) replicationCron();
    }

    
    run_with_period(100) {
        if (server.cluster_enabled) clusterCron();
    }

    
    if (server.sentinel_mode) sentinelTimer();

    
    run_with_period(1000) {
        migrateCloseTimedoutSockets();
    }

    
    stopThreadedIOIfNeeded();

    
    if (server.tracking_clients) trackingLimitUsedSlots();

    
    if (!hasActiveChildProcess() && server.rdb_bgsave_scheduled && (server.unixtime-server.lastbgsave_try > CONFIG_BGSAVE_RETRY_DELAY || server.lastbgsave_status == C_OK))


    {
        rdbSaveInfo rsi, *rsiptr;
        rsiptr = rdbPopulateSaveInfo(&rsi);
        if (rdbSaveBackground(server.rdb_filename,rsiptr) == C_OK)
            server.rdb_bgsave_scheduled = 0;
    }

    
    RedisModuleCronLoopV1 ei = {REDISMODULE_CRON_LOOP_VERSION,server.hz};
    moduleFireServerEvent(REDISMODULE_EVENT_CRON_LOOP, 0, &ei);


    server.cronloops++;
    return 1000/server.hz;
}


void blockingOperationStarts() {
    if(!server.blocking_op_nesting++){
        updateCachedTime(0);
        server.blocked_last_cron = server.mstime;
    }
}

void blockingOperationEnds() {
    if(!(--server.blocking_op_nesting)){
        server.blocked_last_cron = 0;
    }
}


void whileBlockedCron() {
    

    
    serverAssert(server.blocked_last_cron);

    
    if (server.blocked_last_cron >= server.mstime)
        return;

    mstime_t latency;
    latencyStartMonitor(latency);

    
    long hz_ms = 1000/server.hz;
    while (server.blocked_last_cron < server.mstime) {

        
        activeDefragCycle();

        server.blocked_last_cron += hz_ms;

        
        server.cronloops++;
    }

    

    
    if (server.loading) cronUpdateMemoryStats();

    latencyEndMonitor(latency);
    latencyAddSampleIfNeeded("while-blocked-cron",latency);
}

extern int ProcessingEventsWhileBlocked;


void beforeSleep(struct aeEventLoop *eventLoop) {
    UNUSED(eventLoop);

    size_t zmalloc_used = zmalloc_used_memory();
    if (zmalloc_used > server.stat_peak_memory)
        server.stat_peak_memory = zmalloc_used;

    
    if (ProcessingEventsWhileBlocked) {
        uint64_t processed = 0;
        processed += handleClientsWithPendingReadsUsingThreads();
        processed += tlsProcessPendingData();
        processed += handleClientsWithPendingWrites();
        processed += freeClientsInAsyncFreeQueue();
        server.events_processed_while_blocked += processed;
        return;
    }

    
    handleBlockedClientsTimeout();

    
    handleClientsWithPendingReadsUsingThreads();

    
    tlsProcessPendingData();

    
    aeSetDontWait(server.el, tlsHasPendingData());

    
    if (server.cluster_enabled) clusterBeforeSleep();

    
    if (server.active_expire_enabled && server.masterhost == NULL)
        activeExpireCycle(ACTIVE_EXPIRE_CYCLE_FAST);

    
    if (listLength(server.clients_waiting_acks))
        processClientsWaitingReplicas();

    
    if (moduleCount()) moduleHandleBlockedClients();

    
    if (listLength(server.unblocked_clients))
        processUnblockedClients();

    
    if (server.get_ack_from_slaves && !checkClientPauseTimeoutAndReturnIfPaused()) {
        robj *argv[3];

        argv[0] = shared.replconf;
        argv[1] = shared.getack;
        argv[2] = shared.special_asterick; 
        replicationFeedSlaves(server.slaves, server.slaveseldb, argv, 3);
        server.get_ack_from_slaves = 0;
    }

    
    updateFailoverStatus();

    
    trackingBroadcastInvalidationMessages();

    
    if (server.aof_state == AOF_ON)
        flushAppendOnlyFile(0);

    
    handleClientsWithPendingWritesUsingThreads();

    
    freeClientsInAsyncFreeQueue();

    
    handleClientsBlockedOnKeys();

    
    evictClients();

    
    if (moduleCount()) moduleReleaseGIL();

    
}


void afterSleep(struct aeEventLoop *eventLoop) {
    UNUSED(eventLoop);

    

    
    if (!ProcessingEventsWhileBlocked) {
        if (moduleCount()) moduleAcquireGIL();
    }
}



void createSharedObjects(void) {
    int j;

    
    shared.crlf = createObject(OBJ_STRING,sdsnew("\r\n"));
    shared.ok = createObject(OBJ_STRING,sdsnew("+OK\r\n"));
    shared.emptybulk = createObject(OBJ_STRING,sdsnew("$0\r\n\r\n"));
    shared.czero = createObject(OBJ_STRING,sdsnew(":0\r\n"));
    shared.cone = createObject(OBJ_STRING,sdsnew(":1\r\n"));
    shared.emptyarray = createObject(OBJ_STRING,sdsnew("*0\r\n"));
    shared.pong = createObject(OBJ_STRING,sdsnew("+PONG\r\n"));
    shared.queued = createObject(OBJ_STRING,sdsnew("+QUEUED\r\n"));
    shared.emptyscan = createObject(OBJ_STRING,sdsnew("*2\r\n$1\r\n0\r\n*0\r\n"));
    shared.space = createObject(OBJ_STRING,sdsnew(" "));
    shared.plus = createObject(OBJ_STRING,sdsnew("+"));

    
    shared.wrongtypeerr = createObject(OBJ_STRING,sdsnew( "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"));
    shared.err = createObject(OBJ_STRING,sdsnew("-ERR\r\n"));
    shared.nokeyerr = createObject(OBJ_STRING,sdsnew( "-ERR no such key\r\n"));
    shared.syntaxerr = createObject(OBJ_STRING,sdsnew( "-ERR syntax error\r\n"));
    shared.sameobjecterr = createObject(OBJ_STRING,sdsnew( "-ERR source and destination objects are the same\r\n"));
    shared.outofrangeerr = createObject(OBJ_STRING,sdsnew( "-ERR index out of range\r\n"));
    shared.noscripterr = createObject(OBJ_STRING,sdsnew( "-NOSCRIPT No matching script. Please use EVAL.\r\n"));
    shared.loadingerr = createObject(OBJ_STRING,sdsnew( "-LOADING Redis is loading the dataset in memory\r\n"));
    shared.slowscripterr = createObject(OBJ_STRING,sdsnew( "-BUSY Redis is busy running a script. You can only call SCRIPT KILL or SHUTDOWN NOSAVE.\r\n"));
    shared.masterdownerr = createObject(OBJ_STRING,sdsnew( "-MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to 'no'.\r\n"));
    shared.bgsaveerr = createObject(OBJ_STRING,sdsnew( "-MISCONF Redis is configured to save RDB snapshots, but it is currently not able to persist on disk. Commands that may modify the data set are disabled, because this instance is configured to report errors during writes if RDB snapshotting fails (stop-writes-on-bgsave-error option). Please check the Redis logs for details about the RDB error.\r\n"));
    shared.roslaveerr = createObject(OBJ_STRING,sdsnew( "-READONLY You can't write against a read only replica.\r\n"));
    shared.noautherr = createObject(OBJ_STRING,sdsnew( "-NOAUTH Authentication required.\r\n"));
    shared.oomerr = createObject(OBJ_STRING,sdsnew( "-OOM command not allowed when used memory > 'maxmemory'.\r\n"));
    shared.execaborterr = createObject(OBJ_STRING,sdsnew( "-EXECABORT Transaction discarded because of previous errors.\r\n"));
    shared.noreplicaserr = createObject(OBJ_STRING,sdsnew( "-NOREPLICAS Not enough good replicas to write.\r\n"));
    shared.busykeyerr = createObject(OBJ_STRING,sdsnew( "-BUSYKEY Target key name already exists.\r\n"));

    
    shared.null[0] = NULL;
    shared.null[1] = NULL;
    shared.null[2] = createObject(OBJ_STRING,sdsnew("$-1\r\n"));
    shared.null[3] = createObject(OBJ_STRING,sdsnew("_\r\n"));

    shared.nullarray[0] = NULL;
    shared.nullarray[1] = NULL;
    shared.nullarray[2] = createObject(OBJ_STRING,sdsnew("*-1\r\n"));
    shared.nullarray[3] = createObject(OBJ_STRING,sdsnew("_\r\n"));

    shared.emptymap[0] = NULL;
    shared.emptymap[1] = NULL;
    shared.emptymap[2] = createObject(OBJ_STRING,sdsnew("*0\r\n"));
    shared.emptymap[3] = createObject(OBJ_STRING,sdsnew("%0\r\n"));

    shared.emptyset[0] = NULL;
    shared.emptyset[1] = NULL;
    shared.emptyset[2] = createObject(OBJ_STRING,sdsnew("*0\r\n"));
    shared.emptyset[3] = createObject(OBJ_STRING,sdsnew("~0\r\n"));

    for (j = 0; j < PROTO_SHARED_SELECT_CMDS; j++) {
        char dictid_str[64];
        int dictid_len;

        dictid_len = ll2string(dictid_str,sizeof(dictid_str),j);
        shared.select[j] = createObject(OBJ_STRING, sdscatprintf(sdsempty(), "*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n", dictid_len, dictid_str));


    }
    shared.messagebulk = createStringObject("$7\r\nmessage\r\n",13);
    shared.pmessagebulk = createStringObject("$8\r\npmessage\r\n",14);
    shared.subscribebulk = createStringObject("$9\r\nsubscribe\r\n",15);
    shared.unsubscribebulk = createStringObject("$11\r\nunsubscribe\r\n",18);
    shared.psubscribebulk = createStringObject("$10\r\npsubscribe\r\n",17);
    shared.punsubscribebulk = createStringObject("$12\r\npunsubscribe\r\n",19);

    
    shared.del = createStringObject("DEL",3);
    shared.unlink = createStringObject("UNLINK",6);
    shared.rpop = createStringObject("RPOP",4);
    shared.lpop = createStringObject("LPOP",4);
    shared.lpush = createStringObject("LPUSH",5);
    shared.rpoplpush = createStringObject("RPOPLPUSH",9);
    shared.lmove = createStringObject("LMOVE",5);
    shared.blmove = createStringObject("BLMOVE",6);
    shared.zpopmin = createStringObject("ZPOPMIN",7);
    shared.zpopmax = createStringObject("ZPOPMAX",7);
    shared.multi = createStringObject("MULTI",5);
    shared.exec = createStringObject("EXEC",4);
    shared.hset = createStringObject("HSET",4);
    shared.srem = createStringObject("SREM",4);
    shared.xgroup = createStringObject("XGROUP",6);
    shared.xclaim = createStringObject("XCLAIM",6);
    shared.script = createStringObject("SCRIPT",6);
    shared.replconf = createStringObject("REPLCONF",8);
    shared.pexpireat = createStringObject("PEXPIREAT",9);
    shared.pexpire = createStringObject("PEXPIRE",7);
    shared.persist = createStringObject("PERSIST",7);
    shared.set = createStringObject("SET",3);
    shared.eval = createStringObject("EVAL",4);

    
    shared.left = createStringObject("left",4);
    shared.right = createStringObject("right",5);
    shared.pxat = createStringObject("PXAT", 4);
    shared.time = createStringObject("TIME",4);
    shared.retrycount = createStringObject("RETRYCOUNT",10);
    shared.force = createStringObject("FORCE",5);
    shared.justid = createStringObject("JUSTID",6);
    shared.lastid = createStringObject("LASTID",6);
    shared.default_username = createStringObject("default",7);
    shared.ping = createStringObject("ping",4);
    shared.setid = createStringObject("SETID",5);
    shared.keepttl = createStringObject("KEEPTTL",7);
    shared.absttl = createStringObject("ABSTTL",6);
    shared.load = createStringObject("LOAD",4);
    shared.createconsumer = createStringObject("CREATECONSUMER",14);
    shared.getack = createStringObject("GETACK",6);
    shared.special_asterick = createStringObject("*",1);
    shared.special_equals = createStringObject("=",1);
    shared.redacted = makeObjectShared(createStringObject("(redacted)",10));

    for (j = 0; j < OBJ_SHARED_INTEGERS; j++) {
        shared.integers[j] = makeObjectShared(createObject(OBJ_STRING,(void*)(long)j));
        shared.integers[j]->encoding = OBJ_ENCODING_INT;
    }
    for (j = 0; j < OBJ_SHARED_BULKHDR_LEN; j++) {
        shared.mbulkhdr[j] = createObject(OBJ_STRING, sdscatprintf(sdsempty(),"*%d\r\n",j));
        shared.bulkhdr[j] = createObject(OBJ_STRING, sdscatprintf(sdsempty(),"$%d\r\n",j));
    }
    
    shared.minstring = sdsnew("minstring");
    shared.maxstring = sdsnew("maxstring");
}

void initServerConfig(void) {
    int j;
    char *default_bindaddr[CONFIG_DEFAULT_BINDADDR_COUNT] = CONFIG_DEFAULT_BINDADDR;

    updateCachedTime(1);
    getRandomHexChars(server.runid,CONFIG_RUN_ID_SIZE);
    server.runid[CONFIG_RUN_ID_SIZE] = '\0';
    changeReplicationId();
    clearReplicationId2();
    server.hz = CONFIG_DEFAULT_HZ; 
    server.timezone = getTimeZone(); 
    server.configfile = NULL;
    server.executable = NULL;
    server.arch_bits = (sizeof(long) == 8) ? 64 : 32;
    server.bindaddr_count = CONFIG_DEFAULT_BINDADDR_COUNT;
    for (j = 0; j < CONFIG_DEFAULT_BINDADDR_COUNT; j++)
        server.bindaddr[j] = zstrdup(default_bindaddr[j]);
    server.bind_source_addr = NULL;
    server.unixsocketperm = CONFIG_DEFAULT_UNIX_SOCKET_PERM;
    server.ipfd.count = 0;
    server.tlsfd.count = 0;
    server.sofd = -1;
    server.active_expire_enabled = 1;
    server.skip_checksum_validation = 0;
    server.saveparams = NULL;
    server.loading = 0;
    server.loading_rdb_used_mem = 0;
    server.logfile = zstrdup(CONFIG_DEFAULT_LOGFILE);
    server.aof_state = AOF_OFF;
    server.aof_rewrite_base_size = 0;
    server.aof_rewrite_scheduled = 0;
    server.aof_flush_sleep = 0;
    server.aof_last_fsync = time(NULL);
    atomicSet(server.aof_bio_fsync_status,C_OK);
    server.aof_rewrite_time_last = -1;
    server.aof_rewrite_time_start = -1;
    server.aof_lastbgrewrite_status = C_OK;
    server.aof_delayed_fsync = 0;
    server.aof_fd = -1;
    server.aof_selected_db = -1; 
    server.aof_flush_postponed_start = 0;
    server.pidfile = NULL;
    server.active_defrag_running = 0;
    server.notify_keyspace_events = 0;
    server.blocked_clients = 0;
    memset(server.blocked_clients_by_type,0, sizeof(server.blocked_clients_by_type));
    server.shutdown_asap = 0;
    server.cluster_configfile = zstrdup(CONFIG_DEFAULT_CLUSTER_CONFIG_FILE);
    server.cluster_module_flags = CLUSTER_MODULE_FLAG_NONE;
    server.migrate_cached_sockets = dictCreate(&migrateCacheDictType);
    server.next_client_id = 1; 
    server.loading_process_events_interval_bytes = (1024*1024*2);
    server.page_size = sysconf(_SC_PAGESIZE);
    server.pause_cron = 0;

    unsigned int lruclock = getLRUClock();
    atomicSet(server.lruclock,lruclock);
    resetServerSaveParams();

    appendServerSaveParams(60*60,1);  
    appendServerSaveParams(300,100);  
    appendServerSaveParams(60,10000); 

    
    server.masterauth = NULL;
    server.masterhost = NULL;
    server.masterport = 6379;
    server.master = NULL;
    server.cached_master = NULL;
    server.master_initial_offset = -1;
    server.repl_state = REPL_STATE_NONE;
    server.repl_transfer_tmpfile = NULL;
    server.repl_transfer_fd = -1;
    server.repl_transfer_s = NULL;
    server.repl_syncio_timeout = CONFIG_REPL_SYNCIO_TIMEOUT;
    server.repl_down_since = 0; 
    server.master_repl_offset = 0;

    
    server.repl_backlog = NULL;
    server.repl_backlog_histlen = 0;
    server.repl_backlog_idx = 0;
    server.repl_backlog_off = 0;
    server.repl_no_slaves_since = time(NULL);

    
    server.failover_end_time = 0;
    server.force_failover = 0;
    server.target_replica_host = NULL;
    server.target_replica_port = 0;
    server.failover_state = NO_FAILOVER;

    
    for (j = 0; j < CLIENT_TYPE_OBUF_COUNT; j++)
        server.client_obuf_limits[j] = clientBufferLimitsDefaults[j];

    
    for (j = 0; j < CONFIG_OOM_COUNT; j++)
        server.oom_score_adj_values[j] = configOOMScoreAdjValuesDefaults[j];

    
    R_Zero = 0.0;
    R_PosInf = 1.0/R_Zero;
    R_NegInf = -1.0/R_Zero;
    R_Nan = R_Zero/R_Zero;

    
    server.commands = dictCreate(&commandTableDictType);
    server.orig_commands = dictCreate(&commandTableDictType);
    populateCommandTable();

    
    server.watchdog_period = 0;

    
    server.lua_always_replicate_commands = 1;

    initConfigValues();
}

extern char **environ;


int restartServer(int flags, mstime_t delay) {
    int j;

    
    if (access(server.executable,X_OK) == -1) {
        serverLog(LL_WARNING,"Can't restart: this process has no " "permissions to execute %s", server.executable);
        return C_ERR;
    }

    
    if (flags & RESTART_SERVER_CONFIG_REWRITE && server.configfile && rewriteConfig(server.configfile, 0) == -1)

    {
        serverLog(LL_WARNING,"Can't restart: configuration rewrite process " "failed");
        return C_ERR;
    }

    
    if (flags & RESTART_SERVER_GRACEFULLY && prepareForShutdown(SHUTDOWN_NOFLAGS) != C_OK)
    {
        serverLog(LL_WARNING,"Can't restart: error preparing for shutdown");
        return C_ERR;
    }

    
    for (j = 3; j < (int)server.maxclients + 1024; j++) {
        
        if (fcntl(j,F_GETFD) != -1) close(j);
    }

    
    if (delay) usleep(delay*1000);
    zfree(server.exec_argv[0]);
    server.exec_argv[0] = zstrdup(server.executable);
    execve(server.executable,server.exec_argv,environ);

    
    _exit(1);

    return C_ERR; 
}

static void readOOMScoreAdj(void) {

    char buf[64];
    int fd = open("/proc/self/oom_score_adj", O_RDONLY);

    if (fd < 0) return;
    if (read(fd, buf, sizeof(buf)) > 0)
        server.oom_score_adj_base = atoi(buf);
    close(fd);

}


int setOOMScoreAdj(int process_class) {

    if (server.oom_score_adj == OOM_SCORE_ADJ_NO) return C_OK;
    if (process_class == -1)
        process_class = (server.masterhost ? CONFIG_OOM_REPLICA : CONFIG_OOM_MASTER);

    serverAssert(process_class >= 0 && process_class < CONFIG_OOM_COUNT);


    int fd;
    int val;
    char buf[64];

    val = server.oom_score_adj_values[process_class];
    if (server.oom_score_adj == OOM_SCORE_RELATIVE)
        val += server.oom_score_adj_base;
    if (val > 1000) val = 1000;
    if (val < -1000) val = -1000;

    snprintf(buf, sizeof(buf) - 1, "%d\n", val);

    fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd < 0 || write(fd, buf, strlen(buf)) < 0) {
        serverLog(LL_WARNING, "Unable to write oom_score_adj: %s", strerror(errno));
        if (fd != -1) close(fd);
        return C_ERR;
    }

    close(fd);
    return C_OK;

    
    return C_ERR;

}


void adjustOpenFilesLimit(void) {
    rlim_t maxfiles = server.maxclients+CONFIG_MIN_RESERVED_FDS;
    struct rlimit limit;

    if (getrlimit(RLIMIT_NOFILE,&limit) == -1) {
        serverLog(LL_WARNING,"Unable to obtain the current NOFILE limit (%s), assuming 1024 and setting the max clients configuration accordingly.", strerror(errno));
        server.maxclients = 1024-CONFIG_MIN_RESERVED_FDS;
    } else {
        rlim_t oldlimit = limit.rlim_cur;

        
        if (oldlimit < maxfiles) {
            rlim_t bestlimit;
            int setrlimit_error = 0;

            
            bestlimit = maxfiles;
            while(bestlimit > oldlimit) {
                rlim_t decr_step = 16;

                limit.rlim_cur = bestlimit;
                limit.rlim_max = bestlimit;
                if (setrlimit(RLIMIT_NOFILE,&limit) != -1) break;
                setrlimit_error = errno;

                
                if (bestlimit < decr_step) {
                    bestlimit = oldlimit;
                    break;
                }
                bestlimit -= decr_step;
            }

            
            if (bestlimit < oldlimit) bestlimit = oldlimit;

            if (bestlimit < maxfiles) {
                unsigned int old_maxclients = server.maxclients;
                server.maxclients = bestlimit-CONFIG_MIN_RESERVED_FDS;
                
                if (bestlimit <= CONFIG_MIN_RESERVED_FDS) {
                    serverLog(LL_WARNING,"Your current 'ulimit -n' " "of %llu is not enough for the server to start. " "Please increase your open file limit to at least " "%llu. Exiting.", (unsigned long long) oldlimit, (unsigned long long) maxfiles);




                    exit(1);
                }
                serverLog(LL_WARNING,"You requested maxclients of %d " "requiring at least %llu max file descriptors.", old_maxclients, (unsigned long long) maxfiles);


                serverLog(LL_WARNING,"Server can't set maximum open files " "to %llu because of OS error: %s.", (unsigned long long) maxfiles, strerror(setrlimit_error));

                serverLog(LL_WARNING,"Current maximum open files is %llu. " "maxclients has been reduced to %d to compensate for " "low ulimit. " "If you need higher maxclients increase 'ulimit -n'.", (unsigned long long) bestlimit, server.maxclients);



            } else {
                serverLog(LL_NOTICE,"Increased maximum number of open files " "to %llu (it was originally set to %llu).", (unsigned long long) maxfiles, (unsigned long long) oldlimit);


            }
        }
    }
}


void checkTcpBacklogSettings(void) {

    FILE *fp = fopen("/proc/sys/net/core/somaxconn","r");
    char buf[1024];
    if (!fp) return;
    if (fgets(buf,sizeof(buf),fp) != NULL) {
        int somaxconn = atoi(buf);
        if (somaxconn > 0 && somaxconn < server.tcp_backlog) {
            serverLog(LL_WARNING,"WARNING: The TCP backlog setting of %d cannot be enforced because /proc/sys/net/core/somaxconn is set to the lower value of %d.", server.tcp_backlog, somaxconn);
        }
    }
    fclose(fp);

}

void closeSocketListeners(socketFds *sfd) {
    int j;

    for (j = 0; j < sfd->count; j++) {
        if (sfd->fd[j] == -1) continue;

        aeDeleteFileEvent(server.el, sfd->fd[j], AE_READABLE);
        close(sfd->fd[j]);
    }

    sfd->count = 0;
}


int createSocketAcceptHandler(socketFds *sfd, aeFileProc *accept_handler) {
    int j;

    for (j = 0; j < sfd->count; j++) {
        if (aeCreateFileEvent(server.el, sfd->fd[j], AE_READABLE, accept_handler,NULL) == AE_ERR) {
            
            for (j = j-1; j >= 0; j--) aeDeleteFileEvent(server.el, sfd->fd[j], AE_READABLE);
            return C_ERR;
        }
    }
    return C_OK;
}


int listenToPort(int port, socketFds *sfd) {
    int j;
    char **bindaddr = server.bindaddr;

    
    if (server.bindaddr_count == 0) return C_OK;

    for (j = 0; j < server.bindaddr_count; j++) {
        char* addr = bindaddr[j];
        int optional = *addr == '-';
        if (optional) addr++;
        if (strchr(addr,':')) {
            
            sfd->fd[sfd->count] = anetTcp6Server(server.neterr,port,addr,server.tcp_backlog);
        } else {
            
            sfd->fd[sfd->count] = anetTcpServer(server.neterr,port,addr,server.tcp_backlog);
        }
        if (sfd->fd[sfd->count] == ANET_ERR) {
            int net_errno = errno;
            serverLog(LL_WARNING, "Warning: Could not create server TCP listening socket %s:%d: %s", addr, port, server.neterr);

            if (net_errno == EADDRNOTAVAIL && optional)
                continue;
            if (net_errno == ENOPROTOOPT     || net_errno == EPROTONOSUPPORT || net_errno == ESOCKTNOSUPPORT || net_errno == EPFNOSUPPORT || net_errno == EAFNOSUPPORT)

                continue;

            
            closeSocketListeners(sfd);
            return C_ERR;
        }
        anetNonBlock(NULL,sfd->fd[sfd->count]);
        anetCloexec(sfd->fd[sfd->count]);
        sfd->count++;
    }
    return C_OK;
}


void resetServerStats(void) {
    int j;

    server.stat_numcommands = 0;
    server.stat_numconnections = 0;
    server.stat_expiredkeys = 0;
    server.stat_expired_stale_perc = 0;
    server.stat_expired_time_cap_reached_count = 0;
    server.stat_expire_cycle_time_used = 0;
    server.stat_evictedkeys = 0;
    server.stat_evictedclients = 0;
    server.stat_total_eviction_exceeded_time = 0;
    server.stat_last_eviction_exceeded_time = 0;
    server.stat_keyspace_misses = 0;
    server.stat_keyspace_hits = 0;
    server.stat_active_defrag_hits = 0;
    server.stat_active_defrag_misses = 0;
    server.stat_active_defrag_key_hits = 0;
    server.stat_active_defrag_key_misses = 0;
    server.stat_active_defrag_scanned = 0;
    server.stat_total_active_defrag_time = 0;
    server.stat_last_active_defrag_time = 0;
    server.stat_fork_time = 0;
    server.stat_fork_rate = 0;
    server.stat_total_forks = 0;
    server.stat_rejected_conn = 0;
    server.stat_sync_full = 0;
    server.stat_sync_partial_ok = 0;
    server.stat_sync_partial_err = 0;
    server.stat_io_reads_processed = 0;
    atomicSet(server.stat_total_reads_processed, 0);
    server.stat_io_writes_processed = 0;
    atomicSet(server.stat_total_writes_processed, 0);
    for (j = 0; j < STATS_METRIC_COUNT; j++) {
        server.inst_metric[j].idx = 0;
        server.inst_metric[j].last_sample_time = mstime();
        server.inst_metric[j].last_sample_count = 0;
        memset(server.inst_metric[j].samples,0, sizeof(server.inst_metric[j].samples));
    }
    atomicSet(server.stat_net_input_bytes, 0);
    atomicSet(server.stat_net_output_bytes, 0);
    server.stat_unexpected_error_replies = 0;
    server.stat_total_error_replies = 0;
    server.stat_dump_payload_sanitizations = 0;
    server.aof_delayed_fsync = 0;
    lazyfreeResetStats();
}


void makeThreadKillable(void) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
}

void initServer(void) {
    int j;

    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    setupSignalHandlers();
    makeThreadKillable();

    if (server.syslog_enabled) {
        openlog(server.syslog_ident, LOG_PID | LOG_NDELAY | LOG_NOWAIT, server.syslog_facility);
    }

    
    server.aof_state = server.aof_enabled ? AOF_ON : AOF_OFF;
    server.hz = server.config_hz;
    server.pid = getpid();
    server.in_fork_child = CHILD_TYPE_NONE;
    server.main_thread_id = pthread_self();
    server.current_client = NULL;
    server.errors = raxNew();
    server.fixed_time_expire = 0;
    server.clients = listCreate();
    server.clients_index = raxNew();
    server.clients_to_close = listCreate();
    server.slaves = listCreate();
    server.monitors = listCreate();
    server.clients_pending_write = listCreate();
    server.clients_pending_read = listCreate();
    server.clients_timeout_table = raxNew();
    server.replication_allowed = 1;
    server.slaveseldb = -1; 
    server.unblocked_clients = listCreate();
    server.ready_keys = listCreate();
    server.clients_waiting_acks = listCreate();
    server.get_ack_from_slaves = 0;
    server.client_pause_type = CLIENT_PAUSE_OFF;
    server.client_pause_end_time = 0;
    server.paused_clients = listCreate();
    server.events_processed_while_blocked = 0;
    server.system_memory_size = zmalloc_get_memory_size();
    server.blocked_last_cron = 0;
    server.blocking_op_nesting = 0;
    server.thp_enabled = 0;

    if ((server.tls_port || server.tls_replication || server.tls_cluster)
                && tlsConfigure(&server.tls_ctx_config) == C_ERR) {
        serverLog(LL_WARNING, "Failed to configure TLS. Check logs for more info.");
        exit(1);
    }

    for (j = 0; j < CLIENT_MEM_USAGE_BUCKETS; j++) {
        server.client_mem_usage_buckets[j].mem_usage_sum = 0;
        server.client_mem_usage_buckets[j].clients = listCreate();
    }

    createSharedObjects();
    adjustOpenFilesLimit();
    const char *clk_msg = monotonicInit();
    serverLog(LL_NOTICE, "monotonic clock: %s", clk_msg);
    server.el = aeCreateEventLoop(server.maxclients+CONFIG_FDSET_INCR);
    if (server.el == NULL) {
        serverLog(LL_WARNING, "Failed creating the event loop. Error message: '%s'", strerror(errno));

        exit(1);
    }
    server.db = zmalloc(sizeof(redisDb)*server.dbnum);

    
    if (server.port != 0 && listenToPort(server.port,&server.ipfd) == C_ERR) {
        serverLog(LL_WARNING, "Failed listening on port %u (TCP), aborting.", server.port);
        exit(1);
    }
    if (server.tls_port != 0 && listenToPort(server.tls_port,&server.tlsfd) == C_ERR) {
        serverLog(LL_WARNING, "Failed listening on port %u (TLS), aborting.", server.tls_port);
        exit(1);
    }

    
    if (server.unixsocket != NULL) {
        unlink(server.unixsocket); 
        server.sofd = anetUnixServer(server.neterr,server.unixsocket, server.unixsocketperm, server.tcp_backlog);
        if (server.sofd == ANET_ERR) {
            serverLog(LL_WARNING, "Opening Unix socket: %s", server.neterr);
            exit(1);
        }
        anetNonBlock(NULL,server.sofd);
        anetCloexec(server.sofd);
    }

    
    if (server.ipfd.count == 0 && server.tlsfd.count == 0 && server.sofd < 0) {
        serverLog(LL_WARNING, "Configured to not listen anywhere, exiting.");
        exit(1);
    }

    
    for (j = 0; j < server.dbnum; j++) {
        server.db[j].dict = dictCreate(&dbDictType);
        server.db[j].expires = dictCreate(&dbExpiresDictType);
        server.db[j].expires_cursor = 0;
        server.db[j].blocking_keys = dictCreate(&keylistDictType);
        server.db[j].ready_keys = dictCreate(&objectKeyPointerValueDictType);
        server.db[j].watched_keys = dictCreate(&keylistDictType);
        server.db[j].id = j;
        server.db[j].avg_ttl = 0;
        server.db[j].defrag_later = listCreate();
        listSetFreeMethod(server.db[j].defrag_later,(void (*)(void*))sdsfree);
    }
    evictionPoolAlloc(); 
    server.pubsub_channels = dictCreate(&keylistDictType);
    server.pubsub_patterns = dictCreate(&keylistDictType);
    server.cronloops = 0;
    server.in_eval = 0;
    server.in_exec = 0;
    server.propagate_in_transaction = 0;
    server.client_pause_in_transaction = 0;
    server.child_pid = -1;
    server.child_type = CHILD_TYPE_NONE;
    server.rdb_child_type = RDB_CHILD_TYPE_NONE;
    server.rdb_pipe_conns = NULL;
    server.rdb_pipe_numconns = 0;
    server.rdb_pipe_numconns_writing = 0;
    server.rdb_pipe_buff = NULL;
    server.rdb_pipe_bufflen = 0;
    server.rdb_bgsave_scheduled = 0;
    server.child_info_pipe[0] = -1;
    server.child_info_pipe[1] = -1;
    server.child_info_nread = 0;
    aofRewriteBufferReset();
    server.aof_buf = sdsempty();
    server.lastsave = time(NULL); 
    server.lastbgsave_try = 0;    
    server.rdb_save_time_last = -1;
    server.rdb_save_time_start = -1;
    server.rdb_last_load_keys_expired = 0;
    server.rdb_last_load_keys_loaded = 0;
    server.dirty = 0;
    resetServerStats();
    
    server.stat_starttime = time(NULL);
    server.stat_peak_memory = 0;
    server.stat_current_cow_peak = 0;
    server.stat_current_cow_bytes = 0;
    server.stat_current_cow_updated = 0;
    server.stat_current_save_keys_processed = 0;
    server.stat_current_save_keys_total = 0;
    server.stat_rdb_cow_bytes = 0;
    server.stat_aof_cow_bytes = 0;
    server.stat_module_cow_bytes = 0;
    server.stat_module_progress = 0;
    for (int j = 0; j < CLIENT_TYPE_COUNT; j++)
        server.stat_clients_type_memory[j] = 0;
    server.cron_malloc_stats.zmalloc_used = 0;
    server.cron_malloc_stats.process_rss = 0;
    server.cron_malloc_stats.allocator_allocated = 0;
    server.cron_malloc_stats.allocator_active = 0;
    server.cron_malloc_stats.allocator_resident = 0;
    server.lastbgsave_status = C_OK;
    server.aof_last_write_status = C_OK;
    server.aof_last_write_errno = 0;
    server.repl_good_slaves_count = 0;

    
    if (aeCreateTimeEvent(server.el, 1, serverCron, NULL, NULL) == AE_ERR) {
        serverPanic("Can't create event loop timers.");
        exit(1);
    }

    
    if (createSocketAcceptHandler(&server.ipfd, acceptTcpHandler) != C_OK) {
        serverPanic("Unrecoverable error creating TCP socket accept handler.");
    }
    if (createSocketAcceptHandler(&server.tlsfd, acceptTLSHandler) != C_OK) {
        serverPanic("Unrecoverable error creating TLS socket accept handler.");
    }
    if (server.sofd > 0 && aeCreateFileEvent(server.el,server.sofd,AE_READABLE, acceptUnixHandler,NULL) == AE_ERR) serverPanic("Unrecoverable error creating server.sofd file event.");


    
    if (aeCreateFileEvent(server.el, server.module_blocked_pipe[0], AE_READABLE, moduleBlockedClientPipeReadable,NULL) == AE_ERR) {
            serverPanic( "Error registering the readable event for the module " "blocked clients subsystem.");

    }

    
    aeSetBeforeSleepProc(server.el,beforeSleep);
    aeSetAfterSleepProc(server.el,afterSleep);

    
    if (server.arch_bits == 32 && server.maxmemory == 0) {
        serverLog(LL_WARNING,"Warning: 32 bit instance detected but no memory limit set. Setting 3 GB maxmemory limit with 'noeviction' policy now.");
        server.maxmemory = 3072LL*(1024*1024); 
        server.maxmemory_policy = MAXMEMORY_NO_EVICTION;
    }

    if (server.cluster_enabled) clusterInit();
    replicationScriptCacheInit();
    scriptingInit(1);
    slowlogInit();
    latencyMonitorInit();
    
    
    ACLUpdateDefaultUserPassword(server.requirepass);
}


void InitServerLast() {
    bioInit();
    initThreadedIO();
    set_jemalloc_bg_thread(server.jemalloc_bg_thread);
    server.initial_memory_usage = zmalloc_used_memory();
}


void populateCommandLegacyRangeSpec(struct redisCommand *c) {
    memset(&c->legacy_range_key_spec, 0, sizeof(c->legacy_range_key_spec));

    if (c->key_specs_num == 0)
        return;

    if (c->key_specs_num == 1 && c->key_specs[0].begin_search_type == KSPEC_BS_INDEX && c->key_specs[0].find_keys_type == KSPEC_FK_RANGE)

    {
        
        c->legacy_range_key_spec = c->key_specs[0];
        return;
    }

    int firstkey = INT_MAX, lastkey = 0;
    int prev_lastkey = 0;
    for (int i = 0; i < c->key_specs_num; i++) {
        if (c->key_specs[i].begin_search_type != KSPEC_BS_INDEX || c->key_specs[i].find_keys_type != KSPEC_FK_RANGE)
            continue;
        if (c->key_specs[i].fk.range.keystep != 1)
            return;
        if (prev_lastkey && prev_lastkey != c->key_specs[i].bs.index.pos-1)
            return;
        firstkey = min(firstkey, c->key_specs[i].bs.index.pos);
        
        int lastkey_abs_index = c->key_specs[i].fk.range.lastkey;
        if (lastkey_abs_index >= 0)
            lastkey_abs_index += c->key_specs[i].bs.index.pos;
        
        lastkey = max((unsigned)lastkey, (unsigned)lastkey_abs_index);
    }

    if (firstkey == INT_MAX)
        return;

    serverAssert(firstkey != 0);
    serverAssert(lastkey != 0);

    c->legacy_range_key_spec.begin_search_type = KSPEC_BS_INDEX;
    c->legacy_range_key_spec.bs.index.pos = firstkey;
    c->legacy_range_key_spec.find_keys_type = KSPEC_FK_RANGE;
    c->legacy_range_key_spec.fk.range.lastkey = lastkey < 0 ? lastkey : (lastkey-firstkey); 
    c->legacy_range_key_spec.fk.range.keystep = 1;
    c->legacy_range_key_spec.fk.range.limit = 0;
}


int populateSingleCommand(struct redisCommand *c, char *strflags) {
    int argc;
    sds *argv;

    
    argv = sdssplitargs(strflags,&argc);
    if (argv == NULL) return C_ERR;

    for (int j = 0; j < argc; j++) {
        char *flag = argv[j];
        if (!strcasecmp(flag,"write")) {
            c->flags |= CMD_WRITE|CMD_CATEGORY_WRITE;
        } else if (!strcasecmp(flag,"read-only")) {
            c->flags |= CMD_READONLY|CMD_CATEGORY_READ;
        } else if (!strcasecmp(flag,"use-memory")) {
            c->flags |= CMD_DENYOOM;
        } else if (!strcasecmp(flag,"admin")) {
            c->flags |= CMD_ADMIN|CMD_CATEGORY_ADMIN|CMD_CATEGORY_DANGEROUS;
        } else if (!strcasecmp(flag,"pub-sub")) {
            c->flags |= CMD_PUBSUB|CMD_CATEGORY_PUBSUB;
        } else if (!strcasecmp(flag,"no-script")) {
            c->flags |= CMD_NOSCRIPT;
        } else if (!strcasecmp(flag,"random")) {
            c->flags |= CMD_RANDOM;
        } else if (!strcasecmp(flag,"to-sort")) {
            c->flags |= CMD_SORT_FOR_SCRIPT;
        } else if (!strcasecmp(flag,"ok-loading")) {
            c->flags |= CMD_LOADING;
        } else if (!strcasecmp(flag,"ok-stale")) {
            c->flags |= CMD_STALE;
        } else if (!strcasecmp(flag,"no-monitor")) {
            c->flags |= CMD_SKIP_MONITOR;
        } else if (!strcasecmp(flag,"no-slowlog")) {
            c->flags |= CMD_SKIP_SLOWLOG;
        } else if (!strcasecmp(flag,"cluster-asking")) {
            c->flags |= CMD_ASKING;
        } else if (!strcasecmp(flag,"fast")) {
            c->flags |= CMD_FAST | CMD_CATEGORY_FAST;
        } else if (!strcasecmp(flag,"no-auth")) {
            c->flags |= CMD_NO_AUTH;
        } else if (!strcasecmp(flag,"may-replicate")) {
            c->flags |= CMD_MAY_REPLICATE;
        } else {
            
            uint64_t catflag;
            if (flag[0] == '@' && (catflag = ACLGetCommandCategoryFlagByName(flag+1)) != 0)
            {
                c->flags |= catflag;
            } else {
                sdsfreesplitres(argv,argc);
                return C_ERR;
            }
        }
    }
    
    if (!(c->flags & CMD_CATEGORY_FAST)) c->flags |= CMD_CATEGORY_SLOW;

    sdsfreesplitres(argv,argc);

    

    
    c->key_specs = c->key_specs_static;
    c->key_specs_max = STATIC_KEY_SPECS_NUM;

    for (int i = 0; i < STATIC_KEY_SPECS_NUM; i++) {
        if (c->key_specs[i].begin_search_type == KSPEC_BS_INVALID)
            continue;

        
        argv = sdssplitargs(c->key_specs[i].sflags,&argc);
        if (argv == NULL)
            return C_ERR;

        for (int j = 0; j < argc; j++) {
            char *flag = argv[j];
            if (!strcasecmp(flag,"write")) {
                c->key_specs[i].flags |= CMD_KEY_WRITE;
            } else if (!strcasecmp(flag,"read")) {
                c->key_specs[i].flags |= CMD_KEY_READ;
            } else if (!strcasecmp(flag,"incomplete")) {
                c->key_specs[i].flags |= CMD_KEY_INCOMPLETE;
            }
        }

        c->key_specs_num++;
        sdsfreesplitres(argv,argc);
    }

    populateCommandLegacyRangeSpec(c);

    
    populateCommandMovableKeys(c);

    return C_OK;
}


void populateCommandTable(void) {
    int j;
    int numcommands = sizeof(redisCommandTable)/sizeof(struct redisCommand);

    for (j = 0; j < numcommands; j++) {
        struct redisCommand *c = redisCommandTable+j;
        int retval1, retval2;

        
        if (populateSingleCommand(c,c->sflags) == C_ERR)
            serverPanic("Unsupported command flag or key spec flag");

        c->id = ACLGetCommandID(c->name); 
        retval1 = dictAdd(server.commands, sdsnew(c->name), c);
        
        retval2 = dictAdd(server.orig_commands, sdsnew(c->name), c);
        serverAssert(retval1 == DICT_OK && retval2 == DICT_OK);
    }
}

void resetCommandTableStats(void) {
    struct redisCommand *c;
    dictEntry *de;
    dictIterator *di;

    di = dictGetSafeIterator(server.commands);
    while((de = dictNext(di)) != NULL) {
        c = (struct redisCommand *) dictGetVal(de);
        c->microseconds = 0;
        c->calls = 0;
        c->rejected_calls = 0;
        c->failed_calls = 0;
    }
    dictReleaseIterator(di);

}

void resetErrorTableStats(void) {
    raxFreeWithCallback(server.errors, zfree);
    server.errors = raxNew();
}



void redisOpArrayInit(redisOpArray *oa) {
    oa->ops = NULL;
    oa->numops = 0;
}

int redisOpArrayAppend(redisOpArray *oa, int dbid, robj **argv, int argc, int target) {
    redisOp *op;

    oa->ops = zrealloc(oa->ops,sizeof(redisOp)*(oa->numops+1));
    op = oa->ops+oa->numops;
    op->dbid = dbid;
    op->argv = argv;
    op->argc = argc;
    op->target = target;
    oa->numops++;
    return oa->numops;
}

void redisOpArrayFree(redisOpArray *oa) {
    while(oa->numops) {
        int j;
        redisOp *op;

        oa->numops--;
        op = oa->ops+oa->numops;
        for (j = 0; j < op->argc; j++)
            decrRefCount(op->argv[j]);
        zfree(op->argv);
    }
    zfree(oa->ops);
    oa->ops = NULL;
}



struct redisCommand *lookupCommand(sds name) {
    return dictFetchValue(server.commands, name);
}

struct redisCommand *lookupCommandByCString(const char *s) {
    struct redisCommand *cmd;
    sds name = sdsnew(s);

    cmd = dictFetchValue(server.commands, name);
    sdsfree(name);
    return cmd;
}


struct redisCommand *lookupCommandOrOriginal(sds name) {
    struct redisCommand *cmd = dictFetchValue(server.commands, name);

    if (!cmd) cmd = dictFetchValue(server.orig_commands,name);
    return cmd;
}


void propagate(int dbid, robj **argv, int argc, int flags) {
    if (!server.replication_allowed)
        return;

    
    if (server.in_exec && !server.propagate_in_transaction)
        execCommandPropagateMulti(dbid);

    
    serverAssert(!(areClientsPaused() && !server.client_pause_in_transaction));

    if (server.aof_state != AOF_OFF && flags & PROPAGATE_AOF)
        feedAppendOnlyFile(dbid,argv,argc);
    if (flags & PROPAGATE_REPL)
        replicationFeedSlaves(server.slaves,dbid,argv,argc);
}


void alsoPropagate(int dbid, robj **argv, int argc, int target) {
    robj **argvcopy;
    int j;

    if (server.loading) return; 

    argvcopy = zmalloc(sizeof(robj*)*argc);
    for (j = 0; j < argc; j++) {
        argvcopy[j] = argv[j];
        incrRefCount(argv[j]);
    }
    redisOpArrayAppend(&server.also_propagate,dbid,argvcopy,argc,target);
}


void forceCommandPropagation(client *c, int flags) {
    serverAssert(c->cmd->flags & (CMD_WRITE | CMD_MAY_REPLICATE));
    if (flags & PROPAGATE_REPL) c->flags |= CLIENT_FORCE_REPL;
    if (flags & PROPAGATE_AOF) c->flags |= CLIENT_FORCE_AOF;
}


void preventCommandPropagation(client *c) {
    c->flags |= CLIENT_PREVENT_PROP;
}


void preventCommandAOF(client *c) {
    c->flags |= CLIENT_PREVENT_AOF_PROP;
}


void preventCommandReplication(client *c) {
    c->flags |= CLIENT_PREVENT_REPL_PROP;
}


void slowlogPushCurrentCommand(client *c, struct redisCommand *cmd, ustime_t duration) {
    
    if (cmd->flags & CMD_SKIP_SLOWLOG)
        return;

    
    robj **argv = c->original_argv ? c->original_argv : c->argv;
    int argc = c->original_argv ? c->original_argc : c->argc;
    slowlogPushEntryIfNeeded(c,argv,argc,duration);
}


void call(client *c, int flags) {
    long long dirty;
    monotime call_timer;
    int client_old_flags = c->flags;
    struct redisCommand *real_cmd = c->cmd;
    static long long prev_err_count;

    
    c->flags &= ~(CLIENT_FORCE_AOF|CLIENT_FORCE_REPL|CLIENT_PREVENT_PROP);
    redisOpArray prev_also_propagate = server.also_propagate;
    redisOpArrayInit(&server.also_propagate);

    
    dirty = server.dirty;
    prev_err_count = server.stat_total_error_replies;

    
    if (server.fixed_time_expire++ == 0) {
        updateCachedTime(0);
    }

    elapsedStart(&call_timer);
    c->cmd->proc(c);
    const long duration = elapsedUs(call_timer);
    c->duration = duration;
    dirty = server.dirty-dirty;
    if (dirty < 0) dirty = 0;

    
    if ((server.stat_total_error_replies - prev_err_count) > 0) {
        real_cmd->failed_calls++;
    }

    
    if (c->flags & CLIENT_CLOSE_AFTER_COMMAND) {
        c->flags &= ~CLIENT_CLOSE_AFTER_COMMAND;
        c->flags |= CLIENT_CLOSE_AFTER_REPLY;
    }

    
    if (server.loading && c->flags & CLIENT_LUA)
        flags &= ~(CMD_CALL_SLOWLOG | CMD_CALL_STATS);

    
    if (c->flags & CLIENT_LUA && server.lua_caller) {
        if (c->flags & CLIENT_FORCE_REPL)
            server.lua_caller->flags |= CLIENT_FORCE_REPL;
        if (c->flags & CLIENT_FORCE_AOF)
            server.lua_caller->flags |= CLIENT_FORCE_AOF;
    }

    

    
    if (flags & CMD_CALL_SLOWLOG) {
        char *latency_event = (real_cmd->flags & CMD_FAST) ? "fast-command" : "command";
        latencyAddSampleIfNeeded(latency_event,duration/1000);
    }

    
    if ((flags & CMD_CALL_SLOWLOG) && !(c->flags & CLIENT_BLOCKED))
        slowlogPushCurrentCommand(c, real_cmd, duration);

    
    if (!(c->cmd->flags & (CMD_SKIP_MONITOR|CMD_ADMIN))) {
        robj **argv = c->original_argv ? c->original_argv : c->argv;
        int argc = c->original_argv ? c->original_argc : c->argc;
        replicationFeedMonitors(c,server.monitors,c->db->id,argv,argc);
    }

    
    if (!(c->flags & CLIENT_BLOCKED))
        freeClientOriginalArgv(c);

    
    if (flags & CMD_CALL_STATS) {
        real_cmd->microseconds += duration;
        real_cmd->calls++;
    }

    
    if (flags & CMD_CALL_PROPAGATE && (c->flags & CLIENT_PREVENT_PROP) != CLIENT_PREVENT_PROP)
    {
        int propagate_flags = PROPAGATE_NONE;

        
        if (dirty) propagate_flags |= (PROPAGATE_AOF|PROPAGATE_REPL);

        
        if (c->flags & CLIENT_FORCE_REPL) propagate_flags |= PROPAGATE_REPL;
        if (c->flags & CLIENT_FORCE_AOF) propagate_flags |= PROPAGATE_AOF;

        
        if (c->flags & CLIENT_PREVENT_REPL_PROP || !(flags & CMD_CALL_PROPAGATE_REPL))
                propagate_flags &= ~PROPAGATE_REPL;
        if (c->flags & CLIENT_PREVENT_AOF_PROP || !(flags & CMD_CALL_PROPAGATE_AOF))
                propagate_flags &= ~PROPAGATE_AOF;

        
        if (propagate_flags != PROPAGATE_NONE && !(c->cmd->flags & CMD_MODULE))
            propagate(c->db->id,c->argv,c->argc,propagate_flags);
    }

    
    c->flags &= ~(CLIENT_FORCE_AOF|CLIENT_FORCE_REPL|CLIENT_PREVENT_PROP);
    c->flags |= client_old_flags & (CLIENT_FORCE_AOF|CLIENT_FORCE_REPL|CLIENT_PREVENT_PROP);

    
    if (server.also_propagate.numops) {
        int j;
        redisOp *rop;

        if (flags & CMD_CALL_PROPAGATE) {
            int multi_emitted = 0;
            
            if (server.also_propagate.numops > 1 && !(c->cmd->flags & CMD_MODULE) && !(c->flags & CLIENT_MULTI) && !(flags & CMD_CALL_NOWRAP))


            {
                execCommandPropagateMulti(c->db->id);
                multi_emitted = 1;
            }

            for (j = 0; j < server.also_propagate.numops; j++) {
                rop = &server.also_propagate.ops[j];
                int target = rop->target;
                
                if (!(flags&CMD_CALL_PROPAGATE_AOF)) target &= ~PROPAGATE_AOF;
                if (!(flags&CMD_CALL_PROPAGATE_REPL)) target &= ~PROPAGATE_REPL;
                if (target)
                    propagate(rop->dbid,rop->argv,rop->argc,target);
            }

            if (multi_emitted) {
                execCommandPropagateExec(c->db->id);
            }
        }
        redisOpArrayFree(&server.also_propagate);
    }
    server.also_propagate = prev_also_propagate;

    
    if (!server.in_exec && server.client_pause_in_transaction) {
        server.client_pause_in_transaction = 0;
    }

    
    if (c->cmd->flags & CMD_READONLY) {
        client *caller = (c->flags & CLIENT_LUA && server.lua_caller) ? server.lua_caller : c;
        if (caller->flags & CLIENT_TRACKING && !(caller->flags & CLIENT_TRACKING_BCAST))
        {
            trackingRememberKeys(caller);
        }
    }

    server.fixed_time_expire--;
    server.stat_numcommands++;
    prev_err_count = server.stat_total_error_replies;

    
    size_t zmalloc_used = zmalloc_used_memory();
    if (zmalloc_used > server.stat_peak_memory)
        server.stat_peak_memory = zmalloc_used;
}


void rejectCommand(client *c, robj *reply) {
    flagTransaction(c);
    if (c->cmd) c->cmd->rejected_calls++;
    if (c->cmd && c->cmd->proc == execCommand) {
        execCommandAbort(c, reply->ptr);
    } else {
        
        addReplyErrorObject(c, reply);
    }
}

void rejectCommandFormat(client *c, const char *fmt, ...) {
    if (c->cmd) c->cmd->rejected_calls++;
    flagTransaction(c);
    va_list ap;
    va_start(ap,fmt);
    sds s = sdscatvprintf(sdsempty(),fmt,ap);
    va_end(ap);
    
    sdsmapchars(s, "\r\n", "  ",  2);
    if (c->cmd && c->cmd->proc == execCommand) {
        execCommandAbort(c, s);
        sdsfree(s);
    } else {
        
        addReplyErrorSds(c, s);
    }
}


void populateCommandMovableKeys(struct redisCommand *cmd) {
    int movablekeys = 0;
    if (cmd->getkeys_proc && !(cmd->flags & CMD_MODULE)) {
        
        movablekeys = 1;
    } else if (cmd->flags & CMD_MODULE_GETKEYS) {
        
        movablekeys = 1;
    } else {
        
        for (int i = 0; i < cmd->key_specs_num; i++) {
            if (cmd->key_specs[i].begin_search_type != KSPEC_BS_INDEX || cmd->key_specs[i].find_keys_type != KSPEC_FK_RANGE)
            {
                
                movablekeys = 1;
                break;
            }
        }
    }

    cmd->movablekeys = movablekeys;
}


int processCommand(client *c) {
    if (!server.lua_timedout) {
        
        serverAssert(!server.propagate_in_transaction);
        serverAssert(!server.in_exec);
        serverAssert(!server.in_eval);
    }

    moduleCallCommandFilters(c);

    
    if (!strcasecmp(c->argv[0]->ptr,"quit")) {
        addReply(c,shared.ok);
        c->flags |= CLIENT_CLOSE_AFTER_REPLY;
        return C_ERR;
    }

    
    c->cmd = c->lastcmd = lookupCommand(c->argv[0]->ptr);
    if (!c->cmd) {
        sds args = sdsempty();
        int i;
        for (i=1; i < c->argc && sdslen(args) < 128; i++)
            args = sdscatprintf(args, "`%.*s`, ", 128-(int)sdslen(args), (char*)c->argv[i]->ptr);
        rejectCommandFormat(c,"unknown command `%s`, with args beginning with: %s", (char*)c->argv[0]->ptr, args);
        sdsfree(args);
        return C_OK;
    } else if ((c->cmd->arity > 0 && c->cmd->arity != c->argc) || (c->argc < -c->cmd->arity)) {
        rejectCommandFormat(c,"wrong number of arguments for '%s' command", c->cmd->name);
        return C_OK;
    }

    int is_read_command = (c->cmd->flags & CMD_READONLY) || (c->cmd->proc == execCommand && (c->mstate.cmd_flags & CMD_READONLY));
    int is_write_command = (c->cmd->flags & CMD_WRITE) || (c->cmd->proc == execCommand && (c->mstate.cmd_flags & CMD_WRITE));
    int is_denyoom_command = (c->cmd->flags & CMD_DENYOOM) || (c->cmd->proc == execCommand && (c->mstate.cmd_flags & CMD_DENYOOM));
    int is_denystale_command = !(c->cmd->flags & CMD_STALE) || (c->cmd->proc == execCommand && (c->mstate.cmd_inv_flags & CMD_STALE));
    int is_denyloading_command = !(c->cmd->flags & CMD_LOADING) || (c->cmd->proc == execCommand && (c->mstate.cmd_inv_flags & CMD_LOADING));
    int is_may_replicate_command = (c->cmd->flags & (CMD_WRITE | CMD_MAY_REPLICATE)) || (c->cmd->proc == execCommand && (c->mstate.cmd_flags & (CMD_WRITE | CMD_MAY_REPLICATE)));

    
    int auth_required = (!(DefaultUser->flags & USER_FLAG_NOPASS) || (DefaultUser->flags & USER_FLAG_DISABLED)) && !c->authenticated;

    if (auth_required) {
        
        if (!(c->cmd->flags & CMD_NO_AUTH)) {
            rejectCommand(c,shared.noautherr);
            return C_OK;
        }
    }

    
    int acl_errpos;
    int acl_retval = ACLCheckAllPerm(c,&acl_errpos);
    if (acl_retval != ACL_OK) {
        addACLLogEntry(c,acl_retval,(c->flags & CLIENT_MULTI) ? ACL_LOG_CTX_MULTI : ACL_LOG_CTX_TOPLEVEL,acl_errpos,NULL,NULL);
        switch (acl_retval) {
        case ACL_DENIED_CMD:
            rejectCommandFormat(c, "-NOPERM this user has no permissions to run " "the '%s' command or its subcommand", c->cmd->name);

            break;
        case ACL_DENIED_KEY:
            rejectCommandFormat(c, "-NOPERM this user has no permissions to access " "one of the keys used as arguments");

            break;
        case ACL_DENIED_CHANNEL:
            rejectCommandFormat(c, "-NOPERM this user has no permissions to access " "one of the channels used as arguments");

            break;
        default:
            rejectCommandFormat(c, "no permission");
            break;
        }
        return C_OK;
    }

    
    if (server.cluster_enabled && !(c->flags & CLIENT_MASTER) && !(c->flags & CLIENT_LUA && server.lua_caller->flags & CLIENT_MASTER) && !(!c->cmd->movablekeys && c->cmd->key_specs_num == 0 && c->cmd->proc != execCommand))




    {
        int hashslot;
        int error_code;
        clusterNode *n = getNodeByQuery(c,c->cmd,c->argv,c->argc, &hashslot,&error_code);
        if (n == NULL || n != server.cluster->myself) {
            if (c->cmd->proc == execCommand) {
                discardTransaction(c);
            } else {
                flagTransaction(c);
            }
            clusterRedirectClient(c,n,hashslot,error_code);
            c->cmd->rejected_calls++;
            return C_OK;
        }
    }

    
    evictClients();
    if (server.current_client == NULL) {
        
        return C_ERR;
    }

    
    if (server.maxmemory && !server.lua_timedout) {
        int out_of_memory = (performEvictions() == EVICT_FAIL);
        
        if (server.current_client == NULL) return C_ERR;

        int reject_cmd_on_oom = is_denyoom_command;
        
        if (c->flags & CLIENT_MULTI && c->cmd->proc != execCommand && c->cmd->proc != discardCommand && c->cmd->proc != resetCommand) {


            reject_cmd_on_oom = 1;
        }

        if (out_of_memory && reject_cmd_on_oom) {
            rejectCommand(c, shared.oomerr);
            return C_OK;
        }

        
        if (c->cmd->proc == evalCommand || c->cmd->proc == evalShaCommand) {
            server.lua_oom = out_of_memory;
        }
    }

    
    if (server.tracking_clients) trackingLimitUsedSlots();

    
    int deny_write_type = writeCommandsDeniedByDiskError();
    if (deny_write_type != DISK_ERROR_TYPE_NONE && server.masterhost == NULL && (is_write_command ||c->cmd->proc == pingCommand))

    {
        if (deny_write_type == DISK_ERROR_TYPE_RDB)
            rejectCommand(c, shared.bgsaveerr);
        else rejectCommandFormat(c, "-MISCONF Errors writing to the AOF file: %s", strerror(server.aof_last_write_errno));


        return C_OK;
    }

    
    if (server.masterhost == NULL && server.repl_min_slaves_to_write && server.repl_min_slaves_max_lag && is_write_command && server.repl_good_slaves_count < server.repl_min_slaves_to_write)



    {
        rejectCommand(c, shared.noreplicaserr);
        return C_OK;
    }

    
    if (server.masterhost && server.repl_slave_ro && !(c->flags & CLIENT_MASTER) && is_write_command)

    {
        rejectCommand(c, shared.roslaveerr);
        return C_OK;
    }

    
    if ((c->flags & CLIENT_PUBSUB && c->resp == 2) && c->cmd->proc != pingCommand && c->cmd->proc != subscribeCommand && c->cmd->proc != unsubscribeCommand && c->cmd->proc != psubscribeCommand && c->cmd->proc != punsubscribeCommand && c->cmd->proc != resetCommand) {





        rejectCommandFormat(c, "Can't execute '%s': only (P)SUBSCRIBE / " "(P)UNSUBSCRIBE / PING / QUIT / RESET are allowed in this context", c->cmd->name);


        return C_OK;
    }

    
    if (server.masterhost && server.repl_state != REPL_STATE_CONNECTED && server.repl_serve_stale_data == 0 && is_denystale_command)

    {
        rejectCommand(c, shared.masterdownerr);
        return C_OK;
    }

    
    if (server.loading && is_denyloading_command) {
        rejectCommand(c, shared.loadingerr);
        return C_OK;
    }

    
    if (server.lua_timedout && c->cmd->proc != authCommand && c->cmd->proc != helloCommand && c->cmd->proc != replconfCommand && c->cmd->proc != multiCommand && c->cmd->proc != discardCommand && c->cmd->proc != watchCommand && c->cmd->proc != unwatchCommand && c->cmd->proc != resetCommand && !(c->cmd->proc == shutdownCommand && c->argc == 2 && tolower(((char*)c->argv[1]->ptr)[0]) == 'n') && !(c->cmd->proc == scriptCommand && c->argc == 2 && tolower(((char*)c->argv[1]->ptr)[0]) == 'k'))













    {
        rejectCommand(c, shared.slowscripterr);
        return C_OK;
    }

    
    if ((c->flags & CLIENT_SLAVE) && (is_may_replicate_command || is_write_command || is_read_command)) {
        rejectCommandFormat(c, "Replica can't interact with the keyspace");
        return C_OK;
    }

    
    if (!(c->flags & CLIENT_SLAVE) &&  ((server.client_pause_type == CLIENT_PAUSE_ALL) || (server.client_pause_type == CLIENT_PAUSE_WRITE && is_may_replicate_command)))

    {
        c->bpop.timeout = 0;
        blockClient(c,BLOCKED_PAUSE);
        return C_OK;       
    }

    
    if (c->flags & CLIENT_MULTI && c->cmd->proc != execCommand && c->cmd->proc != discardCommand && c->cmd->proc != multiCommand && c->cmd->proc != watchCommand && c->cmd->proc != resetCommand)


    {
        queueMultiCommand(c);
        addReply(c,shared.queued);
    } else {
        call(c,CMD_CALL_FULL);
        c->woff = server.master_repl_offset;
        if (listLength(server.ready_keys))
            handleClientsBlockedOnKeys();
    }

    return C_OK;
}



void incrementErrorCount(const char *fullerr, size_t namelen) {
    struct redisError *error = raxFind(server.errors,(unsigned char*)fullerr,namelen);
    if (error == raxNotFound) {
        error = zmalloc(sizeof(*error));
        error->count = 0;
        raxInsert(server.errors,(unsigned char*)fullerr,namelen,error,NULL);
    }
    error->count++;
}




void closeListeningSockets(int unlink_unix_socket) {
    int j;

    for (j = 0; j < server.ipfd.count; j++) close(server.ipfd.fd[j]);
    for (j = 0; j < server.tlsfd.count; j++) close(server.tlsfd.fd[j]);
    if (server.sofd != -1) close(server.sofd);
    if (server.cluster_enabled)
        for (j = 0; j < server.cfd.count; j++) close(server.cfd.fd[j]);
    if (unlink_unix_socket && server.unixsocket) {
        serverLog(LL_NOTICE,"Removing the unix socket file.");
        unlink(server.unixsocket); 
    }
}

int prepareForShutdown(int flags) {
    
    if (server.loading || server.sentinel_mode)
        flags = (flags & ~SHUTDOWN_SAVE) | SHUTDOWN_NOSAVE;

    int save = flags & SHUTDOWN_SAVE;
    int nosave = flags & SHUTDOWN_NOSAVE;

    serverLog(LL_WARNING,"User requested shutdown...");
    if (server.supervised_mode == SUPERVISED_SYSTEMD)
        redisCommunicateSystemd("STOPPING=1\n");

    
    ldbKillForkedSessions();

    
    if (server.child_type == CHILD_TYPE_RDB) {
        serverLog(LL_WARNING,"There is a child saving an .rdb. Killing it!");
        killRDBChild();
        
        rdbRemoveTempFile(server.child_pid, 0);
    }

    
    if (server.child_type == CHILD_TYPE_MODULE) {
        serverLog(LL_WARNING,"There is a module fork child. Killing it!");
        TerminateModuleForkChild(server.child_pid,0);
    }

    if (server.aof_state != AOF_OFF) {
        
        if (server.child_type == CHILD_TYPE_AOF) {
            
            if (server.aof_state == AOF_WAIT_REWRITE) {
                serverLog(LL_WARNING, "Writing initial AOF, can't exit.");
                return C_ERR;
            }
            serverLog(LL_WARNING, "There is a child rewriting the AOF. Killing it!");
            killAppendOnlyChild();
        }
        
        serverLog(LL_NOTICE,"Calling fsync() on the AOF file.");
        flushAppendOnlyFile(1);
        if (redis_fsync(server.aof_fd) == -1) {
            serverLog(LL_WARNING,"Fail to fsync the AOF file: %s.", strerror(errno));
        }
    }

    
    if ((server.saveparamslen > 0 && !nosave) || save) {
        serverLog(LL_NOTICE,"Saving the final RDB snapshot before exiting.");
        if (server.supervised_mode == SUPERVISED_SYSTEMD)
            redisCommunicateSystemd("STATUS=Saving the final RDB snapshot\n");
        
        rdbSaveInfo rsi, *rsiptr;
        rsiptr = rdbPopulateSaveInfo(&rsi);
        if (rdbSave(server.rdb_filename,rsiptr) != C_OK) {
            
            serverLog(LL_WARNING,"Error trying to save the DB, can't exit.");
            if (server.supervised_mode == SUPERVISED_SYSTEMD)
                redisCommunicateSystemd("STATUS=Error trying to save the DB, can't exit.\n");
            return C_ERR;
        }
    }

    
    moduleFireServerEvent(REDISMODULE_EVENT_SHUTDOWN,0,NULL);

    
    if (server.daemonize || server.pidfile) {
        serverLog(LL_NOTICE,"Removing the pid file.");
        unlink(server.pidfile);
    }

    
    flushSlavesOutputBuffers();

    
    closeListeningSockets(1);
    serverLog(LL_WARNING,"%s is now ready to exit, bye bye...", server.sentinel_mode ? "Sentinel" : "Redis");
    return C_OK;
}




int writeCommandsDeniedByDiskError(void) {
    if (server.stop_writes_on_bgsave_err && server.saveparamslen > 0 && server.lastbgsave_status == C_ERR)

    {
        return DISK_ERROR_TYPE_RDB;
    } else if (server.aof_state != AOF_OFF) {
        if (server.aof_last_write_status == C_ERR) {
            return DISK_ERROR_TYPE_AOF;
        }
        
        int aof_bio_fsync_status;
        atomicGet(server.aof_bio_fsync_status,aof_bio_fsync_status);
        if (aof_bio_fsync_status == C_ERR) {
            atomicGet(server.aof_bio_fsync_errno,server.aof_last_write_errno);
            return DISK_ERROR_TYPE_AOF;
        }
    }

    return DISK_ERROR_TYPE_NONE;
}


void pingCommand(client *c) {
    
    if (c->argc > 2) {
        addReplyErrorFormat(c,"wrong number of arguments for '%s' command", c->cmd->name);
        return;
    }

    if (c->flags & CLIENT_PUBSUB && c->resp == 2) {
        addReply(c,shared.mbulkhdr[2]);
        addReplyBulkCBuffer(c,"pong",4);
        if (c->argc == 1)
            addReplyBulkCBuffer(c,"",0);
        else addReplyBulk(c,c->argv[1]);
    } else {
        if (c->argc == 1)
            addReply(c,shared.pong);
        else addReplyBulk(c,c->argv[1]);
    }
}

void echoCommand(client *c) {
    addReplyBulk(c,c->argv[1]);
}

void timeCommand(client *c) {
    struct timeval tv;

    
    gettimeofday(&tv,NULL);
    addReplyArrayLen(c,2);
    addReplyBulkLongLong(c,tv.tv_sec);
    addReplyBulkLongLong(c,tv.tv_usec);
}


int addReplyCommandFlag(client *c, uint64_t flags, uint64_t f, char *reply) {
    if (flags & f) {
        addReplyStatus(c, reply);
        return 1;
    }
    return 0;
}

void addReplyFlagsForCommand(client *c, struct redisCommand *cmd) {
    int flagcount = 0;
    void *flaglen = addReplyDeferredLen(c);
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_WRITE, "write");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_READONLY, "readonly");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_DENYOOM, "denyoom");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_ADMIN, "admin");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_PUBSUB, "pubsub");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_NOSCRIPT, "noscript");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_RANDOM, "random");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_SORT_FOR_SCRIPT,"sort_for_script");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_LOADING, "loading");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_STALE, "stale");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_SKIP_MONITOR, "skip_monitor");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_SKIP_SLOWLOG, "skip_slowlog");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_ASKING, "asking");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_FAST, "fast");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_NO_AUTH, "no_auth");
    flagcount += addReplyCommandFlag(c,cmd->flags,CMD_MAY_REPLICATE, "may_replicate");
    if (cmd->movablekeys) {
        addReplyStatus(c, "movablekeys");
        flagcount += 1;
    }
    setDeferredSetLen(c, flaglen, flagcount);
}

void addReplyFlagsForKeyArgs(client *c, uint64_t flags) {
    int flagcount = 0;
    void *flaglen = addReplyDeferredLen(c);
    flagcount += addReplyCommandFlag(c,flags,CMD_KEY_WRITE, "write");
    flagcount += addReplyCommandFlag(c,flags,CMD_KEY_READ, "read");
    flagcount += addReplyCommandFlag(c,flags,CMD_KEY_INCOMPLETE, "incomplete");
    setDeferredSetLen(c, flaglen, flagcount);
}

void addReplyCommandKeyArgs(client *c, struct redisCommand *cmd) {
    addReplySetLen(c, cmd->key_specs_num);
    for (int i = 0; i < cmd->key_specs_num; i++) {
        addReplyMapLen(c, 3);

        addReplyBulkCString(c, "flags");
        addReplyFlagsForKeyArgs(c,cmd->key_specs[i].flags);

        addReplyBulkCString(c, "begin_search");
        switch (cmd->key_specs[i].begin_search_type) {
            case KSPEC_BS_UNKNOWN:
                addReplyMapLen(c, 2);
                addReplyBulkCString(c, "type");
                addReplyBulkCString(c, "unknown");

                addReplyBulkCString(c, "spec");
                addReplyMapLen(c, 0);
                break;
            case KSPEC_BS_INDEX:
                addReplyMapLen(c, 2);
                addReplyBulkCString(c, "type");
                addReplyBulkCString(c, "index");

                addReplyBulkCString(c, "spec");
                addReplyMapLen(c, 1);
                addReplyBulkCString(c, "index");
                addReplyLongLong(c, cmd->key_specs[i].bs.index.pos);
                break;
            case KSPEC_BS_KEYWORD:
                addReplyMapLen(c, 2);
                addReplyBulkCString(c, "type");
                addReplyBulkCString(c, "keyword");

                addReplyBulkCString(c, "spec");
                addReplyMapLen(c, 2);
                addReplyBulkCString(c, "keyword");
                addReplyBulkCString(c, cmd->key_specs[i].bs.keyword.keyword);
                addReplyBulkCString(c, "startfrom");
                addReplyLongLong(c, cmd->key_specs[i].bs.keyword.startfrom);
                break;
            default:
                serverPanic("Invalid begin_search key spec type %d", cmd->key_specs[i].begin_search_type);
        }

        addReplyBulkCString(c, "find_keys");
        switch (cmd->key_specs[i].find_keys_type) {
            case KSPEC_FK_UNKNOWN:
                addReplyMapLen(c, 2);
                addReplyBulkCString(c, "type");
                addReplyBulkCString(c, "unknown");

                addReplyBulkCString(c, "spec");
                addReplyMapLen(c, 0);
                break;
            case KSPEC_FK_RANGE:
                addReplyMapLen(c, 2);
                addReplyBulkCString(c, "type");
                addReplyBulkCString(c, "range");

                addReplyBulkCString(c, "spec");
                addReplyMapLen(c, 3);
                addReplyBulkCString(c, "lastkey");
                addReplyLongLong(c, cmd->key_specs[i].fk.range.lastkey);
                addReplyBulkCString(c, "keystep");
                addReplyLongLong(c, cmd->key_specs[i].fk.range.keystep);
                addReplyBulkCString(c, "limit");
                addReplyLongLong(c, cmd->key_specs[i].fk.range.limit);
                break;
            case KSPEC_FK_KEYNUM:
                addReplyMapLen(c, 2);
                addReplyBulkCString(c, "type");
                addReplyBulkCString(c, "keynum");

                addReplyBulkCString(c, "spec");
                addReplyMapLen(c, 3);
                addReplyBulkCString(c, "keynumidx");
                addReplyLongLong(c, cmd->key_specs[i].fk.keynum.keynumidx);
                addReplyBulkCString(c, "firstkey");
                addReplyLongLong(c, cmd->key_specs[i].fk.keynum.firstkey);
                addReplyBulkCString(c, "keystep");
                addReplyLongLong(c, cmd->key_specs[i].fk.keynum.keystep);
                break;
            default:
                serverPanic("Invalid begin_search key spec type %d", cmd->key_specs[i].begin_search_type);
        }
    }
}


void addReplyCommand(client *c, struct redisCommand *cmd) {
    if (!cmd) {
        addReplyNull(c);
    } else {
        int firstkey = 0, lastkey = 0, keystep = 0;
        if (cmd->legacy_range_key_spec.begin_search_type != KSPEC_BS_INVALID) {
            firstkey = cmd->legacy_range_key_spec.bs.index.pos;
            lastkey = cmd->legacy_range_key_spec.fk.range.lastkey;
            if (lastkey >= 0)
                lastkey += firstkey;
            keystep = cmd->legacy_range_key_spec.fk.range.keystep;
        }
        
        addReplyArrayLen(c, 8);
        addReplyBulkCString(c, cmd->name);
        addReplyLongLong(c, cmd->arity);
        addReplyFlagsForCommand(c, cmd);
        addReplyLongLong(c, firstkey);
        addReplyLongLong(c, lastkey);
        addReplyLongLong(c, keystep);
        addReplyCommandCategories(c,cmd);
        addReplyCommandKeyArgs(c,cmd);
    }
}


void commandCommand(client *c) {
    dictIterator *di;
    dictEntry *de;

    if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"help")) {
        const char *help[] = {
"(no subcommand)", "    Return details about all Redis commands.", "COUNT", "    Return the total number of commands in this Redis server.", "GETKEYS <full-command>", "    Return the keys from a full Redis command.", "INFO [<command-name> ...]", "    Return details about multiple Redis commands.", NULL };








        addReplyHelp(c, help);
    } else if (c->argc == 1) {
        addReplyArrayLen(c, dictSize(server.commands));
        di = dictGetIterator(server.commands);
        while ((de = dictNext(di)) != NULL) {
            addReplyCommand(c, dictGetVal(de));
        }
        dictReleaseIterator(di);
    } else if (!strcasecmp(c->argv[1]->ptr, "info")) {
        int i;
        addReplyArrayLen(c, c->argc-2);
        for (i = 2; i < c->argc; i++) {
            addReplyCommand(c, dictFetchValue(server.commands, c->argv[i]->ptr));
        }
    } else if (!strcasecmp(c->argv[1]->ptr, "count") && c->argc == 2) {
        addReplyLongLong(c, dictSize(server.commands));
    } else if (!strcasecmp(c->argv[1]->ptr,"getkeys") && c->argc >= 3) {
        struct redisCommand *cmd = lookupCommand(c->argv[2]->ptr);
        getKeysResult result = GETKEYS_RESULT_INIT;
        int j;

        if (!cmd) {
            addReplyError(c,"Invalid command specified");
            return;
        } else if (cmd->getkeys_proc == NULL && cmd->key_specs_num == 0) {
            addReplyError(c,"The command has no key arguments");
            return;
        } else if ((cmd->arity > 0 && cmd->arity != c->argc-2) || ((c->argc-2) < -cmd->arity))
        {
            addReplyError(c,"Invalid number of arguments specified for command");
            return;
        }

        if (!getKeysFromCommand(cmd,c->argv+2,c->argc-2,&result)) {
            addReplyError(c,"Invalid arguments specified for command");
        } else {
            addReplyArrayLen(c,result.numkeys);
            for (j = 0; j < result.numkeys; j++) addReplyBulk(c,c->argv[result.keys[j]+2]);
        }
        getKeysFreeResult(&result);
    } else {
        addReplySubcommandSyntaxError(c);
    }
}


void bytesToHuman(char *s, unsigned long long n) {
    double d;

    if (n < 1024) {
        
        sprintf(s,"%lluB",n);
    } else if (n < (1024*1024)) {
        d = (double)n/(1024);
        sprintf(s,"%.2fK",d);
    } else if (n < (1024LL*1024*1024)) {
        d = (double)n/(1024*1024);
        sprintf(s,"%.2fM",d);
    } else if (n < (1024LL*1024*1024*1024)) {
        d = (double)n/(1024LL*1024*1024);
        sprintf(s,"%.2fG",d);
    } else if (n < (1024LL*1024*1024*1024*1024)) {
        d = (double)n/(1024LL*1024*1024*1024);
        sprintf(s,"%.2fT",d);
    } else if (n < (1024LL*1024*1024*1024*1024*1024)) {
        d = (double)n/(1024LL*1024*1024*1024*1024);
        sprintf(s,"%.2fP",d);
    } else {
        
        sprintf(s,"%lluB",n);
    }
}


static char unsafe_info_chars[] = "#:\n\r";
static char unsafe_info_chars_substs[] = "____";   


const char *getSafeInfoString(const char *s, size_t len, char **tmp) {
    *tmp = NULL;
    if (mempbrk(s, len, unsafe_info_chars,sizeof(unsafe_info_chars)-1)
        == NULL) return s;
    char *new = *tmp = zmalloc(len + 1);
    memcpy(new, s, len);
    new[len] = '\0';
    return memmapchars(new, len, unsafe_info_chars, unsafe_info_chars_substs, sizeof(unsafe_info_chars)-1);
}


sds genRedisInfoString(const char *section) {
    sds info = sdsempty();
    time_t uptime = server.unixtime-server.stat_starttime;
    int j;
    int allsections = 0, defsections = 0, everything = 0, modules = 0;
    int sections = 0;

    if (section == NULL) section = "default";
    allsections = strcasecmp(section,"all") == 0;
    defsections = strcasecmp(section,"default") == 0;
    everything = strcasecmp(section,"everything") == 0;
    modules = strcasecmp(section,"modules") == 0;
    if (everything) allsections = 1;

    
    if (allsections || defsections || !strcasecmp(section,"server")) {
        static int call_uname = 1;
        static struct utsname name;
        char *mode;
        char *supervised;

        if (server.cluster_enabled) mode = "cluster";
        else if (server.sentinel_mode) mode = "sentinel";
        else mode = "standalone";

        if (server.supervised) {
            if (server.supervised_mode == SUPERVISED_UPSTART) supervised = "upstart";
            else if (server.supervised_mode == SUPERVISED_SYSTEMD) supervised = "systemd";
            else supervised = "unknown";
        } else {
            supervised = "no";
        }

        if (sections++) info = sdscat(info,"\r\n");

        if (call_uname) {
            
            uname(&name);
            call_uname = 0;
        }

        unsigned int lruclock;
        atomicGet(server.lruclock,lruclock);
        info = sdscatfmt(info, "# Server\r\n" "redis_version:%s\r\n" "redis_git_sha1:%s\r\n" "redis_git_dirty:%i\r\n" "redis_build_id:%s\r\n" "redis_mode:%s\r\n" "os:%s %s %s\r\n" "arch_bits:%i\r\n" "multiplexing_api:%s\r\n" "atomicvar_api:%s\r\n" "gcc_version:%i.%i.%i\r\n" "process_id:%I\r\n" "process_supervised:%s\r\n" "run_id:%s\r\n" "tcp_port:%i\r\n" "server_time_usec:%I\r\n" "uptime_in_seconds:%I\r\n" "uptime_in_days:%I\r\n" "hz:%i\r\n" "configured_hz:%i\r\n" "lru_clock:%u\r\n" "executable:%s\r\n" "config_file:%s\r\n" "io_threads_active:%i\r\n", REDIS_VERSION, redisGitSHA1(), strtol(redisGitDirty(),NULL,10) > 0, redisBuildIdString(), mode, name.sysname, name.release, name.machine, server.arch_bits, aeGetApiName(), REDIS_ATOMIC_API,  __GNUC__,__GNUC_MINOR__,__GNUC_PATCHLEVEL__,  0,0,0,  (int64_t) getpid(), supervised, server.runid, server.port ? server.port : server.tls_port, (int64_t)server.ustime, (int64_t)uptime, (int64_t)(uptime/(3600*24)), server.hz, server.config_hz, lruclock, server.executable ? server.executable : "", server.configfile ? server.configfile : "", server.io_threads_active);


















































    }

    
    if (allsections || defsections || !strcasecmp(section,"clients")) {
        size_t maxin, maxout;
        getExpansiveClientsInfo(&maxin,&maxout);
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Clients\r\n" "connected_clients:%lu\r\n" "cluster_connections:%lu\r\n" "maxclients:%u\r\n" "client_recent_max_input_buffer:%zu\r\n" "client_recent_max_output_buffer:%zu\r\n" "blocked_clients:%d\r\n" "tracking_clients:%d\r\n" "clients_in_timeout_table:%llu\r\n", listLength(server.clients)-listLength(server.slaves), getClusterConnectionsCount(), server.maxclients, maxin, maxout, server.blocked_clients, server.tracking_clients, (unsigned long long) raxSize(server.clients_timeout_table));















    }

    
    if (allsections || defsections || !strcasecmp(section,"memory")) {
        char hmem[64];
        char peak_hmem[64];
        char total_system_hmem[64];
        char used_memory_lua_hmem[64];
        char used_memory_scripts_hmem[64];
        char used_memory_rss_hmem[64];
        char maxmemory_hmem[64];
        size_t zmalloc_used = zmalloc_used_memory();
        size_t total_system_mem = server.system_memory_size;
        const char *evict_policy = evictPolicyToString();
        long long memory_lua = server.lua ? (long long)lua_gc(server.lua,LUA_GCCOUNT,0)*1024 : 0;
        struct redisMemOverhead *mh = getMemoryOverheadData();

        
        if (zmalloc_used > server.stat_peak_memory)
            server.stat_peak_memory = zmalloc_used;

        bytesToHuman(hmem,zmalloc_used);
        bytesToHuman(peak_hmem,server.stat_peak_memory);
        bytesToHuman(total_system_hmem,total_system_mem);
        bytesToHuman(used_memory_lua_hmem,memory_lua);
        bytesToHuman(used_memory_scripts_hmem,mh->lua_caches);
        bytesToHuman(used_memory_rss_hmem,server.cron_malloc_stats.process_rss);
        bytesToHuman(maxmemory_hmem,server.maxmemory);

        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Memory\r\n" "used_memory:%zu\r\n" "used_memory_human:%s\r\n" "used_memory_rss:%zu\r\n" "used_memory_rss_human:%s\r\n" "used_memory_peak:%zu\r\n" "used_memory_peak_human:%s\r\n" "used_memory_peak_perc:%.2f%%\r\n" "used_memory_overhead:%zu\r\n" "used_memory_startup:%zu\r\n" "used_memory_dataset:%zu\r\n" "used_memory_dataset_perc:%.2f%%\r\n" "allocator_allocated:%zu\r\n" "allocator_active:%zu\r\n" "allocator_resident:%zu\r\n" "total_system_memory:%lu\r\n" "total_system_memory_human:%s\r\n" "used_memory_lua:%lld\r\n" "used_memory_lua_human:%s\r\n" "used_memory_scripts:%lld\r\n" "used_memory_scripts_human:%s\r\n" "number_of_cached_scripts:%lu\r\n" "maxmemory:%lld\r\n" "maxmemory_human:%s\r\n" "maxmemory_policy:%s\r\n" "allocator_frag_ratio:%.2f\r\n" "allocator_frag_bytes:%zu\r\n" "allocator_rss_ratio:%.2f\r\n" "allocator_rss_bytes:%zd\r\n" "rss_overhead_ratio:%.2f\r\n" "rss_overhead_bytes:%zd\r\n" "mem_fragmentation_ratio:%.2f\r\n" "mem_fragmentation_bytes:%zd\r\n" "mem_not_counted_for_evict:%zu\r\n" "mem_replication_backlog:%zu\r\n" "mem_clients_slaves:%zu\r\n" "mem_clients_normal:%zu\r\n" "mem_aof_buffer:%zu\r\n" "mem_allocator:%s\r\n" "active_defrag_running:%d\r\n" "lazyfree_pending_objects:%zu\r\n" "lazyfreed_objects:%zu\r\n", zmalloc_used, hmem, server.cron_malloc_stats.process_rss, used_memory_rss_hmem, server.stat_peak_memory, peak_hmem, mh->peak_perc, mh->overhead_total, mh->startup_allocated, mh->dataset, mh->dataset_perc, server.cron_malloc_stats.allocator_allocated, server.cron_malloc_stats.allocator_active, server.cron_malloc_stats.allocator_resident, (unsigned long)total_system_mem, total_system_hmem, memory_lua, used_memory_lua_hmem, (long long) mh->lua_caches, used_memory_scripts_hmem, dictSize(server.lua_scripts), server.maxmemory, maxmemory_hmem, evict_policy, mh->allocator_frag, mh->allocator_frag_bytes, mh->allocator_rss, mh->allocator_rss_bytes, mh->rss_extra, mh->rss_extra_bytes, mh->total_frag, mh->total_frag_bytes, freeMemoryGetNotCountedMemory(), mh->repl_backlog, mh->clients_slaves, mh->clients_normal, mh->aof_buffer, ZMALLOC_LIB, server.active_defrag_running, lazyfreeGetPendingObjectsCount(), lazyfreeGetFreedObjectsCount()


















































































        );
        freeMemoryOverheadData(mh);
    }

    
    if (allsections || defsections || !strcasecmp(section,"persistence")) {
        if (sections++) info = sdscat(info,"\r\n");
        double fork_perc = 0;
        if (server.stat_module_progress) {
            fork_perc = server.stat_module_progress * 100;
        } else if (server.stat_current_save_keys_total) {
            fork_perc = ((double)server.stat_current_save_keys_processed / server.stat_current_save_keys_total) * 100;
        }
        int aof_bio_fsync_status;
        atomicGet(server.aof_bio_fsync_status,aof_bio_fsync_status);

        info = sdscatprintf(info, "# Persistence\r\n" "loading:%d\r\n" "current_cow_peak:%zu\r\n" "current_cow_size:%zu\r\n" "current_cow_size_age:%lu\r\n" "current_fork_perc:%.2f\r\n" "current_save_keys_processed:%zu\r\n" "current_save_keys_total:%zu\r\n" "rdb_changes_since_last_save:%lld\r\n" "rdb_bgsave_in_progress:%d\r\n" "rdb_last_save_time:%jd\r\n" "rdb_last_bgsave_status:%s\r\n" "rdb_last_bgsave_time_sec:%jd\r\n" "rdb_current_bgsave_time_sec:%jd\r\n" "rdb_last_cow_size:%zu\r\n" "rdb_last_load_keys_expired:%lld\r\n" "rdb_last_load_keys_loaded:%lld\r\n" "aof_enabled:%d\r\n" "aof_rewrite_in_progress:%d\r\n" "aof_rewrite_scheduled:%d\r\n" "aof_last_rewrite_time_sec:%jd\r\n" "aof_current_rewrite_time_sec:%jd\r\n" "aof_last_bgrewrite_status:%s\r\n" "aof_last_write_status:%s\r\n" "aof_last_cow_size:%zu\r\n" "module_fork_in_progress:%d\r\n" "module_fork_last_cow_size:%zu\r\n", (int)server.loading, server.stat_current_cow_peak, server.stat_current_cow_bytes, server.stat_current_cow_updated ? (unsigned long) elapsedMs(server.stat_current_cow_updated) / 1000 : 0, fork_perc, server.stat_current_save_keys_processed, server.stat_current_save_keys_total, server.dirty, server.child_type == CHILD_TYPE_RDB, (intmax_t)server.lastsave, (server.lastbgsave_status == C_OK) ? "ok" : "err", (intmax_t)server.rdb_save_time_last, (intmax_t)((server.child_type != CHILD_TYPE_RDB) ? -1 : time(NULL)-server.rdb_save_time_start), server.stat_rdb_cow_bytes, server.rdb_last_load_keys_expired, server.rdb_last_load_keys_loaded, server.aof_state != AOF_OFF, server.child_type == CHILD_TYPE_AOF, server.aof_rewrite_scheduled, (intmax_t)server.aof_rewrite_time_last, (intmax_t)((server.child_type != CHILD_TYPE_AOF) ? -1 : time(NULL)-server.aof_rewrite_time_start), (server.aof_lastbgrewrite_status == C_OK) ? "ok" : "err", (server.aof_last_write_status == C_OK && aof_bio_fsync_status == C_OK) ? "ok" : "err", server.stat_aof_cow_bytes, server.child_type == CHILD_TYPE_MODULE, server.stat_module_cow_bytes);
























































        if (server.aof_enabled) {
            info = sdscatprintf(info, "aof_current_size:%lld\r\n" "aof_base_size:%lld\r\n" "aof_pending_rewrite:%d\r\n" "aof_buffer_length:%zu\r\n" "aof_rewrite_buffer_length:%lu\r\n" "aof_pending_bio_fsync:%llu\r\n" "aof_delayed_fsync:%lu\r\n", (long long) server.aof_current_size, (long long) server.aof_rewrite_base_size, server.aof_rewrite_scheduled, sdslen(server.aof_buf), aofRewriteBufferSize(), bioPendingJobsOfType(BIO_AOF_FSYNC), server.aof_delayed_fsync);













        }

        if (server.loading) {
            double perc = 0;
            time_t eta, elapsed;
            off_t remaining_bytes = 1;

            if (server.loading_total_bytes) {
                perc = ((double)server.loading_loaded_bytes / server.loading_total_bytes) * 100;
                remaining_bytes = server.loading_total_bytes - server.loading_loaded_bytes;
            } else if(server.loading_rdb_used_mem) {
                perc = ((double)server.loading_loaded_bytes / server.loading_rdb_used_mem) * 100;
                remaining_bytes = server.loading_rdb_used_mem - server.loading_loaded_bytes;
                
                if (perc > 99.99) perc = 99.99;
                if (remaining_bytes < 1) remaining_bytes = 1;
            }

            elapsed = time(NULL)-server.loading_start_time;
            if (elapsed == 0) {
                eta = 1; 
            } else {
                eta = (elapsed*remaining_bytes)/(server.loading_loaded_bytes+1);
            }

            info = sdscatprintf(info, "loading_start_time:%jd\r\n" "loading_total_bytes:%llu\r\n" "loading_rdb_used_mem:%llu\r\n" "loading_loaded_bytes:%llu\r\n" "loading_loaded_perc:%.2f\r\n" "loading_eta_seconds:%jd\r\n", (intmax_t) server.loading_start_time, (unsigned long long) server.loading_total_bytes, (unsigned long long) server.loading_rdb_used_mem, (unsigned long long) server.loading_loaded_bytes, perc, (intmax_t)eta );












        }
    }

    
    if (allsections || defsections || !strcasecmp(section,"stats")) {
        long long stat_total_reads_processed, stat_total_writes_processed;
        long long stat_net_input_bytes, stat_net_output_bytes;
        long long current_eviction_exceeded_time = server.stat_last_eviction_exceeded_time ? (long long) elapsedUs(server.stat_last_eviction_exceeded_time): 0;
        long long current_active_defrag_time = server.stat_last_active_defrag_time ? (long long) elapsedUs(server.stat_last_active_defrag_time): 0;
        atomicGet(server.stat_total_reads_processed, stat_total_reads_processed);
        atomicGet(server.stat_total_writes_processed, stat_total_writes_processed);
        atomicGet(server.stat_net_input_bytes, stat_net_input_bytes);
        atomicGet(server.stat_net_output_bytes, stat_net_output_bytes);

        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Stats\r\n" "total_connections_received:%lld\r\n" "total_commands_processed:%lld\r\n" "instantaneous_ops_per_sec:%lld\r\n" "total_net_input_bytes:%lld\r\n" "total_net_output_bytes:%lld\r\n" "instantaneous_input_kbps:%.2f\r\n" "instantaneous_output_kbps:%.2f\r\n" "rejected_connections:%lld\r\n" "sync_full:%lld\r\n" "sync_partial_ok:%lld\r\n" "sync_partial_err:%lld\r\n" "expired_keys:%lld\r\n" "expired_stale_perc:%.2f\r\n" "expired_time_cap_reached_count:%lld\r\n" "expire_cycle_cpu_milliseconds:%lld\r\n" "evicted_keys:%lld\r\n" "evicted_clients:%lld\r\n" "total_eviction_exceeded_time:%lld\r\n" "current_eviction_exceeded_time:%lld\r\n" "keyspace_hits:%lld\r\n" "keyspace_misses:%lld\r\n" "pubsub_channels:%ld\r\n" "pubsub_patterns:%lu\r\n" "latest_fork_usec:%lld\r\n" "total_forks:%lld\r\n" "migrate_cached_sockets:%ld\r\n" "slave_expires_tracked_keys:%zu\r\n" "active_defrag_hits:%lld\r\n" "active_defrag_misses:%lld\r\n" "active_defrag_key_hits:%lld\r\n" "active_defrag_key_misses:%lld\r\n" "total_active_defrag_time:%lld\r\n" "current_active_defrag_time:%lld\r\n" "tracking_total_keys:%lld\r\n" "tracking_total_items:%lld\r\n" "tracking_total_prefixes:%lld\r\n" "unexpected_error_replies:%lld\r\n" "total_error_replies:%lld\r\n" "dump_payload_sanitizations:%lld\r\n" "total_reads_processed:%lld\r\n" "total_writes_processed:%lld\r\n" "io_threaded_reads_processed:%lld\r\n" "io_threaded_writes_processed:%lld\r\n", server.stat_numconnections, server.stat_numcommands, getInstantaneousMetric(STATS_METRIC_COMMAND), stat_net_input_bytes, stat_net_output_bytes, (float)getInstantaneousMetric(STATS_METRIC_NET_INPUT)/1024, (float)getInstantaneousMetric(STATS_METRIC_NET_OUTPUT)/1024, server.stat_rejected_conn, server.stat_sync_full, server.stat_sync_partial_ok, server.stat_sync_partial_err, server.stat_expiredkeys, server.stat_expired_stale_perc*100, server.stat_expired_time_cap_reached_count, server.stat_expire_cycle_time_used/1000, server.stat_evictedkeys, server.stat_evictedclients, (server.stat_total_eviction_exceeded_time + current_eviction_exceeded_time) / 1000, current_eviction_exceeded_time / 1000, server.stat_keyspace_hits, server.stat_keyspace_misses, dictSize(server.pubsub_channels), dictSize(server.pubsub_patterns), server.stat_fork_time, server.stat_total_forks, dictSize(server.migrate_cached_sockets), getSlaveKeyWithExpireCount(), server.stat_active_defrag_hits, server.stat_active_defrag_misses, server.stat_active_defrag_key_hits, server.stat_active_defrag_key_misses, (server.stat_total_active_defrag_time + current_active_defrag_time) / 1000, current_active_defrag_time / 1000, (unsigned long long) trackingGetTotalKeys(), (unsigned long long) trackingGetTotalItems(), (unsigned long long) trackingGetTotalPrefixes(), server.stat_unexpected_error_replies, server.stat_total_error_replies, server.stat_dump_payload_sanitizations, stat_total_reads_processed, stat_total_writes_processed, server.stat_io_reads_processed, server.stat_io_writes_processed);






















































































    }

    
    if (allsections || defsections || !strcasecmp(section,"replication")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Replication\r\n" "role:%s\r\n", server.masterhost == NULL ? "master" : "slave");


        if (server.masterhost) {
            long long slave_repl_offset = 1;
            long long slave_read_repl_offset = 1;

            if (server.master) {
                slave_repl_offset = server.master->reploff;
                slave_read_repl_offset = server.master->read_reploff;
            } else if (server.cached_master) {
                slave_repl_offset = server.cached_master->reploff;
                slave_read_repl_offset = server.cached_master->read_reploff;
            }

            info = sdscatprintf(info, "master_host:%s\r\n" "master_port:%d\r\n" "master_link_status:%s\r\n" "master_last_io_seconds_ago:%d\r\n" "master_sync_in_progress:%d\r\n" "slave_read_repl_offset:%lld\r\n" "slave_repl_offset:%lld\r\n" ,server.masterhost, server.masterport, (server.repl_state == REPL_STATE_CONNECTED) ? "up" : "down", server.master ? ((int)(server.unixtime-server.master->lastinteraction)) : -1, server.repl_state == REPL_STATE_TRANSFER, slave_read_repl_offset, slave_repl_offset );

















            if (server.repl_state == REPL_STATE_TRANSFER) {
                double perc = 0;
                if (server.repl_transfer_size) {
                    perc = ((double)server.repl_transfer_read / server.repl_transfer_size) * 100;
                }
                info = sdscatprintf(info, "master_sync_total_bytes:%lld\r\n" "master_sync_read_bytes:%lld\r\n" "master_sync_left_bytes:%lld\r\n" "master_sync_perc:%.2f\r\n" "master_sync_last_io_seconds_ago:%d\r\n", (long long) server.repl_transfer_size, (long long) server.repl_transfer_read, (long long) (server.repl_transfer_size - server.repl_transfer_read), perc, (int)(server.unixtime-server.repl_transfer_lastio)









                );
            }

            if (server.repl_state != REPL_STATE_CONNECTED) {
                info = sdscatprintf(info, "master_link_down_since_seconds:%jd\r\n", server.repl_down_since ? (intmax_t)(server.unixtime-server.repl_down_since) : -1);


            }
            info = sdscatprintf(info, "slave_priority:%d\r\n" "slave_read_only:%d\r\n" "replica_announced:%d\r\n", server.slave_priority, server.repl_slave_ro, server.replica_announced);





        }

        info = sdscatprintf(info, "connected_slaves:%lu\r\n", listLength(server.slaves));


        
        if (server.repl_min_slaves_to_write && server.repl_min_slaves_max_lag) {
            info = sdscatprintf(info, "min_slaves_good_slaves:%d\r\n", server.repl_good_slaves_count);

        }

        if (listLength(server.slaves)) {
            int slaveid = 0;
            listNode *ln;
            listIter li;

            listRewind(server.slaves,&li);
            while((ln = listNext(&li))) {
                client *slave = listNodeValue(ln);
                char *state = NULL;
                char ip[NET_IP_STR_LEN], *slaveip = slave->slave_addr;
                int port;
                long lag = 0;

                if (!slaveip) {
                    if (connPeerToString(slave->conn,ip,sizeof(ip),&port) == -1)
                        continue;
                    slaveip = ip;
                }
                switch(slave->replstate) {
                case SLAVE_STATE_WAIT_BGSAVE_START:
                case SLAVE_STATE_WAIT_BGSAVE_END:
                    state = "wait_bgsave";
                    break;
                case SLAVE_STATE_SEND_BULK:
                    state = "send_bulk";
                    break;
                case SLAVE_STATE_ONLINE:
                    state = "online";
                    break;
                }
                if (state == NULL) continue;
                if (slave->replstate == SLAVE_STATE_ONLINE)
                    lag = time(NULL) - slave->repl_ack_time;

                info = sdscatprintf(info, "slave%d:ip=%s,port=%d,state=%s," "offset=%lld,lag=%ld\r\n", slaveid,slaveip,slave->slave_listening_port,state, slave->repl_ack_off, lag);



                slaveid++;
            }
        }
        info = sdscatprintf(info, "master_failover_state:%s\r\n" "master_replid:%s\r\n" "master_replid2:%s\r\n" "master_repl_offset:%lld\r\n" "second_repl_offset:%lld\r\n" "repl_backlog_active:%d\r\n" "repl_backlog_size:%lld\r\n" "repl_backlog_first_byte_offset:%lld\r\n" "repl_backlog_histlen:%lld\r\n", getFailoverStateString(), server.replid, server.replid2, server.master_repl_offset, server.second_replid_offset, server.repl_backlog != NULL, server.repl_backlog_size, server.repl_backlog_off, server.repl_backlog_histlen);

















    }

    
    if (allsections || defsections || !strcasecmp(section,"cpu")) {
        if (sections++) info = sdscat(info,"\r\n");

        struct rusage self_ru, c_ru;
        getrusage(RUSAGE_SELF, &self_ru);
        getrusage(RUSAGE_CHILDREN, &c_ru);
        info = sdscatprintf(info, "# CPU\r\n" "used_cpu_sys:%ld.%06ld\r\n" "used_cpu_user:%ld.%06ld\r\n" "used_cpu_sys_children:%ld.%06ld\r\n" "used_cpu_user_children:%ld.%06ld\r\n", (long)self_ru.ru_stime.tv_sec, (long)self_ru.ru_stime.tv_usec, (long)self_ru.ru_utime.tv_sec, (long)self_ru.ru_utime.tv_usec, (long)c_ru.ru_stime.tv_sec, (long)c_ru.ru_stime.tv_usec, (long)c_ru.ru_utime.tv_sec, (long)c_ru.ru_utime.tv_usec);









        struct rusage m_ru;
        getrusage(RUSAGE_THREAD, &m_ru);
        info = sdscatprintf(info, "used_cpu_sys_main_thread:%ld.%06ld\r\n" "used_cpu_user_main_thread:%ld.%06ld\r\n", (long)m_ru.ru_stime.tv_sec, (long)m_ru.ru_stime.tv_usec, (long)m_ru.ru_utime.tv_sec, (long)m_ru.ru_utime.tv_usec);




    }

    
    if (allsections || defsections || !strcasecmp(section,"modules")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info,"# Modules\r\n");
        info = genModulesInfoString(info);
    }

    
    if (allsections || !strcasecmp(section,"commandstats")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Commandstats\r\n");

        struct redisCommand *c;
        dictEntry *de;
        dictIterator *di;
        di = dictGetSafeIterator(server.commands);
        while((de = dictNext(di)) != NULL) {
            char *tmpsafe;
            c = (struct redisCommand *) dictGetVal(de);
            if (!c->calls && !c->failed_calls && !c->rejected_calls)
                continue;
            info = sdscatprintf(info, "cmdstat_%s:calls=%lld,usec=%lld,usec_per_call=%.2f" ",rejected_calls=%lld,failed_calls=%lld\r\n", getSafeInfoString(c->name, strlen(c->name), &tmpsafe), c->calls, c->microseconds, (c->calls == 0) ? 0 : ((float)c->microseconds/c->calls), c->rejected_calls, c->failed_calls);




            if (tmpsafe != NULL) zfree(tmpsafe);
        }
        dictReleaseIterator(di);
    }
    
    if (allsections || defsections || !strcasecmp(section,"errorstats")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscat(info, "# Errorstats\r\n");
        raxIterator ri;
        raxStart(&ri,server.errors);
        raxSeek(&ri,"^",NULL,0);
        struct redisError *e;
        while(raxNext(&ri)) {
            char *tmpsafe;
            e = (struct redisError *) ri.data;
            info = sdscatprintf(info, "errorstat_%.*s:count=%lld\r\n", (int)ri.key_len, getSafeInfoString((char *) ri.key, ri.key_len, &tmpsafe), e->count);

            if (tmpsafe != NULL) zfree(tmpsafe);
        }
        raxStop(&ri);
    }

    
    if (allsections || defsections || !strcasecmp(section,"cluster")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Cluster\r\n" "cluster_enabled:%d\r\n", server.cluster_enabled);


    }

    
    if (allsections || defsections || !strcasecmp(section,"keyspace")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Keyspace\r\n");
        for (j = 0; j < server.dbnum; j++) {
            long long keys, vkeys;

            keys = dictSize(server.db[j].dict);
            vkeys = dictSize(server.db[j].expires);
            if (keys || vkeys) {
                info = sdscatprintf(info, "db%d:keys=%lld,expires=%lld,avg_ttl=%lld\r\n", j, keys, vkeys, server.db[j].avg_ttl);

            }
        }
    }

    
    if (everything || modules || (!allsections && !defsections && sections==0)) {
        info = modulesCollectInfo(info, everything || modules ? NULL: section, 0, sections);


    }
    return info;
}

void infoCommand(client *c) {
    char *section = c->argc == 2 ? c->argv[1]->ptr : "default";

    if (c->argc > 2) {
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }
    sds info = genRedisInfoString(section);
    addReplyVerbatim(c,info,sdslen(info),"txt");
    sdsfree(info);
}

void monitorCommand(client *c) {
    if (c->flags & CLIENT_DENY_BLOCKING) {
        
        addReplyError(c, "MONITOR isn't allowed for DENY BLOCKING client");
        return;
    }

    
    if (c->flags & CLIENT_SLAVE) return;

    c->flags |= (CLIENT_SLAVE|CLIENT_MONITOR);
    listAddNodeTail(server.monitors,c);
    addReply(c,shared.ok);
}



int checkIgnoreWarning(const char *warning) {
    int argc, j;
    sds *argv = sdssplitargs(server.ignore_warnings, &argc);
    if (argv == NULL)
        return 0;

    for (j = 0; j < argc; j++) {
        char *flag = argv[j];
        if (!strcasecmp(flag, warning))
            break;
    }
    sdsfreesplitres(argv,argc);
    return j < argc;
}


int linuxOvercommitMemoryValue(void) {
    FILE *fp = fopen("/proc/sys/vm/overcommit_memory","r");
    char buf[64];

    if (!fp) return -1;
    if (fgets(buf,64,fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    return atoi(buf);
}

void linuxMemoryWarnings(void) {
    if (linuxOvercommitMemoryValue() == 0) {
        serverLog(LL_WARNING,"WARNING overcommit_memory is set to 0! Background save may fail under low memory condition. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.");
    }
    if (THPIsEnabled()) {
        server.thp_enabled = 1;
        if (THPDisable() == 0) {
            server.thp_enabled = 0;
            return;
        }
        serverLog(LL_WARNING,"WARNING you have Transparent Huge Pages (THP) support enabled in your kernel. This will create latency and memory usage issues with Redis. To fix this issue run the command 'echo madvise > /sys/kernel/mm/transparent_hugepage/enabled' as root, and add it to your /etc/rc.local in order to retain the setting after a reboot. Redis must be restarted after THP is disabled (set to 'madvise' or 'never').");
    }
}




static int smapsGetSharedDirty(unsigned long addr) {
    int ret, in_mapping = 0, val = -1;
    unsigned long from, to;
    char buf[64];
    FILE *f;

    f = fopen("/proc/self/smaps", "r");
    if (!f) return -1;

    while (1) {
        if (!fgets(buf, sizeof(buf), f))
            break;

        ret = sscanf(buf, "%lx-%lx", &from, &to);
        if (ret == 2)
            in_mapping = from <= addr && addr < to;

        if (in_mapping && !memcmp(buf, "Shared_Dirty:", 13)) {
            sscanf(buf, "%*s %d", &val);
            
            break;
        }
    }

    fclose(f);
    return val;
}


int linuxMadvFreeForkBugCheck(void) {
    int ret, pipefd[2] = { -1, -1 };
    pid_t pid;
    char *p = NULL, *q;
    int bug_found = 0;
    long page_size = sysconf(_SC_PAGESIZE);
    long map_size = 3 * page_size;

    
    p = mmap(NULL, map_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        serverLog(LL_WARNING, "Failed to mmap(): %s", strerror(errno));
        return -1;
    }

    q = p + page_size;

    
    ret = mprotect(q, page_size, PROT_READ | PROT_WRITE);
    if (ret < 0) {
        serverLog(LL_WARNING, "Failed to mprotect(): %s", strerror(errno));
        bug_found = -1;
        goto exit;
    }

    
    *(volatile char*)q = 0;

    



    ret = madvise(q, page_size, MADV_FREE);
    if (ret < 0) {
        
        if (errno == EINVAL) goto exit;

        serverLog(LL_WARNING, "Failed to madvise(): %s", strerror(errno));
        bug_found = -1;
        goto exit;
    }

    
    *(volatile char*)q = 0;

    
    ret = pipe(pipefd);
    if (ret < 0) {
        serverLog(LL_WARNING, "Failed to create pipe: %s", strerror(errno));
        bug_found = -1;
        goto exit;
    }

    
    pid = fork();
    if (pid < 0) {
        serverLog(LL_WARNING, "Failed to fork: %s", strerror(errno));
        bug_found = -1;
        goto exit;
    } else if (!pid) {
        
        ret = smapsGetSharedDirty((unsigned long) q);
        if (!ret)
            bug_found = 1;
        else if (ret == -1)     
            bug_found = -1;

        if (write(pipefd[1], &bug_found, sizeof(bug_found)) < 0)
            serverLog(LL_WARNING, "Failed to write to parent: %s", strerror(errno));
        exitFromChild(0);
    } else {
        
        ret = read(pipefd[0], &bug_found, sizeof(bug_found));
        if (ret < 0) {
            serverLog(LL_WARNING, "Failed to read from child: %s", strerror(errno));
            bug_found = -1;
        }

        
        waitpid(pid, NULL, 0);
    }

exit:
    
    if (pipefd[0] != -1) close(pipefd[0]);
    if (pipefd[1] != -1) close(pipefd[1]);
    if (p != NULL) munmap(p, map_size);

    return bug_found;
}



void createPidFile(void) {
    
    if (!server.pidfile) server.pidfile = zstrdup(CONFIG_DEFAULT_PID_FILE);

    
    FILE *fp = fopen(server.pidfile,"w");
    if (fp) {
        fprintf(fp,"%d\n",(int)getpid());
        fclose(fp);
    }
}

void daemonize(void) {
    int fd;

    if (fork() != 0) exit(0); 
    setsid(); 

    
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}

void version(void) {
    printf("Redis server v=%s sha=%s:%d malloc=%s bits=%d build=%llx\n", REDIS_VERSION, redisGitSHA1(), atoi(redisGitDirty()) > 0, ZMALLOC_LIB, sizeof(long) == 4 ? 32 : 64, (unsigned long long) redisBuildId());





    exit(0);
}

void usage(void) {
    fprintf(stderr,"Usage: ./redis-server [/path/to/redis.conf] [options] [-]\n");
    fprintf(stderr,"       ./redis-server - (read config from stdin)\n");
    fprintf(stderr,"       ./redis-server -v or --version\n");
    fprintf(stderr,"       ./redis-server -h or --help\n");
    fprintf(stderr,"       ./redis-server --test-memory <megabytes>\n\n");
    fprintf(stderr,"Examples:\n");
    fprintf(stderr,"       ./redis-server (run the server with default conf)\n");
    fprintf(stderr,"       ./redis-server /etc/redis/6379.conf\n");
    fprintf(stderr,"       ./redis-server --port 7777\n");
    fprintf(stderr,"       ./redis-server --port 7777 --replicaof 127.0.0.1 8888\n");
    fprintf(stderr,"       ./redis-server /etc/myredis.conf --loglevel verbose -\n");
    fprintf(stderr,"       ./redis-server /etc/myredis.conf --loglevel verbose\n\n");
    fprintf(stderr,"Sentinel mode:\n");
    fprintf(stderr,"       ./redis-server /etc/sentinel.conf --sentinel\n");
    exit(1);
}

void redisAsciiArt(void) {

    char *buf = zmalloc(1024*16);
    char *mode;

    if (server.cluster_enabled) mode = "cluster";
    else if (server.sentinel_mode) mode = "sentinel";
    else mode = "standalone";

    
    int show_logo = ((!server.syslog_enabled && server.logfile[0] == '\0' && isatty(fileno(stdout))) || server.always_show_logo);



    if (!show_logo) {
        serverLog(LL_NOTICE, "Running mode=%s, port=%d.", mode, server.port ? server.port : server.tls_port );


    } else {
        snprintf(buf,1024*16,ascii_logo, REDIS_VERSION, redisGitSHA1(), strtol(redisGitDirty(),NULL,10) > 0, (sizeof(long) == 8) ? "64" : "32", mode, server.port ? server.port : server.tls_port, (long) getpid()





        );
        serverLogRaw(LL_NOTICE|LL_RAW,buf);
    }
    zfree(buf);
}

int changeBindAddr(sds *addrlist, int addrlist_len) {
    int i;
    int result = C_OK;

    char *prev_bindaddr[CONFIG_BINDADDR_MAX];
    int prev_bindaddr_count;

    
    closeSocketListeners(&server.ipfd);
    closeSocketListeners(&server.tlsfd);

    
    prev_bindaddr_count = server.bindaddr_count;
    memcpy(prev_bindaddr, server.bindaddr, sizeof(server.bindaddr));

    
    memset(server.bindaddr, 0, sizeof(server.bindaddr));
    for (i = 0; i < addrlist_len; i++) {
        server.bindaddr[i] = zstrdup(addrlist[i]);
    }
    server.bindaddr_count = addrlist_len;

    
    if ((server.port != 0 && listenToPort(server.port, &server.ipfd) != C_OK) || (server.tls_port != 0 && listenToPort(server.tls_port, &server.tlsfd) != C_OK)) {
        serverLog(LL_WARNING, "Failed to bind, trying to restore old listening sockets.");

        
        for (i = 0; i < addrlist_len; i++) {
            zfree(server.bindaddr[i]);
        }
        memcpy(server.bindaddr, prev_bindaddr, sizeof(server.bindaddr));
        server.bindaddr_count = prev_bindaddr_count;

        
        server.ipfd.count = 0;
        if (server.port != 0 && listenToPort(server.port, &server.ipfd) != C_OK) {
            serverPanic("Failed to restore old listening TCP socket.");
        }

        server.tlsfd.count = 0;
        if (server.tls_port != 0 && listenToPort(server.tls_port, &server.tlsfd) != C_OK) {
            serverPanic("Failed to restore old listening TLS socket.");
        }

        result = C_ERR;
    } else {
        
        for (i = 0; i < prev_bindaddr_count; i++) {
            zfree(prev_bindaddr[i]);
        }
    }

    
    if (createSocketAcceptHandler(&server.ipfd, acceptTcpHandler) != C_OK) {
        serverPanic("Unrecoverable error creating TCP socket accept handler.");
    }
    if (createSocketAcceptHandler(&server.tlsfd, acceptTLSHandler) != C_OK) {
        serverPanic("Unrecoverable error creating TLS socket accept handler.");
    }

    if (server.set_proc_title) redisSetProcTitle(NULL);

    return result;
}

int changeListenPort(int port, socketFds *sfd, aeFileProc *accept_handler) {
    socketFds new_sfd = {{0}};

    
    if (port == 0) {
        closeSocketListeners(sfd);
        if (server.set_proc_title) redisSetProcTitle(NULL);
        return C_OK;
    }

    
    if (listenToPort(port, &new_sfd) != C_OK) {
        return C_ERR;
    }

    
    if (createSocketAcceptHandler(&new_sfd, accept_handler) != C_OK) {
        closeSocketListeners(&new_sfd);
        return C_ERR;
    }

    
    closeSocketListeners(sfd);

    
    sfd->count = new_sfd.count;
    memcpy(sfd->fd, new_sfd.fd, sizeof(new_sfd.fd));

    if (server.set_proc_title) redisSetProcTitle(NULL);

    return C_OK;
}

static void sigShutdownHandler(int sig) {
    char *msg;

    switch (sig) {
    case SIGINT:
        msg = "Received SIGINT scheduling shutdown...";
        break;
    case SIGTERM:
        msg = "Received SIGTERM scheduling shutdown...";
        break;
    default:
        msg = "Received shutdown signal, scheduling shutdown...";
    };

    
    if (server.shutdown_asap && sig == SIGINT) {
        serverLogFromHandler(LL_WARNING, "You insist... exiting now.");
        rdbRemoveTempFile(getpid(), 1);
        exit(1); 
    } else if (server.loading) {
        serverLogFromHandler(LL_WARNING, "Received shutdown signal during loading, exiting now.");
        exit(0);
    }

    serverLogFromHandler(LL_WARNING, msg);
    server.shutdown_asap = 1;
}

void setupSignalHandlers(void) {
    struct sigaction act;

    
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigShutdownHandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);

    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
    act.sa_sigaction = sigsegvHandler;
    if(server.crashlog_enabled) {
        sigaction(SIGSEGV, &act, NULL);
        sigaction(SIGBUS, &act, NULL);
        sigaction(SIGFPE, &act, NULL);
        sigaction(SIGILL, &act, NULL);
        sigaction(SIGABRT, &act, NULL);
    }
    return;
}

void removeSignalHandlers(void) {
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_RESETHAND;
    act.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
    sigaction(SIGILL, &act, NULL);
    sigaction(SIGABRT, &act, NULL);
}


static void sigKillChildHandler(int sig) {
    UNUSED(sig);
    int level = server.in_fork_child == CHILD_TYPE_MODULE? LL_VERBOSE: LL_WARNING;
    serverLogFromHandler(level, "Received SIGUSR1 in child, exiting now.");
    exitFromChild(SERVER_CHILD_NOERROR_RETVAL);
}

void setupChildSignalHandlers(void) {
    struct sigaction act;

    
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigKillChildHandler;
    sigaction(SIGUSR1, &act, NULL);
}


void closeChildUnusedResourceAfterFork() {
    closeListeningSockets(0);
    if (server.cluster_enabled && server.cluster_config_file_lock_fd != -1)
        close(server.cluster_config_file_lock_fd);  

    
    zfree(server.pidfile);
    server.pidfile = NULL;
}


int redisFork(int purpose) {
    if (isMutuallyExclusiveChildType(purpose)) {
        if (hasActiveChildProcess())
            return -1;

        openChildInfoPipe();
    }

    int childpid;
    long long start = ustime();
    if ((childpid = fork()) == 0) {
        
        server.in_fork_child = purpose;
        setupChildSignalHandlers();
        setOOMScoreAdj(CONFIG_OOM_BGCHILD);
        dismissMemoryInChild();
        closeChildUnusedResourceAfterFork();
    } else {
        
        server.stat_total_forks++;
        server.stat_fork_time = ustime()-start;
        server.stat_fork_rate = (double) zmalloc_used_memory() * 1000000 / server.stat_fork_time / (1024*1024*1024); 
        latencyAddSampleIfNeeded("fork",server.stat_fork_time/1000);
        if (childpid == -1) {
            if (isMutuallyExclusiveChildType(purpose)) closeChildInfoPipe();
            return -1;
        }

        
        if (isMutuallyExclusiveChildType(purpose)) {
            server.child_pid = childpid;
            server.child_type = purpose;
            server.stat_current_cow_peak = 0;
            server.stat_current_cow_bytes = 0;
            server.stat_current_cow_updated = 0;
            server.stat_current_save_keys_processed = 0;
            server.stat_module_progress = 0;
            server.stat_current_save_keys_total = dbTotalServerKeyCount();
        }

        updateDictResizePolicy();
        moduleFireServerEvent(REDISMODULE_EVENT_FORK_CHILD, REDISMODULE_SUBEVENT_FORK_CHILD_BORN, NULL);

    }
    return childpid;
}

void sendChildCowInfo(childInfoType info_type, char *pname) {
    sendChildInfoGeneric(info_type, 0, -1, pname);
}

void sendChildInfo(childInfoType info_type, size_t keys, char *pname) {
    sendChildInfoGeneric(info_type, keys, -1, pname);
}


void dismissMemory(void* ptr, size_t size_hint) {
    if (ptr == NULL) return;

    
    if (size_hint && size_hint <= server.page_size/2) return;

    zmadvise_dontneed(ptr);
}


void dismissClientMemory(client *c) {
    
    dismissSds(c->querybuf);
    dismissSds(c->pending_querybuf);
    
    if (c->argc && c->argv_len_sum/c->argc >= server.page_size) {
        for (int i = 0; i < c->argc; i++) {
            dismissObject(c->argv[i], 0);
        }
    }
    if (c->argc) dismissMemory(c->argv, c->argc*sizeof(robj*));

    
    if (listLength(c->reply) && c->reply_bytes/listLength(c->reply) >= server.page_size)
    {
        listIter li;
        listNode *ln;
        listRewind(c->reply, &li);
        while ((ln = listNext(&li))) {
            clientReplyBlock *bulk = listNodeValue(ln);
            
            if (bulk) dismissMemory(bulk, bulk->size);
        }
    }

    
    dismissMemory(c, 0);
}


void dismissMemoryInChild(void) {
    
    if (server.thp_enabled) return;

    


    
    if (server.repl_backlog != NULL) {
        dismissMemory(server.repl_backlog, server.repl_backlog_size);
    }

    
    listIter li;
    listNode *ln;
    listRewind(server.clients, &li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        dismissClientMemory(c);
    }

}

void memtest(size_t megabytes, int passes);


int checkForSentinelMode(int argc, char **argv, char *exec_name) {
    if (strstr(exec_name,"redis-sentinel") != NULL) return 1;

    for (int j = 1; j < argc; j++)
        if (!strcmp(argv[j],"--sentinel")) return 1;
    return 0;
}


void loadDataFromDisk(void) {
    long long start = ustime();
    if (server.aof_state == AOF_ON) {
        
        int ret = loadAppendOnlyFile(server.aof_filename);
        if (ret == AOF_FAILED || ret == AOF_OPEN_ERR)
            exit(1);
        if (ret == AOF_OK)
            serverLog(LL_NOTICE,"DB loaded from append only file: %.3f seconds",(float)(ustime()-start)/1000000);
    } else {
        rdbSaveInfo rsi = RDB_SAVE_INFO_INIT;
        errno = 0; 
        int rdb_flags = RDBFLAGS_NONE;
        if (iAmMaster()) {
            
            createReplicationBacklog();
            rdb_flags |= RDBFLAGS_FEED_REPL;
        }
        if (rdbLoad(server.rdb_filename,&rsi,rdb_flags) == C_OK) {
            serverLog(LL_NOTICE,"DB loaded from disk: %.3f seconds", (float)(ustime()-start)/1000000);

            
            if (rsi.repl_id_is_set && rsi.repl_offset != -1 &&  rsi.repl_stream_db != -1)


            {
                if (!iAmMaster()) {
                    memcpy(server.replid,rsi.repl_id,sizeof(server.replid));
                    server.master_repl_offset = rsi.repl_offset;
                    
                    replicationCacheMasterUsingMyself();
                    selectDb(server.cached_master,rsi.repl_stream_db);
                } else {
                    
                    memcpy(server.replid2,rsi.repl_id,sizeof(server.replid));
                    server.second_replid_offset = rsi.repl_offset+1;
                    
                    server.master_repl_offset += rsi.repl_offset;
                    server.repl_backlog_off = server.master_repl_offset - server.repl_backlog_histlen + 1;
                    server.repl_no_slaves_since = time(NULL);
                }
            }
        } else if (errno != ENOENT) {
            serverLog(LL_WARNING,"Fatal error loading the DB: %s. Exiting.",strerror(errno));
            exit(1);
        }
    }
}

void redisOutOfMemoryHandler(size_t allocation_size) {
    serverLog(LL_WARNING,"Out Of Memory allocating %zu bytes!", allocation_size);
    serverPanic("Redis aborting for OUT OF MEMORY. Allocating %zu bytes!", allocation_size);
}


static sds redisProcTitleGetVariable(const sds varname, void *arg)
{
    if (!strcmp(varname, "title")) {
        return sdsnew(arg);
    } else if (!strcmp(varname, "listen-addr")) {
        if (server.port || server.tls_port)
            return sdscatprintf(sdsempty(), "%s:%u", server.bindaddr_count ? server.bindaddr[0] : "*", server.port ? server.port : server.tls_port);

        else return sdscatprintf(sdsempty(), "unixsocket:%s", server.unixsocket);
    } else if (!strcmp(varname, "server-mode")) {
        if (server.cluster_enabled) return sdsnew("[cluster]");
        else if (server.sentinel_mode) return sdsnew("[sentinel]");
        else return sdsempty();
    } else if (!strcmp(varname, "config-file")) {
        return sdsnew(server.configfile ? server.configfile : "-");
    } else if (!strcmp(varname, "port")) {
        return sdscatprintf(sdsempty(), "%u", server.port);
    } else if (!strcmp(varname, "tls-port")) {
        return sdscatprintf(sdsempty(), "%u", server.tls_port);
    } else if (!strcmp(varname, "unixsocket")) {
        return sdsnew(server.unixsocket);
    } else return NULL;
}


static sds expandProcTitleTemplate(const char *template, const char *title) {
    sds res = sdstemplate(template, redisProcTitleGetVariable, (void *) title);
    if (!res)
        return NULL;
    return sdstrim(res, " ");
}

int validateProcTitleTemplate(const char *template) {
    int ok = 1;
    sds res = expandProcTitleTemplate(template, "");
    if (!res)
        return 0;
    if (sdslen(res) == 0) ok = 0;
    sdsfree(res);
    return ok;
}

int redisSetProcTitle(char *title) {

    if (!title) title = server.exec_argv[0];
    sds proc_title = expandProcTitleTemplate(server.proc_title_template, title);
    if (!proc_title) return C_ERR;  

    setproctitle("%s", proc_title);
    sdsfree(proc_title);

    UNUSED(title);


    return C_OK;
}

void redisSetCpuAffinity(const char *cpulist) {

    setcpuaffinity(cpulist);

    UNUSED(cpulist);

}


int redisCommunicateSystemd(const char *sd_notify_msg) {

    int ret = sd_notify(0, sd_notify_msg);

    if (ret == 0)
        serverLog(LL_WARNING, "systemd supervision error: NOTIFY_SOCKET not found!");
    else if (ret < 0)
        serverLog(LL_WARNING, "systemd supervision error: sd_notify: %d", ret);
    return ret;

    UNUSED(sd_notify_msg);
    return 0;

}


static int redisSupervisedUpstart(void) {
    const char *upstart_job = getenv("UPSTART_JOB");

    if (!upstart_job) {
        serverLog(LL_WARNING, "upstart supervision requested, but UPSTART_JOB not found!");
        return 0;
    }

    serverLog(LL_NOTICE, "supervised by upstart, will stop to signal readiness.");
    raise(SIGSTOP);
    unsetenv("UPSTART_JOB");
    return 1;
}


static int redisSupervisedSystemd(void) {

    serverLog(LL_WARNING, "systemd supervision requested or auto-detected, but Redis is compiled without libsystemd support!");
    return 0;

    if (redisCommunicateSystemd("STATUS=Redis is loading...\n") <= 0)
        return 0;
    serverLog(LL_NOTICE, "Supervised by systemd. Please make sure you set appropriate values for TimeoutStartSec and TimeoutStopSec in your service unit.");
    return 1;

}

int redisIsSupervised(int mode) {
    int ret = 0;

    if (mode == SUPERVISED_AUTODETECT) {
        if (getenv("UPSTART_JOB")) {
            serverLog(LL_VERBOSE, "Upstart supervision detected.");
            mode = SUPERVISED_UPSTART;
        } else if (getenv("NOTIFY_SOCKET")) {
            serverLog(LL_VERBOSE, "Systemd supervision detected.");
            mode = SUPERVISED_SYSTEMD;
        }
    }

    switch (mode) {
        case SUPERVISED_UPSTART:
            ret = redisSupervisedUpstart();
            break;
        case SUPERVISED_SYSTEMD:
            ret = redisSupervisedSystemd();
            break;
        default:
            break;
    }

    if (ret)
        server.supervised_mode = mode;

    return ret;
}

int iAmMaster(void) {
    return ((!server.cluster_enabled && server.masterhost == NULL) || (server.cluster_enabled && nodeIsMaster(server.cluster->myself)));
}


typedef int redisTestProc(int argc, char **argv, int accurate);
struct redisTest {
    char *name;
    redisTestProc *proc;
    int failed;
} redisTests[] = {
    {"ziplist", ziplistTest}, {"quicklist", quicklistTest}, {"intset", intsetTest}, {"zipmap", zipmapTest}, {"sha1test", sha1Test}, {"util", utilTest}, {"endianconv", endianconvTest}, {"crc64", crc64Test}, {"zmalloc", zmalloc_test}, {"sds", sdsTest}, {"dict", dictTest}, {"listpack", listpackTest}










};
redisTestProc *getTestProcByName(const char *name) {
    int numtests = sizeof(redisTests)/sizeof(struct redisTest);
    for (int j = 0; j < numtests; j++) {
        if (!strcasecmp(name,redisTests[j].name)) {
            return redisTests[j].proc;
        }
    }
    return NULL;
}


int main(int argc, char **argv) {
    struct timeval tv;
    int j;
    char config_from_stdin = 0;


    if (argc >= 3 && !strcasecmp(argv[1], "test")) {
        int accurate = 0;
        for (j = 3; j < argc; j++) {
            if (!strcasecmp(argv[j], "--accurate")) {
                accurate = 1;
            }
        }

        if (!strcasecmp(argv[2], "all")) {
            int numtests = sizeof(redisTests)/sizeof(struct redisTest);
            for (j = 0; j < numtests; j++) {
                redisTests[j].failed = (redisTests[j].proc(argc,argv,accurate) != 0);
            }

            
            int failed_num = 0;
            for (j = 0; j < numtests; j++) {
                if (redisTests[j].failed) {
                    failed_num++;
                    printf("[failed] Test - %s\n", redisTests[j].name);
                } else {
                    printf("[ok] Test - %s\n", redisTests[j].name);
                }
            }

            printf("%d tests, %d passed, %d failed\n", numtests, numtests-failed_num, failed_num);

            return failed_num == 0 ? 0 : 1;
        } else {
            redisTestProc *proc = getTestProcByName(argv[2]);
            if (!proc) return -1; 
            return proc(argc,argv,accurate);
        }

        return 0;
    }


    

    spt_init(argc, argv);

    setlocale(LC_COLLATE,"");
    tzset(); 
    zmalloc_set_oom_handler(redisOutOfMemoryHandler);
    srand(time(NULL)^getpid());
    srandom(time(NULL)^getpid());
    gettimeofday(&tv,NULL);
    init_genrand64(((long long) tv.tv_sec * 1000000 + tv.tv_usec) ^ getpid());
    crc64_init();

    
    umask(server.umask = umask(0777));

    uint8_t hashseed[16];
    getRandomBytes(hashseed,sizeof(hashseed));
    dictSetHashFunctionSeed(hashseed);

    char *exec_name = strrchr(argv[0], '/');
    if (exec_name == NULL) exec_name = argv[0];
    server.sentinel_mode = checkForSentinelMode(argc,argv, exec_name);
    initServerConfig();
    ACLInit(); 
    moduleInitModulesSystem();
    tlsInit();

    
    server.executable = getAbsolutePath(argv[0]);
    server.exec_argv = zmalloc(sizeof(char*)*(argc+1));
    server.exec_argv[argc] = NULL;
    for (j = 0; j < argc; j++) server.exec_argv[j] = zstrdup(argv[j]);

    
    if (server.sentinel_mode) {
        initSentinelConfig();
        initSentinel();
    }

    
    if (strstr(exec_name,"redis-check-rdb") != NULL)
        redis_check_rdb_main(argc,argv,NULL);
    else if (strstr(exec_name,"redis-check-aof") != NULL)
        redis_check_aof_main(argc,argv);

    if (argc >= 2) {
        j = 1; 
        sds options = sdsempty();

        
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) version();
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) usage();
        if (strcmp(argv[1], "--test-memory") == 0) {
            if (argc == 3) {
                memtest(atoi(argv[2]),50);
                exit(0);
            } else {
                fprintf(stderr,"Please specify the amount of memory to test in megabytes.\n");
                fprintf(stderr,"Example: ./redis-server --test-memory 4096\n\n");
                exit(1);
            }
        }
        
        if (argv[1][0] != '-') {
            
            server.configfile = getAbsolutePath(argv[1]);
            zfree(server.exec_argv[1]);
            server.exec_argv[1] = zstrdup(server.configfile);
            j = 2; 
        }
        while(j < argc) {
            
            if (argv[j][0] == '-' && argv[j][1] == '\0' && (j == 1 || j == argc-1)) {
                config_from_stdin = 1;
            }
            
            else if (argv[j][0] == '-' && argv[j][1] == '-') {
                
                if (sdslen(options)) options = sdscat(options,"\n");
                options = sdscat(options,argv[j]+2);
                options = sdscat(options," ");
            } else {
                
                options = sdscatrepr(options,argv[j],strlen(argv[j]));
                options = sdscat(options," ");
            }
            j++;
        }

        loadServerConfig(server.configfile, config_from_stdin, options);
        if (server.sentinel_mode) loadSentinelConfigFromQueue();
        sdsfree(options);
    }
    if (server.sentinel_mode) sentinelCheckConfigFile();
    server.supervised = redisIsSupervised(server.supervised_mode);
    int background = server.daemonize && !server.supervised;
    if (background) daemonize();

    serverLog(LL_WARNING, "oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo");
    serverLog(LL_WARNING, "Redis version=%s, bits=%d, commit=%s, modified=%d, pid=%d, just started", REDIS_VERSION, (sizeof(long) == 8) ? 64 : 32, redisGitSHA1(), strtol(redisGitDirty(),NULL,10) > 0, (int)getpid());






    if (argc == 1) {
        serverLog(LL_WARNING, "Warning: no config file specified, using the default config. In order to specify a config file use %s /path/to/redis.conf", argv[0]);
    } else {
        serverLog(LL_WARNING, "Configuration loaded");
    }

    readOOMScoreAdj();
    initServer();
    if (background || server.pidfile) createPidFile();
    if (server.set_proc_title) redisSetProcTitle(NULL);
    redisAsciiArt();
    checkTcpBacklogSettings();

    if (!server.sentinel_mode) {
        
        serverLog(LL_WARNING,"Server initialized");
    #ifdef __linux__
        linuxMemoryWarnings();
    #if defined (__arm64__)
        int ret;
        if ((ret = linuxMadvFreeForkBugCheck())) {
            if (ret == 1)
                serverLog(LL_WARNING,"WARNING Your kernel has a bug that could lead to data corruption during background save. " "Please upgrade to the latest stable kernel.");
            else serverLog(LL_WARNING, "Failed to test the kernel for a bug that could lead to data corruption during background save. " "Your system could be affected, please report this error.");

            if (!checkIgnoreWarning("ARM64-COW-BUG")) {
                serverLog(LL_WARNING,"Redis will now exit to prevent data corruption. " "Note that it is possible to suppress this warning by setting the following config: ignore-warnings ARM64-COW-BUG");
                exit(1);
            }
        }
    #endif 
    #endif 
        moduleInitModulesSystemLast();
        moduleLoadFromQueue();
        ACLLoadUsersAtStartup();
        InitServerLast();
        loadDataFromDisk();
        
        if (server.aof_state == AOF_ON) {
            server.aof_fd = open(server.aof_filename, O_WRONLY|O_APPEND|O_CREAT,0644);
            if (server.aof_fd == -1) {
                serverLog(LL_WARNING, "Can't open the append-only file: %s", strerror(errno));
                exit(1);
            }
        }
        if (server.cluster_enabled) {
            if (verifyClusterConfigWithData() == C_ERR) {
                serverLog(LL_WARNING, "You can't have keys in a DB different than DB 0 when in " "Cluster mode. Exiting.");

                exit(1);
            }
        }
        if (server.ipfd.count > 0 || server.tlsfd.count > 0)
            serverLog(LL_NOTICE,"Ready to accept connections");
        if (server.sofd > 0)
            serverLog(LL_NOTICE,"The server is now ready to accept connections at %s", server.unixsocket);
        if (server.supervised_mode == SUPERVISED_SYSTEMD) {
            if (!server.masterhost) {
                redisCommunicateSystemd("STATUS=Ready to accept connections\n");
            } else {
                redisCommunicateSystemd("STATUS=Ready to accept connections in read-only mode. Waiting for MASTER <-> REPLICA sync\n");
            }
            redisCommunicateSystemd("READY=1\n");
        }
    } else {
        ACLLoadUsersAtStartup();
        InitServerLast();
        sentinelIsRunning();
        if (server.supervised_mode == SUPERVISED_SYSTEMD) {
            redisCommunicateSystemd("STATUS=Ready to accept connections\n");
            redisCommunicateSystemd("READY=1\n");
        }
    }

    
    if (server.maxmemory > 0 && server.maxmemory < 1024*1024) {
        serverLog(LL_WARNING,"WARNING: You specified a maxmemory value that is less than 1MB (current value is %llu bytes). Are you sure this is what you really want?", server.maxmemory);
    }

    redisSetCpuAffinity(server.server_cpulist);
    setOOMScoreAdj(-1);

    aeMain(server.el);
    aeDeleteEventLoop(server.el);
    return 0;
}


