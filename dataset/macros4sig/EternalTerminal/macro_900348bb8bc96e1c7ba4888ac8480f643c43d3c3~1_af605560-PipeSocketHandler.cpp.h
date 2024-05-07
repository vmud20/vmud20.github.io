#include<netinet/in.h>
#include<time.h>
#include<termios.h>


#include<unistd.h>
#include<sys/ioctl.h>

#include<pthread.h>

#include<exception>

#include<set>
#include<vector>

#include<unordered_map>

#include<deque>
#include<string.h>
#include<stdlib.h>




#include<mutex>

#include<fstream>
#include<pwd.h>

#include<stdio.h>
#include<errno.h>
#include<paths.h>

#include<arpa/inet.h>
#include<string>
#include<memory>

#include<sstream>
#include<experimental/filesystem>
#include<sys/wait.h>
#include<streambuf>


#include<locale>
#include<netinet/tcp.h>

#include<unordered_set>

#include<filesystem>
#include<algorithm>
#include<ctime>

#include<grp.h>
#include<array>
#include<sys/stat.h>
#include<fcntl.h>
#include<codecvt>
#include<sys/socket.h>
#include<sys/types.h>

#include<signal.h>
#include<thread>
#include<stdint.h>
#include<pty.h>
#include<atomic>

#include<netdb.h>
#include<sys/un.h>
#include<resolv.h>
#include<iostream>




#define CPPHTTPLIB_OPENSSL_SUPPORT (1)
#define CPPHTTPLIB_ZLIB_SUPPORT (1)
#define ET_VERSION "unknown"
#define FATAL_FAIL(X)                             \
  if (((X) == -1))                                \
    LOG(FATAL) << "Error: (" << WSAGetLastError() \
               << "): " << WindowsErrnoToString();
#define FATAL_FAIL_UNLESS_EINVAL(X) FATAL_FAIL(X)
#define FATAL_FAIL_UNLESS_ZERO(X)                 \
  if (((X) != 0))                                 \
    LOG(FATAL) << "Error: (" << WSAGetLastError() \
               << "): " << WindowsErrnoToString();
#define STERROR LOG(ERROR) << "No Stack Trace on Android" << endl
#define STFATAL LOG(FATAL) << "No Stack Trace on Android" << endl


#define pclose _pclose
#define popen _popen
#define ssize_t SSIZE_T

