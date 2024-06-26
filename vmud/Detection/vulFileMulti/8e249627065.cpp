














































































namespace HPHP {


bool RepoOptions::s_init{false};
RepoOptions RepoOptions::s_defaults;

namespace {


const static bool s_PHP7_default = false;

const static bool s_PHP7_default = true;






static bool s_PHP7_master = s_PHP7_default;

std::vector<std::string> s_RelativeConfigs;



char mangleForKey(bool b) { return b ? '1' : '0'; }
std::string mangleForKey(const RepoOptions::StringMap& map) {
  std::string s;
  s += folly::to<std::string>(map.size());
  s += '\0';
  for (auto& par : map) {
    s += par.first + '\0' + par.second + '\0';
  }
  return s;
}
std::string mangleForKey(std::string s) { return s; }
void hdfExtract(const Hdf& hdf, const char* name, bool& val, bool dv) {
  val = hdf[name].configGetBool(dv);
}
void hdfExtract(const Hdf& hdf, const char* name, uint16_t& val, uint16_t dv) {
  val = hdf[name].configGetUInt16(dv);
}
void hdfExtract( const Hdf& hdf, const char* name, RepoOptions::StringMap& map, const RepoOptions::StringMap& dv ) {




  Hdf config = hdf[name];
  if (config.exists() && !config.isEmpty()) config.configGet(map);
  else map = dv;
}
void hdfExtract( const Hdf& hdf, const char* name, std::string& val, std::string dv ) {




  val = hdf[name].configGetString(dv);
}
folly::dynamic toIniValue(bool b) {
  return b ? "1" : "0";
}

folly::dynamic toIniValue(const RepoOptions::StringMap& map) {
  folly::dynamic obj = folly::dynamic::object();
  for (auto& kv : map) {
    obj[kv.first] = kv.second;
  }
  return obj;
}

folly::dynamic toIniValue(const std::string& str) {
  return str;
}

struct CachedRepoOptions {
  CachedRepoOptions() = default;
  explicit CachedRepoOptions(RepoOptions&& opts)
    : options(new RepoOptions(std::move(opts)))
  {}
  CachedRepoOptions(const CachedRepoOptions& opts)
    : options(nullptr)
  {
    if (auto o = opts.options.load(std::memory_order_relaxed)) {
      options.store(new RepoOptions(*o), std::memory_order_relaxed);
    }
  }
  ~CachedRepoOptions() {
    Treadmill::enqueue([opt = options.exchange(nullptr)] { delete opt; });
  }

  CachedRepoOptions& operator=(const CachedRepoOptions& opts) {
    auto const o = opts.options.load(std::memory_order_relaxed);
    auto const old = options.exchange(o ? new RepoOptions(*o) : nullptr);
    if (old) Treadmill::enqueue([old] { delete old; });
    return *this;
  }

  static bool isChanged(const RepoOptions* opts, struct stat s) {
    auto const o = opts->stat();
    return s.st_mtim.tv_sec  != o.st_mtim.tv_sec || s.st_mtim.tv_nsec != o.st_mtim.tv_nsec || s.st_ctim.tv_sec  != o.st_ctim.tv_sec || s.st_ctim.tv_nsec != o.st_ctim.tv_nsec || s.st_dev != o.st_dev || s.st_ino != o.st_ino;





  }

  const RepoOptions* update(RepoOptions&& opts) const {
    auto const val = new RepoOptions(std::move(opts));
    auto const old = options.exchange(val);
    if (old) Treadmill::enqueue([old] { delete old; });
    return val;
  }

  const RepoOptions* fetch(struct stat st) const {
    auto const opts = options.load(std::memory_order_relaxed);
    return opts && !isChanged(opts, st) ? opts : nullptr;
  }

  mutable std::atomic<RepoOptions*> options{nullptr};
};

using RepoOptionCache = tbb::concurrent_hash_map< std::string, CachedRepoOptions, stringHashCompare >;



RepoOptionCache s_repoOptionCache;

template<class F> bool walkDirTree(std::string fpath, F func) {
  const char* filename = ".hhvmconfig.hdf";
  do {
    auto const off = fpath.rfind('/');
    if (off == std::string::npos) return false;
    fpath.resize(off);
    fpath += '/';
    fpath += filename;

    if (func(fpath)) return true;

    fpath.resize(off);
  } while (!fpath.empty() && fpath != "/");
  return false;
}

RDS_LOCAL(std::string, s_lastSeenRepoConfig);

}

const RepoOptions& RepoOptions::forFile(const char* path) {
  tracing::BlockNoTrace _{"repo-options";

  if (!RuntimeOption::EvalEnablePerRepoOptions) return defaults();

  std::string fpath{path};
  if (boost::starts_with(fpath, "/:")) return defaults();

  auto const isParentOf = [] (const std::string& p1, const std::string& p2) {
    return boost::starts_with( boost::filesystem::path{p2}, boost::filesystem::path{p1}.parent_path()

    );
  };

  
  
  
  
  
  if (!g_context.isNull()) {
    if (auto const opts = g_context->getRepoOptionsForRequest()) {
      
      
      if (opts->path().empty()) return *opts;

      if (isParentOf(opts->path(), fpath)) {
        struct stat st;
        if (lstat(opts->path().data(), &st) == 0) {
          if (!CachedRepoOptions::isChanged(opts, st)) return *opts;
        }
      }
    }
  }

  auto const set = [&] ( RepoOptionCache::const_accessor& rpathAcc, const std::string& path, const struct stat& st ) -> const RepoOptions* {



    *s_lastSeenRepoConfig = path;
    if (auto const opts = rpathAcc->second.fetch(st)) {
      return opts;
    }
    RepoOptions newOpts{path.data()};
    newOpts.m_stat = st;
    return rpathAcc->second.update(std::move(newOpts));
  };

  auto const test = [&] (const std::string& path) -> const RepoOptions* {
    struct stat st;
    RepoOptionCache::const_accessor rpathAcc;
    if (!s_repoOptionCache.find(rpathAcc, path)) return nullptr;
    if (lstat(path.data(), &st) != 0) {
      s_repoOptionCache.erase(rpathAcc);
      return nullptr;
    }
    return set(rpathAcc, path, st);
  };

  const RepoOptions* ret{nullptr};

  
  
  
  
  
  
  
  if (RuntimeOption::EvalCachePerRepoOptionsPath) {
    if (!s_lastSeenRepoConfig->empty() && isParentOf(*s_lastSeenRepoConfig, fpath)) {
      if (auto const r = test(*s_lastSeenRepoConfig)) return *r;
      s_lastSeenRepoConfig->clear();
    }

    
    
    walkDirTree(fpath, [&] (const std::string& path) {
      return (ret = test(path)) != nullptr;
    });
  }

  if (ret) return *ret;

  walkDirTree(fpath, [&] (const std::string& path) {
    struct stat st;
    if (lstat(path.data(), &st) != 0) return false;
    RepoOptionCache::const_accessor rpathAcc;
    s_repoOptionCache.insert(rpathAcc, path);
    ret = set(rpathAcc, path, st);
    return true;
  });

  return ret ? *ret : defaults();
}

std::string RepoOptions::cacheKeyRaw() const {
  return std::string("")




PARSERFLAGS()
AUTOLOADFLAGS();




}

std::string RepoOptions::cacheKeySha1() const {
  return string_sha1(cacheKeyRaw());
}

std::string RepoOptions::toJSON() const {
  return folly::toJson(toDynamic());
}

folly::dynamic RepoOptions::toDynamic() const {
  folly::dynamic json = folly::dynamic::object();














PARSERFLAGS()
AUTOLOADFLAGS();







  return json;
}

bool RepoOptions::operator==(const RepoOptions& o) const {




PARSERFLAGS()
AUTOLOADFLAGS();




  return true;
}

const RepoOptions& RepoOptions::defaults() {
  always_assert(s_init);
  return s_defaults;
}

void RepoOptions::filterNamespaces() {
  for (auto it = AliasedNamespaces.begin(); it != AliasedNamespaces.end(); ) {
    if (!is_valid_class_name(it->second)) {
      Logger::Warning("Skipping invalid AliasedNamespace %s\n", it->second.c_str());
      it = AliasedNamespaces.erase(it);
      continue;
    }

    while (it->second.size() && it->second[0] == '\\') {
      it->second = it->second.substr(1);
    }

    ++it;
  }
}

RepoOptions::RepoOptions(const char* file) : m_path(file) {
  always_assert(s_init);
  Hdf config{file};
  Hdf parserConfig = config["Parser"];





PARSERFLAGS();





  Hdf autoloadConfig = config["Autoload"];




AUTOLOADFLAGS();





  filterNamespaces();
}

void RepoOptions::initDefaults(const Hdf& hdf, const IniSettingMap& ini) {




PARSERFLAGS()
AUTOLOADFLAGS()





  filterNamespaces();
  m_path.clear();
}

void RepoOptions::setDefaults(const Hdf& hdf, const IniSettingMap& ini) {
  always_assert(!s_init);
  s_defaults.initDefaults(hdf, ini);
  s_init = true;
}



std::string RuntimeOption::BuildId;
std::string RuntimeOption::InstanceId;
std::string RuntimeOption::DeploymentId;
int64_t RuntimeOption::ConfigId = 0;
std::string RuntimeOption::PidFile = "www.pid";

bool RuntimeOption::ServerMode = false;

bool RuntimeOption::EnableHipHopSyntax = true;
bool RuntimeOption::EnableShortTags = true;
bool RuntimeOption::EnableXHP = true;
bool RuntimeOption::EnableIntrinsicsExtension = false;
bool RuntimeOption::CheckSymLink = true;
bool RuntimeOption::TrustAutoloaderPath = false;
bool RuntimeOption::EnableArgsInBacktraces = true;
bool RuntimeOption::EnableZendIniCompat = true;
bool RuntimeOption::TimeoutsUseWallTime = true;
bool RuntimeOption::CheckFlushOnUserClose = true;
bool RuntimeOption::EvalAuthoritativeMode = false;
bool RuntimeOption::DumpPreciseProfData = true;
uint32_t RuntimeOption::EvalInitialStaticStringTableSize = kDefaultInitialStaticStringTableSize;
uint32_t RuntimeOption::EvalInitialNamedEntityTableSize = 30000;
JitSerdesMode RuntimeOption::EvalJitSerdesMode{};
int RuntimeOption::ProfDataTTLHours = 24;
std::string RuntimeOption::ProfDataTag;
std::string RuntimeOption::EvalJitSerdesFile;

std::map<std::string, ErrorLogFileData> RuntimeOption::ErrorLogs = {
  {Logger::DEFAULT, ErrorLogFileData()}, };

std::string RuntimeOption::LogFile;
std::string RuntimeOption::LogFileSymLink;
uint16_t RuntimeOption::LogFilePeriodMultiplier;

int RuntimeOption::LogHeaderMangle = 0;
bool RuntimeOption::AlwaysLogUnhandledExceptions = true;
bool RuntimeOption::AlwaysEscapeLog = true;
bool RuntimeOption::NoSilencer = false;
int RuntimeOption::ErrorUpgradeLevel = 0;
bool RuntimeOption::CallUserHandlerOnFatals = false;
bool RuntimeOption::ThrowExceptionOnBadMethodCall = true;
bool RuntimeOption::LogNativeStackOnOOM = true;
int RuntimeOption::RuntimeErrorReportingLevel = static_cast<int>(ErrorMode::HPHP_ALL);
int RuntimeOption::ForceErrorReportingLevel = 0;

std::string RuntimeOption::ServerUser;
std::vector<std::string> RuntimeOption::TzdataSearchPaths;

int RuntimeOption::MaxSerializedStringSize = 64 * 1024 * 1024; 
bool RuntimeOption::NoInfiniteRecursionDetection = false;
bool RuntimeOption::AssertEmitted = true;
int64_t RuntimeOption::NoticeFrequency = 1;
int64_t RuntimeOption::WarningFrequency = 1;
int RuntimeOption::RaiseDebuggingFrequency = 1;
int64_t RuntimeOption::SerializationSizeLimit = StringData::MaxSize;

std::string RuntimeOption::AccessLogDefaultFormat = "%h %l %u %t \"%r\" %>s %b";
std::map<std::string, AccessLogFileData> RuntimeOption::AccessLogs;

std::string RuntimeOption::AdminLogFormat = "%h %t %s %U";
std::string RuntimeOption::AdminLogFile;
std::string RuntimeOption::AdminLogSymLink;

std::map<std::string, AccessLogFileData> RuntimeOption::RPCLogs;

std::string RuntimeOption::Host;
std::string RuntimeOption::DefaultServerNameSuffix;
std::string RuntimeOption::ServerType = "proxygen";
std::string RuntimeOption::ServerIP;
std::string RuntimeOption::ServerFileSocket;
int RuntimeOption::ServerPort = 80;
int RuntimeOption::ServerPortFd = -1;
int RuntimeOption::ServerBacklog = 128;
int RuntimeOption::ServerConnectionLimit = 0;
int RuntimeOption::ServerThreadCount = 50;
int RuntimeOption::ServerQueueCount = 50;
int RuntimeOption::ServerIOThreadCount = 1;
int RuntimeOption::ServerHighQueueingThreshold = 60;
bool RuntimeOption::ServerLegacyBehavior = true;
int RuntimeOption::ServerHugeThreadCount = 0;
int RuntimeOption::ServerHugeStackKb = 384;
uint32_t RuntimeOption::ServerLoopSampleRate = 0;
int RuntimeOption::ServerWarmupThrottleRequestCount = 0;
int RuntimeOption::ServerWarmupThrottleThreadCount = 0;
int RuntimeOption::ServerThreadDropCacheTimeoutSeconds = 0;
int RuntimeOption::ServerThreadJobLIFOSwitchThreshold = INT_MAX;
int RuntimeOption::ServerThreadJobMaxQueuingMilliSeconds = -1;
bool RuntimeOption::AlwaysDecodePostDataDefault = true;
bool RuntimeOption::ServerThreadDropStack = false;
bool RuntimeOption::ServerHttpSafeMode = false;
bool RuntimeOption::ServerStatCache = false;
bool RuntimeOption::ServerFixPathInfo = false;
bool RuntimeOption::ServerAddVaryEncoding = true;
bool RuntimeOption::ServerLogSettingsOnStartup = false;
bool RuntimeOption::ServerLogReorderProps = false;
bool RuntimeOption::ServerForkEnabled = true;
bool RuntimeOption::ServerForkLogging = false;
bool RuntimeOption::ServerWarmupConcurrently = false;
bool RuntimeOption::ServerDedupeWarmupRequests = false;
int RuntimeOption::ServerWarmupThreadCount = 1;
int RuntimeOption::ServerExtendedWarmupThreadCount = 1;
unsigned RuntimeOption::ServerExtendedWarmupRepeat = 1;
unsigned RuntimeOption::ServerExtendedWarmupDelaySeconds = 60;
std::vector<std::string> RuntimeOption::ServerWarmupRequests;
std::vector<std::string> RuntimeOption::ServerExtendedWarmupRequests;
std::string RuntimeOption::ServerCleanupRequest;
int RuntimeOption::ServerInternalWarmupThreads = 0;
boost::container::flat_set<std::string> RuntimeOption::ServerHighPriorityEndPoints;
bool RuntimeOption::ServerExitOnBindFail;
int RuntimeOption::PageletServerThreadCount = 0;
int RuntimeOption::PageletServerHugeThreadCount = 0;
int RuntimeOption::PageletServerThreadDropCacheTimeoutSeconds = 0;
int RuntimeOption::PageletServerQueueLimit = 0;
bool RuntimeOption::PageletServerThreadDropStack = false;
int RuntimeOption::RequestTimeoutSeconds = 0;
int RuntimeOption::PspTimeoutSeconds = 0;
int RuntimeOption::PspCpuTimeoutSeconds = 0;
int64_t RuntimeOption::MaxRequestAgeFactor = 0;
int64_t RuntimeOption::RequestMemoryMaxBytes = std::numeric_limits<int64_t>::max();
int64_t RuntimeOption::RequestHugeMaxBytes = 0;
int64_t RuntimeOption::ImageMemoryMaxBytes = 0;
int RuntimeOption::ServerGracefulShutdownWait = 0;
bool RuntimeOption::ServerHarshShutdown = true;
bool RuntimeOption::ServerEvilShutdown = true;
bool RuntimeOption::ServerKillOnTimeout = true;
bool RuntimeOption::Server503OnShutdownAbort = false;
int RuntimeOption::ServerPreShutdownWait = 0;
int RuntimeOption::ServerShutdownListenWait = 0;
int RuntimeOption::ServerShutdownEOMWait = 0;
int RuntimeOption::ServerPrepareToStopTimeout = 0;
int RuntimeOption::ServerPartialPostStatusCode = -1;
bool RuntimeOption::StopOldServer = false;
int RuntimeOption::OldServerWait = 30;
int RuntimeOption::CacheFreeFactor = 50;
int64_t RuntimeOption::ServerRSSNeededMb = 4096;
int64_t RuntimeOption::ServerCriticalFreeMb = 512;
std::vector<std::string> RuntimeOption::ServerNextProtocols;
bool RuntimeOption::ServerEnableH2C = false;
int RuntimeOption::BrotliCompressionEnabled = -1;
int RuntimeOption::BrotliChunkedCompressionEnabled = -1;
int RuntimeOption::BrotliCompressionMode = 0;
int RuntimeOption::BrotliCompressionQuality = 6;
int RuntimeOption::BrotliCompressionLgWindowSize = 20;
int RuntimeOption::ZstdCompressionEnabled = -1;
int RuntimeOption::ZstdCompressionLevel = 3;
int RuntimeOption::ZstdChecksumRate = 0;
int RuntimeOption::GzipCompressionLevel = 3;
int RuntimeOption::GzipMaxCompressionLevel = 9;
bool RuntimeOption::EnableKeepAlive = true;
bool RuntimeOption::ExposeHPHP = true;
bool RuntimeOption::ExposeXFBServer = false;
bool RuntimeOption::ExposeXFBDebug = false;
std::string RuntimeOption::XFBDebugSSLKey;
int RuntimeOption::ConnectionTimeoutSeconds = -1;
bool RuntimeOption::EnableOutputBuffering = false;
std::string RuntimeOption::OutputHandler;
bool RuntimeOption::ImplicitFlush = false;
bool RuntimeOption::EnableEarlyFlush = true;
bool RuntimeOption::ForceChunkedEncoding = false;
int64_t RuntimeOption::MaxPostSize = 100;
int64_t RuntimeOption::LowestMaxPostSize = LLONG_MAX;
bool RuntimeOption::AlwaysPopulateRawPostData = false;
int64_t RuntimeOption::UploadMaxFileSize = 100;
std::string RuntimeOption::UploadTmpDir = "/tmp";
bool RuntimeOption::EnableFileUploads = true;
bool RuntimeOption::EnableUploadProgress = false;
int64_t RuntimeOption::MaxFileUploads = 20;
int RuntimeOption::Rfc1867Freq = 256 * 1024;
std::string RuntimeOption::Rfc1867Prefix = "vupload_";
std::string RuntimeOption::Rfc1867Name = "video_ptoken";
bool RuntimeOption::ExpiresActive = true;
int RuntimeOption::ExpiresDefault = 2592000;
std::string RuntimeOption::DefaultCharsetName = "";
bool RuntimeOption::ForceServerNameToHeader = false;
bool RuntimeOption::PathDebug = false;

int64_t RuntimeOption::RequestBodyReadLimit = -1;

bool RuntimeOption::EnableSSL = false;
int RuntimeOption::SSLPort = 443;
int RuntimeOption::SSLPortFd = -1;
std::string RuntimeOption::SSLCertificateFile;
std::string RuntimeOption::SSLCertificateKeyFile;
std::string RuntimeOption::SSLCertificateDir;
std::string RuntimeOption::SSLTicketSeedFile;
bool RuntimeOption::TLSDisableTLS1_2 = false;
std::string RuntimeOption::TLSClientCipherSpec;
bool RuntimeOption::EnableSSLWithPlainText = false;
int RuntimeOption::SSLClientAuthLevel = 0;
std::string RuntimeOption::SSLClientCAFile = "";

std::string RuntimeOption::ClientAuthAclIdentity;
std::string RuntimeOption::ClientAuthAclAction;
bool RuntimeOption::ClientAuthFailClose = false;
uint32_t RuntimeOption::SSLClientAuthLoggingSampleRatio = 0;
uint32_t RuntimeOption::ClientAuthSuccessLogSampleRatio = 0;
uint32_t RuntimeOption::ClientAuthFailureLogSampleRatio = 0;
uint32_t RuntimeOption::ClientAuthLogSampleBase = 100;

std::vector<std::shared_ptr<VirtualHost>> RuntimeOption::VirtualHosts;
std::shared_ptr<IpBlockMap> RuntimeOption::IpBlocks;
std::vector<std::shared_ptr<SatelliteServerInfo>> RuntimeOption::SatelliteServerInfos;

bool RuntimeOption::AllowRunAsRoot = false; 

int RuntimeOption::XboxServerThreadCount = 10;
int RuntimeOption::XboxServerMaxQueueLength = INT_MAX;
int RuntimeOption::XboxServerInfoMaxRequest = 500;
int RuntimeOption::XboxServerInfoDuration = 120;
std::string RuntimeOption::XboxServerInfoReqInitFunc;
std::string RuntimeOption::XboxServerInfoReqInitDoc;
bool RuntimeOption::XboxServerInfoAlwaysReset = false;
bool RuntimeOption::XboxServerLogInfo = false;
std::string RuntimeOption::XboxProcessMessageFunc = "xbox_process_message";
std::string RuntimeOption::XboxPassword;
std::set<std::string> RuntimeOption::XboxPasswords;

std::string RuntimeOption::SourceRoot = Process::GetCurrentDirectory() + '/';
std::vector<std::string> RuntimeOption::IncludeSearchPaths;
std::map<std::string, std::string> RuntimeOption::IncludeRoots;
std::map<std::string, std::string> RuntimeOption::AutoloadRoots;
bool RuntimeOption::AutoloadEnabled;
std::string RuntimeOption::AutoloadDBPath;
std::string RuntimeOption::FileCache;
std::string RuntimeOption::DefaultDocument;
std::string RuntimeOption::GlobalDocument;
std::string RuntimeOption::ErrorDocument404;
bool RuntimeOption::ForbiddenAs404 = false;
std::string RuntimeOption::ErrorDocument500;
std::string RuntimeOption::FatalErrorMessage;
std::string RuntimeOption::FontPath;
bool RuntimeOption::EnableStaticContentFromDisk = true;
bool RuntimeOption::EnableOnDemandUncompress = true;
bool RuntimeOption::EnableStaticContentMMap = true;

bool RuntimeOption::Utf8izeReplace = true;

std::string RuntimeOption::RequestInitFunction;
std::string RuntimeOption::RequestInitDocument;
std::string RuntimeOption::AutoPrependFile;
std::string RuntimeOption::AutoAppendFile;

bool RuntimeOption::SafeFileAccess = false;
std::vector<std::string> RuntimeOption::AllowedDirectories;
std::set<std::string> RuntimeOption::AllowedFiles;
hphp_string_imap<std::string> RuntimeOption::StaticFileExtensions;
hphp_string_imap<std::string> RuntimeOption::PhpFileExtensions;
std::set<std::string> RuntimeOption::ForbiddenFileExtensions;
std::vector<std::shared_ptr<FilesMatch>> RuntimeOption::FilesMatches;

bool RuntimeOption::WhitelistExec = false;
bool RuntimeOption::WhitelistExecWarningOnly = false;
std::vector<std::string> RuntimeOption::AllowedExecCmds;

bool RuntimeOption::UnserializationWhitelistCheck = false;
bool RuntimeOption::UnserializationWhitelistCheckWarningOnly = true;
int64_t RuntimeOption::UnserializationBigMapThreshold = 1 << 16;

std::string RuntimeOption::TakeoverFilename;
std::string RuntimeOption::AdminServerIP;
int RuntimeOption::AdminServerPort = 0;
int RuntimeOption::AdminThreadCount = 1;
bool RuntimeOption::AdminServerEnableSSLWithPlainText = false;
bool RuntimeOption::AdminServerStatsNeedPassword = true;
std::string RuntimeOption::AdminPassword;
std::set<std::string> RuntimeOption::AdminPasswords;
std::set<std::string> RuntimeOption::HashedAdminPasswords;

std::string RuntimeOption::ProxyOriginRaw;
int RuntimeOption::ProxyPercentageRaw = 0;
int RuntimeOption::ProxyRetry = 3;
bool RuntimeOption::UseServeURLs;
std::set<std::string> RuntimeOption::ServeURLs;
bool RuntimeOption::UseProxyURLs;
std::set<std::string> RuntimeOption::ProxyURLs;
std::vector<std::string> RuntimeOption::ProxyPatterns;
bool RuntimeOption::AlwaysUseRelativePath = false;

int RuntimeOption::HttpDefaultTimeout = 30;
int RuntimeOption::HttpSlowQueryThreshold = 5000; 

bool RuntimeOption::NativeStackTrace = false;
bool RuntimeOption::ServerErrorMessage = false;
bool RuntimeOption::RecordInput = false;
bool RuntimeOption::ClearInputOnSuccess = true;
std::string RuntimeOption::ProfilerOutputDir = "/tmp";
std::string RuntimeOption::CoreDumpEmail;
bool RuntimeOption::CoreDumpReport = true;
std::string RuntimeOption::CoreDumpReportDirectory =  "/tmp";


  "/var/tmp/cores";

std::string RuntimeOption::StackTraceFilename;
int RuntimeOption::StackTraceTimeout = 0; 
std::string RuntimeOption::RemoteTraceOutputDir = "/tmp";
std::set<std::string, stdltistr> RuntimeOption::TraceFunctions;

bool RuntimeOption::EnableStats = false;
bool RuntimeOption::EnableAPCStats = false;
bool RuntimeOption::EnableWebStats = false;
bool RuntimeOption::EnableMemoryStats = false;
bool RuntimeOption::EnableSQLStats = false;
bool RuntimeOption::EnableSQLTableStats = false;
bool RuntimeOption::EnableNetworkIOStatus = false;
std::string RuntimeOption::StatsXSL;
std::string RuntimeOption::StatsXSLProxy;
uint32_t RuntimeOption::StatsSlotDuration = 10 * 60; 
uint32_t RuntimeOption::StatsMaxSlot = 12 * 6; 

int64_t RuntimeOption::MaxSQLRowCount = 0;
int64_t RuntimeOption::SocketDefaultTimeout = 60;
bool RuntimeOption::LockCodeMemory = false;
int RuntimeOption::MaxArrayChain = INT_MAX;
bool RuntimeOption::WarnOnCollectionToArray = false;
bool RuntimeOption::UseDirectCopy = false;


bool RuntimeOption::DisableSmallAllocator = true;

bool RuntimeOption::DisableSmallAllocator = false;


std::map<std::string, std::string> RuntimeOption::ServerVariables;
std::map<std::string, std::string> RuntimeOption::EnvVariables;

std::string RuntimeOption::LightProcessFilePrefix = "./lightprocess";
int RuntimeOption::LightProcessCount = 0;

int64_t RuntimeOption::HeapSizeMB = 4096; 
int64_t RuntimeOption::HeapResetCountBase = 1;
int64_t RuntimeOption::HeapResetCountMultiple = 2;
int64_t RuntimeOption::HeapLowWaterMark = 16;
int64_t RuntimeOption::HeapHighWaterMark = 1024;
uint64_t RuntimeOption::DisableCallUserFunc = 0;
uint64_t RuntimeOption::DisableCallUserFuncArray = 0;
uint64_t RuntimeOption::DisableAssert = 0;
uint64_t RuntimeOption::DisableConstant = 0;
bool RuntimeOption::DisableNontoplevelDeclarations = false;
bool RuntimeOption::DisableStaticClosures = false;
bool RuntimeOption::EnableClassLevelWhereClauses = false;


std::string RuntimeOption::ExtensionDir = HHVM_DYNAMIC_EXTENSION_DIR;

std::string RuntimeOption::ExtensionDir = "";


std::vector<std::string> RuntimeOption::Extensions;
std::vector<std::string> RuntimeOption::DynamicExtensions;
std::string RuntimeOption::DynamicExtensionPath = ".";
int RuntimeOption::CheckCLIClientCommands = 0;

int RuntimeOption::CheckIntOverflow = 0;
HackStrictOption RuntimeOption::StrictArrayFillKeys = HackStrictOption::OFF;


bool RuntimeOption::LookForTypechecker = false;
bool RuntimeOption::AutoTypecheck = false;

bool RuntimeOption::PHP7_EngineExceptions = false;
bool RuntimeOption::PHP7_NoHexNumerics = false;
bool RuntimeOption::PHP7_Builtins = false;
bool RuntimeOption::PHP7_Substr = false;
bool RuntimeOption::PHP7_DisallowUnsafeCurlUploads = false;

int RuntimeOption::GetScannerType() {
  int type = 0;
  if (EnableShortTags) type |= Scanner::AllowShortTags;
  return type;
}

const std::string& RuntimeOption::GetServerPrimaryIPv4() {
   static std::string serverPrimaryIPv4 = GetPrimaryIPv4();
   return serverPrimaryIPv4;
}

const std::string& RuntimeOption::GetServerPrimaryIPv6() {
   static std::string serverPrimaryIPv6 = GetPrimaryIPv6();
   return serverPrimaryIPv6;
}

static inline std::string regionSelectorDefault() {
  return "tracelet";
}

static inline bool pgoDefault() {

  return false;

  return true;

}

static inline bool eagerGcDefault() {

  return true;

  return false;

}

static inline std::string hackCompilerArgsDefault() {
  return "--daemon --dump-symbol-refs";
}

static inline std::string hackCompilerCommandDefault() {

  return "";

  std::string hackc = folly::sformat( "{}/hh_single_compile", current_executable_directory()

  );
  if (::access(hackc.data(), X_OK) != 0) {

    return "";

    hackc = HACKC_FALLBACK_PATH;
    if (::access(hackc.data(), X_OK) != 0) {
      return "";
    }

  }

  return folly::sformat( "{} {}", hackc, hackCompilerArgsDefault()


  );

}

static inline bool enableGcDefault() {
  return RuntimeOption::EvalEagerGC || one_bit_refcount;
}

static inline uint64_t pgoThresholdDefault() {
  return debug ? 2 : 2000;
}

static inline bool alignMacroFusionPairs() {
  switch (getProcessorFamily()) {
    case ProcessorFamily::Intel_SandyBridge:
    case ProcessorFamily::Intel_IvyBridge:
    case ProcessorFamily::Intel_Haswell:
    case ProcessorFamily::Intel_Broadwell:
    case ProcessorFamily::Intel_Skylake:
    case ProcessorFamily::Intel_Cooperlake:
      return true;
    case ProcessorFamily::Unknown:
      return false;
  }
  return false;
}

static inline bool armLseDefault() {

  return (getauxval(AT_HWCAP) & HWCAP_ATOMICS) != 0;

  return false;

}

static inline bool evalJitDefault() {

  return false;

  return true;

}

static inline bool reuseTCDefault() {
  return hhvm_reuse_tc && !RuntimeOption::RepoAuthoritative;
}

static inline bool useFileBackedArenaDefault() {
  return RuntimeOption::RepoAuthoritative && RuntimeOption::ServerExecutionMode();
}

static inline bool hugePagesSoundNice() {
  return RuntimeOption::ServerExecutionMode();
}

static inline uint32_t hotTextHugePagesDefault() {
  if (!hugePagesSoundNice()) return 0;
  return arch() == Arch::ARM ? 12 : 8;
}

static inline std::string reorderPropsDefault() {
  if (isJitDeserializing()) {
    return "countedness-hotness";
  }
  return debug ? "alphabetical" : "countedness";
}

static inline uint32_t profileRequestsDefault() {
  return debug ? std::numeric_limits<uint32_t>::max() : 2500;
}

static inline uint32_t profileBCSizeDefault() {
  return debug ? std::numeric_limits<uint32_t>::max()
    : RuntimeOption::EvalJitConcurrently ? 3750000 : 4300000;
}

static inline uint32_t resetProfCountersDefault() {
  return RuntimeOption::EvalJitPGORacyProfiling ? std::numeric_limits<uint32_t>::max()
    : RuntimeOption::EvalJitConcurrently ? 250 : 1000;
}

static inline int retranslateAllRequestDefault() {
  return RuntimeOption::ServerExecutionMode() ? 1000000 : 0;
}

static inline int retranslateAllSecondsDefault() {
  return RuntimeOption::ServerExecutionMode() ? 180 : 0;
}

static inline bool pgoLayoutSplitHotColdDefault() {
  return arch() != Arch::ARM;
}

static inline bool layoutPrologueSplitHotColdDefault() {
  return arch() != Arch::ARM;
}

uint64_t ahotDefault() {
  return RuntimeOption::RepoAuthoritative ? 4 << 20 : 0;
}

folly::Optional<folly::fs::path> RuntimeOption::GetHomePath( const folly::StringPiece user) {

  auto homePath = folly::fs::path{RuntimeOption::SandboxHome}
    / folly::fs::path{user};
  if (folly::fs::is_directory(homePath)) {
    return {std::move(homePath)};
  }

  if (!RuntimeOption::SandboxFallback.empty()) {
    homePath = folly::fs::path{RuntimeOption::SandboxFallback}
      / folly::fs::path{user};
    if (folly::fs::is_directory(homePath)) {
      return {std::move(homePath)};
    }
  }

  return {};
}

std::string RuntimeOption::GetDefaultUser() {
  if (SandboxDefaultUserFile.empty()) return {};

  folly::fs::path file{SandboxDefaultUserFile};
  if (!folly::fs::is_regular_file(file)) return {};

  std::string user;
  if (!folly::readFile(file.c_str(), user) || user.empty()) return {};

  return user;
}

bool RuntimeOption::ReadPerUserSettings(const folly::fs::path& confFileName, IniSettingMap& ini, Hdf& config) {
  try {
    Config::ParseConfigFile(confFileName.native(), ini, config, false);
    return true;
  } catch (HdfException& e) {
    Logger::Error("%s ignored: %s", confFileName.native().c_str(), e.getMessage().c_str());
    return false;
  }
}

std::string RuntimeOption::getTraceOutputFile() {
  return folly::sformat("{}/hphp.{}.log", RuntimeOption::RemoteTraceOutputDir, (int64_t)getpid());
}

const uint64_t kEvalVMStackElmsDefault =  0x800  0x4000  ;






constexpr uint32_t kEvalVMInitialGlobalTableSizeDefault = 512;
constexpr uint64_t kJitRelocationSizeDefault = 1 << 20;

static const bool kJitTimerDefault =  true  false  ;






using std::string;

EVALFLAGS();

hphp_string_imap<TypedValue> RuntimeOption::ConstantFunctions;

bool RuntimeOption::RecordCodeCoverage = false;
std::string RuntimeOption::CodeCoverageOutputFile;

RepoMode RuntimeOption::RepoLocalMode = RepoMode::ReadOnly;
std::string RuntimeOption::RepoLocalPath;
RepoMode RuntimeOption::RepoCentralMode = RepoMode::ReadWrite;
std::string RuntimeOption::RepoCentralPath;
int32_t RuntimeOption::RepoCentralFileMode;
std::string RuntimeOption::RepoCentralFileUser;
std::string RuntimeOption::RepoCentralFileGroup;
std::string RuntimeOption::RepoJournal = "delete";
bool RuntimeOption::RepoAllowFallbackPath = true;
bool RuntimeOption::RepoCommit = true;
bool RuntimeOption::RepoDebugInfo = true;
bool RuntimeOption::RepoLitstrLazyLoad = true;


bool RuntimeOption::RepoLocalReadaheadConcurrent = false;
int64_t RuntimeOption::RepoLocalReadaheadRate = 0;
uint32_t RuntimeOption::RepoBusyTimeoutMS = 15000;

bool RuntimeOption::HHProfEnabled = false;
bool RuntimeOption::HHProfActive = false;
bool RuntimeOption::HHProfAccum = false;
bool RuntimeOption::HHProfRequest = false;

bool RuntimeOption::SandboxMode = false;
std::string RuntimeOption::SandboxPattern;
std::string RuntimeOption::SandboxHome;
std::string RuntimeOption::SandboxFallback;
std::string RuntimeOption::SandboxConfFile;
std::map<std::string, std::string> RuntimeOption::SandboxServerVariables;
bool RuntimeOption::SandboxFromCommonRoot = false;
std::string RuntimeOption::SandboxDirectoriesRoot;
std::string RuntimeOption::SandboxLogsRoot;
std::string RuntimeOption::SandboxDefaultUserFile;
std::string RuntimeOption::SandboxHostAlias;

bool RuntimeOption::EnableHphpdDebugger = false;
bool RuntimeOption::EnableVSDebugger = false;
int RuntimeOption::VSDebuggerListenPort = -1;
std::string RuntimeOption::VSDebuggerDomainSocketPath;
bool RuntimeOption::VSDebuggerNoWait = false;
bool RuntimeOption::EnableDebuggerColor = true;
bool RuntimeOption::EnableDebuggerPrompt = true;
bool RuntimeOption::EnableDebuggerServer = false;
bool RuntimeOption::EnableDebuggerUsageLog = false;
bool RuntimeOption::DebuggerDisableIPv6 = false;
std::string RuntimeOption::DebuggerServerIP;
int RuntimeOption::DebuggerServerPort = 8089;
int RuntimeOption::DebuggerDefaultRpcPort = 8083;
std::string RuntimeOption::DebuggerDefaultRpcAuth;
std::string RuntimeOption::DebuggerRpcHostDomain;
int RuntimeOption::DebuggerDefaultRpcTimeout = 30;
std::string RuntimeOption::DebuggerDefaultSandboxPath;
std::string RuntimeOption::DebuggerStartupDocument;
int RuntimeOption::DebuggerSignalTimeout = 1;
std::string RuntimeOption::DebuggerAuthTokenScriptBin;
std::string RuntimeOption::DebuggerSessionAuthScriptBin;

std::string RuntimeOption::SendmailPath = "sendmail -t -i";
std::string RuntimeOption::MailForceExtraParameters;

int64_t RuntimeOption::PregBacktraceLimit = 1000000;
int64_t RuntimeOption::PregRecursionLimit = 100000;
bool RuntimeOption::EnablePregErrorLog = true;

bool RuntimeOption::SimpleXMLEmptyNamespaceMatchesAll = false;

bool RuntimeOption::AllowDuplicateCookies = true;

bool RuntimeOption::EnableHotProfiler = true;
int RuntimeOption::ProfilerTraceBuffer = 2000000;
double RuntimeOption::ProfilerTraceExpansion = 1.2;
int RuntimeOption::ProfilerMaxTraceBuffer = 0;


bool RuntimeOption::EnableFb303Server = false;
int RuntimeOption::Fb303ServerPort = 0;
std::string RuntimeOption::Fb303ServerIP;
int RuntimeOption::Fb303ServerThreadStackSizeMb = 8;
int RuntimeOption::Fb303ServerWorkerThreads = 1;
int RuntimeOption::Fb303ServerPoolThreads = 1;


double RuntimeOption::XenonPeriodSeconds = 0.0;
uint32_t RuntimeOption::XenonRequestFreq = 1;
bool RuntimeOption::XenonForceAlwaysOn = false;

bool RuntimeOption::StrobelightEnabled = false;

bool RuntimeOption::TrackPerUnitMemory = false;

bool RuntimeOption::SetProfileNullThisObject = true;

std::map<std::string, std::string> RuntimeOption::CustomSettings;


  #ifdef ALWAYS_ASSERT
    const StaticString s_hhvm_build_type("Release with asserts");
  #else
    const StaticString s_hhvm_build_type("Release");
  #endif

  const StaticString s_hhvm_build_type("Debug");




static void setResourceLimit(int resource, const IniSetting::Map& ini, const Hdf& rlimit, const char* nodeName) {
  if (!Config::GetString(ini, rlimit, nodeName).empty()) {
    struct rlimit rl;
    getrlimit(resource, &rl);
    rl.rlim_cur = Config::GetInt64(ini, rlimit, nodeName);
    if (rl.rlim_max < rl.rlim_cur) {
      rl.rlim_max = rl.rlim_cur;
    }
    int ret = setrlimit(resource, &rl);
    if (ret) {
      Logger::Error("Unable to set %s to %" PRId64 ": %s (%d)", nodeName, (int64_t)rl.rlim_cur, folly::errnoStr(errno).c_str(), errno);

    }
  }
}

static void normalizePath(std::string &path) {
  if (!path.empty()) {
    if (path[path.length() - 1] == '/') {
      path = path.substr(0, path.length() - 1);
    }
    if (path[0] != '/') {
      path = std::string("/") + path;
    }
  }
}

static String todayDate() {
  time_t rawtime;
  struct tm timeinfo;
  char buf[256];
  time(&rawtime);
  localtime_r(&rawtime, &timeinfo);
  strftime(buf, sizeof(buf), "%Y-%m-%d", &timeinfo);
  return buf;
}

static bool matchShard( const std::string& hostname, const IniSetting::Map& ini, Hdf hdfPattern, std::vector<std::string>& messages ) {



  if (!hdfPattern.exists("Shard")) return true;
  auto const shard = Config::GetInt64(ini, hdfPattern, "Shard", -1, false);

  auto const nshards = Config::GetInt64(ini, hdfPattern, "ShardCount", 100, false);

  if (shard < 0 || shard >= nshards) {
    messages.push_back(folly::sformat("Invalid value for Shard: {}", shard));
    return true;
  }

  auto input = hostname;
  if (hdfPattern.exists("ShardSalt")) {
    auto salt = Config::GetString(ini, hdfPattern, "ShardSalt", "", false);
    salt = string_replace(salt, "%{date}", todayDate()).toCppString();
    input += salt;
  }

  auto const md5 = Md5Digest(input.data(), input.size());
  uint32_t seed{0};
  memcpy(&seed, &md5.digest[0], 4);

  
  
  
  seed = ntohl(seed) >> 4;

  messages.push_back(folly::sformat( "Checking Shard = {}; Input = {}; Seed = {}; ShardCount = {}; Value = {}", shard, input, seed, nshards, seed % nshards ));



  return seed % nshards <= shard;
}





static std::vector<std::string> getTierOverwrites(IniSetting::Map& ini, Hdf& config) {

  
  string hostname, tier, task, cpu, tiers, tags;
  {
    hostname = Config::GetString(ini, config, "Machine.name");
    if (hostname.empty()) {
      hostname = Process::GetHostName();
    }

    tier = Config::GetString(ini, config, "Machine.tier");

    task = Config::GetString(ini, config, "Machine.task");

    cpu = Config::GetString(ini, config, "Machine.cpu");
    if (cpu.empty()) {
      cpu = Process::GetCPUModel();
    }

    tiers = Config::GetString(ini, config, "Machine.tiers");
    if (!tiers.empty()) {
      if (!folly::readFile(tiers.c_str(), tiers)) {
        tiers.clear();
      }
    }

    tags = Config::GetString(ini, config, "Machine.tags");
    if (!tags.empty()) {
      if (!folly::readFile(tags.c_str(), tags)) {
        tags.clear();
      }
    }
  }

  auto const checkPatterns = [&] (Hdf hdf) {
    
    
    
    return Config::matchHdfPattern(hostname, ini, hdf, "machine") & Config::matchHdfPattern(tier, ini, hdf, "tier") & Config::matchHdfPattern(task, ini, hdf, "task") & Config::matchHdfPattern(tiers, ini, hdf, "tiers", "m") & Config::matchHdfPattern(tags, ini, hdf, "tags", "m") & Config::matchHdfPattern(cpu, ini, hdf, "cpu");





  };

  std::vector<std::string> messages;
  
  {
    for (Hdf hdf = config["Tiers"].firstChild(); hdf.exists();
         hdf = hdf.next()) {
      if (messages.empty()) {
        messages.emplace_back(folly::sformat( "Matching tiers using: " "machine='{}', tier='{}', task='{}', " "cpu='{}', tiers='{}', tags='{}'", hostname, tier, task, cpu, tiers, tags));



      }
      
      
      
      if (checkPatterns(hdf) & (!hdf.exists("exclude") || !checkPatterns(hdf["exclude"])) & matchShard(hostname, ini, hdf, messages)) {

        messages.emplace_back(folly::sformat( "Matched tier: {}", hdf.getName()));
        if (hdf.exists("clear")) {
          std::vector<std::string> list;
          hdf["clear"].configGet(list);
          for (auto const& s : list) {
            config.remove(s);
          }
        }
        config.copy(hdf["overwrite"]);
        
      }
      hdf["overwrite"].setVisited(); 
      if (hdf.exists("clear")) {
        
        
        hdf["clear"].setVisited();
      }
    }
  }
  return messages;
}

void RuntimeOption::ReadSatelliteInfo( const IniSettingMap& ini, const Hdf& hdf, std::vector<std::shared_ptr<SatelliteServerInfo>>& infos, std::string& xboxPassword, std::set<std::string>& xboxPasswords) {




  auto ss_callback = [&] (const IniSettingMap &ini_ss, const Hdf &hdf_ss, const std::string &ini_ss_key) {
    auto satellite = std::make_shared<SatelliteServerInfo>(ini_ss, hdf_ss, ini_ss_key);
    infos.push_back(satellite);
    if (satellite->getType() == SatelliteServer::Type::KindOfRPCServer) {
      xboxPassword = satellite->getPassword();
      xboxPasswords = satellite->getPasswords();
    }
  };
  Config::Iterate(ss_callback, ini, hdf, "Satellites");
}

extern void initialize_apc();
void RuntimeOption::Load( IniSetting::Map& ini, Hdf& config, const std::vector<std::string>& iniClis , const std::vector<std::string>& hdfClis , std::vector<std::string>* messages , std::string cmd ) {




  ARRPROV_USE_RUNTIME_LOCATION_FORCE();

  
  
  tl_heap.getCheck();

  
  
  
  
  
  for (auto& istr : iniClis) {
    Config::ParseIniString(istr, ini);
  }
  for (auto& hstr : hdfClis) {
    Config::ParseHdfString(hstr, config);
  }

  
  auto m = getTierOverwrites(ini, config);
  if (messages) *messages = std::move(m);

  
  
  
  
  
  
  
  
  
  std::string relConfigsError;
  Config::Bind(s_RelativeConfigs, ini, config, "RelativeConfigs");
  if (!cmd.empty() && !s_RelativeConfigs.empty()) {
    String strcmd(cmd, CopyString);
    Process::InitProcessStatics();
    auto const currentDir = Process::CurrentWorkingDirectory.data();
    std::vector<std::string> newConfigs;
    auto const original = s_RelativeConfigs;
    for (auto& str : original) {
      if (str.empty()) continue;

      std::string fullpath;
      auto const found = FileUtil::runRelative( str, strcmd, currentDir, [&] (const String& f) {

          if (access(f.data(), R_OK) == 0) {
            fullpath = f.toCppString();
            FTRACE_MOD(Trace::watchman_autoload, 3, "Parsing {}\n", fullpath);
            Config::ParseConfigFile(fullpath, ini, config);
            return true;
          }
          return false;
        }
      );
      if (found) newConfigs.emplace_back(std::move(fullpath));
    }
    if (!newConfigs.empty()) {
      auto m2 = getTierOverwrites(ini, config);
      if (messages) *messages = std::move(m2);
      if (s_RelativeConfigs != original) {
        relConfigsError = folly::sformat( "RelativeConfigs node was modified while loading configs from [{}] " "to [{}]", folly::join(", ", original), folly::join(", ", s_RelativeConfigs)



        );
      }
    }
    s_RelativeConfigs.swap(newConfigs);
  } else {
    s_RelativeConfigs.clear();
  }

  
  
  
  
  
  for (auto& istr : iniClis) {
    Config::ParseIniString(istr, ini);
  }
  for (auto& hstr : hdfClis) {
    Config::ParseHdfString(hstr, config);
  }

  Config::Bind(PidFile, ini, config, "PidFile", "www.pid");
  Config::Bind(DeploymentId, ini, config, "DeploymentId");

  {
    static std::string deploymentIdOverride;
    Config::Bind(deploymentIdOverride, ini, config, "DeploymentIdOverride");
    if (!deploymentIdOverride.empty()) {
      RuntimeOption::DeploymentId = deploymentIdOverride;
    }
  }

  {
    
    Config::Bind(ConfigId, ini, config, "ConfigId", 0);
    auto configIdCounter = ServiceData::createCounter("vm.config.id");
    configIdCounter->setValue(ConfigId);
  }

  {
    
    auto setLogLevel = [](const std::string& value) {
      
      if (value == "None" || value == "") {
        Logger::LogLevel = Logger::LogNone;
      } else if (value == "Error") {
        Logger::LogLevel = Logger::LogError;
      } else if (value == "Warning") {
        Logger::LogLevel = Logger::LogWarning;
      } else if (value == "Info") {
        Logger::LogLevel = Logger::LogInfo;
      } else if (value == "Verbose") {
        Logger::LogLevel = Logger::LogVerbose;
      } else {
        return false;
      }
      return true;
    };
    auto str = Config::GetString(ini, config, "Log.Level");
    if (!str.empty()) {
      setLogLevel(str);
    }
    IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_SYSTEM, "hhvm.log.level", IniSetting::SetAndGet<std::string>( setLogLevel, []() {


        switch (Logger::LogLevel) {
          case Logger::LogNone:
            return "None";
          case Logger::LogError:
            return "Error";
          case Logger::LogWarning:
            return "Warning";
          case Logger::LogInfo:
            return "Info";
          case Logger::LogVerbose:
            return "Verbose";
        }
        return "";
      }
    ));

    Config::Bind(Logger::UseLogFile, ini, config, "Log.UseLogFile", true);
    Config::Bind(LogFile, ini, config, "Log.File");
    Config::Bind(LogFileSymLink, ini, config, "Log.SymLink");
    Config::Bind(LogFilePeriodMultiplier, ini, config, "Log.PeriodMultiplier", 0);
    if (Logger::UseLogFile && RuntimeOption::ServerExecutionMode()) {
      RuntimeOption::ErrorLogs[Logger::DEFAULT] = ErrorLogFileData(LogFile, LogFileSymLink, LogFilePeriodMultiplier);
    }
    if (Config::GetBool(ini, config, "Log.AlwaysPrintStackTraces")) {
      Logger::SetTheLogger(Logger::DEFAULT, new ExtendedLogger());
      ExtendedLogger::EnabledByDefault = true;
    }

    Config::Bind(Logger::LogHeader, ini, config, "Log.Header");
    Config::Bind(Logger::LogNativeStackTrace, ini, config, "Log.NativeStackTrace", true);
    Config::Bind(Logger::UseSyslog, ini, config, "Log.UseSyslog", false);
    Config::Bind(Logger::UseRequestLog, ini, config, "Log.UseRequestLog", false);
    Config::Bind(Logger::AlwaysEscapeLog, ini, config, "Log.AlwaysEscapeLog", true);
    Config::Bind(Logger::UseCronolog, ini, config, "Log.UseCronolog", false);
    Config::Bind(Logger::MaxMessagesPerRequest, ini, config, "Log.MaxMessagesPerRequest", -1);
    Config::Bind(LogFileFlusher::DropCacheChunkSize, ini, config, "Log.DropCacheChunkSize", 1 << 20);
    Config::Bind(RuntimeOption::LogHeaderMangle, ini, config, "Log.HeaderMangle", 0);
    Config::Bind(AlwaysLogUnhandledExceptions, ini, config, "Log.AlwaysLogUnhandledExceptions", true);

    Config::Bind(NoSilencer, ini, config, "Log.NoSilencer");
    Config::Bind(RuntimeErrorReportingLevel, ini, config, "Log.RuntimeErrorReportingLevel", static_cast<int>(ErrorMode::HPHP_ALL));

    Config::Bind(ForceErrorReportingLevel, ini, config, "Log.ForceErrorReportingLevel", 0);
    Config::Bind(AccessLogDefaultFormat, ini, config, "Log.AccessLogDefaultFormat", "%h %l %u %t \"%r\" %>s %b");

    auto parseLogs = [] (const Hdf &config, const IniSetting::Map& ini, const std::string &name, std::map<std::string, AccessLogFileData> &logs) {

      auto parse_logs_callback = [&] (const IniSetting::Map &ini_pl, const Hdf &hdf_pl, const std::string &ini_pl_key) {

        string logName = hdf_pl.exists() && !hdf_pl.isEmpty()
                       ? hdf_pl.getName()
                       : ini_pl_key;
        string fname = Config::GetString(ini_pl, hdf_pl, "File", "", false);
        if (!fname.empty()) {
          string symlink = Config::GetString(ini_pl, hdf_pl, "SymLink", "", false);
          string format = Config::GetString(ini_pl, hdf_pl, "Format", AccessLogDefaultFormat, false);
          auto periodMultiplier = Config::GetUInt16(ini_pl, hdf_pl, "PeriodMultiplier", 0, false);

          logs[logName] = AccessLogFileData(fname, symlink, format, periodMultiplier);


        }
      };
      Config::Iterate(parse_logs_callback, ini, config, name);
    };

    parseLogs(config, ini, "Log.Access", AccessLogs);
    RPCLogs = AccessLogs;
    parseLogs(config, ini, "Log.RPC", RPCLogs);

    Config::Bind(AdminLogFormat, ini, config, "Log.AdminLog.Format", "%h %t %s %U");
    Config::Bind(AdminLogFile, ini, config, "Log.AdminLog.File");
    Config::Bind(AdminLogSymLink, ini, config, "Log.AdminLog.SymLink");
  }
  {
    

    Config::Bind(ErrorUpgradeLevel, ini, config, "ErrorHandling.UpgradeLevel", 0);
    Config::Bind(MaxSerializedStringSize, ini, config, "ErrorHandling.MaxSerializedStringSize", 64 * 1024 * 1024);

    Config::Bind(CallUserHandlerOnFatals, ini, config, "ErrorHandling.CallUserHandlerOnFatals", false);
    Config::Bind(ThrowExceptionOnBadMethodCall, ini, config, "ErrorHandling.ThrowExceptionOnBadMethodCall", true);
    Config::Bind(LogNativeStackOnOOM, ini, config, "ErrorHandling.LogNativeStackOnOOM", false);
    Config::Bind(NoInfiniteRecursionDetection, ini, config, "ErrorHandling.NoInfiniteRecursionDetection");
    Config::Bind(NoticeFrequency, ini, config, "ErrorHandling.NoticeFrequency", 1);
    Config::Bind(WarningFrequency, ini, config, "ErrorHandling.WarningFrequency", 1);
  }

  
  
  if (!relConfigsError.empty()) Logger::Error(relConfigsError);

  {
    if (Config::GetInt64(ini, config, "ResourceLimit.CoreFileSizeOverride")) {
      setResourceLimit(RLIMIT_CORE, ini,  config, "ResourceLimit.CoreFileSizeOverride");
    } else {
      setResourceLimit(RLIMIT_CORE, ini, config, "ResourceLimit.CoreFileSize");
    }
    setResourceLimit(RLIMIT_NOFILE, ini, config, "ResourceLimit.MaxSocket");
    setResourceLimit(RLIMIT_DATA, ini, config, "ResourceLimit.RSS");
    
    
    
    static int64_t s_core_file_size_override, s_core_file_size, s_rss = 0;
    static int32_t s_max_socket = 0;
    Config::Bind(s_core_file_size_override, ini, config, "ResourceLimit.CoreFileSizeOverride", 0);
    Config::Bind(s_core_file_size, ini, config, "ResourceLimit.CoreFileSize", 0);
    Config::Bind(s_max_socket, ini, config, "ResourceLimit.MaxSocket", 0);
    Config::Bind(s_rss, ini, config, "ResourceLimit.RSS", 0);

    Config::Bind(SocketDefaultTimeout, ini, config, "ResourceLimit.SocketDefaultTimeout", 60);
    Config::Bind(MaxSQLRowCount, ini, config, "ResourceLimit.MaxSQLRowCount", 0);
    Config::Bind(SerializationSizeLimit, ini, config, "ResourceLimit.SerializationSizeLimit", StringData::MaxSize);
    Config::Bind(HeapSizeMB, ini, config, "ResourceLimit.HeapSizeMB", HeapSizeMB);
    Config::Bind(HeapResetCountBase, ini, config, "ResourceLimit.HeapResetCountBase", HeapResetCountBase);
    Config::Bind(HeapResetCountMultiple, ini, config, "ResourceLimit.HeapResetCountMultiple", HeapResetCountMultiple);

    Config::Bind(HeapLowWaterMark , ini, config, "ResourceLimit.HeapLowWaterMark", HeapLowWaterMark);
    Config::Bind(HeapHighWaterMark , ini, config, "ResourceLimit.HeapHighWaterMark",HeapHighWaterMark);
  }
  {
    
    Config::Bind(DisableCallUserFunc, ini, config, "Hack.Lang.Phpism.DisableCallUserFunc", DisableCallUserFunc);

    Config::Bind(DisableCallUserFuncArray, ini, config, "Hack.Lang.Phpism.DisableCallUserFuncArray", DisableCallUserFuncArray);

    Config::Bind(DisableAssert, ini, config, "Hack.Lang.Phpism.DisableAssert", DisableAssert);

    Config::Bind(DisableNontoplevelDeclarations, ini, config, "Hack.Lang.Phpism.DisableNontoplevelDeclarations", DisableNontoplevelDeclarations);

    Config::Bind(DisableStaticClosures, ini, config, "Hack.Lang.Phpism.DisableStaticClosures", DisableStaticClosures);

    Config::Bind(DisableConstant, ini, config, "Hack.Lang.Phpism.DisableConstant", DisableConstant);

  }
  {
    
    auto repoModeToStr = [](RepoMode mode) {
      switch (mode) {
        case RepoMode::Closed:
          return "--";
        case RepoMode::ReadOnly:
          return "r-";
        case RepoMode::ReadWrite:
          return "rw";
      }

      always_assert(false);
      return "";
    };

    auto parseRepoMode = [&](const std::string& repoModeStr, const char* type, RepoMode defaultMode) {
      if (repoModeStr.empty()) {
        return defaultMode;
      }
      if (repoModeStr == "--") {
        return RepoMode::Closed;
      }
      if (repoModeStr == "r-") {
        return RepoMode::ReadOnly;
      }
      if (repoModeStr == "rw") {
        return RepoMode::ReadWrite;
      }

      Logger::Error("Bad config setting: Repo.%s.Mode=%s", type, repoModeStr.c_str());
      return RepoMode::ReadWrite;
    };

    
    static std::string repoLocalMode;
    Config::Bind(repoLocalMode, ini, config, "Repo.Local.Mode", repoModeToStr(RepoLocalMode));
    RepoLocalMode = parseRepoMode(repoLocalMode, "Local", RepoMode::ReadOnly);

    
    Config::Bind(RepoLocalPath, ini, config, "Repo.Local.Path");
    if (RepoLocalPath.empty()) {
      const char* HHVM_REPO_LOCAL_PATH = getenv("HHVM_REPO_LOCAL_PATH");
      if (HHVM_REPO_LOCAL_PATH != nullptr) {
        RepoLocalPath = HHVM_REPO_LOCAL_PATH;
      }
    }

    
    static std::string repoCentralMode;
    Config::Bind(repoCentralMode, ini, config, "Repo.Central.Mode", repoModeToStr(RepoCentralMode));
    RepoCentralMode = parseRepoMode(repoCentralMode, "Central", RepoMode::ReadWrite);

    
    Config::Bind(RepoCentralPath, ini, config, "Repo.Central.Path");
    Config::Bind(RepoCentralFileMode, ini, config, "Repo.Central.FileMode");
    Config::Bind(RepoCentralFileUser, ini, config, "Repo.Central.FileUser");
    Config::Bind(RepoCentralFileGroup, ini, config, "Repo.Central.FileGroup");

    Config::Bind(RepoAllowFallbackPath, ini, config, "Repo.AllowFallbackPath", RepoAllowFallbackPath);

    replacePlaceholders(RepoLocalPath);
    replacePlaceholders(RepoCentralPath);

    Config::Bind(RepoJournal, ini, config, "Repo.Journal", RepoJournal);
    Config::Bind(RepoCommit, ini, config, "Repo.Commit", RepoCommit);
    Config::Bind(RepoDebugInfo, ini, config, "Repo.DebugInfo", RepoDebugInfo);
    Config::Bind(RepoLitstrLazyLoad, ini, config, "Repo.LitstrLazyLoad", RepoLitstrLazyLoad);
    Config::Bind(RepoAuthoritative, ini, config, "Repo.Authoritative", RepoAuthoritative);
    Config::Bind(RepoLocalReadaheadRate, ini, config, "Repo.LocalReadaheadRate", 0);
    Config::Bind(RepoLocalReadaheadConcurrent, ini, config, "Repo.LocalReadaheadConcurrent", false);
    Config::Bind(RepoBusyTimeoutMS, ini, config, "Repo.BusyTimeoutMS", RepoBusyTimeoutMS);
  }

  if (use_jemalloc) {
    
    Config::Bind(HHProfEnabled, ini, config, "HHProf.Enabled", false);
    Config::Bind(HHProfActive, ini, config, "HHProf.Active", false);
    Config::Bind(HHProfAccum, ini, config, "HHProf.Accum", false);
    Config::Bind(HHProfRequest, ini, config, "HHProf.Request", false);
  }
  {
    
    Config::Bind(EnableHipHopSyntax, ini, config, "Eval.EnableHipHopSyntax", EnableHipHopSyntax);
    Config::Bind(EnableShortTags, ini, config, "Eval.EnableShortTags", true);
    Config::Bind(EnableXHP, ini, config, "Eval.EnableXHP", EnableXHP);
    Config::Bind(TimeoutsUseWallTime, ini, config, "Eval.TimeoutsUseWallTime", true);
    Config::Bind(CheckFlushOnUserClose, ini, config, "Eval.CheckFlushOnUserClose", true);
    Config::Bind(EvalInitialNamedEntityTableSize, ini, config, "Eval.InitialNamedEntityTableSize", EvalInitialNamedEntityTableSize);

    Config::Bind(EvalInitialStaticStringTableSize, ini, config, "Eval.InitialStaticStringTableSize", EvalInitialStaticStringTableSize);


    static std::string jitSerdesMode;
    Config::Bind(jitSerdesMode, ini, config, "Eval.JitSerdesMode", "Off");

    EvalJitSerdesMode = [&] {
      #define X(x) if (jitSerdesMode == #x) return JitSerdesMode::x
      X(Serialize);
      X(SerializeAndExit);
      X(Deserialize);
      X(DeserializeOrFail);
      X(DeserializeOrGenerate);
      X(DeserializeAndDelete);
      X(DeserializeAndExit);
      #undef X
      return JitSerdesMode::Off;
    }();
    Config::Bind(EvalJitSerdesFile, ini, config, "Eval.JitSerdesFile", EvalJitSerdesFile);
    
    
    
    
    
    
    
    auto const couldDump = !EvalJitSerdesFile.empty() && (isJitSerializing() || (EvalJitSerdesMode == JitSerdesMode::DeserializeOrGenerate));

    Config::Bind(DumpPreciseProfData, ini, config, "Eval.DumpPreciseProfData", couldDump);
    Config::Bind(ProfDataTTLHours, ini, config, "Eval.ProfDataTTLHours", ProfDataTTLHours);
    Config::Bind(ProfDataTag, ini, config, "Eval.ProfDataTag", ProfDataTag);

    Config::Bind(CheckSymLink, ini, config, "Eval.CheckSymLink", true);
    Config::Bind(TrustAutoloaderPath, ini, config, "Eval.TrustAutoloaderPath", false);


    EVALFLAGS()


    if (EvalJitSerdesModeForceOff) EvalJitSerdesMode = JitSerdesMode::Off;
    if (!EvalEnableReusableTC) EvalReusableTCPadding = 0;
    if (numa_num_nodes <= 1) {
      EvalEnableNuma = false;
    }

    Config::Bind(ServerForkEnabled, ini, config, "Server.Forking.Enabled", ServerForkEnabled);
    Config::Bind(ServerForkLogging, ini, config, "Server.Forking.LogForkAttempts", ServerForkLogging);
    if (!ServerForkEnabled && ServerExecutionMode()) {
      
      low_2m_pages(EvalMaxLowMemHugePages);
      high_2m_pages(EvalMaxHighArenaHugePages);
    }
    s_enable_static_arena = Config::GetBool(ini, config, "Eval.UseTLStaticArena", true);

    replacePlaceholders(EvalHackCompilerExtractPath);
    replacePlaceholders(EvalHackCompilerFallbackPath);
    replacePlaceholders(EvalEmbeddedDataExtractPath);
    replacePlaceholders(EvalEmbeddedDataFallbackPath);

    if (!jit::mcgen::retranslateAllEnabled()) {
      EvalJitWorkerThreads = 0;
      if (EvalJitSerdesMode != JitSerdesMode::Off) {
        if (ServerMode) {
          Logger::Warning("Eval.JitSerdesMode reset from " + jitSerdesMode + " to off, becasue JitRetranslateAll isn't enabled.");
        }
        EvalJitSerdesMode = JitSerdesMode::Off;
      }
      EvalJitSerdesFile.clear();
      DumpPreciseProfData = false;
    }
    EvalJitPGOUseAddrCountedCheck &= addr_encodes_persistency;
    HardwareCounter::Init(EvalProfileHWEnable, url_decode(EvalProfileHWEvents.data(), EvalProfileHWEvents.size()).toCppString(), false, EvalProfileHWExcludeKernel, EvalProfileHWFastReads, EvalProfileHWExportInterval);






    Config::Bind(EnableIntrinsicsExtension, ini, config, "Eval.EnableIntrinsicsExtension", EnableIntrinsicsExtension);

    Config::Bind(RecordCodeCoverage, ini, config, "Eval.RecordCodeCoverage");
    if (EvalJit && RecordCodeCoverage) {
      throw std::runtime_error("Code coverage is not supported with " "Eval.Jit=true");
    }
    Config::Bind(DisableSmallAllocator, ini, config, "Eval.DisableSmallAllocator", DisableSmallAllocator);
    SetArenaSlabAllocBypass(DisableSmallAllocator);
    EvalSlabAllocAlign = folly::nextPowTwo(EvalSlabAllocAlign);
    EvalSlabAllocAlign = std::min(EvalSlabAllocAlign, decltype(EvalSlabAllocAlign){4096});

    if (RecordCodeCoverage) CheckSymLink = true;
    Config::Bind(CodeCoverageOutputFile, ini, config, "Eval.CodeCoverageOutputFile");
    
    Config::Bind(EnableArgsInBacktraces, ini, config, "Eval.EnableArgsInBacktraces", !RepoAuthoritative);
    Config::Bind(EvalAuthoritativeMode, ini, config, "Eval.AuthoritativeMode", false);

    Config::Bind(CheckCLIClientCommands, ini, config, "Eval.CheckCLIClientCommands", 1);
    if (RepoAuthoritative) {
      EvalAuthoritativeMode = true;
    }
    {
      
      Config::Bind(EnableHphpdDebugger, ini, config, "Eval.Debugger.EnableDebugger");
      Config::Bind(EnableDebuggerColor, ini, config, "Eval.Debugger.EnableDebuggerColor", true);
      Config::Bind(EnableDebuggerPrompt, ini, config, "Eval.Debugger.EnableDebuggerPrompt", true);
      Config::Bind(EnableDebuggerServer, ini, config, "Eval.Debugger.EnableDebuggerServer");
      Config::Bind(EnableDebuggerUsageLog, ini, config, "Eval.Debugger.EnableDebuggerUsageLog");
      Config::Bind(DebuggerServerIP, ini, config, "Eval.Debugger.IP");
      Config::Bind(DebuggerServerPort, ini, config, "Eval.Debugger.Port", 8089);
      Config::Bind(DebuggerDisableIPv6, ini, config, "Eval.Debugger.DisableIPv6", false);
      Config::Bind(DebuggerDefaultSandboxPath, ini, config, "Eval.Debugger.DefaultSandboxPath");
      Config::Bind(DebuggerStartupDocument, ini, config, "Eval.Debugger.StartupDocument");
      Config::Bind(DebuggerSignalTimeout, ini, config, "Eval.Debugger.SignalTimeout", 1);
      Config::Bind(DebuggerDefaultRpcPort, ini, config, "Eval.Debugger.RPC.DefaultPort", 8083);
      DebuggerDefaultRpcAuth = Config::GetString(ini, config, "Eval.Debugger.RPC.DefaultAuth");
      Config::Bind(DebuggerRpcHostDomain, ini, config, "Eval.Debugger.RPC.HostDomain");
      Config::Bind(DebuggerDefaultRpcTimeout, ini, config, "Eval.Debugger.RPC.DefaultTimeout", 30);
      Config::Bind(DebuggerAuthTokenScriptBin, ini, config, "Eval.Debugger.Auth.TokenScriptBin");
      Config::Bind(DebuggerSessionAuthScriptBin, ini, config, "Eval.Debugger.Auth.SessionAuthScriptBin");
    }
  }
  {
    
    using jit::CodeCache;
    Config::Bind(CodeCache::AHotSize, ini, config, "Eval.JitAHotSize", ahotDefault());
    Config::Bind(CodeCache::ASize, ini, config, "Eval.JitASize", 60 << 20);
    Config::Bind(CodeCache::AProfSize, ini, config, "Eval.JitAProfSize", RuntimeOption::EvalJitPGO ? (64 << 20) : 0);
    Config::Bind(CodeCache::AColdSize, ini, config, "Eval.JitAColdSize", 24 << 20);
    Config::Bind(CodeCache::AFrozenSize, ini, config, "Eval.JitAFrozenSize", 40 << 20);
    Config::Bind(CodeCache::ABytecodeSize, ini, config, "Eval.JitABytecodeSize", 0);
    Config::Bind(CodeCache::GlobalDataSize, ini, config, "Eval.JitGlobalDataSize", CodeCache::ASize >> 2);

    Config::Bind(CodeCache::MapTCHuge, ini, config, "Eval.MapTCHuge", hugePagesSoundNice());

    Config::Bind(CodeCache::TCNumHugeHotMB, ini, config, "Eval.TCNumHugeHotMB", 64);
    Config::Bind(CodeCache::TCNumHugeMainMB, ini, config, "Eval.TCNumHugeMainMB", 16);
    Config::Bind(CodeCache::TCNumHugeColdMB, ini, config, "Eval.TCNumHugeColdMB", 4);

    Config::Bind(CodeCache::AutoTCShift, ini, config, "Eval.JitAutoTCShift", 1);
  }
  {
    
    Config::Bind(CheckIntOverflow, ini, config, "Hack.Lang.CheckIntOverflow", 0);
    Config::Bind(StrictArrayFillKeys, ini, config, "Hack.Lang.StrictArrayFillKeys", HackStrictOption::ON);

    Config::Bind(LookForTypechecker, ini, config, "Hack.Lang.LookForTypechecker", false);

    
    
    
    
    Config::Bind(AutoTypecheck, ini, config, "Hack.Lang.AutoTypecheck", LookForTypechecker);
    Config::Bind(EnableClassLevelWhereClauses, ini, config, "Hack.Lang.EnableClassLevelWhereClauses", false);

  }
  {
    
    
    
    
    
    
    
    
    
    
    
    
    
    Config::Bind(s_PHP7_master, ini, config, "PHP7.all", s_PHP7_default);
    Config::Bind(PHP7_EngineExceptions, ini, config, "PHP7.EngineExceptions", s_PHP7_master);
    Config::Bind(PHP7_NoHexNumerics, ini, config, "PHP7.NoHexNumerics", s_PHP7_master);
    Config::Bind(PHP7_Builtins, ini, config, "PHP7.Builtins", s_PHP7_master);
    Config::Bind(PHP7_Substr, ini, config, "PHP7.Substr", s_PHP7_master);
    Config::Bind(PHP7_DisallowUnsafeCurlUploads, ini, config, "PHP7.DisallowUnsafeCurlUploads", s_PHP7_master);
  }
  {
    
    Config::Bind(Host, ini, config, "Server.Host");
    Config::Bind(DefaultServerNameSuffix, ini, config, "Server.DefaultServerNameSuffix");
    Config::Bind(AlwaysDecodePostDataDefault, ini, config, "Server.AlwaysDecodePostDataDefault", AlwaysDecodePostDataDefault);

    Config::Bind(ServerType, ini, config, "Server.Type", ServerType);
    Config::Bind(ServerIP, ini, config, "Server.IP");
    Config::Bind(ServerFileSocket, ini, config, "Server.FileSocket");


    
    if (GetServerPrimaryIPv4().empty() && GetServerPrimaryIPv6().empty()) {
      throw std::runtime_error("Unable to resolve the server's " "IPv4 or IPv6 address");
    }


    Config::Bind(ServerPort, ini, config, "Server.Port", 80);
    Config::Bind(ServerBacklog, ini, config, "Server.Backlog", 128);
    Config::Bind(ServerConnectionLimit, ini, config, "Server.ConnectionLimit", 0);
    Config::Bind(ServerThreadCount, ini, config, "Server.ThreadCount", Process::GetCPUCount() * 2);
    Config::Bind(ServerQueueCount, ini, config, "Server.QueueCount", ServerThreadCount);
    Config::Bind(ServerIOThreadCount, ini, config, "Server.IOThreadCount", 1);
    Config::Bind(ServerLegacyBehavior, ini, config, "Server.LegacyBehavior", ServerLegacyBehavior);
    Config::Bind(ServerHugeThreadCount, ini, config, "Server.HugeThreadCount", 0);
    Config::Bind(ServerHugeStackKb, ini, config, "Server.HugeStackSizeKb", 384);
    Config::Bind(ServerLoopSampleRate, ini, config, "Server.LoopSampleRate", 0);
    Config::Bind(ServerWarmupThrottleRequestCount, ini, config, "Server.WarmupThrottleRequestCount", ServerWarmupThrottleRequestCount);

    Config::Bind(ServerWarmupThrottleThreadCount, ini, config, "Server.WarmupThrottleThreadCount", Process::GetCPUCount());

    Config::Bind(ServerThreadDropCacheTimeoutSeconds, ini, config, "Server.ThreadDropCacheTimeoutSeconds", 0);
    if (Config::GetBool(ini, config, "Server.ThreadJobLIFO")) {
      ServerThreadJobLIFOSwitchThreshold = 0;
    }
    Config::Bind(ServerThreadJobLIFOSwitchThreshold, ini, config, "Server.ThreadJobLIFOSwitchThreshold", ServerThreadJobLIFOSwitchThreshold);

    Config::Bind(ServerThreadJobMaxQueuingMilliSeconds, ini, config, "Server.ThreadJobMaxQueuingMilliSeconds", -1);
    Config::Bind(ServerThreadDropStack, ini, config, "Server.ThreadDropStack");
    Config::Bind(ServerHttpSafeMode, ini, config, "Server.HttpSafeMode");
    Config::Bind(ServerStatCache, ini, config, "Server.StatCache", false);
    Config::Bind(ServerFixPathInfo, ini, config, "Server.FixPathInfo", false);
    Config::Bind(ServerAddVaryEncoding, ini, config, "Server.AddVaryEncoding", ServerAddVaryEncoding);
    Config::Bind(ServerLogSettingsOnStartup, ini, config, "Server.LogSettingsOnStartup", false);
    Config::Bind(ServerLogReorderProps, ini, config, "Server.LogReorderProps", false);
    Config::Bind(ServerWarmupConcurrently, ini, config, "Server.WarmupConcurrently", false);
    Config::Bind(ServerDedupeWarmupRequests, ini, config, "Server.DedupeWarmupRequests", false);
    Config::Bind(ServerWarmupThreadCount, ini, config, "Server.WarmupThreadCount", ServerWarmupThreadCount);
    Config::Bind(ServerExtendedWarmupThreadCount, ini, config, "Server.ExtendedWarmup.ThreadCount", ServerExtendedWarmupThreadCount);

    Config::Bind(ServerExtendedWarmupDelaySeconds, ini, config, "Server.ExtendedWarmup.DelaySeconds", ServerExtendedWarmupDelaySeconds);

    Config::Bind(ServerExtendedWarmupRepeat, ini, config, "Server.ExtendedWarmup.Repeat", ServerExtendedWarmupRepeat);
    Config::Bind(ServerWarmupRequests, ini, config, "Server.WarmupRequests");
    Config::Bind(ServerExtendedWarmupRequests, ini, config, "Server.ExtendedWarmup.Requests");
    Config::Bind(ServerCleanupRequest, ini, config, "Server.CleanupRequest");
    Config::Bind(ServerInternalWarmupThreads, ini, config, "Server.InternalWarmupThreads", 0);
    Config::Bind(ServerHighPriorityEndPoints, ini, config, "Server.HighPriorityEndPoints");
    Config::Bind(ServerExitOnBindFail, ini, config, "Server.ExitOnBindFail", false);

    Config::Bind(RequestTimeoutSeconds, ini, config, "Server.RequestTimeoutSeconds", 0);
    Config::Bind(MaxRequestAgeFactor, ini, config, "Server.MaxRequestAgeFactor", 0);
    Config::Bind(PspTimeoutSeconds, ini, config, "Server.PspTimeoutSeconds", 0);
    Config::Bind(PspCpuTimeoutSeconds, ini, config, "Server.PspCpuTimeoutSeconds", 0);
    Config::Bind(RequestMemoryMaxBytes, ini, config, "Server.RequestMemoryMaxBytes", (16LL << 30));
    RequestInfo::setOOMKillThreshold( Config::GetUInt64(ini, config, "Server.RequestMemoryOOMKillBytes", 128ULL << 20));

    Config::Bind(RequestHugeMaxBytes, ini, config, "Server.RequestHugeMaxBytes", (24LL << 20));
    Config::Bind(ServerGracefulShutdownWait, ini, config, "Server.GracefulShutdownWait", 0);
    Config::Bind(ServerHarshShutdown, ini, config, "Server.HarshShutdown", true);
    Config::Bind(ServerKillOnTimeout, ini, config, "Server.KillOnTimeout", true);
    Config::Bind(ServerEvilShutdown, ini, config, "Server.EvilShutdown", true);
    Config::Bind(ServerPreShutdownWait, ini, config, "Server.PreShutdownWait", 0);
    Config::Bind(ServerShutdownListenWait, ini, config, "Server.ShutdownListenWait", 0);
    Config::Bind(ServerShutdownEOMWait, ini, config, "Server.ShutdownEOMWait", 0);
    Config::Bind(ServerPrepareToStopTimeout, ini, config, "Server.PrepareToStopTimeout", 240);
    Config::Bind(ServerPartialPostStatusCode, ini, config, "Server.PartialPostStatusCode", -1);
    Config::Bind(StopOldServer, ini, config, "Server.StopOld", false);
    Config::Bind(OldServerWait, ini, config, "Server.StopOldWait", 30);
    Config::Bind(ServerRSSNeededMb, ini, config, "Server.RSSNeededMb", 4096);
    Config::Bind(ServerCriticalFreeMb, ini, config, "Server.CriticalFreeMb", 512);
    Config::Bind(CacheFreeFactor, ini, config, "Server.CacheFreeFactor", 50);
    if (CacheFreeFactor > 100) CacheFreeFactor = 100;
    if (CacheFreeFactor < 0) CacheFreeFactor = 0;

    Config::Bind(ServerNextProtocols, ini, config, "Server.SSLNextProtocols");
    Config::Bind(ServerEnableH2C, ini, config, "Server.EnableH2C");
    extern bool g_brotliUseLocalArena;
    Config::Bind(g_brotliUseLocalArena, ini, config, "Server.BrotliUseLocalArena", g_brotliUseLocalArena);
    Config::Bind(BrotliCompressionEnabled, ini, config, "Server.BrotliCompressionEnabled", -1);
    Config::Bind(BrotliChunkedCompressionEnabled, ini, config, "Server.BrotliChunkedCompressionEnabled", -1);
    Config::Bind(BrotliCompressionLgWindowSize, ini, config, "Server.BrotliCompressionLgWindowSize", 20);
    Config::Bind(BrotliCompressionMode, ini, config, "Server.BrotliCompressionMode", 0);
    Config::Bind(BrotliCompressionQuality, ini, config, "Server.BrotliCompressionQuality", 6);
    Config::Bind(ZstdCompressionEnabled, ini, config, "Server.ZstdCompressionEnabled", -1);
    Config::Bind(ZstdCompressor::s_useLocalArena, ini, config, "Server.ZstdUseLocalArena", ZstdCompressor::s_useLocalArena);
    Config::Bind(ZstdCompressionLevel, ini, config, "Server.ZstdCompressionLevel", 3);
    Config::Bind(ZstdChecksumRate, ini, config, "Server.ZstdChecksumRate", 0);
    Config::Bind(GzipCompressionLevel, ini, config, "Server.GzipCompressionLevel", 3);
    Config::Bind(GzipMaxCompressionLevel, ini, config, "Server.GzipMaxCompressionLevel", 9);
    Config::Bind(GzipCompressor::s_useLocalArena, ini, config, "Server.GzipUseLocalArena", GzipCompressor::s_useLocalArena);
    Config::Bind(EnableKeepAlive, ini, config, "Server.EnableKeepAlive", true);
    Config::Bind(ExposeHPHP, ini, config, "Server.ExposeHPHP", true);
    Config::Bind(ExposeXFBServer, ini, config, "Server.ExposeXFBServer", false);
    Config::Bind(ExposeXFBDebug, ini, config, "Server.ExposeXFBDebug", false);
    Config::Bind(XFBDebugSSLKey, ini, config, "Server.XFBDebugSSLKey", "");
    Config::Bind(ConnectionTimeoutSeconds, ini, config, "Server.ConnectionTimeoutSeconds", -1);
    Config::Bind(EnableOutputBuffering, ini, config, "Server.EnableOutputBuffering");
    Config::Bind(OutputHandler, ini, config, "Server.OutputHandler");
    Config::Bind(ImplicitFlush, ini, config, "Server.ImplicitFlush");
    Config::Bind(EnableEarlyFlush, ini, config, "Server.EnableEarlyFlush", true);
    Config::Bind(ForceChunkedEncoding, ini, config, "Server.ForceChunkedEncoding");
    Config::Bind(MaxPostSize, ini, config, "Server.MaxPostSize", 100);
    MaxPostSize <<= 20;
    Config::Bind(AlwaysPopulateRawPostData, ini, config, "Server.AlwaysPopulateRawPostData", false);
    Config::Bind(TakeoverFilename, ini, config, "Server.TakeoverFilename");
    Config::Bind(ExpiresActive, ini, config, "Server.ExpiresActive", true);
    Config::Bind(ExpiresDefault, ini, config, "Server.ExpiresDefault", 2592000);
    if (ExpiresDefault < 0) ExpiresDefault = 2592000;
    Config::Bind(DefaultCharsetName, ini, config, "Server.DefaultCharsetName", "");
    Config::Bind(RequestBodyReadLimit, ini, config, "Server.RequestBodyReadLimit", -1);
    Config::Bind(EnableSSL, ini, config, "Server.EnableSSL");
    Config::Bind(SSLPort, ini, config, "Server.SSLPort", 443);
    Config::Bind(SSLCertificateFile, ini, config, "Server.SSLCertificateFile");
    Config::Bind(SSLCertificateKeyFile, ini, config, "Server.SSLCertificateKeyFile");
    Config::Bind(SSLCertificateDir, ini, config, "Server.SSLCertificateDir");
    Config::Bind(SSLTicketSeedFile, ini, config, "Server.SSLTicketSeedFile");
    Config::Bind(TLSDisableTLS1_2, ini, config, "Server.TLSDisableTLS1_2", false);
    Config::Bind(TLSClientCipherSpec, ini, config, "Server.TLSClientCipherSpec");
    Config::Bind(EnableSSLWithPlainText, ini, config, "Server.EnableSSLWithPlainText");
    Config::Bind(SSLClientAuthLevel, ini, config, "Server.SSLClientAuthLevel", 0);
    if (SSLClientAuthLevel < 0) SSLClientAuthLevel = 0;
    if (SSLClientAuthLevel > 2) SSLClientAuthLevel = 2;
    Config::Bind(SSLClientCAFile, ini, config, "Server.SSLClientCAFile", "");
    if (!SSLClientAuthLevel) {
      SSLClientCAFile = "";
    } else if (SSLClientCAFile.empty()) {
      throw std::runtime_error( "SSLClientCAFile is required to enable client auth");
    }

    Config::Bind(ClientAuthAclIdentity, ini, config, "Server.ClientAuthAclIdentity", "");
    Config::Bind(ClientAuthAclAction, ini, config, "Server.ClientAuthAclAction", "");
    Config::Bind(ClientAuthFailClose, ini, config, "Server.ClientAuthFailClose", false);

    Config::Bind(ClientAuthLogSampleBase, ini, config, "Server.ClientAuthLogSampleBase", 100);
    if (ClientAuthLogSampleBase < 1) {
      ClientAuthLogSampleBase = 1;
    }

    Config::Bind(SSLClientAuthLoggingSampleRatio, ini, config, "Server.SSLClientAuthLoggingSampleRatio", 0);
    if (SSLClientAuthLoggingSampleRatio < 0) {
      SSLClientAuthLoggingSampleRatio = 0;
    }
    if (SSLClientAuthLoggingSampleRatio > ClientAuthLogSampleBase) {
      SSLClientAuthLoggingSampleRatio = ClientAuthLogSampleBase;
    }

    Config::Bind(ClientAuthSuccessLogSampleRatio, ini, config, "Server.ClientAuthSuccessLogSampleRatio", 0);
    if (ClientAuthSuccessLogSampleRatio < SSLClientAuthLoggingSampleRatio) {
      ClientAuthSuccessLogSampleRatio = SSLClientAuthLoggingSampleRatio;
    }
    if (ClientAuthSuccessLogSampleRatio > ClientAuthLogSampleBase) {
      ClientAuthSuccessLogSampleRatio = ClientAuthLogSampleBase;
    }

    Config::Bind(ClientAuthFailureLogSampleRatio, ini, config, "Server.ClientAuthFailureLogSampleRatio", 0);
    if (ClientAuthFailureLogSampleRatio < SSLClientAuthLoggingSampleRatio) {
      ClientAuthFailureLogSampleRatio = SSLClientAuthLoggingSampleRatio;
    }
    if (ClientAuthFailureLogSampleRatio > ClientAuthLogSampleBase) {
      ClientAuthFailureLogSampleRatio = ClientAuthLogSampleBase;
    }

    
    auto defSourceRoot = SourceRoot;
    Config::Bind(SourceRoot, ini, config, "Server.SourceRoot", SourceRoot);
    SourceRoot = FileUtil::normalizeDir(SourceRoot);
    if (SourceRoot.empty()) {
      SourceRoot = defSourceRoot;
    }
    FileCache::SourceRoot = SourceRoot;

    Config::Bind(IncludeSearchPaths, ini, config, "Server.IncludeSearchPaths");
    for (unsigned int i = 0; i < IncludeSearchPaths.size(); i++) {
      IncludeSearchPaths[i] = FileUtil::normalizeDir(IncludeSearchPaths[i]);
    }
    IncludeSearchPaths.insert(IncludeSearchPaths.begin(), ".");

    Config::Bind(AutoloadEnabled, ini, config, "Autoload.Enabled", false);
    Config::Bind(AutoloadDBPath, ini, config, "Autoload.DBPath");

    Config::Bind(FileCache, ini, config, "Server.FileCache");
    Config::Bind(DefaultDocument, ini, config, "Server.DefaultDocument", "index.php");
    Config::Bind(GlobalDocument, ini, config, "Server.GlobalDocument");
    Config::Bind(ErrorDocument404, ini, config, "Server.ErrorDocument404");
    normalizePath(ErrorDocument404);
    Config::Bind(ForbiddenAs404, ini, config, "Server.ForbiddenAs404");
    Config::Bind(ErrorDocument500, ini, config, "Server.ErrorDocument500");
    normalizePath(ErrorDocument500);
    Config::Bind(FatalErrorMessage, ini, config, "Server.FatalErrorMessage");
    FontPath = FileUtil::normalizeDir( Config::GetString(ini, config, "Server.FontPath"));
    Config::Bind(EnableStaticContentFromDisk, ini, config, "Server.EnableStaticContentFromDisk", true);
    Config::Bind(EnableOnDemandUncompress, ini, config, "Server.EnableOnDemandUncompress", true);
    Config::Bind(EnableStaticContentMMap, ini, config, "Server.EnableStaticContentMMap", true);
    if (EnableStaticContentMMap) {
      EnableOnDemandUncompress = true;
    }
    Config::Bind(Utf8izeReplace, ini, config, "Server.Utf8izeReplace", true);

    Config::Bind(RequestInitFunction, ini, config, "Server.RequestInitFunction");
    Config::Bind(RequestInitDocument, ini, config, "Server.RequestInitDocument");
    Config::Bind(SafeFileAccess, ini, config, "Server.SafeFileAccess");
    Config::Bind(AllowedDirectories, ini, config, "Server.AllowedDirectories");
    Config::Bind(WhitelistExec, ini, config, "Server.WhitelistExec");
    Config::Bind(WhitelistExecWarningOnly, ini, config, "Server.WhitelistExecWarningOnly");
    Config::Bind(AllowedExecCmds, ini, config, "Server.AllowedExecCmds");
    Config::Bind(UnserializationWhitelistCheck, ini, config, "Server.UnserializationWhitelistCheck", false);
    Config::Bind(UnserializationWhitelistCheckWarningOnly, ini, config, "Server.UnserializationWhitelistCheckWarningOnly", true);
    Config::Bind(UnserializationBigMapThreshold, ini, config, "Server.UnserializationBigMapThreshold", 1 << 16);
    Config::Bind(AllowedFiles, ini, config, "Server.AllowedFiles");
    Config::Bind(ForbiddenFileExtensions, ini, config, "Server.ForbiddenFileExtensions");
    Config::Bind(LockCodeMemory, ini, config, "Server.LockCodeMemory", false);
    Config::Bind(MaxArrayChain, ini, config, "Server.MaxArrayChain", INT_MAX);
    if (MaxArrayChain != INT_MAX) {
      
      
      MaxArrayChain *= 2;
    }

    Config::Bind(WarnOnCollectionToArray, ini, config, "Server.WarnOnCollectionToArray", false);
    Config::Bind(UseDirectCopy, ini, config, "Server.UseDirectCopy", false);
    Config::Bind(AlwaysUseRelativePath, ini, config, "Server.AlwaysUseRelativePath", false);
    {
      
      Config::Bind(UploadMaxFileSize, ini, config, "Server.Upload.UploadMaxFileSize", 100);
      UploadMaxFileSize <<= 20;
      Config::Bind(UploadTmpDir, ini, config, "Server.Upload.UploadTmpDir", "/tmp");
      Config::Bind(EnableFileUploads, ini, config, "Server.Upload.EnableFileUploads", true);
      Config::Bind(MaxFileUploads, ini, config, "Server.Upload.MaxFileUploads", 20);
      Config::Bind(EnableUploadProgress, ini, config, "Server.Upload.EnableUploadProgress");
      Config::Bind(Rfc1867Freq, ini, config, "Server.Upload.Rfc1867Freq", 256 * 1024);
      if (Rfc1867Freq < 0) Rfc1867Freq = 256 * 1024;
      Config::Bind(Rfc1867Prefix, ini, config, "Server.Upload.Rfc1867Prefix", "vupload_");
      Config::Bind(Rfc1867Name, ini, config, "Server.Upload.Rfc1867Name", "video_ptoken");
    }
    Config::Bind(ImageMemoryMaxBytes, ini, config, "Server.ImageMemoryMaxBytes", 0);
    if (ImageMemoryMaxBytes == 0) {
      ImageMemoryMaxBytes = UploadMaxFileSize * 2;
    }
    Config::Bind(LightProcessFilePrefix, ini, config, "Server.LightProcessFilePrefix", "./lightprocess");
    Config::Bind(LightProcessCount, ini, config, "Server.LightProcessCount", 0);
    Config::Bind(ForceServerNameToHeader, ini, config, "Server.ForceServerNameToHeader");
    Config::Bind(AllowDuplicateCookies, ini, config, "Server.AllowDuplicateCookies", false);
    Config::Bind(PathDebug, ini, config, "Server.PathDebug", false);
    Config::Bind(ServerUser, ini, config, "Server.User", "");
    Config::Bind(AllowRunAsRoot, ini, config, "Server.AllowRunAsRoot", false);
  }

  VirtualHost::SortAllowedDirectories(AllowedDirectories);
  {
    auto vh_callback = [] (const IniSettingMap &ini_vh, const Hdf &hdf_vh, const std::string &ini_vh_key) {
      if (VirtualHost::IsDefault(ini_vh, hdf_vh, ini_vh_key)) {
        VirtualHost::GetDefault().init(ini_vh, hdf_vh, ini_vh_key);
        VirtualHost::GetDefault().addAllowedDirectories(AllowedDirectories);
      } else {
        auto host = std::make_shared<VirtualHost>(ini_vh, hdf_vh, ini_vh_key);
        host->addAllowedDirectories(AllowedDirectories);
        VirtualHosts.push_back(host);
      }
    };
    
    
    
    
    
    Config::Iterate(vh_callback, ini, config, "VirtualHost");
    LowestMaxPostSize = VirtualHost::GetLowestMaxPostSize();
  }
  {
    
    IpBlocks = std::make_shared<IpBlockMap>(ini, config);
  }
  {
    ReadSatelliteInfo(ini, config, SatelliteServerInfos, XboxPassword, XboxPasswords);
  }
  {
    
    Config::Bind(XboxServerThreadCount, ini, config, "Xbox.ServerInfo.ThreadCount", 10);
    Config::Bind(XboxServerMaxQueueLength, ini, config, "Xbox.ServerInfo.MaxQueueLength", INT_MAX);
    if (XboxServerMaxQueueLength < 0) XboxServerMaxQueueLength = INT_MAX;
    Config::Bind(XboxServerInfoMaxRequest, ini, config, "Xbox.ServerInfo.MaxRequest", 500);
    Config::Bind(XboxServerInfoDuration, ini, config, "Xbox.ServerInfo.MaxDuration", 120);
    Config::Bind(XboxServerInfoReqInitFunc, ini, config, "Xbox.ServerInfo.RequestInitFunction", "");
    Config::Bind(XboxServerInfoReqInitDoc, ini, config, "Xbox.ServerInfo.RequestInitDocument", "");
    Config::Bind(XboxServerInfoAlwaysReset, ini, config, "Xbox.ServerInfo.AlwaysReset", false);
    Config::Bind(XboxServerLogInfo, ini, config, "Xbox.ServerInfo.LogInfo", false);
    Config::Bind(XboxProcessMessageFunc, ini, config, "Xbox.ProcessMessageFunc", "xbox_process_message");
  }
  {
    
    Config::Bind(PageletServerThreadCount, ini, config, "PageletServer.ThreadCount", 0);
    Config::Bind(PageletServerHugeThreadCount, ini, config, "PageletServer.HugeThreadCount", 0);
    Config::Bind(PageletServerThreadDropStack, ini, config, "PageletServer.ThreadDropStack");
    Config::Bind(PageletServerThreadDropCacheTimeoutSeconds, ini, config, "PageletServer.ThreadDropCacheTimeoutSeconds", 0);
    Config::Bind(PageletServerQueueLimit, ini, config, "PageletServer.QueueLimit", 0);
  }
  {
    

    hphp_string_imap<std::string> staticFileDefault;
    staticFileDefault["css"] = "text/css";
    staticFileDefault["gif"] = "image/gif";
    staticFileDefault["html"] = "text/html";
    staticFileDefault["jpeg"] = "image/jpeg";
    staticFileDefault["jpg"] = "image/jpeg";
    staticFileDefault["mp3"] = "audio/mpeg";
    staticFileDefault["png"] = "image/png";
    staticFileDefault["tif"] = "image/tiff";
    staticFileDefault["tiff"] = "image/tiff";
    staticFileDefault["txt"] = "text/plain";
    staticFileDefault["zip"] = "application/zip";

    Config::Bind(StaticFileExtensions, ini, config, "StaticFile.Extensions", staticFileDefault);

    auto matches_callback = [](const IniSettingMap& ini_m, const Hdf& hdf_m, const std::string& ) {
      FilesMatches.push_back(std::make_shared<FilesMatch>(ini_m, hdf_m));
    };
    Config::Iterate(matches_callback, ini, config, "StaticFile.FilesMatch");
  }
  {
    
    Config::Bind(PhpFileExtensions, ini, config, "PhpFile.Extensions");
  }
  {
    
    Config::Bind(AdminServerIP, ini, config, "AdminServer.IP", ServerIP);
    Config::Bind(AdminServerPort, ini, config, "AdminServer.Port", 0);
    Config::Bind(AdminThreadCount, ini, config, "AdminServer.ThreadCount", 1);
    Config::Bind(AdminServerEnableSSLWithPlainText, ini, config, "AdminServer.EnableSSLWithPlainText", false);
    Config::Bind(AdminServerStatsNeedPassword, ini, config, "AdminServer.StatsNeedPassword", AdminServerStatsNeedPassword);
    AdminPassword = Config::GetString(ini, config, "AdminServer.Password");
    AdminPasswords = Config::GetSet(ini, config, "AdminServer.Passwords");
    HashedAdminPasswords = Config::GetSet(ini, config, "AdminServer.HashedPasswords");
  }
  {
    
    Config::Bind(ProxyOriginRaw, ini, config, "Proxy.Origin");
    Config::Bind(ProxyPercentageRaw, ini, config, "Proxy.Percentage", 0);
    Config::Bind(ProxyRetry, ini, config, "Proxy.Retry", 3);
    Config::Bind(UseServeURLs, ini, config, "Proxy.ServeURLs");
    Config::Bind(ServeURLs, ini, config, "Proxy.ServeURLs");
    Config::Bind(UseProxyURLs, ini, config, "Proxy.ProxyURLs");
    Config::Bind(ProxyURLs, ini, config, "Proxy.ProxyURLs");
    Config::Bind(ProxyPatterns, ini, config, "Proxy.ProxyPatterns");
  }
  {
    
    Config::Bind(HttpDefaultTimeout, ini, config, "Http.DefaultTimeout", 30);
    Config::Bind(HttpSlowQueryThreshold, ini, config, "Http.SlowQueryThreshold", 5000);
  }
  {
    

    Config::Bind(NativeStackTrace, ini, config, "Debug.NativeStackTrace");
    StackTrace::Enabled = NativeStackTrace;
    Config::Bind(ServerErrorMessage, ini, config, "Debug.ServerErrorMessage");
    Config::Bind(RecordInput, ini, config, "Debug.RecordInput");
    Config::Bind(ClearInputOnSuccess, ini, config, "Debug.ClearInputOnSuccess", true);
    Config::Bind(ProfilerOutputDir, ini, config, "Debug.ProfilerOutputDir", "/tmp");
    Config::Bind(CoreDumpEmail, ini, config, "Debug.CoreDumpEmail");
    Config::Bind(CoreDumpReport, ini, config, "Debug.CoreDumpReport", true);
    if (CoreDumpReport) {
      install_crash_reporter();
    }
    
    
    Config::Bind(CoreDumpReportDirectory, ini, config, "Debug.CoreDumpReportDirectory", CoreDumpReportDirectory);
    std::ostringstream stack_trace_stream;
    stack_trace_stream << CoreDumpReportDirectory << "/stacktrace." << (int64_t)getpid() << ".log";
    StackTraceFilename = stack_trace_stream.str();

    Config::Bind(StackTraceTimeout, ini, config, "Debug.StackTraceTimeout", 0);
    Config::Bind(RemoteTraceOutputDir, ini, config, "Debug.RemoteTraceOutputDir", "/tmp");
    Config::Bind(TraceFunctions, ini, config, "Debug.TraceFunctions", TraceFunctions);
  }
  {
    
    Config::Bind(EnableStats, ini, config, "Stats.Enable", false);
    Config::Bind(EnableAPCStats, ini, config, "Stats.APC", false);
    Config::Bind(EnableWebStats, ini, config, "Stats.Web");
    Config::Bind(EnableMemoryStats, ini, config, "Stats.Memory");
    Config::Bind(EnableSQLStats, ini, config, "Stats.SQL");
    Config::Bind(EnableSQLTableStats, ini, config, "Stats.SQLTable");
    Config::Bind(EnableNetworkIOStatus, ini, config, "Stats.NetworkIO");
    Config::Bind(StatsXSL, ini, config, "Stats.XSL");
    Config::Bind(StatsXSLProxy, ini, config, "Stats.XSLProxy");
    Config::Bind(StatsSlotDuration, ini, config, "Stats.SlotDuration", 10 * 60);
    Config::Bind(StatsMaxSlot, ini, config, "Stats.MaxSlot", 12 * 6);
    StatsSlotDuration = std::max(1u, StatsSlotDuration);
    StatsMaxSlot = std::max(2u, StatsMaxSlot);
    Config::Bind(EnableHotProfiler, ini, config, "Stats.EnableHotProfiler", true);
    Config::Bind(ProfilerTraceBuffer, ini, config, "Stats.ProfilerTraceBuffer", 2000000);
    Config::Bind(ProfilerTraceExpansion, ini, config, "Stats.ProfilerTraceExpansion", 1.2);
    Config::Bind(ProfilerMaxTraceBuffer, ini, config, "Stats.ProfilerMaxTraceBuffer", 0);
    Config::Bind(TrackPerUnitMemory, ini, config, "Stats.TrackPerUnitMemory", false);
  }
  {
    Config::Bind(ServerVariables, ini, config, "ServerVariables");
    Config::Bind(EnvVariables, ini, config, "EnvVariables");
  }
  {
    
    Config::Bind(SandboxMode, ini, config, "Sandbox.SandboxMode");
    Config::Bind(SandboxPattern, ini, config, "Sandbox.Pattern");
    SandboxPattern = format_pattern(SandboxPattern, true);
    Config::Bind(SandboxHome, ini, config, "Sandbox.Home");
    Config::Bind(SandboxFallback, ini, config, "Sandbox.Fallback");
    Config::Bind(SandboxConfFile, ini, config, "Sandbox.ConfFile");
    Config::Bind(SandboxFromCommonRoot, ini, config, "Sandbox.FromCommonRoot");
    Config::Bind(SandboxDirectoriesRoot, ini, config, "Sandbox.DirectoriesRoot");
    Config::Bind(SandboxLogsRoot, ini, config, "Sandbox.LogsRoot");
    Config::Bind(SandboxServerVariables, ini, config, "Sandbox.ServerVariables");
    Config::Bind(SandboxDefaultUserFile, ini, config, "Sandbox.DefaultUserFile");
    Config::Bind(SandboxHostAlias, ini, config, "Sandbox.HostAlias");
  }
  {
    
    Config::Bind(SendmailPath, ini, config, "Mail.SendmailPath", "/usr/lib/sendmail -t -i");
    Config::Bind(MailForceExtraParameters, ini, config, "Mail.ForceExtraParameters");
  }
  {
    
    Config::Bind(PregBacktraceLimit, ini, config, "Preg.BacktraceLimit", 1000000);
    Config::Bind(PregRecursionLimit, ini, config, "Preg.RecursionLimit", 100000);
    Config::Bind(EnablePregErrorLog, ini, config, "Preg.ErrorLog", true);
  }
  {
    
    Config::Bind(SimpleXMLEmptyNamespaceMatchesAll, ini, config, "SimpleXML.EmptyNamespaceMatchesAll", false);
  }

  {
    
    Config::Bind(EnableFb303Server, ini, config, "Fb303Server.Enable", EnableFb303Server);
    Config::Bind(Fb303ServerPort, ini, config, "Fb303Server.Port", 0);
    Config::Bind(Fb303ServerIP, ini, config, "Fb303Server.IP");
    Config::Bind(Fb303ServerThreadStackSizeMb, ini, config, "Fb303Server.ThreadStackSizeMb", 8);
    Config::Bind(Fb303ServerWorkerThreads, ini, config, "Fb303Server.WorkerThreads", 1);
    Config::Bind(Fb303ServerPoolThreads, ini, config, "Fb303Server.PoolThreads", 1);
  }


  {
    
    Config::Bind(XenonPeriodSeconds, ini, config, "Xenon.Period", 0.0);
    Config::Bind(XenonRequestFreq, ini, config, "Xenon.RequestFreq", 1);
    Config::Bind(XenonForceAlwaysOn, ini, config, "Xenon.ForceAlwaysOn", false);
  }
  {
    
    Config::Bind(StrobelightEnabled, ini, config, "Strobelight.Enabled", false);
  }
  {
    
    Config::Bind(SetProfileNullThisObject, ini, config, "SetProfile.NullThisObject", true);
  }
  {
    
    
    
    
    
    Variant v;
    bool b = IniSetting::GetSystem("zend.assertions", v);
    if (b) RuntimeOption::AssertEmitted = v.toInt64() >= 0;
  }

  Config::Bind(TzdataSearchPaths, ini, config, "TzdataSearchPaths");

  Config::Bind(CustomSettings, ini, config, "CustomSettings");

  
  refineStaticStringTableSize();
  InitFiniNode::ProcessPostRuntimeOptions();

  
  
  
  
  
  
  
  
  
  
  
  
  

  
  
  
  
  
  Config::Bind(EnableZendIniCompat, ini, config, "Eval.EnableZendIniCompat", true);
  
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_ONLY, "expose_php", &RuntimeOption::ExposeHPHP);
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_PERDIR, "auto_prepend_file", &RuntimeOption::AutoPrependFile);
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_PERDIR, "auto_append_file", &RuntimeOption::AutoAppendFile);

  
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_PERDIR, "post_max_size", IniSetting::SetAndGet<int64_t>( nullptr, []() {



                       return VirtualHost::GetMaxPostSize();
                     }
                   ), &RuntimeOption::MaxPostSize);
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_PERDIR, "always_populate_raw_post_data", &RuntimeOption::AlwaysPopulateRawPostData);


  
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_SYSTEM, "doc_root", &RuntimeOption::SourceRoot);
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_SYSTEM, "sendmail_path", &RuntimeOption::SendmailPath);

  
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_ONLY, "pid", &RuntimeOption::PidFile);

  
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_SYSTEM, "file_uploads", "true", &RuntimeOption::EnableFileUploads);

  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_SYSTEM, "upload_tmp_dir", &RuntimeOption::UploadTmpDir);
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_PERDIR, "upload_max_filesize", IniSetting::SetAndGet<std::string>( [](const std::string& value) {


                       return ini_on_update( value, RuntimeOption::UploadMaxFileSize);
                     }, []() {
                       return convert_long_to_bytes( VirtualHost::GetUploadMaxFileSize());
                     }
                   ));
  
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_SYSTEM, "allow_url_fopen", IniSetting::SetAndGet<std::string>( [](const std::string& ) { return false; }, []() { return "1"; }));




  
  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_NONE, "hphp.compiler_id", IniSetting::SetAndGet<std::string>( [](const std::string& ) { return false; }, []() { return compilerId().begin(); }));



  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_NONE, "hphp.compiler_version", IniSetting::SetAndGet<std::string>( [](const std::string& ) { return false; }, []() { return getHphpCompilerVersion(); }));



  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_NONE, "hphp.cli_server_api_version", IniSetting::SetAndGet<uint64_t>( [](const uint64_t ) { return false; }, []() { return cli_server_api_version(); }));



  IniSetting::Bind( IniSetting::CORE, IniSetting::PHP_INI_NONE, "hphp.build_id", IniSetting::SetAndGet<std::string>( [](const std::string& ) { return false; }, nullptr), &RuntimeOption::BuildId);



  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_SYSTEM, "notice_frequency", &RuntimeOption::NoticeFrequency);

  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_SYSTEM, "warning_frequency", &RuntimeOption::WarningFrequency);

  IniSetting::Bind(IniSetting::CORE, IniSetting::PHP_INI_ONLY, "hhvm.build_type", IniSetting::SetAndGet<std::string>( [](const std::string&) {


      return false;
    }, []() {
      return s_hhvm_build_type.c_str();
    }
  ));

  
  Config::Bind(RuntimeOption::ExtensionDir, ini, config, "extension_dir", RuntimeOption::ExtensionDir, false);
  Config::Bind(RuntimeOption::DynamicExtensionPath, ini, config, "DynamicExtensionPath", RuntimeOption::DynamicExtensionPath);

  Config::Bind(RuntimeOption::Extensions, ini, config, "extensions");
  Config::Bind(RuntimeOption::DynamicExtensions, ini, config, "DynamicExtensions");

  ExtensionRegistry::moduleLoad(ini, config);
  initialize_apc();

  if (TraceFunctions.size()) Trace::ensureInit(getTraceOutputFile());

  
  if (RO::EvalHackArrDVArrs) {
    RO::EvalArrayProvenance = false;
    RO::EvalLogArrayProvenance = false;
  }

  

  
  
  if (RO::EvalBespokeArrayLikeMode > 0 && (RO::EvalArrayProvenance || RO::EvalLogArrayProvenance)) {
    RO::EvalBespokeArrayLikeMode = 0;
  }

  
  
  
  if (RO::EvalBespokeArrayLikeMode == 0) {
    specializeVanillaDestructors();
    bespoke::setLoggingEnabled(false);
  } else {
    bespoke::setLoggingEnabled(true);
  }

  

  if (!RuntimeOption::EvalEmitClsMethPointers) {
    RuntimeOption::EvalIsCompatibleClsMethType = false;
  }

  if (RuntimeOption::EvalArrayProvenance) {
    RuntimeOption::EvalJitForceVMRegSync = true;
  }

  
  
  RuntimeOption::EvalPureEnforceCalls = std::max( RuntimeOption::EvalPureEnforceCalls, RuntimeOption::EvalRxEnforceCalls);
  RuntimeOption::EvalPureVerifyBody = std::max( RuntimeOption::EvalPureVerifyBody, RuntimeOption::EvalRxVerifyBody);

  
  RepoOptions::setDefaults(config, ini);
}


}
