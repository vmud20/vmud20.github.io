












































void Curl_version_init(void);


void Curl_version_init(void)
{
  curl_version();
  curl_version_info(CURLVERSION_NOW);
}

char *curl_version(void)
{
  static bool initialized;
  static char version[200];
  char *ptr = version;
  size_t len;
  size_t left = sizeof(version);

  if(initialized)
    return version;

  strcpy(ptr, LIBCURL_NAME "/" LIBCURL_VERSION);
  len = strlen(ptr);
  left -= len;
  ptr += len;

  if(left > 1) {
    len = Curl_ssl_version(ptr + 1, left - 1);

    if(len > 0) {
      *ptr = ' ';
      left -= ++len;
      ptr += len;
    }
  }


  len = snprintf(ptr, left, " zlib/%s", zlibVersion());
  left -= len;
  ptr += len;


  
  len = snprintf(ptr, left, " c-ares/%s", ares_version(NULL));
  left -= len;
  ptr += len;


  if(stringprep_check_version(LIBIDN_REQUIRED_VERSION)) {
    len = snprintf(ptr, left, " libidn/%s", stringprep_check_version(NULL));
    left -= len;
    ptr += len;
  }


  len = snprintf(ptr, left, " libpsl/%s", psl_get_version());
  left -= len;
  ptr += len;


  len = snprintf(ptr, left, " WinIDN");
  left -= len;
  ptr += len;



  len = snprintf(ptr, left, " iconv/%d.%d", _LIBICONV_VERSION >> 8, _LIBICONV_VERSION & 255);

  
  len = snprintf(ptr, left, " iconv");

  left -= len;
  ptr += len;


  len = snprintf(ptr, left, " libssh2/%s", CURL_LIBSSH2_VERSION);
  left -= len;
  ptr += len;


  len = Curl_http2_ver(ptr, left);
  left -= len;
  ptr += len;


  {
    char suff[2];
    if(RTMP_LIB_VERSION & 0xff) {
      suff[0] = (RTMP_LIB_VERSION & 0xff) + 'a' - 1;
      suff[1] = '\0';
    }
    else suff[0] = '\0';

    snprintf(ptr, left, " librtmp/%d.%d%s", RTMP_LIB_VERSION >> 16, (RTMP_LIB_VERSION >> 8) & 0xff, suff);


  }


  initialized = true;
  return version;
}



static const char * const protocols[] = {

  "dict",   "file",   "ftp",   "ftps",   "gopher",   "http",   "https",   "imap",   "imaps",   "ldap",   "ldaps",    "pop3",   "pop3s",   "rtmp",   "rtsp",   "scp",   "sftp",    "smb",  "smbs",    "smtp",   "smtps",   "telnet",   "tftp",   NULL };








































































static curl_version_info_data version_info = {
  CURLVERSION_NOW, LIBCURL_VERSION, LIBCURL_VERSION_NUM, OS, 0  | CURL_VERSION_IPV6   | CURL_VERSION_SSL   | CURL_VERSION_NTLM   | CURL_VERSION_NTLM_WB   | CURL_VERSION_SPNEGO   | CURL_VERSION_KERBEROS5   | CURL_VERSION_GSSAPI   | CURL_VERSION_SSPI   | CURL_VERSION_LIBZ   | CURL_VERSION_DEBUG   | CURL_VERSION_CURLDEBUG   | CURL_VERSION_ASYNCHDNS   | CURL_VERSION_LARGEFILE   | CURL_VERSION_CONV   | CURL_VERSION_TLSAUTH_SRP   | CURL_VERSION_HTTP2   | CURL_VERSION_UNIX_SOCKETS   | CURL_VERSION_PSL  , NULL, 0, NULL, protocols, NULL, 0, NULL, 0, NULL, };





































































curl_version_info_data *curl_version_info(CURLversion stamp)
{
  static bool initialized;

  static char ssh_buffer[80];


  static char ssl_buffer[80];


  if(initialized)
    return &version_info;


  Curl_ssl_version(ssl_buffer, sizeof(ssl_buffer));
  version_info.ssl_version = ssl_buffer;



  version_info.libz_version = zlibVersion();
  


  {
    int aresnum;
    version_info.ares = ares_version(&aresnum);
    version_info.ares_num = aresnum;
  }


  
  version_info.libidn = stringprep_check_version(LIBIDN_REQUIRED_VERSION);
  if(version_info.libidn)
    version_info.features |= CURL_VERSION_IDN;

  version_info.features |= CURL_VERSION_IDN;




  version_info.iconv_ver_num = _LIBICONV_VERSION;

  
  version_info.iconv_ver_num = -1;




  snprintf(ssh_buffer, sizeof(ssh_buffer), "libssh2/%s", LIBSSH2_VERSION);
  version_info.libssh_version = ssh_buffer;


  (void)stamp; 

  initialized = true;
  return &version_info;
}
