



















































































static OSStatus SocketRead(SSLConnectionRef connection, void *data, size_t *dataLength)

{
  size_t bytesToGo = *dataLength;
  size_t initLen = bytesToGo;
  UInt8 *currData = (UInt8 *)data;
  
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)connection;
  int sock = connssl->ssl_sockfd;
  OSStatus rtn = noErr;
  size_t bytesRead;
  ssize_t rrtn;
  int theErr;

  *dataLength = 0;

  for(;;) {
    bytesRead = 0;
    rrtn = read(sock, currData, bytesToGo);
    if(rrtn <= 0) {
      
      theErr = errno;
      if(rrtn == 0) { 
        
        rtn = errSSLClosedGraceful;
      }
      else  switch(theErr) {
          case ENOENT:
            
            rtn = errSSLClosedGraceful;
            break;
          case ECONNRESET:
            rtn = errSSLClosedAbort;
            break;
          case EAGAIN:
            rtn = errSSLWouldBlock;
            connssl->ssl_direction = false;
            break;
          default:
            rtn = ioErr;
            break;
        }
      break;
    }
    else {
      bytesRead = rrtn;
    }
    bytesToGo -= bytesRead;
    currData  += bytesRead;

    if(bytesToGo == 0) {
      
      break;
    }
  }
  *dataLength = initLen - bytesToGo;

  return rtn;
}

static OSStatus SocketWrite(SSLConnectionRef connection, const void *data, size_t *dataLength)

{
  size_t bytesSent = 0;
  
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)connection;
  int sock = connssl->ssl_sockfd;
  ssize_t length;
  size_t dataLen = *dataLength;
  const UInt8 *dataPtr = (UInt8 *)data;
  OSStatus ortn;
  int theErr;

  *dataLength = 0;

  do {
    length = write(sock, (char *)dataPtr + bytesSent, dataLen - bytesSent);

  } while((length > 0) && ( (bytesSent += length) < dataLen) );

  if(length <= 0) {
    theErr = errno;
    if(theErr == EAGAIN) {
      ortn = errSSLWouldBlock;
      connssl->ssl_direction = true;
    }
    else {
      ortn = ioErr;
    }
  }
  else {
    ortn = noErr;
  }
  *dataLength = bytesSent;
  return ortn;
}


CF_INLINE const char *SSLCipherNameForNumber(SSLCipherSuite cipher)
{
  switch(cipher) {
    
    case SSL_RSA_WITH_NULL_MD5:
      return "SSL_RSA_WITH_NULL_MD5";
      break;
    case SSL_RSA_WITH_NULL_SHA:
      return "SSL_RSA_WITH_NULL_SHA";
      break;
    case SSL_RSA_EXPORT_WITH_RC4_40_MD5:
      return "SSL_RSA_EXPORT_WITH_RC4_40_MD5";
      break;
    case SSL_RSA_WITH_RC4_128_MD5:
      return "SSL_RSA_WITH_RC4_128_MD5";
      break;
    case SSL_RSA_WITH_RC4_128_SHA:
      return "SSL_RSA_WITH_RC4_128_SHA";
      break;
    case SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
      return "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5";
      break;
    case SSL_RSA_WITH_IDEA_CBC_SHA:
      return "SSL_RSA_WITH_IDEA_CBC_SHA";
      break;
    case SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_RSA_WITH_DES_CBC_SHA:
      return "SSL_RSA_WITH_DES_CBC_SHA";
      break;
    case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
      return "SSL_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DH_DSS_WITH_DES_CBC_SHA:
      return "SSL_DH_DSS_WITH_DES_CBC_SHA";
      break;
    case SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DH_RSA_WITH_DES_CBC_SHA:
      return "SSL_DH_RSA_WITH_DES_CBC_SHA";
      break;
    case SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DHE_DSS_WITH_DES_CBC_SHA:
      return "SSL_DHE_DSS_WITH_DES_CBC_SHA";
      break;
    case SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DHE_RSA_WITH_DES_CBC_SHA:
      return "SSL_DHE_RSA_WITH_DES_CBC_SHA";
      break;
    case SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DH_anon_EXPORT_WITH_RC4_40_MD5:
      return "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5";
      break;
    case SSL_DH_anon_WITH_RC4_128_MD5:
      return "SSL_DH_anon_WITH_RC4_128_MD5";
      break;
    case SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
      return "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
      break;
    case SSL_DH_anon_WITH_DES_CBC_SHA:
      return "SSL_DH_anon_WITH_DES_CBC_SHA";
      break;
    case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
      return "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_FORTEZZA_DMS_WITH_NULL_SHA:
      return "SSL_FORTEZZA_DMS_WITH_NULL_SHA";
      break;
    case SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA:
      return "SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA";
      break;
    
    case TLS_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
      return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
      return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
      break;
    case TLS_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
      return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
      return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
      break;
    
    case SSL_RSA_WITH_RC2_CBC_MD5:
      return "SSL_RSA_WITH_RC2_CBC_MD5";
      break;
    case SSL_RSA_WITH_IDEA_CBC_MD5:
      return "SSL_RSA_WITH_IDEA_CBC_MD5";
      break;
    case SSL_RSA_WITH_DES_CBC_MD5:
      return "SSL_RSA_WITH_DES_CBC_MD5";
      break;
    case SSL_RSA_WITH_3DES_EDE_CBC_MD5:
      return "SSL_RSA_WITH_3DES_EDE_CBC_MD5";
      break;
  }
  return "SSL_NULL_WITH_NULL_NULL";
}

CF_INLINE const char *TLSCipherNameForNumber(SSLCipherSuite cipher)
{
  switch(cipher) {
    
    case TLS_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
      return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
      return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
      break;
    case TLS_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
      return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
      return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
      break;

    
    case TLS_ECDH_ECDSA_WITH_NULL_SHA:
      return "TLS_ECDH_ECDSA_WITH_NULL_SHA";
      break;
    case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
      return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
      break;
    case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
      return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
      return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_NULL_SHA:
      return "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
      return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
      return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
      return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_ECDH_RSA_WITH_NULL_SHA:
      return "TLS_ECDH_RSA_WITH_NULL_SHA";
      break;
    case TLS_ECDH_RSA_WITH_RC4_128_SHA:
      return "TLS_ECDH_RSA_WITH_RC4_128_SHA";
      break;
    case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_NULL_SHA:
      return "TLS_ECDHE_RSA_WITH_NULL_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_RC4_128_SHA:
      return "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
      return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
      return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
      break;
    case TLS_ECDH_anon_WITH_NULL_SHA:
      return "TLS_ECDH_anon_WITH_NULL_SHA";
      break;
    case TLS_ECDH_anon_WITH_RC4_128_SHA:
      return "TLS_ECDH_anon_WITH_RC4_128_SHA";
      break;
    case TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
      return "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
      return "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
      break;
    case TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
      return "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
      break;


    
    case TLS_RSA_WITH_NULL_MD5:
      return "TLS_RSA_WITH_NULL_MD5";
      break;
    case TLS_RSA_WITH_NULL_SHA:
      return "TLS_RSA_WITH_NULL_SHA";
      break;
    case TLS_RSA_WITH_RC4_128_MD5:
      return "TLS_RSA_WITH_RC4_128_MD5";
      break;
    case TLS_RSA_WITH_RC4_128_SHA:
      return "TLS_RSA_WITH_RC4_128_SHA";
      break;
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_RSA_WITH_NULL_SHA256:
      return "TLS_RSA_WITH_NULL_SHA256";
      break;
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_RSA_WITH_AES_256_CBC_SHA256:
      return "TLS_RSA_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
      return "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
      return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
      return "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
      return "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
      return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
      return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
      break;
    case TLS_DH_anon_WITH_RC4_128_MD5:
      return "TLS_DH_anon_WITH_RC4_128_MD5";
      break;
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DH_anon_WITH_AES_128_CBC_SHA256:
      return "TLS_DH_anon_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DH_anon_WITH_AES_256_CBC_SHA256:
      return "TLS_DH_anon_WITH_AES_256_CBC_SHA256";
      break;
    
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
      return "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
      return "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
      return "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
      return "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DH_anon_WITH_AES_128_GCM_SHA256:
      return "TLS_DH_anon_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
      return "TLS_DH_anon_WITH_AES_256_GCM_SHA384";
      break;
    
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
      return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
      return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
      return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
      return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
      return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
      return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
      return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
      return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
      return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
      return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
      return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
      return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
      return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
      return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
      break;

    case SSL_RSA_WITH_NULL_MD5:
      return "TLS_RSA_WITH_NULL_MD5";
      break;
    case SSL_RSA_WITH_NULL_SHA:
      return "TLS_RSA_WITH_NULL_SHA";
      break;
    case SSL_RSA_WITH_RC4_128_MD5:
      return "TLS_RSA_WITH_RC4_128_MD5";
      break;
    case SSL_RSA_WITH_RC4_128_SHA:
      return "TLS_RSA_WITH_RC4_128_SHA";
      break;
    case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
      return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
      break;
    case SSL_DH_anon_WITH_RC4_128_MD5:
      return "TLS_DH_anon_WITH_RC4_128_MD5";
      break;
    case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
      break;


    
    case TLS_PSK_WITH_RC4_128_SHA:
      return "TLS_PSK_WITH_RC4_128_SHA";
      break;
    case TLS_PSK_WITH_3DES_EDE_CBC_SHA:
      return "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_PSK_WITH_AES_128_CBC_SHA:
      return "TLS_PSK_WITH_AES_128_CBC_SHA";
      break;
    case TLS_PSK_WITH_AES_256_CBC_SHA:
      return "TLS_PSK_WITH_AES_256_CBC_SHA";
      break;
    case TLS_DHE_PSK_WITH_RC4_128_SHA:
      return "TLS_DHE_PSK_WITH_RC4_128_SHA";
      break;
    case TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
      return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
      return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
      break;
    case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
      return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA";
      break;
    case TLS_RSA_PSK_WITH_RC4_128_SHA:
      return "TLS_RSA_PSK_WITH_RC4_128_SHA";
      break;
    case TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
      return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA";
      break;
    case TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
      return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA";
      break;
    case TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
      return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA";
      break;
    
    case TLS_PSK_WITH_NULL_SHA:
      return "TLS_PSK_WITH_NULL_SHA";
      break;
    case TLS_DHE_PSK_WITH_NULL_SHA:
      return "TLS_DHE_PSK_WITH_NULL_SHA";
      break;
    case TLS_RSA_PSK_WITH_NULL_SHA:
      return "TLS_RSA_PSK_WITH_NULL_SHA";
      break;
    
    case TLS_PSK_WITH_AES_128_GCM_SHA256:
      return "TLS_PSK_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
      return "TLS_PSK_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
      return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
      return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
      return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
      break;
    case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
      return "TLS_PSK_WITH_AES_256_GCM_SHA384";
      break;
    case TLS_PSK_WITH_AES_128_CBC_SHA256:
      return "TLS_PSK_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_PSK_WITH_AES_256_CBC_SHA384:
      return "TLS_PSK_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_PSK_WITH_NULL_SHA256:
      return "TLS_PSK_WITH_NULL_SHA256";
      break;
    case TLS_PSK_WITH_NULL_SHA384:
      return "TLS_PSK_WITH_NULL_SHA384";
      break;
    case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
      return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
      return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_DHE_PSK_WITH_NULL_SHA256:
      return "TLS_DHE_PSK_WITH_NULL_SHA256";
      break;
    case TLS_DHE_PSK_WITH_NULL_SHA384:
      return "TLS_RSA_PSK_WITH_NULL_SHA384";
      break;
    case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
      return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256";
      break;
    case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
      return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384";
      break;
    case TLS_RSA_PSK_WITH_NULL_SHA256:
      return "TLS_RSA_PSK_WITH_NULL_SHA256";
      break;
    case TLS_RSA_PSK_WITH_NULL_SHA384:
      return "TLS_RSA_PSK_WITH_NULL_SHA384";
      break;

  }
  return "TLS_NULL_WITH_NULL_NULL";
}



CF_INLINE void GetDarwinVersionNumber(int *major, int *minor)
{
  int mib[2];
  char *os_version;
  size_t os_version_len;
  char *os_version_major, *os_version_minor;
  char *tok_buf;

  
  mib[0] = CTL_KERN;
  mib[1] = KERN_OSRELEASE;
  if(sysctl(mib, 2, NULL, &os_version_len, NULL, 0) == -1)
    return;
  os_version = malloc(os_version_len*sizeof(char));
  if(!os_version)
    return;
  if(sysctl(mib, 2, os_version, &os_version_len, NULL, 0) == -1) {
    free(os_version);
    return;
  }

  
  os_version_major = strtok_r(os_version, ".", &tok_buf);
  os_version_minor = strtok_r(NULL, ".", &tok_buf);
  *major = atoi(os_version_major);
  *minor = atoi(os_version_minor);
  free(os_version);
}



CF_INLINE CFStringRef CopyCertSubject(SecCertificateRef cert)
{
  CFStringRef server_cert_summary = CFSTR("(null)");


  
  server_cert_summary = SecCertificateCopySubjectSummary(cert);


  
  if(SecCertificateCopyLongDescription != NULL)
    server_cert_summary = SecCertificateCopyLongDescription(NULL, cert, NULL);
  else    if(SecCertificateCopySubjectSummary != NULL)



    server_cert_summary = SecCertificateCopySubjectSummary(cert);
  else   (void)SecCertificateCopyCommonName(cert, &server_cert_summary);



  return server_cert_summary;
}



static OSStatus CopyIdentityWithLabelOldSchool(char *label, SecIdentityRef *out_c_a_k)
{
  OSStatus status = errSecItemNotFound;
  SecKeychainAttributeList attr_list;
  SecKeychainAttribute attr;
  SecKeychainSearchRef search = NULL;
  SecCertificateRef cert = NULL;

  
  attr_list.count = 1L;
  attr_list.attr = &attr;

  
  attr.tag = kSecLabelItemAttr;
  attr.data = label;
  attr.length = (UInt32)strlen(label);

  
  status = SecKeychainSearchCreateFromAttributes(NULL, kSecCertificateItemClass, &attr_list, &search);


  if(status == noErr) {
    status = SecKeychainSearchCopyNext(search, (SecKeychainItemRef *)&cert);
    if(status == noErr && cert) {
      
      status = SecIdentityCreateWithCertificate(NULL, cert, out_c_a_k);
      CFRelease(cert);
    }
  }

  if(search)
    CFRelease(search);
  return status;
}


static OSStatus CopyIdentityWithLabel(char *label, SecIdentityRef *out_cert_and_key)
{
  OSStatus status = errSecItemNotFound;


  CFArrayRef keys_list;
  CFIndex keys_list_count;
  CFIndex i;
  CFStringRef common_name;

  
  if(SecItemCopyMatching != NULL && kSecClassIdentity != NULL) {
    CFTypeRef keys[5];
    CFTypeRef values[5];
    CFDictionaryRef query_dict;
    CFStringRef label_cf = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);

    
    values[0] = kSecClassIdentity; 
    keys[0] = kSecClass;
    values[1] = kCFBooleanTrue;    
    keys[1] = kSecReturnRef;
    values[2] = kSecMatchLimitAll; 
    keys[2] = kSecMatchLimit;
    
    values[3] = SecPolicyCreateSSL(false, NULL);
    keys[3] = kSecMatchPolicy;
    
    values[4] = label_cf;
    keys[4] = kSecAttrLabel;
    query_dict = CFDictionaryCreate(NULL, (const void **)keys, (const void **)values, 5L, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);


    CFRelease(values[3]);

    
    status = SecItemCopyMatching(query_dict, (CFTypeRef *) &keys_list);

    
    if(status == noErr) {
      keys_list_count = CFArrayGetCount(keys_list);
      *out_cert_and_key = NULL;
      status = 1;
      for(i=0; i<keys_list_count; i++) {
        OSStatus err = noErr;
        SecCertificateRef cert = NULL;
        SecIdentityRef identity = (SecIdentityRef) CFArrayGetValueAtIndex(keys_list, i);
        err = SecIdentityCopyCertificate(identity, &cert);
        if(err == noErr) {

          common_name = SecCertificateCopySubjectSummary(cert);

          SecCertificateCopyCommonName(cert, &common_name);

          if(CFStringCompare(common_name, label_cf, 0) == kCFCompareEqualTo) {
            CFRelease(cert);
            CFRelease(common_name);
            CFRetain(identity);
            *out_cert_and_key = identity;
            status = noErr;
            break;
          }
          CFRelease(common_name);
        }
        CFRelease(cert);
      }
    }

    if(keys_list)
      CFRelease(keys_list);
    CFRelease(query_dict);
    CFRelease(label_cf);
  }
  else {

    
    status = CopyIdentityWithLabelOldSchool(label, out_cert_and_key);

  }

  
  status = CopyIdentityWithLabelOldSchool(label, out_cert_and_key);

  return status;
}

static OSStatus CopyIdentityFromPKCS12File(const char *cPath, const char *cPassword, SecIdentityRef *out_cert_and_key)

{
  OSStatus status = errSecItemNotFound;
  CFURLRef pkcs_url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)cPath, strlen(cPath), false);
  CFStringRef password = cPassword ? CFStringCreateWithCString(NULL, cPassword, kCFStringEncodingUTF8) : NULL;
  CFDataRef pkcs_data = NULL;

  
  

  if(CFURLCreateDataAndPropertiesFromResource(NULL, pkcs_url, &pkcs_data, NULL, NULL, &status)) {
    const void *cKeys[] = {kSecImportExportPassphrase};
    const void *cValues[] = {password};
    CFDictionaryRef options = CFDictionaryCreate(NULL, cKeys, cValues, password ? 1L : 0L, NULL, NULL);
    CFArrayRef items = NULL;

    
    status = SecPKCS12Import(pkcs_data, options, &items);
    if(status == errSecSuccess && items && CFArrayGetCount(items)) {
      CFDictionaryRef identity_and_trust = CFArrayGetValueAtIndex(items, 0L);
      const void *temp_identity = CFDictionaryGetValue(identity_and_trust, kSecImportItemIdentity);

      
      CFRetain(temp_identity);
      *out_cert_and_key = (SecIdentityRef)temp_identity;
    }

    if(items)
      CFRelease(items);
    CFRelease(options);
    CFRelease(pkcs_data);
  }

  if(password)
    CFRelease(password);
  CFRelease(pkcs_url);
  return status;
}


CF_INLINE bool is_file(const char *filename)
{
  struct_stat st;

  if(filename == NULL)
    return false;

  if(stat(filename, &st) == 0)
    return S_ISREG(st.st_mode);
  return false;
}


static CURLcode darwinssl_version_from_curl(long *darwinver, long ssl_version)
{
  switch(ssl_version) {
    case CURL_SSLVERSION_TLSv1_0:
      *darwinver = kTLSProtocol1;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_1:
      *darwinver = kTLSProtocol11;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_2:
      *darwinver = kTLSProtocol12;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_3:
      break;
  }
  return CURLE_SSL_CONNECT_ERROR;
}


static CURLcode set_ssl_version_min_max(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  long ssl_version = SSL_CONN_CONFIG(version);
  long ssl_version_max = SSL_CONN_CONFIG(version_max);

  switch(ssl_version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      ssl_version = CURL_SSLVERSION_TLSv1_0;
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }

  switch(ssl_version_max) {
    case CURL_SSLVERSION_MAX_NONE:
      ssl_version_max = ssl_version << 16;
      break;
    case CURL_SSLVERSION_MAX_DEFAULT:
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }


  if(SSLSetProtocolVersionMax != NULL) {
    SSLProtocol darwin_ver_min = kTLSProtocol1;
    SSLProtocol darwin_ver_max = kTLSProtocol1;
    CURLcode result = darwinssl_version_from_curl(&darwin_ver_min, ssl_version);
    if(result) {
      failf(data, "unsupported min version passed via CURLOPT_SSLVERSION");
      return result;
    }
    result = darwinssl_version_from_curl(&darwin_ver_max, ssl_version_max >> 16);
    if(result) {
      failf(data, "unsupported max version passed via CURLOPT_SSLVERSION");
      return result;
    }

    (void)SSLSetProtocolVersionMin(connssl->ssl_ctx, darwin_ver_min);
    (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, darwin_ver_max);
    return result;
  }
  else {

    long i = ssl_version;
    (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocolAll, false);

    for(; i <= (ssl_version_max >> 16); i++) {
      switch(i) {
        case CURL_SSLVERSION_TLSv1_0:
          (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kTLSProtocol1, true);

          break;
        case CURL_SSLVERSION_TLSv1_1:
          (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kTLSProtocol11, true);

          break;
        case CURL_SSLVERSION_TLSv1_2:
          (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kTLSProtocol12, true);

          break;
        case CURL_SSLVERSION_TLSv1_3:
          failf(data, "DarwinSSL: TLS 1.3 is not yet supported");
          return CURLE_SSL_CONNECT_ERROR;
      }
    }
    return CURLE_OK;

  }

  failf(data, "DarwinSSL: cannot set SSL protocol");
  return CURLE_SSL_CONNECT_ERROR;
}


static CURLcode darwinssl_connect_step1(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  const char * const ssl_cafile = SSL_CONN_CONFIG(CAfile);
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  char * const ssl_cert = SSL_SET_OPTION(cert);
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;
  const long int port = SSL_IS_PROXY() ? conn->port : conn->remote_port;

  struct in6_addr addr;

  struct in_addr addr;

  size_t all_ciphers_count = 0UL, allowed_ciphers_count = 0UL, i;
  SSLCipherSuite *all_ciphers = NULL, *allowed_ciphers = NULL;
  OSStatus err = noErr;

  int darwinver_maj = 0, darwinver_min = 0;

  GetDarwinVersionNumber(&darwinver_maj, &darwinver_min);



  if(SSLCreateContext != NULL) {  
    if(connssl->ssl_ctx)
      CFRelease(connssl->ssl_ctx);
    connssl->ssl_ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if(!connssl->ssl_ctx) {
      failf(data, "SSL: couldn't create a context!");
      return CURLE_OUT_OF_MEMORY;
    }
  }
  else {
  

    if(connssl->ssl_ctx)
      (void)SSLDisposeContext(connssl->ssl_ctx);
    err = SSLNewContext(false, &(connssl->ssl_ctx));
    if(err != noErr) {
      failf(data, "SSL: couldn't create a context: OSStatus %d", err);
      return CURLE_OUT_OF_MEMORY;
    }

  }

  if(connssl->ssl_ctx)
    (void)SSLDisposeContext(connssl->ssl_ctx);
  err = SSLNewContext(false, &(connssl->ssl_ctx));
  if(err != noErr) {
    failf(data, "SSL: couldn't create a context: OSStatus %d", err);
    return CURLE_OUT_OF_MEMORY;
  }

  connssl->ssl_write_buffered_length = 0UL; 

  

  if(SSLSetProtocolVersionMax != NULL) {
    switch(conn->ssl_config.version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      (void)SSLSetProtocolVersionMin(connssl->ssl_ctx, kTLSProtocol1);
      (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kTLSProtocol12);
      break;
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1_1:
    case CURL_SSLVERSION_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_3:
      {
        CURLcode result = set_ssl_version_min_max(conn, sockindex);
        if(result != CURLE_OK)
          return result;
        break;
      }
    case CURL_SSLVERSION_SSLv3:
      err = SSLSetProtocolVersionMin(connssl->ssl_ctx, kSSLProtocol3);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv3");
        return CURLE_SSL_CONNECT_ERROR;
      }
      (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kSSLProtocol3);
      break;
    case CURL_SSLVERSION_SSLv2:
      err = SSLSetProtocolVersionMin(connssl->ssl_ctx, kSSLProtocol2);
      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv2");
        return CURLE_SSL_CONNECT_ERROR;
      }
      (void)SSLSetProtocolVersionMax(connssl->ssl_ctx, kSSLProtocol2);
      break;
    default:
      failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {

    (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocolAll, false);

    switch(conn->ssl_config.version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kTLSProtocol1, true);

      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kTLSProtocol11, true);

      (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kTLSProtocol12, true);

      break;
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1_1:
    case CURL_SSLVERSION_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_3:
      {
        CURLcode result = set_ssl_version_min_max(conn, sockindex);
        if(result != CURLE_OK)
          return result;
        break;
      }
    case CURL_SSLVERSION_SSLv3:
      err = SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocol3, true);

      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv3");
        return CURLE_SSL_CONNECT_ERROR;
      }
      break;
    case CURL_SSLVERSION_SSLv2:
      err = SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocol2, true);

      if(err != noErr) {
        failf(data, "Your version of the OS does not support SSLv2");
        return CURLE_SSL_CONNECT_ERROR;
      }
      break;
    default:
      failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
    }

  }

  if(conn->ssl_config.version_max != CURL_SSLVERSION_MAX_NONE) {
    failf(data, "Your version of the OS does not support to set maximum" " SSL/TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }
  (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocolAll, false);
  switch(conn->ssl_config.version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
    (void)SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kTLSProtocol1, true);

    break;
  case CURL_SSLVERSION_TLSv1_1:
    failf(data, "Your version of the OS does not support TLSv1.1");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_TLSv1_2:
    failf(data, "Your version of the OS does not support TLSv1.2");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_TLSv1_3:
    failf(data, "Your version of the OS does not support TLSv1.3");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_SSLv2:
    err = SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocol2, true);

    if(err != noErr) {
      failf(data, "Your version of the OS does not support SSLv2");
      return CURLE_SSL_CONNECT_ERROR;
    }
    break;
  case CURL_SSLVERSION_SSLv3:
    err = SSLSetProtocolVersionEnabled(connssl->ssl_ctx, kSSLProtocol3, true);

    if(err != noErr) {
      failf(data, "Your version of the OS does not support SSLv3");
      return CURLE_SSL_CONNECT_ERROR;
    }
    break;
  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }


  if(SSL_SET_OPTION(key)) {
    infof(data, "WARNING: SSL: CURLOPT_SSLKEY is ignored by Secure " "Transport. The private key must be in the Keychain.\n");
  }

  if(ssl_cert) {
    SecIdentityRef cert_and_key = NULL;
    bool is_cert_file = is_file(ssl_cert);

    
    if(is_cert_file) {
      if(!SSL_SET_OPTION(cert_type))
        infof(data, "WARNING: SSL: Certificate type not set, assuming " "PKCS#12 format.\n");
      else if(strncmp(SSL_SET_OPTION(cert_type), "P12", strlen(SSL_SET_OPTION(cert_type))) != 0)
        infof(data, "WARNING: SSL: The Security framework only supports " "loading identities that are in PKCS#12 format.\n");

      err = CopyIdentityFromPKCS12File(ssl_cert, SSL_SET_OPTION(key_passwd), &cert_and_key);
    }
    else err = CopyIdentityWithLabel(ssl_cert, &cert_and_key);

    if(err == noErr) {
      SecCertificateRef cert = NULL;
      CFTypeRef certs_c[1];
      CFArrayRef certs;

      
      err = SecIdentityCopyCertificate(cert_and_key, &cert);
      if(err == noErr) {
        CFStringRef cert_summary = CopyCertSubject(cert);
        char cert_summary_c[128];

        if(cert_summary) {
          memset(cert_summary_c, 0, 128);
          if(CFStringGetCString(cert_summary, cert_summary_c, 128, kCFStringEncodingUTF8)) {


            infof(data, "Client certificate: %s\n", cert_summary_c);
          }
          CFRelease(cert_summary);
          CFRelease(cert);
        }
      }
      certs_c[0] = cert_and_key;
      certs = CFArrayCreate(NULL, (const void **)certs_c, 1L, &kCFTypeArrayCallBacks);
      err = SSLSetCertificate(connssl->ssl_ctx, certs);
      if(certs)
        CFRelease(certs);
      if(err != noErr) {
        failf(data, "SSL: SSLSetCertificate() failed: OSStatus %d", err);
        return CURLE_SSL_CERTPROBLEM;
      }
      CFRelease(cert_and_key);
    }
    else {
      switch(err) {
      case errSecAuthFailed: case -25264: 
        failf(data, "SSL: Incorrect password for the certificate \"%s\" " "and its private key.", ssl_cert);
        break;
      case -26275:  case -25257: 
        failf(data, "SSL: Couldn't make sense of the data in the " "certificate \"%s\" and its private key.", ssl_cert);

        break;
      case -25260: 
        failf(data, "SSL The certificate \"%s\" requires a password.", ssl_cert);
        break;
      case errSecItemNotFound:
        failf(data, "SSL: Can't find the certificate \"%s\" and its private " "key in the Keychain.", ssl_cert);
        break;
      default:
        failf(data, "SSL: Can't load the certificate \"%s\" and its private " "key: OSStatus %d", ssl_cert, err);
        break;
      }
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  

  

  if(SSLSetSessionOption != NULL && darwinver_maj >= 13) {

  if(SSLSetSessionOption != NULL) {

    bool break_on_auth = !conn->ssl_config.verifypeer || ssl_cafile;
    err = SSLSetSessionOption(connssl->ssl_ctx, kSSLSessionOptionBreakOnServerAuth, break_on_auth);

    if(err != noErr) {
      failf(data, "SSL: SSLSetSessionOption() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {

    err = SSLSetEnableCertVerify(connssl->ssl_ctx, conn->ssl_config.verifypeer?true:false);
    if(err != noErr) {
      failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }

  }

  err = SSLSetEnableCertVerify(connssl->ssl_ctx, conn->ssl_config.verifypeer?true:false);
  if(err != noErr) {
    failf(data, "SSL: SSLSetEnableCertVerify() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }


  if(ssl_cafile && verifypeer) {
    bool is_cert_file = is_file(ssl_cafile);

    if(!is_cert_file) {
      failf(data, "SSL: can't load CA certificate file %s", ssl_cafile);
      return CURLE_SSL_CACERT_BADFILE;
    }
  }

  
  if(conn->ssl_config.verifyhost) {
    err = SSLSetPeerDomainName(connssl->ssl_ctx, hostname, strlen(hostname));

    if(err != noErr) {
      infof(data, "WARNING: SSL: SSLSetPeerDomainName() failed: OSStatus %d\n", err);
    }

    if((Curl_inet_pton(AF_INET, hostname, &addr))
  #ifdef ENABLE_IPV6
    || (Curl_inet_pton(AF_INET6, hostname, &addr))
  #endif
       ) {
      infof(data, "WARNING: using IP address, SNI is being disabled by " "the OS.\n");
    }
  }
  else {
    infof(data, "WARNING: disabling hostname validation also disables SNI.\n");
  }

  
  (void)SSLGetNumberSupportedCiphers(connssl->ssl_ctx, &all_ciphers_count);
  all_ciphers = malloc(all_ciphers_count*sizeof(SSLCipherSuite));
  allowed_ciphers = malloc(all_ciphers_count*sizeof(SSLCipherSuite));
  if(all_ciphers && allowed_ciphers && SSLGetSupportedCiphers(connssl->ssl_ctx, all_ciphers, &all_ciphers_count) == noErr) {

    for(i = 0UL ; i < all_ciphers_count ; i++) {

     
      if(darwinver_maj == 12 && darwinver_min <= 3 && all_ciphers[i] >= 0xC001 && all_ciphers[i] <= 0xC032) {
        continue;
      }

      switch(all_ciphers[i]) {
        
        case SSL_NULL_WITH_NULL_NULL:
        case SSL_RSA_WITH_NULL_MD5:
        case SSL_RSA_WITH_NULL_SHA:
        case 0x003B: 
        case SSL_FORTEZZA_DMS_WITH_NULL_SHA:
        case 0xC001: 
        case 0xC006: 
        case 0xC00B: 
        case 0xC010: 
        case 0x002C: 
        case 0x002D: 
        case 0x002E: 
        case 0x00B0: 
        case 0x00B1: 
        case 0x00B4: 
        case 0x00B5: 
        case 0x00B8: 
        case 0x00B9: 
        
        case SSL_DH_anon_EXPORT_WITH_RC4_40_MD5:
        case SSL_DH_anon_WITH_RC4_128_MD5:
        case SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_anon_WITH_DES_CBC_SHA:
        case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
        case TLS_DH_anon_WITH_AES_128_CBC_SHA:
        case TLS_DH_anon_WITH_AES_256_CBC_SHA:
        case 0xC015: 
        case 0xC016: 
        case 0xC017: 
        case 0xC018: 
        case 0xC019: 
        case 0x006C: 
        case 0x006D: 
        case 0x00A6: 
        case 0x00A7: 
        
        case SSL_RSA_EXPORT_WITH_RC4_40_MD5:
        case SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
        case SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
        case SSL_RSA_WITH_DES_CBC_SHA:
        case SSL_DH_DSS_WITH_DES_CBC_SHA:
        case SSL_DH_RSA_WITH_DES_CBC_SHA:
        case SSL_DHE_DSS_WITH_DES_CBC_SHA:
        case SSL_DHE_RSA_WITH_DES_CBC_SHA:
        
        case SSL_RSA_WITH_IDEA_CBC_SHA:
        case SSL_RSA_WITH_IDEA_CBC_MD5:
        
        case SSL_RSA_WITH_RC4_128_MD5:
        case SSL_RSA_WITH_RC4_128_SHA:
        case 0xC002: 
        case 0xC007: 
        case 0xC00C: 
        case 0xC011: 
        case 0x008A: 
        case 0x008E: 
        case 0x0092: 
          break;
        default: 
          allowed_ciphers[allowed_ciphers_count++] = all_ciphers[i];
          break;
      }
    }
    err = SSLSetEnabledCiphers(connssl->ssl_ctx, allowed_ciphers, allowed_ciphers_count);
    if(err != noErr) {
      failf(data, "SSL: SSLSetEnabledCiphers() failed: OSStatus %d", err);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
    Curl_safefree(all_ciphers);
    Curl_safefree(allowed_ciphers);
    failf(data, "SSL: Failed to allocate memory for allowed ciphers");
    return CURLE_OUT_OF_MEMORY;
  }
  Curl_safefree(all_ciphers);
  Curl_safefree(allowed_ciphers);


  
  if(SSLSetSessionOption != NULL) {
    
    SSLSetSessionOption(connssl->ssl_ctx, kSSLSessionOptionSendOneByteRecord, !data->set.ssl.enable_beast);
    SSLSetSessionOption(connssl->ssl_ctx, kSSLSessionOptionFalseStart, data->set.ssl.falsestart);
  }


  
  if(data->set.general_ssl.sessionid) {
    char *ssl_sessionid;
    size_t ssl_sessionid_len;

    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, (void **)&ssl_sessionid, &ssl_sessionid_len, sockindex)) {
      
      err = SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
      Curl_ssl_sessionid_unlock(conn);
      if(err != noErr) {
        failf(data, "SSL: SSLSetPeerID() failed: OSStatus %d", err);
        return CURLE_SSL_CONNECT_ERROR;
      }
      
      infof(data, "SSL re-using session ID\n");
    }
    
    else {
      CURLcode result;
      ssl_sessionid = aprintf("%s:%d:%d:%s:%hu", ssl_cafile, verifypeer, SSL_CONN_CONFIG(verifyhost), hostname, port);

      ssl_sessionid_len = strlen(ssl_sessionid);

      err = SSLSetPeerID(connssl->ssl_ctx, ssl_sessionid, ssl_sessionid_len);
      if(err != noErr) {
        Curl_ssl_sessionid_unlock(conn);
        failf(data, "SSL: SSLSetPeerID() failed: OSStatus %d", err);
        return CURLE_SSL_CONNECT_ERROR;
      }

      result = Curl_ssl_addsessionid(conn, ssl_sessionid, ssl_sessionid_len, sockindex);
      Curl_ssl_sessionid_unlock(conn);
      if(result) {
        failf(data, "failed to store ssl session");
        return result;
      }
    }
  }

  err = SSLSetIOFuncs(connssl->ssl_ctx, SocketRead, SocketWrite);
  if(err != noErr) {
    failf(data, "SSL: SSLSetIOFuncs() failed: OSStatus %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  
  
  connssl->ssl_sockfd = sockfd;
  err = SSLSetConnection(connssl->ssl_ctx, connssl);
  if(err != noErr) {
    failf(data, "SSL: SSLSetConnection() failed: %d", err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

static long pem_to_der(const char *in, unsigned char **out, size_t *outlen)
{
  char *sep_start, *sep_end, *cert_start, *cert_end;
  size_t i, j, err;
  size_t len;
  unsigned char *b64;

  
  sep_start = strstr(in, "-----");
  if(sep_start == NULL)
    return 0;
  cert_start = strstr(sep_start + 1, "-----");
  if(cert_start == NULL)
    return -1;

  cert_start += 5;

  
  cert_end = strstr(cert_start, "-----");
  if(cert_end == NULL)
    return -1;

  sep_end = strstr(cert_end + 1, "-----");
  if(sep_end == NULL)
    return -1;
  sep_end += 5;

  len = cert_end - cert_start;
  b64 = malloc(len + 1);
  if(!b64)
    return -1;

  
  for(i = 0, j = 0; i < len; i++) {
    if(cert_start[i] != '\r' && cert_start[i] != '\n')
      b64[j++] = cert_start[i];
  }
  b64[j] = '\0';

  err = Curl_base64_decode((const char *)b64, out, outlen);
  free(b64);
  if(err) {
    free(*out);
    return -1;
  }

  return sep_end - in;
}

static int read_cert(const char *file, unsigned char **out, size_t *outlen)
{
  int fd;
  ssize_t n, len = 0, cap = 512;
  unsigned char buf[cap], *data;

  fd = open(file, 0);
  if(fd < 0)
    return -1;

  data = malloc(cap);
  if(!data) {
    close(fd);
    return -1;
  }

  for(;;) {
    n = read(fd, buf, sizeof(buf));
    if(n < 0) {
      close(fd);
      free(data);
      return -1;
    }
    else if(n == 0) {
      close(fd);
      break;
    }

    if(len + n >= cap) {
      cap *= 2;
      data = realloc(data, cap);
      if(!data) {
        close(fd);
        return -1;
      }
    }

    memcpy(data + len, buf, n);
    len += n;
  }
  data[len] = '\0';

  *out = data;
  *outlen = len;

  return 0;
}

static int sslerr_to_curlerr(struct Curl_easy *data, int err)
{
  switch(err) {
    case errSSLXCertChainInvalid:
      failf(data, "SSL certificate problem: Invalid certificate chain");
      return CURLE_SSL_CACERT;
    case errSSLUnknownRootCert:
      failf(data, "SSL certificate problem: Untrusted root certificate");
      return CURLE_SSL_CACERT;
    case errSSLNoRootCert:
      failf(data, "SSL certificate problem: No root certificate");
      return CURLE_SSL_CACERT;
    case errSSLCertExpired:
      failf(data, "SSL certificate problem: Certificate chain had an " "expired certificate");
      return CURLE_SSL_CACERT;
    case errSSLBadCert:
      failf(data, "SSL certificate problem: Couldn't understand the server " "certificate format");
      return CURLE_SSL_CONNECT_ERROR;
    case errSSLHostNameMismatch:
      failf(data, "SSL certificate peer hostname mismatch");
      return CURLE_PEER_FAILED_VERIFICATION;
    default:
      failf(data, "SSL unexpected certificate error %d", err);
      return CURLE_SSL_CACERT;
  }
}

static int append_cert_to_array(struct Curl_easy *data, unsigned char *buf, size_t buflen, CFMutableArrayRef array)

{
    CFDataRef certdata = CFDataCreate(kCFAllocatorDefault, buf, buflen);
    if(!certdata) {
      failf(data, "SSL: failed to allocate array for CA certificate");
      return CURLE_OUT_OF_MEMORY;
    }

    SecCertificateRef cacert = SecCertificateCreateWithData(kCFAllocatorDefault, certdata);
    CFRelease(certdata);
    if(!cacert) {
      failf(data, "SSL: failed to create SecCertificate from CA certificate");
      return CURLE_SSL_CACERT;
    }

    
    CFStringRef subject = CopyCertSubject(cacert);
    if(subject) {
      char subject_cbuf[128];
      memset(subject_cbuf, 0, 128);
      if(!CFStringGetCString(subject, subject_cbuf, 128, kCFStringEncodingUTF8)) {


        CFRelease(cacert);
        failf(data, "SSL: invalid CA certificate subject");
        return CURLE_SSL_CACERT;
      }
      CFRelease(subject);
    }
    else {
      CFRelease(cacert);
      failf(data, "SSL: invalid CA certificate");
      return CURLE_SSL_CACERT;
    }

    CFArrayAppendValue(array, cacert);
    CFRelease(cacert);

    return CURLE_OK;
}

static int verify_cert(const char *cafile, struct Curl_easy *data, SSLContextRef ctx)
{
  int n = 0, rc;
  long res;
  unsigned char *certbuf, *der;
  size_t buflen, derlen, offset = 0;

  if(read_cert(cafile, &certbuf, &buflen) < 0) {
    failf(data, "SSL: failed to read or invalid CA certificate");
    return CURLE_SSL_CACERT;
  }

  
  CFMutableArrayRef array = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  if(array == NULL) {
    free(certbuf);
    failf(data, "SSL: out of memory creating CA certificate array");
    return CURLE_OUT_OF_MEMORY;
  }

  while(offset < buflen) {
    n++;

    
    res = pem_to_der((const char *)certbuf + offset, &der, &derlen);
    if(res < 0) {
      free(certbuf);
      CFRelease(array);
      failf(data, "SSL: invalid CA certificate #%d (offset %d) in bundle", n, offset);
      return CURLE_SSL_CACERT;
    }
    offset += res;

    if(res == 0 && offset == 0) {
      
      rc = append_cert_to_array(data, certbuf, buflen, array);
      free(certbuf);
      if(rc != CURLE_OK) {
        CFRelease(array);
        return rc;
      }
      break;
    }
    else if(res == 0) {
      
      free(certbuf);
      break;
    }

    rc = append_cert_to_array(data, der, derlen, array);
    free(der);
    if(rc != CURLE_OK) {
      free(certbuf);
      CFRelease(array);
      return rc;
    }
  }

  SecTrustRef trust;
  OSStatus ret = SSLCopyPeerTrust(ctx, &trust);
  if(trust == NULL) {
    failf(data, "SSL: error getting certificate chain");
    CFRelease(array);
    return CURLE_OUT_OF_MEMORY;
  }
  else if(ret != noErr) {
    CFRelease(array);
    return sslerr_to_curlerr(data, ret);
  }

  ret = SecTrustSetAnchorCertificates(trust, array);
  if(ret != noErr) {
    CFRelease(trust);
    return sslerr_to_curlerr(data, ret);
  }
  ret = SecTrustSetAnchorCertificatesOnly(trust, true);
  if(ret != noErr) {
    CFRelease(trust);
    return sslerr_to_curlerr(data, ret);
  }

  SecTrustResultType trust_eval = 0;
  ret = SecTrustEvaluate(trust, &trust_eval);
  CFRelease(array);
  CFRelease(trust);
  if(ret != noErr) {
    return sslerr_to_curlerr(data, ret);
  }

  switch(trust_eval) {
    case kSecTrustResultUnspecified:
    case kSecTrustResultProceed:
      return CURLE_OK;

    case kSecTrustResultRecoverableTrustFailure:
    case kSecTrustResultDeny:
    default:
      failf(data, "SSL: certificate verification failed (result: %d)", trust_eval);
      return CURLE_PEER_FAILED_VERIFICATION;
  }
}

static CURLcode darwinssl_connect_step2(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  OSStatus err;
  SSLCipherSuite cipher;
  SSLProtocol protocol = 0;
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;

  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state);


  
  err = SSLHandshake(connssl->ssl_ctx);

  if(err != noErr) {
    switch(err) {
      case errSSLWouldBlock:  
        connssl->connecting_state = connssl->ssl_direction ? ssl_connect_2_writing : ssl_connect_2_reading;
        return CURLE_OK;

      
      case -9841:
        if(SSL_CONN_CONFIG(CAfile) && SSL_CONN_CONFIG(verifypeer)) {
          int res = verify_cert(SSL_CONN_CONFIG(CAfile), data, connssl->ssl_ctx);
          if(res != CURLE_OK)
            return res;
        }
        
        return darwinssl_connect_step2(conn, sockindex);

      
      case errSSLXCertChainInvalid:
        failf(data, "SSL certificate problem: Invalid certificate chain");
        return CURLE_SSL_CACERT;
      case errSSLUnknownRootCert:
        failf(data, "SSL certificate problem: Untrusted root certificate");
        return CURLE_SSL_CACERT;
      case errSSLNoRootCert:
        failf(data, "SSL certificate problem: No root certificate");
        return CURLE_SSL_CACERT;
      case errSSLCertExpired:
        failf(data, "SSL certificate problem: Certificate chain had an " "expired certificate");
        return CURLE_SSL_CACERT;
      case errSSLBadCert:
        failf(data, "SSL certificate problem: Couldn't understand the server " "certificate format");
        return CURLE_SSL_CONNECT_ERROR;

      
      case errSecAuthFailed:
        failf(data, "SSL authentication failed");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLPeerHandshakeFail:
        failf(data, "SSL peer handshake failed, the server most likely " "requires a client certificate to connect");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLPeerUnknownCA:
        failf(data, "SSL server rejected the client certificate due to " "the certificate being signed by an unknown certificate " "authority");

        return CURLE_SSL_CONNECT_ERROR;

      
      case errSSLHostNameMismatch:
        failf(data, "SSL certificate peer verification failed, the " "certificate did not match \"%s\"\n", conn->host.dispname);
        return CURLE_PEER_FAILED_VERIFICATION;

      
      case errSSLConnectionRefused:
        failf(data, "Server dropped the connection during the SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLClosedAbort:
        failf(data, "Server aborted the SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLNegotiation:
        failf(data, "Could not negotiate an SSL cipher suite with the server");
        return CURLE_SSL_CONNECT_ERROR;
      
      case paramErr: case errSSLInternal:
        failf(data, "Internal SSL engine error encountered during the " "SSL handshake");
        return CURLE_SSL_CONNECT_ERROR;
      case errSSLFatalAlert:
        failf(data, "Fatal SSL engine error encountered during the SSL " "handshake");
        return CURLE_SSL_CONNECT_ERROR;
      default:
        failf(data, "Unknown SSL protocol error in connection to %s:%d", hostname, err);
        return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
    
    connssl->connecting_state = ssl_connect_3;

    
    (void)SSLGetNegotiatedCipher(connssl->ssl_ctx, &cipher);
    (void)SSLGetNegotiatedProtocolVersion(connssl->ssl_ctx, &protocol);
    switch(protocol) {
      case kSSLProtocol2:
        infof(data, "SSL 2.0 connection using %s\n", SSLCipherNameForNumber(cipher));
        break;
      case kSSLProtocol3:
        infof(data, "SSL 3.0 connection using %s\n", SSLCipherNameForNumber(cipher));
        break;
      case kTLSProtocol1:
        infof(data, "TLS 1.0 connection using %s\n", TLSCipherNameForNumber(cipher));
        break;

      case kTLSProtocol11:
        infof(data, "TLS 1.1 connection using %s\n", TLSCipherNameForNumber(cipher));
        break;
      case kTLSProtocol12:
        infof(data, "TLS 1.2 connection using %s\n", TLSCipherNameForNumber(cipher));
        break;

      default:
        infof(data, "Unknown protocol connection\n");
        break;
    }

    return CURLE_OK;
  }
}



static void show_verbose_server_cert(struct connectdata *conn, int sockindex)

{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  CFStringRef server_cert_summary;
  char server_cert_summary_c[128];
  CFArrayRef server_certs = NULL;
  SecCertificateRef server_cert;
  OSStatus err;
  CFIndex i, count;
  SecTrustRef trust = NULL;

  if(!connssl->ssl_ctx)
    return;




  err = SSLCopyPeerTrust(connssl->ssl_ctx, &trust);
  
  if(err == noErr && trust) {
    count = SecTrustGetCertificateCount(trust);
    for(i = 0L ; i < count ; i++) {
      server_cert = SecTrustGetCertificateAtIndex(trust, i);
      server_cert_summary = CopyCertSubject(server_cert);
      memset(server_cert_summary_c, 0, 128);
      if(CFStringGetCString(server_cert_summary, server_cert_summary_c, 128, kCFStringEncodingUTF8)) {


        infof(data, "Server certificate: %s\n", server_cert_summary_c);
      }
      CFRelease(server_cert_summary);
    }
    CFRelease(trust);
  }

  
  if(SecTrustEvaluateAsync != NULL) {

    err = SSLCopyPeerTrust(connssl->ssl_ctx, &trust);
    
    if(err == noErr && trust) {
      count = SecTrustGetCertificateCount(trust);
      for(i = 0L ; i < count ; i++) {
        server_cert = SecTrustGetCertificateAtIndex(trust, i);
        server_cert_summary = CopyCertSubject(server_cert);
        memset(server_cert_summary_c, 0, 128);
        if(CFStringGetCString(server_cert_summary, server_cert_summary_c, 128, kCFStringEncodingUTF8)) {


          infof(data, "Server certificate: %s\n", server_cert_summary_c);
        }
        CFRelease(server_cert_summary);
      }
      CFRelease(trust);
    }
  }
  else {

    err = SSLCopyPeerCertificates(connssl->ssl_ctx, &server_certs);
    
    if(err == noErr && server_certs) {
      count = CFArrayGetCount(server_certs);
      for(i = 0L ; i < count ; i++) {
        server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs, i);

        server_cert_summary = CopyCertSubject(server_cert);
        memset(server_cert_summary_c, 0, 128);
        if(CFStringGetCString(server_cert_summary, server_cert_summary_c, 128, kCFStringEncodingUTF8)) {


          infof(data, "Server certificate: %s\n", server_cert_summary_c);
        }
        CFRelease(server_cert_summary);
      }
      CFRelease(server_certs);
    }

  }



  err = SSLCopyPeerCertificates(connssl->ssl_ctx, &server_certs);
  if(err == noErr) {
    count = CFArrayGetCount(server_certs);
    for(i = 0L ; i < count ; i++) {
      server_cert = (SecCertificateRef)CFArrayGetValueAtIndex(server_certs, i);
      server_cert_summary = CopyCertSubject(server_cert);
      memset(server_cert_summary_c, 0, 128);
      if(CFStringGetCString(server_cert_summary, server_cert_summary_c, 128, kCFStringEncodingUTF8)) {


        infof(data, "Server certificate: %s\n", server_cert_summary_c);
      }
      CFRelease(server_cert_summary);
    }
    CFRelease(server_certs);
  }

}


static CURLcode darwinssl_connect_step3(struct connectdata *conn, int sockindex)

{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  

  if(data->set.verbose)
    show_verbose_server_cert(conn, sockindex);


  connssl->connecting_state = ssl_connect_done;
  return CURLE_OK;
}

static Curl_recv darwinssl_recv;
static Curl_send darwinssl_send;

static CURLcode darwinssl_connect_common(struct connectdata *conn, int sockindex, bool nonblocking, bool *done)



{
  CURLcode result;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
  int what;

  
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1==connssl->connecting_state) {
    
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = darwinssl_connect_step1(conn, sockindex);
    if(result)
      return result;
  }

  while(ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state) {


    
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    
    if(connssl->connecting_state == ssl_connect_2_reading || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing == connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading == connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd, nonblocking?0:timeout_ms);
      if(what < 0) {
        
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          
          failf(data, "SSL connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      
    }

    
    result = darwinssl_connect_step2(conn, sockindex);
    if(result || (nonblocking && (ssl_connect_2 == connssl->connecting_state || ssl_connect_2_reading == connssl->connecting_state || ssl_connect_2_writing == connssl->connecting_state)))


      return result;

  } 


  if(ssl_connect_3 == connssl->connecting_state) {
    result = darwinssl_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = darwinssl_recv;
    conn->send[sockindex] = darwinssl_send;
    *done = TRUE;
  }
  else *done = FALSE;

  
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

CURLcode Curl_darwinssl_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done)


{
  return darwinssl_connect_common(conn, sockindex, TRUE, done);
}

CURLcode Curl_darwinssl_connect(struct connectdata *conn, int sockindex)

{
  CURLcode result;
  bool done = FALSE;

  result = darwinssl_connect_common(conn, sockindex, FALSE, &done);

  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

void Curl_darwinssl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->ssl_ctx) {
    (void)SSLClose(connssl->ssl_ctx);

    if(SSLCreateContext != NULL)
      CFRelease(connssl->ssl_ctx);

    else (void)SSLDisposeContext(connssl->ssl_ctx);


    (void)SSLDisposeContext(connssl->ssl_ctx);

    connssl->ssl_ctx = NULL;
  }
  connssl->ssl_sockfd = 0;
}

int Curl_darwinssl_shutdown(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;
  ssize_t nread;
  int what;
  int rc;
  char buf[120];

  if(!connssl->ssl_ctx)
    return 0;

  if(data->set.ftp_ccc != CURLFTPSSL_CCC_ACTIVE)
    return 0;

  Curl_darwinssl_close(conn, sockindex);

  rc = 0;

  what = SOCKET_READABLE(conn->sock[sockindex], SSL_SHUTDOWN_TIMEOUT);

  for(;;) {
    if(what < 0) {
      
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      rc = -1;
      break;
    }

    if(!what) {                                
      failf(data, "SSL shutdown timeout");
      break;
    }

    

    nread = read(conn->sock[sockindex], buf, sizeof(buf));

    if(nread < 0) {
      failf(data, "read: %s", strerror(errno));
      rc = -1;
    }

    if(nread <= 0)
      break;

    what = SOCKET_READABLE(conn->sock[sockindex], 0);
  }

  return rc;
}

void Curl_darwinssl_session_free(void *ptr)
{
  
  Curl_safefree(ptr);
}

size_t Curl_darwinssl_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "SecureTransport");
}


int Curl_darwinssl_check_cxn(struct connectdata *conn)
{
  struct ssl_connect_data *connssl = &conn->ssl[FIRSTSOCKET];
  OSStatus err;
  SSLSessionState state;

  if(connssl->ssl_ctx) {
    err = SSLGetSessionState(connssl->ssl_ctx, &state);
    if(err == noErr)
      return state == kSSLConnected || state == kSSLHandshake;
    return -1;
  }
  return 0;
}

bool Curl_darwinssl_data_pending(const struct connectdata *conn, int connindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[connindex];
  OSStatus err;
  size_t buffer;

  if(connssl->ssl_ctx) {  
    err = SSLGetBufferedReadSize(connssl->ssl_ctx, &buffer);
    if(err == noErr)
      return buffer > 0UL;
    return false;
  }
  else return false;
}

CURLcode Curl_darwinssl_random(unsigned char *entropy, size_t length)
{
  
  size_t i;
  u_int32_t random_number = 0;

  for(i = 0 ; i < length ; i++) {
    if(i % sizeof(u_int32_t) == 0)
      random_number = arc4random();
    entropy[i] = random_number & 0xFF;
    random_number >>= 8;
  }
  i = random_number = 0;
  return CURLE_OK;
}

void Curl_darwinssl_md5sum(unsigned char *tmp,  size_t tmplen, unsigned char *md5sum, size_t md5len)


{
  (void)md5len;
  (void)CC_MD5(tmp, (CC_LONG)tmplen, md5sum);
}

bool Curl_darwinssl_false_start(void)
{

  if(SSLSetSessionOption != NULL)
    return TRUE;

  return FALSE;
}

static ssize_t darwinssl_send(struct connectdata *conn, int sockindex, const void *mem, size_t len, CURLcode *curlcode)



{
  
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  size_t processed = 0UL;
  OSStatus err;

  

  
  if(connssl->ssl_write_buffered_length) {
    
    err = SSLWrite(connssl->ssl_ctx, NULL, 0UL, &processed);
    switch(err) {
      case noErr:
        
        processed = connssl->ssl_write_buffered_length;
        connssl->ssl_write_buffered_length = 0UL;
        break;
      case errSSLWouldBlock: 
        *curlcode = CURLE_AGAIN;
        return -1L;
      default:
        failf(conn->data, "SSLWrite() returned error %d", err);
        *curlcode = CURLE_SEND_ERROR;
        return -1L;
    }
  }
  else {
    
    err = SSLWrite(connssl->ssl_ctx, mem, len, &processed);
    if(err != noErr) {
      switch(err) {
        case errSSLWouldBlock:
          
          connssl->ssl_write_buffered_length = len;
          *curlcode = CURLE_AGAIN;
          return -1L;
        default:
          failf(conn->data, "SSLWrite() returned error %d", err);
          *curlcode = CURLE_SEND_ERROR;
          return -1L;
      }
    }
  }
  return (ssize_t)processed;
}

static ssize_t darwinssl_recv(struct connectdata *conn, int num, char *buf, size_t buffersize, CURLcode *curlcode)



{
  
  struct ssl_connect_data *connssl = &conn->ssl[num];
  size_t processed = 0UL;
  OSStatus err = SSLRead(connssl->ssl_ctx, buf, buffersize, &processed);

  if(err != noErr) {
    switch(err) {
      case errSSLWouldBlock:  
        if(processed)
          return (ssize_t)processed;
        *curlcode = CURLE_AGAIN;
        return -1L;
        break;

      
      case errSSLClosedGraceful:
      case errSSLClosedNoNotify:
        *curlcode = CURLE_OK;
        return -1L;
        break;

      default:
        failf(conn->data, "SSLRead() return error %d", err);
        *curlcode = CURLE_RECV_ERROR;
        return -1L;
        break;
    }
  }
  return (ssize_t)processed;
}


