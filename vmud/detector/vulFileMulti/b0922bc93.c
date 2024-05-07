



















static bool Curl_isunreserved(unsigned char in)
{
  switch (in) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case 'a': case 'b': case 'c': case 'd': case 'e':
    case 'f': case 'g': case 'h': case 'i': case 'j':
    case 'k': case 'l': case 'm': case 'n': case 'o':
    case 'p': case 'q': case 'r': case 's': case 't':
    case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
    case 'A': case 'B': case 'C': case 'D': case 'E':
    case 'F': case 'G': case 'H': case 'I': case 'J':
    case 'K': case 'L': case 'M': case 'N': case 'O':
    case 'P': case 'Q': case 'R': case 'S': case 'T':
    case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
    case '-': case '.': case '_': case '~':
      return TRUE;
    default:
      break;
  }
  return FALSE;
}


char *curl_escape(const char *string, int inlength)
{
  return curl_easy_escape(NULL, string, inlength);
}


char *curl_unescape(const char *string, int length)
{
  return curl_easy_unescape(NULL, string, length, NULL);
}

char *curl_easy_escape(CURL *handle, const char *string, int inlength)
{
  size_t alloc = (inlength?(size_t)inlength:strlen(string))+1;
  char *ns;
  char *testing_ptr = NULL;
  unsigned char in; 
  size_t newlen = alloc;
  int strindex=0;
  size_t length;
  CURLcode res;

  ns = malloc(alloc);
  if(!ns)
    return NULL;

  length = alloc-1;
  while(length--) {
    in = *string;

    if(Curl_isunreserved(in))
      
      ns[strindex++]=in;
    else {
      
      newlen += 2; 
      if(newlen > alloc) {
        alloc *= 2;
        testing_ptr = realloc(ns, alloc);
        if(!testing_ptr) {
          free( ns );
          return NULL;
        }
        else {
          ns = testing_ptr;
        }
      }

      res = Curl_convert_to_network(handle, &in, 1);
      if(res) {
        
        free(ns);
        return NULL;
      }

      snprintf(&ns[strindex], 4, "%%%02X", in);

      strindex+=3;
    }
    string++;
  }
  ns[strindex]=0; 
  return ns;
}


char *curl_easy_unescape(CURL *handle, const char *string, int length, int *olen)
{
  int alloc = (length?length:(int)strlen(string))+1;
  char *ns = malloc(alloc);
  unsigned char in;
  int strindex=0;
  unsigned long hex;
  CURLcode res;

  if(!ns)
    return NULL;

  while(--alloc > 0) {
    in = *string;
    if(('%' == in) && ISXDIGIT(string[1]) && ISXDIGIT(string[2])) {
      
      char hexstr[3];
      char *ptr;
      hexstr[0] = string[1];
      hexstr[1] = string[2];
      hexstr[2] = 0;

      hex = strtoul(hexstr, &ptr, 16);

      in = curlx_ultouc(hex); 

      res = Curl_convert_from_network(handle, &in, 1);
      if(res) {
        
        free(ns);
        return NULL;
      }

      string+=2;
      alloc-=2;
    }

    ns[strindex++] = in;
    string++;
  }
  ns[strindex]=0; 

  if(olen)
    
    *olen = strindex;
  return ns;
}


void curl_free(void *p)
{
  if(p)
    free(p);
}
