







static char raw_tolower(char in);


char Curl_raw_toupper(char in)
{
  if(in >= 'a' && in <= 'z')
    return (char)('A' + in - 'a');
  return in;
}



static char raw_tolower(char in)
{
  if(in >= 'A' && in <= 'Z')
    return (char)('a' + in - 'A');
  return in;
}



int Curl_strcasecompare(const char *first, const char *second)
{
  while(*first && *second) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second))
      
      break;
    first++;
    second++;
  }
  
  return (Curl_raw_toupper(*first) == Curl_raw_toupper(*second));
}

int Curl_safe_strcasecompare(const char *first, const char *second)
{
  if(first && second)
    
    return Curl_strcasecompare(first, second);

  
  return (NULL == first && NULL == second);
}


int Curl_strncasecompare(const char *first, const char *second, size_t max)
{
  while(*first && *second && max) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second)) {
      break;
    }
    max--;
    first++;
    second++;
  }
  if(0 == max)
    return 1; 

  return Curl_raw_toupper(*first) == Curl_raw_toupper(*second);
}


void Curl_strntoupper(char *dest, const char *src, size_t n)
{
  if(n < 1)
    return;

  do {
    *dest++ = Curl_raw_toupper(*src);
  } while(*src++ && --n);
}


void Curl_strntolower(char *dest, const char *src, size_t n)
{
  if(n < 1)
    return;

  do {
    *dest++ = raw_tolower(*src);
  } while(*src++ && --n);
}



int curl_strequal(const char *first, const char *second)
{
  return Curl_strcasecompare(first, second);
}
int curl_strnequal(const char *first, const char *second, size_t max)
{
  return Curl_strncasecompare(first, second, max);
}
