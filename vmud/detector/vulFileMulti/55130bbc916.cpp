














namespace HPHP {



String StringUtil::Pad(const String& input, int final_length, const String& pad_string , PadType type ) {

  int len = input.size();
  return string_pad(input.data(), len, final_length, pad_string.data(), pad_string.size(), static_cast<int>(type));
}

String StringUtil::StripHTMLTags(const String& input, const String& allowable_tags ) {
  if (input.empty()) return input;
  return string_strip_tags(input.data(), input.size(), allowable_tags.data(), allowable_tags.size(), false);
}




Variant StringUtil::Explode(const String& input, const String& delimiter, int64_t limit ) {
  if (delimiter.empty()) {
    raise_invalid_argument_warning("delimiter: (empty)");
    return false;
  }

  Array ret(Array::CreateVArray());

  if (input.empty()) {
    if (limit >= 0) {
      ret.append("");
    }
    return ret;
  }

  if (limit > 1) {
    int pos = input.find(delimiter);
    if (pos < 0) {
      ret.append(input);
    } else {
      int len = delimiter.size();
      int pos0 = 0;
      do {
        ret.append(input.substr(pos0, pos - pos0));
        pos += len;
        pos0 = pos;
      } while ((pos = input.find(delimiter, pos)) >= 0 && --limit > 1);

      if (pos0 <= input.size()) {
        ret.append(input.substr(pos0));
      }
    }
  } else if (limit < 0) {
    int pos = input.find(delimiter);
    if (pos >= 0) {
      std::vector<int> positions;
      int len = delimiter.size();
      int pos0 = 0;
      int64_t found = 0;
      do {
        positions.push_back(pos0);
        positions.push_back(pos - pos0);
        pos += len;
        pos0 = pos;
        found++;
      } while ((pos = input.find(delimiter, pos)) >= 0);

      if (pos0 <= input.size()) {
        positions.push_back(pos0);
        positions.push_back(input.size() - pos0);
        found++;
      }
      uint64_t nelems = std::max(found + limit, (int64_t)0);
      for (uint64_t i = 0; i < nelems * 2; i += 2) {
        ret.append(input.substr(positions[i], positions[i+1]));
      }
    } 
  } else {
    ret.append(input);
  }

  return ret;
}

String StringUtil::Implode(const Variant& items, const String& delim, const bool checkIsContainer ) {
  if (checkIsContainer && !isContainer(items)) {
    throw_param_is_not_container();
  }
  int size = getContainerSize(items);
  if (size == 0) return empty_string();

  req::vector<String> sitems;
  sitems.reserve(size);
  size_t len = 0;
  size_t lenDelim = delim.size();
  for (ArrayIter iter(items); iter; ++iter) {
    sitems.emplace_back(iter.second().toString());
    len += sitems.back().size() + lenDelim;
  }
  len -= lenDelim; 
  assertx(sitems.size() == size);

  String s = String(len, ReserveString);
  char *buffer = s.mutableData();
  const char *sdelim = delim.data();
  char *p = buffer;
  String &init_str = sitems[0];
  int init_len = init_str.size();
  memcpy(p, init_str.data(), init_len);
  p += init_len;
  for (int i = 1; i < size; i++) {
    String &item = sitems[i];
    memcpy(p, sdelim, lenDelim);
    p += lenDelim;
    int lenItem = item.size();
    memcpy(p, item.data(), lenItem);
    p += lenItem;
  }
  assertx(p - buffer == len);
  s.setSize(len);
  return s;
}

Variant StringUtil::Split(const String& str, int64_t split_length ) {
  if (split_length <= 0) {
    raise_invalid_argument_warning( "The length of each segment must be greater than zero" );

    return false;
  }

  int len = str.size();
  VArrayInit ret(len / split_length + 1);
  if (split_length >= len) {
    ret.append(str);
  } else {
    for (int i = 0; i < len; i += split_length) {
      ret.append(str.substr(i, split_length));
    }
  }
  return ret.toArray();
}

Variant StringUtil::ChunkSplit(const String& body, int chunklen , const String& end ) {
  if (chunklen <= 0) {
    raise_invalid_argument_warning("chunklen: (non-positive)");
    return false;
  }

  String ret;
  int len = body.size();
  if (chunklen >= len) {
    ret = body;
    ret += end;
  } else {
    return string_chunk_split(body.data(), len, end.c_str(), end.size(), chunklen);
  }
  return ret;
}




String StringUtil::HtmlEncode(const String& input, QuoteStyle quoteStyle, const char *charset, bool dEncode, bool htmlEnt) {
  return HtmlEncode(input, static_cast<int64_t>(quoteStyle), charset, dEncode, htmlEnt);
}

String StringUtil::HtmlEncode(const String& input, const int64_t qsBitmask, const char *charset, bool dEncode, bool htmlEnt) {
  if (input.empty()) return input;

  assertx(charset);
  bool utf8 = true;
  if (strcasecmp(charset, "ISO-8859-1") == 0) {
    utf8 = false;
  } else if (strcasecmp(charset, "UTF-8")) {
    throw_not_implemented(charset);
  }

  int len = input.size();
  char *ret = string_html_encode(input.data(), len, qsBitmask, utf8, dEncode, htmlEnt);
  if (!ret) {
    return empty_string();
  }
  return String(ret, len, AttachString);
}




static const AsciiMap mapNoQuotes = {
  {   A1(A1(A1(A1(A1(A1(0, '<'), '>'), '&'), '{'), '}'), '@'), A2(A2(A2(A2(A2(A2(0, '<'), '>'), '&'), '{'), '}'), '@') }
};

static const AsciiMap mapDoubleQuotes = {
  {   A1(A1(A1(A1(A1(A1(A1(0, '<'), '>'), '&'), '{'), '}'), '@'), '"'), A2(A2(A2(A2(A2(A2(A2(0, '<'), '>'), '&'), '{'), '}'), '@'), '"') }
};

static const AsciiMap mapBothQuotes = {
  { A1(A1(A1(A1(A1(A1(A1(A1(0, '<'), '>'), '&'), '{'), '}'), '@'), '"'), '\''), A2(A2(A2(A2(A2(A2(A2(A2(0, '<'), '>'), '&'), '{'), '}'), '@'), '"'), '\'') }
};

static const AsciiMap mapNothing = {};

String StringUtil::HtmlEncodeExtra(const String& input, QuoteStyle quoteStyle, const char *charset, bool nbsp, Array extra) {

  if (input.empty()) return input;

  assertx(charset);
  int flags = STRING_HTML_ENCODE_UTF8;
  if (nbsp) {
    flags |= STRING_HTML_ENCODE_NBSP;
  }
  if (RuntimeOption::Utf8izeReplace) {
    flags |= STRING_HTML_ENCODE_UTF8IZE_REPLACE;
  }
  if (!*charset || strcasecmp(charset, "UTF-8") == 0) {
  } else if (strcasecmp(charset, "ISO-8859-1") == 0) {
    flags &= ~STRING_HTML_ENCODE_UTF8;
  } else {
    throw_not_implemented(charset);
  }

  const AsciiMap *am;
  AsciiMap tmp;

  switch (quoteStyle) {
    case QuoteStyle::FBUtf8Only:
      am = &mapNothing;
      flags |= STRING_HTML_ENCODE_HIGH;
      break;
    case QuoteStyle::FBUtf8:
      am = &mapBothQuotes;
      flags |= STRING_HTML_ENCODE_HIGH;
      break;
    case QuoteStyle::Both:
      am = &mapBothQuotes;
      break;
    case QuoteStyle::Double:
      am = &mapDoubleQuotes;
      break;
    case QuoteStyle::No:
      am = &mapNoQuotes;
      break;
    default:
      am = &mapNothing;
      raise_error("Unknown quote style: %d", (int)quoteStyle);
  }

  if (quoteStyle != QuoteStyle::FBUtf8Only && extra.toBoolean()) {
    tmp = *am;
    am = &tmp;
    for (ArrayIter iter(extra); iter; ++iter) {
      String item = iter.second().toString();
      char c = item.data()[0];
      tmp.map[c & 64 ? 1 : 0] |= 1uLL << (c & 63);
    }
  }

  int len = input.size();
  char *ret = string_html_encode_extra(input.data(), len, (StringHtmlEncoding)flags, am);
  if (!ret) {
    raise_error("HtmlEncode called on too large input (%d)", len);
  }
  return String(ret, len, AttachString);
}

String StringUtil::HtmlDecode(const String& input, QuoteStyle quoteStyle, const char *charset, bool all) {
  if (input.empty()) return input;

  assertx(charset);

  int len = input.size();
  char *ret = string_html_decode(input.data(), len, quoteStyle != QuoteStyle::No, quoteStyle == QuoteStyle::Both, charset, all);


  if (!ret) {
    
    throw_not_implemented(charset);
    
  }

  return String(ret, len, AttachString);
}

String StringUtil::QuotedPrintableEncode(const String& input) {
  if (input.empty()) return input;
  int len = input.size();
  return string_quoted_printable_encode(input.data(), len);
}

String StringUtil::QuotedPrintableDecode(const String& input) {
  if (input.empty()) return input;
  int len = input.size();
  return string_quoted_printable_decode(input.data(), len, false);
}

String StringUtil::UUEncode(const String& input) {
  if (input.empty()) return input;
  return string_uuencode(input.data(), input.size());
}

String StringUtil::UUDecode(const String& input) {
  if (!input.empty()) {
    return string_uudecode(input.data(), input.size());
  }
  return String();
}

String StringUtil::Base64Encode(const String& input) {
  int len = input.size();
  return string_base64_encode(input.data(), len);
}

String StringUtil::Base64Decode(const String& input, bool strict ) {
  int len = input.size();
  return string_base64_decode(input.data(), len, strict);
}

String StringUtil::UrlEncode(const String& input, bool encodePlus ) {
  return encodePlus ? url_encode(input.data(), input.size()) :
    url_raw_encode(input.data(), input.size());
}

String StringUtil::UrlDecode(const String& input, bool decodePlus ) {
  return decodePlus ? url_decode(input.data(), input.size()) :
    url_raw_decode(input.data(), input.size());
}

bool StringUtil::IsFileUrl(const String& input) {
  return string_strncasecmp( input.data(), input.size(), "file://", sizeof("file://") - 1, sizeof("file://") - 1) == 0;


}

String StringUtil::DecodeFileUrl(const String& input) {
  Url url;
  if (!url_parse(url, input.data(), input.size())) {
    return null_string;
  }
  if (bstrcasecmp(url.scheme.data(), url.scheme.size(), "file", sizeof("file")-1) != 0) {
    
    return null_string;
  }
  if (url.host.size() > 0 && bstrcasecmp(url.host.data(), url.host.size(), "localhost", sizeof("localhost")-1) != 0) {

    
    return null_string;
  }
  return url_raw_decode(url.path.data(), url.path.size());
}




String StringUtil::MoneyFormat(const char *format, double value) {
  assertx(format);
  return string_money_format(format, value);
}




String StringUtil::Translate(const String& input, const String& from, const String& to) {
  if (input.empty()) return input;

  int len = input.size();
  String retstr(len, ReserveString);
  char *ret = retstr.mutableData();
  memcpy(ret, input.data(), len);
  auto trlen = std::min(from.size(), to.size());
  string_translate(ret, len, from.data(), to.data(), trlen);
  retstr.setSize(len);
  return retstr;
}

String StringUtil::ROT13(const String& input) {
  if (input.empty()) return input;
  return String(string_rot13(input.data(), input.size()), input.size(), AttachString);
}

String StringUtil::Crypt(const String& input, const char *salt ) {
  if (salt && salt[0] == '\0') {
    raise_notice("crypt(): No salt parameter was specified." " You must use a randomly generated salt and a strong" " hash function to produce a secure hash.");

  }
  return String(string_crypt(input.c_str(), salt), AttachString);
}

String StringUtil::MD5(const char *data, uint32_t size, bool raw ) {
  Md5Digest md5(data, size);
  auto const rawLen = sizeof(md5.digest);
  if (raw) return String((char*)md5.digest, rawLen, CopyString);
  auto const hexLen = rawLen * 2;
  String hex(hexLen, ReserveString);
  string_bin2hex((char*)md5.digest, rawLen, hex.mutableData());
  hex.setSize(hexLen);
  return hex;
}

String StringUtil::MD5(const String& input, bool raw ) {
  return MD5(input.data(), input.length(), raw);
}

String StringUtil::SHA1(const String& input, bool raw ) {
  int len;
  char *ret = string_sha1(input.data(), input.size(), raw, len);
  return String(ret, len, AttachString);
}



size_t safe_address(size_t nmemb, size_t size, size_t offset) {
  uint64_t result = (uint64_t) nmemb * (uint64_t) size + (uint64_t) offset;
  if (UNLIKELY(result > StringData::MaxSize)) {
    raiseStringLengthExceededError(result);
  }
  return result;
}


}
