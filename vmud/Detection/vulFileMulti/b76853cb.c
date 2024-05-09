





TEST_IMPL(utf8_decode1) {
  const char* p;
  char b[32];
  int i;

  
  p = b;
  snprintf(b, sizeof(b), "%c\x7F", 0x00);
  ASSERT(0 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 1);
  ASSERT(127 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 2);

  
  p = b;
  snprintf(b, sizeof(b), "\xC2\x80\xDF\xBF");
  ASSERT(128 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 2);
  ASSERT(0x7FF == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 4);

  
  p = b;
  snprintf(b, sizeof(b), "\xE0\xA0\x80\xEF\xBF\xBF");
  ASSERT(0x800 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 3);
  ASSERT(0xFFFF == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 6);

  
  p = b;
  snprintf(b, sizeof(b), "\xF0\x90\x80\x80\xF4\x8F\xBF\xBF");
  ASSERT(0x10000 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 4);
  ASSERT(0x10FFFF == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 8);

  
  p = b;
  snprintf(b, sizeof(b), "\xF4\x90\xC0\xC0\xF7\xBF\xBF\xBF");
  ASSERT((unsigned) -1 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 4);
  ASSERT((unsigned) -1 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 8);

  
  p = b;
  snprintf(b, sizeof(b), "\xC0\x80\xC1\x80");
  ASSERT((unsigned) -1 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 2);
  ASSERT((unsigned) -1 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 4);

  
  p = b;
  snprintf(b, sizeof(b), "\xED\xA0\x80\xED\xA3\xBF");
  ASSERT((unsigned) -1 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 3);
  ASSERT((unsigned) -1 == uv__utf8_decode1(&p, b + sizeof(b)));
  ASSERT(p == b + 6);

  
  p = b;
  snprintf(b, sizeof(b), "\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF");

  for (i = 1; i <= 8; i++) {
    ASSERT((unsigned) -1 == uv__utf8_decode1(&p, b + sizeof(b)));
    ASSERT(p == b + i);
  }

  return 0;
}

























TEST_IMPL(idna_toascii) {
  
  F("\xC0\x80\xC1\x80", UV_EINVAL);  
  F("\xC0\x80\xC1\x80.com", UV_EINVAL);  
  
  T("", "");
  T(".", ".");
  T(".com", ".com");
  T("example", "example");
  T("example-", "example-");
  T("straße.de", "xn--strae-oqa.de");
  
  T("foo.bar", "foo.bar");
  T("mañana.com", "xn--maana-pta.com");
  T("example.com.", "example.com.");
  T("bücher.com", "xn--bcher-kva.com");
  T("café.com", "xn--caf-dma.com");
  T("café.café.com", "xn--caf-dma.xn--caf-dma.com");
  T("☃-⌘.com", "xn----dqo34k.com");
  T("퐀☃-⌘.com", "xn----dqo34kn65z.com");
  T("💩.la", "xn--ls8h.la");
  T("mañana.com", "xn--maana-pta.com");
  T("mañana。com", "xn--maana-pta.com");
  T("mañana．com", "xn--maana-pta.com");
  T("mañana｡com", "xn--maana-pta.com");
  T("ü", "xn--tda");
  T(".ü", ".xn--tda");
  T("ü.ü", "xn--tda.xn--tda");
  T("ü.ü.", "xn--tda.xn--tda.");
  T("üëäö♥", "xn--4can8av2009b");
  T("Willst du die Blüthe des frühen, die Früchte des späteren Jahres", "xn--Willst du die Blthe des frhen, " "die Frchte des spteren Jahres-x9e96lkal");

  T("ليهمابتكلموشعربي؟", "xn--egbpdaj6bu4bxfgehfvwxn");
  T("他们为什么不说中文", "xn--ihqwcrb4cv8a8dqg056pqjye");
  T("他們爲什麽不說中文", "xn--ihqwctvzc91f659drss3x8bo0yb");
  T("Pročprostěnemluvíčesky", "xn--Proprostnemluvesky-uyb24dma41a");
  T("למההםפשוטלאמדבריםעברית", "xn--4dbcagdahymbxekheh6e0a7fei0b");
  T("यहलोगहिन्दीक्योंनहींबोलसकतेहैं", "xn--i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd");
  T("なぜみんな日本語を話してくれないのか", "xn--n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa");
  T("세계의모든사람들이한국어를이해한다면얼마나좋을까", "xn--989aomsvi5e83db1d2a355cv1e0vak1d" "wrv93d5xbh15a0dt30a5jpsd879ccm6fea98c");

  T("почемужеонинеговорятпорусски", "xn--b1abfaaepdrnnbgefbadotcwatmq2g4l");
  T("PorquénopuedensimplementehablarenEspañol", "xn--PorqunopuedensimplementehablarenEspaol-fmd56a");
  T("TạisaohọkhôngthểchỉnóitiếngViệt", "xn--TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g");
  T("3年B組金八先生", "xn--3B-ww4c5e180e575a65lsy2b");
  T("安室奈美恵-with-SUPER-MONKEYS", "xn---with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n");
  T("Hello-Another-Way-それぞれの場所", "xn--Hello-Another-Way--fc4qua05auwb3674vfr0b");
  T("ひとつ屋根の下2", "xn--2-u9tlzr9756bt3uc0v");
  T("MajiでKoiする5秒前", "xn--MajiKoi5-783gue6qz075azm5e");
  T("パフィーdeルンバ", "xn--de-jg4avhby1noc0d");
  T("そのスピードで", "xn--d9juau41awczczp");
  T("-> $1.00 <-", "-> $1.00 <-");
  
  T("faß.de", "xn--fa-hia.de");
  T("βόλος.com", "xn--nxasmm1c.com");
  T("ශ්‍රී.com", "xn--10cl1a0b660p.com");
  T("نامه‌ای.com", "xn--mgba3gch31f060k.com");
  return 0;
}




