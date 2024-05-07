


#include<stdlib.h>







#include<stdarg.h>



#include<stdio.h>




#include<string.h>

#include<assert.h>







#define DISCARD_CONST_QUAL(t, v) ((t)(uintptr_t)(v))
#define DISCARD_CONST_QUAL_XMLCHAR(v) DISCARD_CONST_QUAL(xmlChar *, v)
#define DOC_NODE_CACHE(x) (((nokogiriTuplePtr)(x->_private))->node_cache)
#define DOC_RUBY_OBJECT(x) (((nokogiriTuplePtr)(x->_private))->doc)
#define DOC_RUBY_OBJECT_TEST(x) ((nokogiriTuplePtr)(x->_private))
#define DOC_UNLINKED_NODE_HASH(x) (((nokogiriTuplePtr)(x->_private))->unlinkedNodes)
#  define NOKOGIRI_DEBUG_END(p) if (getenv("NOKOGIRI_DEBUG")) fprintf(stderr,"nokogiri: %s:%d %p end\n", "__FILE__", "__LINE__", p);
#  define NOKOGIRI_DEBUG_START(p) if (getenv("NOKOGIRI_NO_FREE")) return ; if (getenv("NOKOGIRI_DEBUG")) fprintf(stderr,"nokogiri: %s:%d %p start\n", "__FILE__", "__LINE__", p);
#define NOKOGIRI_NAMESPACE_EH(node) ((node)->type == XML_NAMESPACE_DECL)

#define NOKOGIRI_SAX_CTXT(_ctxt) ((nokogiriSAXTuplePtr)(_ctxt))->ctxt
#define NOKOGIRI_SAX_SELF(_ctxt) ((nokogiriSAXTuplePtr)(_ctxt))->self
#define NOKOGIRI_SAX_TUPLE_DESTROY(_tuple) ruby_xfree(_tuple)
#define NOKOGIRI_SAX_TUPLE_NEW(_ctxt, _self) nokogiri_sax_tuple_new(_ctxt, _self)
#define NOKOGIRI_STR_NEW(str, len) rb_external_str_new_with_enc((const char *)(str), (long)(len), rb_utf8_encoding())
#define NOKOGIRI_STR_NEW2(str) NOKOGIRI_STR_NEW(str, strlen((const char *)(str)))
#  define NOKOPUBFUN __declspec(dllexport)
#  define NOKOPUBVAR __declspec(dllexport) extern
#    define NORETURN(name) __attribute__((noreturn)) name
#define RBSTR_OR_QNIL(_str) (_str ? NOKOGIRI_STR_NEW2(_str) : Qnil)
#    define WIN32
#    define WIN32_LEAN_AND_MEAN
#define XMLNS_PREFIX "xmlns"
#define XMLNS_PREFIX_LEN 6 
