
#include<stddef.h>


#include<stdlib.h>
#include<stdbool.h>


#include<string.h>
#define FileWrapper_CheckExact(x) ((x)->ob_type == &FileWrapper_Type)
  #define DBG(...) \
    do { \
      printf(__VA_ARGS__); \
      printf("\n"); \
    } while(0)
#define DBG_REFCOUNT(obj) \
  DBG(#obj "->obj_refcnt: %d", obj->ob_refcnt)
#define DBG_REFCOUNT_REQ(request, obj) \
  DBG_REQ(request, #obj "->ob_refcnt: %d", obj->ob_refcnt)
  #define DBG_REQ(request, ...) \
    do { \
      printf("[DEBUG Req %ld] ", request->id); \
      DBG(__VA_ARGS__); \
    } while(0)
#define TYPE_ERROR(what, expected, got) \
  TYPE_ERROR_INNER(what, expected, "(got '%.200s' object instead)", Py_TYPE(got)->tp_name)
#define TYPE_ERROR_INNER(what, expected, ...) \
  PyErr_Format(PyExc_TypeError, what " must be " expected " " __VA_ARGS__)

  #define assert(...) do{}while(0)
#define REQUEST_FROM_WATCHER(watcher) \
  (Request*)((size_t)watcher - (size_t)(&(((Request*)NULL)->ev_watcher)));


