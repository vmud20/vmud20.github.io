


#define ARGS_TYPE v8::FunctionCallbackInfo<v8::Value>
    #define CALL_INIT_WITH_EXPORTS(f) f(exports);
#define CLOSE_SCOPE(v) scope.Escape(v)
#define CREATE_ESCAPABLE_SCOPE v8::EscapableHandleScope scope(isolate)
#define CREATE_ISOLATE_CONTEXT Isolate* isolate = Isolate::GetCurrent()
#define CREATE_SCOPE HandleScope scope(isolate)
    #define DECLARE_EXTERNAL(C) C* c1 = new C(isolate, exports); Local<External> external = External::New(isolate, c1); 
    #define DECLARE_EXTERNAL_DE_CON_STRUCTORS(C) v8::Persistent<v8::Object> mExports; \
                                            C(v8::Isolate* isolate, v8::Local<v8::Object> exports); \
                                            static void DeleteMe(const v8::WeakCallbackInfo<C>& info); \
                                            virtual ~C();
    #define DEC_SUBORDINATE_INIT(f) static void f(v8::Local<v8::Object> exports);
    #define DEFINE_EXTERNAL_DE_CON_STRUCTORS(C) \
        C::C(Isolate* isolate, Local<Object> exports) { \
            mExports.Reset(isolate, exports); \
            mExports.SetWeak(this, DeleteMe, WeakCallbackType::kParameter); \
        } \
        C::~C() { \
            if (!mExports.IsEmpty()) { \
                mExports.ClearWeak(); \
                mExports.Reset(); \
            } \
        } \
        void C::DeleteMe(const WeakCallbackInfo<C>& info) { \
            delete info.GetParameter(); \
        }
    #define DEF_INIT(f) void f(Local<Object> exports)
    #define DEF_SUBORDINATE_INIT(f) void f(Local<Object> exports)
#define DISPOSE_PERSISTENT(p) p.Reset()
#define ESCAPABLE_HANDLE(v) Local<v>
    #define EXPORTS_SET(e,k,v) e->Set(k,v);
    #define EXPOSE_EXTERNAL(C, c, e) C* c = reinterpret_cast<C*>(e->Value());
    #define EXPOSE_EXTERNAL_ARGS(C, c) EXPOSE_EXTERNAL(C, c, args.Data().As<External>())
    #define EXPOSE_EXTERNAL_FOR_INIT(C, c) EXPOSE_EXTERNAL(C, c, external)
#define GET_CURRENT_CONTEXT v8::Isolate::GetCurrent()->GetCurrentContext()
#define HAS_INSTANCE(c,o) Local<FunctionTemplate>::New(isolate, c)->HasInstance(o->TO_OBJECT())
#define IS_CONTEXT_AWARE NODE_MODULE_VERSION >= NODE_CONTEXT_AWARE_VERSION
    #define IS_CONTEXT_AWARE_MODULE 1
#define METHOD_RETURN_TYPE void
#define NEW_ARRAY(X) Array::New(isolate,X)
#define NEW_BOOLEAN(X) Boolean::New(isolate,X)
#define NEW_FUNCTION_TEMPLATE(X) FunctionTemplate::New(isolate, X)
    #define NEW_FUNCTION_TEMPLATE_EXTERNAL(X) NEW_FUNCTION_TEMPLATE(X)
#define NEW_INSTANCE(c,i) Local<Function> c1 = Local<Function>::New(isolate, c); Local<Object> i = Local<Function>::New(isolate, c1)->NewInstance(GET_CURRENT_CONTEXT).ToLocalChecked()
#define NEW_INSTANCE_ARGS(c,i,argc,argv) Local<Function> c1 = Local<Function>::New(isolate, c); Local<Object> i = Local<Function>::New(isolate, c1)->NewInstance(GET_CURRENT_CONTEXT,argc,argv).ToLocalChecked()
#define NEW_INTEGER(X) Integer::New(isolate,X)
#define NEW_NUMBER(X) Number::New(isolate,X)
#define NEW_OBJECT Object::New(isolate)
#define NEW_STRING(X) String::NewFromUtf8(isolate, X, v8::NewStringType::kNormal).ToLocalChecked()
#define NEW_SYMBOL(X) NEW_STRING(X)
#define NODE_10_0_0_MODULE_VERSION 64
#define NODE_11_0_0_MODULE_VERSION 67
#define NODE_2_5_0_MODULE_VERSION 44
#define NODE_CONTEXT_AWARE_VERSION NODE_10_0_0_MODULE_VERSION
#define OBJECT_FROM_PERSISTENT(p) Local<Object>::New(isolate, p)
#define PROPERTY_SETTER_TYPE v8::PropertyCallbackInfo<void>
#define PROPERTY_TYPE v8::PropertyCallbackInfo<v8::Value>
#define SET_ACCESSOR_METHOD(t,s,f) t->InstanceTemplate()->SetAccessor(NEW_STRING(s), f);
#define SET_ACCESSOR_METHODS(t,s,f,g) t->InstanceTemplate()->SetAccessor(NEW_STRING(s), f,g);
#define SET_ACCESSOR_RETURN_VALUE(v) {info.GetReturnValue().Set(v); return;}
#define SET_CONSTRUCTOR(c,t) c.Reset(isolate, t->GetFunction(GET_CURRENT_CONTEXT).ToLocalChecked())
#define SET_CONSTRUCTOR_EXPORT(s,c) EXPORTS_SET(exports,NEW_STRING(s),c->GetFunction(GET_CURRENT_CONTEXT).ToLocalChecked())
#define SET_CONSTRUCTOR_TEMPLATE(c,t) SET_PERSISTENT_OBJECT(c,FunctionTemplate,t)
#define SET_FUNCTION_RETURN_VALUE(v) {args.GetReturnValue().Set(v); return;}
#define SET_PERSISTENT_OBJECT(c,ot,t) c.Reset(isolate,t)
#define SET_PROTOTYPE_METHOD(t, s, f) NODE_SET_PROTOTYPE_METHOD(t,s,f)
#define THIS_HANDLE (this->handle())
#define THROW_EXCEPTION(s) isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,s,v8::NewStringType::kNormal).ToLocalChecked()))
    #define TO_BOOLEAN() ToBoolean(isolate)
#define TO_INT32(x) x->ToInt32(GET_CURRENT_CONTEXT).ToLocalChecked()
#define TO_NUMBER(x) x->ToNumber(GET_CURRENT_CONTEXT).ToLocalChecked()
    #define TO_OBJECT() ToObject(GET_CURRENT_CONTEXT).FromMaybe(Local<Object>())
    #define TO_STRING() ToString(GET_CURRENT_CONTEXT).FromMaybe(Local<String>())
#define TO_UINT32(x) x->ToUint32(GET_CURRENT_CONTEXT).ToLocalChecked()
#define TO_UINT32Value() ToUint32(GET_CURRENT_CONTEXT).ToLocalChecked()->Value()
#define UNDEFINED Undefined(isolate)
    #define UTF_8_VALUE(x) String::Utf8Value(isolate, x)
