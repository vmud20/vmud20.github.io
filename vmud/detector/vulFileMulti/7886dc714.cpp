


































using llvh::dbgs;
using namespace hermes::inst;

HERMES_SLOW_STATISTIC( NumGetById, "NumGetById: Number of property 'read by id' accesses");

HERMES_SLOW_STATISTIC( NumGetByIdCacheHits, "NumGetByIdCacheHits: Number of property 'read by id' cache hits");

HERMES_SLOW_STATISTIC( NumGetByIdProtoHits, "NumGetByIdProtoHits: Number of property 'read by id' cache hits for the prototype");

HERMES_SLOW_STATISTIC( NumGetByIdCacheEvicts, "NumGetByIdCacheEvicts: Number of property 'read by id' cache evictions");

HERMES_SLOW_STATISTIC( NumGetByIdFastPaths, "NumGetByIdFastPaths: Number of property 'read by id' fast paths");

HERMES_SLOW_STATISTIC( NumGetByIdAccessor, "NumGetByIdAccessor: Number of property 'read by id' accessors");

HERMES_SLOW_STATISTIC( NumGetByIdProto, "NumGetByIdProto: Number of property 'read by id' in the prototype chain");

HERMES_SLOW_STATISTIC( NumGetByIdNotFound, "NumGetByIdNotFound: Number of property 'read by id' not found");

HERMES_SLOW_STATISTIC( NumGetByIdTransient, "NumGetByIdTransient: Number of property 'read by id' of non-objects");

HERMES_SLOW_STATISTIC( NumGetByIdDict, "NumGetByIdDict: Number of property 'read by id' of dictionaries");

HERMES_SLOW_STATISTIC( NumGetByIdSlow, "NumGetByIdSlow: Number of property 'read by id' slow path");


HERMES_SLOW_STATISTIC( NumPutById, "NumPutById: Number of property 'write by id' accesses");

HERMES_SLOW_STATISTIC( NumPutByIdCacheHits, "NumPutByIdCacheHits: Number of property 'write by id' cache hits");

HERMES_SLOW_STATISTIC( NumPutByIdCacheEvicts, "NumPutByIdCacheEvicts: Number of property 'write by id' cache evictions");

HERMES_SLOW_STATISTIC( NumPutByIdFastPaths, "NumPutByIdFastPaths: Number of property 'write by id' fast paths");

HERMES_SLOW_STATISTIC( NumPutByIdTransient, "NumPutByIdTransient: Number of property 'write by id' to non-objects");


HERMES_SLOW_STATISTIC( NumNativeFunctionCalls, "NumNativeFunctionCalls: Number of native function calls");

HERMES_SLOW_STATISTIC( NumBoundFunctionCalls, "NumBoundCalls: Number of bound function calls");













PROFILER_SYMBOLS(INTERP_WRAPPER)


namespace hermes {
namespace vm {


typedef CallResult<HermesValue> (*WrapperFunc)(Runtime *, CodeBlock *);

static const WrapperFunc interpWrappers[] = {PROFILER_SYMBOLS(LIST_ITEM)};









CallResult<PseudoHandle<JSGeneratorFunction>> Interpreter::createGeneratorClosure( Runtime *runtime, RuntimeModule *runtimeModule, unsigned funcIndex, Handle<Environment> envHandle) {




  return JSGeneratorFunction::create( runtime, runtimeModule->getDomain(runtime), Handle<JSObject>::vmcast(&runtime->generatorFunctionPrototype), envHandle, runtimeModule->getCodeBlockMayAllocate(funcIndex));




}

CallResult<PseudoHandle<JSGenerator>> Interpreter::createGenerator_RJS( Runtime *runtime, RuntimeModule *runtimeModule, unsigned funcIndex, Handle<Environment> envHandle, NativeArgs args) {




  auto gifRes = GeneratorInnerFunction::create( runtime, runtimeModule->getDomain(runtime), Handle<JSObject>::vmcast(&runtime->functionPrototype), envHandle, runtimeModule->getCodeBlockMayAllocate(funcIndex), args);





  if (LLVM_UNLIKELY(gifRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  auto generatorFunction = runtime->makeHandle(vmcast<JSGeneratorFunction>( runtime->getCurrentFrame().getCalleeClosure()));

  auto prototypeProp = JSObject::getNamed_RJS( generatorFunction, runtime, Predefined::getSymbolID(Predefined::prototype));


  if (LLVM_UNLIKELY(prototypeProp == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSObject> prototype = vmisa<JSObject>(prototypeProp->get())
      ? runtime->makeHandle<JSObject>(prototypeProp->get())
      : Handle<JSObject>::vmcast(&runtime->generatorPrototype);

  return JSGenerator::create(runtime, *gifRes, prototype);
}

CallResult<Handle<Arguments>> Interpreter::reifyArgumentsSlowPath( Runtime *runtime, Handle<Callable> curFunction, bool strictMode) {


  auto frame = runtime->getCurrentFrame();
  uint32_t argCount = frame.getArgCount();
  
  auto argRes = Arguments::create(runtime, argCount, curFunction, strictMode);
  if (LLVM_UNLIKELY(argRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<Arguments> args = *argRes;

  for (uint32_t argIndex = 0; argIndex < argCount; ++argIndex) {
    Arguments::unsafeSetExistingElementAt( *args, runtime, argIndex, frame.getArgRef(argIndex));
  }

  
  return args;
}

CallResult<PseudoHandle<>> Interpreter::getArgumentsPropByValSlowPath_RJS( Runtime *runtime, PinnedHermesValue *lazyReg, PinnedHermesValue *valueReg, Handle<Callable> curFunction, bool strictMode) {




  auto frame = runtime->getCurrentFrame();

  
  if (!lazyReg->isUndefined()) {
    
    
    assert(lazyReg->isObject() && "arguments lazy register is not an object");

    return JSObject::getComputed_RJS( Handle<JSObject>::vmcast(lazyReg), runtime, Handle<>(valueReg));
  }

  if (!valueReg->isSymbol()) {
    
    
    
    auto strRes = toString_RJS(runtime, Handle<>(valueReg));
    if (strRes == ExecutionStatus::EXCEPTION)
      return ExecutionStatus::EXCEPTION;
    auto strPrim = runtime->makeHandle(std::move(*strRes));

    
    if (auto index = toArrayIndex(runtime, strPrim)) {
      if (*index < frame.getArgCount()) {
        return createPseudoHandle(frame.getArgRef(*index));
      }

      auto objectPrototype = Handle<JSObject>::vmcast(&runtime->objectPrototype);

      
      
      
      MutableHandle<JSObject> inObject{runtime};
      ComputedPropertyDescriptor desc;
      JSObject::getComputedPrimitiveDescriptor( objectPrototype, runtime, strPrim, inObject, desc);

      
      if (!inObject)
        return createPseudoHandle(HermesValue::encodeUndefinedValue());

      
      
      if (!desc.flags.accessor) {
        return createPseudoHandle( JSObject::getComputedSlotValue(inObject.get(), runtime, desc));
      }
    }

    
    if (runtime->symbolEqualsToStringPrim( Predefined::getSymbolID(Predefined::length), *strPrim)) {
      return createPseudoHandle( HermesValue::encodeDoubleValue(frame.getArgCount()));
    }
  }

  
  auto argRes = reifyArgumentsSlowPath(runtime, curFunction, strictMode);
  if (argRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  
  *lazyReg = argRes->getHermesValue();

  
  return getArgumentsPropByValSlowPath_RJS( runtime, lazyReg, valueReg, curFunction, strictMode);
}

ExecutionStatus Interpreter::handleGetPNameList( Runtime *runtime, PinnedHermesValue *frameRegs, const Inst *ip) {


  if (O2REG(GetPNameList).isUndefined() || O2REG(GetPNameList).isNull()) {
    
    O1REG(GetPNameList) = HermesValue::encodeUndefinedValue();
    return ExecutionStatus::RETURNED;
  }

  
  auto res = toObject(runtime, Handle<>(&O2REG(GetPNameList)));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  O2REG(GetPNameList) = res.getValue();

  auto obj = runtime->makeMutableHandle(vmcast<JSObject>(res.getValue()));
  uint32_t beginIndex;
  uint32_t endIndex;
  auto cr = getForInPropertyNames(runtime, obj, beginIndex, endIndex);
  if (cr == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto arr = *cr;
  O1REG(GetPNameList) = arr.getHermesValue();
  O3REG(GetPNameList) = HermesValue::encodeNumberValue(beginIndex);
  O4REG(GetPNameList) = HermesValue::encodeNumberValue(endIndex);
  return ExecutionStatus::RETURNED;
}

CallResult<PseudoHandle<>> Interpreter::handleCallSlowPath( Runtime *runtime, PinnedHermesValue *callTarget) {

  if (auto *native = dyn_vmcast<NativeFunction>(*callTarget)) {
    ++NumNativeFunctionCalls;
    
    return NativeFunction::_nativeCall(native, runtime);
  } else if (auto *bound = dyn_vmcast<BoundFunction>(*callTarget)) {
    ++NumBoundFunctionCalls;
    
    return BoundFunction::_boundCall(bound, runtime->getCurrentIP(), runtime);
  } else {
    return runtime->raiseTypeErrorForValue( Handle<>(callTarget), " is not a function");
  }
}

inline PseudoHandle<> Interpreter::tryGetPrimitiveOwnPropertyById( Runtime *runtime, Handle<> base, SymbolID id) {


  if (base->isString() && id == Predefined::getSymbolID(Predefined::length)) {
    return createPseudoHandle( HermesValue::encodeNumberValue(base->getString()->getStringLength()));
  }
  return createPseudoHandle(HermesValue::encodeEmptyValue());
}

CallResult<PseudoHandle<>> Interpreter::getByIdTransient_RJS( Runtime *runtime, Handle<> base, SymbolID id) {


  
  
  

  
  PseudoHandle<> valOpt = tryGetPrimitiveOwnPropertyById(runtime, base, id);
  if (!valOpt->isEmpty()) {
    return valOpt;
  }

  
  
  
  CallResult<Handle<JSObject>> primitivePrototypeResult = getPrimitivePrototype(runtime, base);
  if (primitivePrototypeResult == ExecutionStatus::EXCEPTION) {
    
    
    
    return amendPropAccessErrorMsgWithPropName(runtime, base, "read", id);
  }

  return JSObject::getNamedWithReceiver_RJS( *primitivePrototypeResult, runtime, id, base);
}

PseudoHandle<> Interpreter::getByValTransientFast( Runtime *runtime, Handle<> base, Handle<> nameHandle) {


  if (base->isString()) {
    
    
    
    
    

    OptValue<uint32_t> arrayIndex = toArrayIndexFastPath(*nameHandle);
    
    
    if (arrayIndex && arrayIndex.getValue() < base->getString()->getStringLength()) {
      return createPseudoHandle( runtime ->getCharacterString(base->getString()->at(arrayIndex.getValue()))

              .getHermesValue());
    }
  }
  return createPseudoHandle(HermesValue::encodeEmptyValue());
}

CallResult<PseudoHandle<>> Interpreter::getByValTransient_RJS( Runtime *runtime, Handle<> base, Handle<> name) {


  
  
  

  
  PseudoHandle<> fastRes = getByValTransientFast(runtime, base, name);
  if (!fastRes->isEmpty()) {
    return fastRes;
  }

  auto res = toObject(runtime, base);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;

  return JSObject::getComputedWithReceiver_RJS( runtime->makeHandle<JSObject>(res.getValue()), runtime, name, base);
}

static ExecutionStatus transientObjectPutErrorMessage(Runtime *runtime, Handle<> base, SymbolID id) {
  
  
  StringView propName = runtime->getIdentifierTable().getStringView(runtime, id);
  Handle<StringPrimitive> baseType = runtime->makeHandle(vmcast<StringPrimitive>(typeOf(runtime, base)));
  StringView baseTypeAsString = StringPrimitive::createStringView(runtime, baseType);
  MutableHandle<StringPrimitive> valueAsString{runtime};
  if (base->isSymbol()) {
    
    auto str = symbolDescriptiveString(runtime, Handle<SymbolID>::vmcast(base));
    if (str != ExecutionStatus::EXCEPTION) {
      valueAsString = *str;
    } else {
      runtime->clearThrownValue();
      valueAsString = StringPrimitive::createNoThrow( runtime, "<<Exception occurred getting the value>>");
    }
  } else {
    auto str = toString_RJS(runtime, base);
    assert( str != ExecutionStatus::EXCEPTION && "Primitives should be convertible to string without exceptions");

    valueAsString = std::move(*str);
  }
  StringView valueAsStringPrintable = StringPrimitive::createStringView(runtime, valueAsString);

  SmallU16String<32> tmp1;
  SmallU16String<32> tmp2;
  return runtime->raiseTypeError( TwineChar16("Cannot create property '") + propName + "' on " + baseTypeAsString.getUTF16Ref(tmp1) + " '" + valueAsStringPrintable.getUTF16Ref(tmp2) + "'");


}

ExecutionStatus Interpreter::putByIdTransient_RJS( Runtime *runtime, Handle<> base, SymbolID id, Handle<> value, bool strictMode) {




  
  

  
  auto res = toObject(runtime, base);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    
    
    
    return amendPropAccessErrorMsgWithPropName(runtime, base, "set", id);
  }

  auto O = runtime->makeHandle<JSObject>(res.getValue());

  NamedPropertyDescriptor desc;
  JSObject *propObj = JSObject::getNamedDescriptor(O, runtime, id, desc);

  
  
  
  if (!propObj || (propObj != O.get() && (!desc.flags.accessor && !desc.flags.proxyObject))) {

    if (strictMode) {
      return transientObjectPutErrorMessage(runtime, base, id);
    }
    return ExecutionStatus::RETURNED;
  }

  
  if (!desc.flags.accessor && !desc.flags.proxyObject) {
    if (strictMode) {
      return runtime->raiseTypeError( "Cannot modify a property in a transient object");
    }
    return ExecutionStatus::RETURNED;
  }

  if (desc.flags.accessor) {
    
    auto *accessor = vmcast<PropertyAccessor>( JSObject::getNamedSlotValue(propObj, runtime, desc));

    
    if (!accessor->setter) {
      if (strictMode) {
        return runtime->raiseTypeError("Cannot modify a read-only accessor");
      }
      return ExecutionStatus::RETURNED;
    }

    CallResult<PseudoHandle<>> setRes = accessor->setter.get(runtime)->executeCall1( runtime->makeHandle(accessor->setter), runtime, base, *value);

    if (setRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  } else {
    assert(desc.flags.proxyObject && "descriptor flags are impossible");
    CallResult<bool> setRes = JSProxy::setNamed( runtime->makeHandle(propObj), runtime, id, value, base);
    if (setRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!*setRes && strictMode) {
      return runtime->raiseTypeError("transient proxy set returned false");
    }
  }
  return ExecutionStatus::RETURNED;
}

ExecutionStatus Interpreter::putByValTransient_RJS( Runtime *runtime, Handle<> base, Handle<> name, Handle<> value, bool strictMode) {




  auto idRes = valueToSymbolID(runtime, name);
  if (idRes == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;

  return putByIdTransient_RJS(runtime, base, **idRes, value, strictMode);
}

CallResult<PseudoHandle<>> Interpreter::createObjectFromBuffer( Runtime *runtime, CodeBlock *curCodeBlock, unsigned numLiterals, unsigned keyBufferIndex, unsigned valBufferIndex) {




  
  auto *runtimeModule = curCodeBlock->getRuntimeModule();
  const llvh::Optional<Handle<HiddenClass>> optCachedHiddenClassHandle = runtimeModule->findCachedLiteralHiddenClass( runtime, keyBufferIndex, numLiterals);

  
  
  
  auto obj = runtime->makeHandle( optCachedHiddenClassHandle.hasValue()
          ? JSObject::create(runtime, optCachedHiddenClassHandle.getValue())
          : JSObject::create(runtime, numLiterals));

  MutableHandle<> tmpHandleKey(runtime);
  MutableHandle<> tmpHandleVal(runtime);
  auto &gcScope = *runtime->getTopGCScope();
  auto marker = gcScope.createMarker();

  auto genPair = curCodeBlock->getObjectBufferIter( keyBufferIndex, valBufferIndex, numLiterals);
  auto keyGen = genPair.first;
  auto valGen = genPair.second;

  if (optCachedHiddenClassHandle.hasValue()) {
    uint32_t propIndex = 0;
    
    while (valGen.hasNext()) {

      {
        
        
        
        SymbolID stringIdResult{};
        auto key = keyGen.get(runtime);
        if (key.isSymbol()) {
          stringIdResult = ID(key.getSymbol().unsafeGetIndex());
        } else {
          tmpHandleKey = HermesValue::encodeDoubleValue(key.getNumber());
          auto idRes = valueToSymbolID(runtime, tmpHandleKey);
          assert( idRes != ExecutionStatus::EXCEPTION && "valueToIdentifier() failed for uint32_t value");

          stringIdResult = **idRes;
        }
        NamedPropertyDescriptor desc;
        auto pos = HiddenClass::findProperty( optCachedHiddenClassHandle.getValue(), runtime, stringIdResult, PropertyFlags::defaultNewNamedPropertyFlags(), desc);




        assert( pos && "Should find this property in cached hidden class property table.");

        assert( desc.slot == propIndex && "propIndex should be the same as recorded in hidden class table.");

      }

      
      
      
      auto val = valGen.get(runtime);
      JSObject::setNamedSlotValue(obj.get(), runtime, propIndex, val);
      gcScope.flushToMarker(marker);
      ++propIndex;
    }
  } else {
    
    while (keyGen.hasNext()) {
      
      
      
      auto key = keyGen.get(runtime);
      tmpHandleVal = valGen.get(runtime);
      if (key.isSymbol()) {
        auto stringIdResult = ID(key.getSymbol().unsafeGetIndex());
        if (LLVM_UNLIKELY( JSObject::defineNewOwnProperty( obj, runtime, stringIdResult, PropertyFlags::defaultNewNamedPropertyFlags(), tmpHandleVal) == ExecutionStatus::EXCEPTION)) {





          return ExecutionStatus::EXCEPTION;
        }
      } else {
        tmpHandleKey = HermesValue::encodeDoubleValue(key.getNumber());
        if (LLVM_UNLIKELY( !JSObject::defineOwnComputedPrimitive( obj, runtime, tmpHandleKey, DefinePropertyFlags::getDefaultNewPropertyFlags(), tmpHandleVal)





                     .getValue())) {
          return ExecutionStatus::EXCEPTION;
        }
      }
      gcScope.flushToMarker(marker);
    }
  }
  tmpHandleKey.clear();
  tmpHandleVal.clear();

  
  HiddenClass *const clazz = obj->getClass(runtime);
  if (!optCachedHiddenClassHandle.hasValue() && !clazz->isDictionary()) {
    assert( numLiterals == clazz->getNumProperties() && "numLiterals should match hidden class property count.");

    assert( clazz->getNumProperties() < 256 && "cached hidden class should have property count less than 256");

    runtimeModule->tryCacheLiteralHiddenClass(runtime, keyBufferIndex, clazz);
  }

  return createPseudoHandle(HermesValue::encodeObjectValue(*obj));
}

CallResult<PseudoHandle<>> Interpreter::createArrayFromBuffer( Runtime *runtime, CodeBlock *curCodeBlock, unsigned numElements, unsigned numLiterals, unsigned bufferIndex) {




  
  
  auto arrRes = JSArray::create(runtime, numElements, numElements);
  if (arrRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  
  auto arr = runtime->makeHandle(std::move(*arrRes));
  JSArray::setStorageEndIndex(arr, runtime, numElements);

  auto iter = curCodeBlock->getArrayBufferIter(bufferIndex, numLiterals);
  JSArray::size_type i = 0;
  while (iter.hasNext()) {
    
    auto value = iter.get(runtime);
    JSArray::unsafeSetExistingElementAt(*arr, runtime, i++, value);
  }

  return createPseudoHandle(HermesValue::encodeObjectValue(*arr));
}


namespace {


struct DumpHermesValue {
  const HermesValue hv;
  DumpHermesValue(HermesValue hv) : hv(hv) {}
};

} 

static llvh::raw_ostream &operator<<( llvh::raw_ostream &OS, DumpHermesValue dhv) {

  OS << dhv.hv;
  
  if (dhv.hv.isString()) {
    SmallU16String<32> str;
    dhv.hv.getString()->appendUTF16String(str);
    UTF16Ref ref = str.arrayRef();
    if (str.size() <= 8) {
      OS << ":'" << ref << "'";
    } else {
      OS << ":'" << ref.slice(0, 8) << "'";
      OS << "...[" << str.size() << "]";
    }
  }
  return OS;
}


LLVM_ATTRIBUTE_UNUSED static void dumpCallArguments( llvh::raw_ostream &OS, Runtime *runtime, StackFramePtr calleeFrame) {



  OS << "arguments:\n";
  OS << "  " << 0 << " " << DumpHermesValue(calleeFrame.getThisArgRef())
     << "\n";
  for (unsigned i = 0; i < calleeFrame.getArgCount(); ++i) {
    OS << "  " << (i + 1) << " " << DumpHermesValue(calleeFrame.getArgRef(i))
       << "\n";
  }
}

LLVM_ATTRIBUTE_UNUSED static void printDebugInfo( CodeBlock *curCodeBlock, PinnedHermesValue *frameRegs, const Inst *ip) {



  
  bool debug = false;
  SLOW_DEBUG(debug = true);
  if (!debug)
    return;

  DecodedInstruction decoded = decodeInstruction(ip);

  dbgs() << llvh::format_decimal((const uint8_t *)ip - curCodeBlock->begin(), 4)
         << " OpCode::" << getOpCodeString(decoded.meta.opCode);

  for (unsigned i = 0; i < decoded.meta.numOperands; ++i) {
    auto operandType = decoded.meta.operandType[i];
    auto value = decoded.operandValue[i];

    dbgs() << (i == 0 ? " " : ", ");
    dumpOperand(dbgs(), operandType, value);

    if (operandType == OperandType::Reg8 || operandType == OperandType::Reg32) {
      
      if (i != 0 || decoded.meta.numOperands == 1)
        dbgs() << "=" << DumpHermesValue(REG(value.integer));
    }
  }

  dbgs() << "\n";
}



LLVM_ATTRIBUTE_UNUSED static bool isCallType(OpCode opcode) {
  switch (opcode) {



    default:
      return false;
  }
}





LLVM_ATTRIBUTE_ALWAYS_INLINE static inline const Inst *nextInstCall(const Inst *ip) {
  HERMES_SLOW_ASSERT(isCallType(ip->opCode) && "ip is not of call type");

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  constexpr bool callSizesMonotoneIncreasing = monotoneIncreasing(   SIZE_MAX );



  static_assert( callSizesMonotoneIncreasing, "Call instruction sizes are not monotone increasing");





  llvm_unreachable("Not a call type");
}

CallResult<HermesValue> Runtime::interpretFunctionImpl( CodeBlock *newCodeBlock) {
  newCodeBlock->lazyCompile(this);


  
  
  
  
  const inst::Inst *ip = getCurrentIP();
  (void)ip;


  if (ip) {
    const CodeBlock *codeBlock;
    std::tie(codeBlock, ip) = getCurrentInterpreterLocation(ip);
    
    
    if (codeBlock) {
      
      
      pushCallStack(codeBlock, ip);
    } else {
      
      pushCallStack(newCodeBlock, (const Inst *)newCodeBlock->begin());
    }
  } else {
    
    pushCallStack(newCodeBlock, (const Inst *)newCodeBlock->begin());
  }


  InterpreterState state{newCodeBlock, 0};
  return Interpreter::interpretFunction<false>(this, state);
}

CallResult<HermesValue> Runtime::interpretFunction(CodeBlock *newCodeBlock) {

  auto id = getProfilerID(newCodeBlock);
  if (id >= NUM_PROFILER_SYMBOLS) {
    id = NUM_PROFILER_SYMBOLS - 1; 
  }
  return interpWrappers[id](this, newCodeBlock);

  return interpretFunctionImpl(newCodeBlock);

}


ExecutionStatus Runtime::stepFunction(InterpreterState &state) {
  return Interpreter::interpretFunction<true>(this, state).getStatus();
}



static double doDiv(double x, double y)
    LLVM_NO_SANITIZE("float-divide-by-zero");
static inline double doDiv(double x, double y) {
  
  
  
  
  
  
  return x / y;
}


static inline double doMult(double x, double y) {
  return x * y;
}


static inline double doSub(double x, double y) {
  return x - y;
}

template <bool SingleStep> CallResult<HermesValue> Interpreter::interpretFunction( Runtime *runtime, InterpreterState &state) {


  
  
  
  
  
  
  
  
  
  
  
  
  
  
  struct IPSaver {
    IPSaver(Runtime *runtime)
        : ip_(runtime->getCurrentIP()), runtime_(runtime) {}

    ~IPSaver() {
      runtime_->setCurrentIP(ip_);
    }

   private:
    const Inst *ip_;
    Runtime *runtime_;
  };
  IPSaver ipSaver(runtime);


  static_assert(!SingleStep, "can't use single-step mode without the debugger");

  
  
  static_assert( HiddenClass::kDictionaryThreshold <= SegmentedArray::kValueToSegmentThreshold, "Cannot avoid branches in cache check if the dictionary " "crossover point is larger than the inline storage");




  CodeBlock *curCodeBlock = state.codeBlock;
  const Inst *ip = nullptr;
  
  
  PinnedHermesValue *frameRegs;
  
  bool strictMode;
  
  PropOpFlags defaultPropOpFlags;










































  LLVM_DEBUG(dbgs() << "interpretFunction() called\n");

  ScopedNativeDepthTracker depthTracker{runtime};
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime->raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }

  if (!SingleStep) {
    if (auto jitPtr = runtime->jitContext_.compile(runtime, curCodeBlock)) {
      return (*jitPtr)(runtime);
    }
  }

  GCScope gcScope(runtime);
  
  MutableHandle<> tmpHandle(runtime);
  CallResult<HermesValue> res{ExecutionStatus::EXCEPTION};
  CallResult<PseudoHandle<>> resPH{ExecutionStatus::EXCEPTION};
  CallResult<Handle<Arguments>> resArgs{ExecutionStatus::EXCEPTION};
  CallResult<bool> boolRes{ExecutionStatus::EXCEPTION};

  
  
  static constexpr unsigned KEEP_HANDLES = 1;
  assert( gcScope.getHandleCountDbg() == KEEP_HANDLES && "scope has unexpected number of handles");


  INIT_OPCODE_PROFILER;


tailCall:

  PROFILER_ENTER_FUNCTION(curCodeBlock);


  runtime->getDebugger().willEnterCodeBlock(curCodeBlock);


  runtime->getCodeCoverageProfiler().markExecuted(runtime, curCodeBlock);

  
  curCodeBlock->incrementExecutionCount();

  if (!SingleStep) {
    auto newFrame = runtime->setCurrentFrameToTopOfStack();
    runtime->saveCallerIPInStackFrame();

    runtime->invalidateCurrentIP();


    
    
    
    frameRegs = &newFrame.getFirstLocalRef();


    LLVM_DEBUG( dbgs() << "function entry: stackLevel=" << runtime->getStackLevel()
               << ", argCount=" << runtime->getCurrentFrame().getArgCount()
               << ", frameSize=" << curCodeBlock->getFrameSize() << "\n");

    LLVM_DEBUG( dbgs() << " callee " << DumpHermesValue( runtime->getCurrentFrame().getCalleeClosureOrCBRef())


               << "\n");
    LLVM_DEBUG( dbgs() << "   this " << DumpHermesValue(runtime->getCurrentFrame().getThisArgRef())

               << "\n");
    for (uint32_t i = 0; i != runtime->getCurrentFrame()->getArgCount(); ++i) {
      LLVM_DEBUG( dbgs() << "   " << llvh::format_decimal(i, 4) << " " << DumpHermesValue(runtime->getCurrentFrame().getArgRef(i))

                 << "\n");
    }


    
    if (LLVM_UNLIKELY(!runtime->checkAndAllocStack( curCodeBlock->getFrameSize() + StackFrameLayout::CalleeExtraRegistersAtStart, HermesValue::encodeUndefinedValue())))


      goto stackOverflow;

    ip = (Inst const *)curCodeBlock->begin();

    
    if (LLVM_UNLIKELY(curCodeBlock->getHeaderFlags().isCallProhibited( newFrame.isConstructorCall()))) {
      if (!newFrame.isConstructorCall()) {
        CAPTURE_IP( runtime->raiseTypeError("Class constructor invoked without new"));
      } else {
        CAPTURE_IP(runtime->raiseTypeError("Function is not a constructor"));
      }
      goto handleExceptionInParent;
    }
  } else {
    
    frameRegs = &runtime->getCurrentFrame().getFirstLocalRef();
    ip = (Inst const *)(curCodeBlock->begin() + state.offset);
  }

  assert((const uint8_t *)ip < curCodeBlock->end() && "CodeBlock is empty");

  INIT_STATE_FOR_CODEBLOCK(curCodeBlock);















  static void *opcodeDispatch[] = {


      &&case__last};






































  for (;;) {
    BEFORE_OP_CODE;


    goto *opcodeDispatch[(unsigned)ip->opCode];

    switch (ip->opCode)

    {
      const Inst *nextIP;
      uint32_t idVal;
      bool tryProp;
      uint32_t callArgCount;
      
      
      
      
      HermesValue::RawType callNewTarget;









































































































































































































































































      CASE(Mov) {
        O1REG(Mov) = O2REG(Mov);
        ip = NEXTINST(Mov);
        DISPATCH;
      }

      CASE(MovLong) {
        O1REG(MovLong) = O2REG(MovLong);
        ip = NEXTINST(MovLong);
        DISPATCH;
      }

      CASE(LoadParam) {
        if (LLVM_LIKELY(ip->iLoadParam.op2 <= FRAME.getArgCount())) {
          
          O1REG(LoadParam) = FRAME.getArgRef((int32_t)ip->iLoadParam.op2 - 1);
          ip = NEXTINST(LoadParam);
          DISPATCH;
        }
        O1REG(LoadParam) = HermesValue::encodeUndefinedValue();
        ip = NEXTINST(LoadParam);
        DISPATCH;
      }

      CASE(LoadParamLong) {
        if (LLVM_LIKELY(ip->iLoadParamLong.op2 <= FRAME.getArgCount())) {
          
          O1REG(LoadParamLong) = FRAME.getArgRef((int32_t)ip->iLoadParamLong.op2 - 1);
          ip = NEXTINST(LoadParamLong);
          DISPATCH;
        }
        O1REG(LoadParamLong) = HermesValue::encodeUndefinedValue();
        ip = NEXTINST(LoadParamLong);
        DISPATCH;
      }

      CASE(CoerceThisNS) {
        if (LLVM_LIKELY(O2REG(CoerceThisNS).isObject())) {
          O1REG(CoerceThisNS) = O2REG(CoerceThisNS);
        } else if ( O2REG(CoerceThisNS).isNull() || O2REG(CoerceThisNS).isUndefined()) {
          O1REG(CoerceThisNS) = runtime->global_;
        } else {
          tmpHandle = O2REG(CoerceThisNS);
          nextIP = NEXTINST(CoerceThisNS);
          goto coerceThisSlowPath;
        }
        ip = NEXTINST(CoerceThisNS);
        DISPATCH;
      }
      CASE(LoadThisNS) {
        if (LLVM_LIKELY(FRAME.getThisArgRef().isObject())) {
          O1REG(LoadThisNS) = FRAME.getThisArgRef();
        } else if ( FRAME.getThisArgRef().isNull() || FRAME.getThisArgRef().isUndefined()) {

          O1REG(LoadThisNS) = runtime->global_;
        } else {
          tmpHandle = FRAME.getThisArgRef();
          nextIP = NEXTINST(LoadThisNS);
          goto coerceThisSlowPath;
        }
        ip = NEXTINST(LoadThisNS);
        DISPATCH;
      }
    coerceThisSlowPath : {
      CAPTURE_IP_ASSIGN(res, toObject(runtime, tmpHandle));
      if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
        goto exception;
      }
      O1REG(CoerceThisNS) = res.getValue();
      tmpHandle.clear();
      gcScope.flushToSmallCount(KEEP_HANDLES);
      ip = nextIP;
      DISPATCH;
    }

      CASE(ConstructLong) {
        callArgCount = (uint32_t)ip->iConstructLong.op3;
        nextIP = NEXTINST(ConstructLong);
        callNewTarget = O2REG(ConstructLong).getRaw();
        goto doCall;
      }
      CASE(CallLong) {
        callArgCount = (uint32_t)ip->iCallLong.op3;
        nextIP = NEXTINST(CallLong);
        callNewTarget = HermesValue::encodeUndefinedValue().getRaw();
        goto doCall;
      }

      
      
      
      
      CASE(Call1) {
        callArgCount = 1;
        nextIP = NEXTINST(Call1);
        StackFramePtr fr{runtime->stackPointer_};
        fr.getArgRefUnsafe(-1) = O3REG(Call1);
        callNewTarget = HermesValue::encodeUndefinedValue().getRaw();
        goto doCall;
      }

      CASE(Call2) {
        callArgCount = 2;
        nextIP = NEXTINST(Call2);
        StackFramePtr fr{runtime->stackPointer_};
        fr.getArgRefUnsafe(-1) = O3REG(Call2);
        fr.getArgRefUnsafe(0) = O4REG(Call2);
        callNewTarget = HermesValue::encodeUndefinedValue().getRaw();
        goto doCall;
      }

      CASE(Call3) {
        callArgCount = 3;
        nextIP = NEXTINST(Call3);
        StackFramePtr fr{runtime->stackPointer_};
        fr.getArgRefUnsafe(-1) = O3REG(Call3);
        fr.getArgRefUnsafe(0) = O4REG(Call3);
        fr.getArgRefUnsafe(1) = O5REG(Call3);
        callNewTarget = HermesValue::encodeUndefinedValue().getRaw();
        goto doCall;
      }

      CASE(Call4) {
        callArgCount = 4;
        nextIP = NEXTINST(Call4);
        StackFramePtr fr{runtime->stackPointer_};
        fr.getArgRefUnsafe(-1) = O3REG(Call4);
        fr.getArgRefUnsafe(0) = O4REG(Call4);
        fr.getArgRefUnsafe(1) = O5REG(Call4);
        fr.getArgRefUnsafe(2) = O6REG(Call4);
        callNewTarget = HermesValue::encodeUndefinedValue().getRaw();
        goto doCall;
      }

      CASE(Construct) {
        callArgCount = (uint32_t)ip->iConstruct.op3;
        nextIP = NEXTINST(Construct);
        callNewTarget = O2REG(Construct).getRaw();
        goto doCall;
      }
      CASE(Call) {
        callArgCount = (uint32_t)ip->iCall.op3;
        nextIP = NEXTINST(Call);
        callNewTarget = HermesValue::encodeUndefinedValue().getRaw();
        
      }

    doCall : {

      
      if (uint8_t asyncFlags = runtime->testAndClearDebuggerAsyncBreakRequest()) {
        RUN_DEBUGGER_ASYNC_BREAK(asyncFlags);
        gcScope.flushToSmallCount(KEEP_HANDLES);
        DISPATCH;
      }


      
      
      CAPTURE_IP_ASSIGN_NO_INVALIDATE( auto newFrame, StackFramePtr::initFrame( runtime->stackPointer_, FRAME, ip, curCodeBlock, callArgCount - 1, O2REG(Call), HermesValue::fromRaw(callNewTarget)));








      (void)newFrame;

      SLOW_DEBUG(dumpCallArguments(dbgs(), runtime, newFrame));

      if (auto *func = dyn_vmcast<JSFunction>(O2REG(Call))) {
        assert(!SingleStep && "can't single-step a call");


        runtime->pushCallStack(curCodeBlock, ip);


        CodeBlock *calleeBlock = func->getCodeBlock();
        calleeBlock->lazyCompile(runtime);

        CAPTURE_IP_ASSIGN_NO_INVALIDATE( res, runtime->interpretFunction(calleeBlock));
        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(Call) = *res;
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = nextIP;
        DISPATCH;

        if (auto jitPtr = runtime->jitContext_.compile(runtime, calleeBlock)) {
          res = (*jitPtr)(runtime);
          if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
            goto exception;
          O1REG(Call) = *res;
          SLOW_DEBUG( dbgs() << "JIT return value r" << (unsigned)ip->iCall.op1 << "=" << DumpHermesValue(O1REG(Call)) << "\n");

          gcScope.flushToSmallCount(KEEP_HANDLES);
          ip = nextIP;
          DISPATCH;
        }
        curCodeBlock = calleeBlock;
        goto tailCall;

      }
      CAPTURE_IP_ASSIGN_NO_INVALIDATE( resPH, Interpreter::handleCallSlowPath(runtime, &O2REG(Call)));
      if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
        goto exception;
      }
      O1REG(Call) = std::move(resPH->get());
      SLOW_DEBUG( dbgs() << "native return value r" << (unsigned)ip->iCall.op1 << "=" << DumpHermesValue(O1REG(Call)) << "\n");

      gcScope.flushToSmallCount(KEEP_HANDLES);
      ip = nextIP;
      DISPATCH;
    }

      CASE(CallDirect)
      CASE(CallDirectLongIndex) {

        
        if (uint8_t asyncFlags = runtime->testAndClearDebuggerAsyncBreakRequest()) {
          RUN_DEBUGGER_ASYNC_BREAK(asyncFlags);
          gcScope.flushToSmallCount(KEEP_HANDLES);
          DISPATCH;
        }


        CAPTURE_IP_ASSIGN( CodeBlock * calleeBlock, ip->opCode == OpCode::CallDirect ? curCodeBlock->getRuntimeModule()->getCodeBlockMayAllocate( ip->iCallDirect.op3)



                : curCodeBlock->getRuntimeModule()->getCodeBlockMayAllocate( ip->iCallDirectLongIndex.op3));

        CAPTURE_IP_ASSIGN_NO_INVALIDATE( auto newFrame, StackFramePtr::initFrame( runtime->stackPointer_, FRAME, ip, curCodeBlock, (uint32_t)ip->iCallDirect.op2 - 1, HermesValue::encodeNativePointer(calleeBlock), HermesValue::encodeUndefinedValue()));








        (void)newFrame;

        LLVM_DEBUG(dumpCallArguments(dbgs(), runtime, newFrame));

        assert(!SingleStep && "can't single-step a call");

        calleeBlock->lazyCompile(runtime);

        CAPTURE_IP_ASSIGN_NO_INVALIDATE( res, runtime->interpretFunction(calleeBlock));
        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(CallDirect) = *res;
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = ip->opCode == OpCode::CallDirect ? NEXTINST(CallDirect)
                                              : NEXTINST(CallDirectLongIndex);
        DISPATCH;

        if (auto jitPtr = runtime->jitContext_.compile(runtime, calleeBlock)) {
          res = (*jitPtr)(runtime);
          if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
            goto exception;
          O1REG(CallDirect) = *res;
          LLVM_DEBUG( dbgs() << "JIT return value r" << (unsigned)ip->iCallDirect.op1 << "=" << DumpHermesValue(O1REG(Call)) << "\n");

          gcScope.flushToSmallCount(KEEP_HANDLES);
          ip = ip->opCode == OpCode::CallDirect ? NEXTINST(CallDirect)
                                                : NEXTINST(CallDirectLongIndex);
          DISPATCH;
        }
        curCodeBlock = calleeBlock;
        goto tailCall;

      }

      CASE(CallBuiltin) {
        NativeFunction *nf = runtime->getBuiltinNativeFunction(ip->iCallBuiltin.op2);

        CAPTURE_IP_ASSIGN( auto newFrame, StackFramePtr::initFrame( runtime->stackPointer_, FRAME, ip, curCodeBlock, (uint32_t)ip->iCallBuiltin.op3 - 1, nf, false));








        
        newFrame.getThisArgRef() = HermesValue::encodeUndefinedValue();

        SLOW_DEBUG(dumpCallArguments(dbgs(), runtime, newFrame));

        CAPTURE_IP_ASSIGN(resPH, NativeFunction::_nativeCall(nf, runtime));
        if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION))
          goto exception;
        O1REG(CallBuiltin) = std::move(resPH->get());
        SLOW_DEBUG( dbgs() << "native return value r" << (unsigned)ip->iCallBuiltin.op1 << "=" << DumpHermesValue(O1REG(CallBuiltin)) << "\n");

        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(CallBuiltin);
        DISPATCH;
      }

      CASE(CompleteGenerator) {
        auto *innerFn = vmcast<GeneratorInnerFunction>( runtime->getCurrentFrame().getCalleeClosure());
        innerFn->setState(GeneratorInnerFunction::State::Completed);
        ip = NEXTINST(CompleteGenerator);
        DISPATCH;
      }

      CASE(SaveGenerator) {
        nextIP = IPADD(ip->iSaveGenerator.op1);
        goto doSaveGen;
      }
      CASE(SaveGeneratorLong) {
        nextIP = IPADD(ip->iSaveGeneratorLong.op1);
        goto doSaveGen;
      }

    doSaveGen : {
      auto *innerFn = vmcast<GeneratorInnerFunction>( runtime->getCurrentFrame().getCalleeClosure());

      innerFn->saveStack(runtime);
      innerFn->setNextIP(nextIP);
      innerFn->setState(GeneratorInnerFunction::State::SuspendedYield);
      ip = NEXTINST(SaveGenerator);
      DISPATCH;
    }

      CASE(StartGenerator) {
        auto *innerFn = vmcast<GeneratorInnerFunction>( runtime->getCurrentFrame().getCalleeClosure());
        if (innerFn->getState() == GeneratorInnerFunction::State::SuspendedStart) {
          nextIP = NEXTINST(StartGenerator);
        } else {
          nextIP = innerFn->getNextIP();
          innerFn->restoreStack(runtime);
        }
        innerFn->setState(GeneratorInnerFunction::State::Executing);
        ip = nextIP;
        DISPATCH;
      }

      CASE(ResumeGenerator) {
        auto *innerFn = vmcast<GeneratorInnerFunction>( runtime->getCurrentFrame().getCalleeClosure());
        O1REG(ResumeGenerator) = innerFn->getResult();
        O2REG(ResumeGenerator) = HermesValue::encodeBoolValue( innerFn->getAction() == GeneratorInnerFunction::Action::Return);
        innerFn->clearResult(runtime);
        if (innerFn->getAction() == GeneratorInnerFunction::Action::Throw) {
          runtime->setThrownValue(O1REG(ResumeGenerator));
          goto exception;
        }
        ip = NEXTINST(ResumeGenerator);
        DISPATCH;
      }

      CASE(Ret) {

        
        if (uint8_t asyncFlags = runtime->testAndClearDebuggerAsyncBreakRequest()) {
          RUN_DEBUGGER_ASYNC_BREAK(asyncFlags);
          gcScope.flushToSmallCount(KEEP_HANDLES);
          DISPATCH;
        }


        PROFILER_EXIT_FUNCTION(curCodeBlock);


        runtime->popCallStack();


        
        res = O1REG(Ret);

        ip = FRAME.getSavedIP();
        curCodeBlock = FRAME.getSavedCodeBlock();

        frameRegs = &runtime->restoreStackAndPreviousFrame(FRAME).getFirstLocalRef();

        SLOW_DEBUG( dbgs() << "function exit: restored stackLevel=" << runtime->getStackLevel() << "\n");


        
        if (!curCodeBlock) {
          SLOW_DEBUG(dbgs() << "function exit: returning to native code\n");
          return res;
        }



        return res;


        INIT_STATE_FOR_CODEBLOCK(curCodeBlock);
        O1REG(Call) = res.getValue();
        ip = nextInstCall(ip);
        DISPATCH;
      }

      CASE(Catch) {
        assert(!runtime->thrownValue_.isEmpty() && "Invalid thrown value");
        assert( !isUncatchableError(runtime->thrownValue_) && "Uncatchable thrown value was caught");

        O1REG(Catch) = runtime->thrownValue_;
        runtime->clearThrownValue();

        
        
        runtime->debugger_.finishedUnwindingException();

        ip = NEXTINST(Catch);
        DISPATCH;
      }

      CASE(Throw) {
        runtime->thrownValue_ = O1REG(Throw);
        SLOW_DEBUG( dbgs() << "Exception thrown: " << DumpHermesValue(runtime->thrownValue_) << "\n");

        goto exception;
      }

      CASE(ThrowIfUndefinedInst) {
        if (LLVM_UNLIKELY(O1REG(ThrowIfUndefinedInst).isUndefined())) {
          SLOW_DEBUG( dbgs() << "Throwing ReferenceError for undefined variable");
          CAPTURE_IP(runtime->raiseReferenceError( "accessing an uninitialized variable"));
          goto exception;
        }
        ip = NEXTINST(ThrowIfUndefinedInst);
        DISPATCH;
      }

      CASE(Debugger) {
        SLOW_DEBUG(dbgs() << "debugger statement executed\n");

        {
          if (!runtime->debugger_.isDebugging()) {
            
            
            CAPTURE_IP_ASSIGN( auto res, runDebuggerUpdatingState( Debugger::RunReason::Opcode, runtime, curCodeBlock, ip, frameRegs));






            if (res == ExecutionStatus::EXCEPTION) {
              
              
              
              
              
              
              goto exception;
            }
          }
          auto breakpointOpt = runtime->debugger_.getBreakpointLocation(ip);
          if (breakpointOpt.hasValue()) {
            
            curCodeBlock->uninstallBreakpointAtOffset( CUROFFSET, breakpointOpt->opCode);
            if (ip->opCode == OpCode::Debugger) {
              
              
              ip = NEXTINST(Debugger);
            } else {
              InterpreterState newState{curCodeBlock, (uint32_t)CUROFFSET};
              CAPTURE_IP_ASSIGN( ExecutionStatus status, runtime->stepFunction(newState));
              curCodeBlock->installBreakpointAtOffset(CUROFFSET);
              if (status == ExecutionStatus::EXCEPTION) {
                goto exception;
              }
              curCodeBlock = newState.codeBlock;
              ip = newState.codeBlock->getOffsetPtr(newState.offset);
              INIT_STATE_FOR_CODEBLOCK(curCodeBlock);
              
              frameRegs = &runtime->getCurrentFrame().getFirstLocalRef();
            }
          } else if (ip->opCode == OpCode::Debugger) {
            
            
            
            
            ip = NEXTINST(Debugger);
          }
          gcScope.flushToSmallCount(KEEP_HANDLES);
        }
        DISPATCH;

        ip = NEXTINST(Debugger);
        DISPATCH;

      }

      CASE(AsyncBreakCheck) {
        if (LLVM_UNLIKELY(runtime->hasAsyncBreak())) {

          if (uint8_t asyncFlags = runtime->testAndClearDebuggerAsyncBreakRequest()) {
            RUN_DEBUGGER_ASYNC_BREAK(asyncFlags);
          }

          if (runtime->testAndClearTimeoutAsyncBreakRequest()) {
            CAPTURE_IP_ASSIGN(auto nRes, runtime->notifyTimeout());
            if (nRes == ExecutionStatus::EXCEPTION) {
              goto exception;
            }
          }
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);

        ip = NEXTINST(AsyncBreakCheck);
        DISPATCH;
      }

      CASE(ProfilePoint) {

        auto pointIndex = ip->iProfilePoint.op1;
        SLOW_DEBUG(llvh::dbgs() << "ProfilePoint: " << pointIndex << "\n");
        CAPTURE_IP(runtime->getBasicBlockExecutionInfo().executeBlock( curCodeBlock, pointIndex));

        ip = NEXTINST(ProfilePoint);
        DISPATCH;
      }

      CASE(Unreachable) {
        llvm_unreachable("Hermes bug: unreachable instruction");
      }

      CASE(CreateClosure) {
        idVal = ip->iCreateClosure.op3;
        nextIP = NEXTINST(CreateClosure);
        goto createClosure;
      }
      CASE(CreateClosureLongIndex) {
        idVal = ip->iCreateClosureLongIndex.op3;
        nextIP = NEXTINST(CreateClosureLongIndex);
        goto createClosure;
      }
    createClosure : {
      auto *runtimeModule = curCodeBlock->getRuntimeModule();
      CAPTURE_IP_ASSIGN( O1REG(CreateClosure), JSFunction::create( runtime, runtimeModule->getDomain(runtime), Handle<JSObject>::vmcast(&runtime->functionPrototype), Handle<Environment>::vmcast(&O2REG(CreateClosure)), runtimeModule->getCodeBlockMayAllocate(idVal))






              .getHermesValue());
      gcScope.flushToSmallCount(KEEP_HANDLES);
      ip = nextIP;
      DISPATCH;
    }

      CASE(CreateGeneratorClosure) {
        CAPTURE_IP_ASSIGN( auto res, createGeneratorClosure( runtime, curCodeBlock->getRuntimeModule(), ip->iCreateClosure.op3, Handle<Environment>::vmcast(&O2REG(CreateGeneratorClosure))));





        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(CreateGeneratorClosure) = res->getHermesValue();
        res->invalidate();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(CreateGeneratorClosure);
        DISPATCH;
      }
      CASE(CreateGeneratorClosureLongIndex) {
        CAPTURE_IP_ASSIGN( auto res, createGeneratorClosure( runtime, curCodeBlock->getRuntimeModule(), ip->iCreateClosureLongIndex.op3, Handle<Environment>::vmcast( &O2REG(CreateGeneratorClosureLongIndex))));






        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(CreateGeneratorClosureLongIndex) = res->getHermesValue();
        res->invalidate();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(CreateGeneratorClosureLongIndex);
        DISPATCH;
      }

      CASE(CreateGenerator) {
        CAPTURE_IP_ASSIGN( auto res, createGenerator_RJS( runtime, curCodeBlock->getRuntimeModule(), ip->iCreateGenerator.op3, Handle<Environment>::vmcast(&O2REG(CreateGenerator)), FRAME.getNativeArgs()));






        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(CreateGenerator) = res->getHermesValue();
        res->invalidate();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(CreateGenerator);
        DISPATCH;
      }
      CASE(CreateGeneratorLongIndex) {
        CAPTURE_IP_ASSIGN( auto res, createGenerator_RJS( runtime, curCodeBlock->getRuntimeModule(), ip->iCreateGeneratorLongIndex.op3, Handle<Environment>::vmcast(&O2REG(CreateGeneratorLongIndex)), FRAME.getNativeArgs()));






        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(CreateGeneratorLongIndex) = res->getHermesValue();
        res->invalidate();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(CreateGeneratorLongIndex);
        DISPATCH;
      }

      CASE(GetEnvironment) {
        
        Environment *curEnv = FRAME.getCalleeClosureUnsafe()->getEnvironment(runtime);
        for (unsigned level = ip->iGetEnvironment.op2; level; --level) {
          assert(curEnv && "invalid environment relative level");
          curEnv = curEnv->getParentEnvironment(runtime);
        }
        O1REG(GetEnvironment) = HermesValue::encodeObjectValue(curEnv);
        ip = NEXTINST(GetEnvironment);
        DISPATCH;
      }

      CASE(CreateEnvironment) {
        tmpHandle = HermesValue::encodeObjectValue( FRAME.getCalleeClosureUnsafe()->getEnvironment(runtime));

        CAPTURE_IP_ASSIGN( res, Environment::create( runtime, tmpHandle->getPointer() ? Handle<Environment>::vmcast(tmpHandle)



                                        : Handle<Environment>::vmcast_or_null( &runtime->nullPointer_), curCodeBlock->getEnvironmentSize()));

        if (res == ExecutionStatus::EXCEPTION) {
          goto exception;
        }
        O1REG(CreateEnvironment) = *res;

        FRAME.getDebugEnvironmentRef() = *res;

        tmpHandle = HermesValue::encodeUndefinedValue();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(CreateEnvironment);
        DISPATCH;
      }

      CASE(StoreToEnvironment) {
        vmcast<Environment>(O1REG(StoreToEnvironment))
            ->slot(ip->iStoreToEnvironment.op2)
            .set(O3REG(StoreToEnvironment), &runtime->getHeap());
        ip = NEXTINST(StoreToEnvironment);
        DISPATCH;
      }
      CASE(StoreToEnvironmentL) {
        vmcast<Environment>(O1REG(StoreToEnvironmentL))
            ->slot(ip->iStoreToEnvironmentL.op2)
            .set(O3REG(StoreToEnvironmentL), &runtime->getHeap());
        ip = NEXTINST(StoreToEnvironmentL);
        DISPATCH;
      }

      CASE(StoreNPToEnvironment) {
        vmcast<Environment>(O1REG(StoreNPToEnvironment))
            ->slot(ip->iStoreNPToEnvironment.op2)
            .setNonPtr(O3REG(StoreNPToEnvironment), &runtime->getHeap());
        ip = NEXTINST(StoreNPToEnvironment);
        DISPATCH;
      }
      CASE(StoreNPToEnvironmentL) {
        vmcast<Environment>(O1REG(StoreNPToEnvironmentL))
            ->slot(ip->iStoreNPToEnvironmentL.op2)
            .setNonPtr(O3REG(StoreNPToEnvironmentL), &runtime->getHeap());
        ip = NEXTINST(StoreNPToEnvironmentL);
        DISPATCH;
      }

      CASE(LoadFromEnvironment) {
        O1REG(LoadFromEnvironment) = vmcast<Environment>(O2REG(LoadFromEnvironment))
                ->slot(ip->iLoadFromEnvironment.op3);
        ip = NEXTINST(LoadFromEnvironment);
        DISPATCH;
      }

      CASE(LoadFromEnvironmentL) {
        O1REG(LoadFromEnvironmentL) = vmcast<Environment>(O2REG(LoadFromEnvironmentL))
                ->slot(ip->iLoadFromEnvironmentL.op3);
        ip = NEXTINST(LoadFromEnvironmentL);
        DISPATCH;
      }

      CASE(GetGlobalObject) {
        O1REG(GetGlobalObject) = runtime->global_;
        ip = NEXTINST(GetGlobalObject);
        DISPATCH;
      }

      CASE(GetNewTarget) {
        O1REG(GetNewTarget) = FRAME.getNewTargetRef();
        ip = NEXTINST(GetNewTarget);
        DISPATCH;
      }

      CASE(DeclareGlobalVar) {
        DefinePropertyFlags dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
        dpf.configurable = 0;
        
        dpf.setValue = 0;

        CAPTURE_IP_ASSIGN( auto res, JSObject::defineOwnProperty( runtime->getGlobal(), runtime, ID(ip->iDeclareGlobalVar.op1), dpf, Runtime::getUndefinedValue(), PropOpFlags().plusThrowOnError()));







        if (res == ExecutionStatus::EXCEPTION) {
          assert( !runtime->getGlobal()->isProxyObject() && "global can't be a proxy object");

          
          
          
          
          
          
          NamedPropertyDescriptor desc;
          CAPTURE_IP_ASSIGN( auto res, JSObject::getOwnNamedDescriptor( runtime->getGlobal(), runtime, ID(ip->iDeclareGlobalVar.op1), desc));





          if (!res) {
            goto exception;
          } else {
            runtime->clearThrownValue();
          }
          
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(DeclareGlobalVar);
        DISPATCH;
      }

      CASE(TryGetByIdLong) {
        tryProp = true;
        idVal = ip->iTryGetByIdLong.op4;
        nextIP = NEXTINST(TryGetByIdLong);
        goto getById;
      }
      CASE(GetByIdLong) {
        tryProp = false;
        idVal = ip->iGetByIdLong.op4;
        nextIP = NEXTINST(GetByIdLong);
        goto getById;
      }
      CASE(GetByIdShort) {
        tryProp = false;
        idVal = ip->iGetByIdShort.op4;
        nextIP = NEXTINST(GetByIdShort);
        goto getById;
      }
      CASE(TryGetById) {
        tryProp = true;
        idVal = ip->iTryGetById.op4;
        nextIP = NEXTINST(TryGetById);
        goto getById;
      }
      CASE(GetById) {
        tryProp = false;
        idVal = ip->iGetById.op4;
        nextIP = NEXTINST(GetById);
      }
    getById : {
      ++NumGetById;
      
      
      
      CallResult<HermesValue> propRes{ExecutionStatus::EXCEPTION};
      if (LLVM_LIKELY(O2REG(GetById).isObject())) {
        auto *obj = vmcast<JSObject>(O2REG(GetById));
        auto cacheIdx = ip->iGetById.op3;
        auto *cacheEntry = curCodeBlock->getReadCacheEntry(cacheIdx);


        {
          HERMES_SLOW_ASSERT( gcScope.getHandleCountDbg() == KEEP_HANDLES && "unaccounted handles were created");

          auto objHandle = runtime->makeHandle(obj);
          auto cacheHCPtr = vmcast_or_null<HiddenClass>(static_cast<GCCell *>( cacheEntry->clazz.get(runtime, &runtime->getHeap())));
          CAPTURE_IP(runtime->recordHiddenClass( curCodeBlock, ip, ID(idVal), obj->getClass(runtime), cacheHCPtr));
          
          obj = objHandle.get();
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);

        auto clazzGCPtr = obj->getClassGCPtr();

        if (clazzGCPtr.get(runtime)->isDictionary())
          ++NumGetByIdDict;

        (void)NumGetByIdDict;


        
        
        if (LLVM_LIKELY(cacheEntry->clazz == clazzGCPtr.getStorageType())) {
          ++NumGetByIdCacheHits;
          CAPTURE_IP_ASSIGN( O1REG(GetById), JSObject::getNamedSlotValue<PropStorage::Inline::Yes>( obj, runtime, cacheEntry->slot));


          ip = nextIP;
          DISPATCH;
        }
        auto id = ID(idVal);
        NamedPropertyDescriptor desc;
        CAPTURE_IP_ASSIGN( OptValue<bool> fastPathResult, JSObject::tryGetOwnNamedDescriptorFast(obj, runtime, id, desc));

        if (LLVM_LIKELY( fastPathResult.hasValue() && fastPathResult.getValue()) && !desc.flags.accessor) {

          ++NumGetByIdFastPaths;

          
          
          auto *clazz = clazzGCPtr.getNonNull(runtime);
          if (LLVM_LIKELY(!clazz->isDictionaryNoCache()) && LLVM_LIKELY(cacheIdx != hbc::PROPERTY_CACHING_DISABLED)) {

            if (cacheEntry->clazz && cacheEntry->clazz != clazzGCPtr.getStorageType())
              ++NumGetByIdCacheEvicts;

            (void)NumGetByIdCacheEvicts;

            
            cacheEntry->clazz = clazzGCPtr.getStorageType();
            cacheEntry->slot = desc.slot;
          }

          CAPTURE_IP_ASSIGN( O1REG(GetById), JSObject::getNamedSlotValue(obj, runtime, desc));
          ip = nextIP;
          DISPATCH;
        }

        
        
        
        if (fastPathResult.hasValue() && !fastPathResult.getValue() && !obj->isProxyObject()) {
          CAPTURE_IP_ASSIGN(JSObject * parent, obj->getParent(runtime));
          
          
          
          
          if (parent && cacheEntry->clazz == parent->getClassGCPtr().getStorageType() && LLVM_LIKELY(!obj->isLazy())) {

            ++NumGetByIdProtoHits;
            CAPTURE_IP_ASSIGN( O1REG(GetById), JSObject::getNamedSlotValue(parent, runtime, cacheEntry->slot));

            ip = nextIP;
            DISPATCH;
          }
        }


        CAPTURE_IP_ASSIGN( JSObject * propObj, JSObject::getNamedDescriptor( Handle<JSObject>::vmcast(&O2REG(GetById)), runtime, id, desc));


        if (propObj) {
          if (desc.flags.accessor)
            ++NumGetByIdAccessor;
          else if (propObj != vmcast<JSObject>(O2REG(GetById)))
            ++NumGetByIdProto;
        } else {
          ++NumGetByIdNotFound;
        }

        (void)NumGetByIdAccessor;
        (void)NumGetByIdProto;
        (void)NumGetByIdNotFound;


        auto *savedClass = cacheIdx != hbc::PROPERTY_CACHING_DISABLED ? cacheEntry->clazz.get(runtime, &runtime->getHeap())
            : nullptr;

        ++NumGetByIdSlow;
        CAPTURE_IP_ASSIGN( resPH, JSObject::getNamed_RJS( Handle<JSObject>::vmcast(&O2REG(GetById)), runtime, id, !tryProp ? defaultPropOpFlags : defaultPropOpFlags.plusMustExist(), cacheIdx != hbc::PROPERTY_CACHING_DISABLED ? cacheEntry : nullptr));








        if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }

        if (cacheIdx != hbc::PROPERTY_CACHING_DISABLED && savedClass && cacheEntry->clazz.get(runtime, &runtime->getHeap()) != savedClass) {
          ++NumGetByIdCacheEvicts;
        }

      } else {
        ++NumGetByIdTransient;
        assert(!tryProp && "TryGetById can only be used on the global object");
        
        CAPTURE_IP_ASSIGN( resPH, Interpreter::getByIdTransient_RJS( runtime, Handle<>(&O2REG(GetById)), ID(idVal)));


        if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
      }
      O1REG(GetById) = resPH->get();
      gcScope.flushToSmallCount(KEEP_HANDLES);
      ip = nextIP;
      DISPATCH;
    }

      CASE(TryPutByIdLong) {
        tryProp = true;
        idVal = ip->iTryPutByIdLong.op4;
        nextIP = NEXTINST(TryPutByIdLong);
        goto putById;
      }
      CASE(PutByIdLong) {
        tryProp = false;
        idVal = ip->iPutByIdLong.op4;
        nextIP = NEXTINST(PutByIdLong);
        goto putById;
      }
      CASE(TryPutById) {
        tryProp = true;
        idVal = ip->iTryPutById.op4;
        nextIP = NEXTINST(TryPutById);
        goto putById;
      }
      CASE(PutById) {
        tryProp = false;
        idVal = ip->iPutById.op4;
        nextIP = NEXTINST(PutById);
      }
    putById : {
      ++NumPutById;
      if (LLVM_LIKELY(O1REG(PutById).isObject())) {
        auto *obj = vmcast<JSObject>(O1REG(PutById));
        auto cacheIdx = ip->iPutById.op3;
        auto *cacheEntry = curCodeBlock->getWriteCacheEntry(cacheIdx);


        {
          HERMES_SLOW_ASSERT( gcScope.getHandleCountDbg() == KEEP_HANDLES && "unaccounted handles were created");

          auto objHandle = runtime->makeHandle(obj);
          auto cacheHCPtr = vmcast_or_null<HiddenClass>(static_cast<GCCell *>( cacheEntry->clazz.get(runtime, &runtime->getHeap())));
          CAPTURE_IP(runtime->recordHiddenClass( curCodeBlock, ip, ID(idVal), obj->getClass(runtime), cacheHCPtr));
          
          obj = objHandle.get();
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);

        auto clazzGCPtr = obj->getClassGCPtr();
        
        
        if (LLVM_LIKELY(cacheEntry->clazz == clazzGCPtr.getStorageType())) {
          ++NumPutByIdCacheHits;
          CAPTURE_IP(JSObject::setNamedSlotValue<PropStorage::Inline::Yes>( obj, runtime, cacheEntry->slot, O2REG(PutById)));
          ip = nextIP;
          DISPATCH;
        }
        auto id = ID(idVal);
        NamedPropertyDescriptor desc;
        CAPTURE_IP_ASSIGN( OptValue<bool> hasOwnProp, JSObject::tryGetOwnNamedDescriptorFast(obj, runtime, id, desc));

        if (LLVM_LIKELY(hasOwnProp.hasValue() && hasOwnProp.getValue()) && !desc.flags.accessor && desc.flags.writable && !desc.flags.internalSetter) {

          ++NumPutByIdFastPaths;

          
          
          auto *clazz = clazzGCPtr.getNonNull(runtime);
          if (LLVM_LIKELY(!clazz->isDictionary()) && LLVM_LIKELY(cacheIdx != hbc::PROPERTY_CACHING_DISABLED)) {

            if (cacheEntry->clazz && cacheEntry->clazz != clazzGCPtr.getStorageType())
              ++NumPutByIdCacheEvicts;

            (void)NumPutByIdCacheEvicts;

            
            cacheEntry->clazz = clazzGCPtr.getStorageType();
            cacheEntry->slot = desc.slot;
          }

          CAPTURE_IP(JSObject::setNamedSlotValue( obj, runtime, desc.slot, O2REG(PutById)));
          ip = nextIP;
          DISPATCH;
        }

        CAPTURE_IP_ASSIGN( auto putRes, JSObject::putNamed_RJS( Handle<JSObject>::vmcast(&O1REG(PutById)), runtime, id, Handle<>(&O2REG(PutById)), !tryProp ? defaultPropOpFlags : defaultPropOpFlags.plusMustExist()));







        if (LLVM_UNLIKELY(putRes == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
      } else {
        ++NumPutByIdTransient;
        assert(!tryProp && "TryPutById can only be used on the global object");
        CAPTURE_IP_ASSIGN( auto retStatus, Interpreter::putByIdTransient_RJS( runtime, Handle<>(&O1REG(PutById)), ID(idVal), Handle<>(&O2REG(PutById)), strictMode));






        if (retStatus == ExecutionStatus::EXCEPTION) {
          goto exception;
        }
      }
      gcScope.flushToSmallCount(KEEP_HANDLES);
      ip = nextIP;
      DISPATCH;
    }

      CASE(GetByVal) {
        CallResult<HermesValue> propRes{ExecutionStatus::EXCEPTION};
        if (LLVM_LIKELY(O2REG(GetByVal).isObject())) {
          CAPTURE_IP_ASSIGN( resPH, JSObject::getComputed_RJS( Handle<JSObject>::vmcast(&O2REG(GetByVal)), runtime, Handle<>(&O3REG(GetByVal))));




          if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
            goto exception;
          }
        } else {
          
          CAPTURE_IP_ASSIGN( resPH, Interpreter::getByValTransient_RJS( runtime, Handle<>(&O2REG(GetByVal)), Handle<>(&O3REG(GetByVal))));




          if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
            goto exception;
          }
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        O1REG(GetByVal) = resPH->get();
        ip = NEXTINST(GetByVal);
        DISPATCH;
      }

      CASE(PutByVal) {
        if (LLVM_LIKELY(O1REG(PutByVal).isObject())) {
          CAPTURE_IP_ASSIGN( auto putRes, JSObject::putComputed_RJS( Handle<JSObject>::vmcast(&O1REG(PutByVal)), runtime, Handle<>(&O2REG(PutByVal)), Handle<>(&O3REG(PutByVal)), defaultPropOpFlags));






          if (LLVM_UNLIKELY(putRes == ExecutionStatus::EXCEPTION)) {
            goto exception;
          }
        } else {
          
          CAPTURE_IP_ASSIGN( auto retStatus, Interpreter::putByValTransient_RJS( runtime, Handle<>(&O1REG(PutByVal)), Handle<>(&O2REG(PutByVal)), Handle<>(&O3REG(PutByVal)), strictMode));






          if (LLVM_UNLIKELY(retStatus == ExecutionStatus::EXCEPTION)) {
            goto exception;
          }
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(PutByVal);
        DISPATCH;
      }

      CASE(PutOwnByIndexL) {
        nextIP = NEXTINST(PutOwnByIndexL);
        idVal = ip->iPutOwnByIndexL.op3;
        goto putOwnByIndex;
      }
      CASE(PutOwnByIndex) {
        nextIP = NEXTINST(PutOwnByIndex);
        idVal = ip->iPutOwnByIndex.op3;
      }
    putOwnByIndex : {
      tmpHandle = HermesValue::encodeDoubleValue(idVal);
      CAPTURE_IP(JSObject::defineOwnComputedPrimitive( Handle<JSObject>::vmcast(&O1REG(PutOwnByIndex)), runtime, tmpHandle, DefinePropertyFlags::getDefaultNewPropertyFlags(), Handle<>(&O2REG(PutOwnByIndex))));




      gcScope.flushToSmallCount(KEEP_HANDLES);
      tmpHandle.clear();
      ip = nextIP;
      DISPATCH;
    }

      CASE(GetPNameList) {
        CAPTURE_IP_ASSIGN( auto pRes, handleGetPNameList(runtime, frameRegs, ip));
        if (LLVM_UNLIKELY(pRes == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(GetPNameList);
        DISPATCH;
      }

      CASE(GetNextPName) {
        {
          assert( vmisa<BigStorage>(O2REG(GetNextPName)) && "GetNextPName's second op must be BigStorage");

          auto obj = Handle<JSObject>::vmcast(&O3REG(GetNextPName));
          auto arr = Handle<BigStorage>::vmcast(&O2REG(GetNextPName));
          uint32_t idx = O4REG(GetNextPName).getNumber();
          uint32_t size = O5REG(GetNextPName).getNumber();
          MutableHandle<JSObject> propObj{runtime};
          
          while (idx < size) {
            tmpHandle = arr->at(idx);
            ComputedPropertyDescriptor desc;
            CAPTURE_IP(JSObject::getComputedPrimitiveDescriptor( obj, runtime, tmpHandle, propObj, desc));
            if (LLVM_LIKELY(propObj))
              break;
            ++idx;
          }
          if (idx < size) {
            
            if (tmpHandle->isNumber()) {
              CAPTURE_IP_ASSIGN(auto status, toString_RJS(runtime, tmpHandle));
              assert( status == ExecutionStatus::RETURNED && "toString on number cannot fail");

              tmpHandle = status->getHermesValue();
            }
            O1REG(GetNextPName) = tmpHandle.get();
            O4REG(GetNextPName) = HermesValue::encodeNumberValue(idx + 1);
          } else {
            O1REG(GetNextPName) = HermesValue::encodeUndefinedValue();
          }
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        tmpHandle.clear();
        ip = NEXTINST(GetNextPName);
        DISPATCH;
      }

      CASE(ToNumber) {
        if (LLVM_LIKELY(O2REG(ToNumber).isNumber())) {
          O1REG(ToNumber) = O2REG(ToNumber);
          ip = NEXTINST(ToNumber);
        } else {
          CAPTURE_IP_ASSIGN( res, toNumber_RJS(runtime, Handle<>(&O2REG(ToNumber))));
          if (res == ExecutionStatus::EXCEPTION)
            goto exception;
          gcScope.flushToSmallCount(KEEP_HANDLES);
          O1REG(ToNumber) = res.getValue();
          ip = NEXTINST(ToNumber);
        }
        DISPATCH;
      }

      CASE(ToInt32) {
        CAPTURE_IP_ASSIGN(res, toInt32_RJS(runtime, Handle<>(&O2REG(ToInt32))));
        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
          goto exception;
        gcScope.flushToSmallCount(KEEP_HANDLES);
        O1REG(ToInt32) = res.getValue();
        ip = NEXTINST(ToInt32);
        DISPATCH;
      }

      CASE(AddEmptyString) {
        if (LLVM_LIKELY(O2REG(AddEmptyString).isString())) {
          O1REG(AddEmptyString) = O2REG(AddEmptyString);
          ip = NEXTINST(AddEmptyString);
        } else {
          CAPTURE_IP_ASSIGN( res, toPrimitive_RJS( runtime, Handle<>(&O2REG(AddEmptyString)), PreferredType::NONE));




          if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION))
            goto exception;
          tmpHandle = res.getValue();
          CAPTURE_IP_ASSIGN(auto strRes, toString_RJS(runtime, tmpHandle));
          if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION))
            goto exception;
          tmpHandle.clear();
          gcScope.flushToSmallCount(KEEP_HANDLES);
          O1REG(AddEmptyString) = strRes->getHermesValue();
          ip = NEXTINST(AddEmptyString);
        }
        DISPATCH;
      }

      CASE(Jmp) {
        ip = IPADD(ip->iJmp.op1);
        DISPATCH;
      }
      CASE(JmpLong) {
        ip = IPADD(ip->iJmpLong.op1);
        DISPATCH;
      }
      CASE(JmpTrue) {
        if (toBoolean(O2REG(JmpTrue)))
          ip = IPADD(ip->iJmpTrue.op1);
        else ip = NEXTINST(JmpTrue);
        DISPATCH;
      }
      CASE(JmpTrueLong) {
        if (toBoolean(O2REG(JmpTrueLong)))
          ip = IPADD(ip->iJmpTrueLong.op1);
        else ip = NEXTINST(JmpTrueLong);
        DISPATCH;
      }
      CASE(JmpFalse) {
        if (!toBoolean(O2REG(JmpFalse)))
          ip = IPADD(ip->iJmpFalse.op1);
        else ip = NEXTINST(JmpFalse);
        DISPATCH;
      }
      CASE(JmpFalseLong) {
        if (!toBoolean(O2REG(JmpFalseLong)))
          ip = IPADD(ip->iJmpFalseLong.op1);
        else ip = NEXTINST(JmpFalseLong);
        DISPATCH;
      }
      CASE(JmpUndefined) {
        if (O2REG(JmpUndefined).isUndefined())
          ip = IPADD(ip->iJmpUndefined.op1);
        else ip = NEXTINST(JmpUndefined);
        DISPATCH;
      }
      CASE(JmpUndefinedLong) {
        if (O2REG(JmpUndefinedLong).isUndefined())
          ip = IPADD(ip->iJmpUndefinedLong.op1);
        else ip = NEXTINST(JmpUndefinedLong);
        DISPATCH;
      }
      CASE(Add) {
        if (LLVM_LIKELY( O2REG(Add).isNumber() && O3REG(Add).isNumber())) {

          CASE(AddN) {
            O1REG(Add) = HermesValue::encodeDoubleValue( O2REG(Add).getNumber() + O3REG(Add).getNumber());
            ip = NEXTINST(Add);
            DISPATCH;
          }
        }
        CAPTURE_IP_ASSIGN( res, addOp_RJS(runtime, Handle<>(&O2REG(Add)), Handle<>(&O3REG(Add))));

        if (res == ExecutionStatus::EXCEPTION) {
          goto exception;
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        O1REG(Add) = res.getValue();
        ip = NEXTINST(Add);
        DISPATCH;
      }

      CASE(BitNot) {
        if (LLVM_LIKELY(O2REG(BitNot).isNumber())) { 
          O1REG(BitNot) = HermesValue::encodeDoubleValue( ~hermes::truncateToInt32(O2REG(BitNot).getNumber()));
          ip = NEXTINST(BitNot);
          DISPATCH;
        }
        CAPTURE_IP_ASSIGN(res, toInt32_RJS(runtime, Handle<>(&O2REG(BitNot))));
        if (res == ExecutionStatus::EXCEPTION) {
          goto exception;
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        O1REG(BitNot) = HermesValue::encodeDoubleValue( ~static_cast<int32_t>(res->getNumber()));
        ip = NEXTINST(BitNot);
        DISPATCH;
      }

      CASE(GetArgumentsLength) {
        
        if (O2REG(GetArgumentsLength).isUndefined()) {
          O1REG(GetArgumentsLength) = HermesValue::encodeNumberValue(FRAME.getArgCount());
          ip = NEXTINST(GetArgumentsLength);
          DISPATCH;
        }
        
        
        assert( O2REG(GetArgumentsLength).isObject() && "arguments lazy register is not an object");

        CAPTURE_IP_ASSIGN( resPH, JSObject::getNamed_RJS( Handle<JSObject>::vmcast(&O2REG(GetArgumentsLength)), runtime, Predefined::getSymbolID(Predefined::length)));




        if (resPH == ExecutionStatus::EXCEPTION) {
          goto exception;
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        O1REG(GetArgumentsLength) = resPH->get();
        ip = NEXTINST(GetArgumentsLength);
        DISPATCH;
      }

      CASE(GetArgumentsPropByVal) {
        
        
        if (O3REG(GetArgumentsPropByVal).isUndefined()) {
          
          if (auto index = toArrayIndexFastPath(O2REG(GetArgumentsPropByVal))) {
            
            if (*index < FRAME.getArgCount()) {
              O1REG(GetArgumentsPropByVal) = FRAME.getArgRef(*index);
              ip = NEXTINST(GetArgumentsPropByVal);
              DISPATCH;
            }
          }
        }
        
        CAPTURE_IP_ASSIGN( auto res, getArgumentsPropByValSlowPath_RJS( runtime, &O3REG(GetArgumentsPropByVal), &O2REG(GetArgumentsPropByVal), FRAME.getCalleeClosureHandleUnsafe(), strictMode));






        if (res == ExecutionStatus::EXCEPTION) {
          goto exception;
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        O1REG(GetArgumentsPropByVal) = res->getHermesValue();
        ip = NEXTINST(GetArgumentsPropByVal);
        DISPATCH;
      }

      CASE(ReifyArguments) {
        
        if (!O1REG(ReifyArguments).isUndefined()) {
          assert( O1REG(ReifyArguments).isObject() && "arguments lazy register is not an object");

          ip = NEXTINST(ReifyArguments);
          DISPATCH;
        }
        CAPTURE_IP_ASSIGN( resArgs, reifyArgumentsSlowPath( runtime, FRAME.getCalleeClosureHandleUnsafe(), strictMode));


        if (LLVM_UNLIKELY(resArgs == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(ReifyArguments) = resArgs->getHermesValue();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(ReifyArguments);
        DISPATCH;
      }

      CASE(NewObject) {
        
        
        
        CAPTURE_IP_ASSIGN( O1REG(NewObject), JSObject::create(runtime).getHermesValue());
        assert( gcScope.getHandleCountDbg() == KEEP_HANDLES && "Should not create handles.");

        ip = NEXTINST(NewObject);
        DISPATCH;
      }
      CASE(NewObjectWithParent) {
        CAPTURE_IP_ASSIGN( O1REG(NewObjectWithParent), JSObject::create( runtime, O2REG(NewObjectWithParent).isObject()



                    ? Handle<JSObject>::vmcast(&O2REG(NewObjectWithParent))
                    : O2REG(NewObjectWithParent).isNull()
                        ? Runtime::makeNullHandle<JSObject>()
                        : Handle<JSObject>::vmcast(&runtime->objectPrototype))
                .getHermesValue());
        assert( gcScope.getHandleCountDbg() == KEEP_HANDLES && "Should not create handles.");

        ip = NEXTINST(NewObjectWithParent);
        DISPATCH;
      }

      CASE(NewObjectWithBuffer) {
        CAPTURE_IP_ASSIGN( resPH, Interpreter::createObjectFromBuffer( runtime, curCodeBlock, ip->iNewObjectWithBuffer.op3, ip->iNewObjectWithBuffer.op4, ip->iNewObjectWithBuffer.op5));






        if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(NewObjectWithBuffer) = resPH->get();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(NewObjectWithBuffer);
        DISPATCH;
      }

      CASE(NewObjectWithBufferLong) {
        CAPTURE_IP_ASSIGN( resPH, Interpreter::createObjectFromBuffer( runtime, curCodeBlock, ip->iNewObjectWithBufferLong.op3, ip->iNewObjectWithBufferLong.op4, ip->iNewObjectWithBufferLong.op5));






        if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(NewObjectWithBufferLong) = resPH->get();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(NewObjectWithBufferLong);
        DISPATCH;
      }

      CASE(NewArray) {
        
        
        
        CAPTURE_IP_ASSIGN( auto createRes, JSArray::create(runtime, ip->iNewArray.op2, ip->iNewArray.op2));

        if (createRes == ExecutionStatus::EXCEPTION) {
          goto exception;
        }
        O1REG(NewArray) = createRes->getHermesValue();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(NewArray);
        DISPATCH;
      }

      CASE(NewArrayWithBuffer) {
        CAPTURE_IP_ASSIGN( resPH, Interpreter::createArrayFromBuffer( runtime, curCodeBlock, ip->iNewArrayWithBuffer.op2, ip->iNewArrayWithBuffer.op3, ip->iNewArrayWithBuffer.op4));






        if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(NewArrayWithBuffer) = resPH->get();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        tmpHandle.clear();
        ip = NEXTINST(NewArrayWithBuffer);
        DISPATCH;
      }

      CASE(NewArrayWithBufferLong) {
        CAPTURE_IP_ASSIGN( resPH, Interpreter::createArrayFromBuffer( runtime, curCodeBlock, ip->iNewArrayWithBufferLong.op2, ip->iNewArrayWithBufferLong.op3, ip->iNewArrayWithBufferLong.op4));






        if (LLVM_UNLIKELY(resPH == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(NewArrayWithBufferLong) = resPH->get();
        gcScope.flushToSmallCount(KEEP_HANDLES);
        tmpHandle.clear();
        ip = NEXTINST(NewArrayWithBufferLong);
        DISPATCH;
      }

      CASE(CreateThis) {
        
        if (LLVM_UNLIKELY(!vmisa<Callable>(O3REG(CreateThis)))) {
          CAPTURE_IP(runtime->raiseTypeError("constructor is not callable"));
          goto exception;
        }
        CAPTURE_IP_ASSIGN( auto res, Callable::newObject( Handle<Callable>::vmcast(&O3REG(CreateThis)), runtime, Handle<JSObject>::vmcast( O2REG(CreateThis).isObject() ? &O2REG(CreateThis)





                                                 : &runtime->objectPrototype)));
        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        O1REG(CreateThis) = res->getHermesValue();
        ip = NEXTINST(CreateThis);
        DISPATCH;
      }

      CASE(SelectObject) {
        
        O1REG(SelectObject) = O3REG(SelectObject).isObject()
            ? O3REG(SelectObject)
            : O2REG(SelectObject);
        ip = NEXTINST(SelectObject);
        DISPATCH;
      }

      CASE(Eq)
      CASE(Neq) {
        CAPTURE_IP_ASSIGN( res, abstractEqualityTest_RJS( runtime, Handle<>(&O2REG(Eq)), Handle<>(&O3REG(Eq))));


        if (res == ExecutionStatus::EXCEPTION) {
          goto exception;
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        O1REG(Eq) = ip->opCode == OpCode::Eq ? res.getValue()
            : HermesValue::encodeBoolValue(!res->getBool());
        ip = NEXTINST(Eq);
        DISPATCH;
      }
      CASE(StrictEq) {
        O1REG(StrictEq) = HermesValue::encodeBoolValue( strictEqualityTest(O2REG(StrictEq), O3REG(StrictEq)));
        ip = NEXTINST(StrictEq);
        DISPATCH;
      }
      CASE(StrictNeq) {
        O1REG(StrictNeq) = HermesValue::encodeBoolValue( !strictEqualityTest(O2REG(StrictNeq), O3REG(StrictNeq)));
        ip = NEXTINST(StrictNeq);
        DISPATCH;
      }
      CASE(Not) {
        O1REG(Not) = HermesValue::encodeBoolValue(!toBoolean(O2REG(Not)));
        ip = NEXTINST(Not);
        DISPATCH;
      }
      CASE(Negate) {
        if (LLVM_LIKELY(O2REG(Negate).isNumber())) {
          O1REG(Negate) = HermesValue::encodeDoubleValue(-O2REG(Negate).getNumber());
        } else {
          CAPTURE_IP_ASSIGN( res, toNumber_RJS(runtime, Handle<>(&O2REG(Negate))));
          if (res == ExecutionStatus::EXCEPTION)
            goto exception;
          gcScope.flushToSmallCount(KEEP_HANDLES);
          O1REG(Negate) = HermesValue::encodeDoubleValue(-res->getNumber());
        }
        ip = NEXTINST(Negate);
        DISPATCH;
      }
      CASE(TypeOf) {
        CAPTURE_IP_ASSIGN( O1REG(TypeOf), typeOf(runtime, Handle<>(&O2REG(TypeOf))));
        ip = NEXTINST(TypeOf);
        DISPATCH;
      }
      CASE(Mod) {
        
        
        
        
        
        
        
        
        if (LLVM_LIKELY(O2REG(Mod).isNumber() && O3REG(Mod).isNumber())) {
          
          O1REG(Mod) = HermesValue::encodeDoubleValue( std::fmod(O2REG(Mod).getNumber(), O3REG(Mod).getNumber()));
          ip = NEXTINST(Mod);
          DISPATCH;
        }
        CAPTURE_IP_ASSIGN(res, toNumber_RJS(runtime, Handle<>(&O2REG(Mod))));
        if (res == ExecutionStatus::EXCEPTION)
          goto exception;
        double left = res->getDouble();
        CAPTURE_IP_ASSIGN(res, toNumber_RJS(runtime, Handle<>(&O3REG(Mod))));
        if (res == ExecutionStatus::EXCEPTION)
          goto exception;
        O1REG(Mod) = HermesValue::encodeDoubleValue(std::fmod(left, res->getDouble()));
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(Mod);
        DISPATCH;
      }
      CASE(InstanceOf) {
        CAPTURE_IP_ASSIGN( auto result, instanceOfOperator_RJS( runtime, Handle<>(&O2REG(InstanceOf)), Handle<>(&O3REG(InstanceOf))));




        if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(InstanceOf) = HermesValue::encodeBoolValue(*result);
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(InstanceOf);
        DISPATCH;
      }
      CASE(IsIn) {
        {
          if (LLVM_UNLIKELY(!O3REG(IsIn).isObject())) {
            CAPTURE_IP(runtime->raiseTypeError( "right operand of 'in' is not an object"));
            goto exception;
          }
          CAPTURE_IP_ASSIGN( auto cr, JSObject::hasComputed( Handle<JSObject>::vmcast(&O3REG(IsIn)), runtime, Handle<>(&O2REG(IsIn))));




          if (cr == ExecutionStatus::EXCEPTION) {
            goto exception;
          }
          O1REG(IsIn) = HermesValue::encodeBoolValue(*cr);
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(IsIn);
        DISPATCH;
      }

      CASE(PutNewOwnByIdShort) {
        nextIP = NEXTINST(PutNewOwnByIdShort);
        idVal = ip->iPutNewOwnByIdShort.op3;
        goto putOwnById;
      }
      CASE(PutNewOwnNEByIdLong)
      CASE(PutNewOwnByIdLong) {
        nextIP = NEXTINST(PutNewOwnByIdLong);
        idVal = ip->iPutNewOwnByIdLong.op3;
        goto putOwnById;
      }
      CASE(PutNewOwnNEById)
      CASE(PutNewOwnById) {
        nextIP = NEXTINST(PutNewOwnById);
        idVal = ip->iPutNewOwnById.op3;
      }
    putOwnById : {
      assert( O1REG(PutNewOwnById).isObject() && "Object argument of PutNewOwnById must be an object");

      CAPTURE_IP_ASSIGN( auto res, JSObject::defineNewOwnProperty( Handle<JSObject>::vmcast(&O1REG(PutNewOwnById)), runtime, ID(idVal), ip->opCode <= OpCode::PutNewOwnByIdLong ? PropertyFlags::defaultNewNamedPropertyFlags()






                  : PropertyFlags::nonEnumerablePropertyFlags(), Handle<>(&O2REG(PutNewOwnById))));
      if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
        goto exception;
      }
      gcScope.flushToSmallCount(KEEP_HANDLES);
      ip = nextIP;
      DISPATCH;
    }

      CASE(DelByIdLong) {
        idVal = ip->iDelByIdLong.op3;
        nextIP = NEXTINST(DelByIdLong);
        goto DelById;
      }

      CASE(DelById) {
        idVal = ip->iDelById.op3;
        nextIP = NEXTINST(DelById);
      }
    DelById : {
      if (LLVM_LIKELY(O2REG(DelById).isObject())) {
        CAPTURE_IP_ASSIGN( auto status, JSObject::deleteNamed( Handle<JSObject>::vmcast(&O2REG(DelById)), runtime, ID(idVal), defaultPropOpFlags));





        if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(DelById) = HermesValue::encodeBoolValue(status.getValue());
      } else {
        
        CAPTURE_IP_ASSIGN(res, toObject(runtime, Handle<>(&O2REG(DelById))));
        if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
          
          
          
          CAPTURE_IP(amendPropAccessErrorMsgWithPropName( runtime, Handle<>(&O2REG(DelById)), "delete", ID(idVal)));
          goto exception;
        }
        tmpHandle = res.getValue();
        CAPTURE_IP_ASSIGN( auto status, JSObject::deleteNamed( Handle<JSObject>::vmcast(tmpHandle), runtime, ID(idVal), defaultPropOpFlags));





        if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
          goto exception;
        }
        O1REG(DelById) = HermesValue::encodeBoolValue(status.getValue());
        tmpHandle.clear();
      }
      gcScope.flushToSmallCount(KEEP_HANDLES);
      ip = nextIP;
      DISPATCH;
    }

      CASE(DelByVal) {
        if (LLVM_LIKELY(O2REG(DelByVal).isObject())) {
          CAPTURE_IP_ASSIGN( auto status, JSObject::deleteComputed( Handle<JSObject>::vmcast(&O2REG(DelByVal)), runtime, Handle<>(&O3REG(DelByVal)), defaultPropOpFlags));





          if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
            goto exception;
          }
          O1REG(DelByVal) = HermesValue::encodeBoolValue(status.getValue());
        } else {
          
          CAPTURE_IP_ASSIGN(res, toObject(runtime, Handle<>(&O2REG(DelByVal))));
          if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
            goto exception;
          }
          tmpHandle = res.getValue();
          CAPTURE_IP_ASSIGN( auto status, JSObject::deleteComputed( Handle<JSObject>::vmcast(tmpHandle), runtime, Handle<>(&O3REG(DelByVal)), defaultPropOpFlags));





          if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
            goto exception;
          }
          O1REG(DelByVal) = HermesValue::encodeBoolValue(status.getValue());
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        tmpHandle.clear();
        ip = NEXTINST(DelByVal);
        DISPATCH;
      }
      CASE(CreateRegExp) {
        {
          
          CAPTURE_IP_ASSIGN(auto re, JSRegExp::create(runtime));
          
          CAPTURE_IP_ASSIGN( auto pattern, runtime->makeHandle(curCodeBlock->getRuntimeModule()

                                      ->getStringPrimFromStringIDMayAllocate( ip->iCreateRegExp.op2)));
          CAPTURE_IP_ASSIGN( auto flags, runtime->makeHandle(curCodeBlock->getRuntimeModule()

                                      ->getStringPrimFromStringIDMayAllocate( ip->iCreateRegExp.op3)));
          CAPTURE_IP_ASSIGN( auto bytecode, curCodeBlock->getRuntimeModule()->getRegExpBytecodeFromRegExpID( ip->iCreateRegExp.op4));


          CAPTURE_IP_ASSIGN( auto initRes, JSRegExp::initialize(re, runtime, pattern, flags, bytecode));

          if (LLVM_UNLIKELY(initRes == ExecutionStatus::EXCEPTION)) {
            goto exception;
          }
          
          O1REG(CreateRegExp) = re.getHermesValue();
        }
        gcScope.flushToSmallCount(KEEP_HANDLES);
        ip = NEXTINST(CreateRegExp);
        DISPATCH;
      }

      CASE(SwitchImm) {
        if (LLVM_LIKELY(O1REG(SwitchImm).isNumber())) {
          double numVal = O1REG(SwitchImm).getNumber();
          uint32_t uintVal = (uint32_t)numVal;
          if (LLVM_LIKELY(numVal == uintVal) &&  LLVM_LIKELY(uintVal >= ip->iSwitchImm.op4) && LLVM_LIKELY(uintVal <= ip->iSwitchImm.op5))

          {
            
            
            const uint8_t *tablestart = (const uint8_t *)llvh::alignAddr( (const uint8_t *)ip + ip->iSwitchImm.op2, sizeof(uint32_t));

            
            
            const int32_t *loc = (const int32_t *)tablestart + uintVal - ip->iSwitchImm.op4;

            ip = IPADD(*loc);
            DISPATCH;
          }
        }
        
        ip = IPADD(ip->iSwitchImm.op3);
        DISPATCH;
      }
      LOAD_CONST( LoadConstUInt8, HermesValue::encodeDoubleValue(ip->iLoadConstUInt8.op2));

      LOAD_CONST( LoadConstInt, HermesValue::encodeDoubleValue(ip->iLoadConstInt.op2));
      LOAD_CONST( LoadConstDouble, HermesValue::encodeDoubleValue(ip->iLoadConstDouble.op2));

      LOAD_CONST_CAPTURE_IP( LoadConstString, HermesValue::encodeStringValue( curCodeBlock->getRuntimeModule()


                  ->getStringPrimFromStringIDMayAllocate( ip->iLoadConstString.op2)));
      LOAD_CONST_CAPTURE_IP( LoadConstStringLongIndex, HermesValue::encodeStringValue( curCodeBlock->getRuntimeModule()


                  ->getStringPrimFromStringIDMayAllocate( ip->iLoadConstStringLongIndex.op2)));
      LOAD_CONST(LoadConstUndefined, HermesValue::encodeUndefinedValue());
      LOAD_CONST(LoadConstNull, HermesValue::encodeNullValue());
      LOAD_CONST(LoadConstTrue, HermesValue::encodeBoolValue(true));
      LOAD_CONST(LoadConstFalse, HermesValue::encodeBoolValue(false));
      LOAD_CONST(LoadConstZero, HermesValue::encodeDoubleValue(0));
      BINOP(Sub, doSub);
      BINOP(Mul, doMult);
      BINOP(Div, doDiv);
      BITWISEBINOP(BitAnd, &);
      BITWISEBINOP(BitOr, |);
      BITWISEBINOP(BitXor, ^);
      
      
      SHIFTOP(LShift, <<, toUInt32_RJS, uint32_t, int32_t);
      SHIFTOP(RShift, >>, toInt32_RJS, int32_t, int32_t);
      SHIFTOP(URshift, >>, toUInt32_RJS, uint32_t, uint32_t);
      CONDOP(Less, <, lessOp_RJS);
      CONDOP(LessEq, <=, lessEqualOp_RJS);
      CONDOP(Greater, >, greaterOp_RJS);
      CONDOP(GreaterEq, >=, greaterEqualOp_RJS);
      JCOND(Less, <, lessOp_RJS);
      JCOND(LessEqual, <=, lessEqualOp_RJS);
      JCOND(Greater, >, greaterOp_RJS);
      JCOND(GreaterEqual, >=, greaterEqualOp_RJS);

      JCOND_STRICT_EQ_IMPL( JStrictEqual, , IPADD(ip->iJStrictEqual.op1), NEXTINST(JStrictEqual));
      JCOND_STRICT_EQ_IMPL( JStrictEqual, Long, IPADD(ip->iJStrictEqualLong.op1), NEXTINST(JStrictEqualLong));



      JCOND_STRICT_EQ_IMPL( JStrictNotEqual, , NEXTINST(JStrictNotEqual), IPADD(ip->iJStrictNotEqual.op1));



      JCOND_STRICT_EQ_IMPL( JStrictNotEqual, Long, NEXTINST(JStrictNotEqualLong), IPADD(ip->iJStrictNotEqualLong.op1));




      JCOND_EQ_IMPL(JEqual, , IPADD(ip->iJEqual.op1), NEXTINST(JEqual));
      JCOND_EQ_IMPL( JEqual, Long, IPADD(ip->iJEqualLong.op1), NEXTINST(JEqualLong));
      JCOND_EQ_IMPL( JNotEqual, , NEXTINST(JNotEqual), IPADD(ip->iJNotEqual.op1));
      JCOND_EQ_IMPL( JNotEqual, Long, NEXTINST(JNotEqualLong), IPADD(ip->iJNotEqualLong.op1));




      CASE_OUTOFLINE(PutOwnByVal);
      CASE_OUTOFLINE(PutOwnGetterSetterByVal);
      CASE_OUTOFLINE(DirectEval);

      CASE_OUTOFLINE(IteratorBegin);
      CASE_OUTOFLINE(IteratorNext);
      CASE(IteratorClose) {
        if (LLVM_UNLIKELY(O1REG(IteratorClose).isObject())) {
          
          
          
          CAPTURE_IP_ASSIGN( auto res, iteratorClose( runtime, Handle<JSObject>::vmcast(&O1REG(IteratorClose)), Runtime::getEmptyValue()));




          if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
            if (ip->iIteratorClose.op2 && !isUncatchableError(runtime->thrownValue_)) {
              
              runtime->clearThrownValue();
            } else {
              goto exception;
            }
          }
          gcScope.flushToSmallCount(KEEP_HANDLES);
        }
        ip = NEXTINST(IteratorClose);
        DISPATCH;
      }

      CASE(_last) {
        llvm_unreachable("Invalid opcode _last");
      }
    }

    llvm_unreachable("unreachable");

  
  stackOverflow:
    CAPTURE_IP(runtime->raiseStackOverflow( Runtime::StackOverflowKind::JSRegisterStack));

  
  
  handleExceptionInParent:
    
    curCodeBlock = FRAME.getSavedCodeBlock();
    ip = FRAME.getSavedIP();

    
    frameRegs = &runtime->restoreStackAndPreviousFrame(FRAME).getFirstLocalRef();

    
    if (!curCodeBlock)
      return ExecutionStatus::EXCEPTION;



    return ExecutionStatus::EXCEPTION;

  
  exception:
    UPDATE_OPCODE_TIME_SPENT;
    assert( !runtime->thrownValue_.isEmpty() && "thrownValue unavailable at exception");


    bool catchable = true;
    
    
    if (auto *jsError = dyn_vmcast<JSError>(runtime->thrownValue_)) {
      catchable = jsError->catchable();
      if (!jsError->getStackTrace()) {
        
        CAPTURE_IP_ASSIGN( auto errorHandle, runtime->makeHandle(vmcast<JSError>(runtime->thrownValue_)));

        runtime->clearThrownValue();

        CAPTURE_IP(JSError::recordStackTrace( errorHandle, runtime, false, curCodeBlock, ip));

        
        runtime->setThrownValue(errorHandle.getHermesValue());
      }
    }

    gcScope.flushToSmallCount(KEEP_HANDLES);
    tmpHandle.clear();


    if (SingleStep) {
      
      
      state.codeBlock = curCodeBlock;
      state.offset = CUROFFSET;
      return ExecutionStatus::EXCEPTION;
    }

    using PauseOnThrowMode = facebook::hermes::debugger::PauseOnThrowMode;
    auto mode = runtime->debugger_.getPauseOnThrowMode();
    if (mode != PauseOnThrowMode::None) {
      if (!runtime->debugger_.isDebugging()) {
        
        bool caught = runtime->debugger_ .findCatchTarget(InterpreterState(curCodeBlock, CUROFFSET))

                .hasValue();
        bool shouldStop = mode == PauseOnThrowMode::All || (mode == PauseOnThrowMode::Uncaught && !caught);
        if (shouldStop) {
          
          
          
          
          
          InterpreterState tmpState{curCodeBlock, (uint32_t)CUROFFSET};
          CAPTURE_IP_ASSIGN( ExecutionStatus resultStatus, runtime->debugger_.runDebugger( Debugger::RunReason::Exception, tmpState));


          (void)resultStatus;
          assert( tmpState == InterpreterState(curCodeBlock, CUROFFSET) && "not allowed to step internally in a pauseOnThrow");

          gcScope.flushToSmallCount(KEEP_HANDLES);
        }
      }
    }


    int32_t handlerOffset = 0;

    
    while (((handlerOffset = curCodeBlock->findCatchTargetOffset(CUROFFSET)) == -1) || !catchable) {

      PROFILER_EXIT_FUNCTION(curCodeBlock);


      runtime->popCallStack();


      
      curCodeBlock = FRAME.getSavedCodeBlock();
      ip = FRAME.getSavedIP();

      
      frameRegs = &runtime->restoreStackAndPreviousFrame(FRAME).getFirstLocalRef();

      SLOW_DEBUG( dbgs() << "function exit with exception: restored stackLevel=" << runtime->getStackLevel() << "\n");


      
      if (!curCodeBlock) {
        SLOW_DEBUG( dbgs()
            << "function exit with exception: returning to native code\n");
        return ExecutionStatus::EXCEPTION;
      }

      assert( isCallType(ip->opCode) && "return address is not Call-type instruction");




      return ExecutionStatus::EXCEPTION;

    }

    INIT_STATE_FOR_CODEBLOCK(curCodeBlock);

    ip = IPADD(handlerOffset - CUROFFSET);
  }
}

} 
} 
