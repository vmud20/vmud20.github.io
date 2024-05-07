#include<hermes/Public/GCConfig.h>
#include<hermes/VM/GCConcurrency.h>
#include<hermes/VM/GCPointer.h>
#include<hermes/VM/HandleRootOwner.h>
#include<map>
#include<optional>
#include<hermes/VM/ArrayStorage.h>
#include<hermes/VM/RuntimeModule-inline.h>
#include<cstddef>
#include<hermes/Support/SourceErrorManager.h>
#include<cassert>
#include<hermes/VM/InterpreterState.h>
#include<bitset>
#include<llvh/Support/PointerLikeTypeTraits.h>
#include<condition_variable>
#include<hermes/BCGen/HBC/BytecodeDataProvider.h>
#include<hermes/VM/SmallHermesValue-inline.h>
#include<hermes/VM/CompressedPointer.h>
#include<hermes/VM/SmallXString.h>
#include<random>
#include<system_error>
#include<hermes/Support/StringTable.h>
#include<hermes/VM/Casting.h>
#include<PredefinedStrings.def>
#include<llvh/ADT/DenseMap.h>
#include<hermes/VM/InternalProperties.def>
#include<hermes/VM/RuntimeModule.h>
#include<hermes/VM/CallResult.h>
#include<PredefinedSymbols.def>
#include<hermes/VM/SlotKinds.def>
#include<memory>
#include<hermes/VM/NativeArgs.h>
#include<hermes/BCGen/HBC/BytecodeFileFormat.h>
#include<llvh/ADT/SmallString.h>
#include<cmath>
#include<TokenKinds.def>
#include<llvh/Support/MathExtras.h>
#include<llvh/Support/ErrorOr.h>
#include<hermes/VM/Predefined.h>
#include<array>
#include<CallResult.h>
#include<hermes/Inst/Inst.h>
#include<hermes/VM/RootSections.def>
#include<sigmux.h>
#include<llvh/Support/raw_ostream.h>
#include<hermes/Public/DebuggerTypes.h>
#include<hermes/VM/Runtime.h>
#include<hermes/Public/CrashManager.h>
#include<hermes/VM/SegmentInfo.h>
#include<hermes/Support/StringSetVector.h>
#include<future>
#include<hermes/VM/StringPrimitive.h>
#include<hermes/BCGen/HBC/BytecodeList.def>
#include<hermes/VM/ExpectedPageSize.h>
#include<hermes/VM/MallocGC.h>
#include<hermes/VM/AllocOptions.h>
#include<hermes/VM/HermesValueTraits.h>
#include<hermes/BCGen/HBC/DebugInfo.h>
#include<hermes/VM/SlotAcceptor.h>
#include<llvh/Support/Format.h>
#include<llvh/ADT/MapVector.h>
#include<llvh/ADT/SparseBitVector.h>
#include<new>
#include<Builtins.def>
#include<llvh/ADT/DenseMapInfo.h>
#include<llvh/ADT/Twine.h>
#include<functional>
#include<llvh/Support/Compiler.h>
#include<sstream>
#include<hermes/VM/SegmentedArray.h>
#include<unordered_map>
#include<SmallXString.h>
#include<hermes/VM/Interpreter.h>
#include<cstdlib>
#include<signal.h>
#include<hermes/VM/HeapAlign.h>
#include<hermes/VM/CellKinds.def>
#include<string>
#include<atomic>
#include<llvh/Support/Debug.h>
#include<hermes/Support/RegExpSerialization.h>
#include<llvh/ADT/STLExtras.h>
#include<hermes/VM/Profiler.h>
#include<hermes/VM/StringView.h>
#include<hermes/Support/StringTableEntry.h>
#include<hermes/Support/CheckedMalloc.h>
#include<hermes/VM/Callable.h>
#include<hermes/VM/BigIntPrimitive.h>
#include<mutex>
#include<llvh/ADT/SmallBitVector.h>
#include<cstdint>
#include<hermes/Public/GCTripwireContext.h>
#include<hermes/VM/RegExpMatch.h>
#include<unordered_set>
#include<hermes/ADT/BitArray.h>
#include<x86intrin.h>
#include<hermes/VM/JSObject.h>
#include<hermes/VM/StackTracesTree-NoRuntime.h>
#include<utility>
#include<hermes/VM/SmallHermesValue.h>
#include<llvh/ADT/FoldingSet.h>
#include<hermes/Support/Allocator.h>
#include<hermes/VM/Handle.h>
#include<hermes/VM/AllocResult.h>
#include<hermes/Support/OSCompat.h>
#include<hermes/VM/GC.h>
#include<algorithm>
#include<vector>
#include<hermes/VM/CellKind.h>
#include<hermes/VM/StringRefUtils.h>
#include<hermes/VM/VTable.h>
#include<llvh/ADT/StringExtras.h>
#include<cstring>
#include<hermes/Support/HashString.h>
#include<malloc.h>
#include<hermes/VM/GCCell.h>
#include<hermes/VM/GCPointer-inline.h>
#include<hermes/Support/JSONEmitter.h>
#include<list>
#include<limits>
#include<hermes/Support/Algorithms.h>
#include<hermes/VM/PropertyCache.h>
#include<hermes/VM/GCDecl.h>
#include<hermes/VM/Domain.h>
#include<hermes/VM/TwineChar16.h>
#include<hermes/Support/ErrorHandling.h>
#include<hermes/VM/InternalProperty.h>
#include<llvh/Support/SourceMgr.h>
#include<hermes/BCGen/HBC/ConsecutiveStringStorage.h>
#include<llvh/ADT/Statistic.h>
#include<llvh/ADT/DenseSet.h>
#include<hermes/Support/UTF8.h>
#include<hermes/VM/VMExperiments.h>
#include<hermes/VM/WeakRoot-inline.h>
#include<hermes/Public/RuntimeConfig.h>
#include<hermes/VM/Operations.h>
#include<hermes/VM/IdentifierTable.h>
#include<hermes/VM/HeapSnapshot.def>
#include<llvh/ADT/None.h>
#include<thread>
#include<hermes/Support/Conversions.h>
#include<llvh/ADT/ArrayRef.h>
#include<hermes/VM/WeakRoot.h>
#include<hermes/VM/AlignedStorage.h>
#include<hermes/ADT/PtrOrInt.h>
#include<hermes/VM/SymbolID.h>
#include<llvh/Support/type_traits.h>
#include<InternalProperties.def>
#include<hermes/VM/HermesValue.h>
#include<iterator>
#include<hermes/Support/Compiler.h>
#include<llvh/ADT/Optional.h>
#include<hermes/Support/SlowAssert.h>
#include<hermes/Public/Buffer.h>
#include<hermes/VM/PointerBase.h>
#include<llvh/Support/Casting.h>
#include<hermes/VM/HeapSnapshot.h>
#include<hermes/VM/Metadata.h>
#include<hermes/VM/HermesValue-inline.h>
#include<hermes/VM/CodeBlock.h>
#include<llvh/ADT/StringRef.h>
#include<hermes/VM/HandleRootOwner-inline.h>
#include<hermes/VM/WeakRefSlot.h>
#include<chrono>
#include<llvh/Support/TrailingObjects.h>
#include<tuple>
#include<llvh/Support/AlignOf.h>
#include<hermes/VM/PropertyDescriptor.h>
#include<io.h>
#include<llvh/ADT/simple_ilist.h>
#include<llvh/ADT/BitVector.h>
#include<hermes/VM/TypedArrays.def>
#include<hermes/VM/AllocSource.h>
#include<llvh/ADT/SmallVector.h>
#include<hermes/VM/GCBase.h>
#include<llvh/Support/ErrorHandling.h>
#include<hermes/Support/BigIntSupport.h>
#include<hermes/VM/StackFrame.h>
#include<unistd.h>
#include<hermes/Support/OptValue.h>
#include<type_traits>
#include<hermes/VM/HadesGC.h>
#include<deque>
#define CUROFFSET ((const uint8_t *)ip - (const uint8_t *)curCodeBlock->begin())
#define DEFAULT_PROP_OP_FLAGS(strictMode) \
  (strictMode ? PropOpFlags().plusThrowOnError() : PropOpFlags())
#define FRAME StackFramePtr(frameRegs - StackFrameLayout::FirstLocal)
#define HERMES_VM_INTERPRETER_INTERNAL_H
#define ID(stringID) \
  (curCodeBlock->getRuntimeModule()->getSymbolIDMustExist(stringID))
#define IPADD(val) ((const Inst *)((const uint8_t *)ip + (val)))
#define NEXTINST(name) ((const Inst *)(&ip->i##name + 1))
#define O1REG(name) REG(ip->i##name.op1)
#define O2REG(name) REG(ip->i##name.op2)
#define O3REG(name) REG(ip->i##name.op3)
#define O4REG(name) REG(ip->i##name.op4)
#define O5REG(name) REG(ip->i##name.op5)
#define O6REG(name) REG(ip->i##name.op6)
#define REG(index) frameRegs[index]
#define HERMES_VM_INTERPRETER_H
#define HERMESVM_CRASH_TRACE 0
#define HERMES_VM_RUNTIME_H
#define PROP_CACHE_IDS(V) V(RegExpLastIndex, Predefined::lastIndex)
#define RUNTIME_HV_FIELD(name) PinnedHermesValue name{};
#define RUNTIME_HV_FIELD_INSTANCE(name) RUNTIME_HV_FIELD(name)
#define RUNTIME_HV_FIELD_PROTOTYPE(name) RUNTIME_HV_FIELD(name)
#define RUNTIME_HV_FIELD_RUNTIMEMODULE(name) RUNTIME_HV_FIELD(name)
#define V(id, predef) id,
#define INLINECACHE_PROFILER_H
#define HERMES_VM_SYMBOLID_H
#define HERMES_VM_GCDECL_H
#define HERMES_VM_GCCONCURRENCY_H
#define HERMES_VM_VMEXPERIMENTS_H
#define HERMES_SUPPORT_TWINECHAR16_H
#define HERMES_VM_UTF16REF_H
#define HERMES_SUPPORT_CONVERSIONS_H
#define HERMES_SUPPORT_OPTVALUE_H
#define HERMES_ATTRIBUTE_FORMAT(archetype, string_index, first_to_check) \
  __attribute__((format(archetype, string_index, first_to_check)))
#define HERMES_ATTRIBUTE_WARN_UNUSED_RESULT_TYPE \
  __attribute__((warn_unused_result))
#define HERMES_ATTRIBUTE_WARN_UNUSED_VARIABLES __attribute__((warn_unused))
#define HERMES_LIMIT_STACK_DEPTH
#define HERMES_SUPPORT_COMPILER_H
#define TsanBenignRaceSized(address, size, description)
#define TsanIgnoreReadsBegin()
#define TsanIgnoreReadsEnd()
#define TsanIgnoreWritesBegin() AnnotateIgnoreWritesBegin("__FILE__", "__LINE__")
#define TsanIgnoreWritesEnd() AnnotateIgnoreWritesEnd("__FILE__", "__LINE__")
#define TsanThreadName(name) AnnotateThreadName("__FILE__", "__LINE__", name)
#define HERMES_VM_TIMELIMITMONITOR_H
#define HERMES_VM_SYMBOLREGISTRY_H
#define HERMES_VM_HERMESVALUE_H
#define HERMES_VM_HANDLE_H
#define HERMES_VM_GCOBJECT(name) \
  class name;                    \
  template <>                    \
  struct IsGCObject<name> : public std::true_type {}
#define HERMES_VM_HERMESVALUETRAITS_H
#define CELL_KIND(name) name##Kind,
#define CELL_RANGE(rangeName, first, last) \
  rangeName##Kind_first = first##Kind, rangeName##Kind_last = last##Kind,
#define HERMES_VM_CELLKIND_H
#define HERMES_VM_GCPOINTER_H
#define HERMES_VM_COMPRESSEDPOINTER_H
#define HERMES_VM_POINTERBASE_H
#define HERMESVM_COMPRESSED_POINTERS
#define HERMESVM_CONTIGUOUS_HEAP
#define HERMES_VM_SEGMENTINFO_H
#define HERMES_VM_ALIGNED_STORAGE_H
#define HERMES_VM_ALLOC_SOURCE_H
#define HERMES_VM_CASTING_H
#define HERMES_VM_GCCELL_H
#define HERMES_VM_VTABLE_H
#define HERMES_VM_SLOTACCEPTOR_H
#define ROOT_SECTION(name) name,
#define HERMES_VM_SMALLHERMESVALUE_H
#define HERMES_VM_HEAPALIGN_H
#define HERMES_SUPPORT_ALGORITHMS_H
#define HERMES_VM_HEAPSNAPSHOT_H
#define V8_EDGE_FIELD(label, type) +1
#define V8_EDGE_TYPE(enumerand, label) enumerand,
#define V8_LOCATION_FIELD(label) +1
#define V8_NODE_FIELD(label, type) +1
#define V8_NODE_TYPE(enumerand, label) enumerand,
#define V8_SAMPLE_FIELD(label) +1
#define V8_SNAPSHOT_SECTION(enumerand, label) enumerand,
#define HERMES_STACK_TRACES_TREE_NO_RUNTIME_H
#define HERMES_SUPPORT_STRINGSETVECTOR_H
#define HERMES_SUPPORT_JSONEMITTER_H
#define GC_KIND(kind)          \
  case GCBase::HeapKind::kind: \
    return f(llvh::cast<kind>(this));
#define HERMES_VM_GCBASE_H
#define ROOT_SECTION(name) name,
#define RUNTIME_GC_KINDS GC_KIND(HadesGC)
#define HERMES_VM_WEAKREFSLOT_H
#define HERMES_VM_WEAKROOT_H
#define HERMES_VM_STORAGEPROVIDER_H
#define HERMES_VM_SLOTVISITOR_H
#define SLOT_TYPE(type)              \
  for (; i < offsets.end##type; ++i) \
    visitSlot<type>(base + offsets.fields[i]);
#define HERMES_VM_METADATA_H
#define HERMES_VM_EXECTRACE_H
#define HERMES_VM_BUILDMETADATA_H
#define HERMES_VM_ALLOCOPTIONS_H
#define HERMES_SUPPORT_STATSACCUMULATOR_H
#define HERMES_SUPPORT_OSCOMPAT_H
#define STDERR_FILENO 2
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define HERMES_SUPPORT_CHECKEDMALLOC_H
#define HERMES_EXTRA_DEBUG(x) x
#define HERMES_SUPPORT_ERRORHANDLING_H
#define HERMES_PLATFORM_LOGGING_H
#define DEFINE_OPCODE(name) name,
#define DEFINE_OPCODE_0(name) LLVM_PACKED(struct name##Inst { OpCode opCode; });
#define DEFINE_OPCODE_1(name, op1type) \
  LLVM_PACKED(struct name##Inst {      \
    OpCode opCode;                     \
    Operand##op1type op1;              \
  });
#define DEFINE_OPCODE_2(name, op1type, op2type) \
  LLVM_PACKED(struct name##Inst {               \
    OpCode opCode;                              \
    Operand##op1type op1;                       \
    Operand##op2type op2;                       \
  });
#define DEFINE_OPCODE_3(name, op1type, op2type, op3type) \
  LLVM_PACKED(struct name##Inst {                        \
    OpCode opCode;                                       \
    Operand##op1type op1;                                \
    Operand##op2type op2;                                \
    Operand##op3type op3;                                \
  });
#define DEFINE_OPCODE_4(name, op1type, op2type, op3type, op4type) \
  LLVM_PACKED(struct name##Inst {                                 \
    OpCode opCode;                                                \
    Operand##op1type op1;                                         \
    Operand##op2type op2;                                         \
    Operand##op3type op3;                                         \
    Operand##op4type op4;                                         \
  });
#define DEFINE_OPCODE_5(name, op1type, op2type, op3type, op4type, op5type) \
  LLVM_PACKED(struct name##Inst {                                          \
    OpCode opCode;                                                         \
    Operand##op1type op1;                                                  \
    Operand##op2type op2;                                                  \
    Operand##op3type op3;                                                  \
    Operand##op4type op4;                                                  \
    Operand##op5type op5;                                                  \
  });
#define DEFINE_OPCODE_6(                                        \
    name, op1type, op2type, op3type, op4type, op5type, op6type) \
  LLVM_PACKED(struct name##Inst {                               \
    OpCode opCode;                                              \
    Operand##op1type op1;                                       \
    Operand##op2type op2;                                       \
    Operand##op3type op3;                                       \
    Operand##op4type op4;                                       \
    Operand##op5type op5;                                       \
    Operand##op6type op6;                                       \
  });
#define DEFINE_OPERAND_TYPE(name, type) typedef type Operand##name;
#define HERMES_INST_INST_H
#define HERMES_VM_CALLRESULT_H
#define HERMES_VM_STACKFRAME_H
#define _HERMESVM_DEFINE_STACKFRAME_REF(name) \
  LLVM_ATTRIBUTE_ALWAYS_INLINE                \
  QualifiedHV &get##name##Ref() const {       \
    return frame_[StackFrameLayout::name];    \
  }
#define HERMES_VM_NATIVEARGS_H
#define HERMESVM_DEBUG_MAX_GCSCOPE_HANDLES 48
#define HERMES_VM_HANDLEROOTOWNER_H
#define HERMES_BCGEN_HBC_STACKFRAMELAYOUT_H
#define HERMES_VM_RUNTIMEMODULE_H
#define HERMES_VM_IDENTIFIERTABLE_H
#define HERMES_VM_IDENTIFIERHASHTABLE_H
#define HERMES_SUPPORT_HASHSTRING_H
#define HERMES_SUPPORT_JENKINSHASH_H
#define HERMES_ADT_PTRORINT_H
#define HERMES_SUPPORT_COMPACTARRAY_H
#define HERMES_VM_GC_H
#define HERMES_VM_MALLOCGC_H
#define HERMES_VM_HADESGC_H
#define HERMES_VM_SEGMENT_H
#define HERMES_VM_MARKBITARRAYNC_H
#define HERMES_VM_EXPECTEDPAGESIZE_H
#define HERMES_ADT_BITARRAY_H
#define HERMES_VM_CARDTABLE_H
#define HERMES_VM_ALLOCRESULT_H
#define HERMES_VM_MARKUNUSED_H
#define HERMES_SLOW_ASSERT(x) assert(x)
#define HERMES_SUPPORT_SLOWASSERT_H
#define SLOW_DEBUG(x) LLVM_DEBUG(x)
#define HERMES_ADT_EXPONENTIALMOVINGAVERAGE_H
#define HERMES_VM_CODEBLOCK_H
#define HERMES_VM_SERIALIZEDLITERALPARSER_H
#define HERMES_BCGEN_HBC_SERIALIZEDLITERALPARSERBASE_H
#define PROJECT_PROPERTYCACHE_H
#define HERMESVM_RDTSC() __rdtsc()
#define HERMES_VM_PROFILER_H
#define INC_OPCODE_COUNT ++runtime.opcodeCount
#define INIT_OPCODE_PROFILER      \
  uint64_t startTime = __rdtsc(); \
  unsigned curOpcode = (unsigned)OpCode::Call;
#define PROFILER_ENTER_FUNCTION(block)
#define PROFILER_EXIT_FUNCTION(block)
#define RECORD_OPCODE_START_TIME               \
  curOpcode = (unsigned)ip->opCode;            \
  runtime.opcodeExecuteFrequency[curOpcode]++; \
  startTime = __rdtsc();
#define UPDATE_OPCODE_TIME_SPENT \
  runtime.timeSpent[curOpcode] += __rdtsc() - startTime
#define HEADER_FIELD_ACCESSOR(api_type, store_type, name, bits) \
  api_type name() const {                                       \
    if (LLVM_UNLIKELY(isLarge()))                               \
      return asLarge()->name;                                   \
    else                                                        \
      return asSmall()->name;                                   \
  }
#define HERMES_BCGEN_HBC_BYTECODEDATAPROVIDER_H
#define HERMES_SUPPORT_STRINGTABLEENTRY_H
#define HERMES_SUPPORT_REGEXPSERIALIZATION_H
#define HERMES_HAS_REAL_PAGE_TRACKER
#define HERMES_VM_INSTRUMENTATION_PAGEACCESSTRACKERWINDOWS_H
#define HERMES_SUPPORT_PAGEACCESSTRACKERPOSIX_H
#define HERMES_SUPPORT_BIGINT_H
#define HERMES_SUPPORT_SOURCEMAPGENERATOR_H
#define HERMES_SUPPORT_SOURCEMAP_H
#define HERMES_PARSER_JSONPARSER_H
#define HERMES_PARSER_PACK_H
#define HERMES_PARSER_JSLEXER_H
#define PUNCTUATOR(name, str) \
  case TokenKind::name:       \
    return true;
#define TOK(name, str) name,
#define HERMES_SUPPORT_UTF8_H
#define HERMES_PLATFORMUNICODE_CHARACTERPROPERTIES_H
#define HERMES_SUPPORT_STRINGTABLE_H
#define HERMES_SUPPORT_ALLOCATOR_H
#define HERMES_SUPPORT_SOURCEERRORMANAGER_H
#define HERMES_SUPPORT_WARNINGS_H
#define WARNING_CATEGORY_HIDDEN(name, specifier, description) name,
#define HERMES_PARSER_CONFIG_H
#define HERMES_PARSE_FLOW 0
#define HERMES_PARSE_JSX 0
#define HERMES_PARSE_TS 0
#define HERMES_BCGEN_HBC_DEBUGINFO_H
#define HERMES_SUPPORT_LEB128_H
#define HERMES_BCGEN_HBC_UNIQUINGFILENAMETABLE_H
#define HERMES_SUPPORT_STRINGSTORAGE_H
#define HERMES_BCGEN_HBC_STREAMVECTOR_H
#define CHECK_COPY_FIELD(api_type, store_type, name, bits) \
  if (large.name > (1U << bits) - 1) {                     \
    setLargeHeaderOffset(large.infoOffset);                \
    return;                                                \
  }                                                        \
  name = large.name;
#define DECLARE_BITFIELD(api_type, store_type, name, bits) \
  store_type name : bits;
#define DECLARE_FIELD(api_type, store_type, name, bits) api_type name;
#define FUNC_HEADER_FIELDS(V)                    \
                                 \
  V(uint32_t, uint32_t, offset, 25)              \
  V(uint32_t, uint32_t, paramCount, 7)           \
                                \
  V(uint32_t, uint32_t, bytecodeSizeInBytes, 15) \
  V(uint32_t, uint32_t, functionName, 17)        \
                                 \
  V(uint32_t, uint32_t, infoOffset, 25)          \
  V(uint32_t, uint32_t, frameSize, 7)            \
              \
  V(uint32_t, uint8_t, environmentSize, 8)       \
  V(uint8_t, uint8_t, highestReadCacheIndex, 8)  \
  V(uint8_t, uint8_t, highestWriteCacheIndex, 8)
#define HERMES_BCGEN_HBC_BYTECODEFILEFORMAT_H
#define HERMES_SUPPORT_SHA1_H
#define HERMES_SUPPORT_STRINGKIND_H
#define HERMES_BCGEN_HBC_BYTECODEVERSION_H
#define HERMES_VM_REGEXPMATCH_H
#define HERMES_VM_PROPERTYDESCRIPTOR_H
#define HERMES_VM_PREDEFINED_H
#define NAMED_PROP(name) InternalProperty##name,
#define PROP(i) InternalProperty##i,
#define STR(name, string) name,
#define SYM(name, desc) name,
#define HERMES_VM_INTERPRETERSTATE_H
#define HERMES_VM_INTERNALPROPERTY_H
#define HERMES_VM_HANDLEROOTOWNER_INLINE_H
#define HERMES_VM_HANDLE_INLINE_H
#define GC_KIND(kind) sizeof(kind),
#define HERMES_VM_GCSTORAGE_H
#define HERMES_VM_GCBASE_INLINE_H
#define HERMES_VM_DEBUGGER_DEBUGGER_H
#define HERMES_VM_DEBUGGER_DEBUGCOMMAND_H
#define DEFINE_OPCODE(name) name##Op,
#define DEFINE_OPCODE_0(name)        \
  offset_t emit##name() {            \
    auto loc = emitOpcode(name##Op); \
    return loc;                      \
  };
#define DEFINE_OPCODE_1(name, t1)    \
  offset_t emit##name(param_t p1) {  \
    auto loc = emitOpcode(name##Op); \
    emit##t1(p1);                    \
    return loc;                      \
  };
#define DEFINE_OPCODE_2(name, t1, t2)           \
  offset_t emit##name(param_t p1, param_t p2) { \
    auto loc = emitOpcode(name##Op);            \
    emit##t1(p1);                               \
    emit##t2(p2);                               \
    return loc;                                 \
  };
#define DEFINE_OPCODE_3(name, t1, t2, t3)                   \
  offset_t emit##name(param_t p1, param_t p2, param_t p3) { \
    auto loc = emitOpcode(name##Op);                        \
    emit##t1(p1);                                           \
    emit##t2(p2);                                           \
    emit##t3(p3);                                           \
    return loc;                                             \
  };
#define DEFINE_OPCODE_4(name, t1, t2, t3, t4)                           \
  offset_t emit##name(param_t p1, param_t p2, param_t p3, param_t p4) { \
    auto loc = emitOpcode(name##Op);                                    \
    emit##t1(p1);                                                       \
    emit##t2(p2);                                                       \
    emit##t3(p3);                                                       \
    emit##t4(p4);                                                       \
    return loc;                                                         \
  };
#define DEFINE_OPCODE_5(name, t1, t2, t3, t4, t5)                   \
  offset_t emit##name(                                              \
      param_t p1, param_t p2, param_t p3, param_t p4, param_t p5) { \
    auto loc = emitOpcode(name##Op);                                \
    emit##t1(p1);                                                   \
    emit##t2(p2);                                                   \
    emit##t3(p3);                                                   \
    emit##t4(p4);                                                   \
    emit##t5(p5);                                                   \
    return loc;                                                     \
  };
#define DEFINE_OPCODE_6(name, t1, t2, t3, t4, t5, t6) \
  offset_t emit##name(                                \
      param_t p1,                                     \
      param_t p2,                                     \
      param_t p3,                                     \
      param_t p4,                                     \
      param_t p5,                                     \
      param_t p6) {                                   \
    auto loc = emitOpcode(name##Op);                  \
    emit##t1(p1);                                     \
    emit##t2(p2);                                     \
    emit##t3(p3);                                     \
    emit##t4(p4);                                     \
    emit##t5(p5);                                     \
    emit##t6(p6);                                     \
    return loc;                                       \
  };
#define DEFINE_OPERAND_TYPE(name, ctype)          \
  void emit##name(param_t value) {                \
    assert(                                       \
        (((param_t)(ctype)value) == value ||      \
         std::is_floating_point<ctype>::value) && \
        "Value does not fit in " #ctype);         \
    emitOperand(value, sizeof(ctype));            \
  }
#define HERMES_BCGEN_HBC_BYTECODELIST_H
#define HERMES_VM_BASICBLOCKEXECUTIONINFO_H
#define HERMES_VM_WEAKROOT_INLINE_H
#define HERMES_VM_STRINGVIEW_H
#define HERMES_VM_STRINGPRIMITIVE_H
#define HERMES_VM_COPYABLEBASICSTRING_H
#define HERMES_VM_STACKFRAME_INLINE_H
#define HERMES_VM_RUNTIMEMODULE_INLINE_H
#define HERMES_VM_PROPERTYACCESSOR_H
#define HERMES_VM_CALLABLE_H
#define HERMES_VM_RUNTIME_INLINE_H
#define BUILTIN_METHOD(object, name) object##_##name,
#define HERMES_INST_BUILTINS_H
#define JS_BUILTIN(name) PRIVATE_BUILTIN(name)
#define MARK_FIRST_JS_BUILTIN(name) _firstJS = JS_BUILTIN(name)
#define MARK_FIRST_PRIVATE_BUILTIN(name) _firstPrivate = PRIVATE_BUILTIN(name)
#define PRIVATE_BUILTIN(name) BUILTIN_METHOD(HermesBuiltin, name)
#define HERMES_VM_JSOBJECT_H
#define HERMES_VM__LIST_OwnKeysFlags(FLAG) \
  FLAG(IncludeSymbols)                     \
  FLAG(IncludeNonSymbols)                  \
  FLAG(IncludeNonEnumerable)
#define HERMES_VM__LIST_PropOpFlags(FLAG) \
  FLAG(ThrowOnError)                      \
  FLAG(MustExist)                         \
  FLAG(InternalForce)
#define HERMES_VM_TYPESAFEFLAGS_H
#define HERMES_VM__DECLARE_FLAGS_CLASS(ClassName, listMacro) \
  union ClassName {                                          \
   private:                                                  \
    struct {                                                 \
      listMacro(_HERMES_VM__DECL_FLAG)                       \
    };                                                       \
    unsigned flags_ = 0;                                     \
                                                             \
   public:                                                   \
    typedef ClassName Self;                                  \
    unsigned getRaw() const {                                \
      return flags_;                                         \
    }                                                        \
    listMacro(_HERMES_VM__IMPL_FLAG)                         \
  }
#define _HERMES_VM__DECL_FLAG(name) bool f##name##_ : 1;
#define _HERMES_VM__IMPL_FLAG(name) \
  Self plus##name() const {         \
    auto r(*this);                  \
    r.f##name##_ = true;            \
    return r;                       \
  }                                 \
  Self minus##name() const {        \
    auto r(*this);                  \
    r.f##name##_ = false;           \
    return r;                       \
  }                                 \
  Self set##name(bool v) const {    \
    auto r(*this);                  \
    r.f##name##_ = v;               \
    return r;                       \
  }                                 \
  bool get##name() const {          \
    return f##name##_;              \
  }
#define HERMES_VM_SMALLHERMESVALUE_INLINE_H
#define HERMES_VM_HERMESVALUE_INLINE_H
#define HERMES_VM_BOXEDDOUBLE_H
#define HERMES_VM_BIGINTPRIMITIVE_H
#define HERMES_VM_OPERATIONS_H
#define HERMES_VM_HIDDENCLASS_H
#define HERMES_VM_WEAKVALUEMAP_H
#define HERMES_VM_WEAKREF_H
#define HERMES_VM_WEAKREFSLOT_INLINE_H
#define HERMES_VM_GCPOINTER_INL_H
#define HERMES_VM_SEGMENTEDARRAY_H
#define HERMES_VM_DICTPROPERTYMAP_H
#define HERMES_VM_ARRAYSTORAGE_H
#define HERMES_VM_DOMAIN_H
#define HERMES_SUPPORT_COPYABLEVECTOR_H
#define HERMES_VM_CODECOVERAGEPROFILER_H
#define HERMES_VM_JSTYPEDARRAY_H
#define TYPED_ARRAY(name, type) \
  using name##Array = JSTypedArray<type, CellKind::name##ArrayKind>;
#define HERMES_VM_JSARRAYBUFFER_H
#define HERMES_VM_NATIVESTATE_H
#define HERMES_VM_JSREGEXP_H
#define HERMES_VM_SMALLXSTRING_H
#define HERMES_REGEX_TYPES_H
#define HERMES_VM_JSPROXY_H
#define HERMES_VM_JSGENERATOR_H
#define HERMES_VM_JSERROR_H
#define HERMES_VM_JSARRAY_H
#define HERMES_VM_ITERATIONKIND_H
#define HERMES_SLOW_STATISTIC(Name, Desc) STATISTIC(Name, Desc)
#define HERMES_SUPPORT_STATISTIC_H
#define STATISTIC(Name, Desc) static hermes::DummyCounter Name;
#define DEFINE_OPERAND_TYPE(name, type) name,
#define HERMES_INST_INSTDECODE_H
