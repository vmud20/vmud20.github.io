

#define fxBuildHostConstructor(THE, CALLBACK, LENGTH, NAME) fxNewHostConstructor(THE, CALLBACK, LENGTH, NAME)
#define fxBuildHostFunction(THE, CALLBACK, LENGTH, NAME) fxNewHostFunction(THE, CALLBACK, LENGTH, NAME)
#define mxAggregateErrorConstructor the->stackPrototypes[-1 - _AggregateError]
#define mxAggregateErrorPrototype the->stackPrototypes[-1 - mxAggregateErrorPrototypeStackIndex]
#define mxArgc ((the->frame - 1)->value.integer)
#define mxArgumentsSloppyPrototype the->stackPrototypes[-1 - mxArgumentsSloppyPrototypeStackIndex]
#define mxArgumentsStrictPrototype the->stackPrototypes[-1 - mxArgumentsStrictPrototypeStackIndex]
#define mxArgv(THE_INDEX) (the->frame - 2 - (THE_INDEX))
#define mxArrayBufferConstructor the->stackPrototypes[-1 - _ArrayBuffer]
#define mxArrayBufferPrototype the->stackPrototypes[-1 - mxArrayBufferPrototypeStackIndex]
#define mxArrayConstructor the->stackPrototypes[-1 - _Array]
#define  mxArrayIteratorFunction the->stackPrototypes[-1 - mxArrayIteratorFunctionIndex]
#define mxArrayIteratorPrototype the->stackPrototypes[-1 - mxArrayIteratorPrototypeStackIndex]
#define mxArrayLengthAccessor the->stackPrototypes[-1 - mxArrayLengthAccessorStackIndex]
#define mxArrayPrototype the->stackPrototypes[-1 - mxArrayPrototypeStackIndex]
#define mxAssignObjectFunction the->stackPrototypes[-1 - mxAssignObjectFunctionStackIndex]
#define mxAsyncFromSyncIteratorPrototype the->stackPrototypes[-1 - mxAsyncFromSyncIteratorPrototypeStackIndex]
#define mxAsyncFunctionPrototype the->stackPrototypes[-1 - mxAsyncFunctionPrototypeStackIndex]
#define mxAsyncGeneratorFunctionPrototype the->stackPrototypes[-1 - mxAsyncGeneratorFunctionPrototypeStackIndex]
#define mxAsyncGeneratorPrototype the->stackPrototypes[-1 - mxAsyncGeneratorPrototypeStackIndex]
#define mxAsyncIteratorPrototype the->stackPrototypes[-1 - mxAsyncIteratorPrototypeStackIndex]
#define mxAtomicsObject the->stackPrototypes[-1 - _Atomics]
#define mxBehavior(INSTANCE) (gxBehaviors[((INSTANCE)->flag & XS_EXOTIC_FLAG) ? (INSTANCE)->next->ID : 0])
#define mxBehaviorCall(THE, INSTANCE, THIS, ARGUMENTS) \
	(*mxBehavior(INSTANCE)->call)(THE, INSTANCE, THIS, ARGUMENTS)
#define mxBehaviorConstruct(THE, INSTANCE, ARGUMENTS, TARGET) \
	(*mxBehavior(INSTANCE)->construct)(THE, INSTANCE, ARGUMENTS, TARGET)
#define mxBehaviorDefineOwnProperty(THE, INSTANCE, ID, INDEX, VALUE, MASK) \
	(*mxBehavior(INSTANCE)->defineOwnProperty)(THE, INSTANCE, ID, INDEX, VALUE, MASK)
#define mxBehaviorDeleteProperty(THE, INSTANCE, ID, INDEX) \
	(*mxBehavior(INSTANCE)->deleteProperty)(THE, INSTANCE, ID, INDEX)
#define mxBehaviorGetOwnProperty(THE, INSTANCE, ID, INDEX, VALUE) \
	(*mxBehavior(INSTANCE)->getOwnProperty)(THE, INSTANCE, ID, INDEX, VALUE)
#define mxBehaviorGetProperty(THE, INSTANCE, ID, INDEX, FLAG) \
	(*mxBehavior(INSTANCE)->getProperty)(THE, INSTANCE, ID, INDEX, FLAG)
#define mxBehaviorGetPropertyValue(THE, INSTANCE, ID, INDEX, RECEIVER, VALUE) \
	(*mxBehavior(INSTANCE)->getPropertyValue)(THE, INSTANCE, ID, INDEX, RECEIVER, VALUE)
#define mxBehaviorGetPrototype(THE, INSTANCE, PROTOTYPE) \
	(*mxBehavior(INSTANCE)->getPrototype)(THE, INSTANCE, PROTOTYPE)
#define mxBehaviorHasProperty(THE, INSTANCE, ID, INDEX) \
	(*mxBehavior(INSTANCE)->hasProperty)(THE, INSTANCE, ID, INDEX)
#define mxBehaviorIsExtensible(THE, INSTANCE) \
	(*mxBehavior(INSTANCE)->isExtensible)(THE, INSTANCE)
#define mxBehaviorOwnKeys(THE, INSTANCE, FLAG, KEYS) \
	(*mxBehavior(INSTANCE)->ownKeys)(THE, INSTANCE, FLAG, KEYS)
#define mxBehaviorPreventExtensions(THE, INSTANCE) \
	(*mxBehavior(INSTANCE)->preventExtensions)(THE, INSTANCE)
#define mxBehaviorSetProperty(THE, INSTANCE, ID, INDEX, FLAG) \
	(*mxBehavior(INSTANCE)->setProperty)(THE, INSTANCE, ID, INDEX, FLAG)
#define mxBehaviorSetPropertyValue(THE, INSTANCE, ID, INDEX, VALUE, RECEIVER) \
	(*mxBehavior(INSTANCE)->setPropertyValue)(THE, INSTANCE, ID, INDEX, VALUE, RECEIVER)
#define mxBehaviorSetPrototype(THE, INSTANCE, PROTOTYPE) \
	(*mxBehavior(INSTANCE)->setPrototype)(THE, INSTANCE, PROTOTYPE)
#define mxBigInt64ArrayConstructor the->stackPrototypes[-1 - _BigInt64Array]
#define mxBigIntConstructor the->stackPrototypes[-1 - _BigInt]
#define mxBigIntPrototype the->stackPrototypes[-1 - mxBigIntPrototypeStackIndex]
#define mxBigIntString the->stackPrototypes[-1 - mxBigIntStringStackIndex]
#define mxBigUint64ArrayConstructor the->stackPrototypes[-1 - _BigUint64Array]
#define mxBooleanConstructor the->stackPrototypes[-1 - _Boolean]
#define mxBooleanPrototype the->stackPrototypes[-1 - mxBooleanPrototypeStackIndex]
#define mxBooleanString the->stackPrototypes[-1 - mxBooleanStringStackIndex]
		#define mxBoundsCheck 1
#define mxBreakpoints the->stackTop[-1 - mxBreakpointsStackIndex]
#define mxCall() \
	(mxOverflow(-4), \
	fxCall(the))
#define mxCallback(CALLBACK) fxNewLinkerCallback(the, CALLBACK, #CALLBACK)
#define mxCatch(THE_MACHINE) \
		(THE_MACHINE)->firstJump = __JUMP__.nextJump; \
	} \
	else for ( \
		the->stack = __JUMP__.stack, \
		the->scope = __JUMP__.scope, \
		the->frame = __JUMP__.frame, \
		the->code = __JUMP__.code, \
		(THE_MACHINE)->firstJump = __JUMP__.nextJump; \
		(__JUMP__.stack); \
		__JUMP__.stack = NULL)
#define mxCheck(THE, THE_ASSERTION) \
	if (!(THE_ASSERTION)) \
		fxCheck(THE, "__FILE__","__LINE__")
#define mxCheckCStack() \
	(fxCheckCStack(the))
#define mxCompartmentConstructor the->stackPrototypes[-1 - _Compartment]
#define mxCompartmentGlobal the->stackPrototypes[-1 - mxCompartmentGlobalStackIndex]
#define mxCompartmentPrototype the->stackPrototypes[-1 - mxCompartmentPrototypeStackIndex]
#define mxCopyObjectFunction the->stackPrototypes[-1 - mxCopyObjectFunctionStackIndex]
#define mxDataViewConstructor the->stackPrototypes[-1 - _DataView]
#define mxDataViewPrototype the->stackPrototypes[-1 - mxDataViewPrototypeStackIndex]
#define mxDateConstructor the->stackPrototypes[-1 - _Date]
#define mxDatePrototype the->stackPrototypes[-1 - mxDatePrototypeStackIndex]
#define mxDebugID(THE_ERROR, THE_FORMAT, THE_ID) ( \
	fxIDToString(the, THE_ID, the->nameBuffer, sizeof(the->nameBuffer)), \
	fxThrowMessage(the, NULL, 0, THE_ERROR, THE_FORMAT, the->nameBuffer) \
)
#define mxDecodeURIComponentFunction the->stackPrototypes[-1 - _decodeURIComponent]
#define mxDecodeURIFunction the->stackPrototypes[-1 - _decodeURI]
#define mxDefaultString the->stackPrototypes[-1 - mxDefaultStringStackIndex]
#define mxDefineAll(ID, INDEX, FLAG, MASK) \
	(mxMeterOne(), fxDefineAll(the, ID, INDEX, FLAG, MASK))
#define mxDefineAt(FLAG, MASK) \
	(mxMeterOne(), fxDefineAt(the, FLAG, MASK))
#define mxDefineID(ID, FLAG, MASK) \
	(mxMeterOne(), fxDefineAll(the, ID, 0, FLAG, MASK))
#define mxDefineIndex(INDEX, FLAG, MASK) \
	(mxMeterOne(), fxDefineAll(the, XS_NO_ID, INDEX, FLAG, MASK))
#define mxDeleteAll(ID, INDEX) \
	(mxMeterOne(), fxDeleteAll(the, ID, INDEX))
#define mxDeleteAt() \
	(mxMeterOne(), fxDeleteAt(the))
#define mxDeleteID(ID) \
	(mxMeterOne(), fxDeleteAll(the, ID, 0))
#define mxDeleteIndex(INDEX) \
	(mxMeterOne(), fxDeleteAll(the, XS_NO_ID, INDEX))
#define mxDub() \
	(mxOverflow(-1), \
	((--the->stack)->next = C_NULL, \
	the->stack->flag = XS_NO_FLAG, \
	mxInitSlotKind(the->stack, (the->stack + 1)->kind), \
	the->stack->value = (the->stack + 1)->value))
#define mxDuringJobs the->stackTop[-1 - mxDuringJobsStackIndex]
#define mxEmptyCode the->stackPrototypes[-1 - mxEmptyCodeStackIndex]
#define mxEmptyRegExp the->stackPrototypes[-1 - mxEmptyRegExpStackIndex]
#define mxEmptyString the->stackPrototypes[-1 - mxEmptyStringStackIndex]
#define mxEncodeURIComponentFunction the->stackPrototypes[-1 - _encodeURIComponent]
#define mxEncodeURIFunction the->stackPrototypes[-1 - _encodeURI]
#define mxEnumeratorFunction the->stackPrototypes[-1 - mxEnumeratorFunctionStackIndex]
#define mxErrorConstructor the->stackPrototypes[-1 - _Error]
#define mxErrorPrototype the->stackPrototypes[-1 - mxErrorPrototypeStackIndex]
#define mxErrorPrototypes(THE_ERROR) (the->stackPrototypes[-mxErrorPrototypeStackIndex-(THE_ERROR)])
#define mxEscapeFunction the->stackPrototypes[-1 - _escape]
#define mxEvalError(...) fxThrowMessage(the, NULL, 0, XS_EVAL_ERROR, __VA_ARGS__)
#define mxEvalErrorConstructor the->stackPrototypes[-1 - _EvalError]
#define mxEvalErrorPrototype the->stackPrototypes[-1 - mxEvalErrorPrototypeStackIndex]
#define mxEvalFunction the->stackPrototypes[-1 - _eval]
#define mxException the->stackTop[-1 - mxExceptionStackIndex]
#define  mxExecuteRegExpFunction the->stackPrototypes[-1 - mxExecuteRegExpFunctionIndex]
#define mxFinalizationRegistries the->stackTop[-1 - mxFinalizationRegistriesStackIndex]
#define mxFinalizationRegistryConstructor the->stackPrototypes[-1 - _FinalizationRegistry]
#define mxFinalizationRegistryPrototype the->stackPrototypes[-1 - mxFinalizationRegistryPrototypeStackIndex]
#define mxFloat32ArrayConstructor the->stackPrototypes[-1 - _Float32Array]
#define mxFloat64ArrayConstructor the->stackPrototypes[-1 - _Float64Array]
#define mxFloatingPointOp(operation) \
		 \
		the->floatingPointOps += 1
#define mxFrameToEnvironment(FRAME) ((FRAME) - 1 - ((FRAME) - 1)->value.integer - 1)
#define mxFunction (the->frame + 3)
#define mxFunctionConstructor the->stackPrototypes[-1 - _Function]
#define mxFunctionInstanceCode(INSTANCE) 		((INSTANCE)->next)
#define mxFunctionInstanceHome(INSTANCE) 		((INSTANCE)->next->next)
#define mxFunctionInstanceProfile(INSTANCE) 	((INSTANCE)->next->next->next)
#define mxFunctionPrototype the->stackPrototypes[-1 - mxFunctionPrototypeStackIndex]
#define mxFunctionString the->stackPrototypes[-1 - mxFunctionStringStackIndex]
#define mxGeneratorFunctionPrototype the->stackPrototypes[-1 - mxGeneratorFunctionPrototypeStackIndex]
#define mxGeneratorPrototype the->stackPrototypes[-1 - mxGeneratorPrototypeStackIndex]
#define mxGetAll(ID, INDEX) \
	(mxMeterOne(), fxGetAll(the, ID, INDEX))
#define mxGetAt() \
	(mxMeterOne(), fxGetAt(the))
#define mxGetID(ID) \
	(mxMeterOne(), fxGetAll(the, ID, 0))
#define mxGetIndex(INDEX) \
	(mxMeterOne(), fxGetAll(the, XS_NO_ID, INDEX))
#define mxGlobal the->stackTop[-1 - mxGlobalStackIndex]
#define mxHasAll(ID, INDEX) \
	(mxMeterOne(), fxHasAll(the, ID, INDEX))
#define mxHasAt() \
	(mxMeterOne(), fxHasAt(the))
#define mxHasID(ID) \
	(mxMeterOne(), fxHasAll(the, ID, 0))
#define mxHasIndex(INDEX) \
	(mxMeterOne(), fxHasAll(the, XS_NO_ID, INDEX))
#define mxHookInstance the->stackPrototypes[-1 - mxHookInstanceIndex]
#define mxHostInspectors the->stackTop[-1 - mxHostInspectorsStackIndex]
#define mxHostPrototype the->stackPrototypes[-1 - mxHostPrototypeStackIndex]
#define mxHosts the->stackTop[-1 - mxHostsStackIndex]
#define mxID(ID) ((txID)(ID))
#define mxInfinity the->stackPrototypes[-1 - _Infinity]
#define mxInitSlotKind(SLOT,KIND) ((SLOT)->ID_FLAG_KIND = (uint8_t)(KIND))
#define  mxInitializeRegExpFunction the->stackPrototypes[-1 - mxInitializeRegExpFunctionIndex]
#define mxInstanceInspectors the->stackTop[-1 - mxInstanceInspectorsStackIndex]
#define mxInt16ArrayConstructor the->stackPrototypes[-1 - _Int16Array]
#define mxInt32ArrayConstructor the->stackPrototypes[-1 - _Int32Array]
#define mxInt8ArrayConstructor the->stackPrototypes[-1 - _Int8Array]
#define mxIsBigInt(THE_SLOT) \
	(((THE_SLOT)->kind == XS_BIGINT_KIND) || ((THE_SLOT)->kind == XS_BIGINT_X_KIND))
#define mxIsBoolean(THE_SLOT) \
	( ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && ((THE_SLOT)->next->kind == XS_BOOLEAN_KIND))
#define mxIsCallable(THE_SLOT) \
	( (THE_SLOT) &&  ((THE_SLOT)->next) && (((THE_SLOT)->next->kind == XS_CALLBACK_KIND) || ((THE_SLOT)->next->kind == XS_CALLBACK_X_KIND) || ((THE_SLOT)->next->kind == XS_CODE_KIND) || ((THE_SLOT)->next->kind == XS_CODE_X_KIND) || ((THE_SLOT)->next->kind == XS_PROXY_KIND)))
#define mxIsConstructor(THE_SLOT) \
	((THE_SLOT) && ((THE_SLOT)->flag & XS_CAN_CONSTRUCT_FLAG))
#define mxIsDate(THE_SLOT) \
	( ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && ((THE_SLOT)->next->kind == XS_DATE_KIND))
#define mxIsFiniteFunction the->stackPrototypes[-1 - _isFinite]
#define mxIsFunction(THE_SLOT) \
	( (THE_SLOT) &&  ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && (((THE_SLOT)->next->kind == XS_CALLBACK_KIND) || ((THE_SLOT)->next->kind == XS_CALLBACK_X_KIND) || ((THE_SLOT)->next->kind == XS_CODE_KIND) || ((THE_SLOT)->next->kind == XS_CODE_X_KIND)))
#define mxIsHost(THE_SLOT) \
	( ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && ((THE_SLOT)->next->kind == XS_HOST_KIND))
#define mxIsNaNFunction the->stackPrototypes[-1 - _isNaN]
#define mxIsNull(THE_SLOT) \
	((THE_SLOT)->kind == XS_NULL_KIND)
#define mxIsNumber(THE_SLOT) \
	( ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && ((THE_SLOT)->next->kind == XS_NUMBER_KIND))
#define mxIsPromise(THE_SLOT) \
	((THE_SLOT) && ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && ((THE_SLOT)->next->kind == XS_PROMISE_KIND) && (THE_SLOT != mxPromisePrototype.value.reference))
#define mxIsProxy(THE_SLOT) \
	( ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && ((THE_SLOT)->next->kind == XS_PROXY_KIND))
#define mxIsReference(THE_SLOT) \
	((THE_SLOT)->kind == XS_REFERENCE_KIND)
#define mxIsRegExp(THE_SLOT) \
	( ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && ((THE_SLOT)->next->kind == XS_REGEXP_KIND))
#define mxIsString(THE_SLOT) \
	( ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && (((THE_SLOT)->next->kind == XS_STRING_KIND) || ((THE_SLOT)->next->kind == XS_STRING_X_KIND)))
#define mxIsStringPrimitive(THE_SLOT) \
	(((THE_SLOT)->kind == XS_STRING_KIND) || ((THE_SLOT)->kind == XS_STRING_X_KIND))
#define mxIsSymbol(THE_SLOT) \
	( ((THE_SLOT)->next) && ((THE_SLOT)->next->flag & XS_INTERNAL_FLAG) && ((THE_SLOT)->next->kind == XS_SYMBOL_KIND))
#define mxIsUndefined(THE_SLOT) \
	((THE_SLOT)->kind == XS_UNDEFINED_KIND)
#define mxIteratorPrototype the->stackPrototypes[-1 - mxIteratorPrototypeStackIndex]
#define mxJSONObject the->stackPrototypes[-1 - _JSON]
#define mxLoadHook(REALM)				((REALM)->next->next->next->next->next->next->next->next)
#define mxLoadNowHook(REALM)			((REALM)->next->next->next->next->next->next->next->next->next)
#define mxMapConstructor the->stackPrototypes[-1 - _Map]
#define mxMapIteratorPrototype the->stackPrototypes[-1 - mxMapIteratorPrototypeStackIndex]
#define mxMapPrototype the->stackPrototypes[-1 - mxMapPrototypeStackIndex]
#define mxMathObject the->stackPrototypes[-1 - _Math]
#define mxMeterOne() \
	(the->meterIndex++)
#define mxMeterSome(_COUNT) \
	(the->meterIndex += _COUNT)
#define mxModuleExecute(MODULE) 	mxModuleInstanceExecute((MODULE)->value.reference)
#define mxModuleExports(MODULE) 	mxModuleInstanceExports((MODULE)->value.reference)
#define mxModuleFulfill(MODULE) 	mxModuleInstanceFulfill((MODULE)->value.reference)
#define mxModuleHosts(MODULE) 		mxModuleInstanceHosts((MODULE)->value.reference)
#define mxModuleInitialize(MODULE) 	mxModuleInstanceInitialize((MODULE)->value.reference)
#define mxModuleInstanceExecute(MODULE)		((MODULE)->next->next->next->next->next->next)
#define mxModuleInstanceExports(MODULE)		((MODULE)->next->next)
#define mxModuleInstanceFulfill(MODULE)		((MODULE)->next->next->next->next->next->next->next->next)
#define mxModuleInstanceHosts(MODULE)			((MODULE)->next->next->next->next->next->next->next)
#define mxModuleInstanceInitialize(MODULE)		((MODULE)->next->next->next->next->next)
#define mxModuleInstanceInternal(MODULE)		((MODULE)->next)
#define mxModuleInstanceMeta(MODULE)			((MODULE)->next->next->next)
#define mxModuleInstanceReject(MODULE)			((MODULE)->next->next->next->next->next->next->next->next->next)
#define mxModuleInstanceTransfers(MODULE)		((MODULE)->next->next->next->next)
#define mxModuleInternal(MODULE) 	mxModuleInstanceInternal((MODULE)->value.reference)
#define mxModuleMap(REALM)				((REALM)->next->next->next->next->next->next)
#define mxModuleMapHook(REALM)			((REALM)->next->next->next->next->next->next->next)
#define mxModuleMeta(MODULE) 		mxModuleInstanceMeta((MODULE)->value.reference)
#define mxModulePrototype the->stackPrototypes[-1 - mxModulePrototypeStackIndex]
#define mxModuleQueue the->stackTop[-1 - mxModuleQueueStackIndex]
#define mxModuleReject(MODULE) 		mxModuleInstanceReject((MODULE)->value.reference)
#define mxModuleTransfers(MODULE) 	mxModuleInstanceTransfers((MODULE)->value.reference)
#define mxNaN the->stackPrototypes[-1 - _NaN]
#define mxNew() \
	(mxOverflow(-5), \
	fxNew(the))
#define mxNumberConstructor the->stackPrototypes[-1 - _Number]
#define mxNumberPrototype the->stackPrototypes[-1 - mxNumberPrototypeStackIndex]
#define mxNumberString the->stackPrototypes[-1 - mxNumberStringStackIndex]
#define mxObjectConstructor the->stackPrototypes[-1 - _Object]
#define mxObjectPrototype the->stackPrototypes[-1 - mxObjectPrototypeStackIndex]
#define mxObjectString the->stackPrototypes[-1 - mxObjectStringStackIndex]
#define mxOnRejectedPromiseFunction the->stackPrototypes[-1 - mxOnRejectedPromiseFunctionStackIndex]
#define mxOnResolvedPromiseFunction the->stackPrototypes[-1 - mxOnResolvedPromiseFunctionStackIndex]
#define mxOnThenableFunction the->stackPrototypes[-1 - mxOnThenableFunctionStackIndex]
#define mxOrdinaryToPrimitiveFunction the->stackPrototypes[-1 - mxOrdinaryToPrimitiveFunctionStackIndex]
#define mxOverflow(_COUNT) \
	(mxMeterOne(), fxOverflow(the,_COUNT,C_NULL, 0))
#define mxOwnModules(REALM)				((REALM)->next->next->next->next)
#define mxParseFloatFunction the->stackPrototypes[-1 - _parseFloat]
#define mxParseIntFunction the->stackPrototypes[-1 - _parseInt]
#define mxPendingJobs the->stackTop[-1 - mxPendingJobsStackIndex]
#define mxPop() \
	(mxMeterOne(), the->stack++)
#define mxProgram the->stackTop[-1 - mxProgramStackIndex]
#define mxPromiseConstructor the->stackPrototypes[-1 - _Promise]
#define mxPromiseEnvironment(INSTANCE) ((INSTANCE)->next->next->next->next)
#define mxPromisePrototype the->stackPrototypes[-1 - mxPromisePrototypeStackIndex]
#define mxPromiseResult(INSTANCE) ((INSTANCE)->next->next->next)
#define mxPromiseStatus(INSTANCE) ((INSTANCE)->next)
#define mxPromiseThens(INSTANCE) ((INSTANCE)->next->next)
#define mxProxyAccessor the->stackPrototypes[-1 - mxProxyAccessorStackIndex]
#define mxProxyConstructor the->stackPrototypes[-1 - _Proxy]
#define mxProxyPrototype the->stackPrototypes[-1 - mxProxyPrototypeStackIndex]
#define mxPull(THE_SLOT) \
	(mxMeterOne(), \
	(THE_SLOT).value = the->stack->value, \
	(THE_SLOT).kind = (the->stack++)->kind)
#define mxPullSlot(THE_SLOT) \
	(mxMeterOne(), \
	(THE_SLOT)->value = the->stack->value, \
	(THE_SLOT)->kind = (the->stack++)->kind)
#define mxPush(THE_SLOT) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, (THE_SLOT).kind), \
	the->stack->value = (THE_SLOT).value)
#define mxPushAt(ID,INDEX) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_AT_KIND), \
	the->stack->value.at.index = (INDEX), \
	the->stack->value.at.id = (ID))
#define mxPushBigInt(THE_BIGINT) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_BIGINT_KIND), \
	the->stack->value.bigint = (THE_BIGINT))
#define mxPushBoolean(THE_BOOLEAN) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_BOOLEAN_KIND), \
	the->stack->value.boolean = (THE_BOOLEAN))
#define mxPushClosure(THE_SLOT) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_CLOSURE_KIND), \
	the->stack->value.closure = (THE_SLOT))
#define mxPushInteger(THE_NUMBER) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_INTEGER_KIND), \
	the->stack->value.integer = (THE_NUMBER))
#define mxPushList() \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_LIST_KIND), \
	the->stack->value.list.first = C_NULL, \
	the->stack->value.list.last = C_NULL)
#define mxPushNull() \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_NULL_KIND))
#define mxPushNumber(THE_NUMBER) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_NUMBER_KIND), \
	the->stack->value.number = (THE_NUMBER))
#define mxPushReference(THE_SLOT) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_REFERENCE_KIND), \
	the->stack->value.reference = (THE_SLOT))
#define mxPushSlot(THE_SLOT) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, (THE_SLOT)->kind), \
	the->stack->value = (THE_SLOT)->value)
#define mxPushString(THE_STRING) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_STRING_KIND), \
	the->stack->value.string = (THE_STRING))
#define mxPushStringC(THE_STRING) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_UNDEFINED_KIND), \
	fxCopyStringC(the, the->stack, THE_STRING))
#define mxPushStringX(THE_STRING) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_UNDEFINED_KIND), \
	fxCopyStringC(the, the->stack, THE_STRING))
#define mxPushSymbol(THE_SYMBOL) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_SYMBOL_KIND), \
	the->stack->value.symbol = (THE_SYMBOL))
#define mxPushUndefined() \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_UNDEFINED_KIND))
#define mxPushUninitialized() \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	mxInitSlotKind(the->stack, XS_UNINITIALIZED_KIND))
#define mxPushUnsigned(THE_NUMBER) \
	(mxOverflow(-1), \
	(--the->stack)->next = C_NULL, \
	(THE_NUMBER < 0x7FFFFFFF) ? \
		(mxInitSlotKind(the->stack, XS_INTEGER_KIND), \
		the->stack->value.integer = (txInteger)(THE_NUMBER)) \
	: \
		(mxInitSlotKind(the->stack, XS_NUMBER_KIND), \
		the->stack->value.number = (txNumber)(THE_NUMBER)) \
	)
#define mxRangeError(...) fxThrowMessage(the, NULL, 0, XS_RANGE_ERROR, __VA_ARGS__)
#define mxRangeErrorConstructor the->stackPrototypes[-1 - _RangeError]
#define mxRangeErrorPrototype the->stackPrototypes[-1 - mxRangeErrorPrototypeStackIndex]
#define mxRealmClosures(REALM)			((REALM)->next->next)
#define mxRealmGlobal(REALM)			((REALM)->next)
#define mxRealmParent(REALM)			((REALM)->next->next->next->next->next->next->next->next->next->next)
#define mxRealmTemplateCache(REALM)		((REALM)->next->next->next)
#define mxReferenceError(...) fxThrowMessage(the, NULL, 0, XS_REFERENCE_ERROR, __VA_ARGS__)
#define mxReferenceErrorConstructor the->stackPrototypes[-1 - _ReferenceError]
#define mxReferenceErrorPrototype the->stackPrototypes[-1 - mxReferenceErrorPrototypeStackIndex]
#define mxReflectObject the->stackPrototypes[-1 - _Reflect]
#define mxRegExpConstructor the->stackPrototypes[-1 - _RegExp]
#define mxRegExpPrototype the->stackPrototypes[-1 - mxRegExpPrototypeStackIndex]
#define mxRegExpStringIteratorPrototype the->stackPrototypes[-1 - mxRegExpStringIteratorPrototypeStackIndex]
#define mxResolveHook(REALM)			((REALM)->next->next->next->next->next)
#define mxResult (the->frame + 1)
#define mxRunCount(_COUNT) \
	(mxMeterOne(), fxRunID(the, C_NULL, _COUNT))
#define mxRunningJobs the->stackTop[-1 - mxRunningJobsStackIndex]
#define mxSetAll(ID, INDEX) \
	(mxMeterOne(), fxSetAll(the, ID, INDEX))
#define mxSetAt() \
	(mxMeterOne(), fxSetAt(the))
#define mxSetConstructor the->stackPrototypes[-1 - _Set]
#define mxSetID(ID) \
	(mxMeterOne(), fxSetAll(the, ID, 0))
#define mxSetIndex(INDEX) \
	(mxMeterOne(), fxSetAll(the, XS_NO_ID, INDEX))
#define mxSetIteratorPrototype the->stackPrototypes[-1 - mxSetIteratorPrototypeStackIndex]
#define mxSetPrototype the->stackPrototypes[-1 - mxSetPrototypeStackIndex]
#define mxSharedArrayBufferConstructor the->stackPrototypes[-1 - _SharedArrayBuffer]
#define mxSharedArrayBufferPrototype the->stackPrototypes[-1 - mxSharedArrayBufferPrototypeStackIndex]
#define mxSortPartitionCount 30
#define mxSortThreshold 4
#define mxStaticModuleRecordConstructor the->stackPrototypes[-1 - _StaticModuleRecord]
#define mxStaticModuleRecordPrototype the->stackPrototypes[-1 - mxStaticModuleRecordPrototypeStackIndex]
#define mxStringAccessor the->stackPrototypes[-1 - mxStringAccessorStackIndex]
#define mxStringConstructor the->stackPrototypes[-1 - _String]
#define mxStringIteratorPrototype the->stackPrototypes[-1 - mxStringIteratorPrototypeStackIndex]
#define mxStringPrototype the->stackPrototypes[-1 - mxStringPrototypeStackIndex]
#define mxStringString the->stackPrototypes[-1 - mxStringStringStackIndex]
#define mxSymbolConstructor the->stackPrototypes[-1 - _Symbol]
#define mxSymbolPrototype the->stackPrototypes[-1 - mxSymbolPrototypeStackIndex]
#define mxSymbolString the->stackPrototypes[-1 - mxSymbolStringStackIndex]
#define mxSyntaxError(...) fxThrowMessage(the, NULL, 0, XS_SYNTAX_ERROR, __VA_ARGS__)
#define mxSyntaxErrorConstructor the->stackPrototypes[-1 - _SyntaxError]
#define mxSyntaxErrorPrototype the->stackPrototypes[-1 - mxSyntaxErrorPrototypeStackIndex]
#define mxTarget (the->frame + 2)
#define mxTemporary(_SLOT) \
	(mxOverflow(-1), \
	_SLOT = --the->stack, \
	mxInitSlotKind(the->stack, XS_UNDEFINED_KIND))
#define mxThis (the->frame + 4)
#define mxThrowMessage(_CODE,...) fxThrowMessage(the, C_NULL, 0, _CODE, __VA_ARGS__)
#define mxThrowTypeErrorFunction the->stackPrototypes[-1 - mxThrowTypeErrorFunctionStackIndex]
#define mxTraceFunction the->stackPrototypes[-1 - _trace]
#define mxTransferAliases(TRANSFER)	(TRANSFER)->value.reference->next->next->next->next
#define mxTransferClosure(TRANSFER)	(TRANSFER)->value.reference->next->next->next->next->next
#define mxTransferFrom(TRANSFER) 	(TRANSFER)->value.reference->next->next
#define mxTransferImport(TRANSFER) 	(TRANSFER)->value.reference->next->next->next
#define mxTransferLocal(TRANSFER)	(TRANSFER)->value.reference->next
#define mxTransferPrototype the->stackPrototypes[-1 - mxTransferPrototypeStackIndex]
#define mxTry(THE_MACHINE) \
	txJump __JUMP__; \
	__JUMP__.nextJump = (THE_MACHINE)->firstJump; \
	__JUMP__.stack = the->stack; \
	__JUMP__.scope = the->scope; \
	__JUMP__.frame = the->frame; \
	__JUMP__.code = the->code; \
	__JUMP__.flag = 0; \
	(THE_MACHINE)->firstJump = &__JUMP__; \
	if (c_setjmp(__JUMP__.buffer) == 0) {
#define mxTypeArrayCount 11
#define mxTypeError(...) fxThrowMessage(the, NULL, 0, XS_TYPE_ERROR, __VA_ARGS__)
#define mxTypeErrorConstructor the->stackPrototypes[-1 - _TypeError]
#define mxTypeErrorPrototype the->stackPrototypes[-1 - mxTypeErrorPrototypeStackIndex]
#define mxTypedArrayAccessor the->stackPrototypes[-1 - mxTypedArrayAccessorStackIndex]
#define mxTypedArrayConstructor the->stackPrototypes[-1 - _TypedArray]
#define mxTypedArrayPrototype the->stackPrototypes[-1 - mxTypedArrayPrototypeStackIndex]
#define mxURIError(...) fxThrowMessage(the, NULL, 0, XS_URI_ERROR, __VA_ARGS__)
#define mxURIErrorConstructor the->stackPrototypes[-1 - _URIError]
#define mxURIErrorPrototype the->stackPrototypes[-1 - mxURIErrorPrototypeStackIndex]
#define mxUint16ArrayConstructor the->stackPrototypes[-1 - _Uint16Array]
#define mxUint32ArrayConstructor the->stackPrototypes[-1 - _Uint32Array]
#define mxUint8ArrayConstructor the->stackPrototypes[-1 - _Uint8Array]
#define mxUint8ClampedArrayConstructor the->stackPrototypes[-1 - _Uint8ClampedArray]
#define mxUndefined the->stackPrototypes[-1 - _undefined]
#define mxUndefinedString the->stackPrototypes[-1 - mxUndefinedStringStackIndex]
#define mxUnescapeFunction the->stackPrototypes[-1 - _unescape]
#define mxUnhandledPromises the->stackTop[-1 - mxUnhandledPromisesStackIndex]
#define mxUnknownError(...) fxThrowMessage(the, NULL, 0, XS_UNKNOWN_ERROR, __VA_ARGS__)
#define mxVarc (the->scope->value.environment.variable.count)
#define mxVarv(THE_INDEX) (the->scope - 1 - (THE_INDEX))
#define mxWeakMapConstructor the->stackPrototypes[-1 - _WeakMap]
#define mxWeakMapPrototype the->stackPrototypes[-1 - mxWeakMapPrototypeStackIndex]
#define mxWeakRefConstructor the->stackPrototypes[-1 - _WeakRef]
#define mxWeakRefPrototype the->stackPrototypes[-1 - mxWeakRefPrototypeStackIndex]
#define mxWeakSetConstructor the->stackPrototypes[-1 - _WeakSet]
#define mxWeakSetPrototype the->stackPrototypes[-1 - mxWeakSetPrototypeStackIndex]
#define XS_ATOM_ARCHIVE 0x58535F41 
#define XS_ATOM_BINARY 0x58535F42 
#define XS_ATOM_CHECKSUM 0x43484B53 
#define XS_ATOM_CODE 0x434F4445 
#define XS_ATOM_DATA 0x44415441 
#define XS_ATOM_ERROR 0x58535F45 
#define XS_ATOM_HOSTS 0x484F5354 
#define XS_ATOM_MODULES 0x4D4F4453 
#define XS_ATOM_NAME 0x4E414D45 
#define XS_ATOM_PATH 0x50415448 
#define XS_ATOM_RESOURCES 0x52535243 
#define XS_ATOM_SIGNATURE 0x5349474E 
#define XS_ATOM_SYMBOLS 0x53594D42 
#define XS_ATOM_VERSION 0x56455253 
#define XS_DIGEST_SIZE 16
#define XS_INTRINSICS_COUNT _AsyncFunction
#define XS_MAJOR_VERSION 11
#define XS_MINOR_VERSION 7
#define XS_PATCH_VERSION 1
#define XS_SYMBOL_ID_COUNT _AggregateError
#define XS_VERSION_SIZE 4

#define mxBigIntHighWord(x)		((txU4)((x) >> 32))
#define mxBigIntIsNaN(x) ((x)->size == 0)
#define mxBigIntLowWord(x)		((txU4)(x))
#define mxDecode2(THE_CODE, THE_VALUE)	{ \
	txS1* src = (txS1*)(THE_CODE); \
	txS1* dst = (txS1*)&(THE_VALUE) + 1; \
	*dst-- = *src++; \
	*dst = *src++; \
	(THE_CODE) = (void *)src; \
	}
#define mxDecode4(THE_CODE, THE_VALUE)	{ \
	txS1* src = (THE_CODE); \
	txS1* dst = (txS1*)&(THE_VALUE) + 3; \
	*dst-- = *src++; \
	*dst-- = *src++; \
	*dst-- = *src++; \
	*dst = *src++; \
	(THE_CODE) = src; \
	}
#define mxDecode8(THE_CODE, THE_VALUE)	{ \
	txS1* src = (THE_CODE); \
	txS1* dst = (txS1*)&(THE_VALUE) + 7; \
	*dst-- = *src++; \
	*dst-- = *src++; \
	*dst-- = *src++; \
	*dst-- = *src++; \
	*dst-- = *src++; \
	*dst-- = *src++; \
	*dst-- = *src++; \
	*dst = *src++; \
	(THE_CODE) = src; \
}
#define mxDecodeID(THE_CODE, THE_VALUE) mxDecode4(THE_CODE, THE_VALUE)	
#define mxEncode2(THE_CODE, THE_VALUE)	{ \
	txByte* dst = (THE_CODE); \
	txByte* src = (txByte*)&(THE_VALUE) + 1; \
	*dst++ = *src--; \
	*dst++ = *src; \
	(THE_CODE) = dst; \
	}
#define mxEncode4(THE_CODE, THE_VALUE)	{ \
	txByte* dst = (THE_CODE); \
	txByte* src = (txByte*)&(THE_VALUE) + 3; \
	*dst++ = *src--; \
	*dst++ = *src--; \
	*dst++ = *src--; \
	*dst++ = *src; \
	(THE_CODE) = dst; \
	}
#define mxEncode8(THE_CODE, THE_VALUE)	{ \
	txByte* dst = (THE_CODE); \
	txByte* src = (txByte*)&(THE_VALUE) + 7; \
	*dst++ = *src--; \
	*dst++ = *src--; \
	*dst++ = *src--; \
	*dst++ = *src--; \
	*dst++ = *src--; \
	*dst++ = *src--; \
	*dst++ = *src--; \
	*dst++ = *src; \
	(THE_CODE) = dst; \
	}
#define mxEncodeID(THE_CODE, THE_VALUE) mxEncode4(THE_CODE, THE_VALUE)	
#define mxPtrDiff(_DIFF) ((txSize)(_DIFF))
#define mxStringByteDecode fxCESU8Decode
#define mxStringByteEncode fxCESU8Encode
#define mxStringByteLength fxCESU8Length
#define mxStringLength(_STRING) ((txSize)c_strlen(_STRING))
