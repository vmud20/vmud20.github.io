


using namespace v8;

ObjectByteWriterWithPosition::ObjectByteWriterWithPosition(Local<Object> inObject)
{
	CREATE_ISOLATE_CONTEXT;

	SET_PERSISTENT_OBJECT(mObject, Object, inObject);
}

ObjectByteWriterWithPosition::~ObjectByteWriterWithPosition()
{
	DISPOSE_PERSISTENT(mObject);
}

IOBasicTypes::LongBufferSizeType ObjectByteWriterWithPosition::Write(const IOBasicTypes::Byte* inBuffer,IOBasicTypes::LongBufferSizeType inBufferSize)
{
	CREATE_ISOLATE_CONTEXT;
	CREATE_ESCAPABLE_SCOPE;

    Local<Object> anArray = NEW_ARRAY((int)inBufferSize);
    for(int i=0;i<(int)inBufferSize;++i)
        anArray->Set(GET_CURRENT_CONTEXT, NEW_NUMBER(i),NEW_NUMBER(inBuffer[i]));
    
	Local<Value> value = OBJECT_FROM_PERSISTENT(mObject)->Get(GET_CURRENT_CONTEXT, NEW_STRING("write")).ToLocalChecked();
    if(value->IsUndefined() || !value->IsFunction())
    {
		THROW_EXCEPTION("write is not a function, it should be you know...");
        return 0;
    }
    Local<Function> func = Local<Function>::Cast(value);
    
    Local<Value> args[1];
    args[0] = anArray;
    
	Local<Value> result = func->Call(GET_CURRENT_CONTEXT,  OBJECT_FROM_PERSISTENT(mObject), 1, args).ToLocalChecked();
    if(result.IsEmpty())
    {
		THROW_EXCEPTION("wrong return value. it's empty. return the number of written characters");
		return 0;
    }
    else if(result->IsNumber())
    {
        return TO_UINT32(result)->Value();
    }
    else {
		THROW_EXCEPTION("wrong return value. write should return the number of written characters");
		return 0;
    }
}

IOBasicTypes::LongFilePositionType ObjectByteWriterWithPosition::GetCurrentPosition()
{
	CREATE_ISOLATE_CONTEXT;
	CREATE_ESCAPABLE_SCOPE;

	Local<Value> value = OBJECT_FROM_PERSISTENT(mObject)->Get(GET_CURRENT_CONTEXT, NEW_STRING("getCurrentPosition")).ToLocalChecked();
    if(value->IsUndefined())
        return true;
    Local<Function> func = Local<Function>::Cast(value);
    
	return TO_NUMBER(func->Call(GET_CURRENT_CONTEXT, OBJECT_FROM_PERSISTENT(mObject), 0, NULL).ToLocalChecked())->Value();
}