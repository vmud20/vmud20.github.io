

































































































void RegisterAllModules();
void TmqhSetup (void);

int RunUnittests(int list_unittests, char *regex_arg)
{

    
    GlobalInits();
    TimeInit();
    SupportFastPatternForSigMatchTypes();

    default_packet_size = DEFAULT_PACKET_SIZE;

    
    SCCudaInitCudaEnvironment();
    CudaBufferInit();

    
    MpmTableSetup();

    MpmCudaEnvironmentSetup();


    AppLayerDetectProtoThreadInit();
    AppLayerParsersInitPostProcess();

    
    SigTableSetup(); 
    TmqhSetup();

    StorageInit();
    CIDRInit();
    SigParsePrepare();


    SCLogInfo("Memory used at startup: %"PRIdMAX, (intmax_t)global_mem);

    SCReputationInitCtx();
    SCProtoNameInit();

    TagInitCtx();

    RegisterAllModules();

    DetectEngineRegisterAppInspectionEngines();

    StorageFinalize();
   
    if(regex_arg == NULL){
        regex_arg = ".*";
        UtRunSelftest(regex_arg); 
    }

    AppLayerHtpEnableRequestBodyCallback();
    AppLayerHtpNeedFileInspection();

    UtInitialize();
    UTHRegisterTests();
    SCReputationRegisterTests();
    TmModuleRegisterTests();
    SigTableRegisterTests();
    HashTableRegisterTests();
    HashListTableRegisterTests();
    BloomFilterRegisterTests();
    BloomFilterCountingRegisterTests();
    PoolRegisterTests();
    ByteRegisterTests();
    MpmRegisterTests();
    FlowBitRegisterTests();
    SCPerfRegisterTests();
    DecodePPPRegisterTests();
    DecodeVLANRegisterTests();
    HTPParserRegisterTests();
    SSLParserRegisterTests();
    SSHParserRegisterTests();
    SMBParserRegisterTests();
    DCERPCParserRegisterTests();
    DCERPCUDPParserRegisterTests();
    FTPParserRegisterTests();
    DecodeRawRegisterTests();
    DecodePPPOERegisterTests();
    DecodeICMPV4RegisterTests();
    DecodeICMPV6RegisterTests();
    DecodeIPV4RegisterTests();
    DecodeIPV6RegisterTests();
    DecodeTCPRegisterTests();
    DecodeUDPV4RegisterTests();
    DecodeGRERegisterTests();
    DecodeAsn1RegisterTests();
    AlpDetectRegisterTests();
    ConfRegisterTests();
    ConfYamlRegisterTests();
    TmqhFlowRegisterTests();
    FlowRegisterTests();
    SCSigRegisterSignatureOrderingTests();
    SCRadixRegisterTests();
    DefragRegisterTests();
    SigGroupHeadRegisterTests();
    SCHInfoRegisterTests();
    SCRuleVarsRegisterTests();
    AppLayerParserRegisterTests();
    ThreadMacrosRegisterTests();
    UtilSpmSearchRegistertests();
    UtilActionRegisterTests();
    SCClassConfRegisterTests();
    SCThresholdConfRegisterTests();
    SCRConfRegisterTests();

    SCCudaRegisterTests();

    PayloadRegisterTests();
    DcePayloadRegisterTests();
    UriRegisterTests();

    SCProfilingRegisterTests();

    DeStateRegisterTests();
    DetectRingBufferRegisterTests();
    MemcmpRegisterTests();
    DetectEngineHttpClientBodyRegisterTests();
    DetectEngineHttpServerBodyRegisterTests();
    DetectEngineHttpHeaderRegisterTests();
    DetectEngineHttpRawHeaderRegisterTests();
    DetectEngineHttpMethodRegisterTests();
    DetectEngineHttpCookieRegisterTests();
    DetectEngineHttpRawUriRegisterTests();
    DetectEngineHttpStatMsgRegisterTests();
    DetectEngineHttpStatCodeRegisterTests();
    DetectEngineHttpUARegisterTests();
    DetectEngineHttpHHRegisterTests();
    DetectEngineHttpHRHRegisterTests();
    DetectEngineRegisterTests();
    SCLogRegisterTests();
    SMTPParserRegisterTests();
    MagicRegisterTests();
    UtilMiscRegisterTests();
    DetectAddressTests();
    DetectProtoTests();
    DetectPortTests();
    SCAtomicRegisterTests();
    MemrchrRegisterTests();

    CudaBufferRegisterUnittests();

    if (list_unittests) {
        UtListTests(regex_arg);
    } else {
        uint32_t failed = UtRunTests(regex_arg);
        UtCleanup();

        if (PatternMatchDefaultMatcher() == MPM_AC_CUDA)
            MpmCudaBufferDeSetup();
        CudaHandlerFreeProfiles();

        if (failed) {
            exit(EXIT_FAILURE);
        }
    }


    SCLogInfo("Total memory used (without SCFree()): %"PRIdMAX, (intmax_t)global_mem);


    exit(EXIT_SUCCESS);

    SCLogError(SC_ERR_NOT_SUPPORTED, "Unittests are not build-in");
    exit(EXIT_FAILURE);

}

