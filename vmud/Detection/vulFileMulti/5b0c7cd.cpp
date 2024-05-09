














































using namespace jsonrpc;
using namespace std;

class TestFixture {
public:
    TestFixture() {
        TestUtils::resetDB();
        setOptions(L_INFO, false, true);
        initAll(L_INFO, false, true);
    }

    ~TestFixture() {
        TestUtils::destroyEnclave();
    }
};

class TestFixtureHTTPS {
public:
    TestFixtureHTTPS() {
        TestUtils::resetDB();
        setOptions(L_INFO, true, true);
        initAll(L_INFO, false, true);
    }

    ~TestFixtureHTTPS() {
        TestUtils::destroyEnclave();
    }
};

class TestFixtureNoResetFromBackup {
public:
    TestFixtureNoResetFromBackup() {
        setFullOptions(L_INFO, false, true, true);
        initAll(L_INFO, false, true);
    }

    ~TestFixtureNoResetFromBackup() {
        TestUtils::destroyEnclave();
    }
};


class TestFixtureNoReset {
public:
    TestFixtureNoReset() {
        setOptions(L_INFO, false, true);
        initAll(L_INFO, false, true);
    }

    ~TestFixtureNoReset() {
        TestUtils::destroyEnclave();
    }
};

TEST_CASE_METHOD(TestFixture, "ECDSA AES keygen and signature test", "[ecdsa-aes-key-sig-gen]") {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);

    uint32_t encLen = 0;
    PRINT_SRC_LINE auto status = trustedGenerateEcdsaKeyAES(eid, &errStatus, errMsg.data(), encrPrivKey.data(), &encLen, pubKeyX.data(), pubKeyY.data());


    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    string hex = SAMPLE_HEX_HASH;
    vector<char> signatureR(BUF_LEN, 0);
    vector<char> signatureS(BUF_LEN, 0);
    uint8_t signatureV = 0;


    for (int i = 0; i < 50; i++) {
        PRINT_SRC_LINE status = trustedEcdsaSignAES(eid, &errStatus, errMsg.data(), encrPrivKey.data(), encLen, hex.data(), signatureR.data(), signatureS.data(), &signatureV, 16);



        REQUIRE(status == SGX_SUCCESS);
        REQUIRE(errStatus == SGX_SUCCESS);
    }

}


TEST_CASE_METHOD(TestFixture, "ECDSA AES key gen", "[ecdsa-aes-key-gen]") {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    uint32_t encLen = 0;
    PRINT_SRC_LINE auto status = trustedGenerateEcdsaKeyAES(eid, &errStatus, errMsg.data(), encrPrivKey.data(), &encLen, pubKeyX.data(), pubKeyY.data());



    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}


TEST_CASE_METHOD(TestFixture, "ECDSA AES get public key", "[ecdsa-aes-get-pub-key]") {
    int errStatus = 0;
    vector<char> errMsg(BUF_LEN, 0);
    vector <uint8_t> encPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    uint32_t encLen = 0;

    PRINT_SRC_LINE auto status = trustedGenerateEcdsaKeyAES(eid, &errStatus, errMsg.data(), encPrivKey.data(), &encLen, pubKeyX.data(), pubKeyY.data());


    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> receivedPubKeyX(BUF_LEN, 0);
    vector<char> receivedPubKeyY(BUF_LEN, 0);

    PRINT_SRC_LINE status = trustedGetPublicEcdsaKeyAES(eid, &errStatus, errMsg.data(), encPrivKey.data(), encLen, receivedPubKeyX.data(), receivedPubKeyY.data());


    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}





string genECDSAKeyAPI(StubClient &_c) {
    Json::Value genKey = _c.generateECDSAKey();
    CHECK_STATE(genKey["status"].asInt() == 0);
    auto keyName = genKey["keyName"].asString();
    CHECK_STATE(keyName.size() == ECDSA_KEY_NAME_SIZE);
    return keyName;
}

TEST_CASE_METHOD(TestFixture, "ECDSA key gen API", "[ecdsa-key-gen-api]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    for (int i = 0; i <= 20; i++) {
        try {
            PRINT_SRC_LINE auto keyName = genECDSAKeyAPI(c);
            PRINT_SRC_LINE Json::Value sig = c.ecdsaSignMessageHash(16, keyName, SAMPLE_HASH);
            REQUIRE(sig["status"].asInt() == 0);
            Json::Value getPubKey = c.getPublicECDSAKey(keyName);
            REQUIRE(getPubKey["status"].asInt() == 0);
        } catch (JsonRpcException &e) {
            cerr << e.what() << endl;
            throw;
        }
    }

    auto keyName = genECDSAKeyAPI(c);


    Json::Value sig = c.ecdsaSignMessageHash(10, keyName, SAMPLE_HASH);


    for (int i = 0; i <= 20; i++) {
        try {
            PRINT_SRC_LINE auto keyName = genECDSAKeyAPI(c);
            PRINT_SRC_LINE Json::Value sig = c.ecdsaSignMessageHash(10, keyName, SAMPLE_HASH);
            REQUIRE(sig["status"].asInt() == 0);
            PRINT_SRC_LINE Json::Value getPubKey = c.getPublicECDSAKey(keyName);
            REQUIRE(getPubKey["status"].asInt() == 0);
        } catch (JsonRpcException &e) {
            cerr << e.what() << endl;
            throw;
        }
    }
}

TEST_CASE_METHOD(TestFixture, "BLS key encrypt", "[bls-key-encrypt]") {
    auto key = TestUtils::encryptTestKey();
    REQUIRE(key != nullptr);
}


TEST_CASE_METHOD(TestFixture, "DKG AES gen test", "[dkg-aes-gen]") {
    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    PRINT_SRC_LINE auto status = trustedGenDkgSecretAES(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 32);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> secret(BUF_LEN, 0);
    vector<char> errMsg1(BUF_LEN, 0);

    status = trustedDecryptDkgSecretAES(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(), encLen, (uint8_t *) secret.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}


TEST_CASE_METHOD(TestFixture, "DKG AES public shares test", "[dkg-aes-pub-shares]") {
    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    unsigned t = 32, n = 32;
    PRINT_SRC_LINE auto status = trustedGenDkgSecretAES(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, n);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> errMsg1(BUF_LEN, 0);

    char colon = ':';
    vector<char> pubShares(10000, 0);
    PRINT_SRC_LINE status = trustedGetPublicSharesAES(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(), encLen, pubShares.data(), t, n);

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector <string> g2Strings = splitString(pubShares.data(), ',');
    vector <libff::alt_bn128_G2> pubSharesG2;
    for (u_int64_t i = 0; i < g2Strings.size(); i++) {
        vector <string> coeffStr = splitString(g2Strings.at(i).c_str(), ':');

        pubSharesG2.push_back(TestUtils::vectStringToG2(coeffStr));
    }

    vector<char> secret(BUF_LEN, 0);
    PRINT_SRC_LINE status = trustedDecryptDkgSecretAES(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(), encLen, (uint8_t *) secret.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    signatures::Dkg dkgObj(t, n);

    vector <libff::alt_bn128_Fr> poly = TestUtils::splitStringToFr(secret.data(), colon);
    vector <libff::alt_bn128_G2> pubSharesDkg = dkgObj.VerificationVector(poly);
    for (uint32_t i = 0; i < pubSharesDkg.size(); i++) {
        libff::alt_bn128_G2 el = pubSharesDkg.at(i);
        el.to_affine_coordinates();
    }
    REQUIRE(pubSharesG2 == pubSharesDkg);
}

TEST_CASE_METHOD(TestFixture, "DKG AES encrypted secret shares test", "[dkg-aes-encr-sshares]") {
    vector<char> errMsg(BUF_LEN, 0);
    vector<char> result(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    PRINT_SRC_LINE auto status = trustedGenDkgSecretAES(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 2);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    uint64_t enc_len = encLen;

    PRINT_SRC_LINE status = trustedSetEncryptedDkgPolyAES(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), enc_len);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector <uint8_t> encrPRDHKey(BUF_LEN, 0);

    string pub_keyB = SAMPLE_PUBLIC_KEY_B;

    vector<char> s_shareG2(BUF_LEN, 0);
    PRINT_SRC_LINE status = trustedGetEncryptedSecretShareAES(eid, &errStatus, errMsg.data(), encrPRDHKey.data(), &encLen, result.data(), s_shareG2.data(), (char *) pub_keyB.data(), 2, 2, 1);




    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}









TEST_CASE_METHOD(TestFixture, "DKG_BLS test", "[dkg-bls]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    vector <string> ecdsaKeyNames;
    vector <string> blsKeyNames;

    int schainID = TestUtils::randGen();
    int dkgID = TestUtils::randGen();

    PRINT_SRC_LINE TestUtils::doDKG(c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

    REQUIRE(blsKeyNames.size() == 4);

    schainID = TestUtils::randGen();
    dkgID = TestUtils::randGen();

    TestUtils::doDKG(c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID, dkgID);
}

TEST_CASE_METHOD(TestFixture, "Delete Bls Key", "[delete-bls-key]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
    libff::alt_bn128_Fr key = libff::alt_bn128_Fr( "6507625568967977077291849236396320012317305261598035438182864059942098934847");
    std::string key_str = TestUtils::stringFromFr(key);
    PRINT_SRC_LINE c.importBLSKeyShare(key_str, name);
    PRINT_SRC_LINE REQUIRE(c.deleteBlsKey(name)["deleted"] == true);
}

TEST_CASE_METHOD(TestFixture, "Backup Key", "[backup-key]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    std::ifstream sek_file("sgx_data/sgxwallet_backup_key.txt");
    REQUIRE(sek_file.good());

    std::string sek;
    sek_file >> sek;

    REQUIRE(sek.size() == 32);
}

TEST_CASE_METHOD(TestFixture, "Get ServerStatus", "[get-server-status]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    REQUIRE(c.getServerStatus()["status"] == 0);
}

TEST_CASE_METHOD(TestFixture, "Get ServerVersion", "[get-server-version]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    REQUIRE(c.getServerVersion()["version"] == SGXWalletServer::getVersion());
}


TEST_CASE_METHOD(TestFixtureHTTPS, "Cert request sign", "[cert-sign]") {

    PRINT_SRC_LINE  REQUIRE_NOTHROW(SGXRegistrationServer::getServer());


    PRINT_SRC_LINE  string csrFile = "insecure-samples/yourdomain.csr";


    ifstream infile(csrFile);
    infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    ostringstream ss;
    ss << infile.rdbuf();
    infile.close();

    PRINT_SRC_LINE  auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());


    REQUIRE(result["status"] == 0);


    PRINT_SRC_LINE result = SGXRegistrationServer::getServer()->SignCertificate("Haha");

    REQUIRE(result["status"] != 0);
}

TEST_CASE_METHOD(TestFixture, "DKG API test", "[dkg-api]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    string polyName = SAMPLE_POLY_NAME;

    PRINT_SRC_LINE Json::Value genPoly = c.generateDKGPoly(polyName, 2);
    REQUIRE(genPoly["status"].asInt() == 0);

    Json::Value publicKeys;
    publicKeys.append(SAMPLE_DKG_PUB_KEY_1);
    publicKeys.append(SAMPLE_DKG_PUB_KEY_2);

    
    Json::Value genPolyWrongName = c.generateDKGPoly("poly", 2);
    REQUIRE(genPolyWrongName["status"].asInt() != 0);

    Json::Value verifVectWrongName = c.getVerificationVector("poly", 2, 2);
    REQUIRE(verifVectWrongName["status"].asInt() != 0);

    Json::Value secretSharesWrongName = c.getSecretShare("poly", publicKeys, 2, 2);
    REQUIRE(secretSharesWrongName["status"].asInt() != 0);

    
    Json::Value genPolyWrong_t = c.generateDKGPoly(polyName, 33);
    REQUIRE(genPolyWrong_t["status"].asInt() != 0);

    Json::Value verifVectWrong_t = c.getVerificationVector(polyName, 1, 2);
    REQUIRE(verifVectWrong_t["status"].asInt() != 0);

    Json::Value secretSharesWrong_t = c.getSecretShare(polyName, publicKeys, 3, 3);
    REQUIRE(secretSharesWrong_t["status"].asInt() != 0);

    
    Json::Value verifVectWrong_n = c.getVerificationVector(polyName, 2, 1);
    REQUIRE(verifVectWrong_n["status"].asInt() != 0);

    Json::Value publicKeys1;
    publicKeys1.append(SAMPLE_DKG_PUB_KEY_1);
    Json::Value secretSharesWrong_n = c.getSecretShare(polyName, publicKeys1, 2, 1);
    REQUIRE(secretSharesWrong_n["status"].asInt() != 0);

    
    Json::Value secretSharesWrongPkeys = c.getSecretShare(polyName, publicKeys, 2, 3);
    REQUIRE(secretSharesWrongPkeys["status"].asInt() != 0);

    
    Json::Value Skeys = c.getSecretShare(polyName, publicKeys, 2, 2);
    Json::Value verifVect = c.getVerificationVector(polyName, 2, 2);
    Json::Value verificationWrongSkeys = c.dkgVerification("", "", "", 2, 2, 1);
    REQUIRE(verificationWrongSkeys["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixture, "PolyExists test", "[dkg-poly-exists]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    string polyName = SAMPLE_POLY_NAME;
    PRINT_SRC_LINE Json::Value genPoly = c.generateDKGPoly(polyName, 2);
    REQUIRE(genPoly["status"] == 0);

    PRINT_SRC_LINE Json::Value polyExists = c.isPolyExists(polyName);
    REQUIRE(polyExists["status"] == 0);
    REQUIRE(polyExists["IsExist"].asBool());

    PRINT_SRC_LINE Json::Value polyDoesNotExist = c.isPolyExists("Vasya");
    REQUIRE(!polyDoesNotExist["IsExist"].asBool());
}

TEST_CASE_METHOD(TestFixture, "AES_DKG test", "[aes-dkg]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    int n = 2, t = 2;
    Json::Value ethKeys[n];
    Json::Value verifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value blsSigShares[n];
    vector <string> pubShares(n);
    vector <string> polyNames(n);

    int schainID = TestUtils::randGen();
    int dkgID = TestUtils::randGen();
    for (uint8_t i = 0; i < n; i++) {
        PRINT_SRC_LINE ethKeys[i] = c.generateECDSAKey();
        REQUIRE(ethKeys[i]["status"] == 0);
        string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);
        REQUIRE(ethKeys[i]["status"] == 0);
        auto response = c.generateDKGPoly(polyName, t);
        REQUIRE(response["status"] == 0);

        polyNames[i] = polyName;
        PRINT_SRC_LINE verifVects[i] = c.getVerificationVector(polyName, t, n);
        REQUIRE(verifVects[i]["status"] == 0);

        pubEthKeys.append(ethKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        PRINT_SRC_LINE secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
        REQUIRE(secretShares[i]["status"] == 0);

        for (uint8_t k = 0; k < t; k++)
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = verifVects[i]["verificationVector"][k][j].asString();
                pubShares[i] += TestUtils::convertDecToHex(pubShare);
            }
    }

    int k = 0;
    vector <string> secShares(n);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            PRINT_SRC_LINE Json::Value verif = c.dkgVerification(pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
            REQUIRE(verif["status"] == 0);
            bool res = verif["result"].asBool();
            k++;
            REQUIRE(res);
        }

    Json::Value complaintResponse = c.complaintResponse(polyNames[1], 0);
    REQUIRE(complaintResponse["status"] == 0);

    BLSSigShareSet sigShareSet(t, n);

    string hash = SAMPLE_HASH;

    auto hash_arr = make_shared < array < uint8_t, 32 >> ();

    uint64_t binLen;

    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data(), 32)) {
        throw SGXException(INVALID_HEX, "Invalid hash");
    }

    map <size_t, shared_ptr<BLSPublicKeyShare>> coeffs_pkeys_map;

    for (int i = 0; i < t; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        auto response = c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(), polyNames[i], secShares[i], t, n);
        REQUIRE(response["status"] == 0);

        PRINT_SRC_LINE pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
        REQUIRE(pubBLSKeys[i]["status"] == 0);

        string hash = SAMPLE_HASH;
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n);
        REQUIRE(blsSigShares[i]["status"] == 0);

        shared_ptr <string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));

        vector <string> pubKey_vect;
        for (uint8_t j = 0; j < 4; j++) {
            pubKey_vect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
        }
        BLSPublicKeyShare pubKey(make_shared < vector < string >> (pubKey_vect), t, n);
        PRINT_SRC_LINE REQUIRE(pubKey.VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig), t, n));

        coeffs_pkeys_map[i + 1] = make_shared<BLSPublicKeyShare>(pubKey);
    }

    shared_ptr <BLSSignature> commonSig = sigShareSet.merge();
    BLSPublicKey common_public(make_shared < map < size_t, shared_ptr < BLSPublicKeyShare >>>(coeffs_pkeys_map), t, n);

    REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig, t, n));
}

TEST_CASE_METHOD(TestFixture, "AES encrypt/decrypt", "[aes-encrypt-decrypt]") {
    int errStatus = 0;
    vector<char> errMsg(BUF_LEN, 0);
    uint32_t encLen;
    string key = SAMPLE_AES_KEY;
    vector <uint8_t> encrypted_key(BUF_LEN, 0);

    PRINT_SRC_LINE auto status = trustedEncryptKeyAES(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key.data(), &encLen);

    REQUIRE(status == 0);
    REQUIRE(errStatus == 0);

    vector<char> decr_key(BUF_LEN, 0);
    PRINT_SRC_LINE status = trustedDecryptKeyAES(eid, &errStatus, errMsg.data(), encrypted_key.data(), encLen, decr_key.data());

    REQUIRE(status == 0);
    REQUIRE(errStatus == 0);
    REQUIRE(key.compare(decr_key.data()) == 0);
}


TEST_CASE_METHOD(TestFixture, "Many threads ecdsa dkg bls", "[many-threads-crypto]") {
    vector <thread> threads;
    int num_threads = 4;
    for (int i = 0; i < num_threads; i++) {
        threads.push_back(thread(TestUtils::sendRPCRequest));
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

TEST_CASE_METHOD(TestFixture, "First run", "[first-run]") {

    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    try {
        PRINT_SRC_LINE auto keyName = genECDSAKeyAPI(c);
        ofstream namefile("/tmp/keyname");
        namefile << keyName;

        PRINT_SRC_LINE } catch (JsonRpcException & e)
    {
        cerr << e.what() << endl;
        throw;
    }


}

TEST_CASE_METHOD(TestFixtureNoReset, "Second run", "[second-run]") {

    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    try {
        PRINT_SRC_LINE string keyName;
        ifstream namefile("/tmp/keyname");
        getline(namefile, keyName);

        Json::Value sig = c.ecdsaSignMessageHash(16, keyName, SAMPLE_HASH);
        REQUIRE(sig["status"].asInt() == 0);
        Json::Value getPubKey = c.getPublicECDSAKey(keyName);
        REQUIRE(getPubKey["status"].asInt() == 0);
    } catch (JsonRpcException &e) {
        cerr << e.what() << endl;
        throw;
    }
}


TEST_CASE_METHOD(TestFixtureNoResetFromBackup, "Backup restore", "[backup-restore]") {
}
