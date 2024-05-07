




















void fillRandomBuffer(vector<unsigned char> &_buffer) {
    ifstream devRandom("/dev/urandom", ios::in | ios::binary);
    devRandom.exceptions(ifstream::failbit | ifstream::badbit);
    devRandom.read((char *) _buffer.data(), _buffer.size());
    devRandom.close();
}

vector <string> genECDSAKey() {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encr_pr_key(BUF_LEN, 0);
    vector<char> pub_key_x(BUF_LEN, 0);
    vector<char> pub_key_y(BUF_LEN, 0);

    uint32_t enc_len = 0;

    sgx_status_t status = trustedGenerateEcdsaKeyAES(eid, &errStatus, errMsg.data(), encr_pr_key.data(), &enc_len, pub_key_x.data(), pub_key_y.data());


    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus,errMsg.data());

    vector <string> keys(3);

    vector<char> hexEncrKey(BUF_LEN * 2, 0);

    carray2Hex(encr_pr_key.data(), enc_len, hexEncrKey.data(), BUF_LEN * 2);
    keys.at(0) = hexEncrKey.data();
    keys.at(1) = string(pub_key_x.data()) + string(pub_key_y.data());

    vector<unsigned char> randBuffer(32, 0);
    fillRandomBuffer(randBuffer);

    vector<char> rand_str(BUF_LEN, 0);

    carray2Hex(randBuffer.data(), 32, rand_str.data(), BUF_LEN);

    keys.at(2) = rand_str.data();

    CHECK_STATE(keys.at(2).size() == 64);

    return keys;
}

string getECDSAPubKey(const std::string& _encryptedKeyHex) {
    vector<char> errMsg(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    vector<uint8_t> encrPrKey(BUF_LEN, 0);

    int errStatus = 0;
    uint64_t enc_len = 0;

    if (!hex2carray(_encryptedKeyHex.c_str(), &enc_len, encrPrKey.data(), BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    sgx_status_t status = trustedGetPublicEcdsaKeyAES(eid, &errStatus, errMsg.data(), encrPrKey.data(), enc_len, pubKeyX.data(), pubKeyY.data());

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data())

    string pubKey = string(pubKeyX.data()) + string(pubKeyY.data());

    if (pubKey.size() != 128) {
        spdlog::error("Incorrect pub key size", status);
        throw SGXException(666, "Incorrect pub key size");
    }

    return pubKey;
}

bool verifyECDSASig(string& pubKeyStr, const char *hashHex, const char *signatureR, const char *signatureS, int base) {

    CHECK_STATE(hashHex)
    CHECK_STATE(signatureR)
    CHECK_STATE(signatureS)

    auto x = pubKeyStr.substr(0, 64);
    auto y = pubKeyStr.substr(64, 128);

    mpz_t msgMpz;
    mpz_init(msgMpz);
    if (mpz_set_str(msgMpz, hashHex, 16) == -1) {
        spdlog::error("invalid message hash {}", hashHex);
        mpz_clear(msgMpz);
        return false;
    }

    signature sig = signature_init();
    if (signature_set_str(sig, signatureR, signatureS, base) != 0) {
        spdlog::error("Failed to set str signature");
        mpz_clear(msgMpz);
        signature_free(sig);
        return false;
    }

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    point publicKey = point_init();

    point_set_hex(publicKey, x.c_str(), y.c_str());
    if (!signature_verify(msgMpz, sig, publicKey, curve)) {
        spdlog::error("ECDSA sig not verified");
        mpz_clear(msgMpz);
        signature_free(sig);
        domain_parameters_clear(curve);
        point_clear(publicKey);
        return false;
    }

    mpz_clear(msgMpz);
    signature_free(sig);
    domain_parameters_clear(curve);
    point_clear(publicKey);

    return true;
}

vector <string> ecdsaSignHash(const std::string& encryptedKeyHex, const char *hashHex, int base) {

    CHECK_STATE(hashHex);

    vector <string> signatureVector(3);

    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector<char> signatureR(BUF_LEN, 0);
    vector<char> signatureS(BUF_LEN, 0);
    vector<uint8_t> encryptedKey(BUF_LEN, 0);
    uint8_t signatureV = 0;
    uint64_t decLen = 0;

    string pubKeyStr = "";

    if (!hex2carray(encryptedKeyHex.c_str(), &decLen, encryptedKey.data(), BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    sgx_status_t status = trustedEcdsaSignAES(eid, &errStatus, errMsg.data(), encryptedKey.data(), decLen, hashHex, signatureR.data(), signatureS.data(), &signatureV, base);



    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());


    signatureVector.at(0) = to_string(signatureV);

    if (base == 16) {
        signatureVector.at(1) = "0x" + string(signatureR.data());
        signatureVector.at(2) = "0x" + string(signatureS.data());
    } else {
        signatureVector.at(1) = string(signatureR.data());
        signatureVector.at(2) = string(signatureS.data());
    }

    

    pubKeyStr = getECDSAPubKey(encryptedKeyHex);

    static uint64_t  i = 0;

    i++;

    if (i % 1000 == 0) {

        if (!verifyECDSASig(pubKeyStr, hashHex, signatureR.data(), signatureS.data(), base)) {
            spdlog::error("failed to verify ecdsa signature");
            throw SGXException(667, "ECDSA did not verify");
        }
    }

    return signatureVector;
}
