

















using namespace std;




bool case_insensitive_match(string s1, string s2) {
    
    transform(s1.begin(), s1.end(), s1.begin(), ::tolower);
    transform(s2.begin(), s2.end(), s2.begin(), ::tolower);
    return s1.compare(s2);
}

void create_test_key() {
    int errStatus = 0;
    vector<char> errMsg(1024, 0);
    uint32_t enc_len;

    SAFE_UINT8_BUF(encrypted_key, BUF_LEN);

    string key = TEST_VALUE;

    sgx_status_t status = trustedEncryptKeyAES(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key, &enc_len);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    vector<char> hexEncrKey(2 * enc_len + 1, 0);

    carray2Hex(encrypted_key, enc_len, hexEncrKey.data(), 2 * enc_len + 1);

    LevelDB::getLevelDb()->writeDataUnique("TEST_KEY", hexEncrKey.data());
}


void validate_SEK() {

    shared_ptr <string> test_key_ptr = LevelDB::getLevelDb()->readString("TEST_KEY");
    vector <uint8_t> encr_test_key(BUF_LEN, 0);
    vector<char> decr_key(BUF_LEN, 0);
    uint64_t len = 0;
    vector<char> errMsg(BUF_LEN, 0);

    int err_status = 0;

    if (!hex2carray(test_key_ptr->c_str(), &len, encr_test_key.data(), BUF_LEN)) {
        spdlog::error("Corrupt test key is LevelDB");
        exit(-1);
    }

    sgx_status_t status = trustedDecryptKeyAES(eid, &err_status, errMsg.data(), encr_test_key.data(), len, decr_key.data());

    HANDLE_TRUSTED_FUNCTION_ERROR(status, err_status, errMsg.data());

    string test_key = TEST_VALUE;

    if (test_key.compare(decr_key.data()) != 0) {
        spdlog::error("Invalid storage key. You need to recover using backup key");
        spdlog::error("Set the correct backup key into sgx_datasgxwallet_backup_key.txt");
        spdlog::error("Then run sgxwallet using backup flag");
        exit(-1);
    }
}


shared_ptr <vector<uint8_t>> check_and_set_SEK(const string &SEK) {

    vector<char> decr_key(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);
    int err_status = 0;

    auto encrypted_SEK = make_shared < vector < uint8_t >> (BUF_LEN, 0);

    uint32_t l = 0;

    sgx_status_t status = trustedSetSEK_backup(eid, &err_status, errMsg.data(), encrypted_SEK->data(), &l, SEK.c_str());

    encrypted_SEK->resize(l);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, err_status, errMsg.data());

    validate_SEK();

    return encrypted_SEK;
}

void gen_SEK() {
    vector<char> errMsg(1024, 0);
    int err_status = 0;
    vector <uint8_t> encrypted_SEK(1024, 0);
    uint32_t enc_len = 0;

    SAFE_CHAR_BUF(SEK, 65);

    spdlog::info("Generating backup key. Will be stored in backup_key.txt ... ");

    sgx_status_t status = trustedGenerateSEK(eid, &err_status, errMsg.data(), encrypted_SEK.data(), &enc_len, SEK);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, err_status, errMsg.data());


    if (strnlen(SEK, 33) != 32) {
        throw SGXException(-1, "strnlen(SEK,33) != 32");
    }

    vector<char> hexEncrKey(2 * enc_len + 1, 0);

    carray2Hex(encrypted_SEK.data(), enc_len, hexEncrKey.data(), 2 * enc_len + 1);

    spdlog::info(string("Encrypted storage encryption key:") + hexEncrKey.data());

    ofstream sek_file(BACKUP_PATH);
    sek_file.clear();

    sek_file << SEK;


    cout << "ATTENTION! YOUR BACKUP KEY HAS BEEN WRITTEN INTO sgx_data/backup_key.txt \n" << "PLEASE COPY IT TO THE SAFE PLACE AND THEN DELETE THE FILE MANUALLY BY RUNNING THE FOLLOWING COMMAND:\n" << "apt-get install secure-delete && srm -vz sgx_data/backup_key.txt" << endl;



    if (!autoconfirm) {
        string confirm_str = "I confirm";
        string buffer;
        do {
            cout << " DO YOU CONFIRM THAT YOU COPIED THE KEY? (if you confirm type - I confirm)" << endl;
            getline(cin, buffer);
        } while (case_insensitive_match(confirm_str, buffer));
    }


    LevelDB::getLevelDb()->writeDataUnique("SEK", hexEncrKey.data());

    create_test_key();

    validate_SEK();

    shared_ptr <string> encrypted_SEK_ptr = LevelDB::getLevelDb()->readString("SEK");

    setSEK(encrypted_SEK_ptr);

    validate_SEK();

}

void setSEK(shared_ptr <string> hex_encrypted_SEK) {

    CHECK_STATE(hex_encrypted_SEK);

    vector<char> errMsg(1024, 0);
    int err_status = 0;

    SAFE_UINT8_BUF(encrypted_SEK, BUF_LEN);

    uint64_t len = 0;

    if (!hex2carray(hex_encrypted_SEK->c_str(), &len, encrypted_SEK, BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encrypted SEK Hex");
    }

    sgx_status_t status = trustedSetSEK(eid, &err_status, errMsg.data(), encrypted_SEK);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, err_status, errMsg.data());


    validate_SEK();


}





void enter_SEK() {

    shared_ptr <string> test_key_ptr = LevelDB::getLevelDb()->readString("TEST_KEY");
    if (test_key_ptr == nullptr) {
        spdlog::error("Error: corrupt or empty LevelDB database");
        exit(-1);
    }


    if (!experimental::filesystem::is_regular_file(BACKUP_PATH)) {
        spdlog::error("File does not exist: "  BACKUP_PATH);
        exit(-1);
    }

    ifstream sek_file(BACKUP_PATH);

    spdlog::info("Reading backup key from file ...");

    string sek((istreambuf_iterator<char>(sek_file)), istreambuf_iterator<char>());

    boost::trim(sek);

    spdlog::info("Setting backup key ...");

    while (!checkHex(sek, 16)) {
        spdlog::error("Invalid hex in key");
        exit(-1);
    }

    auto encrypted_SEK = check_and_set_SEK(sek);

    vector<char> hexEncrKey(BUF_LEN, 0);

    carray2Hex(encrypted_SEK->data(), encrypted_SEK->size(), hexEncrKey.data(), BUF_LEN);

    spdlog::info("Got sealed storage encryption key.");

    LevelDB::getLevelDb()->deleteKey("SEK");

    spdlog::info("Storing sealed storage encryption key in LevelDB ...");

    LevelDB::getLevelDb()->writeDataUnique("SEK", hexEncrKey.data());

    spdlog::info("Stored storage encryption key in LevelDB.");

}

void initSEK() {
    shared_ptr <string> encrypted_SEK_ptr = LevelDB::getLevelDb()->readString("SEK");
    if (enterBackupKey) {
        enter_SEK();
    } else {
        if (encrypted_SEK_ptr == nullptr) {
            spdlog::warn("SEK was not created yet. Going to create SEK");
            gen_SEK();
        } else {
            setSEK(encrypted_SEK_ptr);
        }
    }
}


