




















const char* cert_name[3] = { "Akeo Consulting", "Akeo Systems", "Pete Batard" };

typedef struct {
	LPWSTR lpszProgramName;
	LPWSTR lpszPublisherLink;
	LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, *PSPROG_PUBLISHERINFO;



const char* WinPKIErrorString(void)
{
	static char error_string[64];
	DWORD error_code = GetLastError();

	if ((error_code >> 16) != 0x8009)
		return WindowsErrorString();

	switch (error_code) {
	case NTE_BAD_UID:
		return "Bad UID.";
	case CRYPT_E_MSG_ERROR:
		return "An error occurred while performing an operation on a cryptographic message.";
	case CRYPT_E_UNKNOWN_ALGO:
		return "Unknown cryptographic algorithm.";
	case CRYPT_E_INVALID_MSG_TYPE:
		return "Invalid cryptographic message type.";
	case CRYPT_E_HASH_VALUE:
		return "The hash value is not correct";
	case CRYPT_E_ISSUER_SERIALNUMBER:
		return "Invalid issuer and/or serial number.";
	case CRYPT_E_BAD_LEN:
		return "The length specified for the output data was insufficient.";
	case CRYPT_E_BAD_ENCODE:
		return "An error occurred during encode or decode operation.";
	case CRYPT_E_FILE_ERROR:
		return "An error occurred while reading or writing to a file.";
	case CRYPT_E_NOT_FOUND:
		return "Cannot find object or property.";
	case CRYPT_E_EXISTS:
		return "The object or property already exists.";
	case CRYPT_E_NO_PROVIDER:
		return "No provider was specified for the store or object.";
	case CRYPT_E_DELETED_PREV:
		return "The previous certificate or CRL context was deleted.";
	case CRYPT_E_NO_MATCH:
		return "Cannot find the requested object.";
	case CRYPT_E_UNEXPECTED_MSG_TYPE:
	case CRYPT_E_NO_KEY_PROPERTY:
	case CRYPT_E_NO_DECRYPT_CERT:
		return "Private key or certificate issue";
	case CRYPT_E_BAD_MSG:
		return "Not a cryptographic message.";
	case CRYPT_E_NO_SIGNER:
		return "The signed cryptographic message does not have a signer for the specified signer index.";
	case CRYPT_E_REVOKED:
		return "The certificate is revoked.";
	case CRYPT_E_NO_REVOCATION_DLL:
	case CRYPT_E_NO_REVOCATION_CHECK:
	case CRYPT_E_REVOCATION_OFFLINE:
	case CRYPT_E_NOT_IN_REVOCATION_DATABASE:
		return "Cannot check certificate revocation.";
	case CRYPT_E_INVALID_NUMERIC_STRING:
	case CRYPT_E_INVALID_PRINTABLE_STRING:
	case CRYPT_E_INVALID_IA5_STRING:
	case CRYPT_E_INVALID_X500_STRING:
	case  CRYPT_E_NOT_CHAR_STRING:
		return "Invalid string.";
	case CRYPT_E_SECURITY_SETTINGS:
		return "The cryptographic operation failed due to a local security option setting.";
	case CRYPT_E_NO_VERIFY_USAGE_CHECK:
	case CRYPT_E_VERIFY_USAGE_OFFLINE:
		return "Cannot complete usage check.";
	case CRYPT_E_NO_TRUSTED_SIGNER:
		return "None of the signers of the cryptographic message or certificate trust list is trusted.";
	default:
		static_sprintf(error_string, "Unknown PKI error 0x%08lX", error_code);
		return error_string;
	}
}


char* GetSignatureName(const char* path)
{
	static char szSubjectName[128];
	char *p = NULL, *mpath = NULL;
	BOOL r;
	HMODULE hm;
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD dwSize, dwEncoding, dwContentType, dwFormatType, dwSubjectSize;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	DWORD dwSignerInfo = 0;
	CERT_INFO CertInfo = { 0 };
	SPROG_PUBLISHERINFO ProgPubInfo = { 0 };
	wchar_t *szFileName;

	
	if (path == NULL) {
		szFileName = calloc(MAX_PATH, sizeof(wchar_t));
		if (szFileName == NULL)
			return NULL;
		hm = GetModuleHandle(NULL);
		if (hm == NULL) {
			uprintf("PKI: Could not get current executable handle: %s", WinPKIErrorString());
			return NULL;
		}
		dwSize = GetModuleFileNameW(hm, szFileName, MAX_PATH);
		if ((dwSize == 0) || ((dwSize == MAX_PATH) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))) {
			uprintf("PKI: Could not get module filename: %s", WinPKIErrorString());
			return NULL;
		}
		mpath = wchar_to_utf8(szFileName);
	} else {
		szFileName = utf8_to_wchar(path);
	}

	
	r = CryptQueryObject(CERT_QUERY_OBJECT_FILE, szFileName, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, NULL);

	if (!r) {
		uprintf("PKI: Failed to get signature for '%s': %s", (path==NULL)?mpath:path, WinPKIErrorString());
		goto out;
	}

	
	r = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
	if (!r) {
		uprintf("PKI: Failed to get signer size: %s", WinPKIErrorString());
		goto out;
	}

	
	pSignerInfo = (PCMSG_SIGNER_INFO)calloc(dwSignerInfo, 1);
	if (!pSignerInfo) {
		uprintf("PKI: Could not allocate memory for signer information");
		goto out;
	}

	
	r = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);
	if (!r) {
		uprintf("PKI: Failed to get signer information: %s", WinPKIErrorString());
		goto out;
	}

	
	CertInfo.Issuer = pSignerInfo->Issuer;
	CertInfo.SerialNumber = pSignerInfo->SerialNumber;

	pCertContext = CertFindCertificateInStore(hStore, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);
	if (!pCertContext) {
		uprintf("PKI: Failed to locate signer certificate in temporary store: %s", WinPKIErrorString());
		goto out;
	}

	
	dwSubjectSize = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szSubjectName, sizeof(szSubjectName));
	if (dwSubjectSize <= 1) {
		uprintf("PKI: Failed to get Subject Name");
		goto out;
	}

	uprintf("Downloaded executable is signed by '%s'", szSubjectName);
	p = szSubjectName;

out:
	safe_free(mpath);
	safe_free(szFileName);
	safe_free(ProgPubInfo.lpszProgramName);
	safe_free(ProgPubInfo.lpszPublisherLink);
	safe_free(ProgPubInfo.lpszMoreInfoLink);
	safe_free(pSignerInfo);
	safe_free(pCounterSignerInfo);
	if (pCertContext != NULL)
		CertFreeCertificateContext(pCertContext);
	if (hStore != NULL)
		CertCloseStore(hStore, 0);
	if (hMsg != NULL)
		CryptMsgClose(hMsg);
	return p;
}


LONG ValidateSignature(HWND hDlg, const char* path)
{
	LONG r;
	WINTRUST_DATA trust_data = { 0 };
	WINTRUST_FILE_INFO trust_file = { 0 };
	GUID guid_generic_verify =	 { 0xaac56b, 0xcd44, 0x11d0,{ 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };
	char *signature_name;
	size_t i, len;

	
	
	
	signature_name = GetSignatureName(path);
	if (signature_name == NULL) {
		uprintf("PKI: Could not get signature name");
		MessageBoxExU(hDlg, lmprintf(MSG_284), lmprintf(MSG_283), MB_OK | MB_ICONERROR | MB_IS_RTL, selected_langid);
		return TRUST_E_NOSIGNATURE;
	}
	for (i = 0; i < ARRAYSIZE(cert_name); i++) {
		len = strlen(cert_name[i]);
		if (strncmp(signature_name, cert_name[i], len) == 0) {
			
			if ((len >= strlen(signature_name)) || isspace(signature_name[len]))
				break;
		}
	}
	if (i >= ARRAYSIZE(cert_name)) {
		uprintf("PKI: Signature '%s' is unexpected...", signature_name);
		if (MessageBoxExU(hDlg, lmprintf(MSG_285, signature_name), lmprintf(MSG_283), MB_YESNO | MB_ICONWARNING | MB_IS_RTL, selected_langid) != IDYES)
			return TRUST_E_EXPLICIT_DISTRUST;
	}

	trust_file.cbStruct = sizeof(trust_file);
	trust_file.pcwszFilePath = utf8_to_wchar(path);
	if (trust_file.pcwszFilePath == NULL) {
		uprintf("PKI: Unable to convert '%s' to UTF16", path);
		return ERROR_SEVERITY_ERROR | FAC(FACILITY_CERT) | ERROR_NOT_ENOUGH_MEMORY;
	}

	trust_data.cbStruct = sizeof(trust_data);
	trust_data.dwUIChoice = WTD_UI_ALL;
	
	trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	
	trust_data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN | 0x400;
	trust_data.dwUnionChoice = WTD_CHOICE_FILE;
	trust_data.pFile = &trust_file;

	r = WinVerifyTrust(NULL, &guid_generic_verify, &trust_data);
	safe_free(trust_file.pcwszFilePath);

	return r;
}
