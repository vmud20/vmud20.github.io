






    #include <wchar.h>
    #include <windows.h>









    const char* fileSystemRepresentation(const std::wstring& sFileName);







    #define MAX_PATH 1024



std::wstring g_overrideTmpPath = L"";




	#include <wchar.h>
	#include <windows.h>

	std::wstring CorrectPathW(const std::wstring& path)
	{
		int len = (int)path.length();
		if (2 > len)
			return path;

		const wchar_t* path_str = path.c_str();
		if (path_str[0] == '\\' || path_str[1] == '/')
			return path;

		
		
		int nLen = GetFullPathNameW(path_str, 0, 0, 0);
		wchar_t* pBuf = new wchar_t[(4 + nLen) * sizeof(wchar_t)];

		pBuf[0] = L'\\', pBuf[1] = L'\\',  pBuf[2] = L'?', pBuf[3] = L'\\';
		GetFullPathNameW(path_str, nLen, pBuf + 4, NULL);

		std::wstring retPath(pBuf);
		delete [] pBuf;
		return retPath;
	}

	std::wstring CorrectPathW(const std::wstring& path)
	{
		return path;
	}


namespace NSFile {
    std::wstring CUtf8Converter::GetUnicodeFromCharPtr(const char* pData, LONG lCount, INT bIsUtf8)
    {
        if (bIsUtf8)
            return GetUnicodeStringFromUTF8((BYTE*)pData, lCount);

        wchar_t* pUnicode = new wchar_t[lCount + 1];
        for (LONG i = 0; i < lCount; ++i)
            pUnicode[i] = (wchar_t)(BYTE)pData[i];

        pUnicode[lCount] = 0;

        std::wstring s(pUnicode, lCount);
        RELEASEARRAYOBJECTS(pUnicode);

        return s;
    }
    std::wstring CUtf8Converter::GetUnicodeFromCharPtr(const std::string& sParam, INT bIsUtf8)
    {
        return GetUnicodeFromCharPtr(sParam.c_str(), (LONG)sParam.length(), bIsUtf8);
    }
	LONG CUtf8Converter::GetUnicodeStringFromUTF8BufferSize(LONG lCount)
    {
        return lCount + 1;
    }
    std::wstring CUtf8Converter::GetUnicodeStringFromUTF8_4bytes( BYTE* pBuffer, LONG lCount )
    {
        std::wstring strRes;
        GetUnicodeStringFromUTF8_4bytes(pBuffer, lCount, strRes);
        return strRes;
    }
    std::wstring CUtf8Converter::GetUnicodeStringFromUTF8_2bytes( BYTE* pBuffer, LONG lCount )
    {
        std::wstring strRes;
        GetUnicodeStringFromUTF8_2bytes(pBuffer, lCount, strRes);
        return strRes;
    }

    std::wstring CUtf8Converter::GetUnicodeStringFromUTF8( BYTE* pBuffer, LONG lCount )
    {
        std::wstring strRes;
        GetUnicodeStringFromUTF8(pBuffer, lCount, strRes);
        return strRes;
    }

    void CUtf8Converter::GetUnicodeStringFromUTF8_4bytes( BYTE* pBuffer, LONG lCount, std::wstring& sOutput )
    {
        WCHAR* pUnicodeString = new WCHAR[lCount + 1];
        LONG lIndexUnicode = 0;

        LONG lIndex = 0;
        while (lIndex < lCount)
        {
            BYTE byteMain = pBuffer[lIndex];
            if (0x00 == (byteMain & 0x80))
            {
                
                pUnicodeString[lIndexUnicode++] = (WCHAR)byteMain;
                ++lIndex;
            }
            else if (0x00 == (byteMain & 0x20))
            {
                
                int val = (int)(((byteMain & 0x1F) << 6) | (pBuffer[lIndex + 1] & 0x3F));
                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 2;
            }
            else if (0x00 == (byteMain & 0x10))
            {
                
                int val = (int)(((byteMain & 0x0F) << 12) | ((pBuffer[lIndex + 1] & 0x3F) << 6) | (pBuffer[lIndex + 2] & 0x3F));

                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 3;
            }
            else if (0x00 == (byteMain & 0x0F))
            {
                
                int val = (int)(((byteMain & 0x07) << 18) | ((pBuffer[lIndex + 1] & 0x3F) << 12) | ((pBuffer[lIndex + 2] & 0x3F) << 6) | (pBuffer[lIndex + 3] & 0x3F));


                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 4;
            }
            else if (0x00 == (byteMain & 0x08))
            {
                
                int val = (int)(((byteMain & 0x07) << 18) | ((pBuffer[lIndex + 1] & 0x3F) << 12) | ((pBuffer[lIndex + 2] & 0x3F) << 6) | (pBuffer[lIndex + 3] & 0x3F));


                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 4;
            }
            else if (0x00 == (byteMain & 0x04))
            {
                
                int val = (int)(((byteMain & 0x03) << 24) | ((pBuffer[lIndex + 1] & 0x3F) << 18) | ((pBuffer[lIndex + 2] & 0x3F) << 12) | ((pBuffer[lIndex + 3] & 0x3F) << 6) | (pBuffer[lIndex + 4] & 0x3F));



                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 5;
            }
            else {
                
                int val = (int)(((byteMain & 0x01) << 30) | ((pBuffer[lIndex + 1] & 0x3F) << 24) | ((pBuffer[lIndex + 2] & 0x3F) << 18) | ((pBuffer[lIndex + 3] & 0x3F) << 12) | ((pBuffer[lIndex + 4] & 0x3F) << 6) | (pBuffer[lIndex + 5] & 0x3F));




                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 5;
            }
        }

        pUnicodeString[lIndexUnicode] = 0;

        sOutput.append(pUnicodeString);

        delete [] pUnicodeString;
    }
    void CUtf8Converter::GetUnicodeStringFromUTF8_2bytes( BYTE* pBuffer, LONG lCount, std::wstring& sOutput )
    {
        WCHAR* pUnicodeString = new WCHAR[lCount + 1];
        WCHAR* pStart = pUnicodeString;

        LONG lIndex = 0;
        while (lIndex < lCount)
        {
            BYTE byteMain = pBuffer[lIndex];
            if (0x00 == (byteMain & 0x80))
            {
                
                *pUnicodeString++ = (WCHAR)byteMain;
                ++lIndex;
            }
            else if (0x00 == (byteMain & 0x20))
            {
                
                int val = (int)(((byteMain & 0x1F) << 6) | (pBuffer[lIndex + 1] & 0x3F));
                *pUnicodeString++ = (WCHAR)(val);
                lIndex += 2;
            }
            else if (0x00 == (byteMain & 0x10))
            {
                
                int val = (int)(((byteMain & 0x0F) << 12) | ((pBuffer[lIndex + 1] & 0x3F) << 6) | (pBuffer[lIndex + 2] & 0x3F));


                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 3;
            }
            else if (0x00 == (byteMain & 0x0F))
            {
                
                int val = (int)(((byteMain & 0x07) << 18) | ((pBuffer[lIndex + 1] & 0x3F) << 12) | ((pBuffer[lIndex + 2] & 0x3F) << 6) | (pBuffer[lIndex + 3] & 0x3F));



                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 4;
            }
            else if (0x00 == (byteMain & 0x08))
            {
                
                int val = (int)(((byteMain & 0x07) << 18) | ((pBuffer[lIndex + 1] & 0x3F) << 12) | ((pBuffer[lIndex + 2] & 0x3F) << 6) | (pBuffer[lIndex + 3] & 0x3F));



                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 4;
            }
            else if (0x00 == (byteMain & 0x04))
            {
                
                int val = (int)(((byteMain & 0x03) << 24) | ((pBuffer[lIndex + 1] & 0x3F) << 18) | ((pBuffer[lIndex + 2] & 0x3F) << 12) | ((pBuffer[lIndex + 3] & 0x3F) << 6) | (pBuffer[lIndex + 4] & 0x3F));




                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 5;
            }
            else {
                
                int val = (int)(((byteMain & 0x01) << 30) | ((pBuffer[lIndex + 1] & 0x3F) << 24) | ((pBuffer[lIndex + 2] & 0x3F) << 18) | ((pBuffer[lIndex + 3] & 0x3F) << 12) | ((pBuffer[lIndex + 4] & 0x3F) << 6) | (pBuffer[lIndex + 5] & 0x3F));





                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 5;
            }
        }

        *pUnicodeString++ = 0;

        sOutput.append(pStart);

        delete [] pStart;
    }
    void CUtf8Converter::GetUnicodeStringFromUTF8( BYTE* pBuffer, LONG lCount, std::wstring& sOutput )
    {
        if (sizeof(WCHAR) == 2)
            GetUnicodeStringFromUTF8_2bytes(pBuffer, lCount, sOutput);
        else GetUnicodeStringFromUTF8_4bytes(pBuffer, lCount, sOutput);
    }




































    long CUtf8Converter::CheckHHHHChar(const BYTE* pBuffer)
	{
        CHECK_HHHH(pBuffer);
	}
    long CUtf8Converter::CheckHHHHChar(const wchar_t* pBuffer)
	{
        CHECK_HHHH(pBuffer);
	}

    void CUtf8Converter::GetUnicodeStringFromUTF8WithHHHH_4bytes( const BYTE* pBuffer, LONG lCount, wchar_t*& pUnicodes, LONG& lOutputCount )
    {
        if (NULL == pUnicodes)
        {
            pUnicodes = new wchar_t[GetUnicodeStringFromUTF8BufferSize(lCount)];
        }
        WCHAR* pUnicodeString = pUnicodes;
        LONG lIndexUnicode = 0;

        LONG lIndex = 0;
        while (lIndex < lCount)
        {
            BYTE byteMain = pBuffer[lIndex];
            if (0x00 == (byteMain & 0x80))
            {
				
                long code = CheckHHHHChar(pBuffer + lIndex);
                if(code < 0)
                {
					pUnicodeString[lIndexUnicode++] = (WCHAR)byteMain;
					++lIndex;
				}
                else {
                    pUnicodeString[lIndexUnicode++] = (WCHAR)code;
                    lIndex += 7;
                }
            }
            else if (0x00 == (byteMain & 0x20))
            {
                
                int val = (int)(((byteMain & 0x1F) << 6) | (pBuffer[lIndex + 1] & 0x3F));
                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 2;
            }
            else if (0x00 == (byteMain & 0x10))
            {
                
                int val = (int)(((byteMain & 0x0F) << 12) | ((pBuffer[lIndex + 1] & 0x3F) << 6) | (pBuffer[lIndex + 2] & 0x3F));

                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 3;
            }
            else if (0x00 == (byteMain & 0x0F))
            {
                
                int val = (int)(((byteMain & 0x07) << 18) | ((pBuffer[lIndex + 1] & 0x3F) << 12) | ((pBuffer[lIndex + 2] & 0x3F) << 6) | (pBuffer[lIndex + 3] & 0x3F));


                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 4;
            }
            else if (0x00 == (byteMain & 0x08))
            {
                
                int val = (int)(((byteMain & 0x07) << 18) | ((pBuffer[lIndex + 1] & 0x3F) << 12) | ((pBuffer[lIndex + 2] & 0x3F) << 6) | (pBuffer[lIndex + 3] & 0x3F));


                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 4;
            }
            else if (0x00 == (byteMain & 0x04))
            {
                
                int val = (int)(((byteMain & 0x03) << 24) | ((pBuffer[lIndex + 1] & 0x3F) << 18) | ((pBuffer[lIndex + 2] & 0x3F) << 12) | ((pBuffer[lIndex + 3] & 0x3F) << 6) | (pBuffer[lIndex + 4] & 0x3F));



                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 5;
            }
            else {
                
                int val = (int)(((byteMain & 0x01) << 30) | ((pBuffer[lIndex + 1] & 0x3F) << 24) | ((pBuffer[lIndex + 2] & 0x3F) << 18) | ((pBuffer[lIndex + 3] & 0x3F) << 12) | ((pBuffer[lIndex + 4] & 0x3F) << 6) | (pBuffer[lIndex + 5] & 0x3F));




                pUnicodeString[lIndexUnicode++] = (WCHAR)(val);
                lIndex += 5;
            }
        }

        pUnicodeString[lIndexUnicode] = 0;
		lOutputCount = lIndexUnicode;
    }
    void CUtf8Converter::GetUnicodeStringFromUTF8WithHHHH_2bytes( const BYTE* pBuffer, LONG lCount, wchar_t*& pUnicodes, LONG& lOutputCount )
    {
        if (NULL == pUnicodes)
        {
            pUnicodes = new wchar_t[GetUnicodeStringFromUTF8BufferSize(lCount)];
        }
        WCHAR* pUnicodeString = pUnicodes;
        WCHAR* pStart = pUnicodeString;
        LONG lIndex = 0;
        while (lIndex < lCount)
        {
            BYTE byteMain = pBuffer[lIndex];
            if (0x00 == (byteMain & 0x80))
            {
                
                long code = CheckHHHHChar(pBuffer + lIndex);
                if(code < 0)
                {
                    *pUnicodeString++ = (WCHAR)byteMain;
                    ++lIndex;
                }
                else {
                    *pUnicodeString++ = (WCHAR)code;
                    lIndex += 7;
                }

            }
            else if (0x00 == (byteMain & 0x20))
            {
                
                int val = (int)(((byteMain & 0x1F) << 6) | (pBuffer[lIndex + 1] & 0x3F));
                *pUnicodeString++ = (WCHAR)(val);
                lIndex += 2;
            }
            else if (0x00 == (byteMain & 0x10))
            {
                
                int val = (int)(((byteMain & 0x0F) << 12) | ((pBuffer[lIndex + 1] & 0x3F) << 6) | (pBuffer[lIndex + 2] & 0x3F));


                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 3;
            }
            else if (0x00 == (byteMain & 0x0F))
            {
                
                int val = (int)(((byteMain & 0x07) << 18) | ((pBuffer[lIndex + 1] & 0x3F) << 12) | ((pBuffer[lIndex + 2] & 0x3F) << 6) | (pBuffer[lIndex + 3] & 0x3F));



                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 4;
            }
            else if (0x00 == (byteMain & 0x08))
            {
                
                int val = (int)(((byteMain & 0x07) << 18) | ((pBuffer[lIndex + 1] & 0x3F) << 12) | ((pBuffer[lIndex + 2] & 0x3F) << 6) | (pBuffer[lIndex + 3] & 0x3F));



                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 4;
            }
            else if (0x00 == (byteMain & 0x04))
            {
                
                int val = (int)(((byteMain & 0x03) << 24) | ((pBuffer[lIndex + 1] & 0x3F) << 18) | ((pBuffer[lIndex + 2] & 0x3F) << 12) | ((pBuffer[lIndex + 3] & 0x3F) << 6) | (pBuffer[lIndex + 4] & 0x3F));




                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 5;
            }
            else {
                
                int val = (int)(((byteMain & 0x01) << 30) | ((pBuffer[lIndex + 1] & 0x3F) << 24) | ((pBuffer[lIndex + 2] & 0x3F) << 18) | ((pBuffer[lIndex + 3] & 0x3F) << 12) | ((pBuffer[lIndex + 4] & 0x3F) << 6) | (pBuffer[lIndex + 5] & 0x3F));





                WriteUtf16_WCHAR(val, pUnicodeString);
                lIndex += 5;
            }
        }

		lOutputCount = pUnicodeString - pStart;
        *pUnicodeString++ = 0;
    }
    void CUtf8Converter::GetUnicodeStringFromUTF8WithHHHH( const BYTE* pBuffer, LONG lCount, wchar_t*& pUnicodes, LONG& lOutputCount )
    {
        if (sizeof(WCHAR) == 2)
            return GetUnicodeStringFromUTF8WithHHHH_2bytes(pBuffer, lCount, pUnicodes, lOutputCount);
        return GetUnicodeStringFromUTF8WithHHHH_4bytes(pBuffer, lCount, pUnicodes, lOutputCount);
    }

    void CUtf8Converter::GetUtf8StringFromUnicode_4bytes(const wchar_t* pUnicodes, LONG lCount, BYTE*& pData, LONG& lOutputCount, bool bIsBOM)
    {
        if (NULL == pData)
        {
            pData = new BYTE[6 * lCount + 3 + 1 ];
        }

        BYTE* pCodesCur = pData;
        if (bIsBOM)
        {
            pCodesCur[0] = 0xEF;
            pCodesCur[1] = 0xBB;
            pCodesCur[2] = 0xBF;
            pCodesCur += 3;
        }

        const wchar_t* pEnd = pUnicodes + lCount;
        const wchar_t* pCur = pUnicodes;

        while (pCur < pEnd)
        {
            unsigned int code = (unsigned int)*pCur++;

            if (code < 0x80)
            {
                *pCodesCur++ = (BYTE)code;
            }
            else if (code < 0x0800)
            {
                *pCodesCur++ = 0xC0 | (code >> 6);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
            else if (code < 0x10000)
            {
                *pCodesCur++ = 0xE0 | (code >> 12);
                *pCodesCur++ = 0x80 | (code >> 6 & 0x3F);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
            else if (code < 0x1FFFFF)
            {
                *pCodesCur++ = 0xF0 | (code >> 18);
                *pCodesCur++ = 0x80 | (code >> 12 & 0x3F);
                *pCodesCur++ = 0x80 | (code >> 6 & 0x3F);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
            else if (code < 0x3FFFFFF)
            {
                *pCodesCur++ = 0xF8 | (code >> 24);
                *pCodesCur++ = 0x80 | (code >> 18 & 0x3F);
                *pCodesCur++ = 0x80 | (code >> 12 & 0x3F);
                *pCodesCur++ = 0x80 | (code >> 6 & 0x3F);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
            else if (code < 0x7FFFFFFF)
            {
                *pCodesCur++ = 0xFC | (code >> 30);
                *pCodesCur++ = 0x80 | (code >> 24 & 0x3F);
                *pCodesCur++ = 0x80 | (code >> 18 & 0x3F);
                *pCodesCur++ = 0x80 | (code >> 12 & 0x3F);
                *pCodesCur++ = 0x80 | (code >> 6 & 0x3F);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
        }

        lOutputCount = (LONG)(pCodesCur - pData);
        *pCodesCur++ = 0;
    }

    void CUtf8Converter::GetUtf8StringFromUnicode_2bytes(const wchar_t* pUnicodes, LONG lCount, BYTE*& pData, LONG& lOutputCount, bool bIsBOM)
    {
        if (NULL == pData)
        {
            pData = new BYTE[6 * lCount + 3 + 1];
        }

        BYTE* pCodesCur = pData;
        if (bIsBOM)
        {
            pCodesCur[0] = 0xEF;
            pCodesCur[1] = 0xBB;
            pCodesCur[2] = 0xBF;
            pCodesCur += 3;
        }

        const wchar_t* pEnd = pUnicodes + lCount;
        const wchar_t* pCur = pUnicodes;

        while (pCur < pEnd)
        {
            unsigned int code = (unsigned int)*pCur++;
            if (code >= 0xD800 && code <= 0xDFFF && pCur < pEnd)
            {
                code = 0x10000 + (((code & 0x3FF) << 10) | (0x03FF & *pCur++));
            }

            if (code < 0x80)
            {
                *pCodesCur++ = (BYTE)code;
            }
            else if (code < 0x0800)
            {
                *pCodesCur++ = 0xC0 | (code >> 6);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
            else if (code < 0x10000)
            {
                *pCodesCur++ = 0xE0 | (code >> 12);
                *pCodesCur++ = 0x80 | ((code >> 6) & 0x3F);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
            else if (code < 0x1FFFFF)
            {
                *pCodesCur++ = 0xF0 | (code >> 18);
                *pCodesCur++ = 0x80 | ((code >> 12) & 0x3F);
                *pCodesCur++ = 0x80 | ((code >> 6) & 0x3F);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
            else if (code < 0x3FFFFFF)
            {
                *pCodesCur++ = 0xF8 | (code >> 24);
                *pCodesCur++ = 0x80 | ((code >> 18) & 0x3F);
                *pCodesCur++ = 0x80 | ((code >> 12) & 0x3F);
                *pCodesCur++ = 0x80 | ((code >> 6) & 0x3F);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
            else if (code < 0x7FFFFFFF)
            {
                *pCodesCur++ = 0xFC | (code >> 30);
                *pCodesCur++ = 0x80 | ((code >> 24) & 0x3F);
                *pCodesCur++ = 0x80 | ((code >> 18) & 0x3F);
                *pCodesCur++ = 0x80 | ((code >> 12) & 0x3F);
                *pCodesCur++ = 0x80 | ((code >> 6) & 0x3F);
                *pCodesCur++ = 0x80 | (code & 0x3F);
            }
        }

        lOutputCount = (LONG)(pCodesCur - pData);
        *pCodesCur++ = 0;
    }

    void CUtf8Converter::GetUtf8StringFromUnicode(const wchar_t* pUnicodes, LONG lCount, BYTE*& pData, LONG& lOutputCount, bool bIsBOM)
    {
        if (sizeof(WCHAR) == 2)
            return GetUtf8StringFromUnicode_2bytes(pUnicodes, lCount, pData, lOutputCount, bIsBOM);
        return GetUtf8StringFromUnicode_4bytes(pUnicodes, lCount, pData, lOutputCount, bIsBOM);
    }

    std::string CUtf8Converter::GetUtf8StringFromUnicode2(const wchar_t* pUnicodes, LONG lCount, bool bIsBOM)
    {
        BYTE* pData = NULL;
        LONG lLen = 0;

        GetUtf8StringFromUnicode(pUnicodes, lCount, pData, lLen, bIsBOM);

        std::string s((char*)pData, lLen);

        RELEASEARRAYOBJECTS(pData);
        return s;
    }

    std::string CUtf8Converter::GetUtf8StringFromUnicode(const std::wstring& sData)
    {
        return GetUtf8StringFromUnicode2(sData.c_str(), (LONG)sData.length());
    }

    
    void CUtf8Converter::GetUtf16StringFromUnicode_4bytes(const wchar_t* pUnicodes, LONG lCount, BYTE*& pData, int& lOutputCount, bool bIsBOM)
    {
        if (NULL == pData)
        {
            pData = new BYTE[4 * lCount + 3 + 2];
        }

        BYTE* pCodesCur = pData;
        if (bIsBOM)
        {
            pCodesCur[0] = 0xEF;
            pCodesCur[1] = 0xBB;
            pCodesCur[2] = 0xBF;
            pCodesCur += 3;
        }

        const wchar_t* pEnd = pUnicodes + lCount;
        const wchar_t* pCur = pUnicodes;

        while (pCur < pEnd)
        {
            unsigned int code = (unsigned int)*pCur++;

            if (code <= 0xFFFF)
            {
                USHORT usCode = (USHORT)(code & 0xFFFF);
                memcpy(pCodesCur, &usCode, 2);
                pCodesCur += 2;
            }
            else {
                code -= 0x10000;
                code &= 0xFFFFF;

                USHORT us1 = 0xD800 | ((code >> 10) & 0x03FF);
                USHORT us2 = 0xDC00 | (code & 0x03FF);

                memcpy(pCodesCur, &us1, 2);
                pCodesCur += 2;

                memcpy(pCodesCur, &us2, 2);
                pCodesCur += 2;
            }
        }

        lOutputCount = (LONG)(pCodesCur - pData);
        *pCodesCur++ = 0;
        *pCodesCur++ = 0;
    }

    void CUtf8Converter::GetUtf16StringFromUnicode_4bytes2(const wchar_t* pUnicodes, LONG lCount, CStringUtf16& data)
    {
        GetUtf16StringFromUnicode_4bytes(pUnicodes, lCount, data.Data, data.Length);
    }

    std::wstring CUtf8Converter::GetWStringFromUTF16(const CStringUtf16& data)
    {
        if (0 == data.Length)
            return L"";

        if (sizeof(wchar_t) == 2)
            return std::wstring((wchar_t*)data.Data, data.Length / 2);

        int nCount = data.Length / 2;
        USHORT* pShort = (USHORT*)data.Data;

        wchar_t* pWChar = new wchar_t[nCount + 1];
        wchar_t* pWCurrent = pWChar;

        int nCurrent = 0;
        while (nCurrent < nCount)
        {
            if (*pShort < 0xD800 || *pShort > 0xDBFF)
            {
                *pWCurrent = (wchar_t)(*pShort);
                ++pShort;
                ++nCurrent;
            }
            else {
                *pWCurrent = (wchar_t)(((((pShort[0] - 0xD800) & 0x03FF) << 10) | ((pShort[1] - 0xDC00) & 0x03FF)) + 0x10000);
                pShort += 2;
                nCurrent += 2;
            }
            ++pWCurrent;
        }

        std::wstring sRet(pWChar, pWCurrent - pWChar);

        RELEASEARRAYOBJECTS(pWChar);
        return sRet;
    }
    std::wstring CUtf8Converter::GetWStringFromUTF16(const unsigned short* pUtf16, LONG lCount)
    {
        CStringUtf16 oString;
        oString.Data   = (BYTE*)pUtf16;
        oString.Length = lCount * 2;
        std::wstring wsResult = GetWStringFromUTF16(oString);
        oString.Data = NULL;
        return wsResult;
    }
}

namespace NSFile {
    CFileBinary::CFileBinary()
    {
        m_pFile = NULL;
        m_lFilePosition = 0;
        m_lFileSize = 0;
    }
    CFileBinary::~CFileBinary()
    {
        CloseFile();
    }

    void CFileBinary::CloseFile()
    {
        m_lFilePosition = 0;
        m_lFileSize = 0;

        if (m_pFile != NULL)
        {
            fclose(m_pFile);
            m_pFile = NULL;
        }
    }

    FILE* CFileBinary::GetFileNative()
    {
        return m_pFile;
    }
    long CFileBinary::GetFileSize()
    {
        return m_lFileSize;
    }
    long CFileBinary::GetFilePosition()
    {
        return m_lFilePosition;
    }


    
    bool CFileBinary::OpenFile(const std::wstring& sFileName, bool bRewrite)
    {
        m_pFile = fopen(fileSystemRepresentation(sFileName), bRewrite ? "rb+" : "rb");
        
        if (NULL == m_pFile) {

            

            return false;
        }
        
        fseek(m_pFile, 0, SEEK_END);
        m_lFileSize = ftell(m_pFile);
        fseek(m_pFile, 0, SEEK_SET);
        
        m_lFilePosition = 0;
        
        if (0 < sFileName.length())
        {
            if (((wchar_t)'/') == sFileName.c_str()[sFileName.length() - 1])
                m_lFileSize = 0x7FFFFFFF;
        }
        
        unsigned int err = 0x7FFFFFFF;
        unsigned int cur = (unsigned int)m_lFileSize;
        if (err == cur)
        {
            CloseFile();
            return false;
        }
        
        return true;
    }

    bool CFileBinary::CreateFileW(const std::wstring& sFileName)
    {
        m_pFile = fopen(fileSystemRepresentation(sFileName), "wb");

        if (NULL == m_pFile) {

        

            return false;
        }

        m_lFilePosition = 0;
        return true;
    }



    bool CFileBinary::OpenFile(const std::wstring& sFileName, bool bRewrite)
    {

        if ( 0 != _wfopen_s(&m_pFile, sFileName.c_str(), bRewrite ? L"rb+" : L"rb"))
            return false;

        BYTE* pUtf8 = NULL;
        LONG lLen = 0;
        CUtf8Converter::GetUtf8StringFromUnicode(sFileName.c_str(), sFileName.length(), pUtf8, lLen, false);
        m_pFile = fopen((char*)pUtf8, bRewrite ? "rb+" : "rb");

        delete [] pUtf8;

        if (NULL == m_pFile)
            return false;

        fseek(m_pFile, 0, SEEK_END);
        m_lFileSize = ftell(m_pFile);
        fseek(m_pFile, 0, SEEK_SET);

        m_lFilePosition = 0;

        if (0 < sFileName.length())
        {
            if (((wchar_t)'/') == sFileName.c_str()[sFileName.length() - 1])
                m_lFileSize = 0x7FFFFFFF;
        }

        unsigned int err = 0x7FFFFFFF;
        unsigned int cur = (unsigned int)m_lFileSize;
        if (err == cur)
        {
            CloseFile();
            return false;
        }

        return true;
    }

    bool CFileBinary::CreateFileW(const std::wstring& sFileName)
    {

         if ( 0 != _wfopen_s(&m_pFile, sFileName.c_str(), L"wb"))
             return false;

        BYTE* pUtf8 = NULL;
        LONG lLen = 0;
        CUtf8Converter::GetUtf8StringFromUnicode(sFileName.c_str(), sFileName.length(), pUtf8, lLen, false);
        m_pFile = fopen((char*)pUtf8, "wb");
        delete [] pUtf8;

        if (NULL == m_pFile)
            return false;

        m_lFilePosition = 0;
        return true;
    }



    bool CFileBinary::CreateTempFile()
    {

        if (0 != tmpfile_s(&m_pFile))
            return false;

        m_pFile = tmpfile();
        if (NULL == m_pFile)
            return false;

        m_lFilePosition = 0;
        return true;
    }
    bool CFileBinary::SeekFile(int lFilePosition, int nSeekMode)
    {
        if (!m_pFile)
            return false;

        m_lFilePosition = fseek(m_pFile, lFilePosition, nSeekMode);
        return true;
    }
    bool CFileBinary::ReadFile(BYTE* pData, DWORD nBytesToRead, DWORD& dwSizeRead)
    {
        if (!m_pFile)
            return false;

        dwSizeRead = (DWORD)fread((void*)pData, 1, nBytesToRead, m_pFile);
        return true;
    }
    bool CFileBinary::WriteFile(const BYTE* pData, DWORD nBytesCount)
    {
        if (!m_pFile)
            return false;

        size_t nCountWrite = fwrite((const void*)pData, 1, nBytesCount, m_pFile);
        return true;
    }
    long CFileBinary::TellFile()
    {
        if (!m_pFile)
            return 0;

        return ftell(m_pFile);
    }
    long CFileBinary::SizeFile()
    {
        if (!m_pFile)
            return 0;

        long lPos = TellFile();
        fseek(m_pFile, 0, SEEK_END);
        m_lFileSize = ftell(m_pFile);
        fseek(m_pFile, lPos, SEEK_SET);

        return m_lFileSize;
    }
    void CFileBinary::WriteStringUTF8(const std::wstring& strXml, bool bIsBOM)
    {
        BYTE* pData = NULL;
        LONG lLen = 0;

        CUtf8Converter::GetUtf8StringFromUnicode(strXml.c_str(), (LONG)strXml.length(), pData, lLen, bIsBOM);

        WriteFile(pData, lLen);

        RELEASEARRAYOBJECTS(pData);
    }
    bool CFileBinary::ReadAllBytes(const std::wstring&  strFileName, BYTE** ppData, DWORD& nBytesCount)
    {
        *ppData = NULL;
        nBytesCount = 0;
        bool bRes = false;
        CFileBinary oFileBinary;
        if (oFileBinary.OpenFile(strFileName))
        {
            long nFileSize = oFileBinary.GetFileSize();
            BYTE* pData = new BYTE[nFileSize];
            DWORD dwSizeRead;
            if (oFileBinary.ReadFile(pData, nFileSize, dwSizeRead))
            {
                oFileBinary.CloseFile();
                *ppData = pData;
                nBytesCount = dwSizeRead;
                bRes = true;
            }
            else RELEASEARRAYOBJECTS(pData);
        }
        return bRes;
    }
    bool CFileBinary::ReadAllTextUtf8(const std::wstring&  strFileName, std::wstring& sData)
    {
        bool bRes = false;
        BYTE* pData = NULL;
        DWORD nDataSize;
        if (CFileBinary::ReadAllBytes(strFileName, &pData, nDataSize))
        {
            
            BYTE* pDataStart = pData;
            DWORD nBOMSize = 3;
            if (nDataSize > nBOMSize && 0xef == pDataStart[0] && 0xbb == pDataStart[1] && 0xbf == pDataStart[2])
            {
                pDataStart += nBOMSize;
                nDataSize -= nBOMSize;
            }
            sData = CUtf8Converter::GetUnicodeStringFromUTF8(pDataStart, nDataSize);
            RELEASEARRAYOBJECTS(pData);
            bRes = true;
        }
        return bRes;
    }
    bool CFileBinary::ReadAllTextUtf8A(const std::wstring&  strFileName, std::string& sData)
    {
        bool bRes = false;
        BYTE* pData = NULL;
        DWORD nDataSize;
        if (CFileBinary::ReadAllBytes(strFileName, &pData, nDataSize))
        {
            
            BYTE* pDataStart = pData;
            DWORD nBOMSize = 3;
            if (nDataSize > nBOMSize && 0xef == pDataStart[0] && 0xbb == pDataStart[1] && 0xbf == pDataStart[2])
            {
                pDataStart += nBOMSize;
                nDataSize -= nBOMSize;
            }
            sData = std::string((char*)pDataStart, nDataSize);
            RELEASEARRAYOBJECTS(pData);
            bRes = true;
        }
        return bRes;
    }
    bool CFileBinary::SaveToFile(const std::wstring&  strFileName, const std::wstring& strXml, bool bIsBOM)
    {
        CFileBinary oFile;
        oFile.CreateFileW(strFileName);
        oFile.WriteStringUTF8(strXml, bIsBOM);
        oFile.CloseFile();
        return true;
    }
    bool CFileBinary::Exists(const std::wstring&  strFileName)
    {

        FILE* pFile = NULL;
        if ( 0 != _wfopen_s( &pFile, strFileName.c_str(), L"rb"))
            return false;

        BYTE* pUtf8 = NULL;
        LONG lLen = 0;
        CUtf8Converter::GetUtf8StringFromUnicode(strFileName.c_str(), strFileName.length(), pUtf8, lLen, false);
        FILE* pFile = fopen((char*)pUtf8, "rb");
        delete [] pUtf8;

        if (NULL != pFile)
        {
            fclose(pFile);
            return true;
        }
        else return false;
    }
    bool CFileBinary::Copy(const std::wstring&  strSrc, const std::wstring& strDst)
    {
        if (strSrc == strDst)
            return true;

        std::ifstream src;
        std::ofstream dst;

        int nLenBuffer = 1024 * 1024; 
        CFileBinary oFile;
        if (oFile.OpenFile(strSrc))
        {
            int nFileSize = (int)oFile.GetFileSize();
            if (nFileSize < nLenBuffer)
                nLenBuffer = nFileSize;

            oFile.CloseFile();
        }
        else {

            return (0 != ::CopyFileW(strSrc.c_str(), strDst.c_str(), 1));

        }

        char* pBuffer_in = NULL;
        char* pBuffer_out = NULL;

        if (nLenBuffer > 0)
        {
            pBuffer_in = new char[nLenBuffer];
            pBuffer_out = new char[nLenBuffer];

            src.rdbuf()->pubsetbuf(pBuffer_in, nLenBuffer);
            dst.rdbuf()->pubsetbuf(pBuffer_out, nLenBuffer);
        }


        src.open(strSrc.c_str(), std::ios::binary);
        dst.open(strDst.c_str(), std::ios::binary);

        BYTE* pUtf8Src = NULL;
        LONG lLenSrc = 0;
        CUtf8Converter::GetUtf8StringFromUnicode(strSrc.c_str(), strSrc.length(), pUtf8Src, lLenSrc, false);
        BYTE* pUtf8Dst = NULL;
        LONG lLenDst = 0;
        CUtf8Converter::GetUtf8StringFromUnicode(strDst.c_str(), strDst.length(), pUtf8Dst, lLenDst, false);

        src.open((char*)pUtf8Src, std::ios::binary);
        dst.open((char*)pUtf8Dst, std::ios::binary);

        delete [] pUtf8Src;
        delete [] pUtf8Dst;


        bool bRet = false;

        if (src.is_open() && dst.is_open())
        {
            dst << src.rdbuf();
            src.close();
            dst.close();

            bRet = true;
        }
        RELEASEARRAYOBJECTS(pBuffer_in);
        RELEASEARRAYOBJECTS(pBuffer_out);
        return bRet;
    }
    bool CFileBinary::Remove(const std::wstring& strFileName)
    {

        int nRes = _wremove(strFileName.c_str());

        BYTE* pUtf8 = NULL;
        LONG lLen = 0;
        CUtf8Converter::GetUtf8StringFromUnicode(strFileName.c_str(), strFileName.length(), pUtf8, lLen, false);
        int nRes = std::remove((char*)pUtf8);
        delete [] pUtf8;

        return 0 == nRes;
    }
    bool CFileBinary::Move(const std::wstring&  strSrc, const std::wstring& strDst)
    {
        if (strSrc == strDst)
            return true;
        if (Copy(strSrc, strDst))
            if (Remove(strSrc))
                return true;
        return false;
    }

    bool CFileBinary::Truncate(const std::wstring& sPath, size_t nNewSize)
    {
        bool bIsSuccess = false;


        HANDLE hFile = ::CreateFileW( sPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

        if ( hFile == INVALID_HANDLE_VALUE )
        {
            return bIsSuccess;
        }

        LARGE_INTEGER Size = { 0 };

        if ( GetFileSizeEx( hFile, &Size ) )
        {
            LARGE_INTEGER Distance = { 0 };
            
            Distance.QuadPart = (LONGLONG)nNewSize - Size.QuadPart;
            bIsSuccess = (SetFilePointerEx(hFile, Distance, NULL, FILE_END) && SetEndOfFile(hFile));
        }

        CloseHandle( hFile );

        std::string sFileUTF8 = U_TO_UTF8(sPath);
        bIsSuccess = (0 == truncate(sFileUTF8.c_str(), nNewSize));

        return bIsSuccess;
    }

    std::wstring CFileBinary::GetTempPath()
    {
        if (!g_overrideTmpPath.empty())
            return g_overrideTmpPath;


        wchar_t pBuffer[MAX_PATH + 1];
        memset(pBuffer, 0, sizeof(wchar_t) * (MAX_PATH + 1));
        ::GetTempPathW(MAX_PATH, pBuffer);

        std::wstring sRet(pBuffer);

        size_t nSeparatorPos = sRet.find_last_of(wchar_t('/'));
        if (std::wstring::npos == nSeparatorPos)
        {
            nSeparatorPos = sRet.find_last_of(wchar_t('\\'));
        }

        if (std::wstring::npos == nSeparatorPos)
            return L"";

        return sRet.substr(0, nSeparatorPos);

        char *folder = getenv("TEMP");

        if (NULL == folder)
            folder = getenv("TMP");
        if (NULL == folder)
            folder = getenv("TMPDIR");
        if (NULL == folder)
            folder = "/tmp";

        return NSFile::CUtf8Converter::GetUnicodeStringFromUTF8((BYTE*)folder, strlen(folder));

    }
    std::wstring CFileBinary::CreateTempFileWithUniqueName(const std::wstring& strFolderPathRoot, const std::wstring& Prefix)
    {

        wchar_t pBuffer[MAX_PATH + 1];
        ::GetTempFileNameW(strFolderPathRoot.c_str(), Prefix.c_str(), 0, pBuffer);
        std::wstring sRet(pBuffer);
        return sRet;

        char pcRes[MAX_PATH];
        BYTE* pData = (BYTE*)pcRes;

        std::wstring sPrefix = strFolderPathRoot + L"/" + Prefix + L"_XXXXXX";
        LONG lLen = 0;
        NSFile::CUtf8Converter::GetUtf8StringFromUnicode(sPrefix.c_str(), (LONG)sPrefix.length(), pData, lLen);
        pcRes[lLen] = '\0';

        int res = mkstemp(pcRes);
        if (-1 != res)
            close(res);

        std::string sRes = pcRes;
        return NSFile::CUtf8Converter::GetUnicodeStringFromUTF8((BYTE*)sRes.c_str(), sRes.length());

    }
    bool CFileBinary::OpenTempFile(std::wstring *pwsName, FILE **ppFile, wchar_t *wsMode, wchar_t *wsExt, wchar_t *wsFolder, wchar_t* wsName)
    {
        

        std::wstring wsTemp, wsFileName;
        FILE *pTempFile = NULL;

        wchar_t *wsTempDir = NULL;
        size_t sz = 0;
        if ( (0 == _wdupenv_s(&wsTempDir, &sz, L"TEMP")) && (wsFolder == NULL))
        {
            wsTemp = std::wstring(wsTempDir, sz-1);

        char *wsTempDirA;
        if ((wsTempDirA = getenv("TEMP")) && (wsFolder == NULL))
        {
            std::wstring wsTempDir = NSFile::CUtf8Converter::GetUnicodeStringFromUTF8((BYTE*)wsTempDirA, strlen(wsTempDirA));
            wsTemp = wsTempDir.c_str();

            wsTemp += L"/";
        }
        else if (wsFolder != NULL)
        {
            wsTemp = std::wstring(wsFolder);
            wsTemp += L"/";
        }
        else {
            wsTemp = L"";
        }
        wsTemp += L"x";
        int nTime = (int)time(NULL);
        for (int nIndex = 0; nIndex < 1000; ++nIndex)
        {
            wsFileName = wsTemp;
            wsFileName.append(std::to_wstring(nTime + nIndex));

            if (wsExt)
            {
                wsFileName.append(wsExt);
            }

            if ( 0 != _wfopen_s(&pTempFile, wsFileName.c_str(), L"r") )
            {
                if (0 != _wfopen_s(&pTempFile, wsFileName.c_str(), wsMode))

            std::string sFileName = U_TO_UTF8(wsFileName);
            if (!(pTempFile = fopen(sFileName.c_str(), "r")))
            {
                std::wstring strMode(wsMode);
                std::string sMode = U_TO_UTF8(strMode);
                if (!(pTempFile = fopen(sFileName.c_str(), sMode.c_str())))

                {
                    return FALSE;
                }
                *pwsName = wsFileName;
                *ppFile = pTempFile;
                return TRUE;
            }

            fclose(pTempFile);
        }

        return FALSE;
    }
    FILE* CFileBinary::OpenFileNative(const std::wstring& sFileName, const std::wstring& sMode)
    {

        FILE* pFile = NULL;
        _wfopen_s(&pFile, sFileName.c_str(), sMode.c_str());

        return pFile;

        BYTE* pUtf8 = NULL;
        LONG lLen = 0;
        CUtf8Converter::GetUtf8StringFromUnicode(sFileName.c_str(), sFileName.length(), pUtf8, lLen, false);

        BYTE* pMode = NULL;
        LONG lLenMode;
        CUtf8Converter::GetUtf8StringFromUnicode(sMode.c_str(), sMode.length(), pMode, lLenMode, false);

        FILE* pFile = fopen((char*)pUtf8, (char*)pMode);

        delete [] pUtf8;
        delete [] pMode;

        return pFile;

    }

    void CFileBinary::SetTempPath(const std::wstring& strTempPath)
    {
        g_overrideTmpPath = strTempPath;
    }

    unsigned long CFileBinary::GetDateTime(const std::wstring & inputFile)
    {
        unsigned long result = 0;

        HANDLE hFile;
        hFile = ::CreateFileW(inputFile.c_str(), GENERIC_READ, FILE_SHARE_READ,  NULL,  OPEN_EXISTING,  FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile)
        {
            FILETIME ft; ft.dwLowDateTime = ft.dwHighDateTime = 0;
            if (GetFileTime(hFile, NULL, NULL, &ft))
            {
                WORD fatDate = 0, fatTime = 0;
                if (FileTimeToDosDateTime(&ft, &fatDate,  &fatTime))
                {
                    result = (fatDate << 16) + fatTime;
                }
            }
            CloseHandle(hFile);
        }

        std::string inputFileA = U_TO_UTF8(inputFile);

        struct stat attrib;
        stat(inputFileA.c_str(), &attrib);
        result = attrib.st_mtim.tv_nsec;

        struct stat attrib;
        stat(inputFileA.c_str(), &attrib);
        result = (unsigned long)attrib.st_mtimespec.tv_nsec;


        return result;
    }
}

namespace NSFile {
    bool CBase64Converter::Encode(BYTE* pDataSrc, int nLenSrc, char*& pDataDst, int& nLenDst, DWORD dwFlags)
    {
        if (!pDataSrc || nLenSrc < 1)
            return false;

        nLenDst = NSBase64::Base64EncodeGetRequiredLength(nLenSrc, dwFlags);
        pDataDst = new char[nLenDst];

        if (FALSE == NSBase64::Base64Encode(pDataSrc, nLenSrc, (BYTE*)pDataDst, &nLenDst, dwFlags))
        {
            RELEASEARRAYOBJECTS(pDataDst);
            return false;
        }
        return true;
    }
    bool CBase64Converter::Decode(const char* pDataSrc, int nLenSrc, BYTE*& pDataDst, int& nLenDst)
    {
        if (!pDataSrc || nLenSrc < 1)
            return false;

        nLenDst = NSBase64::Base64DecodeGetRequiredLength(nLenSrc);
        pDataDst = new BYTE[nLenDst];

        if (FALSE == NSBase64::Base64Decode(pDataSrc, nLenSrc, pDataDst, &nLenDst))
        {
            RELEASEARRAYOBJECTS(pDataDst);
            return false;
        }
        return true;
    }
}

namespace NSFile {
    std::wstring GetProcessPath()
    {

        wchar_t buf [NS_FILE_MAX_PATH];
        GetModuleFileNameW(GetModuleHandle(NULL), buf, NS_FILE_MAX_PATH);
        return std::wstring(buf);



        char buf[NS_FILE_MAX_PATH];
        memset(buf, 0, NS_FILE_MAX_PATH);
        if (readlink ("/proc/self/exe", buf, NS_FILE_MAX_PATH) <= 0)
        {

            uint32_t _size = NS_FILE_MAX_PATH;
            _NSGetExecutablePath(buf, &_size);
            std::string sUTF8(buf);
            std::wstring sRet = CUtf8Converter::GetUnicodeStringFromUTF8((BYTE*)sUTF8.c_str(), sUTF8.length());
            return sRet;

            return L"";
        }

        std::string sUTF8(buf);
        std::wstring sRet = CUtf8Converter::GetUnicodeStringFromUTF8((BYTE*)sUTF8.c_str(), sUTF8.length());
        return sRet;


        return L"";
    }

    std::wstring GetProcessDirectory()
    {
        std::wstring sPath = GetProcessPath();

        size_t pos1 = sPath.find_last_of(wchar_t('/'));
        size_t pos2 = sPath.find_last_of(wchar_t('\\'));

        size_t pos = std::wstring::npos;
        if (pos1 != std::wstring::npos)
            pos = pos1;

        if (pos2 != std::wstring::npos)
        {
            if (pos == std::wstring::npos)
                pos = pos2;
            else if (pos2 > pos)
                pos = pos2;
        }

        if (pos != std::wstring::npos)
        {
            sPath = sPath.substr(0, pos);
        }
        return sPath;
    }

    
    std::wstring GetFileExtention(const std::wstring& sPath)
    {
        std::wstring::size_type nPos = sPath.rfind('.');
        if (nPos != std::wstring::npos)
            return sPath.substr(nPos + 1);
        return sPath;
    }
    std::wstring GetFileName(const std::wstring& sPath)
    {
        std::wstring::size_type nPos1 = sPath.rfind('\\');
        std::wstring::size_type nPos2 = sPath.rfind('/');
        std::wstring::size_type nPos = std::wstring::npos;

        if (nPos1 != std::wstring::npos)
        {
            nPos = nPos1;
            if (nPos2 != std::wstring::npos && nPos2 > nPos)
                nPos = nPos2;
        }
        else nPos = nPos2;

        if (nPos == std::wstring::npos)
            return sPath;
        return sPath.substr(nPos + 1);
    }
    std::wstring GetDirectoryName(const std::wstring& sPath)
    {
        std::wstring::size_type nPos1 = sPath.rfind('\\');
        std::wstring::size_type nPos2 = sPath.rfind('/');
        std::wstring::size_type nPos = std::wstring::npos;

        if (nPos1 != std::wstring::npos)
        {
            nPos = nPos1;
            if (nPos2 != std::wstring::npos && nPos2 > nPos)
                nPos = nPos2;
        }
        else nPos = nPos2;

        if (nPos == std::wstring::npos)
            return sPath;
        return sPath.substr(0, nPos);
    }
}
