﻿       namespace NSFontConverter {







    #define LINESIZE 1024

    #define PFB_MARKER 128
    #define PFB_ASCII    1
    #define PFB_BINARY   2
    #define PFB_DONE     3


    #define IS_PS_NEWLINE( ch )  ( (ch) == '\r' || (ch) == '\n'


    #define IS_PS_SPACE( ch )   ( (ch) == ' '         || IS_PS_NEWLINE( ch ) || (ch) == '\t'        || (ch) == '\f'        || (ch) == '\0'





    
    static const signed char c_arrCharTable[128] = {
        
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, -1, -1, -1, -1, -1, };








    
    #define OP  >=

    #define WriteChar(Value)  nChar = (char)(Value); pOutputFunc( pOutputStream, &nChar, 1 )


    unsigned int EexecDecode   (unsigned char** cursor, unsigned char* limit, unsigned char* buffer, unsigned int n, unsigned short* seed )
    {
        unsigned char*  p;
        unsigned int r;
        unsigned int s = *seed;

        p = *cursor;
        if ( n > (unsigned int)(limit - p) )
          n = (unsigned int)(limit - p);

        for ( r = 0; r < n; r++ )
        {
          unsigned int  val = p[r];
          unsigned int  b   = ( val ^ ( s >> 8 ) );


          s         = ( (val + s)*52845U + 22719 ) & 0xFFFFU;
          buffer[r] = (unsigned char) b;
        }

        *cursor = p + n;
        *seed   = (unsigned short)s;

        return r;
      }

    unsigned int ASCIIHexDecode(unsigned char** cursor, unsigned char* limit, unsigned char* buffer, unsigned int n)
    {
        unsigned char*  p;
        unsigned int  r   = 0;
        unsigned int  w   = 0;
        unsigned int  pad = 0x01;


        n *= 2;

        p  = *cursor;
        if ( n > (unsigned int)( limit - p ) )
          n = (unsigned int)( limit - p );

        
        for ( ; r < n; r++ )
        {
          FT_UInt  c = p[r];


          if ( IS_PS_SPACE( c ) )
            continue;

          if ( c OP 0x80 )
            break;

          c = c_arrCharTable[c & 0x7F];
          if ( (unsigned)c >= 16 )
            break;

          pad = ( pad << 4 ) | c;
          if ( pad & 0x100 )
          {
            buffer[w++] = (FT_Byte)pad;
            pad         = 0x01;
          }
        }

        if ( pad != 0x01 )
          buffer[w++] = (FT_Byte)( pad << 4 );

        *cursor = p + r;

        return w;
      }
    
    
    

    CFontFileType1 *CFontFileType1::LoadFromBuffer(char *sBuffer, int nLen)
    {
        return new CFontFileType1(sBuffer, nLen, false);
    }

    CFontFileType1 *CFontFileType1::LoadFromFile(const wchar_t *wsFileName)
    {
        char *sBuffer;
        int nLen = 0;

        if ( !( sBuffer = CFontFileBase::ReadFile(wsFileName, &nLen) ) )
            return NULL;

        return new CFontFileType1(sBuffer, nLen, true);
    }

    CFontFileType1::CFontFileType1(char *sBuffer, int nLen, bool bFreeData):
    CFontFileBase(sBuffer, nLen, bFreeData)
    {
        m_sName = NULL;
        m_arrEncoding = NULL;

        Parse();
        m_bParsed = false;
    }

    CFontFileType1::~CFontFileType1()
    {
        if (m_sName)
            MemUtilsFree(m_sName);

        if ( m_arrEncoding && m_arrEncoding != c_arrsFontFileType1StandardEncoding )
        {
            for (int nIndex = 0; nIndex < 256; ++nIndex )
            {
                MemUtilsFree( m_arrEncoding[nIndex] );
            }
            MemUtilsFree(m_arrEncoding);
        }
    }

    char *CFontFileType1::GetName()
    {
        if ( !m_bParsed )
            Parse();

        return m_sName;
    }

    char **CFontFileType1::GetEncoding()
    {
        if (!m_bParsed)
            Parse();

        return m_arrEncoding;
    }

    void CFontFileType1::WriteEncoded(char **ppNewEncoding, FontFileOutputFunc pOutputFunc, void *pOutputStream)
    {
        char sBuffer[512];
        char *sLine, *sLine2, *sCurChar;

        
        for ( sLine = (char *)m_sFile; sLine && strncmp( sLine, "/Encoding", 9); sLine = GetNextLine(sLine) );
        if ( !sLine )
        {
            
            (*pOutputFunc)( pOutputStream, (char *)m_sFile, m_nLen);
            return;
        }
        (*pOutputFunc)( pOutputStream, (char *)m_sFile, sLine - (char *)m_sFile);

        
        (*pOutputFunc)( pOutputStream, "/Encoding 256 array\n", 20);
        (*pOutputFunc)( pOutputStream, "0 1 255 {1 index exch /.notdef put} for\n", 40);
        for ( int nIndex = 0; nIndex < 256; ++nIndex )
        {
            if (ppNewEncoding[nIndex])
            {
                sprintf( sBuffer, "dup %d /%s put\n", nIndex, ppNewEncoding[nIndex]);
                (*pOutputFunc)( pOutputStream, sBuffer, strlen( sBuffer ));
            }
        }
        (*pOutputFunc)( pOutputStream, "readonly def\n", 13);

        if ( !strncmp( sLine, "/Encoding StandardEncoding def", 30) )
        {
            sLine = GetNextLine(sLine);
        }
        else {
            sCurChar = sLine + 10;
            sLine = NULL;
            for (; sCurChar < (char *)m_sFile + m_nLen; ++sCurChar)
            {
                if ((*sCurChar == ' ' || *sCurChar == '\t' || *sCurChar == '\x0a' || *sCurChar == '\x0d' || *sCurChar == '\x0c' || *sCurChar == '\0') && sCurChar + 4 <= (char *)m_sFile + m_nLen && !strncmp(sCurChar + 1, "def", 3) )
                {
                    sLine = sCurChar + 4;
                    break;
                }
            }
        }

        
        if ( sLine )
        {
            int nIndex;
            for ( sLine2 = sLine, nIndex = 0; nIndex < 20 && sLine2 && strncmp(sLine2, "/Encoding", 9); sLine2 = GetNextLine(sLine2), ++nIndex) ;
            if ( nIndex < 20 && sLine2 )
            {
                (*pOutputFunc)( pOutputStream, sLine, sLine2 - sLine);
                if ( !strncmp(sLine2, "/Encoding StandardEncoding def", 30) )
                {
                    sLine = GetNextLine( sLine2 );
                }
                else {
                    sCurChar = sLine2 + 10;
                    sLine = NULL;
                    for (; sCurChar < (char *)m_sFile + m_nLen; ++sCurChar)
                    {
                        if ((*sCurChar == ' ' || *sCurChar == '\t' || *sCurChar == '\x0a' || *sCurChar == '\x0d' || *sCurChar == '\x0c' || *sCurChar == '\0') && sCurChar + 4 <= (char *)m_sFile + m_nLen && !strncmp(sCurChar + 1, "def", 3) )
                        {
                            sLine = sCurChar + 4;
                            break;
                        }
                    }
                }
            }

            
            if ( sLine )
            {
                (*pOutputFunc)( pOutputStream, sLine, ((char *)m_sFile + m_nLen) - sLine );
            }
        }
    }

    char *CFontFileType1::GetNextLine(char *sLine)
    {
        while ( sLine < (char *)m_sFile + m_nLen && *sLine != '\x0a' && *sLine != '\x0d')
            ++sLine;

        if ( sLine < (char *)m_sFile + m_nLen && *sLine == '\x0d')
            ++sLine;

        if ( sLine < (char *)m_sFile + m_nLen && *sLine == '\x0a')
            ++sLine;

        if ( sLine >= (char *)m_sFile + m_nLen )
            return NULL;

        return sLine;
    }

    void CFontFileType1::Parse()
    {
        
        Reset();

        while( m_nPos < m_nLen && ( ' ' == m_sFile[m_nPos] || '\t' == m_sFile[m_nPos] || '\r' == m_sFile[m_nPos] || '\n' == m_sFile[m_nPos] ) )
            ++m_nPos;

        bool bSuccess = true;
        int nChar = GetU8( m_nPos, &bSuccess );
        if ( !bSuccess || ( PFB_MARKER != nChar && '%' != nChar ) )
            return;
        else if ( PFB_MARKER == nChar )
        {
            if ( !RemovePfbMarkers() )
                return;
        }

        char *sLine, *sLine1, *pCur, *pTemp;
        char sBuffer[256];
        int nCount, nCode;
        int nIndex = 0;
        unsigned char *sEexec = NULL;

        m_oTopDict.arrdFontBBox[0] = 0; m_oTopDict.arrdFontBBox[1] = 0;
        m_oTopDict.arrdFontBBox[2] = 0; m_oTopDict.arrdFontBBox[3] = 0;

        m_oTopDict.arrdFontMatrix[0] = 0.001; m_oTopDict.arrdFontMatrix[1] = 0;
        m_oTopDict.arrdFontMatrix[2] = 0;     m_oTopDict.arrdFontMatrix[3] = 0.001;
        m_oTopDict.arrdFontMatrix[4] = 0;     m_oTopDict.arrdFontMatrix[5] = 0;

        for (nIndex = 1, sLine = (char *)m_sFile; nIndex <= 100 && sLine && (!m_sName || !m_arrEncoding); ++nIndex )
        {
            if ( !m_sName && !strncmp( sLine, "/FontName", 9) )
            {
                strncpy( sBuffer, sLine, 255);
                sBuffer[255] = '\0';
                if ( ( pCur = strchr( sBuffer + 9, '/' ) ) && ( pCur = strtok( pCur + 1, " \t\n\r" ) ) )
                {
                    m_sName = CopyString( pCur );
                }
                sLine = GetNextLine(sLine);

            }
            else if ( !strncmp( sLine, "/FontMatrix", 11 ) )
            {
                strncpy( sBuffer, sLine, 255);
                sBuffer[255] = '\0';

                ReadDoubleArray<6>( (unsigned char*)(sBuffer + 11), 244, m_oTopDict.arrdFontMatrix );
                sLine = GetNextLine( sLine );
            }
            else if ( !strncmp( sLine, "/FontBBox", 9 ) )
            {
                strncpy( sBuffer, sLine, 255);
                sBuffer[255] = '\0';

                ReadDoubleArray<4>( (unsigned char*)(sBuffer + 9), 246, m_oTopDict.arrdFontBBox );
                sLine = GetNextLine( sLine );
            }
            else if (!m_arrEncoding && !strncmp( sLine, "/Encoding StandardEncoding def", 30))
            {
                m_arrEncoding = c_arrsFontFileType1StandardEncoding;
            }
            else if (!m_arrEncoding && !strncmp( sLine, "/Encoding 256 array", 19))
            {
                m_arrEncoding = (char **)MemUtilsMallocArray(256, sizeof(char *));
                int nJ = 0;
                for (nJ = 0; nJ < 256; ++nJ )
                {
                    m_arrEncoding[nJ] = NULL;
                }
                for (nJ = 0, sLine = GetNextLine(sLine); nJ < 300 && sLine && ( sLine1 = GetNextLine( sLine )); ++nJ, sLine = sLine1)
                {
                    if ( ( nCount = sLine1 - sLine ) > 255 )
                    {
                        nCount = 255;
                    }
                    strncpy( sBuffer, sLine, nCount);
                    sBuffer[ nCount ] = '\0';
                    for ( pCur = sBuffer; *pCur == ' ' || *pCur == '\t'; ++pCur );
                    if ( !strncmp( pCur, "dup", 3 ) )
                    {
                        for ( pCur += 3; *pCur == ' ' || *pCur == '\t'; ++pCur ) ;
                        for ( pTemp = pCur; *pTemp >= '0' && *pTemp <= '9'; ++pTemp ) ;
                        if ( *pTemp )
                        {
                            char nChar = *pTemp;
                            *pTemp = '\0';
                            nCode = atoi( pCur );
							if (nCode < 0) nCode = 0;								
                            *pTemp = nChar;
                            if ( nCode == 8 && *pTemp == '#')
                            {
                                nCode = 0;
                                for (++pTemp; *pTemp >= '0' && *pTemp <= '7'; ++pTemp)
                                {
                                    nCode = nCode * 8 + (*pTemp - '0');
                                }
                            }
                            if ( nCode < 256 )
                            {
                                for ( pCur = pTemp; *pCur == ' ' || *pCur == '\t'; ++pCur ) ;
                                if ( *pCur == '/')
                                {
                                    ++pCur;
                                    for ( pTemp = pCur; *pTemp && *pTemp != ' ' && *pTemp != '\t'; ++pTemp ) ;
                                    *pTemp = '\0';
                                    m_arrEncoding[ nCode ] = CopyString( pCur );
                                }
                            }
                        }
                    }
                    else {
                        if ( strtok( sBuffer, " \t") && ( pCur = strtok(NULL, " \t\n\r")) && !strcmp( pCur, "def"))
                        {
                            break;
                        }
                    }
                }
            }
            else {
                if ( !sEexec )
                    sEexec = (unsigned char*)strstr( sLine, "currentfile eexec" );

                sLine = GetNextLine(sLine);
            }
        }

        if ( NULL != sEexec )
        {
            unsigned char* sTemp = sEexec;
            while ( sTemp != (unsigned char*)strstr( (char*)sTemp, "cleartomark" ) && sTemp < m_sFile + m_nLen )
                sTemp++;

            int nBufferLen = sTemp - ( sEexec + 17 );
            unsigned char *sEexecBuffer = (unsigned char*)MemUtilsMalloc( nBufferLen );
            if ( !sEexecBuffer )
                return;

            memcpy( sEexecBuffer, sEexec + 17, nBufferLen );
            DecryptEexec( &sEexecBuffer, nBufferLen );

            sEexec = sEexecBuffer + 4; 
            int nEexecLen = nBufferLen - 4;

            
            bool bGlyphsSection = false, bSubrsSection = false;
            
            std::wstring sToken, sGlyph;
            int nLength = 0;

            
            m_oPrivateDict.nBlueValues       = 0;
            m_oPrivateDict.nOtherBlues       = 0;
            m_oPrivateDict.nFamilyBlues      = 0;
            m_oPrivateDict.nFamilyOtherBlues = 0;
            m_oPrivateDict.dBlueScale        = 0.039625;
            m_oPrivateDict.nBlueShift        = 7;
            m_oPrivateDict.nBlueFuzz         = 1;
            m_oPrivateDict.bHasStdHW         = false;
            m_oPrivateDict.bHasStdVW         = false;
            m_oPrivateDict.nStemSnapH        = 0;
            m_oPrivateDict.nStemSnapV        = 0;
            m_oPrivateDict.bHasForceBold     = false;
            m_oPrivateDict.nLanguageGroup    = 0;
            m_oPrivateDict.nLenIV            = 4;
            m_oPrivateDict.dExpansionFactor  = 0.06;

            for ( int nIndex = 0; nIndex < nEexecLen; nIndex++ )
            {
                unsigned char nChar = sEexec[nIndex];

                if ( ( bGlyphsSection || bSubrsSection ) && 'R' == nChar && nLength > 0 )
                {
                    unsigned char *sData = new unsigned char[nLength];
                    if ( sData )
                    {
                        memcpy( sData, sEexec + nIndex + 3, nLength );
                        unsigned short unKey = 4330U;
                        unsigned char *sCur = sData;
                        EexecDecode( &sCur, sCur + nLength, sCur, nLength, &unKey );

                        if ( m_oPrivateDict.nLenIV > 0 && m_oPrivateDict.nLenIV < nLength )
                        {
                            Type1Charstring oCharstring = DecodeCharString( sData + m_oPrivateDict.nLenIV, nLength - m_oPrivateDict.nLenIV );
                            if ( bGlyphsSection )
                            {
                                int nUnicode = Type1NameToUnicodeW( sGlyph.c_str() );

                                if ( 0 != nUnicode )
                                    m_arrCharstrings.Add( Type1Glyph( sGlyph, nUnicode, oCharstring )  );
                            }
                            else  {
                                m_arrSubrs.Add( oCharstring );
                            }
                        }

                        delete []sData;
                    }

                    nIndex += nLength + 3;
                }
                else if ( IS_PS_SPACE( nChar ) )
                {
                    nLength = Utils::GetInteger( sToken );
                    sToken.clear();
                }
                else {
                    sToken.push_back( (wchar_t)nChar );
                    if ( !bGlyphsSection && '/' == sToken[0] )
                    {
                        int nTempChar = sToken[1];
                        switch (nTempChar)
                        {
                        case 'B':
                            {
                                if ( L"/BlueValues" == sToken )
                                    m_oPrivateDict.nBlueValues = ReadIntArray<type1MaxBlueValues>( sEexec + nIndex + 2, nEexecLen - nIndex - 2, m_oPrivateDict.arrnBlueValues );
                                else if ( L"/BlueScale" == sToken )
                                    m_oPrivateDict.dBlueScale  = ReadDouble( sEexec + nIndex + 1, nEexecLen - nIndex - 1 );
                                else if ( L"/BlueShift" == sToken )
                                    m_oPrivateDict.nBlueShift  = ReadInt( sEexec + nIndex + 1, nEexecLen - nIndex - 1 );
                                else if ( L"/BlueFuzz" == sToken )
                                    m_oPrivateDict.nBlueFuzz   = ReadInt( sEexec + nIndex + 1, nEexecLen - nIndex - 1 );

                                break;
                            }
                        case 'C':
                            {
                                if ( L"/CharString" == sToken )
                                    bGlyphsSection = true;

                                break;
                            }
                        case 'E':
                            {
                                if ( L"/ExpansionFactor" == sToken )
                                    m_oPrivateDict.dExpansionFactor = ReadDouble( sEexec + nIndex + 1, nEexecLen - nIndex - 1 );

                                break;
                            }
                        case 'F':
                            {
                                if ( L"/FamilyBlues" == sToken )
                                    m_oPrivateDict.nFamilyBlues = ReadIntArray<type1MaxBlueValues>( sEexec + nIndex + 2, nEexecLen - nIndex - 2, m_oPrivateDict.arrnFamilyBlues );
                                else if ( L"/FamilyOtherBlues" == sToken )
                                    m_oPrivateDict.nFamilyOtherBlues = ReadIntArray<type1MaxOtherBlues>( sEexec + nIndex + 2, nEexecLen - nIndex - 2, m_oPrivateDict.arrnFamilyOtherBlues );
                                else if ( L"/ForceBold" == sToken )
                                {
                                    m_oPrivateDict.bHasForceBold = true;
                                    m_oPrivateDict.bForceBold = ReadBool( sEexec + nIndex + 1, nEexecLen - nIndex - 1 );
                                }

                                break;
                            }
                        case 'L':
                            {
                                if ( L"/LanguageGroup" == sToken )
                                    m_oPrivateDict.nLanguageGroup = ReadInt( sEexec + nIndex + 1, nEexecLen - nIndex - 1 );
                                else if ( L"/lenIV" == sToken )
                                    m_oPrivateDict.nLenIV = ReadInt( sEexec + nIndex + 1, nEexecLen - nIndex - 1 );

                                break;
                            }
                        case 'S':
                            {
                                if ( L"/Subrs" == sToken )
                                    bSubrsSection = true;
                                else if ( L"/StemSnapH" == sToken )
                                    m_oPrivateDict.nStemSnapH = ReadDoubleArray<type1MaxStemSnap>( sEexec + nIndex + 2, nEexecLen - nIndex - 2, m_oPrivateDict.arrdStemSnapH );
                                else if ( L"/StemSnapV" == sToken )
                                    m_oPrivateDict.nStemSnapV = ReadDoubleArray<type1MaxStemSnap>( sEexec + nIndex + 2, nEexecLen - nIndex - 2, m_oPrivateDict.arrdStemSnapV );
                                else if ( L"/StdHW" == sToken )
                                {
                                    
                                    double dTemp[1];

                                    if ( ReadDoubleArray<1>( sEexec + nIndex + 2, nEexecLen - nIndex - 2, dTemp ) > 0 )
                                    {
                                        m_oPrivateDict.bHasStdHW = true;
                                        m_oPrivateDict.dStdHW = dTemp[0];
                                    }
                                }
                                else if ( L"/StdVW" == sToken )
                                {
                                    
                                    double dTemp[1];
                                    if ( ReadDoubleArray<1>( sEexec + nIndex + 2, nEexecLen - nIndex - 2, dTemp ) > 0 )
                                    {
                                        m_oPrivateDict.bHasStdHW = true;
                                        m_oPrivateDict.dStdVW = dTemp[0];
                                    }
                                }
                            }
                        }
                    }
                    else if ( '/' == nChar  )
                    {
                        sToken.clear();
                        sGlyph.clear();

                        while ( nIndex < nEexecLen && ( nChar = sEexec[++nIndex] ) != ' ' )
                            sGlyph.push_back( (wchar_t)nChar );
                    }
                }
            }
            MemUtilsFree( sEexecBuffer );

            
            qsort( m_arrCharstrings.GetData(), m_arrCharstrings.GetSize(), sizeof(Type1Glyph), CompareType1Glyph );
        }

        m_bParsed = true;
    }

    void CFontFileType1::DecryptEexec(unsigned char** ppEexecBuffer, int nLen)
    {
        
        
        unsigned char *sCur = (unsigned char*)(*ppEexecBuffer);
        while( sCur < (unsigned char*)(*ppEexecBuffer) + nLen && ( ' ' == *sCur || '\t' == *sCur || '\r' == *sCur || '\n' == *sCur ) )
            ++sCur;

        
        
        bool bASCII = false;

        if ( isxdigit( sCur[0] ) && isxdigit( sCur[1] ) && isxdigit( sCur[2] ) && isxdigit( sCur[3] ) )
            bASCII = true;

        if ( bASCII )
            ASCIIHexDecode( &sCur, sCur + nLen, sCur, nLen );

        unsigned short ushKey = 55665U;
        EexecDecode( &sCur, *ppEexecBuffer + nLen, sCur, nLen, &ushKey );
    }
    bool CFontFileType1::RemovePfbMarkers()
    {
        bool bSuccess = true;

        int nBlockType = 0;
        int nBlockLen  = 0;
        int nChar = 0;

        unsigned char *sBuffer = NULL;
        unsigned int nBufLen = 0;

        while ( nBlockType != PFB_DONE )
        {
            while ( 0 == nBlockLen )
            {
                nChar = ReadU8( &bSuccess );
                if ( !bSuccess )
                    return false;

                nBlockType = ReadU8( &bSuccess );
                if ( !bSuccess || PFB_MARKER != nChar || ( PFB_ASCII != nBlockType && PFB_BINARY != nBlockType && PFB_DONE != nBlockType ) )
                    return false;

                if ( PFB_DONE == nBlockType )
                    break;

                nBlockLen = ReadU32LE( &bSuccess );
                if ( !bSuccess )
                    return false;
            }

            
            if ( nBlockLen > 0 )
            {
                if ( !sBuffer )
                {
                    sBuffer = (unsigned char*)MemUtilsMalloc( nBlockLen );
                    if ( !sBuffer )
                        return false;
                }
                else sBuffer = (unsigned char*)MemUtilsRealloc( sBuffer, nBufLen + nBlockLen );

                Read( sBuffer + nBufLen, nBlockLen );
                nBufLen += nBlockLen;
            }
            nBlockLen = 0;
        }

        if ( m_bFreeFileData )
            MemUtilsFree( m_sFile );

        m_bFreeFileData = true;
        m_sFile         = (unsigned char*)sBuffer;
        m_sFileData     = m_sFile;
        m_nLen          = nBufLen;
        m_nPos          = 0;

        return true;
    }

    Type1Charstring CFontFileType1::DecodeCharString(unsigned char *sString, int nLen)
    {
        CArray<Type1CharstringItem> sCharString;

        int nLSB = 0, nWidth = 0;

        for ( int nIndex = 0; nIndex < nLen; nIndex++ )
        {
            int nValue = sString[nIndex];

            if ( nValue < 32 ) 
            {
                int nCommand = 0;

                if ( 12 == nValue )
                {
                    int nNextValue = sString[++nIndex];

                    if ( 16 == nNextValue )
                    {
                        if ( sCharString.GetSize() <= 0 )
                            continue;

                        int nInd = sCharString[sCharString.GetSize() - 1].nValue;
                        sCharString.RemoveAt( sCharString.GetSize() - 1 );

                        while ( sCharString.GetSize() > 0 && false == sCharString[sCharString.GetSize() - 1].bCommand )
                            sCharString.RemoveAt( sCharString.GetSize() - 1 );

                        
                        
                        
                        if ( nInd < 3 )
                            continue;

                        
                        
                        if ( 3 == nInd )
                        {
                            sCharString.Add( Type1CharstringItem( 3, true ) );
                            nIndex++;
                            continue;
                        }
                    }

                    nCommand = 12 + ( nNextValue << 8 );
                }
                else {
                    if ( 13 == nValue )
                    {
                        if ( 2 == sCharString.GetSize() )
                            nWidth = sCharString[1].nValue;
                        else if ( 4 == sCharString.GetSize() && 0x0C0C == sCharString[3].nValue && sCharString[3].bCommand )
                            nWidth = sCharString[1].nValue / sCharString[2].nValue;
                        else {
                            
                            nWidth = 0;
                        }

                        if ( sCharString.GetSize() > 0 )
                        {
                            nLSB = sCharString[0].nValue;
                            sCharString.Add( Type1CharstringItem( nLSB, false ) );
                            sCharString.Add( Type1CharstringItem( c_nType1hmoveto, true ) );
                            sCharString.RemoveAt( 0 );
                        }
                        else {
                            nLSB = 0;
                            sCharString.Add( Type1CharstringItem( nLSB, false ) );
                            sCharString.Add( Type1CharstringItem( c_nType1hmoveto, true ) );
                        }

                        continue;
                    }

                    nCommand = nValue;
                }

                
                
                if ( !nCommand && nIndex < nLen )
                    continue;
                else if ( !nCommand )
                    break;
                else if ( c_nType1seac == nCommand || c_nType1sbw == nCommand )
                {
                    
                }

                sCharString.Add( Type1CharstringItem( nCommand, true ) );
            }
            else {
                if ( nValue <= 246 )
                    nValue = nValue - 139;
                else if ( nValue <= 250 )
                    nValue =  ( ( nValue - 247 ) * 256 ) + (int)( sString[++nIndex] ) + 108;
                else if ( nValue <= 254 )
                    nValue = -( ( nValue - 251 ) * 256 ) - (int)( sString[++nIndex] ) - 108;
                else nValue = ( sString[++nIndex] & 0xff ) << 24 | ( sString[++nIndex] & 0xff ) << 16 | ( sString[++nIndex] & 0xff ) << 8 | ( sString[++nIndex] & 0xff ) << 0;

                sCharString.Add( Type1CharstringItem( nValue, false ) );
            }
        }

        return Type1Charstring( sCharString, nWidth, nLSB );
    }
    Type1Charstring CFontFileType1::FlattenCharstring(Type1Charstring& oCharstring, int nBias)
    {
        Type1Charstring oNew;
        oNew.nLSB   = oCharstring.nLSB;
        oNew.nWidth = oCharstring.nWidth;

        for ( int nIndex = 0; nIndex < oCharstring.arrCharstring.GetSize(); nIndex++ )
        {
            Type1CharstringItem oItem = oCharstring.arrCharstring[nIndex];
            int nValue = oItem.nValue;
            if ( oItem.bCommand )
            {
                if ( nValue == c_nType1sub )
                {
                    oNew.arrCharstring.Add( Type1CharstringItem( 12, true ) );
                    oNew.arrCharstring.Add( Type1CharstringItem( 11, true ) );
                }
                else if ( nValue == c_nType1div )
                {
                    oNew.arrCharstring.Add( Type1CharstringItem( 12, true ) );
                    oNew.arrCharstring.Add( Type1CharstringItem( 12, true ) );
                }
                else if ( nValue == c_nType1pop )
                {
                    
                    oNew.arrCharstring.Add( Type1CharstringItem( 12, true ) );
                    oNew.arrCharstring.Add( Type1CharstringItem( 18, true ) );
                }
                else if ( nValue == c_nType1callsubr  )
                {
                    
                    
                    
                    

                    
                    
                    
                    
                    
                    

                    
                    
                    
                    
                    
                    

                    
                    
                    
                    
                    
                    
                    

                    
                    
                    
                    
                    
                    oNew.arrCharstring.Add( Type1CharstringItem( oItem.nValue, true ) );
                }
                else oNew.arrCharstring.Add( Type1CharstringItem( oItem.nValue, true ) );
            }
            else {
                
                if ( oItem.nValue > 32000 )
                {
                    int nDivisor = oCharstring.arrCharstring[nIndex + 1].nValue;
                    if ( 0 != nDivisor )
                        nValue /= nDivisor;
                }
                oNew.arrCharstring.Add( Type1CharstringItem( 28, true ) );
                oNew.arrCharstring.Add( Type1CharstringItem( nValue >> 8, false ) );
                oNew.arrCharstring.Add( Type1CharstringItem( nValue & 0xFF, false ) );
            }
        }

        return oNew;
    }
    void CFontFileType1::CFFCreateIndexHeader(FontFileOutputFunc pOutputFunc, void *pOutputStream, CArray<std::wstring> aObjects)
    {
        char nChar;
        int nCount = aObjects.GetSize();
        if ( 0 == nCount )
        {
            pOutputFunc( pOutputStream, "\x00\x00\x00", 3 );
            return;
        }

        
        WriteChar( nCount >> 8 );
        WriteChar( nCount & 0xFF );
        
        WriteChar( 0x04 );

        int nRelativeOffset = 1;
        for ( int nIndex = 0; nIndex < nCount + 1; nIndex++ )
        {
            WriteChar( (nRelativeOffset >> 24) & 0xFF );
            WriteChar( (nRelativeOffset >> 16) & 0xFF );
            WriteChar( (nRelativeOffset >>  8) & 0xFF );
            WriteChar( (nRelativeOffset)       & 0xFF );

            if ( nIndex < nCount )
                nRelativeOffset += aObjects[nIndex].length();
        }

        for ( int nIndex = 0; nIndex < nCount; nIndex++ )
        {
            std::string sCur = U_TO_UTF8((aObjects[nIndex]));
            pOutputFunc( pOutputStream, sCur.c_str(), sCur.length() );
        }
    }
    void CFontFileType1::CFFCreateIndexHeader(FontFileOutputFunc pOutputFunc, void *pOutputStream, CArray<Type1Charstring> aObjects)
    {
        char nChar;
        int nCount = aObjects.GetSize();
        if ( 0 == nCount )
        {
            pOutputFunc( pOutputStream, "\x00\x00\x00", 3 );
            return;
        }

        
        WriteChar( nCount >> 8 );
        WriteChar( nCount & 0xFF );
        
        WriteChar( 0x04 );

        int nRelativeOffset = 1;
        for ( int nIndex = 0; nIndex < nCount + 1; nIndex++ )
        {
            WriteChar( (nRelativeOffset >> 24) & 0xFF );
            WriteChar( (nRelativeOffset >> 16) & 0xFF );
            WriteChar( (nRelativeOffset >>  8) & 0xFF );
            WriteChar( (nRelativeOffset)       & 0xFF );

            if ( nIndex < nCount )
                nRelativeOffset += aObjects[nIndex].arrCharstring.GetSize();
        }

        for ( int nI = 0; nI < nCount; nI++ )
        {
            for ( int nJ = 0; nJ < aObjects[nI].arrCharstring.GetSize(); nJ++ )
            {
                WriteChar( aObjects[nI].arrCharstring[nJ].nValue & 0xFF );
            }
        }
    }
    void CFontFileType1::CFFEncodeNumber(FontFileOutputFunc pOutputFunc, void *pOutputStream, int nValue, bool bForceLong)
    {
        char nChar;
        if ( !bForceLong && nValue >= -32768 && nValue <= 32767 )
        {
            WriteChar( 0x1c );
            WriteChar( ( nValue >> 8 ) & 0xFF );
            WriteChar( nValue & 0xFF );
        }
        else  {
            WriteChar( 0x1d );
            WriteChar( ( nValue >> 24 ) & 0xFF );
            WriteChar( ( nValue >> 16 ) & 0xFF );
            WriteChar( ( nValue >>  8 ) & 0xFF );
            WriteChar( nValue & 0xFF );
        }
    }
    void CFontFileType1::CFFEncodeNumber(FontFileOutputFunc pOutputFunc, void *pOutputStream, double dValue)
    {
        char nChar = 0;

        WriteChar( 0x1e ); 

        std::wstring sValue = std::to_wstring(dValue);
        bool bFirstNibble = true;
        for ( int nIndex = 0; nIndex < sValue.length(); nIndex++ )
        {
            int nCurChar = sValue.c_str()[ nIndex ];
            if ( '0' <= nCurChar && nCurChar <= '9' )
                nCurChar -= (int)('0');
            else if ( '.' == nCurChar )
                nCurChar = 0x0a;
            else if ( '-' == nCurChar )
                nCurChar = 0x0e;
            else continue;

            if ( bFirstNibble )
                nChar = nCurChar << 4;
            else {
                nChar += nCurChar;
                WriteChar( nChar );
            }

            bFirstNibble = !bFirstNibble;
        }

        
        if ( bFirstNibble )
            nChar = (char)0xff;
        else nChar += 0x0f;

        WriteChar( nChar );
    }
    void CFontFileType1::ToCFF(FontFileOutputFunc pOutputFunc, void *pOutputStream)
    {
        std::wstring sFontName = NSFile::CUtf8Converter::GetUnicodeFromCharPtr( m_sName, (LONG)strlen(m_sName) );
        CArray<std::wstring> aString;

        int nBias = 0;
        int nSubrsLen = m_arrSubrs.GetSize();
        if ( nSubrsLen < 1240 )
            nBias = 107;
        else if ( nSubrsLen < 33900 )
            nBias = 1131;
        else nBias = 32768;

        CArray<Type1Charstring> arrType2Charstrings;
        Type1Charstring oFirstCharstring;
        oFirstCharstring.arrCharstring.Add( Type1CharstringItem( 0x8B, false ) );
        oFirstCharstring.arrCharstring.Add( Type1CharstringItem( 0x0E, false ) );
        arrType2Charstrings.Add( oFirstCharstring );
        for ( int nIndex = 0; nIndex < m_arrCharstrings.GetSize(); nIndex++ )
        {
            std::wstring sG = m_arrCharstrings[nIndex].sGlyph;
            if ( L"afii10090" == sG )
                int k = 10;
            arrType2Charstrings.Add( FlattenCharstring( m_arrCharstrings[nIndex].oData, nBias ) );
        }

        CArray<Type1Charstring> arrType2Subrs;

        
        
        
        
        

        for ( int nIndex = 0; nIndex < nSubrsLen; nIndex++ )
        {
            
            
            
            
            
            
            
            arrType2Subrs.Add( FlattenCharstring( m_arrSubrs[nIndex], 0 ) );
        }

        
        TCharBuffer oHeader;
        oHeader.Write( "\x01\x00\x04\x04", 4 );

        
        TCharBuffer oName;
        aString.RemoveAll();
        aString.Add( sFontName );
        CFFCreateIndexHeader( CharBufferWrite, &oName, aString );

        
        TCharBuffer oStrings;
        aString.RemoveAll();
        int nNewSID = CFF_STANDARD_STRINGS_COUNT;
        aString.Add( L"Version 0.11" );        nNewSID++; 
        aString.Add( L"See original notice" ); nNewSID++; 
        aString.Add( sFontName );                 nNewSID++; 
        aString.Add( sFontName );                 nNewSID++; 
        aString.Add( L"Medium" );              nNewSID++; 

        for ( int nIndex = 0; nIndex < m_arrCharstrings.GetSize(); nIndex++ )
        {
            int nSID = GetCFFStringIndex( m_arrCharstrings[nIndex].sGlyph.c_str() );
            if ( nSID < 0 )
            {
                aString.Add( m_arrCharstrings[nIndex].sGlyph );
                nSID = nNewSID;
                nNewSID++;
            }

            m_arrCharstrings[nIndex].nReserved = nSID;
        }

        CFFCreateIndexHeader( CharBufferWrite, &oStrings, aString );

        
        TCharBuffer oGlobalSubrs;
        aString.RemoveAll(); 
        CFFCreateIndexHeader( CharBufferWrite, &oGlobalSubrs, aString );

        
        TCharBuffer oCharset;
        oCharset.Write( (char)0x00 ); 

        int nGlyphsCount = m_arrCharstrings.GetSize();
        for ( int nIndex = 0; nIndex < nGlyphsCount; nIndex++ )
        {
            int nSID = m_arrCharstrings[nIndex].nReserved;
            oCharset.Write( (char)(nSID >> 8) );
            oCharset.Write( (char)(nSID & 0xFF) );
        }

        
        TCharBuffer oCharstrings;
        CFFCreateIndexHeader( NSFontConverter::CharBufferWrite, &oCharstrings, arrType2Charstrings );

        
        TCharBuffer oPrivate;
        oPrivate.Write( "\x8b\x14", 2 ); 
        oPrivate.Write( "\x8b\x15", 2 ); 

        
        if ( m_oPrivateDict.nBlueValues > 0 )
        {
            CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrnBlueValues[0] );
            for ( int nIndex = 1; nIndex < m_oPrivateDict.nBlueValues; nIndex++ )
                CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrnBlueValues[nIndex] - m_oPrivateDict.arrnBlueValues[nIndex - 1] );

            oPrivate.Write( (char)0x06 );
        }

        
        if ( m_oPrivateDict.nOtherBlues > 0 )
        {
            CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrnOtherBlues[0] );
            for ( int nIndex = 1; nIndex < m_oPrivateDict.nOtherBlues; nIndex++ )
                CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrnOtherBlues[nIndex] - m_oPrivateDict.arrnOtherBlues[nIndex - 1] );

            oPrivate.Write( (char)0x07 );
        }

        
        if ( m_oPrivateDict.nFamilyBlues > 0 )
        {
            CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrnFamilyBlues[0] );
            for ( int nIndex = 1; nIndex < m_oPrivateDict.nFamilyBlues; nIndex++ )
                CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrnFamilyBlues[nIndex] - m_oPrivateDict.arrnFamilyBlues[nIndex - 1] );

            oPrivate.Write( (char)0x08 );
        }

        
        if ( m_oPrivateDict.nFamilyOtherBlues > 0 )
        {
            CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrnFamilyOtherBlues[0] );
            for ( int nIndex = 1; nIndex < m_oPrivateDict.nFamilyOtherBlues; nIndex++ )
                CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrnFamilyOtherBlues[nIndex] - m_oPrivateDict.arrnFamilyOtherBlues[nIndex - 1] );

            oPrivate.Write( (char)0x09 );
        }

        
        if ( m_oPrivateDict.nStemSnapH > 0 )
        {
            CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrdStemSnapH[0] );
            for ( int nIndex = 1; nIndex < m_oPrivateDict.nStemSnapH; nIndex++ )
                CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrdStemSnapH[nIndex] - m_oPrivateDict.arrdStemSnapH[nIndex - 1] );

            oPrivate.Write( "\x0c\x0c" , 2);
        }

        
        if ( m_oPrivateDict.nStemSnapV > 0 )
        {
            CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrdStemSnapV[0] );
            for ( int nIndex = 1; nIndex < m_oPrivateDict.nStemSnapV; nIndex++ )
                CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.arrdStemSnapV[nIndex] - m_oPrivateDict.arrdStemSnapV[nIndex - 1] );

            oPrivate.Write( "\x0c\x0d" , 2);
        }

        
        CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.nBlueShift );
        oPrivate.Write( "\x0c\x0a", 2 );

        
        CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.nBlueFuzz );
        oPrivate.Write( "\x0c\x0b", 2 );

        
        CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.dBlueScale );
        oPrivate.Write( "\x0c\x09", 2 );

        
        CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.nLanguageGroup );
        oPrivate.Write( "\x0c\x11", 2 );

        
        CFFEncodeNumber( CharBufferWrite, &oPrivate, m_oPrivateDict.dExpansionFactor );
        oPrivate.Write( "\x0c\x18", 2 );

        
        int nPrivateLen = oPrivate.nLen + (5 + 1);
        CFFEncodeNumber( CharBufferWrite, &oPrivate, nPrivateLen, true );
        oPrivate.Write( "\x13", 1 );

        
        TCharBuffer oLocalSubrs;
        CFFCreateIndexHeader( CharBufferWrite, &oLocalSubrs, arrType2Subrs );

        
        TCharBuffer oTopDict;
        oTopDict.Write( "\x00\x01\x04\x00\x00\x00\x01\x00\x00\0x00\x00", 11 );
        oTopDict.Write( "\xf8\x1b\x00", 3 ); 
        oTopDict.Write( "\xf8\x1c\x01", 3 ); 
        oTopDict.Write( "\xf8\x1d\x02", 3 ); 
        oTopDict.Write( "\xf8\x1e\x03", 3 ); 
        oTopDict.Write( "\xf8\x1f\x04", 3 ); 
        oTopDict.Write( "\x1c\x00\x00\x10", 4 ); 

        
        CFFEncodeNumber( CharBufferWrite, &oTopDict, m_oTopDict.arrdFontBBox[0] );
        CFFEncodeNumber( CharBufferWrite, &oTopDict, m_oTopDict.arrdFontBBox[1] );
        CFFEncodeNumber( CharBufferWrite, &oTopDict, m_oTopDict.arrdFontBBox[2] );
        CFFEncodeNumber( CharBufferWrite, &oTopDict, m_oTopDict.arrdFontBBox[3] );
        oTopDict.Write( "\x05", 1 );

        
        
        int nTopDictLen = oTopDict.nLen + ( 4 * 5 + 3);

        int nOffset = oHeader.nLen + oName.nLen + nTopDictLen + oStrings.nLen + oGlobalSubrs.nLen;
        CFFEncodeNumber( CharBufferWrite, &oTopDict, nOffset, true );
        oTopDict.Write( "\x0f", 1 ); 

        nOffset += oCharset.nLen;
        CFFEncodeNumber( CharBufferWrite, &oTopDict, nOffset, true );
        oTopDict.Write( "\x11", 1 ); 

        CFFEncodeNumber( CharBufferWrite, &oTopDict, oPrivate.nLen, true );
        nOffset += oCharstrings.nLen;
        CFFEncodeNumber( CharBufferWrite, &oTopDict, nOffset, true );
        oTopDict.Write( "\x12", 1 ); 

        
        int nTopDictDataLen = nTopDictLen - 10;
        oTopDict.sBuffer[7]  = ( nTopDictDataLen >> 24 ) & 0xFF;
        oTopDict.sBuffer[8]  = ( nTopDictDataLen >> 16 ) & 0xFF;
        oTopDict.sBuffer[9]  = ( nTopDictDataLen >> 8  ) & 0xFF;
        oTopDict.sBuffer[10] = nTopDictDataLen & 0xFF;

        
        pOutputFunc( pOutputStream, oHeader.sBuffer,      oHeader.nLen      );
        pOutputFunc( pOutputStream, oName.sBuffer,        oName.nLen        );
        pOutputFunc( pOutputStream, oTopDict.sBuffer,     oTopDict.nLen     );
        pOutputFunc( pOutputStream, oStrings.sBuffer,     oStrings.nLen     );
        pOutputFunc( pOutputStream, oGlobalSubrs.sBuffer, oGlobalSubrs.nLen );
        pOutputFunc( pOutputStream, oCharset.sBuffer,     oCharset.nLen     );
        pOutputFunc( pOutputStream, oCharstrings.sBuffer, oCharstrings.nLen );
        pOutputFunc( pOutputStream, oPrivate.sBuffer,     oPrivate.nLen     );
        pOutputFunc( pOutputStream, oLocalSubrs.sBuffer,  oLocalSubrs.nLen  );
    }
}
