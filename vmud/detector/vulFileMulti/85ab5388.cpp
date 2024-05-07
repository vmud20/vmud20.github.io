









using namespace std;
using namespace PoDoFo;

static string generateXRefEntries(size_t count);
static bool canOutOfMemoryKillUnitTests();
static void testReadXRefSubsection();
static size_t getStackOverflowDepth();




constexpr unsigned maxNumberOfIndirectObjects = 8388607;

namespace PoDoFo {
    class PdfParserTest : public PdfParser {
    public:
        PdfParserTest(PdfIndirectObjectList& objectList, string buff)
            : PdfParser(objectList), m_buffer(std::move(buff)), m_device(new SpanStreamDevice(m_buffer))
        {
        }

        void ReadXRefContents(size_t offset, bool positionAtEnd)
        {
            
            PdfParser::ReadXRefContents(*m_device, offset, positionAtEnd);
        }

        void ReadXRefSubsection(int64_t firstObject, int64_t objectCount)
        {
            
            PdfParser::ReadXRefSubsection(*m_device, firstObject, objectCount);
        }

        void ReadXRefStreamContents(size_t offset, bool readOnlyTrailer)
        {
            
            PdfParser::ReadXRefStreamContents(*m_device, offset, readOnlyTrailer);
        }

        void ReadDocumentStructure()
        {
            
            PdfParser::ReadDocumentStructure(*m_device);
        }

        void ReadObjects()
        {
            
            PdfParser::ReadObjects(*m_device);
        }

        bool IsPdfFile()
        {
            
            return PdfParser::IsPdfFile(*m_device);
        }

        const shared_ptr<InputStreamDevice>& GetDevice() { return m_device; }

    private:
        string m_buffer;
        shared_ptr<InputStreamDevice> m_device;
    };
}

TEST_CASE("TestMaxObjectCount")
{
    PdfParser::SetMaxObjectCount(numeric_limits<unsigned short>::max());
    testReadXRefSubsection();

    PdfParser::SetMaxObjectCount(maxNumberOfIndirectObjects);
    testReadXRefSubsection();
}


TEST_CASE("TestMaxObjectCount2", "[.]")
{
    PdfParser::SetMaxObjectCount(numeric_limits<unsigned>::max());
    testReadXRefSubsection();
}


TEST_CASE("TestReadXRefContents")
{
    try {
        
        
        
        
        
        
        
        
        
        
        ostringstream oss;
        oss << "xref\r\n0 3\r\n";
        oss << generateXRefEntries(3);
        oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
        oss << "startxref 0\r\n";
        oss << "%EOF";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, oss.str());
        parser.ReadXRefContents(0, false);
        
    }
    catch (PdfError&)
    {
        FAIL("Should not throw PdfError");
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    try {
        
        
        
        
        
        
        
        
        
        
        ostringstream oss;
        oss << "xref\r\n0 3\r\n";
        oss << generateXRefEntries(2); 
        oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
        oss << "startxref 0\r\n";
        oss << "%EOF";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, oss.str());
        parser.ReadXRefContents(0, false);
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    try {
        
        
        
        
        
        
        
        
        
        
        
        
        
        ostringstream oss;
        oss << "xref\r\n0 5\r\n";
        oss << "000000000 65535\r\n";
        oss << "00000000065535 x\r\n";
        oss << "0000000\r\n";
        oss << generateXRefEntries(2);
        oss << "trailer << /Root 1 0 R /Size 5 >>\r\n";
        oss << "startxref 0\r\n";
        oss << "%EOF";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, oss.str());
        parser.ReadXRefContents(0, false);
        
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    

    try {
        
        
        
        
        
        
        
        
        
        
        
        ostringstream oss;

        
        string streamContents = "01 0E8A 0\r\n" "02 0002 00\r\n";

        size_t streamContentsLength = streamContents.size() - strlen("\r\n");

        
        
        oss << "xref\r\n0 1\r\n";
        oss << generateXRefEntries(1);

        
        
        
        size_t offsetXrefStm1Whitespace = oss.str().length();
        oss << "    \r\n";
        oss << "% comments and leading white space are ignored - see PdfTokenizer::GetNextToken\r\n";
        size_t offsetXrefStm1 = oss.str().length();
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << streamContentsLength << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 3 ";
        oss << "/Prev " << offsetXrefStm1Whitespace << " ";     
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        oss << streamContents;
        oss << "endstream\r\n";
        oss << "endobj\r\n";

        oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
        oss << "startxref " << offsetXrefStm1 << "\r\n";
        oss << "%EOF";

        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, oss.str());
        parser.ReadXRefContents(offsetXrefStm1, false);
        
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRefType);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    try {
        
        
        
        
        
        
        
        
        
        
        
        ostringstream oss;

        
        string streamContents = "01 0E8A 0\r\n" "02 0002 00\r\n";

        size_t streamContentsLength = streamContents.size() - strlen("\r\n");

        
        
        oss << "xref\r\n0 1\r\n";
        oss << generateXRefEntries(1);

        
        size_t offsetXrefStm1 = oss.str().length();
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << streamContentsLength << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 3 ";
        oss << "/Prev 185 ";     
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        oss << streamContents;
        oss << "endstream\r\n";
        oss << "endobj\r\n";

        
        size_t offsetXrefStm2 = oss.str().length();
        REQUIRE(offsetXrefStm2 == 185); 
        oss << "3 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << streamContentsLength << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 3 ";
        oss << "/Prev " << offsetXrefStm1 << " ";     
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        oss << streamContents;
        oss << "endstream\r\n";
        oss << "endobj\r\n";

        oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
        oss << "startxref " << offsetXrefStm2 << "\r\n";
        oss << "%EOF";

        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, oss.str());
        parser.ReadXRefContents(offsetXrefStm2, false);
        
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRefType);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    try {
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        ostringstream oss;
        size_t prevOffset = 0;
        size_t currentOffset = 0;

        
        string streamContents = "01 0E8A 0\r\n" "02 0002 00\r\n";

        size_t streamContentsLength = streamContents.size() - strlen("\r\n");

        
        
        oss << "xref\r\n0 1\r\n";
        oss << generateXRefEntries(1);

        
        

        constexpr size_t maxXrefStreams = 10000;
        for (size_t i = 0; i < maxXrefStreams; i++)
        {
            size_t objNo = i + 2;

            
            prevOffset = currentOffset;
            currentOffset = oss.str().length();
            oss << objNo << " 0 obj ";
            oss << "<< /Type /XRef ";
            oss << "/Length " << streamContentsLength << " ";
            oss << "/Index [2 2] ";
            oss << "/Size 3 ";
            if (prevOffset > 0)
                oss << "/Prev " << prevOffset << " ";
            oss << "/W [1 2 1] ";
            oss << "/Filter /ASCIIHexDecode ";
            oss << ">>\r\n";
            oss << "stream\r\n";
            oss << streamContents;
            oss << "endstream\r\n";
            oss << "endobj\r\n";
        }

        oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
        oss << "startxref " << currentOffset << "\r\n";
        oss << "%EOF";

        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, oss.str());
        parser.ReadXRefContents(currentOffset, false);
        
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRefType);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }
}

void testReadXRefSubsection()
{
    int64_t firstObject = 0;
    int64_t objectCount = 0;

    

    
    
    
    
    
    
    

    
    
    

    if (PdfParser::GetMaxObjectCount() <= maxNumberOfIndirectObjects)
    {
        try {
            string strInput = generateXRefEntries(PdfParser::GetMaxObjectCount());
            PdfIndirectObjectList objects;
            PdfParserTest parser(objects, strInput);
            firstObject = 0;
            objectCount = PdfParser::GetMaxObjectCount();
            parser.ReadXRefSubsection(firstObject, objectCount);
            
        }
        catch (PdfError&)
        {
            FAIL("should not throw PdfError");
        }
        catch (exception&)
        {
            FAIL("Unexpected exception type");
        }
    }
    else {
        
        
    }

    
    
    if (PdfParser::GetMaxObjectCount() < numeric_limits<unsigned>::max())
    {
        
        unsigned numXRefEntries = std::min(maxNumberOfIndirectObjects + 1, PdfParser::GetMaxObjectCount() + 1);

        try {
            string strInput = generateXRefEntries(numXRefEntries);
            PdfIndirectObjectList objects;
            PdfParserTest parser(objects, strInput);
            firstObject = 0;
            objectCount = (int64_t)PdfParser::GetMaxObjectCount() + 1;
            parser.ReadXRefSubsection(firstObject, objectCount);
            FAIL("PdfError not thrown");
        }
        catch (PdfError& error)
        {
            
            
            REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
        }
        catch (exception&)
        {
            FAIL("Wrong exception type");
        }
    }

    
    
    try {
        
        
        
        
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = 1;
        objectCount = numeric_limits<size_t>::max() / 2 - 1;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        
        
        REQUIRE((error.GetCode() == PdfErrorCode::InvalidXRef || error.GetCode() == PdfErrorCode::ValueOutOfRange || error.GetCode() == PdfErrorCode::OutOfMemory));

    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    if (!canOutOfMemoryKillUnitTests())
    {
        constexpr size_t maxObjects = numeric_limits<size_t>::max() / sizeof(PdfXRefEntry) / 100 * 95;

        try {
            string strInput = " ";
            PdfIndirectObjectList objects;
            PdfParserTest parser(objects, strInput);
            firstObject = 1;
            objectCount = maxObjects;
            parser.ReadXRefSubsection(firstObject, objectCount);
            FAIL("PdfError not thrown");
        }
        catch (PdfError& error)
        {
            if (maxObjects >= (size_t)PdfParser::GetMaxObjectCount())
                REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
            else REQUIRE(error.GetCode() == PdfErrorCode::OutOfMemory);
        }
        catch (exception&)
        {
            FAIL("Wrong exception type");
        }
    }

    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    

    try {
        string strInput = "0000000000 65535 f\r\n";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = -5LL;
        objectCount = 5;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE((error.GetCode() == PdfErrorCode::ValueOutOfRange || error.GetCode() == PdfErrorCode::NoXRef));
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    

    try {
        string strInput = "0000000000 65535 f\r\n";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = numeric_limits<unsigned>::max();
        objectCount = numeric_limits<unsigned>::max();
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    try {
        string strInput = "0000000000 65535 f\r\n";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = numeric_limits<int64_t>::max();
        objectCount = numeric_limits<int64_t>::max();
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::ValueOutOfRange);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    
    
    
    REQUIRE(PdfParser::GetMaxObjectCount() <= numeric_limits<unsigned>::max());

    
    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = -1LL;
        objectCount = 1;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::ValueOutOfRange);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = numeric_limits<unsigned>::min();
        objectCount = 1;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::UnexpectedEOF);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = numeric_limits<int64_t>::min();
        objectCount = 1;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::ValueOutOfRange);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = numeric_limits<unsigned>::max();
        objectCount = 1;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = numeric_limits<int64_t>::max();
        objectCount = 1;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::ValueOutOfRange);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = numeric_limits<size_t>::max();
        objectCount = 1;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        
        REQUIRE((error.GetCode() == PdfErrorCode::ValueOutOfRange || sizeof(size_t) == 4));
        REQUIRE((error.GetCode() == PdfErrorCode::InvalidXRef || sizeof(size_t) == 8));
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        REQUIRE(PdfParser::GetMaxObjectCount() > 0);
        firstObject = PdfParser::GetMaxObjectCount();
        objectCount = 1;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = 1;
        objectCount = -1LL;
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::ValueOutOfRange);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = 1;
        objectCount = numeric_limits<int>::min();
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::ValueOutOfRange);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = 1;
        objectCount = numeric_limits<int64_t>::min();
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::ValueOutOfRange);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    
    

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = 1;
        objectCount = numeric_limits<unsigned>::max();
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = 1;
        objectCount = numeric_limits<int64_t>::max();
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::ValueOutOfRange);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = 1;
        objectCount = numeric_limits<size_t>::max();
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        
        REQUIRE((error.GetCode() == PdfErrorCode::ValueOutOfRange || sizeof(size_t) == 4));
        REQUIRE((error.GetCode() == PdfErrorCode::InvalidXRef || sizeof(size_t) == 8));
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    try {
        string strInput = " ";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        firstObject = 1;
        objectCount = PdfParser::GetMaxObjectCount();
        parser.ReadXRefSubsection(firstObject, objectCount);
        FAIL("PdfError not thrown");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    
    static uint64_t s_values[] = {
        
        
        
        (1ull << 63) - 1, (1ull << 63), (1ull << 63) + 1, (1ull << 62) - 1, (1ull << 62), (1ull << 62) + 1,  (1ull << 49) - 1, (1ull << 49), (1ull << 49) + 1, (1ull << 48) - 1, (1ull << 48), (1ull << 48) + 1, (1ull << 47) - 1, (1ull << 47), (1ull << 47) + 1,  (1ull << 33) - 1, (1ull << 33), (1ull << 33) + 1, (1ull << 32) - 1, (1ull << 32), (1ull << 32) + 1, (1ull << 31) - 1, (1ull << 31), (1ull << 31) + 1,  (1ull << 25) - 1, (1ull << 33), (1ull << 33) + 1, (1ull << 24) - 1, (1ull << 24), (1ull << 24) + 1, (1ull << 31) - 1, (1ull << 31), (1ull << 31) + 1,  (1ull << 17) - 1, (1ull << 17), (1ull << 17) + 1, (1ull << 16) - 1, (1ull << 16), (1ull << 16) + 1, (1ull << 15) - 1, (1ull << 15), (1ull << 15) + 1,  (uint64_t)-1, 0, 1 };

















































    constexpr size_t numValues = sizeof(s_values) / sizeof(s_values[0]);

    for (size_t i = 0; i < numValues; i++)
    {
        for (size_t j = 0; j < numValues; j++)
        {
            try {
                string strInput = " ";
                PdfIndirectObjectList objects;
                PdfParserTest parser(objects, strInput);
                firstObject = s_values[i];
                objectCount = s_values[j];

                if (canOutOfMemoryKillUnitTests() && (firstObject > maxNumberOfIndirectObjects || objectCount > maxNumberOfIndirectObjects))
                {
                    
                    
                }
                else {
                    parser.ReadXRefSubsection(firstObject, objectCount);
                    
                }
            }
            catch (PdfError& error)
            {
                
                
                REQUIRE((error.GetCode() == PdfErrorCode::InvalidXRef || error.GetCode() == PdfErrorCode::ValueOutOfRange || error.GetCode() == PdfErrorCode::UnexpectedEOF || error.GetCode() == PdfErrorCode::OutOfMemory));

            }
            catch (exception&)
            {
                
                FAIL("Wrong exception type");
            }
        }
    }
}

TEST_CASE("testReadXRefStreamContents")
{
    
    try {
        
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        
        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = oss.str().length();
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 5 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, oss.str());
        parser.ReadXRefStreamContents(offsetXRefObject, false);
        
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        
        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 5 ";
        oss << "/W [ 1 2 9223372036854775807 ] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::NoXRef);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        
        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 5 ";
        oss << "/W [ 1 -4 2 ] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::NoXRef);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        
        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 5 ";
        oss << "/W [ 4095 1 1 ] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE((offsetEndstream - offsetStream - strlen("\r\n")) == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRefStream);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        
        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 5 ";
        oss << "/W [ 4 4 4 ] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRefType);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        
        size_t lengthXRefObject = 22;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 2 ";
        oss << "/W [ 1 4 4 ] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::NoXRef);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        size_t lengthXRefObject = 22;
        size_t offsetXRefObject = 34;
        oss << "%PDF-1.4\r\n";
        oss << "1 0 obj\r\n";
        oss << "<< >>\r\n";
        oss << "endobj\r\n";
        oss << "2 0 obj\r\n";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [1 2] ";
        oss << "/Root 1 0 R ";
        oss << "/Size 3 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 000A 00\r\n";
        oss << "01 001A 00\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        doc.LoadFromDevice(device);
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 10 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "01 0002 00\r\n";
        oss << "01 0002 01\r\n";
        oss << "01 0002 02\r\n";
        oss << "01 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        (void)error;
        
        
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 10 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "01 0002 00\r\n";
        oss << "01 0002 01\r\n";
        oss << "01 0002 02\r\n";
        oss << "01 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        (void)error;
        
        
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [0 0] ";
        oss << "/Size 5 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        (void)error;
        
        
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [-1 -1] ";
        oss << "/Size 5 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        (void)error;
        
        
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [ ] ";
        oss << "/Size 5 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        (void)error;
        
        
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2 2] ";
        oss << "/Size 5 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::NoXRef);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }

    
    try {
        ostringstream oss;
        size_t offsetStream;
        size_t offsetEndstream;

        size_t lengthXRefObject = 58;
        size_t offsetXRefObject = 10;
        oss << "%PDF-1.4\r\n";
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22] ";
        oss << "/Size 5 ";
        oss << "/W [1 2 1] ";
        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "00 0000 00\r\n";
        oss << "00 0000 00\r\n";
        oss << "00 0000 00\r\n";
        oss << "00 0000 00\r\n";
        oss << "00 0000 00\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%%EOF";

        auto inputStr = oss.str();
        PdfXRefEntries offsets;
        auto device = std::make_shared<SpanStreamDevice>(inputStr);
        PdfMemDocument doc;
        doc.LoadFromDevice(device);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::NoXRef);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }
}

TEST_CASE("testReadObjects")
{
    
    try {
        ostringstream oss;
        oss << "%PDF-1.0\r\n";
        oss << "xref\r\n0 3\r\n";
        oss << generateXRefEntries(3);
        oss << "trailer << /Root 1 0 R /Size 3 /Encrypt 3 0 R >>\r\n";
        oss << "startxref 0\r\n";
        oss << "%%EOF";
        PdfIndirectObjectList objects;
        auto docbuff = oss.str();
        PdfParserTest parser(objects, docbuff);
        parser.ReadDocumentStructure();
        parser.ReadObjects();
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidEncryptionDict);
    }
    catch (exception&)
    {
        FAIL("Unexpected exception type");
    }
}

TEST_CASE("testIsPdfFile")
{
    try {
        string strInput = "%PDF-1.0";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        REQUIRE(parser.IsPdfFile());
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    try {
        string strInput = "%PDF-1.1";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        REQUIRE(parser.IsPdfFile());
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    try {
        string strInput = "%PDF-1.7";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        REQUIRE(parser.IsPdfFile());
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    try {
        string strInput = "%PDF-1.9";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        REQUIRE(!parser.IsPdfFile());
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    try {
        string strInput = "%PDF-2.0";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        REQUIRE(parser.IsPdfFile());
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    try {
        string strInput = "%!PS-Adobe-2.0";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        REQUIRE(!parser.IsPdfFile());
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }

    try {
        string strInput = "GIF89a";
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, strInput);
        REQUIRE(!parser.IsPdfFile());
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
    catch (exception&)
    {
        FAIL("Wrong exception type");
    }
}

TEST_CASE("testSaveIncrementalRoundTrip")
{
    ostringstream oss;
    oss << "%PDF-1.1\n";
    unsigned currObj = 1;
    streamoff objPos[20];

    

    unsigned pagesObj = currObj;
    objPos[currObj] = oss.tellp();
    oss << currObj++ << " 0 obj\n";
    oss << "<</Type /Pages /Count 0 /Kids []>>\n";
    oss << "endobj\n";

    

    unsigned rootObj = currObj;
    objPos[currObj] = oss.tellp();
    oss << currObj++ << " 0 obj\n";
    oss << "<</Type /Catalog /Pages " << pagesObj << " 0 R>>\n";
    oss << "endobj\n";

    
    unsigned idObj = currObj;
    objPos[currObj] = oss.tellp();
    oss << currObj++ << " 0 obj\n";
    oss << "[<F1E375363A6314E3766EDF396D614748> <F1E375363A6314E3766EDF396D614748>]\n";
    oss << "endobj\n";

    streamoff xrefPos = oss.tellp();
    oss << "xref\n";
    oss << "0 " << currObj << "\n";
    oss << "0000000000 65535 f \n";
    for (unsigned i = 1; i < currObj; i++)
        oss << utls::Format("{:010d} 00000 n \n", objPos[i]);

    oss << "trailer <<\n" << "  /Size " << currObj << "\n" << "  /Root " << rootObj << " 0 R\n" << "  /ID " << idObj << " 0 R\n" << ">>\n" << "startxref\n" << xrefPos << "\n" << "%%EOF\n";







    string docBuff = oss.str();
    try {
        PdfMemDocument doc;
        
        doc.LoadFromBuffer(docBuff);

        StringStreamDevice outDev(docBuff);

        doc.SaveUpdate(outDev);
        doc.LoadFromBuffer(docBuff);
    }
    catch (PdfError&)
    {
        FAIL("Unexpected PdfError");
    }
}


TEST_CASE("testNestedArrays")
{
    
    
    ostringstream oss;
    size_t offsetStream;
    size_t offsetEndstream;
    size_t offsetXRefObject;
    string buffer;

    
    constexpr size_t lengthXRefObject = 58;

    offsetXRefObject = oss.str().length();
    oss << "2 0 obj ";
    oss << "<< /Type /XRef ";
    oss << "/Length " << lengthXRefObject << " ";
    oss << "/Index [2 2] ";
    oss << "/Size 5 ";
    oss << "/W [1 2 1] ";
    oss << "/Filter /ASCIIHexDecode ";
    oss << ">>\r\n";
    oss << "stream\r\n";
    offsetStream = oss.str().length();
    oss << "01 0E8A 00\r\n";
    oss << "02 0002 00\r\n";
    oss << "02 0002 01\r\n";
    oss << "02 0002 02\r\n";
    oss << "02 0002 03\r\n";
    offsetEndstream = oss.str().length();
    oss << "endstream\r\n";
    oss << "endobj\r\n";
    REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

    
    oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
    oss << "startxref " << offsetXRefObject << "\r\n";
    oss << "%EOF";

    buffer = oss.str();

    {
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, buffer);
        parser.ReadXRefStreamContents(offsetXRefObject, false);
        REQUIRE(true);
    }

    
    try {
        
        oss.str("");
        const size_t maxNesting = getStackOverflowDepth(); 
        
        offsetXRefObject = oss.str().length();
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 5 ";
        oss << "/W [1 2 1] ";
        
        
        for (size_t i = 0; i < maxNesting; i++)
        {
            oss << "[";
        }
        oss << "0";
        for (size_t i = 0; i < maxNesting; i++)
        {
            oss << "]";
        }
        oss << " ";

        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%EOF";

        buffer = oss.str();

        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, buffer);
        parser.ReadXRefStreamContents(offsetXRefObject, false);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
}


TEST_CASE("testNestedDictionaries")
{
    
    
    ostringstream oss;
    size_t offsetStream;
    size_t offsetEndstream;
    size_t offsetXRefObject;
    string buffer;

    
    constexpr size_t lengthXRefObject = 58;

    offsetXRefObject = oss.str().length();
    oss << "2 0 obj ";
    oss << "<< /Type /XRef ";
    oss << "/Length " << lengthXRefObject << " ";
    oss << "/Index [2 2] ";
    oss << "/Size 5 ";
    oss << "/W [1 2 1] ";
    oss << "/Filter /ASCIIHexDecode ";
    oss << ">>\r\n";
    oss << "stream\r\n";
    offsetStream = oss.str().length();
    oss << "01 0E8A 00\r\n";
    oss << "02 0002 00\r\n";
    oss << "02 0002 01\r\n";
    oss << "02 0002 02\r\n";
    oss << "02 0002 03\r\n";
    offsetEndstream = oss.str().length();
    oss << "endstream\r\n";
    oss << "endobj\r\n";
    REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

    
    oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
    oss << "startxref " << offsetXRefObject << "\r\n";
    oss << "%EOF";

    buffer = oss.str();

    {
        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, buffer);
        parser.ReadXRefStreamContents(offsetXRefObject, false);
        REQUIRE(true);
    }

    
    try {
        
        oss.str("");

        const size_t maxNesting = getStackOverflowDepth(); 
        
        offsetXRefObject = oss.str().length();
        oss << "2 0 obj ";
        oss << "<< /Type /XRef ";
        oss << "/Length " << lengthXRefObject << " ";
        oss << "/Index [2 2] ";
        oss << "/Size 5 ";
        oss << "/W [1 2 1] ";

        
        for (size_t i = 0; i < maxNesting; i++)
        {
            oss << "<< ";
        }
        oss << " /Test 0";
        for (size_t i = 0; i < maxNesting; i++)
        {
            oss << " >>";
        }
        oss << " ";

        oss << "/Filter /ASCIIHexDecode ";
        oss << ">>\r\n";
        oss << "stream\r\n";
        offsetStream = oss.str().length();
        oss << "01 0E8A 00\r\n";
        oss << "02 0002 00\r\n";
        oss << "02 0002 01\r\n";
        oss << "02 0002 02\r\n";
        oss << "02 0002 03\r\n";
        offsetEndstream = oss.str().length();
        oss << "endstream\r\n";
        oss << "endobj\r\n";
        REQUIRE(offsetEndstream - offsetStream - strlen("\r\n") == lengthXRefObject); 

        
        oss << "trailer << /Root 1 0 R /Size 3 >>\r\n";
        oss << "startxref " << offsetXRefObject << "\r\n";
        oss << "%EOF";

        buffer = oss.str();

        PdfIndirectObjectList objects;
        PdfParserTest parser(objects, buffer);
        parser.ReadXRefStreamContents(offsetXRefObject, false);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
}


TEST_CASE("testNestedNameTree")
{
    
    
    
    ostringstream oss;
    const size_t maxDepth = getStackOverflowDepth() - 6 - 1;
    const size_t numObjects = maxDepth + 6;
    vector<size_t> offsets(numObjects);
    size_t xrefOffset = 0;

    offsets[0] = 0;
    oss << "%PDF-1.0\r\n";

    offsets[1] = oss.tellp();
    oss << "1 0 obj<</Type/Catalog /Pages 2 0 R /Names 4 0 R>>endobj ";

    offsets[2] = oss.tellp();
    oss << "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj ";

    offsets[3] = oss.tellp();
    oss << "3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj ";

    
    offsets[4] = oss.tellp();
    oss << "4 0 obj<</Dests 5 0 R>>endobj ";

    
    offsets[5] = oss.tellp();
    oss << "5 0 obj<</Kids [6 0 R]>>endobj ";

    
    
    for (size_t objNo = 6; objNo < numObjects; objNo++)
    {
        offsets[objNo] = oss.tellp();

        if (objNo < numObjects - 1)
            oss << objNo << " 0 obj<</Kids [" << objNo + 1 << " 0 R] /Limits [(A) (Z)]>>endobj ";
        else oss << objNo << " 0 obj<</Limits [(A) (Z)] /Names [ (A) (Avalue) (Z) (Zvalue) ] >>endobj ";
    }

    
    oss << "\r\n";
    xrefOffset = oss.tellp();
    oss << "xref\r\n";
    oss << "0 " << numObjects << "\r\n";

    oss << "0000000000 65535 f\r\n";

    for (size_t objNo = 1; objNo < offsets.size(); objNo++)
    {
        
        
        char refEntry[21];
        snprintf(refEntry, 21, "%010zu 00000 n\r\n", offsets[objNo]);

        oss << refEntry;
    }

    oss << "trailer<</Size " << numObjects << "/Root 1 0 R>>\r\n";
    oss << "startxref\r\n";
    oss << xrefOffset << "\r\n";
    oss << "%%EOF";

    auto buffer = oss.str();

    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(buffer);

        auto names = doc.GetNames();
        if (names != nullptr)
        {
            PdfDictionary dict;
            names->ToDictionary("Dests", dict);
        }

        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
}


TEST_CASE("testLoopingNameTree")
{
    string strNoLoop = "%PDF-1.0\r\n" "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 4 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj 4 0 obj<</Dests 2 0 R>>endobj\r\n" "xref\r\n" "0 5\r\n" "0000000000 65535 f\r\n" "0000000010 00000 n\r\n" "0000000066 00000 n\r\n" "0000000115 00000 n\r\n" "0000000161 00000 n\r\n" "trailer<</Size 4/Root 1 0 R>>\r\n" "startxref\r\n" "192\r\n" "%%EOF";













    {
        PdfMemDocument doc;
        doc.LoadFromBuffer(strNoLoop);

        auto names = doc.GetNames();
        if (names != nullptr)
        {
            PdfDictionary dict;
            names->ToDictionary("Dests", dict);
        }
    }

    
    string strSelfLoop = "%PDF-1.0\r\n" "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 4 0 R>>endobj 2 0 obj<</Type/Pages/Kids[2 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj 4 0 obj<</Dests 2 0 R>>endobj\r\n" "xref\r\n" "0 5\r\n" "0000000000 65535 f\r\n" "0000000010 00000 n\r\n" "0000000066 00000 n\r\n" "0000000115 00000 n\r\n" "0000000161 00000 n\r\n" "trailer<</Size 4/Root 1 0 R>>\r\n" "startxref\r\n" "192\r\n" "%%EOF";













    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(strSelfLoop);

        auto names = doc.GetNames();
        if (names != nullptr)
        {
            PdfDictionary dict;
            names->ToDictionary("Dests", dict);
        }

        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }

    
    string strAncestorLoop = "%PDF-1.0\r\n" "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 4 0 R>>endobj 2 0 obj<</Type/Pages/Kids[1 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj 4 0 obj<</Dests 2 0 R>>endobj\r\n" "xref\r\n" "0 5\r\n" "0000000000 65535 f\r\n" "0000000010 00000 n\r\n" "0000000066 00000 n\r\n" "0000000115 00000 n\r\n" "0000000161 00000 n\r\n" "trailer<</Size 4/Root 1 0 R>>\r\n" "startxref\r\n" "192\r\n" "%%EOF";













    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(strAncestorLoop);

        auto names = doc.GetNames();
        if (names != nullptr)
        {
            PdfDictionary dict;
            names->ToDictionary("Dests", dict);
        }

        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidDataType);
    }
}


TEST_CASE("testNestedPageTree")
{
    
    
    
    ostringstream oss;
    const size_t maxDepth = getStackOverflowDepth() - 4 - 1;
    const size_t numObjects = maxDepth + 4;
    vector<size_t> offsets(numObjects);
    size_t xrefOffset = 0;

    offsets[0] = 0;
    oss << "%PDF-1.0\r\n";

    offsets[1] = oss.tellp();
    oss << "1 0 obj<</Type/Catalog /AcroForm 2 0 R /Pages 3 0 R>>endobj ";

    offsets[2] = oss.tellp();
    oss << "2 0 obj<</Type/AcroForm >>endobj ";

    offsets[3] = oss.tellp();
    oss << "3 0 obj<</Type/Pages /Kids [4 0 R] /Count 1 >>endobj ";

    
    
    for (size_t objNo = 4; objNo < numObjects; objNo++)
    {
        offsets[objNo] = oss.tellp();

        if (objNo < numObjects - 1)
            oss << objNo << " 0 obj<</Type/Pages /Kids [" << objNo + 1 << " 0 R] /Parent " << objNo - 1 << " 0 R /Count 1 >>endobj ";
        else oss << objNo << " 0 obj<</Type/Page  /Parent " << objNo - 1 << " 0 R >>endobj ";
    }

    
    oss << "\r\n";
    xrefOffset = oss.tellp();
    oss << "xref\r\n";
    oss << "0 " << numObjects << "\r\n";

    oss << "0000000000 65535 f\r\n";

    for (size_t objNo = 1; objNo < offsets.size(); objNo++)
    {
        
        
        char refEntry[21];
        snprintf(refEntry, 21, "%010zu 00000 n\r\n", offsets[objNo]);

        oss << refEntry;
    }

    oss << "trailer<</Size " << numObjects << "/Root 1 0 R>>\r\n";
    oss << "startxref\r\n";
    oss << xrefOffset << "\r\n";
    oss << "%%EOF";

    auto buffer = oss.str();
    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(buffer);

        auto& pages = doc.GetPages();
        for (unsigned pageNo = 0; pageNo < pages.GetCount(); pageNo++)
            (void)pages.GetPageAt(pageNo);

        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
}


TEST_CASE("testLoopingPageTree")
{
    
    string strNoLoop = "%PDF-1.0\r\n" "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj\r\n" "xref\r\n" "0 4\r\n" "0000000000 65535 f\r\n" "0000000010 00000 n\r\n" "0000000053 00000 n\r\n" "0000000102 00000 n\r\n" "trailer<</Size 4/Root 1 0 R>>\r\n" "startxref\r\n" "149\r\n" "%%EOF";












    {
        PdfMemDocument doc;
        doc.LoadFromBuffer(strNoLoop);
        auto& pages = doc.GetPages();
        for (unsigned pageNo = 0; pageNo < doc.GetPages().GetCount(); pageNo++)
            (void)pages.GetPageAt(pageNo);
        REQUIRE(true);
    }

    
    string strSelfLoop = "%PDF-1.0\r\n" "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[2 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj\r\n" "xref\r\n" "0 4\r\n" "0000000000 65535 f\r\n" "0000000010 00000 n\r\n" "0000000053 00000 n\r\n" "0000000102 00000 n\r\n" "trailer<</Size 4/Root 1 0 R>>\r\n" "startxref\r\n" "149\r\n" "%%EOF";












    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(strSelfLoop);
        auto& pages = doc.GetPages();
        for (unsigned pageNo = 0; pageNo < pages.GetCount(); pageNo++)
            (void)pages.GetPageAt(pageNo);

        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::PageNotFound);
    }

    
    string strAncestorLoop = "%PDF-1.0\r\n" "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[1 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj\r\n" "xref\r\n" "0 4\r\n" "0000000000 65535 f\r\n" "0000000010 00000 n\r\n" "0000000053 00000 n\r\n" "0000000102 00000 n\r\n" "trailer<</Size 4/Root 1 0 R>>\r\n" "startxref\r\n" "149\r\n" "%%EOF";












    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(strAncestorLoop);
        auto& pages = doc.GetPages();
        pages.GetPageAt(0);
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::PageNotFound);
    }
}


TEST_CASE("testNestedOutlines")
{
    
    
    
    ostringstream oss;
    const size_t maxDepth = getStackOverflowDepth() - 4 - 1;
    const size_t numObjects = maxDepth + 4;
    vector<size_t> offsets(numObjects);
    size_t xrefOffset = 0;

    offsets[0] = 0;
    oss << "%PDF-1.0\r\n";

    offsets[1] = oss.tellp();
    oss << "1 0 obj<</Type/Catalog /AcroForm 2 0 R /Outlines 3 0 R>>endobj ";

    offsets[2] = oss.tellp();
    oss << "2 0 obj<</Type/AcroForm >>endobj ";

    offsets[3] = oss.tellp();
    oss << "3 0 obj<</Type/Outlines /First 4 0 R /Count " << maxDepth << " /Last 5 0 R >>endobj ";

    
    
    for (size_t objNo = 4; objNo < numObjects; objNo++)
    {
        offsets[objNo] = oss.tellp();

        if (objNo < numObjects - 1)
            oss << objNo << " 0 obj<</Title (Outline Item) /First " << objNo + 1 << " 0 R /Last " << objNo + 1 << " 0 R>>endobj ";
        else oss << objNo << " 0 obj<</Title (Outline Item)>>endobj ";
    }

    
    oss << "\r\n";
    xrefOffset = oss.tellp();
    oss << "xref\r\n";
    oss << "0 " << numObjects << "\r\n";

    oss << "0000000000 65535 f\r\n";

    for (size_t objNo = 1; objNo < offsets.size(); objNo++)
    {
        
        
        char szXrefEntry[21];
        snprintf(szXrefEntry, 21, "%010zu 00000 n\r\n", offsets[objNo]);

        oss << szXrefEntry;
    }

    oss << "trailer<</Size " << numObjects << "/Root 1 0 R>>\r\n";
    oss << "startxref\r\n";
    oss << xrefOffset << "\r\n";
    oss << "%%EOF";

    auto buffer = oss.str();
    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(buffer);

        
        (void)doc.GetOutlines();
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
}


TEST_CASE("testLoopingOutlines")
{
    
    string strNextLoop = "%PDF-1.0\r\n" "1 0 obj<</Type/Catalog /AcroForm 2 0 R /Outlines 3 0 R>>endobj " "2 0 obj<</Type/AcroForm >>endobj " "3 0 obj<</Type/Outlines /First 4 0 R /Count 2 /Last 5 0 R >>endobj " "4 0 obj<</Title (Outline Item 1) /Next 5 0 R>>endobj " "5 0 obj<</Title (Outline Item 2) /Next 4 0 R>>endobj " "\r\n" "xref\r\n" "0 6\r\n" "0000000000 65535 f\r\n" "0000000010 00000 n\r\n" "0000000073 00000 n\r\n" "0000000106 00000 n\r\n" "0000000173 00000 n\r\n" "0000000226 00000 n\r\n" "trailer<</Size 6/Root 1 0 R>>\r\n" "startxref\r\n" "281\r\n" "%%EOF";



















    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(strNextLoop);

        
        (void)doc.GetOutlines();
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }

    
    string strSelfLoop = "%PDF-1.0\r\n" "1 0 obj<</Type/Catalog/Outlines 2 0 R>>endobj " "2 0 obj<</Type/Outlines /First 2 0 R /Last 2 0 R /Count 1>>endobj" "\r\n" "xref\r\n" "0 3\r\n" "0000000000 65535 f\r\n" "0000000010 00000 n\r\n" "0000000056 00000 n\r\n" "trailer<</Size 3/Root 1 0 R>>\r\n" "startxref\r\n" "123\r\n" "%%EOF";













    try {
        PdfMemDocument doc;
        doc.LoadFromBuffer(strNextLoop);

        
        (void)doc.GetOutlines();
        FAIL("Should throw exception");
    }
    catch (PdfError& error)
    {
        REQUIRE(error.GetCode() == PdfErrorCode::InvalidXRef);
    }
}

string generateXRefEntries(size_t count)
{
    string strXRefEntries;

    
    
    
    
    
    try {
        strXRefEntries.reserve(count * 20);
        for (size_t i = 0; i < count; i++)
        {
            if (i == 0)
                strXRefEntries.append("0000000000 65535 f\r\n");
            else strXRefEntries.append("0000000120 00000 n\r\n");
        }
    }
    catch (exception&)
    {
        
        FAIL("generateXRefEntries memory allocation failure");
    }

    return strXRefEntries;
}

bool canOutOfMemoryKillUnitTests()
{
    
    


    
    bool canTerminateProcess = false;

    
    

    
    
    
    
    bool canTerminateProcess = true;

    
    
    
    
    bool canTerminateProcess = false;


    
    bool canTerminateProcess = false;

    
    bool canTerminateProcess = false;

    return canTerminateProcess;
}

size_t getStackOverflowDepth()
{
    
    
    
    constexpr size_t parserObjectSize = sizeof(PdfParserObject);


    
    
    
    
    constexpr size_t stackSize = 1 * 1024 * 1024;
    constexpr size_t frameSize = sizeof(void*) * (4 + 4 + 1); 
    constexpr size_t maxFrames = stackSize / frameSize; 

    
    
    
    constexpr size_t stackSize = 1 * 1024 * 1024;
    constexpr size_t frameSize = sizeof(void*) * (1 + 1); 
    constexpr size_t maxFrames = stackSize / frameSize; 

    
    
    
    constexpr size_t stackSize = 8 * 1024 * 1024;
    constexpr size_t frameSize = sizeof(void*) * (1 + 1); 
    constexpr size_t maxFrames = stackSize / frameSize; 


    
    constexpr size_t overflowDepth = maxFrames + 1000;

    
    
    
    REQUIRE(overflowDepth < PdfParser::GetMaxObjectCount());
    REQUIRE(overflowDepth * parserObjectSize < numeric_limits<size_t>::max() / 2);

    return overflowDepth;
}
