










using namespace std;
using namespace PoDoFo;

PdfXRefStreamParserObject::PdfXRefStreamParserObject(PdfDocument& doc, InputStreamDevice& device, PdfXRefEntries& entries)
    : PdfXRefStreamParserObject(&doc, device, entries) { }

PdfXRefStreamParserObject::PdfXRefStreamParserObject(InputStreamDevice& device, PdfXRefEntries& entries)
    : PdfXRefStreamParserObject(nullptr, device, entries) { }

PdfXRefStreamParserObject::PdfXRefStreamParserObject(PdfDocument* doc, InputStreamDevice& device, PdfXRefEntries& entries)
    : PdfParserObject(doc, PdfReference(), device, -1), m_NextOffset(-1), m_entries(&entries)
{
}

void PdfXRefStreamParserObject::DelayedLoadImpl()
{
    

    PdfTokenizer tokenizer;
    auto reference = ReadReference(tokenizer);
    SetIndirectReference(reference);
    PdfParserObject::Parse(tokenizer);

    
    auto& dict = m_Variant.GetDictionary();
    auto keyObj = dict.FindKey(PdfName::KeyType);
    if (keyObj == nullptr)
        PODOFO_RAISE_ERROR(PdfErrorCode::NoXRef);

    if (!keyObj->IsName() || keyObj->GetName() != "XRef")
        PODOFO_RAISE_ERROR(PdfErrorCode::NoXRef);

    if (!dict.HasKey(PdfName::KeySize)
        || !dict.HasKey("W"))
    {
        PODOFO_RAISE_ERROR(PdfErrorCode::NoXRef);
    }

    if (dict.HasKey("Prev"))
        m_NextOffset = static_cast<ssize_t>(dict.FindKeyAs<double>("Prev", 0));

    if (!this->HasStreamToParse())
        PODOFO_RAISE_ERROR(PdfErrorCode::NoXRef);
}

void PdfXRefStreamParserObject::ReadXRefTable()
{
    int64_t size = this->GetDictionary().FindKeyAs<int64_t>(PdfName::KeySize, 0);
    auto& arrObj = this->GetDictionary().MustFindKey("W");

    
    
    const PdfArray* arr;
    if (!arrObj.TryGetArray(arr) || arr->size() != 3)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::NoXRef, "Invalid XRef stream /W array");

    int64_t wArray[W_ARRAY_SIZE] = { 0, 0, 0 };
    int64_t num;
    for (unsigned i = 0; i < W_ARRAY_SIZE; i++)
    {

        if (!(*arr)[i].TryGetNumber(num))
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::NoXRef, "Invalid XRef stream /W array");

        wArray[i] = num;
    }

    vector<int64_t> indices;
    getIndices(indices, static_cast<int64_t>(size));

    parseStream(wArray, indices);
}

void PdfXRefStreamParserObject::parseStream(const int64_t wArray[W_ARRAY_SIZE], const vector<int64_t>& indices)
{
    for (int64_t lengthSum = 0, i = 0; i < W_ARRAY_SIZE; i++)
    {
        if (wArray[i] < 0)
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::NoXRef, "Negative field length in XRef stream");
        }
        if (numeric_limits<int64_t>::max() - lengthSum < wArray[i])
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::NoXRef, "Invalid entry length in XRef stream");
        }
        else {
            lengthSum += wArray[i];
        }
    }

    const size_t entryLen = static_cast<size_t>(wArray[0] + wArray[1] + wArray[2]);

    charbuff buffer;
    this->GetOrCreateStream().CopyTo(buffer);

    vector<int64_t>::const_iterator it = indices.begin();
    char* cursor = buffer.data();
    while (it != indices.end())
    {
        int64_t firstObj = *it++;
        int64_t count = *it++;

        m_entries->Enlarge(firstObj + count);
        for (unsigned index = 0; index < (unsigned)count; index++)
        {
            if ((size_t)(cursor - buffer.data()) >= buffer.size())
                PODOFO_RAISE_ERROR_INFO(PdfErrorCode::NoXRef, "Invalid count in XRef stream");

            unsigned objIndex = (unsigned)firstObj + index;
            auto& entry = (*m_entries)[objIndex];
            if (objIndex < m_entries->GetSize() && !entry.Parsed)
                readXRefStreamEntry(entry, cursor, wArray);

            cursor += entryLen;
        }
    }
}

void PdfXRefStreamParserObject::getIndices(vector<int64_t>& indices, int64_t size)
{
    
    
    auto indexObj = this->GetDictionary().GetKey("Index");
    if (indexObj == nullptr)
    {
        
        indices.push_back(static_cast<int64_t>(0));
        indices.push_back(size);
    }
    else {
        const PdfArray* arr;
        if (!indexObj->TryGetArray(arr))
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::NoXRef, "Invalid XRef Stream /Index");

        for (auto index : *arr)
            indices.push_back(index.GetNumber());
    }

    
    if (indices.size() % 2 != 0)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::NoXRef, "Invalid XRef Stream /Index");
}

void PdfXRefStreamParserObject::readXRefStreamEntry(PdfXRefEntry& entry, char* buffer, const int64_t wArray[W_ARRAY_SIZE])
{
    uint64_t entryRaw[W_ARRAY_SIZE];
    for (unsigned i = 0; i < W_ARRAY_SIZE; i++)
    {
        if (wArray[i] > W_MAX_BYTES)
        {
            PoDoFo::LogMessage(PdfLogSeverity::Error, "The XRef stream dictionary has an entry in /W of size {}. The maximum supported value is {}", wArray[i], W_MAX_BYTES);


            PODOFO_RAISE_ERROR(PdfErrorCode::InvalidXRefStream);
        }

        entryRaw[i] = 0;
        for (int64_t z = W_MAX_BYTES - wArray[i]; z < W_MAX_BYTES; z++)
        {
            entryRaw[i] = (entryRaw[i] << 8) + static_cast<unsigned char>(*buffer);
            buffer++;
        }
    }

    entry.Parsed = true;

    
    
    uint64_t type;
    if (wArray[0] == 0)
        type = 1;
    else type = entryRaw[0];

    switch (type)
    {
        
        case 0:
            
            entry.ObjectNumber = entryRaw[1];
            entry.Generation = (uint32_t)entryRaw[2];
            entry.Type = XRefEntryType::Free;
            break;
        case 1:
            
            entry.Offset = entryRaw[1];
            entry.Generation = (uint32_t)entryRaw[2];
            entry.Type = XRefEntryType::InUse;
            break;
        case 2:
            
            entry.ObjectNumber = entryRaw[1]; 
            entry.Index = (uint32_t)entryRaw[2]; 
            entry.Type = XRefEntryType::Compressed;
            break;
        default:
            PODOFO_RAISE_ERROR(PdfErrorCode::InvalidXRefType);
    }
}

bool PdfXRefStreamParserObject::TryGetPreviousOffset(size_t& previousOffset) const {
    bool ret = m_NextOffset != -1;
    previousOffset = ret ? (size_t)m_NextOffset : 0;
    return ret;
}