
























ACSequentialScan::ACSequentialScan(class Frame *frame,class Scan *scan, UBYTE start,UBYTE stop,UBYTE lowbit,UBYTE, bool differential,bool residual,bool large)

  : EntropyParser(frame,scan)

  , m_pBlockCtrl(NULL), m_ucScanStart(start), m_ucScanStop(stop), m_ucLowBit(lowbit), m_bMeasure(false), m_bDifferential(differential), m_bResidual(residual), m_bLargeRange(large)


{

  m_ucCount = scan->ComponentsInScan();
  
  for(UBYTE i = 0;i < m_ucCount;i++) {
    m_ucSmall[i]     = 0;
    m_ucLarge[i]     = 1;
    m_ucBlockEnd[i]  = 5;
  }

  NOREF(start);
  NOREF(stop);
  NOREF(lowbit);
  NOREF(differential);
  NOREF(residual);
  NOREF(large);

}



ACSequentialScan::~ACSequentialScan(void)
{
}



void ACSequentialScan::StartParseScan(class ByteStream *io,class Checksum *chk,class BufferCtrl *ctrl)
{ 

  class ACTemplate *ac,*dc;
  int i;

  for(i = 0;i < m_ucCount;i++) {
    dc = m_pScan->DCConditionerOf(i);
    ac = m_pScan->ACConditionerOf(i); 
    
    m_ucDCContext[i]  = m_pScan->DCTableIndexOf(i);
    m_ucACContext[i]  = m_pScan->ACTableIndexOf(i);

    if (dc) {
      m_ucSmall[i]    = dc->LowerThresholdOf();
      m_ucLarge[i]    = dc->UpperThresholdOf();
    } else {
      m_ucSmall[i]    = 0;
      m_ucLarge[i]    = 1;
    }

    if (ac) {
      m_ucBlockEnd[i] = ac->BandDiscriminatorOf();
    } else {
      m_ucBlockEnd[i] = 5;
    }

    m_lDC[i]         = 0; 
    m_lDiff[i]       = 0;
    m_ulX[i]         = 0;
  }
  
  for(i = 0;i < 4;i++) {
    m_Context[i].Init();
  }
  
  assert(!ctrl->isLineBased());
  m_pBlockCtrl = dynamic_cast<BlockCtrl *>(ctrl);
  m_pBlockCtrl->ResetToStartOfScan(m_pScan);
  m_Coder.OpenForRead(io,chk);

  NOREF(io);
  NOREF(chk);
  NOREF(ctrl);
  JPG_THROW(NOT_IMPLEMENTED,"ACSequentialScan::StartParseScan", "Lossless JPEG not available in your code release, please contact Accusoft for a full version");

}



void ACSequentialScan::StartWriteScan(class ByteStream *io,class Checksum *chk,class BufferCtrl *ctrl)
{ 

  class ACTemplate *ac,*dc;
  int i;

  for(i = 0;i < m_ucCount;i++) {
    dc = m_pScan->DCConditionerOf(i);
    ac = m_pScan->ACConditionerOf(i);
   
    m_ucDCContext[i]  = m_pScan->DCTableIndexOf(i);
    m_ucACContext[i]  = m_pScan->ACTableIndexOf(i);

    if (dc) {
      m_ucSmall[i]    = dc->LowerThresholdOf();
      m_ucLarge[i]    = dc->UpperThresholdOf();
    } else {
      m_ucSmall[i]    = 0;
      m_ucLarge[i]    = 1;
    }

    if (ac) {
      m_ucBlockEnd[i] = ac->BandDiscriminatorOf();
    } else {
      m_ucBlockEnd[i] = 5;
    }

    m_lDC[i]           = 0;
    m_lDiff[i]         = 0;
    m_ulX[i]           = 0;
  }
  for(i = 0;i < 4;i++) {
    m_Context[i].Init();
  }

  assert(!ctrl->isLineBased());
  m_pBlockCtrl = dynamic_cast<BlockCtrl *>(ctrl);
  m_pBlockCtrl->ResetToStartOfScan(m_pScan);

  EntropyParser::StartWriteScan(io,chk,ctrl);

  m_pScan->WriteMarker(io);
  m_Coder.OpenForWrite(io,chk);

  NOREF(io);
  NOREF(chk);
  NOREF(ctrl);
  JPG_THROW(NOT_IMPLEMENTED,"ACSequentialScan::StartWriteScan", "Lossless JPEG not available in your code release, please contact Accusoft for a full version");

}




void ACSequentialScan::StartMeasureScan(class BufferCtrl *)
{ 
  
  
  JPG_THROW(NOT_IMPLEMENTED,"ACSequentialScan::StartMeasureScan", "arithmetic coding is always adaptive and does not require " "to measure the statistics");

}




bool ACSequentialScan::StartMCURow(void)
{

  bool more = m_pBlockCtrl->StartMCUQuantizerRow(m_pScan);

  for(int i = 0;i < m_ucCount;i++) {
    m_ulX[i]   = 0;
  }

  return more;

  return false;

}




bool ACSequentialScan::WriteMCU(void)
{ 

  bool more = true;
  int c;

  assert(m_pBlockCtrl);
  
  BeginWriteMCU(m_Coder.ByteStreamOf());

  for(c = 0;c < m_ucCount;c++) {
    class Component *comp    = m_pComponent[c];
    class QuantizedRow *q    = m_pBlockCtrl->CurrentQuantizedRow(comp->IndexOf());
    LONG &prevdc             = m_lDC[c];
    LONG &prevdiff           = m_lDiff[c];
    UBYTE l                  = m_ucSmall[c];
    UBYTE u                  = m_ucLarge[c];
    UBYTE kx                 = m_ucBlockEnd[c];
    UBYTE mcux               = (m_ucCount > 1)?(comp->MCUWidthOf() ):(1);
    UBYTE mcuy               = (m_ucCount > 1)?(comp->MCUHeightOf()):(1);
    ULONG xmin               = m_ulX[c];
    ULONG xmax               = xmin + mcux;
    ULONG x,y; 
    if (xmax >= q->WidthOf()) {
      more     = false;
    }
    for(y = 0;y < mcuy;y++) {
      for(x = xmin;x < xmax;x++) {
        LONG *block,dummy[64];
        if (q && x < q->WidthOf()) {
          block  = q->BlockAt(x)->m_Data;
        } else {
          block  = dummy;
          memset(dummy ,0,sizeof(dummy) );
          block[0] = prevdc;
        }
        EncodeBlock(block,prevdc,prevdiff,l,u,kx,m_ucDCContext[c],m_ucACContext[c]);
      }
      if (q) q = q->NextOf();
    }
    
    m_ulX[c] = xmax;
  }

  return more;

  return false;

}




void ACSequentialScan::Restart(void)
{

  int i;
  
  for(i = 0;i < m_ucCount;i++) {
    m_lDC[i]         = 0; 
    m_lDiff[i]       = 0;
  }
  for(i = 0;i < 4;i++) {
    m_Context[i].Init();
  }
  
  m_Coder.OpenForRead(m_Coder.ByteStreamOf(),m_Coder.ChecksumOf());

}




bool ACSequentialScan::ParseMCU(void)
{

  bool more = true;
  int c;

  assert(m_pBlockCtrl);

  bool valid = BeginReadMCU(m_Coder.ByteStreamOf());
  
  for(c = 0;c < m_ucCount;c++) {
    class Component *comp    = m_pComponent[c];
    class QuantizedRow *q    = m_pBlockCtrl->CurrentQuantizedRow(comp->IndexOf());
    LONG &prevdc             = m_lDC[c];
    LONG &prevdiff           = m_lDiff[c];
    UBYTE l                  = m_ucSmall[c];
    UBYTE u                  = m_ucLarge[c];
    UBYTE kx                 = m_ucBlockEnd[c];
    UBYTE mcux               = (m_ucCount > 1)?(comp->MCUWidthOf() ):(1);
    UBYTE mcuy               = (m_ucCount > 1)?(comp->MCUHeightOf()):(1);
    ULONG xmin               = m_ulX[c];
    ULONG xmax               = xmin + mcux;
    ULONG x,y;
    if (xmax >= q->WidthOf()) {
      more     = false;
    }
    for(y = 0;y < mcuy;y++) {
      for(x = xmin;x < xmax;x++) {
        LONG *block,dummy[64];
        if (q && x < q->WidthOf()) {
          block  = q->BlockAt(x)->m_Data;
        } else {
          block  = dummy;
        }
        if (valid) {
          DecodeBlock(block,prevdc,prevdiff,l,u,kx,m_ucDCContext[c],m_ucACContext[c]);
        } else {
          for(UBYTE i = m_ucScanStart;i <= m_ucScanStop;i++) {
            block[i] = 0;
          }
        }
      }
      if (q) q = q->NextOf();
    }
    
    m_ulX[c] = xmax;
  }

  return more;

  return false;

}






struct ACSequentialScan::QMContextSet::DCContextZeroSet &ACSequentialScan::QMContextSet::Classify(LONG diff,UBYTE l,UBYTE u)
{
  LONG abs = (diff > 0)?(diff):(-diff);
  
  if (abs <= ((1 << l) >> 1)) {
    
    return DCZero;
  }
  if (abs <= (1 << u)) {
    if (diff < 0) {
      return DCSmallNegative;
    } else {
      return DCSmallPositive;
    }
  }
  if (diff < 0) {
    return DCLargeNegative;
  } else {
    return DCLargePositive;
  }
}






void ACSequentialScan::EncodeBlock(const LONG *block, LONG &prevdc,LONG &prevdiff, UBYTE small,UBYTE large,UBYTE kx,UBYTE dc,UBYTE ac)

{
  
  if (m_ucScanStart == 0 && m_bResidual == false) {
    struct QMContextSet::DCContextZeroSet &cz = m_Context[dc].Classify(prevdiff,small,large);
    LONG diff;
    
    diff   = block[0] >> m_ucLowBit; 
    diff  -= prevdc;
    if (m_bDifferential) {
      prevdc = 0;
    } else {
      prevdc = block[0] >> m_ucLowBit;
    }

    if (diff) {
      LONG sz;
      
      
      m_Coder.Put(cz.S0,true);
      
      
      
      if (diff < 0) {
        m_Coder.Put(cz.SS,true);
        sz = -diff - 1;
      } else {
        m_Coder.Put(cz.SS,false);
        sz = diff - 1;
      }
      
      
      if (sz >= 1) {
        int  i = 0;
        LONG m = 2;
        m_Coder.Put((diff > 0)?(cz.SP):(cz.SN),true);
        
        
        while(sz >= m) {
          m_Coder.Put(m_Context[dc].DCMagnitude.X[i],true);
          m <<= 1;
          i++;
        } 
        
        m_Coder.Put(m_Context[dc].DCMagnitude.X[i],false);
        
        
        m >>= 1;
        
        while((m >>= 1)) {
          m_Coder.Put(m_Context[dc].DCMagnitude.M[i],(m & sz)?(true):(false));
        }
      } else {
        m_Coder.Put((diff > 0)?(cz.SP):(cz.SN),false);
      }
    } else {
      
      m_Coder.Put(cz.S0,false);
    }
    
    prevdiff = diff;
  }

  if (m_ucScanStop) {
    LONG data;
    int eob,k;
    
    
    
    
    eob = m_ucScanStop;
    k   = (m_ucScanStart)?(m_ucScanStart):((m_bResidual)?0:1);
    
    while(eob >= k) {
      data = block[DCT::ScanOrder[eob]];
      if ((data >= 0)?(data >> m_ucLowBit):((-data) >> m_ucLowBit))
        break;
      eob--;
    }
    
    
    eob++; 

    do {
      LONG data,sz;
      
      if (k == eob) {
        m_Coder.Put(m_Context[ac].ACZero[k-1].SE,true); 
        break;
      }
      
      m_Coder.Put(m_Context[ac].ACZero[k-1].SE,false);
      
      
      
      
      do {
        data = block[DCT::ScanOrder[k]];
        data = (data >= 0)?(data >> m_ucLowBit):(-((-data) >> m_ucLowBit));
        if (data == 0) {
          m_Coder.Put(m_Context[ac].ACZero[k-1].S0,false);
          k++;
        }
      } while(data == 0);
      m_Coder.Put(m_Context[ac].ACZero[k-1].S0,true);
      
      
      
      if (data < 0) {
        m_Coder.Put(m_Context[ac].Uniform,true);
        sz = -data - 1;
      } else {
        m_Coder.Put(m_Context[ac].Uniform,false);
        sz =  data - 1;
      }
      
      
      if (sz >= 1) {
        m_Coder.Put(m_Context[ac].ACZero[k-1].SP,true); 
        if (sz >= 2) {
          int  i = 0;
          LONG m = 4;
          struct QMContextSet::ACContextMagnitudeSet &acm = (k > kx)?(m_Context[ac].ACMagnitudeHigh):(m_Context[ac].ACMagnitudeLow);
          
          m_Coder.Put(m_Context[ac].ACZero[k-1].SP,true); 
          
          
          while(sz >= m) {
            m_Coder.Put(acm.X[i],true);
            m <<= 1;
            i++;
          }
          m_Coder.Put(acm.X[i],false);
          
          
          m >>= 1;
          
          
          while((m >>= 1)) {
            m_Coder.Put(acm.M[i],(m & sz)?true:false);
          }
        } else {
          m_Coder.Put(m_Context[ac].ACZero[k-1].SP,false);
        }
      } else {
        m_Coder.Put(m_Context[ac].ACZero[k-1].SP,false);
      }
      
      
      
    } while(++k <= m_ucScanStop);
  }
}






void ACSequentialScan::DecodeBlock(LONG *block, LONG &prevdc,LONG &prevdiff, UBYTE small,UBYTE large,UBYTE kx,UBYTE dc,UBYTE ac)

{
  
  if (m_ucScanStart == 0 && m_bResidual == false) {
    LONG diff;
    struct QMContextSet::DCContextZeroSet &cz = m_Context[dc].Classify(prevdiff,small,large);
    
    if (m_Coder.Get(cz.S0)) {
      LONG sz;
      bool sign = m_Coder.Get(cz.SS); 
      
      
      
      
      if (m_Coder.Get((sign)?(cz.SN):(cz.SP))) {
        int  i = 0;
        LONG m = 2;
        
        while(m_Coder.Get(m_Context[dc].DCMagnitude.X[i])) {
          m <<= 1;
          i++;
          if (m == 0) 
            JPG_THROW(MALFORMED_STREAM,"ACSequentialScan::DecodeBlock", "QMDecoder is out of sync");
        }
        
        
        m >>= 1;
        sz  = m;
        
        
        while((m >>= 1)) {
          if (m_Coder.Get(m_Context[dc].DCMagnitude.M[i])) {
            sz |= m;
          }
        }
      } else {
        sz = 0;
      }
      
      
      if (sign) {
        diff = -sz - 1;
      } else {
        diff = sz + 1;
      }
    } else {
      
      diff = 0;
    }

    prevdiff = diff;
    if (m_bDifferential) {
      prevdc   = diff;
    } else {
      prevdc  += diff;
    }
    block[0] = prevdc << m_ucLowBit; 
  }

  if (m_ucScanStop) {
    
    int k = (m_ucScanStart)?(m_ucScanStart):((m_bResidual)?0:1);
    
    
    while(k <= m_ucScanStop && !m_Coder.Get(m_Context[ac].ACZero[k-1].SE)) {
      LONG sz;
      bool sign;
      
      
      while(!m_Coder.Get(m_Context[ac].ACZero[k-1].S0)) {
        k++;
        if (k > m_ucScanStop)
          JPG_THROW(MALFORMED_STREAM,"ACSequentialScan::DecodeBlock", "QMDecoder is out of sync");
      }
      
      
      
      sign = m_Coder.Get(m_Context[ac].Uniform);
      
      
      if (m_Coder.Get(m_Context[ac].ACZero[k-1].SP)) {
        
        if (m_Coder.Get(m_Context[ac].ACZero[k-1].SP)) {
          int  i = 0;
          LONG m = 4;
          struct QMContextSet::ACContextMagnitudeSet &acm = (k > kx)?(m_Context[ac].ACMagnitudeHigh):(m_Context[ac].ACMagnitudeLow);
          
          while(m_Coder.Get(acm.X[i])) {
            m <<= 1;
            i++;
            if (m == 0)
              JPG_THROW(MALFORMED_STREAM,"ACSequentialScan::DecodeBlock", "QMDecoder is out of sync");
          }
          
          
          m >>= 1;
          sz  = m;
          
          
          while((m >>= 1)) {
            if (m_Coder.Get(acm.M[i])) {
              sz |= m;
            }
          }
        } else {
          sz = 1;
        }
      } else {
        sz = 0;
      }
      
      
      sz++;
      if (sign) 
        sz = -sz;
      block[DCT::ScanOrder[k]] = sz << m_ucLowBit;
      
      
      k++;
    }
  }
}





void ACSequentialScan::WriteFrameType(class ByteStream *io)
{

  UBYTE hidden = m_pFrame->TablesOf()->HiddenDCTBitsOf();

  if (m_ucScanStart > 0 || m_ucScanStop < 63 || m_ucLowBit > hidden) {
    
    if (m_bResidual) {
      io->PutWord(0xffba); 
    } else {
      if (m_bDifferential) {
        io->PutWord(0xffce);
      } else {
        io->PutWord(0xffca);
      }
    }
  } else {
    if (m_bResidual) {
      io->PutWord(0xffb9); 
    } else if (m_bDifferential) {
      io->PutWord(0xffcd); 
    } else if (m_bLargeRange) {
      io->PutWord(0xffbb);
    } else {
      io->PutWord(0xffc9); 
    }
  }

  NOREF(io);

}




void ACSequentialScan::Flush(bool)
{

  int i;
  
  m_Coder.Flush();

  for(i = 0;i < m_ucCount;i++) {
    m_lDC[i]    = 0;
    m_lDiff[i]  = 0;
  }
  for(i = 0;i < 4;i++) {
    m_Context[i].Init();
  }
  
  m_Coder.OpenForWrite(m_Coder.ByteStreamOf(),m_Coder.ChecksumOf());

}





void ACSequentialScan::OptimizeBlock(LONG, LONG, UBYTE ,double , class DCT *,LONG [64])
{
  JPG_THROW(NOT_IMPLEMENTED,"ACSequentialScan::OptimizeBlock", "Rate-distortion optimization is not implemented for arithmetic coding");
}





void ACSequentialScan::OptimizeDC(void)
{
  JPG_THROW(NOT_IMPLEMENTED,"ACSequentialScan::OptimizeDC", "Rate-distortion optimization is not implemented for arithmetic coding");
}




void ACSequentialScan::StartOptimizeScan(class BufferCtrl *)
{  
  JPG_THROW(NOT_IMPLEMENTED,"ACSequentialScan::StartOptimizeScan", "Rate-distortion optimization is not implemented for arithmetic coding");
}

