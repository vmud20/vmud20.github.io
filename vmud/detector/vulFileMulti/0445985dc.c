

























typedef struct _TIM2FileHeader {
  unsigned int magic_num;

  unsigned char format_vers, format_type;


  unsigned short image_count;
} TIM2FileHeader;

typedef struct _TIM2ImageHeader {
  unsigned int total_size, clut_size, image_size;



  unsigned short header_size, clut_color_count;


  unsigned char img_format, mipmap_count, clut_type, bpp_type;




  unsigned short width, height;


  MagickSizeType GsTex0, GsTex1;


  unsigned int GsRegs, GsTexClut;

} TIM2ImageHeader;

typedef enum {
  CSM1=0, CSM2=1, } CSM;


typedef enum {
  RGBA32=0, RGB24=1, RGBA16=2, } TIM2ColorEncoding;




static inline void ReadTIM2ImageHeader(Image *image,TIM2ImageHeader *header)
{
  header->total_size=ReadBlobLSBLong(image);
  header->clut_size=ReadBlobLSBLong(image);
  header->image_size=ReadBlobLSBLong(image);
  header->header_size=ReadBlobLSBShort(image);

  header->clut_color_count=ReadBlobLSBShort(image);
  header->img_format=(unsigned char) ReadBlobByte(image);
  header->mipmap_count=(unsigned char) ReadBlobByte(image);
  header->clut_type=(unsigned char) ReadBlobByte(image);
  header->bpp_type=(unsigned char) ReadBlobByte(image);

  header->width=ReadBlobLSBShort(image);
  header->height=ReadBlobLSBShort(image);

  header->GsTex0=ReadBlobMSBLongLong(image);
  header->GsTex1=ReadBlobMSBLongLong(image);
  header->GsRegs=ReadBlobMSBLong(image);
  header->GsTexClut=ReadBlobMSBLong(image);
}

static inline Quantum GetChannelValue(unsigned int word,unsigned char channel, TIM2ColorEncoding ce)
{
  switch(ce)
  {
    case RGBA16:
      
      return ScaleCharToQuantum((word>>channel*5 & ~(~0x0U<<5))<<3);
    case RGB24:
    case RGBA32:
      return ScaleCharToQuantum(word>>channel*8 & ~(~0x0U<<8));
    default:
      return QuantumRange;
  }
}

static inline Quantum GetAlpha(unsigned int word,TIM2ColorEncoding ce)
{
  switch(ce)
  {
    case RGBA16:
      return ScaleCharToQuantum((word>>3*5&0x1F)==0?0:0xFF);
    case RGBA32:
      
      return ScaleCharToQuantum(MagickMin((word>>3*8&0xFF)<<1,0xFF));
    default:
      return 0xFF;
  }
}

static inline void deshufflePalette(Image *image,PixelInfo* oldColormap)
{
  const size_t pages=image->colors/32, blocks=4, colors=8;



  int page;

  size_t i=0;

  (void) memcpy(oldColormap,image->colormap,(size_t)image->colors* sizeof(*oldColormap));

  
  for (page=0; page < (ssize_t) pages; page++)
  {
    memcpy(&(image->colormap[i+1*colors]),&(oldColormap[i+2*colors]),colors* sizeof(PixelInfo));
    memcpy(&(image->colormap[i+2*colors]),&(oldColormap[i+1*colors]),colors* sizeof(PixelInfo));

    i+=blocks*colors;
  }
}

static MagickBooleanType ReadTIM2ImageData(const ImageInfo *image_info, Image *image,TIM2ImageHeader *header,char clut_depth,char bits_per_pixel, ExceptionInfo *exception)

{
  MagickBooleanType status;

  ssize_t x;

  Quantum *q;

  unsigned char *p;

  size_t bits_per_line, bytes_per_line;


  ssize_t count, y;


  unsigned char *row_data;

  unsigned int word;

  status=SetImageExtent(image,image->columns,image->rows,exception);
  if (status == MagickFalse)
    return(MagickFalse);
  
  status=DiscardBlobBytes(image,header->header_size-48);
  if (status == MagickFalse)
    return(MagickFalse);
  
  bits_per_line=image->columns*bits_per_pixel;
  bytes_per_line=bits_per_line/8 + ((bits_per_line%8==0) ? 0 : 1);
  row_data=(unsigned char*) AcquireQuantumMemory(1,bytes_per_line);
  if (row_data == (unsigned char *) NULL)
    ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed", image_info->filename);
  if (clut_depth != 0)
    {
      image->colors=header->clut_color_count;
      if (AcquireImageColormap(image,image->colors,exception) == MagickFalse)
        {
          row_data=(unsigned char *) RelinquishMagickMemory(row_data);
          ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed", image_info->filename);
        }
      switch (bits_per_pixel)
      {
        case 4:
        {
          for (y=0; y<(ssize_t) image->rows; y++)
          {
            q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
            if (q == (Quantum *) NULL)
              break;
            count=ReadBlob(image,bytes_per_line,row_data);
            if (count != (ssize_t) bytes_per_line)
              {
                row_data=(unsigned char *) RelinquishMagickMemory(row_data);
                ThrowBinaryException(CorruptImageError, "InsufficientImageDataInFile",image_info->filename);
              }
            p=row_data;
            for (x=0; x < ((ssize_t) image->columns-1); x+=2)
            {
              SetPixelIndex(image,(*p >> 0) & 0x0F,q);
              q+=GetPixelChannels(image);
              SetPixelIndex(image,(*p >> 4) & 0x0F,q);
              p++;
              q+=GetPixelChannels(image);
            }
            if ((image->columns % 2) != 0)
              {
                SetPixelIndex(image,(*p >> 4) & 0x0F,q);
                p++;
                q+=GetPixelChannels(image);
              }
            if (SyncAuthenticPixels(image,exception) == MagickFalse)
              break;
            if (image->previous == (Image *) NULL)
              {
                status=SetImageProgress(image,LoadImageTag, (MagickOffsetType) y,image->rows);
                if (status == MagickFalse)
                  break;
              }
          }
          break;
        }
        case 8:
        {
          for (y=0;y<(ssize_t) image->rows; y++)
          {
            q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
            if (q == (Quantum *) NULL)
              break;
            count=ReadBlob(image,bytes_per_line,row_data);
            if (count != (ssize_t) bytes_per_line)
              {
                row_data=(unsigned char *) RelinquishMagickMemory(row_data);
                ThrowBinaryException(CorruptImageError, "InsufficientImageDataInFile",image_info->filename);
              }
            p=row_data;
            for (x=0; x < (ssize_t) image->columns; x++)
            {
              SetPixelIndex(image,*p,q);
              p++;
              q+=GetPixelChannels(image);
            }
            if (SyncAuthenticPixels(image,exception) == MagickFalse)
              break;
            if (image->previous == (Image *) NULL)
              {
                status=SetImageProgress(image,LoadImageTag, (MagickOffsetType) y,image->rows);
                if (status == MagickFalse)
                  break;
              }
          }
          break;
        }
        default:
        {
          row_data=(unsigned char *) RelinquishMagickMemory(row_data);
          ThrowBinaryException(CorruptImageError,"ImproperImageHeader", image_info->filename);
        }
      }
      SyncImage(image,exception);
    }
  else   {
      switch (bits_per_pixel)
      {
        case 16:
        {
          for (y=0; y<(ssize_t) image->rows; y++)
          {
            q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
            if (q == (Quantum *) NULL)
              break;
            count=ReadBlob(image,bytes_per_line,row_data);
            if (count != (ssize_t) bytes_per_line)
              {
                row_data=(unsigned char *) RelinquishMagickMemory(row_data);
                ThrowBinaryException(CorruptImageError, "InsufficientImageDataInFile",image_info->filename);
              }
            p=row_data;
            for (x=0; x < (ssize_t) image->columns; x++)
            {
              word = ((unsigned int)* p   )<<0*8 | ((unsigned int)*(p+1))<<1*8;

              SetPixelRed(image,GetChannelValue(word,0,RGBA16),q);
              SetPixelGreen(image,GetChannelValue(word,1,RGBA16),q);
              SetPixelBlue(image,GetChannelValue(word,2,RGBA16),q);
              SetPixelAlpha(image,GetAlpha(word,RGBA16),q);
              q+=GetPixelChannels(image);
              p+=sizeof(unsigned short);
            }
            if (SyncAuthenticPixels(image,exception) == MagickFalse)
              break;
            if (image->previous == (Image *) NULL)
              {
                status=SetImageProgress(image,LoadImageTag, (MagickOffsetType) y,image->rows);
                if (status == MagickFalse)
                  break;
              }
          }
          break;
        }
        case 24:
        {
          for (y = 0; y<(ssize_t) image->rows; y++)
          {
            q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
            if (q == (Quantum *) NULL)
              break;
            count=ReadBlob(image,bytes_per_line,row_data);
            if (count != (ssize_t) bytes_per_line)
              {
                row_data=(unsigned char *) RelinquishMagickMemory(row_data);
                ThrowBinaryException(CorruptImageError, "InsufficientImageDataInFile",image_info->filename);
              }
            p=row_data;
            for (x=0; x < (ssize_t) image->columns; x++)
            {
              word = (unsigned int)(* p   )<<0*8 | (unsigned int)(*(p+1))<<1*8 | (unsigned int)(*(p+2))<<2*8;


              SetPixelRed(image,GetChannelValue(word,0,RGB24),q);
              SetPixelGreen(image,GetChannelValue(word,1,RGB24),q);
              SetPixelBlue(image,GetChannelValue(word,2,RGB24),q);
              q+=GetPixelChannels(image);
              p+=3;
            }
            if (SyncAuthenticPixels(image,exception) == MagickFalse)
              break;
            if (image->previous == (Image *) NULL)
              {
                status=SetImageProgress(image,LoadImageTag, (MagickOffsetType) y,image->rows);
                if (status == MagickFalse)
                  break;
              }
          }
          break;
        }
        case 32:
        {  
          for (y = 0; y<(ssize_t) image->rows; y++)
          {
            q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
            if (q == (Quantum *) NULL)
              break;
            count=ReadBlob(image,bytes_per_line,row_data);
            if (count != (ssize_t) bytes_per_line)
              {
                row_data=(unsigned char *) RelinquishMagickMemory(row_data);
                ThrowBinaryException(CorruptImageError, "InsufficientImageDataInFile",image_info->filename);
              }
            p=row_data;
            for (x=0; x < (ssize_t) image->columns; x++)
            {
              word = ((unsigned int)* p   )<<0*8 | ((unsigned int)*(p+1))<<1*8 | ((unsigned int)*(p+2))<<2*8 | ((unsigned int)*(p+3))<<3*8;



              SetPixelRed(image,GetChannelValue(word,0,RGBA32),q);
              SetPixelGreen(image,GetChannelValue(word,1,RGBA32),q);
              SetPixelBlue(image,GetChannelValue(word,2,RGBA32),q);
              SetPixelAlpha(image,GetAlpha(word,RGBA32),q);
              q+=GetPixelChannels(image);
              p+=4;
            }
            if (SyncAuthenticPixels(image,exception) == MagickFalse)
              break;
            if (image->previous == (Image *) NULL)
              {
                status=SetImageProgress(image,LoadImageTag, (MagickOffsetType) y,image->rows);
                if (status == MagickFalse)
                  break;
              }
          }
          break;
        }
        default:
        {
          row_data=(unsigned char *) RelinquishMagickMemory(row_data);
          ThrowBinaryException(CorruptImageError,"ImproperImageHeader", image_info->filename);
        }
      }
    }
  row_data=(unsigned char *) RelinquishMagickMemory(row_data);
  if ((status != MagickFalse) && (clut_depth != 0))
  {
    CSM csm;

    ssize_t i;

    unsigned char *clut_data;

    
    clut_data=(unsigned char *) AcquireQuantumMemory(1,header->clut_size);
    if (clut_data == (unsigned char *) NULL)
      ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed", image_info->filename);
    count=ReadBlob(image,header->clut_size,clut_data);
    if (count != (ssize_t) (header->clut_size))
      {
        clut_data=(unsigned char *) RelinquishMagickMemory(clut_data);
        ThrowBinaryException(CorruptImageError,"InsufficientImageDataInFile", image_info->filename);
      }
    
    p=clut_data;
    switch(clut_depth)
    {
      case 16:
      {
        for (i=0; i < (ssize_t) image->colors; i++)
        {
          word = ((unsigned short)* p   )<<0*8 | ((unsigned short)*(p+1))<<1*8;

          image->colormap[i].red=GetChannelValue(word,0,RGBA16);
          image->colormap[i].green=GetChannelValue(word,1,RGBA16);
          image->colormap[i].blue=GetChannelValue(word,2,RGBA16);
          image->colormap[i].alpha=GetAlpha(word,RGBA16);
          p+=2;
        }
        break;
      }
      case 24:
      {
        for (i=0; i < (ssize_t) image->colors; i++)
        {
          word = ((unsigned int)* p   )<<0*8 | ((unsigned int)*(p+1))<<1*8 | ((unsigned int)*(p+2))<<2*8;


          image->colormap[i].red=GetChannelValue(word,0,RGB24);
          image->colormap[i].green=GetChannelValue(word,1,RGB24);
          image->colormap[i].blue=GetChannelValue(word,2,RGB24);
          p+=3;
        }
        break;
      }
      case 32:
      {
        for (i=0; i < (ssize_t) image->colors; i++)
        {
          word = ((unsigned int)* p   )<<0*8 | ((unsigned int)*(p+1))<<1*8 | ((unsigned int)*(p+2))<<2*8 | ((unsigned int)*(p+3))<<3*8;



          image->colormap[i].red=GetChannelValue(word,0,RGBA32);
          image->colormap[i].green=GetChannelValue(word,1,RGBA32);
          image->colormap[i].blue=GetChannelValue(word,2,RGBA32);
          image->colormap[i].alpha=GetAlpha(word,RGBA32);
          p+=4;
        }
        break;
      }
    }
    clut_data=(unsigned char *) RelinquishMagickMemory(clut_data);
    
    switch ((int) header->clut_type>>4)  
    {
      case 0:
        csm=CSM1;
        break;
      case 1:
        csm=CSM2;
        break;
      default:
        ThrowBinaryException(CorruptImageError,"ImproperImageHeader", image_info->filename);
        break;
    }
    if (csm == CSM1)
      {
        PixelInfo *oldColormap;

        oldColormap=(PixelInfo *) AcquireQuantumMemory((size_t)(image->colors)+ 1,sizeof(*image->colormap));
        if (oldColormap == (PixelInfo *) NULL)
          ThrowBinaryException(ResourceLimitError,"MemoryAllocationFailed", image_info->filename);
        deshufflePalette(image,oldColormap);
        RelinquishMagickMemory(oldColormap);
      }
  }
  return(status);
}

static Image *ReadTIM2Image(const ImageInfo *image_info, ExceptionInfo *exception)
{
  Image *image;

  MagickBooleanType status;

  ssize_t i;

  TIM2FileHeader file_header;

  
  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickCoreSignature);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickCoreSignature);
  if (IsEventLogging() != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s", image_info->filename);
  image=AcquireImage(image_info,exception);
  status=OpenBlob(image_info,image,ReadBinaryBlobMode,exception);
  if (status == MagickFalse)
    {
      image=DestroyImageList(image);
      return((Image *) NULL);
    }
  file_header.magic_num=ReadBlobMSBLong(image);
  if (file_header.magic_num != 0x54494D32) 
    ThrowReaderException(CorruptImageError,"ImproperImageHeader");
  file_header.format_vers=ReadBlobByte(image);
  if (file_header.format_vers != 0x04)
    ThrowReaderException(CoderError,"ImageTypeNotSupported");
  file_header.format_type=ReadBlobByte(image);
  file_header.image_count=ReadBlobLSBShort(image);
  if (DiscardBlobBytes(image,8) == MagickFalse) 
    ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
  if ((file_header.format_type > 0) && (DiscardBlobBytes(image,112) == MagickFalse))
    ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
  
  if (file_header.image_count != 1)
    ThrowReaderException(CoderError,"NumberOfImagesIsNotSupported");
  for (i=0; i < (ssize_t) file_header.image_count; i++)
  {
    char clut_depth, bits_per_pixel;


    TIM2ImageHeader image_header;

    if (i > 0)
      {
        
        if (image_info->number_scenes != 0)
          if (image->scene >= (image_info->scene+image_info->number_scenes-1))
            break;
        
        AcquireNextImage(image_info,image,exception);
        if (GetNextImageInList(image) == (Image *) NULL)
          {
            status=MagickFalse;
            break;
          }
        image=SyncNextImageInList(image);
        status=SetImageProgress(image,LoadImagesTag,image->scene-1,image->scene);
        if (status == MagickFalse)
          break;
      }
    ReadTIM2ImageHeader(image,&image_header);
    if (image_header.mipmap_count != 1)
      ThrowReaderException(CoderError,"NumberOfImagesIsNotSupported");
    if (image_header.header_size < 48)
      ThrowReaderException(CorruptImageError,"ImproperImageHeader");
    if ((MagickSizeType) image_header.image_size > GetBlobSize(image))
      ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
    if ((MagickSizeType) image_header.clut_size > GetBlobSize(image))
      ThrowReaderException(CorruptImageError,"InsufficientImageDataInFile");
    image->columns=image_header.width;
    image->rows=image_header.height;
    clut_depth=0;
    if (image_header.clut_type !=0)
      {
        switch((int) image_header.clut_type&0x0F)  
        {
          case 1:
            clut_depth=16;
            break;
          case 2:
            clut_depth=24;
            break;
          case 3:
            clut_depth=32;
            break;
          default:
            ThrowReaderException(CorruptImageError,"ImproperImageHeader");
            break;
        }
      }
    switch ((int) image_header.bpp_type)
    {
      case 1:
        bits_per_pixel=16;
        break;
      case 2:
        bits_per_pixel=24;
        break;
      case 3:
        bits_per_pixel=32;
        break;
      case 4:
        bits_per_pixel=4;  
        break;
      case 5:
        bits_per_pixel=8;  
        break;
      default:
        ThrowReaderException(CorruptImageError,"ImproperImageHeader");
        break;
    }
    image->depth=(clut_depth != 0) ? clut_depth : bits_per_pixel;
    if ((image->depth == 16) || (image->depth == 32))
      image->alpha_trait=BlendPixelTrait;
    if (image->ping == MagickFalse)
      {
        status=ReadTIM2ImageData(image_info,image,&image_header,clut_depth, bits_per_pixel,exception);
        if (status==MagickFalse)
          break;
      }
    if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
      if (image->scene >= (image_info->scene+image_info->number_scenes-1))
        break;
    if ((image->storage_class == PseudoClass) && (EOFBlob(image) != MagickFalse))
      {
        ThrowFileException(exception,CorruptImageError,"UnexpectedEndOfFile", image->filename);
        break;
      }
  }
  (void) CloseBlob(image);
  if (status == MagickFalse)
    return(DestroyImageList(image));
  return(GetFirstImageInList(image));
}


ModuleExport size_t RegisterTIM2Image(void)
{
  MagickInfo *entry;

  entry=AcquireMagickInfo("TIM2","TM2","PS2 TIM2");
  entry->decoder=(DecodeImageHandler *) ReadTIM2Image;
  (void) RegisterMagickInfo(entry);
  return(MagickImageCoderSignature);
}


ModuleExport void UnregisterTIM2Image(void)
{
  (void) UnregisterMagickInfo("TM2");
}
