






EFI_HII_IMAGE_BLOCK * GetImageIdOrAddress ( IN EFI_HII_IMAGE_BLOCK *ImageBlocks, IN OUT EFI_IMAGE_ID    *ImageId )



{
  EFI_IMAGE_ID                   ImageIdCurrent;
  EFI_HII_IMAGE_BLOCK            *CurrentImageBlock;
  UINTN                          Length;

  ASSERT (ImageBlocks != NULL && ImageId != NULL);
  CurrentImageBlock = ImageBlocks;
  ImageIdCurrent    = 1;

  while (CurrentImageBlock->BlockType != EFI_HII_IIBT_END) {
    if (*ImageId != 0) {
      if (*ImageId == ImageIdCurrent) {
        
        
        
        
        if (CurrentImageBlock->BlockType == EFI_HII_IIBT_DUPLICATE) {
          *ImageId = ReadUnaligned16 ((VOID *) &((EFI_HII_IIBT_DUPLICATE_BLOCK *) CurrentImageBlock)->ImageId);
          ASSERT (*ImageId != ImageIdCurrent);
          ASSERT (*ImageId != 0);
          CurrentImageBlock = ImageBlocks;
          ImageIdCurrent = 1;
          continue;
        }

        return CurrentImageBlock;
      }
      if (*ImageId < ImageIdCurrent) {
        
        
        
        return NULL;
      }
    }
    switch (CurrentImageBlock->BlockType) {
    case EFI_HII_IIBT_EXT1:
      Length = ((EFI_HII_IIBT_EXT1_BLOCK *) CurrentImageBlock)->Length;
      break;
    case EFI_HII_IIBT_EXT2:
      Length = ReadUnaligned16 (&((EFI_HII_IIBT_EXT2_BLOCK *) CurrentImageBlock)->Length);
      break;
    case EFI_HII_IIBT_EXT4:
      Length = ReadUnaligned32 ((VOID *) &((EFI_HII_IIBT_EXT4_BLOCK *) CurrentImageBlock)->Length);
      break;

    case EFI_HII_IIBT_IMAGE_1BIT:
    case EFI_HII_IIBT_IMAGE_1BIT_TRANS:
      Length = sizeof (EFI_HII_IIBT_IMAGE_1BIT_BLOCK) - sizeof (UINT8) + BITMAP_LEN_1_BIT ( ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_1BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width), ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_1BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height)


                 );
      ImageIdCurrent++;
      break;

    case EFI_HII_IIBT_IMAGE_4BIT:
    case EFI_HII_IIBT_IMAGE_4BIT_TRANS:
      Length = sizeof (EFI_HII_IIBT_IMAGE_4BIT_BLOCK) - sizeof (UINT8) + BITMAP_LEN_4_BIT ( ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_4BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width), ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_4BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height)


                 );
      ImageIdCurrent++;
      break;

    case EFI_HII_IIBT_IMAGE_8BIT:
    case EFI_HII_IIBT_IMAGE_8BIT_TRANS:
      Length = sizeof (EFI_HII_IIBT_IMAGE_8BIT_BLOCK) - sizeof (UINT8) + BITMAP_LEN_8_BIT ( (UINT32) ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_8BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width), ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_8BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height)


                 );
      ImageIdCurrent++;
      break;

    case EFI_HII_IIBT_IMAGE_24BIT:
    case EFI_HII_IIBT_IMAGE_24BIT_TRANS:
      Length = sizeof (EFI_HII_IIBT_IMAGE_24BIT_BLOCK) - sizeof (EFI_HII_RGB_PIXEL) + BITMAP_LEN_24_BIT ( (UINT32) ReadUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width), ReadUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height)


                 );
      ImageIdCurrent++;
      break;

    case EFI_HII_IIBT_DUPLICATE:
      Length = sizeof (EFI_HII_IIBT_DUPLICATE_BLOCK);
      ImageIdCurrent++;
      break;

    case EFI_HII_IIBT_IMAGE_JPEG:
      Length = OFFSET_OF (EFI_HII_IIBT_JPEG_BLOCK, Data) + ReadUnaligned32 ((VOID *) &((EFI_HII_IIBT_JPEG_BLOCK *) CurrentImageBlock)->Size);
      ImageIdCurrent++;
      break;

    case EFI_HII_IIBT_IMAGE_PNG:
      Length = OFFSET_OF (EFI_HII_IIBT_PNG_BLOCK, Data) + ReadUnaligned32 ((VOID *) &((EFI_HII_IIBT_PNG_BLOCK *) CurrentImageBlock)->Size);
      ImageIdCurrent++;
      break;

    case EFI_HII_IIBT_SKIP1:
      Length = sizeof (EFI_HII_IIBT_SKIP1_BLOCK);
      ImageIdCurrent += ((EFI_HII_IIBT_SKIP1_BLOCK *) CurrentImageBlock)->SkipCount;
      break;

    case EFI_HII_IIBT_SKIP2:
      Length = sizeof (EFI_HII_IIBT_SKIP2_BLOCK);
      ImageIdCurrent += ReadUnaligned16 ((VOID *) &((EFI_HII_IIBT_SKIP2_BLOCK *) CurrentImageBlock)->SkipCount);
      break;

    default:
      
      
      
      ASSERT (FALSE);
      Length = 0;
      break;
    }

    CurrentImageBlock = (EFI_HII_IMAGE_BLOCK *) ((UINT8 *) CurrentImageBlock + Length);

  }

  
  
  
  if (*ImageId == 0) {
    *ImageId = ImageIdCurrent;
    return CurrentImageBlock;
  }

  return NULL;
}




VOID CopyGopToRgbPixel ( OUT EFI_HII_RGB_PIXEL              *BitMapOut, IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BitMapIn, IN  UINTN                          PixelNum )




{
  UINTN Index;

  ASSERT (BitMapOut != NULL && BitMapIn != NULL);

  for (Index = 0; Index < PixelNum; Index++) {
    CopyMem (BitMapOut + Index, BitMapIn + Index, sizeof (EFI_HII_RGB_PIXEL));
  }
}



VOID CopyRgbToGopPixel ( OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BitMapOut, IN  EFI_HII_RGB_PIXEL              *BitMapIn, IN  UINTN                          PixelNum )




{
  UINTN Index;

  ASSERT (BitMapOut != NULL && BitMapIn != NULL);

  for (Index = 0; Index < PixelNum; Index++) {
    CopyMem (BitMapOut + Index, BitMapIn + Index, sizeof (EFI_HII_RGB_PIXEL));
  }
}



VOID Output1bitPixel ( IN OUT EFI_IMAGE_INPUT             *Image, IN UINT8                           *Data, IN EFI_HII_IMAGE_PALETTE_INFO      *PaletteInfo )




{
  UINT16                             Xpos;
  UINT16                             Ypos;
  UINTN                              OffsetY;
  UINT8                              Index;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *BitMapPtr;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      PaletteValue[2];
  EFI_HII_IMAGE_PALETTE_INFO         *Palette;
  UINTN                              PaletteSize;
  UINT8                              Byte;

  ASSERT (Image != NULL && Data != NULL && PaletteInfo != NULL);

  BitMapPtr = Image->Bitmap;

  
  
  
  PaletteSize = 0;
  CopyMem (&PaletteSize, PaletteInfo, sizeof (UINT16));
  PaletteSize += sizeof (UINT16);
  Palette = AllocateZeroPool (PaletteSize);
  ASSERT (Palette != NULL);
  if (Palette == NULL) {
    return;
  }
  CopyMem (Palette, PaletteInfo, PaletteSize);

  ZeroMem (PaletteValue, sizeof (PaletteValue));
  CopyRgbToGopPixel (&PaletteValue[0], &Palette->PaletteValue[0], 1);
  CopyRgbToGopPixel (&PaletteValue[1], &Palette->PaletteValue[1], 1);
  FreePool (Palette);

  
  
  
  for (Ypos = 0; Ypos < Image->Height; Ypos++) {
    OffsetY = BITMAP_LEN_1_BIT (Image->Width, Ypos);
    
    
    
    for (Xpos = 0; Xpos < Image->Width / 8; Xpos++) {
      Byte = *(Data + OffsetY + Xpos);
      for (Index = 0; Index < 8; Index++) {
        if ((Byte & (1 << Index)) != 0) {
          BitMapPtr[Ypos * Image->Width + Xpos * 8 + (8 - Index - 1)] = PaletteValue[1];
        } else {
          BitMapPtr[Ypos * Image->Width + Xpos * 8 + (8 - Index - 1)] = PaletteValue[0];
        }
      }
    }

    if (Image->Width % 8 != 0) {
      
      
      
      Byte = *(Data + OffsetY + Xpos);
      for (Index = 0; Index < Image->Width % 8; Index++) {
        if ((Byte & (1 << (8 - Index - 1))) != 0) {
          BitMapPtr[Ypos * Image->Width + Xpos * 8 + Index] = PaletteValue[1];
        } else {
          BitMapPtr[Ypos * Image->Width + Xpos * 8 + Index] = PaletteValue[0];
        }
      }
    }
  }
}



VOID Output4bitPixel ( IN OUT EFI_IMAGE_INPUT             *Image, IN UINT8                           *Data, IN EFI_HII_IMAGE_PALETTE_INFO      *PaletteInfo )




{
  UINT16                             Xpos;
  UINT16                             Ypos;
  UINTN                              OffsetY;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *BitMapPtr;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      PaletteValue[16];
  EFI_HII_IMAGE_PALETTE_INFO         *Palette;
  UINTN                              PaletteSize;
  UINT16                             PaletteNum;
  UINT8                              Byte;

  ASSERT (Image != NULL && Data != NULL && PaletteInfo != NULL);

  BitMapPtr = Image->Bitmap;

  
  
  
  PaletteSize = 0;
  CopyMem (&PaletteSize, PaletteInfo, sizeof (UINT16));
  PaletteSize += sizeof (UINT16);
  Palette = AllocateZeroPool (PaletteSize);
  ASSERT (Palette != NULL);
  if (Palette == NULL) {
    return;
  }
  CopyMem (Palette, PaletteInfo, PaletteSize);
  PaletteNum = (UINT16)(Palette->PaletteSize / sizeof (EFI_HII_RGB_PIXEL));

  ZeroMem (PaletteValue, sizeof (PaletteValue));
  CopyRgbToGopPixel (PaletteValue, Palette->PaletteValue, PaletteNum);
  FreePool (Palette);

  
  
  
  for (Ypos = 0; Ypos < Image->Height; Ypos++) {
    OffsetY = BITMAP_LEN_4_BIT (Image->Width, Ypos);
    
    
    
    for (Xpos = 0; Xpos < Image->Width / 2; Xpos++) {
      Byte = *(Data + OffsetY + Xpos);
      BitMapPtr[Ypos * Image->Width + Xpos * 2]     = PaletteValue[Byte >> 4];
      BitMapPtr[Ypos * Image->Width + Xpos * 2 + 1] = PaletteValue[Byte & 0x0F];
    }

    if (Image->Width % 2 != 0) {
      
      
      
      Byte = *(Data + OffsetY + Xpos);
      BitMapPtr[Ypos * Image->Width + Xpos * 2]     = PaletteValue[Byte >> 4];
    }
  }
}



VOID Output8bitPixel ( IN OUT EFI_IMAGE_INPUT             *Image, IN UINT8                           *Data, IN EFI_HII_IMAGE_PALETTE_INFO      *PaletteInfo )




{
  UINT16                             Xpos;
  UINT16                             Ypos;
  UINTN                              OffsetY;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *BitMapPtr;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      PaletteValue[256];
  EFI_HII_IMAGE_PALETTE_INFO         *Palette;
  UINTN                              PaletteSize;
  UINT16                             PaletteNum;
  UINT8                              Byte;

  ASSERT (Image != NULL && Data != NULL && PaletteInfo != NULL);

  BitMapPtr = Image->Bitmap;

  
  
  
  PaletteSize = 0;
  CopyMem (&PaletteSize, PaletteInfo, sizeof (UINT16));
  PaletteSize += sizeof (UINT16);
  Palette = AllocateZeroPool (PaletteSize);
  ASSERT (Palette != NULL);
  if (Palette == NULL) {
    return;
  }
  CopyMem (Palette, PaletteInfo, PaletteSize);
  PaletteNum = (UINT16)(Palette->PaletteSize / sizeof (EFI_HII_RGB_PIXEL));
  ZeroMem (PaletteValue, sizeof (PaletteValue));
  CopyRgbToGopPixel (PaletteValue, Palette->PaletteValue, PaletteNum);
  FreePool (Palette);

  
  
  
  for (Ypos = 0; Ypos < Image->Height; Ypos++) {
    OffsetY = BITMAP_LEN_8_BIT ((UINT32) Image->Width, Ypos);
    
    
    
    for (Xpos = 0; Xpos < Image->Width; Xpos++) {
      Byte = *(Data + OffsetY + Xpos);
      BitMapPtr[OffsetY + Xpos] = PaletteValue[Byte];
    }
  }

}



VOID Output24bitPixel ( IN OUT EFI_IMAGE_INPUT             *Image, IN EFI_HII_RGB_PIXEL               *Data )



{
  UINT16                             Ypos;
  UINTN                              OffsetY;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *BitMapPtr;

  ASSERT (Image != NULL && Data != NULL);

  BitMapPtr = Image->Bitmap;

  for (Ypos = 0; Ypos < Image->Height; Ypos++) {
    OffsetY = BITMAP_LEN_8_BIT ((UINT32) Image->Width, Ypos);
    CopyRgbToGopPixel (&BitMapPtr[OffsetY], &Data[OffsetY], Image->Width);
  }

}



EFI_STATUS ImageToBlt ( IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL   *BltBuffer, IN UINTN                           BltX, IN UINTN                           BltY, IN UINTN                           Width, IN UINTN                           Height, IN BOOLEAN                         Transparent, IN OUT EFI_IMAGE_OUTPUT            **Blt )








{
  EFI_IMAGE_OUTPUT                   *ImageOut;
  UINTN                              Xpos;
  UINTN                              Ypos;
  UINTN                              OffsetY1; 
  UINTN                              OffsetY2; 
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      SrcPixel;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      ZeroPixel;

  if (BltBuffer == NULL || Blt == NULL || *Blt == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ImageOut = *Blt;

  if (Width + BltX > ImageOut->Width) {
    return EFI_INVALID_PARAMETER;
  }
  if (Height + BltY > ImageOut->Height) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&ZeroPixel, sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL));

  for (Ypos = 0; Ypos < Height; Ypos++) {
    OffsetY1 = Width * Ypos;
    OffsetY2 = ImageOut->Width * (BltY + Ypos);
    for (Xpos = 0; Xpos < Width; Xpos++) {
      SrcPixel = BltBuffer[OffsetY1 + Xpos];
      if (Transparent) {
        if (CompareMem (&SrcPixel, &ZeroPixel, 3) != 0) {
          ImageOut->Image.Bitmap[OffsetY2 + BltX + Xpos] = SrcPixel;
        }
      } else {
        ImageOut->Image.Bitmap[OffsetY2 + BltX + Xpos] = SrcPixel;
      }
    }
  }

  return EFI_SUCCESS;
}


HII_DATABASE_PACKAGE_LIST_INSTANCE * LocatePackageList ( IN  LIST_ENTRY                     *Database, IN  EFI_HII_HANDLE                 PackageList )



{
  LIST_ENTRY                         *Link;
  HII_DATABASE_RECORD                *Record;

  
  
  
  for (Link = GetFirstNode (Database);
       !IsNull (Database, Link);
       Link = GetNextNode (Database, Link)
      ) {
    Record = CR (Link, HII_DATABASE_RECORD, DatabaseEntry, HII_DATABASE_RECORD_SIGNATURE);
    if (Record->Handle == PackageList) {
      return Record->PackageList;
    }
  }
  return NULL;
}


EFI_STATUS EFIAPI HiiNewImage ( IN  CONST EFI_HII_IMAGE_PROTOCOL   *This, IN  EFI_HII_HANDLE                 PackageList, OUT EFI_IMAGE_ID                   *ImageId, IN  CONST EFI_IMAGE_INPUT          *Image )






{
  HII_DATABASE_PRIVATE_DATA           *Private;
  HII_DATABASE_PACKAGE_LIST_INSTANCE  *PackageListNode;
  HII_IMAGE_PACKAGE_INSTANCE          *ImagePackage;
  EFI_HII_IMAGE_BLOCK                 *ImageBlocks;
  UINT32                              NewBlockSize;

  if (This == NULL || ImageId == NULL || Image == NULL || Image->Bitmap == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Private = HII_IMAGE_DATABASE_PRIVATE_DATA_FROM_THIS (This);
  PackageListNode = LocatePackageList (&Private->DatabaseList, PackageList);
  if (PackageListNode == NULL) {
    return EFI_NOT_FOUND;
  }

  EfiAcquireLock (&mHiiDatabaseLock);

  NewBlockSize = sizeof (EFI_HII_IIBT_IMAGE_24BIT_BLOCK) - sizeof (EFI_HII_RGB_PIXEL) + BITMAP_LEN_24_BIT ((UINT32) Image->Width, Image->Height);

  
  
  
  
  if (PackageListNode->ImagePkg != NULL) {
    ImagePackage = PackageListNode->ImagePkg;

    
    
    
    
    *ImageId = 0;
    GetImageIdOrAddress (ImagePackage->ImageBlock, ImageId);

    
    
    
    ImageBlocks = AllocatePool (ImagePackage->ImageBlockSize + NewBlockSize);
    if (ImageBlocks == NULL) {
      EfiReleaseLock (&mHiiDatabaseLock);
      return EFI_OUT_OF_RESOURCES;
    }
    
    
    
    CopyMem ( ImageBlocks, ImagePackage->ImageBlock, ImagePackage->ImageBlockSize - sizeof (EFI_HII_IIBT_END_BLOCK)


      );
    FreePool (ImagePackage->ImageBlock);
    ImagePackage->ImageBlock = ImageBlocks;

    
    
    
    ImageBlocks = (EFI_HII_IMAGE_BLOCK *) ( (UINT8 *) ImageBlocks + ImagePackage->ImageBlockSize - sizeof (EFI_HII_IIBT_END_BLOCK)
                    );
    
    
    
    ImagePackage->ImageBlockSize                  += NewBlockSize;
    ImagePackage->ImagePkgHdr.Header.Length       += NewBlockSize;
    PackageListNode->PackageListHdr.PackageLength += NewBlockSize;

  } else {
    
    
    
    
    ImagePackage = (HII_IMAGE_PACKAGE_INSTANCE *) AllocateZeroPool (sizeof (HII_IMAGE_PACKAGE_INSTANCE));
    if (ImagePackage == NULL) {
      EfiReleaseLock (&mHiiDatabaseLock);
      return EFI_OUT_OF_RESOURCES;
    }
    
    
    
    
    *ImageId = 1;
    
    
    
    ImagePackage->ImagePkgHdr.Header.Length     = sizeof (EFI_HII_IMAGE_PACKAGE_HDR) + NewBlockSize + sizeof (EFI_HII_IIBT_END_BLOCK);
    ImagePackage->ImagePkgHdr.Header.Type       = EFI_HII_PACKAGE_IMAGES;
    ImagePackage->ImagePkgHdr.ImageInfoOffset   = sizeof (EFI_HII_IMAGE_PACKAGE_HDR);
    ImagePackage->ImagePkgHdr.PaletteInfoOffset = 0;

    
    
    
    ImagePackage->PaletteBlock    = NULL;
    ImagePackage->PaletteInfoSize = 0;

    
    
    
    ImagePackage->ImageBlockSize = NewBlockSize + sizeof (EFI_HII_IIBT_END_BLOCK);
    ImagePackage->ImageBlock = AllocateZeroPool (NewBlockSize + sizeof (EFI_HII_IIBT_END_BLOCK));
    if (ImagePackage->ImageBlock == NULL) {
      FreePool (ImagePackage);
      EfiReleaseLock (&mHiiDatabaseLock);
      return EFI_OUT_OF_RESOURCES;
    }
    ImageBlocks = ImagePackage->ImageBlock;

    
    
    
    PackageListNode->ImagePkg = ImagePackage;
    PackageListNode->PackageListHdr.PackageLength += ImagePackage->ImagePkgHdr.Header.Length;
  }

  
  
  
  if (Image->Flags == EFI_IMAGE_TRANSPARENT) {
    ImageBlocks->BlockType = EFI_HII_IIBT_IMAGE_24BIT_TRANS;
  } else {
    ImageBlocks->BlockType = EFI_HII_IIBT_IMAGE_24BIT;
  }
  WriteUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) ImageBlocks)->Bitmap.Width, Image->Width);
  WriteUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) ImageBlocks)->Bitmap.Height, Image->Height);
  CopyGopToRgbPixel (((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) ImageBlocks)->Bitmap.Bitmap, Image->Bitmap, (UINT32) Image->Width * Image->Height);

  
  
  
  ImageBlocks = (EFI_HII_IMAGE_BLOCK *) ((UINT8 *) ImageBlocks + NewBlockSize);
  ImageBlocks->BlockType = EFI_HII_IIBT_END;

  
  
  
  
  if (gExportAfterReadyToBoot) {
    HiiGetDatabaseInfo(&Private->HiiDatabase);
  }

  EfiReleaseLock (&mHiiDatabaseLock);

  return EFI_SUCCESS;
}



EFI_STATUS IGetImage ( IN  LIST_ENTRY                     *Database, IN  EFI_HII_HANDLE                 PackageList, IN  EFI_IMAGE_ID                   ImageId, OUT EFI_IMAGE_INPUT                *Image, IN  BOOLEAN                        BitmapOnly )






{
  EFI_STATUS                          Status;
  HII_DATABASE_PACKAGE_LIST_INSTANCE  *PackageListNode;
  HII_IMAGE_PACKAGE_INSTANCE          *ImagePackage;
  EFI_HII_IMAGE_BLOCK                 *CurrentImageBlock;
  EFI_HII_IIBT_IMAGE_1BIT_BLOCK       Iibt1bit;
  UINT16                              Width;
  UINT16                              Height;
  UINTN                               ImageLength;
  UINT8                               *PaletteInfo;
  UINT8                               PaletteIndex;
  UINT16                              PaletteSize;
  EFI_HII_IMAGE_DECODER_PROTOCOL      *Decoder;
  EFI_IMAGE_OUTPUT                    *ImageOut;

  if (Image == NULL || ImageId == 0) {
    return EFI_INVALID_PARAMETER;
  }

  PackageListNode = LocatePackageList (Database, PackageList);
  if (PackageListNode == NULL) {
    return EFI_NOT_FOUND;
  }
  ImagePackage = PackageListNode->ImagePkg;
  if (ImagePackage == NULL) {
    return EFI_NOT_FOUND;
  }

  
  
  
  CurrentImageBlock = GetImageIdOrAddress (ImagePackage->ImageBlock, &ImageId);
  if (CurrentImageBlock == NULL) {
    return EFI_NOT_FOUND;
  }

  Image->Flags = 0;
  switch (CurrentImageBlock->BlockType) {
  case EFI_HII_IIBT_IMAGE_JPEG:
  case EFI_HII_IIBT_IMAGE_PNG:
    if (BitmapOnly) {
      return EFI_UNSUPPORTED;
    }

    ImageOut = NULL;
    Decoder = LocateHiiImageDecoder (CurrentImageBlock->BlockType);
    if (Decoder == NULL) {
      return EFI_UNSUPPORTED;
    }
    
    
    
    ASSERT (OFFSET_OF (EFI_HII_IIBT_JPEG_BLOCK, Data) == OFFSET_OF (EFI_HII_IIBT_PNG_BLOCK, Data));
    ASSERT (sizeof (((EFI_HII_IIBT_JPEG_BLOCK *) CurrentImageBlock)->Data) == sizeof (((EFI_HII_IIBT_PNG_BLOCK *) CurrentImageBlock)->Data));
    ASSERT (OFFSET_OF (EFI_HII_IIBT_JPEG_BLOCK, Size) == OFFSET_OF (EFI_HII_IIBT_PNG_BLOCK, Size));
    ASSERT (sizeof (((EFI_HII_IIBT_JPEG_BLOCK *) CurrentImageBlock)->Size) == sizeof (((EFI_HII_IIBT_PNG_BLOCK *) CurrentImageBlock)->Size));
    Status = Decoder->DecodeImage ( Decoder, ((EFI_HII_IIBT_JPEG_BLOCK *) CurrentImageBlock)->Data, ((EFI_HII_IIBT_JPEG_BLOCK *) CurrentImageBlock)->Size, &ImageOut, FALSE );






    
    
    
    
    if (!EFI_ERROR (Status)) {
      Image->Bitmap = ImageOut->Image.Bitmap;
      Image->Height = ImageOut->Height;
      Image->Width = ImageOut->Width;
      FreePool (ImageOut);
    }
    return Status;

  case EFI_HII_IIBT_IMAGE_1BIT_TRANS:
  case EFI_HII_IIBT_IMAGE_4BIT_TRANS:
  case EFI_HII_IIBT_IMAGE_8BIT_TRANS:
    Image->Flags = EFI_IMAGE_TRANSPARENT;
    
    
    
  case EFI_HII_IIBT_IMAGE_1BIT:
  case EFI_HII_IIBT_IMAGE_4BIT:
  case EFI_HII_IIBT_IMAGE_8BIT:
    
    
    
    CopyMem (&Iibt1bit, CurrentImageBlock, sizeof (EFI_HII_IIBT_IMAGE_1BIT_BLOCK));
    ImageLength = sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL) * ((UINT32) Iibt1bit.Bitmap.Width * Iibt1bit.Bitmap.Height);
    Image->Bitmap = AllocateZeroPool (ImageLength);
    if (Image->Bitmap == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Image->Width  = Iibt1bit.Bitmap.Width;
    Image->Height = Iibt1bit.Bitmap.Height;

    PaletteInfo = ImagePackage->PaletteBlock + sizeof (EFI_HII_IMAGE_PALETTE_INFO_HEADER);
    for (PaletteIndex = 1; PaletteIndex < Iibt1bit.PaletteIndex; PaletteIndex++) {
      CopyMem (&PaletteSize, PaletteInfo, sizeof (UINT16));
      PaletteInfo += PaletteSize + sizeof (UINT16);
    }
    ASSERT (PaletteIndex == Iibt1bit.PaletteIndex);

    
    
    
    if (CurrentImageBlock->BlockType == EFI_HII_IIBT_IMAGE_1BIT || CurrentImageBlock->BlockType == EFI_HII_IIBT_IMAGE_1BIT_TRANS) {
      Output1bitPixel ( Image, ((EFI_HII_IIBT_IMAGE_1BIT_BLOCK *) CurrentImageBlock)->Bitmap.Data, (EFI_HII_IMAGE_PALETTE_INFO *) PaletteInfo );



    } else if (CurrentImageBlock->BlockType == EFI_HII_IIBT_IMAGE_4BIT || CurrentImageBlock->BlockType == EFI_HII_IIBT_IMAGE_4BIT_TRANS) {
      Output4bitPixel ( Image, ((EFI_HII_IIBT_IMAGE_4BIT_BLOCK *) CurrentImageBlock)->Bitmap.Data, (EFI_HII_IMAGE_PALETTE_INFO *) PaletteInfo );



    } else {
      Output8bitPixel ( Image, ((EFI_HII_IIBT_IMAGE_8BIT_BLOCK *) CurrentImageBlock)->Bitmap.Data, (EFI_HII_IMAGE_PALETTE_INFO *) PaletteInfo );



    }

    return EFI_SUCCESS;

  case EFI_HII_IIBT_IMAGE_24BIT_TRANS:
    Image->Flags = EFI_IMAGE_TRANSPARENT;
    
    
    
  case EFI_HII_IIBT_IMAGE_24BIT:
    Width = ReadUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width);
    Height = ReadUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height);
    ImageLength = sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL) * ((UINT32) Width * Height);
    Image->Bitmap = AllocateZeroPool (ImageLength);
    if (Image->Bitmap == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Image->Width  = Width;
    Image->Height = Height;

    
    
    
    Output24bitPixel ( Image, ((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) CurrentImageBlock)->Bitmap.Bitmap );


    return EFI_SUCCESS;

  default:
    return EFI_NOT_FOUND;
  }
}


EFI_STATUS EFIAPI HiiGetImage ( IN  CONST EFI_HII_IMAGE_PROTOCOL   *This, IN  EFI_HII_HANDLE                 PackageList, IN  EFI_IMAGE_ID                   ImageId, OUT EFI_IMAGE_INPUT                *Image )






{
  HII_DATABASE_PRIVATE_DATA           *Private;
  Private = HII_IMAGE_DATABASE_PRIVATE_DATA_FROM_THIS (This);
  return IGetImage (&Private->DatabaseList, PackageList, ImageId, Image, TRUE);
}



EFI_STATUS EFIAPI HiiSetImage ( IN CONST EFI_HII_IMAGE_PROTOCOL    *This, IN EFI_HII_HANDLE                  PackageList, IN EFI_IMAGE_ID                    ImageId, IN CONST EFI_IMAGE_INPUT           *Image )






{
  HII_DATABASE_PRIVATE_DATA           *Private;
  HII_DATABASE_PACKAGE_LIST_INSTANCE  *PackageListNode;
  HII_IMAGE_PACKAGE_INSTANCE          *ImagePackage;
  EFI_HII_IMAGE_BLOCK                 *CurrentImageBlock;
  EFI_HII_IMAGE_BLOCK                 *ImageBlocks;
  EFI_HII_IMAGE_BLOCK                 *NewImageBlock;
  UINT32                              NewBlockSize;
  UINT32                              OldBlockSize;
  UINT32                               Part1Size;
  UINT32                               Part2Size;

  if (This == NULL || Image == NULL || ImageId == 0 || Image->Bitmap == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Private = HII_IMAGE_DATABASE_PRIVATE_DATA_FROM_THIS (This);
  PackageListNode = LocatePackageList (&Private->DatabaseList, PackageList);
  if (PackageListNode == NULL) {
    return EFI_NOT_FOUND;
  }
  ImagePackage = PackageListNode->ImagePkg;
  if (ImagePackage == NULL) {
    return EFI_NOT_FOUND;
  }

  
  
  
  CurrentImageBlock = GetImageIdOrAddress (ImagePackage->ImageBlock, &ImageId);
  if (CurrentImageBlock == NULL) {
    return EFI_NOT_FOUND;
  }

  EfiAcquireLock (&mHiiDatabaseLock);

  
  
  
  
  switch (CurrentImageBlock->BlockType) {
  case EFI_HII_IIBT_IMAGE_JPEG:
    OldBlockSize = OFFSET_OF (EFI_HII_IIBT_JPEG_BLOCK, Data) + ReadUnaligned32 ((VOID *) &((EFI_HII_IIBT_JPEG_BLOCK *) CurrentImageBlock)->Size);
    break;
  case EFI_HII_IIBT_IMAGE_PNG:
    OldBlockSize = OFFSET_OF (EFI_HII_IIBT_PNG_BLOCK, Data) + ReadUnaligned32 ((VOID *) &((EFI_HII_IIBT_PNG_BLOCK *) CurrentImageBlock)->Size);
    break;
  case EFI_HII_IIBT_IMAGE_1BIT:
  case EFI_HII_IIBT_IMAGE_1BIT_TRANS:
    OldBlockSize = sizeof (EFI_HII_IIBT_IMAGE_1BIT_BLOCK) - sizeof (UINT8) + BITMAP_LEN_1_BIT ( ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_1BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width), ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_1BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height)


                     );
    break;
  case EFI_HII_IIBT_IMAGE_4BIT:
  case EFI_HII_IIBT_IMAGE_4BIT_TRANS:
    OldBlockSize = sizeof (EFI_HII_IIBT_IMAGE_4BIT_BLOCK) - sizeof (UINT8) + BITMAP_LEN_4_BIT ( ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_4BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width), ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_4BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height)


                     );
    break;
  case EFI_HII_IIBT_IMAGE_8BIT:
  case EFI_HII_IIBT_IMAGE_8BIT_TRANS:
    OldBlockSize = sizeof (EFI_HII_IIBT_IMAGE_8BIT_BLOCK) - sizeof (UINT8) + BITMAP_LEN_8_BIT ( (UINT32) ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_8BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width), ReadUnaligned16 (&((EFI_HII_IIBT_IMAGE_8BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height)


                     );
    break;
  case EFI_HII_IIBT_IMAGE_24BIT:
  case EFI_HII_IIBT_IMAGE_24BIT_TRANS:
    OldBlockSize = sizeof (EFI_HII_IIBT_IMAGE_24BIT_BLOCK) - sizeof (EFI_HII_RGB_PIXEL) + BITMAP_LEN_24_BIT ( (UINT32) ReadUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) CurrentImageBlock)->Bitmap.Width), ReadUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) CurrentImageBlock)->Bitmap.Height)


                     );
    break;
  default:
    EfiReleaseLock (&mHiiDatabaseLock);
    return EFI_NOT_FOUND;
  }

  
  
  
  NewBlockSize = sizeof (EFI_HII_IIBT_IMAGE_24BIT_BLOCK) - sizeof (EFI_HII_RGB_PIXEL) + BITMAP_LEN_24_BIT ((UINT32) Image->Width, Image->Height);
  
  
  
  ImageBlocks = AllocateZeroPool (ImagePackage->ImageBlockSize + NewBlockSize - OldBlockSize);
  if (ImageBlocks == NULL) {
    EfiReleaseLock (&mHiiDatabaseLock);
    return EFI_OUT_OF_RESOURCES;
  }

  Part1Size = (UINT32) ((UINTN) CurrentImageBlock - (UINTN) ImagePackage->ImageBlock);
  Part2Size = ImagePackage->ImageBlockSize - Part1Size - OldBlockSize;
  CopyMem (ImageBlocks, ImagePackage->ImageBlock, Part1Size);

  
  
  
  NewImageBlock = (EFI_HII_IMAGE_BLOCK *) ((UINT8 *) ImageBlocks + Part1Size);
  if ((Image->Flags & EFI_IMAGE_TRANSPARENT) == EFI_IMAGE_TRANSPARENT) {
    NewImageBlock->BlockType= EFI_HII_IIBT_IMAGE_24BIT_TRANS;
  } else {
    NewImageBlock->BlockType = EFI_HII_IIBT_IMAGE_24BIT;
  }
  WriteUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) NewImageBlock)->Bitmap.Width, Image->Width);
  WriteUnaligned16 ((VOID *) &((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) NewImageBlock)->Bitmap.Height, Image->Height);
  CopyGopToRgbPixel (((EFI_HII_IIBT_IMAGE_24BIT_BLOCK *) NewImageBlock)->Bitmap.Bitmap, Image->Bitmap, (UINT32) Image->Width * Image->Height);

  CopyMem ((UINT8 *) NewImageBlock + NewBlockSize, (UINT8 *) CurrentImageBlock + OldBlockSize, Part2Size);

  FreePool (ImagePackage->ImageBlock);
  ImagePackage->ImageBlock                       = ImageBlocks;
  ImagePackage->ImageBlockSize                  += NewBlockSize - OldBlockSize;
  ImagePackage->ImagePkgHdr.Header.Length       += NewBlockSize - OldBlockSize;
  PackageListNode->PackageListHdr.PackageLength += NewBlockSize - OldBlockSize;

  
  
  
  
  if (gExportAfterReadyToBoot) {
    HiiGetDatabaseInfo(&Private->HiiDatabase);
  }

  EfiReleaseLock (&mHiiDatabaseLock);
  return EFI_SUCCESS;

}



EFI_STATUS EFIAPI HiiDrawImage ( IN CONST EFI_HII_IMAGE_PROTOCOL    *This, IN EFI_HII_DRAW_FLAGS              Flags, IN CONST EFI_IMAGE_INPUT           *Image, IN OUT EFI_IMAGE_OUTPUT            **Blt, IN UINTN                           BltX, IN UINTN                           BltY )








{
  EFI_STATUS                          Status;
  HII_DATABASE_PRIVATE_DATA           *Private;
  BOOLEAN                             Transparent;
  EFI_IMAGE_OUTPUT                    *ImageOut;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL       *BltBuffer;
  UINTN                               BufferLen;
  UINTN                               Width;
  UINTN                               Height;
  UINTN                               Xpos;
  UINTN                               Ypos;
  UINTN                               OffsetY1;
  UINTN                               OffsetY2;
  EFI_FONT_DISPLAY_INFO               *FontInfo;
  UINTN                               Index;

  if (This == NULL || Image == NULL || Blt == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Flags & EFI_HII_DRAW_FLAG_CLIP) == EFI_HII_DRAW_FLAG_CLIP && *Blt == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Flags & EFI_HII_DRAW_FLAG_TRANSPARENT) == EFI_HII_DRAW_FLAG_TRANSPARENT) {
    return EFI_INVALID_PARAMETER;
  }

  FontInfo = NULL;

  
  
  
  Transparent = FALSE;
  if ((Flags & EFI_HII_DRAW_FLAG_TRANSPARENT) == EFI_HII_DRAW_FLAG_FORCE_TRANS) {
    Transparent = TRUE;
  } else if ((Flags & EFI_HII_DRAW_FLAG_TRANSPARENT) == EFI_HII_DRAW_FLAG_FORCE_OPAQUE){
    Transparent = FALSE;
  } else {
    
    
    
    
    if ((Image->Flags & EFI_IMAGE_TRANSPARENT) == EFI_IMAGE_TRANSPARENT) {
      Transparent = TRUE;
    }
  }

  
  
  
  
  if (Transparent) {
    if (*Blt == NULL) {
      return EFI_INVALID_PARAMETER;
    } else if ((Flags & EFI_HII_DIRECT_TO_SCREEN) == EFI_HII_DIRECT_TO_SCREEN) {
      return EFI_INVALID_PARAMETER;
    }
  }

  Private = HII_IMAGE_DATABASE_PRIVATE_DATA_FROM_THIS (This);

  
  
  
  
  
  if (*Blt != NULL) {
    
    
    

    Width  = Image->Width;
    Height = Image->Height;

    if (Width > (*Blt)->Width - BltX) {
      Width = (*Blt)->Width - BltX;
    }
    if (Height > (*Blt)->Height - BltY) {
      Height = (*Blt)->Height - BltY;
    }

    BufferLen = Width * Height * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
    BltBuffer = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *) AllocateZeroPool (BufferLen);
    if (BltBuffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    if (Width == Image->Width && Height == Image->Height) {
      CopyMem (BltBuffer, Image->Bitmap, BufferLen);
    } else {
      for (Ypos = 0; Ypos < Height; Ypos++) {
        OffsetY1 = Image->Width * Ypos;
        OffsetY2 = Width * Ypos;
        for (Xpos = 0; Xpos < Width; Xpos++) {
          BltBuffer[OffsetY2 + Xpos] = Image->Bitmap[OffsetY1 + Xpos];
        }
      }
    }

    
    
    
    if ((Flags & EFI_HII_DIRECT_TO_SCREEN) == EFI_HII_DIRECT_TO_SCREEN) {
      
      
      

      
      
      
      Status = (*Blt)->Image.Screen->Blt ( (*Blt)->Image.Screen, BltBuffer, EfiBltBufferToVideo, 0, 0, BltX, BltY, Width, Height, 0 );










    } else {
      
      
      
      Status = ImageToBlt ( BltBuffer, BltX, BltY, Width, Height, Transparent, Blt );








    }

    FreePool (BltBuffer);
    return Status;

  } else {
    
    
    
    Width  = Image->Width  + BltX;
    Height = Image->Height + BltY;

    BufferLen = Width * Height * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
    BltBuffer = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *) AllocateZeroPool (BufferLen);
    if (BltBuffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    ImageOut = (EFI_IMAGE_OUTPUT *) AllocateZeroPool (sizeof (EFI_IMAGE_OUTPUT));
    if (ImageOut == NULL) {
      FreePool (BltBuffer);
      return EFI_OUT_OF_RESOURCES;
    }
    ImageOut->Width        = (UINT16) Width;
    ImageOut->Height       = (UINT16) Height;
    ImageOut->Image.Bitmap = BltBuffer;

    
    
    
    
    Status = GetSystemFont (Private, &FontInfo, NULL);
    if (EFI_ERROR (Status)) {
      FreePool (BltBuffer);
      FreePool (ImageOut);
      return Status;
    }
    ASSERT (FontInfo != NULL);
    for (Index = 0; Index < Width * Height; Index++) {
      BltBuffer[Index] = FontInfo->BackgroundColor;
    }
    FreePool (FontInfo);

    
    
    
    *Blt = ImageOut;
    return ImageToBlt ( Image->Bitmap, BltX, BltY, Image->Width, Image->Height, Transparent, Blt );








  }
}



EFI_STATUS EFIAPI HiiDrawImageId ( IN CONST EFI_HII_IMAGE_PROTOCOL    *This, IN EFI_HII_DRAW_FLAGS              Flags, IN EFI_HII_HANDLE                  PackageList, IN EFI_IMAGE_ID                    ImageId, IN OUT EFI_IMAGE_OUTPUT            **Blt, IN UINTN                           BltX, IN UINTN                           BltY )









{
  EFI_STATUS                          Status;
  EFI_IMAGE_INPUT                     Image;

  
  
  
  if (This == NULL || Blt == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  
  
  
  Status = HiiGetImage (This, PackageList, ImageId, &Image);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  Status = HiiDrawImage (This, Flags, &Image, Blt, BltX, BltY);
  if (Image.Bitmap != NULL) {
    FreePool (Image.Bitmap);
  }
  return Status;
}

