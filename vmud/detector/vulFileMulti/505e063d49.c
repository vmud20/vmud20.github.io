




CHAR16 mLanguageWindow[16] = {
  0x0000, 0x0080, 0x0100, 0x0300, 0x2000, 0x2080, 0x2100, 0x3000, 0x0080, 0x00C0, 0x0400, 0x0600, 0x0900, 0x3040, 0x30A0, 0xFF00 };






BOOLEAN ReferFontInfoLocally ( IN  HII_DATABASE_PRIVATE_DATA   *Private, IN  HII_STRING_PACKAGE_INSTANCE *StringPackage, IN  UINT8                       FontId, IN  BOOLEAN                     DuplicateEnable, IN  HII_GLOBAL_FONT_INFO        *GlobalFontInfo, OUT HII_FONT_INFO               **LocalFontInfo )







{
  HII_FONT_INFO                 *LocalFont;
  LIST_ENTRY                    *Link;

  ASSERT (Private != NULL && StringPackage != NULL && GlobalFontInfo != NULL && LocalFontInfo != NULL);

  if (!DuplicateEnable) {
    for (Link = StringPackage->FontInfoList.ForwardLink;
         Link != &StringPackage->FontInfoList;
         Link = Link->ForwardLink ) {
      LocalFont = CR (Link, HII_FONT_INFO, Entry, HII_FONT_INFO_SIGNATURE);
      if (LocalFont->GlobalEntry == &GlobalFontInfo->Entry) {
        
        
        
        *LocalFontInfo = LocalFont;
        return TRUE;
      }
    }
  }
  
  
  
  
  LocalFont = (HII_FONT_INFO *) AllocateZeroPool (sizeof (HII_FONT_INFO));
  ASSERT (LocalFont != NULL);

  LocalFont->Signature   = HII_FONT_INFO_SIGNATURE;
  LocalFont->FontId      = FontId;
  LocalFont->GlobalEntry = &GlobalFontInfo->Entry;
  InsertTailList (&StringPackage->FontInfoList, &LocalFont->Entry);

  *LocalFontInfo = LocalFont;
  return FALSE;
}



EFI_STATUS ConvertToUnicodeText ( OUT EFI_STRING       StringDest, IN  CHAR8            *StringSrc, IN  OUT UINTN        *BufferSize )




{
  UINTN  StringSize;
  UINTN  Index;

  ASSERT (StringSrc != NULL && BufferSize != NULL);

  StringSize = AsciiStrSize (StringSrc) * 2;
  if (*BufferSize < StringSize || StringDest == NULL) {
    *BufferSize = StringSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  for (Index = 0; Index < AsciiStrLen (StringSrc); Index++) {
    StringDest[Index] = (CHAR16) StringSrc[Index];
  }

  StringDest[Index] = 0;
  return EFI_SUCCESS;
}



EFI_STATUS GetUnicodeStringTextOrSize ( OUT EFI_STRING       StringDest, OPTIONAL IN  UINT8            *StringSrc, IN  OUT UINTN        *BufferSize )




{
  UINTN  StringSize;
  UINT8  *StringPtr;

  ASSERT (StringSrc != NULL && BufferSize != NULL);

  StringSize = sizeof (CHAR16);
  StringPtr  = StringSrc;
  while (ReadUnaligned16 ((UINT16 *) StringPtr) != 0) {
    StringSize += sizeof (CHAR16);
    StringPtr += sizeof (CHAR16);
  }

  if (*BufferSize < StringSize) {
    *BufferSize = StringSize;
    return EFI_BUFFER_TOO_SMALL;
  }
  if (StringDest != NULL) {
    CopyMem (StringDest, StringSrc, StringSize);
  }

  *BufferSize = StringSize;
  return EFI_SUCCESS;
}



EFI_STATUS GetStringFontInfo ( IN  HII_STRING_PACKAGE_INSTANCE     *StringPackage, IN  UINT8                           FontId, OUT EFI_FONT_INFO                   **StringFontInfo )




{
  LIST_ENTRY                           *Link;
  HII_FONT_INFO                        *FontInfo;
  HII_GLOBAL_FONT_INFO                 *GlobalFont;

  ASSERT (StringFontInfo != NULL && StringPackage != NULL);

  for (Link = StringPackage->FontInfoList.ForwardLink; Link != &StringPackage->FontInfoList; Link = Link->ForwardLink) {
    FontInfo = CR (Link, HII_FONT_INFO, Entry, HII_FONT_INFO_SIGNATURE);
    if (FontInfo->FontId == FontId) {
      GlobalFont = CR (FontInfo->GlobalEntry, HII_GLOBAL_FONT_INFO, Entry, HII_GLOBAL_FONT_INFO_SIGNATURE);
      *StringFontInfo = (EFI_FONT_INFO *) AllocateZeroPool (GlobalFont->FontInfoSize);
      if (*StringFontInfo == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem (*StringFontInfo, GlobalFont->FontInfo, GlobalFont->FontInfoSize);
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}



EFI_STATUS FindStringBlock ( IN HII_DATABASE_PRIVATE_DATA        *Private, IN  HII_STRING_PACKAGE_INSTANCE     *StringPackage, IN  EFI_STRING_ID                   StringId, OUT UINT8                           *BlockType, OPTIONAL OUT UINT8                           **StringBlockAddr, OPTIONAL OUT UINTN                           *StringTextOffset, OPTIONAL OUT EFI_STRING_ID                   *LastStringId, OPTIONAL OUT EFI_STRING_ID                   *StartStringId OPTIONAL )









{
  UINT8                                *BlockHdr;
  EFI_STRING_ID                        CurrentStringId;
  UINTN                                BlockSize;
  UINTN                                Index;
  UINT8                                *StringTextPtr;
  UINTN                                Offset;
  HII_FONT_INFO                        *LocalFont;
  EFI_FONT_INFO                        *FontInfo;
  HII_GLOBAL_FONT_INFO                 *GlobalFont;
  UINTN                                FontInfoSize;
  UINT16                               StringCount;
  UINT16                               SkipCount;
  EFI_HII_FONT_STYLE                   FontStyle;
  UINT16                               FontSize;
  UINT8                                Length8;
  EFI_HII_SIBT_EXT2_BLOCK              Ext2;
  UINT8                                FontId;
  UINT32                               Length32;
  UINTN                                StringSize;
  CHAR16                               Zero;

  ASSERT (StringPackage != NULL);
  ASSERT (StringPackage->Signature == HII_STRING_PACKAGE_SIGNATURE);

  CurrentStringId = 1;
  StringSize = 0;

  if (StringId != (EFI_STRING_ID) (-1) && StringId != 0) {
    ASSERT (BlockType != NULL && StringBlockAddr != NULL && StringTextOffset != NULL);
    if (StringId > StringPackage->MaxStringId) {
      return EFI_NOT_FOUND;
    }
  } else {
    ASSERT (Private != NULL && Private->Signature == HII_DATABASE_PRIVATE_DATA_SIGNATURE);
    if (StringId == 0 && LastStringId != NULL) {
      *LastStringId = StringPackage->MaxStringId;
      return EFI_SUCCESS;
    }
  }

  ZeroMem (&Zero, sizeof (CHAR16));

  
  
  
  BlockHdr  = StringPackage->StringBlock;
  BlockSize = 0;
  Offset    = 0;
  while (*BlockHdr != EFI_HII_SIBT_END) {
    switch (*BlockHdr) {
    case EFI_HII_SIBT_STRING_SCSU:
      Offset = sizeof (EFI_HII_STRING_BLOCK);
      StringTextPtr = BlockHdr + Offset;
      BlockSize += Offset + AsciiStrSize ((CHAR8 *) StringTextPtr);
      CurrentStringId++;
      break;

    case EFI_HII_SIBT_STRING_SCSU_FONT:
      Offset = sizeof (EFI_HII_SIBT_STRING_SCSU_FONT_BLOCK) - sizeof (UINT8);
      StringTextPtr = BlockHdr + Offset;
      BlockSize += Offset + AsciiStrSize ((CHAR8 *) StringTextPtr);
      CurrentStringId++;
      break;

    case EFI_HII_SIBT_STRINGS_SCSU:
      CopyMem (&StringCount, BlockHdr + sizeof (EFI_HII_STRING_BLOCK), sizeof (UINT16));
      StringTextPtr = (UINT8*)((UINTN)BlockHdr + sizeof (EFI_HII_SIBT_STRINGS_SCSU_BLOCK) - sizeof (UINT8));
      BlockSize += StringTextPtr - BlockHdr;

      for (Index = 0; Index < StringCount; Index++) {
        BlockSize += AsciiStrSize ((CHAR8 *) StringTextPtr);
        if (CurrentStringId == StringId) {
          ASSERT (BlockType != NULL && StringBlockAddr != NULL && StringTextOffset != NULL);
          *BlockType        = *BlockHdr;
          *StringBlockAddr  = BlockHdr;
          *StringTextOffset = StringTextPtr - BlockHdr;
          return EFI_SUCCESS;
        }
        StringTextPtr = StringTextPtr + AsciiStrSize ((CHAR8 *) StringTextPtr);
        CurrentStringId++;
      }
      break;

    case EFI_HII_SIBT_STRINGS_SCSU_FONT:
      CopyMem ( &StringCount, (UINT8*)((UINTN)BlockHdr + sizeof (EFI_HII_STRING_BLOCK) + sizeof (UINT8)), sizeof (UINT16)


        );
      StringTextPtr = (UINT8*)((UINTN)BlockHdr + sizeof (EFI_HII_SIBT_STRINGS_SCSU_FONT_BLOCK) - sizeof (UINT8));
      BlockSize += StringTextPtr - BlockHdr;

      for (Index = 0; Index < StringCount; Index++) {
        BlockSize += AsciiStrSize ((CHAR8 *) StringTextPtr);
        if (CurrentStringId == StringId) {
          ASSERT (BlockType != NULL && StringBlockAddr != NULL && StringTextOffset != NULL);
          *BlockType        = *BlockHdr;
          *StringBlockAddr  = BlockHdr;
          *StringTextOffset = StringTextPtr - BlockHdr;
          return EFI_SUCCESS;
        }
        StringTextPtr = StringTextPtr + AsciiStrSize ((CHAR8 *) StringTextPtr);
        CurrentStringId++;
      }
      break;

    case EFI_HII_SIBT_STRING_UCS2:
      Offset        = sizeof (EFI_HII_STRING_BLOCK);
      StringTextPtr = BlockHdr + Offset;
      
      
      
      
      GetUnicodeStringTextOrSize (NULL, StringTextPtr, &StringSize);
      BlockSize += Offset + StringSize;
      CurrentStringId++;
      break;

    case EFI_HII_SIBT_STRING_UCS2_FONT:
      Offset = sizeof (EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK)  - sizeof (CHAR16);
      StringTextPtr = BlockHdr + Offset;
      
      
      
      
      GetUnicodeStringTextOrSize (NULL, StringTextPtr, &StringSize);
      BlockSize += Offset + StringSize;
      CurrentStringId++;
      break;

    case EFI_HII_SIBT_STRINGS_UCS2:
      Offset = sizeof (EFI_HII_SIBT_STRINGS_UCS2_BLOCK) - sizeof (CHAR16);
      StringTextPtr = BlockHdr + Offset;
      BlockSize += Offset;
      CopyMem (&StringCount, BlockHdr + sizeof (EFI_HII_STRING_BLOCK), sizeof (UINT16));
      for (Index = 0; Index < StringCount; Index++) {
        GetUnicodeStringTextOrSize (NULL, StringTextPtr, &StringSize);
        BlockSize += StringSize;
        if (CurrentStringId == StringId) {
          ASSERT (BlockType != NULL && StringBlockAddr != NULL && StringTextOffset != NULL);
          *BlockType        = *BlockHdr;
          *StringBlockAddr  = BlockHdr;
          *StringTextOffset = StringTextPtr - BlockHdr;
          return EFI_SUCCESS;
        }
        StringTextPtr = StringTextPtr + StringSize;
        CurrentStringId++;
      }
      break;

    case EFI_HII_SIBT_STRINGS_UCS2_FONT:
      Offset = sizeof (EFI_HII_SIBT_STRINGS_UCS2_FONT_BLOCK) - sizeof (CHAR16);
      StringTextPtr = BlockHdr + Offset;
      BlockSize += Offset;
      CopyMem ( &StringCount, (UINT8*)((UINTN)BlockHdr + sizeof (EFI_HII_STRING_BLOCK) + sizeof (UINT8)), sizeof (UINT16)


        );
      for (Index = 0; Index < StringCount; Index++) {
        GetUnicodeStringTextOrSize (NULL, StringTextPtr, &StringSize);
        BlockSize += StringSize;
        if (CurrentStringId == StringId) {
          ASSERT (BlockType != NULL && StringBlockAddr != NULL && StringTextOffset != NULL);
          *BlockType        = *BlockHdr;
          *StringBlockAddr  = BlockHdr;
          *StringTextOffset = StringTextPtr - BlockHdr;
          return EFI_SUCCESS;
        }
        StringTextPtr = StringTextPtr + StringSize;
        CurrentStringId++;
      }
      break;

    case EFI_HII_SIBT_DUPLICATE:
      if (CurrentStringId == StringId) {
        
        
        
        
        
        CopyMem ( &StringId, BlockHdr + sizeof (EFI_HII_STRING_BLOCK), sizeof (EFI_STRING_ID)


          );
        ASSERT (StringId != CurrentStringId);
        CurrentStringId = 1;
        BlockSize       = 0;
      } else {
        BlockSize       += sizeof (EFI_HII_SIBT_DUPLICATE_BLOCK);
        CurrentStringId++;
      }
      break;

    case EFI_HII_SIBT_SKIP1:
      SkipCount = (UINT16) (*(UINT8*)((UINTN)BlockHdr + sizeof (EFI_HII_STRING_BLOCK)));
      CurrentStringId = (UINT16) (CurrentStringId + SkipCount);
      BlockSize       +=  sizeof (EFI_HII_SIBT_SKIP1_BLOCK);
      break;

    case EFI_HII_SIBT_SKIP2:
      CopyMem (&SkipCount, BlockHdr + sizeof (EFI_HII_STRING_BLOCK), sizeof (UINT16));
      CurrentStringId = (UINT16) (CurrentStringId + SkipCount);
      BlockSize       +=  sizeof (EFI_HII_SIBT_SKIP2_BLOCK);
      break;

    case EFI_HII_SIBT_EXT1:
      CopyMem ( &Length8, (UINT8*)((UINTN)BlockHdr + sizeof (EFI_HII_STRING_BLOCK) + sizeof (UINT8)), sizeof (UINT8)


        );
      BlockSize += Length8;
      break;

    case EFI_HII_SIBT_EXT2:
      CopyMem (&Ext2, BlockHdr, sizeof (EFI_HII_SIBT_EXT2_BLOCK));
      if (Ext2.BlockType2 == EFI_HII_SIBT_FONT && StringId == (EFI_STRING_ID) (-1)) {
        
        
        
        
        BlockHdr += sizeof (EFI_HII_SIBT_EXT2_BLOCK);
        CopyMem (&FontId, BlockHdr, sizeof (UINT8));
        BlockHdr ++;
        CopyMem (&FontSize, BlockHdr, sizeof (UINT16));
        BlockHdr += sizeof (UINT16);
        CopyMem (&FontStyle, BlockHdr, sizeof (EFI_HII_FONT_STYLE));
        BlockHdr += sizeof (EFI_HII_FONT_STYLE);
        GetUnicodeStringTextOrSize (NULL, BlockHdr, &StringSize);

        FontInfoSize = sizeof (EFI_FONT_INFO) - sizeof (CHAR16) + StringSize;
        FontInfo = (EFI_FONT_INFO *) AllocateZeroPool (FontInfoSize);
        if (FontInfo == NULL) {
          return EFI_OUT_OF_RESOURCES;
        }
        FontInfo->FontStyle = FontStyle;
        FontInfo->FontSize  = FontSize;
        CopyMem (FontInfo->FontName, BlockHdr, StringSize);

        
        
        
        
        if (IsFontInfoExisted (Private, FontInfo, NULL, NULL, &GlobalFont)) {
          ReferFontInfoLocally (Private, StringPackage, FontId, TRUE, GlobalFont, &LocalFont);
        }

        
        
        
        
        
        StringPackage->FontId++;

        FreePool (FontInfo);
      }

      BlockSize += Ext2.Length;

      break;

    case EFI_HII_SIBT_EXT4:
      CopyMem ( &Length32, (UINT8*)((UINTN)BlockHdr + sizeof (EFI_HII_STRING_BLOCK) + sizeof (UINT8)), sizeof (UINT32)


        );

      BlockSize += Length32;
      break;

    default:
      break;
    }

    if (StringId > 0 && StringId != (EFI_STRING_ID)(-1)) {
      ASSERT (BlockType != NULL && StringBlockAddr != NULL && StringTextOffset != NULL);
      *BlockType        = *BlockHdr;
      *StringBlockAddr  = BlockHdr;
      *StringTextOffset = Offset;

      if (StringId == CurrentStringId - 1) {
        
        
        
        if(*BlockType == EFI_HII_SIBT_SKIP2 || *BlockType == EFI_HII_SIBT_SKIP1) {
          return EFI_NOT_FOUND;
        } else {
          return EFI_SUCCESS;
        }
      }

      if (StringId < CurrentStringId - 1) {
        return EFI_NOT_FOUND;
      }
    }
    BlockHdr  = StringPackage->StringBlock + BlockSize;
    if (StartStringId != NULL) {
        *StartStringId  = CurrentStringId;
    }
  }

  
  
  
  if (StringId == (EFI_STRING_ID) (-1) && LastStringId != NULL) {
    *LastStringId = (EFI_STRING_ID) (CurrentStringId - 1);
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}



EFI_STATUS GetStringWorker ( IN HII_DATABASE_PRIVATE_DATA        *Private, IN  HII_STRING_PACKAGE_INSTANCE     *StringPackage, IN  EFI_STRING_ID                   StringId, OUT EFI_STRING                      String, IN  OUT UINTN                       *StringSize, OPTIONAL OUT EFI_FONT_INFO                   **StringFontInfo OPTIONAL )







{
  UINT8                                *StringTextPtr;
  UINT8                                BlockType;
  UINT8                                *StringBlockAddr;
  UINTN                                StringTextOffset;
  EFI_STATUS                           Status;
  UINT8                                FontId;

  ASSERT (StringPackage != NULL);
  ASSERT (Private != NULL && Private->Signature == HII_DATABASE_PRIVATE_DATA_SIGNATURE);

  
  
  
  Status = FindStringBlock ( Private, StringPackage, StringId, &BlockType, &StringBlockAddr, &StringTextOffset, NULL, NULL );








  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (StringSize == NULL) {
    
    
    
    return EFI_SUCCESS;
  }

  
  
  
  StringTextPtr = StringBlockAddr + StringTextOffset;
  switch (BlockType) {
  case EFI_HII_SIBT_STRING_SCSU:
  case EFI_HII_SIBT_STRING_SCSU_FONT:
  case EFI_HII_SIBT_STRINGS_SCSU:
  case EFI_HII_SIBT_STRINGS_SCSU_FONT:
    Status = ConvertToUnicodeText (String, (CHAR8 *) StringTextPtr, StringSize);
    break;
  case EFI_HII_SIBT_STRING_UCS2:
  case EFI_HII_SIBT_STRING_UCS2_FONT:
  case EFI_HII_SIBT_STRINGS_UCS2:
  case EFI_HII_SIBT_STRINGS_UCS2_FONT:
    Status = GetUnicodeStringTextOrSize (String, StringTextPtr, StringSize);
    break;
  default:
    return EFI_NOT_FOUND;
  }
  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  
  if (StringFontInfo != NULL) {
    switch (BlockType) {
    case EFI_HII_SIBT_STRING_SCSU_FONT:
    case EFI_HII_SIBT_STRINGS_SCSU_FONT:
    case EFI_HII_SIBT_STRING_UCS2_FONT:
    case EFI_HII_SIBT_STRINGS_UCS2_FONT:
      FontId = *(StringBlockAddr + sizeof (EFI_HII_STRING_BLOCK));
      break;
    default:
      FontId = 0;
    }
    Status = GetStringFontInfo (StringPackage, FontId, StringFontInfo);
    if (Status == EFI_NOT_FOUND) {
        *StringFontInfo = NULL;
    }
  }

  return EFI_SUCCESS;
}


EFI_STATUS InsertLackStringBlock ( IN OUT HII_STRING_PACKAGE_INSTANCE         *StringPackage, IN EFI_STRING_ID                           StartStringId, IN EFI_STRING_ID                           StringId, IN OUT UINT8                               *BlockType, IN OUT UINT8                               **StringBlockAddr, IN BOOLEAN                                 FontBlock )







{
  UINT8                                *BlockPtr;
  UINT8                                *StringBlock;
  UINT32                               SkipLen;
  UINT32                               OldBlockSize;
  UINT32                               NewBlockSize;
  UINT32                               FrontSkipNum;
  UINT32                               NewUCSBlockLen;
  UINT8                                *OldStringAddr;
  UINT32                               IdCount;

  FrontSkipNum  = 0;
  SkipLen       = 0;
  OldStringAddr = *StringBlockAddr;

  ASSERT (*BlockType == EFI_HII_SIBT_SKIP1 || *BlockType == EFI_HII_SIBT_SKIP2);
  
  
  
  if (*BlockType == EFI_HII_SIBT_SKIP1) {
    SkipLen = sizeof (EFI_HII_SIBT_SKIP1_BLOCK);
    IdCount = *(UINT8*)(OldStringAddr + sizeof (EFI_HII_STRING_BLOCK));
  } else {
    SkipLen = sizeof (EFI_HII_SIBT_SKIP2_BLOCK);
    IdCount = *(UINT16*)(OldStringAddr + sizeof (EFI_HII_STRING_BLOCK));
  }

  
  
  
  if (FontBlock) {
    NewUCSBlockLen = sizeof (EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK);
  } else {
    NewUCSBlockLen = sizeof (EFI_HII_SIBT_STRING_UCS2_BLOCK);
  }

  OldBlockSize = StringPackage->StringPkgHdr->Header.Length - StringPackage->StringPkgHdr->HdrSize;

  if (StartStringId == StringId) {
    
    
    
    if (IdCount > 1) {
      NewBlockSize = OldBlockSize + NewUCSBlockLen;
    } else {
      NewBlockSize = OldBlockSize + NewUCSBlockLen - SkipLen;
    }
  } else if (StartStringId + IdCount - 1 == StringId){
    
    
    
    NewBlockSize = OldBlockSize + NewUCSBlockLen;
    FrontSkipNum = StringId - StartStringId;
  } else {
    
    
    
    NewBlockSize = OldBlockSize + NewUCSBlockLen + SkipLen;
    FrontSkipNum = StringId - StartStringId;
  }

  StringBlock = (UINT8 *) AllocateZeroPool (NewBlockSize);
  if (StringBlock == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  
  
  
  CopyMem (StringBlock, StringPackage->StringBlock, OldStringAddr - StringPackage->StringBlock);
  BlockPtr = StringBlock + (OldStringAddr - StringPackage->StringBlock);

  if (FrontSkipNum > 0) {
    *BlockPtr = *BlockType;
    if (*BlockType == EFI_HII_SIBT_SKIP1) {
      *(BlockPtr + sizeof (EFI_HII_STRING_BLOCK)) = (UINT8) FrontSkipNum;
    } else {
      *(UINT16 *)(BlockPtr + sizeof (EFI_HII_STRING_BLOCK)) = (UINT16) FrontSkipNum;
    }
    BlockPtr += SkipLen;
  }

  
  
  
  *StringBlockAddr = BlockPtr;
  if (FontBlock) {
    *BlockPtr = EFI_HII_SIBT_STRING_UCS2_FONT;
  } else {
    *BlockPtr = EFI_HII_SIBT_STRING_UCS2;
  }
  BlockPtr += NewUCSBlockLen;

  if (IdCount > FrontSkipNum + 1) {
    *BlockPtr = *BlockType;
    if (*BlockType == EFI_HII_SIBT_SKIP1) {
      *(BlockPtr + sizeof (EFI_HII_STRING_BLOCK)) = (UINT8) (IdCount - FrontSkipNum - 1);
    } else {
      *(UINT16 *)(BlockPtr + sizeof (EFI_HII_STRING_BLOCK)) = (UINT16) (IdCount - FrontSkipNum - 1);
    }
    BlockPtr += SkipLen;
  }

  
  
  
  CopyMem (BlockPtr, OldStringAddr + SkipLen, OldBlockSize - (OldStringAddr - StringPackage->StringBlock) - SkipLen);

  if (FontBlock) {
    *BlockType = EFI_HII_SIBT_STRING_UCS2_FONT;
  } else {
    *BlockType = EFI_HII_SIBT_STRING_UCS2;
  }
  FreePool (StringPackage->StringBlock);
  StringPackage->StringBlock = StringBlock;
  StringPackage->StringPkgHdr->Header.Length += NewBlockSize - OldBlockSize;

  return EFI_SUCCESS;
}


EFI_STATUS SetStringWorker ( IN  HII_DATABASE_PRIVATE_DATA       *Private, IN OUT HII_STRING_PACKAGE_INSTANCE  *StringPackage, IN  EFI_STRING_ID                   StringId, IN  EFI_STRING                      String, IN  EFI_FONT_INFO                   *StringFontInfo OPTIONAL )






{
  UINT8                                *StringTextPtr;
  UINT8                                BlockType;
  UINT8                                *StringBlockAddr;
  UINTN                                StringTextOffset;
  EFI_STATUS                           Status;
  UINT8                                *Block;
  UINT8                                *BlockPtr;
  UINTN                                BlockSize;
  UINTN                                OldBlockSize;
  HII_FONT_INFO                        *LocalFont;
  HII_GLOBAL_FONT_INFO                 *GlobalFont;
  BOOLEAN                              Referred;
  EFI_HII_SIBT_EXT2_BLOCK              Ext2;
  UINTN                                StringSize;
  UINTN                                TmpSize;
  EFI_STRING_ID                        StartStringId;

  StartStringId = 0;
  StringSize    = 0;
  ASSERT (Private != NULL && StringPackage != NULL && String != NULL);
  ASSERT (Private->Signature == HII_DATABASE_PRIVATE_DATA_SIGNATURE);
  
  
  
  Status = FindStringBlock ( Private, StringPackage, StringId, &BlockType, &StringBlockAddr, &StringTextOffset, NULL, &StartStringId );








  if (EFI_ERROR (Status) && (BlockType == EFI_HII_SIBT_SKIP1 || BlockType == EFI_HII_SIBT_SKIP2)) {
    Status = InsertLackStringBlock(StringPackage, StartStringId, StringId, &BlockType, &StringBlockAddr, (BOOLEAN)(StringFontInfo != NULL)




                          );
    if (EFI_ERROR (Status)) {
      return Status;
    }
    if (StringFontInfo != NULL) {
      StringTextOffset = sizeof (EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK) - sizeof (CHAR16);
    } else {
      StringTextOffset = sizeof (EFI_HII_SIBT_STRING_UCS2_BLOCK) - sizeof (CHAR16);
    }
  }

  LocalFont  = NULL;
  GlobalFont = NULL;
  Referred   = FALSE;

  
  
  
  if (StringFontInfo != NULL) {
    if (!IsFontInfoExisted (Private, StringFontInfo, NULL, NULL, &GlobalFont)) {
      return EFI_INVALID_PARAMETER;
    } else {
      Referred = ReferFontInfoLocally ( Private, StringPackage, StringPackage->FontId, FALSE, GlobalFont, &LocalFont );






      if (!Referred) {
        StringPackage->FontId++;
      }
    }
    
    
    
    switch (BlockType) {
    case EFI_HII_SIBT_STRING_SCSU_FONT:
    case EFI_HII_SIBT_STRINGS_SCSU_FONT:
    case EFI_HII_SIBT_STRING_UCS2_FONT:
    case EFI_HII_SIBT_STRINGS_UCS2_FONT:
      *(StringBlockAddr + sizeof (EFI_HII_STRING_BLOCK)) = LocalFont->FontId;
      break;
    default:
      
      
      
      
      
      return EFI_UNSUPPORTED;
    }
  }

  OldBlockSize = StringPackage->StringPkgHdr->Header.Length - StringPackage->StringPkgHdr->HdrSize;

  
  
  
  StringTextPtr = StringBlockAddr + StringTextOffset;
  switch (BlockType) {
  case EFI_HII_SIBT_STRING_SCSU:
  case EFI_HII_SIBT_STRING_SCSU_FONT:
  case EFI_HII_SIBT_STRINGS_SCSU:
  case EFI_HII_SIBT_STRINGS_SCSU_FONT:
    BlockSize = OldBlockSize + StrLen (String);
    BlockSize -= AsciiStrSize ((CHAR8 *) StringTextPtr);
    Block = AllocateZeroPool (BlockSize);
    if (Block == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    CopyMem (Block, StringPackage->StringBlock, StringTextPtr - StringPackage->StringBlock);
    BlockPtr = Block + (StringTextPtr - StringPackage->StringBlock);

    while (*String != 0) {
      *BlockPtr++ = (CHAR8) *String++;
    }
    *BlockPtr++ = 0;


    TmpSize = OldBlockSize - (StringTextPtr - StringPackage->StringBlock) - AsciiStrSize ((CHAR8 *) StringTextPtr);
    CopyMem ( BlockPtr, StringTextPtr + AsciiStrSize ((CHAR8 *)StringTextPtr), TmpSize );




    FreePool (StringPackage->StringBlock);
    StringPackage->StringBlock = Block;
    StringPackage->StringPkgHdr->Header.Length += (UINT32) (BlockSize - OldBlockSize);
    break;

  case EFI_HII_SIBT_STRING_UCS2:
  case EFI_HII_SIBT_STRING_UCS2_FONT:
  case EFI_HII_SIBT_STRINGS_UCS2:
  case EFI_HII_SIBT_STRINGS_UCS2_FONT:
    
    
    
    
    GetUnicodeStringTextOrSize (NULL, StringTextPtr, &StringSize);

    BlockSize = OldBlockSize + StrSize (String) - StringSize;
    Block = AllocateZeroPool (BlockSize);
    if (Block == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    CopyMem (Block, StringPackage->StringBlock, StringTextPtr - StringPackage->StringBlock);
    BlockPtr = Block + (StringTextPtr - StringPackage->StringBlock);

    CopyMem (BlockPtr, String, StrSize (String));
    BlockPtr += StrSize (String);

    CopyMem ( BlockPtr, StringTextPtr + StringSize, OldBlockSize - (StringTextPtr - StringPackage->StringBlock) - StringSize );




    FreePool (StringPackage->StringBlock);
    StringPackage->StringBlock = Block;
    StringPackage->StringPkgHdr->Header.Length += (UINT32) (BlockSize - OldBlockSize);
    break;

  default:
    return EFI_NOT_FOUND;
  }

  
  
  
  
  
  
  
  if (StringFontInfo == NULL || Referred) {
    return EFI_SUCCESS;
  }

  OldBlockSize = StringPackage->StringPkgHdr->Header.Length - StringPackage->StringPkgHdr->HdrSize;
  BlockSize = OldBlockSize + sizeof (EFI_HII_SIBT_FONT_BLOCK) - sizeof (CHAR16) + StrSize (GlobalFont->FontInfo->FontName);

  Block = AllocateZeroPool (BlockSize);
  if (Block == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  BlockPtr = Block;
  Ext2.Header.BlockType = EFI_HII_SIBT_EXT2;
  Ext2.BlockType2       = EFI_HII_SIBT_FONT;
  Ext2.Length           = (UINT16) (BlockSize - OldBlockSize);
  CopyMem (BlockPtr, &Ext2, sizeof (EFI_HII_SIBT_EXT2_BLOCK));
  BlockPtr += sizeof (EFI_HII_SIBT_EXT2_BLOCK);

  *BlockPtr = LocalFont->FontId;
  BlockPtr ++;
  CopyMem (BlockPtr, &GlobalFont->FontInfo->FontSize, sizeof (UINT16));
  BlockPtr += sizeof (UINT16);
  CopyMem (BlockPtr, &GlobalFont->FontInfo->FontStyle, sizeof (UINT32));
  BlockPtr += sizeof (UINT32);
  CopyMem ( BlockPtr, GlobalFont->FontInfo->FontName, StrSize (GlobalFont->FontInfo->FontName)


    );
  BlockPtr += StrSize (GlobalFont->FontInfo->FontName);

  CopyMem (BlockPtr, StringPackage->StringBlock, OldBlockSize);

  FreePool (StringPackage->StringBlock);
  StringPackage->StringBlock = Block;
  StringPackage->StringPkgHdr->Header.Length += Ext2.Length;

  return EFI_SUCCESS;

}



EFI_STATUS EFIAPI HiiNewString ( IN  CONST EFI_HII_STRING_PROTOCOL   *This, IN  EFI_HII_HANDLE                  PackageList, OUT EFI_STRING_ID                   *StringId, IN  CONST CHAR8                     *Language, IN  CONST CHAR16                    *LanguageName, OPTIONAL IN  CONST EFI_STRING                String, IN  CONST EFI_FONT_INFO             *StringFontInfo OPTIONAL )









{
  EFI_STATUS                          Status;
  LIST_ENTRY                          *Link;
  HII_DATABASE_PRIVATE_DATA           *Private;
  HII_DATABASE_RECORD                 *DatabaseRecord;
  HII_DATABASE_PACKAGE_LIST_INSTANCE  *PackageListNode;
  HII_STRING_PACKAGE_INSTANCE         *StringPackage;
  UINT32                              HeaderSize;
  UINT32                              BlockSize;
  UINT32                              OldBlockSize;
  UINT8                               *StringBlock;
  UINT8                               *BlockPtr;
  UINT32                              Ucs2BlockSize;
  UINT32                              FontBlockSize;
  UINT32                              Ucs2FontBlockSize;
  EFI_HII_SIBT_EXT2_BLOCK             Ext2;
  HII_FONT_INFO                       *LocalFont;
  HII_GLOBAL_FONT_INFO                *GlobalFont;
  EFI_STRING_ID                       NewStringId;
  EFI_STRING_ID                       NextStringId;
  EFI_STRING_ID                       Index;
  HII_STRING_PACKAGE_INSTANCE         *MatchStringPackage;
  BOOLEAN                             NewStringPackageCreated;


  if (This == NULL || String == NULL || StringId == NULL || Language == NULL || PackageList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!IsHiiHandleValid (PackageList)) {
    return EFI_NOT_FOUND;
  }

  Private    = HII_STRING_DATABASE_PRIVATE_DATA_FROM_THIS (This);
  GlobalFont = NULL;

  
  
  
  if (StringFontInfo != NULL) {
    if (!IsFontInfoExisted (Private, (EFI_FONT_INFO *) StringFontInfo, NULL, NULL, &GlobalFont)) {
      return EFI_INVALID_PARAMETER;
    }
  }

  
  
  
  PackageListNode = NULL;
  for (Link = Private->DatabaseList.ForwardLink; Link != &Private->DatabaseList; Link = Link->ForwardLink) {
    DatabaseRecord = CR (Link, HII_DATABASE_RECORD, DatabaseEntry, HII_DATABASE_RECORD_SIGNATURE);
    if (DatabaseRecord->Handle == PackageList) {
      PackageListNode = DatabaseRecord->PackageList;
      break;
    }
  }
  if (PackageListNode == NULL) {
    return EFI_NOT_FOUND;
  }

  EfiAcquireLock (&mHiiDatabaseLock);

  Status = EFI_SUCCESS;
  NewStringPackageCreated = FALSE;
  NewStringId   = 0;
  NextStringId  = 0;
  StringPackage = NULL;
  MatchStringPackage = NULL;
  for (Link = PackageListNode->StringPkgHdr.ForwardLink;
       Link != &PackageListNode->StringPkgHdr;
       Link = Link->ForwardLink ) {
    StringPackage = CR (Link, HII_STRING_PACKAGE_INSTANCE, StringEntry, HII_STRING_PACKAGE_SIGNATURE);
    
    
    
    
    Status = FindStringBlock ( Private, StringPackage, 0, NULL, NULL, NULL, &NextStringId, NULL );








    if (EFI_ERROR (Status)) {
      goto Done;
    }
    
    
    
    if (NewStringId != 0 && NewStringId != NextStringId) {
      ASSERT (FALSE);
      Status = EFI_INVALID_PARAMETER;
      goto Done;
    }
    NewStringId = NextStringId;
    
    
    
    if (HiiCompareLanguage (StringPackage->StringPkgHdr->Language, (CHAR8 *) Language)) {
      MatchStringPackage = StringPackage;
    } else {
      OldBlockSize = StringPackage->StringPkgHdr->Header.Length - StringPackage->StringPkgHdr->HdrSize;
      
      
      
      Ucs2BlockSize = (UINT32) sizeof (EFI_HII_SIBT_STRING_UCS2_BLOCK);

      StringBlock = (UINT8 *) AllocateZeroPool (OldBlockSize + Ucs2BlockSize);
      if (StringBlock == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto Done;
      }
      
      
      
      CopyMem (StringBlock, StringPackage->StringBlock, OldBlockSize - sizeof (EFI_HII_SIBT_END_BLOCK));
      
      
      
      BlockPtr  = StringBlock + OldBlockSize - sizeof (EFI_HII_SIBT_END_BLOCK);
      *BlockPtr = EFI_HII_SIBT_STRING_UCS2;
      BlockPtr  += sizeof (EFI_HII_SIBT_STRING_UCS2_BLOCK);

      
      
      
      *BlockPtr = EFI_HII_SIBT_END;
      FreePool (StringPackage->StringBlock);
      StringPackage->StringBlock = StringBlock;
      StringPackage->StringPkgHdr->Header.Length += Ucs2BlockSize;
      PackageListNode->PackageListHdr.PackageLength += Ucs2BlockSize;
    }
  }
  if (NewStringId == 0) {
    
    
    
    
    *StringId = 2;
  } else {
    
    
    
    *StringId = (EFI_STRING_ID) (NewStringId + 1);
  }

  if (MatchStringPackage != NULL) {
    StringPackage = MatchStringPackage;
  } else {
    
    
    
    if (LanguageName == NULL) {
      Status = EFI_INVALID_PARAMETER;
      goto Done;
    }

    StringPackage = AllocateZeroPool (sizeof (HII_STRING_PACKAGE_INSTANCE));
    if (StringPackage == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    StringPackage->Signature   = HII_STRING_PACKAGE_SIGNATURE;
    StringPackage->MaxStringId = *StringId;
    StringPackage->FontId      = 0;
    InitializeListHead (&StringPackage->FontInfoList);

    
    
    
    HeaderSize = (UINT32) (AsciiStrSize ((CHAR8 *) Language) - 1 + sizeof (EFI_HII_STRING_PACKAGE_HDR));
    StringPackage->StringPkgHdr = AllocateZeroPool (HeaderSize);
    if (StringPackage->StringPkgHdr == NULL) {
      FreePool (StringPackage);
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }
    StringPackage->StringPkgHdr->Header.Type      = EFI_HII_PACKAGE_STRINGS;
    StringPackage->StringPkgHdr->HdrSize          = HeaderSize;
    StringPackage->StringPkgHdr->StringInfoOffset = HeaderSize;
    CopyMem (StringPackage->StringPkgHdr->LanguageWindow, mLanguageWindow, 16 * sizeof (CHAR16));
    StringPackage->StringPkgHdr->LanguageName     = 1;
    AsciiStrCpyS (StringPackage->StringPkgHdr->Language, (HeaderSize - OFFSET_OF(EFI_HII_STRING_PACKAGE_HDR,Language)) / sizeof (CHAR8), (CHAR8 *) Language);

    
    
    
    
    Ucs2BlockSize = (UINT32) (StrSize ((CHAR16 *) LanguageName) + (*StringId - 1) * sizeof (EFI_HII_SIBT_STRING_UCS2_BLOCK) - sizeof (CHAR16));

    BlockSize     = Ucs2BlockSize + sizeof (EFI_HII_SIBT_END_BLOCK);
    StringPackage->StringBlock = (UINT8 *) AllocateZeroPool (BlockSize);
    if (StringPackage->StringBlock == NULL) {
      FreePool (StringPackage->StringPkgHdr);
      FreePool (StringPackage);
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    
    
    
    BlockPtr  = StringPackage->StringBlock;
    *BlockPtr = EFI_HII_SIBT_STRING_UCS2;
    BlockPtr  += sizeof (EFI_HII_STRING_BLOCK);
    CopyMem (BlockPtr, (EFI_STRING) LanguageName, StrSize ((EFI_STRING) LanguageName));
    BlockPtr += StrSize ((EFI_STRING) LanguageName);
    for (Index = 2; Index <= *StringId - 1; Index ++) {
      *BlockPtr = EFI_HII_SIBT_STRING_UCS2;
      BlockPtr += sizeof (EFI_HII_SIBT_STRING_UCS2_BLOCK);
    }
    
    
    
    *BlockPtr = EFI_HII_SIBT_END;

    
    
    
    StringPackage->StringPkgHdr->Header.Length    = HeaderSize + BlockSize;
    PackageListNode->PackageListHdr.PackageLength += StringPackage->StringPkgHdr->Header.Length;
    InsertTailList (&PackageListNode->StringPkgHdr, &StringPackage->StringEntry);
    NewStringPackageCreated = TRUE;
  }

  OldBlockSize = StringPackage->StringPkgHdr->Header.Length - StringPackage->StringPkgHdr->HdrSize;

  if (StringFontInfo == NULL) {
    
    
    
    Ucs2BlockSize = (UINT32) (StrSize (String) + sizeof (EFI_HII_SIBT_STRING_UCS2_BLOCK)
                              - sizeof (CHAR16));

    StringBlock = (UINT8 *) AllocateZeroPool (OldBlockSize + Ucs2BlockSize);
    if (StringBlock == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }
    
    
    
    CopyMem (StringBlock, StringPackage->StringBlock, OldBlockSize - sizeof (EFI_HII_SIBT_END_BLOCK));
    
    
    
    BlockPtr  = StringBlock + OldBlockSize - sizeof (EFI_HII_SIBT_END_BLOCK);
    *BlockPtr = EFI_HII_SIBT_STRING_UCS2;
    BlockPtr  += sizeof (EFI_HII_STRING_BLOCK);
    CopyMem (BlockPtr, (EFI_STRING) String, StrSize ((EFI_STRING) String));
    BlockPtr += StrSize ((EFI_STRING) String);

    
    
    
    *BlockPtr = EFI_HII_SIBT_END;
    FreePool (StringPackage->StringBlock);
    StringPackage->StringBlock = StringBlock;
    StringPackage->StringPkgHdr->Header.Length += Ucs2BlockSize;
    PackageListNode->PackageListHdr.PackageLength += Ucs2BlockSize;

  } else {
    
    
    
    
    
    
    Ucs2FontBlockSize = (UINT32) (StrSize (String) + sizeof (EFI_HII_SIBT_STRING_UCS2_FONT_BLOCK) - sizeof (CHAR16));
    if (ReferFontInfoLocally (Private, StringPackage, StringPackage->FontId, FALSE, GlobalFont, &LocalFont)) {
      
      
      
      StringBlock = (UINT8 *) AllocateZeroPool (OldBlockSize + Ucs2FontBlockSize);
      if (StringBlock == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto Done;
      }
      
      
      
      CopyMem (StringBlock, StringPackage->StringBlock, OldBlockSize - sizeof (EFI_HII_SIBT_END_BLOCK));
      
      
      
      BlockPtr  = StringBlock + OldBlockSize - sizeof (EFI_HII_SIBT_END_BLOCK);
      *BlockPtr = EFI_HII_SIBT_STRING_UCS2_FONT;
      BlockPtr  += sizeof (EFI_HII_STRING_BLOCK);
      *BlockPtr = LocalFont->FontId;
      BlockPtr ++;
      CopyMem (BlockPtr, (EFI_STRING) String, StrSize ((EFI_STRING) String));
      BlockPtr += StrSize ((EFI_STRING) String);

      
      
      
      *BlockPtr = EFI_HII_SIBT_END;
      FreePool (StringPackage->StringBlock);
      StringPackage->StringBlock = StringBlock;
      StringPackage->StringPkgHdr->Header.Length += Ucs2FontBlockSize;
      PackageListNode->PackageListHdr.PackageLength += Ucs2FontBlockSize;

    } else {
      
      
      
      
      
      FontBlockSize = (UINT32) (StrSize (((EFI_FONT_INFO *) StringFontInfo)->FontName) + sizeof (EFI_HII_SIBT_FONT_BLOCK) - sizeof (CHAR16));
      StringBlock = (UINT8 *) AllocateZeroPool (OldBlockSize + FontBlockSize + Ucs2FontBlockSize);
      if (StringBlock == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto Done;
      }
      
      
      
      CopyMem (StringBlock, StringPackage->StringBlock, OldBlockSize - sizeof (EFI_HII_SIBT_END_BLOCK));

      
      
      
      
      BlockPtr = StringBlock + OldBlockSize - sizeof (EFI_HII_SIBT_END_BLOCK);

      Ext2.Header.BlockType = EFI_HII_SIBT_EXT2;
      Ext2.BlockType2       = EFI_HII_SIBT_FONT;
      Ext2.Length           = (UINT16) FontBlockSize;
      CopyMem (BlockPtr, &Ext2, sizeof (EFI_HII_SIBT_EXT2_BLOCK));
      BlockPtr += sizeof (EFI_HII_SIBT_EXT2_BLOCK);

      *BlockPtr = LocalFont->FontId;
      BlockPtr ++;
      CopyMem (BlockPtr, &((EFI_FONT_INFO *) StringFontInfo)->FontSize, sizeof (UINT16));
      BlockPtr += sizeof (UINT16);
      CopyMem (BlockPtr, &((EFI_FONT_INFO *) StringFontInfo)->FontStyle, sizeof (EFI_HII_FONT_STYLE));
      BlockPtr += sizeof (EFI_HII_FONT_STYLE);
      CopyMem ( BlockPtr, &((EFI_FONT_INFO *) StringFontInfo)->FontName, StrSize (((EFI_FONT_INFO *) StringFontInfo)->FontName)


        );
      BlockPtr += StrSize (((EFI_FONT_INFO *) StringFontInfo)->FontName);
      
      
      
      *BlockPtr = EFI_HII_SIBT_STRING_UCS2_FONT;
      BlockPtr  += sizeof (EFI_HII_STRING_BLOCK);
      *BlockPtr = LocalFont->FontId;
      BlockPtr  ++;
      CopyMem (BlockPtr, (EFI_STRING) String, StrSize ((EFI_STRING) String));
      BlockPtr += StrSize ((EFI_STRING) String);

      
      
      
      *BlockPtr = EFI_HII_SIBT_END;
      FreePool (StringPackage->StringBlock);
      StringPackage->StringBlock = StringBlock;
      StringPackage->StringPkgHdr->Header.Length += FontBlockSize + Ucs2FontBlockSize;
      PackageListNode->PackageListHdr.PackageLength += FontBlockSize + Ucs2FontBlockSize;

      
      
      
      
      StringPackage->FontId++;
    }
  }

Done:
  if (!EFI_ERROR (Status) && NewStringPackageCreated) {
    
    
    
    Status = InvokeRegisteredFunction ( Private, EFI_HII_DATABASE_NOTIFY_NEW_PACK, (VOID *) StringPackage, EFI_HII_PACKAGE_STRINGS, PackageList );





  }

  if (!EFI_ERROR (Status)) {
    
    
    
    for (Link = PackageListNode->StringPkgHdr.ForwardLink;
      Link != &PackageListNode->StringPkgHdr;
      Link = Link->ForwardLink ) {
        StringPackage = CR (Link, HII_STRING_PACKAGE_INSTANCE, StringEntry, HII_STRING_PACKAGE_SIGNATURE);
        StringPackage->MaxStringId = *StringId;
    }
  } else if (NewStringPackageCreated) {
    
    
    
    RemoveEntryList (&StringPackage->StringEntry);
    FreePool (StringPackage->StringBlock);
    FreePool (StringPackage->StringPkgHdr);
    FreePool (StringPackage);
  }
  
  
  
  
  
  
  
  if (gExportAfterReadyToBoot) {
    if (!EFI_ERROR (Status)) {
      HiiGetDatabaseInfo(&Private->HiiDatabase);
    }
  }

  EfiReleaseLock (&mHiiDatabaseLock);

  return Status;
}



EFI_STATUS EFIAPI HiiGetString ( IN  CONST EFI_HII_STRING_PROTOCOL   *This, IN  CONST CHAR8                     *Language, IN  EFI_HII_HANDLE                  PackageList, IN  EFI_STRING_ID                   StringId, OUT EFI_STRING                      String, IN  OUT UINTN                       *StringSize, OUT EFI_FONT_INFO                   **StringFontInfo OPTIONAL )









{
  EFI_STATUS                          Status;
  LIST_ENTRY                          *Link;
  HII_DATABASE_PRIVATE_DATA           *Private;
  HII_DATABASE_RECORD                 *DatabaseRecord;
  HII_DATABASE_PACKAGE_LIST_INSTANCE  *PackageListNode;
  HII_STRING_PACKAGE_INSTANCE         *StringPackage;

  if (This == NULL || Language == NULL || StringId < 1 || StringSize == NULL || PackageList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (String == NULL && *StringSize != 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (!IsHiiHandleValid (PackageList)) {
    return EFI_NOT_FOUND;
  }

  Private = HII_STRING_DATABASE_PRIVATE_DATA_FROM_THIS (This);
  PackageListNode = NULL;

  for (Link = Private->DatabaseList.ForwardLink; Link != &Private->DatabaseList; Link = Link->ForwardLink) {
    DatabaseRecord = CR (Link, HII_DATABASE_RECORD, DatabaseEntry, HII_DATABASE_RECORD_SIGNATURE);
    if (DatabaseRecord->Handle == PackageList) {
      PackageListNode = DatabaseRecord->PackageList;
      break;
    }
  }

  if (PackageListNode != NULL) {
    
    
    
    for (Link =  PackageListNode->StringPkgHdr.ForwardLink;
         Link != &PackageListNode->StringPkgHdr;
         Link =  Link->ForwardLink ) {
        StringPackage = CR (Link, HII_STRING_PACKAGE_INSTANCE, StringEntry, HII_STRING_PACKAGE_SIGNATURE);
        if (HiiCompareLanguage (StringPackage->StringPkgHdr->Language, (CHAR8 *) Language)) {
          Status = GetStringWorker (Private, StringPackage, StringId, String, StringSize, StringFontInfo);
          if (Status != EFI_NOT_FOUND) {
            return Status;
          }
        }
      }
      
      
      
      for (Link =  PackageListNode->StringPkgHdr.ForwardLink;
           Link != &PackageListNode->StringPkgHdr;
           Link =  Link->ForwardLink ) {
      StringPackage = CR (Link, HII_STRING_PACKAGE_INSTANCE, StringEntry, HII_STRING_PACKAGE_SIGNATURE);
      Status = GetStringWorker (Private, StringPackage, StringId, NULL, NULL, NULL);
      if (!EFI_ERROR (Status)) {
        return EFI_INVALID_LANGUAGE;
      }
    }
  }

  return EFI_NOT_FOUND;
}




EFI_STATUS EFIAPI HiiSetString ( IN CONST EFI_HII_STRING_PROTOCOL    *This, IN EFI_HII_HANDLE                   PackageList, IN EFI_STRING_ID                    StringId, IN CONST CHAR8                      *Language, IN CONST EFI_STRING                 String, IN CONST EFI_FONT_INFO              *StringFontInfo OPTIONAL )








{
  EFI_STATUS                          Status;
  LIST_ENTRY                          *Link;
  HII_DATABASE_PRIVATE_DATA           *Private;
  HII_DATABASE_RECORD                 *DatabaseRecord;
  HII_DATABASE_PACKAGE_LIST_INSTANCE  *PackageListNode;
  HII_STRING_PACKAGE_INSTANCE         *StringPackage;
  UINT32                              OldPackageLen;

  if (This == NULL || Language == NULL || StringId < 1 || String == NULL || PackageList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!IsHiiHandleValid (PackageList)) {
    return EFI_NOT_FOUND;
  }

  EfiAcquireLock (&mHiiDatabaseLock);

  Private = HII_STRING_DATABASE_PRIVATE_DATA_FROM_THIS (This);
  PackageListNode = NULL;

  for (Link = Private->DatabaseList.ForwardLink; Link != &Private->DatabaseList; Link = Link->ForwardLink) {
    DatabaseRecord = CR (Link, HII_DATABASE_RECORD, DatabaseEntry, HII_DATABASE_RECORD_SIGNATURE);
    if (DatabaseRecord->Handle == PackageList) {
      PackageListNode = (HII_DATABASE_PACKAGE_LIST_INSTANCE *) (DatabaseRecord->PackageList);
    }
  }

  if (PackageListNode != NULL) {
    for (Link =  PackageListNode->StringPkgHdr.ForwardLink;
         Link != &PackageListNode->StringPkgHdr;
         Link =  Link->ForwardLink ) {
      StringPackage = CR (Link, HII_STRING_PACKAGE_INSTANCE, StringEntry, HII_STRING_PACKAGE_SIGNATURE);
      if (HiiCompareLanguage (StringPackage->StringPkgHdr->Language, (CHAR8 *) Language)) {
        OldPackageLen = StringPackage->StringPkgHdr->Header.Length;
        Status = SetStringWorker ( Private, StringPackage, StringId, (EFI_STRING) String, (EFI_FONT_INFO *) StringFontInfo );





        if (EFI_ERROR (Status)) {
          EfiReleaseLock (&mHiiDatabaseLock);
          return Status;
        }
        PackageListNode->PackageListHdr.PackageLength += StringPackage->StringPkgHdr->Header.Length - OldPackageLen;
        
        
        
        
        if (gExportAfterReadyToBoot) {
          HiiGetDatabaseInfo(&Private->HiiDatabase);
        }
        EfiReleaseLock (&mHiiDatabaseLock);
        return EFI_SUCCESS;
      }
    }
  }

  EfiReleaseLock (&mHiiDatabaseLock);
  return EFI_NOT_FOUND;
}




EFI_STATUS EFIAPI HiiGetLanguages ( IN CONST EFI_HII_STRING_PROTOCOL    *This, IN EFI_HII_HANDLE                   PackageList, IN OUT CHAR8                        *Languages, IN OUT UINTN                        *LanguagesSize )






{
  LIST_ENTRY                          *Link;
  HII_DATABASE_PRIVATE_DATA           *Private;
  HII_DATABASE_RECORD                 *DatabaseRecord;
  HII_DATABASE_PACKAGE_LIST_INSTANCE  *PackageListNode;
  HII_STRING_PACKAGE_INSTANCE         *StringPackage;
  UINTN                               ResultSize;

  if (This == NULL || LanguagesSize == NULL || PackageList == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (*LanguagesSize != 0 && Languages == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (!IsHiiHandleValid (PackageList)) {
    return EFI_NOT_FOUND;
  }

  Private = HII_STRING_DATABASE_PRIVATE_DATA_FROM_THIS (This);

  PackageListNode = NULL;
  for (Link = Private->DatabaseList.ForwardLink; Link != &Private->DatabaseList; Link = Link->ForwardLink) {
    DatabaseRecord  = CR (Link, HII_DATABASE_RECORD, DatabaseEntry, HII_DATABASE_RECORD_SIGNATURE);
    if (DatabaseRecord->Handle == PackageList) {
      PackageListNode = DatabaseRecord->PackageList;
      break;
    }
  }
  if (PackageListNode == NULL) {
    return EFI_NOT_FOUND;
  }

  
  
  
  ResultSize = 0;
  for (Link = PackageListNode->StringPkgHdr.ForwardLink;
       Link != &PackageListNode->StringPkgHdr;
       Link = Link->ForwardLink ) {
    StringPackage = CR (Link, HII_STRING_PACKAGE_INSTANCE, StringEntry, HII_STRING_PACKAGE_SIGNATURE);
    ResultSize += AsciiStrSize (StringPackage->StringPkgHdr->Language);
    if (ResultSize <= *LanguagesSize) {
      AsciiStrCpyS (Languages, *LanguagesSize / sizeof (CHAR8), StringPackage->StringPkgHdr->Language);
      Languages += AsciiStrSize (StringPackage->StringPkgHdr->Language);
      *(Languages - 1) = L';';
    }
  }
  if (ResultSize == 0) {
    return EFI_NOT_FOUND;
  }

  if (*LanguagesSize < ResultSize) {
    *LanguagesSize = ResultSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  *(Languages - 1) = 0;
  return EFI_SUCCESS;
}



EFI_STATUS EFIAPI HiiGetSecondaryLanguages ( IN CONST EFI_HII_STRING_PROTOCOL   *This, IN EFI_HII_HANDLE                  PackageList, IN CONST CHAR8                     *PrimaryLanguage, IN OUT CHAR8                       *SecondaryLanguages, IN OUT UINTN                       *SecondaryLanguagesSize )







{
  LIST_ENTRY                          *Link;
  LIST_ENTRY                          *Link1;
  HII_DATABASE_PRIVATE_DATA           *Private;
  HII_DATABASE_RECORD                 *DatabaseRecord;
  HII_DATABASE_PACKAGE_LIST_INSTANCE  *PackageListNode;
  HII_STRING_PACKAGE_INSTANCE         *StringPackage;
  CHAR8                               *Languages;
  UINTN                               ResultSize;

  if (This == NULL || PackageList == NULL || PrimaryLanguage == NULL || SecondaryLanguagesSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (SecondaryLanguages == NULL && *SecondaryLanguagesSize != 0) {
    return EFI_INVALID_PARAMETER;
  }
  if (!IsHiiHandleValid (PackageList)) {
    return EFI_NOT_FOUND;
  }

  Private    = HII_STRING_DATABASE_PRIVATE_DATA_FROM_THIS (This);

  PackageListNode = NULL;
  for (Link = Private->DatabaseList.ForwardLink; Link != &Private->DatabaseList; Link = Link->ForwardLink) {
    DatabaseRecord  = CR (Link, HII_DATABASE_RECORD, DatabaseEntry, HII_DATABASE_RECORD_SIGNATURE);
    if (DatabaseRecord->Handle == PackageList) {
      PackageListNode = (HII_DATABASE_PACKAGE_LIST_INSTANCE *) (DatabaseRecord->PackageList);
        break;
      }
    }
    if (PackageListNode == NULL) {
      return EFI_NOT_FOUND;
    }

    Languages  = NULL;
    ResultSize = 0;
    for (Link1 = PackageListNode->StringPkgHdr.ForwardLink;
         Link1 != &PackageListNode->StringPkgHdr;
         Link1 = Link1->ForwardLink ) {
    StringPackage = CR (Link1, HII_STRING_PACKAGE_INSTANCE, StringEntry, HII_STRING_PACKAGE_SIGNATURE);
    if (HiiCompareLanguage (StringPackage->StringPkgHdr->Language, (CHAR8 *) PrimaryLanguage)) {
      Languages = StringPackage->StringPkgHdr->Language;
      
      
      
      
      
      Languages = AsciiStrStr (Languages, ";");
      if (Languages == NULL) {
        break;
      }
      Languages++;

      ResultSize = AsciiStrSize (Languages);
      if (ResultSize <= *SecondaryLanguagesSize) {
        AsciiStrCpyS (SecondaryLanguages, *SecondaryLanguagesSize / sizeof (CHAR8), Languages);
      } else {
        *SecondaryLanguagesSize = ResultSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      return EFI_SUCCESS;
    }
  }

  return EFI_INVALID_LANGUAGE;
}


VOID EFIAPI AsciiHiiToLower ( IN CHAR8  *ConfigString )



{
  ASSERT (ConfigString != NULL);

  
  
  
  for (; *ConfigString != '\0'; ConfigString++) {
    if ( *ConfigString >= 'A' && *ConfigString <= 'Z') {
      *ConfigString = (CHAR8) (*ConfigString - 'A' + 'a');
    }
  }
}


BOOLEAN HiiCompareLanguage ( IN  CHAR8  *Language1, IN  CHAR8  *Language2 )



{
  UINTN  Index;
  UINTN  StrLen;
  CHAR8  *Lan1;
  CHAR8  *Lan2;

  
  
  
  StrLen = AsciiStrSize (Language1);
  Lan1   = AllocateZeroPool (StrLen);
  ASSERT (Lan1 != NULL);
  AsciiStrCpyS(Lan1, StrLen / sizeof (CHAR8), Language1);
  AsciiHiiToLower (Lan1);

  StrLen = AsciiStrSize (Language2);
  Lan2   = AllocateZeroPool (StrLen);
  ASSERT (Lan2 != NULL);
  AsciiStrCpyS(Lan2, StrLen / sizeof (CHAR8), Language2);
  AsciiHiiToLower (Lan2);

  
  
  
  for (Index = 0; Lan1[Index] != 0 && Lan1[Index] != ';'; Index++) {
    if (Lan1[Index] != Lan2[Index]) {
      
      
      
      FreePool (Lan1);
      FreePool (Lan2);
      return FALSE;
    }
  }

  FreePool (Lan1);
  FreePool (Lan2);

  
  
  
  
  
  
  return (BOOLEAN) (Language2[Index] == 0);
}
