




SCRIPT_TABLE_PRIVATE_DATA        *mS3BootScriptTablePtr;




SCRIPT_TABLE_PRIVATE_DATA        *mS3BootScriptTableSmmPtr;

EFI_GUID                         mBootScriptDataGuid = {
  0xaea6b965, 0xdcf5, 0x4311, { 0xb4, 0xb8, 0xf, 0x12, 0x46, 0x44, 0x94, 0xd2 }
};

EFI_GUID                         mBootScriptDataBootTimeGuid = {
  0xb5af1d7a, 0xb8cf, 0x4eb3, { 0x89, 0x25, 0xa8, 0x20, 0xe1, 0x6b, 0x68, 0x7d }
};

EFI_GUID                         mBootScriptTableBaseGuid = {
  0x1810ab4a, 0x2314, 0x4df6, { 0x81, 0xeb, 0x67, 0xc6, 0xec, 0x5, 0x85, 0x91 }
};

EFI_GUID                         mBootScriptSmmPrivateDataGuid = {
  0x627ee2da, 0x3bf9, 0x439b, { 0x92, 0x9f, 0x2e, 0xe, 0x6e, 0x9d, 0xba, 0x62 }
};

EFI_EVENT                        mEventDxeSmmReadyToLock = NULL;
VOID                             *mRegistrationSmmExitBootServices = NULL;
VOID                             *mRegistrationSmmLegacyBoot = NULL;
VOID                             *mRegistrationSmmReadyToLock = NULL;
BOOLEAN                          mS3BootScriptTableAllocated = FALSE;
BOOLEAN                          mS3BootScriptTableSmmAllocated = FALSE;
EFI_SMM_SYSTEM_TABLE2            *mBootScriptSmst = NULL;
BOOLEAN                          mAcpiS3Enable = TRUE;


UINT8* S3BootScriptInternalCloseTable ( VOID )


{
  UINT8                          *S3TableBase;
  EFI_BOOT_SCRIPT_TERMINATE      ScriptTerminate;
  EFI_BOOT_SCRIPT_TABLE_HEADER   *ScriptTableInfo;
  S3TableBase = mS3BootScriptTablePtr->TableBase;

  if (S3TableBase == NULL) {
    
    
    
    return S3TableBase;
  }
  
  
  
  ScriptTerminate.OpCode  = S3_BOOT_SCRIPT_LIB_TERMINATE_OPCODE;
  ScriptTerminate.Length  = (UINT8) sizeof (EFI_BOOT_SCRIPT_TERMINATE);
  CopyMem (mS3BootScriptTablePtr->TableBase + mS3BootScriptTablePtr->TableLength, &ScriptTerminate, sizeof (EFI_BOOT_SCRIPT_TERMINATE));
  
  
  
  ScriptTableInfo                = (EFI_BOOT_SCRIPT_TABLE_HEADER*)(mS3BootScriptTablePtr->TableBase);
  ScriptTableInfo->TableLength = mS3BootScriptTablePtr->TableLength + sizeof (EFI_BOOT_SCRIPT_TERMINATE);



  return S3TableBase;
  
  
  
  
  
  
}


VOID SaveBootScriptDataToLockBox ( VOID )


{
  EFI_STATUS            Status;

  
  
  
  
  Status = SaveLockBox ( &mBootScriptDataGuid, (VOID *)mS3BootScriptTablePtr->TableBase, EFI_PAGES_TO_SIZE (mS3BootScriptTablePtr->TableMemoryPageNumber)


             );
  ASSERT_EFI_ERROR (Status);

  Status = SetLockBoxAttributes (&mBootScriptDataGuid, LOCK_BOX_ATTRIBUTE_RESTORE_IN_PLACE);
  ASSERT_EFI_ERROR (Status);

  
  
  
  
  Status = SaveLockBox ( &mBootScriptTableBaseGuid, (VOID *)&mS3BootScriptTablePtr->TableBase, sizeof(mS3BootScriptTablePtr->TableBase)


             );
  ASSERT_EFI_ERROR (Status);

  Status = SetLockBoxAttributes (&mBootScriptTableBaseGuid, LOCK_BOX_ATTRIBUTE_RESTORE_IN_PLACE);
  ASSERT_EFI_ERROR (Status);
}


VOID EFIAPI S3BootScriptEventCallBack ( IN EFI_EVENT  Event, IN VOID       *Context )




{
  EFI_STATUS   Status;
  VOID         *Interface;

  
  
  
  
  Status = gBS->LocateProtocol ( &gEfiDxeSmmReadyToLockProtocolGuid, NULL, &Interface );



  if (EFI_ERROR (Status)) {
    return ;
  }

  
  
  
  
  if (!mS3BootScriptTablePtr->SmmLocked) {
    
    
    
    
    
    S3BootScriptInternalCloseTable ();
    mS3BootScriptTablePtr->SmmLocked = TRUE;

    
    
    
    SaveBootScriptDataToLockBox ();
  }
}


EFI_STATUS EFIAPI S3BootScriptSmmEventCallBack ( IN CONST EFI_GUID  *Protocol, IN VOID            *Interface, IN EFI_HANDLE      Handle )





{
  
  
  
  if (mS3BootScriptTablePtr == mS3BootScriptTableSmmPtr) {
    return EFI_SUCCESS;
  }

  
  
  
  S3BootScriptEventCallBack (NULL, NULL);

  
  
  
  if (mS3BootScriptTableSmmPtr->TableBase == NULL) {
    CopyMem (mS3BootScriptTableSmmPtr, mS3BootScriptTablePtr, sizeof(*mS3BootScriptTablePtr));

    
    
    
    
    mS3BootScriptTableSmmPtr->InSmm = TRUE;
  }
  
  
  
  mS3BootScriptTablePtr = mS3BootScriptTableSmmPtr;

  return EFI_SUCCESS;
}


VOID SaveBootTimeDataToLockBox ( VOID )


{
  EFI_STATUS    Status;

  
  
  
  
  Status = RestoreLockBox ( &mBootScriptDataGuid, NULL, NULL );



  ASSERT_EFI_ERROR (Status);

  
  
  
  
  Status = SaveLockBox ( &mBootScriptDataBootTimeGuid, (VOID *) mS3BootScriptTablePtr->TableBase, mS3BootScriptTablePtr->BootTimeScriptLength );



  ASSERT_EFI_ERROR (Status);
}


VOID SaveSmmPriviateDataToLockBoxAtRuntime ( VOID )


{
  EFI_STATUS    Status;

  
  
  
  mS3BootScriptTablePtr->BackFromS3 = TRUE;
  Status = SaveLockBox ( &mBootScriptSmmPrivateDataGuid, (VOID *) mS3BootScriptTablePtr, sizeof (SCRIPT_TABLE_PRIVATE_DATA)


             );
  ASSERT_EFI_ERROR (Status);

  Status = SetLockBoxAttributes (&mBootScriptSmmPrivateDataGuid, LOCK_BOX_ATTRIBUTE_RESTORE_IN_PLACE);
  ASSERT_EFI_ERROR (Status);

  
  
  
  mS3BootScriptTablePtr->BackFromS3 = FALSE;
}


EFI_STATUS EFIAPI S3BootScriptSmmAtRuntimeCallBack ( IN CONST EFI_GUID     *Protocol, IN VOID               *Interface, IN EFI_HANDLE         Handle )





{
  if (!mS3BootScriptTablePtr->AtRuntime) {
    mS3BootScriptTablePtr->BootTimeScriptLength = (UINT32) (mS3BootScriptTablePtr->TableLength + sizeof (EFI_BOOT_SCRIPT_TERMINATE));
    SaveBootTimeDataToLockBox ();

    mS3BootScriptTablePtr->AtRuntime = TRUE;
    SaveSmmPriviateDataToLockBoxAtRuntime ();
  }

  return EFI_SUCCESS;
}


RETURN_STATUS EFIAPI S3BootScriptLibInitialize ( IN EFI_HANDLE           ImageHandle, IN EFI_SYSTEM_TABLE     *SystemTable )




{
  EFI_STATUS                      Status;
  SCRIPT_TABLE_PRIVATE_DATA      *S3TablePtr;
  SCRIPT_TABLE_PRIVATE_DATA      *S3TableSmmPtr;
  VOID                           *Registration;
  EFI_SMM_BASE2_PROTOCOL         *SmmBase2;
  BOOLEAN                        InSmm;
  EFI_PHYSICAL_ADDRESS           Buffer;

  if (!PcdGetBool (PcdAcpiS3Enable)) {
    mAcpiS3Enable = FALSE;
    DEBUG ((DEBUG_INFO, "%a: Skip S3BootScript because ACPI S3 disabled.\n", gEfiCallerBaseName));
    return RETURN_SUCCESS;
  }

  S3TablePtr = (SCRIPT_TABLE_PRIVATE_DATA*)(UINTN)PcdGet64(PcdS3BootScriptTablePrivateDataPtr);
  
  
  
  if (S3TablePtr == 0) {
    Buffer = SIZE_4GB - 1;
    Status = gBS->AllocatePages ( AllocateMaxAddress, EfiReservedMemoryType, EFI_SIZE_TO_PAGES(sizeof(SCRIPT_TABLE_PRIVATE_DATA)), &Buffer );




    ASSERT_EFI_ERROR (Status);
    mS3BootScriptTableAllocated = TRUE;
    S3TablePtr = (VOID *) (UINTN) Buffer;

    Status = PcdSet64S (PcdS3BootScriptTablePrivateDataPtr, (UINT64) (UINTN)S3TablePtr);
    ASSERT_EFI_ERROR (Status);
    ZeroMem (S3TablePtr, sizeof(SCRIPT_TABLE_PRIVATE_DATA));
    
    
    
    mEventDxeSmmReadyToLock = EfiCreateProtocolNotifyEvent ( &gEfiDxeSmmReadyToLockProtocolGuid, TPL_CALLBACK, S3BootScriptEventCallBack, NULL, &Registration );





    ASSERT (mEventDxeSmmReadyToLock != NULL);
  }
  mS3BootScriptTablePtr = S3TablePtr;

  
  
  
  Status = gBS->LocateProtocol (&gEfiSmmBase2ProtocolGuid, NULL, (VOID**) &SmmBase2);
  if (EFI_ERROR (Status)) {
    return RETURN_SUCCESS;
  }
  Status = SmmBase2->InSmm (SmmBase2, &InSmm);
  if (EFI_ERROR (Status)) {
    return RETURN_SUCCESS;
  }
  if (!InSmm) {
    return RETURN_SUCCESS;
  }
  
  
  
  Status = SmmBase2->GetSmstLocation (SmmBase2, &mBootScriptSmst);
  if (EFI_ERROR (Status)) {
    return RETURN_SUCCESS;
  }

  S3TableSmmPtr = (SCRIPT_TABLE_PRIVATE_DATA*)(UINTN)PcdGet64(PcdS3BootScriptTablePrivateSmmDataPtr);
  
  
  
  if (S3TableSmmPtr == 0) {
    Status = mBootScriptSmst->SmmAllocatePool ( EfiRuntimeServicesData, sizeof(SCRIPT_TABLE_PRIVATE_DATA), (VOID **) &S3TableSmmPtr );



    ASSERT_EFI_ERROR (Status);
    mS3BootScriptTableSmmAllocated = TRUE;

    Status = PcdSet64S (PcdS3BootScriptTablePrivateSmmDataPtr, (UINT64) (UINTN)S3TableSmmPtr);
    ASSERT_EFI_ERROR (Status);
    ZeroMem (S3TableSmmPtr, sizeof(SCRIPT_TABLE_PRIVATE_DATA));

    
    
    
    Status = mBootScriptSmst->SmmRegisterProtocolNotify ( &gEdkiiSmmExitBootServicesProtocolGuid, S3BootScriptSmmAtRuntimeCallBack, &mRegistrationSmmExitBootServices );



    ASSERT_EFI_ERROR (Status);

    Status = mBootScriptSmst->SmmRegisterProtocolNotify ( &gEdkiiSmmLegacyBootProtocolGuid, S3BootScriptSmmAtRuntimeCallBack, &mRegistrationSmmLegacyBoot );



    ASSERT_EFI_ERROR (Status);
  }
  mS3BootScriptTableSmmPtr = S3TableSmmPtr;

  
  
  
  Status = mBootScriptSmst->SmmRegisterProtocolNotify ( &gEfiSmmReadyToLockProtocolGuid, S3BootScriptSmmEventCallBack, &mRegistrationSmmReadyToLock );



  ASSERT_EFI_ERROR (Status);

  return RETURN_SUCCESS;
}


RETURN_STATUS EFIAPI S3BootScriptLibDeinitialize ( IN EFI_HANDLE             ImageHandle, IN EFI_SYSTEM_TABLE       *SystemTable )




{
  EFI_STATUS                Status;

  if (!mAcpiS3Enable) {
    return RETURN_SUCCESS;
  }

  DEBUG ((EFI_D_INFO, "%a() in %a module\n", __FUNCTION__, gEfiCallerBaseName));

  if (mEventDxeSmmReadyToLock != NULL) {
    
    
    
    Status = gBS->CloseEvent (mEventDxeSmmReadyToLock);
    ASSERT_EFI_ERROR (Status);
  }

  if (mBootScriptSmst != NULL) {
    if (mRegistrationSmmExitBootServices != NULL) {
      
      
      
      Status = mBootScriptSmst->SmmRegisterProtocolNotify ( &gEdkiiSmmExitBootServicesProtocolGuid, NULL, &mRegistrationSmmExitBootServices );



      ASSERT_EFI_ERROR (Status);
    }
    if (mRegistrationSmmLegacyBoot != NULL) {
      
      
      
      Status = mBootScriptSmst->SmmRegisterProtocolNotify ( &gEdkiiSmmLegacyBootProtocolGuid, NULL, &mRegistrationSmmLegacyBoot );



      ASSERT_EFI_ERROR (Status);
    }
    if (mRegistrationSmmReadyToLock != NULL) {
      
      
      
      Status = mBootScriptSmst->SmmRegisterProtocolNotify ( &gEfiSmmReadyToLockProtocolGuid, NULL, &mRegistrationSmmReadyToLock );



      ASSERT_EFI_ERROR (Status);
    }
  }

  
  
  
  if (mS3BootScriptTableAllocated) {
    Status = gBS->FreePages ((EFI_PHYSICAL_ADDRESS) (UINTN) mS3BootScriptTablePtr, EFI_SIZE_TO_PAGES(sizeof(SCRIPT_TABLE_PRIVATE_DATA)));
    ASSERT_EFI_ERROR (Status);
    Status = PcdSet64S (PcdS3BootScriptTablePrivateDataPtr, 0);
    ASSERT_EFI_ERROR (Status);
  }
  if ((mBootScriptSmst != NULL) && mS3BootScriptTableSmmAllocated) {
    Status = mBootScriptSmst->SmmFreePool (mS3BootScriptTableSmmPtr);
    ASSERT_EFI_ERROR (Status);
    Status = PcdSet64S (PcdS3BootScriptTablePrivateSmmDataPtr, 0);
    ASSERT_EFI_ERROR (Status);
  }

  return RETURN_SUCCESS;
}


UINT8* S3BootScriptGetBootTimeEntryAddAddress ( UINT8  EntryLength )


{
   EFI_PHYSICAL_ADDRESS              S3TableBase;
   EFI_PHYSICAL_ADDRESS              NewS3TableBase;
   UINT8                            *NewEntryPtr;
   UINT32                            TableLength;
   UINT16                            PageNumber;
   EFI_STATUS                        Status;
   EFI_BOOT_SCRIPT_TABLE_HEADER      *ScriptTableInfo;

   S3TableBase = (EFI_PHYSICAL_ADDRESS)(UINTN)(mS3BootScriptTablePtr->TableBase);
   if (S3TableBase == 0) {
     
     
     
     
     S3TableBase = 0xffffffff;
     Status = gBS->AllocatePages ( AllocateMaxAddress, EfiReservedMemoryType, 2 + PcdGet16(PcdS3BootScriptRuntimeTableReservePageNumber), (EFI_PHYSICAL_ADDRESS*)&S3TableBase );





     if (EFI_ERROR(Status)) {
       ASSERT_EFI_ERROR (Status);
       return 0;
     }
     
     
     
     ScriptTableInfo              = (EFI_BOOT_SCRIPT_TABLE_HEADER*)(UINTN)S3TableBase;
     ScriptTableInfo->OpCode      = S3_BOOT_SCRIPT_LIB_TABLE_OPCODE;
     ScriptTableInfo->Length      = (UINT8) sizeof (EFI_BOOT_SCRIPT_TABLE_HEADER);
     ScriptTableInfo->Version     = BOOT_SCRIPT_TABLE_VERSION;
     ScriptTableInfo->TableLength = 0;   
     mS3BootScriptTablePtr->TableLength = sizeof (EFI_BOOT_SCRIPT_TABLE_HEADER);
     mS3BootScriptTablePtr->TableBase = (UINT8*)(UINTN)S3TableBase;
     mS3BootScriptTablePtr->TableMemoryPageNumber = (UINT16)(2 + PcdGet16(PcdS3BootScriptRuntimeTableReservePageNumber));
   }

   
   PageNumber = (UINT16) (mS3BootScriptTablePtr->TableMemoryPageNumber - PcdGet16(PcdS3BootScriptRuntimeTableReservePageNumber));
   TableLength =  mS3BootScriptTablePtr->TableLength;
   if (EFI_PAGES_TO_SIZE ((UINTN) PageNumber) < (TableLength + EntryLength + sizeof (EFI_BOOT_SCRIPT_TERMINATE))) {
     
     
     
     NewS3TableBase = 0xffffffff;
     Status = gBS->AllocatePages ( AllocateMaxAddress, EfiReservedMemoryType, 2 + PageNumber + PcdGet16(PcdS3BootScriptRuntimeTableReservePageNumber), (EFI_PHYSICAL_ADDRESS*)&NewS3TableBase );





     if (EFI_ERROR(Status)) {
       ASSERT_EFI_ERROR (Status);
       return 0;
     }

     CopyMem ((VOID*)(UINTN)NewS3TableBase, (VOID*)(UINTN)S3TableBase, TableLength);
     gBS->FreePages (S3TableBase, mS3BootScriptTablePtr->TableMemoryPageNumber);

     mS3BootScriptTablePtr->TableBase = (UINT8*)(UINTN)NewS3TableBase;
     mS3BootScriptTablePtr->TableMemoryPageNumber =  (UINT16) (2 + PageNumber + PcdGet16(PcdS3BootScriptRuntimeTableReservePageNumber));
   }
   
   
   
   NewEntryPtr = mS3BootScriptTablePtr->TableBase + TableLength;

   
   
   
   mS3BootScriptTablePtr->TableLength =  TableLength + EntryLength;

   
   
   
   
   
   

   return NewEntryPtr;
}

UINT8* S3BootScriptGetRuntimeEntryAddAddress ( UINT8  EntryLength )


{
   UINT8     *NewEntryPtr;

   NewEntryPtr = NULL;
   
   
   
   if ((mS3BootScriptTablePtr->TableLength + EntryLength + sizeof (EFI_BOOT_SCRIPT_TERMINATE)) <= EFI_PAGES_TO_SIZE ((UINTN) (mS3BootScriptTablePtr->TableMemoryPageNumber))) {
     NewEntryPtr = mS3BootScriptTablePtr->TableBase + mS3BootScriptTablePtr->TableLength;
     mS3BootScriptTablePtr->TableLength = mS3BootScriptTablePtr->TableLength + EntryLength;
     
     
     
     S3BootScriptInternalCloseTable ();
   }
   return (UINT8*)NewEntryPtr;
}


VOID RestoreBootTimeDataFromLockBox ( VOID )


{
  EFI_STATUS    Status;
  UINTN         LockBoxLength;

  
  
  
  LockBoxLength = mS3BootScriptTablePtr->BootTimeScriptLength;
  Status = RestoreLockBox ( &mBootScriptDataBootTimeGuid, (VOID *) mS3BootScriptTablePtr->TableBase, &LockBoxLength );



  ASSERT_EFI_ERROR (Status);

  
  
  
  Status = UpdateLockBox ( &mBootScriptDataGuid, 0, (VOID *) mS3BootScriptTablePtr->TableBase, LockBoxLength );




  ASSERT_EFI_ERROR (Status);

  
  
  
  mS3BootScriptTablePtr->TableLength = (UINT32) (mS3BootScriptTablePtr->BootTimeScriptLength - sizeof (EFI_BOOT_SCRIPT_TERMINATE));
}


UINT8* S3BootScriptGetEntryAddAddress ( UINT8  EntryLength )


{
  UINT8*                         NewEntryPtr;

  if (!mAcpiS3Enable) {
    return NULL;
  }

  if (mS3BootScriptTablePtr->SmmLocked) {
    
    
    
    if (!mS3BootScriptTablePtr->InSmm) {
      
      
      
      
      DEBUG ((EFI_D_ERROR, "FATAL ERROR: Set boot script outside SMM after SmmReadyToLock!!!\n"));
      return NULL;
    }

    if (mS3BootScriptTablePtr->BackFromS3) {
      
      
      
      
      RestoreBootTimeDataFromLockBox ();
      mS3BootScriptTablePtr->BackFromS3 = FALSE;
    }

    NewEntryPtr  = S3BootScriptGetRuntimeEntryAddAddress (EntryLength);
  } else {
    NewEntryPtr  = S3BootScriptGetBootTimeEntryAddAddress (EntryLength);
  }
  return NewEntryPtr;

}


VOID SyncBootScript ( IN UINT8      *Script )


{
  EFI_STATUS  Status;
  UINT32      ScriptOffset;
  UINT32      TotalScriptLength;

  if (!mS3BootScriptTablePtr->SmmLocked || !mS3BootScriptTablePtr->InSmm) {
    
    
    
    
    return ;
  }

  ScriptOffset = (UINT32) (Script - mS3BootScriptTablePtr->TableBase);

  TotalScriptLength = (UINT32) (mS3BootScriptTablePtr->TableLength + sizeof (EFI_BOOT_SCRIPT_TERMINATE));

  
  
  
  
  Status = UpdateLockBox ( &mBootScriptDataGuid, ScriptOffset, (VOID *)((UINTN)mS3BootScriptTablePtr->TableBase + ScriptOffset), TotalScriptLength - ScriptOffset );




  ASSERT_EFI_ERROR (Status);

  
  
  
  
  Status = UpdateLockBox ( &mBootScriptDataGuid, OFFSET_OF (EFI_BOOT_SCRIPT_TABLE_HEADER, TableLength), &TotalScriptLength, sizeof (TotalScriptLength)



             );
  ASSERT_EFI_ERROR (Status);
}


UINT8* EFIAPI S3BootScriptCloseTable ( VOID )



{
  UINT8                          *S3TableBase;
  UINT32                          TableLength;
  UINT8                          *Buffer;
  EFI_STATUS                      Status;
  EFI_BOOT_SCRIPT_TABLE_HEADER      *ScriptTableInfo;

  S3TableBase =    mS3BootScriptTablePtr->TableBase;
  if (S3TableBase == 0) {
    return 0;
  }
  
  
  
  S3BootScriptInternalCloseTable();
  TableLength = mS3BootScriptTablePtr->TableLength + sizeof (EFI_BOOT_SCRIPT_TERMINATE);
  
  
  
  Status = gBS->AllocatePool ( EfiBootServicesData, (UINTN)TableLength, (VOID **) &Buffer );



  if (EFI_ERROR (Status)) {
        return 0;
  }
  CopyMem (Buffer, S3TableBase, TableLength);

  
  
  
  
  
  ScriptTableInfo                    = (EFI_BOOT_SCRIPT_TABLE_HEADER*)S3TableBase;
  ScriptTableInfo->OpCode      = S3_BOOT_SCRIPT_LIB_TABLE_OPCODE;
  ScriptTableInfo->Length      = (UINT8) sizeof (EFI_BOOT_SCRIPT_TABLE_HEADER);
  ScriptTableInfo->TableLength = 0;   

  mS3BootScriptTablePtr->TableLength = sizeof (EFI_BOOT_SCRIPT_TABLE_HEADER);
  return Buffer;
}

RETURN_STATUS EFIAPI S3BootScriptSaveIoWrite ( IN  S3_BOOT_SCRIPT_LIB_WIDTH          Width, IN  UINT64                            Address, IN  UINTN                             Count, IN  VOID                              *Buffer )







{
  UINT8                     Length;
  UINT8                    *Script;
  UINT8                     WidthInByte;
  EFI_BOOT_SCRIPT_IO_WRITE  ScriptIoWrite;

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_IO_WRITE) + (WidthInByte * Count));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptIoWrite.OpCode  = EFI_BOOT_SCRIPT_IO_WRITE_OPCODE;
  ScriptIoWrite.Length  = Length;
  ScriptIoWrite.Width   = Width;
  ScriptIoWrite.Address = Address;
  ScriptIoWrite.Count   = (UINT32) Count;
  CopyMem ((VOID*)Script, (VOID*)&ScriptIoWrite, sizeof(EFI_BOOT_SCRIPT_IO_WRITE));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_IO_WRITE)), Buffer, WidthInByte * Count);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}


RETURN_STATUS EFIAPI S3BootScriptSaveIoReadWrite ( IN  S3_BOOT_SCRIPT_LIB_WIDTH         Width, IN  UINT64                           Address, IN  VOID                            *Data, IN  VOID                            *DataMask )






{
  UINT8                 Length;
  UINT8                *Script;
  UINT8                 WidthInByte;
  EFI_BOOT_SCRIPT_IO_READ_WRITE  ScriptIoReadWrite;

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_IO_READ_WRITE) + (WidthInByte * 2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptIoReadWrite.OpCode  = EFI_BOOT_SCRIPT_IO_READ_WRITE_OPCODE;
  ScriptIoReadWrite.Length  = Length;
  ScriptIoReadWrite.Width   = Width;
  ScriptIoReadWrite.Address = Address;

  CopyMem ((VOID*)Script, (VOID*)&ScriptIoReadWrite, sizeof(EFI_BOOT_SCRIPT_IO_READ_WRITE));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_IO_READ_WRITE)), Data, WidthInByte);
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_IO_READ_WRITE) + WidthInByte), DataMask, WidthInByte);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSaveMemWrite ( IN  S3_BOOT_SCRIPT_LIB_WIDTH          Width, IN  UINT64                            Address, IN  UINTN                             Count, IN  VOID                              *Buffer )






{
  UINT8                 Length;
  UINT8                *Script;
  UINT8                 WidthInByte;
  EFI_BOOT_SCRIPT_MEM_WRITE  ScriptMemWrite;

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_MEM_WRITE) + (WidthInByte * Count));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptMemWrite.OpCode   = EFI_BOOT_SCRIPT_MEM_WRITE_OPCODE;
  ScriptMemWrite.Length   = Length;
  ScriptMemWrite.Width    = Width;
  ScriptMemWrite.Address  = Address;
  ScriptMemWrite.Count    = (UINT32) Count;

  CopyMem ((VOID*)Script, (VOID*)&ScriptMemWrite, sizeof(EFI_BOOT_SCRIPT_MEM_WRITE));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_MEM_WRITE)), Buffer, WidthInByte * Count);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSaveMemReadWrite ( IN  S3_BOOT_SCRIPT_LIB_WIDTH          Width, IN  UINT64                            Address, IN  VOID                              *Data, IN  VOID                              *DataMask )






{
  UINT8                 Length;
  UINT8                *Script;
  UINT8                 WidthInByte;
  EFI_BOOT_SCRIPT_MEM_READ_WRITE  ScriptMemReadWrite;

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_MEM_READ_WRITE) + (WidthInByte * 2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptMemReadWrite.OpCode   = EFI_BOOT_SCRIPT_MEM_READ_WRITE_OPCODE;
  ScriptMemReadWrite.Length   = Length;
  ScriptMemReadWrite.Width    = Width;
  ScriptMemReadWrite.Address  = Address;

  CopyMem ((VOID*)Script, (VOID*)&ScriptMemReadWrite , sizeof (EFI_BOOT_SCRIPT_MEM_READ_WRITE));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_MEM_READ_WRITE)), Data, WidthInByte);
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_MEM_READ_WRITE) + WidthInByte), DataMask, WidthInByte);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSavePciCfgWrite ( IN  S3_BOOT_SCRIPT_LIB_WIDTH         Width, IN  UINT64                           Address, IN  UINTN                            Count, IN  VOID                            *Buffer )






{
  UINT8                 Length;
  UINT8                *Script;
  UINT8                 WidthInByte;
  EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE  ScriptPciWrite;

  if (Width == S3BootScriptWidthUint64 || Width == S3BootScriptWidthFifoUint64 || Width == S3BootScriptWidthFillUint64) {

    return EFI_INVALID_PARAMETER;
  }

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE) + (WidthInByte * Count));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptPciWrite.OpCode   = EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE_OPCODE;
  ScriptPciWrite.Length   = Length;
  ScriptPciWrite.Width    = Width;
  ScriptPciWrite.Address  = Address;
  ScriptPciWrite.Count    = (UINT32) Count;

  CopyMem ((VOID*)Script, (VOID*)&ScriptPciWrite,  sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_WRITE)), Buffer, WidthInByte * Count);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSavePciCfgReadWrite ( IN  S3_BOOT_SCRIPT_LIB_WIDTH          Width, IN  UINT64                            Address, IN  VOID                              *Data, IN  VOID                              *DataMask )






{
  UINT8                 Length;
  UINT8                *Script;
  UINT8                 WidthInByte;
  EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE  ScriptPciReadWrite;

  if (Width == S3BootScriptWidthUint64 || Width == S3BootScriptWidthFifoUint64 || Width == S3BootScriptWidthFillUint64) {

    return EFI_INVALID_PARAMETER;
  }

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE) + (WidthInByte * 2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptPciReadWrite.OpCode   = EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE_OPCODE;
  ScriptPciReadWrite.Length   = Length;
  ScriptPciReadWrite.Width    = Width;
  ScriptPciReadWrite.Address  = Address;

  CopyMem ((VOID*)Script, (VOID*)&ScriptPciReadWrite, sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE)), Data, WidthInByte);
  CopyMem ( (VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_READ_WRITE) + WidthInByte), DataMask, WidthInByte );




  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSavePciCfg2Write ( IN S3_BOOT_SCRIPT_LIB_WIDTH        Width, IN UINT16                          Segment, IN UINT64                          Address, IN UINTN                           Count, IN VOID                           *Buffer )







{
  UINT8                 Length;
  UINT8                *Script;
  UINT8                 WidthInByte;
  EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE  ScriptPciWrite2;

  if (Width == S3BootScriptWidthUint64 || Width == S3BootScriptWidthFifoUint64 || Width == S3BootScriptWidthFillUint64) {

    return EFI_INVALID_PARAMETER;
  }

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE) + (WidthInByte * Count));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptPciWrite2.OpCode   = EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE_OPCODE;
  ScriptPciWrite2.Length   = Length;
  ScriptPciWrite2.Width    = Width;
  ScriptPciWrite2.Address  = Address;
  ScriptPciWrite2.Segment  = Segment;
  ScriptPciWrite2.Count    = (UINT32)Count;

  CopyMem ((VOID*)Script, (VOID*)&ScriptPciWrite2, sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_WRITE)), Buffer, WidthInByte * Count);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSavePciCfg2ReadWrite ( IN S3_BOOT_SCRIPT_LIB_WIDTH        Width, IN UINT16                          Segment, IN UINT64                          Address, IN VOID                           *Data, IN VOID                           *DataMask )







{
  UINT8                 Length;
  UINT8                *Script;
  UINT8                 WidthInByte;
  EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE  ScriptPciReadWrite2;

  if (Width == S3BootScriptWidthUint64 || Width == S3BootScriptWidthFifoUint64 || Width == S3BootScriptWidthFillUint64) {

    return EFI_INVALID_PARAMETER;
  }

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE) + (WidthInByte * 2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptPciReadWrite2.OpCode   = EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE_OPCODE;
  ScriptPciReadWrite2.Length   = Length;
  ScriptPciReadWrite2.Width    = Width;
  ScriptPciReadWrite2.Segment  = Segment;
  ScriptPciReadWrite2.Address  = Address;

  CopyMem ((VOID*)Script, (VOID*)&ScriptPciReadWrite2, sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE)), Data, WidthInByte);
  CopyMem ( (VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_READ_WRITE) + WidthInByte), DataMask, WidthInByte );




  SyncBootScript (Script);

  return RETURN_SUCCESS;
}


EFI_STATUS CheckParameters ( IN     UINTN                    SmBusAddress, IN     EFI_SMBUS_OPERATION      Operation, IN OUT UINTN                    *Length, IN     VOID                     *Buffer )





{
  EFI_STATUS  Status;
  UINTN       RequiredLen;
  EFI_SMBUS_DEVICE_COMMAND Command;
  BOOLEAN                  PecCheck;

  Command      = SMBUS_LIB_COMMAND (SmBusAddress);
  PecCheck     = SMBUS_LIB_PEC (SmBusAddress);
  
  
  
  
  RequiredLen = 2;
  Status      = EFI_SUCCESS;
  switch (Operation) {
    case EfiSmbusQuickRead:
    case EfiSmbusQuickWrite:
      if (PecCheck || Command != 0) {
        return EFI_UNSUPPORTED;
      }
      break;
    case EfiSmbusReceiveByte:
    case EfiSmbusSendByte:
      if (Command != 0) {
        return EFI_UNSUPPORTED;
      }
      
      
      
    case EfiSmbusReadByte:
    case EfiSmbusWriteByte:
      RequiredLen = 1;
      
      
      
    case EfiSmbusReadWord:
    case EfiSmbusWriteWord:
    case EfiSmbusProcessCall:
      if (Buffer == NULL || Length == NULL) {
        return EFI_INVALID_PARAMETER;
      } else if (*Length < RequiredLen) {
        Status = EFI_BUFFER_TOO_SMALL;
      }
      *Length = RequiredLen;
      break;
    case EfiSmbusReadBlock:
    case EfiSmbusWriteBlock:
    case EfiSmbusBWBRProcessCall:
      if ((Buffer == NULL) || (Length == NULL) || (*Length < MIN_SMBUS_BLOCK_LEN) || (*Length > MAX_SMBUS_BLOCK_LEN)) {


        return EFI_INVALID_PARAMETER;
      }
      break;
    default:
      return EFI_INVALID_PARAMETER;
  }
  return Status;
}


RETURN_STATUS EFIAPI S3BootScriptSaveSmbusExecute ( IN  UINTN                             SmBusAddress, IN  EFI_SMBUS_OPERATION               Operation, IN  UINTN                             *Length, IN  VOID                              *Buffer )






{
  EFI_STATUS            Status;
  UINTN                 BufferLength;
  UINT8                 DataSize;
  UINT8                *Script;
  EFI_BOOT_SCRIPT_SMBUS_EXECUTE  ScriptSmbusExecute;

  if (Length == NULL) {
    BufferLength = 0;
  } else {
    BufferLength = *Length;
  }

  Status = CheckParameters (SmBusAddress, Operation, &BufferLength, Buffer);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DataSize = (UINT8)(sizeof (EFI_BOOT_SCRIPT_SMBUS_EXECUTE) + BufferLength);

  Script = S3BootScriptGetEntryAddAddress (DataSize);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptSmbusExecute.OpCode       = EFI_BOOT_SCRIPT_SMBUS_EXECUTE_OPCODE;
  ScriptSmbusExecute.Length       = DataSize;
  ScriptSmbusExecute.SmBusAddress = (UINT64) SmBusAddress;
  ScriptSmbusExecute.Operation    = Operation;
  ScriptSmbusExecute.DataSize     = (UINT32) BufferLength;

  CopyMem ((VOID*)Script, (VOID*)&ScriptSmbusExecute, sizeof (EFI_BOOT_SCRIPT_SMBUS_EXECUTE));
  CopyMem ( (VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_SMBUS_EXECUTE)), Buffer, BufferLength );




  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSaveStall ( IN  UINTN                             Duration )



{
  UINT8                 Length;
  UINT8                *Script;
  EFI_BOOT_SCRIPT_STALL  ScriptStall;

  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_STALL));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptStall.OpCode    = EFI_BOOT_SCRIPT_STALL_OPCODE;
  ScriptStall.Length    = Length;
  ScriptStall.Duration  = Duration;

  CopyMem ((VOID*)Script, (VOID*)&ScriptStall, sizeof (EFI_BOOT_SCRIPT_STALL));

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSaveDispatch2 ( IN  VOID                      *EntryPoint, IN  VOID                      *Context )




{
  UINT8                 Length;
  UINT8                 *Script;
  EFI_BOOT_SCRIPT_DISPATCH_2  ScriptDispatch2;
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_DISPATCH_2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptDispatch2.OpCode     = EFI_BOOT_SCRIPT_DISPATCH_2_OPCODE;
  ScriptDispatch2.Length     = Length;
  ScriptDispatch2.EntryPoint = (EFI_PHYSICAL_ADDRESS)(UINTN)EntryPoint;
  ScriptDispatch2.Context =   (EFI_PHYSICAL_ADDRESS)(UINTN)Context;

  CopyMem ((VOID*)Script, (VOID*)&ScriptDispatch2, sizeof (EFI_BOOT_SCRIPT_DISPATCH_2));

  SyncBootScript (Script);

  return RETURN_SUCCESS;

}

RETURN_STATUS EFIAPI S3BootScriptSaveMemPoll ( IN  S3_BOOT_SCRIPT_LIB_WIDTH          Width, IN  UINT64                            Address, IN  VOID                              *BitMask, IN  VOID                              *BitValue, IN  UINTN                             Duration, IN  UINT64                            LoopTimes )








{
  UINT8                 Length;
  UINT8                *Script;
  UINT8                 WidthInByte;
  EFI_BOOT_SCRIPT_MEM_POLL      ScriptMemPoll;

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));

  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_MEM_POLL) + (WidthInByte * 2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptMemPoll.OpCode   = EFI_BOOT_SCRIPT_MEM_POLL_OPCODE;
  ScriptMemPoll.Length   = Length;
  ScriptMemPoll.Width    = Width;
  ScriptMemPoll.Address  = Address;
  ScriptMemPoll.Duration = Duration;
  ScriptMemPoll.LoopTimes = LoopTimes;

  CopyMem ((UINT8 *) (Script + sizeof (EFI_BOOT_SCRIPT_MEM_POLL)), BitValue, WidthInByte);
  CopyMem ((UINT8 *) (Script + sizeof (EFI_BOOT_SCRIPT_MEM_POLL) + WidthInByte), BitMask, WidthInByte);
  CopyMem ((VOID*)Script, (VOID*)&ScriptMemPoll, sizeof (EFI_BOOT_SCRIPT_MEM_POLL));

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSaveInformation ( IN  UINT32                                InformationLength, IN  VOID                                 *Information )




{
  UINT8                 Length;
  UINT8                 *Script;
  EFI_BOOT_SCRIPT_INFORMATION  ScriptInformation;

  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_INFORMATION) + InformationLength);

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptInformation.OpCode     = EFI_BOOT_SCRIPT_INFORMATION_OPCODE;
  ScriptInformation.Length     = Length;


  ScriptInformation.InformationLength = InformationLength;

  CopyMem ((VOID*)Script, (VOID*)&ScriptInformation, sizeof (EFI_BOOT_SCRIPT_INFORMATION));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_INFORMATION)), (VOID *) Information, (UINTN) InformationLength);

  SyncBootScript (Script);

  return RETURN_SUCCESS;

}

RETURN_STATUS EFIAPI S3BootScriptSaveInformationAsciiString ( IN  CONST CHAR8               *String )



{
  return S3BootScriptSaveInformation ( (UINT32) AsciiStrLen (String) + 1, (VOID*) String );


}

RETURN_STATUS EFIAPI S3BootScriptSaveDispatch ( IN  VOID                              *EntryPoint )



{
  UINT8                 Length;
  UINT8                *Script;
  EFI_BOOT_SCRIPT_DISPATCH  ScriptDispatch;

  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_DISPATCH));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptDispatch.OpCode     = EFI_BOOT_SCRIPT_DISPATCH_OPCODE;
  ScriptDispatch.Length     = Length;
  ScriptDispatch.EntryPoint = (EFI_PHYSICAL_ADDRESS)(UINTN)EntryPoint;

  CopyMem ((VOID*)Script, (VOID*)&ScriptDispatch, sizeof (EFI_BOOT_SCRIPT_DISPATCH));

  SyncBootScript (Script);

  return RETURN_SUCCESS;

}

RETURN_STATUS EFIAPI S3BootScriptSaveIoPoll ( IN S3_BOOT_SCRIPT_LIB_WIDTH       Width, IN UINT64                     Address, IN VOID                      *Data, IN VOID                      *DataMask, IN UINT64                     Delay )







{
  UINT8                 WidthInByte;
  UINT8                *Script;
  UINT8                 Length;
  EFI_BOOT_SCRIPT_IO_POLL  ScriptIoPoll;


  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_IO_POLL) + (WidthInByte * 2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptIoPoll.OpCode   = EFI_BOOT_SCRIPT_IO_POLL_OPCODE;
  ScriptIoPoll.Length   = (UINT8) (sizeof (EFI_BOOT_SCRIPT_IO_POLL) + (WidthInByte * 2));
  ScriptIoPoll.Width    = Width;
  ScriptIoPoll.Address  = Address;
  ScriptIoPoll.Delay    = Delay;

  CopyMem ((VOID*)Script, (VOID*)&ScriptIoPoll, sizeof (EFI_BOOT_SCRIPT_IO_POLL));
  CopyMem ((UINT8 *) (Script + sizeof (EFI_BOOT_SCRIPT_IO_POLL)), Data, WidthInByte);
  CopyMem ((UINT8 *) (Script + sizeof (EFI_BOOT_SCRIPT_IO_POLL) + WidthInByte), DataMask, WidthInByte);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}


RETURN_STATUS EFIAPI S3BootScriptSavePciPoll ( IN S3_BOOT_SCRIPT_LIB_WIDTH   Width, IN UINT64                     Address, IN VOID                      *Data, IN VOID                      *DataMask, IN UINT64                     Delay )







{
  UINT8                   *Script;
  UINT8                    WidthInByte;
  UINT8                    Length;
  EFI_BOOT_SCRIPT_PCI_CONFIG_POLL  ScriptPciPoll;

  if (Width == S3BootScriptWidthUint64 || Width == S3BootScriptWidthFifoUint64 || Width == S3BootScriptWidthFillUint64) {

    return EFI_INVALID_PARAMETER;
  }

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_POLL) + (WidthInByte * 2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptPciPoll.OpCode   = EFI_BOOT_SCRIPT_PCI_CONFIG_POLL_OPCODE;
  ScriptPciPoll.Length   = (UINT8) (sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_POLL) + (WidthInByte * 2));
  ScriptPciPoll.Width    = Width;
  ScriptPciPoll.Address  = Address;
  ScriptPciPoll.Delay    = Delay;

  CopyMem ((VOID*)Script, (VOID*)&ScriptPciPoll, sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_POLL));
  CopyMem ((UINT8 *) (Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_POLL)), Data, WidthInByte);
  CopyMem ((UINT8 *) (Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG_POLL) + WidthInByte), DataMask, WidthInByte);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptSavePci2Poll ( IN S3_BOOT_SCRIPT_LIB_WIDTH      Width, IN UINT16                        Segment, IN UINT64                        Address, IN VOID                         *Data, IN VOID                         *DataMask, IN UINT64                         Delay )








{
  UINT8                    WidthInByte;
  UINT8                   *Script;
  UINT8                    Length;
  EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL  ScriptPci2Poll;

  if (Width == S3BootScriptWidthUint64 || Width == S3BootScriptWidthFifoUint64 || Width == S3BootScriptWidthFillUint64) {

    return EFI_INVALID_PARAMETER;
  }

  WidthInByte = (UINT8) (0x01 << (Width & 0x03));
  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL) + (WidthInByte * 2));

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptPci2Poll.OpCode   = EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL_OPCODE;
  ScriptPci2Poll.Length   = (UINT8) (sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL) + (WidthInByte * 2));
  ScriptPci2Poll.Width    = Width;
  ScriptPci2Poll.Segment  = Segment;
  ScriptPci2Poll.Address  = Address;
  ScriptPci2Poll.Delay    = Delay;

  CopyMem ((VOID*)Script, (VOID*)&ScriptPci2Poll, sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL));
  CopyMem ((UINT8 *) (Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL)), Data, WidthInByte);
  CopyMem ((UINT8 *) (Script + sizeof (EFI_BOOT_SCRIPT_PCI_CONFIG2_POLL) + WidthInByte), DataMask, WidthInByte);

  SyncBootScript (Script);

  return RETURN_SUCCESS;
}

VOID S3BootScriptCalculateInsertAddress ( IN  UINT8     EntryLength, IN  VOID     *Position OPTIONAL, IN  BOOLEAN   BeforeOrAfter OPTIONAL, OUT UINT8   **Script )





{
   UINTN                            TableLength;
   UINT8                            *S3TableBase;
   UINTN                            PositionOffset;
   EFI_BOOT_SCRIPT_COMMON_HEADER     ScriptHeader;
   
   
   
   TableLength =  mS3BootScriptTablePtr->TableLength - EntryLength;
   S3TableBase = mS3BootScriptTablePtr->TableBase ;
   
   
   
   if (Position != NULL) {
     PositionOffset = (UINTN)Position - (UINTN)S3TableBase;

     
     
     
     if (!BeforeOrAfter) {
        CopyMem ((VOID*)&ScriptHeader, Position, sizeof(EFI_BOOT_SCRIPT_COMMON_HEADER));
        PositionOffset += (ScriptHeader.Length);
     }
     
     
     
     CopyMem (S3TableBase+PositionOffset+EntryLength, S3TableBase+PositionOffset, TableLength - PositionOffset);
     
     
     
     *Script = S3TableBase + PositionOffset;

   } else {
     if (!BeforeOrAfter) {
       
       
       
       *Script = S3TableBase + TableLength;
     } else {
       
       
       
       PositionOffset = (UINTN) sizeof(EFI_BOOT_SCRIPT_TABLE_HEADER);
       CopyMem (S3TableBase+PositionOffset+EntryLength, S3TableBase+PositionOffset, TableLength - PositionOffset);
       *Script = S3TableBase + PositionOffset;
     }
   }
}

RETURN_STATUS EFIAPI S3BootScriptMoveLastOpcode ( IN     BOOLEAN                        BeforeOrAfter, IN OUT VOID                         **Position OPTIONAL )




{
  UINT8*                Script;
  VOID                  *TempPosition;
  UINTN                 StartAddress;
  UINT32                TableLength;
  EFI_BOOT_SCRIPT_COMMON_HEADER  ScriptHeader;
  BOOLEAN               ValidatePosition;
  UINT8*                LastOpcode;
  UINT8                 TempBootScriptEntry[BOOT_SCRIPT_NODE_MAX_LENGTH];

  ValidatePosition = FALSE;
  TempPosition = (Position == NULL) ? NULL:(*Position);

  
  
  
  Script = S3BootScriptGetEntryAddAddress (0);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  Script = mS3BootScriptTablePtr->TableBase;

  StartAddress  = (UINTN) Script;
  TableLength   = mS3BootScriptTablePtr->TableLength;
  Script        = Script + sizeof(EFI_BOOT_SCRIPT_TABLE_HEADER);
  LastOpcode    = Script;
  
  
  
  while ((UINTN) Script < (UINTN) (StartAddress + TableLength)) {
    CopyMem ((VOID*)&ScriptHeader, Script, sizeof(EFI_BOOT_SCRIPT_COMMON_HEADER));
    if (TempPosition != NULL && TempPosition == Script) {
      
      
      
      ValidatePosition = TRUE;
    }
    if (ScriptHeader.OpCode != S3_BOOT_SCRIPT_LIB_TERMINATE_OPCODE) {
      LastOpcode = Script;
    }
    Script  = Script + ScriptHeader.Length;
  }
  
  
  
  if (TempPosition != NULL && !ValidatePosition) {
    return RETURN_INVALID_PARAMETER;
  }

  CopyMem ((VOID*)&ScriptHeader, LastOpcode, sizeof(EFI_BOOT_SCRIPT_COMMON_HEADER));

  CopyMem((VOID*)TempBootScriptEntry, LastOpcode, ScriptHeader.Length);
  
  
  
  S3BootScriptCalculateInsertAddress ( ScriptHeader.Length, TempPosition, BeforeOrAfter, &Script );




  
  
  
  CopyMem((VOID*)Script, (VOID*)TempBootScriptEntry, ScriptHeader.Length);

  SyncBootScript (Script);

  
  
  
  if (Position != NULL) {
    *Position = Script;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS EFIAPI S3BootScriptLabelInternal ( IN        BOOLEAN                        BeforeOrAfter, IN OUT    VOID                         **Position OPTIONAL, IN        UINT32                         InformationLength, IN CONST  CHAR8                          *Information )






{
  UINT8                 Length;
  UINT8                 *Script;
  EFI_BOOT_SCRIPT_INFORMATION  ScriptInformation;

  Length = (UINT8)(sizeof (EFI_BOOT_SCRIPT_INFORMATION) + InformationLength);

  Script = S3BootScriptGetEntryAddAddress (Length);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  
  
  
  ScriptInformation.OpCode     = S3_BOOT_SCRIPT_LIB_LABEL_OPCODE;
  ScriptInformation.Length     = Length;


  ScriptInformation.InformationLength = InformationLength;

  CopyMem ((VOID*)Script, (VOID*)&ScriptInformation, sizeof (EFI_BOOT_SCRIPT_INFORMATION));
  CopyMem ((VOID*)(Script + sizeof (EFI_BOOT_SCRIPT_INFORMATION)), (VOID *) Information, (UINTN) InformationLength);

  SyncBootScript (Script);

  return S3BootScriptMoveLastOpcode (BeforeOrAfter, Position);

}

RETURN_STATUS EFIAPI S3BootScriptLabel ( IN       BOOLEAN                      BeforeOrAfter, IN       BOOLEAN                      CreateIfNotFound, IN OUT   VOID                       **Position OPTIONAL, IN CONST CHAR8                       *Label )






{
  UINT8*                Script;
  UINTN                 StartAddress;
  UINT32                TableLength;
  EFI_BOOT_SCRIPT_COMMON_HEADER  ScriptHeader;
  EFI_BOOT_SCRIPT_TABLE_HEADER   TableHeader;
  UINT32                         LabelLength;
  
  
  
  if (Label == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  
  
  if (Label[0] == '\0') {
    return EFI_INVALID_PARAMETER;
  }

  
  
  
  
  
  Script = S3BootScriptGetEntryAddAddress (0);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  
  
  
  Script = mS3BootScriptTablePtr->TableBase;
  CopyMem ((VOID*)&TableHeader, Script, sizeof(EFI_BOOT_SCRIPT_TABLE_HEADER));
  if (TableHeader.OpCode != S3_BOOT_SCRIPT_LIB_TABLE_OPCODE) {
    return EFI_INVALID_PARAMETER;
  }
  StartAddress  = (UINTN) Script;
  TableLength   = mS3BootScriptTablePtr->TableLength;
  Script    =     Script + TableHeader.Length;
  while ((UINTN) Script < (UINTN) (StartAddress + TableLength)) {

    CopyMem ((VOID*)&ScriptHeader, Script, sizeof(EFI_BOOT_SCRIPT_COMMON_HEADER));
    if (ScriptHeader.OpCode == S3_BOOT_SCRIPT_LIB_LABEL_OPCODE) {
      if (AsciiStrCmp ((CHAR8 *)(UINTN)(Script+sizeof(EFI_BOOT_SCRIPT_INFORMATION)), Label) == 0) {
        (*Position) = Script;
        return EFI_SUCCESS;
      }
    }
    Script  = Script + ScriptHeader.Length;
  }
  if (CreateIfNotFound) {
    LabelLength = (UINT32)AsciiStrSize(Label);
    return S3BootScriptLabelInternal (BeforeOrAfter,Position, LabelLength, Label);
  } else {
    return EFI_NOT_FOUND;
  }
}


RETURN_STATUS EFIAPI S3BootScriptCompare ( IN  UINT8                       *Position1, IN  UINT8                       *Position2, OUT UINTN                       *RelativePosition )





{
  UINT8*                    Script;
  UINT32                    TableLength;

  if (RelativePosition == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  
  
  
  Script = S3BootScriptGetEntryAddAddress (0);
  if (Script == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }
  Script = mS3BootScriptTablePtr->TableBase;

  
  
  
  TableLength = mS3BootScriptTablePtr->TableLength + sizeof (EFI_BOOT_SCRIPT_TERMINATE);
  if (Position1 < Script || Position1 > Script+TableLength) {
    return EFI_INVALID_PARAMETER;
  }
  if (Position2 < Script || Position2 > Script+TableLength) {
    return EFI_INVALID_PARAMETER;
  }
  *RelativePosition = (Position1 < Position2)?-1:((Position1 == Position2)?0:1);

  return EFI_SUCCESS;
}

