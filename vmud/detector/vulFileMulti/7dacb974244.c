






PWSTR DatabasePath = L"\\Registry\\Machine\\System\\MountedDevices";
PWSTR OfflinePath = L"\\Registry\\Machine\\System\\MountedDevices\\Offline";

UNICODE_STRING RemoteDatabase = RTL_CONSTANT_STRING(L"\\System Volume Information\\MountPointManagerRemoteDatabase");
UNICODE_STRING RemoteDatabaseFile = RTL_CONSTANT_STRING(L"\\:$MountMgrRemoteDatabase");


LONG GetRemoteDatabaseSize(IN HANDLE Database)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION StandardInfo;

    
    Status = ZwQueryInformationFile(Database, &IoStatusBlock, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);



    if (NT_SUCCESS(Status))
    {
        return StandardInfo.EndOfFile.LowPart;
    }

    return 0;
}


NTSTATUS AddRemoteDatabaseEntry(IN HANDLE Database, IN PDATABASE_ENTRY Entry)

{
    LARGE_INTEGER Size;
    IO_STATUS_BLOCK IoStatusBlock;

    
    Size.QuadPart = GetRemoteDatabaseSize(Database);

    return ZwWriteFile(Database, 0, NULL, NULL, &IoStatusBlock, Entry, Entry->EntrySize, &Size, NULL);

}


NTSTATUS CloseRemoteDatabase(IN HANDLE Database)
{
    return ZwClose(Database);
}


NTSTATUS TruncateRemoteDatabase(IN HANDLE Database, IN LONG NewSize)

{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_END_OF_FILE_INFORMATION EndOfFile;
    FILE_ALLOCATION_INFORMATION Allocation;

    EndOfFile.EndOfFile.QuadPart = NewSize;
    Allocation.AllocationSize.QuadPart = NewSize;

    
    Status = ZwSetInformationFile(Database, &IoStatusBlock, &EndOfFile, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);



    if (NT_SUCCESS(Status))
    {
        
        Status = ZwSetInformationFile(Database, &IoStatusBlock, &Allocation, sizeof(FILE_ALLOCATION_INFORMATION), FileAllocationInformation);



    }

    return Status;
}


PDATABASE_ENTRY GetRemoteDatabaseEntry(IN HANDLE Database, IN LONG StartingOffset)

{
    NTSTATUS Status;
    ULONG EntrySize;
    PDATABASE_ENTRY Entry;
    LARGE_INTEGER ByteOffset;
    IO_STATUS_BLOCK IoStatusBlock;

    
    ByteOffset.QuadPart = StartingOffset;
    Status = ZwReadFile(Database, NULL, NULL, NULL, &IoStatusBlock, &EntrySize, sizeof(EntrySize), &ByteOffset, NULL);







    if (!NT_SUCCESS(Status))
    {
        return NULL;
    }

    
    if (!EntrySize)
    {
        TruncateRemoteDatabase(Database, StartingOffset);
        return NULL;
    }

    
    Entry = AllocatePool(EntrySize);
    if (!Entry)
    {
        return NULL;
    }

    
    Status = ZwReadFile(Database, NULL, NULL, NULL, &IoStatusBlock, Entry, EntrySize, &ByteOffset, NULL);







    
    if (!NT_SUCCESS(Status) || (IoStatusBlock.Information != EntrySize) || (EntrySize < sizeof(DATABASE_ENTRY)) )

    {
        TruncateRemoteDatabase(Database, StartingOffset);
        FreePool(Entry);
        return NULL;
    }

    
    if (MAX(Entry->SymbolicNameOffset + Entry->SymbolicNameLength, Entry->UniqueIdOffset + Entry->UniqueIdLength) > (LONG)EntrySize)
    {
        TruncateRemoteDatabase(Database, StartingOffset);
        FreePool(Entry);
        return NULL;
    }

    return Entry;
}


NTSTATUS WriteRemoteDatabaseEntry(IN HANDLE Database, IN LONG Offset, IN PDATABASE_ENTRY Entry)


{
    NTSTATUS Status;
    LARGE_INTEGER ByteOffset;
    IO_STATUS_BLOCK IoStatusBlock;

    ByteOffset.QuadPart = Offset;
    Status = ZwWriteFile(Database, NULL, NULL, NULL, &IoStatusBlock, Entry, Entry->EntrySize, &ByteOffset, NULL);







    if (NT_SUCCESS(Status))
    {
        if (IoStatusBlock.Information < Entry->EntrySize)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    return Status;
}


NTSTATUS DeleteRemoteDatabaseEntry(IN HANDLE Database, IN LONG StartingOffset)

{
    ULONG EndSize;
    PVOID TmpBuffer;
    NTSTATUS Status;
    ULONG DatabaseSize;
    PDATABASE_ENTRY Entry;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER EndEntriesOffset;

    
    DatabaseSize = GetRemoteDatabaseSize(Database);
    if (!DatabaseSize)
    {
        return STATUS_INVALID_PARAMETER;
    }

    
    Entry = GetRemoteDatabaseEntry(Database, StartingOffset);
    if (!Entry)
    {
        return STATUS_INVALID_PARAMETER;
    }

    
    if (Entry->EntrySize + StartingOffset > DatabaseSize)
    {
        
        FreePool(Entry);
        return TruncateRemoteDatabase(Database, StartingOffset);
    }

    
    EndSize = DatabaseSize - Entry->EntrySize - StartingOffset;
    
    TmpBuffer = AllocatePool(EndSize);
    if (!TmpBuffer)
    {
        FreePool(Entry);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    
    EndEntriesOffset.QuadPart = Entry->EntrySize + StartingOffset;
    
    FreePool(Entry);

    
    Status = ZwReadFile(Database, NULL, NULL, NULL, &IoStatusBlock, TmpBuffer, EndSize, &EndEntriesOffset, NULL);
    if (!NT_SUCCESS(Status))
    {
        FreePool(TmpBuffer);
        return Status;
    }

    
    if (IoStatusBlock.Information != EndSize)
    {
        FreePool(TmpBuffer);
        return STATUS_INVALID_PARAMETER;
    }

    
    Status = TruncateRemoteDatabase(Database, StartingOffset + EndSize);
    if (!NT_SUCCESS(Status))
    {
        FreePool(TmpBuffer);
        return Status;
    }

    
    EndEntriesOffset.QuadPart = StartingOffset;
    Status = ZwWriteFile(Database, NULL, NULL, NULL, &IoStatusBlock, TmpBuffer, EndSize, &EndEntriesOffset, NULL);

    FreePool(TmpBuffer);

    return Status;
}


NTSTATUS NTAPI DeleteFromLocalDatabaseRoutine(IN PWSTR ValueName, IN ULONG ValueType, IN PVOID ValueData, IN ULONG ValueLength, IN PVOID Context, IN PVOID EntryContext)






{
    PMOUNTDEV_UNIQUE_ID UniqueId = Context;

    UNREFERENCED_PARAMETER(ValueType);
    UNREFERENCED_PARAMETER(EntryContext);

    
    if ((UniqueId->UniqueIdLength == ValueLength) && (RtlCompareMemory(UniqueId->UniqueId, ValueData, ValueLength) == ValueLength))

    {
        RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, DatabasePath, ValueName);

    }

    return STATUS_SUCCESS;
}


VOID DeleteFromLocalDatabase(IN PUNICODE_STRING SymbolicLink, IN PMOUNTDEV_UNIQUE_ID UniqueId)

{
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];

    RtlZeroMemory(QueryTable, sizeof(QueryTable));
    QueryTable[0].QueryRoutine = DeleteFromLocalDatabaseRoutine;
    QueryTable[0].Name = SymbolicLink->Buffer;

    RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, DatabasePath, QueryTable, UniqueId, NULL);



}


NTSTATUS WaitForRemoteDatabaseSemaphore(IN PDEVICE_EXTENSION DeviceExtension)
{
    NTSTATUS Status;
    LARGE_INTEGER Timeout;

    
    Timeout.QuadPart = 0xFA0A1F00;
    Status = KeWaitForSingleObject(&(DeviceExtension->RemoteDatabaseLock), Executive, KernelMode, FALSE, &Timeout);
    if (Status != STATUS_TIMEOUT)
    {
        return Status;
    }

    return STATUS_IO_TIMEOUT;
}


VOID ReleaseRemoteDatabaseSemaphore(IN PDEVICE_EXTENSION DeviceExtension)
{
    KeReleaseSemaphore(&(DeviceExtension->RemoteDatabaseLock), IO_NO_INCREMENT, 1, FALSE);
}


NTSTATUS NTAPI QueryUniqueIdQueryRoutine(IN PWSTR ValueName, IN ULONG ValueType, IN PVOID ValueData, IN ULONG ValueLength, IN PVOID Context, IN PVOID EntryContext)






{
    PMOUNTDEV_UNIQUE_ID IntUniqueId;
    PMOUNTDEV_UNIQUE_ID * UniqueId;

    UNREFERENCED_PARAMETER(ValueName);
    UNREFERENCED_PARAMETER(ValueType);
    UNREFERENCED_PARAMETER(EntryContext);

    
    if (ValueLength >= 0x10000)
    {
        return STATUS_SUCCESS;
    }

    
    IntUniqueId = AllocatePool(sizeof(UniqueId) + ValueLength);
    if (IntUniqueId)
    {
        
        IntUniqueId->UniqueIdLength = (USHORT)ValueLength;
        RtlCopyMemory(&(IntUniqueId->UniqueId), ValueData, ValueLength);

        UniqueId = Context;
        *UniqueId = IntUniqueId;
    }

    return STATUS_SUCCESS;
}


NTSTATUS QueryUniqueIdFromMaster(IN PDEVICE_EXTENSION DeviceExtension, IN PUNICODE_STRING SymbolicName, OUT PMOUNTDEV_UNIQUE_ID * UniqueId)


{
    NTSTATUS Status;
    PDEVICE_INFORMATION DeviceInformation;
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];

    
    RtlZeroMemory(QueryTable, sizeof(QueryTable));
    QueryTable[0].QueryRoutine = QueryUniqueIdQueryRoutine;
    QueryTable[0].Name = SymbolicName->Buffer;

    *UniqueId = NULL;
    RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, DatabasePath, QueryTable, UniqueId, NULL);



    
    if (*UniqueId)
    {
        return STATUS_SUCCESS;
    }

    
    Status = FindDeviceInfo(DeviceExtension, SymbolicName, FALSE, &DeviceInformation);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    *UniqueId = AllocatePool(DeviceInformation->UniqueId->UniqueIdLength + sizeof(MOUNTDEV_UNIQUE_ID));
    if (!*UniqueId)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    
    (*UniqueId)->UniqueIdLength = DeviceInformation->UniqueId->UniqueIdLength;
    RtlCopyMemory(&((*UniqueId)->UniqueId), &(DeviceInformation->UniqueId->UniqueId), (*UniqueId)->UniqueIdLength);

    return STATUS_SUCCESS;
}


NTSTATUS WriteUniqueIdToMaster(IN PDEVICE_EXTENSION DeviceExtension, IN PDATABASE_ENTRY DatabaseEntry)

{
    NTSTATUS Status;
    PWCHAR SymbolicName;
    PLIST_ENTRY NextEntry;
    UNICODE_STRING SymbolicString;
    PDEVICE_INFORMATION DeviceInformation;

    
    SymbolicName = AllocatePool(DatabaseEntry->SymbolicNameLength + sizeof(WCHAR));
    if (!SymbolicName)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(SymbolicName, (PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->SymbolicNameOffset), DatabaseEntry->SymbolicNameLength);

    SymbolicName[DatabaseEntry->SymbolicNameLength / sizeof(WCHAR)] = UNICODE_NULL;

    
    Status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, DatabasePath, SymbolicName, REG_BINARY, (PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->UniqueIdOffset), DatabaseEntry->UniqueIdLength);




    FreePool(SymbolicName);

    
    SymbolicString.Length = DatabaseEntry->SymbolicNameLength;
    SymbolicString.MaximumLength = DatabaseEntry->SymbolicNameLength;
    SymbolicString.Buffer = (PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->SymbolicNameOffset);

    
    for (NextEntry = DeviceExtension->DeviceListHead.Flink;
         NextEntry != &(DeviceExtension->DeviceListHead);
         NextEntry = NextEntry->Flink)
    {
        DeviceInformation = CONTAINING_RECORD(NextEntry, DEVICE_INFORMATION, DeviceListEntry);


        if (DeviceInformation->UniqueId->UniqueIdLength != DatabaseEntry->UniqueIdLength)
        {
            continue;
        }

        if (RtlCompareMemory((PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->UniqueIdOffset), DeviceInformation->UniqueId->UniqueId, DatabaseEntry->UniqueIdLength) == DatabaseEntry->UniqueIdLength)

        {
            break;
        }
    }

    
    if (NextEntry != &(DeviceExtension->DeviceListHead))
    {
        MountMgrCreatePointWorker(DeviceExtension, &SymbolicString, &(DeviceInformation->DeviceName));
    }

    return Status;
}


VOID NTAPI ReconcileThisDatabaseWithMasterWorker(IN PVOID Parameter)

{
    ULONG Offset;
    NTSTATUS Status;
    PFILE_OBJECT FileObject;
    PDEVICE_OBJECT DeviceObject;
    PMOUNTDEV_UNIQUE_ID UniqueId;
    PDATABASE_ENTRY DatabaseEntry;
    HANDLE DatabaseHandle, Handle;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PDEVICE_INFORMATION ListDeviceInfo;
    PLIST_ENTRY Entry, EntryInfo, NextEntry;
    PASSOCIATED_DEVICE_ENTRY AssociatedDevice;
    BOOLEAN HardwareErrors, Restart, FailedFinding;
    WCHAR FileNameBuffer[0x8], SymbolicNameBuffer[100];
    UNICODE_STRING ReparseFile, FileName, SymbolicName, VolumeName;
    FILE_REPARSE_POINT_INFORMATION ReparsePointInformation, SavedReparsePointInformation;
    PDEVICE_EXTENSION DeviceExtension = ((PRECONCILE_WORK_ITEM_CONTEXT)Parameter)->DeviceExtension;
    PDEVICE_INFORMATION DeviceInformation = ((PRECONCILE_WORK_ITEM_CONTEXT)Parameter)->DeviceInformation;

    
    if (Unloading)
    {
        return;
    }

    
    if (!NT_SUCCESS(WaitForRemoteDatabaseSemaphore(DeviceExtension)))
    {
        return;
    }

    
    if (Unloading)
    {
        goto ReleaseRDS;
    }

    
    KeWaitForSingleObject(&DeviceExtension->DeviceLock, Executive, KernelMode, FALSE, NULL);
    for (Entry = DeviceExtension->DeviceListHead.Flink;
         Entry != &DeviceExtension->DeviceListHead;
         Entry = Entry->Flink)
    {
        ListDeviceInfo = CONTAINING_RECORD(Entry, DEVICE_INFORMATION, DeviceListEntry);
        if (ListDeviceInfo == DeviceInformation)
        {
            break;
        }
    }

    
    if (Entry == &DeviceExtension->DeviceListHead || DeviceInformation->Removable)
    {
        KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
        goto ReleaseRDS;
    }

    
    Status = IoGetDeviceObjectPointer(&ListDeviceInfo->DeviceName, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
        goto ReleaseRDS;
    }

    if (DeviceObject->Flags & 1)
    {
        _InterlockedExchangeAdd(&ListDeviceInfo->MountState, 1u);
    }

    ObDereferenceObject(FileObject);

    
    DeviceInformation->NeedsReconcile = TRUE;
    DeviceInformation->NoDatabase = TRUE;
    FailedFinding = FALSE;

    
    for (Entry = DeviceExtension->DeviceListHead.Flink;
         Entry != &DeviceExtension->DeviceListHead;
         Entry = Entry->Flink)
    {
        ListDeviceInfo = CONTAINING_RECORD(Entry, DEVICE_INFORMATION, DeviceListEntry);

        EntryInfo = ListDeviceInfo->AssociatedDevicesHead.Flink;
        while (EntryInfo != &ListDeviceInfo->AssociatedDevicesHead)
        {
            AssociatedDevice = CONTAINING_RECORD(EntryInfo, ASSOCIATED_DEVICE_ENTRY, AssociatedDevicesEntry);
            NextEntry = EntryInfo->Flink;

            if (AssociatedDevice->DeviceInformation == DeviceInformation)
            {
                RemoveEntryList(&AssociatedDevice->AssociatedDevicesEntry);
                FreePool(AssociatedDevice->String.Buffer);
                FreePool(AssociatedDevice);
            }

            EntryInfo = NextEntry;
        }
    }

    
    DatabaseHandle = OpenRemoteDatabase(DeviceInformation, FALSE);

    
    ReparseFile.Length = DeviceInformation->DeviceName.Length + ReparseIndex.Length;
    ReparseFile.MaximumLength = ReparseFile.Length + sizeof(UNICODE_NULL);
    ReparseFile.Buffer = AllocatePool(ReparseFile.MaximumLength);
    if (ReparseFile.Buffer == NULL)
    {
        if (DatabaseHandle != 0)
        {
            CloseRemoteDatabase(DatabaseHandle);
        }
        KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
        goto ReleaseRDS;
    }

    
    RtlCopyMemory(ReparseFile.Buffer, DeviceInformation->DeviceName.Buffer, DeviceInformation->DeviceName.Length);
    RtlCopyMemory((PVOID)((ULONG_PTR)ReparseFile.Buffer + DeviceInformation->DeviceName.Length), ReparseFile.Buffer, ReparseFile.Length);
    ReparseFile.Buffer[ReparseFile.Length / sizeof(WCHAR)] = UNICODE_NULL;

    InitializeObjectAttributes(&ObjectAttributes, &ReparseFile, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);




    
    HardwareErrors = IoSetThreadHardErrorMode(FALSE);
    Status = ZwOpenFile(&Handle, FILE_GENERIC_READ, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_ALERT);




    IoSetThreadHardErrorMode(HardwareErrors);

    FreePool(ReparseFile.Buffer);

    if (!NT_SUCCESS(Status))
    {
        if (DatabaseHandle != 0)
        {
            TruncateRemoteDatabase(DatabaseHandle, 0);
            CloseRemoteDatabase(DatabaseHandle);
        }
        KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
        goto ReleaseRDS;
    }

    
    RtlZeroMemory(FileNameBuffer, sizeof(FileNameBuffer));
    FileName.Buffer = FileNameBuffer;
    FileName.Length = sizeof(FileNameBuffer);
    FileName.MaximumLength = sizeof(FileNameBuffer);
    ((PULONG)FileNameBuffer)[0] = IO_REPARSE_TAG_MOUNT_POINT;
    Status = ZwQueryDirectoryFile(Handle, NULL, NULL, NULL, &IoStatusBlock, &ReparsePointInformation, sizeof(FILE_REPARSE_POINT_INFORMATION), FileReparsePointInformation, TRUE, &FileName, FALSE);









    if (!NT_SUCCESS(Status))
    {
        ZwClose(Handle);
        if (DatabaseHandle != 0)
        {
            TruncateRemoteDatabase(DatabaseHandle, 0);
            CloseRemoteDatabase(DatabaseHandle);
        }
        KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
        goto ReleaseRDS;
    }

    
    if (DatabaseHandle == 0)
    {
        DatabaseHandle = OpenRemoteDatabase(DeviceInformation, TRUE);
        if (DatabaseHandle == 0)
        {
            KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
            goto ReleaseRDS;
        }
    }

    KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);

    
    Offset = 0;
    for (;;)
    {
        DatabaseEntry = GetRemoteDatabaseEntry(DatabaseHandle, Offset);
        if (DatabaseEntry == NULL)
        {
            break;
        }

        DatabaseEntry->EntryReferences = 0;
        Status = WriteRemoteDatabaseEntry(DatabaseHandle, Offset, DatabaseEntry);
        if (!NT_SUCCESS(Status))
        {
            FreePool(DatabaseEntry);
            goto CloseReparse;
        }

        Offset += DatabaseEntry->EntrySize;
        FreePool(DatabaseEntry);
    }

    
    SymbolicName.MaximumLength = sizeof(SymbolicNameBuffer);
    SymbolicName.Length = 0;
    SymbolicName.Buffer = SymbolicNameBuffer;
    Restart = TRUE;

    
    for (;;)
    {
        RtlCopyMemory(&SavedReparsePointInformation, &ReparsePointInformation, sizeof(FILE_REPARSE_POINT_INFORMATION));
        Status = ZwQueryDirectoryFile(Handle, NULL, NULL, NULL, &IoStatusBlock, &ReparsePointInformation, sizeof(FILE_REPARSE_POINT_INFORMATION), FileReparsePointInformation, TRUE, Restart ? &FileName : NULL, Restart);









        
        if (Restart)
        {
            Restart = FALSE;
        }
        else {
            
            if (ReparsePointInformation.FileReference == SavedReparsePointInformation.FileReference && ReparsePointInformation.Tag == SavedReparsePointInformation.Tag)
            {
                break;
            }
        }

        
        if (!NT_SUCCESS(Status) || Unloading || ReparsePointInformation.Tag != IO_REPARSE_TAG_MOUNT_POINT)
        {
            break;
        }

        
        Status = QueryVolumeName(Handle, &ReparsePointInformation, 0, &SymbolicName, &VolumeName);
        if (!NT_SUCCESS(Status))
        {
            continue;
        }

        
        Offset = 0;
        for (;;)
        {
            UNICODE_STRING DbName;

            DatabaseEntry = GetRemoteDatabaseEntry(DatabaseHandle, Offset);
            if (DatabaseEntry == NULL)
            {
                break;
            }

            DbName.MaximumLength = DatabaseEntry->SymbolicNameLength;
            DbName.Length = DbName.MaximumLength;
            DbName.Buffer = (PWSTR)((ULONG_PTR)DatabaseEntry + DatabaseEntry->SymbolicNameOffset);
            
            if (RtlEqualUnicodeString(&DbName, &SymbolicName, TRUE))
            {
                break;
            }

            Offset += DatabaseEntry->EntrySize;
            FreePool(DatabaseEntry);
        }

        
        if (DatabaseEntry != NULL)
        {
            
            if (DatabaseEntry->EntryReferences)
            {
                ++DatabaseEntry->EntryReferences;
                Status = WriteRemoteDatabaseEntry(DatabaseHandle, Offset, DatabaseEntry);
                if (!NT_SUCCESS(Status))
                {
                    goto FreeDBEntry;
                }

                FreePool(DatabaseEntry);
            }
            else {
                
                KeWaitForSingleObject(&DeviceExtension->DeviceLock, Executive, KernelMode, FALSE, NULL);
                Status = QueryUniqueIdFromMaster(DeviceExtension, &SymbolicName, &UniqueId);
                if (!NT_SUCCESS(Status))
                {
                    
                    Status = WriteUniqueIdToMaster(DeviceExtension, DatabaseEntry);
                    if (!NT_SUCCESS(Status))
                    {
                        goto ReleaseDeviceLock;
                    }

                    
                    ++DatabaseEntry->EntryReferences;
                    Status = WriteRemoteDatabaseEntry(DatabaseHandle, Offset, DatabaseEntry);
                    if (!NT_SUCCESS(Status))
                    {
                        goto ReleaseDeviceLock;
                    }

                    KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
                    FreePool(DatabaseEntry);
                }
                
                else if (UniqueId->UniqueIdLength == DatabaseEntry->UniqueIdLength && RtlCompareMemory(UniqueId->UniqueId, (PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->UniqueIdOffset), UniqueId->UniqueIdLength) == UniqueId->UniqueIdLength)


                {
                    
                    ++DatabaseEntry->EntryReferences;
                    Status = WriteRemoteDatabaseEntry(DatabaseHandle, Offset, DatabaseEntry);
                    if (!NT_SUCCESS(Status))
                    {
                        goto FreeUniqueId;
                    }

                    FreePool(UniqueId);
                    KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
                    FreePool(DatabaseEntry);
                }
                
                else if (IsUniqueIdPresent(DeviceExtension, DatabaseEntry))
                {
                    
                    Status = WriteUniqueIdToMaster(DeviceExtension, DatabaseEntry);
                    if (!NT_SUCCESS(Status))
                    {
                        goto FreeUniqueId;
                    }

                    
                    ++DatabaseEntry->EntryReferences;
                    Status = WriteRemoteDatabaseEntry(DatabaseHandle, Offset, DatabaseEntry);
                    if (!NT_SUCCESS(Status))
                    {
                        goto FreeUniqueId;
                    }

                    FreePool(UniqueId);
                    KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
                    FreePool(DatabaseEntry);
                }
                else {
                    
                    Status = DeleteRemoteDatabaseEntry(DatabaseHandle, Offset);
                    if (!NT_SUCCESS(Status))
                    {
                        goto FreeUniqueId;
                    }

                    FreePool(DatabaseEntry);
                    
                    DatabaseEntry = AllocatePool(UniqueId->UniqueIdLength + SymbolicName.Length + sizeof(DATABASE_ENTRY));
                    if (DatabaseEntry == NULL)
                    {
                       goto FreeUniqueId;
                    }

                    
                    DatabaseEntry->EntrySize = UniqueId->UniqueIdLength + SymbolicName.Length + sizeof(DATABASE_ENTRY);
                    DatabaseEntry->EntryReferences = 1;
                    DatabaseEntry->SymbolicNameOffset = sizeof(DATABASE_ENTRY);
                    DatabaseEntry->SymbolicNameLength = SymbolicName.Length;
                    DatabaseEntry->UniqueIdOffset = SymbolicName.Length + sizeof(DATABASE_ENTRY);
                    DatabaseEntry->UniqueIdLength = UniqueId->UniqueIdLength;
                    RtlCopyMemory((PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->SymbolicNameOffset), SymbolicName.Buffer, DatabaseEntry->SymbolicNameLength);
                    RtlCopyMemory((PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->UniqueIdOffset), UniqueId->UniqueId, UniqueId->UniqueIdLength);

                    
                    Status = AddRemoteDatabaseEntry(DatabaseHandle, DatabaseEntry);
                    if (!NT_SUCCESS(Status))
                    {
                       FreePool(DatabaseEntry);
                       goto FreeUniqueId;
                    }

                    FreePool(UniqueId);
                    FreePool(DatabaseEntry);
                    KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
                }
            }
        }
        else {
            
            KeWaitForSingleObject(&DeviceExtension->DeviceLock, Executive, KernelMode, FALSE, NULL);
            
            Status = QueryUniqueIdFromMaster(DeviceExtension, &SymbolicName, &UniqueId);
            KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
            if (NT_SUCCESS(Status))
            {
                
                DatabaseEntry = AllocatePool(UniqueId->UniqueIdLength + SymbolicName.Length + sizeof(DATABASE_ENTRY));
                if (DatabaseEntry != NULL)
                {
                    
                    DatabaseEntry->EntrySize = UniqueId->UniqueIdLength + SymbolicName.Length + sizeof(DATABASE_ENTRY);
                    DatabaseEntry->EntryReferences = 1;
                    DatabaseEntry->SymbolicNameOffset = sizeof(DATABASE_ENTRY);
                    DatabaseEntry->SymbolicNameLength = SymbolicName.Length;
                    DatabaseEntry->UniqueIdOffset = SymbolicName.Length + sizeof(DATABASE_ENTRY);
                    DatabaseEntry->UniqueIdLength = UniqueId->UniqueIdLength;
                    RtlCopyMemory((PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->SymbolicNameOffset), SymbolicName.Buffer, DatabaseEntry->SymbolicNameLength);
                    RtlCopyMemory((PVOID)((ULONG_PTR)DatabaseEntry + DatabaseEntry->UniqueIdOffset), UniqueId->UniqueId, UniqueId->UniqueIdLength);

                    
                    Status = AddRemoteDatabaseEntry(DatabaseHandle, DatabaseEntry);
                    FreePool(DatabaseEntry);
                    FreePool(UniqueId);

                    if (!NT_SUCCESS(Status))
                    {
                        goto FreeVolume;
                    }
                }
                else {
                    FreePool(UniqueId);
                }
            }
        }

        
        KeWaitForSingleObject(&DeviceExtension->DeviceLock, Executive, KernelMode, FALSE, NULL);
        Status = FindDeviceInfo(DeviceExtension, &SymbolicName, FALSE, &ListDeviceInfo);
        if (!NT_SUCCESS(Status))
        {
            FailedFinding = TRUE;
            FreePool(VolumeName.Buffer);
        }
        else {
            
            AssociatedDevice = AllocatePool(sizeof(ASSOCIATED_DEVICE_ENTRY));
            if (AssociatedDevice == NULL)
            {
                FreePool(VolumeName.Buffer);
            }
            else {
                AssociatedDevice->DeviceInformation = DeviceInformation;
                AssociatedDevice->String.Length = VolumeName.Length;
                AssociatedDevice->String.MaximumLength = VolumeName.MaximumLength;
                AssociatedDevice->String.Buffer = VolumeName.Buffer;
                InsertTailList(&ListDeviceInfo->AssociatedDevicesHead, &AssociatedDevice->AssociatedDevicesEntry);
            }

            
            if (!ListDeviceInfo->SkipNotifications)
            {
                PostOnlineNotification(DeviceExtension, &ListDeviceInfo->SymbolicName);
            }
        }

        KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
    }

    
    ZwClose(Handle);

    
    KeWaitForSingleObject(&DeviceExtension->DeviceLock, Executive, KernelMode, FALSE, NULL);
    for (Entry = DeviceExtension->DeviceListHead.Flink;
         Entry != &DeviceExtension->DeviceListHead;
         Entry = Entry->Flink)
    {
        ListDeviceInfo = CONTAINING_RECORD(Entry, DEVICE_INFORMATION, DeviceListEntry);
        if (ListDeviceInfo == DeviceInformation)
        {
            break;
        }
    }

    if (Entry == &DeviceExtension->DeviceListHead)
    {
        ListDeviceInfo = NULL;
    }

    
    Offset = 0;
    for (;;)
    {
        
        DatabaseEntry = GetRemoteDatabaseEntry(DatabaseHandle, Offset);
        if (DatabaseEntry == NULL)
        {
            break;
        }

        
        if (DatabaseEntry->EntryReferences == 0)
        {
            Status = DeleteRemoteDatabaseEntry(DatabaseHandle, Offset);
            if (!NT_SUCCESS(Status))
            {
                FreePool(DatabaseEntry);
                KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
                goto CloseRDB;
            }
        }
        
        else {
            if (ListDeviceInfo != NULL)
            {
                UpdateReplicatedUniqueIds(ListDeviceInfo, DatabaseEntry);
            }

            Offset += DatabaseEntry->EntrySize;
        }

        FreePool(DatabaseEntry);
    }

    
    if (ListDeviceInfo != NULL && !FailedFinding)
    {
        DeviceInformation->NoDatabase = FALSE;
    }

    KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);

    goto CloseRDB;

FreeUniqueId:
    FreePool(UniqueId);
ReleaseDeviceLock:
    KeReleaseSemaphore(&DeviceExtension->DeviceLock, IO_NO_INCREMENT, 1, FALSE);
FreeDBEntry:
    FreePool(DatabaseEntry);
FreeVolume:
    FreePool(VolumeName.Buffer);
CloseReparse:
    ZwClose(Handle);
CloseRDB:
    CloseRemoteDatabase(DatabaseHandle);
ReleaseRDS:
    ReleaseRemoteDatabaseSemaphore(DeviceExtension);
    return;
}


VOID NTAPI WorkerThread(IN PDEVICE_OBJECT DeviceObject, IN PVOID Context)


{
    ULONG i;
    KEVENT Event;
    KIRQL OldIrql;
    NTSTATUS Status;
    HANDLE SafeEvent;
    PLIST_ENTRY Entry;
    LARGE_INTEGER Timeout;
    PRECONCILE_WORK_ITEM WorkItem;
    PDEVICE_EXTENSION DeviceExtension;
    OBJECT_ATTRIBUTES ObjectAttributes;

    UNREFERENCED_PARAMETER(DeviceObject);

    InitializeObjectAttributes(&ObjectAttributes, &SafeVolumes, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);



    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Timeout.LowPart = 0xFFFFFFFF;
    Timeout.HighPart = 0xFF676980;

    
    for (i = (Unloading ? 999 : 0); i < 1000; i++)
    {
        Status = ZwOpenEvent(&SafeEvent, EVENT_ALL_ACCESS, &ObjectAttributes);
        if (NT_SUCCESS(Status))
        {
            break;
        }

        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &Timeout);
    }

    if (i < 1000)
    {
        do {
            Status = ZwWaitForSingleObject(SafeEvent, FALSE, &Timeout);
        }
        while (Status == STATUS_TIMEOUT && !Unloading);

        ZwClose(SafeEvent);
    }

    DeviceExtension = Context;

    InterlockedExchange(&(DeviceExtension->WorkerThreadStatus), 1);

    
    KeWaitForSingleObject(&(DeviceExtension->WorkerSemaphore), Executive, KernelMode, FALSE, NULL);

    KeAcquireSpinLock(&(DeviceExtension->WorkerLock), &OldIrql);

    
    while (!IsListEmpty(&(DeviceExtension->WorkerQueueListHead)))
    {
        
        Entry = RemoveHeadList(&(DeviceExtension->WorkerQueueListHead));
        WorkItem = CONTAINING_RECORD(Entry, RECONCILE_WORK_ITEM, WorkerQueueListEntry);


        KeReleaseSpinLock(&(DeviceExtension->WorkerLock), OldIrql);

        
        WorkItem->WorkerRoutine(WorkItem->Context);

        IoFreeWorkItem(WorkItem->WorkItem);
        FreePool(WorkItem);

        if (InterlockedDecrement(&(DeviceExtension->WorkerReferences)) == 0)
        {
            return;
        }

        KeWaitForSingleObject(&(DeviceExtension->WorkerSemaphore), Executive, KernelMode, FALSE, NULL);
        KeAcquireSpinLock(&(DeviceExtension->WorkerLock), &OldIrql);
    }
    KeReleaseSpinLock(&(DeviceExtension->WorkerLock), OldIrql);

    InterlockedDecrement(&(DeviceExtension->WorkerReferences));

    
    KeSetEvent(&UnloadEvent, IO_NO_INCREMENT, FALSE);
}


NTSTATUS QueueWorkItem(IN PDEVICE_EXTENSION DeviceExtension, IN PRECONCILE_WORK_ITEM WorkItem, IN PVOID Context)


{
    KIRQL OldIrql;

    WorkItem->Context = Context;

    

    
    if (InterlockedIncrement(&(DeviceExtension->WorkerReferences)))
    {
        IoQueueWorkItem(WorkItem->WorkItem, WorkerThread, DelayedWorkQueue, DeviceExtension);
    }

    
    KeAcquireSpinLock(&(DeviceExtension->WorkerLock), &OldIrql);
    InsertTailList(&(DeviceExtension->WorkerQueueListHead), &(WorkItem->WorkerQueueListEntry));
    KeReleaseSpinLock(&(DeviceExtension->WorkerLock), OldIrql);

    KeReleaseSemaphore(&(DeviceExtension->WorkerSemaphore), IO_NO_INCREMENT, 1, FALSE);

    return STATUS_SUCCESS;
}


NTSTATUS QueryVolumeName(IN HANDLE RootDirectory, IN PFILE_REPARSE_POINT_INFORMATION ReparsePointInformation, IN PUNICODE_STRING FileName OPTIONAL, OUT PUNICODE_STRING SymbolicName, OUT PUNICODE_STRING VolumeName)




{
    HANDLE Handle;
    NTSTATUS Status;
    ULONG NeededLength;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PFILE_NAME_INFORMATION FileNameInfo;
    PREPARSE_DATA_BUFFER ReparseDataBuffer;

    UNREFERENCED_PARAMETER(ReparsePointInformation);

    if (!FileName)
    {
        InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, RootDirectory, NULL);



    }
    else {
        InitializeObjectAttributes(&ObjectAttributes, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);



    }

    
    Status = ZwOpenFile(&Handle, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, (FileName) ? FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT :




                                     FILE_OPEN_BY_FILE_ID | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    
    ReparseDataBuffer = AllocatePool(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    if (!ReparseDataBuffer)
    {
        ZwClose(Handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwFsControlFile(Handle, 0, NULL, NULL, &IoStatusBlock, FSCTL_GET_REPARSE_POINT, NULL, 0, ReparseDataBuffer, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);








    if (!NT_SUCCESS(Status))
    {
        FreePool(ReparseDataBuffer);
        ZwClose(Handle);
        return Status;
    }

    
    if (ReparseDataBuffer->MountPointReparseBuffer.SubstituteNameLength + sizeof(UNICODE_NULL) > SymbolicName->MaximumLength)
    {
        FreePool(ReparseDataBuffer);
        ZwClose(Handle);
        return STATUS_BUFFER_TOO_SMALL;
    }

    
    SymbolicName->Length = ReparseDataBuffer->MountPointReparseBuffer.SubstituteNameLength;
    RtlCopyMemory(SymbolicName->Buffer, (PWSTR)((ULONG_PTR)ReparseDataBuffer->MountPointReparseBuffer.PathBuffer + ReparseDataBuffer->MountPointReparseBuffer.SubstituteNameOffset), ReparseDataBuffer->MountPointReparseBuffer.SubstituteNameLength);



    FreePool(ReparseDataBuffer);

    
    if (SymbolicName->Buffer[SymbolicName->Length / sizeof(WCHAR) - 1] != L'\\')
    {
        ZwClose(Handle);
        return STATUS_INVALID_PARAMETER;
    }

    
    SymbolicName->Length -= sizeof(WCHAR);
    SymbolicName->Buffer[SymbolicName->Length / sizeof(WCHAR)] = UNICODE_NULL;

    
    if (!MOUNTMGR_IS_VOLUME_NAME(SymbolicName))
    {
        ZwClose(Handle);
        return STATUS_INVALID_PARAMETER;
    }

    
    FileNameInfo = AllocatePool(sizeof(FILE_NAME_INFORMATION) + 2 * sizeof(WCHAR));
    if (!FileNameInfo)
    {
        ZwClose(Handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQueryInformationFile(Handle, &IoStatusBlock, FileNameInfo, sizeof(FILE_NAME_INFORMATION) + 2 * sizeof(WCHAR), FileNameInformation);



    if (Status == STATUS_BUFFER_OVERFLOW)
    {
        
        NeededLength = FileNameInfo->FileNameLength;
        FreePool(FileNameInfo);

        FileNameInfo = AllocatePool(sizeof(FILE_NAME_INFORMATION) + NeededLength);
        if (!FileNameInfo)
        {
            ZwClose(Handle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        
        Status = ZwQueryInformationFile(Handle, &IoStatusBlock, FileNameInfo, sizeof(FILE_NAME_INFORMATION) + NeededLength, FileNameInformation);



    }

    ZwClose(Handle);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    
    VolumeName->Length = (USHORT)FileNameInfo->FileNameLength;
    VolumeName->MaximumLength = (USHORT)FileNameInfo->FileNameLength + sizeof(WCHAR);
    VolumeName->Buffer = AllocatePool(VolumeName->MaximumLength);
    if (!VolumeName->Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(VolumeName->Buffer, FileNameInfo->FileName, FileNameInfo->FileNameLength);
    VolumeName->Buffer[FileNameInfo->FileNameLength / sizeof(WCHAR)] = UNICODE_NULL;

    FreePool(FileNameInfo);

    return STATUS_SUCCESS;
}


VOID OnlineMountedVolumes(IN PDEVICE_EXTENSION DeviceExtension, IN PDEVICE_INFORMATION DeviceInformation)

{
    HANDLE Handle;
    NTSTATUS Status;
    BOOLEAN RestartScan;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PDEVICE_INFORMATION VolumeDeviceInformation;
    WCHAR FileNameBuffer[0x8], SymbolicNameBuffer[0x64];
    UNICODE_STRING ReparseFile, FileName, SymbolicName, VolumeName;
    FILE_REPARSE_POINT_INFORMATION ReparsePointInformation, SavedReparsePointInformation;

    
    if (DeviceInformation->Removable)
    {
        return;
    }

    
    ReparseFile.Length = DeviceInformation->DeviceName.Length + ReparseIndex.Length;
    ReparseFile.MaximumLength = ReparseFile.Length + sizeof(UNICODE_NULL);
    ReparseFile.Buffer = AllocatePool(ReparseFile.MaximumLength);
    if (!ReparseFile.Buffer)
    {
        return;
    }

    RtlCopyMemory(ReparseFile.Buffer, DeviceInformation->DeviceName.Buffer, DeviceInformation->DeviceName.Length);
    RtlCopyMemory((PVOID)((ULONG_PTR)ReparseFile.Buffer + DeviceInformation->DeviceName.Length), ReparseFile.Buffer, ReparseFile.Length);
    ReparseFile.Buffer[ReparseFile.Length / sizeof(WCHAR)] = UNICODE_NULL;

    InitializeObjectAttributes(&ObjectAttributes, &ReparseFile, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);




    
    Status = ZwOpenFile(&Handle, FILE_GENERIC_READ, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_ALERT | FILE_OPEN_REPARSE_POINT);




    FreePool(ReparseFile.Buffer);
    if (!NT_SUCCESS(Status))
    {
        DeviceInformation->NoDatabase = FALSE;
        return;
    }

    
    RtlZeroMemory(FileNameBuffer, sizeof(FileNameBuffer));
    FileName.Buffer = FileNameBuffer;
    FileName.Length = sizeof(FileNameBuffer);
    FileName.MaximumLength = sizeof(FileNameBuffer);
    ((PULONG)FileNameBuffer)[0] = IO_REPARSE_TAG_MOUNT_POINT;
    Status = ZwQueryDirectoryFile(Handle, NULL, NULL, NULL, &IoStatusBlock, &ReparsePointInformation, sizeof(FILE_REPARSE_POINT_INFORMATION), FileReparsePointInformation, TRUE, &FileName, FALSE);









    if (!NT_SUCCESS(Status))
    {
        ZwClose(Handle);
        return;
    }

    RestartScan = TRUE;

    
    while (TRUE)
    {
        SymbolicName.Length = 0;
        SymbolicName.MaximumLength = sizeof(SymbolicNameBuffer);
        SymbolicName.Buffer = SymbolicNameBuffer;
        RtlCopyMemory(&SavedReparsePointInformation, &ReparsePointInformation, sizeof(FILE_REPARSE_POINT_INFORMATION));

        Status = ZwQueryDirectoryFile(Handle, NULL, NULL, NULL, &IoStatusBlock, &ReparsePointInformation, sizeof(FILE_REPARSE_POINT_INFORMATION), FileReparsePointInformation, TRUE, (RestartScan) ? &FileName : NULL, RestartScan);









         if (!RestartScan)
         {
             if (ReparsePointInformation.FileReference == SavedReparsePointInformation.FileReference && ReparsePointInformation.Tag == SavedReparsePointInformation.Tag)
             {
                 break;
             }
         }
         else {
             RestartScan = FALSE;
         }

         if (!NT_SUCCESS(Status) || ReparsePointInformation.Tag != IO_REPARSE_TAG_MOUNT_POINT)
         {
             break;
         }

         
         Status = QueryVolumeName(Handle, &ReparsePointInformation, NULL, &SymbolicName, &VolumeName);


         if (!NT_SUCCESS(Status))
         {
             continue;
         }

         FreePool(VolumeName.Buffer);

         
         Status = FindDeviceInfo(DeviceExtension, &SymbolicName, FALSE, &VolumeDeviceInformation);
         if (!NT_SUCCESS(Status))
         {
             DeviceInformation->NoDatabase = TRUE;
             continue;
         }

         
         if (!DeviceInformation->SkipNotifications)
         {
             PostOnlineNotification(DeviceExtension, &VolumeDeviceInformation->SymbolicName);
         }
    }

    ZwClose(Handle);
}


VOID ReconcileThisDatabaseWithMaster(IN PDEVICE_EXTENSION DeviceExtension, IN PDEVICE_INFORMATION DeviceInformation)

{
    PRECONCILE_WORK_ITEM WorkItem;

    
    if (DeviceInformation->Removable)
    {
        return;
    }

    
    WorkItem = AllocatePool(sizeof(RECONCILE_WORK_ITEM));
    if (!WorkItem)
    {
        return;
    }

    WorkItem->WorkItem = IoAllocateWorkItem(DeviceExtension->DeviceObject);
    if (!WorkItem->WorkItem)
    {
        FreePool(WorkItem);
        return;
    }

    
    WorkItem->WorkerRoutine = ReconcileThisDatabaseWithMasterWorker;
    WorkItem->DeviceExtension = DeviceExtension;
    WorkItem->DeviceInformation = DeviceInformation;
    QueueWorkItem(DeviceExtension, WorkItem, &(WorkItem->DeviceExtension));

    
    if (DeviceExtension->WorkerThreadStatus == 0 && DeviceExtension->AutomaticDriveLetter == 1 && DeviceExtension->NoAutoMount == FALSE)

    {
        OnlineMountedVolumes(DeviceExtension, DeviceInformation);
    }
}


VOID ReconcileAllDatabasesWithMaster(IN PDEVICE_EXTENSION DeviceExtension)
{
    PLIST_ENTRY NextEntry;
    PDEVICE_INFORMATION DeviceInformation;

    
    for (NextEntry = DeviceExtension->DeviceListHead.Flink;
         NextEntry != &(DeviceExtension->DeviceListHead);
         NextEntry = NextEntry->Flink)
    {
        DeviceInformation = CONTAINING_RECORD(NextEntry, DEVICE_INFORMATION, DeviceListEntry);

        
        if (!DeviceInformation->Removable)
        {
            ReconcileThisDatabaseWithMaster(DeviceExtension, DeviceInformation);
        }
    }
}


VOID NTAPI MigrateRemoteDatabaseWorker(IN PDEVICE_OBJECT DeviceObject, IN PVOID Context)


{
    ULONG Length;
    NTSTATUS Status;
    PVOID TmpBuffer;
    CHAR Disposition;
    LARGE_INTEGER ByteOffset;
    PMIGRATE_WORK_ITEM WorkItem;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE Migrate = 0, Database = 0;
    PDEVICE_INFORMATION DeviceInformation;
    BOOLEAN PreviousMode, Complete = FALSE;
    UNICODE_STRING DatabaseName, DatabaseFile;
    OBJECT_ATTRIBUTES ObjectAttributes, MigrateAttributes;


    UNREFERENCED_PARAMETER(DeviceObject);

    
    WorkItem = Context;
    DeviceInformation = WorkItem->DeviceInformation;

    
    DatabaseName.Length = DeviceInformation->DeviceName.Length + RemoteDatabase.Length;
    DatabaseName.MaximumLength = DatabaseName.Length + sizeof(WCHAR);

    DatabaseFile.Length = DeviceInformation->DeviceName.Length + RemoteDatabaseFile.Length;
    DatabaseFile.MaximumLength = DatabaseFile.Length + sizeof(WCHAR);

    DatabaseName.Buffer = AllocatePool(DatabaseName.MaximumLength);
    DatabaseFile.Buffer = AllocatePool(DatabaseFile.MaximumLength);
    
    TmpBuffer = AllocatePool(TEMP_BUFFER_SIZE);
    if (!DatabaseName.Buffer || !DatabaseFile.Buffer || !TmpBuffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    
    Status = RtlCreateSystemVolumeInformationFolder(&(DeviceInformation->DeviceName));
    if (!NT_SUCCESS(Status))
    {
        goto Cleanup;
    }

    
    RtlCopyMemory(DatabaseName.Buffer, DeviceInformation->DeviceName.Buffer, DeviceInformation->DeviceName.Length);
    RtlCopyMemory(DatabaseFile.Buffer, DeviceInformation->DeviceName.Buffer, DeviceInformation->DeviceName.Length);
    RtlCopyMemory(DatabaseName.Buffer + (DeviceInformation->DeviceName.Length / sizeof(WCHAR)), RemoteDatabase.Buffer, RemoteDatabase.Length);
    RtlCopyMemory(DatabaseFile.Buffer + (DeviceInformation->DeviceName.Length / sizeof(WCHAR)), RemoteDatabaseFile.Buffer, RemoteDatabaseFile.Length);
    DatabaseName.Buffer[DatabaseName.Length / sizeof(WCHAR)] = UNICODE_NULL;
    DatabaseFile.Buffer[DatabaseFile.Length / sizeof(WCHAR)] = UNICODE_NULL;

    
    InitializeObjectAttributes(&ObjectAttributes, &DatabaseName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);




    Status = ZwCreateFile(&Database, SYNCHRONIZE | READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_WRITE_PROPERTIES | FILE_READ_PROPERTIES | FILE_APPEND_DATA | FILE_WRITE_DATA | FILE_READ_DATA, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);











    if (!NT_SUCCESS(Status))
    {
        Database = 0;
        goto Cleanup;
    }

    InitializeObjectAttributes(&MigrateAttributes, &DatabaseFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);




    
    PreviousMode = IoSetThreadHardErrorMode(FALSE);
    Status = ZwCreateFile(&Migrate, SYNCHRONIZE | READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_WRITE_PROPERTIES | FILE_READ_PROPERTIES | FILE_APPEND_DATA | FILE_WRITE_DATA | FILE_READ_DATA, &MigrateAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);











    IoSetThreadHardErrorMode(PreviousMode);
    if (!NT_SUCCESS(Status))
    {
        Migrate = 0;
    }
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        Status = STATUS_SUCCESS;
        Complete = TRUE;
    }
    if (!NT_SUCCESS(Status) || Complete)
    {
        goto Cleanup;
    }

    ByteOffset.QuadPart = 0LL;
    PreviousMode = IoSetThreadHardErrorMode(FALSE);
    
    while (Status == STATUS_SUCCESS)
    {
        
        Status = ZwReadFile(Migrate, NULL, NULL, NULL, &IoStatusBlock, TmpBuffer, TEMP_BUFFER_SIZE, &ByteOffset, NULL);







        if (!NT_SUCCESS(Status))
        {
            break;
        }

        
        Length = (ULONG)IoStatusBlock.Information;
        Status = ZwWriteFile(Database, NULL, NULL, NULL, &IoStatusBlock, TmpBuffer, Length, &ByteOffset, NULL);







        ByteOffset.QuadPart += Length;
    }
    IoSetThreadHardErrorMode(PreviousMode);

    
    if (Status == STATUS_END_OF_FILE)
    {
        Disposition = 1;
        Status = ZwSetInformationFile(Migrate, &IoStatusBlock, &Disposition, sizeof(Disposition), FileDispositionInformation);



    }

    

Cleanup:
    if (TmpBuffer)
    {
        FreePool(TmpBuffer);
    }

    if (DatabaseFile.Buffer)
    {
        FreePool(DatabaseFile.Buffer);
    }

    if (DatabaseName.Buffer)
    {
        FreePool(DatabaseName.Buffer);
    }

    if (Migrate)
    {
        ZwClose(Migrate);
    }

    if (NT_SUCCESS(Status))
    {
        DeviceInformation->Migrated = 1;
    }
    else if (Database)
    {
        ZwClose(Database);
    }

    IoFreeWorkItem(WorkItem->WorkItem);

    WorkItem->WorkItem = NULL;
    WorkItem->Status = Status;
    WorkItem->Database = Database;

    KeSetEvent(WorkItem->Event, 0, FALSE);

}


NTSTATUS MigrateRemoteDatabase(IN PDEVICE_INFORMATION DeviceInformation, IN OUT PHANDLE Database)

{
    KEVENT Event;
    NTSTATUS Status;
    PMIGRATE_WORK_ITEM WorkItem;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    
    WorkItem = AllocatePool(sizeof(MIGRATE_WORK_ITEM));
    if (!WorkItem)
    {
        *Database = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(WorkItem, sizeof(MIGRATE_WORK_ITEM));
    WorkItem->Event = &Event;
    WorkItem->DeviceInformation = DeviceInformation;
    WorkItem->WorkItem = IoAllocateWorkItem(DeviceInformation->DeviceExtension->DeviceObject);
    if (!WorkItem->WorkItem)
    {
        FreePool(WorkItem);
        *Database = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    
    IoQueueWorkItem(WorkItem->WorkItem, MigrateRemoteDatabaseWorker, DelayedWorkQueue, WorkItem);



    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    Status = WorkItem->Status;

    *Database = (NT_SUCCESS(Status) ? WorkItem->Database : 0);

    FreePool(WorkItem);
    return Status;
}


HANDLE OpenRemoteDatabase(IN PDEVICE_INFORMATION DeviceInformation, IN BOOLEAN MigrateDatabase)

{
    HANDLE Database;
    NTSTATUS Status;
    BOOLEAN PreviousMode;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING DeviceRemoteDatabase;

    Database = 0;

    
    DeviceRemoteDatabase.Length = DeviceInformation->DeviceName.Length + RemoteDatabase.Length;
    DeviceRemoteDatabase.MaximumLength = DeviceRemoteDatabase.Length + sizeof(WCHAR);
    DeviceRemoteDatabase.Buffer = AllocatePool(DeviceRemoteDatabase.MaximumLength);
    if (!DeviceRemoteDatabase.Buffer)
    {
        return 0;
    }

    RtlCopyMemory(DeviceRemoteDatabase.Buffer, DeviceInformation->DeviceName.Buffer, DeviceInformation->DeviceName.Length);
    RtlCopyMemory(DeviceRemoteDatabase.Buffer + (DeviceInformation->DeviceName.Length / sizeof(WCHAR)), RemoteDatabase.Buffer, RemoteDatabase.Length);
    DeviceRemoteDatabase.Buffer[DeviceRemoteDatabase.Length / sizeof(WCHAR)] = UNICODE_NULL;

    
    InitializeObjectAttributes(&ObjectAttributes, &DeviceRemoteDatabase, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);




    
    PreviousMode = IoSetThreadHardErrorMode(FALSE);

    Status = ZwCreateFile(&Database, SYNCHRONIZE | READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_WRITE_PROPERTIES | FILE_READ_PROPERTIES | FILE_APPEND_DATA | FILE_WRITE_DATA | FILE_READ_DATA, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, 0, (!MigrateDatabase || DeviceInformation->Migrated == 0) ? FILE_OPEN_IF : FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);












    
    if (MigrateDatabase && NT_SUCCESS(Status))
    {
        MigrateRemoteDatabase(DeviceInformation, &Database);
    }

    IoSetThreadHardErrorMode(PreviousMode);
    FreePool(DeviceRemoteDatabase.Buffer);

    return Database;
}


VOID ChangeRemoteDatabaseUniqueId(IN PDEVICE_INFORMATION DeviceInformation, IN PMOUNTDEV_UNIQUE_ID OldUniqueId, IN PMOUNTDEV_UNIQUE_ID NewUniqueId)


{
    LONG Offset = 0;
    HANDLE Database;
    PDATABASE_ENTRY Entry, NewEntry;
    NTSTATUS Status = STATUS_SUCCESS;

    
    Database = OpenRemoteDatabase(DeviceInformation, FALSE);
    if (!Database)
    {
        return;
    }

    
    do {
        Entry = GetRemoteDatabaseEntry(Database, Offset);
        if (!Entry)
        {
            break;
        }

        
        if (Entry->UniqueIdLength != OldUniqueId->UniqueIdLength)
        {
            Offset += Entry->EntrySize;
            FreePool(Entry);
            continue;
        }

        
        if (RtlCompareMemory(OldUniqueId->UniqueId, (PVOID)((ULONG_PTR)Entry + Entry->UniqueIdOffset), Entry->UniqueIdLength) != Entry->UniqueIdLength)

        {
            Offset += Entry->EntrySize;
            FreePool(Entry);
            continue;
        }

        
        NewEntry = AllocatePool(Entry->EntrySize + NewUniqueId->UniqueIdLength - OldUniqueId->UniqueIdLength);
        if (!NewEntry)
        {
            Offset += Entry->EntrySize;
            FreePool(Entry);
            continue;
        }

        
        NewEntry->EntrySize = Entry->EntrySize + NewUniqueId->UniqueIdLength - OldUniqueId->UniqueIdLength;
        NewEntry->EntryReferences = Entry->EntryReferences;
        NewEntry->SymbolicNameOffset = sizeof(DATABASE_ENTRY);
        NewEntry->SymbolicNameLength = Entry->SymbolicNameLength;
        NewEntry->UniqueIdOffset = Entry->SymbolicNameLength + sizeof(DATABASE_ENTRY);
        NewEntry->UniqueIdLength = NewUniqueId->UniqueIdLength;
        RtlCopyMemory((PVOID)((ULONG_PTR)NewEntry + NewEntry->SymbolicNameOffset), (PVOID)((ULONG_PTR)Entry + Entry->SymbolicNameOffset), NewEntry->SymbolicNameLength);

        RtlCopyMemory((PVOID)((ULONG_PTR)NewEntry + NewEntry->UniqueIdOffset), NewUniqueId->UniqueId, NewEntry->UniqueIdLength);

        
        Status = DeleteRemoteDatabaseEntry(Database, Offset);
        if (!NT_SUCCESS(Status))
        {
            FreePool(Entry);
            FreePool(NewEntry);
            break;
        }

        
        Status = AddRemoteDatabaseEntry(Database, NewEntry);
        FreePool(Entry);
        FreePool(NewEntry);
    } while (NT_SUCCESS(Status));

    CloseRemoteDatabase(Database);

    return;
}


NTSTATUS NTAPI DeleteDriveLetterRoutine(IN PWSTR ValueName, IN ULONG ValueType, IN PVOID ValueData, IN ULONG ValueLength, IN PVOID Context, IN PVOID EntryContext)






{
    PMOUNTDEV_UNIQUE_ID UniqueId;
    UNICODE_STRING RegistryEntry;

    UNREFERENCED_PARAMETER(EntryContext);

    if (ValueType != REG_BINARY)
    {
        return STATUS_SUCCESS;
    }

    UniqueId = Context;

    
    if (UniqueId->UniqueIdLength != ValueLength)
    {
        return STATUS_SUCCESS;
    }

    if (RtlCompareMemory(UniqueId->UniqueId, ValueData, ValueLength) != ValueLength)
    {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&RegistryEntry, ValueName);

    
    if (IsDriveLetter(&RegistryEntry))
    {
        RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, DatabasePath, ValueName);

    }

    return STATUS_SUCCESS;
}


VOID DeleteRegistryDriveLetter(IN PMOUNTDEV_UNIQUE_ID UniqueId)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];

    RtlZeroMemory(QueryTable, sizeof(QueryTable));
    QueryTable[0].QueryRoutine = DeleteDriveLetterRoutine;

    RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, DatabasePath, QueryTable, UniqueId, NULL);



}


NTSTATUS NTAPI DeleteNoDriveLetterEntryRoutine(IN PWSTR ValueName, IN ULONG ValueType, IN PVOID ValueData, IN ULONG ValueLength, IN PVOID Context, IN PVOID EntryContext)






{
    PMOUNTDEV_UNIQUE_ID UniqueId = Context;

    UNREFERENCED_PARAMETER(EntryContext);

    
    if (ValueName[0] != L'#' || ValueType != REG_BINARY || UniqueId->UniqueIdLength != ValueLength)
    {
        return STATUS_SUCCESS;
    }

    
    if (RtlCompareMemory(UniqueId->UniqueId, ValueData, ValueLength) != ValueLength)
    {
        RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, DatabasePath, ValueName);

    }

    return STATUS_SUCCESS;
}


VOID DeleteNoDriveLetterEntry(IN PMOUNTDEV_UNIQUE_ID UniqueId)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];

    RtlZeroMemory(QueryTable, sizeof(QueryTable));
    QueryTable[0].QueryRoutine = DeleteNoDriveLetterEntryRoutine;

    RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, DatabasePath, QueryTable, UniqueId, NULL);



}
