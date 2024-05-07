





IP4_ASSEMBLE_ENTRY * Ip4CreateAssembleEntry ( IN IP4_ADDR               Dst, IN IP4_ADDR               Src, IN UINT16                 Id, IN UINT8                  Protocol )





{

  IP4_ASSEMBLE_ENTRY        *Assemble;

  Assemble = AllocatePool (sizeof (IP4_ASSEMBLE_ENTRY));

  if (Assemble == NULL) {
    return NULL;
  }

  InitializeListHead (&Assemble->Link);
  InitializeListHead (&Assemble->Fragments);

  Assemble->Dst      = Dst;
  Assemble->Src      = Src;
  Assemble->Id       = Id;
  Assemble->Protocol = Protocol;
  Assemble->TotalLen = 0;
  Assemble->CurLen   = 0;
  Assemble->Head     = NULL;
  Assemble->Info     = NULL;
  Assemble->Life     = IP4_FRAGMENT_LIFE;

  return Assemble;
}



VOID Ip4FreeAssembleEntry ( IN IP4_ASSEMBLE_ENTRY     *Assemble )


{
  LIST_ENTRY                *Entry;
  LIST_ENTRY                *Next;
  NET_BUF                   *Fragment;

  NET_LIST_FOR_EACH_SAFE (Entry, Next, &Assemble->Fragments) {
    Fragment = NET_LIST_USER_STRUCT (Entry, NET_BUF, List);

    RemoveEntryList (Entry);
    NetbufFree (Fragment);
  }

  FreePool (Assemble);
}



VOID Ip4InitAssembleTable ( IN OUT IP4_ASSEMBLE_TABLE     *Table )


{
  UINT32                    Index;

  for (Index = 0; Index < IP4_ASSEMLE_HASH_SIZE; Index++) {
    InitializeListHead (&Table->Bucket[Index]);
  }
}



VOID Ip4CleanAssembleTable ( IN IP4_ASSEMBLE_TABLE     *Table )


{
  LIST_ENTRY                *Entry;
  LIST_ENTRY                *Next;
  IP4_ASSEMBLE_ENTRY        *Assemble;
  UINT32                    Index;

  for (Index = 0; Index < IP4_ASSEMLE_HASH_SIZE; Index++) {
    NET_LIST_FOR_EACH_SAFE (Entry, Next, &Table->Bucket[Index]) {
      Assemble = NET_LIST_USER_STRUCT (Entry, IP4_ASSEMBLE_ENTRY, Link);

      RemoveEntryList (Entry);
      Ip4FreeAssembleEntry (Assemble);
    }
  }
}



VOID Ip4TrimPacket ( IN OUT NET_BUF                *Packet, IN     INTN                   Start, IN     INTN                   End )




{
  IP4_CLIP_INFO             *Info;
  INTN                      Len;

  Info = IP4_GET_CLIP_INFO (Packet);

  ASSERT (Info->Start + Info->Length == Info->End);
  ASSERT ((Info->Start < End) && (Start < Info->End));

   if (Info->Start < Start) {
    Len = Start - Info->Start;

    NetbufTrim (Packet, (UINT32) Len, NET_BUF_HEAD);
    Info->Start   = Start;
    Info->Length -= Len;
  }

  if (End < Info->End) {
    Len = End - Info->End;

    NetbufTrim (Packet, (UINT32) Len, NET_BUF_TAIL);
    Info->End     = End;
    Info->Length -= Len;
  }
}



VOID EFIAPI Ip4OnFreeFragments ( IN VOID                   *Arg )



{
  Ip4FreeAssembleEntry ((IP4_ASSEMBLE_ENTRY *) Arg);
}



NET_BUF * Ip4Reassemble ( IN OUT IP4_ASSEMBLE_TABLE     *Table, IN OUT NET_BUF                *Packet )



{
  IP4_HEAD                  *IpHead;
  IP4_CLIP_INFO             *This;
  IP4_CLIP_INFO             *Node;
  IP4_ASSEMBLE_ENTRY        *Assemble;
  LIST_ENTRY                *Head;
  LIST_ENTRY                *Prev;
  LIST_ENTRY                *Cur;
  NET_BUF                   *Fragment;
  NET_BUF                   *NewPacket;
  INTN                      Index;

  IpHead  = Packet->Ip.Ip4;
  This    = IP4_GET_CLIP_INFO (Packet);

  ASSERT (IpHead != NULL);

  
  
  
  Assemble  = NULL;
  Index     = IP4_ASSEMBLE_HASH (IpHead->Dst, IpHead->Src, IpHead->Id, IpHead->Protocol);

  NET_LIST_FOR_EACH (Cur, &Table->Bucket[Index]) {
    Assemble = NET_LIST_USER_STRUCT (Cur, IP4_ASSEMBLE_ENTRY, Link);

    if ((Assemble->Dst == IpHead->Dst) && (Assemble->Src == IpHead->Src) && (Assemble->Id == IpHead->Id)   && (Assemble->Protocol == IpHead->Protocol)) {
      break;
    }
  }

  
  
  
  if (Cur == &Table->Bucket[Index]) {
    Assemble = Ip4CreateAssembleEntry ( IpHead->Dst, IpHead->Src, IpHead->Id, IpHead->Protocol );





    if (Assemble == NULL) {
      goto DROP;
    }

    InsertHeadList (&Table->Bucket[Index], &Assemble->Link);
  }
  
  
  
  ASSERT (Assemble != NULL);

  
  
  
  
  
  Head = &Assemble->Fragments;

  NET_LIST_FOR_EACH (Cur, Head) {
    Fragment = NET_LIST_USER_STRUCT (Cur, NET_BUF, List);

    if (This->Start < IP4_GET_CLIP_INFO (Fragment)->Start) {
      break;
    }
  }

  
  
  
  
  
  
  if ((Prev = Cur->BackLink) != Head) {
    Fragment  = NET_LIST_USER_STRUCT (Prev, NET_BUF, List);
    Node      = IP4_GET_CLIP_INFO (Fragment);

    if (This->Start < Node->End) {
      if (This->End <= Node->End) {
        NetbufFree (Packet);
        return NULL;
      }

      Ip4TrimPacket (Packet, Node->End, This->End);
    }
  }

  
  
  
  
  NetListInsertBefore (Cur, &Packet->List);

  
  
  
  
  
  
  while (Cur != Head) {
    Fragment = NET_LIST_USER_STRUCT (Cur, NET_BUF, List);
    Node     = IP4_GET_CLIP_INFO (Fragment);

    
    
    
    if (Node->End <= This->End) {
      Cur = Cur->ForwardLink;

      RemoveEntryList (&Fragment->List);
      Assemble->CurLen -= Node->Length;

      NetbufFree (Fragment);
      continue;
    }

    
    
    
    
    
    
    if (Node->Start < This->End) {
      if (This->Start == Node->Start) {
        RemoveEntryList (&Packet->List);
        goto DROP;
      }

      Ip4TrimPacket (Packet, This->Start, Node->Start);
    }

    break;
  }

  
  
  
  
  
  Assemble->CurLen += This->Length;

  if (This->Start == 0) {
    
    
    
    
    
    ASSERT (Assemble->Head == NULL);

    Assemble->Head  = IpHead;
    Assemble->Info  = IP4_GET_CLIP_INFO (Packet);
  }

  
  
  
  if (IP4_LAST_FRAGMENT (IpHead->Fragment) && (Assemble->TotalLen == 0)) {
    Assemble->TotalLen = This->End;
  }

  
  
  
  
  
  
  
  if ((Assemble->TotalLen != 0) && (Assemble->CurLen >= Assemble->TotalLen)) {

    RemoveEntryList (&Assemble->Link);

    
    
    
    
    
    Fragment = NET_LIST_USER_STRUCT (Head->BackLink, NET_BUF, List);

    if (IP4_GET_CLIP_INFO (Fragment)->End != Assemble->TotalLen) {
      Ip4FreeAssembleEntry (Assemble);
      return NULL;
    }

    
    
    
    NewPacket = NetbufFromBufList ( &Assemble->Fragments, 0, 0, Ip4OnFreeFragments, Assemble );






    if (NewPacket == NULL) {
      Ip4FreeAssembleEntry (Assemble);
      return NULL;
    }

    NewPacket->Ip.Ip4 = Assemble->Head;

    ASSERT (Assemble->Info != NULL);

    CopyMem ( IP4_GET_CLIP_INFO (NewPacket), Assemble->Info, sizeof (*IP4_GET_CLIP_INFO (NewPacket))


      );

    return NewPacket;
  }

  return NULL;

DROP:
  NetbufFree (Packet);
  return NULL;
}


VOID EFIAPI Ip4IpSecFree ( IN VOID                   *Arg )



{
  IP4_IPSEC_WRAP            *Wrap;

  Wrap = (IP4_IPSEC_WRAP *) Arg;

  if (Wrap->IpSecRecycleSignal != NULL) {
    gBS->SignalEvent (Wrap->IpSecRecycleSignal);
  }

  NetbufFree (Wrap->Packet);

  FreePool (Wrap);

  return;
}


EFI_STATUS Ip4IpSecProcessPacket ( IN     IP4_SERVICE            *IpSb, IN OUT IP4_HEAD               **Head, IN OUT NET_BUF                **Netbuf, IN OUT UINT8                  **Options, IN OUT UINT32                 *OptionsLen, IN     EFI_IPSEC_TRAFFIC_DIR  Direction, IN     VOID                   *Context )








{
  NET_FRAGMENT              *FragmentTable;
  NET_FRAGMENT              *OriginalFragmentTable;
  UINT32                    FragmentCount;
  UINT32                    OriginalFragmentCount;
  EFI_EVENT                 RecycleEvent;
  NET_BUF                   *Packet;
  IP4_TXTOKEN_WRAP          *TxWrap;
  IP4_IPSEC_WRAP            *IpSecWrap;
  EFI_STATUS                Status;
  IP4_HEAD                  ZeroHead;

  Status        = EFI_SUCCESS;

  if (!mIpSec2Installed) {
    goto ON_EXIT;
  }
  ASSERT (mIpSec != NULL);

  Packet        = *Netbuf;
  RecycleEvent  = NULL;
  IpSecWrap     = NULL;
  FragmentTable = NULL;
  TxWrap        = (IP4_TXTOKEN_WRAP *) Context;
  FragmentCount = Packet->BlockOpNum;

  ZeroMem (&ZeroHead, sizeof (IP4_HEAD));

  
  
  
  if (mIpSec->DisabledFlag) {
    
    
    
    IpSb->MaxPacketSize = IpSb->OldMaxPacketSize;
    goto ON_EXIT;
  } else {
    
    
    
    IpSb->MaxPacketSize = IpSb->OldMaxPacketSize - IP4_MAX_IPSEC_HEADLEN;
  }

  
  
  
  FragmentTable = AllocateZeroPool (FragmentCount * sizeof (NET_FRAGMENT));

  if (FragmentTable == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }

  Status = NetbufBuildExt (Packet, FragmentTable, &FragmentCount);

  
  
  
  OriginalFragmentTable = FragmentTable;
  OriginalFragmentCount = FragmentCount;

  if (EFI_ERROR (Status)) {
    FreePool (FragmentTable);
    goto ON_EXIT;
  }

  
  
  
  Ip4NtohHead (*Head);

  Status = mIpSec->ProcessExt ( mIpSec, IpSb->Controller, IP_VERSION_4, (VOID *) (*Head), &(*Head)->Protocol, (VOID **) Options, OptionsLen, (EFI_IPSEC_FRAGMENT_DATA **) (&FragmentTable), &FragmentCount, Direction, &RecycleEvent );











  
  
  
  Ip4NtohHead (*Head);

  if (EFI_ERROR (Status)) {
    FreePool (OriginalFragmentTable);
    goto ON_EXIT;
  }

  if (OriginalFragmentTable == FragmentTable && OriginalFragmentCount == FragmentCount) {
    
    
    
    FreePool (FragmentTable);
    goto ON_EXIT;
  } else {
    
    
    
    FreePool (OriginalFragmentTable);
  }

  if (Direction == EfiIPsecOutBound && TxWrap != NULL) {

    TxWrap->IpSecRecycleSignal = RecycleEvent;
    TxWrap->Packet             = NetbufFromExt ( FragmentTable, FragmentCount, IP4_MAX_HEADLEN, 0, Ip4FreeTxToken, TxWrap );






    if (TxWrap->Packet == NULL) {
      
      
      
      
      TxWrap->Packet = *Netbuf;
      Status = EFI_OUT_OF_RESOURCES;
      goto ON_EXIT;
    }

    
    
    
    NetIpSecNetbufFree (*Netbuf);
    *Netbuf = TxWrap->Packet;

  } else {

    IpSecWrap = AllocateZeroPool (sizeof (IP4_IPSEC_WRAP));

    if (IpSecWrap == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      gBS->SignalEvent (RecycleEvent);
      goto ON_EXIT;
    }

    IpSecWrap->IpSecRecycleSignal = RecycleEvent;
    IpSecWrap->Packet             = Packet;
    Packet                        = NetbufFromExt ( FragmentTable, FragmentCount, IP4_MAX_HEADLEN, 0, Ip4IpSecFree, IpSecWrap );







    if (Packet == NULL) {
      Packet = IpSecWrap->Packet;
      gBS->SignalEvent (RecycleEvent);
      FreePool (IpSecWrap);
      Status = EFI_OUT_OF_RESOURCES;
      goto ON_EXIT;
    }

    if (Direction == EfiIPsecInBound && 0 != CompareMem (*Head, &ZeroHead, sizeof (IP4_HEAD))) {
      Ip4PrependHead (Packet, *Head, *Options, *OptionsLen);
      Ip4NtohHead (Packet->Ip.Ip4);
      NetbufTrim (Packet, ((*Head)->HeadLen << 2), TRUE);

      CopyMem ( IP4_GET_CLIP_INFO (Packet), IP4_GET_CLIP_INFO (IpSecWrap->Packet), sizeof (IP4_CLIP_INFO)


        );
    }
    *Netbuf = Packet;
  }

ON_EXIT:
  return Status;
}


EFI_STATUS Ip4PreProcessPacket ( IN     IP4_SERVICE    *IpSb, IN OUT NET_BUF        **Packet, IN     IP4_HEAD       *Head, IN     UINT8          *Option, IN     UINT32         OptionLen, IN     UINT32         Flag )







{
  IP4_CLIP_INFO             *Info;
  UINT32                    HeadLen;
  UINT32                    TotalLen;
  UINT16                    Checksum;

  
  
  
  if ((*Packet)->TotalSize < IP4_MIN_HEADLEN) {
    return EFI_INVALID_PARAMETER;
  }

  HeadLen  = (Head->HeadLen << 2);
  TotalLen = NTOHS (Head->TotalLen);

  
  
  
  if (TotalLen < (*Packet)->TotalSize) {
    NetbufTrim (*Packet, (*Packet)->TotalSize - TotalLen, FALSE);
  }

  if ((Head->Ver != 4) || (HeadLen < IP4_MIN_HEADLEN) || (TotalLen < HeadLen) || (TotalLen != (*Packet)->TotalSize)) {
    return EFI_INVALID_PARAMETER;
  }

  
  
  
  Checksum = (UINT16) (~NetblockChecksum ((UINT8 *) Head, HeadLen));

  if ((Head->Checksum != 0) && (Checksum != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  
  
  
  (*Packet)->Ip.Ip4  = Ip4NtohHead (Head);

  Info            = IP4_GET_CLIP_INFO (*Packet);
  Info->LinkFlag  = Flag;
  Info->CastType  = Ip4GetHostCast (IpSb, Head->Dst, Head->Src);
  Info->Start     = (Head->Fragment & IP4_HEAD_OFFSET_MASK) << 3;
  Info->Length    = Head->TotalLen - HeadLen;
  Info->End       = Info->Start + Info->Length;
  Info->Status    = EFI_SUCCESS;

  
  
  
  if ((Info->CastType == 0) || (Info->End > IP4_MAX_PACKET_SIZE)) {
    return EFI_INVALID_PARAMETER;
  }

  
  
  
  

  if ((OptionLen > 0) && !Ip4OptionIsValid (Option, OptionLen, TRUE)) {
    return EFI_INVALID_PARAMETER;
  }

  
  
  
  
  NetbufTrim (*Packet, HeadLen, TRUE);

  
  
  
  
  
  if (((Head->Fragment & IP4_HEAD_MF_MASK) != 0) || (Info->Start != 0)) {
    
    
    
    
    if ((Head->Fragment & IP4_HEAD_DF_MASK) != 0) {
      return EFI_INVALID_PARAMETER;
    }

    
    
    
    if (((Head->Fragment & IP4_HEAD_MF_MASK) != 0) && (Info->Length % 8 != 0)) {
      return EFI_INVALID_PARAMETER;
    }

    *Packet = Ip4Reassemble (&IpSb->Assemble, *Packet);

    
    
    
    if (*Packet == NULL) {
      return EFI_INVALID_PARAMETER;
    }
  }

  return EFI_SUCCESS;
}


VOID Ip4AccpetFrame ( IN IP4_PROTOCOL           *Ip4Instance, IN NET_BUF                *Packet, IN EFI_STATUS             IoStatus, IN UINT32                 Flag, IN VOID                   *Context )






{
  IP4_SERVICE               *IpSb;
  IP4_HEAD                  *Head;
  EFI_STATUS                Status;
  IP4_HEAD                  ZeroHead;
  UINT8                     *Option;
  UINT32                    OptionLen;

  IpSb   = (IP4_SERVICE *) Context;
  Option = NULL;

  if (EFI_ERROR (IoStatus) || (IpSb->State == IP4_SERVICE_DESTROY)) {
    goto DROP;
  }

  Head      = (IP4_HEAD *) NetbufGetByte (Packet, 0, NULL);
  ASSERT (Head != NULL);
  OptionLen = (Head->HeadLen << 2) - IP4_MIN_HEADLEN;
  if (OptionLen > 0) {
    Option = (UINT8 *) (Head + 1);
  }

  
  
  
  Status = Ip4PreProcessPacket ( IpSb, &Packet, Head, Option, OptionLen, Flag );







  if (EFI_ERROR (Status)) {
    goto RESTART;
  }

  
  
  
  
  Status = Ip4IpSecProcessPacket ( IpSb, &Head, &Packet, &Option, &OptionLen, EfiIPsecInBound, NULL );








  if (EFI_ERROR (Status)) {
    goto RESTART;
  }

  
  
  
  ZeroMem (&ZeroHead, sizeof (IP4_HEAD));
  if (0 == CompareMem (Head, &ZeroHead, sizeof (IP4_HEAD))) {
  
  
  
  
    Head = (IP4_HEAD *) NetbufGetByte (Packet, 0, NULL);
    ASSERT (Head != NULL);
    Status = Ip4PreProcessPacket ( IpSb, &Packet, Head, Option, OptionLen, Flag );






    if (EFI_ERROR (Status)) {
      goto RESTART;
    }
  }

  ASSERT (Packet != NULL);
  Head  = Packet->Ip.Ip4;
  IP4_GET_CLIP_INFO (Packet)->Status = EFI_SUCCESS;

  switch (Head->Protocol) {
  case EFI_IP_PROTO_ICMP:
    Ip4IcmpHandle (IpSb, Head, Packet);
    break;

  case IP4_PROTO_IGMP:
    Ip4IgmpHandle (IpSb, Head, Packet);
    break;

  default:
    Ip4Demultiplex (IpSb, Head, Packet, Option, OptionLen);
  }

  Packet = NULL;

  
  
  
  
  DispatchDpc ();

RESTART:
  Ip4ReceiveFrame (IpSb->DefaultInterface, NULL, Ip4AccpetFrame, IpSb);

DROP:
  if (Packet != NULL) {
    NetbufFree (Packet);
  }

  return ;
}



BOOLEAN Ip4InstanceFrameAcceptable ( IN IP4_PROTOCOL           *IpInstance, IN IP4_HEAD               *Head, IN NET_BUF                *Packet )




{
  IP4_ICMP_ERROR_HEAD       Icmp;
  EFI_IP4_CONFIG_DATA       *Config;
  IP4_CLIP_INFO             *Info;
  UINT16                    Proto;
  UINT32                    Index;

  Config = &IpInstance->ConfigData;

  
  
  
  
  
  
  
  
  if (Config->ReceiveTimeout == (UINT32)(-1)) {
    return FALSE;
  }

  if (Config->AcceptPromiscuous) {
    return TRUE;
  }

  
  
  
  
  
  Proto = Head->Protocol;

  if ((Proto == EFI_IP_PROTO_ICMP) && (!Config->AcceptAnyProtocol) && (Proto != Config->DefaultProtocol)) {
    NetbufCopy (Packet, 0, sizeof (Icmp.Head), (UINT8 *) &Icmp.Head);

    if (mIcmpClass[Icmp.Head.Type].IcmpClass == ICMP_ERROR_MESSAGE) {
      if (!Config->AcceptIcmpErrors) {
        return FALSE;
      }

      NetbufCopy (Packet, 0, sizeof (Icmp), (UINT8 *) &Icmp);
      Proto = Icmp.IpHead.Protocol;
    }
  }

  
  
  
  if (!Config->AcceptAnyProtocol && (Proto != Config->DefaultProtocol)) {
    return FALSE;
  }

  
  
  
  
  Info = IP4_GET_CLIP_INFO (Packet);

  if (IP4_IS_BROADCAST (Info->CastType)) {
    return Config->AcceptBroadcast;
  }

  
  
  
  if (Info->CastType == IP4_MULTICAST) {
    
    
    
    if (!IpInstance->ConfigData.UseDefaultAddress && (IpInstance->Interface->Ip == 0)) {
      return TRUE;
    }

    for (Index = 0; Index < IpInstance->GroupCount; Index++) {
      if (IpInstance->Groups[Index] == HTONL (Head->Dst)) {
        break;
      }
    }

    return (BOOLEAN)(Index < IpInstance->GroupCount);
  }

  return TRUE;
}



EFI_STATUS Ip4InstanceEnquePacket ( IN IP4_PROTOCOL           *IpInstance, IN IP4_HEAD               *Head, IN NET_BUF                *Packet )




{
  IP4_CLIP_INFO             *Info;
  NET_BUF                   *Clone;

  
  
  
  if (IpInstance->State != IP4_STATE_CONFIGED) {
    return EFI_NOT_STARTED;
  }

  if (!Ip4InstanceFrameAcceptable (IpInstance, Head, Packet)) {
    return EFI_INVALID_PARAMETER;
  }

  
  
  
  Clone = NetbufClone (Packet);

  if (Clone == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  
  
  
  
  Info        = IP4_GET_CLIP_INFO (Clone);
  Info->Life  = IP4_US_TO_SEC (IpInstance->ConfigData.ReceiveTimeout);

  InsertTailList (&IpInstance->Received, &Clone->List);
  return EFI_SUCCESS;
}



VOID EFIAPI Ip4OnRecyclePacket ( IN EFI_EVENT              Event, IN VOID                   *Context )




{
  IP4_RXDATA_WRAP           *Wrap;

  Wrap = (IP4_RXDATA_WRAP *) Context;

  EfiAcquireLockOrFail (&Wrap->IpInstance->RecycleLock);
  RemoveEntryList (&Wrap->Link);
  EfiReleaseLock (&Wrap->IpInstance->RecycleLock);

  ASSERT (!NET_BUF_SHARED (Wrap->Packet));
  NetbufFree (Wrap->Packet);

  gBS->CloseEvent (Wrap->RxData.RecycleSignal);
  FreePool (Wrap);
}



IP4_RXDATA_WRAP * Ip4WrapRxData ( IN IP4_PROTOCOL           *IpInstance, IN NET_BUF                *Packet )



{
  IP4_RXDATA_WRAP           *Wrap;
  EFI_IP4_RECEIVE_DATA      *RxData;
  EFI_STATUS                Status;
  BOOLEAN                   RawData;

  Wrap = AllocatePool (IP4_RXDATA_WRAP_SIZE (Packet->BlockOpNum));

  if (Wrap == NULL) {
    return NULL;
  }

  InitializeListHead (&Wrap->Link);

  Wrap->IpInstance  = IpInstance;
  Wrap->Packet      = Packet;
  RxData            = &Wrap->RxData;

  ZeroMem (RxData, sizeof (EFI_IP4_RECEIVE_DATA));

  Status = gBS->CreateEvent ( EVT_NOTIFY_SIGNAL, TPL_NOTIFY, Ip4OnRecyclePacket, Wrap, &RxData->RecycleSignal );






  if (EFI_ERROR (Status)) {
    FreePool (Wrap);
    return NULL;
  }

  ASSERT (Packet->Ip.Ip4 != NULL);

  ASSERT (IpInstance != NULL);
  RawData = IpInstance->ConfigData.RawData;

  
  
  
  if (!RawData) {
    RxData->HeaderLength  = (Packet->Ip.Ip4->HeadLen << 2);
    RxData->Header        = (EFI_IP4_HEADER *) Ip4NtohHead (Packet->Ip.Ip4);
    RxData->OptionsLength = RxData->HeaderLength - IP4_MIN_HEADLEN;
    RxData->Options       = NULL;

    if (RxData->OptionsLength != 0) {
      RxData->Options = (VOID *) (RxData->Header + 1);
    }
  }

  RxData->DataLength  = Packet->TotalSize;

  
  
  
  RxData->FragmentCount = Packet->BlockOpNum;
  NetbufBuildExt (Packet, (NET_FRAGMENT *) RxData->FragmentTable, &RxData->FragmentCount);

  return Wrap;
}



EFI_STATUS Ip4InstanceDeliverPacket ( IN IP4_PROTOCOL           *IpInstance )


{
  EFI_IP4_COMPLETION_TOKEN  *Token;
  IP4_RXDATA_WRAP           *Wrap;
  NET_BUF                   *Packet;
  NET_BUF                   *Dup;
  UINT8                     *Head;
  UINT32                    HeadLen;

  
  
  
  while (!IsListEmpty (&IpInstance->Received) && !NetMapIsEmpty (&IpInstance->RxTokens)) {

    Packet = NET_LIST_HEAD (&IpInstance->Received, NET_BUF, List);

    if (!NET_BUF_SHARED (Packet)) {
      
      
      
      Wrap = Ip4WrapRxData (IpInstance, Packet);

      if (Wrap == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }

      RemoveEntryList (&Packet->List);

    } else {
      
      
      
      if (IpInstance->ConfigData.RawData) {
        HeadLen = 0;
      } else {
        HeadLen = IP4_MAX_HEADLEN;
      }

      Dup = NetbufDuplicate (Packet, NULL, HeadLen);

      if (Dup == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }

      if (!IpInstance->ConfigData.RawData) {
        
        
        
        
        
        Head = NetbufAllocSpace (Dup, IP4_MAX_HEADLEN, NET_BUF_HEAD);
        ASSERT (Head != NULL);

        Dup->Ip.Ip4 = (IP4_HEAD *) Head;

        CopyMem (Head, Packet->Ip.Ip4, Packet->Ip.Ip4->HeadLen << 2);
        NetbufTrim (Dup, IP4_MAX_HEADLEN, TRUE);
      }

      Wrap = Ip4WrapRxData (IpInstance, Dup);

      if (Wrap == NULL) {
        NetbufFree (Dup);
        return EFI_OUT_OF_RESOURCES;
      }

      RemoveEntryList (&Packet->List);
      NetbufFree (Packet);

      Packet = Dup;
    }

    
    
    
    
    EfiAcquireLockOrFail (&IpInstance->RecycleLock);
    InsertHeadList (&IpInstance->Delivered, &Wrap->Link);
    EfiReleaseLock (&IpInstance->RecycleLock);

    Token                = NetMapRemoveHead (&IpInstance->RxTokens, NULL);
    Token->Status        = IP4_GET_CLIP_INFO (Packet)->Status;
    Token->Packet.RxData = &Wrap->RxData;

    gBS->SignalEvent (Token->Event);
  }

  return EFI_SUCCESS;
}



INTN Ip4InterfaceEnquePacket ( IN IP4_SERVICE            *IpSb, IN IP4_HEAD               *Head, IN NET_BUF                *Packet, IN UINT8                  *Option, IN UINT32                 OptionLen, IN IP4_INTERFACE          *IpIf )







{
  IP4_PROTOCOL              *IpInstance;
  IP4_CLIP_INFO             *Info;
  LIST_ENTRY                *Entry;
  INTN                      Enqueued;
  INTN                      LocalType;
  INTN                      SavedType;

  
  
  
  
  
  
  LocalType = 0;
  Info      = IP4_GET_CLIP_INFO (Packet);

  if ((Info->CastType == IP4_MULTICAST) || (Info->CastType == IP4_LOCAL_BROADCAST)) {
    
    
    
    
    
    LocalType = Info->CastType;

  } else {
    
    
    
    
    
    
    if (IpIf->Ip == IP4_ALLZERO_ADDRESS) {
      LocalType = IP4_LOCAL_HOST;

    } else {
      LocalType = Ip4GetNetCast (Head->Dst, IpIf);

      if ((LocalType == 0) && IpIf->PromiscRecv) {
        LocalType = IP4_PROMISCUOUS;
      }
    }
  }

  if (LocalType == 0) {
    return 0;
  }

  
  
  
  
  
  
  SavedType       = Info->CastType;
  Info->CastType  = LocalType;

  Enqueued        = 0;

  NET_LIST_FOR_EACH (Entry, &IpIf->IpInstances) {
    IpInstance = NET_LIST_USER_STRUCT (Entry, IP4_PROTOCOL, AddrLink);
    NET_CHECK_SIGNATURE (IpInstance, IP4_PROTOCOL_SIGNATURE);

    
    
    
    if ((IpInstance->ConfigData.RawData) && (Option != NULL) && (OptionLen != 0)){
      Ip4PrependHead (Packet, Head, Option, OptionLen);
    }

    if (Ip4InstanceEnquePacket (IpInstance, Head, Packet) == EFI_SUCCESS) {
      Enqueued++;
    }
  }

  Info->CastType = SavedType;
  return Enqueued;
}



EFI_STATUS Ip4InterfaceDeliverPacket ( IN IP4_SERVICE            *IpSb, IN IP4_INTERFACE          *IpIf )



{
  IP4_PROTOCOL              *Ip4Instance;
  LIST_ENTRY                *Entry;

  NET_LIST_FOR_EACH (Entry, &IpIf->IpInstances) {
    Ip4Instance = NET_LIST_USER_STRUCT (Entry, IP4_PROTOCOL, AddrLink);
    Ip4InstanceDeliverPacket (Ip4Instance);
  }

  return EFI_SUCCESS;
}



EFI_STATUS Ip4Demultiplex ( IN IP4_SERVICE            *IpSb, IN IP4_HEAD               *Head, IN NET_BUF                *Packet, IN UINT8                  *Option, IN UINT32                 OptionLen )






{
  LIST_ENTRY                *Entry;
  IP4_INTERFACE             *IpIf;
  INTN                      Enqueued;

  
  
  
  
  Enqueued = 0;

  NET_LIST_FOR_EACH (Entry, &IpSb->Interfaces) {
    IpIf = NET_LIST_USER_STRUCT (Entry, IP4_INTERFACE, Link);

    if (IpIf->Configured) {
      Enqueued += Ip4InterfaceEnquePacket ( IpSb, Head, Packet, Option, OptionLen, IpIf );






    }
  }

  
  
  
  
  
  NetbufFree (Packet);

  if (Enqueued == 0) {
    return EFI_NOT_FOUND;
  }

  NET_LIST_FOR_EACH (Entry, &IpSb->Interfaces) {
    IpIf = NET_LIST_USER_STRUCT (Entry, IP4_INTERFACE, Link);

    if (IpIf->Configured) {
      Ip4InterfaceDeliverPacket (IpSb, IpIf);
    }
  }

  return EFI_SUCCESS;
}



VOID Ip4PacketTimerTicking ( IN IP4_SERVICE            *IpSb )


{
  LIST_ENTRY                *InstanceEntry;
  LIST_ENTRY                *Entry;
  LIST_ENTRY                *Next;
  IP4_PROTOCOL              *IpInstance;
  IP4_ASSEMBLE_ENTRY        *Assemble;
  NET_BUF                   *Packet;
  IP4_CLIP_INFO             *Info;
  UINT32                    Index;

  
  
  
  
  for (Index = 0; Index < IP4_ASSEMLE_HASH_SIZE; Index++) {
    NET_LIST_FOR_EACH_SAFE (Entry, Next, &IpSb->Assemble.Bucket[Index]) {
      Assemble = NET_LIST_USER_STRUCT (Entry, IP4_ASSEMBLE_ENTRY, Link);

      if ((Assemble->Life > 0) && (--Assemble->Life == 0)) {
        RemoveEntryList (Entry);
        Ip4FreeAssembleEntry (Assemble);
      }
    }
  }

  NET_LIST_FOR_EACH (InstanceEntry, &IpSb->Children) {
    IpInstance = NET_LIST_USER_STRUCT (InstanceEntry, IP4_PROTOCOL, Link);

    
    
    
    NET_LIST_FOR_EACH_SAFE (Entry, Next, &IpInstance->Received) {
      Packet = NET_LIST_USER_STRUCT (Entry, NET_BUF, List);
      Info   = IP4_GET_CLIP_INFO (Packet);

      if ((Info->Life > 0) && (--Info->Life == 0)) {
        RemoveEntryList (Entry);
        NetbufFree (Packet);
      }
    }

    
    
    
    NetMapIterate (&IpInstance->TxTokens, Ip4SentPacketTicking, NULL);
  }
}
