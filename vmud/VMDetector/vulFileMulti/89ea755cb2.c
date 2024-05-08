




EFI_STATUS Dns4RemoveTokenEntry ( IN NET_MAP                    *TokenMap, IN DNS4_TOKEN_ENTRY           *TokenEntry )



{
  NET_MAP_ITEM  *Item;

  
  
  
  Item = NetMapFindKey (TokenMap, (VOID *) TokenEntry);

  if (Item != NULL) {
    
    
    
    NetMapRemoveItem (TokenMap, Item, NULL);

    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}


EFI_STATUS Dns6RemoveTokenEntry ( IN NET_MAP                    *TokenMap, IN DNS6_TOKEN_ENTRY           *TokenEntry )



{
  NET_MAP_ITEM  *Item;

  
  
  
  Item = NetMapFindKey (TokenMap, (VOID *) TokenEntry);

  if (Item != NULL) {
    
    
    
    NetMapRemoveItem (TokenMap, Item, NULL);

    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}


EFI_STATUS EFIAPI Dns4CancelTokens ( IN NET_MAP       *Map, IN NET_MAP_ITEM  *Item, IN VOID          *Arg OPTIONAL )





{
  DNS4_TOKEN_ENTRY           *TokenEntry;
  NET_BUF                    *Packet;
  UDP_IO                     *UdpIo;

  if ((Arg != NULL) && (Item->Key != Arg)) {
    return EFI_SUCCESS;
  }

  if (Item->Value != NULL) {
    
    
    
    
    Packet  = (NET_BUF *) (Item->Value);
    UdpIo = (UDP_IO *) (*((UINTN *) &Packet->ProtoData[0]));

    UdpIoCancelSentDatagram (UdpIo, Packet);
  }

  
  
  
  TokenEntry = (DNS4_TOKEN_ENTRY *) Item->Key;
  if (Dns4RemoveTokenEntry (Map, TokenEntry) == EFI_SUCCESS) {
    TokenEntry->Token->Status = EFI_ABORTED;
    gBS->SignalEvent (TokenEntry->Token->Event);
    DispatchDpc ();
  }

  if (Arg != NULL) {
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}


EFI_STATUS EFIAPI Dns6CancelTokens ( IN NET_MAP       *Map, IN NET_MAP_ITEM  *Item, IN VOID          *Arg OPTIONAL )





{
  DNS6_TOKEN_ENTRY           *TokenEntry;
  NET_BUF                    *Packet;
  UDP_IO                     *UdpIo;

  if ((Arg != NULL) && (Item->Key != Arg)) {
    return EFI_SUCCESS;
  }

  if (Item->Value != NULL) {
    
    
    
    
    Packet  = (NET_BUF *) (Item->Value);
    UdpIo = (UDP_IO *) (*((UINTN *) &Packet->ProtoData[0]));

    UdpIoCancelSentDatagram (UdpIo, Packet);
  }

  
  
  
  TokenEntry = (DNS6_TOKEN_ENTRY *) Item->Key;
  if (Dns6RemoveTokenEntry (Map, TokenEntry) == EFI_SUCCESS) {
    TokenEntry->Token->Status = EFI_ABORTED;
    gBS->SignalEvent (TokenEntry->Token->Event);
    DispatchDpc ();
  }

  if (Arg != NULL) {
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}


EFI_STATUS EFIAPI GetDns4TokenEntry ( IN     NET_MAP                   *TokensMap, IN     EFI_DNS4_COMPLETION_TOKEN *Token, OUT DNS4_TOKEN_ENTRY          **TokenEntry )





{
  LIST_ENTRY              *Entry;

  NET_MAP_ITEM            *Item;

  NET_LIST_FOR_EACH (Entry, &TokensMap->Used) {
    Item = NET_LIST_USER_STRUCT (Entry, NET_MAP_ITEM, Link);
    *TokenEntry = (DNS4_TOKEN_ENTRY *) (Item->Key);
    if ((*TokenEntry)->Token == Token) {
      return EFI_SUCCESS;
    }
  }

  *TokenEntry = NULL;

  return EFI_NOT_FOUND;
}


EFI_STATUS EFIAPI GetDns6TokenEntry ( IN     NET_MAP                   *TokensMap, IN     EFI_DNS6_COMPLETION_TOKEN *Token, OUT DNS6_TOKEN_ENTRY          **TokenEntry )





{
  LIST_ENTRY              *Entry;

  NET_MAP_ITEM            *Item;

  NET_LIST_FOR_EACH (Entry, &TokensMap->Used) {
    Item = NET_LIST_USER_STRUCT (Entry, NET_MAP_ITEM, Link);
    *TokenEntry = (DNS6_TOKEN_ENTRY *) (Item->Key);
    if ((*TokenEntry)->Token == Token) {
      return EFI_SUCCESS;
    }
  }

  *TokenEntry =NULL;

  return EFI_NOT_FOUND;
}


EFI_STATUS Dns4InstanceCancelToken ( IN DNS_INSTANCE               *Instance, IN EFI_DNS4_COMPLETION_TOKEN  *Token )



{
  EFI_STATUS        Status;
  DNS4_TOKEN_ENTRY  *TokenEntry;

  TokenEntry = NULL;

  if(Token != NULL  ) {
    Status = GetDns4TokenEntry (&Instance->Dns4TxTokens, Token, &TokenEntry);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else {
    TokenEntry = NULL;
  }

  
  
  
  Status = NetMapIterate (&Instance->Dns4TxTokens, Dns4CancelTokens, TokenEntry);

  if ((TokenEntry != NULL) && (Status == EFI_ABORTED)) {
    
    
    
    
    if (NetMapIsEmpty (&Instance->Dns4TxTokens)) {
       Instance->UdpIo->Protocol.Udp4->Cancel (Instance->UdpIo->Protocol.Udp4, &Instance->UdpIo->RecvRequest->Token.Udp4);
    }
    return EFI_SUCCESS;
  }

  ASSERT ((TokenEntry != NULL) || (0 == NetMapGetCount (&Instance->Dns4TxTokens)));

  if (NetMapIsEmpty (&Instance->Dns4TxTokens)) {
    Instance->UdpIo->Protocol.Udp4->Cancel (Instance->UdpIo->Protocol.Udp4, &Instance->UdpIo->RecvRequest->Token.Udp4);
  }

  return EFI_SUCCESS;
}


EFI_STATUS Dns6InstanceCancelToken ( IN DNS_INSTANCE               *Instance, IN EFI_DNS6_COMPLETION_TOKEN  *Token )



{
  EFI_STATUS        Status;
  DNS6_TOKEN_ENTRY  *TokenEntry;

  TokenEntry = NULL;

  if(Token != NULL  ) {
    Status = GetDns6TokenEntry (&Instance->Dns6TxTokens, Token, &TokenEntry);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else {
    TokenEntry = NULL;
  }

  
  
  
  Status = NetMapIterate (&Instance->Dns6TxTokens, Dns6CancelTokens, TokenEntry);

  if ((TokenEntry != NULL) && (Status == EFI_ABORTED)) {
    
    
    
    
    if (NetMapIsEmpty (&Instance->Dns6TxTokens)) {
       Instance->UdpIo->Protocol.Udp6->Cancel (Instance->UdpIo->Protocol.Udp6, &Instance->UdpIo->RecvRequest->Token.Udp6);
    }
    return EFI_SUCCESS;
  }

  ASSERT ((TokenEntry != NULL) || (0 == NetMapGetCount (&Instance->Dns6TxTokens)));

  if (NetMapIsEmpty (&Instance->Dns6TxTokens)) {
    Instance->UdpIo->Protocol.Udp6->Cancel (Instance->UdpIo->Protocol.Udp6, &Instance->UdpIo->RecvRequest->Token.Udp6);
  }

  return EFI_SUCCESS;
}


VOID Dns4CleanConfigure ( IN OUT EFI_DNS4_CONFIG_DATA  *Config )


{
  if (Config->DnsServerList != NULL) {
    FreePool (Config->DnsServerList);
  }

  ZeroMem (Config, sizeof (EFI_DNS4_CONFIG_DATA));
}


VOID Dns6CleanConfigure ( IN OUT EFI_DNS6_CONFIG_DATA  *Config )


{
  if (Config->DnsServerList != NULL) {
    FreePool (Config->DnsServerList);
  }

  ZeroMem (Config, sizeof (EFI_DNS6_CONFIG_DATA));
}


EFI_STATUS Dns4CopyConfigure ( OUT EFI_DNS4_CONFIG_DATA  *Dst, IN  EFI_DNS4_CONFIG_DATA  *Src )



{
  UINTN                     Len;
  UINT32                    Index;

  CopyMem (Dst, Src, sizeof (*Dst));
  Dst->DnsServerList = NULL;

  
  
  
  if (Src->DnsServerList != NULL) {
    Len                = Src->DnsServerListCount * sizeof (EFI_IPv4_ADDRESS);
    Dst->DnsServerList = AllocatePool (Len);
    if (Dst->DnsServerList == NULL) {
      Dns4CleanConfigure (Dst);
      return EFI_OUT_OF_RESOURCES;
    }

    for (Index = 0; Index < Src->DnsServerListCount; Index++) {
      CopyMem (&Dst->DnsServerList[Index], &Src->DnsServerList[Index], sizeof (EFI_IPv4_ADDRESS));
    }
  }

  return EFI_SUCCESS;
}


EFI_STATUS Dns6CopyConfigure ( OUT EFI_DNS6_CONFIG_DATA  *Dst, IN  EFI_DNS6_CONFIG_DATA  *Src )



{
  UINTN                     Len;
  UINT32                    Index;

  CopyMem (Dst, Src, sizeof (*Dst));
  Dst->DnsServerList = NULL;

  
  
  
  if (Src->DnsServerList != NULL) {
    Len                = Src->DnsServerCount * sizeof (EFI_IPv6_ADDRESS);
    Dst->DnsServerList = AllocatePool (Len);
    if (Dst->DnsServerList == NULL) {
      Dns6CleanConfigure (Dst);
      return EFI_OUT_OF_RESOURCES;
    }

    for (Index = 0; Index < Src->DnsServerCount; Index++) {
      CopyMem (&Dst->DnsServerList[Index], &Src->DnsServerList[Index], sizeof (EFI_IPv6_ADDRESS));
    }
  }

  return EFI_SUCCESS;
}


VOID EFIAPI DnsDummyExtFree ( IN VOID                   *Arg )



{
}


BOOLEAN Dns4GetMapping ( IN DNS_INSTANCE           *Instance, IN UDP_IO                 *UdpIo, IN EFI_UDP4_CONFIG_DATA   *UdpCfgData )




{
  DNS_SERVICE               *Service;
  EFI_IP4_MODE_DATA         Ip4Mode;
  EFI_UDP4_PROTOCOL         *Udp;
  EFI_STATUS                Status;

  ASSERT (Instance->Dns4CfgData.UseDefaultSetting);

  Service = Instance->Service;
  Udp     = UdpIo->Protocol.Udp4;

  Status = gBS->SetTimer ( Service->TimerToGetMap, TimerRelative, DNS_TIME_TO_GETMAP * TICKS_PER_SECOND );



  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  while (EFI_ERROR (gBS->CheckEvent (Service->TimerToGetMap))) {
    Udp->Poll (Udp);

    if (!EFI_ERROR (Udp->GetModeData (Udp, NULL, &Ip4Mode, NULL, NULL)) && Ip4Mode.IsConfigured) {

      Udp->Configure (Udp, NULL);
      return (BOOLEAN) (Udp->Configure (Udp, UdpCfgData) == EFI_SUCCESS);
    }
  }

  return FALSE;
}


BOOLEAN Dns6GetMapping ( IN DNS_INSTANCE           *Instance, IN UDP_IO                 *UdpIo, IN EFI_UDP6_CONFIG_DATA   *UdpCfgData )




{
  DNS_SERVICE               *Service;
  EFI_IP6_MODE_DATA         Ip6Mode;
  EFI_UDP6_PROTOCOL         *Udp;
  EFI_STATUS                Status;

  Service = Instance->Service;
  Udp     = UdpIo->Protocol.Udp6;

  Status = gBS->SetTimer ( Service->TimerToGetMap, TimerRelative, DNS_TIME_TO_GETMAP * TICKS_PER_SECOND );



  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  while (EFI_ERROR (gBS->CheckEvent (Service->TimerToGetMap))) {
    Udp->Poll (Udp);

    if (!EFI_ERROR (Udp->GetModeData (Udp, NULL, &Ip6Mode, NULL, NULL))) {
      if (Ip6Mode.AddressList != NULL) {
        FreePool (Ip6Mode.AddressList);
      }

      if (Ip6Mode.GroupTable != NULL) {
        FreePool (Ip6Mode.GroupTable);
      }

      if (Ip6Mode.RouteTable != NULL) {
        FreePool (Ip6Mode.RouteTable);
      }

      if (Ip6Mode.NeighborCache != NULL) {
        FreePool (Ip6Mode.NeighborCache);
      }

      if (Ip6Mode.PrefixTable != NULL) {
        FreePool (Ip6Mode.PrefixTable);
      }

      if (Ip6Mode.IcmpTypeList != NULL) {
        FreePool (Ip6Mode.IcmpTypeList);
      }

      if (!Ip6Mode.IsStarted || Ip6Mode.IsConfigured) {
        Udp->Configure (Udp, NULL);
        if (Udp->Configure (Udp, UdpCfgData) == EFI_SUCCESS) {
          return TRUE;
        }
      }
    }
  }

  return FALSE;
}


EFI_STATUS Dns4ConfigUdp ( IN DNS_INSTANCE           *Instance, IN UDP_IO                 *UdpIo )



{
  EFI_DNS4_CONFIG_DATA      *Config;
  EFI_UDP4_CONFIG_DATA      UdpConfig;
  EFI_STATUS                Status;

  Config = &Instance->Dns4CfgData;

  UdpConfig.AcceptBroadcast    = FALSE;
  UdpConfig.AcceptPromiscuous  = FALSE;
  UdpConfig.AcceptAnyPort      = FALSE;
  UdpConfig.AllowDuplicatePort = FALSE;
  UdpConfig.TypeOfService      = 0;
  UdpConfig.TimeToLive         = 128;
  UdpConfig.DoNotFragment      = FALSE;
  UdpConfig.ReceiveTimeout     = 0;
  UdpConfig.TransmitTimeout    = 0;
  UdpConfig.UseDefaultAddress  = Config->UseDefaultSetting;
  UdpConfig.SubnetMask         = Config->SubnetMask;
  UdpConfig.StationPort        = Config->LocalPort;
  UdpConfig.RemotePort         = DNS_SERVER_PORT;

  CopyMem (&UdpConfig.StationAddress, &Config->StationIp, sizeof (EFI_IPv4_ADDRESS));
  CopyMem (&UdpConfig.RemoteAddress, &Instance->SessionDnsServer.v4, sizeof (EFI_IPv4_ADDRESS));

  Status = UdpIo->Protocol.Udp4->Configure (UdpIo->Protocol.Udp4, &UdpConfig);

  if ((Status == EFI_NO_MAPPING) && Dns4GetMapping (Instance, UdpIo, &UdpConfig)) {
    return EFI_SUCCESS;
  }

  return Status;
}


EFI_STATUS Dns6ConfigUdp ( IN DNS_INSTANCE           *Instance, IN UDP_IO                 *UdpIo )



{
  EFI_DNS6_CONFIG_DATA      *Config;
  EFI_UDP6_CONFIG_DATA      UdpConfig;
  EFI_STATUS                Status;

  Config = &Instance->Dns6CfgData;

  UdpConfig.AcceptPromiscuous  = FALSE;
  UdpConfig.AcceptAnyPort      = FALSE;
  UdpConfig.AllowDuplicatePort = FALSE;
  UdpConfig.TrafficClass       = 0;
  UdpConfig.HopLimit           = 128;
  UdpConfig.ReceiveTimeout     = 0;
  UdpConfig.TransmitTimeout    = 0;
  UdpConfig.StationPort        = Config->LocalPort;
  UdpConfig.RemotePort         = DNS_SERVER_PORT;
  CopyMem (&UdpConfig.StationAddress, &Config->StationIp, sizeof (EFI_IPv6_ADDRESS));
  CopyMem (&UdpConfig.RemoteAddress, &Instance->SessionDnsServer.v6, sizeof (EFI_IPv6_ADDRESS));

  Status = UdpIo->Protocol.Udp6->Configure (UdpIo->Protocol.Udp6, &UdpConfig);

  if ((Status == EFI_NO_MAPPING) && Dns6GetMapping (Instance, UdpIo, &UdpConfig)) {
    return EFI_SUCCESS;
  }

  return Status;
}


EFI_STATUS EFIAPI UpdateDns4Cache ( IN LIST_ENTRY             *Dns4CacheList, IN BOOLEAN                DeleteFlag, IN BOOLEAN                Override, IN EFI_DNS4_CACHE_ENTRY   DnsCacheEntry )






{
  DNS4_CACHE    *NewDnsCache;
  DNS4_CACHE    *Item;
  LIST_ENTRY    *Entry;
  LIST_ENTRY    *Next;

  NewDnsCache = NULL;
  Item        = NULL;

  
  
  
  NET_LIST_FOR_EACH_SAFE (Entry, Next, Dns4CacheList) {
    Item = NET_LIST_USER_STRUCT (Entry, DNS4_CACHE, AllCacheLink);
    if (StrCmp (DnsCacheEntry.HostName, Item->DnsCache.HostName) == 0 &&  CompareMem (DnsCacheEntry.IpAddress, Item->DnsCache.IpAddress, sizeof (EFI_IPv4_ADDRESS)) == 0)
      
      
      
      if (DeleteFlag) {
        
        
        
        RemoveEntryList (&Item->AllCacheLink);

        FreePool (Item->DnsCache.HostName);
        FreePool (Item->DnsCache.IpAddress);
        FreePool (Item);

        return EFI_SUCCESS;
      } else if (Override) {
        
        
        
        Item->DnsCache.Timeout = DnsCacheEntry.Timeout;

        return EFI_SUCCESS;
      }else {
        return EFI_ACCESS_DENIED;
      }
    }
  }

  
  
  
  NewDnsCache = AllocatePool (sizeof (DNS4_CACHE));
  if (NewDnsCache == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  InitializeListHead (&NewDnsCache->AllCacheLink);

  NewDnsCache->DnsCache.HostName = AllocatePool (StrSize (DnsCacheEntry.HostName));
  if (NewDnsCache->DnsCache.HostName == NULL) {
    FreePool (NewDnsCache);
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (NewDnsCache->DnsCache.HostName, DnsCacheEntry.HostName, StrSize (DnsCacheEntry.HostName));

  NewDnsCache->DnsCache.IpAddress = AllocatePool (sizeof (EFI_IPv4_ADDRESS));
  if (NewDnsCache->DnsCache.IpAddress == NULL) {
    FreePool (NewDnsCache->DnsCache.HostName);
    FreePool (NewDnsCache);
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (NewDnsCache->DnsCache.IpAddress, DnsCacheEntry.IpAddress, sizeof (EFI_IPv4_ADDRESS));

  NewDnsCache->DnsCache.Timeout = DnsCacheEntry.Timeout;

  InsertTailList (Dns4CacheList, &NewDnsCache->AllCacheLink);

  return EFI_SUCCESS;
}


EFI_STATUS EFIAPI UpdateDns6Cache ( IN LIST_ENTRY             *Dns6CacheList, IN BOOLEAN                DeleteFlag, IN BOOLEAN                Override, IN EFI_DNS6_CACHE_ENTRY   DnsCacheEntry )






{
  DNS6_CACHE    *NewDnsCache;
  DNS6_CACHE    *Item;
  LIST_ENTRY    *Entry;
  LIST_ENTRY    *Next;

  NewDnsCache = NULL;
  Item        = NULL;

  
  
  
  NET_LIST_FOR_EACH_SAFE (Entry, Next, Dns6CacheList) {
    Item = NET_LIST_USER_STRUCT (Entry, DNS6_CACHE, AllCacheLink);
    if (StrCmp (DnsCacheEntry.HostName, Item->DnsCache.HostName) == 0 &&  CompareMem (DnsCacheEntry.IpAddress, Item->DnsCache.IpAddress, sizeof (EFI_IPv6_ADDRESS)) == 0)
      
      
      
      if (DeleteFlag) {
        
        
        
        RemoveEntryList (&Item->AllCacheLink);

        FreePool (Item->DnsCache.HostName);
        FreePool (Item->DnsCache.IpAddress);
        FreePool (Item);

        return EFI_SUCCESS;
      } else if (Override) {
        
        
        
        Item->DnsCache.Timeout = DnsCacheEntry.Timeout;

        return EFI_SUCCESS;
      }else {
        return EFI_ACCESS_DENIED;
      }
    }
  }

  
  
  
  NewDnsCache = AllocatePool (sizeof (DNS6_CACHE));
  if (NewDnsCache == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  InitializeListHead (&NewDnsCache->AllCacheLink);

  NewDnsCache->DnsCache.HostName = AllocatePool (StrSize (DnsCacheEntry.HostName));
  if (NewDnsCache->DnsCache.HostName == NULL) {
    FreePool (NewDnsCache);
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (NewDnsCache->DnsCache.HostName, DnsCacheEntry.HostName, StrSize (DnsCacheEntry.HostName));

  NewDnsCache->DnsCache.IpAddress = AllocatePool (sizeof (EFI_IPv6_ADDRESS));
  if (NewDnsCache->DnsCache.IpAddress == NULL) {
    FreePool (NewDnsCache->DnsCache.HostName);
    FreePool (NewDnsCache);
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (NewDnsCache->DnsCache.IpAddress, DnsCacheEntry.IpAddress, sizeof (EFI_IPv6_ADDRESS));

  NewDnsCache->DnsCache.Timeout = DnsCacheEntry.Timeout;

  InsertTailList (Dns6CacheList, &NewDnsCache->AllCacheLink);

  return EFI_SUCCESS;
}


EFI_STATUS EFIAPI AddDns4ServerIp ( IN LIST_ENTRY                *Dns4ServerList, IN EFI_IPv4_ADDRESS           ServerIp )




{
  DNS4_SERVER_IP    *NewServerIp;
  DNS4_SERVER_IP    *Item;
  LIST_ENTRY        *Entry;
  LIST_ENTRY        *Next;

  NewServerIp = NULL;
  Item        = NULL;

  
  
  
  NET_LIST_FOR_EACH_SAFE (Entry, Next, Dns4ServerList) {
    Item = NET_LIST_USER_STRUCT (Entry, DNS4_SERVER_IP, AllServerLink);
    if (CompareMem (&Item->Dns4ServerIp, &ServerIp, sizeof (EFI_IPv4_ADDRESS)) == 0) {
      
      
      
      return EFI_SUCCESS;
    }
  }

  
  
  
  NewServerIp = AllocatePool (sizeof (DNS4_SERVER_IP));
  if (NewServerIp == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  InitializeListHead (&NewServerIp->AllServerLink);

  CopyMem (&NewServerIp->Dns4ServerIp, &ServerIp, sizeof (EFI_IPv4_ADDRESS));

  InsertTailList (Dns4ServerList, &NewServerIp->AllServerLink);

  return EFI_SUCCESS;
}


EFI_STATUS EFIAPI AddDns6ServerIp ( IN LIST_ENTRY                *Dns6ServerList, IN EFI_IPv6_ADDRESS           ServerIp )




{
  DNS6_SERVER_IP    *NewServerIp;
  DNS6_SERVER_IP    *Item;
  LIST_ENTRY        *Entry;
  LIST_ENTRY        *Next;

  NewServerIp = NULL;
  Item        = NULL;

  
  
  
  NET_LIST_FOR_EACH_SAFE (Entry, Next, Dns6ServerList) {
    Item = NET_LIST_USER_STRUCT (Entry, DNS6_SERVER_IP, AllServerLink);
    if (CompareMem (&Item->Dns6ServerIp, &ServerIp, sizeof (EFI_IPv6_ADDRESS)) == 0) {
      
      
      
      return EFI_SUCCESS;
    }
  }

  
  
  
  NewServerIp = AllocatePool (sizeof (DNS6_SERVER_IP));
  if (NewServerIp == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  InitializeListHead (&NewServerIp->AllServerLink);

  CopyMem (&NewServerIp->Dns6ServerIp, &ServerIp, sizeof (EFI_IPv6_ADDRESS));

  InsertTailList (Dns6ServerList, &NewServerIp->AllServerLink);

  return EFI_SUCCESS;
}


BOOLEAN IsValidDnsResponse ( IN     NET_MAP      *TokensMap, IN     UINT16       Identification, IN     UINT16       Type, IN     UINT16       Class, OUT NET_MAP_ITEM **Item )






{
  LIST_ENTRY              *Entry;

  NET_BUF                 *Packet;
  UINT8                   *TxString;
  DNS_HEADER              *DnsHeader;
  CHAR8                   *QueryName;
  DNS_QUERY_SECTION       *QuerySection;

  NET_LIST_FOR_EACH (Entry, &TokensMap->Used) {
    *Item = NET_LIST_USER_STRUCT (Entry, NET_MAP_ITEM, Link);
    Packet = (NET_BUF *) ((*Item)->Value);
    if (Packet == NULL){

      continue;
    } else {
      TxString = NetbufGetByte (Packet, 0, NULL);
      ASSERT (TxString != NULL);
      DnsHeader = (DNS_HEADER *) TxString;
      QueryName = (CHAR8 *) (TxString + sizeof (*DnsHeader));
      QuerySection = (DNS_QUERY_SECTION *) (QueryName + AsciiStrLen (QueryName) + 1);

      if (NTOHS (DnsHeader->Identification) == Identification && NTOHS (QuerySection->Type) == Type && NTOHS (QuerySection->Class) == Class) {

        return TRUE;
      }
    }
  }

  *Item = NULL;

  return FALSE;
}


EFI_STATUS ParseDnsResponse ( IN OUT DNS_INSTANCE              *Instance, IN     UINT8                     *RxString, OUT BOOLEAN                   *Completed )




{
  DNS_HEADER            *DnsHeader;

  CHAR8                 *QueryName;
  DNS_QUERY_SECTION     *QuerySection;

  CHAR8                 *AnswerName;
  DNS_ANSWER_SECTION    *AnswerSection;
  UINT8                 *AnswerData;

  NET_MAP_ITEM          *Item;
  DNS4_TOKEN_ENTRY      *Dns4TokenEntry;
  DNS6_TOKEN_ENTRY      *Dns6TokenEntry;

  UINT32                IpCount;
  UINT32                RRCount;
  UINT32                AnswerSectionNum;
  UINT32                CNameTtl;

  EFI_IPv4_ADDRESS      *HostAddr4;
  EFI_IPv6_ADDRESS      *HostAddr6;

  EFI_DNS4_CACHE_ENTRY  *Dns4CacheEntry;
  EFI_DNS6_CACHE_ENTRY  *Dns6CacheEntry;

  DNS_RESOURCE_RECORD   *Dns4RR;
  DNS6_RESOURCE_RECORD  *Dns6RR;

  EFI_STATUS            Status;

  EFI_TPL               OldTpl;

  Item             = NULL;
  Dns4TokenEntry   = NULL;
  Dns6TokenEntry   = NULL;

  IpCount          = 0;
  RRCount          = 0;
  AnswerSectionNum = 0;
  CNameTtl         = 0;

  HostAddr4        = NULL;
  HostAddr6        = NULL;

  Dns4CacheEntry   = NULL;
  Dns6CacheEntry   = NULL;

  Dns4RR           = NULL;
  Dns6RR           = NULL;

  *Completed       = TRUE;
  Status           = EFI_SUCCESS;

  
  
  
  DnsHeader = (DNS_HEADER *) RxString;

  DnsHeader->Identification = NTOHS (DnsHeader->Identification);
  DnsHeader->Flags.Uint16 = NTOHS (DnsHeader->Flags.Uint16);
  DnsHeader->QuestionsNum = NTOHS (DnsHeader->QuestionsNum);
  DnsHeader->AnswersNum = NTOHS (DnsHeader->AnswersNum);
  DnsHeader->AuthorityNum = NTOHS (DnsHeader->AuthorityNum);
  DnsHeader->AditionalNum = NTOHS (DnsHeader->AditionalNum);

  
  
  
  QueryName = (CHAR8 *) (RxString + sizeof (*DnsHeader));

  
  
  
  QuerySection = (DNS_QUERY_SECTION *) (QueryName + AsciiStrLen (QueryName) + 1);
  QuerySection->Type = NTOHS (QuerySection->Type);
  QuerySection->Class = NTOHS (QuerySection->Class);

  
  
  
  AnswerName = (CHAR8 *) QuerySection + sizeof (*QuerySection);

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  
  
  
  if (Instance->Service->IpVersion == IP_VERSION_4) {
    if (!IsValidDnsResponse ( &Instance->Dns4TxTokens, DnsHeader->Identification, QuerySection->Type, QuerySection->Class, &Item )) {





      *Completed = FALSE;
      Status = EFI_ABORTED;
      goto ON_EXIT;
    }
    ASSERT (Item != NULL);
    Dns4TokenEntry = (DNS4_TOKEN_ENTRY *) (Item->Key);
  } else {
    if (!IsValidDnsResponse ( &Instance->Dns6TxTokens, DnsHeader->Identification, QuerySection->Type, QuerySection->Class, &Item )) {





      *Completed = FALSE;
      Status = EFI_ABORTED;
      goto ON_EXIT;
    }
    ASSERT (Item != NULL);
    Dns6TokenEntry = (DNS6_TOKEN_ENTRY *) (Item->Key);
  }

  
  
  
  if (DnsHeader->Flags.Bits.RCode != DNS_FLAGS_RCODE_NO_ERROR || DnsHeader->AnswersNum < 1 ||  DnsHeader->Flags.Bits.QR != DNS_FLAGS_QR_RESPONSE)
    
    
    
    if (DnsHeader->Flags.Bits.RCode == DNS_FLAGS_RCODE_NAME_ERROR) {
      Status = EFI_NOT_FOUND;
    } else {
      Status = EFI_DEVICE_ERROR;
    }

    goto ON_COMPLETE;
  }

  
  
  
  if (Instance->Service->IpVersion == IP_VERSION_4) {
    ASSERT (Dns4TokenEntry != NULL);

    if (Dns4TokenEntry->GeneralLookUp) {
      
      
      
      Dns4TokenEntry->Token->RspData.GLookupData = AllocateZeroPool (sizeof (DNS_RESOURCE_RECORD));
      if (Dns4TokenEntry->Token->RspData.GLookupData == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }
      Dns4TokenEntry->Token->RspData.GLookupData->RRList = AllocateZeroPool (DnsHeader->AnswersNum * sizeof (DNS_RESOURCE_RECORD));
      if (Dns4TokenEntry->Token->RspData.GLookupData->RRList == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }
    } else {
      
      
      
      if (QuerySection->Type == DNS_TYPE_A) {
        Dns4TokenEntry->Token->RspData.H2AData = AllocateZeroPool (sizeof (DNS_HOST_TO_ADDR_DATA));
        if (Dns4TokenEntry->Token->RspData.H2AData == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
        Dns4TokenEntry->Token->RspData.H2AData->IpList = AllocateZeroPool (DnsHeader->AnswersNum * sizeof (EFI_IPv4_ADDRESS));
        if (Dns4TokenEntry->Token->RspData.H2AData->IpList == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
      } else {
        Status = EFI_UNSUPPORTED;
        goto ON_EXIT;
      }
    }
  } else {
    ASSERT (Dns6TokenEntry != NULL);

    if (Dns6TokenEntry->GeneralLookUp) {
      
      
      
      Dns6TokenEntry->Token->RspData.GLookupData = AllocateZeroPool (sizeof (DNS_RESOURCE_RECORD));
      if (Dns6TokenEntry->Token->RspData.GLookupData == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }
      Dns6TokenEntry->Token->RspData.GLookupData->RRList = AllocateZeroPool (DnsHeader->AnswersNum * sizeof (DNS_RESOURCE_RECORD));
      if (Dns6TokenEntry->Token->RspData.GLookupData->RRList == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }
    } else {
      
      
      
      if (QuerySection->Type == DNS_TYPE_AAAA) {
        Dns6TokenEntry->Token->RspData.H2AData = AllocateZeroPool (sizeof (DNS6_HOST_TO_ADDR_DATA));
        if (Dns6TokenEntry->Token->RspData.H2AData == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
        Dns6TokenEntry->Token->RspData.H2AData->IpList = AllocateZeroPool (DnsHeader->AnswersNum * sizeof (EFI_IPv6_ADDRESS));
        if (Dns6TokenEntry->Token->RspData.H2AData->IpList == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
      } else {
        Status = EFI_UNSUPPORTED;
        goto ON_EXIT;
      }
    }
  }

  Status = EFI_NOT_FOUND;

  
  
  
  while (AnswerSectionNum < DnsHeader->AnswersNum) {
    
    
    
    if ((*(UINT8 *) AnswerName & 0xC0) != 0xC0) {
      Status = EFI_UNSUPPORTED;
      goto ON_EXIT;
    }

    
    
    
    AnswerSection = (DNS_ANSWER_SECTION *) (AnswerName + sizeof (UINT16));
    AnswerSection->Type = NTOHS (AnswerSection->Type);
    AnswerSection->Class = NTOHS (AnswerSection->Class);
    AnswerSection->Ttl = NTOHL (AnswerSection->Ttl);
    AnswerSection->DataLength = NTOHS (AnswerSection->DataLength);

    
    
    
    if (Instance->Service->IpVersion == IP_VERSION_4 && Dns4TokenEntry->GeneralLookUp) {
      Dns4RR = Dns4TokenEntry->Token->RspData.GLookupData->RRList;
      AnswerData = (UINT8 *) AnswerSection + sizeof (*AnswerSection);

      
      
      
      Dns4RR[RRCount].QName = AllocateZeroPool (AsciiStrLen (QueryName) + 1);
      if (Dns4RR[RRCount].QName == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }
      CopyMem (Dns4RR[RRCount].QName, QueryName, AsciiStrLen (QueryName));
      Dns4RR[RRCount].QType = AnswerSection->Type;
      Dns4RR[RRCount].QClass = AnswerSection->Class;
      Dns4RR[RRCount].TTL = AnswerSection->Ttl;
      Dns4RR[RRCount].DataLength = AnswerSection->DataLength;
      Dns4RR[RRCount].RData = AllocateZeroPool (Dns4RR[RRCount].DataLength);
      if (Dns4RR[RRCount].RData == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }
      CopyMem (Dns4RR[RRCount].RData, AnswerData, Dns4RR[RRCount].DataLength);

      RRCount ++;
      Status = EFI_SUCCESS;
    } else if (Instance->Service->IpVersion == IP_VERSION_6 && Dns6TokenEntry->GeneralLookUp) {
      Dns6RR = Dns6TokenEntry->Token->RspData.GLookupData->RRList;
      AnswerData = (UINT8 *) AnswerSection + sizeof (*AnswerSection);

      
      
      
      Dns6RR[RRCount].QName = AllocateZeroPool (AsciiStrLen (QueryName) + 1);
      if (Dns6RR[RRCount].QName == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }
      CopyMem (Dns6RR[RRCount].QName, QueryName, AsciiStrLen (QueryName));
      Dns6RR[RRCount].QType = AnswerSection->Type;
      Dns6RR[RRCount].QClass = AnswerSection->Class;
      Dns6RR[RRCount].TTL = AnswerSection->Ttl;
      Dns6RR[RRCount].DataLength = AnswerSection->DataLength;
      Dns6RR[RRCount].RData = AllocateZeroPool (Dns6RR[RRCount].DataLength);
      if (Dns6RR[RRCount].RData == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_EXIT;
      }
      CopyMem (Dns6RR[RRCount].RData, AnswerData, Dns6RR[RRCount].DataLength);

      RRCount ++;
      Status = EFI_SUCCESS;
    } else {
      
      
      
      
      switch (AnswerSection->Type) {
      case DNS_TYPE_A:
        
        
        
        ASSERT (Dns4TokenEntry != NULL);

        if (AnswerSection->DataLength != 4) {
          Status = EFI_ABORTED;
          goto ON_EXIT;
        }

        HostAddr4 = Dns4TokenEntry->Token->RspData.H2AData->IpList;
        AnswerData = (UINT8 *) AnswerSection + sizeof (*AnswerSection);
        CopyMem (&HostAddr4[IpCount], AnswerData, sizeof (EFI_IPv4_ADDRESS));

        
        
        
        Dns4CacheEntry = AllocateZeroPool (sizeof (EFI_DNS4_CACHE_ENTRY));
        if (Dns4CacheEntry == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
        Dns4CacheEntry->HostName = AllocateZeroPool (2 * (StrLen(Dns4TokenEntry->QueryHostName) + 1));
        if (Dns4CacheEntry->HostName == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
        CopyMem (Dns4CacheEntry->HostName, Dns4TokenEntry->QueryHostName, 2 * (StrLen(Dns4TokenEntry->QueryHostName) + 1));
        Dns4CacheEntry->IpAddress = AllocateZeroPool (sizeof (EFI_IPv4_ADDRESS));
        if (Dns4CacheEntry->IpAddress == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
        CopyMem (Dns4CacheEntry->IpAddress, AnswerData, sizeof (EFI_IPv4_ADDRESS));

        if (CNameTtl != 0 && AnswerSection->Ttl != 0) {
          Dns4CacheEntry->Timeout = MIN (CNameTtl, AnswerSection->Ttl);
        } else {
          Dns4CacheEntry->Timeout = MAX (CNameTtl, AnswerSection->Ttl);
        }

        UpdateDns4Cache (&mDriverData->Dns4CacheList, FALSE, TRUE, *Dns4CacheEntry);

        
        
        
        FreePool (Dns4CacheEntry->HostName);
        Dns4CacheEntry->HostName = NULL;

        FreePool (Dns4CacheEntry->IpAddress);
        Dns4CacheEntry->IpAddress = NULL;

        FreePool (Dns4CacheEntry);
        Dns4CacheEntry = NULL;

        IpCount ++;
        Status = EFI_SUCCESS;
        break;
      case DNS_TYPE_AAAA:
        
        
        
        ASSERT (Dns6TokenEntry != NULL);

        if (AnswerSection->DataLength != 16) {
          Status = EFI_ABORTED;
          goto ON_EXIT;
        }

        HostAddr6 = Dns6TokenEntry->Token->RspData.H2AData->IpList;
        AnswerData = (UINT8 *) AnswerSection + sizeof (*AnswerSection);
        CopyMem (&HostAddr6[IpCount], AnswerData, sizeof (EFI_IPv6_ADDRESS));

        
        
        
        Dns6CacheEntry = AllocateZeroPool (sizeof (EFI_DNS6_CACHE_ENTRY));
        if (Dns6CacheEntry == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
        Dns6CacheEntry->HostName = AllocateZeroPool (2 * (StrLen(Dns6TokenEntry->QueryHostName) + 1));
        if (Dns6CacheEntry->HostName == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
        CopyMem (Dns6CacheEntry->HostName, Dns6TokenEntry->QueryHostName, 2 * (StrLen(Dns6TokenEntry->QueryHostName) + 1));
        Dns6CacheEntry->IpAddress = AllocateZeroPool (sizeof (EFI_IPv6_ADDRESS));
        if (Dns6CacheEntry->IpAddress == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_EXIT;
        }
        CopyMem (Dns6CacheEntry->IpAddress, AnswerData, sizeof (EFI_IPv6_ADDRESS));

        if (CNameTtl != 0 && AnswerSection->Ttl != 0) {
          Dns6CacheEntry->Timeout = MIN (CNameTtl, AnswerSection->Ttl);
        } else {
          Dns6CacheEntry->Timeout = MAX (CNameTtl, AnswerSection->Ttl);
        }

        UpdateDns6Cache (&mDriverData->Dns6CacheList, FALSE, TRUE, *Dns6CacheEntry);

        
        
        
        FreePool (Dns6CacheEntry->HostName);
        Dns6CacheEntry->HostName = NULL;

        FreePool (Dns6CacheEntry->IpAddress);
        Dns6CacheEntry->IpAddress = NULL;

        FreePool (Dns6CacheEntry);
        Dns6CacheEntry = NULL;

        IpCount ++;
        Status = EFI_SUCCESS;
        break;
      case DNS_TYPE_CNAME:
        
        
        
        
        
        CNameTtl = AnswerSection->Ttl;
        break;
      default:
        Status = EFI_UNSUPPORTED;
        goto ON_EXIT;
      }
    }

    
    
    
    AnswerName = (CHAR8 *) AnswerSection + sizeof (*AnswerSection) + AnswerSection->DataLength;
    AnswerSectionNum ++;
  }

  if (Instance->Service->IpVersion == IP_VERSION_4) {
    ASSERT (Dns4TokenEntry != NULL);

    if (Dns4TokenEntry->GeneralLookUp) {
      Dns4TokenEntry->Token->RspData.GLookupData->RRCount = RRCount;
    } else {
      if (QuerySection->Type == DNS_TYPE_A) {
        Dns4TokenEntry->Token->RspData.H2AData->IpCount = IpCount;
      } else {
        Status = EFI_UNSUPPORTED;
        goto ON_EXIT;
      }
    }
  } else {
    ASSERT (Dns6TokenEntry != NULL);

    if (Dns6TokenEntry->GeneralLookUp) {
      Dns6TokenEntry->Token->RspData.GLookupData->RRCount = RRCount;
    } else {
      if (QuerySection->Type == DNS_TYPE_AAAA) {
        Dns6TokenEntry->Token->RspData.H2AData->IpCount = IpCount;
      } else {
        Status = EFI_UNSUPPORTED;
        goto ON_EXIT;
      }
    }
  }

ON_COMPLETE:
  
  
  
  if (Item != NULL && Item->Value != NULL) {
    NetbufFree ((NET_BUF *) (Item->Value));
  }

  if (Instance->Service->IpVersion == IP_VERSION_4) {
    ASSERT (Dns4TokenEntry != NULL);
    Dns4RemoveTokenEntry (&Instance->Dns4TxTokens, Dns4TokenEntry);
    Dns4TokenEntry->Token->Status = Status;
    if (Dns4TokenEntry->Token->Event != NULL) {
      gBS->SignalEvent (Dns4TokenEntry->Token->Event);
      DispatchDpc ();
    }
  } else {
    ASSERT (Dns6TokenEntry != NULL);
    Dns6RemoveTokenEntry (&Instance->Dns6TxTokens, Dns6TokenEntry);
    Dns6TokenEntry->Token->Status = Status;
    if (Dns6TokenEntry->Token->Event != NULL) {
      gBS->SignalEvent (Dns6TokenEntry->Token->Event);
      DispatchDpc ();
    }
  }

ON_EXIT:
  
  
  
  if (EFI_ERROR (Status)) {
    if (Dns4TokenEntry != NULL) {
      if (Dns4TokenEntry->GeneralLookUp) {
        if (Dns4TokenEntry->Token->RspData.GLookupData != NULL) {
          if (Dns4TokenEntry->Token->RspData.GLookupData->RRList != NULL) {
            while (RRCount != 0) {
              RRCount --;
              if (Dns4TokenEntry->Token->RspData.GLookupData->RRList[RRCount].QName != NULL) {
                FreePool (Dns4TokenEntry->Token->RspData.GLookupData->RRList[RRCount].QName);
              }

              if (Dns4TokenEntry->Token->RspData.GLookupData->RRList[RRCount].RData != NULL) {
                FreePool (Dns4TokenEntry->Token->RspData.GLookupData->RRList[RRCount].RData);
              }
            }

            FreePool (Dns4TokenEntry->Token->RspData.GLookupData->RRList);
          }

          FreePool (Dns4TokenEntry->Token->RspData.GLookupData);
        }
      } else {
        if (QuerySection->Type == DNS_TYPE_A && Dns4TokenEntry->Token->RspData.H2AData != NULL) {
          if (Dns4TokenEntry->Token->RspData.H2AData->IpList != NULL) {
            FreePool (Dns4TokenEntry->Token->RspData.H2AData->IpList);
          }

          FreePool (Dns4TokenEntry->Token->RspData.H2AData);
        }
      }
    }

    if (Dns6TokenEntry != NULL) {
      if (Dns6TokenEntry->GeneralLookUp) {
        if (Dns6TokenEntry->Token->RspData.GLookupData != NULL) {
          if (Dns6TokenEntry->Token->RspData.GLookupData->RRList != NULL) {
            while (RRCount != 0) {
              RRCount --;
              if (Dns6TokenEntry->Token->RspData.GLookupData->RRList[RRCount].QName != NULL) {
                FreePool (Dns6TokenEntry->Token->RspData.GLookupData->RRList[RRCount].QName);
              }

              if (Dns6TokenEntry->Token->RspData.GLookupData->RRList[RRCount].RData != NULL) {
                FreePool (Dns6TokenEntry->Token->RspData.GLookupData->RRList[RRCount].RData);
              }
            }

            FreePool (Dns6TokenEntry->Token->RspData.GLookupData->RRList);
          }

          FreePool (Dns6TokenEntry->Token->RspData.GLookupData);
        }
      } else {
        if (QuerySection->Type == DNS_TYPE_AAAA && Dns6TokenEntry->Token->RspData.H2AData != NULL) {
          if (Dns6TokenEntry->Token->RspData.H2AData->IpList != NULL) {
            FreePool (Dns6TokenEntry->Token->RspData.H2AData->IpList);
          }

          FreePool (Dns6TokenEntry->Token->RspData.H2AData);
        }
      }
    }

    if (Dns4CacheEntry != NULL) {
      if (Dns4CacheEntry->HostName != NULL) {
        FreePool (Dns4CacheEntry->HostName);
      }

      if (Dns4CacheEntry->IpAddress != NULL) {
        FreePool (Dns4CacheEntry->IpAddress);
      }

      FreePool (Dns4CacheEntry);
    }

    if (Dns6CacheEntry != NULL) {
      if (Dns6CacheEntry->HostName != NULL) {
        FreePool (Dns6CacheEntry->HostName);
      }

      if (Dns6CacheEntry->IpAddress != NULL) {
        FreePool (Dns6CacheEntry->IpAddress);
      }

      FreePool (Dns6CacheEntry);
    }
  }

  gBS->RestoreTPL (OldTpl);
  return Status;
}


VOID EFIAPI DnsOnPacketReceived ( NET_BUF                   *Packet, UDP_END_POINT             *EndPoint, EFI_STATUS                IoStatus, VOID                      *Context )






{
  DNS_INSTANCE              *Instance;

  UINT8                     *RcvString;

  BOOLEAN                   Completed;

  Instance  = (DNS_INSTANCE *) Context;
  NET_CHECK_SIGNATURE (Instance, DNS_INSTANCE_SIGNATURE);

  RcvString = NULL;
  Completed = FALSE;

  if (EFI_ERROR (IoStatus)) {
    goto ON_EXIT;
  }

  ASSERT (Packet != NULL);

  if (Packet->TotalSize <= sizeof (DNS_HEADER)) {
    goto ON_EXIT;
  }

  RcvString = NetbufGetByte (Packet, 0, NULL);
  ASSERT (RcvString != NULL);

  
  
  
  ParseDnsResponse (Instance, RcvString, &Completed);

ON_EXIT:

  if (Packet != NULL) {
    NetbufFree (Packet);
  }

  if (!Completed) {
    UdpIoRecvDatagram (Instance->UdpIo, DnsOnPacketReceived, Instance, 0);
  }
}


VOID EFIAPI DnsOnPacketSent ( NET_BUF                   *Packet, UDP_END_POINT             *EndPoint, EFI_STATUS                IoStatus, VOID                      *Context )






{
  DNS_INSTANCE              *Instance;
  LIST_ENTRY                *Entry;
  NET_MAP_ITEM              *Item;
  DNS4_TOKEN_ENTRY          *Dns4TokenEntry;
  DNS6_TOKEN_ENTRY          *Dns6TokenEntry;

  Dns4TokenEntry = NULL;
  Dns6TokenEntry = NULL;

  Instance  = (DNS_INSTANCE *) Context;
  NET_CHECK_SIGNATURE (Instance, DNS_INSTANCE_SIGNATURE);

  if (Instance->Service->IpVersion == IP_VERSION_4) {
    NET_LIST_FOR_EACH (Entry, &Instance->Dns4TxTokens.Used) {
      Item = NET_LIST_USER_STRUCT (Entry, NET_MAP_ITEM, Link);
      if (Packet == (NET_BUF *)(Item->Value)) {
        Dns4TokenEntry = ((DNS4_TOKEN_ENTRY *)Item->Key);
        Dns4TokenEntry->PacketToLive = Dns4TokenEntry->Token->RetryInterval;
        break;
      }
    }
  } else {
    NET_LIST_FOR_EACH (Entry, &Instance->Dns6TxTokens.Used) {
      Item = NET_LIST_USER_STRUCT (Entry, NET_MAP_ITEM, Link);
      if (Packet == (NET_BUF *)(Item->Value)) {
        Dns6TokenEntry = ((DNS6_TOKEN_ENTRY *)Item->Key);
        Dns6TokenEntry->PacketToLive = Dns6TokenEntry->Token->RetryInterval;
        break;
      }
    }
  }

  NetbufFree (Packet);
}


EFI_STATUS DoDnsQuery ( IN  DNS_INSTANCE              *Instance, IN  NET_BUF                   *Packet )



{
  EFI_STATUS      Status;

  
  
  
  if (Instance->UdpIo->RecvRequest == NULL) {
    Status = UdpIoRecvDatagram (Instance->UdpIo, DnsOnPacketReceived, Instance, 0);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  
  
  
  NET_GET_REF (Packet);

  Status = UdpIoSendDatagram (Instance->UdpIo, Packet, NULL, NULL, DnsOnPacketSent, Instance);

  return Status;
}


EFI_STATUS ConstructDNSQuery ( IN  DNS_INSTANCE              *Instance, IN  CHAR8                     *QueryName, IN  UINT16                    Type, IN  UINT16                    Class, OUT NET_BUF                   **Packet )






{
  NET_FRAGMENT        Frag;
  DNS_HEADER          *DnsHeader;
  DNS_QUERY_SECTION   *DnsQuery;

  
  
  
  
  Frag.Bulk = AllocatePool (DNS_MAX_MESSAGE_SIZE * sizeof (UINT8));
  if (Frag.Bulk == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  
  
  
  DnsHeader = (DNS_HEADER *) Frag.Bulk;
  DnsHeader->Identification = (UINT16)NET_RANDOM (NetRandomInitSeed());
  DnsHeader->Flags.Uint16 = 0x0000;
  DnsHeader->Flags.Bits.RD = 1;
  DnsHeader->Flags.Bits.OpCode = DNS_FLAGS_OPCODE_STANDARD;
  DnsHeader->Flags.Bits.QR = DNS_FLAGS_QR_QUERY;
  DnsHeader->QuestionsNum = 1;
  DnsHeader->AnswersNum = 0;
  DnsHeader->AuthorityNum = 0;
  DnsHeader->AditionalNum = 0;

  DnsHeader->Identification = HTONS (DnsHeader->Identification);
  DnsHeader->Flags.Uint16 = HTONS (DnsHeader->Flags.Uint16);
  DnsHeader->QuestionsNum = HTONS (DnsHeader->QuestionsNum);
  DnsHeader->AnswersNum = HTONS (DnsHeader->AnswersNum);
  DnsHeader->AuthorityNum = HTONS (DnsHeader->AuthorityNum);
  DnsHeader->AditionalNum = HTONS (DnsHeader->AditionalNum);

  Frag.Len = sizeof (*DnsHeader);

  
  
  
  CopyMem (Frag.Bulk + Frag.Len, QueryName, AsciiStrLen (QueryName));
  Frag.Len = (UINT32) (Frag.Len + AsciiStrLen (QueryName));
  *(Frag.Bulk + Frag.Len) = 0;
  Frag.Len ++;

  
  
  
  DnsQuery = (DNS_QUERY_SECTION *) (Frag.Bulk + Frag.Len);

  DnsQuery->Type = HTONS (Type);
  DnsQuery->Class = HTONS (Class);

  Frag.Len += sizeof (*DnsQuery);

  
  
  
  *Packet = NetbufFromExt (&Frag, 1, 0, 0, DnsDummyExtFree, NULL);
  if (*Packet == NULL) {
    FreePool (Frag.Bulk);
    return EFI_OUT_OF_RESOURCES;
  }

  
  
  
  *((UINTN *) &((*Packet)->ProtoData[0])) = (UINTN) (Instance->UdpIo);

  return EFI_SUCCESS;
}


EFI_STATUS DnsRetransmit ( IN DNS_INSTANCE        *Instance, IN NET_BUF             *Packet )



{
  EFI_STATUS      Status;

  UINT8           *Buffer;

  ASSERT (Packet != NULL);

  
  
  
  Buffer = NetbufGetByte (Packet, 0, NULL);
  ASSERT (Buffer != NULL);

  NET_GET_REF (Packet);

  Status = UdpIoSendDatagram ( Instance->UdpIo, Packet, NULL, NULL, DnsOnPacketSent, Instance );







  if (EFI_ERROR (Status)) {
    NET_PUT_REF (Packet);
  }

  return Status;
}


VOID EFIAPI DnsOnTimerRetransmit ( IN EFI_EVENT              Event, IN VOID                   *Context )




{
  DNS_SERVICE                *Service;

  LIST_ENTRY                 *Entry;
  LIST_ENTRY                 *Next;

  DNS_INSTANCE               *Instance;
  LIST_ENTRY                 *EntryNetMap;
  NET_MAP_ITEM               *ItemNetMap;
  DNS4_TOKEN_ENTRY           *Dns4TokenEntry;
  DNS6_TOKEN_ENTRY           *Dns6TokenEntry;

  Dns4TokenEntry = NULL;
  Dns6TokenEntry = NULL;

  Service = (DNS_SERVICE *) Context;


  if (Service->IpVersion == IP_VERSION_4) {
    
    
    
    
    NET_LIST_FOR_EACH_SAFE (Entry, Next, &Service->Dns4ChildrenList) {
      Instance = NET_LIST_USER_STRUCT (Entry, DNS_INSTANCE, Link);

      EntryNetMap = Instance->Dns4TxTokens.Used.ForwardLink;
      while (EntryNetMap != &Instance->Dns4TxTokens.Used) {
        ItemNetMap = NET_LIST_USER_STRUCT (EntryNetMap, NET_MAP_ITEM, Link);
        Dns4TokenEntry = (DNS4_TOKEN_ENTRY *)(ItemNetMap->Key);
        if (Dns4TokenEntry->PacketToLive == 0 || (--Dns4TokenEntry->PacketToLive > 0)) {
          EntryNetMap = EntryNetMap->ForwardLink;
          continue;
        }

        
        
        
        
        if (++Dns4TokenEntry->RetryCounting <= Dns4TokenEntry->Token->RetryCount) {
          DnsRetransmit (Instance, (NET_BUF *)ItemNetMap->Value);
          EntryNetMap = EntryNetMap->ForwardLink;
        } else {
          
          
          
          Dns4RemoveTokenEntry (&Instance->Dns4TxTokens, Dns4TokenEntry);
          Dns4TokenEntry->Token->Status = EFI_TIMEOUT;
          gBS->SignalEvent (Dns4TokenEntry->Token->Event);
          DispatchDpc ();

          
          
          
          if (ItemNetMap->Value != NULL) {
            NetbufFree ((NET_BUF *)(ItemNetMap->Value));
          }

          EntryNetMap = Instance->Dns4TxTokens.Used.ForwardLink;
        }
      }
    }
  }else {
    
    
    
    
    NET_LIST_FOR_EACH_SAFE (Entry, Next, &Service->Dns6ChildrenList) {
      Instance = NET_LIST_USER_STRUCT (Entry, DNS_INSTANCE, Link);

      EntryNetMap = Instance->Dns6TxTokens.Used.ForwardLink;
      while (EntryNetMap != &Instance->Dns6TxTokens.Used) {
        ItemNetMap = NET_LIST_USER_STRUCT (EntryNetMap, NET_MAP_ITEM, Link);
        Dns6TokenEntry = (DNS6_TOKEN_ENTRY *) (ItemNetMap->Key);
        if (Dns6TokenEntry->PacketToLive == 0 || (--Dns6TokenEntry->PacketToLive > 0)) {
          EntryNetMap = EntryNetMap->ForwardLink;
          continue;
        }

        
        
        
        
        if (++Dns6TokenEntry->RetryCounting <= Dns6TokenEntry->Token->RetryCount) {
          DnsRetransmit (Instance, (NET_BUF *) ItemNetMap->Value);
          EntryNetMap = EntryNetMap->ForwardLink;
        } else {
          
          
          
          Dns6RemoveTokenEntry (&Instance->Dns6TxTokens, Dns6TokenEntry);
          Dns6TokenEntry->Token->Status = EFI_TIMEOUT;
          gBS->SignalEvent (Dns6TokenEntry->Token->Event);
          DispatchDpc ();

          
          
          
          if (ItemNetMap->Value != NULL) {
            NetbufFree ((NET_BUF *) (ItemNetMap->Value));
          }

          EntryNetMap = Instance->Dns6TxTokens.Used.ForwardLink;
        }
      }
    }
  }
}


VOID EFIAPI DnsOnTimerUpdate ( IN EFI_EVENT              Event, IN VOID                   *Context )




{
  LIST_ENTRY                 *Entry;
  LIST_ENTRY                 *Next;
  DNS4_CACHE                 *Item4;
  DNS6_CACHE                 *Item6;

  Item4 = NULL;
  Item6 = NULL;

  
  
  
  NET_LIST_FOR_EACH_SAFE (Entry, Next, &mDriverData->Dns4CacheList) {
    Item4 = NET_LIST_USER_STRUCT (Entry, DNS4_CACHE, AllCacheLink);
    Item4->DnsCache.Timeout--;
  }

  Entry = mDriverData->Dns4CacheList.ForwardLink;
  while (Entry != &mDriverData->Dns4CacheList) {
    Item4 = NET_LIST_USER_STRUCT (Entry, DNS4_CACHE, AllCacheLink);
    if (Item4->DnsCache.Timeout == 0) {
      RemoveEntryList (&Item4->AllCacheLink);
      FreePool (Item4->DnsCache.HostName);
      FreePool (Item4->DnsCache.IpAddress);
      FreePool (Item4);
      Entry = mDriverData->Dns4CacheList.ForwardLink;
    } else {
      Entry = Entry->ForwardLink;
    }
  }

  
  
  
  NET_LIST_FOR_EACH_SAFE (Entry, Next, &mDriverData->Dns6CacheList) {
    Item6 = NET_LIST_USER_STRUCT (Entry, DNS6_CACHE, AllCacheLink);
    Item6->DnsCache.Timeout--;
  }

  Entry = mDriverData->Dns6CacheList.ForwardLink;
  while (Entry != &mDriverData->Dns6CacheList) {
    Item6 = NET_LIST_USER_STRUCT (Entry, DNS6_CACHE, AllCacheLink);
    if (Item6->DnsCache.Timeout == 0) {
      RemoveEntryList (&Item6->AllCacheLink);
      FreePool (Item6->DnsCache.HostName);
      FreePool (Item6->DnsCache.IpAddress);
      FreePool (Item6);
      Entry = mDriverData->Dns6CacheList.ForwardLink;
    } else {
      Entry = Entry->ForwardLink;
    }
  }
}

