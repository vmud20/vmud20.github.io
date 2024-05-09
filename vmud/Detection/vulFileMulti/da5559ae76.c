




VOID DumpCapabilityReg ( IN UINT8                Slot, IN SD_MMC_HC_SLOT_CAP   *Capability )



{
  
  
  
  DEBUG ((DEBUG_INFO, " == Slot [%d] Capability is 0x%x ==\n", Slot, Capability));
  DEBUG ((DEBUG_INFO, "   Timeout Clk Freq  %d%a\n", Capability->TimeoutFreq, (Capability->TimeoutUnit) ? "MHz" : "KHz"));
  DEBUG ((DEBUG_INFO, "   Base Clk Freq     %dMHz\n", Capability->BaseClkFreq));
  DEBUG ((DEBUG_INFO, "   Max Blk Len       %dbytes\n", 512 * (1 << Capability->MaxBlkLen)));
  DEBUG ((DEBUG_INFO, "   8-bit Support     %a\n", Capability->BusWidth8 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   ADMA2 Support     %a\n", Capability->Adma2 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   HighSpeed Support %a\n", Capability->HighSpeed ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   SDMA Support      %a\n", Capability->Sdma ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Suspend/Resume    %a\n", Capability->SuspRes ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Voltage 3.3       %a\n", Capability->Voltage33 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Voltage 3.0       %a\n", Capability->Voltage30 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Voltage 1.8       %a\n", Capability->Voltage18 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   V4 64-bit Sys Bus %a\n", Capability->SysBus64V4 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   V3 64-bit Sys Bus %a\n", Capability->SysBus64V3 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Async Interrupt   %a\n", Capability->AsyncInt ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   SlotType          "));
  if (Capability->SlotType == 0x00) {
    DEBUG ((DEBUG_INFO, "%a\n", "Removable Slot"));
  } else if (Capability->SlotType == 0x01) {
    DEBUG ((DEBUG_INFO, "%a\n", "Embedded Slot"));
  } else if (Capability->SlotType == 0x02) {
    DEBUG ((DEBUG_INFO, "%a\n", "Shared Bus Slot"));
  } else {
    DEBUG ((DEBUG_INFO, "%a\n", "Reserved"));
  }
  DEBUG ((DEBUG_INFO, "   SDR50  Support    %a\n", Capability->Sdr50 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   SDR104 Support    %a\n", Capability->Sdr104 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   DDR50  Support    %a\n", Capability->Ddr50 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Driver Type A     %a\n", Capability->DriverTypeA ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Driver Type C     %a\n", Capability->DriverTypeC ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Driver Type D     %a\n", Capability->DriverTypeD ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Driver Type 4     %a\n", Capability->DriverType4 ? "TRUE" : "FALSE"));
  if (Capability->TimerCount == 0) {
    DEBUG ((DEBUG_INFO, "   Retuning TimerCnt Disabled\n", 2 * (Capability->TimerCount - 1)));
  } else {
    DEBUG ((DEBUG_INFO, "   Retuning TimerCnt %dseconds\n", 2 * (Capability->TimerCount - 1)));
  }
  DEBUG ((DEBUG_INFO, "   SDR50 Tuning      %a\n", Capability->TuningSDR50 ? "TRUE" : "FALSE"));
  DEBUG ((DEBUG_INFO, "   Retuning Mode     Mode %d\n", Capability->RetuningMod + 1));
  DEBUG ((DEBUG_INFO, "   Clock Multiplier  M = %d\n", Capability->ClkMultiplier + 1));
  DEBUG ((DEBUG_INFO, "   HS 400            %a\n", Capability->Hs400 ? "TRUE" : "FALSE"));
  return;
}


EFI_STATUS EFIAPI SdMmcHcGetSlotInfo ( IN     EFI_PCI_IO_PROTOCOL   *PciIo, OUT UINT8                 *FirstBar, OUT UINT8                 *SlotNum )





{
  EFI_STATUS                   Status;
  SD_MMC_HC_SLOT_INFO          SlotInfo;

  Status = PciIo->Pci.Read ( PciIo, EfiPciIoWidthUint8, SD_MMC_HC_SLOT_OFFSET, sizeof (SlotInfo), &SlotInfo );





  if (EFI_ERROR (Status)) {
    return Status;
  }

  *FirstBar = SlotInfo.FirstBar;
  *SlotNum  = SlotInfo.SlotNum + 1;
  ASSERT ((*FirstBar + *SlotNum) < SD_MMC_HC_MAX_SLOT);
  return EFI_SUCCESS;
}


EFI_STATUS EFIAPI SdMmcHcRwMmio ( IN     EFI_PCI_IO_PROTOCOL   *PciIo, IN     UINT8                 BarIndex, IN     UINT32                Offset, IN     BOOLEAN               Read, IN     UINT8                 Count, IN OUT VOID                  *Data )








{
  EFI_STATUS                   Status;
  EFI_PCI_IO_PROTOCOL_WIDTH    Width;

  if ((PciIo == NULL) || (Data == NULL))  {
    return EFI_INVALID_PARAMETER;
  }

  switch (Count) {
    case 1:
      Width = EfiPciIoWidthUint8;
      break;
    case 2:
      Width = EfiPciIoWidthUint16;
      Count = 1;
      break;
    case 4:
      Width = EfiPciIoWidthUint32;
      Count = 1;
      break;
    case 8:
      Width = EfiPciIoWidthUint32;
      Count = 2;
      break;
    default:
      return EFI_INVALID_PARAMETER;
  }

  if (Read) {
    Status = PciIo->Mem.Read ( PciIo, Width, BarIndex, (UINT64) Offset, Count, Data );






  } else {
    Status = PciIo->Mem.Write ( PciIo, Width, BarIndex, (UINT64) Offset, Count, Data );






  }

  return Status;
}


EFI_STATUS EFIAPI SdMmcHcOrMmio ( IN  EFI_PCI_IO_PROTOCOL      *PciIo, IN  UINT8                    BarIndex, IN  UINT32                   Offset, IN  UINT8                    Count, IN  VOID                     *OrData )







{
  EFI_STATUS                   Status;
  UINT64                       Data;
  UINT64                       Or;

  Status = SdMmcHcRwMmio (PciIo, BarIndex, Offset, TRUE, Count, &Data);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Count == 1) {
    Or = *(UINT8*) OrData;
  } else if (Count == 2) {
    Or = *(UINT16*) OrData;
  } else if (Count == 4) {
    Or = *(UINT32*) OrData;
  } else if (Count == 8) {
    Or = *(UINT64*) OrData;
  } else {
    return EFI_INVALID_PARAMETER;
  }

  Data  |= Or;
  Status = SdMmcHcRwMmio (PciIo, BarIndex, Offset, FALSE, Count, &Data);

  return Status;
}


EFI_STATUS EFIAPI SdMmcHcAndMmio ( IN  EFI_PCI_IO_PROTOCOL      *PciIo, IN  UINT8                    BarIndex, IN  UINT32                   Offset, IN  UINT8                    Count, IN  VOID                     *AndData )







{
  EFI_STATUS                   Status;
  UINT64                       Data;
  UINT64                       And;

  Status = SdMmcHcRwMmio (PciIo, BarIndex, Offset, TRUE, Count, &Data);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Count == 1) {
    And = *(UINT8*) AndData;
  } else if (Count == 2) {
    And = *(UINT16*) AndData;
  } else if (Count == 4) {
    And = *(UINT32*) AndData;
  } else if (Count == 8) {
    And = *(UINT64*) AndData;
  } else {
    return EFI_INVALID_PARAMETER;
  }

  Data  &= And;
  Status = SdMmcHcRwMmio (PciIo, BarIndex, Offset, FALSE, Count, &Data);

  return Status;
}


EFI_STATUS EFIAPI SdMmcHcCheckMmioSet ( IN  EFI_PCI_IO_PROTOCOL       *PciIo, IN  UINT8                     BarIndex, IN  UINT32                    Offset, IN  UINT8                     Count, IN  UINT64                    MaskValue, IN  UINT64                    TestValue )








{
  EFI_STATUS            Status;
  UINT64                Value;

  
  
  
  Value  = 0;
  Status = SdMmcHcRwMmio (PciIo, BarIndex, Offset, TRUE, Count, &Value);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Value &= MaskValue;

  if (Value == TestValue) {
    return EFI_SUCCESS;
  }

  return EFI_NOT_READY;
}


EFI_STATUS EFIAPI SdMmcHcWaitMmioSet ( IN  EFI_PCI_IO_PROTOCOL       *PciIo, IN  UINT8                     BarIndex, IN  UINT32                    Offset, IN  UINT8                     Count, IN  UINT64                    MaskValue, IN  UINT64                    TestValue, IN  UINT64                    Timeout )









{
  EFI_STATUS            Status;
  BOOLEAN               InfiniteWait;

  if (Timeout == 0) {
    InfiniteWait = TRUE;
  } else {
    InfiniteWait = FALSE;
  }

  while (InfiniteWait || (Timeout > 0)) {
    Status = SdMmcHcCheckMmioSet ( PciIo, BarIndex, Offset, Count, MaskValue, TestValue );






    if (Status != EFI_NOT_READY) {
      return Status;
    }

    
    
    
    gBS->Stall (1);

    Timeout--;
  }

  return EFI_TIMEOUT;
}


EFI_STATUS SdMmcHcGetControllerVersion ( IN     EFI_PCI_IO_PROTOCOL  *PciIo, IN     UINT8                Slot, OUT    UINT16               *Version )




{
  EFI_STATUS                Status;

  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_CTRL_VER, TRUE, sizeof (UINT16), Version);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *Version &= 0xFF;

  return EFI_SUCCESS;
}


EFI_STATUS SdMmcHcReset ( IN SD_MMC_HC_PRIVATE_DATA *Private, IN UINT8                  Slot )



{
  EFI_STATUS                Status;
  UINT8                     SwReset;
  EFI_PCI_IO_PROTOCOL       *PciIo;

  
  
  
  
  if (mOverride != NULL && mOverride->NotifyPhase != NULL) {
    Status = mOverride->NotifyPhase ( Private->ControllerHandle, Slot, EdkiiSdMmcResetPre, NULL);



    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "%a: SD/MMC pre reset notifier callback failed - %r\n", __FUNCTION__, Status));

      return Status;
    }
  }

  PciIo   = Private->PciIo;
  SwReset = BIT0;
  Status  = SdMmcHcOrMmio (PciIo, Slot, SD_MMC_HC_SW_RST, sizeof (SwReset), &SwReset);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "SdMmcHcReset: write SW Reset for All fails: %r\n", Status));
    return Status;
  }

  Status = SdMmcHcWaitMmioSet ( PciIo, Slot, SD_MMC_HC_SW_RST, sizeof (SwReset), BIT0, 0x00, SD_MMC_HC_GENERIC_TIMEOUT );







  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "SdMmcHcReset: reset done with %r\n", Status));
    return Status;
  }

  
  
  
  Status = SdMmcHcEnableInterrupt (PciIo, Slot);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "SdMmcHcReset: SdMmcHcEnableInterrupt done with %r\n", Status));
    return Status;
  }

  
  
  
  
  if (mOverride != NULL && mOverride->NotifyPhase != NULL) {
    Status = mOverride->NotifyPhase ( Private->ControllerHandle, Slot, EdkiiSdMmcResetPost, NULL);



    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "%a: SD/MMC post reset notifier callback failed - %r\n", __FUNCTION__, Status));

    }
  }

  return Status;
}


EFI_STATUS SdMmcHcEnableInterrupt ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot )



{
  EFI_STATUS                Status;
  UINT16                    IntStatus;

  
  
  
  IntStatus = 0xFFFF;
  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_ERR_INT_STS_EN, FALSE, sizeof (IntStatus), &IntStatus);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  
  
  
  IntStatus = 0xFFFF;
  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_NOR_INT_STS_EN, FALSE, sizeof (IntStatus), &IntStatus);

  return Status;
}


EFI_STATUS SdMmcHcGetCapability ( IN     EFI_PCI_IO_PROTOCOL  *PciIo, IN     UINT8                Slot, OUT SD_MMC_HC_SLOT_CAP   *Capability )




{
  EFI_STATUS                Status;
  UINT64                    Cap;

  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_CAP, TRUE, sizeof (Cap), &Cap);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  CopyMem (Capability, &Cap, sizeof (Cap));

  return EFI_SUCCESS;
}


EFI_STATUS SdMmcHcGetMaxCurrent ( IN     EFI_PCI_IO_PROTOCOL  *PciIo, IN     UINT8                Slot, OUT UINT64               *MaxCurrent )




{
  EFI_STATUS          Status;

  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_MAX_CURRENT_CAP, TRUE, sizeof (UINT64), MaxCurrent);

  return Status;
}


EFI_STATUS SdMmcHcCardDetect ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot, OUT BOOLEAN            *MediaPresent )




{
  EFI_STATUS                Status;
  UINT16                    Data;
  UINT32                    PresentState;

  
  
  
  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_PRESENT_STATE, TRUE, sizeof (PresentState), &PresentState);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((PresentState & BIT16) != 0) {
    *MediaPresent = TRUE;
  } else {
    *MediaPresent = FALSE;
  }

  
  
  
  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_NOR_INT_STS, TRUE, sizeof (Data), &Data);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((Data & (BIT6 | BIT7)) != 0) {
    
    
    
    Data  &= BIT6 | BIT7;
    Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_NOR_INT_STS, FALSE, sizeof (Data), &Data);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    return EFI_MEDIA_CHANGED;
  }

  return EFI_SUCCESS;
}


EFI_STATUS SdMmcHcStopClock ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot )



{
  EFI_STATUS                Status;
  UINT32                    PresentState;
  UINT16                    ClockCtrl;

  
  
  
  
  
  Status = SdMmcHcWaitMmioSet ( PciIo, Slot, SD_MMC_HC_PRESENT_STATE, sizeof (PresentState), BIT0 | BIT1, 0, SD_MMC_HC_GENERIC_TIMEOUT );







  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  ClockCtrl = (UINT16)~BIT2;
  Status = SdMmcHcAndMmio (PciIo, Slot, SD_MMC_HC_CLOCK_CTRL, sizeof (ClockCtrl), &ClockCtrl);

  return Status;
}


EFI_STATUS SdMmcHcStartSdClock ( IN EFI_PCI_IO_PROTOCOL  *PciIo, IN UINT8                Slot )



{
  UINT16                    ClockCtrl;

  
  
  
  ClockCtrl = BIT2;
  return SdMmcHcOrMmio (PciIo, Slot, SD_MMC_HC_CLOCK_CTRL, sizeof (ClockCtrl), &ClockCtrl);
}


EFI_STATUS SdMmcHcClockSupply ( IN SD_MMC_HC_PRIVATE_DATA  *Private, IN UINT8                   Slot, IN SD_MMC_BUS_MODE         BusTiming, IN BOOLEAN                 FirstTimeSetup, IN UINT64                  ClockFreq )






{
  EFI_STATUS                Status;
  UINT32                    SettingFreq;
  UINT32                    Divisor;
  UINT32                    Remainder;
  UINT16                    ClockCtrl;
  UINT32                    BaseClkFreq;
  UINT16                    ControllerVer;
  EFI_PCI_IO_PROTOCOL       *PciIo;

  PciIo = Private->PciIo;
  BaseClkFreq = Private->BaseClkFreq[Slot];
  ControllerVer = Private->ControllerVersion[Slot];

  if (BaseClkFreq == 0 || ClockFreq == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (ClockFreq > (BaseClkFreq * 1000)) {
    ClockFreq = BaseClkFreq * 1000;
  }

  
  
  
  Divisor     = 0;
  SettingFreq = BaseClkFreq * 1000;
  while (ClockFreq < SettingFreq) {
    Divisor++;

    SettingFreq = (BaseClkFreq * 1000) / (2 * Divisor);
    Remainder   = (BaseClkFreq * 1000) % (2 * Divisor);
    if ((ClockFreq == SettingFreq) && (Remainder == 0)) {
      break;
    }
    if ((ClockFreq == SettingFreq) && (Remainder != 0)) {
      SettingFreq ++;
    }
  }

  DEBUG ((DEBUG_INFO, "BaseClkFreq %dMHz Divisor %d ClockFreq %dKhz\n", BaseClkFreq, Divisor, ClockFreq));

  
  
  
  if ((ControllerVer >= SD_MMC_HC_CTRL_VER_300) && (ControllerVer <= SD_MMC_HC_CTRL_VER_420)) {
    ASSERT (Divisor <= 0x3FF);
    ClockCtrl = ((Divisor & 0xFF) << 8) | ((Divisor & 0x300) >> 2);
  } else if ((ControllerVer == SD_MMC_HC_CTRL_VER_100) || (ControllerVer == SD_MMC_HC_CTRL_VER_200)) {
    
    
    
    if (((Divisor - 1) & Divisor) != 0) {
      Divisor = 1 << (HighBitSet32 (Divisor) + 1);
    }
    ASSERT (Divisor <= 0x80);
    ClockCtrl = (Divisor & 0xFF) << 8;
  } else {
    DEBUG ((DEBUG_ERROR, "Unknown SD Host Controller Spec version [0x%x]!!!\n", ControllerVer));
    return EFI_UNSUPPORTED;
  }

  
  
  
  Status = SdMmcHcStopClock (PciIo, Slot);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  ClockCtrl |= BIT0;
  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_CLOCK_CTRL, FALSE, sizeof (ClockCtrl), &ClockCtrl);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Set SDCLK Frequency Select and Internal Clock Enable fields fails\n"));
    return Status;
  }

  
  
  
  Status = SdMmcHcWaitMmioSet ( PciIo, Slot, SD_MMC_HC_CLOCK_CTRL, sizeof (ClockCtrl), BIT1, BIT1, SD_MMC_HC_GENERIC_TIMEOUT );







  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SdMmcHcStartSdClock (PciIo, Slot);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  
  
  if (!FirstTimeSetup && mOverride != NULL && mOverride->NotifyPhase != NULL) {
    Status = mOverride->NotifyPhase ( Private->ControllerHandle, Slot, EdkiiSdMmcSwitchClockFreqPost, &BusTiming );




    if (EFI_ERROR (Status)) {
      DEBUG (( DEBUG_ERROR, "%a: SD/MMC switch clock freq post notifier callback failed - %r\n", __FUNCTION__, Status ));




      return Status;
    }
  }

  return Status;
}


EFI_STATUS SdMmcHcPowerControl ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot, IN UINT8                  PowerCtrl )




{
  EFI_STATUS                Status;

  
  
  
  PowerCtrl &= (UINT8)~BIT0;
  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_POWER_CTRL, FALSE, sizeof (PowerCtrl), &PowerCtrl);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  PowerCtrl |= BIT0;
  Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_POWER_CTRL, FALSE, sizeof (PowerCtrl), &PowerCtrl);

  return Status;
}


EFI_STATUS SdMmcHcSetBusWidth ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot, IN UINT16                 BusWidth )




{
  EFI_STATUS                Status;
  UINT8                     HostCtrl1;

  if (BusWidth == 1) {
    HostCtrl1 = (UINT8)~(BIT5 | BIT1);
    Status = SdMmcHcAndMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL1, sizeof (HostCtrl1), &HostCtrl1);
  } else if (BusWidth == 4) {
    Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL1, TRUE, sizeof (HostCtrl1), &HostCtrl1);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    HostCtrl1 |= BIT1;
    HostCtrl1 &= (UINT8)~BIT5;
    Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL1, FALSE, sizeof (HostCtrl1), &HostCtrl1);
  } else if (BusWidth == 8) {
    Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL1, TRUE, sizeof (HostCtrl1), &HostCtrl1);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    HostCtrl1 &= (UINT8)~BIT1;
    HostCtrl1 |= BIT5;
    Status = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL1, FALSE, sizeof (HostCtrl1), &HostCtrl1);
  } else {
    ASSERT (FALSE);
    return EFI_INVALID_PARAMETER;
  }

  return Status;
}


EFI_STATUS SdMmcHcInitV4Enhancements ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot, IN SD_MMC_HC_SLOT_CAP     Capability, IN UINT16                 ControllerVer )





{
  EFI_STATUS                Status;
  UINT16                    HostCtrl2;

  
  
  
  if (ControllerVer >= SD_MMC_HC_CTRL_VER_400) {
    HostCtrl2 = SD_MMC_HC_V4_EN;
    
    
    
    if (ControllerVer == SD_MMC_HC_CTRL_VER_400) {
      
      
      
      if (Capability.SysBus64V3 != 0) {
        HostCtrl2 |= SD_MMC_HC_64_ADDR_EN;
        DEBUG ((DEBUG_INFO, "Enabled V4 64 bit system bus support\n"));
      }
    }
    
    
    
    else if (ControllerVer >= SD_MMC_HC_CTRL_VER_410) {
      
      
      
      if (Capability.SysBus64V4 != 0) {
        HostCtrl2 |= SD_MMC_HC_64_ADDR_EN;
        DEBUG ((DEBUG_INFO, "Enabled V4 64 bit system bus support\n"));
      }
      HostCtrl2 |= SD_MMC_HC_26_DATA_LEN_ADMA_EN;
      DEBUG ((DEBUG_INFO, "Enabled V4 26 bit data length ADMA support\n"));
    }
    Status = SdMmcHcOrMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL2, sizeof (HostCtrl2), &HostCtrl2);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return EFI_SUCCESS;
}


EFI_STATUS SdMmcHcInitPowerVoltage ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot, IN SD_MMC_HC_SLOT_CAP     Capability )




{
  EFI_STATUS                Status;
  UINT8                     MaxVoltage;
  UINT8                     HostCtrl2;

  
  
  
  if (Capability.Voltage33 != 0) {
    
    
    
    MaxVoltage = 0x0E;
  } else if (Capability.Voltage30 != 0) {
    
    
    
    MaxVoltage = 0x0C;
  } else if (Capability.Voltage18 != 0) {
    
    
    
    MaxVoltage = 0x0A;
    HostCtrl2  = BIT3;
    Status = SdMmcHcOrMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL2, sizeof (HostCtrl2), &HostCtrl2);
    gBS->Stall (5000);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else {
    ASSERT (FALSE);
    return EFI_DEVICE_ERROR;
  }

  
  
  
  Status = SdMmcHcPowerControl (PciIo, Slot, MaxVoltage);

  return Status;
}


EFI_STATUS SdMmcHcInitTimeoutCtrl ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot )



{
  EFI_STATUS                Status;
  UINT8                     Timeout;

  Timeout = 0x0E;
  Status  = SdMmcHcRwMmio (PciIo, Slot, SD_MMC_HC_TIMEOUT_CTRL, FALSE, sizeof (Timeout), &Timeout);

  return Status;
}


EFI_STATUS SdMmcHcInitHost ( IN SD_MMC_HC_PRIVATE_DATA *Private, IN UINT8                  Slot )



{
  EFI_STATUS                Status;
  EFI_PCI_IO_PROTOCOL       *PciIo;
  SD_MMC_HC_SLOT_CAP        Capability;

  
  
  
  
  if (mOverride != NULL && mOverride->NotifyPhase != NULL) {
    Status = mOverride->NotifyPhase ( Private->ControllerHandle, Slot, EdkiiSdMmcInitHostPre, NULL);



    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "%a: SD/MMC pre init notifier callback failed - %r\n", __FUNCTION__, Status));

      return Status;
    }
  }

  PciIo = Private->PciIo;
  Capability = Private->Capability[Slot];

  Status = SdMmcHcInitV4Enhancements (PciIo, Slot, Capability, Private->ControllerVersion[Slot]);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  
  
  
  
  Status = SdMmcHcClockSupply (Private, Slot, 0, TRUE, 400);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SdMmcHcInitPowerVoltage (PciIo, Slot, Capability);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SdMmcHcInitTimeoutCtrl (PciIo, Slot);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  
  if (mOverride != NULL && mOverride->NotifyPhase != NULL) {
    Status = mOverride->NotifyPhase ( Private->ControllerHandle, Slot, EdkiiSdMmcInitHostPost, NULL);



    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "%a: SD/MMC post init notifier callback failed - %r\n", __FUNCTION__, Status));

    }
  }
  return Status;
}


EFI_STATUS SdMmcHcUhsSignaling ( IN EFI_HANDLE             ControllerHandle, IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot, IN SD_MMC_BUS_MODE        Timing )





{
  EFI_STATUS                 Status;
  UINT8                      HostCtrl2;

  HostCtrl2 = (UINT8)~SD_MMC_HC_CTRL_UHS_MASK;
  Status = SdMmcHcAndMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL2, sizeof (HostCtrl2), &HostCtrl2);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  switch (Timing) {
    case SdMmcUhsSdr12:
      HostCtrl2 = SD_MMC_HC_CTRL_UHS_SDR12;
      break;
    case SdMmcUhsSdr25:
      HostCtrl2 = SD_MMC_HC_CTRL_UHS_SDR25;
      break;
    case SdMmcUhsSdr50:
      HostCtrl2 = SD_MMC_HC_CTRL_UHS_SDR50;
      break;
    case SdMmcUhsSdr104:
      HostCtrl2 = SD_MMC_HC_CTRL_UHS_SDR104;
      break;
    case SdMmcUhsDdr50:
      HostCtrl2 = SD_MMC_HC_CTRL_UHS_DDR50;
      break;
    case SdMmcMmcLegacy:
      HostCtrl2 = SD_MMC_HC_CTRL_MMC_LEGACY;
      break;
    case SdMmcMmcHsSdr:
      HostCtrl2 = SD_MMC_HC_CTRL_MMC_HS_SDR;
      break;
    case SdMmcMmcHsDdr:
      HostCtrl2 = SD_MMC_HC_CTRL_MMC_HS_DDR;
      break;
    case SdMmcMmcHs200:
      HostCtrl2 = SD_MMC_HC_CTRL_MMC_HS200;
      break;
    case SdMmcMmcHs400:
      HostCtrl2 = SD_MMC_HC_CTRL_MMC_HS400;
      break;
    default:
     HostCtrl2 = 0;
     break;
  }
  Status = SdMmcHcOrMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL2, sizeof (HostCtrl2), &HostCtrl2);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (mOverride != NULL && mOverride->NotifyPhase != NULL) {
    Status = mOverride->NotifyPhase ( ControllerHandle, Slot, EdkiiSdMmcUhsSignaling, &Timing );




    if (EFI_ERROR (Status)) {
      DEBUG (( DEBUG_ERROR, "%a: SD/MMC uhs signaling notifier callback failed - %r\n", __FUNCTION__, Status ));




      return Status;
    }
  }

  return EFI_SUCCESS;
}


EFI_STATUS SdMmcSetDriverStrength ( IN EFI_PCI_IO_PROTOCOL      *PciIo, IN UINT8                    SlotIndex, IN SD_DRIVER_STRENGTH_TYPE  DriverStrength )




{
  EFI_STATUS  Status;
  UINT16      HostCtrl2;

  if (DriverStrength == SdDriverStrengthIgnore) {
    return EFI_SUCCESS;
  }

  HostCtrl2 = (UINT16)~SD_MMC_HC_CTRL_DRIVER_STRENGTH_MASK;
  Status = SdMmcHcAndMmio (PciIo, SlotIndex, SD_MMC_HC_HOST_CTRL2, sizeof (HostCtrl2), &HostCtrl2);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  HostCtrl2 = (DriverStrength << 4) & SD_MMC_HC_CTRL_DRIVER_STRENGTH_MASK;
  return SdMmcHcOrMmio (PciIo, SlotIndex, SD_MMC_HC_HOST_CTRL2, sizeof (HostCtrl2), &HostCtrl2);
}


EFI_STATUS SdMmcHcLedOnOff ( IN EFI_PCI_IO_PROTOCOL    *PciIo, IN UINT8                  Slot, IN BOOLEAN                On )




{
  EFI_STATUS                Status;
  UINT8                     HostCtrl1;

  if (On) {
    HostCtrl1 = BIT0;
    Status    = SdMmcHcOrMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL1, sizeof (HostCtrl1), &HostCtrl1);
  } else {
    HostCtrl1 = (UINT8)~BIT0;
    Status    = SdMmcHcAndMmio (PciIo, Slot, SD_MMC_HC_HOST_CTRL1, sizeof (HostCtrl1), &HostCtrl1);
  }

  return Status;
}


EFI_STATUS BuildAdmaDescTable ( IN SD_MMC_HC_TRB          *Trb, IN UINT16                 ControllerVer )



{
  EFI_PHYSICAL_ADDRESS      Data;
  UINT64                    DataLen;
  UINT64                    Entries;
  UINT32                    Index;
  UINT64                    Remaining;
  UINT64                    Address;
  UINTN                     TableSize;
  EFI_PCI_IO_PROTOCOL       *PciIo;
  EFI_STATUS                Status;
  UINTN                     Bytes;
  UINT32                    AdmaMaxDataPerLine;
  UINT32                    DescSize;
  VOID                      *AdmaDesc;

  AdmaMaxDataPerLine = ADMA_MAX_DATA_PER_LINE_16B;
  DescSize           = sizeof (SD_MMC_HC_ADMA_32_DESC_LINE);
  AdmaDesc           = NULL;

  Data    = Trb->DataPhy;
  DataLen = Trb->DataLen;
  PciIo   = Trb->Private->PciIo;

  
  
  
  if ((Trb->Mode == SdMmcAdma32bMode) && ((Data >= 0x100000000ul) || ((Data + DataLen) > 0x100000000ul))) {
    return EFI_INVALID_PARAMETER;
  }
  
  
  
  if (Trb->Mode != SdMmcAdma32bMode) {
    
    
    
    if ((Data & (BIT0 | BIT1 | BIT2)) != 0) {
      DEBUG ((DEBUG_INFO, "The buffer [0x%x] to construct ADMA desc is not aligned to 8 bytes boundary!\n", Data));
    }
  } else {
    
    
    
    if ((Data & (BIT0 | BIT1)) != 0) {
      DEBUG ((DEBUG_INFO, "The buffer [0x%x] to construct ADMA desc is not aligned to 4 bytes boundary!\n", Data));
    }
  }

  
  
  
  if (Trb->Mode == SdMmcAdma64bV3Mode) {
    DescSize = sizeof (SD_MMC_HC_ADMA_64_V3_DESC_LINE);
  }else if (Trb->Mode == SdMmcAdma64bV4Mode) {
    DescSize = sizeof (SD_MMC_HC_ADMA_64_V4_DESC_LINE);
  }
  
  
  
  if (Trb->AdmaLengthMode == SdMmcAdmaLen26b) {
    AdmaMaxDataPerLine = ADMA_MAX_DATA_PER_LINE_26B;
  }

  Entries   = DivU64x32 ((DataLen + AdmaMaxDataPerLine - 1), AdmaMaxDataPerLine);
  TableSize = (UINTN)MultU64x32 (Entries, DescSize);
  Trb->AdmaPages = (UINT32)EFI_SIZE_TO_PAGES (TableSize);
  Status = PciIo->AllocateBuffer ( PciIo, AllocateAnyPages, EfiBootServicesData, EFI_SIZE_TO_PAGES (TableSize), (VOID **)&AdmaDesc, 0 );






  if (EFI_ERROR (Status)) {
    return EFI_OUT_OF_RESOURCES;
  }
  ZeroMem (AdmaDesc, TableSize);
  Bytes  = TableSize;
  Status = PciIo->Map ( PciIo, EfiPciIoOperationBusMasterCommonBuffer, AdmaDesc, &Bytes, &Trb->AdmaDescPhy, &Trb->AdmaMap );







  if (EFI_ERROR (Status) || (Bytes != TableSize)) {
    
    
    
    PciIo->FreeBuffer ( PciIo, EFI_SIZE_TO_PAGES (TableSize), AdmaDesc );



    return EFI_OUT_OF_RESOURCES;
  }

  if ((Trb->Mode == SdMmcAdma32bMode) && (UINT64)(UINTN)Trb->AdmaDescPhy > 0x100000000ul) {
    
    
    
    PciIo->Unmap ( PciIo, Trb->AdmaMap );


    PciIo->FreeBuffer ( PciIo, EFI_SIZE_TO_PAGES (TableSize), AdmaDesc );



    return EFI_DEVICE_ERROR;
  }

  Remaining = DataLen;
  Address   = Data;
  if (Trb->Mode == SdMmcAdma32bMode) {
    Trb->Adma32Desc = AdmaDesc;
  } else if (Trb->Mode == SdMmcAdma64bV3Mode) {
    Trb->Adma64V3Desc = AdmaDesc;
  } else {
    Trb->Adma64V4Desc = AdmaDesc;
  }

  for (Index = 0; Index < Entries; Index++) {
    if (Trb->Mode == SdMmcAdma32bMode) {
      if (Remaining <= AdmaMaxDataPerLine) {
        Trb->Adma32Desc[Index].Valid = 1;
        Trb->Adma32Desc[Index].Act   = 2;
        if (Trb->AdmaLengthMode == SdMmcAdmaLen26b) {
          Trb->Adma32Desc[Index].UpperLength = (UINT16)RShiftU64 (Remaining, 16);
        }
        Trb->Adma32Desc[Index].LowerLength = (UINT16)(Remaining & MAX_UINT16);
        Trb->Adma32Desc[Index].Address = (UINT32)Address;
        break;
      } else {
        Trb->Adma32Desc[Index].Valid = 1;
        Trb->Adma32Desc[Index].Act   = 2;
        if (Trb->AdmaLengthMode == SdMmcAdmaLen26b) {
          Trb->Adma32Desc[Index].UpperLength  = 0;
        }
        Trb->Adma32Desc[Index].LowerLength  = 0;
        Trb->Adma32Desc[Index].Address = (UINT32)Address;
      }
    } else if (Trb->Mode == SdMmcAdma64bV3Mode) {
      if (Remaining <= AdmaMaxDataPerLine) {
        Trb->Adma64V3Desc[Index].Valid = 1;
        Trb->Adma64V3Desc[Index].Act   = 2;
        if (Trb->AdmaLengthMode == SdMmcAdmaLen26b) {
          Trb->Adma64V3Desc[Index].UpperLength  = (UINT16)RShiftU64 (Remaining, 16);
        }
        Trb->Adma64V3Desc[Index].LowerLength  = (UINT16)(Remaining & MAX_UINT16);
        Trb->Adma64V3Desc[Index].LowerAddress = (UINT32)Address;
        Trb->Adma64V3Desc[Index].UpperAddress = (UINT32)RShiftU64 (Address, 32);
        break;
      } else {
        Trb->Adma64V3Desc[Index].Valid = 1;
        Trb->Adma64V3Desc[Index].Act   = 2;
        if (Trb->AdmaLengthMode == SdMmcAdmaLen26b) {
          Trb->Adma64V3Desc[Index].UpperLength  = 0;
        }
        Trb->Adma64V3Desc[Index].LowerLength  = 0;
        Trb->Adma64V3Desc[Index].LowerAddress = (UINT32)Address;
        Trb->Adma64V3Desc[Index].UpperAddress = (UINT32)RShiftU64 (Address, 32);
      }
    } else {
      if (Remaining <= AdmaMaxDataPerLine) {
        Trb->Adma64V4Desc[Index].Valid = 1;
        Trb->Adma64V4Desc[Index].Act   = 2;
        if (Trb->AdmaLengthMode == SdMmcAdmaLen26b) {
          Trb->Adma64V4Desc[Index].UpperLength  = (UINT16)RShiftU64 (Remaining, 16);
        }
        Trb->Adma64V4Desc[Index].LowerLength  = (UINT16)(Remaining & MAX_UINT16);
        Trb->Adma64V4Desc[Index].LowerAddress = (UINT32)Address;
        Trb->Adma64V4Desc[Index].UpperAddress = (UINT32)RShiftU64 (Address, 32);
        break;
      } else {
        Trb->Adma64V4Desc[Index].Valid = 1;
        Trb->Adma64V4Desc[Index].Act   = 2;
        if (Trb->AdmaLengthMode == SdMmcAdmaLen26b) {
          Trb->Adma64V4Desc[Index].UpperLength  = 0;
        }
        Trb->Adma64V4Desc[Index].LowerLength  = 0;
        Trb->Adma64V4Desc[Index].LowerAddress = (UINT32)Address;
        Trb->Adma64V4Desc[Index].UpperAddress = (UINT32)RShiftU64 (Address, 32);
      }
    }

    Remaining -= AdmaMaxDataPerLine;
    Address   += AdmaMaxDataPerLine;
  }

  
  
  
  if (Trb->Mode == SdMmcAdma32bMode) {
    Trb->Adma32Desc[Index].End = 1;
  } else if (Trb->Mode == SdMmcAdma64bV3Mode) {
    Trb->Adma64V3Desc[Index].End = 1;
  } else {
    Trb->Adma64V4Desc[Index].End = 1;
  }
  return EFI_SUCCESS;
}


SD_MMC_HC_TRB * SdMmcCreateTrb ( IN SD_MMC_HC_PRIVATE_DATA              *Private, IN UINT8                               Slot, IN EFI_SD_MMC_PASS_THRU_COMMAND_PACKET *Packet, IN EFI_EVENT                           Event )





{
  SD_MMC_HC_TRB                 *Trb;
  EFI_STATUS                    Status;
  EFI_TPL                       OldTpl;
  EFI_PCI_IO_PROTOCOL_OPERATION Flag;
  EFI_PCI_IO_PROTOCOL           *PciIo;
  UINTN                         MapLength;

  Trb = AllocateZeroPool (sizeof (SD_MMC_HC_TRB));
  if (Trb == NULL) {
    return NULL;
  }

  Trb->Signature = SD_MMC_HC_TRB_SIG;
  Trb->Slot      = Slot;
  Trb->BlockSize = 0x200;
  Trb->Packet    = Packet;
  Trb->Event     = Event;
  Trb->Started   = FALSE;
  Trb->Timeout   = Packet->Timeout;
  Trb->Retries   = SD_MMC_TRB_RETRIES;
  Trb->Private   = Private;

  if ((Packet->InTransferLength != 0) && (Packet->InDataBuffer != NULL)) {
    Trb->Data    = Packet->InDataBuffer;
    Trb->DataLen = Packet->InTransferLength;
    Trb->Read    = TRUE;
  } else if ((Packet->OutTransferLength != 0) && (Packet->OutDataBuffer != NULL)) {
    Trb->Data    = Packet->OutDataBuffer;
    Trb->DataLen = Packet->OutTransferLength;
    Trb->Read    = FALSE;
  } else if ((Packet->InTransferLength == 0) && (Packet->OutTransferLength == 0)) {
    Trb->Data    = NULL;
    Trb->DataLen = 0;
  } else {
    goto Error;
  }

  if ((Trb->DataLen != 0) && (Trb->DataLen < Trb->BlockSize)) {
    Trb->BlockSize = (UINT16)Trb->DataLen;
  }

  if (((Private->Slot[Trb->Slot].CardType == EmmcCardType) && (Packet->SdMmcCmdBlk->CommandIndex == EMMC_SEND_TUNING_BLOCK)) || ((Private->Slot[Trb->Slot].CardType == SdCardType) && (Packet->SdMmcCmdBlk->CommandIndex == SD_SEND_TUNING_BLOCK))) {


    Trb->Mode = SdMmcPioMode;
  } else {
    if (Trb->Read) {
      Flag = EfiPciIoOperationBusMasterWrite;
    } else {
      Flag = EfiPciIoOperationBusMasterRead;
    }

    PciIo = Private->PciIo;
    if (Trb->DataLen != 0) {
      MapLength = Trb->DataLen;
      Status = PciIo->Map ( PciIo, Flag, Trb->Data, &MapLength, &Trb->DataPhy, &Trb->DataMap );






      if (EFI_ERROR (Status) || (Trb->DataLen != MapLength)) {
        Status = EFI_BAD_BUFFER_SIZE;
        goto Error;
      }
    }

    if (Trb->DataLen == 0) {
      Trb->Mode = SdMmcNoData;
    } else if (Private->Capability[Slot].Adma2 != 0) {
      Trb->Mode = SdMmcAdma32bMode;
      Trb->AdmaLengthMode = SdMmcAdmaLen16b;
      if ((Private->ControllerVersion[Slot] == SD_MMC_HC_CTRL_VER_300) && (Private->Capability[Slot].SysBus64V3 == 1)) {
        Trb->Mode = SdMmcAdma64bV3Mode;
      } else if (((Private->ControllerVersion[Slot] == SD_MMC_HC_CTRL_VER_400) && (Private->Capability[Slot].SysBus64V3 == 1)) || ((Private->ControllerVersion[Slot] >= SD_MMC_HC_CTRL_VER_410) && (Private->Capability[Slot].SysBus64V4 == 1))) {


        Trb->Mode = SdMmcAdma64bV4Mode;
      }
      if (Private->ControllerVersion[Slot] >= SD_MMC_HC_CTRL_VER_410) {
        Trb->AdmaLengthMode = SdMmcAdmaLen26b;
      }
      Status = BuildAdmaDescTable (Trb, Private->ControllerVersion[Slot]);
      if (EFI_ERROR (Status)) {
        PciIo->Unmap (PciIo, Trb->DataMap);
        goto Error;
      }
    } else if (Private->Capability[Slot].Sdma != 0) {
      Trb->Mode = SdMmcSdmaMode;
    } else {
      Trb->Mode = SdMmcPioMode;
    }
  }

  if (Event != NULL) {
    OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
    InsertTailList (&Private->Queue, &Trb->TrbList);
    gBS->RestoreTPL (OldTpl);
  }

  return Trb;

Error:
  SdMmcFreeTrb (Trb);
  return NULL;
}


VOID SdMmcFreeTrb ( IN SD_MMC_HC_TRB           *Trb )


{
  EFI_PCI_IO_PROTOCOL        *PciIo;

  PciIo = Trb->Private->PciIo;

  if (Trb->AdmaMap != NULL) {
    PciIo->Unmap ( PciIo, Trb->AdmaMap );


  }
  if (Trb->Adma32Desc != NULL) {
    PciIo->FreeBuffer ( PciIo, Trb->AdmaPages, Trb->Adma32Desc );



  }
  if (Trb->Adma64V3Desc != NULL) {
    PciIo->FreeBuffer ( PciIo, Trb->AdmaPages, Trb->Adma64V3Desc );



  }
  if (Trb->Adma64V4Desc != NULL) {
    PciIo->FreeBuffer ( PciIo, Trb->AdmaPages, Trb->Adma64V4Desc );



  }
  if (Trb->DataMap != NULL) {
    PciIo->Unmap ( PciIo, Trb->DataMap );


  }
  FreePool (Trb);
  return;
}


EFI_STATUS SdMmcCheckTrbEnv ( IN SD_MMC_HC_PRIVATE_DATA           *Private, IN SD_MMC_HC_TRB                    *Trb )



{
  EFI_STATUS                          Status;
  EFI_SD_MMC_PASS_THRU_COMMAND_PACKET *Packet;
  EFI_PCI_IO_PROTOCOL                 *PciIo;
  UINT32                              PresentState;

  Packet = Trb->Packet;

  if ((Packet->SdMmcCmdBlk->CommandType == SdMmcCommandTypeAdtc) || (Packet->SdMmcCmdBlk->ResponseType == SdMmcResponseTypeR1b) || (Packet->SdMmcCmdBlk->ResponseType == SdMmcResponseTypeR5b)) {

    
    
    
    
    PresentState = BIT0 | BIT1;
  } else {
    
    
    
    
    PresentState = BIT0;
  }

  PciIo  = Private->PciIo;
  Status = SdMmcHcCheckMmioSet ( PciIo, Trb->Slot, SD_MMC_HC_PRESENT_STATE, sizeof (PresentState), PresentState, 0 );







  return Status;
}


EFI_STATUS SdMmcWaitTrbEnv ( IN SD_MMC_HC_PRIVATE_DATA           *Private, IN SD_MMC_HC_TRB                    *Trb )



{
  EFI_STATUS                          Status;
  EFI_SD_MMC_PASS_THRU_COMMAND_PACKET *Packet;
  UINT64                              Timeout;
  BOOLEAN                             InfiniteWait;

  
  
  
  Packet  = Trb->Packet;
  Timeout = Packet->Timeout;
  if (Timeout == 0) {
    InfiniteWait = TRUE;
  } else {
    InfiniteWait = FALSE;
  }

  while (InfiniteWait || (Timeout > 0)) {
    
    
    
    Status = SdMmcCheckTrbEnv (Private, Trb);
    if (Status != EFI_NOT_READY) {
      return Status;
    }
    
    
    
    gBS->Stall (1);

    Timeout--;
  }

  return EFI_TIMEOUT;
}


EFI_STATUS SdMmcExecTrb ( IN SD_MMC_HC_PRIVATE_DATA           *Private, IN SD_MMC_HC_TRB                    *Trb )



{
  EFI_STATUS                          Status;
  EFI_SD_MMC_PASS_THRU_COMMAND_PACKET *Packet;
  EFI_PCI_IO_PROTOCOL                 *PciIo;
  UINT16                              Cmd;
  UINT16                              IntStatus;
  UINT32                              Argument;
  UINT32                              BlkCount;
  UINT16                              BlkSize;
  UINT16                              TransMode;
  UINT8                               HostCtrl1;
  UINT64                              SdmaAddr;
  UINT64                              AdmaAddr;
  BOOLEAN                             AddressingMode64;

  AddressingMode64 = FALSE;

  Packet = Trb->Packet;
  PciIo  = Trb->Private->PciIo;
  
  
  
  IntStatus = 0xFFFF;
  Status    = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_ERR_INT_STS, FALSE, sizeof (IntStatus), &IntStatus);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  
  
  
  IntStatus = 0xFF3F;
  Status    = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_NOR_INT_STS, FALSE, sizeof (IntStatus), &IntStatus);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Private->ControllerVersion[Trb->Slot] >= SD_MMC_HC_CTRL_VER_400) {
    Status = SdMmcHcCheckMmioSet(PciIo, Trb->Slot, SD_MMC_HC_HOST_CTRL2, sizeof(UINT16), SD_MMC_HC_64_ADDR_EN, SD_MMC_HC_64_ADDR_EN);
    if (!EFI_ERROR (Status)) {
      AddressingMode64 = TRUE;
    }
  }

  
  
  
  if ((Trb->Mode == SdMmcAdma32bMode) || (Trb->Mode == SdMmcAdma64bV4Mode)) {
    HostCtrl1 = BIT4;
    Status = SdMmcHcOrMmio (PciIo, Trb->Slot, SD_MMC_HC_HOST_CTRL1, sizeof (HostCtrl1), &HostCtrl1);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if (Trb->Mode == SdMmcAdma64bV3Mode) {
    HostCtrl1 = BIT4|BIT3;
    Status = SdMmcHcOrMmio (PciIo, Trb->Slot, SD_MMC_HC_HOST_CTRL1, sizeof (HostCtrl1), &HostCtrl1);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  SdMmcHcLedOnOff (PciIo, Trb->Slot, TRUE);

  if (Trb->Mode == SdMmcSdmaMode) {
    if ((!AddressingMode64) && ((UINT64)(UINTN)Trb->DataPhy >= 0x100000000ul)) {
      return EFI_INVALID_PARAMETER;
    }

    SdmaAddr = (UINT64)(UINTN)Trb->DataPhy;

    if (Private->ControllerVersion[Trb->Slot] >= SD_MMC_HC_CTRL_VER_400) {
      Status = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_ADMA_SYS_ADDR, FALSE, sizeof (UINT64), &SdmaAddr);
    } else {
      Status = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_SDMA_ADDR, FALSE, sizeof (UINT32), &SdmaAddr);
    }

    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if ((Trb->Mode == SdMmcAdma32bMode) || (Trb->Mode == SdMmcAdma64bV3Mode) || (Trb->Mode == SdMmcAdma64bV4Mode)) {

    AdmaAddr = (UINT64)(UINTN)Trb->AdmaDescPhy;
    Status   = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_ADMA_SYS_ADDR, FALSE, sizeof (AdmaAddr), &AdmaAddr);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  BlkSize = Trb->BlockSize;
  if (Trb->Mode == SdMmcSdmaMode) {
    
    
    
    BlkSize |= 0x7000;
  }

  Status = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_BLK_SIZE, FALSE, sizeof (BlkSize), &BlkSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  BlkCount = 0;
  if (Trb->Mode != SdMmcNoData) {
    
    
    
    BlkCount = (Trb->DataLen / Trb->BlockSize);
  }
  if (Private->ControllerVersion[Trb->Slot] >= SD_MMC_HC_CTRL_VER_410) {
    Status = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_SDMA_ADDR, FALSE, sizeof (UINT32), &BlkCount);
  } else {
    Status = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_BLK_COUNT, FALSE, sizeof (UINT16), &BlkCount);
  }
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Argument = Packet->SdMmcCmdBlk->CommandArgument;
  Status   = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_ARG1, FALSE, sizeof (Argument), &Argument);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  TransMode = 0;
  if (Trb->Mode != SdMmcNoData) {
    if (Trb->Mode != SdMmcPioMode) {
      TransMode |= BIT0;
    }
    if (Trb->Read) {
      TransMode |= BIT4;
    }
    if (BlkCount > 1) {
      TransMode |= BIT5 | BIT1;
    }
    
    
    
    if (Private->Slot[Trb->Slot].CardType == SdCardType) {
      if (BlkCount > 1) {
        TransMode |= BIT2;
      }
    }
  }

  Status = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_TRANS_MOD, FALSE, sizeof (TransMode), &TransMode);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Cmd = (UINT16)LShiftU64(Packet->SdMmcCmdBlk->CommandIndex, 8);
  if (Packet->SdMmcCmdBlk->CommandType == SdMmcCommandTypeAdtc) {
    Cmd |= BIT5;
  }
  
  
  
  if (Packet->SdMmcCmdBlk->CommandType != SdMmcCommandTypeBc) {
    switch (Packet->SdMmcCmdBlk->ResponseType) {
      case SdMmcResponseTypeR1:
      case SdMmcResponseTypeR5:
      case SdMmcResponseTypeR6:
      case SdMmcResponseTypeR7:
        Cmd |= (BIT1 | BIT3 | BIT4);
        break;
      case SdMmcResponseTypeR2:
        Cmd |= (BIT0 | BIT3);
       break;
      case SdMmcResponseTypeR3:
      case SdMmcResponseTypeR4:
        Cmd |= BIT1;
        break;
      case SdMmcResponseTypeR1b:
      case SdMmcResponseTypeR5b:
        Cmd |= (BIT0 | BIT1 | BIT3 | BIT4);
        break;
      default:
        ASSERT (FALSE);
        break;
    }
  }
  
  
  
  Status = SdMmcHcRwMmio (PciIo, Trb->Slot, SD_MMC_HC_COMMAND, FALSE, sizeof (Cmd), &Cmd);
  return Status;
}


EFI_STATUS SdMmcSoftwareReset ( IN SD_MMC_HC_PRIVATE_DATA  *Private, IN UINT8                   Slot, IN UINT16                  ErrIntStatus )




{
  UINT8       SwReset;
  EFI_STATUS  Status;

  SwReset = 0;
  if ((ErrIntStatus & 0x0F) != 0) {
    SwReset |= BIT1;
  }
  if ((ErrIntStatus & 0x70) != 0) {
    SwReset |= BIT2;
  }

  Status  = SdMmcHcRwMmio ( Private->PciIo, Slot, SD_MMC_HC_SW_RST, FALSE, sizeof (SwReset), &SwReset );






  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SdMmcHcWaitMmioSet ( Private->PciIo, Slot, SD_MMC_HC_SW_RST, sizeof (SwReset), 0xFF, 0, SD_MMC_HC_GENERIC_TIMEOUT );







  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}


EFI_STATUS SdMmcCheckAndRecoverErrors ( IN SD_MMC_HC_PRIVATE_DATA  *Private, IN UINT8                   Slot, IN UINT16                  IntStatus )




{
  UINT16      ErrIntStatus;
  EFI_STATUS  Status;
  EFI_STATUS  ErrorStatus;

  if ((IntStatus & BIT15) == 0) {
    return EFI_SUCCESS;
  }

  Status = SdMmcHcRwMmio ( Private->PciIo, Slot, SD_MMC_HC_ERR_INT_STS, TRUE, sizeof (ErrIntStatus), &ErrIntStatus );






  if (EFI_ERROR (Status)) {
    return Status;
  }

  
  
  
  
  
  
  
  
  
  if (((ErrIntStatus & BIT4) != 0) && ((IntStatus & BIT1) != 0)) {
    return EFI_SUCCESS;
  }

  
  
  
  
  
  
  
  if ((ErrIntStatus & (BIT1 | BIT2 | BIT5 | BIT6)) != 0) {
    ErrorStatus = EFI_CRC_ERROR;
  } else {
    ErrorStatus = EFI_DEVICE_ERROR;
  }

  Status = SdMmcSoftwareReset (Private, Slot, ErrIntStatus);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return ErrorStatus;
}


EFI_STATUS SdMmcCheckTrbResult ( IN SD_MMC_HC_PRIVATE_DATA           *Private, IN SD_MMC_HC_TRB                    *Trb )



{
  EFI_STATUS                          Status;
  EFI_SD_MMC_PASS_THRU_COMMAND_PACKET *Packet;
  UINT16                              IntStatus;
  UINT32                              Response[4];
  UINT64                              SdmaAddr;
  UINT8                               Index;
  UINT32                              PioLength;

  Packet  = Trb->Packet;
  
  
  
  Status = SdMmcHcRwMmio ( Private->PciIo, Trb->Slot, SD_MMC_HC_NOR_INT_STS, TRUE, sizeof (IntStatus), &IntStatus );






  if (EFI_ERROR (Status)) {
    goto Done;
  }

  
  
  
  
  Status = SdMmcCheckAndRecoverErrors (Private, Trb->Slot, IntStatus);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  
  
  
  if ((IntStatus & BIT1) == BIT1) {
    goto Done;
  }

  
  
  
  if ((Trb->Mode == SdMmcSdmaMode) && ((IntStatus & BIT3) == BIT3)) {
    
    
    
    IntStatus = BIT3;
    Status    = SdMmcHcRwMmio ( Private->PciIo, Trb->Slot, SD_MMC_HC_NOR_INT_STS, FALSE, sizeof (IntStatus), &IntStatus );






    if (EFI_ERROR (Status)) {
      goto Done;
    }
    
    
    
    SdmaAddr = SD_MMC_SDMA_ROUND_UP ((UINTN)Trb->DataPhy, SD_MMC_SDMA_BOUNDARY);

    if (Private->ControllerVersion[Trb->Slot] >= SD_MMC_HC_CTRL_VER_400) {
      Status = SdMmcHcRwMmio ( Private->PciIo, Trb->Slot, SD_MMC_HC_ADMA_SYS_ADDR, FALSE, sizeof (UINT64), &SdmaAddr );






    } else {
      Status = SdMmcHcRwMmio ( Private->PciIo, Trb->Slot, SD_MMC_HC_SDMA_ADDR, FALSE, sizeof (UINT32), &SdmaAddr );






    }

    if (EFI_ERROR (Status)) {
      goto Done;
    }
    Trb->DataPhy = (UINT64)(UINTN)SdmaAddr;
  }

  if ((Packet->SdMmcCmdBlk->CommandType != SdMmcCommandTypeAdtc) && (Packet->SdMmcCmdBlk->ResponseType != SdMmcResponseTypeR1b) && (Packet->SdMmcCmdBlk->ResponseType != SdMmcResponseTypeR5b)) {

    if ((IntStatus & BIT0) == BIT0) {
      Status = EFI_SUCCESS;
      goto Done;
    }
  }

  if (((Private->Slot[Trb->Slot].CardType == EmmcCardType) && (Packet->SdMmcCmdBlk->CommandIndex == EMMC_SEND_TUNING_BLOCK)) || ((Private->Slot[Trb->Slot].CardType == SdCardType) && (Packet->SdMmcCmdBlk->CommandIndex == SD_SEND_TUNING_BLOCK))) {


    
    
    
    
    
    if ((IntStatus & BIT5) == BIT5) {
      
      
      
      IntStatus = BIT5;
      SdMmcHcRwMmio (Private->PciIo, Trb->Slot, SD_MMC_HC_NOR_INT_STS, FALSE, sizeof (IntStatus), &IntStatus);
      
      
      
      for (PioLength = 0; PioLength < Trb->DataLen; PioLength += 4) {
        SdMmcHcRwMmio (Private->PciIo, Trb->Slot, SD_MMC_HC_BUF_DAT_PORT, TRUE, 4, (UINT8*)Trb->Data + PioLength);
      }
      Status = EFI_SUCCESS;
      goto Done;
    }
  }

  Status = EFI_NOT_READY;
Done:
  
  
  
  if (!EFI_ERROR (Status)) {
    if (Packet->SdMmcCmdBlk->CommandType != SdMmcCommandTypeBc) {
      for (Index = 0; Index < 4; Index++) {
        Status = SdMmcHcRwMmio ( Private->PciIo, Trb->Slot, SD_MMC_HC_RESPONSE + Index * 4, TRUE, sizeof (UINT32), &Response[Index] );






        if (EFI_ERROR (Status)) {
          SdMmcHcLedOnOff (Private->PciIo, Trb->Slot, FALSE);
          return Status;
        }
      }
      CopyMem (Packet->SdMmcStatusBlk, Response, sizeof (Response));
    }
  }

  if (Status != EFI_NOT_READY) {
    SdMmcHcLedOnOff (Private->PciIo, Trb->Slot, FALSE);
  }

  return Status;
}


EFI_STATUS SdMmcWaitTrbResult ( IN SD_MMC_HC_PRIVATE_DATA           *Private, IN SD_MMC_HC_TRB                    *Trb )



{
  EFI_STATUS                          Status;
  EFI_SD_MMC_PASS_THRU_COMMAND_PACKET *Packet;
  UINT64                              Timeout;
  BOOLEAN                             InfiniteWait;

  Packet = Trb->Packet;
  
  
  
  Timeout = Packet->Timeout;
  if (Timeout == 0) {
    InfiniteWait = TRUE;
  } else {
    InfiniteWait = FALSE;
  }

  while (InfiniteWait || (Timeout > 0)) {
    
    
    
    Status = SdMmcCheckTrbResult (Private, Trb);
    if (Status != EFI_NOT_READY) {
      return Status;
    }
    
    
    
    gBS->Stall (1);

    Timeout--;
  }

  return EFI_TIMEOUT;
}

