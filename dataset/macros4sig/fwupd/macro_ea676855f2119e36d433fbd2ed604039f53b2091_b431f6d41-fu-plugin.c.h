



#include<fcntl.h>








#include<string.h>









#include<unistd.h>


#include<errno.h>


#define FU_TYPE_SECURITY_ATTR (fu_security_attr_get_type())
#define FU_CONTEXT_FLAG_NONE (0u)
#define FU_CONTEXT_FLAG_SAVE_EVENTS (1u << 0)
#define FU_TYPE_CONTEXT (fu_context_get_type())
#define FU_TYPE_FIRMWARE_ATTRS (fu_bios_settings_get_type())
#define FWUPD_BIOS_SETTING_PENDING_REBOOT "pending_reboot"
#define FWUPD_TYPE_BIOS_SETTING (fwupd_bios_setting_get_type())
#define FWUPD_TYPE_SECURITY_ATTR (fwupd_security_attr_get_type())
#define FU_TYPE_SECURITY_ATTRS (fu_security_attrs_get_type())
#define FU_TYPE_PLUGIN (fu_plugin_get_type())
#define fu_plugin_add_flag(p, f)    fwupd_plugin_add_flag(FWUPD_PLUGIN(p), f)
#define fu_plugin_get_flags(p)	    fwupd_plugin_get_flags(FWUPD_PLUGIN(p))
#define fu_plugin_has_flag(p, f)    fwupd_plugin_has_flag(FWUPD_PLUGIN(p), f)
#define fu_plugin_remove_flag(p, f) fwupd_plugin_remove_flag(FWUPD_PLUGIN(p), f)
#define FWUPD_TYPE_PLUGIN (fwupd_plugin_get_type())
#define FWUPD_DBUS_INTERFACE "org.freedesktop.fwupd"
#define FWUPD_DBUS_P2P_SOCKET_ADDRESS "tcp:host=localhost,port=1341"
#define FWUPD_DBUS_PATH "/"
#define FWUPD_DBUS_SERVICE "org.freedesktop.fwupd"
#define FWUPD_DEVICE_ID_ANY "*"
#define FU_TYPE_UDEV_DEVICE (fu_udev_device_get_type())
#define G_UDEV_TYPE_DEVICE G_TYPE_OBJECT
#define FU_TYPE_USB_DEVICE (fu_usb_device_get_type())
#define GUsbContext GObject
#define GUsbDevice  GObject
#define G_USB_CHECK_VERSION(a, c, b) 0
#define FU_QUIRKS_ACQUIESCE_DELAY "AcquiesceDelay"
#define FU_QUIRKS_BATTERY_THRESHOLD "BatteryThreshold"
#define FU_QUIRKS_BRANCH "Branch"
#define FU_QUIRKS_CFI_DEVICE_BLOCK_SIZE "CfiDeviceBlockSize"
#define FU_QUIRKS_CFI_DEVICE_CMD_BLOCK_ERASE "CfiDeviceCmdBlockErase"
#define FU_QUIRKS_CFI_DEVICE_CMD_CHIP_ERASE "CfiDeviceCmdChipErase"
#define FU_QUIRKS_CFI_DEVICE_CMD_PAGE_PROG "CfiDeviceCmdPageProg"
#define FU_QUIRKS_CFI_DEVICE_CMD_READ_DATA "CfiDeviceCmdReadData"
#define FU_QUIRKS_CFI_DEVICE_CMD_READ_ID "CfiDeviceCmdReadId"
#define FU_QUIRKS_CFI_DEVICE_CMD_READ_ID_SZ "CfiDeviceCmdReadIdSz"
#define FU_QUIRKS_CFI_DEVICE_CMD_READ_STATUS "CfiDeviceCmdReadStatus"
#define FU_QUIRKS_CFI_DEVICE_CMD_SECTOR_ERASE "CfiDeviceCmdSectorErase"
#define FU_QUIRKS_CFI_DEVICE_CMD_WRITE_EN "CfiDeviceCmdWriteEn"
#define FU_QUIRKS_CFI_DEVICE_CMD_WRITE_STATUS "CfiDeviceCmdWriteStatus"
#define FU_QUIRKS_CFI_DEVICE_PAGE_SIZE "CfiDevicePageSize"
#define FU_QUIRKS_CFI_DEVICE_SECTOR_SIZE "CfiDeviceSectorSize"
#define FU_QUIRKS_CHILDREN "Children"
#define FU_QUIRKS_COUNTERPART_GUID "CounterpartGuid"
#define FU_QUIRKS_FIRMWARE_GTYPE "FirmwareGType"
#define FU_QUIRKS_FIRMWARE_SIZE "FirmwareSize"
#define FU_QUIRKS_FIRMWARE_SIZE_MAX "FirmwareSizeMax"
#define FU_QUIRKS_FIRMWARE_SIZE_MIN "FirmwareSizeMin"
#define FU_QUIRKS_FLAGS "Flags"
#define FU_QUIRKS_GTYPE "GType"
#define FU_QUIRKS_GUID "Guid"
#define FU_QUIRKS_ICON "Icon"
#define FU_QUIRKS_INHIBIT "Inhibit"
#define FU_QUIRKS_INSTALL_DURATION "InstallDuration"
#define FU_QUIRKS_ISSUE "Issue"
#define FU_QUIRKS_NAME "Name"
#define FU_QUIRKS_PARENT_GUID "ParentGuid"
#define FU_QUIRKS_PLUGIN "Plugin"
#define FU_QUIRKS_PRIORITY "Priority"
#define FU_QUIRKS_PROTOCOL "Protocol"
#define FU_QUIRKS_PROXY_GUID "ProxyGuid"
#define FU_QUIRKS_REMOVE_DELAY "RemoveDelay"
#define FU_QUIRKS_SUMMARY "Summary"
#define FU_QUIRKS_UPDATE_IMAGE "UpdateImage"
#define FU_QUIRKS_UPDATE_MESSAGE "UpdateMessage"
#define FU_QUIRKS_VENDOR "Vendor"
#define FU_QUIRKS_VENDOR_ID "VendorId"
#define FU_QUIRKS_VERSION "Version"
#define FU_QUIRKS_VERSION_FORMAT "VersionFormat"
#define FU_TYPE_QUIRKS (fu_quirks_get_type())
#define FU_HWIDS_KEY_BASEBOARD_MANUFACTURER "BaseboardManufacturer"
#define FU_HWIDS_KEY_BASEBOARD_PRODUCT "BaseboardProduct"
#define FU_HWIDS_KEY_BIOS_MAJOR_RELEASE "BiosMajorRelease"
#define FU_HWIDS_KEY_BIOS_MINOR_RELEASE "BiosMinorRelease"
#define FU_HWIDS_KEY_BIOS_VENDOR "BiosVendor"
#define FU_HWIDS_KEY_BIOS_VERSION "BiosVersion"
#define FU_HWIDS_KEY_ENCLOSURE_KIND "EnclosureKind"
#define FU_HWIDS_KEY_FAMILY "Family"
#define FU_HWIDS_KEY_FIRMWARE_MAJOR_RELEASE "FirmwareMajorRelease"
#define FU_HWIDS_KEY_FIRMWARE_MINOR_RELEASE "FirmwareMinorRelease"
#define FU_HWIDS_KEY_MANUFACTURER "Manufacturer"
#define FU_HWIDS_KEY_PRODUCT_NAME "ProductName"
#define FU_HWIDS_KEY_PRODUCT_SKU "ProductSku"
#define FU_TYPE_HWIDS (fu_hwids_get_type())
#define FU_SMBIOS_STRUCTURE_TYPE_BASEBOARD 0x02
#define FU_SMBIOS_STRUCTURE_TYPE_BIOS 0x00
#define FU_SMBIOS_STRUCTURE_TYPE_CHASSIS 0x03
#define FU_SMBIOS_STRUCTURE_TYPE_LAST 0x04
#define FU_SMBIOS_STRUCTURE_TYPE_SYSTEM 0x01
#define FU_TYPE_SMBIOS (fu_smbios_get_type())
#define FU_FIRMWARE_ALIGNMENT_128  0x07
#define FU_FIRMWARE_ALIGNMENT_128K 0x11
#define FU_FIRMWARE_ALIGNMENT_128M 0x1B
#define FU_FIRMWARE_ALIGNMENT_16   0x04
#define FU_FIRMWARE_ALIGNMENT_16K  0x0E
#define FU_FIRMWARE_ALIGNMENT_16M  0x18
#define FU_FIRMWARE_ALIGNMENT_1G   0x1E
#define FU_FIRMWARE_ALIGNMENT_1K   0x0A
#define FU_FIRMWARE_ALIGNMENT_1M   0x14
#define FU_FIRMWARE_ALIGNMENT_256  0x08
#define FU_FIRMWARE_ALIGNMENT_256K 0x12
#define FU_FIRMWARE_ALIGNMENT_256M 0x1C
#define FU_FIRMWARE_ALIGNMENT_2G   0x1F
#define FU_FIRMWARE_ALIGNMENT_2K   0x0B
#define FU_FIRMWARE_ALIGNMENT_2M   0x15
#define FU_FIRMWARE_ALIGNMENT_32   0x05
#define FU_FIRMWARE_ALIGNMENT_32K  0x0F
#define FU_FIRMWARE_ALIGNMENT_32M  0x19
#define FU_FIRMWARE_ALIGNMENT_4G   0x20
#define FU_FIRMWARE_ALIGNMENT_4K   0x0C
#define FU_FIRMWARE_ALIGNMENT_4M   0x16
#define FU_FIRMWARE_ALIGNMENT_512  0x09
#define FU_FIRMWARE_ALIGNMENT_512K 0x13
#define FU_FIRMWARE_ALIGNMENT_512M 0x1D
#define FU_FIRMWARE_ALIGNMENT_64   0x06
#define FU_FIRMWARE_ALIGNMENT_64K  0x10
#define FU_FIRMWARE_ALIGNMENT_64M  0x1A
#define FU_FIRMWARE_ALIGNMENT_8K   0x0D
#define FU_FIRMWARE_ALIGNMENT_8M   0x17
#define FU_FIRMWARE_EXPORT_FLAG_ASCII_DATA (1u << 1)
#define FU_FIRMWARE_EXPORT_FLAG_INCLUDE_DEBUG (1u << 0)
#define FU_FIRMWARE_EXPORT_FLAG_NONE (0u)
#define FU_FIRMWARE_FLAG_DEDUPE_ID (1u << 0)
#define FU_FIRMWARE_FLAG_DEDUPE_IDX (1u << 1)
#define FU_FIRMWARE_FLAG_DONE_PARSE (1u << 4)
#define FU_FIRMWARE_FLAG_HAS_CHECKSUM (1u << 2)
#define FU_FIRMWARE_FLAG_HAS_STORED_SIZE (1u << 5)
#define FU_FIRMWARE_FLAG_HAS_VID_PID (1u << 3)
#define FU_FIRMWARE_FLAG_NONE (0u)
#define FU_FIRMWARE_ID_HEADER "header"
#define FU_FIRMWARE_ID_PAYLOAD "payload"
#define FU_FIRMWARE_ID_SIGNATURE "signature"
#define FU_TYPE_FIRMWARE (fu_firmware_get_type())
#define FU_TYPE_CHUNK (fu_chunk_get_type())
#define FU_DEVICE_INTERNAL_AUTO_PAUSE_POLLING (1ull << 24)
#define FU_DEVICE_INTERNAL_FLAG_ATTACH_EXTRA_RESET (1ull << 13)
#define FU_DEVICE_INTERNAL_FLAG_AUTO_PARENT_CHILDREN (1ull << 12)
#define FU_DEVICE_INTERNAL_FLAG_ENSURE_SEMVER (1ull << 1)
#define FU_DEVICE_INTERNAL_FLAG_INHERIT_ACTIVATION (1ull << 9)
#define FU_DEVICE_INTERNAL_FLAG_INHIBIT_CHILDREN (1ull << 14)
#define FU_DEVICE_INTERNAL_FLAG_IS_OPEN (1ull << 10)
#define FU_DEVICE_INTERNAL_FLAG_MD_SET_ICON (1ull << 6)
#define FU_DEVICE_INTERNAL_FLAG_MD_SET_NAME (1ull << 3)
#define FU_DEVICE_INTERNAL_FLAG_MD_SET_NAME_CATEGORY (1ull << 4)
#define FU_DEVICE_INTERNAL_FLAG_MD_SET_SIGNED (1ull << 23)
#define FU_DEVICE_INTERNAL_FLAG_MD_SET_VENDOR (1ull << 20)
#define FU_DEVICE_INTERNAL_FLAG_MD_SET_VERFMT (1ull << 5)
#define FU_DEVICE_INTERNAL_FLAG_NONE (0)
#define FU_DEVICE_INTERNAL_FLAG_NO_AUTO_INSTANCE_IDS (1ull << 0)
#define FU_DEVICE_INTERNAL_FLAG_NO_AUTO_REMOVE (1llu << 19)
#define FU_DEVICE_INTERNAL_FLAG_NO_AUTO_REMOVE_CHILDREN (1ull << 15)
#define FU_DEVICE_INTERNAL_FLAG_NO_LID_CLOSED (1ull << 21)
#define FU_DEVICE_INTERNAL_FLAG_NO_PROBE (1ull << 22)
#define FU_DEVICE_INTERNAL_FLAG_NO_SERIAL_NUMBER (1ull << 11)
#define FU_DEVICE_INTERNAL_FLAG_ONLY_SUPPORTED (1ull << 2)
#define FU_DEVICE_INTERNAL_FLAG_ONLY_WAIT_FOR_REPLUG (1ull << 25)
#define FU_DEVICE_INTERNAL_FLAG_REPLUG_MATCH_GUID (1ull << 8)
#define FU_DEVICE_INTERNAL_FLAG_RETRY_OPEN (1ull << 7)
#define FU_DEVICE_INTERNAL_FLAG_UNKNOWN G_MAXUINT64
#define FU_DEVICE_INTERNAL_FLAG_USE_PARENT_FOR_BATTERY (1ull << 17)
#define FU_DEVICE_INTERNAL_FLAG_USE_PARENT_FOR_OPEN (1ull << 16)
#define FU_DEVICE_INTERNAL_FLAG_USE_PROXY_FALLBACK (1ull << 18)
#define FU_DEVICE_REMOVE_DELAY_RE_ENUMERATE 10000 
#define FU_DEVICE_REMOVE_DELAY_USER_REPLUG 40000 
#define FU_TYPE_DEVICE (fu_device_get_type())
#define fu_device_add_checksum(d, v)	   fwupd_device_add_checksum(FWUPD_DEVICE(d), v)
#define fu_device_add_icon(d, v)	   fwupd_device_add_icon(FWUPD_DEVICE(d), v)
#define fu_device_add_issue(d, v)	   fwupd_device_add_issue(FWUPD_DEVICE(d), v)
#define fu_device_add_protocol(d, v)	   fwupd_device_add_protocol(FWUPD_DEVICE(d), v)
#define fu_device_add_release(d, v)	   fwupd_device_add_release(FWUPD_DEVICE(d), v)
#define fu_device_add_vendor_id(d, v)	   fwupd_device_add_vendor_id(FWUPD_DEVICE(d), v)
#define fu_device_get_branch(d)		     fwupd_device_get_branch(FWUPD_DEVICE(d))
#define fu_device_get_checksums(d)	     fwupd_device_get_checksums(FWUPD_DEVICE(d))
#define fu_device_get_composite_id(d)	     fwupd_device_get_composite_id(FWUPD_DEVICE(d))
#define fu_device_get_created(d)	     fwupd_device_get_created(FWUPD_DEVICE(d))
#define fu_device_get_flags(d)		     fwupd_device_get_flags(FWUPD_DEVICE(d))
#define fu_device_get_flashes_left(d)	    fwupd_device_get_flashes_left(FWUPD_DEVICE(d))
#define fu_device_get_guid_default(d)	     fwupd_device_get_guid_default(FWUPD_DEVICE(d))
#define fu_device_get_guids(d)		     fwupd_device_get_guids(FWUPD_DEVICE(d))
#define fu_device_get_icons(d)		     fwupd_device_get_icons(FWUPD_DEVICE(d))
#define fu_device_get_id(d)		     fwupd_device_get_id(FWUPD_DEVICE(d))
#define fu_device_get_install_duration(d)   fwupd_device_get_install_duration(FWUPD_DEVICE(d))
#define fu_device_get_instance_ids(d)	     fwupd_device_get_instance_ids(FWUPD_DEVICE(d))
#define fu_device_get_issues(d)		     fwupd_device_get_issues(FWUPD_DEVICE(d))
#define fu_device_get_modified(d)	     fwupd_device_get_modified(FWUPD_DEVICE(d))
#define fu_device_get_name(d)		     fwupd_device_get_name(FWUPD_DEVICE(d))
#define fu_device_get_plugin(d)		     fwupd_device_get_plugin(FWUPD_DEVICE(d))
#define fu_device_get_protocols(d)	    fwupd_device_get_protocols(FWUPD_DEVICE(d))
#define fu_device_get_serial(d)		     fwupd_device_get_serial(FWUPD_DEVICE(d))
#define fu_device_get_summary(d)	     fwupd_device_get_summary(FWUPD_DEVICE(d))
#define fu_device_get_update_error(d)	     fwupd_device_get_update_error(FWUPD_DEVICE(d))
#define fu_device_get_update_image(d)	     fwupd_device_get_update_image(FWUPD_DEVICE(d))
#define fu_device_get_update_message(d)	     fwupd_device_get_update_message(FWUPD_DEVICE(d))
#define fu_device_get_update_state(d)	     fwupd_device_get_update_state(FWUPD_DEVICE(d))
#define fu_device_get_vendor(d)		     fwupd_device_get_vendor(FWUPD_DEVICE(d))
#define fu_device_get_vendor_ids(d)	    fwupd_device_get_vendor_ids(FWUPD_DEVICE(d))
#define fu_device_get_version(d)	     fwupd_device_get_version(FWUPD_DEVICE(d))
#define fu_device_get_version_bootloader(d)  fwupd_device_get_version_bootloader(FWUPD_DEVICE(d))
#define fu_device_get_version_bootloader_raw(d)                                                    \
	fwupd_device_get_version_bootloader_raw(FWUPD_DEVICE(d))
#define fu_device_get_version_build_date(d) fwupd_device_get_version_build_date(FWUPD_DEVICE(d))
#define fu_device_get_version_format(d)	     fwupd_device_get_version_format(FWUPD_DEVICE(d))
#define fu_device_get_version_lowest(d)	     fwupd_device_get_version_lowest(FWUPD_DEVICE(d))
#define fu_device_get_version_lowest_raw(d)  fwupd_device_get_version_lowest_raw(FWUPD_DEVICE(d))
#define fu_device_get_version_raw(d)	     fwupd_device_get_version_raw(FWUPD_DEVICE(d))
#define fu_device_has_flag(d, v)	   fwupd_device_has_flag(FWUPD_DEVICE(d), v)
#define fu_device_has_icon(d, v)	   fwupd_device_has_icon(FWUPD_DEVICE(d), v)
#define fu_device_has_instance_id(d, v)	   fwupd_device_has_instance_id(FWUPD_DEVICE(d), v)
#define fu_device_has_protocol(d, v)	   fwupd_device_has_protocol(FWUPD_DEVICE(d), v)
#define fu_device_has_vendor_id(d, v)	   fwupd_device_has_vendor_id(FWUPD_DEVICE(d), v)
#define fu_device_set_branch(d, v)	   fwupd_device_set_branch(FWUPD_DEVICE(d), v)
#define fu_device_set_created(d, v)	   fwupd_device_set_created(FWUPD_DEVICE(d), v)
#define fu_device_set_description(d, v)	   fwupd_device_set_description(FWUPD_DEVICE(d), v)
#define fu_device_set_flags(d, v)	   fwupd_device_set_flags(FWUPD_DEVICE(d), v)
#define fu_device_set_flashes_left(d, v)     fwupd_device_set_flashes_left(FWUPD_DEVICE(d), v)
#define fu_device_set_install_duration(d, v) fwupd_device_set_install_duration(FWUPD_DEVICE(d), v)
#define fu_device_set_modified(d, v)	   fwupd_device_set_modified(FWUPD_DEVICE(d), v)
#define fu_device_set_plugin(d, v)	   fwupd_device_set_plugin(FWUPD_DEVICE(d), v)
#define fu_device_set_serial(d, v)	   fwupd_device_set_serial(FWUPD_DEVICE(d), v)
#define fu_device_set_summary(d, v)	   fwupd_device_set_summary(FWUPD_DEVICE(d), v)
#define fu_device_set_update_error(d, v)   fwupd_device_set_update_error(FWUPD_DEVICE(d), v)
#define fu_device_set_update_image(d, v)   fwupd_device_set_update_image(FWUPD_DEVICE(d), v)
#define fu_device_set_update_message(d, v) fwupd_device_set_update_message(FWUPD_DEVICE(d), v)
#define fu_device_set_version_bootloader_raw(d, v)                                                 \
	fwupd_device_set_version_bootloader_raw(FWUPD_DEVICE(d), v)
#define fu_device_set_version_build_date(d, v)                                                     \
	fwupd_device_set_version_build_date(FWUPD_DEVICE(d), v)
#define fu_device_set_version_lowest_raw(d, v)                                                     \
	fwupd_device_set_version_lowest_raw(FWUPD_DEVICE(d), v)
#define fu_device_set_version_raw(d, v)	   fwupd_device_set_version_raw(FWUPD_DEVICE(d), v)
#define FU_PROGRESS_FLAG_CHILD_FINISHED (1ull << 2)
#define FU_PROGRESS_FLAG_GUESSED (1ull << 0)
#define FU_PROGRESS_FLAG_NONE (0)
#define FU_PROGRESS_FLAG_NO_PROFILE (1ull << 1)
#define FU_PROGRESS_FLAG_NO_TRACEBACK (1ull << 3)
#define FU_PROGRESS_FLAG_UNKNOWN G_MAXUINT64
#define FU_TYPE_PROGRESS (fu_progress_get_type())
#define FU_TYPE_DEVICE_LOCKER (fu_device_locker_get_type())
#define FU_TYPE_BLUEZ_DEVICE (fu_bluez_device_get_type())
#define fu_device_set_plugin(d, v) fwupd_device_set_plugin(FWUPD_DEVICE(d), v)
#define FU_TYPE_VOLUME (fu_volume_get_type())
#define FU_VOLUME_KIND_BDP "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
#define FU_VOLUME_KIND_ESP "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
