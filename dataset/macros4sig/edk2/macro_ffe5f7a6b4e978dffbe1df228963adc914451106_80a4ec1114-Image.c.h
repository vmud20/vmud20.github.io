



























#define BITMAP_LEN_1_BIT(Width, Height)  (((Width) + 7) / 8 * (Height))
#define BITMAP_LEN_24_BIT(Width, Height) ((Width) * (Height) * 3)
#define BITMAP_LEN_4_BIT(Width, Height)  (((Width) + 1) / 2 * (Height))
#define BITMAP_LEN_8_BIT(Width, Height)  ((Width) * (Height))
#define CONFIG_KEYWORD_HANDLER_DATABASE_PRIVATE_DATA_FROM_THIS(a) \
  CR (a, \
      HII_DATABASE_PRIVATE_DATA, \
      ConfigKeywordHandler, \
      HII_DATABASE_PRIVATE_DATA_SIGNATURE \
      )
#define CONFIG_ROUTING_DATABASE_PRIVATE_DATA_FROM_THIS(a) \
  CR (a, \
      HII_DATABASE_PRIVATE_DATA, \
      ConfigRouting, \
      HII_DATABASE_PRIVATE_DATA_SIGNATURE \
      )
#define EFI_HII_VARSTORE_BUFFER              0
#define EFI_HII_VARSTORE_EFI_VARIABLE        2
#define EFI_HII_VARSTORE_EFI_VARIABLE_BUFFER 3
#define EFI_HII_VARSTORE_NAME_VALUE          1
#define EFI_KEYWORD_FILTER_BUFFER            0x10
#define EFI_KEYWORD_FILTER_NUMERIC           0x20
#define EFI_KEYWORD_FILTER_NUMERIC_1         0x30
#define EFI_KEYWORD_FILTER_NUMERIC_2         0x40
#define EFI_KEYWORD_FILTER_NUMERIC_4         0x50
#define EFI_KEYWORD_FILTER_NUMERIC_8         0x60
#define EFI_KEYWORD_FILTER_READONY           0x01
#define EFI_KEYWORD_FILTER_REAWRITE          0x02
#define HII_DATABASE_DATABASE_PRIVATE_DATA_FROM_THIS(a) \
  CR (a, \
      HII_DATABASE_PRIVATE_DATA, \
      HiiDatabase, \
      HII_DATABASE_PRIVATE_DATA_SIGNATURE \
      )
#define HII_DATABASE_NOTIFY_SIGNATURE   SIGNATURE_32 ('h','i','d','n')
#define HII_DATABASE_PRIVATE_DATA_SIGNATURE SIGNATURE_32 ('H', 'i', 'D', 'p')
#define HII_DATABASE_RECORD_SIGNATURE   SIGNATURE_32 ('h','i','d','r')
#define HII_FONT_DATABASE_PRIVATE_DATA_FROM_THIS(a) \
  CR (a, \
      HII_DATABASE_PRIVATE_DATA, \
      HiiFont, \
      HII_DATABASE_PRIVATE_DATA_SIGNATURE \
      )
#define HII_FONT_INFO_SIGNATURE         SIGNATURE_32 ('h','l','f','i')
#define HII_FONT_PACKAGE_SIGNATURE      SIGNATURE_32 ('h','i','f','p')
#define HII_FORMSET_STORAGE_SIGNATURE           SIGNATURE_32 ('H', 'S', 'T', 'G')
#define HII_GLOBAL_FONT_INFO_SIGNATURE  SIGNATURE_32 ('h','g','f','i')
#define HII_GLYPH_INFO_SIGNATURE        SIGNATURE_32 ('h','g','i','s')
#define HII_GUID_PACKAGE_SIGNATURE      SIGNATURE_32 ('h','i','g','p')
#define HII_HANDLE_SIGNATURE            SIGNATURE_32 ('h','i','h','l')
#define HII_IFR_PACKAGE_SIGNATURE       SIGNATURE_32 ('h','f','r','p')
#define HII_IMAGE_DATABASE_PRIVATE_DATA_FROM_THIS(a) \
  CR (a, \
      HII_DATABASE_PRIVATE_DATA, \
      HiiImage, \
      HII_DATABASE_PRIVATE_DATA_SIGNATURE \
      )
#define HII_IMAGE_EX_DATABASE_PRIVATE_DATA_FROM_THIS(a) \
  CR (a, \
      HII_DATABASE_PRIVATE_DATA, \
      HiiImageEx, \
      HII_DATABASE_PRIVATE_DATA_SIGNATURE \
      )
#define HII_KB_LAYOUT_PACKAGE_SIGNATURE SIGNATURE_32 ('h','k','l','p')
#define HII_PIXEL_MASK                  0x80
#define HII_STRING_DATABASE_PRIVATE_DATA_FROM_THIS(a) \
  CR (a, \
      HII_DATABASE_PRIVATE_DATA, \
      HiiString, \
      HII_DATABASE_PRIVATE_DATA_SIGNATURE \
      )
#define HII_STRING_PACKAGE_SIGNATURE    SIGNATURE_32 ('h','i','s','p')
#define HII_S_FONT_PACKAGE_SIGNATURE    SIGNATURE_32 ('h','s','f','p')
#define MAX_FONT_NAME_LEN                  256
#define MAX_STRING_LENGTH                  1024
#define NARROW_BASELINE                    15
#define NARROW_GLYPH                       0x40
#define PROPORTIONAL_GLYPH                 0x80
#define REPLACE_UNKNOWN_GLYPH              0xFFFD
#define SYS_FONT_INFO_MASK                 0x37
#define WIDE_BASELINE                      14

