#include<malloc.h>

#include<stddef.h>




#include<sys/types.h>


#include<stdlib.h>
#include<inttypes.h>


#include<stdio.h>
#include<fcntl.h>

#include<ctype.h>
#include<stdint.h>
#include<sys/stat.h>



#define LOC_FRAMEWORK_VERSION  1
#define LOC_HTAB_SIZE           1031	
#define LOC_MESSAGE_NB          32
#define LOC_MESSAGE_SIZE        2048
#define LOC_NEEDS_UPDATE        0x00000002
#define LOC_RIGHT_TO_LEFT       0x00000001
#define MSG_MASK                0x0FFFFFFF
#define MSG_RTF                 0x10000000
#define exit_localization() _exit_localization(FALSE)
#define init_localization() _init_localization(FALSE)
#define list_empty(entry) ((entry)->next == (entry))
#define list_entry(ptr, type, member) \
	((type *)((uintptr_t)(ptr) - (uintptr_t)offsetof(type, member)))
#define list_for_each_entry(pos, head, type, member)			\
	for (pos = list_entry((head)->next, type, member);			\
		 &pos->member != (head);								\
		 pos = list_entry(pos->member.next, type, member))
#define list_for_each_entry_safe(pos, n, head, type, member)	\
	for (pos = list_entry((head)->next, type, member),			\
		 n = list_entry(pos->member.next, type, member);		\
		 &pos->member != (head);								\
		 pos = n, n = list_entry(n->member.next, type, member))
#define luprint(msg) uprintf("%s(%d): " msg "\n", loc_filename, loc_line_nr)
#define luprintf(msg, ...) uprintf("%s(%d): " msg "\n", loc_filename, loc_line_nr, __VA_ARGS__)
#define reinit_localization() do {_exit_localization(TRUE); _init_localization(TRUE);} while(0)
#define ComboBox_AddStringU(hCtrl, str) ((int)(DWORD)SendMessageLU(hCtrl, CB_ADDSTRING, (WPARAM)FALSE, str))
#define ComboBox_GetTextU(hCtrl, str, max_str) GetWindowTextU(hCtrl, str, max_str)
#define ComboBox_InsertStringU(hCtrl, index, str) ((int)(DWORD)SendMessageLU(hCtrl, CB_INSERTSTRING, (WPARAM)index, str))
#define Edit_ReplaceSelU(hCtrl, str) ((void)SendMessageLU(hCtrl, EM_REPLACESEL, (WPARAM)FALSE, str))
#define GetOpenFileNameU(p) GetOpenSaveFileNameU(p, FALSE)
#define GetSaveFileNameU(p) GetOpenSaveFileNameU(p, TRUE)
#define LTEXT(txt) _LTEXT(txt)
#define ListView_SetItemTextU(hwndLV,i,iSubItem_,pszText_) { LVITEMW _ms_wlvi; _ms_wlvi.iSubItem = iSubItem_; \
	_ms_wlvi.pszText = utf8_to_wchar(pszText_); \
	SNDMSG((hwndLV),LVM_SETITEMTEXTW,(WPARAM)(i),(LPARAM)&_ms_wlvi); sfree(_ms_wlvi.pszText);}
#define _LTEXT(txt) L##txt
#define isasciiU(c) isascii((unsigned char)(c))
#define iscntrlU(c) iscntrl((unsigned char)(c))
#define isdigitU(c) isdigit((unsigned char)(c))
#define isspaceU(c) isspace((unsigned char)(c))
#define isxdigitU(c) isxdigit((unsigned char)(c))
#define sfree(p) do {if (p != NULL) {free((void*)(p)); p = NULL;}} while(0)
#define utf8_to_wchar_no_alloc(src, wdest, wdest_size) \
	MultiByteToWideChar(CP_UTF8, 0, src, -1, wdest, wdest_size)
#define walloc(p, size) wchar_t* w ## p = (p == NULL)?NULL:(wchar_t*)calloc(size, sizeof(wchar_t))
#define wchar_to_utf8_no_alloc(wsrc, dest, dest_size) \
	WideCharToMultiByte(CP_UTF8, 0, wsrc, -1, dest, dest_size, NULL, NULL)
#define wconvert(p)     wchar_t* w ## p = utf8_to_wchar(p)
#define wfree(p) sfree(w ## p)
#define IDC_ABOUT                       1007
#define IDC_ABOUT_BLURB                 1034
#define IDC_ABOUT_COPYRIGHTS            1033
#define IDC_ABOUT_ICON                  1031
#define IDC_ABOUT_LICENSE               1030
#define IDC_ABOUT_UPDATES               1032
#define IDC_ADVANCED                    1043
#define IDC_BADBLOCKS                   1011
#define IDC_BOOT                        1010
#define IDC_BOOTTYPE                    1013
#define IDC_CHECK_NOW                   1066
#define IDC_CLUSTERSIZE                 1005
#define IDC_DEVICE                      1001
#define IDC_DISK_ID                     1022
#define IDC_DOWNLOAD                    1065
#define IDC_DOWNLOAD_URL                1070
#define IDC_ENABLE_FIXED_DISKS          1024
#define IDC_EXTRA_PARTITION             1023
#define IDC_FILESYSTEM                  1002
#define IDC_HASH                        1026
#define IDC_INCLUDE_BETAS               1063
#define IDC_INFO                        1020
#define IDC_LABEL                       1008
#define IDC_LATEST_VERSION              1069
#define IDC_LICENSE_TEXT                1036
#define IDC_LIST_ICON                   1093
#define IDC_LIST_ITEM1                  1096
#define IDC_LIST_ITEM10                 1105
#define IDC_LIST_ITEM11                 1106
#define IDC_LIST_ITEM12                 1107
#define IDC_LIST_ITEM13                 1108
#define IDC_LIST_ITEM14                 1109
#define IDC_LIST_ITEM15                 1110
#define IDC_LIST_ITEM2                  1097
#define IDC_LIST_ITEM3                  1098
#define IDC_LIST_ITEM4                  1099
#define IDC_LIST_ITEM5                  1100
#define IDC_LIST_ITEM6                  1101
#define IDC_LIST_ITEM7                  1102
#define IDC_LIST_ITEM8                  1103
#define IDC_LIST_ITEM9                  1104
#define IDC_LIST_ITEMMAX                1111
#define IDC_LIST_LINE                   1095
#define IDC_LIST_TEXT                   1094
#define IDC_LOG                         1045
#define IDC_LOG_CLEAR                   1052
#define IDC_LOG_EDIT                    1050
#define IDC_LOG_SAVE                    1051
#define IDC_MD5                         1071
#define IDC_MORE_INFO                   1060
#define IDC_NBPASSES                    1014
#define IDC_NOTIFICATION_ICON           1040
#define IDC_NOTIFICATION_LINE           1042
#define IDC_NOTIFICATION_TEXT           1041
#define IDC_PARTITION_TYPE              1004
#define IDC_POLICY                      1061
#define IDC_PROGRESS                    1012
#define IDC_QUICKFORMAT                 1009
#define IDC_RELEASE_NOTES               1064
#define IDC_RUFUS_MBR                   1018
#define IDC_SELECTION_CHOICE1           1077
#define IDC_SELECTION_CHOICE10          1086
#define IDC_SELECTION_CHOICE11          1087
#define IDC_SELECTION_CHOICE12          1088
#define IDC_SELECTION_CHOICE13          1089
#define IDC_SELECTION_CHOICE14          1090
#define IDC_SELECTION_CHOICE15          1091
#define IDC_SELECTION_CHOICE2           1078
#define IDC_SELECTION_CHOICE3           1079
#define IDC_SELECTION_CHOICE4           1080
#define IDC_SELECTION_CHOICE5           1081
#define IDC_SELECTION_CHOICE6           1082
#define IDC_SELECTION_CHOICE7           1083
#define IDC_SELECTION_CHOICE8           1084
#define IDC_SELECTION_CHOICE9           1085
#define IDC_SELECTION_CHOICEMAX         1092
#define IDC_SELECTION_ICON              1074
#define IDC_SELECTION_LINE              1076
#define IDC_SELECTION_TEXT              1075
#define IDC_SELECT_ISO                  1016
#define IDC_SET_ICON                    1017
#define IDC_SHA1                        1072
#define IDC_SHA256                      1073
#define IDC_START                       1003
#define IDC_STATUS                      1006
#define IDC_STATUS_TOOLBAR              1025
#define IDC_TEST                        1015
#define IDC_UPDATE_FREQUENCY            1062
#define IDC_WEBSITE                     1067
#define IDC_WINDOWS_INSTALL             1047
#define IDC_WINDOWS_TO_GO               1048
#define IDC_YOUR_VERSION                1068
#define IDD_ABOUTBOX                    102
#define IDD_ABOUTBOX_RTL                202
#define IDD_ABOUTBOX_RTL_XP             252
#define IDD_ABOUTBOX_XP                 152
#define IDD_CHECKSUM                    109
#define IDD_DIALOG                      101
#define IDD_DIALOG_RTL                  201
#define IDD_DIALOG_RTL_XP               251
#define IDD_DIALOG_XP                   151
#define IDD_LICENSE                     105
#define IDD_LICENSE_RTL                 204
#define IDD_LICENSE_RTL_XP              254
#define IDD_LICENSE_XP                  154
#define IDD_LIST                        110
#define IDD_LOG                         106
#define IDD_LOG_RTL                     205
#define IDD_LOG_RTL_XP                  255
#define IDD_LOG_XP                      155
#define IDD_NEW_VERSION                 108
#define IDD_NEW_VERSION_RTL             207
#define IDD_NEW_VERSION_RTL_XP          257
#define IDD_NEW_VERSION_XP              157
#define IDD_NOTIFICATION                103
#define IDD_NOTIFICATION_RTL            203
#define IDD_NOTIFICATION_RTL_XP         253
#define IDD_NOTIFICATION_XP             153
#define IDD_SELECTION                   104
#define IDD_UPDATE_POLICY               107
#define IDD_UPDATE_POLICY_RTL           206
#define IDD_UPDATE_POLICY_RTL_XP        256
#define IDD_UPDATE_POLICY_XP            156
#define IDI_DOWN                        122
#define IDI_ICON                        120
#define IDI_UP                          121
#define IDR_FD_COMMAND_COM              300
#define IDR_FD_DISPLAY_EXE              302
#define IDR_FD_EGA10_CPX                318
#define IDR_FD_EGA11_CPX                319
#define IDR_FD_EGA12_CPX                320
#define IDR_FD_EGA13_CPX                321
#define IDR_FD_EGA14_CPX                322
#define IDR_FD_EGA15_CPX                323
#define IDR_FD_EGA16_CPX                324
#define IDR_FD_EGA17_CPX                325
#define IDR_FD_EGA18_CPX                326
#define IDR_FD_EGA1_CPX                 309
#define IDR_FD_EGA2_CPX                 310
#define IDR_FD_EGA3_CPX                 311
#define IDR_FD_EGA4_CPX                 312
#define IDR_FD_EGA5_CPX                 313
#define IDR_FD_EGA6_CPX                 314
#define IDR_FD_EGA7_CPX                 315
#define IDR_FD_EGA8_CPX                 316
#define IDR_FD_EGA9_CPX                 317
#define IDR_FD_KB1_SYS                  305
#define IDR_FD_KB2_SYS                  306
#define IDR_FD_KB3_SYS                  307
#define IDR_FD_KB4_SYS                  308
#define IDR_FD_KERNEL_SYS               301
#define IDR_FD_KEYB_EXE                 303
#define IDR_FD_MODE_COM                 304
#define IDR_GR_GRUB2_CORE_IMG           451
#define IDR_GR_GRUB_GRLDR_MBR           450
#define IDR_LC_RUFUS_LOC                500
#define IDR_SL_LDLINUX_V4_BSS           400
#define IDR_SL_LDLINUX_V4_SYS           401
#define IDR_SL_LDLINUX_V6_BSS           402
#define IDR_SL_LDLINUX_V6_SYS           403
#define IDR_SL_MBOOT_C32                404
#define IDR_TOGO_SAN_POLICY_XML         503
#define IDR_TOGO_UNATTEND_XML           504
#define IDR_UEFI_NTFS                   502
#define IDR_XT_HOGGER                   501
#define IDS_ADVANCED_OPTIONS_GRP        1044
#define IDS_CHECK_NOW_GRP               2012
#define IDS_CLUSTERSIZE_TXT             2003
#define IDS_DEVICE_TXT                  2000
#define IDS_FILESYSTEM_TXT              2002
#define IDS_FORMAT_OPTIONS_GRP          2005
#define IDS_INCLUDE_BETAS_TXT           2008
#define IDS_LABEL_TXT                   2004
#define IDS_NEW_VERSION_AVAIL_TXT       2009
#define IDS_NEW_VERSION_DOWNLOAD_GRP    2010
#define IDS_NEW_VERSION_NOTES_GRP       2011
#define IDS_PARTITION_TYPE_TXT          2001
#define IDS_UPDATE_FREQUENCY_TXT        2007
#define IDS_UPDATE_SETTINGS_GRP         2006
#define MSG_000                         3000
#define MSG_001                         3001
#define MSG_002                         3002
#define MSG_003                         3003
#define MSG_004                         3004
#define MSG_005                         3005
#define MSG_006                         3006
#define MSG_007                         3007
#define MSG_008                         3008
#define MSG_009                         3009
#define MSG_010                         3010
#define MSG_011                         3011
#define MSG_012                         3012
#define MSG_013                         3013
#define MSG_014                         3014
#define MSG_015                         3015
#define MSG_016                         3016
#define MSG_017                         3017
#define MSG_018                         3018
#define MSG_019                         3019
#define MSG_020                         3020
#define MSG_021                         3021
#define MSG_022                         3022
#define MSG_023                         3023
#define MSG_024                         3024
#define MSG_025                         3025
#define MSG_026                         3026
#define MSG_027                         3027
#define MSG_028                         3028
#define MSG_029                         3029
#define MSG_030                         3030
#define MSG_031                         3031
#define MSG_032                         3032
#define MSG_033                         3033
#define MSG_034                         3034
#define MSG_035                         3035
#define MSG_036                         3036
#define MSG_037                         3037
#define MSG_038                         3038
#define MSG_039                         3039
#define MSG_040                         3040
#define MSG_041                         3041
#define MSG_042                         3042
#define MSG_043                         3043
#define MSG_044                         3044
#define MSG_045                         3045
#define MSG_046                         3046
#define MSG_047                         3047
#define MSG_048                         3048
#define MSG_049                         3049
#define MSG_050                         3050
#define MSG_051                         3051
#define MSG_052                         3052
#define MSG_053                         3053
#define MSG_054                         3054
#define MSG_055                         3055
#define MSG_056                         3056
#define MSG_057                         3057
#define MSG_058                         3058
#define MSG_059                         3059
#define MSG_060                         3060
#define MSG_061                         3061
#define MSG_062                         3062
#define MSG_063                         3063
#define MSG_064                         3064
#define MSG_065                         3065
#define MSG_066                         3066
#define MSG_067                         3067
#define MSG_068                         3068
#define MSG_069                         3069
#define MSG_070                         3070
#define MSG_071                         3071
#define MSG_072                         3072
#define MSG_073                         3073
#define MSG_074                         3074
#define MSG_075                         3075
#define MSG_076                         3076
#define MSG_077                         3077
#define MSG_078                         3078
#define MSG_079                         3079
#define MSG_080                         3080
#define MSG_081                         3081
#define MSG_082                         3082
#define MSG_083                         3083
#define MSG_084                         3084
#define MSG_085                         3085
#define MSG_086                         3086
#define MSG_087                         3087
#define MSG_088                         3088
#define MSG_089                         3089
#define MSG_090                         3090
#define MSG_091                         3091
#define MSG_092                         3092
#define MSG_093                         3093
#define MSG_094                         3094
#define MSG_095                         3095
#define MSG_096                         3096
#define MSG_097                         3097
#define MSG_098                         3098
#define MSG_099                         3099
#define MSG_100                         3100
#define MSG_101                         3101
#define MSG_102                         3102
#define MSG_103                         3103
#define MSG_104                         3104
#define MSG_105                         3105
#define MSG_106                         3106
#define MSG_107                         3107
#define MSG_108                         3108
#define MSG_109                         3109
#define MSG_110                         3110
#define MSG_111                         3111
#define MSG_112                         3112
#define MSG_113                         3113
#define MSG_114                         3114
#define MSG_115                         3115
#define MSG_116                         3116
#define MSG_117                         3117
#define MSG_118                         3118
#define MSG_119                         3119
#define MSG_120                         3120
#define MSG_121                         3121
#define MSG_122                         3122
#define MSG_123                         3123
#define MSG_124                         3124
#define MSG_125                         3125
#define MSG_126                         3126
#define MSG_127                         3127
#define MSG_128                         3128
#define MSG_129                         3129
#define MSG_130                         3130
#define MSG_131                         3131
#define MSG_132                         3132
#define MSG_133                         3133
#define MSG_134                         3134
#define MSG_135                         3135
#define MSG_136                         3136
#define MSG_137                         3137
#define MSG_138                         3138
#define MSG_139                         3139
#define MSG_140                         3140
#define MSG_141                         3141
#define MSG_142                         3142
#define MSG_143                         3143
#define MSG_144                         3144
#define MSG_145                         3145
#define MSG_146                         3146
#define MSG_147                         3147
#define MSG_148                         3148
#define MSG_149                         3149
#define MSG_150                         3150
#define MSG_151                         3151
#define MSG_152                         3152
#define MSG_153                         3153
#define MSG_154                         3154
#define MSG_155                         3155
#define MSG_156                         3156
#define MSG_157                         3157
#define MSG_158                         3158
#define MSG_159                         3159
#define MSG_160                         3160
#define MSG_161                         3161
#define MSG_162                         3162
#define MSG_163                         3163
#define MSG_164                         3164
#define MSG_165                         3165
#define MSG_166                         3166
#define MSG_167                         3167
#define MSG_168                         3168
#define MSG_169                         3169
#define MSG_170                         3170
#define MSG_171                         3171
#define MSG_172                         3172
#define MSG_173                         3173
#define MSG_174                         3174
#define MSG_175                         3175
#define MSG_176                         3176
#define MSG_177                         3177
#define MSG_178                         3178
#define MSG_179                         3179
#define MSG_180                         3180
#define MSG_181                         3181
#define MSG_182                         3182
#define MSG_183                         3183
#define MSG_184                         3184
#define MSG_185                         3185
#define MSG_186                         3186
#define MSG_187                         3187
#define MSG_188                         3188
#define MSG_189                         3189
#define MSG_190                         3190
#define MSG_191                         3191
#define MSG_192                         3192
#define MSG_193                         3193
#define MSG_194                         3194
#define MSG_195                         3195
#define MSG_196                         3196
#define MSG_197                         3197
#define MSG_198                         3198
#define MSG_199                         3199
#define MSG_200                         3200
#define MSG_201                         3201
#define MSG_202                         3202
#define MSG_203                         3203
#define MSG_204                         3204
#define MSG_205                         3205
#define MSG_206                         3206
#define MSG_207                         3207
#define MSG_208                         3208
#define MSG_209                         3209
#define MSG_210                         3210
#define MSG_211                         3211
#define MSG_212                         3212
#define MSG_213                         3213
#define MSG_214                         3214
#define MSG_215                         3215
#define MSG_216                         3216
#define MSG_217                         3217
#define MSG_218                         3218
#define MSG_219                         3219
#define MSG_220                         3220
#define MSG_221                         3221
#define MSG_222                         3222
#define MSG_223                         3223
#define MSG_224                         3224
#define MSG_225                         3225
#define MSG_226                         3226
#define MSG_227                         3227
#define MSG_228                         3228
#define MSG_229                         3229
#define MSG_230                         3230
#define MSG_231                         3231
#define MSG_232                         3232
#define MSG_233                         3233
#define MSG_234                         3234
#define MSG_235                         3235
#define MSG_236                         3236
#define MSG_237                         3237
#define MSG_238                         3238
#define MSG_239                         3239
#define MSG_240                         3240
#define MSG_241                         3241
#define MSG_242                         3242
#define MSG_243                         3243
#define MSG_244                         3244
#define MSG_245                         3245
#define MSG_246                         3246
#define MSG_247                         3247
#define MSG_248                         3248
#define MSG_249                         3249
#define MSG_250                         3250
#define MSG_251                         3251
#define MSG_252                         3252
#define MSG_253                         3253
#define MSG_254                         3254
#define MSG_255                         3255
#define MSG_256                         3256
#define MSG_257                         3257
#define MSG_258                         3258
#define MSG_259                         3259
#define MSG_260                         3260
#define MSG_261                         3261
#define MSG_262                         3262
#define MSG_263                         3263
#define MSG_264                         3264
#define MSG_265                         3265
#define MSG_266                         3266
#define MSG_267                         3267
#define MSG_268                         3268
#define MSG_269                         3269
#define MSG_270                         3270
#define MSG_271                         3271
#define MSG_272                         3272
#define MSG_273                         3273
#define MSG_274                         3274
#define MSG_275                         3275
#define MSG_276                         3276
#define MSG_277                         3277
#define MSG_278                         3278
#define MSG_279                         3279
#define MSG_280                         3280
#define MSG_281                         3281
#define MSG_282                         3282
#define MSG_283                         3283
#define MSG_284                         3284
#define MSG_285                         3285
#define MSG_286                         3286
#define MSG_287                         3287
#define MSG_288                         3288
#define MSG_289                         3289
#define MSG_290                         3290
#define MSG_291                         3291
#define MSG_292                         3292
#define MSG_293                         3293
#define MSG_294                         3294
#define MSG_295                         3295
#define MSG_296                         3296
#define MSG_297                         3297
#define MSG_298                         3298
#define MSG_299                         3299
#define MSG_MAX                         3300
#define _APS_NEXT_COMMAND_VALUE         40001
#define _APS_NEXT_CONTROL_VALUE         1079
#define _APS_NEXT_RESOURCE_VALUE        505
#define _APS_NEXT_SYMED_VALUE           4000
#define _APS_NO_MFC                     1
#define APPERR(err)                    (APPLICATION_ERROR_MASK|err)
#define APPLICATION_NAME            "Rufus"
#define ARRAYSIZE(A)                (sizeof(A)/sizeof((A)[0]))
#define BADBLOCK_PATTERNS           {0xaa, 0x55, 0xff, 0x00}
#define CHECK_FOR_USER_CANCEL       if (IS_ERROR(FormatStatus)) goto out
#define         CLOSE_OPENED_LIBRARIES while(OpenedLibrariesHandleSize > 0) FreeLibrary(OpenedLibrariesHandle[--OpenedLibrariesHandleSize])
#define COMPANY_NAME                "Akeo Consulting"
#define DD_BUFFER_SIZE              65536		
#define DOWNLOAD_URL                RUFUS_NO_SSL_URL "/downloads"
#define DRIVE_ACCESS_RETRIES        150			
#define DRIVE_ACCESS_TIMEOUT        15000		
#define DRIVE_INDEX_MAX             0x000000C0
#define DRIVE_INDEX_MIN             0x00000080
#define ERROR_BADBLOCKS_FAILURE        0x1206
#define ERROR_CANT_ASSIGN_LETTER       0x120B
#define ERROR_CANT_MOUNT_VOLUME        0x120C
#define ERROR_CANT_PATCH               0x120A
#define ERROR_CANT_QUICK_FORMAT        0x1202
#define ERROR_CANT_REMOUNT_VOLUME      0x1209
#define ERROR_CANT_START_THREAD        0x1205
#define ERROR_INCOMPATIBLE_FS          0x1201
#define ERROR_INVALID_CLUSTER_SIZE     0x1203
#define ERROR_INVALID_VOLUME_SIZE      0x1204
#define ERROR_ISO_EXTRACT              0x1208
#define ERROR_ISO_SCAN                 0x1207
#define EXT_D(prefix, ...) const char* _##prefix##_d[] = { __VA_ARGS__ }
#define EXT_DECL(var, filename, extensions, descriptions)                   \
	EXT_X(var, extensions);                                                 \
	EXT_D(var, descriptions);                                               \
	ext_t var = { ARRAYSIZE(_##var##_x), filename, _##var##_x, _##var##_d }
#define EXT_X(prefix, ...) const char* _##prefix##_x[] = { __VA_ARGS__ }
#define FAC(f)                         (f<<16)
#define FAT32_CLUSTER_THRESHOLD     1.011f		
#define FILES_DIR                   "rufus_files"
#define FILES_URL                   RUFUS_NO_SSL_URL "/files"
#define FS_DEFAULT                  FS_FAT32
#define GETPARTTYPE(x)   (((x)>0)?((x) & 0xFFFF):0);
#define GETTARGETTYPE(x) (((x)>0)?(((x) >> 16) & 0xFFFF):0)
#define HAS_BOOTMGR(r)      (r.has_bootmgr)
#define HAS_EFI_IMG(r)      (r.efi_img_path[0] != 0)
#define HAS_GRUB(r)         ((r.has_grub2) || (r.has_grub4dos))
#define HAS_INSTALL_WIM(r)  (r.install_wim_path[0] != 0)
#define HAS_KOLIBRIOS(r)    (r.has_kolibrios)
#define HAS_REACTOS(r)      (r.reactos_path[0] != 0)
#define HAS_SYSLINUX(r)     (r.sl_version != 0)
#define HAS_WIN7_EFI(r)     ((r.has_efi == 1) && HAS_INSTALL_WIM(r))
#define HAS_WINDOWS(r)      (HAS_BOOTMGR(r) || (r.uses_minint) || HAS_WINPE(r))
#define HAS_WINPE(r)        (((r.winpe & WINPE_MININT) == WINPE_MININT)||((r.winpe & WINPE_I386) == WINPE_I386))
#define HAS_WINTOGO(r)      (HAS_BOOTMGR(r) && IS_EFI_BOOTABLE(r) && HAS_INSTALL_WIM(r) && (r.install_wim_version < MAX_WIM_VERSION))
#define HTAB_EMPTY {NULL, 0, 0}
#define IGNORE_RETVAL(expr)         do { (void)(expr); } while(0)
#define IMG_SAVE_TYPE_ISO 2
#define IMG_SAVE_TYPE_VHD 1
#define IS_BIOS_BOOTABLE(r) (HAS_BOOTMGR(r) || HAS_SYSLINUX(r) || HAS_WINPE(r) || HAS_GRUB(r) || HAS_REACTOS(r) || HAS_KOLIBRIOS(r))
#define IS_DD_BOOTABLE(r)   (r.is_bootable_img)
#define IS_EFI_BOOTABLE(r)  (r.has_efi != 0)
#define IS_FAT(fs)          ((fs == FS_FAT16) || (fs == FS_FAT32))
#define IsChecked(CheckBox_ID)      (IsDlgButtonChecked(hMainDialog, CheckBox_ID) == BST_CHECKED)
#define IsStrArrayEmpty(arr) (arr.Index == 0)
#define LARGE_FAT32_SIZE            (32*1073741824LL)	
#define LEFT_TO_RIGHT_EMBEDDING     "‪"
#define LEFT_TO_RIGHT_MARK          "‎"
#define MAX_CLUSTER_SIZES           18
#define MAX_DRIVES                  (DRIVE_INDEX_MAX - DRIVE_INDEX_MIN)
#define MAX_FAT32_SIZE              2.0f		
#define MAX_GPT_PARTITIONS          128
#define MAX_GUID_STRING_LENGTH      40
#define         MAX_LIBRARY_HANDLES 32
#define MAX_LOG_SIZE                0x7FFFFFFE
#define MAX_PROGRESS                (0xFFFF-1)	
#define MAX_REFRESH                 25			
#define MAX_SECTORS_TO_CLEAR        128			
#define MAX_SIZE_SUFFIXES           6			
#define MAX_TOOLTIPS                128
#define MAX_WIM_VERSION     0x000E0000
#define MBR_UEFI_MARKER             0x49464555	
#define MB_IS_RTL                   (right_to_left_mode?MB_RTLREADING|MB_RIGHT:0)
#define MIN_DRIVE_SIZE              8			
#define MIN_EXTRA_PART_SIZE         (1024*1024)	
#define NB_OLD_C32          2
#define OLD_C32_NAMES       { "menu.c32", "vesamenu.c32" }
#define OLD_C32_THRESHOLD   { 53500, 148000 }
#define         OPENED_LIBRARIES_VARS HMODULE OpenedLibrariesHandle[MAX_LIBRARY_HANDLES]; uint16_t OpenedLibrariesHandleSize = 0
#define PARTITION_STYLE_SFD PARTITION_STYLE_RAW
#define PF_DECL(proc)						static proc##_t pf##proc = NULL
#define PF_INIT(proc, name)					if (pf##proc == NULL) pf##proc = \
	(proc##_t) GetProcAddress(GetLibraryHandle(#name), #proc)
#define PF_INIT_OR_OUT(proc, name)			do {PF_INIT(proc, name);         \
	if (pf##proc == NULL) {uprintf("Unable to locate %s() in %s.dll: %s\n",  \
	#proc, #name, WindowsErrorString()); goto out;} } while(0)
#define PF_TYPE(api, ret, proc, args)		typedef ret (api *proc##_t)args
#define PF_TYPE_DECL(api, ret, proc, args)	PF_TYPE(api, ret, proc, args); PF_DECL(proc)
#define POP_DIRECTIONAL_FORMATTING  "‬"
#define PrintInfo(...) PrintStatusInfo(TRUE, FALSE, __VA_ARGS__)
#define PrintInfoDebug(...) PrintStatusInfo(TRUE, TRUE, __VA_ARGS__)
#define PrintStatus(...) PrintStatusInfo(FALSE, FALSE, __VA_ARGS__)
#define PrintStatusDebug(...) PrintStatusInfo(FALSE, TRUE, __VA_ARGS__)
#define RIGHT_TO_LEFT_EMBEDDING     "‫"
#define RIGHT_TO_LEFT_MARK          "‏"
#define RIGHT_TO_LEFT_OVERRIDE      "‮"
#define RUFUS_LOGGING               
#define RUFUS_NO_SSL_URL            "http://rufus.akeo.ie"	
#define RUFUS_URL                   "https://rufus.akeo.ie"
#define SB_SECTION_LEFT         0
#define SB_SECTION_MIDDLE       1
#define SB_SECTION_RIGHT        2
#define SB_TIMER_SECTION_SIZE   58.0f
#define SEVENZIP_URL                "http://www.7-zip.org"
#define SINGLE_CLUSTERSIZE_DEFAULT  0x00000100
#define SL_MAJOR(x) ((uint8_t)((x)>>8))
#define SL_MINOR(x) ((uint8_t)(x))
#define STATUS_MSG_TIMEOUT          3500		
#define STRINGIFY(x)                #x
#define STR_NO_LABEL                "NO_LABEL"
#define UBUFFER_SIZE                2048
#define UDF_FORMAT_SPEED            3.1f		
#define UDF_FORMAT_WARN             20			
#define WINPE_I386          0x15
#define WINPE_MININT        0x2A
#define WRITE_RETRIES               3
#define _GetTickCount64() ((pfGetTickCount64 != NULL)?(uint64_t)pfGetTickCount64():(uint64_t)GetTickCount())
#define __VA_GROUP__(...)  __VA_ARGS__
#define _uprintf NULL
#define duprintf(...) _uprintf(__VA_ARGS__)
#define get_token_data_file(token, filename) get_token_data_file_indexed(token, filename, 1)
#define printbits(x) _printbits(sizeof(x), &x, 0)
#define printbitslz(x) _printbits(sizeof(x), &x, 1)
#define safe_closehandle(h) do {if ((h != INVALID_HANDLE_VALUE) && (h != NULL)) {CloseHandle(h); h = INVALID_HANDLE_VALUE;}} while(0)
#define safe_free(p) do {free((void*)p); p = NULL;} while(0)
#define safe_min(a, b) min((size_t)(a), (size_t)(b))
#define safe_mm_free(p) do {_mm_free((void*)p); p = NULL;} while(0)
#define safe_release_dc(hDlg, hDC) do {if ((hDC != INVALID_HANDLE_VALUE) && (hDC != NULL)) {ReleaseDC(hDlg, hDC); hDC = NULL;}} while(0)
#define safe_sprintf(dst, count, ...) do {_snprintf(dst, count, __VA_ARGS__); (dst)[(count)-1] = 0; } while(0)
#define safe_strcat(dst, dst_max, src) safe_strncat(dst, dst_max, src, safe_strlen(src)+1)
#define safe_strcmp(str1, str2) strcmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2))
#define safe_strcp(dst, dst_max, src, count) do {memcpy(dst, src, safe_min(count, dst_max)); \
	((char*)dst)[safe_min(count, dst_max)-1] = 0;} while(0)
#define safe_strcpy(dst, dst_max, src) safe_strcp(dst, dst_max, src, safe_strlen(src)+1)
#define safe_strdup _strdup
#define safe_stricmp(str1, str2) _stricmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2))
#define safe_strlen(str) ((((char*)str)==NULL)?0:strlen(str))
#define safe_strncat(dst, dst_max, src, count) strncat(dst, src, safe_min(count, dst_max - safe_strlen(dst) - 1))
#define safe_strncmp(str1, str2, count) strncmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2), count)
#define safe_strnicmp(str1, str2, count) _strnicmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2), count)
#define safe_strstr(str1, str2) strstr(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2))
#define safe_vsnprintf vsnprintf
#define static_sprintf(dst, ...) safe_sprintf(dst, sizeof(dst), __VA_ARGS__)
#define static_strcat(dst, src) safe_strcat(dst, sizeof(dst), src)
#define static_strcpy(dst, src) safe_strcpy(dst, sizeof(dst), src)
#define suprintf(...) do { if (!bSilent) _uprintf(__VA_ARGS__); } while(0)
#define ubflush() do { if (ubuffer_pos) uprintf("%s", ubuffer); ubuffer_pos = 0; } while(0)
#define ubprintf(...) do { safe_sprintf(&ubuffer[ubuffer_pos], UBUFFER_SIZE - ubuffer_pos - 2, __VA_ARGS__); \
	ubuffer_pos = strlen(ubuffer); ubuffer[ubuffer_pos++] = '\r'; ubuffer[ubuffer_pos++] = '\n'; \
	ubuffer[ubuffer_pos] = 0; } while(0)
#define uprintf(...) _uprintf(__VA_ARGS__)
#define uuprintf(...) do { if (usb_debug) _uprintf(__VA_ARGS__); } while(0)
#define vuprintf(...) do { if (verbose) _uprintf(__VA_ARGS__); } while(0)
#define vvuprintf(...) do { if (verbose > 1) _uprintf(__VA_ARGS__); } while(0)
