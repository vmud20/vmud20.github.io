
#include<pwd.h>

#include<stdio.h>
#include<dirent.h>

#include<unistd.h>

#include<sys/stat.h>
#include<libintl.h>
#include<sys/types.h>
#include<locale.h>
#include<string.h>
#include<stdlib.h>

#define CPDB_BACKEND_PREFIX  "org.openprinting.Backend."
#define CPDB_DEFAULT_PRINTERS_FILE "default-printers"
#define CPDB_DIALOG_BUS_NAME "org.openprinting.PrintFrontend"
#define CPDB_DIALOG_OBJ_PATH "/"
#define CPDB_PRINT_SETTINGS_FILE   "print-settings"

#define logdebug(...) cpdbFDebugPrintf(CPDB_DEBUG_LEVEL_DEBUG, __VA_ARGS__)
#define logerror(...) cpdbFDebugPrintf(CPDB_DEBUG_LEVEL_ERROR, __VA_ARGS__)
#define loginfo(...)  cpdbFDebugPrintf(CPDB_DEBUG_LEVEL_INFO, __VA_ARGS__)
#define logwarn(...)  cpdbFDebugPrintf(CPDB_DEBUG_LEVEL_WARN, __VA_ARGS__)
#define CPDB_BSIZE 512
#define CPDB_COLLATE_DISABLED           N_("separate-documents-uncollated-copies")
#define CPDB_COLLATE_ENABLED            N_("separate-documents-collated-copies")
#define CPDB_COLOR_MODE_AUTO            N_("auto")
#define CPDB_COLOR_MODE_BW              N_("monochrome")
#define CPDB_COLOR_MODE_COLOR           N_("color")
#define CPDB_DEBUG_LEVEL   "CPDB_DEBUG_LEVEL"
#define CPDB_DEBUG_LOGFILE "CPDB_DEBUG_LOGFILE"
#define CPDB_GROUP_ADVANCED     N_("Advanced")
#define CPDB_GROUP_COLOR        N_("Color")
#define CPDB_GROUP_COPIES       N_("Copies")
#define CPDB_GROUP_FINISHINGS   N_("Finishings")
#define CPDB_GROUP_JOB_MGMT     N_("Job Management")
#define CPDB_GROUP_MEDIA        N_("Media")
#define CPDB_GROUP_PAGE_MGMT    N_("Page Management")
#define CPDB_GROUP_QUALITY      N_("Ouput Quality")
#define CPDB_GROUP_SCALING      N_("Scaling")
#define CPDB_GRP_PREFIX "GRP"
#define CPDB_JOB_ARGS "(ssssssi)"
#define CPDB_JOB_ARRAY_ARGS "a(ssssssi)"
#define CPDB_JOB_HOLD_INDEFINITE        N_("indefinite")
#define CPDB_JOB_HOLD_NONE              N_("no-hold")
#define CPDB_JOB_STATE_ABORTED N_("Aborted")
#define CPDB_JOB_STATE_CANCELLED N_("Cancelled")
#define CPDB_JOB_STATE_COMPLETED N_("Completed")
#define CPDB_JOB_STATE_HELD N_("Held")
#define CPDB_JOB_STATE_PENDING N_("Pending") 
#define CPDB_JOB_STATE_PRINTING N_("Printing")
#define CPDB_JOB_STATE_STOPPED N_("Stopped")
#define CPDB_OPTION_BILLING_INFO            N_("billing-info")
#define CPDB_OPTION_BOOKLET                 N_("booklet")
#define CPDB_OPTION_COLLATE                 N_("multiple-document-handling")
#define CPDB_OPTION_COLOR_MODE              N_("print-color-mode")
#define CPDB_OPTION_COPIES                  N_("copies")
#define CPDB_OPTION_COPIES_SUPPORTED        N_("multiple-document-jobs-supported")
#define CPDB_OPTION_FIDELITY                N_("ipp-attribute-fidelity")
#define CPDB_OPTION_FINISHINGS              N_("finishings")
#define CPDB_OPTION_JOB_HOLD_UNTIL          N_("job-hold-until")
#define CPDB_OPTION_JOB_NAME                N_("job-name")
#define CPDB_OPTION_JOB_PRIORITY            N_("job-priority")
#define CPDB_OPTION_JOB_SHEETS              N_("job-sheets")
#define CPDB_OPTION_MARGIN_BOTTOM           N_("media-bottom-margin")
#define CPDB_OPTION_MARGIN_LEFT             N_("media-left-margin")
#define CPDB_OPTION_MARGIN_RIGHT            N_("media-right-margin")
#define CPDB_OPTION_MARGIN_TOP              N_("media-top-margin")
#define CPDB_OPTION_MEDIA                   N_("media")
#define CPDB_OPTION_MEDIA_COL               N_("media-col")
#define CPDB_OPTION_MEDIA_SOURCE            N_("media-source")
#define CPDB_OPTION_MEDIA_TYPE              N_("media-type")
#define CPDB_OPTION_MIRROR                  N_("mirror")
#define CPDB_OPTION_NUMBER_UP               N_("number-up")
#define CPDB_OPTION_NUMBER_UP_LAYOUT        N_("number-up-layout")
#define CPDB_OPTION_ORIENTATION             N_("orientation-requested")
#define CPDB_OPTION_OUTPUT_BIN              N_("output-bin")
#define CPDB_OPTION_PAGE_BORDER             N_("page-border")
#define CPDB_OPTION_PAGE_DELIVERY           N_("page-delivery")
#define CPDB_OPTION_PAGE_RANGES             N_("page-ranges")
#define CPDB_OPTION_PAGE_SET                N_("page-set")
#define CPDB_OPTION_POSITION                N_("position")
#define CPDB_OPTION_PRINT_QUALITY           N_("print-quality")
#define CPDB_OPTION_PRINT_SCALING           N_("print-scaling")
#define CPDB_OPTION_RESOLUTION              N_("printer-resolution")
#define CPDB_OPTION_SIDES                   N_("sides")
#define CPDB_OPT_PREFIX "OPT"
#define CPDB_ORIENTATION_LANDSCAPE      N_("4")
#define CPDB_ORIENTATION_PORTRAIT       N_("3")
#define CPDB_ORIENTATION_RLANDSCAPE     N_("5")
#define CPDB_ORIENTATION_RPORTRAIT      N_("6")
#define CPDB_PAGE_DELIVERY_REVERSE      N_("reverse-order")
#define CPDB_PAGE_DELIVERY_SAME         N_("same-order")
#define CPDB_PAGE_SET_ALL               N_("all")
#define CPDB_PAGE_SET_EVEN              N_("even")
#define CPDB_PAGE_SET_ODD               N_("odd")
#define CPDB_PRINTER_ADDED_ARGS "(sssssbss)"
#define CPDB_PRINTER_ARGS "(sssssbss)"
#define CPDB_PRINTER_ARRAY_ARGS "a(sssssbss)"
#define CPDB_PRIORITY_HIGH              N_("high")
#define CPDB_PRIORITY_LOW               N_("low")
#define CPDB_PRIORITY_MEDIUM            N_("medium")
#define CPDB_PRIORITY_URGENT            N_("urgent")
#define CPDB_QUALITY_DRAFT              N_("draft")
#define CPDB_QUALITY_HIGH               N_("high")
#define CPDB_QUALITY_NORMAL             N_("normal")
#define CPDB_SIDES_ONE_SIDED            N_("one-sided")
#define CPDB_SIDES_TWO_SIDED_LONG       N_("two-sided-long-edge")
#define CPDB_SIDES_TWO_SIDED_SHORT      N_("two-sided-short-edge")
#define CPDB_SIGNAL_HIDE_REMOTE "HideRemotePrinters"
#define CPDB_SIGNAL_HIDE_TEMP "HideTemporaryPrinters"
#define CPDB_SIGNAL_PRINTER_ADDED "PrinterAdded"
#define CPDB_SIGNAL_PRINTER_REMOVED "PrinterRemoved"
#define CPDB_SIGNAL_PRINTER_STATE_CHANGED "PrinterStateChanged"
#define CPDB_SIGNAL_REFRESH_BACKEND "RefreshBackend"
#define CPDB_SIGNAL_STOP_BACKEND "StopListing"
#define CPDB_SIGNAL_UNHIDE_REMOTE "UnhideRemotePrinters"
#define CPDB_SIGNAL_UNHIDE_TEMP "UnhideTemporaryPrinters"
#define CPDB_STATE_IDLE                 N_("idle")
#define CPDB_STATE_PRINTING             N_("printing")
#define CPDB_STATE_STOPPED              N_("stopped")
#define CPDB_SYSCONFDIR_PERM 0755
#define CPDB_TL_ARGS "{ss}"
#define CPDB_TL_DICT_ARGS "a{ss}"
#define CPDB_USRCONFDIR_PERM 0755
#define GETTEXT_PACKAGE "cpdb"

