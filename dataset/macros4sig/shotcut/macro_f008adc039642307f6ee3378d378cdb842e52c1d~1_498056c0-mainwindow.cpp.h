


































































#include<clocale>























#include<stdint.h>




























#define MLT_VERSION_CPP_UPDATED ((6<<16)+(17<<8))

#define kAspectRatioDenominator "shotcut_aspect_den"
#define kAspectRatioNumerator "shotcut_aspect_num"
#define kAudioLevelsProperty "_shotcut:audio-levels"
#define kAudioTrackProperty "shotcut:audio"
#define kBackgroundCaptureProperty "_shotcut:bgcapture"
#define kBackgroundTrackId "background"
#define kCommentProperty "shotcut:comment"
#define kDefaultAudioIndexProperty "shotcut:defaultAudioIndex"
#define kDefaultMltProfile "atsc_1080p_25"
#define kDisableProxyProperty "shotcut:disableProxy"
#define kExportFromProperty "_shotcut:exportFromDefault"
#define kFilterInProperty "_shotcut:filter_in"
#define kFilterOutProperty "_shotcut:filter_out"
#define kIsProxyProperty "shotcut:proxy"
#define kLegacyPlaylistTrackId "main bin"
#define kMultitrackItemProperty "_shotcut:multitrack-item"
#define kOriginalInProperty "shotcut:originalIn"
#define kOriginalOutProperty "shotcut:originalOut"
#define kOriginalResourceProperty "shotcut:resource"
#define kPlaylistIndexProperty "_shotcut:playlistIndex"
#define kPlaylistStartProperty "_shotcut:playlistStart"
#define kPlaylistTrackId "main_bin"
#define kShotcutAnimInProperty "shotcut:animIn"
#define kShotcutAnimOutProperty "shotcut:animOut"
#define kShotcutCaptionProperty "shotcut:caption"
#define kShotcutDetailProperty "shotcut:detail"
#define kShotcutFilterProperty "shotcut:filter"
#define kShotcutHashProperty "shotcut:hash"
#define kShotcutPlaylistProperty "shotcut:playlist"
#define kShotcutProducerProperty "shotcut:producer"
#define kShotcutProjectAudioChannels "shotcut:projectAudioChannels"
#define kShotcutProjectFolder "shotcut:projectFolder"
#define kShotcutSequenceProperty "shotcut_sequence"
#define kShotcutSkipConvertProperty "shotcut:skipConvert"
#define kShotcutTransitionProperty "shotcut:transition"
#define kShotcutVirtualClip "shotcut:virtual"
#define kShotcutVuiMetaProperty "meta.shotcut.vui"
#define kShotcutXmlProperty "shotcut"
#define kThumbnailInProperty "_shotcut:thumbnail-in"
#define kThumbnailOutProperty "_shotcut:thumbnail-out"
#define kTimelineScaleProperty "shotcut:scaleFactor"
#define kTrackHeightProperty "shotcut:trackHeight"
#define kTrackLockProperty "shotcut:lock"
#define kTrackNameProperty "shotcut:name"
#define kUndoIdProperty "_shotcut:undo_id"
#define kUuidProperty "_shotcut:uuid"
#define kVideoTrackProperty "shotcut:video"









#define kDetailedMode "detailed"
#define kIconsMode "icons"
#define kTiledMode "tiled"
#define MLT Mlt::Controller::singleton()

#   define MLT_LC_CATEGORY LC_NUMERIC
#   define MLT_LC_NAME     "LC_NUMERIC"
#define MLT_VERSION_PREVIEW_SCALE ((6<<16)+(19<<8))
#define MLT_VERSION_SET_STRING ((6<<16)+(19<<8))









#define DB Database::singleton()


#define Settings ShotcutSettings::singleton()











#define JOBS JobQueue::singleton()





























#define EXIT_RESTART (42)
#define MAIN MainWindow::singleton()


