

#include<sys/wait.h>
#include<fcntl.h>
#include<X11/Xauth.h>

#include<sys/utsname.h>




#include<sys/socket.h>

#include<unistd.h>
#include<sys/ioctl.h>









#include<grp.h>
#include<sys/syscall.h>
#include<stdio.h>
#include<sys/vfs.h>


#include<string.h>




#include<sys/personality.h>


#include<ctype.h>
#define FLATPAK_SESSION_HELPER_BUS_NAME "org.freedesktop.Flatpak"
#define FLATPAK_SESSION_HELPER_INTERFACE "org.freedesktop.Flatpak.SessionHelper"
#define FLATPAK_SESSION_HELPER_INTERFACE_DEVELOPMENT "org.freedesktop.Flatpak.Development"
#define FLATPAK_SESSION_HELPER_PATH "/org/freedesktop/Flatpak/SessionHelper"
#define FLATPAK_SESSION_HELPER_PATH_DEVELOPMENT "/org/freedesktop/Flatpak/Development"

#define FLATPAK_ERROR flatpak_error_quark ()


#define FLATPAK_INSTANCE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_INSTANCE, FlatpakInstance))
#define FLATPAK_IS_INSTANCE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_INSTANCE))
#define FLATPAK_TYPE_INSTANCE flatpak_instance_get_type ()

#define FLATPAK_CLI_UPDATE_INTERVAL_MS 300
#define FLATPAK_DEPLOY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_DEPLOY, FlatpakDeploy))
#define FLATPAK_DEPLOY_DATA_GVARIANT_FORMAT G_VARIANT_TYPE (FLATPAK_DEPLOY_DATA_GVARIANT_STRING)
#define FLATPAK_DEPLOY_DATA_GVARIANT_STRING "(ssasta{sv})"
#define FLATPAK_DEPLOY_VERSION_ANY 0
#define FLATPAK_DEPLOY_VERSION_CURRENT 4
#define FLATPAK_DIR(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_DIR, FlatpakDir))
#define FLATPAK_HELPER_CANCEL_PULL_FLAGS_ALL (FLATPAK_HELPER_CANCEL_PULL_FLAGS_PRESERVE_PULL |\
                                              FLATPAK_HELPER_CANCEL_PULL_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_CONFIGURE_FLAGS_ALL (FLATPAK_HELPER_CONFIGURE_FLAGS_UNSET | \
                                            FLATPAK_HELPER_CONFIGURE_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_CONFIGURE_REMOTE_FLAGS_ALL (FLATPAK_HELPER_CONFIGURE_REMOTE_FLAGS_FORCE_REMOVE | \
                                                   FLATPAK_HELPER_CONFIGURE_REMOTE_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_DEPLOY_APPSTREAM_FLAGS_ALL (FLATPAK_HELPER_DEPLOY_APPSTREAM_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_DEPLOY_FLAGS_ALL (FLATPAK_HELPER_DEPLOY_FLAGS_UPDATE | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_NO_DEPLOY | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_LOCAL_PULL | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_REINSTALL | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_NO_INTERACTION | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_APP_HINT | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_INSTALL_HINT | \
                                         FLATPAK_HELPER_DEPLOY_FLAGS_UPDATE_PINNED)
#define FLATPAK_HELPER_ENSURE_REPO_FLAGS_ALL (FLATPAK_HELPER_ENSURE_REPO_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_GENERATE_OCI_SUMMARY_FLAGS_ALL (FLATPAK_HELPER_GENERATE_OCI_SUMMARY_FLAGS_NO_INTERACTION |\
                                                       FLATPAK_HELPER_GENERATE_OCI_SUMMARY_FLAGS_ONLY_CACHED)
#define FLATPAK_HELPER_GET_REVOKEFS_FD_FLAGS_ALL (FLATPAK_HELPER_GET_REVOKEFS_FD_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_INSTALL_BUNDLE_FLAGS_ALL (FLATPAK_HELPER_INSTALL_BUNDLE_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_PRUNE_LOCAL_REPO_FLAGS_ALL (FLATPAK_HELPER_PRUNE_LOCAL_REPO_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_REMOVE_LOCAL_REF_FLAGS_ALL (FLATPAK_HELPER_REMOVE_LOCAL_REF_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_RUN_TRIGGERS_FLAGS_ALL (FLATPAK_HELPER_RUN_TRIGGERS_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_UNINSTALL_FLAGS_ALL (FLATPAK_HELPER_UNINSTALL_FLAGS_KEEP_REF | \
                                            FLATPAK_HELPER_UNINSTALL_FLAGS_FORCE_REMOVE | \
                                            FLATPAK_HELPER_UNINSTALL_FLAGS_NO_INTERACTION)
#define FLATPAK_HELPER_UPDATE_REMOTE_FLAGS_ALL (FLATPAK_HELPER_UPDATE_REMOTE_FLAGS_NO_INTERACTION | \
                                                FLATPAK_HELPER_UPDATE_REMOTE_FLAGS_SUMMARY_IS_INDEX)
#define FLATPAK_HELPER_UPDATE_SUMMARY_FLAGS_ALL (FLATPAK_HELPER_UPDATE_SUMMARY_FLAGS_NO_INTERACTION |\
                                                 FLATPAK_HELPER_UPDATE_SUMMARY_FLAGS_DELETE)
#define FLATPAK_IS_DEPLOY(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_DEPLOY))
#define FLATPAK_IS_DIR(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_DIR))
#define FLATPAK_REF_BRANCH_KEY "Branch"
#define FLATPAK_REF_COLLECTION_ID_KEY "CollectionID"
#define FLATPAK_REF_DEPLOY_COLLECTION_ID_KEY "DeployCollectionID"
#define FLATPAK_REF_DEPLOY_SIDELOAD_COLLECTION_ID_KEY "DeploySideloadCollectionID"
#define FLATPAK_REF_GPGKEY_KEY "GPGKey"
#define FLATPAK_REF_GROUP "Flatpak Ref"
#define FLATPAK_REF_IS_RUNTIME_KEY "IsRuntime"
#define FLATPAK_REF_NAME_KEY "Name"
#define FLATPAK_REF_RUNTIME_REPO_KEY "RuntimeRepo"
#define FLATPAK_REF_SUGGEST_REMOTE_NAME_KEY "SuggestRemoteName"
#define FLATPAK_REF_TITLE_KEY "Title"
#define FLATPAK_REF_URL_KEY "Url"
#define FLATPAK_REF_VERSION_KEY "Version"
#define FLATPAK_REPO_AUTHENTICATOR_INSTALL_KEY "AuthenticatorInstall"
#define FLATPAK_REPO_AUTHENTICATOR_NAME_KEY "AuthenticatorName"
#define FLATPAK_REPO_COLLECTION_ID_KEY "CollectionID"
#define FLATPAK_REPO_COMMENT_KEY "Comment"
#define FLATPAK_REPO_DEFAULT_BRANCH_KEY "DefaultBranch"
#define FLATPAK_REPO_DEPLOY_COLLECTION_ID_KEY "DeployCollectionID"
#define FLATPAK_REPO_DEPLOY_SIDELOAD_COLLECTION_ID_KEY "DeploySideloadCollectionID"
#define FLATPAK_REPO_DESCRIPTION_KEY "Description"
#define FLATPAK_REPO_FILTER_KEY "Filter"
#define FLATPAK_REPO_GPGKEY_KEY "GPGKey"
#define FLATPAK_REPO_GROUP "Flatpak Repo"
#define FLATPAK_REPO_HOMEPAGE_KEY "Homepage"
#define FLATPAK_REPO_ICON_KEY "Icon"
#define FLATPAK_REPO_NODEPS_KEY "NoDeps"
#define FLATPAK_REPO_SUBSET_KEY "Subset"
#define FLATPAK_REPO_TITLE_KEY "Title"
#define FLATPAK_REPO_URL_KEY "Url"
#define FLATPAK_REPO_VERSION_KEY "Version"
#define FLATPAK_SPARSE_CACHE_KEY_ENDOFLINE "eol"
#define FLATPAK_SPARSE_CACHE_KEY_ENDOFLINE_REBASE "eolr"
#define FLATPAK_SPARSE_CACHE_KEY_EXTRA_DATA_SIZE "eds"
#define FLATPAK_SPARSE_CACHE_KEY_TOKEN_TYPE "tokt"
#define FLATPAK_SUMMARY_INDEX_GVARIANT_FORMAT G_VARIANT_TYPE (FLATPAK_SUMMARY_INDEX_GVARIANT_STRING)
#define FLATPAK_SUMMARY_INDEX_GVARIANT_STRING "(a{s(ayaaya{sv})}a{sv})"
#define FLATPAK_TYPE_DEPLOY flatpak_deploy_get_type ()
#define FLATPAK_TYPE_DIR flatpak_dir_get_type ()
#define SYSTEM_DIR_DEFAULT_DISPLAY_NAME _("Default system installation")
#define SYSTEM_DIR_DEFAULT_ID "default"
#define SYSTEM_DIR_DEFAULT_PRIORITY 0
#define SYSTEM_DIR_DEFAULT_STORAGE_TYPE FLATPAK_DIR_STORAGE_TYPE_DEFAULT


#define FLATPAK_IS_REF(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_REF))
#define FLATPAK_REF(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_REF, FlatpakRef))
#define FLATPAK_TYPE_REF flatpak_ref_get_type ()


#define FLATKPAK_MAIN_CONTEXT_INIT {NULL}
#define FLATPAK_DEFAULT_UPDATE_INTERVAL_MS 100

#define FLATPAK_TYPE_PROGRESS flatpak_progress_get_type ()
#define FLATPAK_INSTALLATION(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_INSTALLATION, FlatpakInstallation))
#define FLATPAK_IS_INSTALLATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_INSTALLATION))
#define FLATPAK_TYPE_INSTALLATION flatpak_installation_get_type ()

#define FLATPAK_IS_REMOTE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_REMOTE))
#define FLATPAK_REMOTE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_REMOTE, FlatpakRemote))
#define FLATPAK_TYPE_REMOTE flatpak_remote_get_type ()

#define FLATPAK_IS_REMOTE_REF(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_REMOTE_REF))
#define FLATPAK_REMOTE_REF(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_REMOTE_REF, FlatpakRemoteRef))
#define FLATPAK_TYPE_REMOTE_REF flatpak_remote_ref_get_type ()

#define FLATPAK_INSTALLED_REF(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FLATPAK_TYPE_INSTALLED_REF, FlatpakInstalledRef))
#define FLATPAK_IS_INSTALLED_REF(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FLATPAK_TYPE_INSTALLED_REF))
#define FLATPAK_TYPE_INSTALLED_REF flatpak_installed_ref_get_type ()




# define G_DBUS_METHOD_INVOCATION_HANDLED TRUE
# define G_DBUS_METHOD_INVOCATION_UNHANDLED FALSE

#define FLATPAK_METADATA_GROUP_APPLICATION "Application"
#define FLATPAK_METADATA_GROUP_CONTEXT "Context"
#define FLATPAK_METADATA_GROUP_DCONF "X-DConf"
#define FLATPAK_METADATA_GROUP_ENVIRONMENT "Environment"
#define FLATPAK_METADATA_GROUP_EXTENSION_OF "ExtensionOf"
#define FLATPAK_METADATA_GROUP_EXTRA_DATA "Extra Data"
#define FLATPAK_METADATA_GROUP_INSTANCE "Instance"
#define FLATPAK_METADATA_GROUP_PREFIX_EXTENSION "Extension "
#define FLATPAK_METADATA_GROUP_PREFIX_POLICY "Policy "
#define FLATPAK_METADATA_GROUP_RUNTIME "Runtime"
#define FLATPAK_METADATA_GROUP_SESSION_BUS_POLICY "Session Bus Policy"
#define FLATPAK_METADATA_GROUP_SYSTEM_BUS_POLICY "System Bus Policy"
#define FLATPAK_METADATA_KEY_ADD_LD_PATH "add-ld-path"
#define FLATPAK_METADATA_KEY_APP_COMMIT "app-commit"
#define FLATPAK_METADATA_KEY_APP_EXTENSIONS "app-extensions"
#define FLATPAK_METADATA_KEY_APP_PATH "app-path"
#define FLATPAK_METADATA_KEY_ARCH "arch"
#define FLATPAK_METADATA_KEY_AUTODELETE "autodelete"
#define FLATPAK_METADATA_KEY_AUTOPRUNE_UNLESS "autoprune-unless"
#define FLATPAK_METADATA_KEY_BRANCH "branch"
#define FLATPAK_METADATA_KEY_BUILD "build"
#define FLATPAK_METADATA_KEY_COLLECTION_ID "collection-id"
#define FLATPAK_METADATA_KEY_COMMAND "command"
#define FLATPAK_METADATA_KEY_DCONF_MIGRATE_PATH "migrate-path"
#define FLATPAK_METADATA_KEY_DCONF_PATHS "paths"
#define FLATPAK_METADATA_KEY_DEVEL "devel"
#define FLATPAK_METADATA_KEY_DEVICES "devices"
#define FLATPAK_METADATA_KEY_DIRECTORY "directory"
#define FLATPAK_METADATA_KEY_DOWNLOAD_IF "download-if"
#define FLATPAK_METADATA_KEY_ENABLE_IF "enable-if"
#define FLATPAK_METADATA_KEY_EXTRA_ARGS "extra-args"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_CHECKSUM "checksum"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_INSTALLED_SIZE "installed-size"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_NAME "name"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_SIZE "size"
#define FLATPAK_METADATA_KEY_EXTRA_DATA_URI "uri"
#define FLATPAK_METADATA_KEY_FEATURES "features"
#define FLATPAK_METADATA_KEY_FILESYSTEMS "filesystems"
#define FLATPAK_METADATA_KEY_FLATPAK_VERSION "flatpak-version"
#define FLATPAK_METADATA_KEY_INSTANCE_ID "instance-id"
#define FLATPAK_METADATA_KEY_INSTANCE_PATH "instance-path"
#define FLATPAK_METADATA_KEY_LOCALE_SUBSET "locale-subset"
#define FLATPAK_METADATA_KEY_MERGE_DIRS "merge-dirs"
#define FLATPAK_METADATA_KEY_NAME "name"
#define FLATPAK_METADATA_KEY_NO_AUTODOWNLOAD "no-autodownload"
#define FLATPAK_METADATA_KEY_NO_RUNTIME "NoRuntime"
#define FLATPAK_METADATA_KEY_ORIGINAL_APP_PATH "original-app-path"
#define FLATPAK_METADATA_KEY_ORIGINAL_RUNTIME_PATH "original-runtime-path"
#define FLATPAK_METADATA_KEY_PERSISTENT "persistent"
#define FLATPAK_METADATA_KEY_PRIORITY "priority"
#define FLATPAK_METADATA_KEY_REF "ref"
#define FLATPAK_METADATA_KEY_REQUIRED_FLATPAK "required-flatpak"
#define FLATPAK_METADATA_KEY_RUNTIME "runtime"
#define FLATPAK_METADATA_KEY_RUNTIME_COMMIT "runtime-commit"
#define FLATPAK_METADATA_KEY_RUNTIME_EXTENSIONS "runtime-extensions"
#define FLATPAK_METADATA_KEY_RUNTIME_PATH "runtime-path"
#define FLATPAK_METADATA_KEY_SANDBOX "sandbox"
#define FLATPAK_METADATA_KEY_SDK "sdk"
#define FLATPAK_METADATA_KEY_SESSION_BUS_PROXY "session-bus-proxy"
#define FLATPAK_METADATA_KEY_SHARED "shared"
#define FLATPAK_METADATA_KEY_SOCKETS "sockets"
#define FLATPAK_METADATA_KEY_SUBDIRECTORIES "subdirectories"
#define FLATPAK_METADATA_KEY_SUBDIRECTORY_SUFFIX "subdirectory-suffix"
#define FLATPAK_METADATA_KEY_SYSTEM_BUS_PROXY "system-bus-proxy"
#define FLATPAK_METADATA_KEY_TAG "tag"
#define FLATPAK_METADATA_KEY_TAGS "tags"
#define FLATPAK_METADATA_KEY_UNSET_ENVIRONMENT "unset-environment"
#define FLATPAK_METADATA_KEY_VERSION "version"
#define FLATPAK_METADATA_KEY_VERSIONS "versions"

#define AUTOFS_SUPER_MAGIC 0x0187
#define AUTOLOCK(name) G_GNUC_UNUSED __attribute__((cleanup (flatpak_auto_unlock_helper))) GMutex * G_PASTE (auto_unlock, "__LINE__") = flatpak_auto_lock_helper (&G_LOCK_NAME (name))
#define FLATPAK_ANSI_ALT_SCREEN_OFF "\x1b[?1049l"
#define FLATPAK_ANSI_ALT_SCREEN_ON "\x1b[?1049h"
#define FLATPAK_ANSI_BOLD_OFF "\x1b[22m"
#define FLATPAK_ANSI_BOLD_ON "\x1b[1m"
#define FLATPAK_ANSI_CLEAR "\x1b[0J"
#define FLATPAK_ANSI_COLOR_RESET "\x1b[0m"
#define FLATPAK_ANSI_FAINT_OFF "\x1b[22m"
#define FLATPAK_ANSI_FAINT_ON "\x1b[2m"
#define FLATPAK_ANSI_GREEN "\x1b[32m"
#define FLATPAK_ANSI_HIDE_CURSOR "\x1b[?25l"
#define FLATPAK_ANSI_RED "\x1b[31m"
#define FLATPAK_ANSI_ROW_N "\x1b[%d;1H"
#define FLATPAK_ANSI_SHOW_CURSOR "\x1b[?25h"
#define FLATPAK_MESSAGE_ID "c7b39b1e006b464599465e105b361485"
#define FLATPAK_SUMMARY_DIFF_HEADER "xadf"
#define FLATPAK_SUMMARY_HISTORY_LENGTH_DEFAULT 16
#define FLATPAK_VARIANT_BUILDER_INITIALIZER {{0, }}
#define FLATPAK_VARIANT_DICT_INITIALIZER {{0, }}
#define FLATPAK_XA_CACHE_VERSION 2
#define FLATPAK_XA_SUMMARY_VERSION 1
#define OSTREE_COMMIT_TIMESTAMP "ostree.commit.timestamp"
#define OSTREE_COMMIT_TIMESTAMP2 "ot.ts" 

#define flatpak_fail glnx_throw
#define FLATPAK_HTTP_ERROR flatpak_http_error_quark ()

#   define FLATPAK_MISSING_SYSCALL_BASE 4000
# define __NR_clone3 (FLATPAK_MISSING_SYSCALL_BASE + 435)
# define __NR_close_range (FLATPAK_MISSING_SYSCALL_BASE + 436)
# define __NR_epoll_pwait2 (FLATPAK_MISSING_SYSCALL_BASE + 441)
# define __NR_faccessat2 (FLATPAK_MISSING_SYSCALL_BASE + 439)
# define __NR_fsconfig (FLATPAK_MISSING_SYSCALL_BASE + 431)
# define __NR_fsmount (FLATPAK_MISSING_SYSCALL_BASE + 432)
# define __NR_fsopen (FLATPAK_MISSING_SYSCALL_BASE + 430)
# define __NR_fspick (FLATPAK_MISSING_SYSCALL_BASE + 433)
# define __NR_landlock_add_rule (FLATPAK_MISSING_SYSCALL_BASE + 445)
# define __NR_landlock_create_ruleset (FLATPAK_MISSING_SYSCALL_BASE + 444)
# define __NR_landlock_restrict_self (FLATPAK_MISSING_SYSCALL_BASE + 446)
# define __NR_memfd_secret (FLATPAK_MISSING_SYSCALL_BASE + 447)
# define __NR_mount_setattr (FLATPAK_MISSING_SYSCALL_BASE + 442)
# define __NR_move_mount (FLATPAK_MISSING_SYSCALL_BASE + 429)
# define __NR_open_tree (FLATPAK_MISSING_SYSCALL_BASE + 428)
# define __NR_openat2 (FLATPAK_MISSING_SYSCALL_BASE + 437)
# define __NR_pidfd_getfd (FLATPAK_MISSING_SYSCALL_BASE + 438)
# define __NR_pidfd_open (FLATPAK_MISSING_SYSCALL_BASE + 434)
# define __NR_process_madvise (FLATPAK_MISSING_SYSCALL_BASE + 440)
# define __NR_quotactl_fd (FLATPAK_MISSING_SYSCALL_BASE + 443)
# define __SNR_clone3 __NR_clone3
# define __SNR_close_range __NR_close_range
# define __SNR_epoll_pwait2 __NR_epoll_pwait2
# define __SNR_faccessat2 __NR_faccessat2
# define __SNR_fsconfig __NR_fsconfig
# define __SNR_fsmount __NR_fsmount
# define __SNR_fsopen __NR_fsopen
# define __SNR_fspick __NR_fspick
# define __SNR_landlock_add_rule __NR_landlock_add_rule
# define __SNR_landlock_create_ruleset __NR_landlock_create_ruleset
# define __SNR_landlock_restrict_self __NR_landlock_restrict_self
# define __SNR_memfd_secret __NR_memfd_secret
# define __SNR_mount_setattr __NR_mount_setattr
# define __SNR_move_mount __NR_move_mount
# define __SNR_open_tree __NR_open_tree
# define __SNR_openat2 __NR_openat2
# define __SNR_pidfd_getfd __NR_pidfd_getfd
# define __SNR_pidfd_open __NR_pidfd_open
# define __SNR_process_madvise __NR_process_madvise
# define __SNR_quotactl_fd __NR_quotactl_fd
