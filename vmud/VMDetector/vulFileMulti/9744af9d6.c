
























static void fu_plugin_finalize(GObject *object);

typedef struct {
	GModule *module;
	guint order;
	guint priority;
	gboolean done_init;
	GPtrArray *rules[FU_PLUGIN_RULE_LAST];
	GPtrArray *devices; 
	GHashTable *runtime_versions;
	GHashTable *compile_versions;
	FuContext *ctx;
	GArray *device_gtypes; 
	GHashTable *cache;     
	GRWLock cache_mutex;
	GHashTable *report_metadata; 
	GFileMonitor *config_monitor;
	FuPluginData *data;
	FuPluginVfuncs vfuncs;
} FuPluginPrivate;

enum {
	SIGNAL_DEVICE_ADDED, SIGNAL_DEVICE_REMOVED, SIGNAL_DEVICE_REGISTER, SIGNAL_RULES_CHANGED, SIGNAL_CONFIG_CHANGED, SIGNAL_CHECK_SUPPORTED, SIGNAL_LAST };







static guint signals[SIGNAL_LAST] = {0};

G_DEFINE_TYPE_WITH_PRIVATE(FuPlugin, fu_plugin, FWUPD_TYPE_PLUGIN)


typedef void (*FuPluginInitVfuncsFunc)(FuPluginVfuncs *vfuncs);
typedef gboolean (*FuPluginDeviceFunc)(FuPlugin *self, FuDevice *device, GError **error);
typedef gboolean (*FuPluginDeviceProgressFunc)(FuPlugin *self, FuDevice *device, FuProgress *progress, GError **error);


typedef gboolean (*FuPluginFlaggedDeviceFunc)(FuPlugin *self, FuDevice *device, FuProgress *progress, FwupdInstallFlags flags, GError **error);



typedef gboolean (*FuPluginDeviceArrayFunc)(FuPlugin *self, GPtrArray *devices, GError **error);


gboolean fu_plugin_is_open(FuPlugin *self)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	return priv->module != NULL;
}


const gchar * fu_plugin_get_name(FuPlugin *self)
{
	g_return_val_if_fail(FU_IS_PLUGIN(self), NULL);
	return fwupd_plugin_get_name(FWUPD_PLUGIN(self));
}


void fu_plugin_set_name(FuPlugin *self, const gchar *name)
{
	g_return_if_fail(FU_IS_PLUGIN(self));
	fwupd_plugin_set_name(FWUPD_PLUGIN(self), name);
}

static FuPluginVfuncs * fu_plugin_get_vfuncs(FuPlugin *self)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	return &priv->vfuncs;
}


const gchar * fu_plugin_get_build_hash(FuPlugin *self)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_return_val_if_fail(FU_IS_PLUGIN(self), NULL);
	return vfuncs->build_hash;
}


gpointer fu_plugin_cache_lookup(FuPlugin *self, const gchar *id)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	g_autoptr(GRWLockReaderLocker) locker = g_rw_lock_reader_locker_new(&priv->cache_mutex);
	g_return_val_if_fail(FU_IS_PLUGIN(self), NULL);
	g_return_val_if_fail(id != NULL, NULL);
	g_return_val_if_fail(locker != NULL, NULL);
	if (priv->cache == NULL)
		return NULL;
	return g_hash_table_lookup(priv->cache, id);
}


void fu_plugin_cache_add(FuPlugin *self, const gchar *id, gpointer dev)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	g_autoptr(GRWLockWriterLocker) locker = g_rw_lock_writer_locker_new(&priv->cache_mutex);
	g_return_if_fail(FU_IS_PLUGIN(self));
	g_return_if_fail(id != NULL);
	g_return_if_fail(G_IS_OBJECT(dev));
	g_return_if_fail(locker != NULL);
	if (priv->cache == NULL) {
		priv->cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_object_unref);


	}
	g_hash_table_insert(priv->cache, g_strdup(id), g_object_ref(dev));
}


void fu_plugin_cache_remove(FuPlugin *self, const gchar *id)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	g_autoptr(GRWLockWriterLocker) locker = g_rw_lock_writer_locker_new(&priv->cache_mutex);
	g_return_if_fail(FU_IS_PLUGIN(self));
	g_return_if_fail(id != NULL);
	g_return_if_fail(locker != NULL);
	if (priv->cache == NULL)
		return;
	g_hash_table_remove(priv->cache, id);
}


FuPluginData * fu_plugin_get_data(FuPlugin *self)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_IS_PLUGIN(self), NULL);
	return priv->data;
}


FuPluginData * fu_plugin_alloc_data(FuPlugin *self, gsize data_sz)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_IS_PLUGIN(self), NULL);
	if (priv->data != NULL) {
		g_critical("fu_plugin_alloc_data() already used by plugin");
		return priv->data;
	}
	priv->data = g_malloc0(data_sz);
	return priv->data;
}


gchar * fu_plugin_guess_name_from_fn(const gchar *filename)
{
	const gchar *prefix = "libfu_plugin_";
	gchar *name;
	gchar *str = g_strstr_len(filename, -1, prefix);
	if (str == NULL)
		return NULL;
	name = g_strdup(str + strlen(prefix));
	g_strdelimit(name, ".", '\0');
	return name;
}


gboolean fu_plugin_open(FuPlugin *self, const gchar *filename, GError **error)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	FuPluginInitVfuncsFunc init_vfuncs = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	priv->module = g_module_open(filename, 0);
	if (priv->module == NULL) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to open plugin %s: %s", filename, g_module_error());




		fu_plugin_add_flag(self, FWUPD_PLUGIN_FLAG_FAILED_OPEN);
		fu_plugin_add_flag(self, FWUPD_PLUGIN_FLAG_USER_WARNING);
		return FALSE;
	}

	
	g_module_symbol(priv->module, "fu_plugin_init_vfuncs", (gpointer *)&init_vfuncs);
	if (init_vfuncs == NULL) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to init_vfuncs() on plugin %s", filename);



		fu_plugin_add_flag(self, FWUPD_PLUGIN_FLAG_FAILED_OPEN);
		fu_plugin_add_flag(self, FWUPD_PLUGIN_FLAG_USER_WARNING);
		return FALSE;
	}
	init_vfuncs(vfuncs);

	
	if (fu_plugin_get_name(self) == NULL) {
		g_autofree gchar *str = fu_plugin_guess_name_from_fn(filename);
		fu_plugin_set_name(self, str);
	}

	
	if (vfuncs->load != NULL) {
		FuContext *ctx = fu_plugin_get_context(self);
		g_debug("load(%s)", filename);
		vfuncs->load(ctx);
	}

	return TRUE;
}

static gchar * fu_plugin_flags_to_string(FwupdPluginFlags flags)
{
	g_autoptr(GString) str = g_string_new(NULL);
	for (guint i = 0; i < 64; i++) {
		FwupdPluginFlags flag = (guint64)1 << i;
		if ((flags & flag) == 0)
			continue;
		if (str->len > 0)
			g_string_append_c(str, ',');
		g_string_append(str, fwupd_plugin_flag_to_string(flag));
	}
	if (str->len == 0)
		return NULL;
	return g_string_free(g_steal_pointer(&str), FALSE);
}


void fu_plugin_add_string(FuPlugin *self, guint idt, GString *str)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	const gchar *name = fwupd_plugin_get_name(FWUPD_PLUGIN(self));
	g_autofree gchar *flags = NULL;

	g_return_if_fail(FU_IS_PLUGIN(self));
	g_return_if_fail(str != NULL);

	
	fu_string_append(str, idt, G_OBJECT_TYPE_NAME(self), "");
	if (name != NULL)
		fu_string_append(str, idt + 1, "Name", name);
	flags = fu_plugin_flags_to_string(fwupd_plugin_get_flags(FWUPD_PLUGIN(self)));
	if (flags != NULL)
		fu_string_append(str, idt + 1, "Flags", flags);
	if (priv->order != 0)
		fu_string_append_ku(str, idt + 1, "Order", priv->order);
	if (priv->priority != 0)
		fu_string_append_ku(str, idt + 1, "Priority", priv->priority);

	
	if (vfuncs->to_string != NULL)
		vfuncs->to_string(self, idt + 1, str);
}


gchar * fu_plugin_to_string(FuPlugin *self)
{
	g_autoptr(GString) str = g_string_new(NULL);
	g_return_val_if_fail(FU_IS_PLUGIN(self), NULL);
	fu_plugin_add_string(self, 0, str);
	return g_string_free(g_steal_pointer(&str), FALSE);
}


static const gchar * fu_plugin_build_device_update_error(FuPlugin *self)
{
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_NO_HARDWARE))
		return "Not updatable as required hardware was not found";
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_LEGACY_BIOS))
		return "Not updatable in legacy BIOS mode";
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_CAPSULES_UNSUPPORTED))
		return "Not updatable as UEFI capsule updates not enabled in firmware setup";
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_UNLOCK_REQUIRED))
		return "Not updatable as requires unlock";
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_AUTH_REQUIRED))
		return "Not updatable as requires authentication";
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_EFIVAR_NOT_MOUNTED))
		return "Not updatable as efivarfs was not found";
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_ESP_NOT_FOUND))
		return "Not updatable as UEFI ESP partition not detected";
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return "Not updatable as plugin was disabled";
	return NULL;
}

static void fu_plugin_ensure_devices(FuPlugin *self)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	if (priv->devices != NULL)
		return;
	priv->devices = g_ptr_array_new_with_free_func((GDestroyNotify)g_object_unref);
}

static void fu_plugin_device_child_added_cb(FuDevice *device, FuDevice *child, FuPlugin *self)
{
	g_debug("child %s added to parent %s after setup, adding to daemon", fu_device_get_id(child), fu_device_get_id(device));

	fu_plugin_device_add(self, child);
}

static void fu_plugin_device_child_removed_cb(FuDevice *device, FuDevice *child, FuPlugin *self)
{
	g_debug("child %s removed from parent %s after setup, removing from daemon", fu_device_get_id(child), fu_device_get_id(device));

	fu_plugin_device_remove(self, child);
}

static void fu_plugin_config_monitor_changed_cb(GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event_type, gpointer user_data)




{
	FuPlugin *self = FU_PLUGIN(user_data);
	g_autofree gchar *fn = g_file_get_path(file);
	g_debug("%s changed, sending signal", fn);
	g_signal_emit(self, signals[SIGNAL_CONFIG_CHANGED], 0);
}

static gchar * fu_plugin_get_config_filename(FuPlugin *self)
{
	g_autofree gchar *conf_dir = fu_path_from_kind(FU_PATH_KIND_SYSCONFDIR_PKG);
	g_autofree gchar *conf_file = g_strdup_printf("%s.conf", fu_plugin_get_name(self));
	return g_build_filename(conf_dir, conf_file, NULL);
}


void fu_plugin_device_add(FuPlugin *self, FuDevice *device)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	GPtrArray *children;
	g_autoptr(GError) error = NULL;

	g_return_if_fail(FU_IS_PLUGIN(self));
	g_return_if_fail(FU_IS_DEVICE(device));

	
	if (!fu_device_ensure_id(device, &error)) {
		g_warning("ignoring add: %s", error->message);
		return;
	}

	
	fu_plugin_ensure_devices(self);
	g_ptr_array_add(priv->devices, g_object_ref(device));

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_CLEAR_UPDATABLE)) {
		if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_USER_WARNING)) {
			fu_device_inhibit(device, "clear-updatable", fu_plugin_build_device_update_error(self));

		} else {
			fu_device_inhibit(device, "clear-updatable", "Plugin disallowed updates with no user warning");

		}
	}

	g_debug("emit added from %s: %s", fu_plugin_get_name(self), fu_device_get_id(device));
	fu_device_set_created(device, (guint64)g_get_real_time() / G_USEC_PER_SEC);
	fu_device_set_plugin(device, fu_plugin_get_name(self));
	g_signal_emit(self, signals[SIGNAL_DEVICE_ADDED], 0, device);

	
	children = fu_device_get_children(device);
	for (guint i = 0; i < children->len; i++) {
		FuDevice *child = g_ptr_array_index(children, i);
		if (fu_device_get_created(child) == 0)
			fu_plugin_device_add(self, child);
	}

	
	g_signal_connect(FU_DEVICE(device), "child-added", G_CALLBACK(fu_plugin_device_child_added_cb), self);


	g_signal_connect(FU_DEVICE(device), "child-removed", G_CALLBACK(fu_plugin_device_child_removed_cb), self);


}


GPtrArray * fu_plugin_get_devices(FuPlugin *self)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	g_return_val_if_fail(FU_IS_PLUGIN(self), NULL);
	fu_plugin_ensure_devices(self);
	return priv->devices;
}


void fu_plugin_device_register(FuPlugin *self, FuDevice *device)
{
	g_autoptr(GError) error = NULL;

	g_return_if_fail(FU_IS_PLUGIN(self));
	g_return_if_fail(FU_IS_DEVICE(device));

	
	if (!fu_device_ensure_id(device, &error)) {
		g_warning("ignoring registration: %s", error->message);
		return;
	}

	g_debug("emit device-register from %s: %s", fu_plugin_get_name(self), fu_device_get_id(device));

	g_signal_emit(self, signals[SIGNAL_DEVICE_REGISTER], 0, device);
}


void fu_plugin_device_remove(FuPlugin *self, FuDevice *device)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);

	g_return_if_fail(FU_IS_PLUGIN(self));
	g_return_if_fail(FU_IS_DEVICE(device));

	
	if (priv->devices != NULL)
		g_ptr_array_remove(priv->devices, device);

	g_debug("emit removed from %s: %s", fu_plugin_get_name(self), fu_device_get_id(device));
	g_signal_emit(self, signals[SIGNAL_DEVICE_REMOVED], 0, device);
}


static gboolean fu_plugin_check_supported(FuPlugin *self, const gchar *guid)
{
	gboolean retval = FALSE;
	g_signal_emit(self, signals[SIGNAL_CHECK_SUPPORTED], 0, guid, &retval);
	return retval;
}


FuContext * fu_plugin_get_context(FuPlugin *self)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	return priv->ctx;
}

static gboolean fu_plugin_device_attach(FuPlugin *self, FuDevice *device, FuProgress *progress, GError **error)
{
	FuDevice *proxy = fu_device_get_proxy_with_fallback(device);
	FuDeviceClass *proxy_klass = FU_DEVICE_GET_CLASS(proxy);
	g_autoptr(FuDeviceLocker) locker = NULL;
	if (proxy_klass->attach == NULL)
		return TRUE;
	locker = fu_device_locker_new(proxy, error);
	if (locker == NULL)
		return FALSE;
	return fu_device_attach_full(device, progress, error);
}

static gboolean fu_plugin_device_detach(FuPlugin *self, FuDevice *device, FuProgress *progress, GError **error)
{
	FuDevice *proxy = fu_device_get_proxy_with_fallback(device);
	FuDeviceClass *proxy_klass = FU_DEVICE_GET_CLASS(proxy);
	g_autoptr(FuDeviceLocker) locker = NULL;
	if (proxy_klass->detach == NULL)
		return TRUE;
	locker = fu_device_locker_new(proxy, error);
	if (locker == NULL)
		return FALSE;
	return fu_device_detach_full(device, progress, error);
}

static gboolean fu_plugin_device_activate(FuPlugin *self, FuDevice *device, FuProgress *progress, GError **error)
{
	FuDevice *proxy = fu_device_get_proxy_with_fallback(device);
	FuDeviceClass *proxy_klass = FU_DEVICE_GET_CLASS(proxy);
	g_autoptr(FuDeviceLocker) locker = NULL;
	if (proxy_klass->activate == NULL)
		return TRUE;
	locker = fu_device_locker_new(proxy, error);
	if (locker == NULL)
		return FALSE;
	return fu_device_activate(device, progress, error);
}

static gboolean fu_plugin_device_write_firmware(FuPlugin *self, FuDevice *device, GBytes *fw, FuProgress *progress, FwupdInstallFlags flags, GError **error)





{
	FuDevice *proxy = fu_device_get_proxy_with_fallback(device);
	g_autoptr(FuDeviceLocker) locker = NULL;
	locker = fu_device_locker_new(proxy, error);
	if (locker == NULL)
		return FALSE;

	
	if (fu_device_has_flag(device, FWUPD_DEVICE_FLAG_BACKUP_BEFORE_INSTALL)) {
		g_autoptr(GBytes) fw_old = NULL;
		g_autofree gchar *path = NULL;
		g_autofree gchar *fn = NULL;
		g_autofree gchar *localstatedir = NULL;

		
		fu_progress_set_id(progress, G_STRLOC);
		fu_progress_add_flag(progress, FU_PROGRESS_FLAG_NO_PROFILE);
		fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_READ, 25, NULL);
		fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 75, NULL);

		fw_old = fu_device_dump_firmware(device, fu_progress_get_child(progress), error);
		if (fw_old == NULL) {
			g_prefix_error(error, "failed to backup old firmware: ");
			return FALSE;
		}
		localstatedir = fu_path_from_kind(FU_PATH_KIND_LOCALSTATEDIR_PKG);
		fn = g_strdup_printf("%s.bin", fu_device_get_version(device));
		path = g_build_filename( localstatedir, "backup", fu_device_get_id(device), fu_device_get_serial(device) != NULL ? fu_device_get_serial(device) : "default", fn, NULL);





		fu_progress_step_done(progress);
		if (!fu_bytes_set_contents(path, fw_old, error))
			return FALSE;
		if (!fu_device_write_firmware(device, fw, fu_progress_get_child(progress), flags, error))



			return FALSE;
		fu_progress_step_done(progress);
		return TRUE;
	}

	return fu_device_write_firmware(device, fw, progress, flags, error);
}

static gboolean fu_plugin_device_get_results(FuPlugin *self, FuDevice *device, GError **error)
{
	g_autoptr(FuDeviceLocker) locker = NULL;
	g_autoptr(GError) error_local = NULL;
	locker = fu_device_locker_new(device, error);
	if (locker == NULL)
		return FALSE;
	if (!fu_device_get_results(device, &error_local)) {
		if (g_error_matches(error_local, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED))
			return TRUE;
		g_propagate_error(error, g_steal_pointer(&error_local));
		return FALSE;
	}
	return TRUE;
}

static gboolean fu_plugin_device_read_firmware(FuPlugin *self, FuDevice *device, FuProgress *progress, GError **error)



{
	FuDevice *proxy = fu_device_get_proxy_with_fallback(device);
	g_autoptr(FuDeviceLocker) locker = NULL;
	g_autoptr(FuFirmware) firmware = NULL;
	g_autoptr(GBytes) fw = NULL;
	GChecksumType checksum_types[] = {G_CHECKSUM_SHA1, G_CHECKSUM_SHA256, 0};
	locker = fu_device_locker_new(proxy, error);
	if (locker == NULL)
		return FALSE;
	if (!fu_device_detach_full(device, progress, error))
		return FALSE;
	firmware = fu_device_read_firmware(device, progress, error);
	if (firmware == NULL) {
		g_autoptr(GError) error_local = NULL;
		if (!fu_device_attach_full(device, progress, &error_local))
			g_debug("ignoring attach failure: %s", error_local->message);
		g_prefix_error(error, "failed to read firmware: ");
		return FALSE;
	}
	fw = fu_firmware_write(firmware, error);
	if (fw == NULL) {
		g_autoptr(GError) error_local = NULL;
		if (!fu_device_attach_full(device, progress, &error_local))
			g_debug("ignoring attach failure: %s", error_local->message);
		g_prefix_error(error, "failed to write firmware: ");
		return FALSE;
	}
	for (guint i = 0; checksum_types[i] != 0; i++) {
		g_autofree gchar *hash = NULL;
		hash = g_compute_checksum_for_bytes(checksum_types[i], fw);
		fu_device_add_checksum(device, hash);
	}
	return fu_device_attach_full(device, progress, error);
}


gboolean fu_plugin_runner_startup(FuPlugin *self, FuProgress *progress, GError **error)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_autofree gchar *config_filename = fu_plugin_get_config_filename(self);
	g_autoptr(GError) error_local = NULL;
	g_autoptr(GFile) file = g_file_new_for_path(config_filename);

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);

	
	fu_progress_set_name(progress, fu_plugin_get_name(self));

	
	fu_plugin_runner_init(self);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (vfuncs->startup == NULL)
		return TRUE;
	g_debug("startup(%s)", fu_plugin_get_name(self));
	if (!vfuncs->startup(self, progress, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in startup(%s)", fu_plugin_get_name(self));
			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to startup using %s: ", fu_plugin_get_name(self));


		return FALSE;
	}

	
	priv->config_monitor = g_file_monitor_file(file, G_FILE_MONITOR_NONE, NULL, error);
	if (priv->config_monitor == NULL)
		return FALSE;
	g_signal_connect(G_FILE_MONITOR(priv->config_monitor), "changed", G_CALLBACK(fu_plugin_config_monitor_changed_cb), self);



	
	return TRUE;
}


void fu_plugin_runner_init(FuPlugin *self)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	FuPluginPrivate *priv = GET_PRIVATE(self);

	g_return_if_fail(FU_IS_PLUGIN(self));

	
	if (priv->done_init)
		return;

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return;

	
	if (vfuncs->init != NULL) {
		g_debug("init(%s)", fu_plugin_get_name(self));
		vfuncs->init(self);
		priv->done_init = TRUE;
	}
}

static gboolean fu_plugin_runner_device_generic(FuPlugin *self, FuDevice *device, const gchar *symbol_name, FuPluginDeviceFunc device_func, GError **error)




{
	g_autoptr(GError) error_local = NULL;

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (device_func == NULL)
		return TRUE;
	g_debug("%s(%s)", symbol_name + 10, fu_plugin_get_name(self));
	if (!device_func(self, device, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in %s(%s)", fu_plugin_get_name(self), symbol_name + 10);

			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to %s using %s: ", symbol_name + 10, fu_plugin_get_name(self));



		return FALSE;
	}
	return TRUE;
}

static gboolean fu_plugin_runner_device_generic_progress(FuPlugin *self, FuDevice *device, FuProgress *progress, const gchar *symbol_name, FuPluginDeviceProgressFunc device_func, GError **error)





{
	g_autoptr(GError) error_local = NULL;

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (device_func == NULL)
		return TRUE;
	g_debug("%s(%s)", symbol_name + 10, fu_plugin_get_name(self));
	if (!device_func(self, device, progress, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in %s(%s)", fu_plugin_get_name(self), symbol_name + 10);

			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to %s using %s: ", symbol_name + 10, fu_plugin_get_name(self));



		return FALSE;
	}
	return TRUE;
}

static gboolean fu_plugin_runner_flagged_device_generic(FuPlugin *self, FuDevice *device, FuProgress *progress, FwupdInstallFlags flags, const gchar *symbol_name, FuPluginFlaggedDeviceFunc func, GError **error)






{
	g_autoptr(GError) error_local = NULL;

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (func == NULL)
		return TRUE;
	g_debug("%s(%s)", symbol_name + 10, fu_plugin_get_name(self));
	if (!func(self, device, progress, flags, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in %s(%s)", fu_plugin_get_name(self), symbol_name + 10);

			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to %s using %s: ", symbol_name + 10, fu_plugin_get_name(self));



		return FALSE;
	}
	return TRUE;
}

static gboolean fu_plugin_runner_device_array_generic(FuPlugin *self, GPtrArray *devices, const gchar *symbol_name, FuPluginDeviceArrayFunc func, GError **error)




{
	g_autoptr(GError) error_local = NULL;

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (func == NULL)
		return TRUE;
	g_debug("%s(%s)", symbol_name + 10, fu_plugin_get_name(self));
	if (!func(self, devices, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in for %s(%s)", fu_plugin_get_name(self), symbol_name + 10);

			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to %s using %s: ", symbol_name + 10, fu_plugin_get_name(self));



		return FALSE;
	}
	return TRUE;
}


gboolean fu_plugin_runner_coldplug(FuPlugin *self, FuProgress *progress, GError **error)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_autoptr(GError) error_local = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);

	
	fu_progress_set_name(progress, fu_plugin_get_name(self));

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_REQUIRE_HWID))
		return TRUE;

	
	if (vfuncs->coldplug == NULL)
		return TRUE;
	g_debug("coldplug(%s)", fu_plugin_get_name(self));
	if (!vfuncs->coldplug(self, progress, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in coldplug(%s)", fu_plugin_get_name(self));
			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		
		if (priv->devices != NULL) {
			for (guint i = 0; i < priv->devices->len; i++) {
				FuDevice *device = g_ptr_array_index(priv->devices, i);
				g_warning("removing device %s due to failed coldplug", fu_device_get_id(device));
				fu_plugin_device_remove(self, device);
			}
		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to coldplug using %s: ", fu_plugin_get_name(self));


		return FALSE;
	}
	return TRUE;
}


gboolean fu_plugin_runner_composite_prepare(FuPlugin *self, GPtrArray *devices, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	return fu_plugin_runner_device_array_generic(self, devices, "fu_plugin_composite_prepare", vfuncs->composite_prepare, error);



}


gboolean fu_plugin_runner_composite_cleanup(FuPlugin *self, GPtrArray *devices, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	return fu_plugin_runner_device_array_generic(self, devices, "fu_plugin_composite_cleanup", vfuncs->composite_cleanup, error);



}


gboolean fu_plugin_runner_prepare(FuPlugin *self, FuDevice *device, FuProgress *progress, FwupdInstallFlags flags, GError **error)




{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	fu_device_add_backend_tag(device, "prepare");
	return fu_plugin_runner_flagged_device_generic(self, device, progress, flags, "fu_plugin_prepare", vfuncs->prepare, error);





}


gboolean fu_plugin_runner_cleanup(FuPlugin *self, FuDevice *device, FuProgress *progress, FwupdInstallFlags flags, GError **error)




{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	fu_device_add_backend_tag(device, "cleanup");
	return fu_plugin_runner_flagged_device_generic(self, device, progress, flags, "fu_plugin_cleanup", vfuncs->cleanup, error);





}


gboolean fu_plugin_runner_attach(FuPlugin *self, FuDevice *device, FuProgress *progress, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	fu_device_add_backend_tag(device, "attach");
	return fu_plugin_runner_device_generic_progress( self, device, progress, "fu_plugin_attach", vfuncs->attach != NULL ? vfuncs->attach : fu_plugin_device_attach, error);





}


gboolean fu_plugin_runner_detach(FuPlugin *self, FuDevice *device, FuProgress *progress, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	fu_device_add_backend_tag(device, "detach");
	return fu_plugin_runner_device_generic_progress( self, device, progress, "fu_plugin_detach", vfuncs->detach != NULL ? vfuncs->detach : fu_plugin_device_detach, error);





}


gboolean fu_plugin_runner_reload(FuPlugin *self, FuDevice *device, GError **error)
{
	FuDevice *proxy = fu_device_get_proxy_with_fallback(device);
	g_autoptr(FuDeviceLocker) locker = NULL;

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	locker = fu_device_locker_new(proxy, error);
	if (locker == NULL)
		return FALSE;
	fu_device_add_backend_tag(device, "reload");
	return fu_device_reload(device, error);
}


void fu_plugin_runner_add_security_attrs(FuPlugin *self, FuSecurityAttrs *attrs)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);

	
	if (vfuncs->add_security_attrs == NULL)
		return;
	g_debug("add_security_attrs(%s)", fu_plugin_get_name(self));
	vfuncs->add_security_attrs(self, attrs);
}


void fu_plugin_add_device_gtype(FuPlugin *self, GType device_gtype)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);

	
	if (priv->device_gtypes == NULL)
		priv->device_gtypes = g_array_new(FALSE, FALSE, sizeof(GType));

	
	g_type_ensure(device_gtype);
	g_array_append_val(priv->device_gtypes, device_gtype);
}

static gchar * fu_common_string_uncamelcase(const gchar *str)
{
	GString *tmp = g_string_new(NULL);
	for (guint i = 0; str[i] != '\0'; i++) {
		if (g_ascii_islower(str[i]) || g_ascii_isdigit(str[i])) {
			g_string_append_c(tmp, str[i]);
			continue;
		}
		if (i > 0)
			g_string_append_c(tmp, '-');
		g_string_append_c(tmp, g_ascii_tolower(str[i]));
	}
	return g_string_free(tmp, FALSE);
}

static gboolean fu_plugin_check_amdgpu_dpaux(FuPlugin *self, GError **error)
{

	gsize bufsz = 0;
	g_autofree gchar *buf = NULL;
	g_auto(GStrv) lines = NULL;

	
	if (!g_file_test("/proc/modules", G_FILE_TEST_EXISTS))
		return TRUE;
	if (!g_file_get_contents("/proc/modules", &buf, &bufsz, error))
		return FALSE;
	lines = g_strsplit(buf, "\n", -1);
	for (guint i = 0; lines[i] != NULL; i++) {
		if (g_str_has_prefix(lines[i], "amdgpu ")) {
			
			return fu_kernel_check_version("5.2.0", error);
		}
	}

	return TRUE;
}


void fu_plugin_add_udev_subsystem(FuPlugin *self, const gchar *subsystem)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);

	
	if (g_strcmp0(subsystem, "drm_dp_aux_dev") == 0) {
		g_autoptr(GError) error = NULL;
		if (!fu_plugin_check_amdgpu_dpaux(self, &error)) {
			g_warning("failed to add subsystem: %s", error->message);
			fu_plugin_add_flag(self, FWUPD_PLUGIN_FLAG_DISABLED);
			fu_plugin_add_flag(self, FWUPD_PLUGIN_FLAG_KERNEL_TOO_OLD);
			return;
		}
	}

	
	fu_context_add_udev_subsystem(priv->ctx, subsystem);
}


void fu_plugin_add_firmware_gtype(FuPlugin *self, const gchar *id, GType gtype)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	g_autofree gchar *id_safe = NULL;
	if (id != NULL) {
		id_safe = g_strdup(id);
	} else {
		g_autoptr(GString) str = g_string_new(g_type_name(gtype));
		if (g_str_has_prefix(str->str, "Fu"))
			g_string_erase(str, 0, 2);
		fu_string_replace(str, "Firmware", "");
		id_safe = fu_common_string_uncamelcase(str->str);
	}
	fu_context_add_firmware_gtype(priv->ctx, id_safe, gtype);
}

static gboolean fu_plugin_check_supported_device(FuPlugin *self, FuDevice *device)
{
	GPtrArray *instance_ids = fu_device_get_instance_ids(device);
	for (guint i = 0; i < instance_ids->len; i++) {
		const gchar *instance_id = g_ptr_array_index(instance_ids, i);
		g_autofree gchar *guid = fwupd_guid_hash_string(instance_id);
		if (fu_plugin_check_supported(self, guid))
			return TRUE;
	}
	return FALSE;
}

static gboolean fu_plugin_backend_device_added(FuPlugin *self, FuDevice *device, GError **error)
{
	FuDevice *proxy;
	FuPluginPrivate *priv = GET_PRIVATE(self);
	GType device_gtype = fu_device_get_specialized_gtype(FU_DEVICE(device));
	g_autoptr(FuDevice) dev = NULL;
	g_autoptr(FuDeviceLocker) locker = NULL;

	
	if (device_gtype == G_TYPE_INVALID) {
		if (priv->device_gtypes->len > 1) {
			g_set_error_literal(error, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "too many GTypes to choose a default");


			return FALSE;
		}
		device_gtype = g_array_index(priv->device_gtypes, GType, 0);
	}

	
	dev = g_object_new(device_gtype, "context", priv->ctx, NULL);
	fu_device_incorporate(dev, FU_DEVICE(device));
	if (!fu_plugin_runner_device_created(self, dev, error))
		return FALSE;

	
	if (fu_device_has_internal_flag(dev, FU_DEVICE_INTERNAL_FLAG_ONLY_SUPPORTED)) {
		if (!fu_device_probe(dev, error))
			return FALSE;
		fu_device_convert_instance_ids(dev);
		if (!fu_plugin_check_supported_device(self, dev)) {
			g_autofree gchar *guids = fu_device_get_guids_as_str(dev);
			g_debug("%s has no updates, so ignoring device", guids);
			return TRUE;
		}
	}

	
	proxy = fu_device_get_proxy(device);
	if (proxy != NULL) {
		g_autoptr(FuDeviceLocker) locker_proxy = NULL;
		locker_proxy = fu_device_locker_new(proxy, error);
		if (locker_proxy == NULL)
			return FALSE;
	}
	locker = fu_device_locker_new(dev, error);
	if (locker == NULL)
		return FALSE;
	fu_plugin_device_add(self, dev);
	fu_plugin_runner_device_added(self, dev);
	return TRUE;
}


gboolean fu_plugin_runner_backend_device_added(FuPlugin *self, FuDevice *device, GError **error)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_autoptr(GError) error_local = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (vfuncs->backend_device_added == NULL) {
		if (priv->device_gtypes != NULL || fu_device_get_specialized_gtype(device) != G_TYPE_INVALID) {
			return fu_plugin_backend_device_added(self, device, error);
		}
		g_set_error_literal(error, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "No device GType set");


		return FALSE;
	}
	g_debug("backend_device_added(%s)", fu_plugin_get_name(self));
	if (!vfuncs->backend_device_added(self, device, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in backend_device_added(%s)", fu_plugin_get_name(self));
			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to add device using on %s: ", fu_plugin_get_name(self));


		return FALSE;
	}
	return TRUE;
}


gboolean fu_plugin_runner_backend_device_changed(FuPlugin *self, FuDevice *device, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_autoptr(GError) error_local = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (vfuncs->backend_device_changed == NULL)
		return TRUE;
	g_debug("udev_device_changed(%s)", fu_plugin_get_name(self));
	if (!vfuncs->backend_device_changed(self, device, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in udev_device_changed(%s)", fu_plugin_get_name(self));
			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to change device on %s: ", fu_plugin_get_name(self));


		return FALSE;
	}
	return TRUE;
}


void fu_plugin_runner_device_added(FuPlugin *self, FuDevice *device)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return;

	
	if (vfuncs->device_added == NULL)
		return;
	g_debug("fu_plugin_device_added(%s)", fu_plugin_get_name(self));
	vfuncs->device_added(self, device);
}


void fu_plugin_runner_device_removed(FuPlugin *self, FuDevice *device)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_autoptr(GError) error_local = NULL;

	if (!fu_plugin_runner_device_generic(self, device, "fu_plugin_backend_device_removed", vfuncs->backend_device_removed, &error_local))



		g_warning("%s", error_local->message);
}


void fu_plugin_runner_device_register(FuPlugin *self, FuDevice *device)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return;

	
	if (vfuncs->device_registered != NULL) {
		g_debug("fu_plugin_device_registered(%s)", fu_plugin_get_name(self));
		vfuncs->device_registered(self, device);
	}
}


gboolean fu_plugin_runner_device_created(FuPlugin *self, FuDevice *device, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (vfuncs->device_created == NULL)
		return TRUE;
	g_debug("fu_plugin_device_created(%s)", fu_plugin_get_name(self));
	return vfuncs->device_created(self, device, error);
}


gboolean fu_plugin_runner_verify(FuPlugin *self, FuDevice *device, FuProgress *progress, FuPluginVerifyFlags flags, GError **error)




{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	GPtrArray *checksums;
	g_autoptr(GError) error_local = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(FU_IS_PROGRESS(progress), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (vfuncs->verify == NULL) {
		if (!fu_device_has_flag(device, FWUPD_DEVICE_FLAG_CAN_VERIFY)) {
			g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED, "device %s does not support verification", fu_device_get_id(device));



			return FALSE;
		}
		return fu_plugin_device_read_firmware(self, device, progress, error);
	}

	
	checksums = fu_device_get_checksums(device);
	g_ptr_array_set_size(checksums, 0);

	
	if (!fu_plugin_runner_device_generic_progress( self, device, progress, "fu_plugin_detach", vfuncs->detach != NULL ? vfuncs->detach : fu_plugin_device_detach, error))





		return FALSE;

	
	g_debug("verify(%s)", fu_plugin_get_name(self));
	if (!vfuncs->verify(self, device, progress, flags, &error_local)) {
		g_autoptr(GError) error_attach = NULL;
		if (error_local == NULL) {
			g_critical("unset plugin error in verify(%s)", fu_plugin_get_name(self));
			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to verify using %s: ", fu_plugin_get_name(self));


		
		if (!fu_plugin_runner_device_generic_progress( self, device, progress, "fu_plugin_attach", vfuncs->attach != NULL ? vfuncs->attach : fu_plugin_device_attach, &error_attach)) {





			g_warning("failed to attach whilst aborting verify(): %s", error_attach->message);
		}
		return FALSE;
	}

	
	if (!fu_plugin_runner_device_generic_progress( self, device, progress, "fu_plugin_attach", vfuncs->attach != NULL ? vfuncs->attach : fu_plugin_device_attach, error))





		return FALSE;

	
	return TRUE;
}


gboolean fu_plugin_runner_activate(FuPlugin *self, FuDevice *device, FuProgress *progress, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	guint64 flags;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(FU_IS_PROGRESS(progress), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	flags = fu_device_get_flags(device);
	if ((flags & FWUPD_DEVICE_FLAG_NEEDS_ACTIVATION) == 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED, "Device %s does not need activation", fu_device_get_id(device));



		return FALSE;
	}

	
	fu_device_add_backend_tag(device, "activate");
	if (!fu_plugin_runner_device_generic_progress( self, device, progress, "fu_plugin_activate", vfuncs->activate != NULL ? vfuncs->activate : fu_plugin_device_activate, error))





		return FALSE;

	
	fu_device_remove_flag(device, FWUPD_DEVICE_FLAG_NEEDS_ACTIVATION);
	fu_device_set_modified(device, (guint64)g_get_real_time() / G_USEC_PER_SEC);
	return TRUE;
}


gboolean fu_plugin_runner_unlock(FuPlugin *self, FuDevice *device, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	guint64 flags;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	flags = fu_device_get_flags(device);
	if ((flags & FWUPD_DEVICE_FLAG_LOCKED) == 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_SUPPORTED, "Device %s is not locked", fu_device_get_id(device));



		return FALSE;
	}

	
	fu_device_add_backend_tag(device, "unlock");
	if (!fu_plugin_runner_device_generic(self, device, "fu_plugin_unlock", vfuncs->unlock, error))



		return FALSE;

	
	fu_device_remove_flag(device, FWUPD_DEVICE_FLAG_LOCKED);
	fu_device_set_modified(device, (guint64)g_get_real_time() / G_USEC_PER_SEC);
	return TRUE;
}


gboolean fu_plugin_runner_write_firmware(FuPlugin *self, FuDevice *device, GBytes *blob_fw, FuProgress *progress, FwupdInstallFlags flags, GError **error)





{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_autoptr(GError) error_local = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(FU_IS_PROGRESS(progress), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED)) {
		g_debug("plugin not enabled, skipping");
		return TRUE;
	}
	fu_device_add_backend_tag(device, "write-firmware");

	
	if (vfuncs->write_firmware == NULL) {
		g_debug("superclassed write_firmware(%s)", fu_plugin_get_name(self));
		return fu_plugin_device_write_firmware(self, device, blob_fw, progress, flags, error);




	}

	
	if (!vfuncs->write_firmware(self, device, blob_fw, progress, flags, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in update(%s)", fu_plugin_get_name(self));
			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


			return FALSE;
		}
		fu_device_set_update_error(device, error_local->message);
		g_propagate_error(error, g_steal_pointer(&error_local));
		return FALSE;
	}

	
	if (!fu_device_has_flag(device, FWUPD_DEVICE_FLAG_NEEDS_REBOOT) && !fu_device_has_flag(device, FWUPD_DEVICE_FLAG_NEEDS_SHUTDOWN)) {
		GPtrArray *checksums = fu_device_get_checksums(device);
		g_ptr_array_set_size(checksums, 0);
	}

	
	return TRUE;
}


gboolean fu_plugin_runner_clear_results(FuPlugin *self, FuDevice *device, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_autoptr(GError) error_local = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (vfuncs->clear_results == NULL)
		return TRUE;
	g_debug("clear_result(%s)", fu_plugin_get_name(self));
	if (!vfuncs->clear_results(self, device, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in clear_result(%s)", fu_plugin_get_name(self));
			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to clear_result using %s: ", fu_plugin_get_name(self));


		return FALSE;
	}
	return TRUE;
}


gboolean fu_plugin_runner_get_results(FuPlugin *self, FuDevice *device, GError **error)
{
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);
	g_autoptr(GError) error_local = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(FU_IS_DEVICE(device), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	
	if (fu_plugin_has_flag(self, FWUPD_PLUGIN_FLAG_DISABLED))
		return TRUE;

	
	if (vfuncs->get_results == NULL) {
		g_debug("superclassed get_results(%s)", fu_plugin_get_name(self));
		return fu_plugin_device_get_results(self, device, error);
	}
	g_debug("get_results(%s)", fu_plugin_get_name(self));
	if (!vfuncs->get_results(self, device, &error_local)) {
		if (error_local == NULL) {
			g_critical("unset plugin error in get_results(%s)", fu_plugin_get_name(self));
			g_set_error_literal(&error_local, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "unspecified error");


		}
		g_propagate_prefixed_error(error, g_steal_pointer(&error_local), "failed to get_results using %s: ", fu_plugin_get_name(self));


		return FALSE;
	}
	return TRUE;
}


guint fu_plugin_get_order(FuPlugin *self)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	return priv->order;
}


void fu_plugin_set_order(FuPlugin *self, guint order)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	priv->order = order;
}


guint fu_plugin_get_priority(FuPlugin *self)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	return priv->priority;
}


void fu_plugin_set_priority(FuPlugin *self, guint priority)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	priv->priority = priority;
}


void fu_plugin_add_rule(FuPlugin *self, FuPluginRule rule, const gchar *name)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	if (priv->rules[rule] == NULL)
		priv->rules[rule] = g_ptr_array_new_with_free_func(g_free);
	g_ptr_array_add(priv->rules[rule], g_strdup(name));
	g_signal_emit(self, signals[SIGNAL_RULES_CHANGED], 0);
}


GPtrArray * fu_plugin_get_rules(FuPlugin *self, FuPluginRule rule)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	g_return_val_if_fail(rule < FU_PLUGIN_RULE_LAST, NULL);
	return priv->rules[rule];
}


gboolean fu_plugin_has_rule(FuPlugin *self, FuPluginRule rule, const gchar *name)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	if (priv->rules[rule] == NULL)
		return FALSE;
	for (guint i = 0; i < priv->rules[rule]->len; i++) {
		const gchar *tmp = g_ptr_array_index(priv->rules[rule], i);
		if (g_strcmp0(tmp, name) == 0)
			return TRUE;
	}
	return FALSE;
}


void fu_plugin_add_report_metadata(FuPlugin *self, const gchar *key, const gchar *value)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	if (priv->report_metadata == NULL) {
		priv->report_metadata = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}
	g_hash_table_insert(priv->report_metadata, g_strdup(key), g_strdup(value));
}


GHashTable * fu_plugin_get_report_metadata(FuPlugin *self)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	return priv->report_metadata;
}


gchar * fu_plugin_get_config_value(FuPlugin *self, const gchar *key)
{
	g_autofree gchar *conf_path = fu_plugin_get_config_filename(self);
	g_autoptr(GKeyFile) keyfile = NULL;
	if (!g_file_test(conf_path, G_FILE_TEST_IS_REGULAR))
		return NULL;
	keyfile = g_key_file_new();
	if (!g_key_file_load_from_file(keyfile, conf_path, G_KEY_FILE_NONE, NULL))
		return NULL;
	return g_key_file_get_string(keyfile, fu_plugin_get_name(self), key, NULL);
}


FwupdSecurityAttr * fu_plugin_security_attr_new(FuPlugin *self, const gchar *appstream_id)
{
	FuPluginPrivate *priv = fu_plugin_get_instance_private(self);
	g_autoptr(FwupdSecurityAttr) attr = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), NULL);
	g_return_val_if_fail(appstream_id != NULL, NULL);

	attr = fu_security_attr_new(priv->ctx, appstream_id);
	fwupd_security_attr_set_plugin(attr, fu_plugin_get_name(self));
	return g_steal_pointer(&attr);
}


gboolean fu_plugin_set_config_value(FuPlugin *self, const gchar *key, const gchar *value, GError **error)
{
	g_autofree gchar *conf_path = fu_plugin_get_config_filename(self);
	g_autoptr(GKeyFile) keyfile = NULL;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	keyfile = g_key_file_new();
	if (!g_key_file_load_from_file(keyfile, conf_path, G_KEY_FILE_KEEP_COMMENTS, error))
		return FALSE;
	g_key_file_set_string(keyfile, fu_plugin_get_name(self), key, value);
	return g_key_file_save_to_file(keyfile, conf_path, error);
}


gboolean fu_plugin_set_secure_config_value(FuPlugin *self, const gchar *key, const gchar *value, GError **error)



{
	g_autofree gchar *conf_path = fu_plugin_get_config_filename(self);
	gint ret;

	g_return_val_if_fail(FU_IS_PLUGIN(self), FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_file_test(conf_path, G_FILE_TEST_EXISTS)) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_NOT_FOUND, "%s is missing", conf_path);
		return FALSE;
	}
	ret = g_chmod(conf_path, 0660);
	if (ret == -1) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INTERNAL, "failed to set permissions on %s", conf_path);



		return FALSE;
	}

	return fu_plugin_set_config_value(self, key, value, error);
}


gboolean fu_plugin_get_config_value_boolean(FuPlugin *self, const gchar *key)
{
	g_autofree gchar *tmp = fu_plugin_get_config_value(self, key);
	if (tmp == NULL)
		return FALSE;
	return g_ascii_strcasecmp(tmp, "true") == 0;
}


gint fu_plugin_name_compare(FuPlugin *plugin1, FuPlugin *plugin2)
{
	return g_strcmp0(fu_plugin_get_name(plugin1), fu_plugin_get_name(plugin2));
}


gint fu_plugin_order_compare(FuPlugin *plugin1, FuPlugin *plugin2)
{
	FuPluginPrivate *priv1 = fu_plugin_get_instance_private(plugin1);
	FuPluginPrivate *priv2 = fu_plugin_get_instance_private(plugin2);
	if (priv1->order < priv2->order)
		return -1;
	if (priv1->order > priv2->order)
		return 1;
	return fu_plugin_name_compare(plugin1, plugin2);
}

static void fu_plugin_class_init(FuPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = fu_plugin_finalize;

	
	signals[SIGNAL_DEVICE_ADDED] = g_signal_new("device-added", G_TYPE_FROM_CLASS(object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET(FuPluginClass, device_added), NULL, NULL, g_cclosure_marshal_VOID__OBJECT, G_TYPE_NONE, 1, FU_TYPE_DEVICE);








	
	signals[SIGNAL_DEVICE_REMOVED] = g_signal_new("device-removed", G_TYPE_FROM_CLASS(object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET(FuPluginClass, device_removed), NULL, NULL, g_cclosure_marshal_VOID__OBJECT, G_TYPE_NONE, 1, FU_TYPE_DEVICE);









	
	signals[SIGNAL_DEVICE_REGISTER] = g_signal_new("device-register", G_TYPE_FROM_CLASS(object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET(FuPluginClass, device_register), NULL, NULL, g_cclosure_marshal_VOID__OBJECT, G_TYPE_NONE, 1, FU_TYPE_DEVICE);









	
	signals[SIGNAL_CHECK_SUPPORTED] = g_signal_new("check-supported", G_TYPE_FROM_CLASS(object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET(FuPluginClass, check_supported), NULL, NULL, g_cclosure_marshal_generic, G_TYPE_BOOLEAN, 1, G_TYPE_STRING);









	signals[SIGNAL_RULES_CHANGED] = g_signal_new("rules-changed", G_TYPE_FROM_CLASS(object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET(FuPluginClass, rules_changed), NULL, NULL, g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);







	
	signals[SIGNAL_CONFIG_CHANGED] = g_signal_new("config-changed", G_TYPE_FROM_CLASS(object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET(FuPluginClass, config_changed), NULL, NULL, g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);








}

static void fu_plugin_init(FuPlugin *self)
{
	FuPluginPrivate *priv = GET_PRIVATE(self);
	g_rw_lock_init(&priv->cache_mutex);
}

static void fu_plugin_finalize(GObject *object)
{
	FuPlugin *self = FU_PLUGIN(object);
	FuPluginPrivate *priv = GET_PRIVATE(self);
	FuPluginVfuncs *vfuncs = fu_plugin_get_vfuncs(self);

	g_rw_lock_clear(&priv->cache_mutex);

	
	if (priv->done_init && vfuncs->destroy != NULL) {
		g_debug("destroy(%s)", fu_plugin_get_name(self));
		vfuncs->destroy(self);
	}

	for (guint i = 0; i < FU_PLUGIN_RULE_LAST; i++) {
		if (priv->rules[i] != NULL)
			g_ptr_array_unref(priv->rules[i]);
	}
	if (priv->devices != NULL)
		g_ptr_array_unref(priv->devices);
	if (priv->ctx != NULL)
		g_object_unref(priv->ctx);
	if (priv->runtime_versions != NULL)
		g_hash_table_unref(priv->runtime_versions);
	if (priv->compile_versions != NULL)
		g_hash_table_unref(priv->compile_versions);
	if (priv->report_metadata != NULL)
		g_hash_table_unref(priv->report_metadata);
	if (priv->cache != NULL)
		g_hash_table_unref(priv->cache);
	if (priv->device_gtypes != NULL)
		g_array_unref(priv->device_gtypes);
	if (priv->config_monitor != NULL)
		g_object_unref(priv->config_monitor);
	g_free(priv->data);

	G_OBJECT_CLASS(fu_plugin_parent_class)->finalize(object);
}


FuPlugin * fu_plugin_new(FuContext *ctx)
{
	FuPlugin *self = FU_PLUGIN(g_object_new(FU_TYPE_PLUGIN, NULL));
	FuPluginPrivate *priv = GET_PRIVATE(self);
	if (ctx != NULL)
		priv->ctx = g_object_ref(ctx);
	return self;
}