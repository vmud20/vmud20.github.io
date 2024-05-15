




























const char *flatpak_context_shares[] = {
  "network", "ipc", NULL };




const char *flatpak_context_sockets[] = {
  "x11", "wayland", "pulseaudio", "session-bus", "system-bus", "fallback-x11", "ssh-auth", "pcsc", "cups", NULL };










const char *flatpak_context_devices[] = {
  "dri", "all", "kvm", "shm", NULL };





const char *flatpak_context_features[] = {
  "devel", "multiarch", "bluetooth", "canbus", "per-app-dev-shm", NULL };






const char *flatpak_context_special_filesystems[] = {
  "home", "host", "host-etc", "host-os", NULL };





FlatpakContext * flatpak_context_new (void)
{
  FlatpakContext *context;

  context = g_slice_new0 (FlatpakContext);
  context->env_vars = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  context->persistent = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  
  context->filesystems = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  context->session_bus_policy = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  context->system_bus_policy = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  context->generic_policy = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_strfreev);

  return context;
}

void flatpak_context_free (FlatpakContext *context)
{
  g_hash_table_destroy (context->env_vars);
  g_hash_table_destroy (context->persistent);
  g_hash_table_destroy (context->filesystems);
  g_hash_table_destroy (context->session_bus_policy);
  g_hash_table_destroy (context->system_bus_policy);
  g_hash_table_destroy (context->generic_policy);
  g_slice_free (FlatpakContext, context);
}

static guint32 flatpak_context_bitmask_from_string (const char *name, const char **names)
{
  guint32 i;

  for (i = 0; names[i] != NULL; i++)
    {
      if (strcmp (names[i], name) == 0)
        return 1 << i;
    }

  return 0;
}

static char ** flatpak_context_bitmask_to_string (guint32 enabled, guint32 valid, const char **names)
{
  guint32 i;
  GPtrArray *array;

  array = g_ptr_array_new ();

  for (i = 0; names[i] != NULL; i++)
    {
      guint32 bitmask = 1 << i;
      if (valid & bitmask)
        {
          if (enabled & bitmask)
            g_ptr_array_add (array, g_strdup (names[i]));
          else g_ptr_array_add (array, g_strdup_printf ("!%s", names[i]));
        }
    }

  g_ptr_array_add (array, NULL);
  return (char **) g_ptr_array_free (array, FALSE);
}

static void flatpak_context_bitmask_to_args (guint32 enabled, guint32 valid, const char **names, const char *enable_arg, const char *disable_arg, GPtrArray *args)


{
  guint32 i;

  for (i = 0; names[i] != NULL; i++)
    {
      guint32 bitmask = 1 << i;
      if (valid & bitmask)
        {
          if (enabled & bitmask)
            g_ptr_array_add (args, g_strdup_printf ("%s=%s", enable_arg, names[i]));
          else g_ptr_array_add (args, g_strdup_printf ("%s=%s", disable_arg, names[i]));
        }
    }
}


static FlatpakContextShares flatpak_context_share_from_string (const char *string, GError **error)
{
  FlatpakContextShares shares = flatpak_context_bitmask_from_string (string, flatpak_context_shares);

  if (shares == 0)
    {
      g_autofree char *values = g_strjoinv (", ", (char **) flatpak_context_shares);
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Unknown share type %s, valid types are: %s"), string, values);
    }

  return shares;
}

static char ** flatpak_context_shared_to_string (FlatpakContextShares shares, FlatpakContextShares valid)
{
  return flatpak_context_bitmask_to_string (shares, valid, flatpak_context_shares);
}

static void flatpak_context_shared_to_args (FlatpakContextShares shares, FlatpakContextShares valid, GPtrArray           *args)


{
  return flatpak_context_bitmask_to_args (shares, valid, flatpak_context_shares, "--share", "--unshare", args);
}

static FlatpakPolicy flatpak_policy_from_string (const char *string, GError **error)
{
  const char *policies[] = { "none", "see", "talk", "own", NULL };
  int i;
  g_autofree char *values = NULL;

  for (i = 0; policies[i]; i++)
    {
      if (strcmp (string, policies[i]) == 0)
        return i;
    }

  values = g_strjoinv (", ", (char **) policies);
  g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Unknown policy type %s, valid types are: %s"), string, values);

  return -1;
}

static const char * flatpak_policy_to_string (FlatpakPolicy policy)
{
  if (policy == FLATPAK_POLICY_SEE)
    return "see";
  if (policy == FLATPAK_POLICY_TALK)
    return "talk";
  if (policy == FLATPAK_POLICY_OWN)
    return "own";

  return "none";
}

static gboolean flatpak_verify_dbus_name (const char *name, GError **error)
{
  const char *name_part;
  g_autofree char *tmp = NULL;

  if (g_str_has_suffix (name, ".*"))
    {
      tmp = g_strndup (name, strlen (name) - 2);
      name_part = tmp;
    }
  else {
      name_part = name;
    }

  if (g_dbus_is_name (name_part) && !g_dbus_is_unique_name (name_part))
    return TRUE;

  g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Invalid dbus name %s"), name);
  return FALSE;
}

static FlatpakContextSockets flatpak_context_socket_from_string (const char *string, GError **error)
{
  FlatpakContextSockets sockets = flatpak_context_bitmask_from_string (string, flatpak_context_sockets);

  if (sockets == 0)
    {
      g_autofree char *values = g_strjoinv (", ", (char **) flatpak_context_sockets);
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Unknown socket type %s, valid types are: %s"), string, values);
    }

  return sockets;
}

static char ** flatpak_context_sockets_to_string (FlatpakContextSockets sockets, FlatpakContextSockets valid)
{
  return flatpak_context_bitmask_to_string (sockets, valid, flatpak_context_sockets);
}

static void flatpak_context_sockets_to_args (FlatpakContextSockets sockets, FlatpakContextSockets valid, GPtrArray            *args)


{
  return flatpak_context_bitmask_to_args (sockets, valid, flatpak_context_sockets, "--socket", "--nosocket", args);
}

static FlatpakContextDevices flatpak_context_device_from_string (const char *string, GError **error)
{
  FlatpakContextDevices devices = flatpak_context_bitmask_from_string (string, flatpak_context_devices);

  if (devices == 0)
    {
      g_autofree char *values = g_strjoinv (", ", (char **) flatpak_context_devices);
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Unknown device type %s, valid types are: %s"), string, values);
    }
  return devices;
}

static char ** flatpak_context_devices_to_string (FlatpakContextDevices devices, FlatpakContextDevices valid)
{
  return flatpak_context_bitmask_to_string (devices, valid, flatpak_context_devices);
}

static void flatpak_context_devices_to_args (FlatpakContextDevices devices, FlatpakContextDevices valid, GPtrArray            *args)


{
  return flatpak_context_bitmask_to_args (devices, valid, flatpak_context_devices, "--device", "--nodevice", args);
}

static FlatpakContextFeatures flatpak_context_feature_from_string (const char *string, GError **error)
{
  FlatpakContextFeatures feature = flatpak_context_bitmask_from_string (string, flatpak_context_features);

  if (feature == 0)
    {
      g_autofree char *values = g_strjoinv (", ", (char **) flatpak_context_features);
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Unknown feature type %s, valid types are: %s"), string, values);
    }

  return feature;
}

static char ** flatpak_context_features_to_string (FlatpakContextFeatures features, FlatpakContextFeatures valid)
{
  return flatpak_context_bitmask_to_string (features, valid, flatpak_context_features);
}

static void flatpak_context_features_to_args (FlatpakContextFeatures features, FlatpakContextFeatures valid, GPtrArray             *args)


{
  return flatpak_context_bitmask_to_args (features, valid, flatpak_context_features, "--allow", "--disallow", args);
}

static void flatpak_context_add_shares (FlatpakContext      *context, FlatpakContextShares shares)

{
  context->shares_valid |= shares;
  context->shares |= shares;
}

static void flatpak_context_remove_shares (FlatpakContext      *context, FlatpakContextShares shares)

{
  context->shares_valid |= shares;
  context->shares &= ~shares;
}

static void flatpak_context_add_sockets (FlatpakContext       *context, FlatpakContextSockets sockets)

{
  context->sockets_valid |= sockets;
  context->sockets |= sockets;
}

static void flatpak_context_remove_sockets (FlatpakContext       *context, FlatpakContextSockets sockets)

{
  context->sockets_valid |= sockets;
  context->sockets &= ~sockets;
}

static void flatpak_context_add_devices (FlatpakContext       *context, FlatpakContextDevices devices)

{
  context->devices_valid |= devices;
  context->devices |= devices;
}

static void flatpak_context_remove_devices (FlatpakContext       *context, FlatpakContextDevices devices)

{
  context->devices_valid |= devices;
  context->devices &= ~devices;
}

static void flatpak_context_add_features (FlatpakContext        *context, FlatpakContextFeatures features)

{
  context->features_valid |= features;
  context->features |= features;
}

static void flatpak_context_remove_features (FlatpakContext        *context, FlatpakContextFeatures features)

{
  context->features_valid |= features;
  context->features &= ~features;
}

static void flatpak_context_set_env_var (FlatpakContext *context, const char     *name, const char     *value)


{
  g_hash_table_insert (context->env_vars, g_strdup (name), g_strdup (value));
}

void flatpak_context_set_session_bus_policy (FlatpakContext *context, const char     *name, FlatpakPolicy   policy)


{
  g_hash_table_insert (context->session_bus_policy, g_strdup (name), GINT_TO_POINTER (policy));
}

GStrv flatpak_context_get_session_bus_policy_allowed_own_names (FlatpakContext *context)
{
  GHashTableIter iter;
  gpointer key, value;
  g_autoptr(GPtrArray) names = g_ptr_array_new_with_free_func (g_free);

  g_hash_table_iter_init (&iter, context->session_bus_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    if (GPOINTER_TO_INT (value) == FLATPAK_POLICY_OWN)
      g_ptr_array_add (names, g_strdup (key));

  g_ptr_array_add (names, NULL);
  return (GStrv) g_ptr_array_free (g_steal_pointer (&names), FALSE);
}

void flatpak_context_set_system_bus_policy (FlatpakContext *context, const char     *name, FlatpakPolicy   policy)


{
  g_hash_table_insert (context->system_bus_policy, g_strdup (name), GINT_TO_POINTER (policy));
}

static void flatpak_context_apply_generic_policy (FlatpakContext *context, const char     *key, const char     *value)


{
  GPtrArray *new = g_ptr_array_new ();
  const char **old_v;
  int i;

  g_assert (strchr (key, '.') != NULL);

  old_v = g_hash_table_lookup (context->generic_policy, key);
  for (i = 0; old_v != NULL && old_v[i] != NULL; i++)
    {
      const char *old = old_v[i];
      const char *cmp1 = old;
      const char *cmp2 = value;
      if (*cmp1 == '!')
        cmp1++;
      if (*cmp2 == '!')
        cmp2++;
      if (strcmp (cmp1, cmp2) != 0)
        g_ptr_array_add (new, g_strdup (old));
    }

  g_ptr_array_add (new, g_strdup (value));
  g_ptr_array_add (new, NULL);

  g_hash_table_insert (context->generic_policy, g_strdup (key), g_ptr_array_free (new, FALSE));
}

static void flatpak_context_set_persistent (FlatpakContext *context, const char     *path)

{
  g_hash_table_insert (context->persistent, g_strdup (path), GINT_TO_POINTER (1));
}

static gboolean get_xdg_dir_from_prefix (const char  *prefix, const char **where, const char **dir)


{
  if (strcmp (prefix, "xdg-data") == 0)
    {
      if (where)
        *where = "data";
      if (dir)
        *dir = g_get_user_data_dir ();
      return TRUE;
    }
  if (strcmp (prefix, "xdg-cache") == 0)
    {
      if (where)
        *where = "cache";
      if (dir)
        *dir = g_get_user_cache_dir ();
      return TRUE;
    }
  if (strcmp (prefix, "xdg-config") == 0)
    {
      if (where)
        *where = "config";
      if (dir)
        *dir = g_get_user_config_dir ();
      return TRUE;
    }
  return FALSE;
}


static char * get_xdg_dir_from_string (const char  *filesystem, const char **suffix, const char **where)


{
  char *slash;
  const char *rest;
  g_autofree char *prefix = NULL;
  const char *dir = NULL;
  gsize len;

  slash = strchr (filesystem, '/');

  if (slash)
    len = slash - filesystem;
  else len = strlen (filesystem);

  rest = filesystem + len;
  while (*rest == '/')
    rest++;

  if (suffix != NULL)
    *suffix = rest;

  prefix = g_strndup (filesystem, len);

  if (get_xdg_dir_from_prefix (prefix, where, &dir))
    return g_build_filename (dir, rest, NULL);

  return NULL;
}

static gboolean get_xdg_user_dir_from_string (const char  *filesystem, const char **config_key, const char **suffix, const char **dir)



{
  char *slash;
  const char *rest;
  g_autofree char *prefix = NULL;
  gsize len;

  slash = strchr (filesystem, '/');

  if (slash)
    len = slash - filesystem;
  else len = strlen (filesystem);

  rest = filesystem + len;
  while (*rest == '/')
    rest++;

  if (suffix)
    *suffix = rest;

  prefix = g_strndup (filesystem, len);

  if (strcmp (prefix, "xdg-desktop") == 0)
    {
      if (config_key)
        *config_key = "XDG_DESKTOP_DIR";
      if (dir)
        *dir = g_get_user_special_dir (G_USER_DIRECTORY_DESKTOP);
      return TRUE;
    }
  if (strcmp (prefix, "xdg-documents") == 0)
    {
      if (config_key)
        *config_key = "XDG_DOCUMENTS_DIR";
      if (dir)
        *dir = g_get_user_special_dir (G_USER_DIRECTORY_DOCUMENTS);
      return TRUE;
    }
  if (strcmp (prefix, "xdg-download") == 0)
    {
      if (config_key)
        *config_key = "XDG_DOWNLOAD_DIR";
      if (dir)
        *dir = g_get_user_special_dir (G_USER_DIRECTORY_DOWNLOAD);
      return TRUE;
    }
  if (strcmp (prefix, "xdg-music") == 0)
    {
      if (config_key)
        *config_key = "XDG_MUSIC_DIR";
      if (dir)
        *dir = g_get_user_special_dir (G_USER_DIRECTORY_MUSIC);
      return TRUE;
    }
  if (strcmp (prefix, "xdg-pictures") == 0)
    {
      if (config_key)
        *config_key = "XDG_PICTURES_DIR";
      if (dir)
        *dir = g_get_user_special_dir (G_USER_DIRECTORY_PICTURES);
      return TRUE;
    }
  if (strcmp (prefix, "xdg-public-share") == 0)
    {
      if (config_key)
        *config_key = "XDG_PUBLICSHARE_DIR";
      if (dir)
        *dir = g_get_user_special_dir (G_USER_DIRECTORY_PUBLIC_SHARE);
      return TRUE;
    }
  if (strcmp (prefix, "xdg-templates") == 0)
    {
      if (config_key)
        *config_key = "XDG_TEMPLATES_DIR";
      if (dir)
        *dir = g_get_user_special_dir (G_USER_DIRECTORY_TEMPLATES);
      return TRUE;
    }
  if (strcmp (prefix, "xdg-videos") == 0)
    {
      if (config_key)
        *config_key = "XDG_VIDEOS_DIR";
      if (dir)
        *dir = g_get_user_special_dir (G_USER_DIRECTORY_VIDEOS);
      return TRUE;
    }
  if (get_xdg_dir_from_prefix (prefix, NULL, dir))
    {
      if (config_key)
        *config_key = NULL;
      return TRUE;
    }
  
  if (strcmp (prefix, "xdg-run") == 0 && *rest != 0)
    {
      if (config_key)
        *config_key = NULL;
      if (dir)
        *dir = flatpak_get_real_xdg_runtime_dir ();
      return TRUE;
    }

  return FALSE;
}

static char * unparse_filesystem_flags (const char           *path, FlatpakFilesystemMode mode)

{
  g_autoptr(GString) s = g_string_new ("");
  const char *p;

  for (p = path; *p != 0; p++)
    {
      if (*p == ':')
        g_string_append (s, "\\:");
      else if (*p == '\\')
        g_string_append (s, "\\\\");
      else g_string_append_c (s, *p);
    }

  switch (mode)
    {
    case FLATPAK_FILESYSTEM_MODE_READ_ONLY:
      g_string_append (s, ":ro");
      break;

    case FLATPAK_FILESYSTEM_MODE_CREATE:
      g_string_append (s, ":create");
      break;

    case FLATPAK_FILESYSTEM_MODE_READ_WRITE:
      break;

    case FLATPAK_FILESYSTEM_MODE_NONE:
      g_string_insert_c (s, 0, '!');
      break;

    default:
      g_warning ("Unexpected filesystem mode %d", mode);
      break;
    }

  return g_string_free (g_steal_pointer (&s), FALSE);
}

static char * parse_filesystem_flags (const char            *filesystem, FlatpakFilesystemMode *mode_out)

{
  g_autoptr(GString) s = g_string_new ("");
  const char *p, *suffix;
  FlatpakFilesystemMode mode;

  p = filesystem;
  while (*p != 0 && *p != ':')
    {
      if (*p == '\\')
        {
          p++;
          if (*p != 0)
            g_string_append_c (s, *p++);
        }
      else g_string_append_c (s, *p++);
    }

  mode = FLATPAK_FILESYSTEM_MODE_READ_WRITE;

  if (*p == ':')
    {
      suffix = p + 1;

      if (strcmp (suffix, "ro") == 0)
        mode = FLATPAK_FILESYSTEM_MODE_READ_ONLY;
      else if (strcmp (suffix, "rw") == 0)
        mode = FLATPAK_FILESYSTEM_MODE_READ_WRITE;
      else if (strcmp (suffix, "create") == 0)
        mode = FLATPAK_FILESYSTEM_MODE_CREATE;
      else if (*suffix != 0)
        g_warning ("Unexpected filesystem suffix %s, ignoring", suffix);
    }

  if (mode_out)
    *mode_out = mode;

  return g_string_free (g_steal_pointer (&s), FALSE);
}

gboolean flatpak_context_parse_filesystem (const char             *filesystem_and_mode, char                  **filesystem_out, FlatpakFilesystemMode  *mode_out, GError                **error)



{
  g_autofree char *filesystem = parse_filesystem_flags (filesystem_and_mode, mode_out);
  char *slash;

  slash = strchr (filesystem, '/');

  
  if (slash != NULL)
    {
      if (g_str_has_prefix (slash + 1, "../") || g_str_has_suffix (slash + 1, "/..") || strstr (slash + 1, "/../") != NULL)

        {
          g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, _("Filesystem location \"%s\" contains \"..\""), filesystem);

          return FALSE;
        }

      
      for (; slash != NULL; slash = strchr (slash + 1, '/'))
        {
          while (TRUE)
            {
              if (slash[1] == '/')
                memmove (slash + 1, slash + 2, strlen (slash + 2) + 1);
              else if (slash[1] == '.' && slash[2] == '/')
                memmove (slash + 1, slash + 3, strlen (slash + 3) + 1);
              else break;
            }
        }

      
      while (TRUE)
        {
          slash = strrchr (filesystem, '/');

          if (slash != NULL && ((slash != filesystem && slash[1] == '\0') || (slash[1] == '.' && slash[2] == '\0')))

            *slash = '\0';
          else break;
        }

      if (filesystem[0] == '/' && filesystem[1] == '\0')
        {
          
          g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, _("--filesystem=/ is not available, " "use --filesystem=host for a similar result"));

          return FALSE;
        }
    }

  if (g_strv_contains (flatpak_context_special_filesystems, filesystem) || get_xdg_user_dir_from_string (filesystem, NULL, NULL, NULL) || g_str_has_prefix (filesystem, "~/") || g_str_has_prefix (filesystem, "/"))


    {
      if (filesystem_out != NULL)
        *filesystem_out = g_steal_pointer (&filesystem);

      return TRUE;
    }

  if (strcmp (filesystem, "~") == 0)
    {
      if (filesystem_out != NULL)
        *filesystem_out = g_strdup ("home");

      return TRUE;
    }

  if (g_str_has_prefix (filesystem, "home/"))
    {
      if (filesystem_out != NULL)
        *filesystem_out = g_strconcat ("~/", filesystem + 5, NULL);

      return TRUE;
    }

  g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Unknown filesystem location %s, valid locations are: host, host-os, host-etc, home, xdg-*[/…], ~/dir, /dir"), filesystem);
  return FALSE;
}

static void flatpak_context_take_filesystem (FlatpakContext        *context, char                  *fs, FlatpakFilesystemMode  mode)


{
  g_hash_table_insert (context->filesystems, fs, GINT_TO_POINTER (mode));
}

void flatpak_context_merge (FlatpakContext *context, FlatpakContext *other)

{
  GHashTableIter iter;
  gpointer key, value;

  context->shares &= ~other->shares_valid;
  context->shares |= other->shares;
  context->shares_valid |= other->shares_valid;
  context->sockets &= ~other->sockets_valid;
  context->sockets |= other->sockets;
  context->sockets_valid |= other->sockets_valid;
  context->devices &= ~other->devices_valid;
  context->devices |= other->devices;
  context->devices_valid |= other->devices_valid;
  context->features &= ~other->features_valid;
  context->features |= other->features;
  context->features_valid |= other->features_valid;

  g_hash_table_iter_init (&iter, other->env_vars);
  while (g_hash_table_iter_next (&iter, &key, &value))
    g_hash_table_insert (context->env_vars, g_strdup (key), g_strdup (value));

  g_hash_table_iter_init (&iter, other->persistent);
  while (g_hash_table_iter_next (&iter, &key, &value))
    g_hash_table_insert (context->persistent, g_strdup (key), value);

  g_hash_table_iter_init (&iter, other->filesystems);
  while (g_hash_table_iter_next (&iter, &key, &value))
    g_hash_table_insert (context->filesystems, g_strdup (key), value);

  g_hash_table_iter_init (&iter, other->session_bus_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    g_hash_table_insert (context->session_bus_policy, g_strdup (key), value);

  g_hash_table_iter_init (&iter, other->system_bus_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    g_hash_table_insert (context->system_bus_policy, g_strdup (key), value);

  g_hash_table_iter_init (&iter, other->system_bus_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    g_hash_table_insert (context->system_bus_policy, g_strdup (key), value);

  g_hash_table_iter_init (&iter, other->generic_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      const char **policy_values = (const char **) value;
      int i;

      for (i = 0; policy_values[i] != NULL; i++)
        flatpak_context_apply_generic_policy (context, (char *) key, policy_values[i]);
    }
}

static gboolean option_share_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  FlatpakContextShares share;

  share = flatpak_context_share_from_string (value, error);
  if (share == 0)
    return FALSE;

  flatpak_context_add_shares (context, share);

  return TRUE;
}

static gboolean option_unshare_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  FlatpakContextShares share;

  share = flatpak_context_share_from_string (value, error);
  if (share == 0)
    return FALSE;

  flatpak_context_remove_shares (context, share);

  return TRUE;
}

static gboolean option_socket_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  FlatpakContextSockets socket;

  socket = flatpak_context_socket_from_string (value, error);
  if (socket == 0)
    return FALSE;

  if (socket == FLATPAK_CONTEXT_SOCKET_FALLBACK_X11)
    socket |= FLATPAK_CONTEXT_SOCKET_X11;

  flatpak_context_add_sockets (context, socket);

  return TRUE;
}

static gboolean option_nosocket_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  FlatpakContextSockets socket;

  socket = flatpak_context_socket_from_string (value, error);
  if (socket == 0)
    return FALSE;

  if (socket == FLATPAK_CONTEXT_SOCKET_FALLBACK_X11)
    socket |= FLATPAK_CONTEXT_SOCKET_X11;

  flatpak_context_remove_sockets (context, socket);

  return TRUE;
}

static gboolean option_device_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  FlatpakContextDevices device;

  device = flatpak_context_device_from_string (value, error);
  if (device == 0)
    return FALSE;

  flatpak_context_add_devices (context, device);

  return TRUE;
}

static gboolean option_nodevice_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  FlatpakContextDevices device;

  device = flatpak_context_device_from_string (value, error);
  if (device == 0)
    return FALSE;

  flatpak_context_remove_devices (context, device);

  return TRUE;
}

static gboolean option_allow_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  FlatpakContextFeatures feature;

  feature = flatpak_context_feature_from_string (value, error);
  if (feature == 0)
    return FALSE;

  flatpak_context_add_features (context, feature);

  return TRUE;
}

static gboolean option_disallow_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  FlatpakContextFeatures feature;

  feature = flatpak_context_feature_from_string (value, error);
  if (feature == 0)
    return FALSE;

  flatpak_context_remove_features (context, feature);

  return TRUE;
}

static gboolean option_filesystem_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  g_autofree char *fs = NULL;
  FlatpakFilesystemMode mode;

  if (!flatpak_context_parse_filesystem (value, &fs, &mode, error))
    return FALSE;

  flatpak_context_take_filesystem (context, g_steal_pointer (&fs), mode);
  return TRUE;
}

static gboolean option_nofilesystem_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  g_autofree char *fs = NULL;
  FlatpakFilesystemMode mode;

  if (!flatpak_context_parse_filesystem (value, &fs, &mode, error))
    return FALSE;

  flatpak_context_take_filesystem (context, g_steal_pointer (&fs), FLATPAK_FILESYSTEM_MODE_NONE);
  return TRUE;
}

static gboolean option_env_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  g_auto(GStrv) split = g_strsplit (value, "=", 2);

  if (split == NULL || split[0] == NULL || split[0][0] == 0 || split[1] == NULL)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Invalid env format %s"), value);
      return FALSE;
    }

  flatpak_context_set_env_var (context, split[0], split[1]);
  return TRUE;
}

gboolean flatpak_context_parse_env_block (FlatpakContext *context, const char *data, gsize length, GError **error)



{
  const char *p = data;
  gsize remaining = length;

  
  while (remaining > 0)
    {
      size_t len = strnlen (p, remaining);
      const char *equals;
      g_autofree char *env_var = NULL;
      g_autofree char *env_value = NULL;

      g_assert (len <= remaining);

      equals = memchr (p, '=', len);

      if (equals == NULL || equals == p)
        return glnx_throw (error, "Environment variable must be given in the form VARIABLE=VALUE, not %.*s", (int) len, p);

      env_var = g_strndup (p, equals - p);
      env_value = g_strndup (equals + 1, len - (equals - p) - 1);
      flatpak_context_set_env_var (context, env_var, env_value);
      p += len;
      remaining -= len;

      if (remaining > 0)
        {
          g_assert (*p == '\0');
          p += 1;
          remaining -= 1;
        }
    }

  return TRUE;
}

gboolean flatpak_context_parse_env_fd (FlatpakContext *context, int fd, GError **error)


{
  g_autoptr(GBytes) env_block = NULL;
  const char *data;
  gsize len;

  env_block = glnx_fd_readall_bytes (fd, NULL, error);

  if (env_block == NULL)
    return FALSE;

  data = g_bytes_get_data (env_block, &len);
  return flatpak_context_parse_env_block (context, data, len, error);
}

static gboolean option_env_fd_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  guint64 fd;
  gchar *endptr;
  gboolean ret;

  fd = g_ascii_strtoull (value, &endptr, 10);

  if (endptr == NULL || *endptr != '\0' || fd > G_MAXINT)
    return glnx_throw (error, "Not a valid file descriptor: %s", value);

  ret = flatpak_context_parse_env_fd (context, (int) fd, error);

  if (fd >= 3)
    close (fd);

  return ret;
}

static gboolean option_unset_env_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;

  if (strchr (value, '=') != NULL)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED, _("Environment variable name must not contain '=': %s"), value);
      return FALSE;
    }

  flatpak_context_set_env_var (context, value, NULL);
  return TRUE;
}

static gboolean option_own_name_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;

  if (!flatpak_verify_dbus_name (value, error))
    return FALSE;

  flatpak_context_set_session_bus_policy (context, value, FLATPAK_POLICY_OWN);
  return TRUE;
}

static gboolean option_talk_name_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;

  if (!flatpak_verify_dbus_name (value, error))
    return FALSE;

  flatpak_context_set_session_bus_policy (context, value, FLATPAK_POLICY_TALK);
  return TRUE;
}

static gboolean option_no_talk_name_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;

  if (!flatpak_verify_dbus_name (value, error))
    return FALSE;

  flatpak_context_set_session_bus_policy (context, value, FLATPAK_POLICY_NONE);
  return TRUE;
}

static gboolean option_system_own_name_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;

  if (!flatpak_verify_dbus_name (value, error))
    return FALSE;

  flatpak_context_set_system_bus_policy (context, value, FLATPAK_POLICY_OWN);
  return TRUE;
}

static gboolean option_system_talk_name_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;

  if (!flatpak_verify_dbus_name (value, error))
    return FALSE;

  flatpak_context_set_system_bus_policy (context, value, FLATPAK_POLICY_TALK);
  return TRUE;
}

static gboolean option_system_no_talk_name_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;

  if (!flatpak_verify_dbus_name (value, error))
    return FALSE;

  flatpak_context_set_system_bus_policy (context, value, FLATPAK_POLICY_NONE);
  return TRUE;
}

static gboolean option_add_generic_policy_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  char *t;
  g_autofree char *key = NULL;
  const char *policy_value;

  t = strchr (value, '=');
  if (t == NULL)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, _("--add-policy arguments must be in the form SUBSYSTEM.KEY=VALUE"));
      return FALSE;
    }
  policy_value = t + 1;
  key = g_strndup (value, t - value);
  if (strchr (key, '.') == NULL)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, _("--add-policy arguments must be in the form SUBSYSTEM.KEY=VALUE"));
      return FALSE;
    }

  if (policy_value[0] == '!')
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, _("--add-policy values can't start with \"!\""));
      return FALSE;
    }

  flatpak_context_apply_generic_policy (context, key, policy_value);

  return TRUE;
}

static gboolean option_remove_generic_policy_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;
  char *t;
  g_autofree char *key = NULL;
  const char *policy_value;
  g_autofree char *extended_value = NULL;

  t = strchr (value, '=');
  if (t == NULL)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, _("--remove-policy arguments must be in the form SUBSYSTEM.KEY=VALUE"));
      return FALSE;
    }
  policy_value = t + 1;
  key = g_strndup (value, t - value);
  if (strchr (key, '.') == NULL)
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, _("--remove-policy arguments must be in the form SUBSYSTEM.KEY=VALUE"));
      return FALSE;
    }

  if (policy_value[0] == '!')
    {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE, _("--remove-policy values can't start with \"!\""));
      return FALSE;
    }

  extended_value = g_strconcat ("!", policy_value, NULL);

  flatpak_context_apply_generic_policy (context, key, extended_value);

  return TRUE;
}

static gboolean option_persist_cb (const gchar *option_name, const gchar *value, gpointer     data, GError     **error)



{
  FlatpakContext *context = data;

  flatpak_context_set_persistent (context, value);
  return TRUE;
}

static gboolean option_no_desktop_deprecated;

static GOptionEntry context_options[] = {
  { "share", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_share_cb, N_("Share with host"), N_("SHARE") }, { "unshare", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_unshare_cb, N_("Unshare with host"), N_("SHARE") }, { "socket", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_socket_cb, N_("Expose socket to app"), N_("SOCKET") }, { "nosocket", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_nosocket_cb, N_("Don't expose socket to app"), N_("SOCKET") }, { "device", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_device_cb, N_("Expose device to app"), N_("DEVICE") }, { "nodevice", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_nodevice_cb, N_("Don't expose device to app"), N_("DEVICE") }, { "allow", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_allow_cb, N_("Allow feature"), N_("FEATURE") }, { "disallow", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_disallow_cb, N_("Don't allow feature"), N_("FEATURE") }, { "filesystem", 0, G_OPTION_FLAG_IN_MAIN | G_OPTION_FLAG_FILENAME, G_OPTION_ARG_CALLBACK, &option_filesystem_cb, N_("Expose filesystem to app (:ro for read-only)"), N_("FILESYSTEM[:ro]") }, { "nofilesystem", 0, G_OPTION_FLAG_IN_MAIN | G_OPTION_FLAG_FILENAME, G_OPTION_ARG_CALLBACK, &option_nofilesystem_cb, N_("Don't expose filesystem to app"), N_("FILESYSTEM") }, { "env", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_env_cb, N_("Set environment variable"), N_("VAR=VALUE") }, { "env-fd", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_env_fd_cb, N_("Read environment variables in env -0 format from FD"), N_("FD") }, { "unset-env", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_unset_env_cb, N_("Remove variable from environment"), N_("VAR") }, { "own-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_own_name_cb, N_("Allow app to own name on the session bus"), N_("DBUS_NAME") }, { "talk-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_talk_name_cb, N_("Allow app to talk to name on the session bus"), N_("DBUS_NAME") }, { "no-talk-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_no_talk_name_cb, N_("Don't allow app to talk to name on the session bus"), N_("DBUS_NAME") }, { "system-own-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_system_own_name_cb, N_("Allow app to own name on the system bus"), N_("DBUS_NAME") }, { "system-talk-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_system_talk_name_cb, N_("Allow app to talk to name on the system bus"), N_("DBUS_NAME") }, { "system-no-talk-name", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_system_no_talk_name_cb, N_("Don't allow app to talk to name on the system bus"), N_("DBUS_NAME") }, { "add-policy", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_add_generic_policy_cb, N_("Add generic policy option"), N_("SUBSYSTEM.KEY=VALUE") }, { "remove-policy", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_remove_generic_policy_cb, N_("Remove generic policy option"), N_("SUBSYSTEM.KEY=VALUE") }, { "persist", 0, G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_CALLBACK, &option_persist_cb, N_("Persist home directory subpath"), N_("FILENAME") },  { "no-desktop", 0, G_OPTION_FLAG_IN_MAIN |  G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &option_no_desktop_deprecated, N_("Don't require a running session (no cgroups creation)"), NULL }, { NULL }























};

GOptionEntry * flatpak_context_get_option_entries (void)
{
  return context_options;
}

GOptionGroup  * flatpak_context_get_options (FlatpakContext *context)
{
  GOptionGroup *group;

  group = g_option_group_new ("environment", "Runtime Environment", "Runtime Environment", context, NULL);



  g_option_group_set_translation_domain (group, GETTEXT_PACKAGE);

  g_option_group_add_entries (group, context_options);

  return group;
}

static const char * parse_negated (const char *option, gboolean *negated)
{
  if (option[0] == '!')
    {
      option++;
      *negated = TRUE;
    }
  else {
      *negated = FALSE;
    }
  return option;
}


gboolean flatpak_context_load_metadata (FlatpakContext *context, GKeyFile       *metakey, GError        **error)


{
  gboolean remove;
  g_auto(GStrv) groups = NULL;
  gsize i;

  if (g_key_file_has_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_SHARED, NULL))
    {
      g_auto(GStrv) shares = g_key_file_get_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_SHARED, NULL, error);
      if (shares == NULL)
        return FALSE;

      for (i = 0; shares[i] != NULL; i++)
        {
          FlatpakContextShares share;

          share = flatpak_context_share_from_string (parse_negated (shares[i], &remove), NULL);
          if (share == 0)
            g_debug ("Unknown share type %s", shares[i]);
          else {
              if (remove)
                flatpak_context_remove_shares (context, share);
              else flatpak_context_add_shares (context, share);
            }
        }
    }

  if (g_key_file_has_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_SOCKETS, NULL))
    {
      g_auto(GStrv) sockets = g_key_file_get_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_SOCKETS, NULL, error);
      if (sockets == NULL)
        return FALSE;

      for (i = 0; sockets[i] != NULL; i++)
        {
          FlatpakContextSockets socket = flatpak_context_socket_from_string (parse_negated (sockets[i], &remove), NULL);
          if (socket == 0)
            g_debug ("Unknown socket type %s", sockets[i]);
          else {
              if (remove)
                flatpak_context_remove_sockets (context, socket);
              else flatpak_context_add_sockets (context, socket);
            }
        }
    }

  if (g_key_file_has_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_DEVICES, NULL))
    {
      g_auto(GStrv) devices = g_key_file_get_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_DEVICES, NULL, error);
      if (devices == NULL)
        return FALSE;


      for (i = 0; devices[i] != NULL; i++)
        {
          FlatpakContextDevices device = flatpak_context_device_from_string (parse_negated (devices[i], &remove), NULL);
          if (device == 0)
            g_debug ("Unknown device type %s", devices[i]);
          else {
              if (remove)
                flatpak_context_remove_devices (context, device);
              else flatpak_context_add_devices (context, device);
            }
        }
    }

  if (g_key_file_has_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_FEATURES, NULL))
    {
      g_auto(GStrv) features = g_key_file_get_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_FEATURES, NULL, error);
      if (features == NULL)
        return FALSE;


      for (i = 0; features[i] != NULL; i++)
        {
          FlatpakContextFeatures feature = flatpak_context_feature_from_string (parse_negated (features[i], &remove), NULL);
          if (feature == 0)
            g_debug ("Unknown feature type %s", features[i]);
          else {
              if (remove)
                flatpak_context_remove_features (context, feature);
              else flatpak_context_add_features (context, feature);
            }
        }
    }

  if (g_key_file_has_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_FILESYSTEMS, NULL))
    {
      g_auto(GStrv) filesystems = g_key_file_get_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_FILESYSTEMS, NULL, error);
      if (filesystems == NULL)
        return FALSE;

      for (i = 0; filesystems[i] != NULL; i++)
        {
          const char *fs = parse_negated (filesystems[i], &remove);
          g_autofree char *filesystem = NULL;
          FlatpakFilesystemMode mode;

          if (!flatpak_context_parse_filesystem (fs, &filesystem, &mode, NULL))
            g_debug ("Unknown filesystem type %s", filesystems[i]);
          else {
              if (remove)
                flatpak_context_take_filesystem (context, g_steal_pointer (&filesystem), FLATPAK_FILESYSTEM_MODE_NONE);
              else flatpak_context_take_filesystem (context, g_steal_pointer (&filesystem), mode);
            }
        }
    }

  if (g_key_file_has_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_PERSISTENT, NULL))
    {
      g_auto(GStrv) persistent = g_key_file_get_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_PERSISTENT, NULL, error);
      if (persistent == NULL)
        return FALSE;

      for (i = 0; persistent[i] != NULL; i++)
        flatpak_context_set_persistent (context, persistent[i]);
    }

  if (g_key_file_has_group (metakey, FLATPAK_METADATA_GROUP_SESSION_BUS_POLICY))
    {
      g_auto(GStrv) keys = NULL;
      gsize keys_count;

      keys = g_key_file_get_keys (metakey, FLATPAK_METADATA_GROUP_SESSION_BUS_POLICY, &keys_count, NULL);
      for (i = 0; i < keys_count; i++)
        {
          const char *key = keys[i];
          g_autofree char *value = g_key_file_get_string (metakey, FLATPAK_METADATA_GROUP_SESSION_BUS_POLICY, key, NULL);
          FlatpakPolicy policy;

          if (!flatpak_verify_dbus_name (key, error))
            return FALSE;

          policy = flatpak_policy_from_string (value, NULL);
          if ((int) policy != -1)
            flatpak_context_set_session_bus_policy (context, key, policy);
        }
    }

  if (g_key_file_has_group (metakey, FLATPAK_METADATA_GROUP_SYSTEM_BUS_POLICY))
    {
      g_auto(GStrv) keys = NULL;
      gsize keys_count;

      keys = g_key_file_get_keys (metakey, FLATPAK_METADATA_GROUP_SYSTEM_BUS_POLICY, &keys_count, NULL);
      for (i = 0; i < keys_count; i++)
        {
          const char *key = keys[i];
          g_autofree char *value = g_key_file_get_string (metakey, FLATPAK_METADATA_GROUP_SYSTEM_BUS_POLICY, key, NULL);
          FlatpakPolicy policy;

          if (!flatpak_verify_dbus_name (key, error))
            return FALSE;

          policy = flatpak_policy_from_string (value, NULL);
          if ((int) policy != -1)
            flatpak_context_set_system_bus_policy (context, key, policy);
        }
    }

  if (g_key_file_has_group (metakey, FLATPAK_METADATA_GROUP_ENVIRONMENT))
    {
      g_auto(GStrv) keys = NULL;
      gsize keys_count;

      keys = g_key_file_get_keys (metakey, FLATPAK_METADATA_GROUP_ENVIRONMENT, &keys_count, NULL);
      for (i = 0; i < keys_count; i++)
        {
          const char *key = keys[i];
          g_autofree char *value = g_key_file_get_string (metakey, FLATPAK_METADATA_GROUP_ENVIRONMENT, key, NULL);

          flatpak_context_set_env_var (context, key, value);
        }
    }

  
  if (g_key_file_has_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_UNSET_ENVIRONMENT, NULL))
    {
      g_auto(GStrv) vars = NULL;
      gsize vars_count;

      vars = g_key_file_get_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_UNSET_ENVIRONMENT, &vars_count, error);


      if (vars == NULL)
        return FALSE;

      for (i = 0; i < vars_count; i++)
        {
          const char *var = vars[i];

          flatpak_context_set_env_var (context, var, NULL);
        }
    }

  groups = g_key_file_get_groups (metakey, NULL);
  for (i = 0; groups[i] != NULL; i++)
    {
      const char *group = groups[i];
      const char *subsystem;
      int j;

      if (g_str_has_prefix (group, FLATPAK_METADATA_GROUP_PREFIX_POLICY))
        {
          g_auto(GStrv) keys = NULL;
          subsystem = group + strlen (FLATPAK_METADATA_GROUP_PREFIX_POLICY);
          keys = g_key_file_get_keys (metakey, group, NULL, NULL);
          for (j = 0; keys != NULL && keys[j] != NULL; j++)
            {
              const char *key = keys[j];
              g_autofree char *policy_key = g_strdup_printf ("%s.%s", subsystem, key);
              g_auto(GStrv) values = NULL;
              int k;

              values = g_key_file_get_string_list (metakey, group, key, NULL, NULL);
              for (k = 0; values != NULL && values[k] != NULL; k++)
                flatpak_context_apply_generic_policy (context, policy_key, values[k]);
            }
        }
    }

  return TRUE;
}


void flatpak_context_save_metadata (FlatpakContext *context, gboolean        flatten, GKeyFile       *metakey)


{
  g_auto(GStrv) shared = NULL;
  g_auto(GStrv) sockets = NULL;
  g_auto(GStrv) devices = NULL;
  g_auto(GStrv) features = NULL;
  g_autoptr(GPtrArray) unset_env = NULL;
  GHashTableIter iter;
  gpointer key, value;
  FlatpakContextShares shares_mask = context->shares;
  FlatpakContextShares shares_valid = context->shares_valid;
  FlatpakContextSockets sockets_mask = context->sockets;
  FlatpakContextSockets sockets_valid = context->sockets_valid;
  FlatpakContextDevices devices_mask = context->devices;
  FlatpakContextDevices devices_valid = context->devices_valid;
  FlatpakContextFeatures features_mask = context->features;
  FlatpakContextFeatures features_valid = context->features_valid;
  g_auto(GStrv) groups = NULL;
  int i;

  if (flatten)
    {
      
      
      shares_mask &= shares_valid;
      sockets_mask &= sockets_valid;
      devices_mask &= devices_valid;
      features_mask &= features_valid;

      
      shares_valid = shares_mask;
      sockets_valid = sockets_mask;
      devices_valid = devices_mask;
      features_valid = features_mask;
    }

  shared = flatpak_context_shared_to_string (shares_mask, shares_valid);
  sockets = flatpak_context_sockets_to_string (sockets_mask, sockets_valid);
  devices = flatpak_context_devices_to_string (devices_mask, devices_valid);
  features = flatpak_context_features_to_string (features_mask, features_valid);

  if (shared[0] != NULL)
    {
      g_key_file_set_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_SHARED, (const char * const *) shared, g_strv_length (shared));


    }
  else {
      g_key_file_remove_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_SHARED, NULL);


    }

  if (sockets[0] != NULL)
    {
      g_key_file_set_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_SOCKETS, (const char * const *) sockets, g_strv_length (sockets));


    }
  else {
      g_key_file_remove_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_SOCKETS, NULL);


    }

  if (devices[0] != NULL)
    {
      g_key_file_set_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_DEVICES, (const char * const *) devices, g_strv_length (devices));


    }
  else {
      g_key_file_remove_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_DEVICES, NULL);


    }

  if (features[0] != NULL)
    {
      g_key_file_set_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_FEATURES, (const char * const *) features, g_strv_length (features));


    }
  else {
      g_key_file_remove_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_FEATURES, NULL);


    }

  if (g_hash_table_size (context->filesystems) > 0)
    {
      g_autoptr(GPtrArray) array = g_ptr_array_new_with_free_func (g_free);

      g_hash_table_iter_init (&iter, context->filesystems);
      while (g_hash_table_iter_next (&iter, &key, &value))
        {
          FlatpakFilesystemMode mode = GPOINTER_TO_INT (value);

          g_ptr_array_add (array, unparse_filesystem_flags (key, mode));
        }

      g_key_file_set_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_FILESYSTEMS, (const char * const *) array->pdata, array->len);


    }
  else {
      g_key_file_remove_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_FILESYSTEMS, NULL);


    }

  if (g_hash_table_size (context->persistent) > 0)
    {
      g_autofree char **keys = (char **) g_hash_table_get_keys_as_array (context->persistent, NULL);

      g_key_file_set_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_PERSISTENT, (const char * const *) keys, g_strv_length (keys));


    }
  else {
      g_key_file_remove_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_PERSISTENT, NULL);


    }

  g_key_file_remove_group (metakey, FLATPAK_METADATA_GROUP_SESSION_BUS_POLICY, NULL);
  g_hash_table_iter_init (&iter, context->session_bus_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      FlatpakPolicy policy = GPOINTER_TO_INT (value);

      if (flatten && (policy == 0))
        continue;

      g_key_file_set_string (metakey, FLATPAK_METADATA_GROUP_SESSION_BUS_POLICY, (char *) key, flatpak_policy_to_string (policy));

    }

  g_key_file_remove_group (metakey, FLATPAK_METADATA_GROUP_SYSTEM_BUS_POLICY, NULL);
  g_hash_table_iter_init (&iter, context->system_bus_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      FlatpakPolicy policy = GPOINTER_TO_INT (value);

      if (flatten && (policy == 0))
        continue;

      g_key_file_set_string (metakey, FLATPAK_METADATA_GROUP_SYSTEM_BUS_POLICY, (char *) key, flatpak_policy_to_string (policy));

    }

  
  unset_env = g_ptr_array_new ();

  g_key_file_remove_group (metakey, FLATPAK_METADATA_GROUP_ENVIRONMENT, NULL);
  g_hash_table_iter_init (&iter, context->env_vars);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      if (value != NULL)
        {
          g_key_file_set_string (metakey, FLATPAK_METADATA_GROUP_ENVIRONMENT, (char *) key, (char *) value);

        }
      else {
          
          g_key_file_set_string (metakey, FLATPAK_METADATA_GROUP_ENVIRONMENT, (char *) key, "");

          g_ptr_array_add (unset_env, key);
        }
    }

  if (unset_env->len > 0)
    {
      g_ptr_array_add (unset_env, NULL);
      g_key_file_set_string_list (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_UNSET_ENVIRONMENT, (const char * const *) unset_env->pdata, unset_env->len - 1);


    }
  else {
      g_key_file_remove_key (metakey, FLATPAK_METADATA_GROUP_CONTEXT, FLATPAK_METADATA_KEY_UNSET_ENVIRONMENT, NULL);
    }

  groups = g_key_file_get_groups (metakey, NULL);
  for (i = 0; groups[i] != NULL; i++)
    {
      const char *group = groups[i];
      if (g_str_has_prefix (group, FLATPAK_METADATA_GROUP_PREFIX_POLICY))
        g_key_file_remove_group (metakey, group, NULL);
    }

  g_hash_table_iter_init (&iter, context->generic_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      g_auto(GStrv) parts = g_strsplit ((const char *) key, ".", 2);
      g_autofree char *group = NULL;
      g_assert (parts[1] != NULL);
      const char **policy_values = (const char **) value;
      g_autoptr(GPtrArray) new = g_ptr_array_new ();

      for (i = 0; policy_values[i] != NULL; i++)
        {
          const char *policy_value = policy_values[i];

          if (!flatten || policy_value[0] != '!')
            g_ptr_array_add (new, (char *) policy_value);
        }

      if (new->len > 0)
        {
          group = g_strconcat (FLATPAK_METADATA_GROUP_PREFIX_POLICY, parts[0], NULL);
          g_key_file_set_string_list (metakey, group, parts[1], (const char * const *) new->pdata, new->len);

        }
    }
}

void flatpak_context_allow_host_fs (FlatpakContext *context)
{
  flatpak_context_take_filesystem (context, g_strdup ("host"), FLATPAK_FILESYSTEM_MODE_READ_WRITE);
}

gboolean flatpak_context_get_needs_session_bus_proxy (FlatpakContext *context)
{
  return g_hash_table_size (context->session_bus_policy) > 0;
}

gboolean flatpak_context_get_needs_system_bus_proxy (FlatpakContext *context)
{
  return g_hash_table_size (context->system_bus_policy) > 0;
}

static gboolean adds_flags (guint32 old_flags, guint32 new_flags)
{
  return (new_flags & ~old_flags) != 0;
}

static gboolean adds_bus_policy (GHashTable *old, GHashTable *new)
{
  GLNX_HASH_TABLE_FOREACH_KV (new, const char *, name, gpointer, _new_policy)
    {
      int new_policy = GPOINTER_TO_INT (_new_policy);
      int old_policy = GPOINTER_TO_INT (g_hash_table_lookup (old, name));
      if (new_policy > old_policy)
        return TRUE;
    }

  return FALSE;
}

static gboolean adds_generic_policy (GHashTable *old, GHashTable *new)
{
  GLNX_HASH_TABLE_FOREACH_KV (new, const char *, key, GPtrArray *, new_values)
    {
      GPtrArray *old_values = g_hash_table_lookup (old, key);
      int i;

      if (new_values == NULL || new_values->len == 0)
        continue;

      if (old_values == NULL || old_values->len == 0)
        return TRUE;

      for (i = 0; i < new_values->len; i++)
        {
          const char *new_value = g_ptr_array_index (new_values, i);

          if (!flatpak_g_ptr_array_contains_string (old_values, new_value))
            return TRUE;
        }
    }

  return FALSE;
}

static gboolean adds_filesystem_access (GHashTable *old, GHashTable *new)
{
  FlatpakFilesystemMode old_host_mode = GPOINTER_TO_INT (g_hash_table_lookup (old, "host"));

  GLNX_HASH_TABLE_FOREACH_KV (new, const char *, location, gpointer, _new_mode)
    {
      FlatpakFilesystemMode new_mode = GPOINTER_TO_INT (_new_mode);
      FlatpakFilesystemMode old_mode = GPOINTER_TO_INT (g_hash_table_lookup (old, location));

      
      if (new_mode <= old_mode)
        continue;

      
     if (new_mode <= old_host_mode)
        continue;

     

      return TRUE;
    }

  return FALSE;
}


gboolean flatpak_context_adds_permissions (FlatpakContext *old, FlatpakContext *new)

{
  
  guint32 harmless_features = (FLATPAK_CONTEXT_FEATURE_MULTIARCH | FLATPAK_CONTEXT_FEATURE_PER_APP_DEV_SHM);
  guint32 old_sockets;

  if (adds_flags (old->shares & old->shares_valid, new->shares & new->shares_valid))
    return TRUE;

  old_sockets = old->sockets & old->sockets_valid;

  
  if (old_sockets & FLATPAK_CONTEXT_SOCKET_X11)
    old_sockets |= FLATPAK_CONTEXT_SOCKET_FALLBACK_X11;

  if (adds_flags (old_sockets, new->sockets & new->sockets_valid))
    return TRUE;

  if (adds_flags (old->devices & old->devices_valid, new->devices & new->devices_valid))
    return TRUE;

  if (adds_flags ((old->features & old->features_valid) | harmless_features, new->features & new->features_valid))
    return TRUE;

  if (adds_bus_policy (old->session_bus_policy, new->session_bus_policy))
    return TRUE;

  if (adds_bus_policy (old->system_bus_policy, new->system_bus_policy))
    return TRUE;

  if (adds_generic_policy (old->generic_policy, new->generic_policy))
    return TRUE;

  if (adds_filesystem_access (old->filesystems, new->filesystems))
    return TRUE;

  return FALSE;
}

gboolean flatpak_context_allows_features (FlatpakContext        *context, FlatpakContextFeatures features)

{
  return (context->features & features) == features;
}

void flatpak_context_to_args (FlatpakContext *context, GPtrArray      *args)

{
  GHashTableIter iter;
  gpointer key, value;

  flatpak_context_shared_to_args (context->shares, context->shares_valid, args);
  flatpak_context_sockets_to_args (context->sockets, context->sockets_valid, args);
  flatpak_context_devices_to_args (context->devices, context->devices_valid, args);
  flatpak_context_features_to_args (context->features, context->features_valid, args);

  g_hash_table_iter_init (&iter, context->env_vars);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      if (value != NULL)
        g_ptr_array_add (args, g_strdup_printf ("--env=%s=%s", (char *) key, (char *) value));
      else g_ptr_array_add (args, g_strdup_printf ("--unset-env=%s", (char *) key));
    }

  g_hash_table_iter_init (&iter, context->persistent);
  while (g_hash_table_iter_next (&iter, &key, &value))
    g_ptr_array_add (args, g_strdup_printf ("--persist=%s", (char *) key));

  g_hash_table_iter_init (&iter, context->session_bus_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      const char *name = key;
      FlatpakPolicy policy = GPOINTER_TO_INT (value);

      g_ptr_array_add (args, g_strdup_printf ("--%s-name=%s", flatpak_policy_to_string (policy), name));
    }

  g_hash_table_iter_init (&iter, context->system_bus_policy);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      const char *name = key;
      FlatpakPolicy policy = GPOINTER_TO_INT (value);

      g_ptr_array_add (args, g_strdup_printf ("--system-%s-name=%s", flatpak_policy_to_string (policy), name));
    }

  g_hash_table_iter_init (&iter, context->filesystems);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      FlatpakFilesystemMode mode = GPOINTER_TO_INT (value);

      if (mode != FLATPAK_FILESYSTEM_MODE_NONE)
        {
          g_autofree char *fs = unparse_filesystem_flags (key, mode);
          g_ptr_array_add (args, g_strdup_printf ("--filesystem=%s", fs));
        }
      else g_ptr_array_add (args, g_strdup_printf ("--nofilesystem=%s", (char *) key));
    }
}

void flatpak_context_add_bus_filters (FlatpakContext *context, const char     *app_id, gboolean        session_bus, gboolean        sandboxed, FlatpakBwrap   *bwrap)




{
  GHashTable *ht;
  GHashTableIter iter;
  gpointer key, value;

  flatpak_bwrap_add_arg (bwrap, "--filter");
  if (app_id && session_bus)
    {
      if (!sandboxed)
        {
          flatpak_bwrap_add_arg_printf (bwrap, "--own=%s.*", app_id);
          flatpak_bwrap_add_arg_printf (bwrap, "--own=org.mpris.MediaPlayer2.%s.*", app_id);
        }
      else flatpak_bwrap_add_arg_printf (bwrap, "--own=%s.Sandboxed.*", app_id);
    }

  if (session_bus)
    ht = context->session_bus_policy;
  else ht = context->system_bus_policy;

  g_hash_table_iter_init (&iter, ht);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      FlatpakPolicy policy = GPOINTER_TO_INT (value);

      if (policy > 0)
        flatpak_bwrap_add_arg_printf (bwrap, "--%s=%s", flatpak_policy_to_string (policy), (char *) key);

    }
}

void flatpak_context_reset_non_permissions (FlatpakContext *context)
{
  g_hash_table_remove_all (context->env_vars);
}

void flatpak_context_reset_permissions (FlatpakContext *context)
{
  context->shares_valid = 0;
  context->sockets_valid = 0;
  context->devices_valid = 0;
  context->features_valid = 0;

  context->shares = 0;
  context->sockets = 0;
  context->devices = 0;
  context->features = 0;

  g_hash_table_remove_all (context->persistent);
  g_hash_table_remove_all (context->filesystems);
  g_hash_table_remove_all (context->session_bus_policy);
  g_hash_table_remove_all (context->system_bus_policy);
  g_hash_table_remove_all (context->generic_policy);
}

void flatpak_context_make_sandboxed (FlatpakContext *context)
{
  
  context->shares_valid &= 0;
  context->sockets_valid &= 0;
  context->devices_valid &= 0;
  context->features_valid &= FLATPAK_CONTEXT_FEATURE_MULTIARCH;

  context->shares &= context->shares_valid;
  context->sockets &= context->sockets_valid;
  context->devices &= context->devices_valid;
  context->features &= context->features_valid;

  g_hash_table_remove_all (context->persistent);
  g_hash_table_remove_all (context->filesystems);
  g_hash_table_remove_all (context->session_bus_policy);
  g_hash_table_remove_all (context->system_bus_policy);
  g_hash_table_remove_all (context->generic_policy);
}

const char *dont_mount_in_root[] = {
  ".", "..", "lib", "lib32", "lib64", "bin", "sbin", "usr", "boot", "root", "tmp", "etc", "app", "run", "proc", "sys", "dev", "var", NULL };


static void flatpak_context_export (FlatpakContext *context, FlatpakExports *exports, GFile          *app_id_dir, GPtrArray       *extra_app_id_dirs, gboolean        do_create, gchar         **xdg_dirs_conf_out, gboolean       *home_access_out)






{
  gboolean home_access = FALSE;
  g_autoptr(GString) xdg_dirs_conf = NULL;
  FlatpakFilesystemMode fs_mode, os_mode, etc_mode, home_mode;
  GHashTableIter iter;
  gpointer key, value;

  if (xdg_dirs_conf_out != NULL)
    xdg_dirs_conf = g_string_new ("");

  fs_mode = GPOINTER_TO_INT (g_hash_table_lookup (context->filesystems, "host"));
  if (fs_mode != FLATPAK_FILESYSTEM_MODE_NONE)
    {
      DIR *dir;
      struct dirent *dirent;

      g_debug ("Allowing host-fs access");
      home_access = TRUE;

      
      dir = opendir ("/");
      if (dir != NULL)
        {
          while ((dirent = readdir (dir)))
            {
              g_autofree char *path = NULL;

              if (g_strv_contains (dont_mount_in_root, dirent->d_name))
                continue;

              path = g_build_filename ("/", dirent->d_name, NULL);
              flatpak_exports_add_path_expose (exports, fs_mode, path);
            }
          closedir (dir);
        }
      flatpak_exports_add_path_expose (exports, fs_mode, "/run/media");
    }

  os_mode = MAX (GPOINTER_TO_INT (g_hash_table_lookup (context->filesystems, "host-os")), fs_mode);

  if (os_mode != FLATPAK_FILESYSTEM_MODE_NONE)
    flatpak_exports_add_host_os_expose (exports, os_mode);

  etc_mode = MAX (GPOINTER_TO_INT (g_hash_table_lookup (context->filesystems, "host-etc")), fs_mode);

  if (etc_mode != FLATPAK_FILESYSTEM_MODE_NONE)
    flatpak_exports_add_host_etc_expose (exports, etc_mode);

  home_mode = GPOINTER_TO_INT (g_hash_table_lookup (context->filesystems, "home"));
  if (home_mode != FLATPAK_FILESYSTEM_MODE_NONE)
    {
      g_debug ("Allowing homedir access");
      home_access = TRUE;

      flatpak_exports_add_path_expose (exports, MAX (home_mode, fs_mode), g_get_home_dir ());
    }

  g_hash_table_iter_init (&iter, context->filesystems);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      const char *filesystem = key;
      FlatpakFilesystemMode mode = GPOINTER_TO_INT (value);

      if (g_strv_contains (flatpak_context_special_filesystems, filesystem))
        continue;

      if (g_str_has_prefix (filesystem, "xdg-"))
        {
          const char *path, *rest = NULL;
          const char *config_key = NULL;
          g_autofree char *subpath = NULL;

          if (!get_xdg_user_dir_from_string (filesystem, &config_key, &rest, &path))
            {
              g_warning ("Unsupported xdg dir %s", filesystem);
              continue;
            }

          if (path == NULL)
            continue; 

          if (strcmp (path, g_get_home_dir ()) == 0)
            {
              
              g_debug ("Xdg dir %s is $HOME (i.e. disabled), ignoring", filesystem);
              continue;
            }

          subpath = g_build_filename (path, rest, NULL);

          if (mode == FLATPAK_FILESYSTEM_MODE_CREATE && do_create)
            g_mkdir_with_parents (subpath, 0755);

          if (g_file_test (subpath, G_FILE_TEST_EXISTS))
            {
              if (config_key && xdg_dirs_conf)
                g_string_append_printf (xdg_dirs_conf, "%s=\"%s\"\n", config_key, path);

              flatpak_exports_add_path_expose_or_hide (exports, mode, subpath);
            }
        }
      else if (g_str_has_prefix (filesystem, "~/"))
        {
          g_autofree char *path = NULL;

          path = g_build_filename (g_get_home_dir (), filesystem + 2, NULL);

          if (mode == FLATPAK_FILESYSTEM_MODE_CREATE && do_create)
            g_mkdir_with_parents (path, 0755);

          if (g_file_test (path, G_FILE_TEST_EXISTS))
            flatpak_exports_add_path_expose_or_hide (exports, mode, path);
        }
      else if (g_str_has_prefix (filesystem, "/"))
        {
          if (mode == FLATPAK_FILESYSTEM_MODE_CREATE && do_create)
            g_mkdir_with_parents (filesystem, 0755);

          if (g_file_test (filesystem, G_FILE_TEST_EXISTS))
            flatpak_exports_add_path_expose_or_hide (exports, mode, filesystem);
        }
      else {
          g_warning ("Unexpected filesystem arg %s", filesystem);
        }
    }

  if (app_id_dir)
    {
      g_autoptr(GFile) apps_dir = g_file_get_parent (app_id_dir);
      int i;
      
      flatpak_exports_add_path_tmpfs (exports, flatpak_file_get_path_cached (apps_dir));
      
      flatpak_exports_add_path_expose (exports, FLATPAK_FILESYSTEM_MODE_READ_WRITE, flatpak_file_get_path_cached (app_id_dir));

      if (extra_app_id_dirs != NULL)
        {
          for (i = 0; i < extra_app_id_dirs->len; i++)
            {
              GFile *extra_app_id_dir = g_ptr_array_index (extra_app_id_dirs, i);
              flatpak_exports_add_path_expose (exports, FLATPAK_FILESYSTEM_MODE_READ_WRITE, flatpak_file_get_path_cached (extra_app_id_dir));
            }
        }
    }

  if (home_access_out != NULL)
    *home_access_out = home_access;

  if (xdg_dirs_conf_out != NULL)
    {
      g_assert (xdg_dirs_conf != NULL);
      *xdg_dirs_conf_out = g_string_free (g_steal_pointer (&xdg_dirs_conf), FALSE);
    }
}

FlatpakExports * flatpak_context_get_exports (FlatpakContext *context, const char     *app_id)

{
  g_autoptr(GFile) app_id_dir = flatpak_get_data_dir (app_id);

  return flatpak_context_get_exports_full (context, app_id_dir, NULL, FALSE, FALSE, NULL, NULL);

}

FlatpakRunFlags flatpak_context_get_run_flags (FlatpakContext *context)
{
  FlatpakRunFlags flags = 0;

  if (flatpak_context_allows_features (context, FLATPAK_CONTEXT_FEATURE_DEVEL))
    flags |= FLATPAK_RUN_FLAG_DEVEL;

  if (flatpak_context_allows_features (context, FLATPAK_CONTEXT_FEATURE_MULTIARCH))
    flags |= FLATPAK_RUN_FLAG_MULTIARCH;

  if (flatpak_context_allows_features (context, FLATPAK_CONTEXT_FEATURE_BLUETOOTH))
    flags |= FLATPAK_RUN_FLAG_BLUETOOTH;

  if (flatpak_context_allows_features (context, FLATPAK_CONTEXT_FEATURE_CANBUS))
    flags |= FLATPAK_RUN_FLAG_CANBUS;

  return flags;
}

FlatpakExports * flatpak_context_get_exports_full (FlatpakContext *context, GFile          *app_id_dir, GPtrArray      *extra_app_id_dirs, gboolean        do_create, gboolean        include_default_dirs, gchar         **xdg_dirs_conf_out, gboolean       *home_access_out)






{
  g_autoptr(FlatpakExports) exports = flatpak_exports_new ();

  flatpak_context_export (context, exports, app_id_dir, extra_app_id_dirs, do_create, xdg_dirs_conf_out, home_access_out);


  if (include_default_dirs)
    {
      g_autoptr(GFile) user_flatpak_dir = NULL;

      
      user_flatpak_dir = flatpak_get_user_base_dir_location ();
      flatpak_exports_add_path_tmpfs (exports, flatpak_file_get_path_cached (user_flatpak_dir));

      
      flatpak_exports_add_path_dir (exports, g_get_home_dir ());
    }

  return g_steal_pointer (&exports);
}

void flatpak_context_append_bwrap_filesystem (FlatpakContext  *context, FlatpakBwrap    *bwrap, const char      *app_id, GFile           *app_id_dir, FlatpakExports  *exports, const char      *xdg_dirs_conf, gboolean         home_access)






{
  GHashTableIter iter;
  gpointer key, value;

  if (app_id_dir != NULL)
    flatpak_run_apply_env_appid (bwrap, app_id_dir);

  if (!home_access)
    {
      

      g_hash_table_iter_init (&iter, context->persistent);
      while (g_hash_table_iter_next (&iter, &key, NULL))
        {
          const char *persist = key;
          g_autofree char *src = g_build_filename (g_get_home_dir (), ".var/app", app_id, persist, NULL);
          g_autofree char *dest = g_build_filename (g_get_home_dir (), persist, NULL);

          g_mkdir_with_parents (src, 0755);

          flatpak_bwrap_add_bind_arg (bwrap, "--bind", src, dest);
        }
    }

  if (app_id_dir != NULL)
    {
      g_autofree char *user_runtime_dir = flatpak_get_real_xdg_runtime_dir ();
      g_autofree char *run_user_app_dst = g_strdup_printf ("/run/flatpak/app/%s", app_id);
      g_autofree char *run_user_app_src = g_build_filename (user_runtime_dir, "app", app_id, NULL);

      if (glnx_shutil_mkdir_p_at (AT_FDCWD, run_user_app_src, 0700, NULL, NULL))



        flatpak_bwrap_add_args (bwrap, "--bind", run_user_app_src, run_user_app_dst, NULL);


      
      flatpak_bwrap_add_runtime_dir_member (bwrap, "app");
    }

  
  flatpak_exports_append_bwrap_args (exports, bwrap);

  
  if (app_id_dir)
    {
      g_hash_table_iter_init (&iter, context->filesystems);
      while (g_hash_table_iter_next (&iter, &key, &value))
        {
          const char *filesystem = key;
          FlatpakFilesystemMode mode = GPOINTER_TO_INT (value);
          g_autofree char *xdg_path = NULL;
          const char *rest, *where;

          xdg_path = get_xdg_dir_from_string (filesystem, &rest, &where);

          if (xdg_path != NULL && *rest != 0 && mode >= FLATPAK_FILESYSTEM_MODE_READ_ONLY)
            {
              g_autoptr(GFile) app_version = g_file_get_child (app_id_dir, where);
              g_autoptr(GFile) app_version_subdir = g_file_resolve_relative_path (app_version, rest);

              if (g_file_test (xdg_path, G_FILE_TEST_IS_DIR) || g_file_test (xdg_path, G_FILE_TEST_IS_REGULAR))
                {
                  g_autofree char *xdg_path_in_app = g_file_get_path (app_version_subdir);
                  flatpak_bwrap_add_bind_arg (bwrap, mode == FLATPAK_FILESYSTEM_MODE_READ_ONLY ? "--ro-bind" : "--bind", xdg_path, xdg_path_in_app);

                }
            }
        }
    }

  if (home_access && app_id_dir != NULL)
    {
      g_autofree char *src_path = g_build_filename (g_get_user_config_dir (), "user-dirs.dirs", NULL);

      g_autofree char *path = g_build_filename (flatpak_file_get_path_cached (app_id_dir), "config/user-dirs.dirs", NULL);
      if (g_file_test (src_path, G_FILE_TEST_EXISTS))
        flatpak_bwrap_add_bind_arg (bwrap, "--ro-bind", src_path, path);
    }
  else if (xdg_dirs_conf != NULL && xdg_dirs_conf[0] != '\0' && app_id_dir != NULL)
    {
      g_autofree char *path = g_build_filename (flatpak_file_get_path_cached (app_id_dir), "config/user-dirs.dirs", NULL);


      flatpak_bwrap_add_args_data (bwrap, "xdg-config-dirs", xdg_dirs_conf, strlen (xdg_dirs_conf), path, NULL);
    }
}