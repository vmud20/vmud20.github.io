



















int irc_nick_valid (struct t_irc_channel *channel, struct t_irc_nick *nick)
{
    struct t_irc_nick *ptr_nick;

    if (!channel || !nick)
        return 0;

    for (ptr_nick = channel->nicks; ptr_nick; ptr_nick = ptr_nick->next_nick)
    {
        if (ptr_nick == nick)
            return 1;
    }

    
    return 0;
}



int irc_nick_is_nick (const char *string)
{
    const char *ptr;

    if (!string || !string[0])
        return 0;

    
    ptr = string;
    if (strchr ("0123456789-", *ptr))
        return 0;

    while (ptr && ptr[0])
    {
        if (!strchr (IRC_NICK_VALID_CHARS, *ptr))
            return 0;
        ptr++;
    }

    return 1;
}



char * irc_nick_find_color (const char *nickname)
{
    return weechat_info_get ("nick_color", nickname);
}



char * irc_nick_find_color_name (const char *nickname)
{
    return weechat_info_get ("nick_color_name", nickname);
}



void irc_nick_set_current_prefix (struct t_irc_nick *nick)
{
    char *ptr_prefixes;

    if (!nick)
        return;

    nick->prefix[0] = ' ';
    for (ptr_prefixes = nick->prefixes; ptr_prefixes[0]; ptr_prefixes++)
    {
        if (ptr_prefixes[0] != ' ')
        {
            nick->prefix[0] = ptr_prefixes[0];
            break;
        }
    }
}



void irc_nick_set_prefix (struct t_irc_server *server, struct t_irc_nick *nick, int set, char prefix)

{
    int index;

    if (!nick)
        return;

    index = irc_server_get_prefix_char_index (server, prefix);
    if (index >= 0)
    {
        nick->prefixes[index] = (set) ? prefix : ' ';
        irc_nick_set_current_prefix (nick);
    }
}



void irc_nick_set_prefixes (struct t_irc_server *server, struct t_irc_nick *nick, const char *prefixes)

{
    const char *ptr_prefixes;

    if (!nick)
        return;

    
    memset (nick->prefixes, ' ', strlen (nick->prefixes));

    
    if (prefixes)
    {
        for (ptr_prefixes = prefixes; ptr_prefixes[0]; ptr_prefixes++)
        {
            irc_nick_set_prefix (server, nick, 1, ptr_prefixes[0]);
        }
    }

    
    irc_nick_set_current_prefix (nick);
}



void irc_nick_set_host (struct t_irc_nick *nick, const char *host)
{
    if (!nick)
        return;

    
    if ((!nick->host && !host)
        || (nick->host && host && strcmp (nick->host, host) == 0))
    {
        return;
    }

    
    if (nick->host)
        free (nick->host);
    nick->host = (host) ? strdup (host) : NULL;
}



int irc_nick_is_op (struct t_irc_server *server, struct t_irc_nick *nick)
{
    int index;

    if (nick->prefix[0] == ' ')
        return 0;

    index = irc_server_get_prefix_char_index (server, nick->prefix[0]);
    if (index < 0)
        return 0;

    return (index <= irc_server_get_prefix_mode_index (server, 'o')) ? 1 : 0;
}



int irc_nick_has_prefix_mode (struct t_irc_server *server, struct t_irc_nick *nick, char prefix_mode)

{
    char prefix_char;

    prefix_char = irc_server_get_prefix_char_for_mode (server, prefix_mode);
    if (prefix_char == ' ')
        return 0;

    return (strchr (nick->prefixes, prefix_char)) ? 1 : 0;
}



struct t_gui_nick_group * irc_nick_get_nicklist_group (struct t_irc_server *server, struct t_gui_buffer *buffer, struct t_irc_nick *nick)


{
    int index;
    char str_group[2];
    const char *prefix_modes;
    struct t_gui_nick_group *ptr_group;

    if (!server || !buffer || !nick)
        return NULL;

    ptr_group = NULL;
    index = irc_server_get_prefix_char_index (server, nick->prefix[0]);
    if (index < 0)
    {
        ptr_group = weechat_nicklist_search_group (buffer, NULL, IRC_NICK_GROUP_OTHER_NAME);
    }
    else {
        prefix_modes = irc_server_get_prefix_modes (server);
        str_group[0] = prefix_modes[index];
        str_group[1] = '\0';
        ptr_group = weechat_nicklist_search_group (buffer, NULL, str_group);
    }

    return ptr_group;
}



const char * irc_nick_get_prefix_color_name (struct t_irc_server *server, char prefix)
{
    static char *default_color = "";
    const char *prefix_modes, *color;
    char mode[2];
    int index;

    if (irc_config_hashtable_nick_prefixes)
    {
        mode[0] = ' ';
        mode[1] = '\0';

        index = irc_server_get_prefix_char_index (server, prefix);
        if (index >= 0)
        {
            prefix_modes = irc_server_get_prefix_modes (server);
            mode[0] = prefix_modes[index];
            color = weechat_hashtable_get (irc_config_hashtable_nick_prefixes, mode);
            if (color)
                return color;
        }

        
        mode[0] = '*';
        color = weechat_hashtable_get (irc_config_hashtable_nick_prefixes, mode);
        if (color)
            return color;
    }

    
    return default_color;
}



char * irc_nick_get_color_for_nicklist (struct t_irc_server *server, struct t_irc_nick *nick)

{
    static char *nick_color_bar_fg = "bar_fg";
    static char *nick_color_self = "weechat.color.chat_nick_self";
    static char *nick_color_away = "weechat.color.nicklist_away";

    if (nick->away)
        return strdup (nick_color_away);

    if (weechat_config_boolean (irc_config_look_color_nicks_in_nicklist))
    {
        if (irc_server_strcasecmp (server, nick->name, server->nick) == 0)
            return strdup (nick_color_self);
        else return irc_nick_find_color_name (nick->name);
    }

    return strdup (nick_color_bar_fg);
}



void irc_nick_nicklist_add (struct t_irc_server *server, struct t_irc_channel *channel, struct t_irc_nick *nick)


{
    struct t_gui_nick_group *ptr_group;
    char *color;

    ptr_group = irc_nick_get_nicklist_group (server, channel->buffer, nick);
    color = irc_nick_get_color_for_nicklist (server, nick);
    weechat_nicklist_add_nick (channel->buffer, ptr_group, nick->name, color, nick->prefix, irc_nick_get_prefix_color_name (server, nick->prefix[0]), 1);




    if (color)
        free (color);
}



void irc_nick_nicklist_remove (struct t_irc_server *server, struct t_irc_channel *channel, struct t_irc_nick *nick)


{
    struct t_gui_nick_group *ptr_group;

    ptr_group = irc_nick_get_nicklist_group (server, channel->buffer, nick);
    weechat_nicklist_remove_nick (channel->buffer, weechat_nicklist_search_nick (channel->buffer, ptr_group, nick->name));


}



void irc_nick_nicklist_set (struct t_irc_channel *channel, struct t_irc_nick *nick, const char *property, const char *value)


{
    struct t_gui_nick *ptr_nick;

    ptr_nick = weechat_nicklist_search_nick (channel->buffer, NULL, nick->name);
    if (ptr_nick)
    {
        weechat_nicklist_nick_set (channel->buffer, ptr_nick, property, value);
    }
}



void irc_nick_nicklist_set_prefix_color_all ()
{
    struct t_irc_server *ptr_server;
    struct t_irc_channel *ptr_channel;
    struct t_irc_nick *ptr_nick;

    for (ptr_server = irc_servers; ptr_server;
         ptr_server = ptr_server->next_server)
    {
        for (ptr_channel = ptr_server->channels; ptr_channel;
             ptr_channel = ptr_channel->next_channel)
        {
            for (ptr_nick = ptr_channel->nicks; ptr_nick;
                 ptr_nick = ptr_nick->next_nick)
            {
                irc_nick_nicklist_set (ptr_channel, ptr_nick, "prefix_color", irc_nick_get_prefix_color_name (ptr_server, ptr_nick->prefix[0]));

            }
        }
    }
}



void irc_nick_nicklist_set_color_all ()
{
    struct t_irc_server *ptr_server;
    struct t_irc_channel *ptr_channel;
    struct t_irc_nick *ptr_nick;
    char *color;

    for (ptr_server = irc_servers; ptr_server;
         ptr_server = ptr_server->next_server)
    {
        for (ptr_channel = ptr_server->channels; ptr_channel;
             ptr_channel = ptr_channel->next_channel)
        {
            for (ptr_nick = ptr_channel->nicks; ptr_nick;
                 ptr_nick = ptr_nick->next_nick)
            {
                color = irc_nick_get_color_for_nicklist (ptr_server, ptr_nick);
                irc_nick_nicklist_set (ptr_channel, ptr_nick, "color", color);
                if (color)
                    free (color);
            }
        }
    }
}



struct t_irc_nick * irc_nick_new (struct t_irc_server *server, struct t_irc_channel *channel, const char *nickname, const char *host, const char *prefixes, int away, const char *account, const char *realname)


{
    struct t_irc_nick *new_nick, *ptr_nick;
    int length;

    if (!nickname || !nickname[0])
        return NULL;

    if (!channel->nicks)
        irc_channel_add_nicklist_groups (server, channel);

    
    ptr_nick = irc_nick_search (server, channel, nickname);
    if (ptr_nick)
    {
        
        irc_nick_nicklist_remove (server, channel, ptr_nick);

        
        irc_nick_set_prefixes (server, ptr_nick, prefixes);

        
        irc_nick_nicklist_add (server, channel, ptr_nick);

        return ptr_nick;
    }

    
    if ((new_nick = malloc (sizeof (*new_nick))) == NULL)
        return NULL;

    
    new_nick->name = strdup (nickname);
    new_nick->host = (host) ? strdup (host) : NULL;
    new_nick->account = (account) ? strdup (account) : NULL;
    new_nick->realname = (realname) ? strdup (realname) : NULL;
    length = strlen (irc_server_get_prefix_chars (server));
    new_nick->prefixes = malloc (length + 1);
    new_nick->prefix = malloc (2);
    if (!new_nick->name || !new_nick->prefixes || !new_nick->prefix)
    {
        if (new_nick->name)
            free (new_nick->name);
        if (new_nick->host)
            free (new_nick->host);
        if (new_nick->account)
            free (new_nick->account);
        if (new_nick->realname)
            free (new_nick->realname);
        if (new_nick->prefixes)
            free (new_nick->prefixes);
        if (new_nick->prefix)
            free (new_nick->prefix);
        free (new_nick);
        return NULL;
    }
    memset (new_nick->prefixes, ' ', length);
    new_nick->prefixes[length] = '\0';
    new_nick->prefix[0] = ' ';
    new_nick->prefix[1] = '\0';
    irc_nick_set_prefixes (server, new_nick, prefixes);
    new_nick->away = away;
    if (irc_server_strcasecmp (server, new_nick->name, server->nick) == 0)
        new_nick->color = strdup (IRC_COLOR_CHAT_NICK_SELF);
    else new_nick->color = irc_nick_find_color (new_nick->name);

    
    new_nick->prev_nick = channel->last_nick;
    if (channel->last_nick)
        channel->last_nick->next_nick = new_nick;
    else channel->nicks = new_nick;
    channel->last_nick = new_nick;
    new_nick->next_nick = NULL;

    channel->nicks_count++;

    channel->nick_completion_reset = 1;

    
    irc_nick_nicklist_add (server, channel, new_nick);

    
    return new_nick;
}



void irc_nick_change (struct t_irc_server *server, struct t_irc_channel *channel, struct t_irc_nick *nick, const char *new_nick)

{
    int nick_is_me;

    
    irc_nick_nicklist_remove (server, channel, nick);

    
    nick_is_me = (irc_server_strcasecmp (server, new_nick, server->nick) == 0) ? 1 : 0;
    if (!nick_is_me)
        irc_channel_nick_speaking_rename (channel, nick->name, new_nick);

    
    if (nick->name)
        free (nick->name);
    nick->name = strdup (new_nick);
    if (nick->color)
        free (nick->color);
    if (nick_is_me)
        nick->color = strdup (IRC_COLOR_CHAT_NICK_SELF);
    else nick->color = irc_nick_find_color (nick->name);

    
    irc_nick_nicklist_add (server, channel, nick);
}



void irc_nick_set_mode (struct t_irc_server *server, struct t_irc_channel *channel, struct t_irc_nick *nick, int set, char mode)

{
    int index;
    const char *prefix_chars;

    index = irc_server_get_prefix_mode_index (server, mode);
    if (index < 0)
        return;

    
    irc_nick_nicklist_remove (server, channel, nick);

    
    prefix_chars = irc_server_get_prefix_chars (server);
    irc_nick_set_prefix (server, nick, set, prefix_chars[index]);

    
    irc_nick_nicklist_add (server, channel, nick);

    if (irc_server_strcasecmp (server, nick->name, server->nick) == 0)
    {
        weechat_bar_item_update ("input_prompt");
        weechat_bar_item_update ("irc_nick");
        weechat_bar_item_update ("irc_nick_host");
    }
}



void irc_nick_free (struct t_irc_server *server, struct t_irc_channel *channel, struct t_irc_nick *nick)

{
    struct t_irc_nick *new_nicks;

    if (!channel || !nick)
        return;

    
    irc_nick_nicklist_remove (server, channel, nick);

    
    if (channel->last_nick == nick)
        channel->last_nick = nick->prev_nick;
    if (nick->prev_nick)
    {
        (nick->prev_nick)->next_nick = nick->next_nick;
        new_nicks = channel->nicks;
    }
    else new_nicks = nick->next_nick;

    if (nick->next_nick)
        (nick->next_nick)->prev_nick = nick->prev_nick;

    channel->nicks_count--;

    
    if (nick->name)
        free (nick->name);
    if (nick->host)
        free (nick->host);
    if (nick->prefixes)
        free (nick->prefixes);
    if (nick->prefix)
        free (nick->prefix);
    if (nick->account)
        free (nick->account);
    if (nick->realname)
        free (nick->realname);
    if (nick->color)
        free (nick->color);

    free (nick);

    channel->nicks = new_nicks;
    channel->nick_completion_reset = 1;
}



void irc_nick_free_all (struct t_irc_server *server, struct t_irc_channel *channel)
{
    if (!channel)
        return;

    
    while (channel->nicks)
    {
        irc_nick_free (server, channel, channel->nicks);
    }

    
    weechat_nicklist_remove_all (channel->buffer);

    
    channel->nicks_count = 0;
}



struct t_irc_nick * irc_nick_search (struct t_irc_server *server, struct t_irc_channel *channel, const char *nickname)

{
    struct t_irc_nick *ptr_nick;

    if (!channel || !nickname)
        return NULL;

    for (ptr_nick = channel->nicks; ptr_nick;
         ptr_nick = ptr_nick->next_nick)
    {
        if (irc_server_strcasecmp (server, ptr_nick->name, nickname) == 0)
            return ptr_nick;
    }

    
    return NULL;
}



void irc_nick_count (struct t_irc_server *server, struct t_irc_channel *channel, int *total, int *count_op, int *count_halfop, int *count_voice, int *count_normal)


{
    struct t_irc_nick *ptr_nick;

    (*total) = 0;
    (*count_op) = 0;
    (*count_halfop) = 0;
    (*count_voice) = 0;
    (*count_normal) = 0;
    for (ptr_nick = channel->nicks; ptr_nick;
         ptr_nick = ptr_nick->next_nick)
    {
        (*total)++;
        if (irc_nick_is_op (server, ptr_nick))
            (*count_op)++;
        else {
            if (irc_nick_has_prefix_mode (server, ptr_nick, 'h'))
                (*count_halfop)++;
            else {
                if (irc_nick_has_prefix_mode (server, ptr_nick, 'v'))
                    (*count_voice)++;
                else (*count_normal)++;
            }
        }
    }
}



void irc_nick_set_away (struct t_irc_server *server, struct t_irc_channel *channel, struct t_irc_nick *nick, int is_away)

{
    char *color;

    if (is_away != nick->away)
    {
        nick->away = is_away;
        color = irc_nick_get_color_for_nicklist (server, nick);
        irc_nick_nicklist_set (channel, nick, "color", color);
        if (color)
            free (color);
    }
}



const char * irc_nick_mode_for_display (struct t_irc_server *server, struct t_irc_nick *nick, int prefix)

{
    static char result[32];
    char str_prefix[2];
    int nick_mode;
    const char *str_prefix_color;

    str_prefix[0] = (nick) ? nick->prefix[0] : '\0';
    str_prefix[1] = '\0';

    nick_mode = weechat_config_integer (irc_config_look_nick_mode);
    if ((nick_mode == IRC_CONFIG_LOOK_NICK_MODE_BOTH)
        || (prefix && (nick_mode == IRC_CONFIG_LOOK_NICK_MODE_PREFIX))
        || (!prefix && (nick_mode == IRC_CONFIG_LOOK_NICK_MODE_ACTION)))
    {
        if (nick)
        {
            if ((str_prefix[0] == ' ')
                && (!prefix || !weechat_config_boolean (irc_config_look_nick_mode_empty)))
            {
                str_prefix[0] = '\0';
            }
            str_prefix_color = weechat_color ( irc_nick_get_prefix_color_name (server, nick->prefix[0]));
        }
        else {
            str_prefix[0] = (prefix && weechat_config_boolean (irc_config_look_nick_mode_empty)) ? ' ' : '\0';

            str_prefix_color = IRC_COLOR_RESET;
        }
    }
    else {
        str_prefix[0] = '\0';
        str_prefix_color = IRC_COLOR_RESET;
    }

    snprintf (result, sizeof (result), "%s%s", str_prefix_color, str_prefix);

    return result;
}



const char * irc_nick_as_prefix (struct t_irc_server *server, struct t_irc_nick *nick, const char *nickname, const char *force_color)

{
    static char result[256];
    char *color;

    if (force_color)
        color = strdup (force_color);
    else if (nick)
        color = strdup (nick->color);
    else if (nickname)
        color = irc_nick_find_color (nickname);
    else color = strdup (IRC_COLOR_CHAT_NICK);

    snprintf (result, sizeof (result), "%s%s%s\t", irc_nick_mode_for_display (server, nick, 1), color, (nick) ? nick->name : nickname);



    if (color)
        free (color);

    return result;
}



const char * irc_nick_color_for_msg (struct t_irc_server *server, int server_message, struct t_irc_nick *nick, const char *nickname)

{
    static char color[16][64];
    static int index_color = 0;
    char *color_found;

    if (server_message && !weechat_config_boolean (irc_config_look_color_nicks_in_server_messages))
    {
        return IRC_COLOR_CHAT_NICK;
    }

    if (nick)
        return nick->color;

    if (nickname)
    {
        if (server && (irc_server_strcasecmp (server, nickname, server->nick) == 0))
        {
            return IRC_COLOR_CHAT_NICK_SELF;
        }
        color_found = irc_nick_find_color (nickname);
        index_color = (index_color + 1) % 16;
        snprintf (color[index_color], sizeof (color[index_color]), "%s", color_found);

        if (color_found)
            free (color_found);
        return color[index_color];
    }

    return IRC_COLOR_CHAT_NICK;
}



const char * irc_nick_color_for_pv (struct t_irc_channel *channel, const char *nickname)
{
    if (weechat_config_boolean (irc_config_look_color_pv_nick_like_channel))
    {
        if (!channel->pv_remote_nick_color)
            channel->pv_remote_nick_color = irc_nick_find_color (nickname);
        if (channel->pv_remote_nick_color)
            return channel->pv_remote_nick_color;
    }

    return IRC_COLOR_CHAT_NICK_OTHER;
}



char * irc_nick_default_ban_mask (struct t_irc_nick *nick)
{
    const char *ptr_ban_mask;
    char *pos_hostname, user[128], ident[128], *res, *temp;

    if (!nick)
        return NULL;

    ptr_ban_mask = weechat_config_string (irc_config_network_ban_mask_default);

    pos_hostname = (nick->host) ? strchr (nick->host, '@') : NULL;

    if (!nick->host || !pos_hostname || !ptr_ban_mask || !ptr_ban_mask[0])
        return NULL;

    if (pos_hostname - nick->host > (int)sizeof (user) - 1)
        return NULL;

    strncpy (user, nick->host, pos_hostname - nick->host);
    user[pos_hostname - nick->host] = '\0';
    strcpy (ident, (user[0] != '~') ? user : "*");
    pos_hostname++;

    
    temp = weechat_string_replace (ptr_ban_mask, "$nick", nick->name);
    if (!temp)
        return NULL;
    res = temp;

    
    temp = weechat_string_replace (res, "$user", user);
    free (res);
    if (!temp)
        return NULL;
    res = temp;

    
    temp = weechat_string_replace (res, "$ident", ident);
    free (res);
    if (!temp)
        return NULL;
    res = temp;

    
    temp = weechat_string_replace (res, "$host", pos_hostname);
    free (res);
    if (!temp)
        return NULL;
    res = temp;

    return res;
}



struct t_hdata * irc_nick_hdata_nick_cb (const void *pointer, void *data, const char *hdata_name)

{
    struct t_hdata *hdata;

    
    (void) pointer;
    (void) data;

    hdata = weechat_hdata_new (hdata_name, "prev_nick", "next_nick", 0, 0, NULL, NULL);
    if (hdata)
    {
        WEECHAT_HDATA_VAR(struct t_irc_nick, name, STRING, 0, NULL, NULL);
        WEECHAT_HDATA_VAR(struct t_irc_nick, host, STRING, 0, NULL, NULL);
        WEECHAT_HDATA_VAR(struct t_irc_nick, prefixes, STRING, 0, NULL, NULL);
        WEECHAT_HDATA_VAR(struct t_irc_nick, prefix, STRING, 0, NULL, NULL);
        WEECHAT_HDATA_VAR(struct t_irc_nick, away, INTEGER, 0, NULL, NULL);
        WEECHAT_HDATA_VAR(struct t_irc_nick, account, STRING, 0, NULL, NULL);
        WEECHAT_HDATA_VAR(struct t_irc_nick, realname, STRING, 0, NULL, NULL);
        WEECHAT_HDATA_VAR(struct t_irc_nick, color, STRING, 0, NULL, NULL);
        WEECHAT_HDATA_VAR(struct t_irc_nick, prev_nick, POINTER, 0, NULL, hdata_name);
        WEECHAT_HDATA_VAR(struct t_irc_nick, next_nick, POINTER, 0, NULL, hdata_name);
    }
    return hdata;
}



int irc_nick_add_to_infolist (struct t_infolist *infolist, struct t_irc_nick *nick)

{
    struct t_infolist_item *ptr_item;

    if (!infolist || !nick)
        return 0;

    ptr_item = weechat_infolist_new_item (infolist);
    if (!ptr_item)
        return 0;

    if (!weechat_infolist_new_var_string (ptr_item, "name", nick->name))
        return 0;
    if (!weechat_infolist_new_var_string (ptr_item, "host", nick->host))
        return 0;
    if (!weechat_infolist_new_var_string (ptr_item, "prefixes", nick->prefixes))
        return 0;
    if (!weechat_infolist_new_var_string (ptr_item, "prefix", nick->prefix))
        return 0;
    if (!weechat_infolist_new_var_integer (ptr_item, "away", nick->away))
        return 0;
    if (!weechat_infolist_new_var_string (ptr_item, "account", nick->account))
        return 0;
    if (!weechat_infolist_new_var_string (ptr_item, "realname", nick->realname))
        return 0;
    if (!weechat_infolist_new_var_string (ptr_item, "color", nick->color))
        return 0;

    return 1;
}



void irc_nick_print_log (struct t_irc_nick *nick)
{
    weechat_log_printf ("");
    weechat_log_printf ("    => nick %s (addr:0x%lx):",    nick->name, nick);
    weechat_log_printf ("         host . . . . . : '%s'",  nick->host);
    weechat_log_printf ("         prefixes . . . : '%s'",  nick->prefixes);
    weechat_log_printf ("         prefix . . . . : '%s'",  nick->prefix);
    weechat_log_printf ("         away . . . . . : %d",    nick->away);
    weechat_log_printf ("         account. . . . : '%s'",  nick->account);
    weechat_log_printf ("         realname . . . : '%s'",  nick->realname);
    weechat_log_printf ("         color. . . . . : '%s'",  nick->color);
    weechat_log_printf ("         prev_nick. . . : 0x%lx", nick->prev_nick);
    weechat_log_printf ("         next_nick. . . : 0x%lx", nick->next_nick);
}
