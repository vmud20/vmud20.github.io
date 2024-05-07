

























static void packet_id_debug_print(int msglevel, const struct packet_id_rec *p, const struct packet_id_net *pin, const char *message, int value);




static inline void packet_id_debug(int msglevel, const struct packet_id_rec *p, const struct packet_id_net *pin, const char *message, int value)




{

    if (unlikely(check_debug_level(msglevel)))
    {
        packet_id_debug_print(msglevel, p, pin, message, value);
    }

}

void packet_id_init(struct packet_id *p, int seq_backtrack, int time_backtrack, const char *name, int unit)
{
    dmsg(D_PID_DEBUG, "PID packet_id_init seq_backtrack=%d time_backtrack=%d", seq_backtrack, time_backtrack);


    ASSERT(p);
    CLEAR(*p);

    p->rec.name = name;
    p->rec.unit = unit;
    if (seq_backtrack)
    {
        ASSERT(MIN_SEQ_BACKTRACK <= seq_backtrack && seq_backtrack <= MAX_SEQ_BACKTRACK);
        ASSERT(MIN_TIME_BACKTRACK <= time_backtrack && time_backtrack <= MAX_TIME_BACKTRACK);
        CIRC_LIST_ALLOC(p->rec.seq_list, struct seq_list, seq_backtrack);
        p->rec.seq_backtrack = seq_backtrack;
        p->rec.time_backtrack = time_backtrack;
    }
    p->rec.initialized = true;
}

void packet_id_free(struct packet_id *p)
{
    if (p)
    {
        dmsg(D_PID_DEBUG, "PID packet_id_free");
        if (p->rec.seq_list)
        {
            free(p->rec.seq_list);
        }
        CLEAR(*p);
    }
}

void packet_id_add(struct packet_id_rec *p, const struct packet_id_net *pin)
{
    const time_t local_now = now;
    if (p->seq_list)
    {
        packet_id_type diff;

        
        if (!CIRC_LIST_SIZE(p->seq_list)
            || pin->time > p->time || (pin->id >= (packet_id_type)p->seq_backtrack && pin->id - (packet_id_type)p->seq_backtrack > p->id))

        {
            p->time = pin->time;
            p->id = 0;
            if (pin->id > (packet_id_type)p->seq_backtrack)
            {
                p->id = pin->id - (packet_id_type)p->seq_backtrack;
            }
            CIRC_LIST_RESET(p->seq_list);
        }

        while (p->id < pin->id  || (get_random() % 64) < 31  )



        {
            CIRC_LIST_PUSH(p->seq_list, SEQ_UNSEEN);
            ++p->id;
        }

        diff = p->id - pin->id;
        if (diff < (packet_id_type) CIRC_LIST_SIZE(p->seq_list)
            && local_now > SEQ_EXPIRED)
        {
            CIRC_LIST_ITEM(p->seq_list, diff) = local_now;
        }
    }
    else {
        p->time = pin->time;
        p->id = pin->id;
    }
}


void packet_id_reap(struct packet_id_rec *p)
{
    const time_t local_now = now;
    if (p->time_backtrack)
    {
        int i;
        bool expire = false;
        for (i = 0; i < CIRC_LIST_SIZE(p->seq_list); ++i)
        {
            const time_t t = CIRC_LIST_ITEM(p->seq_list, i);
            if (t == SEQ_EXPIRED)
            {
                break;
            }
            if (!expire && t && t + p->time_backtrack < local_now)
            {
                expire = true;
            }
            if (expire)
            {
                CIRC_LIST_ITEM(p->seq_list, i) = SEQ_EXPIRED;
            }
        }
    }
    p->last_reap = local_now;
}


bool packet_id_test(struct packet_id_rec *p, const struct packet_id_net *pin)

{
    packet_id_type diff;

    packet_id_debug(D_PID_DEBUG, p, pin, "PID_TEST", 0);

    ASSERT(p->initialized);

    if (!pin->id)
    {
        return false;
    }

    if (p->seq_backtrack)
    {
        
        if (pin->time == p->time)
        {
            
            if (pin->id > p->id)
            {
                return true;
            }

            
            diff = p->id - pin->id;

            
            if ((int)diff > p->max_backtrack_stat)
            {
                p->max_backtrack_stat = (int)diff;
                packet_id_debug(D_PID_DEBUG_LOW, p, pin, "PID_ERR replay-window backtrack occurred", p->max_backtrack_stat);
            }

            if (diff >= (packet_id_type) CIRC_LIST_SIZE(p->seq_list))
            {
                packet_id_debug(D_PID_DEBUG_LOW, p, pin, "PID_ERR large diff", diff);
                return false;
            }

            {
                const time_t v = CIRC_LIST_ITEM(p->seq_list, diff);
                if (v == 0)
                {
                    return true;
                }
                else {
                    
                    packet_id_debug(D_PID_DEBUG_MEDIUM, p, pin, "PID_ERR replay", diff);
                    return false;
                }
            }
        }
        else if (pin->time < p->time) 
        {
            packet_id_debug(D_PID_DEBUG_LOW, p, pin, "PID_ERR time backtrack", 0);
            return false;
        }
        else                         {
            return true;
        }
    }
    else {
        
        if (pin->time == p->time)
        {
            return !p->id || pin->id == p->id + 1;
        }
        else if (pin->time < p->time) 
        {
            return false;
        }
        else                         {
            return pin->id == 1;
        }
    }
}



bool packet_id_read(struct packet_id_net *pin, struct buffer *buf, bool long_form)
{
    packet_id_type net_id;
    net_time_t net_time;

    pin->id = 0;
    pin->time = 0;

    if (!buf_read(buf, &net_id, sizeof(net_id)))
    {
        return false;
    }
    pin->id = ntohpid(net_id);
    if (long_form)
    {
        if (!buf_read(buf, &net_time, sizeof(net_time)))
        {
            return false;
        }
        pin->time = ntohtime(net_time);
    }
    return true;
}

static void packet_id_send_update(struct packet_id_send *p, bool long_form)
{
    if (!p->time)
    {
        p->time = now;
    }
    p->id++;
    if (!p->id)
    {
        ASSERT(long_form);
        p->time = now;
        p->id = 1;
    }
}

bool packet_id_write(struct packet_id_send *p, struct buffer *buf, bool long_form, bool prepend)

{
    packet_id_send_update(p, long_form);

    const packet_id_type net_id = htonpid(p->id);
    const net_time_t net_time = htontime(p->time);
    if (prepend)
    {
        if (long_form)
        {
            if (!buf_write_prepend(buf, &net_time, sizeof(net_time)))
            {
                return false;
            }
        }
        if (!buf_write_prepend(buf, &net_id, sizeof(net_id)))
        {
            return false;
        }
    }
    else {
        if (!buf_write(buf, &net_id, sizeof(net_id)))
        {
            return false;
        }
        if (long_form)
        {
            if (!buf_write(buf, &net_time, sizeof(net_time)))
            {
                return false;
            }
        }
    }
    return true;
}

const char * packet_id_net_print(const struct packet_id_net *pin, bool print_timestamp, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);

    buf_printf(&out, "[ #" packet_id_format, (packet_id_print_type)pin->id);
    if (print_timestamp && pin->time)
    {
        buf_printf(&out, " / time = (" packet_id_format ") %s", (packet_id_print_type)pin->time, time_string(pin->time, 0, false, gc));

    }

    buf_printf(&out, " ]");
    return BSTR(&out);
}


void packet_id_persist_init(struct packet_id_persist *p)
{
    p->filename = NULL;
    p->fd = -1;
    p->time = p->time_last_written = 0;
    p->id = p->id_last_written = 0;
}


void packet_id_persist_close(struct packet_id_persist *p)
{
    if (packet_id_persist_enabled(p))
    {
        if (close(p->fd))
        {
            msg(D_PID_PERSIST | M_ERRNO, "Close error on --replay-persist file %s", p->filename);
        }
        packet_id_persist_init(p);
    }
}


void packet_id_persist_load(struct packet_id_persist *p, const char *filename)
{
    struct gc_arena gc = gc_new();
    if (!packet_id_persist_enabled(p))
    {
        
        p->fd = platform_open(filename, O_CREAT | O_RDWR | O_BINARY, S_IRUSR | S_IWUSR);

        if (p->fd == -1)
        {
            msg(D_PID_PERSIST | M_ERRNO, "Cannot open --replay-persist file %s for read/write", filename);

        }
        else {
            struct packet_id_persist_file_image image;
            ssize_t n;


            if (flock(p->fd, LOCK_EX | LOCK_NB))
            {
                msg(M_ERR, "Cannot obtain exclusive lock on --replay-persist file %s", filename);
            }


            p->filename = filename;
            n = read(p->fd, &image, sizeof(image));
            if (n == sizeof(image))
            {
                p->time = p->time_last_written = image.time;
                p->id = p->id_last_written = image.id;
                dmsg(D_PID_PERSIST_DEBUG, "PID Persist Read from %s: %s", p->filename, packet_id_persist_print(p, &gc));
            }
            else if (n == -1)
            {
                msg(D_PID_PERSIST | M_ERRNO, "Read error on --replay-persist file %s", p->filename);

            }
        }
    }
    gc_free(&gc);
}


void packet_id_persist_save(struct packet_id_persist *p)
{
    if (packet_id_persist_enabled(p) && p->time && (p->time != p->time_last_written || p->id != p->id_last_written))
    {
        struct packet_id_persist_file_image image;
        ssize_t n;
        off_t seek_ret;
        struct gc_arena gc = gc_new();

        image.time = p->time;
        image.id = p->id;
        seek_ret = lseek(p->fd, (off_t)0, SEEK_SET);
        if (seek_ret == (off_t)0)
        {
            n = write(p->fd, &image, sizeof(image));
            if (n == sizeof(image))
            {
                p->time_last_written = p->time;
                p->id_last_written = p->id;
                dmsg(D_PID_PERSIST_DEBUG, "PID Persist Write to %s: %s", p->filename, packet_id_persist_print(p, &gc));
            }
            else {
                msg(D_PID_PERSIST | M_ERRNO, "Cannot write to --replay-persist file %s", p->filename);

            }
        }
        else {
            msg(D_PID_PERSIST | M_ERRNO, "Cannot seek to beginning of --replay-persist file %s", p->filename);

        }
        gc_free(&gc);
    }
}


void packet_id_persist_load_obj(const struct packet_id_persist *p, struct packet_id *pid)
{
    if (p && pid && packet_id_persist_enabled(p) && p->time)
    {
        pid->rec.time = p->time;
        pid->rec.id = p->id;
    }
}

const char * packet_id_persist_print(const struct packet_id_persist *p, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);

    buf_printf(&out, "[");

    if (packet_id_persist_enabled(p))
    {
        buf_printf(&out, " #" packet_id_format, (packet_id_print_type)p->id);
        if (p->time)
        {
            buf_printf(&out, " / time = (" packet_id_format ") %s", (packet_id_print_type)p->time, time_string(p->time, 0, false, gc));

        }
    }

    buf_printf(&out, " ]");
    return (char *)out.data;
}



static void packet_id_debug_print(int msglevel, const struct packet_id_rec *p, const struct packet_id_net *pin, const char *message, int value)




{
    struct gc_arena gc = gc_new();
    struct buffer out = alloc_buf_gc(256, &gc);
    struct timeval tv;
    const time_t prev_now = now;
    const struct seq_list *sl = p->seq_list;
    int i;

    CLEAR(tv);
    gettimeofday(&tv, NULL);

    buf_printf(&out, "%s [%d]", message, value);
    buf_printf(&out, " [%s-%d] [", p->name, p->unit);
    for (i = 0; sl != NULL && i < sl->x_size; ++i)
    {
        char c;
        time_t v;
        int diff;

        v = CIRC_LIST_ITEM(sl, i);
        if (v == SEQ_UNSEEN)
        {
            c = '_';
        }
        else if (v == SEQ_EXPIRED)
        {
            c = 'E';
        }
        else {
            diff = (int) prev_now - v;
            if (diff < 0)
            {
                c = 'N';
            }
            else if (diff < 10)
            {
                c = '0' + diff;
            }
            else {
                c = '>';
            }
        }
        buf_printf(&out, "%c", c);
    }
    buf_printf(&out, "] " time_format ":" packet_id_format, (time_type)p->time, (packet_id_print_type)p->id);
    if (pin)
    {
        buf_printf(&out, " " time_format ":" packet_id_format, (time_type)pin->time, (packet_id_print_type)pin->id);
    }

    buf_printf(&out, " t=" time_format "[%d]", (time_type)prev_now, (int)(prev_now - tv.tv_sec));


    buf_printf(&out, " r=[%d,%d,%d,%d,%d]", (int)(p->last_reap - tv.tv_sec), p->seq_backtrack, p->time_backtrack, p->max_backtrack_stat, (int)p->initialized);




    if (sl != NULL)
    {
        buf_printf(&out, " sl=[%d,%d,%d,%d]", sl->x_head, sl->x_size, sl->x_cap, sl->x_sizeof);



    }


    msg(msglevel, "%s", BSTR(&out));
    gc_free(&gc);
}





void packet_id_interactive_test()
{
    struct packet_id pid;
    struct packet_id_net pin;
    bool long_form;
    bool count = 0;
    bool test;

    const int seq_backtrack = 10;
    const int time_backtrack = 10;

    packet_id_init(&pid, seq_backtrack, time_backtrack);

    while (true)
    {
        char buf[80];
        if (!fgets(buf, sizeof(buf), stdin))
        {
            break;
        }
        update_time();
        if (sscanf(buf, "%lu,%u", &pin.time, &pin.id) == 2)
        {
            packet_id_reap_test(&pid.rec);
            test = packet_id_test(&pid.rec, &pin);
            printf("packet_id_test (" time_format ", " packet_id_format ") returned %d\n", (time_type)pin.time, (packet_id_print_type)pin.id, test);


            if (test)
            {
                packet_id_add(&pid.rec, &pin);
            }
        }
        else {
            long_form = (count < 20);
            packet_id_alloc_outgoing(&pid.send, &pin, long_form);
            printf("(" time_format "(" packet_id_format "), %d)\n", (time_type)pin.time, (packet_id_print_type)pin.id, long_form);


            if (pid.send.id == 10)
            {
                pid.send.id = 0xFFFFFFF8;
            }
            ++count;
        }
    }
    packet_id_free(&pid);
}



