

































module AP_MODULE_DECLARE_DATA status_module;

static int server_limit, thread_limit, threads_per_child, max_servers, is_async;


APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap, STATUS, int, status_hook, (request_rec *r, int flags), (r, flags), OK, DECLINED)





static pid_t child_pid;



static void format_byte_out(request_rec *r, apr_off_t bytes)
{
    if (bytes < (5 * KBYTE))
        ap_rprintf(r, "%d B", (int) bytes);
    else if (bytes < (MBYTE / 2))
        ap_rprintf(r, "%.1f kB", (float) bytes / KBYTE);
    else if (bytes < (GBYTE / 2))
        ap_rprintf(r, "%.1f MB", (float) bytes / MBYTE);
    else ap_rprintf(r, "%.1f GB", (float) bytes / GBYTE);
}

static void format_kbyte_out(request_rec *r, apr_off_t kbytes)
{
    if (kbytes < KBYTE)
        ap_rprintf(r, "%d kB", (int) kbytes);
    else if (kbytes < MBYTE)
        ap_rprintf(r, "%.1f MB", (float) kbytes / KBYTE);
    else ap_rprintf(r, "%.1f GB", (float) kbytes / MBYTE);
}

static void show_time(request_rec *r, apr_interval_time_t tsecs)
{
    int days, hrs, mins, secs;

    secs = (int)(tsecs % 60);
    tsecs /= 60;
    mins = (int)(tsecs % 60);
    tsecs /= 60;
    hrs = (int)(tsecs % 24);
    days = (int)(tsecs / 24);

    if (days)
        ap_rprintf(r, " %d day%s", days, days == 1 ? "" : "s");

    if (hrs)
        ap_rprintf(r, " %d hour%s", hrs, hrs == 1 ? "" : "s");

    if (mins)
        ap_rprintf(r, " %d minute%s", mins, mins == 1 ? "" : "s");

    if (secs)
        ap_rprintf(r, " %d second%s", secs, secs == 1 ? "" : "s");
}










struct stat_opt {
    int id;
    const char *form_data_str;
    const char *hdr_out_str;
};

static const struct stat_opt status_options[] =  {
    {STAT_OPT_REFRESH, "refresh", "Refresh", {STAT_OPT_NOTABLE, "notable", NULL}, {STAT_OPT_AUTO, "auto", NULL}, {STAT_OPT_END, NULL, NULL}


};





static char status_flags[MOD_STATUS_NUM_STATUS];

static int status_handler(request_rec *r)
{
    const char *loc;
    apr_time_t nowtime;
    apr_interval_time_t up_time;
    int j, i, res, written;
    int ready;
    int busy;
    unsigned long count;
    unsigned long lres, my_lres, conn_lres;
    apr_off_t bytes, my_bytes, conn_bytes;
    apr_off_t bcount, kbcount;
    long req_time;
    int short_report;
    int no_table_report;
    worker_score *ws_record;
    process_score *ps_record;
    char *stat_buffer;
    pid_t *pid_buffer, worker_pid;
    int *thread_idle_buffer = NULL;
    int *thread_busy_buffer = NULL;
    clock_t tu, ts, tcu, tcs;
    ap_generation_t mpm_generation, worker_generation;

    float tick;
    int times_per_thread;


    if (strcmp(r->handler, STATUS_MAGIC_TYPE) && strcmp(r->handler, "server-status")) {
        return DECLINED;
    }


    times_per_thread = getpid() != child_pid;


    ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);



    tick = sysconf(_SC_CLK_TCK);

    tick = HZ;



    ready = 0;
    busy = 0;
    count = 0;
    bcount = 0;
    kbcount = 0;
    short_report = 0;
    no_table_report = 0;

    pid_buffer = apr_palloc(r->pool, server_limit * sizeof(pid_t));
    stat_buffer = apr_palloc(r->pool, server_limit * thread_limit * sizeof(char));
    if (is_async) {
        thread_idle_buffer = apr_palloc(r->pool, server_limit * sizeof(int));
        thread_busy_buffer = apr_palloc(r->pool, server_limit * sizeof(int));
    }

    nowtime = apr_time_now();
    tu = ts = tcu = tcs = 0;

    if (!ap_exists_scoreboard_image()) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01237)
                      "Server status unavailable in inetd mode");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allowed = (AP_METHOD_BIT << M_GET);
    if (r->method_number != M_GET)
        return DECLINED;

    ap_set_content_type(r, "text/html; charset=ISO-8859-1");

    

    if (r->args) {
        i = 0;
        while (status_options[i].id != STAT_OPT_END) {
            if ((loc = ap_strstr_c(r->args, status_options[i].form_data_str)) != NULL) {
                switch (status_options[i].id) {
                case STAT_OPT_REFRESH: {
                    apr_size_t len = strlen(status_options[i].form_data_str);
                    long t = 0;

                    if (*(loc + len ) == '=') {
                        t = atol(loc + len + 1);
                    }
                    apr_table_setn(r->headers_out, status_options[i].hdr_out_str, apr_ltoa(r->pool, t < 1 ? 10 : t));

                    break;
                }
                case STAT_OPT_NOTABLE:
                    no_table_report = 1;
                    break;
                case STAT_OPT_AUTO:
                    ap_set_content_type(r, "text/plain; charset=ISO-8859-1");
                    short_report = 1;
                    break;
                }
            }

            i++;
        }
    }

    for (i = 0; i < server_limit; ++i) {

        clock_t proc_tu = 0, proc_ts = 0, proc_tcu = 0, proc_tcs = 0;
        clock_t tmp_tu, tmp_ts, tmp_tcu, tmp_tcs;


        ps_record = ap_get_scoreboard_process(i);
        if (is_async) {
            thread_idle_buffer[i] = 0;
            thread_busy_buffer[i] = 0;
        }
        for (j = 0; j < thread_limit; ++j) {
            int indx = (i * thread_limit) + j;

            ws_record = ap_get_scoreboard_worker_from_indexes(i, j);
            res = ws_record->status;

            if ((i >= max_servers || j >= threads_per_child)
                && (res == SERVER_DEAD))
                stat_buffer[indx] = status_flags[SERVER_DISABLED];
            else stat_buffer[indx] = status_flags[res];

            if (!ps_record->quiescing && ps_record->pid) {
                if (res == SERVER_READY) {
                    if (ps_record->generation == mpm_generation)
                        ready++;
                    if (is_async)
                        thread_idle_buffer[i]++;
                }
                else if (res != SERVER_DEAD && res != SERVER_STARTING && res != SERVER_IDLE_KILL) {

                    busy++;
                    if (is_async) {
                        if (res == SERVER_GRACEFUL)
                            thread_idle_buffer[i]++;
                        else thread_busy_buffer[i]++;
                    }
                }
            }

            
            if (ap_extended_status) {
                lres = ws_record->access_count;
                bytes = ws_record->bytes_served;

                if (lres != 0 || (res != SERVER_READY && res != SERVER_DEAD)) {

                    tmp_tu = ws_record->times.tms_utime;
                    tmp_ts = ws_record->times.tms_stime;
                    tmp_tcu = ws_record->times.tms_cutime;
                    tmp_tcs = ws_record->times.tms_cstime;

                    if (times_per_thread) {
                        proc_tu += tmp_tu;
                        proc_ts += tmp_ts;
                        proc_tcu += tmp_tcu;
                        proc_tcs += tmp_tcs;
                    }
                    else {
                        if (tmp_tu > proc_tu || tmp_ts > proc_ts || tmp_tcu > proc_tcu || tmp_tcs > proc_tcs) {


                            proc_tu = tmp_tu;
                            proc_ts = tmp_ts;
                            proc_tcu = tmp_tcu;
                            proc_tcs = tmp_tcs;
                        }
                    }


                    count += lres;
                    bcount += bytes;

                    if (bcount >= KBYTE) {
                        kbcount += (bcount >> 10);
                        bcount = bcount & 0x3ff;
                    }
                }
            }
        }

        tu += proc_tu;
        ts += proc_ts;
        tcu += proc_tcu;
        tcs += proc_tcs;

        pid_buffer[i] = ps_record->pid;
    }

    
    up_time = (apr_uint32_t) apr_time_sec(nowtime - ap_scoreboard_image->global->restart_time);

    if (!short_report) {
        ap_loadavg_t t;

        ap_rputs(DOCTYPE_HTML_3_2 "<html><head>\n" "<title>Apache Status</title>\n" "</head><body>\n" "<h1>Apache Server Status for ", r);



        ap_rvputs(r, ap_escape_html(r->pool, ap_get_server_name(r)), " (via ", r->connection->local_ip, ")</h1>\n\n", NULL);

        ap_rvputs(r, "<dl><dt>Server Version: ", ap_get_server_description(), "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Server MPM: ", ap_show_mpm(), "</dt>\n", NULL);
        ap_rvputs(r, "<dt>Server Built: ", ap_get_server_built(), "\n</dt></dl><hr /><dl>\n", NULL);
        ap_rvputs(r, "<dt>Current Time: ", ap_ht_time(r->pool, nowtime, DEFAULT_TIME_FORMAT, 0), "</dt>\n", NULL);

        ap_rvputs(r, "<dt>Restart Time: ", ap_ht_time(r->pool, ap_scoreboard_image->global->restart_time, DEFAULT_TIME_FORMAT, 0), "</dt>\n", NULL);



        ap_rprintf(r, "<dt>Parent Server Config. Generation: %d</dt>\n", ap_state_query(AP_SQ_CONFIG_GEN));
        ap_rprintf(r, "<dt>Parent Server MPM Generation: %d</dt>\n", (int)mpm_generation);
        ap_rputs("<dt>Server uptime: ", r);
        show_time(r, up_time);
        ap_rputs("</dt>\n", r);
        ap_get_loadavg(&t);
        ap_rprintf(r, "<dt>Server load: %.2f %.2f %.2f</dt>\n", t.loadavg, t.loadavg5, t.loadavg15);
    }

    if (ap_extended_status) {
        if (short_report) {
            ap_rprintf(r, "Total Accesses: %lu\nTotal kBytes: %" APR_OFF_T_FMT "\n", count, kbcount);



            
            if (ts || tu || tcu || tcs)
                ap_rprintf(r, "CPULoad: %g\n", (tu + ts + tcu + tcs) / tick / up_time * 100.);


            ap_rprintf(r, "Uptime: %ld\n", (long) (up_time));
            if (up_time > 0) {
                ap_rprintf(r, "ReqPerSec: %g\n", (float) count / (float) up_time);

                ap_rprintf(r, "BytesPerSec: %g\n", KBYTE * (float) kbcount / (float) up_time);
            }
            if (count > 0)
                ap_rprintf(r, "BytesPerReq: %g\n", KBYTE * (float) kbcount / (float) count);
        }
        else { 
            ap_rprintf(r, "<dt>Total accesses: %lu - Total Traffic: ", count);
            format_kbyte_out(r, kbcount);
            ap_rputs("</dt>\n", r);


            
            ap_rprintf(r, "<dt>CPU Usage: u%g s%g cu%g cs%g", tu / tick, ts / tick, tcu / tick, tcs / tick);

            if (ts || tu || tcu || tcs)
                ap_rprintf(r, " - %.3g%% CPU load</dt>\n", (tu + ts + tcu + tcs) / tick / up_time * 100.);


            if (up_time > 0) {
                ap_rprintf(r, "<dt>%.3g requests/sec - ", (float) count / (float) up_time);

                format_byte_out(r, (unsigned long)(KBYTE * (float) kbcount / (float) up_time));
                ap_rputs("/second - ", r);
            }

            if (count > 0) {
                format_byte_out(r, (unsigned long)(KBYTE * (float) kbcount / (float) count));
                ap_rputs("/request", r);
            }

            ap_rputs("</dt>\n", r);
        } 
    } 

    if (!short_report)
        ap_rprintf(r, "<dt>%d requests currently being processed, " "%d idle workers</dt>\n", busy, ready);
    else ap_rprintf(r, "BusyWorkers: %d\nIdleWorkers: %d\n", busy, ready);

    if (!short_report)
        ap_rputs("</dl>", r);

    if (is_async) {
        int write_completion = 0, lingering_close = 0, keep_alive = 0, connections = 0;
        
        int busy_workers = 0, idle_workers = 0;
        if (!short_report)
            ap_rputs("\n\n<table rules=\"all\" cellpadding=\"1%\">\n" "<tr><th rowspan=\"2\">PID</th>" "<th colspan=\"2\">Connections</th>\n" "<th colspan=\"2\">Threads</th>" "<th colspan=\"4\">Async connections</th></tr>\n" "<tr><th>total</th><th>accepting</th>" "<th>busy</th><th>idle</th><th>writing</th>" "<th>keep-alive</th><th>closing</th></tr>\n", r);






        for (i = 0; i < server_limit; ++i) {
            ps_record = ap_get_scoreboard_process(i);
            if (ps_record->pid) {
                connections      += ps_record->connections;
                write_completion += ps_record->write_completion;
                keep_alive       += ps_record->keep_alive;
                lingering_close  += ps_record->lingering_close;
                busy_workers     += thread_busy_buffer[i];
                idle_workers     += thread_idle_buffer[i];
                if (!short_report)
                    ap_rprintf(r, "<tr><td>%" APR_PID_T_FMT "</td><td>%u</td>" "<td>%s</td><td>%u</td><td>%u</td>" "<td>%u</td><td>%u</td><td>%u</td>" "</tr>\n", ps_record->pid, ps_record->connections, ps_record->not_accepting ? "no" : "yes", thread_busy_buffer[i], thread_idle_buffer[i], ps_record->write_completion, ps_record->keep_alive, ps_record->lingering_close);








            }
        }
        if (!short_report) {
            ap_rprintf(r, "<tr><td>Sum</td><td>%d</td><td>&nbsp;</td><td>%d</td>" "<td>%d</td><td>%d</td><td>%d</td><td>%d</td>" "</tr>\n</table>\n", connections, busy_workers, idle_workers, write_completion, keep_alive, lingering_close);




        }
        else {
            ap_rprintf(r, "ConnsTotal: %d\n" "ConnsAsyncWriting: %d\n" "ConnsAsyncKeepAlive: %d\n" "ConnsAsyncClosing: %d\n", connections, write_completion, keep_alive, lingering_close);




        }
    }

    
    if (!short_report)
        ap_rputs("<pre>", r);
    else ap_rputs("Scoreboard: ", r);

    written = 0;
    for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
            int indx = (i * thread_limit) + j;
            if (stat_buffer[indx] != status_flags[SERVER_DISABLED]) {
                ap_rputc(stat_buffer[indx], r);
                if ((written % STATUS_MAXLINE == (STATUS_MAXLINE - 1))
                    && !short_report)
                    ap_rputs("\n", r);
                written++;
            }
        }
    }


    if (short_report)
        ap_rputs("\n", r);
    else {
        ap_rputs("</pre>\n" "<p>Scoreboard Key:<br />\n" "\"<b><code>_</code></b>\" Waiting for Connection, \n" "\"<b><code>S</code></b>\" Starting up, \n" "\"<b><code>R</code></b>\" Reading Request,<br />\n" "\"<b><code>W</code></b>\" Sending Reply, \n" "\"<b><code>K</code></b>\" Keepalive (read), \n" "\"<b><code>D</code></b>\" DNS Lookup,<br />\n" "\"<b><code>C</code></b>\" Closing connection, \n" "\"<b><code>L</code></b>\" Logging, \n" "\"<b><code>G</code></b>\" Gracefully finishing,<br /> \n" "\"<b><code>I</code></b>\" Idle cleanup of worker, \n" "\"<b><code>.</code></b>\" Open slot with no current process<br />\n" "<p />\n", r);












        if (!ap_extended_status) {
            int j;
            int k = 0;
            ap_rputs("PID Key: <br />\n" "<pre>\n", r);
            for (i = 0; i < server_limit; ++i) {
                for (j = 0; j < thread_limit; ++j) {
                    int indx = (i * thread_limit) + j;

                    if (stat_buffer[indx] != '.') {
                        ap_rprintf(r, "   %" APR_PID_T_FMT " in state: %c ", pid_buffer[i], stat_buffer[indx]);


                        if (++k >= 3) {
                            ap_rputs("\n", r);
                            k = 0;
                        } else ap_rputs(",", r);
                    }
                }
            }

            ap_rputs("\n" "</pre>\n", r);
        }
    }

    if (ap_extended_status && !short_report) {
        if (no_table_report)
            ap_rputs("<hr /><h2>Server Details</h2>\n\n", r);
        else ap_rputs("\n\n<table border=\"0\"><tr>" "<th>Srv</th><th>PID</th><th>Acc</th>" "<th>M</th>"  "<th>CPU\n</th>"  "<th>SS</th><th>Req</th>" "<th>Conn</th><th>Child</th><th>Slot</th>" "<th>Client</th><th>VHost</th>" "<th>Request</th></tr>\n\n", r);










        for (i = 0; i < server_limit; ++i) {
            for (j = 0; j < thread_limit; ++j) {
                ws_record = ap_get_scoreboard_worker_from_indexes(i, j);

                if (ws_record->access_count == 0 && (ws_record->status == SERVER_READY || ws_record->status == SERVER_DEAD)) {

                    continue;
                }

                ps_record = ap_get_scoreboard_process(i);

                if (ws_record->start_time == 0L)
                    req_time = 0L;
                else req_time = (long)
                        ((ws_record->stop_time - ws_record->start_time) / 1000);
                if (req_time < 0L)
                    req_time = 0L;

                lres = ws_record->access_count;
                my_lres = ws_record->my_access_count;
                conn_lres = ws_record->conn_count;
                bytes = ws_record->bytes_served;
                my_bytes = ws_record->my_bytes_served;
                conn_bytes = ws_record->conn_bytes;
                if (ws_record->pid) { 
                    worker_pid = ws_record->pid;
                    worker_generation = ws_record->generation;
                }
                else {
                    worker_pid = ps_record->pid;
                    worker_generation = ps_record->generation;
                }

                if (no_table_report) {
                    if (ws_record->status == SERVER_DEAD)
                        ap_rprintf(r, "<b>Server %d-%d</b> (-): %d|%lu|%lu [", i, (int)worker_generation, (int)conn_lres, my_lres, lres);


                    else ap_rprintf(r, "<b>Server %d-%d</b> (%" APR_PID_T_FMT "): %d|%lu|%lu [", i, (int) worker_generation, worker_pid, (int)conn_lres, my_lres, lres);






                    switch (ws_record->status) {
                    case SERVER_READY:
                        ap_rputs("Ready", r);
                        break;
                    case SERVER_STARTING:
                        ap_rputs("Starting", r);
                        break;
                    case SERVER_BUSY_READ:
                        ap_rputs("<b>Read</b>", r);
                        break;
                    case SERVER_BUSY_WRITE:
                        ap_rputs("<b>Write</b>", r);
                        break;
                    case SERVER_BUSY_KEEPALIVE:
                        ap_rputs("<b>Keepalive</b>", r);
                        break;
                    case SERVER_BUSY_LOG:
                        ap_rputs("<b>Logging</b>", r);
                        break;
                    case SERVER_BUSY_DNS:
                        ap_rputs("<b>DNS lookup</b>", r);
                        break;
                    case SERVER_CLOSING:
                        ap_rputs("<b>Closing</b>", r);
                        break;
                    case SERVER_DEAD:
                        ap_rputs("Dead", r);
                        break;
                    case SERVER_GRACEFUL:
                        ap_rputs("Graceful", r);
                        break;
                    case SERVER_IDLE_KILL:
                        ap_rputs("Dying", r);
                        break;
                    default:
                        ap_rputs("?STATE?", r);
                        break;
                    }

                    ap_rprintf(r, "] "  "u%g s%g cu%g cs%g"  "\n %ld %ld (",  ws_record->times.tms_utime / tick, ws_record->times.tms_stime / tick, ws_record->times.tms_cutime / tick, ws_record->times.tms_cstime / tick,  (long)apr_time_sec(nowtime - ws_record->last_used), (long) req_time);













                    format_byte_out(r, conn_bytes);
                    ap_rputs("|", r);
                    format_byte_out(r, my_bytes);
                    ap_rputs("|", r);
                    format_byte_out(r, bytes);
                    ap_rputs(")\n", r);
                    ap_rprintf(r, " <i>%s {%s}</i> <b>[%s]</b><br />\n\n", ap_escape_html(r->pool, ws_record->client), ap_escape_html(r->pool, ap_escape_logitem(r->pool, ws_record->request)), ap_escape_html(r->pool, ws_record->vhost));







                }
                else { 
                    if (ws_record->status == SERVER_DEAD)
                        ap_rprintf(r, "<tr><td><b>%d-%d</b></td><td>-</td><td>%d/%lu/%lu", i, (int)worker_generation, (int)conn_lres, my_lres, lres);


                    else ap_rprintf(r, "<tr><td><b>%d-%d</b></td><td>%" APR_PID_T_FMT "</td><td>%d/%lu/%lu", i, (int)worker_generation, worker_pid, (int)conn_lres, my_lres, lres);








                    switch (ws_record->status) {
                    case SERVER_READY:
                        ap_rputs("</td><td>_", r);
                        break;
                    case SERVER_STARTING:
                        ap_rputs("</td><td><b>S</b>", r);
                        break;
                    case SERVER_BUSY_READ:
                        ap_rputs("</td><td><b>R</b>", r);
                        break;
                    case SERVER_BUSY_WRITE:
                        ap_rputs("</td><td><b>W</b>", r);
                        break;
                    case SERVER_BUSY_KEEPALIVE:
                        ap_rputs("</td><td><b>K</b>", r);
                        break;
                    case SERVER_BUSY_LOG:
                        ap_rputs("</td><td><b>L</b>", r);
                        break;
                    case SERVER_BUSY_DNS:
                        ap_rputs("</td><td><b>D</b>", r);
                        break;
                    case SERVER_CLOSING:
                        ap_rputs("</td><td><b>C</b>", r);
                        break;
                    case SERVER_DEAD:
                        ap_rputs("</td><td>.", r);
                        break;
                    case SERVER_GRACEFUL:
                        ap_rputs("</td><td>G", r);
                        break;
                    case SERVER_IDLE_KILL:
                        ap_rputs("</td><td>I", r);
                        break;
                    default:
                        ap_rputs("</td><td>?", r);
                        break;
                    }

                    ap_rprintf(r, "\n</td>"  "<td>%.2f</td>"  "<td>%ld</td><td>%ld",  (ws_record->times.tms_utime + ws_record->times.tms_stime + ws_record->times.tms_cutime + ws_record->times.tms_cstime) / tick,  (long)apr_time_sec(nowtime - ws_record->last_used), (long)req_time);














                    ap_rprintf(r, "</td><td>%-1.1f</td><td>%-2.2f</td><td>%-2.2f\n", (float)conn_bytes / KBYTE, (float) my_bytes / MBYTE, (float)bytes / MBYTE);


                    ap_rprintf(r, "</td><td>%s</td><td nowrap>%s</td>" "<td nowrap>%s</td></tr>\n\n", ap_escape_html(r->pool, ws_record->client), ap_escape_html(r->pool, ws_record->vhost), ap_escape_html(r->pool, ap_escape_logitem(r->pool, ws_record->request)));







                } 
            } 
        } 

        if (!no_table_report) {
            ap_rputs("</table>\n  <hr /> <table>\n <tr><th>Srv</th><td>Child Server number - generation</td></tr>\n <tr><th>PID</th><td>OS process ID</td></tr>\n <tr><th>Acc</th><td>Number of accesses this connection / this child / this slot</td></tr>\n <tr><th>M</th><td>Mode of operation</td></tr>\n        "<tr><th>CPU</th><td>CPU usage, number of seconds</td></tr>\n"   "<tr><th>SS</th><td>Seconds since beginning of most recent request</td></tr>\n  <tr><th>Req</th><td>Milliseconds required to process most recent request</td></tr>\n <tr><th>Conn</th><td>Kilobytes transferred this connection</td></tr>\n <tr><th>Child</th><td>Megabytes transferred this child</td></tr>\n <tr><th>Slot</th><td>Total megabytes transferred this slot</td></tr>\n </table>\n", r)














        }
    } 
    else {

        if (!short_report) {
            ap_rputs("<hr />To obtain a full report with current status " "information you need to use the " "<code>ExtendedStatus On</code> directive.\n", r);

        }
    }

    {
        
        int flags = (short_report ? AP_STATUS_SHORT : 0) | (no_table_report ? AP_STATUS_NOTABLE : 0) | (ap_extended_status ? AP_STATUS_EXTENDED : 0);



        ap_run_status_hook(r, flags);
    }

    if (!short_report) {
        ap_rputs(ap_psignature("<hr />\n",r), r);
        ap_rputs("</body></html>\n", r);
    }

    return 0;
}

static int status_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    
    ap_extended_status = 1;
    return OK;
}

static int status_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    status_flags[SERVER_DEAD] = '.';  
    status_flags[SERVER_READY] = '_'; 
    status_flags[SERVER_STARTING] = 'S';
    status_flags[SERVER_BUSY_READ] = 'R';
    status_flags[SERVER_BUSY_WRITE] = 'W';
    status_flags[SERVER_BUSY_KEEPALIVE] = 'K';
    status_flags[SERVER_BUSY_LOG] = 'L';
    status_flags[SERVER_BUSY_DNS] = 'D';
    status_flags[SERVER_CLOSING] = 'C';
    status_flags[SERVER_GRACEFUL] = 'G';
    status_flags[SERVER_IDLE_KILL] = 'I';
    status_flags[SERVER_DISABLED] = ' ';
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threads_per_child);
    
    if (threads_per_child == 0)
        threads_per_child = 1;
    ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_servers);
    ap_mpm_query(AP_MPMQ_IS_ASYNC, &is_async);
    return OK;
}


static void status_child_init(apr_pool_t *p, server_rec *s)
{
    child_pid = getpid();
}


static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(status_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(status_pre_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(status_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_child_init(status_child_init, NULL, NULL, APR_HOOK_MIDDLE);

}

AP_DECLARE_MODULE(status) = {
    STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL, register_hooks };






