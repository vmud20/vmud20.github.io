

































double strtod();                


module AP_MODULE_DECLARE_DATA imagemap_module;

typedef struct {
    char *imap_menu;
    char *imap_default;
    char *imap_base;
} imap_conf_rec;

static void *create_imap_dir_config(apr_pool_t *p, char *dummy)
{
    imap_conf_rec *icr = (imap_conf_rec *) apr_palloc(p, sizeof(imap_conf_rec));

    icr->imap_menu = NULL;
    icr->imap_default = NULL;
    icr->imap_base = NULL;

    return icr;
}

static void *merge_imap_dir_configs(apr_pool_t *p, void *basev, void *addv)
{
    imap_conf_rec *new = (imap_conf_rec *) apr_pcalloc(p, sizeof(imap_conf_rec));
    imap_conf_rec *base = (imap_conf_rec *) basev;
    imap_conf_rec *add = (imap_conf_rec *) addv;

    new->imap_menu = add->imap_menu ? add->imap_menu : base->imap_menu;
    new->imap_default = add->imap_default ? add->imap_default : base->imap_default;
    new->imap_base = add->imap_base ? add->imap_base : base->imap_base;

    return new;
}


static const command_rec imap_cmds[] = {
    AP_INIT_TAKE1("ImapMenu", ap_set_string_slot, (void *)APR_OFFSETOF(imap_conf_rec, imap_menu), OR_INDEXES, "the type of menu generated: none, formatted, semiformatted, " "unformatted"), AP_INIT_TAKE1("ImapDefault", ap_set_string_slot, (void *)APR_OFFSETOF(imap_conf_rec, imap_default), OR_INDEXES, "the action taken if no match: error, nocontent, referer, " "menu, URL"), AP_INIT_TAKE1("ImapBase", ap_set_string_slot, (void *)APR_OFFSETOF(imap_conf_rec, imap_base), OR_INDEXES, "the base for all URL's: map, referer, URL (or start of)"), {NULL}










};

static int pointinrect(const double point[2], double coords[MAXVERTS][2])
{
    double max[2], min[2];
    if (coords[0][X] > coords[1][X]) {
        max[0] = coords[0][X];
        min[0] = coords[1][X];
    }
    else {
        max[0] = coords[1][X];
        min[0] = coords[0][X];
    }

    if (coords[0][Y] > coords[1][Y]) {
        max[1] = coords[0][Y];
        min[1] = coords[1][Y];
    }
    else {
        max[1] = coords[1][Y];
        min[1] = coords[0][Y];
    }

    return ((point[X] >= min[0] && point[X] <= max[0]) && (point[Y] >= min[1] && point[Y] <= max[1]));
}

static int pointincircle(const double point[2], double coords[MAXVERTS][2])
{
    double radius1, radius2;

    radius1 = ((coords[0][Y] - coords[1][Y]) * (coords[0][Y] - coords[1][Y]))
        + ((coords[0][X] - coords[1][X]) * (coords[0][X] - coords[1][X]));

    radius2 = ((coords[0][Y] - point[Y]) * (coords[0][Y] - point[Y]))
        + ((coords[0][X] - point[X]) * (coords[0][X] - point[X]));

    return (radius2 <= radius1);
}




static int pointinpoly(const double point[2], double pgon[MAXVERTS][2])
{
    int i, numverts, crossings = 0;
    double x = point[X], y = point[Y];

    for (numverts = 0; pgon[numverts][X] != -1 && numverts < MAXVERTS;
        numverts++) {
        
    }

    for (i = 0; i < numverts; i++) {
        double x1=pgon[i][X];
        double y1=pgon[i][Y];
        double x2=pgon[(i + 1) % numverts][X];
        double y2=pgon[(i + 1) % numverts][Y];
        double d=(y - y1) * (x2 - x1) - (x - x1) * (y2 - y1);

        if ((y1 >= y) != (y2 >= y)) {
            crossings +=y2 - y1 >= 0 ? d >= 0 : d <= 0;
        }
        if (!d && fmin(x1,x2) <= x && x <= fmax(x1,x2)
            && fmin(y1,y2) <= y && y <= fmax(y1,y2)) {
            return 1;
        }
    }
    return crossings & 0x01;
}


static int is_closer(const double point[2], double coords[MAXVERTS][2], double *closest)
{
    double dist_squared = ((point[X] - coords[0][X])
                           * (point[X] - coords[0][X]))
                          + ((point[Y] - coords[0][Y])
                             * (point[Y] - coords[0][Y]));

    if (point[X] < 0 || point[Y] < 0) {
        return (0);          
    }

    if (*closest < 0 || dist_squared < *closest) {
        *closest = dist_squared;
        return (1);          
    }

    return (0);              

}

static double get_x_coord(const char *args)
{
    char *endptr;               
    double x_coord = -1;        

    if (args == NULL) {
        return (-1);            
    }

    while (*args && !apr_isdigit(*args) && *args != ',') {
        args++;                 
    }

    x_coord = strtod(args, &endptr);

    if (endptr > args) {        
        return (x_coord);
    }

    return (-1);                
}

static double get_y_coord(const char *args)
{
    char *endptr;               
    const char *start_of_y = NULL;
    double y_coord = -1;        

    if (args == NULL) {
        return (-1);            
    }

    start_of_y = ap_strchr_c(args, ',');     

    if (start_of_y) {

        start_of_y++;           

        while (*start_of_y && !apr_isdigit(*start_of_y)) {
            start_of_y++;       
        }

        y_coord = strtod(start_of_y, &endptr);

        if (endptr > start_of_y) {
            return (y_coord);
        }
    }

    return (-1);                
}



static void read_quoted(char **string, char **quoted_part)
{
    char *strp = *string;

    
    *quoted_part = NULL;

    while (apr_isspace(*strp)) {
        strp++;                 
    }

    if (*strp == '"') {         
        strp++;                 
        *quoted_part = strp;    

        while (*strp && *strp != '"') {
            ++strp;             
        }

        *strp = '\0';           

        strp++;                 
        *string = strp;
    }
}


static char *imap_url(request_rec *r, const char *base, const char *value)
{

    int slen, clen;
    char *string_pos = NULL;
    const char *string_pos_const = NULL;
    char *directory = NULL;
    const char *referer = NULL;
    char *my_base;

    if (!strcasecmp(value, "map") || !strcasecmp(value, "menu")) {
        return ap_construct_url(r->pool, r->uri, r);
    }

    if (!strcasecmp(value, "nocontent") || !strcasecmp(value, "error")) {
        return apr_pstrdup(r->pool, value);      
    }

    if (!strcasecmp(value, "referer")) {
        referer = apr_table_get(r->headers_in, "Referer");
        if (referer && *referer) {
            return apr_pstrdup(r->pool, referer);
        }
        else {
            
            value = "";      
        }
    }

    string_pos_const = value;
    while (apr_isalpha(*string_pos_const)) {
        string_pos_const++;           
    }
    if (*string_pos_const == ':') {
        
        
        return apr_pstrdup(r->pool, value);
    }

    if (!base || !*base) {
        if (value && *value) {
            return apr_pstrdup(r->pool, value); 
        }
        
        return ap_construct_url(r->pool, "/", r);
    }

    
    if (ap_strchr_c(base, '/') == NULL && (!strncmp(value, "../", 3)
        || !strcmp(value, ".."))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "invalid base directive in map file: %s", r->uri);
        return NULL;
    }
    my_base = apr_pstrdup(r->pool, base);
    string_pos = my_base;
    while (*string_pos) {
        if (*string_pos == '/' && *(string_pos + 1) == '/') {
            string_pos += 2;    
            continue;
        }
        if (*string_pos == '/') {       
            if (value[0] == '/') {
                *string_pos = '\0';
            }                   
            else {
                directory = string_pos;         

                string_pos = strrchr(string_pos, '/');  
                string_pos++;   
                *string_pos = '\0';
            }                   
            break;
        }
        string_pos++;           
    }

    while (!strncmp(value, "../", 3) || !strcmp(value, "..")) {

        if (directory && (slen = strlen(directory))) {

            

            clen = slen - 1;

            while ((slen - clen) == 1) {

                if ((string_pos = strrchr(directory, '/'))) {
                    *string_pos = '\0';
                }
                clen = strlen(directory);
                if (clen == 0) {
                    break;
                }
            }

            value += 2;         
        }
        else if (directory) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "invalid directory name in map file: %s", r->uri);
            return NULL;
        }

        if (!strncmp(value, "/../", 4) || !strcmp(value, "/..")) {
            value++;            
        }

    }                           

    if (value && *value) {
        return apr_pstrcat(r->pool, my_base, value, NULL);
    }
    return my_base;
}

static int imap_reply(request_rec *r, char *redirect)
{
    if (!strcasecmp(redirect, "error")) {
        
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!strcasecmp(redirect, "nocontent")) {
        
        return HTTP_NO_CONTENT;
    }
    if (redirect && *redirect) {
        
        apr_table_setn(r->headers_out, "Location", redirect);
        return HTTP_MOVED_TEMPORARILY;
    }
    return HTTP_INTERNAL_SERVER_ERROR;
}

static void menu_header(request_rec *r, char *menu)
{
    ap_set_content_type(r, "text/html");

    ap_rvputs(r, DOCTYPE_HTML_3_2, "<html><head>\n<title>Menu for ", r->uri, "</title>\n</head><body>\n", NULL);

    if (!strcasecmp(menu, "formatted")) {
        ap_rvputs(r, "<h1>Menu for ", r->uri, "</h1>\n<hr />\n\n", NULL);
    }

    return;
}

static void menu_blank(request_rec *r, char *menu)
{
    if (!strcasecmp(menu, "formatted")) {
        ap_rputs("\n", r);
    }
    if (!strcasecmp(menu, "semiformatted")) {
        ap_rputs("<br />\n", r);
    }
    if (!strcasecmp(menu, "unformatted")) {
        ap_rputs("\n", r);
    }
    return;
}

static void menu_comment(request_rec *r, char *menu, char *comment)
{
    if (!strcasecmp(menu, "formatted")) {
        ap_rputs("\n", r);         
    }
    if (!strcasecmp(menu, "semiformatted") && *comment) {
        ap_rvputs(r, comment, "\n", NULL);
    }
    if (!strcasecmp(menu, "unformatted") && *comment) {
        ap_rvputs(r, comment, "\n", NULL);
    }
    return;                     
}

static void menu_default(request_rec *r, char *menu, char *href, char *text)
{
    if (!strcasecmp(href, "error") || !strcasecmp(href, "nocontent")) {
        return;                 
    }
    if (!strcasecmp(menu, "formatted")) {
        ap_rvputs(r, "<pre>(Default) <a href=\"", href, "\">", text, "</a></pre>\n", NULL);
    }
    if (!strcasecmp(menu, "semiformatted")) {
        ap_rvputs(r, "<pre>(Default) <a href=\"", href, "\">", text, "</a></pre>\n", NULL);
    }
    if (!strcasecmp(menu, "unformatted")) {
        ap_rvputs(r, "<a href=\"", href, "\">", text, "</a>", NULL);
    }
    return;
}

static void menu_directive(request_rec *r, char *menu, char *href, char *text)
{
    if (!strcasecmp(href, "error") || !strcasecmp(href, "nocontent")) {
        return;                 
    }
    if (!strcasecmp(menu, "formatted")) {
        ap_rvputs(r, "<pre>          <a href=\"", href, "\">", text, "</a></pre>\n", NULL);
    }
    if (!strcasecmp(menu, "semiformatted")) {
        ap_rvputs(r, "<pre>          <a href=\"", href, "\">", text, "</a></pre>\n", NULL);
    }
    if (!strcasecmp(menu, "unformatted")) {
        ap_rvputs(r, "<a href=\"", href, "\">", text, "</a>", NULL);
    }
    return;
}

static void menu_footer(request_rec *r)
{
    ap_rputs("\n\n</body>\n</html>\n", r);         
}

static int imap_handler_internal(request_rec *r)
{
    char input[MAX_STRING_LEN];
    char *directive;
    char *value;
    char *href_text;
    char *base;
    char *redirect;
    char *mapdflt;
    char *closest = NULL;
    double closest_yet = -1;
    apr_status_t status;

    double testpoint[2];
    double pointarray[MAXVERTS + 1][2];
    int vertex;

    char *string_pos;
    int showmenu = 0;

    imap_conf_rec *icr;

    char *imap_menu;
    char *imap_default;
    char *imap_base;

    ap_configfile_t *imap;

    icr = ap_get_module_config(r->per_dir_config, &imagemap_module);

    imap_menu = icr->imap_menu ? icr->imap_menu : IMAP_MENU_DEFAULT;
    imap_default = icr->imap_default ?  icr->imap_default : IMAP_DEFAULT_DEFAULT;
    imap_base = icr->imap_base ? icr->imap_base : IMAP_BASE_DEFAULT;

    status = ap_pcfg_openfile(&imap, r->pool, r->filename);

    if (status != APR_SUCCESS) {
        return HTTP_NOT_FOUND;
    }

    base = imap_url(r, NULL, imap_base);         
    if (!base) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    mapdflt = imap_url(r, NULL, imap_default);   
    if (!mapdflt) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    testpoint[X] = get_x_coord(r->args);
    testpoint[Y] = get_y_coord(r->args);

    if ((testpoint[X] == -1 || testpoint[Y] == -1) || (testpoint[X] == 0 && testpoint[Y] == 0)) {
        
        
        testpoint[X] = -1;
        testpoint[Y] = -1;
        if (strncasecmp(imap_menu, "none", 2)) {
            showmenu = 1;       
        }
    }

    if (showmenu) {             
        menu_header(r, imap_menu);
    }

    while (!ap_cfg_getline(input, sizeof(input), imap)) {
        if (!input[0]) {
            if (showmenu) {
                menu_blank(r, imap_menu);
            }
            continue;
        }

        if (input[0] == '#') {
            if (showmenu) {
                menu_comment(r, imap_menu, input + 1);
            }
            continue;
        }                       

        
        string_pos = input;
        if (!*string_pos) {   
            goto need_2_fields;
        }

        directive = string_pos;
        while (*string_pos && !apr_isspace(*string_pos)) {   
            ++string_pos;
        }
        if (!*string_pos) {   
            goto need_2_fields;
        }
        *string_pos++ = '\0';

        if (!*string_pos) {   
            goto need_2_fields;
        }
        while(*string_pos && apr_isspace(*string_pos)) { 
            ++string_pos;
        }

        value = string_pos;
        while (*string_pos && !apr_isspace(*string_pos)) {   
            ++string_pos;
        }
        if (apr_isspace(*string_pos)) {
            *string_pos++ = '\0';
        }
        else {
            
            *string_pos = '\0';
        }

        if (!strncasecmp(directive, "base", 4)) {       
            base = imap_url(r, NULL, value);
            if (!base) {
                goto menu_bail;
            }
            continue;           
        }

        read_quoted(&string_pos, &href_text);

        if (!strcasecmp(directive, "default")) {        
            mapdflt = imap_url(r, NULL, value);
            if (!mapdflt) {
                goto menu_bail;
            }
            if (showmenu) {     
                redirect = imap_url(r, base, mapdflt);
                if (!redirect) {
                    goto menu_bail;
                }
                menu_default(r, imap_menu, redirect, href_text ? href_text : mapdflt);
            }
            continue;
        }

        vertex = 0;
        while (vertex < MAXVERTS && sscanf(string_pos, "%lf%*[, ]%lf", &pointarray[vertex][X], &pointarray[vertex][Y]) == 2) {

            
            while (apr_isspace(*string_pos)) {      
                string_pos++;
            }
            while (apr_isdigit(*string_pos)) {      
                string_pos++;
            }
            string_pos++;       
            while (apr_isspace(*string_pos)) {      
                string_pos++;
            }
            while (apr_isdigit(*string_pos)) {      
                string_pos++;
            }
            vertex++;
        }                       

        pointarray[vertex][X] = -1;     

        if (showmenu) {
            if (!href_text) {
                read_quoted(&string_pos, &href_text);     
            }
            redirect = imap_url(r, base, value);
            if (!redirect) {
                goto menu_bail;
            }
            menu_directive(r, imap_menu, redirect, href_text ? href_text : value);
            continue;
        }
        

        if (testpoint[X] == -1 || pointarray[0][X] == -1) {
            continue;           
        }

        if (!strcasecmp(directive, "poly")) {   

            if (pointinpoly(testpoint, pointarray)) {
                ap_cfg_closefile(imap);
                redirect = imap_url(r, base, value);
                if (!redirect) {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                return (imap_reply(r, redirect));
            }
            continue;
        }

        if (!strcasecmp(directive, "circle")) {         

            if (pointincircle(testpoint, pointarray)) {
                ap_cfg_closefile(imap);
                redirect = imap_url(r, base, value);
                if (!redirect) {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                return (imap_reply(r, redirect));
            }
            continue;
        }

        if (!strcasecmp(directive, "rect")) {   

            if (pointinrect(testpoint, pointarray)) {
                ap_cfg_closefile(imap);
                redirect = imap_url(r, base, value);
                if (!redirect) {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                return (imap_reply(r, redirect));
            }
            continue;
        }

        if (!strcasecmp(directive, "point")) {  

            if (is_closer(testpoint, pointarray, &closest_yet)) {
                closest = apr_pstrdup(r->pool, value);
            }

            continue;
        }                       

    }                           

    ap_cfg_closefile(imap);        

    if (showmenu) {
        menu_footer(r);         
        return OK;
    }

    if (closest) {             
        redirect = imap_url(r, base, closest);
        if (!redirect) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        return (imap_reply(r, redirect));
    }

    if (mapdflt) {             
        redirect = imap_url(r, base, mapdflt);
        if (!redirect) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        return (imap_reply(r, redirect));
    }

    return HTTP_INTERNAL_SERVER_ERROR;        

need_2_fields:
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "map file %s, line %d syntax error: requires at " "least two fields", r->uri, imap->line_number);

    
menu_bail:
    ap_cfg_closefile(imap);
    if (showmenu) {
        
        ap_rputs("\n\n[an internal server error occured]\n", r);
        menu_footer(r);
        return OK;
    }
    return HTTP_INTERNAL_SERVER_ERROR;
}

static int imap_handler(request_rec *r)
{
    
    if (r->method_number != M_GET || (strcmp(r->handler,IMAP_MAGIC_TYPE)
                                      && strcmp(r->handler, "imap-file"))) {
        return DECLINED;
    }
    else {
        return imap_handler_internal(r);
    }
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(imap_handler,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA imagemap_module = {
    STANDARD20_MODULE_STUFF, create_imap_dir_config, merge_imap_dir_configs, NULL, NULL, imap_cmds, register_hooks };






