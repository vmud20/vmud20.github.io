

















































































static void sigsegv(int sig);
static void print_trace(int use_syslog);

 
















typedef unsigned char bool;

typedef enum { FALSE = 0, TRUE  = 1 } bool;



typedef enum {
    FAIL, OK, OK_ATTACHMENTS_NOT_SAVED, VIRUS, MAXREC, MAXFILES } mbox_status;


































typedef struct mbox_ctx {
    const char *dir;
    const table_t *rfc821Table;
    const table_t *subtypeTable;
    cli_ctx *ctx;
    unsigned int files; 

    json_object *wrkobj;

} mbox_ctx;












static int cli_parse_mbox(const char *dir, cli_ctx *ctx);
static message *parseEmailFile(fmap_t *map, size_t *at, const table_t *rfc821Table, const char *firstLine, const char *dir);
static message *parseEmailHeaders(message *m, const table_t *rfc821Table);
static int parseEmailHeader(message *m, const char *line, const table_t *rfc821Table);
static cl_error_t parseMHTMLComment(const char *comment, cli_ctx *ctx, void *wrkjobj, void *cbdata);
static mbox_status parseRootMHTML(mbox_ctx *mctx, message *m, text *t);
static mbox_status parseEmailBody(message *messageIn, text *textIn, mbox_ctx *mctx, unsigned int recursion_level);
static int boundaryStart(const char *line, const char *boundary);
static int boundaryEnd(const char *line, const char *boundary);
static int initialiseTables(table_t **rfc821Table, table_t **subtypeTable);
static int getTextPart(message *const messages[], size_t size);
static size_t strip(char *buf, int len);
static int parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg);
static int saveTextPart(mbox_ctx *mctx, message *m, int destroy_text);
static char *rfc2047(const char *in);
static char *rfc822comments(const char *in, char *out);
static int rfc1341(message *m, const char *dir);
static bool usefulHeader(int commandNumber, const char *cmd);
static char *getline_from_mbox(char *buffer, size_t len, fmap_t *map, size_t *at);
static bool isBounceStart(mbox_ctx *mctx, const char *line);
static bool exportBinhexMessage(mbox_ctx *mctx, message *m);
static int exportBounceMessage(mbox_ctx *ctx, text *start);
static const char *getMimeTypeStr(mime_type mimetype);
static const char *getEncTypeStr(encoding_type enctype);
static message *do_multipart(message *mainMessage, message **messages, int i, mbox_status *rc, mbox_ctx *mctx, message *messageIn, text **tptr, unsigned int recursion_level);
static int count_quotes(const char *buf);
static bool next_is_folded_header(const text *t);
static bool newline_in_header(const char *line);

static blob *getHrefs(message *m, tag_arguments_t *hrefs);
static void hrefs_done(blob *b, tag_arguments_t *hrefs);
static void checkURLs(message *m, mbox_ctx *mctx, mbox_status *rc, int is_html);



























static const struct tableinit {
    const char *key;
    int value;
} rfc821headers[] = {
    
    {"Content-Type", CONTENT_TYPE}, {"Content-Transfer-Encoding", CONTENT_TRANSFER_ENCODING}, {"Content-Disposition", CONTENT_DISPOSITION}, {NULL, 0}}, mimeSubtypes[] = {



                    
                    {"plain", PLAIN}, {"enriched", ENRICHED}, {"html", HTML}, {"richtext", RICHTEXT},  {"mixed", MIXED}, {"alternative", ALTERNATIVE}, {"digest", DIGEST}, {"signed", SIGNED}, {"parallel", PARALLEL}, {"related", RELATED}, {"report", REPORT}, {"appledouble", APPLEDOUBLE}, {"fax-message", FAX}, {"encrypted", ENCRYPTED}, {"x-bfile", X_BFILE}, {"knowbot", KNOWBOT}, {"knowbot-metadata", KNOWBOT}, {"knowbot-code", KNOWBOT}, {"knowbot-state", KNOWBOT}, {NULL, 0}}, mimeTypeStr[] = {{"NOMIME", NOMIME}, {"APPLICATION", APPLICATION}, {"AUDIO", AUDIO}, {"IMAGE", IMAGE}, {"MESSAGE", MESSAGE}, {"MULTIPART", MULTIPART}, {"TEXT", TEXT}, {"VIDEO", VIDEO}, {"MEXTENSION", MEXTENSION}, {NULL, 0}}, encTypeStr[] = {{"NOENCODING", NOENCODING}, {"QUOTEDPRINTABLE", QUOTEDPRINTABLE}, {"BASE64", BASE64}, {"EIGHTBIT", EIGHTBIT}, {"BINARY", BINARY}, {"UUENCODE", UUENCODE}, {"YENCODE", YENCODE}, {"EEXTENSION", EEXTENSION}, {"BINHEX", BINHEX}, {NULL, 0}};






















static pthread_mutex_t tables_mutex = PTHREAD_MUTEX_INITIALIZER;

static table_t *rfc821  = NULL;
static table_t *subtype = NULL;

int cli_mbox(const char *dir, cli_ctx *ctx)
{
    if (dir == NULL) {
        cli_dbgmsg("cli_mbox called with NULL dir\n");
        return CL_ENULLARG;
    }
    return cli_parse_mbox(dir, ctx);
}


static int cli_parse_mbox(const char *dir, cli_ctx *ctx)
{
    int retcode;
    message *body;
    char buffer[RFC2821LENGTH + 1];
    mbox_ctx mctx;
    size_t at   = 0;
    fmap_t *map = *ctx->fmap;

    cli_dbgmsg("in mbox()\n");

    if (!fmap_gets(map, buffer, &at, sizeof(buffer) - 1)) {
        
        return CL_CLEAN;
    }

    pthread_mutex_lock(&tables_mutex);

    if (rfc821 == NULL) {
        assert(subtype == NULL);

        if (initialiseTables(&rfc821, &subtype) < 0) {
            rfc821  = NULL;
            subtype = NULL;

            pthread_mutex_unlock(&tables_mutex);

            return CL_EMEM;
        }
    }

    pthread_mutex_unlock(&tables_mutex);


    retcode = CL_SUCCESS;
    body    = NULL;

    mctx.dir          = dir;
    mctx.rfc821Table  = rfc821;
    mctx.subtypeTable = subtype;
    mctx.ctx          = ctx;
    mctx.files        = 0;

    mctx.wrkobj = ctx->wrkproperty;


    
    
    if (strncmp(buffer, "From ", 5) == 0) {
        
        bool lastLineWasEmpty;
        int messagenumber;
        message *m = messageCreate();

        if (m == NULL)
            return CL_EMEM;

        lastLineWasEmpty = FALSE;
        messagenumber    = 1;
        messageSetCTX(m, ctx);

        do {
            cli_chomp(buffer);
            
            if (lastLineWasEmpty && (strncmp(buffer, "From ", 5) == 0)) {
                cli_dbgmsg("Deal with message number %d\n", messagenumber++);
                
                body = parseEmailHeaders(m, rfc821);
                if (body == NULL) {
                    messageReset(m);
                    continue;
                }
                messageSetCTX(body, ctx);
                messageDestroy(m);
                if (messageGetBody(body)) {
                    mbox_status rc = parseEmailBody(body, NULL, &mctx, 0);
                    if (rc == FAIL) {
                        messageReset(body);
                        m = body;
                        continue;
                    } else if (rc == VIRUS) {
                        cli_dbgmsg("Message number %d is infected\n", messagenumber - 1);
                        retcode = CL_VIRUS;
                        m       = NULL;
                        break;
                    }
                }
                
                m = body;
                messageReset(body);
                messageSetCTX(body, ctx);

                cli_dbgmsg("Finished processing message\n");
            } else lastLineWasEmpty = (bool)(buffer[0] == '\0');

            if (isuuencodebegin(buffer)) {
                
                if (uudecodeFile(m, buffer, dir, map, &at) < 0)
                    if (messageAddStr(m, buffer) < 0)
                        break;
            } else  if (messageAddStr(m, buffer) < 0)

                break;
        } while (fmap_gets(map, buffer, &at, sizeof(buffer) - 1));

        if (retcode == CL_SUCCESS) {
            cli_dbgmsg("Extract attachments from email %d\n", messagenumber);
            body = parseEmailHeaders(m, rfc821);
        }
        if (m)
            messageDestroy(m);
    } else {
        
        if (strncmp(buffer, "P I ", 4) == 0)
            
            while (fmap_gets(map, buffer, &at, sizeof(buffer) - 1) && (strchr("\r\n", buffer[0]) == NULL))
                ;
        
        
        while (strchr("\r\n", buffer[0]) && (getline_from_mbox(buffer, sizeof(buffer) - 1, map, &at) != NULL))
            ;

        buffer[sizeof(buffer) - 1] = '\0';

        body = parseEmailFile(map, &at, rfc821, buffer, dir);
    }

    if (body) {
        
        if ((retcode == CL_SUCCESS) && messageGetBody(body)) {
            messageSetCTX(body, ctx);
            switch (parseEmailBody(body, NULL, &mctx, 0)) {
                case OK:
                case OK_ATTACHMENTS_NOT_SAVED:
                    break;
                case FAIL:
                    
                    retcode = CL_EFORMAT;
                    break;
                case MAXREC:
                    retcode = CL_EMAXREC;
                    break;
                case MAXFILES:
                    retcode = CL_EMAXFILES;
                    break;
                case VIRUS:
                    retcode = CL_VIRUS;
                    break;
            }
        }

        if (body->isTruncated && retcode == CL_SUCCESS)
            retcode = CL_EMEM;
        
        messageDestroy(body);
    }

    if ((retcode == CL_CLEAN) && ctx->found_possibly_unwanted && (*ctx->virname == NULL || SCAN_ALLMATCHES)) {
        retcode                      = cli_append_virus(ctx, "Heuristics.Phishing.Email");
        ctx->found_possibly_unwanted = 0;
    }

    cli_dbgmsg("cli_mbox returning %d\n", retcode);

    return retcode;
}


static message * parseEmailFile(fmap_t *map, size_t *at, const table_t *rfc821, const char *firstLine, const char *dir)
{
    bool inHeader     = TRUE;
    bool bodyIsEmpty  = TRUE;
    bool lastWasBlank = FALSE, lastBodyLineWasBlank = FALSE;
    message *ret;
    bool anyHeadersFound = FALSE;
    int commandNumber    = -1;
    char *fullline = NULL, *boundary = NULL;
    size_t fulllinelength = 0;
    char buffer[RFC2821LENGTH + 1];

    cli_dbgmsg("parseEmailFile\n");

    ret = messageCreate();
    if (ret == NULL)
        return NULL;

    strncpy(buffer, firstLine, sizeof(buffer) - 1);
    do {
        const char *line;

        (void)cli_chomp(buffer);

        if (buffer[0] == '\0')
            line = NULL;
        else line = buffer;

        
        if (lastWasBlank) {
            lastWasBlank = FALSE;
            if (boundaryStart(buffer, boundary)) {
                cli_dbgmsg("Found a header line with space that should be blank\n");
                inHeader = FALSE;
            }
        }
        if (inHeader) {
            cli_dbgmsg("parseEmailFile: check '%s' fullline %p\n", buffer, fullline);
            
            if (line && isspace(line[0] & 0xFF)) {
                char copy[sizeof(buffer)];

                strcpy(copy, buffer);
                strstrip(copy);
                if (copy[0] == '\0') {
                    
                    if (fullline) {
                        if (parseEmailHeader(ret, fullline, rfc821) < 0)
                            continue;

                        free(fullline);
                        fullline = NULL;
                    }
                    if (boundary || ((boundary = (char *)messageFindArgument(ret, "boundary")) != NULL)) {
                        lastWasBlank = TRUE;
                        continue;
                    }
                }
            }
            if ((line == NULL) && (fullline == NULL)) { 
                
                if (!anyHeadersFound)
                    
                    continue;

                cli_dbgmsg("End of header information\n");
                inHeader    = FALSE;
                bodyIsEmpty = TRUE;
            } else {
                char *ptr;
                const char *lookahead;

                if (fullline == NULL) {
                    char cmd[RFC2821LENGTH + 1], out[RFC2821LENGTH + 1];

                    
                    if (isblank(line[0]))
                        continue;

                    
                    if ((strchr(line, ':') == NULL) || (cli_strtokbuf(line, 0, ":", cmd) == NULL)) {
                        if (strncmp(line, "From ", 5) == 0)
                            anyHeadersFound = TRUE;
                        continue;
                    }

                    ptr           = rfc822comments(cmd, out);
                    commandNumber = tableFind(rfc821, ptr ? ptr : cmd);

                    switch (commandNumber) {
                        case CONTENT_TRANSFER_ENCODING:
                        case CONTENT_DISPOSITION:
                        case CONTENT_TYPE:
                            anyHeadersFound = TRUE;
                            break;
                        default:
                            if (!anyHeadersFound)
                                anyHeadersFound = usefulHeader(commandNumber, cmd);
                            continue;
                    }
                    fullline       = cli_strdup(line);
                    fulllinelength = strlen(line) + 1;
                    if (!fullline) {
                        if (ret)
                            ret->isTruncated = TRUE;
                        break;
                    }
                } else if (line != NULL) {
                    fulllinelength += strlen(line) + 1;
                    ptr = cli_realloc(fullline, fulllinelength);
                    if (ptr == NULL)
                        continue;
                    fullline = ptr;
                    cli_strlcat(fullline, line, fulllinelength);
                }

                assert(fullline != NULL);

                if ((lookahead = fmap_need_off_once(map, *at, 1))) {
                    
                    if (isblank(*lookahead))
                        continue;
                }

                
                if (fullline[strlen(fullline) - 1] == ';')
                    
                    continue;

                if (line && (count_quotes(fullline) & 1))
                    continue;

                ptr = rfc822comments(fullline, NULL);
                if (ptr) {
                    free(fullline);
                    fullline = ptr;
                }

                if (parseEmailHeader(ret, fullline, rfc821) < 0)
                    continue;

                free(fullline);
                fullline = NULL;
            }
        } else if (line && isuuencodebegin(line)) {
            
            bodyIsEmpty = FALSE;
            if (uudecodeFile(ret, line, dir, map, at) < 0)
                if (messageAddStr(ret, line) < 0)
                    break;
        } else {
            if (line == NULL) {
                
                if (lastBodyLineWasBlank && (messageGetMimeType(ret) != TEXT)) {
                    cli_dbgmsg("Ignoring consecutive blank lines in the body\n");
                    continue;
                }
                lastBodyLineWasBlank = TRUE;
            } else {
                if (bodyIsEmpty) {
                    
                    if (newline_in_header(line))
                        continue;
                    bodyIsEmpty = FALSE;
                }
                lastBodyLineWasBlank = FALSE;
            }

            if (messageAddStr(ret, line) < 0)
                break;
        }
    } while (getline_from_mbox(buffer, sizeof(buffer) - 1, map, at) != NULL);

    if (boundary)
        free(boundary);

    if (fullline) {
        if (*fullline) switch (commandNumber) {
                case CONTENT_TRANSFER_ENCODING:
                case CONTENT_DISPOSITION:
                case CONTENT_TYPE:
                    cli_dbgmsg("parseEmailFile: Fullline unparsed '%s'\n", fullline);
            }
        free(fullline);
    }

    if (!anyHeadersFound) {
        
        messageDestroy(ret);
        cli_dbgmsg("parseEmailFile: no headers found, assuming it isn't an email\n");
        return NULL;
    }

    cli_dbgmsg("parseEmailFile: return\n");

    return ret;
}


static message * parseEmailHeaders(message *m, const table_t *rfc821)
{
    bool inHeader    = TRUE;
    bool bodyIsEmpty = TRUE;
    text *t;
    message *ret;
    bool anyHeadersFound  = FALSE;
    int commandNumber     = -1;
    char *fullline        = NULL;
    size_t fulllinelength = 0;

    cli_dbgmsg("parseEmailHeaders\n");

    if (m == NULL)
        return NULL;

    ret = messageCreate();

    for (t = messageGetBody(m); t; t = t->t_next) {
        const char *line;

        if (t->t_line)
            line = lineGetData(t->t_line);
        else line = NULL;

        if (inHeader) {
            cli_dbgmsg("parseEmailHeaders: check '%s'\n", line ? line : "");
            if (line == NULL) {
                
                cli_dbgmsg("End of header information\n");
                if (!anyHeadersFound) {
                    cli_dbgmsg("Nothing interesting in the header\n");
                    break;
                }
                inHeader    = FALSE;
                bodyIsEmpty = TRUE;
            } else {
                char *ptr;

                if (fullline == NULL) {
                    char cmd[RFC2821LENGTH + 1];

                    
                    if (isblank(line[0]))
                        continue;

                    
                    if ((strchr(line, ':') == NULL) || (cli_strtokbuf(line, 0, ":", cmd) == NULL)) {
                        if (strncmp(line, "From ", 5) == 0)
                            anyHeadersFound = TRUE;
                        continue;
                    }

                    ptr           = rfc822comments(cmd, NULL);
                    commandNumber = tableFind(rfc821, ptr ? ptr : cmd);
                    if (ptr)
                        free(ptr);

                    switch (commandNumber) {
                        case CONTENT_TRANSFER_ENCODING:
                        case CONTENT_DISPOSITION:
                        case CONTENT_TYPE:
                            anyHeadersFound = TRUE;
                            break;
                        default:
                            if (!anyHeadersFound)
                                anyHeadersFound = usefulHeader(commandNumber, cmd);
                            continue;
                    }
                    fullline       = cli_strdup(line);
                    fulllinelength = strlen(line) + 1;
                } else if (line) {
                    fulllinelength += strlen(line) + 1;
                    ptr = cli_realloc(fullline, fulllinelength);
                    if (ptr == NULL)
                        continue;
                    fullline = ptr;
                    cli_strlcat(fullline, line, fulllinelength);
                }
                assert(fullline != NULL);

                if (next_is_folded_header(t))
                    
                    continue;

                lineUnlink(t->t_line);
                t->t_line = NULL;

                if (count_quotes(fullline) & 1)
                    continue;

                ptr = rfc822comments(fullline, NULL);
                if (ptr) {
                    free(fullline);
                    fullline = ptr;
                }

                if (parseEmailHeader(ret, fullline, rfc821) < 0)
                    continue;

                free(fullline);
                fullline = NULL;
            }
        } else {
            if (bodyIsEmpty) {
                if (line == NULL)
                    
                    continue;
                
                if (newline_in_header(line))
                    continue;
                bodyIsEmpty = FALSE;
            }
            
            cli_dbgmsg("parseEmailHeaders: finished with headers, moving body\n");
            messageMoveText(ret, t, m);
            break;
        }
    }

    if (fullline) {
        if (*fullline) switch (commandNumber) {
                case CONTENT_TRANSFER_ENCODING:
                case CONTENT_DISPOSITION:
                case CONTENT_TYPE:
                    cli_dbgmsg("parseEmailHeaders: Fullline unparsed '%s'\n", fullline);
            }
        free(fullline);
    }

    if (!anyHeadersFound) {
        
        messageDestroy(ret);
        cli_dbgmsg("parseEmailHeaders: no headers found, assuming it isn't an email\n");
        return NULL;
    }

    cli_dbgmsg("parseEmailHeaders: return\n");

    return ret;
}


static int parseEmailHeader(message *m, const char *line, const table_t *rfc821)
{
    int ret;

    char *strptr;

    const char *separator;
    char *cmd, *copy, tokenseparator[2];

    cli_dbgmsg("parseEmailHeader '%s'\n", line);

    
    for (separator = ":= "; *separator; separator++)
        if (strchr(line, *separator) != NULL)
            break;

    if (*separator == '\0')
        return -1;

    copy = rfc2047(line);
    if (copy == NULL)
        
        copy = cli_strdup(line);

    tokenseparator[0] = *separator;
    tokenseparator[1] = '\0';

    ret = -1;


    cmd = strtok_r(copy, tokenseparator, &strptr);

    cmd = strtok(copy, tokenseparator);


    if (cmd && (strstrip(cmd) > 0)) {

        char *arg = strtok_r(NULL, "", &strptr);

        char *arg = strtok(NULL, "");


        if (arg)
            
            ret = parseMimeHeader(m, cmd, rfc821, arg);
    }
    free(copy);
    return ret;
}


static const struct key_entry mhtml_keys[] = {
    
    {"html", "RootHTML", MSXML_JSON_ROOT | MSXML_JSON_ATTRIB},  {"head", "Head", MSXML_JSON_WRKPTR | MSXML_COMMENT_CB}, {"meta", "Meta", MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_ATTRIB}, {"link", "Link", MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_ATTRIB}, {"script", "Script", MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_VALUE}};




static size_t num_mhtml_keys = sizeof(mhtml_keys) / sizeof(struct key_entry);

static const struct key_entry mhtml_comment_keys[] = {
    
    {"o:documentproperties", "DocumentProperties", MSXML_JSON_ROOT | MSXML_JSON_ATTRIB}, {"o:author", "Author", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:lastauthor", "LastAuthor", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:revision", "Revision", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:totaltime", "TotalTime", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:created", "Created", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:lastsaved", "LastSaved", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:pages", "Pages", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:words", "Words", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:characters", "Characters", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:company", "Company", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:lines", "Lines", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:paragraphs", "Paragraphs", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:characterswithspaces", "CharactersWithSpaces", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE}, {"o:version", "Version", MSXML_JSON_WRKPTR | MSXML_JSON_VALUE},  {"o:officedocumentsettings", "DocumentSettings", MSXML_IGNORE_ELEM}, {"w:worddocument", "WordDocument", MSXML_IGNORE_ELEM}, {"w:latentstyles", "LatentStyles", MSXML_IGNORE_ELEM}};

















static size_t num_mhtml_comment_keys = sizeof(mhtml_comment_keys) / sizeof(struct key_entry);



static cl_error_t parseMHTMLComment(const char *comment, cli_ctx *ctx, void *wrkjobj, void *cbdata)
{
    cl_error_t ret = CL_SUCCESS;


    const char *xmlsrt, *xmlend;
    xmlTextReaderPtr reader;

    UNUSEDPARAM(cbdata);
    UNUSEDPARAM(wrkjobj);

    xmlend = comment;
    while ((xmlsrt = strstr(xmlend, "<xml>"))) {
        xmlend = strstr(xmlsrt, "</xml>");
        if (xmlend == NULL) {
            cli_dbgmsg("parseMHTMLComment: unbounded xml tag\n");
            break;
        }

        reader = xmlReaderForMemory(xmlsrt, xmlend - xmlsrt + 6, "comment.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
        if (!reader) {
            cli_dbgmsg("parseMHTMLComment: cannot initialize xmlReader\n");


            if (ctx->wrkproperty != NULL)
                ret = cli_json_parse_error(ctx->wrkproperty, "MHTML_ERROR_XML_READER_MEM");

            return ret; 
        }

        
        
        
        ret = cli_msxml_parse_document(ctx, reader, mhtml_comment_keys, num_mhtml_comment_keys, MSXML_FLAG_JSON, NULL);

        xmlTextReaderClose(reader);
        xmlFreeTextReader(reader);
        if (ret != CL_SUCCESS)
            return ret;
    }

    UNUSEDPARAM(comment);
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(wrkjobj);
    UNUSEDPARAM(cbdata);

    cli_dbgmsg("in parseMHTMLComment\n");
    cli_dbgmsg("parseMHTMLComment: parsing html xml-comments requires libxml2!\n");

    return ret;
}


static mbox_status parseRootMHTML(mbox_ctx *mctx, message *m, text *t)
{
    cli_ctx *ctx = mctx->ctx;


    struct msxml_ctx mxctx;
    blob *input = NULL;
    htmlDocPtr htmlDoc;
    xmlTextReaderPtr reader;
    int ret        = CL_SUCCESS;
    mbox_status rc = OK;

    json_object *rhtml;


    cli_dbgmsg("in parseRootMHTML\n");

    if (ctx == NULL)
        return OK;

    if (m == NULL && t == NULL)
        return OK;

    if (m != NULL)
        input = messageToBlob(m, 0);
    else  input = textToBlob(t, NULL, 0);

    if (input == NULL)
        return OK;

    htmlDoc = htmlReadMemory((char *)input->data, input->len, "mhtml.html", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (htmlDoc == NULL) {
        cli_dbgmsg("parseRootMHTML: cannot initialize read html document\n");

        if (ctx->wrkproperty != NULL)
            ret = cli_json_parse_error(ctx->wrkproperty, "MHTML_ERROR_HTML_READ");
        if (ret != CL_SUCCESS)
            rc = FAIL;

        blobDestroy(input);
        return rc;
    }


    if (mctx->wrkobj) {
        rhtml = cli_jsonobj(mctx->wrkobj, "RootHTML");
        if (rhtml != NULL) {
            
            cli_jsonstr(rhtml, "Encoding", (const char *)htmlGetMetaEncoding(htmlDoc));
            cli_jsonint(rhtml, "CompressMode", xmlGetDocCompressMode(htmlDoc));
        }
    }


    reader = xmlReaderWalker(htmlDoc);
    if (reader == NULL) {
        cli_dbgmsg("parseRootMHTML: cannot initialize xmlTextReader\n");

        if (ctx->wrkproperty != NULL)
            ret = cli_json_parse_error(ctx->wrkproperty, "MHTML_ERROR_XML_READER_IO");
        if (ret != CL_SUCCESS)
            rc = FAIL;

        blobDestroy(input);
        return rc;
    }

    memset(&mxctx, 0, sizeof(mxctx));
    
    mxctx.comment_cb = parseMHTMLComment;
    ret              = cli_msxml_parse_document(ctx, reader, mhtml_keys, num_mhtml_keys, MSXML_FLAG_JSON | MSXML_FLAG_WALK, &mxctx);
    switch (ret) {
        case CL_SUCCESS:
        case CL_ETIMEOUT:
        case CL_BREAK:
            rc = OK;
            break;

        case CL_EMAXREC:
            rc = MAXREC;
            break;

        case CL_EMAXFILES:
            rc = MAXFILES;
            break;

        case CL_VIRUS:
            rc = VIRUS;
            break;

        default:
            rc = FAIL;
    }

    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);
    xmlFreeDoc(htmlDoc);
    blobDestroy(input);
    return rc;

    UNUSEDPARAM(m);
    UNUSEDPARAM(t);
    cli_dbgmsg("in parseRootMHTML\n");
    cli_dbgmsg("parseRootMHTML: parsing html documents disabled in libxml2!\n");


    UNUSEDPARAM(m);
    UNUSEDPARAM(t);
    cli_dbgmsg("in parseRootMHTML\n");
    cli_dbgmsg("parseRootMHTML: parsing html documents requires libxml2!\n");

    return OK;

}


static mbox_status parseEmailBody(message *messageIn, text *textIn, mbox_ctx *mctx, unsigned int recursion_level)
{
    mbox_status rc;
    text *aText          = textIn;
    message *mainMessage = messageIn;
    fileblob *fb;
    bool infected                  = FALSE;
    const struct cl_engine *engine = mctx->ctx->engine;
    const int doPhishingScan       = engine->dboptions & CL_DB_PHISHING_URLS && (DCONF_PHISHING & PHISHING_CONF_ENGINE);

    json_object *saveobj = mctx->wrkobj;


    cli_dbgmsg("in parseEmailBody, %u files saved so far\n", mctx->files);

    
    if (engine->maxreclevel)
        
        if (recursion_level > engine->maxreclevel) {

            cli_dbgmsg("parseEmailBody: hit maximum recursion level (%u)\n", recursion_level);
            return MAXREC;
        }
    if (engine->maxfiles && (mctx->files >= engine->maxfiles)) {
        
        cli_dbgmsg("parseEmailBody: number of files exceeded %u\n", engine->maxfiles);
        return MAXFILES;
    }

    rc = OK;

    
    if (mainMessage && (messageGetBody(mainMessage) != NULL)) {
        mime_type mimeType;
        int subtype, inhead, htmltextPart, inMimeHead, i;
        const char *mimeSubtype;
        char *boundary;
        const text *t_line;
        
        message *aMessage;
        int multiparts     = 0;
        message **messages = NULL; 

        cli_dbgmsg("Parsing mail file\n");

        mimeType    = messageGetMimeType(mainMessage);
        mimeSubtype = messageGetMimeSubtype(mainMessage);

        if (mctx->wrkobj != NULL) {
            mctx->wrkobj = cli_jsonobj(mctx->wrkobj, "Body");
            cli_jsonstr(mctx->wrkobj, "MimeType", getMimeTypeStr(mimeType));
            cli_jsonstr(mctx->wrkobj, "MimeSubtype", mimeSubtype);
            cli_jsonstr(mctx->wrkobj, "EncodingType", getEncTypeStr(messageGetEncoding(mainMessage)));
            cli_jsonstr(mctx->wrkobj, "Disposition", messageGetDispositionType(mainMessage));
            cli_jsonstr(mctx->wrkobj, "Filename", messageHasFilename(mainMessage) ? messageGetFilename(mainMessage) : "(inline)");
        }


        
        subtype = tableFind(mctx->subtypeTable, mimeSubtype);
        if ((mimeType == TEXT) && (subtype == PLAIN)) {
            
            cli_dbgmsg("text/plain: Assume no attachments\n");
            mimeType = NOMIME;
            messageSetMimeSubtype(mainMessage, "");
        } else if ((mimeType == MESSAGE) && (strcasecmp(mimeSubtype, "rfc822-headers") == 0)) {
            
            cli_dbgmsg("Changing message/rfc822-headers to text/rfc822-headers\n");
            mimeType = NOMIME;
            messageSetMimeSubtype(mainMessage, "");
        } else cli_dbgmsg("mimeType = %d\n", (int)mimeType);

        switch (mimeType) {
            case NOMIME:
                cli_dbgmsg("Not a mime encoded message\n");
                aText = textAddMessage(aText, mainMessage);

                if (!doPhishingScan)
                    break;
                
            case TEXT:
                
                if (doPhishingScan) {
                    
                    checkURLs(mainMessage, mctx, &rc, (subtype == HTML));
                    
                    if (rc == VIRUS)
                        infected = TRUE;
                }
                break;
            case MULTIPART:
                cli_dbgmsg("Content-type 'multipart' handler\n");
                boundary = messageFindArgument(mainMessage, "boundary");


                if (mctx->wrkobj != NULL)
                    cli_jsonstr(mctx->wrkobj, "Boundary", boundary);


                if (boundary == NULL) {
                    cli_dbgmsg("Multipart/%s MIME message contains no boundary header\n", mimeSubtype);
                    
                    mimeType = NOMIME;
                    
                    break;
                }

                cli_chomp(boundary);

                
                if (mimeSubtype[0] == '\0') {
                    cli_dbgmsg("Multipart has no subtype assuming alternative\n");
                    mimeSubtype = "alternative";
                    messageSetMimeSubtype(mainMessage, "alternative");
                }

                
                t_line = messageGetBody(mainMessage);

                if (t_line == NULL) {
                    cli_dbgmsg("Multipart MIME message has no body\n");
                    free((char *)boundary);
                    mimeType = NOMIME;
                    break;
                }

                do if (t_line->t_line) {
                        if (boundaryStart(lineGetData(t_line->t_line), boundary))
                            break;
                        
                        if (binhexBegin(mainMessage) == t_line) {
                            if (exportBinhexMessage(mctx, mainMessage)) {
                                
                                rc       = VIRUS;
                                infected = TRUE;
                                break;
                            }
                        } else if (t_line->t_next && (encodingLine(mainMessage) == t_line->t_next)) {
                            
                            cli_dbgmsg("Found MIME attachment before the first MIME section \"%s\"\n", lineGetData(t_line->t_next->t_line));
                            if (messageGetEncoding(mainMessage) == NOENCODING)
                                break;
                        }
                    }
                while ((t_line = t_line->t_next) != NULL);

                if (t_line == NULL) {
                    cli_dbgmsg("Multipart MIME message contains no boundary lines (%s)\n", boundary);
                    free((char *)boundary);
                    mimeType = NOMIME;
                    
                    break;
                }
                
                inhead     = 1;
                inMimeHead = 0;

                
                subtype = tableFind(mctx->subtypeTable, mimeSubtype);

                
                for (multiparts = 0; t_line && !infected; multiparts++) {
                    int lines = 0;
                    message **m;
                    mbox_status old_rc;

                    m = cli_realloc(messages, ((multiparts + 1) * sizeof(message *)));
                    if (m == NULL)
                        break;
                    messages = m;

                    aMessage = messages[multiparts] = messageCreate();
                    if (aMessage == NULL) {
                        multiparts--;
                        
                        break;
                    }
                    messageSetCTX(aMessage, mctx->ctx);

                    cli_dbgmsg("Now read in part %d\n", multiparts);

                    
                    while ((t_line = t_line->t_next) != NULL)
                        if (t_line->t_line &&  (strlen(lineGetData(t_line->t_line)) > 0))

                            break;

                    if (t_line == NULL) {
                        cli_dbgmsg("Empty part\n");
                        
                        if (mainMessage && (binhexBegin(mainMessage) == NULL)) {
                            messageDestroy(aMessage);
                            --multiparts;
                        }
                        continue;
                    }

                    do {
                        const char *line = lineGetData(t_line->t_line);

                        

                        if (inMimeHead) { 
                            if (line == NULL) {
                                inMimeHead = 0;
                                continue;
                            }
                            
                            cli_dbgmsg("Multipart %d: About to add mime Argument '%s'\n", multiparts, line);
                            
                            parseEmailHeader(aMessage, line, mctx->rfc821Table);

                            while (isspace((int)*line))
                                line++;

                            if (*line == '\0') {
                                inhead = inMimeHead = 0;
                                continue;
                            }
                            inMimeHead = FALSE;
                            messageAddArgument(aMessage, line);
                        } else if (inhead) { 
                            
                            char *fullline, *ptr;

                            if (line == NULL) {
                                
                                const text *next = t_line->t_next;

                                if (next && next->t_line) {
                                    const char *data = lineGetData(next->t_line);

                                    if ((messageGetEncoding(aMessage) == NOENCODING) && (messageGetMimeType(aMessage) == APPLICATION) && data && strstr(data, "base64")) {

                                        
                                        messageSetEncoding(aMessage, "base64");
                                        cli_dbgmsg("Ignoring fake end of headers\n");
                                        continue;
                                    }
                                    if ((strncmp(data, "Content", 7) == 0) || (strncmp(data, "filename=", 9) == 0)) {
                                        cli_dbgmsg("Ignoring fake end of headers\n");
                                        continue;
                                    }
                                }
                                cli_dbgmsg("Multipart %d: End of header information\n", multiparts);
                                inhead = 0;
                                continue;
                            }
                            if (isspace((int)*line)) {
                                
                                cli_dbgmsg("Part %d starts with a continuation line\n", multiparts);
                                messageAddArgument(aMessage, line);
                                
                                if (messageGetMimeType(aMessage) == NOMIME)
                                    messageSetMimeType(aMessage, "application");
                                continue;
                            }

                            inMimeHead = FALSE;

                            assert(strlen(line) <= RFC2821LENGTH);

                            fullline = rfc822comments(line, NULL);
                            if (fullline == NULL)
                                fullline = cli_strdup(line);

                            

                            
                            while (t_line && next_is_folded_header(t_line)) {
                                const char *data;
                                size_t datasz;

                                t_line = t_line->t_next;

                                data = lineGetData(t_line->t_line);

                                if (data[1] == '\0') {
                                    
                                    cli_dbgmsg("Multipart %d: headers not terminated by blank line\n", multiparts);
                                    inhead = FALSE;
                                    break;
                                }

                                datasz = strlen(fullline) + strlen(data) + 1;
                                ptr    = cli_realloc(fullline, datasz);

                                if (ptr == NULL)
                                    break;

                                fullline = ptr;
                                cli_strlcat(fullline, data, datasz);

                                
                            }

                            cli_dbgmsg("Multipart %d: About to parse folded header '%s'\n", multiparts, fullline);

                            parseEmailHeader(aMessage, fullline, mctx->rfc821Table);
                            free(fullline);
                        } else if (boundaryEnd(line, boundary)) {
                            
                            
                            break;
                        } else if (boundaryStart(line, boundary)) {
                            inhead = 1;
                            break;
                        } else {
                            if (messageAddLine(aMessage, t_line->t_line) < 0)
                                break;
                            lines++;
                        }
                    } while ((t_line = t_line->t_next) != NULL);

                    cli_dbgmsg("Part %d has %d lines, rc = %d\n", multiparts, lines, (int)rc);

                    
                    switch (subtype) {
                        case MIXED:
                        case ALTERNATIVE:
                        case REPORT:
                        case DIGEST:
                        case APPLEDOUBLE:
                        case KNOWBOT:
                        case -1:
                            old_rc      = rc;
                            mainMessage = do_multipart(mainMessage, messages, multiparts, &rc, mctx, messageIn, &aText, recursion_level);


                            if ((rc == OK_ATTACHMENTS_NOT_SAVED) && (old_rc == OK))
                                rc = OK;
                            if (messages[multiparts]) {
                                messageDestroy(messages[multiparts]);
                                messages[multiparts] = NULL;
                            }
                            --multiparts;
                            if (rc == VIRUS)
                                infected = TRUE;
                            break;

                        case RELATED:
                        case ENCRYPTED:
                        case SIGNED:
                        case PARALLEL:
                            
                            break;
                        default:
                            
                            if (messages[multiparts]) {
                                messageDestroy(messages[multiparts]);
                                messages[multiparts] = NULL;
                            }
                            --multiparts;
                    }
                }

                free((char *)boundary);

                
                switch (subtype) {
                    case KNOWBOT:
                        
                        cli_dbgmsg("multipart/knowbot parsed as multipart/mixed for now\n");
                        mimeSubtype = "mixed";
                        break;
                    case -1:
                        
                        cli_dbgmsg("Unsupported multipart format `%s', parsed as mixed\n", mimeSubtype);
                        mimeSubtype = "mixed";
                        break;
                }

                
                if (mainMessage && (mainMessage != messageIn)) {
                    messageDestroy(mainMessage);
                    mainMessage = NULL;
                }

                cli_dbgmsg("The message has %d parts\n", multiparts);

                if (infected || ((multiparts == 0) && (aText == NULL))) {
                    if (messages) {
                        for (i = 0; i < multiparts; i++)
                            if (messages[i])
                                messageDestroy(messages[i]);
                        free(messages);
                    }
                    if (aText && (textIn == NULL))
                        textDestroy(aText);


                    mctx->wrkobj = saveobj;

                    
                    switch (rc) {
                        case VIRUS:
                            return VIRUS;
                        case MAXREC:
                            return MAXREC;
                        default:
                            return OK_ATTACHMENTS_NOT_SAVED;
                    }
                }

                cli_dbgmsg("Find out the multipart type (%s)\n", mimeSubtype);

                
                switch (tableFind(mctx->subtypeTable, mimeSubtype)) {
                    case RELATED:
                        cli_dbgmsg("Multipart related handler\n");
                        
                        aMessage = NULL;
                        assert(multiparts > 0);

                        htmltextPart = getTextPart(messages, multiparts);

                        if (htmltextPart >= 0 && messages) {
                            if (messageGetBody(messages[htmltextPart]))

                                aText = textAddMessage(aText, messages[htmltextPart]);
                        } else  for (i = 0; i < multiparts; i++)

                                if (messageGetMimeType(messages[i]) == MULTIPART) {
                                    aMessage     = messages[i];
                                    htmltextPart = i;
                                    break;
                                }

                        if (htmltextPart == -1)
                            cli_dbgmsg("No HTML code found to be scanned\n");
                        else {

                            
                            if (mctx->ctx->wrkproperty)
                                parseRootMHTML(mctx, aMessage, aText);

                            rc = parseEmailBody(aMessage, aText, mctx, recursion_level + 1);
                            if ((rc == OK) && aMessage) {
                                assert(aMessage == messages[htmltextPart]);
                                messageDestroy(aMessage);
                                messages[htmltextPart] = NULL;
                            } else if (rc == VIRUS) {
                                infected = TRUE;
                                break;
                            }
                        }

                        
                    case DIGEST:
                        
                    case ALTERNATIVE:
                        cli_dbgmsg("Multipart alternative handler\n");

                        
                    case REPORT:
                        
                    case ENCRYPTED:
                        
                    case MIXED:
                    case APPLEDOUBLE: 
                        
                        if (aText) {
                            if (mainMessage && (mainMessage != messageIn))
                                messageDestroy(mainMessage);
                            mainMessage = NULL;
                        }

                        cli_dbgmsg("Mixed message with %d parts\n", multiparts);
                        for (i = 0; i < multiparts; i++) {
                            mainMessage = do_multipart(mainMessage, messages, i, &rc, mctx, messageIn, &aText, recursion_level + 1);

                            if (rc == VIRUS) {
                                infected = TRUE;
                                break;
                            }
                            if (rc == MAXREC)
                                break;
                            if (rc == OK_ATTACHMENTS_NOT_SAVED)
                                rc = OK;
                        }

                        
                        break;
                    case SIGNED:
                    case PARALLEL:
                        
                        if (messages) {
                            htmltextPart = getTextPart(messages, multiparts);
                            if (htmltextPart == -1)
                                htmltextPart = 0;
                            rc = parseEmailBody(messages[htmltextPart], aText, mctx, recursion_level + 1);
                        }
                        break;
                    default:
                        assert(0);
                }

                if (mainMessage && (mainMessage != messageIn))
                    messageDestroy(mainMessage);

                if (aText && (textIn == NULL)) {
                    if ((!infected) && (fb = fileblobCreate()) != NULL) {
                        cli_dbgmsg("Save non mime and/or text/plain part\n");
                        fileblobSetFilename(fb, mctx->dir, "textpart");
                        
                        fileblobSetCTX(fb, mctx->ctx);
                        (void)textToFileblob(aText, fb, 1);

                        fileblobDestroy(fb);
                        mctx->files++;
                    }
                    textDestroy(aText);
                }

                for (i = 0; i < multiparts; i++)
                    if (messages[i])
                        messageDestroy(messages[i]);

                if (messages)
                    free(messages);


                mctx->wrkobj = saveobj;

                return rc;

            case MESSAGE:
                
                switch (messageGetEncoding(mainMessage)) {
                    case NOENCODING:
                    case EIGHTBIT:
                    case BINARY:
                        break;
                    default:
                        cli_dbgmsg("MIME type 'message' cannot be decoded\n");
                        break;
                }
                rc = FAIL;
                if ((strcasecmp(mimeSubtype, "rfc822") == 0) || (strcasecmp(mimeSubtype, "delivery-status") == 0)) {
                    message *m = parseEmailHeaders(mainMessage, mctx->rfc821Table);
                    if (m) {
                        cli_dbgmsg("Decode rfc822\n");

                        messageSetCTX(m, mctx->ctx);

                        if (mainMessage && (mainMessage != messageIn)) {
                            messageDestroy(mainMessage);
                            mainMessage = NULL;
                        } else messageReset(mainMessage);
                        if (messageGetBody(m))
                            rc = parseEmailBody(m, NULL, mctx, recursion_level + 1);

                        messageDestroy(m);
                    }
                    break;
                } else if (strcasecmp(mimeSubtype, "disposition-notification") == 0) {
                    
                    rc = OK;
                    break;
                } else if (strcasecmp(mimeSubtype, "partial") == 0) {
                    if (mctx->ctx->options->mail & CL_SCAN_MAIL_PARTIAL_MESSAGE) {
                        
                        if (rfc1341(mainMessage, mctx->dir) >= 0)
                            rc = OK;
                    } else {
                        cli_warnmsg("Partial message received from MUA/MTA - message cannot be scanned\n");
                    }
                } else if (strcasecmp(mimeSubtype, "external-body") == 0)
                    
                    cli_warnmsg("Attempt to send Content-type message/external-body trapped\n");
                else cli_warnmsg("Unsupported message format `%s' - if you believe this file contains a virus, submit it to www.clamav.net\n", mimeSubtype);

                if (mainMessage && (mainMessage != messageIn))
                    messageDestroy(mainMessage);
                if (messages)
                    free(messages);

                mctx->wrkobj = saveobj;

                return rc;

            default:
                cli_dbgmsg("Message received with unknown mime encoding - assume application\n");
                
            case APPLICATION:
                
                {
                    fb = messageToFileblob(mainMessage, mctx->dir, 1);

                    if (fb) {
                        cli_dbgmsg("Saving main message as attachment\n");
                        if (fileblobScanAndDestroy(fb) == CL_VIRUS)
                            rc = VIRUS;
                        mctx->files++;
                        if (mainMessage != messageIn) {
                            messageDestroy(mainMessage);
                            mainMessage = NULL;
                        } else messageReset(mainMessage);
                    }
                } 
                break;

            case AUDIO:
            case VIDEO:
            case IMAGE:
                break;
        }

        if (messages) {
            
            cli_warnmsg("messages != NULL\n");
            free(messages);
        }
    }

    if (aText && (textIn == NULL)) {
        
        const text *t;
        
        bool lookahead_definately_is_bounce = FALSE;

        for (t = aText; t && (rc != VIRUS); t = t->t_next) {
            const line_t *l = t->t_line;
            const text *lookahead, *topofbounce;
            const char *s;
            bool inheader;

            if (l == NULL) {
                
                continue;
            }

            if (lookahead_definately_is_bounce)
                lookahead_definately_is_bounce = FALSE;
            else if (!isBounceStart(mctx, lineGetData(l)))
                continue;

            lookahead = t->t_next;
            if (lookahead) {
                if (isBounceStart(mctx, lineGetData(lookahead->t_line))) {
                    lookahead_definately_is_bounce = TRUE;
                    
                    continue;
                }
            } else  break;

            
            for (; lookahead; lookahead = lookahead->t_next) {
                l = lookahead->t_line;

                if (l == NULL)
                    break;
                s = lineGetData(l);
                if (strncasecmp(s, "Content-Type:", 13) == 0) {
                    
                    if (CLI_STRCASESTR(s, "text/plain") != NULL)
                        
                        continue;
                    if ((!doPhishingScan) && (CLI_STRCASESTR(s, "text/html") != NULL))
                        continue;
                    break;
                }
            }

            if (lookahead && (lookahead->t_line == NULL)) {
                cli_dbgmsg("Non mime part bounce message is not mime encoded, so it will not be scanned\n");
                t = lookahead;
                
                continue;
            }

            
            for (; lookahead; lookahead = lookahead->t_next) {
                l = lookahead->t_line;

                if (l) {
                    s = lineGetData(l);
                    if ((strncasecmp(s, "Content-Type:", 13) == 0) && (strstr(s, "multipart/") == NULL) && (strstr(s, "message/rfc822") == NULL) && (strstr(s, "text/plain") == NULL))


                        break;
                }
            }
            if (lookahead == NULL) {
                cli_dbgmsg("cli_mbox: I believe it's plain text which must be clean\n");
                
                break;
            }
            if ((fb = fileblobCreate()) == NULL)
                break;
            cli_dbgmsg("Save non mime part bounce message\n");
            fileblobSetFilename(fb, mctx->dir, "bounce");
            fileblobAddData(fb, (const unsigned char *)"Received: by clamd (bounce)\n", 28);
            fileblobSetCTX(fb, mctx->ctx);

            inheader    = TRUE;
            topofbounce = NULL;
            do {
                l = t->t_line;

                if (l == NULL) {
                    if (inheader) {
                        inheader    = FALSE;
                        topofbounce = t;
                    }
                } else {
                    s = lineGetData(l);
                    fileblobAddData(fb, (const unsigned char *)s, strlen(s));
                }
                fileblobAddData(fb, (const unsigned char *)"\n", 1);
                lookahead = t->t_next;
                if (lookahead == NULL)
                    break;
                t = lookahead;
                l = t->t_line;
                if ((!inheader) && l) {
                    s = lineGetData(l);
                    if (isBounceStart(mctx, s)) {
                        cli_dbgmsg("Found the start of another bounce candidate (%s)\n", s);
                        lookahead_definately_is_bounce = TRUE;
                        break;
                    }
                }
            } while (!fileblobInfected(fb));

            if (fileblobScanAndDestroy(fb) == CL_VIRUS)
                rc = VIRUS;
            mctx->files++;

            if (topofbounce)
                t = topofbounce;
        }
        textDestroy(aText);
        aText = NULL;
    }

    
    if (mainMessage && (rc != VIRUS)) {
        text *t_line;

        
        if (mainMessage->body_first != NULL && (encodingLine(mainMessage) != NULL) && ((t_line = bounceBegin(mainMessage)) != NULL))

            rc = (exportBounceMessage(mctx, t_line) == CL_VIRUS) ? VIRUS : OK;
        else {
            bool saveIt;

            if (messageGetMimeType(mainMessage) == MESSAGE)
                
                saveIt = (bool)(encodingLine(mainMessage) != NULL);
            else if (mainMessage->body_last != NULL && (t_line = encodingLine(mainMessage)) != NULL) {
                
                if ((fb = fileblobCreate()) != NULL) {
                    cli_dbgmsg("Found a bounce message with no header at '%s'\n", lineGetData(t_line->t_line));
                    fileblobSetFilename(fb, mctx->dir, "bounce");
                    fileblobAddData(fb, (const unsigned char *)"Received: by clamd (bounce)\n", 28);


                    fileblobSetCTX(fb, mctx->ctx);
                    if (fileblobScanAndDestroy(textToFileblob(t_line, fb, 1)) == CL_VIRUS)
                        rc = VIRUS;
                    mctx->files++;
                }
                saveIt = FALSE;
            } else  saveIt = TRUE;


            if (saveIt) {
                cli_dbgmsg("Saving text part to scan, rc = %d\n", (int)rc);
                if (saveTextPart(mctx, mainMessage, 1) == CL_VIRUS)
                    rc = VIRUS;

                if (mainMessage != messageIn) {
                    messageDestroy(mainMessage);
                    mainMessage = NULL;
                } else messageReset(mainMessage);
            }
        }
    } 
      

    if (mainMessage && (mainMessage != messageIn))
        messageDestroy(mainMessage);

    if ((rc != FAIL) && infected)
        rc = VIRUS;


    mctx->wrkobj = saveobj;


    cli_dbgmsg("parseEmailBody() returning %d\n", (int)rc);

    return rc;
}


static int boundaryStart(const char *line, const char *boundary)
{
    const char *ptr;
    char *out;
    int rc;
    char buf[RFC2821LENGTH + 1];
    char *newline;

    if (line == NULL || *line == '\0')
        return 0; 
    if (boundary == NULL)
        return 0;

    newline = strdup(line);
    if (!(newline))
        newline = (char *)line;

    if (newline != line && strlen(line)) {
        char *p;
        
        p = newline + strlen(line) - 1;
        while (p >= newline && *p == ' ')
            *(p--) = '\0';
    }

    if (newline != line)
        cli_chomp(newline);

    

    if ((*newline != '-') && (*newline != '(')) {
        if (newline != line)
            free(newline);
        return 0;
    }

    if (strchr(newline, '-') == NULL) {
        if (newline != line)
            free(newline);
        return 0;
    }

    if (strlen(newline) <= sizeof(buf)) {
        out = NULL;
        ptr = rfc822comments(newline, buf);
    } else ptr = out = rfc822comments(newline, NULL);

    if (ptr == NULL)
        ptr = newline;

    if ((*ptr++ != '-') || (*ptr == '\0')) {
        if (out)
            free(out);
        if (newline != line)
            free(newline);

        return 0;
    }

    
    if ((strstr(&ptr[1], boundary) != NULL) || (strstr(newline, boundary) != NULL)) {
        const char *k = ptr;

        
        rc = 0;
        do if (strcmp(++k, boundary) == 0) {
                rc = 1;
                break;
            }
        while (*k == '-');
        if (rc == 0) {
            k = &line[1];
            do if (strcmp(++k, boundary) == 0) {
                    rc = 1;
                    break;
                }
            while (*k == '-');
        }
    } else if (*ptr++ != '-')
        rc = 0;
    else rc = (strcasecmp(ptr, boundary) == 0);

    if (out)
        free(out);

    if (rc == 1)
        cli_dbgmsg("boundaryStart: found %s in %s\n", boundary, line);

    if (newline != line)
        free(newline);

    return rc;
}


static int boundaryEnd(const char *line, const char *boundary)
{
    size_t len;
    char *newline, *p, *p2;

    if (line == NULL || *line == '\0')
        return 0;

    p = newline = strdup(line);
    if (!(newline)) {
        p       = (char *)line;
        newline = (char *)line;
    }

    if (newline != line && strlen(line)) {
        
        p2 = newline + strlen(line) - 1;
        while (p2 >= newline && *p2 == ' ')
            *(p2--) = '\0';
    }

    

    if (*p++ != '-') {
        if (newline != line)
            free(newline);
        return 0;
    }

    if (*p++ != '-') {
        if (newline != line)
            free(newline);

        return 0;
    }

    len = strlen(boundary);
    if (strncasecmp(p, boundary, len) != 0) {
        if (newline != line)
            free(newline);

        return 0;
    }
    
    if (strlen(p) < (len + 2)) {
        if (newline != line)
            free(newline);

        return 0;
    }

    p = &p[len];
    if (*p++ != '-') {
        if (newline != line)
            free(newline);

        return 0;
    }

    if (*p == '-') {
        
        if (newline != line)
            free(newline);

        return 1;
    }

    if (newline != line)
        free(newline);

    return 0;
}


static int initialiseTables(table_t **rfc821Table, table_t **subtypeTable)
{
    const struct tableinit *tableinit;

    
    *rfc821Table = tableCreate();
    assert(*rfc821Table != NULL);

    for (tableinit = rfc821headers; tableinit->key; tableinit++)
        if (tableInsert(*rfc821Table, tableinit->key, tableinit->value) < 0) {
            tableDestroy(*rfc821Table);
            *rfc821Table = NULL;
            return -1;
        }

    *subtypeTable = tableCreate();
    assert(*subtypeTable != NULL);

    for (tableinit = mimeSubtypes; tableinit->key; tableinit++)
        if (tableInsert(*subtypeTable, tableinit->key, tableinit->value) < 0) {
            tableDestroy(*rfc821Table);
            tableDestroy(*subtypeTable);
            *rfc821Table  = NULL;
            *subtypeTable = NULL;
            return -1;
        }

    return 0;
}


static int getTextPart(message *const messages[], size_t size)
{
    size_t i;
    int textpart = -1;

    for (i = 0; i < size; i++)
        if (messages[i] && (messageGetMimeType(messages[i]) == TEXT)) {
            if (strcasecmp(messageGetMimeSubtype(messages[i]), "html") == 0)
                return (int)i;
            textpart = (int)i;
        }

    return textpart;
}


static size_t strip(char *buf, int len)
{
    register char *ptr;
    register size_t i;

    if ((buf == NULL) || (len <= 0))
        return 0;

    i = strlen(buf);
    if (len > (int)(i + 1))
        return i;
    ptr = &buf[--len];


    do if (*ptr)
            *ptr = '\0';
    while ((--len >= 0) && (!isgraph(*--ptr)) && (*ptr != '\n') && (*ptr != '\r'));

    do  if (*ptr)


            *ptr = '\0';
    while ((--len >= 0) && ((*--ptr == '\0') || isspace((int)(*ptr & 0xFF))));

    return ((size_t)(len + 1));
}


size_t strstrip(char *s)
{
    if (s == (char *)NULL)
        return (0);

    return (strip(s, strlen(s) + 1));
}


static int parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg)
{
    char *copy, *p, *buf;
    const char *ptr;
    int commandNumber;

    cli_dbgmsg("parseMimeHeader: cmd='%s', arg='%s'\n", cmd, arg);

    copy = rfc822comments(cmd, NULL);
    if (copy) {
        commandNumber = tableFind(rfc821Table, copy);
        free(copy);
    } else commandNumber = tableFind(rfc821Table, cmd);

    copy = rfc822comments(arg, NULL);

    if (copy)
        ptr = copy;
    else ptr = arg;

    buf = NULL;

    switch (commandNumber) {
        case CONTENT_TYPE:
            
            if (arg == NULL)
                
                cli_dbgmsg("Empty content-type received, no subtype specified, assuming text/plain; charset=us-ascii\n");
            else if (strchr(ptr, '/') == NULL)
                
                cli_dbgmsg("Invalid content-type '%s' received, no subtype specified, assuming text/plain; charset=us-ascii\n", ptr);
            else {
                int i;

                buf = cli_malloc(strlen(ptr) + 1);
                if (buf == NULL) {
                    cli_errmsg("parseMimeHeader: Unable to allocate memory for buf %llu\n", (long long unsigned)(strlen(ptr) + 1));
                    if (copy)
                        free(copy);
                    return -1;
                }
                
                if (*arg == '/') {
                    cli_dbgmsg("Content-type '/' received, assuming application/octet-stream\n");
                    messageSetMimeType(m, "application");
                    messageSetMimeSubtype(m, "octet-stream");
                } else {
                    
                    while (isspace(*ptr))
                        ptr++;
                    if (ptr[0] == '\"')
                        ptr++;

                    if (ptr[0] != '/') {
                        char *s;

                        char *strptr = NULL;


                        s = cli_strtokbuf(ptr, 0, ";", buf);
                        
                        if (s && *s) {
                            char *buf2 = cli_strdup(buf);

                            if (buf2 == NULL) {
                                if (copy)
                                    free(copy);
                                free(buf);
                                return -1;
                            }
                            for (;;) {

                                int set = messageSetMimeType(m, strtok_r(s, "/", &strptr));

                                int set = messageSetMimeType(m, strtok(s, "/"));



                                s = strtok_r(NULL, ";", &strptr);

                                s       = strtok(NULL, ";");

                                if (s == NULL)
                                    break;
                                if (set) {
                                    size_t len = strstrip(s) - 1;
                                    if (s[len] == '\"') {
                                        s[len] = '\0';
                                        len    = strstrip(s);
                                    }
                                    if (len) {
                                        if (strchr(s, ' '))
                                            messageSetMimeSubtype(m, cli_strtokbuf(s, 0, " ", buf2));
                                        else messageSetMimeSubtype(m, s);
                                    }
                                }

                                while (*s && !isspace(*s))
                                    s++;
                                if (*s++ == '\0')
                                    break;
                                if (*s == '\0')
                                    break;
                            }
                            free(buf2);
                        }
                    }
                }

                
                i = 1;
                while (cli_strtokbuf(ptr, i++, ";", buf) != NULL) {
                    cli_dbgmsg("mimeArgs = '%s'\n", buf);

                    messageAddArguments(m, buf);
                }
            }
            break;
        case CONTENT_TRANSFER_ENCODING:
            messageSetEncoding(m, ptr);
            break;
        case CONTENT_DISPOSITION:
            buf = cli_malloc(strlen(ptr) + 1);
            if (buf == NULL) {
                cli_errmsg("parseMimeHeader: Unable to allocate memory for buf %llu\n", (long long unsigned)(strlen(ptr) + 1));
                if (copy)
                    free(copy);
                return -1;
            }
            p = cli_strtokbuf(ptr, 0, ";", buf);
            if (p && *p) {
                messageSetDispositionType(m, p);
                messageAddArgument(m, cli_strtokbuf(ptr, 1, ";", buf));
            }
            if (!messageHasFilename(m))
                
                messageAddArgument(m, "filename=unknown");
    }
    if (copy)
        free(copy);
    if (buf)
        free(buf);

    return 0;
}


static int saveTextPart(mbox_ctx *mctx, message *m, int destroy_text)
{
    fileblob *fb;

    messageAddArgument(m, "filename=textportion");
    if ((fb = messageToFileblob(m, mctx->dir, destroy_text)) != NULL) {
        
        cli_dbgmsg("Saving main message\n");

        mctx->files++;
        return fileblobScanAndDestroy(fb);
    }
    return CL_ETMPFILE;
}


static char * rfc822comments(const char *in, char *out)
{
    const char *iptr;
    char *optr;
    int backslash, inquote, commentlevel;

    if (in == NULL)
        return NULL;

    if (strchr(in, '(') == NULL)
        return NULL;

    assert(out != in);

    while (isspace(*in))
        in++;

    if (out == NULL) {
        out = cli_malloc(strlen(in) + 1);
        if (out == NULL) {
            cli_errmsg("rfc822comments: Unable to allocate memory for out %llu\n", (long long unsigned)(strlen(in) + 1));
            return NULL;
        }
    }

    backslash = commentlevel = inquote = 0;
    optr                               = out;

    cli_dbgmsg("rfc822comments: contains a comment\n");

    for (iptr = in; *iptr; iptr++)
        if (backslash) {
            if (commentlevel == 0)
                *optr++ = *iptr;
            backslash = 0;
        } else switch (*iptr) {
                case '\\':
                    backslash = 1;
                    break;
                case '\"':
                    *optr++ = '\"';
                    inquote = !inquote;
                    break;
                case '(':
                    if (inquote)
                        *optr++ = '(';
                    else commentlevel++;
                    break;
                case ')':
                    if (inquote)
                        *optr++ = ')';
                    else if (commentlevel > 0)
                        commentlevel--;
                    break;
                default:
                    if (commentlevel == 0)
                        *optr++ = *iptr;
            }

    if (backslash) 
        *optr++ = '\\';
    *optr = '\0';

    

    cli_dbgmsg("rfc822comments '%s'=>'%s'\n", in, out);

    return out;
}


static char * rfc2047(const char *in)
{
    char *out, *pout;
    size_t len;

    if ((strstr(in, "=?") == NULL) || (strstr(in, "?=") == NULL))
        return cli_strdup(in);

    cli_dbgmsg("rfc2047 '%s'\n", in);
    out = cli_malloc(strlen(in) + 1);

    if (out == NULL) {
        cli_errmsg("rfc2047: Unable to allocate memory for out %llu\n", (long long unsigned)(strlen(in) + 1));
        return NULL;
    }

    pout = out;

    
    while (*in) {
        char encoding, *ptr, *enctext;
        message *m;
        blob *b;

        
        while (*in) {
            if ((*in == '=') && (in[1] == '?')) {
                in += 2;
                break;
            }
            *pout++ = *in++;
        }
        
        while ((*in != '?') && *in)
            in++;
        if (*in == '\0')
            break;
        encoding = *++in;
        encoding = (char)tolower(encoding);

        if ((encoding != 'q') && (encoding != 'b')) {
            cli_warnmsg("Unsupported RFC2047 encoding type '%c' - if you believe this file contains a virus, submit it to www.clamav.net\n", encoding);
            free(out);
            out = NULL;
            break;
        }
        
        if (*++in != '?')
            break;
        if (*++in == '\0')
            break;

        enctext = cli_strdup(in);
        if (enctext == NULL) {
            free(out);
            out = NULL;
            break;
        }
        in = strstr(in, "?=");
        if (in == NULL) {
            free(enctext);
            break;
        }
        in += 2;
        ptr = strstr(enctext, "?=");
        assert(ptr != NULL);
        *ptr = '\0';
        

        m = messageCreate();
        if (m == NULL) {
            free(enctext);
            break;
        }
        messageAddStr(m, enctext);
        free(enctext);
        switch (encoding) {
            case 'q':
                messageSetEncoding(m, "quoted-printable");
                break;
            case 'b':
                messageSetEncoding(m, "base64");
                break;
        }
        b = messageToBlob(m, 1);
        if (b == NULL) {
            messageDestroy(m);
            break;
        }
        len = blobGetDataSize(b);
        cli_dbgmsg("Decoded as '%*.*s'\n", (int)len, (int)len, (const char *)blobGetData(b));
        memcpy(pout, blobGetData(b), len);
        blobDestroy(b);
        messageDestroy(m);
        if (len > 0 && pout[len - 1] == '\n')
            pout += len - 1;
        else pout += len;
    }
    if (out == NULL)
        return NULL;

    *pout = '\0';

    cli_dbgmsg("rfc2047 returns '%s'\n", out);
    return out;
}


static int rfc1341(message *m, const char *dir)
{
    char *arg, *id, *number, *total, *oldfilename;
    const char *tmpdir;
    int n;
    char pdir[NAME_MAX + 1];
    unsigned char md5_val[16];
    char *md5_hex;

    id = (char *)messageFindArgument(m, "id");
    if (id == NULL)
        return -1;

    tmpdir = cli_gettmpdir();

    snprintf(pdir, sizeof(pdir) - 1, "%s" PATHSEP "clamav-partial", tmpdir);

    if ((mkdir(pdir, S_IRWXU) < 0) && (errno != EEXIST)) {
        cli_errmsg("Can't create the directory '%s'\n", pdir);
        free(id);
        return -1;
    } else if (errno == EEXIST) {
        STATBUF statb;

        if (CLAMSTAT(pdir, &statb) < 0) {
            char err[128];
            cli_errmsg("Partial directory %s: %s\n", pdir, cli_strerror(errno, err, sizeof(err)));
            free(id);
            return -1;
        }
        if (statb.st_mode & 077)
            cli_warnmsg("Insecure partial directory %s (mode 0%o)\n", pdir,  (int)(statb.st_mode & ACCESSPERMS)



                        (int)(statb.st_mode & 0777)

            );
    }

    number = (char *)messageFindArgument(m, "number");
    if (number == NULL) {
        free(id);
        return -1;
    }

    oldfilename = messageGetFilename(m);

    arg = cli_malloc(10 + strlen(id) + strlen(number));
    if (arg) {
        sprintf(arg, "filename=%s%s", id, number);
        messageAddArgument(m, arg);
        free(arg);
    }

    if (oldfilename) {
        cli_dbgmsg("Must reset to %s\n", oldfilename);
        free(oldfilename);
    }

    n = atoi(number);
    cl_hash_data("md5", id, strlen(id), md5_val, NULL);
    md5_hex = cli_str2hex((const char *)md5_val, 16);

    if (!md5_hex) {
        free(id);
        free(number);
        return CL_EMEM;
    }

    if (messageSavePartial(m, pdir, md5_hex, n) < 0) {
        free(md5_hex);
        free(id);
        free(number);
        return -1;
    }

    total = (char *)messageFindArgument(m, "total");
    cli_dbgmsg("rfc1341: %s, %s of %s\n", id, number, (total) ? total : "?");
    if (total) {
        int t   = atoi(total);
        DIR *dd = NULL;

        free(total);
        
        if ((n == t) && ((dd = opendir(pdir)) != NULL)) {
            FILE *fout;
            char outname[NAME_MAX + 1];
            time_t now;

            sanitiseName(id);

            snprintf(outname, sizeof(outname) - 1, "%s" PATHSEP "%s", dir, id);

            cli_dbgmsg("outname: %s\n", outname);

            fout = fopen(outname, "wb");
            if (fout == NULL) {
                cli_errmsg("Can't open '%s' for writing", outname);
                free(id);
                free(number);
                free(md5_hex);
                closedir(dd);
                return -1;
            }

            time(&now);
            for (n = 1; n <= t; n++) {
                char filename[NAME_MAX + 1];
                struct dirent *dent;

                snprintf(filename, sizeof(filename), "_%s-%u", md5_hex, n);

                while ((dent = readdir(dd))) {
                    FILE *fin;
                    char buffer[BUFSIZ], fullname[NAME_MAX + 1];
                    int nblanks;
                    STATBUF statb;
                    const char *dentry_idpart;
                    int test_fd;

                    if (dent->d_ino == 0)
                        continue;

                    if (!strcmp(".", dent->d_name) || !strcmp("..", dent->d_name))
                        continue;
                    snprintf(fullname, sizeof(fullname) - 1, "%s" PATHSEP "%s", pdir, dent->d_name);
                    dentry_idpart = strchr(dent->d_name, '_');

                    if (!dentry_idpart || strcmp(filename, dentry_idpart) != 0) {
                        if (!m->ctx->engine->keeptmp)
                            continue;

                        if ((test_fd = open(fullname, O_RDONLY)) < 0)
                            continue;

                        if (FSTAT(test_fd, &statb) < 0) {
                            close(test_fd);
                            continue;
                        }

                        if (now - statb.st_mtime > (time_t)(7 * 24 * 3600)) {
                            if (cli_unlink(fullname)) {
                                cli_unlink(outname);
                                fclose(fout);
                                free(md5_hex);
                                free(id);
                                free(number);
                                closedir(dd);
                                close(test_fd);
                                return -1;
                            }
                        }

                        close(test_fd);
                        continue;
                    }

                    fin = fopen(fullname, "rb");
                    if (fin == NULL) {
                        cli_errmsg("Can't open '%s' for reading", fullname);
                        fclose(fout);
                        cli_unlink(outname);
                        free(md5_hex);
                        free(id);
                        free(number);
                        closedir(dd);
                        return -1;
                    }
                    nblanks = 0;
                    while (fgets(buffer, sizeof(buffer) - 1, fin) != NULL)
                        
                        if (buffer[0] == '\n')
                            nblanks++;
                        else {
                            if (nblanks)
                                do {
                                    if (putc('\n', fout) == EOF) break;
                                } while (--nblanks > 0);
                            if (nblanks || fputs(buffer, fout) == EOF) {
                                fclose(fin);
                                fclose(fout);
                                cli_unlink(outname);
                                free(md5_hex);
                                free(id);
                                free(number);
                                closedir(dd);
                                return -1;
                            }
                        }
                    fclose(fin);

                    
                    if (!m->ctx->engine->keeptmp) {
                        if (cli_unlink(fullname)) {
                            fclose(fout);
                            cli_unlink(outname);
                            free(md5_hex);
                            free(id);
                            free(number);
                            closedir(dd);
                            return -1;
                        }
                    }
                    break;
                }
                rewinddir(dd);
            }
            closedir(dd);
            fclose(fout);
        }
    }
    free(number);
    free(id);
    free(md5_hex);

    return 0;
}

static void hrefs_done(blob *b, tag_arguments_t *hrefs)
{
    if (b)
        blobDestroy(b);
    html_tag_arg_free(hrefs);
}


static void extract_text_urls(const unsigned char *mem, size_t len, tag_arguments_t *hrefs)
{
    char url[1024];
    size_t off;
    for (off = 0; off + 10 < len; off++) {
        
        int32_t proto = cli_readint32(mem + off);
        
        proto |= 0x20202020;
        
        if ((proto == 0x70747468 && (mem[off + 4] == ':' || (mem[off + 5] == 's' && mem[off + 6] == ':'))) || proto == 0x3a707466) {

            size_t url_len;
            for (url_len = 4; off + url_len < len && url_len < (sizeof(url) - 1); url_len++) {
                unsigned char c = mem[off + url_len];
                
                if (c == ' ' || c == '\n' || c == '\t')
                    break;
            }
            memcpy(url, mem + off, url_len);
            url[url_len] = '\0';
            html_tag_arg_add(hrefs, "href", url);
            off += url_len;
        }
    }
}


static blob * getHrefs(message *m, tag_arguments_t *hrefs)
{
    unsigned char *mem;
    blob *b = messageToBlob(m, 0);
    size_t len;

    if (b == NULL)
        return NULL;

    len = blobGetDataSize(b);

    if (len == 0) {
        blobDestroy(b);
        return NULL;
    }

    
    if (len > 100 * 1024) {
        cli_dbgmsg("Viruses pointed to by URLs not scanned in large message\n");
        blobDestroy(b);
        return NULL;
    }

    hrefs->count = 0;
    hrefs->tag = hrefs->value = NULL;
    hrefs->contents           = NULL;

    cli_dbgmsg("getHrefs: calling html_normalise_mem\n");
    mem = blobGetData(b);
    if (!html_normalise_mem(mem, (off_t)len, NULL, hrefs, m->ctx->dconf)) {
        blobDestroy(b);
        return NULL;
    }
    cli_dbgmsg("getHrefs: html_normalise_mem returned\n");
    if (!hrefs->count && hrefs->scanContents) {
        extract_text_urls(mem, len, hrefs);
    }

    
    return b;
}


static void checkURLs(message *mainMessage, mbox_ctx *mctx, mbox_status *rc, int is_html)
{
    blob *b;
    tag_arguments_t hrefs;

    UNUSEDPARAM(is_html);

    if (*rc == VIRUS)
        return;

    hrefs.scanContents = mctx->ctx->engine->dboptions & CL_DB_PHISHING_URLS && (DCONF_PHISHING & PHISHING_CONF_ENGINE);

    if (!hrefs.scanContents)
        
        return;

    hrefs.count = 0;
    hrefs.tag = hrefs.value = NULL;
    hrefs.contents          = NULL;

    b = getHrefs(mainMessage, &hrefs);
    if (b) {
        if (hrefs.scanContents) {
            if (phishingScan(mctx->ctx, &hrefs) == CL_VIRUS) {
                
                mainMessage->isInfected = TRUE;
                *rc                     = VIRUS;
                cli_dbgmsg("PH:Phishing found\n");
            }
        }
    }
    hrefs_done(b, &hrefs);
}


static void sigsegv(int sig)
{
    signal(SIGSEGV, SIG_DFL);
    print_trace(1);
    exit(SIGSEGV);
}

static void print_trace(int use_syslog)
{
    void *array[10];
    size_t size;
    char **strings;
    size_t i;
    pid_t pid = getpid();

    cli_errmsg("Segmentation fault, attempting to print backtrace\n");

    size    = backtrace(array, 10);
    strings = backtrace_symbols(array, size);

    cli_errmsg("Backtrace of pid %d:\n", pid);
    if (use_syslog)
        syslog(LOG_ERR, "Backtrace of pid %d:", pid);

    for (i = 0; i < size; i++) {
        cli_errmsg("%s\n", strings[i]);
        if (use_syslog)
            syslog(LOG_ERR, "bt[%llu]: %s", (unsigned long long)i, strings[i]);
    }


    cli_errmsg("The errant mail file has been saved\n");

    

    free(strings);
}



static bool usefulHeader(int commandNumber, const char *cmd)
{
    switch (commandNumber) {
        case CONTENT_TRANSFER_ENCODING:
        case CONTENT_DISPOSITION:
        case CONTENT_TYPE:
            return TRUE;
        default:
            if (strcasecmp(cmd, "From") == 0)
                return TRUE;
            if (strcasecmp(cmd, "Received") == 0)
                return TRUE;
            if (strcasecmp(cmd, "De") == 0)
                return TRUE;
    }

    return FALSE;
}


static char * getline_from_mbox(char *buffer, size_t buffer_len, fmap_t *map, size_t *at)
{
    const char *src, *cursrc;
    char *curbuf;
    size_t i;
    size_t input_len = MIN(map->len - *at, buffer_len + 1);
    src = cursrc = fmap_need_off_once(map, *at, input_len);

    
    if (!src) {
        cli_dbgmsg("getline_from_mbox: fmap need failed\n");
        return NULL;
    }
    if ((buffer_len == 0) || (buffer == NULL)) {
        cli_errmsg("Invalid call to getline_from_mbox(). Refer to https://www.clamav.net/documents/installing-clamav\n");
        return NULL;
    }

    curbuf = buffer;

    for (i = 0; i < buffer_len - 1; i++) {
        char c;

        if (!input_len--) {
            if (curbuf == buffer) {
                
                return NULL;
            }
            break;
        }

        switch ((c = *cursrc++)) {
            case '\0':
                continue;
            case '\n':
                *curbuf++ = '\n';
                if (input_len && *cursrc == '\r') {
                    i++;
                    cursrc++;
                }
                break;
            case '\r':
                *curbuf++ = '\r';
                if (input_len && *cursrc == '\n') {
                    i++;
                    cursrc++;
                }
                break;
            default:
                *curbuf++ = c;
                continue;
        }
        break;
    }
    *at += cursrc - src;
    *curbuf = '\0';

    return buffer;
}


static bool isBounceStart(mbox_ctx *mctx, const char *line)
{
    size_t len;

    if (line == NULL)
        return FALSE;
    if (*line == '\0')
        return FALSE;
    

    len = strlen(line);
    if ((len < 6) || (len >= 72))
        return FALSE;

    if ((memcmp(line, "From ", 5) == 0) || (memcmp(line, ">From ", 6) == 0)) {
        int numSpaces = 0, numDigits = 0;

        line += 4;

        do if (*line == ' ')
                numSpaces++;
            else if (isdigit((*line) & 0xFF))
                numDigits++;
        while (*++line != '\0');

        if (numSpaces < 6)
            return FALSE;
        if (numDigits < 11)
            return FALSE;
        return TRUE;
    }
    return (bool)(cli_filetype((const unsigned char *)line, len, mctx->ctx->engine) == CL_TYPE_MAIL);
}


static bool exportBinhexMessage(mbox_ctx *mctx, message *m)
{
    bool infected = FALSE;
    fileblob *fb;

    if (messageGetEncoding(m) == NOENCODING)
        messageSetEncoding(m, "x-binhex");

    fb = messageToFileblob(m, mctx->dir, 0);

    if (fb) {
        cli_dbgmsg("Binhex file decoded to %s\n", fileblobGetFilename(fb));

        if (fileblobScanAndDestroy(fb) == CL_VIRUS)
            infected = TRUE;
        mctx->files++;
    } else cli_errmsg("Couldn't decode binhex file to %s\n", mctx->dir);

    return infected;
}


static int exportBounceMessage(mbox_ctx *mctx, text *start)
{
    int rc = CL_CLEAN;
    text *t;
    fileblob *fb;

    
    for (t = start; t; t = t->t_next) {
        const char *txt = lineGetData(t->t_line);
        char cmd[RFC2821LENGTH + 1];

        if (txt == NULL)
            continue;
        if (cli_strtokbuf(txt, 0, ":", cmd) == NULL)
            continue;

        switch (tableFind(mctx->rfc821Table, cmd)) {
            case CONTENT_TRANSFER_ENCODING:
                if ((strstr(txt, "7bit") == NULL) && (strstr(txt, "8bit") == NULL))
                    break;
                continue;
            case CONTENT_DISPOSITION:
                break;
            case CONTENT_TYPE:
                if (strstr(txt, "text/plain") != NULL)
                    t = NULL;
                break;
            default:
                if (strcasecmp(cmd, "From") == 0)
                    start = t;
                else if (strcasecmp(cmd, "Received") == 0)
                    start = t;
                continue;
        }
        break;
    }
    if (t && ((fb = fileblobCreate()) != NULL)) {
        cli_dbgmsg("Found a bounce message\n");
        fileblobSetFilename(fb, mctx->dir, "bounce");
        fileblobSetCTX(fb, mctx->ctx);
        if (textToFileblob(start, fb, 1) == NULL) {
            cli_dbgmsg("Nothing new to save in the bounce message\n");
            fileblobDestroy(fb);
        } else rc = fileblobScanAndDestroy(fb);
        mctx->files++;
    } else cli_dbgmsg("Not found a bounce message\n");

    return rc;
}


static const char *getMimeTypeStr(mime_type mimetype)
{
    const struct tableinit *entry = mimeTypeStr;

    while (entry->key) {
        if (mimetype == entry->value)
            return entry->key;
        entry++;
    }
    return "UNKNOWN";
}


static const char *getEncTypeStr(encoding_type enctype)
{
    const struct tableinit *entry = encTypeStr;

    while (entry->key) {
        if (enctype == entry->value)
            return entry->key;
        entry++;
    }
    return "UNKNOWN";
}


static message * do_multipart(message *mainMessage, message **messages, int i, mbox_status *rc, mbox_ctx *mctx, message *messageIn, text **tptr, unsigned int recursion_level)
{
    bool addToText = FALSE;
    const char *dtype;

    message *body;

    message *aMessage        = messages[i];
    const int doPhishingScan = mctx->ctx->engine->dboptions & CL_DB_PHISHING_URLS && (DCONF_PHISHING & PHISHING_CONF_ENGINE);

    json_object *thisobj = NULL, *saveobj = mctx->wrkobj;

    if (mctx->wrkobj != NULL) {
        json_object *multiobj = cli_jsonarray(mctx->wrkobj, "Multipart");
        if (multiobj == NULL) {
            cli_errmsg("Cannot get multipart preclass array\n");
            *rc = -1;
            return mainMessage;
        }

        thisobj = messageGetJObj(aMessage);
        if (thisobj == NULL) {
            cli_errmsg("Cannot get message preclass object\n");
            *rc = -1;
            return mainMessage;
        }
        if (cli_json_addowner(multiobj, thisobj, NULL, -1) != CL_SUCCESS) {
            cli_errmsg("Cannot assign message preclass object to multipart preclass array\n");
            *rc = -1;
            return mainMessage;
        }
    }


    if (aMessage == NULL) {

        if (thisobj != NULL)
            cli_jsonstr(thisobj, "MimeType", "NULL");

        return mainMessage;
    }

    if (*rc != OK)
        return mainMessage;

    cli_dbgmsg("Mixed message part %d is of type %d\n", i, messageGetMimeType(aMessage));


    if (thisobj != NULL) {
        cli_jsonstr(thisobj, "MimeType", getMimeTypeStr(messageGetMimeType(aMessage)));
        cli_jsonstr(thisobj, "MimeSubtype", messageGetMimeSubtype(aMessage));
        cli_jsonstr(thisobj, "EncodingType", getEncTypeStr(messageGetEncoding(aMessage)));
        cli_jsonstr(thisobj, "Disposition", messageGetDispositionType(aMessage));
        cli_jsonstr(thisobj, "Filename", messageHasFilename(aMessage) ? messageGetFilename(aMessage) : "(inline)");
    }


    switch (messageGetMimeType(aMessage)) {
        case APPLICATION:
        case AUDIO:
        case IMAGE:
        case VIDEO:
            break;
        case NOMIME:
            cli_dbgmsg("No mime headers found in multipart part %d\n", i);
            if (mainMessage) {
                if (binhexBegin(aMessage)) {
                    cli_dbgmsg("Found binhex message in multipart/mixed mainMessage\n");

                    if (exportBinhexMessage(mctx, mainMessage))
                        *rc = VIRUS;
                }
                if (mainMessage != messageIn)
                    messageDestroy(mainMessage);
                mainMessage = NULL;
            } else if (aMessage) {
                if (binhexBegin(aMessage)) {
                    cli_dbgmsg("Found binhex message in multipart/mixed non mime part\n");
                    if (exportBinhexMessage(mctx, aMessage))
                        *rc = VIRUS;
                    assert(aMessage == messages[i]);
                    messageReset(messages[i]);
                }
            }
            addToText = TRUE;
            if (messageGetBody(aMessage) == NULL)
                
                cli_dbgmsg("No plain text alternative\n");
            break;
        case TEXT:
            dtype = messageGetDispositionType(aMessage);
            cli_dbgmsg("Mixed message text part disposition \"%s\"\n", dtype);
            if (strcasecmp(dtype, "attachment") == 0)
                break;
            if ((*dtype == '\0') || (strcasecmp(dtype, "inline") == 0)) {
                const char *cptr;

                if (mainMessage && (mainMessage != messageIn))
                    messageDestroy(mainMessage);
                mainMessage = NULL;
                cptr        = messageGetMimeSubtype(aMessage);
                cli_dbgmsg("Mime subtype \"%s\"\n", cptr);
                if ((tableFind(mctx->subtypeTable, cptr) == PLAIN) && (messageGetEncoding(aMessage) == NOENCODING)) {
                    
                    if (!messageHasFilename(aMessage)) {
                        cli_dbgmsg("Adding part to main message\n");
                        addToText = TRUE;
                    } else cli_dbgmsg("Treating inline as attachment\n");
                } else {
                    const int is_html = (tableFind(mctx->subtypeTable, cptr) == HTML);
                    if (doPhishingScan)
                        checkURLs(aMessage, mctx, rc, is_html);
                    messageAddArgument(aMessage, "filename=mixedtextportion");
                }
                break;
            }
            cli_dbgmsg("Text type %s is not supported\n", dtype);
            return mainMessage;
        case MESSAGE:
            
            cli_dbgmsg("Found message inside multipart (encoding type %d)\n", messageGetEncoding(aMessage));

            switch (messageGetEncoding(aMessage)) {
                case NOENCODING:
                case EIGHTBIT:
                case BINARY:
                    if (encodingLine(aMessage) == NULL) {
                        
                        cli_dbgmsg("Unencoded multipart/message will not be scanned\n");
                        assert(aMessage == messages[i]);
                        messageDestroy(messages[i]);
                        messages[i] = NULL;
                        return mainMessage;
                    }
                    
                default:
                    cli_dbgmsg("Encoded multipart/message will be scanned\n");
            }


			messageAddStrAtTop(aMessage, "Received: by clamd (message/rfc822)");


            
            if (saveTextPart(mctx, aMessage, 1) == CL_VIRUS)
                *rc = VIRUS;
            assert(aMessage == messages[i]);
            messageDestroy(messages[i]);
            messages[i] = NULL;

            
            body = parseEmailHeaders(aMessage, mctx->rfc821Table);

            
            assert(aMessage == messages[i]);
            messageDestroy(messages[i]);
            messages[i]  = NULL;

            mctx->wrkobj = thisobj;

            if (body) {
                messageSetCTX(body, mctx->ctx);
                *rc = parseEmailBody(body, NULL, mctx, recursion_level + 1);
                if ((*rc == OK) && messageContainsVirus(body))
                    *rc = VIRUS;
                messageDestroy(body);
            }

            mctx->wrkobj = saveobj;


            return mainMessage;
        case MULTIPART:
            
            cli_dbgmsg("Found multipart inside multipart\n");

            mctx->wrkobj = thisobj;

            if (aMessage) {
                
                *rc = parseEmailBody(aMessage, *tptr, mctx, recursion_level + 1);
                cli_dbgmsg("Finished recursion, rc = %d\n", (int)*rc);
                assert(aMessage == messages[i]);
                messageDestroy(messages[i]);
                messages[i] = NULL;
            } else {
                *rc = parseEmailBody(NULL, NULL, mctx, recursion_level + 1);
                if (mainMessage && (mainMessage != messageIn))
                    messageDestroy(mainMessage);
                mainMessage = NULL;
            }

            mctx->wrkobj = saveobj;

            return mainMessage;
        default:
            cli_dbgmsg("Only text and application attachments are fully supported, type = %d\n", messageGetMimeType(aMessage));
            
    }

    if (*rc != VIRUS) {
        fileblob *fb = messageToFileblob(aMessage, mctx->dir, 1);

        json_object *arrobj;
        size_t arrlen = 0;

        if (thisobj != NULL) {
            
            if (json_object_object_get_ex(mctx->ctx->wrkproperty, "ContainedObjects", &arrobj))
                arrlen = json_object_array_length(arrobj);
        }


        if (fb) {
            
            fileblobSetCTX(fb, mctx->ctx);
            if (fileblobScanAndDestroy(fb) == CL_VIRUS)
                *rc = VIRUS;
            if (!addToText)
                mctx->files++;
        }

        if (thisobj != NULL) {
            json_object *entry = NULL;
            const char *dtype  = NULL;

            
            if (json_object_object_get_ex(mctx->ctx->wrkproperty, "ContainedObjects", &arrobj))
                if (json_object_array_length(arrobj) > arrlen)
                    entry = json_object_array_get_idx(arrobj, arrlen);
            if (entry) {
                json_object_object_get_ex(entry, "FileType", &entry);
                if (entry)
                    dtype = json_object_get_string(entry);
            }
            cli_jsonint(thisobj, "ContainedObjectsIndex", (uint32_t)arrlen);
            cli_jsonstr(thisobj, "ClamAVFileType", dtype ? dtype : "UNKNOWN");
        }

        if (messageContainsVirus(aMessage))
            *rc = VIRUS;
    }
    messageDestroy(aMessage);
    messages[i] = NULL;

    return mainMessage;
}


static int count_quotes(const char *buf)
{
    int quotes = 0;

    while (*buf)
        if (*buf++ == '\"')
            quotes++;

    return quotes;
}


static bool next_is_folded_header(const text *t)
{
    const text *next = t->t_next;
    const char *data, *ptr;

    if (next == NULL)
        return FALSE;

    if (next->t_line == NULL)
        return FALSE;

    data = lineGetData(next->t_line);

    
    if (isblank(data[0]))
        return TRUE;

    if (strchr(data, '=') == NULL)
        
        return FALSE;

    
    data = lineGetData(t->t_line);

    ptr = strchr(data, '\0');

    while (--ptr > data)
        switch (*ptr) {
            case ';':
                return TRUE;
            case '\n':
            case ' ':
            case '\r':
            case '\t':
                continue; 
            default:
                return FALSE;
        }
    return FALSE;
}


static bool newline_in_header(const char *line)
{
    cli_dbgmsg("newline_in_header, check \"%s\"\n", line);

    if (strncmp(line, "Message-Id: ", 12) == 0)
        return TRUE;
    if (strncmp(line, "Date: ", 6) == 0)
        return TRUE;

    return FALSE;
}
