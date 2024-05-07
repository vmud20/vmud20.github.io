




















size_t mobi_get_rawlink_location(const MOBIRawml *rawml, const uint32_t pos_fid, const uint32_t pos_off) {
    if (!rawml || !rawml->frag || !rawml->frag->entries ) {
        debug_print("%s", "Initialization failed\n");
        return SIZE_MAX;
    }
    if (pos_fid >= rawml->frag->entries_count) {
        debug_print("%s", "pos_fid not found\n");
        return SIZE_MAX;
    }
    const MOBIIndexEntry *entry = &rawml->frag->entries[pos_fid];
    const size_t insert_position = strtoul(entry->label, NULL, 10);
    size_t file_offset = insert_position + pos_off;
    return file_offset;
}


MOBI_RET mobi_search_links_kf7(MOBIResult *result, const unsigned char *data_start, const unsigned char *data_end) {
    if (!result) {
        debug_print("Result structure is null%s", "\n");
        return MOBI_PARAM_ERR;
    }
    result->start = result->end = NULL;
    *(result->value) = '\0';
    if (!data_start || !data_end) {
        debug_print("Data is null%s", "\n");
        return MOBI_PARAM_ERR;
    }
    const char *needle1 = "filepos=";
    const char *needle2 = "recindex=";
    const size_t needle1_length = strlen(needle1);
    const size_t needle2_length = strlen(needle2);
    const size_t needle_length = max(needle1_length,needle2_length);
    if (data_start + needle_length > data_end) {
        return MOBI_SUCCESS;
    }
    unsigned char *data = (unsigned char *) data_start;
    const unsigned char tag_open = '<';
    const unsigned char tag_close = '>';
    unsigned char last_border = tag_open;
    while (data <= data_end) {
        if (*data == tag_open || *data == tag_close) {
            last_border = *data;
        }
        if (data + needle_length <= data_end && (memcmp(data, needle1, needle1_length) == 0 || memcmp(data, needle2, needle2_length) == 0)) {

                
                if (last_border != tag_open) {
                    
                    data += needle_length;
                    continue;
                }
                
                while (data >= data_start && !isspace(*data) && *data != tag_open) {
                    data--;
                }
                result->start = ++data;
                
                int i = 0;
                while (data <= data_end && !isspace(*data) && *data != tag_close && i < MOBI_ATTRVALUE_MAXSIZE) {
                    result->value[i++] = (char) *data++;
                }
                
                if (*(data - 1) == '/' && *data == '>') {
                    --data; --i;
                }
                result->end = data;
                result->value[i] = '\0';
                return MOBI_SUCCESS;
            }
        data++;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_find_attrvalue(MOBIResult *result, const unsigned char *data_start, const unsigned char *data_end, const MOBIFiletype type, const char *needle) {
    if (!result) {
        debug_print("Result structure is null%s", "\n");
        return MOBI_PARAM_ERR;
    }
    result->start = result->end = NULL;
    *(result->value) = '\0';
    if (!data_start || !data_end) {
        debug_print("Data is null%s", "\n");
        return MOBI_PARAM_ERR;
    }
    size_t needle_length = strlen(needle);
    if (needle_length > MOBI_ATTRNAME_MAXSIZE) {
        debug_print("Attribute too long: %zu\n", needle_length);
        return MOBI_PARAM_ERR;
    }
    if (data_start + needle_length > data_end) {
        return MOBI_SUCCESS;
    }
    unsigned char *data = (unsigned char *) data_start;
    unsigned char tag_open;
    unsigned char tag_close;
    if (type == T_CSS) {
        tag_open = '{';
        tag_close = '}';
    } else {
        tag_open = '<';
        tag_close = '>';
    }
    unsigned char last_border = tag_close;
    while (data <= data_end) {
        if (*data == tag_open || *data == tag_close) {
            last_border = *data;
        }
        if (data + needle_length <= data_end && memcmp(data, needle, needle_length) == 0) {
            
            if (last_border != tag_open) {
                
                data += needle_length;
                continue;
            }
            
            while (data >= data_start && !isspace(*data) && *data != tag_open && *data != '=' && *data != '(') {
                data--;
            }
            result->is_url = (*data == '(');
            result->start = ++data;
            
            int i = 0;
            while (data <= data_end && !isspace(*data) && *data != tag_close && *data != ')' && i < MOBI_ATTRVALUE_MAXSIZE) {
                result->value[i++] = (char) *data++;
            }
            
            if (*(data - 1) == '/' && *data == '>') {
                --data; --i;
            }
            result->end = data;
            result->value[i] = '\0';
            return MOBI_SUCCESS;
        }
        data++;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_find_attrname(MOBIResult *result, const unsigned char *data_start, const unsigned char *data_end, const char *attrname) {
    if (!result) {
        debug_print("Result structure is null%s", "\n");
        return MOBI_PARAM_ERR;
    }
    result->start = result->end = NULL;
    *(result->value) = '\0';
    if (!data_start || !data_end) {
        debug_print("Data is null%s", "\n");
        return MOBI_PARAM_ERR;
    }
    char needle[MOBI_ATTRNAME_MAXSIZE + 1];
    snprintf(needle, MOBI_ATTRNAME_MAXSIZE + 1, "%s=", attrname);
    size_t needle_length = strlen(needle);
    if (data_start + needle_length > data_end) {
        return MOBI_SUCCESS;
    }
    unsigned char *data = (unsigned char *) data_start;
    const unsigned char quote = '"';
    const unsigned char tag_open = '<';
    const unsigned char tag_close = '>';
    unsigned char last_border = tag_close;
    while (data <= data_end) {
        if (*data == tag_open || *data == tag_close) {
            last_border = *data;
        }
        if (data + needle_length + 2 <= data_end && memcmp(data, needle, needle_length) == 0) {
            
            if (last_border != tag_open) {
                
                data += needle_length;
                continue;
            }
            
            if (data > data_start) {
                data--;
                if (!isspace(*data) && *data != tag_open) {
                    
                    data += needle_length;
                    continue;
                }
            }
            result->start = ++data;
            
            data += needle_length;
            if (*data++ != quote) {
                
                result->start = NULL;
                continue;
            }
            while (data <= data_end) {
                if (*data == quote) {
                    result->end = ++data;
                    return MOBI_SUCCESS;
                }
                data++;
            }
            result->start = NULL;
        }
        data++;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_search_links_kf8(MOBIResult *result, const unsigned char *data_start, const unsigned char *data_end, const MOBIFiletype type) {
    return mobi_find_attrvalue(result, data_start, data_end, type, "kindle:");
}


size_t mobi_get_attribute_value(char *value, const unsigned char *data, const size_t size, const char *attribute, bool only_quoted) {
    
    if (!data) {
        debug_print("Data is null%s", "\n");
        return SIZE_MAX;
    }
    size_t length = size;
    size_t attr_length = strlen(attribute);
    if (attr_length > MOBI_ATTRNAME_MAXSIZE) {
        debug_print("Attribute too long: %zu\n", attr_length);
        return SIZE_MAX;
    }
    char attr[MOBI_ATTRNAME_MAXSIZE + 2];
    strcpy(attr, attribute);
    strcat(attr, "=");
    attr_length++;
    if (size < attr_length) {
        return SIZE_MAX;
    }
    
    unsigned char last_border = '\0';
    do {
        if (*data == '<' || *data == '>') {
            last_border = *data;
        }
        if (length > attr_length + 1 && memcmp(data, attr, attr_length) == 0) {
            
            size_t offset = size - length;
            if (last_border == '>') {
                
                data += attr_length;
                length -= attr_length - 1;
                continue;
            }
            
            if (offset > 0) {
                if (data[-1] != '<' && !isspace(data[-1])) {
                    data += attr_length;
                    length -= attr_length - 1;
                    continue;
                }
            }
            
            data += attr_length;
            length -= attr_length;
            unsigned char separator;
            if (*data != '\'' && *data != '"') {
                if (only_quoted) {
                    continue;
                }
                separator = ' ';
            } else {
                separator = *data;
                data++;
                length--;
            }
            size_t j;
            for (j = 0; j < MOBI_ATTRVALUE_MAXSIZE && length && *data != separator && *data != '>'; j++) {
                *value++ = (char) *data++;
                length--;
            }
            
            if (*(data - 1) == '/' && *data == '>') {
                value--;
            }
            *value = '\0';
            
            return size - length - j;
        }
        data++;
    } while (--length);
    value[0] = '\0';
    return SIZE_MAX;
}


size_t mobi_get_aid_offset(const MOBIPart *html, const char *aid) {
    size_t length = html->size;
    const char *data = (char *) html->data;
    const size_t aid_length = strlen(aid);
    const size_t attr_length = 5; 
    do {
        if (length > (aid_length + attr_length) && memcmp(data, "aid=", attr_length - 1) == 0) {
            data += attr_length;
            length -= attr_length;
            if (memcmp(data, aid, aid_length) == 0) {
                if (data[aid_length] == '\'' || data[aid_length] == '"') {
                    return html->size - length;
                }
            }
        }
        data++;
    } while (--length);
    return SIZE_MAX;
}


MOBI_RET mobi_get_offset_by_posoff(uint32_t *file_number, size_t *offset, const MOBIRawml *rawml, const size_t pos_fid, const size_t pos_off) {
    if (!rawml || !rawml->frag || !rawml->frag->entries || !rawml->skel || !rawml->skel->entries) {
        debug_print("%s", "Initialization failed\n");
        return MOBI_INIT_FAILED;
    }
    MOBI_RET ret;
    if (pos_fid >= rawml->frag->entries_count) {
        debug_print("Entry for pos:fid:%zu doesn't exist\n", pos_fid);
        return MOBI_DATA_CORRUPT;
    }
    const MOBIIndexEntry entry = rawml->frag->entries[pos_fid];
    *offset = strtoul(entry.label, NULL, 10);
    uint32_t file_nr;
    ret = mobi_get_indxentry_tagvalue(&file_nr, &entry, INDX_TAG_FRAG_FILE_NR);
    if (ret != MOBI_SUCCESS) {
        return ret;
    }
    if (file_nr >= rawml->skel->entries_count) {
        debug_print("Entry for skeleton part no %u doesn't exist\n", file_nr);
        return MOBI_DATA_CORRUPT;
        
    }
    const MOBIIndexEntry skel_entry = rawml->skel->entries[file_nr];
    uint32_t skel_position;
    ret = mobi_get_indxentry_tagvalue(&skel_position, &skel_entry, INDX_TAG_SKEL_POSITION);
    if (ret != MOBI_SUCCESS) {
        return ret;
    }
    *offset -= skel_position;
    *offset += pos_off;
    *file_number = file_nr;
    return MOBI_SUCCESS;
}


MOBI_RET mobi_get_aid_by_offset(char *aid, const MOBIPart *html, const size_t offset) {
    if (!aid || !html) {
        debug_print("Parameter error (aid (%p), html (%p)\n", (void *) aid, (void *) html);
        return MOBI_PARAM_ERR;
    }
    if (offset > html->size) {
        debug_print("Parameter error: offset (%zu) > part size (%zu)\n", offset, html->size);
        return MOBI_PARAM_ERR;
    }
    const unsigned char *data = html->data;
    data += offset;
    size_t length = html->size - offset;
    
    size_t off = mobi_get_attribute_value(aid, data, length, "aid", true);
    if (off == SIZE_MAX) {
        return MOBI_DATA_CORRUPT;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_get_id_by_offset(char *id, const MOBIPart *html, const size_t offset, MOBIAttrType *pref_attr) {
    if (!id || !html) {
        debug_print("Parameter error (id (%p), html (%p)\n", (void *) id, (void *) html);
        return MOBI_PARAM_ERR;
    }
    if (offset > html->size) {
        debug_print("Parameter error: offset (%zu) > part size (%zu)\n", offset, html->size);
        return MOBI_PARAM_ERR;
    }
    const unsigned char *data = html->data;
    data += offset;
    size_t length = html->size - offset;
    static const char * attributes[] = {
        [ATTR_ID] = "id", [ATTR_NAME] = "name", };

    size_t off = mobi_get_attribute_value(id, data, length, attributes[*pref_attr], true);
    if (off == SIZE_MAX) {
        
        const MOBIAttrType opt_attr = (*pref_attr == ATTR_ID) ? ATTR_NAME : ATTR_ID;
        off = mobi_get_attribute_value(id, data, length, attributes[opt_attr], true);
        if (off == SIZE_MAX) {
            id[0] = '\0';
        } else {
            
            *pref_attr = opt_attr;
        }
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_get_aid_by_posoff(uint32_t *file_number, char *aid, const MOBIRawml *rawml, const size_t pos_fid, const size_t pos_off) {
    size_t offset;
    MOBI_RET ret = mobi_get_offset_by_posoff(file_number, &offset, rawml, pos_fid, pos_off);
    if (ret != MOBI_SUCCESS) {
        return MOBI_DATA_CORRUPT;
    }
    const MOBIPart *html = mobi_get_part_by_uid(rawml, *file_number);
    if (html == NULL) {
        return MOBI_DATA_CORRUPT;
    }
    ret = mobi_get_aid_by_offset(aid, html, offset);
    if (ret != MOBI_SUCCESS) {
        return MOBI_DATA_CORRUPT;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_get_id_by_posoff(uint32_t *file_number, char *id, const MOBIRawml *rawml, const size_t pos_fid, const size_t pos_off, MOBIAttrType *pref_attr) {
    size_t offset;
    MOBI_RET ret = mobi_get_offset_by_posoff(file_number, &offset, rawml, pos_fid, pos_off);
    if (ret != MOBI_SUCCESS) {
        return MOBI_DATA_CORRUPT;
    }
    const MOBIPart *html = mobi_get_part_by_uid(rawml, *file_number);
    if (html == NULL) {
        return MOBI_DATA_CORRUPT;
    }
    ret = mobi_get_id_by_offset(id, html, offset, pref_attr);
    if (ret != MOBI_SUCCESS) {
        return MOBI_DATA_CORRUPT;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_reconstruct_resources(const MOBIData *m, MOBIRawml *rawml) {
    size_t first_res_seqnumber = mobi_get_first_resource_record(m);
    if (first_res_seqnumber == MOBI_NOTSET) {
        
        first_res_seqnumber = 0;
    }
    const MOBIPdbRecord *curr_record = mobi_get_record_by_seqnumber(m, first_res_seqnumber);
    if (curr_record == NULL) {
        debug_print("First resource record not found at %zu, skipping resources\n", first_res_seqnumber);
        return MOBI_SUCCESS;
    }
    size_t i = 0;
    MOBIPart *head = NULL;
    while (curr_record != NULL) {
        const MOBIFiletype filetype = mobi_determine_resource_type(curr_record);
        if (filetype == T_UNKNOWN) {
            curr_record = curr_record->next;
            i++;
            continue;
        }
        if (filetype == T_BREAK) {
            break;
        }
        
        MOBIPart *curr_part = calloc(1, sizeof(MOBIPart));;
        if (curr_part == NULL) {
            debug_print("%s\n", "Memory allocation for flow part failed");
            return MOBI_MALLOC_FAILED;
        }
        curr_part->data = curr_record->data;
        curr_part->size = curr_record->size;
        curr_part->uid = i++;
        curr_part->next = NULL;
        
        MOBI_RET ret = MOBI_SUCCESS;
        if (filetype == T_FONT) {
            ret = mobi_add_font_resource(curr_part);
            if (ret != MOBI_SUCCESS) {
                debug_print("%s\n", "Decoding font resource failed");
            }
        } else if (filetype == T_AUDIO) {
            ret = mobi_add_audio_resource(curr_part);
            if (ret != MOBI_SUCCESS) {
                debug_print("%s\n", "Decoding audio resource failed");
            }
        } else if (filetype == T_VIDEO) {
            ret = mobi_add_video_resource(curr_part);
            if (ret != MOBI_SUCCESS) {
                debug_print("%s\n", "Decoding video resource failed");
            }
        } else {
            curr_part->type = filetype;
        }
        
        curr_record = curr_record->next;
        
        if (ret != MOBI_SUCCESS) {
            free(curr_part);
            curr_part = NULL;
        } else if (head) {
            head->next = curr_part;
            head = curr_part;
        } else {
            rawml->resources = curr_part;
            head = curr_part;
        }
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_process_replica(unsigned char *pdf, const char *text, size_t *length) {
    MOBI_RET ret = MOBI_SUCCESS;
    MOBIBuffer *buf = mobi_buffer_init_null((unsigned char*) text, *length);
    if (buf == NULL) {
        debug_print("%s\n", "Memory allocation failed");
        return MOBI_MALLOC_FAILED;
    }
    mobi_buffer_setpos(buf, 12);
    size_t pdf_offset = mobi_buffer_get32(buf); 
    size_t pdf_length = mobi_buffer_get32(buf); 
    if (pdf_length > *length) {
        debug_print("PDF size from replica header too large: %zu", pdf_length);
        mobi_buffer_free_null(buf);
        return MOBI_DATA_CORRUPT;
    }
    mobi_buffer_setpos(buf, pdf_offset);
    mobi_buffer_getraw(pdf, buf, pdf_length);
    ret = buf->error;
    mobi_buffer_free_null(buf);
    *length = pdf_length;
    return ret;
}


MOBI_RET mobi_reconstruct_flow(MOBIRawml *rawml, const char *text, const size_t length) {
    
    if (rawml->fdst != NULL) {
        rawml->flow = calloc(1, sizeof(MOBIPart));
        if (rawml->flow == NULL) {
            debug_print("%s", "Memory allocation for flow part failed\n");
            return MOBI_MALLOC_FAILED;
        }
        
        MOBIPart *curr = rawml->flow;
        size_t i = 0;
        const size_t section_count = rawml->fdst->fdst_section_count;
        while (i < section_count) {
            if (i > 0) {
                curr->next = calloc(1, sizeof(MOBIPart));
                if (curr->next == NULL) {
                    debug_print("%s", "Memory allocation for flow part failed\n");
                    return MOBI_MALLOC_FAILED;
                }
                curr = curr->next;
            }
            const uint32_t section_start = rawml->fdst->fdst_section_starts[i];
            const uint32_t section_end = rawml->fdst->fdst_section_ends[i];
            const size_t section_length = section_end - section_start;
            if (section_start + section_length > length) {
                debug_print("Wrong fdst section length: %zu\n", section_length);
                return MOBI_DATA_CORRUPT;
            }
            unsigned char *section_data = malloc(section_length);
            if (section_data == NULL) {
                debug_print("%s", "Memory allocation failed\n");
                return MOBI_MALLOC_FAILED;
            }
            memcpy(section_data, (text + section_start), section_length);
            curr->uid = i;
            curr->data = section_data;
            curr->type = mobi_determine_flowpart_type(rawml, i);
            curr->size = section_length;
            curr->next = NULL;
            i++;
        }
    } else {
        
        
        rawml->flow = calloc(1, sizeof(MOBIPart));
        if (rawml->flow == NULL) {
            debug_print("%s", "Memory allocation for flow part failed\n");
            return MOBI_MALLOC_FAILED;
        }
        MOBIPart *curr = rawml->flow;
        size_t section_length = 0;
        MOBIFiletype section_type = T_HTML;
        unsigned char *section_data;
        
        if (memcmp(text, REPLICA_MAGIC, 4) == 0) {
            debug_print("%s", "Print Replica book\n");
            
            unsigned char *pdf = malloc(length);
            if (pdf == NULL) {
                debug_print("%s", "Memory allocation for flow part failed\n");
                return MOBI_MALLOC_FAILED;
            }
            section_length = length;
            section_type = T_PDF;
            const MOBI_RET ret = mobi_process_replica(pdf, text, &section_length);
            if (ret != MOBI_SUCCESS) {
                free(pdf);
                return ret;
            }
            section_data = malloc(section_length);
            if (section_data == NULL) {
                debug_print("%s", "Memory allocation failed\n");
                free(pdf);
                return MOBI_MALLOC_FAILED;
            }
            memcpy(section_data, pdf, section_length);
            free(pdf);
        } else {
            
            section_length = length;
            section_data = malloc(section_length);
            if (section_data == NULL) {
                debug_print("%s", "Memory allocation failed\n");
                return MOBI_MALLOC_FAILED;
            }
            memcpy(section_data, text, section_length);
        }
        curr->uid = 0;
        curr->data = section_data;
        curr->type = section_type;
        curr->size = section_length;
        curr->next = NULL;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_reconstruct_parts(MOBIRawml *rawml) {
    MOBI_RET ret;
    if (rawml->flow == NULL) {
        debug_print("%s", "Flow structure not initialized\n");
        return MOBI_INIT_FAILED;
    }
    
    MOBIBuffer *buf = mobi_buffer_init_null(rawml->flow->data, rawml->flow->size);
    if (buf == NULL) {
        debug_print("%s\n", "Memory allocation failed");
        return MOBI_MALLOC_FAILED;
    }
    rawml->markup = calloc(1, sizeof(MOBIPart));
    if (rawml->markup == NULL) {
        debug_print("%s", "Memory allocation for markup part failed\n");
        mobi_buffer_free_null(buf);
        return MOBI_MALLOC_FAILED;
    }
    MOBIPart *curr = rawml->markup;
    
    if (rawml->skel == NULL) {
        unsigned char *data = malloc(buf->maxlen);
        if (data == NULL) {
            debug_print("%s", "Memory allocation failed\n");
            mobi_buffer_free_null(buf);
            return MOBI_MALLOC_FAILED;
        }
        memcpy(data, buf->data, buf->maxlen);
        curr->uid = 0;
        curr->size = buf->maxlen;
        curr->data = data;
        curr->type = rawml->flow->type;
        curr->next = NULL;
        mobi_buffer_free_null(buf);
        return MOBI_SUCCESS;
    }
    
    size_t i = 0;
    size_t j = 0;
    size_t curr_position = 0;
    size_t total_fragments_count = rawml->frag->total_entries_count;
    while (i < rawml->skel->entries_count) {
        const MOBIIndexEntry *entry = &rawml->skel->entries[i];
        uint32_t fragments_count;
        ret = mobi_get_indxentry_tagvalue(&fragments_count, entry, INDX_TAG_SKEL_COUNT);
        if (ret != MOBI_SUCCESS) {
            mobi_buffer_free_null(buf);
            return ret;
        }
        if (fragments_count > total_fragments_count) {
            debug_print("%s", "Wrong count of fragments\n");
            mobi_buffer_free_null(buf);
            return MOBI_DATA_CORRUPT;
        }
        total_fragments_count -= fragments_count;
        uint32_t skel_position;
        ret = mobi_get_indxentry_tagvalue(&skel_position, entry, INDX_TAG_SKEL_POSITION);
        if (ret != MOBI_SUCCESS) {
            mobi_buffer_free_null(buf);
            return ret;
        }
        uint32_t skel_length;
        ret = mobi_get_indxentry_tagvalue(&skel_length, entry, INDX_TAG_SKEL_LENGTH);
        if (ret != MOBI_SUCCESS || skel_position + skel_length > buf->maxlen) {
            mobi_buffer_free_null(buf);
            return MOBI_DATA_CORRUPT;
        }
        debug_print("%zu\t%s\t%i\t%i\t%i\n", i, entry->label, fragments_count, skel_position, skel_length);
        mobi_buffer_setpos(buf, skel_position);
        
        unsigned char *frag_buffer = mobi_buffer_getpointer(buf, skel_length);
        if (frag_buffer == NULL) {
            debug_print("%s\n", "Fragment data beyond buffer");
            mobi_buffer_free_null(buf);
            return MOBI_DATA_CORRUPT;
        }
        MOBIFragment *first_fragment = mobi_list_add(NULL, 0, frag_buffer, skel_length, false);
        MOBIFragment *current_fragment = first_fragment;
        while (fragments_count--) {
            entry = &rawml->frag->entries[j];
            uint32_t insert_position = (uint32_t) strtoul(entry->label, NULL, 10);
            if (insert_position < curr_position) {
                debug_print("Insert position (%u) before part start (%zu)\n", insert_position, curr_position);
                mobi_buffer_free_null(buf);
                mobi_list_del_all(first_fragment);
                return MOBI_DATA_CORRUPT;
            }
            uint32_t file_number;
            ret = mobi_get_indxentry_tagvalue(&file_number, entry, INDX_TAG_FRAG_FILE_NR);
            if (ret != MOBI_SUCCESS) {
                mobi_buffer_free_null(buf);
                mobi_list_del_all(first_fragment);
                return ret;
            }
            if (file_number != i) {
                debug_print("%s", "SKEL part number and fragment sequence number don't match\n");
                mobi_buffer_free_null(buf);
                mobi_list_del_all(first_fragment);
                return MOBI_DATA_CORRUPT;
            }
            uint32_t frag_length;
            ret = mobi_get_indxentry_tagvalue(&frag_length, entry, INDX_TAG_FRAG_LENGTH);
            if (ret != MOBI_SUCCESS) {
                mobi_buffer_free_null(buf);
                mobi_list_del_all(first_fragment);
                return ret;
            }

            
            uint32_t seq_number;
            ret = mobi_get_indxentry_tagvalue(&seq_number, entry, INDX_TAG_FRAG_SEQUENCE_NR);
            if (ret != MOBI_SUCCESS) {
                mobi_buffer_free_null(buf);
                mobi_list_del_all(first_fragment);
                return ret;
            }
            uint32_t frag_position;
            ret = mobi_get_indxentry_tagvalue(&frag_position, entry, INDX_TAG_FRAG_POSITION);
            if (ret != MOBI_SUCCESS) {
                mobi_buffer_free_null(buf);
                mobi_list_del_all(first_fragment);
                return ret;
            }
            uint32_t cncx_offset;
            ret = mobi_get_indxentry_tagvalue(&cncx_offset, entry, INDX_TAG_FRAG_AID_CNCX);
            if (ret != MOBI_SUCCESS) {
                mobi_buffer_free_null(buf);
                mobi_list_del_all(first_fragment);
                return ret;
            }
            const MOBIPdbRecord *cncx_record = rawml->frag->cncx_record;
            char *aid_text = mobi_get_cncx_string(cncx_record, cncx_offset);
            if (aid_text == NULL) {
                mobi_buffer_free_null(buf);
                debug_print("%s\n", "Memory allocation failed");
                mobi_list_del_all(first_fragment);
                return MOBI_MALLOC_FAILED;
            }
            debug_print("posfid[%zu]\t%i\t%i\t%s\t%i\t%i\t%i\t%i\n", j, insert_position, cncx_offset, aid_text, file_number, seq_number, frag_position, frag_length);
            free(aid_text);

            
            insert_position -= curr_position;
            if (skel_length < insert_position) {
                debug_print("Insert position (%u) after part end (%u)\n", insert_position, skel_length);
                
                
                insert_position = skel_length;
            }
            skel_length += frag_length;
            
            frag_buffer = mobi_buffer_getpointer(buf, frag_length);
            if (frag_buffer == NULL) {
                debug_print("%s\n", "Fragment data beyond buffer");
                mobi_buffer_free_null(buf);
                mobi_list_del_all(first_fragment);
                return MOBI_DATA_CORRUPT;
            }
            current_fragment = mobi_list_insert(current_fragment, insert_position, frag_buffer, frag_length, false, insert_position);
            j++;
            
        }
        char *skel_text = malloc(skel_length);
        if (skel_text == NULL) {
            debug_print("%s", "Memory allocation for markup data failed\n");
            mobi_buffer_free_null(buf);
            mobi_list_del_all(first_fragment);
            return MOBI_MALLOC_FAILED;
        }
        char *p = skel_text;
        while (first_fragment) {
            if (first_fragment->fragment) {
                memcpy(p, first_fragment->fragment, first_fragment->size);
                p += first_fragment->size;
            } else {
                debug_print("Skipping broken fragment in part %zu\n", i);
            }
            first_fragment = mobi_list_del(first_fragment);
        }
        if (i > 0) {
            curr->next = calloc(1, sizeof(MOBIPart));
            if (curr->next == NULL) {
                debug_print("%s", "Memory allocation for markup part failed\n");
                free(skel_text);
                mobi_buffer_free_null(buf);
                return MOBI_MALLOC_FAILED;
            }
            curr = curr->next;
        }
        curr->uid = i;
        curr->size = skel_length;
        curr->data = (unsigned char *) skel_text;
        curr->type = T_HTML;
        curr->next = NULL;
        curr_position += skel_length;
        i++;
    }
    mobi_buffer_free_null(buf);
    return MOBI_SUCCESS;
}


MOBI_RET mobi_get_filepos_array(MOBIArray *links, const MOBIPart *part) {
    if (!links || !part) {
        return MOBI_INIT_FAILED;
    }
    size_t offset = 0;
    size_t size = part->size;
    unsigned char *data = part->data;
    while (true) {
        char val[MOBI_ATTRVALUE_MAXSIZE + 1];
        size -= offset;
        data += offset;
        offset = mobi_get_attribute_value(val, data, size, "filepos", false);
        if (offset == SIZE_MAX) { break; }
        size_t filepos = strtoul(val, NULL, 10);
        if (filepos > UINT32_MAX || filepos == 0) {
            debug_print("Filepos out of range: %zu\n", filepos);
            continue;
        }
        MOBI_RET ret = array_insert(links, (uint32_t) filepos);
        if (ret != MOBI_SUCCESS) {
            return ret;
        }
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_get_ncx_filepos_array(MOBIArray *links, const MOBIRawml *rawml) {
    if (!links || !rawml) {
        return MOBI_PARAM_ERR;
    }
    MOBIPart *part = rawml->resources;
    while (part) {
        if (part->type == T_NCX) {
            size_t offset = 0;
            size_t size = part->size;
            unsigned char *data = part->data;
            while (true) {
                char val[MOBI_ATTRVALUE_MAXSIZE + 1];
                size -= offset;
                data += offset;
                offset = mobi_get_attribute_value(val, data, size, "src", false);
                if (offset == SIZE_MAX) { break; }
                
                uint32_t filepos = 0;
                sscanf(val + 15, "%10u", &filepos);
                MOBI_RET ret = array_insert(links, filepos);
                if (ret != MOBI_SUCCESS) {
                    return ret;
                }
            }
        }
        part = part->next;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_posfid_to_link(char *link, const MOBIRawml *rawml, const char *value, MOBIAttrType *pref_attr) {
    
    
    if (strlen(value) < (sizeof("kindle:pos:fid:0000:off:0000000000") - 1)) {
        debug_print("Skipping too short link: %s\n", value);
        *link = '\0';
        return MOBI_SUCCESS;
    }
    value += (sizeof("kindle:pos:fid:") - 1);
    if (value[4] != ':') {
        debug_print("Skipping malformed link: kindle:pos:fid:%s\n", value);
        *link = '\0';
        return MOBI_SUCCESS;
    }
    char str_fid[4 + 1];
    strncpy(str_fid, value, 4);
    str_fid[4] = '\0';
    char str_off[10 + 1];
    value += (sizeof("0001:off:") - 1);
    strncpy(str_off, value, 10);
    str_off[10] = '\0';
    
    
    uint32_t pos_off;
    uint32_t pos_fid;
    MOBI_RET ret = mobi_base32_decode(&pos_off, str_off);
    if (ret != MOBI_SUCCESS) {
        return ret;
    }
    ret = mobi_base32_decode(&pos_fid, str_fid);
    if (ret != MOBI_SUCCESS) {
        return ret;
    }
    uint32_t part_id;
    char id[MOBI_ATTRVALUE_MAXSIZE + 1];
    ret = mobi_get_id_by_posoff(&part_id, id, rawml, pos_fid, pos_off, pref_attr);
    if (ret != MOBI_SUCCESS) {
        return ret;
    }
    
    if (pos_off) {
        int n = snprintf(link, MOBI_ATTRVALUE_MAXSIZE + 1, "\"part%05u.html#%s\"", part_id, id);
        if (n > MOBI_ATTRVALUE_MAXSIZE + 1) {
            debug_print("Skipping truncated link: %s\n", link);
            *link = '\0';
            return MOBI_SUCCESS;
       }
    } else {
        snprintf(link, MOBI_ATTRVALUE_MAXSIZE + 1, "\"part%05u.html\"", part_id);
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_flow_to_link(char *link, const MOBIRawml *rawml, const char *value) {
    
    *link = '\0';
    if (strlen(value) < (sizeof("kindle:flow:0000?mime=") - 1)) {
        debug_print("Skipping too short link: %s\n", value);
        return MOBI_SUCCESS;
    }
    value += (sizeof("kindle:flow:") - 1);
    if (value[4] != '?') {
        debug_print("Skipping broken link: kindle:flow:%s\n", value);
        return MOBI_SUCCESS;
    }
    char str_fid[4 + 1];
    strncpy(str_fid, value, 4);
    str_fid[4] = '\0';
    
    MOBIPart *flow = mobi_get_flow_by_fid(rawml, str_fid);
    if (flow == NULL) {
        debug_print("Skipping broken link (missing resource): kindle:flow:%s\n", value);
        return MOBI_SUCCESS;
    }
    MOBIFileMeta meta = mobi_get_filemeta_by_type(flow->type);
    char *extension = meta.extension;
    snprintf(link, MOBI_ATTRVALUE_MAXSIZE + 1, "\"flow%05zu.%s\"", flow->uid, extension);
    return MOBI_SUCCESS;
}


MOBI_RET mobi_embed_to_link(char *link, const MOBIRawml *rawml, const char *value) {
    
    
    while (*value == '"' || *value == '\'' || isspace(*value)) {
        value++;
    }
    *link = '\0';
    if (strlen(value) < (sizeof("kindle:embed:0000") - 1)) {
        debug_print("Skipping too short link: %s\n", value);
        return MOBI_SUCCESS;
    }
    value += (sizeof("kindle:embed:") - 1);
    char str_fid[4 + 1];
    strncpy(str_fid, value, 4);
    str_fid[4] = '\0';
    
    
    uint32_t part_id;
    MOBI_RET ret = mobi_base32_decode(&part_id, str_fid);
    if (ret != MOBI_SUCCESS) {
        debug_print("Skipping broken link (corrupt base32): kindle:embed:%s\n", value);
        return MOBI_SUCCESS;
    }
    part_id--;
    MOBIPart *resource = mobi_get_resource_by_uid(rawml, part_id);
    if (resource == NULL) {
        debug_print("Skipping broken link (missing resource): kindle:embed:%s\n", value);
        return MOBI_SUCCESS;
    }
    MOBIFileMeta meta = mobi_get_filemeta_by_type(resource->type);
    char *extension = meta.extension;
    snprintf(link, MOBI_ATTRVALUE_MAXSIZE + 1, "\"resource%05u.%s\"", part_id, extension);
    return MOBI_SUCCESS;
}


MOBI_RET mobi_reconstruct_links_kf8(const MOBIRawml *rawml) {
    MOBIResult result;
    
    typedef struct NEWData {
        size_t part_group;
        size_t part_uid;
        MOBIFragment *list;
        size_t size;
        struct NEWData *next;
    } NEWData;
    
    NEWData *partdata = NULL;
    NEWData *curdata = NULL;
    MOBIPart *parts[] = {
        rawml->markup,  rawml->flow->next };

    size_t i;
    for (i = 0; i < 2; i++) {
        MOBIPart *part = parts[i];
        while (part) {
            unsigned char *data_in = part->data;
            result.start = part->data;
            const unsigned char *data_end = part->data + part->size - 1;
            MOBIFragment *first = NULL;
            MOBIFragment *curr = NULL;
            size_t part_size = 0;
            MOBIAttrType pref_attr = ATTR_ID;
            while (true) {
                mobi_search_links_kf8(&result, result.start, data_end, part->type);
                if (result.start == NULL) {
                    break;
                }
                char *value = (char *) result.value;
                unsigned char *data_cur = result.start;
                char *target = NULL;
                if (data_cur < data_in) {
                    mobi_list_del_all(first);
                    return MOBI_DATA_CORRUPT;
                }
                size_t size = (size_t) (data_cur - data_in);
                char link[MOBI_ATTRVALUE_MAXSIZE + 1];
                if ((target = strstr(value, "kindle:pos:fid:")) != NULL) {
                    
                    
                    
                    MOBI_RET ret = mobi_posfid_to_link(link, rawml, target, &pref_attr);
                    if (ret != MOBI_SUCCESS) {
                        mobi_list_del_all(first);
                        return ret;
                    }
                } else if ((target = strstr(value, "kindle:flow:")) != NULL) {
                    
                    
                    MOBI_RET ret = mobi_flow_to_link(link, rawml, target);
                    if (ret != MOBI_SUCCESS) {
                        mobi_list_del_all(first);
                        return ret;
                    }
                } else if ((target = strstr(value, "kindle:embed:")) != NULL) {
                    
                    
                    
                    MOBI_RET ret = mobi_embed_to_link(link, rawml, target);
                    if (ret != MOBI_SUCCESS) {
                        mobi_list_del_all(first);
                        return ret;
                    }
                }
                if (target && *link != '\0') {
                    
                    curr = mobi_list_add(curr, (size_t) (data_in - part->data), data_in, size, false);
                    if (curr == NULL) {
                        mobi_list_del_all(first);
                        debug_print("%s\n", "Memory allocation failed");
                        return MOBI_MALLOC_FAILED;
                    }
                    if (!first) { first = curr; }
                    part_size += curr->size;
                    
                    
                    curr = mobi_list_add(curr, SIZE_MAX, (unsigned char *) strdup(link + result.is_url), strlen(link) - 2 * result.is_url, true);

                    if (curr == NULL) {
                        mobi_list_del_all(first);
                        debug_print("%s\n", "Memory allocation failed");
                        return MOBI_MALLOC_FAILED;
                    }
                    part_size += curr->size;
                    data_in = result.end;
                }
            }
            if (first && first->fragment) {
                
                if (part->data + part->size < data_in) {
                    mobi_list_del_all(first);
                    return MOBI_DATA_CORRUPT;
                }
                size_t size = (size_t) (part->data + part->size - data_in);
                curr = mobi_list_add(curr, (size_t) (data_in - part->data), data_in, size, false);
                if (curr == NULL) {
                    mobi_list_del_all(first);
                    debug_print("%s\n", "Memory allocation failed");
                    return MOBI_MALLOC_FAILED;
                }
                part_size += curr->size;
                
                if (!curdata) {
                    curdata = calloc(1, sizeof(NEWData));
                    partdata = curdata;
                } else {
                    curdata->next = calloc(1, sizeof(NEWData));
                    curdata = curdata->next;
                }
                curdata->part_group = i;
                curdata->part_uid = part->uid;
                curdata->list = first;
                curdata->size = part_size;
            }
            part = part->next;
        }
    }
    
    debug_print("Inserting links%s", "\n");
    for (i = 0; i < 2; i++) {
        MOBIPart *part = parts[i];
        while (part) {
            if (partdata && part->uid == partdata->part_uid && i == partdata->part_group) {
                MOBIFragment *fragdata = partdata->list;
                unsigned char *new_data = malloc(partdata->size);
                if (new_data == NULL) {
                    mobi_list_del_all(fragdata);
                    debug_print("%s\n", "Memory allocation failed");
                    return MOBI_MALLOC_FAILED;
                }
                unsigned char *data_out = new_data;
                while (fragdata) {
                    memcpy(data_out, fragdata->fragment, fragdata->size);
                    data_out += fragdata->size;
                    fragdata = mobi_list_del(fragdata);
                }
                free(part->data);
                part->data = new_data;
                part->size = partdata->size;
                NEWData *partused = partdata;
                partdata = partdata->next;
                free(partused);
            }
            part = part->next;
        }
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_reconstruct_infl(char *outstring, const MOBIIndx *infl, const MOBIIndexEntry *orth_entry) {
    const char *label = orth_entry->label;
    uint32_t *infl_groups = NULL;
    size_t infl_count = mobi_get_indxentry_tagarray(&infl_groups, orth_entry, INDX_TAGARR_ORTH_INFL);
    
    if (infl_count == 0 || !infl_groups) {
        return MOBI_SUCCESS;
    }    
    const char *start_tag = "<idx:infl>";
    const char *end_tag = "</idx:infl>";
    const char *iform_tag = "<idx:iform%s value=\"%s\"/>";
    char name_attr[INDX_INFLBUF_SIZEMAX + 1];
    char infl_tag[INDX_INFLBUF_SIZEMAX + 1];
    strcpy(outstring, start_tag);
    size_t initlen = strlen(start_tag) + strlen(end_tag);
    size_t outlen = initlen;
    size_t label_length = strlen(label);
    if (label_length > INDX_INFLBUF_SIZEMAX) {
        debug_print("Entry label too long (%s)\n", label);
        return MOBI_DATA_CORRUPT;
    }
    if (infl->cncx_record == NULL) {
        debug_print("%s\n", "Missing cncx record");
        return MOBI_DATA_CORRUPT;
    }
    for (size_t i = 0; i < infl_count; i++) {
        size_t offset = infl_groups[i];
        if (offset >= infl->entries_count) {
            debug_print("%s\n", "Invalid entry offset");
            return MOBI_DATA_CORRUPT;
        }
        uint32_t *groups;
        size_t group_cnt = mobi_get_indxentry_tagarray(&groups, &infl->entries[offset], INDX_TAGARR_INFL_GROUPS);
        uint32_t *parts;
        size_t part_cnt = mobi_get_indxentry_tagarray(&parts, &infl->entries[offset], INDX_TAGARR_INFL_PARTS_V2);
        if (group_cnt != part_cnt) {
            return MOBI_DATA_CORRUPT;
        }
        for (size_t j = 0; j < part_cnt; j++) {
            name_attr[0] = '\0';
            char *group_name = mobi_get_cncx_string(infl->cncx_record, groups[j]);
            if (group_name == NULL) {
                debug_print("%s\n", "Memory allocation failed");
                return MOBI_MALLOC_FAILED;
            }
            if (strlen(group_name)) {
                snprintf(name_attr, INDX_INFLBUF_SIZEMAX, " name=\"%s\"", group_name);
            }
            free(group_name);
            
            unsigned char decoded[INDX_INFLBUF_SIZEMAX + 1];
            memset(decoded, 0, INDX_INFLBUF_SIZEMAX + 1);
            if (parts[j] >= infl->entries_count) {
                debug_print("%s\n", "Invalid entry offset");
                return MOBI_DATA_CORRUPT;
            }
            unsigned char *rule = (unsigned char *) infl->entries[parts[j]].label;
            memcpy(decoded, label, label_length);
            int decoded_length = (int) label_length;
            MOBI_RET ret = mobi_decode_infl(decoded, &decoded_length, rule);
            if (ret != MOBI_SUCCESS) {
                return ret;
            }
            if (decoded_length == 0) {
                continue;
            }
            int n = snprintf(infl_tag, INDX_INFLBUF_SIZEMAX, iform_tag, name_attr, decoded);
            if (n > INDX_INFLBUF_SIZEMAX) {
                debug_print("Skipping truncated tag: %s\n", infl_tag);
                continue;
            }
            outlen += strlen(infl_tag);
            if (outlen > INDX_INFLTAG_SIZEMAX) {
                debug_print("Inflections text in %s too long (%zu)\n", label, outlen);
                return MOBI_ERROR;
            }
            strcat(outstring, infl_tag);
        }
    }
    if (outlen == initlen) {
        outstring[0] = '\0';
    } else {
        strcat(outstring, end_tag);
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_reconstruct_infl_v1(char *outstring, MOBITrie * const infl_tree, const MOBIIndexEntry *orth_entry) {
    const char *label = orth_entry->label;
    const size_t label_length = strlen(label);
    if (label_length > INDX_INFLBUF_SIZEMAX) {
        debug_print("Entry label too long (%s)\n", label);
        return MOBI_DATA_CORRUPT;
    }
    char *infl_strings[INDX_INFLSTRINGS_MAX];
    size_t infl_count = mobi_trie_get_inflgroups(infl_strings, infl_tree, label);
    
    if (infl_count == 0) {
        return MOBI_SUCCESS;
    }
    
    const char *start_tag = "<idx:infl>";
    const char *end_tag = "</idx:infl>";
    const char *iform_tag = "<idx:iform value=\"%s\"/>";
    char infl_tag[INDX_INFLBUF_SIZEMAX + 1];
    strcpy(outstring, start_tag);
    size_t initlen = strlen(start_tag) + strlen(end_tag);
    size_t outlen = initlen;
    for (size_t i = 0; i < infl_count; i++) {
        char *decoded = infl_strings[i];
        size_t decoded_length = strlen(decoded);

        if (decoded_length == 0) {
            free(decoded);
            continue;
        }
        int n = snprintf(infl_tag, INDX_INFLBUF_SIZEMAX, iform_tag, decoded);
        
        free(decoded);
        if (n > INDX_INFLBUF_SIZEMAX) {
            debug_print("Skipping too long tag: %s\n", infl_tag);
            continue;
        }
        outlen += strlen(infl_tag);
        if (outlen > INDX_INFLTAG_SIZEMAX) {
            debug_print("Inflections text in %s too long (%zu)\n", label, outlen);
            break;
        }
        strcat(outstring, infl_tag);
    }
    if (outlen == initlen) {
        outstring[0] = '\0';
    } else {
        strcat(outstring, end_tag);
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_reconstruct_orth(const MOBIRawml *rawml, MOBIFragment *first, size_t *new_size) {
    MOBITrie *infl_trie = NULL;
    bool is_infl_v2 = mobi_indx_has_tag(rawml->orth, INDX_TAGARR_ORTH_INFL);
    bool is_infl_v1 = false;
    if (is_infl_v2 == false) {
        is_infl_v1 = mobi_indx_has_tag(rawml->infl, INDX_TAGARR_INFL_PARTS_V1);
    }
    debug_print("Reconstructing orth index %s\n", (is_infl_v1)?"(infl v1)":(is_infl_v2)?"(infl v2)":"");
    if (is_infl_v1) {
        size_t total = rawml->infl->entries_count;
        size_t j = 0;
        while (j < total) {
            MOBI_RET ret = mobi_trie_insert_infl(&infl_trie, rawml->infl, j++);
            if (ret != MOBI_SUCCESS || infl_trie == NULL) {
                debug_print("Building trie for inflections failed%s", "\n");
                mobi_trie_free(infl_trie);
                is_infl_v1 = false;
            }
        }
    }
    
    MOBIFragment *curr = first;
    size_t i = 0;
    const size_t count = rawml->orth->entries_count;
    const char *start_tag1 = "<idx:entry><idx:orth value=\"%s\">%s</idx:orth></idx:entry>";
    const char *start_tag2 = "<idx:entry scriptable=\"yes\"><idx:orth value=\"%s\">%s</idx:orth>";
    const char *end_tag = "</idx:entry>";
    const size_t start_tag1_len = strlen(start_tag1) - 4;
    const size_t start_tag2_len = strlen(start_tag2) - 4;
    const size_t end_tag_len = strlen(end_tag);
    uint32_t prev_startpos = 0;
    while (i < count) {
        const MOBIIndexEntry *orth_entry = &rawml->orth->entries[i];
        const char *label = orth_entry->label;
        uint32_t entry_startpos;
        MOBI_RET ret = mobi_get_indxentry_tagvalue(&entry_startpos, orth_entry, INDX_TAG_ORTH_POSITION);
        if (ret != MOBI_SUCCESS) {
            i++;
            continue;
        }
        size_t entry_length = 0;
        uint32_t entry_textlen = 0;
        mobi_get_indxentry_tagvalue(&entry_textlen, orth_entry, INDX_TAG_ORTH_LENGTH);
        char *start_tag;
        if (entry_textlen == 0) {
            entry_length += start_tag1_len + strlen(label);
            start_tag = (char *) start_tag1;
        } else {
            entry_length += start_tag2_len + strlen(label);
            start_tag = (char *) start_tag2;
        }

        char *entry_text;
        if (rawml->infl) {
            char *infl_tag = malloc(INDX_INFLTAG_SIZEMAX + 1);
            if (infl_tag == NULL) {
                debug_print("%s\n", "Memory allocation failed");
                mobi_trie_free(infl_trie);
                return MOBI_MALLOC_FAILED;
            }
            infl_tag[0] = '\0';
            if (is_infl_v2) {
                ret = mobi_reconstruct_infl(infl_tag, rawml->infl, orth_entry);
            } else if (is_infl_v1) {
                ret = mobi_reconstruct_infl_v1(infl_tag, infl_trie, orth_entry);
            } else {
                debug_print("Unknown inflection scheme?%s", "\n");
            }
            if (ret != MOBI_SUCCESS) {
                free(infl_tag);
                return ret;
            }
            entry_length += strlen(infl_tag);
            
            entry_text = malloc(entry_length + 1);
            if (entry_text == NULL) {
                debug_print("%s\n", "Memory allocation failed");
                mobi_trie_free(infl_trie);
                free(infl_tag);
                return MOBI_MALLOC_FAILED;
            }
            snprintf(entry_text, entry_length + 1, start_tag, label, infl_tag);
            free(infl_tag);
        } else {
            entry_text = malloc(entry_length + 1);
            if (entry_text == NULL) {
                debug_print("%s\n", "Memory allocation failed");
                mobi_trie_free(infl_trie);
                return MOBI_MALLOC_FAILED;
            }
            snprintf(entry_text, entry_length + 1, start_tag, label, "");
        }
        
        if (entry_startpos < prev_startpos) {
            curr = first;
        }
        curr = mobi_list_insert(curr, SIZE_MAX, (unsigned char *) entry_text, entry_length, true, entry_startpos);

        prev_startpos = entry_startpos;
        if (curr == NULL) {
            debug_print("%s\n", "Memory allocation failed");
            mobi_trie_free(infl_trie);
            return MOBI_MALLOC_FAILED;
        }
        *new_size += curr->size;
        if (entry_textlen > 0) {
            
            curr = mobi_list_insert(curr, SIZE_MAX, (unsigned char *) strdup(end_tag), end_tag_len, true, entry_startpos + entry_textlen);

            if (curr == NULL) {
                debug_print("%s\n", "Memory allocation failed");
                mobi_trie_free(infl_trie);
                return MOBI_MALLOC_FAILED;
            }
            *new_size += curr->size;
        }
        i++;
    }
    mobi_trie_free(infl_trie);
    return MOBI_SUCCESS;
}


MOBI_RET mobi_reconstruct_links_kf7(const MOBIRawml *rawml) {
    MOBIResult result;
    MOBIArray *links = array_init(25);
    if (links == NULL) {
        debug_print("%s\n", "Memory allocation failed");
        return MOBI_MALLOC_FAILED;
    }
    MOBIPart *part = rawml->markup;
    
    MOBI_RET ret = mobi_get_filepos_array(links, part);
    if (ret != MOBI_SUCCESS) {
        array_free(links);
        return ret;
    }
    ret = mobi_get_ncx_filepos_array(links, rawml);
    if (ret != MOBI_SUCCESS) {
        array_free(links);
        return ret;
    }
    array_sort(links, true);
    unsigned char *data_in = part->data;
    MOBIFragment *first = NULL;
    MOBIFragment *curr = NULL;
    size_t new_size = 0;
    
    result.start = part->data;
    const unsigned char *data_end = part->data + part->size - 1;
    while (true) {
        mobi_search_links_kf7(&result, result.start, data_end);
        if (result.start == NULL) {
            break;
        }
        char *attribute = (char *) result.value;
        unsigned char *data_cur = result.start;
        result.start = result.end;
        char link[MOBI_ATTRVALUE_MAXSIZE + 1];
        const char *numbers = "0123456789";
        char *value = strpbrk(attribute, numbers);
        if (value == NULL) {
            debug_print("Unknown link target: %s\n", attribute);
            continue;
        }
        size_t target;
        switch (attribute[0]) {
            case 'f':
                
                
                target = strtoul(value, NULL, 10);
                snprintf(link, MOBI_ATTRVALUE_MAXSIZE + 1, "href=\"#%010u\"", (uint32_t)target);
                break;
            case 'h':
            case 'l':
                data_cur += 2;
                
            case 'r':
                
                
                target = strtoul(value, NULL, 10);
                if (target > 0) {
                    target--;
                }
                MOBIFiletype filetype = mobi_get_resourcetype_by_uid(rawml, target);
                MOBIFileMeta filemeta = mobi_get_filemeta_by_type(filetype);
                snprintf(link, MOBI_ATTRVALUE_MAXSIZE + 1, "src=\"resource%05u.%s\"", (uint32_t) target, filemeta.extension);
                break;
            default:
                debug_print("Unknown link target: %s\n", attribute);
                continue;
        }
        
        
        if (data_cur < data_in) {
            mobi_list_del_all(first);
            array_free(links);
            return MOBI_DATA_CORRUPT;
        }
        size_t size = (size_t) (data_cur - data_in);
        size_t raw_offset = (size_t) (data_in - part->data);
        curr = mobi_list_add(curr, raw_offset, data_in, size, false);
        if (curr == NULL) {
            mobi_list_del_all(first);
            array_free(links);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        if (!first) { first = curr; }
        new_size += curr->size;
        
        curr = mobi_list_add(curr, SIZE_MAX, (unsigned char *) strdup(link), strlen(link), true);

        if (curr == NULL) {
            mobi_list_del_all(first);
            array_free(links);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        new_size += curr->size;
        data_in = result.end;
    }
    if (first) {
        
        if (part->data + part->size < data_in) {
            mobi_list_del_all(first);
            array_free(links);
            return MOBI_DATA_CORRUPT;
        }
        size_t size = (size_t) (part->data + part->size - data_in);
        size_t raw_offset = (size_t) (data_in - part->data);
        curr = mobi_list_add(curr, raw_offset, data_in, size, false);
        if (curr == NULL) {
            mobi_list_del_all(first);
            array_free(links);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        new_size += curr->size;
    } else {
        
        first = mobi_list_add(first, 0, part->data, part->size, false);
        if (first == NULL) {
            array_free(links);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        new_size += first->size;
    }
    
    curr = first;
    size_t i = 0;
    while (i < links->size) {
        const uint32_t offset = links->data[i];
        char anchor[MOBI_ATTRVALUE_MAXSIZE + 1];
        snprintf(anchor, MOBI_ATTRVALUE_MAXSIZE + 1, "<a id=\"%010u\"></a>", offset);
        curr = mobi_list_insert(curr, SIZE_MAX, (unsigned char *) strdup(anchor), strlen(anchor), true, offset);

        if (curr == NULL) {
            mobi_list_del_all(first);
            array_free(links);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        new_size += curr->size;
        i++;
    }
    array_free(links);
    
    if (rawml->orth) {
        ret = mobi_reconstruct_orth(rawml, first, &new_size);
        if (ret != MOBI_SUCCESS) {
            mobi_list_del_all(first);
            return ret;
        }
    }
    if (first && first->next) {
        
        debug_print("Inserting links%s", "\n");
        unsigned char *new_data = malloc(new_size);
        if (new_data == NULL) {
            mobi_list_del_all(first);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        unsigned char *data_out = new_data;
        MOBIFragment *fragdata = first;
        while (fragdata) {
            memcpy(data_out, fragdata->fragment, fragdata->size);
            data_out += fragdata->size;
            fragdata = mobi_list_del(fragdata);
        }
        free(part->data);
        part->data = new_data;
        part->size = new_size;
    } else {
        mobi_list_del(first);
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_reconstruct_links(const MOBIRawml *rawml) {
    debug_print("Reconstructing links%s", "\n");
    if (rawml == NULL) {
        debug_print("%s\n", "Rawml not initialized\n");
        return MOBI_INIT_FAILED;
    }
    MOBI_RET ret;
    if (mobi_is_rawml_kf8(rawml)) {
        
        ret = mobi_reconstruct_links_kf8(rawml);
    } else {
        
        ret = mobi_reconstruct_links_kf7(rawml);
    }
    return ret;
}


MOBI_RET mobi_iterate_txtparts(MOBIRawml *rawml, MOBI_RET (*cb) (MOBIPart *)) {
    MOBIPart *parts[] = {
        rawml->markup,  rawml->flow->next };

    size_t i;
    for (i = 0; i < 2; i++) {
        MOBIPart *part = parts[i];
        while (part) {
            if (part->type == T_HTML || part->type == T_CSS) {
                MOBI_RET ret = cb(part);
                if (ret != MOBI_SUCCESS) {
                    return ret;
                }
            }
            part = part->next;
        }
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_markup_to_utf8(MOBIPart *part) {
    if (part == NULL) {
        return MOBI_INIT_FAILED;
    }
    unsigned char *text = part->data;
    size_t length = part->size;
    
    size_t out_length = 3 * length + 1;
    char *out_text = malloc(out_length);
    if (out_text == NULL) {
        debug_print("%s", "Memory allocation failed\n");
        return MOBI_MALLOC_FAILED;
    }
    MOBI_RET ret = mobi_cp1252_to_utf8(out_text, (const char *) text, &out_length, length);
    free(text);
    if (ret != MOBI_SUCCESS || out_length == 0) {
        debug_print("%s", "conversion from cp1252 to utf8 failed\n");
        free(out_text);
        part->data = NULL;
        return MOBI_DATA_CORRUPT;
    }
    text = malloc(out_length);
    if (text == NULL) {
        debug_print("%s", "Memory allocation failed\n");
        free(out_text);
        part->data = NULL;
        return MOBI_MALLOC_FAILED;
    }
    memcpy(text, out_text, out_length);
    free(out_text);
    part->data = text;
    part->size = out_length;
    return MOBI_SUCCESS;
}


MOBI_RET mobi_strip_mobitags(MOBIPart *part) {
    if (part == NULL || part->data == NULL) {
        return MOBI_INIT_FAILED;
    }
    if (part->type != T_HTML) {
        return MOBI_SUCCESS;
    }
    MOBIResult result;
    unsigned char *data_in = part->data;
    result.start = part->data;
    const unsigned char *data_end = part->data + part->size - 1;
    MOBIFragment *first = NULL;
    MOBIFragment *curr = NULL;
    size_t part_size = 0;
    while (true) {
        mobi_find_attrname(&result, result.start, data_end, "aid");
        if (result.start == NULL) {
            break;
        }
        unsigned char *data_cur = result.start;
        result.start = result.end;
        if (data_cur < data_in) {
            mobi_list_del_all(first);
            return MOBI_DATA_CORRUPT;
        }
        size_t size = (size_t) (data_cur - data_in);
        
        curr = mobi_list_add(curr, (size_t) (data_in - part->data ), data_in, size, false);
        if (curr == NULL) {
            mobi_list_del_all(first);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        if (!first) { first = curr; }
        part_size += curr->size;
        data_in = result.end;
    }
    if (first) {
        
        if (part->data + part->size < data_in) {
            mobi_list_del_all(first);
            return MOBI_DATA_CORRUPT;
        }
        size_t size = (size_t) (part->data + part->size - data_in);
        curr = mobi_list_add(curr, (size_t) (data_in - part->data ), data_in, size, false);
        if (curr == NULL) {
            mobi_list_del_all(first);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        part_size += curr->size;
        
        unsigned char *new_data = malloc(part_size);
        if (new_data == NULL) {
            mobi_list_del_all(first);
            debug_print("%s\n", "Memory allocation failed");
            return MOBI_MALLOC_FAILED;
        }
        unsigned char *data_out = new_data;
        while (first) {
            memcpy(data_out, first->fragment, first->size);
            data_out += first->size;
            first = mobi_list_del(first);
        }
        free(part->data);
        part->data = new_data;
        part->size = part_size;
    }
    return MOBI_SUCCESS;
}


MOBI_RET mobi_parse_rawml(MOBIRawml *rawml, const MOBIData *m) {
    return mobi_parse_rawml_opt(rawml, m, true, true, true);
}


MOBI_RET mobi_parse_rawml_opt(MOBIRawml *rawml, const MOBIData *m, bool parse_toc, bool parse_dict, bool reconstruct) {
    
    MOBI_RET ret;
    if (m == NULL) {
        debug_print("%s", "Mobi structure not initialized\n");
        return MOBI_INIT_FAILED;
    }
    if (rawml == NULL) {
        return MOBI_INIT_FAILED;
    }
    
    
    const size_t maxlen = mobi_get_text_maxsize(m);
    if (maxlen == MOBI_NOTSET) {
        debug_print("%s", "Insane text length\n");
        return MOBI_DATA_CORRUPT;
    }
    char *text = malloc(maxlen + 1);
    if (text == NULL) {
        debug_print("%s", "Memory allocation failed\n");
        return MOBI_MALLOC_FAILED;
    }
    
    size_t length = maxlen;
    ret = mobi_get_rawml(m, text, &length);
    if (ret != MOBI_SUCCESS) {
        debug_print("%s", "Error parsing text\n");
        free(text);
        return ret;
    }
    
    if (mobi_exists_fdst(m)) {
        
        if (m->mh->fdst_section_count && *m->mh->fdst_section_count > 1) {
            ret = mobi_parse_fdst(m, rawml);
            if (ret != MOBI_SUCCESS) {
                free(text);
                return ret;
            }
        }
    }
    ret = mobi_reconstruct_flow(rawml, text, length);
    free(text);
    if (ret != MOBI_SUCCESS) {
        return ret;
    }
    ret = mobi_reconstruct_resources(m, rawml);
    if (ret != MOBI_SUCCESS) {
        return ret;
    }
    const size_t offset = mobi_get_kf8offset(m);
    
    if (mobi_exists_skel_indx(m) && mobi_exists_frag_indx(m)) {
        const size_t indx_record_number = *m->mh->skeleton_index + offset;
        
        MOBIIndx *skel_meta = mobi_init_indx();
        ret = mobi_parse_index(m, skel_meta, indx_record_number);
        if (ret != MOBI_SUCCESS) {
            return ret;
        }
        rawml->skel = skel_meta;
    }
    
    
    if (mobi_exists_frag_indx(m)) {
        MOBIIndx *frag_meta = mobi_init_indx();
        const size_t indx_record_number = *m->mh->fragment_index + offset;
        ret = mobi_parse_index(m, frag_meta, indx_record_number);
        if (ret != MOBI_SUCCESS) {
            return ret;
        }
        rawml->frag = frag_meta;
    }
    
    if (parse_toc) {
        
        if (mobi_exists_guide_indx(m)) {
            MOBIIndx *guide_meta = mobi_init_indx();
            const size_t indx_record_number = *m->mh->guide_index + offset;
            ret = mobi_parse_index(m, guide_meta, indx_record_number);
            if (ret != MOBI_SUCCESS) {
                return ret;
            }
            rawml->guide = guide_meta;
        }
        
        
        if (mobi_exists_ncx(m)) {
            MOBIIndx *ncx_meta = mobi_init_indx();
            const size_t indx_record_number = *m->mh->ncx_index + offset;
            ret = mobi_parse_index(m, ncx_meta, indx_record_number);
            if (ret != MOBI_SUCCESS) {
                return ret;
            }
            rawml->ncx = ncx_meta;
        }
    }
    
    if (parse_dict && mobi_is_dictionary(m)) {
        
        MOBIIndx *orth_meta = mobi_init_indx();
        size_t indx_record_number = *m->mh->orth_index + offset;
        ret = mobi_parse_index(m, orth_meta, indx_record_number);
        if (ret != MOBI_SUCCESS) {
            return ret;
        }
        rawml->orth = orth_meta;
        
        if (mobi_exists_infl(m)) {
            MOBIIndx *infl_meta = mobi_init_indx();
            indx_record_number = *m->mh->infl_index + offset;
            ret = mobi_parse_index(m, infl_meta, indx_record_number);
            if (ret != MOBI_SUCCESS) {
                return ret;
            }
            rawml->infl = infl_meta;
        }
    }
    
    ret = mobi_reconstruct_parts(rawml);
    if (ret != MOBI_SUCCESS) {
        return ret;
    }
    if (reconstruct) {

        ret = mobi_build_opf(rawml, m);
        if (ret != MOBI_SUCCESS) {
            return ret;
        }

        ret = mobi_reconstruct_links(rawml);
        if (ret != MOBI_SUCCESS) {
            return ret;
        }
        if (mobi_is_kf8(m)) {
            debug_print("Stripping unneeded tags%s", "\n");
            ret = mobi_iterate_txtparts(rawml, mobi_strip_mobitags);
            if (ret != MOBI_SUCCESS) {
                return ret;
            }
        }

    }
    if (mobi_is_cp1252(m)) {
        debug_print("Converting cp1252 to utf8%s", "\n");
        ret = mobi_iterate_txtparts(rawml, mobi_markup_to_utf8);
        if (ret != MOBI_SUCCESS) {
            return ret;
        }
    }
    return MOBI_SUCCESS;
}
