














static const char tstr[] = " [|NSH]";
static const struct tok nsh_flags [] = {
    { 0x20, "O" }, { 0x10, "C" }, { 0, NULL }

};





void nsh_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    int n, vn;
    uint8_t ver;
    uint8_t flags;
    uint8_t length;
    uint8_t md_type;
    uint8_t next_protocol;
    uint32_t service_path_id;
    uint8_t service_index;
    uint32_t ctx;
    uint16_t tlv_class;
    uint8_t tlv_type;
    uint8_t tlv_len;
    u_int next_len;

    
    if (len < NSH_BASE_HDR_LEN + NSH_SERVICE_PATH_HDR_LEN)
        goto trunc;

    ND_TCHECK2(*bp, NSH_BASE_HDR_LEN + NSH_SERVICE_PATH_HDR_LEN);

    ver = (uint8_t)(*bp >> 6);
    flags = *bp;
    bp += 1;
    length = *bp;
    bp += 1;
    md_type = *bp;
    bp += 1;
    next_protocol = *bp;
    bp += 1;
    service_path_id = EXTRACT_24BITS(bp);
    bp += 3;
    service_index = *bp;
    bp += 1;

    ND_PRINT((ndo, "NSH, "));
    if (ndo->ndo_vflag > 1) {
        ND_PRINT((ndo, "ver %d, ", ver));
    }
    ND_PRINT((ndo, "flags [%s], ", bittok2str_nosep(nsh_flags, "none", flags)));
    if (ndo->ndo_vflag > 2) {
        ND_PRINT((ndo, "length %d, ", length));
        ND_PRINT((ndo, "md type 0x%x, ", md_type));
    }
    if (ndo->ndo_vflag > 1) {
        ND_PRINT((ndo, "next-protocol 0x%x, ", next_protocol));
    }
    ND_PRINT((ndo, "service-path-id 0x%06x, ", service_path_id));
    ND_PRINT((ndo, "service-index 0x%x", service_index));

    
    if (len < length * NSH_HDR_WORD_SIZE)
        goto trunc;

    ND_TCHECK2(*bp, length * NSH_HDR_WORD_SIZE);

    
    if (length < 2)
        goto trunc;

    
    if (ndo->ndo_vflag > 2) {
        if (md_type == 0x01) {
            for (n = 0; n < length - 2; n++) {
                ctx = EXTRACT_32BITS(bp);
                bp += NSH_HDR_WORD_SIZE;
                ND_PRINT((ndo, "\n        Context[%02d]: 0x%08x", n, ctx));
            }
        }
        else if (md_type == 0x02) {
            n = 0;
            while (n < length - 2) {
                tlv_class = EXTRACT_16BITS(bp);
                bp += 2;
                tlv_type  = *bp;
                bp += 1;
                tlv_len   = *bp;
                bp += 1;

                ND_PRINT((ndo, "\n        TLV Class %d, Type %d, Len %d", tlv_class, tlv_type, tlv_len));

                n += 1;

                if (length - 2 < n + tlv_len) {
                    ND_PRINT((ndo, " ERROR: invalid-tlv-length"));
                    return;
                }

                for (vn = 0; vn < tlv_len; vn++) {
                    ctx = EXTRACT_32BITS(bp);
                    bp += NSH_HDR_WORD_SIZE;
                    ND_PRINT((ndo, "\n            Value[%02d]: 0x%08x", vn, ctx));
                }
                n += tlv_len;
            }
        }
        else {
            ND_PRINT((ndo, "ERROR: unknown-next-protocol"));
            return;
        }
    }
    else {
        bp += (length - 2) * NSH_HDR_WORD_SIZE;
    }
    ND_PRINT((ndo, ndo->ndo_vflag ? "\n    " : ": "));

    
    next_len = len - length * NSH_HDR_WORD_SIZE;
    switch (next_protocol) {
    case 0x1:
        ip_print(ndo, bp, next_len);
        break;
    case 0x2:
        ip6_print(ndo, bp, next_len);
        break;
    case 0x3:
        ether_print(ndo, bp, next_len, next_len, NULL, NULL);
        break;
    default:
        ND_PRINT((ndo, "ERROR: unknown-next-protocol"));
        return;
    }

    return;

trunc:
    ND_PRINT((ndo, "%s", tstr));
}

