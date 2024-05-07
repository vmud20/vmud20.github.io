
















void otv_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    uint8_t flags;

    ND_PRINT((ndo, "OTV, "));
    if (len < 8)
        goto trunc;

    ND_TCHECK(*bp);
    flags = *bp;
    ND_PRINT((ndo, "flags [%s] (0x%02x), ", flags & 0x08 ? "I" : ".", flags));
    bp += 1;

    ND_TCHECK2(*bp, 3);
    ND_PRINT((ndo, "overlay %u, ", EXTRACT_24BITS(bp)));
    bp += 3;

    ND_TCHECK2(*bp, 3);
    ND_PRINT((ndo, "instance %u\n", EXTRACT_24BITS(bp)));
    bp += 3;

    
    ND_TCHECK(*bp);
    bp += 1;

    ether_print(ndo, bp, len - 8, len - 8, NULL, NULL);
    return;

trunc:
    ND_PRINT((ndo, " [|OTV]"));
}
