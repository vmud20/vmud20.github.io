
























int flag2str(int flag, char *flag_str) {
    if (flag & 0x1)
        flag_str[2] = 'E';
    if (flag >> 1 & 0x1)
        flag_str[1] = 'W';
    if (flag >> 2 & 0x1)
        flag_str[0] = 'R';
    
    return 0;
}

int flag2str_sh(int flag, char *flag_str) {
    if (flag & 0x1)
        flag_str[2] = 'W';
    if (flag >> 1 & 0x1)
        flag_str[1] = 'A';
    if (flag >> 2 & 0x1)
        flag_str[0] = 'E';
    
    return 0;
}

int parse(char *elf) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    int count;
    char *tmp;
    char *name;
    char flag[4];

    MODE = get_elf_class(elf);

    fd = open(elf, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    
    if (MODE == ELFCLASS32) {
        
        Elf32_Ehdr *ehdr;
        ehdr = (Elf32_Ehdr *)elf_map;

        INFO("ELF Header\n");        
        switch (ehdr->e_type) {
            case ET_NONE:
                tmp = "An unknown type";
                break;

            case ET_REL:
                tmp = "A relocatable file";
                break;

            case ET_EXEC:
                tmp = "An executable file";
                break;

            case ET_DYN:
                tmp = "A shared object";
                break;

            case ET_CORE:
                tmp = "A core file";
                break;
            
            default:
                tmp = "An unknown type";
                break;
        }
        PRINT_HEADER_EXP("e_type:", ehdr->e_type, tmp);

        switch (ehdr->e_type) {
            case EM_NONE:
                tmp = "An unknown machine";
                break;

            case EM_M32:
                tmp = "AT&T WE 32100";
                break;

            case EM_SPARC:
                tmp = "Sun Microsystems SPARC";
                break;

            case EM_386:
                tmp = "Intel 80386";
                break;

            case EM_68K:
                tmp = "Motorola 68000";
                break;
            
            case EM_88K:
                tmp = "Motorola 88000";
                break;

            case EM_860:
                tmp = "Intel 80860";
                break;

            case EM_MIPS:
                tmp = "MIPS RS3000 (big-endian only)";
                break;

            case EM_PARISC:
                tmp = "HP/PA";
                break;

            case EM_SPARC32PLUS:
                tmp = "SPARC with enhanced instruction set";
                break;
            
            case EM_PPC:
                tmp = "PowerPC";
                break;

            case EM_PPC64:
                tmp = "PowerPC 64-bit";
                break;

            case EM_S390:
                tmp = "IBM S/390";
                break;

            case EM_ARM:
                tmp = "Advanced RISC Machines";
                break;

            case EM_SH:
                tmp = "Renesas SuperH";
                break;
            
            case EM_SPARCV9:
                tmp = "SPARC v9 64-bit";
                break;

            case EM_IA_64:
                tmp = "Intel Itanium";
                break;

            case EM_X86_64:
                tmp = "AMD x86-64";
                break;

            case EM_VAX:
                tmp = "DEC Vax";
                break;
            
            default:
                tmp = "An unknown machine";
                break;
        }
        PRINT_HEADER_EXP("e_machine:", ehdr->e_machine, tmp);

        switch (ehdr->e_version) {
            case EV_NONE:
                tmp = "Invalid version";
                break;

            case EV_CURRENT:
                tmp = "Current version";
                break;

            default:
                tmp = "Known version";
                break;
        }
        PRINT_HEADER_EXP("e_version:", ehdr->e_version, tmp);
        PRINT_HEADER("e_entry:", ehdr->e_entry);
        PRINT_HEADER("e_phoff:", ehdr->e_phoff);
        PRINT_HEADER("e_shoff:", ehdr->e_shoff);
        PRINT_HEADER("e_flags:", ehdr->e_flags);
        PRINT_HEADER("e_ehsize:", ehdr->e_ehsize);
        PRINT_HEADER("e_phentsize:", ehdr->e_phentsize);
        PRINT_HEADER("e_phnum:", ehdr->e_phnum);
        PRINT_HEADER("e_shentsize:", ehdr->e_shentsize);
        PRINT_HEADER("e_shentsize:", ehdr->e_shentsize);
        PRINT_HEADER("e_shstrndx:", ehdr->e_shstrndx);

        
        Elf32_Shdr *shdr;
        Elf32_Phdr *phdr;
        Elf32_Shdr shstrtab;

        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        INFO("Section Header Table\n");
        PRINT_SECTION_TITLE("Nr", "Name", "Type", "Addr", "Off", "Size", "Es", "Flg", "Lk", "Inf", "Al");
        for (int i = 0; i < ehdr->e_shnum; i++) {
            name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;

            switch (shdr[i].sh_type) {
                case SHT_NULL:
                    tmp = "SHT_NULL";
                    break;
                
                case SHT_PROGBITS:
                    tmp = "SHT_PROGBITS";
                    break;

                case SHT_SYMTAB:
                    tmp = "SHT_SYMTAB";
                    break;

                case SHT_STRTAB:
                    tmp = "SHT_STRTAB";
                    break;

                case SHT_RELA:
                    tmp = "SHT_RELA";
                    break;

                case SHT_HASH:
                    tmp = "SHT_HASH";
                    break;

                case SHT_DYNAMIC:
                    tmp = "SHT_DYNAMIC";
                    break;

                case SHT_NOTE:
                    tmp = "SHT_NOTE";
                    break;

                case SHT_NOBITS:
                    tmp = "SHT_NOBITS";
                    break;

                case SHT_REL:
                    tmp = "SHT_REL";
                    break;

                case SHT_SHLIB:
                    tmp = "SHT_SHLIB";
                    break;

                case SHT_DYNSYM:
                    tmp = "SHT_DYNSYM";
                    break;

                case SHT_LOPROC:
                    tmp = "SHT_LOPROC";
                    break;

                case SHT_HIPROC:
                    tmp = "SHT_HIPROC";
                    break;

                case SHT_LOUSER:
                    tmp = "SHT_LOUSER";
                    break;

                case SHT_HIUSER:
                    tmp = "SHT_HIUSER";
                    break;
                
                default:
                    break;
            }

            if (strlen(name) > 15) {
                strcpy(&name[15 - 6], "[...]");
            }
            strcpy(flag, "   ");
            flag2str_sh(shdr[i].sh_flags, flag);
            PRINT_SECTION(i, name, tmp, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_entsize,  flag, shdr[i].sh_link, shdr[i].sh_info, shdr[i].sh_addralign)
        }

        INFO("Program Header Table\n");
        PRINT_PROGRAM_TITLE("Nr", "Type", "Offset", "Virtaddr", "Physaddr", "Filesiz", "Memsiz", "Flg", "Align");
        for (int i = 0; i < ehdr->e_phnum; i++) {
            switch (phdr[i].p_type) {
                case PT_NULL:
                    tmp = "PT_NULL";
                    break;
                
                case PT_LOAD:
                    tmp = "PT_LOAD";
                    break;

                case PT_DYNAMIC:
                    tmp = "PT_DYNAMIC";
                    break;

                case PT_INTERP:
                    tmp = "PT_INTERP";
                    break;

                case PT_NOTE:
                    tmp = "PT_NOTE";
                    break;

                case PT_SHLIB:
                    tmp = "PT_SHLIB";
                    break;

                case PT_PHDR:
                    tmp = "PT_PHDR";
                    break;

                case PT_LOPROC:
                    tmp = "PT_LOPROC";
                    break;

                case PT_HIPROC:
                    tmp = "PT_HIPROC";
                    break;

                case PT_GNU_STACK:
                    tmp = "PT_GNU_STACK";
                    break;
                
                default:
                    break;
            }
            strcpy(flag, "   ");
            flag2str(phdr[i].p_flags, flag);
            PRINT_PROGRAM(i, tmp, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, flag, phdr[i].p_align); 
        }

        INFO("Section to segment mapping\n");
        for (int i = 0; i < ehdr->e_phnum; i++) {
            printf("     [%2d]", i);
            for (int j = 0; j < ehdr->e_shnum; j++) {
                name = elf_map + shstrtab.sh_offset + shdr[j].sh_name;
                if (shdr[j].sh_addr >= phdr[i].p_vaddr && shdr[j].sh_addr + shdr[j].sh_size <= phdr[i].p_vaddr + phdr[i].p_memsz && shdr[j].sh_type != SHT_NULL) {
                    if (shdr[j].sh_flags >> 1 & 0x1) {
                        printf(" %s", name);
                    }
                }    
            }
            printf("\n");
        }

        INFO("Dynamic link information\n");
        int dynstr;
        int dynamic;
        Elf32_Dyn *dyn;
        for (int i = 0; i < ehdr->e_shnum; i++) {
            name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(name, ".dynstr")) {
                dynstr = i;
            }
            if (!strcmp(name, ".dynamic")) {
                dynamic = i;
            }
        }

        char value[50];
        name = "";
        dyn = (Elf32_Dyn *)&elf_map[shdr[dynamic].sh_offset];
        count = shdr[dynamic].sh_size / sizeof(Elf32_Dyn);
        INFO("Dynamic section at offset 0x%x contains %d entries\n", shdr[dynamic].sh_offset, count);
        PRINT_DYN_TITLE("Tag", "Type", "Name/Value");
        
        for(int i = 0; i < count; i++) {
            tmp = "";
            memset(value, 0, 50);
            snprintf(value, 50, "0x%x", dyn[i].d_un.d_val);
            switch (dyn[i].d_tag) {
                
                case DT_NULL:
                    tmp = "DT_NULL";
                    break;

                case DT_NEEDED:
                    tmp = "DT_NEEDED";
                    name = elf_map + shdr[dynstr].sh_offset + dyn[i].d_un.d_val;
                    snprintf(value, 50, "Shared library: [%s]", name);
                    break;
                
                case DT_PLTRELSZ:
                    tmp = "DT_PLTRELSZ";
                    break;

                case DT_PLTGOT:
                    tmp = "DT_PLTGOT";
                    break;

                case DT_HASH:
                    tmp = "DT_HASH";
                    break;

                case DT_STRTAB:
                    tmp = "DT_STRTAB";
                    break;

                case DT_SYMTAB:
                    tmp = "DT_SYMTAB";
                    break;

                case DT_RELA:
                    tmp = "DT_RELA";
                    break;

                case DT_RELASZ:
                    tmp = "DT_RELASZ";
                    break;

                case DT_RELAENT:
                    tmp = "DT_RELAENT";
                    break;

                case DT_STRSZ:
                    tmp = "DT_STRSZ";
                    break;

                case DT_SYMENT:
                    tmp = "DT_SYMENT";
                    break;

                case DT_INIT:
                    tmp = "DT_INIT";
                    break;

                case DT_FINI:
                    tmp = "DT_FINI";
                    break;

                case DT_SONAME:
                    tmp = "DT_SONAME";
                    break;

                case DT_RPATH:
                    tmp = "DT_RPATH";
                    break;

                case DT_SYMBOLIC:
                    tmp = "DT_SYMBOLIC";
                    break;

                case DT_REL:
                    tmp = "DT_REL";
                    break;

                case DT_RELSZ:
                    tmp = "DT_RELSZ";
                    break;

                case DT_RELENT:
                    tmp = "DT_RELENT";
                    break;
                    
                case DT_PLTREL:
                    tmp = "DT_PLTREL";
                    break;

                case DT_DEBUG:
                    tmp = "DT_DEBUG";
                    break;

                case DT_TEXTREL:
                    tmp = "DT_TEXTREL";
                    break;

                case DT_JMPREL:
                    tmp = "DT_JMPREL";
                    break;

                case DT_BIND_NOW:
                    tmp = "DT_BIND_NOW";
                    break;

                case DT_INIT_ARRAY:
                    tmp = "DT_INIT_ARRAY";
                    break;

                case DT_FINI_ARRAY:
                    tmp = "DT_FINI_ARRAY";
                    break;

                case DT_INIT_ARRAYSZ:
                    tmp = "DT_INIT_ARRAYSZ";
                    break;
                
                case DT_FINI_ARRAYSZ:
                    tmp = "DT_FINI_ARRAYSZ";
                    break;

                case DT_RUNPATH:
                    tmp = "DT_RUNPATH";
                    break;

                case DT_FLAGS:
                    tmp = "DT_FLAGS";
                    snprintf(value, 50, "Flags: %d", dyn[i].d_un.d_val);
                    break;
                
                case DT_ENCODING:
                    tmp = "DT_ENCODING";
                    break;

                case DT_PREINIT_ARRAYSZ:
                    tmp = "DT_PREINIT_ARRAYSZ";
                    break;

                case DT_SYMTAB_SHNDX:
                    tmp = "DT_SYMTAB_SHNDX";
                    break;
                
                case DT_NUM:
                    tmp = "DT_NUM";
                    break;

                case DT_LOOS:
                    tmp = "DT_LOOS";
                    break;

                case DT_HIOS:
                    tmp = "DT_HIOS";
                    break;

                case DT_LOPROC:
                    tmp = "DT_LOPROC";
                    break;

                case DT_HIPROC:
                    tmp = "DT_HIPROC";
                    break;

                case DT_PROCNUM:
                    tmp = "DT_LOPROC";
                    break;

                

                case DT_VALRNGLO:
                    tmp = "DT_VALRNGLO";
                    break;

                case DT_GNU_PRELINKED:
                    tmp = "DT_GNU_PRELINKED";
                    break;
                
                case DT_GNU_CONFLICTSZ:
                    tmp = "DT_GNU_CONFLICTSZ";
                    break;

                case DT_GNU_LIBLISTSZ:
                    tmp = "DT_GNU_LIBLISTSZ";
                    break;

                case DT_CHECKSUM:
                    tmp = "DT_CHECKSUM";
                    break;

                case DT_PLTPADSZ:
                    tmp = "DT_PLTPADSZ";
                    break;

                case DT_MOVEENT:
                    tmp = "DT_MOVEENT";
                    break;

                case DT_MOVESZ:
                    tmp = "DT_MOVESZ";
                    break;

                case DT_FEATURE_1:
                    tmp = "DT_FEATURE_1";
                    break;

                case DT_POSFLAG_1:
                    tmp = "DT_POSFLAG_1";
                    break;

                case DT_SYMINSZ:
                    tmp = "DT_SYMINSZ";
                    break;

                case DT_SYMINENT:
                    tmp = "DT_SYMINENT";
                    break;

                
                case DT_ADDRRNGLO:
                    tmp = "DT_ADDRRNGLO";
                    break;

                case DT_GNU_HASH:
                    tmp = "DT_GNU_HASH";
                    break;

                case DT_TLSDESC_PLT:
                    tmp = "DT_TLSDESC_PLT";
                    break;

                case DT_TLSDESC_GOT:
                    tmp = "DT_TLSDESC_GOT";
                    break;

                case DT_GNU_CONFLICT:
                    tmp = "DT_GNU_CONFLICT";
                    break;

                case DT_GNU_LIBLIST:
                    tmp = "DT_GNU_LIBLIST";
                    break;

                case DT_CONFIG:
                    tmp = "DT_CONFIG";
                    break;

                case DT_DEPAUDIT:
                    tmp = "DT_DEPAUDIT";
                    break;

                case DT_AUDIT:
                    tmp = "DT_AUDIT";
                    break;

                case DT_PLTPAD:
                    tmp = "DT_PLTPAD";
                    break;

                case DT_MOVETAB:
                    tmp = "DT_MOVETAB";
                    break;

                case DT_SYMINFO:
                    tmp = "DT_SYMINFO";
                    break;
                    
                
                case DT_VERSYM:
                    tmp = "DT_VERSYM";
                    break;

                case DT_RELACOUNT:
                    tmp = "DT_RELACOUNT";
                    break;

                case DT_RELCOUNT:
                    tmp = "DT_RELCOUNT";
                    break;
                
                
                case DT_FLAGS_1:
                    tmp = "DT_FLAGS_1";
                    switch (dyn[i].d_un.d_val) {
                        case DF_1_PIE:
                            snprintf(value, 50, "Flags: %s", "PIE");
                            break;
                        
                        default:
                            snprintf(value, 50, "Flags: %d", dyn[i].d_un.d_val);
                            break;
                    }
                    
                    break;

                case DT_VERDEF:
                    tmp = "DT_VERDEF";
                    break;

                case DT_VERDEFNUM:
                    tmp = "DT_VERDEFNUM";
                    break;

                case DT_VERNEED:
                    tmp = "DT_VERNEED";
                    break;

                case DT_VERNEEDNUM:
                    tmp = "DT_VERNEEDNUM";
                    break;
                
                default:
                    break;
            }
            PRINT_DYN(dyn[i].d_tag, tmp, value);
        }        
    }

    
    if (MODE == ELFCLASS64) {
        
        Elf64_Ehdr *ehdr;
        ehdr = (Elf64_Ehdr *)elf_map;

        INFO("ELF Header\n");        
        switch (ehdr->e_type) {
            case ET_NONE:
                tmp = "An unknown type";
                break;

            case ET_REL:
                tmp = "A relocatable file";
                break;

            case ET_EXEC:
                tmp = "An executable file";
                break;

            case ET_DYN:
                tmp = "A shared object";
                break;

            case ET_CORE:
                tmp = "A core file";
                break;
            
            default:
                tmp = "An unknown type";
                break;
        }
        PRINT_HEADER_EXP("e_type:", ehdr->e_type, tmp);

        switch (ehdr->e_type) {
            case EM_NONE:
                tmp = "An unknown machine";
                break;

            case EM_M32:
                tmp = "AT&T WE 32100";
                break;

            case EM_SPARC:
                tmp = "Sun Microsystems SPARC";
                break;

            case EM_386:
                tmp = "Intel 80386";
                break;

            case EM_68K:
                tmp = "Motorola 68000";
                break;
            
            case EM_88K:
                tmp = "Motorola 88000";
                break;

            case EM_860:
                tmp = "Intel 80860";
                break;

            case EM_MIPS:
                tmp = "MIPS RS3000 (big-endian only)";
                break;

            case EM_PARISC:
                tmp = "HP/PA";
                break;

            case EM_SPARC32PLUS:
                tmp = "SPARC with enhanced instruction set";
                break;
            
            case EM_PPC:
                tmp = "PowerPC";
                break;

            case EM_PPC64:
                tmp = "PowerPC 64-bit";
                break;

            case EM_S390:
                tmp = "IBM S/390";
                break;

            case EM_ARM:
                tmp = "Advanced RISC Machines";
                break;

            case EM_SH:
                tmp = "Renesas SuperH";
                break;
            
            case EM_SPARCV9:
                tmp = "SPARC v9 64-bit";
                break;

            case EM_IA_64:
                tmp = "Intel Itanium";
                break;

            case EM_X86_64:
                tmp = "AMD x86-64";
                break;

            case EM_VAX:
                tmp = "DEC Vax";
                break;
            
            default:
                tmp = "An unknown machine";
                break;
        }
        PRINT_HEADER_EXP("e_machine:", ehdr->e_machine, tmp);

        switch (ehdr->e_version) {
            case EV_NONE:
                tmp = "Invalid version";
                break;

            case EV_CURRENT:
                tmp = "Current version";
                break;

            default:
                tmp = "Known version";
                break;
        }
        PRINT_HEADER_EXP("e_version:", ehdr->e_version, tmp);
        PRINT_HEADER("e_entry:", ehdr->e_entry);
        PRINT_HEADER("e_phoff:", ehdr->e_phoff);
        PRINT_HEADER("e_shoff:", ehdr->e_shoff);
        PRINT_HEADER("e_flags:", ehdr->e_flags);
        PRINT_HEADER("e_ehsize:", ehdr->e_ehsize);
        PRINT_HEADER("e_phentsize:", ehdr->e_phentsize);
        PRINT_HEADER("e_phnum:", ehdr->e_phnum);
        PRINT_HEADER("e_shentsize:", ehdr->e_shentsize);
        PRINT_HEADER("e_shentsize:", ehdr->e_shentsize);
        PRINT_HEADER("e_shstrndx:", ehdr->e_shstrndx);

        
        Elf64_Shdr *shdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr shstrtab;

        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        phdr = (Elf64_Phdr *)&elf_map[ehdr->e_phoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        INFO("Section Header Table\n");
        PRINT_SECTION_TITLE("Nr", "Name", "Type", "Addr", "Off", "Size", "Es", "Flg", "Lk", "Inf", "Al");
        for (int i = 0; i < ehdr->e_shnum; i++) {
            name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;

            switch (shdr[i].sh_type) {
                case SHT_NULL:
                    tmp = "SHT_NULL";
                    break;
                
                case SHT_PROGBITS:
                    tmp = "SHT_PROGBITS";
                    break;

                case SHT_SYMTAB:
                    tmp = "SHT_SYMTAB";
                    break;

                case SHT_STRTAB:
                    tmp = "SHT_STRTAB";
                    break;

                case SHT_RELA:
                    tmp = "SHT_RELA";
                    break;

                case SHT_HASH:
                    tmp = "SHT_HASH";
                    break;

                case SHT_DYNAMIC:
                    tmp = "SHT_DYNAMIC";
                    break;

                case SHT_NOTE:
                    tmp = "SHT_NOTE";
                    break;

                case SHT_NOBITS:
                    tmp = "SHT_NOBITS";
                    break;

                case SHT_REL:
                    tmp = "SHT_REL";
                    break;

                case SHT_SHLIB:
                    tmp = "SHT_SHLIB";
                    break;

                case SHT_DYNSYM:
                    tmp = "SHT_DYNSYM";
                    break;

                case SHT_LOPROC:
                    tmp = "SHT_LOPROC";
                    break;

                case SHT_HIPROC:
                    tmp = "SHT_HIPROC";
                    break;

                case SHT_LOUSER:
                    tmp = "SHT_LOUSER";
                    break;

                case SHT_HIUSER:
                    tmp = "SHT_HIUSER";
                    break;
                
                default:
                    break;
            }

            if (strlen(name) > 15) {
                strcpy(&name[15 - 6], "[...]");
            }
            strcpy(flag, "   ");
            flag2str_sh(shdr[i].sh_flags, flag);
            PRINT_SECTION(i, name, tmp, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_entsize,  flag, shdr[i].sh_link, shdr[i].sh_info, shdr[i].sh_addralign)
        }

        INFO("Program Header Table\n");
        PRINT_PROGRAM_TITLE("Nr", "Type", "Offset", "Virtaddr", "Physaddr", "Filesiz", "Memsiz", "Flg", "Align");
        for (int i = 0; i < ehdr->e_phnum; i++) {
            switch (phdr[i].p_type) {
                case PT_NULL:
                    tmp = "PT_NULL";
                    break;
                
                case PT_LOAD:
                    tmp = "PT_LOAD";
                    break;

                case PT_DYNAMIC:
                    tmp = "PT_DYNAMIC";
                    break;

                case PT_INTERP:
                    tmp = "PT_INTERP";
                    break;

                case PT_NOTE:
                    tmp = "PT_NOTE";
                    break;

                case PT_SHLIB:
                    tmp = "PT_SHLIB";
                    break;

                case PT_PHDR:
                    tmp = "PT_PHDR";
                    break;

                case PT_LOPROC:
                    tmp = "PT_LOPROC";
                    break;

                case PT_HIPROC:
                    tmp = "PT_HIPROC";
                    break;

                case PT_GNU_STACK:
                    tmp = "PT_GNU_STACK";
                    break;
                
                default:
                    break;
            }
            strcpy(flag, "   ");
            flag2str(phdr[i].p_flags, flag);
            PRINT_PROGRAM(i, tmp, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, flag, phdr[i].p_align); 
        }

        INFO("Section to segment mapping\n");
        for (int i = 0; i < ehdr->e_phnum; i++) {
            printf("     [%2d]", i);
            for (int j = 0; j < ehdr->e_shnum; j++) {
                name = elf_map + shstrtab.sh_offset + shdr[j].sh_name;
                if (shdr[j].sh_addr >= phdr[i].p_vaddr && shdr[j].sh_addr + shdr[j].sh_size <= phdr[i].p_vaddr + phdr[i].p_memsz && shdr[j].sh_type != SHT_NULL) {
                    if (shdr[j].sh_flags >> 1 & 0x1) {
                        printf(" %s", name);
                    }
                }    
            }
            printf("\n");
        }

        INFO("Dynamic link information\n");
        int dynstr;
        int dynamic;
        Elf64_Dyn *dyn;
        for (int i = 0; i < ehdr->e_shnum; i++) {
            name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(name, ".dynstr")) {
                dynstr = i;
            }
            if (!strcmp(name, ".dynamic")) {
                dynamic = i;
            }
        }

        char value[50];
        name = "";
        dyn = (Elf64_Dyn *)&elf_map[shdr[dynamic].sh_offset];
        count = shdr[dynamic].sh_size / sizeof(Elf64_Dyn);
        INFO("Dynamic section at offset 0x%x contains %d entries\n", shdr[dynamic].sh_offset, count);
        PRINT_DYN_TITLE("Tag", "Type", "Name/Value");
        
        for(int i = 0; i < count; i++) {
            tmp = "";
            memset(value, 0, 50);
            snprintf(value, 50, "0x%x", dyn[i].d_un.d_val);
            switch (dyn[i].d_tag) {
                
                case DT_NULL:
                    tmp = "DT_NULL";
                    break;

                case DT_NEEDED:
                    tmp = "DT_NEEDED";
                    name = elf_map + shdr[dynstr].sh_offset + dyn[i].d_un.d_val;
                    snprintf(value, 50, "Shared library: [%s]", name);
                    break;
                
                case DT_PLTRELSZ:
                    tmp = "DT_PLTRELSZ";
                    break;

                case DT_PLTGOT:
                    tmp = "DT_PLTGOT";
                    break;

                case DT_HASH:
                    tmp = "DT_HASH";
                    break;

                case DT_STRTAB:
                    tmp = "DT_STRTAB";
                    break;

                case DT_SYMTAB:
                    tmp = "DT_SYMTAB";
                    break;

                case DT_RELA:
                    tmp = "DT_RELA";
                    break;

                case DT_RELASZ:
                    tmp = "DT_RELASZ";
                    break;

                case DT_RELAENT:
                    tmp = "DT_RELAENT";
                    break;

                case DT_STRSZ:
                    tmp = "DT_STRSZ";
                    break;

                case DT_SYMENT:
                    tmp = "DT_SYMENT";
                    break;

                case DT_INIT:
                    tmp = "DT_INIT";
                    break;

                case DT_FINI:
                    tmp = "DT_FINI";
                    break;

                case DT_SONAME:
                    tmp = "DT_SONAME";
                    break;

                case DT_RPATH:
                    tmp = "DT_RPATH";
                    break;

                case DT_SYMBOLIC:
                    tmp = "DT_SYMBOLIC";
                    break;

                case DT_REL:
                    tmp = "DT_REL";
                    break;

                case DT_RELSZ:
                    tmp = "DT_RELSZ";
                    break;

                case DT_RELENT:
                    tmp = "DT_RELENT";
                    break;
                    
                case DT_PLTREL:
                    tmp = "DT_PLTREL";
                    break;

                case DT_DEBUG:
                    tmp = "DT_DEBUG";
                    break;

                case DT_TEXTREL:
                    tmp = "DT_TEXTREL";
                    break;

                case DT_JMPREL:
                    tmp = "DT_JMPREL";
                    break;

                case DT_BIND_NOW:
                    tmp = "DT_BIND_NOW";
                    break;

                case DT_INIT_ARRAY:
                    tmp = "DT_INIT_ARRAY";
                    break;

                case DT_FINI_ARRAY:
                    tmp = "DT_FINI_ARRAY";
                    break;

                case DT_INIT_ARRAYSZ:
                    tmp = "DT_INIT_ARRAYSZ";
                    break;
                
                case DT_FINI_ARRAYSZ:
                    tmp = "DT_FINI_ARRAYSZ";
                    break;

                case DT_RUNPATH:
                    tmp = "DT_RUNPATH";
                    break;

                case DT_FLAGS:
                    tmp = "DT_FLAGS";
                    snprintf(value, 50, "Flags: %d", dyn[i].d_un.d_val);
                    break;
                
                case DT_ENCODING:
                    tmp = "DT_ENCODING";
                    break;

                case DT_PREINIT_ARRAYSZ:
                    tmp = "DT_PREINIT_ARRAYSZ";
                    break;

                case DT_SYMTAB_SHNDX:
                    tmp = "DT_SYMTAB_SHNDX";
                    break;
                
                case DT_NUM:
                    tmp = "DT_NUM";
                    break;

                case DT_LOOS:
                    tmp = "DT_LOOS";
                    break;

                case DT_HIOS:
                    tmp = "DT_HIOS";
                    break;

                case DT_LOPROC:
                    tmp = "DT_LOPROC";
                    break;

                case DT_HIPROC:
                    tmp = "DT_HIPROC";
                    break;

                case DT_PROCNUM:
                    tmp = "DT_LOPROC";
                    break;

                

                case DT_VALRNGLO:
                    tmp = "DT_VALRNGLO";
                    break;

                case DT_GNU_PRELINKED:
                    tmp = "DT_GNU_PRELINKED";
                    break;
                
                case DT_GNU_CONFLICTSZ:
                    tmp = "DT_GNU_CONFLICTSZ";
                    break;

                case DT_GNU_LIBLISTSZ:
                    tmp = "DT_GNU_LIBLISTSZ";
                    break;

                case DT_CHECKSUM:
                    tmp = "DT_CHECKSUM";
                    break;

                case DT_PLTPADSZ:
                    tmp = "DT_PLTPADSZ";
                    break;

                case DT_MOVEENT:
                    tmp = "DT_MOVEENT";
                    break;

                case DT_MOVESZ:
                    tmp = "DT_MOVESZ";
                    break;

                case DT_FEATURE_1:
                    tmp = "DT_FEATURE_1";
                    break;

                case DT_POSFLAG_1:
                    tmp = "DT_POSFLAG_1";
                    break;

                case DT_SYMINSZ:
                    tmp = "DT_SYMINSZ";
                    break;

                case DT_SYMINENT:
                    tmp = "DT_SYMINENT";
                    break;

                
                case DT_ADDRRNGLO:
                    tmp = "DT_ADDRRNGLO";
                    break;

                case DT_GNU_HASH:
                    tmp = "DT_GNU_HASH";
                    break;

                case DT_TLSDESC_PLT:
                    tmp = "DT_TLSDESC_PLT";
                    break;

                case DT_TLSDESC_GOT:
                    tmp = "DT_TLSDESC_GOT";
                    break;

                case DT_GNU_CONFLICT:
                    tmp = "DT_GNU_CONFLICT";
                    break;

                case DT_GNU_LIBLIST:
                    tmp = "DT_GNU_LIBLIST";
                    break;

                case DT_CONFIG:
                    tmp = "DT_CONFIG";
                    break;

                case DT_DEPAUDIT:
                    tmp = "DT_DEPAUDIT";
                    break;

                case DT_AUDIT:
                    tmp = "DT_AUDIT";
                    break;

                case DT_PLTPAD:
                    tmp = "DT_PLTPAD";
                    break;

                case DT_MOVETAB:
                    tmp = "DT_MOVETAB";
                    break;

                case DT_SYMINFO:
                    tmp = "DT_SYMINFO";
                    break;
                    
                
                case DT_VERSYM:
                    tmp = "DT_VERSYM";
                    break;

                case DT_RELACOUNT:
                    tmp = "DT_RELACOUNT";
                    break;

                case DT_RELCOUNT:
                    tmp = "DT_RELCOUNT";
                    break;
                
                
                case DT_FLAGS_1:
                    tmp = "DT_FLAGS_1";
                    switch (dyn[i].d_un.d_val) {
                        case DF_1_PIE:
                            snprintf(value, 50, "Flags: %s", "PIE");
                            break;
                        
                        default:
                            snprintf(value, 50, "Flags: %d", dyn[i].d_un.d_val);
                            break;
                    }
                    
                    break;

                case DT_VERDEF:
                    tmp = "DT_VERDEF";
                    break;

                case DT_VERDEFNUM:
                    tmp = "DT_VERDEFNUM";
                    break;

                case DT_VERNEED:
                    tmp = "DT_VERNEED";
                    break;

                case DT_VERNEEDNUM:
                    tmp = "DT_VERNEEDNUM";
                    break;
                
                default:
                    break;
            }
            PRINT_DYN(dyn[i].d_tag, tmp, value);
        }        
    }

    return 0;
}