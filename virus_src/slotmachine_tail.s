morph_tbl_end:
    .int 0
virend:

// ELF Header
    .struct 0
e_ident:
    .struct e_ident + 16
e_type:
    .struct e_type + 2
e_machine:
    .struct e_machine + 2
e_version:
    .struct e_version + 4
e_entry:
    .struct e_entry + 8
e_phoff:
    .struct e_phoff + 8
e_shoff:
    .struct e_shoff + 8
e_flags:
    .struct e_flags + 4
e_ehsize:
    .struct e_ehsize + 2
e_phentsize:
    .struct e_phentsize + 2
e_phnum:
    .struct e_phnum + 2
e_shentsize:
    .struct e_shentsize + 2
e_shnum:
    .struct e_shnum + 2
e_shstrndx:

// PHDR
    .struct 0
p_type:
    .struct p_type + 4
p_flags:
    .struct p_flags + 4
p_offset:
    .struct p_offset + 8
p_vaddr:
    .struct p_vaddr + 8
p_paddr:
    .struct p_paddr + 8
p_filesz:
    .struct p_filesz + 8
p_memsz:
    .struct p_memsz + 8
p_align:

// dirent64
    .struct 0
d_ino:
    .struct d_ino + 8
d_off:
    .struct d_off + 8
d_reclen:
    .struct d_reclen + 2
d_type:
    .struct d_type + 1
d_name:
