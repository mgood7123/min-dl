char ** argv;
#if __PIC__ == 0
// compiled without -fpic or -fPIC
#warning recompile this with the flag -fpic or -fPIC to enable compiling this as a shared library

int
readelf_(const char * filename);
int main() {
    readelf_(argv[0]);
}
#else
// compiled with -fpic or -fPIC
const char * global_quiet = "no";
const char * symbol_quiet = "yes";
const char * relocation_quiet = "yes";
const char * analysis_quiet = "no";
#define quiet symbol_quiet

// define all headers first

#include <elf.h>
#include <libiberty/libiberty.h>
#include <libiberty/demangle.h>
#include <libiberty/safe-ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <ucontext.h>
#include <setjmp.h>
#include <errno.h>
extern int errno;
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>


// need to add every needed declaration into this struct

int library_index = 0; // must be global
struct lib
{
    int init_lock;
    char * struct_init;
    char * library_name;
    char ** NEEDED;
    char library_first_character;
    char * library_len;
    char * library_symbol;
    uintptr_t mappingb;
    Elf64_Ehdr * _elf_header;
    Elf64_Phdr * _elf_program_header;
    Elf64_Shdr * _elf_symbol_table;
    char *strtab;
    size_t len;
    char * array;
    char * current_lib;
    char * last_lib;
    int is_mapped;
    size_t align;
    Elf64_Addr base_address;
    Elf64_Addr mappingb_end;
    int init__;
    int PT_DYNAMIC_;
    char * tmp99D;
    Elf64_Dyn * dynamic;
    int First_Load_Header_index;
    int Last_Load_Header_index;
    size_t RELA_PLT_SIZE;
    int _R_X86_64_NONE;
    int _R_X86_64_64;
    int _R_X86_64_PC32;
    int _R_X86_64_GOT32;
    int _R_X86_64_PLT32;
    int _R_X86_64_COPY;
    int _R_X86_64_GLOB_DAT;
    int _R_X86_64_JUMP_SLOT;
    int _R_X86_64_RELATIVE;
    int _R_X86_64_GOTPCREL;
    int _R_X86_64_32;
    int _R_X86_64_32S;
    int _R_X86_64_16;
    int _R_X86_64_PC16;
    int _R_X86_64_8;
    int _R_X86_64_PC8;
    int _R_X86_64_DTPMOD64;
    int _R_X86_64_DTPOFF64;
    int _R_X86_64_TPOFF64;
    int _R_X86_64_TLSGD;
    int _R_X86_64_TLSLD;
    int _R_X86_64_DTPOFF32;
    int _R_X86_64_GOTTPOFF;
    int _R_X86_64_TPOFF32;
    int _R_X86_64_PC64;
    int _R_X86_64_GOTOFF64;
    int _R_X86_64_GOTPC32;
    int _R_X86_64_GOT64;
    int _R_X86_64_GOTPCREL64;
    int _R_X86_64_GOTPC64;
    int _Deprecated1;
    int _R_X86_64_PLTOFF64;
    int _R_X86_64_SIZE32;
    int _R_X86_64_SIZE64;
    int _R_X86_64_GOTPC32_TLSDESC;
    int _R_X86_64_TLSDESC_CALL;
    int _R_X86_64_TLSDESC;
    int _R_X86_64_IRELATIVE;
    int _R_X86_64_RELATIVE64;
    int _Deprecated2;
    int _Deprecated3;
    int _R_X86_64_GOTPLT64;
    int _R_X86_64_GOTPCRELX;
    int _R_X86_64_REX_GOTPCRELX;
    int _R_X86_64_NUM;
    int _R_X86_64_UNKNOWN;
    Elf64_Addr * GOT;
    Elf64_Addr * GOT2;
    Elf64_Addr * PLT;
} library[512];

int
init_struct() {
    library[library_index].struct_init = "initialized";
    library[library_index].library_name;
    library[library_index].NEEDED = malloc(sizeof(library[library_index].NEEDED));
    library[library_index].library_first_character;
    library[library_index].library_len;
    library[library_index].library_symbol;
    library[library_index].mappingb;
    library[library_index]._elf_header;
    library[library_index]._elf_program_header;
    library[library_index]._elf_symbol_table;
    library[library_index].strtab = NULL;
    library[library_index].len;
    library[library_index].array;
    library[library_index].current_lib = "NULL";
    library[library_index].last_lib = "NULL";
    library[library_index].is_mapped = 0;
    library[library_index].align;
    library[library_index].base_address = 0x00000000;
    library[library_index].mappingb_end = 0x00000000;
    library[library_index].init__ = 0;
    library[library_index].PT_DYNAMIC_ = NULL;
    library[library_index].tmp99D;
    library[library_index].First_Load_Header_index = NULL;
    library[library_index].Last_Load_Header_index = NULL;
    library[library_index].RELA_PLT_SIZE = 0;
    library[library_index]._R_X86_64_NONE = 0;
    library[library_index]._R_X86_64_64 = 0;
    library[library_index]._R_X86_64_PC32 = 0;
    library[library_index]._R_X86_64_GOT32 = 0;
    library[library_index]._R_X86_64_PLT32 = 0;
    library[library_index]._R_X86_64_COPY = 0;
    library[library_index]._R_X86_64_GLOB_DAT = 0;
    library[library_index]._R_X86_64_JUMP_SLOT = 0;
    library[library_index]._R_X86_64_RELATIVE = 0;
    library[library_index]._R_X86_64_GOTPCREL = 0;
    library[library_index]._R_X86_64_32 = 0;
    library[library_index]._R_X86_64_32S = 0;
    library[library_index]._R_X86_64_16 = 0;
    library[library_index]._R_X86_64_PC16 = 0;
    library[library_index]._R_X86_64_8 = 0;
    library[library_index]._R_X86_64_PC8 = 0;
    library[library_index]._R_X86_64_DTPMOD64 = 0;
    library[library_index]._R_X86_64_DTPOFF64 = 0;
    library[library_index]._R_X86_64_TPOFF64 = 0;
    library[library_index]._R_X86_64_TLSGD = 0;
    library[library_index]._R_X86_64_TLSLD = 0;
    library[library_index]._R_X86_64_DTPOFF32 = 0;
    library[library_index]._R_X86_64_GOTTPOFF = 0;
    library[library_index]._R_X86_64_TPOFF32 = 0;
    library[library_index]._R_X86_64_PC64 = 0;
    library[library_index]._R_X86_64_GOTOFF64 = 0;
    library[library_index]._R_X86_64_GOTPC32 = 0;
    library[library_index]._R_X86_64_GOT64 = 0;
    library[library_index]._R_X86_64_GOTPCREL64 = 0;
    library[library_index]._R_X86_64_GOTPC64 = 0;
    library[library_index]._Deprecated1 = 0;
    library[library_index]._R_X86_64_PLTOFF64 = 0;
    library[library_index]._R_X86_64_SIZE32 = 0;
    library[library_index]._R_X86_64_SIZE64 = 0;
    library[library_index]._R_X86_64_GOTPC32_TLSDESC = 0;
    library[library_index]._R_X86_64_TLSDESC_CALL = 0;
    library[library_index]._R_X86_64_TLSDESC = 0;
    library[library_index]._R_X86_64_IRELATIVE = 0;
    library[library_index]._R_X86_64_RELATIVE64 = 0;
    library[library_index]._Deprecated2 = 0;
    library[library_index]._Deprecated3 = 0;
    library[library_index]._R_X86_64_GOTPLT64 = 0;
    library[library_index]._R_X86_64_GOTPCRELX = 0;
    library[library_index]._R_X86_64_REX_GOTPCRELX = 0;
    library[library_index]._R_X86_64_NUM = 0;
    library[library_index]._R_X86_64_UNKNOWN = 0;
    library[library_index].GOT = NULL;
    library[library_index].GOT2 = NULL;
    library[library_index].PLT = NULL;
}

// bytecmp compares two strings char by char for an EXACT full string match, returns -1 if strings differ in length or do not match but are of same length

int bcmp_q(void const *vp, size_t n, void const *vp2, size_t n2)
{
    int string_match = 0;
    if (n == n2) {
        unsigned char const *p = vp;
        unsigned char const *p2 = vp2;
        for (size_t i=0; i<n; i++)
            if (p[i] == p2[i]) {
                string_match = 1;
            } else { string_match = 0; break; }
        if (string_match == 0) {
            return -1;
        } else return 0;
    } else
    {
        return -1;
    }
}


int bytecmpq(void const * p, void const * pp) { return bcmp_q(p, strlen(p), pp, strlen(pp)); }

int bcmp_(void const *vp, size_t n, void const *vp2, size_t n2)
{
    int string_match = 0;
    fprintf(stderr, "n = %d\nn2 = %d\n", n, n2);
    if (n == n2) {
        unsigned char const *p = vp;
        unsigned char const *p2 = vp2;
        for (size_t i=0; i<n; i++)
            if (p[i] == p2[i]) {
                fprintf(stderr, "p[%d] = %c\n", i, p[i]);
                string_match = 1;
            } else { string_match = 0; break; }
        if (string_match == 0) {
            fprintf(stderr, "ERROR: strings do not match\n");
            return -1;
        } else {
            fprintf(stderr, "returning 0\n");
            return 0;
        }
    } else
    {
        fprintf(stderr, "ERROR: different length string comparision, might want to use strcmp instead\n");
        return -1;
    }
}

int bytecmp(void const * p, void const * pp) { return bcmp_(p, strlen(p), pp, strlen(pp)); }
int i = 0;
int main_() {
//     sleep(0.9);
//     for (int i = 0; i<=4096; i++) {
        char lib1[4096] = "/lib/";
        fprintf(stderr, "i = %d\n", i);
        fprintf(stderr, "test      = %s\ntest      = %014p\n", lib1, lib1);
        fprintf(stderr, "T[0].test = %s\nT[0].test = %014p\n", library[library_index].last_lib, library[library_index].last_lib);
        if (bytecmpq(lib1, library[library_index].last_lib) == 0) exit(-1);
//     }
    i++;
    main_();
}
init() {
    library_index = 0;
    init_struct();
    library[0].last_lib = "/opt/";

    library_index = 1;
    init_struct();
    library[library_index].last_lib = "/opt/";
    library_index = 2;
    init_struct();
    library[library_index].last_lib = "/opt/";
    library_index = 3;
    init_struct();
    library[library_index].last_lib = "/opt/";

// library[3].last_lib = 0x7ffec4b80b90
// lib1                = 0x7ffec4b7caa0
}

int
readelf_(const char * filename) {}
#endif
