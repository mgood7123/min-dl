// PC DEAD, WAITING FOR A NEW LAPTOP

// could a C++ template reduce for example, a 1k LOC files with say 500 lines of the same code but slightly different, with the 500 lines consisting of 25 blocks of code and each block is 20 lines, with the only changes in each block is say filenames and variable names, to only a 500 LOC file with only 1 block but still be as if there are 25 blocks *

/*

git clone https://github.com/mgood7123/min-dl-dynamic-loader.git
cd min-dl-dynamic-loader/loader
git checkout -b test_branch f74e804a974b27e02033ea97a6ab19ff7692194c
./make_loader

should end up with example1: readelf_.c:2487: get_needed: Assertion `bytecmpq(lib_now, library[3].last_lib) == 0' failed. )

*/
    /*

    printf resolution:
    
    initialization:
    in during relocation JMP_SLOT relocations are preformed, which write directly to the GOT, in this case "printf" is translated directly to "puts" at compile time
    ->
    R_X86_64_JUMP_SLOT           calculation: S (symbol value)
    library[library_index].mappingb    = 0x7ffff0000000
    reloc->r_offset = 0x7ffff0000000+0x000000201018=0x7ffff0201018
    attempting to look up symbol, index = 2
    looking up index 2 of table 3
    requested symbol name for index 2 is puts
    symbol = 0 (         (nil))
    0x7ffff0201018 = 0x7ffff0000000

    in gdb tracing/examining the calls:
    callq  540 <puts@plt>
    ->
    jmpq   *0x200ad2(%rip)        # 201018 <puts@GLIBC_2.2.5>
    ->
    retrieves the _GLOBAL_OFFSET_TABLE_ as an array called GOT
    
    address of GOT[3] = 0x7ffff0000000
    (
        pwndbg> x /g 0x7ffff0201000+0x8+0x10
        0x7ffff0201018: 0x00007ffff0000000
    )
    ->
    jumps to 0x00007ffff0000000 wich is incorrect as it is not the location of printf
    
    ► 0x7ffff0000540    jmp    qword ptr [rip + 0x200ad2] // callq  540 <puts@plt>
        ↓
    0x7ffff0000000    jg     0x7ffff0000047
    
    
    since the jump can be modified we can make it jump to whatever we like wich would be bad in normal cases but usefull in specific cases, but for now we will try to make it jump to the actual location of puts in the libc library
    
    "ld.so takes the first symbol it finds"

    */
char ** argv;
#ifndef __SHARED__
// compiled without -fpic or -fPIC
#warning recompile this with the flag -D__SHARED__ to enable compiling this as a shared library

int
readelf_(const char * filename);
int main() {
    readelf_(argv[1]);
}
#else
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
#include "../../CCR/Scripts/Shell/builtins/printfmacro.h"
#include "../../CCR/Scripts/Shell/builtins/env.h"
// compiled with -fpic or -fPIC

void *
dlopen(const char * cc);

int self = 0;
int readelf = 0;

#define char_n "no"
#define char_y "yes"

const char * sleep_ = 			char_n; // no | yes
const char * sleep_r = 			char_n; // no | yes

const char * GQ = 				char_y; // no | yes
const char * symbol_quiet = 	char_y; // no | yes
const char * relocation_quiet = char_y; // no | yes
const char * analysis_quiet = 	char_y; // no | yes
const char * ldd_quiet = 		char_y; // no | yes

const int do_tests = 0; // tests are REQUIRED to be done, cannot be skipped
const produce_backtrace = false;


// need to add every needed declaration into this struct

int library_index = 0; // must be global
#include "lib.h"
int
init_needed_struct() {
    library[library_index].struct_needed_init = "initialized";
    library[library_index].parent = "-1";
    library[library_index].NEEDED = malloc(sizeof(library[library_index].NEEDED));
    library[library_index].current_lib = "NULL";
    library[library_index].last_lib = "NULL";
}
int
init_struct() {
    library[library_index].struct_init = "initialized";
    library[library_index].Resolve_Index[0] = 0;
    library[library_index].Resolved = malloc(sizeof(library[library_index].Resolved));
    library[library_index].Resolved[0] = "NULL";
    library[library_index].library_name;
    library[library_index].library_first_character;
    library[library_index].library_len;
    library[library_index].library_symbol;
    library[library_index].mappingb;
    library[library_index]._elf_header;
    library[library_index]._elf_program_header;
    library[library_index]._elf_symbol_table;
    library[library_index].strtab = NULL;
    if (library[library_index].current_lib == NULL && library[library_index].last_lib == NULL) {
        library[library_index].current_lib = "NULL";
        library[library_index].last_lib = "NULL";
    }
    library[library_index].len;
    library[library_index].array;
    library[library_index].is_mapped = 0;
    library[library_index].align;
    library[library_index].base_address = 0x00000000;
    library[library_index].mappingb_end = 0x00000000;
    library[library_index].init__ = 0;
    library[library_index].PT_DYNAMIC_ = NULL;
    library[library_index].interp = "";
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

int init_(const char * filename);
int initv_(const char * filename);

void * lookup_symbol_by_name_(const char * lib, const char * name);
// for C++ symbol name demangling should libirty become incompatible
// http://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling
// https://itanium-cxx-abi.github.io/cxx-abi/gcc-cxxabi.h
// https://github.com/xaxxon/xl/blob/master/include/xl/demangle.h
// gdb and c++filt use demangler provided by libiberty

// allow for demangling of C++ symbols, link with -liberty
int flags = DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE;
int strip_underscore = 0;
char * demangle_it (char *mangled_name)
{
char *result;
unsigned int skip_first = 0;

/* _ and $ are sometimes found at the start of function names
    in assembler sources in order to distinguish them from other
    names (eg register names).  So skip them here.  */
if (mangled_name[0] == '.' || mangled_name[0] == '$')
    ++skip_first;
if (strip_underscore && mangled_name[skip_first] == '_')
    ++skip_first;

result = cplus_demangle (mangled_name + skip_first, flags);
//   bytecmpq(mangled_name, mangled_name);
//   mangled_name[strlen(mangled_name)-2] = '\0';
int len = strlen(mangled_name);
//   for (int i = 0; i=len-2; i++)
//   if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "trimming %s", mangled_name);
if (result == NULL) return mangled_name;
else {
    if ( result[strlen(result)-2] == '(' && result[strlen(result)-1] == ')' ) result[strlen(result)-2] = '\0';
    if (mangled_name[0] == '.') return strjoin_(".", result); else return result;
}
}

char * __print_quoted_string__(const char *str, unsigned int size, const unsigned int style, const char * return_type);
#define _GNU_SOURCE
#define __USE_GNU

// ELF Spec     FULL:  http://refspecs.linuxbase.org/elf/elf.pdf
// ELF Spec ABI FULL:  https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf


//sig handling
jmp_buf restore_point;
struct sigaction sa;
void Handler(int sig, siginfo_t *si, ucontext_t *context)
{
    if (sig == SIGSEGV)
    {
        void * h = &Handler;
        signal(SIGSEGV, h);
        longjmp(restore_point, SIGSEGV);
    }
}
void
init_handler() {
    sa.sa_flags = SA_SIGINFO|SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = Handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        perror("failed to set handler");
}

int test(char * address)
{
    if (do_tests == 1) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "TESTS DISABLED");
        return -1;
    }
    init_handler();
    int fault_code = setjmp(restore_point);
    if (fault_code == 0)
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "value: %15d\t", *(int*)address);
        return 0;
    }
    else
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "value: %s\t", "     is not int");
        return -1;
    }
}

int pointers=0;

int is_pointer_valid(void *p) {
    int page_size = getpagesize();                                            
    void *aligned = (void *)((uintptr_t)p & ~(page_size - 1));           
    if (msync(aligned, page_size, MS_ASYNC) == -1) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Seg faulted, restoring\n");
        longjmp(restore_point, -1);
    }
    return 0;
}

int test_address(char ** addr)
{
    if (do_tests == 1) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "TESTS DISABLED");
        return -1;
    }
    init_handler();
    int fault_code = setjmp(restore_point);
    if (fault_code == 0)
    {
        is_pointer_valid(addr);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "TEST ADDRESS %014p = %014p\n", addr, *addr);
        if (produce_backtrace == true) bt();
        pointers++;
        return 0;
    }
    else
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "TEST ADDRESS %014p = %s\n", addr, "INVALID");
        pointers--;
        return -1;
    }
}

int test_string(char * addr)
{
    if (do_tests == 1) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "TESTS DISABLED");
        return -1;
    }
    init_handler();
    int fault_code = setjmp(restore_point);
    if (fault_code == 0)
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s", addr);
        for (int i = 0; i <= strlen(addr); i++)  if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\b");
        return 0;
    }
    else
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "INVALID");
        for (int i = 0; i <= strlen("INVALID"); i++)  if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\b");

        return -1;
    }
}

char * analyse_address(char ** addr, char * name)
{
    if (do_tests == 1) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "CANNOT ALALYSE: TESTS DISABLED");
        return addr;
    }
    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(analysis_quiet, char_n) == 0) fprintf(stderr, "analysing address %014p\n", addr);
    char ** addr_original = addr;
    pointers = 0;
    while( test_address(addr) == 0) addr = *addr;

    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(analysis_quiet, char_n) == 0) fprintf(stderr, "pointers: %d\n", pointers);

    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(analysis_quiet, char_n) == 0) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "data ");
        for (int i = 1; i<=pointers; i++) fprintf(stderr, "*");
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " %s\n", name);
    }
    if (pointers == 0)
    {
        pointers = 0;
        if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(analysis_quiet, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, addr_original);
        return addr_original;
    }
    else 
    {
        pointers = 0;
        if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(analysis_quiet, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, *addr_original);
        return *addr_original;
    }
}

int testh(char * address)
{
    init_handler();
    int fault_code = setjmp(restore_point);
    if (fault_code == 0)
    {
        /*
        if this seg faults in gdb, pass "handle SIGSEGV nostop pass noprint" to gdb command line to allow the hander init_handler() to handle this instead of gdb:
        (gdb) handle SIGSEGV nostop pass noprint
        <enter>
        (gdb) r
        <enter>
        
        if u use pwndbg the instructions are the same:
        pwndbg> handle SIGSEGV nostop pass noprint
        <enter>
        pwndbg> r
        <enter>
            
        alternatively start gdb like this (this assumes this is run inside a script and the executable this is compiled into is named ./loader and compiled with  test_loader.c containing a
        main() { 
            ... ;
            return 0;
        }
        with return 0; being on line 22, note the ... signifies a variable amount of text as we do not know what code main() {} can contain) :

        gdb ./loader -ex "set args $1" -ex "break test_loader.c:22" -ex "handle SIGSEGV nostop pass noprint" -ex "r"

        else this works fine:

        gdb <file> -ex "handle SIGSEGV nostop pass noprint" -ex "r"


        */
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "value: %15x\t", *(int*)address);
        return 0;
    }
    else
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "value: %s\t", "     is not hex");
        return -1;
    }
}

#define QUOTE_0_TERMINATED			0x01
#define QUOTE_OMIT_LEADING_TRAILING_QUOTES	0x02
#define QUOTE_OMIT_TRAILING_0			0x08
#define QUOTE_FORCE_HEX				0x10
#define QUOTE_FORCE_HEXOLD				9998
#define QUOTE_FORCE_LEN				9999
#define error_msg printf
int search(const char * lib) {
    // need to be smarter
    int i = 0;
    while(1)
    {
        if (library[i].struct_init == "initialized") {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "current index %d holds \"%s\"\n", i, library[i].last_lib);
            if ( bytecmpq(lib, library[i].last_lib) == -1 && bytecmpq("NULL", library[i].last_lib) == -1 ) i++;
            else if ( bytecmpq("NULL", library[i].last_lib) == -1 )
                {
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "index %d holds desired library \"%s\"\n", i, lib); // bugs
                    break;
                }
            else {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "attempting to save to index %d\n", i);
                break;
            }
        } else {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "WARNING: index %d is %s\n", i, library[i].struct_init);
            break;
        }
    }
    return i;
}

int search_resolved(const char * symbol) {
    // need to be smarter
    int i = 0;
    while(1)
    {
        if (library[i].struct_init == "initialized") {
            for (int ii = 0; ii <= library[i].Resolve_Index[0]; ii++)
            {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "current index %d of %s holds (%d) \"%s\"\n", ii, library[i].last_lib, library[i].Resolve_Index[0], library[i].Resolved[ii]);
                if ( bytecmpq(symbol, library[i].Resolved[ii]) == 0 )
                    {
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "index %d of (%d) %s holds desired symbol \"%s\"\n", ii, library[i].Resolve_Index[0], library[i].last_lib, symbol);
                        return 0;
                    }
            }
            i++;
        } else {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "WARNING: index %d is %s\n", i, library[i].struct_init);
            break;
        }
    }
    return -1;
}

int searchq(const char * lib) {
    // need to be smarter
    int i = 0;
    while(1)
    {
        if (library[i].struct_init == "initialized") {
			if ( bytecmpq(lib, library[i].last_lib) == 0) break;
            else if ( bytecmpq("NULL", library[i].last_lib) != 0 ) i++;
            else if ( bytecmpq("NULL", library[i].last_lib) == 0 ) return -1;
        } else {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "WARNING: index %d is %s\n", i, library[i].struct_init);
            return -1;
        }
    }
    return i;
}

int search_neededq(const char * lib) {
    // need to be smarter
    int i = 0;
    while(1)
    {
        if (library[i].struct_needed_init == "initialized") {
			if ( bytecmpq(lib, library[i].last_lib) == 0) break;
            else if ( bytecmpq("NULL", library[i].last_lib) != 0 ) i++;
            else if ( bytecmpq("NULL", library[i].last_lib) == 0 ) return -1;
        } else {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "WARNING: index %d is %s\n", i, library[i].struct_needed_init);
            return -1;
        }
    }
    return i;
}

void check_init(void) {
    if (library[library_index].struct_init == NULL) init_struct();
	else if (strcmp(library[library_index].struct_init,"initialized") != 0) init_struct();
    if (library[library_index].struct_init == NULL) abort_();
	else if (strcmp(library[library_index].struct_init,"initialized") != 0) abort_();
}

void check_init_needed(void) {
    if (library[library_index].struct_needed_init == NULL) init_needed_struct();
	else if (strcmp(library[library_index].struct_needed_init,"initialized") != 0) init_needed_struct();
    if (library[library_index].struct_needed_init == NULL) abort_();
	else if (strcmp(library[library_index].struct_needed_init,"initialized") != 0) abort_();
}

int init(char * lib) {
	puts("INIT_ CALLED");
// 	sleep (5);
	ps(lib);
	check_init();
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "current index %d holds \"%s\"\nsearching indexes for \"%s\" incase it has already been loaded\n", library_index, library[library_index].last_lib, lib);
    
    int index = searchq(lib);
	if (index != -1) library_index = index;
	check_init();
	pi(library_index);
    library[library_index].last_lib = lib;
    library[library_index].current_lib = lib;
    if (library[library_index].array == NULL) {
        int fd = open(lib, O_RDONLY);
        if (fd < 0) {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "cannot open \"%s\", returned %i\n", lib, fd);
            return -1;
        }
        library[library_index].len = 0;
        library[library_index].len = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, 0);
        library[library_index].array = mmap (NULL, library[library_index].len, PROT_READ, MAP_PRIVATE, fd, 0);
        if (library[library_index].array == MAP_FAILED) {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "map failed\n");
            exit;
        } else {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "map succeded with address: %014p\n", library[library_index].array);
            return 0;
        }
    } else return 0;
    return -1;
}

int prot_from_phdr(const int p_flags)
{
    int prot = 0;
    if (p_flags & PF_R)
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PROT_READ|");
        prot |= PROT_READ;
    }
    if (p_flags & PF_W)
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PROT_WRITE|");
        prot |= PROT_WRITE;
    }
    if (p_flags & PF_X)
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PROT_EXEC|");
        prot |= PROT_EXEC;
    }
    return prot;
}

void map() {
    if (library[library_index].is_mapped == 0) {
        library[library_index]._elf_header = (Elf64_Ehdr *) library[library_index].array;
        library[library_index]._elf_program_header = (Elf64_Phdr *)((unsigned long)library[library_index]._elf_header + library[library_index]._elf_header->e_phoff);

// the very first thing we do is obtain the base address

// Base Address
// The virtual addresses in the program headers might not represent the actual virtual addresses
// of the program's memory image. Executable files typically contain absolute code. To let the
// process execute correctly, the segments must reside at the virtual addresses used to build the
// executable file. On the other hand, shared object segments typically contain
// position-independent code. This lets a segment's virtual address change from one process to
// another, without invalidating execution behavior. Though the system chooses virtual addresses
// for individual processes, it maintains the segments’ relative positions. Because
// position-independent code uses relative addressing between segments, the difference between
// virtual addresses in memory must match the difference between virtual addresses in the file.
// 
// The difference between the virtual address of any segment in memory and the corresponding
// virtual address in the file is thus a single constant value for any one executable or shared object
// in a given process. This difference is the base address. One use of the base address is to relocate
// the memory image of the program during dynamic linking.
// 
// An executable or shared object file's base address is calculated during execution from three
// values: the virtual memory load address, the maximum page size, and the lowest virtual address
// of a program's loadable segment. To compute the base address, one determines the memory
// address associated with the lowest p_vaddr value for a PT_LOAD segment. This address is
// truncated to the nearest multiple of the maximum page size. The corresponding p_vaddr value
// itself is also truncated to the nearest multiple of the maximum page size. The base address is
// the difference between the truncated memory address and the truncated p_vaddr value.

        int PT_LOADS=0;
        for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
            switch(library[library_index]._elf_program_header[i].p_type)
            {
                case PT_LOAD:
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "i = %d\n", i);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOADS = %d\n", PT_LOADS);
                    if (!PT_LOADS)  {
//                             if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "saving first load\n");
                        library[library_index].First_Load_Header_index = i;
                    }
                    if (PT_LOADS) {
//                             if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "saving last load\n");
                        library[library_index].Last_Load_Header_index = i;
                    }
                    PT_LOADS=PT_LOADS+1;
                    break;
            }
        }
        size_t span = library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr + library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_memsz - library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_vaddr;

        size_t pagesize = 0x1000;

        read_fast_verifyb(library[library_index].array, library[library_index].len, &library[library_index].mappingb, span, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index], library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index]);

        library[library_index].align = round_down(library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr, pagesize);
        library[library_index].base_address = library[library_index].mappingb - library[library_index].align;
        library[library_index].mappingb_end = library[library_index].mappingb+span;

//             if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "base address range = %014p - %014p\nmapping = %014p\n", library[library_index].mappingb, library[library_index].mappingb_end, mapping);

// base address aquired, map all PT_LOAD segments adjusting by base address then continue with the rest
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n\n\nfind %014p, %014p, (int) 1239\n\n\n\n", library[library_index].mappingb, library[library_index].mappingb_end);

        if (library[library_index].mappingb == 0x00000000) abort_();
        int PT_LOADS_CURRENT = 0;
        for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
            switch(library[library_index]._elf_program_header[i].p_type)
            {
                case PT_LOAD:
                    PT_LOADS_CURRENT = PT_LOADS_CURRENT + 1;
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "mapping PT_LOAD number %d\n", PT_LOADS_CURRENT);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_flags:  %014p\n", library[library_index]._elf_program_header[i].p_flags);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_offset: %014p\n", library[library_index]._elf_program_header[i].p_offset);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_vaddr:  %014p\n", library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mappingb);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_paddr:  %014p\n", library[library_index]._elf_program_header[i].p_paddr);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_filesz: %014p\n", library[library_index]._elf_program_header[i].p_filesz);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_memsz:  %014p\n", library[library_index]._elf_program_header[i].p_memsz);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_align:  %014p\n\n", library[library_index]._elf_program_header[i].p_align);
// 
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\tp_flags: %014p", library[library_index]._elf_program_header[i].p_flags);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_offset: %014p", library[library_index]._elf_program_header[i].p_offset);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_vaddr: %014p", library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mappingb);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_paddr: %014p", library[library_index]._elf_program_header[i].p_paddr);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_filesz: %014p", library[library_index]._elf_program_header[i].p_filesz);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_memsz: %014p", library[library_index]._elf_program_header[i].p_memsz);
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_align: %014p\n\n\n", library[library_index]._elf_program_header[i].p_align);

                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "mprotect(%014p+round_down(%014p, %014p), %014p, ", library[library_index].mappingb, library[library_index]._elf_program_header[i].p_vaddr, library[library_index]._elf_program_header[i].p_align, library[library_index]._elf_program_header[i].p_memsz);
                    prot_from_phdr(library[library_index]._elf_program_header[i].p_flags);
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, ");\n");
                    errno = 0;
                    int check_mprotect_success = mprotect(library[library_index].mappingb+round_down(library[library_index]._elf_program_header[i].p_vaddr, library[library_index]._elf_program_header[i].p_align), round_up(library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_align), library[library_index]._elf_program_header[i].p_flags);
                    if (errno == 0)
                    {
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "mprotect on %014p succeded with size: %014p\n", library[library_index].mappingb+round_down(library[library_index]._elf_program_header[i].p_vaddr, library[library_index]._elf_program_header[i].p_align), round_up(library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_align));
                        print_maps();
                    }
                    else
                    {
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "mprotect failed with: %s (errno: %d, check_mprotect_success = %d)\n", strerror(errno), errno, check_mprotect_success);
                        print_maps();
                        abort_();
                    }
                    break;
            }
        }
        library[library_index].is_mapped = 1;
    }
}
// not used but kept incase needed
void __lseek_string__(char **src, int len, int offset) {
    char *p = malloc(len);
    memcpy(p, *src+offset, len);
    *src = p;
}

// not used but kept incase needed, a version of lseek_string that has an offset multiplier as so this does not need to be specified multiple times, eg if offset is 64 and multiplier is 2 the offset is then 128, this is intended for loops and related
void __lseek_stringb__(char **src, int len, int offset, int offsetT) {
    char *p = malloc(len);
    int off;
    off=((len*offsetT));
    memcpy(p, *src+offset+off, len);
    *src = p;
}
int __stream__(char *file, char **p, int *q, int LINES_TO_READ) {
            const char *filename = file;
            int fd = open(filename, O_RDONLY);
            if (fd < 0) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "cannot open \"%s\", returned %i\n", filename, fd);
                return -1;
            }
            char * array;
            char ch;
            size_t lines = 1;
            // Read the file byte by byte
            int bytes=1;
            int count=1;
            array = malloc(sizeof(char) * 2048);
            char *array_tmp;
            while (read(fd, &ch, 1) == 1) {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\rbytes read: %'i", bytes);
                if (count == 1024) { array_tmp = realloc(array, bytes+1024);
                    if (array_tmp == NULL) {
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "failed to allocate array to new size");
                        free(array);
                        exit(1);
                    } else {
                        array = array_tmp;
                    }
                    count=1;
                }
                array[bytes-1] = ch;
                if (ch == '\n') {
                    if (lines == LINES_TO_READ) {
                        break;
                    }
                    lines++;
                }
                count++;
                bytes++;
            }
            bytes--;
            array_tmp = realloc(array, bytes);
            if (array_tmp == NULL) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "failed to allocate array to new size");
                free(array);
                exit(1);
            } else {
                array = array_tmp;
            }
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\rbytes read: %'i\n", bytes);
    *p = array;
    *q = bytes;
    return bytes;
}

// not used but kept incase needed, a version of stream__ that only outputs the last line read
int __streamb__(char *file, char **p, int *q, int LINES_TO_READ) {
            const char *filename = file;
            int fd = open(filename, O_RDONLY);
            if (fd < 0) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "cannot open \"%s\", returned %i\n", filename, fd);
                return -1;
            }
            char * array;
            char * array_tmp;
            char * array_lines;
            char * array_lines_tmp;
            char ch;
            size_t lines = 1;
            // Read the file byte by byte
            int bytes=1;
            int count=1;
            array = malloc(sizeof(char) * 2048);
            while (read(fd, &ch, 1) == 1) {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\rbytes read: %'i", bytes);
                if (count == 1024) { array_tmp = realloc(array, bytes+1024);
                    if (array_tmp == NULL) {
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "failed to allocate array to new size");
                        free(array);
                        exit(1);
                    } else {
                        array = array_tmp;
                    }
                    count=1;
                }
                array[bytes-1] = ch;
                if (ch == '\n') {
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "attempting to reset array\n");
                    if (lines == LINES_TO_READ) {
                        break;
                    } else {
                        // reset array to as if we just executed this function
                        int y;
                        for (y=0; y<bytes; y++) {
                            array[y] = 0;
                        }
                        free(array);
                        array = malloc(sizeof(char) * 2048);
                        bytes=1;
                        count=1;
                    }
                    lines++;
                }
//                 count++;
                bytes++;
            }
            bytes--;
            array_tmp = realloc(array, bytes);
            if (array_tmp == NULL) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "failed to allocate array to new size");
                free(array);
                exit(1);
            } else {
                array = array_tmp;
            }
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\rbytes read: %'i\n", bytes);
    *p = array;
    *q = bytes;
    return bytes;
}

// reads a entire file
int __readb__(char *file, char **p, size_t *q) {
    int fd;
    size_t len = 0;
    char *o;
    if (!(fd = open(file, O_RDONLY)))
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "open() failure\n");
        return (1);
    }
    len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, 0);
    if (!(o = malloc(len))) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "failure to malloc()\n");
    }
    if ((read(fd, o, len)) == -1) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "failure to read()\n");
    }
    int cl = close(fd);
    if (cl < 0) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "cannot close \"%s\", returned %i\n", file, cl);
        return -1;
    }
    *p = o;
    *q = len;
    return len;
}

int
__string_quote__(const char *instr, char *outstr, const unsigned int size, const unsigned int style);

#ifndef ALLOCA_CUTOFF
# define ALLOCA_CUTOFF	4032
#endif
#define use_alloca(n) ((n) <= ALLOCA_CUTOFF)

char *
__print_quoted_string__(const char *str, unsigned int size, const unsigned int style, const char * return_type)
{
    char *buf;
    char *outstr;
    unsigned int alloc_size;
    int rc;

    if (size && style & QUOTE_0_TERMINATED)
        --size;

    alloc_size = 4 * size;
    if (alloc_size / 4 != size) {
        error_msg("Out of memory");
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "???");
        return "-1";
    }
    alloc_size += 1 + (style & QUOTE_OMIT_LEADING_TRAILING_QUOTES ? 0 : 2);

    if (use_alloca(alloc_size)) {
        outstr = alloca(alloc_size);
        buf = NULL;
    } else {
        outstr = buf = malloc(alloc_size);
        if (!buf) {
            error_msg("Out of memory");
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "???");
            return "-1";
        }
    }

//         rc = string_quote(str, outstr, size, style);
    __string_quote__(str, outstr, size, style);
    if ( return_type == "return") {
        return outstr;
    } else if ( return_type == "print") {
        if (bytecmpq(GQ, char_n) == 0) printf(outstr);
    }

    free(buf);
//         return rc;
}

Elf64_Word
get_dynamic_entryq(Elf64_Dyn *dynamic, int field);

// read section header table
int read_section_header_table_(const char * arrayb, Elf64_Ehdr * eh, Elf64_Shdr * sh_table[])
{
    *sh_table = (Elf64_Shdr *)(arrayb + eh->e_shoff);
    if(!sh_table) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Failed to read table\n");
        return -1;
    }
    return 0;
}

char * read_section_(char * ar, Elf64_Shdr sh) {
    char * buff = (char *)(ar + sh.sh_offset);
    return buff ;
}

int get_section(char * sourcePtr, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], char * section) {
    fprintf(stderr, "\nreading section: %s\n", section);
    char * sh_str = read_section_(sourcePtr, sh_table[eh->e_shstrndx]); // will fail untill section header table can be read
    for(int i=0; i<eh->e_shnum; i++) if (bytecmpq((sh_str + sh_table[i].sh_name), section) == 0) {
        return i;
    }
    
    return 0; // if section cannot be found
}

char * print_section_headers_(char * sourcePtr, Elf64_Ehdr * eh, Elf64_Shdr sh_table[]) {
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n");
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "eh->e_shstrndx = 0x%x (%d)\n", eh->e_shstrndx+library[library_index].mappingb, eh->e_shstrndx);
    char * sh_str;
    sh_str = read_section_(sourcePtr, sh_table[eh->e_shstrndx]); // will fail untill section header table can be read
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t========================================");
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "========================================\n");
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\tidx offset     load-addr  size       algn type       flags      section\n");
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t========================================");
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "========================================\n");

    for(int i=0; i<eh->e_shnum; i++) { // will fail untill section header table can be read
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t%03d ", i);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_offset); // not sure if this should be adjusted to base address
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_addr+library[library_index].mappingb);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_size);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%4d ", library[library_index]._elf_symbol_table[i].sh_addralign);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_type);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_flags);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s\t", (sh_str + sh_table[i].sh_name));
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n");
        if (bytecmpq((sh_str + sh_table[i].sh_name), ".rela.plt") == 0) library[library_index].RELA_PLT_SIZE=library[library_index]._elf_symbol_table[i].sh_size;
    }
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t========================================");
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "========================================\n");
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n");
}

void read_symbol(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table) {
    char *str_tbl;
    Elf64_Sym* sym_tbl;
    uint64_t i, symbol_count;
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "symbol_table = %d\n", symbol_table);
    sym_tbl = (Elf64_Sym*)read_section_(arrayc, sh_table[symbol_table]);

    /* Read linked string-table
    * Section containing the string table having names of
    * symbols of this section
    */
    uint64_t str_tbl_ndx = sh_table[symbol_table].sh_link;
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "string/symbol table index = %d\n", str_tbl_ndx);
    str_tbl = read_section_(arrayc, sh_table[str_tbl_ndx]);

    symbol_count = sh_table[symbol_table].sh_size/sizeof(Elf64_Sym);
    int link_ = sh_table[symbol_table].sh_link;
    link_ = sh_table[link_].sh_link;
    int linkn = 0;
    while (link_ != 0) {
        link_ = sh_table[link_].sh_link;
        linkn++;
    }
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "links: %d\n", linkn);
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%d symbols\n", symbol_count);

//   Elf64_Word	st_name;		/* Symbol name (string tbl index) */
//   unsigned char	st_info;		/* Symbol type and binding */
//   unsigned char st_other;		/* Symbol visibility */
//   Elf64_Section	st_shndx;		/* Section index */
//   Elf64_Addr	st_value;		/* Symbol value */
//   Elf64_Xword	st_size;		/* Symbol size */
    for(int i=0; i< symbol_count; i++) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "index: %d\t", i);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "size: %10d \t", sym_tbl[i].st_size);
// /* Legal values for ST_BIND subfield of st_info (symbol binding).  */
// 
// #define STB_LOCAL	0		/* Local symbol */
// #define STB_GLOBAL	1		/* Global symbol */
// #define STB_WEAK	2		/* Weak symbol */
// #define	STB_NUM		3		/* Number of defined types.  */
// #define STB_LOOS	10		/* Start of OS-specific */
// #define STB_GNU_UNIQUE	10		/* Unique symbol.  */
// #define STB_HIOS	12		/* End of OS-specific */
// #define STB_LOPROC	13		/* Start of processor-specific */
// #define STB_HIPROC	15		/* End of processor-specific */
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "binding: ");
        switch (ELF64_ST_BIND(sym_tbl[i].st_info)) {
            case STB_LOCAL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "LOCAL   ( Local  symbol )  ");
                break;
            case STB_GLOBAL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GLOBAL  ( Global symbol )  ");
                break;
            case STB_WEAK:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "WEAK    (  Weak symbol  )  ");
                break;
            default:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "UNKNOWN (%d)                ", ELF64_ST_BIND(sym_tbl[i].st_info));
                break;
        }
// /* Legal values for ST_TYPE subfield of st_info (symbol type).  */
// 
// #define STT_NOTYPE	0		/* Symbol type is unspecified */
// #define STT_OBJECT	1		/* Symbol is a data object */
// #define STT_FUNC	2		/* Symbol is a code object */
// #define STT_SECTION	3		/* Symbol associated with a section */
// #define STT_FILE	4		/* Symbol's name is file name */
// #define STT_COMMON	5		/* Symbol is a common data object */
// #define STT_TLS		6		/* Symbol is thread-local data object*/
// #define	STT_NUM		7		/* Number of defined types.  */
// #define STT_LOOS	10		/* Start of OS-specific */
// #define STT_GNU_IFUNC	10		/* Symbol is indirect code object */
// #define STT_HIOS	12		/* End of OS-specific */
// #define STT_LOPROC	13		/* Start of processor-specific */
// #define STT_HIPROC	15		/* End of processor-specific */
// /* Symbol visibility specification encoded in the st_other field.  */
// #define STV_DEFAULT	0		/* Default symbol visibility rules */
// #define STV_INTERNAL	1		/* Processor specific hidden class */
// #define STV_HIDDEN	2		/* Sym unavailable in other modules */
// #define STV_PROTECTED	3		/* Not preemptible, not exported */
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "visibility: ");
        switch (ELF64_ST_VISIBILITY(sym_tbl[i].st_other)) {
            case STV_DEFAULT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "default   (Default symbol visibility rules)      ");
                break;
            case STV_INTERNAL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "internal  (Processor specific hidden class)      ");
                break;
            case STV_HIDDEN:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "hidden    (Symbol unavailable in other modules)  ");
                break;
            case STV_PROTECTED:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "protected (Not preemptible, not exported)        ");
                break;
        }
        char * address = sym_tbl[i].st_value+library[library_index].mappingb;
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "address: %014p\t", address);
        if ( address > library[library_index].mappingb && address < library[library_index].mappingb_end ) test(address);
        else if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "value: %015p\t", sym_tbl[i].st_value);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "type: ");
        switch (ELF64_ST_TYPE(sym_tbl[i].st_info)) {
            case STT_NOTYPE:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NOTYPE   (Symbol type is unspecified)             ");
                break;
            case STT_OBJECT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OBJECT   (Symbol is a data object)                ");
                break;
                case STT_FUNC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "FUNCTION (Symbol is a code object)                ");
                break;
                case STT_SECTION:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "SECTION  (Symbol associated with a section)       ");
                break;
                case STT_FILE:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "FILE     (Symbol's name is file name)             ");
                break;
                case STT_COMMON:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "COMMON   (Symbol is a common data object)         ");
                break;
                case STT_TLS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "TLS      (Symbol is thread-local data object)     ");
                break;
            default:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "UNKNOWN  (%d)                                     ", ELF64_ST_TYPE(sym_tbl[i].st_info));
                break;
        }
        char * name;
        if (test_string(str_tbl + sym_tbl[i].st_name) == 0) name = str_tbl + sym_tbl[i].st_name;
        else name = "INVALID";
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "name: %s\n", demangle_it(name));
        if (bytecmpq(GQ, char_n) == 0) nl();
    }
}

void print_elf_symbol_table(char * arrayc, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], uint64_t symbol_table)
{
    int level = 0;
        switch(sh_table[symbol_table].sh_type) {
            case SHT_NULL:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_PROGBITS:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_SYMTAB:
                read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_STRTAB:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_RELA:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_HASH:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_DYNAMIC:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_NOTE:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_NOBITS:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_REL:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_SHLIB:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_DYNSYM:
                read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_INIT_ARRAY:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_FINI_ARRAY:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_PREINIT_ARRAY:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_GROUP:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_SYMTAB_SHNDX:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_NUM:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_LOOS:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_ATTRIBUTES:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_HASH:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_LIBLIST:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_CHECKSUM:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_LOSUNW:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_SUNW_COMDAT:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_SUNW_syminfo:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_verdef:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_verneed:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_versym:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_LOPROC:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_HIPROC:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_LOUSER:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_HIUSER:
                if (level == 3) read_symbol(arrayc, sh_table, symbol_table);
                break;
            default:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "UNKNOWN ");
                break;
        }
}

void print_symbols(char * arrayd, Elf64_Ehdr * eh, Elf64_Shdr sh_table[])
{
// /* Legal values for sh_type (section type).  */
// 
// #define SHT_NULL	  0		/* Section header table entry unused */
// #define SHT_PROGBITS	  1		/* Program data */
// #define SHT_SYMTAB	  2		/* Symbol table */
// #define SHT_STRTAB	  3		/* String table */
// #define SHT_RELA	  4		/* Relocation entries with addends */
// #define SHT_HASH	  5		/* Symbol hash table */
// #define SHT_DYNAMIC	  6		/* Dynamic linking information */
// #define SHT_NOTE	  7		/* Notes */
// #define SHT_NOBITS	  8		/* Program space with no data (bss) */
// #define SHT_REL		  9		/* Relocation entries, no addends */
// #define SHT_SHLIB	  10		/* Reserved */
// #define SHT_DYNSYM	  11		/* Dynamic linker symbol table */
// #define SHT_INIT_ARRAY	  14		/* Array of constructors */
// #define SHT_FINI_ARRAY	  15		/* Array of destructors */
// #define SHT_PREINIT_ARRAY 16		/* Array of pre-constructors */
// #define SHT_GROUP	  17		/* Section group */
// #define SHT_SYMTAB_SHNDX  18		/* Extended section indeces */
// #define	SHT_NUM		  19		/* Number of defined types.  */
// #define SHT_LOOS	  0x60000000	/* Start OS-specific.  */
// #define SHT_GNU_ATTRIBUTES 0x6ffffff5	/* Object attributes.  */
// #define SHT_GNU_HASH	  0x6ffffff6	/* GNU-style hash table.  */
// #define SHT_GNU_LIBLIST	  0x6ffffff7	/* Prelink library list */
// #define SHT_CHECKSUM	  0x6ffffff8	/* Checksum for DSO content.  */
// #define SHT_LOSUNW	  0x6ffffffa	/* Sun-specific low bound.  */
// #define SHT_SUNW_move	  0x6ffffffa
// #define SHT_SUNW_COMDAT   0x6ffffffb
// #define SHT_SUNW_syminfo  0x6ffffffc
// #define SHT_GNU_verdef	  0x6ffffffd	/* Version definition section.  */
// #define SHT_GNU_verneed	  0x6ffffffe	/* Version needs section.  */
// #define SHT_GNU_versym	  0x6fffffff	/* Version symbol table.  */
// #define SHT_HISUNW	  0x6fffffff	/* Sun-specific high bound.  */
// #define SHT_HIOS	  0x6fffffff	/* End OS-specific type */
// #define SHT_LOPROC	  0x70000000	/* Start of processor-specific */
// #define SHT_HIPROC	  0x7fffffff	/* End of processor-specific */
// #define SHT_LOUSER	  0x80000000	/* Start of application-specific */
// #define SHT_HIUSER	  0x8fffffff	/* End of application-specific */
    int ii = 0;
    for(int i=0; i<eh->e_shnum; i++) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n[");
        switch(sh_table[i].sh_type) {
            case SHT_NULL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NULL                     (Section header table entry unused)                   ");
                break;
            case SHT_PROGBITS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PROGBITS                 (Program data)                                        ");
                break;
            case SHT_SYMTAB: 
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "SYMTAB                   (Symbol table)                                        ");
                break;
            case SHT_STRTAB:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "STRTAB                   (String table)                                        ");
                break;
            case SHT_RELA:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "RELA                     (Relocation entries with addends)                     ");
                break;
            case SHT_HASH:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "HASH                     (Symbol hash table)                                   ");
                break;
            case SHT_DYNAMIC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DYNAMIC                  (Dynamic linking information)                         ");
                break;
            case SHT_NOTE:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NOTE                     (Notes)                                               ");
                break;
            case SHT_NOBITS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NOBITS                   (Program space with no data (bss))                    ");
                break;
            case SHT_REL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "REL                      (Relocation entries, no addends)                      ");
                break;
            case SHT_SHLIB:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "SHLIB                    (Reserved)                                            ");
                break;
            case SHT_DYNSYM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DYNSYM                   (Dynamic linker symbol table)                         ");
                break;
            case SHT_INIT_ARRAY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "INIT_ARRAY               (Array of constructors)                               ");
                break;
            case SHT_FINI_ARRAY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "FINI_ARRAY               (Array of destructors)                                ");
                break;
            case SHT_PREINIT_ARRAY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PREINIT_ARRAY            (Array of pre-constructors)                           ");
                break;
            case SHT_GROUP:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GROUP                    (Section group)                                       ");
                break;
            case SHT_SYMTAB_SHNDX:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "SYMTAB_SHNDX             (Extended section indeces)                            ");
                break;
            case SHT_NUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NUM                      (Number of defined types)                             ");
                break;
            case SHT_LOOS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "LOOS                     (Start OS-specific)                                   ");
                break;
            case SHT_GNU_ATTRIBUTES:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GNU_ATTRIBUTES           (Object attributes)                                   ");
                break;
            case SHT_GNU_HASH:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GNU_HASH                 (GNU-style hash table)                                ");
                break;
            case SHT_GNU_LIBLIST:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GNU_LIBLIST              (Prelink library list)                                ");
                break;
            case SHT_CHECKSUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "CHECKSUM                 (Checksum for DSO content)                            ");
                break;
            case SHT_LOSUNW:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "LOSUNW or SUNW_move                                                            ");
                break;
            case SHT_SUNW_COMDAT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "SUNW_COMDAT                                                                    ");
                break;
            case SHT_SUNW_syminfo:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "SUNW_syminfo                                                                   ");
                break;
            case SHT_GNU_verdef:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GNU_verdef               (Version definition section)                          ");
                break;
            case SHT_GNU_verneed:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GNU_verneed              (Version needs section)                               ");
                break;
            case SHT_GNU_versym:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GNU_versym               (Version symbol table) or HISUNW (Sun-specific high bound) or HIOS (End OS-specific type) ");
                break;
            case SHT_LOPROC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "LOPROC                   (Start of processor-specific)                         ");
                break;
            case SHT_HIPROC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "HIPROC                   (End of processor-specific)                           ");
                break;
            case SHT_LOUSER:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "LOUSER                   (Start of application-specific)                       ");
                break;
            case SHT_HIUSER:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "HIUSER                   (End of application-specific)                         ");
                break;
            default:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "UNKNOWN                                                                        ");
        }
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Section %d, Index %d]\n", ii, i);
        print_elf_symbol_table(arrayd, eh, sh_table, i);
        ii++;
    }
}

char *
find_needed(const char * lib, const char * symbol);

int JUMP = 0;
int a = 0;

char * lib_origin = NULL;
const char * interp = "./supplied/lib/ld-2.26.so";
const char * libc = "./supplied/lib/libc-2.26.so";
int first = 0;

char * current_symbol;
char * symbol_lookup(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table, int index, int mode, const char * am_i_quiet, const char * is_jump) {
    char * k = library[library_index].last_lib;
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: finding index %d\n", __FILE__, __LINE__, __func__, index);
    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "looking up index %d of table %d\n", index, symbol_table);
    Elf64_Sym* sym_tbl = (Elf64_Sym*)read_section_(arrayc, sh_table[symbol_table]);
    uint64_t str_tbl_ndx = sh_table[symbol_table].sh_link;
    char *str_tbl = read_section_(arrayc, sh_table[str_tbl_ndx]);
    uint64_t symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));
    
    current_symbol = demangle_it(str_tbl + sym_tbl[index].st_name);
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "searching for %s in %s\n", demangle_it(str_tbl + sym_tbl[index].st_name), library[library_index].last_lib);
    
    if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "%s:%d:%s: requested symbol name for index %d of %s is %s\n", __FILE__, __LINE__, __func__, index, library[library_index].last_lib, demangle_it(str_tbl + sym_tbl[index].st_name));

    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: readelf = %d, JUMP = %d, a = %d, is_jump = %s\n", __FILE__, __LINE__, __func__, readelf, JUMP, a, is_jump); 
    if (readelf == 0 && bytecmpq(is_jump, char_y) == 0 && a == 0) {
		puts("READELF==0 START");
// 		sleep(20);
        lib_origin = library[library_index].last_lib;
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "lib_origin = %s\n", lib_origin);
        char * sym = NULL;
        first = 0;
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "calling find_needed\n");
        if (produce_backtrace == true) bt();
        sym = find_needed(lib_origin, demangle_it(str_tbl + sym_tbl[index].st_name));
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "called find_needed\n");
        if (produce_backtrace == true) bt();
        if (sym == NULL && bytecmpq(lib_origin, "/lib/ld-linux-x86-64.so.2") == -1) {
//             if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s not found, searching interpreter %s\n", demangle_it(str_tbl + sym_tbl[index].st_name), interp);
//             sym = find_needed(interp, demangle_it(str_tbl + sym_tbl[index].st_name));
            if (sym == NULL) {
                lib_origin = k;
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "symbol has not been found in %s, searching dependancies of %s\n", interp, lib_origin);
                if (bytecmpq(sleep_, "YES") == 0) sleep(12);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "calling find_needed\n");
                if (produce_backtrace == true) bt();
                sym = find_needed(lib_origin, demangle_it(str_tbl + sym_tbl[index].st_name));
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "called find_needed\n");
                if (produce_backtrace == true) bt();
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s still not found, trying self (%s)\n", demangle_it(str_tbl + sym_tbl[index].st_name), lib_origin);
                a = 1;
                self = 1;
                first = 1;
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "calling find_needed\n");
                if (produce_backtrace == true) bt();
                sym = lookup_symbol_by_name_(lib_origin, demangle_it(str_tbl + sym_tbl[index].st_name));
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "called find_needed\n");
                if (produce_backtrace == true) bt();
                first = 0;
                self = 0;
                a = 0;
                if (sym == NULL) {
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s still not found, aborting\n", demangle_it(str_tbl + sym_tbl[index].st_name));
                    if (!(bytecmpq(library[library_index].last_lib, interp) == 0 || bytecmpq(library[library_index].last_lib, libc) == 0)) abort_();
                }
            }
		puts("READELF==0 END");
// 		sleep(20);
        }
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "found %014p for symbol %s in %s\n", sym, demangle_it(str_tbl + sym_tbl[index].st_name), library[library_index].last_lib);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, sym);
        if (bytecmpq(sleep_r, char_y) == 0) sleep(15);
        if (sym != NULL && mode == 1) return sym;
    }
    if ( mode == 1) return sym_tbl[index].st_value;
    else if (mode == 2) return sym_tbl[index].st_size;
}
char * symbol_lookup_name(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table, char * name_);

char * symbol_lookup_plt(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table, int index, int mode, const char * am_i_quiet) {
    char *str_tbl;
    Elf64_Sym* sym_tbl;
    uint64_t i, symbol_count;
    sym_tbl = (Elf64_Sym*)read_section_(arrayc, sh_table[symbol_table]);

    uint64_t str_tbl_ndx = sh_table[symbol_table].sh_link;
    str_tbl = read_section_(arrayc, sh_table[str_tbl_ndx]);

    symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));
    char * name_ = demangle_it(str_tbl + sym_tbl[index].st_name);
//     read_symbol(arrayc, sh_table, symbol_table);
    printf("looking up index %d value %014p\n", index, sym_tbl[index].st_value);
    for(int i=0; i< symbol_count; i++) {
        char * name = demangle_it(str_tbl + sym_tbl[i].st_name);
        if (bytecmpq(name,name_) == 0) {
            current_symbol = name_;
            char * address = sym_tbl[i].st_value;
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: requested symbol name \"%s\" found in table %d at address %014p is \"%s\"\n", __FILE__, __LINE__, __func__, name_, symbol_table, address, name);
            if (sym_tbl[i].st_value == 0) return name_;
            else if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n%s:%d:%s: requested symbol name \"%s\" in PLT table %d does not have a valid JUMP relocation value\n\n", __FILE__, __LINE__, __func__, name_, symbol_table);
        }
    }
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n%s:%d:%s: requested symbol name \"%s\" could not be found in PLT table %d\n\n", __FILE__, __LINE__, __func__, name_, symbol_table);
    return "NOT_PLT";
}

char * symbol_lookupb(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table, int index, int mode, const char * am_i_quiet, const char * is_jump) {
    char * k = library[library_index].last_lib;
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: finding index %d\n", __FILE__, __LINE__, __func__, index);
    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "looking up index %d of table %d\n", index, symbol_table);
    Elf64_Sym* sym_tbl = (Elf64_Sym*)read_section_(arrayc, sh_table[symbol_table]);
    uint64_t str_tbl_ndx = sh_table[symbol_table].sh_link;
    char *str_tbl = read_section_(arrayc, sh_table[str_tbl_ndx]);
    uint64_t symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));
    
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "searching for %s in %s\n", demangle_it(str_tbl + sym_tbl[index].st_name), library[library_index].last_lib);
    
    if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "%s:%d:%s: requested symbol name for index %d of %s is %s\n", __FILE__, __LINE__, __func__, index, library[library_index].last_lib, demangle_it(str_tbl + sym_tbl[index].st_name));

    if (bytecmpq(is_jump, char_y) == 0 && a == 0) {
        lib_origin = library[library_index].last_lib;
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "lib_origin = %s\n", lib_origin);
        char * sym;
        sym = find_needed(lib_origin, demangle_it(str_tbl + sym_tbl[index].st_name));
        if (sym == NULL && bytecmpq(lib_origin, interp) == -1) {
            if (bytecmpq(library[library_index].last_lib, interp) == 0) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s not found, searching libc %s\n", demangle_it(str_tbl + sym_tbl[index].st_name), libc);
                sym = lookup_symbol_by_name_(libc, demangle_it(str_tbl + sym_tbl[index].st_name));
                lib_origin = k;
            }
            else if (bytecmpq(library[library_index].last_lib, libc) == 0) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s not found, searching gnu interpreter %s as required by %s\n", demangle_it(str_tbl + sym_tbl[index].st_name), interp, libc);
                sym = lookup_symbol_by_name_(interp, demangle_it(str_tbl + sym_tbl[index].st_name));
                lib_origin = k;
            }
            if (sym == NULL) {
                lib_origin = k;
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s still not found, trying self (%s)\n", demangle_it(str_tbl + sym_tbl[index].st_name), lib_origin);
                self = 1;
                a = 1;
                sym = lookup_symbol_by_name_(lib_origin, demangle_it(str_tbl + sym_tbl[index].st_name));
                self = 0;
                a = 0;
                if (sym == NULL) {
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s still not found, aborting\n", demangle_it(str_tbl + sym_tbl[index].st_name));
                    if (bytecmpq(library[library_index].last_lib, interp) == 0 || bytecmpq(library[library_index].last_lib, libc) == 0) if (bytecmpq(sleep_, "YES") == 0) sleep(4);
                    else abort_();
                }
            }
        }
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "found %014p for symbol %s in %s\n", sym, demangle_it(str_tbl + sym_tbl[index].st_name), library[library_index].last_lib);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, sym);
        if (bytecmpq(library[library_index].last_lib, interp) == 0 || bytecmpq(library[library_index].last_lib, libc) == 0) if (bytecmpq(sleep_, "YES") == 0) sleep(15);
        if (sym != NULL && mode == 1) return sym;
    }
    if ( mode == 1) return sym_tbl[index].st_value;
    else if (mode == 2) return sym_tbl[index].st_size;
}

char * symbol_lookup_name(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table, char * name_) {
    char *str_tbl;
    Elf64_Sym* sym_tbl;
    uint64_t i, symbol_count;
    sym_tbl = (Elf64_Sym*)read_section_(arrayc, sh_table[symbol_table]);

    uint64_t str_tbl_ndx = sh_table[symbol_table].sh_link;
    str_tbl = read_section_(arrayc, sh_table[str_tbl_ndx]);

    symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));

    for(int i=0; i< symbol_count; i++) {
        char * name = demangle_it(str_tbl + sym_tbl[i].st_name);
        if (bytecmpq(name,name_) == 0) {
            current_symbol = name;
            char * address = sym_tbl[i].st_value+library[library_index].mappingb;
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s requested symbol name \"%s\" found in table %d at address %014p is \"%s\"\n", __FILE__, __LINE__, __func__, name_, symbol_table, address, name);
            fprintf(stderr, "lib = %s\n", library[library_index].last_lib);

            if (sym_tbl[i].st_value != 0) return analyse_address(address, name);
            else fprintf(stderr, "sym_tbl[%d].st_value is zero\n", i);
            switch (ELF64_ST_BIND(sym_tbl[i].st_info)) {
                case STB_WEAK:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "however symbol is defined as WEAK\n");
                    return "WEAK ZERO";
                    break;
            }
        }
    }
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n%s:%d:%s: requested symbol name \"%s\" could not be found in table %d\n\n", __FILE__, __LINE__, __func__, name_, symbol_table);
    if (produce_backtrace == true) bt();
    return NULL;
}
char * print_elf_symbol_table_lookup(char * arrayc, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], uint64_t symbol_table, int index, int mode, const char * is_jump)
{
        char * name_;
        switch(sh_table[symbol_table].sh_type) {
            case SHT_DYNSYM:
                name_ = symbol_lookup(arrayc, sh_table, symbol_table, index, mode, relocation_quiet, is_jump);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, name_);
                if (name_ != NULL) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning VALUED %014p\n", __FILE__, __LINE__, __func__, name_);
                    return name_;
                }
                else {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning NULLED %014p\n", __FILE__, __LINE__, __func__, name_);
//                     abort_();
                    return NULL;
                }
                break;
            case SHT_SYMTAB:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: JUMP = %d, is_jump = %s\n", __FILE__, __LINE__, __func__, JUMP, is_jump); 
                name_ = symbol_lookup(arrayc, sh_table, symbol_table, index, mode, relocation_quiet, is_jump);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, name_);
                if (name_ != NULL) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning VALUED %014p\n", __FILE__, __LINE__, __func__, name_);
                    return name_;
                }
                else {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning NULLED %014p\n", __FILE__, __LINE__, __func__, name_);
//                     abort_();
                    return NULL;
                }
                break;
            default:
                return NULL;
                break;
        }
}

char * print_elf_symbol_table_lookup_plt(char * arrayc, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], uint64_t symbol_table, int index, int mode)
{
        char * name_;
        switch(sh_table[symbol_table].sh_type) {
            case SHT_DYNSYM:
                name_ = symbol_lookup_plt(arrayc, sh_table, symbol_table, index, mode, relocation_quiet);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %s\n", __FILE__, __LINE__, __func__, name_);
                return name_;
                break;
            default:
                return NULL;
                break;
        }
}

char * print_elf_symbol_table_lookup_name(char * arrayc, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], uint64_t symbol_table, char * index)
{
        char * name_;
        switch(sh_table[symbol_table].sh_type) {
            case SHT_DYNSYM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "searching for symbol %s in SHT_DYNSYM\n", index);
                name_ = symbol_lookup_name(arrayc, sh_table, symbol_table, index);
                if (name_ != NULL) {
                    return name_;
                }
                else {
                    return NULL;
                }
                break;
            case SHT_SYMTAB:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "searching for symbol %s in SHT_SYMTAB\n", index);
                name_ = symbol_lookup_name(arrayc, sh_table, symbol_table, index);
                if (name_ != NULL) {
                    return name_;
                }
                else {
                    return NULL;
                }
                break;
            default:
                return NULL;
                break;
        }
}

char * print_symbols_lookup(char * arrayd, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], int index, int mode, const char * is_jump)
{
    char * sym;
    for(int i=0; i<eh->e_shnum; i++) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: looking for index %d\n", __FILE__, __LINE__, __func__, i);
        sym = print_elf_symbol_table_lookup(arrayd, eh, sh_table, i, index, mode, is_jump);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, sym);
        if ( sym != NULL ) {
            return sym;
        }
    }
    if (sym == NULL) return NULL;
}

char * print_symbols_lookup_plt(char * arrayd, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], int index, int mode)
{
    char * sym;
    for(int i=0; i<eh->e_shnum; i++) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: looking for index %d\n", __FILE__, __LINE__, __func__, i);
        sym = print_elf_symbol_table_lookup_plt(arrayd, eh, sh_table, i, index, mode);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %s\n", __FILE__, __LINE__, __func__, sym);
        if ( sym != NULL ) {
            return sym;
        }
    }
    if (sym == NULL) return NULL;
}

char * print_symbols_lookup_name(char * arrayd, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], char * index)
{
    char * value;
    for(int i=0; i<eh->e_shnum; i++) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "searching for symbol %s in index %d\n", index, i);
        value = print_elf_symbol_table_lookup_name(arrayd, eh, sh_table, i, index);
        if ( value != NULL ) {
            return value;
        }
    }
    if (value == NULL) return NULL;

}

void * lookup_symbol_by_name(const char * arrayb, Elf64_Ehdr * eh, char * name) {

        read_section_header_table_(arrayb, eh, &library[library_index]._elf_symbol_table);
        char * symbol = print_symbols_lookup_name(arrayb, eh, library[library_index]._elf_symbol_table, name);
        return symbol;
}

void * lookup_symbol_by_name_(const char * lib, const char * name) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "attempting to look up symbol %s in lib %s\n", name, lib);    
        dlopen(lib);
        if (produce_backtrace == true) bt();
        const char * arrayb = library[library_index].array;
        Elf64_Ehdr * eh = (Elf64_Ehdr *) arrayb;
        Elf64_Shdr *_elf_symbol_tableb;
        if(!strncmp((char*)eh->e_ident, "\177ELF", 4)) {
            if ( read_section_header_table_(arrayb, eh, &_elf_symbol_tableb) == 0) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "init done, looking up symbol %s in lib %s\n", name, lib);
                char * symbol = print_symbols_lookup_name(arrayb, eh, _elf_symbol_tableb, name);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, symbol);
                return symbol;
            }
        }
        else abort_();
}

void * lookup_symbol_by_index(const char * arrayb, Elf64_Ehdr * eh, int symbol_index, int mode, const char * am_i_quiet, const char * is_jump) {
        if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "attempting to look up symbol, index = %d\n", symbol_index);

        read_section_header_table_(arrayb, eh, &library[library_index]._elf_symbol_table);
        char * symbol = print_symbols_lookup(arrayb, eh, library[library_index]._elf_symbol_table, symbol_index, mode, is_jump);
        if (produce_backtrace == true) bt();
        if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "%s:%d:%s: symbol = %d (%014p)\n", __FILE__, __LINE__, __func__, symbol, symbol);
        return symbol;
}

char * lookup_symbol_by_index_plt(const char * arrayb, Elf64_Ehdr * eh, int symbol_index, int mode, const char * am_i_quiet) {
        if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "%s:%d:%s: attempting to look up symbol, index = %d\n", __FILE__, __LINE__, __func__, symbol_index);

        read_section_header_table_(arrayb, eh, &library[library_index]._elf_symbol_table);
        char * symbol = print_symbols_lookup_plt(arrayb, eh, library[library_index]._elf_symbol_table, symbol_index, mode);
        if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "%s:%d:%s: returning %s\n", __FILE__, __LINE__, __func__, symbol);
        return symbol;
}

Elf64_Word
get_dynamic_entry(Elf64_Dyn *dynamic, int field)
{
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "called get_dynamic_entry\n");

// Name        Value       d_un        Executable      Shared Object
// DT_NULL     0           ignored     mandatory       mandatory
// DT_NEEDED   1           d_val       optional        optional
// DT_PLTRELSZ 2           d_val       optional        optional
// DT_PLTGOT   3           d_ptr       optional        optional
// DT_HASH     4           d_ptr       mandatory       mandatory
// DT_STRTAB   5           d_ptr       mandatory       mandatory
// DT_SYMTAB   6           d_ptr       mandatory       mandatory
// DT_RELA     7           d_ptr       mandatory       optional
// DT_RELASZ   8           d_val       mandatory       optional
// DT_RELAENT  9           d_val       mandatory       optional
// DT_STRSZ    10          d_val       mandatory       mandatory
// DT_SYMENT   11          d_val       mandatory       mandatory
// DT_INIT     12          d_ptr       optional        optional
// DT_FINI     13          d_ptr       optional        optional
// DT_SONAME   14          d_val       ignored         optional
// DT_RPATH    15          d_val       optional        ignored
// DT_SYMBOLIC 16          ignored     ignored         optional
// DT_REL      17          d_ptr       mandatory       optional
// DT_RELSZ    18          d_val       mandatory       optional
// DT_RELENT   19          d_val       mandatory       optional
// DT_PLTREL   20          d_val       optional        optional
// DT_DEBUG    21          d_ptr       optional        ignored
// DT_TEXTREL  22          ignored     optional        optional
// DT_JMPREL   23          d_ptr       optional        optional
// DT_BIND_NOW 24          ignored     optional        optional
// DT_LOPROC   0x70000000  unspecified unspecified     unspecified
// DT_HIPROC   0x7fffffff  unspecified unspecified     unspecified
// 
// DT_NULL         An entry with a DT_NULL tag marks the end of the _DYNAMIC array.
// DT_NEEDED       This element holds the string table offset of a null-terminated string, giving
//                 the name of a needed library. The offset is an index into the table recorded
//                 in the DT_STRTAB entry. See "Shared Object Dependencies'' for more
//                 information about these names. The dynamic array may contain multiple
//                 entries with this type. These entries' relative order is significant, though
//                 their relation to entries of other types is not.
// 
// DT_PLTRELSZ     This element holds the total size, in bytes, of the relocation entries
//                 associated with the procedure linkage table. If an entry of type DT_JMPREL
//                 is present, a DT_PLTRELSZ must accompany it.
// 
// DT_PLTGOT       This element holds an address associated with the procedure linkage table
//                 and/or the global offset table.
// 
// DT_HASH         This element holds the address of the symbol hash table, described in "Hash
//                 Table". This hash table refers to the symbol table referenced by the
//                 DT_SYMTAB element.
// 
// DT_STRTAB       This element holds the address of the string table, described in Chapter 1.
//                 Symbol names, library names, and other strings reside in this table.
// 
// DT_SYMTAB       This element holds the address of the symbol table, described in
//                 Chapter 1, with Elf32_Sym entries for the 32-bit class of files.
// 
// DT_RELA         This element holds the address of a relocation table, described in
//                 Chapter 1. Entries in the table have explicit addends, such as Elf32_Rela
//                 for the 32-bit file class. An object file may have multiple relocation
//                 sections. When building the relocation table for an executable or shared
//                 object file, the link editor catenates those sections to form a single table.
//                 Although the sections remain independent in the object file, the dynamic
//                 linker sees a single table. When the dynamic linker creates the process
//                 image for an executable file or adds a shared object to the process image,
//                 it reads the relocation table and performs the associated actions. If this
//                 element is present, the dynamic structure must also have DT_RELASZ and
//                 DT_RELAENT elements. When relocation is "mandatory" for a file, either
//                 DT_RELA or DT_REL may occur (both are permitted but not required).
// 
// DT_RELASZ       This element holds the total size, in bytes, of the DT_RELA relocation table.
// 
// DT_RELAENT      This element holds the size, in bytes, of the DT_RELA relocation entry.
// 
// DT_STRSZ        This element holds the size, in bytes, of the string table.
// 
// DT_SYMENT       This element holds the size, in bytes, of a symbol table entry.
// 
// DT_INIT         This element holds the address of the initialization function, discussed in
//                 "Initialization and Termination Functions" below.
// 
// DT_FINI         This element holds the address of the termination function, discussed in
//                 "Initialization and Termination Functions" below.
// 
// DT_SONAME       This element holds the string table offset of a null-terminated string, giving
//                 the name of the shared object. The offset is an index into the table recorded
//                 in the DT_STRTAB entry. See "Shared Object Dependencies" below for
//                 more information about these names.
// 
// DT_RPATH        This element holds the string table offset of a null-terminated search library
//                 search path string, discussed in "Shared Object Dependencies". The offset
//                 is an index into the table recorded in the DT_STRTAB entry.
// 
// DT_SYMBOLIC     This element's presence in a shared object library alters the dynamic linker's
//                 symbol resolution algorithm for references within the library. Instead of
//                 starting a symbol search with the executable file, the dynamic linker starts
//                 from the shared object itself. If the shared object fails to supply the
//                 referenced symbol, the dynamic linker then searches the executable file and
//                 other shared objects as usual.
// 
// DT_REL          This element is similar to DT_RELA, except its table has implicit addends,
//                 such as Elf32_Rel for the 32-bit file class. If this element is present, the
//                 dynamic structure must also have DT_RELSZ and DT_RELENT elements.
// 
// DT_RELSZ        This element holds the total size, in bytes, of the DT_REL relocation table.
// 
// DT_RELENT       This element holds the size, in bytes, of the DT_REL relocation entry.
// 
// DT_PLTREL       This member specifies the type of relocation entry to which the procedure
//                 linkage table refers. The d_val member holds DT_REL or DT_RELA , as
//                 appropriate. All relocations in a procedure linkage table must use the same
//                 relocation.
// 
// DT_DEBUG        This member is used for debugging. Its contents are not specified in this
//                 document.
// 
// DT_TEXTREL      This member's absence signifies that no relocation entry should cause a
//                 modification to a non-writable segment, as specified by the segment
//                 permissions in the program header table. If this member is present, one or
//                 more relocation entries might request modifications to a non-writable
//                 segment, and the dynamic linker can prepare accordingly.
// 
// DT_JMPREL       If present, this entries d_ptr member holds the address of relocation
//                 entries associated solely with the procedure linkage table. Separating these
//                 relocation entries lets the dynamic linker ignore them during process
//                 initialization, if lazy binding is enabled. If this entry is present, the related
//                 entries of types DT_PLTRELSZ and DT_PLTREL must also be present.
// 
// DT_BIND_NOW     If present in a shared object or executable, this entry instructs the dynamic
//                 linker to process all relocations for the object containing this entry before
//                 transferring control to the program. The presence of this entry takes
//                 precedence over a directive to use lazy binding for this object when
//                 specified through the environment or via dlopen( BA_LIB).
// 
// DT_LOPROC through DT_HIPROC
//                 Values in this inclusive range are reserved for processor-specific semantics.
//                 If meanings are specified, the processor supplement explains them.
// 
// Except for the DT_NULL element at the end of the library[library_index].array, and the relative order of DT_NEEDED
// elements, entries may appear in any order. Tag values not appearing in the table are reserved.


    for (; dynamic->d_tag != DT_NULL; dynamic++) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "testing if ");
/* Legal values for d_tag (dynamic entry type).  */

// #define DT_NULL		0		/* Marks end of dynamic section */
// #define DT_NEEDED	1		/* Name of needed library */
// #define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
// #define DT_PLTGOT	3		/* Processor defined value */
// #define DT_HASH		4		/* Address of symbol hash table */
// #define DT_STRTAB	5		/* Address of string table */
// #define DT_SYMTAB	6		/* Address of symbol table */
// #define DT_RELA		7		/* Address of Rela relocs */
// #define DT_RELASZ	8		/* Total size of Rela relocs */
// #define DT_RELAENT	9		/* Size of one Rela reloc */
// #define DT_STRSZ	10		/* Size of string table */
// #define DT_SYMENT	11		/* Size of one symbol table entry */
// #define DT_INIT		12		/* Address of init function */
// #define DT_FINI		13		/* Address of termination function */
// #define DT_SONAME	14		/* Name of shared object */
// #define DT_RPATH	15		/* Library search path (deprecated) */
// #define DT_SYMBOLIC	16		/* Start symbol search here */
// #define DT_REL		17		/* Address of Rel relocs */
// #define DT_RELSZ	18		/* Total size of Rel relocs */
// #define DT_RELENT	19		/* Size of one Rel reloc */
// #define DT_PLTREL	20		/* Type of reloc in PLT */
// #define DT_DEBUG	21		/* For debugging; unspecified */
// #define DT_TEXTREL	22		/* Reloc might modify .text */
// #define DT_JMPREL	23		/* Address of PLT relocs */
// #define	DT_BIND_NOW	24		/* Process relocations of object */
// #define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
// #define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
// #define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
// #define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
// #define DT_RUNPATH	29		/* Library search path */
// #define DT_FLAGS	30		/* Flags for the object being loaded */
// #define DT_ENCODING	32		/* Start of encoded range */
// #define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
// #define DT_PREINIT_ARRAYSZ 33		/* size in bytes of DT_PREINIT_ARRAY */
// #define	DT_NUM		34		/* Number used */
// #define DT_LOOS		0x6000000d	/* Start of OS-specific */
// #define DT_HIOS		0x6ffff000	/* End of OS-specific */
// #define DT_LOPROC	0x70000000	/* Start of processor-specific */
// #define DT_HIPROC	0x7fffffff	/* End of processor-specific */
// #define	DT_PROCNUM	DT_MIPS_NUM	/* Most used by any processor */
        switch (dynamic->d_tag) {
            case DT_NULL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_NULL");
                break;
            case DT_NEEDED:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_NEEDED");
                break;
            case DT_PLTRELSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PLTRELSZ");
                break;
            case DT_PLTGOT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PLTGOT");
                break;
            case DT_HASH:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_HASH");
                break;
            case DT_STRTAB:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_STRTAB");
                break;
            case DT_SYMTAB:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_SYMTAB");
                break;
            case DT_RELA:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELA");
                break;
            case DT_RELASZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELASZ");
                break;
            case DT_RELAENT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELAENT");
                break;
            case DT_STRSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_STRSZ");
                break;
            case DT_SYMENT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_SYMENT");
                break;
            case DT_INIT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_INIT");
                break;
            case DT_FINI:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FINI");
                break;
            case DT_SONAME:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_SONAME");
                break;
            case DT_RPATH:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RPATH");
                break;
            case DT_SYMBOLIC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_SYMBOLIC");
                break;
            case DT_REL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_REL");
                break;
            case DT_RELSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELSZ");
                break;
            case DT_RELENT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELENT");
                break;
            case DT_PLTREL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PLTREL");
                break;
            case DT_DEBUG:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_DEBUG");
                break;
            case DT_TEXTREL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_TEXTREL");
                break;
            case DT_JMPREL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_JMPREL");
                break;
            case DT_BIND_NOW:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_BIND_NOW");
                break;
            case DT_INIT_ARRAY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_INIT_ARRAY");
                break;
            case DT_FINI_ARRAY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FINI_ARRAY");
                break;
            case DT_INIT_ARRAYSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_INIT_ARRAYSZ");
                break;
            case DT_FINI_ARRAYSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FINI_ARRAYSZ");
                break;
            case DT_RUNPATH:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RUNPATH");
                break;
            case DT_FLAGS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FLAGS");
                break;
            case DT_ENCODING:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_ENCODING (or DT_PREINIT_ARRAY)");
                break;
            case DT_PREINIT_ARRAYSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PREINIT_ARRAYSZ");
                break;
            case DT_NUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_NUM");
                break;
            case DT_LOOS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_LOOS");
                break;
            case DT_HIOS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_HIOS");
                break;
            case DT_LOPROC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_LOPROC");
                break;
            case DT_HIPROC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_HIPROC (or DT_FILTER)");
                break;
            case DT_PROCNUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PROCNUM");
                break;
            case DT_VERSYM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERSYM");
                break;
            case DT_RELACOUNT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELACOUNT");
                break;
            case DT_RELCOUNT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELCOUNT");
                break;
            case DT_FLAGS_1:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FLAGS_1");
                break;
            case DT_VERDEF:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERDEF");
                break;
            case DT_VERDEFNUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERDEFNUM");
                break;
            case DT_VERNEED:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERNEED");
                break;
            case DT_VERNEEDNUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERNEEDNUM");
                break;
            case DT_AUXILIARY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_AUXILIARY");
                break;
            default:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%d", dynamic->d_tag);
                break;
        }
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " == ");
        switch (field) {
            case DT_NULL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_NULL");
                break;
            case DT_NEEDED:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_NEEDED");
                break;
            case DT_PLTRELSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PLTRELSZ");
                break;
            case DT_PLTGOT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PLTGOT");
                break;
            case DT_HASH:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_HASH");
                break;
            case DT_STRTAB:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_STRTAB");
                break;
            case DT_SYMTAB:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_SYMTAB");
                break;
            case DT_RELA:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELA");
                break;
            case DT_RELASZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELASZ");
                break;
            case DT_RELAENT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELAENT");
                break;
            case DT_STRSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_STRSZ");
                break;
            case DT_SYMENT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_SYMENT");
                break;
            case DT_INIT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_INIT");
                break;
            case DT_FINI:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FINI");
                break;
            case DT_SONAME:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_SONAME");
                break;
            case DT_RPATH:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RPATH");
                break;
            case DT_SYMBOLIC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_SYMBOLIC");
                break;
            case DT_REL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_REL");
                break;
            case DT_RELSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELSZ");
                break;
            case DT_RELENT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELENT");
                break;
            case DT_PLTREL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PLTREL");
                break;
            case DT_DEBUG:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_DEBUG");
                break;
            case DT_TEXTREL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_TEXTREL");
                break;
            case DT_JMPREL:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_JMPREL");
                break;
            case DT_BIND_NOW:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_BIND_NOW");
                break;
            case DT_INIT_ARRAY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_INIT_ARRAY");
                break;
            case DT_FINI_ARRAY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FINI_ARRAY");
                break;
            case DT_INIT_ARRAYSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_INIT_ARRAYSZ");
                break;
            case DT_FINI_ARRAYSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FINI_ARRAYSZ");
                break;
            case DT_RUNPATH:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RUNPATH");
                break;
            case DT_FLAGS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FLAGS");
                break;
            case DT_ENCODING:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_ENCODING (or DT_PREINIT_ARRAY)");
                break;
            case DT_PREINIT_ARRAYSZ:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PREINIT_ARRAYSZ");
                break;
            case DT_NUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_NUM");
                break;
            case DT_LOOS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_LOOS");
                break;
            case DT_HIOS:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_HIOS");
                break;
            case DT_LOPROC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_LOPROC");
                break;
            case DT_HIPROC:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_HIPROC (or DT_FILTER)");
                break;
            case DT_PROCNUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_PROCNUM");
                break;
            case DT_VERSYM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERSYM");
                break;
            case DT_RELACOUNT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELACOUNT");
                break;
            case DT_RELCOUNT:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_RELCOUNT");
                break;
            case DT_FLAGS_1:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_FLAGS_1");
                break;
            case DT_VERDEF:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERDEF");
                break;
            case DT_VERDEFNUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERDEFNUM");
                break;
            case DT_VERNEED:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERNEED");
                break;
            case DT_VERNEEDNUM:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_VERNEEDNUM");
                break;
            case DT_AUXILIARY:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "DT_AUXILIARY");
                break;
            default:
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%d (unknown)", field);
                break;
        }
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n");
        if (dynamic->d_tag == field) {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning %014p\n", __FILE__, __LINE__, __func__, dynamic->d_un.d_val);
            return dynamic->d_un.d_val;
        }
    }
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: returning 0\n", __FILE__, __LINE__, __func__);
    return 0;
}

Elf64_Word
get_dynamic_entryq(Elf64_Dyn *dynamic, int field)
{
    for (; dynamic->d_tag != DT_NULL; dynamic++) if (dynamic->d_tag == field) return dynamic->d_un.d_val;
    return 0;
}

int
if_valid(const char * file) {
    fprintf(stderr, "    if(!access(%s, %d)) return 0;\n", file, F_OK);
    if(!access(file, F_OK)) return 0;
    else return -1;
}

void *
dlopen_(const char * cc);

void *
dlsym_(const char * cc1, const char * cc2);

Elf64_Word
get_needed(const char * lib, const char * parent);

int dl = 0;
extern void bt(void);

void info(void) {
    read_section_header_table_(library[library_index].array, library[library_index]._elf_header, &library[library_index]._elf_symbol_table);

    read_symbol(library[library_index].array, library[library_index]._elf_symbol_table, get_section(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table, ".dynsym"));
    
    read_symbol(library[library_index].array, library[library_index]._elf_symbol_table, get_section(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table, ".symtab"));

    read_symbol(library[library_index].array, library[library_index]._elf_symbol_table, get_section(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table, ".plt.got"));

    
    read_symbol(
        library[library_index].array,
        library[library_index]._elf_symbol_table, 
        get_section(
            library[library_index].array,
            library[library_index]._elf_header,
            library[library_index]._elf_symbol_table,
            ".plt"
        )
    );
    print_section_headers_(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table);
    Elf64_Addr * GOT =
    library
    [
        library_index
    ]
    .
    _elf_symbol_table
    [
        get_section
        (
            library[library_index].array,
            library[library_index]._elf_header,
            library[library_index]._elf_symbol_table,
            ".got"
        )
    ]
    .sh_addr+library[library_index].mappingb;
    fprintf(stderr, "\n\naddress of GOT = %014p\n", GOT);
    for (int i = 0; i<=10; i++) {
//         if (i == 3) GOT[i] = &bt; // puts is located at GOT[3]
        fprintf(stderr, "address of GOT[%02d] = %014p, value of GOT[%02d] = %014p\n", i, &GOT[i], i, GOT[i]);
    }
    Elf64_Addr * PLT =
    library
    [
        library_index
    ]
    .
    _elf_symbol_table
    [
        get_section
        (
            library[library_index].array,
            library[library_index]._elf_header,
            library[library_index]._elf_symbol_table,
            ".plt"
        )
    ]
    .sh_addr+library[library_index].mappingb;
    fprintf(stderr, "\n\naddress of PLT = %014p\n", PLT);
    int align = library[library_index]._elf_symbol_table[get_section(library[library_index].array,library[library_index]._elf_header,library[library_index]._elf_symbol_table,".plt")].sh_addralign/8;
    for (int i = 0; i<=10; i++) {
        int ii = i*align;
//             if (i == 1 || i == 2) PLT[ii] = &bt;
        fprintf(stderr, "address of PLT[%02d] = %014p, value of PLT[%02d] = %014p\n", i, &PLT[ii], i, PLT[ii]);
    }
}
char *
find_needed(const char * lib, const char * symbol)
{
    char * sym = NULL;
    if (bytecmpq(ldd_quiet, char_n) == 1) fprintf(stderr, "\n\naquiring symbol \"%s\"\n", symbol);
    if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "current index %d holds \"%s\"\nsearching indexes for \"%s\" incase it has already been loaded\n", library_index, library[library_index].last_lib, lib);
    if (bytecmpq(sleep_r, char_y) == 0) sleep(12);
    int index = searchq(lib);
    int local_indexb = library_index;
	if (index != -1) library_index = index;
    int local_index = library_index;
    if ( if_valid(lib) == -1) {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "\"%s\" not found\n", lib);
        errno = 0;
        abort_();
        return "-1";
    }
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "%s:%d:%s: looking in %s for \"%s\"\n", __FILE__, __LINE__, __func__, lib, symbol);
    if (bytecmpq(sleep_r, char_y) == 0) sleep(12);
    if (bytecmpq(lib_origin, lib) == -1)
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n\n\n\n\nlooking in %s for \"%s\" (origin: %s)\n\n\n\n\n\n", lib, symbol, lib_origin);
        if (bytecmpq(sleep_, "YES") == 0) sleep(12);
        sym = lookup_symbol_by_name_(lib, symbol);
    }
    else
    if ((bytecmpq(lib_origin, lib) == 0 && first == 1) || dl == 1)
    {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n\n\n\n\nlooking in origin: %s for \"%s\" (origin: %s)\n\n\n\n\n\n", lib, symbol, lib_origin);
        if (bytecmpq(sleep_, "YES") == 0) sleep(12);
        sym = lookup_symbol_by_name_(lib, symbol);
    }
    else sym = NULL;
    index = searchq(lib);
	if (index != -1) library_index = index;
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "checking symbol \"%s\" has been found in %s\n", symbol, lib);
    if(sym == NULL)
    {
        if ((bytecmpq(lib_origin, lib) == 0 && first == 0) || dl == 0)
        {
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "skipping %s on first search for PLT (@plt) relocations, searching dependancies of %s\n", lib, lib);
            if (bytecmpq(sleep_r, char_y) == 0) sleep(12);
        } else
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "symbol has not been found in %s, searching dependancies of %s\n", lib, lib);
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n\nneeded for %s: %d\n", library[library_index].last_lib, library[library_index].NEEDED_COUNT);
        if (library[library_index].NEEDED_COUNT != 0) for (int i = 0; i<=library[library_index].NEEDED_COUNT-1; i++) {
			fprintf(stderr, "library[%d].NEEDED[%d] = %s\n", library_index, i, library[library_index].NEEDED[i]);
			if (bytecmpq(library[library_index].NEEDED[i], library[library_index].last_lib) == 0) abort();
		}
        if (bytecmpq(sleep_r, char_y) == 0) sleep(15);
        for (int i = 0; i<=library[library_index].NEEDED_COUNT-1; i++) {
            if (bytecmpq(lib, libc) == 0 && bytecmpq(library[library_index].NEEDED[i], interp) != 0) {
                if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "gnu libc detected, redirecting needed %s to %s\n", library[library_index].NEEDED[i], interp);
                library[library_index].NEEDED[i] = interp;
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "looking in %s for \"%s\"\n", library[library_index].NEEDED[i], symbol);
            }
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "looking in %s for \"%s\"\n", library[library_index].NEEDED[i], symbol);
            sym = find_needed(library[library_index].NEEDED[i], symbol);
			int index = searchq(lib);
			if (index != -1) library_index = index;
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "checking symbol \"%s\" has been found in %s of %s\n", symbol, library[library_index].NEEDED[i], lib);
            if(sym == NULL) {
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "symbol \"%s\" has not been found in %s of %s\n", symbol, library[library_index].NEEDED[i], lib);
                return NULL;
            }
            else {
            if (dl == 1) {
                info();
                dl = 0;
            }
            return sym;
            }
        }
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "error, %s has no dependancies, parent dependancy is %s\n", lib, library[library_index].parent);
        return NULL; // has no dependancies
    }
    else {
    if (dl == 1) {
        info();
        dl = 0;
    }
    return sym;
    }
}

int find_next_space() {
	int i = 0;
	while(1) {
		pp(library[i].struct_needed_init)
		pp(library[i+1].struct_needed_init)
		if (library[i].struct_needed_init == "initialized") i++;
		else return i;
	}
	return -1;
}

Elf64_Word
get_needed(const char * lib, const char * parent)
{
    if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "\n\naquiring \"%s\"\n", lib);
// 	sleep(5);
	check_init_needed();
    if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "current index %d holds \"%s\"\nsearching indexes for \"%s\" incase it has already been loaded\n", library_index, library[library_index].last_lib, lib);
    
    int index = search_neededq(lib);
    int local_indexb = library_index;
	if (index != -1) library_index = index;
	check_init_needed();
    int local_index = library_index;
	pi(library_index)
	ps(library[library_index].struct_needed_init)
    library[library_index].last_lib = lib;
    library[library_index].current_lib = lib;

    if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "checking if %s index %d is locked\n", library[library_index].last_lib, library_index);
    if (library[library_index].init_lock == 1) {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "get_needed: LOCKED\n");
    }
    else {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "get_needed: UNLOCKED\n");
    }
    if ( if_valid(lib) == -1) {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "\"%s\" not found\n", lib);
        errno = 0;
        abort_();
        return "-1";
    }
    if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "init\n");
    if (library[library_index].array != NULL) {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "%s has a non null array\n", library[library_index].last_lib);
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "index %d get_needed: LOCKING\n", library_index);
        library[library_index].init_lock = 1;
        if (library[library_index].init_lock == 1) {
            if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "status: LOCKED\n");
        }
        else {
            if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "status: UNLOCKED\n");
        }
    } else {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "%s has a null array\n", library[library_index].last_lib);
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "index %d get_needed: UNLOCKING\n", library_index);
        library[library_index].init_lock = 0;
        if (library[library_index].init_lock == 1) {
            if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "status: LOCKED\n");
        }
        else {
            if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "status: UNLOCKED\n");
        }
    }
    if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "init done\n");
    if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "current index %d holds \"%s\"\nsearching indexes for \"%s\" incase it has already been loaded\n", library_index, library[library_index].last_lib, lib);
    
    index = search_neededq(lib);
	if (index != -1) library_index = index;
	library_index = index;
	check_init_needed();
    local_index = library_index;
    library[library_index].last_lib = lib;
    library[library_index].current_lib = lib;

    Elf64_Dyn *dynamic = library[library_index].dynamic;
    Elf64_Dyn *dynamicb = library[library_index].dynamic;
    const char * arrayb = library[library_index].array;
    print_needed(lib, parent,depth_default, LDD);
    fprintf(stderr, "got needed\n");
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n\nneeded for %s: %d\n", library[library_index].last_lib, library[library_index].NEEDED_COUNT);
	int k = library_index;
    if (library[k].NEEDED_COUNT != 0) for (int i = 0; i<=library[k].NEEDED_COUNT-1; i++) {
		library_index = find_next_space();
		fprintf(stderr, "library[%d].NEEDED[%d] = %s\nnext available space is %d\n", k, i, library[k].NEEDED[i], library_index);
		sleep(10);
		dlopen(library[k].NEEDED[i]);
	}
//     if (bytecmpq(sleep_r, char_y) == 0) sleep(15);
    for (int i = 0; i<=library[k].NEEDED_COUNT-1; i++) get_needed(library[k].NEEDED[i], lib);
    library_index = local_indexb;
    if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "index %d get_needed: UNLOCKING\n", library_index);
    library[library_index].init_lock = 0;
    if (library[library_index].init_lock == 1) {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "status: LOCKED\n");
    }
    else {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "status: UNLOCKED\n");
    }
//     dlopen_(lib);
//     dlsym_(lib, "");
}

#define symbol_mode_S 1
#define symbol_mode_Z 2

void
r_init() {
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
}

int
r(Elf64_Rela *relocs, size_t relocs_size, const char * am_i_quiet) {
/*

Relocation
Relocation Types
Relocation entries describe how to alter the following instruction and data fields (bit numbers
appear in the lower box corners).


        word32
31                  0

word32      This specifies a 32-bit field occupying 4 bytes with arbitrary byte alignment. These
            values use the same byte order as other word values in the Intel architecture.

                        3    2    1    0
0x01020304           01   02   03   04
                31                     0

Calculations below assume the actions are transforming a relocatable file into either an
executable or a shared object file. Conceptually, the link editor merges one or more relocatable
files to form the output. It first decides how to combine and locate the input files, then updates
the symbol values, and finally performs the relocation. Relocations applied to executable or
shared object files are similar and accomplish the same result. Descriptions below use the
following notation.

A       This means the addend used to compute the value of the relocatable field.

B       This means the base address at which a shared object has been loaded into memory
        during execution. Generally, a shared object file is built with a 0 base virtual address,
        but the execution address will be different.

G       This means the offset into the global offset table at which the address of the
        relocation entry's symbol will reside during execution. See "Global Offset Table''
        below for more information.

GOT     This means the address of the global offset table. See "Global Offset Table'' below
        for more information.

L       This means the place (section offset or address) of the procedure linkage table entry
        for a symbol. A procedure linkage table entry redirects a function call to the proper
        destination. The link editor builds the initial procedure linkage table, and the
        dynamic linker modifies the entries during execution. See "Procedure Linkage
        Table'' below for more information.

P       This means the place (section offset or address) of the storage unit being relocated
        (computed using r_offset ).
        
S       This means the value of the symbol whose index resides in the relocation entry.

A relocation entry's r_offset value designates the offset or virtual address of the first byte
of the affected storage unit. The relocation type specifies which bits to change and how to
calculate their values. The Intel architecture uses only Elf32_Rel relocation entries, the field
to be relocated holds the addend. In all cases, the addend and the computed result use the same
byte order.

Name                Value       Field       Calculation
R_386_NONE          0           none        none
R_386_32            1           word32      S + A
R_386_PC32          2           word32      S + A - P
R_386_GOT32         3           word32      G + A
R_386_PLT32         4           word32      L + A - P
R_386_COPY          5           none        none
R_386_GLOB_DAT      6           word32      S
R_386_JMP_SLOT      7           word32      S
R_386_RELATIVE      8           word32      B + A
R_386_GOTOFF        9           word32      S + A - GOT
R_386_GOTPC         10          word32      GOT + A - P

Some relocation types have semantics beyond simple calculation.

R_386_GLOB_DAT      This relocation type is used to set a global offset table entry to the address
                    of the specified symbol. The special relocation type allows one to determine
                    the correspondence between symbols and global offset table entries.

R_386_JMP_SLOT      The link editor creates this relocation type for dynamic linking. Its offset
                    member gives the location of a procedure linkage table entry. The dynamic
                    linker modifies the procedure linkage table entry to transfer control to the
                    designated symbol's address [see "Procedure Linkage Table'' below].

R_386_RELATIVE      The link editor creates this relocation type for dynamic linking. Its offset
                    member gives a location within a shared object that contains a value
                    representing a relative address. The dynamic linker computes the
                    corresponding virtual address by adding the virtual address at which the
                    shared object was loaded to the relative address. Relocation entries for this
                    type must specify 0 for the symbol table index.

R_386_GOTOFF        This relocation type computes the difference between a symbol's value and
                    the address of the global offset table. It additionally instructs the link editor
                    to build the global offset table.
                    
R_386_GOTPC         This relocation type resembles R_386_PC32, except it uses the address
                    of the global offset table in its calculation. The symbol referenced in this
                    relocation normally is _GLOBAL_OFFSET_TABLE_, which additionally
                    instructs the link editor to build the global offset table.

*/

/*

Relocation
Relocation Types
Relocation entries describe how to alter the following instruction and data fields (bit numbers
appear in the lower box corners).

            word8  
            7       0
            
                word16
            15              0
            
                        word32
            31                              0

                                        word64
            63                                                              0

word8       This specifies a 8-bit field occupying 1 byte.

word16      This specifies a 16-bit field occupying 2 bytes with arbitrary
            byte alignment. These values use the same byte order as
            other word values in the AMD64 architecture.

word32      This specifies a 32-bit field occupying 4 bytes with arbitrary
            byte alignment. These values use the same byte order as
            other word values in the AMD64 architecture.

word64      This specifies a 64-bit field occupying 8 bytes with arbitrary
            byte alignment. These values use the same byte order as
            other word values in the AMD64 architecture.

wordclass   This specifies word64 for LP64 and specifies word32 for
            ILP32.

Calculations below assume the actions are transforming a relocatable file into either an
executable or a shared object file. Conceptually, the link editor merges one or more relocatable
files to form the output. It first decides how to combine and locate the input files, then updates
the symbol values, and finally performs the relocation. Relocations applied to executable or
shared object files are similar and accomplish the same result. Descriptions below use the
following notation.

A           Represents the addend used to compute the value of the relocatable field.

B           Represents the base address at which a shared object has been loaded into
            memory during execution. Generally, a shared object is built with a 0 base
            virtual address, but the execution address will be different.

G           Represents the offset into the global offset table at which the relocation
            entry’s symbol will reside during execution.

GOT         Represents the address of the global offset table.

L           Represents the place (section offset or address) of the Procedure Linkage Table
            entry for a symbol.

P           Represents the place (section offset or address) of the storage unit being
            relocated (computed using r_offset).

S           Represents the value of the symbol whose index resides in the relocation entry.

Z           Represents the size of the symbol whose index resides in the relocation entry.

A relocation entry's r_offset value designates the offset or virtual address of the first byte
of the affected storage unit. The relocation type specifies which bits to change and how to
calculate their values. The Intel architecture uses only Elf32_Rel relocation entries, the field
to be relocated holds the addend. In all cases, the addend and the computed result use the same
byte order.

The AMD64 LP64 ABI architecture uses only Elf64_Rela relocation entries with explicit addends.
The r_addend member serves as the relocation addend.

The AMD64 ILP32 ABI architecture uses only Elf32_Rela relocation entries in relocatable files.
Executable files or shared objects may use either Elf32_Rela or Elf32_Rel relocation entries.

Name                        Value       Field       Calculation
R_X86_64_NONE               0           none        none
R_X86_64_64                 1           word64      S + A
R_X86_64_PC32               2           word32      S + A - P
R_X86_64_GOT32              3           word32      G + A
R_X86_64_PLT32              4           word32      L + A - P
R_X86_64_COPY               5           none        none
R_X86_64_GLOB_DAT           6           wordclass   S
R_X86_64_JUMP_SLOT          7           wordclass   S
R_X86_64_RELATIVE           8           wordclass   B + A
R_X86_64_GOTPCREL           9           word32      G + GOT + A - P
R_X86_64_32                 10          word32      S + A
R_X86_64_32S                11          word32      S + A
R_X86_64_16                 12          word16      S + A
R_X86_64_PC16               13          word16      S + A - P
R_X86_64_8                  14          word8       S + A
R_X86_64_PC8                15          word8       S + A - P
R_X86_64_DTPMOD64           16          word64      none
R_X86_64_DTPOFF64           17          word64      none
R_X86_64_TPOFF64            18          word64      none
R_X86_64_TLSGD              19          word32      none
R_X86_64_TLSLD              20          word32      none
R_X86_64_DTPOFF32           21          word32      none
R_X86_64_GOTTPOFF           22          word32      none
R_X86_64_TPOFF32            23          word32      none                †
R_X86_64_PC64               24          word64      S + A - P           †
R_X86_64_GOTOFF64           25          word64      S + A - GOT
R_X86_64_GOTPC32            26          word32      GOT + A - P
R_X86_64_GOT64              27          word64      G + A
R_X86_64_GOTPCREL64         28          word64      G + GOT - P + A
R_X86_64_GOTPC64            29          word64      GOT - P + A
Deprecated                  30          none        none
R_X86_64_PLTOFF64           31          word64      L - GOT + A
R_X86_64_SIZE32             32          word32      Z + A               †
R_X86_64_SIZE64             33          word64      Z + A
R_X86_64_GOTPC32_TLSDESC    34          word32      none
R_X86_64_TLSDESC_CALL       35          none        none
R_X86_64_TLSDESC            36          word64×2    none
R_X86_64_IRELATIVE          37          wordclass   indirect (B + A)    ††
R_X86_64_RELATIVE64         38          word64      B + A
Deprecated                  39          none        none
Deprecated                  40          none        none
R_X86_64_GOTPCRELX          41          word32      G + GOT + A - P
R_X86_64_REX_GOTPCRELX      42          word32      G + GOT + A - P

†   This relocation is used only for LP64.
††  This relocation only appears in ILP32 executable files or shared objects.

Some relocation types have semantics beyond simple calculation.

R_386_GLOB_DAT      This relocation type is used to set a global offset table entry to the address
                    of the specified symbol. The special relocation type allows one to determine
                    the correspondence between symbols and global offset table entries.

R_386_JMP_SLOT      The link editor creates this relocation type for dynamic linking. Its offset
                    member gives the location of a procedure linkage table entry. The dynamic
                    linker modifies the procedure linkage table entry to transfer control to the
                    designated symbol's address [see "Procedure Linkage Table'' below].

R_386_RELATIVE      The link editor creates this relocation type for dynamic linking. Its offset
                    member gives a location within a shared object that contains a value
                    representing a relative address. The dynamic linker computes the
                    corresponding virtual address by adding the virtual address at which the
                    shared object was loaded to the relative address. Relocation entries for this
                    type must specify 0 for the symbol table index.

R_386_GOTOFF        This relocation type computes the difference between a symbol's value and
                    the address of the global offset table. It additionally instructs the link editor
                    to build the global offset table.
                    
R_386_GOTPC         This relocation type resembles R_386_PC32, except it uses the address
                    of the global offset table in its calculation. The symbol referenced in this
                    relocation normally is _GLOBAL_OFFSET_TABLE_, which additionally
                    instructs the link editor to build the global offset table.

*/
    if (relocs != library[library_index].mappingb && relocs_size != 0) {
        for (int i = 0; i < relocs_size  / sizeof(Elf64_Rela); i++) {
            Elf64_Rela *reloc = &relocs[i];
            int reloc_type = ELF64_R_TYPE(reloc->r_info);
            if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "i = %d,\t\tELF64_R_TYPE(reloc->r_info)\t= ", i);
            switch (reloc_type) {
                #if defined(__x86_64__)
                case R_X86_64_NONE:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_NONE                calculation: none\n");
                    library[library_index]._R_X86_64_NONE++;
                    break;
                }
                case R_X86_64_64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_64                  calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_64++;
                    break;
                }
                case R_X86_64_PC32:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_PC32                calculation: S + A - P (symbol value + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_PC32++;
                    break;
                }
                case R_X86_64_GOT32:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOT32               calculation: G + A (address of global offset table + r_addend)\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOT32++;
                    break;
                }
                case R_X86_64_PLT32:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_PLT32               calculation: L + A - P ((L: This means the place (section offset or address) of the procedure linkage table entry for a symbol) + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).) \n");
                    library[library_index]._R_X86_64_PLT32++;
                    break;
                }
                case R_X86_64_COPY:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_COPY                calculation: none\n");
                    library[library_index]._R_X86_64_COPY++;
                    break;
                }
                case R_X86_64_GLOB_DAT:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GLOB_DAT            calculation: S (symbol value)\n");
                    
                    if (bytecmpq(sleep_, "YES") == 0) sleep(5);
                    
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].mappingb, reloc->r_offset, library[library_index].mappingb+reloc->r_offset);
                    
                    char * symbol = NULL;
                    
                    if (bytecmpq(sleep_, "YES") == 0) sleep(5);
                    
                    if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "retrieving sample symbol\n");
                    if (self == 1 || readelf == 1) {
                        if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "skipping\n");
                        symbol = "NOT_PLT";
                    }
                    else {
						symbol = lookup_symbol_by_index_plt(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet);
					}
                    
                    if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "sample symbol retrieved\n");
                    if (bytecmpq(sleep_, "YES") == 0) sleep(5);
                    
                    if (bytecmpq(sleep_, "YES") == 0) sleep(15);
                    
                    char * symbol_;
                    if (bytecmpq(symbol, "NOT_PLT") == -1)
                    {
						ps(symbol)
                        int a_;
                        a?(a_ = 1):(a_ = 0);
                        a = 0;
						pi(a)
                        symbol_ = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_y);
                        if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "TESTING IF SYMBOL IS STRING\n");
                        if (test_string(symbol_) == 0)
                        {
                        if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "SYMBOL IS STRING\nSYMBOL IS %s\nTESTING IF %s IS \"WEAK ZERO\"\n", symbol_, symbol_);
                            if (bytecmp(symbol_, "WEAK ZERO") == 0) {
//                                 symbol_ = 0x7FFFFFFFFFFFFF;
                                symbol_ = 0x0;
                            }
                            else if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "SYMBOL IS NOT WEAK ZERO\n", symbol_);
                        }
                        else if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "SYMBOL IS NOT STRING\n");
                        a = a_;
						pi(a)
                        library[library_index]._R_X86_64_JUMP_SLOT++;
                        if (bytecmpq(am_i_quiet, char_n) == 0)printf("symbol_ = %014p\n", symbol_);
                        char * current = strdup(current_symbol);
                        if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "current symbol = %s\n", current);
                        if (search_resolved(current) == 0) {
                            if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "symbol \"%s\" is already resolved\n", current);
                        }
                        else {
                            if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "symbol \"%s\" is not resolved, attempting to resolve\n", current);
                            library[library_index].Resolved[library[library_index].Resolve_Index[0]] = current_symbol;
                            library[library_index].Resolve_Index[0] = library[library_index].Resolve_Index[0] + 1;
                            library[library_index].Resolved[library[library_index].Resolve_Index[0]] = "NULL";
                            *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = symbol_;
//                             *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = &bt;
                        }
                        *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = symbol_;
//                         *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = &bt;
                    }
                    else {
                        library[library_index]._R_X86_64_GLOB_DAT++;
                        
                        symbol_ = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n);
                        
                        char * current = strdup(current_symbol);
                        if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "current symbol = %s\n", current);
                        if (search_resolved(current) == 0) {
                            if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "symbol \"%s\" is already resolved\n", current);
                        }
                        else {
                            if (bytecmpq(am_i_quiet, char_n) == 0)fprintf(stderr, "symbol \"%s\" is not resolved, attempting to resolve\n", current);
                            library[library_index].Resolved[library[library_index].Resolve_Index[0]] = current_symbol;
                            library[library_index].Resolve_Index[0] = library[library_index].Resolve_Index[0] + 1;
                            library[library_index].Resolved[library[library_index].Resolve_Index[0]] = "NULL";
                            *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = symbol_;
//                             *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = &bt;
                        }
                    }
                    char ** addr = reloc->r_offset + library[library_index].mappingb;
                    test_address(addr); // %014p = %014p
                    break;
                }
                case R_X86_64_JUMP_SLOT:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_JUMP_SLOT           calculation: S (symbol value)\n");
                    
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "library[library_index].mappingb    = %014p\n", library[library_index].mappingb);
                    
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].mappingb, reloc->r_offset, library[library_index].mappingb+reloc->r_offset);
                    
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_y);
                    
                    char ** addr = reloc->r_offset + library[library_index].mappingb;
                    
                    test_address(addr);
                    
                    library[library_index]._R_X86_64_JUMP_SLOT++;
                    
                    break;
                }
                case R_X86_64_RELATIVE:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_RELATIVE            calculation: B + A (base address + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "library[library_index].mappingb    = %014p\n", library[library_index].mappingb);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].mappingb, reloc->r_offset, library[library_index].mappingb+reloc->r_offset);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_addend = %014p+%014p=%014p\n", library[library_index].mappingb, reloc->r_addend, ((char*)library[library_index].mappingb + reloc->r_addend) );
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = ((char*)library[library_index].mappingb + reloc->r_addend);
                    char ** addr = reloc->r_offset + library[library_index].mappingb;
                    test_address(addr);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_RELATIVE++;
                    break;
                }
                case R_X86_64_GOTPCREL:
                {
//                     if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(\
                    stderr, "\n\naddress of GOT[0] = %014p\n", \
                    (\
                    (Elf64_Addr *) \
                    lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_")\
                    )\
                    [0]\
                    );
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPCREL            calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).))) \n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPCREL++;
                    break;
                }
                case R_X86_64_32:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_32                  calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_32++;
                    break;
                }
                case R_X86_64_32S:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_32S                 calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_32S++;
                    break;
                }
                case R_X86_64_16:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_16                  calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_16++;
                    break;
                }
                case R_X86_64_PC16:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_PC16                calculation: S + A - P (symbol value + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).))\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_PC16++;
                    break;
                }
                case R_X86_64_8:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_8                   calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_8++;
                    break;
                }
                case R_X86_64_PC8:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_PC8                 calculation: S + A - P (symbol value + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).))\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_PC8++;
                    break;
                }
                case R_X86_64_DTPMOD64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_DTPMOD64\n");
                    library[library_index]._R_X86_64_DTPMOD64++;
                    break;
                }
                case R_X86_64_DTPOFF64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_DTPOFF64\n");
                    library[library_index]._R_X86_64_DTPOFF64++;
                    break;
                }
                case R_X86_64_TPOFF64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_TPOFF64\n");
                    library[library_index]._R_X86_64_TPOFF64++;
                    break;
                }
                case R_X86_64_TLSGD:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_TLSGD\n");
                    library[library_index]._R_X86_64_TLSGD++;
                    break;
                }
                case R_X86_64_TLSLD:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_TLSLD\n");
                    library[library_index]._R_X86_64_TLSLD++;
                    break;
                }
                case R_X86_64_DTPOFF32:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_DTPOFF32\n");
                    library[library_index]._R_X86_64_DTPOFF32++;
                    break;
                }
                case R_X86_64_GOTTPOFF:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTTPOFF\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTTPOFF++;
                    break;
                }
                case R_X86_64_TPOFF32:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_TPOFF32\n");
                    library[library_index]._R_X86_64_TPOFF32++;
                    break;
                }
                case R_X86_64_PC64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_PC64                calculation: S + A - P (symbol value + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).))\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_PC64++;
                    break;
                }
                case R_X86_64_GOTOFF64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTOFF64            calculation: S + A - GOT (symbol value + r_addend - address of global offset table)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTOFF64++;
                    break;
                }
                case R_X86_64_GOTPC32:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPC32             calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPC32++;
                    break;
                }
                case R_X86_64_GOT64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOT64               calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOT64++;
                    break;
                }
                case R_X86_64_GOTPCREL64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPCREL64          calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPCREL64++;
                    break;
                }
                case R_X86_64_GOTPC64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPC64             calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPC64++;
                    break;
                }
                case R_X86_64_GOTPLT64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPLT64            calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPLT64++;
                    break;
                }
                case R_X86_64_PLTOFF64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_PLTOFF64\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_PLTOFF64++;
                    break;
                }
                case R_X86_64_SIZE32:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_SIZE32                 calculation: Z + A (symbol size + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_Z, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_SIZE32++;
                    break;
                }
                case R_X86_64_SIZE64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_SIZE64                 calculation: Z + A (symbol size + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_Z, symbol_quiet, char_n) + reloc->r_addend+library[library_index].mappingb;
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_SIZE64++;
                    break;
                }
                case R_X86_64_GOTPC32_TLSDESC:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPC32_TLSDESC     calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPC32_TLSDESC++;
                    break;
                }
                case R_X86_64_TLSDESC_CALL:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_TLSDESC_CALL\n");
                    library[library_index]._R_X86_64_TLSDESC_CALL++;
                    break;
                }
                case R_X86_64_TLSDESC:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_TLSDESC\n");
                    library[library_index]._R_X86_64_TLSDESC++;
                    break;
                }
                case R_X86_64_IRELATIVE:
                {

                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_IRELATIVE                 calculation: (indirect) B + A (base address + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "library[library_index].mappingb    = %014p\n", library[library_index].mappingb);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].mappingb, reloc->r_offset, library[library_index].mappingb+reloc->r_offset);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_addend = %014p+%014p=%014p\n", library[library_index].mappingb, reloc->r_addend, ((char*)library[library_index].mappingb + reloc->r_addend) );
                    Elf64_Addr value;
//                     // changed, somehow this may cause a seg fault, dont use
//                     value = ((char*)library[library_index].mappingb + reloc->r_addend);
//                     value = ((Elf64_Addr (*) (void)) value) ();
//                     *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = value;
                    // original
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = ((char*)library[library_index].mappingb + reloc->r_addend);
                    //
                    char ** addr = reloc->r_offset + library[library_index].mappingb;
                    test_address(addr);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_IRELATIVE++;
                    break;
                }
                case R_X86_64_RELATIVE64:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_RELATIVE64                 calculation: B + A (base address + r_addend)\n");
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "library[library_index].mappingb    = %014p\n", library[library_index].mappingb);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].mappingb, reloc->r_offset, library[library_index].mappingb+reloc->r_offset);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "reloc->r_addend = %014p+%014p=%014p\n", library[library_index].mappingb, reloc->r_addend, ((char*)library[library_index].mappingb + reloc->r_addend) );
                    *((char**)((char*)library[library_index].mappingb + reloc->r_offset)) = ((char*)library[library_index].mappingb + reloc->r_addend);
                    char ** addr = reloc->r_offset + library[library_index].mappingb;
                    test_address(addr);
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "((char*)library[library_index].mappingb + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mappingb + reloc->r_offset));
                    library[library_index]._R_X86_64_RELATIVE64++;
                    break;
                }
                case R_X86_64_GOTPCRELX:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPCRELX           calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPCRELX++;
                    break;
                }
                case R_X86_64_REX_GOTPCRELX:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_REX_GOTPCRELX       calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_REX_GOTPCRELX++;
                    break;
                }
                case R_X86_64_NUM:
                {
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "\n\n\nR_X86_64_NUM\n");
                    library[library_index]._R_X86_64_NUM++;
                    break;
                }
                #endif
                default:
                    if (bytecmpq(GQ, char_n) == 0) if (bytecmpq(am_i_quiet, char_n) == 0) fprintf(stderr, "unknown type, got %d\n", reloc_type);
                    library[library_index]._R_X86_64_UNKNOWN++;
                    break;
            }
        }
    }
    if (bytecmpq(GQ, char_n) == 0) nl();
    if (bytecmpq(GQ, char_n) == 0) nl();
    if (bytecmpq(GQ, char_n) == 0) nl();
}

int r_summary() {
    if (bytecmpq(GQ, char_n) == 0) printf( "relocation summary:\n \
    _R_X86_64_NONE              = %d\n \
    _R_X86_64_64                = %d\n \
    _R_X86_64_PC32              = %d\n \
    _R_X86_64_GOT32             = %d\n \
    _R_X86_64_PLT32             = %d\n \
    _R_X86_64_COPY              = %d\n \
    _R_X86_64_GLOB_DAT          = %d\n \
    _R_X86_64_JUMP_SLOT         = %d\n \
    _R_X86_64_RELATIVE          = %d\n \
    _R_X86_64_GOTPCREL          = %d\n \
    _R_X86_64_32                = %d\n \
    _R_X86_64_32S               = %d\n \
    _R_X86_64_16                = %d\n \
    _R_X86_64_PC16              = %d\n \
    _R_X86_64_8                 = %d\n \
    _R_X86_64_PC8               = %d\n \
    _R_X86_64_DTPMOD64          = %d\n \
    _R_X86_64_DTPOFF64          = %d\n \
    _R_X86_64_TPOFF64           = %d\n \
    _R_X86_64_TLSGD             = %d\n \
    _R_X86_64_TLSLD             = %d\n \
    _R_X86_64_DTPOFF32          = %d\n \
    _R_X86_64_GOTTPOFF          = %d\n \
    _R_X86_64_TPOFF32           = %d\n \
    _R_X86_64_PC64              = %d\n \
    _R_X86_64_GOTOFF64          = %d\n \
    _R_X86_64_GOTPC32           = %d\n \
    _R_X86_64_GOT64             = %d\n \
    _R_X86_64_GOTPCREL64        = %d\n \
    _R_X86_64_GOTPC64           = %d\n \
    _Deprecated1                = %d\n \
    _R_X86_64_PLTOFF64          = %d\n \
    _R_X86_64_SIZE32            = %d\n \
    _R_X86_64_SIZE64            = %d\n \
    _R_X86_64_GOTPC32_TLSDESC   = %d\n \
    _R_X86_64_TLSDESC_CALL      = %d\n \
    _R_X86_64_TLSDESC           = %d\n \
    _R_X86_64_IRELATIVE         = %d\n \
    _R_X86_64_RELATIVE64        = %d\n \
    _Deprecated2                = %d\n \
    _Deprecated3                = %d\n \
    _R_X86_64_GOTPLT64          = %d\n \
    _R_X86_64_GOTPCRELX         = %d\n \
    _R_X86_64_REX_GOTPCRELX     = %d\n \
    _R_X86_64_NUM               = %d\n \
    _R_X86_64_UNKNOWN           = %d\n \
    total                       = %d\n", library[library_index]._R_X86_64_NONE, library[library_index]._R_X86_64_64, library[library_index]._R_X86_64_PC32, library[library_index]._R_X86_64_GOT32, library[library_index]._R_X86_64_PLT32, library[library_index]._R_X86_64_COPY, library[library_index]._R_X86_64_GLOB_DAT, library[library_index]._R_X86_64_JUMP_SLOT, library[library_index]._R_X86_64_RELATIVE, library[library_index]._R_X86_64_GOTPCREL, library[library_index]._R_X86_64_32, library[library_index]._R_X86_64_32S, library[library_index]._R_X86_64_16, library[library_index]._R_X86_64_PC16, library[library_index]._R_X86_64_8, library[library_index]._R_X86_64_PC8, library[library_index]._R_X86_64_DTPMOD64, library[library_index]._R_X86_64_DTPOFF64, library[library_index]._R_X86_64_TPOFF64, library[library_index]._R_X86_64_TLSGD, library[library_index]._R_X86_64_TLSLD, library[library_index]._R_X86_64_DTPOFF32, library[library_index]._R_X86_64_GOTTPOFF, library[library_index]._R_X86_64_TPOFF32, library[library_index]._R_X86_64_PC64, library[library_index]._R_X86_64_GOTOFF64, library[library_index]._R_X86_64_GOTPC32, library[library_index]._R_X86_64_GOT64, library[library_index]._R_X86_64_GOTPCREL64, library[library_index]._R_X86_64_GOTPC64, library[library_index]._Deprecated1, library[library_index]._R_X86_64_PLTOFF64, library[library_index]._R_X86_64_SIZE32, library[library_index]._R_X86_64_SIZE64, library[library_index]._R_X86_64_GOTPC32_TLSDESC, library[library_index]._R_X86_64_TLSDESC_CALL, library[library_index]._R_X86_64_TLSDESC, library[library_index]._R_X86_64_IRELATIVE, library[library_index]._R_X86_64_RELATIVE64, library[library_index]._Deprecated2, library[library_index]._Deprecated3, library[library_index]._R_X86_64_GOTPLT64, library[library_index]._R_X86_64_GOTPCRELX, library[library_index]._R_X86_64_REX_GOTPCRELX, library[library_index]._R_X86_64_NUM, library[library_index]._R_X86_64_UNKNOWN, library[library_index]._R_X86_64_NONE + library[library_index]._R_X86_64_64 + library[library_index]._R_X86_64_PC32 + library[library_index]._R_X86_64_GOT32 + library[library_index]._R_X86_64_PLT32 + library[library_index]._R_X86_64_COPY + library[library_index]._R_X86_64_GLOB_DAT + library[library_index]._R_X86_64_JUMP_SLOT + library[library_index]._R_X86_64_RELATIVE + library[library_index]._R_X86_64_GOTPCREL + library[library_index]._R_X86_64_32 + library[library_index]._R_X86_64_32S + library[library_index]._R_X86_64_16 + library[library_index]._R_X86_64_PC16 + library[library_index]._R_X86_64_8 + library[library_index]._R_X86_64_PC8 + library[library_index]._R_X86_64_DTPMOD64 + library[library_index]._R_X86_64_DTPOFF64 + library[library_index]._R_X86_64_TPOFF64 + library[library_index]._R_X86_64_TLSGD + library[library_index]._R_X86_64_TLSLD + library[library_index]._R_X86_64_DTPOFF32 + library[library_index]._R_X86_64_GOTTPOFF + library[library_index]._R_X86_64_TPOFF32 + library[library_index]._R_X86_64_PC64 + library[library_index]._R_X86_64_GOTOFF64 + library[library_index]._R_X86_64_GOTPC32 + library[library_index]._R_X86_64_GOT64 + library[library_index]._R_X86_64_GOTPCREL64 + library[library_index]._R_X86_64_GOTPC64 + library[library_index]._Deprecated1 + library[library_index]._R_X86_64_PLTOFF64 + library[library_index]._R_X86_64_SIZE32 + library[library_index]._R_X86_64_SIZE64 + library[library_index]._R_X86_64_GOTPC32_TLSDESC + library[library_index]._R_X86_64_TLSDESC_CALL + library[library_index]._R_X86_64_TLSDESC + library[library_index]._R_X86_64_IRELATIVE + library[library_index]._R_X86_64_RELATIVE64 + library[library_index]._Deprecated2 + library[library_index]._Deprecated3 + library[library_index]._R_X86_64_GOTPLT64 + library[library_index]._R_X86_64_GOTPCRELX + library[library_index]._R_X86_64_REX_GOTPCRELX + library[library_index]._R_X86_64_NUM + library[library_index]._R_X86_64_UNKNOWN);
}

int
init_(const char * filename) {
	puts("INIT_ CALLED");
// 	sleep (5);
    init(filename);
    if (library[library_index].init__ == 1) return 0;
    library[library_index]._elf_header = (Elf64_Ehdr *) library[library_index].array;
    read_section_header_table_(library[library_index].array, library[library_index]._elf_header, &library[library_index]._elf_symbol_table);
    library[library_index].RELA_PLT_SIZE=library[library_index]._elf_symbol_table[get_section(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table, ".rela.plt")].sh_size;
    if(!strncmp((char*)library[library_index]._elf_header->e_ident, "\177ELF", 4)) {
        map();
        char *load_addr = NULL;
        uint32_t load_offset = 0;
        for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
            char * section_;
            switch(library[library_index]._elf_program_header[i].p_type)
            {
                case PT_NULL:
                    section_="PT_NULL";
                    break;
                case PT_LOAD:
                    section_="PT_LOAD";
                    load_addr = (const char *)library[library_index]._elf_program_header->p_vaddr;
                    load_offset = library[library_index]._elf_program_header->p_offset;
                    break;
                case PT_DYNAMIC:
                    section_="PT_DYNAMIC";
                    library[library_index].PT_DYNAMIC_=i;
                    break;
                case PT_INTERP:
                    section_="PT_INTERP";
                    break;
                case PT_NOTE:
                    section_="PT_NOTE";
                    break;
                case PT_SHLIB:
                    section_="PT_SHLIB";
                    break;
                case PT_PHDR:
                    section_="PT_PHDR";
                    break;
                case PT_TLS:
                    section_="PT_TLS";
                    break;
                case PT_NUM:
                    section_="PT_NUM";
                    break;
                case PT_LOOS:
                    section_="PT_LOOS";
                    break;
                case PT_GNU_EH_FRAME:
                    section_="PT_GNU_EH_FRAME";
                    break;
                case PT_GNU_STACK:
                    section_="PT_GNU_STACK";
                    break;
                case PT_GNU_RELRO:
                    section_="PT_GNU_RELRO";
                    break;
                case PT_SUNWBSS:
                    section_="PT_SUNWBSS";
                    break;
                case PT_SUNWSTACK:
                    section_="PT_SUNWSTACK";
                    break;
                case PT_HIOS:
                    section_="PT_HIOS";
                    break;
                case PT_LOPROC:
                    section_="PT_LOPROC";
                    break;
                case PT_HIPROC:
                    section_="PT_HIPROC";
                    break;
                default:
                    section_="Unknown";
                    break;
            }
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "attempting to read PT_INTERP of %s\n", library[library_index].last_lib);
            if (section_ == "PT_INTERP")
            {
                read_fast_verify(library[library_index].array, library[library_index].len, &library[library_index].interp, (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                __lseek_string__(&library[library_index].interp, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "interp of %s PT_INTERP = %s\n", library[library_index].last_lib, library[library_index].interp);
            }
            if (section_ == "PT_DYNAMIC")
            {
                read_fast_verify(library[library_index].array, library[library_index].len, &library[library_index].tmp99D, (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                __lseek_string__(&library[library_index].tmp99D, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_offset);
            }
        }
        if (library[library_index].PT_DYNAMIC_ != 0) {
            library[library_index].dynamic = library[library_index].tmp99D;
            for (; library[library_index].dynamic->d_tag != DT_NULL; library[library_index].dynamic++) {
                if (library[library_index].dynamic->d_tag == DT_STRTAB) {
                const char *strtab_addr = (const char *)library[library_index].dynamic->d_un.d_ptr;
                uint32_t strtab_offset = load_offset + (strtab_addr - load_addr);
                library[library_index].strtab = library[library_index].array + strtab_offset;
                }
            }
            if (library[library_index].strtab == NULL) {
                abort_();
            }
            library[library_index].dynamic = library[library_index].tmp99D;
            library[library_index].GOT2 = library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_PLTGOT);

            r_init();
            r(library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_RELA), get_dynamic_entry(library[library_index].dynamic, DT_RELASZ), relocation_quiet);
            r(library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_JMPREL), library[library_index].RELA_PLT_SIZE, relocation_quiet);
            r(library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_BIND_NOW), library[library_index].RELA_PLT_SIZE, relocation_quiet);
//             r(library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_PLTREL), get_dynamic_entry(library[library_index].dynamic, DT_PLTRELSZ), relocation_quiet);
            r_summary();
            if (produce_backtrace == true) bt();
        }
    } else return -1;
    library[library_index].init__ = 1;
    return 0;
}

int
initv_(const char * filename) {
    init(filename);
    if (library[library_index].init__ == 1) return 0;
    setlocale(LC_NUMERIC, "en_US.utf-8"); /* important */
        library[library_index]._elf_header = (Elf64_Ehdr *) library[library_index].array;
        read_section_header_table_(library[library_index].array, library[library_index]._elf_header, &library[library_index]._elf_symbol_table);
        library[library_index].RELA_PLT_SIZE=library[library_index]._elf_symbol_table[get_section(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table, ".rela.plt")].sh_size;
        if(!strncmp((char*)library[library_index]._elf_header->e_ident, "\177ELF", 4)) {
//                 ELF Header:
//                 Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
//                 Class:                             ELF64
//                 Data:                              2's complement, little endian
//                 Version:                           1 (current)
//                 OS/ABI:                            UNIX - System V
//                 ABI Version:                       0
//                 Type:                              EXEC (Executable file)
//                 Machine:                           Advanced Micro Devices X86-64
//                 Version:                           0x1
//                 Entry point address:               0x400820
//                 Start of program headers:          64 (bytes into file)
//                 Start of section headers:          11408 (bytes into file)
//                 Flags:                             0x0
//                 Size of this header:               64 (bytes)
//                 Size of program headers:           56 (bytes)
//                 Number of program headers:         9
//                 Size of section headers:           64 (bytes)
//                 Number of section headers:         30
//                 Section header string table index: 29
//
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Name:\t\t %s\n", filename);
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ELF Identifier\t %s (", library[library_index]._elf_header->e_ident);
            __print_quoted_string__(library[library_index]._elf_header->e_ident, sizeof(library[library_index]._elf_header->e_ident), QUOTE_FORCE_HEX|QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " )\n");

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Architecture\t ");
            switch(library[library_index]._elf_header->e_ident[EI_CLASS])
            {
                case ELFCLASSNONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case ELFCLASS32:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "32-bit\n");
                    break;

                case ELFCLASS64:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "64-bit\n");
                    break;
                    
                case ELFCLASSNUM:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NUM ( unspecified )\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown CLASS\n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Data Type\t ");
            switch(library[library_index]._elf_header->e_ident[EI_DATA])
            {
                case ELFDATANONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case ELFDATA2LSB:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "2's complement, little endian\n");
                    break;

                case ELFDATA2MSB:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "2's complement, big endian\n");
                    break;
                    
                case ELFDATANUM:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NUM ( unspecified )\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Version\t\t ");
            switch(library[library_index]._elf_header->e_ident[EI_VERSION])
            {
                case EV_NONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case EV_CURRENT:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Current\n");
                    break;

                case EV_NUM:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NUM ( Unspecified )\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OS ABI\t\t ");
            switch(library[library_index]._elf_header->e_ident[EI_OSABI])
            {
                case ELFOSABI_NONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "UNIX System V ABI\n");
                    break;

//                     case ELFOSABI_SYSV:
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "SYSV\n");
//                         break;
// 
                case ELFOSABI_HPUX:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "HP-UX\n");
                    break;

                case ELFOSABI_NETBSD:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NetBSD\n");
                    break;

                case ELFOSABI_GNU:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GNU\n");
                    break;

//                     case ELFOSABI_LINUX:
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Linux\n");
//                         break;
// 
                case ELFOSABI_SOLARIS:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Sun Solaris\n");
                    break;

                case ELFOSABI_AIX:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ABM AIX\n");
                    break;

                case ELFOSABI_FREEBSD:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "FreeBSD\n");
                    break;

                case ELFOSABI_TRU64:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Compaq Tru64\n");
                    break;

                case ELFOSABI_MODESTO:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Novell Modesto\n");
                    break;

                case ELFOSABI_OPENBSD:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OpenBSD\n");
                    break;

//                 case ELFOSABI_ARM_AEABI: // not in musl
//                     if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ARM EABI\n");
//                     break;

//                 case ELFOSABI_ARM: // not in musl
//                     if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ARM\n");
//                     break;

                case ELFOSABI_STANDALONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Standalone (embedded) application\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "File Type\t ");
            switch(library[library_index]._elf_header->e_type)
            {
                case ET_NONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case ET_REL:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Relocatable file\n");
                    break;

                case ET_EXEC:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Executable file\n");
                    break;

                case ET_DYN:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Shared object file\n");
                    break;

                case ET_CORE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Core file\n");
                    break;

                case ET_NUM:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Number of defined types\n");
                    break;

                case ET_LOOS:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OS-specific range start\n");
                    break;

                case ET_HIOS:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OS-specific range end\n");
                    break;

                case ET_LOPROC:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Processor-specific range start\n");
                    break;

                case ET_HIPROC:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Processor-specific range end\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Machine\t\t ");
            switch(library[library_index]._elf_header->e_machine)
            {
                case EM_NONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case EM_386:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "INTEL x86\n");
                        break;

                case EM_X86_64:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "AMD x86-64 architecture\n");
                        break;

                case EM_ARM:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ARM\n");
                        break;
                default:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown\n");
                break;
            }
            
            /* Entry point */
            int entry=library[library_index]._elf_header->e_entry;
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Entry point\t %014p\n", library[library_index]._elf_header->e_entry);
            

            /* ELF header size in bytes */
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ELF header size\t %014p\n", library[library_index]._elf_header->e_ehsize);

            /* Program Header */
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Program Header\t %014p (%d entries with a total of %d bytes)\n",
            library[library_index]._elf_header->e_phoff,
            library[library_index]._elf_header->e_phnum,
            library[library_index]._elf_header->e_phentsize
            );
            map();
// continue analysis
            char *load_addr = NULL;
            uint32_t load_offset = 0;
            for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
                char * section_;
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "p_type:\t\t\t/* Segment type */\t\t= ");
                switch(library[library_index]._elf_program_header[i].p_type)
                {
                    case PT_NULL:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_NULL\t\t/* Program header table entry unused */\n");
                        section_="PT_NULL";
                        break;
                    case PT_LOAD:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOAD\t\t/* Loadable program segment */\n");
                        section_="PT_LOAD";
                        load_addr = (const char *)library[library_index]._elf_program_header->p_vaddr;
                        load_offset = library[library_index]._elf_program_header->p_offset;
                        break;
                    case PT_DYNAMIC:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_DYNAMIC\t\t/* Dynamic linking information */\n");
                        section_="PT_DYNAMIC";
                        library[library_index].PT_DYNAMIC_=i;
                        break;
                    case PT_INTERP:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_INTERP\t\t/* Program interpreter */\n");
                        section_="PT_INTERP";
                        break;
                    case PT_NOTE:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_NOTE\t\t/* Auxiliary information */\n");
                        section_="PT_NOTE";
                        break;
                    case PT_SHLIB:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_SHLIB\t\t/* Reserved */\n");
                        section_="PT_SHLIB";
                        break;
                    case PT_PHDR:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_PHDR\t\t/* Entry for header table itself */\n");
                        section_="PT_PHDR";
                        break;
                    case PT_TLS:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_TLS\t\t/* Thread-local storage segment */\n");
                        section_="PT_TLS";
                        break;
                    case PT_NUM:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_NUM\t\t/* Number of defined types */\n");
                        section_="PT_NUM";
                        break;
                    case PT_LOOS:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOOS\t\t/* Start of OS-specific */\n");
                        section_="PT_LOOS";
                        break;
                    case PT_GNU_EH_FRAME:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_GNU_EH_FRAME\t/* GCC .eh_frame_hdr segment */\n");
                        section_="PT_GNU_EH_FRAME";
                        break;
                    case PT_GNU_STACK:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_GNU_STACK\t\t/* Indicates stack executability */\n");
                        section_="PT_GNU_STACK";
                        break;
                    case PT_GNU_RELRO:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_GNU_RELRO\t\t/* Read-only after relocation */\n");
                        section_="PT_GNU_RELRO";
                        break;
                    case PT_SUNWBSS:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_SUNWBSS\t\t/* Sun Specific segment */\n");
                        section_="PT_SUNWBSS";
                        break;
                    case PT_SUNWSTACK:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_SUNWSTACK\t\t/* Stack segment */\n");
                        section_="PT_SUNWSTACK";
                        break;
                    case PT_HIOS:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_HIOS\t\t/* End of OS-specific */\n");
                        section_="PT_HIOS";
                        break;
                    case PT_LOPROC:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOPROC\t\t/* Start of processor-specific */\n");
                        section_="PT_LOPROC";
                        break;
                    case PT_HIPROC:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_HIPROC\t\t/* End of processor-specific */\n");
                        section_="PT_HIPROC";
                        break;
                    default:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown\n");
                        section_="Unknown";
                        break;
                }
                if (section_ == "PT_DYNAMIC")
                {
                    // obtain PT_DYNAMIC into seperate library[library_index].array for use later
                    read_fast_verify(library[library_index].array, library[library_index].len, &library[library_index].tmp99D, (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                    __lseek_string__(&library[library_index].tmp99D, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_offset);
                }
                char * tmp99;/* = malloc((library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));*/
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ATTEMPING TO READ\n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "reading                %014p\n", (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                read_fast_verify(library[library_index].array, library[library_index].len, &tmp99, (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "correcting position by %014p\n", library[library_index]._elf_program_header[i].p_offset);
                __lseek_string__(&tmp99, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "reading                %d\n", library[library_index]._elf_program_header[i].p_memsz);
                __print_quoted_string__(tmp99, library[library_index]._elf_program_header[i].p_memsz, 0, "print");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\nREAD\n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[i].p_flags, library[library_index]._elf_program_header[i].p_offset, library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mappingb, library[library_index]._elf_program_header[i].p_paddr, library[library_index]._elf_program_header[i].p_filesz, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_align);
                if (bytecmpq(GQ, char_n) == 0) nl();
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_flags: %014p", library[library_index]._elf_program_header[i].p_flags);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_offset: %014p", library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_vaddr:  %014p", library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mappingb);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_paddr: %014p", library[library_index]._elf_program_header[i].p_paddr);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_filesz: %014p", library[library_index]._elf_program_header[i].p_filesz);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_memsz: %014p", library[library_index]._elf_program_header[i].p_memsz);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_align: %014p\n", library[library_index]._elf_program_header[i].p_align);
            }

            if (library[library_index].PT_DYNAMIC_ != 0) {
// A PT_DYNAMIC program header element points at the .dynamic section, explained in
// "Dynamic Section" below. The .got and .plt sections also hold information related to
// position-independent code and dynamic linking. Although the .plt appears in a text segment
// above, it may reside in a text or a data segment, depending on the processor.
// 
// As "Sections" describes, the .bss section has the type SHT_NOBITS. Although it occupies no
// space in the file, it contributes to the segment's memory image. Normally, these uninitialized
// data reside at the end of the segment, thereby making p_memsz larger than p_filesz.
// 

                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOAD 1 = \n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_flags, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_offset, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_vaddr+library[library_index].mappingb, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_paddr, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_filesz, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_memsz, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_align);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOAD 2 = \n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_flags, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_offset, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr+library[library_index].mappingb, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_paddr, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_filesz, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_memsz, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_align);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "first PT_LOAD library[library_index]._elf_program_header[%d]->p_paddr = \n%014p\n", library[library_index].First_Load_Header_index, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_paddr+library[library_index].mappingb);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Second PT_LOAD library[library_index]._elf_program_header[%d]->p_paddr = \n%014p\n", library[library_index].Last_Load_Header_index, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_paddr+library[library_index].mappingb);
                library[library_index].dynamic = library[library_index].tmp99D;
                for (; library[library_index].dynamic->d_tag != DT_NULL; library[library_index].dynamic++) {
                    if (library[library_index].dynamic->d_tag == DT_STRTAB) {
                    const char *strtab_addr = (const char *)library[library_index].dynamic->d_un.d_ptr;
                    uint32_t strtab_offset = load_offset + (strtab_addr - load_addr);
                    library[library_index].strtab = library[library_index].array + strtab_offset;
                    }
                }
                if (library[library_index].strtab == NULL) {
                    abort_();
                }
                library[library_index].dynamic = library[library_index].tmp99D;

                library[library_index].GOT2 = library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_PLTGOT);
//                 library[library_index].PLT = library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_PLTREL);

//                 if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "printing symbol data\n");
//                 Elf64_Sym *syms = library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_SYMTAB);
//                 symbol1(library[library_index].array, syms, 0);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "examining current entries:\n");
                get_dynamic_entry(library[library_index].dynamic, -1);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "printing relocation data\n");
                // needs to be the address of the mapping itself, not the base address
                r_init();
                r(library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_RELA), get_dynamic_entry(library[library_index].dynamic, DT_RELASZ), relocation_quiet);
                r(library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_JMPREL), library[library_index].RELA_PLT_SIZE, relocation_quiet);
                r(library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_BIND_NOW), library[library_index].RELA_PLT_SIZE, relocation_quiet);
//                 r(library[library_index].mappingb + get_dynamic_entry(library[library_index].dynamic, DT_PLTREL), get_dynamic_entry(library[library_index].dynamic, DT_PLTRELSZ), relocation_quiet);
                r_summary();
            }
//             if (bytecmpq(GQ, char_n) == 0) nl();
            
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Section Header\t \
library[library_index]._elf_header->e_shstrndx %014p (\
library[library_index]._elf_header->e_shnum = %d entries with a total of \
library[library_index]._elf_header->e_shentsize = %d (should match %d) bytes, offset is \
library[library_index]._elf_header->e_shoff = %014p)\n",\
            library[library_index]._elf_header->e_shstrndx,\
            library[library_index]._elf_header->e_shnum,\
            library[library_index]._elf_header->e_shentsize,\
            sizeof(Elf64_Shdr),\
            library[library_index]._elf_header->e_shoff,\
            (char *)library[library_index].array + library[library_index]._elf_header->e_shoff\
            );
            read_section_header_table_(library[library_index].array, library[library_index]._elf_header, &library[library_index]._elf_symbol_table);
            print_section_headers_(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table);
            print_symbols(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table);
        } else {
                /* Not ELF file */
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ELFMAGIC not found\n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "header = ");
                __print_quoted_string__(library[library_index].array, sizeof(library[library_index]._elf_header->e_ident), QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ELF Identifier\t %s (", library[library_index]._elf_header->e_ident);
                __print_quoted_string__(library[library_index]._elf_header->e_ident, sizeof(library[library_index]._elf_header->e_ident), QUOTE_FORCE_HEX|QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " )\n");
            return 0;
        }
    library[library_index].init__ = 1;
    return 0;
}

int
readelf_(const char * filename);

void *
dlopen_(const char * cc)
{
	puts("DLOPEN_ CALLED");
// 	sleep (5);
    if (library[library_index].init_lock == 1) {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "dlopen: LOCKED\n");
        return "-1";
    };
    if ( if_valid(cc) == -1) {
        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\"%s\" not found\n", cc);
        errno = 0;
        abort_();
        return "-1";
    }
    init_(cc);
//     library_index++;
    library[library_index].library_name = cc;
    library[library_index].library_first_character = library[library_index].library_name[0];
    library[library_index].library_len = strlen(library[library_index].library_name);
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "dlopen: adding %s to index %d\n", cc, library_index);
    return cc;
}

void *
dlopen(const char * cc) {
//     int index = searchq(cc);
// 	pi(index);
// 	if (index != -1) return -1;
	printf("\n\nDLOPEN CALLED WITH %s\n", cc);
	if (bytecmpq(cc, libc) == 0) {
// 		check_init_needed();
// 		print_needed(cc, "-1",depth_default, LDD);
// 		fprintf(stderr, "got needed\n");
// 		if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n\nneeded for %s: %d\n", library[library_index].last_lib, library[library_index].NEEDED_COUNT);
// // 		int n = library_index;
		library_index=1;
// // 		pi(library_index);
		dlopen(interp);
		library_index = 0;
	}
// 	sleep(5);
//     readelf_(cc);
//     abort_();
// 	int n = library_index;
// 	pi(library_index);
// 	sleep(5);
//     get_needed(cc, "-1");
// 	library_index = n;
	puts("DLOPEN: AQUIRED NEEDED");
// 	sleep(5);
// 	init_(cc);
    return dlopen_(cc);
}

void *
dlsym(const char * cc1, const char * cc2)
{
    if (library[library_index].init_lock == 1) {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "dlsym: LOCKED\n");
        return "-1";
    };
    
    if (bytecmpq(cc1,"-1") == 0) return "-1";
    library_index = search(cc1);
    library[library_index].library_symbol = cc2;
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "dlsym: adding %s from %s\n", library[library_index].library_symbol, library[library_index].library_name);
    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "calling find needed\n");
    dl = 1;
    find_needed(cc1, cc2);
}

void *
dlsym_(const char * cc1, const char * cc2)
{
    if (library[library_index].init_lock == 1) {
        if (bytecmpq(ldd_quiet, char_n) == 0) fprintf(stderr, "dlsym: LOCKED\n");
        return "-1";
    }
    if (bytecmpq(cc1,"-1") == 0) return "-1";
    library_index = search(cc1);
    return lookup_symbol_by_name_(cc1, cc2);
}

int
readelf_(const char * filename) {
    readelf = 1;
    setlocale(LC_NUMERIC, "en_US.utf-8"); /* important */
    init_(filename);
        if(!strncmp((char*)library[library_index]._elf_header->e_ident, "\177ELF", 4)) {
//                 ELF Header:
//                 Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
//                 Class:                             ELF64
//                 Data:                              2's complement, little endian
//                 Version:                           1 (current)
//                 OS/ABI:                            UNIX - System V
//                 ABI Version:                       0
//                 Type:                              EXEC (Executable file)
//                 Machine:                           Advanced Micro Devices X86-64
//                 Version:                           0x1
//                 Entry point address:               0x400820
//                 Start of program headers:          64 (bytes into file)
//                 Start of section headers:          11408 (bytes into file)
//                 Flags:                             0x0
//                 Size of this header:               64 (bytes)
//                 Size of program headers:           56 (bytes)
//                 Number of program headers:         9
//                 Size of section headers:           64 (bytes)
//                 Number of section headers:         30
//                 Section header string table index: 29
//
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Name:\t\t %s\n", filename);
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ELF Identifier\t %s (", library[library_index]._elf_header->e_ident);
            __print_quoted_string__(library[library_index]._elf_header->e_ident, sizeof(library[library_index]._elf_header->e_ident), QUOTE_FORCE_HEX|QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " )\n");

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Architecture\t ");
            switch(library[library_index]._elf_header->e_ident[EI_CLASS])
            {
                case ELFCLASSNONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case ELFCLASS32:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "32-bit\n");
                    break;

                case ELFCLASS64:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "64-bit\n");
                    break;
                    
                case ELFCLASSNUM:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NUM ( unspecified )\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown CLASS\n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Data Type\t ");
            switch(library[library_index]._elf_header->e_ident[EI_DATA])
            {
                case ELFDATANONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case ELFDATA2LSB:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "2's complement, little endian\n");
                    break;

                case ELFDATA2MSB:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "2's complement, big endian\n");
                    break;
                    
                case ELFDATANUM:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NUM ( unspecified )\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Version\t\t ");
            switch(library[library_index]._elf_header->e_ident[EI_VERSION])
            {
                case EV_NONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case EV_CURRENT:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Current\n");
                    break;

                case EV_NUM:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NUM ( Unspecified )\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OS ABI\t\t ");
            switch(library[library_index]._elf_header->e_ident[EI_OSABI])
            {
                case ELFOSABI_NONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "UNIX System V ABI\n");
                    break;

//                     case ELFOSABI_SYSV:
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "SYSV\n");
//                         break;
// 
                case ELFOSABI_HPUX:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "HP-UX\n");
                    break;

                case ELFOSABI_NETBSD:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "NetBSD\n");
                    break;

                case ELFOSABI_GNU:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "GNU\n");
                    break;

//                     case ELFOSABI_LINUX:
//                         if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Linux\n");
//                         break;
// 
                case ELFOSABI_SOLARIS:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Sun Solaris\n");
                    break;

                case ELFOSABI_AIX:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ABM AIX\n");
                    break;

                case ELFOSABI_FREEBSD:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "FreeBSD\n");
                    break;

                case ELFOSABI_TRU64:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Compaq Tru64\n");
                    break;

                case ELFOSABI_MODESTO:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Novell Modesto\n");
                    break;

                case ELFOSABI_OPENBSD:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OpenBSD\n");
                    break;

//                 case ELFOSABI_ARM_AEABI:
//                     if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ARM EABI\n");
//                     break;

//                 case ELFOSABI_ARM:
//                     if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ARM\n");
//                     break;

                case ELFOSABI_STANDALONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Standalone (embedded) application\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "File Type\t ");
            switch(library[library_index]._elf_header->e_type)
            {
                case ET_NONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case ET_REL:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Relocatable file\n");
                    break;

                case ET_EXEC:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Executable file\n");
                    break;

                case ET_DYN:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Shared object file\n");
                    break;

                case ET_CORE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Core file\n");
                    break;

                case ET_NUM:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Number of defined types\n");
                    break;

                case ET_LOOS:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OS-specific range start\n");
                    break;

                case ET_HIOS:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "OS-specific range end\n");
                    break;

                case ET_LOPROC:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Processor-specific range start\n");
                    break;

                case ET_HIPROC:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Processor-specific range end\n");
                    break;

                default:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Machine\t\t ");
            switch(library[library_index]._elf_header->e_machine)
            {
                case EM_NONE:
                    if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "None\n");
                    break;

                case EM_386:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "INTEL x86\n");
                        break;

                case EM_X86_64:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "AMD x86-64 architecture\n");
                        break;

                case EM_ARM:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ARM\n");
                        break;
                default:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown\n");
                break;
            }
            
            /* Entry point */
            int entry=library[library_index]._elf_header->e_entry;
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Entry point\t %014p\n", library[library_index]._elf_header->e_entry);
            

            /* ELF header size in bytes */
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ELF header size\t %014p\n", library[library_index]._elf_header->e_ehsize);

            /* Program Header */
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Program Header\t %014p (%d entries with a total of %d bytes)\n",
            library[library_index]._elf_header->e_phoff,
            library[library_index]._elf_header->e_phnum,
            library[library_index]._elf_header->e_phentsize
            );
// continue analysis
            for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
                char * section_;
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "p_type:\t\t\t/* Segment type */\t\t= ");
                switch(library[library_index]._elf_program_header[i].p_type)
                {
                    case PT_NULL:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_NULL\t\t/* Program header table entry unused */\n");
                        section_="PT_NULL";
                        break;
                    case PT_LOAD:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOAD\t\t/* Loadable program segment */\n");
                        section_="PT_LOAD";
                        break;
                    case PT_DYNAMIC:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_DYNAMIC\t\t/* Dynamic linking information */\n");
                        section_="PT_DYNAMIC";
                        library[library_index].PT_DYNAMIC_=i;
                        break;
                    case PT_INTERP:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_INTERP\t\t/* Program interpreter */\n");
                        section_="PT_INTERP";
                        break;
                    case PT_NOTE:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_NOTE\t\t/* Auxiliary information */\n");
                        section_="PT_NOTE";
                        break;
                    case PT_SHLIB:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_SHLIB\t\t/* Reserved */\n");
                        section_="PT_SHLIB";
                        break;
                    case PT_PHDR:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_PHDR\t\t/* Entry for header table itself */\n");
                        section_="PT_PHDR";
                        break;
                    case PT_TLS:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_TLS\t\t/* Thread-local storage segment */\n");
                        section_="PT_TLS";
                        break;
                    case PT_NUM:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_NUM\t\t/* Number of defined types */\n");
                        section_="PT_NUM";
                        break;
                    case PT_LOOS:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOOS\t\t/* Start of OS-specific */\n");
                        section_="PT_LOOS";
                        break;
                    case PT_GNU_EH_FRAME:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_GNU_EH_FRAME\t/* GCC .eh_frame_hdr segment */\n");
                        section_="PT_GNU_EH_FRAME";
                        break;
                    case PT_GNU_STACK:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_GNU_STACK\t\t/* Indicates stack executability */\n");
                        section_="PT_GNU_STACK";
                        break;
                    case PT_GNU_RELRO:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_GNU_RELRO\t\t/* Read-only after relocation */\n");
                        section_="PT_GNU_RELRO";
                        break;
                    case PT_SUNWBSS:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_SUNWBSS\t\t/* Sun Specific segment */\n");
                        section_="PT_SUNWBSS";
                        break;
                    case PT_SUNWSTACK:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_SUNWSTACK\t\t/* Stack segment */\n");
                        section_="PT_SUNWSTACK";
                        break;
                    case PT_HIOS:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_HIOS\t\t/* End of OS-specific */\n");
                        section_="PT_HIOS";
                        break;
                    case PT_LOPROC:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOPROC\t\t/* Start of processor-specific */\n");
                        section_="PT_LOPROC";
                        break;
                    case PT_HIPROC:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_HIPROC\t\t/* End of processor-specific */\n");
                        section_="PT_HIPROC";
                        break;
                    default:
                        if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Unknown\n");
                        section_="Unknown";
                        break;
                }
                if (section_ == "PT_DYNAMIC")
                {
                    // obtain PT_DYNAMIC into seperate library[library_index].array for use later
                    read_fast_verify(library[library_index].array, library[library_index].len, &library[library_index].tmp99D, (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                    __lseek_string__(&library[library_index].tmp99D, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_offset);
                }
                char * tmp99;/* = malloc((library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));*/
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ATTEMPING TO READ\n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "reading                %014p\n", (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                read_fast_verify(library[library_index].array, library[library_index].len, &tmp99, (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "correcting position by %014p\n", library[library_index]._elf_program_header[i].p_offset);
                __lseek_string__(&tmp99, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "reading                %d\n", library[library_index]._elf_program_header[i].p_memsz);
                __print_quoted_string__(tmp99, library[library_index]._elf_program_header[i].p_memsz, 0, "print");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\nREAD\n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[i].p_flags, library[library_index]._elf_program_header[i].p_offset, library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mappingb, library[library_index]._elf_program_header[i].p_paddr, library[library_index]._elf_program_header[i].p_filesz, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_align);
                if (bytecmpq(GQ, char_n) == 0) nl();
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\t\tp_flags: %014p", library[library_index]._elf_program_header[i].p_flags);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_offset: %014p", library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_vaddr:  %014p", library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mappingb);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_paddr: %014p", library[library_index]._elf_program_header[i].p_paddr);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_filesz: %014p", library[library_index]._elf_program_header[i].p_filesz);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_memsz: %014p", library[library_index]._elf_program_header[i].p_memsz);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " p_align: %014p\n", library[library_index]._elf_program_header[i].p_align);
            }

            if (library[library_index].PT_DYNAMIC_ != 0) {
// A PT_DYNAMIC program header element points at the .dynamic section, explained in
// "Dynamic Section" below. The .got and .plt sections also hold information related to
// position-independent code and dynamic linking. Although the .plt appears in a text segment
// above, it may reside in a text or a data segment, depending on the processor.
// 
// As "Sections" describes, the .bss section has the type SHT_NOBITS. Although it occupies no
// space in the file, it contributes to the segment's memory image. Normally, these uninitialized
// data reside at the end of the segment, thereby making p_memsz larger than p_filesz.
// 

                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOAD 1 = \n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_flags, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_offset, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_vaddr+library[library_index].mappingb, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_paddr, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_filesz, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_memsz, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_align);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "PT_LOAD 2 = \n");
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_flags, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_offset, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr+library[library_index].mappingb, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_paddr, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_filesz, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_memsz, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_align);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "first PT_LOAD library[library_index]._elf_program_header[%d]->p_paddr = \n%014p\n", library[library_index].First_Load_Header_index, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_paddr+library[library_index].mappingb);
                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Second PT_LOAD library[library_index]._elf_program_header[%d]->p_paddr = \n%014p\n", library[library_index].Last_Load_Header_index, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_paddr+library[library_index].mappingb);
                Elf64_Dyn * dynamic = library[library_index].tmp99D;

                if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "examining current entries:\n");
                get_dynamic_entry(library[library_index].dynamic, -1);
            }

            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "Section Header\t \
library[library_index]._elf_header->e_shstrndx %014p (\
library[library_index]._elf_header->e_shnum = %d entries with a total of \
library[library_index]._elf_header->e_shentsize = %d (should match %d) bytes, offset is \
library[library_index]._elf_header->e_shoff = %014p)\n",\
            library[library_index]._elf_header->e_shstrndx,\
            library[library_index]._elf_header->e_shnum,\
            library[library_index]._elf_header->e_shentsize,\
            sizeof(Elf64_Shdr),\
            library[library_index]._elf_header->e_shoff,\
            (char *)library[library_index].array + library[library_index]._elf_header->e_shoff\
            );
            read_section_header_table_(library[library_index].array, library[library_index]._elf_header, &library[library_index]._elf_symbol_table);
            print_section_headers_(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table);
            print_symbols(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table);
        } else {
            /* Not ELF file */
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ELFMAGIC not found\n");
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "header = ");
            __print_quoted_string__(library[library_index].array, sizeof(library[library_index]._elf_header->e_ident), QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "\n");
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, "ELF Identifier\t %s (", library[library_index]._elf_header->e_ident);
            __print_quoted_string__(library[library_index]._elf_header->e_ident, sizeof(library[library_index]._elf_header->e_ident), QUOTE_FORCE_HEX|QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
            if (bytecmpq(GQ, char_n) == 0) fprintf(stderr, " )\n");
            readelf = 0;
            return 0;
        }
    readelf = 0;
    return 0;
}

int
__string_quote__(const char *instr, char *outstr, const unsigned int size, const unsigned int style)
{
    const unsigned char *ustr = (const unsigned char *) instr;
    char *s = outstr;
    unsigned int i;
    int usehex, usehexX, uselen, c;

    int xflag = 0;
    usehex = 0;
    usehexX = 0;
    uselen = 0;
    if ((style == 9998)) {
        usehexX = 1;
    } else if ((style == 9999)) {
        uselen = 1;
    } else if ((xflag > 1) || (style & QUOTE_FORCE_HEX)) {
        usehex = 1;
    } else if (xflag) {
        /* Check for presence of symbol which require
        to hex-quote the whole string. */
        for (i = 0; i < size; ++i) {
            c = ustr[i];
            /* Check for NUL-terminated string. */
            if (c == 0x100)
                break;

            /* Force hex unless c is printable or whitespace */
            if (c > 0x7e) {
                usehex = 1;
                break;
            }
            /* In ASCII isspace is only these chars: "\t\n\v\f\r".
            * They happen to have ASCII codes 9,10,11,12,13.
            */
            if (c < ' ' && (unsigned)(c - 9) >= 5) {
                usehex = 1;
                break;
            }
        }
    }

    if (!(style & QUOTE_OMIT_LEADING_TRAILING_QUOTES))
        *s++ = '\"';

    if (usehexX) {
        /* Hex-quote the whole string. */
        for (i = 0; i < size; ++i) {
            c = ustr[i];
            /* Check for NUL-terminated string. */
            if (c == 0x100)
                goto asciz_ended;
            // print hex in " 00 00" format instead of "\x00\x00" format
//             *s++ = '\\';
            *s++ = ' ';
            *s++ = "0123456789abcdef"[c >> 4];
            *s++ = "0123456789abcdef"[c & 0xf];
        }
    } else if (usehex) {
        /* Hex-quote the whole string. */
        for (i = 0; i < size; ++i) {
            c = ustr[i];
            /* Check for NUL-terminated string. */
            if (c == 0x100)
                goto asciz_ended;
            *s++ = '\\';
            *s++ = 'x';
            *s++ = "0123456789abcdef"[c >> 4];
            *s++ = "0123456789abcdef"[c & 0xf];
        }
    } else if (uselen) {
        /* Hex-quote the whole string. */
        for (i = 0; i < size; ++i) {
            c = ustr[i];
            /* Check for NUL-terminated string. */
            if (c == 0x100)
                goto asciz_ended;
            *s++ = '1';
        }
    } else {
        for (i = 0; i < size; ++i) {
            c = ustr[i];
            /* Check for NUL-terminated string. */
            if (c == 0x100)
                goto asciz_ended;
            if ((i == (size - 1)) &&
                (style & QUOTE_OMIT_TRAILING_0) && (c == '\0'))
                goto asciz_ended;
                int pass_one = 0;
                int pass_two = 0;
                int pass_three = 0;
                int pass_four = 0;
                if (c == '\f') {
                    *s++ = '\\';
                    *s++ = 'f';
                    pass_one = 1;
                    pass_three = 1;
                    pass_four= 1;
//                         if i wanted a string to be if (bytecmpq(GQ, char_n) == 0) printf safe what characters would i need to replace or modify, for example "hi"ko-pl" would need to be "hi\"ko"'-'"pl"
//                         \x27 is '
//                     xargs -0 if (bytecmpq(GQ, char_n) == 0) printf '%s'<<EOF
//                     "hi"ko-p'l"
//                     EOF
                }
                if (pass_one == 0) {
                    if (c == '%'/*FOR PRINTF*/) {
                        *s++ = '%';
                        *s++ = '%';
                        pass_two = 1;
                        pass_three = 1;
                        pass_four= 1;
                    } else {
                        pass_two = 1;
                    }
                }
                if (pass_two == 0) {
                    if (c == '\"') {
                        /*FOR PRINTF/SHELL*/
                        *s++ = '\\';
                        *s++ = '\"';
                        pass_three = 1;
                        pass_four= 1;
                    } else if (c == '\\') {
                        /*FOR PRINTF/SHELL*/
                        *s++ = '\\';
                        *s++ = '\\';
                        pass_three = 1;
                        pass_four= 1;
                    } else if (c == '`'/*FOR PRINTF*/|| c == '$'/*FOR BASH*/) {
//                             *s++ = '\\';
                        *s++ = c;
                        pass_three = 1;
                        pass_four= 1;
                    } else if (c == '\''/*FOR PRINTF*/) {
//                             *s++ = '\\';
//                             *s++ = 'x';
//                             *s++ = '2';
                        *s++ = c;
                        pass_three = 1;
                        pass_four= 1;
                    } else if (c == '!'/*FOR BASH*/ || c ==  '-'/*FOR PRINTF*/) {
//                             *s++ = '"';
//                             *s++ = '\'';
                        *s++ = c;
//                             *s++ = '\'';
//                             *s++ = '"';
                        pass_three = 1;
                        pass_four= 1;
                    } else if (c == '%'/*FOR PRINTF*/) {
                        *s++ = '%';
                        *s++ = '%';
                        *s++ = '%';
                        *s++ = '%';
                        pass_three = 1;
                        pass_four= 1;
                    }
                }
                if (pass_three == 0) {
                    if (c == '\n') {
                        *s++ = '\\';
                        *s++ = 'n';
                        pass_four = 1;
                    } else if (c == '\r') {
                        *s++ = '\\';
                        *s++ = 'r';
                        pass_four = 1;
                    } else if (c == '\t') {
                        *s++ = '\\';
                        *s++ = 't';
                        pass_four = 1;
                    } else if (c == '\v') {
                        *s++ = '\\';
                        *s++ = 'v';
                        pass_four = 1;
                    }
                }
                if (pass_four == 0) {
                    if (c >= ' ' && c <= 0x7e)
                        *s++ = c;
                    else {
                        /* Print \octal */
                        *s++ = '\\';
                        if (i + 1 < size
                            && ustr[i + 1] >= '0'
                            && ustr[i + 1] <= '9'
                        ) {
                            /* Print \ooo */
                            *s++ = '0' + (c >> 6);
                            *s++ = '0' + ((c >> 3) & 0x7);
                        } else {
                            /* Print \[[o]o]o */
                            if ((c >> 3) != 0) {
                                if ((c >> 6) != 0)
                                    *s++ = '0' + (c >> 6);
                                *s++ = '0' + ((c >> 3) & 0x7);
                            }
                        }
                        *s++ = '0' + (c & 0x7);
                    }
            }
        }
    }

    if (!(style & QUOTE_OMIT_LEADING_TRAILING_QUOTES))
        *s++ = '\"';
    *s = '\0';

    /* Return zero if we printed entire ASCIZ string (didn't truncate it) */
    if (style & QUOTE_0_TERMINATED && ustr[i] == '\0') {
        /* We didn't see NUL yet (otherwise we'd jump to 'asciz_ended')
        * but next char is NUL.
        */
        return 0;
    }

    return 1;

asciz_ended:
    if (!(style & QUOTE_OMIT_LEADING_TRAILING_QUOTES))
        *s++ = '\"';
    *s = '\0';
    /* Return zero: we printed entire ASCIZ string (didn't truncate it) */
    return 0;
}
#endif
