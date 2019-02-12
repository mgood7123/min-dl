/*
STABLE

commit ea20d1806d08f44300df120b6e5bed0d6093afbc
Author: mgood7123 <smallville7123@gmail.com>
Date:   Fri Mar 16 09:59:40 2018 +1000

*/

#include <stdbool.h>
extern int libstring_argc;
extern char ** libstring_argv;
extern char ** libstring_env;

bool is_readelf = false;

#ifndef __SHARED__
// compiled without -fpic or -fPIC
#warning recompile this with the flag -fpic or -fPIC to enable compiling this as a shared library

int
readelf_(const char * filename);
int main() {
    readelf_(libstring_argv[1]);
}
#else
// compiled with -fpic or -fPIC
const char * global_quiet = "no";
const char * SignalHandler_quiet = "no";
const char * symbol_quiet = "no";
const char * relocation_quiet = "no";
const char * analysis_quiet = "no";
const char * ldd_quiet = "no";

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
#include "../../CCR/Scripts/Shell/builtins/env.h"
#include "../../CCR/Scripts/Shell/builtins/printfmacro.h"

// need to add every needed declaration into this struct

int library_index = 0; // must be global
#include "lib.h"

int
init_struct() {
    library[library_index].struct_init = "initialized";
    library[library_index].library_name;
    library[library_index].NEEDED = malloc(sizeof(library[library_index].NEEDED));
    library[library_index].library_first_character;
    library[library_index].library_len;
    library[library_index].library_symbol;
    library[library_index].mapping_start;
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
    library[library_index].mapping_end = 0x00000000;
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

Elf64_Dyn DYN_EMPTY = {0};

int init_(const char * filename);
int initv_(const char * filename);

void * lookup_symbol_by_name_(const char * lib, const char * name);
// for C++ symbol name demangling should libiberty become incompatible
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
//   bytecmp(mangled_name, mangled_name);
//   mangled_name[strlen(mangled_name)-2] = '\0';
  int len = strlen(mangled_name);
//   for (int i = 0; i=len-2; i++)
//   if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "trimming %s", mangled_name);
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
jmp_buf restore_pointb;
struct sigaction sa, sab;
void Handlerb(int sig, siginfo_t *si, ucontext_t *unused)
{
    if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "received signal (%d)\n", sig);
    if (sig == SIGSEGV)
    {
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "\r    NOTICE\n");
        void * h_ = &Handlerb;
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    received SegFault (%d)\n", sig);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    addr:   %014p\n", si->si_addr);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    arch:   %d\n", si->si_arch);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    signo:  %d\n", si->si_signo);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    errno:  %d\n", si->si_errno);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    code:   %d (If this is less than or equal to 0, then the signal was generated by a process)\n", si->si_code);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    pid:    %d\n", (pid_t) si->si_pid);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    uid:    %d\n", (uid_t) si->si_uid);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    value:  %d\n", (sigval_t) si->si_value); // not in musl
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    status: %d\n", si->si_status);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "    aquiring ucontext_t\n");
//         getcontext(unused); // not used and not in musl
        signal(SIGSEGV, h_);
        longjmp(restore_pointb, SIGSEGV);
    }
}

void
init_handlerb() {
    sab.sa_flags = SA_SIGINFO|SA_NODEFER;
    sigemptyset(&sab.sa_mask);
    sab.sa_sigaction = Handlerb;
    if (sigaction(SIGSEGV, &sab, NULL) == -1) {
        perror("failed to set handler");
        pause();
    }
}

void Handler(int sig, siginfo_t *si, ucontext_t *context)
{
//     init_handlerb();

// dont print anything, silently skip

    if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "                                                                                                                        received signal (%d)\n", sig);
    if (sig == SIGSEGV)
    {
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "NOTICE\n");
        void * h = &Handler;
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "received SegFault (%d)\n", sig);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "addr:   %014p\n", si->si_addr);
//         int fault_code = setjmp(restore_pointb);
//         if (fault_code == 0) if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "arch:   %d\n", si->si_arch);
//         else  if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "arch:   NULL (recovered from a fault, code = %d)\n", fault_code);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "signo:  %d\n", si->si_signo);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "errno:  %d\n", si->si_errno);
        if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "code:   %d (If this is less than or equal to 0, then the signal was generated by a process)\n", si->si_code);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "pid:    %d\n", (pid_t) si->si_pid);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "uid:    %d\n", (uid_t) si->si_uid);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "value:  %d\n", (sigval_t) si->si_value);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "status: %d\n", si->si_status);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "aquiring ucontext_t\n");
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "Address of crash:          %x\n",context->uc_mcontext.gregs[REG_RIP]);
//  RAX  0xbc748
//  RBX  0x2
//  RCX  0x40bbba (__libc_sigaction+266) ◂— cmp    rax, -0x1000 /* 'H=' */
//  RDX  0x86d3373220279bca
//  RDI  0x6bbe00 (restore_point) ◂— 0x2
//  RSI  0x0
//  R8   0x0
//  R9   0x33
//  R10  0x8
//  R11  0x246
//  R12  0x0
//  R13  0x6ba340 (_dl_main_map) ◂— 0
//  R14  0x6b9018 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x432240 (__strcpy_ssse3) ◂— mov    rcx, rsi
//  R15  0x0
//  RBP  0x7fffffffe0b0 —▸ 0x7fffffffe0f0 —▸ 0x4012d9 (callback) ◂— push   rbp
//  RSP  0x7fffffffe090 —▸ 0x7fffffffe1d0 —▸ 0x7fffffffe200 —▸ 0x404f10 (__libc_csu_init) ◂— ...
//  RIP  0x4012a0 (test+50) ◂— mov    eax, dword ptr [rax]
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RAX:                       %x\n",context->uc_mcontext.gregs[REG_RAX]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RBX:                       %x\n",context->uc_mcontext.gregs[REG_RBX]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RCX:                       %x\n",context->uc_mcontext.gregs[REG_RCX]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RDX:                       %x\n",context->uc_mcontext.gregs[REG_RDX]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RDI:                       %x\n",context->uc_mcontext.gregs[REG_RDI]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RSI:                       %x\n",context->uc_mcontext.gregs[REG_RSI]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "R8:                        %x\n",context->uc_mcontext.gregs[REG_R8]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "R9:                        %x\n",context->uc_mcontext.gregs[REG_R9]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "R10:                       %x\n",context->uc_mcontext.gregs[REG_R10]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "R11:                       %x\n",context->uc_mcontext.gregs[REG_R11]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "R12:                       %x\n",context->uc_mcontext.gregs[REG_R12]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "R13:                       %x\n",context->uc_mcontext.gregs[REG_R13]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "R14:                       %x\n",context->uc_mcontext.gregs[REG_R14]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "R15:                       %x\n",context->uc_mcontext.gregs[REG_R15]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RBP:                       %x\n",context->uc_mcontext.gregs[REG_RBP]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RSP:                       %x\n",context->uc_mcontext.gregs[REG_RSP]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "RIP:                       %x\n",context->uc_mcontext.gregs[REG_RIP]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "EFL:                       %x\n",context->uc_mcontext.gregs[REG_EFL]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "CSGSFS:                    %x\n",context->uc_mcontext.gregs[REG_CSGSFS]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "ERR:                       %x\n",context->uc_mcontext.gregs[REG_ERR]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "TRAPNO:                    %x\n",context->uc_mcontext.gregs[REG_TRAPNO]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "OLDMASK:                   %x\n",context->uc_mcontext.gregs[REG_OLDMASK]);
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "CR2:                       %x\n",context->uc_mcontext.gregs[REG_CR2]);
//         context->uc_mcontext.gregs[REG_RIP] = context->uc_mcontext.gregs[REG_RIP] + 0x02 ;
//         if (bytecmpq(SignalHandler_quiet, "no") == 0) fprintf(stderr, "Next Address:              %x\n",context->uc_mcontext.gregs[REG_RIP]);
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
//     if (sigaction(SIGHUP, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGINT, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGQUIT, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGILL, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGTRAP, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGABRT, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGBUS, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGFPE, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGKILL, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGUSR1, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGUSR2, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGPIPE, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGALRM, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGTERM, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGSTKFLT, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGCLD, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGCONT, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGSTOP, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGTSTP, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGTTIN, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGTTOU, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGURG, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGXCPU, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGXFSZ, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGVTALRM, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGPROF, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGWINCH, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGPOLL, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGPWR, &sa, NULL) == -1)
//         perror("failed to set handler");
//     if (sigaction(SIGSYS, &sa, NULL) == -1)
//         perror("failed to set handler");
}

int test(char * address)
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "value: %15d\t", *(int*)address);
        return 0;
    }
    else
    {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "value: %s\t", "     is not int");
        return -1;
    }
}

int pointers=0;

int test_address(char ** addr)
{
    init_handler();
    int fault_code = setjmp(restore_point);
    if (fault_code == 0)
    {
        fprintf(stderr, "%014p = %014p\n", addr, *addr);
        pointers++;
        return 0;
    }
    else
    {
        fprintf(stderr, "%014p = %s\n", addr, "INVALID");
        pointers--;
        return -1;
    }
}

int test_string(char * addr)
{
    init_handler();
    int fault_code = setjmp(restore_point);
    if (fault_code == 0)
    {
        fprintf(stderr, "%s", addr);
        return 0;
    }
    else
    {
        fprintf(stderr, "INVALID");
        return -1;
    }
}

char * analyse_address(char ** addr, char * name)
{
    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(analysis_quiet, "no") == 0) fprintf(stderr, "analysing address %014p\n", addr);
    char ** addr_original = addr;
    pointers = 0;
    while( test_address(addr) == 0) addr = *addr;

    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(analysis_quiet, "no") == 0) fprintf(stderr, "pointers: %d\n", pointers);

    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(analysis_quiet, "no") == 0) {
        fprintf(stderr, "data ");
        for (int i = 1; i<=pointers; i++) fprintf(stderr, "*");
        fprintf(stderr, " %s\n", name);
    }
    if (pointers == 0)
    {
        pointers = 0;
        if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(analysis_quiet, "no") == 0) fprintf(stderr, "returning %014p\n", addr_original);
        return addr_original;
    }
    else 
    {
        pointers = 0;
        if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(analysis_quiet, "no") == 0) fprintf(stderr, "returning %014p\n", *addr_original);
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "value: %15x\t", *(int*)address);
        return 0;
    }
    else
    {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "value: %s\t", "     is not hex");
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
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "current index %d holds \"%s\"\n", i, library[i].last_lib);
            if ( bytecmpq(lib, library[i].last_lib) == -1 && bytecmpq("NULL", library[i].last_lib) == -1 ) i++;
            else if ( bytecmpq("NULL", library[i].last_lib) == -1 )
                 {
                     if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "index %d holds desired library \"%s\"\n", i, lib); // bugs
                     break;
                 }
            else {
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "attempting to save to index %d\n", i);
                break;
            }
        } else {
            fprintf(stderr, "WARNING: index %d is %s\n", i, library[i].struct_init);
            break;
        }
    }
    return i;
}

int searchq(const char * lib) {
    // need to be smarter
    int i = 0;
    while(1)
    {
        if (library[i].struct_init == "initialized") {
            if ( bytecmpq(lib, library[i].last_lib) == -1 && bytecmpq("NULL", library[i].last_lib) == -1 ) i++;
            else if ( bytecmpq("NULL", library[i].last_lib) == -1 )
                 {
                     break;
                 }
            else {
                break;
            }
        } else {
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "WARNING: index %d is %s\n", i, library[i].struct_init);
            break;
        }
    }
    return i;
}

int init(char * lib) {
    if (library[library_index].struct_init != "initialized") init_struct();
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "current index %d holds \"%s\"\nsearching indexes for \"%s\" incase it has already been loaded\n", library_index, library[library_index].last_lib, lib);
    
    library_index = search(lib);
    library[library_index].last_lib = lib;
    library[library_index].current_lib = lib;
    if (library[library_index].array == NULL) {
        int fd = open(lib, O_RDONLY);
        if (fd < 0) {
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "cannot open \"%s\", returned %i\n", lib, fd);
            return -1;
        }
        library[library_index].len = 0;
        library[library_index].len = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, 0);
        library[library_index].array = mmap (NULL, library[library_index].len, PROT_READ, MAP_PRIVATE, fd, 0);
        if (library[library_index].array == MAP_FAILED) {
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "map failed\n");
            exit;
        } else {
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "map succeded with address: %014p\n", library[library_index].array);
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PROT_READ|");
        prot |= PROT_READ;
    }
    if (p_flags & PF_W)
    {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PROT_WRITE|");
        prot |= PROT_WRITE;
    }
    if (p_flags & PF_X)
    {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PROT_EXEC|");
        prot |= PROT_EXEC;
    }
    return prot;
}

#define truncate_to_nearest_multiple(x, n) x - (x % n)

void map() {
    if (library[library_index].is_mapped == 0) {
        library[library_index]._elf_header = (Elf64_Ehdr *) library[library_index].array;
        library[library_index]._elf_program_header = (Elf64_Phdr *)((unsigned long)library[library_index]._elf_header + library[library_index]._elf_header->e_phoff);

/*
the very first thing we do is obtain the base address

Base Address
The virtual addresses in the program headers might not represent the actual virtual addresses
of the program's memory image. Executable files typically contain absolute code. To let the
process execute correctly, the segments must reside at the virtual addresses used to build the
executable file. On the other hand, shared object segments typically contain
position-independent code. This lets a segment's virtual address change from one process to
another, without invalidating execution behavior. Though the system chooses virtual addresses
for individual processes, it maintains the segments’ relative positions. Because
position-independent code uses relative addressing between segments, the difference between
virtual addresses in memory must match the difference between virtual addresses in the file.

The difference between the virtual address of any segment in memory and the corresponding
virtual address in the file is thus a single constant value for any one executable or shared object
in a given process. This difference is the base address. One use of the base address is to relocate
the memory image of the program during dynamic linking.

An executable or shared object file's base address is calculated during execution from three
values: the virtual memory load address, the maximum page size, and the lowest virtual address
of a program's loadable segment. To compute the base address, one determines the memory
address associated with the lowest p_vaddr value for a PT_LOAD segment. This address is
truncated to the nearest multiple of the maximum page size. The corresponding p_vaddr value
itself is also truncated to the nearest multiple of the maximum page size. The base address is
the difference between the truncated memory address and the truncated p_vaddr value.
*/

		// aquire the first and last PT_LOAD'S
        int PT_LOADS=0;
        for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
            switch(library[library_index]._elf_program_header[i].p_type)
            {
                case PT_LOAD:
//                         if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "i = %d\n", i);
//                         if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOADS = %d\n", PT_LOADS);
                    if (!PT_LOADS)  {
//                             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "saving first load\n");
                        library[library_index].First_Load_Header_index = i;
                    }
                    if (PT_LOADS) {
//                             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "saving last load\n");
                        library[library_index].Last_Load_Header_index = i;
                    }
                    PT_LOADS=PT_LOADS+1;
                    break;
            }
        }
        size_t span = library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr + library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_memsz - library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_vaddr;


        read_fast_verifyb(library[library_index].array, library[library_index].len, &library[library_index].mapping_start, span, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index], library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index]);

		fprintf(stderr, "library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr = %014p\n", library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr);
		
		// aquire the lowest PT_LOAD'S
		Elf64_Addr lowest_p_vaddr = 0;
		int lowest_idx = -1;
        for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
            switch(library[library_index]._elf_program_header[i].p_type)
            {
                case PT_LOAD:
					if (!lowest_p_vaddr) {
						lowest_p_vaddr = library[library_index]._elf_program_header[i].p_vaddr;
						lowest_idx = i;
					}
					if (lowest_p_vaddr < library[library_index]._elf_program_header[i].p_memsz) {
						lowest_p_vaddr = library[library_index]._elf_program_header[i].p_vaddr;
						lowest_idx = i;
					}
                    break;
            }
        }
        size_t pagesize = getpagesize();
		if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "library[library_index]._elf_program_header[lowest_idx].p_paddr = %014p\nlibrary[library_index]._elf_program_header[lowest_idx].p_vaddr = %014p\n",library[library_index]._elf_program_header[lowest_idx].p_paddr, library[library_index]._elf_program_header[lowest_idx].p_vaddr);
        Elf64_Addr truncated_physical_address = truncate_to_nearest_multiple(library[library_index]._elf_program_header[lowest_idx].p_paddr, pagesize);
        Elf64_Addr truncated_virtual_address = truncate_to_nearest_multiple(library[library_index]._elf_program_header[lowest_idx].p_vaddr, pagesize);
		ppx(truncated_physical_address)
		ppx(truncated_virtual_address)
		library[library_index].base_address = truncated_physical_address - truncated_virtual_address;
// 		library[library_index].base_address = library[library_index].mapping_start;

        library[library_index].align = round_nearest(library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr, pagesize);
// 		library[library_index].base_address = library[library_index].mapping_start - library[library_index].align;
        library[library_index].mapping_end = library[library_index].mapping_start+span;

		if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "base address range = %014p - %014p\nmapping = %014p\nbase address = %014p\n", library[library_index].mapping_start, library[library_index].mapping_end, library[library_index].mapping_start, library[library_index].base_address);

		abort_();
		// base address aquired, map all PT_LOAD segments adjusting by base address then continue with the rest
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n\n\nfind %014p, %014p, (int) 1239\n\n\n\n", library[library_index].mapping_start, library[library_index].mapping_end);

        if (library[library_index].mapping_start == 0x00000000) abort_();
        int PT_LOADS_CURRENT = 0;
        for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
            switch(library[library_index]._elf_program_header[i].p_type)
            {
                case PT_LOAD:
                    PT_LOADS_CURRENT = PT_LOADS_CURRENT + 1;
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "mapping PT_LOAD number %d\n", PT_LOADS_CURRENT);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_flags:  %014p\n", library[library_index]._elf_program_header[i].p_flags);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_offset: %014p\n", library[library_index]._elf_program_header[i].p_offset);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_vaddr:  %014p\n", library[library_index]._elf_program_header[i].p_vaddr);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_paddr:  %014p\n", library[library_index]._elf_program_header[i].p_paddr);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_filesz: %014p\n", library[library_index]._elf_program_header[i].p_filesz);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_memsz:  %014p\n", library[library_index]._elf_program_header[i].p_memsz);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_align:  %014p\n\n", library[library_index]._elf_program_header[i].p_align);

                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\tp_flags: %014p", library[library_index]._elf_program_header[i].p_flags);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_offset: %014p", library[library_index]._elf_program_header[i].p_offset);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_vaddr: %014p", library[library_index]._elf_program_header[i].p_vaddr);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_paddr: %014p", library[library_index]._elf_program_header[i].p_paddr);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_filesz: %014p", library[library_index]._elf_program_header[i].p_filesz);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_memsz: %014p", library[library_index]._elf_program_header[i].p_memsz);
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_align: %014p\n\n\n", library[library_index]._elf_program_header[i].p_align);

                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "mprotect(%014p+round_down(%014p, %014p), %014p, ", library[library_index].mapping_start, library[library_index]._elf_program_header[i].p_vaddr, library[library_index]._elf_program_header[i].p_align, library[library_index]._elf_program_header[i].p_memsz);
                    prot_from_phdr(library[library_index]._elf_program_header[i].p_flags);
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, ");\n");
                    errno = 0;
                    int check_mprotect_success = mprotect(library[library_index].mapping_start+round_down(library[library_index]._elf_program_header[i].p_vaddr, library[library_index]._elf_program_header[i].p_align), round_up(library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_align), library[library_index]._elf_program_header[i].p_flags);
                    if (errno == 0)
                    {
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "mprotect on %014p succeded with size: %014p\n", library[library_index].mapping_start+round_down(library[library_index]._elf_program_header[i].p_vaddr, library[library_index]._elf_program_header[i].p_align), round_up(library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_align));
                        print_maps();
                    }
                    else
                    {
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "mprotect failed with: %s (errno: %d, check_mprotect_success = %d)\n", strerror(errno), errno, check_mprotect_success);
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
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "cannot open \"%s\", returned %i\n", filename, fd);
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
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\rbytes read: %'i", bytes);
                if (count == 1024) { array_tmp = realloc(array, bytes+1024);
                    if (array_tmp == NULL) {
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "failed to allocate array to new size");
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
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "failed to allocate array to new size");
                free(array);
                exit(1);
            } else {
                array = array_tmp;
            }
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\rbytes read: %'i\n", bytes);
    *p = array;
    *q = bytes;
    return bytes;
}

// not used but kept incase needed, a version of stream__ that only outputs the last line read
int __streamb__(char *file, char **p, int *q, int LINES_TO_READ) {
            const char *filename = file;
            int fd = open(filename, O_RDONLY);
            if (fd < 0) {
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "cannot open \"%s\", returned %i\n", filename, fd);
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
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\rbytes read: %'i", bytes);
                if (count == 1024) { array_tmp = realloc(array, bytes+1024);
                    if (array_tmp == NULL) {
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "failed to allocate array to new size");
                        free(array);
                        exit(1);
                    } else {
                        array = array_tmp;
                    }
                    count=1;
                }
                array[bytes-1] = ch;
                if (ch == '\n') {
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "attempting to reset array\n");
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
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "failed to allocate array to new size");
                free(array);
                exit(1);
            } else {
                array = array_tmp;
            }
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\rbytes read: %'i\n", bytes);
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "open() failure\n");
        return (1);
    }
    len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, 0);
    if (!(o = malloc(len))) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "failure to malloc()\n");
    }
    if ((read(fd, o, len)) == -1) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "failure to read()\n");
    }
    int cl = close(fd);
    if (cl < 0) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "cannot close \"%s\", returned %i\n", file, cl);
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "???");
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
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "???");
            return "-1";
        }
    }

//         rc = string_quote(str, outstr, size, style);
    __string_quote__(str, outstr, size, style);
    if ( return_type == "return") {
        return outstr;
    } else if ( return_type == "print") {
        if (bytecmpq(global_quiet, "no") == 0) printf(outstr);
    }

    free(buf);
//         return rc;
}

Elf64_Dyn *
get_dynamic_entryq(Elf64_Dyn *dynamic, int field);

// read section header table
int read_section_header_table_(const char * arrayb, Elf64_Ehdr * eh, Elf64_Shdr * sh_table[])
{
    *sh_table = (Elf64_Shdr *)(arrayb + eh->e_shoff);
    if(!sh_table) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Failed to read table\n");
        return -1;
    }
    return 0;
}

char * read_section_(char * ar, Elf64_Shdr sh) {
    char * buff = (char *)(ar + sh.sh_offset);
    return buff ;
}

char * obtain_rela_plt_size(char * sourcePtr, Elf64_Ehdr * eh, Elf64_Shdr sh_table[]) {
    char * sh_str = read_section_(sourcePtr, sh_table[eh->e_shstrndx]); // will fail untill section header table can be read
    for(int i=0; i<eh->e_shnum; i++) if (bytecmpq((sh_str + sh_table[i].sh_name), ".rela.plt") == 0) library[library_index].RELA_PLT_SIZE=library[library_index]._elf_symbol_table[i].sh_size;
}

char * print_section_headers_(char * sourcePtr, Elf64_Ehdr * eh, Elf64_Shdr sh_table[]) {
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n");
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "eh->e_shstrndx = 0x%x (%d)\n", eh->e_shstrndx+library[library_index].mapping_start, eh->e_shstrndx);
    char * sh_str;
    sh_str = read_section_(sourcePtr, sh_table[eh->e_shstrndx]); // will fail untill section header table can be read
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t=============================================================================================\n");
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t%03s %14s %14s %14s %14s %14s %14s\n", "idx", "offset", "load-addr", "size", "algn type", "flags", "section");
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t=============================================================================================\n");

    for(int i=0; i<eh->e_shnum; i++) { // will fail untill section header table can be read
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t%03d ", i);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_offset); // not sure if this should be adjusted to base address
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_addr+library[library_index].mapping_start);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_size);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%14d ", library[library_index]._elf_symbol_table[i].sh_addralign);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_type);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%014p ", library[library_index]._elf_symbol_table[i].sh_flags);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%s\t", (sh_str + sh_table[i].sh_name));
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n");
        if (bytecmpq((sh_str + sh_table[i].sh_name), ".rela.plt") == 0) library[library_index].RELA_PLT_SIZE=library[library_index]._elf_symbol_table[i].sh_size;
    }
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t=============================================================================================\n");
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n");
}

int symbol1(char * arrayc, Elf64_Sym sym_tbl[], uint64_t symbol_table) {
    uint64_t i, symbol_count;


//   Elf64_Word	st_name;		/* Symbol name (string tbl index) */
//   unsigned char	st_info;		/* Symbol type and binding */
//   unsigned char st_other;		/* Symbol visibility */
//   Elf64_Section	st_shndx;		/* Section index */
//   Elf64_Addr	st_value;		/* Symbol value */
//   Elf64_Xword	st_size;		/* Symbol size */
    for(int i=0; i< 40; i++) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "index: %d\t", i);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "size: %d \t", sym_tbl[i].st_size);
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "binding: ");
        switch (ELF64_ST_BIND(sym_tbl[i].st_info)) {
            case STB_LOCAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "LOCAL  ( Local  symbol )   ");
                break;
            case STB_GLOBAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GLOBAL ( Global symbol )   ");
                break;
            case STB_WEAK:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "WEAK   (  Weak symbol  )   ");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNKNOWN (%d)               ", ELF64_ST_BIND(sym_tbl[i].st_info));
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "visibility: ");
        switch (ELF64_ST_VISIBILITY(sym_tbl[i].st_other)) {
            case STV_DEFAULT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "default (Default symbol visibility rules)        ");
                break;
            case STV_INTERNAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "internal (Processor specific hidden class)       ");
                break;
            case STV_HIDDEN:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "hidden (Symbol unavailable in other modules)     ");
                break;
            case STV_PROTECTED:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "protected (Not preemptible, not exported)        ");
                break;
        }
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "type: ");
        switch (ELF64_ST_TYPE(sym_tbl[i].st_info)) {
            case STT_NOTYPE:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NOTYPE   (Symbol type is unspecified)             ");
                break;
            case STT_OBJECT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OBJECT   (Symbol is a data object)                ");
                break;
                case STT_FUNC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FUNCTION (Symbol is a code object)                ");
                break;
                case STT_SECTION:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SECTION  (Symbol associated with a section)       ");
                break;
                case STT_FILE:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FILE     (Symbol's name is file name)             ");
                break;
                case STT_COMMON:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "COMMON   (Symbol is a common data object)         ");
                break;
                case STT_TLS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "TLS      (Symbol is thread-local data object)     ");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNKNOWN (%d)                                      ", ELF64_ST_TYPE(sym_tbl[i].st_info));
                break;
        }
        if ( ELF64_ST_TYPE(sym_tbl[i].st_info) == STT_FUNC)
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address: %014p\t", sym_tbl[i].st_value+library[library_index].mapping_start+library[library_index].align);
        else
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address: %014p\t", sym_tbl[i].st_value+library[library_index].mapping_start);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "name: [Not obtained due to unavailability]\n");
    }
}

int symbol(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table) {
    char *str_tbl;
    Elf64_Sym* sym_tbl;
    uint64_t i, symbol_count;
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "symbol_table = %d\n", symbol_table);
    sym_tbl = (Elf64_Sym*)read_section_(arrayc, sh_table[symbol_table]);

    /* Read linked string-table
    * Section containing the string table having names of
    * symbols of this section
    */
    uint64_t str_tbl_ndx = sh_table[symbol_table].sh_link;
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "string/symbol table index = %d\n", str_tbl_ndx);
    str_tbl = read_section_(arrayc, sh_table[str_tbl_ndx]);

    symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));
    int link_ = sh_table[symbol_table].sh_link;
    link_ = sh_table[link_].sh_link;
    int linkn = 0;
    while (link_ != 0) {
        link_ = sh_table[link_].sh_link;
        linkn++;
    }
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "links: %d\n", linkn);
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%d symbols\n", symbol_count);

//   Elf64_Word	st_name;		/* Symbol name (string tbl index) */
//   unsigned char	st_info;		/* Symbol type and binding */
//   unsigned char st_other;		/* Symbol visibility */
//   Elf64_Section	st_shndx;		/* Section index */
//   Elf64_Addr	st_value;		/* Symbol value */
//   Elf64_Xword	st_size;		/* Symbol size */
    for(int i=0; i< symbol_count; i++) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "index: %d\t", i);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "size: %10d \t", sym_tbl[i].st_size);
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "binding: ");
        switch (ELF64_ST_BIND(sym_tbl[i].st_info)) {
            case STB_LOCAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "LOCAL   ( Local  symbol )  ");
                break;
            case STB_GLOBAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GLOBAL  ( Global symbol )  ");
                break;
            case STB_WEAK:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "WEAK    (  Weak symbol  )  ");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNKNOWN (%d)                ", ELF64_ST_BIND(sym_tbl[i].st_info));
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "visibility: ");
        switch (ELF64_ST_VISIBILITY(sym_tbl[i].st_other)) {
            case STV_DEFAULT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "default   (Default symbol visibility rules)      ");
                break;
            case STV_INTERNAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "internal  (Processor specific hidden class)      ");
                break;
            case STV_HIDDEN:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "hidden    (Symbol unavailable in other modules)  ");
                break;
            case STV_PROTECTED:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "protected (Not preemptible, not exported)        ");
                break;
        }
        char * address = sym_tbl[i].st_value+library[library_index].mapping_start;
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address: %014p\t", address);
        if ( address > library[library_index].mapping_start && address < library[library_index].mapping_end ) test(address);
        else if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "value: %015p\t", sym_tbl[i].st_value);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "type: ");
        switch (ELF64_ST_TYPE(sym_tbl[i].st_info)) {
            case STT_NOTYPE:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NOTYPE   (Symbol type is unspecified)             ");
                break;
            case STT_OBJECT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OBJECT   (Symbol is a data object)                ");
                break;
                case STT_FUNC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FUNCTION (Symbol is a code object)                ");
                break;
                case STT_SECTION:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SECTION  (Symbol associated with a section)       ");
                break;
                case STT_FILE:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FILE     (Symbol's name is file name)             ");
                break;
                case STT_COMMON:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "COMMON   (Symbol is a common data object)         ");
                break;
                case STT_TLS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "TLS      (Symbol is thread-local data object)     ");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNKNOWN  (%d)                                     ", ELF64_ST_TYPE(sym_tbl[i].st_info));
                break;
        }
        char * name = str_tbl + sym_tbl[i].st_name;
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "name: %s\n", demangle_it(name));
        if (bytecmpq(global_quiet, "no") == 0) nl();
//         if (bytecmp(name,"t") == 0) {
// 
//             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "t found\n");
//                         
// // #define JMP_ADDR(x) asm("\tjmp  *%0\n" :: "r" (x))
// //             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "(%014p+%014p=%014p)\n", library[library_index].mapping_start, sym_tbl[i].st_value, sym_tbl[i].st_value+library[library_index].mapping_start);
// //             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "JMP_ADDR(%014p);\n", address);
// //             JMP_ADDR(address);
//                         if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "int (*testb)()                               =%014p\n", address);
// // 
//             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "(%014p+%014p=%014p)\n", library[library_index].mapping_start, sym_tbl[i].st_value, sym_tbl[i].st_value+library[library_index].mapping_start);
// // 
//             int (*testb)() = lookup_symbol_by_name_("/chakra/home/universalpackagemanager/chroot/arch-chroot/arch-pkg-build/packages/glibc/repos/core-x86_64/min-dl/loader/files/test_lib.so", "t");
//             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "testb = %014p\n", testb);
//             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "testb() returned %d;\n",
//             testb()
//             );
// 
//             if (bytecmpq(global_quiet, "no") == 0) nl();
// //             int (*testc)() = library[library_index].mapping_start+sym_tbl[i].st_value;
// //             if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "int (*testc)()                =%014p ; testc();\n", library[library_index].mapping_start+sym_tbl[i].st_value);
// //             testc();
// //             if (bytecmpq(global_quiet, "no") == 0) nl();
// //             int foo(int i){ return i + 1;}
// // 
// //             typedef int (*g)(int);  // Declare typedef
// // 
// //             g func = library[library_index].mapping_start+sym_tbl[i].st_value;          // Define function-pointer variable, and initialise
// // 
// //             int hvar = func(3);     // Call function through pointer
//             if (bytecmpq(global_quiet, "no") == 0) nl();
//             print_maps();
//         }
    }
}

int relocation(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table) {
    char *str_tbl;
    Elf64_Sym* sym_tbl;
    uint64_t i, symbol_count;

    sym_tbl = (Elf64_Sym*)read_section_(arrayc, sh_table[symbol_table]);

    /* Read linked string-table
    * Section containing the string table having names of
    * symbols of this section
    */
    uint64_t str_tbl_ndx = sh_table[symbol_table].sh_link;
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "string/symbol table index = %d\n", str_tbl_ndx);
    str_tbl = read_section_(arrayc, sh_table[str_tbl_ndx]);

    symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));
    int link_ = sh_table[symbol_table].sh_link;
    link_ = sh_table[link_].sh_link;
    int linkn = 0;
    while (link_ != 0) {
        link_ = sh_table[link_].sh_link;
        linkn++;
    }
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "links: %d\n", linkn);
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%d symbols\n", symbol_count);

//   Elf64_Word	st_name;		/* Symbol name (string tbl index) */
//   unsigned char	st_info;		/* Symbol type and binding */
//   unsigned char st_other;		/* Symbol visibility */
//   Elf64_Section	st_shndx;		/* Section index */
//   Elf64_Addr	st_value;		/* Symbol value */
//   Elf64_Xword	st_size;		/* Symbol size */
    for(int i=0; i< symbol_count; i++) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "index: %d\t", i);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "size: %10d \t", sym_tbl[i].st_size);
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "binding: ");
        switch (ELF64_ST_BIND(sym_tbl[i].st_info)) {
            case STB_LOCAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "LOCAL   ( Local  symbol )  ");
                break;
            case STB_GLOBAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GLOBAL  ( Global symbol )  ");
                break;
            case STB_WEAK:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "WEAK    (  Weak symbol  )  ");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNKNOWN (%d)                ", ELF64_ST_BIND(sym_tbl[i].st_info));
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "visibility: ");
        switch (ELF64_ST_VISIBILITY(sym_tbl[i].st_other)) {
            case STV_DEFAULT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "default   (Default symbol visibility rules)      ");
                break;
            case STV_INTERNAL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "internal  (Processor specific hidden class)      ");
                break;
            case STV_HIDDEN:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "hidden    (Symbol unavailable in other modules)  ");
                break;
            case STV_PROTECTED:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "protected (Not preemptible, not exported)        ");
                break;
        }
        char * address;
        if ( ELF64_ST_TYPE(sym_tbl[i].st_info) == STT_FUNC)
        {
            address = sym_tbl[i].st_value+library[library_index].mapping_start+library[library_index].align;
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address: %014p\t", address);
        }
        else
        {
            address = sym_tbl[i].st_value+library[library_index].mapping_start;
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address: %014p\t", address);
        }
        if ( address > library[library_index].mapping_start && address < library[library_index].mapping_end ) test(address);
        else if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "value: %15s\t", "invalid range");
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "type: ");
        switch (ELF64_ST_TYPE(sym_tbl[i].st_info)) {
            case STT_NOTYPE:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NOTYPE   (Symbol type is unspecified)             ");
                break;
            case STT_OBJECT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OBJECT   (Symbol is a data object)                ");
                break;
                case STT_FUNC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FUNCTION (Symbol is a code object)                ");
                break;
                case STT_SECTION:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SECTION  (Symbol associated with a section)       ");
                break;
                case STT_FILE:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FILE     (Symbol's name is file name)             ");
                break;
                case STT_COMMON:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "COMMON   (Symbol is a common data object)         ");
                break;
                case STT_TLS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "TLS      (Symbol is thread-local data object)     ");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNKNOWN  (%d)                                     ", ELF64_ST_TYPE(sym_tbl[i].st_info));
                break;
        }
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "name: [Not obtained due to it may crash this program]\n");
//         if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n");
    }
}

void print_elf_symbol_table(char * arrayc, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], uint64_t symbol_table)
{
    int level = 0;
        switch(sh_table[symbol_table].sh_type) {
            case SHT_NULL:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_PROGBITS:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_SYMTAB:
                symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_STRTAB:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_RELA:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_HASH:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_DYNAMIC:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_NOTE:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_NOBITS:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_REL:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_SHLIB:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_DYNSYM:
                symbol(arrayc, sh_table, symbol_table);
                break;
            case SHT_INIT_ARRAY:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_FINI_ARRAY:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_PREINIT_ARRAY:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_GROUP:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_SYMTAB_SHNDX:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_NUM:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_LOOS:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_ATTRIBUTES:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_HASH:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_LIBLIST:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_CHECKSUM:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_LOSUNW:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_SUNW_COMDAT:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_SUNW_syminfo:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_verdef:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_verneed:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_GNU_versym:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_LOPROC:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_HIPROC:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_LOUSER:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            case SHT_HIUSER:
                if (level == 3) relocation(arrayc, sh_table, symbol_table);
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNKNOWN ");
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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n[");
        switch(sh_table[i].sh_type) {
            case SHT_NULL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NULL                     (Section header table entry unused)                   ");
                break;
            case SHT_PROGBITS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PROGBITS                 (Program data)                                        ");
                break;
            case SHT_SYMTAB: 
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SYMTAB                   (Symbol table)                                        ");
                break;
            case SHT_STRTAB:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "STRTAB                   (String table)                                        ");
                break;
            case SHT_RELA:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "RELA                     (Relocation entries with addends)                     ");
                break;
            case SHT_HASH:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "HASH                     (Symbol hash table)                                   ");
                break;
            case SHT_DYNAMIC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DYNAMIC                  (Dynamic linking information)                         ");
                break;
            case SHT_NOTE:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NOTE                     (Notes)                                               ");
                break;
            case SHT_NOBITS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NOBITS                   (Program space with no data (bss))                    ");
                break;
            case SHT_REL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "REL                      (Relocation entries, no addends)                      ");
                break;
            case SHT_SHLIB:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SHLIB                    (Reserved)                                            ");
                break;
            case SHT_DYNSYM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DYNSYM                   (Dynamic linker symbol table)                         ");
                break;
            case SHT_INIT_ARRAY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "INIT_ARRAY               (Array of constructors)                               ");
                break;
            case SHT_FINI_ARRAY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FINI_ARRAY               (Array of destructors)                                ");
                break;
            case SHT_PREINIT_ARRAY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PREINIT_ARRAY            (Array of pre-constructors)                           ");
                break;
            case SHT_GROUP:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GROUP                    (Section group)                                       ");
                break;
            case SHT_SYMTAB_SHNDX:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SYMTAB_SHNDX             (Extended section indeces)                            ");
                break;
            case SHT_NUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NUM                      (Number of defined types)                             ");
                break;
            case SHT_LOOS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "LOOS                     (Start OS-specific)                                   ");
                break;
            case SHT_GNU_ATTRIBUTES:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GNU_ATTRIBUTES           (Object attributes)                                   ");
                break;
            case SHT_GNU_HASH:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GNU_HASH                 (GNU-style hash table)                                ");
                break;
            case SHT_GNU_LIBLIST:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GNU_LIBLIST              (Prelink library list)                                ");
                break;
            case SHT_CHECKSUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "CHECKSUM                 (Checksum for DSO content)                            ");
                break;
            case SHT_LOSUNW:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "LOSUNW or SUNW_move                                                            ");
                break;
            case SHT_SUNW_COMDAT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SUNW_COMDAT                                                                    ");
                break;
            case SHT_SUNW_syminfo:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SUNW_syminfo                                                                   ");
                break;
            case SHT_GNU_verdef:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GNU_verdef               (Version definition section)                          ");
                break;
            case SHT_GNU_verneed:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GNU_verneed              (Version needs section)                               ");
                break;
            case SHT_GNU_versym:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GNU_versym               (Version symbol table) or HISUNW (Sun-specific high bound) or HIOS (End OS-specific type) ");
                break;
            case SHT_LOPROC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "LOPROC                   (Start of processor-specific)                         ");
                break;
            case SHT_HIPROC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "HIPROC                   (End of processor-specific)                           ");
                break;
            case SHT_LOUSER:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "LOUSER                   (Start of application-specific)                       ");
                break;
            case SHT_HIUSER:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "HIUSER                   (End of application-specific)                         ");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNKNOWN                                                                        ");
        }
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Section %d, Index %d]\n", ii, i);
        print_elf_symbol_table(arrayd, eh, sh_table, i);
        ii++;
    }
}

char * symbol_lookup(char * arrayc, Elf64_Shdr sh_table[], uint64_t symbol_table, int index, int mode, const char * am_i_quiet) {
    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "looking up index %d of table %d\n", index, symbol_table);
    Elf64_Sym* sym_tbl = (Elf64_Sym*)read_section_(arrayc, sh_table[symbol_table]);
    uint64_t str_tbl_ndx = sh_table[symbol_table].sh_link;
    char *str_tbl = read_section_(arrayc, sh_table[str_tbl_ndx]);
    uint64_t symbol_count = (sh_table[symbol_table].sh_size/sizeof(Elf64_Sym));
    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "requested symbol name for index %d is %s\n", index, demangle_it(str_tbl + sym_tbl[index].st_name));
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
            char * address = sym_tbl[i].st_value+library[library_index].mapping_start;
            if (bytecmpq(symbol_quiet, "no") == 0) fprintf(stderr, "requested symbol name \"%s\" found in table %d at address %014p is \"%s\"\n", name_, symbol_table, address, name);

            return analyse_address(address, name);
        }
    }
    if (bytecmpq(symbol_quiet, "no") == 0) fprintf(stderr, "\nrequested symbol name \"%s\" could not be found in table %d\n\n", name_, symbol_table);
    return NULL;
}

char * print_elf_symbol_table_lookup(char * arrayc, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], uint64_t symbol_table, int index, int mode)
{
        switch(sh_table[symbol_table].sh_type) {
            case SHT_DYNSYM:
                return symbol_lookup(arrayc, sh_table, symbol_table, index, mode, relocation_quiet);
                break;
            default:
                return (int) -1;
                break;
        }
}

char * print_elf_symbol_table_lookup_name(char * arrayc, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], uint64_t symbol_table, char * index)
{
        char * name_;
        switch(sh_table[symbol_table].sh_type) {
            case SHT_DYNSYM:
                name_ = symbol_lookup_name(arrayc, sh_table, symbol_table, index);
                if (name_ != NULL) {
                    return name_;
                }
                else {
                    return NULL;
                }
                break;
            case SHT_SYMTAB:
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

char * print_symbols_lookup(char * arrayd, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], int index, int mode)
{
    for(int i=0; i<eh->e_shnum; i++) {
        int value = print_elf_symbol_table_lookup(arrayd, eh, sh_table, i, index, mode);
        if ( value != -1 ) return value;
    }
}

char * print_symbols_lookup_name(char * arrayd, Elf64_Ehdr * eh, Elf64_Shdr sh_table[], char * index)
{
    char * value;
    for(int i=0; i<eh->e_shnum; i++) {
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
        init_(lib);
        const char * arrayb = library[library_index].array;
        Elf64_Ehdr * eh = (Elf64_Ehdr *) arrayb;
        Elf64_Shdr *_elf_symbol_tableb;
        if(!strncmp((char*)eh->e_ident, "\177ELF", 4)) {
            if ( read_section_header_table_(arrayb, eh, &_elf_symbol_tableb) == 0) {
                char * symbol = print_symbols_lookup_name(arrayb, eh, _elf_symbol_tableb, name);
//                 fprintf(stderr, "returning %014p\n", symbol);
                return symbol;
            }
        }
        else abort_();
}

void * lookup_symbol_by_index(const char * arrayb, Elf64_Ehdr * eh, int symbol_index, int mode, const char * am_i_quiet) {
        if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "attempting to look up symbol, index = %d\n", symbol_index);

        read_section_header_table_(arrayb, eh, &library[library_index]._elf_symbol_table);
        char * symbol = print_symbols_lookup(arrayb, eh, library[library_index]._elf_symbol_table, symbol_index, mode);
        if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "symbol = %d (%014p)\n", symbol, symbol);
        return symbol;
}

Elf64_Dyn *
get_dynamic_entry(Elf64_Dyn *dynamic, int field)
{
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "called get_dynamic_entry\n");

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
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "testing if ");
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
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_NULL");
                break;
            case DT_NEEDED:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_NEEDED");
                break;
            case DT_PLTRELSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PLTRELSZ");
                break;
            case DT_PLTGOT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PLTGOT");
                break;
            case DT_HASH:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_HASH");
                break;
            case DT_STRTAB:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_STRTAB");
                break;
            case DT_SYMTAB:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_SYMTAB");
                break;
            case DT_RELA:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELA");
                break;
            case DT_RELASZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELASZ");
                break;
            case DT_RELAENT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELAENT");
                break;
            case DT_STRSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_STRSZ");
                break;
            case DT_SYMENT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_SYMENT");
                break;
            case DT_INIT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_INIT");
                break;
            case DT_FINI:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FINI");
                break;
            case DT_SONAME:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_SONAME");
                break;
            case DT_RPATH:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RPATH");
                break;
            case DT_SYMBOLIC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_SYMBOLIC");
                break;
            case DT_REL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_REL");
                break;
            case DT_RELSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELSZ");
                break;
            case DT_RELENT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELENT");
                break;
            case DT_PLTREL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PLTREL");
                break;
            case DT_DEBUG:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_DEBUG");
                break;
            case DT_TEXTREL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_TEXTREL");
                break;
            case DT_JMPREL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_JMPREL");
                break;
            case DT_BIND_NOW:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_BIND_NOW");
                break;
            case DT_INIT_ARRAY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_INIT_ARRAY");
                break;
            case DT_FINI_ARRAY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FINI_ARRAY");
                break;
            case DT_INIT_ARRAYSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_INIT_ARRAYSZ");
                break;
            case DT_FINI_ARRAYSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FINI_ARRAYSZ");
                break;
            case DT_RUNPATH:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RUNPATH");
                break;
            case DT_FLAGS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FLAGS");
                break;
            case DT_ENCODING:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_ENCODING (or DT_PREINIT_ARRAY)");
                break;
            case DT_PREINIT_ARRAYSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PREINIT_ARRAYSZ");
                break;
            case DT_NUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_NUM");
                break;
            case DT_LOOS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_LOOS");
                break;
            case DT_HIOS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_HIOS");
                break;
            case DT_LOPROC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_LOPROC");
                break;
            case DT_HIPROC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_HIPROC (or DT_FILTER)");
                break;
            case DT_PROCNUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PROCNUM");
                break;
            case DT_VERSYM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERSYM");
                break;
            case DT_RELACOUNT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELACOUNT");
                break;
            case DT_RELCOUNT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELCOUNT");
                break;
            case DT_FLAGS_1:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FLAGS_1");
                break;
            case DT_VERDEF:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERDEF");
                break;
            case DT_VERDEFNUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERDEFNUM");
                break;
            case DT_VERNEED:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERNEED");
                break;
            case DT_VERNEEDNUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERNEEDNUM");
                break;
            case DT_AUXILIARY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_AUXILIARY");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%d", dynamic->d_tag);
                break;
        }
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " == ");
        switch (field) {
            case DT_NULL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_NULL");
                break;
            case DT_NEEDED:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_NEEDED");
                break;
            case DT_PLTRELSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PLTRELSZ");
                break;
            case DT_PLTGOT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PLTGOT");
                break;
            case DT_HASH:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_HASH");
                break;
            case DT_STRTAB:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_STRTAB");
                break;
            case DT_SYMTAB:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_SYMTAB");
                break;
            case DT_RELA:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELA");
                break;
            case DT_RELASZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELASZ");
                break;
            case DT_RELAENT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELAENT");
                break;
            case DT_STRSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_STRSZ");
                break;
            case DT_SYMENT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_SYMENT");
                break;
            case DT_INIT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_INIT");
                break;
            case DT_FINI:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FINI");
                break;
            case DT_SONAME:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_SONAME");
                break;
            case DT_RPATH:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RPATH");
                break;
            case DT_SYMBOLIC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_SYMBOLIC");
                break;
            case DT_REL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_REL");
                break;
            case DT_RELSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELSZ");
                break;
            case DT_RELENT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELENT");
                break;
            case DT_PLTREL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PLTREL");
                break;
            case DT_DEBUG:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_DEBUG");
                break;
            case DT_TEXTREL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_TEXTREL");
                break;
            case DT_JMPREL:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_JMPREL");
                break;
            case DT_BIND_NOW:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_BIND_NOW");
                break;
            case DT_INIT_ARRAY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_INIT_ARRAY");
                break;
            case DT_FINI_ARRAY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FINI_ARRAY");
                break;
            case DT_INIT_ARRAYSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_INIT_ARRAYSZ");
                break;
            case DT_FINI_ARRAYSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FINI_ARRAYSZ");
                break;
            case DT_RUNPATH:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RUNPATH");
                break;
            case DT_FLAGS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FLAGS");
                break;
            case DT_ENCODING:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_ENCODING (or DT_PREINIT_ARRAY)");
                break;
            case DT_PREINIT_ARRAYSZ:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PREINIT_ARRAYSZ");
                break;
            case DT_NUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_NUM");
                break;
            case DT_LOOS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_LOOS");
                break;
            case DT_HIOS:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_HIOS");
                break;
            case DT_LOPROC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_LOPROC");
                break;
            case DT_HIPROC:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_HIPROC (or DT_FILTER)");
                break;
            case DT_PROCNUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_PROCNUM");
                break;
            case DT_VERSYM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERSYM");
                break;
            case DT_RELACOUNT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELACOUNT");
                break;
            case DT_RELCOUNT:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_RELCOUNT");
                break;
            case DT_FLAGS_1:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_FLAGS_1");
                break;
            case DT_VERDEF:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERDEF");
                break;
            case DT_VERDEFNUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERDEFNUM");
                break;
            case DT_VERNEED:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERNEED");
                break;
            case DT_VERNEEDNUM:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_VERNEEDNUM");
                break;
            case DT_AUXILIARY:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "DT_AUXILIARY");
                break;
            default:
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "%d (unknown)", field);
                break;
        }
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n");
        if (dynamic->d_tag == field) return dynamic;
    }
    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "returning 0\n");
    return &DYN_EMPTY;
}

Elf64_Dyn *
get_dynamic_entryq(Elf64_Dyn *dynamic, int field)
{
    for (; dynamic->d_tag != DT_NULL; dynamic++) if (dynamic->d_tag == field) return dynamic;
    return &DYN_EMPTY;
}

int
if_valid(const char * file) {
    if(!access(file, F_OK)) return 0;
    else return -1;
}

void *
dlopen_(const char * cc);

void *
dlsym(const char * cc1, const char * cc2);

Elf64_Word
get_needed(const char * lib)
{
     if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "\n\naquiring \"%s\"\n", lib);

     if (library[library_index].struct_init != "initialized") init_struct();
     if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "current index %d holds \"%s\"\nsearching indexes for \"%s\" incase it has already been loaded\n", library_index, library[library_index].last_lib, lib);
    
    library_index = searchq(lib);
    int local_index = library_index;
    int local_indexb = library_index;
    library[library_index].last_lib = lib;
    library[library_index].current_lib = lib;

     if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "checking if %s index %d is locked\n", library[library_index].last_lib, library_index);
    if (library[library_index].init_lock == 1) {
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "get_needed: LOCKED\n");
    }
    else {
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "get_needed: UNLOCKED\n");
    }
    if ( if_valid(lib) == -1) {
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "\"%s\" not found\n", lib);
        errno = 0;
        return "-1";
    }
     if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "init\n");
    if (library[library_index].array != NULL) {
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "%s has a non null array\n", library[library_index].last_lib);
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "index %d get_needed: LOCKING\n", library_index);
        library[library_index].init_lock = 1;
        if (library[library_index].init_lock == 1) {
             if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "status: LOCKED\n");
        }
        else {
             if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "status: UNLOCKED\n");
        }
    } else {
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "%s has a null array\n", library[library_index].last_lib);
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "index %d get_needed: UNLOCKING\n", library_index);
        library[library_index].init_lock = 0;
        if (library[library_index].init_lock == 1) {
             if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "status: LOCKED\n");
        }
        else {
             if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "status: UNLOCKED\n");
        }
    }
    dlopen_(lib);
    dlsym(lib, "");
     if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "init done\n");
     if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "current index %d holds \"%s\"\nsearching indexes for \"%s\" incase it has already been loaded\n", library_index, library[library_index].last_lib, lib);
    
    library_index = searchq(lib);
    local_index = library_index;
    library[library_index].last_lib = lib;
    library[library_index].current_lib = lib;

    Elf64_Dyn *dynamic = library[library_index].dynamic;
    Elf64_Dyn *dynamicb = library[library_index].dynamic;
    const char * arrayb = library[library_index].array;
    print_needed(lib, depth_default, LDD);
    for (int i = 0; i<=library[library_index].NEEDED_COUNT-1; i++) get_needed(library[library_index].NEEDED[i]);
    local_index = local_indexb;
     if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "index %d get_needed: UNLOCKING\n", local_index);
    library[local_index].init_lock = 0;
    if (library[local_index].init_lock == 1) {
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "status: LOCKED\n");
    }
    else {
         if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "status: UNLOCKED\n");
    }
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
    if (relocs != library[library_index].mapping_start && relocs_size != 0) {
        for (int i = 0; i < relocs_size  / sizeof(Elf64_Rela); i++) {
            Elf64_Rela *reloc = &relocs[i];
            int reloc_type = ELF64_R_TYPE(reloc->r_info);
            if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "i = %d,\t\tELF64_R_TYPE(reloc->r_info)\t= ", i);
            switch (reloc_type) {
                #if defined(__x86_64__)
                case R_X86_64_NONE:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_NONE                calculation: none\n");
                    library[library_index]._R_X86_64_NONE++;
                    break;
                }
                case R_X86_64_64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_64                  calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_64++;
                    break;
                }
                case R_X86_64_PC32:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_PC32                calculation: S + A - P (symbol value + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_PC32++;
                    break;
                }
                case R_X86_64_GOT32:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOT32               calculation: G + A (address of global offset table + r_addend)\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOT32++;
                    break;
                }
                case R_X86_64_PLT32:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_PLT32               calculation: L + A - P ((L: This means the place (section offset or address) of the procedure linkage table entry for a symbol) + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).) \n");
                    library[library_index]._R_X86_64_PLT32++;
                    break;
                }
                case R_X86_64_COPY:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_COPY                calculation: none\n");
                    library[library_index]._R_X86_64_COPY++;
                    break;
                }
                case R_X86_64_GLOB_DAT:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GLOB_DAT            calculation: S (symbol value)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].mapping_start, reloc->r_offset, library[library_index].mapping_start+reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet)+library[library_index].mapping_start;
                    char ** addr = reloc->r_offset + library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) test_address(addr);
                    library[library_index]._R_X86_64_GLOB_DAT++;
                    break;
                }
                case R_X86_64_JUMP_SLOT:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_JUMP_SLOT           calculation: S (symbol value)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "library[library_index].mapping_start    = %014p\n", library[library_index].mapping_start);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].mapping_start, reloc->r_offset, library[library_index].mapping_start+reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet)+library[library_index].mapping_start;
                    char ** addr = reloc->r_offset + library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) test_address(addr);
                    library[library_index]._R_X86_64_JUMP_SLOT++;
                    break;
                }
                case R_X86_64_RELATIVE:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_RELATIVE            calculation: B + A (base address + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "library[library_index].base_address    = %014p\n", library[library_index].base_address);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].base_address, reloc->r_offset, library[library_index].base_address+reloc->r_offset);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_addend = %014p+%014p=%014p\n", library[library_index].base_address, reloc->r_addend, ((char*)library[library_index].base_address + reloc->r_addend) );
					pp(((char**)((char*)library[library_index].base_address + reloc->r_offset)));
					pp(*((char**)((char*)library[library_index].base_address + reloc->r_offset)));
					*((char**)((char*)library[library_index].base_address + reloc->r_offset)) = 0x1;
					pp(*((char**)((char*)library[library_index].base_address + reloc->r_offset)));
                    *((char**)((char*)library[library_index].base_address + reloc->r_offset)) = ((char*)library[library_index].base_address + reloc->r_addend);
                    char ** addr = reloc->r_offset + library[library_index].base_address;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) test_address(addr);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].base_address + reloc->r_offset)            = %014p\n", ((char*)library[library_index].base_address + reloc->r_offset));
                    library[library_index]._R_X86_64_RELATIVE++;
                    break;
                }
                case R_X86_64_GOTPCREL:
                {
//                     if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\naddress of GOT[0] = %014p\n", ((Elf64_Addr *) lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_"))[0]);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPCREL            calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).))) \n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPCREL++;
                    break;
                }
                case R_X86_64_32:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_32                  calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_32++;
                    break;
                }
                case R_X86_64_32S:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_32S                 calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_32S++;
                    break;
                }
                case R_X86_64_16:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_16                  calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_16++;
                    break;
                }
                case R_X86_64_PC16:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_PC16                calculation: S + A - P (symbol value + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).))\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_PC16++;
                    break;
                }
                case R_X86_64_8:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_8                   calculation: S + A (symbol value + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_8++;
                    break;
                }
                case R_X86_64_PC8:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_PC8                 calculation: S + A - P (symbol value + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).))\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_PC8++;
                    break;
                }
                case R_X86_64_DTPMOD64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_DTPMOD64\n");
                    library[library_index]._R_X86_64_DTPMOD64++;
                    break;
                }
                case R_X86_64_DTPOFF64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_DTPOFF64\n");
                    library[library_index]._R_X86_64_DTPOFF64++;
                    break;
                }
                case R_X86_64_TPOFF64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_TPOFF64\n");
                    library[library_index]._R_X86_64_TPOFF64++;
                    break;
                }
                case R_X86_64_TLSGD:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_TLSGD\n");
                    library[library_index]._R_X86_64_TLSGD++;
                    break;
                }
                case R_X86_64_TLSLD:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_TLSLD\n");
                    library[library_index]._R_X86_64_TLSLD++;
                    break;
                }
                case R_X86_64_DTPOFF32:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_DTPOFF32\n");
                    library[library_index]._R_X86_64_DTPOFF32++;
                    break;
                }
                case R_X86_64_GOTTPOFF:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTTPOFF\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTTPOFF++;
                    break;
                }
                case R_X86_64_TPOFF32:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_TPOFF32\n");
                    library[library_index]._R_X86_64_TPOFF32++;
                    break;
                }
                case R_X86_64_PC64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_PC64                calculation: S + A - P (symbol value + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).))\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_PC64++;
                    break;
                }
                case R_X86_64_GOTOFF64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTOFF64            calculation: S + A - GOT (symbol value + r_addend - address of global offset table)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_S, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTOFF64++;
                    break;
                }
                case R_X86_64_GOTPC32:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPC32             calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPC32++;
                    break;
                }
                case R_X86_64_GOT64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOT64               calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOT64++;
                    break;
                }
                case R_X86_64_GOTPCREL64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPCREL64          calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPCREL64++;
                    break;
                }
                case R_X86_64_GOTPC64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPC64             calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPC64++;
                    break;
                }
                case R_X86_64_GOTPLT64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPLT64            calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPLT64++;
                    break;
                }
                case R_X86_64_PLTOFF64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_PLTOFF64\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_PLTOFF64++;
                    break;
                }
                case R_X86_64_SIZE32:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_SIZE32                 calculation: Z + A (symbol size + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_Z, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_SIZE32++;
                    break;
                }
                case R_X86_64_SIZE64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_SIZE64                 calculation: Z + A (symbol size + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p\n", reloc->r_offset);
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = lookup_symbol_by_index(library[library_index].array, library[library_index]._elf_header, ELF64_R_SYM(reloc->r_info), symbol_mode_Z, symbol_quiet) + reloc->r_addend+library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_SIZE64++;
                    break;
                }
                case R_X86_64_GOTPC32_TLSDESC:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPC32_TLSDESC     calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPC32_TLSDESC++;
                    break;
                }
                case R_X86_64_TLSDESC_CALL:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_TLSDESC_CALL\n");
                    library[library_index]._R_X86_64_TLSDESC_CALL++;
                    break;
                }
                case R_X86_64_TLSDESC:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_TLSDESC\n");
                    library[library_index]._R_X86_64_TLSDESC++;
                    break;
                }
                case R_X86_64_IRELATIVE:
                {

                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_IRELATIVE                 calculation: (indirect) B + A (base address + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "library[library_index].mapping_start    = %014p\n", library[library_index].mapping_start);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].mapping_start, reloc->r_offset, library[library_index].mapping_start+reloc->r_offset);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_addend = %014p+%014p=%014p\n", library[library_index].mapping_start, reloc->r_addend, ((char*)library[library_index].mapping_start + reloc->r_addend) );
                    Elf64_Addr value;
//                     // changed, somehow this may cause a seg fault, dont use
//                     value = ((char*)library[library_index].mapping_start + reloc->r_addend);
//                     value = ((Elf64_Addr (*) (void)) value) ();
//                     *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = value;
                    // original
                    *((char**)((char*)library[library_index].mapping_start + reloc->r_offset)) = ((char*)library[library_index].mapping_start + reloc->r_addend);
                    //
                    char ** addr = reloc->r_offset + library[library_index].mapping_start;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) test_address(addr);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].mapping_start + reloc->r_offset)            = %014p\n", ((char*)library[library_index].mapping_start + reloc->r_offset));
                    library[library_index]._R_X86_64_IRELATIVE++;
                    break;
                }
                case R_X86_64_RELATIVE64:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_RELATIVE64                 calculation: B + A (base address + r_addend)\n");
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "library[library_index].base_address    = %014p\n", library[library_index].base_address);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_offset = %014p+%014p=%014p\n", library[library_index].base_address, reloc->r_offset, library[library_index].base_address+reloc->r_offset);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "reloc->r_addend = %014p+%014p=%014p\n", library[library_index].base_address, reloc->r_addend, ((char*)library[library_index].base_address + reloc->r_addend) );
                    *((char**)((char*)library[library_index].base_address + reloc->r_offset)) = ((char*)library[library_index].base_address + reloc->r_addend);
                    char ** addr = reloc->r_offset + library[library_index].base_address;
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) test_address(addr);
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "((char*)library[library_index].base_address + reloc->r_offset)            = %014p\n", ((char*)library[library_index].base_address + reloc->r_offset));
                    library[library_index]._R_X86_64_RELATIVE64++;
                    break;
                }
                case R_X86_64_GOTPCRELX:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_GOTPCRELX           calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_GOTPCRELX++;
                    break;
                }
                case R_X86_64_REX_GOTPCRELX:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_REX_GOTPCRELX       calculation: (_GOTPC: GOT + A - P (address of global offset table + r_addend - (P: This means the place (section offset or address) of the storage unit being relocated (computed using r_offset ).)))\n");
                    Elf64_Addr * GOT = lookup_symbol_by_name(library[library_index].array, library[library_index]._elf_header, "_GLOBAL_OFFSET_TABLE_");
                    library[library_index]._R_X86_64_REX_GOTPCRELX++;
                    break;
                }
                case R_X86_64_NUM:
                {
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "\n\n\nR_X86_64_NUM\n");
                    library[library_index]._R_X86_64_NUM++;
                    break;
                }
                #endif
                default:
                    if (bytecmpq(global_quiet, "no") == 0) if (bytecmpq(am_i_quiet, "no") == 0) fprintf(stderr, "unknown type, got %d\n", reloc_type);
                    library[library_index]._R_X86_64_UNKNOWN++;
                    break;
            }
        }
    }
    if (bytecmpq(global_quiet, "no") == 0) nl();
    if (bytecmpq(global_quiet, "no") == 0) nl();
    if (bytecmpq(global_quiet, "no") == 0) nl();
}

int r_summary() {
    if (bytecmpq(global_quiet, "no") == 0) printf( "relocation summary:\n \
    R_X86_64_NONE              = %d\n \
    R_X86_64_64                = %d\n \
    R_X86_64_PC32              = %d\n \
    R_X86_64_GOT32             = %d\n \
    R_X86_64_PLT32             = %d\n \
    R_X86_64_COPY              = %d\n \
    R_X86_64_GLOB_DAT          = %d\n \
    R_X86_64_JUMP_SLOT         = %d\n \
    R_X86_64_RELATIVE          = %d\n \
    R_X86_64_GOTPCREL          = %d\n \
    R_X86_64_32                = %d\n \
    R_X86_64_32S               = %d\n \
    R_X86_64_16                = %d\n \
    R_X86_64_PC16              = %d\n \
    R_X86_64_8                 = %d\n \
    R_X86_64_PC8               = %d\n \
    R_X86_64_DTPMOD64          = %d\n \
    R_X86_64_DTPOFF64          = %d\n \
    R_X86_64_TPOFF64           = %d\n \
    R_X86_64_TLSGD             = %d\n \
    R_X86_64_TLSLD             = %d\n \
    R_X86_64_DTPOFF32          = %d\n \
    R_X86_64_GOTTPOFF          = %d\n \
    R_X86_64_TPOFF32           = %d\n \
    R_X86_64_PC64              = %d\n \
    R_X86_64_GOTOFF64          = %d\n \
    R_X86_64_GOTPC32           = %d\n \
    R_X86_64_GOT64             = %d\n \
    R_X86_64_GOTPCREL64        = %d\n \
    R_X86_64_GOTPC64           = %d\n \
    Deprecated1                = %d\n \
    R_X86_64_PLTOFF64          = %d\n \
    R_X86_64_SIZE32            = %d\n \
    R_X86_64_SIZE64            = %d\n \
    R_X86_64_GOTPC32_TLSDESC   = %d\n \
    R_X86_64_TLSDESC_CALL      = %d\n \
    R_X86_64_TLSDESC           = %d\n \
    R_X86_64_IRELATIVE         = %d\n \
    R_X86_64_RELATIVE64        = %d\n \
    Deprecated2                = %d\n \
    Deprecated3                = %d\n \
    R_X86_64_GOTPLT64          = %d\n \
    R_X86_64_GOTPCRELX         = %d\n \
    R_X86_64_REX_GOTPCRELX     = %d\n \
    R_X86_64_NUM               = %d\n \
    R_X86_64_UNKNOWN           = %d\n \
    total                       = %d\n", library[library_index]._R_X86_64_NONE, library[library_index]._R_X86_64_64, library[library_index]._R_X86_64_PC32, library[library_index]._R_X86_64_GOT32, library[library_index]._R_X86_64_PLT32, library[library_index]._R_X86_64_COPY, library[library_index]._R_X86_64_GLOB_DAT, library[library_index]._R_X86_64_JUMP_SLOT, library[library_index]._R_X86_64_RELATIVE, library[library_index]._R_X86_64_GOTPCREL, library[library_index]._R_X86_64_32, library[library_index]._R_X86_64_32S, library[library_index]._R_X86_64_16, library[library_index]._R_X86_64_PC16, library[library_index]._R_X86_64_8, library[library_index]._R_X86_64_PC8, library[library_index]._R_X86_64_DTPMOD64, library[library_index]._R_X86_64_DTPOFF64, library[library_index]._R_X86_64_TPOFF64, library[library_index]._R_X86_64_TLSGD, library[library_index]._R_X86_64_TLSLD, library[library_index]._R_X86_64_DTPOFF32, library[library_index]._R_X86_64_GOTTPOFF, library[library_index]._R_X86_64_TPOFF32, library[library_index]._R_X86_64_PC64, library[library_index]._R_X86_64_GOTOFF64, library[library_index]._R_X86_64_GOTPC32, library[library_index]._R_X86_64_GOT64, library[library_index]._R_X86_64_GOTPCREL64, library[library_index]._R_X86_64_GOTPC64, library[library_index]._Deprecated1, library[library_index]._R_X86_64_PLTOFF64, library[library_index]._R_X86_64_SIZE32, library[library_index]._R_X86_64_SIZE64, library[library_index]._R_X86_64_GOTPC32_TLSDESC, library[library_index]._R_X86_64_TLSDESC_CALL, library[library_index]._R_X86_64_TLSDESC, library[library_index]._R_X86_64_IRELATIVE, library[library_index]._R_X86_64_RELATIVE64, library[library_index]._Deprecated2, library[library_index]._Deprecated3, library[library_index]._R_X86_64_GOTPLT64, library[library_index]._R_X86_64_GOTPCRELX, library[library_index]._R_X86_64_REX_GOTPCRELX, library[library_index]._R_X86_64_NUM, library[library_index]._R_X86_64_UNKNOWN, library[library_index]._R_X86_64_NONE + library[library_index]._R_X86_64_64 + library[library_index]._R_X86_64_PC32 + library[library_index]._R_X86_64_GOT32 + library[library_index]._R_X86_64_PLT32 + library[library_index]._R_X86_64_COPY + library[library_index]._R_X86_64_GLOB_DAT + library[library_index]._R_X86_64_JUMP_SLOT + library[library_index]._R_X86_64_RELATIVE + library[library_index]._R_X86_64_GOTPCREL + library[library_index]._R_X86_64_32 + library[library_index]._R_X86_64_32S + library[library_index]._R_X86_64_16 + library[library_index]._R_X86_64_PC16 + library[library_index]._R_X86_64_8 + library[library_index]._R_X86_64_PC8 + library[library_index]._R_X86_64_DTPMOD64 + library[library_index]._R_X86_64_DTPOFF64 + library[library_index]._R_X86_64_TPOFF64 + library[library_index]._R_X86_64_TLSGD + library[library_index]._R_X86_64_TLSLD + library[library_index]._R_X86_64_DTPOFF32 + library[library_index]._R_X86_64_GOTTPOFF + library[library_index]._R_X86_64_TPOFF32 + library[library_index]._R_X86_64_PC64 + library[library_index]._R_X86_64_GOTOFF64 + library[library_index]._R_X86_64_GOTPC32 + library[library_index]._R_X86_64_GOT64 + library[library_index]._R_X86_64_GOTPCREL64 + library[library_index]._R_X86_64_GOTPC64 + library[library_index]._Deprecated1 + library[library_index]._R_X86_64_PLTOFF64 + library[library_index]._R_X86_64_SIZE32 + library[library_index]._R_X86_64_SIZE64 + library[library_index]._R_X86_64_GOTPC32_TLSDESC + library[library_index]._R_X86_64_TLSDESC_CALL + library[library_index]._R_X86_64_TLSDESC + library[library_index]._R_X86_64_IRELATIVE + library[library_index]._R_X86_64_RELATIVE64 + library[library_index]._Deprecated2 + library[library_index]._Deprecated3 + library[library_index]._R_X86_64_GOTPLT64 + library[library_index]._R_X86_64_GOTPCRELX + library[library_index]._R_X86_64_REX_GOTPCRELX + library[library_index]._R_X86_64_NUM + library[library_index]._R_X86_64_UNKNOWN);
}

bool DYN_IS_NULL(Elf64_Dyn * DYN) {
	return (DYN->d_un.d_ptr != 0 && DYN->d_un.d_val != 0);
}

/* Type of the initializer.  */
typedef void (*init_t) (int, char **, char **);
# define DL_CALL_DT_INIT(start, argc, argv, env) ((init_t) (start)) (argc, argv, env)
# define DL_CALL_DT_FINI(map, start) ((fini_t) (start)) ()

void call_init_(int library_index) {
	Elf64_Dyn * INIT = get_dynamic_entry(library[library_index].dynamic, DT_INIT);
	if (DYN_IS_NULL(INIT)) {
		printf("attempting to call DT_INIT for %s\n", library[library_index].current_lib);
		pp(library[library_index].base_address + INIT->d_un.d_ptr)
		DL_CALL_DT_INIT(library[library_index].base_address + INIT->d_un.d_ptr, libstring_argc, libstring_argv, libstring_env);
		puts("DT_INIT CALLED");
	}
	else {
		puts("NO DT_INIT");
		pi(INIT->d_un.d_ptr)
		pi(INIT->d_un.d_val)
	}
			
	/* Next see whether there is an array with initialization functions.  */
	Elf64_Dyn *init_array = get_dynamic_entry(library[library_index].dynamic, DT_INIT_ARRAY);
	if (DYN_IS_NULL(init_array)) {
		unsigned int j;

		unsigned int jm = get_dynamic_entry(library[library_index].dynamic, DT_INIT_ARRAYSZ)->d_un.d_val / sizeof (Elf64_Addr);
		printf("get_dynamic_entry(library[library_index].dynamic, DT_INIT_ARRAYSZ)->d_un.d_val / sizeof (Elf64_Addr) = %d, ", get_dynamic_entry(library[library_index].dynamic, DT_INIT_ARRAYSZ)->d_un.d_val / sizeof (Elf64_Addr));

		Elf64_Addr *addrs = (Elf64_Addr *) (library[library_index].base_address + init_array->d_un.d_ptr);
		for (j=0; j<jm;j++) {
			printf("((Elf64_Addr *) (library[library_index].base_address + init_array->d_un.d_ptr))[%d] = 0x%012x", j, ((Elf64_Addr *) (library[library_index].base_address + init_array->d_un.d_ptr))[j]);
			if (j+1!=jm) printf(", ");
		}
		puts("");

		printf("addrs    = %p\n", addrs);
		printf("addrs[0] = 0x%012x\n", addrs[0]);
		printf("addrs[1] = 0x%012x\n", addrs[1]);
		for (j = 0; j < jm; ++j) {
			printf("addrs[%d] = 0x%012x\n", j, addrs[j]);
			printf("executing ((init_t) addrs[%d]) (libstring_argc, libstring_argv, libstring_env)\n", j);
			// gdb ./files/loader -ex "handle SIGSEGV nostop pass noprint" -ex "r" -ex "break readelf_.c:3158"
			((init_t) addrs[j]) (libstring_argc, libstring_argv, libstring_env);
			printf("successfully executed ((init_t) addrs[%d]) (libstring_argc, libstring_argv, libstring_env)\n", j);
		}
		
// 		for (j = 0; j < get_dynamic_entry(library[library_index].dynamic, DT_INIT_ARRAYSZ)->d_un.d_val / sizeof (Elf64_Addr); ++j) ((init_t) ((Elf64_Addr *) (library[library_index].base_address + get_dynamic_entry(library[library_index].dynamic, DT_INIT_ARRAY)->d_un.d_ptr))[j]) (libstring_argc, libstring_argv, libstring_env);
// 		abort();
	}
}

int
init_(const char * filename) {
    init(filename);
    if (library[library_index].init__ == 1) return 0;
    library[library_index]._elf_header = (Elf64_Ehdr *) library[library_index].array;
    read_section_header_table_(library[library_index].array, library[library_index]._elf_header, &library[library_index]._elf_symbol_table);
    obtain_rela_plt_size(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table);
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
            library[library_index].GOT2 = library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_PLTGOT)->d_un.d_val;

            r_init();
            r(library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_RELA)->d_un.d_val, get_dynamic_entry(library[library_index].dynamic, DT_RELASZ)->d_un.d_val, relocation_quiet);
            r(library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_JMPREL)->d_un.d_val, library[library_index].RELA_PLT_SIZE, relocation_quiet);
            r(library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_BIND_NOW)->d_un.d_val, library[library_index].RELA_PLT_SIZE, relocation_quiet);
//             r(library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_PLTREL)->d_un.d_val, get_dynamic_entry(library[library_index].dynamic, DT_PLTRELSZ)->d_un.d_val, relocation_quiet);
            r_summary();
			
			// call init
			
  Elf64_Dyn *preinit_array = get_dynamic_entry(library[library_index].dynamic, DT_PREINIT_ARRAY);
  Elf64_Dyn *preinit_array_size = get_dynamic_entry(library[library_index].dynamic, DT_PREINIT_ARRAYSZ);
  unsigned int i;
  
//   if (__glibc_unlikely (GL(dl_initfirst) != NULL))
//     {
//       call_init (GL(dl_initfirst), argc, argv, env);
//       GL(dl_initfirst) = NULL;
//     }
// 
//   /* Don't do anything if there is no preinit array.  */
	pp(library[library_index].dynamic[DT_PREINIT_ARRAY])
  if (DYN_IS_NULL(preinit_array)
      && DYN_IS_NULL(preinit_array_size)
      && (i = preinit_array_size->d_un.d_val / sizeof (Elf64_Addr)) > 0)
    {
      Elf64_Addr *addrs;
      unsigned int cnt;

	  printf("\ncalling preinit: %s\n\n", library[library_index].current_lib);

	  addrs = (Elf64_Addr *) (preinit_array->d_un.d_ptr + library[library_index].base_address);
      for (cnt = 0; cnt < i; ++cnt) {
		  ((init_t) addrs[cnt]) (libstring_argc, libstring_argv, libstring_env);
	  }
    }
    else {
		puts("NO DT_PREINIT_ARRAY");
		pi(preinit_array->d_un.d_ptr)
		pi(preinit_array->d_un.d_val)
	}

	/* Stupid users forced the ELF specification to be changed.  It now
		says that the dynamic loader is responsible for determining the
		order in which the constructors have to run.  The constructors
		for all dependencies of an object must run before the constructor
		for the object itself.  Circular dependencies are left unspecified.

		This is highly questionable since it puts the burden on the dynamic
		loader which has to find the dependencies at runtime instead of
		letting the user do it right.  Stupidity rules!  */
// 
//   i = main_map->l_searchlist.r_nlist;
//   while (i-- > 0)
//     call_init (main_map->l_initfini[i], argc, argv, env);
			call_init_(library_index);
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
        obtain_rela_plt_size(library[library_index].array, library[library_index]._elf_header, library[library_index]._elf_symbol_table);
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
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Name:\t\t %s\n", filename);
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ELF Identifier\t %s (", library[library_index]._elf_header->e_ident);
//             __print_quoted_string__(library[library_index]._elf_header->e_ident, sizeof(library[library_index]._elf_header->e_ident), QUOTE_FORCE_HEX|QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " )\n");

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Architecture\t ");
            switch(library[library_index]._elf_header->e_ident[EI_CLASS])
            {
                case ELFCLASSNONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case ELFCLASS32:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "32-bit\n");
                    break;

                case ELFCLASS64:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "64-bit\n");
                    break;
                    
                case ELFCLASSNUM:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NUM ( unspecified )\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown CLASS\n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Data Type\t ");
            switch(library[library_index]._elf_header->e_ident[EI_DATA])
            {
                case ELFDATANONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case ELFDATA2LSB:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "2's complement, little endian\n");
                    break;

                case ELFDATA2MSB:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "2's complement, big endian\n");
                    break;
                    
                case ELFDATANUM:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NUM ( unspecified )\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Version\t\t ");
            switch(library[library_index]._elf_header->e_ident[EI_VERSION])
            {
                case EV_NONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case EV_CURRENT:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Current\n");
                    break;

                case EV_NUM:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NUM ( Unspecified )\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OS ABI\t\t ");
            switch(library[library_index]._elf_header->e_ident[EI_OSABI])
            {
                case ELFOSABI_NONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNIX System V ABI\n");
                    break;

//                     case ELFOSABI_SYSV:
//                         if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SYSV\n");
//                         break;
// 
                case ELFOSABI_HPUX:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "HP-UX\n");
                    break;

                case ELFOSABI_NETBSD:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NetBSD\n");
                    break;

                case ELFOSABI_GNU:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GNU\n");
                    break;

//                     case ELFOSABI_LINUX:
//                         if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Linux\n");
//                         break;
// 
                case ELFOSABI_SOLARIS:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Sun Solaris\n");
                    break;

                case ELFOSABI_AIX:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ABM AIX\n");
                    break;

                case ELFOSABI_FREEBSD:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FreeBSD\n");
                    break;

                case ELFOSABI_TRU64:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Compaq Tru64\n");
                    break;

                case ELFOSABI_MODESTO:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Novell Modesto\n");
                    break;

                case ELFOSABI_OPENBSD:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OpenBSD\n");
                    break;

//                 case ELFOSABI_ARM_AEABI: // not in musl
//                     if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ARM EABI\n");
//                     break;

//                 case ELFOSABI_ARM: // not in musl
//                     if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ARM\n");
//                     break;

                case ELFOSABI_STANDALONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Standalone (embedded) application\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "File Type\t ");
            switch(library[library_index]._elf_header->e_type)
            {
                case ET_NONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case ET_REL:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Relocatable file\n");
                    break;

                case ET_EXEC:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Executable file\n");
                    break;

                case ET_DYN:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Shared object file\n");
                    break;

                case ET_CORE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Core file\n");
                    break;

                case ET_NUM:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Number of defined types\n");
                    break;

                case ET_LOOS:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OS-specific range start\n");
                    break;

                case ET_HIOS:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OS-specific range end\n");
                    break;

                case ET_LOPROC:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Processor-specific range start\n");
                    break;

                case ET_HIPROC:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Processor-specific range end\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Machine\t\t ");
            switch(library[library_index]._elf_header->e_machine)
            {
                case EM_NONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case EM_386:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "INTEL x86\n");
                        break;

                case EM_X86_64:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "AMD x86-64 architecture\n");
                        break;

                case EM_ARM:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ARM\n");
                        break;
                default:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown\n");
                break;
            }
            
            /* Entry point */
            int entry=library[library_index]._elf_header->e_entry;
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Entry point\t %014p\n", library[library_index]._elf_header->e_entry);
            

            /* ELF header size in bytes */
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ELF header size\t %014p\n", library[library_index]._elf_header->e_ehsize);

            /* Program Header */
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Program Header\t %014p (%d entries with a total of %d bytes)\n",
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
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "p_type:\t\t\t/* Segment type */\t\t= ");
                switch(library[library_index]._elf_program_header[i].p_type)
                {
                    case PT_NULL:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_NULL\t\t/* Program header table entry unused */\n");
                        section_="PT_NULL";
                        break;
                    case PT_LOAD:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOAD\t\t/* Loadable program segment */\n");
                        section_="PT_LOAD";
                        load_addr = (const char *)library[library_index]._elf_program_header->p_vaddr;
                        load_offset = library[library_index]._elf_program_header->p_offset;
                        break;
                    case PT_DYNAMIC:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_DYNAMIC\t\t/* Dynamic linking information */\n");
                        section_="PT_DYNAMIC";
                        library[library_index].PT_DYNAMIC_=i;
                        break;
                    case PT_INTERP:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_INTERP\t\t/* Program interpreter */\n");
                        section_="PT_INTERP";
                        break;
                    case PT_NOTE:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_NOTE\t\t/* Auxiliary information */\n");
                        section_="PT_NOTE";
                        break;
                    case PT_SHLIB:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_SHLIB\t\t/* Reserved */\n");
                        section_="PT_SHLIB";
                        break;
                    case PT_PHDR:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_PHDR\t\t/* Entry for header table itself */\n");
                        section_="PT_PHDR";
                        break;
                    case PT_TLS:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_TLS\t\t/* Thread-local storage segment */\n");
                        section_="PT_TLS";
                        break;
                    case PT_NUM:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_NUM\t\t/* Number of defined types */\n");
                        section_="PT_NUM";
                        break;
                    case PT_LOOS:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOOS\t\t/* Start of OS-specific */\n");
                        section_="PT_LOOS";
                        break;
                    case PT_GNU_EH_FRAME:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_GNU_EH_FRAME\t/* GCC .eh_frame_hdr segment */\n");
                        section_="PT_GNU_EH_FRAME";
                        break;
                    case PT_GNU_STACK:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_GNU_STACK\t\t/* Indicates stack executability */\n");
                        section_="PT_GNU_STACK";
                        break;
                    case PT_GNU_RELRO:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_GNU_RELRO\t\t/* Read-only after relocation */\n");
                        section_="PT_GNU_RELRO";
                        break;
                    case PT_SUNWBSS:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_SUNWBSS\t\t/* Sun Specific segment */\n");
                        section_="PT_SUNWBSS";
                        break;
                    case PT_SUNWSTACK:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_SUNWSTACK\t\t/* Stack segment */\n");
                        section_="PT_SUNWSTACK";
                        break;
                    case PT_HIOS:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_HIOS\t\t/* End of OS-specific */\n");
                        section_="PT_HIOS";
                        break;
                    case PT_LOPROC:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOPROC\t\t/* Start of processor-specific */\n");
                        section_="PT_LOPROC";
                        break;
                    case PT_HIPROC:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_HIPROC\t\t/* End of processor-specific */\n");
                        section_="PT_HIPROC";
                        break;
                    default:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown\n");
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
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ATTEMPTING TO READ\n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "reading                %014p\n", (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                read_fast_verify(library[library_index].array, library[library_index].len, &tmp99, (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "correcting position by %014p\n", library[library_index]._elf_program_header[i].p_offset);
                __lseek_string__(&tmp99, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "reading                %d\n", library[library_index]._elf_program_header[i].p_memsz);
                __print_quoted_string__(tmp99, library[library_index]._elf_program_header[i].p_memsz, 0, "print");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\nREAD\n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[i].p_flags, library[library_index]._elf_program_header[i].p_offset, library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mapping_start, library[library_index]._elf_program_header[i].p_paddr, library[library_index]._elf_program_header[i].p_filesz, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_align);
                if (bytecmpq(global_quiet, "no") == 0) nl();
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_flags: %014p", library[library_index]._elf_program_header[i].p_flags);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_offset: %014p", library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_vaddr:  %014p", library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mapping_start);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_paddr: %014p", library[library_index]._elf_program_header[i].p_paddr);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_filesz: %014p", library[library_index]._elf_program_header[i].p_filesz);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_memsz: %014p", library[library_index]._elf_program_header[i].p_memsz);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_align: %014p\n", library[library_index]._elf_program_header[i].p_align);
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

                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOAD 1 = \n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_flags, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_offset, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_vaddr+library[library_index].mapping_start, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_paddr, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_filesz, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_memsz, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_align);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOAD 2 = \n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_flags, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_offset, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr+library[library_index].mapping_start, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_paddr, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_filesz, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_memsz, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_align);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "first PT_LOAD library[library_index]._elf_program_header[%d]->p_paddr = \n%014p\n", library[library_index].First_Load_Header_index, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_paddr+library[library_index].mapping_start);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Second PT_LOAD library[library_index]._elf_program_header[%d]->p_paddr = \n%014p\n", library[library_index].Last_Load_Header_index, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_paddr+library[library_index].mapping_start);
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

                library[library_index].GOT2 = library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_PLTGOT)->d_un.d_val;
//                 library[library_index].PLT = library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_PLTREL)->d_un.d_val;

//                 if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "printing symbol data\n");
//                 Elf64_Sym *syms = library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_SYMTAB)->d_un.d_val;
//                 symbol1(library[library_index].array, syms, 0);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "examining current entries:\n");
                get_dynamic_entry(library[library_index].dynamic, -1);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "printing relocation data\n");
                // needs to be the address of the mapping itself, not the base address
                r_init();
                r(library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_RELA)->d_un.d_val, get_dynamic_entry(library[library_index].dynamic, DT_RELASZ)->d_un.d_val, relocation_quiet);
                r(library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_JMPREL)->d_un.d_val, library[library_index].RELA_PLT_SIZE, relocation_quiet);
                r(library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_BIND_NOW)->d_un.d_val, library[library_index].RELA_PLT_SIZE, relocation_quiet);
//                 r(library[library_index].mapping_start + get_dynamic_entry(library[library_index].dynamic, DT_PLTREL)->d_un.d_val, get_dynamic_entry(library[library_index].dynamic, DT_PLTRELSZ)->d_un.d_val, relocation_quiet);
                r_summary();
            }
//             if (bytecmpq(global_quiet, "no") == 0) nl();
            
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Section Header\t \
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
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ELFMAGIC not found\n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "header = ");
//                 __print_quoted_string__(library[library_index].array, sizeof(library[library_index]._elf_header->e_ident), QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ELF Identifier\t %s (", library[library_index]._elf_header->e_ident);
//                 __print_quoted_string__(library[library_index]._elf_header->e_ident, sizeof(library[library_index]._elf_header->e_ident), QUOTE_FORCE_HEX|QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " )\n");
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
    if (library[library_index].init_lock == 1) {
        if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "dlopen: LOCKED\n");
        return "-1";
    };
    if ( if_valid(cc) == -1) {
        fprintf(stderr, "\"%s\" not found\n", cc);
        errno = 0;
        return "-1";
    }
    init_(cc);
//     library_index++;
    library[library_index].library_name = cc;
    library[library_index].library_first_character = library[library_index].library_name[0];
    library[library_index].library_len = strlen(library[library_index].library_name);
    fprintf(stderr, "dlopen: adding %s to index %d\n", cc, library_index);
    return cc;
}

void *
dlopen(const char * cc) {
    get_needed(cc);
    return dlopen_(cc);
}

void *
dlsym(const char * cc1, const char * cc2)
{
    if (library[library_index].init_lock == 1) {
        if (bytecmpq(ldd_quiet, "no") == 0) fprintf(stderr, "dlsym: LOCKED\n");
        return "-1";
    };
    /*

    printf resolution:
    
    initialization:
    in during relocation JMP_SLOT relocations are preformed, which write directly to the GOT, in this case "printf" is translated directly to "puts" at compile time
    ->
    R_X86_64_JUMP_SLOT           calculation: S (symbol value)
    library[library_index].mapping_start    = 0x7ffff0000000
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
    
    if (bytecmpq(cc1,"-1") == 0) return "-1";
    library_index = search(cc1);

    library[library_index].library_symbol = cc2;

    fprintf(stderr, "dlsym: adding %s from %s\n", library[library_index].library_symbol, library[library_index].library_name);

    library[library_index].GOT = lookup_symbol_by_name_(cc1, "_GLOBAL_OFFSET_TABLE_");
    if (library[library_index].GOT != NULL) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n\naddress of GOT   = %014p\n", library[library_index].GOT);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[1] = %014p\n", library[library_index].GOT[1]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[2] = %014p\n", library[library_index].GOT[2]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[3] = %014p\n", library[library_index].GOT[3]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[4] = %014p\n", library[library_index].GOT[4]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[5] = %014p\n", library[library_index].GOT[5]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[6] = %014p\n", library[library_index].GOT[6]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[7] = %014p\n", library[library_index].GOT[7]);
    }
    else if (library[library_index].GOT2 != NULL) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n\naddress of GOT   = %014p\n", library[library_index].GOT2);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[1] = %014p\n", library[library_index].GOT2[1]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[2] = %014p\n", library[library_index].GOT2[2]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[3] = %014p\n", library[library_index].GOT2[3]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[4] = %014p\n", library[library_index].GOT2[4]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[5] = %014p\n", library[library_index].GOT2[5]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[6] = %014p\n", library[library_index].GOT2[6]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of GOT[7] = %014p\n", library[library_index].GOT2[7]);
    }
    if (library[library_index].PLT != NULL) {
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n\naddress of PLT   = %014p\n", library[library_index].PLT);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of PLT[1] = %014p\n", library[library_index].PLT[1]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of PLT[2] = %014p\n", library[library_index].PLT[2]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of PLT[3] = %014p\n", library[library_index].PLT[3]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of PLT[4] = %014p\n", library[library_index].PLT[4]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of PLT[5] = %014p\n", library[library_index].PLT[5]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of PLT[6] = %014p\n", library[library_index].PLT[6]);
        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "address of PLT[7] = %014p\n", library[library_index].PLT[7]);
    }
    return lookup_symbol_by_name_(cc1, cc2);
}

int
readelf_(const char * filename) {
	is_readelf = true;
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
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Name:\t\t %s\n", filename);
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ELF Identifier\t %s (", library[library_index]._elf_header->e_ident);
//             __print_quoted_string__(library[library_index]._elf_header->e_ident, sizeof(library[library_index]._elf_header->e_ident), QUOTE_FORCE_HEX|QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " )\n");

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Architecture\t ");
            switch(library[library_index]._elf_header->e_ident[EI_CLASS])
            {
                case ELFCLASSNONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case ELFCLASS32:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "32-bit\n");
                    break;

                case ELFCLASS64:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "64-bit\n");
                    break;
                    
                case ELFCLASSNUM:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NUM ( unspecified )\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown CLASS\n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Data Type\t ");
            switch(library[library_index]._elf_header->e_ident[EI_DATA])
            {
                case ELFDATANONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case ELFDATA2LSB:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "2's complement, little endian\n");
                    break;

                case ELFDATA2MSB:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "2's complement, big endian\n");
                    break;
                    
                case ELFDATANUM:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NUM ( unspecified )\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Version\t\t ");
            switch(library[library_index]._elf_header->e_ident[EI_VERSION])
            {
                case EV_NONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case EV_CURRENT:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Current\n");
                    break;

                case EV_NUM:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NUM ( Unspecified )\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OS ABI\t\t ");
            switch(library[library_index]._elf_header->e_ident[EI_OSABI])
            {
                case ELFOSABI_NONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "UNIX System V ABI\n");
                    break;

//                     case ELFOSABI_SYSV:
//                         if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "SYSV\n");
//                         break;
// 
                case ELFOSABI_HPUX:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "HP-UX\n");
                    break;

                case ELFOSABI_NETBSD:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "NetBSD\n");
                    break;

                case ELFOSABI_GNU:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "GNU\n");
                    break;

//                     case ELFOSABI_LINUX:
//                         if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Linux\n");
//                         break;
// 
                case ELFOSABI_SOLARIS:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Sun Solaris\n");
                    break;

                case ELFOSABI_AIX:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ABM AIX\n");
                    break;

                case ELFOSABI_FREEBSD:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "FreeBSD\n");
                    break;

                case ELFOSABI_TRU64:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Compaq Tru64\n");
                    break;

                case ELFOSABI_MODESTO:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Novell Modesto\n");
                    break;

                case ELFOSABI_OPENBSD:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OpenBSD\n");
                    break;

//                 case ELFOSABI_ARM_AEABI:
//                     if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ARM EABI\n");
//                     break;

//                 case ELFOSABI_ARM:
//                     if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ARM\n");
//                     break;

                case ELFOSABI_STANDALONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Standalone (embedded) application\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "File Type\t ");
            switch(library[library_index]._elf_header->e_type)
            {
                case ET_NONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case ET_REL:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Relocatable file\n");
                    break;

                case ET_EXEC:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Executable file\n");
                    break;

                case ET_DYN:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Shared object file\n");
                    break;

                case ET_CORE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Core file\n");
                    break;

                case ET_NUM:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Number of defined types\n");
                    break;

                case ET_LOOS:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OS-specific range start\n");
                    break;

                case ET_HIOS:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "OS-specific range end\n");
                    break;

                case ET_LOPROC:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Processor-specific range start\n");
                    break;

                case ET_HIPROC:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Processor-specific range end\n");
                    break;

                default:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown \n");
                    break;
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Machine\t\t ");
            switch(library[library_index]._elf_header->e_machine)
            {
                case EM_NONE:
                    if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "None\n");
                    break;

                case EM_386:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "INTEL x86\n");
                        break;

                case EM_X86_64:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "AMD x86-64 architecture\n");
                        break;

                case EM_ARM:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ARM\n");
                        break;
                default:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown\n");
                break;
            }
            
            /* Entry point */
            int entry=library[library_index]._elf_header->e_entry;
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Entry point\t %014p\n", library[library_index]._elf_header->e_entry);
            

            /* ELF header size in bytes */
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ELF header size\t %014p\n", library[library_index]._elf_header->e_ehsize);

            /* Program Header */
            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Program Header\t %014p (%d entries with a total of %d bytes)\n",
            library[library_index]._elf_header->e_phoff,
            library[library_index]._elf_header->e_phnum,
            library[library_index]._elf_header->e_phentsize
            );
// continue analysis
            for (int i = 0; i < library[library_index]._elf_header->e_phnum; ++i) {
                char * section_;
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "p_type:\t\t\t/* Segment type */\t\t= ");
                switch(library[library_index]._elf_program_header[i].p_type)
                {
                    case PT_NULL:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_NULL\t\t/* Program header table entry unused */\n");
                        section_="PT_NULL";
                        break;
                    case PT_LOAD:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOAD\t\t/* Loadable program segment */\n");
                        section_="PT_LOAD";
                        break;
                    case PT_DYNAMIC:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_DYNAMIC\t\t/* Dynamic linking information */\n");
                        section_="PT_DYNAMIC";
                        library[library_index].PT_DYNAMIC_=i;
                        break;
                    case PT_INTERP:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_INTERP\t\t/* Program interpreter */\n");
                        section_="PT_INTERP";
                        break;
                    case PT_NOTE:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_NOTE\t\t/* Auxiliary information */\n");
                        section_="PT_NOTE";
                        break;
                    case PT_SHLIB:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_SHLIB\t\t/* Reserved */\n");
                        section_="PT_SHLIB";
                        break;
                    case PT_PHDR:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_PHDR\t\t/* Entry for header table itself */\n");
                        section_="PT_PHDR";
                        break;
                    case PT_TLS:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_TLS\t\t/* Thread-local storage segment */\n");
                        section_="PT_TLS";
                        break;
                    case PT_NUM:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_NUM\t\t/* Number of defined types */\n");
                        section_="PT_NUM";
                        break;
                    case PT_LOOS:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOOS\t\t/* Start of OS-specific */\n");
                        section_="PT_LOOS";
                        break;
                    case PT_GNU_EH_FRAME:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_GNU_EH_FRAME\t/* GCC .eh_frame_hdr segment */\n");
                        section_="PT_GNU_EH_FRAME";
                        break;
                    case PT_GNU_STACK:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_GNU_STACK\t\t/* Indicates stack executability */\n");
                        section_="PT_GNU_STACK";
                        break;
                    case PT_GNU_RELRO:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_GNU_RELRO\t\t/* Read-only after relocation */\n");
                        section_="PT_GNU_RELRO";
                        break;
                    case PT_SUNWBSS:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_SUNWBSS\t\t/* Sun Specific segment */\n");
                        section_="PT_SUNWBSS";
                        break;
                    case PT_SUNWSTACK:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_SUNWSTACK\t\t/* Stack segment */\n");
                        section_="PT_SUNWSTACK";
                        break;
                    case PT_HIOS:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_HIOS\t\t/* End of OS-specific */\n");
                        section_="PT_HIOS";
                        break;
                    case PT_LOPROC:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOPROC\t\t/* Start of processor-specific */\n");
                        section_="PT_LOPROC";
                        break;
                    case PT_HIPROC:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_HIPROC\t\t/* End of processor-specific */\n");
                        section_="PT_HIPROC";
                        break;
                    default:
                        if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Unknown\n");
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
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ATTEMPTING TO READ\n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "reading                %014p\n", (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                read_fast_verify(library[library_index].array, library[library_index].len, &tmp99, (library[library_index]._elf_program_header[i].p_memsz + library[library_index]._elf_program_header[i].p_offset));
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "correcting position by %014p\n", library[library_index]._elf_program_header[i].p_offset);
                __lseek_string__(&tmp99, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "reading                %d\n", library[library_index]._elf_program_header[i].p_memsz);
//                 __print_quoted_string__(tmp99, library[library_index]._elf_program_header[i].p_memsz, 0, "print");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\nREAD\n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[i].p_flags, library[library_index]._elf_program_header[i].p_offset, library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mapping_start, library[library_index]._elf_program_header[i].p_paddr, library[library_index]._elf_program_header[i].p_filesz, library[library_index]._elf_program_header[i].p_memsz, library[library_index]._elf_program_header[i].p_align);
                if (bytecmpq(global_quiet, "no") == 0) nl();
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\t\tp_flags: %014p", library[library_index]._elf_program_header[i].p_flags);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_offset: %014p", library[library_index]._elf_program_header[i].p_offset);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_vaddr:  %014p", library[library_index]._elf_program_header[i].p_vaddr+library[library_index].mapping_start);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_paddr: %014p", library[library_index]._elf_program_header[i].p_paddr);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_filesz: %014p", library[library_index]._elf_program_header[i].p_filesz);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_memsz: %014p", library[library_index]._elf_program_header[i].p_memsz);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " p_align: %014p\n", library[library_index]._elf_program_header[i].p_align);
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

                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOAD 1 = \n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_flags, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_offset, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_vaddr+library[library_index].mapping_start, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_paddr, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_filesz, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_memsz, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_align);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "PT_LOAD 2 = \n");
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "p_flags:\t\t/* Segment flags */\t\t= %014p\np_offset:\t\t/* Segment file offset */\t= %014p\np_vaddr:\t\t/* Segment virtual address */\t= %014p\np_paddr:\t\t/* Segment physical address */\t= %014p\np_filesz:\t\t/* Segment size in file */\t= %014p\np_memsz:\t\t/* Segment size in memory */\t= %014p\np_align:\t\t/* Segment alignment */\t\t= %014p\n\n\n", library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_flags, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_offset, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_vaddr+library[library_index].mapping_start, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_paddr, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_filesz, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_memsz, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_align);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "first PT_LOAD library[library_index]._elf_program_header[%d]->p_paddr = \n%014p\n", library[library_index].First_Load_Header_index, library[library_index]._elf_program_header[library[library_index].First_Load_Header_index].p_paddr+library[library_index].mapping_start);
                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Second PT_LOAD library[library_index]._elf_program_header[%d]->p_paddr = \n%014p\n", library[library_index].Last_Load_Header_index, library[library_index]._elf_program_header[library[library_index].Last_Load_Header_index].p_paddr+library[library_index].mapping_start);
                Elf64_Dyn * dynamic = library[library_index].tmp99D;

                if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "examining current entries:\n");
                get_dynamic_entry(library[library_index].dynamic, -1);
            }

            if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "Section Header\t \
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
			if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ELFMAGIC not found\n");
			if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "header = ");
// 			__print_quoted_string__(library[library_index].array, sizeof(library[library_index]._elf_header->e_ident), QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
			if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "\n");
			if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, "ELF Identifier\t %s (", library[library_index]._elf_header->e_ident);
// 			__print_quoted_string__(library[library_index]._elf_header->e_ident, sizeof(library[library_index]._elf_header->e_ident), QUOTE_FORCE_HEX|QUOTE_OMIT_LEADING_TRAILING_QUOTES, "print");
			if (bytecmpq(global_quiet, "no") == 0) fprintf(stderr, " )\n");
			is_readelf = false;
            return 0;
        }
	is_readelf = false;
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
//                         if i wanted a string to be if (bytecmpq(global_quiet, "no") == 0) printf safe what characters would i need to replace or modify, for example "hi"ko-pl" would need to be "hi\"ko"'-'"pl"
//                         \x27 is '
//                     xargs -0 if (bytecmpq(global_quiet, "no") == 0) printf '%s'<<EOF
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
