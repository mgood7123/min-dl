#include <stdio.h>

extern "C" void hello() {
    printf("hello!\n");
    /*
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
    ->
    in gdb, calls:
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
}
