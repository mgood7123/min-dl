#include <assert.h>
#include <stdio.h>
// #include <dlfcn.h>
// #include <string.h>
// #include <elf.h>
// #include <link.h>
// #include <unistd.h>
// #include <locale.h>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <fcntl.h>
// #include <sys/mman.h>
// #include <stdlib.h>
// void * getaux(void * type);
// char ** argv;

// unfortunately this is nessicary
void * lookup_symbol_by_name_(const char * lib, const char * name);
int readelf_(const char * filename);

int main() {
//     readelf_("/lib/libc.so.6");

    const char * (*func_char)();
    const int (*func_int)();

//     printf("Test exported functions >\n");
// 
//     func_char = lookup_symbol_by_name_("./files/test_lib.so", "foo");
//     printf("func = %s\n", func_char());
//     
//     func_int = lookup_symbol_by_name_("./files/test_lib.so", "bar_int");
//     printf("func_int = %d\n", func_int());
// 
//     func_char = lookup_symbol_by_name_("./files/test_lib.so", "bar");
//     printf("func_char = %s\n", func_char());
// 
//     func_char = lookup_symbol_by_name_("./files/test_lib.so", "bar2");
//     printf("func_char = %s\n", func_char());
// 
//     printf("OK!\n");
// 
// 
// 
//     printf("Test nested functions >\n");
// 
// //     func_int = lookup_symbol_by_name_("./files/test_lib.so", "test_nested.2245");
//     func_int = lookup_symbol_by_name_("./files/test_lib.so", "test_nested.2283");
//     printf("test_nested = %d\n", func_int());
// 
//     func_int = lookup_symbol_by_name_("./files/test_lib.so", "test");
//     printf("test = %d\n", func_int());
// 
// 
//     printf("OK!\n");
// 
//     printf("Test functions that call external libc functions >\n");
// 
//     func_int = lookup_symbol_by_name_("./files/test_lib.so", "test_strlen");
//     printf("func_int = %d\n", func_int());
// 
//     printf("OK!\n");
// 
//     
//     printf("Test musl libc functions >\n");
// 
//     int (*func_int_write_musl)();
//     func_int_write_musl = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "write");
//     func_int_write_musl(1, "write\n", 7);
// 
//     int (*func_int_strlen_musl)();
//     func_int_strlen_musl = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "strlen");
//     printf("func_int_strlen_musl(\"test string\\n\") = %d\n", func_int_strlen_musl("test string\n"));
// 
//     int (*func_int_puts_musl)();
//     func_int_puts_musl = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "puts");
//     func_int_puts_musl("func_int_strlen_gnu(\"test string\\n\")\n");
// 
//     int (*func_int_printf_musl)();
//     func_int_printf_musl = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "printf");
//     func_int_printf_musl("func_int_strlen_musl(\"test string\\n\")\n");
// 
//     printf("OK!\n");
// 
//     printf("Test dlopen/dlsym >\n");
//     
// 
//     printf("dlopen\n");
//     int in = dlopen("l");
//     printf("dlsym\n");
//     dlsym(in, "k");
// 
//     printf("OK!\n");
// 
//     
// //     printf("Test gnu libc functions >\n");
// //     
// //     int (*func_int_write_gnu)();
// //     func_int_write_gnu = lookup_symbol_by_name_("/lib/libc.so.6", "write");
// //     func_int_write_gnu(1, "write\n", 7);
// // 
// //     int (*func_int_strlen_gnu)();
// //     func_int_strlen_gnu = lookup_symbol_by_name_("/lib/libc.so.6", "strlen");
// //     printf("func_int_strlen_gnu(\"test string\\n\") = %d\n", func_int_strlen_gnu("test string\n"));
// // 
// //     int (*func_int_puts_gnu)();
// //     func_int_puts_gnu = lookup_symbol_by_name_("/lib/libc.so.6", "puts");
// //     func_int_puts_gnu("func_int_strlen_gnu(\"test string\\n\")\n");
// // 
// //     int (*func_int_printf_gnu)();
// //     func_int_printf_gnu = lookup_symbol_by_name_("/lib/libc.so.6", "printf");
// //     func_int_printf_gnu("func_int_strlen_gnu(\"test string\\n\")\n");
// // 
// //     printf("OK!\n");

    
// multi test
    
    printf("Test exported functions >\n");

    func_char = lookup_symbol_by_name_("./files/test_lib.so", "foo");
    printf("func = %s\n", func_char());
    
    printf("OK!\n");

    
    printf("Test musl libc functions >\n");

    int (*func_int_write_musl)();
    func_int_write_musl = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "write");
    func_int_write_musl(1, "write\n", 7);

    printf("OK!\n");


    printf("Test functions that call external libc functions >\n");

    func_int = lookup_symbol_by_name_("./files/test_lib.so", "test_strlen");
    printf("func_int = %d\n", func_int());

    printf("OK!\n");


    printf("Test gnu libc functions >\n");

    int (*func_int_strlen_gnu)();
    func_int_strlen_gnu = lookup_symbol_by_name_("/lib/libc.so.6", "strlen");
    printf("func_int_strlen_gnu(\"test string\\n\") = %d\n", func_int_strlen_gnu("test string\n"));

    printf("OK!\n");


    func_int = lookup_symbol_by_name_("./files/test_lib.so", "bar_int");
    printf("func_int = %d\n", func_int());

    func_char = lookup_symbol_by_name_("./files/test_lib.so", "bar");
    printf("func_char = %s\n", func_char());

    func_char = lookup_symbol_by_name_("./files/test_lib.so", "bar2");
    printf("func_char = %s\n", func_char());

    printf("OK!\n");



    printf("Test nested functions >\n");


    func_int = lookup_symbol_by_name_("./files/test_lib.so", "test");
    printf("test = %d\n", func_int());


    printf("OK!\n");


    
    printf("Test musl libc functions >\n");

    int (*func_int_puts_musl)();
    func_int_puts_musl = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "puts");
    func_int_puts_musl("func_int_strlen_gnu(\"test string\\n\")\n");

    int (*func_int_printf_musl)();
    func_int_printf_musl = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "printf");
    func_int_printf_musl("func_int_strlen_musl(\"test string\\n\")\n");

    printf("OK!\n");

    printf("Test dlopen/dlsym >\n");
    

    printf("dlopen\n");
    int in = dlopen("l");
    printf("dlsym\n");
    dlsym(in, "k");

    printf("OK!\n");

    
    printf("Test gnu and musl libc functions >\n");
    
    int (*func_int_write_gnu)();
    func_int_write_gnu = lookup_symbol_by_name_("/lib/libc.so.6", "write");
    func_int_write_gnu(1, "write\n", 7);

    int (*func_int_write_musl_)();
    func_int_write_musl_ = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "write");
    func_int_write_musl_(1, "write\n", 7);

    int (*func_int_strlen_gnu_)();
    func_int_strlen_gnu_ = lookup_symbol_by_name_("/lib/libc.so.6", "strlen");
    printf("func_int_strlen_gnu(\"test string\\n\") = %d\n", func_int_strlen_gnu_("test string\n"));

    int (*func_int_strlen_musl)();
    func_int_strlen_musl = lookup_symbol_by_name_("/lib/ld-musl-x86_64.so.1", "strlen");
    printf("func_int_strlen_musl(\"test string\\n\") = %d\n", func_int_strlen_musl("test string\n"));

    printf("OK!\n");


    printf("Test nested functions >\n");

    func_int = lookup_symbol_by_name_("./files/test_lib.so", "test_nested.2283");
    printf("test_nested = %d\n", func_int());

    printf("OK!\n");


    return 0;
}
