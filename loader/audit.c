// [exec@exec-pc loader]$ gcc audit.c
// audit.c: In function ‘la_objsearch’:
// audit.c:212:29: error: ‘LA_SER_ORIG’ undeclared (first use in this function)
//                     (flag == LA_SER_ORIG) ?    "LA_SER_ORIG" :
//                              ^~~~~~~~~~~
// audit.c:212:29: note: each undeclared identifier is reported only once for each function it appears in
// audit.c:213:29: error: ‘LA_SER_LIBPATH’ undeclared (first use in this function); did you mean ‘LA_SER_ORIG’?
//                     (flag == LA_SER_LIBPATH) ? "LA_SER_LIBPATH" :
//                              ^~~~~~~~~~~~~~
//                              LA_SER_ORIG
// audit.c:214:29: error: ‘LA_SER_RUNPATH’ undeclared (first use in this function); did you mean ‘LA_SER_LIBPATH’?
//                     (flag == LA_SER_RUNPATH) ? "LA_SER_RUNPATH" :
//                              ^~~~~~~~~~~~~~
//                              LA_SER_LIBPATH
// audit.c:215:29: error: ‘LA_SER_DEFAULT’ undeclared (first use in this function); did you mean ‘STV_DEFAULT’?
//                     (flag == LA_SER_DEFAULT) ? "LA_SER_DEFAULT" :
//                              ^~~~~~~~~~~~~~
//                              STV_DEFAULT
// audit.c:216:29: error: ‘LA_SER_CONFIG’ undeclared (first use in this function); did you mean ‘LA_SER_ORIG’?
//                     (flag == LA_SER_CONFIG) ?  "LA_SER_CONFIG" :
//                              ^~~~~~~~~~~~~
//                              LA_SER_ORIG
// audit.c:217:29: error: ‘LA_SER_SECURE’ undeclared (first use in this function); did you mean ‘LA_SER_DEFAULT’?
//                     (flag == LA_SER_SECURE) ?  "LA_SER_SECURE" :
//                              ^~~~~~~~~~~~~
//                              LA_SER_DEFAULT
// audit.c:220:19: warning: return discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
//             return name;
//                    ^~~~
// audit.c: In function ‘la_activity’:
// audit.c:227:29: error: ‘LA_ACT_CONSISTENT’ undeclared (first use in this function); did you mean ‘RT_CONSISTENT’?
//                     (flag == LA_ACT_CONSISTENT) ? "LA_ACT_CONSISTENT" :
//                              ^~~~~~~~~~~~~~~~~
//                              RT_CONSISTENT
// audit.c:228:29: error: ‘LA_ACT_ADD’ undeclared (first use in this function); did you mean ‘RT_ADD’?
//                     (flag == LA_ACT_ADD) ?        "LA_ACT_ADD" :
//                              ^~~~~~~~~~
//                              RT_ADD
// audit.c:229:29: error: ‘LA_ACT_DELETE’ undeclared (first use in this function); did you mean ‘RT_DELETE’?
//                     (flag == LA_ACT_DELETE) ?     "LA_ACT_DELETE" :
//                              ^~~~~~~~~~~~~
//                              RT_DELETE
// audit.c: At top level:
// audit.c:234:41: error: unknown type name ‘Lmid_t’; did you mean ‘id_t’?
//         la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
//                                          ^~~~~~
//                                          id_t
// audit.c:286:56: error: unknown type name ‘La_i86_regs’; did you mean ‘La_x32_regs’?
//                 uintptr_t *refcook, uintptr_t *defcook, La_i86_regs *regs,
//                                                         ^~~~~~~~~~~
//                                                         La_x32_regs
// [exec@exec-pc loader]$ gcc audit.c -m32
// audit.c: In function ‘la_objsearch’:
// audit.c:212:29: error: ‘LA_SER_ORIG’ undeclared (first use in this function)
//                     (flag == LA_SER_ORIG) ?    "LA_SER_ORIG" :
//                              ^~~~~~~~~~~
// audit.c:212:29: note: each undeclared identifier is reported only once for each function it appears in
// audit.c:213:29: error: ‘LA_SER_LIBPATH’ undeclared (first use in this function); did you mean ‘LA_SER_ORIG’?
//                     (flag == LA_SER_LIBPATH) ? "LA_SER_LIBPATH" :
//                              ^~~~~~~~~~~~~~
//                              LA_SER_ORIG
// audit.c:214:29: error: ‘LA_SER_RUNPATH’ undeclared (first use in this function); did you mean ‘LA_SER_LIBPATH’?
//                     (flag == LA_SER_RUNPATH) ? "LA_SER_RUNPATH" :
//                              ^~~~~~~~~~~~~~
//                              LA_SER_LIBPATH
// audit.c:215:29: error: ‘LA_SER_DEFAULT’ undeclared (first use in this function); did you mean ‘STV_DEFAULT’?
//                     (flag == LA_SER_DEFAULT) ? "LA_SER_DEFAULT" :
//                              ^~~~~~~~~~~~~~
//                              STV_DEFAULT
// audit.c:216:29: error: ‘LA_SER_CONFIG’ undeclared (first use in this function); did you mean ‘LA_SER_ORIG’?
//                     (flag == LA_SER_CONFIG) ?  "LA_SER_CONFIG" :
//                              ^~~~~~~~~~~~~
//                              LA_SER_ORIG
// audit.c:217:29: error: ‘LA_SER_SECURE’ undeclared (first use in this function); did you mean ‘LA_SER_DEFAULT’?
//                     (flag == LA_SER_SECURE) ?  "LA_SER_SECURE" :
//                              ^~~~~~~~~~~~~
//                              LA_SER_DEFAULT
// audit.c:220:19: warning: return discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
//             return name;
//                    ^~~~
// audit.c: In function ‘la_activity’:
// audit.c:227:29: error: ‘LA_ACT_CONSISTENT’ undeclared (first use in this function); did you mean ‘RT_CONSISTENT’?
//                     (flag == LA_ACT_CONSISTENT) ? "LA_ACT_CONSISTENT" :
//                              ^~~~~~~~~~~~~~~~~
//                              RT_CONSISTENT
// audit.c:228:29: error: ‘LA_ACT_ADD’ undeclared (first use in this function); did you mean ‘RT_ADD’?
//                     (flag == LA_ACT_ADD) ?        "LA_ACT_ADD" :
//                              ^~~~~~~~~~
//                              RT_ADD
// audit.c:229:29: error: ‘LA_ACT_DELETE’ undeclared (first use in this function); did you mean ‘RT_DELETE’?
//                     (flag == LA_ACT_DELETE) ?     "LA_ACT_DELETE" :
//                              ^~~~~~~~~~~~~
//                              RT_DELETE
// audit.c: At top level:
// audit.c:234:41: error: unknown type name ‘Lmid_t’; did you mean ‘id_t’?
//         la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
//                                          ^~~~~~
//                                          id_t
// [exec@exec-pc loader]$ cat ./audit.c 
// RTLD-AUDIT(7)                                                                                               Linux Programmer's Manual                                                                                               RTLD-AUDIT(7)
// 
// NAME
//        rtld-audit - auditing API for the dynamic linker
// 
// SYNOPSIS
//        #define _GNU_SOURCE             /* See feature_test_macros(7) */
// 
//        #include <link.h>
// 
// DESCRIPTION
//        The  GNU  dynamic  linker (run-time linker) provides an auditing API that allows an application to be notified when various dynamic linking events occur.  This API is very similar to the auditing interface provided by the Solaris run-
//        time linker.  The necessary constants and prototypes are defined by including <link.h>.
// 
//        To use this interface, the programmer creates a shared library that implements a standard set of function names.  Not all of the functions need to be implemented: in most cases, if the programmer is  not  interested  in  a  particular
//        class of auditing event, then no implementation needs to be provided for the corresponding auditing function.
// 
//        To  employ  the auditing interface, the environment variable LD_AUDIT must be defined to contain a colon-separated list of shared libraries, each of which can implement (parts of) the auditing API.  When an auditable event occurs, the
//        corresponding function is invoked in each library, in the order that the libraries are listed.
// 
//    la_version()
// 
//        unsigned int la_version(unsigned int version);
// 
//        This is the only function that must be defined by an auditing library: it performs the initial handshake between the dynamic linker and the auditing library.  When invoking this function, the dynamic linker  passes,  in  version,  the
//        highest version of the auditing interface that the linker supports.  If necessary, the auditing library can check that this version is sufficient for its requirements.
// 
//        As its function result, this function should return the version of the auditing interface that this auditing library expects to use (returning version is acceptable).  If the returned value is 0, or a version that is greater than that
//        supported by the dynamic linker, then the audit library is ignored.
// 
//    la_objsearch()
// 
//        char *la_objsearch(const char *name, uintptr_t *cookie,
//                           unsigned int flag);
// 
//        The dynamic linker invokes this function to inform the auditing library that it is about to search for a shared object.  The name argument is the filename or pathname that is to be searched for.  cookie identifies  the  shared  object
//        that initiated the search.  flag is set to one of the following values:
// 
//        LA_SER_ORIG      This is the original name that is being searched for.  Typically, this name comes from an ELF DT_NEEDED entry, or is the filename argument given to dlopen(3).
// 
//        LA_SER_LIBPATH   name was created using a directory specified in LD_LIBRARY_PATH.
// 
//        LA_SER_RUNPATH   name was created using a directory specified in an ELF DT_RPATH or DT_RUNPATH list.
// 
//        LA_SER_CONFIG    name was found via the ldconfig(8) cache (/etc/ld.so.cache).
// 
//        LA_SER_DEFAULT   name was found via a search of one of the default directories.
// 
//        LA_SER_SECURE    name is specific to a secure object (unused on Linux).
// 
//        As  its  function result, la_objsearch() returns the pathname that the dynamic linker should use for further processing.  If NULL is returned, then this pathname is ignored for further processing.  If this audit library simply intends
//        to monitor search paths, then name should be returned.
// 
//    la_activity()
// 
//        void la_activity( uintptr_t *cookie, unsigned int flag);
// 
//        The dynamic linker calls this function to inform the auditing library that link-map activity is occurring.  cookie identifies the object at the head of the link map.  When the dynamic linker invokes this function, flag is set  to  one
//        of the following values:
// 
//        LA_ACT_ADD         New objects are being added to the link map.
// 
//        LA_ACT_DELETE      Objects are being removed from the link map.
// 
//        LA_ACT_CONSISTENT  Link-map activity has been completed: the map is once again consistent.
// 
//    la_objopen()
// 
//        unsigned int la_objopen(struct link_map *map, Lmid_t lmid,
//                                uintptr_t *cookie);
// 
//        The dynamic linker calls this function when a new shared object is loaded.  The map argument is a pointer to a link-map structure that describes the object.  The lmid field has one of the following values
// 
//        LM_ID_BASE       Link map is part of the initial namespace.
// 
//        LM_ID_NEWLM      Link map is part of a new namespace requested via dlmopen(3).
// 
//        cookie is a pointer to an identifier for this object.  The identifier is provided to later calls to functions in the auditing library in order to identify this object.  This identifier is initialized to point to object's link map, but
//        the audit library can change the identifier to some other value that it may prefer to use to identify the object.
// 
//        As its return value, la_objopen() returns a bit mask created by ORing zero or more of the following constants, which allow the auditing library to select the objects to be monitored by la_symbind*():
// 
//        LA_FLG_BINDTO    Audit symbol bindings to this object.
// 
//        LA_FLG_BINDFROM  Audit symbol bindings from this object.
// 
//        A return value of 0 from la_objopen() indicates that no symbol bindings should be audited for this object.
// 
//    la_objclose()
// 
//        unsigned int la_objclose(uintptr_t *cookie);
// 
//        The dynamic linker invokes this function after any finalization code for the object has been executed, before the object is unloaded.  The cookie argument is the identifier obtained from a previous invocation of la_objopen().
// 
//        In the current implementation, the value returned by la_objclose() is ignored.
// 
//    la_preinit()
// 
//        void la_preinit(uintptr_t *cookie);
// 
//        The dynamic linker invokes this function after all shared objects have been loaded, before control is passed to the application (i.e., before calling main()).  Note that main() may still later dynamically load objects using dlopen(3).
// 
//    la_symbind*()
// 
//        uintptr_t la_symbind32(Elf32_Sym *sym, unsigned int ndx,
//                               uintptr_t *refcook, uintptr_t *defcook,
//                               unsigned int *flags, const char *symname);
//        uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
//                               uintptr_t *refcook, uintptr_t *defcook,
//                               unsigned int *flags, const char *symname);
// 
//        The dynamic linker invokes one of these functions when a symbol binding occurs between two shared objects that have been marked for auditing notification by la_objopen().  The la_symbind32() function is employed on  32-bit  platforms;
//        the la_symbind64() function is employed on 64-bit platforms.
// 
//        The  sym argument is a pointer to a structure that provides information about the symbol being bound.  The structure definition is shown in <elf.h>.  Among the fields of this structure, st_value indicates the address to which the sym‐
//        bol is bound.
// 
//        The ndx argument gives the index of the symbol in the symbol table of the bound shared object.
// 
//        The refcook argument identifies the shared object that is making the symbol reference; this is the same identifier that is provided to the la_objopen() function that returned  LA_FLG_BINDFROM.   The  defcook  argument  identifies  the
//        shared object that defines the referenced symbol; this is the same identifier that is provided to the la_objopen() function that returned LA_FLG_BINDTO.
// 
//        The symname argument points a string containing the name of the symbol.
// 
//        The  flags  argument is a bit mask that both provides information about the symbol and can be used to modify further auditing of this PLT (Procedure Linkage Table) entry.  The dynamic linker may supply the following bit values in this
//        argument:
// 
//        LA_SYMB_DLSYM         The binding resulted from a call to dlsym(3).
// 
//        LA_SYMB_ALTVALUE      A previous la_symbind*() call returned an alternate value for this symbol.
// 
//        By default, if the auditing library implements la_pltenter() and la_pltexit() functions (see below), then these functions are invoked, after la_symbind(), for PLT entries, each time the symbol is referenced.  The following  flags  can
//        be ORed into *flags to change this default behavior:
// 
//        LA_SYMB_NOPLTENTER    Don't call la_pltenter() for this symbol.
// 
//        LA_SYMB_NOPLTEXIT     Don't call la_pltexit() for this symbol.
//        
//        The  return value of la_symbind32() and la_symbind64() is the address to which control should be passed after the function returns.  If the auditing library is simply monitoring symbol bindings, then it should return sym->st_value.  A
//        different value may be returned if the library wishes to direct control to an alternate location.
// 
//    la_pltenter()
//        The precise name and argument types for this function depend on the hardware platform.  (The appropriate definition is supplied by <link.h>.)  Here is the definition for x86-32:
// 
//        Elf32_Addr la_i86_gnu_pltenter(Elf32_Sym *sym, unsigned int ndx,
//                         uintptr_t *refcook, uintptr_t *defcook,
//                         La_i86_regs *regs, unsigned int *flags,
//                         const char *symname, long int *framesizep);
// 
//        This function is invoked just before a PLT entry is called, between two shared objects that have been marked for binding notification.
// 
//        The sym, ndx, refcook, defcook, and symname are as for la_symbind*().
// 
//        The regs argument points to a structure (defined in <link.h>) containing the values of registers to be used for the call to this PLT entry.
// 
//        The flags argument points to a bit mask that conveys information about, and can be used to modify subsequent auditing of, this PLT entry, as for la_symbind*().
// 
//        The framesizep argument points to a long int buffer that can be used to explicitly set the frame size used for the call to this PLT entry.  If different la_pltenter() invocations for this symbol return different values, then the maxi‐
//        mum returned value is used.  The la_pltenter() function is called only if this buffer is explicitly set to a suitable value.
// 
//        The return value of la_pltenter() is as for la_symbind*().
// 
//    la_pltexit()
//        The precise name and argument types for this function depend on the hardware platform.  (The appropriate definition is supplied by <link.h>.)  Here is the definition for x86-32:
// 
//        unsigned int la_i86_gnu_pltexit(Elf32_Sym *sym, unsigned int ndx,
//                         uintptr_t *refcook, uintptr_t *defcook,
//                         const La_i86_regs *inregs, La_i86_retval *outregs,
//                         const char *symname);
// 
//        This function is called when a PLT entry, made between two shared objects that have been marked for binding notification, returns.  The function is called just before control returns to the caller of the PLT entry.
// 
//        The sym, ndx, refcook, defcook, and symname are as for la_symbind*().
// 
//        The inregs argument points to a structure (defined in <link.h>) containing the values of registers used for the call to this PLT entry.  The outregs argument points to a structure (defined in <link.h>) containing return values for the
//        call to this PLT entry.  These values can be modified by the caller, and the changes will be visible to the caller of the PLT entry.
// 
//        In the current GNU implementation, the return value of la_pltexit() is ignored.
// 
// CONFORMING TO
//        This API is nonstandard, but very similar to the Solaris API, described in the Solaris Linker and Libraries Guide, in the chapter Runtime Linker Auditing Interface.
// 
// NOTES
//        Note the following differences from the Solaris dynamic linker auditing API:
// 
//        *  The Solaris la_objfilter() interface is not supported by the GNU implementation.
// 
//        *  The Solaris la_symbind32() and la_pltexit() functions do not provide a symname argument.
// 
//        *  The Solaris la_pltexit() function does not provide inregs and outregs arguments (but does provide a retval argument with the function return value).
// 
// BUGS
//        In glibc versions up to and include 2.9, specifying more than one audit library in LD_AUDIT results in a run-time crash.  This is reportedly fixed in glibc 2.10.
// 
// EXAMPLE
       #include <link.h>
       #include <stdio.h>

       unsigned int
       la_version(unsigned int version)
       {
           printf("la_version(): %d\n", version);

           return version;
       }

       char *
       la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
       {
           printf("la_objsearch(): name = %s; cookie = %x", name, cookie);
           printf("; flag = %s\n",
                   (flag == LA_SER_ORIG) ?    "LA_SER_ORIG" :
                   (flag == LA_SER_LIBPATH) ? "LA_SER_LIBPATH" :
                   (flag == LA_SER_RUNPATH) ? "LA_SER_RUNPATH" :
                   (flag == LA_SER_DEFAULT) ? "LA_SER_DEFAULT" :
                   (flag == LA_SER_CONFIG) ?  "LA_SER_CONFIG" :
                   (flag == LA_SER_SECURE) ?  "LA_SER_SECURE" :
                   "???");

           return name;
       }

       void
       la_activity (uintptr_t *cookie, unsigned int flag)
       {
           printf("la_activity(): cookie = %x; flag = %s\n", cookie,
                   (flag == LA_ACT_CONSISTENT) ? "LA_ACT_CONSISTENT" :
                   (flag == LA_ACT_ADD) ?        "LA_ACT_ADD" :
                   (flag == LA_ACT_DELETE) ?     "LA_ACT_DELETE" :
                   "???");
       }

       unsigned int
       la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
       {
           printf("la_objopen(): loading \"%s\"; lmid = %s; cookie=%x\n",
                   map->l_name,
                   (lmid == LM_ID_BASE) ?  "LM_ID_BASE" :
                   (lmid == LM_ID_NEWLM) ? "LM_ID_NEWLM" :
                   "???",
                   cookie);

           return LA_FLG_BINDTO | LA_FLG_BINDFROM;
       }

       unsigned int
       la_objclose (uintptr_t *cookie)
       {
           printf("la_objclose(): %x\n", cookie);

           return 0;
       }

       void
       la_preinit(uintptr_t *cookie)
       {
           printf("la_preinit(): %x\n", cookie);
       }

       uintptr_t
       la_symbind32(Elf32_Sym *sym, unsigned int ndx, uintptr_t *refcook,
               uintptr_t *defcook, unsigned int *flags, const char *symname)
       {
           printf("la_symbind32(): symname = %s; sym->st_value = %p\n",
                   symname, sym->st_value);
           printf("        ndx = %d; flags = 0x%x", ndx, *flags);
           printf("; refcook = %x; defcook = %x\n", refcook, defcook);

           return sym->st_value;
       }

       uintptr_t
       la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
               uintptr_t *defcook, unsigned int *flags, const char *symname)
       {
           printf("la_symbind64(): symname = %s; sym->st_value = %p\n",
                   symname, sym->st_value);
           printf("        ndx = %d; flags = 0x%x", ndx, *flags);
           printf("; refcook = %x; defcook = %x\n", refcook, defcook);

           return sym->st_value;
       }

       Elf32_Addr
       la_i86_gnu_pltenter(Elf32_Sym *sym, unsigned int ndx,
               uintptr_t *refcook, uintptr_t *defcook, La_i86_regs *regs,
               unsigned int *flags, const char *symname, long int *framesizep)
       {
           printf("la_i86_gnu_pltenter(): %s (%p)\n", symname, sym->st_value);

           return sym->st_value;
       }

// // SEE ALSO
// //        ldd(1), dlopen(3), ld.so(8), ldconfig(8)
// // 
// // COLOPHON
// //        This page is part of release 4.00 of the Linux man-pages project.  A description of the project, information about reporting bugs, and the latest version of this page, can be found at http://www.kernel.org/doc/man-pages/.
// // 
// // Linux                                                                                                               2012-07-07                                                                                                      RTLD-AUDIT(7)
// [exec@exec-pc loader]$ 
