# min-dl: minimal dynamic linker implementation

## the aim
    
    To load any package compiled with any libc implimentation (glibc, musl, uclibc, dietlibc, and others)

    To launch the package without requiring host dependancies unless necessary

    aims to be a fully functional dlopen, dlsym, dlclose, implimentation on top of a fully functional
    dynamic loader, currently only supports musl libc applications due to glibc requiring symbols for
    certain functions (for example: puts() ) from its own dynamic loader ld.so (ld-linux-x86_64.so) that
    it does not specify explicitly as required

    also features a slightly modified C++ symbol demangler function (from cfilt++) for aiding in
    attempting to dlopen C++ functions (uses libiberty)

    this also aims to (once stable) optimise dynamic loading for size by mapping only the minimum amount
    required, and unmapping the rest, moving mappings to make room for more mappings should there not be
    enough free space to map another file into the process address space, kinda like lazy mapping but
    smartly, in that only the needed parts are mapped and all other parts are unmapped for example if the
    only needed function is write() then only the write() function will be mapped instead of the entire
    libc.so, wich does not sound like much given only one dependancy but given hundreads of applications
    to execute and potentially thousands of dependancies, even with shared memory, could reduce total
    memory usage considerably as the full size of the dependancies are not loaded into memory and as a
    result, is not wasting space that could be used for other tasks

## rules

    THIS MUST BE ABLE TO REDIRECT THE LOADING OF SHARED OBJECTS (.so) TO ./ INSTEAD OF USING THE SYSTEM
    DEFAULT /

    THIS REDIRECTION PATH CAN BE CONFIGURED BY SETTING THE ENVIRONMENTAL VARIABLE LD_SYSTEM_PATH TO A NON
    NULL PATH

    THIS REDIRECTION PATH IS ALLOWED TO BE RELATIVE

    IF THE REDIRECTION PATH DOES NOT EXIST THE DEFAULT ./ IS ASSUMED AS A FALLBACK

    IF A LIBRARY CANNOT BE FOUND USING LD_SYSTEM_PATH AND CANNOT BE FOUND IN ./ THEN / WILL BE TRIED

    IF LIBRARY STILL CANNOT BE FOUND AN A ERROR SHALL OCCUR AND EXECUTION SHALL BE ABORTED DURING DYNAMIC
    LOADING

    OTHERWISE IF LIBRARY STILL CANNOT BE FOUND AN ERROR SHALL OCCUR AND EXECUTION SHALL CONTINUE EVEN
    THOUGH IT WILL LIKELY FAIL WITH Segmentation Fault








##### TODO
      1.  correctly impliment a recursive symbol resolver and tracker to prevent the same symbols being
      resolved multiple times leading to incorrectly resolved symbols or unresolvable symbols
      
      2. find a way to initialize global variables required in functions for correct execution (may need
      alot of help with this part)
      
      3. correct address bugs

      4. Impliment As A Fully Functional Dynamic Loader
 

re-written loader is in loader (https://github.com/mgood7123/min-dl-dynamic-loader/blob/master/loader/)

original min-dl is in min-dl

#### compilation:

git clone https://github.com/mgood7123/min-dl-dynamic-loader.git

cd min-dl-dynamic-loader/loader

./make_loader

cd ../






 


#### UNCHANGED from original README.MD (mostly useless since i use 1% of min dl's code)
To support dynamic linking, each ELF shared libary and each executable that
uses shared libraries has a Procedure Linkage Table (PLT), which adds a level
of indirection for function calls analogous to that provided by the GOT for
data. The PLT also permits "lazy evaluation", that is, not resolving
procedure addresses until they are called for the first time.

Since the PLT tends to have a lot more entries than the GOT, and most of the
routines will never be called in any given program, that can both speed
startup and save considerable time overall.

`min-dl` introduces a straightforward way to load the specified shared
objects and then perform the necessary relocations, including the shared
objects that the target shared object uses.

# Licensing
`min-dl` is freely redistributable under the two-clause BSD License.
Use of this source code is governed by a BSD-style license that can be found
in the `LICENSE` file.
