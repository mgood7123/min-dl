# min-dl: minimal dynamic linker implementation

##### TODO
      1.  correctly impliment a recursive symbol resolver and tracker to prevent the same symbols being resolved multiple times leading to incorrectly resolved symbols or unresolvable symbols
      
      2. find a way to initialize global variables required in functions for correct execution (may need alot of help with this part)
      
      3. correct address bugs

      4. Impliment As A Fully Functional Dynamic Loader
 

re-written loader is in loader (https://github.com/mgood7123/min-dl-dynamic-loader/blob/master/loader/)

original min-dl is in min-dl

#### compilation:

git clone https://github.com/mgood7123/min-dl-dynamic-loader.git

cd min-dl-dynamic-loader/loader

./make_loader

cd ../

## this aims to be a fully functional dlopen, dlsym, dlclose, implimentation on top of a fully functional dynamic loader, currently only supports musl libc applications due to glibc requiring symbols for certain functions (for example: puts() ) from its own dynamic loader ld.so (ld-linux-x86_64.so) that it does not specify explicitly as required


#### UNCHANGED from original README.MD
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
