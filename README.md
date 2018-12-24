![logo](https://i.imgur.com/dSAJ2VG.png)
# ROPfuscator
ROPfuscator is an LLVM backend extension that aims to perform code obfuscation taking advantage of ROP chains: supported instructions are replaced by semantically equivalent ROP gadgets.

##### Features
- Available gadgets and symbols are automatically extracted from `libc`.
- Gadgets are referenced using **symbol hooking**, i.e. each gadget is referenced using a random symbol within `libc` and its offset from it. Since symbol addresses are automatically resolved at runtime by the dynamic loader (`ld`), we can guarantee to reach the wanted gadget even if the library is mapped in memory at a non-static address.
- ASLR-resilient: works flawlessly with ASLR enabled.

##### Limitations
- Dependence on the specific version of `libc` used at compile time.  
    To avoid this, you can potentially use a library that will be distributed along with the binary as source for ROP gadgets.
- Only the following instructions are currently supported: `ADD32ri(8)`, `SUB32ri(8)`, `MOV32ri`, `MOV32rm` and `MOV32mr`.

##### Dependencies
- `libcapstone-dev`
- `binutils-dev`

-------

### Getting started
#### Joining with LLVM source tree
1. **Download** LLVM 7.0 **sources** from http://releases.llvm.org/7.0.0/llvm-7.0.0.src.tar.xz
2. **Unpack** them in a directory of your choice which will refer to as `[SRC-DIR]`. 
3. **Clone** this repository specifically in `[SRC-DIR]/lib/Target/X86/ropfuscator`:

        git clone git@bitbucket.org:s2lab/ropfuscator.git [SRC-DIR]/lib/Target/X86/ropfuscator


4. **Patch** the following LLVM backend source files, in order to enable the pass execution when compiling:

        cd [SRC-DIR]/lib/Target/X86/
        patch X86.h ropfuscator/patches/X86.patch
        patch X86TargetMachine.cpp ropfuscator/patches/X86TargetMachine.patch
        patch CMakeLists.txt ropfuscator/patches/CMakeLists.patch


    Now ROPfuscator has been merged to the LLVM backend. Time to compile everything!

#### Compiling

1. **Install** all the **prerequisites**:

        sudo apt install cmake ninja-build clang

3. Create a **build directory** which will refer to as `[BUILD-DIR]`:

        mkdir [BUILD-DIR]
        cd [BUILD-DIR]

4. Let's **configure** the build environment, instructing `cmake` as follows:

        cmake -DCMAKE_BUILD_TYPE=Debug -DLLVM_TARGETS_TO_BUILD=X86 -DBUILD_SHARED_LIBS=ON -GNinja [SRC-DIR] 

    As you can see, there are a couple of flags that are worth to be mentioned:

    - `-DCMAKE_BUILD_TYPE=Debug`: just to obtain a debug build (more flexible)
    - `-DLLVM_TARGETS_TO_BUILD=X86`: we're interested only in the X86 platform, so we don't want to lose time compiling the backend also for all the other platforms, such as ARM, MIPS, SPARC, etc. This speeds up the compilation process, and make us save up to 4 GB of disk space.
    - `-DBUILD_SHARED_LIBS=ON`: shared code is moved in `.so` libraries, that can be linked at runtime, thus speeding up the compilation process even more.
    - `-GNinja`: specifies to use `ninja` as build generator. By using `ninja` the overall compile time can decrease by more than 50% (it seems that it has better support to multithreading), but most importantly we can invoke a specific command to compile only `llc`.
    
5. Now start the actual **compilation** within your build directory

        cmake --build .

    Building takes some time to finish. 

6. Finally, we can create a symbolic link to our custom version of `llc`, in order to call it in a simpler way:

        sudo ln -s [BUILD-DIR]/bin/llc /usr/local/bin/llc

#### Recompiling LLC 
Since ROPfuscator is a `MachineFunctionPass`, we have to recompile `llc` (LLVM system compiler) each time we modify the pass. 
Luckily we're using `ninja-build`, so we don't have to recompile the whole backend; doing this is just a matter of seconds by running:

    ninja llc

----------

### Usage
1. Generate the LLVM IR (`.ll`) out of a given C program:

        clang -O0 -S -emit-llvm hello.c -o hello.ll

2. Run the assembly code generation using `llc`:

        llc hello.ll

3. Compile the output file (`.s`) using `gcc` with the following arguments:

        gcc -o hello hello.s -Wl,--unresolved-symbols=ignore-in-object-files -lc

    Using those flags will instruct the static linker to exclusively use `libc` as library.

