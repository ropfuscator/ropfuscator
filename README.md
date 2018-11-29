# README
ROPfuscator is an LLVM backend extension that aims to perform code obfuscation taking advantage of ROP chains: supported instructions are replaced by semantically equivalent ROP gadgets.

##### Limitations
The current implementation has several limitations, so the following requirements must be met if you want to get everything working:
- Gadgets are borrowed from `libc` (x86); so, since we refer to them using offsets, you must use this specific version: `Debian GLIBC 2.24-11+deb9u3`. 
**For this reason, I suggest you to do everything in the very same VM I used (Debian 9 i386)**.
- Address Space Layout Randomization (ASLR) isn't supported yet. Remember to disable it when you test compiled programs.

-------

### Getting started
#### Joining with LLVM source tree
1. **Download** LLVM 7.0 **sources** from http://releases.llvm.org/7.0.0/llvm-7.0.0.src.tar.xz
2. **Unpack** them in a directory of your choice which will refer to as `[SRC-DIR]`. 
3. **Clone** this repository specifically in `[SRC-DIR]/lib/Target/X86/ropfuscator`:

    ```
    git clone git@bitbucket.org:s2lab/ropfuscator.git [SRC-DIR]/lib/Target/X86/ropfuscator
    ```
4. **Patch** the following LLVM backend source files, in order to enable the pass execution when compiling:

    ```
    cd [SRC-DIR]/lib/Target/X86/
    patch X86.h ropfuscator/patches/X86.patch
    patch X86TargetMachine.cpp ropfuscator/patches/X86TargetMachine.patch
    patch CMakeLists.txt ropfuscator/patches/CMakeLists.patch
    ```
    
Now ROPfuscator has been merged to the LLVM backend. Time to compile everything!

#### Compiling

1. **Install** all the **prerequisites**:

    ```
    sudo apt install cmake ninja-build clang
    ```
    
3. Create a **build directory** which will refer to as `[BUILD-DIR]`:

    ```
    mkdir [BUILD-DIR]
    cd [BUILD-DIR]
    ```
    
4. Let's **configure** the build environment, instructing `cmake` as follows:

   ```
    cmake -DCMAKE_BUILD_TYPE=Debug -DLLVM_TARGETS_TO_BUILD=X86 -DBUILD_SHARED_LIBS=ON -GNinja [SRC-DIR] 
    ```
    As you can see, there are a couple of flags that are worth to be mentioned:
    - `-DCMAKE_BUILD_TYPE=Debug`: just to obtain a debug build (more flexible)
    - `-DLLVM_TARGETS_TO_BUILD=X86`: we're interested only in the X86 platform, so we don't want to lose time compiling the backend also for all the other platforms, such as ARM, MIPS, SPARC, etc. This speeds up the compilation process, and make us save up to 4 GB of disk space.
    - `-DBUILD_SHARED_LIBS=ON`: shared code is moved in `.so` libraries, that can be linked at runtime, thus speeding up the compilation process even more.
    - `-GNinja`: specifies to use `ninja` as build generator. By using `ninja` the overall compile time can decrease by more than 50% (it seems that it has better support to multithreading), but most importantly we can invoke a specific command to compile only `llc`.
    
5. Now start the actual **compilation** within your build directory

    ```
    cmake --build .
    ```

    Building takes some time to finish. 

6. Finally, we can create a symbolic link to our custom version of `llc`, in order to call it in a simpler way:

    ```
    sudo ln -s [BUILD-DIR]/bin/llc /usr/local/bin/llc
    ```
    
#### Recompiling LLC 
Since ROPfuscator is a `MachineFunctionPass`, we have to recompile `llc` (LLVM system compiler) each time we modify the pass. 
Luckily we're using `ninja-build`, so we don't have to recompile the whole backend; doing this is just a matter of seconds by running:

```
ninja llc
```

----------

### Running experiments
`llc` works at the IR level, so we have to generate the `.ll` file out of our C program:

```
clang -O0 -S -emit-llvm hello.c -o hello.ll
```

then we have to run only the code generation use `llc`:

```
llc hello.ll
```

The output is an `asm` file, that can be compiled simply with `gcc`:

```
gcc hello.s -o hello
```

------------

### Troubleshooting
##### Segmentation fault during ROP Chain execution
* **Getting the correct libc version:** ROPfuscator build ROP chains using gadgets located at very specific locations with `libc`. A slight version variation can lead to errors.
Please be sure to use this exact version: `Debian GLIBC 2.24-11+deb9u3`.

* **Disabling ASLR:** ROPfuscator uses `libc` to inject ROP gadgets onto the stack. Until now, we're unable to handle with ASLR, so we have to disable it:

    ```
    sudo sysctl -w kernel.randomize_va_space=0
    ```