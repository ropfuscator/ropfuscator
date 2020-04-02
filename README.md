# ROPfuscator

![logo](https://i.imgur.com/dSAJ2VG.png)

ROPfuscator is an LLVM backend extension that aims to perform code obfuscation taking advantage of ROP chains: supported instructions are replaced by semantically equivalent ROP gadgets.

-------

## Project architecture

![Imgur](https://i.imgur.com/ipResnS.png)

-------

## Features

- Gadgets are automatically extracted from `libc` or from a custom library, if provided.
- Gadgets are referenced using **symbol anchoring**: each gadget is referenced using a random symbol within the provided library and its offset from it. Since symbol addresses are automatically resolved at runtime by the dynamic loader (`ld`), we can guarantee to reach the wanted gadget even if the library is mapped in memory at a non-static address.
- ASLR-resilient: works flawlessly with ASLR enabled.
- **Data-flow analysis**: in case of need of a scratch register where to compute temporary values, only registers that don't hold useful data are used. 
- **Gadget generalisation** through the **Xchg graph** allows to parametrise gadget instruction operands, giving the possibility to re-use the same gadgets but with different operands. This way we ensure that instructions are correctly obfuscated even in case the number of extracted gadgets is very restricted.

## Limitations

- Dependence on the specific version of `libc` used at compile time.  
    To avoid this, you can potentially use a library that will be distributed along with the binary.
- Support is currently limited to x86 platforms.
- Only the following instructions are currently supported: `ADD32ri(8)`, `SUB32ri(8)`, `INC32r`, `DEC32r`, `MOV32rm` and `MOV32mr`.

-------

## Prerequisites

- `ninja`
- `libfmt`, version `5.X`
- `pkg-config`
- `cmake`, version `>= 3.13`

### Prerequisites installation (Ubuntu & Debian)

    sudo apt install cmake ninja-build pkg-config libfmt-dev

## Build

Make sure to be able to clone this repository first and then run:

    wget http://releases.llvm.org/7.0.0/llvm-7.0.0.src.tar.xz
    tar -xf llvm-7.0.0.src.tar.xz && rm llvm-7.0.0.src.tar.xz 
    cd llvm-7.0.0.src
    pushd tools
    wget https://releases.llvm.org/7.0.0/cfe-7.0.0.src.tar.xz
    tar -xf cfe-7.0.0.src.tar.xz && rm cfe-7.0.0.src.tar.xz
    popd
    pushd lib/Target/X86
    git init
    git remote add origin git@bitbucket.org:s2lab/ropfuscator.git
    git fetch --all
    git reset --hard origin/master
    popd
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=Debug -DLLVM_TARGETS_TO_BUILD=X86 -DBUILD_SHARED_LIBS=ON -DLLVM_ENABLE_EH=On -DLLVM_ENABLE_RTTI=On -GNinja ..
    ninja llc

### Project configuration

There are a couple of flags that are worth to be mentioned when configuring the build:

- `-DCMAKE_BUILD_TYPE=Debug`: just to obtain a debug build (more flexible)
- `-DLLVM_TARGETS_TO_BUILD=X86`: we're interested only in the X86 platform, so we don't want to lose time compiling the backend also for all the other platforms, such as ARM, MIPS, SPARC, etc. This speeds up the compilation process, and make us save up to 4 GB of disk space.
- `-DBUILD_SHARED_LIBS=ON`: shared code is moved in `.so` libraries, that can be linked at runtime, thus speeding up the compilation process even more.
- `-GNinja`: specifies to use `ninja` as build generator. By using `ninja` the overall compile time can decrease by more than 50% (it seems that it has better support to multithreading), but most importantly we can invoke a specific command to compile only `llc`.

Once the project is compiled, we can create a symbolic link to our custom version of `llc`, in order to call it in a simpler way, `ropf-llc`:

    sudo ln -s [BUILD-DIR]/bin/llc $(HOME)/.local/bin/ropf-llc

Make sure that `$(HOME)/.local/bin/` is set in your `PATH` environment variable.

## Recompiling LLC

Since ROPfuscator is a `MachineFunctionPass`, we have to recompile `llc` (LLVM system compiler) each time we modify the pass.
Luckily we're using `ninja-build`, so we don't have to recompile the whole backend; doing this is just a matter of seconds by running:

    ninja llc

-------

## Usage

1. Convert the source code file to obfuscate in LLVM IR:

        clang -O0 -S -emit-llvm example.c

    this will create a new file `example.ll`.

2. Compile using our custom LLVM `llc` tool:

        ropf-llc example.ll [ -march=x86 ]

    - `-march=x86`: compile in 32-bit mode from a x64 platform  

    The output is an asm `example.s` file.

3. Assemble and link:

        [ LD_RUN_PATH='$ORIGIN/' ] gcc example1.s -o example [ -m32 ] [ -lc | -L. -l:libcustom.so ]


    - `-m32`: compile in 32-bit mode from a x64 platform (you will need to have `gcc-multilib` installed for this)

    - `-lc`: only if you used `libc` to extract gadgets and symbols during the linking phase. This will enforce the static linker to resolve the symbols we injected using only `libc`.

    - `-L. -l:libcustom.so`: only if you used a custom library. 
    - `LD_RUN_PATH`: only if you used a custom library. Enforce the dynamic loader to look for the needed libraries in the specified path first. This will ensure that the loader will load your library first, as soon as it is shipped along with the binary.

    Note: we use `gcc` only because, in its default behaviour, it doesn't use **lazy binding** to resolve symbols. This is crucial since we need to have all the symbols resolved as soon as the program has been loaded in memory.

## Compiling the examples

While in the `build` directory, run:

    ninja ropfuscator-examples

The compiled examples will be found in the `bin/` directory.

-------

### Known issues

- When compiling a program on a 64-bit platform, the custom `llc` compiler may disrupt the correct functioning of library calls.
It seems to be caused by the fact that certain integer parameter values are pushed onto the stack as if they were 64-bit types, even if we're compiling using the `-march=x86` switch.
This happens even if the ROPfuscator pass is disabled (naively by putting a `return false` at the beginning of `runOnMachineFunction()`).  
    An example of this behaviour can be observed in `example7`.
The program has been compiled with plain `clang` compiler once, and with our custom `llc` but with ROPfuscator pass disabled.
Setting up a breakpoint on the `fseek` call (in `count_characters` function) we have this:

![Imgur](https://i.imgur.com/qmW6LPj.png)
