# Performance Evaluation

This directory contains evaluation configurations with SPEC CPU 2017 (and custom benchmark using binutils).

The evaluation is done on Ubuntu 18.04 64bit environment and the following descriptions assume this environment.
It would work on another environment, software installation should be adjusted to the environment.


## Preparation

1. Install required software
2. Install SPEC CPU 2017 to `/opt/cpu2017`
3. Build ROPfuscator
4. Install ROPfuscator to `/opt/ropfuscator`

### Install required software

Install build tools (cmake, ninja), compiler (gcc, g++, clang-7), and 32bit libc/libstdc++ (gcc-multilib, g++-multilib)

    sudo apt install cmake ninja-build pkg-config gcc g++ clang-7 gcc-multilib g++-multilib

### Install SPEC CPU 2017

Mount the ISO file and execute `./install.sh` in the mounted directory.
When asked the installation directory, enter `/opt/cpu2017`.

### Build ROPfuscator

1. copy the entire ropfuscator directory to `/usr/local/src/ropfuscator`.
2. obtain [LLVM 7.0.0](http://releases.llvm.org/7.0.0/llvm-7.0.0.src.tar.xz) source code and extract it into `/usr/local/src/llvm-7.0.0.src`.
3. obtain [Clang 7.0.0](https://releases.llvm.org/7.0.0/cfe-7.0.0.src.tar.xz) source code and extract it into `/usr/local/src/llvm-7.0.0.src/tools/cfe-7.0.0.src`.
4. create a symbolic link from `/usr/local/src/ropfuscator` to `lib/target/X86/ropfuscator`.
5. apply a patch (`ropfuscator/patch/llvm-7.patch`) to LLVM source tree.
6. create a build directory `/usr/local/src/build-ropfuscator`.
7. run `cmake` to create build configurations.
8. build `llc`, `clang` and `llvm-link`.

    # Step 1:
    cd /usr/local/src
    cp -r /path/to/ropfuscator-source /usr/local/src/ropfuscator
    # Step 2:
    wget http://releases.llvm.org/7.0.0/llvm-7.0.0.src.tar.xz
    tar -xf llvm-7.0.0.src.tar.xz && rm llvm-7.0.0.src.tar.xz
    # Step 3:
    cd llvm-7.0.0.src/tools
    wget https://releases.llvm.org/7.0.0/cfe-7.0.0.src.tar.xz
    tar -xf cfe-7.0.0.src.tar.xz && rm cfe-7.0.0.src.tar.xz
    # Step 4:
    cd ../lib/Target/X86
    ln -s /usr/local/src/ropfuscator
    # Step 5:
    patch < ropfuscator/patch/llvm-7.patch
    # Step 6:
    cd /usr/local/src
    mkdir build-ropfuscator
    # Step 7:
    cd build-ropfuscator
    cmake -DCMAKE_BUILD_TYPE=Debug -DLLVM_TARGETS_TO_BUILD=X86 -DBUILD_SHARED_LIBS=ON -GNinja ..
    # Step 8:
    ninja llc clang llvm-link

### Install ROPfuscator

1. create `/opt/ropfuscator` directory.
2. create a symbolic link to the binary directory built in the previous steps (`/usr/local/src/build-ropfuscator/{bin,lib}`) from the directory.
3. create a symbolic link to the ropfuscator compiler harness (`/usr/local/src/ropfuscator/ropcc.sh`) from the directory.
4. create a symbolic link to the evaluation directory (`/usr/local/src/ropfuscator/evaluation`) from the directory.

    mkdir /opt/ropfuscator
    ln -s /usr/local/src/build-ropfuscator/bin
    ln -s /usr/local/src/build-ropfuscator/lib
    ln -s /usr/local/src/ropfuscator/ropcc.sh
    ln -s /usr/local/src/ropfuscator/evaluation


## Evaluation with SPEC CPU

1. Coverage evaluation
2. Size evaluation
3. Throughput performance evaluation

### Prepare SPEC CPU environment

Go to SPEC CPU installation directory, and set environment variables with `shrc`.

   cd /opt/cpu2017
   source shrc

### Coverage evaluation

Execute SPEC CPU with `instrstat` config (`-O0` and `-O3`, build only).

    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-instrstat-o0.cfg --action=build intrate
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-instrstat-o3.cfg --action=build intrate

Then, look at each `make.out` file output in the build directory.
Note that the result includes pseudo-instructions (label, etc) - they are not actual instructions.
They are shown as instruction numbers less than 100, and should be excluded in final statistics.

### Size evaluation

Execute SPEC CPU with `plain`, `roponly`, `opaque`, `stegano` config (`-O0`, build only).

    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-plain-o0.cfg --action=build intrate
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-roponly-o0.cfg --action=build intrate
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-opaque-o0.cfg --action=build intrate
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-stegano-o0.cfg --action=build intrate

Then, strip each generated executables, and measure the size.

### Throughput performance evaluation

Execute SPEC CPU with `plain`, `roponly` config (`-O0`).
Plain config takes about 3.5 hours, and ROPonly config likely takes about 1-2 weeks.
This means that `opaque` and `stegano` configs would take more than a month (or a year), thus cannot be tested practically.

    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-plain-o0.cfg intrate
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-roponly-o0.cfg intrate

Even `plain` and `roponly` takes so long, and the tasks can be split into 4 machines as follows:

    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-plain-o0.cfg 500.perlbench_r 523.xalancbmk_r
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-plain-o0.cfg 520.omnetpp_r 525.x264_r
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-plain-o0.cfg 502.gcc_r 541.leela_r
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-plain-o0.cfg 505.mcf_r 531.deepsjeng_r 557.xz_r

    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-roponly-o0.cfg 500.perlbench_r 523.xalancbmk_r
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-roponly-o0.cfg 520.omnetpp_r 525.x264_r
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-roponly-o0.cfg 502.gcc_r 541.leela_r
    runcpu --config=/opt/ropfuscator/evaluation/speccpu2017/spec/ropf-roponly-o0.cfg 505.mcf_r 531.deepsjeng_r 557.xz_r


## Evaluation with binutils

### Binutils custom test specification

|binary |test                                   |command                    |
|-------|---------------------------------------|---------------------------|
|readelf|read ELF information of libstdc++.so.6.|`readelf -a libstdc++.so.6`|
|objdump|disassemble libstdc++.so.6.            |`objdump -d libstdc++.so.6`|
|c++filt|demangle all symbols in libstdc++.so.6.|`c++filt < syms10.txt`     |

Test input files:
* `binutils-input/libstdc++.so.6.xz`: 32bit libstdc++ library (decompress before use)
* `binutils-input/syms10.txt.xz`: output of `readelf -sW libstdc++.so.6`, repeated 10 times (decompress before use)

### Build binary

Build executables for each configuration, as shown in the table below.
`eval.*.instrstat` will generate coverage information in stdout.
Note that intermediate assembly files can be huge (10-20GB), so be careful of storage amount.

|binary |plain config      |roponly config      |OP/OC config       |stegano config      |coverage config       |
|-------|------------------|--------------------|-------------------|--------------------|----------------------|
|readelf|eval.readelf.plain|eval.readelf.roponly|eval.readelf.opaque|eval.readelf.stegano|eval.readelf.instrstat|
|objdump|eval.objdump.plain|eval.objdump.roponly|eval.objdump.opaque|eval.objdump.stegano|eval.objdump.instrstat|
|c++filt|eval.c++filt.plain|eval.c++filt.roponly|eval.c++filt.opaque|eval.c++filt.stegano|eval.c++filt.instrstat|

    ninja eval.readelf.plain eval.readelf.roponly eval.readelf.opaque eval.readelf.stegano
    ninja eval.objdump.plain eval.objdump.roponly eval.objdump.opaque eval.objdump.stegano
    ninja eval.c++filt.plain eval.c++filt.roponly eval.c++filt.opaque eval.c++filt.stegano
    ninja eval.readelf.instrstat eval.objdump.instrstat eval.c++filt.instrstat > binutils-coverage.log

### Run test

Measure execution time for each test case and config.

    time bin/eval.readelf.plain   -a libstdc++.so.6 >/dev/null
    time bin/eval.readelf.roponly -a libstdc++.so.6 >/dev/null
    time bin/eval.readelf.opaque  -a libstdc++.so.6 >/dev/null
    time bin/eval.readelf.stegano -a libstdc++.so.6 >/dev/null

    time bin/eval.objdump.plain   -d libstdc++.so.6 >/dev/null
    time bin/eval.objdump.roponly -d libstdc++.so.6 >/dev/null
    time bin/eval.objdump.opaque  -d libstdc++.so.6 >/dev/null
    time bin/eval.objdump.stegano -d libstdc++.so.6 >/dev/null

    time bin/eval.c++filt.plain   < sym10.txt >/dev/null
    time bin/eval.c++filt.roponly < sym10.txt >/dev/null
    time bin/eval.c++filt.opaque  < sym10.txt >/dev/null
    time bin/eval.c++filt.stegano < sym10.txt >/dev/null
