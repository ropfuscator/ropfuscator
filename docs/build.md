# Building ROPfuscator

You can build ROPfuscator either manually, or by using docker.

## Docker Build

ROPfuscator supports docker build with [Dockerfile](../docker/Dockerfile.llvm-7).

After cloning this project (and updating submodules), you can just run:
```
sh docker/build.sh
```

It will define the following tags:

- `ropfuscator:prebuild-llvm-7`: just before building ropfuscator
- `ropfuscator:build-llvm-7`: after building ropfuscator
- `ropfuscator:llvm-7`: ropfuscator binary (without build files)

You can use `ropfuscator:llvm-7` to obfuscate programs.


## Manual Build

### Build dependencies

- `ninja`
- `pkg-config`
- `cmake`, version `>= 3.00`
- external libraries (`libfmt==5.2.1`, `tinytoml==0.4`) included in `thirdparty/`
- C++ compiler (clang or g++)

On Ubuntu/Debian distribution, use the following command to install build dependencies:

```
sudo apt-get install cmake ninja-build pkg-config
```

### Compilation

Make sure to be able to clone this repository (and third party repositories in `thirdparty/` directory) first and then run:

```
wget http://releases.llvm.org/7.0.0/llvm-7.0.0.src.tar.xz
tar -xf llvm-7.0.0.src.tar.xz && rm llvm-7.0.0.src.tar.xz
cd llvm-7.0.0.src
pushd tools
wget https://releases.llvm.org/7.0.0/cfe-7.0.0.src.tar.xz
tar -xf cfe-7.0.0.src.tar.xz && rm cfe-7.0.0.src.tar.xz
popd
pushd lib/Target/X86
git clone --recursive git@bitbucket.org:s2lab/ropfuscator.git
patch < ropfuscator/patch/llvm-7.patch
popd
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DLLVM_TARGETS_TO_BUILD=X86 -DBUILD_SHARED_LIBS=ON -GNinja ..
ninja llc
```

### Project configuration

There are a couple of flags that are worth to be mentioned when configuring the build:

- `-DCMAKE_BUILD_TYPE=Debug`: just to obtain a debug build (more flexible)
- `-DLLVM_TARGETS_TO_BUILD=X86`: we're interested only in the X86 platform, so we don't want to lose time compiling the backend also for all the other platforms, such as ARM, MIPS, SPARC, etc. This speeds up the compilation process, and make us save up to 4 GB of disk space.
- `-DBUILD_SHARED_LIBS=ON`: shared code is moved in `.so` libraries, that can be linked at runtime, thus speeding up the compilation process even more.
- `-GNinja`: specifies to use `ninja` as build generator. By using `ninja` the overall compile time can decrease by more than 50% (it seems that it has better support to multithreading), but most importantly we can invoke a specific command to compile only `llc`.

Once the project is compiled, we can create a symbolic link to our custom version of `llc`, in order to call it in a simpler way, `ropf-llc`:

```
sudo ln -s [BUILD-DIR]/bin/llc $(HOME)/.local/bin/ropf-llc
```

Make sure that `$(HOME)/.local/bin/` is set in your `PATH` environment variable.

### Recompiling LLC

Since ROPfuscator is a `MachineFunctionPass`, we have to recompile `llc` (LLVM system compiler) each time we modify the pass.
Luckily we're using `ninja-build`, so we don't have to recompile the whole backend; doing this is just a matter of seconds by running:

```
ninja llc
```

