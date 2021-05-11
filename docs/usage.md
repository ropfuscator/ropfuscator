
# Usage for ROPfuscator

## Basic usage: if you use docker build

You can use `ropfuscator:llvm-9` image. This image provides `clang-7` and `llc` commands, which run ROPfuscator.

- If there are multiple source files

  ```
  # compile
  clang-9 -m32 -c -emit-llvm foo.c
  clang-9 -m32 -c -emit-llvm bar.c
  # bitcode link
  llvm-link-9 -o out.bc foo.bc bar.bc
  # obfuscate and build executable
  clang-9 -m32 -pie -o out out.bc
  ```

- If there is only one source file (not recommended)

  ```
  # compile, link, obfuscate
  clang-9 -m32 -pie main.c
  ```

## Basic usage: if you use manual build

### Dependencies

To use ROPfuscator (note: NOT to use generated binaries), the following binaries would be needed:

- clang (the same version as used in building ROPfuscator; clang-9 by default)
- 32bit libc / libstdc++ development library (in Ubuntu, `gcc-multilib` and `g++-multilib`)

### Steps

1. Convert the source code file to LLVM IR:

   ```
   clang [ -m32 ] -O0 -c -emit-llvm example.c
   ```

    - `-m32`: compile in 32-bit mode on 64-bit host (you will need to have `gcc-multilib` installed for this)

   This will create a new file `example.bc`.
2. Compile and obfuscate using our custom LLVM `llc` tool:

   ```
   ropf-llc example.bc [ -march=x86 ]
   ```

    - `-march=x86`: compile in 32-bit mode on 64-bit host

    The output is an asm `example.s` file.
3. Assemble and link:

   ```
   [ LD_RUN_PATH='$ORIGIN/' ] gcc -pie example1.s -o example [ -m32 ] [ -lc | -L. -l:libcustom.so ]
   ```

    - `-m32`: compile in 32-bit mode on 64-bit host (you will need to have `gcc-multilib` installed for this)
    - `-lc`: only if you used `libc` to extract gadgets and symbols during the linking phase. This will enforce the static linker to resolve the symbols we injected using only `libc`.
    - `-L. -l:libcustom.so`: only if you used a custom library.
    - `LD_RUN_PATH`: only if you used a custom library. Enforce the dynamic loader to look for the needed libraries in the specified path first. This will ensure that the loader will load your library first, as soon as it is shipped along with the binary.
    - Note: we have to use `-pie` to avoid **lazy binding** (aka PLT) to resolve symbols. This is crucial since we need direct function addresses of `libc` rather than the address of PLT entry, to compute gadget address. `gcc` has default compile option `-pie` while `clang` doesn't, so be careful if you are using `clang` instead to link the program. Also note that you should not use `-fpic` in compiling source file to bitcode.

## Configuring obfuscation

By default, this implementation applies ROP transformation only to the entire program. You can control obfuscation algorithm in a per-function basis.
To change configuration, you need to create a TOML file. The configuration file format and meaning are described below.

You can use the configuration file by `-ropfuscator-config <filepath>` option in `ropf-llc`. If you are directly using `clang`, you need to pass it via `-mllvm`, such as `-mllvm -ropfuscator-config -mllvm <filepath>` (put `-mllvm` in front of each parameter).

```toml
[general]
obfuscation_enabled = true
custom_library_path = "/lib/i386-linux-gnu/libc.so.6"
linked_libraries = ["/lib/i386-linux-gnu/libgcc_s.so.1", "/lib/i386-linux-gnu/libm.so.6"]

[functions.default]
obfuscation_enabled = true

[function.no_obfuscation]
name = "main"
obfuscation_enabled = false

[function.instr_hiding]
name = "AES_.*"
opaque_predicates_enabled = true
opaque_predicates_algorithm = "multcomp"
opaque_stegano_enabled = true
```

This configuration means as follows:

- In global setting, obfuscation is enabled (otherwise obfuscation is just skipped) and library `/lib/i386-linux-gnu/libc.so.6` is used for .
- By default, function is obfuscated with ROP transformation only.
- `main` function is not obfuscated at all.
- Functions named `AES_*` are obfuscated with ROP transformation and opaque predicates (`opaque_predicates_enabled = true`) and instruction hiding (`opaque_stegano_enabled = true`). The opaque predicate algorithm is "multiply and compare" (`opaque_predicates_algorithm = "multcomp"`).

The TOML format is as follows:

- `[general]` section
  - Configure application-wide options
- `[functions.default]` section
  - Configure default obfuscation options for all functions
- `[functions.<arbitrary-name>]` section
  - Configure obfuscation algorithms for specific functions (the function name pattern is specified by a regular expression)
  - You can use arbitrary string for `<arbitrary-name>`; it has nothing to do with function name pattern.

Each configuration is specified:
(for details, see comments in [ropfuscator-default.conf](../configs/ropfuscator-default.conf))

| Section       | Option                            | Default value      | Example value                                        | Type        | Meaning                                                                                                 |
|---------------|-----------------------------------|--------------------|------------------------------------------------------|-------------|---------------------------------------------------------------------------------------------------------|
| [general]     | obfuscation_enabled               | `true`             | `true`, `false`                                      | boolean     | if false, ROPfuscator is not applied and other configs are ignored                                      |
| [general]     | custom_library_path               | `""` (auto detect) | `"/lib32/libc.so.6"`                                 | string      | library path from which the gadgets are extracted                                                       |
| [general]     | library_hash_sha1                 | `""`               | `"e3d54f57..."`                                      | string      | SHA1 hash of the above library (used to verify)                                                         |
| [general]     | linked_libraries                  | `""` (auto detect) | `["/lib32/libpthread.so.0", "/lib32/libcss_s.so.1"]` | string list | list of linked libraries (avoid to use symbol names from these libraries as anchors)                    |
| [general]     | search_segment_for_gadget         | `true`             | `true`, `false`                                      | boolean     | gadgets are taken from segments (true) or sections (false)                                              |
| [general]     | avoid_multiversion_symbol         | `false`            | `true`, `false`                                      | boolean     | avoid using symbols `foo` such that both `foo@ver1` and `foo@var2` exist                                |
| [general]     | show_progress                     | `false`            | `true`, `false`                                      | boolean     | show progress of each function obfuscation                                                              |
| [general]     | print_instr_stat                  | `false`            | `true`, `false`                                      | boolean     | show the number of (non-)obfuscated instructions for each opcode                                        |
| [functions.*] | name                              | - (required)       | `"(AES|aes).*"`                                      | string      | function name pattern in regular expression (cannot be used in [functions.default]; required otherwise) |
| [functions.*] | obfuscation_enabled               | `true`             | `true`, `false`                                      | boolean     | if false, ROPfuscator is not applied for the function by default                                        |
| [functions.*] | opaque_predicates_enabled         | `false`            | `true`, `false`                                      | boolean     | if true, opaque predicates are used for the function                                                    |
| [functions.*] | obfuscate_stack_saved_values      | `false`            | `true`, `false`                                      | boolean     | if true, random constants are saved onto stack for later use in opaque predicate computation            |
| [functions.*] | obfuscate_immediate_operand       | `true`             | `true`, `false`                                      | boolean     | if true, immediate operands (e.g., `123` in `mov eax, 123`) is obfuscated using opaque constant         |
| [functions.*] | obfuscate_branch_target           | `true`             | `true`, `false`                                      | boolean     | if true, immediate operands (e.g., address of `L1` in `je L1`) is obfuscated using opaque constant      |
| [functions.*] | opaque_predicates_algorithm       | `"mov"`            | `"mov"`, `"r3sat32"`, `"multcomp"`                   | string      | select opaque constant (predicate) algorithm                                                            |
| [functions.*] | opaque_predicates_input_algorithm | `"addreg"`         | `"const"`, `"addreg"`, `"rdtsc"`                     | string      | select input value generation algorithm for opaque predicates                                           |
| [functions.*] | opaque_predicate_use_contextual   | `true`             | `true`, `false`                                      | boolean     | if true, use contextual opaque predicates                                                               |
| [functions.*] | opaque_stegano_enabled            | `false`            | `true`, `false`                                      | boolean     | if true, instruction hiding is enabled                                                                  |
| [functions.*] | branch_divergence_enabled         | `false`            | `true`, `false`                                      | boolean     | if true, branch divergence is enabled                                                                   |
| [functions.*] | branch_divergence_max_branches    | `32`               | `4`, `16`, `32`                                      | integer     | maximum number of branches in branch divergence                                                         |
| [functions.*] | branch_divergence_algorithm       | `"addreg+mov"`     | `"addreg+mov"`, `"rdtsc+mov"`, `"negativestack+mov"` | string      | algorithm for branch divergence                                                                         |

For algorithm details, see [algorithm.md](./algorithm.md).

## Build harness

To automate the steps above in existing build scripts (such as `Makefile`), we provide a shell script `ropcc.sh`. It serves both as a compiler and a linker.
The following example compiles `foo.c` and `bar.c` separately, link the objects with `libbaz.so` (obfuscated with config `obf.conf`) to generate an obfuscated binary `exefile`.
You just need to replace C-compiler with `ropcc.sh cc`, and C++-compiler with `ropcc.sh c++`, and supply obfuscation configuration (`-ropfuscator-config=...`).
Command line options are passed to compiler/linker appropriately.
See shell script (comment) for further details.

```
ropcc.sh cc -c foo.c -o foo.o
ropcc.sh cc -c bar.c -o bar.o
ropcc.sh cc -ropfuscator-config=obf.conf foo.o bar.o -lbaz -o exefile
```

### Compiling the examples

While in the `build` directory, run:

```
ninja ropfuscator-examples
```

The compiled examples will be found in the `bin/` directory.

### Compiling binutils

While in the `build` directory, run:

```
ninja ropfuscator-binutils
```

The compiled `binutils` programs will be found in the `bin/` directory.
