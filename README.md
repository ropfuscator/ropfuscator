# ROPfuscator [![Build](https://github.com/ropfuscator/ropfuscator/actions/workflows/main.yaml/badge.svg)](https://github.com/ropfuscator/ropfuscator/actions/workflows/main.yaml)
![logo](./docs/logo.png)

ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
It is implemented as an extension to LLVM (10.0.1) x86 backend.

For build, usage and implementation, see individual documents:

- Building ROPfuscator: [build.md](./docs/build.md)
- Using ROPfuscator to obfuscate programs: [usage.md](./docs/usage.md)
- Obfuscation algorithm details: [algorithm.md](./docs/algorithm.md)
- Implementation details: [implementation.md](./docs/implementation.md)

## Get started

### Using Nix (recommended)

#### Step 0: Install Nix

Install [Nix](https://nix.dev/tutorials/install-nix) (the package manager) and make sure that its daemon is running.

#### Step 1: Enable Nix to use Flakes

Flakes allow you to specify your code's dependencies in a declarative way and they allow to easily specify inputs and outputs for projects. ROPfuscator exposes different outputs hence we need to enable Nix to use flakes.

[Here](https://nixos.wiki/wiki/Flakes) is a step-by-step process on how to enable them.

#### Step 2: Add ROPfuscator cache repository to Nix's channels (optional) 

This step allows to leverage ROPfuscator cache repository to avoid recompiling the project and all its dependencies from scratch. This step is obviously optional but recommended.

To enable ROPfuscator's cache, first install `cachix`:

```
nix-env -iA cachix -f https://cachix.org/api/v1/install
```

Then, configure `nix.conf` to use the binary cache:

```
cachix use ropfuscator
```

#### Step 3: Build and use ROPfuscator

The final step is to build ROPfuscator. This can be achieved by invoking:

```
nix build github:ropfuscator/ropfuscator -L
```

If you want to drop in a shell configured to use ROPfuscator by default, just invoke:

```
nix shell github:ropfuscator/ropfuscator
```

## ROPfuscator Overview

![architecture](./docs/architecture.svg)

We combine the following obfuscation layers to achieve robust obfuscation against several attacks.

- ROP Transformation
  - Convert each instruction into one or more ROP gadgets, and translate the entire code to ROP chains.
- Opaque Predicate Insertion
  - Translate ROP gadget address(es) and stack pushed values into opaque constants, which are composition of multiple opaque predicates.

## Limitations

- Linux 32-bit x86 binaries are the only supported target (as of now)
- For detailed limitations, see [limitation.md](./docs/limitation.md).
