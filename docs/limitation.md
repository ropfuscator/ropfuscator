# Limitations of ROPfuscator

- Generated binaries depends on the specific version of `libc` used at compile time. This means that the generated binary is locked to specific environment, and the program may not work after libc update. Therefore, it is highly recommended that the library from which the gadgets are extracted is distributed along with the obfuscated program.
- Programs need to be built as PIE (position independent executable) without PIC option (i.e. with `-pie` in linking, and without `-fpic` in compiling).
- Inline assembly (`asm`) written in the source code cannot be obfuscated.
- Some version of `libc` may not have enough gadgets to obfuscate fundamental instructions and can result in very low obfuscation coverage. If this happens, another version of `libc` or other libraries to which the program is linked should be used instead.
- Enabling optimization may lower obfuscation coverage (and robustness); it is recommended to disable optimization for functions that are to be obfuscated.
- Current implementation does not take any defence measures against ROP exploitation into account, for example, CFI (control flow integrity) and behaviour-based malware detection.
- Only works in release build mode (with NDEBUG enabled).
- LibLLVM should be compiled as a native 64bit binary even if we only support 32bit targets.
