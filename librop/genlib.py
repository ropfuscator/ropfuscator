#!/usr/bin/env python3

from typing import List


OUTFILE = "librop.c"

REG2REG_OP = ["xor", "and", "or", "mov", "add", "sub", "xchg", "cmova", "cmovae", "cmovb", "cmovbe", "cmovc", "cmove", "cmovg", "cmovge", "cmovl", "cmovle", "cmovna", "cmovnae",
              "cmovnb", "cmovnbe", "cmovnc", "cmovne", "cmovng", "cmovnge", "cmovnl", "cmovnle", "cmovno", "cmovnp", "cmovns", "cmovnz", "cmovo", "cmovp", "cmovpe", "cmovpo", "cmovs", "cmovz"]
REGONLY_OP = ["push", "pop", "dec", "inc"]

X86_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]


def create_function(name, mnemonic, req_op, opt_op = None):
    return \
        f"""__attribute__((naked))void {name}(){{
            __asm {{
                {mnemonic} {",".join([x for x in [req_op, opt_op] if x])}
                ret
            }}
        }}"""

def main():
    functions: List[str] = []

    for op in REG2REG_OP:
        for dst in X86_REGS:
            for src in X86_REGS:
                symname = f"{op}_{dst}_{src}"
                functions.append(create_function(symname, op, dst, src))

    for op in REGONLY_OP:
        for r in X86_REGS:
            symname = f"{op}_{r}"
            functions.append(create_function(symname, op, r))

    with open(OUTFILE, "w") as f:
        f.write("\n".join(functions))

    return


if __name__ == "__main__":
    main()
