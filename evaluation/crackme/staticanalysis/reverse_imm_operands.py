import argparse
import capstone
from elftools.elf.elffile import ELFFile

ap = argparse.ArgumentParser()
ap.add_argument('program')
args = ap.parse_args()

cs_opt_map = {
    'EM_386':    [capstone.CS_ARCH_X86, capstone.CS_MODE_32],
    'EM_X86_64': [capstone.CS_ARCH_X86, capstone.CS_MODE_64],
}

with open(args.program, 'rb') as f:
    elf = ELFFile(f)
    e_machine = elf.header.e_machine
    if not (e_machine in cs_opt_map):
        print('Unsupported architecture: %s' % e_machine)
        exit(1)
    print('Disassembling architecture: %s' % e_machine)
    cs = capstone.Cs(*(cs_opt_map[e_machine]))
    cs.detail = True
    codesection = elf.get_section_by_name('.text')
    code = codesection.data()
    immediates = []
    for inst in cs.disasm(code, codesection.header.sh_addr):
        if inst.mnemonic[:1] != 'j' and inst.mnemonic != 'call':
            for o in inst.operands:
                if o.type == capstone.CS_OP_IMM:
                    print('0x%08x: immediate=%d' % (inst.address, o.imm))
                    immediates += [(inst, o.imm)]

print('========== Trying to extract immediate string... ==========')

# find recurring pattern of loading/comparing bytes
for i in range(1, 50):
    for j in range(i):
        s = ''
        for k in range(j, len(immediates), i):
            (inst, imm) = immediates[k]
            if imm >= 0x20 and imm < 0x80:
                s += chr(imm)
            else:
                if len(s) > 5:
                    print(s)
                s = ''
        if len(s) > 5:
            print(s)
