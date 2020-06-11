import math
import struct
import argparse

import cle
import unicorn as uc
import unicorn.x86_const as ux86
import capstone as cs

STACK_ADDR = 0x7fff0000
STACK_SIZE = 0x10000
PAGESIZE = 0x1000

ap = argparse.ArgumentParser()
ap.add_argument('program', type=str)
ap.add_argument('start_addr', type=lambda x: int(x, 0))
ap.add_argument('stop_addr', type=lambda x: int(x, 0))

args = ap.parse_args()

ld = cle.Loader(args.program)

mu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
for obj in ld.all_elf_objects:
    mu.mem_map(obj.min_addr, math.ceil((obj.max_addr - obj.min_addr)/PAGESIZE)*PAGESIZE)
    mu.mem_write(obj.min_addr, ld.memory.load(obj.min_addr, obj.max_addr - obj.min_addr))

mu.mem_map(STACK_ADDR - STACK_SIZE, STACK_SIZE*2)

mu.reg_write(ux86.UC_X86_REG_ESP, STACK_ADDR)
mu.reg_write(ux86.UC_X86_REG_EIP, ld.main_object.entry)

class State: pass

state = State()
state.in_rop = False
state.chain = []

def hook_code(mu, address, size, user_data):
    #eflags = mu.reg_read(ux86.UC_X86_REG_EFLAGS)
    is_ret = mu.mem_read(address, 1)[0] == 0xc3
    if user_data.in_rop and not is_ret:
        inst = next(md.disasm(mu.mem_read(address, size), size))
        esp = mu.reg_read(ux86.UC_X86_REG_ESP)
        state.chain.append((inst, mu.mem_read(esp, 4)))
        #print("0x{:08x}:\t{}\t{}".format(address, inst.mnemonic, inst.op_str))
    if is_ret:
        user_data.in_rop = True


def hook_mem_invalid(uc, access, address, size, value, user_data):
    uc.mem_map(math.floor(address / PAGESIZE), PAGESIZE)
    return True


mu.hook_add(uc.UC_HOOK_CODE, hook_code, state)
mu.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED | uc.UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

def analyse_chain(addr_start, addr_stop):
    state.in_rop = False
    state.chain = []
    esp = mu.reg_read(ux86.UC_X86_REG_ESP)
    mu.emu_start(addr_start, addr_stop)
    addr = mu.reg_read(ux86.UC_X86_REG_EIP)
    while not state.in_rop:
        mu.emu_start(addr, 0, count=1)
        addr = mu.reg_read(ux86.UC_X86_REG_EIP)
    while True:
        mu.emu_start(addr, 0, count=2)
        addr = mu.reg_read(ux86.UC_X86_REG_EIP)
        if mu.reg_read(ux86.UC_X86_REG_ESP) >= esp:
            break
    return state.chain

def dump_chain(addr_start, addr_stop):
    print('chain 0x{:x}--0x{:x}'.format(addr_start, addr_stop))
    for (instr, data) in analyse_chain(addr_start, addr_stop):
        if instr.mnemonic == 'pop':
            print('\t{}\t{}\tdata=0x{:08x}'.format(instr.mnemonic, instr.op_str, struct.unpack('<I', data)[0]))
        else:
            print('\t{}\t{}'.format(instr.mnemonic, instr.op_str))

dump_chain(args.start_addr, args.stop_addr)
