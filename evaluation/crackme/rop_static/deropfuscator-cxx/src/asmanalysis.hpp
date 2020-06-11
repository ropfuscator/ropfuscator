#ifndef ASMANALYSIS_HPP_INCLUDED
#define ASMANALYSIS_HPP_INCLUDED

#include <capstone/capstone.h>
#include <ostream>

std::ostream &operator<<(std::ostream &os, const cs_insn &insn) {
  os << insn.mnemonic << "\t" << insn.op_str;
}

class AsmAnalysis {
  csh handle;
  AsmAnalysis(const AsmAnalysis&) = delete;
  AsmAnalysis& operator=(const AsmAnalysis&) = delete;
public:
  AsmAnalysis(cs_arch arch, cs_mode mode) {
    cs_open(arch, mode, &handle);
  }
  ~AsmAnalysis() {
    cs_close(&handle);
  }
  AsmAnalysis &set_option(cs_opt_type type, size_t value) {
    cs_option(handle, type, value);
    return *this;
  }
  class Disassembler;
  class DisassembleIterator
    : public std::iterator<std::input_iterator_tag, const cs_insn> {
    friend class Disassembler;
    const csh &handle;
    const uint8_t *code_pos;
    size_t remaining;
    uint64_t addr;
    bool valid;
    std::shared_ptr<cs_insn> insn;
    DisassembleIterator(const csh &handle, const uint8_t *code, size_t len, uint64_t addr)
      : handle(handle), code_pos(code), remaining(len), addr(addr), valid(code != nullptr),
        insn(cs_malloc(handle), std::bind2nd(std::ptr_fun(cs_free), 1)) {
      if (valid) operator++();
    }
  public:
    DisassembleIterator(const DisassembleIterator &) = default;
    DisassembleIterator &operator++() {
      valid = cs_disasm_iter(handle, &code_pos, &remaining, &addr, insn.get());
      return *this;
    }
    const cs_insn &operator*() const {
      return *insn;
    }
    bool is_valid() const {
      return valid;
    }
    bool operator==(const DisassembleIterator &other) const {
      if (valid) {
	return other.valid && &handle == &other.handle && code_pos == other.code_pos;
      } else {
	return !other.valid;
      }
    }
    bool operator!=(const DisassembleIterator &other) const {
      return !(*this == other);
    }
  };
  class Disassembler {
    friend class AsmAnalysis;
    const csh &handle;
    const uint8_t *code;
    size_t len;
    uint64_t addr;
    Disassembler(const csh &handle_, const uint8_t *code_, size_t len_, uint64_t addr_)
      : handle(handle_), code(code_), len(len_), addr(addr_) {}
  public:
    DisassembleIterator begin() {
      return DisassembleIterator(handle, code, len, addr);
    }
    DisassembleIterator end() {
      return DisassembleIterator(handle, nullptr, 0, 0);
    }
  };
  Disassembler disassembler(const void *code, size_t len, uint64_t addr) {
    return Disassembler(handle, static_cast<const uint8_t *>(code), len, addr);
  }
};

#endif // ASMANALYSIS_HPP_INCLUDED
