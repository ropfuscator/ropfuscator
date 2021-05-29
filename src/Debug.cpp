#include "Debug.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_os_ostream.h"
#include <ostream>

namespace ropf {

class llvm_raw_ostream_wrapper_ostream : public std::streambuf {
  llvm::raw_ostream &raw_os;

public:
  std::streamsize xsputn(const char *s, std::streamsize n) override {
    raw_os.write(s, n);
    return n;
  }
  int overflow(int c) override {
    if (c != EOF) {
      raw_os.write(c);
    }
    return c;
  }
  llvm_raw_ostream_wrapper_ostream(llvm::raw_ostream &raw_os)
      : raw_os(raw_os) {}
};

std::ostream &debugs() {
  static struct debug_stream_impl {
    llvm_raw_ostream_wrapper_ostream buf;
    std::ostream                     os;
    debug_stream_impl() : buf(llvm::dbgs()), os(&buf) {}
  } debug_stream;

  return debug_stream.os;
}

} // namespace ropf

namespace llvm {

std::ostream &operator<<(std::ostream &os, const llvm::StringRef &s) {
  return os.write(s.data(), s.size());
}

#define DEFINE_OUTPUT_FUNC_FOR_LLVM_TYPE(T)                                    \
  std::ostream &operator<<(std::ostream &os, const llvm::T &value) {           \
    llvm::raw_os_ostream raw_os {os};                                          \
    raw_os << value;                                                           \
    return os;                                                                 \
  }

DEFINE_OUTPUT_FUNC_FOR_LLVM_TYPE(Error)
DEFINE_OUTPUT_FUNC_FOR_LLVM_TYPE(GlobalValue)
DEFINE_OUTPUT_FUNC_FOR_LLVM_TYPE(MachineInstr)
DEFINE_OUTPUT_FUNC_FOR_LLVM_TYPE(MachineBasicBlock)

} // namespace llvm
