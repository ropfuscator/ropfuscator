#include "Utils.h"
#include <string>
#include <system_error>
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

std::string findLibraryPath(const std::string &libfile) {
  for (auto &dir : POSSIBLE_LIBC_FOLDERS) {
    // searching for libc in regular files only
    std::error_code ec;

    for (auto dir_it  = llvm::sys::fs::directory_iterator(dir, ec),
              dir_end = llvm::sys::fs::directory_iterator();
         !ec && dir_it != dir_end;
         dir_it.increment(ec)) {
      auto st = dir_it->status();
      if (st && st->type() == llvm::sys::fs::file_type::regular_file &&
          llvm::sys::path::filename(dir_it->path()) == libfile) {
        std::string libraryPath = dir_it->path();
        return libraryPath;
      }
    }
  }

  return "";
}