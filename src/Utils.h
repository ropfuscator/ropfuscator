#include <algorithm>
#include <string>

#ifndef ROPFUSCATOR_UTILS_H
#define ROPFUSCATOR_UTILS_H

const std::string SYSTEM_LIB_FOLDERS[] = {
    "/lib/i386-linux-gnu",
    "/usr/lib/i386-linux-gnu",
    "/lib32",
    "/usr/lib32",
    "/usr/local/lib",
    "/lib",
    "/usr/lib",
};

std::string findLibraryPath(const std::string &libfile);

namespace ropf {
template <typename T,
          typename V,
          typename SFINAE = decltype(std::declval<T>().begin(),
                                     std::declval<T>().end())>
bool contains(const T &container, const V &value) {
  return std::find(container.begin(), container.end(), value) !=
         container.end();
}
} // namespace ropf

#endif
