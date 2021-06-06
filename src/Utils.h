//#include <ranges>
//#include <utility>
#include <algorithm>

#ifndef ROPFUSCATOR_UTILS_H
#define ROPFUSCATOR_UTILS_H

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
