/* This program is for testing adc instruction
 * followed by add instruction.
 * Obfuscating add instruction should not change
 * the semantics of setting EFLAGS.
 * Example:
 *      addl    $651588039, %eax
 *      adcl    $2587007, %edx
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

int64_t f(int64_t a1) {
  return a1 + 11111111111111111LL;
}

int main()
{
  int i;
  int64_t x = 0;
  for (i = 0; i < 9; i++) {
    x = f(x);
  }
  printf("%" PRId64 "\n", x);
}
