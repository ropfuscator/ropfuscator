/* This program is for testing mov instruction
 * between cmp and conditional branch.
 * Obfuscated mov instruction should not modify
 * any of EFLAGS.
 * Example:
 *      cmpl    gb, %eax
 *      movl    gc, %eax
 *      movl    (%eax), %eax
 *      jge     .Local_X
 */

#include <stdio.h>

volatile int ga = 615, gb = -615;
volatile int *volatile gc = &ga;

int f()
{
  int x = ga - gb;
  int y = *gc;
  if (x < 0) {
    return y / 9;
  } else {
    return (y - gb) + 4;
  }
}

int g()
{
  int x = ga + gb;
  int y = *gc;
  int z;
  if (x != 0) {
    return y / 9;
  } else {
    return (y - gb) + 4;
  }
  return z;
}

int main() {
  printf("%d %d\n", f(), g());
  return 0;
}
