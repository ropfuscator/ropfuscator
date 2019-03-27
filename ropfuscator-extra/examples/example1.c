#include <stdio.h>

int sum(int a) {
  int b = a + 12;
  while (b > 46) {
    b = b - 2;
    printf("%d\n", b);
  }
  return b;
}

int main() {
  int a = sum(40);
  a += 256;
  printf("%d\n", a);
}
