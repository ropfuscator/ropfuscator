#include <stdio.h>

void lcm(int n1, int n2) {
  int minMultiple;

  // maximum number between n1 and n2 is stored in minMultiple
  minMultiple = (n1 > n2) ? n1 : n2;

  // Always true
  while (1) {
    if (minMultiple % n1 == 0 && minMultiple % n2 == 0) {
      printf("The LCM of %d and %d is %d.\n", n1, n2, minMultiple);
      break;
    }
    ++minMultiple;
  }
}

int main() {
  lcm(1, 1);
  lcm(1, 2);
  lcm(2, 2);
  lcm(2, 3);
  lcm(4, 6);
  lcm(123, 99);
}
