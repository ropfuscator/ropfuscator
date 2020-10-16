#include <stdio.h>

void maxelem(float *arr, int n) {
  int i;

  // Loop to store largest number to arr[0]
  for (i = 1; i < n; ++i) {
    // Change < to > if you want to find the smallest element
    if (arr[0] < arr[i])
      arr[0] = arr[i];
  }
  printf("Largest element = %.2f\n", arr[0]);
}

int main() {
  float test1[] = {1.2};
  float test2[] = {1.2, 3.4, 5.6};
  float test3[] = {1.2, 9.9, 3.5};
  float test4[] = {1.2e+4, 1.2e+8, 1.2e+6};

  maxelem(test1, sizeof(test1)/sizeof(test1[0]));
  maxelem(test2, sizeof(test2)/sizeof(test2[0]));
  maxelem(test3, sizeof(test3)/sizeof(test3[0]));
  maxelem(test4, sizeof(test4)/sizeof(test4[0]));

  return 0;
}
