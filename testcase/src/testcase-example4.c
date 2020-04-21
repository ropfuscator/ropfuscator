/*
 * C Program to Implement Selection Sort Recursively
 */
#include <stdio.h>

void selection(int[], int, int, int, int);
void selection_sort(int[], int);

int main() {
  int test1[] = {1, 3, 5, 7, 9, 11, 13, 15};
  int test2[] = {9, 8, 7, 6, 5, 4, 3, 2, 1};
  int test3[] = {34, 26, 1, 50, 23, 121, 23, 52, 62};
  int test4[] = {4, 99, 99, 4, 99, 33, 2, -34, 2148};
  selection_sort(test1, sizeof(test1)/sizeof(test1[0]));
  selection_sort(test2, sizeof(test2)/sizeof(test2[0]));
  selection_sort(test3, sizeof(test3)/sizeof(test3[0]));
  selection_sort(test4, sizeof(test4)/sizeof(test4[0]));
}

void selection_sort(int *list, int size) {
  int i;
  selection(list, 0, 0, size, 1);
  printf("The sorted list in ascending order is\n");
  for (i = 0; i < size; i++) {
    printf("%d  ", list[i]);
  }
  printf("\n");
}

void selection(int list[], int i, int j, int size, int flag) {
  int temp;

  if (i < size - 1) {
    if (flag) {
      j = i + 1;
    }
    if (j < size) {
      if (list[i] > list[j]) {
        temp = list[i];
        list[i] = list[j];
        list[j] = temp;
      }
      selection(list, i, j + 1, size, 0);
    }
    selection(list, i + 1, 0, size, 1);
  }
}
