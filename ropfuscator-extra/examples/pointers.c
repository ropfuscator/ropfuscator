#include <stdio.h>

typedef struct example {
  unsigned int a;
  unsigned long long b;
  char c;
} t_example;

void print_ptr(t_example *e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx | c @ %p: 0x%x\n", &e->a, e->a, &e->b,
         e->b, &e->c, e->c);
  return;
}

int main(int argc, char *argv[]) {
  t_example example;

  example.a = 0x41414141;
  example.b = 0x4242424242424242;
  example.c = 0x43;

  printf("Printing object.\n");
  printf("a @ %p: 0x%x | b @ %p : 0x%llx | c @ %p: 0x%x\n", &example.a,
         example.a, &example.b, example.b, &example.c, example.c);
  printf("Printing by reference.\n");
  print_ptr(&example);

  return 0;
}
