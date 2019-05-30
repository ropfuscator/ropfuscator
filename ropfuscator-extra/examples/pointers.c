#include <stdint.h>
#include <stdio.h>

typedef struct example1 {
  uint32_t a;
} t_example_1;

typedef struct example2 {
  uint32_t a;
  uint64_t b;
} t_example_2;

typedef struct example3 {
  uint32_t a;
  uint64_t b;
  uint8_t c;
} t_example_3;

void pp_one(t_example_1 *e) { printf("a @ %p: 0x%x\n", e, e->a); }

void pp_two(t_example_2 *e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx \n", &e->a, e->a, &e->b, e->b);
}

void pp_three(t_example_3 *e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx | c @ %p: 0x%x\n", &e->a, e->a, &e->b,
         e->b, &e->c, e->c);
}

void p_one(t_example_1 e) { printf("a @ %p: 0x%x\n", &e.a, e.a); }

void p_two(t_example_2 e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx \n", &e.a, e.a, &e.b, e.b);
}

void p_three(t_example_3 e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx | c @ %p: 0x%x\n", &e.a, e.a, &e.b,
         e.b, &e.c, e.c);
}

int main(int argc, char *argv[]) {
  t_example_1 e1;
  t_example_2 e2;
  t_example_3 e3;

  e1.a = 0x11000000;

  e2.a = 0x22000000;
  e2.b = 0x2211111111111111;

  e3.a = 0x33000000;
  e3.b = 0x3311111111111111;
  e3.c = 0x33;

  printf("Struct print:\n");
  p_one(e1);
  p_two(e2);
  p_three(e3);

  printf("Pointers print:\n");
  pp_one(&e1);
  pp_two(&e2);
  pp_three(&e3);

  return 0;
}
