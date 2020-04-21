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

void pp_one(t_example_1 *e) { printf("a @ %p: 0x%x\n", (void *)e, e->a); }

void pp_two(t_example_2 *e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx \n", (void *)&e->a, e->a,
         (void *)&e->b, e->b);
}

void pp_three(t_example_3 *e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx | c @ %p: 0x%x\n", (void *)&e->a, e->a,
         (void *)&e->b, e->b, (void *)&e->c, e->c);
}

void p_one(t_example_1 e) { printf("a @ %p: 0x%x\n", (void *)&e.a, e.a); }

void p_two(t_example_2 e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx \n", (void *)&e.a, e.a, (void *)&e.b,
         e.b);
}

void p_three(t_example_3 e) {
  printf("a @ %p: 0x%x | b @ %p : 0x%llx | c @ %p: 0x%x\n", (void *)&e.a, e.a,
         (void *)&e.b, e.b, (void *)&e.c, e.c);
}

int main(int argc, char *argv[]) {
  t_example_1 e1;
  t_example_2 e2;
  t_example_3 e3;

  e1.a = 0x1AAAAAAA;

  e2.a = 0x2AAAAAAA;
  e2.b = 0x2BBBBBBBBBBBBBBB;

  e3.a = 0x3AAAAAAA;
  e3.b = 0x3BBBBBBBBBBBBBBB;
  e3.c = 0x3C;

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
