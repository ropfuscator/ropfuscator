#include <stdio.h>

#pragma GCC optimize ("O0")
#pragma clang optimize off

int check(const char *s) {
  if (s[0] != 'H') return 0;
  if (s[1] != 'e') return 0;
  if (s[2] != 'l') return 0;
  if (s[3] != 'l') return 0;
  if (s[4] != 'o') return 0;
  if (s[5] != ' ') return 0;
  if (s[6] != 'w') return 0;
  if (s[7] != 'o') return 0;
  if (s[8] != 'r') return 0;
  if (s[9] != 'l') return 0;
  if (s[10] != 'd') return 0;
  if (s[11] != '!') return 0;
  if (s[12] != '\0') return 0;
  return 1;
}

int main(int argc, char **argv)
{
  if (argc == 2 && check(argv[1])) {
    puts("OK");
  }
  return 0;
}
