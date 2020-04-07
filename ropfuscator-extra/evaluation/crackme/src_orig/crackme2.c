#include <stdio.h>

int check(const char *s) {
  int i = 0;
  i += (s[0] == 'H');
  i += (s[1] == 'e');
  i += (s[2] == 'l');
  i += (s[3] == 'l');
  i += (s[4] == 'o');
  i += (s[5] == ' ');
  i += (s[6] == 'w');
  i += (s[7] == 'o');
  i += (s[8] == 'r');
  i += (s[9] == 'l');
  i += (s[10] == 'd');
  i += (s[11] == '!');
  i += (s[12] == '\0');
  return i == 13;
}

int main(int argc, char **argv)
{
  if (argc == 2 && check(argv[1])) {
    puts("OK");
  }
  return 0;
}
