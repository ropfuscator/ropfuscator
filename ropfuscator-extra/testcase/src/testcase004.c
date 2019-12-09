/* This program is for testing branch instruction obfuscation problem. */

const char table[256] =
  "bbbbbbbbbbbbbbbb" "bbbbbbbbbbbbbbbb"
  "s!!!!!!!!!!!!!!!" "0000000000!!!!!!"
  "AAAAAAAAAAAAAAAA" "AAAAAAAAAA!!!!!!"
  "aaaaaaaaaaaaaaaa" "aaaaaaaaaa!!!!!!"
  "bbbbbbbbbbbbbbbb" "bbbbbbbbbbbbbbbb"
  "bbbbbbbbbbbbbbbb" "bbbbbbbbbbbbbbbb"
  "bbbbbbbbbbbbbbbb" "bbbbbbbbbbbbbbbb"
  "bbbbbbbbbbbbbbbb" "bbbbbbbbbbbbbbbb";

int isnumstr(const char *s) {
  const char *p;
  for (p = s; *p != '\0' && table[*p] == '0'; p++) {
  }
  return *p == '\0';
}

int main(void) {
  const char *s1 = "abcdef";
  const char *s2 = "123456";
  const char *s3 = "abc123";
  const char *s4 = "123abc";

  printf("%s %d\n", s1, isnumstr(s1));
  printf("%s %d\n", s2, isnumstr(s2));
  printf("%s %d\n", s3, isnumstr(s3));
  printf("%s %d\n", s4, isnumstr(s4));
  return 0;
}
