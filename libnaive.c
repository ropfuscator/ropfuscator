void func1() {
  asm("popl %ebp");
  return;
}

void func2() {
  asm("addl %eax, %ebx");
  return;
}

void func3() {
  asm("xchgl %ecx, %esi");
  return;
}

void func4() {
  asm("xchgl %ebx, %esi");
  return;
}

void func5() {
  asm("xchgl %ebx, %edi");
  return;
}

void func6() {
  asm("xchgl %edi, %edx");
  return;
}

void func7() {
  asm("xchgl %edx, %eax");
  return;
}

void func8() {
  asm("xchgl %ebp, %eax");
  return;
}