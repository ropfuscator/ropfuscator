void func1() {
	asm("popl %ecx");
	return;
}

void func2() {
	asm("addl %ecx, %eax");
	return;
}

void func3() {
	asm("movl (%edx), %eax");
	return;
}

void func4() {
	asm("movl %eax, (%edx)");
	return;
}

void func5() {
	asm("xchgl %eax, %ebp");
	return;
}

void func6() {
	asm("xchgl %eax, %edx");
	return;
}

void func7() {
	asm("movl %edx, %eax");
	return;
}

