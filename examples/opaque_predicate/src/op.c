#include <time.h>
#include <stdlib.h>

int _op() {
	srand(time(NULL));
	int i = rand();
	float a = i / 42.0;
	float b = 0.1;
	if (a!=0.1 & a-b==0) return 1;
		else return 0;
}

int opaquePredicate() {
	asm("xchgl %eax, %ebx");
	asm("calll _op");
	asm("xchgl %eax, %ebx");
	asm("test %ebx, %ebx");
}
