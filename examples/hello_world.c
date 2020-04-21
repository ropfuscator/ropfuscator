#include <stdio.h>

int sum(int a, int b) {
	return a + b;
}

int main(int argc, char * argv[]) {
	puts("Hello world!");

	if (argc > 1) {
		printf("argc: %d", sum(0, argc));
	}
	return 0;
}
