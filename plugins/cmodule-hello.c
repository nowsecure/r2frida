/*
 * Run it like this:
 *
 * $ r2 -qqi':. cmodule-hello.c' frida://0
 *
 */
#include <stdio.h>

int main() {
	printf ("Hello World\n");
	return 0;
}
