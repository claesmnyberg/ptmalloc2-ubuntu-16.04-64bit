/*
 * Vulnerable program for 3.1 in ptmalloc2-ubuntu-16.04.4-64bit
 * Author: Claes M Nyberg
 * When: Summer 2018
 * Compile: gcc -ggdb -z execstack -o vuln_3.1 vuln_3.1.c
 */
#include <stdio.h>
#include <stdlib.h>

void
vuln(void)
{
	char *buf;
	size_t len;

	fread(&len, sizeof(len), 1, stdin);
	fprintf(stderr, "malloc(%lu)\n", len);
	buf = malloc(len);
	fprintf(stderr, "%p\n", buf);
	fgets(buf, 256, stdin);

	fread(&len, sizeof(len), 1, stdin);
	buf = malloc(len);
	fprintf(stderr, "%p\n", buf);
	fgets(buf, 256, stdin);

	fread(&len, sizeof(len), 1, stdin);
	buf = malloc(len);
	fprintf(stderr, "%p\n", buf);
	fgets(buf, 256, stdin);
}

int
main(int argc, char **argv)
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	vuln();
	exit(0);
}
