/*
 * Vulnerable program for 3.3 in ptmalloc2-ubuntu-16.04.4-64bit
 * Author: Claes M Nyberg
 * When: Summer 2018
 * Compile: gcc -ggdb -z execstack -o vuln_3.3 vuln_3.3.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct data {
	uint64_t prev_size1;
	uint64_t chunk_size;
	uint64_t data1;
	void (*funcpt)();
	uint64_t data3;
	uint64_t data4;
	uint64_t data5;
	uint64_t data6;
	uint64_t prev_size;
	uint64_t valid_chunk_size;
} __attribute__((aligned(16)));

void
logfunc()
{
	fprintf(stderr, "Hello World\n");
}

void
vuln(void)
{
	uint64_t *pointer;
	struct data fake_fast_bin;
	void *mem;
	uint64_t len;

	/* Set up the data structure */
	memset(&fake_fast_bin, 0x00, sizeof(fake_fast_bin));
	fake_fast_bin.funcpt = logfunc;

	/* 16 < valid_chunk_size < 128*1024 */
	fake_fast_bin.valid_chunk_size = 0x1234;

	/* Just call malloc to set up the main_arena */
	malloc(0x18);

	fprintf(stderr, "Please feed me a valid chunk size\n");
	fread(&fake_fast_bin.chunk_size, sizeof(uint64_t), 1, stdin);
	fprintf(stderr, "Data located at %p\n", &fake_fast_bin);

	fprintf(stderr, "Please feed me a pointer to free\n");
	fread(&pointer, sizeof(uint64_t *), 1, stdin);
	free(pointer);
	
	/* The next call to malloc with  length that will result in the
     * same fake fast bin chunk size will result in malloc returning
     * the address passed onto free previously */
	len = fake_fast_bin.chunk_size-8;
	mem = malloc(len);
	fprintf(stderr, "malloc(%ld)=%p\n", len, mem);

	fprintf(stderr, "Please send me at most %ld bytes\n", len);
	fgets(mem, len, stdin);

	/* Call the function pointer in the structure */
	fake_fast_bin.funcpt();
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
