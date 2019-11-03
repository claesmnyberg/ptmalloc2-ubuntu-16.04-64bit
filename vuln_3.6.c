/*
 * Vulnerable program for 3.6 in ptmalloc2-ubuntu-16.04.4-64bit
 * Author: Claes M Nyberg
 * When: Summer 2018
 * Compile: gcc -ggdb -z execstack -o vuln_3.6 vuln_3.6.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>

struct fake_chunk {
	uint64_t prev_size;
	uint64_t chunk_size;
	uint64_t fwd;
	uint64_t bck;
	uint64_t fwd_nextsize;
	uint64_t bck_nextsize;
} __attribute__((aligned(16)));


void
logfunc()
{
	fprintf(stderr, "Hello World\n");
}

void
vuln(void)
{
	struct fake_chunk fc;
	char local_buf[1024];
	char *str;
	size_t len;

	/* Read the fake chunk, could be anywhere in memory */
	fprintf(stderr, "Please feed me 48 bytes to address %p\n", &fc);
	fread(&fc, sizeof(fc), 1, stdin);

	/* Read string and allocate first chunk */
	memset(local_buf, 0x00, sizeof(local_buf));
	fprintf(stderr, "Send me first string\n");
	fgets(local_buf, sizeof(local_buf), stdin);
	len = strlen(local_buf);
	str = malloc(len);
	fprintf(stderr, "Allocated 0x%lx bytes at %p\n", 
		malloc_usable_size(str), str);
	memcpy(str, local_buf, len);

	/* Read string and allocate second chunk */
	memset(local_buf, 0x00, sizeof(local_buf));
	fprintf(stderr, "Send me second string\n");
	fgets(local_buf, sizeof(local_buf), stdin);
	len = strlen(local_buf);
	str = malloc(len);
	fprintf(stderr, "Allocated 0x%lx bytes at %p\n", 
		malloc_usable_size(str), str);
	memcpy(str, local_buf, len);
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
