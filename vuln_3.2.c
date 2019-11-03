/*
 * Vulnerable program for 3.2 in ptmalloc2-ubuntu-16.04.4-64bit
 * Author: Claes M Nyberg
 * When: Summer 2018
 * Compile: gcc -ggdb -z execstack -o vuln_3.2 vuln_3.2.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define CHUNK_SIZE(msz) ((((msz)+8) + (16 - 1)) & -16)

void
vuln(void)
{
    void *bufa;
    void *bufb;

    uint64_t chunk_size;
    uint64_t len;

    /* Simulate a leak of a memory area
     * which holds the size of the chunk */
    fread(&len, sizeof(len), 1, stdin);
    fprintf(stderr, "%p\n", &chunk_size);

    /* Vulnerable code */
    chunk_size = CHUNK_SIZE(len);
    bufa = malloc(len);
    bufb = malloc(len);
    free(bufa);
    free(bufb);
    free(bufa);

    /* Double free'd chunk, read fwd pointer */
    bufa = malloc(len);
    fread(bufa, sizeof(uint64_t), 1, stdin);

    /* Empty fast bin until fake chunk 
     * is the only chunk */
    malloc(len);
    malloc(len);

    /* Finally, malloc returns our fake chunk 
     * from the fast bin */
    bufb = malloc(len);
    fgets(bufb, len, stdin);
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
