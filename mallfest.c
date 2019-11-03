/*
 * File: mallfest.c
 * Author: Claes M. Nyberg <cmn@nybergit.se>
 * When: Summer 2018
 * What: Small tool to help understand malloc implementations
 * Compile: gcc -Wall -ggdb -o mallfest mallfest.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>

void
usage(char *pname)
{
    fprintf(stderr, "Malloc Fest - <cmn@nybergit.se>\n");
    fprintf(stderr, "Usage: %s <cmd> [<cmd>...]\n", pname);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "   <size>      - malloc(<size>)\n");
    fprintf(stderr, "   <size>:f    - free(malloc(<size>))\n");
    fprintf(stderr, "   f:<i>       - Free chunk allocated at argv[i]\n");
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
    intptr_t **chunks;
    int i;
    int o;
    struct options {
        int verbose; 
    } opt;

    memset(&opt, 0x00, sizeof(opt));

    if (argv[1] == NULL) 
        usage(argv[0]);


    /* Allocate array for chunk pointers.
     * We allocate on the stack to avoid messing with malloc(3) ... */
    chunks = alloca(argc * sizeof(void*));
    memset(chunks, 0x00, argc * sizeof(void*));

    while ( (o = getopt(argc, argv, "v")) != -1) {
        switch(o) {
            case 'v':
                opt.verbose = 1;
                break;
        }
    }

    for (i=optind; argv[i] != NULL; i++) {
        size_t n;
        void *mem;
        char *pt;    
        int f = 0;

        if ( (pt = strchr(argv[i], ':')) != NULL) {
            *pt = '\0';
            pt++;

            if (*pt == 'f')
                f = 1;
        }

        /* Free chunk f:<i> */
        if (strcmp(argv[i], "f") == 0) {
            n = strtoul(pt, NULL, 0);

            if (n < 1 || n > argc) {
                fprintf(stderr, "free index out of range\n");
                exit(EXIT_FAILURE);
            }

            if (chunks[n] == NULL) { 
                fprintf(stderr, "free index %d NULL\n", (int)n);
                exit(EXIT_FAILURE);
            }

            fprintf(stderr, "[%d] free(%p);\n", (int)n, (void *)chunks[n]);
            free(chunks[n]);
            continue;
        }
        
        n = strtoul(argv[i], NULL, 0);
        mem = malloc(n);        
        fprintf(stderr, "[%d] %p = malloc(0x%lx)\n", i, mem, n);
        chunks[i] = mem;

        if (f) {
            fprintf(stderr, "[%d] free(%p);\n", i, mem);
            free(mem);
        }
    }

    fprintf(stderr, "Done.\n");
    return 0;
}
